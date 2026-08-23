"""Deterministic freestanding PE32 construction for candidate reconstruction semantic engines.

This module only constructs candidate binaries. Its manifests are build and
provenance evidence; none of them can qualify a candidate.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from ..artifacts.formats import (
    NATIVE_ENGINE_PACKAGE_FORMAT as _NATIVE_FORMAT,
)
from ..roundtrip_fuzz.image_model import (
    LoadImageContract,
)
from .engine_layout import (
    EngineLayout,
    EngineLayoutFeature,
    SPX_ENGINE_LAYOUT_MAGIC_BYTES,
    parse_spx_engine_layout_payload,
)
from .pe import PayloadRelocation, PayloadRelocationInventory
from ..util import sha256_bytes, sha256_file


PAYLOAD_FILENAME = "payload.exe"
PAYLOAD_MAP_FILENAME = "payload.map"
ENGINE_LAYOUT_FILENAME = "engine-layout.bin"
PAYLOAD_RELOCATION_INVENTORY_FILENAME = "payload-relocations.json"

_SEMANTIC_MANIFEST = "state-machine-implementation.json"
_NATIVE_MANIFEST = "native-engine-package.json"
_SEMANTIC_FORMAT = "spaghetti-extractor-semantic-c-implementation-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PLACEHOLDER_INT3 = re.compile(
    r"(?im)^\s*(?:int3|int\s+\$?3)\s*(?:[#;/].*)?$|"
    r"^\s*\.byte\s+0xcc\s*(?:[#;/].*)?$"
)
_EXPECTED_LAYOUT_FEATURES = (
    EngineLayoutFeature.SPLIT_FLAGS
    | EngineLayoutFeature.PACKED_EFLAGS
    | EngineLayoutFeature.FS_BASE
    | EngineLayoutFeature.ORIGINAL_RVA
)
_EXPECTED_X87_SLOTS = 8
_IMAGE_FILE_RELOCS_STRIPPED = 0x0001
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_DIRECTORY_IMPORT = 1
_DIRECTORY_BASE_RELOCATION = 5
_DIRECTORY_TLS = 9
_DIRECTORY_IAT = 12
_DIRECTORY_DELAY_IMPORT = 13


class CandidateNativeBuildError(ValueError):
    """A candidate-generation input or output failed closed validation."""


@dataclass(frozen=True)
class _Artifact:
    owner: str
    key: str
    relative_path: str
    sha256: str
    path: Path

    def payload(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "key": self.key,
            "path": self.relative_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class _Toolchain:
    compiler: Path
    assembler: Path
    linker: Path
    nm: Path
    target: str
    compiler_version: str
    linker_version: str
    compiler_sha256: str
    assembler_sha256: str
    linker_sha256: str
    nm_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "compiler": str(self.compiler),
            "compiler_sha256": self.compiler_sha256,
            "compiler_version": self.compiler_version,
            "assembler": str(self.assembler),
            "assembler_sha256": self.assembler_sha256,
            "linker": str(self.linker),
            "linker_sha256": self.linker_sha256,
            "linker_version": self.linker_version,
            "nm": str(self.nm),
            "nm_sha256": self.nm_sha256,
            "target": self.target,
        }


def _semantic_artifacts(root: Path, manifest: Mapping[str, Any]) -> tuple[_Artifact, ...]:
    if manifest.get("format") != _SEMANTIC_FORMAT:
        raise CandidateNativeBuildError("unsupported semantic-C package format")
    artifacts = _mapping(manifest.get("artifacts"), "semantic-C artifacts")
    required = {
        "runtime_header",
        "transfers_header",
        "generated_source",
        "repair_source",
        "dispatch_header",
        "dispatch_source",
        "engine_header",
        "engine_source",
        "api_adapters_header",
        "api_adapters_source",
        "api_adapters_report",
        "source_map",
        "runtime_obligations",
    }
    missing = required - set(artifacts)
    if missing:
        raise CandidateNativeBuildError(
            "semantic-C package omits artifacts: " + ", ".join(sorted(missing))
        )
    return tuple(
        _parse_artifact(root, "semantic", key, value)
        for key, value in sorted(artifacts.items())
    )


def _native_artifacts(root: Path, manifest: Mapping[str, Any]) -> tuple[_Artifact, ...]:
    if manifest.get("format") != _NATIVE_FORMAT:
        raise CandidateNativeBuildError("unsupported native-engine package format")
    result = [_parse_artifact(root, "native", "plan", manifest.get("plan"))]
    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise CandidateNativeBuildError("native-engine package has no source inventory")
    seen: set[str] = set()
    for index, value in enumerate(sources):
        artifact = _parse_artifact(root, "native", f"source_{index:03d}", value)
        if artifact.relative_path in seen:
            raise CandidateNativeBuildError("native-engine source inventory has duplicates")
        seen.add(artifact.relative_path)
        result.append(artifact)
    return tuple(result)


def _parse_artifact(root: Path, owner: str, key: str, value: Any) -> _Artifact:
    record = _mapping(value, f"{owner} artifact {key}")
    relative = _relative_path(record.get("path"), f"{owner} artifact {key} path")
    expected = _digest(record.get("sha256"), f"{owner} artifact {key} SHA-256")
    path = root / relative
    if not path.is_file():
        raise CandidateNativeBuildError(f"{owner} artifact {key} is missing: {relative}")
    observed = sha256_file(path)
    if observed != expected:
        raise CandidateNativeBuildError(f"{owner} artifact {key} has a stale SHA-256")
    return _Artifact(owner, key, relative.as_posix(), expected, path)


def _package_blockers(
    *,
    semantic: Mapping[str, Any],
    native: Mapping[str, Any],
    native_artifacts: Sequence[_Artifact],
    runtime_binding: Mapping[str, Any],
    entry_symbol: str,
) -> list[str]:
    blockers: list[str] = []
    inventory = semantic.get("transfer_inventory")
    if not isinstance(inventory, list) or not inventory:
        blockers.append("semantic transfer inventory is empty")
    elif any(
        not isinstance(row, Mapping) or row.get("implementation") == "repair_stub"
        for row in inventory
    ):
        blockers.append("semantic package contains repair stubs")
    strict = _mapping(semantic.get("strict_candidate"), "semantic strict-candidate state")
    raw_strict_blockers = strict.get("blockers")
    if not isinstance(raw_strict_blockers, list) or any(
        not isinstance(item, str) for item in raw_strict_blockers
    ):
        blockers.append("semantic strict-candidate blocker inventory is malformed")
    else:
        residual = set(raw_strict_blockers) - {"runtime_call_adapters_unbound"}
        if residual:
            blockers.append("semantic package is incomplete: " + ", ".join(sorted(residual)))
    if native.get("status") != "ready" or native.get("blockers") != []:
        blockers.append("native-engine package is not ready")
    if runtime_binding.get("status") != "ready":
        blockers.append("native runtime obligations are not exactly bound")

    source_texts: list[str] = []
    for artifact in native_artifacts:
        if artifact.path.suffix.lower() not in {".c", ".s", ".asm"}:
            continue
        try:
            text = artifact.path.read_text(encoding="ascii")
        except (OSError, UnicodeError):
            blockers.append(f"native source is not readable ASCII: {artifact.relative_path}")
            continue
        source_texts.append(text)
        if _PLACEHOLDER_INT3.search(text):
            blockers.append(f"placeholder INT3 bridge source: {artifact.relative_path}")
    escaped = re.escape(entry_symbol)
    has_entry = any(
        re.search(rf"(?m)^\s*_?{escaped}\s*:", text)
        or re.search(rf"\b{escaped}\s*\([^;{{}}]*\)\s*\{{", text)
        for text in source_texts
    )
    if not has_entry:
        blockers.append(f"native package does not define payload entry {entry_symbol}")
    return sorted(set(blockers))


def _compile_units(
    semantic: Sequence[_Artifact], native: Sequence[_Artifact]
) -> tuple[_Artifact, ...]:
    semantic_keys = {
        "generated_source", "repair_source", "dispatch_source", "engine_source"
    }
    selected = [item for item in semantic if item.key in semantic_keys]
    selected.extend(
        item
        for item in native
        if item.key != "plan" and item.path.suffix.lower() in {".c", ".s"}
    )
    if not selected:
        raise CandidateNativeBuildError("native build has no compilation units")

    def order(item: _Artifact) -> tuple[int, str, str]:
        if item.owner == "native" and item.path.suffix.lower() == ".s":
            return (0, item.relative_path, item.key)
        if item.owner == "native":
            return (1, item.relative_path, item.key)
        return (2, item.relative_path, item.key)

    return tuple(sorted(selected, key=order))


def _prepared_compile_units(
    prepared: Mapping[str, Any], semantic_root: Path, native_root: Path
) -> tuple[_Artifact, ...]:
    rows = prepared.get("compile_units")
    if not isinstance(rows, list) or not rows:
        raise CandidateNativeBuildError("prepare manifest has no compile units")
    result: list[_Artifact] = []
    for index, value in enumerate(rows):
        row = _mapping(value, f"compile unit {index}")
        owner = row.get("owner")
        if owner not in {"semantic", "native"}:
            raise CandidateNativeBuildError(f"compile unit {index} owner is malformed")
        root = semantic_root if owner == "semantic" else native_root
        result.append(_parse_artifact(root, owner, _string(row.get("key"), "compile key"), row))
    return tuple(result)


def _revalidate_prepared_packages(
    prepared: Mapping[str, Any], semantic_root: Path, native_root: Path
) -> None:
    inputs = _mapping(prepared.get("inputs"), "prepare inputs")
    for owner, root, manifest_name in (
        ("semantic_c_package", semantic_root, _SEMANTIC_MANIFEST),
        ("native_engine_package", native_root, _NATIVE_MANIFEST),
    ):
        binding = _mapping(inputs.get(owner), f"prepare {owner}")
        manifest = root / manifest_name
        if not manifest.is_file() or sha256_file(manifest) != binding.get("manifest_sha256"):
            raise CandidateNativeBuildError(f"{owner} manifest changed after preparation")
        rows = binding.get("artifacts")
        if not isinstance(rows, list):
            raise CandidateNativeBuildError(f"{owner} artifact binding is malformed")
        for index, row in enumerate(rows):
            parsed = _mapping(row, f"{owner} artifact binding {index}")
            artifact = root / _relative_path(parsed.get("path"), f"{owner} artifact path")
            if not artifact.is_file() or sha256_file(artifact) != parsed.get("sha256"):
                raise CandidateNativeBuildError(
                    f"{owner} artifact changed after preparation: {parsed.get('path')}"
                )


def _select_toolchain(compiler: Path | str) -> _Toolchain:
    requested = str(compiler)
    compiler_path = shutil.which(requested) if not Path(requested).is_absolute() else requested
    if compiler_path is None or not Path(compiler_path).is_file():
        raise CandidateNativeBuildError(f"selected MinGW compiler is unavailable: {compiler}")
    compiler_real = Path(compiler_path).resolve()
    target = _tool_output([str(compiler_real), "-dumpmachine"])
    if target != "i686-w64-mingw32":
        raise CandidateNativeBuildError(
            f"selected compiler target is {target!r}, expected i686-w64-mingw32"
        )
    prefix = Path(compiler_path).name.rsplit("gcc", 1)[0]
    def matching_tool(name: str) -> Path:
        path = shutil.which(prefix + name)
        if path is None:
            candidate = Path(compiler_path).parent / (prefix + name)
            path = str(candidate) if candidate.is_file() else None
        if path is None:
            raise CandidateNativeBuildError(
                f"selected MinGW toolchain has no matching {name}"
            )
        return Path(path).resolve()

    assembler_real = matching_tool("as")
    linker_real = matching_tool("ld")
    nm_real = matching_tool("nm")
    return _Toolchain(
        compiler=compiler_real,
        assembler=assembler_real,
        linker=linker_real,
        nm=nm_real,
        target=target,
        compiler_version=_tool_output(
            [str(compiler_real), "-dumpfullversion", "-dumpversion"]
        ),
        linker_version=_tool_output([str(compiler_real), "-Wl,--version"], first_line=True),
        compiler_sha256=sha256_file(compiler_real),
        assembler_sha256=sha256_file(assembler_real),
        linker_sha256=sha256_file(linker_real),
        nm_sha256=sha256_file(nm_real),
    )


def _revalidate_toolchain(prepared: Mapping[str, Any]) -> _Toolchain:
    binding = _mapping(prepared.get("toolchain"), "prepare toolchain")
    toolchain = _select_toolchain(_string(binding.get("compiler"), "compiler path"))
    if toolchain.payload() != dict(binding):
        raise CandidateNativeBuildError("selected toolchain changed after preparation")
    return toolchain


def _compile_flags(
    source_sha256: str, semantic_root: Path, native_root: Path
) -> list[str]:
    return [
        *_common_compile_flags(source_sha256),
        f"-ffile-prefix-map={semantic_root}=/candidate/semantic",
        f"-ffile-prefix-map={native_root}=/candidate/native",
        f"-fdebug-prefix-map={semantic_root}=/candidate/semantic",
        f"-fdebug-prefix-map={native_root}=/candidate/native",
        f"-fmacro-prefix-map={semantic_root}=/candidate/semantic",
        f"-fmacro-prefix-map={native_root}=/candidate/native",
    ]


def _canonical_compile_flags(source_sha256: str) -> list[str]:
    return [
        *_common_compile_flags(source_sha256),
        "-ffile-prefix-map=<semantic-package>=/candidate/semantic",
        "-ffile-prefix-map=<native-package>=/candidate/native",
        "-fdebug-prefix-map=<semantic-package>=/candidate/semantic",
        "-fdebug-prefix-map=<native-package>=/candidate/native",
        "-fmacro-prefix-map=<semantic-package>=/candidate/semantic",
        "-fmacro-prefix-map=<native-package>=/candidate/native",
    ]


def _common_compile_flags(source_sha256: str) -> list[str]:
    return [
        "-std=c11",
        "-Os",
        "-g0",
        "-ffreestanding",
        "-fno-builtin",
        "-fno-ident",
        "-fno-asynchronous-unwind-tables",
        "-fno-unwind-tables",
        "-fno-stack-protector",
        "-fno-exceptions",
        f"-frandom-seed={source_sha256}",
    ]


def _relocation_anchor_source(entry_symbol: str) -> str:
    entry = entry_symbol if entry_symbol.startswith("_") else "_" + entry_symbol
    return (
        ".section .stgbrel,\"dr\"\n"
        ".balign 4\n"
        ".globl _spx_payload_relocation_anchor\n"
        "_spx_payload_relocation_anchor:\n"
        f"  .long {entry}\n"
    )


def _link_flags(
    *,
    entry_symbol: str,
    image_base: int,
    payload_rva: int,
    section_alignment: int,
    file_alignment: int,
    linker_map: Path,
) -> list[str]:
    entry = entry_symbol if entry_symbol.startswith("_") else "_" + entry_symbol
    return [
        f"-Wl,--entry,{entry}",
        "-Wl,--subsystem,console",
        "-Wl,--exclude-all-symbols",
        "-Wl,--strip-all",
        "-Wl,--dynamicbase",
        "-Wl,--enable-reloc-section",
        "-Wl,--disable-auto-import",
        "-Wl,--disable-runtime-pseudo-reloc",
        "-Wl,--no-insert-timestamp",
        f"-Wl,--image-base,0x{image_base:x}",
        f"-Wl,--section-alignment,0x{section_alignment:x}",
        f"-Wl,--file-alignment,0x{file_alignment:x}",
        f"-Wl,--section-start,.text=0x{image_base + payload_rva:x}",
        f"-Wl,-Map,{linker_map}",
    ]


def _normalize_empty_import_directory(image: bytes) -> bytes:
    pe = _pe(image, "linked payload")
    optional = _optional_header(pe)
    directories = optional.DATA_DIRECTORY
    for index, label in (
        (_DIRECTORY_IAT, "IAT"),
        (_DIRECTORY_DELAY_IMPORT, "delay imports"),
        (_DIRECTORY_TLS, "TLS"),
    ):
        directory = directories[index]
        if int(directory.VirtualAddress) or int(directory.Size):
            pe.close()
            raise CandidateNativeBuildError(f"payload has forbidden {label}")
    import_directory = directories[_DIRECTORY_IMPORT]
    rva = int(import_directory.VirtualAddress)
    size = int(import_directory.Size)
    normalized = bytearray(image)
    if rva or size:
        if not rva or size != 20:
            pe.close()
            raise CandidateNativeBuildError("payload has a nonempty import directory")
        try:
            offset = pe.get_offset_from_rva(rva)
        except pefile.PEFormatError as exc:
            pe.close()
            raise CandidateNativeBuildError("payload import directory is unmapped") from exc
        if offset < 0 or offset + size > len(image) or any(image[offset : offset + size]):
            pe.close()
            raise CandidateNativeBuildError("payload has actual imported symbols")
        directory_offset = import_directory.get_file_offset()
        normalized[directory_offset : directory_offset + 8] = bytes(8)
    checksum_offset = optional.get_field_absolute_offset("CheckSum")
    normalized[checksum_offset : checksum_offset + 4] = bytes(4)
    pe.close()
    return bytes(normalized)


def _qualify_payload_pe(
    image: bytes,
    *,
    image_base: int,
    minimum_rva: int,
    section_alignment: int,
    file_alignment: int,
) -> pefile.PE:
    pe = _pe(image, "qualified payload")
    file_header = _file_header(pe)
    optional = _optional_header(pe)
    if int(file_header.Machine) != 0x14C or int(optional.Magic) != 0x10B:
        pe.close()
        raise CandidateNativeBuildError("payload architecture is not i386 PE32")
    if int(optional.ImageBase) != image_base:
        pe.close()
        raise CandidateNativeBuildError("payload image base differs from the prepared contract")
    if int(optional.SectionAlignment) != section_alignment:
        pe.close()
        raise CandidateNativeBuildError("payload section alignment changed")
    if int(optional.FileAlignment) != file_alignment:
        pe.close()
        raise CandidateNativeBuildError("payload file alignment changed")
    if not int(optional.DllCharacteristics) & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        pe.close()
        raise CandidateNativeBuildError("payload is not dynamically relocatable")
    directories = optional.DATA_DIRECTORY
    forbidden = (
        (_DIRECTORY_IMPORT, "imports"),
        (_DIRECTORY_TLS, "TLS"),
        (_DIRECTORY_IAT, "IAT"),
        (_DIRECTORY_DELAY_IMPORT, "delay imports"),
    )
    for index, label in forbidden:
        if int(directories[index].VirtualAddress) or int(directories[index].Size):
            pe.close()
            raise CandidateNativeBuildError(f"payload has forbidden {label}")
    relocation_directory = directories[_DIRECTORY_BASE_RELOCATION]
    relocation_present = bool(
        int(relocation_directory.VirtualAddress) or int(relocation_directory.Size)
    )
    relocations_stripped = bool(
        int(file_header.Characteristics) & _IMAGE_FILE_RELOCS_STRIPPED
    )
    if relocation_present == relocations_stripped:
        pe.close()
        raise CandidateNativeBuildError(
            "payload relocation directory disagrees with RELOCS_STRIPPED"
        )
    if not pe.sections:
        pe.close()
        raise CandidateNativeBuildError("payload has no sections")
    for section in pe.sections:
        rva = int(section.VirtualAddress)
        if rva < minimum_rva or rva % section_alignment:
            pe.close()
            raise CandidateNativeBuildError("payload has a section outside its high-RVA range")
    entry = int(optional.AddressOfEntryPoint)
    executable = [
        section
        for section in pe.sections
        if int(section.Characteristics) & _IMAGE_SCN_MEM_EXECUTE
        and int(section.VirtualAddress) <= entry
        < int(section.VirtualAddress) + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    ]
    if len(executable) != 1:
        pe.close()
        raise CandidateNativeBuildError("payload entry symbol is absent or non-executable")
    return pe


def _payload_relocation_inventory(
    pe: pefile.PE, image: bytes
) -> PayloadRelocationInventory:
    """Extract the complete PE32 HIGHLOW inventory from a qualified payload."""

    optional = _optional_header(pe)
    image_base = int(optional.ImageBase)
    directory = optional.DATA_DIRECTORY[_DIRECTORY_BASE_RELOCATION]
    directory_rva = int(directory.VirtualAddress)
    directory_size = int(directory.Size)
    if (directory_rva, directory_size) == (0, 0):
        return PayloadRelocationInventory(
            payload_sha256=sha256_bytes(image),
            image_base=image_base,
            relocations=(),
        )
    if not directory_rva or directory_size < 8:
        raise CandidateNativeBuildError(
            "payload base-relocation directory is partial or too small"
        )
    raw = _read_payload_rva(
        pe,
        image,
        directory_rva,
        directory_size,
        context="payload base-relocation directory",
    )
    relocations: list[PayloadRelocation] = []
    cursor = 0
    previous_page = -1
    seen_targets: set[int] = set()
    while cursor < len(raw):
        if len(raw) - cursor < 8:
            raise CandidateNativeBuildError(
                "payload base-relocation directory has a partial block"
            )
        page_rva, block_size = struct.unpack_from("<II", raw, cursor)
        if page_rva % 0x1000:
            raise CandidateNativeBuildError(
                "payload base-relocation block page is not 4 KiB aligned"
            )
        if page_rva <= previous_page:
            raise CandidateNativeBuildError(
                "payload base-relocation blocks are duplicated or unordered"
            )
        if block_size < 8 or block_size % 4 or cursor + block_size > len(raw):
            raise CandidateNativeBuildError(
                "payload base-relocation block has an invalid size"
            )
        slot_count = (block_size - 8) // 2
        slots = struct.unpack_from("<" + "H" * slot_count, raw, cursor + 8)
        for slot in slots:
            relocation_type = slot >> 12
            offset = slot & 0xFFF
            if relocation_type == 0:
                continue
            if relocation_type != 3:
                raise CandidateNativeBuildError(
                    "payload base-relocation directory contains unsupported "
                    f"PE32 relocation type {relocation_type}"
                )
            target_rva = page_rva + offset
            if target_rva in seen_targets:
                raise CandidateNativeBuildError(
                    "payload base-relocation target is duplicated"
                )
            preferred = int.from_bytes(
                _read_payload_rva(
                    pe,
                    image,
                    target_rva,
                    4,
                    context="payload HIGHLOW relocation target",
                ),
                "little",
            )
            seen_targets.add(target_rva)
            relocations.append(
                PayloadRelocation(rva=target_rva, preferred_value=preferred)
            )
        previous_page = page_rva
        cursor += block_size

    ordered = tuple(sorted(relocations, key=lambda item: item.rva))
    for previous, current in zip(ordered, ordered[1:]):
        if current.rva < previous.rva + previous.width:
            raise CandidateNativeBuildError(
                "payload HIGHLOW relocation target ranges overlap"
            )
    return PayloadRelocationInventory(
        payload_sha256=sha256_bytes(image),
        image_base=image_base,
        relocations=ordered,
    )


def _read_payload_rva(
    pe: pefile.PE,
    image: bytes,
    rva: int,
    size: int,
    *,
    context: str,
) -> bytes:
    matches = [
        section
        for section in pe.sections
        if int(section.VirtualAddress) <= rva
        and rva + size
        <= int(section.VirtualAddress) + int(section.SizeOfRawData)
    ]
    if len(matches) != 1:
        raise CandidateNativeBuildError(
            f"{context} is not contained by exactly one raw-backed section"
        )
    section = matches[0]
    offset = int(section.PointerToRawData) + rva - int(section.VirtualAddress)
    result = image[offset : offset + size]
    if len(result) != size:
        raise CandidateNativeBuildError(f"{context} raw bytes are truncated")
    return result


def _extract_engine_layout(
    pe: pefile.PE, image: bytes
) -> tuple[bytes, EngineLayout, tuple[int, str]]:
    matches: list[tuple[bytes, EngineLayout, int, str]] = []
    for section in pe.sections:
        characteristics = int(section.Characteristics)
        if characteristics & (_IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_WRITE):
            continue
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        data = image[raw_offset : raw_offset + raw_size]
        cursor = 0
        while True:
            found = data.find(SPX_ENGINE_LAYOUT_MAGIC_BYTES, cursor)
            if found < 0:
                break
            cursor = found + 1
            rva = int(section.VirtualAddress) + found
            if rva % 4 or found + 12 > len(data):
                continue
            total_words = struct.unpack_from("<I", data, found + 8)[0]
            byte_count = total_words * 4
            if byte_count <= 0 or found + byte_count > len(data):
                continue
            payload = data[found : found + byte_count]
            try:
                layout = parse_spx_engine_layout_payload(
                    payload,
                    expected_features=_EXPECTED_LAYOUT_FEATURES,
                    expected_x87_slot_count=_EXPECTED_X87_SLOTS,
                )
            except Exception:
                continue
            name = section.Name.rstrip(b"\0").decode("ascii", errors="strict")
            matches.append((payload, layout, rva, name))
    if len(matches) != 1:
        raise CandidateNativeBuildError(
            f"payload has {len(matches)} qualified compiler-materialized engine-layout tables"
        )
    payload, layout, rva, section_name = matches[0]
    return payload, layout, (rva, section_name)



def _unresolved_symbols(nm: Path, payload: Path, env: Mapping[str, str]) -> list[str]:
    completed = _run(
        [str(nm), "-u", str(payload)],
        phase="inspect unresolved payload symbols",
        env=env,
        capture=True,
    )
    result: list[str] = []
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        result.append(stripped.split()[-1])
    return sorted(set(result))


def _run(
    command: Sequence[str],
    *,
    phase: str,
    env: Mapping[str, str],
    capture: bool = False,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(command),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        cwd=cwd,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stdout[-3000:] + completed.stderr[-9000:]).strip()
        raise CandidateNativeBuildError(f"{phase} failed:\n{detail}")
    if not capture and completed.stderr.strip():
        warnings = completed.stderr.strip()
        if "warning:" in warnings.lower():
            raise CandidateNativeBuildError(f"{phase} emitted a warning:\n{warnings[-6000:]}")
    return completed


def _tool_output(command: Sequence[str], *, first_line: bool = False) -> str:
    completed = subprocess.run(
        list(command), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    if completed.returncode != 0:
        raise CandidateNativeBuildError(
            f"toolchain identity command failed: {' '.join(command)}"
        )
    value = completed.stdout.strip()
    if first_line:
        value = value.splitlines()[0] if value else ""
    if not value:
        raise CandidateNativeBuildError("toolchain identity command returned no output")
    return value


def _deterministic_environment() -> dict[str, str]:
    return {
        **os.environ,
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "1",
        "ZERO_AR_DATE": "1",
    }


def _require_pe32_contract(contract: LoadImageContract) -> None:
    identity = contract.identity
    if identity.machine != "i386" or identity.bitness != 32 or identity.pointer_width != 4:
        raise CandidateNativeBuildError("load-image contract is not i386 PE32")
    if not contract.completeness.complete:
        raise CandidateNativeBuildError("load-image contract is incomplete")


def _state_machine_sha256(manifest: Mapping[str, Any]) -> str:
    binding = _mapping(manifest.get("state_machine"), "semantic state-machine binding")
    return _digest(binding.get("sha256"), "semantic state-machine SHA-256")


def _load_closed_manifest(path: Path, expected_format: str, label: str) -> dict[str, Any]:
    payload = _read_json_object(path, label)
    if payload.get("format") != expected_format:
        raise CandidateNativeBuildError(f"unsupported {label} format")
    hashes = _mapping(payload.get("hashes"), f"{label} hashes")
    if hashes.get("algorithm") != "sha256":
        raise CandidateNativeBuildError(f"{label} hash algorithm is unsupported")
    expected = _digest(hashes.get("manifest_core_sha256"), f"{label} core SHA-256")
    core = {key: value for key, value in payload.items() if key != "hashes"}
    if _canonical_sha256(core) != expected:
        raise CandidateNativeBuildError(f"{label} deterministic hash does not close")
    return payload


def _close_manifest(core: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **core,
        "hashes": {
            "algorithm": "sha256",
            "manifest_core_sha256": _canonical_sha256(core),
        },
    }


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateNativeBuildError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateNativeBuildError(f"{label} must be a JSON object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256_bytes(encoded)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidateNativeBuildError(f"{label} must be an object")
    return value


def _relative_path(value: Any, label: str) -> Path:
    text = _string(value, label)
    path = Path(text)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateNativeBuildError(f"{label} must be a confined relative path")
    return path


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise CandidateNativeBuildError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateNativeBuildError(f"{label} must be a nonnegative integer")
    return value


def _u32(value: Any, label: str) -> int:
    result = _integer(value, label)
    if result > 0xFFFFFFFF:
        raise CandidateNativeBuildError(f"{label} does not fit uint32")
    return result


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CandidateNativeBuildError(f"{label} must be a nonempty string")
    return value


def _directory(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_dir():
        raise CandidateNativeBuildError(f"{label} is not a directory: {path}")
    return path.resolve()


def _file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise CandidateNativeBuildError(f"{label} is not a file: {path}")
    return path.resolve()


def _pe(data: bytes, label: str) -> pefile.PE:
    try:
        return pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        raise CandidateNativeBuildError(f"{label} is not a valid PE: {exc}") from exc


def _optional_header(pe: pefile.PE) -> Any:
    header = pe.OPTIONAL_HEADER
    if header is None:
        raise CandidateNativeBuildError("PE has no optional header")
    return header


def _file_header(pe: pefile.PE) -> Any:
    header = pe.FILE_HEADER
    if header is None:
        raise CandidateNativeBuildError("PE has no file header")
    return header


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise CandidateNativeBuildError("PE alignment is not a positive power of two")
    return (value + alignment - 1) & ~(alignment - 1)


__all__ = [
    "ENGINE_LAYOUT_FILENAME",
    "PAYLOAD_FILENAME",
    "PAYLOAD_MAP_FILENAME",
    "PAYLOAD_RELOCATION_INVENTORY_FILENAME",
    "CandidateNativeBuildError",
]
