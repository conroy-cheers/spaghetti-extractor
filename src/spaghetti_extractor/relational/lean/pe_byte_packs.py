"""Generate cacheable exact-PE byte-pack certificates for Lean consumers.

Payload modules contain only balanced local byte trees.  One authoritative PE
module assembles those trees and parses the PE metadata once.  Per-pack
derivation modules then prove structural locations in that authoritative tree.
Schedule modules import only the derivations intersecting their requested RVA
spans and reduce local pack trees instead of the complete PE.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from ...stage_binary import StageAInputError, _parse_stage_a_pe
from ...util import sha256_bytes, sha256_file, write_json
from .common import _lean_import_certificate, _lean_pe, _lean_relocations


PE_BYTE_PACK_FORMAT = "stage-a-relational-pe-byte-packs-v1"
PE_BYTE_PACK_SCHEDULE_FORMAT = "stage-a-relational-pe-byte-pack-schedule-v1"
DEFAULT_PE_BYTE_PACK_SIZE = 256 * 1024
DEFAULT_PE_BYTE_CHUNK_SIZE = 1024

_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_NAMESPACE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$")
_LEAN_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


class PEBytePackGenerationError(StageAInputError):
    """The requested exact byte-pack graph cannot be generated safely."""


@dataclass(frozen=True)
class PEBytePackSpan:
    """A named nonempty section-backed RVA span requested by one consumer."""

    name: str
    rva: int
    size: int


@dataclass(frozen=True)
class _Section:
    index: int
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return self.virtual_size or self.raw_size

    def lean(self) -> str:
        return (
            "{ virtualSize := "
            f"{self.virtual_size}, virtualAddress := {self.virtual_address}, "
            f"rawSize := {self.raw_size}, rawPointer := {self.raw_offset}, "
            f"characteristics := {self.characteristics} }}"
        )

    def payload(self) -> dict[str, int]:
        return {
            "index": self.index,
            "virtual_size": self.virtual_size,
            "virtual_address": self.virtual_address,
            "raw_size": self.raw_size,
            "raw_offset": self.raw_offset,
            "characteristics": self.characteristics,
        }


@dataclass(frozen=True)
class PEBytePack:
    index: int
    raw_offset: int
    size: int
    sha256: str
    payload_module: str
    certificate_module: str
    tree_name: str
    certificate_name: str

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.size

    def payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "raw_offset": self.raw_offset,
            "bytes": self.size,
            "sha256": self.sha256,
            "payload_module": self.payload_module,
            "certificate_module": self.certificate_module,
            "tree_name": self.tree_name,
            "certificate_name": self.certificate_name,
        }


@dataclass(frozen=True)
class PEBytePackInventory:
    source_path: Path
    source_sha256: str
    source_size: int
    module_prefix: str
    namespace: str
    authoritative_module: str
    authoritative_bytes_name: str
    authoritative_pe_name: str
    runtime_binding_prefix: str | None
    pack_size: int
    chunk_size: int
    size_of_headers: int
    size_of_image: int
    sections: tuple[_Section, ...]
    packs: tuple[PEBytePack, ...]
    modules: tuple[dict[str, Any], ...]
    standalone_modules: tuple[str, ...]

    @property
    def qualified_pe_name(self) -> str:
        return f"{self.namespace}.{self.authoritative_pe_name}"

    def payload(self) -> dict[str, Any]:
        return {
            "format": PE_BYTE_PACK_FORMAT,
            "source_sha256": self.source_sha256,
            "source_bytes": self.source_size,
            "module_prefix": self.module_prefix,
            "namespace": self.namespace,
            "authoritative_module": self.authoritative_module,
            "authoritative_bytes_name": self.authoritative_bytes_name,
            "authoritative_pe_name": self.authoritative_pe_name,
            "runtime_binding_prefix": self.runtime_binding_prefix,
            "pack_size": self.pack_size,
            "chunk_size": self.chunk_size,
            "size_of_headers": self.size_of_headers,
            "size_of_image": self.size_of_image,
            "sections": [section.payload() for section in self.sections],
            "packs": [pack.payload() for pack in self.packs],
            "modules": list(self.modules),
            "standalone_modules": list(self.standalone_modules),
            "authority": (
                "kernel-checked structural pack locations in one parsed "
                "authoritative PE ByteTree"
            ),
        }


@dataclass(frozen=True)
class PEBytePackScheduleInventory:
    module: str
    namespace: str
    spans: tuple[dict[str, Any], ...]
    imports: tuple[str, ...]
    source_sha256: str
    source_bytes: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": PE_BYTE_PACK_SCHEDULE_FORMAT,
            "module": self.module,
            "namespace": self.namespace,
            "spans": list(self.spans),
            "imports": list(self.imports),
            "source_sha256": self.source_sha256,
            "source_bytes": self.source_bytes,
        }


@dataclass(frozen=True)
class PEBytePackSpanProof:
    """One inline exact-span proof and the pack modules it requires."""

    source: str
    imports: tuple[str, ...]
    exact_theorem: str
    expected_name: str
    data: bytes
    raw_offset: int
    pack_indices: tuple[int, ...]


@dataclass(frozen=True)
class _Tree:
    size: int
    expression: str
    pack_index: int | None = None
    left: _Tree | None = None
    right: _Tree | None = None


@dataclass(frozen=True)
class _ResolvedSpan:
    request: PEBytePackSpan
    section: _Section
    raw_offset: int
    data: bytes
    pieces: tuple[tuple[PEBytePack, int, int], ...]


def _validate_identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise PEBytePackGenerationError(f"{label} is not a Lean identifier: {value!r}")
    return value


def _validate_namespace(value: str) -> str:
    if not _NAMESPACE.fullmatch(value):
        raise PEBytePackGenerationError(f"invalid Lean namespace: {value!r}")
    return value


def _definition_prefix(module_prefix: str) -> str:
    return module_prefix[0].lower() + module_prefix[1:]


def _lean_bytes(data: bytes) -> str:
    rows = [
        ", ".join(str(byte) for byte in data[offset : offset + 32])
        for offset in range(0, len(data), 32)
    ]
    return "[\n  " + ",\n  ".join(rows) + "\n]"


def _balanced_tree(parts: Sequence[tuple[int, str, int | None]]) -> _Tree:
    trees = [_Tree(size, expression, pack_index=index) for size, expression, index in parts]
    if not trees:
        return _Tree(0, ".empty")
    while len(trees) > 1:
        merged: list[_Tree] = []
        for index in range(0, len(trees), 2):
            if index + 1 == len(trees):
                merged.append(trees[index])
                continue
            left = trees[index]
            right = trees[index + 1]
            merged.append(
                _Tree(
                    left.size + right.size,
                    f"(.node {left.size + right.size} {left.size} "
                    f"{left.expression} {right.expression})",
                    left=left,
                    right=right,
                )
            )
        trees = merged
    return trees[0]


def _location_term(tree: _Tree, pack_index: int) -> str:
    if tree.pack_index == pack_index:
        return f"ByteTreePackAt.here {tree.expression}"
    if tree.left is not None and tree.right is not None:
        try:
            child = _location_term(tree.left, pack_index)
            return (
                "ByteTreePackAt.left "
                f"(left := {tree.left.expression}) (right := {tree.right.expression}) "
                f"rfl rfl ({child})"
            )
        except KeyError:
            child = _location_term(tree.right, pack_index)
            return (
                "ByteTreePackAt.right "
                f"(left := {tree.left.expression}) (right := {tree.right.expression}) "
                f"rfl rfl ({child})"
            )
    raise KeyError(pack_index)


def _write_text_if_changed(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == source:
            return
    except FileNotFoundError:
        pass
    path.write_text(source, encoding="utf-8")


def _module_row(name: str, role: str, source: str, **extra: Any) -> dict[str, Any]:
    encoded = source.encode("utf-8")
    return {
        "name": name,
        "role": role,
        "imports": _LEAN_IMPORT.findall(source),
        "source_bytes": len(encoded),
        "source_sha256": sha256_bytes(encoded),
        **extra,
    }


def _copy_kernel_closure(destination: Path) -> tuple[str, ...]:
    source_root = Path(__file__).parents[2] / "lean" / "StageA"
    pending = ["RelationalPEBytePacks"]
    copied: set[str] = set()
    while pending:
        module = pending.pop()
        if module in copied:
            continue
        source = source_root / f"{module}.lean"
        if not source.is_file():
            raise PEBytePackGenerationError(f"missing Lean kernel module: {source}")
        text = source.read_text(encoding="utf-8")
        _write_text_if_changed(destination / source.name, text)
        copied.add(module)
        pending.extend(_LEAN_IMPORT.findall(text))
    return tuple(sorted(copied))


def _payload_source(
    *, namespace: str, pack: PEBytePack, data: bytes, chunk_size: int
) -> str:
    chunks = [data[offset : offset + chunk_size] for offset in range(0, len(data), chunk_size)]
    chunk_names = [f"{pack.tree_name}Chunk{index:04d}" for index in range(len(chunks))]
    definitions = [
        f"def {name} : Bytes := {_lean_bytes(chunk)}"
        for name, chunk in zip(chunk_names, chunks, strict=True)
    ]
    tree = _balanced_tree(
        [
            (len(chunk), f"(.leaf {name})", None)
            for name, chunk in zip(chunk_names, chunks, strict=True)
        ]
    )
    definitions.append(f"def {pack.tree_name} : ByteTree :=\n  {tree.expression}")
    definitions.append(
        f"theorem {pack.tree_name}Length : {pack.tree_name}.length = {len(data)} := by\n"
        "  decide"
    )
    return f"""import StageA.Formal

namespace {namespace}

open StageA.Formal

set_option maxRecDepth 1000000

{chr(10).join(chr(10) + definition for definition in definitions).lstrip()}

end {namespace}
"""


def _authoritative_source(
    *,
    namespace: str,
    inventory_names: tuple[str, str],
    payload_modules: Sequence[str],
    tree: _Tree,
    pe_literal: str,
    runtime_binding_prefix: str | None,
    import_certificate_literal: str | None,
    relocations_literal: str | None,
) -> str:
    bytes_name, pe_name = inventory_names
    imports = "\n".join(
        ["import StageA.RelationalPEBytePacks"]
        + [f"import StageA.{module}" for module in payload_modules]
    )
    runtime_bindings = ""
    if runtime_binding_prefix is not None:
        if import_certificate_literal is None or relocations_literal is None:
            raise PEBytePackGenerationError(
                "runtime PE bindings require import and relocation literals"
            )
        runtime_bindings = f"""

def {runtime_binding_prefix}ImportCertificate : ImportTableCertificate :=
  {import_certificate_literal}

def {runtime_binding_prefix}Imports : List PEImport :=
  {runtime_binding_prefix}ImportCertificate.imports

def {runtime_binding_prefix}Relocations : List BaseRelocation :=
  {relocations_literal}
"""
    runtime_theorems = ""
    if runtime_binding_prefix is not None:
        runtime_theorems = f"""

theorem {runtime_binding_prefix}ImportsChecked :
    importTableValid {pe_name} {runtime_binding_prefix}ImportCertificate = true := by
  decide

/-- Import parsing is reduced once here, rather than in every schedule. -/
theorem {runtime_binding_prefix}ImportsParsed :
    parseImports {pe_name} = some {runtime_binding_prefix}Imports := by
  decide

theorem {runtime_binding_prefix}RelocationsParsed :
    parseRelocations {pe_name} = some {runtime_binding_prefix}Relocations := by
  decide
"""
    return f"""{imports}

namespace {namespace}

open StageA.Formal

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def {bytes_name} : ByteTree :=
  {tree.expression}

def {pe_name} : PE32 :=
  {pe_literal}
{runtime_bindings}

/-- The PE metadata is parsed once in the authoritative binding module. -/
theorem {pe_name}MetadataParsed :
    parsePEMetadataTree {bytes_name} = some {pe_name}.metadata := by
  decide

theorem {pe_name}Parsed : parsePE32Tree {bytes_name} = some {pe_name} := by
  simp [parsePE32Tree, {pe_name}MetadataParsed, PE32.metadata,
    PEMetadata.toPE32, {pe_name}]
{runtime_theorems}

end {namespace}
"""


def _certificate_source(
    *,
    namespace: str,
    authoritative_module: str,
    authoritative_pe_name: str,
    authoritative_bytes_name: str,
    pack: PEBytePack,
    location: str,
) -> str:
    return f"""import StageA.{authoritative_module}

namespace {namespace}

open StageA.Formal
open StageA.Relational
open StageA.Relational.PEBytePacks

set_option maxRecDepth 1000000

def {pack.certificate_name} : PEBytePackCertificate {authoritative_pe_name} := {{
  rawOffset := {pack.raw_offset}
  pack := {pack.tree_name}
  nonempty := by decide
  valid := by decide
  located := by
    simp only [{authoritative_pe_name}, {authoritative_bytes_name}]
    exact {location}
}}

/-- The aligned whole-pack equation is checked once in this derivation. -/
theorem {pack.certificate_name}WholeExact :
    {authoritative_pe_name}.bytes.readBytes {pack.raw_offset} {pack.size} =
      {pack.tree_name}.readBytes 0 {pack.size} := by
  exact {pack.certificate_name}.readBytes_eq 0 {pack.size} (by decide)

end {namespace}
"""


def generate_pe_byte_pack_bundle(
    *,
    pe_path: Path | str,
    out_dir: Path | str,
    module_prefix: str,
    namespace: str = "StageA.GeneratedRelational.PEBytePacks",
    pack_size: int = DEFAULT_PE_BYTE_PACK_SIZE,
    chunk_size: int = DEFAULT_PE_BYTE_CHUNK_SIZE,
    standalone: bool = True,
    authoritative_module: str | None = None,
    authoritative_bytes_name: str | None = None,
    authoritative_pe_name: str | None = None,
    runtime_binding_prefix: str | None = None,
) -> PEBytePackInventory:
    """Generate payload, authoritative-PE, and structural derivation modules."""

    source_path = Path(pe_path).resolve()
    destination = Path(out_dir)
    _validate_identifier(module_prefix, "module prefix")
    _validate_namespace(namespace)
    if pack_size <= 0 or chunk_size <= 0 or chunk_size > pack_size:
        raise PEBytePackGenerationError(
            "pack and chunk sizes must be positive, with chunk size at most pack size"
        )
    if not source_path.is_file() or source_path.is_symlink():
        raise PEBytePackGenerationError(f"PE is not a regular file: {source_path}")
    source_data = source_path.read_bytes()
    if not source_data:
        raise PEBytePackGenerationError("PE is empty")
    source_sha256 = sha256_bytes(source_data)

    definition_prefix = _definition_prefix(module_prefix)
    authoritative_module = _validate_identifier(
        authoritative_module or f"{module_prefix}PE", "authoritative module"
    )
    authoritative_bytes_name = _validate_identifier(
        authoritative_bytes_name or f"{definition_prefix}Bytes",
        "authoritative bytes name",
    )
    authoritative_pe_name = _validate_identifier(
        authoritative_pe_name or f"{definition_prefix}Pe",
        "authoritative PE name",
    )
    if runtime_binding_prefix is not None:
        runtime_binding_prefix = _validate_identifier(
            runtime_binding_prefix, "runtime binding prefix"
        )
    packs: list[PEBytePack] = []
    for index, raw_offset in enumerate(range(0, len(source_data), pack_size)):
        data = source_data[raw_offset : raw_offset + pack_size]
        packs.append(
            PEBytePack(
                index=index,
                raw_offset=raw_offset,
                size=len(data),
                sha256=sha256_bytes(data),
                payload_module=f"{module_prefix}BytePack{index:04d}",
                certificate_module=f"{module_prefix}BytePackCertificate{index:04d}",
                tree_name=f"{definition_prefix}BytePack{index:04d}",
                certificate_name=f"{definition_prefix}BytePackCertificate{index:04d}",
            )
        )

    binary = _parse_stage_a_pe(source_path)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise PEBytePackGenerationError("exact PE byte packs require i386 PE32")
        sections = tuple(
            _Section(
                index=index,
                virtual_size=int(sec.Misc_VirtualSize),
                virtual_address=int(sec.VirtualAddress),
                raw_size=int(sec.SizeOfRawData),
                raw_offset=int(sec.PointerToRawData),
                characteristics=int(sec.Characteristics),
            )
            for index, sec in enumerate(binary.pe.sections)
        )
        size_of_headers = binary.size_of_headers
        size_of_image = binary.size_of_image
        tree = _balanced_tree(
            [(pack.size, pack.tree_name, pack.index) for pack in packs]
        )
        pe_literal = _lean_pe(binary, authoritative_bytes_name)
        import_certificate_literal = (
            _lean_import_certificate(binary)
            if runtime_binding_prefix is not None
            else None
        )
        relocations_literal = (
            _lean_relocations(binary) if runtime_binding_prefix is not None else None
        )
        if sha256_file(source_path) != source_sha256:
            raise PEBytePackGenerationError("PE changed while byte packs were generated")
    finally:
        binary.pe.close()

    stage_a = destination / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    standalone_modules = _copy_kernel_closure(stage_a) if standalone else ()
    modules: list[dict[str, Any]] = []

    for pack in packs:
        data = source_data[pack.raw_offset : pack.raw_end]
        source = _payload_source(
            namespace=namespace, pack=pack, data=data, chunk_size=chunk_size
        )
        _write_text_if_changed(stage_a / f"{pack.payload_module}.lean", source)
        modules.append(
            _module_row(
                pack.payload_module,
                "byte-pack-payload",
                source,
                pack_index=pack.index,
                raw_offset=pack.raw_offset,
                bytes=pack.size,
                payload_sha256=pack.sha256,
            )
        )

    authoritative = _authoritative_source(
        namespace=namespace,
        inventory_names=(authoritative_bytes_name, authoritative_pe_name),
        payload_modules=[pack.payload_module for pack in packs],
        tree=tree,
        pe_literal=pe_literal,
        runtime_binding_prefix=runtime_binding_prefix,
        import_certificate_literal=import_certificate_literal,
        relocations_literal=relocations_literal,
    )
    _write_text_if_changed(stage_a / f"{authoritative_module}.lean", authoritative)
    modules.append(
        _module_row(
            authoritative_module,
            "authoritative-pe-binding",
            authoritative,
            parsed_once=True,
        )
    )

    for pack in packs:
        source = _certificate_source(
            namespace=namespace,
            authoritative_module=authoritative_module,
            authoritative_pe_name=authoritative_pe_name,
            authoritative_bytes_name=authoritative_bytes_name,
            pack=pack,
            location=_location_term(tree, pack.index),
        )
        _write_text_if_changed(stage_a / f"{pack.certificate_module}.lean", source)
        modules.append(
            _module_row(
                pack.certificate_module,
                "byte-pack-derivation",
                source,
                pack_index=pack.index,
                raw_offset=pack.raw_offset,
                bytes=pack.size,
            )
        )

    inventory = PEBytePackInventory(
        source_path=source_path,
        source_sha256=source_sha256,
        source_size=len(source_data),
        module_prefix=module_prefix,
        namespace=namespace,
        authoritative_module=authoritative_module,
        authoritative_bytes_name=authoritative_bytes_name,
        authoritative_pe_name=authoritative_pe_name,
        runtime_binding_prefix=runtime_binding_prefix,
        pack_size=pack_size,
        chunk_size=chunk_size,
        size_of_headers=size_of_headers,
        size_of_image=size_of_image,
        sections=sections,
        packs=tuple(packs),
        modules=tuple(modules),
        standalone_modules=tuple(
            [*standalone_modules, *(row["name"] for row in modules)]
        ),
    )
    write_json(destination / "pe-byte-packs.json", inventory.payload())
    return inventory


def _manifest_int(value: object, label: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise PEBytePackGenerationError(f"{label} must be an integer")
    if value < (1 if positive else 0):
        qualifier = "positive" if positive else "nonnegative"
        raise PEBytePackGenerationError(f"{label} must be {qualifier}")
    return value


def _manifest_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PEBytePackGenerationError(f"{label} must be a nonempty string")
    return value


def load_pe_byte_pack_inventory(
    manifest_path: Path | str, *, pe_path: Path | str
) -> PEBytePackInventory:
    """Reload an immutable pack inventory and rebind it to the exact PE file."""

    manifest = Path(manifest_path)
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PEBytePackGenerationError(
            f"cannot read PE byte-pack inventory {manifest}: {error}"
        ) from error
    if not isinstance(payload, dict) or payload.get("format") != PE_BYTE_PACK_FORMAT:
        raise PEBytePackGenerationError("unsupported PE byte-pack inventory format")

    source_path = Path(pe_path).resolve()
    if not source_path.is_file() or source_path.is_symlink():
        raise PEBytePackGenerationError(f"PE is not a regular file: {source_path}")
    source_size = _manifest_int(payload.get("source_bytes"), "source_bytes", positive=True)
    source_sha256 = _manifest_string(payload.get("source_sha256"), "source_sha256")
    source_data = source_path.read_bytes()
    if len(source_data) != source_size or sha256_bytes(source_data) != source_sha256:
        raise PEBytePackGenerationError(
            "PE does not match the byte-pack inventory source binding"
        )

    module_prefix = _validate_identifier(
        _manifest_string(payload.get("module_prefix"), "module_prefix"),
        "module prefix",
    )
    namespace = _validate_namespace(
        _manifest_string(payload.get("namespace"), "namespace")
    )
    authoritative_module = _validate_identifier(
        _manifest_string(payload.get("authoritative_module"), "authoritative_module"),
        "authoritative module",
    )
    authoritative_bytes_name = _validate_identifier(
        _manifest_string(
            payload.get("authoritative_bytes_name"), "authoritative_bytes_name"
        ),
        "authoritative bytes name",
    )
    authoritative_pe_name = _validate_identifier(
        _manifest_string(payload.get("authoritative_pe_name"), "authoritative_pe_name"),
        "authoritative PE name",
    )
    raw_runtime_prefix = payload.get("runtime_binding_prefix")
    if raw_runtime_prefix is not None:
        raw_runtime_prefix = _validate_identifier(
            _manifest_string(raw_runtime_prefix, "runtime_binding_prefix"),
            "runtime binding prefix",
        )
    pack_size = _manifest_int(payload.get("pack_size"), "pack_size", positive=True)
    chunk_size = _manifest_int(payload.get("chunk_size"), "chunk_size", positive=True)
    if chunk_size > pack_size:
        raise PEBytePackGenerationError("inventory chunk_size exceeds pack_size")

    raw_sections = payload.get("sections")
    if not isinstance(raw_sections, list) or not raw_sections:
        raise PEBytePackGenerationError("inventory sections must be a nonempty list")
    sections: list[_Section] = []
    for expected_index, raw in enumerate(raw_sections):
        if not isinstance(raw, dict):
            raise PEBytePackGenerationError("inventory section must be an object")
        index = _manifest_int(raw.get("index"), "section index")
        if index != expected_index:
            raise PEBytePackGenerationError("inventory section indices are not contiguous")
        sections.append(
            _Section(
                index=index,
                virtual_size=_manifest_int(raw.get("virtual_size"), "virtual_size"),
                virtual_address=_manifest_int(
                    raw.get("virtual_address"), "virtual_address"
                ),
                raw_size=_manifest_int(raw.get("raw_size"), "raw_size"),
                raw_offset=_manifest_int(raw.get("raw_offset"), "raw_offset"),
                characteristics=_manifest_int(
                    raw.get("characteristics"), "characteristics"
                ),
            )
        )

    raw_packs = payload.get("packs")
    if not isinstance(raw_packs, list) or not raw_packs:
        raise PEBytePackGenerationError("inventory packs must be a nonempty list")
    packs: list[PEBytePack] = []
    expected_offset = 0
    for expected_index, raw in enumerate(raw_packs):
        if not isinstance(raw, dict):
            raise PEBytePackGenerationError("inventory pack must be an object")
        index = _manifest_int(raw.get("index"), "pack index")
        raw_offset = _manifest_int(raw.get("raw_offset"), "pack raw_offset")
        size = _manifest_int(raw.get("bytes"), "pack bytes", positive=True)
        if index != expected_index or raw_offset != expected_offset:
            raise PEBytePackGenerationError(
                "inventory packs are not contiguous and zero based"
            )
        pack = PEBytePack(
            index=index,
            raw_offset=raw_offset,
            size=size,
            sha256=_manifest_string(raw.get("sha256"), "pack sha256"),
            payload_module=_validate_identifier(
                _manifest_string(raw.get("payload_module"), "payload_module"),
                "payload module",
            ),
            certificate_module=_validate_identifier(
                _manifest_string(
                    raw.get("certificate_module"), "certificate_module"
                ),
                "certificate module",
            ),
            tree_name=_validate_identifier(
                _manifest_string(raw.get("tree_name"), "tree_name"), "tree name"
            ),
            certificate_name=_validate_identifier(
                _manifest_string(raw.get("certificate_name"), "certificate_name"),
                "certificate name",
            ),
        )
        if pack.raw_end > source_size or sha256_bytes(
            source_data[pack.raw_offset : pack.raw_end]
        ) != pack.sha256:
            raise PEBytePackGenerationError(
                f"inventory pack {pack.index} does not match the PE"
            )
        packs.append(pack)
        expected_offset = pack.raw_end
    if expected_offset != source_size:
        raise PEBytePackGenerationError("inventory packs do not cover the whole PE")

    raw_modules = payload.get("modules")
    raw_standalone = payload.get("standalone_modules")
    if not isinstance(raw_modules, list) or not all(
        isinstance(row, dict) for row in raw_modules
    ):
        raise PEBytePackGenerationError("inventory modules must be a list of objects")
    if not isinstance(raw_standalone, list) or not all(
        isinstance(module, str) for module in raw_standalone
    ):
        raise PEBytePackGenerationError(
            "inventory standalone_modules must be a list of strings"
        )
    return PEBytePackInventory(
        source_path=source_path,
        source_sha256=source_sha256,
        source_size=source_size,
        module_prefix=module_prefix,
        namespace=namespace,
        authoritative_module=authoritative_module,
        authoritative_bytes_name=authoritative_bytes_name,
        authoritative_pe_name=authoritative_pe_name,
        runtime_binding_prefix=raw_runtime_prefix,
        pack_size=pack_size,
        chunk_size=chunk_size,
        size_of_headers=_manifest_int(payload.get("size_of_headers"), "size_of_headers"),
        size_of_image=_manifest_int(payload.get("size_of_image"), "size_of_image"),
        sections=tuple(sections),
        packs=tuple(packs),
        modules=tuple(dict(row) for row in raw_modules),
        standalone_modules=tuple(raw_standalone),
    )


def _resolve_span(
    inventory: PEBytePackInventory, request: PEBytePackSpan
) -> _ResolvedSpan:
    _validate_identifier(request.name, "span name")
    if request.rva < 0 or request.size <= 0:
        raise PEBytePackGenerationError(
            f"span {request.name} must have a nonnegative RVA and positive size"
        )
    if request.rva < inventory.size_of_headers:
        raise PEBytePackGenerationError(
            f"span {request.name} is in PE headers, not a unique section"
        )
    if request.rva > inventory.size_of_image or request.size > (
        inventory.size_of_image - request.rva
    ):
        raise PEBytePackGenerationError(f"span {request.name} exceeds SizeOfImage")
    matches = [
        sec
        for sec in inventory.sections
        if sec.virtual_address <= request.rva
        and request.size
        <= sec.virtual_address + sec.mapped_size - request.rva
    ]
    if len(matches) != 1:
        raise PEBytePackGenerationError(
            f"span {request.name} has {len(matches)} containing PE sections; expected one"
        )
    sec = matches[0]
    section_offset = request.rva - sec.virtual_address
    if section_offset > sec.raw_size or request.size > sec.raw_size - section_offset:
        raise PEBytePackGenerationError(
            f"span {request.name} reaches virtual zero-fill or exceeds section raw bytes"
        )
    raw_offset = sec.raw_offset + section_offset
    if raw_offset > inventory.source_size or request.size > inventory.source_size - raw_offset:
        raise PEBytePackGenerationError(f"span {request.name} exceeds the PE file")

    pieces: list[tuple[PEBytePack, int, int]] = []
    cursor = raw_offset
    remaining = request.size
    while remaining:
        matches = [pack for pack in inventory.packs if pack.raw_offset <= cursor < pack.raw_end]
        if len(matches) != 1:
            raise PEBytePackGenerationError(
                f"span {request.name} raw offset {cursor} has no unique pack"
            )
        pack = matches[0]
        relative = cursor - pack.raw_offset
        count = min(remaining, pack.size - relative)
        if count <= 0:
            raise PEBytePackGenerationError(f"span {request.name} made no pack progress")
        pieces.append((pack, relative, count))
        cursor += count
        remaining -= count

    with inventory.source_path.open("rb") as handle:
        handle.seek(raw_offset)
        data = handle.read(request.size)
    if len(data) != request.size:
        raise PEBytePackGenerationError(f"span {request.name} changed during generation")
    return _ResolvedSpan(request, sec, raw_offset, data, tuple(pieces))


def _slice_name(span: PEBytePackSpan, index: int) -> str:
    return f"{span.name}BytePackSlice{index:04d}"


def _chain_term(resolved: _ResolvedSpan, index: int = 0) -> str:
    if index == len(resolved.pieces):
        return f"PEBytePackSliceChain.nil {resolved.raw_offset + resolved.request.size}"
    name = _slice_name(resolved.request, index)
    return (
        f"PEBytePackSliceChain.cons {name} (by decide) "
        f"({_chain_term(resolved, index + 1)})"
    )


def _schedule_span_source(
    inventory: PEBytePackInventory,
    resolved: _ResolvedSpan,
    *,
    print_axioms: bool = True,
) -> str:
    request = resolved.request
    pe_name = inventory.authoritative_pe_name
    section_name = f"{request.name}Section"
    expected_name = f"{request.name}ExpectedBytes"
    checked_name = f"{request.name}RvaMappingChecked"
    exact_name = f"{request.name}ExactRvaBytes"
    lines = [
        f"def {section_name} : Section := {resolved.section.lean()}",
        f"def {expected_name} : Bytes := {_lean_bytes(resolved.data)}",
        "",
        f"theorem {checked_name} :",
        "    PESectionRvaSpanCertificate.checked",
        f"      {pe_name} {section_name} {request.rva} {request.size}",
        f"      {resolved.raw_offset} = true := by",
        "  decide",
        "",
    ]
    if len(resolved.pieces) == 1:
        pack, relative, _ = resolved.pieces[0]
        lines.extend(
            [
                f"theorem {request.name}PackRead :",
                f"    readExactSectionRvaSpan {pe_name} {request.rva} {request.size} =",
                f"      {pack.tree_name}.readBytes {relative} {request.size} := by",
                "  exact readExactSectionRvaSpan_eq_pack_of_checked",
                f"    {pack.certificate_name} {section_name} {request.rva}",
                f"    {request.size} {relative} (by decide) {checked_name}",
                "",
                f"theorem {exact_name} :",
                f"    readExactSectionRvaSpan {pe_name} {request.rva} {request.size} =",
                f"      some {expected_name} := by",
                f"  rw [{request.name}PackRead]",
                "  decide",
            ]
        )
    else:
        slice_names: list[str] = []
        for index, (pack, relative, count) in enumerate(resolved.pieces):
            name = _slice_name(request, index)
            slice_names.append(name)
            lines.extend(
                [
                    f"def {name} : PEBytePackSlice {pe_name} := {{",
                    f"  certificate := {pack.certificate_name}",
                    f"  offset := {relative}",
                    f"  size := {count}",
                    "  nonempty := by decide",
                    "  bounded := by decide",
                    "}",
                    "",
                ]
            )
        slices_name = f"{request.name}BytePackSlices"
        chain_name = f"{request.name}BytePackChain"
        lines.extend(
            [
                f"def {slices_name} : List (PEBytePackSlice {pe_name}) :=",
                "  [" + ", ".join(slice_names) + "]",
                "",
                f"theorem {chain_name} :",
                f"    PEBytePackSliceChain {pe_name} {resolved.raw_offset}",
                f"      {request.size} {slices_name} := by",
                f"  exact {_chain_term(resolved)}",
                "",
                f"theorem {request.name}PackRead :",
                f"    readExactSectionRvaSpan {pe_name} {request.rva} {request.size} =",
                f"      readPEBytePackSlices {slices_name} := by",
                "  exact readExactSectionRvaSpan_eq_slices_of_checked",
                f"    {section_name} {request.rva} {request.size} {resolved.raw_offset}",
                f"    {slices_name} {chain_name} {checked_name}",
                "",
                f"theorem {exact_name} :",
                f"    readExactSectionRvaSpan {pe_name} {request.rva} {request.size} =",
                f"      some {expected_name} := by",
                f"  rw [{request.name}PackRead]",
                "  decide",
            ]
        )
    if print_axioms:
        lines.extend(["", f"#print axioms {exact_name}"])
    return "\n".join(lines)


def _check_inventory_source(inventory: PEBytePackInventory) -> None:
    if (
        not inventory.source_path.is_file()
        or inventory.source_path.is_symlink()
        or inventory.source_path.stat().st_size != inventory.source_size
        or sha256_file(inventory.source_path) != inventory.source_sha256
    ):
        raise PEBytePackGenerationError(
            "authoritative PE changed after byte-pack generation"
        )


def render_pe_byte_pack_span_proof(
    inventory: PEBytePackInventory,
    *,
    span: PEBytePackSpan,
    print_axioms: bool = False,
) -> PEBytePackSpanProof:
    """Render a namespace-local proof for embedding in a generated consumer."""

    _check_inventory_source(inventory)
    resolved = _resolve_span(inventory, span)
    needed = tuple(sorted({pack.index for pack, _, _ in resolved.pieces}))
    return PEBytePackSpanProof(
        source=_schedule_span_source(
            inventory, resolved, print_axioms=print_axioms
        ),
        imports=tuple(inventory.packs[index].certificate_module for index in needed),
        exact_theorem=f"{span.name}ExactRvaBytes",
        expected_name=f"{span.name}ExpectedBytes",
        data=resolved.data,
        raw_offset=resolved.raw_offset,
        pack_indices=needed,
    )


def render_pe_byte_pack_schedule_source(
    inventory: PEBytePackInventory,
    *,
    module_name: str,
    spans: Iterable[PEBytePackSpan],
    namespace: str | None = None,
) -> tuple[str, PEBytePackScheduleInventory]:
    """Render one consumer module importing exactly its intersecting packs."""

    _validate_identifier(module_name, "schedule module")
    schedule_namespace = _validate_namespace(namespace or f"{inventory.namespace}.{module_name}")
    requests = tuple(spans)
    if not requests:
        raise PEBytePackGenerationError("a schedule must request at least one RVA span")
    _check_inventory_source(inventory)
    if len({request.name for request in requests}) != len(requests):
        raise PEBytePackGenerationError("schedule span names must be unique")
    resolved = tuple(_resolve_span(inventory, request) for request in requests)
    needed = sorted(
        {pack.index for span in resolved for pack, _, _ in span.pieces}
    )
    imports = tuple(inventory.packs[index].certificate_module for index in needed)
    source = (
        "\n".join(f"import StageA.{module}" for module in imports)
        + f"\n\nnamespace {schedule_namespace}\n\n"
        + "open StageA.Formal\n"
        + "open StageA.Relational.PEBytePacks\n"
        + f"open {inventory.namespace}\n\n"
        + "set_option maxRecDepth 1000000\n\n"
        + "\n\n".join(_schedule_span_source(inventory, span) for span in resolved)
        + f"\n\nend {schedule_namespace}\n"
    )
    encoded = source.encode("utf-8")
    schedule = PEBytePackScheduleInventory(
        module=module_name,
        namespace=schedule_namespace,
        spans=tuple(
            {
                "name": span.request.name,
                "rva": span.request.rva,
                "bytes": span.request.size,
                "raw_offset": span.raw_offset,
                "pack_indices": [pack.index for pack, _, _ in span.pieces],
                "sha256": sha256_bytes(span.data),
            }
            for span in resolved
        ),
        imports=imports,
        source_sha256=sha256_bytes(encoded),
        source_bytes=len(encoded),
    )
    return source, schedule


def generate_pe_byte_pack_schedule(
    inventory: PEBytePackInventory,
    *,
    out_dir: Path | str,
    module_name: str,
    spans: Iterable[PEBytePackSpan],
    namespace: str | None = None,
) -> PEBytePackScheduleInventory:
    """Write one exact-span consumer and its deterministic inventory."""

    source, schedule = render_pe_byte_pack_schedule_source(
        inventory, module_name=module_name, spans=spans, namespace=namespace
    )
    destination = Path(out_dir)
    _write_text_if_changed(destination / "StageA" / f"{module_name}.lean", source)
    write_json(destination / f"{module_name}.json", schedule.payload())
    return schedule


__all__ = [
    "DEFAULT_PE_BYTE_CHUNK_SIZE",
    "DEFAULT_PE_BYTE_PACK_SIZE",
    "PE_BYTE_PACK_FORMAT",
    "PE_BYTE_PACK_SCHEDULE_FORMAT",
    "PEBytePack",
    "PEBytePackGenerationError",
    "PEBytePackInventory",
    "PEBytePackScheduleInventory",
    "PEBytePackSpan",
    "PEBytePackSpanProof",
    "generate_pe_byte_pack_bundle",
    "generate_pe_byte_pack_schedule",
    "load_pe_byte_pack_inventory",
    "render_pe_byte_pack_schedule_source",
    "render_pe_byte_pack_span_proof",
]
