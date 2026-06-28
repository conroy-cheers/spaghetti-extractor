from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import capstone
from capstone.x86 import X86_OP_IMM
import pefile

from .roles import RoleDecision
from .util import entropy, sha256_bytes, sha256_file


IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

MACHINE_NAMES = {
    0x014C: "i386",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "arm64",
}

SUBSYSTEM_NAMES = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    7: "posix_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
    14: "xbox",
    16: "windows_boot_application",
}

RESOURCE_TYPES = {
    1: "cursor",
    2: "bitmap",
    3: "icon",
    4: "menu",
    5: "dialog",
    6: "string",
    7: "font_directory",
    8: "font",
    9: "accelerator",
    10: "rcdata",
    11: "message_table",
    12: "group_cursor",
    14: "group_icon",
    16: "version",
    24: "manifest",
}

BRANCH_PREFIXES = ("j",)
BLOCK_TERMINATORS = {
    "ret",
    "retf",
    "iret",
    "iretd",
    "iretq",
    "int",
    "syscall",
    "sysenter",
    "ud2",
}
PADDING_MNEMONICS = {
    "int3",
    "nop",
}


@dataclass(frozen=True)
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    flags: str
    sha256: str | None
    entropy: float
    executable: bool


@dataclass(frozen=True)
class ImportInfo:
    dll: str
    symbol: str | None
    ordinal: int | None
    hint: int | None
    thunk_rva: int | None


@dataclass(frozen=True)
class ExportInfo:
    symbol: str | None
    ordinal: int
    rva: int
    forwarder: str | None


@dataclass(frozen=True)
class ResourceInfo:
    type_name: str
    name: str
    language: str
    rva: int
    size: int
    sha256: str | None


@dataclass(frozen=True)
class FunctionSeed:
    rva: int
    name: str
    source: str
    confidence: str


@dataclass(frozen=True)
class BlockCandidate:
    rva_start: int
    rva_end: int
    source: str
    classification: str
    confidence: str


@dataclass(frozen=True)
class EdgeCandidate:
    from_rva: int
    to_rva: int
    edge_type: str
    source: str
    confidence: str


@dataclass(frozen=True)
class PEInfo:
    path: Path
    relative_path: str
    role: RoleDecision
    sha256: str
    size: int
    kind: str
    machine: str
    timestamp: int
    image_base: int
    entrypoint_rva: int
    size_of_image: int
    subsystem: str
    linker_version: str
    checksum: int
    sections: list[SectionInfo] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    function_seeds: list[FunctionSeed] = field(default_factory=list)


def is_pe_path(path: Path) -> bool:
    if path.suffix.lower() not in {".exe", ".dll", ".ocx", ".cpl", ".scr"}:
        return False
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def find_pe_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and is_pe_path(path))


def parse_pe(path: Path, root: Path, role: RoleDecision) -> PEInfo:
    pe = pefile.PE(str(path), fast_load=False)
    relative_path = path.relative_to(root).as_posix()
    file_header = pe.FILE_HEADER
    optional = pe.OPTIONAL_HEADER
    machine = MACHINE_NAMES.get(file_header.Machine, f"unknown_0x{file_header.Machine:04x}")
    kind = "dll" if file_header.IMAGE_FILE_DLL else "exe"
    linker_version = f"{optional.MajorLinkerVersion}.{optional.MinorLinkerVersion}"

    sections = [_section_info(section) for section in pe.sections]
    imports = _imports(pe)
    exports = _exports(pe)
    resources = _resources(pe)
    function_seeds = _function_seeds(optional.AddressOfEntryPoint, exports, kind)

    return PEInfo(
        path=path,
        relative_path=relative_path,
        role=role,
        sha256=sha256_file(path),
        size=path.stat().st_size,
        kind=kind,
        machine=machine,
        timestamp=file_header.TimeDateStamp,
        image_base=optional.ImageBase,
        entrypoint_rva=optional.AddressOfEntryPoint,
        size_of_image=optional.SizeOfImage,
        subsystem=SUBSYSTEM_NAMES.get(optional.Subsystem, f"unknown_{optional.Subsystem}"),
        linker_version=linker_version,
        checksum=optional.CheckSum,
        sections=sections,
        imports=imports,
        exports=exports,
        resources=resources,
        function_seeds=function_seeds,
    )


def executable_range_classification(role: RoleDecision) -> tuple[str, str]:
    if role.scope == "included" or role.scope == "candidate":
        return "unknown", "executable PE section awaiting Ghidra/static/dynamic disposition"
    if role.role == "source_available_external":
        return "source-available external", role.reason
    if role.role == "vendor_replaceable":
        return "vendor/replaceable", role.reason
    return "excluded tool/runtime", role.reason


def mapped_section_size(virtual_size: int, raw_size: int) -> int:
    """Return the RVA span Windows maps for a PE section.

    SizeOfRawData may be larger than VirtualSize because of file alignment; the
    raw tail is not part of the mapped executable image.
    """

    return virtual_size if virtual_size > 0 else raw_size


def discover_linear_blocks(path: Path) -> tuple[list[BlockCandidate], list[EdgeCandidate]]:
    pe = pefile.PE(str(path), fast_load=False)
    machine = pe.FILE_HEADER.Machine
    mode = capstone.CS_MODE_64 if machine == 0x8664 else capstone.CS_MODE_32
    dis = capstone.Cs(capstone.CS_ARCH_X86, mode)
    dis.detail = True

    blocks: list[BlockCandidate] = []
    edges: list[EdgeCandidate] = []
    image_base = pe.OPTIONAL_HEADER.ImageBase

    for section in pe.sections:
        characteristics = section.Characteristics
        if not (characteristics & IMAGE_SCN_MEM_EXECUTE):
            continue
        data = section.get_data()[: mapped_section_size(section.Misc_VirtualSize, section.SizeOfRawData)]
        section_rva = section.VirtualAddress
        offset = 0
        block_start: int | None = None
        last_end: int | None = None
        padding_start: int | None = None
        padding_end: int | None = None

        while offset < len(data):
            address = image_base + section_rva + offset
            insns = list(dis.disasm(data[offset : offset + 16], address, count=1))
            if not insns:
                if block_start is not None and last_end is not None and last_end > block_start:
                    blocks.append(_block(block_start, last_end))
                if padding_start is not None and padding_end is not None and padding_end > padding_start:
                    blocks.append(_padding_block(padding_start, padding_end))
                block_start = None
                last_end = None
                padding_start = None
                padding_end = None
                offset += 1
                continue

            insn = insns[0]
            insn_rva = insn.address - image_base
            if block_start is None and _is_padding_instruction(insn):
                if padding_start is None:
                    padding_start = insn_rva
                padding_end = insn_rva + insn.size
                offset += insn.size
                continue

            if padding_start is not None and padding_end is not None and padding_end > padding_start:
                blocks.append(_padding_block(padding_start, padding_end))
                padding_start = None
                padding_end = None

            if block_start is None:
                block_start = insn_rva
            last_end = insn_rva + insn.size
            offset += insn.size

            target = _direct_branch_target(insn, image_base)
            if target is not None:
                edge_type = "call" if insn.mnemonic.startswith("call") else "branch"
                edges.append(
                    EdgeCandidate(
                        from_rva=insn_rva,
                        to_rva=target,
                        edge_type=edge_type,
                        source="capstone-linear",
                        confidence="low",
                    )
                )

            if _ends_block(insn) or (last_end - block_start) >= 512:
                blocks.append(_block(block_start, last_end))
                block_start = None
                last_end = None

        if block_start is not None and last_end is not None and last_end > block_start:
            blocks.append(_block(block_start, last_end))
        if padding_start is not None and padding_end is not None and padding_end > padding_start:
            blocks.append(_padding_block(padding_start, padding_end))

    return _split_blocks_at_edge_targets(blocks, edges), edges


def _split_blocks_at_edge_targets(
    blocks: list[BlockCandidate],
    edges: list[EdgeCandidate],
) -> list[BlockCandidate]:
    targets = {edge.to_rva for edge in edges}
    if not targets:
        return blocks
    split: list[BlockCandidate] = []
    for block in blocks:
        if block.classification != "code":
            split.append(block)
            continue
        inner_targets = sorted(target for target in targets if block.rva_start < target < block.rva_end)
        if not inner_targets:
            split.append(block)
            continue
        boundaries = [block.rva_start, *inner_targets, block.rva_end]
        for start, end in zip(boundaries, boundaries[1:]):
            if end <= start:
                continue
            split.append(
                BlockCandidate(
                    rva_start=start,
                    rva_end=end,
                    source=block.source,
                    classification=block.classification,
                    confidence=block.confidence,
                )
            )
    return split


def _section_info(section: Any) -> SectionInfo:
    raw_name = section.Name.rstrip(b"\x00")
    name = raw_name.decode("utf-8", errors="replace") if raw_name else "<unnamed>"
    data = section.get_data()
    flags = _section_flags(section.Characteristics)
    return SectionInfo(
        name=name,
        virtual_address=section.VirtualAddress,
        virtual_size=section.Misc_VirtualSize,
        raw_pointer=section.PointerToRawData,
        raw_size=section.SizeOfRawData,
        characteristics=section.Characteristics,
        flags=",".join(flags),
        sha256=sha256_bytes(data) if data else None,
        entropy=entropy(data),
        executable=bool(section.Characteristics & IMAGE_SCN_MEM_EXECUTE),
    )


def _section_flags(characteristics: int) -> list[str]:
    flags: list[str] = []
    if characteristics & IMAGE_SCN_CNT_CODE:
        flags.append("code")
    if characteristics & IMAGE_SCN_MEM_EXECUTE:
        flags.append("execute")
    if characteristics & IMAGE_SCN_MEM_READ:
        flags.append("read")
    if characteristics & IMAGE_SCN_MEM_WRITE:
        flags.append("write")
    return flags or ["none"]


def _imports(pe: pefile.PE) -> list[ImportInfo]:
    result: list[ImportInfo] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("utf-8", errors="replace")
        for symbol in entry.imports:
            name = symbol.name.decode("utf-8", errors="replace") if symbol.name else None
            result.append(
                ImportInfo(
                    dll=dll,
                    symbol=name,
                    ordinal=symbol.ordinal,
                    hint=symbol.hint,
                    thunk_rva=symbol.address - pe.OPTIONAL_HEADER.ImageBase if symbol.address else None,
                )
            )
    return result


def _exports(pe: pefile.PE) -> list[ExportInfo]:
    result: list[ExportInfo] = []
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return result
    for symbol in directory.symbols:
        name = symbol.name.decode("utf-8", errors="replace") if symbol.name else None
        forwarder = symbol.forwarder.decode("utf-8", errors="replace") if symbol.forwarder else None
        result.append(ExportInfo(symbol=name, ordinal=symbol.ordinal, rva=symbol.address, forwarder=forwarder))
    return result


def _resources(pe: pefile.PE) -> list[ResourceInfo]:
    result: list[ResourceInfo] = []
    directory = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if directory is None:
        return result
    for type_entry in directory.entries:
        type_name = _resource_entry_name(type_entry, RESOURCE_TYPES)
        type_directory = getattr(type_entry, "directory", None)
        if type_directory is None:
            continue
        for name_entry in type_directory.entries:
            name = _resource_entry_name(name_entry, {})
            name_directory = getattr(name_entry, "directory", None)
            if name_directory is None:
                continue
            for lang_entry in name_directory.entries:
                data = getattr(lang_entry, "data", None)
                if data is None:
                    continue
                data_rva = data.struct.OffsetToData
                size = data.struct.Size
                blob = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                result.append(
                    ResourceInfo(
                        type_name=type_name,
                        name=name,
                        language=str(lang_entry.id),
                        rva=data_rva,
                        size=size,
                        sha256=sha256_bytes(blob) if blob else None,
                    )
                )
    return result


def _resource_entry_name(entry: Any, names: dict[int, str]) -> str:
    if getattr(entry, "name", None):
        return str(entry.name)
    return names.get(entry.id, str(entry.id))


def _function_seeds(entrypoint_rva: int, exports: list[ExportInfo], kind: str) -> list[FunctionSeed]:
    seeds: list[FunctionSeed] = []
    if entrypoint_rva:
        seeds.append(
            FunctionSeed(
                rva=entrypoint_rva,
                name="entrypoint" if kind == "exe" else "dll_entrypoint",
                source="pe-entrypoint",
                confidence="medium",
            )
        )
    for export in exports:
        name = export.symbol or f"ordinal_{export.ordinal}"
        seeds.append(FunctionSeed(rva=export.rva, name=name, source="pe-export", confidence="medium"))
    return seeds


def _ends_block(insn: Any) -> bool:
    mnemonic = insn.mnemonic.lower()
    return mnemonic.startswith(BRANCH_PREFIXES) or mnemonic.startswith("call") or mnemonic in BLOCK_TERMINATORS


def _is_padding_instruction(insn: Any) -> bool:
    return str(insn.mnemonic).lower() in PADDING_MNEMONICS


def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    mnemonic = insn.mnemonic.lower()
    if not (mnemonic.startswith("j") or mnemonic.startswith("call")):
        return None
    if not insn.operands or insn.operands[0].type != X86_OP_IMM:
        return None
    target = int(insn.operands[0].imm)
    if target < image_base:
        return None
    return target - image_base


def _block(start: int, end: int) -> BlockCandidate:
    return BlockCandidate(
        rva_start=start,
        rva_end=end,
        source="capstone-linear",
        classification="code",
        confidence="low",
    )


def _padding_block(start: int, end: int) -> BlockCandidate:
    return BlockCandidate(
        rva_start=start,
        rva_end=end,
        source="capstone-linear",
        classification="padding/alignment",
        confidence="medium",
    )
