from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from .pe import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    mapped_section_size,
)
from .util import sha256_bytes, sha256_file


STAGE_A_MODEL_ID = "x86-pe32-env-v1"
STAGE_A_X86_64_MODEL_ID = "x86_64-pe32plus-env-v1"
STAGE_A_MODEL_SPECS = {
    STAGE_A_MODEL_ID: {"architecture": "x86", "machine": "i386", "bitness": 32, "magic": 0x10B},
    STAGE_A_X86_64_MODEL_ID: {"architecture": "x86_64", "machine": "x86_64", "bitness": 64, "magic": 0x20B},
}


@dataclass(frozen=True)
class StageASection:
    name: str
    rva_start: int
    rva_end: int
    raw_pointer: int
    raw_size: int
    characteristics: int
    executable: bool
    readable: bool
    writable: bool
    contains_code: bool


@dataclass(frozen=True)
class StageAImport:
    dll: str
    symbol: str | None
    ordinal: int | None
    thunk_rva: int | None


@dataclass(frozen=True)
class StageABinary:
    path: Path
    sha256: str
    size: int
    machine: str
    bitness: int
    image_base: int
    entrypoint_rva: int
    size_of_image: int
    subsystem: str
    sections: tuple[StageASection, ...]
    imports: tuple[StageAImport, ...]
    pe: pefile.PE


@dataclass(frozen=True)
class BlockSide:
    rva_start: int
    rva_end: int

    @property
    def size(self) -> int:
        return self.rva_end - self.rva_start


class StageAInputError(ValueError):
    pass


def _artifact_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value).strip("-") or "artifact"


def _parse_stage_a_pe(path: Path) -> StageABinary:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as exc:  # pefile raises several non-public exception types.
        raise StageAInputError(f"{path} is not a parseable PE file: {exc}") from exc

    machine = pe.FILE_HEADER.Machine
    magic = pe.OPTIONAL_HEADER.Magic
    if machine == 0x014C and magic == 0x10B:
        machine_name = "i386"
        bitness = 32
    elif machine == 0x8664 and magic == 0x20B:
        machine_name = "x86_64"
        bitness = 64
    else:
        machine_name = f"0x{machine:04x}"
        magic_name = f"0x{magic:04x}"
        raise StageAInputError(f"{path} is out of model: expected x86 PE32 or x86_64 PE32+, got machine={machine_name} magic={magic_name}")

    imports = _imports(pe)
    sections = tuple(_stage_a_section(section) for section in pe.sections)
    return StageABinary(
        path=path,
        sha256=sha256_file(path),
        size=path.stat().st_size,
        machine=machine_name,
        bitness=bitness,
        image_base=int(pe.OPTIONAL_HEADER.ImageBase),
        entrypoint_rva=int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        size_of_image=int(pe.OPTIONAL_HEADER.SizeOfImage),
        subsystem=_subsystem_name(int(pe.OPTIONAL_HEADER.Subsystem)),
        sections=sections,
        imports=imports,
        pe=pe,
    )


def _stage_a_section(section: Any) -> StageASection:
    name = section.Name.rstrip(b"\0").decode("utf-8", errors="replace")
    rva_start = int(section.VirtualAddress)
    rva_end = rva_start + mapped_section_size(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    characteristics = int(section.Characteristics)
    return StageASection(
        name=name,
        rva_start=rva_start,
        rva_end=rva_end,
        raw_pointer=int(section.PointerToRawData),
        raw_size=int(section.SizeOfRawData),
        characteristics=characteristics,
        executable=bool(characteristics & IMAGE_SCN_MEM_EXECUTE),
        readable=bool(characteristics & IMAGE_SCN_MEM_READ),
        writable=bool(characteristics & IMAGE_SCN_MEM_WRITE),
        contains_code=bool(characteristics & IMAGE_SCN_CNT_CODE),
    )


def _imports(pe: pefile.PE) -> tuple[StageAImport, ...]:
    imports: list[StageAImport] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        for item in entry.imports:
            symbol = item.name.decode("utf-8", errors="replace") if item.name else None
            thunk_rva = int(item.address - pe.OPTIONAL_HEADER.ImageBase) if item.address is not None else None
            imports.append(StageAImport(dll=dll.lower(), symbol=symbol, ordinal=item.ordinal, thunk_rva=thunk_rva))
    return tuple(imports)


def _subsystem_name(value: int) -> str:
    names = {
        1: "native",
        2: "windows_gui",
        3: "windows_cui",
        7: "posix_cui",
        9: "windows_ce_gui",
    }
    return names.get(value, f"unknown_{value}")


def _parse_linker_map_functions(path: Path, binary: StageABinary) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise StageAInputError(f"cannot read linker map {path}: {exc}") from exc
    symbol_starts: dict[int, list[str]] = {}
    boundary_starts: set[int] = set()
    pending_text_section: str | None = None
    for line in text.splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is not None:
            rva, name = parsed
            if _executable_section_for_rva(binary, rva) is None:
                continue
            symbol_starts.setdefault(rva, [])
            if name not in symbol_starts[rva]:
                symbol_starts[rva].append(name)
            continue
        boundary = _parse_linker_map_text_boundary_line(line, binary)
        if boundary is not None:
            boundary_starts.add(boundary)
            fragment_symbol = _linker_map_text_fragment_symbol(line)
            if fragment_symbol is not None:
                symbol_starts.setdefault(boundary, [])
                if fragment_symbol not in symbol_starts[boundary]:
                    symbol_starts[boundary].append(fragment_symbol)
            pending_text_section = None
            continue
        continuation = _parse_linker_map_text_boundary_continuation_line(line, binary)
        if continuation is not None and pending_text_section is not None:
            boundary_starts.add(continuation)
            fragment_symbol = _linker_map_section_fragment_symbol(pending_text_section)
            if fragment_symbol is not None:
                symbol_starts.setdefault(continuation, [])
                if fragment_symbol not in symbol_starts[continuation]:
                    symbol_starts[continuation].append(fragment_symbol)
            pending_text_section = None
            continue
        text_section = _parse_linker_map_text_section_only_line(line)
        if text_section is not None:
            pending_text_section = text_section
            continue
        if line.strip():
            pending_text_section = None

    functions: list[dict[str, Any]] = []
    ordered = sorted(symbol_starts)
    range_boundaries = sorted(set(ordered) | boundary_starts)
    for rva in ordered:
        section = _executable_section_for_rva(binary, rva)
        if section is None:
            continue
        next_starts = [value for value in range_boundaries if value > rva and value <= section.rva_end]
        rva_end = next_starts[0] if next_starts else section.rva_end
        if rva_end <= rva:
            continue
        primary = _primary_symbol_name(symbol_starts[rva])
        functions.append(
            {
                "name": primary,
                "aliases": symbol_starts[rva],
                "rva_start": rva,
                "rva_end": rva_end,
                "section": section.name,
            }
        )
    return functions


def _parse_linker_map_text_boundary_line(line: str, binary: StageABinary) -> int | None:
    match = re.match(r"^\s*\.text\S*\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    rva = address - binary.image_base if address >= binary.image_base else address
    if _executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_boundary_continuation_line(line: str, binary: StageABinary) -> int | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    rva = address - binary.image_base if address >= binary.image_base else address
    if _executable_section_for_rva(binary, rva) is None:
        return None
    return rva


def _parse_linker_map_text_section_only_line(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\s*$", line)
    return match.group(1) if match is not None else None


def _linker_map_text_fragment_symbol(line: str) -> str | None:
    match = re.match(r"^\s*(\.text\S*)\b", line)
    if match is None:
        return None
    return _linker_map_section_fragment_symbol(match.group(1))


def _linker_map_section_fragment_symbol(section_name: str) -> str | None:
    if "$" not in section_name:
        return None
    fragment = section_name.split("$", 1)[1].strip()
    if not fragment or fragment.startswith("."):
        return None
    return fragment


def _parse_linker_map_symbol_line(line: str, binary: StageABinary) -> tuple[int, str] | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$", line)
    if match is None:
        return None
    address = int(match.group(1), 16)
    name = match.group(2)
    if name.startswith(".") or name in {"PROVIDE", "CREATE_OBJECT_SYMBOLS"}:
        return None
    rva = address - binary.image_base if address >= binary.image_base else address
    return rva, name


def _primary_symbol_name(names: list[str]) -> str:
    for name in names:
        if not name.startswith("__") and not name.startswith("___"):
            return name
    return names[0]


def _executable_section_for_rva(binary: StageABinary, rva: int) -> StageASection | None:
    for section in binary.sections:
        if section.executable and section.rva_start <= rva < section.rva_end:
            return section
    return None


def _executable_section_covering_range(binary: StageABinary, rva_start: int, rva_end: int) -> StageASection | None:
    if rva_end <= rva_start:
        return None
    for section in binary.sections:
        if section.executable and section.rva_start <= rva_start and rva_end <= section.rva_end:
            return section
    return None


def _capstone_mode(binary: StageABinary) -> int:
    return capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32


def _linker_function_match_key(name: str) -> str:
    value = name.strip()
    if value.startswith("@"):
        value = value[1:]
    if "@" in value:
        left, right = value.rsplit("@", 1)
        if right.isdigit():
            value = left
    return value.lstrip("_")


def _linker_function_import_thunk_evidence(binary: StageABinary, function: dict[str, Any]) -> dict[str, Any] | None:
    start = int(function["rva_start"])
    end = int(function["rva_end"])
    if end <= start:
        return None
    data = binary.pe.get_data(start, min(16, end - start))
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + start))
    if not instructions:
        return None
    first = instructions[0]
    if int(first.address - binary.image_base) != start:
        return None
    imported = _direct_import_jump_instruction(binary, first)
    if imported is None:
        return None
    thunk_end = start + int(first.size)
    if thunk_end > end:
        return None
    padding = binary.pe.get_data(thunk_end, end - thunk_end)
    if len(padding) != end - thunk_end or not _is_padding_bytes(binary, thunk_end, padding):
        return None
    return {
        "function": function,
        "block": BlockSide(start, thunk_end),
        "function_range": BlockSide(start, end),
        "import": imported,
        "signature_key": _import_thunk_match_key(imported),
        "instruction": _instruction_report(binary, first),
        "padding_sha256": sha256_bytes(padding),
    }


def _direct_cfg_edges(binary: StageABinary, side: BlockSide) -> list[dict[str, Any]]:
    data = binary.pe.get_data(side.rva_start, side.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + side.rva_start))
    if not instructions or sum(insn.size for insn in instructions) != len(data):
        return []
    last = instructions[-1]
    last_rva = int(last.address - binary.image_base)
    fallthrough_rva = last_rva + int(last.size)
    mnemonic = last.mnemonic
    if _is_conditional_jump(mnemonic):
        target = _resolved_branch_target(binary, last)
        if target is None:
            return []
        return [
            {"kind": "taken", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic},
            {"kind": "fallthrough", "target_rva": fallthrough_rva, "instruction_rva": last_rva, "mnemonic": mnemonic},
        ]
    if mnemonic in {"jmp", "ljmp"}:
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "jump", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "call":
        target = _resolved_branch_target(binary, last)
        return [] if target is None else [{"kind": "call", "target_rva": target, "instruction_rva": last_rva, "mnemonic": mnemonic}]
    if mnemonic == "ret":
        return []
    return [{"kind": "fallthrough", "target_rva": side.rva_end, "instruction_rva": last_rva, "mnemonic": mnemonic}]


def _is_padding_bytes(binary: StageABinary, rva_start: int, data: bytes) -> bool:
    if not data:
        return True
    if all(byte == 0 for byte in data):
        return True
    if all(byte in {0x00, 0x90, 0xCC} for byte in data):
        return True
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return False
    if all(_is_padding_instruction(insn) for insn in instructions):
        return True
    return _is_alignment_jump_over_padding(binary, BlockSide(rva_start, rva_start + len(data)), instructions)


def _is_padding_instruction(insn: Any) -> bool:
    if insn.mnemonic in {"nop", "int3"}:
        return True
    if insn.mnemonic != "lea" or len(insn.operands) != 2:
        return False
    destination, source = insn.operands
    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
        return False
    mem = source.mem
    return destination.reg == mem.base and not mem.index and mem.disp == 0


def _is_alignment_jump_over_padding(binary: StageABinary, span: BlockSide, instructions: list[Any]) -> bool:
    if not instructions:
        return False
    insn = instructions[0]
    if insn.mnemonic not in {"jmp", "ljmp"}:
        return False
    target = _resolved_branch_target(binary, insn)
    if target is None:
        return False
    insn_end = int(insn.address - binary.image_base) + int(insn.size)
    if target < insn_end:
        return False
    if target < span.rva_end and not all(_is_padding_instruction(item) for item in instructions[1:]):
        return False
    bridge_end = max(span.rva_end, target)
    section = _executable_section_covering_range(binary, span.rva_start, bridge_end)
    if section is None:
        return False
    skipped_start = insn_end
    skipped_end = target
    if skipped_start == skipped_end:
        return target == span.rva_end
    skipped = binary.pe.get_data(skipped_start, skipped_end - skipped_start)
    return len(skipped) == skipped_end - skipped_start and _is_padding_bytes(binary, skipped_start, skipped)


def _instruction_report(binary: StageABinary, insn: Any) -> dict[str, Any]:
    return {
        "rva": int(insn.address - binary.image_base),
        "size": int(insn.size),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": bytes(insn.bytes).hex(),
    }


def _import_thunk_match_key(imported: StageAImport) -> str:
    symbol = imported.symbol if imported.symbol is not None else f"ordinal-{imported.ordinal}"
    return f"{imported.dll}!{symbol}"


def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    return int(operand.imm - image_base)


def _resolved_branch_target(binary: StageABinary, insn: Any) -> int | None:
    target = _direct_branch_target(insn, binary.image_base)
    if target is not None:
        return target
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    pointer_rva = _absolute_mem_operand_rva(binary, operand)
    if pointer_rva is None:
        return None
    width = 8 if binary.bitness == 64 else 4
    data = binary.pe.get_data(pointer_rva, width)
    if len(data) != width:
        return None
    value = int.from_bytes(data, "little")
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        target_rva = value - binary.image_base
    elif 0 <= value < binary.size_of_image:
        target_rva = value
    else:
        return None
    if _executable_section_for_rva(binary, target_rva) is None:
        return None
    return target_rva


def _direct_import_jump_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)


def _import_for_absolute_memory_operand(binary: StageABinary, operand: Any) -> StageAImport | None:
    thunk_rva = _absolute_mem_operand_rva(binary, operand)
    if thunk_rva is None:
        return None
    for item in binary.imports:
        if item.thunk_rva == thunk_rva:
            return item
    return None


def _absolute_mem_operand_rva(binary: StageABinary, operand: Any) -> int | None:
    mem = operand.mem
    if mem.base or mem.index:
        return None
    address = int(mem.disp)
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None


def _is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic in {
        "ja",
        "jae",
        "jb",
        "jbe",
        "jc",
        "je",
        "jg",
        "jge",
        "jl",
        "jle",
        "jna",
        "jnae",
        "jnb",
        "jnbe",
        "jnc",
        "jne",
        "jng",
        "jnge",
        "jnl",
        "jnle",
        "jno",
        "jnp",
        "jns",
        "jnz",
        "jo",
        "jp",
        "jpe",
        "jpo",
        "js",
        "jz",
    }
