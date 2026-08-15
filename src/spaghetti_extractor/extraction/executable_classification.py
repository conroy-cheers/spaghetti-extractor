"""Static map and executable-byte classification proposals."""

from __future__ import annotations

from collections import Counter
from bisect import bisect_left
from typing import Any

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ..pe32.model import BlockSide, ParsedPEImage, PEImport
from ..pe32.queries import executable_section_for_rva, section_for_rva
from ..static_program.semantics.support import (
    _is_conditional_jump,
)
from ..util import sha256_bytes


NORETURN_IMPORT_SYMBOLS = {
    "abort",
    "amsg_exit",
    "exit",
    "exitprocess",
    "terminateprocess",
}


def _incomplete_record(
    *,
    category: str,
    obligation_id: str,
    blocker: str,
    next_action: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": "incomplete",
        "status": "incomplete",
        "category": category,
        "obligation_id": obligation_id,
        "blocker": blocker,
        "next_action": next_action,
        "details": details or {},
    }


def _failure_record(
    *,
    category: str,
    obligation_id: str,
    blocker: str,
    original: Any,
    candidate: Any,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": "fail",
        "status": "fail",
        "category": category,
        "obligation_id": obligation_id,
        "blocker": blocker,
        "original": original,
        "candidate": candidate,
        "details": details or {},
    }








def _capstone_mode(binary: ParsedPEImage) -> int:
    return capstone.CS_MODE_64 if binary.bitness == 64 else capstone.CS_MODE_32

def _linker_function_issues(binary_name: str, functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not functions:
        issues.append(
            _incomplete_record(
                category="missing_linker_map_entries",
                obligation_id=f"map:{binary_name}:functions",
                blocker=f"{binary_name} linker map did not expose executable symbols",
                next_action="rebuild with linker map emission and unstripped symbols",
            )
        )
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(str(function["name"]), []).append(function)
    duplicates = {
        name: [
            {"rva_start": item["rva_start"], "rva_end": item["rva_end"], "aliases": item.get("aliases", [])}
            for item in entries
        ]
        for name, entries in by_name.items()
        if len(entries) > 1
    }
    if duplicates:
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=f"map:{binary_name}:duplicate-function-names",
                blocker=f"{binary_name} linker map contains duplicate primary function names",
                next_action="disambiguate duplicate linker-map symbols before accepting generated mappings",
                details={"functions": duplicates},
            )
        )
    seen_ranges: list[tuple[str, BlockSide]] = [
        (str(item["name"]), BlockSide(int(item["rva_start"]), int(item["rva_end"]))) for item in functions
    ]
    for overlap in _range_overlap_issues(binary_name, seen_ranges):
        issues.append(
            _incomplete_record(
                category="ambiguous_linker_map",
                obligation_id=overlap["obligation_id"],
                blocker=overlap["blocker"],
                next_action="fix linker-map function range recovery before generating a static analysis map",
                details=overlap,
            )
        )
    return issues





def _linker_function_import_thunk_evidence(binary: ParsedPEImage, function: dict[str, Any]) -> dict[str, Any] | None:
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



def _import_thunk_match_key(imported: PEImport) -> str:
    symbol = imported.symbol if imported.symbol is not None else f"ordinal-{imported.ordinal}"
    return f"{imported.dll}!{symbol}"











def _recover_basic_blocks(binary: ParsedPEImage, rva_start: int, rva_end: int) -> list[dict[str, Any]]:
    data = binary.pe.get_data(rva_start, rva_end - rva_start)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + rva_start))
    decoded = sum(int(insn.size) for insn in instructions)
    if not instructions or decoded != len(data):
        return [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

    insn_by_rva = {int(insn.address - binary.image_base): insn for insn in instructions}
    starts: set[int] = {rva_start}
    declared_roots = {binary.entrypoint_rva}
    if binary.tls_callback_rvas is not None:
        declared_roots.update(binary.tls_callback_rvas)
    if binary.exports is not None:
        declared_roots.update(
            exported.rva
            for exported in binary.exports
            if exported.kind == "code"
        )
    starts.update(
        root for root in declared_roots if rva_start <= root < rva_end
    )
    for insn in instructions:
        rva = int(insn.address - binary.image_base)
        next_rva = rva + int(insn.size)
        mnemonic = insn.mnemonic
        if _is_conditional_jump(mnemonic):
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
            if next_rva < rva_end:
                starts.add(next_rva)
        elif mnemonic in {"jmp", "ljmp"}:
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
        elif mnemonic == "call":
            target = _resolved_branch_target(binary, insn)
            if target is not None and rva_start <= target < rva_end:
                starts.add(target)
            if next_rva < rva_end:
                starts.add(next_rva)

    ordered_starts = [start for start in sorted(starts) if start in insn_by_rva]
    if not ordered_starts:
        return [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

    blocks: list[dict[str, Any]] = []
    instruction_rvas = sorted(insn_by_rva)
    for index, start in enumerate(ordered_starts):
        next_start = ordered_starts[index + 1] if index + 1 < len(ordered_starts) else rva_end
        block_end = next_start
        instruction_start = bisect_left(instruction_rvas, start)
        instruction_stop = bisect_left(
            instruction_rvas, next_start, lo=instruction_start
        )
        for insn_rva in instruction_rvas[instruction_start:instruction_stop]:
            insn = insn_by_rva[insn_rva]
            insn_end = insn_rva + int(insn.size)
            if _instruction_ends_basic_block(insn) or _is_noreturn_import_call(binary, insn):
                block_end = insn_end
                instruction_stop = bisect_left(
                    instruction_rvas, block_end, lo=instruction_start
                )
                break
        if block_end <= start:
            continue
        block_data = binary.pe.get_data(start, block_end - start)
        if _is_padding_bytes(binary, start, block_data):
            continue
        blocks.append(
            {
                "rva_start": start,
                "rva_end": block_end,
                "bytes_sha256": sha256_bytes(block_data),
                "match_key": {
                    "kind": "recovered_basic_block",
                    "function_rva_start": rva_start,
                    "function_rva_end": rva_end,
                    "block_index": len(blocks),
                    "instruction_count": instruction_stop - instruction_start,
                    "range_size": len(block_data),
                },
            }
        )
    return blocks or [_function_range_block(binary, rva_start, rva_end, data, len(instructions), decoded)]

def _function_range_block(
    binary: ParsedPEImage,
    rva_start: int,
    rva_end: int,
    data: bytes,
    instruction_count: int,
    decoded: int,
) -> dict[str, Any]:
    del binary
    return {
        "rva_start": rva_start,
        "rva_end": rva_end,
        "bytes_sha256": sha256_bytes(data),
        "match_key": {
            "kind": "linker_map_function_range",
            "instruction_count": instruction_count,
            "decoded_bytes": decoded,
            "range_size": len(data),
        },
    }


def _section_gap_code_blocks(
    binary_name: str,
    binary: ParsedPEImage,
    gaps: list[BlockSide],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    code_blocks: list[dict[str, Any]] = []
    waivers: list[dict[str, Any]] = []
    for gap_index, gap in enumerate(gaps):
        queue = [gap]
        seen: set[tuple[int, int]] = set()
        gap_block_index = 0
        while queue:
            span = queue.pop(0)
            span_key = (span.rva_start, span.rva_end)
            if span_key in seen or span.size <= 0:
                continue
            seen.add(span_key)
            data = binary.pe.get_data(span.rva_start, span.size)
            if len(data) != span.size:
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": span,
                        "bytes": data,
                        "match_key": {"kind": "unreadable_section_gap_fragment", "range_size": span.size, "read_bytes": len(data)},
                    }
                )
                gap_block_index += 1
                continue
            if _is_padding_bytes(binary, span.rva_start, data):
                waivers.append(_padding_waiver(binary_name, span))
                continue

            recovery_span = _decodable_prefix_before_padding_suffix(
                binary, span, data
            )
            recovered = [
                item
                for item in _recover_basic_blocks(
                    binary, recovery_span.rva_start, recovery_span.rva_end
                )
                if span.rva_start <= int(item["rva_start"]) < int(item["rva_end"]) <= span.rva_end
            ]
            recovered_ranges: list[BlockSide] = []
            for item in recovered:
                block = BlockSide(int(item["rva_start"]), int(item["rva_end"]))
                block_bytes = binary.pe.get_data(block.rva_start, block.size)
                recovered_ranges.append(block)
                if len(block_bytes) != block.size:
                    code_blocks.append(
                        {
                            "gap_index": gap_index,
                            "gap_block_index": gap_block_index,
                            "block": block,
                            "bytes": block_bytes,
                            "match_key": {
                                "kind": "unreadable_section_gap_fragment",
                                "range_size": block.size,
                                "read_bytes": len(block_bytes),
                            },
                        }
                    )
                    gap_block_index += 1
                    continue
                if _is_padding_bytes(binary, block.rva_start, block_bytes):
                    waivers.append(_padding_waiver(binary_name, block))
                    continue

                edge_padding, code_span, code_bytes = _trim_padding_edges(binary, block, block_bytes)
                for padding in edge_padding:
                    waivers.append(_padding_waiver(binary_name, padding))
                if code_span is None:
                    continue
                if _is_padding_bytes(binary, code_span.rva_start, code_bytes):
                    waivers.append(_padding_waiver(binary_name, code_span))
                    continue
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": code_span,
                        "bytes": code_bytes,
                        "match_key": {
                            **item["match_key"],
                            "trimmed_padding_prefix": code_span.rva_start - block.rva_start,
                            "trimmed_padding_suffix": block.rva_end - code_span.rva_end,
                        },
                    }
                )
                gap_block_index += 1

            if not recovered_ranges:
                code_blocks.append(
                    {
                        "gap_index": gap_index,
                        "gap_block_index": gap_block_index,
                        "block": span,
                        "bytes": data,
                        "match_key": {"kind": "unrecovered_section_gap_fragment", "range_size": span.size},
                    }
                )
                gap_block_index += 1
                continue

            for residue in _gaps(span.rva_start, span.rva_end, recovered_ranges):
                if residue.size > 0:
                    queue.append(residue)
    code_blocks.sort(key=lambda item: (item["block"].rva_start, item["block"].rva_end))
    return code_blocks, waivers

def _decodable_prefix_before_padding_suffix(
    binary: ParsedPEImage,
    span: BlockSide,
    data: bytes,
) -> BlockSide:
    """Keep an exact decode prefix when only verified tail padding is invalid."""

    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    instructions = list(dis.disasm(data, binary.image_base + span.rva_start))
    decoded = sum(int(instruction.size) for instruction in instructions)
    if decoded == len(data) or decoded <= 0:
        return span
    suffix = data[decoded:]
    suffix_start = span.rva_start + decoded
    if not _is_padding_bytes(binary, suffix_start, suffix):
        return span
    return BlockSide(span.rva_start, suffix_start)

def _trim_padding_edges(binary: ParsedPEImage, block: BlockSide, data: bytes) -> tuple[list[BlockSide], BlockSide | None, bytes]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + block.rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return [], block, data

    first_code_index = 0
    while first_code_index < len(instructions) and _is_padding_instruction(instructions[first_code_index]):
        first_code_index += 1
    if first_code_index == len(instructions):
        return [block], None, b""

    last_code_index = len(instructions) - 1
    while last_code_index > first_code_index and _is_padding_instruction(instructions[last_code_index]):
        last_code_index -= 1

    code_start = int(instructions[first_code_index].address - binary.image_base)
    last_code = instructions[last_code_index]
    code_end = int(last_code.address - binary.image_base) + int(last_code.size)
    padding: list[BlockSide] = []
    if block.rva_start < code_start:
        padding.append(BlockSide(block.rva_start, code_start))
    if code_end < block.rva_end:
        padding.append(BlockSide(code_end, block.rva_end))
    code_span = BlockSide(code_start, code_end)
    return padding, code_span, binary.pe.get_data(code_span.rva_start, code_span.size)

def _padding_waiver(binary_name: str, span: BlockSide) -> dict[str, Any]:
    return {
        "id": f"{binary_name}-padding-{span.rva_start:x}-{span.rva_end:x}",
        "binary": binary_name,
        "rva": span.rva_start,
        "size": span.size,
        "reason": "verified executable section gap is zero-fill or padding instructions",
    }


def _section_gaps(binary: ParsedPEImage, ranges: list[BlockSide]) -> dict[str, list[BlockSide]]:
    result: dict[str, list[BlockSide]] = {}
    executable_name_counts = Counter(
        section.name for section in binary.sections if section.executable
    )
    for section in binary.sections:
        if not section.executable:
            continue
        identity = (
            section.name
            if executable_name_counts[section.name] == 1
            else f"{section.name}@{section.rva_start:08x}"
        )
        result[identity] = _gaps(section.rva_start, section.rva_end, ranges)
    return result

def _is_padding_bytes(binary: ParsedPEImage, rva_start: int, data: bytes) -> bool:
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
    return all(_is_padding_instruction(insn) for insn in instructions)

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

def _range_overlap_issues(binary_name: str, ranges: list[tuple[str, BlockSide]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    ordered = sorted(ranges, key=lambda item: (item[1].rva_start, item[1].rva_end, item[0]))
    for left, right in zip(ordered, ordered[1:]):
        left_id, left_range = left
        right_id, right_range = right
        if left_range.rva_end > right_range.rva_start:
            issues.append(
                _failure_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:{binary_name}:overlap:{left_id}:{right_id}",
                    blocker=f"{binary_name} block mappings overlap",
                    original={"id": left_id, "rva_start": left_range.rva_start, "rva_end": left_range.rva_end},
                    candidate={"id": right_id, "rva_start": right_range.rva_start, "rva_end": right_range.rva_end},
                )
            )
    return issues

def _gaps(start: int, end: int, ranges: list[BlockSide]) -> list[BlockSide]:
    cursor = start
    gaps: list[BlockSide] = []
    for item in sorted(ranges, key=lambda entry: (entry.rva_start, entry.rva_end)):
        if item.rva_end <= start or item.rva_start >= end:
            continue
        clipped_start = max(start, item.rva_start)
        clipped_end = min(end, item.rva_end)
        if clipped_start > cursor:
            gaps.append(BlockSide(cursor, clipped_start))
        cursor = max(cursor, clipped_end)
    if cursor < end:
        gaps.append(BlockSide(cursor, end))
    return gaps

def _instruction_report(binary: ParsedPEImage, insn: Any) -> dict[str, Any]:
    return {
        "rva": int(insn.address - binary.image_base),
        "size": int(insn.size),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "bytes": bytes(insn.bytes).hex(),
    }

def _instruction_ends_basic_block(insn: Any) -> bool:
    mnemonic = insn.mnemonic
    return mnemonic in {"call", "ret", "jmp", "ljmp"} or _is_conditional_jump(mnemonic)


def _direct_branch_target(insn: Any, image_base: int) -> int | None:
    if len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    return int(operand.imm - image_base)

def _resolved_branch_target(binary: ParsedPEImage, insn: Any) -> int | None:
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
    pointer_section = section_for_rva(binary, pointer_rva)
    if (
        pointer_section is None
        or not pointer_section.readable
        or pointer_section.writable
    ):
        # A mapped image word is a runtime control value, not a direct edge,
        # when execution can replace it.  Import/IAT transfers are classified
        # separately before this resolver is used.
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
    if executable_section_for_rva(binary, target_rva) is None:
        return None
    return target_rva

def _external_import_call(binary: ParsedPEImage, insn: Any) -> PEImport | None:
    if insn.mnemonic != "call" or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_MEM:
        return _import_for_absolute_memory_operand(binary, operand)
    if operand.type == X86_OP_IMM:
        target_rva = int(operand.imm - binary.image_base)
        return _direct_import_thunk(binary, target_rva)
    return None


def _external_import_jump(binary: ParsedPEImage, insn: Any) -> PEImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_MEM:
        return _import_for_absolute_memory_operand(binary, operand)
    if operand.type == X86_OP_IMM:
        target_rva = int(operand.imm - binary.image_base)
        return _direct_import_thunk(binary, target_rva)
    return None

def _direct_import_jump_instruction(binary: ParsedPEImage, insn: Any) -> PEImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)

def _import_for_absolute_memory_operand(binary: ParsedPEImage, operand: Any) -> PEImport | None:
    thunk_rva = _absolute_mem_operand_rva(binary, operand)
    if thunk_rva is None:
        return None
    return _import_for_thunk_rva(binary, thunk_rva)

def _import_for_thunk_rva(binary: ParsedPEImage, thunk_rva: int) -> PEImport | None:
    for item in binary.imports:
        if item.thunk_rva == thunk_rva:
            return item
    return None

def _direct_import_thunk(binary: ParsedPEImage, target_rva: int) -> PEImport | None:
    if executable_section_for_rva(binary, target_rva) is None:
        return None
    data = binary.pe.get_data(target_rva, 16)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + target_rva))
    if not instructions:
        return None
    first = instructions[0]
    if first.mnemonic not in {"jmp", "ljmp"} or len(first.operands) != 1:
        return None
    operand = first.operands[0]
    if operand.type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, operand)

def _is_noreturn_import_call(binary: ParsedPEImage, insn: Any) -> bool:
    imported = _external_import_call(binary, insn)
    if imported is None:
        return False
    symbol = _normalized_import_symbol(imported.symbol)
    return symbol in NORETURN_IMPORT_SYMBOLS

def _normalized_import_symbol(symbol: str | None) -> str:
    if not symbol:
        return ""
    name = symbol.split("@", 1)[0]
    return name.lstrip("_").lower()

def _absolute_mem_operand_rva(binary: ParsedPEImage, operand: Any) -> int | None:
    mem = operand.mem
    if mem.base or mem.index:
        return None
    address = int(mem.disp)
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None
