from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import capstone

from ..stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ..util import sha256_file, write_json
from .artifacts import read_json_object as _read_json
from .model import PURE_SEMANTIC_EXPR_OPERATIONS
from .schema import (
    EXTERNAL_ENVIRONMENT_PROFILE_FORMAT,
    FLAG_BITS,
    MACHINE_CALL_ABI_REGISTERS,
    MACHINE_CALL_ABI_TEMPLATES,
    MACHINE_CALL_DISPOSITIONS,
    MACHINE_CALL_MAX_ARGUMENT_WORDS,
    MACHINE_CALL_MEMORY_EFFECTS,
    MACHINE_CALL_RESULT_RELATIONS,
    MACHINE_CALL_RESULT_WORD_RELATIONS,
    MACHINE_CALL_WORLD_EFFECTS,
    PROTOCOL_CALLBACK_CONTROL_FORMAT,
    ProtocolCallbackControl,
    ProtocolCallbackControlState,
    REGISTERS,
    RELATION_CONTRACT_FORMAT,
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_OBSERVATIONS,
    RegionStatePredicate,
    SchemaError,
    STAGE_A_RELATIONAL_MODEL_ID,
    integer as _integer,
)


def _raw_base_relocations(binary: StageABinary) -> list[dict[str, int]]:
    directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    cursor = int(directory.VirtualAddress)
    stop = cursor + int(directory.Size)
    relocations: list[dict[str, int]] = []
    while cursor < stop:
        header = binary.pe.get_data(cursor, 8)
        if len(header) != 8:
            raise StageAInputError("truncated PE base-relocation block header")
        page_rva = int.from_bytes(header[0:4], "little")
        block_size = int.from_bytes(header[4:8], "little")
        if block_size < 8 or block_size % 2 != 0 or cursor + block_size > stop:
            raise StageAInputError("malformed PE base-relocation block size")
        entries = binary.pe.get_data(cursor + 8, block_size - 8)
        if len(entries) != block_size - 8:
            raise StageAInputError("truncated PE base-relocation entries")
        for offset in range(0, len(entries), 2):
            encoded = int.from_bytes(entries[offset:offset + 2], "little")
            relocations.append({
                "rva": page_rva + (encoded & 0x0FFF),
                "type": encoded >> 12,
            })
        cursor += block_size
    return relocations


def _load_contract(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    if payload.get("format") != RELATION_CONTRACT_FORMAT:
        raise StageAInputError(
            f"relation contract format must be {RELATION_CONTRACT_FORMAT}"
        )
    return payload


def _semantic_cutpoint_spans(
    original: StageABinary,
    candidate: StageABinary,
    original_span: dict[str, int],
    candidate_span: dict[str, int],
    block_id: str,
) -> list[tuple[dict[str, int], dict[str, int]]]:
    def decode(binary: StageABinary, span: dict[str, int]) -> list[Any]:
        data = binary.pe.get_data(span["rva_start"], span["size"])
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoded = list(disassembler.disasm(data, binary.image_base + span["rva_start"]))
        if not decoded or sum(int(instruction.size) for instruction in decoded) != len(data):
            raise StageAInputError(f"mapping block {block_id} does not decode exactly for semantic cutpoint projection")
        return decoded

    original_decoded = decode(original, original_span)
    candidate_decoded = decode(candidate, candidate_span)
    periodic = len(original_decoded) == len(candidate_decoded)

    def boundaries(binary: StageABinary, span: dict[str, int], decoded: list[Any]) -> list[int]:
        result = [0]
        for instruction_index, instruction in enumerate(decoded, start=1):
            semantic = instruction.mnemonic in {
                "rep movsd", "movsd", "div", "idiv", "lock cmpxchg",
            }
            bounded = periodic and instruction_index % 4 == 0
            if semantic or bounded:
                offset = int(instruction.address - binary.image_base - span["rva_start"] + instruction.size)
                if offset < span["size"] and offset != result[-1]:
                    result.append(offset)
        result.append(span["size"])
        return result

    original_boundaries = boundaries(original, original_span, original_decoded)
    candidate_boundaries = boundaries(candidate, candidate_span, candidate_decoded)
    if len(original_boundaries) != len(candidate_boundaries):
        raise StageAInputError(
            f"mapping block {block_id} has mismatched semantic cutpoint counts: "
            f"original={len(original_boundaries) - 2}, candidate={len(candidate_boundaries) - 2}"
        )
    result = []
    for index in range(len(original_boundaries) - 1):
        original_start = original_span["rva_start"] + original_boundaries[index]
        candidate_start = candidate_span["rva_start"] + candidate_boundaries[index]
        result.append((
            {"rva_start": original_start, "rva_end": original_span["rva_start"] + original_boundaries[index + 1], "size": original_boundaries[index + 1] - original_boundaries[index]},
            {"rva_start": candidate_start, "rva_end": candidate_span["rva_start"] + candidate_boundaries[index + 1], "size": candidate_boundaries[index + 1] - candidate_boundaries[index]},
        ))
    return result

def _assign_region_targets(
    regions: list[dict[str, Any]],
    code_targets: list[dict[str, int]],
    value_targets: list[dict[str, int]],
    padding: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
) -> None:
    value_target_ids_by_key: dict[tuple[int, int, int], int] = {
        (
            target["original_value"], target["candidate_value"],
            target.get("mapped_size", 0),
        ): target["id"]
        for target in value_targets
    }

    def intern_value_target(
        original_value: int,
        candidate_value: int,
        original_relocation_rva: int,
        candidate_relocation_rva: int,
        mapped_size: int,
    ) -> int:
        key = (
            original_value & 0xFFFFFFFF,
            candidate_value & 0xFFFFFFFF,
            mapped_size,
        )
        existing = value_target_ids_by_key.get(key)
        if existing is not None:
            return existing
        value_id = len(value_targets)
        value_targets.append({
            "id": value_id,
            "original_value": key[0],
            "candidate_value": key[1],
            "original_relocation_rva": original_relocation_rva,
            "candidate_relocation_rva": candidate_relocation_rva,
            "mapped_size": key[2],
        })
        value_target_ids_by_key[key] = value_id
        return value_id

    lookups = {
        "original": {target["original_rva"]: target["id"] for target in code_targets},
        "candidate": {target["candidate_rva"]: target["id"] for target in code_targets},
    }
    targets_by_id = {target["id"]: target for target in code_targets}
    starts = {
        side: sorted((region[side]["rva"], target["id"]) for region, target in zip(regions, code_targets, strict=True))
        for side in ("original", "candidate")
    }
    padding_by_side = {
        side: sorted(
            (item["rva"], item["rva"] + item["size"])
            for item in padding
            if item["side"] in {side, "both"}
        )
        for side in ("original", "candidate")
    }
    relocations = {}
    for side, binary in (("original", original), ("candidate", candidate)):
        relocations[side] = {
            relocation["rva"]
            for relocation in _raw_base_relocations(binary)
            if relocation["type"] == 3
        }

    def immutable_equal_span(original_value: int, candidate_value: int, size: int) -> bool:
        spans: list[bytes] = []
        for binary, absolute in ((original, original_value), (candidate, candidate_value)):
            if absolute < binary.image_base:
                return False
            rva = absolute - binary.image_base
            section = next((
                section for section in binary.sections
                if not section.writable and section.rva_start <= rva and rva + size <= section.rva_end
            ), None)
            if section is None:
                return False
            data = binary.pe.get_data(rva, size)
            if len(data) != size:
                return False
            spans.append(data)
        return spans[0] == spans[1]

    def resolve(side: str, rva: int) -> int | None:
        if rva in lookups[side]:
            return lookups[side][rva]
        for start, target_id in starts[side]:
            if start <= rva:
                continue
            cursor = rva
            for padding_start, padding_stop in padding_by_side[side]:
                if padding_stop <= cursor:
                    continue
                if padding_start != cursor:
                    break
                cursor = padding_stop
                if cursor == start:
                    aliases = targets_by_id[target_id].setdefault(f"{side}_aliases", [])
                    if rva not in aliases:
                        aliases.append(rva)
                    return target_id
                if cursor > start:
                    break
            return None
        return None

    def relocation_pointer_table(
        original_value: int,
        candidate_value: int,
    ) -> tuple[int, set[int], set[int]] | None:
        if original_value < original.image_base or candidate_value < candidate.image_base:
            return None
        original_rva = original_value - original.image_base
        candidate_rva = candidate_value - candidate.image_base
        target_ids: set[int] = set()
        value_ids: set[int] = set()
        offset = 0
        while offset < 65536:
            original_entry = original_rva + offset
            candidate_entry = candidate_rva + offset
            if original_entry not in relocations["original"] or candidate_entry not in relocations["candidate"]:
                break
            original_pointer = int(original.pe.get_dword_at_rva(original_entry) or 0)
            candidate_pointer = int(candidate.pe.get_dword_at_rva(candidate_entry) or 0)
            original_target = resolve("original", original_pointer - original.image_base)
            candidate_target = resolve("candidate", candidate_pointer - candidate.image_base)
            if original_target is not None and original_target == candidate_target:
                target_ids.add(original_target)
            elif original_pointer == candidate_pointer:
                pass
            else:
                original_pointer_rva = original_pointer - original.image_base
                candidate_pointer_rva = candidate_pointer - candidate.image_base
                original_section = next((
                    section for section in original.sections
                    if section.rva_start <= original_pointer_rva < section.rva_end
                ), None)
                candidate_section = next((
                    section for section in candidate.sections
                    if section.rva_start <= candidate_pointer_rva < section.rva_end
                ), None)
                if original_section is None or candidate_section is None:
                    break
                value_ids.add(intern_value_target(
                    original_pointer,
                    candidate_pointer,
                    original_entry,
                    candidate_entry,
                    0,
                ))
            offset += 4
        return (offset, target_ids, value_ids) if offset else None

    for region in regions:
        target_ids: set[int] = set()
        bounds: set[tuple[str, str, int]] = set()
        decoded_by_side: dict[str, list[Any]] = {}
        for side, binary in (("original", original), ("candidate", candidate)):
            span = region[side]
            continuation = span["rva"] + span["size"]
            if (target_id := resolve(side, continuation)) is not None:
                target_ids.add(target_id)
            data = binary.pe.get_data(span["rva"], span["size"])
            disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            disassembler.detail = True
            decoded = list(disassembler.disasm(data, binary.image_base + span["rva"]))
            decoded_by_side[side] = decoded
            for instruction in decoded:
                control_flow = instruction.mnemonic == "call" or instruction.mnemonic.startswith("j")
                for operand in instruction.operands:
                    if operand.type != capstone.x86.X86_OP_IMM:
                        continue
                    immediate_rva = int(instruction.address - binary.image_base + instruction.imm_offset)
                    if not control_flow and immediate_rva not in relocations[side]:
                        continue
                    target_rva = int(operand.imm) - binary.image_base
                    if (target_id := resolve(side, target_rva)) is not None:
                        target_ids.add(target_id)
        region["target_ids"] = sorted(target_ids)
        region_value_ids: set[int] = set()
        original_decoded = decoded_by_side.get("original", [])
        candidate_decoded = decoded_by_side.get("candidate", [])
        if len(original_decoded) == len(candidate_decoded):
            for original_instruction, candidate_instruction in zip(original_decoded, candidate_decoded, strict=True):
                original_immediates = {
                    operand_index: (int(operand.imm), int(original_instruction.address - original.image_base + original_instruction.imm_offset))
                    for operand_index, operand in enumerate(original_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_IMM
                    and int(original_instruction.address - original.image_base + original_instruction.imm_offset) in relocations["original"]
                }
                candidate_immediates = {
                    operand_index: (int(operand.imm), int(candidate_instruction.address - candidate.image_base + candidate_instruction.imm_offset))
                    for operand_index, operand in enumerate(candidate_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_IMM
                    and int(candidate_instruction.address - candidate.image_base + candidate_instruction.imm_offset) in relocations["candidate"]
                }
                for operand_index in sorted(original_immediates.keys() & candidate_immediates.keys()):
                    original_value, original_relocation_rva = original_immediates[operand_index]
                    candidate_value, candidate_relocation_rva = candidate_immediates[operand_index]
                    original_code = resolve("original", original_value - original.image_base)
                    candidate_code = resolve("candidate", candidate_value - candidate.image_base)
                    if original_code is not None and original_code == candidate_code:
                        target_ids.add(original_code)
                        continue
                    if original_value == candidate_value:
                        continue
                    region_value_ids.add(intern_value_target(
                        original_value,
                        candidate_value,
                        original_relocation_rva,
                        candidate_relocation_rva,
                        0,
                    ))

                original_memory = {
                    operand_index: (
                        int(operand.mem.disp) & 0xFFFFFFFF,
                        int(original_instruction.address - original.image_base + original_instruction.disp_offset),
                        int(operand.size),
                        original_instruction.reg_name(operand.mem.base) if operand.mem.base else None,
                        original_instruction.reg_name(operand.mem.index) if operand.mem.index else None,
                        int(operand.mem.scale),
                    )
                    for operand_index, operand in enumerate(original_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_MEM
                    and int(original_instruction.disp_offset) > 0
                    and int(original_instruction.address - original.image_base + original_instruction.disp_offset)
                        in relocations["original"]
                }
                candidate_memory = {
                    operand_index: (
                        int(operand.mem.disp) & 0xFFFFFFFF,
                        int(candidate_instruction.address - candidate.image_base + candidate_instruction.disp_offset),
                        int(operand.size),
                        candidate_instruction.reg_name(operand.mem.base) if operand.mem.base else None,
                        candidate_instruction.reg_name(operand.mem.index) if operand.mem.index else None,
                        int(operand.mem.scale),
                    )
                    for operand_index, operand in enumerate(candidate_instruction.operands)
                    if operand.type == capstone.x86.X86_OP_MEM
                    and int(candidate_instruction.disp_offset) > 0
                    and int(candidate_instruction.address - candidate.image_base + candidate_instruction.disp_offset)
                        in relocations["candidate"]
                }
                for operand_index in sorted(original_memory.keys() & candidate_memory.keys()):
                    (
                        original_value, original_relocation_rva, original_size,
                        original_base, original_index, original_scale,
                    ) = original_memory[operand_index]
                    (
                        candidate_value, candidate_relocation_rva, candidate_size,
                        candidate_base, candidate_index, candidate_scale,
                    ) = candidate_memory[operand_index]
                    if original_size <= 0 or original_size != candidate_size:
                        continue
                    if immutable_equal_span(original_value, candidate_value, original_size):
                        continue
                    mapped_size = original_size
                    table = relocation_pointer_table(original_value, candidate_value)
                    if original_value == candidate_value and table is None:
                        continue
                    if table is not None and table[0] >= original_size:
                        mapped_size, table_targets, table_values = table
                        target_ids.update(table_targets)
                        region_value_ids.update(table_values)
                        if (
                            original_base is None and candidate_base is None
                            and original_index in REGISTERS and candidate_index in REGISTERS
                            and original_scale == candidate_scale and original_scale > 0
                        ):
                            upper_exclusive = (mapped_size - original_size) // original_scale + 1
                            bounds.add((original_index, candidate_index, upper_exclusive))
                    region_value_ids.add(intern_value_target(
                        original_value,
                        candidate_value,
                        original_relocation_rva,
                        candidate_relocation_rva,
                        mapped_size,
                    ))
        region["target_ids"] = sorted(target_ids)
        region["value_target_ids"] = sorted(region_value_ids)
        region["bounds"] = [
            {"original": original_reg, "candidate": candidate_reg, "unsigned_lt": upper}
            for original_reg, candidate_reg, upper in sorted(bounds)
        ]


def _terminal_return_address_pairs(
    regions: list[dict[str, Any]],
    code_targets: list[dict[str, Any]],
    padding: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
) -> list[dict[str, int]]:
    """Propose paired final-padding return words for later Lean checking."""
    target_lookup = {
        side: {
            int(rva): int(target["id"])
            for target in code_targets
            for rva in (
                int(target[f"{side}_rva"]),
                *(int(value) for value in target.get(f"{side}_aliases", [])),
            )
        }
        for side in ("original", "candidate")
    }
    padding_by_side = {
        side: {
            int(span["rva"]): int(span["size"])
            for span in padding
            if span.get("side") in {side, "both"}
            and _integer(span.get("rva")) is not None
            and _integer(span.get("size")) is not None
        }
        for side in ("original", "candidate")
    }
    proposed: list[dict[str, int]] = []
    seen: set[tuple[int, int]] = set()
    for region_index, region in enumerate(regions):
        calls: dict[str, tuple[int, int]] = {}
        for side, binary in (("original", original), ("candidate", candidate)):
            span = region[side]
            data = binary.pe.get_data(int(span["rva"]), int(span["size"]))
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            decoder.detail = True
            instructions = list(decoder.disasm(
                data, binary.image_base + int(span["rva"])
            ))
            if not instructions or instructions[-1].mnemonic != "call":
                calls = {}
                break
            instruction = instructions[-1]
            immediates = [
                operand for operand in instruction.operands
                if operand.type == capstone.x86.X86_OP_IMM
            ]
            if len(immediates) != 1:
                calls = {}
                break
            target_rva = int(immediates[0].imm) - binary.image_base
            target_id = target_lookup[side].get(target_rva)
            return_rva = int(instruction.address + instruction.size) - binary.image_base
            if (
                target_id is None
                or return_rva in target_lookup[side]
                or return_rva not in padding_by_side[side]
                or padding_by_side[side][return_rva] <= 0
            ):
                calls = {}
                break
            calls[side] = (target_id, return_rva)
        if set(calls) != {"original", "candidate"}:
            continue
        original_target, original_return = calls["original"]
        candidate_target, candidate_return = calls["candidate"]
        if original_target != candidate_target:
            continue
        key = (original_return, candidate_return)
        if key in seen:
            continue
        seen.add(key)
        proposed.append({
            "id": len(proposed),
            "caller_region_index": region_index,
            "callee_target_id": original_target,
            "original_rva": original_return,
            "candidate_rva": candidate_return,
            "original_padding_size": padding_by_side["original"][original_return],
            "candidate_padding_size": padding_by_side["candidate"][candidate_return],
        })
    return proposed

def stage_a_generate_relation_contract(
    *,
    original: Path,
    candidate: Path,
    mapping: Path,
    external_profile: Path | list[Path] | tuple[Path, ...] | None = None,
    out: Path,
) -> dict[str, Any]:
    original_bin = _parse_stage_a_pe(Path(original))
    candidate_bin = _parse_stage_a_pe(Path(candidate))
    mapping_payload = _read_json(Path(mapping))
    blocks = mapping_payload.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        raise StageAInputError("block mapping must contain a non-empty blocks list")
    pairs = [{"original": register, "candidate": register} for register in sorted(REGISTERS)]
    code_targets: list[dict[str, int]] = []
    value_targets: list[dict[str, int]] = []
    regions: list[dict[str, Any]] = []
    padding: list[dict[str, Any]] = []
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise StageAInputError(f"mapping block {index} must be an object")
        block_id = str(block.get("id") or f"region-{index}")
        original_span = _span(block.get("original"))
        candidate_span = _span(block.get("candidate"))
        if original_span is None or candidate_span is None:
            raise StageAInputError(f"mapping block {block_id} has malformed spans")
        if block.get("kind", "code") == "code":
            source = block.get("source") if isinstance(block.get("source"), dict) else {}
            root_evidence = block.get("root") if isinstance(block.get("root"), dict) else {}
            function_id = str(
                source.get("function")
                or (
                    root_evidence.get("symbol")
                    if root_evidence.get("kind") == "linker_map_function"
                    else ""
                )
                or ""
            )
            function_block_index = _integer(source.get("function_block_index"))
            checked_function_entry = bool(
                root_evidence.get("checked")
                and root_evidence.get("kind") == "linker_map_function"
            )
            split_spans = _semantic_cutpoint_spans(
                original_bin, candidate_bin, original_span, candidate_span, block_id
            )
            for split_index, (original_split, candidate_split) in enumerate(split_spans):
                target_id = len(code_targets)
                code_targets.append({
                    "id": target_id,
                    "original_rva": original_split["rva_start"],
                    "candidate_rva": candidate_split["rva_start"],
                })
                region = {
                    "id": block_id if len(split_spans) == 1 else f"{block_id}~cut-{split_index}",
                    "root": (
                        original_split["rva_start"] == original_bin.entrypoint_rva
                        and candidate_split["rva_start"] == candidate_bin.entrypoint_rva
                    ),
                    "original": {"rva": original_split["rva_start"], "size": original_split["size"]},
                    "candidate": {"rva": candidate_split["rva_start"], "size": candidate_split["size"]},
                    "inputs": pairs,
                    "outputs": pairs,
                }
                if function_id:
                    region["function_id"] = function_id
                if function_block_index is not None and function_block_index >= 0:
                    region["function_block_index"] = function_block_index
                    region["function_cut_index"] = split_index
                if checked_function_entry and split_index == 0:
                    region["function_entry"] = True
                    region["function_root_kind"] = "linker_map_function"
                    region["function_root_symbol"] = str(
                        root_evidence.get("symbol") or function_id
                    )
                regions.append(region)
        else:
            padding.extend([
                {"id": f"{block_id}-original", "side": "original", "rva": original_span["rva_start"], "size": original_span["size"]},
                {"id": f"{block_id}-candidate", "side": "candidate", "rva": candidate_span["rva_start"], "size": candidate_span["size"]},
            ])
    waivers = mapping_payload.get("waivers", [])
    if not isinstance(waivers, list):
        raise StageAInputError("mapping waivers must be a list")
    for index, waiver in enumerate(waivers):
        if not isinstance(waiver, dict):
            raise StageAInputError(f"mapping waiver {index} must be an object")
        span = _span(waiver)
        side = waiver.get("binary")
        if span is None or side not in {"original", "candidate", "both"}:
            raise StageAInputError(f"mapping waiver {index} has malformed span or binary side")
        padding.append({
            "id": str(waiver.get("id") or f"waiver-{index}"),
            "side": side,
            "rva": span["rva_start"],
            "size": span["size"],
        })
    _assign_region_targets(regions, code_targets, value_targets, padding, original_bin, candidate_bin)
    terminal_return_addresses = _terminal_return_address_pairs(
        regions, code_targets, padding, original_bin, candidate_bin
    )
    contract = {
        "format": RELATION_CONTRACT_FORMAT,
        "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
        "observations": RELATIONAL_OBSERVATIONS,
        "memory_relation": {"mode": "identity"},
        "code_targets": code_targets,
        "value_targets": value_targets,
        "terminal_return_addresses": terminal_return_addresses,
        "regions": regions,
        "padding": padding,
        "provenance": {
            "kind": "untrusted_block_map_projection",
            "mapping_sha256": sha256_file(Path(mapping)),
        },
    }
    profile_summaries: list[dict[str, Any]] = []
    profile_issues: list[dict[str, Any]] = []
    if external_profile is None:
        external_profile_paths: list[Path] = []
    elif isinstance(external_profile, (str, Path)):
        external_profile_paths = [Path(external_profile)]
    else:
        external_profile_paths = [Path(path) for path in external_profile]
    if external_profile_paths:
        machine_contracts, profile_summaries, profile_issues = (
            _select_external_profile_set_contracts(
                external_profile_paths, original_bin, candidate_bin
            )
        )
        contract["machine_import_call_contracts"] = machine_contracts
    normalized, normalization_issues = _normalize_contract(
        contract, original_bin, candidate_bin
    )
    issues = profile_issues + normalization_issues
    payload = contract if issues else normalized
    write_json(Path(out), payload)
    result = {
        "format": "stage-a-relation-contract-generation-v1",
        "status": "generated" if not issues else "incomplete",
        "out": str(out),
        "counts": {
            "regions": len(regions),
            "code_targets": len(code_targets),
            "value_targets": len(value_targets),
            "padding": len(padding),
            "machine_import_call_contracts": len(
                contract.get("machine_import_call_contracts", [])
            ),
        },
        "issues": issues,
    }
    if len(profile_summaries) == 1:
        result["external_profile"] = profile_summaries[0]
    if profile_summaries:
        result["external_profiles"] = profile_summaries
        result["external_profile_set"] = {
            "format": "stage-a-external-environment-profile-set-v1",
            "ids": [summary["id"] for summary in profile_summaries],
            "selected_contracts": len(
                contract.get("machine_import_call_contracts", [])
            ),
        }
    return result


def _select_external_profile_set_contracts(
    paths: list[Path],
    original: StageABinary,
    candidate: StageABinary,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    seen_profile_ids: dict[str, Path] = {}
    seen_imports: dict[tuple[str, str, str | int], str] = {}
    for path in paths:
        contracts, summary, profile_issues = _select_external_profile_contracts(
            path, original, candidate
        )
        summaries.append(summary)
        issues.extend(profile_issues)
        profile_id = str(summary["id"])
        prior_path = seen_profile_ids.get(profile_id)
        if prior_path is not None:
            issues.append({
                "category": "external_environment_profile_id_duplicate",
                "severity": "hard",
                "profile_id": profile_id,
                "paths": [str(prior_path), str(path)],
                "next_action": "compose profiles with unique stable ids",
            })
        else:
            seen_profile_ids[profile_id] = path
        for contract in contracts:
            identity = _import_identity(contract.get("import"))
            if identity is None:
                continue
            normalized_identity = (identity[0].lower(), identity[1], identity[2])
            prior_profile = seen_imports.get(normalized_identity)
            if prior_profile is not None:
                issues.append({
                    "category": "external_environment_profile_import_duplicate",
                    "severity": "hard",
                    "import": contract["import"],
                    "profiles": [prior_profile, profile_id],
                    "next_action": (
                        "declare each imported call in exactly one composed profile"
                    ),
                })
                continue
            seen_imports[normalized_identity] = profile_id
            selected.append(dict(contract))
    for contract_id, contract in enumerate(selected):
        contract["id"] = contract_id
    return selected, summaries, issues


def _select_external_profile_contracts(
    path: Path,
    original: StageABinary,
    candidate: StageABinary,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
    payload = _read_json(path)
    issues: list[dict[str, Any]] = []
    profile_id = payload.get("id")
    raw_contracts = payload.get("machine_import_call_contracts")
    if payload.get("format") != EXTERNAL_ENVIRONMENT_PROFILE_FORMAT:
        issues.append({
            "category": "external_environment_profile_format_mismatch",
            "severity": "hard",
            "expected": EXTERNAL_ENVIRONMENT_PROFILE_FORMAT,
            "observed": payload.get("format"),
        })
    if not isinstance(profile_id, str) or not profile_id:
        issues.append({
            "category": "external_environment_profile_id_missing",
            "severity": "hard",
        })
        profile_id = "invalid"
    if not isinstance(raw_contracts, list):
        issues.append({
            "category": "external_environment_profile_contracts_not_list",
            "severity": "hard",
        })
        raw_contracts = []

    selected = _machine_import_call_contracts(
        raw_contracts,
        original,
        candidate,
        issues,
        select_common_imports=True,
    )

    def binary_imports(binary: StageABinary) -> set[tuple[str, str, str | int]]:
        return {
            (identity[0].lower(), identity[1], identity[2])
            for imported in binary.imports
            if (identity := _import_identity(imported)) is not None
        }

    common_imports = binary_imports(original).intersection(binary_imports(candidate))
    covered_imports = {
        identity
        for contract in selected
        if (identity := _import_identity(contract.get("import"))) is not None
    }

    def rendered(identity: tuple[str, str, str | int]) -> dict[str, Any]:
        result: dict[str, Any] = {"dll": identity[0]}
        result[identity[1]] = identity[2]
        return result

    summary = {
        "format": EXTERNAL_ENVIRONMENT_PROFILE_FORMAT,
        "id": profile_id,
        "sha256": sha256_file(path),
        "declared_contracts": len(raw_contracts),
        "selected_contracts": len(selected),
        "ignored_contracts": len(raw_contracts) - len(selected),
        "common_imports": len(common_imports),
        "covered_common_imports": len(covered_imports),
        "uncovered_common_imports": [
            rendered(identity) for identity in sorted(common_imports - covered_imports)
        ],
    }
    return selected, summary, issues

def _normalize_contract(contract: dict[str, Any], original: StageABinary, candidate: StageABinary) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    allowed_fields = {
        "format", "model", "environment", "observations", "memory_relation",
        "code_targets", "value_targets", "terminal_return_addresses",
        "static_dynamic_pointer_slots",
        "static_word_relation_slots",
        "machine_import_call_contracts", "protocol_callback_control", "launch", "regions",
        "padding", "provenance",
    }
    unknown_fields = sorted(set(contract) - allowed_fields)
    if unknown_fields:
        issues.append({
            "category": "unknown_relation_contract_fields",
            "severity": "hard",
            "fields": unknown_fields,
            "next_action": (
                "remove unknown fields or introduce a versioned relation-contract schema"
            ),
        })
    if original.bitness != 32 or candidate.bitness != 32:
        issues.append({"category": "unsupported_bitness", "expected": 32})
    environment = contract.get("environment")
    if not isinstance(environment, dict) or environment.get("id") != RELATIONAL_ENVIRONMENT_ID:
        issues.append({
            "category": "environment_contract_missing",
            "severity": "hard",
            "expected": RELATIONAL_ENVIRONMENT_ID,
            "next_action": "declare the adversarial external environment contract",
        })
    observations = contract.get("observations")
    if observations != RELATIONAL_OBSERVATIONS:
        issues.append({
            "category": "observation_contract_mismatch",
            "severity": "hard",
            "expected": RELATIONAL_OBSERVATIONS,
            "observed": observations,
            "next_action": "use the complete v3 externally observable event set",
        })
        observations = RELATIONAL_OBSERVATIONS
    memory_relation = contract.get("memory_relation")
    if not isinstance(memory_relation, dict) or memory_relation.get("mode") not in {
        "identity", "mapped_objects", "relational_world",
    }:
        issues.append({
            "category": "memory_relation_missing",
            "severity": "hard",
            "expected": {"mode": "identity"},
            "next_action": "declare the relation between original and candidate data addresses",
        })
        memory_relation = {"mode": "identity"}
    targets = contract.get("code_targets")
    value_targets = contract.get("value_targets", [])
    terminal_return_addresses = contract.get("terminal_return_addresses", [])
    static_dynamic_pointer_slots = contract.get("static_dynamic_pointer_slots", [])
    static_word_relation_slots = contract.get("static_word_relation_slots", [])
    machine_import_call_contracts = contract.get("machine_import_call_contracts", [])
    protocol_callback_control = contract.get(
        "protocol_callback_control", ProtocolCallbackControl.empty().to_payload()
    )
    regions = contract.get("regions")
    padding = contract.get("padding", [])
    if not isinstance(targets, list) or not targets:
        issues.append({"category": "code_targets_missing"})
        targets = []
    if not isinstance(regions, list) or not regions:
        issues.append({"category": "regions_missing"})
        regions = []
    if not isinstance(value_targets, list):
        issues.append({"category": "value_targets_not_list"})
        value_targets = []
    if not isinstance(terminal_return_addresses, list):
        issues.append({"category": "terminal_return_addresses_not_list"})
        terminal_return_addresses = []
    if not isinstance(static_dynamic_pointer_slots, list):
        issues.append({
            "category": "static_dynamic_pointer_slots_not_list",
            "severity": "hard",
        })
        static_dynamic_pointer_slots = []
    if not isinstance(static_word_relation_slots, list):
        issues.append({
            "category": "static_word_relation_slots_not_list",
            "severity": "hard",
        })
        static_word_relation_slots = []
    if not isinstance(machine_import_call_contracts, list):
        issues.append({
            "category": "machine_import_call_contracts_not_list",
            "severity": "hard",
        })
        machine_import_call_contracts = []
    if (
        not isinstance(protocol_callback_control, dict)
        or set(protocol_callback_control) != {"format", "states"}
        or protocol_callback_control.get("format")
            != PROTOCOL_CALLBACK_CONTROL_FORMAT
        or not isinstance(protocol_callback_control.get("states"), list)
    ):
        issues.append({
            "category": "protocol_callback_control_invalid",
            "severity": "hard",
            "next_action": (
                "declare a versioned finite callback control-state inventory"
            ),
        })
        protocol_callback_control = ProtocolCallbackControl.empty().to_payload()
    if not isinstance(padding, list):
        issues.append({"category": "padding_not_list"})
        padding = []

    normalized_targets: list[dict[str, Any]] = []
    target_ids: set[int] = set()
    for index, item in enumerate(targets):
        if not isinstance(item, dict):
            issues.append({"category": "malformed_code_target", "index": index})
            continue
        target_id = _integer(item.get("id"))
        original_rva = _integer(item.get("original_rva"))
        candidate_rva = _integer(item.get("candidate_rva"))
        original_aliases = item.get("original_aliases", [])
        candidate_aliases = item.get("candidate_aliases", [])
        if (
            target_id is None or original_rva is None or candidate_rva is None or target_id in target_ids
            or not isinstance(original_aliases, list) or not isinstance(candidate_aliases, list)
            or any(_integer(alias) is None for alias in original_aliases)
            or any(_integer(alias) is None for alias in candidate_aliases)
        ):
            issues.append({"category": "malformed_code_target", "index": index})
            continue
        target_ids.add(target_id)
        normalized_targets.append({
            "id": target_id,
            "original_rva": original_rva,
            "candidate_rva": candidate_rva,
            "original_aliases": sorted({_integer(alias) for alias in original_aliases}),
            "candidate_aliases": sorted({_integer(alias) for alias in candidate_aliases}),
        })
    canonical_target_ids = {
        index
        for index, target in enumerate(normalized_targets)
        if target["id"] == index
    }

    normalized_regions: list[dict[str, Any]] = []
    region_ids: set[str] = set()
    target_by_id = {target["id"]: target for target in normalized_targets}
    normalized_value_targets: list[dict[str, Any]] = []
    value_target_ids: set[int] = set()
    for index, item in enumerate(value_targets):
        if not isinstance(item, dict):
            issues.append({"category": "malformed_value_target", "index": index})
            continue
        fields = {
            field: _integer(item.get(field))
            for field in (
                "id", "original_value", "candidate_value",
                "original_relocation_rva", "candidate_relocation_rva",
                "mapped_size",
            )
        }
        if any(value is None for value in fields.values()) or fields["id"] in value_target_ids:
            issues.append({"category": "malformed_value_target", "index": index})
            continue
        value_target_ids.add(fields["id"])
        normalized_target = {field: int(value) for field, value in fields.items()}
        normalized_target["relocation_offsets"] = _mapped_relocation_offsets(
            original, candidate, normalized_target, issues,
        )
        normalized_value_targets.append(normalized_target)
    value_target_by_id = {target["id"]: target for target in normalized_value_targets}
    normalized_terminal_return_addresses: list[dict[str, int]] = []
    terminal_return_ids: set[int] = set()
    for index, item in enumerate(terminal_return_addresses):
        fields = {
            field: _integer(item.get(field)) if isinstance(item, dict) else None
            for field in (
                "id", "original_rva", "candidate_rva",
                "original_padding_size", "candidate_padding_size",
            )
        }
        if (
            any(value is None for value in fields.values())
            or fields["id"] in terminal_return_ids
            or int(fields["original_padding_size"] or 0) <= 0
            or int(fields["candidate_padding_size"] or 0) <= 0
        ):
            issues.append({
                "category": "malformed_terminal_return_address",
                "index": index,
            })
            continue
        terminal_return_ids.add(int(fields["id"]))
        normalized_terminal_return_addresses.append({
            field: int(value) for field, value in fields.items() if value is not None
        })
    normalized_static_dynamic_pointer_slots = _static_dynamic_pointer_slots(
        static_dynamic_pointer_slots, original, candidate, issues,
    )
    normalized_static_word_relation_slots = _static_word_relation_slots(
        static_word_relation_slots,
        normalized_static_dynamic_pointer_slots,
        original,
        candidate,
        issues,
        normalized_targets,
    )
    normalized_machine_import_call_contracts = _machine_import_call_contracts(
        machine_import_call_contracts, original, candidate, issues,
    )
    normalized_protocol_callback_states: list[dict[str, Any]] = []
    seen_protocol_callback_target_ids: set[int] = set()
    for index, raw_state in enumerate(protocol_callback_control["states"]):
        try:
            parsed_state = ProtocolCallbackControlState.parse(raw_state)
        except (TypeError, ValueError):
            parsed_state = None
        target_id = parsed_state.target_id if parsed_state is not None else None
        return_target_id = (
            parsed_state.return_invariant.target_id
            if parsed_state is not None
            else None
        )
        if (
            target_id is None
            or target_id not in target_ids
            or target_id in seen_protocol_callback_target_ids
            or (
                parsed_state is not None
                and parsed_state.return_invariant.kind == "region_input"
                and return_target_id not in target_ids
            )
        ):
            issues.append({
                "category": "protocol_callback_control_state_invalid",
                "severity": "hard",
                "index": index,
                "state": raw_state,
                "next_action": (
                    "use one mapped target, checked active frame offset, and explicit "
                    "return-invariant reference per callback control state"
                ),
            })
            continue
        seen_protocol_callback_target_ids.add(target_id)
        normalized_protocol_callback_states.append(parsed_state.to_payload())
    for index, item in enumerate(regions):
        if not isinstance(item, dict):
            issues.append({"category": "malformed_region", "index": index})
            continue
        region_id = str(item.get("id") or "")
        original_span = _span(item.get("original"))
        candidate_span = _span(item.get("candidate"))
        inputs = _register_pairs(item.get("inputs"), issues, region_id, "inputs")
        outputs = _register_pairs(item.get("outputs"), issues, region_id, "outputs")
        input_relations = (
            _register_relations(
                item.get("input_relations"), issues, region_id,
                "input_relations", canonical_target_ids,
            )
            if "input_relations" in item else None
        )
        output_relations = (
            _register_relations(
                item.get("output_relations"), issues, region_id,
                "output_relations", canonical_target_ids,
            )
            if "output_relations" in item else None
        )
        input_dynamic_range_relations = _dynamic_range_relations(
            item.get("input_dynamic_range_relations", []), issues, region_id,
            "input_dynamic_range_relations",
        )
        output_dynamic_range_relations = _dynamic_range_relations(
            item.get("output_dynamic_range_relations", []), issues, region_id,
            "output_dynamic_range_relations",
        )
        input_dynamic_stack_range_relations = _dynamic_stack_range_relations(
            item.get("input_dynamic_stack_range_relations", []), issues,
            region_id, "input_dynamic_stack_range_relations",
        )
        output_dynamic_stack_range_relations = _dynamic_stack_range_relations(
            item.get("output_dynamic_stack_range_relations", []), issues,
            region_id, "output_dynamic_stack_range_relations",
        )
        state_predicates: list[dict[str, Any]] | None = None
        if "state_predicates" in item:
            raw_state_predicates = item["state_predicates"]
            state_predicates = []
            if not isinstance(raw_state_predicates, list):
                issues.append({
                    "category": "malformed_region_state_predicates",
                    "severity": "hard",
                    "id": region_id,
                })
            else:
                for predicate_index, raw_predicate in enumerate(
                    raw_state_predicates
                ):
                    try:
                        if not isinstance(raw_predicate, dict):
                            raise SchemaError(
                                "region state predicate row must be an object"
                            )
                        predicate = RegionStatePredicate.parse(raw_predicate)
                    except SchemaError as exc:
                        issues.append({
                            "category": "malformed_region_state_predicate",
                            "severity": "hard",
                            "id": region_id,
                            "index": predicate_index,
                            "reason": str(exc),
                        })
                    else:
                        state_predicates.append(predicate.to_payload())
        raw_bounds = item.get("bounds", [])
        bounds: list[dict[str, Any]] = []
        if not isinstance(raw_bounds, list):
            issues.append({"category": "malformed_region_bounds", "id": region_id})
            raw_bounds = []
        for bound in raw_bounds:
            upper = _integer(bound.get("unsigned_lt")) if isinstance(bound, dict) else None
            if (
                not isinstance(bound, dict)
                or bound.get("original") not in REGISTERS
                or bound.get("candidate") not in REGISTERS
                or upper is None or upper <= 0 or upper > 2 ** 32
            ):
                issues.append({"category": "malformed_region_bound", "id": region_id, "bound": bound})
                continue
            bounds.append({
                "original": str(bound["original"]),
                "candidate": str(bound["candidate"]),
                "unsigned_lt": upper,
            })
            normalized_bound = bounds[-1]
            expressions_present = [
                f"{side}_expression" in bound for side in ("original", "candidate")
            ]
            if any(expressions_present):
                if not all(expressions_present) or not all(
                    _semantic_expr_is_pure(bound.get(f"{side}_expression"))
                    for side in ("original", "candidate")
                ):
                    issues.append({
                        "category": "malformed_region_bound_expression",
                        "id": region_id,
                        "bound": bound,
                    })
                else:
                    normalized_bound["original_expression"] = bound["original_expression"]
                    normalized_bound["candidate_expression"] = bound["candidate_expression"]
                    normalized_bound["expression_source"] = str(
                        bound.get("expression_source") or "contract"
                    )
        if not region_id or region_id in region_ids or original_span is None or candidate_span is None:
            issues.append({"category": "malformed_region", "index": index, "id": region_id})
            continue
        region_ids.add(region_id)
        if not _inside_executable(original, original_span) or not _inside_executable(candidate, candidate_span):
            issues.append({"category": "region_outside_executable_section", "id": region_id})
        raw_target_ids = item.get("target_ids")
        if raw_target_ids is None and isinstance(item.get("code_targets"), list):
            raw_target_ids = [target.get("id") for target in item["code_targets"] if isinstance(target, dict)]
        if raw_target_ids is None:
            raw_target_ids = [target["id"] for target in normalized_targets]
        if not isinstance(raw_target_ids, list) or any(_integer(target_id) not in target_ids for target_id in raw_target_ids):
            issues.append({"category": "malformed_region_target_ids", "id": region_id})
            raw_target_ids = []
        region_targets = [
            target_by_id[target_id]
            for raw_target_id in raw_target_ids
            if (target_id := _integer(raw_target_id)) in target_by_id
        ]
        raw_value_target_ids = item.get("value_target_ids")
        if raw_value_target_ids is None and isinstance(item.get("values"), list):
            raw_value_target_ids = [target.get("id") for target in item["values"] if isinstance(target, dict)]
        if raw_value_target_ids is None:
            raw_value_target_ids = []
        if (
            not isinstance(raw_value_target_ids, list)
            or any(_integer(target_id) not in value_target_ids for target_id in raw_value_target_ids)
        ):
            issues.append({"category": "malformed_region_value_target_ids", "id": region_id})
            raw_value_target_ids = []
        region_values = [
            value_target_by_id[target_id]
            for raw_target_id in raw_value_target_ids
            if (target_id := _integer(raw_target_id)) in value_target_by_id
        ]
        address_separations = _infer_region_address_separations(
            original,
            candidate,
            original_span,
            candidate_span,
            region_values,
            inputs,
        )
        function_id = item.get("function_id")
        function_block_index = _integer(item.get("function_block_index"))
        function_cut_index = _integer(item.get("function_cut_index"))
        function_entry = bool(item.get("function_entry"))
        function_root_kind = item.get("function_root_kind")
        function_root_symbol = item.get("function_root_symbol")
        has_function_metadata = any(
            field in item
            for field in (
                "function_id", "function_block_index", "function_cut_index",
                "function_entry", "function_root_kind", "function_root_symbol",
            )
        )
        if has_function_metadata and (
            not isinstance(function_id, str)
            or not function_id
            or function_block_index is None
            or function_block_index < 0
            or function_cut_index is None
            or function_cut_index < 0
            or (
                function_entry
                and (
                    function_root_kind != "linker_map_function"
                    or not isinstance(function_root_symbol, str)
                    or not function_root_symbol
                )
            )
        ):
            issues.append({
                "category": "malformed_region_function_metadata",
                "id": region_id,
            })
        normalized_region = {
                "id": region_id,
                "numeric_id": index,
                "original": original_span,
                "candidate": candidate_span,
                "inputs": inputs,
                "outputs": outputs,
                "input_dynamic_range_relations": input_dynamic_range_relations,
                "output_dynamic_range_relations": output_dynamic_range_relations,
                "input_dynamic_stack_range_relations":
                    input_dynamic_stack_range_relations,
                "output_dynamic_stack_range_relations":
                    output_dynamic_stack_range_relations,
                "bounds": bounds,
                "target_ids": [target["id"] for target in region_targets],
                "code_targets": region_targets,
                "value_target_ids": [target["id"] for target in region_values],
                "values": region_values,
                "address_separations": address_separations,
                "root": bool(item.get("root")),
            }
        if input_relations is not None:
            normalized_region["input_relations"] = input_relations
        if output_relations is not None:
            normalized_region["output_relations"] = output_relations
        if state_predicates is not None:
            normalized_region["state_predicates"] = state_predicates
        if has_function_metadata and not any(
            issue.get("category") == "malformed_region_function_metadata"
            and issue.get("id") == region_id
            for issue in issues
        ):
            normalized_region.update({
                "function_id": function_id,
                "function_block_index": function_block_index,
                "function_cut_index": function_cut_index,
                "function_entry": function_entry,
            })
            if function_entry:
                normalized_region.update({
                    "function_root_kind": function_root_kind,
                    "function_root_symbol": function_root_symbol,
                })
        normalized_regions.append(normalized_region)

    normalized_padding = _normalize_padding(padding, original, candidate, issues)
    padding_indices = {
        side: {
            span["rva_start"]: index
            for index, span in enumerate(
                item
                for item in normalized_padding
                if item["side"] in {side, "both"}
            )
        }
        for side in ("original", "candidate")
    }
    for target in normalized_targets:
        for side in ("original", "candidate"):
            canonical = target[f"{side}_rva"]
            alias_padding_indices: list[int] = []
            for alias in target[f"{side}_aliases"]:
                if not _padding_bridge_valid(side, alias, canonical, normalized_padding):
                    issues.append({
                        "category": "code_target_alias_not_verified_padding",
                        "severity": "hard",
                        "target_id": target["id"],
                        "side": side,
                        "alias_rva": alias,
                        "canonical_rva": canonical,
                    })
                padding_index = padding_indices[side].get(alias)
                if padding_index is None:
                    issues.append({
                        "category": "code_target_alias_padding_index_missing",
                        "severity": "hard",
                        "target_id": target["id"],
                        "side": side,
                        "alias_rva": alias,
                    })
                else:
                    alias_padding_indices.append(padding_index)
            target[f"{side}_alias_padding_indices"] = alias_padding_indices
    _check_span_overlap(normalized_regions, normalized_padding, issues)
    _check_coverage(original, candidate, normalized_regions, normalized_padding, issues)
    if not any(
        region.get("root")
        and region["original"]["rva_start"] == original.entrypoint_rva
        and region["candidate"]["rva_start"] == candidate.entrypoint_rva
        for region in normalized_regions
    ):
        issues.append({
            "category": "checked_entry_root_missing",
            "severity": "hard",
            "expected": {"original_rva": original.entrypoint_rva, "candidate_rva": candidate.entrypoint_rva},
            "next_action": "mark the region pairing both PE entrypoints as a checked root",
        })
    region_index_by_starts = {
        (region["original"]["rva_start"], region["candidate"]["rva_start"]): index
        for index, region in enumerate(normalized_regions)
    }
    for target in normalized_targets:
        target_starts = (target["original_rva"], target["candidate_rva"])
        region_index = region_index_by_starts.get(target_starts)
        if region_index is None:
            issues.append({
                "category": "unresolved_code_target",
                "severity": "hard",
                "target_id": target["id"],
                "expected": "a paired region beginning at both target RVAs",
                "observed": target,
                "next_action": "add or correct the target region relation",
            })
        else:
            target["region_index"] = region_index
    launch = _derive_launch_profile(
        original, candidate, normalized_targets, issues
    )
    _annotate_flag_liveness(original, candidate, normalized_regions, issues)
    return {
        "format": RELATION_CONTRACT_FORMAT,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "code_targets": normalized_targets,
        "value_targets": normalized_value_targets,
        "terminal_return_addresses": normalized_terminal_return_addresses,
        "static_dynamic_pointer_slots": normalized_static_dynamic_pointer_slots,
        "static_word_relation_slots": normalized_static_word_relation_slots,
        "machine_import_call_contracts": normalized_machine_import_call_contracts,
        "protocol_callback_control": {
            "format": PROTOCOL_CALLBACK_CONTROL_FORMAT,
            "states": sorted(
                normalized_protocol_callback_states,
                key=lambda state: state["target_id"],
            ),
        },
        "launch": launch,
        "regions": normalized_regions,
        "padding": normalized_padding,
        "environment": {
            "id": RELATIONAL_ENVIRONMENT_ID,
            "external_results": "paired_environment_refinement_required",
            "original_execution": "static_only",
        },
        "observations": observations,
        "memory_relation": memory_relation,
    }, issues


def _derive_launch_profile(
    original: StageABinary,
    candidate: StageABinary,
    code_targets: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> dict[str, Any]:
    def export_payload(binary: StageABinary) -> list[dict[str, Any]] | None:
        if binary.exports is None:
            return None
        return [
            {
                "ordinal": exported.ordinal,
                "name": exported.name,
                "rva": exported.rva,
                "kind": exported.kind,
                "forwarder": exported.forwarder,
            }
            for exported in binary.exports
        ]

    original_exports = export_payload(original)
    candidate_exports = export_payload(candidate)
    original_loader_diagnostics = original.loader_diagnostics.as_payload()
    candidate_loader_diagnostics = candidate.loader_diagnostics.as_payload()
    for side, binary, exports in (
        ("original", original, original_exports),
        ("candidate", candidate, candidate_exports),
    ):
        if binary.export_parse_error is not None:
            issues.append({
                "category": "console_launch_export_inventory_unparsed",
                "severity": "hard",
                "side": side,
                "observed": binary.export_parse_error,
                "next_action": (
                    "repair or explicitly reject the malformed PE export directory"
                ),
            })
        elif exports is None:
            issues.append({
                "category": "console_launch_export_inventory_missing",
                "severity": "hard",
                "side": side,
                "next_action": "parse the exact PE export directory before launch",
            })
        elif exports:
            issues.append({
                "category": "console_launch_exports_unsupported",
                "severity": "hard",
                "side": side,
                "count": len(exports),
                "examples": exports[:3],
                "next_action": (
                    "use an export-aware launch profile that roots every executable "
                    "export and classifies data exports and forwarders"
                ),
            })
        if binary.is_dll:
            issues.append({
                "category": "console_launch_dll_unsupported",
                "severity": "hard",
                "side": side,
                "characteristics": binary.coff_characteristics,
                "next_action": (
                    "use a DLL launch profile covering DllMain, exports, TLS events, "
                    "and supported loader reasons"
                ),
            })
        if binary.tls_callback_array_immutable is False:
            issues.append({
                "category": "pre_entry_tls_callback_array_mutable",
                "severity": "hard",
                "side": side,
                "rva": binary.tls_callback_array_rva,
                "size": binary.tls_callback_array_size,
                "next_action": (
                    "place the TLS directory callback pointer, every callback slot, "
                    "and the null terminator in non-writable image memory, or use a "
                    "launch profile that rereads and resolves the runtime inventory"
                ),
            })
        hard_loader_diagnostics = [
            diagnostic
            for diagnostic in binary.loader_diagnostics.diagnostics
            if diagnostic.severity.value == "error"
        ]
        if hard_loader_diagnostics:
            issues.append({
                "category": "loader_image_invalid",
                "severity": "hard",
                "side": side,
                "policy": binary.loader_diagnostics.policy,
                "diagnostic_codes": [
                    diagnostic.code for diagnostic in hard_loader_diagnostics
                ],
                "diagnostics": [
                    {
                        "code": diagnostic.code,
                        "message": diagnostic.message,
                    }
                    for diagnostic in hard_loader_diagnostics
                ],
                "next_action": (
                    "repair the PE32 loader image; Lean loader validation remains "
                    "the authoritative acceptance check"
                ),
            })

    callback_target_ids: list[int] = []
    parse_errors = [
        ("original", original.tls_callback_parse_error),
        ("candidate", candidate.tls_callback_parse_error),
    ]
    for side, error in parse_errors:
        if error is not None:
            issues.append({
                "category": "pre_entry_tls_inventory_unparsed",
                "severity": "hard",
                "side": side,
                "observed": error,
                "next_action": "repair or explicitly reject the malformed PE32 TLS directory",
            })
    original_callbacks = original.tls_callback_rvas
    candidate_callbacks = candidate.tls_callback_rvas
    if original_callbacks is None or candidate_callbacks is None:
        return {
            "profile": "pe32-console-launch-v2-required",
            "original_is_dll": original.is_dll,
            "candidate_is_dll": candidate.is_dll,
            "original_exports": original_exports,
            "candidate_exports": candidate_exports,
            "original_export_parse_error": original.export_parse_error,
            "candidate_export_parse_error": candidate.export_parse_error,
            "original_loader_diagnostics": original_loader_diagnostics,
            "candidate_loader_diagnostics": candidate_loader_diagnostics,
            "tls_callback_target_ids": [],
            "original_tls_callback_rvas": original_callbacks,
            "candidate_tls_callback_rvas": candidate_callbacks,
            "original_tls_callback_array_immutable": (
                original.tls_callback_array_immutable
            ),
            "candidate_tls_callback_array_immutable": (
                candidate.tls_callback_array_immutable
            ),
        }
    if len(original_callbacks) != len(candidate_callbacks):
        issues.append({
            "category": "pre_entry_tls_callback_count_mismatch",
            "severity": "hard",
            "original_count": len(original_callbacks),
            "candidate_count": len(candidate_callbacks),
            "next_action": "restore a pointwise TLS callback sequence",
        })
    else:
        mapping_complete = True
        for index, (original_rva, candidate_rva) in enumerate(zip(
            original_callbacks, candidate_callbacks, strict=True
        )):
            matches = [
                target for target in code_targets
                if original_rva == int(target["original_rva"])
                and candidate_rva == int(target["candidate_rva"])
            ]
            if len(matches) != 1:
                mapping_complete = False
                issues.append({
                    "category": "pre_entry_tls_callback_mapping_unresolved",
                    "severity": "hard",
                    "index": index,
                    "original_rva": original_rva,
                    "candidate_rva": candidate_rva,
                    "matches": len(matches),
                    "next_action": "add one canonical code-target pair for this TLS callback",
                })
            else:
                callback_target_ids.append(int(matches[0]["id"]))
        if not mapping_complete:
            callback_target_ids = []
    tls_present = any((
        original.tls_directory_rva,
        original.tls_directory_size,
        candidate.tls_directory_rva,
        candidate.tls_directory_size,
    ))
    return {
        "profile": (
            "pe32-console-launch-v2-required"
            if tls_present else "pe32-console-launch-v1"
        ),
        "original_is_dll": original.is_dll,
        "candidate_is_dll": candidate.is_dll,
        "original_exports": original_exports,
        "candidate_exports": candidate_exports,
        "original_export_parse_error": original.export_parse_error,
        "candidate_export_parse_error": candidate.export_parse_error,
        "original_loader_diagnostics": original_loader_diagnostics,
        "candidate_loader_diagnostics": candidate_loader_diagnostics,
        "tls_callback_target_ids": callback_target_ids,
        "original_tls_callback_rvas": original_callbacks,
        "candidate_tls_callback_rvas": candidate_callbacks,
        "original_tls_callback_array_immutable": (
            original.tls_callback_array_immutable
        ),
        "candidate_tls_callback_array_immutable": (
            candidate.tls_callback_array_immutable
        ),
    }

def _annotate_flag_liveness(
    original: StageABinary,
    candidate: StageABinary,
    regions: list[dict[str, Any]],
    issues: list[dict[str, Any]],
) -> None:
    from capstone import x86_const

    read_masks = {
        bit: (
            getattr(x86_const, f"X86_EFLAGS_TEST_{name}")
            | getattr(x86_const, f"X86_EFLAGS_PRIOR_{name}")
        )
        for bit, name in FLAG_BITS.items()
    }
    write_masks = {
        bit: sum(
            getattr(x86_const, f"X86_EFLAGS_{kind}_{name}", 0)
            for kind in ("MODIFY", "RESET", "SET", "UNDEFINED")
        )
        for bit, name in FLAG_BITS.items()
    }

    def local(
        binary: StageABinary,
        span: dict[str, int],
        *,
        region_id: str,
        side: str,
    ) -> tuple[set[int], set[int]]:
        data = binary.pe.get_data(span["rva_start"], span["size"])
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        disassembler.detail = True
        used_before_definition: set[int] = set()
        defined: set[int] = set()
        decoded_size = 0
        for instruction in disassembler.disasm(
            data, binary.image_base + span["rva_start"]
        ):
            decoded_size += int(instruction.size)
            eflags = (
                0 if (
                    instruction.group(capstone.x86.X86_GRP_FPU)
                    or instruction.mnemonic.startswith("f")
                )
                else int(instruction.eflags)
            )
            unmodeled_reads = [
                name for name in ("AF", "IF", "TF", "NT", "RF")
                if eflags & (
                    getattr(x86_const, f"X86_EFLAGS_TEST_{name}", 0)
                    | getattr(x86_const, f"X86_EFLAGS_PRIOR_{name}", 0)
                )
            ]
            if unmodeled_reads:
                issues.append({
                    "category": "unmodeled_live_eflag",
                    "severity": "hard",
                    "region_id": region_id,
                    "side": side,
                    "instruction_rva": int(instruction.address) - binary.image_base,
                    "flags": unmodeled_reads,
                    "next_action": "extend the formal flag model before proving this instruction",
                })
            used_before_definition.update(
                bit for bit, mask in read_masks.items()
                if eflags & mask and bit not in defined
            )
            defined.update(
                bit for bit, mask in write_masks.items() if eflags & mask
            )
        if decoded_size != len(data):
            raise StageAInputError("flag-liveness analysis did not decode a region exactly")
        return used_before_definition, defined

    uses: list[set[int]] = []
    definitions: list[set[int]] = []
    successors: list[set[int]] = []
    for region in regions:
        original_uses, original_defs = local(
            original, region["original"], region_id=region["id"], side="original"
        )
        candidate_uses, candidate_defs = local(
            candidate, region["candidate"], region_id=region["id"], side="candidate"
        )
        uses.append(original_uses | candidate_uses)
        definitions.append(original_defs & candidate_defs)
        successors.append({
            int(target["region_index"])
            for target in region.get("code_targets", [])
            if "region_index" in target
        })

    live_in = [set(region_uses) for region_uses in uses]
    live_out = [set() for _ in regions]
    changed = True
    while changed:
        changed = False
        for index in range(len(regions) - 1, -1, -1):
            output = set().union(*(live_in[target] for target in successors[index])) \
                if successors[index] else set()
            entry = uses[index] | (output - definitions[index])
            if output != live_out[index] or entry != live_in[index]:
                live_out[index] = output
                live_in[index] = entry
                changed = True

    for index, region in enumerate(regions):
        region["flag_inputs"] = sorted(live_in[index])
        region["flag_outputs"] = sorted(live_out[index])

def _infer_region_address_separations(
    original: StageABinary,
    candidate: StageABinary,
    original_span: dict[str, int],
    candidate_span: dict[str, int],
    values: list[dict[str, int]],
    inputs: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not values:
        return []

    def accesses(
        binary: StageABinary,
        span: dict[str, int],
    ) -> tuple[list[tuple[str, int, int]], list[tuple[int, int]]]:
        data = binary.pe.get_data(span["rva_start"], span["size"])
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        disassembler.detail = True
        writes: list[tuple[str, int, int]] = []
        reads: list[tuple[int, int]] = []
        for instruction in disassembler.disasm(data, binary.image_base + span["rva_start"]):
            for operand in instruction.operands:
                if operand.type != capstone.x86.X86_OP_MEM:
                    continue
                base = instruction.reg_name(operand.mem.base) if operand.mem.base else ""
                index = instruction.reg_name(operand.mem.index) if operand.mem.index else ""
                if operand.access & capstone.CS_AC_WRITE and base in REGISTERS and not index:
                    writes.append((base, int(operand.mem.disp), int(operand.size)))
                if operand.access & capstone.CS_AC_READ and not base and not index:
                    reads.append((int(operand.mem.disp) & 0xFFFFFFFF, int(operand.size)))
        return writes, reads

    original_writes, original_reads = accesses(original, original_span)
    candidate_writes, candidate_reads = accesses(candidate, candidate_span)
    if len(original_writes) != len(candidate_writes) or len(original_reads) != len(candidate_reads):
        return []
    register_map = {pair["original"]: pair["candidate"] for pair in inputs}
    paired_writes = [
        (original_write, candidate_write)
        for original_write, candidate_write in zip(original_writes, candidate_writes)
        if (
            register_map.get(original_write[0]) == candidate_write[0]
            and original_write[2] == candidate_write[2]
        )
    ]
    if len(paired_writes) != len(original_writes):
        return []

    rows: set[tuple[str, str, int, int, int, int]] = set()
    for (original_address, original_width), (candidate_address, candidate_width) in zip(
        original_reads, candidate_reads
    ):
        if original_width != candidate_width:
            continue
        matching_target = next((
            target for target in values
            if (
                target["mapped_size"] > 0
                and target["original_value"] <= original_address
                and original_address + original_width <= target["original_value"] + target["mapped_size"]
                and target["candidate_value"] <= candidate_address
                and candidate_address + candidate_width <= target["candidate_value"] + target["mapped_size"]
                and original_address - target["original_value"]
                    == candidate_address - target["candidate_value"]
            )
        ), None)
        if matching_target is None:
            continue
        for original_write, candidate_write in paired_writes:
            for read_offset in range(original_width):
                for write_offset in range(original_write[2]):
                    rows.add((
                        original_write[0],
                        candidate_write[0],
                        (original_write[1] + write_offset) & 0xFFFFFFFF,
                        (candidate_write[1] + write_offset) & 0xFFFFFFFF,
                        (original_address + read_offset) & 0xFFFFFFFF,
                        (candidate_address + read_offset) & 0xFFFFFFFF,
                    ))
    return [
        {
            "original_register": original_register,
            "candidate_register": candidate_register,
            "original_offset": original_offset,
            "candidate_offset": candidate_offset,
            "original_address": original_address,
            "candidate_address": candidate_address,
        }
        for (
            original_register,
            candidate_register,
            original_offset,
            candidate_offset,
            original_address,
            candidate_address,
        ) in sorted(rows)
    ]

def _span(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    start = _integer(value.get("rva_start", value.get("rva")))
    size = _integer(value.get("size"))
    if start is None or size is None or size <= 0:
        return None
    return {"rva_start": start, "rva_end": start + size, "size": size}

def _static_dynamic_pointer_slots(
    value: list[Any],
    original: StageABinary,
    candidate: StageABinary,
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    ids: set[int] = set()
    address_ranges: dict[str, list[tuple[int, int]]] = {
        "original": [], "candidate": [],
    }

    def writable_data_word(binary: StageABinary, address: int) -> bool:
        rva = address - binary.image_base
        return 0 <= address < 2**32 and address + 4 <= 2**32 and any(
            section.writable and not section.executable
            and section.rva_start <= rva
            and rva + 4 <= section.rva_end
            for section in binary.sections
        )

    def overlaps_iat(binary: StageABinary, address: int) -> bool:
        return any(
            imported.thunk_rva is not None
            and address < binary.image_base + int(imported.thunk_rva) + 4
            and binary.image_base + int(imported.thunk_rva) < address + 4
            for imported in binary.imports
        )

    for index, item in enumerate(value):
        slot_id = _integer(item.get("id")) if isinstance(item, dict) else None
        original_address = (
            _integer(item.get("original_address")) if isinstance(item, dict) else None
        )
        candidate_address = (
            _integer(item.get("candidate_address")) if isinstance(item, dict) else None
        )
        required_words = item.get("required_words") if isinstance(item, dict) else None
        malformed = (
            not isinstance(item, dict)
            or slot_id is None
            or slot_id < 0
            or slot_id in ids
            or original_address is None
            or candidate_address is None
            or original_address == 0
            or candidate_address == 0
            or not isinstance(required_words, list)
            or not required_words
        )
        words: list[dict[str, Any]] = []
        word_offsets: set[int] = set()
        if not malformed:
            for word in required_words:
                offset = _integer(word.get("offset")) if isinstance(word, dict) else None
                kind = word.get("kind") if isinstance(word, dict) else None
                if (
                    offset is None
                    or not 0 <= offset < 2**32
                    or offset + 4 > 2**32
                    or kind not in {
                        "relatedWord", "codePointer", "dataPointer",
                        "nullableDynamicPointer",
                    }
                    or any(
                        offset < prior_offset + 4 and prior_offset < offset + 4
                        for prior_offset in word_offsets
                    )
                ):
                    malformed = True
                    break
                word_offsets.add(offset)
                words.append({"offset": offset, "kind": str(kind)})
        if malformed:
            issues.append({
                "category": "static_dynamic_pointer_slot_invalid",
                "severity": "hard",
                "index": index,
                "item": item,
                "next_action": (
                    "declare one unique PE pointer-word pair and a nonempty, "
                    "nonoverlapping dynamic-object word shape"
                ),
            })
            continue
        assert slot_id is not None
        assert original_address is not None
        assert candidate_address is not None
        ids.add(slot_id)
        side_values = {
            "original": (original, original_address),
            "candidate": (candidate, candidate_address),
        }
        side_invalid = False
        for side, (binary, address) in side_values.items():
            if not writable_data_word(binary, address):
                issues.append({
                    "category": "static_dynamic_pointer_slot_not_writable_data",
                    "severity": "hard",
                    "index": index,
                    "side": side,
                    "address": address,
                    "next_action": (
                        "use a four-byte word wholly inside a writable, "
                        "non-executable mapped PE section"
                    ),
                })
                side_invalid = True
            if overlaps_iat(binary, address):
                issues.append({
                    "category": "static_dynamic_pointer_slot_overlaps_iat",
                    "severity": "hard",
                    "index": index,
                    "side": side,
                    "address": address,
                    "next_action": "classify this word as an import address instead",
                })
                side_invalid = True
            if any(address < stop and start < address + 4
                   for start, stop in address_ranges[side]):
                issues.append({
                    "category": "static_dynamic_pointer_slot_overlap",
                    "severity": "hard",
                    "index": index,
                    "side": side,
                    "address": address,
                })
                side_invalid = True
        if side_invalid:
            continue
        for side, (_, address) in side_values.items():
            address_ranges[side].append((address, address + 4))
        result.append({
            "id": slot_id,
            "original_address": original_address,
            "candidate_address": candidate_address,
            "required_words": sorted(words, key=lambda word: word["offset"]),
        })
    return sorted(result, key=lambda slot: slot["id"])

def _static_word_relation_slots(
    value: list[Any],
    pointer_slots: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
    issues: list[dict[str, Any]],
    code_targets: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    ids: set[int] = set()
    address_ranges: dict[str, list[tuple[int, int]]] = {
        "original": [
            (int(slot["original_address"]), int(slot["original_address"]) + 4)
            for slot in pointer_slots
        ],
        "candidate": [
            (int(slot["candidate_address"]), int(slot["candidate_address"]) + 4)
            for slot in pointer_slots
        ],
    }

    def writable_data_word(binary: StageABinary, address: int) -> bool:
        rva = address - binary.image_base
        return 0 < address < 2**32 and address + 4 <= 2**32 and any(
            section.writable and not section.executable
            and section.rva_start <= rva
            and rva + 4 <= section.rva_end
            for section in binary.sections
        )

    def overlaps_iat(binary: StageABinary, address: int) -> bool:
        return any(
            imported.thunk_rva is not None
            and address < binary.image_base + int(imported.thunk_rva) + 4
            and binary.image_base + int(imported.thunk_rva) < address + 4
            for imported in binary.imports
        )

    relation_names = {
        "exact": "exact",
        "related_word": "related_word",
        "relatedWord": "related_word",
        "code_pointer": "code_pointer",
        "codePointer": "code_pointer",
        "fixed_code_pointer": "fixed_code_pointer",
        "fixedCodePointer": "fixed_code_pointer",
        "data_pointer": "data_pointer",
        "dataPointer": "data_pointer",
    }
    for index, item in enumerate(value):
        slot_id = _integer(item.get("id")) if isinstance(item, dict) else None
        original_address = (
            _integer(item.get("original_address")) if isinstance(item, dict) else None
        )
        candidate_address = (
            _integer(item.get("candidate_address")) if isinstance(item, dict) else None
        )
        relation = (
            relation_names.get(str(item.get("relation")))
            if isinstance(item, dict) else None
        )
        target_id = (
            _integer(item.get("target_id")) if isinstance(item, dict) else None
        )
        if (
            slot_id is None or slot_id < 0 or slot_id in ids
            or original_address is None or candidate_address is None
            or relation is None
            or (
                relation == "fixed_code_pointer"
                and (
                    target_id is None
                    or target_id < 0
                    or not any(
                        int(target["id"]) == target_id
                        for target in (code_targets or [])
                    )
                )
            )
        ):
            issues.append({
                "category": "static_word_relation_slot_invalid",
                "severity": "hard",
                "index": index,
                "item": item,
                "next_action": (
                    "declare a unique paired writable-static word with one of "
                    "exact, related_word, code_pointer, fixed_code_pointer, or data_pointer"
                ),
            })
            continue
        side_invalid = False
        for side, binary, address in (
            ("original", original, original_address),
            ("candidate", candidate, candidate_address),
        ):
            if not writable_data_word(binary, address):
                issues.append({
                    "category": "static_word_relation_slot_not_writable_data",
                    "severity": "hard",
                    "index": index,
                    "side": side,
                    "address": address,
                    "next_action": (
                        "use a four-byte word wholly inside a writable, "
                        "non-executable mapped PE section"
                    ),
                })
                side_invalid = True
            if overlaps_iat(binary, address):
                issues.append({
                    "category": "static_word_relation_slot_overlaps_iat",
                    "severity": "hard",
                    "index": index,
                    "side": side,
                    "address": address,
                    "next_action": "classify this word as an import address instead",
                })
                side_invalid = True
            if any(
                address < stop and start < address + 4
                for start, stop in address_ranges[side]
            ):
                issues.append({
                    "category": "static_word_relation_slot_overlap",
                    "severity": "hard",
                    "index": index,
                    "side": side,
                    "address": address,
                    "next_action": (
                        "remove overlap with another static word or dynamic-pointer slot"
                    ),
                })
                side_invalid = True
        if side_invalid:
            continue
        ids.add(slot_id)
        address_ranges["original"].append((original_address, original_address + 4))
        address_ranges["candidate"].append((candidate_address, candidate_address + 4))
        normalized = {
            "id": slot_id,
            "original_address": original_address,
            "candidate_address": candidate_address,
            "relation": relation,
        }
        if relation == "fixed_code_pointer":
            normalized["target_id"] = target_id
        result.append(normalized)
    return sorted(result, key=lambda slot: slot["id"])

def _machine_call_memory_size(
    value: Any, argument_count: int, *, footprint: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    if kind == "fixed":
        size_bytes = _integer(value.get("bytes"))
        if size_bytes is not None and 0 < size_bytes < 2**32:
            return {"kind": "fixed", "bytes": size_bytes}
        return None
    if kind == "argument":
        argument = _integer(value.get("argument"))
        scale = _integer(value.get("scale", 1))
        if (
            argument is not None
            and 0 <= argument < argument_count
            and scale is not None
            and 0 < scale < 2**32
        ):
            return {"kind": "argument", "argument": argument, "scale": scale}
        return None
    if kind == "product":
        left_argument = _integer(value.get("left_argument"))
        right_argument = _integer(value.get("right_argument"))
        if (
            left_argument is not None
            and 0 <= left_argument < argument_count
            and right_argument is not None
            and 0 <= right_argument < argument_count
        ):
            return {
                "kind": "product",
                "left_argument": left_argument,
                "right_argument": right_argument,
            }
    if kind in {
        "bounded_terminated", "argument_or_bounded_terminated",
    } and footprint:
        source_argument = _integer(value.get("source_argument"))
        source_offset = _integer(value.get("source_offset"))
        unit_bytes = _integer(value.get("unit_bytes"))
        raw_sentinel = value.get("sentinel")
        sentinel = (
            [_integer(byte) for byte in raw_sentinel]
            if isinstance(raw_sentinel, list) else None
        )
        max_units = _integer(value.get("max_units"))
        bounded_bytes = (
            unit_bytes * max_units
            if unit_bytes is not None and max_units is not None else None
        )
        common_valid = (
            source_argument is not None
            and 0 <= source_argument < argument_count
            and source_offset is not None
            and 0 <= source_offset < 2**32
            and unit_bytes is not None
            and unit_bytes > 0
            and sentinel is not None
            and len(sentinel) == unit_bytes
            and all(byte is not None and 0 <= byte <= 0xFF for byte in sentinel)
            and max_units is not None
            and max_units > 0
            and bounded_bytes is not None
            and bounded_bytes < 2**32
            and source_offset + bounded_bytes <= 2**32
        )
        if not common_valid:
            return None
        assert source_argument is not None
        assert source_offset is not None
        assert unit_bytes is not None
        assert sentinel is not None
        assert max_units is not None
        normalized: dict[str, Any] = {
            "kind": str(kind),
            "source_argument": source_argument,
            "source_offset": source_offset,
            "unit_bytes": unit_bytes,
            "sentinel": [int(byte) for byte in sentinel],
            "max_units": max_units,
        }
        if kind == "argument_or_bounded_terminated":
            length_argument = _integer(value.get("length_argument"))
            terminated_value = _integer(value.get("terminated_value"))
            if (
                length_argument is None
                or not 0 <= length_argument < argument_count
                or terminated_value is None
                or not 0 <= terminated_value < 2**32
            ):
                return None
            normalized = {
                "kind": "argument_or_bounded_terminated",
                "length_argument": length_argument,
                "terminated_value": terminated_value,
                **{key: field for key, field in normalized.items() if key != "kind"},
            }
        return normalized
    return None


def _canonical_machine_call_value(value: Any) -> tuple[Any, ...]:
    if isinstance(value, dict):
        return (
            "object",
            tuple(
                (key, _canonical_machine_call_value(value[key]))
                for key in sorted(value)
            ),
        )
    if isinstance(value, list):
        return (
            "array",
            tuple(_canonical_machine_call_value(item) for item in value),
        )
    return (type(value).__name__, value)


def _machine_import_call_contracts(
    value: list[Any],
    original: StageABinary,
    candidate: StageABinary,
    issues: list[dict[str, Any]],
    *,
    select_common_imports: bool = False,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    ids: set[int] = set()
    targets: set[tuple[str, str, str | int]] = set()

    def binary_imports(binary: StageABinary) -> set[tuple[str, str, str | int]]:
        return {
            (identity[0].lower(), identity[1], identity[2])
            for imported in binary.imports
            if (identity := _import_identity(imported)) is not None
        }

    original_imports = binary_imports(original)
    candidate_imports = binary_imports(candidate)
    for index, item in enumerate(value):
        contract_id = _integer(item.get("id")) if isinstance(item, dict) else None
        imported = item.get("import") if isinstance(item, dict) else None
        dll = imported.get("dll") if isinstance(imported, dict) else None
        symbol = imported.get("symbol") if isinstance(imported, dict) else None
        ordinal = _integer(imported.get("ordinal")) if isinstance(imported, dict) else None
        abi_template = item.get("abi_template") if isinstance(item, dict) else None
        argument_words = (
            _integer(item.get("argument_words")) if isinstance(item, dict) else None
        )
        explicit_abi_fields = {
            "stack_argument_offsets", "stack_result_delta",
            "preserved_registers", "clobbered_registers",
        }
        has_explicit_abi = isinstance(item, dict) and any(
            field in item for field in explicit_abi_fields
        )
        template = (
            MACHINE_CALL_ABI_TEMPLATES.get(abi_template)
            if isinstance(abi_template, str) else None
        )
        template_valid = abi_template is None or (
            template is not None
            and argument_words is not None
            and 0 <= argument_words <= MACHINE_CALL_MAX_ARGUMENT_WORDS
            and not has_explicit_abi
        )
        if abi_template is not None and template_valid:
            assert template is not None
            assert argument_words is not None
            argument_offsets = list(range(0, argument_words * 4, 4))
            stack_result_delta = argument_words * 4 if template["callee_cleanup"] else 0
            preserved = list(template["preserved_registers"])
            clobbered = list(template["clobbered_registers"])
        else:
            argument_offsets = (
                item.get("stack_argument_offsets") if isinstance(item, dict) else None
            )
            stack_result_delta = (
                _integer(item.get("stack_result_delta"))
                if isinstance(item, dict) else None
            )
            preserved = item.get("preserved_registers") if isinstance(item, dict) else None
            clobbered = item.get("clobbered_registers") if isinstance(item, dict) else None
        memory_effect = item.get("memory_effect") if isinstance(item, dict) else None
        disposition = (
            item.get("disposition", "returns")
            if isinstance(item, dict) else None
        )
        world_effect = item.get("world_effect") if isinstance(item, dict) else None
        world_effect_argument = (
            _integer(item.get("world_effect_argument"))
            if isinstance(item, dict) else None
        )
        import_valid = (
            isinstance(dll, str)
            and bool(dll)
            and (isinstance(symbol, str) and bool(symbol)) != (ordinal is not None)
        )
        target = (
            (dll.lower(), "symbol", str(symbol))
            if import_valid and symbol is not None
            else (dll.lower(), "ordinal", int(ordinal or 0))
            if import_valid else None
        )
        offsets = (
            [_integer(offset) for offset in argument_offsets]
            if isinstance(argument_offsets, list) else []
        )
        raw_footprints = (
            item.get("memory_footprints", []) if isinstance(item, dict) else None
        )
        footprints: list[dict[str, Any]] = []
        footprint_keys: set[tuple[Any, ...]] = set()
        footprints_valid = isinstance(raw_footprints, list)
        if isinstance(raw_footprints, list):
            for footprint in raw_footprints:
                access = footprint.get("access") if isinstance(footprint, dict) else None
                base_argument = (
                    _integer(footprint.get("base_argument"))
                    if isinstance(footprint, dict) else None
                )
                offset = (
                    _integer(footprint.get("offset", 0))
                    if isinstance(footprint, dict) else None
                )
                nullable = (
                    footprint.get("nullable", False)
                    if isinstance(footprint, dict) else None
                )
                size = footprint.get("size") if isinstance(footprint, dict) else None
                normalized_size = _machine_call_memory_size(
                    size, len(offsets), footprint=True,
                )
                size_key = (
                    _canonical_machine_call_value(normalized_size)
                    if normalized_size is not None else None
                )
                key = (
                    access, base_argument, offset, size_key
                ) if size_key is not None else None
                valid_footprint = (
                    access in {"read", "write"}
                    and base_argument is not None
                    and 0 <= base_argument < len(offsets)
                    and offset is not None
                    and 0 <= offset < 2**32
                    and isinstance(nullable, bool)
                    and normalized_size is not None
                    and key not in footprint_keys
                )
                if not valid_footprint:
                    footprints_valid = False
                    continue
                assert key is not None
                footprint_keys.add(key)
                footprints.append({
                    "access": access,
                    "base_argument": base_argument,
                    "offset": offset,
                    "size": normalized_size,
                    "nullable": nullable,
                })
        memory_shape_valid = (
            footprints_valid
            and (
                (memory_effect == "none" and not footprints)
                or (
                    memory_effect == "readOnly"
                    and all(footprint["access"] == "read" for footprint in footprints)
                )
                or (
                    memory_effect == "argumentRanges"
                    and bool(footprints)
                    and any(footprint["access"] == "write" for footprint in footprints)
                )
                or (
                    memory_effect == "newDynamicRanges"
                    and not footprints
                    and world_effect == "dynamicRanges"
                )
                or (
                    memory_effect == "relationalState"
                    and not footprints
                )
            )
        )
        raw_result_relations = (
            item.get("result_register_relations", [])
            if isinstance(item, dict) else None
        )
        result_relations: list[dict[str, Any]] = []
        result_registers: set[str] = set()
        result_relations_valid = isinstance(raw_result_relations, list)
        if isinstance(raw_result_relations, list):
            for relation in raw_result_relations:
                register = (
                    relation.get("register") if isinstance(relation, dict) else None
                )
                relation_kind = (
                    relation.get("relation") if isinstance(relation, dict) else None
                )
                raw_size = relation.get("size") if isinstance(relation, dict) else None
                normalized_result_size = _machine_call_memory_size(
                    raw_size, len(offsets)
                )
                minimum_size = (
                    _integer(relation.get("minimum_size"))
                    if isinstance(relation, dict) else None
                )
                nullable_result = (
                    relation.get("nullable", False)
                    if isinstance(relation, dict) else None
                )
                raw_required_words = (
                    relation.get("required_words")
                    if isinstance(relation, dict) else None
                )
                required_words: list[dict[str, Any]] = []
                required_offsets: set[int] = set()
                required_words_valid = isinstance(raw_required_words, list)
                if isinstance(raw_required_words, list):
                    for required_word in raw_required_words:
                        required_offset = (
                            _integer(required_word.get("offset"))
                            if isinstance(required_word, dict) else None
                        )
                        required_kind = (
                            required_word.get("relation")
                            if isinstance(required_word, dict) else None
                        )
                        if (
                            required_offset is None
                            or required_offset < 0
                            or minimum_size is None
                            or required_offset + 4 > minimum_size
                            or required_offset in required_offsets
                            or required_kind not in MACHINE_CALL_RESULT_WORD_RELATIONS
                        ):
                            required_words_valid = False
                            continue
                        required_offsets.add(required_offset)
                        required_words.append({
                            "offset": required_offset,
                            "relation": str(required_kind),
                        })
                fixed_size_too_small = (
                    normalized_result_size is not None
                    and normalized_result_size["kind"] == "fixed"
                    and minimum_size is not None
                    and int(normalized_result_size["bytes"]) < minimum_size
                )
                dynamic_range_relation_valid = (
                    relation_kind == "dynamic_range_base"
                    and normalized_result_size is not None
                    and minimum_size is not None
                    and 0 <= minimum_size < 2**32
                    and not fixed_size_too_small
                    and required_words_valid
                    and isinstance(nullable_result, bool)
                    and world_effect == "dynamicRanges"
                )
                scalar_relation_valid = (
                    relation_kind in {"exact", "related_word"}
                    and raw_size is None
                    and minimum_size is None
                    and raw_required_words is None
                    and "nullable" not in relation
                )
                valid_relation = (
                    register in MACHINE_CALL_ABI_REGISTERS
                    and isinstance(clobbered, list)
                    and register in clobbered
                    and register not in result_registers
                    and relation_kind in MACHINE_CALL_RESULT_RELATIONS
                    and (scalar_relation_valid or dynamic_range_relation_valid)
                )
                if not valid_relation:
                    result_relations_valid = False
                    continue
                result_registers.add(str(register))
                normalized_relation: dict[str, Any] = {
                    "register": str(register),
                    "relation": str(relation_kind),
                }
                if relation_kind == "dynamic_range_base":
                    assert normalized_result_size is not None
                    assert minimum_size is not None
                    normalized_relation["size"] = normalized_result_size
                    normalized_relation["minimum_size"] = minimum_size
                    normalized_relation["required_words"] = sorted(
                        required_words, key=lambda word: word["offset"]
                    )
                    normalized_relation["nullable"] = bool(nullable_result)
                result_relations.append(normalized_relation)
        if memory_effect == "newDynamicRanges" and not any(
            relation.get("relation") == "dynamic_range_base"
            for relation in result_relations
        ):
            result_relations_valid = False
        malformed = (
            not isinstance(item, dict)
            or not template_valid
            or (abi_template is None and "argument_words" in item)
            or contract_id is None
            or contract_id < 0
            or contract_id in ids
            or target is None
            or target in targets
            or not isinstance(argument_offsets, list)
            or any(offset is None or offset < 0 or offset % 4 != 0
                   or offset + 4 > 2**32 for offset in offsets)
            or len(set(offsets)) != len(offsets)
            or stack_result_delta is None
            or stack_result_delta < 0
            or stack_result_delta >= 2**32
            or stack_result_delta % 4 != 0
            or not isinstance(preserved, list)
            or not isinstance(clobbered, list)
            or any(register not in MACHINE_CALL_ABI_REGISTERS for register in preserved)
            or any(register not in MACHINE_CALL_ABI_REGISTERS for register in clobbered)
            or len(set(preserved)) != len(preserved)
            or len(set(clobbered)) != len(clobbered)
            or set(preserved).intersection(clobbered)
            or set(preserved).union(clobbered) != MACHINE_CALL_ABI_REGISTERS
            or memory_effect not in MACHINE_CALL_MEMORY_EFFECTS
            or not memory_shape_valid
            or (
                memory_effect == "relationalState"
                and disposition != "returns"
            )
            or not result_relations_valid
            or disposition not in MACHINE_CALL_DISPOSITIONS
            or world_effect not in MACHINE_CALL_WORLD_EFFECTS
            or (
                world_effect in {"dynamicRangeRelease", "callbackRegistration"}
                and (
                    world_effect_argument is None
                    or not 0 <= world_effect_argument < len(offsets)
                )
            )
            or (
                world_effect not in {"dynamicRangeRelease", "callbackRegistration"}
                and world_effect_argument is not None
            )
            or (
                disposition == "terminates"
                and (
                    stack_result_delta != 0
                    or memory_effect != "none"
                    or bool(footprints)
                    or bool(result_relations)
                    or world_effect != "none"
                )
            )
            or (
                disposition == "protocol"
                and world_effect != "none"
            )
        )
        if malformed:
            issues.append({
                "category": "machine_import_call_contract_invalid",
                "severity": "hard",
                "index": index,
                "item": item,
                "next_action": (
                    "declare one unique imported target; use either explicit aligned ABI "
                    "fields or one supported ABI template with argument_words; use explicit "
                    "argument-relative read/write footprints for bounded memory effects, or "
                    "footprint-free relationalState when paired StateRel is authoritative; "
                    "and retain an explicit world effect"
                ),
            })
            continue
        assert contract_id is not None
        assert target is not None
        ids.add(contract_id)
        targets.add(target)
        if target not in original_imports or target not in candidate_imports:
            if select_common_imports:
                continue
            issues.append({
                "category": "machine_import_call_contract_import_mismatch",
                "severity": "hard",
                "index": index,
                "import": imported,
                "original_has_import": target in original_imports,
                "candidate_has_import": target in candidate_imports,
                "next_action": "use an import identity present in both exact PE import tables",
            })
            continue
        normalized_import: dict[str, Any] = {"dll": target[0]}
        normalized_import[target[1]] = target[2]
        normalized = {
            "id": contract_id,
            "import": normalized_import,
            "stack_argument_offsets": [int(offset) for offset in offsets],
            "stack_result_delta": stack_result_delta,
            "preserved_registers": sorted(str(register) for register in preserved),
            "clobbered_registers": sorted(str(register) for register in clobbered),
            "result_register_relations": sorted(
                result_relations, key=lambda relation: relation["register"]
            ),
            "disposition": str(disposition),
            "memory_effect": str(memory_effect),
            "memory_footprints": footprints,
            "world_effect": str(world_effect),
        }
        if world_effect_argument is not None:
            normalized["world_effect_argument"] = world_effect_argument
        result.append(normalized)
    return sorted(result, key=lambda contract: contract["id"])

def _register_pairs(value: Any, issues: list[dict[str, Any]], region: str, family: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        issues.append({"category": "register_relation_missing", "region": region, "family": family})
        return []
    result: list[dict[str, str]] = []
    original_seen: set[str] = set()
    candidate_seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or item.get("original") not in REGISTERS or item.get("candidate") not in REGISTERS:
            issues.append({"category": "register_relation_invalid", "region": region, "family": family, "item": item})
            continue
        original_register = str(item["original"])
        candidate_register = str(item["candidate"])
        if original_register in original_seen or candidate_register in candidate_seen:
            issues.append({
                "category": "register_relation_ambiguous",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        original_seen.add(original_register)
        candidate_seen.add(candidate_register)
        result.append({"original": original_register, "candidate": candidate_register})
    return result


def _register_relations(
    value: Any,
    issues: list[dict[str, Any]],
    region: str,
    family: str,
    canonical_target_ids: set[int],
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        issues.append({
            "category": "register_relation_invalid",
            "region": region,
            "family": family,
            "item": value,
        })
        return []
    relation_kinds = {
        "exact", "code_pointer", "data_pointer", "related_word",
        "fixed_code_pointer", "fixed_word",
    }
    result: list[dict[str, Any]] = []
    original_seen: set[str] = set()
    candidate_seen: set[str] = set()
    for item in value:
        relation = item.get("relation") if isinstance(item, dict) else None
        has_target_id = isinstance(item, dict) and "target_id" in item
        target_id = _integer(item.get("target_id")) if has_target_id else None
        has_value = isinstance(item, dict) and "value" in item
        fixed_value = _integer(item.get("value")) if has_value else None
        if (
            not isinstance(item, dict)
            or item.get("original") not in REGISTERS
            or item.get("candidate") not in REGISTERS
            or relation not in relation_kinds
            or (relation == "fixed_code_pointer" and (
                target_id is None
                or target_id < 0
                or target_id not in canonical_target_ids
            ))
            or (relation == "fixed_word" and (
                fixed_value is None or not 0 <= fixed_value < 2**32
            ))
            or (relation != "fixed_code_pointer" and has_target_id)
            or (relation != "fixed_word" and has_value)
        ):
            issues.append({
                "category": "register_relation_invalid",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        original_register = str(item["original"])
        candidate_register = str(item["candidate"])
        if original_register in original_seen or candidate_register in candidate_seen:
            issues.append({
                "category": "register_relation_ambiguous",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        original_seen.add(original_register)
        candidate_seen.add(candidate_register)
        normalized: dict[str, Any] = {
            "original": original_register,
            "candidate": candidate_register,
            "relation": str(relation),
        }
        if relation == "fixed_code_pointer":
            normalized["target_id"] = target_id
        if relation == "fixed_word":
            normalized["value"] = fixed_value
        result.append(normalized)
    return result

_DYNAMIC_WORD_KINDS = {
    "relatedWord", "codePointer", "dataPointer", "nullableDynamicPointer",
}


def _dynamic_words(value: Any) -> list[dict[str, Any]] | None:
    if not isinstance(value, list):
        return None
    words: list[dict[str, Any]] = []
    offsets: set[int] = set()
    for word in value:
        offset = _integer(word.get("offset")) if isinstance(word, dict) else None
        kind = word.get("kind") if isinstance(word, dict) else None
        if (
            offset is None
            or not 0 <= offset < 2**32
            or kind not in _DYNAMIC_WORD_KINDS
            or offset in offsets
        ):
            return None
        offsets.add(offset)
        words.append({"offset": offset, "kind": str(kind)})
    return sorted(words, key=lambda word: word["offset"])


def _dynamic_range_relations(
    value: Any,
    issues: list[dict[str, Any]],
    region: str,
    family: str,
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        issues.append({
            "category": "dynamic_range_relation_not_list",
            "severity": "hard",
            "region": region,
            "family": family,
        })
        return []
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int]] = set()
    for item in value:
        original_offset = _integer(item.get("original_offset")) if isinstance(item, dict) else None
        candidate_offset = _integer(item.get("candidate_offset")) if isinstance(item, dict) else None
        required_words_raw = item.get("required_words") if isinstance(item, dict) else None
        active_words_raw = (
            item.get("active_words", required_words_raw)
            if isinstance(item, dict) else None
        )
        required_words = _dynamic_words(required_words_raw)
        active_words = _dynamic_words(active_words_raw)
        if (
            not isinstance(item, dict)
            or item.get("original") not in REGISTERS
            or item.get("candidate") not in REGISTERS
            or original_offset is None
            or candidate_offset is None
            or not 0 <= original_offset < 2**32
            or not 0 <= candidate_offset < 2**32
            or required_words is None
            or active_words is None
            or any(word not in required_words for word in active_words)
        ):
            issues.append({
                "category": "dynamic_range_relation_invalid",
                "severity": "hard",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        key = (
            str(item["original"]), str(item["candidate"]),
            original_offset, candidate_offset,
        )
        if key in seen:
            issues.append({
                "category": "dynamic_range_relation_invalid",
                "severity": "hard",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        seen.add(key)
        result.append({
            "original": key[0],
            "candidate": key[1],
            "original_offset": original_offset,
            "candidate_offset": candidate_offset,
            "required_words": required_words,
            "active_words": active_words,
        })
    return result


def _dynamic_stack_range_relations(
    value: Any,
    issues: list[dict[str, Any]],
    region: str,
    family: str,
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        issues.append({
            "category": "dynamic_stack_range_relation_not_list",
            "severity": "hard",
            "region": region,
            "family": family,
        })
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        window = item.get("window") if isinstance(item, dict) else None
        stack_offset = _integer(item.get("stack_offset")) if isinstance(item, dict) else None
        original_offset = _integer(item.get("original_offset")) if isinstance(item, dict) else None
        candidate_offset = _integer(item.get("candidate_offset")) if isinstance(item, dict) else None
        required_words_raw = item.get("required_words") if isinstance(item, dict) else None
        active_words_raw = (
            item.get("active_words", required_words_raw)
            if isinstance(item, dict) else None
        )
        required_words = _dynamic_words(required_words_raw)
        active_words = _dynamic_words(active_words_raw)
        window_valid = (
            isinstance(window, dict)
            and _integer(window.get("range_id")) is not None
            and int(window["range_id"]) >= 0
            and window.get("original_register") in REGISTERS
            and window.get("candidate_register") in REGISTERS
            and _integer(window.get("bytes_below")) is not None
            and _integer(window.get("bytes_above")) is not None
            and 0 <= int(window["bytes_below"]) < 2**32
            and 0 < int(window["bytes_above"]) < 2**32
        )
        if (
            not window_valid
            or stack_offset is None
            or original_offset is None
            or candidate_offset is None
            or stack_offset < 0
            or stack_offset % 4 != 0
            or stack_offset + 4 > int(window["bytes_above"])
            or not 0 <= original_offset < 2**32
            or not 0 <= candidate_offset < 2**32
            or required_words is None
            or active_words is None
            or any(word not in required_words for word in active_words)
        ):
            issues.append({
                "category": "dynamic_stack_range_relation_invalid",
                "severity": "hard",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        canonical_window = {
            "range_id": int(window["range_id"]),
            "original_register": str(window["original_register"]),
            "candidate_register": str(window["candidate_register"]),
            "bytes_below": int(window["bytes_below"]),
            "bytes_above": int(window["bytes_above"]),
        }
        normalized = {
            "window": canonical_window,
            "stack_offset": stack_offset,
            "original_offset": original_offset,
            "candidate_offset": candidate_offset,
            "required_words": required_words,
            "active_words": active_words,
        }
        key = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if key in seen:
            issues.append({
                "category": "dynamic_stack_range_relation_invalid",
                "severity": "hard",
                "region": region,
                "family": family,
                "item": item,
            })
            continue
        seen.add(key)
        result.append(normalized)
    return result

def _mapped_relocation_offsets(
    original: StageABinary,
    candidate: StageABinary,
    target: dict[str, int],
    issues: list[dict[str, Any]],
) -> list[int]:
    mapped_size = target["mapped_size"]
    if mapped_size == 0:
        return []

    def offsets(binary: StageABinary, absolute: int) -> list[int]:
        base_rva = absolute - binary.image_base
        return [
            relocation["rva"] - base_rva
            for relocation in _raw_base_relocations(binary)
            if relocation["type"] == 3
            and base_rva <= relocation["rva"]
            and relocation["rva"] + 4 <= base_rva + mapped_size
        ]

    original_offsets = offsets(original, target["original_value"])
    candidate_offsets = offsets(candidate, target["candidate_value"])
    duplicate_offsets = {
        "original": sorted({offset for offset in original_offsets if original_offsets.count(offset) > 1}),
        "candidate": sorted({offset for offset in candidate_offsets if candidate_offsets.count(offset) > 1}),
    }
    if duplicate_offsets["original"] or duplicate_offsets["candidate"]:
        issues.append({
            "category": "mapped_object_relocation_duplicate",
            "severity": "hard",
            "value_target_id": target["id"],
            "duplicates": duplicate_offsets,
            "next_action": "remove duplicate PE32 HIGHLOW entries; each relocation cell must be applied once",
        })
        return []
    original_offsets = sorted(original_offsets)
    candidate_offsets = sorted(candidate_offsets)
    if original_offsets != candidate_offsets:
        issues.append({
            "category": "mapped_object_relocation_shape_mismatch",
            "severity": "hard",
            "value_target_id": target["id"],
            "original_offsets": original_offsets,
            "candidate_offsets": candidate_offsets,
            "next_action": "map objects with identical internal relocation-word structure",
        })
        return []
    ordered = original_offsets
    if any(offset % 4 != 0 for offset in ordered):
        issues.append({
            "category": "mapped_object_relocation_unaligned",
            "severity": "hard",
            "value_target_id": target["id"],
            "offsets": ordered,
            "next_action": "use non-overlapping aligned PE32 HIGHLOW relocation cells",
        })
        return []
    return ordered

def _normalize_padding(value: list[Any], original: StageABinary, candidate: StageABinary, issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or item.get("side") not in {"original", "candidate", "both"}:
            issues.append({"category": "padding_invalid", "index": index})
            continue
        span = _span(item)
        if span is None:
            issues.append({"category": "padding_invalid", "index": index})
            continue
        for side, binary in (("original", original), ("candidate", candidate)):
            if item["side"] not in {side, "both"}:
                continue
            data = binary.pe.get_data(span["rva_start"], span["size"])
            if len(data) != span["size"] or not _padding_bytes(data, binary, span["rva_start"]):
                issues.append({"category": "padding_bytes_invalid", "index": index, "side": side})
        result.append({"id": str(item.get("id") or f"padding-{index}"), "side": item["side"], **span})
    return result

def _padding_bytes(data: bytes, binary: StageABinary, rva: int) -> bool:
    del binary, rva
    patterns = (
        b"\x8d\x74\x26\x00",
        b"\x8d\x76\x00",
        b"\x2e\x8d\x74\x26\x00",
        b"\x2e\x8d\xb4\x26\x00\x00\x00\x00",
        b"\x8d\xb6\x00\x00\x00\x00",
        b"\x8d\xb4\x26\x00\x00\x00\x00",
        b"\x66\x90",
        b"\x00",
        b"\x90",
    )
    def checked(value: bytes) -> bool:
        offset = 0
        while offset < len(value):
            if value[offset] == 0xEB and offset + 2 <= len(value):
                tail = value[offset + 2 :]
                return value[offset + 1] == len(tail) and checked(tail)
            pattern = next((pattern for pattern in patterns if value.startswith(pattern, offset)), None)
            if pattern is None:
                return False
            offset += len(pattern)
        return True

    return checked(data)

def _inside_executable(binary: StageABinary, span: dict[str, int]) -> bool:
    return any(section.executable and section.rva_start <= span["rva_start"] and span["rva_end"] <= section.rva_end for section in binary.sections)

def _padding_bridge_valid(
    side: str,
    alias: int,
    canonical: int,
    padding: list[dict[str, Any]],
) -> bool:
    if alias >= canonical:
        return False
    cursor = alias
    for span in sorted(
        (item for item in padding if item["side"] in {side, "both"}),
        key=lambda item: item["rva_start"],
    ):
        if span["rva_end"] <= cursor:
            continue
        if span["rva_start"] != cursor:
            return False
        cursor = span["rva_end"]
        if cursor == canonical:
            return True
        if cursor > canonical:
            return False
    return False

def _check_span_overlap(regions: list[dict[str, Any]], padding: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for side in ("original", "candidate"):
        spans = [(region[side]["rva_start"], region[side]["rva_end"], region["id"]) for region in regions]
        spans += [(item["rva_start"], item["rva_end"], item["id"]) for item in padding if item["side"] in {side, "both"}]
        spans.sort()
        for left, right in zip(spans, spans[1:]):
            if left[1] > right[0]:
                issues.append({"category": "span_overlap", "side": side, "left": left[2], "right": right[2]})

def _check_coverage(original: StageABinary, candidate: StageABinary, regions: list[dict[str, Any]], padding: list[dict[str, Any]], issues: list[dict[str, Any]]) -> None:
    for side, binary in (("original", original), ("candidate", candidate)):
        spans = [(region[side]["rva_start"], region[side]["rva_end"]) for region in regions]
        spans += [(item["rva_start"], item["rva_end"]) for item in padding if item["side"] in {side, "both"}]
        for section in (section for section in binary.sections if section.executable):
            cursor = section.rva_start
            for start, stop in sorted(span for span in spans if section.rva_start <= span[0] and span[1] <= section.rva_end):
                if start != cursor:
                    issues.append({"category": "executable_coverage_gap", "side": side, "rva_start": cursor, "rva_end": start})
                cursor = max(cursor, stop)
            if cursor != section.rva_end:
                issues.append({"category": "executable_coverage_gap", "side": side, "rva_start": cursor, "rva_end": section.rva_end})

def _semantic_expr_is_pure(expression: Any) -> bool:
    if (
        not isinstance(expression, dict)
        or expression.get("op") not in PURE_SEMANTIC_EXPR_OPERATIONS
    ):
        return False
    for key, value in expression.items():
        if key == "op":
            continue
        if isinstance(value, dict) and "op" in value and not _semantic_expr_is_pure(value):
            return False
        if isinstance(value, list) and any(
            isinstance(item, dict) and "op" in item and not _semantic_expr_is_pure(item)
            for item in value
        ):
            return False
    return True

def _import_identity(imported: Any) -> tuple[str, str, str | int] | None:
    if isinstance(imported, dict):
        dll = str(imported.get("dll", "")).lower()
        symbol = imported.get("symbol")
        ordinal = _integer(imported.get("ordinal"))
    else:
        dll = str(getattr(imported, "dll", "")).lower()
        symbol = getattr(imported, "symbol", None)
        ordinal = getattr(imported, "ordinal", None)
    if not dll or (symbol is None) == (ordinal is None):
        return None
    return (dll, "symbol", str(symbol)) if symbol is not None else (
        dll, "ordinal", int(ordinal)
    )
