"""Machine-level ABI evidence and candidate ABI comparison."""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import sys
from bisect import bisect_left
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from ..pe32.stage_binary import (
    BlockSide,
    StageABinary,
    StageAImport,
    StageAInputError,
    StageASection,
    _artifact_name,
    _coff_symbol_aliases_by_rva,
    _executable_section_for_rva,
    _parse_linker_map_functions,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
    _section_for_rva,
)
from ..extraction.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS,
    BlockMapping,
    STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES,
    _is_conditional_jump,
    _mapping_source,
    _range_report,
)

from .map_analysis import (
    _capstone_mode,
    _linker_function_match_key,
    _recover_basic_blocks,
)
from .map_analysis import (
    _absolute_mem_operand_rva,
    _direct_branch_target,
    _direct_cfg_edges,
    _import_for_absolute_memory_operand,
    _import_for_thunk_rva,
    _instruction_report,
    _resolved_branch_target,
)

from .abi_arguments import (
    _abi_argument_source,
    _abi_call_argument_inventory,
    _abi_callsite_evidence,
    _abi_function_pointer_targets,
    _abi_hidden_sret_evidence,
    _abi_pending_argument_sources,
    _abi_resets_pending_arguments,
    _abi_stack_argument_write_offset,
    _abi_stack_argument_write_source,
    _abi_update_register_definitions,
    _abi_varargs_evidence,
)

from .abi_control_flow import (
    _abi_direct_control_transfers,
    _abi_direct_refptr_transfers,
    _abi_indexed_jump_table_contract,
    _abi_switch_contracts,
)

from .abi_instruction import (
    _abi_instruction_is_semantic_noop,
    _abi_instruction_memory_accesses,
    _abi_loop_hints,
    _abi_mem_operand_report,
    _abi_memory_effect_summary,
    _abi_operand_register_name,
    _abi_register_out_param_candidates,
    _abi_ret_imm,
    _abi_stack_pointer_adjustment,
    _abi_x86_register_family,
    _instruction_register_access,
)

from .abi_support import (
    _abi_function_local_loop_hints,
    _abi_loop_hint_key,
    _optional_contract_int,
    _safe_int,
)

def _abi_function_gap_sample(function: dict[str, Any], match_key: str) -> dict[str, Any]:
    blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
    callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
    return {
        "name": function.get("name"),
        "match_key": match_key,
        "blocks": [
            {
                "block_id": block.get("block_id"),
                "rva_start": block.get("rva_start"),
                "rva_end": block.get("rva_end"),
                "size": block.get("size"),
            }
            for block in blocks[:5]
            if isinstance(block, dict)
        ],
        "callsites": len(callsites),
        "callsite_samples": [_abi_callsite_gap_sample(item) for item in callsites[:5]],
    }

def _abi_callsite_gap_sample(callsite: Any) -> dict[str, Any]:
    if not isinstance(callsite, dict):
        return {}
    instruction = callsite.get("instruction") if isinstance(callsite.get("instruction"), dict) else {}
    return {
        "id": callsite.get("id"),
        "block_id": callsite.get("block_id"),
        "instruction": {
            "rva": instruction.get("rva"),
            "mnemonic": instruction.get("mnemonic"),
            "op_str": instruction.get("op_str"),
        },
        "target": callsite.get("target") if isinstance(callsite.get("target"), dict) else {},
    }

def _abi_function_evidence(
    binary: StageABinary | None,
    mappings: list[BlockMapping],
    *,
    side: str,
    compose_direct_callee_import_memory: bool = False,
) -> list[dict[str, Any]]:
    if binary is None:
        return []
    by_name: dict[str, dict[str, Any]] = {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        name = source.get("function") if isinstance(source.get("function"), str) and source.get("function") else mapped.id
        block = mapped.original if side == "original" else mapped.candidate
        entry = by_name.setdefault(
            name,
            {
                "name": name,
                "blocks": [],
                "callsites": [],
                "registers": {
                    "reads": [],
                    "writes": [],
                    "preserved_candidates": [],
                    "clobbered_candidates": [],
                },
                "stack_delta": {"status": "unknown"},
            },
        )
        block_evidence = _abi_block_evidence(binary, block, mapped.id)
        entry.setdefault("_abi_block_records", []).append(
            {
                "block_id": mapped.id,
                "block": block,
                "evidence": block_evidence,
                "edges": _direct_cfg_edges(binary, block),
            }
        )
        entry["blocks"].append({"block_id": mapped.id, **_range_report(block), "abi": _abi_block_contract_evidence(block_evidence)})
        entry["callsites"].extend(block_evidence["callsites"])
        entry["registers"]["reads"] = sorted(set(entry["registers"]["reads"]) | set(block_evidence["register_reads"]))
        entry["registers"]["writes"] = sorted(set(entry["registers"]["writes"]) | set(block_evidence["register_writes"]))
        entry["registers"]["preserved_candidates"] = sorted(set(entry["registers"]["preserved_candidates"]) | set(block_evidence["preserved_candidates"]))
        entry["registers"]["clobbered_candidates"] = sorted(set(entry["registers"]["clobbered_candidates"]) | set(block_evidence["clobbered_candidates"]))
        entry.setdefault("register_value_provenance", []).extend(block_evidence.get("register_value_provenance", []))
        entry.setdefault("register_out_param_candidates", []).extend(block_evidence.get("register_out_param_candidates", []))
        entry.setdefault("memory_reads", []).extend(block_evidence.get("memory_reads", []))
        entry.setdefault("memory_writes", []).extend(block_evidence.get("memory_writes", []))
        entry.setdefault("field_accesses", []).extend(block_evidence.get("field_accesses", []))
        entry.setdefault("switch_contracts", []).extend(block_evidence.get("switch_contracts", []))
        entry.setdefault("loop_hints", []).extend(block_evidence.get("loop_hints", []))
        entry.setdefault("direct_refptr_transfers", []).extend(block_evidence.get("direct_refptr_transfers", []))
        entry.setdefault("direct_control_transfers", []).extend(block_evidence.get("direct_control_transfers", []))
        entry["memory_effect_summary"] = _abi_memory_effect_summary(entry.get("memory_reads", []), entry.get("memory_writes", []))
    for entry in by_name.values():
        records = entry.pop("_abi_block_records", [])
        if isinstance(records, list):
            _abi_apply_predecessor_argument_sources(binary, records)
            _abi_apply_predecessor_switch_bounds(binary, records)
            entry["callsites"] = [
                callsite
                for record in records
                for callsite in (
                    record.get("evidence", {}).get("callsites", [])
                    if isinstance(record.get("evidence"), dict)
                    else []
                )
                if isinstance(callsite, dict)
            ]
            entry["decision_tree_contracts"] = _abi_direct_compare_dispatch_contracts(binary, records)
        _abi_filter_function_local_loop_hints(entry)
        entry["stack_delta"] = _abi_function_stack_delta_summary(entry.get("blocks"), str(entry.get("name") or ""))
    if compose_direct_callee_import_memory:
        _abi_apply_direct_callee_import_memory_effects(list(by_name.values()))
    return sorted(by_name.values(), key=lambda item: str(item.get("name") or ""))

def _abi_filter_function_local_loop_hints(function: dict[str, Any]) -> None:
    local_hints = _abi_function_local_loop_hints(function)
    local_keys = {_abi_loop_hint_key(item) for item in local_hints}
    function["loop_hints"] = local_hints
    for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
        if not isinstance(block, dict) or not isinstance(block.get("abi"), dict):
            continue
        block["abi"]["loop_hints"] = [
            hint
            for hint in block["abi"].get("loop_hints", [])
            if isinstance(hint, dict) and _abi_loop_hint_key(hint) in local_keys
        ]

def _abi_direct_compare_dispatch_contracts(binary: StageABinary, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases_by_register: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("block"), BlockSide):
            continue
        block = record["block"]
        instructions = _abi_decode_block_instructions(binary, block)
        for index, insn in enumerate(instructions):
            selector = _abi_compare_immediate_selector(insn)
            if selector is None:
                continue
            branch = _abi_next_conditional_branch(instructions, index + 1)
            if branch is None:
                continue
            target = _resolved_branch_target(binary, branch)
            if target is None:
                continue
            cases_by_register.setdefault(selector["register"], []).append(
                {
                    "value": selector["value"],
                    "target_rva": target,
                    "block": _range_report(block),
                    "compare_instruction": _instruction_report(binary, insn),
                    "branch_instruction": _instruction_report(binary, branch),
                }
            )
    contracts: list[dict[str, Any]] = []
    for register, cases in sorted(cases_by_register.items()):
        unique_values = sorted({_safe_int(case.get("value")) for case in cases if _safe_int(case.get("value")) is not None})
        unique_targets = sorted({_safe_int(case.get("target_rva")) for case in cases if _safe_int(case.get("target_rva")) is not None})
        if len(unique_values) < 4 or len(unique_targets) < 2:
            continue
        contracts.append(
            {
                "evidence_status": "derived",
                "kind": "direct_compare_dispatch_candidate",
                "selector_register": register,
                "case_count": len(unique_values),
                "target_count": len(unique_targets),
                "case_values": unique_values,
                "case_targets": sorted(cases, key=lambda item: (_safe_int(item.get("value")) or -1, _safe_int(item.get("target_rva")) or -1)),
                "next_action": "prove this direct compare/branch decision tree covers the reference switch or jump-table target set",
            }
        )
    return contracts

def _abi_decode_block_instructions(binary: StageABinary, block: BlockSide) -> list[Any]:
    data = binary.pe.get_data(block.rva_start, block.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + block.rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return []
    return instructions

def _abi_compare_immediate_selector(insn: Any) -> dict[str, int | str] | None:
    if str(insn.mnemonic) != "cmp" or len(insn.operands) != 2:
        return None
    left, right = insn.operands[0], insn.operands[1]
    if left.type == X86_OP_REG and right.type == X86_OP_IMM:
        register = _abi_operand_register_name(insn, left)
        if register:
            return {"register": register, "value": int(right.imm)}
    if left.type == X86_OP_IMM and right.type == X86_OP_REG:
        register = _abi_operand_register_name(insn, right)
        if register:
            return {"register": register, "value": int(left.imm)}
    return None

def _abi_next_conditional_branch(instructions: list[Any], start_index: int) -> Any | None:
    for insn in instructions[start_index : start_index + 3]:
        if _abi_instruction_is_semantic_noop(insn):
            continue
        if _is_conditional_jump(str(insn.mnemonic)):
            return insn
        return None
    return None

def _abi_apply_direct_callee_import_memory_effects(functions: list[dict[str, Any]], *, max_depth: int = 2) -> None:
    ranges: list[tuple[int, int, dict[str, Any]]] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            ranges.append((start, end, function))
    ranges.sort(key=lambda item: (item[1] - item[0], str(item[2].get("name") or "")))

    def function_for_rva(rva: int) -> dict[str, Any] | None:
        for start, end, function in ranges:
            if start <= rva < end:
                return function
        return None

    cache: dict[tuple[int, int], tuple[list[dict[str, Any]], list[dict[str, Any]]]] = {}

    def collect(function: dict[str, Any], depth: int, stack: tuple[int, ...]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        if depth <= 0:
            return [], []
        function_identity = id(function)
        if function_identity in stack:
            return [], []
        key = (function_identity, depth)
        if key in cache:
            reads, writes = cache[key]
            return [copy.deepcopy(item) for item in reads], [copy.deepcopy(item) for item in writes]

        reads = [
            _abi_composed_direct_callee_memory_access(function, item)
            for item in function.get("memory_reads", [])
            if isinstance(item, dict) and _abi_memory_access_is_import_effect(item)
        ]
        writes = [
            _abi_composed_direct_callee_memory_access(function, item)
            for item in function.get("memory_writes", [])
            if isinstance(item, dict) and _abi_memory_access_is_import_effect(item)
        ]
        for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
            if not isinstance(callsite, dict):
                continue
            target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
            if target.get("kind") != "direct":
                continue
            target_rva = _optional_contract_int(target.get("target_rva"))
            if target_rva is None:
                continue
            callee = function_for_rva(target_rva)
            if callee is None or callee is function:
                continue
            callee_reads, callee_writes = collect(callee, depth - 1, (*stack, function_identity))
            reads.extend(_abi_reparent_composed_memory_access(callsite, callee, item) for item in callee_reads)
            writes.extend(_abi_reparent_composed_memory_access(callsite, callee, item) for item in callee_writes)

        cache[key] = ([copy.deepcopy(item) for item in reads], [copy.deepcopy(item) for item in writes])
        return reads, writes

    for function in functions:
        if not isinstance(function, dict):
            continue
        composed_reads: list[dict[str, Any]] = []
        composed_writes: list[dict[str, Any]] = []
        for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
            if not isinstance(callsite, dict):
                continue
            target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
            if target.get("kind") != "direct":
                continue
            target_rva = _optional_contract_int(target.get("target_rva"))
            if target_rva is None:
                continue
            callee = function_for_rva(target_rva)
            if callee is None or callee is function:
                continue
            callee_reads, callee_writes = collect(callee, max_depth, (id(function),))
            composed_reads.extend(_abi_reparent_composed_memory_access(callsite, callee, item) for item in callee_reads)
            composed_writes.extend(_abi_reparent_composed_memory_access(callsite, callee, item) for item in callee_writes)
        if not composed_reads and not composed_writes:
            continue
        function.setdefault("direct_callee_import_memory_effects", {"reads": [], "writes": []})
        effects = function["direct_callee_import_memory_effects"]
        if isinstance(effects, dict):
            effects["reads"] = [*effects.get("reads", []), *composed_reads] if isinstance(effects.get("reads"), list) else composed_reads
            effects["writes"] = [*effects.get("writes", []), *composed_writes] if isinstance(effects.get("writes"), list) else composed_writes
        function.setdefault("memory_reads", []).extend(composed_reads)
        function.setdefault("memory_writes", []).extend(composed_writes)
        function["memory_effect_summary"] = _abi_memory_effect_summary(
            function.get("memory_reads", []),
            function.get("memory_writes", []),
        )

def _abi_memory_access_is_import_effect(access: dict[str, Any]) -> bool:
    if isinstance(access.get("import"), dict):
        return True
    return access.get("memory_role") == "import_address_table"

def _abi_composed_direct_callee_memory_access(function: dict[str, Any], access: dict[str, Any]) -> dict[str, Any]:
    return {
        **copy.deepcopy(access),
        "evidence_status": "composed",
        "composition_kind": "direct_callee_import_memory",
        "callee_function": function.get("name"),
    }

def _abi_reparent_composed_memory_access(callsite: dict[str, Any], callee: dict[str, Any], access: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(access)
    result["evidence_status"] = "composed"
    result["composition_kind"] = "direct_callee_import_memory"
    result["direct_callsite"] = _abi_callsite_gap_sample(callsite)
    result["callee_function"] = callee.get("name")
    return result

def _abi_apply_predecessor_argument_sources(binary: StageABinary, records: list[dict[str, Any]]) -> None:
    records_by_start: dict[int, dict[str, Any]] = {}
    for record in records:
        block = record.get("block")
        if isinstance(block, BlockSide):
            records_by_start[block.rva_start] = record
    predecessor_sources: dict[int, list[dict[str, Any]]] = {}
    for record in records:
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        exit_sources = evidence.get("exit_argument_sources") if isinstance(evidence.get("exit_argument_sources"), list) else []
        edges = record.get("edges") if isinstance(record.get("edges"), list) else []
        for edge in edges:
            if not isinstance(edge, dict) or edge.get("kind") not in {"fallthrough", "taken", "jump"}:
                continue
            target_rva = _safe_int(edge.get("target_rva"))
            if target_rva is None:
                continue
            resolved_target_rva = _abi_resolve_predecessor_argument_target(binary, target_rva, records_by_start)
            if resolved_target_rva is None:
                continue
            predecessor_sources.setdefault(resolved_target_rva, []).append(
                {
                    "block_id": record.get("block_id"),
                    "edge": edge,
                    "resolved_target_rva": resolved_target_rva,
                    "argument_sources": exit_sources,
                }
            )
    for target_rva, predecessor_items in predecessor_sources.items():
        record = records_by_start.get(target_rva)
        if record is None:
            continue
        block = record.get("block")
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        if not isinstance(block, BlockSide):
            continue
        callsites = evidence.get("callsites") if isinstance(evidence.get("callsites"), list) else []
        first_callsite = callsites[0] if callsites and isinstance(callsites[0], dict) else None
        if first_callsite is None:
            continue
        instruction = first_callsite.get("instruction") if isinstance(first_callsite.get("instruction"), dict) else {}
        if _safe_int(instruction.get("rva")) != block.rva_start:
            continue
        inventory = first_callsite.get("argument_inventory") if isinstance(first_callsite.get("argument_inventory"), dict) else {}
        if _safe_int(inventory.get("argument_count")) not in {None, 0}:
            continue
        unique_sources: dict[str, list[dict[str, Any]]] = {}
        for item in predecessor_items:
            sources = item.get("argument_sources") if isinstance(item.get("argument_sources"), list) else []
            key = json.dumps(sources, sort_keys=True, separators=(",", ":"))
            unique_sources.setdefault(key, []).append(item)
        if len(unique_sources) != 1:
            continue
        sources = list(next(iter(unique_sources.values()))[0]["argument_sources"])
        if not sources:
            continue
        metadata = {
            "status": "derived",
            "source": "direct_cfg_predecessor_exit",
            "predecessor_block_ids": sorted(
                str(item.get("block_id"))
                for item in predecessor_items
                if item.get("block_id") is not None
            ),
            "predecessor_edges": [
                {
                    "kind": item.get("edge", {}).get("kind"),
                    "instruction_rva": item.get("edge", {}).get("instruction_rva"),
                    "target_rva": item.get("edge", {}).get("target_rva"),
                    "resolved_target_rva": item.get("resolved_target_rva"),
                }
                for item in predecessor_items
                if isinstance(item.get("edge"), dict)
            ],
            "argument_source_count": len(sources),
        }
        callsites[0] = _abi_callsite_with_argument_sources(binary, first_callsite, sources, metadata)

def _abi_resolve_predecessor_argument_target(
    binary: StageABinary,
    target_rva: int,
    records_by_start: dict[int, dict[str, Any]],
) -> int | None:
    if target_rva in records_by_start:
        return target_rva
    section = _section_for_rva(binary, target_rva)
    if section is None or not section.executable:
        return None
    size = min(8, section.rva_end - target_rva)
    if size <= 0:
        return None
    data = binary.pe.get_data(target_rva, size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + target_rva))
    if not instructions:
        return None
    insn = instructions[0]
    if int(insn.address - binary.image_base) != target_rva or str(insn.mnemonic) not in {"jmp", "ljmp"}:
        return None
    resolved = _resolved_branch_target(binary, insn)
    if resolved is None or resolved not in records_by_start:
        return None
    return resolved

def _abi_apply_predecessor_switch_bounds(binary: StageABinary, records: list[dict[str, Any]]) -> None:
    records_by_start: dict[int, dict[str, Any]] = {}
    for record in records:
        block = record.get("block")
        if isinstance(block, BlockSide):
            records_by_start[block.rva_start] = record
    predecessor_edges: dict[int, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    for record in records:
        edges = record.get("edges") if isinstance(record.get("edges"), list) else []
        for edge in edges:
            if not isinstance(edge, dict) or edge.get("kind") not in {"fallthrough", "taken", "jump"}:
                continue
            target_rva = _safe_int(edge.get("target_rva"))
            if target_rva is None or target_rva not in records_by_start:
                continue
            predecessor_edges.setdefault(target_rva, []).append((record, edge))

    for record in records:
        block = record.get("block")
        evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
        switches = evidence.get("switch_contracts") if isinstance(evidence.get("switch_contracts"), list) else []
        if not isinstance(block, BlockSide) or not switches:
            continue
        for switch in switches:
            if not isinstance(switch, dict) or switch.get("evidence_status") == "derived":
                continue
            index_expression = switch.get("index_expression") if isinstance(switch.get("index_expression"), dict) else {}
            index_register = _abi_x86_register_family(str(index_expression.get("index") or ""))
            if not index_register:
                continue
            current_bounds = _abi_switch_bounds_dict(switch.get("table_bounds"))
            refined_bounds = current_bounds
            for predecessor, edge in predecessor_edges.get(block.rva_start, []):
                predecessor_block = predecessor.get("block")
                if not isinstance(predecessor_block, BlockSide):
                    continue
                guard_bounds = _abi_predecessor_edge_switch_bounds(
                    binary,
                    predecessor_block,
                    edge,
                    index_register,
                )
                if guard_bounds is None:
                    continue
                refined_bounds = _abi_intersect_switch_bounds(refined_bounds, guard_bounds)
            if refined_bounds is None or refined_bounds == current_bounds:
                continue
            instructions = _abi_capstone_block_instructions(binary, block)
            jmp = next(
                (
                    insn
                    for insn in instructions
                    if str(insn.mnemonic) in {"jmp", "ljmp"}
                    and len(getattr(insn, "operands", []) or []) == 1
                    and insn.operands[0].type == X86_OP_MEM
                    and _safe_int(switch.get("instruction", {}).get("rva") if isinstance(switch.get("instruction"), dict) else None)
                    == int(insn.address - binary.image_base)
                ),
                None,
            )
            if jmp is None:
                continue
            addressing = _abi_mem_operand_report(jmp, jmp.operands[0])
            refined = _abi_indexed_jump_table_contract(
                binary,
                block,
                instructions,
                jmp,
                addressing,
                bounds_override=refined_bounds,
            )
            if refined is not None and refined.get("evidence_status") == "derived":
                switch.clear()
                switch.update(refined)

def _abi_predecessor_edge_switch_bounds(
    binary: StageABinary,
    block: BlockSide,
    edge: dict[str, Any],
    index_register: str,
) -> dict[str, Any] | None:
    instruction_rva = _safe_int(edge.get("instruction_rva"))
    edge_kind = str(edge.get("kind") or "")
    if instruction_rva is None or edge_kind not in {"fallthrough", "taken"}:
        return None
    instructions = _abi_capstone_block_instructions(binary, block)
    for index, insn in enumerate(instructions):
        if int(insn.address - binary.image_base) != instruction_rva:
            continue
        mnemonic = str(insn.mnemonic)
        if not _is_conditional_jump(mnemonic) or index == 0:
            return None
        cmp_insn = instructions[index - 1]
        upper = _abi_cmp_register_immediate_upper_bound(cmp_insn, index_register)
        if upper is None:
            return None
        gives_upper_bound = (
            (mnemonic in {"ja", "jnbe"} and edge_kind == "fallthrough")
            or (mnemonic in {"jbe", "jna"} and edge_kind == "taken")
        )
        if not gives_upper_bound:
            return None
        return {
            "status": "derived",
            "lower": 0,
            "upper": upper,
            "register": index_register,
            "source": "predecessor_unsigned_upper_bound",
            "source_edge": {
                "kind": edge_kind,
                "instruction_rva": instruction_rva,
                "target_rva": edge.get("target_rva"),
            },
            "source_instruction": _instruction_report(binary, cmp_insn),
            "branch_instruction": _instruction_report(binary, insn),
        }
    return None

def _abi_capstone_block_instructions(binary: StageABinary, block: BlockSide) -> list[Any]:
    data = binary.pe.get_data(block.rva_start, block.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return list(dis.disasm(data, binary.image_base + block.rva_start))

def _abi_cmp_register_immediate_upper_bound(insn: Any, index_register: str) -> int | None:
    if str(insn.mnemonic) != "cmp" or len(getattr(insn, "operands", []) or []) != 2:
        return None
    left, right = insn.operands[:2]
    if left.type != X86_OP_REG or right.type != X86_OP_IMM:
        return None
    if _abi_x86_register_family(insn.reg_name(left.reg)) != index_register:
        return None
    value = int(right.imm)
    if value < 0 or value > 4095:
        return None
    return value

def _abi_switch_bounds_dict(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    lower = _safe_int(value.get("lower"))
    upper = _safe_int(value.get("upper"))
    if lower is None or upper is None:
        return None
    return dict(value)

def _abi_intersect_switch_bounds(left: dict[str, Any] | None, right: dict[str, Any]) -> dict[str, Any]:
    if left is None:
        return dict(right)
    lower = max(int(left.get("lower") or 0), int(right.get("lower") or 0))
    upper = min(int(left.get("upper") or 0), int(right.get("upper") or 0))
    result = dict(right if upper == int(right.get("upper") or 0) else left)
    result["status"] = "derived"
    result["lower"] = lower
    result["upper"] = upper
    result["source"] = "intersected_static_index_bounds"
    result["sources"] = [left, right]
    return result

def _abi_callsite_with_argument_sources(
    binary: StageABinary,
    callsite: dict[str, Any],
    argument_sources: list[dict[str, Any]],
    predecessor_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    inventory = _abi_call_argument_inventory(binary, argument_sources, {}, target=target)
    symbol = str(target.get("symbol") or "")
    updated = {
        **callsite,
        "argument_sources": argument_sources,
        "argument_inventory": inventory,
        "hidden_sret_or_out_param_evidence": _abi_hidden_sret_evidence(argument_sources),
        "varargs_evidence": _abi_varargs_evidence(symbol, inventory),
        "function_pointer_targets": _abi_function_pointer_targets(target),
    }
    if predecessor_metadata is not None:
        updated["predecessor_argument_sources"] = predecessor_metadata
    return updated

def _abi_function_stack_delta_summary(blocks: Any, function_name: str = "") -> dict[str, Any]:
    block_items = [block for block in blocks if isinstance(block, dict)] if isinstance(blocks, list) else []
    derived = [
        stack_delta
        for block in block_items
        for stack_delta in [block.get("abi", {}).get("stack_delta") if isinstance(block.get("abi"), dict) else None]
        if isinstance(stack_delta, dict) and stack_delta.get("status") == "derived"
    ]
    if function_name.startswith("section-gap-"):
        return {
            "status": "block_local",
            "reason": "synthetic section-gap unit; stack deltas are reported per block",
            "blocks": len(block_items),
            "derived_blocks": len(derived),
        }
    if len(block_items) == 1 and derived:
        return {**derived[0], "scope": "function"}
    if len(block_items) > 1:
        return {
            "status": "block_local",
            "reason": "function spans multiple Stage A blocks; stack deltas are reported per block",
            "blocks": len(block_items),
            "derived_blocks": len(derived),
        }
    return {"status": "unknown", "reason": "no derived block stack delta"}

def _abi_block_contract_evidence(block_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "callsites": block_evidence.get("callsites", []),
        "register_reads": block_evidence.get("register_reads", []),
        "register_writes": block_evidence.get("register_writes", []),
        "preserved_candidates": block_evidence.get("preserved_candidates", []),
        "clobbered_candidates": block_evidence.get("clobbered_candidates", []),
        "register_value_provenance": block_evidence.get("register_value_provenance", []),
        "register_out_param_candidates": block_evidence.get("register_out_param_candidates", []),
        "exit_argument_sources": block_evidence.get("exit_argument_sources", []),
        "memory_reads": block_evidence.get("memory_reads", []),
        "memory_writes": block_evidence.get("memory_writes", []),
        "field_accesses": block_evidence.get("field_accesses", []),
        "memory_effect_summary": block_evidence.get("memory_effect_summary", {}),
        "switch_contracts": block_evidence.get("switch_contracts", []),
        "loop_hints": block_evidence.get("loop_hints", []),
        "direct_refptr_transfers": block_evidence.get("direct_refptr_transfers", []),
        "direct_control_transfers": block_evidence.get("direct_control_transfers", []),
        "stack_delta": block_evidence.get("stack_delta", {"status": "unknown"}),
    }

def _abi_block_evidence(binary: StageABinary, block: BlockSide, block_id: str) -> dict[str, Any]:
    data = binary.pe.get_data(block.rva_start, block.size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    instructions = list(dis.disasm(data, binary.image_base + block.rva_start))
    if sum(int(insn.size) for insn in instructions) != len(data):
        return {
            "callsites": [],
            "register_reads": [],
            "register_writes": [],
            "preserved_candidates": [],
            "clobbered_candidates": [],
            "register_value_provenance": [],
            "register_out_param_candidates": [],
            "exit_argument_sources": [],
            "memory_reads": [],
            "memory_writes": [],
            "field_accesses": [],
            "memory_effect_summary": {"status": "unknown", "reason": "decode_incomplete"},
            "switch_contracts": [],
            "loop_hints": [],
            "direct_refptr_transfers": [],
            "direct_control_transfers": [],
            "stack_delta": {"status": "unknown", "reason": "decode_incomplete"},
        }
    callsites = []
    register_reads: set[str] = set()
    register_writes: set[str] = set()
    register_definitions: dict[str, dict[str, Any]] = {}
    register_definition_history: list[dict[str, Any]] = []
    pushes: list[dict[str, Any]] = []
    stack_argument_writes: dict[int, dict[str, Any]] = {}
    memory_reads: list[dict[str, Any]] = []
    memory_writes: list[dict[str, Any]] = []
    field_accesses: list[dict[str, Any]] = []
    stack_delta = 0
    for insn in instructions:
        if _abi_instruction_is_semantic_noop(insn):
            continue
        reads, writes = _instruction_register_access(insn)
        register_reads.update(reads)
        register_writes.update(writes)
        accesses = _abi_instruction_memory_accesses(binary, insn, register_definitions)
        memory_reads.extend(accesses["reads"])
        memory_writes.extend(accesses["writes"])
        field_accesses.extend(accesses["field_accesses"])
        mnemonic = str(insn.mnemonic)
        if mnemonic == "push":
            stack_delta -= 4 if binary.bitness == 32 else 8
            pushes.append(_abi_argument_source(binary, insn, register_definitions))
        elif mnemonic == "pop":
            stack_delta += 4 if binary.bitness == 32 else 8
            pushes = []
            stack_argument_writes = {}
        elif mnemonic == "leave":
            stack_delta = 0
            pushes = []
            stack_argument_writes = {}
        elif (stack_adjustment := _abi_stack_pointer_adjustment(binary, insn)) is not None:
            stack_delta += stack_adjustment
            pushes = []
            stack_argument_writes = {}
        elif _abi_resets_pending_arguments(insn):
            pushes = []
            stack_argument_writes = {}
        elif mnemonic == "ret":
            stack_delta += _abi_ret_imm(insn)
            pushes = []
            stack_argument_writes = {}
        elif mnemonic == "call":
            callsites.append(
                _abi_callsite_evidence(
                    binary,
                    insn,
                    block_id,
                    _abi_pending_argument_sources(pushes, stack_argument_writes, word_size=4 if binary.bitness == 32 else 8),
                    register_definitions,
                )
            )
            pushes = []
            stack_argument_writes = {}
        else:
            offset = _abi_stack_argument_write_offset(insn)
            if offset is not None:
                stack_argument_writes[offset] = _abi_stack_argument_write_source(binary, insn, offset, register_definitions)
        defined_register = _abi_update_register_definitions(binary, insn, register_definitions, writes)
        if defined_register is not None and defined_register in register_definitions:
            register_definition_history.append(
                {
                    "register": defined_register,
                    "definition": register_definitions[defined_register],
                    "evidence_status": "derived",
                }
            )
        if mnemonic == "call":
            for volatile in ("eax", "ecx", "edx", "rax", "rcx", "rdx"):
                if volatile != defined_register:
                    register_definitions.pop(volatile, None)
    preserved = sorted(reg for reg in ("ebx", "esi", "edi", "rbx", "rsi", "rdi") if reg in register_reads and reg in register_writes)
    clobbered = sorted(reg for reg in register_writes if reg not in set(preserved) and reg not in {"esp", "rsp", "ebp", "rbp"})
    register_out_params = _abi_register_out_param_candidates(memory_writes)
    return {
        "callsites": callsites,
        "register_reads": sorted(register_reads),
        "register_writes": sorted(register_writes),
        "preserved_candidates": preserved,
        "clobbered_candidates": clobbered,
        "register_value_provenance": register_definition_history,
        "register_out_param_candidates": register_out_params,
        "exit_argument_sources": _abi_pending_argument_sources(pushes, stack_argument_writes, word_size=4 if binary.bitness == 32 else 8),
        "memory_reads": memory_reads,
        "memory_writes": memory_writes,
        "field_accesses": field_accesses,
        "memory_effect_summary": _abi_memory_effect_summary(memory_reads, memory_writes),
        "switch_contracts": _abi_switch_contracts(binary, block, instructions),
        "loop_hints": _abi_loop_hints(binary, block, instructions),
        "direct_refptr_transfers": _abi_direct_refptr_transfers(binary, block, instructions),
        "direct_control_transfers": _abi_direct_control_transfers(binary, block, instructions),
        "stack_delta": {"status": "derived", "net_bytes": stack_delta},
    }

__all__ = [
    '_abi_apply_direct_callee_import_memory_effects',
    '_abi_apply_predecessor_argument_sources',
    '_abi_apply_predecessor_switch_bounds',
    '_abi_block_contract_evidence',
    '_abi_block_evidence',
    '_abi_callsite_gap_sample',
    '_abi_callsite_with_argument_sources',
    '_abi_capstone_block_instructions',
    '_abi_cmp_register_immediate_upper_bound',
    '_abi_compare_immediate_selector',
    '_abi_composed_direct_callee_memory_access',
    '_abi_decode_block_instructions',
    '_abi_direct_compare_dispatch_contracts',
    '_abi_filter_function_local_loop_hints',
    '_abi_function_evidence',
    '_abi_function_gap_sample',
    '_abi_function_stack_delta_summary',
    '_abi_intersect_switch_bounds',
    '_abi_memory_access_is_import_effect',
    '_abi_next_conditional_branch',
    '_abi_predecessor_edge_switch_bounds',
    '_abi_reparent_composed_memory_access',
    '_abi_resolve_predecessor_argument_target',
    '_abi_switch_bounds_dict',
]
