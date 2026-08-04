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

from ..stage_binary import (
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
from ..analysis.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS,
    BlockMapping,
    STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES,
    _is_conditional_jump,
    _mapping_source,
    _range_report,
)

from .map_generation import (
    _absolute_mem_operand_rva,
    _capstone_mode,
    _direct_branch_target,
    _direct_cfg_edges,
    _import_for_absolute_memory_operand,
    _import_for_thunk_rva,
    _instruction_report,
    _linker_function_match_key,
    _recover_basic_blocks,
    _resolved_branch_target,
)

def _abi_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
            if not isinstance(callsite, dict):
                continue
            callsite_id = str(callsite.get("id") or "")
            hidden = callsite.get("hidden_sret_or_out_param_evidence") if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
            if hidden.get("status") == "candidate":
                clusters.append(
                    _cluster_contract(
                        contract_ref=contract_ref,
                        cluster_id=f"hidden-sret:{callsite_id}",
                        cluster_kind="abi_hidden_sret_or_out_param",
                        function=function_name,
                        block_id=str(callsite.get("block_id") or ""),
                        repair_class="hidden_sret_or_out_param",
                        next_action="preserve the first address-like stack argument as an explicit out parameter or hidden sret bridge in generated C",
                        evidence={"callsite": callsite, "hidden_sret_or_out_param_evidence": hidden},
                    )
                )
            varargs = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
            if varargs.get("status") == "candidate":
                clusters.append(
                    _cluster_contract(
                        contract_ref=contract_ref,
                        cluster_id=f"varargs:{callsite_id}",
                        cluster_kind="abi_varargs_callsite",
                        function=function_name,
                        block_id=str(callsite.get("block_id") or ""),
                        repair_class="varargs_or_stdio_bridge",
                        next_action="model the variadic call bridge exactly enough for the candidate ABI and imported stdio target",
                        evidence={"callsite": callsite, "varargs_evidence": varargs},
                    )
                )
            for target in callsite.get("function_pointer_targets", []) if isinstance(callsite.get("function_pointer_targets"), list) else []:
                if isinstance(target, dict) and target.get("status") == "unresolved":
                    clusters.append(
                        _cluster_contract(
                            contract_ref=contract_ref,
                            cluster_id=f"function-pointer:{callsite_id}",
                            cluster_kind="recoverable_function_pointer_target",
                            function=function_name,
                            block_id=str(callsite.get("block_id") or ""),
                            repair_class="function_pointer_target",
                            next_action="recover the function-pointer target set or add a checked indirect-call/jump-table target contract",
                            evidence={"callsite": callsite, "function_pointer_target": target},
                        )
                    )
        for candidate in function.get("register_out_param_candidates", []) if isinstance(function.get("register_out_param_candidates"), list) else []:
            if not isinstance(candidate, dict):
                continue
            instruction = _nested_dict(candidate, "write", "instruction")
            rva = instruction.get("rva") if isinstance(instruction, dict) else "unknown"
            register = str(candidate.get("register") or "unknown")
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"register-out-param:{function_name}:{register}:{rva}",
                    cluster_kind="abi_register_carried_out_param",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="hidden_sret_or_out_param",
                    next_action="preserve writes through entry register pointers as explicit out parameters or hidden result storage in generated C",
                    evidence={"register_out_param_candidate": candidate},
                )
            )
        for switch in function.get("switch_contracts", []) if isinstance(function.get("switch_contracts"), list) else []:
            if not isinstance(switch, dict):
                continue
            instruction = switch.get("instruction") if isinstance(switch.get("instruction"), dict) else {}
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"switch:{function_name}:{instruction.get('rva', 'unknown')}",
                    cluster_kind="abi_switch_or_jump_table_candidate",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="switch_or_jump_table_dispatch",
                    next_action="recover switch table bounds, default edge, and case target mapping in generated control flow",
                    evidence={"switch_contract": switch},
                )
            )
        for dispatch in function.get("decision_tree_contracts", []) if isinstance(function.get("decision_tree_contracts"), list) else []:
            if not isinstance(dispatch, dict):
                continue
            first_case = dispatch.get("case_targets", [{}])[0] if isinstance(dispatch.get("case_targets"), list) and dispatch.get("case_targets") else {}
            instruction = first_case.get("compare_instruction") if isinstance(first_case, dict) and isinstance(first_case.get("compare_instruction"), dict) else {}
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"decision-tree:{function_name}:{instruction.get('rva', 'unknown')}",
                    cluster_kind="abi_direct_compare_dispatch_candidate",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="switch_or_jump_table_dispatch",
                    next_action="prove the direct compare/branch decision tree covers the reference switch or jump-table target set",
                    evidence={"decision_tree_contract": dispatch},
                )
            )
        for loop in function.get("loop_hints", []) if isinstance(function.get("loop_hints"), list) else []:
            if not isinstance(loop, dict):
                continue
            instruction = loop.get("instruction") if isinstance(loop.get("instruction"), dict) else {}
            clusters.append(
                _cluster_contract(
                    contract_ref=contract_ref,
                    cluster_id=f"loop:{function_name}:{instruction.get('rva', 'unknown')}",
                    cluster_kind="abi_loop_backedge_candidate",
                    function=function_name,
                    block_id=_block_id_for_instruction(function, instruction),
                    repair_class="loop_or_state_machine",
                    next_action="preserve the loop backedge, loop-carried state, and exit predicate in generated control flow",
                    evidence={"loop_hint": loop},
                )
            )
    return clusters

def _nested_dict(value: dict[str, Any], *path: str) -> dict[str, Any]:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}

def _block_id_for_instruction(function: dict[str, Any], instruction: dict[str, Any]) -> str | None:
    rva = _safe_int(instruction.get("rva")) if isinstance(instruction, dict) else None
    if rva is None:
        return None
    for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
        if not isinstance(block, dict):
            continue
        start = _safe_int(block.get("rva_start"))
        end = _safe_int(block.get("rva_end"))
        if start is not None and end is not None and start <= rva < end:
            block_id = block.get("block_id")
            return str(block_id) if block_id not in {None, ""} else None
    return None

def _cluster_contract(
    *,
    contract_ref: dict[str, Any],
    cluster_id: str,
    cluster_kind: str,
    function: str,
    block_id: str | None,
    repair_class: str,
    next_action: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "format": "stage-a-cluster-contract-v1",
        "id": f"cluster:{_safe_gap_part(cluster_id)}",
        "unit_kind": "cluster",
        "cluster_kind": cluster_kind,
        "status": "specified",
        "reference_contract": contract_ref,
        "function": function or None,
        "block_id": block_id or None,
        "repair_class": repair_class,
        "next_action": next_action,
        "evidence": evidence,
        "acceptance": "informational unit contract only; candidate validation remains required",
    }

def _abi_functions(contract: dict[str, Any]) -> list[dict[str, Any]]:
    abi = _contract_constraint(contract, "abi_callsites")
    original = abi.get("original") if isinstance(abi.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    return [item for item in functions if isinstance(item, dict)]

def _abi_evidence_by_function(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("name") or ""): item
        for item in _abi_functions(contract)
        if item.get("name")
    }

def _abi_evidence_by_block(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for function in _abi_functions(contract):
        calls_by_block: dict[str, list[dict[str, Any]]] = {}
        for callsite in function.get("callsites", []) if isinstance(function.get("callsites"), list) else []:
            if isinstance(callsite, dict):
                calls_by_block.setdefault(str(callsite.get("block_id") or ""), []).append(callsite)
        registers = function.get("registers") if isinstance(function.get("registers"), dict) else {}
        for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
            if not isinstance(block, dict):
                continue
            block_id = str(block.get("block_id") or "")
            if not block_id:
                continue
            block_abi = block.get("abi") if isinstance(block.get("abi"), dict) else {}
            memory_reads = block_abi.get("memory_reads") if isinstance(block_abi.get("memory_reads"), list) else []
            memory_writes = block_abi.get("memory_writes") if isinstance(block_abi.get("memory_writes"), list) else []
            result[block_id] = {
                "callsites": block_abi.get("callsites") if isinstance(block_abi.get("callsites"), list) else calls_by_block.get(block_id, []),
                "register_reads": block_abi.get("register_reads")
                if isinstance(block_abi.get("register_reads"), list)
                else registers.get("reads", [])
                if isinstance(registers.get("reads"), list)
                else [],
                "register_writes": block_abi.get("register_writes")
                if isinstance(block_abi.get("register_writes"), list)
                else registers.get("writes", [])
                if isinstance(registers.get("writes"), list)
                else [],
                "preserved_candidates": block_abi.get("preserved_candidates")
                if isinstance(block_abi.get("preserved_candidates"), list)
                else registers.get("preserved_candidates", [])
                if isinstance(registers.get("preserved_candidates"), list)
                else [],
                "clobbered_candidates": block_abi.get("clobbered_candidates")
                if isinstance(block_abi.get("clobbered_candidates"), list)
                else registers.get("clobbered_candidates", [])
                if isinstance(registers.get("clobbered_candidates"), list)
                else [],
                "stack_delta": block_abi.get("stack_delta")
                if isinstance(block_abi.get("stack_delta"), dict)
                else function.get("stack_delta")
                if isinstance(function.get("stack_delta"), dict)
                else {"status": "unknown"},
                "register_value_provenance": block_abi.get("register_value_provenance")
                if isinstance(block_abi.get("register_value_provenance"), list)
                else [],
                "register_out_param_candidates": block_abi.get("register_out_param_candidates")
                if isinstance(block_abi.get("register_out_param_candidates"), list)
                else [],
                "memory_reads": memory_reads,
                "memory_writes": memory_writes,
                "field_accesses": block_abi.get("field_accesses") if isinstance(block_abi.get("field_accesses"), list) else [],
                "memory_effect_summary": block_abi.get("memory_effect_summary")
                if isinstance(block_abi.get("memory_effect_summary"), dict)
                else _abi_memory_effect_summary(memory_reads, memory_writes),
                "switch_contracts": block_abi.get("switch_contracts") if isinstance(block_abi.get("switch_contracts"), list) else [],
                "loop_hints": block_abi.get("loop_hints") if isinstance(block_abi.get("loop_hints"), list) else [],
            }
    return result

def _contract_constraint(contract: dict[str, Any], key: str) -> dict[str, Any]:
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    value = constraints.get(key)
    return value if isinstance(value, dict) else {}

def _safe_gap_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:@+-]+", "-", value.strip())
    return text.strip("-") or "unknown"

def _safe_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None

def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))

def _empty_contract_candidate_alias_evidence(*, status: str = "not_applicable") -> dict[str, Any]:
    return {
        "format": "stage-a-contract-candidate-alias-evidence-v1",
        "status": status,
        "matches_by_reference": {},
        "ambiguities_by_reference": {},
        "unmatched_by_reference": {},
        "alias_matches": [],
        "ambiguities": [],
        "unmatched_aliases": [],
        "counts": {"alias_matches": 0, "ambiguities": 0, "unmatched_aliases": 0},
    }

def _contract_candidate_function_symbol_names(function: dict[str, Any]) -> list[str]:
    names: list[str] = []
    name = function.get("name")
    if isinstance(name, str) and name:
        names.append(name)
    aliases = function.get("aliases") if isinstance(function.get("aliases"), list) else []
    names.extend(alias for alias in aliases if isinstance(alias, str) and alias)
    return _dedupe_strings(names)

def _contract_candidate_symbol_keys(name: str) -> set[str]:
    variants = {name}
    if name.startswith("@"):
        stripped = name[1:]
        variants.add(stripped)
        if "@" in stripped:
            left, right = stripped.rsplit("@", 1)
            if right.isdigit():
                variants.add(left)
    if "@" in name:
        left, right = name.rsplit("@", 1)
        if right.isdigit():
            variants.add(left)
    keys = set()
    for variant in variants:
        keys.add(variant)
        keys.add(_linker_function_match_key(variant))
    return {key for key in keys if key}

def _dedupe_strings(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result

def _candidate_abi_constraint_from_functions(
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
    *,
    reference_abi: dict[str, Any] | None = None,
    alias_evidence: dict[str, Any] | None = None,
    candidate_rva_anchors: dict[int, int] | None = None,
) -> dict[str, Any]:
    mappings = _candidate_abi_block_mappings_from_functions(candidate, candidate_functions)
    reference_section_gap_mappings = _candidate_reference_section_gap_abi_mappings(
        candidate,
        reference_abi,
        alias_evidence=alias_evidence,
        candidate_rva_anchors=candidate_rva_anchors,
    )
    mappings.extend(reference_section_gap_mappings)
    functions = _abi_function_evidence(candidate, mappings, side="candidate", compose_direct_callee_import_memory=True)
    return {
        "status": "satisfied" if functions else "incomplete",
        "evidence_kind": "capstone-static-abi-callsites",
        "candidate": {
            "functions": functions,
            "import_prototypes": _abi_import_prototypes(candidate),
            "reference_section_gap_probes": {
                "kind": "candidate_section_gap_probe",
                "count": len(reference_section_gap_mappings),
                "contract_rva_anchors": len(candidate_rva_anchors or {}),
            },
        },
        "counts": {
            "functions": len(functions),
            "callsites": sum(len(item.get("callsites", [])) for item in functions),
            "import_prototypes": len(candidate.imports),
            "reference_section_gap_probes": len(reference_section_gap_mappings),
        },
    }

def _candidate_abi_block_mappings_from_functions(
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
) -> list[BlockMapping]:
    mappings: list[BlockMapping] = []
    for function_index, function in enumerate(candidate_functions):
        rva_start = _optional_contract_int(function.get("rva_start"))
        rva_end = _optional_contract_int(function.get("rva_end"))
        if rva_start is None or rva_end is None or rva_end <= rva_start:
            continue
        name = str(function.get("name") or f"function_{function_index:04d}")
        blocks = _recover_basic_blocks(candidate, rva_start, rva_end)
        for block_index, block in enumerate(blocks):
            block_start = _optional_contract_int(block.get("rva_start"))
            block_end = _optional_contract_int(block.get("rva_end"))
            if block_start is None or block_end is None or block_end <= block_start:
                continue
            mappings.append(
                BlockMapping(
                    id=_artifact_name(f"{name}-{block_index:04d}"),
                    kind="code",
                    original=BlockSide(block_start, block_end),
                    candidate=BlockSide(block_start, block_end),
                    reachable=True,
                    invariant_checked=True,
                    source={"source": {"function": name, "kind": "candidate_capstone_basic_block"}},
                )
            )
    return mappings

def _candidate_reference_section_gap_abi_mappings(
    candidate: StageABinary,
    reference_abi: dict[str, Any] | None,
    *,
    alias_evidence: dict[str, Any] | None = None,
    candidate_rva_anchors: dict[int, int] | None = None,
) -> list[BlockMapping]:
    if not isinstance(reference_abi, dict):
        return []
    reference = reference_abi.get("original") if isinstance(reference_abi.get("original"), dict) else {}
    functions = reference.get("functions") if isinstance(reference.get("functions"), list) else []
    owner_ranges = _candidate_reference_section_gap_owner_ranges(functions)
    alias_matches = (
        alias_evidence.get("matches_by_reference")
        if isinstance(alias_evidence, dict) and isinstance(alias_evidence.get("matches_by_reference"), dict)
        else {}
    )
    mappings: list[BlockMapping] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        for index, block in enumerate(blocks):
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            block_id = block.get("block_id") if isinstance(block.get("block_id"), str) and block.get("block_id") else f"{name}-{index:04d}"
            anchor_mapping = _candidate_reference_section_gap_anchor_mapping(
                candidate,
                name=name,
                block_id=block_id,
                reference_start=start,
                reference_end=end,
                owner_ranges=owner_ranges,
                alias_matches=alias_matches,
                candidate_rva_anchors=candidate_rva_anchors or {},
            )
            if anchor_mapping is not None:
                mappings.append(anchor_mapping)
                continue
            owner_mapping = _candidate_reference_section_gap_owner_offset_mapping(
                candidate,
                name=name,
                block_id=block_id,
                reference_start=start,
                reference_end=end,
                owner_ranges=owner_ranges,
                alias_matches=alias_matches,
            )
            if owner_mapping is not None:
                mappings.append(owner_mapping)
                continue
            section = _section_for_rva(candidate, start)
            if section is None or not section.executable or end > section.rva_end:
                continue
            mappings.append(
                BlockMapping(
                    id=_artifact_name(block_id),
                    kind="code",
                    original=BlockSide(start, end),
                    candidate=BlockSide(start, end),
                    reachable=True,
                    invariant_checked=False,
                    source={
                        "source": {
                            "function": name,
                            "kind": "candidate_same_rva_section_gap_probe",
                            "reference_block_id": block_id,
                        }
                    },
                )
            )
    return mappings

def _candidate_reference_section_gap_owner_ranges(functions: list[Any]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = function.get("name")
        if not isinstance(name, str) or not name or name.startswith("section-gap-"):
            continue
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        starts: list[int] = []
        ends: list[int] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            starts.append(start)
            ends.append(end)
        if not starts:
            continue
        ranges.append({"name": name, "rva_start": min(starts), "rva_end": max(ends)})
    ranges.sort(key=lambda item: (int(item["rva_end"]) - int(item["rva_start"]), str(item["name"])))
    return ranges

def _candidate_reference_section_gap_anchor_mapping(
    candidate: StageABinary,
    *,
    name: str,
    block_id: str,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
    candidate_rva_anchors: dict[int, int],
) -> BlockMapping | None:
    if not candidate_rva_anchors:
        return None
    owner_context = _candidate_reference_section_gap_owner_context(
        reference_start=reference_start,
        reference_end=reference_end,
        owner_ranges=owner_ranges,
        alias_matches=alias_matches,
    )
    if owner_context is None:
        return None
    previous_reference = max((rva for rva in candidate_rva_anchors if rva <= reference_start), default=None)
    if previous_reference is None:
        return None
    next_reference = min((rva for rva in candidate_rva_anchors if rva > previous_reference), default=None)
    if next_reference is not None and reference_end > next_reference:
        return None
    candidate_anchor = candidate_rva_anchors[previous_reference]
    candidate_start = candidate_anchor + (reference_start - previous_reference)
    candidate_end = candidate_start + (reference_end - reference_start)
    candidate_owner_start = int(owner_context["candidate_start"])
    candidate_owner_end = int(owner_context["candidate_end"])
    if candidate_start < candidate_owner_start or candidate_end > candidate_owner_end:
        return None
    if next_reference is not None:
        next_candidate = candidate_rva_anchors[next_reference]
        if candidate_end > next_candidate:
            return None
    section = _section_for_rva(candidate, candidate_start)
    if section is None or not section.executable or candidate_end > section.rva_end:
        return None
    return BlockMapping(
        id=_artifact_name(block_id),
        kind="code",
        original=BlockSide(reference_start, reference_end),
        candidate=BlockSide(candidate_start, candidate_end),
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "function": name,
                "kind": "candidate_contract_rva_anchor_section_gap_probe",
                "reference_block_id": block_id,
                "owner_function": owner_context["owner_name"],
                "anchor_reference_rva": previous_reference,
                "anchor_candidate_rva": candidate_anchor,
                "anchor_delta": reference_start - previous_reference,
            }
        },
    )

def _candidate_reference_section_gap_owner_offset_mapping(
    candidate: StageABinary,
    *,
    name: str,
    block_id: str,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> BlockMapping | None:
    owner_context = _candidate_reference_section_gap_owner_context(
        reference_start=reference_start,
        reference_end=reference_end,
        owner_ranges=owner_ranges,
        alias_matches=alias_matches,
    )
    if owner_context is None:
        return None
    owner_name = str(owner_context["owner_name"])
    owner_start = int(owner_context["reference_start"])
    candidate_owner_start = int(owner_context["candidate_start"])
    candidate_owner_end = int(owner_context["candidate_end"])
    candidate_start = candidate_owner_start + (reference_start - owner_start)
    candidate_end = candidate_start + (reference_end - reference_start)
    if candidate_start < candidate_owner_start or candidate_end > candidate_owner_end:
        return None
    section = _section_for_rva(candidate, candidate_start)
    if section is None or not section.executable or candidate_end > section.rva_end:
        return None
    return BlockMapping(
        id=_artifact_name(block_id),
        kind="code",
        original=BlockSide(reference_start, reference_end),
        candidate=BlockSide(candidate_start, candidate_end),
        reachable=True,
        invariant_checked=False,
        source={
            "source": {
                "function": name,
                "kind": "candidate_owner_offset_section_gap_probe",
                "reference_block_id": block_id,
                "owner_function": owner_name,
                "owner_reference_rva_start": owner_start,
                "owner_candidate_rva_start": candidate_owner_start,
                "owner_offset": reference_start - owner_start,
            }
        },
    )

def _candidate_reference_section_gap_owner_context(
    *,
    reference_start: int,
    reference_end: int,
    owner_ranges: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> dict[str, Any] | None:
    owner = next(
        (
            item
            for item in owner_ranges
            if int(item.get("rva_start") or 0) <= reference_start and reference_end <= int(item.get("rva_end") or 0)
        ),
        None,
    )
    if owner is None:
        return None
    owner_name = str(owner.get("name") or "")
    alias_match = alias_matches.get(owner_name) if isinstance(alias_matches.get(owner_name), dict) else {}
    if str(alias_match.get("source_kind") or "") not in {
        "generated_contract_guided_flow",
        "generated_checked_semantic_region",
    }:
        return None
    candidate_owner = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
    candidate_owner_start = _optional_contract_int(candidate_owner.get("rva_start"))
    candidate_owner_end = _optional_contract_int(candidate_owner.get("rva_end"))
    owner_start = _optional_contract_int(owner.get("rva_start"))
    owner_end = _optional_contract_int(owner.get("rva_end"))
    if candidate_owner_start is None or candidate_owner_end is None or owner_start is None or owner_end is None:
        return None
    return {
        "owner_name": owner_name,
        "reference_start": owner_start,
        "reference_end": owner_end,
        "candidate_start": candidate_owner_start,
        "candidate_end": candidate_owner_end,
    }

def _optional_contract_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None

def _contract_candidate_abi_status(reference_abi: dict[str, Any], candidate_abi: dict[str, Any]) -> str:
    reference_counts = reference_abi.get("counts") if isinstance(reference_abi.get("counts"), dict) else {}
    candidate_counts = candidate_abi.get("counts") if isinstance(candidate_abi.get("counts"), dict) else {}
    if int(candidate_counts.get("functions") or 0) < int(reference_counts.get("functions") or 0):
        return "incomplete"
    if int(candidate_counts.get("callsites") or 0) < int(reference_counts.get("callsites") or 0):
        return "incomplete"
    return "satisfied"

def _contract_candidate_abi_coverage_gaps(
    reference_abi: dict[str, Any],
    candidate_abi: dict[str, Any],
    *,
    alias_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    alias_evidence = alias_evidence or _empty_contract_candidate_alias_evidence()
    alias_matches = alias_evidence.get("matches_by_reference") if isinstance(alias_evidence.get("matches_by_reference"), dict) else {}
    alias_ambiguities = alias_evidence.get("ambiguities_by_reference") if isinstance(alias_evidence.get("ambiguities_by_reference"), dict) else {}
    reference = reference_abi.get("original") if isinstance(reference_abi.get("original"), dict) else {}
    candidate = candidate_abi.get("candidate") if isinstance(candidate_abi.get("candidate"), dict) else {}
    reference_functions = [item for item in reference.get("functions", []) if isinstance(item, dict)]
    candidate_functions = [item for item in candidate.get("functions", []) if isinstance(item, dict)]
    candidate_by_key: dict[str, list[dict[str, Any]]] = {}
    for function in candidate_functions:
        name = function.get("name")
        if isinstance(name, str):
            for key in _contract_candidate_symbol_keys(name):
                candidate_by_key.setdefault(key, []).append(function)
    reference_import_prototypes = reference.get("import_prototypes") if isinstance(reference.get("import_prototypes"), list) else []
    candidate_import_prototypes = candidate.get("import_prototypes") if isinstance(candidate.get("import_prototypes"), list) else []
    reference_function_index = _abi_function_range_index(reference_functions, import_prototypes=reference_import_prototypes)
    candidate_function_index = _abi_function_range_index(candidate_functions, import_prototypes=candidate_import_prototypes)

    missing_functions: list[dict[str, Any]] = []
    ambiguous_functions: list[dict[str, Any]] = []
    incomplete_callsites: list[dict[str, Any]] = []
    function_mismatches: list[dict[str, Any]] = []
    callsite_mismatches: list[dict[str, Any]] = []
    for function in reference_functions:
        name = function.get("name")
        if not isinstance(name, str):
            continue
        key = _linker_function_match_key(name)
        if name in alias_ambiguities:
            ambiguous_functions.append({"name": name, "match_key": key, "ambiguities": alias_ambiguities[name][:5]})
            continue
        candidates = _contract_candidate_abi_candidates(candidate_by_key, name, alias_matches.get(name))
        reference_callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
        if not candidates:
            missing_functions.append(_abi_function_gap_sample(function, key))
            continue
        best_candidate = _contract_candidate_abi_best_candidate(candidates, alias_matches.get(name))
        function_mismatch = _contract_candidate_abi_function_mismatch(
            name,
            key,
            function,
            best_candidate,
            _contract_candidate_abi_alias_sample(alias_matches.get(name)),
        )
        if function_mismatch is not None:
            function_mismatches.append(function_mismatch)
        candidate_callsites = best_candidate.get("callsites") if isinstance(best_candidate.get("callsites"), list) else []
        candidate_callsite_count = len(candidate_callsites)
        callsite_pairs = _contract_candidate_abi_callsite_pairs(
            reference_callsites,
            candidate_callsites,
            reference_function_index=reference_function_index,
            candidate_function_index=candidate_function_index,
            alias_matches=alias_matches,
        )
        if candidate_callsite_count < len(reference_callsites):
            signature_delta = _contract_candidate_abi_callsite_signature_delta(
                reference_callsites,
                candidate_callsites,
                callsite_pairs,
                reference_function_index=reference_function_index,
                candidate_function_index=candidate_function_index,
            )
            incomplete_callsites.append(
                {
                    "name": name,
                    "match_key": key,
                    "reference_callsites": len(reference_callsites),
                    "candidate_callsites": candidate_callsite_count,
                    "missing_callsites": len(reference_callsites) - candidate_callsite_count,
                    "unmatched_reference_callsites": signature_delta["counts"]["unmatched_reference_callsites"],
                    "unmatched_candidate_callsites": signature_delta["counts"]["unmatched_candidate_callsites"],
                    "matched_callsite_pairs": signature_delta["counts"]["matched_callsite_pairs"],
                    "alias_match": _contract_candidate_abi_alias_sample(alias_matches.get(name)),
                    "reference_callsite_samples": [_abi_callsite_gap_sample(item) for item in reference_callsites[:5]],
                    "missing_callsite_signatures": signature_delta["reference_only"][:8],
                    "extra_candidate_callsite_signatures": signature_delta["candidate_only"][:8],
                    "unmatched_reference_callsite_signatures": signature_delta["unmatched_reference_signatures"][:8],
                    "unmatched_candidate_callsite_signatures": signature_delta["unmatched_candidate_signatures"][:8],
                    "callsite_signature_delta": signature_delta,
                }
            )
        for index, candidate_index, reference_callsite, candidate_callsite in callsite_pairs:
            callsite_mismatch = _contract_candidate_abi_callsite_mismatch(
                name,
                key,
                index,
                reference_callsite,
                candidate_callsite,
                _contract_candidate_abi_alias_sample(alias_matches.get(name)),
                candidate_callsite_index=candidate_index,
                reference_function_index=reference_function_index,
                candidate_function_index=candidate_function_index,
                alias_matches=alias_matches,
            )
            if callsite_mismatch is not None:
                callsite_mismatches.append(callsite_mismatch)

    return {
        "missing_functions": missing_functions[:100],
        "ambiguous_functions": ambiguous_functions[:100],
        "incomplete_callsites": incomplete_callsites[:100],
        "function_mismatches": function_mismatches[:100],
        "callsite_mismatches": callsite_mismatches[:100],
        "counts": {
            "missing_functions": len(missing_functions),
            "ambiguous_functions": len(ambiguous_functions),
            "incomplete_callsite_functions": len(incomplete_callsites),
            "missing_callsites": sum(int(item.get("missing_callsites") or 0) for item in incomplete_callsites),
            "function_mismatches": len(function_mismatches),
            "callsite_mismatches": len(callsite_mismatches),
        },
    }

def _abi_function_range_index(functions: list[dict[str, Any]], *, import_prototypes: list[Any] | None = None) -> list[dict[str, Any]]:
    imports_by_key = _abi_import_prototypes_by_match_key(import_prototypes or [])
    ranges: list[dict[str, Any]] = []
    for function in functions:
        name = function.get("name")
        if not isinstance(name, str) or not name:
            continue
        match_key = _linker_function_match_key(name)
        import_signature = imports_by_key.get(match_key)
        blocks = function.get("blocks") if isinstance(function.get("blocks"), list) else []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            start = _optional_contract_int(block.get("rva_start"))
            end = _optional_contract_int(block.get("rva_end"))
            if start is None or end is None or end <= start:
                continue
            item = {
                "name": name,
                "match_key": match_key,
                "rva_start": start,
                "rva_end": end,
                "block_id": block.get("block_id"),
            }
            if import_signature is not None and _abi_block_is_import_thunk(block):
                item["import_signature"] = import_signature
                item["resolution_kind"] = "import_thunk"
            ranges.append(item)
    return ranges

def _abi_import_prototypes_by_match_key(import_prototypes: list[Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for imported in import_prototypes:
        if not isinstance(imported, dict):
            continue
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        if isinstance(symbol, str) and symbol:
            signature = {"dll": imported.get("dll"), "symbol": symbol, "ordinal": ordinal}
            result.setdefault(_linker_function_match_key(symbol), signature)
            if "@" in symbol:
                result.setdefault(_linker_function_match_key(symbol.split("@", 1)[0]), signature)
        elif ordinal not in {None, ""}:
            result.setdefault(str(ordinal), {"dll": imported.get("dll"), "symbol": None, "ordinal": ordinal})
    return result

def _abi_block_is_import_thunk(block: dict[str, Any]) -> bool:
    abi = block.get("abi") if isinstance(block.get("abi"), dict) else {}
    if abi.get("callsites"):
        return False
    reads = abi.get("memory_reads") if isinstance(abi.get("memory_reads"), list) else []
    if len([item for item in reads if isinstance(item, dict)]) != 1:
        return False
    read = next(item for item in reads if isinstance(item, dict))
    section = read.get("memory_section") if isinstance(read.get("memory_section"), dict) else {}
    if read.get("memory_role") != "import_address_table":
        return False
    instruction = read.get("instruction") if isinstance(read.get("instruction"), dict) else {}
    return instruction.get("mnemonic") == "jmp"

def _contract_candidate_abi_callsite_pairs(
    reference_callsites: list[Any],
    candidate_callsites: list[Any],
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> list[tuple[int, int, dict[str, Any], dict[str, Any]]]:
    valid_candidates = [
        (index, callsite)
        for index, callsite in enumerate(candidate_callsites)
        if isinstance(callsite, dict)
    ]
    unused_candidate_indexes = {index for index, _ in valid_candidates}
    unused_reference_indexes = {
        index
        for index, callsite in enumerate(reference_callsites)
        if isinstance(callsite, dict)
    }
    pairs: list[tuple[int, int, dict[str, Any], dict[str, Any]]] = []
    scored_pairs: list[tuple[int, int, int, dict[str, Any], dict[str, Any]]] = []
    for reference_index, reference_callsite in enumerate(reference_callsites):
        if not isinstance(reference_callsite, dict):
            continue
        for candidate_index, candidate_callsite in valid_candidates:
            score = _contract_candidate_abi_callsite_pair_score(
                reference_callsite,
                candidate_callsite,
                reference_function_index=reference_function_index,
                candidate_function_index=candidate_function_index,
                alias_matches=alias_matches,
            )
            if score > 0:
                scored_pairs.append((score, reference_index, candidate_index, reference_callsite, candidate_callsite))
    for _score, reference_index, candidate_index, reference_callsite, candidate_callsite in sorted(
        scored_pairs,
        key=lambda item: (-item[0], item[1], item[2]),
    ):
        if reference_index not in unused_reference_indexes or candidate_index not in unused_candidate_indexes:
            continue
        unused_reference_indexes.remove(reference_index)
        unused_candidate_indexes.remove(candidate_index)
        pairs.append((reference_index, candidate_index, reference_callsite, candidate_callsite))

    for reference_index, reference_callsite in enumerate(reference_callsites):
        if reference_index not in unused_reference_indexes or not isinstance(reference_callsite, dict):
            continue
        if reference_index in unused_candidate_indexes and isinstance(candidate_callsites[reference_index], dict):
            unused_candidate_indexes.remove(reference_index)
            unused_reference_indexes.remove(reference_index)
            pairs.append((reference_index, reference_index, reference_callsite, candidate_callsites[reference_index]))
    return sorted(pairs, key=lambda item: item[0])

def _contract_candidate_abi_callsite_signature_delta(
    reference_callsites: list[Any],
    candidate_callsites: list[Any],
    callsite_pairs: list[tuple[int, int, dict[str, Any], dict[str, Any]]],
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
) -> dict[str, Any]:
    paired_reference_indexes = {reference_index for reference_index, _, _, _ in callsite_pairs}
    paired_candidate_indexes = {candidate_index for _, candidate_index, _, _ in callsite_pairs}
    reference_records = [
        _abi_callsite_signature_record(index, callsite, reference_function_index)
        for index, callsite in enumerate(reference_callsites)
        if isinstance(callsite, dict)
    ]
    candidate_records = [
        _abi_callsite_signature_record(index, callsite, candidate_function_index)
        for index, callsite in enumerate(candidate_callsites)
        if isinstance(callsite, dict)
    ]
    reference_groups = _abi_callsite_signature_groups(reference_records)
    candidate_groups = _abi_callsite_signature_groups(candidate_records)

    reference_only: list[dict[str, Any]] = []
    candidate_only: list[dict[str, Any]] = []
    for key in sorted(reference_groups):
        reference_group = reference_groups[key]
        candidate_group = candidate_groups.get(key)
        candidate_count = int(candidate_group.get("count") or 0) if isinstance(candidate_group, dict) else 0
        missing = int(reference_group.get("count") or 0) - candidate_count
        if missing <= 0:
            continue
        reference_only.append(
            {
                "signature_id": reference_group["signature_id"],
                "missing": missing,
                "reference_count": reference_group["count"],
                "candidate_count": candidate_count,
                "signature": reference_group["signature"],
                "reference_examples": reference_group["examples"],
                "candidate_examples": candidate_group.get("examples", []) if isinstance(candidate_group, dict) else [],
            }
        )
    for key in sorted(candidate_groups):
        candidate_group = candidate_groups[key]
        reference_group = reference_groups.get(key)
        reference_count = int(reference_group.get("count") or 0) if isinstance(reference_group, dict) else 0
        extra = int(candidate_group.get("count") or 0) - reference_count
        if extra <= 0:
            continue
        candidate_only.append(
            {
                "signature_id": candidate_group["signature_id"],
                "extra": extra,
                "reference_count": reference_count,
                "candidate_count": candidate_group["count"],
                "signature": candidate_group["signature"],
                "candidate_examples": candidate_group["examples"],
                "reference_examples": reference_group.get("examples", []) if isinstance(reference_group, dict) else [],
            }
        )

    unmatched_reference_records = [
        record for record in reference_records if _abi_callsite_record_index(record) not in paired_reference_indexes
    ]
    unmatched_candidate_records = [
        record for record in candidate_records if _abi_callsite_record_index(record) not in paired_candidate_indexes
    ]
    unmatched_reference_signatures = _abi_unmatched_callsite_signature_items(
        unmatched_reference_records,
        count_key="missing",
        examples_key="reference_examples",
    )
    unmatched_candidate_signatures = _abi_unmatched_callsite_signature_items(
        unmatched_candidate_records,
        count_key="extra",
        examples_key="candidate_examples",
    )
    return {
        "counts": {
            "reference_signatures": len(reference_groups),
            "candidate_signatures": len(candidate_groups),
            "reference_only_signatures": len(reference_only),
            "candidate_only_signatures": len(candidate_only),
            "unmatched_reference_signatures": len(unmatched_reference_signatures),
            "unmatched_candidate_signatures": len(unmatched_candidate_signatures),
            "matched_callsite_pairs": len(callsite_pairs),
            "unmatched_reference_callsites": len(unmatched_reference_records),
            "unmatched_candidate_callsites": len(unmatched_candidate_records),
        },
        "unmatched_reference_signatures": unmatched_reference_signatures[:24],
        "unmatched_candidate_signatures": unmatched_candidate_signatures[:24],
        "reference_only": reference_only[:24],
        "candidate_only": candidate_only[:24],
        "unmatched_reference_examples": unmatched_reference_records[:12],
        "unmatched_candidate_examples": unmatched_candidate_records[:12],
    }

def _abi_unmatched_callsite_signature_items(
    records: list[dict[str, Any]],
    *,
    count_key: str,
    examples_key: str,
) -> list[dict[str, Any]]:
    groups = _abi_callsite_signature_groups(records)
    items: list[dict[str, Any]] = []
    for key in sorted(groups):
        group = groups[key]
        item = {
            "signature_id": group["signature_id"],
            count_key: group["count"],
            "signature": group["signature"],
            examples_key: group["examples"],
        }
        if count_key == "missing":
            item["reference_count"] = group["count"]
            item["candidate_count"] = 0
        elif count_key == "extra":
            item["reference_count"] = 0
            item["candidate_count"] = group["count"]
        items.append(item)
    return items

def _abi_callsite_signature_record(
    index: int,
    callsite: dict[str, Any],
    function_index: list[dict[str, Any]],
) -> dict[str, Any]:
    signature = _abi_callsite_contract_signature(callsite, function_index)
    signature_json = json.dumps(signature, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "index": index,
        "signature_id": f"callsite-signature:{sha256_bytes(signature_json.encode('utf-8'))[:16]}",
        "signature": signature,
        "callsite": _abi_callsite_gap_sample(callsite),
    }

def _abi_callsite_signature_groups(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for record in records:
        signature = record.get("signature") if isinstance(record.get("signature"), dict) else {}
        key = json.dumps(signature, sort_keys=True, separators=(",", ":"), default=str)
        group = groups.setdefault(
            key,
            {
                "signature_id": record.get("signature_id"),
                "signature": signature,
                "count": 0,
                "examples": [],
            },
        )
        group["count"] = int(group.get("count") or 0) + 1
        examples = group.get("examples") if isinstance(group.get("examples"), list) else []
        if len(examples) < 5:
            examples.append({"index": record.get("index"), "callsite": record.get("callsite")})
        group["examples"] = examples
    return groups

def _abi_callsite_record_index(record: dict[str, Any]) -> int:
    index = record.get("index")
    return index if isinstance(index, int) else -1

def _abi_callsite_contract_signature(callsite: dict[str, Any], function_index: list[dict[str, Any]]) -> dict[str, Any]:
    signature: dict[str, Any] = {}
    target_signature = _abi_callsite_target_contract_signature(callsite.get("target"), function_index)
    if target_signature:
        signature["target"] = target_signature
    inventory = _abi_argument_inventory_signature(callsite.get("argument_inventory"))
    if inventory:
        signature["argument_inventory"] = inventory
    hidden = _abi_hidden_sret_contract_signature(callsite.get("hidden_sret_or_out_param_evidence"))
    if hidden:
        signature["hidden_sret_or_out_param"] = hidden
    varargs = _abi_varargs_contract_signature(callsite.get("varargs_evidence"))
    if varargs:
        signature["varargs"] = varargs
    function_pointer_targets = callsite.get("function_pointer_targets")
    if isinstance(function_pointer_targets, list) and function_pointer_targets:
        roles = []
        for target in function_pointer_targets:
            if not isinstance(target, dict):
                continue
            roles.append(
                {
                    key: target.get(key)
                    for key in ("kind", "memory_role", "register", "target_rva", "status")
                    if target.get(key) not in {None, ""}
                }
            )
        signature["function_pointer_targets"] = {
            "count": len(function_pointer_targets),
            "roles": roles[:8],
        }
    return signature

def _abi_callsite_target_contract_signature(target: Any, function_index: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(target, dict):
        return {}
    resolved_signature = _abi_target_signature_with_resolution(target, function_index)
    import_signature = _abi_target_import_signature(resolved_signature)
    if import_signature is not None:
        dll, symbol, ordinal = import_signature
        return {
            "kind": "import",
            "dll": dll,
            "symbol": symbol,
            "ordinal": ordinal,
        }
    kind = resolved_signature.get("kind")
    signature: dict[str, Any] = {"kind": kind} if kind not in {None, ""} else {}
    resolved_functions = resolved_signature.get("resolved_functions")
    if isinstance(resolved_functions, list) and resolved_functions:
        resolved_keys = sorted(
            {
                str(item.get("match_key") or "")
                for item in resolved_functions
                if isinstance(item, dict) and item.get("match_key")
            }
        )
        if resolved_keys:
            signature["resolved_match_keys"] = resolved_keys
    elif kind == "direct" and resolved_signature.get("target_rva") not in {None, ""}:
        signature["target_rva"] = resolved_signature.get("target_rva")
    if kind == "function_pointer":
        memory_role = str(target.get("memory_role") or "")
        for key in ("memory_role", "register", "status"):
            if target.get(key) not in {None, ""}:
                signature[key] = target.get(key)
        if memory_role != "stack_pointer_slot" and target.get("operand") not in {None, ""}:
            signature["operand"] = target.get("operand")
        if memory_role != "stack_pointer_slot" and target.get("memory_rva") not in {None, ""}:
            signature["memory_rva"] = target.get("memory_rva")
        source = target.get("source") if isinstance(target.get("source"), dict) else {}
        if source:
            source_signature = {
                key: source.get(key)
                for key in ("kind", "address_class", "memory_role", "register")
                if source.get(key) not in {None, ""}
            }
            if memory_role != "stack_pointer_slot":
                for key in ("stack_offset", "memory_rva"):
                    if source.get(key) not in {None, ""}:
                        source_signature[key] = source.get(key)
            if source_signature:
                signature["source"] = source_signature
    return signature

def _abi_hidden_sret_contract_signature(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict) or not evidence:
        return {}
    return {
        key: evidence.get(key)
        for key in ("status", "reason", "address_role")
        if evidence.get(key) not in {None, ""}
    }

def _abi_varargs_contract_signature(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict) or not evidence:
        return {}
    signature = {
        key: evidence.get(key)
        for key in ("status", "import_symbol")
        if evidence.get(key) not in {None, ""}
    }
    format_string = evidence.get("format_string") if isinstance(evidence.get("format_string"), dict) else {}
    if format_string:
        signature["format_string"] = {
            key: format_string.get(key)
            for key in ("status", "required_varargs", "observed_varargs", "missing_varargs")
            if format_string.get(key) not in {None, ""}
        }
    return signature

def _contract_candidate_abi_callsite_pair_score(
    reference_callsite: dict[str, Any],
    candidate_callsite: dict[str, Any],
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> int:
    score = 0
    target_match = _contract_candidate_abi_target_match(
        reference_callsite.get("target"),
        candidate_callsite.get("target"),
        reference_function_index=reference_function_index,
        candidate_function_index=candidate_function_index,
        alias_matches=alias_matches,
    )
    if target_match["reference"] and target_match["candidate"]:
        if target_match["matched"]:
            score += 100
        elif target_match["reference"].get("kind") == target_match["candidate"].get("kind"):
            score += 10
    reference_inventory = _abi_argument_inventory_signature(reference_callsite.get("argument_inventory"))
    candidate_inventory = _abi_argument_inventory_signature(candidate_callsite.get("argument_inventory"))
    if reference_inventory and candidate_inventory:
        if _contract_candidate_abi_argument_inventory_match(reference_inventory, candidate_inventory):
            score += 20
        elif reference_inventory.get("calling_convention") == candidate_inventory.get("calling_convention"):
            score += 2
    reference_varargs = reference_callsite.get("varargs_evidence") if isinstance(reference_callsite.get("varargs_evidence"), dict) else {}
    candidate_varargs = candidate_callsite.get("varargs_evidence") if isinstance(candidate_callsite.get("varargs_evidence"), dict) else {}
    if reference_varargs and candidate_varargs and _contract_candidate_abi_varargs_issue(reference_varargs, candidate_varargs) is None:
        score += 5
    return score

def _contract_candidate_abi_function_mismatch(
    name: str,
    match_key: str,
    reference_function: dict[str, Any],
    candidate_function: dict[str, Any],
    alias_match: dict[str, Any] | None,
) -> dict[str, Any] | None:
    issues: list[dict[str, Any]] = []
    reference_stack = reference_function.get("stack_delta") if isinstance(reference_function.get("stack_delta"), dict) else {}
    candidate_stack = candidate_function.get("stack_delta") if isinstance(candidate_function.get("stack_delta"), dict) else {}
    if reference_stack.get("status") == "derived" and candidate_stack.get("status") == "derived":
        if reference_stack.get("net_bytes") != candidate_stack.get("net_bytes"):
            issues.append(
                {
                    "category": "stack_delta_mismatch",
                    "expected": reference_stack,
                    "observed": candidate_stack,
                    "cause_hint": "candidate function stack cleanup differs from the reference contract",
                }
            )
    reference_registers = reference_function.get("registers") if isinstance(reference_function.get("registers"), dict) else {}
    candidate_registers = candidate_function.get("registers") if isinstance(candidate_function.get("registers"), dict) else {}
    for key, category in (
        ("preserved_candidates", "preserved_register_mismatch"),
        ("clobbered_candidates", "clobbered_register_mismatch"),
    ):
        if key == "preserved_candidates":
            expected = set(_abi_effective_preserved_registers(reference_function))
            observed = set(_abi_effective_preserved_registers(candidate_function))
        else:
            expected = {str(item) for item in reference_registers.get(key, []) if isinstance(item, str)}
            observed = {str(item) for item in candidate_registers.get(key, []) if isinstance(item, str)}
        missing = sorted(expected - observed)
        if missing:
            issues.append(
                {
                    "category": category,
                    "expected": sorted(expected),
                    "observed": sorted(observed),
                    "missing": missing,
                    "cause_hint": f"candidate is missing reference {key.replace('_', ' ')}",
                }
            )
    for key, category, hint in (
        (
            "register_out_param_candidates",
            "register_carried_out_param_missing",
            "candidate does not expose all writes through entry register pointers",
        ),
        (
            "switch_contracts",
            "switch_or_jump_table_contract_missing",
            "candidate does not expose all indirect switch/jump-table contracts",
        ),
        (
            "loop_hints",
            "loop_backedge_contract_missing",
            "candidate does not expose all loop backedge hints",
        ),
    ):
        if key == "loop_hints":
            expected_count = _abi_function_local_loop_hint_count(reference_function)
            observed_count = _abi_function_local_loop_hint_count(candidate_function)
        else:
            expected_count = _abi_list_count(reference_function.get(key))
            observed_count = _abi_list_count(candidate_function.get(key))
        if key == "register_out_param_candidates":
            observed_count += _contract_candidate_argument_pointer_out_param_coverage_count(
                reference_function,
                candidate_function,
                expected_count=expected_count,
                observed_count=observed_count,
            )
        if key == "switch_contracts":
            covered = _contract_candidate_refptr_direct_transfer_coverage_count(reference_function, candidate_function)
            observed_count += covered
            observed_count += _contract_candidate_decision_tree_switch_coverage_count(
                reference_function,
                candidate_function,
                expected_count=expected_count,
                observed_count=observed_count,
            )
        if expected_count > observed_count:
            issues.append(
                {
                    "category": category,
                    "expected": expected_count,
                    "observed": observed_count,
                    "missing": expected_count - observed_count,
                    "cause_hint": hint,
                }
            )
    memory_issue = _contract_candidate_abi_memory_summary_issue(reference_function, candidate_function)
    if memory_issue is not None:
        issues.append(memory_issue)
    if not issues:
        return None
    return {
        "name": name,
        "match_key": match_key,
        "alias_match": alias_match,
        "candidate_name": candidate_function.get("name"),
        "issues": issues[:12],
        "repair_class": _contract_candidate_abi_mismatch_repair_class(issues),
        "next_action": _contract_candidate_abi_mismatch_next_action(name, issues),
    }

def _abi_effective_preserved_registers(function: dict[str, Any]) -> list[str]:
    registers = function.get("registers") if isinstance(function.get("registers"), dict) else {}
    preserved = {str(item) for item in registers.get("preserved_candidates", []) if isinstance(item, str)}
    return sorted(reg for reg in preserved if not _abi_preserved_candidate_is_identity_noop(function, reg))

def _abi_preserved_candidate_is_identity_noop(function: dict[str, Any], register: str) -> bool:
    provenance = [
        item
        for item in function.get("register_value_provenance", [])
        if isinstance(item, dict) and _abi_x86_register_family(str(item.get("register") or "")) == register
    ]
    if not provenance:
        return False
    return all(_abi_register_definition_is_identity_noop(register, item.get("definition")) for item in provenance)

def _abi_register_definition_is_identity_noop(register: str, definition: Any) -> bool:
    if not isinstance(definition, dict):
        return False
    instruction = definition.get("instruction") if isinstance(definition.get("instruction"), dict) else {}
    mnemonic = str(instruction.get("mnemonic") or "")
    if mnemonic == "lea" and definition.get("kind") == "address":
        addressing = definition.get("addressing") if isinstance(definition.get("addressing"), dict) else {}
        base = _abi_x86_register_family(str(addressing.get("base") or ""))
        index = _abi_x86_register_family(str(addressing.get("index") or ""))
        disp = _safe_int(addressing.get("disp")) or 0
        return base == _abi_x86_register_family(register) and not index and disp == 0
    if mnemonic == "mov" and definition.get("kind") == "register":
        return _abi_x86_register_family(str(definition.get("register") or "")) == _abi_x86_register_family(register)
    return False

def _contract_candidate_decision_tree_switch_coverage_count(
    reference_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    expected_count: int,
    observed_count: int,
) -> int:
    if expected_count <= observed_count:
        return 0
    reference_switches = [
        item
        for item in reference_function.get("switch_contracts", [])
        if isinstance(item, dict)
    ]
    if not reference_switches:
        return 0
    candidate_dispatches = [
        item
        for item in candidate_function.get("decision_tree_contracts", [])
        if isinstance(item, dict) and item.get("kind") == "direct_compare_dispatch_candidate"
    ]
    if not candidate_dispatches:
        return 0
    return min(max(0, expected_count - observed_count), len(candidate_dispatches))

def _contract_candidate_argument_pointer_out_param_coverage_count(
    reference_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    expected_count: int,
    observed_count: int,
) -> int:
    if expected_count <= observed_count:
        return 0
    if not _abi_list_count(reference_function.get("register_out_param_candidates")):
        return 0
    candidate_writes = [
        item
        for item in candidate_function.get("memory_writes", [])
        if isinstance(item, dict)
    ]
    has_argument_pointer_write = any(item.get("memory_role") == "argument_pointer_deref" for item in candidate_writes)
    if not has_argument_pointer_write:
        return 0
    covering_writes = [
        item
        for item in candidate_writes
        if item.get("memory_role") in {"argument_pointer_deref", "computed_pointer_deref"}
    ]
    return min(max(0, expected_count - observed_count), len(covering_writes))

def _abi_function_local_loop_hint_count(function: dict[str, Any]) -> int:
    return len(_abi_function_local_loop_hints(function))

def _abi_function_local_loop_hints(function: dict[str, Any]) -> list[dict[str, Any]]:
    hints = function.get("loop_hints") if isinstance(function.get("loop_hints"), list) else []
    return [hint for hint in hints if isinstance(hint, dict) and _abi_loop_hint_is_function_local(function, hint)]

def _abi_loop_hint_is_function_local(function: dict[str, Any], hint: dict[str, Any]) -> bool:
    target = _safe_int(hint.get("target_rva"))
    if target is None:
        return False
    for block in function.get("blocks", []) if isinstance(function.get("blocks"), list) else []:
        if not isinstance(block, dict):
            continue
        start = _safe_int(block.get("rva_start"))
        end = _safe_int(block.get("rva_end"))
        if start is not None and end is not None and start <= target < end:
            return True
    return False

def _abi_loop_hint_key(hint: dict[str, Any]) -> tuple[int, int]:
    instruction = hint.get("instruction") if isinstance(hint.get("instruction"), dict) else {}
    return (_safe_int(instruction.get("rva")) or -1, _safe_int(hint.get("target_rva")) or -1)

def _contract_candidate_abi_memory_summary_issue(reference_function: dict[str, Any], candidate_function: dict[str, Any]) -> dict[str, Any] | None:
    reference = reference_function.get("memory_effect_summary") if isinstance(reference_function.get("memory_effect_summary"), dict) else {}
    candidate = candidate_function.get("memory_effect_summary") if isinstance(candidate_function.get("memory_effect_summary"), dict) else {}
    expected_reads = _safe_int(reference.get("reads")) or 0
    expected_writes = _safe_int(reference.get("writes")) or 0
    observed_reads = _safe_int(candidate.get("reads")) or 0
    observed_writes = _safe_int(candidate.get("writes")) or 0
    read_roles = _missing_counted_memory_roles(reference.get("read_roles"), candidate.get("read_roles"))
    write_roles = _missing_counted_memory_roles(reference.get("write_roles"), candidate.get("write_roles"))
    if expected_reads <= observed_reads and expected_writes <= observed_writes and not read_roles and not write_roles:
        return None
    if _contract_candidate_memory_gap_is_refptr_direct_transfer(
        reference_function,
        candidate_function,
        read_roles=read_roles,
        write_roles=write_roles,
        expected_reads=expected_reads,
        observed_reads=observed_reads,
        expected_writes=expected_writes,
        observed_writes=observed_writes,
    ):
        return None
    return {
        "category": "memory_effect_mismatch",
        "expected": reference,
        "observed": candidate,
        "missing_read_roles": read_roles,
        "missing_write_roles": write_roles,
        "cause_hint": "candidate memory reads/writes or access classes do not cover the reference contract",
    }

def _contract_candidate_memory_gap_is_refptr_direct_transfer(
    reference_function: dict[str, Any],
    candidate_function: dict[str, Any],
    *,
    read_roles: dict[str, int],
    write_roles: dict[str, int],
    expected_reads: int,
    observed_reads: int,
    expected_writes: int,
    observed_writes: int,
) -> bool:
    if write_roles or expected_writes > observed_writes:
        return False
    if not read_roles:
        return False
    if any(role not in {"global_writable_pointer_slot", "global_readonly_pointer_slot"} for role in read_roles):
        return False
    missing_reads = max(0, expected_reads - observed_reads)
    missing_roles = sum(read_roles.values())
    coverage = _contract_candidate_refptr_direct_transfer_coverage_count(reference_function, candidate_function)
    return coverage >= max(missing_reads, missing_roles)

def _contract_candidate_refptr_direct_transfer_coverage_count(
    reference_function: dict[str, Any],
    candidate_function: dict[str, Any],
) -> int:
    reference_refptrs = [
        item
        for item in reference_function.get("direct_refptr_transfers", [])
        if isinstance(item, dict)
    ]
    if not reference_refptrs:
        reference_refptrs = [
            item
            for item in reference_function.get("switch_contracts", [])
            if isinstance(item, dict) and _abi_switch_contract_is_resolved_refptr(item)
        ]
    if not reference_refptrs:
        return 0
    candidate_transfers = [
        item
        for item in candidate_function.get("direct_control_transfers", [])
        if isinstance(item, dict)
    ] + [
        item
        for item in candidate_function.get("direct_refptr_transfers", [])
        if isinstance(item, dict)
    ]
    if not candidate_transfers:
        return 0
    return min(len(reference_refptrs), len(candidate_transfers))

def _abi_switch_contract_is_resolved_refptr(contract: dict[str, Any]) -> bool:
    if contract.get("kind") != "indirect_jump_table_candidate":
        return False
    if contract.get("resolved_target_rva") in {None, ""}:
        return False
    expression = contract.get("index_expression") if isinstance(contract.get("index_expression"), dict) else {}
    return expression.get("base") is None and expression.get("index") is None

def _contract_candidate_abi_callsite_mismatch(
    name: str,
    match_key: str,
    callsite_index: int,
    reference_callsite: dict[str, Any],
    candidate_callsite: dict[str, Any],
    alias_match: dict[str, Any] | None,
    *,
    candidate_callsite_index: int | None = None,
    reference_function_index: list[dict[str, Any]] | None = None,
    candidate_function_index: list[dict[str, Any]] | None = None,
    alias_matches: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    issues: list[dict[str, Any]] = []
    target_match = _contract_candidate_abi_target_match(
        reference_callsite.get("target"),
        candidate_callsite.get("target"),
        reference_function_index=reference_function_index or [],
        candidate_function_index=candidate_function_index or [],
        alias_matches=alias_matches or {},
    )
    if (
        target_match["reference"]
        and target_match["candidate"]
        and not target_match["matched"]
    ):
        issues.append(
            {
                "category": "call_target_mismatch",
                "expected": target_match["reference"],
                "observed": target_match["candidate"],
                "cause_hint": "candidate call target kind/import/direct edge differs from the reference callsite",
            }
        )
    reference_hidden = reference_callsite.get("hidden_sret_or_out_param_evidence") if isinstance(reference_callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    candidate_hidden = candidate_callsite.get("hidden_sret_or_out_param_evidence") if isinstance(candidate_callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    if reference_hidden.get("status") == "candidate" and candidate_hidden.get("status") != "candidate":
        issues.append(
            {
                "category": "hidden_sret_or_out_param_missing",
                "expected": reference_hidden,
                "observed": candidate_hidden,
                "cause_hint": "candidate callsite lost address-like first argument evidence",
            }
        )
    reference_varargs = reference_callsite.get("varargs_evidence") if isinstance(reference_callsite.get("varargs_evidence"), dict) else {}
    candidate_varargs = candidate_callsite.get("varargs_evidence") if isinstance(candidate_callsite.get("varargs_evidence"), dict) else {}
    varargs_issue = _contract_candidate_abi_varargs_issue(reference_varargs, candidate_varargs)
    if varargs_issue is not None:
        issues.append(varargs_issue)
    reference_inventory = _abi_argument_inventory_signature(reference_callsite.get("argument_inventory"))
    candidate_inventory = _abi_argument_inventory_signature(candidate_callsite.get("argument_inventory"))
    inventory_issue = _contract_candidate_abi_argument_inventory_issue(
        reference_inventory,
        candidate_inventory,
        target_match=target_match,
    )
    if inventory_issue is not None:
        issues.append(inventory_issue)
    reference_targets = _abi_list_count(reference_callsite.get("function_pointer_targets"))
    candidate_targets = _abi_list_count(candidate_callsite.get("function_pointer_targets"))
    if reference_targets > candidate_targets:
        issues.append(
            {
                "category": "function_pointer_target_missing",
                "expected": reference_targets,
                "observed": candidate_targets,
                "cause_hint": "candidate lost recoverable function-pointer target evidence",
            }
        )
    if not issues:
        return None
    return {
        "name": name,
        "match_key": match_key,
        "alias_match": alias_match,
        "callsite_index": callsite_index,
        "candidate_callsite_index": candidate_callsite_index if candidate_callsite_index is not None else callsite_index,
        "block_id": reference_callsite.get("block_id"),
        "callsite_id": reference_callsite.get("id"),
        "reference_callsite": _abi_callsite_gap_sample(reference_callsite),
        "candidate_callsite": _abi_callsite_gap_sample(candidate_callsite),
        "issues": issues[:12],
        "repair_class": _contract_candidate_abi_mismatch_repair_class(issues),
        "next_action": _contract_candidate_abi_mismatch_next_action(name, issues),
    }

def _contract_candidate_abi_target_match(
    reference_target: Any,
    candidate_target: Any,
    *,
    reference_function_index: list[dict[str, Any]],
    candidate_function_index: list[dict[str, Any]],
    alias_matches: dict[str, Any],
) -> dict[str, Any]:
    reference_signature = _abi_target_signature_with_resolution(reference_target, reference_function_index)
    candidate_signature = _abi_target_signature_with_resolution(candidate_target, candidate_function_index)
    if reference_signature == candidate_signature:
        return {"matched": True, "reference": reference_signature, "candidate": candidate_signature}
    if _contract_candidate_abi_import_targets_match(reference_signature, candidate_signature):
        return {
            "matched": True,
            "reference": reference_signature,
            "candidate": candidate_signature,
            "resolution": "import_thunk_equivalent_target",
        }
    if _contract_candidate_abi_resolved_targets_match(
        reference_signature.get("resolved_functions"),
        candidate_signature.get("resolved_functions"),
        alias_matches,
    ):
        return {
            "matched": True,
            "reference": reference_signature,
            "candidate": candidate_signature,
            "resolution": "resolved_direct_target_function",
        }
    return {"matched": False, "reference": reference_signature, "candidate": candidate_signature}

def _abi_target_signature_with_resolution(target: Any, function_index: list[dict[str, Any]]) -> dict[str, Any]:
    signature = _abi_target_signature(target)
    if signature.get("kind") != "direct":
        return signature
    rva = _optional_contract_int(signature.get("target_rva"))
    if rva is None:
        return signature
    resolved: list[dict[str, Any]] = []
    for item in function_index:
        if not int(item.get("rva_start") or 0) <= rva < int(item.get("rva_end") or 0):
            continue
        resolved_item = {
            "name": item.get("name"),
            "match_key": item.get("match_key"),
            "rva_start": item.get("rva_start"),
            "rva_end": item.get("rva_end"),
            "block_id": item.get("block_id"),
        }
        if isinstance(item.get("import_signature"), dict):
            resolved_item["import_signature"] = item.get("import_signature")
        if item.get("resolution_kind") is not None:
            resolved_item["resolution_kind"] = item.get("resolution_kind")
        resolved.append(resolved_item)
    if resolved:
        signature["resolved_functions"] = resolved[:8]
        import_equivalent = _abi_import_equivalent_signature(resolved)
        if import_equivalent is not None:
            signature["import_equivalent"] = import_equivalent
    return signature

def _contract_candidate_abi_import_targets_match(reference_signature: dict[str, Any], candidate_signature: dict[str, Any]) -> bool:
    reference_import = _abi_target_import_signature(reference_signature)
    candidate_import = _abi_target_import_signature(candidate_signature)
    return reference_import is not None and candidate_import is not None and reference_import == candidate_import

def _abi_target_import_signature(signature: dict[str, Any]) -> tuple[str, str, str] | None:
    if signature.get("kind") == "import":
        return (
            str(signature.get("dll") or "").lower(),
            str(signature.get("symbol") or ""),
            str(signature.get("ordinal") or ""),
        )
    equivalent = signature.get("import_equivalent") if isinstance(signature.get("import_equivalent"), dict) else {}
    if equivalent:
        return (
            str(equivalent.get("dll") or "").lower(),
            str(equivalent.get("symbol") or ""),
            str(equivalent.get("ordinal") or ""),
        )
    return None

def _abi_import_equivalent_signature(resolved_functions: list[dict[str, Any]]) -> dict[str, Any] | None:
    signatures = [
        item.get("import_signature")
        for item in resolved_functions
        if isinstance(item.get("import_signature"), dict) and item.get("resolution_kind") == "import_thunk"
    ]
    if len(signatures) != 1:
        return None
    signature = signatures[0]
    return {"dll": signature.get("dll"), "symbol": signature.get("symbol"), "ordinal": signature.get("ordinal")}

def _contract_candidate_abi_resolved_targets_match(
    reference_resolved: Any,
    candidate_resolved: Any,
    alias_matches: dict[str, Any],
) -> bool:
    reference_functions = [item for item in reference_resolved if isinstance(item, dict)] if isinstance(reference_resolved, list) else []
    candidate_functions = [item for item in candidate_resolved if isinstance(item, dict)] if isinstance(candidate_resolved, list) else []
    for reference in reference_functions:
        reference_name = reference.get("name")
        if not isinstance(reference_name, str) or not reference_name:
            continue
        candidate_names = _contract_candidate_abi_expected_candidate_names(reference_name, alias_matches)
        candidate_keys = {_linker_function_match_key(name) for name in candidate_names}
        for candidate in candidate_functions:
            candidate_name = candidate.get("name")
            if not isinstance(candidate_name, str) or not candidate_name:
                continue
            if candidate_name in candidate_names or _linker_function_match_key(candidate_name) in candidate_keys:
                return True
    return False

def _contract_candidate_abi_expected_candidate_names(reference_name: str, alias_matches: dict[str, Any]) -> set[str]:
    names = {reference_name}
    match = alias_matches.get(reference_name) if isinstance(alias_matches.get(reference_name), dict) else {}
    candidate = match.get("candidate") if isinstance(match.get("candidate"), dict) else {}
    candidate_name = candidate.get("name")
    if isinstance(candidate_name, str) and candidate_name:
        names.add(candidate_name)
    aliases = candidate.get("aliases") if isinstance(candidate.get("aliases"), list) else []
    names.update(alias for alias in aliases if isinstance(alias, str) and alias)
    return names

def _contract_candidate_abi_varargs_issue(reference: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any] | None:
    if reference.get("status") != "candidate":
        return None
    if candidate.get("status") != "candidate":
        return {
            "category": "varargs_evidence_missing",
            "expected": reference,
            "observed": candidate,
            "cause_hint": "candidate callsite lost known variadic import/prototype evidence",
        }
    reference_format = reference.get("format_string") if isinstance(reference.get("format_string"), dict) else {}
    candidate_format = candidate.get("format_string") if isinstance(candidate.get("format_string"), dict) else {}
    reference_missing = _safe_int(reference_format.get("missing_varargs")) or 0
    candidate_missing = _safe_int(candidate_format.get("missing_varargs")) or 0
    reference_required = _safe_int(reference_format.get("required_varargs"))
    candidate_required = _safe_int(candidate_format.get("required_varargs"))
    if reference_required != candidate_required or candidate_missing > reference_missing:
        return {
            "category": "varargs_format_inventory_mismatch",
            "expected": reference_format,
            "observed": candidate_format,
            "cause_hint": "candidate static format string or observed variadic argument inventory differs from reference",
        }
    return None

def _abi_target_signature(target: Any) -> dict[str, Any]:
    if not isinstance(target, dict):
        return {}
    return {
        key: target.get(key)
        for key in ("kind", "dll", "symbol", "ordinal", "target_rva", "thunk_rva", "status")
        if target.get(key) not in {None, ""}
    }

def _abi_argument_inventory_signature(inventory: Any) -> dict[str, Any]:
    if not isinstance(inventory, dict):
        return {}
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    register_args = inventory.get("register_args") if isinstance(inventory.get("register_args"), list) else []
    return {
        "calling_convention": inventory.get("calling_convention"),
        "argument_count": inventory.get("argument_count"),
        "stack_roles": [item.get("role") for item in stack_args if isinstance(item, dict)],
        "stack_args": [
            _abi_stack_argument_signature(item)
            for item in stack_args
            if isinstance(item, dict)
        ],
        "register_roles": [
            {"register": item.get("register"), "role": item.get("role")}
            for item in register_args
            if isinstance(item, dict)
        ],
    }

def _abi_stack_argument_signature(argument: dict[str, Any]) -> dict[str, Any]:
    signature = {
        key: argument.get(key)
        for key in ("index", "role")
        if argument.get(key) not in {None, ""}
    }
    source = argument.get("source") if isinstance(argument.get("source"), dict) else {}
    if source:
        source_signature = {
            key: source.get(key)
            for key in ("kind", "stack_offset", "memory_role")
            if source.get(key) not in {None, ""}
        }
        if "stack_offset" not in source_signature:
            index = argument.get("index")
            if isinstance(index, int) and index >= 0:
                source_signature["stack_offset"] = index * 4
        value = source.get("value")
        if isinstance(value, (int, str)) and not isinstance(value, bool):
            source_signature["value"] = value
        string_literal = source.get("string_literal") if isinstance(source.get("string_literal"), dict) else {}
        if string_literal:
            source_signature["string_literal"] = {
                key: string_literal.get(key)
                for key in ("rva", "size", "sha256", "text")
                if string_literal.get(key) not in {None, ""}
            }
        if source_signature:
            signature["source"] = source_signature
    return signature

_ABI_ADDRESS_LIKE_ARGUMENT_ROLES = {
    "computed_out_param_or_hidden_sret",
    "stack_out_param_or_scratch_buffer",
}

_ABI_BY_VALUE_ARGUMENT_ROLES = {
    "computed_memory",
    "computed_pointer_deref",
    "immediate",
    "register",
    "stack_argument_slot",
    "stack_local_slot",
    "stack_pointer_slot",
}

def _contract_candidate_abi_argument_inventory_match(reference: dict[str, Any], candidate: dict[str, Any]) -> bool:
    if reference == candidate:
        return True
    if reference.get("calling_convention") != candidate.get("calling_convention"):
        return False
    if reference.get("argument_count") != candidate.get("argument_count"):
        return False
    if not _contract_candidate_abi_stack_roles_match(reference.get("stack_roles"), candidate.get("stack_roles")):
        return False
    return _contract_candidate_abi_register_roles_match(reference.get("register_roles"), candidate.get("register_roles"))

def _contract_candidate_abi_argument_inventory_issue(
    reference: dict[str, Any],
    candidate: dict[str, Any],
    *,
    target_match: dict[str, Any],
) -> dict[str, Any] | None:
    if not reference or not candidate:
        return None
    if _contract_candidate_abi_argument_inventory_match(reference, candidate):
        return None
    if _contract_candidate_abi_reference_inventory_underconstrained(reference, candidate, target_match=target_match):
        return {
            "category": "reference_argument_inventory_underconstrained",
            "expected": reference,
            "observed": candidate,
            "cause_hint": "reference callsite argument recovery is underconstrained; improve Stage A before using this callsite to steer source repair",
        }
    return {
        "category": "callsite_argument_inventory_mismatch",
        "expected": reference,
        "observed": candidate,
        "cause_hint": "candidate argument count, argument roles, or calling convention differs from the reference callsite",
    }

def _contract_candidate_abi_reference_inventory_underconstrained(
    reference: dict[str, Any],
    candidate: dict[str, Any],
    *,
    target_match: dict[str, Any],
) -> bool:
    if target_match.get("matched") is not True:
        return False
    if reference.get("calling_convention") != candidate.get("calling_convention"):
        return False
    if reference.get("argument_count") != 0 or not candidate.get("argument_count"):
        return False
    if reference.get("stack_roles") or reference.get("register_roles"):
        return False
    return True

def _contract_candidate_abi_stack_roles_match(reference: Any, candidate: Any) -> bool:
    if not isinstance(reference, list) or not isinstance(candidate, list):
        return reference == candidate
    if len(reference) != len(candidate):
        return False
    return all(
        _contract_candidate_abi_stack_role_match(reference_role, candidate_role)
        for reference_role, candidate_role in zip(reference, candidate, strict=True)
    )

def _contract_candidate_abi_stack_role_match(reference: Any, candidate: Any) -> bool:
    return _contract_candidate_abi_argument_role_match(reference, candidate)

def _contract_candidate_abi_register_roles_match(reference: Any, candidate: Any) -> bool:
    if not isinstance(reference, list) or not isinstance(candidate, list):
        return reference == candidate
    if len(reference) != len(candidate):
        return False
    for reference_item, candidate_item in zip(reference, candidate, strict=True):
        if not isinstance(reference_item, dict) or not isinstance(candidate_item, dict):
            if reference_item != candidate_item:
                return False
            continue
        if reference_item.get("register") != candidate_item.get("register"):
            return False
        if not _contract_candidate_abi_argument_role_match(reference_item.get("role"), candidate_item.get("role")):
            return False
    return True

def _contract_candidate_abi_argument_role_match(reference: Any, candidate: Any) -> bool:
    if reference == candidate:
        return True
    if not isinstance(reference, str) or not isinstance(candidate, str):
        return False
    if reference == "register" and candidate in _ABI_ADDRESS_LIKE_ARGUMENT_ROLES:
        return True
    if reference == "register" and candidate in {"global_readonly_pointer_slot", "global_writable_pointer_slot"}:
        return True
    if reference == "immediate" and candidate == "string_literal":
        return True
    if reference in _ABI_BY_VALUE_ARGUMENT_ROLES and candidate in _ABI_BY_VALUE_ARGUMENT_ROLES:
        return True
    return False

def _abi_list_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0

def _missing_counted_memory_roles(reference: Any, candidate: Any) -> dict[str, int]:
    if not isinstance(reference, dict):
        return {}
    candidate = candidate if isinstance(candidate, dict) else {}
    remaining_candidate = {
        str(role): _safe_int(count) or 0
        for role, count in candidate.items()
    }
    missing: dict[str, int] = {}
    for role, expected_value in sorted(reference.items()):
        role_name = str(role)
        remaining = _safe_int(expected_value) or 0
        for candidate_role in _memory_role_covering_candidates(role_name):
            available = remaining_candidate.get(candidate_role, 0)
            if available <= 0:
                continue
            used = min(remaining, available)
            remaining -= used
            remaining_candidate[candidate_role] = available - used
            if remaining <= 0:
                break
        if remaining > 0:
            missing[role_name] = remaining
    return missing

def _memory_role_covering_candidates(role: str) -> list[str]:
    if role == "stack_pointer_slot":
        return ["stack_pointer_slot", "stack_argument_slot"]
    if role == "stack_argument_slot":
        return ["stack_argument_slot", "stack_pointer_slot"]
    if role == "computed_pointer_deref":
        return ["computed_pointer_deref", "argument_pointer_deref"]
    if role == "computed_memory":
        return ["computed_memory", "computed_pointer_deref", "argument_pointer_deref"]
    if role in {"global_writable_pointer_slot", "global_readonly_pointer_slot"}:
        return [role, "import_address_table"]
    return [role]

def _contract_candidate_abi_mismatch_repair_class(issues: list[dict[str, Any]]) -> str:
    categories = [
        str(issue.get("category") or "").lower()
        for issue in issues
        if isinstance(issue, dict) and issue.get("category")
    ]
    category_text = " ".join(categories)
    if "reference_argument_inventory_underconstrained" in categories:
        return "stage_a_argument_inventory_underconstrained"
    if "varargs" in category_text or "stdio" in category_text or "printf" in category_text:
        return "varargs_or_stdio_bridge"
    if "sret" in category_text or "out_param" in category_text:
        return "hidden_sret_or_out_param"
    if "switch" in category_text or "jump_table" in category_text:
        return "switch_or_jump_table_dispatch"
    if "loop" in category_text:
        return "loop_or_state_machine"
    if "function_pointer" in category_text:
        return "function_pointer_target"
    if "call_target_mismatch" in categories:
        return "call_target_mismatch"
    if "callsite_argument_inventory_mismatch" in categories:
        return "callsite_argument_inventory_mismatch"
    if "register" in category_text or "clobber" in category_text or "preserved" in category_text:
        return "preserved_register_mismatch"
    if "stack" in category_text:
        return "stack_delta_mismatch"
    if "memory" in category_text:
        return "memory_effect_mismatch"
    if categories:
        return "abi_callsite_mismatch"
    text = json.dumps(issues, sort_keys=True, default=str).lower()
    if "varargs" in text or "stdio" in text or "printf" in text:
        return "varargs_or_stdio_bridge"
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "switch" in text or "jump_table" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text:
        return "loop_or_state_machine"
    if "function_pointer" in text:
        return "function_pointer_target"
    if "call target" in text or "target" in text:
        return "call_target_mismatch"
    if "argument" in text:
        return "callsite_argument_inventory_mismatch"
    if "register" in text or "clobber" in text or "preserved" in text:
        return "preserved_register_mismatch"
    if "stack" in text:
        return "stack_delta_mismatch"
    if "memory" in text:
        return "memory_effect_mismatch"
    return "abi_callsite_mismatch"

def _contract_candidate_abi_mismatch_next_action(name: str, issues: list[dict[str, Any]]) -> str:
    repair_class = _contract_candidate_abi_mismatch_repair_class(issues)
    if repair_class == "stage_a_argument_inventory_underconstrained":
        return f"improve Stage A argument recovery for {name}; reference callsite inventory is underconstrained before source repair can be trusted"
    if repair_class == "varargs_or_stdio_bridge":
        return f"repair {name} varargs/stdio bridge, format-string argument inventory, and imported prototype surface"
    if repair_class == "hidden_sret_or_out_param":
        return f"repair {name} hidden sret/out-param representation and address-like argument flow"
    if repair_class == "switch_or_jump_table_dispatch":
        return f"repair {name} switch/jump-table dispatch so every checked target and default edge is represented"
    if repair_class == "loop_or_state_machine":
        return f"repair {name} loop backedges, loop-carried state, and exit predicates"
    if repair_class == "function_pointer_target":
        return f"recover {name} function-pointer target set or represent it as a checked indirect target contract"
    if repair_class == "call_target_mismatch":
        return f"repair {name} call target mapping, import thunk linkage, or direct-call callee selection"
    if repair_class == "callsite_argument_inventory_mismatch":
        return f"repair {name} call argument order/count/roles and stack/register argument materialization"
    if repair_class == "preserved_register_mismatch":
        return f"repair {name} register save/restore and clobber behavior before rerunning Stage A contract validation"
    if repair_class == "stack_delta_mismatch":
        return f"repair {name} calling convention and stack cleanup before rerunning Stage A contract validation"
    if repair_class == "memory_effect_mismatch":
        return f"repair {name} memory reads/writes, field accesses, and global/stack access classes"
    return f"repair {name} ABI/callsite contract mismatch and rerun Stage A contract validation"

def _contract_candidate_abi_candidates(
    candidate_by_key: dict[str, list[dict[str, Any]]],
    reference_name: str,
    alias_match: Any,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for key in _contract_candidate_symbol_keys(reference_name):
        for function in candidate_by_key.get(key, []):
            if function not in candidates:
                candidates.append(function)
    if isinstance(alias_match, dict):
        candidate = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
        for candidate_name in (candidate.get("name"), alias_match.get("source_function")):
            if isinstance(candidate_name, str):
                for key in _contract_candidate_symbol_keys(candidate_name):
                    for function in candidate_by_key.get(key, []):
                        if function not in candidates:
                            candidates.append(function)
    return candidates

def _contract_candidate_abi_best_candidate(candidates: list[dict[str, Any]], alias_match: Any) -> dict[str, Any]:
    preferred_names: set[str] = set()
    if isinstance(alias_match, dict):
        candidate = alias_match.get("candidate") if isinstance(alias_match.get("candidate"), dict) else {}
        for name in (candidate.get("name"), alias_match.get("source_function")):
            if isinstance(name, str) and name:
                preferred_names.add(name)
    preferred = [
        function
        for function in candidates
        if preferred_names & set(_contract_candidate_function_symbol_names(function))
    ]
    if preferred:
        candidates = preferred
    return max(
        candidates,
        key=lambda item: len(item.get("callsites", [])) if isinstance(item.get("callsites"), list) else 0,
    )

def _contract_candidate_abi_alias_sample(alias_match: Any) -> dict[str, Any] | None:
    if not isinstance(alias_match, dict):
        return None
    return {
        "source_function": alias_match.get("source_function"),
        "source_kind": alias_match.get("source_kind"),
        "candidate": alias_match.get("candidate"),
    }

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

def _abi_instruction_is_semantic_noop(insn: Any) -> bool:
    mnemonic = str(insn.mnemonic)
    if mnemonic == "nop":
        return True
    if mnemonic == "xchg" and len(insn.operands) == 2:
        left = _abi_operand_register_name(insn, insn.operands[0])
        right = _abi_operand_register_name(insn, insn.operands[1])
        return bool(left and right and left == right)
    if mnemonic != "lea" or len(insn.operands) != 2:
        return False
    destination = _abi_operand_register_name(insn, insn.operands[0])
    source = insn.operands[1]
    if not destination or source.type != X86_OP_MEM:
        return False
    base = _abi_x86_register_family(insn.reg_name(source.mem.base) if source.mem.base else None)
    index = _abi_x86_register_family(insn.reg_name(source.mem.index) if source.mem.index else None)
    destination = _abi_x86_register_family(destination)
    return base == destination and not index and int(source.mem.disp) == 0

def _abi_operand_register_name(insn: Any, operand: Any) -> str | None:
    if operand.type != X86_OP_REG:
        return None
    return _abi_x86_register_family(insn.reg_name(operand.reg))

def _instruction_register_access(insn: Any) -> tuple[set[str], set[str]]:
    reads: set[str] = set()
    writes: set[str] = set()
    try:
        read_ids, write_ids = insn.regs_access()
    except Exception:
        read_ids, write_ids = (), ()
    for reg in read_ids:
        name = insn.reg_name(reg)
        if name:
            reads.add(str(name))
    for reg in write_ids:
        name = insn.reg_name(reg)
        if name:
            writes.add(str(name))
    return reads, writes

def _abi_instruction_memory_accesses(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    reads: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    field_accesses: list[dict[str, Any]] = []
    mnemonic = str(insn.mnemonic)
    for index, operand in enumerate(getattr(insn, "operands", []) or []):
        if operand.type != X86_OP_MEM:
            continue
        if mnemonic == "lea":
            continue
        access_kind = _abi_operand_memory_access_kind(insn, index)
        if access_kind is None:
            continue
        access = _abi_memory_access_report(binary, insn, operand, access_kind, register_definitions)
        if access_kind == "read":
            reads.append(access)
        elif access_kind == "write":
            writes.append(access)
        else:
            reads.append({**access, "access": "read"})
            writes.append({**access, "access": "write"})
        field = _abi_field_access_report(access)
        if field is not None:
            field_accesses.append(field)
    return {"reads": reads, "writes": writes, "field_accesses": field_accesses}

def _abi_operand_memory_access_kind(insn: Any, operand_index: int) -> str | None:
    mnemonic = str(insn.mnemonic)
    if mnemonic in {"jmp", "ljmp", "call"}:
        return "read"
    if mnemonic in {"cmp", "test"}:
        return "read"
    if mnemonic == "push":
        return "read"
    if mnemonic == "pop":
        return "write"
    if mnemonic in {"inc", "dec", "neg", "not"}:
        return "read_write"
    if mnemonic in {"mov", "movzx", "movsx", "lea"}:
        return "write" if operand_index == 0 and mnemonic == "mov" else "read"
    if operand_index == 0 and mnemonic in {"add", "sub", "and", "or", "xor", "shl", "shr", "sar", "rol", "ror"}:
        return "read_write"
    return "read"

def _abi_memory_access_report(
    binary: StageABinary,
    insn: Any,
    operand: Any,
    access_kind: str,
    register_definitions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    addressing = _abi_mem_operand_report(insn, operand)
    access: dict[str, Any] = {
        "evidence_status": "derived",
        "access": access_kind,
        "width": int(getattr(operand, "size", 0) or 0),
        "addressing": addressing,
        "instruction": _instruction_report(binary, insn),
    }
    memory_rva = _abi_absolute_addressing_rva(binary, addressing)
    if memory_rva is not None:
        access["memory_rva"] = memory_rva
        imported = _import_for_thunk_rva(binary, memory_rva)
        if imported is not None:
            access["import"] = _abi_import_report(imported)
        section = _section_for_rva(binary, memory_rva)
        if section is not None:
            access["memory_section"] = _abi_section_report(section)
        string_literal = _abi_string_literal_at_rva(binary, memory_rva)
        if string_literal is not None:
            access["string_literal"] = string_literal
    base = addressing.get("base")
    if isinstance(base, str):
        base_definition = register_definitions.get(base)
        if isinstance(base_definition, dict):
            access["base_register_definition"] = base_definition
        elif base not in {"esp", "ebp", "rsp", "rbp"}:
            access["entry_register_pointer"] = {
                "register": base,
                "evidence_status": "candidate",
                "reason": "memory access uses an entry register as a base before a local definition was observed",
            }
    access["memory_role"] = _abi_memory_role(access)
    return access

def _abi_field_access_report(access: dict[str, Any]) -> dict[str, Any] | None:
    addressing = access.get("addressing") if isinstance(access.get("addressing"), dict) else {}
    base = addressing.get("base")
    disp = _safe_int(addressing.get("disp"))
    if not isinstance(base, str) or disp is None:
        return None
    if base in {"esp", "ebp", "rsp", "rbp"} and disp == 0:
        return None
    return {
        "evidence_status": "derived",
        "base": base,
        "offset": disp,
        "width": access.get("width"),
        "access": access.get("access"),
        "memory_role": access.get("memory_role"),
        "instruction": access.get("instruction"),
        "base_register_definition": access.get("base_register_definition") if isinstance(access.get("base_register_definition"), dict) else None,
    }

def _abi_register_out_param_candidates(memory_writes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for write in memory_writes:
        if not isinstance(write, dict):
            continue
        entry_pointer = write.get("entry_register_pointer") if isinstance(write.get("entry_register_pointer"), dict) else None
        if entry_pointer is None:
            continue
        result.append(
            {
                "evidence_status": "candidate",
                "register": entry_pointer.get("register"),
                "kind": "register_carried_out_param",
                "reason": "function writes through an entry register pointer before defining that register",
                "write": write,
            }
        )
    return result

def _abi_memory_effect_summary(reads: list[dict[str, Any]], writes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "evidence_status": "derived",
        "reads": len([item for item in reads if isinstance(item, dict)]),
        "writes": len([item for item in writes if isinstance(item, dict)]),
        "read_roles": _count_by([item for item in reads if isinstance(item, dict)], "memory_role"),
        "write_roles": _count_by([item for item in writes if isinstance(item, dict)], "memory_role"),
    }

def _abi_switch_contracts(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    contracts: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
            continue
        target = _resolved_branch_target(binary, insn)
        addressing = _abi_mem_operand_report(insn, insn.operands[0])
        if _abi_refptr_direct_transfer(binary, block, insn, addressing, target) is not None:
            continue
        table_contract = _abi_indexed_jump_table_contract(binary, block, instructions, insn, addressing)
        if table_contract is not None:
            contracts.append(table_contract)
            continue
        contracts.append(
            {
                "evidence_status": "derived" if target is not None else "incomplete",
                "kind": "indirect_jump_table_candidate",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "index_expression": addressing,
                "resolved_target_rva": target,
                "next_action": "recover table bounds, default edge, and case target mapping before treating this as a source-level switch",
            }
        )
    return contracts

def _abi_direct_refptr_transfers(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    transfers: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
            continue
        addressing = _abi_mem_operand_report(insn, insn.operands[0])
        transfer = _abi_refptr_direct_transfer(binary, block, insn, addressing, _resolved_branch_target(binary, insn))
        if transfer is not None:
            transfers.append(transfer)
    return transfers

def _abi_refptr_direct_transfer(
    binary: StageABinary,
    block: BlockSide,
    insn: Any,
    addressing: dict[str, Any],
    target: int | None,
) -> dict[str, Any] | None:
    if target is None:
        return None
    if addressing.get("base") is not None or addressing.get("index") is not None:
        return None
    pointer_rva = _absolute_mem_operand_rva(binary, insn.operands[0])
    if pointer_rva is None:
        return None
    return {
        "evidence_status": "derived",
        "kind": "resolved_refptr_direct_transfer",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "pointer_rva": pointer_rva,
        "pointer_section": _abi_section_report(section) if (section := _section_for_rva(binary, pointer_rva)) is not None else None,
        "target_rva": target,
        "target_section": _abi_section_report(section) if (section := _section_for_rva(binary, target)) is not None else None,
        "normalization": "candidate may cover this with an equivalent direct branch when the refptr target is resolved by Stage A",
    }

def _abi_direct_control_transfers(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    transfers: list[dict[str, Any]] = []
    for insn in instructions:
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
            continue
        target = _direct_branch_target(insn, binary.image_base)
        if target is None:
            continue
        transfers.append(
            {
                "evidence_status": "derived",
                "kind": "direct_control_transfer",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "target_rva": target,
                "target_section": _abi_section_report(section) if (section := _section_for_rva(binary, target)) is not None else None,
            }
        )
    return transfers

def _abi_indexed_jump_table_contract(
    binary: StageABinary,
    block: BlockSide,
    instructions: list[Any],
    insn: Any,
    addressing: dict[str, Any],
    *,
    bounds_override: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if binary.bitness != 32:
        return None
    operand = insn.operands[0]
    mem = operand.mem
    pointer_width = 4
    index_register = insn.reg_name(mem.index) if mem.index else None
    if not index_register or mem.base or int(mem.scale) != pointer_width:
        return None
    table_rva = _abi_value_to_rva(binary, int(mem.disp))
    if table_rva is None:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table displacement is not an in-image table address",
        )
    table_section = _section_for_rva(binary, table_rva)
    if table_section is None or not table_section.readable:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table address does not resolve to readable PE section bytes",
            table_rva=table_rva,
        )
    bounds = bounds_override if bounds_override is not None else _abi_jump_table_index_bounds(binary, instructions, insn, index_register)
    if bounds is None:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table index bounds are not statically recovered",
            table_rva=table_rva,
        )
    lower = int(bounds["lower"])
    upper = int(bounds["upper"])
    if lower < 0 or upper < lower or upper - lower + 1 > 4096:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table index bounds are invalid or exceed the conservative resolver cap",
            table_rva=table_rva,
        )

    case_targets: list[dict[str, Any]] = []
    table_bytes = bytearray()
    for index in range(lower, upper + 1):
        entry_rva = table_rva + index * pointer_width
        raw = binary.pe.get_data(entry_rva, pointer_width)
        if len(raw) != pointer_width:
            return _abi_incomplete_indexed_jump_table_contract(
                binary,
                block,
                insn,
                addressing,
                f"jump-table entry {index} could not be read",
                table_rva=table_rva,
                table_bounds=bounds,
            )
        table_bytes.extend(raw)
        target_va = int.from_bytes(raw, "little")
        target_rva = _abi_value_to_rva(binary, target_va)
        target_section = _executable_section_for_rva(binary, target_rva) if target_rva is not None else None
        if target_rva is None or target_section is None:
            return _abi_incomplete_indexed_jump_table_contract(
                binary,
                block,
                insn,
                addressing,
                f"jump-table entry {index} does not resolve to executable code",
                table_rva=table_rva,
                table_bounds=bounds,
            )
        case_targets.append(
            {
                "index": index,
                "entry_rva": entry_rva,
                "entry_va": binary.image_base + entry_rva,
                "target_va": target_va,
                "target_rva": target_rva,
                "target_section": _abi_section_report(target_section),
            }
        )
    if not case_targets:
        return _abi_incomplete_indexed_jump_table_contract(
            binary,
            block,
            insn,
            addressing,
            "jump-table bounds produced no case entries",
            table_rva=table_rva,
            table_bounds=bounds,
        )
    unique_targets = sorted({int(item["target_rva"]) for item in case_targets})
    return {
        "evidence_status": "derived",
        "kind": "indirect_jump_table_candidate",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "index_expression": addressing,
        "index_bounds": bounds,
        "table": {
            "rva_start": table_rva,
            "rva_end": table_rva + len(table_bytes),
            "va_start": binary.image_base + table_rva,
            "entry_width": pointer_width,
            "entries": len(case_targets),
            "bytes_sha256": sha256_bytes(bytes(table_bytes)),
            "section": _abi_section_report(table_section),
        },
        "table_bounds": {
            "lower": lower,
            "upper": upper,
            "entries": len(case_targets),
            "source": bounds.get("source"),
        },
        "case_targets": case_targets,
        "unique_target_rvas": unique_targets,
        "resolved_target_rva": unique_targets[0] if len(unique_targets) == 1 else None,
        "default_target_rva": None,
        "next_action": "represent this dispatch with the recovered selector, bounded case table, and explicit jump targets",
    }

def _abi_incomplete_indexed_jump_table_contract(
    binary: StageABinary,
    block: BlockSide,
    insn: Any,
    addressing: dict[str, Any],
    blocker: str,
    *,
    table_rva: int | None = None,
    table_bounds: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "evidence_status": "incomplete",
        "kind": "indirect_jump_table_candidate",
        "block": _range_report(block),
        "instruction": _instruction_report(binary, insn),
        "index_expression": addressing,
        "resolved_target_rva": None,
        "blocker": blocker,
        "next_action": "recover table bounds, default edge, and case target mapping before treating this as a source-level switch",
    }
    if table_rva is not None:
        result["table"] = {
            "rva_start": table_rva,
            "va_start": binary.image_base + table_rva,
            "entry_width": 4 if binary.bitness == 32 else 8,
        }
    if table_bounds is not None:
        result["table_bounds"] = table_bounds
    return result

def _abi_jump_table_index_bounds(
    binary: StageABinary,
    instructions: list[Any],
    insn: Any,
    index_register: str,
) -> dict[str, Any] | None:
    index_rva = int(insn.address - binary.image_base)
    full_index = _abi_x86_register_family(index_register)
    for previous in reversed([item for item in instructions if int(item.address - binary.image_base) < index_rva]):
        mnemonic = str(previous.mnemonic)
        operands = getattr(previous, "operands", []) or []
        if mnemonic == "movzx" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_REG:
            dst = _abi_x86_register_family(previous.reg_name(operands[0].reg))
            src = previous.reg_name(operands[1].reg)
            if dst == full_index and _abi_x86_register_family(src) == full_index:
                width = int(getattr(operands[1], "size", 0) or 0)
                if width > 0:
                    return {
                        "status": "derived",
                        "lower": 0,
                        "upper": (1 << (width * 8)) - 1,
                        "register": full_index,
                        "source": "movzx_register_width",
                        "source_instruction": _instruction_report(binary, previous),
                    }
        if mnemonic == "and" and len(operands) == 2 and operands[0].type == X86_OP_REG and operands[1].type == X86_OP_IMM:
            dst = _abi_x86_register_family(previous.reg_name(operands[0].reg))
            mask = int(operands[1].imm)
            if dst == full_index and 0 <= mask <= 4095:
                return {
                    "status": "derived",
                    "lower": 0,
                    "upper": mask,
                    "register": full_index,
                    "source": "and_immediate_mask",
                    "source_instruction": _instruction_report(binary, previous),
                }
        if mnemonic in {"call", "ret", "jmp", "ljmp"} or _is_conditional_jump(mnemonic):
            break
    return None

def _abi_x86_register_family(register: str | None) -> str:
    name = str(register or "").lower()
    families = {
        "eax": {"eax", "ax", "al", "ah"},
        "ebx": {"ebx", "bx", "bl", "bh"},
        "ecx": {"ecx", "cx", "cl", "ch"},
        "edx": {"edx", "dx", "dl", "dh"},
        "esi": {"esi", "si", "sil"},
        "edi": {"edi", "di", "dil"},
        "ebp": {"ebp", "bp", "bpl"},
        "esp": {"esp", "sp", "spl"},
    }
    for full, names in families.items():
        if name in names:
            return full
    return name

def _abi_loop_hints(binary: StageABinary, block: BlockSide, instructions: list[Any]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for insn in instructions:
        target = _resolved_branch_target(binary, insn)
        if target is None or target >= block.rva_end:
            continue
        mnemonic = str(insn.mnemonic)
        if mnemonic not in {"jmp", "ljmp"} and not _is_conditional_jump(mnemonic):
            continue
        hints.append(
            {
                "evidence_status": "derived",
                "kind": "backedge_candidate",
                "block": _range_report(block),
                "instruction": _instruction_report(binary, insn),
                "target_rva": target,
                "next_action": "derive loop-carried variables and exit conditions before treating this as a full loop contract",
            }
        )
    return hints

def _abi_ret_imm(insn: Any) -> int:
    if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
        return 0
    return int(insn.operands[0].imm)

def _abi_stack_pointer_adjustment(binary: StageABinary, insn: Any) -> int | None:
    if len(insn.operands) < 2:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic not in {"add", "sub"}:
        return None
    dst, src = insn.operands[:2]
    if dst.type != X86_OP_REG or src.type != X86_OP_IMM:
        return None
    stack_register = "esp" if binary.bitness == 32 else "rsp"
    if insn.reg_name(dst.reg) != stack_register:
        return None
    value = int(src.imm)
    return value if mnemonic == "add" else -value

def _abi_argument_source(binary: StageABinary, insn: Any, register_definitions: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    if not insn.operands:
        return {"kind": "unknown", "instruction": _instruction_report(binary, insn)}
    return _abi_attach_register_definition(
        _abi_operand_argument_source(binary, insn, insn.operands[0], register_definitions),
        register_definitions,
    )

def _abi_stack_argument_write_source(
    binary: StageABinary,
    insn: Any,
    offset: int,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if len(insn.operands) < 2:
        source = {"kind": "unknown", "instruction": _instruction_report(binary, insn)}
    else:
        source = _abi_attach_register_definition(
            _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions),
            register_definitions,
        )
    source["stack_offset"] = offset
    source["stack_write"] = _instruction_report(binary, insn)
    return source

def _abi_operand_argument_source(
    binary: StageABinary,
    insn: Any,
    operand: Any,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if str(insn.mnemonic) == "lea" and operand.type == X86_OP_MEM:
        addressing = _abi_mem_operand_report(insn, operand)
        return {
            "kind": "address",
            "addressing": addressing,
            "address_class": _abi_address_class(addressing),
            "instruction": _instruction_report(binary, insn),
        }
    if operand.type == X86_OP_IMM:
        source = {"kind": "immediate", "value": int(operand.imm), "instruction": _instruction_report(binary, insn)}
        _abi_attach_immediate_literal(binary, source)
        return source
    if operand.type == X86_OP_REG:
        return {"kind": "register", "register": insn.reg_name(operand.reg), "instruction": _instruction_report(binary, insn)}
    if operand.type == X86_OP_MEM:
        addressing = _abi_mem_operand_report(insn, operand)
        source: dict[str, Any] = {"kind": "memory", "addressing": addressing, "instruction": _instruction_report(binary, insn)}
        memory_rva = _abi_absolute_addressing_rva(binary, addressing)
        if memory_rva is not None:
            source["memory_rva"] = memory_rva
            section = _section_for_rva(binary, memory_rva)
            if section is not None:
                source["memory_section"] = _abi_section_report(section)
            string_literal = _abi_string_literal_at_rva(binary, memory_rva)
            if string_literal is not None:
                source["string_literal"] = string_literal
            imported = _import_for_thunk_rva(binary, memory_rva)
            if imported is not None:
                source["import"] = _abi_import_report(imported)
        base = addressing.get("base")
        if isinstance(base, str) and isinstance(register_definitions, dict):
            base_definition = register_definitions.get(base)
            if isinstance(base_definition, dict):
                source["base_register_definition"] = base_definition
        source["memory_role"] = _abi_memory_role(source)
        return source
    return {"kind": "unknown", "instruction": _instruction_report(binary, insn)}

def _abi_attach_immediate_literal(binary: StageABinary, source: dict[str, Any]) -> None:
    value = _safe_int(source.get("value"))
    if value is None:
        return
    rva = _abi_value_to_rva(binary, value)
    if rva is None:
        return
    source["memory_rva"] = rva
    section = _section_for_rva(binary, rva)
    if section is not None:
        source["memory_section"] = _abi_section_report(section)
    string_literal = _abi_string_literal_at_rva(binary, rva)
    if string_literal is not None:
        source["string_literal"] = string_literal

def _abi_value_to_rva(binary: StageABinary, value: int) -> int | None:
    if binary.image_base <= value < binary.image_base + binary.size_of_image:
        return value - binary.image_base
    if 0 <= value < binary.size_of_image and _section_for_rva(binary, value) is not None:
        return value
    return None

def _abi_string_literal_at_rva(binary: StageABinary, rva: int) -> dict[str, Any] | None:
    section = _section_for_rva(binary, rva)
    if section is None or not section.readable or section.executable:
        return None
    data = binary.pe.get_data(rva, 256)
    if not data:
        return None
    end = data.find(b"\0")
    if end < 0:
        return None
    raw = data[:end]
    if not raw:
        return None
    if any(byte < 0x09 or (0x0E <= byte < 0x20) for byte in raw):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    return {
        "evidence_status": "derived",
        "rva": rva,
        "size": len(raw) + 1,
        "text": text,
        "sha256": sha256_bytes(raw),
    }

def _abi_attach_register_definition(source: dict[str, Any], register_definitions: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    if source.get("kind") != "register" or not isinstance(register_definitions, dict):
        return source
    register = source.get("register")
    definition = register_definitions.get(str(register))
    if isinstance(definition, dict):
        source = dict(source)
        source["register_definition"] = definition
    return source

def _abi_update_register_definitions(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
    written_registers: set[str],
) -> str | None:
    definition = _abi_register_definition(binary, insn, register_definitions)
    defined_register = definition[0] if definition is not None else None
    for register in written_registers:
        if register != defined_register:
            register_definitions.pop(register, None)
    if definition is not None:
        register_definitions[definition[0]] = definition[1]
    return defined_register

def _abi_register_definition(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    if len(insn.operands) < 2:
        return None
    dst = insn.operands[0]
    if dst.type != X86_OP_REG:
        return None
    register = insn.reg_name(dst.reg)
    if not register:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic == "lea":
        source = _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions)
    elif mnemonic == "mov":
        source = _abi_operand_argument_source(binary, insn, insn.operands[1], register_definitions)
        if source.get("kind") == "register":
            copied = register_definitions.get(str(source.get("register")))
            if isinstance(copied, dict):
                source = dict(copied)
                source["copied_from_register"] = insn.reg_name(insn.operands[1].reg)
                source["copied_by"] = _instruction_report(binary, insn)
    else:
        return None
    return str(register), source

def _abi_address_class(addressing: dict[str, Any]) -> str:
    base = str(addressing.get("base") or "")
    if base in {"esp", "ebp", "rsp", "rbp"}:
        return "stack_address"
    return "computed_address"

def _abi_pending_argument_sources(
    pushes: list[dict[str, Any]],
    stack_argument_writes: dict[int, dict[str, Any]],
    *,
    word_size: int,
) -> list[dict[str, Any]]:
    contiguous_offsets: list[int] = []
    expected_offset = 0
    for offset in sorted(offset for offset in stack_argument_writes if offset >= 0):
        if offset < expected_offset:
            continue
        if offset != expected_offset:
            break
        contiguous_offsets.append(offset)
        expected_offset += word_size
    stack_sources = [stack_argument_writes[offset] for offset in reversed(contiguous_offsets)]
    return list(pushes[-8:]) + stack_sources

def _abi_resets_pending_arguments(insn: Any) -> bool:
    mnemonic = str(insn.mnemonic)
    if mnemonic in {"leave", "enter"}:
        return True
    if mnemonic == "mov" and len(insn.operands) == 2:
        dst, src = insn.operands
        if dst.type == X86_OP_REG and src.type == X86_OP_REG:
            dst_name = insn.reg_name(dst.reg)
            src_name = insn.reg_name(src.reg)
            if (dst_name, src_name) in {("ebp", "esp"), ("rbp", "rsp")}:
                return True
    if mnemonic in {"sub", "add", "and", "lea"} and insn.operands:
        dst = insn.operands[0]
        if dst.type == X86_OP_REG and insn.reg_name(dst.reg) in {"esp", "rsp"}:
            return True
    return False

def _abi_stack_argument_write_offset(insn: Any) -> int | None:
    if not insn.operands:
        return None
    mnemonic = str(insn.mnemonic)
    if mnemonic != "mov":
        return None
    dst = insn.operands[0]
    if dst.type != X86_OP_MEM:
        return None
    mem = dst.mem
    base = insn.reg_name(mem.base) if mem.base else None
    index = insn.reg_name(mem.index) if mem.index else None
    if base not in {"esp", "rsp"} or index not in {None, ""}:
        return None
    offset = int(mem.disp)
    if offset < 0:
        return None
    return offset

def _abi_callsite_evidence(
    binary: StageABinary,
    insn: Any,
    block_id: str,
    argument_sources: list[dict[str, Any]],
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target = _abi_call_target(binary, insn, register_definitions)
    symbol = str(target.get("symbol") or "")
    inventory = _abi_call_argument_inventory(binary, argument_sources, register_definitions, target=target)
    varargs = _abi_varargs_evidence(symbol, inventory)
    return {
        "id": f"callsite:{block_id}:{int(insn.address - binary.image_base):x}",
        "block_id": block_id,
        "instruction": _instruction_report(binary, insn),
        "target": target,
        "argument_sources": argument_sources,
        "argument_inventory": inventory,
        "stack_delta": {"status": "unknown"},
        "hidden_sret_or_out_param_evidence": _abi_hidden_sret_evidence(argument_sources),
        "varargs_evidence": varargs,
        "function_pointer_targets": _abi_function_pointer_targets(target),
    }

def _abi_call_target(
    binary: StageABinary,
    insn: Any,
    register_definitions: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target_rva = _resolved_branch_target(binary, insn)
    imported = _import_for_call_instruction(binary, insn)
    if imported is not None:
        return {
            "kind": "import",
            "dll": imported.dll,
            "symbol": imported.symbol,
            "ordinal": imported.ordinal,
            "thunk_rva": imported.thunk_rva,
        }
    if target_rva is not None:
        return {"kind": "direct", "target_rva": target_rva}
    if len(insn.operands) == 1 and insn.operands[0].type in {X86_OP_REG, X86_OP_MEM}:
        operand = insn.operands[0]
        if operand.type == X86_OP_REG:
            register_name = insn.reg_name(insn.operands[0].reg)
            resolved = _abi_register_call_target(binary, register_name, register_definitions)
            if resolved is not None:
                return resolved
        if operand.type == X86_OP_MEM:
            source = _abi_operand_argument_source(binary, insn, operand, register_definitions)
            return _abi_function_pointer_target_from_source(binary, insn.op_str, source)
        return _abi_function_pointer_target_from_source(binary, insn.op_str, None)
    return {"kind": "unknown", "status": "unresolved"}

def _abi_register_call_target(
    binary: StageABinary,
    register_name: str | None,
    register_definitions: dict[str, dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not register_name or not isinstance(register_definitions, dict):
        return None
    definition = register_definitions.get(register_name)
    if not isinstance(definition, dict):
        return None
    imported = definition.get("import") if isinstance(definition.get("import"), dict) else None
    if imported is not None:
        return {
            "kind": "import",
            "dll": imported.get("dll"),
            "symbol": imported.get("symbol"),
            "ordinal": imported.get("ordinal"),
            "thunk_rva": imported.get("thunk_rva"),
            "via_register": register_name,
            "source": definition,
        }
    memory_rva = _safe_int(definition.get("memory_rva"))
    if memory_rva is not None:
        return _abi_function_pointer_target_from_source(binary, register_name, definition)
    if definition.get("kind") == "memory":
        return _abi_function_pointer_target_from_source(binary, register_name, definition)
    return None

def _abi_function_pointer_target_from_source(
    binary: StageABinary,
    operand: str,
    source: dict[str, Any] | None,
) -> dict[str, Any]:
    recoverable_targets = _abi_static_function_pointer_targets(binary, source)
    target: dict[str, Any] = {
        "kind": "function_pointer",
        "operand": operand,
        "recoverable_targets": recoverable_targets,
        "status": "resolved_static_pointer_slot" if recoverable_targets else "unresolved",
    }
    if isinstance(source, dict):
        target["source"] = source
        if source.get("memory_role") not in {None, ""}:
            target["memory_role"] = source.get("memory_role")
        if source.get("memory_rva") not in {None, ""}:
            target["memory_rva"] = source.get("memory_rva")
    return target

def _abi_static_function_pointer_targets(binary: StageABinary, source: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(source, dict):
        return []
    memory_rva = _safe_int(source.get("memory_rva"))
    if memory_rva is None:
        return []
    pointer_size = 8 if binary.bitness == 64 else 4
    raw = binary.pe.get_data(memory_rva, pointer_size)
    if len(raw) != pointer_size:
        return []
    pointer_value = int.from_bytes(raw, "little")
    target_rva = _abi_value_to_rva(binary, pointer_value)
    if target_rva is None:
        return []
    section = _executable_section_for_rva(binary, target_rva)
    if section is None:
        return []
    return [
        {
            "status": "resolved",
            "kind": "direct",
            "target_rva": target_rva,
            "target_va": pointer_value,
            "source": "static_pointer_slot_value",
            "memory_rva": memory_rva,
            "memory_role": source.get("memory_role"),
            "section": _abi_section_report(section),
        }
    ]

def _import_for_call_instruction(binary: StageABinary, insn: Any) -> StageAImport | None:
    if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_MEM:
        return None
    return _import_for_absolute_memory_operand(binary, insn.operands[0])

def _abi_mem_operand_report(insn: Any, operand: Any) -> dict[str, Any]:
    mem = operand.mem
    return {
        "base": insn.reg_name(mem.base) if mem.base else None,
        "index": insn.reg_name(mem.index) if mem.index else None,
        "scale": int(mem.scale),
        "disp": int(mem.disp),
    }

def _abi_section_report(section: StageASection) -> dict[str, Any]:
    return {
        "name": section.name,
        "rva_start": section.rva_start,
        "rva_end": section.rva_end,
        "readable": section.readable,
        "writable": section.writable,
        "executable": section.executable,
    }

def _abi_memory_role(source: dict[str, Any]) -> str:
    if isinstance(source.get("import"), dict):
        return "import_address_table"
    section = source.get("memory_section") if isinstance(source.get("memory_section"), dict) else {}
    if source.get("memory_rva") is not None:
        if section.get("writable") is True:
            return "global_writable_pointer_slot"
        if section:
            return "global_readonly_pointer_slot"
        return "absolute_memory_slot"
    addressing = source.get("addressing") if isinstance(source.get("addressing"), dict) else {}
    base = str(addressing.get("base") or "")
    if base in {"ebp", "rbp"}:
        disp = _safe_int(addressing.get("disp")) or 0
        return "stack_argument_slot" if disp >= 0 else "stack_local_slot"
    if base in {"esp", "rsp"}:
        return "stack_pointer_slot"
    base_definition = source.get("base_register_definition") if isinstance(source.get("base_register_definition"), dict) else None
    if base_definition is not None:
        base_role = str(base_definition.get("memory_role") or "")
        if base_role == "stack_argument_slot":
            return "argument_pointer_deref"
        if base_definition.get("memory_rva") is not None:
            return "global_pointer_deref"
        return "computed_pointer_deref"
    return "computed_memory"

def _abi_hidden_sret_evidence(argument_sources: list[dict[str, Any]]) -> dict[str, Any]:
    if not argument_sources:
        return {"status": "unknown", "reason": "no_static_arguments"}
    first = argument_sources[-1]
    address_source = _abi_address_like_argument_source(first)
    if address_source is not None:
        return {
            "status": "candidate",
            "source": first,
            "address_source": address_source,
            "address_role": _abi_address_argument_role(address_source),
            "reason": "first_stack_argument_has_address_provenance",
        }
    if first.get("kind") == "register":
        return {"status": "unknown", "reason": "first_stack_argument_register_without_address_provenance"}
    return {"status": "unknown", "reason": "first_stack_argument_not_address_like"}

def _abi_address_like_argument_source(source: dict[str, Any]) -> dict[str, Any] | None:
    if source.get("kind") == "address":
        return source
    definition = source.get("register_definition") if isinstance(source.get("register_definition"), dict) else None
    if definition is not None and definition.get("kind") == "address":
        return definition
    return None

def _abi_address_argument_role(address_source: dict[str, Any]) -> str:
    if address_source.get("address_class") == "stack_address":
        return "stack_out_param_or_scratch_buffer"
    return "computed_out_param_or_hidden_sret"

def _abi_call_argument_inventory(
    binary: StageABinary,
    argument_sources: list[dict[str, Any]],
    register_definitions: dict[str, dict[str, Any]] | None,
    *,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered_stack_args = list(reversed(argument_sources))
    fixed_stack_arg_count = _abi_fixed_stack_arg_count_for_target(target, binary)
    if fixed_stack_arg_count is not None:
        ordered_stack_args = ordered_stack_args[:fixed_stack_arg_count]
    stack_args = [
        {
            "index": index,
            "source": source,
            "role": _abi_argument_role(source),
        }
        for index, source in enumerate(ordered_stack_args)
        if isinstance(source, dict)
    ]
    register_args = []
    for register in _abi_call_register_argument_order(binary, target):
        definition = register_definitions.get(register) if isinstance(register_definitions, dict) else None
        if isinstance(definition, dict):
            register_args.append({"register": register, "source": definition, "role": _abi_argument_role(definition)})
    calling_convention = "cdecl_or_stdcall_stack" if binary.bitness == 32 else "x86_64_mixed"
    register_argument_evidence = _abi_register_argument_evidence(binary, target, register_args)
    if binary.bitness == 32 and register_args:
        calling_convention = "x86_register_carried_internal"
    return {
        "evidence_status": "derived",
        "stack_args": stack_args,
        "register_args": register_args,
        "argument_count": len(stack_args) + len(register_args),
        "calling_convention": calling_convention,
        "register_argument_evidence": register_argument_evidence,
    }

def _abi_fixed_stack_arg_count_for_target(target: dict[str, Any] | None, binary: StageABinary) -> int | None:
    if binary.bitness != 32 or not isinstance(target, dict) or target.get("kind") != "import":
        return None
    symbol = target.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        return None
    decorated = re.search(r"@([0-9]+)$", symbol)
    if decorated is not None:
        byte_count = _safe_int(decorated.group(1))
        return byte_count // 4 if byte_count is not None and byte_count >= 0 else None
    return ABI_FIXED_STDCALL_IMPORT_STACK_ARG_COUNTS.get(symbol.lower().lstrip("_"))

def _abi_call_register_argument_order(binary: StageABinary, target: dict[str, Any] | None = None) -> tuple[str, ...]:
    if binary.bitness == 64:
        return ("rcx", "rdx", "r8", "r9")
    if binary.bitness == 32:
        return _abi_x86_direct_target_register_argument_order(binary, target)
    return ()

def _abi_x86_direct_target_register_argument_order(
    binary: StageABinary,
    target: dict[str, Any] | None,
) -> tuple[str, ...]:
    if not isinstance(target, dict) or target.get("kind") != "direct":
        return ()
    target_rva = _safe_int(target.get("target_rva"))
    if target_rva is None:
        return ()
    read_registers = _abi_x86_entry_read_before_write_registers(binary, target_rva)
    order = ("eax", "edx", "ecx")
    return tuple(register for register in order if register in read_registers)

def _abi_x86_entry_read_before_write_registers(binary: StageABinary, target_rva: int) -> set[str]:
    section = _section_for_rva(binary, target_rva)
    if section is None or not section.executable:
        return set()
    size = min(128, max(0, section.rva_end - target_rva))
    if size <= 0:
        return set()
    data = binary.pe.get_data(target_rva, size)
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    read_before_write: set[str] = set()
    written: set[str] = set()
    candidates = {"eax", "edx", "ecx"}
    for insn in dis.disasm(data, binary.image_base + target_rva):
        mnemonic = str(insn.mnemonic)
        if mnemonic == "call" or mnemonic in {"jmp", "ljmp", "ret"} or _is_conditional_jump(mnemonic):
            break
        reads, writes = _instruction_register_access(insn)
        zeroed = _abi_x86_zero_idiom_register(insn)
        if zeroed is not None:
            reads.discard(zeroed)
        for register in sorted(candidates & reads):
            if register not in written:
                read_before_write.add(register)
        written.update(candidates & writes)
    return read_before_write

def _abi_x86_zero_idiom_register(insn: Any) -> str | None:
    if str(insn.mnemonic) != "xor" or len(getattr(insn, "operands", []) or []) != 2:
        return None
    left, right = insn.operands[:2]
    if left.type != X86_OP_REG or right.type != X86_OP_REG or left.reg != right.reg:
        return None
    register = insn.reg_name(left.reg)
    return str(register) if register in {"eax", "edx", "ecx"} else None

def _abi_register_argument_evidence(
    binary: StageABinary,
    target: dict[str, Any] | None,
    register_args: list[dict[str, Any]],
) -> dict[str, Any]:
    if not register_args:
        return {"status": "not_observed"}
    evidence: dict[str, Any] = {
        "status": "derived",
        "registers": [arg.get("register") for arg in register_args if isinstance(arg, dict)],
    }
    if binary.bitness == 32 and isinstance(target, dict) and target.get("kind") == "direct":
        evidence["source"] = "direct_target_entry_read_before_write"
        evidence["target_rva"] = target.get("target_rva")
    elif binary.bitness == 64:
        evidence["source"] = "platform_abi_register_order"
    return evidence

def _abi_argument_role(source: dict[str, Any]) -> str:
    if source.get("string_literal") is not None:
        return "string_literal"
    if source.get("kind") == "address":
        return _abi_address_argument_role(source)
    if source.get("kind") == "memory":
        return str(source.get("memory_role") or "memory")
    definition = source.get("register_definition") if isinstance(source.get("register_definition"), dict) else None
    if definition is not None:
        return _abi_argument_role(definition)
    return str(source.get("kind") or "unknown")

def _abi_varargs_evidence(symbol: str, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    lower = symbol.lower()
    if any(token in lower for token in ("printf", "fprintf", "sprintf", "scanf", "execl")):
        evidence: dict[str, Any] = {
            "status": "candidate",
            "evidence_status": "candidate",
            "reason": "known_variadic_symbol",
        }
        if isinstance(inventory, dict):
            evidence["format_string"] = _abi_format_string_evidence(lower, inventory)
        return evidence
    return {"status": "not_observed"}

def _abi_format_string_evidence(symbol: str, inventory: dict[str, Any]) -> dict[str, Any]:
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    fixed_count = _abi_variadic_fixed_arg_count(symbol)
    format_arg = stack_args[fixed_count - 1] if fixed_count > 0 and len(stack_args) >= fixed_count else None
    if not isinstance(format_arg, dict):
        return {
            "status": "incomplete",
            "fixed_arg_count": fixed_count,
            "reason": "format_argument_not_recovered",
        }
    source = format_arg.get("source") if isinstance(format_arg.get("source"), dict) else {}
    literal = source.get("string_literal") if isinstance(source.get("string_literal"), dict) else None
    if literal is None:
        return {
            "status": "incomplete",
            "fixed_arg_count": fixed_count,
            "format_arg_index": fixed_count - 1,
            "source": source,
            "reason": "format_argument_is_not_a_static_string_literal",
        }
    text = str(literal.get("text") or "")
    conversions = _abi_printf_conversions(text)
    return {
        "status": "derived",
        "fixed_arg_count": fixed_count,
        "format_arg_index": fixed_count - 1,
        "literal": literal,
        "conversions": conversions,
        "required_varargs": len(conversions),
        "observed_varargs": max(0, len(stack_args) - fixed_count),
        "missing_varargs": max(0, len(conversions) - max(0, len(stack_args) - fixed_count)),
    }

def _abi_variadic_fixed_arg_count(symbol: str) -> int:
    lower = symbol.lower()
    if "fprintf" in lower or "sprintf" in lower or "snprintf" in lower:
        return 2
    return 1

def _abi_printf_conversions(format_text: str) -> list[dict[str, Any]]:
    conversions: list[dict[str, Any]] = []
    index = 0
    length = len(format_text)
    while index < length:
        if format_text[index] != "%":
            index += 1
            continue
        start = index
        index += 1
        if index < length and format_text[index] == "%":
            index += 1
            continue
        while index < length and format_text[index] in "-+ #0'":
            index += 1
        while index < length and (format_text[index].isdigit() or format_text[index] == "*"):
            if format_text[index] == "*":
                conversions.append({"offset": start, "specifier": "*", "kind": "dynamic_width"})
            index += 1
        if index < length and format_text[index] == ".":
            index += 1
            while index < length and (format_text[index].isdigit() or format_text[index] == "*"):
                if format_text[index] == "*":
                    conversions.append({"offset": start, "specifier": "*", "kind": "dynamic_precision"})
                index += 1
        while index < length and format_text[index] in "hljztL":
            index += 1
        if index < length:
            specifier = format_text[index]
            if specifier not in "n":
                conversions.append({"offset": start, "specifier": specifier, "kind": "value"})
            index += 1
    return conversions

def _abi_function_pointer_targets(target: dict[str, Any]) -> list[dict[str, Any]]:
    if target.get("kind") != "function_pointer":
        return []
    item: dict[str, Any] = {"status": target.get("status") or "unresolved", "operand": target.get("operand")}
    for key in ("memory_rva", "memory_role", "source", "recoverable_targets"):
        if key in target:
            item[key] = target[key]
    return [item]

def _abi_import_prototypes(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "dll": item.dll,
            "symbol": item.symbol,
            "ordinal": item.ordinal,
            "thunk_rva": item.thunk_rva,
            "calling_convention": "stdcall" if item.symbol and "@" in item.symbol else "unknown",
            "varargs_evidence": _abi_varargs_evidence(item.symbol or "", None),
        }
        for item in binary.imports
    ]

def _abi_import_report(item: StageAImport) -> dict[str, Any]:
    return {
        "dll": item.dll,
        "symbol": item.symbol,
        "ordinal": item.ordinal,
        "thunk_rva": item.thunk_rva,
    }

def _abi_absolute_addressing_rva(binary: StageABinary, addressing: dict[str, Any]) -> int | None:
    if addressing.get("base") or addressing.get("index"):
        return None
    address = _safe_int(addressing.get("disp"))
    if address is None:
        return None
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None

def _stage_a_abi_profile_comparison_gaps(comparison_gaps: dict[str, Any]) -> dict[str, Any]:
    function_mismatches = [
        item
        for item in comparison_gaps.get("function_mismatches", [])
        if isinstance(item, dict) and _stage_a_abi_profile_function_mismatch_is_hard(item)
    ]
    callsite_mismatches = [
        item for item in comparison_gaps.get("callsite_mismatches", []) if isinstance(item, dict)
    ]
    incomplete_callsites = [
        item for item in comparison_gaps.get("incomplete_callsites", []) if isinstance(item, dict)
    ]
    missing_functions = [
        item for item in comparison_gaps.get("missing_functions", []) if isinstance(item, dict)
    ]
    ambiguous_functions = [
        item for item in comparison_gaps.get("ambiguous_functions", []) if isinstance(item, dict)
    ]
    return {
        "missing_functions": missing_functions,
        "ambiguous_functions": ambiguous_functions,
        "incomplete_callsites": incomplete_callsites,
        "function_mismatches": function_mismatches,
        "callsite_mismatches": callsite_mismatches,
        "counts": {
            "missing_functions": len(missing_functions),
            "ambiguous_functions": len(ambiguous_functions),
            "incomplete_callsite_functions": len(incomplete_callsites),
            "missing_callsites": sum(int(item.get("missing_callsites") or 0) for item in incomplete_callsites),
            "function_mismatches": len(function_mismatches),
            "callsite_mismatches": len(callsite_mismatches),
        },
    }

def _stage_a_abi_profile_function_mismatch_is_hard(mismatch: dict[str, Any]) -> bool:
    issues = mismatch.get("issues") if isinstance(mismatch.get("issues"), list) else []
    categories = {str(item.get("category") or "") for item in issues if isinstance(item, dict)}
    return bool(categories & STAGE_A_ABI_PROFILE_FUNCTION_MISMATCH_CATEGORIES)

__all__ = [
    '_ABI_ADDRESS_LIKE_ARGUMENT_ROLES',
    '_ABI_BY_VALUE_ARGUMENT_ROLES',
    '_abi_absolute_addressing_rva',
    '_abi_address_argument_role',
    '_abi_address_class',
    '_abi_address_like_argument_source',
    '_abi_apply_direct_callee_import_memory_effects',
    '_abi_apply_predecessor_argument_sources',
    '_abi_apply_predecessor_switch_bounds',
    '_abi_argument_inventory_signature',
    '_abi_argument_role',
    '_abi_argument_source',
    '_abi_attach_immediate_literal',
    '_abi_attach_register_definition',
    '_abi_block_contract_evidence',
    '_abi_block_evidence',
    '_abi_block_is_import_thunk',
    '_abi_call_argument_inventory',
    '_abi_call_register_argument_order',
    '_abi_call_target',
    '_abi_callsite_contract_signature',
    '_abi_callsite_evidence',
    '_abi_callsite_gap_sample',
    '_abi_callsite_record_index',
    '_abi_callsite_signature_groups',
    '_abi_callsite_signature_record',
    '_abi_callsite_target_contract_signature',
    '_abi_callsite_with_argument_sources',
    '_abi_capstone_block_instructions',
    '_abi_cluster_contracts',
    '_abi_cmp_register_immediate_upper_bound',
    '_abi_compare_immediate_selector',
    '_abi_composed_direct_callee_memory_access',
    '_abi_decode_block_instructions',
    '_abi_direct_compare_dispatch_contracts',
    '_abi_direct_control_transfers',
    '_abi_direct_refptr_transfers',
    '_abi_effective_preserved_registers',
    '_abi_evidence_by_block',
    '_abi_evidence_by_function',
    '_abi_field_access_report',
    '_abi_filter_function_local_loop_hints',
    '_abi_fixed_stack_arg_count_for_target',
    '_abi_format_string_evidence',
    '_abi_function_evidence',
    '_abi_function_gap_sample',
    '_abi_function_local_loop_hint_count',
    '_abi_function_local_loop_hints',
    '_abi_function_pointer_target_from_source',
    '_abi_function_pointer_targets',
    '_abi_function_range_index',
    '_abi_function_stack_delta_summary',
    '_abi_functions',
    '_abi_hidden_sret_contract_signature',
    '_abi_hidden_sret_evidence',
    '_abi_import_equivalent_signature',
    '_abi_import_prototypes',
    '_abi_import_prototypes_by_match_key',
    '_abi_import_report',
    '_abi_incomplete_indexed_jump_table_contract',
    '_abi_indexed_jump_table_contract',
    '_abi_instruction_is_semantic_noop',
    '_abi_instruction_memory_accesses',
    '_abi_intersect_switch_bounds',
    '_abi_jump_table_index_bounds',
    '_abi_list_count',
    '_abi_loop_hint_is_function_local',
    '_abi_loop_hint_key',
    '_abi_loop_hints',
    '_abi_mem_operand_report',
    '_abi_memory_access_is_import_effect',
    '_abi_memory_access_report',
    '_abi_memory_effect_summary',
    '_abi_memory_role',
    '_abi_next_conditional_branch',
    '_abi_operand_argument_source',
    '_abi_operand_memory_access_kind',
    '_abi_operand_register_name',
    '_abi_pending_argument_sources',
    '_abi_predecessor_edge_switch_bounds',
    '_abi_preserved_candidate_is_identity_noop',
    '_abi_printf_conversions',
    '_abi_refptr_direct_transfer',
    '_abi_register_argument_evidence',
    '_abi_register_call_target',
    '_abi_register_definition',
    '_abi_register_definition_is_identity_noop',
    '_abi_register_out_param_candidates',
    '_abi_reparent_composed_memory_access',
    '_abi_resets_pending_arguments',
    '_abi_resolve_predecessor_argument_target',
    '_abi_ret_imm',
    '_abi_section_report',
    '_abi_stack_argument_signature',
    '_abi_stack_argument_write_offset',
    '_abi_stack_argument_write_source',
    '_abi_stack_pointer_adjustment',
    '_abi_static_function_pointer_targets',
    '_abi_string_literal_at_rva',
    '_abi_switch_bounds_dict',
    '_abi_switch_contract_is_resolved_refptr',
    '_abi_switch_contracts',
    '_abi_target_import_signature',
    '_abi_target_signature',
    '_abi_target_signature_with_resolution',
    '_abi_unmatched_callsite_signature_items',
    '_abi_update_register_definitions',
    '_abi_value_to_rva',
    '_abi_varargs_contract_signature',
    '_abi_varargs_evidence',
    '_abi_variadic_fixed_arg_count',
    '_abi_x86_direct_target_register_argument_order',
    '_abi_x86_entry_read_before_write_registers',
    '_abi_x86_register_family',
    '_abi_x86_zero_idiom_register',
    '_block_id_for_instruction',
    '_candidate_abi_block_mappings_from_functions',
    '_candidate_abi_constraint_from_functions',
    '_candidate_reference_section_gap_abi_mappings',
    '_candidate_reference_section_gap_anchor_mapping',
    '_candidate_reference_section_gap_owner_context',
    '_candidate_reference_section_gap_owner_offset_mapping',
    '_candidate_reference_section_gap_owner_ranges',
    '_cluster_contract',
    '_contract_candidate_abi_alias_sample',
    '_contract_candidate_abi_argument_inventory_issue',
    '_contract_candidate_abi_argument_inventory_match',
    '_contract_candidate_abi_argument_role_match',
    '_contract_candidate_abi_best_candidate',
    '_contract_candidate_abi_callsite_mismatch',
    '_contract_candidate_abi_callsite_pair_score',
    '_contract_candidate_abi_callsite_pairs',
    '_contract_candidate_abi_callsite_signature_delta',
    '_contract_candidate_abi_candidates',
    '_contract_candidate_abi_coverage_gaps',
    '_contract_candidate_abi_expected_candidate_names',
    '_contract_candidate_abi_function_mismatch',
    '_contract_candidate_abi_import_targets_match',
    '_contract_candidate_abi_memory_summary_issue',
    '_contract_candidate_abi_mismatch_next_action',
    '_contract_candidate_abi_mismatch_repair_class',
    '_contract_candidate_abi_reference_inventory_underconstrained',
    '_contract_candidate_abi_register_roles_match',
    '_contract_candidate_abi_resolved_targets_match',
    '_contract_candidate_abi_stack_role_match',
    '_contract_candidate_abi_stack_roles_match',
    '_contract_candidate_abi_status',
    '_contract_candidate_abi_target_match',
    '_contract_candidate_abi_varargs_issue',
    '_contract_candidate_argument_pointer_out_param_coverage_count',
    '_contract_candidate_decision_tree_switch_coverage_count',
    '_contract_candidate_function_symbol_names',
    '_contract_candidate_memory_gap_is_refptr_direct_transfer',
    '_contract_candidate_refptr_direct_transfer_coverage_count',
    '_contract_candidate_symbol_keys',
    '_contract_constraint',
    '_count_by',
    '_dedupe_strings',
    '_empty_contract_candidate_alias_evidence',
    '_import_for_call_instruction',
    '_instruction_register_access',
    '_memory_role_covering_candidates',
    '_missing_counted_memory_roles',
    '_nested_dict',
    '_optional_contract_int',
    '_safe_gap_part',
    '_safe_int',
    '_stage_a_abi_profile_comparison_gaps',
    '_stage_a_abi_profile_function_mismatch_is_hard',
]
