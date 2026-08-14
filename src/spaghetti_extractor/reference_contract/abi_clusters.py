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

from .abi_instruction import (
    _abi_memory_effect_summary,
)

from .abi_support import (
    _block_id_for_instruction,
    _contract_constraint,
    _nested_dict,
    _safe_gap_part,
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

__all__ = [
    '_abi_cluster_contracts',
    '_abi_evidence_by_block',
    '_abi_evidence_by_function',
    '_abi_functions',
    '_cluster_contract',
]
