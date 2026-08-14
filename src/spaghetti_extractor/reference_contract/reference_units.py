"""Reference-contract generation, sidecars, and obligation diagnostics."""

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
    BlockMapping,
    NonCodeWaiver,
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
    _mapping_source,
    _range_report,
)

from .map_analysis import (
    _capstone_mode,
    _generated_map_issues,
    _import_signature,
    _layout_issues,
    _section_compatibility_signature,
    _section_permission_signature,
    _section_rva_start_signature,
)
from .map_analysis import (
    _direct_cfg_edges,
    _gaps,
    _instruction_report,
)
from .map_verification import (
    _parse_block_map,
    _verify_waiver_side,
    _waiver_obligations,
)

from .abi import (
    _abi_function_evidence,
)
from .abi_arguments import (
    _abi_import_prototypes,
)
from .abi_clusters import (
    _abi_cluster_contracts,
    _abi_evidence_by_block,
    _abi_evidence_by_function,
    _abi_functions,
    _cluster_contract,
)
from .abi_comparison import (
    _contract_candidate_abi_coverage_gaps,
)
from .abi_profile import (
    _stage_a_abi_profile_comparison_gaps,
)
from .abi_support import (
    _block_id_for_instruction,
    _contract_constraint,
    _count_by,
    _safe_gap_part,
    _safe_int,
)

from .symbolic_execution import (
    _import_z3,
    _symbolic_execute,
    _symbolic_incomplete,
)
from .symbolic_expressions import (
    _expr_json,
)

from .reference_gaps import (
    _gap_family_rank,
    _reference_contract_gap_items,
)

from .reference_semantics import (
    _semantic_call_summary_contracts,
    _semantic_memory_frame_contracts,
    _semantic_transfer_contracts,
)

from .reference_utils import (
    _gap_severity_rank,
    _load_json,
    _matches_focus,
    _proof_family_status,
    _reference_unit_contract_paths,
)

def _reference_semantic_contract_payloads(
    original: StageABinary,
    mappings: list[BlockMapping],
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
) -> dict[str, Any]:
    transfer_contracts = _semantic_transfer_contracts(original, mappings, contract_ref)
    memory_frames = _semantic_memory_frame_contracts(contract, contract_ref)
    call_summaries = _semantic_call_summary_contracts(contract, contract_ref)
    cluster_contracts = _semantic_cluster_contracts(contract, contract_ref)
    semantic_region_contracts = _reference_semantic_region_unit_contracts(contract, contract_ref)
    return {
        "semantic_transfer_contracts": transfer_contracts,
        "semantic_region_contracts": semantic_region_contracts,
        "memory_frame_contracts": memory_frames,
        "call_summary_contracts": call_summaries,
        "cluster_semantic_contracts": cluster_contracts,
    }

def _fallback_reference_semantic_contract_payloads(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "semantic_transfer_contracts": [],
        "semantic_region_contracts": _reference_semantic_region_unit_contracts(contract, contract_ref),
        "memory_frame_contracts": _semantic_memory_frame_contracts(contract, contract_ref),
        "call_summary_contracts": _semantic_call_summary_contracts(contract, contract_ref),
        "cluster_semantic_contracts": _semantic_cluster_contracts(contract, contract_ref),
    }

def _reference_semantic_region_contracts_constraint(
    binary: StageABinary,
    mappings: list[BlockMapping],
    abi_constraint: dict[str, Any],
) -> dict[str, Any]:
    return {
        "format": "stage-a-semantic-region-contracts-v1",
        "status": "not_applicable",
        "evidence_kind": "not-yet-derived",
        "regions": [],
        "counts": {"regions": 0, "checked": 0, "incomplete": 0},
    }

def _reference_semantic_region_unit_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    constraint = _contract_constraint(contract, "semantic_region_contracts")
    rows = []
    for region in constraint.get("regions", []) if isinstance(constraint.get("regions"), list) else []:
        if not isinstance(region, dict):
            continue
        row = dict(region)
        row["reference_contract"] = contract_ref
        rows.append(row)
    return sorted(rows, key=lambda item: str(item.get("id") or ""))

def _semantic_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for cluster in _reference_cluster_contracts(contract, contract_ref):
        if not isinstance(cluster, dict):
            continue
        status, blocker, next_action = _semantic_cluster_status(cluster)
        rows.append(
            {
                "format": "stage-a-cluster-semantic-contract-v1",
                "id": f"semantic-{cluster.get('id')}",
                "unit_kind": "semantic_cluster",
                "status": status,
                "reference_contract": contract_ref,
                "function": cluster.get("function"),
                "block_id": cluster.get("block_id"),
                "cluster_kind": cluster.get("cluster_kind"),
                "repair_class": cluster.get("repair_class"),
                "source_cluster_id": cluster.get("id"),
                "blocker": blocker,
                "next_action": next_action,
                "source_cluster": cluster,
                "acceptance": "guidance cluster only; candidate static and behavioral validation remain required",
            }
        )
    return sorted(rows, key=lambda item: str(item.get("id") or ""))

def _semantic_cluster_status(cluster: dict[str, Any]) -> tuple[str, str | None, str]:
    kind = str(cluster.get("cluster_kind") or "")
    evidence = cluster.get("evidence") if isinstance(cluster.get("evidence"), dict) else {}
    if kind == "recoverable_function_pointer_target":
        return (
            "complete",
            None,
            "preserve this indirect call as an explicit target-expression boundary unless a finite target set is later recovered",
        )
    if kind == "abi_switch_or_jump_table_candidate":
        switch = evidence.get("switch_contract") if isinstance(evidence.get("switch_contract"), dict) else {}
        if switch.get("table_bounds") and switch.get("case_targets"):
            return ("complete", None, "represent this switch dispatch with the recovered selector, bounds, cases, and default edge")
        return (
            "complete",
            None,
            "preserve this dispatch as an indirect-jump contract with the recovered index expression until source switch bounds are recovered",
        )
    if kind == "abi_loop_backedge_candidate":
        return (
            "complete",
            None,
            "preserve this loop as low-level CFG backedges; source-level loop-carried summaries are optional refinement",
        )
    if kind == "abi_varargs_callsite":
        varargs = evidence.get("varargs_evidence") if isinstance(evidence.get("varargs_evidence"), dict) else {}
        fmt = varargs.get("format_string") if isinstance(varargs.get("format_string"), dict) else {}
        if fmt.get("status") == "incomplete":
            return (
                "incomplete",
                str(fmt.get("reason") or "varargs format-string evidence is incomplete"),
                "recover the format string and observed variadic argument inventory",
            )
    return ("complete", None, str(cluster.get("next_action") or "preserve this semantic cluster in generated C"))

def _reference_unit_contract_payloads(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    *,
    semantic_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    semantic_payload = semantic_payload or _fallback_reference_semantic_contract_payloads(contract, contract_ref)
    block_contracts = _reference_block_contracts(contract, contract_ref)
    function_contracts = _reference_function_contracts(contract, contract_ref, block_contracts)
    cluster_contracts = _reference_cluster_contracts(contract, contract_ref)
    repair_units = _reference_repair_units_sidecar(
        contract,
        contract_ref,
        block_contracts,
        function_contracts,
        cluster_contracts,
        semantic_payload=semantic_payload,
    )
    return {
        "block_contracts": block_contracts,
        "function_contracts": function_contracts,
        "cluster_contracts": cluster_contracts,
        "repair_units": repair_units,
        "semantic_transfer_contracts": semantic_payload["semantic_transfer_contracts"],
        "semantic_region_contracts": semantic_payload.get("semantic_region_contracts", []),
        "memory_frame_contracts": semantic_payload["memory_frame_contracts"],
        "call_summary_contracts": semantic_payload["call_summary_contracts"],
        "cluster_semantic_contracts": semantic_payload["cluster_semantic_contracts"],
    }

def _reference_block_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    cfg = _contract_constraint(contract, "basic_blocks_and_cfg")
    blocks = cfg.get("basic_blocks") if isinstance(cfg.get("basic_blocks"), list) else []
    cfg_by_block = {
        str(item.get("block_id")): item
        for item in cfg.get("cfg_edges", [])
        if isinstance(item, dict) and item.get("block_id")
    }
    abi_by_block = _abi_evidence_by_block(contract)
    functions_by_block = _function_names_by_block(contract)
    result = []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_id = str(block.get("id") or "")
        function_name = str(block.get("function") or functions_by_block.get(block_id) or "")
        abi = abi_by_block.get(block_id, {})
        result.append(
            {
                "format": "stage-a-block-contract-v1",
                "id": f"block:{_safe_gap_part(block_id)}",
                "unit_kind": "basic_block",
                "status": "specified" if block.get("kind") == "code" else "non_code",
                "reference_contract": contract_ref,
                "function": function_name or None,
                "block_id": block_id,
                "kind": block.get("kind"),
                "reachable": block.get("reachable"),
                "original": block.get("original") if isinstance(block.get("original"), dict) else {},
                "candidate": block.get("candidate") if isinstance(block.get("candidate"), dict) else {},
                "byte_contract": {
                    "proof_rule": block.get("proof_rule"),
                    "byte_identical": block.get("byte_identical"),
                    "source_kind": block.get("source_kind"),
                },
                "cfg": _block_cfg_contract(block_id, cfg_by_block),
                "state_contract": {
                    "register_reads": abi.get("register_reads", []),
                    "register_writes": abi.get("register_writes", []),
                    "preserved_register_candidates": abi.get("preserved_candidates", []),
                    "clobbered_register_candidates": abi.get("clobbered_candidates", []),
                    "stack_delta": abi.get("stack_delta", {"status": "unknown"}),
                    "callsites": abi.get("callsites", []),
                    "register_value_provenance": abi.get("register_value_provenance", []),
                    "register_out_param_candidates": abi.get("register_out_param_candidates", []),
                    "memory_reads": abi.get("memory_reads", []),
                    "memory_writes": abi.get("memory_writes", []),
                    "field_accesses": abi.get("field_accesses", []),
                    "memory_access_summary": abi.get("memory_effect_summary")
                    if isinstance(abi.get("memory_effect_summary"), dict)
                    else _block_memory_access_summary(abi.get("callsites", [])),
                    "switch_contracts": abi.get("switch_contracts", []),
                    "loop_hints": abi.get("loop_hints", []),
                },
                "composition": {
                    "pre_state": "caller-provided machine state constrained by function and predecessor contracts",
                    "post_state": "successor-visible machine state and environment events in state_contract",
                    "acceptance": "informational unit contract only; candidate validation remains required",
                },
            }
        )
    return sorted(result, key=lambda item: (str(item.get("function") or ""), str(item.get("block_id") or "")))

def _reference_function_contracts(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    block_contracts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ranges = _contract_constraint(contract, "function_ranges")
    functions = ranges.get("functions") if isinstance(ranges.get("functions"), list) else []
    abi_by_function = _abi_evidence_by_function(contract)
    blocks_by_function: dict[str, list[dict[str, Any]]] = {}
    for block in block_contracts:
        function_name = str(block.get("function") or "")
        if function_name:
            blocks_by_function.setdefault(function_name, []).append(block)
    result = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        abi = abi_by_function.get(name, {})
        block_rows = blocks_by_function.get(name, [])
        callsites = abi.get("callsites") if isinstance(abi.get("callsites"), list) else []
        result.append(
            {
                "format": "stage-a-function-contract-v1",
                "id": f"function:{_safe_gap_part(name)}",
                "unit_kind": "function",
                "status": _proof_family_status(ranges.get("status")),
                "reference_contract": contract_ref,
                "function": name,
                "aliases": function.get("aliases") if isinstance(function.get("aliases"), list) else [],
                "original": function.get("original") if isinstance(function.get("original"), dict) else {},
                "candidate": function.get("candidate") if isinstance(function.get("candidate"), dict) else {},
                "block_ids": function.get("block_ids") if isinstance(function.get("block_ids"), list) else [row.get("block_id") for row in block_rows],
                "block_contract_ids": [row.get("id") for row in block_rows],
                "abi": {
                    "callsites": callsites,
                    "registers": abi.get("registers") if isinstance(abi.get("registers"), dict) else {},
                    "stack_delta": abi.get("stack_delta", {"status": "unknown"}),
                    "register_value_provenance": abi.get("register_value_provenance", []),
                    "register_out_param_candidates": abi.get("register_out_param_candidates", []),
                    "switch_contracts": abi.get("switch_contracts", []),
                    "decision_tree_contracts": abi.get("decision_tree_contracts", []),
                    "loop_hints": abi.get("loop_hints", []),
                },
                "memory_effect_summary": abi.get("memory_effect_summary")
                if isinstance(abi.get("memory_effect_summary"), dict)
                else {},
                "memory_reads": abi.get("memory_reads", []),
                "memory_writes": abi.get("memory_writes", []),
                "field_accesses": abi.get("field_accesses", []),
                "implementation_spec": {
                    "source_shape": "ugly C is acceptable if the candidate binary satisfies this function contract under Stage A",
                    "next_action": _function_contract_next_action(name, abi),
                },
                "counts": {
                    "blocks": len(block_rows),
                    "callsites": len(callsites),
                },
            }
        )
    return sorted(result, key=lambda item: str(item.get("function") or ""))

def _reference_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    clusters.extend(_abi_cluster_contracts(contract, contract_ref))
    clusters.extend(_import_thunk_cluster_contracts(contract, contract_ref))
    clusters.extend(_jump_target_cluster_contracts(contract, contract_ref))
    clusters.extend(_tls_cluster_contracts(contract, contract_ref))
    return sorted(_dedupe_unit_rows(clusters), key=lambda item: str(item.get("id") or ""))

def _import_thunk_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    thunks = _contract_constraint(contract, "import_thunks").get("mapped_import_thunks")
    result = []
    for thunk in thunks if isinstance(thunks, list) else []:
        if not isinstance(thunk, dict):
            continue
        block_id = str(thunk.get("block_id") or "")
        source = thunk.get("source") if isinstance(thunk.get("source"), dict) else {}
        result.append(
            _cluster_contract(
                contract_ref=contract_ref,
                cluster_id=f"import-thunk:{block_id}",
                cluster_kind="import_thunk",
                function=str(source.get("function") or ""),
                block_id=block_id,
                repair_class="import_prototype_mismatch",
                next_action="preserve the import thunk as an import boundary, not as target-owned C logic",
                evidence={"import_thunk": thunk},
            )
        )
    return result

def _jump_target_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    roots = _contract_constraint(contract, "roots_and_jump_tables")
    targets = roots.get("jump_table_targets") if isinstance(roots.get("jump_table_targets"), list) else []
    result = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        block_id = str(target.get("block_id") or "")
        result.append(
            _cluster_contract(
                contract_ref=contract_ref,
                cluster_id=f"jump-target:{block_id}:{target.get('rva', target.get('target_rva', 'unknown'))}",
                cluster_kind="jump_table_target",
                function=str(target.get("function") or ""),
                block_id=block_id,
                repair_class="jump_table_target",
                next_action="represent this target as a reachable switch/computed-goto destination in generated C",
                evidence={"jump_table_target": target},
            )
        )
    return result

def _tls_cluster_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for function in _contract_constraint(contract, "function_ranges").get("functions", []):
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        if "tls" not in name.lower():
            continue
        result.append(
            _cluster_contract(
                contract_ref=contract_ref,
                cluster_id=f"tls-callback:{name}",
                cluster_kind="tls_or_crt_callback",
                function=name,
                block_id=None,
                repair_class="tls_callback_abi",
                next_action="preserve the callback calling convention, stack cleanup, and CRT ownership boundary",
                evidence={"function": function},
            )
        )
    return result

def _reference_repair_units_sidecar(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
    *,
    semantic_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gaps = _reference_contract_gap_items(contract)
    work_items: list[dict[str, Any]] = []
    for gap in gaps:
        work_items.append(_repair_unit_from_gap(gap, block_contracts, function_contracts, cluster_contracts))
    for cluster in cluster_contracts:
        work_items.append(_repair_unit_from_cluster(cluster))
    if isinstance(semantic_payload, dict):
        work_items.extend(_repair_units_from_semantic_payload(semantic_payload))
    work_items = sorted(_dedupe_unit_rows(work_items), key=lambda item: (_repair_unit_priority(item), str(item.get("id") or "")))
    for index, item in enumerate(work_items, start=1):
        item["rank"] = index
    return {
        "format": "stage-a-repair-units-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "work_items": work_items,
        "counts": {
            "work_items": len(work_items),
            "by_family": _count_by(work_items, "family"),
            "by_repair_class": _count_by(work_items, "repair_class"),
        },
    }

def _repair_units_from_semantic_payload(semantic_payload: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    transfers = semantic_payload.get("semantic_transfer_contracts") if isinstance(semantic_payload.get("semantic_transfer_contracts"), list) else []
    for transfer in transfers:
        if not isinstance(transfer, dict) or transfer.get("status") == "reimplementable":
            continue
        items.append(
            {
                "id": f"work:{_safe_gap_part(str(transfer.get('id') or 'semantic-transfer'))}",
                "unit_kind": "semantic_transfer",
                "family": "semantic_transfer",
                "category": transfer.get("blocker_category") or "semantic_transfer_incomplete",
                "severity": "incomplete",
                "original_function": transfer.get("function"),
                "original_block": transfer.get("block_id"),
                "repair_class": _semantic_repair_class(transfer),
                "expected": "complete per-block transfer contract",
                "observed": transfer.get("status"),
                "cause_hint": transfer.get("blocker"),
                "next_action": transfer.get("next_action")
                or "add instruction semantics, memory-frame facts, or a cluster summary for this block",
                "unit_contract_id": transfer.get("id"),
                "source_semantic_transfer": transfer,
            }
        )
    regions = semantic_payload.get("semantic_region_contracts") if isinstance(semantic_payload.get("semantic_region_contracts"), list) else []
    for region in regions:
        if not isinstance(region, dict) or region.get("status") == "checked":
            continue
        items.append(
            {
                "id": f"work:{_safe_gap_part(str(region.get('id') or 'semantic-region'))}",
                "unit_kind": "semantic_region",
                "family": "semantic_region",
                "category": region.get("blocker_category") or "semantic_region_incomplete",
                "severity": "incomplete",
                "original_function": region.get("function"),
                "original_block": region.get("block_id"),
                "repair_class": "verified_decompiler_region_contract",
                "expected": "checked x86-to-IR-to-C semantic region contract",
                "observed": region.get("status"),
                "cause_hint": region.get("blocker"),
                "next_action": region.get("next_action")
                or "close the selected region contract before lowering it into Stage B C",
                "unit_contract_id": region.get("id"),
                "source_semantic_region": region,
            }
        )
    clusters = semantic_payload.get("cluster_semantic_contracts") if isinstance(semantic_payload.get("cluster_semantic_contracts"), list) else []
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get("status") in {"complete", "reimplementable"}:
            continue
        items.append(
            {
                "id": f"work:{_safe_gap_part(str(cluster.get('id') or 'semantic-cluster'))}",
                "unit_kind": "semantic_cluster",
                "family": "semantic_cluster",
                "category": cluster.get("cluster_kind") or "semantic_cluster_incomplete",
                "severity": "incomplete",
                "original_function": cluster.get("function"),
                "original_block": cluster.get("block_id"),
                "repair_class": cluster.get("repair_class") or _semantic_repair_class(cluster),
                "expected": "complete composable semantic cluster contract",
                "observed": cluster.get("status"),
                "cause_hint": cluster.get("blocker"),
                "next_action": cluster.get("next_action") or "recover the missing semantic facts for this cluster",
                "unit_contract_id": cluster.get("id"),
                "source_semantic_cluster": cluster,
            }
        )
    return items

def _semantic_repair_class(row: dict[str, Any]) -> str:
    text = json.dumps(row, sort_keys=True, default=str).lower()
    if "varargs" in text or "stdio" in text or "printf" in text:
        return "varargs_or_stdio_bridge"
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "switch" in text or "jump_table" in text or "indirect_jump" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text or "backedge" in text or "state_machine" in text:
        return "loop_or_state_machine"
    if "function_pointer" in text or "unknown_target" in text:
        return "function_pointer_target"
    if "memory" in text or "frame" in text or "alias" in text:
        return "memory_effect_mismatch"
    return "semantic_transfer_contract"

def _repair_unit_from_gap(
    gap: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    gap_id = str(gap.get("gap_id") or "gap")
    location = gap.get("location") if isinstance(gap.get("location"), dict) else {}
    function = _function_for_gap(gap, block_contracts, function_contracts, cluster_contracts)
    return {
        "id": f"work:{_safe_gap_part(gap_id)}",
        "unit_kind": "gap",
        "family": gap.get("family"),
        "category": gap.get("category"),
        "severity": gap.get("severity"),
        "original_function": function,
        "original_block": location.get("block_id") or _block_for_gap(gap),
        "repair_class": _repair_class_for_gap(gap),
        "expected": gap.get("expected"),
        "observed": gap.get("observed"),
        "cause_hint": gap.get("cause_hint"),
        "next_action": gap.get("next_action"),
        "source_gap": gap,
    }

def _repair_unit_from_cluster(cluster: dict[str, Any]) -> dict[str, Any]:
    cluster_id = str(cluster.get("id") or "cluster")
    return {
        "id": f"work:{_safe_gap_part(cluster_id)}",
        "unit_kind": "cluster",
        "family": _family_for_cluster(cluster),
        "category": cluster.get("cluster_kind"),
        "severity": "incomplete",
        "original_function": cluster.get("function"),
        "original_block": cluster.get("block_id"),
        "repair_class": cluster.get("repair_class"),
        "expected": "generated source preserves this Stage A evidence cluster",
        "observed": "Stage B has not yet proven a source representation for this cluster",
        "cause_hint": cluster.get("cluster_kind"),
        "next_action": cluster.get("next_action"),
        "unit_contract_id": cluster_id,
        "source_cluster": cluster,
    }

def _repair_unit_priority(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        _gap_family_rank(str(item.get("family") or "")),
        -_gap_severity_rank(item.get("severity")),
        str(item.get("repair_class") or ""),
    )

def _repair_class_for_gap(gap: dict[str, Any]) -> str:
    family = str(gap.get("family") or "")
    category = str(gap.get("category") or "")
    text = f"{family} {category} {gap.get('cause_hint') or ''}".lower()
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "varargs" in text or "printf" in text or "stdio" in text:
        return "varargs_or_stdio_bridge"
    if "switch" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text or "state_machine" in text:
        return "loop_or_state_machine"
    if "jump" in text:
        return "jump_table_target"
    if "import" in text:
        return "import_prototype_mismatch"
    if "register" in text or "clobber" in text or "preserved" in text:
        return "preserved_register_mismatch"
    if family == "executable_span_coverage":
        return "missing_code_or_padding_classification"
    if family == "padding_alignment":
        return "padding_or_alignment_classification"
    if family == "function_ranges":
        return "function_root_or_symbol_mapping"
    return family or category or "stage_a_contract_gap"

def _family_for_cluster(cluster: dict[str, Any]) -> str:
    kind = str(cluster.get("cluster_kind") or "")
    if kind.startswith("abi_") or kind == "recoverable_function_pointer_target":
        return "abi_callsites"
    if kind == "jump_table_target":
        return "roots_and_jump_targets"
    if kind == "import_thunk":
        return "import_thunks"
    return "function_ranges"

def _function_contract_next_action(name: str, abi: dict[str, Any]) -> str:
    text = json.dumps(abi, sort_keys=True, default=str).lower()
    if "varargs" in text or "printf" in text:
        return f"repair {name} callsites with an explicit varargs/stdio bridge and re-run candidate-only delta explanation"
    if "sret" in text or "out_param" in text:
        return f"repair {name} hidden sret/out-param handling and re-run candidate-only delta explanation"
    if "switch_contracts" in text or "decision_tree_contracts" in text:
        return f"repair {name} switch/jump-table or direct decision-tree dispatch coverage before Stage A validation"
    if "tls" in name.lower():
        return f"repair {name} callback ABI and stack cleanup before Stage A validation"
    return f"implement {name} until its function, block, CFG, ABI, and proof-obligation contracts close"

def _block_cfg_contract(block_id: str, cfg_by_block: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = cfg_by_block.get(block_id, {})
    return {
        "status": "specified" if raw else "not_observed",
        "direct_edges": raw,
    }

def _block_memory_access_summary(callsites: Any) -> dict[str, Any]:
    if not isinstance(callsites, list):
        return {"status": "unknown", "argument_memory_sources": 0, "function_pointer_targets": 0}
    argument_memory_sources = 0
    function_pointer_targets = 0
    for callsite in callsites:
        if not isinstance(callsite, dict):
            continue
        for source in callsite.get("argument_sources", []) if isinstance(callsite.get("argument_sources"), list) else []:
            if isinstance(source, dict) and source.get("kind") in {"memory", "address"}:
                argument_memory_sources += 1
        function_pointer_targets += len(callsite.get("function_pointer_targets", [])) if isinstance(callsite.get("function_pointer_targets"), list) else 0
    return {
        "status": "derived",
        "argument_memory_sources": argument_memory_sources,
        "function_pointer_targets": function_pointer_targets,
    }

def _function_names_by_block(contract: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    functions = _contract_constraint(contract, "function_ranges").get("functions")
    for function in functions if isinstance(functions, list) else []:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        for block_id in function.get("block_ids", []) if isinstance(function.get("block_ids"), list) else []:
            result[str(block_id)] = name
    return result

def _function_for_gap(
    gap: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> str | None:
    text = json.dumps(gap, sort_keys=True, default=str).lower()
    for rows in (function_contracts, block_contracts, cluster_contracts):
        for row in rows:
            function = row.get("function")
            if isinstance(function, str) and function and function.lower() in text:
                return function
    return None

def _block_for_gap(gap: dict[str, Any]) -> str | None:
    text = json.dumps(gap, sort_keys=True, default=str)
    match = re.search(r"block[:=]([A-Za-z0-9_.:@+-]+)", text)
    return match.group(1) if match else None

def _dedupe_unit_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        row_id = str(row.get("id") or "")
        if row_id and row_id not in by_id:
            by_id[row_id] = row
    return list(by_id.values())

def _reference_unit_contract_artifact(unit_contracts: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "available",
        "counts": {
            "block_contracts": len(unit_contracts.get("block_contracts", [])) if isinstance(unit_contracts.get("block_contracts"), list) else 0,
            "function_contracts": len(unit_contracts.get("function_contracts", [])) if isinstance(unit_contracts.get("function_contracts"), list) else 0,
            "cluster_contracts": len(unit_contracts.get("cluster_contracts", [])) if isinstance(unit_contracts.get("cluster_contracts"), list) else 0,
            "work_items": len(unit_contracts.get("repair_units", {}).get("work_items", []))
            if isinstance(unit_contracts.get("repair_units"), dict)
            else 0,
            "semantic_transfer_contracts": len(unit_contracts.get("semantic_transfer_contracts", []))
            if isinstance(unit_contracts.get("semantic_transfer_contracts"), list)
            else 0,
            "semantic_region_contracts": len(unit_contracts.get("semantic_region_contracts", []))
            if isinstance(unit_contracts.get("semantic_region_contracts"), list)
            else 0,
            "cluster_semantic_contracts": len(unit_contracts.get("cluster_semantic_contracts", []))
            if isinstance(unit_contracts.get("cluster_semantic_contracts"), list)
            else 0,
            "memory_accesses": len(unit_contracts.get("memory_frame_contracts", {}).get("accesses", []))
            if isinstance(unit_contracts.get("memory_frame_contracts"), dict)
            else 0,
            "call_summaries": len(unit_contracts.get("call_summary_contracts", {}).get("calls", []))
            if isinstance(unit_contracts.get("call_summary_contracts"), dict)
            else 0,
        },
    }

def _semantic_coverage_blockers(unit_contracts: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    transfers = unit_contracts.get("semantic_transfer_contracts") if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else []
    for transfer in transfers:
        if not isinstance(transfer, dict) or transfer.get("status") in {"reimplementable", "complete", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="semantic_transfer",
                category=str(transfer.get("blocker_category") or "transfer_contract_incomplete"),
                function=transfer.get("function"),
                block_id=transfer.get("block_id"),
                source_id=transfer.get("id"),
                blocker=transfer.get("blocker") or "block does not have an implementable transfer contract",
                next_action=transfer.get("next_action") or "add instruction semantics, an invariant, or a checked cluster summary",
                sample=transfer,
            )
        )
    regions = unit_contracts.get("semantic_region_contracts") if isinstance(unit_contracts.get("semantic_region_contracts"), list) else []
    for region in regions:
        if not isinstance(region, dict) or region.get("status") in {"checked", "complete", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="semantic_regions",
                category=str(region.get("blocker_category") or "semantic_region_incomplete"),
                function=region.get("function"),
                block_id=region.get("block_id"),
                source_id=region.get("id"),
                blocker=region.get("blocker") or "semantic region contract is incomplete",
                next_action=region.get("next_action") or "close x86-to-IR and IR-to-C proof obligations for this region",
                sample=region,
            )
        )
    memory = unit_contracts.get("memory_frame_contracts") if isinstance(unit_contracts.get("memory_frame_contracts"), dict) else {}
    for access in memory.get("accesses", []) if isinstance(memory.get("accesses"), list) else []:
        if not isinstance(access, dict):
            continue
        frame_kind = str(access.get("frame_kind") or "unknown")
        status = str(access.get("status") or "")
        if status == "classified" and frame_kind not in {"unknown", "external.unknown"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="memory_frames",
                category="unclassified_memory_access" if frame_kind == "unknown" else "external_unknown_memory_access",
                function=access.get("function"),
                block_id=access.get("block_id"),
                source_id=access.get("id"),
                blocker=access.get("blocker") or f"memory access is classified as {frame_kind}",
                next_action="recover stack/global/object frame and alias facts for this memory access",
                sample=access,
            )
        )
    calls = unit_contracts.get("call_summary_contracts") if isinstance(unit_contracts.get("call_summary_contracts"), dict) else {}
    for call in calls.get("calls", []) if isinstance(calls.get("calls"), list) else []:
        if not isinstance(call, dict) or call.get("status") in {"complete", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="call_summaries",
                category="incomplete_call_summary",
                function=call.get("function"),
                block_id=call.get("block_id"),
                source_id=call.get("id"),
                blocker="; ".join(str(item) for item in call.get("blockers", []) if item) or "call summary is incomplete",
                next_action=call.get("next_action") or "recover call args, target, memory effects, or import boundary facts",
                sample=call,
            )
        )
    clusters = unit_contracts.get("cluster_semantic_contracts") if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else []
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get("status") in {"complete", "reimplementable", "external_boundary_contract"}:
            continue
        blockers.append(
            _semantic_coverage_blocker(
                family="semantic_clusters",
                category=str(cluster.get("cluster_kind") or "incomplete_semantic_cluster"),
                function=cluster.get("function"),
                block_id=cluster.get("block_id"),
                source_id=cluster.get("id"),
                blocker=cluster.get("blocker") or "semantic cluster is incomplete",
                next_action=cluster.get("next_action") or "recover missing cluster facts",
                sample=cluster,
            )
        )
    return sorted(blockers, key=lambda item: (_semantic_coverage_family_rank(str(item.get("family") or "")), str(item.get("id") or "")))

def _semantic_coverage_blocker(
    *,
    family: str,
    category: str,
    function: Any,
    block_id: Any,
    source_id: Any,
    blocker: Any,
    next_action: Any,
    sample: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": f"semantic-blocker:{_safe_gap_part(family)}:{_safe_gap_part(str(source_id or category))}",
        "family": family,
        "category": category,
        "severity": "incomplete",
        "function": str(function) if function not in {None, ""} else None,
        "block_id": str(block_id) if block_id not in {None, ""} else None,
        "source_id": source_id,
        "blocker": str(blocker),
        "next_action": str(next_action),
        "sample": _semantic_coverage_sample(sample),
    }

def _semantic_coverage_sample(sample: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "status",
        "function",
        "block_id",
        "blocker_category",
        "blocker",
        "next_action",
        "cluster_kind",
        "repair_class",
        "frame_kind",
        "target_kind",
        "target",
        "blocking_instruction",
        "original",
        "instruction",
    )
    result = {key: sample.get(key) for key in keys if key in sample}
    if isinstance(sample.get("instructions"), list) and sample["instructions"]:
        result["instruction_preview"] = sample["instructions"][:3]
    return result

def _semantic_coverage_families(unit_contracts: dict[str, Any], blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blocker_counts = _count_by(blockers, "family")
    transfer_count = len(unit_contracts.get("semantic_transfer_contracts", [])) if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else 0
    region_count = len(unit_contracts.get("semantic_region_contracts", [])) if isinstance(unit_contracts.get("semantic_region_contracts"), list) else 0
    memory = unit_contracts.get("memory_frame_contracts") if isinstance(unit_contracts.get("memory_frame_contracts"), dict) else {}
    calls = unit_contracts.get("call_summary_contracts") if isinstance(unit_contracts.get("call_summary_contracts"), dict) else {}
    cluster_count = len(unit_contracts.get("cluster_semantic_contracts", [])) if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else 0
    rows = [
        ("semantic_transfer", transfer_count, "all executable blocks have implementable transfer contracts"),
        ("semantic_regions", region_count, "selected decompiler regions have checked x86-to-IR-to-C contracts"),
        ("memory_frames", len(memory.get("accesses", [])) if isinstance(memory.get("accesses"), list) else 0, "all memory accesses have non-unknown frame/alias classification"),
        ("call_summaries", len(calls.get("calls", [])) if isinstance(calls.get("calls"), list) else 0, "all calls have complete summaries or explicit external boundaries"),
        ("semantic_clusters", cluster_count, "all switch/loop/function-pointer clusters are complete or explicitly external-boundary modeled"),
    ]
    return [
        {
            "family": family,
            "status": "satisfied" if blocker_counts.get(family, 0) == 0 else "incomplete",
            "items": total,
            "analysis_blocked": blocker_counts.get(family, 0),
            "requirement": requirement,
        }
        for family, total, requirement in rows
    ]

def _semantic_coverage_counts(unit_contracts: dict[str, Any], blockers: list[dict[str, Any]]) -> dict[str, Any]:
    transfers = unit_contracts.get("semantic_transfer_contracts") if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else []
    regions = unit_contracts.get("semantic_region_contracts") if isinstance(unit_contracts.get("semantic_region_contracts"), list) else []
    memory = unit_contracts.get("memory_frame_contracts") if isinstance(unit_contracts.get("memory_frame_contracts"), dict) else {}
    calls = unit_contracts.get("call_summary_contracts") if isinstance(unit_contracts.get("call_summary_contracts"), dict) else {}
    clusters = unit_contracts.get("cluster_semantic_contracts") if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else []
    by_category = _count_by(blockers, "category")
    return {
        "semantic_transfer_contracts": len(transfers),
        "implementable_transfer_contracts": sum(1 for item in transfers if isinstance(item, dict) and item.get("status") in {"reimplementable", "complete"}),
        "analysis_blocked_transfers": sum(1 for item in blockers if item.get("family") == "semantic_transfer"),
        "semantic_region_contracts": len(regions),
        "checked_semantic_region_contracts": sum(1 for item in regions if isinstance(item, dict) and item.get("status") in {"checked", "complete"}),
        "analysis_blocked_semantic_regions": sum(1 for item in blockers if item.get("family") == "semantic_regions"),
        "memory_accesses": len(memory.get("accesses", [])) if isinstance(memory.get("accesses"), list) else 0,
        "unclassified_memory_accesses": by_category.get("unclassified_memory_access", 0),
        "external_unknown_memory_accesses": by_category.get("external_unknown_memory_access", 0),
        "call_summaries": len(calls.get("calls", [])) if isinstance(calls.get("calls"), list) else 0,
        "incomplete_call_summaries": sum(1 for item in blockers if item.get("family") == "call_summaries"),
        "cluster_semantic_contracts": len(clusters),
        "incomplete_clusters": sum(1 for item in blockers if item.get("family") == "semantic_clusters"),
        "unsupported_instruction_shapes": by_category.get("unsupported_semantics", 0),
        "analysis_blocked": len(blockers),
        "by_family": _count_by(blockers, "family"),
        "by_category": by_category,
    }

def _semantic_coverage_next_work(blockers: list[dict[str, Any]], *, limit: int = 20) -> list[dict[str, Any]]:
    return [
        {
            "id": blocker.get("id"),
            "family": blocker.get("family"),
            "category": blocker.get("category"),
            "function": blocker.get("function"),
            "block_id": blocker.get("block_id"),
            "blocker": blocker.get("blocker"),
            "next_action": blocker.get("next_action"),
        }
        for blocker in blockers[:limit]
    ]

def _semantic_coverage_family_rank(family: str) -> int:
    order = {
        "semantic_transfer": 0,
        "semantic_regions": 1,
        "memory_frames": 2,
        "call_summaries": 3,
        "semantic_clusters": 4,
    }
    return order.get(family, 99)

def _load_reference_unit_contract_sidecars(
    contract: dict[str, Any],
    contract_path: Path,
    *,
    unit_contract_dir: Path | None,
    contract_ref: dict[str, Any],
) -> dict[str, Any]:
    paths = _reference_unit_contract_paths(_reference_unit_contract_dir(contract, contract_path, unit_contract_dir))
    fallback = _reference_unit_contract_payloads(contract, contract_ref)
    return {
        "block_contracts": _load_jsonl_or(paths["block_contracts"], fallback["block_contracts"]),
        "function_contracts": _load_jsonl_or(paths["function_contracts"], fallback["function_contracts"]),
        "cluster_contracts": _load_jsonl_or(paths["cluster_contracts"], fallback["cluster_contracts"]),
        "repair_units": _load_json_or(paths["repair_units"], fallback["repair_units"]),
        "semantic_transfer_contracts": _load_jsonl_or(paths["semantic_transfer_contracts"], fallback["semantic_transfer_contracts"]),
        "semantic_region_contracts": _load_jsonl_or(paths["semantic_region_contracts"], fallback["semantic_region_contracts"]),
        "memory_frame_contracts": _load_json_or(paths["memory_frame_contracts"], fallback["memory_frame_contracts"]),
        "call_summary_contracts": _load_json_or(paths["call_summary_contracts"], fallback["call_summary_contracts"]),
        "cluster_semantic_contracts": _load_jsonl_or(paths["cluster_semantic_contracts"], fallback["cluster_semantic_contracts"]),
        "paths": {name: str(path) for name, path in paths.items()},
    }

def _reference_unit_contract_dir(contract: dict[str, Any], contract_path: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    unit = sidecars.get("unit_contracts") if isinstance(sidecars.get("unit_contracts"), dict) else {}
    directory = unit.get("directory")
    if isinstance(directory, str) and directory:
        path = Path(directory)
        return path if path.is_absolute() else contract_path.parent / path
    return contract_path.parent

def _load_jsonl_or(path: Path, fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not path.is_file():
        return fallback
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    except (OSError, json.JSONDecodeError):
        return fallback
    return rows

def _load_json_or(path: Path, fallback: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return fallback
    try:
        value = _load_json(path)
    except StageAInputError:
        return fallback
    return value if isinstance(value, dict) else fallback

def _matching_unit_contracts(unit_contracts: dict[str, Any], focus_lower: str) -> list[dict[str, Any]]:
    matches = []
    for name in (
        "block_contracts",
        "function_contracts",
        "cluster_contracts",
        "semantic_transfer_contracts",
        "semantic_region_contracts",
        "cluster_semantic_contracts",
    ):
        for row in unit_contracts.get(name, []) if isinstance(unit_contracts.get(name), list) else []:
            if isinstance(row, dict) and _matches_focus(row, focus_lower):
                matches.append(row)
    for name in ("memory_frame_contracts", "call_summary_contracts"):
        payload = unit_contracts.get(name) if isinstance(unit_contracts.get(name), dict) else {}
        if _matches_focus(payload, focus_lower):
            matches.append(payload)
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    for row in repair_units.get("work_items", []) if isinstance(repair_units.get("work_items"), list) else []:
        if isinstance(row, dict) and _matches_focus(row, focus_lower):
            matches.append(row)
    return matches

__all__ = [
    '_block_cfg_contract',
    '_block_for_gap',
    '_block_memory_access_summary',
    '_dedupe_unit_rows',
    '_fallback_reference_semantic_contract_payloads',
    '_family_for_cluster',
    '_function_contract_next_action',
    '_function_for_gap',
    '_function_names_by_block',
    '_import_thunk_cluster_contracts',
    '_jump_target_cluster_contracts',
    '_load_json_or',
    '_load_jsonl_or',
    '_load_reference_unit_contract_sidecars',
    '_matching_unit_contracts',
    '_reference_block_contracts',
    '_reference_cluster_contracts',
    '_reference_function_contracts',
    '_reference_repair_units_sidecar',
    '_reference_semantic_contract_payloads',
    '_reference_semantic_region_contracts_constraint',
    '_reference_semantic_region_unit_contracts',
    '_reference_unit_contract_artifact',
    '_reference_unit_contract_dir',
    '_reference_unit_contract_payloads',
    '_repair_class_for_gap',
    '_repair_unit_from_cluster',
    '_repair_unit_from_gap',
    '_repair_unit_priority',
    '_repair_units_from_semantic_payload',
    '_semantic_cluster_contracts',
    '_semantic_cluster_status',
    '_semantic_coverage_blocker',
    '_semantic_coverage_blockers',
    '_semantic_coverage_counts',
    '_semantic_coverage_families',
    '_semantic_coverage_family_rank',
    '_semantic_coverage_next_work',
    '_semantic_coverage_sample',
    '_semantic_repair_class',
    '_tls_cluster_contracts',
]
