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
    _abi_x86_register_family,
)

from .abi import (
    _abi_callsite_gap_sample,
    _abi_function_gap_sample,
)

from .abi_support import (
    _abi_function_local_loop_hint_count,
    _contract_candidate_function_symbol_names,
    _contract_candidate_symbol_keys,
    _empty_contract_candidate_alias_evidence,
    _optional_contract_int,
    _safe_int,
)

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

__all__ = [
    '_ABI_ADDRESS_LIKE_ARGUMENT_ROLES',
    '_ABI_BY_VALUE_ARGUMENT_ROLES',
    '_abi_argument_inventory_signature',
    '_abi_block_is_import_thunk',
    '_abi_callsite_contract_signature',
    '_abi_callsite_record_index',
    '_abi_callsite_signature_groups',
    '_abi_callsite_signature_record',
    '_abi_callsite_target_contract_signature',
    '_abi_effective_preserved_registers',
    '_abi_function_range_index',
    '_abi_hidden_sret_contract_signature',
    '_abi_import_equivalent_signature',
    '_abi_import_prototypes_by_match_key',
    '_abi_list_count',
    '_abi_preserved_candidate_is_identity_noop',
    '_abi_register_definition_is_identity_noop',
    '_abi_stack_argument_signature',
    '_abi_switch_contract_is_resolved_refptr',
    '_abi_target_import_signature',
    '_abi_target_signature',
    '_abi_target_signature_with_resolution',
    '_abi_unmatched_callsite_signature_items',
    '_abi_varargs_contract_signature',
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
    '_contract_candidate_memory_gap_is_refptr_direct_transfer',
    '_contract_candidate_refptr_direct_transfer_coverage_count',
    '_memory_role_covering_candidates',
    '_missing_counted_memory_roles',
]
