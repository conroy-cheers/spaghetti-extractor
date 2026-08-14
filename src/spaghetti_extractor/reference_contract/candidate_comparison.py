"""Candidate-only contract validation, audit, and repair feedback."""

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
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
)

from .map_analysis import (
    _linker_function_match_key,
)

from .abi_candidate import (
    _candidate_abi_constraint_from_functions,
)
from .abi_comparison import (
    _contract_candidate_abi_coverage_gaps,
    _contract_candidate_abi_status,
)
from .abi_support import (
    _contract_candidate_function_symbol_names,
    _contract_candidate_symbol_keys,
    _contract_constraint,
    _count_by,
    _dedupe_strings,
    _empty_contract_candidate_alias_evidence,
    _safe_gap_part,
    _safe_int,
)

from .reference_contract import (
    _contract_candidate_validation_artifact,
    _contract_candidate_validation_summary,
    _load_contract_candidate_validation,
    stage_a_smoke_contract,
)
from .reference_diagnostics import (
    _load_reference_contract_sidecars,
)
from .reference_semantics import (
    _semantic_disassemble_block,
)
from .reference_sidecars import (
    _reference_sidecar_contract_ref,
)
from .reference_units import (
    _load_reference_unit_contract_sidecars,
    _matching_unit_contracts,
    _reference_unit_contract_artifact,
    _semantic_coverage_blockers,
    _semantic_coverage_counts,
    _semantic_coverage_families,
    _semantic_coverage_next_work,
)
from .reference_utils import (
    _binary_reference_layout,
    _gap_severity_rank,
    _load_json,
    _matches_focus,
    _reference_input_artifact,
)

def _contract_candidate_families(
    contract: dict[str, Any],
    candidate: StageABinary,
    candidate_functions: list[dict[str, Any]],
    *,
    alias_evidence: dict[str, Any] | None = None,
    candidate_rva_anchors: dict[int, int] | None = None,
) -> list[dict[str, Any]]:
    alias_evidence = alias_evidence or _empty_contract_candidate_alias_evidence()
    original = contract.get("original") if isinstance(contract.get("original"), dict) else {}
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    contract_families = {str(item.get("family")): item for item in contract.get("families", []) if isinstance(item, dict)}
    candidate_function_names = _contract_candidate_function_names(candidate_functions)
    function_contract = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    expected_functions = [
        item for item in function_contract.get("functions", []) if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    alias_matches = alias_evidence.get("matches_by_reference") if isinstance(alias_evidence.get("matches_by_reference"), dict) else {}
    alias_ambiguities = alias_evidence.get("ambiguities_by_reference") if isinstance(alias_evidence.get("ambiguities_by_reference"), dict) else {}
    missing_functions = sorted(
        str(item["name"])
        for item in expected_functions
        if str(item["name"]) not in candidate_function_names and str(item["name"]) not in alias_matches
        and str(item["name"]) not in alias_ambiguities
    )
    ambiguous_functions = sorted(str(item["name"]) for item in expected_functions if str(item["name"]) in alias_ambiguities)
    abi_contract = constraints.get("abi_callsites") if isinstance(constraints.get("abi_callsites"), dict) else {}
    candidate_abi = _candidate_abi_constraint_from_functions(
        candidate,
        candidate_functions,
        reference_abi=abi_contract,
        alias_evidence=alias_evidence,
        candidate_rva_anchors=candidate_rva_anchors,
    )
    abi_coverage_gaps = _contract_candidate_abi_coverage_gaps(abi_contract, candidate_abi, alias_evidence=alias_evidence)
    original_imports = _contract_import_signature(original)
    candidate_imports = _contract_import_signature(_binary_reference_layout(candidate))
    missing_function_details = _contract_candidate_missing_function_details(
        missing_functions,
        constraints=constraints,
        candidate_imports=candidate_imports,
        alias_evidence=alias_evidence,
    )
    alias_ambiguity_count = len(ambiguous_functions)
    function_ranges_status = "satisfied" if not missing_functions and not ambiguous_functions and expected_functions else "incomplete"
    abi_status = _contract_candidate_abi_status(abi_contract, candidate_abi)
    expected_binary_signature = _contract_binary_signature(original)
    candidate_binary_signature = _contract_binary_signature(_binary_reference_layout(candidate))
    if alias_ambiguity_count or int(abi_coverage_gaps["counts"].get("missing_functions") or 0) or int(
        abi_coverage_gaps["counts"].get("ambiguous_functions") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("incomplete_callsite_functions") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("function_mismatches") or 0
    ) or int(
        abi_coverage_gaps["counts"].get("callsite_mismatches") or 0
    ):
        abi_status = "incomplete"
    families = [
        _contract_candidate_family(
            "binary_faithfulness",
            "satisfied" if expected_binary_signature == candidate_binary_signature else "violated",
            "candidate PE layout/import/image-base target does not match the Stage A reference contract",
            "rebuild the candidate with matching PE target layout, imports, subsystem, and image base",
            contract_families.get("binary_faithfulness"),
            evidence={
                "expected": expected_binary_signature,
                "candidate": candidate_binary_signature,
                "layout_delta": _contract_binary_signature_delta(expected_binary_signature, candidate_binary_signature),
            },
        ),
        _contract_candidate_family(
            "function_ranges",
            function_ranges_status,
            "candidate linker map is missing or ambiguously maps reference-contract functions",
            "add/generate candidate functions, fix source-map aliases, or remove ambiguous linker roots",
            contract_families.get("function_ranges"),
            evidence={
                "expected_count": len(expected_functions),
                "candidate_count": len(candidate_functions),
                "missing_count": len(missing_functions),
                "ambiguous_count": alias_ambiguity_count,
                "missing_functions": missing_functions[:100],
                "missing_function_details": missing_function_details[:100],
                "missing_by_category": _count_by(missing_function_details, "category"),
                "ambiguous_aliases": [_contract_alias_ambiguity_sample(alias_ambiguities[name]) for name in ambiguous_functions[:100]],
                "alias_matches": _contract_alias_match_samples(alias_matches, expected_functions),
                "alias_evidence_status": alias_evidence.get("status"),
                "alias_evidence_counts": alias_evidence.get("counts"),
            },
        ),
        _contract_candidate_family(
            "abi_callsites",
            abi_status,
            "candidate ABI/callsite evidence does not yet cover the reference contract",
            "repair prototypes, sret/out-params, varargs bridges, stack deltas, or register preservation",
            contract_families.get("abi_callsites"),
            evidence={
                "reference_counts": abi_contract.get("counts") if isinstance(abi_contract.get("counts"), dict) else {},
                "candidate_counts": candidate_abi.get("counts"),
                "candidate_abi": candidate_abi,
                "coverage_gaps": abi_coverage_gaps,
                "alias_evidence": _contract_candidate_alias_evidence_summary(alias_evidence),
            },
        ),
        _contract_candidate_family(
            "import_thunks",
            "satisfied" if original_imports == candidate_imports else "incomplete",
            "candidate imports differ from the reference contract",
            "rebuild/link the candidate with matching import thunk/prototype surface",
            contract_families.get("import_thunks"),
            evidence={"expected_imports": original_imports, "candidate_imports": candidate_imports},
        ),
    ]
    return families

def _contract_candidate_family(
    family: str,
    status: str,
    blocker: str,
    next_action: str,
    contract_family: dict[str, Any] | None,
    *,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    contract_status = contract_family.get("status") if isinstance(contract_family, dict) else None
    if contract_status == "violated":
        status = "violated"
    elif contract_status == "incomplete" and status == "satisfied":
        status = "incomplete"
    return {
        "family": family,
        "status": status,
        "contract_status": contract_status,
        "blocker": "" if status in {"satisfied", "not_applicable"} else blocker,
        "next_action": "" if status in {"satisfied", "not_applicable"} else next_action,
        "evidence": evidence,
    }

def _contract_candidate_skeleton_alias_evidence(skeleton: dict[str, Any], candidate_functions: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(skeleton, dict) or skeleton.get("format") != "stage-b-skeleton-v1":
        raise StageAInputError("skeleton manifest must have format stage-b-skeleton-v1")
    source_map = skeleton.get("source_map") if isinstance(skeleton.get("source_map"), dict) else {}
    entries = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    candidate_lookup = _contract_candidate_function_lookup(candidate_functions)
    unresolved: dict[str, list[dict[str, Any]]] = {}
    unmatched: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("function"), str):
            continue
        source_function = str(entry["function"])
        source_aliases = [
            alias
            for alias in entry.get("aliases", [])
            if isinstance(alias, str) and _contract_candidate_source_alias_is_function_name(alias)
        ]
        reference_names = _dedupe_strings(
            [
                name
                for name in [source_function, *source_aliases]
                if _contract_candidate_source_alias_is_function_name(name)
            ]
        )
        if not reference_names:
            continue
        candidate_matches = _contract_candidate_lookup_matches(candidate_lookup, *reference_names)
        if not candidate_matches:
            for name in reference_names:
                unmatched.setdefault(name, []).append(
                    _contract_candidate_source_alias_sample(entry, reference_name=name, source_aliases=source_aliases)
                )
            continue
        if len(candidate_matches) > 1:
            resolved = _contract_candidate_disambiguate_exact_source_match(candidate_matches, source_function)
            if resolved is not None:
                for name in reference_names:
                    unresolved.setdefault(name, []).append(
                        {
                            "reference_name": name,
                            "source_function": source_function,
                            "source_kind": entry.get("source_kind"),
                            "candidate": _contract_candidate_function_sample(resolved),
                            "source_aliases": source_aliases,
                            "resolution": "unique_exact_source_function",
                        }
                    )
                continue
            ambiguity = {
                "reference_names": reference_names,
                "source_function": source_function,
                "reason": "source function resolves to multiple candidate linker-map functions",
                "candidate_matches": [_contract_candidate_function_sample(item) for item in candidate_matches],
            }
            for name in reference_names:
                unresolved.setdefault(name, []).append(ambiguity)
            continue
        candidate_match = candidate_matches[0]
        for name in reference_names:
            unresolved.setdefault(name, []).append(
                {
                    "reference_name": name,
                    "source_function": source_function,
                    "source_kind": entry.get("source_kind"),
                    "candidate": _contract_candidate_function_sample(candidate_match),
                    "source_aliases": source_aliases,
                }
            )

    matches_by_reference: dict[str, dict[str, Any]] = {}
    ambiguities_by_reference: dict[str, list[dict[str, Any]]] = {}
    alias_matches: list[dict[str, Any]] = []
    ambiguities: list[dict[str, Any]] = []
    unmatched_by_reference: dict[str, list[dict[str, Any]]] = {}
    unmatched_aliases: list[dict[str, Any]] = []
    for reference_name, matches in sorted(unresolved.items()):
        unique = _unique_alias_matches(matches)
        if len(unique) == 1 and "candidate" in unique[0]:
            matches_by_reference[reference_name] = unique[0]
            alias_matches.append(unique[0])
        else:
            ambiguities_by_reference[reference_name] = unique
            ambiguities.append({"reference_name": reference_name, "matches": unique[:5], "matches_total": len(unique)})
    for reference_name, matches in sorted(unmatched.items()):
        if reference_name in matches_by_reference or reference_name in ambiguities_by_reference:
            continue
        unique = _unique_alias_matches(matches)
        unmatched_by_reference[reference_name] = unique
        unmatched_aliases.append({"reference_name": reference_name, "matches": unique[:5], "matches_total": len(unique)})

    return {
        "format": "stage-a-contract-candidate-alias-evidence-v1",
        "status": "incomplete" if ambiguities else "satisfied",
        "matches_by_reference": matches_by_reference,
        "ambiguities_by_reference": ambiguities_by_reference,
        "unmatched_by_reference": unmatched_by_reference,
        "alias_matches": alias_matches[:100],
        "ambiguities": ambiguities[:100],
        "unmatched_aliases": unmatched_aliases[:100],
        "counts": {"alias_matches": len(alias_matches), "ambiguities": len(ambiguities), "unmatched_aliases": len(unmatched_aliases)},
    }

def _contract_candidate_function_lookup(candidate_functions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    lookup: dict[str, list[dict[str, Any]]] = {}
    for function in candidate_functions:
        if not isinstance(function, dict):
            continue
        for name in _contract_candidate_function_symbol_names(function):
            for key in _contract_candidate_symbol_keys(name):
                bucket = lookup.setdefault(key, [])
                if function not in bucket:
                    bucket.append(function)
    return lookup

def _contract_candidate_lookup_matches(lookup: dict[str, list[dict[str, Any]]], *source_names: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for source_name in source_names:
        for key in _contract_candidate_symbol_keys(source_name):
            for function in lookup.get(key, []):
                if function not in matches:
                    matches.append(function)
    return matches

def _contract_candidate_disambiguate_exact_source_match(
    candidate_matches: list[dict[str, Any]],
    source_function: str,
) -> dict[str, Any] | None:
    exact = [
        function
        for function in candidate_matches
        if source_function in _contract_candidate_function_symbol_names(function)
    ]
    return exact[0] if len(exact) == 1 else None

def _contract_candidate_function_names(candidate_functions: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for function in candidate_functions:
        for name in _contract_candidate_function_symbol_names(function):
            names.add(name)
    return names

def _contract_candidate_source_alias_is_function_name(name: str) -> bool:
    if not name:
        return False
    # COFF section symbols such as ".text" can appear in linker/source-map
    # alias lists for section-gap ranges. They are layout evidence, not
    # callable function names, and treating them as aliases creates false
    # ambiguities across every range in the section.
    return not name.startswith(".")

def _unique_alias_matches(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in matches:
        candidate = match.get("candidate") if isinstance(match.get("candidate"), dict) else {}
        key = json.dumps(
            {
                "reference_name": match.get("reference_name"),
                "source_function": match.get("source_function"),
                "candidate_name": candidate.get("name"),
                "candidate_rva_start": candidate.get("rva_start"),
                "candidate_rva_end": candidate.get("rva_end"),
                "reason": match.get("reason"),
                "source_kind": match.get("source_kind"),
                "source_aliases": match.get("source_aliases"),
                "rva_start": match.get("rva_start"),
                "rva_end": match.get("rva_end"),
                "file": match.get("file"),
                "line_start": match.get("line_start"),
            },
            sort_keys=True,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(match)
    return result

def _contract_candidate_source_alias_sample(
    entry: dict[str, Any],
    *,
    reference_name: str,
    source_aliases: list[str],
) -> dict[str, Any]:
    return {
        "reference_name": reference_name,
        "source_function": entry.get("function"),
        "source_kind": entry.get("source_kind"),
        "source_aliases": source_aliases,
        "rva_start": entry.get("rva_start"),
        "rva_end": entry.get("rva_end"),
        "file": entry.get("file"),
        "line_start": entry.get("line_start"),
        "line_end": entry.get("line_end"),
    }

def _contract_candidate_function_sample(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": function.get("name"),
        "aliases": [alias for alias in function.get("aliases", []) if isinstance(alias, str)] if isinstance(function.get("aliases"), list) else [],
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "section": function.get("section"),
    }

def _contract_alias_match_samples(alias_matches: dict[str, Any], expected_functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_names = {str(item["name"]) for item in expected_functions if isinstance(item.get("name"), str)}
    result = []
    for reference_name in sorted(expected_names & set(alias_matches)):
        match = alias_matches[reference_name]
        if isinstance(match, dict):
            result.append(
                {
                    "reference_name": reference_name,
                    "source_function": match.get("source_function"),
                    "source_kind": match.get("source_kind"),
                    "candidate": match.get("candidate"),
                }
            )
    return result[:100]

def _contract_alias_ambiguity_sample(ambiguities: list[dict[str, Any]]) -> dict[str, Any]:
    return {"matches": ambiguities[:5], "matches_total": len(ambiguities)}

def _contract_candidate_alias_evidence_summary(alias_evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": alias_evidence.get("status"),
        "counts": alias_evidence.get("counts"),
        "alias_matches": alias_evidence.get("alias_matches", [])[:20] if isinstance(alias_evidence.get("alias_matches"), list) else [],
        "ambiguities": alias_evidence.get("ambiguities", [])[:20] if isinstance(alias_evidence.get("ambiguities"), list) else [],
        "unmatched_aliases": alias_evidence.get("unmatched_aliases", [])[:20]
        if isinstance(alias_evidence.get("unmatched_aliases"), list)
        else [],
    }

def _contract_candidate_missing_function_details(
    missing_functions: list[str],
    *,
    constraints: dict[str, Any],
    candidate_imports: list[dict[str, Any]],
    alias_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    unmatched = alias_evidence.get("unmatched_by_reference") if isinstance(alias_evidence.get("unmatched_by_reference"), dict) else {}
    reference_import_thunks = _contract_reference_import_thunks_by_function(constraints)
    details: list[dict[str, Any]] = []
    for function_name in missing_functions:
        source_entries = unmatched.get(function_name) if isinstance(unmatched.get(function_name), list) else []
        source_evidence = source_entries[0] if source_entries and isinstance(source_entries[0], dict) else None
        import_thunk = reference_import_thunks.get(function_name)
        candidate_import_match = _contract_candidate_matching_import(import_thunk, candidate_imports)
        category = _contract_candidate_missing_function_category(
            function_name,
            source_evidence=source_evidence,
            reference_import_thunk=import_thunk,
            candidate_import_match=candidate_import_match,
        )
        item: dict[str, Any] = {
            "function": function_name,
            "category": category,
            "severity": "blocking",
            "next_action": _contract_candidate_missing_function_next_action(function_name, category),
        }
        if source_evidence is not None:
            item["source_evidence"] = source_evidence
        if import_thunk is not None:
            item["reference_import_thunk"] = import_thunk
        if candidate_import_match is not None:
            item["candidate_import_match"] = candidate_import_match
        details.append(item)
    return details

def _contract_reference_import_thunks_by_function(constraints: dict[str, Any]) -> dict[str, dict[str, Any]]:
    import_contract = constraints.get("import_thunks") if isinstance(constraints.get("import_thunks"), dict) else {}
    mapped = import_contract.get("mapped_import_thunks") if isinstance(import_contract.get("mapped_import_thunks"), list) else []
    result: dict[str, dict[str, Any]] = {}
    for item in mapped:
        if not isinstance(item, dict):
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        function_name = source.get("function")
        if not isinstance(function_name, str) or not function_name:
            continue
        result.setdefault(
            function_name,
            {
                "id": item.get("id"),
                "function": function_name,
                "function_match_key": _linker_function_match_key(function_name),
                "source_kind": source.get("kind"),
                "import_signature": source.get("import_signature") if isinstance(source.get("import_signature"), dict) else None,
                "original": item.get("original") if isinstance(item.get("original"), dict) else None,
                "candidate": item.get("candidate") if isinstance(item.get("candidate"), dict) else None,
            },
        )
    return result

def _contract_candidate_matching_import(
    reference_import_thunk: dict[str, Any] | None,
    candidate_imports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if not isinstance(reference_import_thunk, dict):
        return None
    signature = reference_import_thunk.get("import_signature")
    if not isinstance(signature, dict):
        return None
    for imported in candidate_imports:
        if not isinstance(imported, dict):
            continue
        if _contract_import_signature_dict_key(imported) == _contract_import_signature_dict_key(signature):
            return imported
    return None

def _contract_import_signature_dict_key(imported: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(imported.get("dll") or "").lower(),
        str(imported.get("symbol") or ""),
        str(imported.get("ordinal") or ""),
    )

def _contract_candidate_missing_function_category(
    function_name: str,
    *,
    source_evidence: dict[str, Any] | None,
    reference_import_thunk: dict[str, Any] | None,
    candidate_import_match: dict[str, Any] | None,
) -> str:
    source_kind = source_evidence.get("source_kind") if isinstance(source_evidence, dict) else None
    if source_kind == "omitted_import_thunk" or reference_import_thunk is not None:
        if candidate_import_match is not None:
            return "import_thunk_symbol_missing_with_matching_import"
        return "import_thunk_symbol_missing"
    if source_kind == "omitted_runtime_entry":
        return "runtime_entry_replaced_by_generated_bridge"
    if source_kind == "generated_contract_placeholder":
        return "generated_contract_placeholder_missing"
    if function_name.startswith("section-gap-"):
        return "section_gap_or_padding_missing"
    if source_evidence is not None:
        return "source_map_alias_unresolved"
    return "function_missing"

def _contract_candidate_missing_function_next_action(function_name: str, category: str) -> str:
    if category == "import_thunk_symbol_missing_with_matching_import":
        return (
            f"preserve the original import thunk symbol for {function_name} or add a strict Stage A import-thunk "
            "representation mapping that proves the matching candidate import is equivalent"
        )
    if category == "import_thunk_symbol_missing":
        return f"restore or map the import thunk for {function_name} and ensure the candidate imports the same target"
    if category == "runtime_entry_replaced_by_generated_bridge":
        return f"emit or retain the runtime/CRT entry/support function {function_name}, or prove the generated bridge is equivalent"
    if category == "generated_contract_placeholder_missing":
        return f"replace or root the generated contract placeholder for {function_name} before rerunning Stage A"
    if category == "section_gap_or_padding_missing":
        return f"classify and preserve the executable section span represented by {function_name}"
    if category == "source_map_alias_unresolved":
        return f"root the generated source-map alias for {function_name} so the candidate linker map exposes it"
    return f"generate or retain candidate implementation and linker root for {function_name}"

def _contract_binary_signature(layout: dict[str, Any]) -> dict[str, Any]:
    return {
        "machine": layout.get("machine"),
        "bitness": layout.get("bitness"),
        "subsystem": layout.get("subsystem"),
        "image_base": layout.get("image_base"),
        "entrypoint_rva": layout.get("entrypoint_rva"),
        "sections": _contract_section_signature(layout),
        "imports": _contract_import_signature(layout),
    }

def _contract_binary_signature_delta(expected: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    header: dict[str, dict[str, Any]] = {}
    for key in ("machine", "bitness", "subsystem", "image_base", "entrypoint_rva"):
        if expected.get(key) != candidate.get(key):
            header[key] = {"expected": expected.get(key), "observed": candidate.get(key)}
    return {
        "header": header,
        "sections": _contract_section_signature_delta(
            expected.get("sections") if isinstance(expected.get("sections"), list) else [],
            candidate.get("sections") if isinstance(candidate.get("sections"), list) else [],
        ),
        "imports": _contract_import_signature_delta(
            expected.get("imports") if isinstance(expected.get("imports"), list) else [],
            candidate.get("imports") if isinstance(candidate.get("imports"), list) else [],
        ),
    }

def _contract_section_signature_delta(expected: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> list[dict[str, Any]]:
    expected_by_name = {str(item.get("name") or ""): item for item in expected if isinstance(item, dict)}
    candidate_by_name = {str(item.get("name") or ""): item for item in candidate if isinstance(item, dict)}
    deltas: list[dict[str, Any]] = []
    for name in sorted(set(expected_by_name) | set(candidate_by_name)):
        expected_section = expected_by_name.get(name)
        candidate_section = candidate_by_name.get(name)
        if expected_section is None:
            deltas.append({"name": name, "status": "extra", "candidate": candidate_section})
            continue
        if candidate_section is None:
            deltas.append({"name": name, "status": "missing", "expected": expected_section})
            continue
        fields: dict[str, dict[str, Any]] = {}
        for key in ("rva_start", "rva_end", "executable", "readable", "writable"):
            if expected_section.get(key) != candidate_section.get(key):
                fields[key] = {"expected": expected_section.get(key), "observed": candidate_section.get(key)}
        expected_size = (_safe_int(expected_section.get("rva_end")) or 0) - (_safe_int(expected_section.get("rva_start")) or 0)
        candidate_size = (_safe_int(candidate_section.get("rva_end")) or 0) - (_safe_int(candidate_section.get("rva_start")) or 0)
        if expected_size != candidate_size:
            fields["size"] = {"expected": expected_size, "observed": candidate_size, "delta": candidate_size - expected_size}
        if fields:
            deltas.append({"name": name, "status": "changed", "delta": fields})
    return deltas

def _contract_import_signature_delta(expected: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    expected_keys = {_contract_import_delta_key(item): item for item in expected if isinstance(item, dict)}
    candidate_keys = {_contract_import_delta_key(item): item for item in candidate if isinstance(item, dict)}
    return {
        "missing": [expected_keys[key] for key in sorted(set(expected_keys) - set(candidate_keys))],
        "extra": [candidate_keys[key] for key in sorted(set(candidate_keys) - set(expected_keys))],
    }

def _contract_import_delta_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (str(item.get("dll") or ""), str(item.get("symbol") or ""), str(item.get("ordinal") or ""))

def _contract_section_signature(layout: dict[str, Any]) -> list[dict[str, Any]]:
    sections = layout.get("sections") if isinstance(layout.get("sections"), list) else []
    result = []
    for item in sections:
        if not isinstance(item, dict):
            continue
        permissions = item.get("permissions") if isinstance(item.get("permissions"), dict) else {}
        result.append(
            {
                "name": item.get("name"),
                "rva_start": item.get("rva_start"),
                "rva_end": item.get("rva_end"),
                "executable": item.get("executable", permissions.get("execute")),
                "readable": item.get("readable", permissions.get("read")),
                "writable": item.get("writable", permissions.get("write")),
            }
        )
    return result

def _contract_import_signature(layout: dict[str, Any]) -> list[dict[str, Any]]:
    imports = layout.get("imports") if isinstance(layout.get("imports"), list) else []
    result = []
    for item in imports:
        if isinstance(item, dict):
            result.append({"dll": item.get("dll"), "symbol": item.get("symbol"), "ordinal": item.get("ordinal")})
        elif isinstance(item, (list, tuple)) and len(item) >= 3:
            result.append({"dll": item[0], "symbol": item[1], "ordinal": item[2]})
    return sorted(result, key=lambda value: (str(value.get("dll")), str(value.get("symbol")), str(value.get("ordinal"))))

def _parse_stage_b_contract_rva_anchors(path: Path, binary: StageABinary) -> dict[int, int]:
    anchors: dict[int, int] = {}
    ambiguous: set[int] = set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = _parse_linker_map_symbol_line(line, binary)
        if parsed is None:
            continue
        candidate_rva, name = parsed
        reference_rva = _stage_b_contract_rva_anchor_reference(name)
        if reference_rva is None:
            continue
        section = _section_for_rva(binary, candidate_rva)
        if section is None or not section.executable:
            continue
        previous = anchors.get(reference_rva)
        if previous is not None and previous != candidate_rva:
            ambiguous.add(reference_rva)
            continue
        anchors[reference_rva] = candidate_rva
    for reference_rva in ambiguous:
        anchors.pop(reference_rva, None)
    return anchors

def _stage_b_contract_rva_anchor_reference(name: str) -> int | None:
    stripped = name.lstrip("_")
    match = re.fullmatch(r"stage_b_contract_rva_([0-9a-fA-F]{8})", stripped)
    if match is None:
        return None
    return int(match.group(1), 16)

__all__ = [
    '_contract_alias_ambiguity_sample',
    '_contract_alias_match_samples',
    '_contract_binary_signature',
    '_contract_binary_signature_delta',
    '_contract_candidate_alias_evidence_summary',
    '_contract_candidate_disambiguate_exact_source_match',
    '_contract_candidate_families',
    '_contract_candidate_family',
    '_contract_candidate_function_lookup',
    '_contract_candidate_function_names',
    '_contract_candidate_function_sample',
    '_contract_candidate_lookup_matches',
    '_contract_candidate_matching_import',
    '_contract_candidate_missing_function_category',
    '_contract_candidate_missing_function_details',
    '_contract_candidate_missing_function_next_action',
    '_contract_candidate_skeleton_alias_evidence',
    '_contract_candidate_source_alias_is_function_name',
    '_contract_candidate_source_alias_sample',
    '_contract_import_delta_key',
    '_contract_import_signature',
    '_contract_import_signature_delta',
    '_contract_import_signature_dict_key',
    '_contract_reference_import_thunks_by_function',
    '_contract_section_signature',
    '_contract_section_signature_delta',
    '_parse_stage_b_contract_rva_anchors',
    '_stage_b_contract_rva_anchor_reference',
    '_unique_alias_matches',
]
