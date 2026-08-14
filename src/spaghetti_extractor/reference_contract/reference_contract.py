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

from .reference_constraints import (
    _layout_contract_from_mapping_payload,
    _reference_abi_callsites_constraint,
    _reference_constraint_issues,
    _reference_contract_status,
    _reference_import_thunk_constraint,
    _reference_layout_normalization_constraint,
    _reference_map_constraints,
    _reference_pe_layout_constraint,
    _reference_roots_and_jump_tables_with_abi_targets,
)

from .reference_diagnostics import (
    _load_reference_contract_sidecars,
    _stage_a_smoke_contract_issues,
)

from .reference_sidecars import (
    _reference_contract_families,
    _reference_contract_sidecar_paths,
    _reference_sidecar_contract_ref,
    _write_reference_contract_sidecars,
)

from .reference_units import (
    _reference_semantic_contract_payloads,
    _reference_semantic_region_contracts_constraint,
)

from .reference_utils import (
    _binary_reference_layout,
    _gap_severity_rank,
    _load_json,
    _load_optional_json,
    _matches_focus,
    _reference_contract_inputs,
    _reference_input_artifact,
    _tool_versions,
)

def stage_a_export_reference_contract(
    *,
    original: Path,
    out: Path,
    candidate: Path | None = None,
    mapping: Path | None = None,
    layout_contract: Path | None = None,
    sidecar_dir: Path | None = None,
    unit_contract_dir: Path | None = None,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
) -> dict[str, Any]:
    original = Path(original)
    candidate = Path(candidate) if candidate is not None else None
    mapping = Path(mapping) if mapping is not None else None
    layout_contract = Path(layout_contract) if layout_contract is not None else None
    out = Path(out)
    sidecar_dir = Path(sidecar_dir) if sidecar_dir is not None else out.parent
    unit_contract_dir = Path(unit_contract_dir) if unit_contract_dir is not None else sidecar_dir
    out.parent.mkdir(parents=True, exist_ok=True)
    sidecar_dir.mkdir(parents=True, exist_ok=True)
    unit_contract_dir.mkdir(parents=True, exist_ok=True)

    original_bin = _parse_stage_a_pe(original)
    candidate_bin = _parse_stage_a_pe(candidate) if candidate is not None else None
    mapping_payload = _load_optional_json(mapping)
    layout_contract_payload = _load_optional_json(layout_contract)
    if layout_contract_payload is None:
        layout_contract_payload = _layout_contract_from_mapping_payload(mapping_payload, mapping)
    map_contract = _reference_map_constraints(
        original=original_bin,
        candidate=candidate_bin,
        mapping_payload=mapping_payload,
    )
    abi_callsites_constraint = _reference_abi_callsites_constraint(original_bin, candidate_bin, map_contract)
    roots_and_jump_tables_constraint = _reference_roots_and_jump_tables_with_abi_targets(
        map_contract["roots_and_jump_tables"],
        abi_callsites_constraint,
    )
    semantic_region_contracts = _reference_semantic_region_contracts_constraint(
        original_bin,
        map_contract["mappings"],
        abi_callsites_constraint,
    )
    constraints = {
        "pe_sections_imports_relocations_image_base": _reference_pe_layout_constraint(
            original=original_bin,
            candidate=candidate_bin,
            layout_contract=layout_contract_payload,
        ),
        "executable_byte_coverage": map_contract["executable_byte_coverage"],
        "function_ranges": map_contract["function_ranges"],
        "basic_blocks_and_cfg": map_contract["basic_blocks_and_cfg"],
        "roots_and_jump_tables": roots_and_jump_tables_constraint,
        "import_thunks": _reference_import_thunk_constraint(original_bin, candidate_bin, map_contract),
        "abi_callsites": abi_callsites_constraint,
        "semantic_region_contracts": semantic_region_contracts,
        "padding_alignment": map_contract["padding_alignment"],
        "layout_normalization_assumptions": _reference_layout_normalization_constraint(layout_contract_payload),
    }
    issues = [
        *_reference_constraint_issues(constraints),
        *map_contract["issues"],
    ]
    contract = {
        "format": "stage-a-reference-contract-v1",
        "generator": "stage-a-export-reference-contract",
        "generated_at": utc_now(),
        "model": model,
        "status": _reference_contract_status(constraints, issues),
        "tool_versions": _tool_versions(),
        "inputs": _reference_contract_inputs(
            original=original,
            candidate=candidate,
            mapping=mapping,
            layout_contract=layout_contract,
            contract_dir=out.parent,
        ),
        "original": _binary_reference_layout(
            original_bin,
            relative_to=out.parent,
        ),
        "candidate": (
            _binary_reference_layout(candidate_bin, relative_to=out.parent)
            if candidate_bin is not None
            else None
        ),
        "constraints": constraints,
        "families": _reference_contract_families(constraints),
        "coverage": {
            "original": constraints["executable_byte_coverage"].get("original"),
            "candidate": constraints["executable_byte_coverage"].get("candidate"),
        },
        "assumptions": {
            "layout_normalization": constraints["layout_normalization_assumptions"],
            "unchecked": [],
        },
        "issues": issues,
        "counts": {
            "issues": len(issues),
            "functions": len(constraints["function_ranges"].get("functions", [])),
            "basic_blocks": len(constraints["basic_blocks_and_cfg"].get("basic_blocks", [])),
            "cfg_edge_sources": len(constraints["basic_blocks_and_cfg"].get("cfg_edges", [])),
            "abi_callsites": constraints["abi_callsites"].get("counts", {}).get("callsites", 0),
            "reconstruction_gaps": len(issues),
        },
        "sidecars": _reference_contract_sidecar_paths(sidecar_dir, out.parent, unit_contract_dir=unit_contract_dir),
    }
    # Sidecar rows bind the completed public contract, so materialize it before
    # computing their reference_contract.sha256 fields.
    write_json(out, contract)
    semantic_payload = _reference_semantic_contract_payloads(
        original_bin,
        map_contract["mappings"],
        contract,
        _reference_sidecar_contract_ref(out, relative_to=unit_contract_dir),
    )
    _write_reference_contract_sidecars(
        contract,
        out,
        sidecar_dir,
        unit_contract_dir=unit_contract_dir,
        semantic_payload=semantic_payload,
    )
    return contract

def stage_a_smoke_contract(*, reference_contract: Path, out: Path | None = None) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    issues = _stage_a_smoke_contract_issues(contract, reference_contract)
    result = {
        "format": "stage-a-contract-smoke-v1",
        "status": "qualified" if not issues else "incomplete",
        "reference_contract": _reference_input_artifact(reference_contract),
        "issues": issues,
        "counts": {"issues": len(issues)},
    }
    if out is not None:
        write_json(Path(out), result)
    return result

def _contract_candidate_validation_summary(validation: dict[str, Any]) -> dict[str, Any]:
    families = [item for item in validation.get("families", []) if isinstance(item, dict)]
    return {
        "format": validation.get("format"),
        "status": validation.get("status") or validation.get("verdict"),
        "verdict": validation.get("verdict") or validation.get("status"),
        "model": validation.get("model"),
        "counts": validation.get("counts", {}),
        "family_statuses": _count_by(families, "status"),
    }

def _contract_candidate_validation_artifact(value: dict[str, Any] | Path | None) -> dict[str, Any] | None:
    if value is None or isinstance(value, dict):
        return None
    path = Path(value)
    return _reference_input_artifact(path) if path.is_file() else {"path": str(path), "exists": False}

def _load_contract_candidate_validation(value: dict[str, Any] | Path | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        payload = value
    else:
        payload = _load_json(Path(value))
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-candidate-contract-check-v2":
        raise StageAInputError("candidate contract check must have format stage-b-candidate-contract-check-v2")
    return payload

def stage_a_explain_obligations(*, reference_contract: Path, focus: str, out: Path | None = None) -> dict[str, Any]:
    reference_contract = Path(reference_contract)
    contract = _load_json(reference_contract)
    sidecars = _load_reference_contract_sidecars(contract, reference_contract)
    focus_lower = focus.lower()
    gaps = [
        item
        for item in sidecars.get("coverage_gaps", {}).get("gaps", [])
        if _matches_focus(item, focus_lower)
    ]
    families = [
        item
        for item in contract.get("families", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    result = {
        "format": "stage-a-contract-explanation-v1",
        "status": "qualified" if gaps or families else "incomplete",
        "focus": focus,
        "reference_contract": _reference_input_artifact(reference_contract),
        "families": families,
        "gaps": gaps,
        "counts": {"families": len(families), "gaps": len(gaps)},
    }
    if out is not None:
        write_json(Path(out), result)
    return result

def stage_a_diff_obligations(*, before: Path, after: Path, out: Path | None = None) -> dict[str, Any]:
    before = Path(before)
    after = Path(after)
    before_contract = _load_json(before)
    after_contract = _load_json(after)
    before_sidecars = _load_reference_contract_sidecars(before_contract, before)
    after_sidecars = _load_reference_contract_sidecars(after_contract, after)
    before_gaps = {
        str(item.get("gap_id")): item
        for item in before_sidecars.get("coverage_gaps", {}).get("gaps", [])
        if isinstance(item, dict) and item.get("gap_id")
    }
    after_gaps = {
        str(item.get("gap_id")): item
        for item in after_sidecars.get("coverage_gaps", {}).get("gaps", [])
        if isinstance(item, dict) and item.get("gap_id")
    }
    before_ids = set(before_gaps)
    after_ids = set(after_gaps)
    unchanged_ids = before_ids & after_ids
    regressed_ids = [
        gap_id
        for gap_id in unchanged_ids
        if _gap_severity_rank(after_gaps[gap_id].get("severity")) > _gap_severity_rank(before_gaps[gap_id].get("severity"))
    ]
    result = {
        "format": "stage-a-contract-diff-v1",
        "status": "qualified",
        "before": _reference_input_artifact(before),
        "after": _reference_input_artifact(after),
        "resolved": [before_gaps[gap_id] for gap_id in sorted(before_ids - after_ids)],
        "new": [after_gaps[gap_id] for gap_id in sorted(after_ids - before_ids)],
        "regressed": [after_gaps[gap_id] for gap_id in sorted(regressed_ids)],
        "unchanged": [after_gaps[gap_id] for gap_id in sorted(unchanged_ids)],
    }
    result["counts"] = {
        "resolved": len(result["resolved"]),
        "new": len(result["new"]),
        "regressed": len(result["regressed"]),
        "unchanged": len(result["unchanged"]),
    }
    if out is not None:
        write_json(Path(out), result)
    return result

__all__ = [
    '_contract_candidate_validation_artifact',
    '_contract_candidate_validation_summary',
    '_load_contract_candidate_validation',
    'stage_a_diff_obligations',
    'stage_a_explain_obligations',
    'stage_a_export_reference_contract',
    'stage_a_smoke_contract',
]
