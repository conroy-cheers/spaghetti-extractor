"""Reference-contract generation and sidecar materialization."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..pe32.stage_binary import _parse_stage_a_pe
from ..util import utc_now, write_json
from .common import REFERENCE_CONTRACT_MODEL_ID

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
    _load_optional_json,
    _reference_contract_inputs,
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

__all__ = [
    'stage_a_export_reference_contract',
]
