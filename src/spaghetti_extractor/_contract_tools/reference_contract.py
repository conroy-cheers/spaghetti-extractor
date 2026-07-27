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
from ..relational.semantic_cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    BlockMapping,
    NonCodeWaiver,
    REFERENCE_CONTRACT_MODEL_ID,
    _incomplete_record,
    _mapping_source,
    _range_report,
)

from .map_generation import (
    _capstone_mode,
    _direct_cfg_edges,
    _gaps,
    _generated_map_issues,
    _import_signature,
    _instruction_report,
    _layout_issues,
    _parse_block_map,
    _section_compatibility_signature,
    _section_permission_signature,
    _section_rva_start_signature,
    _waiver_obligations,
)

from .abi import (
    _abi_cluster_contracts,
    _abi_evidence_by_block,
    _abi_evidence_by_function,
    _abi_function_evidence,
    _abi_functions,
    _abi_import_prototypes,
    _block_id_for_instruction,
    _cluster_contract,
    _contract_candidate_abi_coverage_gaps,
    _contract_constraint,
    _count_by,
    _safe_gap_part,
    _safe_int,
    _stage_a_abi_profile_comparison_gaps,
)

from .symbolic_execution import (
    _expr_json,
    _import_z3,
    _symbolic_execute,
    _symbolic_incomplete,
)

def stage_a_export_reference_contract(
    *,
    original: Path,
    out: Path,
    candidate: Path | None = None,
    mapping: Path | None = None,
    validation_report: Path | None = None,
    layout_contract: Path | None = None,
    sidecar_dir: Path | None = None,
    unit_contract_dir: Path | None = None,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
) -> dict[str, Any]:
    original = Path(original)
    candidate = Path(candidate) if candidate is not None else None
    mapping = Path(mapping) if mapping is not None else None
    validation_report = Path(validation_report) if validation_report is not None else None
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
    validation_payload = _load_stage_a_validation_report(validation_report)
    validation_binding = _reference_validation_report_binding_constraint(
        payload=validation_payload,
        original=original_bin,
        candidate=candidate_bin,
        mapping_payload=mapping_payload,
        model=model,
    )

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
    proof_obligation_inventory = _reference_proof_obligation_inventory(validation_payload)
    proof_obligation_inventory = _reference_proof_obligation_inventory_with_semantic_regions(
        proof_obligation_inventory,
        semantic_region_contracts,
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
        "validation_report_artifact_binding": validation_binding,
        "proof_obligation_inventory": proof_obligation_inventory,
    }
    issues = [
        *_reference_constraint_issues(constraints),
        *validation_binding.get("issues", []),
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
            validation_report=validation_report,
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
            "proof_obligations": constraints["proof_obligation_inventory"].get("counts", {}).get("obligations", 0),
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
        "status": "pass" if not issues else "incomplete",
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
    if not isinstance(payload, dict) or payload.get("format") != "stage-a-contract-candidate-validation-v1":
        raise StageAInputError("contract candidate validation must have format stage-a-contract-candidate-validation-v1")
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
    obligations = [
        item
        for item in sidecars.get("obligation_index", {}).get("obligations", [])
        if _matches_focus(item, focus_lower)
    ]
    families = [
        item
        for item in contract.get("families", [])
        if isinstance(item, dict) and _matches_focus(item, focus_lower)
    ]
    result = {
        "format": "stage-a-obligation-explanation-v1",
        "status": "pass" if gaps or obligations or families else "incomplete",
        "focus": focus,
        "reference_contract": _reference_input_artifact(reference_contract),
        "families": families,
        "gaps": gaps,
        "obligations": obligations,
        "counts": {"families": len(families), "gaps": len(gaps), "obligations": len(obligations)},
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
        "format": "stage-a-obligation-diff-v1",
        "status": "pass",
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

def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid JSON in {path}: {exc}") from exc

def _load_optional_json(path: Path | None) -> Any:
    return None if path is None else _load_json(path)

def _binary_layout(binary: StageABinary) -> dict[str, Any]:
    return {
        "path": str(binary.path),
        "sha256": binary.sha256,
        "size": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "size_of_image": binary.size_of_image,
        "subsystem": binary.subsystem,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "raw_pointer": section.raw_pointer,
                "raw_size": section.raw_size,
                "characteristics": section.characteristics,
                "permissions": {
                    "execute": section.executable,
                    "read": section.readable,
                    "write": section.writable,
                    "code": section.contains_code,
                },
            }
            for section in binary.sections
        ],
        "imports": [
            {
                "dll": item.dll,
                "symbol": item.symbol,
                "ordinal": item.ordinal,
                "thunk_rva": item.thunk_rva,
            }
            for item in binary.imports
        ],
    }

def _binary_reference_layout(
    binary: StageABinary,
    *,
    relative_to: Path | None = None,
) -> dict[str, Any]:
    layout = _binary_layout(binary)
    layout["path"] = _reference_artifact_display_path(
        binary.path,
        relative_to=relative_to,
    )
    layout["relocations"] = _binary_relocation_summary(binary)
    layout["executable_sections"] = [
        {
            "name": section.name,
            "rva_start": section.rva_start,
            "rva_end": section.rva_end,
            "size": section.rva_end - section.rva_start,
        }
        for section in binary.sections
        if section.executable
    ]
    return layout

def _binary_relocation_summary(binary: StageABinary) -> dict[str, Any]:
    directory = binary.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    blocks = []
    entry_count = 0
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        entries = [
            {
                "rva": int(entry.rva),
                "type": int(entry.type),
            }
            for entry in block.entries
        ]
        entry_count += len(entries)
        blocks.append(
            {
                "rva": int(block.struct.VirtualAddress),
                "size": int(block.struct.SizeOfBlock),
                "entries": entries,
            }
        )
    return {
        "status": "present" if blocks else ("empty_directory" if int(directory.Size) == 0 else "not_decoded"),
        "directory": {"rva": int(directory.VirtualAddress), "size": int(directory.Size)},
        "blocks": blocks,
        "counts": {"blocks": len(blocks), "entries": entry_count},
    }

def _reference_contract_inputs(
    *,
    original: Path,
    candidate: Path | None,
    mapping: Path | None,
    validation_report: Path | None,
    layout_contract: Path | None,
    contract_dir: Path,
) -> dict[str, Any]:
    return {
        "original": _reference_input_artifact(original, relative_to=contract_dir),
        "candidate": (
            _reference_input_artifact(candidate, relative_to=contract_dir)
            if candidate is not None
            else None
        ),
        "mapping": (
            _reference_input_artifact(mapping, relative_to=contract_dir)
            if mapping is not None
            else None
        ),
        "validation_report": (
            _reference_validation_report_artifact(
                validation_report,
                relative_to=contract_dir,
            )
            if validation_report is not None
            else None
        ),
        "layout_contract": (
            _reference_input_artifact(
                layout_contract,
                relative_to=contract_dir,
            )
            if layout_contract is not None
            else None
        ),
    }

def _reference_input_artifact(
    path: Path,
    *,
    relative_to: Path | None = None,
) -> dict[str, Any]:
    return {
        "path": _reference_artifact_display_path(path, relative_to=relative_to),
        "sha256": sha256_file(path) if path.is_file() else None,
        "exists": path.exists(),
    }

def _reference_validation_report_artifact(
    path: Path,
    *,
    relative_to: Path | None = None,
) -> dict[str, Any]:
    if path.is_dir():
        files = {}
        for name in (
            "verdict.json",
            "prepared-proof.json",
            "relational-proof-ir.json",
            "relation-contract.json",
            "relational-semantic-ir.json",
            "relational-product-graph.json",
            "whole-program-acceptance.json",
            "composition-progress.json",
        ):
            item = path / name
            if item.is_file():
                files[name] = _reference_input_artifact(
                    item,
                    relative_to=relative_to,
                )
        return {
            "path": _reference_artifact_display_path(
                path,
                relative_to=relative_to,
            ),
            "exists": True,
            "files": files,
        }
    return _reference_input_artifact(path, relative_to=relative_to)

def _reference_artifact_display_path(
    path: Path,
    *,
    relative_to: Path | None,
) -> str:
    path = Path(path)
    if relative_to is None:
        return str(path)
    resolved_path = path.resolve()
    resolved_base = Path(relative_to).resolve()
    if resolved_path == resolved_base or resolved_path.is_relative_to(resolved_base):
        return os.path.relpath(resolved_path, resolved_base)
    return str(path)

_REFERENCE_CONTRACT_FAMILY_KEYS = (
    ("binary_faithfulness", "pe_sections_imports_relocations_image_base"),
    ("executable_span_coverage", "executable_byte_coverage"),
    ("function_ranges", "function_ranges"),
    ("cfg_blocks", "basic_blocks_and_cfg"),
    ("roots_and_jump_targets", "roots_and_jump_tables"),
    ("import_thunks", "import_thunks"),
    ("abi_callsites", "abi_callsites"),
    ("semantic_regions", "semantic_region_contracts"),
    ("padding_alignment", "padding_alignment"),
    ("normalization_assumptions", "layout_normalization_assumptions"),
    ("validation_report_artifact_binding", "validation_report_artifact_binding"),
    ("proof_inventory", "proof_obligation_inventory"),
)

def _reference_contract_sidecar_paths(sidecar_dir: Path, contract_dir: Path, *, unit_contract_dir: Path | None = None) -> dict[str, Any]:
    unit_contract_dir = unit_contract_dir or sidecar_dir

    def display_path(path: Path) -> str:
        if path.parent.resolve() == contract_dir.resolve():
            return path.name
        return str(path)

    unit_paths = _reference_unit_contract_paths(unit_contract_dir)
    return {
        "coverage_gaps": {"path": display_path(sidecar_dir / "coverage_gaps.json")},
        "obligation_index": {"path": display_path(sidecar_dir / "obligation_index.json")},
        "contract_summary": {"path": display_path(sidecar_dir / "contract_summary.json")},
        "abi_callsites": {"path": display_path(sidecar_dir / "abi_callsites.json")},
        "unit_contracts": {
            "directory": "." if unit_contract_dir.resolve() == contract_dir.resolve() else str(unit_contract_dir),
            **{name: {"path": display_path(path)} for name, path in unit_paths.items()},
        },
    }

def _write_reference_contract_sidecars(
    contract: dict[str, Any],
    contract_path: Path,
    sidecar_dir: Path,
    *,
    unit_contract_dir: Path,
    semantic_payload: dict[str, Any] | None = None,
) -> None:
    sidecar_contract_ref = _reference_sidecar_contract_ref(
        contract_path,
        relative_to=sidecar_dir,
    )
    unit_contract_ref = _reference_sidecar_contract_ref(
        contract_path,
        relative_to=unit_contract_dir,
    )
    write_json(
        sidecar_dir / "coverage_gaps.json",
        _reference_coverage_gaps_sidecar(contract, sidecar_contract_ref),
    )
    write_json(
        sidecar_dir / "obligation_index.json",
        _reference_obligation_index_sidecar(contract, sidecar_contract_ref),
    )
    write_json(
        sidecar_dir / "contract_summary.json",
        _reference_contract_summary_sidecar(contract, sidecar_contract_ref),
    )
    write_json(
        sidecar_dir / "abi_callsites.json",
        _reference_abi_callsites_sidecar(contract, sidecar_contract_ref),
    )
    _write_reference_unit_contract_sidecars(
        contract,
        unit_contract_ref,
        unit_contract_dir,
        semantic_payload=semantic_payload,
    )

def _reference_sidecar_contract_ref(
    contract_path: Path,
    *,
    relative_to: Path | None = None,
) -> dict[str, Any]:
    return {
        "path": _reference_artifact_display_path(
            contract_path,
            relative_to=relative_to,
        ),
        "sha256": sha256_file(contract_path) if contract_path.is_file() else None,
        "format": "stage-a-reference-contract-v1",
    }

def _reference_contract_families(constraints: dict[str, Any]) -> list[dict[str, Any]]:
    families = []
    for family, constraint_key in _REFERENCE_CONTRACT_FAMILY_KEYS:
        constraint = constraints.get(constraint_key) if isinstance(constraints.get(constraint_key), dict) else {}
        status = _proof_family_status(constraint.get("status"))
        families.append(
            {
                "family": family,
                "constraint": constraint_key,
                "status": status,
                "raw_status": constraint.get("status"),
                "evidence_kind": constraint.get("evidence_kind"),
                "blocking": status in {"incomplete", "violated"},
                "counts": _reference_family_counts(family, constraint),
            }
        )
    return families

def _proof_family_status(value: Any) -> str:
    status = str(value or "incomplete")
    if status in {"satisfied", "not_applicable"}:
        return status
    if status == "derived":
        return "satisfied"
    if status in {"failed", "fail", "violated"}:
        return "violated"
    return "incomplete"

def _reference_family_counts(family: str, constraint: dict[str, Any]) -> dict[str, int]:
    if family == "function_ranges":
        return {"functions": len(constraint.get("functions", [])) if isinstance(constraint.get("functions"), list) else 0}
    if family == "cfg_blocks":
        return {
            "blocks": len(constraint.get("basic_blocks", [])) if isinstance(constraint.get("basic_blocks"), list) else 0,
            "cfg_edge_sources": len(constraint.get("cfg_edges", [])) if isinstance(constraint.get("cfg_edges"), list) else 0,
        }
    if family == "roots_and_jump_targets":
        return {
            "roots": len(constraint.get("roots", [])) if isinstance(constraint.get("roots"), list) else 0,
            "jump_table_targets": len(constraint.get("jump_table_targets", [])) if isinstance(constraint.get("jump_table_targets"), list) else 0,
        }
    if family == "import_thunks":
        return {
            "original_imports": len(constraint.get("original_imports", [])) if isinstance(constraint.get("original_imports"), list) else 0,
            "mapped_import_thunks": len(constraint.get("mapped_import_thunks", [])) if isinstance(constraint.get("mapped_import_thunks"), list) else 0,
        }
    if family == "abi_callsites":
        counts = constraint.get("counts") if isinstance(constraint.get("counts"), dict) else {}
        return {
            "functions": int(counts.get("functions") or 0),
            "callsites": int(counts.get("callsites") or 0),
            "imports": int(counts.get("import_prototypes") or 0),
        }
    if family == "semantic_regions":
        counts = constraint.get("counts") if isinstance(constraint.get("counts"), dict) else {}
        return {
            "regions": int(counts.get("regions") or 0),
            "checked": int(counts.get("checked") or 0),
            "incomplete": int(counts.get("incomplete") or 0),
        }
    if family == "padding_alignment":
        return {"waivers": len(constraint.get("waivers", [])) if isinstance(constraint.get("waivers"), list) else 0}
    if family == "proof_inventory":
        counts = constraint.get("counts") if isinstance(constraint.get("counts"), dict) else {}
        return {"obligations": int(counts.get("obligations") or 0)}
    return {}

def _reference_coverage_gaps_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    gaps = _reference_contract_gap_items(contract)
    return {
        "format": "stage-a-coverage-gaps-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "status": "pass" if not gaps else "incomplete",
        "gaps": gaps,
        "next_work": _ranked_gap_next_work(gaps),
        "counts": {
            "gaps": len(gaps),
            "by_family": _count_by(gaps, "family"),
            "by_severity": _count_by(gaps, "severity"),
            "by_category": _count_by(gaps, "category"),
        },
    }

def _reference_obligation_index_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    obligations = proof.get("obligations") if isinstance(proof.get("obligations"), list) else []
    indexed = []
    for item in obligations:
        if not isinstance(item, dict):
            continue
        obligation_id = str(item.get("id") or "")
        indexed.append(
            {
                "id": obligation_id,
                "stable_id": f"obligation:{_safe_gap_part(obligation_id)}",
                "kind": str(item.get("kind") or ""),
                "status": str(item.get("status") or ""),
                "proof_rule": item.get("proof_rule"),
                "family": _obligation_family(obligation_id),
                "related_gap_id": f"obligation:{_safe_gap_part(obligation_id)}",
            }
        )
    return {
        "format": "stage-a-obligation-index-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "lean": proof.get("lean") if isinstance(proof.get("lean"), dict) else {},
        "obligations": indexed,
        "counts": {
            "obligations": len(indexed),
            "by_status": _count_by(indexed, "status"),
            "by_kind": _count_by(indexed, "kind"),
            "by_family": _count_by(indexed, "family"),
        },
    }

def _reference_contract_summary_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    families = contract.get("families") if isinstance(contract.get("families"), list) else []
    return {
        "format": "stage-a-contract-summary-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "model": contract.get("model"),
        "families": families,
        "counts": {
            "families": len(families),
            "by_status": _count_by([item for item in families if isinstance(item, dict)], "status"),
            **(contract.get("counts") if isinstance(contract.get("counts"), dict) else {}),
        },
    }

def _reference_abi_callsites_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    abi = _contract_constraint(contract, "abi_callsites")
    return {
        "format": "stage-a-abi-callsites-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "status": _proof_family_status(abi.get("status")),
        "abi_callsites": abi,
        "counts": abi.get("counts") if isinstance(abi.get("counts"), dict) else {},
    }

def _reference_unit_contract_paths(unit_contract_dir: Path) -> dict[str, Path]:
    return {
        "block_contracts": unit_contract_dir / "block-contracts.jsonl",
        "function_contracts": unit_contract_dir / "function-contracts.jsonl",
        "cluster_contracts": unit_contract_dir / "cluster-contracts.jsonl",
        "repair_units": unit_contract_dir / "repair-units.json",
        "source_obligations": unit_contract_dir / "source-obligations.json",
        "semantic_transfer_contracts": unit_contract_dir / "semantic-transfer-contracts.jsonl",
        "semantic_region_contracts": unit_contract_dir / "semantic-region-contracts.jsonl",
        "memory_frame_contracts": unit_contract_dir / "memory-frame-contracts.json",
        "call_summary_contracts": unit_contract_dir / "call-summary-contracts.json",
        "cluster_semantic_contracts": unit_contract_dir / "cluster-semantic-contracts.jsonl",
    }

def _write_reference_unit_contract_sidecars(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    unit_contract_dir: Path,
    *,
    semantic_payload: dict[str, Any] | None = None,
) -> None:
    unit_contract_dir.mkdir(parents=True, exist_ok=True)
    payload = _reference_unit_contract_payloads(contract, contract_ref, semantic_payload=semantic_payload)
    paths = _reference_unit_contract_paths(unit_contract_dir)
    _write_jsonl(paths["block_contracts"], payload["block_contracts"])
    _write_jsonl(paths["function_contracts"], payload["function_contracts"])
    _write_jsonl(paths["cluster_contracts"], payload["cluster_contracts"])
    write_json(paths["repair_units"], payload["repair_units"])
    write_json(paths["source_obligations"], payload["source_obligations"])
    _write_jsonl(paths["semantic_transfer_contracts"], payload["semantic_transfer_contracts"])
    _write_jsonl(paths["semantic_region_contracts"], payload["semantic_region_contracts"])
    write_json(paths["memory_frame_contracts"], payload["memory_frame_contracts"])
    write_json(paths["call_summary_contracts"], payload["call_summary_contracts"])
    _write_jsonl(paths["cluster_semantic_contracts"], payload["cluster_semantic_contracts"])

def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

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
        "evidence_kind": "relational-v3-proof-ir",
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

def _reference_proof_obligation_inventory_with_semantic_regions(
    proof: dict[str, Any],
    semantic_regions: dict[str, Any],
) -> dict[str, Any]:
    obligations = [item for item in proof.get("obligations", []) if isinstance(item, dict)]
    region_obligations = [
        item
        for region in semantic_regions.get("regions", []) if isinstance(region, dict)
        for item in region.get("proof_obligations", []) if isinstance(item, dict)
    ]
    if not region_obligations:
        return proof
    updated = dict(proof)
    updated["obligations"] = [*obligations, *region_obligations]
    counts = dict(updated.get("counts") if isinstance(updated.get("counts"), dict) else {})
    counts["obligations"] = len(updated["obligations"])
    counts["by_status"] = _count_by(updated["obligations"], "status")
    updated["counts"] = counts
    statuses = {str(item.get("status") or "") for item in updated["obligations"]}
    if proof.get("status") == "satisfied" and statuses <= {"proved", "waived_noncode"}:
        updated["status"] = "satisfied"
    elif "failed" in statuses:
        updated["status"] = "failed"
    else:
        updated["status"] = "incomplete"
    return updated

def _semantic_transfer_contracts(
    binary: StageABinary,
    mappings: list[BlockMapping],
    contract_ref: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for mapped in mappings:
        if mapped.kind != "code":
            continue
        source = _mapping_source(mapped)
        function_name = source.get("function") if isinstance(source.get("function"), str) and source.get("function") else mapped.id
        spans = semantic_cutpoint_spans_for_side(
            binary,
            {
                "rva_start": mapped.original.rva_start,
                "rva_end": mapped.original.rva_end,
                "size": mapped.original.size,
            },
            mapped.id,
            periodic=False,
        )
        for cut_index, span in enumerate(spans):
            split = len(spans) > 1
            block_id = (
                f"{mapped.id}~semantic-{cut_index:04d}"
                if split
                else mapped.id
            )
            row = _semantic_transfer_contract(
                binary,
                mapped,
                function_name,
                contract_ref,
                semantic_side=BlockSide(
                    span["rva_start"],
                    span["rva_end"],
                ),
                semantic_block_id=block_id,
            )
            if split:
                row["semantic_cutpoint"] = {
                    "index": cut_index,
                    "parent_block_id": mapped.id,
                    "policy": "formal_stopping_instruction_v1",
                }
            rows.append(row)
    return sorted(rows, key=lambda item: (str(item.get("function") or ""), str(item.get("block_id") or "")))

def _semantic_transfer_contract(
    binary: StageABinary,
    mapped: BlockMapping,
    function_name: str,
    contract_ref: dict[str, Any],
    *,
    semantic_side: BlockSide | None = None,
    semantic_block_id: str | None = None,
) -> dict[str, Any]:
    side = semantic_side or mapped.original
    block_id = semantic_block_id or mapped.id
    data = binary.pe.get_data(side.rva_start, side.size)
    instructions = _semantic_disassemble_block(binary, side, data)
    base_row: dict[str, Any] = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": f"semantic-transfer:{_safe_gap_part(block_id)}",
        "unit_kind": "semantic_transfer",
        "expression_model": "stage-a-semantic-ir-v1",
        "status": "incomplete",
        "reference_contract": contract_ref,
        "function": function_name or None,
        "block_id": block_id,
        "reachable": mapped.reachable,
        "original": _range_report(side),
        "instruction_bytes_sha256": sha256_bytes(data),
        "instructions": instructions,
        "pre_state": _semantic_pre_state(binary),
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "outcome": {"kind": "unknown"},
        "stack_delta": None,
        "fpu_state": None,
        "counts": {
            "register_writes": 0,
            "flag_writes": 0,
            "memory_events": 0,
            "external_events": 0,
            "faults": 0,
            "ordered_events": 0,
            "edge_conditions": 0,
        },
        "acceptance": "guidance contract only; final acceptance requires Stage A binary proof",
    }
    if len(data) != side.size:
        return {
            **base_row,
            "blocker_category": "unreadable_block_bytes",
            "blocker": f"expected {side.size} block bytes, read {len(data)}",
            "next_action": "fix block range or PE section mapping before generating a semantic transfer contract",
        }
    instruction_effect_schedule: dict[str, Any] | None = None
    if _semantic_transfer_inventory_contains_x87(instructions):
        instruction_effect_schedule, symbolic = (
            _semantic_x87_instruction_effect_schedule(
                binary,
                side,
                data,
                instructions,
                mapped,
            )
        )
    else:
        symbolic = _symbolic_execute(binary, side, data, "original", mapped)
    if symbolic.get("status") != "ok":
        instruction = symbolic.get("instruction") if isinstance(symbolic.get("instruction"), dict) else None
        blocked = {
            **base_row,
            "blocker_category": symbolic.get("category") or "unsupported_semantics",
            "blocker": symbolic.get("blocker") or "block is outside the current semantic transfer model",
            "next_action": symbolic.get("next_action") or "add instruction semantics or a checked cluster summary",
            "blocking_instruction": instruction,
        }
        if instruction_effect_schedule is not None:
            blocked["instruction_effect_schedule"] = instruction_effect_schedule
        return blocked
    observables = symbolic.get("observables") if isinstance(symbolic.get("observables"), dict) else {}
    native_exact_command_replay = None
    if instruction_effect_schedule is not None:
        native_exact_command_replay = _semantic_x87_replay_binding(
            binary,
            side,
            data,
            instructions,
            instruction_effect_schedule=instruction_effect_schedule,
        )
    effects = _semantic_effects_from_observables(
        observables,
        ordered_events=symbolic.get("ordered_events"),
        native_exact_command_replay=native_exact_command_replay,
    )
    fpu_state = effects.get("fpu_state")
    if (
        isinstance(fpu_state, dict)
        and fpu_state.get("model") == _X87_REPLAY_OBLIGATION_MODEL
    ):
        return {
            **base_row,
            "blocker_category": "x87_physical_state_requires_native_exact_command_replay",
            "blocker": (
                "legacy symbolic x87 observables do not contain the physical "
                "StageA.X87.PhysicalState required by Stage B"
            ),
            "next_action": (
                "replay each exact x87 singleton with the checked Lean decoder and "
                "executor according to the instruction effect schedule, then export "
                "every physical state field"
            ),
            "instruction_effect_schedule": instruction_effect_schedule,
            **effects,
        }
    return {
        **base_row,
        "status": "reimplementable",
        "blocker_category": None,
        "blocker": None,
        "next_action": "implement this block so the compiled candidate reproduces the transfer contract, then rerun Stage A",
        **effects,
    }

def _semantic_disassemble_block(binary: StageABinary, side: BlockSide, data: bytes) -> list[dict[str, Any]]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    dis.detail = True
    return [_instruction_report(binary, insn) for insn in dis.disasm(data, binary.image_base + side.rva_start)]

def _semantic_pre_state(binary: StageABinary) -> dict[str, Any]:
    registers = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp") if binary.bitness == 32 else ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp")
    flags = ("cf", "zf", "sf", "of", "pf", "df")
    return {
        "registers": {name: _semantic_expr_json(("reg", name)) for name in registers},
        "flags": {name: _semantic_expr_json(("flag", name)) for name in flags},
        "memory": {"op": "memory", "name": "mem0", "address_width": binary.bitness, "value_width": 8},
    }

def _semantic_effects_from_observables(
    observables: dict[str, Any],
    *,
    ordered_events: Any = None,
    native_exact_command_replay: dict[str, Any] | None = None,
) -> dict[str, Any]:
    register_writes = []
    flag_writes = []
    for key, value in sorted(observables.items()):
        if key.startswith("reg:"):
            name = key.split(":", 1)[1]
            if value != ("reg", name):
                register_writes.append({"register": name, "value": _semantic_expr_json(value)})
        elif key.startswith("flag:"):
            name = key.split(":", 1)[1]
            if value != ("flag", name):
                flag_writes.append({"flag": name, "value": _semantic_expr_json(value)})
    memory_events = [_semantic_memory_event_json(event) for event in observables.get("memory_events", [])]
    external_events = [_semantic_external_event_json(event) for event in observables.get("external_events", [])]
    faults = [_semantic_fault_json(fault) for fault in observables.get("fault_conditions", [])]
    ordered = [
        _semantic_ordered_event_json(event)
        for event in (ordered_events if isinstance(ordered_events, (list, tuple)) else ())
    ]
    outcome = _semantic_outcome_json(observables.get("outcome"))
    return {
        "register_writes": register_writes,
        "flag_writes": flag_writes,
        "memory_events": memory_events,
        "external_events": external_events,
        "faults": faults,
        "ordered_events": ordered,
        "fpu_state": _semantic_fpu_state_from_observables(
            observables,
            native_exact_command_replay=native_exact_command_replay,
        ),
        "edge_conditions": _semantic_edge_conditions(outcome),
        "outcome": outcome,
        "stack_delta": _semantic_stack_delta_from_observables(observables),
        "counts": {
            "register_writes": len(register_writes),
            "flag_writes": len(flag_writes),
            "memory_events": len(memory_events),
            "external_events": len(external_events),
            "faults": len(faults),
            "ordered_events": len(ordered),
            "edge_conditions": len(_semantic_edge_conditions(outcome)),
        },
    }

def _semantic_ordered_event_json(event: Any) -> dict[str, Any]:
    if not isinstance(event, tuple) or len(event) != 3:
        return {"kind": "unknown", "raw": _expr_json(event)}
    family, instruction_rva, payload = event
    if family == "memory":
        result = _semantic_memory_event_json(payload)
    elif family == "external":
        result = _semantic_external_event_json(payload)
    elif family == "fault":
        result = _semantic_fault_json(payload)
    else:
        result = {"kind": "unknown", "raw": _expr_json(payload)}
    return {"family": str(family), "instruction_rva": int(instruction_rva), **result}

_X87_PHYSICAL_OBSERVABLE_FIELDS = (
    ("stack", "fpu_stack"),
    ("tags", "fpu_tags"),
    ("control", "fpu_control"),
    ("status", "fpu_status"),
    ("pending_exception", "fpu_pending_exception"),
    ("last_opcode", "fpu_last_opcode"),
    ("instruction_pointer", "fpu_instruction_pointer"),
    ("code_selector", "fpu_code_selector"),
    ("data_pointer", "fpu_data_pointer"),
    ("data_selector", "fpu_data_selector"),
)

_X87_REPLAY_OBLIGATION_MODEL = "native_exact_x87_command_replay_obligation_v1"

_X87_SINGLETON_CHECKED_DECODER = "StageA.Relational.X87.decodeSingletonCommand"

_X87_SINGLETON_CHECKED_EXECUTOR = "StageA.Relational.X87.executeSingletonCommand"

_ORDINARY_CHECKED_DECODER = "StageA.Formal.decodeInstructionExact"

_ORDINARY_CHECKED_EXECUTOR = "StageA.Formal.executeInstruction"

_SEMANTIC_X87_SINGLETON_MNEMONICS = frozenset(
    {
        "wait",
        "fld",
        "fld1",
        "fldz",
        "fild",
        "fst",
        "fstp",
        "fist",
        "fistp",
        "fisttp",
        "fadd",
        "faddp",
        "fsub",
        "fsubp",
        "fsubr",
        "fsubrp",
        "fmul",
        "fmulp",
        "fdiv",
        "fdivp",
        "fdivr",
        "fdivrp",
        "fxch",
        "fchs",
        "fxam",
        "fnstcw",
        "fldcw",
        "fnstsw",
        "fcomi",
        "fcomip",
        "fucomi",
        "fucomip",
        "fcompi",
        "fucompi",
        "fninit",
    }
)

def _semantic_fpu_state_from_observables(
    observables: dict[str, Any],
    *,
    native_exact_command_replay: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    present = {
        output_name: observables[input_name]
        for output_name, input_name in _X87_PHYSICAL_OBSERVABLE_FIELDS
        if input_name in observables
    }
    if not present:
        return None

    converted = {
        name: (
            [_semantic_expr_json(item) for item in value]
            if name in {"stack", "tags"} and isinstance(value, (list, tuple))
            else _semantic_expr_json(value)
        )
        for name, value in present.items()
    }
    missing_or_invalid = [
        output_name
        for output_name, _input_name in _X87_PHYSICAL_OBSERVABLE_FIELDS
        if not _semantic_x87_physical_field_valid(output_name, converted.get(output_name))
    ]
    if not missing_or_invalid:
        return {
            "model": "symbolic_x87_stack_v1",
            **converted,
        }

    logical_guidance = {
        name: converted[name]
        for name in ("stack", "control", "status")
        if name in converted
    }
    return {
        "model": _X87_REPLAY_OBLIGATION_MODEL,
        "status": "required",
        "authoritative_state_type": "StageA.X87.PhysicalState",
        "required_fields": [
            output_name for output_name, _input_name in _X87_PHYSICAL_OBSERVABLE_FIELDS
        ],
        "missing_or_invalid_fields": missing_or_invalid,
        "logical_state_guidance": logical_guidance,
        "replay": {
            "format": "stage-a-native-exact-x87-command-replay-obligation-v1",
            "checked_decoder": _X87_SINGLETON_CHECKED_DECODER,
            "checked_decoder_scope": "each_x87_singleton_instruction",
            "checked_executor": _X87_SINGLETON_CHECKED_EXECUTOR,
            "checked_executor_scope": "each_x87_singleton_instruction",
            **(native_exact_command_replay or {}),
        },
    }

def _semantic_x87_physical_field_valid(name: str, value: Any) -> bool:
    if name in {"stack", "tags"}:
        return (
            isinstance(value, list)
            and len(value) == 8
            and all(_semantic_x87_expression_valid(item) for item in value)
        )
    return _semantic_x87_expression_valid(value)

def _semantic_x87_expression_valid(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("op"), str)

def _semantic_x87_replay_binding(
    binary: StageABinary,
    side: BlockSide,
    data: bytes,
    instructions: list[dict[str, Any]],
    *,
    instruction_effect_schedule: dict[str, Any],
) -> dict[str, Any]:
    return {
        "architecture": "x86",
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "rva_start": side.rva_start,
        "rva_end": side.rva_end,
        "bytes": data.hex(),
        "bytes_sha256": sha256_bytes(data),
        "instruction_effect_schedule": instruction_effect_schedule,
        "instructions": [
            {
                key: instruction[key]
                for key in ("rva", "size", "bytes")
                if key in instruction
            }
            for instruction in instructions
        ],
    }

def _semantic_transfer_inventory_contains_x87(
    instructions: list[dict[str, Any]],
) -> bool:
    return any(
        str(instruction.get("mnemonic") or "").lower()
        in _SEMANTIC_X87_SINGLETON_MNEMONICS
        for instruction in instructions
        if isinstance(instruction, dict)
    )

def _semantic_x87_instruction_effect_schedule(
    binary: StageABinary,
    side: BlockSide,
    data: bytes,
    instructions: list[dict[str, Any]],
    mapped: BlockMapping,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Propose an exact-byte instruction ledger for checked Lean replay.

    Capstone reports are inventory hints only.  Every classification remains bound
    to exact PE bytes and names the Lean decoder/executor that must replay it.
    """

    transfer_digest = sha256_bytes(data)
    records: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    expected_rva = side.rva_start
    external_call_index = 0
    final_symbolic: dict[str, Any] = {
        "status": "incomplete",
        "category": "x87_instruction_effect_schedule_incomplete",
        "blocker": "x87 instruction effect schedule contains no instructions",
        "next_action": "export at least one exact decoded instruction",
    }

    for index, instruction in enumerate(instructions):
        instruction_rva = instruction.get("rva")
        instruction_size = instruction.get("size")
        instruction_hex = instruction.get("bytes")
        mnemonic = str(instruction.get("mnemonic") or "").lower()
        if (
            not isinstance(instruction_rva, int)
            or not isinstance(instruction_size, int)
            or instruction_size <= 0
            or not isinstance(instruction_hex, str)
        ):
            blocker_rva = instruction_rva if isinstance(instruction_rva, int) else expected_rva
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                blocker_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "decoded instruction inventory lacks exact RVA, size, or bytes",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break
        try:
            instruction_bytes = bytes.fromhex(instruction_hex)
        except ValueError:
            instruction_bytes = b""
        if (
            instruction_rva != expected_rva
            or len(instruction_bytes) != instruction_size
            or data[
                instruction_rva - side.rva_start :
                instruction_rva - side.rva_start + instruction_size
            ]
            != instruction_bytes
        ):
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                instruction_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "decoded instruction inventory does not reconstruct the exact PE span",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break

        instruction_end = instruction_rva + instruction_size
        instruction_side = BlockSide(instruction_rva, instruction_end)
        instruction_mapping = BlockMapping(
            id=f"{mapped.id}~instruction-{index}",
            original=instruction_side,
            candidate=instruction_side,
            kind=mapped.kind,
            reachable=mapped.reachable,
            invariant_checked=mapped.invariant_checked,
            source=mapped.source,
        )
        instruction_symbolic = _symbolic_execute(
            binary,
            instruction_side,
            instruction_bytes,
            "original",
            instruction_mapping,
            external_call_index_base=external_call_index,
        )
        if instruction_symbolic.get("status") != "ok":
            blockers.append(
                _semantic_instruction_effect_blocker(
                    index, instruction, instruction_symbolic
                )
            )
            break

        current_observables = instruction_symbolic.get("observables")
        current_ordered_events = instruction_symbolic.get("ordered_events")
        if not isinstance(current_observables, dict) or not isinstance(
            current_ordered_events, tuple
        ):
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                instruction_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "symbolic instruction prefix did not emit structured observables",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break

        local_pre_state = _semantic_initial_instruction_observables(instruction_rva)
        effects = _semantic_instruction_effect_delta(
            local_pre_state,
            current_observables,
            (),
            current_ordered_events,
        )
        if effects is None:
            final_symbolic = _symbolic_incomplete(
                "original",
                "x87_instruction_effect_schedule_incomplete",
                instruction_rva,
                mnemonic or "<decode>",
                str(instruction.get("op_str") or ""),
                "symbolic prefix effects are not a stable extension of the prior instruction",
            )
            blockers.append(
                _semantic_instruction_effect_blocker(index, instruction, final_symbolic)
            )
            break

        instruction_class = (
            "x87_singleton_checked_replay"
            if mnemonic in _SEMANTIC_X87_SINGLETON_MNEMONICS
            else "ordinary_symbolic_instruction"
        )
        checked_decoder = (
            _X87_SINGLETON_CHECKED_DECODER
            if instruction_class == "x87_singleton_checked_replay"
            else _ORDINARY_CHECKED_DECODER
        )
        checked_executor = (
            _X87_SINGLETON_CHECKED_EXECUTOR
            if instruction_class == "x87_singleton_checked_replay"
            else _ORDINARY_CHECKED_EXECUTOR
        )
        record: dict[str, Any] = {
            "index": index,
            "rva_start": instruction_rva,
            "rva_end": instruction_end,
            "bytes": instruction_bytes.hex(),
            "bytes_sha256": sha256_bytes(instruction_bytes),
            "transfer_bytes_sha256": transfer_digest,
            "instruction_class": instruction_class,
            "classification": {
                "status": "proposal_requires_lean_exact_byte_replay",
                "source": "normalized_symbolic_equivalence_v1",
                "proof_authority": False,
                "mnemonic_guidance": mnemonic,
                "operand_guidance": str(instruction.get("op_str") or ""),
                "checked_decoder": checked_decoder,
                "checked_executor": checked_executor,
            },
            "symbolic_pre_state_sha256": _semantic_json_sha256(local_pre_state),
            "symbolic_post_state_sha256": _semantic_json_sha256(current_observables),
            "effects": effects,
        }
        if instruction_class == "x87_singleton_checked_replay":
            record["x87_singleton_replay"] = {
                "rva_start": instruction_rva,
                "rva_end": instruction_end,
                "bytes": instruction_bytes.hex(),
                "bytes_sha256": sha256_bytes(instruction_bytes),
                "checked_decoder": _X87_SINGLETON_CHECKED_DECODER,
                "checked_executor": _X87_SINGLETON_CHECKED_EXECUTOR,
                "physical_state_effect": (
                    "produced_by_checked_executor_not_inferred_by_exporter"
                ),
            }
        record["record_sha256"] = _semantic_json_sha256(record)
        records.append(record)
        external_call_index += len(current_observables.get("external_events", ()))
        expected_rva = instruction_end

    if not blockers and expected_rva != side.rva_end:
        final_symbolic = _symbolic_incomplete(
            "original",
            "x87_instruction_effect_schedule_incomplete",
            expected_rva,
            "<decode>",
            "",
            "decoded instruction inventory does not cover the complete transfer span",
        )
        blockers.append(
            _semantic_instruction_effect_blocker(len(records), {}, final_symbolic)
        )

    if not blockers:
        final_symbolic = _symbolic_execute(
            binary,
            side,
            data,
            "original",
            mapped,
        )
        if final_symbolic.get("status") != "ok":
            blockers.append(
                _semantic_instruction_effect_blocker(
                    len(records), instructions[-1] if instructions else {}, final_symbolic
                )
            )

    schedule: dict[str, Any] = {
        "format": "stage-a-instruction-ordered-effect-schedule-v1",
        "status": "complete" if not blockers else "incomplete",
        "proof_authority": False,
        "ordering": "strict_contiguous_rva_order",
        "rva_start": side.rva_start,
        "rva_end": side.rva_end,
        "transfer_bytes_sha256": transfer_digest,
        "records": records,
        "blockers": blockers,
        "counts": {
            "instructions": len(records),
            "x87_singletons": sum(
                record.get("instruction_class") == "x87_singleton_checked_replay"
                for record in records
            ),
            "ordinary_instructions": sum(
                record.get("instruction_class") == "ordinary_symbolic_instruction"
                for record in records
            ),
            "blockers": len(blockers),
        },
    }
    schedule["schedule_sha256"] = _semantic_json_sha256(schedule)
    return schedule, final_symbolic

def _semantic_initial_instruction_observables(rva: int) -> dict[str, Any]:
    observables = {
        f"reg:{name}": ("reg", name)
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    observables.update(
        {
            f"flag:{name}": ("flag", name)
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        }
    )
    observables.update(
        {
            "outcome": ("fallthrough", rva),
            "memory_events": (),
            "external_events": (),
            "fault_conditions": (),
        }
    )
    return observables

def _semantic_instruction_effect_delta(
    previous: dict[str, Any],
    current: dict[str, Any],
    previous_ordered: tuple[Any, ...],
    current_ordered: tuple[Any, ...],
) -> dict[str, Any] | None:
    sequence_names = ("memory_events", "external_events", "fault_conditions")
    deltas: dict[str, tuple[Any, ...]] = {}
    for name in sequence_names:
        before = previous.get(name, ())
        after = current.get(name, ())
        if (
            not isinstance(before, tuple)
            or not isinstance(after, tuple)
            or after[: len(before)] != before
        ):
            return None
        deltas[name] = after[len(before) :]
    if current_ordered[: len(previous_ordered)] != previous_ordered:
        return None

    register_writes = []
    defined_flag_writes = []
    undefined_flags = []
    undefined_flag_writes = []
    for key, value in sorted(current.items()):
        if key.startswith("reg:") and previous.get(key) != value:
            register_writes.append(
                {"register": key.split(":", 1)[1], "value": _semantic_expr_json(value)}
            )
        elif key.startswith("flag:") and previous.get(key) != value:
            name = key.split(":", 1)[1]
            converted = _semantic_expr_json(value)
            if _semantic_json_contains_op(converted, "undefined_flag"):
                undefined_flags.append(name)
                undefined_flag_writes.append({"flag": name, "value": converted})
            else:
                defined_flag_writes.append({"flag": name, "value": converted})

    memory_events = [
        _semantic_memory_event_json(event) for event in deltas["memory_events"]
    ]
    call_effects = [
        _semantic_external_event_json(event) for event in deltas["external_events"]
    ]
    faults = [_semantic_fault_json(event) for event in deltas["fault_conditions"]]
    ordered_events = [
        _semantic_ordered_event_json(event)
        for event in current_ordered[len(previous_ordered) :]
    ]
    result = {
        "register_writes": register_writes,
        "defined_flag_writes": defined_flag_writes,
        "undefined_flags": undefined_flags,
        "undefined_flag_writes": undefined_flag_writes,
        "memory_events": memory_events,
        "faults": faults,
        "control": _semantic_outcome_json(current.get("outcome")),
        "call_effects": call_effects,
        "ordered_events": ordered_events,
    }
    result["counts"] = {
        name: len(result[name])
        for name in (
            "register_writes",
            "defined_flag_writes",
            "undefined_flags",
            "undefined_flag_writes",
            "memory_events",
            "faults",
            "call_effects",
            "ordered_events",
        )
    }
    return result

def _semantic_instruction_effect_blocker(
    index: int,
    instruction: dict[str, Any],
    symbolic: dict[str, Any],
) -> dict[str, Any]:
    rva = instruction.get("rva")
    blocking_instruction = symbolic.get("instruction")
    if not isinstance(rva, int) and isinstance(blocking_instruction, dict):
        rva = blocking_instruction.get("rva")
    raw_bytes = instruction.get("bytes")
    try:
        exact_bytes = bytes.fromhex(raw_bytes) if isinstance(raw_bytes, str) else b""
    except ValueError:
        exact_bytes = b""
    blocker = {
        "index": index,
        "rva": rva,
        "bytes": exact_bytes.hex(),
        "bytes_sha256": sha256_bytes(exact_bytes),
        "category": symbolic.get("category")
        or "x87_instruction_effect_schedule_incomplete",
        "blocker": symbolic.get("blocker")
        or "instruction effects could not be represented",
        "next_action": symbolic.get("next_action")
        or "add checked per-instruction semantics",
    }
    blocker["blocker_sha256"] = _semantic_json_sha256(blocker)
    return blocker

def _semantic_json_contains_op(value: Any, operation: str) -> bool:
    if isinstance(value, dict):
        if value.get("op") == operation:
            return True
        return any(_semantic_json_contains_op(item, operation) for item in value.values())
    if isinstance(value, list):
        return any(_semantic_json_contains_op(item, operation) for item in value)
    return False

def _semantic_json_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )

def _semantic_expr_json(value: Any) -> Any:
    if not isinstance(value, tuple) or not value:
        if isinstance(value, list):
            return [_semantic_expr_json(item) for item in value]
        if isinstance(value, dict):
            return {str(key): _semantic_expr_json(item) for key, item in value.items()}
        return value
    op = str(value[0])
    if op == "const":
        return {"op": "const", "width": 32, "value": int(value[1]) & 0xFFFFFFFF}
    if op == "reg":
        return {"op": "reg", "width": 32, "name": str(value[1])}
    if op == "flag":
        return {"op": "flag", "name": str(value[1])}
    if op == "mem32":
        return {"op": "load", "width": 4, "address": _semantic_expr_json(value[1])}
    if op == "mem":
        return {"op": "load", "width": int(value[1]) // 8, "address": _semantic_expr_json(value[2])}
    if op == "env_response":
        return {"op": "env_response", "width": 32, "index": int(value[1])}
    if op == "call_response":
        return {"op": "call_response", "width": 32, "call_index": int(value[1]), "register": str(value[2])}
    if op == "call_mem":
        return {"op": "call_memory_load", "width": int(value[2]) // 8, "call_index": int(value[1]), "address": _semantic_expr_json(value[3])}
    if op == "call_flag":
        return {"op": "call_flag", "call_index": int(value[1]), "flag": str(value[2])}
    if op == "undefined_bv":
        result = {
            "op": "undefined_bv",
            "width": 32,
            "reason": str(value[1]),
            "id": str(value[2]),
        }
        if len(value) == 4:
            result["defined_value"] = _semantic_expr_json(value[3])
        return result
    if op == "undefined_flag":
        return {"op": "undefined_flag", "reason": str(value[1]), "id": str(value[2])}
    if op in {"true", "false"}:
        return {"op": op}
    op_map = {
        "add": "add32",
        "sub": "sub32",
        "mul": "mul32",
        "xor": "xor32",
        "and": "and32",
        "or": "or32",
        "bvnot": "not32",
        "neg": "neg32",
        "shl": "shl32",
        "lshr": "lshr32",
        "ashr": "sar",
        "sext": "sign_extend",
        "ite": "ite",
        "ult": "ult32",
        "eq": "eq",
        "msb": "msb32",
        "msb_w": "msb",
        "not": "not",
        "bool_and": "and_bool",
        "bool_or": "or_bool",
        "bool_xor": "xor_bool",
        "bool_eq": "eq_bool",
        "add_overflow": "add_overflow32",
        "sub_overflow": "sub_overflow32",
        "add_overflow_w": "add_overflow",
        "sub_overflow_w": "sub_overflow",
        "shift_cf": "shift_cf",
        "shift_of": "shift_of",
        "bool_bit": "bool_to_bit",
        "adc_carry": "adc_carry",
        "adc_overflow": "adc_overflow",
        "sbb_borrow": "sbb_borrow",
        "sbb_overflow": "sbb_overflow",
        "imul_low": "imul_low32",
        "imul_high": "imul_high32",
        "imul_overflow": "imul_overflow",
        "mul_low": "mul_low32",
        "mul_high": "mul_high32",
        "mul_carry": "mul_carry",
        "parity": "parity",
        "udiv_quot": "udiv_quot32",
        "udiv_rem": "udiv_rem32",
        "udiv_valid": "udiv_valid32",
        "bsr_index": "bsr_index",
        "tzcnt": "tzcnt",
        "fpu_bits_lo": "fpu_bits_lo32",
        "fpu_bits_hi": "fpu_bits_hi32",
        "fpu_int32": "fpu_int32",
        "fpu_status_word": "fpu_status_word",
        "fpu_control_word": "fpu_control_word",
    }
    return {"op": op_map.get(op, op), "args": [_semantic_expr_json(item) for item in value[1:]]}

def _semantic_memory_event_json(event: Any) -> dict[str, Any]:
    if isinstance(event, tuple) and len(event) >= 2 and event[0] == "read":
        mem = event[1]
        if isinstance(mem, tuple) and len(mem) > 1 and mem[0] == "mem32":
            return {"kind": "read", "width": 4, "address": _semantic_expr_json(mem[1])}
        if isinstance(mem, tuple) and len(mem) > 2 and mem[0] == "mem":
            return {"kind": "read", "width": int(mem[1]) // 8, "address": _semantic_expr_json(mem[2])}
        if isinstance(mem, tuple) and len(mem) > 3 and mem[0] == "call_mem":
            return {"kind": "read", "width": int(mem[2]) // 8, "address": _semantic_expr_json(mem[3]), "memory_epoch": {"kind": "internal_call", "call_index": int(mem[1])}}
        return {"kind": "read", "width": 4, "address": _semantic_expr_json(mem)}
    if isinstance(event, tuple) and len(event) >= 3 and event[0] == "write":
        mem = event[1]
        if isinstance(mem, tuple) and len(mem) > 1 and mem[0] == "mem32":
            return {"kind": "write", "width": 4, "address": _semantic_expr_json(mem[1]), "value": _semantic_expr_json(event[2])}
        if isinstance(mem, tuple) and len(mem) > 2 and mem[0] == "mem":
            return {"kind": "write", "width": int(mem[1]) // 8, "address": _semantic_expr_json(mem[2]), "value": _semantic_expr_json(event[2])}
        if isinstance(mem, tuple) and len(mem) > 3 and mem[0] == "call_mem":
            return {
                "kind": "write",
                "width": int(mem[2]) // 8,
                "address": _semantic_expr_json(mem[3]),
                "value": _semantic_expr_json(event[2]),
                "memory_epoch": {"kind": "internal_call", "call_index": int(mem[1])},
            }
        return {"kind": "write", "width": 4, "address": _semantic_expr_json(mem), "value": _semantic_expr_json(event[2])}
    return {"kind": "unknown", "raw": _expr_json(event)}

def _semantic_external_event_json(event: Any) -> dict[str, Any]:
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "external_call":
        result = {
            "kind": "external_call",
            "dll": event[1],
            "symbol": event[2],
            "ordinal": event[3],
            "arguments": [_semantic_expr_json(item) for item in event[4]],
        }
        if len(event) >= 6 and isinstance(event[5], tuple) and event[5]:
            boundary = event[5]
            if boundary[0] == "machine_call_boundary":
                result["return_rva"] = int(boundary[1])
                result["input_model"] = "captured_machine_call_boundary_v1"
                result["register_inputs"] = _semantic_call_register_inputs_json(
                    boundary[2] if len(boundary) > 2 else ()
                )
                result["stack_inputs"] = _semantic_call_stack_inputs_json(
                    boundary[3] if len(boundary) > 3 else ()
                )
                result["flag_inputs"] = _semantic_call_register_inputs_json(
                    boundary[4] if len(boundary) > 4 else ()
                )
            elif boundary[0] == "auto_call_inputs":
                # Backward-compatible decoding for cached v1 symbolic summaries.
                result["input_model"] = "captured_visible_register_and_stack_inputs_v1"
                result["register_inputs"] = _semantic_call_register_inputs_json(
                    boundary[1] if len(boundary) > 1 else ()
                )
                result["stack_inputs"] = _semantic_call_stack_inputs_json(
                    boundary[2] if len(boundary) > 2 else ()
                )
                result["flag_inputs"] = _semantic_call_register_inputs_json(
                    boundary[3] if len(boundary) > 3 else ()
                )
        return result
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "internal_call":
        return {
            "kind": "internal_call",
            "target_rva": int(event[1]),
            "return_rva": int(event[2]),
            "register_inputs": _semantic_call_register_inputs_json(event[3]),
            "stack_inputs": _semantic_call_stack_inputs_json(event[4]),
            "flag_inputs": _semantic_call_register_inputs_json(event[5] if len(event) > 5 else ()),
            "effect_model": "uninterpreted_internal_call_response_v1",
        }
    if isinstance(event, tuple) and len(event) >= 5 and event[0] == "indirect_call":
        return {
            "kind": "indirect_call",
            "target": _semantic_expr_json(event[1]),
            "return_rva": int(event[2]),
            "register_inputs": _semantic_call_register_inputs_json(event[3]),
            "stack_inputs": _semantic_call_stack_inputs_json(event[4]),
            "flag_inputs": _semantic_call_register_inputs_json(event[5] if len(event) > 5 else ()),
            "effect_model": "uninterpreted_indirect_call_response_v1",
        }
    if isinstance(event, tuple) and len(event) >= 6 and event[0] == "rep_movsd":
        return {
            "kind": "rep_movsd",
            "index": int(event[1]),
            "destination": _semantic_expr_json(event[2]),
            "source": _semantic_expr_json(event[3]),
            "count": _semantic_expr_json(event[4]),
            "direction_flag": _semantic_expr_json(event[5]),
            "effect_model": "symbolic_string_copy_v1",
        }
    return {"kind": "unknown_external_event", "raw": _expr_json(event)}

def _semantic_fault_json(fault: Any) -> dict[str, Any]:
    if isinstance(fault, tuple) and len(fault) == 3:
        return {
            "kind": str(fault[0]),
            "condition": _semantic_expr_json(fault[1]),
            "instruction_rva": int(fault[2]),
        }
    return {"kind": "unknown", "raw": _expr_json(fault)}

def _semantic_call_register_inputs_json(items: Any) -> dict[str, Any]:
    result = {}
    for item in items if isinstance(items, tuple) else ():
        if isinstance(item, tuple) and len(item) == 2:
            result[str(item[0])] = _semantic_expr_json(item[1])
    return result

def _semantic_call_stack_inputs_json(items: Any) -> list[dict[str, Any]]:
    result = []
    for item in items if isinstance(items, tuple) else ():
        if isinstance(item, tuple) and len(item) == 3:
            result.append({"offset": int(item[0]), "width": int(item[1]) // 8, "value": _semantic_expr_json(item[2])})
    return result

def _semantic_outcome_json(outcome: Any) -> dict[str, Any]:
    if not isinstance(outcome, tuple) or not outcome:
        return {"kind": "unknown", "raw": _expr_json(outcome)}
    kind = str(outcome[0])
    if kind == "fallthrough":
        return {"kind": "fallthrough", "target_rva": outcome[1]}
    if kind == "jump":
        return {"kind": "jump", "target_rva": outcome[1]}
    if kind == "branch":
        return {
            "kind": "branch",
            "condition": _semantic_expr_json(outcome[1]),
            "true_target_rva": outcome[2],
            "false_target_rva": outcome[3],
        }
    if kind == "return":
        return {"kind": "return", "value": _semantic_expr_json(outcome[1])}
    if kind == "call":
        return {"kind": "direct_call", "target_rva": outcome[1], "return_rva": outcome[2]}
    if kind == "indirect_jump":
        return {"kind": "indirect_jump", "target": _semantic_expr_json(outcome[1])}
    if kind == "indirect_jump_table":
        switch_contract = outcome[2] if len(outcome) > 2 and isinstance(outcome[2], dict) else {}
        return {
            "kind": "indirect_jump_table",
            "target": _semantic_expr_json(outcome[1]),
            "switch_contract": switch_contract,
            "target_rvas": [
                target_rva
                for item in switch_contract.get("case_targets", []) if isinstance(switch_contract.get("case_targets"), list) and isinstance(item, dict)
                for target_rva in [_safe_int(item.get("target_rva"))]
                if target_rva is not None
            ],
        }
    if kind == "external_jump":
        return {"kind": "external_jump", "dll": outcome[1], "symbol": outcome[2], "ordinal": outcome[3]}
    return {"kind": kind, "raw": _expr_json(outcome)}

def _semantic_edge_conditions(outcome: dict[str, Any]) -> list[dict[str, Any]]:
    kind = outcome.get("kind")
    if kind == "branch":
        return [
            {"target_rva": outcome.get("true_target_rva"), "condition": outcome.get("condition")},
            {"target_rva": outcome.get("false_target_rva"), "condition": {"op": "not", "args": [outcome.get("condition")]}},
        ]
    if kind in {"fallthrough", "jump"}:
        return [{"target_rva": outcome.get("target_rva"), "condition": {"op": "true"}}]
    if kind == "indirect_jump_table":
        switch_contract = outcome.get("switch_contract") if isinstance(outcome.get("switch_contract"), dict) else {}
        case_targets = switch_contract.get("case_targets") if isinstance(switch_contract.get("case_targets"), list) else []
        return [
            {
                "target_rva": target_rva,
                "condition": {
                    "op": "jump_table_case",
                    "index": item.get("index"),
                    "instruction_rva": switch_contract.get("instruction", {}).get("rva")
                    if isinstance(switch_contract.get("instruction"), dict)
                    else None,
                },
            }
            for item in case_targets
            if isinstance(item, dict)
            for target_rva in [_safe_int(item.get("target_rva"))]
            if target_rva is not None
        ]
    return []

def _semantic_stack_delta_from_observables(observables: dict[str, Any]) -> dict[str, Any]:
    esp = observables.get("reg:esp")
    delta = _semantic_stack_delta_expr(esp)
    if delta is None:
        return {"status": "unknown", "expression": _semantic_expr_json(esp)}
    return {"status": "derived", "net_bytes": delta, "expression": _semantic_expr_json(esp)}

def _semantic_stack_delta_expr(expr: Any) -> int | None:
    if expr == ("reg", "esp"):
        return 0
    if isinstance(expr, tuple) and expr and expr[0] == "add":
        total = 0
        saw_esp = False
        for part in expr[1:]:
            if part == ("reg", "esp"):
                saw_esp = True
            elif isinstance(part, tuple) and len(part) == 2 and part[0] == "const":
                total += int(part[1])
            else:
                return None
        return total if saw_esp else None
    if isinstance(expr, tuple) and len(expr) == 3 and expr[0] == "sub" and expr[1] == ("reg", "esp"):
        right = expr[2]
        if isinstance(right, tuple) and len(right) == 2 and right[0] == "const":
            return -int(right[1])
    return None

def _semantic_memory_frame_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    frames: dict[str, dict[str, Any]] = {}
    accesses: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for access_kind, access_list_name in (("read", "memory_reads"), ("write", "memory_writes")):
            for index, access in enumerate(function.get(access_list_name, []) if isinstance(function.get(access_list_name), list) else []):
                if not isinstance(access, dict):
                    continue
                frame = _semantic_memory_frame_for_access(access)
                frames.setdefault(str(frame["id"]), frame)
                instruction = access.get("instruction") if isinstance(access.get("instruction"), dict) else {}
                accesses.append(
                    {
                        "id": f"memory-access:{_safe_gap_part(function_name)}:{instruction.get('rva', 'unknown')}:{access_kind}:{index}",
                        "function": function_name or None,
                        "block_id": _block_id_for_instruction(function, instruction),
                        "access": access_kind,
                        "width": access.get("width"),
                        "frame_id": frame["id"],
                        "frame_kind": frame["frame_kind"],
                        "addressing": access.get("addressing") if isinstance(access.get("addressing"), dict) else {},
                        "instruction": instruction,
                        "status": "classified" if frame["frame_kind"] != "unknown" else "incomplete",
                        "blocker": None if frame["frame_kind"] != "unknown" else "memory frame could not be classified from static addressing evidence",
                        "source_access": access,
                    }
                )
    return {
        "format": "stage-a-memory-frame-contracts-v1",
        "reference_contract": contract_ref,
        "frames": sorted(frames.values(), key=lambda item: str(item.get("id") or "")),
        "accesses": sorted(accesses, key=lambda item: str(item.get("id") or "")),
        "counts": {
            "frames": len(frames),
            "accesses": len(accesses),
            "by_frame_kind": _count_by(list(frames.values()), "frame_kind"),
            "by_access": _count_by(accesses, "access"),
        },
    }

def _semantic_memory_frame_for_access(access: dict[str, Any]) -> dict[str, Any]:
    role = str(access.get("memory_role") or "unknown")
    section = access.get("memory_section") if isinstance(access.get("memory_section"), dict) else {}
    addressing = access.get("addressing") if isinstance(access.get("addressing"), dict) else {}
    base = str(addressing.get("base") or "")
    entry_pointer = access.get("entry_register_pointer") if isinstance(access.get("entry_register_pointer"), dict) else {}
    if role == "import_address_table":
        frame_kind = "iat.import"
        frame_key = str(access.get("memory_rva") or "unknown")
    elif role.startswith("global_"):
        frame_kind = "global.rw" if section.get("writable") is True else "global.ro"
        frame_key = str(section.get("name") or access.get("memory_rva") or "unknown")
    elif role == "stack_argument_slot":
        frame_kind = "stack.arg"
        frame_key = base or "stack"
    elif role in {"stack_local_slot", "stack_pointer_slot"}:
        frame_kind = "stack.local"
        frame_key = base or "stack"
    elif entry_pointer:
        frame_kind = "object.pointer_candidate"
        frame_key = str(entry_pointer.get("register") or base or "entry")
    elif role == "argument_pointer_deref":
        frame_kind = "object.argument_pointer"
        frame_key = base or "argument"
    elif role == "global_pointer_deref":
        frame_kind = "object.global_pointer"
        frame_key = base or str(access.get("memory_rva") or "global")
    elif role == "computed_pointer_deref":
        frame_kind = "object.computed_pointer"
        frame_key = base or "computed"
    elif role == "absolute_memory_slot":
        frame_kind = "absolute.memory"
        frame_key = str(access.get("memory_rva") or "absolute")
    elif role == "computed_memory":
        frame_kind = "computed.memory"
        frame_key = base or "computed"
    else:
        frame_kind = f"role.{_safe_gap_part(role)}" if role else "role.unknown"
        frame_key = role
    return {
        "id": f"frame:{_safe_gap_part(frame_kind)}:{_safe_gap_part(frame_key)}",
        "frame_kind": frame_kind,
        "memory_role": role,
        "section": section or None,
        "base_register": base or None,
        "entry_register_pointer": entry_pointer or None,
        "status": "classified",
    }

def _semantic_call_summary_contracts(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    summaries: list[dict[str, Any]] = []
    for function in _abi_functions(contract):
        function_name = str(function.get("name") or "")
        for index, callsite in enumerate(function.get("callsites", []) if isinstance(function.get("callsites"), list) else []):
            if not isinstance(callsite, dict):
                continue
            summary = _semantic_call_summary(function_name, index, callsite)
            summaries.append(summary)
    return {
        "format": "stage-a-call-summary-contracts-v1",
        "reference_contract": contract_ref,
        "calls": sorted(summaries, key=lambda item: str(item.get("id") or "")),
        "counts": {
            "calls": len(summaries),
            "by_status": _count_by(summaries, "status"),
            "by_target_kind": _count_by(summaries, "target_kind"),
        },
    }

def _semantic_call_summary(function_name: str, index: int, callsite: dict[str, Any]) -> dict[str, Any]:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    inventory = callsite.get("argument_inventory") if isinstance(callsite.get("argument_inventory"), dict) else {}
    hidden = callsite.get("hidden_sret_or_out_param_evidence") if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    varargs = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
    targets = callsite.get("function_pointer_targets") if isinstance(callsite.get("function_pointer_targets"), list) else []
    blockers: list[str] = []
    indirect_boundary = (target.get("kind") == "function_pointer" and target.get("status") == "unresolved")
    if any(isinstance(item, dict) and item.get("status") == "unresolved" for item in targets) and not indirect_boundary:
        blockers.append("function-pointer target set is unresolved")
    fmt = varargs.get("format_string") if isinstance(varargs.get("format_string"), dict) else {}
    if fmt.get("status") == "incomplete":
        blockers.append(str(fmt.get("reason") or "varargs format-string inventory is incomplete"))
    status = "complete" if not blockers else "incomplete"
    return {
        "id": str(callsite.get("id") or f"callsite:{_safe_gap_part(function_name)}:{index}"),
        "function": function_name or None,
        "block_id": callsite.get("block_id"),
        "status": status,
        "target_kind": target.get("kind") or "unknown",
        "target": target,
        "calling_convention": inventory.get("calling_convention") or "unknown",
        "argument_inventory": inventory,
        "return_value": {"register": "eax", "status": "environment_response_or_direct_call_result"},
        "stack_delta": callsite.get("stack_delta") if isinstance(callsite.get("stack_delta"), dict) else {"status": "unknown"},
        "hidden_sret_or_out_param_evidence": hidden,
        "varargs_evidence": varargs,
        "function_pointer_targets": targets,
        "indirect_boundary": {"status": "explicit", "effect_model": "preserve_target_expression_and_call_response"} if indirect_boundary else None,
        "blockers": blockers,
        "next_action": _semantic_call_summary_next_action(function_name, target, blockers, varargs, hidden),
        "source_callsite": callsite,
    }

def _semantic_call_summary_next_action(
    function_name: str,
    target: dict[str, Any],
    blockers: list[str],
    varargs: dict[str, Any],
    hidden: dict[str, Any],
) -> str:
    if blockers:
        if any("function-pointer" in item for item in blockers):
            return f"recover finite function-pointer targets for {function_name} or keep the indirect boundary explicit"
        if varargs.get("status") == "candidate" or any("varargs" in item or "format" in item for item in blockers):
            return f"recover the format-string and variadic argument inventory for {function_name}"
        return f"complete the call summary for {function_name}"
    if varargs.get("status") == "candidate":
        return "preserve the variadic import/prototype boundary exactly in generated C"
    if hidden.get("status") == "candidate":
        return "preserve the hidden sret/out-param channel across this call"
    if target.get("kind") == "import":
        return "preserve this call as an import/environment boundary"
    return "preserve this call target, argument inventory, and return-value use"

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
                "acceptance": "guidance cluster only; final acceptance requires Stage A binary proof",
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
    source_obligations = _reference_source_obligations_sidecar(contract, contract_ref, block_contracts, function_contracts, cluster_contracts)
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
        "source_obligations": source_obligations,
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
                    "acceptance": "informational unit contract only; final acceptance requires Stage A pass",
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

def _reference_source_obligations_sidecar(
    contract: dict[str, Any],
    contract_ref: dict[str, Any],
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    obligations = proof.get("obligations") if isinstance(proof.get("obligations"), list) else []
    unit_lookup = _unit_contract_obligation_lookup(block_contracts, function_contracts, cluster_contracts)
    rows = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        obligation_id = str(obligation.get("id") or "")
        rows.append(
            {
                "id": f"source-obligation:{_safe_gap_part(obligation_id)}",
                "obligation_id": obligation_id,
                "kind": obligation.get("kind"),
                "status": obligation.get("status"),
                "proof_rule": obligation.get("proof_rule"),
                "family": _obligation_family(obligation_id),
                "unit_contract_ids": _unit_contract_ids_for_obligation(obligation_id, unit_lookup),
            }
        )
    return {
        "format": "stage-a-source-obligations-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "obligations": rows,
        "counts": {
            "obligations": len(rows),
            "by_status": _count_by(rows, "status"),
            "by_family": _count_by(rows, "family"),
        },
    }

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

def _unit_contract_obligation_lookup(
    block_contracts: list[dict[str, Any]],
    function_contracts: list[dict[str, Any]],
    cluster_contracts: list[dict[str, Any]],
) -> dict[str, Any]:
    by_key: dict[str, set[str]] = {}
    fallback_rows: list[tuple[str, str]] = []

    def add_key(key: Any, unit_id: str) -> None:
        if key is None:
            return
        text = str(key).strip().lower()
        if not text:
            return
        by_key.setdefault(text, set()).add(unit_id)

    for rows in (block_contracts, function_contracts, cluster_contracts):
        for row in rows:
            if not isinstance(row, dict):
                continue
            unit_id = str(row.get("id") or "")
            if not unit_id:
                continue
            add_key(unit_id, unit_id)
            for key_name in ("block_id", "function", "cluster_kind", "category"):
                add_key(row.get(key_name), unit_id)
            block_id = row.get("block_id")
            if isinstance(block_id, str) and block_id:
                add_key(f"block:{block_id}", unit_id)
                add_key(f"reachability:{block_id}", unit_id)
            function = row.get("function")
            if isinstance(function, str) and function:
                add_key(f"function:{function}", unit_id)
            fallback_rows.append((
                unit_id,
                json.dumps(row, sort_keys=True, default=str).lower(),
            ))
    return {"by_key": by_key, "fallback_rows": fallback_rows}

def _unit_contract_ids_for_obligation(obligation_id: str, lookup: dict[str, Any]) -> list[str]:
    text = obligation_id.lower()
    if not text:
        return []
    by_key = lookup.get("by_key") if isinstance(lookup.get("by_key"), dict) else {}
    ids: set[str] = set()

    def add_lookup(key: str) -> None:
        ids.update(by_key.get(key.lower(), set()))

    add_lookup(text)
    parts = obligation_id.split(":")
    known_prefix = parts[0] if parts else ""
    location_prefixes = {
        "address-separation",
        "block",
        "direct-call-push",
        "edge",
        "external-call-edge",
        "function",
        "import-register-invariant",
        "import-register-seed",
        "indirect-edge",
        "indirect-import-call",
        "machine-import-call",
        "memory",
        "memory-transition",
        "reachability",
        "relational",
        "return-pop",
        "return-slot-call-summary",
        "return-slot-frame",
        "return-slot-transfer",
        "segment",
        "stack-separation-inventory",
        "stack-window-frontier",
        "waiver",
    }
    if len(parts) >= 2 and known_prefix in location_prefixes:
        for location in parts[1:]:
            add_lookup(location)
            add_lookup(f"block:{location}")
            add_lookup(f"reachability:{location}")
            add_lookup(f"function:{location}")

    if ids:
        return sorted(ids)
    if known_prefix in location_prefixes:
        return []

    fallback_rows = lookup.get("fallback_rows") if isinstance(lookup.get("fallback_rows"), list) else []
    return sorted(
        {
            unit_id for unit_id, serialized in fallback_rows if text in serialized
        }
    )

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
        "source_obligations": _load_json_or(paths["source_obligations"], fallback["source_obligations"]),
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

def _reference_contract_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for issue in contract.get("issues", []):
        if isinstance(issue, dict):
            gaps.append(_gap_from_issue(issue))
    gaps.extend(_byte_coverage_gap_items(contract))
    gaps.extend(_proof_inventory_gap_items(contract))
    return sorted(_dedupe_gaps(gaps), key=lambda item: str(item.get("gap_id") or ""))

def _gap_from_issue(issue: dict[str, Any]) -> dict[str, Any]:
    obligation_id = str(issue.get("obligation_id") or issue.get("category") or "issue")
    details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
    category = str(issue.get("category") or "stage_a_issue")
    severity = "violated" if issue.get("severity") == "fail" or issue.get("status") == "failed" else "incomplete"
    family = _issue_family(obligation_id, category)
    return {
        "gap_id": f"{family}:{_safe_gap_part(obligation_id)}",
        "family": family,
        "category": category,
        "severity": severity,
        "location": {"obligation_id": obligation_id},
        "expected": details.get("expected") or issue.get("original") or "closed Stage A evidence",
        "observed": details.get("actual") or issue.get("candidate") or issue.get("blocker") or issue.get("status"),
        "example": details.get("example"),
        "cause_hint": issue.get("blocker") or category,
        "next_action": issue.get("next_action") or "inspect the Stage A report for this gap",
    }

def _byte_coverage_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    coverage = _contract_constraint(contract, "executable_byte_coverage")
    items = []
    for side in ("original", "candidate"):
        payload = coverage.get(side)
        if not isinstance(payload, dict):
            continue
        for gap in payload.get("gaps", []):
            if not isinstance(gap, dict):
                continue
            rva_start = _safe_int(gap.get("rva_start"))
            rva_end = _safe_int(gap.get("rva_end"))
            if rva_start is None or rva_end is None:
                continue
            items.append(
                {
                    "gap_id": f"bytes:{side}:rva-{rva_start:08x}-{rva_end:08x}",
                    "family": "executable_span_coverage",
                    "category": "unclassified_executable_bytes",
                    "severity": "incomplete",
                    "location": {"side": side, "rva_start": rva_start, "rva_end": rva_end, "size": rva_end - rva_start},
                    "expected": "every executable byte is classified as code, verified padding, or verified zero-fill",
                    "observed": "unclassified executable byte span",
                    "example": gap,
                    "cause_hint": "Stage A has no code mapping or non-code waiver for this executable span",
                    "next_action": "map the span as code or add a verifiable padding/zero-fill waiver",
                }
            )
    return items

def _proof_inventory_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    obligations = proof.get("obligations") if isinstance(proof.get("obligations"), list) else []
    items = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        status = str(obligation.get("status") or "")
        if status in {"proved", "waived_noncode"}:
            continue
        obligation_id = str(obligation.get("id") or "unknown")
        items.append(
            {
                "gap_id": f"obligation:{_safe_gap_part(obligation_id)}",
                "family": "proof_inventory",
                "category": f"obligation_{status or 'unknown'}",
                "severity": "violated" if status == "failed" else "incomplete",
                "location": {"obligation_id": obligation_id, "kind": obligation.get("kind")},
                "expected": "proved or explicitly waived non-code obligation",
                "observed": status or "missing status",
                "example": obligation,
                "cause_hint": "Stage A final pass is blocked by this proof obligation",
                "next_action": "repair the candidate, mapping, waiver, or proof rule until this obligation closes",
            }
        )
    return items

def _dedupe_gaps(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for gap in gaps:
        gap_id = str(gap.get("gap_id") or "")
        if gap_id and gap_id not in by_id:
            by_id[gap_id] = gap
    return list(by_id.values())

def _ranked_gap_next_work(gaps: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        gaps,
        key=lambda gap: (
            _gap_family_rank(str(gap.get("family") or "")),
            -_gap_severity_rank(gap.get("severity")),
            str(gap.get("gap_id") or ""),
        ),
    )
    return [
        {
            "gap_id": gap.get("gap_id"),
            "family": gap.get("family"),
            "category": gap.get("category"),
            "severity": gap.get("severity"),
            "next_action": gap.get("next_action"),
            "cause_hint": gap.get("cause_hint"),
        }
        for gap in ranked[:limit]
    ]

def _gap_family_rank(family: str) -> int:
    order = {
        "validation_report_artifact_binding": 0,
        "binary_faithfulness": 1,
        "normalization_assumptions": 1,
        "executable_span_coverage": 2,
        "function_ranges": 3,
        "cfg_blocks": 4,
        "roots_and_jump_targets": 5,
        "import_thunks": 6,
        "padding_alignment": 6,
        "semantic_transfer": 6,
        "semantic_region": 6,
        "semantic_regions": 6,
        "semantic_cluster": 6,
        "proof_inventory": 7,
    }
    return order.get(family, 99)

def _issue_family(obligation_id: str, category: str) -> str:
    text = f"{obligation_id} {category}".lower()
    for family, constraint in _REFERENCE_CONTRACT_FAMILY_KEYS:
        if family in text or constraint in text:
            return family
    if "validation-report" in text or "validation_report" in text:
        return "validation_report_artifact_binding"
    if "layout" in text or "section" in text or "import" in text or "image_base" in text:
        return "binary_faithfulness"
    if "waiver" in text or "padding" in text:
        return "padding_alignment"
    if "mapping" in text or "map" in text:
        return "cfg_blocks"
    return "proof_inventory"

def _obligation_family(obligation_id: str) -> str:
    text = obligation_id.lower()
    if text.startswith("block:") or text.startswith("cfg:"):
        return "cfg_blocks"
    if text.startswith("reachability:") or "jump" in text:
        return "roots_and_jump_targets"
    if text.startswith("layout:"):
        return "binary_faithfulness"
    if "waiver" in text or "noncode" in text:
        return "padding_alignment"
    return "proof_inventory"

def _load_reference_contract_sidecars(contract: dict[str, Any], contract_path: Path) -> dict[str, Any]:
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    contract_ref = _reference_sidecar_contract_ref(contract_path)
    result: dict[str, Any] = {}
    builders = {
        "coverage_gaps": _reference_coverage_gaps_sidecar,
        "obligation_index": _reference_obligation_index_sidecar,
        "contract_summary": _reference_contract_summary_sidecar,
        "abi_callsites": _reference_abi_callsites_sidecar,
    }
    for name, builder in builders.items():
        path_text = sidecars.get(name, {}).get("path") if isinstance(sidecars.get(name), dict) else None
        path = _resolve_contract_sidecar_path(contract_path, path_text, name)
        try:
            result[name] = _load_json(path) if path.is_file() else builder(contract, contract_ref)
        except StageAInputError:
            result[name] = builder(contract, contract_ref)
    return result

def _stage_a_smoke_contract_issues(contract: Any, contract_path: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(contract, dict) or contract.get("format") != "stage-a-reference-contract-v1":
        return [
            _incomplete_record(
                category="invalid_reference_contract_format",
                obligation_id="stage-a-smoke-contract:format",
                blocker="reference contract JSON does not have format stage-a-reference-contract-v1",
                next_action="regenerate the Stage A reference contract",
            )
        ]
    for family in contract.get("families", []):
        if not isinstance(family, dict):
            continue
        status = family.get("status")
        if status not in {"satisfied", "incomplete", "not_applicable", "violated"}:
            issues.append(
                _incomplete_record(
                    category="invalid_family_status",
                    obligation_id=f"stage-a-smoke-contract:family:{family.get('family')}",
                    blocker="Stage A contract family has a non-proof status",
                    next_action="regenerate the contract with current Stage A tooling",
                    details={"family": family.get("family"), "status": status},
                )
            )
    issues.extend(_stage_a_smoke_artifact_issues(contract, contract_path))
    issues.extend(_stage_a_smoke_sidecar_issues(contract, contract_path))
    for marker in _unchecked_marker_paths(contract):
        issues.append(
            _incomplete_record(
                category="unchecked_lean_marker",
                obligation_id=f"stage-a-smoke-contract:lean:{marker}",
                blocker="reference contract contains an unchecked Lean marker",
                next_action="rerun Stage A validation until Lean final-pass evidence is checked",
            )
        )
    return issues

def _stage_a_smoke_artifact_issues(
    contract: dict[str, Any],
    contract_path: Path,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    inputs = contract.get("inputs") if isinstance(contract.get("inputs"), dict) else {}
    for name in ("original", "candidate", "mapping", "layout_contract"):
        artifact = inputs.get(name)
        if not isinstance(artifact, dict) or artifact.get("path") in {None, ""}:
            continue
        issues.extend(
            _stage_a_smoke_artifact_hash_issues(
                name,
                artifact,
                relative_to=contract_path.parent,
            )
        )
    validation_report = inputs.get("validation_report")
    if isinstance(validation_report, dict):
        files = validation_report.get("files")
        if isinstance(files, dict):
            for name, artifact in files.items():
                if isinstance(artifact, dict):
                    issues.extend(
                        _stage_a_smoke_artifact_hash_issues(
                            f"validation_report:{name}",
                            artifact,
                            relative_to=contract_path.parent,
                        )
                    )
        else:
            issues.extend(
                _stage_a_smoke_artifact_hash_issues(
                    "validation_report",
                    validation_report,
                    relative_to=contract_path.parent,
                )
            )
    return issues

def _stage_a_smoke_artifact_hash_issues(
    name: str,
    artifact: dict[str, Any],
    *,
    relative_to: Path,
) -> list[dict[str, Any]]:
    path_text = artifact.get("path")
    if not isinstance(path_text, str) or not path_text:
        return []
    path = Path(path_text)
    if not path.is_absolute():
        path = relative_to / path
    if not path.exists():
        return [
            _incomplete_record(
                category="missing_bound_artifact",
                obligation_id=f"stage-a-smoke-contract:artifact:{name}",
                blocker="a reference-contract-bound artifact no longer exists",
                next_action="regenerate the contract from current artifacts",
                details={"path": path_text},
            )
        ]
    expected_sha = artifact.get("sha256")
    if expected_sha is None or path.is_dir():
        return []
    actual_sha = sha256_file(path)
    if actual_sha == expected_sha:
        return []
    return [
        _incomplete_record(
            category="stale_bound_artifact",
            obligation_id=f"stage-a-smoke-contract:artifact:{name}",
            blocker="a reference-contract-bound artifact hash no longer matches",
            next_action="rerun Stage A validation and export a fresh reference contract",
            details={"path": path_text, "expected": expected_sha, "actual": actual_sha},
        )
    ]

def _stage_a_smoke_sidecar_issues(contract: dict[str, Any], contract_path: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    contract_sha = sha256_file(contract_path) if contract_path.is_file() else None
    for name in ("coverage_gaps", "obligation_index", "contract_summary", "abi_callsites"):
        path_text = sidecars.get(name, {}).get("path") if isinstance(sidecars.get(name), dict) else None
        if not isinstance(path_text, str) or not path_text:
            issues.append(
                _incomplete_record(
                    category="missing_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker="reference contract does not identify a required diagnostic sidecar",
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                )
            )
            continue
        path = _resolve_contract_sidecar_path(contract_path, path_text, name)
        if not path.is_file():
            issues.append(
                _incomplete_record(
                    category="missing_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker="required diagnostic sidecar does not exist",
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                    details={"path": path_text},
                )
            )
            continue
        try:
            payload = _load_json(path)
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker=str(exc),
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                )
            )
            continue
        sidecar_contract = payload.get("reference_contract") if isinstance(payload, dict) else {}
        if not isinstance(sidecar_contract, dict) or sidecar_contract.get("sha256") != contract_sha:
            issues.append(
                _incomplete_record(
                    category="stale_contract_sidecar",
                    obligation_id=f"stage-a-smoke-contract:sidecar:{name}",
                    blocker="diagnostic sidecar is not hash-bound to this reference contract",
                    next_action="rerun stage-a-export-reference-contract with current tooling",
                    details={"path": path_text, "expected": contract_sha, "actual": sidecar_contract.get("sha256") if isinstance(sidecar_contract, dict) else None},
                )
            )
    return issues

def _resolve_contract_sidecar_path(contract_path: Path, path_text: Any, name: str) -> Path:
    if isinstance(path_text, str) and path_text:
        path = Path(path_text)
        return path if path.is_absolute() else contract_path.parent / path
    return contract_path.parent / f"{name}.json"

def _unchecked_marker_paths(contract: dict[str, Any]) -> list[str]:
    proof = _contract_constraint(contract, "proof_obligation_inventory")
    lean = proof.get("lean") if isinstance(proof.get("lean"), dict) else {}
    markers: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if "unchecked" in str(key).lower() and child not in (None, False, 0, "", [], {}):
                    markers.append(child_path)
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(lean, "lean")
    return sorted(set(markers))

def _matches_focus(item: Any, focus_lower: str) -> bool:
    return focus_lower in json.dumps(item, sort_keys=True, default=str).lower()

def _gap_severity_rank(value: Any) -> int:
    return {"incomplete": 1, "violated": 2, "failed": 2, "fail": 2}.get(str(value or ""), 0)

def _layout_contract_from_mapping_payload(payload: Any, mapping: Path | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    embedded = payload.get("layout_contract")
    if isinstance(embedded, dict):
        return embedded
    if not isinstance(embedded, str) or not embedded:
        return None
    path = Path(embedded)
    if not path.is_absolute() and mapping is not None:
        path = mapping.parent / path
    try:
        return _load_json(path)
    except StageAInputError:
        return None

def _load_stage_a_validation_report(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    report = path if path.is_dir() else path.parent
    explicit_prepared = path.is_file() and path.name == "prepared-proof.json"
    if explicit_prepared:
        verdict_path = report / "verdict.json"
        prepared_path = path
    else:
        verdict_path = report / "verdict.json" if path.is_dir() else path
        prepared_path = report / "prepared-proof.json"
    proof_ir_path = report / "relational-proof-ir.json"
    if not proof_ir_path.is_file():
        raise StageAInputError(
            "relational v3 Stage A report must contain relational-proof-ir.json"
        )
    proof_ir = _load_json(proof_ir_path)
    report_kind = "relational_v3"
    if verdict_path.is_file() and not explicit_prepared:
        verdict = _load_json(verdict_path)
        report_manifest_sha256 = sha256_file(verdict_path)
    elif prepared_path.is_file():
        prepared = _load_json(prepared_path)
        if (
            prepared.get("format") != "stage-a-prepared-relational-v1"
            or prepared.get("status") != "prepared"
            or prepared.get("profile") != "x86-pe32-lean-relational-v3"
            or prepared.get("model") != REFERENCE_CONTRACT_MODEL_ID
        ):
            raise StageAInputError(
                "reference contracts require a relational v3 prepared proof"
            )
        report_kind = "relational_v3_prepared"
        report_manifest_sha256 = sha256_file(prepared_path)
        verdict = {
            "format": "stage-a-relational-prepared-verdict-v1",
            "verdict": "incomplete",
            "profile": prepared["profile"],
            "model": prepared["model"],
            "acceptance_authority": False,
            "claim_scope": {
                "kind": "whole_program_observational_equivalence",
                "whole_program_observational_equivalence": False,
                "acceptance_eligible": False,
            },
            "original": {"sha256": prepared.get("original_sha256")},
            "candidate": {"sha256": prepared.get("candidate_sha256")},
            "proof_ir_sha256": prepared.get("proof_ir_sha256"),
            "interface_manifest_sha256": prepared.get(
                "interface_manifest_sha256"
            ),
            "relation_contract_sha256": prepared.get("relation_contract_sha256"),
            "semantic_ir_sha256": prepared.get("semantic_ir_sha256"),
            "product_graph_sha256": prepared.get("product_graph_sha256"),
            "whole_program_acceptance_sha256": prepared.get(
                "whole_program_acceptance_sha256"
            ),
            "composition_progress_sha256": prepared.get(
                "composition_progress_sha256"
            ),
            "proof": {"theorem": None, "lean": {"status": "not_built"}},
        }
    else:
        raise StageAInputError(
            "Stage A report must contain verdict.json or prepared-proof.json"
        )
    if verdict.get("profile") != "x86-pe32-lean-relational-v3":
        raise StageAInputError("reference contracts require a relational v3 Stage A report")
    payload: dict[str, Any] = {
        "kind": report_kind,
        "path": str(report),
        "verdict": verdict,
        "proof_ir": proof_ir,
        "report_manifest_sha256": report_manifest_sha256,
        "proof_ir_file_sha256": sha256_file(proof_ir_path),
        "artifacts": {},
    }
    for name in (
        "stage-a-interface-manifest.json",
        "relation-contract.json",
        "relational-semantic-ir.json",
        "relational-product-graph.json",
        "whole-program-acceptance.json",
        "composition-progress.json",
    ):
        artifact_path = report / name
        if artifact_path.is_file():
            payload["artifacts"][name] = {
                "payload": _load_json(artifact_path),
                "sha256": sha256_file(artifact_path),
            }
    return payload

def _reference_validation_report_binding_constraint(
    *,
    payload: dict[str, Any] | None,
    original: StageABinary,
    candidate: StageABinary | None,
    mapping_payload: Any,
    model: str,
) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "blocker": "no relational v3 Stage A report was provided",
            "next_action": "run stage-a-prove and export the contract with --validation-report",
            "issues": [],
        }

    verdict = payload.get("verdict") if isinstance(payload.get("verdict"), dict) else {}
    proof_ir = payload.get("proof_ir") if isinstance(payload.get("proof_ir"), dict) else {}
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
    issues: list[dict[str, Any]] = []
    checks: dict[str, bool] = {}

    def check(name: str, condition: bool, blocker: str, details: dict[str, Any]) -> None:
        checks[name] = condition
        if condition:
            return
        issues.append(
            _incomplete_record(
                category="validation_report_binding_mismatch",
                obligation_id=f"reference-contract:validation-report-binding:{name}",
                blocker=blocker,
                next_action="regenerate the relational v3 report from the exact binaries and relation contract",
                details=details,
            )
        )

    check(
        "profile",
        verdict.get("profile") == "x86-pe32-lean-relational-v3",
        "Stage A report is not relational v3",
        {"actual": verdict.get("profile")},
    )
    check(
        "model",
        verdict.get("model") == model == REFERENCE_CONTRACT_MODEL_ID,
        "Stage A report and reference contract use different relational models",
        {"expected": REFERENCE_CONTRACT_MODEL_ID, "report": verdict.get("model"), "requested": model},
    )
    verdict_original = verdict.get("original") if isinstance(verdict.get("original"), dict) else {}
    verdict_candidate = verdict.get("candidate") if isinstance(verdict.get("candidate"), dict) else {}
    check(
        "original",
        verdict_original.get("sha256") == original.sha256
        and proof_ir.get("original", {}).get("sha256") == original.sha256,
        "Stage A report is bound to a different original binary",
        {
            "expected": original.sha256,
            "verdict": verdict_original.get("sha256"),
            "proof_ir": proof_ir.get("original", {}).get("sha256"),
        },
    )
    expected_candidate = candidate.sha256 if candidate is not None else None
    check(
        "candidate",
        candidate is None
        or (
            verdict_candidate.get("sha256") == expected_candidate
            and proof_ir.get("candidate", {}).get("sha256") == expected_candidate
        ),
        "Stage A report is bound to a different candidate binary",
        {
            "expected": expected_candidate,
            "verdict": verdict_candidate.get("sha256"),
            "proof_ir": proof_ir.get("candidate", {}).get("sha256"),
        },
    )
    check(
        "proof_ir",
        payload.get("proof_ir_file_sha256") == verdict.get("proof_ir_sha256"),
        "relational-proof-ir.json does not match the verdict hash",
        {
            "expected": verdict.get("proof_ir_sha256"),
            "actual": payload.get("proof_ir_file_sha256"),
        },
    )

    artifact_hash_fields = {
        "stage-a-interface-manifest.json": "interface_manifest_sha256",
        "relation-contract.json": "relation_contract_sha256",
        "relational-semantic-ir.json": "semantic_ir_sha256",
        "relational-product-graph.json": "product_graph_sha256",
        "whole-program-acceptance.json": "whole_program_acceptance_sha256",
        "composition-progress.json": "composition_progress_sha256",
    }
    for artifact_name, verdict_field in artifact_hash_fields.items():
        expected = verdict.get(verdict_field)
        artifact = artifacts.get(artifact_name) if isinstance(artifacts.get(artifact_name), dict) else {}
        actual = artifact.get("sha256")
        check(
            artifact_name.removesuffix(".json").replace("-", "_"),
            expected is None or actual == expected,
            f"{artifact_name} does not match the hash recorded by verdict.json",
            {"expected": expected, "actual": actual},
        )

    map_original = (
        mapping_payload.get("original")
        if isinstance(mapping_payload, dict) and isinstance(mapping_payload.get("original"), dict)
        else {}
    )
    map_candidate = (
        mapping_payload.get("candidate")
        if isinstance(mapping_payload, dict) and isinstance(mapping_payload.get("candidate"), dict)
        else {}
    )
    check(
        "mapping",
        not isinstance(mapping_payload, dict)
        or (not map_original and not map_candidate)
        or (
            map_original.get("sha256") == original.sha256
            and (candidate is None or map_candidate.get("sha256") == expected_candidate)
        ),
        "block map is bound to different binaries than the relational v3 report",
        {
            "original": map_original.get("sha256"),
            "candidate": map_candidate.get("sha256"),
        },
    )

    return {
        "status": "satisfied" if not issues else "incomplete",
        "evidence_kind": "relational-v3-artifact-binding",
        "report": payload.get("path"),
        "report_kind": payload.get("kind"),
        "profile": verdict.get("profile"),
        "model": verdict.get("model"),
        "verdict": verdict.get("verdict"),
        "acceptance_authority": verdict.get("acceptance_authority"),
        "checks": checks,
        "issues": issues,
        "blocker": None if not issues else "relational v3 report artifact binding is incomplete",
        "next_action": None if not issues else "regenerate the relational v3 report and reference contract",
    }

def _reference_pe_layout_constraint(
    *,
    original: StageABinary,
    candidate: StageABinary | None,
    layout_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    if candidate is None:
        return {
            "status": "derived",
            "evidence_kind": "pefile",
            "scope": "original",
            "sections": _section_permission_signature(original),
            "imports": _import_signature(original),
            "relocations": _binary_relocation_summary(original),
            "image_base": original.image_base,
        }
    issues = _layout_issues(original, candidate, layout_contract)
    return {
        "status": "satisfied" if not issues else ("failed" if any(issue.get("severity") == "fail" for issue in issues) else "incomplete"),
        "evidence_kind": "stage-a-layout-model",
        "scope": "original-candidate-pair",
        "facts": {
            "matching_machine": original.machine == candidate.machine,
            "matching_bitness": original.bitness == candidate.bitness,
            "matching_section_rvas": _section_rva_start_signature(original) == _section_rva_start_signature(candidate),
            "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
            "matching_imports": _import_signature(original) == _import_signature(candidate),
            "matching_image_base": original.image_base == candidate.image_base,
        },
        "original": {
            "sections": _section_permission_signature(original),
            "imports": _import_signature(original),
            "relocations": _binary_relocation_summary(original),
            "image_base": original.image_base,
        },
        "candidate": {
            "sections": _section_permission_signature(candidate),
            "imports": _import_signature(candidate),
            "relocations": _binary_relocation_summary(candidate),
            "image_base": candidate.image_base,
        },
        "issues": issues,
    }

def _reference_map_constraints(
    *,
    original: StageABinary,
    candidate: StageABinary | None,
    mapping_payload: Any,
) -> dict[str, Any]:
    if mapping_payload is None:
        missing = _reference_missing_map_constraint()
        return {
            "issues": [],
            "mappings": [],
            "verified_waivers": [],
            "executable_byte_coverage": missing,
            "function_ranges": missing,
            "basic_blocks_and_cfg": missing,
            "roots_and_jump_tables": missing,
            "padding_alignment": missing,
        }

    mappings, waivers, map_issues = _parse_block_map(mapping_payload, original)
    map_issues.extend(_generated_map_issues(mapping_payload))
    verified_waivers: list[NonCodeWaiver] = []
    waiver_obligations: list[dict[str, Any]] = []
    if candidate is not None:
        verified_waivers, waiver_obligations = _waiver_obligations(original, candidate, waivers)
    elif waivers:
        map_issues.append(
            _incomplete_record(
                category="unverified_noncode_waiver",
                obligation_id="reference-contract:waivers",
                blocker="non-code waivers require a candidate binary before Stage A can verify pairwise padding",
                next_action="export the reference contract with --candidate when mapping waivers are present",
            )
        )
    for obligation in waiver_obligations:
        if obligation.get("status") == "incomplete" and isinstance(obligation.get("incomplete"), dict):
            map_issues.append(obligation["incomplete"])

    map_status = _reference_map_status(mapping_payload, map_issues)
    return {
        "issues": map_issues,
        "mappings": mappings,
        "verified_waivers": verified_waivers,
        "executable_byte_coverage": {
            "status": "satisfied"
            if map_status == "satisfied"
            and not _reference_coverage_side("original", original, mappings, verified_waivers)["gaps"]
            and (candidate is None or not _reference_coverage_side("candidate", candidate, mappings, verified_waivers)["gaps"])
            else "incomplete",
            "evidence_kind": "stage-a-block-map",
            "original": _reference_coverage_side("original", original, mappings, verified_waivers),
            "candidate": _reference_coverage_side("candidate", candidate, mappings, verified_waivers) if candidate is not None else None,
        },
        "function_ranges": _reference_function_ranges(mappings, map_status),
        "basic_blocks_and_cfg": _reference_basic_blocks_and_cfg(original, candidate, mappings, map_status),
        "roots_and_jump_tables": _reference_roots_and_jump_tables(mappings, map_status),
        "padding_alignment": _reference_padding_alignment(waivers, verified_waivers, waiver_obligations, map_status),
    }

def _reference_missing_map_constraint() -> dict[str, Any]:
    return {
        "status": "not_provided",
        "evidence_kind": "none",
        "blocker": "no Stage A block map was provided",
        "next_action": "generate a Stage A block map and re-export the reference contract",
    }

def _reference_map_status(mapping_payload: Any, issues: list[dict[str, Any]]) -> str:
    if any(issue.get("status") == "failed" or issue.get("severity") == "fail" for issue in issues):
        return "failed"
    if issues:
        return "incomplete"
    if isinstance(mapping_payload, dict) and mapping_payload.get("status") not in {None, "pass"}:
        return "incomplete"
    return "satisfied"

def _reference_coverage_side(
    side: str,
    binary: StageABinary,
    mappings: list[BlockMapping],
    waivers: list[NonCodeWaiver],
) -> dict[str, Any]:
    mapped_ranges = [
        mapped.original if side == "original" else mapped.candidate
        for mapped in mappings
        if mapped.kind == "code"
    ]
    waiver_ranges = [
        BlockSide(waiver.rva_start, waiver.rva_end)
        for waiver in waivers
        if waiver.binary in {side, "both"}
    ]
    classified = mapped_ranges + waiver_ranges
    executable_sections = [section for section in binary.sections if section.executable]
    gaps = [
        gap
        for section in executable_sections
        for gap in _gaps(section.rva_start, section.rva_end, classified)
    ]
    executable_bytes = sum(section.rva_end - section.rva_start for section in executable_sections)
    classified_bytes = sum(item.rva_end - item.rva_start for item in _merged_ranges(classified))
    return {
        "status": "satisfied" if not gaps else "incomplete",
        "binary": side,
        "executable_bytes": executable_bytes,
        "classified_bytes": min(classified_bytes, executable_bytes),
        "mapped_code_ranges": [_range_report(item) for item in mapped_ranges],
        "waived_noncode_ranges": [_range_report(item) for item in waiver_ranges],
        "gaps": [_range_report(item) for item in gaps],
    }

def _merged_ranges(ranges: list[BlockSide]) -> list[BlockSide]:
    merged: list[BlockSide] = []
    for item in sorted(ranges, key=lambda value: (value.rva_start, value.rva_end)):
        if not merged or item.rva_start > merged[-1].rva_end:
            merged.append(item)
            continue
        merged[-1] = BlockSide(merged[-1].rva_start, max(merged[-1].rva_end, item.rva_end))
    return merged

def _reference_function_ranges(mappings: list[BlockMapping], map_status: str) -> dict[str, Any]:
    functions: dict[str, dict[str, Any]] = {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        name = source.get("function") if isinstance(source.get("function"), str) else ""
        if not name:
            continue
        entry = functions.setdefault(
            name,
            {
                "name": name,
                "original": {"rva_start": mapped.original.rva_start, "rva_end": mapped.original.rva_end},
                "candidate": {"rva_start": mapped.candidate.rva_start, "rva_end": mapped.candidate.rva_end},
                "block_ids": [],
            },
        )
        entry["original"]["rva_start"] = min(entry["original"]["rva_start"], mapped.original.rva_start)
        entry["original"]["rva_end"] = max(entry["original"]["rva_end"], mapped.original.rva_end)
        entry["candidate"]["rva_start"] = min(entry["candidate"]["rva_start"], mapped.candidate.rva_start)
        entry["candidate"]["rva_end"] = max(entry["candidate"]["rva_end"], mapped.candidate.rva_end)
        entry["block_ids"].append(mapped.id)
    return {
        "status": map_status if functions else "incomplete",
        "evidence_kind": "linker-map-capstone-block-map",
        "functions": sorted(functions.values(), key=lambda item: item["name"]),
    }

def _reference_basic_blocks_and_cfg(
    original: StageABinary,
    candidate: StageABinary | None,
    mappings: list[BlockMapping],
    map_status: str,
) -> dict[str, Any]:
    blocks = []
    cfg_edges = []
    original_symbol_aliases = _coff_symbol_aliases_by_rva(original)
    candidate_symbol_aliases = _coff_symbol_aliases_by_rva(candidate) if candidate is not None else {}
    for mapped in mappings:
        source = _mapping_source(mapped)
        proof = mapped.source.get("proof") if isinstance(mapped.source.get("proof"), dict) else {}
        block = {
            "id": mapped.id,
            "kind": mapped.kind,
            "reachable": mapped.reachable,
            "function": source.get("function"),
            "original": _range_report(mapped.original),
            "candidate": _range_report(mapped.candidate),
            "source_kind": source.get("kind"),
            "proof_rule": proof.get("rule"),
            "byte_identical": source.get("byte_identical"),
        }
        symbol_aliases = {
            "original": _symbol_aliases_for_range(original_symbol_aliases, mapped.original),
            "candidate": _symbol_aliases_for_range(candidate_symbol_aliases, mapped.candidate) if candidate is not None else [],
        }
        if symbol_aliases["original"] or symbol_aliases["candidate"]:
            block["symbol_aliases"] = symbol_aliases
        blocks.append(block)
        if mapped.kind != "code":
            continue
        edge_report = {
            "block_id": mapped.id,
            "original": _direct_cfg_edges(original, mapped.original),
            "candidate": _direct_cfg_edges(candidate, mapped.candidate) if candidate is not None else None,
        }
        cfg_edges.append(edge_report)
    return {
        "status": map_status if blocks else "incomplete",
        "evidence_kind": "capstone-direct-cfg",
        "basic_blocks": blocks,
        "cfg_edges": cfg_edges,
    }

def _symbol_aliases_for_range(symbols_by_rva: dict[int, list[str]], span: BlockSide) -> list[str]:
    aliases: list[str] = []
    for rva in sorted(rva for rva in symbols_by_rva if span.rva_start <= rva < span.rva_end):
        for alias in symbols_by_rva[rva]:
            if alias and alias not in aliases:
                aliases.append(alias)
    return aliases

def _reference_roots_and_jump_tables(mappings: list[BlockMapping], map_status: str) -> dict[str, Any]:
    roots = []
    jump_table_targets = []
    for mapped in mappings:
        for key in ("root", "reachability"):
            value = mapped.source.get(key)
            if isinstance(value, dict):
                roots.append({"block_id": mapped.id, **value})
        for key in ("jump_table_targets", "checked_jump_table_targets"):
            targets = mapped.source.get(key)
            if isinstance(targets, list):
                for target in targets:
                    if isinstance(target, dict):
                        jump_table_targets.append({"block_id": mapped.id, **target})
    return {
        "status": map_status if roots or jump_table_targets else ("not_applicable" if not mappings else "derived"),
        "evidence_kind": "stage-a-reachability-markers",
        "roots": roots,
        "jump_table_targets": jump_table_targets,
    }

def _reference_roots_and_jump_tables_with_abi_targets(
    roots: dict[str, Any],
    abi_callsites: dict[str, Any],
) -> dict[str, Any]:
    updated = dict(roots)
    existing = [
        item
        for item in roots.get("jump_table_targets", [])
        if isinstance(item, dict)
    ]
    targets: dict[tuple[str, int, int], dict[str, Any]] = {}
    for item in existing:
        key = (
            str(item.get("function") or ""),
            _safe_int(item.get("instruction_rva")) or -1,
            _safe_int(item.get("target_rva", item.get("rva"))) or -1,
        )
        targets.setdefault(key, dict(item))
    original = abi_callsites.get("original") if isinstance(abi_callsites.get("original"), dict) else {}
    functions = original.get("functions") if isinstance(original.get("functions"), list) else []
    for function in functions:
        if not isinstance(function, dict):
            continue
        function_name = str(function.get("name") or "")
        switches = function.get("switch_contracts") if isinstance(function.get("switch_contracts"), list) else []
        for switch in switches:
            if not isinstance(switch, dict) or switch.get("evidence_status") != "derived":
                continue
            instruction = switch.get("instruction") if isinstance(switch.get("instruction"), dict) else {}
            instruction_rva = _safe_int(instruction.get("rva"))
            case_targets = switch.get("case_targets") if isinstance(switch.get("case_targets"), list) else []
            by_target: dict[int, list[int]] = {}
            for case in case_targets:
                if not isinstance(case, dict):
                    continue
                target_rva = _safe_int(case.get("target_rva"))
                index = _safe_int(case.get("index"))
                if target_rva is None:
                    continue
                by_target.setdefault(target_rva, [])
                if index is not None:
                    by_target[target_rva].append(index)
            for target_rva, case_indices in sorted(by_target.items()):
                key = (function_name, instruction_rva or -1, target_rva)
                if key in targets:
                    continue
                targets[key] = {
                    "evidence_status": "derived",
                    "kind": "resolved_static_jump_table_target",
                    "function": function_name,
                    "block_id": _block_id_for_instruction(function, instruction),
                    "instruction_rva": instruction_rva,
                    "target_rva": target_rva,
                    "rva": target_rva,
                    "case_indices": sorted(set(case_indices)),
                    "table": switch.get("table"),
                    "source": "capstone-indexed-memory-jump-table",
                }
    updated["jump_table_targets"] = sorted(
        targets.values(),
        key=lambda item: (
            str(item.get("function") or ""),
            _safe_int(item.get("instruction_rva")) or -1,
            _safe_int(item.get("target_rva", item.get("rva"))) or -1,
        ),
    )
    if updated["jump_table_targets"] and updated.get("status") == "not_applicable":
        updated["status"] = "derived"
    return updated

def _reference_import_thunk_constraint(
    original: StageABinary,
    candidate: StageABinary | None,
    map_contract: dict[str, Any],
) -> dict[str, Any]:
    mappings = map_contract.get("mappings", [])
    mapped_thunks = []
    for mapped in mappings:
        source = _mapping_source(mapped)
        if mapped.kind == "import_thunk" or source.get("kind") == "import_thunk":
            mapped_thunks.append(
                {
                    "block_id": mapped.id,
                    "original": _range_report(mapped.original),
                    "candidate": _range_report(mapped.candidate),
                    "source": source,
                }
            )
    return {
        "status": "derived" if original.imports or (candidate is not None and candidate.imports) or mapped_thunks else "not_applicable",
        "evidence_kind": "pe-import-directory-and-block-map",
        "original_imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in original.imports
        ],
        "candidate_imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in candidate.imports
        ]
        if candidate is not None
        else None,
        "mapped_import_thunks": mapped_thunks,
    }

def _reference_abi_callsites_constraint(
    original: StageABinary,
    candidate: StageABinary | None,
    map_contract: dict[str, Any],
) -> dict[str, Any]:
    mappings = [mapped for mapped in map_contract.get("mappings", []) if isinstance(mapped, BlockMapping) and mapped.kind == "code"]
    map_status = str(map_contract.get("function_ranges", {}).get("status") or "incomplete")
    original_functions = _abi_function_evidence(original, mappings, side="original")
    candidate_functions = _abi_function_evidence(candidate, mappings, side="candidate") if candidate is not None else None
    original_callsites = sum(len(item.get("callsites", [])) for item in original_functions)
    candidate_callsites = (
        sum(len(item.get("callsites", [])) for item in candidate_functions)
        if isinstance(candidate_functions, list)
        else None
    )
    payload = {
        "status": map_status if mappings else "incomplete",
        "evidence_kind": "capstone-static-abi-callsites",
        "scope": "original-candidate-pair" if candidate is not None else "original",
        "original": {
            "functions": original_functions,
            "import_prototypes": _abi_import_prototypes(original),
        },
        "candidate": {
            "functions": candidate_functions,
            "import_prototypes": _abi_import_prototypes(candidate),
        }
        if candidate is not None
        else None,
        "counts": {
            "functions": len(original_functions),
            "callsites": original_callsites,
            "candidate_callsites": candidate_callsites,
            "import_prototypes": len(original.imports),
        },
    }
    if candidate is not None:
        comparison_gaps = _contract_candidate_abi_coverage_gaps(payload, payload)
        payload["comparison_gaps"] = comparison_gaps
        payload["profile_comparison_gaps"] = _stage_a_abi_profile_comparison_gaps(comparison_gaps)
    return payload

def _reference_padding_alignment(
    waivers: list[NonCodeWaiver],
    verified_waivers: list[NonCodeWaiver],
    waiver_obligations: list[dict[str, Any]],
    map_status: str,
) -> dict[str, Any]:
    if not waivers:
        return {"status": "not_applicable", "evidence_kind": "stage-a-waivers", "waivers": [], "obligations": []}
    status = map_status if len(waivers) == len(verified_waivers) and all(item.get("status") != "incomplete" for item in waiver_obligations) else "incomplete"
    return {
        "status": status,
        "evidence_kind": "verified-padding-bytes",
        "waivers": [
            {
                "id": waiver.id,
                "binary": waiver.binary,
                "rva_start": waiver.rva_start,
                "rva_end": waiver.rva_end,
                "reason": waiver.reason,
                "verified": waiver in verified_waivers,
            }
            for waiver in waivers
        ],
        "obligations": waiver_obligations,
    }

def _reference_layout_normalization_constraint(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "blocker": "no Stage A layout contract was provided",
            "next_action": "export a layout contract from stage-a-generate-map or pass --layout-contract",
        }
    required = payload.get("required_facts", []) if isinstance(payload.get("required_facts"), list) else []
    facts = payload.get("facts", {}) if isinstance(payload.get("facts"), dict) else {}
    missing = [fact for fact in required if fact not in facts]
    unsatisfied = [fact for fact in required if facts.get(fact) is not True]
    status = "satisfied" if not missing and not unsatisfied else "incomplete"
    return {
        "status": status,
        "evidence_kind": "stage-a-layout-contract",
        "contract": payload,
        "missing_required_facts": missing,
        "unsatisfied_required_facts": unsatisfied,
    }

def _reference_proof_obligation_inventory(payload: dict[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {
            "status": "not_provided",
            "evidence_kind": "none",
            "counts": {"obligations": 0},
            "obligations": [],
            "verdict": None,
        }
    verdict = payload.get("verdict") if isinstance(payload.get("verdict"), dict) else {}
    proof_ir = payload.get("proof_ir") if isinstance(payload.get("proof_ir"), dict) else {}
    obligations = proof_ir.get("obligations") if isinstance(proof_ir.get("obligations"), list) else []
    inventory = [
        {
            "id": str(item.get("id") or ""),
            "kind": str(item.get("kind") or ""),
            "status": str(item.get("status") or ""),
            "evidence": item.get("evidence"),
            "blocker": item.get("blocker"),
            "next_action": item.get("next_action"),
        }
        for item in obligations
        if isinstance(item, dict)
    ]
    lean = verdict.get("lean_audit")
    final_pass_allowed = (
        isinstance(lean, dict)
        and lean.get("status") == "checked"
        and verdict.get("acceptance_authority") == "whole_program_lean"
        and verdict.get("claim_scope", {}).get("acceptance_eligible") is True
    )
    status = (
        "satisfied"
        if verdict.get("verdict") == "pass"
        and proof_ir.get("status") == "satisfied"
        and final_pass_allowed
        else "incomplete"
    )
    by_status: dict[str, int] = {}
    for obligation in inventory:
        obligation_status = str(obligation.get("status") or "unknown")
        by_status[obligation_status] = by_status.get(obligation_status, 0) + 1
    return {
        "status": status,
        "evidence_kind": "relational-v3-proof-ir",
        "report": payload.get("path"),
        "verdict": verdict.get("verdict"),
        "final_pass_allowed": final_pass_allowed,
        "lean": lean if isinstance(lean, dict) else {},
        "counts": {"obligations": len(inventory), "by_status": by_status},
        "obligations": inventory,
    }

def _reference_constraint_issues(constraints: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for name, constraint in constraints.items():
        if not isinstance(constraint, dict):
            continue
        if constraint.get("status") in {"satisfied", "derived", "not_applicable"}:
            continue
        issues.append(
            _incomplete_record(
                category="reference_contract_constraint_incomplete",
                obligation_id=f"reference-contract:{name}",
                blocker=f"Stage A reference contract constraint {name!r} is not closed",
                next_action="provide the missing Stage A evidence or inspect the constraint details",
                details={"status": constraint.get("status")},
            )
        )
    return issues

def _reference_contract_status(constraints: dict[str, Any], issues: list[dict[str, Any]]) -> str:
    if any(issue.get("status") == "failed" or issue.get("severity") == "fail" for issue in issues):
        return "fail"
    if issues:
        return "incomplete"
    proof = constraints.get("proof_obligation_inventory")
    return "pass" if isinstance(proof, dict) and proof.get("status") == "satisfied" else "incomplete"

def _tool_versions() -> dict[str, Any]:
    z3 = _import_z3()
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "capstone": ".".join(str(part) for part in capstone.cs_version()),
        "pefile": getattr(pefile, "__version__", "unknown"),
        "z3": z3.get_version_string() if z3 is not None else "unavailable",
        "lean": shutil.which("lean") or "unavailable",
    }

__all__ = [
    '_ORDINARY_CHECKED_DECODER',
    '_ORDINARY_CHECKED_EXECUTOR',
    '_REFERENCE_CONTRACT_FAMILY_KEYS',
    '_SEMANTIC_X87_SINGLETON_MNEMONICS',
    '_X87_PHYSICAL_OBSERVABLE_FIELDS',
    '_X87_REPLAY_OBLIGATION_MODEL',
    '_X87_SINGLETON_CHECKED_DECODER',
    '_X87_SINGLETON_CHECKED_EXECUTOR',
    '_binary_layout',
    '_binary_reference_layout',
    '_binary_relocation_summary',
    '_block_cfg_contract',
    '_block_for_gap',
    '_block_memory_access_summary',
    '_byte_coverage_gap_items',
    '_contract_candidate_validation_artifact',
    '_contract_candidate_validation_summary',
    '_dedupe_gaps',
    '_dedupe_unit_rows',
    '_fallback_reference_semantic_contract_payloads',
    '_family_for_cluster',
    '_function_contract_next_action',
    '_function_for_gap',
    '_function_names_by_block',
    '_gap_family_rank',
    '_gap_from_issue',
    '_gap_severity_rank',
    '_import_thunk_cluster_contracts',
    '_issue_family',
    '_jump_target_cluster_contracts',
    '_layout_contract_from_mapping_payload',
    '_load_contract_candidate_validation',
    '_load_json',
    '_load_json_or',
    '_load_jsonl_or',
    '_load_optional_json',
    '_load_reference_contract_sidecars',
    '_load_reference_unit_contract_sidecars',
    '_load_stage_a_validation_report',
    '_matches_focus',
    '_matching_unit_contracts',
    '_merged_ranges',
    '_obligation_family',
    '_proof_family_status',
    '_proof_inventory_gap_items',
    '_ranked_gap_next_work',
    '_reference_abi_callsites_constraint',
    '_reference_abi_callsites_sidecar',
    '_reference_artifact_display_path',
    '_reference_basic_blocks_and_cfg',
    '_reference_block_contracts',
    '_reference_cluster_contracts',
    '_reference_constraint_issues',
    '_reference_contract_families',
    '_reference_contract_gap_items',
    '_reference_contract_inputs',
    '_reference_contract_sidecar_paths',
    '_reference_contract_status',
    '_reference_contract_summary_sidecar',
    '_reference_coverage_gaps_sidecar',
    '_reference_coverage_side',
    '_reference_family_counts',
    '_reference_function_contracts',
    '_reference_function_ranges',
    '_reference_import_thunk_constraint',
    '_reference_input_artifact',
    '_reference_layout_normalization_constraint',
    '_reference_map_constraints',
    '_reference_map_status',
    '_reference_missing_map_constraint',
    '_reference_obligation_index_sidecar',
    '_reference_padding_alignment',
    '_reference_pe_layout_constraint',
    '_reference_proof_obligation_inventory',
    '_reference_proof_obligation_inventory_with_semantic_regions',
    '_reference_repair_units_sidecar',
    '_reference_roots_and_jump_tables',
    '_reference_roots_and_jump_tables_with_abi_targets',
    '_reference_semantic_contract_payloads',
    '_reference_semantic_region_contracts_constraint',
    '_reference_semantic_region_unit_contracts',
    '_reference_sidecar_contract_ref',
    '_reference_source_obligations_sidecar',
    '_reference_unit_contract_artifact',
    '_reference_unit_contract_dir',
    '_reference_unit_contract_paths',
    '_reference_unit_contract_payloads',
    '_reference_validation_report_artifact',
    '_reference_validation_report_binding_constraint',
    '_repair_class_for_gap',
    '_repair_unit_from_cluster',
    '_repair_unit_from_gap',
    '_repair_unit_priority',
    '_repair_units_from_semantic_payload',
    '_resolve_contract_sidecar_path',
    '_semantic_call_register_inputs_json',
    '_semantic_call_stack_inputs_json',
    '_semantic_call_summary',
    '_semantic_call_summary_contracts',
    '_semantic_call_summary_next_action',
    '_semantic_cluster_contracts',
    '_semantic_cluster_status',
    '_semantic_coverage_blocker',
    '_semantic_coverage_blockers',
    '_semantic_coverage_counts',
    '_semantic_coverage_families',
    '_semantic_coverage_family_rank',
    '_semantic_coverage_next_work',
    '_semantic_coverage_sample',
    '_semantic_disassemble_block',
    '_semantic_edge_conditions',
    '_semantic_effects_from_observables',
    '_semantic_expr_json',
    '_semantic_external_event_json',
    '_semantic_fault_json',
    '_semantic_fpu_state_from_observables',
    '_semantic_initial_instruction_observables',
    '_semantic_instruction_effect_blocker',
    '_semantic_instruction_effect_delta',
    '_semantic_json_contains_op',
    '_semantic_json_sha256',
    '_semantic_memory_event_json',
    '_semantic_memory_frame_contracts',
    '_semantic_memory_frame_for_access',
    '_semantic_ordered_event_json',
    '_semantic_outcome_json',
    '_semantic_pre_state',
    '_semantic_repair_class',
    '_semantic_stack_delta_expr',
    '_semantic_stack_delta_from_observables',
    '_semantic_transfer_contract',
    '_semantic_transfer_contracts',
    '_semantic_transfer_inventory_contains_x87',
    '_semantic_x87_expression_valid',
    '_semantic_x87_instruction_effect_schedule',
    '_semantic_x87_physical_field_valid',
    '_semantic_x87_replay_binding',
    '_stage_a_smoke_artifact_hash_issues',
    '_stage_a_smoke_artifact_issues',
    '_stage_a_smoke_contract_issues',
    '_stage_a_smoke_sidecar_issues',
    '_symbol_aliases_for_range',
    '_tls_cluster_contracts',
    '_tool_versions',
    '_unchecked_marker_paths',
    '_unit_contract_ids_for_obligation',
    '_unit_contract_obligation_lookup',
    '_write_jsonl',
    '_write_reference_contract_sidecars',
    '_write_reference_unit_contract_sidecars',
    'stage_a_diff_obligations',
    'stage_a_explain_obligations',
    'stage_a_export_reference_contract',
    'stage_a_smoke_contract',
]
