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
    _ranked_gap_next_work,
    _reference_contract_gap_items,
)

from .reference_units import (
    _reference_unit_contract_payloads,
)

from .reference_utils import (
    _REFERENCE_CONTRACT_FAMILY_KEYS,
    _proof_family_status,
    _reference_artifact_display_path,
    _reference_unit_contract_paths,
    _write_jsonl,
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
    return {}

def _reference_coverage_gaps_sidecar(contract: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    gaps = _reference_contract_gap_items(contract)
    return {
        "format": "stage-a-coverage-gaps-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "status": "qualified" if not gaps else "incomplete",
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
    indexed = _reference_contract_gap_items(contract)
    return {
        "format": "stage-a-reconstruction-gap-index-v1",
        "reference_contract": contract_ref,
        "contract_status": contract.get("status"),
        "gaps": indexed,
        "counts": {
            "gaps": len(indexed),
            "by_severity": _count_by(indexed, "severity"),
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
    _write_jsonl(paths["semantic_transfer_contracts"], payload["semantic_transfer_contracts"])
    _write_jsonl(paths["semantic_region_contracts"], payload["semantic_region_contracts"])
    write_json(paths["memory_frame_contracts"], payload["memory_frame_contracts"])
    write_json(paths["call_summary_contracts"], payload["call_summary_contracts"])
    _write_jsonl(paths["cluster_semantic_contracts"], payload["cluster_semantic_contracts"])

__all__ = [
    '_reference_abi_callsites_sidecar',
    '_reference_contract_families',
    '_reference_contract_sidecar_paths',
    '_reference_contract_summary_sidecar',
    '_reference_coverage_gaps_sidecar',
    '_reference_family_counts',
    '_reference_obligation_index_sidecar',
    '_reference_sidecar_contract_ref',
    '_write_reference_contract_sidecars',
    '_write_reference_unit_contract_sidecars',
]
