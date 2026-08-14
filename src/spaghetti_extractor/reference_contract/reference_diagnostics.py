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

from .reference_sidecars import (
    _reference_abi_callsites_sidecar,
    _reference_contract_summary_sidecar,
    _reference_coverage_gaps_sidecar,
    _reference_obligation_index_sidecar,
    _reference_sidecar_contract_ref,
)

from .reference_utils import (
    _load_json,
)

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

__all__ = [
    '_load_reference_contract_sidecars',
    '_resolve_contract_sidecar_path',
    '_stage_a_smoke_artifact_hash_issues',
    '_stage_a_smoke_artifact_issues',
    '_stage_a_smoke_contract_issues',
    '_stage_a_smoke_sidecar_issues',
]
