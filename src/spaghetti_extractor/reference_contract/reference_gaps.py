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

from .reference_utils import (
    _REFERENCE_CONTRACT_FAMILY_KEYS,
)

from .reference_utils import (
    _gap_severity_rank,
)

def _reference_contract_gap_items(contract: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for issue in contract.get("issues", []):
        if isinstance(issue, dict):
            gaps.append(_gap_from_issue(issue))
    gaps.extend(_byte_coverage_gap_items(contract))
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
        "reconstruction_gap": 7,
    }
    return order.get(family, 99)

def _issue_family(obligation_id: str, category: str) -> str:
    text = f"{obligation_id} {category}".lower()
    for family, constraint in _REFERENCE_CONTRACT_FAMILY_KEYS:
        if family in text or constraint in text:
            return family
    if "layout" in text or "section" in text or "import" in text or "image_base" in text:
        return "binary_faithfulness"
    if "waiver" in text or "padding" in text:
        return "padding_alignment"
    if "mapping" in text or "map" in text:
        return "cfg_blocks"
    return "reconstruction_gap"

__all__ = [
    '_byte_coverage_gap_items',
    '_dedupe_gaps',
    '_gap_family_rank',
    '_gap_from_issue',
    '_issue_family',
    '_ranked_gap_next_work',
    '_reference_contract_gap_items',
]
