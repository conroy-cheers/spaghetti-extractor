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
)

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

def _proof_family_status(value: Any) -> str:
    status = str(value or "incomplete")
    if status in {"satisfied", "not_applicable"}:
        return status
    if status == "derived":
        return "satisfied"
    if status in {"failed", "fail", "violated"}:
        return "violated"
    return "incomplete"

def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

def _matches_focus(item: Any, focus_lower: str) -> bool:
    return focus_lower in json.dumps(item, sort_keys=True, default=str).lower()

def _gap_severity_rank(value: Any) -> int:
    return {"incomplete": 1, "violated": 2, "failed": 2, "fail": 2}.get(str(value or ""), 0)

def _reference_unit_contract_paths(unit_contract_dir: Path) -> dict[str, Path]:
    return {
        "block_contracts": unit_contract_dir / "block-contracts.jsonl",
        "function_contracts": unit_contract_dir / "function-contracts.jsonl",
        "cluster_contracts": unit_contract_dir / "cluster-contracts.jsonl",
        "repair_units": unit_contract_dir / "repair-units.json",
        "semantic_transfer_contracts": unit_contract_dir / "semantic-transfer-contracts.jsonl",
        "semantic_region_contracts": unit_contract_dir / "semantic-region-contracts.jsonl",
        "memory_frame_contracts": unit_contract_dir / "memory-frame-contracts.json",
        "call_summary_contracts": unit_contract_dir / "call-summary-contracts.json",
        "cluster_semantic_contracts": unit_contract_dir / "cluster-semantic-contracts.jsonl",
    }

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
    '_REFERENCE_CONTRACT_FAMILY_KEYS',
    '_binary_layout',
    '_binary_reference_layout',
    '_binary_relocation_summary',
    '_gap_severity_rank',
    '_load_json',
    '_load_optional_json',
    '_matches_focus',
    '_proof_family_status',
    '_reference_artifact_display_path',
    '_reference_contract_inputs',
    '_reference_input_artifact',
    '_reference_unit_contract_paths',
    '_tool_versions',
    '_write_jsonl',
]
