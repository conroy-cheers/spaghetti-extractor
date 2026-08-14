"""Static map and executable-byte classification proposals."""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import sys
from bisect import bisect_left
from collections import Counter
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
    CHECKED_GENERATED_MAPPING_PROOF_RULES,
    NORETURN_IMPORT_SYMBOLS,
    NonCodeWaiver,
    _failure_record,
    _incomplete_record,
    _is_conditional_jump,
    _parse_int,
    _range_report,
)
from .map_analysis import (
    _capstone_mode,
    _direct_import_thunk,
    _import_for_absolute_memory_operand,
    _import_signature,
    _is_padding_bytes,
    _range_overlap_issues,
    _section_compatibility_signature,
    _section_rva_start_signature,
)

def _generated_layout_contract(original: StageABinary, candidate: StageABinary, map_payload: dict[str, Any]) -> dict[str, Any]:
    facts = {
        "matching_architecture": original.machine == candidate.machine and original.bitness == candidate.bitness,
        "matching_section_rvas": _section_rva_start_signature(original) == _section_rva_start_signature(candidate),
        "matching_section_permissions": _section_compatibility_signature(original) == _section_compatibility_signature(candidate),
        "matching_imports": _import_signature(original) == _import_signature(candidate),
        "all_executable_bytes_classified": map_payload.get("status") == "pass",
    }
    facts["matching_normalized_executable_section_spans"] = (
        facts["matching_architecture"]
        and facts["matching_section_rvas"]
        and facts["matching_section_permissions"]
        and facts["all_executable_bytes_classified"]
    )
    return {
        "format": "stage-a-layout-contract-v1",
        "generator": "stage-a-generate-map",
        "require_same_image_base": original.image_base == candidate.image_base,
        "allow_different_section_spans": facts["matching_normalized_executable_section_spans"],
        "required_facts": [
            "matching_architecture",
            "matching_section_rvas",
            "matching_section_permissions",
            "matching_imports",
            "all_executable_bytes_classified",
            "matching_normalized_executable_section_spans",
        ],
        "facts": facts,
        "normalized_sections": _normalized_section_reports(original, candidate),
    }

def _normalized_section_reports(original: StageABinary, candidate: StageABinary) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    by_name = {section.name: section for section in candidate.sections}
    for section in original.sections:
        other = by_name.get(section.name)
        normalized_rva_end = max(section.rva_end, other.rva_end) if other is not None and section.executable else section.rva_end
        reports.append(
            {
                "name": section.name,
                "executable": section.executable,
                "rva_start": section.rva_start,
                "normalized_rva_end": normalized_rva_end,
                "original_rva_end": section.rva_end,
                "candidate_rva_end": other.rva_end if other is not None else None,
            }
        )
    return reports

def _parse_block_map(payload: Any, original: StageABinary) -> tuple[list[BlockMapping], list[NonCodeWaiver], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if isinstance(payload, list):
        block_entries = payload
        waiver_entries: list[Any] = []
    elif isinstance(payload, dict):
        block_entries = payload.get("blocks", payload.get("mappings"))
        waiver_entries = payload.get("waivers", [])
    else:
        block_entries = None
        waiver_entries = []

    if not isinstance(block_entries, list):
        return [], [], [
            _incomplete_record(
                category="invalid_mapping",
                obligation_id="mapping:blocks",
                blocker="block-map.json must be a list or contain a blocks/mappings list",
                next_action="add explicit original-to-candidate block mappings",
            )
        ]

    mappings: list[BlockMapping] = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(block_entries):
        try:
            mapped = _parse_block_mapping(entry, index, original)
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:block:{index}",
                    blocker=str(exc),
                    next_action="fix the malformed block mapping entry",
                )
            )
            continue
        if mapped.id in seen_ids:
            issues.append(
                _failure_record(
                    category="invalid_mapping",
                    obligation_id=f"mapping:block:{mapped.id}",
                    blocker=f"duplicate block mapping id {mapped.id!r}",
                    original={"id": mapped.id},
                    candidate={"id": mapped.id},
                )
            )
            continue
        seen_ids.add(mapped.id)
        mappings.append(mapped)

    issues.extend(_range_overlap_issues("original", [(mapped.id, mapped.original) for mapped in mappings]))
    issues.extend(_range_overlap_issues("candidate", [(mapped.id, mapped.candidate) for mapped in mappings]))

    waivers: list[NonCodeWaiver] = []
    for index, entry in enumerate(waiver_entries if isinstance(waiver_entries, list) else []):
        try:
            waivers.append(_parse_waiver(entry, index))
        except StageAInputError as exc:
            issues.append(
                _incomplete_record(
                    category="invalid_waiver",
                    obligation_id=f"mapping:waiver:{index}",
                    blocker=str(exc),
                    next_action="fix the malformed non-code waiver entry",
                )
            )

    return mappings, waivers, issues

def _parse_block_mapping(entry: Any, index: int, original: StageABinary) -> BlockMapping:
    if not isinstance(entry, dict):
        raise StageAInputError("block mapping entry must be an object")
    block_id = str(entry.get("id") or f"block_{index:04d}")
    original_side = _parse_side(entry.get("original"), "original")
    candidate_side = _parse_side(entry.get("candidate"), "candidate")
    if original_side.size <= 0 or candidate_side.size <= 0:
        raise StageAInputError(f"block {block_id!r} has an empty or inverted range")
    invariant = entry.get("invariant", {})
    invariant_checked = bool(invariant.get("checked", True)) if isinstance(invariant, dict) else False
    reachable = bool(entry.get("reachable", original_side.rva_start == original.entrypoint_rva))
    return BlockMapping(
        id=block_id,
        original=original_side,
        candidate=candidate_side,
        kind=str(entry.get("kind") or "code"),
        reachable=reachable,
        invariant_checked=invariant_checked,
        source=entry,
    )

def _parse_side(value: Any, name: str) -> BlockSide:
    if not isinstance(value, dict):
        raise StageAInputError(f"{name} block side must be an object")
    if "rva_start" in value and "rva_end" in value:
        return BlockSide(_parse_int(value["rva_start"]), _parse_int(value["rva_end"]))
    if "rva" in value and "size" in value:
        start = _parse_int(value["rva"])
        return BlockSide(start, start + _parse_int(value["size"]))
    raise StageAInputError(f"{name} block side must contain rva_start/rva_end or rva/size")

def _parse_waiver(entry: Any, index: int) -> NonCodeWaiver:
    if not isinstance(entry, dict):
        raise StageAInputError("waiver entry must be an object")
    side = _parse_side(entry, "waiver")
    binary = str(entry.get("binary") or "both")
    if binary not in {"original", "candidate", "both"}:
        raise StageAInputError(f"waiver binary must be original, candidate, or both, got {binary!r}")
    return NonCodeWaiver(
        id=str(entry.get("id") or f"waiver_{index:04d}"),
        binary=binary,
        rva_start=side.rva_start,
        rva_end=side.rva_end,
        reason=str(entry.get("reason") or "non-code waiver"),
    )


def _waiver_obligations(
    original: StageABinary,
    candidate: StageABinary,
    waivers: Iterable[NonCodeWaiver],
) -> tuple[list[NonCodeWaiver], list[dict[str, Any]]]:
    verified: list[NonCodeWaiver] = []
    obligations: list[dict[str, Any]] = []
    for waiver in waivers:
        checks = _verify_waiver(original, candidate, waiver)
        obligation_id = f"waiver:{waiver.id}:{waiver.binary}:{waiver.rva_start:x}-{waiver.rva_end:x}"
        failed = [check for check in checks if check["status"] != "verified"]
        if failed:
            blocker = _incomplete_record(
                category="unverified_noncode_waiver",
                obligation_id=obligation_id,
                blocker="non-code waiver bytes are not independently verified as executable-section padding",
                next_action="narrow the waiver to verified padding bytes or map the range as code",
                details={
                    "waiver": {
                        "id": waiver.id,
                        "binary": waiver.binary,
                        "rva_start": waiver.rva_start,
                        "rva_end": waiver.rva_end,
                        "reason": waiver.reason,
                    },
                    "checks": checks,
                },
            )
            obligations.append(
                {
                    "id": obligation_id,
                    "kind": "executable_byte_class",
                    "status": "incomplete",
                    "binary": waiver.binary,
                    "rva_start": waiver.rva_start,
                    "rva_end": waiver.rva_end,
                    "reason": waiver.reason,
                    "incomplete": blocker,
                }
            )
            continue
        verified.append(waiver)
        obligations.append(
            {
                "id": obligation_id,
                "kind": "executable_byte_class",
                "status": "waived_noncode",
                "proof_rule": "verified_padding_bytes_v1",
                "binary": waiver.binary,
                "rva_start": waiver.rva_start,
                "rva_end": waiver.rva_end,
                "reason": waiver.reason,
                "checks": checks,
            }
        )
    return verified, obligations

def _verify_waiver(original: StageABinary, candidate: StageABinary, waiver: NonCodeWaiver) -> list[dict[str, Any]]:
    sides = []
    if waiver.binary in {"original", "both"}:
        sides.append(("original", original))
    if waiver.binary in {"candidate", "both"}:
        sides.append(("candidate", candidate))
    return [_verify_waiver_side(side, binary, waiver) for side, binary in sides]

def _verify_waiver_side(side: str, binary: StageABinary, waiver: NonCodeWaiver) -> dict[str, Any]:
    section = _executable_section_covering_range(binary, waiver.rva_start, waiver.rva_end)
    if section is None:
        return {
            "binary": side,
            "status": "not_executable_section_padding",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "reason": "waiver range is not fully contained in one executable section",
        }
    data = binary.pe.get_data(waiver.rva_start, waiver.rva_end - waiver.rva_start)
    if len(data) != waiver.rva_end - waiver.rva_start:
        return {
            "binary": side,
            "status": "unreadable",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "section": section.name,
            "read_bytes": len(data),
        }
    if not _is_padding_bytes(binary, waiver.rva_start, data):
        return {
            "binary": side,
            "status": "not_padding",
            "rva_start": waiver.rva_start,
            "rva_end": waiver.rva_end,
            "section": section.name,
            "bytes_sha256": sha256_bytes(data),
        }
    return {
        "binary": side,
        "status": "verified",
        "rva_start": waiver.rva_start,
        "rva_end": waiver.rva_end,
        "section": section.name,
        "bytes_sha256": sha256_bytes(data),
        "bytes_hex": data.hex(),
    }

def _executable_section_covering_range(binary: StageABinary, rva_start: int, rva_end: int) -> StageASection | None:
    if rva_end <= rva_start:
        return None
    for section in binary.sections:
        if section.executable and section.rva_start <= rva_start and rva_end <= section.rva_end:
            return section
    return None








def _external_import_jump(binary: StageABinary, insn: Any) -> StageAImport | None:
    if insn.mnemonic not in {"jmp", "ljmp"} or len(insn.operands) != 1:
        return None
    operand = insn.operands[0]
    if operand.type == X86_OP_MEM:
        return _import_for_absolute_memory_operand(binary, operand)
    if operand.type == X86_OP_IMM:
        target_rva = int(operand.imm - binary.image_base)
        return _direct_import_thunk(binary, target_rva)
    return None









__all__ = [
    '_executable_section_covering_range',
    '_external_import_jump',
    '_generated_layout_contract',
    '_normalized_section_reports',
    '_parse_block_map',
    '_parse_block_mapping',
    '_parse_side',
    '_parse_waiver',
    '_verify_waiver',
    '_verify_waiver_side',
    '_waiver_obligations',
]
