"""Plan exact machine-IR cutpoints for checked finite control targets.

The planner is deliberately untrusted.  It identifies byte spans that a
caller must independently decode, symbolically execute, and bind to the exact
PE before they can enter the canonical machine-IR inventory.
"""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, Mapping, Sequence

import capstone

from .stage_binary import StageABinary


TARGET_CUTPOINT_PLAN_V2_FORMAT = (
    "spaghetti-extractor-target-cutpoint-materialization-plan-v2"
)

_TERMINAL_GROUPS = frozenset(
    {
        capstone.CS_GRP_CALL,
        capstone.CS_GRP_INT,
        capstone.CS_GRP_IRET,
        capstone.CS_GRP_JUMP,
        capstone.CS_GRP_RET,
    }
)
_TERMINAL_MNEMONICS = frozenset(
    {
        "hlt",
        "int",
        "int1",
        "int3",
        "into",
        "iret",
        "iretd",
        "syscall",
        "sysenter",
        "sysexit",
        "ud0",
        "ud1",
        "ud2",
    }
)


def plan_recovered_target_cutpoints_v2(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
    required_targets: Mapping[int, Sequence[str]] | None = None,
    authoritative_unit_ids: Sequence[str] | None = None,
    immutable_data_ranges: Sequence[Any] = (),
    max_region_bytes: int = 256,
    max_instructions: int = 64,
) -> dict[str, Any]:
    """Propose exact spans for recovered targets missing from the unit index."""

    if max_region_bytes <= 0 or max_instructions <= 0:
        raise ValueError("target cutpoint planning budgets must be positive")
    data_ranges = sorted(
        (_range_bounds(item) for item in immutable_data_ranges),
        key=lambda item: item[0],
    )
    active_units = [
        unit
        for unit in units
        if not _overlaps_any(_unit_span(unit), data_ranges)
    ]
    authoritative_ids = (
        {str(identity) for identity in authoritative_unit_ids}
        if authoritative_unit_ids is not None
        else {str(unit.get("id")) for unit in active_units}
    )
    starts = {_unit_span(unit)[0]: unit for unit in active_units}
    targets: dict[int, set[str]] = {
        int(target): {str(source) for source in sources}
        for target, sources in (required_targets or {}).items()
    }
    recovery_ids: dict[int, set[str]] = {}
    for recovery in recoveries:
        if not _eligible_recovery(recovery):
            continue
        recovery_id = str(recovery.get("id") or "")
        for value in recovery.get("target_rvas", []):
            if isinstance(value, int) and not isinstance(value, bool):
                targets.setdefault(value, set()).add(f"recovery:{recovery_id}")
                recovery_ids.setdefault(value, set()).add(recovery_id)

    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for target_rva in sorted(targets):
        row, row_issues = _plan_target(
            binary=binary,
            units=active_units,
            starts=starts,
            data_ranges=data_ranges,
            target_rva=target_rva,
            target_sources=sorted(targets[target_rva]),
            recovery_ids=sorted(recovery_ids.get(target_rva, ())),
            authoritative_unit_ids=authoritative_ids,
            max_region_bytes=max_region_bytes,
            max_instructions=max_instructions,
        )
        rows.append(row)
        issues.extend(row_issues)

    body = {
        "format": TARGET_CUTPOINT_PLAN_V2_FORMAT,
        "status": _aggregate_status(issues),
        "binary_sha256": binary.sha256,
        "targets": rows,
        "issues": sorted(
            issues,
            key=lambda item: (
                0 if item["status"] == "violated" else 1,
                int(item["target_rva"]),
                str(item["code"]),
            ),
        ),
        "counts": {
            "targets": len(rows),
            "recovered_targets": sum(bool(row["recovery_ids"]) for row in rows),
            "explicit_required_targets": sum(
                bool(set(row["target_sources"]) - {
                    f"recovery:{identity}" for identity in row["recovery_ids"]
                })
                for row in rows
            ),
            "existing_targets": sum(row["disposition"] == "existing" for row in rows),
            "materialize_targets": sum(
                row["disposition"] == "materialize" for row in rows
            ),
            "unresolved_targets": sum(row["status"] != "complete" for row in rows),
            "proposed_regions": sum(len(row["regions"]) for row in rows),
        },
        "constraints": {
            "original_binary_executed": False,
            "plans_are_untrusted_proposals": True,
            "targets_inside_checked_data_are_rejected": True,
            "targets_inside_existing_instructions_are_rejected": True,
            "speculative_decode_views_cannot_veto_authoritative_targets": True,
            "generated_semantics_must_be_replayed_separately": True,
        },
    }
    return {**body, "id": "target-cutpoint-plan-v2:" + _digest(body)}


def _plan_target(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    starts: Mapping[int, Mapping[str, Any]],
    data_ranges: Sequence[tuple[int, int]],
    target_rva: int,
    target_sources: Sequence[str],
    recovery_ids: Sequence[str],
    authoritative_unit_ids: set[str],
    max_region_bytes: int,
    max_instructions: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    base = {
        "target_rva": target_rva,
        "target_sources": list(target_sources),
        "recovery_ids": list(recovery_ids),
    }
    if any(start <= target_rva < end for start, end in data_ranges):
        issue = _issue(
            "violated",
            "recovered_target_inside_immutable_executable_data",
            target_rva,
        )
        return {**base, "status": "violated", "disposition": "unresolved", "regions": []}, [issue]
    if target_rva in starts:
        return {
            **base,
            "status": "complete",
            "disposition": "existing",
            "existing_unit_id": starts[target_rva].get("id"),
            "regions": [],
        }, []

    boundaries: list[tuple[Mapping[str, Any], int, int]] = []
    interiors: list[tuple[Mapping[str, Any], int, int]] = []
    for unit in units:
        unit_start, unit_end = _unit_span(unit)
        for instruction in unit.get("instructions", []):
            span = _instruction_span(instruction)
            if span is None:
                continue
            start, end = span
            if start == target_rva and unit_start < target_rva < unit_end:
                boundaries.append((unit, unit_start, unit_end))
            elif start < target_rva < end:
                interiors.append((unit, start, end))
    authoritative_interiors = [
        item for item in interiors if str(item[0].get("id")) in authoritative_unit_ids
    ]
    if authoritative_interiors:
        issue = _issue(
            "violated",
            (
                "ambiguous_overlapping_target_decode"
                if boundaries
                else "recovered_target_inside_instruction"
            ),
            target_rva,
            owners=[
                {
                    "unit_id": unit.get("id"),
                    "instruction_rva_start": start,
                    "instruction_rva_end": end,
                }
                for unit, start, end in authoritative_interiors
            ],
        )
        return {**base, "status": "violated", "disposition": "unresolved", "regions": []}, [issue]
    authoritative_boundaries = [
        item for item in boundaries
        if str(item[0].get("id")) in authoritative_unit_ids
    ]
    if len(authoritative_boundaries) > 1:
        issue = _issue(
            "violated",
            "ambiguous_authoritative_cutpoint_owners",
            target_rva,
            owners=[
                {
                    "unit_id": unit.get("id"),
                    "rva_start": start,
                    "rva_end": end,
                }
                for unit, start, end in authoritative_boundaries
            ],
        )
        return {
            **base,
            "status": "violated",
            "disposition": "unresolved",
            "regions": [],
        }, [issue]
    if authoritative_boundaries:
        owner, start, end = authoritative_boundaries[0]
        return {
            **base,
            "status": "complete",
            "disposition": "materialize",
            "evidence": "existing_instruction_boundary",
            "superseded_unit_ids": [str(owner.get("id"))],
            "regions": [
                {
                    "rva_start": start,
                    "rva_end": target_rva,
                    "size": target_rva - start,
                    "cutpoint_role": "prefix_replacement",
                },
                {
                    "rva_start": target_rva,
                    "rva_end": end,
                    "size": end - target_rva,
                    "cutpoint_role": "target",
                },
            ],
        }, []

    section = next(
        (
            section
            for section in binary.sections
            if section.executable
            and section.rva_start <= target_rva
            < min(section.rva_end, section.rva_start + section.raw_size)
        ),
        None,
    )
    if section is None:
        issue = _issue(
            "violated",
            "recovered_target_outside_initialized_executable_bytes",
            target_rva,
        )
        return {**base, "status": "violated", "disposition": "unresolved", "regions": []}, [issue]

    initialized_end = min(section.rva_end, section.rva_start + section.raw_size)
    later_data = [start for start, _ in data_ranges if target_rva < start]
    hard_end = min(
        initialized_end,
        target_rva + max_region_bytes,
        min(later_data) if later_data else initialized_end,
    )
    data = bytes(binary.pe.get_data(target_rva, hard_end - target_rva))
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    disassembler.detail = True
    expected = target_rva
    decoded = 0
    stop_reason: str | None = None
    for instruction in disassembler.disasm(data, binary.image_base + target_rva):
        instruction_rva = int(instruction.address - binary.image_base)
        if instruction_rva != expected:
            break
        if (
            decoded
            and instruction_rva in starts
            and str(starts[instruction_rva].get("id")) in authoritative_unit_ids
        ):
            stop_reason = "existing_unit_boundary"
            break
        decoded += 1
        expected = instruction_rva + int(instruction.size)
        if any(instruction.group(group) for group in _TERMINAL_GROUPS) or (
            instruction.mnemonic.lower() in _TERMINAL_MNEMONICS
        ):
            stop_reason = "decoded_control_boundary"
            break
        if decoded >= max_instructions:
            break

    if expected == target_rva or stop_reason is None:
        issue = _issue(
            "incomplete",
            "target_region_boundary_not_recovered",
            target_rva,
            decoded_instructions=decoded,
            decoded_rva_end=expected,
            hard_rva_end=hard_end,
        )
        return {**base, "status": "incomplete", "disposition": "unresolved", "regions": []}, [issue]
    return {
        **base,
        "status": "complete",
        "disposition": "materialize",
        "evidence": stop_reason,
        "regions": [{"rva_start": target_rva, "rva_end": expected, "size": expected - target_rva}],
    }, []


def _eligible_recovery(recovery: Mapping[str, Any]) -> bool:
    return (
        recovery.get("status") == "recovered"
        and recovery.get("closure") == "checked_finite_target_inventory"
        and recovery.get("recovery_kind", recovery.get("kind"))
        == "pe32_indexed_absolute_jump_table"
        and recovery.get("failure") is None
        and isinstance(recovery.get("target_rvas"), list)
    )


def _unit_span(unit: Mapping[str, Any]) -> tuple[int, int]:
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    if not isinstance(original, Mapping):
        raise ValueError("machine-IR unit omits its original span")
    return int(original["rva_start"]), int(original["rva_end"])


def _instruction_span(instruction: Any) -> tuple[int, int] | None:
    if not isinstance(instruction, Mapping):
        return None
    start = instruction.get("rva_start", instruction.get("rva"))
    end = instruction.get("rva_end")
    if end is None and isinstance(start, int) and isinstance(instruction.get("size"), int):
        end = start + int(instruction["size"])
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start >= end
    ):
        return None
    return start, end


def _range_bounds(item: Any) -> tuple[int, int]:
    if isinstance(item, Mapping):
        return int(item["rva_start"]), int(item["rva_end"])
    return int(item.rva_start), int(item.rva_end)


def _overlaps_any(
    span: tuple[int, int], ranges: Sequence[tuple[int, int]]
) -> bool:
    return any(span[0] < end and start < span[1] for start, end in ranges)


def _issue(status: str, code: str, target_rva: int, **details: Any) -> dict[str, Any]:
    body = {
        "status": status,
        "code": code,
        "target_rva": target_rva,
        **details,
    }
    return {**body, "id": "target-cutpoint-issue-v2:" + _digest(body)}


def _aggregate_status(issues: Sequence[Mapping[str, Any]]) -> str:
    if any(issue.get("status") == "violated" for issue in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "complete"


def _digest(value: Any) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "TARGET_CUTPOINT_PLAN_V2_FORMAT",
    "plan_recovered_target_cutpoints_v2",
]
