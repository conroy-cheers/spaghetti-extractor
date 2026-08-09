"""Proposal and replay phase for checked indirect-control cutpoint facts."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from .control_analysis_v2 import exact_control_inventory_v2
from .exception_invariants_v2 import (
    canonical_sha256,
    check_control_invariant_certificate_v2,
    synthesize_control_invariant_certificate_v2,
)
from .stage_binary import StageABinary


CONTROL_INVARIANT_PHASE_V2_FORMAT = (
    "spaghetti-extractor-control-invariant-phase-v2"
)


def derive_checked_control_invariants_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    binary: StageABinary,
    machine_ir_sha256: str,
    finite_value_budget: int = 32,
    region_unit_budget: int = 12,
) -> dict[str, Any]:
    """Propose and replay facts needed by bounded immutable jump tables.

    Backward region growth is untrusted synthesis guidance. Every exported fact
    comes from an independent exact-unit replay over the final finite region.
    """

    if finite_value_budget <= 0 or region_unit_budget <= 0:
        raise ValueError("control-invariant budgets must be positive")
    exact = exact_control_inventory_v2(units)
    by_id = {str(unit["id"]): unit for unit in units}
    starts = {
        int(unit["source"]["original"]["rva_start"]): str(unit["id"])
        for unit in units
    }
    predecessors: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    for edge in exact["direct_edges"]:
        source = edge.get("source_unit_id")
        target = edge.get("target_unit_id")
        if source in by_id and target in by_id:
            predecessors[str(target)].add(str(source))

    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    authority_records: list[dict[str, Any]] = []
    for exit_record in exact["indirect_exits"]:
        proposal = _static_dispatch_fact(
            exit_record,
            binary=binary,
            code_starts=starts,
            finite_value_budget=finite_value_budget,
        )
        if proposal is None:
            continue
        frontier = str(exit_record["source_unit_id"])
        requested_fact = proposal["fact"]
        members = {frontier}
        final_proposal: Mapping[str, Any] | None = None
        final_report: Mapping[str, Any] | None = None
        attempts = 0
        while members and len(members) <= region_unit_budget:
            attempts += 1
            synthesized = synthesize_control_invariant_certificate_v2(
                units=units,
                member_ids=sorted(members),
                frontier_member_ids=[frontier],
                requested_facts={frontier: [requested_fact]},
                binary_sha256=binary.sha256,
                machine_ir_sha256=machine_ir_sha256,
                finite_value_budget=finite_value_budget,
            )
            report = check_control_invariant_certificate_v2(
                synthesized["certificate"],
                units=units,
                binary_sha256=binary.sha256,
                machine_ir_sha256=machine_ir_sha256,
            )
            final_proposal = synthesized
            final_report = report
            if report["status"] == "complete":
                break
            expanded = set(members)
            for member in members:
                expanded.update(predecessors.get(member, ()))
            if expanded == members or len(expanded) > region_unit_budget:
                break
            if any(
                _unit_has_indirect_control(by_id[member]) and member != frontier
                for member in expanded
            ):
                break
            members = expanded

        assert final_proposal is not None and final_report is not None
        row_body = {
            "indirect_exit_id": exit_record["id"],
            "source_unit_id": frontier,
            "source_rva": exit_record.get("source_rva"),
            "dispatch": proposal["dispatch"],
            "region_members": sorted(members),
            "synthesis_attempts": attempts,
            "proposal": final_proposal,
            "report": final_report,
        }
        rows.append({
            **row_body,
            "id": "control-invariant-row-v2:" + canonical_sha256(row_body),
        })
        if final_report["status"] != "complete":
            issues.append({
                "status": "incomplete",
                "code": "static_dispatch_control_fact_not_proved",
                "indirect_exit_id": exit_record["id"],
                "source_unit_id": frontier,
                "report_status": final_report["status"],
                "report_issues": copy.deepcopy(final_report["issues"]),
            })
            continue
        for record in final_report["checked_invariants"]:
            authority_records.append({
                **copy.deepcopy(dict(record)),
                "binary_sha256": binary.sha256,
                "machine_ir_sha256": machine_ir_sha256,
                "certificate_sha256": final_report["certificate_sha256"],
                "indirect_exit_id": exit_record["id"],
                "source_rva": exit_record.get("source_rva"),
                "dispatch": copy.deepcopy(proposal["dispatch"]),
            })

    body = {
        "format": CONTROL_INVARIANT_PHASE_V2_FORMAT,
        "status": "incomplete" if issues else "complete",
        "binary_sha256": binary.sha256,
        "machine_ir_sha256": machine_ir_sha256,
        "uses_bounded_paths": False,
        "proposal_search_bounded": True,
        "rows": sorted(rows, key=lambda row: str(row["indirect_exit_id"])),
        "authority_records": sorted(
            authority_records,
            key=lambda row: (str(row["unit_id"]), str(row["fact_sha256"])),
        ),
        "issues": sorted(
            issues,
            key=lambda row: (str(row["code"]), str(row["indirect_exit_id"])),
        ),
        "counts": {
            "eligible_static_dispatches": len(rows),
            "checked_facts": len(authority_records),
            "incomplete_dispatches": len(issues),
        },
    }
    return {**body, "id": "control-invariant-phase-v2:" + canonical_sha256(body)}


def _static_dispatch_fact(
    exit_record: Mapping[str, Any],
    *,
    binary: StageABinary,
    code_starts: Mapping[int, str],
    finite_value_budget: int,
) -> dict[str, Any] | None:
    target = exit_record.get("target_expression")
    if not isinstance(target, Mapping) or target.get("op") != "load":
        return None
    indexed = _indexed_address(target.get("address"))
    if indexed is None:
        return None
    table_address, selector, mask, stride = indexed
    if stride != 4 or mask + 1 > finite_value_budget:
        return None
    table_rva = table_address - binary.image_base
    if table_rva < 0:
        return None
    valid: list[int] = []
    entries: list[dict[str, Any]] = []
    for index in range(mask + 1):
        data = bytes(binary.pe.get_data(table_rva + index * stride, 4))
        if len(data) != 4:
            return None
        value = int.from_bytes(data, "little")
        target_rva = value - binary.image_base
        target_unit_id = code_starts.get(target_rva)
        executable = _address_is_executable(binary, value)
        if executable:
            valid.append(index)
        entries.append({
            "index": index,
            "target_address": value,
            "target_rva": target_rva,
            "target_unit_id": target_unit_id,
            "executable": executable,
        })
    if not valid or len(valid) == mask + 1:
        return None
    fact = {
        "kind": "finite_values",
        "expression": copy.deepcopy(selector),
        "values": valid,
    }
    return {
        "fact": fact,
        "dispatch": {
            "kind": "bounded-static-u32-jump-table",
            "table_address": table_address,
            "table_rva": table_rva,
            "stride": stride,
            "mask": mask,
            "entries": entries,
        },
    }


def _indexed_address(
    expression: Any,
) -> tuple[int, dict[str, Any], int, int] | None:
    if not isinstance(expression, Mapping) or expression.get("op") != "add32":
        return None
    args = expression.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    for base_expr, scaled_expr in ((args[0], args[1]), (args[1], args[0])):
        base = _constant(base_expr)
        if base is None or not isinstance(scaled_expr, Mapping):
            continue
        scaled_args = scaled_expr.get("args")
        if (
            scaled_expr.get("op") != "mul32"
            or not isinstance(scaled_args, list)
            or len(scaled_args) != 2
        ):
            continue
        for selector, stride_expr in (
            (scaled_args[0], scaled_args[1]),
            (scaled_args[1], scaled_args[0]),
        ):
            stride = _constant(stride_expr)
            if stride is None or not isinstance(selector, Mapping):
                continue
            mask_args = selector.get("args")
            if (
                selector.get("op") != "and32"
                or not isinstance(mask_args, list)
                or len(mask_args) != 2
            ):
                continue
            mask = next(
                (
                    value
                    for value in (_constant(mask_args[0]), _constant(mask_args[1]))
                    if value is not None
                ),
                None,
            )
            if (
                mask is not None
                and mask < 0xFFFFFFFF
                and _is_power_of_two(mask + 1)
            ):
                return base, copy.deepcopy(dict(selector)), mask, stride
    return None


def _constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    raw = value.get("value")
    return raw & 0xFFFFFFFF if isinstance(raw, int) and not isinstance(raw, bool) else None


def _unit_has_indirect_control(unit: Mapping[str, Any]) -> bool:
    semantics = unit.get("semantics")
    outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
    return isinstance(outcome, Mapping) and outcome.get("kind") in {
        "indirect_call",
        "indirect_jump",
        "unknown",
    }


def _address_is_executable(binary: StageABinary, address: int) -> bool:
    rva = address - binary.image_base
    if rva < 0:
        return False
    for section in binary.sections:
        start = (
            section.get("rva_start")
            if isinstance(section, Mapping)
            else getattr(section, "rva_start", None)
        )
        end = (
            section.get("rva_end")
            if isinstance(section, Mapping)
            else getattr(section, "rva_end", None)
        )
        executable = (
            section.get("executable")
            if isinstance(section, Mapping)
            else getattr(section, "executable", None)
        )
        if executable is True and isinstance(start, int) and isinstance(end, int):
            if start <= rva < end:
                return True
    return False


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


__all__ = [
    "CONTROL_INVARIANT_PHASE_V2_FORMAT",
    "derive_checked_control_invariants_v2",
]
