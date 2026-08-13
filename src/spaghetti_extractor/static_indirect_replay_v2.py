"""Exact replay of static PE32 indirect-control recoveries.

Machine-IR recovery rows are proposals. This module reconstructs the subset
that can support checked indirect-target evidence directly from exact unit
semantics and PE bytes. Unsupported recovery mechanisms remain incomplete.
"""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from collections.abc import Mapping, Sequence
from typing import Any

from .indirect_target_dependency_v2 import (
    IndirectTargetDependencyV2Error,
    build_bounded_selector_dependency_v2,
    validate_bounded_selector_dependency_v2,
)
from .reconstruction_control import (
    pe32_jump_table_index_expression,
    recover_static_pe32_jump_table_inventory,
)
from .stage_binary import StageABinary


def replay_exact_static_recoveries_v2(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    checked_control_invariants: Sequence[Mapping[str, Any]] = (),
    machine_ir_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Rebuild predecessor-bounded immutable jump tables from authority inputs."""

    starts = {
        int(source["rva_start"]): unit
        for unit in units
        for source in (unit.get("source", {}).get("original", {}),)
        if isinstance(source, Mapping)
        and isinstance(source.get("rva_start"), int)
        and not isinstance(source.get("rva_start"), bool)
    }
    units_by_id = {
        str(unit.get("id")): unit
        for unit in units
        if isinstance(unit.get("id"), str)
    }
    predecessors = direct_predecessors_by_target(units)
    checked_domains = _checked_control_domains(
        checked_control_invariants,
        binary=binary,
        machine_ir_sha256=machine_ir_sha256,
        indirect_exits=indirect_exits,
        units_by_id=units_by_id,
    )
    result: list[dict[str, Any]] = []
    for exit_record in indirect_exits:
        source_unit_id = exit_record.get("source_unit_id")
        source_unit = units_by_id.get(source_unit_id)
        if source_unit is None:
            result.append(
                _incomplete_recovery(exit_record, "static_recovery_source_missing")
            )
            continue
        target_expression = exit_record.get("target_expression")
        if not isinstance(target_expression, Mapping):
            result.append(
                _incomplete_recovery(
                    exit_record, "static_recovery_target_expression_missing"
                )
            )
            continue
        recovery = recover_static_pe32_jump_table_inventory(
            target_expression=target_expression,
            predecessor_evidence=indirect_predecessor_evidence(
                source_unit,
                predecessors_by_target=predecessors,
            ),
            image_base=binary.image_base,
            sections=binary.sections,
            read_rva=lambda rva, size: bytes(binary.pe.get_data(rva, size)),
            finite_index_domain=checked_domains.get(str(exit_record.get("id"))),
            valid_target_rvas=starts,
        )
        recovery_kind = recovery.get("kind")
        checked_domain = checked_domains.get(str(exit_record.get("id")))
        if checked_domain is not None:
            recovery["control_invariant_dependencies"] = list(
                checked_domain["authority_dependencies"]
            )
            recovery["authority_dependencies"] = [
                {"role": "control_invariant", "content_id": dependency}
                for dependency in checked_domain["authority_dependencies"]
            ]
        target_rvas = [
            int(rva)
            for rva in recovery.get("target_rvas", [])
            if isinstance(rva, int) and not isinstance(rva, bool)
        ]
        resolved = sorted(rva for rva in target_rvas if rva in starts)
        unresolved = sorted(rva for rva in target_rvas if rva not in starts)
        recovery.update(
            {
                "id": exit_record.get("id"),
                "recovery_kind": recovery_kind,
                "source_unit_id": source_unit_id,
                "source_rva": exit_record.get("source_rva"),
                "source_event_index": exit_record.get("source_event_index"),
                "kind": exit_record.get("kind"),
                "target_expression": copy.deepcopy(target_expression),
                "target_unit_ids": [str(starts[rva]["id"]) for rva in resolved],
                "external_targets": [],
                "unit_binding": {
                    "status": (
                        "complete"
                        if recovery.get("status") == "recovered" and not unresolved
                        else "incomplete"
                    ),
                    "resolved_target_rvas": resolved,
                    "unmaterialized_target_rvas": unresolved,
                },
            }
        )
        if (
            recovery.get("status") == "recovered"
            and recovery.get("closure") == "checked_finite_target_inventory"
            and recovery_kind == "pe32_indexed_absolute_jump_table"
            and recovery.get("failure") is None
            and recovery["unit_binding"]["status"] == "complete"
        ):
            recovery["target_set_dependency"] = (
                build_bounded_selector_dependency_v2(recovery)
            )
        result.append(recovery)
    return result


def replay_inductive_static_hypotheses_v2(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    hypotheses: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Rebind finite-table hypotheses to exact PE bytes and canonical units.

    The selector domain remains an inductive hypothesis.  This function checks
    only the non-circular part of the claim: exact target expression, immutable
    PE table bytes, and complete canonical target-unit binding.  The unified
    interprocedural pass must independently reproduce the target set before the
    hypothesis can authorize an SCC.
    """

    starts = {
        int(source["rva_start"]): unit
        for unit in units
        for source in (unit.get("source", {}).get("original", {}),)
        if isinstance(source, Mapping)
        and isinstance(source.get("rva_start"), int)
        and not isinstance(source.get("rva_start"), bool)
    }
    exits_by_id = {
        str(row.get("id")): row
        for row in indirect_exits
        if isinstance(row.get("id"), str)
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hypothesis in hypotheses:
        identity = hypothesis.get("id")
        if not isinstance(identity, str) or identity in seen:
            continue
        observed_dependency = hypothesis.get("target_set_dependency")
        if not isinstance(observed_dependency, Mapping):
            continue
        try:
            validate_bounded_selector_dependency_v2(hypothesis)
        except (IndirectTargetDependencyV2Error, TypeError, ValueError):
            continue
        exit_record = exits_by_id.get(identity)
        index = hypothesis.get("index")
        submitted_target = hypothesis.get("target_expression")
        if (
            exit_record is None
            or not isinstance(index, Mapping)
            or (
                submitted_target is not None
                and submitted_target != exit_record.get("target_expression")
            )
            or hypothesis.get("source_unit_id")
            != exit_record.get("source_unit_id")
            or hypothesis.get("source_rva") != exit_record.get("source_rva")
            or hypothesis.get("source_event_index")
            != exit_record.get("source_event_index")
            or hypothesis.get("kind") != exit_record.get("kind")
        ):
            continue
        expression = index.get("expression")
        values = index.get("values")
        if (
            not isinstance(expression, Mapping)
            or expression
            != pe32_jump_table_index_expression(
                exit_record.get("target_expression", {})
            )
            or not isinstance(values, list)
            or not values
            or values != sorted(set(values))
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 0xFFFF_FFFF
                for value in values
            )
        ):
            continue
        source_unit_id = exit_record.get("source_unit_id")
        if not isinstance(source_unit_id, str):
            continue
        finite_domain = {
            "format": "stage-a-finite-u32-expression-domain-v1",
            "status": "complete",
            "source_unit_id": source_unit_id,
            "expression_sha256": _expression_sha256(expression),
            "values": list(values),
            "hypothesis_kind": "inductive_static_selector_domain_v2",
        }
        recovery = recover_static_pe32_jump_table_inventory(
            target_expression=exit_record["target_expression"],
            predecessor_evidence=(),
            image_base=binary.image_base,
            sections=binary.sections,
            read_rva=lambda rva, size: bytes(binary.pe.get_data(rva, size)),
            finite_index_domain=finite_domain,
            valid_target_rvas=starts,
        )
        target_rvas = [
            int(rva)
            for rva in recovery.get("target_rvas", ())
            if isinstance(rva, int) and not isinstance(rva, bool)
        ]
        resolved = sorted(rva for rva in target_rvas if rva in starts)
        unresolved = sorted(rva for rva in target_rvas if rva not in starts)
        recovery.update({
            "id": identity,
            "recovery_kind": recovery.get("kind"),
            "source_unit_id": source_unit_id,
            "source_rva": exit_record.get("source_rva"),
            "source_event_index": exit_record.get("source_event_index"),
            "kind": exit_record.get("kind"),
            "target_expression": copy.deepcopy(exit_record["target_expression"]),
            "target_unit_ids": [str(starts[rva]["id"]) for rva in resolved],
            "external_targets": [],
            "unit_binding": {
                "status": (
                    "complete"
                    if recovery.get("status") == "recovered" and not unresolved
                    else "incomplete"
                ),
                "resolved_target_rvas": resolved,
                "unmaterialized_target_rvas": unresolved,
            },
        })
        if (
            recovery.get("status") != "recovered"
            or recovery.get("closure") != "checked_finite_target_inventory"
            or recovery.get("recovery_kind")
            != "pe32_indexed_absolute_jump_table"
            or recovery.get("failure") is not None
            or recovery["unit_binding"]["status"] != "complete"
        ):
            continue
        recovery["target_set_dependency"] = (
            build_bounded_selector_dependency_v2(recovery)
        )
        if (
            recovery["target_set_dependency"] != observed_dependency
            or recovery.get("target_rvas") != hypothesis.get("target_rvas")
            or recovery.get("target_unit_ids")
            != hypothesis.get("target_unit_ids")
        ):
            continue
        recovery.update({
            "proof_authority": False,
            "proposal_source": "inductive_static_target_inventory_v2",
            "hypothesis_validation": "exact_pe_target_inventory_v2",
        })
        seen.add(identity)
        result.append(recovery)
    return sorted(result, key=lambda row: str(row["id"]))


def _expression_sha256(expression: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(
            expression,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _checked_control_domains(
    records: Sequence[Mapping[str, Any]],
    *,
    binary: StageABinary,
    machine_ir_sha256: str | None,
    indirect_exits: Sequence[Mapping[str, Any]],
    units_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not records:
        return {}
    if machine_ir_sha256 is None:
        raise ValueError("checked control facts require a machine-IR binding")
    exits = {str(row.get("id")): row for row in indirect_exits}
    result: dict[str, dict[str, Any]] = {}
    for record in records:
        exit_id = record.get("indirect_exit_id")
        unit_id = record.get("unit_id")
        fact = record.get("fact")
        authority_id = record.get("authority_id")
        certificate_sha256 = record.get("certificate_sha256")
        if (
            not isinstance(exit_id, str)
            or exit_id not in exits
            or not isinstance(unit_id, str)
            or unit_id not in units_by_id
            or exits[exit_id].get("source_unit_id") != unit_id
            or record.get("binary_sha256") != binary.sha256
            or record.get("machine_ir_sha256") != machine_ir_sha256
            or not isinstance(fact, Mapping)
            or fact.get("kind") != "finite_values"
            or not isinstance(authority_id, str)
            or not isinstance(certificate_sha256, str)
        ):
            raise ValueError("checked control-invariant binding is malformed")
        expression = fact.get("expression")
        values = fact.get("values")
        target_expression = exits[exit_id].get("target_expression")
        expected_expression = (
            pe32_jump_table_index_expression(target_expression)
            if isinstance(target_expression, Mapping)
            else None
        )
        if (
            not isinstance(expression, Mapping)
            or expression != expected_expression
            or not isinstance(values, list)
            or not values
            or values != sorted(set(values))
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 0 <= value <= 0xFFFFFFFF
                for value in values
            )
        ):
            raise ValueError("checked control-invariant fact is not a finite index domain")
        fact_sha256 = sha256(
            json.dumps(
                fact,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
        if record.get("fact_sha256") != fact_sha256:
            raise ValueError("checked control-invariant fact hash is stale")
        core = {
            "unit_id": unit_id,
            "fact_sha256": fact_sha256,
            "fact": copy.deepcopy(dict(fact)),
        }
        expected_authority_id = "checked-control-fact-v2:" + sha256(
            json.dumps(
                {
                    "certificate_sha256": certificate_sha256,
                    "fact": core,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
        if authority_id != expected_authority_id or exit_id in result:
            raise ValueError("checked control-invariant authority identity is corrupt")
        expression_sha256 = sha256(
            json.dumps(
                expression,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
        result[exit_id] = {
            "format": "stage-a-finite-u32-expression-domain-v1",
            "status": "complete",
            "source_unit_id": unit_id,
            "expression_sha256": expression_sha256,
            "values": list(values),
            "authority_dependencies": [authority_id],
        }
    return result


def indirect_predecessor_evidence(
    source_unit: Mapping[str, Any],
    *,
    predecessors_by_target: Mapping[int, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    source_rva = int(source_unit["source"]["original"]["rva_start"])
    result: list[dict[str, Any]] = []
    for predecessor in predecessors_by_target.get(source_rva, []):
        outcome = predecessor.get("semantics", {}).get("outcome", {})
        edge_kind = "fallthrough"
        if isinstance(outcome, Mapping) and outcome.get("kind") == "branch":
            edge_kind = (
                "taken"
                if outcome.get("true_target_rva") == source_rva
                else "fallthrough"
            )
        guard = None
        for edge in predecessor.get("semantics", {}).get("edge_conditions", []):
            if isinstance(edge, Mapping) and edge.get("target_rva") == source_rva:
                guard = copy.deepcopy(edge.get("condition"))
                break
        result.append(
            {
                "source_unit_id": predecessor["id"],
                "edge_kind": edge_kind,
                "guard": guard,
                "instructions": bounded_predecessor_instruction_history(
                    predecessor,
                    predecessors_by_target=predecessors_by_target,
                ),
            }
        )
    return sorted(result, key=lambda item: str(item["source_unit_id"]))


def direct_predecessors_by_target(
    units: Sequence[Mapping[str, Any]],
) -> dict[int, list[Mapping[str, Any]]]:
    predecessors_by_target: dict[int, list[Mapping[str, Any]]] = {}
    for candidate in units:
        control = candidate.get("control")
        if not isinstance(control, Mapping):
            continue
        for target in control.get("direct_targets", []):
            if isinstance(target, int) and not isinstance(target, bool):
                predecessors_by_target.setdefault(target, []).append(candidate)
    return predecessors_by_target


def bounded_predecessor_instruction_history(
    predecessor: Mapping[str, Any],
    *,
    predecessors_by_target: Mapping[int, Sequence[Mapping[str, Any]]],
    max_units: int = 8,
) -> list[dict[str, Any]]:
    history = [
        copy.deepcopy(dict(instruction))
        for instruction in predecessor.get("instructions", [])
        if isinstance(instruction, Mapping)
    ]
    cursor = predecessor
    visited = {str(predecessor.get("id"))}
    for _ in range(max_units - 1):
        if any(
            str(instruction.get("mnemonic", "")).lower() == "cmp"
            for instruction in history
        ):
            break
        source = cursor.get("source", {}).get("original", {})
        start = source.get("rva_start") if isinstance(source, Mapping) else None
        if not isinstance(start, int) or isinstance(start, bool):
            break
        candidates = []
        for candidate in predecessors_by_target.get(start, []):
            candidate_id = str(candidate.get("id"))
            candidate_source = candidate.get("source", {}).get("original", {})
            candidate_outcome = candidate.get("semantics", {}).get("outcome", {})
            candidate_events = candidate.get("semantics", {}).get(
                "external_events", []
            )
            if (
                candidate_id in visited
                or not isinstance(candidate_source, Mapping)
                or candidate_source.get("rva_end") != start
                or not isinstance(candidate_outcome, Mapping)
                or candidate_outcome.get("kind") != "fallthrough"
                or candidate_outcome.get("target_rva") != start
                or (isinstance(candidate_events, list) and candidate_events)
            ):
                continue
            candidates.append(candidate)
        if len(candidates) != 1:
            break
        cursor = candidates[0]
        visited.add(str(cursor.get("id")))
        prefix = [
            copy.deepcopy(dict(instruction))
            for instruction in cursor.get("instructions", [])
            if isinstance(instruction, Mapping)
        ]
        history = prefix + history
    return history


def _incomplete_recovery(
    exit_record: Mapping[str, Any], code: str
) -> dict[str, Any]:
    return {
        **copy.deepcopy(dict(exit_record)),
        "status": "incomplete",
        "closure": "unresolved",
        "target_rvas": [],
        "target_unit_ids": [],
        "external_targets": [],
        "failure": {"code": code},
    }
