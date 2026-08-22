"""Static indirect-target and callback-root recovery."""

from __future__ import annotations

import copy
import json
from typing import Any, Callable, Mapping, Sequence

from ..external.callbacks import parse_callback_source
from ..authority_inputs.target_dependencies import build_bounded_selector_dependency_v2
from ..pe32.model import ParsedPEImage
from ..authority_inputs.static_indirect_replay import (
    direct_predecessors_by_target as _direct_predecessors_by_target,
    indirect_predecessor_evidence as _indirect_predecessor_evidence,
)
from ..util import sha256_bytes
from .control_jump_tables import (
    pe32_jump_table_index_expression,
    recover_static_pe32_jump_table_inventory,
)
from .control_reachability import canonical_indirect_external_targets
from .ir_model import MachineIRExportError


def _indirect_recovery_unit_binding_complete(
    recovery: Mapping[str, Any],
    starts: Mapping[int, Mapping[str, Any]],
) -> bool:
    raw_rvas = recovery.get("target_rvas", [])
    raw_ids = recovery.get("target_unit_ids", [])
    if (
        not isinstance(raw_rvas, Sequence)
        or isinstance(raw_rvas, (str, bytes))
        or not isinstance(raw_ids, Sequence)
        or isinstance(raw_ids, (str, bytes))
    ):
        return False
    target_rvas = []
    for raw_rva in raw_rvas:
        if (
            isinstance(raw_rva, bool)
            or not isinstance(raw_rva, int)
            or not 0 <= raw_rva < 2**32
        ):
            return False
        target_rvas.append(raw_rva)
    if any(rva not in starts for rva in target_rvas):
        return False
    expected_ids = {str(starts[rva]["id"]) for rva in target_rvas}
    if {str(value) for value in raw_ids} != expected_ids:
        return False
    external = canonical_indirect_external_targets(recovery)
    return external is not None and bool(target_rvas or external)


def _recovery_failure_message(failure: Mapping[str, Any]) -> str:
    """Render legacy diagnostics without adding prose to v2 authority records."""

    message = failure.get("message")
    if isinstance(message, str) and message:
        return message
    code = failure.get("code")
    if isinstance(code, str) and code:
        return code
    return "indirect target recovery is incomplete"


def _rebind_preclassified_static_recoveries(
    *,
    indirect_exits: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
    starts: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Bind pre-control recovery facts to the filtered canonical unit index."""

    by_id = {
        str(recovery.get("id")): recovery
        for recovery in recoveries
        if isinstance(recovery, Mapping) and isinstance(recovery.get("id"), str)
    }
    rebound: list[dict[str, Any]] = []
    for exit_record in indirect_exits:
        identity = str(exit_record["id"])
        source = by_id.get(identity)
        if source is None:
            raise MachineIRExportError(
                f"pre-control recovery inventory omits {identity}",
                code="precontrol_recovery_inventory_mismatch",
                unit_id=str(exit_record.get("source_unit_id")),
                rva=int(exit_record.get("source_rva", 0)),
            )
        recovery = copy.deepcopy(dict(source))
        recovery_kind = recovery.get("recovery_kind")
        target_rvas = [
            int(rva)
            for rva in recovery.get("target_rvas", [])
            if isinstance(rva, int) and not isinstance(rva, bool)
        ]
        resolved = sorted(rva for rva in target_rvas if rva in starts)
        unresolved = sorted(rva for rva in target_rvas if rva not in starts)
        recovery["target_unit_ids"] = [starts[rva]["id"] for rva in resolved]
        recovery["unit_binding"] = {
            "status": (
                "complete"
                if recovery.get("status") == "recovered" and not unresolved
                else "incomplete"
            ),
            "resolved_target_rvas": resolved,
            "unmaterialized_target_rvas": unresolved,
        }
        if (
            recovery.get("status") == "recovered"
            and recovery.get("closure") == "checked_finite_target_inventory"
            and recovery_kind == "pe32_indexed_absolute_jump_table"
            and recovery.get("failure") is None
            and _indirect_recovery_unit_binding_complete(recovery, starts)
        ):
            recovery["target_set_dependency"] = (
                build_bounded_selector_dependency_v2(recovery)
            )
        rebound.append(recovery)
    return rebound


def _static_jump_table_recovery_fixed_point(
    *,
    binary: ParsedPEImage,
    units: Sequence[Mapping[str, Any]],
    starts: Mapping[int, Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    root_unit_ids: Sequence[str],
    finite_dataflow_factory: Callable[..., Any],
    max_rounds: int = 16,
) -> tuple[list[dict[str, Any]], int, bool]:
    units_by_id = {str(unit["id"]): unit for unit in units}
    predecessors_by_target = _direct_predecessors_by_target(units)
    selected: list[dict[str, Any]] = []
    previous_signature: str | None = None
    dataflow: Any | None = None
    for round_index in range(1, max_rounds + 1):
        extend = getattr(dataflow, "extend_recovered_indirect_targets", None)
        if (
            dataflow is None
            or not callable(extend)
            or not extend(selected)
        ):
            dataflow = finite_dataflow_factory(
                units=units,
                roots=root_unit_ids,
                recovered_indirect_targets=selected,
            )
        recoveries: list[dict[str, Any]] = []
        for exit_record in indirect_exits:
            source_unit_id = str(exit_record["source_unit_id"])
            source_unit = units_by_id[source_unit_id]
            target_expression = exit_record.get("target_expression") or {}
            index_expression = pe32_jump_table_index_expression(target_expression)
            finite_domain = (
                dataflow.expression_domain(source_unit_id, index_expression)
                if index_expression is not None
                else None
            )
            recovery = recover_static_pe32_jump_table_inventory(
                target_expression=target_expression,
                predecessor_evidence=_indirect_predecessor_evidence(
                    source_unit,
                    predecessors_by_target=predecessors_by_target,
                ),
                image_base=binary.image_base,
                sections=binary.sections,
                read_rva=lambda rva, size: bytes(binary.pe.get_data(rva, size)),
                finite_index_domain=finite_domain,
                valid_target_rvas=None,
            )
            recovery_kind = recovery.get("kind")
            target_rvas = [
                int(rva)
                for rva in recovery.get("target_rvas", [])
                if isinstance(rva, int) and not isinstance(rva, bool)
            ]
            resolved_target_rvas = sorted(
                rva for rva in target_rvas if rva in starts
            )
            unmaterialized_target_rvas = sorted(
                rva for rva in target_rvas if rva not in starts
            )
            recovery.update(
                {
                    "id": exit_record["id"],
                    "recovery_kind": recovery_kind,
                    "source_unit_id": source_unit_id,
                    "source_rva": exit_record["source_rva"],
                    "source_event_index": exit_record.get("source_event_index"),
                    "kind": exit_record["kind"],
                    "target_expression": copy.deepcopy(target_expression),
                    "finite_index_domain": finite_domain,
                    "target_unit_ids": [
                        starts[rva]["id"] for rva in resolved_target_rvas
                    ],
                    "unit_binding": {
                        "status": (
                            "complete"
                            if recovery.get("status") == "recovered"
                            and not unmaterialized_target_rvas
                            else "incomplete"
                        ),
                        "resolved_target_rvas": resolved_target_rvas,
                        "unmaterialized_target_rvas": unmaterialized_target_rvas,
                    },
                }
            )
            if (
                recovery.get("status") == "recovered"
                and recovery.get("closure") == "checked_finite_target_inventory"
                and recovery_kind == "pe32_indexed_absolute_jump_table"
                and recovery.get("failure") is None
                and _indirect_recovery_unit_binding_complete(recovery, starts)
            ):
                recovery["target_set_dependency"] = (
                    build_bounded_selector_dependency_v2(recovery)
                )
            recoveries.append(recovery)
        signature = sha256_bytes(
            json.dumps(
                [
                    {
                        "id": row.get("id"),
                        "status": row.get("status"),
                        "index_values": (
                            row["index"].get("values")
                            if isinstance(row.get("index"), Mapping)
                            else None
                        ),
                        "target_rvas": row.get("target_rvas"),
                        "target_unit_ids": row.get("target_unit_ids"),
                        "failure": row.get("failure"),
                    }
                    for row in recoveries
                ],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        selected = recoveries
        if signature == previous_signature:
            return selected, round_index, True
        previous_signature = signature
    return selected, max_rounds, False


def _callback_root_proposals_from_provenance(
    provenance: Mapping[str, Any],
) -> list[dict[str, Any]]:
    raw = provenance.get("callback_registrations")
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for registration in raw:
        if not isinstance(registration, Mapping) or (
            registration.get("status") != "complete"
        ):
            continue
        targets = registration.get("target_rvas")
        if not isinstance(targets, list):
            continue
        imported = registration.get("import")
        for target in targets:
            if not isinstance(target, int) or isinstance(target, bool):
                continue
            result.append({
                "kind": "registered_callback",
                "rva": target,
                "source_unit_id": registration.get("unit_id"),
                "source_event_index": registration.get("event_index"),
                "dll": (
                    imported.get("dll")
                    if isinstance(imported, Mapping)
                    else None
                ),
                "symbol": (
                    imported.get("symbol")
                    if isinstance(imported, Mapping)
                    else None
                ),
                "callback_source": copy.deepcopy(
                    registration.get("callback_source")
                ),
                "callback_abi": copy.deepcopy(
                    registration.get("callback_abi")
                ),
                "provenance_format": registration.get("format"),
            })
    return result


def _local_callback_cutpoint_proposals(
    binary: ParsedPEImage,
    units: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Bootstrap exact cutpoints for locally visible direct callback words.

    These proposals are deliberately conservative and have no proof authority.
    They may add roots but never remove behavior; regenerated provenance must
    still bind each callback to an exact decoded unit before candidate reconstruction can adapt it.
    """

    executable_sections = tuple(
        section
        for section in getattr(binary, "sections", ())
        if getattr(section, "executable", False)
    )
    result: dict[tuple[int, str, int], dict[str, Any]] = {}
    for unit in units:
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                continue
            abi = event.get("abi_contract")
            if (
                not isinstance(abi, Mapping)
                or abi.get("world_effect") != "callbackRegistration"
            ):
                continue
            argument_words = abi.get("argument_words")
            if (
                not isinstance(argument_words, int)
                or isinstance(argument_words, bool)
                or not 0 <= argument_words <= 64
            ):
                continue
            source = parse_callback_source(
                abi,
                argument_words=argument_words,
                context=f"{unit.get('id')} callback cutpoint proposal",
            )
            if source.kind != "argument_word":
                continue
            arguments = _checked_external_argument_values(event)
            if source.argument_index >= len(arguments):
                continue
            expression = _forward_local_callback_expression(
                arguments[source.argument_index],
                unit=unit,
                event=event,
            )
            value = (
                expression.get("value")
                if isinstance(expression, Mapping)
                and expression.get("op") in {"const", "constant"}
                else None
            )
            if not isinstance(value, int) or isinstance(value, bool) or value == 0:
                continue
            rva = value - binary.image_base if value >= binary.image_base else value
            if not any(
                section.rva_start <= rva < section.rva_end
                for section in executable_sections
            ):
                continue
            key = (rva, str(unit.get("id")), event_index)
            result[key] = {
                "kind": "registered_callback",
                "rva": rva,
                "source_unit_id": str(unit.get("id")),
                "source_event_index": event_index,
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "callback_source": source.as_json(),
                "callback_abi": copy.deepcopy(abi.get("callback_abi")),
                "proposal_basis": "local_exact_callback_argument",
                "proof_authority": False,
            }
    return [result[key] for key in sorted(result)]


def _forward_local_callback_expression(
    expression: Any,
    *,
    unit: Mapping[str, Any],
    event: Mapping[str, Any],
) -> Any:
    if (
        not isinstance(expression, Mapping)
        or expression.get("op") != "load"
        or expression.get("width") != 4
    ):
        return expression
    address = expression.get("address")
    instruction_rva = event.get("instruction_rva")
    ordered = unit.get("semantics", {}).get("ordered_events", [])
    if not isinstance(ordered, list):
        return expression
    if not isinstance(instruction_rva, int):
        matching = [
            item
            for item in ordered
            if isinstance(item, Mapping)
            and item.get("kind") in {"external_call", "indirect_call"}
            and all(
                item.get(field) == event.get(field)
                for field in ("kind", "dll", "symbol", "ordinal", "return_rva")
            )
            and isinstance(item.get("instruction_rva"), int)
        ]
        if len(matching) != 1:
            return expression
        instruction_rva = int(matching[0]["instruction_rva"])
    writes = [
        item
        for item in ordered
        if isinstance(item, Mapping)
        and item.get("kind") == "write"
        and item.get("width") == 4
        and item.get("address") == address
        and isinstance(item.get("instruction_rva"), int)
        and int(item["instruction_rva"]) < instruction_rva
    ]
    if not writes:
        return expression
    latest_rva = max(int(item["instruction_rva"]) for item in writes)
    latest = [item for item in writes if item.get("instruction_rva") == latest_rva]
    return latest[0].get("value") if len(latest) == 1 else expression


def _checked_external_argument_values(event: Mapping[str, Any]) -> list[Any]:
    stack_inputs = event.get("stack_inputs")
    if isinstance(stack_inputs, list) and stack_inputs and all(
        isinstance(item, Mapping) and "value" in item for item in stack_inputs
    ):
        return [
            item["value"]
            for item in sorted(
                stack_inputs,
                key=lambda item: (
                    int(item["offset"])
                    if isinstance(item.get("offset"), int)
                    and not isinstance(item.get("offset"), bool)
                    else 0x1_0000_0000
                ),
            )
        ]
    arguments = event.get("arguments")
    return list(arguments) if isinstance(arguments, list) else []


def _merge_callback_root_proposals(
    prior: Sequence[Mapping[str, Any]],
    proposed: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[int, str, int], dict[str, Any]] = {}
    for raw in (*prior, *proposed):
        rva = raw.get("rva")
        source = raw.get("source_unit_id")
        event_index = raw.get("source_event_index")
        if (
            isinstance(rva, int)
            and not isinstance(rva, bool)
            and isinstance(source, str)
            and isinstance(event_index, int)
            and not isinstance(event_index, bool)
        ):
            by_key[(rva, source, event_index)] = copy.deepcopy(dict(raw))
    return [by_key[key] for key in sorted(by_key)]


def _newly_eligible_callback_roots(
    proposals: Sequence[Mapping[str, Any]],
    reachable_sources: set[str],
    existing_roots: Mapping[int, Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    return [
        proposal
        for proposal in proposals
        if str(proposal["source_unit_id"]) in reachable_sources
        and int(proposal["rva"]) not in existing_roots
    ]
