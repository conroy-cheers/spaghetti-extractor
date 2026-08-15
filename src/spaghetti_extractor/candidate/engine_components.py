"""Portable dispatch, callback, and interface synthesis for engine plans."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..external.callbacks import parse_callback_abi, parse_callback_source
from ..pe32.stage_binary import StageAInputError
from .engine_analysis import (
    _direct_outcome_targets,
    _exact_u32_expression,
    _portable_component_selections,
)
from .engine_model import (
    NativeCallbackAdapter,
    NativeCallbackAdapterReceipt,
    NativeCallbackTarget,
    NativeExternalSite,
    NativeImplementationDispatchReceipt,
    NativeImplementationEntry,
    NativeImplementationTarget,
    _PE32_CALLEE_PRESERVED_REGISTERS,
    _canonical_sha256,
)
from .engine_x87 import _blocker, _required_string, _required_u32


def _build_implementation_dispatch_receipt(
    *,
    semantic_input_sha256: str,
    machine_ir_manifest_payload: Mapping[str, Any] | None,
    machine_ir_manifest_sha256: str | None,
    inventory_source_rows: Iterable[Mapping[str, Any]],
    source_rows: Iterable[Mapping[str, Any]],
    rows: Iterable[Mapping[str, Any]],
    external_sites: Iterable[NativeExternalSite],
    selected_portable_components: Iterable[Mapping[str, Any]],
) -> tuple[NativeImplementationDispatchReceipt, tuple[dict[str, Any], ...]]:
    inventory_source_rows = tuple(inventory_source_rows)
    source_rows = tuple(source_rows)
    rows = tuple(rows)
    inventory_ids: set[str] = set()
    for index, source in enumerate(inventory_source_rows):
        unit_id = _required_string(
            source.get("id"), f"implementation inventory unit {index} id"
        )
        if unit_id in inventory_ids:
            raise StageAInputError("duplicate implementation inventory unit id")
        inventory_ids.add(unit_id)
    source_by_id: dict[str, Mapping[str, Any]] = {}
    transfer_by_id: dict[str, tuple[int, str]] = {}
    transfer_id_by_rva: dict[int, str] = {}
    for index, (source, row) in enumerate(zip(source_rows, rows, strict=True)):
        unit_id = _required_string(row.get("id"), f"implementation unit {index} id")
        original = row.get("original")
        if not isinstance(original, Mapping):
            raise StageAInputError(f"{unit_id} has no implementation source span")
        rva = _required_u32(
            original.get("rva_start"), f"{unit_id} implementation RVA"
        )
        transfer_sha256 = str(
            row.get("_source_record_sha256") or _canonical_sha256(source)
        )
        if unit_id in transfer_by_id:
            raise StageAInputError("duplicate state-machine transfer id")
        if rva in transfer_id_by_rva:
            raise StageAInputError("duplicate state-machine transfer RVA")
        source_by_id[unit_id] = source
        transfer_by_id[unit_id] = (rva, transfer_sha256)
        transfer_id_by_rva[rva] = unit_id

    selections = _portable_component_selections(
        selected_portable_components, transfer_by_id=transfer_by_id
    )
    roots: tuple[str, ...] = ()
    reachable_unit_ids: tuple[str, ...] = ()
    potential_unit_ids: tuple[str, ...] = ()
    confirmed_unreachable_unit_ids: tuple[str, ...] = ()
    reachability_frontiers: tuple[dict[str, Any], ...] = ()
    reachability_status = "not_bound"
    reachability_classes = {unit_id: "unbound" for unit_id in transfer_by_id}
    receipt_blockers: list[dict[str, Any]] = []
    reachability: Mapping[str, Any] | None = None
    if machine_ir_manifest_payload is not None:
        control = machine_ir_manifest_payload.get("control")
        candidate = control.get("reachability") if isinstance(control, Mapping) else None
        if isinstance(candidate, Mapping):
            reachability = candidate

    if reachability is not None:
        inventories: dict[str, tuple[str, ...]] = {}
        for field in (
            "roots",
            "reachable_units",
            "potential_units",
            "confirmed_unreachable_units",
        ):
            raw_values = reachability.get(field)
            if not isinstance(raw_values, list) or any(
                not isinstance(value, str) or not value for value in raw_values
            ):
                raise StageAInputError(
                    f"machine-IR reachability {field} is malformed"
                )
            if len(set(raw_values)) != len(raw_values):
                raise StageAInputError(
                    f"machine-IR reachability {field} contains duplicates"
                )
            inventories[field] = tuple(sorted(raw_values))
        roots = inventories["roots"]
        reachable_unit_ids = inventories["reachable_units"]
        potential_unit_ids = inventories["potential_units"]
        confirmed_unreachable_unit_ids = inventories[
            "confirmed_unreachable_units"
        ]
        reachable = set(reachable_unit_ids)
        potential = set(potential_unit_ids)
        unreachable = set(confirmed_unreachable_unit_ids)
        known = inventory_ids
        if (
            not roots
            or not set(roots) <= reachable
            or reachable & potential
            or reachable & unreachable
            or potential & unreachable
            or reachable | potential | unreachable != known
        ):
            raise StageAInputError(
                "machine-IR reachability does not exactly partition its unit inventory"
            )
        for unit_id in reachable:
            reachability_classes[unit_id] = (
                "root" if unit_id in roots else "reachable"
            )
        for unit_id in potential:
            reachability_classes[unit_id] = "potential"
        for unit_id in unreachable:
            reachability_classes[unit_id] = "confirmed_unreachable"
        frontiers = reachability.get("frontiers")
        if not isinstance(frontiers, list):
            raise StageAInputError("machine-IR reachability frontiers are malformed")
        if any(not isinstance(frontier, Mapping) for frontier in frontiers):
            raise StageAInputError(
                "machine-IR reachability frontier inventory is malformed"
            )
        reachability_frontiers = tuple(
            dict(frontier) for frontier in frontiers
        )
        if (
            reachability.get("status") == "complete"
            and not frontiers
            and not potential
        ):
            reachability_status = "complete"
        else:
            reachability_status = "incomplete"
            receipt_blockers.append(_blocker(
                "implementation_reachability_incomplete",
                observed_status=reachability.get("status"),
                potential_units=len(potential),
                frontiers=len(frontiers),
                next_action=(
                    "close the prerequisite rooted static reachability receipt"
                ),
            ))

    entries = tuple(
        NativeImplementationEntry(
            unit_id=unit_id,
            rva=transfer_by_id[unit_id][0],
            transfer_sha256=transfer_by_id[unit_id][1],
            reachability=reachability_classes[unit_id],
            implementation_class=(
                "selected_portable_component"
                if unit_id in selections and selections[unit_id]["dispatch_role"] == "entry"
                else "selected_portable_component_member"
                if unit_id in selections
                else "machine_ir_fallback"
            ),
            dispatch_lookup=(
                "stage_b_region_override_lookup"
                if unit_id in selections and selections[unit_id]["dispatch_role"] == "entry"
                else "component_entry_subsumed"
                if unit_id in selections
                else "stage_b_program_lookup"
            ),
            replacement_id=(
                selections[unit_id]["replacement_id"]
                if unit_id in selections
                else None
            ),
            cluster_id=(
                selections[unit_id]["cluster_id"]
                if unit_id in selections
                else None
            ),
            component_manifest_sha256=(
                selections[unit_id]["component_manifest_sha256"]
                if unit_id in selections
                else None
            ),
            component_entry_rva=(
                selections[unit_id]["entry_rva"]
                if unit_id in selections
                else None
            ),
        )
        for unit_id in sorted(transfer_by_id, key=lambda value: transfer_by_id[value][0])
    )

    targets: list[NativeImplementationTarget] = []
    target_keys: set[tuple[str, str, int | None, str]] = set()
    reachable = set(reachable_unit_ids)

    def add_target(
        *,
        kind: str,
        source_unit_id: str,
        source_event_index: int | None,
        target_unit_id: str | None = None,
        target_rva: int | None = None,
    ) -> None:
        source_rva = transfer_by_id[source_unit_id][0]
        if target_unit_id is None:
            assert target_rva is not None
            target_unit_id = transfer_id_by_rva.get(target_rva)
        if target_unit_id is None or target_unit_id not in transfer_by_id:
            receipt_blockers.append(_blocker(
                "reachable_implementation_target_missing",
                source_unit_id=source_unit_id,
                source_rva=source_rva,
                source_event_index=source_event_index,
                target_rva=target_rva,
                next_action="emit one executable transfer for the reachable target",
            ))
            return
        resolved_rva = transfer_by_id[target_unit_id][0]
        if target_rva is not None and target_rva != resolved_rva:
            receipt_blockers.append(_blocker(
                "reachable_implementation_target_mismatched",
                source_unit_id=source_unit_id,
                source_event_index=source_event_index,
                target_unit_id=target_unit_id,
                expected_rva=resolved_rva,
                observed_rva=target_rva,
                next_action="regenerate the target binding from exact machine IR",
            ))
            return
        if target_unit_id not in reachable:
            receipt_blockers.append(_blocker(
                "reachable_implementation_target_not_rooted",
                source_unit_id=source_unit_id,
                source_event_index=source_event_index,
                target_unit_id=target_unit_id,
                target_rva=resolved_rva,
                next_action="include the feasible target in rooted reachability",
            ))
            return
        key = (kind, source_unit_id, source_event_index, target_unit_id)
        if key in target_keys:
            receipt_blockers.append(_blocker(
                "duplicate_reachable_implementation_target",
                source_unit_id=source_unit_id,
                source_event_index=source_event_index,
                target_unit_id=target_unit_id,
                next_action="emit each reachable dispatch target exactly once",
            ))
            return
        target_keys.add(key)
        targets.append(NativeImplementationTarget(
            kind=kind,
            source_unit_id=source_unit_id,
            source_rva=source_rva,
            source_event_index=source_event_index,
            target_unit_id=target_unit_id,
            target_rva=resolved_rva,
        ))

    if reachability_status == "complete":
        control = machine_ir_manifest_payload.get("control")
        assert isinstance(control, Mapping)
        provenance = control.get("external_interface_provenance")
        if not isinstance(provenance, Mapping):
            raise StageAInputError(
                "machine-IR manifest has no external-interface provenance"
            )
        raw_resolutions = provenance.get("resolutions")
        if not isinstance(raw_resolutions, list):
            raise StageAInputError("machine-IR indirect resolutions are malformed")
        resolutions: dict[tuple[str, int | None], Mapping[str, Any]] = {}
        for index, raw in enumerate(raw_resolutions):
            if not isinstance(raw, Mapping):
                raise StageAInputError(
                    f"machine-IR indirect resolution {index} is malformed"
                )
            source_unit_id = _required_string(
                raw.get("source_unit_id"),
                f"machine-IR indirect resolution {index} source unit",
            )
            event_index = raw.get("source_event_index")
            if event_index is not None and (
                isinstance(event_index, bool) or not isinstance(event_index, int)
            ):
                raise StageAInputError(
                    "machine-IR indirect resolution event index is malformed"
                )
            key = (source_unit_id, event_index)
            if key in resolutions:
                raise StageAInputError("duplicate machine-IR indirect resolution")
            resolutions[key] = raw

        site_by_event = {
            (site.transfer_id, site.event_index): site
            for site in external_sites
        }
        summaries = control.get("internal_call_preservation")
        summaries = summaries.get("summaries") if isinstance(summaries, Mapping) else None
        if not isinstance(summaries, list):
            raise StageAInputError(
                "machine-IR manifest has no internal-call summary inventory"
            )
        summary_by_target_rva: dict[int, Mapping[str, Any]] = {}
        for index, raw in enumerate(summaries):
            if not isinstance(raw, Mapping):
                raise StageAInputError(
                    f"internal-call summary {index} is malformed"
                )
            target_rva = raw.get("target_rva")
            if isinstance(target_rva, int) and not isinstance(target_rva, bool):
                if target_rva in summary_by_target_rva:
                    raise StageAInputError("duplicate internal-call target summary")
                summary_by_target_rva[target_rva] = raw

        for source_unit_id in reachable_unit_ids:
            unit = source_by_id[source_unit_id]
            unit_control = unit.get("control")
            if not isinstance(unit_control, Mapping):
                raise StageAInputError(
                    f"{source_unit_id} has no checked control inventory"
                )
            direct_targets = unit_control.get("direct_targets")
            if not isinstance(direct_targets, list):
                raise StageAInputError(
                    f"{source_unit_id} direct target inventory is malformed"
                )
            if len(set(direct_targets)) != len(direct_targets):
                raise StageAInputError(
                    f"{source_unit_id} direct target inventory contains duplicates"
                )
            for target_rva in direct_targets:
                add_target(
                    kind="direct_control",
                    source_unit_id=source_unit_id,
                    source_event_index=None,
                    target_rva=_required_u32(
                        target_rva, f"{source_unit_id} direct target RVA"
                    ),
                )
            semantics = unit.get("semantics")
            if not isinstance(semantics, Mapping):
                raise StageAInputError(f"{source_unit_id} semantics are malformed")
            events = semantics.get("external_events")
            if not isinstance(events, list):
                raise StageAInputError(
                    f"{source_unit_id} external event inventory is malformed"
                )
            for event_index, event in enumerate(events):
                if not isinstance(event, Mapping):
                    raise StageAInputError(
                        f"{source_unit_id} external event {event_index} is malformed"
                    )
                kind = event.get("kind")
                if kind == "internal_call":
                    target_rva = _required_u32(
                        event.get("target_rva"),
                        f"{source_unit_id} internal-call target RVA",
                    )
                    add_target(
                        kind="internal_call",
                        source_unit_id=source_unit_id,
                        source_event_index=event_index,
                        target_rva=target_rva,
                    )
                    summary = summary_by_target_rva.get(target_rva)
                    return_behavior = (
                        summary.get("return_behavior")
                        if isinstance(summary, Mapping)
                        else None
                    )
                    may_return = (
                        return_behavior.get("may_return")
                        if isinstance(return_behavior, Mapping)
                        else None
                    )
                    if may_return is True:
                        add_target(
                            kind="call_continuation",
                            source_unit_id=source_unit_id,
                            source_event_index=event_index,
                            target_rva=_required_u32(
                                event.get("return_rva"),
                                f"{source_unit_id} return continuation RVA",
                            ),
                        )
                    elif may_return is not False:
                        receipt_blockers.append(_blocker(
                            "call_continuation_summary_missing",
                            source_unit_id=source_unit_id,
                            source_event_index=event_index,
                            target_rva=target_rva,
                            next_action=(
                                "complete the prerequisite internal-call return summary"
                            ),
                        ))
                elif kind in {"external_call", "indirect_call"}:
                    site = site_by_event.get((source_unit_id, event_index))
                    if site is not None and site.disposition == "returns_here":
                        add_target(
                            kind="call_continuation",
                            source_unit_id=source_unit_id,
                            source_event_index=event_index,
                            target_rva=_required_u32(
                                event.get("return_rva"),
                                f"{source_unit_id} return continuation RVA",
                            ),
                        )
                if kind != "indirect_call":
                    continue
                resolution = resolutions.get((source_unit_id, event_index))
                if resolution is None or resolution.get("status") != "recovered":
                    receipt_blockers.append(_blocker(
                        "reachable_indirect_implementation_targets_missing",
                        source_unit_id=source_unit_id,
                        source_event_index=event_index,
                        next_action=(
                            "close the prerequisite finite indirect-target inventory"
                        ),
                    ))
                    continue
                target_unit_ids = resolution.get("target_unit_ids")
                if not isinstance(target_unit_ids, list) or any(
                    not isinstance(value, str) for value in target_unit_ids
                ):
                    raise StageAInputError(
                        "machine-IR indirect internal targets are malformed"
                    )
                if len(set(target_unit_ids)) != len(target_unit_ids):
                    raise StageAInputError(
                        "machine-IR indirect internal targets contain duplicates"
                    )
                for target_unit_id in target_unit_ids:
                    add_target(
                        kind="indirect_internal",
                        source_unit_id=source_unit_id,
                        source_event_index=event_index,
                        target_unit_id=target_unit_id,
                    )

            outcome = semantics.get("outcome")
            if isinstance(outcome, Mapping) and outcome.get("kind") == "indirect_jump":
                resolution = resolutions.get((source_unit_id, None))
                if resolution is None or resolution.get("status") != "recovered":
                    receipt_blockers.append(_blocker(
                        "reachable_indirect_implementation_targets_missing",
                        source_unit_id=source_unit_id,
                        source_event_index=None,
                        next_action=(
                            "close the prerequisite finite indirect-target inventory"
                        ),
                    ))
                else:
                    target_unit_ids = resolution.get("target_unit_ids")
                    if not isinstance(target_unit_ids, list) or any(
                        not isinstance(value, str) for value in target_unit_ids
                    ):
                        raise StageAInputError(
                            "machine-IR indirect jump targets are malformed"
                        )
                    if len(set(target_unit_ids)) != len(target_unit_ids):
                        raise StageAInputError(
                            "machine-IR indirect jump targets contain duplicates"
                        )
                    for target_unit_id in target_unit_ids:
                        add_target(
                            kind="indirect_internal",
                            source_unit_id=source_unit_id,
                            source_event_index=None,
                            target_unit_id=target_unit_id,
                        )

    for unit_id in roots:
        selection = selections.get(unit_id)
        if selection is not None and selection["dispatch_role"] == "subsumed_member":
            receipt_blockers.append(_blocker(
                "portable_component_root_is_not_boundary_entry",
                target_unit_id=unit_id,
                target_rva=transfer_by_id[unit_id][0],
                next_action="split the component or expose this root as a checked entry",
            ))
    for target in targets:
        target_selection = selections.get(target.target_unit_id)
        if target_selection is None or target_selection["dispatch_role"] != "subsumed_member":
            continue
        source_selection = selections.get(target.source_unit_id)
        if (
            source_selection is None
            or source_selection["cluster_id"] != target_selection["cluster_id"]
            or source_selection["component_manifest_sha256"]
            != target_selection["component_manifest_sha256"]
        ):
            receipt_blockers.append(_blocker(
                "portable_component_internal_member_has_external_incoming_edge",
                source_unit_id=target.source_unit_id,
                source_rva=target.source_rva,
                target_unit_id=target.target_unit_id,
                target_rva=target.target_rva,
                next_action="split the component or add the target as a checked boundary entry",
            ))

    targets_tuple = tuple(sorted(
        targets,
        key=lambda item: (
            item.source_rva,
            item.kind,
            -1 if item.source_event_index is None else item.source_event_index,
            item.target_rva,
        ),
    ))
    blockers_tuple = tuple(sorted(
        receipt_blockers,
        key=lambda item: (
            str(item.get("category")),
            str(item.get("source_unit_id")),
            str(item.get("source_event_index")),
            str(item.get("target_unit_id")),
            str(item.get("target_rva")),
        ),
    ))
    receipt = NativeImplementationDispatchReceipt(
        semantic_input_sha256=semantic_input_sha256,
        machine_ir_manifest_sha256=machine_ir_manifest_sha256,
        reachability_status=reachability_status,
        roots=roots,
        reachable_unit_ids=reachable_unit_ids,
        potential_unit_ids=potential_unit_ids,
        confirmed_unreachable_unit_ids=confirmed_unreachable_unit_ids,
        reachability_frontiers=reachability_frontiers,
        entries=entries,
        targets=targets_tuple,
        blockers=blockers_tuple,
    )
    return receipt, blockers_tuple


def _machine_ir_internal_indirect_sites(
    machine_ir_manifest_payload: Mapping[str, Any],
) -> frozenset[tuple[str, int]]:
    """Return indirect call sites proven to target only machine-IR units."""

    control = machine_ir_manifest_payload.get("control")
    provenance = (
        control.get("external_interface_provenance")
        if isinstance(control, Mapping)
        else None
    )
    resolutions = (
        provenance.get("resolutions")
        if isinstance(provenance, Mapping)
        else None
    )
    if not isinstance(resolutions, list):
        return frozenset()
    result: set[tuple[str, int]] = set()
    for raw in resolutions:
        if not isinstance(raw, Mapping) or raw.get("status") != "recovered":
            continue
        unit_id = raw.get("source_unit_id")
        event_index = raw.get("source_event_index")
        targets = raw.get("target_unit_ids")
        if (
            isinstance(unit_id, str)
            and isinstance(event_index, int)
            and not isinstance(event_index, bool)
            and isinstance(targets, list)
            and targets
            and all(isinstance(target, str) and target for target in targets)
        ):
            result.add((unit_id, event_index))
    return frozenset(result)


def _machine_ir_internal_call_preservation(
    payload: Mapping[str, Any] | None,
) -> dict[int, frozenset[str]]:
    """Load complete preservation summaries from a hash-bound manifest."""

    if payload is None:
        return {}
    control = payload.get("control")
    summaries = (
        control.get("internal_call_preservation")
        if isinstance(control, Mapping)
        else None
    )
    if not isinstance(summaries, Mapping):
        raise StageAInputError(
            "machine-IR manifest has no internal-call preservation inventory"
        )
    rows = summaries.get("summaries")
    if not isinstance(rows, list):
        raise StageAInputError("internal-call preservation summaries must be a list")
    result: dict[int, frozenset[str]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise StageAInputError(
                f"internal-call preservation summary {index} is malformed"
            )
        if raw.get("status") != "complete":
            continue
        target_rva = _required_u32(
            raw.get("target_rva"),
            f"internal-call preservation summary {index} target RVA",
        )
        registers = raw.get("preserved_registers")
        if not isinstance(registers, list) or any(
            not isinstance(register, str)
            or register not in _PE32_CALLEE_PRESERVED_REGISTERS
            for register in registers
        ):
            raise StageAInputError(
                f"internal-call preservation summary {index} has invalid registers"
            )
        preserved = frozenset(registers)
        if target_rva in result and result[target_rva] != preserved:
            raise StageAInputError(
                f"internal-call preservation target {target_rva:#x} is ambiguous"
            )
        result[target_rva] = preserved
    return result


def _machine_ir_callback_registrations(
    payload: Mapping[str, Any] | None,
) -> dict[tuple[str, int], Mapping[str, Any]]:
    if payload is None:
        return {}
    control = payload.get("control")
    provenance = (
        control.get("external_interface_provenance")
        if isinstance(control, Mapping)
        else None
    )
    rows = (
        provenance.get("callback_registrations")
        if isinstance(provenance, Mapping)
        else None
    )
    if rows is None:
        return {}
    if not isinstance(rows, list):
        raise StageAInputError("callback-registration provenance must be a list")
    result: dict[tuple[str, int], Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        if (
            not isinstance(row, Mapping)
            or row.get("format")
            != "stage-a-callback-registration-provenance-v1"
            or row.get("record_kind") != "callback_registration"
            or not isinstance(row.get("unit_id"), str)
            or not isinstance(row.get("event_index"), int)
            or isinstance(row.get("event_index"), bool)
        ):
            raise StageAInputError(
                f"callback-registration provenance {index} is malformed"
            )
        key = (str(row["unit_id"]), int(row["event_index"]))
        if key in result and result[key] != row:
            raise StageAInputError(
                f"callback-registration provenance for {key!r} is ambiguous"
            )
        result[key] = row
    return result


def _machine_ir_external_interface_methods(
    payload: Mapping[str, Any] | None,
) -> dict[tuple[str, int], Mapping[str, Any]]:
    """Load uniquely recovered external call protocols from the bound manifest."""

    if payload is None:
        return {}
    control = payload.get("control")
    provenance = (
        control.get("external_interface_provenance")
        if isinstance(control, Mapping)
        else None
    )
    rows = provenance.get("resolutions") if isinstance(provenance, Mapping) else None
    if rows is None:
        return {}
    if not isinstance(rows, list):
        raise StageAInputError("external-interface resolutions must be a list")
    result: dict[tuple[str, int], Mapping[str, Any]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping) or raw.get("status") != "recovered":
            continue
        unit_id = raw.get("source_unit_id")
        event_index = raw.get("source_event_index")
        targets = raw.get("external_targets")
        if (
            not isinstance(unit_id, str)
            or not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or not isinstance(targets, list)
            or len(targets) != 1
            or not isinstance(targets[0], Mapping)
        ):
            continue
        target = targets[0]
        protocol = target.get("external_protocol")
        if protocol is None:
            continue
        argument_words = target.get("argument_words")
        outputs = target.get("out_interfaces", [])
        protocol_kind = (
            protocol.get("kind") if isinstance(protocol, Mapping) else None
        )
        callback_abi = (
            protocol.get("callback_abi")
            if protocol_kind == "pe32-previous-callback"
            else None
        )
        resolved_contract = (
            protocol.get("machine_contract")
            if protocol_kind == "pe32-resolved-export"
            and isinstance(protocol, Mapping)
            else None
        )
        resolved_target = (
            protocol.get("target")
            if protocol_kind == "pe32-resolved-export"
            and isinstance(protocol, Mapping)
            else None
        )
        if (
            not isinstance(protocol, Mapping)
            or protocol_kind
            not in {
                "pe32-interface-method",
                "pe32-previous-callback",
                "pe32-resolved-export",
            }
            or not isinstance(argument_words, int)
            or isinstance(argument_words, bool)
            or not 0 <= argument_words <= 256
            or not isinstance(outputs, list)
            or any(not isinstance(output, Mapping) for output in outputs)
            or (
                protocol_kind == "pe32-previous-callback"
                and (
                    not isinstance(callback_abi, Mapping)
                    or callback_abi.get("kind") != "generic_callback"
                    or callback_abi.get("argument_words") != argument_words
                    or callback_abi.get("stack_cleanup_bytes")
                    != argument_words * 4
                    or not isinstance(callback_abi.get("nullable"), bool)
                    or outputs
                )
            )
            or (
                protocol_kind == "pe32-resolved-export"
                and (
                    protocol.get("transfer_kind") != "call"
                    or not isinstance(resolved_target, Mapping)
                    or not isinstance(resolved_contract, Mapping)
                    or resolved_contract.get("import") != resolved_target
                    or not isinstance(resolved_contract.get("arity"), Mapping)
                    or resolved_contract["arity"].get("kind") != "fixed"
                    or resolved_contract["arity"].get("words") != argument_words
                    or not isinstance(resolved_contract.get("effect_model"), Mapping)
                    or resolved_contract["effect_model"].get("kind")
                    != "exact_native_dll_callthrough_v1"
                    or resolved_contract["effect_model"].get("prerequisites")
                    != {
                        "same_pinned_dll_implementation": True,
                        "exact_machine_arguments": True,
                        "candidate_address_space_used_directly": True,
                    }
                    or resolved_contract.get("memory_effect") != "nativeCallthrough"
                    or resolved_contract.get("world_effect") != "nativeCallthrough"
                    or resolved_contract.get("callback_effect") != "none"
                    or not isinstance(target.get("abi"), Mapping)
                    or target["abi"].get("template")
                    != resolved_contract.get("abi_template")
                    or outputs
                )
            )
        ):
            raise StageAInputError(
                f"recovered external protocol resolution {index} is malformed"
            )
        key = (unit_id, event_index)
        value = dict(target)
        if key in result and result[key] != value:
            raise StageAInputError(
                f"external-interface resolution for {key!r} is ambiguous"
            )
        result[key] = value
    return result


def _build_callback_adapter_receipts(
    *,
    sites: tuple[NativeExternalSite, ...],
    adapters: tuple[NativeCallbackAdapter, ...],
    targets: tuple[NativeCallbackTarget, ...],
) -> tuple[
    tuple[NativeCallbackAdapterReceipt, ...],
    tuple[dict[str, Any], ...],
]:
    """Bind generated adapter entries to their normalized callback contracts."""

    adapters_by_site: dict[
        tuple[int, int], list[NativeCallbackAdapter]
    ] = {}
    duplicate_entries: set[tuple[int, int, int, int]] = set()
    seen_entries: set[tuple[int, int, int, int]] = set()
    for adapter in adapters:
        key = (
            adapter.instruction_rva,
            adapter.argument_index,
            adapter.original_rva,
            adapter.callback_rva,
        )
        if key in seen_entries:
            duplicate_entries.add(key)
        seen_entries.add(key)
        adapters_by_site.setdefault(
            (adapter.instruction_rva, adapter.argument_index), []
        ).append(adapter)

    blockers: list[dict[str, Any]] = []
    if duplicate_entries:
        blockers.append(_blocker(
            "callback_adapter_receipt_duplicate",
            observed=[list(value) for value in sorted(duplicate_entries)],
            next_action=(
                "emit exactly one native callback adapter entry for each checked "
                "registration-site target"
            ),
        ))

    target_by_rva = {target.rva: target for target in targets}
    consumed_adapter_ids: set[int] = set()
    receipts: list[NativeCallbackAdapterReceipt] = []
    for site in sorted(
        sites, key=lambda item: (item.instruction_rva, item.event_index)
    ):
        contract = site.checked_external_contract
        if contract is None or contract.callback_effect != "explicit":
            continue
        checked_adapter = contract.callback_adapter
        if checked_adapter is None:
            blockers.append(_blocker(
                "callback_adapter_receipt_incomplete",
                transfer_id=site.transfer_id,
                event_index=site.event_index,
                instruction_rva=site.instruction_rva,
                observed="explicit callback effect has no normalized adapter",
                next_action=(
                    "regenerate the exact checked external-site contract before "
                    "native candidate planning"
                ),
            ))
            continue
        try:
            source = parse_callback_source(
                {"callback_source": checked_adapter.source},
                argument_words=contract.argument_words,
                context=f"{site.transfer_id} callback receipt",
            )
            abi = parse_callback_abi(
                {"callback_abi": checked_adapter.abi},
                context=f"{site.transfer_id} callback receipt",
            )
        except StageAInputError as exc:
            blockers.append(_blocker(
                "callback_adapter_receipt_incomplete",
                transfer_id=site.transfer_id,
                event_index=site.event_index,
                instruction_rva=site.instruction_rva,
                detail=str(exc),
                next_action=(
                    "emit one canonical callback source and exact PE32 callback ABI"
                ),
            ))
            continue

        site_key = (site.instruction_rva, source.argument_index)
        actual_entries = tuple(sorted(
            adapters_by_site.get(site_key, []),
            key=lambda item: (item.callback_rva, item.original_rva, item.id),
        ))
        expected_rvas = checked_adapter.target_rvas
        actual_rvas = tuple(entry.callback_rva for entry in actual_entries)
        source_matches = (
            site.callback_source_kind == source.kind
            and site.callback_argument_index == source.argument_index
            and site.callback_argument_offset
            == source.stack_argument_offset(contract.argument_base_offset)
            and site.callback_pointee_offset == source.pointee_offset
            and site.callback_nullable == abi.nullable
        )
        target_abis_match = all(
            target_by_rva.get(rva) is not None
            and target_by_rva[rva].kind == abi.kind
            and target_by_rva[rva].stack_cleanup_bytes
            == abi.stack_cleanup_bytes
            for rva in expected_rvas
        )
        entries_match = (
            actual_rvas == expected_rvas
            and len({entry.id for entry in actual_entries})
            == len(actual_entries)
            and all(
                entry.original_rva == entry.callback_rva
                and entry.symbol
                == f"stage_b_payload_callback_{entry.callback_rva:08x}"
                for entry in actual_entries
            )
        )
        if not source_matches or not target_abis_match or not entries_match:
            blockers.append(_blocker(
                "callback_adapter_receipt_mismatch",
                transfer_id=site.transfer_id,
                event_index=site.event_index,
                instruction_rva=site.instruction_rva,
                expected={
                    "source": checked_adapter.source,
                    "abi": checked_adapter.abi,
                    "target_rvas": list(expected_rvas),
                },
                observed={
                    "site_callback_registration": (
                        site.payload().get("callback_registration")
                    ),
                    "adapter_entries": [
                        entry.payload() for entry in actual_entries
                    ],
                },
                next_action=(
                    "regenerate the callback adapters from the exact normalized "
                    "finite target set"
                ),
            ))
            continue
        consumed_adapter_ids.update(entry.id for entry in actual_entries)
        receipts.append(NativeCallbackAdapterReceipt(
            site_id=site.id,
            transfer_id=site.transfer_id,
            event_index=site.event_index,
            instruction_rva=site.instruction_rva,
            checked_external_contract_sha256=_canonical_sha256(
                contract.payload()
            ),
            source=checked_adapter.source,
            abi=checked_adapter.abi,
            lifetime=checked_adapter.lifetime,
            invocation=checked_adapter.invocation,
            target_rvas=expected_rvas,
            adapter_entries=actual_entries,
        ))

    unreceipted = [
        adapter.payload()
        for adapter in adapters
        if adapter.id not in consumed_adapter_ids
    ]
    if unreceipted:
        blockers.append(_blocker(
            "callback_adapter_receipt_missing",
            observed=unreceipted,
            next_action=(
                "bind every generated callback adapter to one explicit checked "
                "external-site callback contract"
            ),
        ))
    return tuple(receipts), tuple(blockers)


def _previous_callback_storage_writes(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    """Return slot writes carrying prior callback tokens and all static writes."""

    callback_results: set[tuple[int, str]] = set()
    row_list = list(rows)
    for row in row_list:
        events = row.get("ordered_events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, Mapping) or event.get("family") != "external":
                continue
            abi = event.get("abi_contract")
            result = abi.get("callback_result") if isinstance(abi, Mapping) else None
            return_rva = event.get("return_rva")
            if (
                isinstance(result, Mapping)
                and result.get("origin") == "previous_registered_callback"
                and isinstance(result.get("register"), str)
                and isinstance(return_rva, int)
                and not isinstance(return_rva, bool)
            ):
                callback_results.add((return_rva, str(result["register"]).lower()))

    callback_writes: dict[int, set[int]] = {}
    all_writes: dict[int, set[int]] = {}
    for row in row_list:
        original = row.get("original")
        row_rva = original.get("rva_start") if isinstance(original, Mapping) else None
        if not isinstance(row_rva, int) or isinstance(row_rva, bool):
            continue
        events = row.get("ordered_events")
        if not isinstance(events, list):
            continue
        for event in events:
            if (
                not isinstance(event, Mapping)
                or event.get("family") != "memory"
                or event.get("kind") != "write"
                or event.get("width") != 4
            ):
                continue
            slot = _exact_u32_expression(event.get("address"))
            if slot is None:
                continue
            all_writes.setdefault(slot, set()).add(row_rva)
            value = event.get("value")
            if (
                isinstance(value, Mapping)
                and value.get("op") == "reg"
                and isinstance(value.get("name"), str)
                and (row_rva, str(value["name"]).lower()) in callback_results
            ):
                callback_writes.setdefault(slot, set()).add(row_rva)
    return callback_writes, all_writes


def _callback_storage_origin_is_safe(
    *,
    rows: Iterable[Mapping[str, Any]],
    use_rva: int,
    storage_va: int,
    callback_writes: Mapping[int, set[int]],
    all_writes: Mapping[int, set[int]],
    initial_zero_ranges: tuple[tuple[int, int], ...],
    nullable: bool,
) -> str | None:
    callback_rows = callback_writes.get(storage_va, set())
    if not callback_rows or all_writes.get(storage_va, set()) != callback_rows:
        return None
    if nullable and any(
        start <= storage_va and storage_va + 4 <= end
        for start, end in initial_zero_ranges
    ):
        return "initial_zero_or_previous_registered_callback"
    predecessors: dict[int, set[int]] = {}
    for row in rows:
        original = row.get("original")
        source = original.get("rva_start") if isinstance(original, Mapping) else None
        if not isinstance(source, int) or isinstance(source, bool):
            continue
        for target in _direct_outcome_targets(row):
            predecessors.setdefault(target, set()).add(source)

    visiting: set[int] = set()
    memo: dict[int, bool] = {}

    def covered(node: int) -> bool:
        if node in callback_rows:
            return True
        if node in memo:
            return memo[node]
        if node in visiting:
            return False
        incoming = predecessors.get(node, set())
        if not incoming:
            memo[node] = False
            return False
        visiting.add(node)
        result = all(covered(predecessor) for predecessor in incoming)
        visiting.remove(node)
        memo[node] = result
        return result

    return "dominating_previous_registered_callback" if covered(use_rva) else None
