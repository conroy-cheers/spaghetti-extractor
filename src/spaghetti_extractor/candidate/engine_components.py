"""Portable dispatch, callback, and interface synthesis for engine plans."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ..external.callbacks import parse_callback_abi, parse_callback_source
from ..errors import ToolkitInputError
from .authority.execution import CandidateExecutionAuthorityV3
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
    _canonical_sha256,
)
from .engine_x87 import _blocker, _required_string, _required_u32


def _build_implementation_dispatch_receipt(
    *,
    semantic_input_sha256: str,
    execution_authority: CandidateExecutionAuthorityV3,
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
            raise ToolkitInputError("duplicate implementation inventory unit id")
        inventory_ids.add(unit_id)
    source_by_id: dict[str, Mapping[str, Any]] = {}
    transfer_by_id: dict[str, tuple[int, str]] = {}
    transfer_id_by_rva: dict[int, str] = {}
    for index, (source, row) in enumerate(zip(source_rows, rows, strict=True)):
        unit_id = _required_string(row.get("id"), f"implementation unit {index} id")
        original = row.get("original")
        if not isinstance(original, Mapping):
            raise ToolkitInputError(f"{unit_id} has no implementation source span")
        rva = _required_u32(
            original.get("rva_start"), f"{unit_id} implementation RVA"
        )
        transfer_sha256 = str(
            row.get("_source_record_sha256") or _canonical_sha256(source)
        )
        if unit_id in transfer_by_id:
            raise ToolkitInputError("duplicate state-machine transfer id")
        if rva in transfer_id_by_rva:
            raise ToolkitInputError("duplicate state-machine transfer RVA")
        source_by_id[unit_id] = source
        transfer_by_id[unit_id] = (rva, transfer_sha256)
        transfer_id_by_rva[rva] = unit_id

    selections = _portable_component_selections(
        selected_portable_components, transfer_by_id=transfer_by_id
    )
    roots = execution_authority.root_unit_ids
    reachable_unit_ids = execution_authority.reachable_unit_ids
    potential_unit_ids: tuple[str, ...] = ()
    confirmed_unreachable_unit_ids = tuple(
        sorted(inventory_ids - set(reachable_unit_ids))
    )
    reachability_frontiers: tuple[dict[str, Any], ...] = ()
    reachability_status = "complete"
    reachability_classes = {
        unit_id: (
            "root"
            if unit_id in roots
            else "reachable"
            if unit_id in set(reachable_unit_ids)
            else "confirmed_unreachable"
        )
        for unit_id in transfer_by_id
    }
    receipt_blockers: list[dict[str, Any]] = []
    if set(reachable_unit_ids) - inventory_ids:
        raise ToolkitInputError(
            "checked rooted authority references units absent from machine IR"
        )

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
                "spx_region_override_lookup"
                if unit_id in selections and selections[unit_id]["dispatch_role"] == "entry"
                else "component_entry_subsumed"
                if unit_id in selections
                else "spx_program_lookup"
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

    for edge in execution_authority.edges:
        if edge.edge_kind == "recovered_indirect":
            continue
        add_target(
            kind=(
                "internal_call"
                if edge.edge_kind == "internal_call"
                else "direct_control"
            ),
            source_unit_id=edge.source_unit_id,
            source_event_index=None,
            target_unit_id=edge.target_unit_id,
        )
    for dispatch in execution_authority.indirect_dispatches:
        for target_unit_id in dispatch.target_unit_ids:
            add_target(
                kind="indirect_internal",
                source_unit_id=dispatch.source_unit_id,
                source_event_index=dispatch.source_event_index,
                target_unit_id=target_unit_id,
            )

    site_by_event = {
        (site.transfer_id, site.event_index): site for site in external_sites
    }
    for source_unit_id in reachable_unit_ids:
        unit = source_by_id[source_unit_id]
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            raise ToolkitInputError(f"{source_unit_id} semantics are malformed")
        events = semantics.get("external_events")
        if not isinstance(events, list):
            raise ToolkitInputError(
                f"{source_unit_id} external event inventory is malformed"
            )
        summary = execution_authority.summary_for_unit(source_unit_id)
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                raise ToolkitInputError(
                    f"{source_unit_id} external event {event_index} is malformed"
                )
            kind = event.get("kind")
            if kind == "internal_call":
                call = summary.call_effect(source_unit_id, event_index)
                if call is None or call.kind not in {
                    "direct_internal",
                    "finite_internal",
                }:
                    receipt_blockers.append(_blocker(
                        "checked_internal_call_summary_missing",
                        source_unit_id=source_unit_id,
                        source_event_index=event_index,
                        next_action="check the exact call effect in its parametric SCC",
                    ))
                    continue
                return_rva = _required_u32(
                    event.get("return_rva"),
                    f"{source_unit_id} return continuation RVA",
                )
                return_unit_id = transfer_id_by_rva.get(return_rva)
                if return_unit_id in reachable:
                    add_target(
                        kind="call_continuation",
                        source_unit_id=source_unit_id,
                        source_event_index=event_index,
                        target_unit_id=return_unit_id,
                    )
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
        except ToolkitInputError as exc:
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
                == f"spx_payload_callback_{entry.callback_rva:08x}"
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
