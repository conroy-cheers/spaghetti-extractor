"""State-independent call-site effects derived from exact import events."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from .call_site_effects import CallSiteEffect, CallSiteId
from .import_abi import SelectedImportABI
from .machine_import_profiles import MachineImportIdentity


def derive_intrinsic_import_call_site_effects(
    units: Iterable[Mapping[str, Any]],
    *,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
) -> dict[CallSiteId, CallSiteEffect]:
    """Project ABI families that do not depend on abstract program state."""

    result: dict[CallSiteId, CallSiteEffect] = {}
    for unit in units:
        unit_id = unit.get("id")
        if not isinstance(unit_id, str) or not unit_id:
            continue
        for event_index, event in enumerate(_events(unit)):
            if event.get("kind") != "external_call":
                continue
            site = CallSiteId(unit_id, event_index)
            identity = _event_import_identity(event)
            selected = import_abis.get(identity) if identity is not None else None
            cleanup = _stack_cleanup(selected)
            memory_preserved = _memory_is_read_only(selected)
            failures = {"result_frame_unknown"}
            if selected is None:
                failures.update({
                    "external_call_abi_unresolved",
                    "register_frame_unknown",
                })
            if cleanup is None:
                failures.add("stack_frame_unknown")
            if not memory_preserved:
                failures.add("memory_frame_unknown")
            result[site] = CallSiteEffect(
                site=site,
                transfer_kind="external_call",
                status="incomplete",
                register_frame_status=(
                    "complete" if selected is not None else "incomplete"
                ),
                preserved_registers=(
                    frozenset(selected.abi.preserved_registers)
                    if selected is not None
                    else frozenset()
                ),
                stack_frame_status=(
                    "complete" if cleanup is not None else "incomplete"
                ),
                stack_cleanup_bytes=cleanup,
                # An empty output inventory must not override a richer
                # selected-import result relation in call-summary analysis.
                result_status="incomplete",
                outputs=(),
                memory_frame_status=(
                    "complete" if memory_preserved else "incomplete"
                ),
                memory_preserved=memory_preserved,
                memory_writes=(),
                abi=None if selected is None else selected.abi,
                argument_words=(
                    None if selected is None else selected.argument_words
                ),
                failure_codes=tuple(sorted(failures)),
            )
    return result


def merge_intrinsic_call_site_effects(
    intrinsic: Mapping[CallSiteId, CallSiteEffect],
    stateful: Sequence[CallSiteEffect],
) -> tuple[list[CallSiteEffect], list[dict[str, Any]]]:
    """Prefer richer stateful facts after checking their ABI projection."""

    merged = dict(intrinsic)
    issues: list[dict[str, Any]] = []
    for observed in stateful:
        expected = merged.get(observed.site)
        if expected is None:
            merged[observed.site] = observed
            continue
        conflict = _projection_conflict(expected, observed)
        if conflict is None:
            merged[observed.site] = observed
            continue
        issues.append({
            "code": "intrinsic_import_call_effect_conflict",
            "unit_id": observed.site.unit_id,
            "event_index": observed.site.event_index,
            "family": conflict,
        })
        merged[observed.site] = CallSiteEffect(
            site=observed.site,
            transfer_kind=observed.transfer_kind,
            status="incomplete",
            register_frame_status="incomplete",
            preserved_registers=frozenset(),
            stack_frame_status="incomplete",
            stack_cleanup_bytes=None,
            result_status="incomplete",
            outputs=(),
            memory_frame_status="incomplete",
            memory_preserved=False,
            memory_writes=(),
            failure_codes=("intrinsic_import_call_effect_conflict",),
        )
    return [merged[site] for site in sorted(merged)], issues


def _projection_conflict(
    expected: CallSiteEffect,
    observed: CallSiteEffect,
) -> str | None:
    if expected.transfer_kind != observed.transfer_kind:
        return "transfer_kind"
    if expected.abi is not None and expected.abi != observed.abi:
        return "abi"
    if (
        expected.argument_words is not None
        and expected.argument_words != observed.argument_words
    ):
        return "argument_words"
    if expected.register_frame_status == "complete" and (
        observed.register_frame_status != "complete"
        or expected.preserved_registers != observed.preserved_registers
    ):
        return "register_frame"
    if expected.stack_frame_status == "complete" and (
        observed.stack_frame_status != "complete"
        or expected.stack_cleanup_bytes != observed.stack_cleanup_bytes
    ):
        return "stack_frame"
    if expected.memory_frame_status == "complete" and (
        observed.memory_frame_status != "complete"
        or expected.memory_preserved != observed.memory_preserved
        or expected.memory_writes != observed.memory_writes
    ):
        return "memory_frame"
    return None


def _events(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    semantics = unit.get("semantics")
    raw = (
        semantics.get("external_events")
        if isinstance(semantics, Mapping)
        else None
    )
    return (
        [event for event in raw if isinstance(event, Mapping)]
        if isinstance(raw, list)
        else []
    )


def _event_import_identity(
    event: Mapping[str, Any],
) -> MachineImportIdentity | None:
    dll = event.get("dll")
    symbol = event.get("symbol")
    ordinal = event.get("ordinal")
    if not isinstance(dll, str):
        return None
    if isinstance(symbol, str) and symbol:
        return MachineImportIdentity(dll.lower(), "symbol", symbol)
    if (
        isinstance(ordinal, int)
        and not isinstance(ordinal, bool)
        and ordinal >= 0
    ):
        return MachineImportIdentity(dll.lower(), "ordinal", ordinal)
    return None


def _stack_cleanup(selected: SelectedImportABI | None) -> int | None:
    if selected is None:
        return None
    if not selected.abi.callee_cleanup:
        return 0
    return (
        None
        if selected.argument_words is None
        else selected.argument_words * 4
    )


def _memory_is_read_only(selected: SelectedImportABI | None) -> bool:
    contract = selected.contract if selected is not None else None
    if not isinstance(contract, Mapping) or contract.get("memory_effect") not in {
        "none",
        "readOnly",
        "read_only",
    }:
        return False
    footprints = contract.get("memory_footprints")
    return footprints is None or footprints == () or footprints == [] or (
        isinstance(footprints, list)
        and all(
            isinstance(footprint, Mapping)
            and footprint.get("access") == "read"
            for footprint in footprints
        )
    )


__all__ = [
    "derive_intrinsic_import_call_site_effects",
    "merge_intrinsic_call_site_effects",
]
