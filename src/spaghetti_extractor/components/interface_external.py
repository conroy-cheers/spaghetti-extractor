"""External-service checks for component machine-to-logical interfaces."""

from __future__ import annotations

import copy
from typing import Any, Callable, Mapping, Sequence

from .external_sites import ComponentExternalSite, ComponentExternalSiteSlice
from .interface_schema import (
    _add_owner,
    _event_arguments,
    _event_identity,
    _identity_complete,
    _issue,
    _normalize_identity,
    _resolve_effect_reference,
)


def check_service(
    service: Mapping[str, Any],
    service_index: int,
    machine: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]],
    owners: dict[str, list[dict[str, str]]],
    issues: list[dict[str, Any]],
    external_site_index: Mapping[
        tuple[str, int], tuple[ComponentExternalSite, ...]
    ],
) -> None:
    location = f"/services/{service_index}"
    identity = service.get("identity")
    events = service.get("events")
    if not isinstance(identity, Mapping):
        _issue(
            issues,
            "incomplete",
            "missing_service_identity",
            location + "/identity",
            expected="structured machine event identity",
            observed=identity,
            remediation=(
                "declare the exact import, internal call, callback, or platform "
                "event identity"
            ),
        )
        return
    if not isinstance(events, list) or not events:
        _issue(
            issues,
            "incomplete",
            "unbound_service",
            location + "/events",
            expected="one or more exact external-event references",
            observed=events,
            remediation="bind the service to its machine external events",
        )
        return
    for event_index, reference in enumerate(events):
        ref_location = f"{location}/events/{event_index}"
        key, effect = _resolve_effect_reference(
            reference,
            inventory,
            "external_event",
            issues,
            ref_location,
        )
        if key is None or effect is None:
            continue
        event = effect["payload"]
        checked_sites = external_site_index.get(
            (effect["unit_id"], effect["index"]), ()
        )
        checked_site = (
            checked_sites[0]
            if len(checked_sites) == 1
            and checked_sites[0].status == "complete"
            and checked_sites[0].authorizing
            and checked_sites[0].contract is not None
            else None
        )
        if external_site_index and checked_sites and checked_site is None:
            _issue(
                issues,
                "incomplete",
                "service_external_site_alternatives_not_lowerable",
                ref_location,
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected="one complete authorizing external-site alternative",
                observed=[row.site_id for row in checked_sites],
                remediation=(
                    "define a finite-alternative logical service interface or "
                    "resolve the site to one checked target"
                ),
            )
        observed_identity = (
            copy.deepcopy(dict(checked_site.identity))
            if checked_site is not None
            else _event_identity(event)
        )
        observed_arguments = (
            copy.deepcopy(list(checked_site.contract.arguments))
            if checked_site is not None
            else _event_arguments(event)
        )
        if not _identity_complete(observed_identity):
            _issue(
                issues,
                "incomplete",
                "unsupported_service_identity",
                location + "/identity",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected="an event with a stable machine identity",
                observed=observed_identity,
                remediation="extend the structured event identity profile",
            )
        elif _normalize_identity(identity) != observed_identity:
            _issue(
                issues,
                "violated",
                "service_identity_mismatch",
                location + "/identity",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=observed_identity,
                observed=_normalize_identity(identity),
                remediation="bind the service to the exact observed machine event",
            )
        if not isinstance(reference, Mapping) or "arguments" not in reference:
            _issue(
                issues,
                "incomplete",
                "unrepresented_service_arguments",
                ref_location + "/arguments",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=observed_arguments,
                observed=None,
                remediation="represent the exact logical argument expressions",
            )
        elif reference.get("arguments") != observed_arguments:
            _issue(
                issues,
                "violated",
                "service_arguments_mismatch",
                ref_location + "/arguments",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=observed_arguments,
                observed=reference.get("arguments"),
                remediation="correct the service argument projection",
            )
        if checked_site is not None:
            if reference.get("external_site_id") != checked_site.site_id:
                _issue(
                    issues,
                    "violated",
                    "service_external_site_binding_mismatch",
                    ref_location + "/external_site_id",
                    unit_id=effect["unit_id"],
                    rva=effect["rva"],
                    expected=checked_site.site_id,
                    observed=reference.get("external_site_id"),
                    remediation="retain the exact canonical external-site ID",
                )
            if (
                reference.get("external_contract_id")
                != checked_site.contract.contract_id
            ):
                _issue(
                    issues,
                    "violated",
                    "service_external_contract_binding_mismatch",
                    ref_location + "/external_contract_id",
                    unit_id=effect["unit_id"],
                    rva=effect["rva"],
                    expected=checked_site.contract.contract_id,
                    observed=reference.get("external_contract_id"),
                    remediation="retain the exact canonical external contract ID",
                )
            if service.get("external_contract") != checked_site.contract.payload():
                _issue(
                    issues,
                    "violated",
                    "service_external_contract_mismatch",
                    location + "/external_contract",
                    unit_id=effect["unit_id"],
                    rva=effect["rva"],
                    expected=checked_site.contract.payload(),
                    observed=copy.deepcopy(service.get("external_contract")),
                    remediation="retain the checked canonical machine contract",
                )
        _add_owner(owners, key, "service", str(service.get("id")), location)


def component_external_site_index(
    external_sites: ComponentExternalSiteSlice | None,
    *,
    component_id: str,
    member_ids: Sequence[str],
    issues: list[dict[str, Any]],
) -> dict[tuple[str, int], tuple[ComponentExternalSite, ...]]:
    if external_sites is None:
        return {}
    expected_members = tuple(sorted(member_ids))
    if external_sites.lift_unit_id != component_id:
        _issue(
            issues,
            "violated",
            "component_external_site_identity_mismatch",
            "/external_sites/lift_unit_id",
            expected=component_id,
            observed=external_sites.lift_unit_id,
            remediation="project external sites for this exact lift unit",
        )
    if external_sites.unit_ids != expected_members:
        _issue(
            issues,
            "violated",
            "component_external_site_membership_mismatch",
            "/external_sites/bindings/unit_ids",
            expected=list(expected_members),
            observed=list(external_sites.unit_ids),
            remediation="regenerate the slice from the exact component resolution",
        )
    return external_sites.by_event()


def check_external_read_footprint_reference(
    reference: object,
    *,
    expected_base: object,
    expected_extent: object,
    external_site_index: Mapping[
        tuple[str, int], tuple[ComponentExternalSite, ...]
    ],
    issues: list[dict[str, Any]],
    json_location: str,
    normalize_argument: Callable[[str, int, object, str], object | None] | None = None,
) -> None:
    """Check one logical byte view against an exact external read footprint."""

    expected_fields = {
        "family",
        "unit_id",
        "event_index",
        "external_site_id",
        "external_contract_id",
        "footprint_index",
    }
    if not isinstance(reference, Mapping) or set(reference) != expected_fields:
        _issue(
            issues,
            "violated",
            "external_footprint_reference_not_canonical",
            json_location,
            expected=sorted(expected_fields),
            observed=(
                sorted(str(key) for key in reference)
                if isinstance(reference, Mapping)
                else reference
            ),
            remediation="use the exact external-footprint reference schema",
        )
        return
    unit_id = reference.get("unit_id")
    event_index = reference.get("event_index")
    footprint_index = reference.get("footprint_index")
    if (
        reference.get("family") != "external_memory_footprint"
        or not isinstance(unit_id, str)
        or not unit_id
        or not isinstance(event_index, int)
        or isinstance(event_index, bool)
        or event_index < 0
        or not isinstance(footprint_index, int)
        or isinstance(footprint_index, bool)
        or footprint_index < 0
    ):
        _issue(
            issues,
            "violated",
            "external_footprint_reference_malformed",
            json_location,
            expected="a nonnegative event and footprint index in a named unit",
            observed=copy.deepcopy(reference),
            remediation="regenerate the reference from the checked external-site slice",
        )
        return
    sites = external_site_index.get((unit_id, event_index), ())
    if not sites:
        _issue(
            issues,
            "incomplete",
            "external_footprint_authority_missing",
            json_location,
            unit_id=unit_id,
            expected="one complete authorizing canonical external site",
            observed=None,
            remediation="supply the component's canonical external-site slice",
        )
        return
    if len(sites) != 1:
        _issue(
            issues,
            "incomplete",
            "external_footprint_target_alternatives_not_lowerable",
            json_location,
            unit_id=unit_id,
            expected="one complete authorizing canonical external site",
            observed=[site.site_id for site in sites],
            remediation=(
                "resolve the call to one target or define a checked logical view "
                "covering every finite alternative"
            ),
        )
        return
    site = sites[0]
    contract = site.contract
    if site.status != "complete" or not site.authorizing or contract is None:
        _issue(
            issues,
            "incomplete",
            "external_footprint_site_not_authorizing",
            json_location,
            unit_id=unit_id,
            expected="a complete authorizing external-site contract",
            observed={"status": site.status, "authorizing": site.authorizing},
            remediation="close the canonical external-site frontier",
        )
        return
    if (
        reference.get("external_site_id") != site.site_id
        or reference.get("external_contract_id") != contract.contract_id
    ):
        _issue(
            issues,
            "violated",
            "external_footprint_binding_mismatch",
            json_location,
            unit_id=unit_id,
            expected={
                "external_site_id": site.site_id,
                "external_contract_id": contract.contract_id,
            },
            observed={
                "external_site_id": reference.get("external_site_id"),
                "external_contract_id": reference.get("external_contract_id"),
            },
            remediation="regenerate the view from the exact canonical contract",
        )
        return
    if footprint_index >= len(contract.memory_footprints):
        _issue(
            issues,
            "violated",
            "external_footprint_index_out_of_bounds",
            json_location + "/footprint_index",
            unit_id=unit_id,
            expected=f"index below {len(contract.memory_footprints)}",
            observed=footprint_index,
            remediation="select an existing footprint from the checked contract",
        )
        return
    footprint = contract.memory_footprints[footprint_index]
    if not isinstance(footprint, Mapping):
        _issue(
            issues,
            "violated",
            "external_footprint_malformed",
            json_location,
            unit_id=unit_id,
            expected="a structured checked memory footprint",
            observed=copy.deepcopy(footprint),
            remediation="repair the external profile and rebuild authority",
        )
        return
    base_argument = footprint.get("base_argument")
    size = footprint.get("size")
    size_argument = size.get("argument") if isinstance(size, Mapping) else None
    shape_supported = (
        footprint.get("access") == "read"
        and footprint.get("offset") == 0
        and isinstance(base_argument, int)
        and not isinstance(base_argument, bool)
        and 0 <= base_argument < len(contract.arguments)
        and isinstance(size, Mapping)
        and size.get("kind") == "argument"
        and size.get("scale") == 1
        and isinstance(size_argument, int)
        and not isinstance(size_argument, bool)
        and 0 <= size_argument < len(contract.arguments)
    )
    if not shape_supported:
        _issue(
            issues,
            "incomplete",
            "external_read_footprint_shape_not_supported",
            json_location,
            unit_id=unit_id,
            expected={
                "access": "read",
                "offset": 0,
                "size": {"kind": "argument", "scale": 1},
            },
            observed=copy.deepcopy(footprint),
            remediation=(
                "use a direct byte-range footprint or add a checked logical-view "
                "lowering for this footprint shape"
            ),
        )
        return
    observed_base = contract.arguments[base_argument]
    observed_extent = contract.arguments[size_argument]
    if normalize_argument is not None:
        observed_base = normalize_argument(
            unit_id, event_index, observed_base, json_location + "/base"
        )
        observed_extent = normalize_argument(
            unit_id, event_index, observed_extent, json_location + "/extent"
        )
        if observed_base is None or observed_extent is None:
            return
    if observed_base != expected_base or observed_extent != expected_extent:
        _issue(
            issues,
            "violated",
            "external_read_footprint_argument_mismatch",
            json_location,
            unit_id=unit_id,
            expected={"base": expected_base, "extent": expected_extent},
            observed={"base": observed_base, "extent": observed_extent},
            remediation=(
                "bind the logical view and extent to the exact call arguments "
                "named by the footprint"
            ),
        )


__all__ = [
    "check_external_read_footprint_reference",
    "check_service",
    "component_external_site_index",
]
