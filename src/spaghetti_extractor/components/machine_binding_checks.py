"""Cross-input checks shared by component machine-binding phases."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Protocol

from ..artifacts.artifact_set import canonical_sha256_v3
from .interface_ir import PortableComponentInterfaceV2
from .value_codec import value_codec_expression_references


class ComponentMachineBindingError(ValueError):
    """A component machine binding is malformed or contradicts checked inputs."""


class LogicalMachineValue(Protocol):
    identity: str
    decoding: Mapping[str, object] | None


class BoundValue(Protocol):
    identity: str


class BoundOperation(Protocol):
    operation_id: str
    parameters: Sequence[BoundValue]
    state: Sequence[BoundValue]


class BoundService(Protocol):
    service_id: str
    provider: Mapping[str, object]


def check_component_operation_services(
    *,
    component_id: str,
    services: Sequence[BoundService],
    machine: Mapping[str, Mapping[str, object]],
    machine_ir_sha256: str,
    resolution: Mapping[str, object] | None,
    catalog: Mapping[str, object] | None,
    issues: list[dict[str, object]],
) -> None:
    """Bind logical component providers to exact selected machine callsites."""

    component_services = [
        service
        for service in services
        if service.provider.get("kind") == "component_operation"
    ]
    if not component_services:
        return
    if resolution is None or catalog is None:
        for service in component_services:
            _issue(
                issues,
                "incomplete",
                "component_operation_call_authority_missing",
                id=service.service_id,
            )
        return

    resolution_sha256 = _authority_digest(
        resolution,
        digest_field="resolution_sha256",
        formats={
            "spaghetti-extractor-component-resolution-v2",
            "spaghetti-extractor-component-resolution-slice-v1",
        },
        source="component resolution",
        issues=issues,
    )
    _authority_digest(
        catalog,
        digest_field="catalog_sha256",
        formats={"spaghetti-extractor-semantic-component-catalog-v1"},
        source="semantic component catalog",
        issues=issues,
    )

    resolution_components = _component_index(
        resolution.get("components"), "component resolution", issues
    )
    catalog_components = _component_index(
        catalog.get("components"), "semantic component catalog", issues
    )
    if resolution.get("status") != "checked":
        _issue(issues, "violated", "component_resolution_not_checked")
    bindings = catalog.get("bindings")
    if (
        not isinstance(bindings, Mapping)
        or bindings.get("machine_ir_sha256") != machine_ir_sha256
    ):
        _issue(issues, "violated", "component_call_catalog_machine_ir_stale")

    caller = catalog_components.get(component_id)
    resolved_caller = resolution_components.get(component_id)
    if caller is None or resolved_caller is None:
        _issue(
            issues,
            "violated",
            "component_operation_consumer_missing",
            id=component_id,
        )
        return
    if caller.get("definition_status") != "valid":
        _issue(
            issues,
            "incomplete",
            "component_operation_consumer_not_valid",
            id=component_id,
        )
    refinement = caller.get("refinement")
    stages = refinement.get("stages") if isinstance(refinement, Mapping) else None
    if not isinstance(stages, list) or not any(
        isinstance(stage, Mapping)
        and stage.get("kind") == "component_resolution_v2"
        and stage.get("resolution_sha256") == resolution_sha256
        for stage in stages
    ):
        _issue(
            issues,
            "violated",
            "component_call_catalog_resolution_stale",
            id=component_id,
        )

    calls = caller.get("component_calls")
    if not isinstance(calls, list):
        _issue(issues, "violated", "component_call_inventory_malformed")
        calls = []
    calls_by_target: dict[str, list[Mapping[str, object]]] = {}
    for call in calls:
        if not isinstance(call, Mapping) or not isinstance(
            call.get("target_component_id"), str
        ):
            _issue(issues, "violated", "component_call_inventory_malformed")
            continue
        calls_by_target.setdefault(str(call["target_component_id"]), []).append(call)

    providers_by_target: dict[str, list[BoundService]] = {}
    for service in component_services:
        provider = service.provider
        target_id = str(provider.get("component_id", ""))
        operation_id = str(provider.get("operation_id", ""))
        providers_by_target.setdefault(target_id, []).append(service)
        target = catalog_components.get(target_id)
        resolved_target = resolution_components.get(target_id)
        if target is None or resolved_target is None:
            _issue(
                issues,
                "violated",
                "component_operation_provider_missing",
                id=service.service_id,
                component_id=target_id,
            )
            continue
        if target.get("definition_status") != "valid":
            _issue(
                issues,
                "incomplete",
                "component_operation_provider_not_valid",
                id=service.service_id,
                component_id=target_id,
            )
        source = resolved_target.get("source")
        operations = source.get("operations") if isinstance(source, Mapping) else None
        if not isinstance(operations, Mapping) or operation_id not in operations:
            _issue(
                issues,
                "violated",
                "component_operation_provider_operation_unknown",
                id=service.service_id,
                component_id=target_id,
                operation_id=operation_id,
            )
        if target_id not in calls_by_target:
            _issue(
                issues,
                "violated",
                "component_operation_provider_has_no_exact_call",
                id=service.service_id,
                component_id=target_id,
            )
            continue
        raw_events = provider.get("events")
        if not isinstance(raw_events, list) or not raw_events:
            _issue(
                issues,
                "incomplete",
                "component_operation_exact_events_missing",
                id=service.service_id,
                component_id=target_id,
            )
            continue
        observed_refs = {
            (str(event.get("unit_id")), event.get("event_index"))
            for event in raw_events
            if isinstance(event, Mapping)
        }
        expected_refs: set[tuple[str, int]] = set()
        for call in calls_by_target[target_id]:
            target_rva = call.get("target_rva")
            callsites = call.get("callsites")
            if not isinstance(target_rva, int) or not isinstance(callsites, list):
                continue
            for callsite in callsites:
                source_id = (
                    callsite.get("source_unit_id")
                    if isinstance(callsite, Mapping)
                    else None
                )
                unit = machine.get(str(source_id))
                semantics = unit.get("semantics") if isinstance(unit, Mapping) else None
                events = (
                    semantics.get("external_events")
                    if isinstance(semantics, Mapping)
                    else None
                )
                if not isinstance(events, list):
                    continue
                expected_refs.update(
                    (str(source_id), index)
                    for index, event in enumerate(events)
                    if isinstance(event, Mapping)
                    and event.get("kind") == "internal_call"
                    and event.get("target_rva") == target_rva
                )
        if observed_refs != expected_refs:
            _issue(
                issues,
                "violated",
                "component_operation_exact_event_inventory_mismatch",
                id=service.service_id,
                expected=sorted(expected_refs),
                observed=sorted(observed_refs),
            )

    for target_id in sorted(calls_by_target):
        providers = providers_by_target.get(target_id, [])
        if not providers:
            _issue(
                issues,
                "incomplete",
                "component_call_has_no_operation_provider",
                component_id=target_id,
            )
        elif len(providers) != 1:
            _issue(
                issues,
                "incomplete",
                "component_call_operation_provider_ambiguous",
                component_id=target_id,
                service_ids=sorted(service.service_id for service in providers),
            )


def _component_index(
    value: object,
    context: str,
    issues: list[dict[str, object]],
) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        _issue(issues, "violated", "component_call_authority_malformed", source=context)
        return {}
    result: dict[str, Mapping[str, object]] = {}
    for row in value:
        identity = row.get("id") if isinstance(row, Mapping) else None
        if not isinstance(identity, str) or identity in result:
            _issue(
                issues,
                "violated",
                "component_call_authority_malformed",
                source=context,
            )
            continue
        result[identity] = row
    return result


def _authority_digest(
    payload: Mapping[str, object],
    *,
    digest_field: str,
    formats: set[str],
    source: str,
    issues: list[dict[str, object]],
) -> str | None:
    core = dict(payload)
    observed = core.pop(digest_field, None)
    if payload.get("format") not in formats or not isinstance(observed, str):
        _issue(
            issues,
            "violated",
            "component_call_authority_malformed",
            source=source,
        )
        return None
    if canonical_sha256_v3(core) != observed:
        _issue(
            issues,
            "violated",
            "component_call_authority_digest_stale",
            source=source,
        )
        return None
    return observed


def check_result_decoding(
    *,
    value: LogicalMachineValue,
    operation_parameters: Mapping[str, Mapping[str, object]],
    types: Mapping[str, Mapping[str, object]],
    operation_id: str,
    issues: list[dict[str, object]],
) -> None:
    if value.decoding is None:
        return
    references = value_codec_expression_references(value.decoding)
    if references["projected_value"] != {"value"}:
        _issue(
            issues,
            "violated",
            "result_decoding_must_use_projected_value",
            id=operation_id,
            value_id=value.identity,
        )
    if references["state_input"]:
        _issue(
            issues,
            "violated",
            "result_decoding_references_component_state",
            id=operation_id,
            value_id=value.identity,
        )
    referenced_parameters = (
        references["parameter"]
        | references["bytes_address"]
        | references["byte_extent"]
        | references["byte_read"]
    )
    if referenced_parameters - set(operation_parameters):
        _issue(
            issues,
            "violated",
            "result_decoding_references_unknown_parameter",
            id=operation_id,
            value_id=value.identity,
        )
    byte_references = (
        references["bytes_address"]
        | references["byte_extent"]
        | references["byte_read"]
    )
    for parameter_id in sorted(byte_references):
        parameter = operation_parameters.get(parameter_id)
        parameter_type = (
            None
            if parameter is None
            else types.get(str(parameter.get("type_id")))
        )
        if parameter_type is None or parameter_type.get("kind") != "bytes":
            _issue(
                issues,
                "violated",
                "result_decoding_byte_reference_has_non_byte_parameter",
                id=operation_id,
                value_id=value.identity,
                parameter_id=parameter_id,
            )


def check_operation_view_aliases(
    *,
    bound: BoundOperation,
    parameter_index: Mapping[str, Mapping[str, object]],
    states: Mapping[str, Mapping[str, object]],
    types: Mapping[str, Mapping[str, object]],
    issues: list[dict[str, object]],
) -> None:
    views: list[tuple[str, str]] = []
    for value in bound.parameters:
        logical = parameter_index.get(value.identity)
        if logical is not None:
            logical_type = types.get(str(logical.get("type_id")))
            if logical_type is not None and logical_type.get("kind") == "bytes":
                views.append((value.identity, str(logical_type.get("access"))))
    for value in bound.state:
        logical = states.get(value.identity)
        if logical is not None:
            logical_type = types.get(str(logical.get("type_id")))
            if logical_type is not None and logical_type.get("kind") == "bytes":
                views.append((value.identity, str(logical_type.get("access"))))
    if len(views) > 1 and any(access != "read" for _, access in views):
        _issue(
            issues,
            "incomplete",
            "operation_memory_alias_relation_unresolved",
            id=bound.operation_id,
            view_ids=[identity for identity, _ in views],
        )


def logical_scalar_width(logical_type: Mapping[str, object]) -> int:
    c_type = str(logical_type.get("c_type", ""))
    match = re.fullmatch(r"u?int(8|16|32|64)_t", c_type)
    if match is None:
        raise ComponentMachineBindingError(
            f"logical scalar C type {c_type!r} has no fixed width"
        )
    return int(match.group(1))


def projection_issue(
    issues: list[dict[str, object]],
    operation_id: str,
    logical_value: Mapping[str, object],
    code: str,
    **fields: object,
) -> None:
    _issue(
        issues,
        "violated",
        code,
        id=operation_id,
        value_id=logical_value.get("id"),
        **fields,
    )


def machine_manifest_pe_sha256(manifest: Mapping[str, object]) -> str:
    candidates: list[object] = []
    binary = manifest.get("binary")
    if isinstance(binary, Mapping):
        candidates.append(binary.get("sha256"))
    inputs = manifest.get("inputs")
    if isinstance(inputs, Mapping):
        original = inputs.get("original_pe")
        if isinstance(original, Mapping):
            candidates.append(original.get("sha256"))
    values = {
        value
        for value in candidates
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
    }
    if len(values) != 1:
        raise ComponentMachineBindingError(
            "machine-IR manifest has no unique PE binding"
        )
    return next(iter(values))


def interface_payload(value: object) -> dict[str, object]:
    if hasattr(value, "to_payload"):
        value = value.to_payload()
    if isinstance(value, (str, bytes)) or not isinstance(value, Mapping):
        raise ComponentMachineBindingError(
            "portable component interface must be a parsed object"
        )
    payload = json.loads(json.dumps(value))
    try:
        return PortableComponentInterfaceV2.parse(payload).to_payload()
    except ValueError as exc:
        raise ComponentMachineBindingError(
            f"portable interface V2 is invalid: {exc}"
        ) from exc


def _issue(
    issues: list[dict[str, object]],
    status: str,
    code: str,
    **detail: object,
) -> None:
    issues.append({"status": status, "code": code, **detail})


__all__ = [
    "ComponentMachineBindingError",
    "check_component_operation_services",
    "check_operation_view_aliases",
    "check_result_decoding",
    "interface_payload",
    "logical_scalar_width",
    "machine_manifest_pe_sha256",
    "projection_issue",
]
