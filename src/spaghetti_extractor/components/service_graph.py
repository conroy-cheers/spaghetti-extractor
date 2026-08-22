"""Typed composition of portable V2 component service dependencies.

The graph is useful before whole-target structural closure exists: unresolved
services produce an ``incomplete`` development graph. Contradictory bindings
produce a ``violated`` graph, and only a fully checked graph can authorize
activation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Sequence, TypeAlias

from ..artifacts.artifact_set import canonical_sha256_v3
from .interface_ir import (
    LogicalTypeV1,
    PortableComponentInterfaceV2,
    PortableOperationV2,
    ServiceDependencyV2,
)


COMPONENT_SERVICE_CONFIGURATION_V1 = (
    "spaghetti-extractor-component-service-configuration-v1"
)
COMPONENT_SERVICE_GRAPH_V1 = "spaghetti-extractor-component-service-graph-v1"
SERVICE_GRAPH_CONFIGURATION_V1_FORMAT = COMPONENT_SERVICE_CONFIGURATION_V1
SERVICE_GRAPH_V1_FORMAT = COMPONENT_SERVICE_GRAPH_V1

_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_EXTERNAL_SITE_ID = re.compile(r"external-site-v3:[0-9a-f]{64}")
_MEDIATION_KINDS = frozenset({"direct", "callback", "protocol"})


class ServiceGraphError(ValueError):
    """A service configuration or graph record is malformed."""


@dataclass(frozen=True)
class ExternalServiceProviderV1:
    """An exact canonical external-site service claim."""

    site_id: str
    parameter_type_ids: tuple[str, ...]
    result_type_id: str | None
    effect_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> "ExternalServiceProviderV1":
        row = _object(value, "external service provider")
        _exact(
            row,
            {
                "kind",
                "site_id",
                "parameter_type_ids",
                "result_type_id",
                "effect_ids",
            },
            "external service provider",
        )
        if row["kind"] != "external_site":
            raise ServiceGraphError("external service provider kind is invalid")
        site_id = _text(row["site_id"], "external-site id")
        if _EXTERNAL_SITE_ID.fullmatch(site_id) is None:
            raise ServiceGraphError(
                "external service provider requires a canonical external-site-v3 id"
            )
        result_type = row["result_type_id"]
        return cls(
            site_id=site_id,
            parameter_type_ids=_identifiers(
                row["parameter_type_ids"], "external provider parameter type"
            ),
            result_type_id=(
                None
                if result_type is None
                else _identifier(result_type, "external provider result type")
            ),
            effect_ids=_identifiers(
                row["effect_ids"], "external provider effect", unique=True
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": "external_site",
            "site_id": self.site_id,
            "parameter_type_ids": list(self.parameter_type_ids),
            "result_type_id": self.result_type_id,
            "effect_ids": list(self.effect_ids),
        }


@dataclass(frozen=True)
class ComponentOperationProviderV1:
    """A service supplied by one operation of another portable component."""

    component_id: str
    operation_id: str

    @classmethod
    def parse(cls, value: object) -> "ComponentOperationProviderV1":
        row = _object(value, "component-operation service provider")
        _exact(
            row,
            {"kind", "component_id", "operation_id"},
            "component-operation service provider",
        )
        if row["kind"] != "component_operation":
            raise ServiceGraphError("component-operation provider kind is invalid")
        return cls(
            component_id=_identifier(row["component_id"], "provider component id"),
            operation_id=_identifier(row["operation_id"], "provider operation id"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": "component_operation",
            "component_id": self.component_id,
            "operation_id": self.operation_id,
        }


@dataclass(frozen=True)
class MachineEventServiceProviderV1:
    """A service implemented by exact, checked machine-call events."""

    event_ids: tuple[str, ...]
    parameter_type_ids: tuple[str, ...]
    result_type_id: str | None
    effect_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> "MachineEventServiceProviderV1":
        row = _object(value, "machine-event service provider")
        _exact(
            row,
            {
                "kind",
                "event_ids",
                "parameter_type_ids",
                "result_type_id",
                "effect_ids",
            },
            "machine-event service provider",
        )
        if row["kind"] != "machine_events":
            raise ServiceGraphError("machine-event service provider kind is invalid")
        event_ids = tuple(
            _text(item, "machine-event provider id")
            for item in _array(row["event_ids"], "machine-event provider ids")
        )
        if not event_ids or event_ids != tuple(sorted(set(event_ids))):
            raise ServiceGraphError(
                "machine-event provider ids must be unique and ordered"
            )
        result_type = row["result_type_id"]
        return cls(
            event_ids=event_ids,
            parameter_type_ids=_identifiers(
                row["parameter_type_ids"], "machine-event parameter type"
            ),
            result_type_id=(
                None
                if result_type is None
                else _identifier(result_type, "machine-event result type")
            ),
            effect_ids=_identifiers(
                row["effect_ids"], "machine-event effect", unique=True
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": "machine_events",
            "event_ids": list(self.event_ids),
            "parameter_type_ids": list(self.parameter_type_ids),
            "result_type_id": self.result_type_id,
            "effect_ids": list(self.effect_ids),
        }


ServiceProviderV1: TypeAlias = (
    ExternalServiceProviderV1
    | MachineEventServiceProviderV1
    | ComponentOperationProviderV1
)


def _parse_provider(value: object) -> ServiceProviderV1:
    row = _object(value, "service provider")
    kind = row.get("kind")
    if kind == "external_site":
        return ExternalServiceProviderV1.parse(row)
    if kind == "machine_events":
        return MachineEventServiceProviderV1.parse(row)
    if kind == "component_operation":
        return ComponentOperationProviderV1.parse(row)
    raise ServiceGraphError(f"unsupported service provider kind {kind!r}")


@dataclass(frozen=True)
class ServiceBindingV1:
    component_id: str
    service_id: str
    provider: ServiceProviderV1
    mediation: str

    @classmethod
    def parse(cls, value: object) -> "ServiceBindingV1":
        row = _object(value, "service binding")
        _exact(
            row,
            {"component_id", "service_id", "provider", "mediation"},
            "service binding",
        )
        mediation = _text(row["mediation"], "service binding mediation")
        if mediation not in _MEDIATION_KINDS:
            raise ServiceGraphError(
                f"unsupported service binding mediation {mediation!r}"
            )
        return cls(
            component_id=_identifier(row["component_id"], "consumer component id"),
            service_id=_identifier(row["service_id"], "required service id"),
            provider=_parse_provider(row["provider"]),
            mediation=mediation,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "component_id": self.component_id,
            "service_id": self.service_id,
            "provider": self.provider.to_payload(),
            "mediation": self.mediation,
        }


@dataclass(frozen=True)
class ServiceGraphConfigurationV1:
    identity: str
    bindings: tuple[ServiceBindingV1, ...]

    @classmethod
    def create(
        cls, *, identity: str, bindings: Sequence[ServiceBindingV1 | object]
    ) -> "ServiceGraphConfigurationV1":
        parsed = tuple(
            item if isinstance(item, ServiceBindingV1) else ServiceBindingV1.parse(item)
            for item in bindings
        )
        payload = {
            "format": COMPONENT_SERVICE_CONFIGURATION_V1,
            "id": identity,
            "bindings": [
                item.to_payload()
                for item in sorted(
                    parsed, key=lambda row: (row.component_id, row.service_id)
                )
            ],
        }
        return cls.parse(payload)

    @classmethod
    def parse(cls, value: object) -> "ServiceGraphConfigurationV1":
        row = _object(value, "service graph configuration")
        _exact(row, {"format", "id", "bindings"}, "service graph configuration")
        if row["format"] != COMPONENT_SERVICE_CONFIGURATION_V1:
            raise ServiceGraphError("unsupported service graph configuration format")
        bindings = tuple(
            ServiceBindingV1.parse(item)
            for item in _array(row["bindings"], "service graph bindings")
        )
        ordered = tuple(
            sorted(bindings, key=lambda item: (item.component_id, item.service_id))
        )
        keys = [(item.component_id, item.service_id) for item in bindings]
        if bindings != ordered or len(keys) != len(set(keys)):
            raise ServiceGraphError(
                "service graph bindings must be canonically ordered and unique"
            )
        return cls(
            identity=_identifier(row["id"], "service configuration id"),
            bindings=bindings,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": COMPONENT_SERVICE_CONFIGURATION_V1,
            "id": self.identity,
            "bindings": [item.to_payload() for item in self.bindings],
        }


@dataclass(frozen=True)
class ServiceGraphInterfaceV1:
    identity: str
    sha256: str

    @classmethod
    def parse(cls, value: object) -> "ServiceGraphInterfaceV1":
        row = _object(value, "service graph interface")
        _exact(row, {"id", "sha256"}, "service graph interface")
        return cls(
            identity=_identifier(row["id"], "service graph interface id"),
            sha256=_digest(row["sha256"], "service graph interface digest"),
        )

    def to_payload(self) -> dict[str, str]:
        return {"id": self.identity, "sha256": self.sha256}


@dataclass(frozen=True)
class ServiceGraphIssueV1:
    status: str
    code: str
    component_id: str | None
    service_id: str | None
    provider_id: str | None
    detail: str
    next_action: str

    @classmethod
    def parse(cls, value: object) -> "ServiceGraphIssueV1":
        row = _object(value, "service graph issue")
        _exact(
            row,
            {
                "status",
                "code",
                "component_id",
                "service_id",
                "provider_id",
                "detail",
                "next_action",
            },
            "service graph issue",
        )
        status = _text(row["status"], "service graph issue status")
        if status not in {"incomplete", "violated"}:
            raise ServiceGraphError("service graph issue status is invalid")
        return cls(
            status=status,
            code=_identifier(row["code"], "service graph issue code"),
            component_id=_optional_identifier(
                row["component_id"], "service graph issue component"
            ),
            service_id=_optional_identifier(
                row["service_id"], "service graph issue service"
            ),
            provider_id=_optional_text(
                row["provider_id"], "service graph issue provider"
            ),
            detail=_text(row["detail"], "service graph issue detail"),
            next_action=_text(
                row["next_action"], "service graph issue next action"
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "code": self.code,
            "component_id": self.component_id,
            "service_id": self.service_id,
            "provider_id": self.provider_id,
            "detail": self.detail,
            "next_action": self.next_action,
        }


def _issue_key(issue: ServiceGraphIssueV1) -> tuple[object, ...]:
    return (
        0 if issue.status == "violated" else 1,
        issue.code,
        issue.component_id or "",
        issue.service_id or "",
        issue.provider_id or "",
        issue.detail,
    )


@dataclass(frozen=True)
class ServiceGraphV1:
    identity: str
    status: str
    activation_authorized: bool
    interfaces: tuple[ServiceGraphInterfaceV1, ...]
    bindings: tuple[ServiceBindingV1, ...]
    activation_order: tuple[tuple[str, ...], ...]
    mediated_cycles: tuple[tuple[str, ...], ...]
    issues: tuple[ServiceGraphIssueV1, ...]
    graph_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ServiceGraphV1":
        row = _object(value, "component service graph")
        _exact(
            row,
            {
                "format",
                "id",
                "status",
                "activation_authorized",
                "interfaces",
                "bindings",
                "activation_order",
                "mediated_cycles",
                "issues",
                "graph_sha256",
            },
            "component service graph",
        )
        if row["format"] != COMPONENT_SERVICE_GRAPH_V1:
            raise ServiceGraphError("unsupported component service graph format")
        interfaces = tuple(
            ServiceGraphInterfaceV1.parse(item)
            for item in _array(row["interfaces"], "service graph interfaces")
        )
        if interfaces != tuple(sorted(interfaces, key=lambda item: item.identity)) or len(
            {item.identity for item in interfaces}
        ) != len(interfaces):
            raise ServiceGraphError(
                "service graph interfaces must be canonically ordered and unique"
            )
        bindings = tuple(
            ServiceBindingV1.parse(item)
            for item in _array(row["bindings"], "service graph bindings")
        )
        if bindings != tuple(
            sorted(bindings, key=lambda item: (item.component_id, item.service_id))
        ) or len({(item.component_id, item.service_id) for item in bindings}) != len(
            bindings
        ):
            raise ServiceGraphError(
                "service graph bindings must be canonically ordered and unique"
            )
        activation_order = _component_groups(
            row["activation_order"], "service graph activation order"
        )
        flattened = tuple(item for group in activation_order for item in group)
        if len(flattened) != len(set(flattened)) or set(flattened) != {
            item.identity for item in interfaces
        }:
            raise ServiceGraphError(
                "service graph activation order must cover every component exactly once"
            )
        mediated_cycles = _component_groups(
            row["mediated_cycles"], "service graph mediated cycles"
        )
        if mediated_cycles != tuple(sorted(set(mediated_cycles))):
            raise ServiceGraphError(
                "service graph mediated cycles must be ordered and unique"
            )
        issues = tuple(
            ServiceGraphIssueV1.parse(item)
            for item in _array(row["issues"], "service graph issues")
        )
        if issues != tuple(sorted(issues, key=_issue_key)):
            raise ServiceGraphError("service graph issues are not canonically ordered")
        expected_status = (
            "violated"
            if any(item.status == "violated" for item in issues)
            else "incomplete"
            if issues
            else "checked"
        )
        status = _text(row["status"], "service graph status")
        authorized = row["activation_authorized"]
        if (
            status != expected_status
            or not isinstance(authorized, bool)
            or authorized is not (status == "checked")
        ):
            raise ServiceGraphError(
                "service graph status or activation authority contradicts its issues"
            )
        core = dict(row)
        observed = _digest(core.pop("graph_sha256"), "service graph digest")
        if canonical_sha256_v3(core) != observed:
            raise ServiceGraphError("component service graph digest is stale")
        return cls(
            identity=_identifier(row["id"], "service graph id"),
            status=status,
            activation_authorized=authorized,
            interfaces=interfaces,
            bindings=bindings,
            activation_order=activation_order,
            mediated_cycles=mediated_cycles,
            issues=issues,
            graph_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": COMPONENT_SERVICE_GRAPH_V1,
            "id": self.identity,
            "status": self.status,
            "activation_authorized": self.activation_authorized,
            "interfaces": [item.to_payload() for item in self.interfaces],
            "bindings": [item.to_payload() for item in self.bindings],
            "activation_order": [list(group) for group in self.activation_order],
            "mediated_cycles": [list(group) for group in self.mediated_cycles],
            "issues": [item.to_payload() for item in self.issues],
            "graph_sha256": self.graph_sha256,
        }


ComponentServiceGraphV1 = ServiceGraphV1


def build_service_graph(
    *,
    interfaces: Mapping[str, PortableComponentInterfaceV2 | Mapping[str, object]],
    configuration: ServiceGraphConfigurationV1 | Mapping[str, object],
) -> ServiceGraphV1:
    """Validate one portable provider/consumer composition."""

    parsed_interfaces = _parse_interfaces(interfaces)
    parsed_configuration = (
        configuration
        if isinstance(configuration, ServiceGraphConfigurationV1)
        else ServiceGraphConfigurationV1.parse(configuration)
    )
    issues: list[ServiceGraphIssueV1] = []
    binding_index = {
        (item.component_id, item.service_id): item
        for item in parsed_configuration.bindings
    }

    expected_services = {
        (component_id, service.identity): service
        for component_id, interface in parsed_interfaces.items()
        for service in interface.services
    }
    for binding in parsed_configuration.bindings:
        interface = parsed_interfaces.get(binding.component_id)
        if interface is None:
            issues.append(
                _issue(
                    "violated",
                    "unknown_consumer_component",
                    binding.component_id,
                    binding.service_id,
                    _provider_id(binding.provider),
                    "the configuration references a component outside the interface set",
                    "remove the binding or provide the exact consumer interface",
                )
            )
        elif (binding.component_id, binding.service_id) not in expected_services:
            issues.append(
                _issue(
                    "violated",
                    "unknown_consumer_service",
                    binding.component_id,
                    binding.service_id,
                    _provider_id(binding.provider),
                    "the consumer interface does not declare this required service",
                    "bind only services declared by the exact consumer interface",
                )
            )

    component_edges: list[tuple[str, str, str]] = []
    for key, service in sorted(expected_services.items()):
        component_id, service_id = key
        binding = binding_index.get(key)
        if binding is None:
            issues.append(
                _issue(
                    "incomplete",
                    "unresolved_required_service",
                    component_id,
                    service_id,
                    None,
                    "the required service has no configured provider",
                    "configure an exact external site or component operation provider",
                )
            )
            continue
        consumer = parsed_interfaces[component_id]
        if isinstance(
            binding.provider,
            (ExternalServiceProviderV1, MachineEventServiceProviderV1),
        ):
            _check_external_provider(consumer, service, binding, issues)
            continue

        provider_id = binding.provider.component_id
        provider = parsed_interfaces.get(provider_id)
        if provider is None:
            issues.append(
                _issue(
                    "incomplete",
                    "unresolved_provider_component",
                    component_id,
                    service_id,
                    provider_id,
                    "the configured provider component interface is unavailable",
                    "add the exact provider interface to the development graph",
                )
            )
            continue
        operation = provider.operation_index().get(binding.provider.operation_id)
        if operation is None:
            issues.append(
                _issue(
                    "incomplete",
                    "unresolved_provider_operation",
                    component_id,
                    service_id,
                    provider_id,
                    "the provider interface has no configured operation",
                    "bind a provider operation present in the exact interface",
                )
            )
            continue
        component_edges.append((component_id, provider_id, binding.mediation))
        _check_component_provider(
            consumer, service, binding, provider, operation, issues
        )

    activation_order, cyclic_groups = _lifecycle_groups(
        tuple(parsed_interfaces), component_edges
    )
    mediated_cycles: list[tuple[str, ...]] = []
    for group in cyclic_groups:
        members = set(group)
        cyclic_edges = [
            edge
            for edge in component_edges
            if edge[0] in members and edge[1] in members
        ]
        if cyclic_edges and all(edge[2] in {"callback", "protocol"} for edge in cyclic_edges):
            mediated_cycles.append(group)
        else:
            issues.append(
                _issue(
                    "violated",
                    "forbidden_service_dependency_cycle",
                    None,
                    None,
                    None,
                    f"direct lifecycle cycle contains components {list(group)!r}",
                    "break the cycle or explicitly mediate every cyclic edge by callback or protocol",
                )
            )

    ordered_issues = tuple(sorted(issues, key=_issue_key))
    status = (
        "violated"
        if any(item.status == "violated" for item in ordered_issues)
        else "incomplete"
        if ordered_issues
        else "checked"
    )
    interface_rows = tuple(
        ServiceGraphInterfaceV1(identity, interface.sha256)
        for identity, interface in parsed_interfaces.items()
    )
    core: dict[str, object] = {
        "format": COMPONENT_SERVICE_GRAPH_V1,
        "id": parsed_configuration.identity,
        "status": status,
        "activation_authorized": status == "checked",
        "interfaces": [item.to_payload() for item in interface_rows],
        "bindings": [item.to_payload() for item in parsed_configuration.bindings],
        "activation_order": [list(group) for group in activation_order],
        "mediated_cycles": [list(group) for group in sorted(mediated_cycles)],
        "issues": [item.to_payload() for item in ordered_issues],
    }
    return ServiceGraphV1.parse(
        {**core, "graph_sha256": canonical_sha256_v3(core)}
    )


compose_service_graph = build_service_graph


def _parse_interfaces(
    values: Mapping[str, PortableComponentInterfaceV2 | Mapping[str, object]],
) -> dict[str, PortableComponentInterfaceV2]:
    result: dict[str, PortableComponentInterfaceV2] = {}
    for component_id, value in values.items():
        _identifier(component_id, "component interface map key")
        parsed = (
            value
            if isinstance(value, PortableComponentInterfaceV2)
            else PortableComponentInterfaceV2.parse(value)
        )
        if parsed.identity != component_id:
            raise ServiceGraphError(
                "component interface map key does not match its portable interface id"
            )
        if parsed.identity in result:
            raise ServiceGraphError("component interface ids are duplicated")
        result[parsed.identity] = parsed
    if not result:
        raise ServiceGraphError("service graph requires at least one component interface")
    return dict(sorted(result.items()))


def _check_external_provider(
    consumer: PortableComponentInterfaceV2,
    service: ServiceDependencyV2,
    binding: ServiceBindingV1,
    issues: list[ServiceGraphIssueV1],
) -> None:
    provider = binding.provider
    assert isinstance(
        provider, (ExternalServiceProviderV1, MachineEventServiceProviderV1)
    )
    provider_id = _provider_id(provider)
    signature_matches = (
        provider.parameter_type_ids == service.parameter_type_ids
        and provider.result_type_id == service.result_type_id
    )
    if not signature_matches:
        issues.append(
            _issue(
                "violated",
                "external_service_signature_mismatch",
                consumer.identity,
                service.identity,
                provider_id,
                "the external site's declared parameter/result signature is not exact",
                "bind the canonical external site with the exact required signature",
            )
        )
    if provider.effect_ids != service.effect_ids:
        issues.append(
            _issue(
                "violated",
                "external_service_effect_mismatch",
                consumer.identity,
                service.identity,
                provider_id,
                "the external site's declared effects differ from the required effects",
                "bind the canonical external site with the exact required effect inventory",
            )
        )


def _check_component_provider(
    consumer: PortableComponentInterfaceV2,
    service: ServiceDependencyV2,
    binding: ServiceBindingV1,
    provider: PortableComponentInterfaceV2,
    operation: PortableOperationV2,
    issues: list[ServiceGraphIssueV1],
) -> None:
    provider_identity = f"{provider.identity}.{operation.identity}"
    expected_result_ids = (
        () if service.result_type_id is None else (service.result_type_id,)
    )
    observed_result_ids = tuple(item.type_id for item in operation.results)
    expected_parameter_ids = service.parameter_type_ids
    observed_parameter_ids = tuple(item.type_id for item in operation.parameters)
    if not _type_sequences_compatible(
        expected_parameter_ids, observed_parameter_ids, consumer, provider
    ):
        code = (
            "resource_ownership_mismatch"
            if _resource_ownership_mismatch(
                expected_parameter_ids,
                observed_parameter_ids,
                consumer,
                provider,
            )
            else "component_service_parameter_mismatch"
        )
        issues.append(
            _issue(
                "violated",
                code,
                consumer.identity,
                service.identity,
                provider_identity,
                "provider operation parameter types are not structurally compatible "
                "with the required service",
                "use structurally compatible portable parameter definitions "
                "and ownership",
            )
        )
    if not _type_sequences_compatible(
        expected_result_ids, observed_result_ids, consumer, provider
    ):
        code = (
            "resource_ownership_mismatch"
            if _resource_ownership_mismatch(
                expected_result_ids,
                observed_result_ids,
                consumer,
                provider,
            )
            else "component_service_result_mismatch"
        )
        issues.append(
            _issue(
                "violated",
                code,
                consumer.identity,
                service.identity,
                provider_identity,
                "provider operation results do not exactly match the required service",
                "align provider result types and resource ownership with the service contract",
            )
        )
    if service.effect_ids != operation.effect_ids or not _effect_definitions_equal(
        service.effect_ids, consumer, provider
    ):
        issues.append(
            _issue(
                "violated",
                "component_service_effect_mismatch",
                consumer.identity,
                service.identity,
                provider_identity,
                "provider operation effects do not exactly match the required service",
                "use the exact required effect ids and portable effect definitions",
            )
        )
    if not _operation_is_reachable(provider, operation.identity):
        issues.append(
            _issue(
                "violated",
                "provider_operation_lifecycle_unreachable",
                consumer.identity,
                service.identity,
                provider_identity,
                "provider operation has no transition reachable from its initial protocol state",
                "repair the provider protocol transitions before composing the service",
            )
        )


def _type_sequences_compatible(
    expected_ids: Sequence[str],
    observed_ids: Sequence[str],
    consumer: PortableComponentInterfaceV2,
    provider: PortableComponentInterfaceV2,
) -> bool:
    if len(expected_ids) != len(observed_ids):
        return False
    consumer_types = consumer.type_index()
    provider_types = provider.type_index()
    compared: set[tuple[str, str]] = set()
    return all(
        _types_compatible(
            expected,
            observed,
            consumer_types,
            provider_types,
            compared,
        )
        for expected, observed in zip(expected_ids, observed_ids, strict=True)
    )


def _types_compatible(
    expected_id: str,
    observed_id: str,
    expected_types: Mapping[str, LogicalTypeV1],
    observed_types: Mapping[str, LogicalTypeV1],
    compared: set[tuple[str, str]],
) -> bool:
    pair = (expected_id, observed_id)
    if pair in compared:
        return True
    expected = expected_types[expected_id]
    observed = observed_types[observed_id]
    if expected.kind != observed.kind:
        return False
    compared.add(pair)

    if expected.kind in {"scalar", "enum"}:
        return expected.c_type == observed.c_type
    if expected.kind == "bytes":
        return (
            expected.access == observed.access
            and expected.extent_parameter_id == observed.extent_parameter_id
            and expected.nul_terminated == observed.nul_terminated
        )
    if expected.kind == "reference":
        return (
            expected.access == observed.access
            and expected.nullable == observed.nullable
            and expected.allow_one_past == observed.allow_one_past
            and expected.lifetime == observed.lifetime
            and expected.element_type_id is not None
            and observed.element_type_id is not None
            and _types_compatible(
                expected.element_type_id,
                observed.element_type_id,
                expected_types,
                observed_types,
                compared,
            )
        )
    if expected.kind == "view":
        return (
            expected.access == observed.access
            and expected.extent_kind == observed.extent_kind
            and expected.extent_parameter_id == observed.extent_parameter_id
            and expected.fixed_extent == observed.fixed_extent
            and expected.ownership == observed.ownership
            and expected.element_type_id is not None
            and observed.element_type_id is not None
            and _types_compatible(
                expected.element_type_id,
                observed.element_type_id,
                expected_types,
                observed_types,
                compared,
            )
        )
    if expected.kind == "record":
        return (
            expected.access == observed.access
            and len(expected.fields) == len(observed.fields)
            and all(
                expected_field.identity == observed_field.identity
                and _types_compatible(
                    expected_field.type_id,
                    observed_field.type_id,
                    expected_types,
                    observed_types,
                    compared,
                )
                for expected_field, observed_field in zip(
                    expected.fields, observed.fields, strict=True
                )
            )
        )
    if expected.kind == "resource":
        return (
            expected.resource_kind == observed.resource_kind
            and expected.ownership == observed.ownership
        )
    if expected.kind == "callback":
        if (
            expected.ownership != observed.ownership
            or expected.nullable != observed.nullable
            or len(expected.parameter_type_ids) != len(observed.parameter_type_ids)
            or (expected.result_type_id is None) != (observed.result_type_id is None)
        ):
            return False
        if not all(
            _types_compatible(
                expected_parameter,
                observed_parameter,
                expected_types,
                observed_types,
                compared,
            )
            for expected_parameter, observed_parameter in zip(
                expected.parameter_type_ids,
                observed.parameter_type_ids,
                strict=True,
            )
        ):
            return False
        if expected.result_type_id is None:
            return True
        observed_result_id = observed.result_type_id
        if observed_result_id is None:
            return False
        return _types_compatible(
            expected.result_type_id,
            observed_result_id,
            expected_types,
            observed_types,
            compared,
        )
    raise AssertionError(expected.kind)


def _resource_ownership_mismatch(
    expected_ids: Sequence[str],
    observed_ids: Sequence[str],
    consumer: PortableComponentInterfaceV2,
    provider: PortableComponentInterfaceV2,
) -> bool:
    if len(expected_ids) != len(observed_ids):
        return False
    consumer_types = consumer.type_index()
    provider_types = provider.type_index()
    compared: set[tuple[str, str]] = set()
    return any(
        _types_have_resource_ownership_mismatch(
            expected_id,
            observed_id,
            consumer_types,
            provider_types,
            compared,
        )
        for expected_id, observed_id in zip(
            expected_ids, observed_ids, strict=True
        )
    )


def _types_have_resource_ownership_mismatch(
    expected_id: str,
    observed_id: str,
    expected_types: Mapping[str, LogicalTypeV1],
    observed_types: Mapping[str, LogicalTypeV1],
    compared: set[tuple[str, str]],
) -> bool:
    pair = (expected_id, observed_id)
    if pair in compared:
        return False
    compared.add(pair)
    expected = expected_types[expected_id]
    observed = observed_types[observed_id]
    if expected.kind != observed.kind:
        return False
    if expected.kind == "resource":
        return (
            expected.resource_kind == observed.resource_kind
            and expected.ownership != observed.ownership
        )
    if expected.kind == "record" and len(expected.fields) == len(observed.fields):
        return any(
            expected_field.identity == observed_field.identity
            and _types_have_resource_ownership_mismatch(
                expected_field.type_id,
                observed_field.type_id,
                expected_types,
                observed_types,
                compared,
            )
            for expected_field, observed_field in zip(
                expected.fields, observed.fields, strict=True
            )
        )
    if expected.kind == "callback" and len(expected.parameter_type_ids) == len(
        observed.parameter_type_ids
    ):
        if any(
            _types_have_resource_ownership_mismatch(
                expected_parameter,
                observed_parameter,
                expected_types,
                observed_types,
                compared,
            )
            for expected_parameter, observed_parameter in zip(
                expected.parameter_type_ids,
                observed.parameter_type_ids,
                strict=True,
            )
        ):
            return True
        if expected.result_type_id is not None and observed.result_type_id is not None:
            return _types_have_resource_ownership_mismatch(
                expected.result_type_id,
                observed.result_type_id,
                expected_types,
                observed_types,
                compared,
            )
    return False


def _effect_definitions_equal(
    effect_ids: Sequence[str],
    consumer: PortableComponentInterfaceV2,
    provider: PortableComponentInterfaceV2,
) -> bool:
    consumer_effects = {item.identity: item for item in consumer.effects}
    provider_effects = {item.identity: item for item in provider.effects}
    return all(
        effect_id in provider_effects
        and consumer_effects[effect_id] == provider_effects[effect_id]
        for effect_id in effect_ids
    )


def _operation_is_reachable(
    interface: PortableComponentInterfaceV2, operation_id: str
) -> bool:
    reachable = {interface.initial_protocol_state}
    changed = True
    while changed:
        changed = False
        for transition in interface.protocol_transitions:
            if transition.from_state in reachable and transition.to_state not in reachable:
                reachable.add(transition.to_state)
                changed = True
    return any(
        transition.operation_id == operation_id
        and transition.from_state in reachable
        for transition in interface.protocol_transitions
    )


def _lifecycle_groups(
    component_ids: tuple[str, ...],
    edges: Sequence[tuple[str, str, str]],
) -> tuple[tuple[tuple[str, ...], ...], tuple[tuple[str, ...], ...]]:
    dependencies = {component_id: set() for component_id in component_ids}
    for consumer, provider, _mediation in edges:
        dependencies[consumer].add(provider)
    groups = _strongly_connected_components(component_ids, dependencies)
    group_by_component = {
        component_id: index
        for index, group in enumerate(groups)
        for component_id in group
    }
    group_dependencies = {index: set() for index in range(len(groups))}
    for consumer, providers in dependencies.items():
        consumer_group = group_by_component[consumer]
        for provider in providers:
            provider_group = group_by_component[provider]
            if provider_group != consumer_group:
                group_dependencies[consumer_group].add(provider_group)

    remaining = set(group_dependencies)
    ordered: list[tuple[str, ...]] = []
    while remaining:
        ready = sorted(
            (
                index
                for index in remaining
                if not (group_dependencies[index] & remaining)
            ),
            key=lambda index: groups[index],
        )
        if not ready:
            raise ServiceGraphError("internal error ordering service graph SCCs")
        for index in ready:
            ordered.append(groups[index])
            remaining.remove(index)

    self_edges = {(consumer, provider) for consumer, provider, _ in edges}
    cyclic = tuple(
        group
        for group in groups
        if len(group) > 1 or (group[0], group[0]) in self_edges
    )
    return tuple(ordered), tuple(sorted(cyclic))


def _strongly_connected_components(
    component_ids: Sequence[str], dependencies: Mapping[str, set[str]]
) -> tuple[tuple[str, ...], ...]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: list[tuple[str, ...]] = []

    def visit(component_id: str) -> None:
        nonlocal index
        indices[component_id] = index
        lowlinks[component_id] = index
        index += 1
        stack.append(component_id)
        on_stack.add(component_id)
        for provider_id in sorted(dependencies[component_id]):
            if provider_id not in indices:
                visit(provider_id)
                lowlinks[component_id] = min(
                    lowlinks[component_id], lowlinks[provider_id]
                )
            elif provider_id in on_stack:
                lowlinks[component_id] = min(
                    lowlinks[component_id], indices[provider_id]
                )
        if lowlinks[component_id] != indices[component_id]:
            return
        group: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            group.append(member)
            if member == component_id:
                break
        result.append(tuple(sorted(group)))

    for component_id in sorted(component_ids):
        if component_id not in indices:
            visit(component_id)
    return tuple(sorted(result))


def _provider_id(provider: ServiceProviderV1) -> str:
    if isinstance(provider, ExternalServiceProviderV1):
        return provider.site_id
    if isinstance(provider, MachineEventServiceProviderV1):
        return provider.event_ids[0]
    return f"{provider.component_id}.{provider.operation_id}"


def _issue(
    status: str,
    code: str,
    component_id: str | None,
    service_id: str | None,
    provider_id: str | None,
    detail: str,
    next_action: str,
) -> ServiceGraphIssueV1:
    return ServiceGraphIssueV1(
        status,
        code,
        component_id,
        service_id,
        provider_id,
        detail,
        next_action,
    )


def _component_groups(value: object, context: str) -> tuple[tuple[str, ...], ...]:
    result: list[tuple[str, ...]] = []
    for index, raw_group in enumerate(_array(value, context)):
        group = _identifiers(raw_group, f"{context} group {index}", unique=True)
        if not group or group != tuple(sorted(group)):
            raise ServiceGraphError(f"{context} groups must be nonempty and sorted")
        result.append(group)
    return tuple(result)


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ServiceGraphError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ServiceGraphError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ServiceGraphError(f"{context} must be a nonempty string")
    return value


def _optional_text(value: object, context: str) -> str | None:
    return None if value is None else _text(value, context)


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ServiceGraphError(f"{context} is not a portable identifier")
    return result


def _optional_identifier(value: object, context: str) -> str | None:
    return None if value is None else _identifier(value, context)


def _identifiers(
    value: object, context: str, *, unique: bool = False
) -> tuple[str, ...]:
    result = tuple(_identifier(item, context) for item in _array(value, context))
    if unique and len(result) != len(set(result)):
        raise ServiceGraphError(f"{context} values must be unique")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise ServiceGraphError(f"{context} must be a SHA-256 digest")
    return result


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise ServiceGraphError(
            f"{context} fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}"
        )


__all__ = [
    "COMPONENT_SERVICE_CONFIGURATION_V1",
    "COMPONENT_SERVICE_GRAPH_V1",
    "SERVICE_GRAPH_CONFIGURATION_V1_FORMAT",
    "SERVICE_GRAPH_V1_FORMAT",
    "ComponentOperationProviderV1",
    "ComponentServiceGraphV1",
    "ExternalServiceProviderV1",
    "MachineEventServiceProviderV1",
    "ServiceBindingV1",
    "ServiceGraphConfigurationV1",
    "ServiceGraphError",
    "ServiceGraphInterfaceV1",
    "ServiceGraphIssueV1",
    "ServiceGraphV1",
    "ServiceProviderV1",
    "build_service_graph",
    "compose_service_graph",
]
