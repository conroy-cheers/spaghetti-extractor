"""Contract-only component composition and release-policy gates."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Protocol, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import (
    COMPONENT_DEPENDENCY_GRAPH_V3_FORMAT,
    COMPONENT_RELEASE_GATE_V1_FORMAT,
)
from .implementation import (
    ComponentImplementationV3,
    read_component_implementation_v3,
)
from .lifecycle_records import ComponentActivationPlanRecordV3
from .universal_contract import ComponentContractV3, read_component_contract_v3
from .service_graph import (
    ComponentOperationProviderV1,
    ExternalServiceProviderV1,
    MachineEventServiceProviderV1,
    ServiceGraphV1,
)


class ComponentDependencyGraphError(ValueError):
    """A component dependency graph is malformed or contradictory."""


class RootedUnitProjection(Protocol):
    reachable_unit_ids: tuple[str, ...]
    structural_unit_count: int
    projection_sha256: str


@dataclass(frozen=True, order=True)
class ComponentDependencyEdgeV3:
    consumer_component_id: str
    consumer_service_id: str
    provider_component_id: str
    provider_operation_id: str
    mediation: str
    callsite_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> "ComponentDependencyEdgeV3":
        row = _object(value, "component dependency edge")
        _exact(
            row,
            {
                "consumer_component_id",
                "consumer_service_id",
                "provider_component_id",
                "provider_operation_id",
                "mediation",
                "callsite_ids",
            },
            "component dependency edge",
        )
        mediation = _choice(
            row["mediation"], {"direct", "callback", "protocol"},
            "component dependency mediation",
        )
        callsites = _strings(row["callsite_ids"], "component dependency callsites")
        if not callsites:
            raise ComponentDependencyGraphError(
                "component dependency edge requires exact callsite identities"
            )
        return cls(
            consumer_component_id=_identifier(
                row["consumer_component_id"], "consumer component id"
            ),
            consumer_service_id=_identifier(
                row["consumer_service_id"], "consumer service id"
            ),
            provider_component_id=_identifier(
                row["provider_component_id"], "provider component id"
            ),
            provider_operation_id=_identifier(
                row["provider_operation_id"], "provider operation id"
            ),
            mediation=mediation,
            callsite_ids=callsites,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "consumer_component_id": self.consumer_component_id,
            "consumer_service_id": self.consumer_service_id,
            "provider_component_id": self.provider_component_id,
            "provider_operation_id": self.provider_operation_id,
            "mediation": self.mediation,
            "callsite_ids": list(self.callsite_ids),
        }


@dataclass(frozen=True)
class ComponentDependencyGraphV3:
    status: str
    contracts: tuple[tuple[str, str], ...]
    implementations: tuple[tuple[str, str, str, str], ...]
    edges: tuple[ComponentDependencyEdgeV3, ...]
    environment_dependencies: tuple[Mapping[str, object], ...]
    reverse_dependencies: tuple[Mapping[str, object], ...]
    sccs: tuple[tuple[str, ...], ...]
    issues: tuple[Mapping[str, object], ...]
    graph_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ComponentDependencyGraphV3":
        row = _object(value, "component dependency graph V3")
        _exact(
            row,
            {
                "format",
                "status",
                "contracts",
                "implementations",
                "edges",
                "environment_dependencies",
                "reverse_dependencies",
                "sccs",
                "issues",
                "policy",
                "graph_sha256",
            },
            "component dependency graph V3",
        )
        if row["format"] != COMPONENT_DEPENDENCY_GRAPH_V3_FORMAT:
            raise ComponentDependencyGraphError(
                "unsupported component dependency graph format"
            )
        status = _choice(
            row["status"], {"checked", "incomplete", "violated"},
            "component dependency graph status",
        )
        contracts = tuple(
            (
                _identifier(_object(item, "graph contract")["id"], "graph contract id"),
                _digest(_object(item, "graph contract")["sha256"], "graph contract digest"),
            )
            for item in _array(row["contracts"], "graph contracts")
        )
        if tuple(item[0] for item in contracts) != tuple(
            sorted({item[0] for item in contracts})
        ):
            raise ComponentDependencyGraphError(
                "graph contracts must be unique and ordered"
            )
        implementations = tuple(
            (
                _identifier(_object(item, "graph implementation")["component_id"], "implementation component id"),
                _identifier(_object(item, "graph implementation")["id"], "implementation id"),
                _identifier(_object(item, "graph implementation")["kind"], "implementation kind"),
                _digest(_object(item, "graph implementation")["sha256"], "implementation digest"),
            )
            for item in _array(row["implementations"], "graph implementations")
        )
        if tuple(item[0] for item in implementations) != tuple(
            sorted({item[0] for item in implementations})
        ):
            raise ComponentDependencyGraphError(
                "graph implementations must select each component at most once"
            )
        edges = tuple(
            ComponentDependencyEdgeV3.parse(item)
            for item in _array(row["edges"], "graph edges")
        )
        if edges != tuple(sorted(set(edges))):
            raise ComponentDependencyGraphError(
                "graph edges must be unique and canonically ordered"
            )
        environment_dependencies = tuple(
            _canonical_object(item, "environment dependency")
            for item in _array(
                row["environment_dependencies"], "environment dependencies"
            )
        )
        environment_keys = tuple(
            (
                str(item.get("consumer_component_id", "")),
                str(item.get("consumer_service_id", "")),
            )
            for item in environment_dependencies
        )
        if environment_keys != tuple(sorted(set(environment_keys))):
            raise ComponentDependencyGraphError(
                "environment dependencies must be unique and canonically ordered"
            )
        reverse = tuple(
            _canonical_object(item, "reverse dependency")
            for item in _array(row["reverse_dependencies"], "reverse dependencies")
        )
        sccs = tuple(
            _strings(item, "component dependency SCC", nonempty=True)
            for item in _array(row["sccs"], "component dependency SCCs")
        )
        if sccs != tuple(sorted(sccs)):
            raise ComponentDependencyGraphError(
                "component dependency SCCs must be canonically ordered"
            )
        issues = tuple(
            _canonical_object(item, "component graph issue")
            for item in _array(row["issues"], "component graph issues")
        )
        if status == "checked" and issues:
            raise ComponentDependencyGraphError(
                "checked dependency graph may not contain issues"
            )
        if status != "checked" and not issues:
            raise ComponentDependencyGraphError(
                "non-checked dependency graph requires an issue"
            )
        policy = _object(row["policy"], "component graph policy")
        if policy != _graph_policy():
            raise ComponentDependencyGraphError(
                "component graph policy weakens contract-only composition"
            )
        core = dict(row)
        observed = _digest(core.pop("graph_sha256"), "component graph digest")
        if observed != canonical_sha256_v3(core):
            raise ComponentDependencyGraphError("component graph digest is stale")
        return cls(
            status=status,
            contracts=contracts,
            implementations=implementations,
            edges=edges,
            environment_dependencies=environment_dependencies,
            reverse_dependencies=reverse,
            sccs=sccs,
            issues=issues,
            graph_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_DEPENDENCY_GRAPH_V3_FORMAT,
            "status": self.status,
            "contracts": [
                {"id": identity, "sha256": digest}
                for identity, digest in self.contracts
            ],
            "implementations": [
                {
                    "component_id": component_id,
                    "id": implementation_id,
                    "kind": kind,
                    "sha256": digest,
                }
                for component_id, implementation_id, kind, digest in self.implementations
            ],
            "edges": [item.to_payload() for item in self.edges],
            "environment_dependencies": [
                dict(item) for item in self.environment_dependencies
            ],
            "reverse_dependencies": [dict(item) for item in self.reverse_dependencies],
            "sccs": [list(item) for item in self.sccs],
            "issues": [dict(item) for item in self.issues],
            "policy": _graph_policy(),
        }
        return {**core, "graph_sha256": self.graph_sha256}


def build_component_dependency_graph_v3(
    *,
    contracts: Mapping[
        str, ComponentContractV3 | Path | str | Mapping[str, object]
    ],
    implementations: Mapping[
        str, ComponentImplementationV3 | Path | str | Mapping[str, object]
    ],
    bindings: Sequence[ComponentDependencyEdgeV3 | Mapping[str, object]],
    environment_dependencies: Sequence[Mapping[str, object]] = (),
    out: Path | str | None = None,
) -> ComponentDependencyGraphV3:
    checked_contracts = {
        component_id: (
            value
            if isinstance(value, ComponentContractV3)
            else read_component_contract_v3(value)
        )
        for component_id, value in contracts.items()
    }
    checked_implementations = {
        component_id: (
            value
            if isinstance(value, ComponentImplementationV3)
            else read_component_implementation_v3(value)
        )
        for component_id, value in implementations.items()
    }
    edges = tuple(
        sorted(
            item
            if isinstance(item, ComponentDependencyEdgeV3)
            else ComponentDependencyEdgeV3.parse(item)
            for item in bindings
        )
    )
    environment_rows = tuple(
        sorted(
            (
                _validate_environment_dependency(item)
                for item in environment_dependencies
            ),
            key=lambda item: (
                str(item["consumer_component_id"]),
                str(item["consumer_service_id"]),
            ),
        )
    )
    issues: list[dict[str, object]] = []
    for component_id, contract in checked_contracts.items():
        if component_id != contract.component_id:
            issues.append(
                _issue("violated", "contract_map_identity_mismatch", component_id=component_id)
            )
        if contract.status != "checked":
            issues.append(
                _issue(
                    "violated" if contract.status == "violated" else "incomplete",
                    "component_contract_not_checked",
                    component_id=component_id,
                )
            )
        implementation = checked_implementations.get(component_id)
        if implementation is None:
            issues.append(
                _issue(
                    "incomplete", "component_implementation_not_selected",
                    component_id=component_id,
                )
            )
        elif (
            implementation.component_id != component_id
            or implementation.contract_sha256 != contract.contract_sha256
        ):
            issues.append(
                _issue(
                    "violated", "implementation_contract_binding_stale",
                    component_id=component_id,
                )
            )
        elif not implementation.authorizing:
            issues.append(
                _issue(
                    "violated" if implementation.status == "violated" else "incomplete",
                    "component_implementation_not_checked",
                    component_id=component_id,
                )
            )
    for component_id in sorted(set(checked_implementations) - set(checked_contracts)):
        issues.append(
            _issue(
                "violated", "implementation_component_unknown",
                component_id=component_id,
            )
        )

    by_consumer_service: dict[tuple[str, str], list[ComponentDependencyEdgeV3]] = {}
    for edge in edges:
        by_consumer_service.setdefault(
            (edge.consumer_component_id, edge.consumer_service_id), []
        ).append(edge)
    environment_by_consumer_service = {
        (
            str(row["consumer_component_id"]),
            str(row["consumer_service_id"]),
        ): row
        for row in environment_rows
    }
    expected_services = {
        (component_id, service.service_id)
        for component_id, contract in checked_contracts.items()
        for service in contract.services
    }
    submitted_services = set(by_consumer_service) | set(
        environment_by_consumer_service
    )
    for key in sorted(expected_services | submitted_services):
        matching = by_consumer_service.get(key, [])
        environment = environment_by_consumer_service.get(key)
        if key not in expected_services:
            issues.append(
                _issue(
                    "violated", "dependency_service_unknown",
                    component_id=key[0], service_id=key[1],
                )
            )
        elif len(matching) + (environment is not None) == 0:
            issues.append(
                _issue(
                    "incomplete", "dependency_service_unresolved",
                    component_id=key[0], service_id=key[1],
                )
            )
        elif len(matching) + (environment is not None) != 1:
            issues.append(
                _issue(
                    "violated", "dependency_service_bound_more_than_once",
                    component_id=key[0], service_id=key[1],
                )
            )

    for row in environment_rows:
        consumer = checked_contracts.get(str(row["consumer_component_id"]))
        if consumer is None:
            issues.append(
                _issue(
                    "violated",
                    "environment_dependency_component_unknown",
                    component_id=row["consumer_component_id"],
                )
            )
            continue
        service = next(
            (
                item
                for item in consumer.services
                if item.service_id == row["consumer_service_id"]
            ),
            None,
        )
        if service is None:
            issues.append(
                _issue(
                    "violated",
                    "environment_dependency_service_unknown",
                    component_id=row["consumer_component_id"],
                    service_id=row["consumer_service_id"],
                )
            )
        if row["authority_status"] != "checked":
            issues.append(
                _issue(
                    "incomplete",
                    "environment_dependency_not_checked",
                    component_id=row["consumer_component_id"],
                    service_id=row["consumer_service_id"],
                )
            )

    for edge in edges:
        consumer = checked_contracts.get(edge.consumer_component_id)
        provider = checked_contracts.get(edge.provider_component_id)
        if consumer is None or provider is None:
            issues.append(
                _issue(
                    "violated", "dependency_component_unknown",
                    component_id=edge.consumer_component_id,
                    provider_component_id=edge.provider_component_id,
                )
            )
            continue
        service = next(
            (item for item in consumer.services if item.service_id == edge.consumer_service_id),
            None,
        )
        operation = next(
            (item for item in provider.operations if item.operation_id == edge.provider_operation_id),
            None,
        )
        if service is None or operation is None:
            issues.append(
                _issue(
                    "violated", "dependency_endpoint_unknown",
                    component_id=edge.consumer_component_id,
                    service_id=edge.consumer_service_id,
                    provider_component_id=edge.provider_component_id,
                    provider_operation_id=edge.provider_operation_id,
                )
            )
            continue
        if not _compatible(consumer, service, provider, operation):
            issues.append(
                _issue(
                    "violated", "dependency_contract_incompatible",
                    component_id=edge.consumer_component_id,
                    service_id=edge.consumer_service_id,
                    provider_component_id=edge.provider_component_id,
                    provider_operation_id=edge.provider_operation_id,
                )
            )

    reverse = _reverse_dependencies(checked_contracts, edges)
    sccs = _sccs(tuple(checked_contracts), edges)
    status = (
        "violated"
        if any(item["status"] == "violated" for item in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    core: dict[str, object] = {
        "format": COMPONENT_DEPENDENCY_GRAPH_V3_FORMAT,
        "status": status,
        "contracts": [
            {"id": item.component_id, "sha256": item.contract_sha256}
            for item in sorted(checked_contracts.values(), key=lambda item: item.component_id)
        ],
        "implementations": [
            {
                "component_id": item.component_id,
                "id": item.implementation_id,
                "kind": item.kind,
                "sha256": item.implementation_sha256,
            }
            for item in sorted(
                checked_implementations.values(), key=lambda item: item.component_id
            )
        ],
        "edges": [item.to_payload() for item in edges],
        "environment_dependencies": list(environment_rows),
        "reverse_dependencies": reverse,
        "sccs": [list(item) for item in sccs],
        "issues": sorted(
            issues,
            key=lambda item: (
                str(item.get("status", "")),
                str(item.get("code", "")),
                str(item.get("component_id", "")),
                str(item.get("service_id", "")),
            ),
        ),
        "policy": _graph_policy(),
    }
    result = ComponentDependencyGraphV3.parse(
        {**core, "graph_sha256": canonical_sha256_v3(core)}
    )
    if out is not None:
        _write(Path(out), "component-dependency-graph-v3.json", result.to_payload())
    return result


def build_component_release_gate_v1(
    *,
    graph: ComponentDependencyGraphV3 | Path | str | Mapping[str, object],
    activation_plan: ComponentActivationPlanRecordV3 | Path | str | Mapping[str, object],
    rooted_projection: RootedUnitProjection,
    mode: str,
    out: Path | str | None = None,
) -> dict[str, object]:
    checked_graph = (
        graph
        if isinstance(graph, ComponentDependencyGraphV3)
        else read_component_dependency_graph_v3(graph)
    )
    checked_activation = (
        activation_plan
        if isinstance(activation_plan, ComponentActivationPlanRecordV3)
        else ComponentActivationPlanRecordV3.parse(
            _load_json_artifact(
                activation_plan,
                "activation-plan.json",
                "component activation plan",
            )
        )
    )
    if mode not in {"hybrid", "portable"}:
        raise ComponentDependencyGraphError("release mode must be hybrid or portable")
    rooted_unit_ids = rooted_projection.reachable_unit_ids
    if (
        not rooted_unit_ids
        or rooted_unit_ids != tuple(sorted(set(rooted_unit_ids)))
        or not isinstance(rooted_projection.structural_unit_count, int)
        or isinstance(rooted_projection.structural_unit_count, bool)
        or rooted_projection.structural_unit_count < len(rooted_unit_ids)
        or not _is_digest(rooted_projection.projection_sha256)
    ):
        raise ComponentDependencyGraphError(
            "release gate rooted behavioral projection is malformed"
        )
    rooted_units = frozenset(rooted_unit_ids)
    allowed = (
        {"portable_c", "pinned_binary", "machine_ir", "external_environment"}
        if mode == "hybrid"
        else {"portable_c", "machine_ir", "external_environment"}
    )
    issues = [dict(item) for item in checked_graph.issues]
    if checked_graph.status != "checked" and not issues:
        issues.append(_issue("incomplete", "component_dependency_graph_not_checked"))
    if checked_activation.status != "checked":
        issues.append(
            _issue(
                "violated" if checked_activation.status == "violated" else "incomplete",
                "component_activation_plan_not_checked",
            )
        )
    activation_implementations: dict[str, str] = {}
    for selection_value in checked_activation.selections:
        selection = _object(selection_value.to_value(), "component activation selection")
        component_id = _identifier(selection.get("id"), "activation component id")
        ownership_state = _choice(
            selection.get("ownership_state"),
            {"portable_replacement", "machine_ir_fallback", "blocked"},
            "activation ownership state",
        )
        if component_id in activation_implementations:
            issues.append(
                _issue(
                    "violated",
                    "component_activation_selection_duplicated",
                    component_id=component_id,
                )
            )
        activation_implementations[component_id] = ownership_state
    graph_implementations = {
        component_id: kind
        for component_id, _implementation_id, kind, _digest_value
        in checked_graph.implementations
    }
    if set(activation_implementations) != set(graph_implementations):
        issues.append(
            _issue(
                "violated",
                "component_activation_graph_inventory_mismatch",
                activation_only=sorted(
                    set(activation_implementations) - set(graph_implementations)
                ),
                graph_only=sorted(
                    set(graph_implementations) - set(activation_implementations)
                ),
            )
        )
    expected_kinds = {
        "portable_replacement": {"portable_c", "pinned_binary"},
        "machine_ir_fallback": {"machine_ir"},
        "blocked": {"blocked"},
    }
    for component_id in sorted(
        set(activation_implementations) & set(graph_implementations)
    ):
        ownership_state = activation_implementations[component_id]
        implementation_kind = graph_implementations[component_id]
        if implementation_kind not in expected_kinds[ownership_state]:
            issues.append(
                _issue(
                    "violated",
                    "component_activation_implementation_kind_mismatch",
                    component_id=component_id,
                    ownership_state=ownership_state,
                    implementation_kind=implementation_kind,
                )
            )
    fallback_units = sum(
        entry.implementation_kind == "machine_ir_fallback"
        for entry in checked_activation.entries
    )
    activation_units = {entry.unit_id for entry in checked_activation.entries}
    if len(activation_units) != rooted_projection.structural_unit_count:
        issues.append(
            _issue(
                "violated",
                "structural_activation_inventory_mismatch",
                expected_units=rooted_projection.structural_unit_count,
                activation_units=len(activation_units),
            )
        )
    missing_rooted_units = sorted(rooted_units - activation_units)
    if missing_rooted_units:
        issues.append(
            _issue(
                "violated",
                "rooted_behavioral_activation_coverage_missing",
                missing_unit_ids=missing_rooted_units,
            )
        )
    rooted_fallback_units = sum(
        entry.unit_id in rooted_units
        and entry.implementation_kind == "machine_ir_fallback"
        for entry in checked_activation.entries
    )
    unreachable_fallback_units = fallback_units - rooted_fallback_units
    blocked_units = sum(
        entry.implementation_kind == "blocked"
        for entry in checked_activation.entries
    )
    if blocked_units:
        issues.append(
            _issue(
                "incomplete",
                "component_activation_contains_blocked_units",
                blocked_units=blocked_units,
            )
        )
    if mode == "portable" and rooted_fallback_units:
        issues.append(
            _issue(
                "incomplete",
                "root_reachable_machine_ir_fallback_forbidden_by_portable_release",
                rooted_fallback_units=rooted_fallback_units,
                unreachable_fallback_units=unreachable_fallback_units,
            )
        )
    counts = {
        kind: sum(item[2] == kind for item in checked_graph.implementations)
        for kind in (
            "portable_c", "pinned_binary", "machine_ir", "external_environment", "blocked"
        )
    }
    counts["machine_ir_fallback_units"] = fallback_units
    counts["root_reachable_units"] = len(rooted_units)
    counts["root_reachable_machine_ir_fallback_units"] = rooted_fallback_units
    counts["unreachable_machine_ir_fallback_units"] = unreachable_fallback_units
    counts["blocked_units"] = blocked_units
    for component_id, _implementation_id, kind, _digest_value in checked_graph.implementations:
        if kind not in allowed:
            issues.append(
                _issue(
                    "incomplete", "implementation_kind_forbidden_by_release_mode",
                    component_id=component_id, implementation_kind=kind, mode=mode,
                )
            )
    status = (
        "violated"
        if any(item.get("status") == "violated" for item in issues)
        else "incomplete"
        if issues
        else "ready"
    )
    core: dict[str, object] = {
        "format": COMPONENT_RELEASE_GATE_V1_FORMAT,
        "mode": mode,
        "status": status,
        "ready": status == "ready",
        "graph_sha256": checked_graph.graph_sha256,
        "activation_plan_sha256": checked_activation.activation_plan_sha256,
        "rooted_behavioral_projection_sha256": rooted_projection.projection_sha256,
        "counts": counts,
        "issues": sorted(
            issues,
            key=lambda item: (
                str(item.get("status", "")), str(item.get("code", "")),
                str(item.get("component_id", "")),
            ),
        ),
        "policy": {
            "original_binary_executed": False,
            "handwritten_behavior_tests_required": False,
            "hybrid_allows_qualified_pinned_implementations": mode == "hybrid",
            "portable_requires_no_pinned_implementations": mode == "portable",
            "portable_requires_no_root_reachable_machine_ir_fallback": mode == "portable",
        },
    }
    result = {**core, "gate_sha256": canonical_sha256_v3(core)}
    if out is not None:
        _write(Path(out), f"component-{mode}-release-gate-v1.json", result)
    return result


def build_component_dependency_graph_from_service_graph_v3(
    *,
    contracts: Mapping[
        str, ComponentContractV3 | Path | str | Mapping[str, object]
    ],
    implementations: Mapping[
        str, ComponentImplementationV3 | Path | str | Mapping[str, object]
    ],
    service_graph: ServiceGraphV1 | Path | str | Mapping[str, object],
    out: Path | str | None = None,
) -> ComponentDependencyGraphV3:
    """Project the checked V1 service authority into the universal graph."""

    graph = (
        service_graph
        if isinstance(service_graph, ServiceGraphV1)
        else ServiceGraphV1.parse(
            _load_json_artifact(
                service_graph, "service-graph.json", "component service graph"
            )
        )
    )
    parsed_contracts = {
        key: (
            value
            if isinstance(value, ComponentContractV3)
            else read_component_contract_v3(value)
        )
        for key, value in contracts.items()
    }
    by_interface = {
        contract.interface_id: contract.component_id
        for contract in parsed_contracts.values()
    }
    edges: list[ComponentDependencyEdgeV3] = []
    environment: list[dict[str, object]] = []
    for binding in graph.bindings:
        consumer_id = by_interface.get(binding.component_id)
        if consumer_id is None:
            raise ComponentDependencyGraphError(
                f"service consumer interface {binding.component_id!r} has no contract"
            )
        provider = binding.provider
        if isinstance(provider, ComponentOperationProviderV1):
            provider_id = by_interface.get(provider.component_id)
            if provider_id is None:
                raise ComponentDependencyGraphError(
                    f"service provider interface {provider.component_id!r} has no contract"
                )
            edges.append(
                ComponentDependencyEdgeV3.parse(
                    {
                        "consumer_component_id": consumer_id,
                        "consumer_service_id": binding.service_id,
                        "provider_component_id": provider_id,
                        "provider_operation_id": provider.operation_id,
                        "mediation": binding.mediation,
                        "callsite_ids": [
                            f"service:{consumer_id}:{binding.service_id}"
                        ],
                    }
                )
            )
            continue
        if isinstance(provider, ExternalServiceProviderV1):
            provider_kind = "external_site"
            provider_ids = [provider.site_id]
            callsites = [provider.site_id]
        elif isinstance(provider, MachineEventServiceProviderV1):
            provider_kind = "machine_events"
            provider_ids = list(provider.event_ids)
            callsites = list(provider.event_ids)
        else:
            raise ComponentDependencyGraphError(
                "unsupported checked service provider in universal graph"
            )
        environment.append(
            {
                "consumer_component_id": consumer_id,
                "consumer_service_id": binding.service_id,
                "provider_kind": provider_kind,
                "provider_ids": provider_ids,
                "mediation": binding.mediation,
                "callsite_ids": callsites,
                "authority_kind": "component_service_graph_v1",
                "authority_sha256": graph.graph_sha256,
                "authority_status": (
                    "checked" if graph.activation_authorized else graph.status
                ),
            }
        )
    return build_component_dependency_graph_v3(
        contracts=parsed_contracts,
        implementations=implementations,
        bindings=edges,
        environment_dependencies=environment,
        out=out,
    )


def read_component_dependency_graph_v3(
    value: Path | str | Mapping[str, object],
) -> ComponentDependencyGraphV3:
    if isinstance(value, Mapping):
        payload = value
    else:
        path = Path(value)
        if path.is_dir():
            path = path / "component-dependency-graph-v3.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ComponentDependencyGraphError(
                f"cannot read component dependency graph: {exc}"
            ) from exc
    return ComponentDependencyGraphV3.parse(payload)


def _compatible(
    consumer: ComponentContractV3,
    service: object,
    provider: ComponentContractV3,
    operation: object,
) -> bool:
    consumer_types = dict(consumer.type_hashes)
    provider_types = dict(provider.type_hashes)
    service_parameters = tuple(
        consumer_types.get(item) for item in getattr(service, "parameter_type_ids")
    )
    operation_parameters = tuple(
        provider_types.get(item) for item in getattr(operation, "parameter_type_ids")
    )
    if None in service_parameters or service_parameters != operation_parameters:
        return False
    service_result_id = getattr(service, "result_type_id")
    operation_result_ids = getattr(operation, "result_type_ids")
    if service_result_id is None:
        if operation_result_ids:
            return False
    elif len(operation_result_ids) != 1 or (
        consumer_types.get(service_result_id)
        != provider_types.get(operation_result_ids[0])
    ):
        return False
    consumer_effects = dict(consumer.effect_hashes)
    provider_effects = dict(provider.effect_hashes)
    return tuple(
        consumer_effects.get(item) for item in getattr(service, "effect_ids")
    ) == tuple(
        provider_effects.get(item) for item in getattr(operation, "effect_ids")
    )


def _reverse_dependencies(
    contracts: Mapping[str, ComponentContractV3],
    edges: Sequence[ComponentDependencyEdgeV3],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for provider_id in sorted(contracts):
        consumers = []
        for edge in edges:
            if edge.provider_component_id != provider_id:
                continue
            consumer = contracts.get(edge.consumer_component_id)
            operation_ids = [] if consumer is None else sorted(
                operation.operation_id
                for operation in consumer.operations
                if edge.consumer_service_id in operation.service_ids
            )
            consumers.append(
                {
                    "component_id": edge.consumer_component_id,
                    "operation_ids": operation_ids,
                    "service_id": edge.consumer_service_id,
                    "provider_operation_id": edge.provider_operation_id,
                    "callsites": list(edge.callsite_ids),
                }
            )
        result.append(
            {
                "provider_component_id": provider_id,
                "retirable": not consumers,
                "consumers": consumers,
            }
        )
    return result


def _sccs(
    components: tuple[str, ...], edges: Sequence[ComponentDependencyEdgeV3]
) -> tuple[tuple[str, ...], ...]:
    adjacency = {component: set() for component in components}
    for edge in edges:
        if edge.consumer_component_id in adjacency and edge.provider_component_id in adjacency:
            adjacency[edge.consumer_component_id].add(edge.provider_component_id)
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    groups: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(adjacency[node]):
            if target not in indices:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])
        if lowlinks[node] == indices[node]:
            members: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                members.append(member)
                if member == node:
                    break
            groups.append(tuple(sorted(members)))

    for component in sorted(components):
        if component not in indices:
            visit(component)
    return tuple(sorted(groups))


def _graph_policy() -> dict[str, bool]:
    return {
        "one_selected_implementation_per_component": True,
        "every_service_has_exactly_one_provider": True,
        "provider_compatibility_uses_contracts_not_implementations": True,
        "callsites_are_explicit": True,
        "hidden_dependencies_fail_closed": True,
        "original_binary_executed": False,
    }


def _validate_environment_dependency(
    value: Mapping[str, object],
) -> dict[str, object]:
    row = _object(value, "environment dependency")
    _exact(
        row,
        {
            "consumer_component_id",
            "consumer_service_id",
            "provider_kind",
            "provider_ids",
            "mediation",
            "callsite_ids",
            "authority_kind",
            "authority_sha256",
            "authority_status",
        },
        "environment dependency",
    )
    provider_kind = _choice(
        row["provider_kind"], {"external_site", "machine_events"},
        "environment provider kind",
    )
    authority_status = _choice(
        row["authority_status"], {"checked", "incomplete", "violated"},
        "environment authority status",
    )
    result = {
        "consumer_component_id": _identifier(
            row["consumer_component_id"], "environment consumer component"
        ),
        "consumer_service_id": _identifier(
            row["consumer_service_id"], "environment consumer service"
        ),
        "provider_kind": provider_kind,
        "provider_ids": list(
            _strings(row["provider_ids"], "environment provider ids", nonempty=True)
        ),
        "mediation": _choice(
            row["mediation"], {"direct", "callback", "protocol"},
            "environment dependency mediation",
        ),
        "callsite_ids": list(
            _strings(row["callsite_ids"], "environment callsite ids", nonempty=True)
        ),
        "authority_kind": _identifier(
            row["authority_kind"], "environment authority kind"
        ),
        "authority_sha256": _digest(
            row["authority_sha256"], "environment authority digest"
        ),
        "authority_status": authority_status,
    }
    return result


def _load_json_artifact(
    value: Path | str | Mapping[str, object],
    filename: str,
    description: str,
) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    path = Path(value)
    if path.is_dir():
        path = path / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentDependencyGraphError(
            f"cannot read {description}: {exc}"
        ) from exc
    return _object(payload, description)


def _issue(status: str, code: str, **fields: object) -> dict[str, object]:
    return {"status": status, "code": code, **fields}


def _write(path: Path, filename: str, payload: Mapping[str, object]) -> None:
    if path.suffix != ".json":
        path.mkdir(parents=True, exist_ok=True)
        path = path / filename
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentDependencyGraphError(f"{description} must be an object")
    return value


def _canonical_object(value: object, description: str) -> Mapping[str, object]:
    return json.loads(json.dumps(_object(value, description)))


def _array(value: object, description: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ComponentDependencyGraphError(f"{description} must be an array")
    return value


def _exact(value: Mapping[str, object], fields: set[str], description: str) -> None:
    if set(value) != fields:
        raise ComponentDependencyGraphError(
            f"{description} must contain exactly {sorted(fields)!r}"
        )


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentDependencyGraphError(f"{description} must be a nonempty string")
    return value


def _identifier(value: object, description: str) -> str:
    result = _text(value, description)
    if not result[0].isalnum() or any(
        not (character.isalnum() or character in "._-:") for character in result
    ):
        raise ComponentDependencyGraphError(f"{description} is invalid")
    return result


def _choice(value: object, choices: set[str], description: str) -> str:
    result = _text(value, description)
    if result not in choices:
        raise ComponentDependencyGraphError(f"{description} is unsupported")
    return result


def _digest(value: object, description: str) -> str:
    result = _text(value, description)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ComponentDependencyGraphError(f"{description} is not a SHA-256 digest")
    return result


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _strings(
    value: object, description: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    result = tuple(_text(item, description) for item in _array(value, description))
    if result != tuple(sorted(set(result))) or (nonempty and not result):
        raise ComponentDependencyGraphError(
            f"{description} must be unique, ordered, and"
            + (" nonempty" if nonempty else " canonical")
        )
    return result


__all__ = [
    "ComponentDependencyEdgeV3",
    "ComponentDependencyGraphError",
    "ComponentDependencyGraphV3",
    "build_component_dependency_graph_from_service_graph_v3",
    "build_component_dependency_graph_v3",
    "build_component_release_gate_v1",
    "read_component_dependency_graph_v3",
]
