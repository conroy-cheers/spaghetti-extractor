"""Machine-derived semantic contracts for portable component operations.

The contract is deliberately data, not an operator-authored behavior model.  It
copies the exact selected machine semantics into a compact, content-bound
artifact after checking the interface and machine binding identities.  Later
checkers may support only a subset of the recorded semantics, but they must
report that limitation as incomplete rather than reinterpret the contract.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import ArtifactV3Error, canonical_sha256_v3
from ..external.site_authority import (
    CanonicalExternalSiteRecordError,
    CheckedCanonicalExternalSite,
    read_canonical_external_sites,
)
from .formats import COMPONENT_SEMANTIC_CONTRACT_V1_FORMAT
from .interface_ir import PortableComponentInterfaceV2
from .machine_binding import ComponentMachineBindingV1


class ComponentSemanticContractError(ValueError):
    """A semantic-contract input is malformed or contradicts exact inputs."""


@dataclass(frozen=True)
class ComponentSemanticContractV1:
    payload: Mapping[str, object]

    @classmethod
    def parse(cls, value: object) -> "ComponentSemanticContractV1":
        row = _object(value, "component semantic contract")
        required = {
            "format", "status", "component_id", "bindings", "operations",
            "services", "issues", "policy", "contract_sha256",
        }
        if set(row) != required:
            raise ComponentSemanticContractError(
                "component semantic-contract fields are noncanonical"
            )
        if row["format"] != COMPONENT_SEMANTIC_CONTRACT_V1_FORMAT:
            raise ComponentSemanticContractError(
                "unsupported component semantic-contract format"
            )
        if row["status"] not in {"satisfied", "incomplete", "violated"}:
            raise ComponentSemanticContractError(
                "component semantic-contract status is invalid"
            )
        core = dict(row)
        observed = core.pop("contract_sha256")
        if not isinstance(observed, str) or canonical_sha256_v3(core) != observed:
            raise ComponentSemanticContractError(
                "component semantic-contract digest is stale"
            )
        operations = row["operations"]
        if not isinstance(operations, list) or not operations:
            raise ComponentSemanticContractError(
                "component semantic contract has no operations"
            )
        return cls(json.loads(json.dumps(row)))

    @property
    def status(self) -> str:
        return str(self.payload["status"])

    @property
    def contract_sha256(self) -> str:
        return str(self.payload["contract_sha256"])

    def to_payload(self) -> dict[str, object]:
        return json.loads(json.dumps(self.payload))


def build_component_semantic_contract(
    *,
    interface: Path | str | Mapping[str, object],
    binding: Path | str | Mapping[str, object],
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    canonical_external_sites: Path | str | None = None,
) -> dict[str, object]:
    """Build an exact selected-unit contract without executing the original."""

    interface_payload = _load(interface, "portable component interface")
    portable = PortableComponentInterfaceV2.parse(interface_payload)
    binding_payload = _load(binding, "component machine binding")
    machine_binding = ComponentMachineBindingV1.parse(binding_payload)
    machine_path = Path(machine_ir)
    manifest_path = Path(machine_ir_manifest)
    machine_bytes = machine_path.read_bytes()
    machine_sha256 = hashlib.sha256(machine_bytes).hexdigest()
    manifest_bytes = manifest_path.read_bytes()
    manifest = _load(manifest_path, "machine-IR manifest")
    manifest_machine = _object(
        _object(manifest.get("artifacts"), "machine-IR artifacts").get("machine_ir"),
        "machine-IR artifact",
    )
    pe = _object(manifest.get("binary"), "machine-IR binary").get("sha256")
    units = _read_units(machine_bytes)
    issues: list[dict[str, object]] = []

    def issue(status: str, code: str, **fields: object) -> None:
        issues.append({"status": status, "code": code, **fields})

    if manifest_machine.get("sha256") != machine_sha256:
        issue("violated", "machine_ir_manifest_digest_mismatch")
    if machine_binding.machine_ir_sha256 != machine_sha256:
        issue("violated", "machine_ir_binding_digest_mismatch")
    if machine_binding.pe_sha256 != pe:
        issue("violated", "pe_binding_digest_mismatch")
    if machine_binding.interface_id != portable.identity:
        issue("violated", "interface_identity_mismatch")
    if machine_binding.interface_sha256 != portable.sha256:
        issue("violated", "interface_digest_mismatch")

    selected: dict[str, Mapping[str, object]] = {}
    for unit_id in machine_binding.unit_ids:
        unit = units.get(unit_id)
        if unit is None:
            issue("violated", "selected_machine_unit_missing", unit_id=unit_id)
            continue
        selected[unit_id] = unit
        if unit.get("status") != "qualified":
            issue(
                "incomplete", "selected_machine_unit_not_qualified",
                unit_id=unit_id, observed=unit.get("status"),
            )

    interface_operations = portable.operation_index()
    operations: list[dict[str, object]] = []
    for operation in machine_binding.operations:
        if operation.operation_id not in interface_operations:
            issue("violated", "bound_operation_unknown", operation_id=operation.operation_id)
            continue
        operation_units = _operation_units(operation, selected)
        if operation_units is None:
            issue(
                "incomplete", "operation_control_closure_unresolved",
                operation_id=operation.operation_id,
            )
            operation_units = tuple(
                selected[item] for item in machine_binding.unit_ids if item in selected
            )
        operations.append({
            "operation_id": operation.operation_id,
            "entry_unit_ids": list(operation.entry_unit_ids),
            "exit_unit_ids": list(operation.exit_unit_ids),
            "parameters": [row.to_payload() for row in operation.parameters],
            "results": [row.to_payload() for row in operation.results],
            "state": [row.to_payload() for row in operation.state],
            "preserved_state_ids": list(operation.preserved_state_ids),
            "effects": [row.to_payload() for row in operation.effects],
            "callback_operation_ids": list(operation.callback_operation_ids),
            "continuation_unit_ids": list(operation.continuation_unit_ids),
            "units": [_contract_unit(row) for row in operation_units],
        })

    external_sites: dict[str, CheckedCanonicalExternalSite] = {}
    if any(
        service.provider.get("kind") == "external_site"
        for service in machine_binding.services
    ):
        if canonical_external_sites is None:
            issue("incomplete", "canonical_external_sites_missing")
        else:
            try:
                external_sites = read_canonical_external_sites(
                    canonical_external_sites,
                    record_ids=machine_binding.unit_ids,
                )
            except (ArtifactV3Error, CanonicalExternalSiteRecordError) as exc:
                issue(
                    "violated",
                    "canonical_external_sites_invalid",
                    detail=str(exc),
                )

    logical_services = {service.identity: service for service in portable.services}
    services: list[dict[str, object]] = []
    for service in machine_binding.services:
        provider = service.provider
        if provider.get("kind") != "external_site":
            services.append(service.to_payload())
            continue
        site_id = provider.get("site_id")
        site = external_sites.get(str(site_id))
        logical = logical_services.get(service.service_id)
        if site is None:
            issue(
                "incomplete",
                "bound_external_site_missing",
                service_id=service.service_id,
                site_id=site_id,
            )
            services.append(service.to_payload())
            continue
        if site.status != "complete" or not site.authorizing or site.contract is None:
            issue(
                "incomplete",
                "bound_external_site_not_authorizing",
                service_id=service.service_id,
                site_id=site.site_id,
            )
        unit = selected.get(site.unit_id)
        if unit is None:
            issue(
                "violated",
                "bound_external_site_outside_component",
                service_id=service.service_id,
                site_id=site.site_id,
            )
            services.append(service.to_payload())
            continue
        machine_events = _array(
            _object(unit.get("semantics"), "machine semantics").get(
                "external_events", []
            ),
            "machine external events",
        )
        if site.event_index >= len(machine_events):
            issue(
                "violated",
                "bound_external_site_event_stale",
                service_id=service.service_id,
                site_id=site.site_id,
            )
            services.append(service.to_payload())
            continue
        machine_event = _object(
            machine_events[site.event_index], "machine external event"
        )
        if site.contract is None:
            services.append(service.to_payload())
            continue
        contract_arguments = list(site.contract.arguments)
        expected_count = (
            0 if logical is None else len(logical.parameter_type_ids)
        )
        if len(contract_arguments) != expected_count:
            issue(
                "violated",
                "external_site_service_argument_inventory_mismatch",
                service_id=service.service_id,
                expected=expected_count,
                observed=len(contract_arguments),
            )
        result: dict[str, object] | None = None
        if logical is not None and logical.result_type_id is not None:
            relations = [
                row
                for row in site.contract.result_register_relations
                if isinstance(row, Mapping) and row.get("relation") == "exact"
            ]
            if len(relations) != 1 or not isinstance(
                relations[0].get("register"), str
            ):
                issue(
                    "incomplete",
                    "external_site_service_result_unresolved",
                    service_id=service.service_id,
                    site_id=site.site_id,
                )
            else:
                result = {
                    "kind": "register",
                    "register": relations[0]["register"],
                    "width": 32,
                    "at": "call",
                }
        services.append(
            {
                "service_id": service.service_id,
                "mediation": service.mediation,
                "provider": {
                    "kind": "checked_external_site_events",
                    "events": [
                        {
                            "site_id": site.site_id,
                            "site_event_sha256": site.event_sha256,
                            "unit_id": site.unit_id,
                            "event_index": site.event_index,
                            "event_sha256": canonical_sha256_v3(machine_event),
                            "arguments": json.loads(
                                json.dumps(contract_arguments)
                            ),
                            "result": result,
                        }
                    ],
                },
            }
        )

    status = (
        "violated" if any(row["status"] == "violated" for row in issues)
        else "incomplete" if issues
        else "satisfied"
    )
    core: dict[str, object] = {
        "format": COMPONENT_SEMANTIC_CONTRACT_V1_FORMAT,
        "status": status,
        "component_id": machine_binding.identity,
        "bindings": {
            "pe_sha256": pe,
            "machine_ir_sha256": machine_sha256,
            "machine_ir_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "interface_sha256": portable.sha256,
            "machine_binding_sha256": machine_binding.binding_sha256,
            "external_sites_sha256": (
                None
                if not external_sites
                else canonical_sha256_v3(
                    [_external_site_payload(site) for site in external_sites.values()]
                )
            ),
        },
        "operations": operations,
        "services": services,
        "issues": sorted(
            issues, key=lambda row: (str(row["status"]), str(row["code"]))
        ),
        "policy": {
            "original_binary_executed": False,
            "behavior_is_machine_derived": True,
            "operator_expected_outputs_accepted": False,
            "unsupported_semantics_fail_closed": True,
        },
    }
    return {**core, "contract_sha256": canonical_sha256_v3(core)}


def _operation_units(operation: object, selected: Mapping[str, Mapping[str, object]]) -> tuple[Mapping[str, object], ...] | None:
    entries = tuple(getattr(operation, "entry_unit_ids"))
    exits = set(getattr(operation, "exit_unit_ids"))
    if any(item not in selected for item in entries) or any(item not in selected for item in exits):
        return None
    by_rva = {
        int(_object(row.get("source"), "machine unit source")
            .get("original", {}).get("rva_start", -1)): unit_id
        for unit_id, row in selected.items()
    }
    visited: set[str] = set()
    pending = list(entries)
    while pending:
        unit_id = pending.pop()
        if unit_id in visited:
            continue
        visited.add(unit_id)
        if unit_id in exits:
            continue
        semantics = _object(selected[unit_id].get("semantics"), "machine semantics")
        targets = []
        for edge in semantics.get("edge_conditions", []):
            if isinstance(edge, Mapping) and isinstance(edge.get("target_rva"), int):
                targets.append(int(edge["target_rva"]))
        outcome = semantics.get("outcome")
        if isinstance(outcome, Mapping):
            for field in ("target_rva", "true_target_rva", "false_target_rva"):
                if isinstance(outcome.get(field), int):
                    targets.append(int(outcome[field]))
        for target in targets:
            target_id = by_rva.get(target)
            if target_id is None:
                return None
            pending.append(target_id)
    if not exits <= visited:
        return None
    return tuple(
        selected[item]
        for item in sorted(
            visited,
            key=lambda item: int(
                _object(selected[item].get("source"), "machine unit source")
                .get("original", {}).get("rva_start", 0)
            ),
        )
    )


def _external_site_payload(site: CheckedCanonicalExternalSite) -> dict[str, object]:
    return {
        "site_id": site.site_id,
        "unit_id": site.unit_id,
        "event_index": site.event_index,
        "alternative_index": site.alternative_index,
        "event_sha256": site.event_sha256,
        "target_sha256": site.target_sha256,
        "identity": json.loads(json.dumps(site.identity)),
        "status": site.status,
        "authorizing": site.authorizing,
        "contract": None if site.contract is None else site.contract.payload(),
    }


def _contract_unit(unit: Mapping[str, object]) -> dict[str, object]:
    source = _object(unit.get("source"), "machine unit source")
    return {
        "id": unit.get("id"),
        "status": unit.get("status"),
        "source": json.loads(json.dumps(source)),
        "semantics": json.loads(json.dumps(_object(unit.get("semantics"), "machine semantics"))),
    }


def _read_units(data: bytes) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for line_number, raw in enumerate(data.decode("utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        value = json.loads(raw)
        row = _object(value, f"machine-IR line {line_number}")
        identity = row.get("id")
        if not isinstance(identity, str) or not identity or identity in result:
            raise ComponentSemanticContractError("machine-IR unit identity is invalid")
        result[identity] = row
    return result


def _load(value: Path | str | Mapping[str, object], context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        result = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentSemanticContractError(f"cannot read {context}: {exc}") from exc
    return dict(_object(result, context))


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentSemanticContractError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentSemanticContractError(f"{context} must be an array")
    return value


__all__ = [
    "ComponentSemanticContractError",
    "ComponentSemanticContractV1",
    "build_component_semantic_contract",
]
