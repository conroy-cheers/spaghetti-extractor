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
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.machine_abi import build_pe32_normal_call_abi_premise
from ..external.contracts import CheckedExternalSiteContractError, require_machine_import_effects
from ..external.lifetime_effects import LifetimeEffectError, checked_lifetime_effect
from ..external.terminated_reads import RELATION as TERMINATED_READ_RELATION, WRITTEN_RELATION, checked_terminated_read, checked_terminated_write
from ..external.resolved import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    resolved_interface_method_index_v1,
)
from ..external.machine_abi import resolve_machine_call_abi
from ..transfer.plan import load_executable_transfer_plan
from ..util import sha256_file
from .interface_ir import ProofKernelComponentInterface
from .machine_binding import ProofKernelMachineBinding
from .semantic_external_transducers import (
    ComponentSemanticContractError,
    checked_captured_external_target_guard as _checked_captured_external_target_guard,
    checked_external_argument_transducers as _checked_external_argument_transducers,
    checked_external_argument_words as _external_argument_words,
    checked_external_contract_id as _external_contract_id,
    checked_external_result_projection as _checked_external_result_projection,
    checked_external_stack_arguments as _checked_external_stack_arguments,
    checked_local_cell_result_projection as _checked_local_cell_result_projection,
)

from .semantic_contract_transfer import (
    _array,
    _atomic_effect_inventory,
    _checked_interface_method_service_v1,
    _checked_machine_image,
    _contract_unit,
    _expression_index,
    _external_event_inventory,
    _external_identity_key,
    _external_machine_event_matches_provider,
    _load,
    _object,
    _operation_units,
    _read_units,
    _resolved_external_contract_index,
    _service_event_selectors,
    transfer_expression_view_v2,
)


@dataclass(frozen=True)
class CanonicalTransferRefinementUniverseV2:
    """Exact contract-selected transfer rows consumed directly by refinement."""

    transfer_payload: Mapping[str, object]
    units: Mapping[str, Mapping[str, object]]
    transfer_plan_sha256: str
    pe_sha256: str




def load_transfer_v2_refinement_universe(
    *, transfer_plan: Path | str, required_unit_ids: Sequence[str]
) -> CanonicalTransferRefinementUniverseV2:
    """Select exact contract-bound rows without serializing a second IR."""

    transfer_path = Path(transfer_plan)
    payload, _ = load_executable_transfer_plan(transfer_path, require_complete=False)
    transfer_sha256 = sha256_file(transfer_path)
    reachable_unit_ids = {str(item) for item in required_unit_ids}
    if (
        not reachable_unit_ids
        or len(reachable_unit_ids) != len(required_unit_ids)
        or any(not item for item in reachable_unit_ids)
    ):
        raise ComponentSemanticContractError(
            "component transfer selection is empty or ambiguous"
        )

    raw_transfers = _array(payload.get("transfers"), "canonical transfers")
    inventory = _array(payload.get("unit_inventory"), "transfer unit inventory")
    inventory_by_id = {
        str(_object(row, "transfer unit binding")["unit_id"]): _object(
            row, "transfer unit binding"
        )
        for row in inventory
    }
    if len(inventory_by_id) != len(inventory):
        raise ComponentSemanticContractError(
            "canonical transfer unit inventory is ambiguous"
        )
    compiled_ids = {str(row["identity"]) for row in raw_transfers}
    blocked_ids: set[str] = set()
    selected_ranges = [inventory_by_id[item] for item in reachable_unit_ids if item in inventory_by_id]
    # An unrelated failed lowering cannot invalidate an otherwise exact region.
    # Global/ambiguous failures and any intersecting unit still prevent proof.
    # The original incomplete plan is retained, never promoted to complete.
    for raw in payload["semantic_blockers"]:
        blocker = _object(raw, "canonical transfer blocker")
        identity = blocker.get("transfer_id")
        row = inventory_by_id.get(identity) if isinstance(identity, str) else None
        if (
            row is None
            or any(not isinstance(row.get(key), int) or isinstance(row.get(key), bool)
                   for key in ("rva_start", "rva_end"))
            or not 0 <= row["rva_start"] < row["rva_end"] <= 0x100000000
            or blocker.get("failure_phase") not in {"semantic_qualification", "semantic_lowering"}
            or blocker.get("rva_start") != row["rva_start"]
            or identity in reachable_unit_ids
            or identity in compiled_ids
            or any(row["rva_start"] < selected["rva_end"] and selected["rva_start"] < row["rva_end"]
                   for selected in selected_ranges)
        ):
            raise ComponentSemanticContractError(
                "component transfer selection has a selected, overlapping, or unscoped blocker"
            )
        blocked_ids.add(identity)
    if set(inventory_by_id) - compiled_ids != blocked_ids:
        raise ComponentSemanticContractError("canonical transfer omissions lack scoped blockers")
    atomic_by_unit: dict[str, list[Mapping[str, object]]] = {}
    for raw in _array(
        payload.get("atomic_effect_authority"),
        "canonical atomic-effect authority",
    ):
        row = _object(raw, "canonical atomic-effect authority row")
        identity = row.get("unit_id")
        if not isinstance(identity, str):
            raise ComponentSemanticContractError(
                "canonical atomic-effect authority unit is malformed"
            )
        atomic_by_unit.setdefault(identity, []).append(row)

    units: dict[str, Mapping[str, object]] = {}
    for raw in raw_transfers:
        transfer = _object(raw, "canonical transfer")
        identity = transfer.get("identity")
        if not isinstance(identity, str) or identity not in reachable_unit_ids:
            continue
        binding = inventory_by_id.get(identity)
        source = _object(transfer.get("source"), "canonical transfer source")
        if binding is None:
            raise ComponentSemanticContractError(
                "canonical transfer source binding is absent"
            )
        expressions = _expression_index(
            _array(transfer.get("expressions"), "canonical transfer expressions")
        )
        units[identity] = {
            "id": identity,
            "status": "qualified",
            "source": {
                "original": {
                    "rva_start": int(source["rva_start"]),
                    "rva_end": int(source["rva_end"]),
                },
                "contract_sha256": str(source["contract_sha256"]),
                "instruction_bytes_sha256": str(source["instruction_bytes_sha256"]),
                "semantic_export": None,
            },
            "semantics": {
                # This is the only executable body. The other rows are narrow
                # checked boundary views used to bind service and atomic intent.
                "transfer_v2": json.loads(json.dumps(transfer)),
                "external_events": _external_event_inventory(
                    _array(transfer.get("calls"), "canonical transfer calls"),
                    expressions,
                ),
                "transfer_atomic_effects": _atomic_effect_inventory(
                    transfer,
                    expressions,
                    atomic_by_unit.get(identity, []),
                ),
                "faults": [],
            },
        }
    missing = sorted(reachable_unit_ids - set(units))
    if missing:
        raise ComponentSemanticContractError(
            "component transfer selection leaves the canonical transfer universe: "
            + ", ".join(missing[:8])
        )
    bindings = _object(payload.get("bindings"), "canonical transfer bindings")
    pe_sha256 = bindings.get("pe_sha256")
    if not isinstance(pe_sha256, str):
        raise ComponentSemanticContractError(
            "canonical transfer PE binding is malformed"
        )
    return CanonicalTransferRefinementUniverseV2(
        transfer_payload=json.loads(json.dumps(payload)),
        units=dict(
            sorted(
                units.items(),
                key=lambda item: (
                    int(item[1]["source"]["original"]["rva_start"]),
                    item[0],
                ),
            )
        ),
        transfer_plan_sha256=transfer_sha256,
        pe_sha256=pe_sha256,
    )


@dataclass(frozen=True)
class ProofKernelSemanticContract:
    payload: Mapping[str, object]

    @classmethod
    def parse(cls, value: object) -> "ProofKernelSemanticContract":
        row = _object(value, "component semantic contract")
        required = {
            "status",
            "component_id",
            "bindings",
            "operations",
            "services",
            "issues",
            "policy",
            "contract_sha256",
        }
        if set(row) != required:
            raise ComponentSemanticContractError(
                "component semantic-contract fields are noncanonical"
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


def build_proof_kernel_semantic_contract(
    *,
    interface: Path | str | Mapping[str, object],
    binding: Path | str | Mapping[str, object],
    machine_ir: Path | str | CanonicalTransferRefinementUniverseV2,
    machine_ir_manifest: Path | str | None = None,
    resolved_external_environment: Path | str | Mapping[str, object] | None = None,
    component_resolution: Path | str | Mapping[str, object] | None = None,
    machine_image: Mapping[str, object] | None = None,
    operation_unit_ids: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, object]:
    """Build an exact selected-unit contract without executing the original."""

    interface_payload = _load(interface, "portable component interface")
    portable = ProofKernelComponentInterface.parse(interface_payload)
    binding_payload = _load(binding, "component machine binding")
    machine_binding = ProofKernelMachineBinding.parse(binding_payload)
    if operation_unit_ids is not None and (
        not isinstance(operation_unit_ids, Mapping)
        or set(operation_unit_ids) != {op.operation_id for op in machine_binding.operations}
    ):
        raise ComponentSemanticContractError("operation ownership inventory differs from bound operations")
    if isinstance(machine_ir, CanonicalTransferRefinementUniverseV2):
        if machine_ir_manifest is not None:
            raise ComponentSemanticContractError(
                "canonical transfer refinement accepts no proof manifest"
            )
        machine_sha256 = machine_ir.transfer_plan_sha256
        manifest_machine = {"sha256": machine_sha256}
        pe = machine_ir.pe_sha256
        units = dict(machine_ir.units)
        semantic_input_bindings = {
            "executable_transfer_plan_sha256": machine_ir.transfer_plan_sha256,
        }
    else:
        if machine_ir_manifest is None:
            raise ComponentSemanticContractError(
                "machine-IR semantic contracts require a manifest"
            )
        machine_path = Path(machine_ir)
        manifest_path = Path(machine_ir_manifest)
        machine_bytes = machine_path.read_bytes()
        machine_sha256 = hashlib.sha256(machine_bytes).hexdigest()
        manifest_bytes = manifest_path.read_bytes()
        manifest = _load(manifest_path, "machine-IR manifest")
        manifest_machine = _object(
            _object(manifest.get("artifacts"), "machine-IR artifacts").get(
                "machine_ir"
            ),
            "machine-IR artifact",
        )
        pe = _object(manifest.get("binary"), "machine-IR binary").get("sha256")
        units = _read_units(machine_bytes)
        semantic_input_bindings = {
            "machine_ir_sha256": machine_sha256,
            "machine_ir_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }
    checked_machine_image = _checked_machine_image(machine_image, pe_sha256=str(pe))
    issues: list[dict[str, object]] = []

    def issue(status: str, code: str, **fields: object) -> None:
        issues.append({"status": status, "code": code, **fields})

    resolution_payload: Mapping[str, object] | None = None
    normal_call_premise = None
    if any(
        service.provider.get("kind") == "component_operation"
        for service in machine_binding.services
    ):
        if component_resolution is None:
            issue("incomplete", "component_operation_resolution_missing")
        else:
            candidate = _load(component_resolution, "component resolution")
            core = dict(candidate)
            observed = core.pop("projection_sha256", None)
            if (
                set(candidate)
                != {"status", "component_id", "component_calls", "projection_sha256"}
                or candidate.get("status") != "checked"
                or candidate.get("component_id") != machine_binding.identity
                or not isinstance(observed, str)
                or canonical_sha256_v3(core) != observed
            ):
                issue("violated", "component_operation_resolution_invalid")
            else:
                resolution_payload = candidate
        normal_call_premise = build_pe32_normal_call_abi_premise()

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
                "incomplete",
                "selected_machine_unit_not_qualified",
                unit_id=unit_id,
                observed=unit.get("status"),
            )

    interface_operations = portable.operation_index()
    operations: list[dict[str, object]] = []
    for operation in machine_binding.operations:
        if operation.operation_id not in interface_operations:
            issue(
                "violated",
                "bound_operation_unknown",
                operation_id=operation.operation_id,
            )
            continue
        operation_units = _operation_units(operation, selected,
            owned_unit_ids=None if operation_unit_ids is None else operation_unit_ids[operation.operation_id])
        if operation_units is None:
            issue(
                "incomplete",
                "operation_control_closure_unresolved",
                operation_id=operation.operation_id,
            )
            operation_units = tuple(
                selected[item] for item in machine_binding.unit_ids if item in selected
            )
        operations.append(
            {
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
                **({"continuation_units": [
                    _contract_unit(selected[unit_id]) for unit_id in operation.continuation_unit_ids
                    if unit_id in selected
                ]} if operation.continuation_unit_ids else {}),
                "units": [_contract_unit(row) for row in operation_units],
                **(
                    {}
                    if checked_machine_image is None
                    else {"machine_image": dict(checked_machine_image)}
                ),
            }
        )

    external_contracts: dict[tuple[str, str, int | None], Mapping[str, object]] = {}
    interface_method_contracts: dict[str, Mapping[str, object]] = {}
    resolved_environment_sha256: str | None = None
    if any(
        service.provider.get("kind") in {"external_call", "interface_method"}
        for service in machine_binding.services
    ):
        if resolved_external_environment is None:
            issue("incomplete", "resolved_external_environment_missing")
        else:
            try:
                resolved = ResolvedExternalEnvironmentV1.parse(
                    _load(
                        resolved_external_environment,
                        "resolved external environment",
                    )
                )
                resolved_environment_sha256 = resolved.identity
                external_contracts = _resolved_external_contract_index(resolved)
                interface_method_contracts = resolved_interface_method_index_v1(
                    resolved
                )
            except (ExternalEnvironmentError, ComponentSemanticContractError) as exc:
                issue(
                    "violated",
                    "resolved_external_environment_invalid",
                    detail=str(exc),
                )

    logical_services = {service.identity: service for service in portable.services}
    logical_types = portable.type_index()
    resolved_component_calls: list[Mapping[str, object]] = []
    if resolution_payload is not None:
        resolved_component_calls = [
            row
            for row in _array(
                resolution_payload.get("component_calls", []),
                "resolved component calls",
            )
            if isinstance(row, Mapping)
        ]
    services: list[dict[str, object]] = []
    for service in machine_binding.services:
        provider = service.provider
        if provider.get("kind") == "component_operation":
            target_id = provider.get("component_id")
            calls = [
                row
                for row in resolved_component_calls
                if row.get("target_component_id") == target_id
            ]
            target_units = sorted(
                {
                    str(row["target_unit_id"])
                    for row in calls
                    if isinstance(row.get("target_unit_id"), str)
                }
            )
            target_unit = units.get(target_units[0]) if len(target_units) == 1 else None
            if target_unit is None or target_unit.get("status") != "qualified":
                issue(
                    "incomplete",
                    "component_operation_call_boundary_unresolved",
                    service_id=service.service_id,
                    component_id=target_id,
                )
                services.append(service.to_payload())
                continue
            assert normal_call_premise is not None
            target_unit_sha256 = canonical_sha256_v3(_contract_unit(target_unit))
            payload = service.to_payload()
            materialized_provider = dict(
                _object(payload.get("provider"), "component-operation provider")
            )
            materialized_provider["call_boundary"] = {
                "contract_id": (f"{normal_call_premise.premise_id}:{target_units[0]}"),
                "target_unit_id": target_units[0],
                "target_unit_sha256": target_unit_sha256,
                "preserved_registers": list(normal_call_premise.preserved_registers),
                "stack_pointer_relation": "same_call_frame",
            }
            payload["provider"] = materialized_provider
            services.append(payload)
            continue
        if provider.get("kind") == "interface_method":
            logical = logical_services.get(service.service_id)
            event_selectors = _service_event_selectors(provider)
            unit_id, event_index = event_selectors[0]
            method_sha256 = str(provider.get("method_contract_sha256", ""))
            target = interface_method_contracts.get(method_sha256)
            if target is None:
                issue(
                    "incomplete",
                    "bound_interface_method_contract_missing",
                    service_id=service.service_id,
                    method_contract_sha256=method_sha256,
                )
                services.append(service.to_payload())
                continue
            unit = selected.get(unit_id)
            if unit is None:
                issue(
                    "violated",
                    "bound_interface_method_outside_component",
                    service_id=service.service_id,
                    unit_id=unit_id,
                )
                services.append(service.to_payload())
                continue
            machine_events = _array(
                _object(unit.get("semantics"), "machine semantics").get(
                    "external_events", []
                ),
                "machine external events",
            )
            if (
                not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
                or event_index >= len(machine_events)
            ):
                issue(
                    "violated",
                    "bound_interface_method_event_stale",
                    service_id=service.service_id,
                    unit_id=unit_id,
                    event_index=event_index,
                )
                services.append(service.to_payload())
                continue
            machine_event = _object(
                machine_events[event_index], "machine interface-method event"
            )
            try:
                checked = _checked_interface_method_service_v1(
                    service_id=service.service_id,
                    logical=logical,
                    logical_types=logical_types,
                    target=target,
                    method_contract_sha256=method_sha256,
                    unit_id=unit_id,
                    event_index=event_index,
                    machine_event=machine_event,
                    argument_transducers=provider.get("argument_transducers"),
                    result_projection=provider.get("result_projection"),
                )
            except ComponentSemanticContractError as exc:
                issue(
                    "violated",
                    "bound_interface_method_contract_invalid",
                    service_id=service.service_id,
                    detail=str(exc),
                )
                services.append(service.to_payload())
                continue
            extra_events: list[Mapping[str, object]] = []
            extra_invalid = False
            for extra_unit_id, extra_event_index in event_selectors[1:]:
                extra_unit = selected.get(extra_unit_id)
                extra_machine_events = (
                    []
                    if extra_unit is None
                    else _array(
                        _object(
                            extra_unit.get("semantics"),
                            "machine semantics",
                        ).get("external_events", []),
                        "machine external events",
                    )
                )
                if (
                    extra_unit is None
                    or extra_event_index >= len(extra_machine_events)
                    or not isinstance(extra_machine_events[extra_event_index], Mapping)
                ):
                    issue(
                        "violated",
                        "bound_interface_method_event_stale",
                        service_id=service.service_id,
                        unit_id=extra_unit_id,
                        event_index=extra_event_index,
                    )
                    extra_invalid = True
                    break
                try:
                    extra_checked = _checked_interface_method_service_v1(
                        service_id=service.service_id,
                        logical=logical,
                        logical_types=logical_types,
                        target=target,
                        method_contract_sha256=method_sha256,
                        unit_id=extra_unit_id,
                        event_index=extra_event_index,
                        machine_event=_object(
                            extra_machine_events[extra_event_index],
                            "machine interface-method event",
                        ),
                        argument_transducers=provider.get("argument_transducers"),
                        result_projection=provider.get("result_projection"),
                    )
                except ComponentSemanticContractError as exc:
                    issue(
                        "violated",
                        "bound_interface_method_contract_invalid",
                        service_id=service.service_id,
                        detail=str(exc),
                    )
                    extra_invalid = True
                    break
                if extra_checked["call_boundary"] != checked["call_boundary"]:
                    issue(
                        "violated",
                        "bound_interface_method_events_abi_mismatch",
                        service_id=service.service_id,
                    )
                    extra_invalid = True
                    break
                extra_events.extend(extra_checked["events"])
            if extra_invalid:
                services.append(service.to_payload())
                continue
            checked["events"].extend(extra_events)
            services.append(
                {
                    "service_id": service.service_id,
                    "mediation": service.mediation,
                    "provider": checked,
                }
            )
            continue
        if provider.get("kind") != "external_call":
            services.append(service.to_payload())
            continue
        logical = logical_services.get(service.service_id)
        event_selectors = _service_event_selectors(provider)
        unit_id, event_index = event_selectors[0]
        identity = _object(provider.get("identity"), "bound external-call identity")
        target_projection = provider.get("target_projection")
        if not isinstance(event_index, int) or isinstance(event_index, bool):
            issue(
                "violated",
                "bound_external_call_event_index_invalid",
                service_id=service.service_id,
            )
            services.append(service.to_payload())
            continue
        contract_row = external_contracts.get(_external_identity_key(identity))
        if contract_row is None:
            issue(
                "incomplete",
                "bound_external_call_contract_missing",
                service_id=service.service_id,
                identity=json.loads(json.dumps(identity)),
            )
            services.append(service.to_payload())
            continue
        unit = selected.get(unit_id)
        if unit is None:
            issue(
                "violated",
                "bound_external_call_outside_component",
                service_id=service.service_id,
                unit_id=unit_id,
            )
            services.append(service.to_payload())
            continue
        machine_events = _array(
            _object(unit.get("semantics"), "machine semantics").get(
                "external_events", []
            ),
            "machine external events",
        )
        if event_index >= len(machine_events):
            issue(
                "violated",
                "bound_external_call_event_stale",
                service_id=service.service_id,
                unit_id=unit_id,
                event_index=event_index,
            )
            services.append(service.to_payload())
            continue
        machine_event = _object(machine_events[event_index], "machine external event")
        if not _external_machine_event_matches_provider(
            machine_event,
            identity=identity,
            captured_target=target_projection is not None,
        ):
            issue(
                "violated",
                "bound_external_call_identity_stale",
                service_id=service.service_id,
                unit_id=unit_id,
                event_index=event_index,
            )
            services.append(service.to_payload())
            continue
        contract = _object(
            contract_row.get("contract"), "resolved machine-import contract"
        )
        contract_payload = _object(
            contract.get("payload"), "resolved machine-import contract payload"
        )
        try:
            require_machine_import_effects(contract_payload, context="bound external call")
        except CheckedExternalSiteContractError as exc:
            issue("incomplete", "bound_external_call_effect_contract_missing",
                  service_id=service.service_id, identity=dict(identity), detail=str(exc))
            services.append(service.to_payload())
            continue
        stack_inputs = [
            _object(row, "machine external stack input")
            for row in _array(
                machine_event.get("stack_inputs", []),
                "machine external stack inputs",
            )
        ]
        expected_count = 0 if logical is None else len(logical.parameter_type_ids)
        argument_words = _external_argument_words(contract_payload)
        contract_arguments = _checked_external_stack_arguments(
            stack_inputs,
            argument_words=argument_words,
        )
        argument_transducers = provider.get("argument_transducers")
        logical_arguments = contract_arguments
        physical_arguments: list[dict[str, object]] | None = None
        argument_guards: list[dict[str, object]] = []
        writebacks: list[dict[str, object]] = []
        if argument_transducers is None:
            if argument_words != expected_count:
                issue(
                    "violated",
                    "external_call_service_argument_inventory_mismatch",
                    service_id=service.service_id,
                    expected=expected_count,
                    observed=argument_words,
                )
        else:
            try:
                (
                    logical_arguments,
                    physical_arguments,
                    argument_guards,
                    writebacks,
                ) = _checked_external_argument_transducers(
                    argument_transducers,
                    logical=logical,
                    logical_types=logical_types,
                    contract=contract,
                    contract_payload=contract_payload,
                    contract_arguments=contract_arguments,
                )
            except ComponentSemanticContractError as exc:
                issue(
                    "violated",
                    "external_call_service_argument_transducer_invalid",
                    service_id=service.service_id,
                    detail=str(exc),
                )
        if target_projection is not None:
            try:
                argument_guards.append(
                    _checked_captured_external_target_guard(
                        target_projection,
                        machine_event=machine_event,
                    )
                )
            except ComponentSemanticContractError as exc:
                issue(
                    "violated",
                    "external_call_captured_target_invalid",
                    service_id=service.service_id,
                    detail=str(exc),
                )
        result: dict[str, object] | None = None
        result_rule: dict[str, object] | None = None
        declared_result = provider.get("result_projection")
        if logical is not None and logical.result_type_id is not None:
            logical_result = logical_types[logical.result_type_id]
            if (
                isinstance(declared_result, Mapping)
                and declared_result.get("kind") == "local_cell_word"
            ):
                try:
                    result, result_rule = _checked_local_cell_result_projection(
                        declared_result,
                        logical_kind=logical_result.kind,
                        transducers=argument_transducers,
                        contract_payload=contract_payload,
                        argument_words=argument_words,
                    )
                except ComponentSemanticContractError as exc:
                    issue(
                        "violated",
                        "external_call_service_result_projection_invalid",
                        service_id=service.service_id,
                        detail=str(exc),
                    )
            else:
                if logical_result.kind == "callback":
                    accepted_relations = (
                        {"related_word"}
                        if (
                            service.mediation == "callback"
                            and contract_payload.get("callback_effect") is not None
                        )
                        else set()
                    )
                elif logical_result.kind in {"reference", "view", "resource"}:
                    # Native pointers and handles are related machine words, not
                    # portable scalar values. Their declared wrapper supplies
                    # the authority needed to interpret the word.
                    accepted_relations = {"exact", "related_word"}
                    if logical_result.kind in {"reference", "view"} and any(
                        isinstance(row, Mapping) and row.get("relation") == "dynamic_range_base"
                        for row in contract_payload.get("result_register_relations", [])
                    ):
                        try:
                            effect = checked_lifetime_effect(contract_payload, argument_words=argument_words)
                            if effect["action"] == "add_result_range":
                                accepted_relations.add("dynamic_range_base")
                        except LifetimeEffectError as exc:
                            issue("incomplete", "external_call_service_allocation_result_unsupported",
                                  service_id=service.service_id, detail=str(exc))
                else:
                    accepted_relations = {"exact"}
                    try:
                        if checked_terminated_read(contract_payload, argument_words=argument_words) is not None:
                            accepted_relations.add(TERMINATED_READ_RELATION)
                        if checked_terminated_write(contract_payload, argument_words=argument_words) is not None:
                            accepted_relations.add(WRITTEN_RELATION)
                    except ValueError as exc:
                        issue("violated", "external_call_service_result_projection_invalid",
                              service_id=service.service_id, detail=str(exc))
                relations = [
                    row
                    for row in _array(
                        contract_payload.get("result_register_relations", []),
                        "resolved result-register relations",
                    )
                    if isinstance(row, Mapping)
                    and row.get("relation") in accepted_relations
                ]
                if len(relations) != 1 or not isinstance(
                    relations[0].get("register"), str
                ):
                    issue(
                        "incomplete",
                        "external_call_service_result_unresolved",
                        service_id=service.service_id,
                    )
                else:
                    machine_result = {
                        "kind": "register",
                        "register": relations[0]["register"],
                        "width": 32,
                        "at": "call",
                    }
                    if declared_result is None:
                        if logical_result.kind in {"scalar", "enum"}:
                            result = machine_result
                        else:
                            issue(
                                "incomplete",
                                "external_call_service_result_projection_missing",
                                service_id=service.service_id,
                                logical_kind=logical_result.kind,
                            )
                    else:
                        try:
                            result_projection = _checked_external_result_projection(
                                declared_result,
                                logical_kind=logical_result.kind,
                                machine_register=str(relations[0]["register"]),
                            )
                        except ComponentSemanticContractError as exc:
                            issue(
                                "violated",
                                "external_call_service_result_projection_invalid",
                                service_id=service.service_id,
                                detail=str(exc),
                            )
                        else:
                            result = result_projection
        elif declared_result is not None:
            issue(
                "violated",
                "external_call_void_service_has_result_projection",
                service_id=service.service_id,
            )
        abi_template = contract_payload.get("abi_template")
        abi = resolve_machine_call_abi(abi_template)
        call_boundary: dict[str, object] | None = None
        if abi is None:
            issue(
                "violated",
                "external_call_service_abi_unsupported",
                service_id=service.service_id,
                abi_template=abi_template,
            )
        else:
            call_boundary = {
                "contract_id": _external_contract_id(
                    contract,
                    contract_payload,
                ),
                "abi_template": abi.template,
                "preserved_registers": list(abi.preserved_registers),
                "stack_pointer_adjustment": (
                    argument_words * 4 if abi.callee_cleanup else 0
                ),
            }
        checked_events = [
            {
                "unit_id": unit_id,
                "event_index": event_index,
                "event_sha256": canonical_sha256_v3(machine_event),
                "identity": json.loads(json.dumps(identity)),
                "arguments": json.loads(json.dumps(logical_arguments)),
                "result": result,
                **({"result_rule": result_rule} if result_rule is not None else {}),
                **(
                    {
                        "physical_arguments": json.loads(
                            json.dumps(physical_arguments or [])
                        ),
                        "argument_guards": json.loads(json.dumps(argument_guards)),
                        "writebacks": json.loads(json.dumps(writebacks)),
                    }
                    if physical_arguments is not None or argument_guards
                    else {}
                ),
            }
        ]
        extra_invalid = False
        for extra_unit_id, extra_event_index in event_selectors[1:]:
            extra_unit = selected.get(extra_unit_id)
            if extra_unit is None:
                issue(
                    "violated",
                    "bound_external_call_outside_component",
                    service_id=service.service_id,
                    unit_id=extra_unit_id,
                )
                extra_invalid = True
                break
            extra_machine_events = _array(
                _object(extra_unit.get("semantics"), "machine semantics").get(
                    "external_events", []
                ),
                "machine external events",
            )
            if extra_event_index >= len(extra_machine_events):
                issue(
                    "violated",
                    "bound_external_call_event_stale",
                    service_id=service.service_id,
                    unit_id=extra_unit_id,
                    event_index=extra_event_index,
                )
                extra_invalid = True
                break
            extra_machine_event = _object(
                extra_machine_events[extra_event_index],
                "machine external event",
            )
            if not _external_machine_event_matches_provider(
                extra_machine_event,
                identity=identity,
                captured_target=target_projection is not None,
            ):
                issue(
                    "violated",
                    "bound_external_call_identity_stale",
                    service_id=service.service_id,
                    unit_id=extra_unit_id,
                    event_index=extra_event_index,
                )
                extra_invalid = True
                break
            extra_stack_inputs = [
                _object(row, "machine external stack input")
                for row in _array(
                    extra_machine_event.get("stack_inputs", []),
                    "machine external stack inputs",
                )
            ]
            extra_contract_arguments = _checked_external_stack_arguments(
                extra_stack_inputs, argument_words=argument_words
            )
            extra_logical_arguments = extra_contract_arguments
            extra_physical_arguments: list[dict[str, object]] | None = None
            extra_argument_guards: list[dict[str, object]] = []
            extra_writebacks: list[dict[str, object]] = []
            if argument_transducers is None:
                if argument_words != expected_count:
                    issue(
                        "violated",
                        "external_call_service_argument_inventory_mismatch",
                        service_id=service.service_id,
                        expected=expected_count,
                        observed=argument_words,
                    )
            else:
                try:
                    (
                        extra_logical_arguments,
                        extra_physical_arguments,
                        extra_argument_guards,
                        extra_writebacks,
                    ) = _checked_external_argument_transducers(
                        argument_transducers,
                        logical=logical,
                        logical_types=logical_types,
                        contract=contract,
                        contract_payload=contract_payload,
                        contract_arguments=extra_contract_arguments,
                    )
                except ComponentSemanticContractError as exc:
                    issue(
                        "violated",
                        "external_call_service_argument_transducer_invalid",
                        service_id=service.service_id,
                        detail=str(exc),
                    )
            if target_projection is not None:
                try:
                    extra_argument_guards.append(
                        _checked_captured_external_target_guard(
                            target_projection,
                            machine_event=extra_machine_event,
                        )
                    )
                except ComponentSemanticContractError as exc:
                    issue(
                        "violated",
                        "external_call_captured_target_invalid",
                        service_id=service.service_id,
                        detail=str(exc),
                    )
                    extra_invalid = True
                    break
            checked_events.append(
                {
                    "unit_id": extra_unit_id,
                    "event_index": extra_event_index,
                    "event_sha256": canonical_sha256_v3(extra_machine_event),
                    "identity": json.loads(json.dumps(identity)),
                    "arguments": json.loads(json.dumps(extra_logical_arguments)),
                    "result": result,
                    **({"result_rule": result_rule} if result_rule is not None else {}),
                    **(
                        {
                            "physical_arguments": json.loads(
                                json.dumps(extra_physical_arguments or [])
                            ),
                            "argument_guards": json.loads(
                                json.dumps(extra_argument_guards)
                            ),
                            "writebacks": json.loads(json.dumps(extra_writebacks)),
                        }
                        if extra_physical_arguments is not None or extra_argument_guards
                        else {}
                    ),
                }
            )
        if extra_invalid:
            services.append(service.to_payload())
            continue
        services.append(
            {
                "service_id": service.service_id,
                "mediation": service.mediation,
                "provider": {
                    "kind": "checked_external_call_events",
                    "call_boundary": call_boundary,
                    "events": checked_events,
                },
            }
        )

    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "satisfied"
    )
    core: dict[str, object] = {
        "status": status,
        "component_id": machine_binding.identity,
        "bindings": {
            "pe_sha256": pe,
            **semantic_input_bindings,
            "interface_sha256": portable.sha256,
            "machine_binding_sha256": machine_binding.binding_sha256,
            "resolved_external_environment_sha256": resolved_environment_sha256,
            "component_resolution_sha256": (
                None
                if resolution_payload is None
                else resolution_payload.get("projection_sha256")
            ),
            "normal_call_abi_premise_sha256": (
                None
                if normal_call_premise is None
                else normal_call_premise.content_sha256
            ),
            "module_interface_sha256": (
                None
                if checked_machine_image is None
                else checked_machine_image["module_interface_sha256"]
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








































__all__ = [
    "CanonicalTransferRefinementUniverseV2",
    "ComponentSemanticContractError",
    "ProofKernelSemanticContract",
    "build_proof_kernel_semantic_contract",
    "load_transfer_v2_refinement_universe",
    "transfer_expression_view_v2",
]
