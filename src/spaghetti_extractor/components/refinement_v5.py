"""Static semantic-refinement facet for V5 portable components.

The public input and output contracts are exclusively V5/V4.  For the first
clean-cut implementation, the proven finite-path kernel is reused through an
in-memory normalized logical view; no legacy artifact is emitted or accepted.
This keeps the existing CBMC proof obligation intact while its internal model
is being renamed independently of the retired public formats.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundaryModelError
from ..boundary._canonical import array, object_
from ..semantic_link.module_v2_codec import LinkedSemanticModuleV2
from ..util import sha256_file, write_json
from .inductive_certificate import materialize_inductive_certificate
from .inductive_contract import check_inductive_operation_certificate
from .inductive_package import materialize_inductive_package
from .inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
    finalize_inductive_refinement_receipt,
)
from .inductive_refinement import check_inductive_source_refinement_artifacts
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelComponentInterface
from .interface_package_v5 import (
    CompiledComponentInterfaceV5,
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from .logical_value_types import checked_nullable_input_values, logical_value_type_uses
from .machine_binding import create_proof_kernel_machine_binding
from .machine_overlay_state_views import checked_state_view
from .normalized_component import (
    NormalizedComponentContract,
    NormalizedMachineBinding,
)
from .proof_facet import ComponentProofFacetResult
from .refinement import check_component_refinement
from .semantic_contract import (
    CanonicalTransferRefinementUniverseV2,
    build_proof_kernel_semantic_contract,
    load_transfer_v2_refinement_universe,
)
from .source import load_component_source_package
from .source_profile import check_component_source_profile


def check_component_semantic_refinement_v5(
    *,
    bundle: CompiledComponentInterfaceV5,
    contract: NormalizedComponentContract,
    machine_binding: NormalizedMachineBinding,
    source_package: Path | str,
    linked_semantic_module: Path | str,
    cbmc: Path | str,
    provider_entry_units: Mapping[str, str] | None = None,
    provider_components: Mapping[str, Mapping[str, Path | str]] | None = None,
    induction_declaration: Path | str | None = None,
    timeout_seconds: int = 300,
    out: Path | str | None = None,
) -> ComponentProofFacetResult:
    """Prove authored C against the exact machine semantics bound by V5."""

    linked = LinkedSemanticModuleV2.load(Path(linked_semantic_module))
    transfer_path = linked.require_member("transfer_plan")
    resolved_external_environment = linked.require_member(
        "resolved_external_environment"
    )
    required_transfer_ids = set(_contract_transfer_ids(contract))
    if induction_declaration is not None:
        required_transfer_ids.update(
            _provider_contract_transfer_ids(provider_components or {})
        )
    transfer_universe = load_transfer_v2_refinement_universe(
        transfer_plan=transfer_path,
        required_unit_ids=sorted(required_transfer_ids),
    )
    transfer_payload = transfer_universe.transfer_payload
    transfer_bindings = object_(
        transfer_payload.get("bindings"), "V5 transfer-plan bindings"
    )
    if (
        machine_binding.component_id != contract.component_id
        or machine_binding.contract_sha256 != contract.contract_sha256
        or machine_binding.artifacts["pe_sha256"] != transfer_bindings.get("pe_sha256")
        or machine_binding.artifacts["machine_ir_sha256"]
        != transfer_bindings.get("machine_ir_sha256")
        or machine_binding.artifacts["machine_ir_manifest_sha256"]
        != transfer_bindings.get("machine_ir_manifest_sha256")
        or machine_binding.artifacts["unit_inventory_sha256"]
        != transfer_bindings.get("unit_inventory_sha256")
    ):
        raise BoundaryModelError(
            "V5 refinement inputs bind another canonical transfer universe"
        )

    portable_payload, portable, semantic_contract, service_rows = (
        _compile_kernel_semantic_contract(
            bundle=bundle,
            contract=contract,
            machine_binding=machine_binding,
            transfer_universe=transfer_universe,
            finite_control_routes=array(
                transfer_payload.get("finite_control_routes"),
                "V5 transfer finite-control routes",
            ),
            resolved_external_environment=resolved_external_environment,
            provider_entry_units=provider_entry_units or {},
        )
    )
    source = load_component_source_package(source_package)
    if source.get("lift_unit_id") != contract.component_id:
        raise BoundaryModelError("V5 refinement source component identity is stale")

    source_profile = check_component_source_profile(package=Path(source_package))
    induction_facet: ComponentProofFacetResult | None = None
    induction_receipt: Mapping[str, object] | None = None
    induction_source_plan: Mapping[str, object] | None = None
    if induction_declaration is None:
        proof = check_component_refinement(
            semantic_contract=semantic_contract,
            interface=portable_payload,
            source_package=Path(source_package),
            source_profile=source_profile,
            cbmc=Path(cbmc),
            timeout_seconds=timeout_seconds,
        )
    else:
        (
            proof,
            induction_facet,
            induction_receipt,
            induction_source_plan,
        ) = _check_inductive_refinement_v5(
            bundle=bundle,
            contract=contract,
            machine_binding=machine_binding,
            portable_payload=portable_payload,
            portable=portable,
            semantic_contract=semantic_contract,
            service_rows=service_rows,
            source_package=Path(source_package),
            source_profile=source_profile,
            declaration_path=Path(induction_declaration),
            transfer_universe=transfer_universe,
            finite_control_routes=array(
                transfer_payload.get("finite_control_routes"),
                "V5 transfer finite-control routes",
            ),
            cbmc=Path(cbmc),
            provider_entry_units=provider_entry_units or {},
            provider_components=provider_components or {},
            resolved_external_environment=resolved_external_environment,
            timeout_seconds=timeout_seconds,
        )
    proof_status = str(proof.get("status"))
    status = {
        "satisfied": "checked",
        "incomplete": "incomplete",
        "violated": "violated",
    }.get(proof_status)
    if status is None:
        raise BoundaryModelError("V5 refinement checker returned an unknown status")
    receipt = ComponentProofFacetResult.create(
        component_id=contract.component_id,
        facet="semantic_refinement",
        status=status,
        inputs={
            "component_contract": contract.contract_sha256,
            "machine_binding": machine_binding.binding_sha256,
            "interface": bundle.interface.interface_sha256,
            "source_package": str(source["implementation_sha256"]),
            "executable_transfer_plan": sha256_file(transfer_path),
            "linked_semantic_module": linked.identity,
            "cbmc": hashlib.sha256(Path(cbmc).read_bytes()).hexdigest(),
            **(
                {}
                if resolved_external_environment is None
                or _semantic_binding_digest(
                    semantic_contract,
                    "resolved_external_environment_sha256",
                    required=False,
                )
                is None
                else {
                    "resolved_external_environment": _semantic_binding_digest(
                        semantic_contract,
                        "resolved_external_environment_sha256",
                    )
                }
            ),
            **(
                {}
                if _semantic_binding_digest(
                    semantic_contract,
                    "normal_call_abi_premise_sha256",
                    required=False,
                )
                is None
                else {
                    "normal_call_abi_premise": _semantic_binding_digest(
                        semantic_contract,
                        "normal_call_abi_premise_sha256",
                    )
                }
            ),
        },
        checks=[
            {
                "code": "cbmc_exact_machine_refinement_checked",
                "status": status,
                "proof_receipt_sha256": proof.get("receipt_sha256"),
                "operation_checks": proof.get("checks", []),
                "issues": proof.get("issues", []),
                "policy": proof.get("policy", {}),
            }
        ],
    )
    if out is not None:
        output = Path(out)
        write_json(output, receipt.to_payload())
        if induction_facet is not None:
            assert induction_receipt is not None
            assert induction_source_plan is not None
            write_json(
                output.parent / "induction-facet-v1.json", induction_facet.to_payload()
            )
            write_json(
                output.parent / "induction-refinement-receipt-v1.json",
                induction_receipt,
            )
            write_json(
                output.parent / "induction-source-plan-v1.json", induction_source_plan
            )
    return receipt


def _semantic_binding_digest(
    semantic_contract: Mapping[str, object], key: str, *, required: bool = True
) -> str | None:
    bindings = object_(
        semantic_contract.get("bindings"), "V5 semantic-contract bindings"
    )
    value = bindings.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or len(value) != 64:
        raise BoundaryModelError(
            f"V5 semantic contract does not bind required input {key!r}"
        )
    return value


def _contract_transfer_ids(
    contract: NormalizedComponentContract,
) -> tuple[str, ...]:
    identities = tuple(
        sorted(
            {
                identity
                for semantics in contract.machine_semantics
                for identity in semantics.transfer_ids
            }
        )
    )
    if not identities:
        raise BoundaryModelError("V5 component contract has no transfer semantics")
    return identities


def _provider_contract_transfer_ids(
    providers: Mapping[str, Mapping[str, Path | str]],
) -> tuple[str, ...]:
    """Select provider rows for induction before their full checked parse."""

    result: set[str] = set()
    for component_id, paths in sorted(providers.items()):
        contract_path = paths.get("contract")
        if contract_path is None:
            raise BoundaryModelError(
                f"V5 induction provider {component_id!r} has no contract"
            )
        payload = object_(
            json.loads(Path(contract_path).read_text(encoding="utf-8")),
            f"V5 induction provider {component_id} contract",
        )
        for raw_semantics in array(
            payload.get("machine_semantics"),
            f"V5 induction provider {component_id} semantics",
        ):
            semantics = object_(
                raw_semantics,
                f"V5 induction provider {component_id} operation semantics",
            )
            for raw_identity in array(
                semantics.get("transfer_ids"),
                f"V5 induction provider {component_id} transfer identities",
            ):
                if not isinstance(raw_identity, str) or not raw_identity:
                    raise BoundaryModelError(
                        "V5 induction provider transfer identity is malformed"
                    )
                result.add(raw_identity)
    return tuple(sorted(result))


def _compile_kernel_semantic_contract(
    *,
    bundle: CompiledComponentInterfaceV5,
    contract: NormalizedComponentContract,
    machine_binding: NormalizedMachineBinding,
    transfer_universe: CanonicalTransferRefinementUniverseV2,
    finite_control_routes: Sequence[object],
    resolved_external_environment: Path | str | None,
    provider_entry_units: Mapping[str, str],
    machine_image: Mapping[str, object] | None = None,
) -> tuple[
    dict[str, object],
    ProofKernelComponentInterface,
    object,
    list[Mapping[str, object]],
]:
    portable_payload = _logical_projection(bundle, contract=contract)
    portable = ProofKernelComponentInterface.parse(portable_payload)
    semantics_index = {item.operation_id: item for item in contract.machine_semantics}
    operations: list[Mapping[str, object]] = []
    service_rows: list[Mapping[str, object]] | None = None
    unit_ids: set[str] = set()
    for operation in bundle.interface.operations:
        semantics = semantics_index.get(operation.identity)
        if semantics is None:
            raise BoundaryModelError("V5 refinement contract operation is missing")
        projection = object_(
            semantics.machine_projection.get("operation"),
            f"V5 refinement operation {operation.identity}",
        )
        normalized_projection = dict(projection)
        normalized_projection.setdefault("callback_operation_ids", [])
        normalized_projection.setdefault("continuation_unit_ids", [])
        normalized_projection = _materialize_kernel_finite_control_targets(
            normalized_projection,
            finite_control_routes=finite_control_routes,
            expected_pe_sha256=machine_binding.artifacts["pe_sha256"],
            machine_image=machine_image,
        )
        operations.append(normalized_projection)
        unit_ids.update(str(item) for item in semantics.transfer_ids)
        raw_services = semantics.machine_projection.get("service_bindings", [])
        if not isinstance(raw_services, list):
            raise BoundaryModelError("V5 refinement service bindings are malformed")
        normalized_services = [
            dict(object_(item, "V5 refinement service binding"))
            for item in raw_services
        ]
        if service_rows is None:
            service_rows = normalized_services
        elif service_rows != normalized_services:
            raise BoundaryModelError(
                "V5 refinement operations disagree on the component service inventory"
            )
    normalized_services = _bind_service_event_hashes(
        service_rows or [], units=transfer_universe.units
    )
    old_binding = create_proof_kernel_machine_binding(
        id=contract.component_id,
        binary={
            "pe_sha256": machine_binding.artifacts["pe_sha256"],
            "machine_ir_sha256": transfer_universe.transfer_plan_sha256,
        },
        interface={"id": portable.identity, "sha256": portable.sha256},
        unit_ids=sorted(unit_ids),
        operations=operations,
        services=normalized_services,
    )
    semantic_contract = build_proof_kernel_semantic_contract(
        interface=portable_payload,
        binding=old_binding,
        machine_ir=transfer_universe,
        resolved_external_environment=resolved_external_environment,
        component_resolution=_component_resolution(
            component_id=contract.component_id,
            services=normalized_services,
            provider_entry_units=provider_entry_units,
        ),
        machine_image=machine_image,
        operation_unit_ids={identity: row.unit_ids for identity, row in semantics_index.items()},
    )
    return portable_payload, portable, semantic_contract, normalized_services


def _materialize_kernel_finite_control_targets(
    operation: Mapping[str, object],
    *,
    finite_control_routes: Sequence[object],
    expected_pe_sha256: str,
    machine_image: Mapping[str, object] | None,
) -> dict[str, object]:
    """Translate only transfer-plan-authorized finite targets into routes."""

    result = json.loads(json.dumps(operation))
    materialized_results: list[dict[str, object]] = []
    for raw_result in array(result.get("results"), "V5 operation results"):
        logical_result = dict(object_(raw_result, "V5 operation result"))
        projection = dict(
            object_(logical_result.get("projection"), "V5 result projection")
        )
        if projection.get("kind") != "finite_control_target":
            materialized_results.append(logical_result)
            continue
        unit_id = str(projection.get("unit_id", ""))
        route_matches = [
            object_(inventory, "V5 canonical finite-control route inventory")
            for inventory in finite_control_routes
            if isinstance(inventory, Mapping) and inventory.get("unit_id") == unit_id
        ]
        if len(route_matches) != 1:
            raise BoundaryModelError(
                "V5 finite-control target authority is absent or ambiguous"
            )
        route_inventory = route_matches[0]
        index_provenance = object_(
            route_inventory.get("index_provenance"),
            "V5 finite-control index provenance",
        )
        if index_provenance.get("kind") != "direct_index":
            raise BoundaryModelError(
                "V5 remapped finite-control selectors lack a proof model"
            )
        if route_inventory.get("pe_sha256") != expected_pe_sha256:
            raise BoundaryModelError(
                "V5 finite-control authority names another PE image"
            )
        if machine_image is not None and (
            route_inventory.get("pe_sha256") != machine_image.get("pe_sha256")
            or route_inventory.get("image_base")
            != machine_image.get("preferred_base")
            or route_inventory.get("image_size") != machine_image.get("image_size")
        ):
            raise BoundaryModelError(
                "V5 finite-control authority disagrees with the proof machine image"
            )
        declared_targets: dict[int, int] = {}
        for raw_target in array(
            projection.get("targets"), "V5 declared finite-control targets"
        ):
            target = object_(raw_target, "V5 declared finite-control target")
            target_rva = target.get("target_rva")
            logical_value = target.get("logical_value")
            if (
                not isinstance(target_rva, int)
                or isinstance(target_rva, bool)
                or not isinstance(logical_value, int)
                or isinstance(logical_value, bool)
                or target_rva in declared_targets
            ):
                raise BoundaryModelError(
                    "V5 finite-control target catalog is malformed or duplicated"
                )
            declared_targets[target_rva] = logical_value
        routes = [
            object_(item, "V5 canonical finite-control route")
            for item in array(
                route_inventory.get("routes"),
                "V5 canonical finite-control routes",
            )
        ]
        route_targets = {int(item["target_rva"]) for item in routes}
        if set(declared_targets) != route_targets:
            raise BoundaryModelError(
                "V5 finite-control targets differ from the canonical transfer plan"
            )
        projection = {
            "kind": "finite_control_target",
            "at": projection.get("at"),
            "unit_id": unit_id,
            "selector_parameter_id": projection.get("selector_parameter_id"),
            "target_inventory_sha256": str(route_inventory["route_inventory_sha256"]),
            "proof_evidence": json.loads(json.dumps(route_inventory)),
            "routes": sorted(
                (
                    {
                        "selector_value": int(route["selector_value"]),
                        "logical_value": declared_targets[int(route["target_rva"])],
                        "target_rva": int(route["target_rva"]),
                        "target_address": int(route["target_address"]),
                    }
                    for route in routes
                ),
                key=lambda item: (
                    item["selector_value"],
                    item["logical_value"],
                    item["target_rva"],
                    item["target_address"],
                ),
            ),
        }
        logical_result["projection"] = projection
        materialized_results.append(logical_result)
    result["results"] = materialized_results
    return result


def _bind_service_event_hashes(
    services: Sequence[Mapping[str, object]],
    *,
    units: Mapping[str, Mapping[str, object]],
) -> list[Mapping[str, object]]:
    """Bind V5 event selectors to exact canonical transfer call rows."""
    result: list[Mapping[str, object]] = []
    for raw_service in services:
        service = json.loads(json.dumps(raw_service))
        provider = object_(service.get("provider"), "V5 service provider")
        events = provider.get("events")
        if (
            provider.get("kind") not in {"machine_events", "component_operation"}
            or events is None
        ):
            result.append(service)
            continue
        bound_events = []
        for raw_event in array(events, "V5 service events"):
            event = dict(object_(raw_event, "V5 service event"))
            unit_id = str(event.get("unit_id", ""))
            event_index = event.get("event_index")
            unit = units.get(unit_id)
            semantics = None if unit is None else unit.get("semantics")
            external_events = (
                None
                if not isinstance(semantics, Mapping)
                else semantics.get("external_events")
            )
            if (
                not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or not isinstance(external_events, list)
                or event_index < 0
                or event_index >= len(external_events)
                or not isinstance(external_events[event_index], Mapping)
            ):
                raise BoundaryModelError(
                    "V5 service event selector is outside canonical transfer semantics"
                )
            event["event_sha256"] = canonical_sha256_v3(external_events[event_index])
            bound_events.append(event)
        provider["events"] = bound_events
        service["provider"] = provider
        result.append(service)
    return result


def _check_inductive_refinement_v5(
    *,
    bundle: CompiledComponentInterfaceV5,
    contract: NormalizedComponentContract,
    machine_binding: NormalizedMachineBinding,
    portable_payload: Mapping[str, object],
    portable: ProofKernelComponentInterface,
    semantic_contract: object,
    service_rows: Sequence[Mapping[str, object]],
    source_package: Path,
    source_profile: Mapping[str, object],
    declaration_path: Path,
    transfer_universe: CanonicalTransferRefinementUniverseV2,
    finite_control_routes: Sequence[object],
    cbmc: Path,
    provider_entry_units: Mapping[str, str],
    provider_components: Mapping[str, Mapping[str, Path | str]],
    provider_views: Mapping[
        str,
        tuple[
            CompiledComponentInterfaceV5,
            NormalizedComponentContract,
            NormalizedMachineBinding,
        ],
    ]
    | None = None,
    resolved_external_environment: Path | str | None,
    timeout_seconds: int,
) -> tuple[
    Mapping[str, object],
    ComponentProofFacetResult,
    Mapping[str, object],
    Mapping[str, object],
]:
    declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
    if not isinstance(declaration, Mapping):
        raise BoundaryModelError("V5 induction declaration must be an object")
    declaration_sha256 = canonical_sha256_v3(declaration)
    induction_bindings = {
        str(item["id"]): item.get("induction_evidence_sha256")
        for item in machine_binding.operations
    }
    if set(induction_bindings) != {
        item.identity for item in bundle.interface.operations
    }:
        raise BoundaryModelError("V5 induction operation inventory is stale")
    if any(value != declaration_sha256 for value in induction_bindings.values()):
        raise BoundaryModelError(
            "V5 machine binding does not content-bind its induction declaration"
        )

    semantic_payload = json.loads(json.dumps(semantic_contract))
    package = materialize_inductive_package(
        declaration=declaration,
        interface=portable_payload,
        semantic_contract=semantic_payload,
    )
    plan = InductiveSourcePlanV1.parse(package["source_plan"])
    operation_rows = [
        row
        for row in semantic_payload["operations"]
        if row.get("operation_id") == plan.operation_id
    ]
    if len(operation_rows) != 1:
        raise BoundaryModelError("V5 inductive operation is absent or ambiguous")
    machine = CheckedInductiveMachineReceiptV1.parse(
        package["machine_receipt"], exact_operation=operation_rows[0]
    )
    relation = InductiveCutpointRelationV1.parse(package["cutpoint_relation"])
    draft = materialize_inductive_certificate(
        proof_declaration=declaration,
        semantic_contract=semantic_payload,
        interface=portable_payload,
        source_package=source_package,
        source_plan=plan,
        machine_receipt=machine,
        cutpoint_relation=relation,
    )
    machine_references = {
        item.receipt_id: machine.to_payload()
        for item in draft.receipts
        if item.kind == "machine_semantics"
    }
    draft_check = check_inductive_operation_certificate(
        draft, receipt_payloads=machine_references
    )

    provider_declarations: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="v5-induction-providers-") as temporary:
        root = Path(temporary)
        for service in service_rows:
            provider = object_(service.get("provider"), "V5 induction provider")
            if provider.get("kind") != "component_operation":
                continue
            component_id = str(provider.get("component_id", ""))
            provider_view = (provider_views or {}).get(component_id)
            if provider_view is None:
                raise BoundaryModelError(
                    "induction provider lacks an exact normalized semantic "
                    f"view: {component_id!r}"
                )
            provider_bundle, provider_contract, provider_binding = provider_view
            provider_portable, _, provider_semantic, _ = (
                _compile_kernel_semantic_contract(
                    bundle=provider_bundle,
                    contract=provider_contract,
                    machine_binding=provider_binding,
                    transfer_universe=transfer_universe,
                    finite_control_routes=finite_control_routes,
                    resolved_external_environment=resolved_external_environment,
                    provider_entry_units=provider_entry_units,
                )
            )
            provider_root = root / component_id
            provider_root.mkdir()
            interface_path = provider_root / "interface.json"
            semantic_path = provider_root / "semantic-contract.json"
            write_json(interface_path, provider_portable)
            write_json(semantic_path, provider_semantic)
            provider_declarations[str(service["service_id"])] = {
                "component_id": component_id,
                "operation_id": str(provider["operation_id"]),
                "semantic_contract": str(semantic_path),
                "interface": str(interface_path),
            }

        source_receipt = check_inductive_source_refinement_artifacts(
            semantic_contract=semantic_payload,
            interface=portable_payload,
            source_package=source_package,
            source_profile=source_profile,
            source_plan=plan.to_payload(),
            machine_receipt=machine.to_payload(),
            cutpoint_relation=relation.to_payload(),
            certificate=draft.to_payload(),
            cbmc=cbmc,
            timeout_seconds=timeout_seconds,
            component_service_contracts=provider_declarations,
        )

    if source_receipt.get("status") == "satisfied":
        certificate = materialize_inductive_certificate(
            proof_declaration=declaration,
            semantic_contract=semantic_payload,
            interface=portable_payload,
            source_package=source_package,
            source_plan=plan,
            machine_receipt=machine,
            cutpoint_relation=relation,
            source_receipt=source_receipt,
        )
        receipts = {
            item.receipt_id: (
                machine.to_payload()
                if item.kind == "machine_semantics"
                else source_receipt
            )
            for item in certificate.receipts
        }
        certificate_check = check_inductive_operation_certificate(
            certificate, receipt_payloads=receipts
        )
    else:
        certificate = draft
        certificate_check = draft_check
    refinement = finalize_inductive_refinement_receipt(
        certificate=certificate,
        certificate_check=certificate_check,
        machine_receipt=machine,
        source_receipt=source_receipt,
    )
    status = {
        "satisfied": "checked",
        "incomplete": "incomplete",
        "violated": "violated",
    }[str(refinement["status"])]
    facet = ComponentProofFacetResult.create(
        component_id=contract.component_id,
        facet="induction",
        status=status,
        inputs={
            "component_contract": contract.contract_sha256,
            "machine_binding": machine_binding.binding_sha256,
            "induction_declaration": declaration_sha256,
            "induction_refinement": str(refinement["receipt_sha256"]),
        },
        checks=[
            {
                "code": "inductive_machine_and_source_refinement_checked",
                "status": status,
                "operation_id": plan.operation_id,
                "certificate_sha256": certificate.certificate_sha256,
                "certificate_check_sha256": certificate_check.check_sha256,
            }
        ],
    )
    proof = {
        "status": str(refinement["status"]),
        "receipt_sha256": refinement["receipt_sha256"],
        "checks": [certificate_check.to_payload()],
        "issues": refinement.get("issues", []),
        "policy": refinement.get("policy", {}),
    }
    return proof, facet, refinement, plan.to_payload()


def _logical_projection(
    bundle: CompiledComponentInterfaceV5,
    *,
    contract: NormalizedComponentContract | None = None,
) -> dict[str, object]:
    """Project canonical boundary types into the proven logical C kernel."""

    schema = bundle.intent.schema
    nullable_inputs = checked_nullable_input_values(bundle, contract)
    borrowed_views = tuple(item for item in bundle.interface.state
                           if item.initial is None and item.value.interpretation == "view")
    if contract is not None and borrowed_views:
        if (contract.interface_sha256 != bundle.interface.interface_sha256 or
                {row.operation_id for row in contract.machine_semantics} !=
                {row.identity for row in bundle.interface.operations}):
            raise BoundaryModelError("borrowed shared state requires current, total operation bindings")
        for semantics in contract.machine_semantics:
            operation = object_(semantics.machine_projection.get("operation"), "borrowed state operation")
            state_rows = {row["id"]: row for row in operation.get("state", [])}
            for item in borrowed_views:
                if item.value.identity not in state_rows:
                    raise BoundaryModelError("borrowed shared state has no operation entry binding")
                checked_state_view(bundle, item, state_rows[item.value.identity])
    type_uses, value_type_ids = logical_value_type_uses(bundle, contract)
    service_result_values = {id(value) for service in bundle.interface.services
                             for value in schema.signature_index[service.signature_id].results}
    other_values = {id(value) for operation in bundle.interface.operations
                    for value in (*schema.signature_index[operation.signature_id].parameters,
                                  *schema.signature_index[operation.signature_id].results)}
    other_values.update(id(value) for service in bundle.interface.services
                        for value in schema.signature_index[service.signature_id].parameters)
    other_values.update(id(item.value) for item in bundle.interface.state)
    types: list[dict[str, object]] = []
    resource_cell_type_ids: dict[tuple[str, str, str], str] = {}
    for signature in schema.signatures:
        for value in (*signature.parameters, *signature.results):
            if value.interpretation != "resource" or value.access == "none":
                continue
            key = (value.type_id, str(value.resource_kind), value.access)
            resource_cell_type_ids.setdefault(
                key,
                "resource_cell_"
                + canonical_sha256_v3(
                    {
                        "type_id": key[0],
                        "resource_kind": key[1],
                        "access": key[2],
                    }
                )[:16],
            )
    enum_underlyings = {
        str(item.body["underlying_type_id"])
        for item in schema.types
        if item.kind == "enum"
    }
    for type_node, values, is_bytes_view in type_uses:
        if type_node.kind in {"void", "function"}:
            continue
        if type_node.identity in enum_underlyings:
            continue
        interpretations = {str(item.interpretation) for item in values}
        if type_node.kind == "integer":
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "scalar",
                    "c_type": _integer_c_type(
                        int(type_node.body["width_bits"]),
                        bool(type_node.body["signed"]),
                    ),
                }
            )
        elif type_node.kind == "enum":
            underlying = schema.type_index[str(type_node.body["underlying_type_id"])]
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "enum",
                    "c_type": _integer_c_type(
                        int(underlying.body["width_bits"]),
                        bool(underlying.body["signed"]),
                    ),
                }
            )
        elif type_node.kind == "record":
            if any(field["bit_width"] is not None for field in type_node.body["fields"]):
                raise BoundaryModelError(
                    f"V5 refinement record {type_node.identity!r} uses bit-fields"
                )
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "record",
                    "access": "read_write",
                    "fields": [
                        {"id": str(field["id"]), "type_id": str(field["type_id"])}
                        for field in type_node.body["fields"]
                    ],
                }
            )
        elif type_node.kind == "opaque":
            sample = values[0] if values else None
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "resource",
                    "resource_kind": (
                        sample.resource_kind
                        if sample is not None and sample.resource_kind is not None
                        else "opaque_object"
                    ),
                    "ownership": "borrowed",
                }
            )
        elif type_node.kind == "pointer" and interpretations == {"callback"}:
            function = schema.type_index[str(type_node.body["pointee_type_id"])]
            sample = values[0]
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "callback",
                    "ownership": "retained"
                    if any(
                        binding.transition == "escape_callback"
                        for lifecycle in bundle.lifecycles.values()
                        for binding in lifecycle.bindings
                        if binding.path.value_id in {item.identity for item in values}
                    )
                    else "borrowed",
                    "nullable": all(item.nullable for item in values),
                    "parameter_type_ids": list(function.body["parameter_type_ids"]),
                    "result_type_id": (
                        None
                        if function.body["result_type_id"] == "unit"
                        else function.body["result_type_id"]
                    ),
                }
            )
        elif type_node.kind == "pointer" and interpretations == {"reference"}:
            sample = values[0]
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "reference",
                    "element_type_id": type_node.body["pointee_type_id"],
                    "access": sample.access,
                    "nullable": all(item.nullable for item in values),
                    "allow_one_past": False,
                    "lifetime": "origin",
                }
            )
        elif type_node.kind == "pointer" and interpretations == {"view"}:
            sample = next(
                (item for item in values if item.extent["kind"] != "none"),
                values[0],
            )
            extent = sample.extent
            nullable_input = bool(values) and all(id(value) in nullable_inputs for value in values)
            if sample.nullable and not nullable_input and (is_bytes_view or
                    any(id(value) not in service_result_values or id(value) in other_values for value in values)):
                raise BoundaryModelError(
                    f"V5 refinement view {type_node.identity!r} needs a nullable logical view contract"
                )
            if is_bytes_view:
                if extent["kind"] == "value":
                    extent_parameter_id = extent["value_id"]
                    nul_terminated = False
                elif extent["kind"] == "nul_terminated":
                    extent_parameter_id = None
                    nul_terminated = True
                else:
                    raise BoundaryModelError(
                        f"V5 refinement bytes {type_node.identity!r} lacks an exact extent"
                    )
                types.append(
                    {
                        "id": type_node.identity,
                        "kind": "bytes",
                        "access": sample.access,
                        "extent_parameter_id": extent_parameter_id,
                        "nul_terminated": nul_terminated,
                    }
                )
                continue
            if extent["kind"] == "value":
                extent_payload = {
                    "kind": "parameter",
                    "parameter_id": extent["value_id"],
                }
            elif extent["kind"] == "nul_terminated":
                extent_payload = {"kind": "nul_terminated"}
            elif extent["kind"] == "fixed":
                extent_payload = {"kind": "fixed", "elements": extent["bytes"]}
            elif extent["kind"] == "none":
                # Service schemas intentionally omit operation-local extent
                # names.  Exact event projections carry the service extent;
                # the logical C kernel needs only a non-authorizing shape.
                extent_payload = ({"kind": "origin_remainder"} if nullable_input
                                  else {"kind": "fixed", "elements": 1})
            else:
                raise BoundaryModelError(
                    f"V5 refinement view {type_node.identity!r} lacks an exact extent"
                )
            types.append(
                {
                    "id": type_node.identity,
                    "kind": "view",
                    "element_type_id": type_node.body["pointee_type_id"],
                    "access": sample.access,
                    "extent": extent_payload,
                    "ownership": "borrowed",
                    **({'nullable': True} if sample.nullable else {}),
                }
            )
        else:
            raise BoundaryModelError(
                f"V5 refinement type {type_node.identity!r} has no logical projection"
            )

    types.extend(
        {
            "id": synthetic_id,
            "kind": "resource_cell",
            "resource_kind": resource_kind,
            "ownership": "borrowed",
            "access": access,
        }
        for (_type_id, resource_kind, access), synthetic_id in sorted(
            resource_cell_type_ids.items()
        )
    )

    def logical_type_id(value: object) -> str:
        if value.interpretation == "resource" and value.access != "none":
            return resource_cell_type_ids[
                (value.type_id, str(value.resource_kind), value.access)
            ]
        return value_type_ids.get(id(value), value.type_id)

    operations = []
    for operation in bundle.interface.operations:
        signature = schema.signature_index[operation.signature_id]
        operations.append(
            {
                "id": operation.identity,
                "kind": "operation",
                "parameters": [
                    {"id": item.identity, "type_id": logical_type_id(item)}
                    for item in signature.parameters
                ],
                "results": [
                    {"id": item.identity, "type_id": logical_type_id(item)}
                    for item in signature.results
                ],
                "effect_ids": list(operation.effect_ids),
                "allowed_service_ids": list(operation.allowed_service_ids),
                "pre_states": list(operation.pre_states),
                "post_states": list(operation.post_states),
            }
        )
    effects = [
        {
            "id": item.identity,
            "kind": item.kind,
            "target_id": None if item.target is None else item.target.value_id,
            "operation": item.operation,
        }
        for item in bundle.interface.effects
    ]
    services = []
    for service in bundle.interface.services:
        signature = schema.signature_index[service.signature_id]
        services.append(
            {
                "id": service.identity,
                "parameter_type_ids": [
                    logical_type_id(item) for item in signature.parameters
                ],
                "result_type_id": (
                    None
                    if not signature.results
                    else logical_type_id(signature.results[0])
                ),
                "effect_ids": list(service.effect_ids),
            }
        )
    return {
        "id": bundle.interface.identity.replace("-", "_"),
        "types": types,
        "state": [
            {
                "id": item.value.identity,
                "type_id": logical_type_id(item.value),
                "initial": item.initial,
            }
            for item in bundle.interface.state
        ],
        "operations": operations,
        "effects": effects,
        "services": services,
        "protocol": {
            "states": list(bundle.interface.protocol_states),
            "initial_state": bundle.interface.initial_protocol_state,
        },
    }


def _component_resolution(
    *,
    component_id: str,
    services: Sequence[Mapping[str, object]],
    provider_entry_units: Mapping[str, str],
) -> dict[str, object] | None:
    component_calls = []
    for service in services:
        provider = object_(service.get("provider"), "V5 refinement service provider")
        if provider.get("kind") != "component_operation":
            continue
        target = str(provider.get("component_id", ""))
        target_unit = provider_entry_units.get(target)
        if target_unit is None:
            return None
        component_calls.append(
            {
                "target_component_id": target,
                "target_unit_id": target_unit,
            }
        )
    if not component_calls:
        return None
    core = {
        "status": "checked",
        "component_id": component_id,
        "component_calls": component_calls,
    }
    return {**core, "projection_sha256": canonical_sha256_v3(core)}


def _integer_c_type(width: int | None, signed: bool | None) -> str:
    if width not in {8, 16, 32, 64} or not isinstance(signed, bool):
        raise BoundaryModelError("V5 refinement integer layout is unsupported")
    return f"{'int' if signed else 'uint'}{width}_t"


__all__ = ["check_component_semantic_refinement_v5"]
