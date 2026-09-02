"""Direct V6 work-package to portable semantic-provider qualification.

This is the clean component path.  V4 contracts, V5 machine-binding receipts,
component-implementation reducers, and aggregate activation graphs are not
inputs.  The existing proof kernel and overlay renderer are reused through an
in-memory normalized view; no compatibility artifact is emitted.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.binding_intent import ComponentMachineBindingIntentV1
from ..components.component_c_v5 import render_component_c_headers_v5
from ..components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from ..components.interaction_contract import (
    InteractionContractCatalogV1,
    InteractionContractReceiptV1,
    contract_type_matches,
)
from ..components.machine_overlay_v5 import render_component_machine_overlay_v5
from ..components.normalized_component import (
    NormalizedComponentContract,
    NormalizedMachineBinding,
)
from ..components.portable_object import compile_portable_component_objects
from ..components.refinement import check_component_refinement
from ..components.refinement_v5 import (
    _check_inductive_refinement_v5,
    _compile_kernel_semantic_contract,
)
from ..components.relation_v5 import ComponentRelationIntentV1
from ..components.semantic_contract import load_transfer_v2_refinement_universe
from ..components.semantic_path_operations import _nullable_same_origin_input
from ..components.source import (
    component_operation_symbols,
    load_component_source_package,
)
from ..components.source_profile import check_component_source_profile
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..transfer.plan import load_executable_transfer_plan
from ..transfer.runtime_abi import exact_runtime_header
from ..util import sha256_file, write_json
from .encapsulated_owned import check_encapsulated_owned_admission
from .qualification_v2 import write_semantic_provider_qualification_v2
from .slices_v2 import SemanticSliceV2


class PortableCWorkPackageError(ValueError):
    """A direct portable provider is stale or cannot be qualified."""


def _fail(message: str) -> None:
    raise PortableCWorkPackageError(message)


def _load_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _direct_component_view(
    *,
    binding_intent: Path,
    interface_package: Path,
    transfer_payload: Mapping[str, Any],
    semantic_slice_sha256: str,
) -> tuple[
    object,
    NormalizedComponentContract,
    NormalizedMachineBinding,
    ComponentMachineBindingIntentV1,
]:
    """Normalize V6 directly for the existing proof/overlay kernels."""

    intent = ComponentInterfaceIntentV1.parse(
        _load_json(
            Path(interface_package) / "component-interface-intent-v1.json",
            "component interface intent",
        )
    )
    bundle = compile_component_interface_v5(intent)
    binding_model = ComponentMachineBindingIntentV1.parse(
        _load_json(
            Path(binding_intent),
            "component machine-binding intent",
        )
    )
    if binding_model.component_id != bundle.interface.identity:
        _fail("direct V6 binding names another component interface")

    semantics = []
    operation_authority: dict[str, Mapping[str, object]] = {}
    for operation in binding_model.operations:
        operation_id = operation.semantics.operation_id
        semantics.append(operation.semantics)
        operation_authority[operation_id] = {
            "object_authority_selectors": list(
                operation.authority["object_authority_selectors"]
            ),
            "pointer_views": list(operation.authority["pointer_views"]),
            "service_ids": list(operation.semantics.service_ids),
            "callback_ids": list(operation.semantics.callback_ids),
            "outcome_protocol_ids": list(operation.semantics.outcome_protocol_ids),
            # Relation and induction proofs are qualified by the direct proof
            # phase, not imported from the retired machine-binding receipt.
            "relation_receipt_sha256s": [],
            "induction_evidence_sha256": operation.authority[
                "induction_evidence_sha256"
            ],
        }
    contract = NormalizedComponentContract.create(
        interface=bundle.interface,
        machine_semantics=semantics,
    )
    transfer_bindings = transfer_payload.get("bindings")
    if not isinstance(transfer_bindings, Mapping):
        _fail("transfer-plan bindings are malformed")
    required = (
        "pe_sha256",
        "machine_ir_sha256",
        "machine_ir_manifest_sha256",
        "unit_inventory_sha256",
    )
    if any(not isinstance(transfer_bindings.get(key), str) for key in required):
        _fail("transfer plan omits a component proof binding")
    machine_binding = NormalizedMachineBinding.create(
        bundle=bundle,
        contract=contract,
        artifacts={
            "pe_sha256": str(transfer_bindings["pe_sha256"]),
            "machine_ir_sha256": str(transfer_bindings["machine_ir_sha256"]),
            "machine_ir_manifest_sha256": str(
                transfer_bindings["machine_ir_manifest_sha256"]
            ),
            "unit_inventory_sha256": str(transfer_bindings["unit_inventory_sha256"]),
            # These identities are internal normalization facts.  They bind
            # the exact V6 ownership projection rather than reviving public
            # structural-unit or component-inventory receipts.
            "structural_units_sha256": canonical_sha256_v3(
                [item.semantics.to_payload() for item in binding_model.operations]
            ),
            "component_unit_inventory_sha256": semantic_slice_sha256,
        },
        operation_authority=operation_authority,
        blockers=[dict(item) for item in binding_model.blockers],
    )
    return bundle, contract, machine_binding, binding_model


def _direct_operation_rows(
    *,
    binding: ComponentMachineBindingIntentV1,
    semantic_slice: SemanticSliceV2,
) -> list[dict[str, object]]:
    definitions = {
        str(row["symbol_id"]): str(row["definition_id"])
        for row in semantic_slice.payload["definitions"]
    }
    result = []
    for operation in binding.operations:
        semantics = operation.semantics
        definition_ids = []
        for unit_id in semantics.unit_ids:
            definition_id = definitions.get(f"original:function:{unit_id}")
            if definition_id is None:
                _fail("direct V6 semantic slice omits an owned transfer")
            definition_ids.append(definition_id)
        result.append(
            {
                "operation_id": semantics.operation_id,
                "definition_ids": sorted(definition_ids),
                "unit_ids": list(semantics.unit_ids),
                "context_transfer_ids": list(semantics.transfer_ids),
                "effect_ids": list(semantics.effect_ids),
                "service_ids": list(semantics.service_ids),
                "callback_ids": list(semantics.callback_ids),
                "outcome_protocol_ids": list(semantics.outcome_protocol_ids),
                "object_authority_selectors": list(
                    operation.authority["object_authority_selectors"]
                ),
                "pointer_views": list(operation.authority["pointer_views"]),
                "machine_projection": dict(semantics.machine_projection),
            }
        )
    if {str(item) for row in result for item in row["definition_ids"]} != {
        str(row["definition_id"]) for row in semantic_slice.payload["definitions"]
    }:
        _fail("direct V6 operation ownership is not slice-total")
    return result


def _has_callback_projection(
    operations: Sequence[Mapping[str, object]],
) -> bool:
    """Return whether the operation view imports a callable capability."""

    def contains(value: object) -> bool:
        if isinstance(value, Mapping):
            return value.get("kind") == "callback_handle" or any(
                contains(item) for item in value.values()
            )
        if isinstance(value, (list, tuple)):
            return any(contains(item) for item in value)
        return False

    return any(contains(row["machine_projection"]) for row in operations)


def _checked_callback_projection_capabilities_v2(
    *,
    operations: Sequence[Mapping[str, object]],
    linked: LinkedSemanticModuleV2,
    module_interface: Mapping[str, Any],
) -> dict[str, Mapping[str, object]]:
    """Validate constant callback projections against V2 semantic facts.

    The overlay renderer still accepts its historical, address-free capability
    lookup as an internal kernel input.  Build that lookup here from the V2
    callback effect and admitted domain instead of importing V1's partial
    code-capability registry.  The binding intent's authority ID is only a
    local projection key; it grants no authority.
    """

    loader = module_interface.get("loader")
    if not isinstance(loader, Mapping):
        _fail("module interface loader geometry is malformed")
    image_base = loader.get("preferred_base")
    if (
        not isinstance(image_base, int)
        or isinstance(image_base, bool)
        or image_base < 0
        or image_base > 0xFFFFFFFF
    ):
        _fail("module interface preferred image base is malformed")
    domains = {
        str(row["domain_sha256"]): row
        for row in linked.payload["admitted_domains"]
        if isinstance(row, Mapping) and isinstance(row.get("domain_sha256"), str)
    }
    active_by_rva: dict[int, list[Mapping[str, Any]]] = {}
    for raw in linked.payload["active_symbols"]:
        if not isinstance(raw, Mapping):
            _fail("linked semantic module active-symbol catalog is malformed")
        rva = raw.get("original_rva")
        if isinstance(rva, int) and not isinstance(rva, bool):
            active_by_rva.setdefault(rva, []).append(raw)
    effects = [
        row
        for row in linked.payload["effects"]["callbacks"]
        if isinstance(row, Mapping)
    ]
    result: dict[str, Mapping[str, object]] = {}
    for operation in operations:
        projection = operation["machine_projection"].get("operation")
        if not isinstance(projection, Mapping):
            _fail("V6 callback operation projection is malformed")
        service_bindings = operation["machine_projection"].get("service_bindings")
        if not isinstance(service_bindings, list):
            _fail("V6 callback service bindings are malformed")
        callback_services = []
        for raw_binding in service_bindings:
            if not isinstance(raw_binding, Mapping):
                _fail("V6 callback service binding is malformed")
            provider = raw_binding.get("provider")
            if (
                raw_binding.get("mediation") == "callback"
                and isinstance(provider, Mapping)
                and provider.get("kind") == "external_call"
            ):
                callback_services.append(provider)
        parameters = projection.get("parameters")
        if not isinstance(parameters, list):
            _fail("V6 callback parameter projection is malformed")
        for raw_parameter in parameters:
            if not isinstance(raw_parameter, Mapping):
                _fail("V6 callback parameter row is malformed")
            callback = raw_parameter.get("projection")
            if not isinstance(callback, Mapping) or callback.get("kind") != (
                "callback_handle"
            ):
                continue
            authority_id = callback.get("authority_id")
            protocol_id = callback.get("protocol_id")
            source = callback.get("source")
            if (
                not isinstance(authority_id, str)
                or not authority_id
                or not isinstance(protocol_id, str)
                or not protocol_id
                or not isinstance(source, Mapping)
                or source.get("kind") != "constant"
                or source.get("width") != 32
                or not isinstance(source.get("value"), int)
                or isinstance(source.get("value"), bool)
            ):
                _fail("V6 callback projection is not an exact constant handle")
            target_word = int(source["value"])
            target_rva = target_word - image_base
            if target_rva < 0 or target_rva > 0xFFFFFFFF:
                _fail("V6 callback projection lies outside the logical image")
            publication_effects = []
            for provider in callback_services:
                identity = provider.get("identity")
                if not isinstance(identity, Mapping):
                    _fail("V6 callback external identity is malformed")
                provider_events = provider.get("events")
                if (
                    not isinstance(provider_events, list)
                    or not provider_events
                    or any(not isinstance(event, Mapping) for event in provider_events)
                ):
                    _fail("V6 callback external event inventory is malformed")
                for event in provider_events:
                    matches = []
                    for effect in effects:
                        external_identity = effect.get("external_identity")
                        if (
                            effect.get("source_transfer_id") == event.get("unit_id")
                            and effect.get("call_id") == event.get("event_index")
                            and effect.get("callback_protocol_id") == protocol_id
                            and isinstance(external_identity, Mapping)
                            and str(external_identity.get("dll", "")).lower()
                            == str(identity.get("dll", "")).lower()
                            and external_identity.get("symbol")
                            == identity.get("symbol")
                            and external_identity.get("ordinal")
                            == identity.get("ordinal")
                        ):
                            matches.append(effect)
                    if len(matches) != 1:
                        _fail("V6 callback event has no unique V2 publication effect")
                    publication_effects.extend(matches)
            if not publication_effects:
                _fail("V6 callback projection has no V2 publication effect")
            for effect in publication_effects:
                domain_reference = effect.get("admitted_domain")
                if not isinstance(domain_reference, Mapping):
                    _fail("V2 callback effect has no admitted domain")
                domain = domains.get(str(domain_reference.get("domain_sha256")))
                if (
                    domain is None
                    or domain.get("kind") != "checked_callback_transfer_entry_rvas"
                    or domain.get("protocol_id") != protocol_id
                    or target_rva not in domain.get("targets", [])
                ):
                    _fail("V6 callback target is outside its checked V2 domain")
            targets = active_by_rva.get(target_rva, [])
            if len(targets) != 1 or targets[0].get("kind") != "function":
                _fail("V6 callback target is not unique active code")
            lifetimes = {effect.get("lifetime") for effect in publication_effects}
            if len(lifetimes) != 1:
                _fail("V2 callback publication lifetimes disagree")
            capability = {
                "capability_id": authority_id,
                "protocol_id": protocol_id,
                "target_rva": target_rva,
                "target_word": target_word,
                "lifetime": next(iter(lifetimes)),
            }
            previous = result.get(authority_id)
            if previous is not None and previous != capability:
                _fail("V6 callback projection authority key is ambiguous")
            result[authority_id] = capability
    return result


def _interaction_expression(
    value: Mapping[str, object],
    *,
    interaction_id: str,
) -> dict[str, object]:
    """Specialize one reviewed portable interaction expression."""

    op = value.get("op")
    if not isinstance(op, str) or not op:
        _fail("reviewed interaction expression operation is malformed")
    if op == "port":
        direction = value.get("direction")
        identity = value.get("id")
        if (
            direction not in {"input", "output"}
            or not isinstance(identity, str)
            or not identity
        ):
            _fail("reviewed interaction port expression is malformed")
        return {
            "op": "logical",
            "args": [],
            "attributes": {
                "path": {
                    "root": "interaction",
                    "id": interaction_id,
                    "fields": [direction, identity],
                }
            },
        }
    if op == "const":
        return {
            "op": "const",
            "args": [],
            "attributes": {
                "value": value.get("value"),
                "width": value.get("width"),
            },
        }
    if op in {"true", "false"}:
        return {"op": op, "args": [], "attributes": {}}
    arguments = value.get("args")
    if not isinstance(arguments, list) or any(
        not isinstance(argument, Mapping) for argument in arguments
    ):
        _fail("reviewed interaction expression arguments are malformed")
    return {
        "op": op,
        "args": [
            _interaction_expression(argument, interaction_id=interaction_id)
            for argument in arguments
        ],
        "attributes": {},
    }


def _checked_relation_boundary_operations(
    *,
    component_id: str,
    bundle: object,
    portable: object,
    semantic_contract: Mapping[str, object],
    relation_intent: Path | None,
    interaction_contract_catalog: Path | None,
) -> tuple[dict[str, Mapping[str, object]], list[Mapping[str, object]]]:
    """Bind operator relation intent to unique reviewed provider contracts.

    The intent requests a relation but grants no authority.  Authority comes
    from a unique catalog contract matching the exact machine import and the
    logical service types, followed by contextual CBMC refinement.
    """

    if relation_intent is None:
        return {}, []
    intent = ComponentRelationIntentV1.parse(
        _load_json(
            Path(relation_intent),
            "component relation intent",
        )
    )
    if (
        intent.component_id != component_id
        or intent.status != "ready_for_check"
        or intent.blockers
    ):
        _fail("component relation intent is not ready for a checked proof")
    if interaction_contract_catalog is None:
        _fail("component relation proof requires an interaction catalog")
    catalog = InteractionContractCatalogV1.parse(
        _load_json(
            Path(interaction_contract_catalog),
            "interaction contract catalog",
        )
    )

    operation_index = portable.operation_index()
    service_index = {service.identity: service for service in portable.services}
    type_index = portable.type_index()
    semantic_services = {
        str(row.get("service_id")): row
        for row in semantic_contract.get("services", [])
        if isinstance(row, Mapping)
    }
    boundary_operations: dict[str, Mapping[str, object]] = {}
    evidence: list[Mapping[str, object]] = []
    for operation in intent.operations:
        operation_id = str(operation["operation_id"])
        logical_operation = operation_index.get(operation_id)
        if logical_operation is None:
            _fail("relation intent names an unknown component operation")
        parameter_ids = {item.identity for item in logical_operation.parameters}
        interactions: list[dict[str, object]] = []
        for requirement in operation["requirements"]:
            if requirement["relation"] != "borrowed_interior_or_null":
                _fail("direct relation proof kind is unsupported")
            service_id = str(requirement["service_id"])
            service = service_index.get(service_id)
            semantic_service = semantic_services.get(service_id)
            if service is None or semantic_service is None:
                _fail("relation intent names an unbound component service")
            if str(requirement["origin_parameter_id"]) not in parameter_ids:
                _fail("relation intent origin is not an operation parameter")
            if (
                service.result_type_id is None
                or requirement["result_value_id"] != "result"
            ):
                _fail("relation intent result does not name the service result")
            provider = semantic_service.get("provider")
            if not isinstance(provider, Mapping) or provider.get("kind") != (
                "checked_external_call_events"
            ):
                _fail("relation proof currently requires a checked external service")
            events = provider.get("events")
            if (
                not isinstance(events, list)
                or len(events) != 1
                or not isinstance(events[0], Mapping)
            ):
                _fail("relation service has no unique checked machine event")
            event = events[0]
            identity = event.get("identity")
            if not isinstance(identity, Mapping):
                _fail("relation service machine identity is malformed")

            matches = []
            for contract in catalog.contracts:
                subject = contract.subject
                if (
                    subject.get("kind") != "external_import"
                    or str(subject.get("dll", "")).lower()
                    != str(identity.get("dll", "")).lower()
                    or subject.get("symbol") != identity.get("symbol")
                    or subject.get("ordinal") != identity.get("ordinal")
                ):
                    continue
                patterns = {item.identity: item for item in contract.type_parameters}
                matched_ports = True
                for port in contract.ports:
                    if port.direction == "input" and port.identity.startswith(
                        "argument."
                    ):
                        suffix = port.identity.removeprefix("argument.")
                        if not suffix.isdigit() or int(suffix) >= len(
                            service.parameter_type_ids
                        ):
                            matched_ports = False
                            break
                        logical_type_id = service.parameter_type_ids[int(suffix)]
                    elif port.direction == "output" and port.identity == "result":
                        logical_type_id = service.result_type_id
                    else:
                        matched_ports = False
                        break
                    if logical_type_id is None or not contract_type_matches(
                        patterns[port.type_parameter],
                        type_index[logical_type_id],
                        type_index,
                    ):
                        matched_ports = False
                        break
                if matched_ports:
                    matches.append(contract)
            if len(matches) != 1:
                _fail("relation service has no unique reviewed interaction contract")
            contract = matches[0]
            receipt = InteractionContractReceiptV1.create(contract)
            if not receipt.authorizing:
                _fail("relation service interaction contract is not reviewed")
            interaction_id = (
                f"service:{service_id}:{event['unit_id']}:{event['event_index']}"
            )
            ensures = [
                _interaction_expression(row, interaction_id=interaction_id)
                for row in contract.ensures
            ]
            input_index = _nullable_same_origin_input(ensures, interaction_id)
            if input_index is None:
                _fail(
                    "reviewed interaction contract omits the requested origin relation"
                )
            interactions.append(
                {
                    "id": interaction_id,
                    "contract_id": contract.identity,
                    "machine_event": {
                        "unit_id": event["unit_id"],
                        "event_index": event["event_index"],
                        "event_sha256": event["event_sha256"],
                    },
                    "invoke_action": {"clause": {"ensures": ensures}},
                }
            )
            evidence.append(
                {
                    "operation_id": operation_id,
                    "requirement_id": requirement["id"],
                    "service_id": service_id,
                    "input_argument_index": input_index,
                    "contract_id": contract.identity,
                    "contract_sha256": contract.contract_sha256,
                    "contract_receipt_sha256": receipt.receipt_sha256,
                }
            )
        boundary_operations[operation_id] = {
            "operation_id": operation_id,
            "interactions": interactions,
        }
    return boundary_operations, evidence


def write_portable_c_work_package_provider_v2(
    *,
    semantic_slice: Path,
    binding_intent: Path,
    interface_package: Path,
    source_package: Path,
    transfer_plan: Path,
    resolved_external_environment: Path,
    machine_object_authority: Path,
    host_compiler: Path,
    pe32_compiler: Path,
    nm: Path,
    cbmc: Path,
    provider_id: str,
    proof_classification: str,
    out: Path,
    linked_semantic_module: Path | None = None,
    generated_choices: Path | None = None,
    provider_entry_units: Mapping[str, str] | None = None,
    relation_intent: Path | None = None,
    induction_intent: Path | None = None,
    provider_components: Mapping[str, Mapping[str, Path]] | None = None,
    provenance_artifacts: Mapping[str, Path] | None = None,
    interaction_contract_catalog: Path | None = None,
    timeout_seconds: int = 300,
) -> dict[str, Path]:
    """Prove, compile, and qualify one direct V6 portable component."""

    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    if proof_classification not in {"machine_overlay", "encapsulated_owned"}:
        _fail("direct portable provider proof classification is unsupported")
    semantic_slice_model = SemanticSliceV2.parse(
        _load_json(
            Path(semantic_slice),
            "component semantic slice V2",
        )
    )

    transfer_path = Path(transfer_plan)
    transfer_payload, transfers = load_executable_transfer_plan(
        transfer_path,
        require_complete=False,
    )
    authority = MachineObjectAuthorityV2.parse(
        _load_json(
            Path(machine_object_authority),
            "machine object authority V2",
        )
    )
    module_interface_path = (
        Path(machine_object_authority).parent / "module-interface.json"
    )
    module_interface = Pe32ModuleInterfaceV2.load(
        module_interface_path,
        require_complete=True,
    ).payload
    transfer_bindings = transfer_payload["bindings"]
    if (
        authority.bindings.get("original_pe_sha256") != transfer_bindings["pe_sha256"]
        or authority.bindings.get("module_interface_sha256")
        != sha256_file(module_interface_path)
        or module_interface["identity"]["pe_sha256"] != transfer_bindings["pe_sha256"]
    ):
        _fail("component proof image/object bindings name another module")
    loader = module_interface["loader"]
    machine_image = {
        "image_size": loader["image_size"],
        "module_interface_sha256": module_interface["interface_sha256"],
        "pe_sha256": transfer_bindings["pe_sha256"],
        "preferred_base": loader["preferred_base"],
    }
    bundle, contract, binding, binding_model = _direct_component_view(
        binding_intent=Path(binding_intent),
        interface_package=Path(interface_package),
        transfer_payload=transfer_payload,
        semantic_slice_sha256=semantic_slice_model.identity,
    )
    if contract.status != "checked" or binding.status != "checked":
        _fail("V6 work package is not statically complete")
    operations = _direct_operation_rows(
        binding=binding_model,
        semantic_slice=semantic_slice_model,
    )
    component_id = bundle.interface.identity
    provenance_sha256s: dict[str, str] = {}
    for artifact_id, artifact_path in sorted((provenance_artifacts or {}).items()):
        if (
            not artifact_id
            or artifact_id[0].isalnum() is False
            or any(
                not (character.isalnum() or character in "._-")
                for character in artifact_id
            )
        ):
            _fail("portable provider provenance identity is malformed")
        path = Path(artifact_path)
        if not path.is_file():
            _fail("portable provider provenance artifact is not a file")
        provenance_sha256s[artifact_id] = sha256_file(path)
    qualification_input = {
        "component_id": component_id,
        "proof_classification": proof_classification,
        "semantic_slice_sha256": semantic_slice_model.identity,
        "binding_intent_sha256": binding_model.intent_sha256,
        "interface_sha256": bundle.interface.interface_sha256,
        "schema_sha256": bundle.interface.schema_sha256,
        "executable_transfer_plan_sha256": sha256_file(transfer_path),
        "module_interface_sha256": module_interface["interface_sha256"],
        "provenance_artifact_sha256s": provenance_sha256s,
        "induction_intent_sha256": (
            None if induction_intent is None else sha256_file(Path(induction_intent))
        ),
    }
    has_callback_projection = _has_callback_projection(operations)
    needs_linked_module = (
        proof_classification == "encapsulated_owned" or has_callback_projection
    )
    if needs_linked_module and linked_semantic_module is None:
        _fail("direct portable provider requires linked callback/ownership facts")
    linked = (
        None
        if linked_semantic_module is None
        else LinkedSemanticModuleV2.load(
            Path(linked_semantic_module),
            require_complete=False,
        )
    )
    if (
        linked is not None
        and linked.payload["bindings"]["executable_transfer_plan_sha256"]
        != transfer_payload["plan_sha256"]
    ):
        _fail("direct portable provider linked transfer binding is stale")
    qualification_input["linked_semantic_module_sha256"] = (
        None if linked is None else linked.identity
    )

    source_root = Path(source_package)
    source = load_component_source_package(source_root)
    if source.get("lift_unit_id") != component_id:
        _fail("component source package binds another V6 component")
    symbols = component_operation_symbols(source)
    if set(symbols) != {str(row["operation_id"]) for row in operations}:
        _fail("component source symbols disagree with the V6 binding")

    provider_entries = dict(provider_entry_units or {})
    referenced_provider_ids: set[str] = set()
    for operation in operations:
        for raw_binding in operation["machine_projection"].get("service_bindings", []):
            if not isinstance(raw_binding, Mapping):
                _fail("V6 service binding is malformed")
            provider = raw_binding.get("provider")
            if (
                isinstance(provider, Mapping)
                and provider.get("kind") == "component_operation"
            ):
                referenced_component_id = provider.get("component_id")
                if (
                    not isinstance(referenced_component_id, str)
                    or not referenced_component_id
                ):
                    _fail("V6 component-operation provider identity is malformed")
                referenced_provider_ids.add(referenced_component_id)
    missing_provider_ids = sorted(referenced_provider_ids - set(provider_entries))
    if missing_provider_ids:
        _fail(
            "V6 component-operation provider entries are missing: "
            + repr(missing_provider_ids)
        )
    provider_paths = dict(provider_components or {})
    missing_provider_views = sorted(referenced_provider_ids - set(provider_paths))
    if missing_provider_views:
        _fail(
            "V6 component-operation provider views are missing: "
            + repr(missing_provider_views)
        )
    provider_views: dict[
        str,
        tuple[object, NormalizedComponentContract, NormalizedMachineBinding],
    ] = {}
    provider_transfer_ids: set[str] = set()
    provider_view_bindings: dict[str, Mapping[str, str]] = {}
    for referenced_component_id in sorted(referenced_provider_ids):
        paths = provider_paths[referenced_component_id]
        provider_slice = SemanticSliceV2.parse(
            _load_json(
                Path(paths["semantic_slice"]),
                f"V6 provider {referenced_component_id} semantic slice",
            )
        )
        (
            provider_bundle,
            provider_contract,
            provider_binding,
            provider_binding_model,
        ) = _direct_component_view(
            binding_intent=Path(paths["binding_intent"]),
            interface_package=Path(paths["interface_package"]),
            transfer_payload=transfer_payload,
            semantic_slice_sha256=provider_slice.identity,
        )
        if (
            provider_bundle.interface.identity != referenced_component_id
            or provider_contract.status != "checked"
            or provider_binding.status != "checked"
        ):
            _fail("V6 component-operation provider view is incomplete")
        provider_views[referenced_component_id] = (
            provider_bundle,
            provider_contract,
            provider_binding,
        )
        provider_transfer_ids.update(
            unit_id
            for operation in provider_binding_model.operations
            for unit_id in operation.semantics.transfer_ids
        )
        provider_view_bindings[referenced_component_id] = {
            "semantic_slice_sha256": provider_slice.identity,
            "binding_intent_sha256": provider_binding_model.intent_sha256,
            "interface_sha256": provider_bundle.interface.interface_sha256,
        }
    qualification_input["provider_components"] = provider_view_bindings
    qualification_input_sha256 = canonical_sha256_v3(qualification_input)
    required_transfer_ids = sorted(
        {str(unit_id) for row in operations for unit_id in row["context_transfer_ids"]}
        | provider_transfer_ids
        | {provider_entries[component_id] for component_id in referenced_provider_ids}
    )
    transfer_universe = load_transfer_v2_refinement_universe(
        transfer_plan=transfer_path,
        required_unit_ids=required_transfer_ids,
    )
    portable_payload, portable, semantic_contract, service_rows = (
        _compile_kernel_semantic_contract(
            bundle=bundle,
            contract=contract,
            machine_binding=binding,
            transfer_universe=transfer_universe,
            finite_control_routes=transfer_payload["finite_control_routes"],
            resolved_external_environment=Path(resolved_external_environment),
            provider_entry_units={
                component_id: provider_entries[component_id]
                for component_id in sorted(referenced_provider_ids)
            },
            machine_image=machine_image,
        )
    )
    if induction_intent is not None and relation_intent is not None:
        _fail("direct inductive relation composition is not yet supported")
    boundary_operations, relation_evidence = _checked_relation_boundary_operations(
        component_id=component_id,
        bundle=bundle,
        portable=portable,
        semantic_contract=semantic_contract,
        relation_intent=relation_intent,
        interaction_contract_catalog=interaction_contract_catalog,
    )
    source_profile = check_component_source_profile(package=source_root)
    induction_facet = None
    induction_receipt = None
    induction_source_plan = None
    if induction_intent is None:
        proof = check_component_refinement(
            semantic_contract=semantic_contract,
            interface=portable_payload,
            source_package=source_root,
            source_profile=source_profile,
            cbmc=Path(cbmc),
            boundary_operations=boundary_operations,
            c_headers=render_component_c_headers_v5(bundle, symbols),
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
            machine_binding=binding,
            portable_payload=portable_payload,
            portable=portable,
            semantic_contract=semantic_contract,
            service_rows=service_rows,
            source_package=source_root,
            source_profile=source_profile,
            declaration_path=Path(induction_intent),
            transfer_universe=transfer_universe,
            finite_control_routes=transfer_payload["finite_control_routes"],
            cbmc=Path(cbmc),
            provider_entry_units=provider_entries,
            provider_components={},
            provider_views=provider_views,
            resolved_external_environment=Path(resolved_external_environment),
            timeout_seconds=timeout_seconds,
        )
        write_json(
            output / "induction-source-plan-v1.json",
            induction_source_plan,
        )
    proof_status = str(proof.get("status"))
    refinement_status = {
        "satisfied": "checked",
        "incomplete": "incomplete",
        "violated": "incomplete",
    }.get(proof_status)
    if refinement_status is None:
        _fail("contextual-refinement checker returned an unknown status")
    refinement_receipt = canonical_sha256_v3(
        {
            "qualification_input_sha256": qualification_input_sha256,
            "source_package_sha256": source["implementation_sha256"],
            "semantic_contract_sha256": canonical_sha256_v3(semantic_contract),
            "cbmc_sha256": sha256_file(Path(cbmc)),
            "proof": proof,
            "relation_evidence": relation_evidence,
            "induction_receipt": induction_receipt,
        }
    )

    if authority.bindings.get("original_pe_sha256") != transfer_bindings["pe_sha256"]:
        _fail("machine object authority binds another module")
    encapsulated_admission = None
    if proof_classification == "encapsulated_owned":
        assert linked is not None
        encapsulated_admission = check_encapsulated_owned_admission(
            component_id=component_id,
            proof_classification=proof_classification,
            operations=operations,
            semantic_slice=semantic_slice_model,
            qualification_input_sha256=qualification_input_sha256,
            bundle=bundle,
            linked=linked,
            transfers=transfers,
            authority=authority,
        )
        write_json(
            output / "encapsulated-owned-admission.json",
            encapsulated_admission,
        )
    resolved = _load_json(
        Path(resolved_external_environment),
        "resolved external environment",
    )
    callback_capabilities: dict[str, Mapping[str, object]] = {}
    if has_callback_projection:
        assert linked is not None and linked_semantic_module is not None
        module_interface = _load_json(
            Path(linked_semantic_module).parent / "module-interface.json",
            "linked module interface",
        )
        callback_capabilities = _checked_callback_projection_capabilities_v2(
            operations=operations,
            linked=linked,
            module_interface=module_interface,
        )
    overlay = render_component_machine_overlay_v5(
        bundle=bundle,
        contract=contract,
        operation_symbols=symbols,
        transfers=transfers,
        machine_binding=binding,
        object_authority_rule_ids=[item.identity for item in authority.rules],
        resolved_external_environment=resolved,
        code_capabilities=callback_capabilities,
        proof_classification=proof_classification,
    )
    component_output = output / "component-object"
    component_output.mkdir()
    runtime_header = exact_runtime_header()
    compile_checks, compile_status, _artifact = compile_portable_component_objects(
        source_root,
        source,
        bundle=bundle,
        operation_symbols=symbols,
        induction_source_plan=(
            None
            if induction_source_plan is None
            else output / "induction-source-plan-v1.json"
        ),
        machine_overlay=overlay,
        machine_overlay_error=None,
        runtime_header=runtime_header,
        host_compiler=Path(host_compiler),
        pe32_compiler=Path(pe32_compiler),
        output=component_output,
    )
    manifest_path = component_output / "object-manifest.json"
    if not manifest_path.is_file():
        _fail("direct portable component did not emit an object manifest")
    component_manifest = dict(
        _load_json(
            manifest_path,
            "direct portable component object manifest",
        )
    )
    original_artifact = component_manifest.pop("artifact_sha256", None)
    if original_artifact != canonical_sha256_v3(component_manifest):
        _fail("direct portable component object manifest is stale")
    component_manifest.update(
        {
            "qualification_input_sha256": qualification_input_sha256,
            "component_id": component_id,
            "proof_classification": proof_classification,
            "semantic_slice_sha256": semantic_slice_model.identity,
            "contextual_refinement_sha256": refinement_receipt,
            "induction_refinement_sha256": (
                None
                if induction_receipt is None
                else induction_receipt["receipt_sha256"]
            ),
            "encapsulated_owned_admission_sha256": (
                None
                if encapsulated_admission is None
                else encapsulated_admission["receipt_sha256"]
            ),
        }
    )
    component_manifest["artifact_sha256"] = canonical_sha256_v3(component_manifest)
    write_json(manifest_path, component_manifest)

    pe32_rows = [
        dict(row)
        for row in component_manifest["objects"]
        if row.get("compiler") == "pe32"
    ]
    if not pe32_rows:
        _fail("direct portable component has no PE32 objects")
    objects_root = output / "objects"
    objects_root.mkdir()
    source_provenance = {
        str(row["path"]): str(row["sha256"])
        for row in source.get("files", [])
        if isinstance(row, Mapping)
    }
    source_provenance.update(
        {
            Path(str(row["path"])).name: str(row["sha256"])
            for row in component_manifest["generated"]
        }
    )
    object_hashes: list[str] = []
    provider_objects = []
    for index, row in enumerate(sorted(pe32_rows, key=lambda item: item["path"])):
        source_object = component_output / str(row["path"])
        digest = sha256_file(source_object)
        if digest != row["sha256"]:
            _fail("direct portable component object binding is stale")
        destination = objects_root / f"{index:04d}-{digest[:16]}.o"
        shutil.copyfile(source_object, destination)
        source_name = str(row["source"])
        source_sha256 = source_provenance.get(source_name)
        if source_sha256 is None:
            _fail("direct portable object lacks exact source provenance")
        object_hashes.append(digest)
        provider_objects.append(
            {
                "source": f"component:{component_id}/" + source_name,
                "source_owner": "portable_c",
                "source_sha256": source_sha256,
                "object_sha256": digest,
                "path": destination.relative_to(output).as_posix(),
                "language": "precompiled-object",
            }
        )
    object_hashes = sorted(set(object_hashes))
    source_hashes = sorted(
        {
            str(source["implementation_sha256"]),
            *(str(row["sha256"]) for row in component_manifest["generated"]),
        }
    )
    provider_manifest_core = {
        "materialization": "portable-work-package-provider-v2",
        "qualification_input_sha256": qualification_input_sha256,
        "component_id": component_id,
        "proof_classification": proof_classification,
        "semantic_slice_sha256": semantic_slice_model.identity,
        "contextual_refinement_sha256": refinement_receipt,
        "induction_refinement_sha256": (
            None if induction_receipt is None else induction_receipt["receipt_sha256"]
        ),
        "encapsulated_owned_admission_sha256": (
            None
            if encapsulated_admission is None
            else encapsulated_admission["receipt_sha256"]
        ),
        "compiler_sha256": sha256_file(Path(pe32_compiler)),
        "nm_sha256": sha256_file(Path(nm)),
        "objects": provider_objects,
    }
    provider_manifest = output / "provider-object-manifest.json"
    write_json(
        provider_manifest,
        {
            **provider_manifest_core,
            "receipt_sha256": canonical_sha256_v3(provider_manifest_core),
        },
    )

    overlay_by_unit: dict[str, Mapping[str, object]] = {}
    for row in overlay.entries:
        for unit_id in row["owned_unit_ids"]:
            if unit_id in overlay_by_unit:
                _fail("direct portable overlay ownership is ambiguous")
            overlay_by_unit[str(unit_id)] = row
    definitions = []
    choices: dict[str, str] = {}
    for definition in semantic_slice_model.payload["definitions"]:
        symbol_id = str(definition["symbol_id"])
        prefix = "original:function:"
        if not symbol_id.startswith(prefix):
            _fail("direct portable slice contains a non-transfer definition")
        unit_id = symbol_id[len(prefix) :]
        overlay_row = overlay_by_unit.get(unit_id)
        if overlay_row is None:
            _fail("direct portable overlay omits a slice definition")
        definition_id = str(definition["definition_id"])
        definitions.append(
            {
                "definition_id": definition_id,
                "native_symbol": str(overlay_row["symbol"]),
                "source_sha256s": source_hashes,
                "object_sha256s": object_hashes,
            }
        )
        choices[definition_id] = provider_id

    tool_sha256s = sorted(
        {
            sha256_file(Path(host_compiler)),
            sha256_file(Path(pe32_compiler)),
            sha256_file(Path(nm)),
            sha256_file(Path(cbmc)),
        }
    )
    common_inputs = {
        "qualification_input": qualification_input_sha256,
        "source_package": str(source["implementation_sha256"]),
        "object_manifest": sha256_file(provider_manifest),
        "proof_classification": proof_classification,
        "provenance_artifact_sha256s": provenance_sha256s,
    }
    facet_status = {
        "compile": compile_status,
        "contextual_refinement": refinement_status,
        "induction": ("checked" if induction_facet is None else induction_facet.status),
        "lifecycle": "checked",
        "native_objects": "checked" if object_hashes else "incomplete",
        "object_binding": "checked",
        "ownership": "checked",
        "relations": "checked"
        if (relation_intent is None or relation_evidence)
        else "incomplete",
        "services": "checked",
        "source": "checked",
    }
    facets = [
        {
            "name": name,
            "status": facet_status[name],
            "receipt_sha256": canonical_sha256_v3(
                {
                    **common_inputs,
                    "facet": name,
                    "status": facet_status[name],
                    **(
                        {"proof_receipt_sha256": refinement_receipt}
                        if name == "contextual_refinement"
                        else {}
                    ),
                    **(
                        {"encapsulated_owned_admission": encapsulated_admission}
                        if name in {"lifecycle", "ownership"}
                        and encapsulated_admission is not None
                        else {}
                    ),
                    **({"evidence": relation_evidence} if name == "relations" else {}),
                    **({"checks": compile_checks} if name == "compile" else {}),
                }
            ),
        }
        for name in sorted(facet_status)
    ]

    qualification = output / "semantic-provider-qualification.json"
    write_semantic_provider_qualification_v2(
        semantic_slice=semantic_slice_model,
        provider_id=provider_id,
        provider_kind="qualified_portable_c",
        provider_artifact_sha256=canonical_sha256_v3(
            {
                **common_inputs,
                "contextual_refinement": refinement_receipt,
                "component_object_artifact": component_manifest["artifact_sha256"],
            }
        ),
        facets=facets,
        definition_materializations=definitions,
        tool_sha256s=tool_sha256s,
        dependencies=sorted(
            {
                *(
                    f"semantic-contract:{item}"
                    for item in semantic_slice_model.payload[
                        "dependency_contract_sha256s"
                    ]
                ),
                *(
                    f"interaction-contract:{row['contract_sha256']}"
                    for row in relation_evidence
                ),
                *(
                    f"interaction-receipt:{row['contract_receipt_sha256']}"
                    for row in relation_evidence
                ),
                *(
                    f"provider-provenance:{artifact_id}:{artifact_sha256}"
                    for artifact_id, artifact_sha256 in provenance_sha256s.items()
                ),
            }
        ),
        out=qualification,
    )
    choices_path = output / "definition-choices.json"
    write_json(choices_path, choices)
    implementation_choices = {
        "definitions": {},
        "obligations": {},
    }
    if generated_choices is not None:
        inherited = _load_json(
            Path(generated_choices),
            "generated definition choices",
        )
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in inherited.items()
        ):
            _fail("generated definition choices are malformed")
        implementation_choices["definitions"].update(inherited)
    implementation_choices["definitions"].update(choices)
    implementation_choices_path = output / "implementation-choices.json"
    write_json(implementation_choices_path, implementation_choices)
    write_json(
        output / "contextual-refinement-result.json",
        {
            "status": proof_status,
            "receipt_sha256": refinement_receipt,
            "qualification_input": qualification_input,
            "qualification_input_sha256": qualification_input_sha256,
            "source_package_sha256": source["implementation_sha256"],
            "proof": proof,
            "relation_evidence": relation_evidence,
            "induction_receipt": induction_receipt,
            "proof_classification": proof_classification,
            "encapsulated_owned_admission": encapsulated_admission,
            "policy": {"tests_authorize": False, "cbmc_required": True},
        },
    )
    return {
        "qualification": qualification,
        "definition_choices": choices_path,
        "implementation_choices": implementation_choices_path,
        "object_manifest": provider_manifest,
        "contextual_refinement": output / "contextual-refinement-result.json",
    }


__all__ = [
    "PortableCWorkPackageError",
    "write_portable_c_work_package_provider_v2",
]
