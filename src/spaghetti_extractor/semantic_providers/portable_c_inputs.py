"""Strict normalized inputs for direct Portable-C provider proofs."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..components.binding_intent import ComponentMachineBindingIntentV1
from ..components.formats import COMPONENT_EXACT_C_SLICE_V1_FORMAT
from ..components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from ..components.normalized_component import NormalizedComponentContract, NormalizedMachineBinding
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..util import sha256_file
from .portable_c_common import fail as _fail, load_json as _load_json
from .slices_v2 import SemanticSliceV2


def pending_local_check_requirements(*, bundle, contract, binding, binding_model, runtime_assurance):
    """Permit diagnostic checking of authored requirements, never structural errors.

    Normalization adds its own blockers for missing or inconsistent authority.
    Those must still prevent model construction. Authored blockers remain exact
    pending requirements; running the model neither assumes nor discharges them.
    """
    authored = sorted((dict(row) for row in binding_model.blockers), key=canonical_sha256_v3)
    structural = (contract.status != "checked"
        or len(binding.operations) != len(bundle.interface.operations)
        or list(binding.blockers) != authored)
    if structural or (binding.status != "checked" and (runtime_assurance is None or not authored)):
        _fail("V6 work package is not statically complete: " + repr([*contract.issues, *binding.blockers]))
    return authored


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
            # Relation and cyclic proofs are qualified by the direct proof
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
                "entry_rvas": list(semantics.entry_rvas),
                "context_transfer_ids": list(semantics.proof_context_transfer_ids),
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


def _component_proof_world_v1(
    *,
    bundle: object,
    binding_intent_sha256: str,
    machine_object_authority_sha256: str,
    checked_component_summaries_used: bool = False,
) -> dict[str, object]:
    """Describe the typed, provider-independent world quantified by CBMC."""

    interface = bundle.interface
    schema = bundle.intent.schema
    core = {
        "format": "spaghetti-extractor-component-proof-world-v1",
        "bindings": {
            "schema_sha256": schema.schema_sha256,
            "interface_sha256": interface.interface_sha256,
            "binding_intent_sha256": binding_intent_sha256,
            "machine_object_authority_sha256": machine_object_authority_sha256,
        },
        "types": [item.to_payload() for item in schema.types],
        "services": [item.to_payload() for item in interface.services],
        "memory": {
            "immutable_reads": (
                "symbolic_initial_bytes_with_checked_immutable_image_overrides"
            ),
            "mutable_state": "symbolic_initial_bytes_and_bounded_write_log",
        },
        "responses": "shared_symbolic_stream_over_separate_cloned_worlds",
        "policy": {
            "provider_behavior_summaries_used": False,
            "checked_component_summaries_used": checked_component_summaries_used,
            "out_of_boundary_calls_are_arbitrary_typed_events": True,
            "resource_lifecycle_checked": True,
            "hidden_shared_mutable_state_allowed": False,
        },
    }
    return {**core, "world_sha256": canonical_sha256_v3(core)}


def _validate_exact_c_slice(
    *,
    manifest: Mapping[str, object],
    root: Path,
    component_id: str,
    operations: Sequence[Mapping[str, object]],
    bisimulation_intent_sha256: str | None,
    executable_transfer_plan_sha256: str,
    dependency_components: Mapping[str, Mapping[str, object]],
) -> None:
    """Recheck every authority-relevant binding on a candidate exact-C slice."""

    if manifest.get("format") != COMPONENT_EXACT_C_SLICE_V1_FORMAT:
        _fail("component exact-C slice has an unsupported format")
    core = dict(manifest)
    digest = core.pop("slice_sha256", None)
    if digest != canonical_sha256_v3(core):
        _fail("component exact-C slice digest is stale")
    if manifest.get("component_id") != component_id:
        _fail("component exact-C slice names another component")
    bindings = manifest.get("bindings")
    dependency_bindings = {
        component_id: str(row["binding_intent_sha256"])
        for component_id, row in sorted(dependency_components.items())
    }
    if not isinstance(bindings, Mapping) or bindings != {
        "executable_transfer_plan_sha256": executable_transfer_plan_sha256,
        "bisimulation_intent_sha256": bisimulation_intent_sha256,
        "dependency_binding_intent_sha256s": dependency_bindings,
    }:
        _fail("component exact-C slice proof bindings are stale")
    expected_root_units = sorted(
        {
            str(unit_id)
            for operation in operations
            for unit_id in operation["unit_ids"]
        }
    )
    expected_root_context_units = sorted(
        {
            str(unit_id)
            for operation in operations
            for unit_id in operation["context_transfer_ids"]
        }
    )
    if not set(expected_root_units) <= set(expected_root_context_units):
        _fail("component exact-C root context omits owned transfers")
    expected_root_entries = sorted(
        {
            int(rva)
            for operation in operations
            for rva in operation["entry_rvas"]
        }
    )
    expected_dependencies = [
        {
            "component_id": dependency_id,
            "binding_intent_sha256": dependency_bindings[dependency_id],
            "unit_ids": sorted(str(item) for item in row["unit_ids"]),
            "entry_rvas": sorted(int(item) for item in row["entry_rvas"]),
        }
        for dependency_id, row in sorted(dependency_components.items())
    ]
    expected_units = sorted(
        set(expected_root_context_units)
        | {
            str(item)
            for row in expected_dependencies
            for item in row["unit_ids"]
        }
    )
    expected_entries = sorted(
        set(expected_root_entries)
        | {
            int(item)
            for row in expected_dependencies
            for item in row["entry_rvas"]
        }
    )
    if manifest.get("root_unit_ids") != expected_root_units:
        _fail("component exact-C slice root transfer ownership is stale")
    if manifest.get("root_context_unit_ids") != expected_root_context_units:
        _fail("component exact-C slice root proof context is stale")
    if manifest.get("root_entry_rvas") != expected_root_entries:
        _fail("component exact-C slice root entries are stale")
    if manifest.get("dependency_components") != expected_dependencies:
        _fail("component exact-C slice dependency closure is stale")
    if manifest.get("unit_ids") != expected_units:
        _fail("component exact-C slice transfer ownership is stale")
    if manifest.get("entry_rvas") != expected_entries:
        _fail("component exact-C slice entries are stale")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        _fail("component exact-C slice has no rendered files")
    seen: set[str] = set()
    for row in files:
        if not isinstance(row, Mapping):
            _fail("component exact-C slice file inventory is malformed")
        relative = row.get("path")
        digest = row.get("sha256")
        if (
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or relative in seen
            or not isinstance(digest, str)
        ):
            _fail("component exact-C slice file inventory is malformed")
        path = root / relative
        if not path.is_file() or sha256_file(path) != digest:
            _fail("component exact-C slice rendered file binding is stale")
        seen.add(relative)
    if not {"behavioral-c.h", "state-machine-runtime.h"}.issubset(seen):
        _fail("component exact-C slice omits its runtime headers")
    policy = manifest.get("policy")
    if not isinstance(policy, Mapping) or policy != {
        "exact_checked_transfers_only": True,
        "connected_component_closure_bound": True,
        "forced_labels_are_step_barriers": True,
        "production_run_semantics_preserved": True,
    }:
        _fail("component exact-C slice policy is not authorizing")
