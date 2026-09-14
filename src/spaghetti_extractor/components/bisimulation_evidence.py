"""Strict model, property-inventory, and execution evidence validation."""

from __future__ import annotations

import re
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation import ComponentBisimulationError
from .bisimulation_assurance import checked_implemented_runtime_assurance, validate_runtime_assurance_binding
from .cbmc_backend import solver_arguments
from .bisimulation_reference_authority import reference_authority_unwind_arguments
from .bisimulation_support import (
    PROOF_RELATION_WITNESS,
    PROOF_PRIVATE_STACK_ABOVE,
    PROOF_PRIVATE_STACK_BELOW,
    property_entry_function as _property_entry_function,
    property_query_order as _property_query_order,
    safety_property_groups,
    safety_group_refinement,
    ASSERTION_QUERY_STRATEGIES, ASSERTION_SINGLE_STRATEGY, authored_query_ids,
)

def _validate_model_and_shard_evidence(
    *,
    proof_plan: Mapping[str, object],
    models: Mapping[str, object],
    shard_results: Sequence[Mapping[str, object]],
    checker: Mapping[str, object] | None = None,
    runtime_assurance: Mapping[str, object] | None = None,
) -> None:
    runtime_assurance = checked_implemented_runtime_assurance(runtime_assurance)
    validate_runtime_assurance_binding(models, runtime_assurance)
    if "source_summary_contracts" in models:
        from .bisimulation_summary_contracts import validate_scalar_summary_contracts

        summary = models["source_summary_contracts"]
        if (not isinstance(summary, Mapping)
                or set(summary) != {"implementation_sha256", "source_profile_sha256", "proof_interface_sha256", "certificate"}
                or summary["implementation_sha256"] != models.get("implementation_sha256")
                or summary["source_profile_sha256"] != models.get("source_profile_sha256")
                or summary["proof_interface_sha256"] != models.get("interface_sha256")
                or not isinstance(summary["certificate"], Mapping)):
            raise ComponentBisimulationError("source summary contract bindings are stale")
        try:
            certificate = summary["certificate"]
            from .bisimulation_source_dependencies import MEMORY_POLICIES, MUTABLE_POLICIES, validate_qualified_dependencies
            from .bisimulation_shared_model import SHARED_CONTRACT_POLICY
            shared = certificate.get("policy") == SHARED_CONTRACT_POLICY
            if certificate.get("policy") in MEMORY_POLICIES or shared:
                from .bisimulation_readonly_evidence import validate_readonly_source_contracts, validate_mutable_source_contracts
                from .bisimulation_readonly_evidence import validate_shared_source_contracts

                validator = (validate_shared_source_contracts if shared else
                             validate_mutable_source_contracts if certificate["policy"] in MUTABLE_POLICIES
                             else validate_readonly_source_contracts)
                validator(certificate)
                if shared and models.get('connected_components'):
                    raise ValueError('shared auxiliary source evidence currently requires a leaf provider')
                validate_qualified_dependencies(certificate, connected=models.get('connected_components'),
                                                component_id=proof_plan.get('component_id'))
                if (certificate["source_package"]["implementation_sha256"] != summary["implementation_sha256"]
                        or certificate["source_profile"]["receipt_sha256"] != summary["source_profile_sha256"]
                        or certificate["interface_intent"]["id"] != proof_plan.get("component_id")):
                    raise ValueError("read-only source contract supplier binding is stale")
            else:
                validate_scalar_summary_contracts(certificate)
        except (ValueError, TypeError, KeyError) as error:
            raise ComponentBisimulationError(str(error)) from error
    operation_models = _mapping_rows(
        models.get("operation_models"), "contextual operation models"
    )
    connected_components = _mapping_rows(
        models.get("connected_components"), "contextual connected components"
    )
    for connected in connected_components:
        from .bisimulation_assurance import admitted_supplier_assurance
        supplier_assurance = admitted_supplier_assurance(
            (connected.get("entry_contract") or {}).get("proof_system", {}).get("proof", {}), runtime_assurance)
        validate_runtime_assurance_binding(connected, supplier_assurance)
        conditional_fields = {"assurance", "authorizing"} if supplier_assurance is not None else set()
        if supplier_assurance is not None and connected.get("qualification_sha256") is not None:
            raise ComponentBisimulationError("conditional supplier cannot supply native qualification")
        if (connected.get('entry_contract') is not None
                and connected['entry_contract']['proof_system']['proof']['models']['connected_components']
                and connected.get('summary_strategy') not in {'image-readable-body-free-v1', 'image-mutable-body-free-v1'}):
            raise ComponentBisimulationError('transitive memory composition requires a checked body-free image world')
        if connected.get("summary_strategy") == "connected-replay-v1" and connected.get("entry_contract") is None:
            raise ComponentBisimulationError("connected replay lacks checked callee entry and machine-state premises")
        if set(connected) - conditional_fields - {"entry_contract", "readable_transport_policy", "mutable_transport_policy"} != {
            "component_id",
            "binding_intent_sha256",
            "implementation_sha256",
            "source_profile_sha256",
            "qualification_sha256",
            "contextual_refinement_sha256",
            "proof_receipt_sha256",
            "machine_overlay_sha256",
            "proof_overlay_sha256",
            "trusted_adapter_lowering_receipt_sha256",
            "machine_overlay_entries_sha256",
            "summary_strategy",
            "source_summary_certificate",
        }:
            raise ComponentBisimulationError(
                "contextual connected-component binding fields differ"
            )
        for field, value in connected.items():
            if field in conditional_fields or field == "qualification_sha256" and supplier_assurance is not None:
                continue
            if field not in {
                "component_id",
                "trusted_adapter_lowering_receipt_sha256",
                "summary_strategy",
                "source_summary_certificate",
                "entry_contract",
                "readable_transport_policy",
                "mutable_transport_policy",
            }:
                _sha256(value, f"connected component {field}")
        certificate = connected["source_summary_certificate"]
        if connected["summary_strategy"] == "scalar-body-free-v1":
            from .bisimulation_summary_contracts import validate_scalar_summary_contracts

            if not isinstance(certificate, Mapping) or certificate.get("status") != "satisfied":
                raise ComponentBisimulationError("body-free scalar summary lacks a checked source contract")
            try:
                validate_scalar_summary_contracts(certificate)
            except (ValueError, TypeError, KeyError) as error:
                raise ComponentBisimulationError(str(error)) from error
        elif connected["summary_strategy"] in {"image-readable-body-free-v1", "image-mutable-body-free-v1"}:
            from .bisimulation_readable_composition import image_readable_operations

            try:
                mutable = connected["summary_strategy"] == "image-mutable-body-free-v1"
                flavor = "mutable" if mutable else "readable"
                if (certificate is not None or connected.get(flavor + "_transport_policy") != "canonical-" + flavor + "-callee-transport-v1"
                        or image_readable_operations(connected.get("entry_contract"), models, mutable=mutable) is None):
                    raise ValueError("body-free readable summary lacks checked image-world premises")
            except (ValueError, TypeError, KeyError, StopIteration, AttributeError) as error:
                raise ComponentBisimulationError(str(error)) from error
        elif connected['summary_strategy'] in {'image-shared-body-free-v1', 'image-shared-framed-body-free-v1'}:
            from .bisimulation_shared_composition import shared_boundary_operations
            try:
                if (certificate is not None or connected.get('mutable_transport_policy') != 'canonical-mutable-callee-transport-v1'
                        or shared_boundary_operations(connected.get('entry_contract'), models,
                            framed=connected['summary_strategy'] == 'image-shared-framed-body-free-v1') is None):
                    raise ValueError('body-free shared summary lacks checked image, alias, service or frame premises')
            except (ValueError, TypeError, KeyError, StopIteration, AttributeError) as error:
                raise ComponentBisimulationError(str(error)) from error
        elif connected["summary_strategy"] != "connected-replay-v1" or certificate is not None:
            raise ComponentBisimulationError("connected summary strategy is malformed")
        if connected.get("entry_contract") is not None:
            from .bisimulation_call_entry import validate_call_entry_contract

            try:
                validate_call_entry_contract(connected["entry_contract"], connected=connected, runtime_assurance=supplier_assurance)
            except (ValueError, TypeError, KeyError) as error:
                raise ComponentBisimulationError(str(error)) from error
        connected_production = connected.get("machine_overlay_sha256")
        connected_proof = connected.get("proof_overlay_sha256")
        connected_lowering = connected.get(
            "trusted_adapter_lowering_receipt_sha256"
        )
        if (
            (connected_production == connected_proof and connected_lowering is not None)
            or (connected_production != connected_proof and connected_lowering is None)
        ):
            raise ComponentBisimulationError(
                "contextual connected-component lowering binding is inconsistent"
            )
        if connected_lowering is not None:
            _sha256(
                connected_lowering,
                "connected component trusted adapter lowering receipt",
            )
    from .bisimulation_readable_composition import mutable_summary_unwind_arguments

    from .bisimulation_call_entry import call_entry_assertions

    entry_assertions = {description for connected in connected_components
                        for description in call_entry_assertions(connected)}
    from .bisimulation_readable_composition import image_readable_assertions

    readable_entry_assertions = {description for connected in connected_components
                                for description in image_readable_assertions(connected)}
    from .bisimulation_shared_composition import shared_entry_assertions
    readable_entry_assertions.update(description for connected in connected_components
                                     for description in shared_entry_assertions(connected))
    from .bisimulation_reference_transport import connected_readable_transport_assertions, connected_mutable_transport_assertions

    try:
        transport_assertions = {description for connected in connected_components
                                for description in (*connected_readable_transport_assertions(connected), *connected_mutable_transport_assertions(connected))}
    except ValueError as error:
        raise ComponentBisimulationError(str(error)) from error
    model_by_obligation: dict[tuple[str, str], Mapping[str, object]] = {}
    planned_operations = {
        str(operation["operation_id"]): operation
        for operation in _mapping_rows(proof_plan.get("operations"), "proof operations")
    }
    for operation_model in operation_models:
        validate_runtime_assurance_binding(operation_model, runtime_assurance)
        clobbers = operation_model.get("machine_clobbers", [])
        extra_fields = {"machine_clobbers", "machine_result_registers"} if clobbers else set()
        if runtime_assurance is not None:
            extra_fields.update({"assurance", "authorizing"})
        from .bisimulation_allocation_cuts import validate_history_model
        from .bisimulation_local_views import validate_local_view_model
        from .bisimulation_stack_scope import validate_scope_model
        from .bisimulation_projection import validate_machine_fact_model
        from .bisimulation_memory_facts import validate_model as validate_memory_fact_model
        try:
            extra_fields.update(validate_machine_fact_model(
                planned_operations[operation_model["operation_id"]], operation_model))
            extra_fields.update(validate_scope_model(
                planned_operations[operation_model["operation_id"]], operation_model))
            extra_fields.update(validate_history_model(
                planned_operations[operation_model["operation_id"]], operation_model))
            extra_fields.update(validate_memory_fact_model(
                planned_operations[operation_model["operation_id"]], operation_model))
            extra_fields.update(validate_local_view_model(
                planned_operations[operation_model["operation_id"]], operation_model))
        except (ValueError, KeyError, TypeError) as error:
            raise ComponentBisimulationError(f"invalid allocation history: {error}") from error
        private_accesses = operation_model.get("private_stack_accesses")
        if "private_stack_accesses" in operation_model:
            extra_fields.add("private_stack_accesses")
        if "reference_origin_capacity" in operation_model:
            extra_fields.add("reference_origin_capacity")
        private_writes = operation_model.get("private_stack_writes", [])
        if private_writes:
            extra_fields.add("private_stack_writes")
        if set(operation_model) != {
            "operation_id",
            "exact_entry_rva",
            "overlay_symbol",
            "machine_image",
            "shards",
            "obligation_models",
        } | extra_fields:
            raise ComponentBisimulationError(
                "contextual operation model fields differ"
            )
        operation_id = str(operation_model.get("operation_id", ""))
        from .bisimulation_image_frame import parse_accesses
        try:
            if "private_stack_accesses" in operation_model and private_accesses is None:
                raise ValueError("private access footprint must be an explicit range list")
            parse_accesses(private_accesses)
        except ValueError as error:
            raise ComponentBisimulationError(str(error)) from error
        if (private_accesses != planned_operations[operation_id].get("private_stack_accesses")
                or ("private_stack_accesses" in operation_model)
                != ("private_stack_accesses" in planned_operations[operation_id])):
            raise ComponentBisimulationError("private access footprint differs from the proof plan")
        from .bisimulation_private_frame import parse_stack_writes
        if private_writes != planned_operations[operation_id].get("private_stack_writes", []):
            raise ComponentBisimulationError("private stack frame differs from the proof plan")
        try:
            parse_stack_writes(private_writes)
        except ValueError as error:
            raise ComponentBisimulationError(str(error)) from error
        if clobbers != planned_operations[operation_id].get("machine_clobbers", []):
            raise ComponentBisimulationError("clobber frame differs from the proof plan")
        if clobbers:
            from .bisimulation_clobber_frame import clobber_specs
            try:
                clobber_specs(clobbers, operation_model["machine_result_registers"])
            except ValueError as error:
                raise ComponentBisimulationError(str(error)) from error
        machine_image = operation_model.get("machine_image")
        if not isinstance(machine_image, Mapping):
            raise ComponentBisimulationError(
                "contextual operation model omits its checked machine image"
            )
        preferred_base = machine_image.get("preferred_base")
        image_size = machine_image.get("image_size")
        if (
            not isinstance(preferred_base, int)
            or isinstance(preferred_base, bool)
            or not isinstance(image_size, int)
            or isinstance(image_size, bool)
            or preferred_base < 0
            or image_size <= 0
            or preferred_base + image_size > 0x100000000
        ):
            raise ComponentBisimulationError(
                "contextual operation model has a malformed machine image"
            )
        operation_obligation_models = _mapping_rows(
            operation_model.get("obligation_models"),
            "contextual obligation models",
        )
        from .bisimulation_reference_origins import validate_capacity_binding
        try:
            validate_capacity_binding(operation_model, planned_operations[operation_id])
        except ValueError as error:
            raise ComponentBisimulationError(str(error)) from error
        if (
            not isinstance(operation_model.get("exact_entry_rva"), int)
            or isinstance(operation_model.get("exact_entry_rva"), bool)
            or int(operation_model["exact_entry_rva"]) < 0
            or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*",
                str(operation_model.get("overlay_symbol", "")),
            ) is None
            or operation_model.get("shards") != len(operation_obligation_models)
        ):
            raise ComponentBisimulationError(
                "contextual operation model inventory is malformed"
            )
        for model in operation_obligation_models:
            validate_runtime_assurance_binding(model, runtime_assurance)
            try:
                validate_machine_fact_model(planned_operations[operation_id], model)
                validate_scope_model(planned_operations[operation_id], model)
                validate_history_model(planned_operations[operation_id], model)
                validate_memory_fact_model(planned_operations[operation_id], model)
                validate_local_view_model(planned_operations[operation_id], model)
            except (ValueError, KeyError, TypeError) as error:
                raise ComponentBisimulationError(f"invalid segment allocation history: {error}") from error
            if ("private_stack_accesses" in model) != ("private_stack_accesses" in operation_model):
                raise ComponentBisimulationError("segment private access footprint differs from its operation")
            if any(model.get(field) != operation_model.get(field) for field in ("machine_clobbers", "machine_result_registers", "private_stack_writes", "private_stack_accesses")):
                raise ComponentBisimulationError("segment clobber frame differs from its operation")
            obligation_id = str(model.get("obligation_id", ""))
            key = (operation_id, obligation_id)
            if key in model_by_obligation:
                raise ComponentBisimulationError(
                    "contextual obligation model is duplicated"
                )
            _sha256(model.get("model_sha256"), "exact obligation model")
            _sha256(model.get("proof_model_sha256"), "proof obligation model")
            model_core_fields = (
                {
                    "scope",
                    "start_unit_id",
                    "selected_unit_ids",
                    "selected_unit_count",
                    "files",
                    "files_sha256",
                }
                if model.get("scope") == "cutpoint_segment"
                else {
                    "scope",
                    "start_unit_id",
                    "selected_unit_ids",
                    "selected_unit_count",
                    "files_sha256",
                }
            )
            if (
                not model_core_fields <= set(model)
                or model.get("model_sha256")
                != canonical_sha256_v3(
                    {field: model[field] for field in model_core_fields}
                )
            ):
                raise ComponentBisimulationError(
                    "contextual exact obligation model is stale"
                )
            exact_stack_accesses = model.get("exact_stack_accesses")
            local_bounds = model.get("model_bounds")
            if (
                not isinstance(exact_stack_accesses, list)
                or any(
                    not isinstance(access, Mapping)
                    or set(access) != {"offset", "width"}
                    or not isinstance(access.get("offset"), int)
                    or isinstance(access.get("offset"), bool)
                    or not isinstance(access.get("width"), int)
                    or isinstance(access.get("width"), bool)
                    or int(access.get("width", 0)) not in {1, 2, 3, 4}
                    or int(access.get("offset", 0)) < -PROOF_PRIVATE_STACK_BELOW
                    or int(access.get("offset", 0))
                    + int(access.get("width", 0))
                    > PROOF_PRIVATE_STACK_ABOVE
                    for access in exact_stack_accesses
                )
                or exact_stack_accesses
                != sorted(
                    exact_stack_accesses,
                    key=lambda access: (
                        int(access["offset"]), int(access["width"])
                    ),
                )
                or not isinstance(local_bounds, Mapping)
                or set(local_bounds)
                != {
                    "static_byte_write_upper_bound",
                    "static_memory_write_call_upper_bound",
                    "declared_public_memory_write_call_upper_bound",
                    "maximum_calls",
                    "maximum_atomics",
                    "exact_stack_cached_accesses",
                    "exact_stack_cached_bytes",
                }
                or local_bounds.get("exact_stack_cached_accesses")
                != len(exact_stack_accesses)
                or local_bounds.get("exact_stack_cached_bytes")
                != len(
                    {
                        int(access["offset"]) + byte
                        for access in exact_stack_accesses
                        for byte in range(int(access["width"]))
                    }
                )
            ):
                raise ComponentBisimulationError(
                    "contextual exact stack-cache inventory is malformed"
                )
            proof_function = model.get("proof_function")
            nonvacuity_function = model.get("nonvacuity_function")
            witness_functions = model.get("witness_functions")
            required_assertion_descriptions = model.get(
                "required_assertion_descriptions"
            )
            if (
                not isinstance(proof_function, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", proof_function) is None
                or nonvacuity_function != f"{proof_function}_relation"
                or not isinstance(witness_functions, list)
                or not witness_functions
                or witness_functions != sorted(set(witness_functions))
                or not isinstance(required_assertion_descriptions, list)
                or not required_assertion_descriptions
                or required_assertion_descriptions
                != sorted(set(required_assertion_descriptions))
                or any(
                    not isinstance(item, str) or not item
                    for item in required_assertion_descriptions
                )
                or model.get("required_assertion_descriptions_sha256")
                != canonical_sha256_v3(required_assertion_descriptions)
                or any(
                    not isinstance(item, str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", item) is None
                    for item in witness_functions
                )
            ):
                raise ComponentBisimulationError(
                    "contextual obligation model has no proof function"
                )
            if entry_assertions != {item for item in required_assertion_descriptions
                                    if item.startswith(("spx-bisimulation-connected-callee-stack-entry:", "spx-bisimulation-connected-callee-machine-state:", "spx-bisimulation-connected-callee-clobber-state:", "spx-bisimulation-connected-callee-private-poststate:"))}:
                raise ComponentBisimulationError("contextual obligation lacks callee entry or machine-state assertions")
            if transport_assertions != {item for item in required_assertion_descriptions
                    if item.startswith(("spx-bisimulation-connected-summary-readable-", "spx-bisimulation-connected-summary-mutable-"))}:
                raise ComponentBisimulationError("contextual obligation lacks canonical readable transport assertions")
            if readable_entry_assertions != {item for item in required_assertion_descriptions
                    if item.startswith(("spx-bisimulation-connected-readable-entry:", "spx-bisimulation-connected-mutable-entry:", "spx-bisimulation-connected-shared-entry:"))}:
                raise ComponentBisimulationError("contextual obligation lacks readable callee world assertions")
            call_memory_assertions = {
                item.replace("spx-bisimulation-typed-call-fields:",
                             "spx-bisimulation-typed-call-public-memory:", 1)
                for item in required_assertion_descriptions
                if item.startswith("spx-bisimulation-typed-call-fields:")
            }
            if not call_memory_assertions <= set(required_assertion_descriptions):
                raise ComponentBisimulationError(
                    "contextual obligation lacks call memory snapshot assertions"
                )
            finite_route_inventory = model.get(
                "finite_control_route_inventory_sha256"
            )
            if finite_route_inventory is None:
                if witness_functions != [PROOF_RELATION_WITNESS]:
                    raise ComponentBisimulationError(
                        "contextual ordinary completion witness inventory is stale"
                    )
            elif (
                not isinstance(finite_route_inventory, str)
                or re.fullmatch(r"[0-9a-f]{64}", finite_route_inventory) is None
                or any(
                    re.fullmatch(r"spx_finite_control_route_[0-9]{4}", item)
                    is None
                    for item in witness_functions
                )
            ):
                raise ComponentBisimulationError(
                    "contextual finite-control witness inventory is stale"
                )
            proof_inputs = model.get("proof_inputs")
            nonvacuity_proof_inputs = model.get("nonvacuity_proof_inputs")
            connected_required = bool(connected_components)
            allowed_roles = {
                "exact_c",
                "source_c",
                "portable_reference_runtime_c",
                "connected_provider_c",
                "production_overlay_c",
                "trusted_proof_overlay_c",
                "proof_header",
                "reference_authority",
                "allocation_class_requirements",
                "source_cut_storage_inventory",
                "source_parameter_binding_inventory",
                "harness",
            }
            if runtime_assurance is not None:
                allowed_roles.add("runtime_assurance")
            if (
                not isinstance(proof_inputs, list)
                or not proof_inputs
                or any(
                    not isinstance(row, Mapping)
                    or set(row) != {"role", "sha256"}
                    or not isinstance(row.get("role"), str)
                    or row.get("role") not in allowed_roles
                    or re.fullmatch(
                        r"[0-9a-f]{64}", str(row.get("sha256", ""))
                    ) is None
                    for row in proof_inputs
                )
                or model.get("proof_model_sha256")
                != canonical_sha256_v3(proof_inputs)
            ):
                raise ComponentBisimulationError(
                    "contextual proof input inventory is stale"
                )
            assurance_inputs = [row for row in proof_inputs if row["role"] == "runtime_assurance"]
            expected_assurance_inputs = ([] if runtime_assurance is None else [
                {"role": "runtime_assurance", "sha256": canonical_sha256_v3(runtime_assurance)}])
            if assurance_inputs != expected_assurance_inputs:
                raise ComponentBisimulationError("conditional runtime assurance proof input differs")
            for role in ("source_cut_storage_inventory", "source_parameter_binding_inventory"):
                if sum(row["role"] == role for row in proof_inputs) != (
                    1 if planned_operations[str(operation_model["operation_id"])]["source"]["syncs"] else 0
                ):
                    raise ComponentBisimulationError(
                        f"contextual proof lacks the source cut storage inventory role {role}"
                    )
            if (
                not isinstance(nonvacuity_proof_inputs, list)
                or not nonvacuity_proof_inputs
                or nonvacuity_proof_inputs != proof_inputs
                or model.get("nonvacuity_proof_model_sha256")
                != model.get("proof_model_sha256")
            ):
                raise ComponentBisimulationError(
                    "contextual nonvacuity proof input inventory is stale"
                )
            property_checker_command = model.get("property_checker_command")
            recorded_assertion_arguments = (property_checker_command.get("assertion_arguments")
                if isinstance(property_checker_command, Mapping) else None)
            # Both encodings preserve the same theorem. Infer this one option
            # from the recorded query, then require the entire property/safety/
            # witness command family to match it exactly. Old completed proofs
            # remain valid; query reuse still requires identical actual options.
            checked_solver_arguments = solver_arguments(
                None if checker is None else checker.get("smt_solver"),
                array_field_sensitive=not (isinstance(recorded_assertion_arguments, list)
                    and "--no-array-field-sensitivity" in recorded_assertion_arguments))
            nonvacuity_checker_command = model.get(
                "nonvacuity_checker_command"
            )
            from .bisimulation import parse_source_unwind_limit
            source_plan = planned_operations[operation_id]["source"]
            unwind = str(parse_source_unwind_limit(source_plan["source_unwind_limit"])) if "source_unwind_limit" in source_plan else "2"
            progress_arguments = ["--no-self-loops-to-assumptions"] if "source_unwind_limit" in source_plan else []
            authority_unwind_arguments = mutable_summary_unwind_arguments(connected_components,
                reference_authority_unwind_arguments(models.get("reference_authority"),
                    allocation_capacity=local_bounds["maximum_calls"] +
                        operation_model.get("maximum_input_allocations", 0)))
            property_common_arguments = [
                "--json-ui",
                "--trace",
                "--stop-on-fail",
                "--function",
                "$PROPERTY_FUNCTION",
                "--symex-cache-dereferences",
                "--object-bits",
                "12",
                *checked_solver_arguments,
                "--unwind",
                unwind,
                *progress_arguments,
                *authority_unwind_arguments,
                "--unwinding-assertions",
                "--reachability-slice-fb",
                "--slice-formula",
            ]
            language_safety_common_arguments = [
                "--json-ui",
                "--trace",
                "--stop-on-fail",
                "--function",
                "$PROPERTY_FUNCTION",
                "--no-unwinding-assertions",
                "--no-assertions",
                "--symex-cache-dereferences",
                "--object-bits",
                "12",
                *checked_solver_arguments,
                "--unwind",
                unwind,
                *progress_arguments,
                *authority_unwind_arguments,
                "--reachability-slice-fb",
                "--slice-formula",
            ]
            expected_property_command = {
                **({"smt_solver": checker["smt_solver"]} if checker is not None and "smt_solver" in checker else {}),
                "backend": "cbmc",
                "goto_model_role": "shared_partitioned_property_queries",
                "strategy": (property_checker_command.get('strategy')
                    if isinstance(property_checker_command, Mapping)
                    and property_checker_command.get('strategy') in ASSERTION_QUERY_STRATEGIES
                    else ASSERTION_SINGLE_STRATEGY),
                "maximum_parallel_queries": 4,
                "discovery_arguments": [
                    "--json-ui",
                    "--function",
                    "$PROPERTY_FUNCTION",
                    "--reachability-slice-fb",
                    "--show-properties",
                ],
                "language_safety_discovery_arguments": [
                    "--json-ui",
                    "--function",
                    "$PROPERTY_FUNCTION",
                    "--no-assertions",
                    "--unwind",
                    unwind,
                    *progress_arguments,
                    *authority_unwind_arguments,
                    "--reachability-slice-fb",
                    "--show-properties",
                ],
                "language_safety_baseline_discovery_arguments": [
                    "--json-ui",
                    "--function",
                    "$PROPERTY_FUNCTION",
                    "--no-standard-checks",
                    "--no-assertions",
                    "--unwind",
                    unwind,
                    *progress_arguments,
                    *authority_unwind_arguments,
                    "--show-properties",
                ],
                "loop_discovery_arguments": [
                    "--json-ui",
                    "--function",
                    "$PROPERTY_FUNCTION",
                    "--show-loops",
                ],
                "entry_assertion_arguments": [
                    *("--no-unwinding-assertions" if item == "--unwinding-assertions" else item
                      for item in property_common_arguments),
                    "--no-standard-checks", "--property", "$PROPERTY_ID",
                ],
                "assertion_arguments": [
                    *property_common_arguments,
                    "--no-standard-checks",
                    "--property",
                    "$PROPERTY_ID",
                ],
                "language_safety_queries": [
                    {
                        "partition": "bounds",
                        "classes": ["array bounds"],
                        "arguments": [
                            *language_safety_common_arguments,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "pointer",
                        "classes": [
                            "pointer",
                            "pointer arithmetic",
                            "pointer dereference",
                            "pointer primitives",
                        ],
                        "arguments": [
                            *language_safety_common_arguments,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "division",
                        "classes": ["division-by-zero"],
                        "arguments": [
                            *language_safety_common_arguments,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "signed_overflow",
                        "classes": ["overflow"],
                        "arguments": [
                            *language_safety_common_arguments,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "undefined_shift",
                        "classes": ["undefined-shift"],
                        "arguments": [
                            *language_safety_common_arguments,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "unwinding",
                        "classes": ["unwind"],
                        "arguments": [
                            *(
                                item
                                for item in language_safety_common_arguments
                                if item not in {"--reachability-slice-fb", "--no-unwinding-assertions"}
                            ),
                            "--no-standard-checks",
                            "--unwinding-assertions",
                        ],
                    },
                ],
            }
            nonvacuity_base_arguments = [
                "--json-ui",
                "--function",
                nonvacuity_function,
                "--no-assertions",
                "--cover",
                "cover",
                "--symex-cache-dereferences",
                "--object-bits",
                "12",
                *checked_solver_arguments,
                "--unwind",
                unwind,
                *progress_arguments,
                *authority_unwind_arguments,
            ]
            expected_nx_queries = (
                [
                    {
                        "functions": [function],
                        "arguments": [
                            *nonvacuity_base_arguments,
                            "--property",
                            f"{function}.coverage.1",
                            "--reachability-slice-fb",
                            "--slice-formula",
                        ],
                    }
                    for function in witness_functions
                ]
                if len(witness_functions) <= 2
                else [{
                    "functions": witness_functions,
                    "arguments": [
                        *nonvacuity_base_arguments,
                        *(argument for function in witness_functions
                          for argument in ("--property", f"{function}.coverage.1")),
                        "--reachability-slice-fb",
                        "--slice-formula",
                    ],
                }]
            )
            expected_nx_command = {
                "backend": "cbmc",
                "goto_model_role": "shared_property_and_relation",
                "strategy": (
                    "per_goal_formula_sliced_v1"
                    if len(witness_functions) <= 2
                    else "aggregate_formula_sliced_v1"
                ),
                "queries": expected_nx_queries,
            }
            if (
                property_checker_command != expected_property_command
                or model.get("property_checker_command_sha256")
                != canonical_sha256_v3(property_checker_command)
            ):
                raise ComponentBisimulationError(
                    "contextual property checker command binding is stale"
                )
            if (
                nonvacuity_checker_command != expected_nx_command
                or model.get("nonvacuity_checker_command_sha256")
                != canonical_sha256_v3(nonvacuity_checker_command)
            ):
                raise ComponentBisimulationError(
                    "contextual nonvacuity checker command binding is stale"
                )
            inputs_by_role = {
                role: [
                    row
                    for row in proof_inputs
                    if row.get("role") == role
                ]
                for role in allowed_roles
            }
            authority_input = models.get("reference_authority")
            expected_authority_inputs = ([] if authority_input is None else [{
                "role": "reference_authority", "sha256": authority_input["authority_sha256"]}])
            if inputs_by_role["reference_authority"] != expected_authority_inputs:
                raise ComponentBisimulationError("contextual native reference authority input is missing or stale")
            requirements = models.get('reference_allocation_requirements')
            expected_class_inputs = ([] if requirements is None else [{
                'role': 'allocation_class_requirements', 'sha256': canonical_sha256_v3(requirements)}])
            if inputs_by_role['allocation_class_requirements'] != expected_class_inputs:
                raise ComponentBisimulationError('contextual allocation class requirement input is missing or stale')
            trusted_lowering = models.get("trusted_adapter_lowering") is not None
            active_overlay_role = (
                "trusted_proof_overlay_c"
                if trusted_lowering
                else "production_overlay_c"
            )
            inactive_overlay_role = (
                "production_overlay_c"
                if trusted_lowering
                else "trusted_proof_overlay_c"
            )
            if (
                any(
                    not inputs_by_role[role]
                    for role in ("exact_c", "source_c")
                )
                or any(
                    len(inputs_by_role[role]) != 1
                    for role in (
                        active_overlay_role,
                        "proof_header",
                        "harness",
                    )
                )
                or inputs_by_role[inactive_overlay_role]
                or bool(inputs_by_role["connected_provider_c"])
                is not connected_required
                or any(
                    sum(
                        row["sha256"] == connected["proof_overlay_sha256"]
                        for row in inputs_by_role["connected_provider_c"]
                    )
                    != 1
                    for connected in connected_components
                )
                or inputs_by_role[active_overlay_role][0]["sha256"]
                != models.get(
                    "proof_overlay_sha256"
                    if trusted_lowering
                    else "machine_overlay_sha256"
                )
            ):
                raise ComponentBisimulationError(
                    "contextual proof input roles are incomplete or unbound"
                )
            model_by_obligation[key] = model
    expected_rows = {
        (str(operation["operation_id"]), str(obligation["id"])): obligation
        for operation in _mapping_rows(
            proof_plan.get("operations"), "contextual proof operations"
        )
        for obligation in _mapping_rows(
            operation.get("obligations"), "contextual proof obligations"
        )
    }
    continuation_by_operation = {
        str(operation["operation_id"]): operation.get("continuation")
        for operation in _mapping_rows(proof_plan.get("operations"), "contextual proof operations")
    }
    parameter_exits_by_operation = {
        str(operation['operation_id']): operation.get('parameter_exit_projections', [])
        for operation in _mapping_rows(proof_plan.get('operations'), 'contextual proof operations')
    }
    expected = set(expected_rows)
    if set(model_by_obligation) != expected:
        raise ComponentBisimulationError(
            "contextual obligation model coverage is incomplete"
        )
    for key, model in model_by_obligation.items():
        from .machine_overlay_result_views import validate_parameter_exit_model
        try:
            validate_parameter_exit_model(parameter_exits_by_operation[key[0]], model)
        except (ValueError, TypeError, KeyError) as error:
            raise ComponentBisimulationError(str(error)) from error
        from .bisimulation_runtime_dispatch import required_dispatch_assertions
        if not required_dispatch_assertions(runtime_assurance) <= set(model["required_assertion_descriptions"]):
            raise ComponentBisimulationError("conditional runtime dispatch applicability check is missing")
        continuation = continuation_by_operation[key[0]]
        if model.get("continuation") != continuation:
            raise ComponentBisimulationError("contextual continuation model differs from its proof plan")
        if continuation is not None:
            from .bisimulation_continuation import continuation_assertions
            if (not set(continuation["unit_ids"]) <= set(model["selected_unit_ids"])
                    or not set(continuation_assertions(key[0], model["proof_function"]))
                    <= set(model["required_assertion_descriptions"])):
                raise ComponentBisimulationError("contextual continuation coverage or checks are missing")
        if f"spx-bisimulation-exit-continuation-state:{key[0]}:{model['proof_function']}" not in model["required_assertion_descriptions"]:
            raise ComponentBisimulationError("contextual continuation state check is missing")
        for kind in ("shared-view-inputs", "source-frame-preservation"):
            if f"spx-bisimulation-{kind}:{key[0]}:{model['proof_function']}" not in model["required_assertion_descriptions"]:
                raise ComponentBisimulationError("contextual shared-view initialization checks are missing")
        if (f"spx-bisimulation-exit-world-memory:{key[0]}:{model['proof_function']}"
                not in model["required_assertion_descriptions"]):
            raise ComponentBisimulationError(
                "contextual exit memory check is missing from the required inventory"
            )
        start_unit_id = expected_rows[key].get("exact_start_unit_id")
        selected_unit_ids = model.get("selected_unit_ids")
        if (
            model.get("start_unit_id") != start_unit_id
            or not isinstance(selected_unit_ids, list)
            or start_unit_id not in selected_unit_ids
            or model.get("selected_unit_count") != len(selected_unit_ids)
        ):
            raise ComponentBisimulationError(
                "contextual exact obligation model starts at another cutpoint"
            )
        planned = planned_operations[key[0]]
        sync_by_unit = {
            str(sync["exact_unit_id"]): str(sync["id"])
            for sync in _mapping_rows(planned["source"]["syncs"], "planned syncs")
        }
        target_syncs = {
            sync_by_unit[str(edge["target_unit_id"])]
            for edge in _mapping_rows(planned["exact"]["control_edges"], "planned edges")
            if str(edge["source_unit_id"]) in selected_unit_ids
            and str(edge["target_unit_id"]) in sync_by_unit
        }
        boundary_checks = {
            f"spx-bisimulation-{kind}:{sync_id}"
            for sync_id in target_syncs
            for kind in ("world-memory", "world-connected-calls", "allocation-cut-admission", "sync-alignment")
        }
        if ("entry_allocation_history" in planned["source"]
                and expected_rows[key]["source"]["kind"] == "operation_entry"):
            boundary_checks.update(f"spx-bisimulation-allocation-entry-{kind}:{key[0]}"
                                   for kind in ("input", "admission"))
        for sync in _mapping_rows(planned["source"]["syncs"], "planned syncs"):
            for fact in sync.get("memory_facts", []):
                phases = (("construction-order", "input-domain") if
                    expected_rows[key]["source"] == {"kind": "sync", "id": sync["id"]} else ())
                phases += ("output-domain", "contents") if sync["id"] in target_syncs else ()
                boundary_checks.update(f"spx-bisimulation-memory-fact-{phase}:{sync['id']}:{fact['id']}"
                                       for phase in phases)
            if (sync["id"] not in target_syncs and
                    expected_rows[key]["source"] != {"kind": "sync", "id": sync["id"]}):
                boundary_checks.add(f"spx-bisimulation-unexpected-sync:{sync['id']}")
            if any("private_stack_scope" in item for item in planned["source"]["syncs"]) and sync["id"] in target_syncs:
                boundary_checks.add(f"spx-bisimulation-private-stack-scope:{sync['id']}")
            if "private_stack_scope" in sync and expected_rows[key]["source"] == {"kind": "sync", "id": sync["id"]}:
                boundary_checks.add(f"spx-bisimulation-private-stack-scope-input:{sync['id']}")
            if "allocation_history" in sync and expected_rows[key]["source"] == {"kind": "sync", "id": sync["id"]}:
                boundary_checks.add(f"spx-bisimulation-allocation-history-input:{sync['id']}")
            for fact in _mapping_rows(sync["derived"], "planned derived relations"):
                if fact["expression"].get("op") != "exact_projection":
                    continue
                reads = any(p.get("kind") == "static_slot" for p in
                            (fact["projection"], fact["expression"]["projection"]))
                if sync["id"] in target_syncs:
                    boundary_checks.add(f"spx-bisimulation-derived:{sync['id']}:{fact['id']}")
                    if reads:
                        boundary_checks.add("spx-bisimulation-exact-output-read")
                if reads and expected_rows[key]["source"] == {"kind": "sync", "id": sync["id"]}:
                    boundary_checks.add("spx-bisimulation-exact-input-read")
            for capture in _mapping_rows(sync["captures"], "planned captures"):
                if capture["mode"] == "native_view":
                    if expected_rows[key]["source"] == {"kind": "sync", "id": sync["id"]}:
                        boundary_checks.add(f"spx-bisimulation-native-view-input:{sync['id']}:{capture['id']}")
                        from .bisimulation_local_views import POLICY, input_owner_description
                        if model.get("local_view_cut_policy") == POLICY:
                            boundary_checks.add(input_owner_description(sync["id"], capture["id"]))
                    if sync["id"] in target_syncs:
                        boundary_checks.update(f"spx-bisimulation-{kind}:{sync['id']}:{capture['id']}"
                                               for kind in ("capture", "resumed-view-admission"))
                        if capture['kind'] == 'parameter':
                            boundary_checks.add(f"spx-bisimulation-capture-reference-memory:{sync['id']}:{capture['id']}")
                if capture["kind"] == "parameter" and capture['mode'] != 'native_view' and (
                    capture["mode"] != "machine_codec" or capture["encoding"] not in [
                        {"op": op, "name": capture["id"]}
                        for op in ("parameter", "bytes_address", "resource_identity")
                    ]
                ):
                    raise ComponentBisimulationError("contextual parameter capture lacks canonical argument encoding")
                if (sync["id"] in target_syncs and capture["kind"] == "source_state"
                        and capture["mode"] == "machine_codec"):
                    boundary_checks.add(f"spx-bisimulation-capture-roundtrip:{sync['id']}:{capture['id']}")
                if (sync["id"] in target_syncs and capture["kind"] == "parameter"
                        and capture["mode"] == "machine_codec" and isinstance(capture["projection"], Mapping)
                        and capture["projection"].get("kind") == "view"):
                    boundary_checks.add(f"spx-bisimulation-resumed-view-admission:{sync['id']}:{capture['id']}")
                if (sync["id"] in target_syncs and capture["kind"] == "parameter"
                        and capture["mode"] == "machine_codec" and isinstance(capture["projection"], Mapping)
                        and capture["projection"].get("kind") in {"view", "bytes_view"}):
                    boundary_checks.add(f"spx-bisimulation-capture-reference-memory:{sync['id']}:{capture['id']}")
                    boundary_checks.add(f"spx-bisimulation-capture-methods:{sync['id']}:{capture['id']}")
                    boundary_checks.add(f"spx-bisimulation-capture-metadata:{sync['id']}:{capture['id']}")
                    boundary_checks.add(f"spx-bisimulation-capture-context:{sync['id']}:{capture['id']}")
                    boundary_checks.add(f"spx-bisimulation-capture-extent:{sync['id']}:{capture['id']}")
        if not boundary_checks <= set(model["required_assertion_descriptions"]):
            raise ComponentBisimulationError(
                "contextual cutpoint boundary checks are missing from the required inventory"
            )
    observed: set[tuple[str, str]] = set()
    for shard in shard_results:
        validate_runtime_assurance_binding(shard, runtime_assurance)
        operation_id = str(shard.get("operation_id", ""))
        obligation_id = str(shard.get("obligation_id", ""))
        key = (operation_id, obligation_id)
        if key in observed or key not in model_by_obligation:
            raise ComponentBisimulationError(
                "contextual shard identity is absent or duplicated"
            )
        observed.add(key)
        if "exact_memory_frame" in shard:
            from .bisimulation_exact_frame import validate_exact_frame

            if checker is None:
                raise ComponentBisimulationError("exact memory frame checker binding is unavailable")
            try:
                validate_exact_frame(shard["exact_memory_frame"], model=model_by_obligation[key], shard=shard, checker=checker, runtime_assurance=runtime_assurance)
            except (ValueError, TypeError, KeyError) as error:
                raise ComponentBisimulationError(str(error)) from error
        for field in ("exact_mutable_memory_frame", "exact_mutable_cut_frame"):
            if field in shard:
                from .bisimulation_mutable_frame import validate_mutable_frame, validate_mutable_cut_frame

                if checker is None:
                    raise ComponentBisimulationError("mutable memory frame checker binding is unavailable")
                try:
                    validator = validate_mutable_frame if field == "exact_mutable_memory_frame" else validate_mutable_cut_frame
                    validator(shard[field], model=model_by_obligation[key], shard=shard, checker=checker, runtime_assurance=runtime_assurance)
                except (ValueError, TypeError, KeyError) as error:
                    raise ComponentBisimulationError(str(error)) from error
        for field in ("readable_entry_contract", "mutable_entry_contract"):
            if field in shard:
                from .bisimulation_readable_entry import validate_readable_entry, validate_mutable_entry

                if checker is None:
                    raise ComponentBisimulationError("memory entry checker binding is unavailable")
                try:
                    validator = validate_readable_entry if field == "readable_entry_contract" else validate_mutable_entry
                    validator(shard[field], model=model_by_obligation[key], shard=shard, checker=checker, runtime_assurance=runtime_assurance)
                except (ValueError, TypeError, KeyError) as error:
                    raise ComponentBisimulationError(str(error)) from error
        from .bisimulation_image_frame import FRAME as IMAGE_FRAME, validate_frame as validate_image_frame
        if IMAGE_FRAME.field in shard:
            if checker is None:
                raise ComponentBisimulationError('image/private frame checker binding is unavailable')
            try:
                validate_image_frame(shard[IMAGE_FRAME.field], model=model_by_obligation[key],
                    shard=shard, checker=checker, runtime_assurance=runtime_assurance)
            except (ValueError, TypeError, KeyError) as error:
                raise ComponentBisimulationError(str(error)) from error
        from .bisimulation_mutable_machine_frame import SPECS, validate_mutable_machine_frame
        for spec in SPECS:
            if spec.field in shard:
                if checker is None:
                    raise ComponentBisimulationError("mutable machine frame checker binding is unavailable")
                try:
                    validate_mutable_machine_frame(shard[spec.field], spec=spec,
                        model=model_by_obligation[key], shard=shard, checker=checker, runtime_assurance=runtime_assurance)
                except (ValueError, TypeError, KeyError) as error:
                    raise ComponentBisimulationError(str(error)) from error
        from .bisimulation_clobber_frame import clobber_specs, validate_clobber_frame
        from .bisimulation_private_frame import specs as private_specs, validate_private_frame
        if {"exact_private_write_frame", "exact_private_cut_frame"} & set(shard):
            try:
                private_model = model_by_obligation[key]
                for spec in private_specs(parse_stack_writes(private_model.get("private_stack_writes", []))):
                    if spec.field in shard:
                        validate_private_frame(shard[spec.field], spec=spec, model=private_model, shard=shard, checker=checker, runtime_assurance=runtime_assurance)
            except (ValueError, TypeError, KeyError) as error:
                raise ComponentBisimulationError(str(error)) from error
        clobber_model = model_by_obligation[key]
        clobber_fields = {"exact_mutable_cut_clobber_frame", "exact_mutable_exit_clobber_frame"}
        if clobber_fields & set(shard):
            try:
                for spec in clobber_specs(clobber_model.get("machine_clobbers", []), clobber_model.get("machine_result_registers", [])):
                    if spec.field in shard:
                        validate_clobber_frame(shard[spec.field], spec=spec, model=clobber_model, shard=shard, checker=checker, runtime_assurance=runtime_assurance)
            except (ValueError, TypeError, KeyError) as error:
                raise ComponentBisimulationError(str(error)) from error
        if shard.get("shard_id") != f"{operation_id}:{obligation_id}":
            raise ComponentBisimulationError("contextual shard id is stale")
        if (
            shard.get("proof_model_sha256")
            != model_by_obligation[key].get("proof_model_sha256")
            or shard.get("nonvacuity_proof_model_sha256")
            != model_by_obligation[key].get("nonvacuity_proof_model_sha256")
            or shard.get("property_checker_command_sha256")
            != model_by_obligation[key].get(
                "property_checker_command_sha256"
            )
            or shard.get("nonvacuity_checker_command_sha256")
            != model_by_obligation[key].get(
                "nonvacuity_checker_command_sha256"
            )
        ):
            raise ComponentBisimulationError(
                "contextual shard proof model binding is stale"
            )
        shard_status = shard.get("status")
        shard_code = shard.get("code")
        if shard_status not in {"satisfied", "violated", "incomplete"}:
            raise ComponentBisimulationError(
                "contextual shard status is unsupported"
            )
        goto_model_sha256 = shard.get("goto_model_sha256")
        if goto_model_sha256 is None:
            if (
                shard_status != "incomplete"
                or not isinstance(shard_code, str)
                or not shard_code.startswith("goto_cc_")
            ):
                raise ComponentBisimulationError(
                    "contextual shard omits its compiled goto model"
                )
        else:
            _sha256(goto_model_sha256, "contextual goto model")
        nonvacuity_goto_sha256 = shard.get("nonvacuity_goto_model_sha256")
        if nonvacuity_goto_sha256 is None:
            witness = shard.get("nonvacuity")
            if (
                not isinstance(witness, Mapping)
                or witness.get("status") != "incomplete"
                or not str(witness.get("code", "")).startswith("goto_cc_")
            ):
                raise ComponentBisimulationError(
                    "contextual shard omits its nonvacuity goto model"
                )
        else:
            _sha256(
                nonvacuity_goto_sha256,
                "contextual nonvacuity goto model",
            )
        if nonvacuity_goto_sha256 != goto_model_sha256:
            raise ComponentBisimulationError(
                "contextual property and relation checks do not share one goto model"
            )
        if (
            goto_model_sha256 != model_by_obligation[key].get(
                "goto_model_sha256"
            )
            or nonvacuity_goto_sha256 != model_by_obligation[key].get(
                "nonvacuity_goto_model_sha256"
            )
        ):
            raise ComponentBisimulationError(
                "contextual shard goto model binding is stale"
            )
        execution_binding = {
            "proof_model_sha256": shard.get("proof_model_sha256"),
            "nonvacuity_proof_model_sha256": shard.get(
                "nonvacuity_proof_model_sha256"
            ),
            "property_checker_command_sha256": shard.get(
                "property_checker_command_sha256"
            ),
            "nonvacuity_checker_command_sha256": shard.get(
                "nonvacuity_checker_command_sha256"
            ),
            "goto_model_sha256": goto_model_sha256,
            "nonvacuity_goto_model_sha256": nonvacuity_goto_sha256,
        }
        if runtime_assurance is not None:
            execution_binding["assurance"] = runtime_assurance
        if (
            shard.get("execution_binding_sha256")
            != canonical_sha256_v3(execution_binding)
            or model_by_obligation[key].get("execution_binding_sha256")
            != shard.get("execution_binding_sha256")
        ):
            raise ComponentBisimulationError(
                "contextual shard execution binding is stale"
            )
        _sha256(shard.get("output_sha256"), "contextual checker output")
        _validate_partitioned_property_evidence(shard=shard, model=model_by_obligation[key])
        witness = shard.get("nonvacuity")
        if not isinstance(witness, Mapping):
            raise ComponentBisimulationError(
                "contextual shard omits its nonvacuity result"
            )
        _sha256(witness.get("output_sha256"), "contextual nonvacuity output")
        if shard_status == "satisfied" and (
            witness.get("status") != "satisfied"
            or witness.get("code") != "cbmc_nonvacuity_witness"
            or witness.get("expected_functions")
            != model_by_obligation[key].get("witness_functions")
            or not isinstance(witness.get("witnessed_functions"), list)
            or not witness.get("witnessed_functions")
            or set(witness["witnessed_functions"])
            != set(model_by_obligation[key]["witness_functions"])
            or not isinstance(witness.get("property_ids"), list)
            or not witness.get("property_ids")
        ):
            raise ComponentBisimulationError(
                "conclusive contextual shard has no nonvacuity witness"
            )
        if shard_status == "violated" and (
            witness.get("status") != "satisfied"
            or witness.get("code")
            != "cbmc_counterexample_inhabits_property_model"
            or witness.get("evidence") != "property_counterexample"
            or witness.get("expected_functions")
            != model_by_obligation[key].get("witness_functions")
            or witness.get("witnessed_functions") != []
            or witness.get("output_sha256") != shard.get("output_sha256")
        ):
            raise ComponentBisimulationError(
                "violated contextual shard has no counterexample inhabitation evidence"
            )
        if shard_status == "satisfied" and (
            shard.get("code") != "cbmc_properties_satisfied"
            or not isinstance(shard.get("property_ids"), list)
            or not shard.get("property_ids")
            or shard.get("properties") != len(shard["property_ids"])
        ):
            raise ComponentBisimulationError(
                "satisfied contextual shard has incomplete CBMC evidence"
            )
    if observed != expected:
        raise ComponentBisimulationError("contextual shard coverage is incomplete")



def _mapping_rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise ComponentBisimulationError(f"{context} must be an array of objects")
    return list(value)



def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ComponentBisimulationError(f"{context} binding is not a SHA-256 digest")
    return value


def _validate_partitioned_property_evidence(*, shard, model, uniform_entry=False):
    """Share the complete partition reader with independent entry qualification.

    Ordinary contextual receipts retain their existing typed-barrier routing.
    Independent entry checks use one bound relation root for every property.
    """
    shard_status = shard.get("status")
    required_sites = model.get("required_assertion_sites")
    if uniform_entry and required_sites is None:
        raise ComponentBisimulationError("independent entry omits its compiled assertion sites")
    if shard_status in {"satisfied", "violated"} or "partitioned_evidence" in shard:
        partitioned = shard.get("partitioned_evidence")
        if (
            not isinstance(partitioned, Mapping)
            or set(partitioned)
            != {
                "strategy",
                "assertion_inventory_output_sha256",
                "language_safety_inventory_output_sha256",
                "language_safety_baseline_inventory_output_sha256",
                "loop_inventory_output_sha256",
                "required_assertion_descriptions_sha256",
                "assertions",
                "language_safety_inventory",
                "language_safety_baseline_inventory",
                "loops",
                "language_safety_properties",
                "queries",
            } | ({"required_assertion_sites_sha256"} if required_sites is not None else set())
            or partitioned.get("strategy") not in ASSERTION_QUERY_STRATEGIES
            or partitioned.get('strategy') != model['property_checker_command']['strategy']
            or canonical_sha256_v3(partitioned)
            != shard.get("output_sha256")
            or partitioned.get("required_assertion_descriptions_sha256")
            != model.get(
                "required_assertion_descriptions_sha256"
            )
        ):
            raise ComponentBisimulationError(
                "contextual shard partitioned property evidence is stale"
            )
        if required_sites is not None and (
                partitioned.get("required_assertion_sites_sha256") != canonical_sha256_v3(required_sites)
                or not isinstance(partitioned.get("assertions"), list)
                or [{key: value for key, value in row.items() if key != "entry_function"}
                    for row in partitioned["assertions"] if isinstance(row, Mapping)] != required_sites):
            raise ComponentBisimulationError("independent entry assertion sites differ from the compiled manifest")
        _sha256(
            partitioned.get("assertion_inventory_output_sha256"),
            "contextual assertion inventory output",
        )
        _sha256(
            partitioned.get("language_safety_inventory_output_sha256"),
            "contextual language-safety inventory output",
        )
        _sha256(
            partitioned.get(
                "language_safety_baseline_inventory_output_sha256"
            ),
            "contextual baseline language-safety inventory output",
        )
        _sha256(
            partitioned.get("loop_inventory_output_sha256"),
            "contextual loop inventory output",
        )
        assertions = partitioned.get("assertions")
        language_safety_inventory = partitioned.get(
            "language_safety_inventory"
        )
        language_safety_baseline_inventory = partitioned.get(
            "language_safety_baseline_inventory"
        )
        loops = partitioned.get("loops")
        queries = partitioned.get("queries")
        proof_function = str(model["proof_function"])
        if (
            not isinstance(assertions, list)
            or not assertions
            or any(
                not isinstance(assertion, Mapping)
                or set(assertion)
                != {
                    "property_id",
                    "description",
                    "source_function",
                    "entry_function",
                }
                or any(
                    not isinstance(assertion.get(field), str)
                    or not assertion.get(field)
                    for field in assertion
                )
                or assertion.get("entry_function")
                != (proof_function if uniform_entry else _property_entry_function(
                    proof_function=proof_function,
                    description=str(assertion.get("description", "")),
                    source_function=str(
                        assertion.get("source_function", "")
                    ),
                ))
                for assertion in assertions
            )
        ):
            raise ComponentBisimulationError(
                "contextual partitioned property inventory is malformed"
            )
        assertion_ids = [str(assertion["property_id"]) for assertion in assertions]
        discovered_descriptions = [
            str(assertion["description"]) for assertion in assertions
        ]
        required_assertion_descriptions = model[
            "required_assertion_descriptions"
        ]
        safety_classes = {
            "bounds": {"array bounds"},
            "pointer": {
                "pointer",
                "pointer arithmetic",
                "pointer dereference",
                "pointer primitives",
            },
            "division": {"division-by-zero"},
            "signed_overflow": {"overflow"},
            "undefined_shift": {"undefined-shift"},
            "unwinding": {"unwind"},
        }
        if (
            assertion_ids != sorted(set(assertion_ids))
            or any(
                discovered_descriptions.count(description) != 1
                for description in required_assertion_descriptions
            )
            or not isinstance(language_safety_inventory, list)
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "property_id",
                    "class",
                    "description",
                    "source_function",
                }
                or any(
                    not isinstance(item.get(field), str)
                    or not item.get(field)
                    for field in item
                )
                or item.get("class")
                not in set().union(*safety_classes.values()) - {"unwind"}
                for item in language_safety_inventory
            )
            or [
                str(item["property_id"])
                for item in language_safety_inventory
            ]
            != sorted({
                str(item["property_id"])
                for item in language_safety_inventory
            })
            or not isinstance(language_safety_baseline_inventory, list)
            or any(
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "property_id",
                    "class",
                    "description",
                    "source_function",
                }
                or any(not isinstance(item.get(field), str) or not item.get(field)
                       for field in item)
                or item.get("class")
                not in set().union(*safety_classes.values()) - {"unwind"}
                for item in language_safety_baseline_inventory
            )
            or [
                str(item["property_id"])
                for item in language_safety_baseline_inventory
            ]
            != sorted({
                str(item["property_id"])
                for item in language_safety_baseline_inventory
            })
            or not isinstance(loops, list)
            or any(
                not isinstance(loop, Mapping)
                or set(loop)
                != {
                    "loop_id",
                    "source_function",
                    "unwinding_property_id",
                }
                or re.fullmatch(r".+\.[0-9]+", str(loop.get("loop_id", "")))
                is None
                or not isinstance(loop.get("source_function"), str)
                or not loop.get("source_function")
                or loop.get("unwinding_property_id")
                != re.sub(
                    r"\.([0-9]+)$",
                    r".unwind.\1",
                    str(loop.get("loop_id", "")),
                )
                for loop in loops
            )
            or [str(loop["loop_id"]) for loop in loops]
            != sorted({str(loop["loop_id"]) for loop in loops})
            or not isinstance(queries, list)
            or not queries
            or not isinstance(
                partitioned.get("language_safety_properties"), int
            )
            or isinstance(
                partitioned.get("language_safety_properties"), bool
            )
            or int(partitioned.get("language_safety_properties", 0)) <= 0
        ):
            raise ComponentBisimulationError(
                "contextual partitioned property inventory is malformed"
            )
        expected_safety_ids = {
            partition: sorted(
                str(item["property_id"])
                for item in language_safety_inventory
                if item["class"] in classes
            )
            for partition, classes in safety_classes.items()
            if partition != "unwinding"
        }
        expected_safety_ids["unwinding"] = [
            str(loop["unwinding_property_id"]) for loop in loops
        ]
        baseline_safety_ids = {
            str(item["property_id"])
            for item in language_safety_baseline_inventory
        }
        expected_safety_groups = [
            (partition, selected_ids)
            for partition in safety_classes
            for selected_ids in safety_property_groups(partition,
                expected_safety_ids[partition], language_safety_inventory, strategy=partitioned['strategy'])
        ]
        if (
            not expected_safety_groups
        ):
            raise ComponentBisimulationError(
                "contextual language-safety property inventory is stale"
            )
        safety_queries = [
            query for query in queries
            if isinstance(query, Mapping)
            and query.get("kind") == "language_safety"
        ]
        authored_queries = [
            query for query in queries
            if isinstance(query, Mapping)
            and query.get("kind") == "authored_assertion"
        ]
        checked_unwinding_ids = {
            str(property_id)
            for query in safety_queries
            if query.get("safety_partition") == "unwinding"
            for property_id in query.get("property_ids", [])
            if property_id in expected_safety_ids["unwinding"]
        }
        if (
            len(safety_queries) + len(authored_queries) != len(queries)
            or not safety_group_refinement(
                [(query.get("safety_partition"), query.get("expected_property_ids"))
                 for query in safety_queries], expected_safety_groups,
                complete=shard_status != "incomplete")
            or any(
                set(query)
                not in (
                    {
                        "kind",
                        "safety_partition",
                        "expected_property_ids",
                        "property_ids",
                        "status",
                        "code",
                        "properties",
                        "output_sha256",
                    },
                    {
                        "kind",
                        "safety_partition",
                        "expected_property_ids",
                        "property_ids",
                        "status",
                        "code",
                        "properties",
                        "output_sha256",
                        "detail",
                    },
                )
                or not isinstance(query.get("property_ids"), list)
                or query.get("property_ids")
                != sorted(set(query.get("property_ids", [])))
                or any(
                    not isinstance(property_id, str) or not property_id
                    for property_id in query.get("property_ids", [])
                )
                for query in safety_queries
            )
            or any(authored_query_ids(query, partitioned['strategy'],
                {row['property_id']: row for row in assertions}) is None for query in authored_queries)
            or any(
                not isinstance(query.get("status"), str)
                or not query.get("status")
                or not isinstance(query.get("code"), str)
                or not query.get("code")
                or not isinstance(query.get("properties"), int)
                or isinstance(query.get("properties"), bool)
                or int(query.get("properties", -1)) < 0
                or re.fullmatch(
                    r"[0-9a-f]{64}", str(query.get("output_sha256", ""))
                )
                is None
                or (
                    "detail" in query
                    and (
                        not isinstance(query.get("detail"), str)
                        or not query.get("detail")
                    )
                )
                for query in queries
            )
            or any(
                (
                    query.get("safety_partition") != "unwinding"
                    and not set(query.get("expected_property_ids", []))
                    <= set(query.get("property_ids", []))
                )
                or not set(query.get("property_ids", []))
                <= set(query.get("expected_property_ids", []))
                | (baseline_safety_ids
                   if query.get("safety_partition") == "unwinding" else set())
                for query in safety_queries
                if query.get("status") == "satisfied"
            )
            or partitioned.get("language_safety_properties")
            != len(language_safety_inventory) + len(checked_unwinding_ids)
        ):
            raise ComponentBisimulationError(
                "contextual partitioned property query evidence is malformed"
            )
        queried_assertions = [
            identity for query in authored_queries for identity in authored_query_ids(
                query, partitioned['strategy'], {row['property_id']: row for row in assertions})
        ]
        scheduled_assertion_ids = [
            str(assertion["property_id"])
            for assertion in sorted(assertions,
                key=lambda assertion: _property_query_order(assertion, strategy=partitioned["strategy"]))
        ]
        if shard_status == "satisfied" and (
            queried_assertions != scheduled_assertion_ids
            or any(query.get("status") != "satisfied" for query in queries)
            or any(
                query.get("properties")
                != len(query.get("property_ids", []))
                for query in safety_queries
            )
        ):
            raise ComponentBisimulationError(
                "satisfied contextual shard did not prove every property partition"
            )
        if shard_status == "violated" and not any(
            query.get("status") == "violated" for query in queries
        ):
            raise ComponentBisimulationError(
                "violated contextual shard has no violated property partition"
            )
