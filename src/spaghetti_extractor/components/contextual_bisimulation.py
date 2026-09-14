"""Source marker extraction and aggregate contextual-refinement receipts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping, Sequence

from .bisimulation_evidence import (
    _mapping_rows,
    _sha256,
    _validate_model_and_shard_evidence,
)

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation import (
    COMPONENT_PROOF_PLAN_V1_FORMAT,
    CONTEXTUAL_REFINEMENT_V2_FORMAT,
    ComponentBisimulationError,
)
from .bisimulation_support import (
    assertion_policy_option,
    PROOF_PRIVATE_STACK_ABOVE,
    PROOF_PRIVATE_STACK_BELOW,
    PROOF_RELATION_WITNESS,
    property_entry_function as _property_entry_function,
    property_query_order as _property_query_order,
)
from .bisimulation_service_effects import (
    checked_proof_external_effect_contract, checked_proof_external_contract_identity,
)
from .bisimulation_reference_authority import reference_authority_bound
from .bisimulation_lifetime_admission import admitted_call_specs, lifetime_implementation_paths, uses_lifetime_services
from .bisimulation_call_ranges import call_range_implementation_paths, uses_call_ranges
from .bisimulation_terminated_reads import (terminated_read_implementation_paths,
    borrowed_memory_implementation_paths, uses_terminated_results)
from .bisimulation_service_targets import external_target_implementation_paths, uses_external_target_slots
from .formats import (
    CONDITIONAL_CONTEXTUAL_REFINEMENT_V1_FORMAT,
    INTERACTION_CONTRACT_RECEIPT_V1_FORMAT,
    TRUSTED_ADAPTER_LOWERING_V1_FORMAT,
)


def operation_source_text(source: str, symbol: str) -> str:
    """Return one C function definition for proof-marker validation."""

    pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(")
    candidates = []
    for match in pattern.finditer(source):
        opening = source.find("(", match.start())
        closing = _balanced(source, opening, "(", ")")
        body = closing + 1
        while body < len(source) and source[body].isspace():
            body += 1
        if body < len(source) and source[body] == "{":
            candidates.append(source[match.start() : _balanced(source, body, "{", "}") + 1])
    if len(candidates) != 1:
        raise ComponentBisimulationError(
            f"operation symbol {symbol!r} has {len(candidates)} source definitions"
        )
    return candidates[0]


def operation_sources_from_package(
    *, source_root: Path, source: Mapping[str, object], symbols: Mapping[str, str]
) -> dict[str, str]:
    translation_units = []
    for row in source.get("files", []):
        if not isinstance(row, Mapping) or not str(row.get("path", "")).endswith(".c"):
            continue
        path = source_root / "sources" / str(row["path"])
        translation_units.append(path.read_text(encoding="utf-8"))
    combined = "\n".join(translation_units)
    return {
        operation_id: operation_source_text(combined, symbol)
        for operation_id, symbol in sorted(symbols.items())
    }


def build_contextual_refinement_v2(
    *, proof_plan, exact_c_slice, implementation_sha256, source_profile_sha256,
    checker, models, shard_results, world,
):
    """Build the ordinary strong receipt; conditional models are rejected."""
    return _build_contextual_refinement(
        proof_plan=proof_plan, exact_c_slice=exact_c_slice,
        implementation_sha256=implementation_sha256, source_profile_sha256=source_profile_sha256,
        checker=checker, models=models, shard_results=shard_results, world=world)


def validate_contextual_refinement_v2(value, *, proof_plan, exact_c_slice, implementation_sha256=None):
    """Strictly validate ordinary authority before native selection."""
    _validate_contextual_refinement(value, proof_plan=proof_plan, exact_c_slice=exact_c_slice,
                                    implementation_sha256=implementation_sha256)


def _required_runtime_assurance(value):
    from .bisimulation_assurance import checked_implemented_runtime_assurance
    checked = checked_implemented_runtime_assurance(value)
    if checked is None:
        raise ComponentBisimulationError("conditional refinement requires explicit runtime contracts")
    return checked


def _conditional_policy(policy, assurance):
    policy["proof_form"] = "conditional_cutpoint_bisimulation"
    policy["assumed_runtime_contracts"] = assurance["contracts"]
    if any(row["id"] == "world-reference-summary" for row in assurance["contracts"]):
        policy["native_cut_reference_decoding"] = False
    if any(row["id"] == "canonical-view-write-dispatch" for row in assurance["contracts"]):
        policy["production_machine_overlay_executed"] = False
        policy["conditional_runtime_write_dispatch"] = "checked-target-forwarding-v1"
    if any(row["id"] == "native-memory-admission" for row in assurance["contracts"]):
        from .bisimulation_native_admission import POLICY
        policy["conditional_native_memory_admission"] = POLICY


def build_conditional_contextual_refinement_v1(*, runtime_assurance, **inputs):
    """Check all component obligations, conditional on named runtime semantics.

    This is neither runtime validation nor supplier admission. Entry, frame and
    postcondition premises remain necessary before a caller may use a summary.
    """
    assurance = _required_runtime_assurance(runtime_assurance)
    result = _build_contextual_refinement(**inputs, runtime_assurance=assurance)
    validate_conditional_contextual_refinement_v1(
        result, runtime_assurance=assurance, proof_plan=inputs["proof_plan"],
        exact_c_slice=inputs["exact_c_slice"], implementation_sha256=inputs["implementation_sha256"])
    return result


def validate_conditional_contextual_refinement_v1(
    value, *, runtime_assurance, proof_plan, exact_c_slice, implementation_sha256=None,
):
    """Validate without granting ordinary qualification or native authority."""
    _validate_contextual_refinement(value, runtime_assurance=_required_runtime_assurance(runtime_assurance),
        proof_plan=proof_plan, exact_c_slice=exact_c_slice, implementation_sha256=implementation_sha256)


def validate_complete_local_refinement(proof_system, *, runtime_assurance=None):
    """Require a complete component domain before exporting local consequences.

    Conditional trust changes runtime assumptions, never the coverage required
    for all-entry/all-exit facts. Regional continuation and allocation-history
    premises need their own composition rules even when every shard passes.
    """
    if not isinstance(proof_system, Mapping) or set(proof_system) != {"proof", "proof_plan", "exact_c_slice"}:
        raise ComponentBisimulationError("complete local proof system is malformed")
    proof = proof_system["proof"]
    plan = proof_system["proof_plan"]
    inputs = {"proof_plan": plan, "exact_c_slice": proof_system["exact_c_slice"]}
    if runtime_assurance is None:
        validate_contextual_refinement_v2(proof, **inputs)
    else:
        validate_conditional_contextual_refinement_v1(proof, runtime_assurance=runtime_assurance, **inputs)
    if proof["status"] != "satisfied" or any(
            operation.get("continuation") is not None or "entry_allocation_history" in operation["source"]
            for operation in plan["operations"]):
        raise ComponentBisimulationError("complete local proof cannot retain continuation or allocation-history premises")


def _build_contextual_refinement(
    *,
    proof_plan: Mapping[str, object],
    exact_c_slice: Mapping[str, object],
    implementation_sha256: str,
    source_profile_sha256: str,
    checker: Mapping[str, object],
    models: Mapping[str, object],
    shard_results: Sequence[Mapping[str, object]],
    world: Mapping[str, object],
    runtime_assurance: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Aggregate the same proof obligations under an explicit trust selection."""

    if proof_plan.get("format") != COMPONENT_PROOF_PLAN_V1_FORMAT:
        raise ComponentBisimulationError("contextual refinement requires a V1 proof plan")
    plan_core = dict(proof_plan)
    plan_digest = plan_core.pop("plan_sha256", None)
    if plan_digest != canonical_sha256_v3(plan_core):
        raise ComponentBisimulationError("contextual refinement proof plan is stale")
    exact_core = dict(exact_c_slice)
    exact_digest = exact_core.pop("slice_sha256", None)
    if exact_digest != canonical_sha256_v3(exact_core):
        raise ComponentBisimulationError("contextual refinement exact-C slice is stale")
    expected = [
        f"{operation['operation_id']}:{obligation['id']}"
        for operation in _mapping_rows(proof_plan.get("operations"), "proof operations")
        for obligation in _mapping_rows(operation.get("obligations"), "proof obligations")
    ]
    observed = [str(item.get("shard_id")) for item in shard_results]
    if observed != sorted(expected) or observed != sorted(set(observed)):
        raise ComponentBisimulationError(
            "contextual refinement shard inventory is missing, duplicated, or unordered"
        )
    models_core = dict(models)
    plan_bindings = proof_plan.get("bindings")
    if not isinstance(plan_bindings, Mapping):
        raise ComponentBisimulationError(
            "contextual refinement proof plan bindings are malformed"
        )
    if (
        models_core.get("exact_c_slice_sha256") != exact_digest
        or models_core.get("implementation_sha256") != implementation_sha256
        or models_core.get("implementation_sha256")
        != plan_bindings.get("source_package_sha256")
        or models_core.get("source_profile_sha256") != source_profile_sha256
        or models_core.get("semantic_contract_sha256")
        != plan_bindings.get("semantic_contract_sha256")
        or models_core.get("interface_sha256")
        != plan_bindings.get("interface_sha256")
        or models_core.get("bisimulation_intent_sha256")
        != plan_bindings.get("bisimulation_intent_sha256")
    ):
        raise ComponentBisimulationError(
            "contextual refinement models are not bound to the exact slice, "
            "implementation, and production overlay"
        )
    trusted_adapter_lowering_used = _trusted_adapter_lowering_used(models_core)
    _validate_model_and_shard_evidence(
        proof_plan=proof_plan,
        models=models_core,
        shard_results=shard_results,
        checker=checker,
        runtime_assurance=runtime_assurance,
    )
    obligation_local_exact_c_slices = _obligation_local_exact_slices(models_core)
    statuses = [str(item.get("status")) for item in shard_results]
    status = (
        "violated"
        if "violated" in statuses
        else "satisfied"
        if (
            statuses
            and set(statuses) == {"satisfied"}
            and obligation_local_exact_c_slices
            and reference_authority_bound(models_core, world)
        )
        else "incomplete"
    )
    checker_core = dict(checker)
    checker_bounds = checker_core.get("model_bounds")
    if (
        not isinstance(checker_bounds, Mapping)
        or checker_bounds.get("private_stack_disjoint_checked_image") is not True
    ):
        raise ComponentBisimulationError(
            "contextual refinement requires private proof stacks to be disjoint "
            "from the checked machine image"
        )
    core: dict[str, object] = {
        "format": CONTEXTUAL_REFINEMENT_V2_FORMAT,
        "status": status,
        "activation_authorized": runtime_assurance is None and status == "satisfied" and not any(
            operation.get("continuation") is not None or "entry_allocation_history" in operation["source"]
            for operation in proof_plan["operations"]),
        "component_id": proof_plan["component_id"],
        "bindings": {
            "proof_plan_sha256": plan_digest,
            "exact_c_slice_sha256": exact_digest,
            "implementation_sha256": _sha256(implementation_sha256, "implementation"),
            "source_profile_sha256": _sha256(source_profile_sha256, "source profile"),
        },
        "checker": checker_core,
        "models": models_core,
        "world": dict(world),
        "shards": [dict(item) for item in shard_results],
        "policy": {
            "proof_form": "strong_cutpoint_bisimulation",
            "compiler_trusted": True,
            "arbitrary_shared_world": True,
            "private_stack_disjoint_checked_image": True,
            "immutable_input_world_specialized": True,
            "machine_side_memory_reads_specialized": True,
            "declared_final_memory_observables_are_complete": True,
            "cutpoint_public_memory_checked": True,
            "exit_public_memory_checked": True,
            "source_cut_storage_overapproximated": True,
            "source_cut_parameter_bindings_checked": True,
            "normal_exit_results_checked": True,
            "intra_function_continuation_state_checked": True,
            "call_public_memory_snapshots_checked": True,
            "call_allocation_lifetimes_checked": True,
            "machine_import_effect_categories_explicit": True,
            "declared_external_range_effects_checked": True,
            "typed_service_borrowed_inputs_checked": True,
            "logical_view_contracts_separated": True,
            "canonical_borrowed_view_spans": True,
            "cutpoint_connected_call_pairing_checked": True,
            "reference_realization_checks_issued_origins": True,
            "native_reference_authority_bound": reference_authority_bound(models_core, world),
            "native_cut_reference_decoding": True,
            "nul_origin_metadata_shared_between_worlds": True,
            "incidental_nonvolatile_memory_write_order_observed": False,
            "memory_writes_are_width_aware_events": True,
            "private_stack_reads_use_checked_containment_fast_path": True,
            "exact_capacity_derived_from_acyclic_unit_costs": True,
            "localized_model_validity_assertions_fail_closed": True,
            "shared_call_responses_are_relative_effects": True,
            "exact_call_arguments_prefer_matching_checked_event_stack_inputs": True,
            "typed_service_fields_use_single_call_boundary_assertion": True,
            "assertion_inventory_is_entry_reachability_sliced": True,
            "experimental_full_slicing_used": False,
            "exact_stack_cache_derived_from_generated_affine_accesses": True,
            "exact_stack_cache_mirrors_every_exact_private_write": True,
            "exact_stack_cache_partial_overlaps_invalidate": True,
            "language_safety_checked_separately": True,
            "language_safety_uses_paired_obligation_entry": True,
            "language_safety_shares_exact_response_transcript": True,
            "production_machine_overlay_executed": not trusted_adapter_lowering_used,
            "proof_overlay_rewrites_used": False,
            "trusted_typed_adapter_lowering_used": trusted_adapter_lowering_used,
            "private_service_outputs_abstracted_at_typed_barriers": (
                trusted_adapter_lowering_used
            ),
            "external_interface_storage_disjoint_private_stack": (
                trusted_adapter_lowering_used
            ),
            "nonvacuity_witness_required_per_shard": True,
            "one_goto_model_per_obligation": True,
            "one_property_goto_model_per_obligation": True,
            "distinct_nonvacuity_goto_model_per_obligation": False,
            "relation_inhabitation_query_shares_property_model": True,
            "relation_inhabitation_uses_unrestricted_domain": True,
            "nonvacuity_executes_paired_exact_and_source_suffixes": False,
            "one_relation_inhabitation_witness_per_ordinary_shard": True,
            "nonvacuity_world_capacity_claimed": False,
            "ordinary_branch_feasibility_claimed": False,
            "ordinary_terminal_feasibility_claimed": False,
            "property_counterexample_proves_model_inhabited": True,
            "nonvacuity_domain_restricts_property_model": False,
            "small_goal_nonvacuity_uses_per_goal_formula_slicing": True,
            "large_goal_nonvacuity_uses_aggregate_formula_slicing": True,
            "finite_control_domain_witness_required_per_route": True,
            "finite_control_image_bytes_bound_pre_execution": True,
            "finite_control_post_result_assumptions": False,
            "obligation_local_exact_c_slices": obligation_local_exact_c_slices,
            "partial_authority": False,
            "path_enumeration_authorizes": False,
            "tests_authorize": False,
        },
    }
    if runtime_assurance is not None:
        core.update(format=CONDITIONAL_CONTEXTUAL_REFINEMENT_V1_FORMAT,
                    assurance=runtime_assurance, authorizing=False)
        _conditional_policy(core["policy"], runtime_assurance)
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _validate_contextual_refinement(
    value: Mapping[str, object],
    *,
    proof_plan: Mapping[str, object],
    exact_c_slice: Mapping[str, object],
    implementation_sha256: str | None = None,
    runtime_assurance: Mapping[str, object] | None = None,
) -> None:
    """Strictly validate an authority receipt before native selection."""

    fields = {
        "format",
        "status",
        "activation_authorized",
        "component_id",
        "bindings",
        "checker",
        "models",
        "world",
        "shards",
        "policy",
        "receipt_sha256",
    }
    from .bisimulation_assurance import validate_runtime_assurance_binding
    validate_runtime_assurance_binding(value, runtime_assurance)
    if runtime_assurance is not None:
        fields.update({"assurance", "authorizing"})
    if set(value) != fields:
        raise ComponentBisimulationError(
            "contextual refinement receipt fields differ"
        )
    core = dict(value)
    digest = core.pop("receipt_sha256", None)
    if digest != canonical_sha256_v3(core):
        raise ComponentBisimulationError("contextual refinement receipt is stale")
    expected_format = (CONTEXTUAL_REFINEMENT_V2_FORMAT if runtime_assurance is None
                       else CONDITIONAL_CONTEXTUAL_REFINEMENT_V1_FORMAT)
    if value.get("format") != expected_format:
        raise ComponentBisimulationError("contextual refinement format is unsupported")
    plan_core = dict(proof_plan)
    plan_digest = plan_core.pop("plan_sha256", None)
    exact_core = dict(exact_c_slice)
    exact_digest = exact_core.pop("slice_sha256", None)
    bindings = value.get("bindings")
    plan_bindings = proof_plan.get("bindings")
    checker = value.get("checker")
    models = value.get("models")
    world = value.get("world")
    shards = value.get("shards")
    policy = value.get("policy")
    if (
        plan_digest != canonical_sha256_v3(plan_core)
        or exact_digest != canonical_sha256_v3(exact_core)
        or not isinstance(bindings, Mapping)
        or not isinstance(plan_bindings, Mapping)
        or not isinstance(checker, Mapping)
        or not isinstance(models, Mapping)
        or not isinstance(world, Mapping)
        or not isinstance(shards, list)
        or any(not isinstance(row, Mapping) for row in shards)
        or not isinstance(policy, Mapping)
    ):
        raise ComponentBisimulationError(
            "contextual refinement authority inputs are malformed"
        )
    trusted_adapter_lowering_used = _trusted_adapter_lowering_used(models)
    if policy.get("source_cut_storage_overapproximated") is not True:
        raise ComponentBisimulationError(
            "contextual refinement policy lacks checked source cut local and parameter storage overapproximation"
        )
    if policy.get("source_cut_parameter_bindings_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked source parameter bindings")
    if policy.get("logical_view_contracts_separated") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks value-specific logical view contracts")
    if policy.get("canonical_borrowed_view_spans") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked borrowed view spans")
    if policy.get("normal_exit_results_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked normal-exit results")
    if policy.get("intra_function_continuation_state_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked continuation state")
    if policy.get("call_public_memory_snapshots_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked call memory snapshots")
    if policy.get("call_allocation_lifetimes_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked call allocation lifetimes")
    if policy.get("machine_import_effect_categories_explicit") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks explicit import effect categories")
    if policy.get("typed_service_borrowed_inputs_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked service borrowed inputs")
    if policy.get("declared_external_range_effects_checked") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks checked declared external range effects")
    if policy.get("exact_stack_cache_partial_overlaps_invalidate") is not True:
        raise ComponentBisimulationError("contextual refinement policy lacks partial-overlap cache invalidation")
    obligation_local_exact_c_slices = _obligation_local_exact_slices(models)
    expected_policy = {
        "proof_form": "strong_cutpoint_bisimulation",
        "compiler_trusted": True,
        "arbitrary_shared_world": True,
        "private_stack_disjoint_checked_image": True,
        "immutable_input_world_specialized": True,
        "machine_side_memory_reads_specialized": True,
        "declared_final_memory_observables_are_complete": True,
        "cutpoint_public_memory_checked": True,
        "exit_public_memory_checked": True,
        "source_cut_storage_overapproximated": True,
        "source_cut_parameter_bindings_checked": True,
        "normal_exit_results_checked": True,
        "intra_function_continuation_state_checked": True,
        "call_public_memory_snapshots_checked": True,
        "call_allocation_lifetimes_checked": True,
        "machine_import_effect_categories_explicit": True,
        "declared_external_range_effects_checked": True,
        "typed_service_borrowed_inputs_checked": True,
        "logical_view_contracts_separated": True,
        "canonical_borrowed_view_spans": True,
        "cutpoint_connected_call_pairing_checked": True,
        "reference_realization_checks_issued_origins": True,
        "native_reference_authority_bound": True,
        "native_cut_reference_decoding": True,
        "nul_origin_metadata_shared_between_worlds": True,
        "incidental_nonvolatile_memory_write_order_observed": False,
        "memory_writes_are_width_aware_events": True,
        "private_stack_reads_use_checked_containment_fast_path": True,
        "exact_capacity_derived_from_acyclic_unit_costs": True,
        "localized_model_validity_assertions_fail_closed": True,
        "shared_call_responses_are_relative_effects": True,
        "exact_call_arguments_prefer_matching_checked_event_stack_inputs": True,
        "typed_service_fields_use_single_call_boundary_assertion": True,
        "assertion_inventory_is_entry_reachability_sliced": True,
        "experimental_full_slicing_used": False,
        "exact_stack_cache_derived_from_generated_affine_accesses": True,
        "exact_stack_cache_mirrors_every_exact_private_write": True,
        "exact_stack_cache_partial_overlaps_invalidate": True,
        "language_safety_checked_separately": True,
        "language_safety_uses_paired_obligation_entry": True,
        "language_safety_shares_exact_response_transcript": True,
        "production_machine_overlay_executed": not trusted_adapter_lowering_used,
        "proof_overlay_rewrites_used": False,
        "trusted_typed_adapter_lowering_used": trusted_adapter_lowering_used,
        "private_service_outputs_abstracted_at_typed_barriers": (
            trusted_adapter_lowering_used
        ),
        "external_interface_storage_disjoint_private_stack": (
            trusted_adapter_lowering_used
        ),
        "nonvacuity_witness_required_per_shard": True,
        "one_goto_model_per_obligation": True,
        "one_property_goto_model_per_obligation": True,
        "distinct_nonvacuity_goto_model_per_obligation": False,
        "relation_inhabitation_query_shares_property_model": True,
        "relation_inhabitation_uses_unrestricted_domain": True,
        "nonvacuity_executes_paired_exact_and_source_suffixes": False,
        "one_relation_inhabitation_witness_per_ordinary_shard": True,
        "nonvacuity_world_capacity_claimed": False,
        "ordinary_branch_feasibility_claimed": False,
        "ordinary_terminal_feasibility_claimed": False,
        "property_counterexample_proves_model_inhabited": True,
        "nonvacuity_domain_restricts_property_model": False,
        "small_goal_nonvacuity_uses_per_goal_formula_slicing": True,
        "large_goal_nonvacuity_uses_aggregate_formula_slicing": True,
        "finite_control_domain_witness_required_per_route": True,
        "finite_control_image_bytes_bound_pre_execution": True,
        "finite_control_post_result_assumptions": False,
        "obligation_local_exact_c_slices": obligation_local_exact_c_slices,
        "partial_authority": False,
        "path_enumeration_authorizes": False,
        "tests_authorize": False,
    }
    expected_model_fields = {
        "reference_authority",
        "interface_sha256",
        "semantic_contract_sha256",
        "source_profile_sha256",
        "implementation_sha256",
        "bisimulation_intent_sha256",
        "exact_c_slice_sha256",
        "machine_overlay_sha256",
        "proof_overlay_sha256",
        "trusted_adapter_lowering",
        "operation_models",
        "connected_components",
    }
    if runtime_assurance is not None:
        expected_model_fields.update({"assurance", "authorizing"})
        _conditional_policy(expected_policy, runtime_assurance)
    expected_checker_fields = {
        "id",
        "version",
        "cbmc_sha256",
        "goto_cc_sha256",
        "architecture",
        "model_bounds",
        "timeout_seconds_per_shard",
        "maximum_parallel_shards",
        "maximum_parallel_solver_processes",
        "nested_solver_parallelism",
        "options",
    }
    from .cbmc_backend import CbmcBackendError, validate_smt_solver_binding
    if "smt_solver" in checker:
        try:
            validate_smt_solver_binding(checker["smt_solver"])
        except CbmcBackendError as error:
            raise ComponentBisimulationError(str(error)) from error
        expected_checker_fields.add("smt_solver")
    expected_world_policy = {
        "provider_behavior_summaries_used": False,
        "checked_component_summaries_used": any(
            row.get("summary_strategy") in {"scalar-body-free-v1", "image-readable-body-free-v1", "image-mutable-body-free-v1", "image-shared-body-free-v1", "image-shared-framed-body-free-v1"}
            for row in models["connected_components"]
        ),
        "out_of_boundary_calls_are_arbitrary_typed_events": True,
        "resource_lifecycle_checked": True,
        "hidden_shared_mutable_state_allowed": False,
    }
    world_core = dict(world)
    world_digest = world_core.pop("world_sha256", None)
    model_bounds = checker.get("model_bounds")
    _validate_contextual_model_bounds(
        model_bounds=model_bounds,
        models=models,
        proof_plan=proof_plan,
    )
    if (
        value.get("component_id") != proof_plan.get("component_id")
        or value.get("component_id") != exact_c_slice.get("component_id")
        or bindings.get("proof_plan_sha256") != plan_digest
        or bindings.get("exact_c_slice_sha256") != exact_digest
        or (implementation_sha256 is not None
            and bindings.get("implementation_sha256") != implementation_sha256)
        or models.get("exact_c_slice_sha256") != exact_digest
        or models.get("implementation_sha256")
        != bindings.get("implementation_sha256")
        or models.get("implementation_sha256")
        != plan_bindings.get("source_package_sha256")
        or models.get("source_profile_sha256")
        != bindings.get("source_profile_sha256")
        or models.get("semantic_contract_sha256")
        != plan_bindings.get("semantic_contract_sha256")
        or models.get("interface_sha256")
        != plan_bindings.get("interface_sha256")
        or models.get("bisimulation_intent_sha256")
        != plan_bindings.get("bisimulation_intent_sha256")
        or not isinstance(exact_c_slice.get("bindings"), Mapping)
        or exact_c_slice["bindings"].get("bisimulation_intent_sha256")
        != plan_bindings.get("bisimulation_intent_sha256")
        or set(models) not in tuple(expected_model_fields | optional for optional in (
            set(), {"source_summary_contracts"},
            {"reference_allocation_requirements", "reference_allocation_requirements_sha256"},
            {"source_summary_contracts", "reference_allocation_requirements", "reference_allocation_requirements_sha256"}))
        or policy != expected_policy
        or set(checker) != expected_checker_fields
        or checker.get("id") != "cbmc-goto-direct-c-bisimulation"
        or checker.get("architecture") != "i386-win32"
        or checker.get("maximum_parallel_shards") != 1
        or checker.get("maximum_parallel_solver_processes") != 4
        or checker.get("nested_solver_parallelism") is not False
        or checker.get("options") != [
            "source-cuts=matched-terminal-v1",
            "object-bits=12",
            "symex-cache-dereferences",
            "smt-solver=z3" if "smt_solver" in checker else "sat-solver=cadical",
            "unwind=2",
            "unwinding-assertions",
            "reachability-slice-fb",
            "slice-formula",
            "stop-on-fail",
            assertion_policy_option(models),
            "assertion-inventory=entry-reachability-sliced",
            "typed-service-fields=single-call-boundary-safe-prefix",
            "exact-stack=affine-word-cache-with-partial-overlap-invalidation",
            "language-safety=inventory-partitioned-paired-obligation-entry",
            "small-goal-nonvacuity=per-goal-formula-sliced",
            "large-goal-nonvacuity=aggregate-formula-sliced",
        ]
        or world_digest != canonical_sha256_v3(world_core)
        or world.get("format")
        != "spaghetti-extractor-component-proof-world-v1"
        or world.get("memory") != {
            "immutable_reads": (
                "symbolic_initial_bytes_with_checked_immutable_image_overrides"
            ),
            "mutable_state": "symbolic_initial_bytes_and_bounded_write_log",
        }
        or world.get("responses")
        != "shared_symbolic_stream_over_separate_cloned_worlds"
        or world.get("policy") != expected_world_policy
    ):
        raise ComponentBisimulationError(
            "contextual refinement policy/checker/world is not strong authority"
        )
    for field in ("cbmc_sha256", "goto_cc_sha256"):
        _sha256(checker.get(field), f"contextual checker {field}")
    world_bindings = world.get("bindings")
    if (
        set(world) != {
            "format",
            "bindings",
            "types",
            "services",
            "memory",
            "responses",
            "policy",
            "world_sha256",
        }
        or not isinstance(world_bindings, Mapping)
        or set(world_bindings) != {
            "schema_sha256",
            "interface_sha256",
            "binding_intent_sha256",
            "machine_object_authority_sha256",
        }
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(item)) is None
            for item in world_bindings.values()
        )
        or not isinstance(world.get("types"), list)
        or not isinstance(world.get("services"), list)
    ):
        raise ComponentBisimulationError(
            "contextual refinement world inventory is malformed"
        )
    _validate_model_and_shard_evidence(
        proof_plan=proof_plan,
        models=models,
        shard_results=shards,
        checker=checker,
        runtime_assurance=runtime_assurance,
    )
    if not reference_authority_bound(models, world):
        raise ComponentBisimulationError("contextual native reference authority is missing or bound to another world")
    statuses = {str(row.get("status")) for row in shards}
    expected_status = (
        "violated"
        if "violated" in statuses
        else "satisfied"
        if statuses == {"satisfied"} and obligation_local_exact_c_slices
        else "incomplete"
    )
    if (
        value.get("status") != expected_status
        or value.get("activation_authorized") is not (
            runtime_assurance is None and expected_status == "satisfied" and not any(
                operation.get("continuation") is not None or "entry_allocation_history" in operation["source"]
                for operation in proof_plan["operations"]))
    ):
        raise ComponentBisimulationError(
            "contextual refinement aggregate status is inconsistent"
        )


def _obligation_local_exact_slices(models: Mapping[str, object]) -> bool:
    operation_models = _mapping_rows(
        models.get("operation_models"), "contextual operation models"
    )
    return bool(operation_models) and all(
        model.get("scope") == "cutpoint_segment"
        for operation in operation_models
        for model in _mapping_rows(
            operation.get("obligation_models"), "contextual obligation models"
        )
    )


def _validate_contextual_model_bounds(
    *,
    model_bounds: object,
    models: Mapping[str, object],
    proof_plan: Mapping[str, object],
) -> None:
    """Validate the descriptive bound summary against its obligation models."""

    numeric_fields = {
        "maximum_static_byte_write_upper_bound",
        "maximum_static_memory_write_call_upper_bound",
        "maximum_declared_public_memory_write_call_upper_bound",
        "maximum_calls_per_obligation",
        "maximum_atomics_per_obligation",
        "maximum_exact_stack_cached_accesses",
        "maximum_exact_stack_cached_bytes",
    }
    expected_fields = numeric_fields | {
        "derivation",
        "inductive_cutpoint_live_in_relation",
        "exact_capacity",
        "localized_model_validity_assertions_fail_closed",
        "public_capacity",
        "pointer_topology",
        "private_stack_disjoint_checked_image",
        "dynamic_allocation",
    }
    derived = _derived_model_bound_maxima(models, proof_plan=proof_plan)
    if (
        not isinstance(model_bounds, Mapping)
        or set(model_bounds) != expected_fields
        or derived is None
        or any(
            not isinstance(model_bounds.get(field), int)
            or isinstance(model_bounds.get(field), bool)
            or int(model_bounds[field]) < 0
            or (
                field not in {
                    "maximum_exact_stack_cached_accesses",
                    "maximum_exact_stack_cached_bytes",
                }
                and int(model_bounds[field]) <= 0
            )
            for field in numeric_fields
        )
        or any(model_bounds.get(name) != value for name, value in derived.items())
        or model_bounds.get("derivation")
        != "obligation_local_cutpoint_segment_capacity"
        or model_bounds.get("inductive_cutpoint_live_in_relation")
        != "universal_authored_relation_without_entry_prefix_replay"
        or model_bounds.get("exact_capacity")
        != "acyclic_unit_and_call_site_upper_bound"
        or model_bounds.get("localized_model_validity_assertions_fail_closed")
        is not True
        or model_bounds.get("public_capacity")
        != "paired_local_capacity_assertions"
        or model_bounds.get("pointer_topology")
        != "generated_harness_owned_and_source_definedness_checked"
        or model_bounds.get("private_stack_disjoint_checked_image") is not True
        or model_bounds.get("dynamic_allocation") != "absent"
    ):
        observed_fields = (
            sorted(str(field) for field in model_bounds)
            if isinstance(model_bounds, Mapping)
            else None
        )
        raise ComponentBisimulationError(
            "contextual refinement model-bound summary is malformed or stale: "
            f"observed_fields={observed_fields!r}; "
            f"observed={dict(model_bounds) if isinstance(model_bounds, Mapping) else model_bounds!r}; "
            f"derived={derived!r}"
        )


def _derived_model_bound_maxima(
    models: Mapping[str, object],
    *,
    proof_plan: Mapping[str, object],
) -> dict[str, int] | None:
    """Recompute checker summaries from the bound obligation-local models."""

    local_to_global = {
        "static_byte_write_upper_bound": "maximum_static_byte_write_upper_bound",
        "static_memory_write_call_upper_bound": (
            "maximum_static_memory_write_call_upper_bound"
        ),
        "declared_public_memory_write_call_upper_bound": (
            "maximum_declared_public_memory_write_call_upper_bound"
        ),
        "maximum_calls": "maximum_calls_per_obligation",
        "maximum_atomics": "maximum_atomics_per_obligation",
        "exact_stack_cached_accesses": "maximum_exact_stack_cached_accesses",
        "exact_stack_cached_bytes": "maximum_exact_stack_cached_bytes",
    }
    local_fields = set(local_to_global)
    values = {global_name: [] for global_name in local_to_global.values()}
    planned_operation_ids: set[str] = set()
    planned_operations = proof_plan.get("operations")
    if not isinstance(planned_operations, list) or not planned_operations:
        return None
    for operation in planned_operations:
        if not isinstance(operation, Mapping):
            return None
        operation_id = operation.get("operation_id")
        if (
            not isinstance(operation_id, str)
            or not operation_id
            or operation_id in planned_operation_ids
        ):
            return None
        planned_operation_ids.add(operation_id)
    operations = models.get("operation_models")
    if not isinstance(operations, list) or not operations:
        return None
    for operation in operations:
        if not isinstance(operation, Mapping):
            return None
        operation_id = operation.get("operation_id")
        if operation_id not in planned_operation_ids:
            return None
        obligations = operation.get("obligation_models")
        if not isinstance(obligations, list) or not obligations:
            return None
        for obligation in obligations:
            if not isinstance(obligation, Mapping):
                return None
            bounds = obligation.get("model_bounds")
            if (
                not isinstance(bounds, Mapping)
                or set(bounds) != local_fields
                or any(
                    not isinstance(bounds.get(field), int)
                    or isinstance(bounds.get(field), bool)
                    or int(bounds[field]) < 0
                    for field in local_fields
                )
                or any(
                    int(bounds[field]) <= 0
                    for field in (
                        "static_byte_write_upper_bound",
                        "static_memory_write_call_upper_bound",
                        "declared_public_memory_write_call_upper_bound",
                        "maximum_calls",
                        "maximum_atomics",
                    )
                )
                or bounds.get("static_memory_write_call_upper_bound")
                != (int(bounds.get("static_byte_write_upper_bound", 0)) + 3) // 4
                or int(bounds.get("declared_public_memory_write_call_upper_bound", 0))
                > int(bounds.get("static_memory_write_call_upper_bound", 0))
            ):
                return None
            for local_name, global_name in local_to_global.items():
                values[global_name].append(int(bounds[local_name]))
    return {name: max(items) for name, items in values.items()}


def _valid_reference_result_relation(
    value: object,
    *,
    service_id: str,
) -> bool:
    if value is None:
        return True
    if not isinstance(value, Mapping) or set(value) != {
        "operation_id",
        "requirement_id",
        "service_id",
        "input_argument_index",
        "relation",
        "origin_type",
        "result_policy",
        "nonnull_min_remaining",
        "contract_id",
        "contract_sha256",
        "contract_catalog_sha256",
        "contract_receipt",
        "contract_receipt_sha256",
    }:
        return False
    origin_type = value.get("origin_type")
    result_policy = value.get("result_policy")
    remaining = value.get("nonnull_min_remaining")
    receipt = value.get("contract_receipt")
    if not isinstance(receipt, Mapping):
        return False
    receipt_core = dict(receipt)
    receipt_digest = receipt_core.pop("receipt_sha256", None)
    return bool(
        value.get("service_id") == service_id
        and isinstance(value.get("operation_id"), str)
        and value.get("operation_id")
        and isinstance(value.get("requirement_id"), str)
        and value.get("requirement_id")
        and value.get("relation") == "borrowed_interior_or_null"
        and isinstance(value.get("input_argument_index"), int)
        and not isinstance(value.get("input_argument_index"), bool)
        and int(value["input_argument_index"]) >= 0
        and isinstance(origin_type, Mapping)
        and set(origin_type) == {"kind", "nul_terminated"}
        and origin_type.get("kind") in {"reference", "view"}
        and isinstance(origin_type.get("nul_terminated"), bool)
        and isinstance(result_policy, Mapping)
        and set(result_policy)
        == {"nullable", "allow_one_past", "permissions"}
        and isinstance(result_policy.get("nullable"), bool)
        and isinstance(result_policy.get("allow_one_past"), bool)
        and isinstance(result_policy.get("permissions"), int)
        and not isinstance(result_policy.get("permissions"), bool)
        and result_policy.get("permissions") in {0, 1, 2, 3}
        and (
            remaining is None
            or (
                isinstance(remaining, Mapping)
                and set(remaining) == {"nonzero_argument_index", "minimum"}
                and isinstance(remaining.get("nonzero_argument_index"), int)
                and not isinstance(
                    remaining.get("nonzero_argument_index"), bool
                )
                and int(remaining["nonzero_argument_index"]) >= 0
                and isinstance(remaining.get("minimum"), int)
                and not isinstance(remaining.get("minimum"), bool)
                and int(remaining["minimum"]) > 0
            )
        )
        and isinstance(value.get("contract_id"), str)
        and value.get("contract_id")
        and re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("contract_sha256", ""))
        )
        is not None
        and re.fullmatch(
            r"[0-9a-f]{64}",
            str(value.get("contract_catalog_sha256", "")),
        )
        is not None
        and set(receipt_core)
        == {"format", "contract_id", "contract_sha256", "status", "code"}
        and receipt_core.get("format")
        == INTERACTION_CONTRACT_RECEIPT_V1_FORMAT
        and receipt_core.get("contract_id") == value.get("contract_id")
        and receipt_core.get("contract_sha256")
        == value.get("contract_sha256")
        and receipt_core.get("status") == "checked"
        and receipt_core.get("code") == "reviewed_reusable_contract"
        and receipt_digest == canonical_sha256_v3(receipt_core)
        and receipt_digest == value.get("contract_receipt_sha256")
    )


def _trusted_adapter_lowering_used(models: Mapping[str, object]) -> bool:
    """Validate and classify a compiler-trusted structural adapter lowering."""

    production_sha256 = _sha256(
        models.get("machine_overlay_sha256"), "production machine overlay"
    )
    proof_sha256 = _sha256(
        models.get("proof_overlay_sha256"), "proof machine overlay"
    )
    lowering = models.get("trusted_adapter_lowering")
    if production_sha256 == proof_sha256:
        if lowering is not None:
            raise ComponentBisimulationError(
                "identical production/proof overlays must not claim a trusted lowering"
            )
        return False
    if not isinstance(lowering, Mapping):
        raise ComponentBisimulationError(
            "distinct production/proof overlays require a trusted adapter lowering"
        )
    expected_fields = {
        "format",
        "status",
        "trust_basis",
        "interface_sha256",
        "adapter_plan",
        "adapter_plan_sha256",
        "production_overlay_sha256",
        "proof_overlay_sha256",
        "renderer",
        "receipt_sha256",
    }
    lowering_core = dict(lowering)
    lowering_digest = lowering_core.pop("receipt_sha256", None)
    adapters = lowering.get("adapter_plan")
    renderer = lowering.get("renderer")
    if (
        set(lowering) != expected_fields
        or lowering_digest != canonical_sha256_v3(lowering_core)
        or lowering.get("format")
        != TRUSTED_ADAPTER_LOWERING_V1_FORMAT
        or lowering.get("status") != "complete"
        or lowering.get("trust_basis")
        != "trusted_c_compiler_over_single_checked_adapter_plan"
        or lowering.get("interface_sha256") != models.get("interface_sha256")
        or lowering.get("production_overlay_sha256") != production_sha256
        or lowering.get("proof_overlay_sha256") != proof_sha256
        or not isinstance(adapters, list)
        or not adapters
        or any(not isinstance(row, Mapping) for row in adapters)
        or lowering.get("adapter_plan_sha256") != canonical_sha256_v3(adapters)
        or not isinstance(renderer, Mapping)
    ):
        raise ComponentBisimulationError(
            "trusted adapter lowering receipt is malformed or stale"
        )

    expected_adapter_fields = {
        "service_id",
        "symbol",
        "provider_kind",
        "abi_sha256",
        "checked_binding",
        "checked_binding_sha256",
        "proof_call_specs",
        "proof_call_specs_sha256",
        "reference_result_origin",
        "adapter_sha256",
    }
    expected_spec_fields = {
        "external_effect_contract",
        "external_contract_identity_sha256",
        "spec_id",
        "behavior_sha256",
        "service_id",
        "event_kind",
        "instruction_rva",
        "event_index",
        "return_rva",
        "offsets",
        "raw_indices",
        "cell_inputs",
        "outputs",
        "compare_target",
        "callee_cleanup",
    }
    adapter_keys: list[tuple[str, str]] = []
    lifetime_used = False
    for adapter in adapters:
        adapter_core = dict(adapter)
        adapter_digest = adapter_core.pop("adapter_sha256", None)
        binding = adapter.get("checked_binding")
        specs = adapter.get("proof_call_specs")
        service_id = str(adapter.get("service_id", ""))
        symbol = str(adapter.get("symbol", ""))
        provider_kind = str(adapter.get("provider_kind", ""))
        abi_sha256 = str(adapter.get("abi_sha256", ""))
        reference_origin = adapter.get("reference_result_origin")
        reference_origin_valid = _valid_reference_result_relation(
            reference_origin,
            service_id=service_id,
        )
        try:
            from .bisimulation_service_effects import require_typed_external_target_support
            if isinstance(binding, Mapping):
                require_typed_external_target_support(binding)
            lifetime = isinstance(binding, Mapping) and uses_lifetime_services((binding,))
            lifetime_used |= lifetime
            if lifetime and (canonical_sha256_v3(specs) != canonical_sha256_v3(admitted_call_specs((binding,),
                    reference_authority=models.get('reference_authority'),
                    allocation_requirements=models.get('reference_allocation_requirements')))):
                raise ValueError('lifetime adapter does not bind its canonical checked call sites')
            external_effect_contract = (
                checked_proof_external_effect_contract(binding, allow_lifetime_effects=lifetime)
                if isinstance(binding, Mapping) else None
            )
            external_contract_identity = (
                checked_proof_external_contract_identity(binding)
                if isinstance(binding, Mapping) else None
            )
        except ValueError as exc:
            raise ComponentBisimulationError(
                f"trusted adapter external effect contract is malformed or unsupported: {exc}"
            ) from exc
        if (
            set(adapter) != expected_adapter_fields
            or adapter_digest != canonical_sha256_v3(adapter_core)
            or not service_id
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None
            or provider_kind not in {"external_call", "interface_method"}
            or re.fullmatch(r"[0-9a-f]{64}", abi_sha256) is None
            or not reference_origin_valid
            or not isinstance(binding, Mapping)
            or binding.get("service_id") != service_id
            or binding.get("symbol") != symbol
            or binding.get("provider_kind") != provider_kind
            or binding.get("abi_sha256") != abi_sha256
            or any(str(key).startswith("_") for key in binding)
            or adapter.get("checked_binding_sha256")
            != canonical_sha256_v3(binding)
            or not isinstance(specs, list)
            or not specs
            or any(
                not isinstance(spec, Mapping)
                or set(spec) != expected_spec_fields | ({'checked_external_contract'} if lifetime else set())
                or spec.get("service_id") != service_id
                or spec.get("external_effect_contract") != external_effect_contract
                or spec.get("external_contract_identity_sha256") != external_contract_identity
                or re.fullmatch(
                    r"[0-9a-f]{64}", str(spec.get("behavior_sha256", ""))
                )
                is None
                or spec.get("behavior_sha256")
                != canonical_sha256_v3(
                    {
                        "external_effect_contract": external_effect_contract,
                        "external_contract_identity_sha256": external_contract_identity,
                        "service_id": service_id,
                        "provider_kind": provider_kind,
                        "abi_sha256": abi_sha256,
                        "event_kind": spec.get("event_kind"),
                        "offsets": spec.get("offsets"),
                        "raw_indices": spec.get("raw_indices"),
                        "cell_inputs": spec.get("cell_inputs"),
                        "outputs": spec.get("outputs"),
                        "compare_target": spec.get("compare_target"),
                        "callee_cleanup": spec.get("callee_cleanup"),
                    }
                )
                or spec.get("spec_id")
                != int(str(spec.get("behavior_sha256"))[:8], 16)
                or spec.get("spec_id") == 0
                for spec in specs
            )
            or adapter.get("proof_call_specs_sha256")
            != canonical_sha256_v3(specs)
        ):
            raise ComponentBisimulationError(
                "trusted adapter lowering plan is malformed or stale"
            )
        adapter_keys.append((service_id, symbol))
    if adapter_keys != sorted(set(adapter_keys)):
        raise ComponentBisimulationError(
            "trusted adapter lowering plan is duplicated or unordered"
        )
    from .bisimulation_call_ranges import validate_readable_range_guards
    try:
        validate_readable_range_guards(
            [spec for adapter in adapters for spec in adapter['proof_call_specs']], models)
    except (ValueError, TypeError) as exc:
        raise ComponentBisimulationError(str(exc)) from exc
    if lifetime_used:
        from .bisimulation_shared_composition import allocation_preserving_dependencies
        if not allocation_preserving_dependencies(models):
            raise ComponentBisimulationError('connected allocation dependencies require transitive proof premises')

    implementation_files = renderer.get("implementation_files")
    expected_implementation_paths = [
        "bisimulation_service_effects.py",
        "bisimulation_service_preconditions.py",
        "bisimulation_typed_services.py",
        "contracts.py",
        "machine_overlay_boundaries_v5.py",
        "machine_overlay_external_v5.py",
        "machine_overlay_result_views.py",
        "machine_overlay_services_v5.py",
        "machine_overlay_state_views.py",
        "machine_overlay_v5.py",
        "range_allocation.py",
        "range_ownership.py",
        "range_release.py",
        "resolved_contract.py",
    ]
    if lifetime_used:
        expected_implementation_paths = sorted([*expected_implementation_paths,
                                              *(path.name for path in lifetime_implementation_paths())])
    if uses_call_ranges([adapter["checked_binding"] for adapter in adapters]):
        expected_implementation_paths = sorted({*expected_implementation_paths,
                                              *(path.name for path in call_range_implementation_paths())})
    terminated_used = uses_terminated_results([adapter["checked_binding"] for adapter in adapters])
    expected_implementation_paths = sorted({*expected_implementation_paths,
        *(path.name for path in borrowed_memory_implementation_paths()),
        *(path.name for path in terminated_read_implementation_paths() if terminated_used)})
    if uses_external_target_slots([adapter["checked_binding"] for adapter in adapters]):
        expected_implementation_paths = sorted({*expected_implementation_paths,
                                              *(path.name for path in external_target_implementation_paths())})
    # Older version-5 renderers recorded this whole conservative superset for
    # every adapter. Keep that exact known inventory valid when unused; never
    # allow omitted string semantics on a terminated read or write contract.
    allowed_implementation_paths = [expected_implementation_paths]
    if not terminated_used:
        allowed_implementation_paths.append(sorted({*expected_implementation_paths,
            *(path.name for path in terminated_read_implementation_paths())}))
    if (
        set(renderer)
        != {
            "id",
            "version",
            "implementation_files",
            "implementation_closure_sha256",
        }
        or renderer.get("id") != "checked-service-adapter-dual-lowering-v5"
        or renderer.get("version") != 5
        or not isinstance(implementation_files, list)
        or any(
            not isinstance(row, Mapping)
            or set(row) != {"path", "sha256"}
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256", ""))) is None
            for row in implementation_files
        )
        or [row.get("path") for row in implementation_files]
        not in allowed_implementation_paths
        or renderer.get("implementation_closure_sha256")
        != canonical_sha256_v3(implementation_files)
    ):
        raise ComponentBisimulationError(
            "trusted adapter lowering renderer closure is malformed or stale"
        )
    return True


def _balanced(source: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise ComponentBisimulationError("C source contains an unterminated delimiter")


__all__ = [
    "build_contextual_refinement_v2",
    "operation_source_text",
    "operation_sources_from_package",
    "validate_contextual_refinement_v2",
]
