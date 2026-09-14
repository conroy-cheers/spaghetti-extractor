from __future__ import annotations

import copy

import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

from spaghetti_extractor.components.bisimulation import (
    COMPONENT_PROOF_PLAN_V1_FORMAT,
    ComponentBisimulationError,
    ComponentBisimulationIntentV1,
    build_component_proof_plan_v1,
)

from spaghetti_extractor.components.contextual_bisimulation import (
    _validate_contextual_model_bounds,
    build_contextual_refinement_v2,
    validate_contextual_refinement_v2,
)

from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.bisimulation_evidence import _validate_model_and_shard_evidence

from .test_bisimulation import _intent, _interface, _operation
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2

_REFERENCE_AUTHORITY = MachineObjectAuthorityV2(machine_backend="x86-pe32",
    bindings={"original_pe_sha256": "b" * 64}, rules=[]).to_payload()


class ContextualReceiptTests(unittest.TestCase):
    def test_contextual_model_bound_summary_is_exact_and_typed(self) -> None:
        proof_plan = {
            "operations": [{
                "operation_id": "run",
                "observables": {"effects": []},
            }]
        }
        first = {
            "static_byte_write_upper_bound": 5,
            "static_memory_write_call_upper_bound": 2,
            "declared_public_memory_write_call_upper_bound": 1,
            "maximum_calls": 3,
            "maximum_atomics": 1,
            "exact_stack_cached_accesses": 2,
            "exact_stack_cached_bytes": 8,
        }
        second = {
            **first,
            "static_byte_write_upper_bound": 8,
            "maximum_calls": 2,
            "maximum_atomics": 4,
            "exact_stack_cached_accesses": 0,
            "exact_stack_cached_bytes": 0,
        }
        models = {
            "operation_models": [{
                "operation_id": "run",
                "obligation_models": [
                    {"model_bounds": first},
                    {"model_bounds": second},
                ],
            }]
        }
        summary = {
            "maximum_static_byte_write_upper_bound": 8,
            "maximum_static_memory_write_call_upper_bound": 2,
            "maximum_declared_public_memory_write_call_upper_bound": 1,
            "maximum_calls_per_obligation": 3,
            "maximum_atomics_per_obligation": 4,
            "maximum_exact_stack_cached_accesses": 2,
            "maximum_exact_stack_cached_bytes": 8,
            "derivation": "obligation_local_cutpoint_segment_capacity",
            "inductive_cutpoint_live_in_relation": (
                "universal_authored_relation_without_entry_prefix_replay"
            ),
            "exact_capacity": "acyclic_unit_and_call_site_upper_bound",
            "localized_model_validity_assertions_fail_closed": True,
            "public_capacity": "paired_local_capacity_assertions",
            "pointer_topology": (
                "generated_harness_owned_and_source_definedness_checked"
            ),
            "private_stack_disjoint_checked_image": True,
            "dynamic_allocation": "absent",
        }
        _validate_contextual_model_bounds(
            model_bounds=summary,
            models=models,
            proof_plan=proof_plan,
        )

        mutations = {
            "boolean maximum": {
                **summary,
                "maximum_static_byte_write_upper_bound": True,
            },
            "stale maximum": {
                **summary,
                "maximum_calls_per_obligation": 2,
            },
            "stale derivation": {**summary, "derivation": "guessed"},
            "stale topology": {**summary, "pointer_topology": "unchecked"},
            "dynamic allocation": {**summary, "dynamic_allocation": "present"},
        }
        for label, mutation in mutations.items():
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(ComponentBisimulationError, "model-bound"),
            ):
                _validate_contextual_model_bounds(
                    model_bounds=mutation,
                    models=models,
                    proof_plan=proof_plan,
                )

        malformed_models = copy.deepcopy(models)
        malformed_models["operation_models"][0]["obligation_models"][0][
            "model_bounds"
        ]["static_memory_write_call_upper_bound"] = 1
        with self.assertRaisesRegex(ComponentBisimulationError, "model-bound"):
            _validate_contextual_model_bounds(
                model_bounds=summary,
                models=malformed_models,
                proof_plan=proof_plan,
            )


    def test_contextual_authority_requires_checked_image_stack_disjointness(self) -> None:
        plan = build_component_proof_plan_v1(
            component_id="counter",
            semantic_contract_sha256="a" * 64,
            interface=_interface(),
            operations=[_operation()],
            operation_sources={
                "run": "SPX_PROOF_BEGIN(run); SPX_PROOF_SYNC(loop, 1, limit, cursor);"
            },
            source_package_sha256="c" * 64,
            intent=_intent(),
        )
        exact_core = {
            "component_id": "counter",
            "bindings": {
                "bisimulation_intent_sha256": plan["bindings"][
                    "bisimulation_intent_sha256"
                ]
            },
            "files": [],
        }
        exact_slice = {
            **exact_core,
            "slice_sha256": canonical_sha256_v3(exact_core),
        }
        proof_inputs = [
            {"role": "reference_authority", "sha256": _REFERENCE_AUTHORITY["authority_sha256"]},
            {"role": "exact_c", "sha256": "5" * 64},
            {"role": "source_c", "sha256": "6" * 64},
            {"role": "production_overlay_c", "sha256": "4" * 64},
            {"role": "proof_header", "sha256": "7" * 64},
            {"role": "source_cut_storage_inventory", "sha256": "8" * 64},
            {"role": "source_parameter_binding_inventory", "sha256": "9" * 64},
            {"role": "harness", "sha256": "e" * 64},
        ]
        proof_model_sha256 = canonical_sha256_v3(proof_inputs)
        obligation_models = [
            {
                "obligation_id": row["id"],
                "scope": "cutpoint_segment",
                "start_unit_id": row["exact_start_unit_id"],
                "selected_unit_ids": [row["exact_start_unit_id"]],
                "selected_unit_count": 1,
                "files": [],
                "files_sha256": canonical_sha256_v3([]),
                "exact_stack_accesses": [],
                "model_bounds": {
                    "static_byte_write_upper_bound": 1,
                    "static_memory_write_call_upper_bound": 1,
                    "declared_public_memory_write_call_upper_bound": 1,
                    "maximum_calls": 1,
                    "maximum_atomics": 1,
                    "exact_stack_cached_accesses": 0,
                    "exact_stack_cached_bytes": 0,
                },
                "proof_function": f"spx_check_{index}",
                "nonvacuity_function": f"spx_check_{index}_relation",
                "witness_functions": ["spx_bisimulation_relation_witness"],
                "required_assertion_descriptions": ["ordinary property", "spx-bisimulation-allocation-cut-admission:loop", "spx-bisimulation-capture-roundtrip:loop:cursor", f"spx-bisimulation-exit-continuation-state:run:spx_check_{index}", f"spx-bisimulation-exit-world-memory:run:spx_check_{index}", f"spx-bisimulation-shared-view-inputs:run:spx_check_{index}", f"spx-bisimulation-source-frame-preservation:run:spx_check_{index}", "spx-bisimulation-sync-alignment:loop", "spx-bisimulation-world-connected-calls:loop", "spx-bisimulation-world-memory:loop"],
                "required_assertion_descriptions_sha256": canonical_sha256_v3(
                    ["ordinary property", "spx-bisimulation-allocation-cut-admission:loop", "spx-bisimulation-capture-roundtrip:loop:cursor", f"spx-bisimulation-exit-continuation-state:run:spx_check_{index}", f"spx-bisimulation-exit-world-memory:run:spx_check_{index}", f"spx-bisimulation-shared-view-inputs:run:spx_check_{index}", f"spx-bisimulation-source-frame-preservation:run:spx_check_{index}", "spx-bisimulation-sync-alignment:loop", "spx-bisimulation-world-connected-calls:loop", "spx-bisimulation-world-memory:loop"]
                ),
                "proof_inputs": proof_inputs,
                "proof_model_sha256": proof_model_sha256,
                "nonvacuity_proof_inputs": copy.deepcopy(proof_inputs),
                "nonvacuity_proof_model_sha256": proof_model_sha256,
            }
            for index, row in enumerate(plan["operations"][0]["obligations"])
        ]
        for row in obligation_models:
            row["model_sha256"] = canonical_sha256_v3(
                {
                    key: row[key]
                    for key in (
                        "scope",
                        "start_unit_id",
                        "selected_unit_ids",
                        "selected_unit_count",
                        "files",
                        "files_sha256",
                    )
                }
            )
            language_safety_common = [
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
                "--sat-solver",
                "cadical",
                "--unwind",
                "2",
                "--reachability-slice-fb",
                "--slice-formula",
            ]
            row["property_checker_command"] = {
                "backend": "cbmc",
                "goto_model_role": "shared_partitioned_property_queries",
                "strategy": (
                    "inventory_function_grouped_paired_language_safety_with_entry_unwinding_reuse_v11"
                ),
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
                    "2",
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
                    "2",
                    "--show-properties",
                ],
                "loop_discovery_arguments": [
                    "--json-ui",
                    "--function",
                    "$PROPERTY_FUNCTION",
                    "--show-loops",
                ],
                "assertion_arguments": [
                    "--json-ui",
                    "--trace",
                    "--stop-on-fail",
                    "--function",
                    "$PROPERTY_FUNCTION",
                    "--symex-cache-dereferences",
                    "--object-bits",
                    "12",
                    "--sat-solver",
                    "cadical",
                    "--unwind",
                    "2",
                    "--unwinding-assertions",
                    "--reachability-slice-fb",
                    "--slice-formula",
                    "--no-standard-checks",
                    "--property",
                    "$PROPERTY_ID",
                ],
                "language_safety_queries": [
                    {
                        "partition": "bounds",
                        "classes": ["array bounds"],
                        "arguments": [
                            *language_safety_common,
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
                            *language_safety_common,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "division",
                        "classes": ["division-by-zero"],
                        "arguments": [
                            *language_safety_common,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "signed_overflow",
                        "classes": ["overflow"],
                        "arguments": [
                            *language_safety_common,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "undefined_shift",
                        "classes": ["undefined-shift"],
                        "arguments": [
                            *language_safety_common,
                            "$PROPERTY_IDS",
                        ],
                    },
                    {
                        "partition": "unwinding",
                        "classes": ["unwind"],
                        "arguments": [
                            *(
                                item
                                for item in language_safety_common
                                if item not in {"--reachability-slice-fb", "--no-unwinding-assertions"}
                            ),
                            "--no-standard-checks",
                            "--unwinding-assertions",
                        ],
                    },
                ],
            }
            row["nonvacuity_checker_command"] = {
                "backend": "cbmc",
                "goto_model_role": "shared_property_and_relation",
                "strategy": "per_goal_formula_sliced_v1",
                "queries": [
                    {
                        "functions": row["witness_functions"],
                        "arguments": [
                            "--json-ui",
                            "--function",
                            row["nonvacuity_function"],
                            "--no-assertions",
                            "--cover",
                            "cover",
                            "--symex-cache-dereferences",
                            "--object-bits",
                            "12",
                            "--sat-solver",
                            "cadical",
                            "--unwind",
                            "2",
                            "--property",
                            f"{row['witness_functions'][0]}.coverage.1",
                            "--reachability-slice-fb",
                            "--slice-formula",
                        ],
                    }
                ],
            }
            row["property_checker_command"]["entry_assertion_arguments"] = [
                "--no-unwinding-assertions" if item == "--unwinding-assertions" else item
                for item in row["property_checker_command"]["assertion_arguments"]]
            row["property_checker_command_sha256"] = canonical_sha256_v3(
                row["property_checker_command"]
            )
            row["nonvacuity_checker_command_sha256"] = canonical_sha256_v3(
                row["nonvacuity_checker_command"]
            )
            row["goto_model_sha256"] = "1" * 64
            row["nonvacuity_goto_model_sha256"] = "1" * 64
            row["execution_binding_sha256"] = canonical_sha256_v3(
                {
                    "proof_model_sha256": proof_model_sha256,
                    "nonvacuity_proof_model_sha256": proof_model_sha256,
                    "property_checker_command_sha256": row[
                        "property_checker_command_sha256"
                    ],
                    "nonvacuity_checker_command_sha256": row[
                        "nonvacuity_checker_command_sha256"
                    ],
                    "goto_model_sha256": row["goto_model_sha256"],
                    "nonvacuity_goto_model_sha256": row[
                        "nonvacuity_goto_model_sha256"
                    ],
                }
            )
        shards = []
        for row in obligation_models:
            partitioned_evidence = {
                "strategy": (
                    "inventory_function_grouped_paired_language_safety_with_entry_unwinding_reuse_v11"
                ),
                "assertion_inventory_output_sha256": "5" * 64,
                "language_safety_inventory_output_sha256": "8" * 64,
                "language_safety_baseline_inventory_output_sha256": "a" * 64,
                "loop_inventory_output_sha256": "9" * 64,
                "required_assertion_descriptions_sha256": row[
                    "required_assertion_descriptions_sha256"
                ],
                "assertions": [
                    {
                        "property_id": f"assert.{index + 1}",
                        "description": description,
                        "source_function": row["proof_function"],
                        "entry_function": row["proof_function"],
                    }
                    for index, description in enumerate(row["required_assertion_descriptions"])
                ],
                "language_safety_inventory": [
                    {
                        "property_id": "proof.array_bounds.1",
                        "class": "array bounds",
                        "description": "proof bound",
                        "source_function": row["proof_function"],
                    }
                ],
                "language_safety_baseline_inventory": [],
                "loops": [],
                "language_safety_properties": 1,
                "queries": [
                    {
                        "kind": "language_safety",
                        "safety_partition": "bounds",
                        "expected_property_ids": ["proof.array_bounds.1"],
                        "property_ids": ["proof.array_bounds.1"],
                        "status": "satisfied",
                        "code": "cbmc_properties_satisfied",
                        "properties": 1,
                        "output_sha256": "6" * 64,
                    },
                    *({
                        "kind": "authored_assertion",
                        "property_id": f"assert.{index + 1}",
                        "entry_function": row["proof_function"],
                        "status": "satisfied",
                        "code": "cbmc_properties_satisfied",
                        "properties": 1,
                        "output_sha256": "7" * 64,
                    } for index, _ in enumerate(row["required_assertion_descriptions"])),
                ],
            }
            partitioned_evidence["assertions"].sort(key=lambda item: item["property_id"])
            partitioned_evidence["queries"][1:] = sorted(
                partitioned_evidence["queries"][1:], key=lambda item: item["property_id"])
            shards.append({
                "shard_id": f"run:{row['obligation_id']}",
                "operation_id": "run",
                "obligation_id": row["obligation_id"],
                "proof_model_sha256": proof_model_sha256,
                "nonvacuity_proof_model_sha256": proof_model_sha256,
                "property_checker_command_sha256": row[
                    "property_checker_command_sha256"
                ],
                "nonvacuity_checker_command_sha256": row[
                    "nonvacuity_checker_command_sha256"
                ],
                "goto_model_sha256": row["goto_model_sha256"],
                "nonvacuity_goto_model_sha256": row[
                    "nonvacuity_goto_model_sha256"
                ],
                "execution_binding_sha256": row[
                    "execution_binding_sha256"
                ],
                "nonvacuity": {
                    "status": "satisfied",
                    "code": "cbmc_nonvacuity_witness",
                    "properties": 1,
                    "property_ids": ["cover.1"],
                    "expected_functions": row["witness_functions"],
                    "witnessed_functions": row["witness_functions"],
                    "output_sha256": "2" * 64,
                },
                "status": "satisfied",
                "code": "cbmc_properties_satisfied",
                "properties": 1,
                "property_ids": ["assert.1"],
                "partitioned_evidence": partitioned_evidence,
                "output_sha256": canonical_sha256_v3(partitioned_evidence),
            })
        models = {
            "reference_authority": _REFERENCE_AUTHORITY,
            "exact_c_slice_sha256": exact_slice["slice_sha256"],
            "implementation_sha256": "c" * 64,
            "source_profile_sha256": "d" * 64,
            "semantic_contract_sha256": "a" * 64,
            "interface_sha256": plan["bindings"]["interface_sha256"],
            "bisimulation_intent_sha256": plan["bindings"][
                "bisimulation_intent_sha256"
            ],
            "machine_overlay_sha256": "4" * 64,
            "proof_overlay_sha256": "4" * 64,
            "trusted_adapter_lowering": None,
            "operation_models": [
                {
                    "operation_id": "run",
                    "exact_entry_rva": 0x1000,
                    "overlay_symbol": "spx_counter_run",
                    "machine_image": {
                        "preferred_base": 0x400000,
                        "image_size": 0x10000,
                    },
                    "shards": len(obligation_models),
                    "obligation_models": obligation_models,
                }
            ],
            "connected_components": [],
        }
        arguments = {
            "proof_plan": plan,
            "exact_c_slice": exact_slice,
            "implementation_sha256": "c" * 64,
            "source_profile_sha256": "d" * 64,
            "models": models,
            "shard_results": shards,
            "world": {"bindings": {"machine_object_authority_sha256": _REFERENCE_AUTHORITY["authority_sha256"]}},
        }

        with self.assertRaisesRegex(ComponentBisimulationError, "disjoint"):
            build_contextual_refinement_v2(
                **arguments,
                checker={"model_bounds": {}},
            )

        proof = build_contextual_refinement_v2(
            **arguments,
            checker={
                "model_bounds": {"private_stack_disjoint_checked_image": True}
            },
        )
        self.assertTrue(proof["activation_authorized"])
        # A complete large class is a conjunction of canonical function groups.
        # A green subset, duplicate group, or regrouped inventory is insufficient.
        grouped_shards = copy.deepcopy(shards)
        grouped = grouped_shards[0]["partitioned_evidence"]
        grouped["language_safety_inventory"] = [
            {"property_id": f"{owner}.pointer_dereference.{index:04}",
             "class": "pointer dereference", "description": "pointer is live",
             "source_function": owner}
            for owner, count in (("first", 512), ("second", 513)) for index in range(count)]
        grouped["language_safety_properties"] = 1025
        grouped_queries = []
        for owner in ("first", "second"):
            ids = [r["property_id"] for r in grouped["language_safety_inventory"] if r["source_function"] == owner]
            grouped_queries.append({"kind": "language_safety", "safety_partition": "pointer",
                "expected_property_ids": ids, "property_ids": ids.copy(), "properties": len(ids),
                "status": "satisfied", "code": "cbmc_properties_satisfied", "output_sha256": "6" * 64})
        grouped["queries"] = grouped_queries + grouped["queries"][1:]
        for mutation in (None, "missing", "duplicate", "cross_owner", "foreign", "order"):
            changed = copy.deepcopy(grouped_shards)
            evidence = changed[0]["partitioned_evidence"]
            queries = evidence["queries"]
            if mutation == "missing": del queries[1]
            elif mutation == "duplicate": queries.insert(0, copy.deepcopy(queries[0]))
            elif mutation == "cross_owner":
                moved = queries[0]["expected_property_ids"].pop()
                queries[0]["property_ids"].remove(moved)
                queries[0]["properties"] -= 1
                for field in ("expected_property_ids", "property_ids"):
                    queries[1][field] = sorted([*queries[1][field], moved])
                queries[1]["properties"] += 1
            elif mutation == "foreign":
                queries[0]["property_ids"].append("foreign.pointer.1")
                queries[0]["properties"] += 1
            elif mutation == "order": queries[0],queries[1] = queries[1],queries[0]
            changed[0]["output_sha256"] = canonical_sha256_v3(evidence)
            with self.subTest(grouping=mutation):
                if mutation is None:
                    build_contextual_refinement_v2(**{**arguments, "shard_results": changed},
                        checker={"model_bounds": {"private_stack_disjoint_checked_image": True}})
                else:
                    with self.assertRaisesRegex(ComponentBisimulationError, "partitioned property query evidence"):
                        build_contextual_refinement_v2(**{**arguments, "shard_results": changed},
                            checker={"model_bounds": {"private_stack_disjoint_checked_image": True}})
        altered_models = copy.deepcopy(models)
        altered_model = altered_models["operation_models"][0]["obligation_models"][0]
        altered_model["property_checker_command"]["entry_assertion_arguments"].append("--no-assertions")
        altered_model["property_checker_command_sha256"] = canonical_sha256_v3(
            altered_model["property_checker_command"])
        with self.assertRaisesRegex(ComponentBisimulationError, "property checker command binding"):
            build_contextual_refinement_v2(
                **{**arguments, "models": altered_models},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}})
        # The unwind baseline has a separate ID domain. It must never excuse a
        # missing selected safety check or an extra property in a static query.
        for mutation in ("missing", "foreign_baseline"):
            altered = copy.deepcopy(shards)
            evidence = altered[0]["partitioned_evidence"]
            query = evidence["queries"][0]
            evidence["language_safety_baseline_inventory"] = [{
                "property_id": "proof.pointer_dereference.1",
                "class": "pointer dereference",
                "description": "dereferenced function pointer must be callback",
                "source_function": "proof",
            }]
            query["property_ids"] = ([] if mutation == "missing" else
                                      ["proof.array_bounds.1", "proof.pointer_dereference.1"])
            query["properties"] = len(query["property_ids"])
            altered[0]["output_sha256"] = canonical_sha256_v3(evidence)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                ComponentBisimulationError, "partitioned property query evidence"
            ):
                build_contextual_refinement_v2(
                    **{**arguments, "shard_results": altered},
                    checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
                )
        missing_state_models = copy.deepcopy(models)
        missing_state = missing_state_models["operation_models"][0]["obligation_models"][0]
        missing_state["proof_inputs"] = [row for row in missing_state["proof_inputs"]
                                         if row["role"] != "source_cut_storage_inventory"]
        missing_state["proof_model_sha256"] = canonical_sha256_v3(missing_state["proof_inputs"])
        with self.assertRaisesRegex(ComponentBisimulationError, "source cut storage inventory"):
            build_contextual_refinement_v2(
                **{**arguments, "models": missing_state_models},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
            )
        self.assertTrue(proof["policy"]["source_cut_storage_overapproximated"])
        missing_parameters = copy.deepcopy(models)
        missing_parameter_model = missing_parameters["operation_models"][0]["obligation_models"][0]
        missing_parameter_model["proof_inputs"] = [row for row in missing_parameter_model["proof_inputs"]
                                                   if row["role"] != "source_parameter_binding_inventory"]
        missing_parameter_model["proof_model_sha256"] = canonical_sha256_v3(missing_parameter_model["proof_inputs"])
        with self.assertRaisesRegex(ComponentBisimulationError, "source_parameter_binding_inventory"):
            build_contextual_refinement_v2(
                **{**arguments, "models": missing_parameters},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
            )
        for field in ("normal_exit_results_checked", "intra_function_continuation_state_checked", "call_public_memory_snapshots_checked", "call_allocation_lifetimes_checked", "machine_import_effect_categories_explicit", "declared_external_range_effects_checked", "typed_service_borrowed_inputs_checked", "exact_stack_cache_partial_overlaps_invalidate", "logical_view_contracts_separated", "canonical_borrowed_view_spans"):
            for mutation in ("absent", "false"):
                stale = copy.deepcopy(proof)
                if mutation == "absent": del stale["policy"][field]
                else: stale["policy"][field] = False
                stale["receipt_sha256"] = canonical_sha256_v3(
                    {key: value for key, value in stale.items() if key != "receipt_sha256"})
                with self.subTest(field=field, mutation=mutation), self.assertRaisesRegex(ComponentBisimulationError, "policy"):
                    validate_contextual_refinement_v2(stale, proof_plan=plan, exact_c_slice=exact_slice)
        missing_call_memory_models = copy.deepcopy(models)
        missing_call_memory = missing_call_memory_models["operation_models"][0]["obligation_models"][0]
        missing_call_memory["required_assertion_descriptions"].append("spx-bisimulation-typed-call-fields:0")
        missing_call_memory["required_assertion_descriptions"].sort()
        missing_call_memory["required_assertion_descriptions_sha256"] = canonical_sha256_v3(
            missing_call_memory["required_assertion_descriptions"])
        with self.assertRaisesRegex(ComponentBisimulationError, "call memory snapshot assertions"):
            build_contextual_refinement_v2(
                **{**arguments, "models": missing_call_memory_models},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
            )
        stale_parameters = copy.deepcopy(proof)
        del stale_parameters["policy"]["source_cut_parameter_bindings_checked"]
        stale_parameters["receipt_sha256"] = canonical_sha256_v3(
            {key: value for key, value in stale_parameters.items() if key != "receipt_sha256"}
        )
        with self.assertRaisesRegex(ComponentBisimulationError, "parameter bindings"):
            validate_contextual_refinement_v2(stale_parameters, proof_plan=plan, exact_c_slice=exact_slice)
        for mutation in ("absent", "false"):
            stale = copy.deepcopy(proof)
            if mutation == "absent":
                del stale["policy"]["source_cut_storage_overapproximated"]
            else:
                stale["policy"]["source_cut_storage_overapproximated"] = False
            stale["receipt_sha256"] = canonical_sha256_v3(
                {key: value for key, value in stale.items() if key != "receipt_sha256"}
            )
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ComponentBisimulationError, "policy"):
                validate_contextual_refinement_v2(stale, proof_plan=plan, exact_c_slice=exact_slice)
        self.assertTrue(proof["policy"]["reference_realization_checks_issued_origins"])
        self.assertTrue(proof["policy"]["nul_origin_metadata_shared_between_worlds"])
        self.assertTrue(
            proof["policy"]["private_stack_disjoint_checked_image"]
        )
        self.assertTrue(
            proof["policy"][
                "relation_inhabitation_query_shares_property_model"
            ]
        )
        self.assertTrue(
            proof["policy"]["relation_inhabitation_uses_unrestricted_domain"]
        )
        self.assertFalse(
            proof["policy"]["nonvacuity_domain_restricts_property_model"]
        )
        self.assertTrue(
            proof["policy"]["property_counterexample_proves_model_inhabited"]
        )

        violated_shards = copy.deepcopy(shards)
        violated_partitioned = copy.deepcopy(
            violated_shards[0]["partitioned_evidence"]
        )
        violated_partitioned["queries"][0].update(
            {
                "status": "violated",
                "code": "cbmc_counterexample",
                "properties": 1,
                "output_sha256": "6" * 64,
            }
        )
        violated_output_sha256 = canonical_sha256_v3(violated_partitioned)
        violated_shards[0].update(
            {
                "status": "violated",
                "code": "cbmc_counterexample",
                "detail": "a real relation mismatch",
                "partitioned_evidence": violated_partitioned,
                "output_sha256": violated_output_sha256,
                "nonvacuity": {
                    "status": "satisfied",
                    "code": "cbmc_counterexample_inhabits_property_model",
                    "evidence": "property_counterexample",
                    "expected_functions": obligation_models[0][
                        "witness_functions"
                    ],
                    "witnessed_functions": [],
                    "output_sha256": violated_output_sha256,
                },
            }
        )
        violated = build_contextual_refinement_v2(
            **{**arguments, "shard_results": violated_shards},
            checker={
                "model_bounds": {"private_stack_disjoint_checked_image": True}
            },
        )
        self.assertEqual(violated["status"], "violated")
        self.assertFalse(violated["activation_authorized"])

        for kind in ("shared-view-inputs", "source-frame-preservation"):
            with self.subTest(missing=kind):
                missing_models = copy.deepcopy(models)
                model = missing_models["operation_models"][0]["obligation_models"][0]
                model["required_assertion_descriptions"].remove(
                    f"spx-bisimulation-{kind}:run:{model['proof_function']}")
                model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(
                    model["required_assertion_descriptions"])
                with self.assertRaisesRegex(ComponentBisimulationError, "shared-view initialization"):
                    build_contextual_refinement_v2(
                        **{**arguments, "models": missing_models},
                        checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
                    )

        for boundary in ("world-memory", "allocation-cut-admission", "sync-alignment"):
            missing_boundary_models = copy.deepcopy(models)
            missing_boundary = missing_boundary_models["operation_models"][0]["obligation_models"][0]
            missing_boundary["required_assertion_descriptions"].remove(f"spx-bisimulation-{boundary}:loop")
            missing_boundary["required_assertion_descriptions_sha256"] = canonical_sha256_v3(
                missing_boundary["required_assertion_descriptions"]
            )
            with self.subTest(boundary=boundary), self.assertRaisesRegex(ComponentBisimulationError, "cutpoint boundary checks"):
                build_contextual_refinement_v2(
                    **{**arguments, "models": missing_boundary_models},
                    checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
                )

        # A declaration cannot reuse an older empty-history proof. Both the
        # operation and resumed segment must bind the transport implementation,
        # and the resumed constructor assertion remains independently required.
        history_plan = copy.deepcopy(plan)
        history_plan["operations"][0]["source"]["syncs"][0]["allocation_history"] = {
            "maximum_instances": 1, "classes": ["scratch"]}
        for bound in (False, True):
            history_models = copy.deepcopy(models)
            if bound:
                operation_model = history_models["operation_models"][0]
                for model in [operation_model, *operation_model["obligation_models"]]:
                    model.update(allocation_history_policy="bounded-allocation-history-checked-class-current-memory-v2",
                                 maximum_input_allocations=1)
            with self.subTest(history_bound=bound), self.assertRaisesRegex(
                    ComponentBisimulationError, "cutpoint boundary checks" if bound else "allocation history"):
                _validate_model_and_shard_evidence(
                    proof_plan=history_plan, models=history_models, shard_results=shards)

        missing_roundtrip_models = copy.deepcopy(models)
        missing_roundtrip = missing_roundtrip_models["operation_models"][0]["obligation_models"][0]
        missing_roundtrip["required_assertion_descriptions"].remove("spx-bisimulation-capture-roundtrip:loop:cursor")
        missing_roundtrip["required_assertion_descriptions_sha256"] = canonical_sha256_v3(
            missing_roundtrip["required_assertion_descriptions"]
        )
        with self.assertRaisesRegex(ComponentBisimulationError, "cutpoint boundary checks"):
            build_contextual_refinement_v2(
                **{**arguments, "models": missing_roundtrip_models},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
            )

        # The evidence reader consumes JSON captures, while the producer uses
        # parsed MachineProjectionV1 objects. Both must require the new goal.
        view_plan = copy.deepcopy(plan)
        view_plan["operations"][0]["source"]["syncs"][0]["captures"].append({
            "kind": "parameter", "id": "buffer", "mode": "machine_codec",
            "projection": {"kind": "view", "at": "entry", "base": {
                "kind": "register", "register": "ebx", "width": 32, "at": "entry"},
                "extent": {"kind": "constant", "width": 32, "value": 4},
                "requested_extent": {"kind": "constant", "width": 32, "value": 4},
                "authority": {"kind": "external", "id": "buffer", "lifetime": "invocation"}},
            "encoding": {"op": "bytes_address", "name": "buffer"}, "decoding": None,
        })
        view_checks = [f"spx-bisimulation-{kind}:loop:buffer" for kind in (
            "resumed-view-admission", "capture-reference-memory", "capture-methods", "capture-metadata", "capture-context", "capture-extent")]
        inventories = [[], ["spx-bisimulation-view-admission:loop:buffer"]]
        inventories.extend([check for check in view_checks if check != missing] for missing in view_checks)
        for inventory in inventories:
            with self.subTest(inventory=inventory):
                view_models = copy.deepcopy(models)
                for model in view_models["operation_models"][0]["obligation_models"]:
                    model["required_assertion_descriptions"].extend(inventory)
                    model["required_assertion_descriptions"].sort()
                    model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(
                        model["required_assertion_descriptions"])
                with self.assertRaisesRegex(ComponentBisimulationError, "cutpoint boundary checks"):
                    _validate_model_and_shard_evidence(
                        proof_plan=view_plan, models=view_models, shard_results=shards)

        missing_exit_models = copy.deepcopy(models)
        missing_exit = missing_exit_models["operation_models"][0]["obligation_models"][0]
        missing_exit["required_assertion_descriptions"] = [
            item for item in missing_exit["required_assertion_descriptions"]
            if not item.startswith("spx-bisimulation-exit-world-memory:")
        ]
        missing_exit["required_assertion_descriptions_sha256"] = canonical_sha256_v3(
            missing_exit["required_assertion_descriptions"]
        )
        with self.assertRaisesRegex(ComponentBisimulationError, "exit memory check"):
            build_contextual_refinement_v2(
                **{**arguments, "models": missing_exit_models},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
            )

        missing_continuation = copy.deepcopy(models)
        model = missing_continuation["operation_models"][0]["obligation_models"][0]
        model["required_assertion_descriptions"] = [
            item for item in model["required_assertion_descriptions"]
            if not item.startswith("spx-bisimulation-exit-continuation-state:")]
        model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
        with self.assertRaisesRegex(ComponentBisimulationError, "continuation state check"):
            build_contextual_refinement_v2(
                **{**arguments, "models": missing_continuation},
                checker={"model_bounds": {"private_stack_disjoint_checked_image": True}},
            )

        stale_nonvacuity_models = copy.deepcopy(models)
        stale_nonvacuity_models["operation_models"][0]["obligation_models"][0][
            "nonvacuity_proof_inputs"
        ][-1]["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            ComponentBisimulationError,
            "nonvacuity proof input inventory is stale",
        ):
            build_contextual_refinement_v2(
                **{**arguments, "models": stale_nonvacuity_models},
                checker={
                    "model_bounds": {"private_stack_disjoint_checked_image": True}
                },
            )

        stale_command_models = copy.deepcopy(models)
        stale_command_models["operation_models"][0]["obligation_models"][0][
            "nonvacuity_checker_command"
        ]["queries"][0]["arguments"].remove("--no-assertions")
        with self.assertRaisesRegex(
            ComponentBisimulationError,
            "nonvacuity checker command binding is stale",
        ):
            build_contextual_refinement_v2(
                **{**arguments, "models": stale_command_models},
                checker={
                    "model_bounds": {"private_stack_disjoint_checked_image": True}
                },
            )

        stale_execution_shards = copy.deepcopy(shards)
        stale_execution_shards[0]["execution_binding_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            ComponentBisimulationError,
            "execution binding is stale",
        ):
            build_contextual_refinement_v2(
                **{**arguments, "shard_results": stale_execution_shards},
                checker={
                    "model_bounds": {"private_stack_disjoint_checked_image": True}
                },
            )

        missing_nonvacuity_goto = copy.deepcopy(shards)
        missing_nonvacuity_goto[0]["nonvacuity_goto_model_sha256"] = None
        with self.assertRaisesRegex(
            ComponentBisimulationError,
            "omits its nonvacuity goto model",
        ):
            build_contextual_refinement_v2(
                **{**arguments, "shard_results": missing_nonvacuity_goto},
                checker={
                    "model_bounds": {"private_stack_disjoint_checked_image": True}
                },
            )

        compatibility_models = copy.deepcopy(models)
        compatibility_model = compatibility_models["operation_models"][0][
            "obligation_models"
        ][0]
        compatibility_model["scope"] = "full_operation_compatibility"
        compatibility_model.pop("files")
        compatibility_model["model_sha256"] = canonical_sha256_v3(
            {
                key: compatibility_model[key]
                for key in (
                    "scope",
                    "start_unit_id",
                    "selected_unit_ids",
                    "selected_unit_count",
                    "files_sha256",
                )
            }
        )
        compatibility = build_contextual_refinement_v2(
            **{**arguments, "models": compatibility_models},
            checker={
                "model_bounds": {"private_stack_disjoint_checked_image": True}
            },
        )
        self.assertEqual(compatibility["status"], "incomplete")
        self.assertFalse(compatibility["activation_authorized"])
        self.assertFalse(
            compatibility["policy"]["obligation_local_exact_c_slices"]
        )

        incomplete_shards = copy.deepcopy(shards)
        incomplete_shards[0].update(
            {
                "status": "incomplete",
                "code": "goto_cc_compile_failed",
                "goto_model_sha256": None,
                "nonvacuity_goto_model_sha256": None,
                "nonvacuity": {
                    "status": "incomplete",
                    "code": "goto_cc_compile_failed",
                    "output_sha256": "8" * 64,
                },
                "output_sha256": "8" * 64,
            }
        )
        incomplete_models = copy.deepcopy(models)
        # A compiler failure has no property inventory or query outputs.
        incomplete_shards[0].pop("partitioned_evidence")
        incomplete_model = incomplete_models["operation_models"][0][
            "obligation_models"
        ][0]
        incomplete_model["goto_model_sha256"] = None
        incomplete_model["nonvacuity_goto_model_sha256"] = None
        incomplete_execution_binding = {
            "proof_model_sha256": incomplete_shards[0][
                "proof_model_sha256"
            ],
            "nonvacuity_proof_model_sha256": incomplete_shards[0][
                "nonvacuity_proof_model_sha256"
            ],
            "property_checker_command_sha256": incomplete_shards[0][
                "property_checker_command_sha256"
            ],
            "nonvacuity_checker_command_sha256": incomplete_shards[0][
                "nonvacuity_checker_command_sha256"
            ],
            "goto_model_sha256": None,
            "nonvacuity_goto_model_sha256": None,
        }
        incomplete_shards[0]["execution_binding_sha256"] = (
            canonical_sha256_v3(incomplete_execution_binding)
        )
        incomplete_model["execution_binding_sha256"] = incomplete_shards[0][
            "execution_binding_sha256"
        ]
        incomplete = build_contextual_refinement_v2(
            **{
                **arguments,
                "models": incomplete_models,
                "shard_results": incomplete_shards,
            },
            checker={
                "model_bounds": {"private_stack_disjoint_checked_image": True}
            },
        )
        self.assertEqual(incomplete["status"], "incomplete")
        self.assertFalse(incomplete["activation_authorized"])



if __name__ == "__main__":
    unittest.main()
