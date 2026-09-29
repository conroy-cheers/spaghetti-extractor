"""Exact typed aggregation of contextual model bounds."""
from __future__ import annotations

import copy
import unittest
from spaghetti_extractor.components.bisimulation import ComponentBisimulationError
from spaghetti_extractor.components.contextual_bisimulation import _validate_contextual_model_bounds


class ContextualModelBoundTests(unittest.TestCase):
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
