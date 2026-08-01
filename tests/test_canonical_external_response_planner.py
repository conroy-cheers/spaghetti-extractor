from __future__ import annotations

import unittest

from spaghetti_extractor.relational.lean.canonical_external_response import (
    CanonicalExternalResponsePlanError,
    plan_canonical_external_response,
)


def _contract(**overrides: object) -> dict[str, object]:
    contract: dict[str, object] = {
        "id": 7,
        "disposition": "returns",
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
        "result_register_relations": [],
    }
    contract.update(overrides)
    return contract


class CanonicalExternalResponsePlannerTests(unittest.TestCase):
    def test_no_effect_recipe_is_untrusted_and_preserving(self) -> None:
        recipe = plan_canonical_external_response(_contract()).to_dict()
        self.assertEqual(recipe["memory_strategy"], "preserve_memory")
        self.assertEqual(recipe["world_strategy"], "preserve_world")
        self.assertFalse(recipe["proof_authority"])
        self.assertEqual(recipe["runtime_requirements"], [])

    def test_argument_ranges_require_both_runtime_footprint_checks(self) -> None:
        recipe = plan_canonical_external_response(
            _contract(memory_effect="argumentRanges")
        )
        self.assertIn(
            "both_runtime_memory_footprint_inventories_valid",
            recipe.runtime_requirements,
        )

    def test_nonnullable_allocation_requires_positive_size_and_fresh_pair(self) -> None:
        recipe = plan_canonical_external_response(
            _contract(
                memory_effect="newDynamicRanges",
                world_effect="dynamicRanges",
                result_register_relations=[
                    {
                        "register": "eax",
                        "relation": "dynamic_range_base",
                        "nullable": False,
                    }
                ],
            )
        )
        self.assertEqual(recipe.result_registers[0].strategy, "fresh_paired_range")
        self.assertIn(
            "positive_runtime_allocation_size:eax", recipe.runtime_requirements
        )
        self.assertIn(
            "fresh_disjoint_paired_dynamic_range:eax",
            recipe.runtime_requirements,
        )

    def test_nullable_allocation_may_return_null_without_fresh_space(self) -> None:
        recipe = plan_canonical_external_response(
            _contract(
                memory_effect="newDynamicRanges",
                world_effect="dynamicRanges",
                result_register_relations=[
                    {
                        "register": "eax",
                        "relation": "dynamic_range_base",
                        "nullable": True,
                    }
                ],
            )
        )
        self.assertEqual(
            recipe.result_registers[0].strategy, "null_or_fresh_paired_range"
        )
        self.assertNotIn(
            "positive_runtime_allocation_size:eax", recipe.runtime_requirements
        )

    def test_release_and_callback_keep_state_indexed_witnesses_explicit(self) -> None:
        release = plan_canonical_external_response(
            _contract(
                world_effect="dynamicRangeRelease", world_effect_argument=1
            )
        )
        self.assertEqual(release.world_argument_index, 1)
        self.assertIn(
            "nonzero_arguments_identify_one_existing_paired_dynamic_range",
            release.runtime_requirements,
        )

        callback = plan_canonical_external_response(
            _contract(
                world_effect="callbackRegistration", world_effect_argument=2
            )
        )
        self.assertIn(
            "arguments_identify_one_valid_paired_callback",
            callback.runtime_requirements,
        )

    def test_nonreturning_and_malformed_contracts_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            CanonicalExternalResponsePlanError, "returning contracts"
        ):
            plan_canonical_external_response(_contract(disposition="protocol"))
        with self.assertRaisesRegex(
            CanonicalExternalResponsePlanError, "dynamic-range result"
        ):
            plan_canonical_external_response(
                _contract(
                    memory_effect="newDynamicRanges", world_effect="dynamicRanges"
                )
            )


if __name__ == "__main__":
    unittest.main()
