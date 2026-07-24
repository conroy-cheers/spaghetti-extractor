from __future__ import annotations

import re
import unittest
from copy import deepcopy
from typing import Any

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.callable_external_execution import (
    CALLABLE_EXTERNAL_EXECUTION_FORMAT,
    CALLABLE_EXTERNAL_PROGRAM_MODULE,
    classify_original_indirect_matches,
    parse_callable_external_execution_artifact,
    relational_callable_external_execution_source,
    relational_callable_external_program_source,
)


def _execution_artifact() -> dict[str, Any]:
    return {
        "format": CALLABLE_EXTERNAL_EXECUTION_FORMAT,
        "sites": [
            {
                "kind": "ordinary",
                "id": 4,
                "source_target_id": 10,
                "machine_contract_id": 12,
                "argument_sources": [{"kind": "stack_word", "offset": 0}],
            },
            {
                "kind": "resolver",
                "id": 8,
                "source_target_id": 11,
                "machine_contract_id": 17,
                "argument_sources": [
                    {"kind": "stack_word", "offset": 0},
                    {"kind": "stack_word", "offset": 4},
                ],
                "resolver_contract_id": 3,
                "capability_id": 41,
            },
        ],
    }


def _classify(**overrides: object) -> str:
    arguments: dict[str, object] = {
        "internal_matches": [],
        "import_matches": [],
        "resource_matches": [],
        "capability_resources": [(41, 41)],
        "abi_routes": [(41, "call"), (41, "jump")],
        "transfer": "call",
    }
    arguments.update(overrides)
    return classify_original_indirect_matches(**arguments)  # type: ignore[arg-type]


class StageACallableExternalExecutionTests(unittest.TestCase):
    def test_program_source_binds_checked_generated_inventories(self) -> None:
        source = relational_callable_external_program_source()
        self.assertEqual(
            CALLABLE_EXTERNAL_PROGRAM_MODULE,
            "GeneratedCallableExternalProgram",
        )
        self.assertIn(
            "generatedOriginalCarrierContextStructurallyValid",
            source,
        )
        self.assertIn("def originalCallableProgram", source)
        self.assertIn("theorem originalCallableProgramValid", source)
        self.assertNotIn("sorry", source)
        self.assertNotIn("native_decide", source)

    def test_emits_static_sites_without_runtime_observations(self) -> None:
        artifact = parse_callable_external_execution_artifact(
            _execution_artifact()
        )
        source = relational_callable_external_execution_source(
            _execution_artifact()
        )

        self.assertEqual([site.kind for site in artifact.sites], ["ordinary", "resolver"])
        self.assertIn("def originalExternalSite4 : OriginalExternalSite", source)
        self.assertIn("resolverContractId := some 3", source)
        self.assertIn("originalExternalSiteIdsUniqueChecked", source)
        for forbidden in (
            "globalExternalIndex :=",
            "externalTrace :=",
            "original_events",
            "candidate_events",
            "EventOrder",
            "native_decide",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_submitted_trace_or_result_authority_is_rejected(self) -> None:
        payload = deepcopy(_execution_artifact())
        payload["runtime_trace"] = []

        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_callable_external_execution_artifact(payload)

    def test_resolution_categories_are_strictly_classified(self) -> None:
        self.assertEqual(_classify(internal_matches=[7]), "internal")
        self.assertEqual(_classify(import_matches=[9]), "imported")
        self.assertEqual(_classify(resource_matches=[41]), "callable")
        self.assertEqual(_classify(), "unmapped")

    def test_cross_category_collisions_fail_as_ambiguous(self) -> None:
        cases = [
            {"internal_matches": [7], "import_matches": [9]},
            {"internal_matches": [7], "resource_matches": [41]},
            {"import_matches": [9], "resource_matches": [41]},
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(_classify(**case), "ambiguous")

    def test_duplicate_side_matches_fail_as_ambiguous(self) -> None:
        self.assertEqual(_classify(internal_matches=[7, 8]), "ambiguous")
        self.assertEqual(_classify(import_matches=[9, 10]), "ambiguous")
        self.assertEqual(_classify(resource_matches=[41, 41]), "ambiguous")

    def test_callable_requires_exact_resource_capability_and_abi_route(self) -> None:
        self.assertEqual(
            _classify(resource_matches=[42]),
            "invalid_callable",
        )
        self.assertEqual(
            _classify(
                resource_matches=[41],
                capability_resources=[(41, 41), (42, 41)],
            ),
            "invalid_callable",
        )
        self.assertEqual(
            _classify(resource_matches=[41], abi_routes=[]),
            "invalid_callable",
        )
        self.assertEqual(
            _classify(resource_matches=[41], transfer="jump", abi_routes=[(41, "call")]),
            "invalid_callable",
        )

    def test_site_routes_must_be_unique_and_canonical(self) -> None:
        duplicate = deepcopy(_execution_artifact())
        duplicate["sites"].append(deepcopy(duplicate["sites"][0]))
        duplicate["sites"][-1]["id"] = 12
        with self.assertRaisesRegex(StageAInputError, "routes are ambiguous"):
            parse_callable_external_execution_artifact(duplicate)

        unordered = deepcopy(_execution_artifact())
        unordered["sites"].reverse()
        with self.assertRaisesRegex(StageAInputError, "canonical id order"):
            parse_callable_external_execution_artifact(unordered)

    def test_site_arguments_must_be_exact_stack_sources(self) -> None:
        payload = deepcopy(_execution_artifact())
        payload["sites"][0]["argument_sources"] = [
            {"kind": "register", "register": "ecx"}
        ]

        with self.assertRaisesRegex(StageAInputError, "exact stack_word"):
            parse_callable_external_execution_artifact(payload)

    def test_internal_target_confusion_is_not_an_execution_field(self) -> None:
        payload = deepcopy(_execution_artifact())
        payload["sites"][1]["internal_target_id"] = 41

        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_callable_external_execution_artifact(payload)


if __name__ == "__main__":
    unittest.main()
