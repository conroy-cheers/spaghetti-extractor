from __future__ import annotations

import unittest

from spaghetti_extractor.relational.lean.callable_external_mixed_bridge import (
    CALLABLE_EXTERNAL_MIXED_BRIDGE_FORMAT,
    CallableExternalMixedBridgeError,
    parse_callable_external_mixed_bridge_binding,
    relational_callable_external_mixed_bridge_source,
)


def _binding() -> dict[str, object]:
    return {
        "format": CALLABLE_EXTERNAL_MIXED_BRIDGE_FORMAT,
        "namespace": "StageA.GeneratedRelational.CallableMixed",
        "imports": ["StageA.GeneratedCallableInventory"],
        "context_term": "Fixture.context",
        "callable_program_term": "Fixture.callableProgram",
        "candidate_program_term": "Fixture.candidateProgram",
        "candidate_program_binding_term": "Fixture.candidateProgramBinding",
        "capability_inventory_term": "Fixture.capabilities",
        "resolved_abi_inventory_term": "Fixture.resolvedABIs",
    }


class StageACallableExternalMixedBridgeTests(unittest.TestCase):
    def test_generator_emits_only_typed_term_bindings(self) -> None:
        parsed = parse_callable_external_mixed_bridge_binding(_binding())
        self.assertEqual(parsed.context_term, "Fixture.context")

        source = relational_callable_external_mixed_bridge_source(_binding())
        self.assertIn(
            "def generatedCandidateKernelCallableFrontier :\n"
            "    CandidateKernelCallableFrontier :=",
            source,
        )
        self.assertIn("Fixture.candidateProgram", source)
        self.assertIn("def generatedCandidateNativeCallableFrontier", source)
        for forbidden in (
            "proof_status",
            "accepted",
            "verified",
            "trace :=",
            "observation :=",
            "sorry",
            "native_decide",
            "axiom ",
            "unsafe ",
        ):
            self.assertNotIn(forbidden, source)

    def test_generator_rejects_status_and_transition_claims(self) -> None:
        for field, value in (
            ("proof_status", "checked"),
            ("accepted", True),
            ("native_transition", "Fixture.claim"),
            ("external_trace", []),
        ):
            payload = {**_binding(), field: value}
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    CallableExternalMixedBridgeError, "unexpected fields"
                ):
                    parse_callable_external_mixed_bridge_binding(payload)

    def test_generator_rejects_injection_and_duplicate_imports(self) -> None:
        payload = {**_binding(), "context_term": "Fixture.context; axiom bad : True"}
        with self.assertRaisesRegex(
            CallableExternalMixedBridgeError, "qualified Lean identifier"
        ):
            parse_callable_external_mixed_bridge_binding(payload)

        duplicate = {
            **_binding(),
            "imports": [
                "StageA.GeneratedCallableInventory",
                "StageA.GeneratedCallableInventory",
            ],
        }
        with self.assertRaisesRegex(
            CallableExternalMixedBridgeError, "duplicate modules"
        ):
            parse_callable_external_mixed_bridge_binding(duplicate)


if __name__ == "__main__":
    unittest.main()
