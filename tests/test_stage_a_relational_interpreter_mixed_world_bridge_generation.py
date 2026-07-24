from __future__ import annotations

import dataclasses
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_world_bridge import (
    INTERPRETER_MIXED_WORLD_BRIDGE_MODULE,
    InterpreterMixedWorldBridgeGenerationError,
    InterpreterMixedWorldBridgeSpec,
    relational_interpreter_mixed_world_bridge_source,
    write_relational_interpreter_mixed_world_bridge,
)


def _spec(**changes: str | None) -> InterpreterMixedWorldBridgeSpec:
    base = InterpreterMixedWorldBridgeSpec(
        binding_module="StageA.Bindings",
        namespace="StageA.Generated.MixedAcceptance",
        original_context="requirements.originalContext",
        original_program="requirements.originalProgram",
        candidate_program="requirements.candidateProgram",
        contract="requirements.contract",
        launch="requirements.launch",
        original_authority="requirements.originalAuthority",
        candidate_authority="requirements.candidateAuthority",
        program_binding="requirements.programBinding",
        original_root="requirements.originalRoot",
        reachability="requirements.reachability",
        candidate_root_rva="requirements.candidateRootRva",
        candidate_root="requirements.candidateRoot",
        launch_realizable="requirements.launchRealizable",
        invariant="requirements.invariant",
        candidate_launch_calls="requirements.candidateLaunchCalls",
        candidate_launch_calls_exact="requirements.candidateLaunchCallsExact",
        roots_related="requirements.rootsRelated",
        component="requirements.component",
        requirement_parameter="requirements",
        requirement_type="StageA.Bindings.RequiredTerms",
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterMixedWorldBridgeGenerationTests(
    unittest.TestCase
):
    def test_source_assembles_only_checked_mixed_terms(self) -> None:
        source = relational_interpreter_mixed_world_bridge_source(_spec())

        self.assertIn("MixedWorldChunkComposition", source)
        self.assertIn("MixedWorldAcceptanceCertificate", source)
        self.assertIn("mixedWorldProgramsEquivalent", source)
        self.assertIn("mixedWorldProgramsEquivalent_trace", source)
        self.assertIn("candidateLaunchCallsExact", source)
        self.assertNotIn("WorldNativeAcceptanceCertificate", source)
        for marker in ("sorry", "axiom", "opaque", "status"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writer_is_deterministic(self) -> None:
        spec = _spec()
        expected = relational_interpreter_mixed_world_bridge_source(spec)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_relational_interpreter_mixed_world_bridge(root, spec)
            first_bytes = first.read_bytes()
            second = write_relational_interpreter_mixed_world_bridge(root, spec)
            second_bytes = second.read_bytes()

        self.assertEqual(
            first.name, f"{INTERPRETER_MIXED_WORLD_BRIDGE_MODULE}.lean"
        )
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_rejects_malformed_names_and_partial_requirement_pair(self) -> None:
        for change in (
            {"binding_module": "Bindings"},
            {"namespace": "StageA.Bad-Namespace"},
            {"component": "requirements.bad term"},
            {"composition_name": "StageA.composition"},
            {"requirement_type": None},
        ):
            with self.subTest(change=change):
                with self.assertRaises(InterpreterMixedWorldBridgeGenerationError):
                    relational_interpreter_mixed_world_bridge_source(_spec(**change))


if __name__ == "__main__":
    unittest.main()
