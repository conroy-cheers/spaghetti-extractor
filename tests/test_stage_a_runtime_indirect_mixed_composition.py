from __future__ import annotations

import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.runtime_indirect_mixed_composition import (
    GuardedCutSpec,
    GuardedIncomingEdgeSpec,
    RuntimeIndirectMixedCompositionGenerationError,
    guarded_cut_source,
)


class StageARuntimeIndirectMixedCompositionTests(unittest.TestCase):
    def test_runtime_cut_kernel_has_no_universal_step_premises(self) -> None:
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
            / "RelationalGuardedRuntimeCut.lean"
        ).read_text(encoding="utf-8")
        self.assertIn("CheckedMixedOperationalCut", source)
        for forbidden in (
            "CompleteIncomingClassification",
            "IncomingGuardExcludes",
            "incomingComplete",
            "guardExcludes",
            "CheckedInvariantOperationalCut",
        ):
            self.assertNotIn(forbidden, source)

    def test_guarded_cut_emits_exact_checked_authority(self) -> None:
        source = guarded_cut_source(
            GuardedCutSpec(
                definition_name="generatedConstructorCut",
                context_name="Fixture.originalContext",
                decoded_authority_name="Fixture.originalAuthority",
                frontier_id="runtime-indirect:constructor-table",
                source_target_id=2595,
                incoming_edges=(
                    GuardedIncomingEdgeSpec(
                        source_target_id=2594,
                        target_target_id=2595,
                        guard_id="guard:constructor-count-nonzero",
                    ),
                ),
                imports=("StageA.Fixture",),
            )
        )

        self.assertIn("CheckedCertificate Fixture.originalContext", source)
        self.assertIn(".checked Fixture.originalContext = true", source)
        self.assertIn("runtime-indirect:constructor-table", source)
        self.assertNotIn("status", source)
        self.assertNotIn("remaining_premises", source)

    def test_guarded_cut_rejects_missing_or_ambiguous_guards(self) -> None:
        with self.assertRaisesRegex(
            RuntimeIndirectMixedCompositionGenerationError,
            "no incoming edges",
        ):
            guarded_cut_source(
                GuardedCutSpec(
                    definition_name="generatedCut",
                    context_name="Fixture.context",
                    decoded_authority_name="Fixture.authority",
                    frontier_id="runtime-indirect:cut",
                    source_target_id=10,
                    incoming_edges=(),
                )
            )

    def test_no_generator_accepts_caller_supplied_operational_proofs(
        self,
    ) -> None:
        module = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "relational"
            / "lean"
            / "runtime_indirect_mixed_composition.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "GuardedOperationalCutSpec",
            "RuntimeIndirectAggregateSpec",
            "chunk_closed_name",
            "route_invariant_name",
            "stack_range_projection_name",
            "guarded_operational_cut_source",
            "runtime_indirect_aggregate_source",
            "native_decide",
        ):
            self.assertNotIn(forbidden, module)

    def test_guarded_cut_rejects_duplicate_edges(self) -> None:
        duplicated = GuardedIncomingEdgeSpec(9, 10, "guard:same")
        with self.assertRaisesRegex(
            RuntimeIndirectMixedCompositionGenerationError,
            "duplicates an incoming edge",
        ):
            guarded_cut_source(
                GuardedCutSpec(
                    definition_name="generatedCut",
                    context_name="Fixture.context",
                    decoded_authority_name="Fixture.authority",
                    frontier_id="runtime-indirect:cut",
                    source_target_id=10,
                    incoming_edges=(duplicated, duplicated),
                )
            )

if __name__ == "__main__":
    unittest.main()
