from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.internal_direct_call_composition import (
    INTERNAL_DIRECT_CALL_COMPOSITION_LEAN_FILENAME,
    InternalDirectCallCompositionGenerationError,
    InternalDirectCallCompositionLeanBindings,
    internal_direct_call_composition_source,
    write_internal_direct_call_composition,
)


def bindings(*, complete: bool = False) -> InternalDirectCallCompositionLeanBindings:
    return InternalDirectCallCompositionLeanBindings(
        context="StageA.Fixture.context",
        summary_tree="StageA.Fixture.tree",
        premises="StageA.Fixture.premises" if complete else None,
        imports=("StageA.InternalDirectCallCompositionFixture",),
    )


class StageAInternalDirectCallCompositionGenerationTests(unittest.TestCase):
    def test_incomplete_binding_is_explicit_non_authority(self) -> None:
        source = internal_direct_call_composition_source(
            bindings(), expectation="incomplete"
        )

        self.assertIn("generatedIntegratedSummaryPremises", source)
        self.assertIn(" := none", source)
        self.assertIn("generatedStandaloneAcceptanceAuthority = false", source)
        self.assertNotIn("generatedSemanticContract", source)
        self.assertNotIn("generatedCheckedDirectCallSummaryProvenance", source)

    def test_complete_binding_exports_composable_contract_and_provenance(self) -> None:
        source = internal_direct_call_composition_source(
            bindings(complete=True), expectation="complete"
        )

        self.assertIn("StageA.Fixture.premises", source)
        self.assertIn("generatedCompletePremises.toSemanticContract", source)
        self.assertIn("CheckedDirectCallSummaryProvenance", source)
        self.assertIn("generatedStandaloneAcceptanceAuthority = true", source)
        self.assertNotIn("proposal_status", source)
        self.assertNotIn("graph_reachable", source)

    def test_complete_requires_a_lean_semantic_witness(self) -> None:
        with self.assertRaisesRegex(
            InternalDirectCallCompositionGenerationError,
            "requires an operationally complete IntegratedSummaryPremises term",
        ):
            internal_direct_call_composition_source(
                bindings(), expectation="complete"
            )

    def test_incomplete_rejects_hidden_semantic_authority(self) -> None:
        with self.assertRaisesRegex(
            InternalDirectCallCompositionGenerationError,
            "must not carry semantic premises",
        ):
            internal_direct_call_composition_source(
                bindings(complete=True), expectation="incomplete"
            )

    def test_identifiers_and_imports_are_strict(self) -> None:
        malformed = InternalDirectCallCompositionLeanBindings(
            context="Fixture.context; #eval 1",
            summary_tree="Fixture.tree",
        )
        with self.assertRaisesRegex(
            InternalDirectCallCompositionGenerationError,
            "qualified Lean identifier",
        ):
            internal_direct_call_composition_source(
                malformed, expectation="incomplete"
            )

        duplicates = InternalDirectCallCompositionLeanBindings(
            context="Fixture.context",
            summary_tree="Fixture.tree",
            imports=("StageA.Fixture", "StageA.Fixture"),
        )
        with self.assertRaisesRegex(
            InternalDirectCallCompositionGenerationError, "duplicate module"
        ):
            internal_direct_call_composition_source(
                duplicates, expectation="incomplete"
            )

    def test_generated_source_contains_no_proof_escape_hatches(self) -> None:
        for complete in (False, True):
            source = internal_direct_call_composition_source(
                bindings(complete=complete),
                expectation="complete" if complete else "incomplete",
            )
            for marker in ("sorry", "native_decide", "axiom ", "unsafe "):
                self.assertNotIn(marker, source)

    def test_writer_uses_dedicated_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = (
                Path(temporary) / INTERNAL_DIRECT_CALL_COMPOSITION_LEAN_FILENAME
            )
            result = write_internal_direct_call_composition(
                destination, bindings(), expectation="incomplete"
            )
            self.assertEqual(result, destination)
            self.assertIn(
                "generatedStandaloneAcceptanceAuthorityFalse",
                destination.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
