from __future__ import annotations

import dataclasses
import re
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.nullable_code_pointer_dispatch import (
    NullableCodePointerDispatchGenerationError,
    NullableCodePointerDispatchSpec,
    PairedDecodedRegionProposal,
    nullable_code_pointer_dispatch_source,
)


def _region(target_id: int, rva: int, size: int = 4) -> PairedDecodedRegionProposal:
    return PairedDecodedRegionProposal(target_id, rva, size, rva, size)


def dispatch_spec() -> NullableCodePointerDispatchSpec:
    return NullableCodePointerDispatchSpec(
        definition_name="nullableDispatch",
        context_name="Fixture.context",
        table_certificate_name="Fixture.tableCertificate",
        table_call_name="Fixture.tableCall",
        scanner_name="Fixture.scanner",
        scanner_source_invariant_name="Fixture.scannerSourceInvariant",
        scanner_post_invariant_name="Fixture.scannerPostInvariant",
        scanner_finished_invariant_name="Fixture.scannerFinishedInvariant",
        dispatch_invariant_name="Fixture.dispatchInvariant",
        scanner_region=_region(0, 0x1000, 12),
        test_region=_region(1, 0x1010, 2),
        bridge_region=_region(2, 0x1020, 2),
        guard_region=_region(3, 0x1030, 5),
        dispatch_region=_region(4, 0x1040, 7),
        dispatch_bypass_target_id=6,
        dispatch_predecessor_ids=(3,),
        original_dispatch_base=0x402000,
        candidate_dispatch_base=0x502000,
        imports=("StageA.Generated.NullableFixture",),
    )


class StageANullableCodePointerDispatchTests(unittest.TestCase):
    def test_emits_exact_binding_and_typed_composition_premise(self) -> None:
        source = nullable_code_pointer_dispatch_source(dispatch_spec())

        for fragment in (
            "dispatchPredecessorIds := [3]",
            "dispatchScale := 4",
            "dispatchIndexOffset := 0",
            "nullableDispatch.checked Fixture.context = true",
            "CompleteDispatchPredecessorPremise",
            "ActualDecodedMixedDispatchClosure",
            "structurallyValid",
        ):
            self.assertIn(fragment, source)
        self.assertNotIn("native_decide", source)
        self.assertNotIn("acceptance_authority", source)

    def test_rejected_binding_remains_a_lean_decision(self) -> None:
        source = nullable_code_pointer_dispatch_source(
            dataclasses.replace(dispatch_spec(), definition_name="badScale"),
            expectation="rejected",
        )

        self.assertIn("badScale.checked Fixture.context = false", source)
        self.assertNotIn("badScaleClosure", source)

    def test_rejects_malformed_names_spans_and_words(self) -> None:
        with self.assertRaises(NullableCodePointerDispatchGenerationError):
            nullable_code_pointer_dispatch_source(
                dataclasses.replace(dispatch_spec(), definition_name="bad-name")
            )
        with self.assertRaises(NullableCodePointerDispatchGenerationError):
            nullable_code_pointer_dispatch_source(
                dataclasses.replace(
                    dispatch_spec(),
                    scanner_region=_region(0, 0x1000, 0),
                )
            )
        with self.assertRaises(NullableCodePointerDispatchGenerationError):
            nullable_code_pointer_dispatch_source(
                dataclasses.replace(
                    dispatch_spec(), original_dispatch_base=1 << 32
                )
            )

    def test_reviewed_bridge_has_no_escape_markers_or_trusted_empty_lists(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalNullableCodePointerDispatch.lean"
        ).read_text(encoding="utf-8")

        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for required in (
            "regionBehaviorWithMachineCallContracts",
            "normalizeSymbolicBehavior",
            "tableCertificateCheckedAgainst",
            "claim.tableCall.staticShapeChecked context",
            "claim.tableCall.rowsChecked context",
            "claim.scanner.checked context",
            "claim.scanner.exitChecked",
            "EmptyLocalDispatchClosed",
            "CompleteDispatchPredecessorPremise",
            "actualDispatchSourceUninhabited_of_complete_predecessors",
            "boundedImmutableCodePointerTableCallTargetsClosed_of_checked",
        ):
            self.assertIn(required, source)
        checked_against = source[
            source.index("def tableCertificateCheckedAgainst") :
            source.index("def bridgeBehaviorChecked")
        ]
        self.assertNotIn("certificate.writers", checked_against)
        self.assertNotIn("certificate.aliases", checked_against)


if __name__ == "__main__":
    unittest.main()
