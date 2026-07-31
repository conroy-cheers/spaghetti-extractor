from __future__ import annotations

import dataclasses
import re
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.nullable_code_pointer_rooted_unreachability import (
    NullableCodePointerRootedUnreachabilityGenerationError,
    NullableCodePointerRootedUnreachabilitySpec,
    OriginalIncomingEdgeProposal,
    nullable_code_pointer_rooted_unreachability_source,
)
from spaghetti_extractor.relational.lean.scanner import (
    OriginalDecodedScannerRegionProposal,
    OriginalScannerExecutionProposal,
)


def scanner_region(
    target_id: int,
) -> OriginalDecodedScannerRegionProposal:
    return OriginalDecodedScannerRegionProposal(
        target_id=target_id,
        rva=0x1000 + target_id * 0x10,
        size=4,
    )


def rooted_spec() -> NullableCodePointerRootedUnreachabilitySpec:
    return NullableCodePointerRootedUnreachabilitySpec(
        definition_name="rootedEmptyDispatch",
        original_context_name="Fixture.originalContext",
        empty_indexed_authority_name="Fixture.emptyIndexedAuthority",
        root_target_ids=(0, 7),
        root_path_target_ids=(0, 8, 10, 11),
        forward_target_ids=(11, 12, 14),
        scc_target_ids=(11, 12),
        incoming_edges=(
            OriginalIncomingEdgeProposal(10, 11),
            OriginalIncomingEdgeProposal(12, 11),
            OriginalIncomingEdgeProposal(11, 12),
        ),
        scanner_execution=OriginalScannerExecutionProposal(
            table_base=0x402000,
            scanner_register="eax",
            count_register="ebx",
            loaded_register="edx",
            selector_region=scanner_region(8),
            zero_region=scanner_region(15),
            scanner_region=scanner_region(16),
            bridge_region=scanner_region(9),
            gate_region=scanner_region(10),
            dispatch_source_target_id=11,
            dispatch_bypass_target_id=14,
        ),
        imports=("StageA.Generated.NullableDispatchFixture",),
    )


class StageANullableCodePointerRootedUnreachabilityTests(unittest.TestCase):
    def test_emits_checked_root_edge_authority_and_original_closure(self) -> None:
        source = nullable_code_pointer_rooted_unreachability_source(rooted_spec())

        for fragment in (
            "rootTargetIds := [0, 7]",
            "sourceTargetId := 10, targetTargetId := 11",
            "rootPathTargetIds := [0, 8, 10, 11]",
            "forwardTargetIds := [11, 12, 14]",
            "sccTargetIds := [11, 12]",
            "RootedSccCertificate",
            "CheckedRootedSccCertificate",
            "decodedAuthority := Fixture.emptyIndexedAuthority.decodedAuthority",
            "OriginalScannerExecutionClaim",
            "CheckedOriginalScannerExecution",
            "CheckedRootedScannerSccExecution",
            "OriginalScannerExecutionResult",
            "RootedScannerOperationalReachable",
            "Fixture.emptyIndexedAuthority",
            "ScannerExecution",
            "ScannerBypassReachable",
            "SccExclusion",
            "SourceExcluded",
            "decide +kernel",
        ):
            self.assertIn(fragment, source)
        for marker in ("native_decide", "acceptance_authority", "gnu", "0xa220"):
            self.assertNotIn(marker, source.lower())

    def test_rejected_certificate_emits_no_authority_or_closure(self) -> None:
        source = nullable_code_pointer_rooted_unreachability_source(
            dataclasses.replace(
                rooted_spec(), definition_name="rejectedRootedDispatch"
            ),
            expectation="rejected",
        )

        self.assertIn("= false := by", source)
        self.assertNotIn("rejectedRootedDispatchAuthority", source)
        self.assertNotIn("rejectedRootedDispatchClosure", source)
        self.assertNotIn("CheckedRootedScannerSccExecution", source)

    def test_rejects_unrepresentable_names_ids_and_edge_values(self) -> None:
        with self.assertRaises(
            NullableCodePointerRootedUnreachabilityGenerationError
        ):
            nullable_code_pointer_rooted_unreachability_source(
                dataclasses.replace(rooted_spec(), definition_name="bad-name")
            )
        with self.assertRaises(
            NullableCodePointerRootedUnreachabilityGenerationError
        ):
            nullable_code_pointer_rooted_unreachability_source(
                dataclasses.replace(rooted_spec(), root_target_ids=(-1,))
            )
        with self.assertRaises(
            NullableCodePointerRootedUnreachabilityGenerationError
        ):
            nullable_code_pointer_rooted_unreachability_source(
                dataclasses.replace(rooted_spec(), incoming_edges=(object(),))
            )

    def test_lean_checker_contains_no_escape_hatches_or_source_name_logic(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalNullableCodePointerDispatch.lean"
        ).read_text(encoding="utf-8")

        for marker in ("sorry", "axiom", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        for required in (
            "certificate.headerWords == [2 ^ 32 - 1]",
            "(table.originalAddress table.upperExclusive) 4 == some 0",
            "table.staticShapeChecked context",
            "table.rowsChecked context",
            "originalRootTargetIds",
            "originalIncomingEdgesForTargets",
            "originalGraphSource?",
            "originalReachabilityWithin",
            "originalSccChecked",
            "originalForwardClosedChecked",
            "originalSccBoundaryChecked",
            "originalRootPathChecked",
            "RootedSccCertificate.checked",
            "executePE32SymbolicSpan",
            "OriginalScannerExecutionClaim.checked",
            "gateCountZero",
            "CheckedRootedScannerSccExecution",
            "RootedScannerOperationalReachable",
            "scannerBypassReachable",
            "phaseUnreachable",
            "sccUnreachable",
        ):
            self.assertIn(
                required,
                source
                + (
                    Path(__file__).parents[1]
                    / "src/spaghetti_extractor/lean/StageA/"
                    "RelationalNullableCodePointerRootedUnreachability.lean"
                ).read_text(encoding="utf-8"),
            )
        self.assertNotRegex(source.lower(), r"\bgnu\b|0xa220")


if __name__ == "__main__":
    unittest.main()
