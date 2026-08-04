from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_indirect_import_call_semantic_evidence import (
    GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_BUNDLE,
    GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError,
    GnuHelloMixedIndirectImportCallSemanticEvidenceSpec,
    generate_gnu_hello_mixed_indirect_import_call_semantic_evidence,
    write_gnu_hello_mixed_indirect_import_call_semantic_evidence,
)
from tests.test_stage_a_gnu_hello_mixed_direct_call_semantic_evidence import (
    _row,
)


def _call_row(
    identity: str,
    start: int,
    *,
    operand: str,
    call_kind: str,
) -> dict[str, object]:
    row = _row(
        identity,
        start,
        mnemonic="call",
        operand=operand,
    )
    row["external_events"] = [
        {
            "kind": call_kind,
            "return_rva": start + 1,
        }
    ]
    return row


class StageAGnuHelloMixedIndirectImportCallSemanticEvidenceTests(
    unittest.TestCase
):
    def test_owns_exact_non_immediate_call_partition(self) -> None:
        rows = [
            _row("ordinary", 0x1000),
            _row("direct", 0x2000, mnemonic="call", operand="0x3000"),
            _call_row(
                "external",
                0x3000,
                operand="dword ptr [0x432100]",
                call_kind="external_call",
            ),
            _call_row(
                "indirect",
                0x4000,
                operand="eax",
                call_kind="indirect_call",
            ),
            _call_row(
                "internal",
                0x5000,
                operand="dword ptr [ebx*4 + 0x428000]",
                call_kind="internal_call",
            ),
            _row("boundary", 0x6000, outcome="external_jump"),
            _row("x87", 0x7000, x87=True),
        ]
        bundle = (
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                rows,
                GnuHelloMixedIndirectImportCallSemanticEvidenceSpec(
                    fused_shard_size=2,
                    shard_size=2,
                ),
            )
        )
        inventory = bundle.inventory

        self.assertEqual(inventory["input_rows"], 7)
        self.assertEqual(inventory["indirect_import_call_rows"], 3)
        self.assertEqual(
            inventory["generated_indirect_import_call_evidence_adapters"], 3
        )
        self.assertEqual(
            inventory["semantic_call_kind_counts"],
            {
                "external_call": 1,
                "indirect_call": 1,
                "internal_call": 1,
            },
        )
        self.assertEqual(
            inventory["unowned_family_counts"],
            {
                "dedicated-direct-call-return": 1,
                "dedicated-external-boundary": 1,
                "dedicated-x87-replay": 1,
                "ordinary-one-step": 1,
            },
        )
        boundary = inventory["checked_boundary"]
        self.assertTrue(
            boundary["semantic_call_bound_to_exact_normalized_pe_span"]
        )
        self.assertTrue(
            boundary["indirect_targets_use_generic_checked_provenance"]
        )
        self.assertTrue(
            boundary["original_path_selected_by_operational_completeness"]
        )
        self.assertTrue(
            boundary["candidate_path_starts_at_exact_candidate_before_world"]
        )
        self.assertFalse(
            boundary[
                "paths_endpoints_observations_statuses_accepted_from_json"
            ]
        )
        self.assertFalse(inventory["proof_authority"])
        self.assertFalse(inventory["acceptance_authority"])

        source = "\n".join(bundle.sources.values())
        self.assertEqual(
            source.count(
                "noncomputable def "
                "generatedCheckedMixedIndirectImportCallSemanticEvidence"
            ),
            3,
        )
        for required in (
            "CheckedIndirectOrImportCallStaticBinding",
            "ExactIndirectOrImportCallOperationalCompleteness",
            "CheckedIndirectOrImportMixedSemanticOperationInput",
            "generatedCheckedFusedOriginalSemanticBinding2",
            "generatedCheckedFusedOriginalSemanticBinding3",
            "generatedCheckedFusedOriginalSemanticBinding4",
            "input.toEvidence",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "generatedCheckedMixedIndirectImportCallSemanticEvidence0",
            "generatedCheckedMixedIndirectImportCallSemanticEvidence1",
            "submittedPath",
            "submittedEndpoint",
            "submittedObservations",
            "submittedStatus",
            "native_decide",
            "sorry",
            "axiom ",
        ):
            self.assertNotIn(forbidden, source)

    def test_fused_imports_follow_stable_binding_positions(self) -> None:
        rows = [
            _row("ordinary", 0x1000),
            _call_row(
                "external",
                0x2000,
                operand="dword ptr [0x432100]",
                call_kind="external_call",
            ),
            _row("ordinary-b", 0x3000),
            _call_row(
                "indirect",
                0x4000,
                operand="eax",
                call_kind="indirect_call",
            ),
        ]
        bundle = (
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                rows,
                GnuHelloMixedIndirectImportCallSemanticEvidenceSpec(
                    fused_shard_size=2,
                    shard_size=2,
                ),
            )
        )
        shard = bundle.sources[
            "GeneratedGnuHelloMixedIndirectImportCallSemanticEvidenceShard0000"
        ]
        self.assertIn(
            "import StageA.GeneratedGnuHelloMixedFusedSemanticEvidenceShard0000",
            shard,
        )
        self.assertIn(
            "import StageA.GeneratedGnuHelloMixedFusedSemanticEvidenceShard0001",
            shard,
        )

    def test_writer_is_deterministic_and_inventory_is_non_authoritative(
        self,
    ) -> None:
        bundle = (
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                [
                    _call_row(
                        "indirect",
                        0x1000,
                        operand="eax",
                        call_kind="indirect_call",
                    )
                ]
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_inventory, first_sources = (
                write_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                    root, bundle
                )
            )
            first_bytes = {
                path.relative_to(root): path.read_bytes()
                for path in (first_inventory, *first_sources)
            }
            second_inventory, second_sources = (
                write_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                    root, bundle
                )
            )
            second_bytes = {
                path.relative_to(root): path.read_bytes()
                for path in (second_inventory, *second_sources)
            }

        self.assertEqual(first_bytes, second_bytes)
        payload = json.loads(
            first_bytes[first_inventory.relative_to(root)].decode("utf-8")
        )
        self.assertFalse(payload["proof_authority"])
        self.assertEqual(
            payload["target"],
            GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_BUNDLE,
        )

    def test_rejects_malformed_call_event_inventory_and_names(self) -> None:
        missing = _call_row(
            "missing",
            0x1000,
            operand="eax",
            call_kind="indirect_call",
        )
        missing["external_events"] = []
        with self.assertRaisesRegex(
            GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError,
            "exactly one semantic call event",
        ):
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                [missing]
            )

        unknown = _call_row(
            "unknown",
            0x2000,
            operand="eax",
            call_kind="unknown_call",
        )
        with self.assertRaisesRegex(
            GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError,
            "unsupported call kind",
        ):
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                [unknown]
            )

        duplicate = _call_row(
            "duplicate",
            0x3000,
            operand="eax",
            call_kind="indirect_call",
        )
        duplicate["external_events"] = copy.deepcopy(
            duplicate["external_events"]
        ) * 2
        with self.assertRaisesRegex(
            GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError,
            "exactly one semantic call event",
        ):
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                [duplicate]
            )

        with self.assertRaisesRegex(
            GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError,
            "fused_binding_prefix",
        ):
            generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
                [
                    _call_row(
                        "indirect",
                        0x4000,
                        operand="eax",
                        call_kind="indirect_call",
                    )
                ],
                GnuHelloMixedIndirectImportCallSemanticEvidenceSpec(
                    fused_binding_prefix="bad; binding"
                ),
            )


if __name__ == "__main__":
    unittest.main()
