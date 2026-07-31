from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_mixed_external_tail_semantic_evidence import (
    GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_BUNDLE,
    GnuHelloMixedExternalTailSemanticEvidenceGenerationError,
    GnuHelloMixedExternalTailSemanticEvidenceSpec,
    generate_gnu_hello_mixed_external_tail_semantic_evidence,
    write_gnu_hello_mixed_external_tail_semantic_evidence,
)
from tests.test_stage_a_gnu_hello_mixed_direct_call_semantic_evidence import (
    _row,
)


def _tail_row(
    identity: str,
    start: int,
    *,
    operand: str = "0x414000",
) -> dict[str, object]:
    row = _row(
        identity,
        start,
        mnemonic="jmp",
        operand=operand,
        outcome="external_jump",
    )
    event = {
        "kind": "external_call",
        "dll": "msvcrt.dll",
        "symbol": "puts",
        "ordinal": None,
        "return_rva": start + 1,
    }
    row["external_events"] = [copy.deepcopy(event)]
    row["outcome"] = {
        "kind": "external_jump",
        "dll": "msvcrt.dll",
        "symbol": "puts",
        "ordinal": None,
    }
    return row


class StageAGnuHelloMixedExternalTailSemanticEvidenceTests(
    unittest.TestCase
):
    def test_owns_exact_external_tail_partition(self) -> None:
        rows = [
            _row("ordinary", 0x1000),
            _row("direct", 0x2000, mnemonic="call", operand="0x3000"),
            _row("indirect-call", 0x3000, mnemonic="call", operand="eax"),
            _tail_row("direct-tail", 0x4000),
            _tail_row(
                "indirect-tail",
                0x5000,
                operand="dword ptr [0x432100]",
            ),
            _row("x87", 0x6000, x87=True),
        ]
        bundle = generate_gnu_hello_mixed_external_tail_semantic_evidence(
            rows,
            GnuHelloMixedExternalTailSemanticEvidenceSpec(
                fused_shard_size=2,
                shard_size=1,
            ),
        )
        inventory = bundle.inventory

        self.assertEqual(inventory["input_rows"], 6)
        self.assertEqual(inventory["external_tail_rows"], 2)
        self.assertEqual(
            inventory["generated_external_tail_evidence_adapters"], 2
        )
        self.assertEqual(
            inventory["route_kind_counts"],
            {"direct": 1, "indirect": 1},
        )
        self.assertEqual(
            inventory["unowned_family_counts"],
            {
                "dedicated-direct-call-return": 1,
                "dedicated-indirect-or-import-call": 1,
                "dedicated-x87-replay": 1,
                "ordinary-one-step": 1,
            },
        )
        boundary = inventory["checked_boundary"]
        self.assertTrue(boundary["classifier_remains_semantic_transfer"])
        self.assertTrue(boundary["semantic_outcome_is_external_jump"])
        self.assertFalse(boundary["external_operation_classifier_used"])
        self.assertFalse(boundary["external_boundary_classifier_used"])
        self.assertTrue(boundary["original_path_is_definitionally_one_pe_step"])
        self.assertTrue(
            boundary["existing_caller_continuation_is_consumed"]
        )
        self.assertFalse(
            boundary[
                "paths_endpoints_observations_statuses_counts_accepted_from_json"
            ]
        )
        self.assertFalse(inventory["proof_authority"])
        self.assertFalse(inventory["acceptance_authority"])

        source = "\n".join(bundle.sources.values())
        self.assertEqual(
            source.count(
                "noncomputable def "
                "generatedCheckedMixedExternalTailSemanticEvidence"
            ),
            2,
        )
        for required in (
            "CheckedExternalTailStaticBinding",
            "ExactExternalTailOperationalCompleteness",
            "CheckedExternalTailMixedSemanticOperationInput",
            "generatedCheckedFusedOriginalSemanticBinding3",
            "generatedCheckedFusedOriginalSemanticBinding4",
            "input.toEvidence",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "generatedCheckedMixedExternalTailSemanticEvidence0",
            "generatedCheckedMixedExternalTailSemanticEvidence1",
            "generatedCheckedMixedExternalTailSemanticEvidence2",
            "submittedPath",
            "submittedEndpoint",
            "submittedObservations",
            "submittedStatus",
            "submittedCount",
            "native_decide",
            "sorry",
            "axiom ",
        ):
            self.assertNotIn(forbidden, source)

    def test_writer_is_deterministic_and_inventory_is_non_authoritative(
        self,
    ) -> None:
        bundle = generate_gnu_hello_mixed_external_tail_semantic_evidence(
            [_tail_row("tail", 0x1000)]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_inventory, first_sources = (
                write_gnu_hello_mixed_external_tail_semantic_evidence(
                    root, bundle
                )
            )
            first_bytes = {
                path.relative_to(root): path.read_bytes()
                for path in (first_inventory, *first_sources)
            }
            second_inventory, second_sources = (
                write_gnu_hello_mixed_external_tail_semantic_evidence(
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
            GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_BUNDLE,
        )

    def test_rejects_malformed_tail_identity_and_names(self) -> None:
        missing = _tail_row("missing", 0x1000)
        missing["external_events"] = []
        with self.assertRaisesRegex(
            GnuHelloMixedExternalTailSemanticEvidenceGenerationError,
            "exactly one external tail event",
        ):
            generate_gnu_hello_mixed_external_tail_semantic_evidence(
                [missing]
            )

        mismatch = _tail_row("mismatch", 0x2000)
        mismatch["outcome"]["symbol"] = "fputs"  # type: ignore[index]
        with self.assertRaisesRegex(
            GnuHelloMixedExternalTailSemanticEvidenceGenerationError,
            "differ in symbol",
        ):
            generate_gnu_hello_mixed_external_tail_semantic_evidence(
                [mismatch]
            )

        not_jump = _tail_row("not-jump", 0x3000)
        not_jump["instructions"][0]["mnemonic"] = "ret"  # type: ignore[index]
        with self.assertRaisesRegex(
            GnuHelloMixedExternalTailSemanticEvidenceGenerationError,
            "must end in a jump",
        ):
            generate_gnu_hello_mixed_external_tail_semantic_evidence(
                [not_jump]
            )

        with self.assertRaisesRegex(
            GnuHelloMixedExternalTailSemanticEvidenceGenerationError,
            "fused_binding_prefix",
        ):
            generate_gnu_hello_mixed_external_tail_semantic_evidence(
                [_tail_row("tail", 0x4000)],
                GnuHelloMixedExternalTailSemanticEvidenceSpec(
                    fused_binding_prefix="bad; binding"
                ),
            )


if __name__ == "__main__":
    unittest.main()
