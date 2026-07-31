from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_mixed_fused_semantic_evidence import (
    GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_BUNDLE,
    GnuHelloMixedFusedSemanticEvidenceGenerationError,
    GnuHelloMixedFusedSemanticEvidenceSpec,
    generate_gnu_hello_mixed_fused_semantic_evidence,
    write_gnu_hello_mixed_fused_semantic_evidence,
)
from tests.test_stage_a_relational_interpreter_normalization_generation import (
    _ret_row,
)


def _row(
    identity: str,
    start: int,
    *,
    mnemonic: str = "ret",
    operand: str = "",
    outcome: str = "return",
    x87: bool = False,
) -> dict[str, object]:
    row = copy.deepcopy(_ret_row())
    row["id"] = identity
    row["original"] = {
        "rva_start": start,
        "rva_end": start + 1,
        "size": 1,
    }
    instruction = row["instructions"][0]  # type: ignore[index]
    instruction["rva"] = start
    instruction["mnemonic"] = mnemonic
    instruction["op_str"] = operand
    row["ordered_events"][0]["instruction_rva"] = start  # type: ignore[index]
    row["fpu_state"] = {} if x87 else None
    if outcome == "external_jump":
        row["outcome"] = {"kind": "external_jump"}
    return row


class StageAGnuHelloMixedFusedSemanticEvidenceTests(unittest.TestCase):
    def test_emits_all_non_x87_bindings_and_only_ordinary_evidence(self) -> None:
        rows = [
            _row("ordinary", 0x1000),
            _row("direct", 0x2000, mnemonic="call", operand="0x3000"),
            _row("indirect", 0x3000, mnemonic="call", operand="eax"),
            _row("external", 0x4000, outcome="external_jump"),
            _row("x87", 0x5000, x87=True),
        ]
        bundle = generate_gnu_hello_mixed_fused_semantic_evidence(
            rows, GnuHelloMixedFusedSemanticEvidenceSpec(shard_size=2)
        )
        inventory = bundle.inventory

        self.assertEqual(inventory["input_rows"], 5)
        self.assertEqual(inventory["non_x87_binding_rows"], 4)
        self.assertEqual(inventory["ordinary_one_step_evidence_rows"], 1)
        self.assertEqual(inventory["x87_rows"], 1)
        self.assertEqual(
            inventory["residual_factory_counts"],
            {
                "dedicated-direct-call-return": 1,
                "dedicated-external-boundary": 1,
                "dedicated-indirect-or-import-call": 1,
                "dedicated-x87-replay": 1,
            },
        )
        self.assertFalse(inventory["proof_authority"])
        self.assertFalse(inventory["acceptance_authority"])
        boundary = inventory["checked_boundary"]
        self.assertTrue(
            boundary["candidate_path_starts_at_exact_candidate_before_world"]
        )
        self.assertTrue(
            boundary["dispatch_anchored_to_candidate_before_machine"]
        )
        self.assertFalse(
            boundary["kernel_dispatch_relation_world_indexed"]
        )
        self.assertTrue(
            boundary["full_world_dispatch_identity_requires_exact_replay_lift"]
        )

        source = "\n".join(bundle.sources.values())
        self.assertEqual(
            source.count("def generatedCheckedFusedOriginalSemanticBinding"),
            4,
        )
        self.assertEqual(
            source.count(
                "noncomputable def generatedCheckedMixedOrdinarySemanticEvidence"
            ),
            1,
        )
        for required in (
            "ExactSemanticTransferFusedMachineRefinement",
            "exactNormalizedTransferFusedMachineRefinement0",
            "CheckedOrdinaryMixedSemanticOperationInput",
            "input.toEvidence",
            "sourceRecordExact",
            "sourceSpanExact",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "submittedPath",
            "submittedEndpoint",
            "acceptanceStatus",
            "native_decide",
            "sorry",
            "axiom",
        ):
            self.assertNotIn(forbidden, source)

    def test_writer_is_deterministic_and_keeps_inventory_non_authoritative(
        self,
    ) -> None:
        bundle = generate_gnu_hello_mixed_fused_semantic_evidence(
            [_row("ordinary", 0x1000)]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_inventory, first_sources = (
                write_gnu_hello_mixed_fused_semantic_evidence(root, bundle)
            )
            first_bytes = {
                path.relative_to(root): path.read_bytes()
                for path in (first_inventory, *first_sources)
            }
            second_inventory, second_sources = (
                write_gnu_hello_mixed_fused_semantic_evidence(root, bundle)
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
            GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_BUNDLE,
        )

    def test_rejects_unsupported_outcomes_and_malformed_names(self) -> None:
        unsupported = _row("unsupported", 0x1000)
        unsupported["outcome"] = {"kind": "syscall"}
        with self.assertRaisesRegex(
            GnuHelloMixedFusedSemanticEvidenceGenerationError,
            "unsupported outcome",
        ):
            generate_gnu_hello_mixed_fused_semantic_evidence([unsupported])

        with self.assertRaisesRegex(
            GnuHelloMixedFusedSemanticEvidenceGenerationError,
            "original_pe",
        ):
            generate_gnu_hello_mixed_fused_semantic_evidence(
                [_row("ordinary", 0x1000)],
                GnuHelloMixedFusedSemanticEvidenceSpec(
                    original_pe="bad; exact"
                ),
            )


if __name__ == "__main__":
    unittest.main()
