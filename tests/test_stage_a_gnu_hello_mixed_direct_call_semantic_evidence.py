from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_direct_call_semantic_evidence import (
    GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_BUNDLE,
    GnuHelloMixedDirectCallSemanticEvidenceGenerationError,
    GnuHelloMixedDirectCallSemanticEvidenceSpec,
    generate_gnu_hello_mixed_direct_call_semantic_evidence,
    write_gnu_hello_mixed_direct_call_semantic_evidence,
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


class StageAGnuHelloMixedDirectCallSemanticEvidenceTests(
    unittest.TestCase
):
    def test_emits_only_immediate_direct_call_rows(self) -> None:
        rows = [
            _row("ordinary", 0x1000),
            _row("direct-a", 0x2000, mnemonic="call", operand="0x3000"),
            _row("indirect", 0x3000, mnemonic="call", operand="eax"),
            _row("direct-b", 0x4000, mnemonic="call", operand="0x5000"),
            _row("external", 0x5000, outcome="external_jump"),
            _row("x87", 0x6000, x87=True),
        ]
        bundle = generate_gnu_hello_mixed_direct_call_semantic_evidence(
            rows,
            GnuHelloMixedDirectCallSemanticEvidenceSpec(
                fused_shard_size=2,
                shard_size=1,
            ),
        )
        inventory = bundle.inventory

        self.assertEqual(inventory["input_rows"], 6)
        self.assertEqual(inventory["direct_call_return_rows"], 2)
        self.assertEqual(
            inventory["generated_direct_call_evidence_adapters"], 2
        )
        self.assertEqual(
            inventory["family_counts"],
            {
                "dedicated-direct-call-return": 2,
                "dedicated-external-boundary": 1,
                "dedicated-indirect-or-import-call": 1,
                "dedicated-x87-replay": 1,
                "ordinary-one-step": 1,
            },
        )
        self.assertEqual(
            inventory["unowned_family_counts"],
            {
                "dedicated-external-boundary": 1,
                "dedicated-indirect-or-import-call": 1,
                "dedicated-x87-replay": 1,
                "ordinary-one-step": 1,
            },
        )
        boundary = inventory["checked_boundary"]
        self.assertTrue(
            boundary["original_path_starts_at_exact_summary_source_world"]
        )
        self.assertTrue(
            boundary["actual_execution_derived_from_operational_completeness"]
        )
        self.assertTrue(
            boundary["one_exact_direct_call_per_generated_adapter"]
        )
        self.assertTrue(
            boundary["candidate_path_starts_at_exact_candidate_before_world"]
        )
        self.assertTrue(
            boundary["semantic_result_compared_to_computed_original_exit"]
        )
        self.assertFalse(
            boundary["kernel_dispatch_relation_world_indexed"]
        )
        self.assertFalse(inventory["proof_authority"])
        self.assertFalse(inventory["acceptance_authority"])

        source = "\n".join(bundle.sources.values())
        self.assertEqual(
            source.count(
                "noncomputable def "
                "generatedCheckedMixedDirectCallSemanticEvidence"
            ),
            2,
        )
        for required in (
            "CheckedDirectCallMixedSemanticOperationInput",
            "IntegratedSummaryPremises",
            "RelatedDirectCallSource",
            "checkedActualDirectCallForSource",
            "generatedCheckedFusedOriginalSemanticBinding1",
            "generatedCheckedFusedOriginalSemanticBinding3",
            "summarySource).source.original.execution candidateBefore",
            "input.toEvidence",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "generatedCheckedMixedDirectCallSemanticEvidence0",
            "generatedCheckedMixedDirectCallSemanticEvidence2",
            "submittedPath",
            "submittedEndpoint",
            "submittedStatus",
            "native_decide",
            "sorry",
            "axiom ",
        ):
            self.assertNotIn(forbidden, source)

    def test_fused_imports_follow_stable_binding_positions(self) -> None:
        rows = [
            _row("ordinary", 0x1000),
            _row("direct-a", 0x2000, mnemonic="call", operand="0x3000"),
            _row("ordinary-b", 0x3000),
            _row("direct-b", 0x4000, mnemonic="call", operand="0x5000"),
        ]
        bundle = generate_gnu_hello_mixed_direct_call_semantic_evidence(
            rows,
            GnuHelloMixedDirectCallSemanticEvidenceSpec(
                fused_shard_size=2,
                shard_size=2,
            ),
        )
        shard = bundle.sources[
            "GeneratedGnuHelloMixedDirectCallSemanticEvidenceShard0000"
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
        bundle = generate_gnu_hello_mixed_direct_call_semantic_evidence(
            [_row("direct", 0x1000, mnemonic="call", operand="0x2000")]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_inventory, first_sources = (
                write_gnu_hello_mixed_direct_call_semantic_evidence(
                    root, bundle
                )
            )
            first_bytes = {
                path.relative_to(root): path.read_bytes()
                for path in (first_inventory, *first_sources)
            }
            second_inventory, second_sources = (
                write_gnu_hello_mixed_direct_call_semantic_evidence(
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
            GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_BUNDLE,
        )

    def test_rejects_unsupported_outcome_and_malformed_names(self) -> None:
        unsupported = _row("unsupported", 0x1000)
        unsupported["outcome"] = {"kind": "syscall"}
        with self.assertRaisesRegex(
            GnuHelloMixedDirectCallSemanticEvidenceGenerationError,
            "unsupported outcome",
        ):
            generate_gnu_hello_mixed_direct_call_semantic_evidence(
                [unsupported]
            )

        with self.assertRaisesRegex(
            GnuHelloMixedDirectCallSemanticEvidenceGenerationError,
            "fused_binding_prefix",
        ):
            generate_gnu_hello_mixed_direct_call_semantic_evidence(
                [_row("direct", 0x1000, mnemonic="call", operand="0x2000")],
                GnuHelloMixedDirectCallSemanticEvidenceSpec(
                    fused_binding_prefix="bad; binding"
                ),
            )

        multiple = _row(
            "multiple", 0x3000, mnemonic="call", operand="0x4000"
        )
        second = copy.deepcopy(multiple["instructions"][0])  # type: ignore[index]
        second["rva"] = 0x3001
        multiple["instructions"].append(second)  # type: ignore[union-attr]
        multiple["original"] = {
            "rva_start": 0x3000,
            "rva_end": 0x3002,
            "size": 2,
        }
        multiple["instruction_bytes_sha256"] = hashlib.sha256(
            bytes.fromhex(
                "".join(
                    instruction["bytes"]
                    for instruction in multiple["instructions"]  # type: ignore[union-attr]
                )
            )
        ).hexdigest()
        with self.assertRaisesRegex(
            GnuHelloMixedDirectCallSemanticEvidenceGenerationError,
            "exactly one immediate direct call",
        ):
            generate_gnu_hello_mixed_direct_call_semantic_evidence([multiple])


if __name__ == "__main__":
    unittest.main()
