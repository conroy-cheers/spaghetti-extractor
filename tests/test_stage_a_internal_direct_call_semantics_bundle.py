from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.relational.lean.internal_direct_call_semantics_bundle import (
    write_mixed_original_direct_call_semantics,
)


class StageAInternalDirectCallSemanticsBundleTests(unittest.TestCase):
    def test_frame_only_request_emits_named_checked_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            state_machine = root / "state-machine.jsonl"
            proposal = root / "proposal.json"
            out = root / "out"
            original.write_bytes(b"test-pe")
            state_machine.write_text("{}\n", encoding="utf-8")
            proposal.write_text(
                json.dumps(
                    {
                        "format": (
                            "stage-a-mixed-original-direct-call-proposals-v1"
                        ),
                        "inputs": {
                            "original_sha256": sha256(
                                original.read_bytes()
                            ).hexdigest(),
                            "state_machine_sha256": sha256(
                                state_machine.read_bytes()
                            ).hexdigest(),
                        },
                        "proposal_modules": [
                            {
                                "callsite_rva": 8282,
                                "source_rva": 8256,
                                "continuation_rva": 8287,
                                "callee_rva": 45632,
                                "source_target_id": 293,
                                "continuation_target_id": 294,
                                "callee_target_id": 2932,
                                "edge_index": 1289828802,
                                "entry_kind": "direct",
                                "contract_id": 0x80000293,
                                "caller_frame_word_offsets": [32],
                                "module": (
                                    "StageA."
                                    "GeneratedRelationalInternalDirectCall"
                                    "SummaryProposal0000205a"
                                ),
                                "summary_tree": "fixtureSummaryTree",
                                "summary_checked": "fixtureSummaryChecked",
                                "summary_certificate_exact": (
                                    "fixtureSummaryCertificateExact"
                                ),
                            }
                        ],
                        "request_plan": {"chains": []},
                    }
                ),
                encoding="utf-8",
            )

            report = write_mixed_original_direct_call_semantics(
                original=original,
                state_machine=state_machine,
                proposal_report=proposal,
                out=out,
            )

            self.assertEqual(report["format"], (
                "stage-a-mixed-original-direct-call-authority-bindings-v2"
            ))
            self.assertEqual(len(report["contracts"]), 1)
            contract = report["contracts"][0]
            expected_term = {
                "module": (
                    "StageA."
                    "GeneratedRelationalInternalDirectCall"
                    "MixedOriginalIntegration0000205aEdge4ce139c2"
                ),
                "namespace": (
                    "StageA.Generated."
                    "GeneratedRelationalInternalDirectCall"
                    "MixedOriginalIntegration0000205aEdge4ce139c2"
                ),
                "symbol": (
                    "generatedCheckedDirectCallCallerFrameWordControlContract"
                ),
            }
            self.assertEqual(
                contract["preserved_caller_frame_word_offsets"],
                [32],
            )
            self.assertEqual(
                contract["caller_frame_word_authorizing_lean_term"],
                expected_term,
            )
            self.assertEqual(contract["authorizing_lean_term"], expected_term)
            self.assertEqual(contract["remaining_semantic_premises"], [])
            self.assertEqual(
                contract["origin"],
                "checked_direct_call_caller_frame_word_summary",
            )
            source = (
                out
                / "StageA"
                / (
                    "GeneratedRelationalInternalDirectCall"
                    "MixedOriginalIntegration0000205aEdge4ce139c2.lean"
                )
            ).read_text(encoding="utf-8")
            self.assertIn(
                "generatedCheckedDirectCallCallerFrameWordControlContract",
                source,
            )
            self.assertIn(
                "generatedCallerFrameWords : List "
                "ReturnSlotExactWordPair := "
                "[{ originalOffset := 36, candidateOffset := 36 }]",
                source,
            )

    def test_finite_origin_frame_request_emits_entry_and_frame_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            state_machine = root / "state-machine.jsonl"
            proposal = root / "proposal.json"
            out = root / "out"
            original.write_bytes(b"test-pe")
            state_machine.write_text("{}\n", encoding="utf-8")
            proposal.write_text(
                json.dumps(
                    {
                        "format": (
                            "stage-a-mixed-original-direct-call-proposals-v1"
                        ),
                        "inputs": {
                            "original_sha256": sha256(
                                original.read_bytes()
                            ).hexdigest(),
                            "state_machine_sha256": sha256(
                                state_machine.read_bytes()
                            ).hexdigest(),
                        },
                        "proposal_modules": [
                            {
                                "callsite_rva": 8252,
                                "source_rva": 8243,
                                "continuation_rva": 8256,
                                "callee_rva": 82848,
                                "source_target_id": 292,
                                "continuation_target_id": 293,
                                "callee_target_id": 5621,
                                "edge_index": 0x292,
                                "entry_kind": "finite_origin_call",
                                "contract_id": 0x80000292,
                                "caller_frame_word_offsets": [32],
                                "module": (
                                    "StageA."
                                    "GeneratedRelationalInternalDirectCall"
                                    "SummaryProposal00002033"
                                ),
                                "summary_tree": "fixtureSummaryTree",
                                "summary_checked": "fixtureSummaryChecked",
                                "summary_certificate_exact": (
                                    "fixtureSummaryCertificateExact"
                                ),
                                "entry_authority_module": (
                                    "StageA.FixtureIndirectAuthority"
                                ),
                                "entry_authority_term": (
                                    "StageA.FixtureIndirectAuthority.authority"
                                ),
                                "entry_authority_certificate_exact_term": (
                                    "StageA.FixtureIndirectAuthority."
                                    "authorityCertificateExact"
                                ),
                            }
                        ],
                        "request_plan": {"chains": []},
                    }
                ),
                encoding="utf-8",
            )

            report = write_mixed_original_direct_call_semantics(
                original=original,
                state_machine=state_machine,
                proposal_report=proposal,
                out=out,
            )

            self.assertEqual(len(report["contracts"]), 1)
            contract = report["contracts"][0]
            self.assertEqual(
                contract["origin"],
                "checked_finite_origin_call_caller_frame_word_summary",
            )
            self.assertEqual(
                contract["preserved_caller_frame_word_offsets"],
                [32],
            )
            self.assertEqual(contract["preserved_registers"], [])
            self.assertEqual(contract["remaining_semantic_premises"], [])
            term = contract["authorizing_lean_term"]
            self.assertEqual(
                term["symbol"],
                "generatedCheckedFiniteOriginCall"
                "CallerFrameWordControlContract",
            )
            self.assertEqual(
                contract["caller_frame_word_authorizing_lean_term"],
                term,
            )
            modules = json.loads(
                (out / "phase-manifest.json").read_text(encoding="utf-8")
            )["modules"]
            self.assertEqual(len(modules), 2)
            entry_module = next(
                module
                for module in modules
                if module.endswith("EntryCertificate")
            )
            entry_source = (
                out / "StageA" / f"{entry_module}.lean"
            ).read_text(encoding="utf-8")
            authority_source = (
                out
                / "StageA"
                / f"{term['module'].removeprefix('StageA.')}.lean"
            ).read_text(encoding="utf-8")
            self.assertNotIn("generatedIdentityChecked", entry_source)
            self.assertIn(
                "generatedCheckedFiniteOriginCall"
                "CallerFrameWordControlContract",
                authority_source,
            )
            self.assertNotIn("sorry", authority_source)


if __name__ == "__main__":
    unittest.main()
