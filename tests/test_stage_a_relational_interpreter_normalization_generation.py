from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.interpreter_normalization import (
    RELATIONAL_INTERPRETER_NORMALIZATION_INVENTORY_FORMAT,
    relational_interpreter_normalization_bundle_sources,
    relational_interpreter_normalization_inventory,
    relational_interpreter_normalization_module_inventory,
    relational_interpreter_normalization_source,
)
from spaghetti_extractor.util import sha256_bytes


def _ret_row() -> dict[str, object]:
    encoded = bytes.fromhex("c3")
    return {
        "stage_b_format": "stage-b-state-machine-transfer-v1",
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": "semantic-transfer:ret",
        "status": "pass-must-be-ignored",
        "contract_sha256": "a" * 64,
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "original": {"rva_start": 0x1000, "rva_end": 0x1001, "size": 1},
        "instructions": [
            {"rva": 0x1000, "size": 1, "bytes": "c3", "mnemonic": "ret", "op_str": ""}
        ],
        "ordered_events": [
            {
                "family": "memory",
                "kind": "read",
                "width": 4,
                "instruction_rva": 0x1000,
                "address": {"op": "reg", "name": "esp", "width": 32},
            }
        ],
        "register_writes": [
            {
                "register": "esp",
                "value": {
                    "op": "add32",
                    "args": [
                        {"op": "const", "value": 4, "width": 32},
                        {"op": "reg", "name": "esp", "width": 32},
                    ],
                },
            }
        ],
        "flag_writes": [],
        "fpu_state": None,
        "outcome": {
            "kind": "return",
            "value": {
                "op": "load",
                "width": 4,
                "address": {"op": "reg", "name": "esp", "width": 32},
            },
        },
    }


class StageARelationalInterpreterNormalizationGenerationTests(unittest.TestCase):
    def test_source_contains_only_data_and_computed_checker(self) -> None:
        source = relational_interpreter_normalization_source(
            _ret_row(),
            source_module="StageA.GeneratedSemanticInterpreterProgram",
            pe_name="StageA.OriginalPE.originalPe",
            record_name="semanticInterpreterProgramRecord0",
            transfer_name="semanticInterpreterTransfer0",
        )

        for required in (
            "import StageA.RelationalInterpreterNormalization",
            "instructions := [",
            "{ rva := 4096, bytes := [195] }",
            "terminal := .returned",
            "orderedEffects := [.read .dword]",
            "diagnosticTransferShapeChecked StageA.OriginalPE.originalPe",
            "SemanticTransferRefinesExactPath StageA.OriginalPE.originalPe",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "checkTransferAgainstPath",
            "pass-must-be-ignored",
            "semanticAgreement",
            "by decide",
            "by native_decide",
            "axiom",
            "sorry",
        ):
            self.assertNotIn(forbidden, source)

    def test_rejects_tampered_partition_digest_and_names(self) -> None:
        cases: list[tuple[dict[str, object], str]] = []
        split = copy.deepcopy(_ret_row())
        split["instructions"][0]["rva"] = 0x1001  # type: ignore[index]
        cases.append((split, "partition is not contiguous"))
        digest = copy.deepcopy(_ret_row())
        digest["instruction_bytes_sha256"] = "0" * 64
        cases.append((digest, "digest differs"))

        for row, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(StageAInputError, message):
                    relational_interpreter_normalization_source(
                        row,
                        source_module="StageA.Source",
                        pe_name="StageA.Source.pe",
                        record_name="StageA.Source.record",
                        transfer_name="StageA.Source.transfer",
                    )

        with self.assertRaisesRegex(StageAInputError, "qualified Lean identifier"):
            relational_interpreter_normalization_source(
                _ret_row(),
                source_module="StageA.Source",
                pe_name="StageA.Source.pe; axiom bad : False",
                record_name="StageA.Source.record",
                transfer_name="StageA.Source.transfer",
            )

    def test_inventory_is_fail_closed_and_ignores_status(self) -> None:
        ordinary = _ret_row()
        x87 = copy.deepcopy(ordinary)
        x87["id"] = "semantic-transfer:x87"
        x87["original"] = {"rva_start": 0x2000, "rva_end": 0x2001, "size": 1}
        x87["instructions"][0].update(  # type: ignore[index]
            {"rva": 0x2000, "bytes": "d9", "mnemonic": "x87"}
        )
        x87["instruction_bytes_sha256"] = sha256_bytes(bytes.fromhex("d9"))
        x87["fpu_state"] = {"model": "physical-x87"}
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            machine.write_text(
                "".join(json.dumps(row) + "\n" for row in (ordinary, x87)),
                encoding="utf-8",
            )
            inventory = relational_interpreter_normalization_inventory(machine)

        self.assertEqual(
            inventory["format"],
            RELATIONAL_INTERPRETER_NORMALIZATION_INVENTORY_FORMAT,
        )
        self.assertEqual(inventory["status"], "incomplete")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(inventory["total_transfers"], 2)
        self.assertEqual(inventory["ready_for_lean_check"], 1)
        self.assertEqual(inventory["blocked"], 1)
        self.assertEqual(inventory["lean_certificates_proved"], 0)
        self.assertEqual(inventory["status_fields_ignored"], 2)
        self.assertEqual(
            inventory["blocker_counts"], {"x87_separate_exact_schedule": 1}
        )

    def test_bundle_is_sharded_data_and_has_a_graph_inventory(self) -> None:
        first = _ret_row()
        second = copy.deepcopy(first)
        second["id"] = "semantic-transfer:ret-two"
        second["original"] = {"rva_start": 0x2000, "rva_end": 0x2001, "size": 1}
        second["instructions"][0]["rva"] = 0x2000  # type: ignore[index]
        sources = relational_interpreter_normalization_bundle_sources(
            [first, second],
            source_module="StageA.GeneratedSemanticInterpreterProgram",
            pe_name="StageA.OriginalPE.originalPe",
            shard_size=1,
        )

        self.assertEqual(
            sorted(sources),
            [
                "GeneratedInterpreterNormalizationBundle",
                "GeneratedInterpreterNormalizationShard0000",
                "GeneratedInterpreterNormalizationShard0001",
            ],
        )
        self.assertNotIn("theorem", "".join(sources.values()))
        inventory = relational_interpreter_normalization_module_inventory(
            sources, target="GeneratedInterpreterNormalizationBundle"
        )
        self.assertEqual(inventory["status"], "data_ready")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(len(inventory["modules"]), 3)

    def test_proof_bundle_constructs_only_typed_acceptance_inventory(self) -> None:
        first = _ret_row()
        second = copy.deepcopy(first)
        second["id"] = "semantic-transfer:ret-two"
        second["original"] = {"rva_start": 0x2000, "rva_end": 0x2001, "size": 1}
        second["instructions"][0]["rva"] = 0x2000  # type: ignore[index]
        sources = relational_interpreter_normalization_bundle_sources(
            [first, second],
            source_module="StageA.GeneratedSemanticInterpreterProgram",
            pe_name="StageA.GeneratedRelational.originalPe",
            shard_size=1,
            semantic_refinement_module="StageA.GeneratedOrdinaryRefinements",
        )

        self.assertEqual(
            sorted(sources),
            [
                "GeneratedInterpreterNormalizationBundle",
                "GeneratedInterpreterNormalizationShard0000",
                "GeneratedInterpreterNormalizationShard0000Data",
                "GeneratedInterpreterNormalizationShard0001",
                "GeneratedInterpreterNormalizationShard0001Data",
            ],
        )
        first_data = sources["GeneratedInterpreterNormalizationShard0000Data"]
        first_certificate = sources["GeneratedInterpreterNormalizationShard0000"]
        bundle = sources["GeneratedInterpreterNormalizationBundle"]
        self.assertIn("exactNormalizedTransferPath0", first_data)
        self.assertNotIn("GeneratedOrdinaryRefinements", first_data)
        self.assertIn(
            "import StageA.GeneratedInterpreterNormalizationShard0000Data",
            first_certificate,
        )
        self.assertIn("import StageA.GeneratedOrdinaryRefinements", first_certificate)
        self.assertIn("ExactProgramRecordNormalizationCertificate", first_certificate)
        self.assertIn(
            "semanticRefinement := exactNormalizedTransferSemanticRefinement0",
            first_certificate,
        )
        self.assertIn("ExactOriginalTransferInventory context", bundle)
        self.assertIn("exactNormalizedTransferSourceRvasNodup", bundle)
        self.assertIn("List.mem_map.mp member", bundle)
        for forbidden in ("axiom", "sorry", "unsafe", "proof_authority := true"):
            self.assertNotIn(forbidden, "".join(sources.values()))

        inventory = relational_interpreter_normalization_module_inventory(
            sources, target="GeneratedInterpreterNormalizationBundle"
        )
        self.assertEqual(inventory["status"], "proof_sources_ready")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(
            inventory["targets"]["exact_original_inventory"],
            "exactNormalizedTransferOriginalInventory",
        )
        self.assertEqual(inventory["counts"]["semantic_refinement_obligations"], 2)
        self.assertEqual(
            inventory["semantic_refinement_obligations"],
            [
                "exactNormalizedTransferSemanticRefinement0",
                "exactNormalizedTransferSemanticRefinement1",
            ],
        )

    def test_bundle_rejects_ambiguous_inventory_and_bad_terminal_shape(self) -> None:
        duplicate_id = copy.deepcopy(_ret_row())
        duplicate_id["original"] = {
            "rva_start": 0x2000,
            "rva_end": 0x2001,
            "size": 1,
        }
        duplicate_id["instructions"][0]["rva"] = 0x2000  # type: ignore[index]
        with self.assertRaisesRegex(StageAInputError, "transfer id.*duplicated"):
            relational_interpreter_normalization_bundle_sources(
                [_ret_row(), duplicate_id],
                source_module="StageA.GeneratedSemanticInterpreterProgram",
                pe_name="StageA.GeneratedRelational.originalPe",
            )

        duplicate_rva = copy.deepcopy(_ret_row())
        duplicate_rva["id"] = "semantic-transfer:other"
        with self.assertRaisesRegex(StageAInputError, "source RVA.*duplicated"):
            relational_interpreter_normalization_bundle_sources(
                [_ret_row(), duplicate_rva],
                source_module="StageA.GeneratedSemanticInterpreterProgram",
                pe_name="StageA.GeneratedRelational.originalPe",
            )

        malformed = copy.deepcopy(_ret_row())
        malformed["outcome"] = {"kind": "return"}
        with self.assertRaisesRegex(StageAInputError, "ordinary normalization transfer"):
            relational_interpreter_normalization_bundle_sources(
                [malformed],
                source_module="StageA.GeneratedSemanticInterpreterProgram",
                pe_name="StageA.GeneratedRelational.originalPe",
            )

    def test_current_gnu_inventory_is_complete_when_present(self) -> None:
        machine = (
            Path(__file__).parents[1]
            / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-x87-schedule-v1/state-machine.jsonl"
        )
        if not machine.is_file():
            self.skipTest("GNU hello state machine is unavailable")

        inventory = relational_interpreter_normalization_inventory(machine)

        self.assertEqual(inventory["total_transfers"], 5326)
        self.assertEqual(inventory["ready_for_lean_check"], 5216)
        self.assertEqual(inventory["blocked"], 110)
        self.assertEqual(
            inventory["blocker_counts"], {"x87_separate_exact_schedule": 110}
        )
        self.assertEqual(len(inventory["shards"]), 109)
        self.assertEqual(inventory["lean_certificates_proved"], 0)


if __name__ == "__main__":
    unittest.main()
