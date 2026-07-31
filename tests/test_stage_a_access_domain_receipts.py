from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.relational.access_domain_receipts import (
    TYPED_ACCESS_FAULT_QUALIFICATION_FORMAT,
    access_domain_receipt_proposals_payload,
    build_access_domain_kernel_check_requests,
    create_access_domain_receipts,
    generate_typed_access_fault_qualification,
)
from spaghetti_extractor.relational.semantic_coverage import (
    build_semantic_coverage,
    validate_semantic_coverage,
)
from spaghetti_extractor.relational.side_extraction_artifact import (
    parse_request,
    request_payload,
)
from spaghetti_extractor.relational.side_isa_artifact import side_isa_payload
from spaghetti_extractor.stage_binary import StageAInputError


MEMORY_SHIFT_FORM = (
    "StageA.Formal.InstructionSemanticForm.shift\n"
    "  (StageA.Formal.ShiftOperation.left)\n"
    "  (StageA.Formal.Operand32SemanticForm.memory\n"
    "    { hasBase := true, hasIndex := false, scaleShift := 0, "
    "hasDisplacement := false })\n"
    "  (StageA.Formal.ShiftCount.immediate 1)"
)
THEOREM = {
    "module": "StageA.GeneratedAccessReceipt",
    "namespace": "StageA.GeneratedAccessReceipt",
    "symbol": "originalOccurrenceModeled",
}
ROOT = Path(__file__).resolve().parents[1]
DRIVER_SPEC = importlib.util.spec_from_file_location(
    "stage_a_semantic_coverage_driver",
    ROOT / "nix" / "stage-a-semantic-coverage.py",
)
assert DRIVER_SPEC is not None and DRIVER_SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(DRIVER_SPEC)
DRIVER_SPEC.loader.exec_module(DRIVER)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class StageAAccessDomainReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        contract = {
            "regions": [
                {
                    "id": "memory-shift",
                    "numeric_id": 0,
                    "original": {"rva_start": 0x1000, "size": 2},
                    "candidate": {"rva_start": 0x2000, "size": 2},
                }
            ]
        }
        hashes = {
            "classifier_sha256": "c" * 64,
            "extractor_sha256": "d" * 64,
            "source_sha256": "e" * 64,
        }
        original_request = parse_request(
            request_payload(contract, "original", "a" * 64)
        )
        candidate_request = parse_request(
            request_payload(contract, "candidate", "b" * 64)
        )
        self.original = side_isa_payload(
            original_request,
            forms={
                ("original", 0): (
                    {
                        "rva": 0x1000,
                        "size": 2,
                        "bytes": "d120",
                        "form": MEMORY_SHIFT_FORM,
                    },
                )
            },
            **hashes,
        )
        self.candidate = side_isa_payload(
            candidate_request,
            forms={
                ("candidate", 0): (
                    {
                        "rva": 0x2000,
                        "size": 2,
                        "bytes": "d120",
                        "form": MEMORY_SHIFT_FORM,
                    },
                )
            },
            **hashes,
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.source_root = Path(self.temporary.name) / "source"
        source = (
            self.source_root
            / "StageA"
            / "GeneratedAccessReceipt.lean"
        )
        source.parent.mkdir(parents=True)
        source.write_text(
            "namespace StageA.GeneratedAccessReceipt\n"
            "theorem originalOccurrenceModeled : True := True.intro\n"
            "end StageA.GeneratedAccessReceipt\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _proposal(
        self,
        *,
        side: str = "original",
        binary_sha256: str | None = None,
        rva: int | None = None,
        theorem: dict[str, str] | None = None,
    ) -> dict[str, object]:
        return {
            "side": side,
            "binary_sha256": (
                binary_sha256
                if binary_sha256 is not None
                else ("a" * 64 if side == "original" else "b" * 64)
            ),
            "rva": (
                rva
                if rva is not None
                else (0x1000 if side == "original" else 0x2000)
            ),
            "size": 2,
            "bytes": "d120",
            "semantic_form": MEMORY_SHIFT_FORM,
            "dimension": "access_fault_domain",
            "theorem": theorem or THEOREM,
        }

    def _bundle(
        self, *, observed_axioms: list[str] | None = None
    ) -> dict[str, object]:
        source = (
            self.source_root
            / "StageA"
            / "GeneratedAccessReceipt.lean"
        )
        return {
            "format": "stage-a-lean-target-bundle-v2",
            "lean_trust": 0,
            "nodes": [
                {
                    "id": "GeneratedAccessReceipt",
                    "modules": ["GeneratedAccessReceipt"],
                    "source_sha256": hashlib.sha256(
                        source.read_bytes()
                    ).hexdigest(),
                    "outputs": [
                        {
                            "module": "GeneratedAccessReceipt",
                            "olean_sha256": "f" * 64,
                            "axiom_audit": {
                                "complete": True,
                                "inventories": {
                                    "originalOccurrenceModeled": (
                                        observed_axioms or []
                                    )
                                },
                            },
                        }
                    ]
                }
            ],
        }

    def _receipts(
        self, proposal: dict[str, object] | None = None
    ) -> dict[str, object]:
        proposals = access_domain_receipt_proposals_payload(
            [proposal or self._proposal()]
        )
        return create_access_domain_receipts(
            proposals_payload=proposals,
            target_bundle=self._bundle(),
            source_root=self.source_root,
        )

    def test_exact_checked_receipt_changes_only_access_dimension(self) -> None:
        baseline = build_semantic_coverage(self.original, self.candidate)
        baseline_original = baseline["occurrences"][0]
        self.assertEqual(
            baseline_original["access_fault_domain"], "requires-proof"
        )

        receipts = self._receipts()
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            access_domain_receipts=receipts,
        )
        original, candidate = artifact["occurrences"]
        self.assertEqual(original["access_fault_domain"], "complete")
        self.assertEqual(original["state_transition_support"], "supported")
        self.assertEqual(
            original["relational_discharge"], "requires-proof"
        )
        self.assertEqual(original["qualification"], "relational-parametric")
        self.assertEqual(
            candidate["access_fault_domain"], "requires-proof"
        )
        self.assertEqual(
            artifact["access_domain_receipts"]["counts"]["accepted"], 1
        )
        validate_semantic_coverage(
            artifact,
            original_side_isa=self.original,
            candidate_side_isa=self.candidate,
            access_domain_receipts=receipts,
        )

    def test_missing_receipt_remains_requires_proof(self) -> None:
        artifact = build_semantic_coverage(self.original, self.candidate)
        self.assertTrue(
            all(
                row["access_fault_domain"] == "requires-proof"
                for row in artifact["occurrences"]
            )
        )
        self.assertEqual(
            artifact["access_domain_receipts"]["status"], "absent"
        )

    def test_stale_binary_receipt_is_diagnosed_and_ignored(self) -> None:
        receipts = self._receipts(
            self._proposal(binary_sha256="9" * 64)
        )
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            access_domain_receipts=receipts,
        )
        self.assertEqual(
            artifact["occurrences"][0]["access_fault_domain"],
            "requires-proof",
        )
        self.assertEqual(
            [
                row["code"]
                for row in artifact["access_domain_receipts"]["diagnostics"]
            ],
            ["receipt-stale-binary"],
        )

    def test_duplicate_exact_key_receipts_are_all_ignored(self) -> None:
        receipts = self._receipts()
        duplicate = copy.deepcopy(receipts)
        duplicate["receipts"].append(copy.deepcopy(duplicate["receipts"][0]))
        body = {
            field: duplicate[field]
            for field in duplicate
            if field != "receipts_sha256"
        }
        duplicate["receipts_sha256"] = _canonical_sha256(body)
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            access_domain_receipts=duplicate,
        )
        self.assertEqual(
            artifact["occurrences"][0]["access_fault_domain"],
            "requires-proof",
        )
        self.assertEqual(
            artifact["access_domain_receipts"]["counts"]["by_code"],
            {"receipt-duplicate-key": 2},
        )

    def test_tampered_receipt_digest_is_diagnosed_and_ignored(self) -> None:
        receipts = self._receipts()
        tampered = copy.deepcopy(receipts)
        tampered["receipts"][0]["receipt_sha256"] = "0" * 64
        body = {
            field: tampered[field]
            for field in tampered
            if field != "receipts_sha256"
        }
        tampered["receipts_sha256"] = _canonical_sha256(body)
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            access_domain_receipts=tampered,
        )
        self.assertEqual(
            artifact["occurrences"][0]["access_fault_domain"],
            "requires-proof",
        )
        self.assertEqual(
            artifact["access_domain_receipts"]["counts"]["by_code"],
            {"receipt-digest-mismatch": 1},
        )

    def test_receipt_evidence_is_part_of_reproduction_validation(self) -> None:
        receipts = self._receipts()
        artifact = build_semantic_coverage(
            self.original,
            self.candidate,
            access_domain_receipts=receipts,
        )
        with self.assertRaisesRegex(
            StageAInputError, "does not reproduce exact side inventories"
        ):
            validate_semantic_coverage(
                artifact,
                original_side_isa=self.original,
                candidate_side_isa=self.candidate,
            )

    def test_unapproved_axiom_cannot_produce_a_receipt(self) -> None:
        proposals = access_domain_receipt_proposals_payload(
            [self._proposal()]
        )
        with self.assertRaisesRegex(StageAInputError, "unapproved axioms"):
            create_access_domain_receipts(
                proposals_payload=proposals,
                target_bundle=self._bundle(observed_axioms=["badAxiom"]),
                source_root=self.source_root,
            )

    def test_compiled_node_must_bind_exact_source_identity(self) -> None:
        proposals = access_domain_receipt_proposals_payload(
            [self._proposal()]
        )
        bundle = self._bundle()
        bundle["nodes"][0]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            StageAInputError, "does not match the exact source files"
        ):
            create_access_domain_receipts(
                proposals_payload=proposals,
                target_bundle=bundle,
                source_root=self.source_root,
            )

    def test_proposals_only_emit_deduplicated_kernel_requests(self) -> None:
        candidate_theorem = {
            **THEOREM,
            "symbol": "originalOccurrenceModeled",
        }
        proposals = access_domain_receipt_proposals_payload(
            [
                self._proposal(),
                self._proposal(
                    side="candidate", theorem=candidate_theorem
                ),
            ]
        )
        requests = build_access_domain_kernel_check_requests(proposals)
        self.assertEqual(
            requests,
            {
                "format": "stage-a-lean-kernel-check-requests-v1",
                "requests": [{"term": THEOREM}],
            },
        )
        artifact = build_semantic_coverage(self.original, self.candidate)
        self.assertTrue(
            all(
                row["access_fault_domain"] == "requires-proof"
                for row in artifact["occurrences"]
            )
        )

    def test_driver_emits_deterministic_stale_receipt_blocker(self) -> None:
        root = Path(self.temporary.name)
        original_path = root / "original.json"
        candidate_path = root / "candidate.json"
        receipts_path = root / "receipts.json"
        proposals_path = root / "proposals.json"
        output = root / "output"
        original_path.write_text(
            json.dumps(self.original), encoding="utf-8"
        )
        candidate_path.write_text(
            json.dumps(self.candidate), encoding="utf-8"
        )
        receipts_path.write_text(
            json.dumps(
                self._receipts(
                    self._proposal(binary_sha256="9" * 64)
                )
            ),
            encoding="utf-8",
        )
        proposals_path.write_text(
            json.dumps(
                access_domain_receipt_proposals_payload(
                    [self._proposal()]
                )
            ),
            encoding="utf-8",
        )
        with patch.object(
            sys,
            "argv",
            [
                "stage-a-semantic-coverage.py",
                "--original-isa",
                str(original_path),
                "--candidate-isa",
                str(candidate_path),
                "--access-domain-receipts",
                str(receipts_path),
                "--access-domain-receipt-proposals",
                str(proposals_path),
                "--out",
                str(output),
            ],
        ):
            DRIVER.main()
        blockers = json.loads(
            (output / "semantic-blockers.json").read_text(encoding="utf-8")
        )
        original_blocker = next(
            row
            for row in blockers["access_domain_blockers"]
            if row["side"] == "original"
        )
        self.assertEqual(
            original_blocker["reason_codes"], ["receipt-stale-binary"]
        )
        candidate_blocker = next(
            row
            for row in blockers["access_domain_blockers"]
            if row["side"] == "candidate"
        )
        self.assertEqual(
            candidate_blocker["reason_codes"],
            ["access-domain-receipt-missing"],
        )
        requests = json.loads(
            (
                output / "access-domain-kernel-check-requests.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            requests,
            {
                "format": "stage-a-lean-kernel-check-requests-v1",
                "requests": [{"term": THEOREM}],
            },
        )


class StageATypedAccessFaultQualificationGenerationTests(
    unittest.TestCase
):
    def _original_isa(self) -> dict[str, object]:
        occurrences = [
            (0x1000, "90", "StageA.Formal.InstructionSemanticForm.nop"),
            (
                0x1010,
                "ff10",
                "StageA.Formal.InstructionSemanticForm.callIndirect",
            ),
            (
                0x1020,
                "f3a5",
                "StageA.Formal.InstructionSemanticForm.repMovsd",
            ),
            (
                0x1030,
                "d9e8",
                "StageA.Formal.InstructionSemanticForm.x87LoadConstant "
                "302222231531620438900736",
            ),
        ]
        return {
            "format": "stage-a-relational-side-isa-v1",
            "side": "original",
            "binary_sha256": "a" * 64,
            "regions": [
                {
                    "id": f"region-{index}",
                    "occurrences": [
                        {
                            "rva": rva,
                            "size": len(encoded) // 2,
                            "bytes": encoded,
                            "form": form,
                        }
                    ],
                }
                for index, (rva, encoded, form) in enumerate(occurrences)
            ],
        }

    def _rows(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        definitions = [
            (0x1000, "nop", None, [], []),
            (
                0x1010,
                "call",
                None,
                [{"kind": "external_call"}],
                [],
            ),
            (0x1020, "rep movsd", None, [], []),
            (0x1030, "fld1", {"kind": "x87"}, [], []),
        ]
        for rva, mnemonic, fpu_state, external_events, faults in definitions:
            rows.append(
                {
                    "original": {
                        "rva_start": rva,
                        "rva_end": rva + 2,
                    },
                    "instructions": [{"mnemonic": mnemonic, "rva": rva}],
                    "external_events": external_events,
                    "fpu_state": fpu_state,
                    "faults": faults,
                }
            )
        return rows

    def _generate(self, output: Path) -> dict[str, object]:
        return generate_typed_access_fault_qualification(
            original_isa=self._original_isa(),
            state_machine_rows=self._rows(),
            reachability_plan={
                "format": "stage-a-interpreter-mixed-original-v1",
                "reachable_target_ids": [0, 1, 2, 3],
            },
            kernel_data_inventory={
                "format": "stage-a-interpreter-kernel-data-inventory-v7",
                "authority_transfer_limit": 64,
                "counts": {
                    "records": 4,
                    "certificate_packs": 1,
                },
            },
            out=output,
        )

    def test_emits_typed_certificate_and_explicit_frontiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            artifact = self._generate(output)
            self.assertEqual(
                artifact["format"],
                TYPED_ACCESS_FAULT_QUALIFICATION_FORMAT,
            )
            self.assertEqual(
                artifact["counts"],
                {
                    "reachable_regions": 4,
                    "typed_qualification_regions": 4,
                    "remaining_state_admissibility_premises": 4,
                    "blocked_regions": 0,
                    "shards": 1,
                    "by_qualification_kind": {
                        "ordinary": 3,
                        "x87": 1,
                    },
                    "by_blocker_reason": {},
                },
            )
            self.assertNotIn("theorem", artifact["qualified_regions"][0])
            source = (
                output
                / "StageA"
                / "GeneratedGnuHelloAccessFaultQualificationShard0000.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("TypedAccessFaultQualification", source)
            self.assertIn("Certificate.checked .original", source)
            self.assertIn("TypedX87AccessFaultQualification", source)
            self.assertIn("executeX87Singleton", source)
            self.assertIn("RegionLookupExact", source)
            self.assertIn("StateAdmissible", source)
            self.assertNotIn(": True", source)

    def test_generation_is_byte_for_byte_deterministic(self) -> None:
        with (
            tempfile.TemporaryDirectory() as first_directory,
            tempfile.TemporaryDirectory() as second_directory,
        ):
            first = Path(first_directory)
            second = Path(second_directory)
            self._generate(first)
            self._generate(second)
            first_files = sorted(
                path.relative_to(first) for path in first.rglob("*")
                if path.is_file()
            )
            second_files = sorted(
                path.relative_to(second) for path in second.rglob("*")
                if path.is_file()
            )
            self.assertEqual(first_files, second_files)
            for relative in first_files:
                self.assertEqual(
                    (first / relative).read_bytes(),
                    (second / relative).read_bytes(),
                )

    def test_missing_program_record_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifact = generate_typed_access_fault_qualification(
                original_isa=self._original_isa(),
                state_machine_rows=self._rows(),
                reachability_plan={
                    "format": "stage-a-interpreter-mixed-original-v1",
                    "reachable_target_ids": [1],
                },
                kernel_data_inventory={
                    "format": (
                        "stage-a-interpreter-kernel-data-inventory-v7"
                    ),
                    "authority_transfer_limit": 64,
                    "counts": {
                        "records": 1,
                        "certificate_packs": 1,
                    },
                },
                out=Path(directory),
            )
            self.assertEqual(
                artifact["blockers"],
                [
                    {
                        "region_id": 1,
                        "rva": 0x1010,
                        "reason": "missing_checked_program_record",
                    }
                ],
            )
            self.assertEqual(
                artifact["counts"]["typed_qualification_regions"], 0
            )


if __name__ == "__main__":
    unittest.main()
