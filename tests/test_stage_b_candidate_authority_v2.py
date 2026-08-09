from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.hybrid_authority_builder_v2 import (
    build_machine_ir_authority_bindings,
)
from spaghetti_extractor.hybrid_authority_v2 import (
    AuthorityBundle,
    BinaryBinding,
    FiniteAlternatives,
    UnitBinding,
    ValueFact,
    canonical_json_bytes,
)
from spaghetti_extractor.stage_b_candidate_authority_v2 import (
    STAGE_B_CANDIDATE_AUTHORITY_V2_FORMAT,
    STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT,
    CandidateAuthorityV2Error,
    CandidateAuthorityV2GateError,
    CandidateAuthorityV2Status,
    build_stage_b_candidate_authority_v2,
    parse_stage_b_candidate_authority_v2,
    require_stage_b_candidate_authority_v2,
    validate_stage_b_candidate_authority_v2,
)
from spaghetti_extractor.stage_b_fallback_coverage import (
    FALLBACK_COVERAGE_RECEIPT_FORMAT,
)


PE_SHA256 = hashlib.sha256(b"fixture-pe").hexdigest()
INSTRUCTION_SHA256 = hashlib.sha256(b"ret").hexdigest()
LOWERING_SHA256 = hashlib.sha256(b"lowering").hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _unit_row() -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:entry",
        "reachable": True,
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "contract_sha256": hashlib.sha256(b"contract").hexdigest(),
            "instruction_bytes_sha256": INSTRUCTION_SHA256,
        },
        "instructions": [{
            "rva_start": 0x1000,
            "rva_end": 0x1001,
            "size": 1,
            "instruction_sha256": INSTRUCTION_SHA256,
            "mnemonic": "ret",
            "operands": [],
            "groups": ["ret"],
            "registers_read": ["esp"],
            "registers_written": ["esp"],
        }],
        "semantics": {
            "external_events": [],
            "faults": [],
            "outcome": {"kind": "return"},
        },
    }


class StageBCandidateAuthorityV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.row = _unit_row()
        self.machine_ir = self.root / "machine-ir.jsonl"
        self.machine_ir.write_bytes(canonical_json_bytes(self.row) + b"\n")
        self.machine_ir_sha256 = _sha256_file(self.machine_ir)

        self.manifest = self.root / "manifest.json"
        manifest = {
            "format": "stage-a-machine-ir-v2",
            "inputs": {"original_pe": {"sha256": PE_SHA256}},
            "binary": {"sha256": PE_SHA256},
            "artifacts": {
                "machine_ir": {
                    "format": "stage-a-machine-ir-v2",
                    "sha256": self.machine_ir_sha256,
                }
            },
            "authority_bindings": build_machine_ir_authority_bindings(
                [self.row], pe_sha256=PE_SHA256
            ),
            "control": {
                "reachability": {
                    "status": "complete",
                    "roots": ["unit:entry"],
                    "reachable_units": ["unit:entry"],
                    "potential_units": [],
                    "confirmed_unreachable_units": [],
                    "frontiers": [],
                }
            },
        }
        _write_json(self.manifest, manifest)

        self.bundle = self._bundle()
        self.bundle_payload = self.bundle.to_payload()
        self.bundle_artifact_sha256 = _canonical_sha256(self.bundle_payload)
        self.audit = self._audit(self.bundle, status="pass")
        self.fallback = self._fallback(status="complete")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _bundle(
        self,
        *,
        alternatives: FiniteAlternatives | None = None,
    ) -> AuthorityBundle:
        binary = BinaryBinding(PE_SHA256, self.machine_ir_sha256)
        unit = UnitBinding(
            binary=binary,
            unit_id="unit:entry",
            rva_start=0x1000,
            rva_end=0x1001,
            unit_sha256=_canonical_sha256(self.row),
            instruction_bytes_sha256=INSTRUCTION_SHA256,
        )
        fact = ValueFact(
            binding=unit,
            location="register:eax",
            width_bits=32,
            alternatives=(
                FiniteAlternatives.of([0], maximum=1)
                if alternatives is None
                else alternatives
            ),
        )
        return AuthorityBundle.of(
            binary=binary,
            records=(fact,),
            required_content_ids=(fact.content_id,),
        )

    def _audit(
        self,
        bundle: AuthorityBundle,
        *,
        status: str,
        findings: list[dict] | None = None,
    ) -> dict:
        bundle_payload = bundle.to_payload()
        body = {
            "format": STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT,
            "status": status,
            "authority_bundle": {
                "format": bundle.FORMAT,
                "content_id": bundle.content_id,
                "artifact_sha256": _canonical_sha256(bundle_payload),
            },
            "machine_ir": {"sha256": self.machine_ir_sha256},
            "machine_ir_manifest": {"sha256": _sha256_file(self.manifest)},
            "policy": {
                "v2_authority_is_only_candidate_authority": True,
                "tainted_accepted_facts_forbidden": True,
                "deferred_transfers_forbidden": True,
            },
            "findings": [] if findings is None else findings,
        }
        return {**body, "audit_sha256": _canonical_sha256(body)}

    def _fallback(self, *, status: str) -> dict:
        entry_core = {
            "unit_id": "unit:entry",
            "rva": 0x1000,
            "unit_contract_sha256": self.row["source"]["contract_sha256"],
            "machine_ir_record_sha256": _canonical_sha256(self.row),
            "lowering_transfer_sha256": LOWERING_SHA256,
            "implementation_kind": "machine_ir_fallback",
            "dispatch_lookup": "stage_b_program_lookup",
            "portable_replacement": None,
        }
        entry = {**entry_core, "entry_sha256": _canonical_sha256(entry_core)}
        complete = status == "complete"
        entries = [entry] if complete else []
        body = {
            "format": FALLBACK_COVERAGE_RECEIPT_FORMAT,
            "status": status,
            "authority": "implementation coverage only",
            "checker": {"id": "fixture", "version": 1},
            "schemas": {},
            "policy": {
                "potential_transfers_may_be_deferred": False,
                "candidate_generation_fails_closed": True,
            },
            "inputs": {
                "machine_ir": {"sha256": self.machine_ir_sha256},
                "machine_ir_manifest": {"sha256": _sha256_file(self.manifest)},
                # This legacy report is diagnostic input only. Its status is not
                # read by the v2 candidate-authority decision.
                "static_semantic_completeness_report": {
                    "format": "stage-b-static-hybrid-completeness-v1",
                    "status": "complete",
                    "sha256": hashlib.sha256(b"legacy-report").hexdigest(),
                },
            },
            "reachability": {
                "status": "complete" if complete else "incomplete",
                "roots": ["unit:entry"],
                "reachable_unit_ids": ["unit:entry"] if complete else [],
            },
            "counts": {
                "rooted_reachable_units": 1 if complete else 0,
                "implementation_entries": len(entries),
                "machine_ir_fallback": len(entries),
                "portable_replacement": 0,
                "blockers": 0 if complete else 1,
            },
            "entries": entries,
            "blockers": [] if complete else [{"code": "lowering_missing"}],
        }
        return {**body, "receipt_sha256": _canonical_sha256(body)}

    def _build(self, **overrides: object):
        arguments = {
            "final_static_hybrid_audit": self.audit,
            "authority_bundle": self.bundle_payload,
            "machine_ir": self.machine_ir,
            "machine_ir_manifest": self.manifest,
            "fallback_coverage_receipt": self.fallback,
        }
        arguments.update(overrides)
        return build_stage_b_candidate_authority_v2(**arguments)

    def test_complete_v2_evidence_authorizes_with_stable_content_id(self) -> None:
        first = self._build()
        second = self._build()

        self.assertEqual(first.status, CandidateAuthorityV2Status.AUTHORIZED)
        self.assertTrue(first.authorizes)
        self.assertTrue(all(first.checks.values()))
        self.assertEqual(first.content_id, second.content_id)
        self.assertEqual(
            first.to_payload()["format"], STAGE_B_CANDIDATE_AUTHORITY_V2_FORMAT
        )
        self.assertEqual(parse_stage_b_candidate_authority_v2(first.to_json()), first)
        self.assertIs(require_stage_b_candidate_authority_v2(first), first)

    def test_validation_recomputes_exact_inputs_and_rejects_stale_receipt(self) -> None:
        receipt = self._build()
        validated = validate_stage_b_candidate_authority_v2(
            receipt=receipt,
            final_static_hybrid_audit=self.audit,
            authority_bundle=self.bundle_payload,
            machine_ir=self.machine_ir,
            machine_ir_manifest=self.manifest,
            fallback_coverage_receipt=self.fallback,
            require_authorized=True,
        )
        self.assertEqual(validated, receipt)

        changed = copy.deepcopy(self.fallback)
        changed["authority"] = "changed diagnostic text"
        changed["receipt_sha256"] = _canonical_sha256({
            key: value for key, value in changed.items()
            if key != "receipt_sha256"
        })
        with self.assertRaisesRegex(CandidateAuthorityV2Error, "stale"):
            validate_stage_b_candidate_authority_v2(
                receipt=receipt,
                final_static_hybrid_audit=self.audit,
                authority_bundle=self.bundle_payload,
                machine_ir=self.machine_ir,
                machine_ir_manifest=self.manifest,
                fallback_coverage_receipt=changed,
            )

    def test_missing_v2_inputs_are_incomplete_and_fail_the_build_gate(self) -> None:
        legacy = {
            "format": "stage-b-final-candidate-generation-authorization-v1",
            "status": "authorized",
        }
        receipt = self._build(
            final_static_hybrid_audit=self.root / "missing-audit.json",
            authority_bundle=self.root / "missing-bundle.json",
            legacy_diagnostic_artifacts=[legacy],
        )

        self.assertEqual(receipt.status, CandidateAuthorityV2Status.INCOMPLETE)
        self.assertFalse(receipt.authorizes)
        self.assertEqual(receipt.legacy_diagnostics[0]["authorizes"], False)
        with self.assertRaises(CandidateAuthorityV2GateError) as caught:
            require_stage_b_candidate_authority_v2(receipt)
        self.assertEqual(caught.exception.status, CandidateAuthorityV2Status.INCOMPLETE)
        with self.assertRaises(CandidateAuthorityV2GateError):
            validate_stage_b_candidate_authority_v2(
                receipt=receipt,
                final_static_hybrid_audit=self.root / "missing-audit.json",
                authority_bundle=self.root / "missing-bundle.json",
                machine_ir=self.machine_ir,
                machine_ir_manifest=self.manifest,
                fallback_coverage_receipt=self.fallback,
                legacy_diagnostic_artifacts=[legacy],
            )

    def test_incomplete_bundle_remains_incomplete_when_audit_agrees(self) -> None:
        incomplete = self._bundle(alternatives=FiniteAlternatives.of([0], maximum=1))
        record = incomplete.records[0]
        assert isinstance(record, ValueFact)
        incomplete_record = ValueFact(
            binding=record.binding,
            location=record.location,
            width_bits=record.width_bits,
            alternatives=None,
        )
        incomplete = AuthorityBundle.of(
            binary=incomplete.binary,
            records=(incomplete_record,),
            required_content_ids=(incomplete_record.content_id,),
        )
        receipt = self._build(
            authority_bundle=incomplete.to_payload(),
            final_static_hybrid_audit=self._audit(incomplete, status="incomplete"),
        )
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.INCOMPLETE)
        self.assertIn(
            "authority_bundle_incomplete", {issue.code for issue in receipt.issues}
        )

    def test_passing_audit_over_incomplete_bundle_is_violated(self) -> None:
        complete_record = self.bundle.records[0]
        assert isinstance(complete_record, ValueFact)
        missing = ValueFact(
            binding=complete_record.binding,
            location=complete_record.location,
            width_bits=complete_record.width_bits,
            alternatives=None,
        )
        bundle = AuthorityBundle.of(
            binary=self.bundle.binary,
            records=(missing,),
            required_content_ids=(missing.content_id,),
        )
        receipt = self._build(
            authority_bundle=bundle.to_payload(),
            final_static_hybrid_audit=self._audit(bundle, status="pass"),
        )
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.VIOLATED)
        self.assertIn(
            "final_v2_audit_authority_conflict",
            {issue.code for issue in receipt.issues},
        )

    def test_exact_machine_ir_hash_mismatch_is_violated(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        manifest["artifacts"]["machine_ir"]["sha256"] = "0" * 64
        _write_json(self.manifest, manifest)
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.VIOLATED)
        self.assertIn(
            "manifest_machine_ir_hash_mismatch",
            {issue.code for issue in receipt.issues},
        )

    def test_incomplete_fallback_receipt_is_not_authority(self) -> None:
        receipt = self._build(fallback_coverage_receipt=self._fallback(status="incomplete"))
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.INCOMPLETE)
        self.assertFalse(receipt.authorizes)

    def test_complete_fallback_claim_with_missing_entry_is_violated(self) -> None:
        fallback = copy.deepcopy(self.fallback)
        fallback["entries"] = []
        fallback["counts"]["implementation_entries"] = 0
        fallback["counts"]["machine_ir_fallback"] = 0
        body = {key: value for key, value in fallback.items() if key != "receipt_sha256"}
        fallback["receipt_sha256"] = _canonical_sha256(body)

        receipt = self._build(fallback_coverage_receipt=fallback)
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.VIOLATED)
        self.assertIn(
            "fallback_coverage_claim_conflict",
            {issue.code for issue in receipt.issues},
        )

    def test_tainted_fact_cannot_be_accepted(self) -> None:
        tainted = self._bundle(
            alternatives=FiniteAlternatives.of(
                [{"kind": "static_data", "tainted": True}], maximum=1
            )
        )
        receipt = self._build(
            authority_bundle=tainted.to_payload(),
            final_static_hybrid_audit=self._audit(tainted, status="pass"),
        )
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.VIOLATED)
        self.assertIn(
            "tainted_accepted_fact", {issue.code for issue in receipt.issues}
        )

    def test_deferred_transfer_cannot_be_accepted(self) -> None:
        fallback = copy.deepcopy(self.fallback)
        fallback["entries"][0]["runtime_disposition"] = "deferred_until_runtime"
        entry_body = dict(fallback["entries"][0])
        entry_body.pop("entry_sha256")
        fallback["entries"][0]["entry_sha256"] = _canonical_sha256(entry_body)
        body = {key: value for key, value in fallback.items() if key != "receipt_sha256"}
        fallback["receipt_sha256"] = _canonical_sha256(body)

        receipt = self._build(fallback_coverage_receipt=fallback)
        self.assertEqual(receipt.status, CandidateAuthorityV2Status.VIOLATED)
        self.assertIn(
            "deferred_transfer_present", {issue.code for issue in receipt.issues}
        )

    def test_parse_rejects_tampering_and_v1_receipts(self) -> None:
        payload = self._build().to_payload()
        payload["content_id"] = "stage-b-candidate-authority-v2:" + "0" * 64
        with self.assertRaisesRegex(CandidateAuthorityV2Error, "content ID"):
            parse_stage_b_candidate_authority_v2(payload)

        legacy = copy.deepcopy(payload)
        legacy["format"] = "stage-b-final-candidate-generation-authorization-v1"
        with self.assertRaisesRegex(CandidateAuthorityV2Error, "v1"):
            parse_stage_b_candidate_authority_v2(legacy)


if __name__ == "__main__":
    unittest.main()
