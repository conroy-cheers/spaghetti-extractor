from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.authority._schema import stable_id
from spaghetti_extractor.authority.authority_common import PrimaryBlockerV3
from spaghetti_extractor.authority.final_authority import (
    FINAL_AUTHORITY_ARTIFACT_KIND_V3,
    FINAL_AUTHORITY_CODEC_V3,
    FINAL_AUTHORITY_SCOPE_V3,
    AuthorityFamilyBindingV3,
    FinalAuthorityRecordV3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
)
from spaghetti_extractor.candidate.authority import (
    CandidateAuthorityV3Error,
    CandidateAuthorityV3GateError,
    CandidateAuthorityV3Status,
    build_candidate_authority,
    parse_candidate_authority,
    require_candidate_authority,
    validate_candidate_authority,
)
from spaghetti_extractor.stage_b_fallback_coverage import (
    FALLBACK_COVERAGE_RECEIPT_FORMAT,
)
from spaghetti_extractor.components.formats import (
    COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
    COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
)


PE_SHA256 = "a" * 64
FAMILY_NAMES = (
    "callbacks",
    "exceptional_transitions",
    "external_sites",
    "fallback_coverage",
    "inductive_authority",
    "isa_qualification",
    "root_closure",
    "semantic_index",
)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _unit() -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:1000",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "contract_sha256": "b" * 64,
            "instruction_bytes_sha256": "c" * 64,
        },
        "instructions": [{"rva_start": 0x1000, "rva_end": 0x1001}],
        "semantics": {"external_events": [], "faults": [], "outcome": {"kind": "return"}},
    }


class CandidateAuthorityV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.unit = _unit()
        self.unit_bytes = canonical_json_bytes_v3(self.unit)
        self.unit_sha256 = hashlib.sha256(self.unit_bytes).hexdigest()
        self.machine_ir = self.root / "machine-ir.jsonl"
        self.machine_ir.write_bytes(self.unit_bytes + b"\n")
        self.machine_ir_sha256 = hashlib.sha256(self.machine_ir.read_bytes()).hexdigest()
        self.manifest = self.root / "machine-ir-manifest.json"
        _write_json(self.manifest, {
            "format": "stage-a-machine-ir-v2",
            "binary": {"sha256": PE_SHA256},
            "inputs": {"original_pe": {"sha256": PE_SHA256}},
            "counts": {"units": 1},
            "artifacts": {
                "machine_ir": {
                    "format": "stage-a-machine-ir-v2",
                    "sha256": self.machine_ir_sha256,
                }
            },
        })
        self.inventory_sha256 = canonical_sha256_v3(["unit:1000"])
        self.universe_sha256 = canonical_sha256_v3({
            "pe_sha256": PE_SHA256,
            "units": [{"id": "unit:1000", "unit_ir_sha256": self.unit_sha256}],
        })
        self.final = self.root / "final"
        self._write_final(self.final)
        self.component_runtime = self.root / "component-runtime"
        self._write_component_runtime(self.component_runtime)
        self.fallback = self.root / "fallback.json"
        self._write_fallback(self.fallback)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _families(self) -> tuple[AuthorityFamilyBindingV3, ...]:
        return tuple(
            AuthorityFamilyBindingV3(
                input_name=name,
                artifact_kind=f"{name}-v3",
                artifact_id=f"artifact-set-v3:{hashlib.sha256(name.encode()).hexdigest()}",
                manifest_sha256=hashlib.sha256(f"manifest:{name}".encode()).hexdigest(),
                record_count=1,
                record_inventory_sha256=hashlib.sha256(f"inventory:{name}".encode()).hexdigest(),
            )
            for name in FAMILY_NAMES
        )

    def _write_final(
        self,
        path: Path,
        *,
        pe_sha256: str = PE_SHA256,
        unit_count: int = 1,
        inventory_sha256: str | None = None,
        universe_sha256: str | None = None,
        status: str = "complete",
        authorizing: bool = True,
    ) -> None:
        families = self._families()
        inventory = self.inventory_sha256 if inventory_sha256 is None else inventory_sha256
        identity = {
            "scope": FINAL_AUTHORITY_SCOPE_V3,
            "families": [row.to_payload() for row in families],
            "exact_unit_count": unit_count,
            "exact_unit_inventory_sha256": inventory,
        }
        blocker = None
        if status != "complete":
            blocker = PrimaryBlockerV3(status, "fixture_not_authorizing")
        final = FinalAuthorityRecordV3(
            record_id=stable_id("final-authority-v3", identity),
            scope=FINAL_AUTHORITY_SCOPE_V3,
            status=status,
            authorizing=authorizing,
            pe_sha256=pe_sha256 if status == "complete" else None,
            exact_universe_sha256=(
                self.universe_sha256 if universe_sha256 is None else universe_sha256
            ) if status == "complete" else None,
            exact_unit_count=unit_count,
            exact_unit_inventory_sha256=inventory,
            families=families,
            primary_blocker=blocker,
            dependencies=(),
        )
        ArtifactSetWriterV3(
            artifact_kind=FINAL_AUTHORITY_ARTIFACT_KIND_V3,
            bindings=(ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256),),
            status="complete",
        ).write(path, (FINAL_AUTHORITY_CODEC_V3.write(final.record_id, final),))

    def _fallback_payload(self) -> dict[str, object]:
        entry_core = {
            "unit_id": "unit:1000",
            "rva": 0x1000,
            "unit_contract_sha256": "b" * 64,
            "source_span_sha256": "c" * 64,
            "machine_ir_record_sha256": self.unit_sha256,
            "lowering_transfer_sha256": "d" * 64,
            "implementation_kind": "machine_ir_fallback",
            "dispatch_lookup": "stage_b_program_lookup",
            "portable_replacement": None,
        }
        entry = {**entry_core, "entry_sha256": canonical_sha256_v3(entry_core)}
        body: dict[str, object] = {
            "format": FALLBACK_COVERAGE_RECEIPT_FORMAT,
            "status": "complete",
            "authority": "implementation availability only",
            "checker": {"id": "fixture", "version": 3},
            "schemas": {},
            "policy": {
                "potential_transfers_may_be_deferred": False,
                "structural_units_require_lowering": True,
                "one_implementation_kind_per_structural_unit": True,
                "rooted_containment_authority": False,
                "default_implementation_kind": "machine_ir_fallback",
                "portable_replacements_must_be_explicit": True,
                "portable_fallback_on_unimplemented": False,
                "candidate_generation_fails_closed": True,
            },
            "inputs": {
                "machine_ir": {"sha256": self.machine_ir_sha256},
                "machine_ir_manifest": {
                    "sha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest()
                },
                "portable_replacements": {
                    "artifact": {
                        "path": "portable-component-selection.json",
                        "sha256": hashlib.sha256(
                            (self.component_runtime / "portable-component-selection.json").read_bytes()
                        ).hexdigest(),
                    }
                },
            },
            "counts": {
                "structural_units": 1,
                "implementation_entries": 1,
                "machine_ir_fallback": 1,
                "portable_replacement": 0,
                "portable_component_member": 0,
                "blockers": 0,
            },
            "entries": [entry],
            "blockers": [],
        }
        return {**body, "receipt_sha256": canonical_sha256_v3(body)}

    def _write_fallback(self, path: Path, payload: dict[str, object] | None = None) -> None:
        _write_json(path, self._fallback_payload() if payload is None else payload)

    def _build(self, **overrides: object):
        arguments = {
            "final_authority": self.final,
            "machine_ir": self.machine_ir,
            "machine_ir_manifest": self.manifest,
            "fallback_coverage_receipt": self.fallback,
            "component_runtime_package": self.component_runtime,
        }
        arguments.update(overrides)
        return build_candidate_authority(**arguments)

    def test_complete_exact_evidence_authorizes_deterministically(self) -> None:
        first = self._build()
        second = self._build()
        self.assertEqual(first.status, CandidateAuthorityV3Status.AUTHORIZED)
        self.assertTrue(first.authorizing)
        self.assertEqual(first.to_bytes(), second.to_bytes())
        self.assertEqual(parse_candidate_authority(first.to_bytes()), first)
        self.assertIs(require_candidate_authority(first), first)

    def test_public_operations_are_owned_by_focused_modules(self) -> None:
        self.assertEqual(
            build_candidate_authority.__module__,
            "spaghetti_extractor.candidate.authority.checker",
        )
        self.assertEqual(
            validate_candidate_authority.__module__,
            "spaghetti_extractor.candidate.authority.checker",
        )
        self.assertEqual(
            require_candidate_authority.__module__,
            "spaghetti_extractor.candidate.authority.checker",
        )
        self.assertEqual(
            parse_candidate_authority.__module__,
            "spaghetti_extractor.candidate.authority.io",
        )
        self.assertEqual(
            CandidateAuthorityV3Status.__module__,
            "spaghetti_extractor.candidate.authority.model",
        )

    def test_stale_final_record_is_violated_and_stale_receipt_is_rejected(self) -> None:
        receipt = self._build()
        stale = self.root / "stale-final"
        self._write_final(stale, universe_sha256="0" * 64)
        rejected = self._build(final_authority=stale)
        self.assertEqual(rejected.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn(
            "final_authority_exact_universe_mismatch",
            {issue.code for issue in rejected.issues},
        )
        with self.assertRaisesRegex(CandidateAuthorityV3Error, "stale"):
            validate_candidate_authority(
                receipt=receipt,
                final_authority=stale,
                machine_ir=self.machine_ir,
                machine_ir_manifest=self.manifest,
                fallback_coverage_receipt=self.fallback,
                component_runtime_package=self.component_runtime,
            )

    def _write_component_runtime(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        selection = path / "portable-component-selection.json"
        _write_json(selection, {"format": "fixture-selection", "entries": []})
        core = {
            "format": COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
            "status": "ready",
            "executes_original_binary": False,
            "bindings": {"machine_ir_sha256": self.machine_ir_sha256},
            "policy": {
                "runtime_package_is_sole_candidate_authority": True,
                "enabled_components_must_be_qualified": True,
                "subsumed_members_may_not_fallback": True,
                "fallback_on_unimplemented": False,
                "original_execution_forbidden": True,
            },
            "components": [],
            "counts": {
                "portable_components": 0,
                "portable_units": 0,
                "override_entries": 0,
            },
            "artifacts": {
                "portable_selection": {
                    "path": selection.name,
                    "sha256": hashlib.sha256(selection.read_bytes()).hexdigest(),
                },
                "region_overrides": None,
            },
        }
        runtime_sha256 = canonical_sha256_v3(core)
        _write_json(
            path / "component-runtime-package.json",
            {**core, "runtime_package_sha256": runtime_sha256},
        )
        completion_core = {
            "format": COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
            "status": "complete",
            "runtime_package_sha256": runtime_sha256,
            "activation_plan_sha256": "0" * 64,
            "structural_units": 1,
            "portable_units": 0,
            "fallback_units": 1,
            "ownership_complete": True,
            "ownership_exclusive": True,
            "executes_original_binary": False,
        }
        _write_json(
            path / "component-runtime-completion.json",
            {
                **completion_core,
                "completion_sha256": canonical_sha256_v3(completion_core),
            },
        )

    def test_wrong_final_pe_count_or_inventory_is_violated(self) -> None:
        cases = (
            ("pe", {"pe_sha256": "9" * 64}, "final_authority_pe_mismatch"),
            ("count", {"unit_count": 2}, "final_authority_unit_count_mismatch"),
            ("inventory", {"inventory_sha256": "8" * 64}, "final_authority_unit_inventory_mismatch"),
        )
        for label, options, code in cases:
            with self.subTest(label=label):
                path = self.root / f"wrong-{label}"
                self._write_final(path, **options)
                receipt = self._build(final_authority=path)
                self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
                self.assertIn(code, {issue.code for issue in receipt.issues})

    def test_missing_and_contradictory_fallback_are_distinct(self) -> None:
        missing = self._build(
            fallback_coverage_receipt=self.root / "missing-fallback.json"
        )
        self.assertEqual(missing.status, CandidateAuthorityV3Status.INCOMPLETE)
        with self.assertRaises(CandidateAuthorityV3GateError):
            require_candidate_authority(missing)

        payload = copy.deepcopy(self._fallback_payload())
        payload["entries"] = []
        payload["counts"]["implementation_entries"] = 0  # type: ignore[index]
        payload["counts"]["machine_ir_fallback"] = 0  # type: ignore[index]
        body = {key: value for key, value in payload.items() if key != "receipt_sha256"}
        payload["receipt_sha256"] = canonical_sha256_v3(body)
        contradictory = self.root / "contradictory-fallback.json"
        self._write_fallback(contradictory, payload)
        rejected = self._build(fallback_coverage_receipt=contradictory)
        self.assertEqual(rejected.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn(
            "fallback_coverage_claim_conflict",
            {issue.code for issue in rejected.issues},
        )

    def test_non_authorizing_final_record_is_incomplete_despite_complete_manifest(self) -> None:
        path = self.root / "non-authorizing-final"
        self._write_final(path, status="incomplete", authorizing=False)
        receipt = self._build(final_authority=path)
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.INCOMPLETE)
        self.assertFalse(receipt.authorizing)
        self.assertTrue(receipt.checks["final_artifact_complete"])
        self.assertFalse(receipt.checks["final_record_authorizing"])

    def test_missing_final_artifact_is_incomplete(self) -> None:
        receipt = self._build(final_authority=self.root / "missing-final")
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.INCOMPLETE)
        self.assertIn("final_authority_missing", {row.code for row in receipt.issues})

    def test_missing_machine_ir_is_incomplete(self) -> None:
        receipt = self._build(machine_ir=self.root / "missing-machine-ir.jsonl")
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.INCOMPLETE)
        self.assertIn("machine_ir_missing", {row.code for row in receipt.issues})

    def test_missing_machine_manifest_is_incomplete(self) -> None:
        receipt = self._build(
            machine_ir_manifest=self.root / "missing-machine-ir-manifest.json"
        )
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.INCOMPLETE)
        self.assertIn("machine_ir_manifest_missing", {row.code for row in receipt.issues})

    def test_corrupt_final_manifest_is_violated(self) -> None:
        (self.final / "manifest.json").write_bytes(b"not-json")
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn("final_authority_corrupt", {row.code for row in receipt.issues})

    def test_machine_ir_duplicate_unit_id_is_violated(self) -> None:
        self.machine_ir.write_bytes(self.unit_bytes + b"\n" + self.unit_bytes + b"\n")
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn("machine_ir_corrupt", {row.code for row in receipt.issues})

    def test_machine_ir_duplicate_rva_is_violated(self) -> None:
        other = copy.deepcopy(self.unit)
        other["id"] = "unit:alias"
        self.machine_ir.write_bytes(
            self.unit_bytes + b"\n" + canonical_json_bytes_v3(other) + b"\n"
        )
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn("machine_ir_corrupt", {row.code for row in receipt.issues})

    def test_manifest_unit_count_mismatch_is_violated(self) -> None:
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["counts"]["units"] = 2
        _write_json(self.manifest, payload)
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn(
            "machine_ir_manifest_binding_mismatch",
            {row.code for row in receipt.issues},
        )

    def test_manifest_machine_ir_hash_mismatch_is_violated(self) -> None:
        payload = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload["artifacts"]["machine_ir"]["sha256"] = "0" * 64
        _write_json(self.manifest, payload)
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn(
            "machine_ir_manifest_binding_mismatch",
            {row.code for row in receipt.issues},
        )

    def test_fallback_unsafe_policy_is_violated(self) -> None:
        payload = copy.deepcopy(self._fallback_payload())
        payload["policy"]["potential_transfers_may_be_deferred"] = True  # type: ignore[index]
        body = {key: value for key, value in payload.items() if key != "receipt_sha256"}
        payload["receipt_sha256"] = canonical_sha256_v3(body)
        self._write_fallback(self.fallback, payload)
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn("fallback_coverage_policy_unsafe", {row.code for row in receipt.issues})

    def test_fallback_duplicate_unit_entry_is_violated(self) -> None:
        payload = copy.deepcopy(self._fallback_payload())
        payload["entries"].append(copy.deepcopy(payload["entries"][0]))  # type: ignore[union-attr,index]
        payload["counts"]["implementation_entries"] = 2  # type: ignore[index]
        payload["counts"]["machine_ir_fallback"] = 2  # type: ignore[index]
        body = {key: value for key, value in payload.items() if key != "receipt_sha256"}
        payload["receipt_sha256"] = canonical_sha256_v3(body)
        self._write_fallback(self.fallback, payload)
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn("fallback_coverage_claim_conflict", {row.code for row in receipt.issues})

    def test_fallback_receipt_identity_mismatch_is_violated(self) -> None:
        payload = copy.deepcopy(self._fallback_payload())
        payload["receipt_sha256"] = "0" * 64
        self._write_fallback(self.fallback, payload)
        receipt = self._build()
        self.assertEqual(receipt.status, CandidateAuthorityV3Status.VIOLATED)
        self.assertIn("fallback_coverage_identity_stale", {row.code for row in receipt.issues})

    def test_candidate_receipt_content_id_mutation_is_rejected(self) -> None:
        payload = self._build().to_payload()
        payload["content_id"] = "stage-b-candidate-authority-v3:" + "0" * 64
        with self.assertRaisesRegex(CandidateAuthorityV3Error, "stale"):
            parse_candidate_authority(payload)

    def test_candidate_receipt_authorizing_bit_mutation_is_rejected(self) -> None:
        payload = self._build().to_payload()
        payload["authorizing"] = False
        with self.assertRaisesRegex(CandidateAuthorityV3Error, "authorization bit"):
            parse_candidate_authority(payload)


if __name__ == "__main__":
    unittest.main()
