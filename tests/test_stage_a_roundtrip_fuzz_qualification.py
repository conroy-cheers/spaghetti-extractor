from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.schema import (
    RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.roundtrip_fuzz.metrics import (
    GenericityEvidence,
    GenericityInventory,
    StaticCaseTiming,
)
from spaghetti_extractor.roundtrip_fuzz.model import (
    ArtifactRef,
    CaseExpectation,
    CaseManifest,
    CorpusCaseRef,
    CorpusManifest,
    ExpectedCounts,
    ExpectedDisposition,
    NegativeMutation,
    ToolchainIdentity,
    write_case_manifest,
    write_corpus_manifest,
)
from spaghetti_extractor.roundtrip_fuzz.qualification import (
    ROUNDTRIP_FEASIBILITY_REPORT_FORMAT,
    write_roundtrip_qualification_report,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file


class StageARoundTripFuzzQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest_path, self.cases = self._write_corpus(self.root / "corpus")
        self.aggregate = self._aggregate(self.cases)
        self.aggregate_path = self.root / "aggregate.json"
        self._write_json(self.aggregate_path, self.aggregate)
        self.static_timings = tuple(
            StaticCaseTiming(case.id, 0.1, 0.1) for case in self.cases
        )
        self.warm_results = tuple(self._warm_result(case) for case in self.cases)
        self.genericity = GenericityEvidence(
            baseline=GenericityInventory(
                structural_shapes=("base",),
                proof_rules=("Core.existingRelated",),
            ),
            current=GenericityInventory(
                structural_shapes=("base", "negative", "positive"),
                proof_rules=("Core.existingRelated", "Core.genericRefinement"),
            ),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_emits_diagnostic_deterministic_feasibility_report(self) -> None:
        output = self.root / "report.json"
        report = self._write_report(output=output)

        self.assertEqual(report["format"], ROUNDTRIP_FEASIBILITY_REPORT_FORMAT)
        self.assertEqual(report["status"], "satisfied")
        self.assertEqual(
            report["counts"],
            {
                "cases": 2,
                "expected": {"pass": 1, "violated": 1, "incomplete": 0},
                "actual": {"pass": 1, "violated": 1, "incomplete": 0},
                "expectation_matches": 2,
                "expectation_mismatches": 0,
                "unexpected_negative_passes": 0,
            },
        )
        self.assertTrue(report["authority"]["diagnostic_only"])
        self.assertFalse(report["authority"]["proof_authority"])
        self.assertNotIn("timestamp", json.dumps(report).lower())
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")), report
        )
        self.assertEqual(
            {gate["status"] for gate in report["gates"]}, {"satisfied"}
        )
        self.assertEqual(
            set(report["inputs"]),
            {
                "corpus_manifest_sha256",
                "nix_aggregate_canonical_sha256",
                "static_timings_canonical_sha256",
                "warm_results_canonical_sha256",
                "genericity_canonical_sha256",
            },
        )

    def test_rejects_malformed_aggregate(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        aggregate["format"] = "stage-a-roundtrip-nix-qualification-v0"
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(StageAInputError, "unsupported.*format"):
            self._write_report()

    def test_rejects_missing_case(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        aggregate["cases"] = aggregate["cases"][:1]
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(StageAInputError, "missing cases"):
            self._write_report()

    def test_rejects_wrong_positive_authority(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        positive = self._aggregate_case(aggregate, "positive")
        positive["result"]["acceptance"]["authority"] = "evidence_only"
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(
            StageAInputError, "lacks whole-program Lean authority"
        ):
            self._write_report()

    def test_rejects_unsupported_positive_theorem(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        positive = self._aggregate_case(aggregate, "positive")
        positive["result"]["acceptance"]["theorem"] = "StageA.fakeTheorem"
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(
            StageAInputError, "lacks whole-program Lean authority"
        ):
            self._write_report()

    def test_rejects_unchecked_violation(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        negative = self._aggregate_case(aggregate, "negative")
        negative["result"]["violation"]["checks"]["lean_trust_zero"] = False
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(StageAInputError, "lacks checked evidence"):
            self._write_report()

    def test_rejects_unmeasured_pack_evidence(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        aggregate["cases"][0]["measurement"]["measured"] = False
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(
            StageAInputError, "lacks measured scheduling evidence"
        ):
            self._write_report()

    def test_rejects_negative_pass(self) -> None:
        aggregate = copy.deepcopy(self.aggregate)
        negative = self._aggregate_case(aggregate, "negative")
        negative["actual"] = "pass"
        self._write_json(self.aggregate_path, aggregate)

        with self.assertRaisesRegex(StageAInputError, "negative.*passed"):
            self._write_report()

    def test_requires_explicit_static_timing_for_every_case(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "static timings mismatch"):
            self._write_report(static_timings=self.static_timings[:1])

    def test_requires_explicit_warm_result_for_every_case(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "warm results mismatch"):
            self._write_report(warm_results=self.warm_results[:1])

    def test_report_is_order_independent(self) -> None:
        first_path = self.root / "first.json"
        first = self._write_report(output=first_path)

        reordered = copy.deepcopy(self.aggregate)
        reordered["cases"].reverse()
        reordered["trust"]["supported_acceptance_theorems"].reverse()
        self._write_json(self.aggregate_path, reordered)
        second_path = self.root / "second.json"
        second = self._write_report(
            output=second_path,
            static_timings=tuple(reversed(self.static_timings)),
            warm_results=tuple(reversed(self.warm_results)),
        )

        self.assertEqual(first, second)
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())

    def _write_report(
        self,
        *,
        output: Path | None = None,
        static_timings: tuple[StaticCaseTiming, ...] | None = None,
        warm_results: tuple[dict[str, object], ...] | None = None,
    ) -> dict[str, object]:
        return write_roundtrip_qualification_report(
            corpus_manifest_path=self.manifest_path,
            nix_aggregate_result_path=self.aggregate_path,
            static_timings=(
                self.static_timings if static_timings is None else static_timings
            ),
            warm_results=(
                self.warm_results if warm_results is None else warm_results
            ),
            genericity=self.genericity,
            output_path=self.root / "report.json" if output is None else output,
        )

    def _write_corpus(
        self, root: Path
    ) -> tuple[Path, tuple[CaseManifest, CaseManifest]]:
        root.mkdir(parents=True)
        cases = (
            self._write_case(root, "positive", ExpectedDisposition.PASS, shard=0),
            self._write_case(root, "negative", ExpectedDisposition.VIOLATED, shard=1),
        )
        references = []
        for case in cases:
            case_path = root / case.id / "case.json"
            references.append(
                CorpusCaseRef(
                    case.id,
                    f"{case.id}/case.json",
                    sha256_file(case_path),
                    case.shard,
                )
            )
        manifest = CorpusManifest(
            generator_version="qualification-test-v1",
            root_seed=17,
            capability_profile="pe32-test",
            toolchain=ToolchainIdentity(
                id="test-toolchain",
                target="i686-w64-mingw32",
                compiler="test-cc",
                compiler_version="1",
                linker="test-ld",
                linker_version="1",
            ),
            cases=tuple(references),
            expected_counts=ExpectedCounts(1, 1, 0),
            shard_count=2,
        )
        manifest_path = root / "corpus.json"
        write_corpus_manifest(manifest_path, manifest)
        return manifest_path, cases

    def _write_case(
        self,
        corpus_root: Path,
        case_id: str,
        disposition: ExpectedDisposition,
        *,
        shard: int,
    ) -> CaseManifest:
        root = corpus_root / case_id
        root.mkdir()
        files = {
            "semantic_program": root / "semantic.json",
            "original_pe": root / "original.exe",
            "candidate_pe": root / "candidate.exe",
            "relation_contract": root / "relation.json",
        }
        for role, path in files.items():
            path.write_bytes(f"{case_id}:{role}\n".encode("ascii"))
        artifacts = tuple(
            ArtifactRef.from_path(role=role, root=root, path=path)
            for role, path in files.items()
        )
        semantic_hash = next(
            artifact.sha256
            for artifact in artifacts
            if artifact.role == "semantic_program"
        )
        case = CaseManifest(
            id=case_id,
            semantic_program_sha256=semantic_hash,
            parent_seed=17 + shard,
            template="straight-line-arithmetic",
            transformations=("register-reassignment",),
            expectation=(
                CaseExpectation(disposition, None, None)
                if disposition is ExpectedDisposition.PASS
                else CaseExpectation(disposition, "semantic-effect", None)
            ),
            mutation=(
                None
                if disposition is ExpectedDisposition.PASS
                else NegativeMutation(
                    "wrong-constant", "constant differs", "entry"
                )
            ),
            capability_profile="pe32-test",
            capabilities=("direct-control",),
            proof_families=("segment-refinement",),
            artifacts=artifacts,
            replay=("spaghetti-extractor", "stage-a-fuzz-run"),
            shard=shard,
        )
        write_case_manifest(root / "case.json", case)
        return case

    def _aggregate(self, cases: tuple[CaseManifest, ...]) -> dict[str, object]:
        aggregate_cases = [self._aggregate_wrapper(case) for case in cases]
        return {
            "format": "stage-a-roundtrip-nix-qualification-v1",
            "status": "pass",
            "corpus": {
                "manifest": "/nix/store/test-corpus/corpus.json",
                "smoke_store_path": "/nix/store/test-corpus",
                "generator_version": "qualification-test-v1",
                "expected_counts": {
                    "pass": 1,
                    "violated": 1,
                    "incomplete": 0,
                },
            },
            "counts": {
                "cases": 2,
                "pass": 1,
                "violated": 1,
                "incomplete": 0,
                "declared_expectations_match_manifest": True,
                "expectation_mismatches": 0,
                "unexpected_passes": 0,
            },
            "expectation_mismatch_case_ids": [],
            "unexpected_pass_case_ids": [],
            "packs": [{
                "id": "pack-0",
                "status": "pass",
                "store_path": "/nix/store/test-pack",
                "derivation_path": "/nix/store/test-pack.drv",
                "result": "packs/pack-0.json",
            }],
            "cases": aggregate_cases,
            "trust": {
                "positive_pass_requires": "whole_program_lean",
                "supported_acceptance_theorems": [
                    RELATIONAL_FINAL_ACCEPTANCE_THEOREM
                ],
                "negative_pass_is_fatal": True,
                "aggregator_has_proof_authority": False,
            },
            "reran_proofs": False,
            "executes_original_binary": False,
        }

    def _aggregate_wrapper(self, case: CaseManifest) -> dict[str, object]:
        disposition = case.expectation.disposition.value
        return {
            "case_id": case.id,
            "expected": disposition,
            "actual": disposition,
            "expectation_matched": True,
            "preparation_store_path": f"/nix/store/{case.id}-preparation",
            "preparation_derivation_path": f"/nix/store/{case.id}-preparation.drv",
            "proof_dag_store_path": f"/nix/store/{case.id}-proof",
            "proof_dag_derivation_path": f"/nix/store/{case.id}-proof.drv",
            "audit_store_path": f"/nix/store/{case.id}-audit",
            "audit_derivation_path": f"/nix/store/{case.id}-audit.drv",
            "measurement": {
                "estimatedMemoryMB": 1024,
                "estimatedSeconds": 1,
                "measured": True,
                "measurementSource": "qualification-test-calibration-v1",
                "resourceClass": "standard",
            },
            "result": self._inner_result(case),
        }

    def _inner_result(self, case: CaseManifest) -> dict[str, object]:
        if case.expectation.disposition is ExpectedDisposition.PASS:
            phases = [{"id": "proof-build-and-audit", "status": "pass"}]
            acceptance: dict[str, object] | None = {
                "theorem": RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
                "authority": "whole_program_lean",
            }
            violation = None
        else:
            phases = [{"id": "checked-violation-replay", "status": "violated"}]
            acceptance = None
            violation = {
                "format": "stage-a-checked-violation-result-v1",
                "status": "violated",
                "family": case.expectation.witness_family,
                "checks": {
                    "lean_trust_zero": True,
                    "replay_checked": True,
                },
                "trust": {
                    "role": "checked_inequivalence_witness",
                    "can_authorize_pass": False,
                    "raw_solver_status_sufficient": False,
                },
            }
        return {
            "format": "stage-a-roundtrip-case-result-v1",
            "case_id": case.id,
            "mode": "proof-core",
            "expected_disposition": case.expectation.disposition.value,
            "actual_disposition": case.expectation.disposition.value,
            "expectation_matched": True,
            "phases": phases,
            "acceptance": acceptance,
            "frontiers": [],
            "violation": violation,
            "error": None,
        }

    def _warm_result(self, case: CaseManifest) -> dict[str, object]:
        phase_id = (
            "proof-build-and-audit"
            if case.expectation.disposition is ExpectedDisposition.PASS
            else "checked-violation-replay"
        )
        return {
            "case_id": case.id,
            "expected_disposition": case.expectation.disposition.value,
            "actual_disposition": case.expectation.disposition.value,
            "expectation_matched": True,
            "phases": [{
                "id": phase_id,
                "status": case.expectation.disposition.value,
                "cache_hit": True,
                "duration_seconds": 0.2,
            }],
            "frontiers": [],
        }

    @staticmethod
    def _aggregate_case(
        aggregate: dict[str, object], case_id: str
    ) -> dict[str, object]:
        cases = aggregate["cases"]
        assert isinstance(cases, list)
        return next(item for item in cases if item["case_id"] == case_id)

    @staticmethod
    def _write_json(path: Path, payload: object) -> None:
        path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
