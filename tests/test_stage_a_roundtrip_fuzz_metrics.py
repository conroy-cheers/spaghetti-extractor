from __future__ import annotations

import unittest
from dataclasses import dataclass

from spaghetti_extractor.roundtrip_fuzz.metrics import (
    GenericityEvidence,
    GenericityInventory,
    QualificationThresholds,
    StaticCaseTiming,
    aggregate_roundtrip_metrics,
    evaluate_roundtrip_qualification,
)
from spaghetti_extractor.roundtrip_fuzz.model import (
    CaseExpectation,
    CaseManifest,
    ExpectedDisposition,
    NegativeMutation,
)
from spaghetti_extractor.stage_binary import StageAInputError


@dataclass(frozen=True)
class _Phase:
    id: str
    status: str
    cache_hit: bool
    duration_seconds: float


@dataclass(frozen=True)
class _Result:
    case_id: str
    expected: ExpectedDisposition
    actual: ExpectedDisposition
    expectation_matched: bool | None
    phases: tuple[_Phase, ...]


def _case(
    case_id: str,
    *,
    template: str,
    transformations: tuple[str, ...],
    expected: ExpectedDisposition,
    proof_families: tuple[str, ...] = ("segment-refinement",),
    mutation: NegativeMutation | None = None,
) -> CaseManifest:
    expectation = {
        ExpectedDisposition.PASS: CaseExpectation(ExpectedDisposition.PASS, None, None),
        ExpectedDisposition.VIOLATED: CaseExpectation(
            ExpectedDisposition.VIOLATED, "semantic-effect", None
        ),
        ExpectedDisposition.INCOMPLETE: CaseExpectation(
            ExpectedDisposition.INCOMPLETE, None, "unsupported-instruction"
        ),
    }[expected]
    return CaseManifest(
        id=case_id,
        semantic_program_sha256="0" * 64,
        parent_seed=1,
        template=template,
        transformations=transformations,
        expectation=expectation,
        mutation=mutation,
        capability_profile="pe32-test",
        capabilities=("direct-control",),
        proof_families=proof_families,
        artifacts=(),
        replay=("spaghetti-extractor", "stage-a-fuzz-run"),
        shard=0,
    )


def _result(
    case: CaseManifest,
    actual: ExpectedDisposition,
    *,
    duration: float,
    cache_hit: bool,
) -> _Result:
    return _Result(
        case_id=case.id,
        expected=case.expectation.disposition,
        actual=actual,
        expectation_matched=actual is case.expectation.disposition,
        phases=(
            _Phase("proof-preparation", "ready", cache_hit, duration),
            _Phase("proof-build-and-audit", actual.value, cache_hit, duration * 2),
        ),
    )


class StageARoundTripFuzzMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.positive = _case(
            "arithmetic-positive",
            template="straight-line-arithmetic",
            transformations=("register-reassignment",),
            expected=ExpectedDisposition.PASS,
        )
        self.incomplete_positive = _case(
            "branch-positive",
            template="guarded-branch",
            transformations=("branch-inversion", "register-reassignment"),
            expected=ExpectedDisposition.PASS,
        )
        self.negative = _case(
            "arithmetic-negative",
            template="straight-line-arithmetic",
            transformations=(),
            expected=ExpectedDisposition.VIOLATED,
            mutation=NegativeMutation(
                "wrong-constant", "constant differs", "entry"
            ),
        )

    def test_aggregates_coverage_timings_and_cache_hits(self) -> None:
        report = aggregate_roundtrip_metrics(
            cases=(self.positive, self.incomplete_positive, self.negative),
            results=(
                _result(self.positive, ExpectedDisposition.PASS, duration=1.0, cache_hit=True),
                _result(
                    self.incomplete_positive,
                    ExpectedDisposition.INCOMPLETE,
                    duration=3.0,
                    cache_hit=False,
                ),
                _result(
                    self.negative,
                    ExpectedDisposition.VIOLATED,
                    duration=2.0,
                    cache_hit=True,
                ),
            ),
        )

        payload = report.to_payload()
        self.assertEqual(payload["cases"]["total"], 3)
        self.assertEqual(payload["cases"]["expectation_matches"], 2)
        self.assertEqual(payload["cases"]["expectation_mismatches"], 1)
        self.assertFalse(payload["authority"]["proof_authority"])
        self.assertTrue(payload["authority"]["diagnostic_only"])
        self.assertEqual(payload["cache"]["phase_samples"], 6)
        self.assertEqual(payload["cache"]["hits"], 4)
        self.assertEqual(payload["cache"]["hit_rate"], 0.666667)
        self.assertEqual(payload["cases"]["actual_dispositions"]["pass"], 1)
        self.assertEqual(payload["cases"]["actual_dispositions"]["violated"], 1)

        phases = {phase["id"]: phase for phase in payload["phases"]}
        preparation = phases["proof-preparation"]
        self.assertEqual(preparation["samples"], 3)
        self.assertEqual(preparation["cache_hits"], 2)
        self.assertEqual(preparation["cache_misses"], 1)
        self.assertEqual(preparation["median_seconds"], 2.0)
        self.assertEqual(preparation["p95_seconds"], 3.0)

        axes = {axis["id"]: axis for axis in payload["coverage"]}
        transformations = {
            entry["id"]: entry
            for entry in axes["transformations"]["entries"]
        }
        self.assertEqual(transformations["register-reassignment"]["cases"], 2)
        self.assertEqual(
            transformations["register-reassignment"]["actual"]["pass"], 1
        )
        mutations = axes["mutations"]["entries"]
        self.assertEqual(mutations[0]["id"], "wrong-constant")
        self.assertEqual(mutations[0]["actual"]["violated"], 1)

    def test_accepts_serialized_case_results(self) -> None:
        typed = _result(
            self.positive,
            ExpectedDisposition.PASS,
            duration=0.25,
            cache_hit=False,
        )
        serialized = {
            "case_id": typed.case_id,
            "expected_disposition": typed.expected.value,
            "actual_disposition": typed.actual.value,
            "expectation_matched": typed.expectation_matched,
            "phases": [
                {
                    "id": phase.id,
                    "status": phase.status,
                    "cache_hit": phase.cache_hit,
                    "duration_seconds": phase.duration_seconds,
                }
                for phase in typed.phases
            ],
            "frontiers": [{
                "phase": "composition",
                "reason_code": "missing-product-edge",
            }],
        }
        report = aggregate_roundtrip_metrics(
            cases=(self.positive,),
            results=(serialized,),
        )
        self.assertEqual(report.expectation_matches, 1)
        self.assertEqual(
            report.to_payload()["frontiers"],
            [{
                "phase": "composition",
                "reason_code": "missing-product-edge",
                "cases": 1,
            }],
        )

    def test_reports_genericity_growth_without_authority(self) -> None:
        bad_negative_result = _result(
            self.negative,
            ExpectedDisposition.PASS,
            duration=1.0,
            cache_hit=False,
        )
        shapes = tuple(sorted((
            "straight-line-arithmetic|none|wrong-constant",
            "straight-line-arithmetic|register-reassignment|none",
        )))
        evidence = GenericityEvidence(
            baseline=GenericityInventory(source_lines=100),
            current=GenericityInventory(
                structural_shapes=shapes,
                semantic_constructors=("assign-register",),
                profile_branches=("profile-a", "profile-b"),
                special_case_conditionals=("case-id-dispatch",),
                source_lines=140,
            ),
            forbidden_dispatch_hits=("acceptance.py:case-id",),
        )
        report = aggregate_roundtrip_metrics(
            cases=(self.positive, self.negative),
            results=(
                _result(
                    self.positive,
                    ExpectedDisposition.PASS,
                    duration=1.0,
                    cache_hit=False,
                ),
                bad_negative_result,
            ),
            genericity=evidence,
        )
        payload = report.to_payload()
        warning_codes = {
            warning["code"] for warning in payload["genericity"]["warnings"]
        }
        self.assertIn("negative_case_passed", warning_codes)
        self.assertIn("forbidden_acceptance_dispatch", warning_codes)
        self.assertIn("special_case_conditional", warning_codes)
        self.assertIn("handler_growth_tracks_shape_growth", warning_codes)
        self.assertEqual(
            payload["genericity"]["deltas"]["structural_shape_growth"], 2
        )
        self.assertEqual(
            payload["genericity"]["deltas"]["source_lines_per_new_shape"],
            20.0,
        )
        self.assertFalse(payload["authority"]["proof_authority"])

    def test_rejects_case_result_mismatch(self) -> None:
        with self.assertRaises(StageAInputError):
            aggregate_roundtrip_metrics(
                cases=(self.positive,),
                results=(),
            )

    def test_qualification_gates_use_explicit_measured_observations(self) -> None:
        cases = (self.positive, self.incomplete_positive, self.negative)
        shapes = tuple(sorted(
            f"{case.template}|"
            f"{'+'.join(sorted(case.transformations)) or 'none'}|"
            f"{'none' if case.mutation is None else case.mutation.id}"
            for case in cases
        ))
        evidence = GenericityEvidence(
            baseline=GenericityInventory(
                structural_shapes=("existing-shape",),
                lean_constructors=("Core.existing",),
                proof_rules=("Core.existingRelated",),
            ),
            current=GenericityInventory(
                structural_shapes=("existing-shape", *shapes),
                lean_constructors=("Core.existing",),
                proof_rules=("Core.existingRelated", "Core.genericRefinement"),
            ),
        )
        static = tuple(
            StaticCaseTiming(case.id, 0.2, preflight)
            for case, preflight in zip(cases, (0.1, 0.2, 0.3), strict=True)
        )
        warm = tuple(
            _result(case, case.expectation.disposition, duration=0.5, cache_hit=True)
            for case in cases
        )

        first = evaluate_roundtrip_qualification(
            cases=cases,
            static_timings=static,
            warm_results=warm,
            genericity=evidence,
        ).to_payload()
        second = evaluate_roundtrip_qualification(
            cases=tuple(reversed(cases)),
            static_timings=tuple(reversed(static)),
            warm_results=tuple(reversed(warm)),
            genericity=evidence,
        ).to_payload()

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "satisfied")
        gates = {gate["id"]: gate for gate in first["gates"]}
        self.assertEqual(
            gates["per-case-generation-plus-static-preflight-median"]["observed"],
            0.4,
        )
        self.assertEqual(gates["warm-final-theorem-median"]["observed"], 1.0)
        self.assertEqual(gates["proof-phase-reuse-rate"]["observed"], 1.0)
        self.assertEqual(
            gates["generic-rule-to-structural-shape-growth-ratio"]["observed"],
            0.333333,
        )
        self.assertFalse(first["authority"]["proof_authority"])

    def test_qualification_reports_threshold_failures_and_missing_baseline(self) -> None:
        cases = (self.positive, self.negative)
        warm = (
            _result(
                self.positive,
                ExpectedDisposition.PASS,
                duration=5.0,
                cache_hit=False,
            ),
            _result(
                self.negative,
                ExpectedDisposition.VIOLATED,
                duration=1.0,
                cache_hit=True,
            ),
        )
        qualification = evaluate_roundtrip_qualification(
            cases=cases,
            static_timings=(
                StaticCaseTiming(self.positive.id, 0.5, 0.5),
                StaticCaseTiming(self.negative.id, 0.5, 0.5),
            ),
            warm_results=warm,
            genericity=GenericityEvidence(current=GenericityInventory()),
        ).to_payload()

        gates = {gate["id"]: gate for gate in qualification["gates"]}
        self.assertEqual(qualification["status"], "violated")
        self.assertEqual(
            gates["per-case-generation-plus-static-preflight-median"]["status"],
            "violated",
        )
        self.assertEqual(gates["warm-final-theorem-median"]["status"], "incomplete")
        self.assertEqual(gates["proof-phase-reuse-rate"]["status"], "violated")
        self.assertEqual(
            gates["generic-rule-to-structural-shape-growth-ratio"]["status"],
            "incomplete",
        )

    def test_qualification_rejects_partial_measurement_sets(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "static timings mismatch"):
            evaluate_roundtrip_qualification(
                cases=(self.positive,),
                static_timings=(),
                warm_results=(
                    _result(
                        self.positive,
                        ExpectedDisposition.PASS,
                        duration=0.1,
                        cache_hit=True,
                    ),
                ),
                genericity=GenericityEvidence(current=GenericityInventory()),
            )

    def test_qualification_thresholds_are_strict_and_validated(self) -> None:
        with self.assertRaises(StageAInputError):
            QualificationThresholds(minimum_proof_phase_reuse_rate=1.1)


if __name__ == "__main__":
    unittest.main()
