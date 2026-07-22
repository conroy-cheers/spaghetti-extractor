from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Any, Mapping, Protocol, Sequence

from ..stage_binary import StageAInputError
from .model import CaseManifest, ExpectedDisposition


class PhaseResultLike(Protocol):
    id: str
    status: str
    cache_hit: bool
    duration_seconds: float


class CaseRunResultLike(Protocol):
    case_id: str
    expected: ExpectedDisposition
    actual: ExpectedDisposition
    expectation_matched: bool | None
    phases: tuple[PhaseResultLike, ...]
    frontiers: tuple[Mapping[str, Any], ...]


class StaticCaseTimingLike(Protocol):
    case_id: str
    generation_seconds: float
    static_preflight_seconds: float


PROOF_PHASE_IDS = frozenset({
    "checked-violation-replay",
    "proof-build-and-audit",
    "proof-preparation",
})


@dataclass(frozen=True)
class CoverageEntry:
    id: str
    cases: int
    expected_pass: int
    expected_violated: int
    expected_incomplete: int
    actual_pass: int
    actual_violated: int
    actual_incomplete: int
    expectation_matches: int
    positive_acceptances: int
    negative_expectation_matches: int

    def to_payload(self) -> dict[str, object]:
        negative_cases = self.expected_violated + self.expected_incomplete
        return {
            "id": self.id,
            "cases": self.cases,
            "expected": {
                "pass": self.expected_pass,
                "violated": self.expected_violated,
                "incomplete": self.expected_incomplete,
            },
            "actual": {
                "pass": self.actual_pass,
                "violated": self.actual_violated,
                "incomplete": self.actual_incomplete,
            },
            "expectation_matches": self.expectation_matches,
            "positive_acceptance_rate": (
                None
                if self.expected_pass == 0
                else _rounded(self.positive_acceptances / self.expected_pass)
            ),
            "negative_expected_result_rate": (
                None
                if negative_cases == 0
                else _rounded(self.negative_expectation_matches / negative_cases)
            ),
        }


@dataclass(frozen=True)
class CoverageAxis:
    id: str
    entries: tuple[CoverageEntry, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "entries": [entry.to_payload() for entry in self.entries],
        }


@dataclass(frozen=True)
class PhaseTiming:
    id: str
    samples: int
    total_seconds: float
    minimum_seconds: float
    median_seconds: float
    p95_seconds: float
    maximum_seconds: float
    cache_hits: int
    cache_misses: int
    cache_hit_rate: float
    statuses: tuple[tuple[str, int], ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "samples": self.samples,
            "total_seconds": self.total_seconds,
            "minimum_seconds": self.minimum_seconds,
            "median_seconds": self.median_seconds,
            "p95_seconds": self.p95_seconds,
            "maximum_seconds": self.maximum_seconds,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": self.cache_hit_rate,
            "statuses": {status: count for status, count in self.statuses},
        }


@dataclass(frozen=True)
class FrontierCount:
    phase: str
    reason_code: str
    cases: int

    def to_payload(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "reason_code": self.reason_code,
            "cases": self.cases,
        }


@dataclass(frozen=True)
class GenericityInventory:
    """Review evidence which is informative but has no proof authority."""

    structural_shapes: tuple[str, ...] = ()
    semantic_constructors: tuple[str, ...] = ()
    lean_constructors: tuple[str, ...] = ()
    proof_rules: tuple[str, ...] = ()
    profile_branches: tuple[str, ...] = ()
    special_case_conditionals: tuple[str, ...] = ()
    source_lines: int | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "structural_shapes",
            "semantic_constructors",
            "lean_constructors",
            "proof_rules",
            "profile_branches",
            "special_case_conditionals",
        ):
            values = getattr(self, field_name)
            if any(not isinstance(item, str) or not item for item in values):
                raise StageAInputError(f"genericity {field_name} must contain strings")
            if tuple(sorted(values)) != values or len(values) != len(set(values)):
                raise StageAInputError(
                    f"genericity {field_name} must be unique and sorted"
                )
        if (
            self.source_lines is not None
            and (
                isinstance(self.source_lines, bool)
                or not isinstance(self.source_lines, int)
                or self.source_lines < 0
            )
        ):
            raise StageAInputError("genericity source_lines must be nonnegative")

    def to_payload(self) -> dict[str, object]:
        return {
            "structural_shapes": list(self.structural_shapes),
            "semantic_constructors": list(self.semantic_constructors),
            "lean_constructors": list(self.lean_constructors),
            "proof_rules": list(self.proof_rules),
            "profile_branches": list(self.profile_branches),
            "special_case_conditionals": list(self.special_case_conditionals),
            "source_lines": self.source_lines,
        }


@dataclass(frozen=True)
class GenericityEvidence:
    current: GenericityInventory
    baseline: GenericityInventory | None = None
    forbidden_dispatch_hits: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(not isinstance(item, str) or not item for item in self.forbidden_dispatch_hits):
            raise StageAInputError("forbidden dispatch hits must contain strings")
        if len(self.forbidden_dispatch_hits) != len(set(self.forbidden_dispatch_hits)):
            raise StageAInputError("forbidden dispatch hits must be unique")


@dataclass(frozen=True)
class GenericityWarning:
    code: str
    severity: str
    message: str
    evidence: tuple[str, ...] = ()

    def to_payload(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class QualificationThresholds:
    static_median_seconds: float = 1.0
    warm_final_theorem_median_seconds: float = 10.0
    minimum_proof_phase_reuse_rate: float = 0.9
    maximum_rule_to_shape_growth_ratio: float = 0.5

    def __post_init__(self) -> None:
        for field_name in (
            "static_median_seconds",
            "warm_final_theorem_median_seconds",
        ):
            value = getattr(self, field_name)
            if not _is_nonnegative_finite_number(value) or float(value) == 0.0:
                raise StageAInputError(
                    f"qualification {field_name} must be finite and positive"
                )
        for field_name in (
            "minimum_proof_phase_reuse_rate",
            "maximum_rule_to_shape_growth_ratio",
        ):
            value = getattr(self, field_name)
            if not _is_nonnegative_finite_number(value) or float(value) > 1.0:
                raise StageAInputError(
                    f"qualification {field_name} must be between zero and one"
                )

    def to_payload(self) -> dict[str, float]:
        return {
            "static_median_seconds": float(self.static_median_seconds),
            "warm_final_theorem_median_seconds": float(
                self.warm_final_theorem_median_seconds
            ),
            "minimum_proof_phase_reuse_rate": float(
                self.minimum_proof_phase_reuse_rate
            ),
            "maximum_rule_to_shape_growth_ratio": float(
                self.maximum_rule_to_shape_growth_ratio
            ),
        }


@dataclass(frozen=True)
class StaticCaseTiming:
    case_id: str
    generation_seconds: float
    static_preflight_seconds: float

    def __post_init__(self) -> None:
        _required_string(self.case_id, "static timing case_id")
        for field_name in ("generation_seconds", "static_preflight_seconds"):
            if not _is_nonnegative_finite_number(getattr(self, field_name)):
                raise StageAInputError(
                    f"static timing {field_name} must be finite and nonnegative"
                )

    @property
    def combined_seconds(self) -> float:
        return float(self.generation_seconds) + float(self.static_preflight_seconds)


@dataclass(frozen=True)
class QualificationGate:
    id: str
    status: str
    observed: int | float | None
    comparator: str
    threshold: int | float | None
    samples: int
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"satisfied", "violated", "incomplete"}:
            raise StageAInputError("qualification gate status is unsupported")

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "status": self.status,
            "observed": self.observed,
            "comparator": self.comparator,
            "threshold": self.threshold,
            "samples": self.samples,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RoundTripQualification:
    gates: tuple[QualificationGate, ...]
    thresholds: QualificationThresholds

    @property
    def status(self) -> str:
        statuses = {gate.status for gate in self.gates}
        if "violated" in statuses:
            return "violated"
        if "incomplete" in statuses:
            return "incomplete"
        return "satisfied"

    def to_payload(self) -> dict[str, object]:
        return {
            "format": "stage-a-roundtrip-qualification-v1",
            "status": self.status,
            "authority": {
                "diagnostic_only": True,
                "proof_authority": False,
            },
            "thresholds": self.thresholds.to_payload(),
            "gates": [gate.to_payload() for gate in self.gates],
        }


@dataclass(frozen=True)
class RoundTripMetrics:
    case_count: int
    expectation_matches: int
    expectation_mismatches: int
    unexpected_negative_passes: tuple[str, ...]
    expected_dispositions: tuple[tuple[str, int], ...]
    actual_dispositions: tuple[tuple[str, int], ...]
    phase_samples: int
    phase_cache_hits: int
    phases: tuple[PhaseTiming, ...]
    frontiers: tuple[FrontierCount, ...]
    coverage: tuple[CoverageAxis, ...]
    observed_structural_shapes: tuple[str, ...]
    genericity_current: GenericityInventory | None
    genericity_baseline: GenericityInventory | None
    genericity_deltas: tuple[tuple[str, int | float | None], ...]
    warnings: tuple[GenericityWarning, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "format": "stage-a-roundtrip-metrics-v1",
            "authority": {
                "diagnostic_only": True,
                "proof_authority": False,
                "acceptance_must_come_from": "whole_program_lean",
            },
            "cases": {
                "total": self.case_count,
                "expectation_matches": self.expectation_matches,
                "expectation_mismatches": self.expectation_mismatches,
                "unexpected_negative_passes": list(self.unexpected_negative_passes),
                "expected_dispositions": dict(self.expected_dispositions),
                "actual_dispositions": dict(self.actual_dispositions),
            },
            "cache": {
                "phase_samples": self.phase_samples,
                "hits": self.phase_cache_hits,
                "misses": self.phase_samples - self.phase_cache_hits,
                "hit_rate": (
                    0.0
                    if self.phase_samples == 0
                    else _rounded(self.phase_cache_hits / self.phase_samples)
                ),
            },
            "phases": [phase.to_payload() for phase in self.phases],
            "frontiers": [frontier.to_payload() for frontier in self.frontiers],
            "coverage": [axis.to_payload() for axis in self.coverage],
            "genericity": {
                "observed_structural_shapes": list(self.observed_structural_shapes),
                "current": (
                    None
                    if self.genericity_current is None
                    else self.genericity_current.to_payload()
                ),
                "baseline": (
                    None
                    if self.genericity_baseline is None
                    else self.genericity_baseline.to_payload()
                ),
                "deltas": {
                    key: value for key, value in self.genericity_deltas
                },
                "warnings": [warning.to_payload() for warning in self.warnings],
            },
        }


@dataclass(frozen=True)
class _NormalizedPhase:
    id: str
    status: str
    cache_hit: bool
    duration_seconds: float


@dataclass(frozen=True)
class _NormalizedResult:
    case_id: str
    expected: ExpectedDisposition
    actual: ExpectedDisposition
    expectation_matched: bool | None
    phases: tuple[_NormalizedPhase, ...]
    frontiers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _CaseAndResult:
    case: CaseManifest
    result: _NormalizedResult


@dataclass(frozen=True)
class _NormalizedStaticTiming:
    case_id: str
    generation_seconds: float
    static_preflight_seconds: float

    @property
    def combined_seconds(self) -> float:
        return self.generation_seconds + self.static_preflight_seconds


def aggregate_roundtrip_metrics(
    *,
    cases: Sequence[CaseManifest],
    results: Sequence[CaseRunResultLike | Mapping[str, Any]],
    genericity: GenericityEvidence | None = None,
) -> RoundTripMetrics:
    """Aggregate deterministic diagnostics without conferring proof authority."""

    case_by_id = {case.id: case for case in cases}
    if len(case_by_id) != len(cases):
        raise StageAInputError("round-trip metrics case ids must be unique")
    normalized_results = tuple(_normalize_result(result) for result in results)
    result_by_id = {result.case_id: result for result in normalized_results}
    if len(result_by_id) != len(normalized_results):
        raise StageAInputError("round-trip metrics result case ids must be unique")
    missing = sorted(set(case_by_id) - set(result_by_id))
    extra = sorted(set(result_by_id) - set(case_by_id))
    if missing or extra:
        raise StageAInputError(
            f"round-trip metrics case/result mismatch: missing={missing}, extra={extra}"
        )

    paired: list[_CaseAndResult] = []
    for case_id in sorted(case_by_id):
        case = case_by_id[case_id]
        result = result_by_id[case_id]
        if result.expected is not case.expectation.disposition:
            raise StageAInputError(
                f"round-trip result {case_id} expectation disagrees with its manifest"
            )
        paired.append(_CaseAndResult(case=case, result=result))

    coverage = tuple(
        _coverage_axis(axis_id, paired, selector)
        for axis_id, selector in (
            ("template_families", lambda case: (case.template,)),
            ("proof_families", lambda case: case.proof_families),
            ("capabilities", lambda case: case.capabilities),
            ("transformations", lambda case: case.transformations),
            (
                "mutations",
                lambda case: () if case.mutation is None else (case.mutation.id,),
            ),
        )
    )
    phase_timings = _phase_timings(paired)
    frontiers = _frontier_counts(paired)
    shapes = tuple(sorted({
        _observed_shape(item.case) for item in paired
    }))
    warnings = _genericity_warnings(paired, shapes, genericity)
    deltas = _genericity_deltas(genericity)
    unexpected_passes = tuple(sorted(
        item.case.id
        for item in paired
        if item.result.expected is not ExpectedDisposition.PASS
        and item.result.actual is ExpectedDisposition.PASS
    ))
    matches = sum(item.result.expectation_matched is True for item in paired)
    mismatches = sum(item.result.expectation_matched is False for item in paired)
    phase_samples = sum(len(item.result.phases) for item in paired)
    phase_cache_hits = sum(
        phase.cache_hit for item in paired for phase in item.result.phases
    )
    return RoundTripMetrics(
        case_count=len(paired),
        expectation_matches=matches,
        expectation_mismatches=mismatches,
        unexpected_negative_passes=unexpected_passes,
        expected_dispositions=tuple(
            (disposition.value, sum(
                item.result.expected is disposition for item in paired
            ))
            for disposition in ExpectedDisposition
        ),
        actual_dispositions=tuple(
            (disposition.value, sum(
                item.result.actual is disposition for item in paired
            ))
            for disposition in ExpectedDisposition
        ),
        phase_samples=phase_samples,
        phase_cache_hits=phase_cache_hits,
        phases=phase_timings,
        frontiers=frontiers,
        coverage=coverage,
        observed_structural_shapes=shapes,
        genericity_current=None if genericity is None else genericity.current,
        genericity_baseline=None if genericity is None else genericity.baseline,
        genericity_deltas=deltas,
        warnings=warnings,
    )


def evaluate_roundtrip_qualification(
    *,
    cases: Sequence[CaseManifest],
    static_timings: Sequence[StaticCaseTimingLike | Mapping[str, Any]],
    warm_results: Sequence[CaseRunResultLike | Mapping[str, Any]],
    genericity: GenericityEvidence,
    thresholds: QualificationThresholds | None = None,
) -> RoundTripQualification:
    """Evaluate the feasibility gates from explicit measured observations.

    The calculation is pure and deterministic. Durations are supplied by the
    caller and belong only in this diagnostic report; they never contribute to
    corpus manifests, case identities, proof inputs, or cache keys.
    """

    thresholds = QualificationThresholds() if thresholds is None else thresholds
    case_by_id = {case.id: case for case in cases}
    if len(case_by_id) != len(cases):
        raise StageAInputError("round-trip qualification case ids must be unique")
    normalized_static = tuple(_normalize_static_timing(item) for item in static_timings)
    static_by_id = {item.case_id: item for item in normalized_static}
    if len(static_by_id) != len(normalized_static):
        raise StageAInputError("round-trip static timing case ids must be unique")
    normalized_warm = tuple(_normalize_result(result) for result in warm_results)
    warm_by_id = {result.case_id: result for result in normalized_warm}
    if len(warm_by_id) != len(normalized_warm):
        raise StageAInputError("round-trip warm result case ids must be unique")
    _require_same_case_ids("static timings", case_by_id, static_by_id)
    _require_same_case_ids("warm results", case_by_id, warm_by_id)

    for case_id, result in warm_by_id.items():
        if result.expected is not case_by_id[case_id].expectation.disposition:
            raise StageAInputError(
                f"round-trip warm result {case_id} expectation disagrees with its manifest"
            )

    static_samples = sorted(
        item.combined_seconds for item in normalized_static
    )
    static_median = (
        None
        if not static_samples
        else _rounded(float(statistics.median(static_samples)))
    )
    static_gate = QualificationGate(
        id="per-case-generation-plus-static-preflight-median",
        status=(
            "incomplete"
            if static_median is None
            else (
                "satisfied"
                if static_median < thresholds.static_median_seconds
                else "violated"
            )
        ),
        observed=static_median,
        comparator="<",
        threshold=float(thresholds.static_median_seconds),
        samples=len(static_samples),
    )

    positive_ids = tuple(sorted(
        case.id
        for case in cases
        if case.expectation.disposition is ExpectedDisposition.PASS
    ))
    warm_theorem_samples: list[float] = []
    missing_warm_theorems: list[str] = []
    for case_id in positive_ids:
        result = warm_by_id[case_id]
        phase = next(
            (phase for phase in result.phases if phase.id == "proof-build-and-audit"),
            None,
        )
        if (
            phase is None
            or not phase.cache_hit
            or result.actual is not ExpectedDisposition.PASS
            or phase.status != ExpectedDisposition.PASS.value
        ):
            missing_warm_theorems.append(case_id)
            continue
        warm_theorem_samples.append(phase.duration_seconds)
    warm_median = (
        None
        if not warm_theorem_samples
        else _rounded(float(statistics.median(sorted(warm_theorem_samples))))
    )
    warm_gate = QualificationGate(
        id="warm-final-theorem-median",
        status=(
            "incomplete"
            if not positive_ids or missing_warm_theorems or warm_median is None
            else (
                "satisfied"
                if warm_median < thresholds.warm_final_theorem_median_seconds
                else "violated"
            )
        ),
        observed=warm_median,
        comparator="<",
        threshold=float(thresholds.warm_final_theorem_median_seconds),
        samples=len(warm_theorem_samples),
        evidence=tuple(
            f"missing_warm_final_theorem={case_id}"
            for case_id in missing_warm_theorems
        ),
    )

    proof_phases = [
        phase
        for result in normalized_warm
        for phase in result.phases
        if phase.id in PROOF_PHASE_IDS
    ]
    proof_hits = sum(phase.cache_hit for phase in proof_phases)
    reuse_rate = (
        None
        if not proof_phases
        else _rounded(proof_hits / len(proof_phases))
    )
    reuse_gate = QualificationGate(
        id="proof-phase-reuse-rate",
        status=(
            "incomplete"
            if reuse_rate is None
            else (
                "satisfied"
                if reuse_rate >= thresholds.minimum_proof_phase_reuse_rate
                else "violated"
            )
        ),
        observed=reuse_rate,
        comparator=">=",
        threshold=float(thresholds.minimum_proof_phase_reuse_rate),
        samples=len(proof_phases),
        evidence=(
            f"cache_hits={proof_hits}",
            f"cache_misses={len(proof_phases) - proof_hits}",
            "reuse_unit=case_phase",
        ),
    )

    dispatch_gate = QualificationGate(
        id="forbidden-acceptance-dispatch",
        status=(
            "satisfied" if not genericity.forbidden_dispatch_hits else "violated"
        ),
        observed=len(genericity.forbidden_dispatch_hits),
        comparator="==",
        threshold=0,
        samples=1,
        evidence=genericity.forbidden_dispatch_hits,
    )

    deltas = dict(_genericity_deltas(genericity))
    shape_growth = deltas.get("structural_shape_growth")
    rule_growth = deltas.get("generic_rule_growth")
    if not isinstance(shape_growth, int) or not isinstance(rule_growth, int):
        growth_status = "incomplete"
        growth_ratio = None
        growth_evidence = ("genericity_baseline_required",)
    elif shape_growth <= 0:
        growth_status = "incomplete"
        growth_ratio = None
        growth_evidence = (
            f"structural_shape_growth={shape_growth}",
            f"generic_rule_growth={rule_growth}",
            "positive_structural_shape_growth_required",
        )
    else:
        growth_ratio = _rounded(rule_growth / shape_growth)
        growth_status = (
            "satisfied"
            if growth_ratio <= thresholds.maximum_rule_to_shape_growth_ratio
            else "violated"
        )
        growth_evidence = (
            f"structural_shape_growth={shape_growth}",
            f"generic_rule_growth={rule_growth}",
        )
    growth_gate = QualificationGate(
        id="generic-rule-to-structural-shape-growth-ratio",
        status=growth_status,
        observed=growth_ratio,
        comparator="<=",
        threshold=float(thresholds.maximum_rule_to_shape_growth_ratio),
        samples=0 if not isinstance(shape_growth, int) else shape_growth,
        evidence=growth_evidence,
    )

    return RoundTripQualification(
        gates=(static_gate, warm_gate, reuse_gate, dispatch_gate, growth_gate),
        thresholds=thresholds,
    )


def _normalize_result(
    result: CaseRunResultLike | Mapping[str, Any],
) -> _NormalizedResult:
    if isinstance(result, Mapping):
        case_id = _required_string(result.get("case_id"), "case result case_id")
        expected = _disposition(
            result.get("expected_disposition"), "case result expected_disposition"
        )
        actual = _disposition(
            result.get("actual_disposition"), "case result actual_disposition"
        )
        matched = result.get("expectation_matched")
        raw_phases = result.get("phases")
        raw_frontiers = result.get("frontiers", ())
    else:
        case_id = _required_string(result.case_id, "case result case_id")
        expected = _disposition(result.expected, "case result expected")
        actual = _disposition(result.actual, "case result actual")
        matched = result.expectation_matched
        raw_phases = result.phases
        raw_frontiers = getattr(result, "frontiers", ())
    if matched is not None and type(matched) is not bool:
        raise StageAInputError("case result expectation_matched must be bool or null")
    if not isinstance(raw_phases, (list, tuple)):
        raise StageAInputError("case result phases must be a sequence")
    phases = tuple(_normalize_phase(phase) for phase in raw_phases)
    phase_ids = tuple(phase.id for phase in phases)
    if len(phase_ids) != len(set(phase_ids)):
        raise StageAInputError(f"case result {case_id} phase ids must be unique")
    if not isinstance(raw_frontiers, (list, tuple)):
        raise StageAInputError("case result frontiers must be a sequence")
    frontiers = tuple(_normalize_frontier(frontier) for frontier in raw_frontiers)
    return _NormalizedResult(case_id, expected, actual, matched, phases, frontiers)


def _normalize_static_timing(
    timing: StaticCaseTimingLike | Mapping[str, Any],
) -> _NormalizedStaticTiming:
    if isinstance(timing, Mapping):
        case_id = _required_string(timing.get("case_id"), "static timing case_id")
        generation = timing.get("generation_seconds")
        preflight = timing.get("static_preflight_seconds")
    else:
        case_id = _required_string(timing.case_id, "static timing case_id")
        generation = timing.generation_seconds
        preflight = timing.static_preflight_seconds
    if not _is_nonnegative_finite_number(generation):
        raise StageAInputError(
            "static timing generation_seconds must be finite and nonnegative"
        )
    if not _is_nonnegative_finite_number(preflight):
        raise StageAInputError(
            "static timing static_preflight_seconds must be finite and nonnegative"
        )
    return _NormalizedStaticTiming(case_id, float(generation), float(preflight))


def _require_same_case_ids(
    label: str,
    expected: Mapping[str, object],
    observed: Mapping[str, object],
) -> None:
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    if missing or extra:
        raise StageAInputError(
            f"round-trip qualification {label} mismatch: "
            f"missing={missing}, extra={extra}"
        )


def _normalize_phase(phase: PhaseResultLike | Mapping[str, Any]) -> _NormalizedPhase:
    if isinstance(phase, Mapping):
        phase_id = _required_string(phase.get("id"), "phase id")
        status = _required_string(phase.get("status"), "phase status")
        cache_hit = phase.get("cache_hit")
        duration = phase.get("duration_seconds")
    else:
        phase_id = _required_string(phase.id, "phase id")
        status = _required_string(phase.status, "phase status")
        cache_hit = phase.cache_hit
        duration = phase.duration_seconds
    if type(cache_hit) is not bool:
        raise StageAInputError("phase cache_hit must be bool")
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(float(duration))
        or float(duration) < 0.0
    ):
        raise StageAInputError("phase duration_seconds must be finite and nonnegative")
    return _NormalizedPhase(phase_id, status, cache_hit, float(duration))


def _is_nonnegative_finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
        and float(value) >= 0.0
    )


def _normalize_frontier(frontier: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(frontier, Mapping):
        raise StageAInputError("case result frontier must be an object")
    phase = _required_string(frontier.get("phase", "unknown"), "frontier phase")
    reason = _required_string(
        frontier.get("reason_code", "unspecified"), "frontier reason_code"
    )
    return phase, reason


def _required_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    return value


def _disposition(value: Any, context: str) -> ExpectedDisposition:
    if isinstance(value, ExpectedDisposition):
        return value
    try:
        return ExpectedDisposition(value)
    except (TypeError, ValueError) as exc:
        raise StageAInputError(f"{context} is unsupported") from exc


def _coverage_axis(
    axis_id: str,
    paired: Sequence[_CaseAndResult],
    selector: Any,
) -> CoverageAxis:
    item_ids = sorted({
        item_id
        for item in paired
        for item_id in selector(item.case)
    })
    entries: list[CoverageEntry] = []
    for item_id in item_ids:
        selected = [item for item in paired if item_id in selector(item.case)]
        entries.append(CoverageEntry(
            id=item_id,
            cases=len(selected),
            expected_pass=_count_disposition(selected, "expected", ExpectedDisposition.PASS),
            expected_violated=_count_disposition(
                selected, "expected", ExpectedDisposition.VIOLATED
            ),
            expected_incomplete=_count_disposition(
                selected, "expected", ExpectedDisposition.INCOMPLETE
            ),
            actual_pass=_count_disposition(selected, "actual", ExpectedDisposition.PASS),
            actual_violated=_count_disposition(
                selected, "actual", ExpectedDisposition.VIOLATED
            ),
            actual_incomplete=_count_disposition(
                selected, "actual", ExpectedDisposition.INCOMPLETE
            ),
            expectation_matches=sum(
                item.result.expectation_matched is True for item in selected
            ),
            positive_acceptances=sum(
                item.result.expected is ExpectedDisposition.PASS
                and item.result.actual is ExpectedDisposition.PASS
                for item in selected
            ),
            negative_expectation_matches=sum(
                item.result.expected is not ExpectedDisposition.PASS
                and item.result.expectation_matched is True
                for item in selected
            ),
        ))
    return CoverageAxis(id=axis_id, entries=tuple(entries))


def _count_disposition(
    selected: Sequence[_CaseAndResult],
    field: str,
    disposition: ExpectedDisposition,
) -> int:
    return sum(getattr(item.result, field) is disposition for item in selected)


def _phase_timings(paired: Sequence[_CaseAndResult]) -> tuple[PhaseTiming, ...]:
    phase_ids = sorted({
        phase.id for item in paired for phase in item.result.phases
    })
    timings: list[PhaseTiming] = []
    for phase_id in phase_ids:
        phases = [
            phase
            for item in paired
            for phase in item.result.phases
            if phase.id == phase_id
        ]
        durations = sorted(phase.duration_seconds for phase in phases)
        hits = sum(phase.cache_hit for phase in phases)
        statuses = tuple(sorted({
            status: sum(phase.status == status for phase in phases)
            for status in {phase.status for phase in phases}
        }.items()))
        timings.append(PhaseTiming(
            id=phase_id,
            samples=len(phases),
            total_seconds=_rounded(sum(durations)),
            minimum_seconds=_rounded(durations[0]),
            median_seconds=_rounded(float(statistics.median(durations))),
            p95_seconds=_rounded(durations[math.ceil(0.95 * len(durations)) - 1]),
            maximum_seconds=_rounded(durations[-1]),
            cache_hits=hits,
            cache_misses=len(phases) - hits,
            cache_hit_rate=_rounded(hits / len(phases)),
            statuses=statuses,
        ))
    return tuple(timings)


def _frontier_counts(
    paired: Sequence[_CaseAndResult],
) -> tuple[FrontierCount, ...]:
    identities = sorted({
        frontier for item in paired for frontier in item.result.frontiers
    })
    return tuple(
        FrontierCount(
            phase=phase,
            reason_code=reason,
            cases=sum(
                (phase, reason) in set(item.result.frontiers) for item in paired
            ),
        )
        for phase, reason in identities
    )


def _rounded(value: float) -> float:
    return round(value, 6)


def _observed_shape(case: CaseManifest) -> str:
    transformations = "+".join(sorted(case.transformations)) or "none"
    mutation = "none" if case.mutation is None else case.mutation.id
    return f"{case.template}|{transformations}|{mutation}"


def _genericity_warnings(
    paired: Sequence[_CaseAndResult],
    shapes: tuple[str, ...],
    genericity: GenericityEvidence | None,
) -> tuple[GenericityWarning, ...]:
    warnings: list[GenericityWarning] = []
    unexpected_passes = tuple(sorted(
        item.case.id
        for item in paired
        if item.result.expected is not ExpectedDisposition.PASS
        and item.result.actual is ExpectedDisposition.PASS
    ))
    if unexpected_passes:
        warnings.append(GenericityWarning(
            code="negative_case_passed",
            severity="critical",
            message="negative cases reached pass; this is a soundness blocker",
            evidence=unexpected_passes,
        ))

    transformations = sorted({
        transformation
        for item in paired
        for transformation in item.case.transformations
    })
    for transformation in transformations:
        templates = tuple(sorted({
            item.case.template
            for item in paired
            if transformation in item.case.transformations
        }))
        if len(templates) == 1:
            warnings.append(GenericityWarning(
                code="transformation_single_family",
                severity="warning",
                message=(
                    f"transformation {transformation} is exercised by only one template family"
                ),
                evidence=templates,
            ))

    proof_families = sorted({
        family for item in paired for family in item.case.proof_families
    })
    for family in proof_families:
        templates = tuple(sorted({
            item.case.template
            for item in paired
            if family in item.case.proof_families
        }))
        cases = sum(family in item.case.proof_families for item in paired)
        if cases > 1 and len(templates) == 1:
            warnings.append(GenericityWarning(
                code="proof_family_single_template",
                severity="warning",
                message=f"proof family {family} has not demonstrated cross-template reuse",
                evidence=templates,
            ))

    if genericity is not None:
        for hit in sorted(genericity.forbidden_dispatch_hits):
            warnings.append(GenericityWarning(
                code="forbidden_acceptance_dispatch",
                severity="critical",
                message="acceptance code contains a forbidden target-shaped dispatch",
                evidence=(hit,),
            ))
        for conditional in genericity.current.special_case_conditionals:
            warnings.append(GenericityWarning(
                code="special_case_conditional",
                severity="critical",
                message="genericity inventory records a special-case conditional",
                evidence=(conditional,),
            ))
        deltas = dict(_genericity_deltas(genericity))
        shape_growth = int(deltas.get("structural_shape_growth") or 0)
        handler_growth = int(deltas.get("handler_growth") or 0)
        if shape_growth > 0 and handler_growth >= shape_growth:
            warnings.append(GenericityWarning(
                code="handler_growth_tracks_shape_growth",
                severity="warning",
                message=(
                    "profile and special-case handler growth is not smaller than "
                    "structural-shape growth"
                ),
                evidence=(
                    f"shape_growth={shape_growth}",
                    f"handler_growth={handler_growth}",
                ),
            ))
        declared_shapes = set(genericity.current.structural_shapes)
        missing_shapes = tuple(sorted(set(shapes) - declared_shapes))
        if declared_shapes and missing_shapes:
            warnings.append(GenericityWarning(
                code="shape_inventory_incomplete",
                severity="warning",
                message="genericity inventory omits observed corpus shapes",
                evidence=missing_shapes,
            ))
    return tuple(sorted(warnings, key=lambda item: (item.severity, item.code, item.evidence)))


def _genericity_deltas(
    genericity: GenericityEvidence | None,
) -> tuple[tuple[str, int | float | None], ...]:
    if genericity is None or genericity.baseline is None:
        return ()
    current = genericity.current
    baseline = genericity.baseline

    def growth(field: str) -> int:
        return len(set(getattr(current, field)) - set(getattr(baseline, field)))

    shape_growth = growth("structural_shapes")
    handler_growth = (
        growth("profile_branches") + growth("special_case_conditionals")
    )
    rule_growth = (
        growth("semantic_constructors")
        + growth("lean_constructors")
        + growth("proof_rules")
    )
    source_line_growth = (
        None
        if current.source_lines is None or baseline.source_lines is None
        else current.source_lines - baseline.source_lines
    )
    lines_per_shape = (
        None
        if source_line_growth is None or shape_growth == 0
        else _rounded(source_line_growth / shape_growth)
    )
    return (
        ("structural_shape_growth", shape_growth),
        ("generic_rule_growth", rule_growth),
        ("handler_growth", handler_growth),
        ("source_line_growth", source_line_growth),
        ("source_lines_per_new_shape", lines_per_shape),
    )
