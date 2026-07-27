from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..relational.schema import RELATIONAL_FINAL_ACCEPTANCE_THEOREM
from ..stage_binary import StageAInputError
from ..util import json_dumps, sha256_file, write_json
from .metrics import (
    CaseRunResultLike,
    GenericityEvidence,
    QualificationThresholds,
    StaticCaseTimingLike,
    evaluate_roundtrip_qualification,
)
from .model import CaseManifest, ExpectedDisposition, load_corpus_manifest


ROUNDTRIP_FEASIBILITY_REPORT_FORMAT = "stage-a-roundtrip-feasibility-report-v1"
_NIX_QUALIFICATION_FORMAT = "stage-a-roundtrip-nix-qualification-v1"
_CASE_RESULT_FORMAT = "stage-a-roundtrip-case-result-v1"
_CHECKED_VIOLATION_FORMAT = "stage-a-checked-violation-result-v1"
_DISPOSITIONS = tuple(disposition.value for disposition in ExpectedDisposition)


def write_roundtrip_qualification_report(
    *,
    corpus_manifest_path: Path,
    nix_aggregate_result_path: Path,
    static_timings: Sequence[StaticCaseTimingLike | Mapping[str, Any]],
    warm_results: Sequence[CaseRunResultLike | Mapping[str, Any]],
    genericity: GenericityEvidence,
    output_path: Path,
    thresholds: QualificationThresholds | None = None,
) -> dict[str, Any]:
    """Validate qualification evidence and emit a deterministic report.

    This report is diagnostic only. It rechecks the proof-authoritative fields
    in the completed Nix aggregate before evaluating performance and
    genericity gates from the explicitly supplied observations.
    """

    corpus_manifest_path = Path(corpus_manifest_path)
    nix_aggregate_result_path = Path(nix_aggregate_result_path)
    output_path = Path(output_path)
    manifest = load_corpus_manifest(corpus_manifest_path)
    loaded_cases = manifest.load_cases(corpus_manifest_path.parent)
    cases = tuple(case for case, _case_root in loaded_cases)
    aggregate = _load_json_object(
        nix_aggregate_result_path, "round-trip Nix aggregate"
    )
    canonical_aggregate, actual_counts = _validate_aggregate(
        aggregate=aggregate,
        cases=cases,
        expected_counts=manifest.expected_counts.to_payload(),
        generator_version=manifest.generator_version,
    )

    qualification = evaluate_roundtrip_qualification(
        cases=cases,
        static_timings=static_timings,
        warm_results=warm_results,
        genericity=genericity,
        thresholds=thresholds,
    )
    qualification_payload = qualification.to_payload()
    expected_counts = manifest.expected_counts.to_payload()
    payload = {
        "format": ROUNDTRIP_FEASIBILITY_REPORT_FORMAT,
        "status": qualification.status,
        "authority": {
            "diagnostic_only": True,
            "proof_authority": False,
            "acceptance_must_come_from": "whole_program_lean",
        },
        "inputs": {
            "corpus_manifest_sha256": sha256_file(corpus_manifest_path),
            "nix_aggregate_canonical_sha256": _payload_sha256(
                canonical_aggregate
            ),
            "static_timings_canonical_sha256": _payload_sha256(
                _canonical_static_timings(static_timings)
            ),
            "warm_results_canonical_sha256": _payload_sha256(
                _canonical_warm_results(warm_results)
            ),
            "genericity_canonical_sha256": _payload_sha256(
                _canonical_genericity(genericity)
            ),
        },
        "counts": {
            "cases": len(cases),
            "expected": expected_counts,
            "actual": actual_counts,
            "expectation_matches": len(cases),
            "expectation_mismatches": 0,
            "unexpected_negative_passes": 0,
        },
        "thresholds": qualification_payload["thresholds"],
        "gates": qualification_payload["gates"],
    }
    try:
        write_json(output_path, payload)
    except OSError as exc:
        raise StageAInputError(
            f"cannot write round-trip feasibility report {output_path}: {exc}"
        ) from exc
    return payload


def _validate_aggregate(
    *,
    aggregate: Mapping[str, Any],
    cases: Sequence[CaseManifest],
    expected_counts: Mapping[str, int],
    generator_version: str,
) -> tuple[dict[str, Any], dict[str, int]]:
    _require_exact_fields(
        aggregate,
        {
            "format",
            "status",
            "corpus",
            "counts",
            "expectation_mismatch_case_ids",
            "unexpected_pass_case_ids",
            "packs",
            "cases",
            "trust",
            "reran_proofs",
            "executes_original_binary",
        },
        "round-trip Nix aggregate",
    )
    if aggregate["format"] != _NIX_QUALIFICATION_FORMAT:
        raise StageAInputError("unsupported round-trip Nix aggregate format")
    if aggregate["status"] != "pass":
        raise StageAInputError("round-trip Nix aggregate is not complete")
    if aggregate["reran_proofs"] is not False:
        raise StageAInputError("round-trip Nix aggregate unexpectedly reran proofs")
    if aggregate["executes_original_binary"] is not False:
        raise StageAInputError("round-trip Nix aggregate executed an original binary")

    trust = _object(aggregate["trust"], "round-trip Nix aggregate trust")
    _require_exact_fields(
        trust,
        {
            "positive_pass_requires",
            "supported_acceptance_theorems",
            "negative_pass_is_fatal",
            "aggregator_has_proof_authority",
        },
        "round-trip Nix aggregate trust",
    )
    theorem_inventory = _string_list(
        trust["supported_acceptance_theorems"],
        "round-trip Nix aggregate supported theorem inventory",
    )
    final_theorem_inventory = [RELATIONAL_FINAL_ACCEPTANCE_THEOREM]
    if (
        trust["positive_pass_requires"] != "whole_program_lean"
        or trust["negative_pass_is_fatal"] is not True
        or trust["aggregator_has_proof_authority"] is not False
        or theorem_inventory != final_theorem_inventory
    ):
        raise StageAInputError("round-trip Nix aggregate trust policy is unsupported")

    corpus = _object(aggregate["corpus"], "round-trip Nix aggregate corpus")
    _require_exact_fields(
        corpus,
        {"manifest", "smoke_store_path", "generator_version", "expected_counts"},
        "round-trip Nix aggregate corpus",
    )
    _required_string(corpus["manifest"], "round-trip Nix aggregate corpus manifest")
    _required_string(
        corpus["smoke_store_path"], "round-trip Nix aggregate smoke store path"
    )
    if corpus["generator_version"] != generator_version:
        raise StageAInputError("round-trip Nix aggregate generator version changed")
    _validate_count_payload(
        corpus["expected_counts"],
        expected_counts,
        "round-trip Nix aggregate expected counts",
    )

    case_by_id = {case.id: case for case in cases}
    raw_cases = aggregate["cases"]
    if not isinstance(raw_cases, list):
        raise StageAInputError("round-trip Nix aggregate cases must be a list")
    observed: dict[str, dict[str, Any]] = {}
    for index, raw_case in enumerate(raw_cases):
        wrapper = _object(raw_case, f"round-trip Nix aggregate cases[{index}]")
        case_id = _required_string(
            wrapper.get("case_id"),
            f"round-trip Nix aggregate cases[{index}].case_id",
        )
        if case_id in observed:
            raise StageAInputError(
                f"round-trip Nix aggregate repeats case {case_id}"
            )
        case = case_by_id.get(case_id)
        if case is None:
            raise StageAInputError(
                f"round-trip Nix aggregate contains unknown case {case_id}"
            )
        observed[case_id] = _validate_aggregate_case(wrapper, case)

    missing = sorted(set(case_by_id) - set(observed))
    if missing:
        raise StageAInputError(
            f"round-trip Nix aggregate is missing cases {missing}"
        )
    actual_counts = {
        disposition: sum(
            result["actual"] == disposition for result in observed.values()
        )
        for disposition in _DISPOSITIONS
    }
    if actual_counts != dict(expected_counts):
        raise StageAInputError(
            "round-trip Nix aggregate actual counts do not match expectations"
        )

    declared_counts = _object(
        aggregate["counts"], "round-trip Nix aggregate counts"
    )
    _require_exact_fields(
        declared_counts,
        {
            "cases",
            "pass",
            "violated",
            "incomplete",
            "declared_expectations_match_manifest",
            "expectation_mismatches",
            "unexpected_passes",
        },
        "round-trip Nix aggregate counts",
    )
    if (
        _nonnegative_integer(declared_counts["cases"], "aggregate case count")
        != len(cases)
        or declared_counts["declared_expectations_match_manifest"] is not True
        or _nonnegative_integer(
            declared_counts["expectation_mismatches"],
            "aggregate expectation mismatch count",
        )
        != 0
        or _nonnegative_integer(
            declared_counts["unexpected_passes"],
            "aggregate unexpected pass count",
        )
        != 0
        or {
            disposition: _nonnegative_integer(
                declared_counts[disposition], f"aggregate {disposition} count"
            )
            for disposition in _DISPOSITIONS
        }
        != actual_counts
    ):
        raise StageAInputError("round-trip Nix aggregate counts are inconsistent")
    if aggregate["expectation_mismatch_case_ids"] != []:
        raise StageAInputError("round-trip Nix aggregate has expectation mismatches")
    if aggregate["unexpected_pass_case_ids"] != []:
        raise StageAInputError("round-trip Nix aggregate has a negative pass")

    packs = _validate_packs(aggregate["packs"])
    canonical = dict(aggregate)
    canonical["cases"] = [observed[case_id] for case_id in sorted(observed)]
    canonical["packs"] = packs
    canonical["trust"] = dict(trust)
    canonical["trust"]["supported_acceptance_theorems"] = sorted(
        theorem_inventory
    )
    return canonical, actual_counts


def _validate_aggregate_case(
    wrapper: Mapping[str, Any], case: CaseManifest
) -> dict[str, Any]:
    _require_exact_fields(
        wrapper,
        {
            "case_id",
            "expected",
            "actual",
            "expectation_matched",
            "preparation_store_path",
            "preparation_derivation_path",
            "proof_dag_store_path",
            "proof_dag_derivation_path",
            "audit_store_path",
            "audit_derivation_path",
            "measurement",
            "result",
        },
        f"round-trip Nix aggregate case {case.id}",
    )
    expected = case.expectation.disposition.value
    if wrapper["expected"] != expected or wrapper["actual"] != expected:
        if wrapper["actual"] == ExpectedDisposition.PASS.value and expected != "pass":
            raise StageAInputError(f"negative round-trip case {case.id} passed")
        raise StageAInputError(
            f"round-trip case {case.id} did not match its expected disposition"
        )
    if wrapper["expectation_matched"] is not True:
        raise StageAInputError(
            f"round-trip case {case.id} is not marked expectation-matched"
        )
    for field in (
        "preparation_store_path",
        "preparation_derivation_path",
        "proof_dag_store_path",
        "proof_dag_derivation_path",
        "audit_store_path",
        "audit_derivation_path",
    ):
        _required_string(wrapper[field], f"round-trip case {case.id} {field}")
    measurement = _object(
        wrapper["measurement"], f"round-trip case {case.id} measurement"
    )
    _require_exact_fields(
        measurement,
        {
            "estimatedMemoryMB",
            "estimatedSeconds",
            "measured",
            "measurementSource",
            "resourceClass",
        },
        f"round-trip case {case.id} measurement",
    )
    _required_string(
        measurement["measurementSource"],
        f"round-trip case {case.id} measurement source",
    )
    _required_string(
        measurement["resourceClass"],
        f"round-trip case {case.id} resource class",
    )
    if (
        measurement["measured"] is not True
        or _nonnegative_integer(
            measurement["estimatedMemoryMB"],
            f"round-trip case {case.id} estimated memory",
        )
        <= 0
        or _nonnegative_integer(
            measurement["estimatedSeconds"],
            f"round-trip case {case.id} estimated seconds",
        )
        <= 0
    ):
        raise StageAInputError(
            f"round-trip case {case.id} lacks measured scheduling evidence"
        )
    result = _object(wrapper["result"], f"round-trip case {case.id} result")
    _validate_inner_result(result, case)
    canonical = dict(wrapper)
    canonical["measurement"] = dict(measurement)
    canonical["result"] = _canonical_inner_result(result)
    return canonical


def _validate_inner_result(result: Mapping[str, Any], case: CaseManifest) -> None:
    required = {
        "format",
        "case_id",
        "mode",
        "expected_disposition",
        "actual_disposition",
        "expectation_matched",
        "phases",
        "acceptance",
        "frontiers",
        "violation",
        "error",
    }
    allowed = required | {"discovery", "nix"}
    missing = sorted(required - set(result))
    extra = sorted(set(result) - allowed)
    if missing or extra:
        raise StageAInputError(
            f"round-trip case {case.id} result schema mismatch: "
            f"missing={missing}, extra={extra}"
        )
    expected = case.expectation.disposition.value
    if (
        result["format"] != _CASE_RESULT_FORMAT
        or result["case_id"] != case.id
        or result["mode"] != "proof-core"
        or result["expected_disposition"] != expected
        or result["actual_disposition"] != expected
        or result["expectation_matched"] is not True
        or result["error"] is not None
    ):
        raise StageAInputError(
            f"round-trip case {case.id} inner result is inconsistent"
        )
    phases = _phase_inventory(result["phases"], case.id)
    frontiers = _frontiers(result["frontiers"], case.id)
    if case.expectation.disposition is ExpectedDisposition.PASS:
        acceptance = _object(
            result["acceptance"], f"round-trip case {case.id} acceptance"
        )
        if set(acceptance) != {"theorem", "authority"}:
            raise StageAInputError(
                f"round-trip case {case.id} acceptance schema is unsupported"
            )
        if (
            acceptance["authority"] != "whole_program_lean"
            or acceptance["theorem"] != RELATIONAL_FINAL_ACCEPTANCE_THEOREM
            or phases.get("proof-build-and-audit") != "pass"
        ):
            raise StageAInputError(
                f"round-trip case {case.id} pass lacks whole-program Lean authority"
            )
        if result["violation"] is not None:
            raise StageAInputError(
                f"round-trip case {case.id} pass advertises violation evidence"
            )
        return

    _require_no_acceptance(result["acceptance"], case.id)
    if case.expectation.disposition is ExpectedDisposition.VIOLATED:
        violation = _object(
            result["violation"], f"round-trip case {case.id} violation"
        )
        checks = _object(
            violation.get("checks"), f"round-trip case {case.id} violation checks"
        )
        trust = _object(
            violation.get("trust"), f"round-trip case {case.id} violation trust"
        )
        if (
            violation.get("format") != _CHECKED_VIOLATION_FORMAT
            or violation.get("status") != "violated"
            or violation.get("family") != case.expectation.witness_family
            or not checks
            or any(value is not True for value in checks.values())
            or trust.get("role") != "checked_inequivalence_witness"
            or trust.get("can_authorize_pass") is not False
            or trust.get("raw_solver_status_sufficient") is not False
            or phases.get("checked-violation-replay") != "violated"
        ):
            raise StageAInputError(
                f"round-trip case {case.id} violation lacks checked evidence"
            )
        return

    if result["violation"] is not None:
        raise StageAInputError(
            f"round-trip case {case.id} incomplete result advertises violation evidence"
        )
    expected_reason = case.expectation.reason_family
    observed_reasons = {
        item.get("reason_code")
        for item in result["phases"]
        if isinstance(item, Mapping)
    } | {item.get("reason_code") for item in frontiers}
    if expected_reason not in observed_reasons:
        raise StageAInputError(
            f"round-trip case {case.id} omits expected incomplete reason family"
        )


def _require_no_acceptance(value: Any, case_id: str) -> None:
    if value is None:
        return
    acceptance = _object(value, f"round-trip case {case_id} acceptance")
    if set(acceptance) != {"theorem", "authority"} or any(
        item is not None for item in acceptance.values()
    ):
        raise StageAInputError(
            f"round-trip case {case_id} negative result has acceptance authority"
        )


def _phase_inventory(value: Any, case_id: str) -> dict[str, str]:
    if not isinstance(value, list):
        raise StageAInputError(f"round-trip case {case_id} phases must be a list")
    phases: dict[str, str] = {}
    for index, raw in enumerate(value):
        phase = _object(raw, f"round-trip case {case_id} phases[{index}]")
        phase_id = _required_string(
            phase.get("id"), f"round-trip case {case_id} phase id"
        )
        status = _required_string(
            phase.get("status"), f"round-trip case {case_id} phase status"
        )
        if phase_id in phases:
            raise StageAInputError(
                f"round-trip case {case_id} repeats phase {phase_id}"
            )
        phases[phase_id] = status
    return phases


def _frontiers(value: Any, case_id: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise StageAInputError(f"round-trip case {case_id} frontiers must be a list")
    return [
        _object(item, f"round-trip case {case_id} frontiers[{index}]")
        for index, item in enumerate(value)
    ]


def _validate_packs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise StageAInputError("round-trip Nix aggregate packs must be nonempty")
    packs: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(value):
        pack = _object(raw, f"round-trip Nix aggregate packs[{index}]")
        _require_exact_fields(
            pack,
            {"id", "status", "store_path", "derivation_path", "result"},
            f"round-trip Nix aggregate packs[{index}]",
        )
        pack_id = _required_string(
            pack["id"], f"round-trip Nix aggregate packs[{index}].id"
        )
        if pack_id in packs:
            raise StageAInputError(f"round-trip Nix aggregate repeats pack {pack_id}")
        if pack["status"] != "pass":
            raise StageAInputError(f"round-trip Nix aggregate pack {pack_id} failed")
        for field in ("store_path", "derivation_path", "result"):
            _required_string(pack[field], f"round-trip Nix aggregate pack {field}")
        packs[pack_id] = dict(pack)
    return [packs[pack_id] for pack_id in sorted(packs)]


def _canonical_inner_result(result: Mapping[str, Any]) -> dict[str, Any]:
    canonical = dict(result)
    canonical["phases"] = sorted(
        (dict(item) for item in result["phases"]), key=lambda item: item["id"]
    )
    canonical["frontiers"] = sorted(
        (dict(item) for item in result["frontiers"]), key=json_dumps
    )
    return canonical


def _canonical_static_timings(
    timings: Sequence[StaticCaseTimingLike | Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for timing in timings:
        if isinstance(timing, Mapping):
            row = {
                "case_id": timing.get("case_id"),
                "generation_seconds": timing.get("generation_seconds"),
                "static_preflight_seconds": timing.get("static_preflight_seconds"),
            }
        else:
            row = {
                "case_id": timing.case_id,
                "generation_seconds": timing.generation_seconds,
                "static_preflight_seconds": timing.static_preflight_seconds,
            }
        rows.append(row)
    return sorted(rows, key=lambda row: str(row["case_id"]))


def _canonical_warm_results(
    results: Sequence[CaseRunResultLike | Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for result in results:
        if isinstance(result, Mapping):
            case_id = result.get("case_id")
            expected = result.get("expected_disposition")
            actual = result.get("actual_disposition")
            matched = result.get("expectation_matched")
            phases = result.get("phases")
            frontiers = result.get("frontiers", ())
        else:
            case_id = result.case_id
            expected = result.expected
            actual = result.actual
            matched = result.expectation_matched
            phases = result.phases
            frontiers = getattr(result, "frontiers", ())
        rows.append({
            "case_id": case_id,
            "expected_disposition": getattr(expected, "value", expected),
            "actual_disposition": getattr(actual, "value", actual),
            "expectation_matched": matched,
            "phases": sorted(
                (_canonical_phase(phase) for phase in phases),
                key=lambda phase: str(phase["id"]),
            ),
            "frontiers": sorted(
                (dict(frontier) for frontier in frontiers), key=json_dumps
            ),
        })
    return sorted(rows, key=lambda row: str(row["case_id"]))


def _canonical_phase(phase: Any) -> dict[str, Any]:
    if isinstance(phase, Mapping):
        return {
            "id": phase.get("id"),
            "status": phase.get("status"),
            "cache_hit": phase.get("cache_hit"),
            "duration_seconds": phase.get("duration_seconds"),
        }
    return {
        "id": phase.id,
        "status": phase.status,
        "cache_hit": phase.cache_hit,
        "duration_seconds": phase.duration_seconds,
    }


def _canonical_genericity(genericity: GenericityEvidence) -> dict[str, Any]:
    return {
        "current": genericity.current.to_payload(),
        "baseline": (
            None if genericity.baseline is None else genericity.baseline.to_payload()
        ),
        "forbidden_dispatch_hits": sorted(genericity.forbidden_dispatch_hits),
    }


def _validate_count_payload(
    value: Any, expected: Mapping[str, int], context: str
) -> None:
    payload = _object(value, context)
    _require_exact_fields(payload, set(_DISPOSITIONS), context)
    observed = {
        disposition: _nonnegative_integer(
            payload[disposition], f"{context}.{disposition}"
        )
        for disposition in _DISPOSITIONS
    }
    if observed != dict(expected):
        raise StageAInputError(f"{context} does not match the corpus manifest")


def _load_json_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc
    return _object(payload, context)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _require_exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str
) -> None:
    missing = sorted(expected - set(payload))
    extra = sorted(set(payload) - expected)
    if missing or extra:
        raise StageAInputError(
            f"{context} schema mismatch: missing={missing}, extra={extra}"
        )


def _required_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    return value


def _string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    return [
        _required_string(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    ]


def _nonnegative_integer(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageAInputError(f"{context} must be a nonnegative integer")
    return value


def _payload_sha256(payload: Any) -> str:
    return hashlib.sha256(json_dumps(payload).encode("utf-8")).hexdigest()
