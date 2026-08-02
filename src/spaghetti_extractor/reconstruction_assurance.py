"""Strict evidence aggregation for high-assurance reconstruction.

These artifacts are an assurance summary, not a Stage A equivalence proof.  They
deliberately use a separate status vocabulary and can never authorize a Stage A
``pass``.  Builders validate and reconcile evidence; parsers replay those
checks so hand-edited JSON cannot silently strengthen a result.
"""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import StageAInputError
from .util import sha256_bytes, write_json


RECONSTRUCTION_QUALIFICATION_FORMAT = "stage-a-reconstruction-qualification-v1"
ASSURANCE_REPORT_FORMAT = "stage-a-assurance-report-v1"

MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
ISA_EVIDENCE_FORMAT = "stage-a-reconstruction-isa-evidence-v1"
LOWERING_EVIDENCE_FORMAT = "stage-a-reconstruction-lowering-evidence-v1"
EXTERNAL_PROTOCOL_FORMAT = "stage-a-external-protocol-coverage-v1"
SOURCE_BINDING_FORMAT = "stage-b-reconstruction-source-binding-v1"
BUILD_BINDING_FORMAT = "stage-b-reconstruction-build-binding-v1"
MUTATION_RESULTS_FORMAT = "stage-a-reconstruction-mutation-results-v1"
FUNCTIONAL_RESULTS_FORMAT = "stage-b-candidate-functional-results-v1"
REGIONAL_REPLACEMENTS_FORMAT = "stage-b-regional-replacement-results-v1"
CACHE_EVIDENCE_FORMAT = "stage-a-reconstruction-cache-evidence-v1"
TIMING_EVIDENCE_FORMAT = "stage-a-reconstruction-timing-evidence-v1"

_DIGEST_LENGTH = 64
_EVIDENCE_CLASSES = frozenset(
    {
        "formal",
        "exhaustive",
        "solver",
        "differential",
        "fuzzed",
        "integration",
        "assumed",
        "unsupported",
    }
)


class ReconstructionAssuranceError(StageAInputError):
    """An assurance artifact or one of its inputs is malformed."""


class AssuranceStatus(StrEnum):
    QUALIFIED = "qualified"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


_STATUS_PRECEDENCE = {
    AssuranceStatus.QUALIFIED: 0,
    AssuranceStatus.INCOMPLETE: 1,
    AssuranceStatus.VIOLATED: 2,
}

_AUTHORITY = {
    "kind": "high-assurance-reconstruction-evidence",
    "proof_authority": False,
    "stage_a_pass_authorized": False,
    "whole_program_equivalence_claim": False,
    "original_runtime_allowed": False,
}

_EVIDENCE_SPECS: dict[str, tuple[str, frozenset[str], frozenset[str]]] = {
    "machine_ir": (
        MACHINE_IR_FORMAT,
        frozenset({"original_sha256", "machine_ir_sha256"}),
        frozenset(
            {
                "executable_bytes",
                "classified_executable_bytes",
                "units",
                "reachable_units",
                "unknown_reachable_units",
                "unsupported_reachable_units",
                "indirect_sites",
                "closed_indirect_sites",
                "external_sites",
                "closed_external_sites",
                "callbacks",
                "closed_callbacks",
            }
        ),
    ),
    "isa": (
        ISA_EVIDENCE_FORMAT,
        frozenset({"original_sha256", "machine_ir_sha256"}),
        frozenset(
            {
                "required_forms",
                "qualified_forms",
                "unsupported_reachable_forms",
                "disputed_forms",
            }
        ),
    ),
    "lowering": (
        LOWERING_EVIDENCE_FORMAT,
        frozenset({"original_sha256", "machine_ir_sha256"}),
        frozenset(
            {
                "reachable_units",
                "lowered_units",
                "unknown_reachable_units",
                "unsupported_reachable_units",
            }
        ),
    ),
    "external_protocol": (
        EXTERNAL_PROTOCOL_FORMAT,
        frozenset({"original_sha256", "machine_ir_sha256"}),
        frozenset(
            {
                "external_sites",
                "closed_external_sites",
                "callbacks",
                "closed_callbacks",
                "unknown_sites",
            }
        ),
    ),
    "source_binding": (
        SOURCE_BINDING_FORMAT,
        frozenset(
            {
                "original_sha256",
                "machine_ir_sha256",
                "source_manifest_sha256",
                "source_tree_sha256",
            }
        ),
        frozenset({"reachable_units", "bound_units"}),
    ),
    "build_binding": (
        BUILD_BINDING_FORMAT,
        frozenset(
            {
                "original_sha256",
                "machine_ir_sha256",
                "source_manifest_sha256",
                "source_tree_sha256",
                "candidate_sha256",
            }
        ),
        frozenset({"source_artifacts", "bound_source_artifacts", "candidate_size"}),
    ),
    "mutations": (
        MUTATION_RESULTS_FORMAT,
        frozenset({"original_sha256", "machine_ir_sha256", "candidate_sha256"}),
        frozenset({"mutations", "detected", "not_detected"}),
    ),
    "regional_replacements": (
        REGIONAL_REPLACEMENTS_FORMAT,
        frozenset({"machine_ir_sha256", "candidate_sha256"}),
        frozenset({"replacements", "qualified", "incomplete", "violated"}),
    ),
    "cache": (
        CACHE_EVIDENCE_FORMAT,
        frozenset({"machine_ir_sha256", "candidate_sha256"}),
        frozenset(
            {
                "artifacts",
                "substituted_no_change",
                "rebuilt_on_region_change",
                "reused_on_region_change",
            }
        ),
    ),
}


@dataclass(frozen=True)
class ReconstructionQualification:
    status: AssuranceStatus
    content_sha256: str
    bindings: Mapping[str, str]
    evidence: Mapping[str, Mapping[str, Any]]
    trust_assumptions: tuple[Mapping[str, str], ...]
    issues: tuple[Mapping[str, Any], ...]
    counts: Mapping[str, int]

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "format": RECONSTRUCTION_QUALIFICATION_FORMAT,
            "status": self.status.value,
            "bindings": dict(self.bindings),
            "evidence": copy.deepcopy(dict(self.evidence)),
            "trust_assumptions": [dict(row) for row in self.trust_assumptions],
            "issues": [copy.deepcopy(dict(row)) for row in self.issues],
            "counts": dict(self.counts),
            "authority": dict(_AUTHORITY),
        }
        payload["content_sha256"] = _content_sha256(payload)
        return payload


@dataclass(frozen=True)
class AssuranceReport:
    status: AssuranceStatus
    content_sha256: str
    reconstruction_qualification: ReconstructionQualification
    evidence: Mapping[str, Mapping[str, Any]]
    trust_assumptions: tuple[Mapping[str, str], ...]
    issues: tuple[Mapping[str, Any], ...]
    counts: Mapping[str, int]

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "format": ASSURANCE_REPORT_FORMAT,
            "status": self.status.value,
            "reconstruction_qualification": (
                self.reconstruction_qualification.to_payload()
            ),
            "evidence": copy.deepcopy(dict(self.evidence)),
            "trust_assumptions": [dict(row) for row in self.trust_assumptions],
            "issues": [copy.deepcopy(dict(row)) for row in self.issues],
            "counts": dict(self.counts),
            "runtime_policy": {
                "candidate_only": True,
                "original_runtime_executions": 0,
                "headless_wine_required": True,
            },
            "authority": dict(_AUTHORITY),
        }
        payload["content_sha256"] = _content_sha256(payload)
        return payload


def build_reconstruction_qualification(
    *,
    machine_ir: Mapping[str, Any],
    isa_evidence: Mapping[str, Any],
    lowering_evidence: Mapping[str, Any],
    external_protocol: Mapping[str, Any],
    source_binding: Mapping[str, Any],
    build_binding: Mapping[str, Any],
    trust_assumptions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Reconcile static reconstruction evidence into a strict qualification."""

    evidence = {
        "machine_ir": _parse_evidence(machine_ir, "machine_ir"),
        "isa": _parse_evidence(isa_evidence, "isa"),
        "lowering": _parse_evidence(lowering_evidence, "lowering"),
        "external_protocol": _parse_evidence(
            external_protocol, "external_protocol"
        ),
        "source_binding": _parse_evidence(source_binding, "source_binding"),
        "build_binding": _parse_evidence(build_binding, "build_binding"),
    }
    assumptions = _parse_assumptions(trust_assumptions, "trust_assumptions")
    issues = _qualification_issues(evidence, assumptions)
    status = _aggregate_status(issues)
    bindings = _qualification_bindings(evidence)
    counts = _aggregate_counts(evidence, issues)
    value = ReconstructionQualification(
        status=status,
        content_sha256="0" * _DIGEST_LENGTH,
        bindings=bindings,
        evidence=evidence,
        trust_assumptions=assumptions,
        issues=tuple(issues),
        counts=counts,
    )
    return value.to_payload()


def parse_reconstruction_qualification(value: Any) -> ReconstructionQualification:
    """Parse and replay a reconstruction qualification's consistency checks."""

    row = _object(value, "reconstruction qualification")
    _fields(
        row,
        {
            "format",
            "status",
            "content_sha256",
            "bindings",
            "evidence",
            "trust_assumptions",
            "issues",
            "counts",
            "authority",
        },
        "reconstruction qualification",
    )
    if row["format"] != RECONSTRUCTION_QUALIFICATION_FORMAT:
        raise ReconstructionAssuranceError(
            "unsupported reconstruction qualification format"
        )
    _validate_content_sha256(row, "reconstruction qualification")
    if row["authority"] != _AUTHORITY:
        raise ReconstructionAssuranceError(
            "reconstruction qualification authority policy changed"
        )
    evidence_row = _object(row["evidence"], "reconstruction evidence")
    _fields(evidence_row, set(_EVIDENCE_SPECS) & {
        "machine_ir", "isa", "lowering", "external_protocol",
        "source_binding", "build_binding",
    }, "reconstruction evidence")
    evidence = {
        family: _parse_evidence(evidence_row[family], family)
        for family in (
            "machine_ir",
            "isa",
            "lowering",
            "external_protocol",
            "source_binding",
            "build_binding",
        )
    }
    assumptions = _parse_assumptions(
        row["trust_assumptions"], "trust_assumptions"
    )
    expected_issues = tuple(_qualification_issues(evidence, assumptions))
    actual_issues = _parse_output_issues(row["issues"], "issues")
    if actual_issues != expected_issues:
        raise ReconstructionAssuranceError(
            "reconstruction qualification issues do not match evidence"
        )
    status = _status(row["status"], "status")
    if status is not _aggregate_status(expected_issues):
        raise ReconstructionAssuranceError(
            "reconstruction qualification status is inconsistent"
        )
    bindings = _digest_mapping(
        row["bindings"],
        {
            "original_sha256",
            "machine_ir_sha256",
            "source_manifest_sha256",
            "source_tree_sha256",
            "candidate_sha256",
        },
        "bindings",
    )
    if bindings != _qualification_bindings(evidence):
        raise ReconstructionAssuranceError(
            "reconstruction qualification bindings are inconsistent"
        )
    counts = _count_mapping(
        row["counts"],
        {"families", "qualified", "incomplete", "violated", "issues"},
        "counts",
    )
    if counts != _aggregate_counts(evidence, expected_issues):
        raise ReconstructionAssuranceError(
            "reconstruction qualification counts are inconsistent"
        )
    return ReconstructionQualification(
        status=status,
        content_sha256=_sha256(row["content_sha256"], "content_sha256"),
        bindings=bindings,
        evidence=evidence,
        trust_assumptions=assumptions,
        issues=actual_issues,
        counts=counts,
    )


def build_assurance_report(
    *,
    reconstruction_qualification: Mapping[str, Any] | ReconstructionQualification,
    mutation_results: Mapping[str, Any],
    functional_results: Mapping[str, Any],
    regional_replacements: Mapping[str, Any],
    cache_evidence: Mapping[str, Any],
    timing_evidence: Mapping[str, Any],
    trust_assumptions: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the final, candidate-only high-assurance evidence report."""

    qualification = (
        reconstruction_qualification
        if isinstance(reconstruction_qualification, ReconstructionQualification)
        else parse_reconstruction_qualification(reconstruction_qualification)
    )
    evidence = {
        "mutations": _parse_evidence(mutation_results, "mutations"),
        "functional": _parse_functional_evidence(functional_results),
        "regional_replacements": _parse_evidence(
            regional_replacements, "regional_replacements"
        ),
        "cache": _parse_cache_evidence(cache_evidence),
        "timing": _parse_timing_evidence(timing_evidence),
    }
    assumptions = (
        qualification.trust_assumptions
        if trust_assumptions is None
        else _parse_assumptions(trust_assumptions, "trust_assumptions")
    )
    issues = _assurance_issues(qualification, evidence, assumptions)
    status = _aggregate_status(issues)
    counts = _assurance_counts(qualification, evidence, issues)
    value = AssuranceReport(
        status=status,
        content_sha256="0" * _DIGEST_LENGTH,
        reconstruction_qualification=qualification,
        evidence=evidence,
        trust_assumptions=assumptions,
        issues=tuple(issues),
        counts=counts,
    )
    return value.to_payload()


def parse_assurance_report(value: Any) -> AssuranceReport:
    """Parse and replay the final assurance aggregation."""

    row = _object(value, "assurance report")
    _fields(
        row,
        {
            "format",
            "status",
            "content_sha256",
            "reconstruction_qualification",
            "evidence",
            "trust_assumptions",
            "issues",
            "counts",
            "runtime_policy",
            "authority",
        },
        "assurance report",
    )
    if row["format"] != ASSURANCE_REPORT_FORMAT:
        raise ReconstructionAssuranceError("unsupported assurance report format")
    _validate_content_sha256(row, "assurance report")
    if row["authority"] != _AUTHORITY:
        raise ReconstructionAssuranceError("assurance report authority policy changed")
    if row["runtime_policy"] != {
        "candidate_only": True,
        "original_runtime_executions": 0,
        "headless_wine_required": True,
    }:
        raise ReconstructionAssuranceError("assurance runtime policy changed")
    qualification = parse_reconstruction_qualification(
        row["reconstruction_qualification"]
    )
    evidence_row = _object(row["evidence"], "assurance evidence")
    _fields(
        evidence_row,
        {"mutations", "functional", "regional_replacements", "cache", "timing"},
        "assurance evidence",
    )
    evidence = {
        "mutations": _parse_evidence(evidence_row["mutations"], "mutations"),
        "functional": _parse_functional_evidence(evidence_row["functional"]),
        "regional_replacements": _parse_evidence(
            evidence_row["regional_replacements"], "regional_replacements"
        ),
        "cache": _parse_cache_evidence(evidence_row["cache"]),
        "timing": _parse_timing_evidence(evidence_row["timing"]),
    }
    assumptions = _parse_assumptions(
        row["trust_assumptions"], "trust_assumptions"
    )
    expected_issues = tuple(_assurance_issues(qualification, evidence, assumptions))
    actual_issues = _parse_output_issues(row["issues"], "issues")
    if actual_issues != expected_issues:
        raise ReconstructionAssuranceError(
            "assurance report issues do not match evidence"
        )
    status = _status(row["status"], "status")
    if status is not _aggregate_status(expected_issues):
        raise ReconstructionAssuranceError("assurance report status is inconsistent")
    counts = _count_mapping(
        row["counts"],
        {"families", "qualified", "incomplete", "violated", "issues"},
        "counts",
    )
    if counts != _assurance_counts(qualification, evidence, expected_issues):
        raise ReconstructionAssuranceError("assurance report counts are inconsistent")
    return AssuranceReport(
        status=status,
        content_sha256=_sha256(row["content_sha256"], "content_sha256"),
        reconstruction_qualification=qualification,
        evidence=evidence,
        trust_assumptions=assumptions,
        issues=actual_issues,
        counts=counts,
    )


def write_reconstruction_qualification(path: Path | str, **kwargs: Any) -> dict[str, Any]:
    payload = build_reconstruction_qualification(**kwargs)
    write_json(Path(path), payload)
    return payload


def write_assurance_report(path: Path | str, **kwargs: Any) -> dict[str, Any]:
    payload = build_assurance_report(**kwargs)
    write_json(Path(path), payload)
    return payload


def _qualification_issues(
    evidence: Mapping[str, Mapping[str, Any]],
    assumptions: tuple[Mapping[str, str], ...],
) -> list[dict[str, Any]]:
    issues = _family_issues(evidence)
    _assumption_reference_issues(issues, evidence, assumptions)
    machine = evidence["machine_ir"]
    counts = machine["counts"]
    for name in ("executable_bytes", "units", "reachable_units"):
        if counts[name] == 0:
            issues.append(_issue(
                AssuranceStatus.INCOMPLETE, "machine_ir", f"empty_{name}",
                f"machine IR {name} inventory is empty",
                _location("machine_ir", f"$.counts.{name}"), "positive", 0,
            ))
    _require_count(
        issues, "machine_ir", "executable_byte_coverage",
        counts["executable_bytes"], counts["classified_executable_bytes"],
        "$.counts.classified_executable_bytes",
    )
    if counts["unknown_reachable_units"]:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "machine_ir", "unknown_reachable_units",
            "reachable machine-IR units remain unknown",
            _location("machine_ir", "$.counts.unknown_reachable_units"),
            0, counts["unknown_reachable_units"],
        ))
    if counts["unsupported_reachable_units"]:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "machine_ir", "unsupported_reachable_units",
            "reachable machine-IR units use unsupported semantics",
            _location("machine_ir", "$.counts.unsupported_reachable_units"),
            0, counts["unsupported_reachable_units"],
        ))
    for stem in ("indirect_sites", "external_sites", "callbacks"):
        _require_count(
            issues, "machine_ir", f"unclosed_{stem}", counts[stem],
            counts[f"closed_{stem}"], f"$.counts.closed_{stem}",
        )

    isa = evidence["isa"]["counts"]
    _require_count(
        issues, "isa", "unqualified_isa_forms", isa["required_forms"],
        isa["qualified_forms"], "$.counts.qualified_forms",
    )
    for name in ("unsupported_reachable_forms", "disputed_forms"):
        if isa[name]:
            severity = (
                AssuranceStatus.VIOLATED
                if name == "disputed_forms"
                else AssuranceStatus.INCOMPLETE
            )
            issues.append(_issue(
                severity, "isa", name,
                "ISA qualification contains disputed forms"
                if name == "disputed_forms"
                else "reachable ISA forms remain unsupported",
                _location("isa", f"$.counts.{name}"), 0, isa[name],
            ))

    lowering = evidence["lowering"]["counts"]
    _require_count(
        issues, "lowering", "unlowered_reachable_units",
        lowering["reachable_units"], lowering["lowered_units"],
        "$.counts.lowered_units",
    )
    for name in ("unknown_reachable_units", "unsupported_reachable_units"):
        if lowering[name]:
            issues.append(_issue(
                AssuranceStatus.INCOMPLETE, "lowering", name,
                "lowering contains reachable unknown or unsupported units",
                _location("lowering", f"$.counts.{name}"), 0, lowering[name],
            ))

    external = evidence["external_protocol"]["counts"]
    for stem in ("external_sites", "callbacks"):
        _require_count(
            issues, "external_protocol", f"unclosed_{stem}", external[stem],
            external[f"closed_{stem}"], f"$.counts.closed_{stem}",
        )
    if external["unknown_sites"]:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "external_protocol", "unknown_sites",
            "external protocol contains unknown reachable sites",
            _location("external_protocol", "$.counts.unknown_sites"),
            0, external["unknown_sites"],
        ))

    source = evidence["source_binding"]["counts"]
    _require_count(
        issues, "source_binding", "unbound_source_units",
        source["reachable_units"], source["bound_units"], "$.counts.bound_units",
    )
    build = evidence["build_binding"]["counts"]
    _require_count(
        issues, "build_binding", "unbound_source_artifacts",
        build["source_artifacts"], build["bound_source_artifacts"],
        "$.counts.bound_source_artifacts",
    )
    if build["candidate_size"] == 0:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "build_binding", "empty_candidate",
            "candidate build is empty", _location("build_binding", "$.counts.candidate_size"),
            "positive", 0,
        ))

    _cross_binding_issues(issues, evidence)
    _count_drift_issue(
        issues, "lowering", "reachable_units",
        counts["reachable_units"], lowering["reachable_units"],
    )
    _count_drift_issue(
        issues, "source_binding", "reachable_units",
        counts["reachable_units"], source["reachable_units"],
    )
    for name in ("external_sites", "callbacks"):
        _count_drift_issue(
            issues, "external_protocol", name, counts[name], external[name]
        )
    return _sorted_issues(issues)


def _assurance_issues(
    qualification: ReconstructionQualification,
    evidence: Mapping[str, Mapping[str, Any]],
    assumptions: tuple[Mapping[str, str], ...],
) -> list[dict[str, Any]]:
    issues = _family_issues(evidence)
    _assumption_reference_issues(issues, evidence, assumptions)
    if qualification.status is not AssuranceStatus.QUALIFIED:
        issues.append(_issue(
            qualification.status, "reconstruction_qualification",
            "static_qualification_not_qualified",
            "static reconstruction qualification is not qualified",
            _location("reconstruction_qualification", "$.status"),
            AssuranceStatus.QUALIFIED.value, qualification.status.value,
        ))
    if assumptions != qualification.trust_assumptions:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "trust_assumptions", "assumption_drift",
            "final report trust assumptions differ from static qualification",
            _location("trust_assumptions", "$"),
            [dict(row) for row in qualification.trust_assumptions],
            [dict(row) for row in assumptions],
        ))

    mutations = evidence["mutations"]["counts"]
    if mutations["mutations"] == 0:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "mutations", "missing_mutation_campaign",
            "no deterministic mutations were tested",
            _location("mutations", "$.counts.mutations"), "positive", 0,
        ))
    if mutations["not_detected"]:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "mutations", "mutation_not_detected",
            "one or more seeded mutations escaped detection",
            _location("mutations", "$.counts.not_detected"), 0,
            mutations["not_detected"],
        ))
    _require_count(
        issues, "mutations", "mutation_accounting",
        mutations["mutations"], mutations["detected"] + mutations["not_detected"],
        "$.counts",
        severity=AssuranceStatus.VIOLATED,
    )

    functional = evidence["functional"]
    functional_counts = functional["counts"]
    if functional_counts["cases"] == 0:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "functional", "empty_functional_suite",
            "candidate-only functional evidence contains no cases",
            _location("functional", "$.counts.cases"), "positive", 0,
        ))
    _require_count(
        issues, "functional", "functional_cases_not_passing",
        functional_counts["cases"], functional_counts["passed"],
        "$.counts.passed", severity=AssuranceStatus.VIOLATED,
    )
    if functional_counts["failed"]:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "functional", "functional_failures",
            "candidate-only functional tests failed",
            _location("functional", "$.counts.failed"), 0,
            functional_counts["failed"],
        ))
    if functional_counts["original_runtime_executions"] != 0:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "functional", "original_runtime_executed",
            "runtime validation executed the original binary",
            _location("functional", "$.counts.original_runtime_executions"),
            0, functional_counts["original_runtime_executions"],
        ))
    if functional["original_runtime_observations"] is not False:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "functional", "original_runtime_observed",
            "runtime validation consumed an original-binary observation",
            _location("functional", "$.original_runtime_observations"),
            False, functional["original_runtime_observations"],
        ))
    _headless_wine_issues(issues, functional["execution"])

    replacements = evidence["regional_replacements"]["counts"]
    if replacements["replacements"] == 0:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "regional_replacements",
            "missing_regional_replacement",
            "no higher-level regional replacement was validated",
            _location("regional_replacements", "$.counts.replacements"),
            "positive", 0,
        ))
    _require_count(
        issues, "regional_replacements", "regional_replacement_accounting",
        replacements["replacements"],
        replacements["qualified"] + replacements["incomplete"] + replacements["violated"],
        "$.counts", severity=AssuranceStatus.VIOLATED,
    )
    if replacements["incomplete"]:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "regional_replacements",
            "incomplete_regional_replacements",
            "regional replacements remain incomplete",
            _location("regional_replacements", "$.counts.incomplete"),
            0, replacements["incomplete"],
        ))
    if replacements["violated"]:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "regional_replacements",
            "violated_regional_replacements",
            "regional replacement validation found divergence",
            _location("regional_replacements", "$.counts.violated"),
            0, replacements["violated"],
        ))

    cache = evidence["cache"]
    cache_counts = cache["counts"]
    if cache_counts["artifacts"] == 0:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "cache", "empty_cache_inventory",
            "cache evidence contains no proof or reconstruction artifacts",
            _location("cache", "$.counts.artifacts"), "positive", 0,
        ))
    _require_count(
        issues, "cache", "warm_cache_miss", cache_counts["artifacts"],
        cache_counts["substituted_no_change"], "$.counts.substituted_no_change",
    )
    _require_count(
        issues, "cache", "region_change_cache_accounting",
        cache_counts["artifacts"],
        cache_counts["rebuilt_on_region_change"] + cache_counts["reused_on_region_change"],
        "$.counts", severity=AssuranceStatus.VIOLATED,
    )
    for field, code in (
        ("no_change_all_substituted", "no_change_not_fully_substituted"),
        ("region_change_scope_preserved", "region_change_scope_not_preserved"),
    ):
        if cache[field] is not True:
            issues.append(_issue(
                AssuranceStatus.INCOMPLETE, "cache", code,
                "cache invalidation contract was not demonstrated",
                _location("cache", f"$.{field}"), True, cache[field],
            ))

    timing = evidence["timing"]
    for observed, limit in (
        ("replacement_iteration_seconds", "replacement_iteration_limit_seconds"),
        ("full_runtime_seconds", "full_runtime_limit_seconds"),
    ):
        if timing[observed] > timing[limit]:
            issues.append(_issue(
                AssuranceStatus.INCOMPLETE, "timing", f"{observed}_over_limit",
                "measured iteration time exceeds the declared viability limit",
                _location("timing", f"$.{observed}"), timing[limit], timing[observed],
            ))

    expected = qualification.bindings
    for family, family_evidence in evidence.items():
        for key, observed in family_evidence.get("bindings", {}).items():
            if key in expected and observed != expected[key]:
                issues.append(_issue(
                    AssuranceStatus.VIOLATED, family, "binding_drift",
                    f"{key} differs from the static reconstruction qualification",
                    _location(family, f"$.bindings.{key}"), expected[key], observed,
                ))
    return _sorted_issues(issues)


def _family_issues(
    evidence: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for family, row in evidence.items():
        status = AssuranceStatus(row["status"])
        if status is not AssuranceStatus.QUALIFIED:
            issues.append(_issue(
                status, family, "upstream_status",
                f"{family} evidence is {status.value}",
                _location(family, "$.status"), AssuranceStatus.QUALIFIED.value,
                status.value,
            ))
        for source in row.get("issues", []):
            issues.append(_issue(
                AssuranceStatus(source["status"]), family, source["code"],
                source["message"], source["location"], source["expected"],
                source["observed"],
            ))
    return issues


def _assumption_reference_issues(
    issues: list[dict[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    assumptions: tuple[Mapping[str, str], ...],
) -> None:
    available = {row["id"] for row in assumptions}
    for family, row in evidence.items():
        classes = set(row["evidence_classes"])
        references = set(row["assumption_ids"])
        unknown = sorted(references - available)
        if unknown:
            issues.append(_issue(
                AssuranceStatus.VIOLATED,
                family,
                "unknown_assumption_reference",
                "evidence references assumptions absent from the assurance case",
                _location(family, "$.assumption_ids"),
                sorted(available),
                unknown,
            ))
        if "assumed" in classes and not references:
            issues.append(_issue(
                AssuranceStatus.INCOMPLETE,
                family,
                "unbound_assumed_evidence",
                "assumed evidence does not identify its trust assumptions",
                _location(family, "$.assumption_ids"),
                "at least one assumption id",
                [],
            ))
        if references and "assumed" not in classes:
            issues.append(_issue(
                AssuranceStatus.VIOLATED,
                family,
                "hidden_assumption_dependency",
                "evidence references assumptions without declaring the assumed class",
                _location(family, "$.evidence_classes"),
                "assumed",
                sorted(classes),
            ))
        if "unsupported" in classes and row["status"] == AssuranceStatus.QUALIFIED.value:
            issues.append(_issue(
                AssuranceStatus.VIOLATED,
                family,
                "unsupported_evidence_qualified",
                "unsupported evidence cannot qualify an assurance family",
                _location(family, "$.evidence_classes"),
                "no unsupported class",
                sorted(classes),
            ))


def _cross_binding_issues(
    issues: list[dict[str, Any]], evidence: Mapping[str, Mapping[str, Any]]
) -> None:
    machine = evidence["machine_ir"]
    expected_original = machine["bindings"]["original_sha256"]
    expected_ir = machine["bindings"]["machine_ir_sha256"]
    if machine["artifact_sha256"] != expected_ir:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "machine_ir", "artifact_binding_drift",
            "machine IR artifact digest differs from its declared identity",
            _location("machine_ir", "$.artifact_sha256"), expected_ir,
            machine["artifact_sha256"],
        ))
    for family, row in evidence.items():
        for key, expected in (
            ("original_sha256", expected_original),
            ("machine_ir_sha256", expected_ir),
        ):
            observed = row["bindings"].get(key)
            if observed is not None and observed != expected:
                issues.append(_issue(
                    AssuranceStatus.VIOLATED, family, "binding_drift",
                    f"{key} differs from the canonical machine IR binding",
                    _location(family, f"$.bindings.{key}"), expected, observed,
                ))
    source = evidence["source_binding"]["bindings"]
    build = evidence["build_binding"]["bindings"]
    for key in ("source_manifest_sha256", "source_tree_sha256"):
        if build[key] != source[key]:
            issues.append(_issue(
                AssuranceStatus.VIOLATED, "build_binding", "binding_drift",
                f"{key} differs from the source binding",
                _location("build_binding", f"$.bindings.{key}"),
                source[key], build[key],
            ))


def _qualification_bindings(
    evidence: Mapping[str, Mapping[str, Any]],
) -> dict[str, str]:
    machine = evidence["machine_ir"]["bindings"]
    source = evidence["source_binding"]["bindings"]
    build = evidence["build_binding"]["bindings"]
    return {
        "original_sha256": machine["original_sha256"],
        "machine_ir_sha256": machine["machine_ir_sha256"],
        "source_manifest_sha256": source["source_manifest_sha256"],
        "source_tree_sha256": source["source_tree_sha256"],
        "candidate_sha256": build["candidate_sha256"],
    }


def _parse_evidence(value: Any, family: str) -> dict[str, Any]:
    expected_format, binding_fields, count_fields = _EVIDENCE_SPECS[family]
    row = _object(value, f"{family} evidence")
    _fields(
        row,
        {
            "format", "status", "artifact_sha256", "bindings", "counts",
            "evidence_classes", "assumption_ids", "issues",
        },
        f"{family} evidence",
    )
    if row["format"] != expected_format:
        raise ReconstructionAssuranceError(f"unsupported {family} evidence format")
    parsed = {
        "format": expected_format,
        "status": _status(row["status"], f"{family}.status").value,
        "artifact_sha256": _sha256(
            row["artifact_sha256"], f"{family}.artifact_sha256"
        ),
        "bindings": _digest_mapping(
            row["bindings"], binding_fields, f"{family}.bindings"
        ),
        "counts": _count_mapping(row["counts"], count_fields, f"{family}.counts"),
        "evidence_classes": _evidence_classes(
            row["evidence_classes"], f"{family}.evidence_classes"
        ),
        "assumption_ids": _identifier_list(
            row["assumption_ids"], f"{family}.assumption_ids"
        ),
        "issues": [
            _parse_source_issue(issue, f"{family}.issues[{index}]")
            for index, issue in enumerate(_list(row["issues"], f"{family}.issues"))
        ],
    }
    _validate_local_count_bounds(family, parsed["counts"])
    return parsed


def _parse_functional_evidence(value: Any) -> dict[str, Any]:
    family = "functional"
    row = _object(value, "functional evidence")
    _fields(
        row,
        {
            "format", "status", "artifact_sha256", "bindings", "counts",
            "evidence_classes", "assumption_ids",
            "original_runtime_observations", "execution", "issues",
        },
        "functional evidence",
    )
    if row["format"] != FUNCTIONAL_RESULTS_FORMAT:
        raise ReconstructionAssuranceError("unsupported functional evidence format")
    observations = _boolean(
        row["original_runtime_observations"],
        "functional.original_runtime_observations",
    )
    execution = _parse_execution(row["execution"])
    parsed = {
        "format": FUNCTIONAL_RESULTS_FORMAT,
        "status": _status(row["status"], "functional.status").value,
        "artifact_sha256": _sha256(row["artifact_sha256"], "functional.artifact_sha256"),
        "bindings": _digest_mapping(
            row["bindings"], {"candidate_sha256"}, "functional.bindings"
        ),
        "counts": _count_mapping(
            row["counts"],
            {"cases", "passed", "failed", "original_runtime_executions"},
            "functional.counts",
        ),
        "evidence_classes": _evidence_classes(
            row["evidence_classes"], "functional.evidence_classes"
        ),
        "assumption_ids": _identifier_list(
            row["assumption_ids"], "functional.assumption_ids"
        ),
        "original_runtime_observations": observations,
        "execution": execution,
        "issues": [
            _parse_source_issue(issue, f"functional.issues[{index}]")
            for index, issue in enumerate(_list(row["issues"], "functional.issues"))
        ],
    }
    counts = parsed["counts"]
    if counts["passed"] + counts["failed"] > counts["cases"]:
        raise ReconstructionAssuranceError(
            "functional passed and failed counts exceed total cases"
        )
    return parsed


def _parse_cache_evidence(value: Any) -> dict[str, Any]:
    row = _object(value, "cache evidence")
    _fields(
        row,
        {
            "format", "status", "artifact_sha256", "bindings", "counts",
            "evidence_classes", "assumption_ids",
            "no_change_all_substituted", "region_change_scope_preserved", "issues",
        },
        "cache evidence",
    )
    common = _parse_evidence(
        {key: row[key] for key in (
            "format", "status", "artifact_sha256", "bindings", "counts",
            "evidence_classes", "assumption_ids", "issues"
        )},
        "cache",
    )
    common["no_change_all_substituted"] = _boolean(
        row["no_change_all_substituted"], "cache.no_change_all_substituted"
    )
    common["region_change_scope_preserved"] = _boolean(
        row["region_change_scope_preserved"],
        "cache.region_change_scope_preserved",
    )
    return common


def _parse_timing_evidence(value: Any) -> dict[str, Any]:
    row = _object(value, "timing evidence")
    _fields(
        row,
        {
            "format", "status", "artifact_sha256", "bindings", "issues",
            "evidence_classes", "assumption_ids",
            "replacement_iteration_seconds", "replacement_iteration_limit_seconds",
            "full_runtime_seconds", "full_runtime_limit_seconds",
        },
        "timing evidence",
    )
    if row["format"] != TIMING_EVIDENCE_FORMAT:
        raise ReconstructionAssuranceError("unsupported timing evidence format")
    result = {
        "format": TIMING_EVIDENCE_FORMAT,
        "status": _status(row["status"], "timing.status").value,
        "artifact_sha256": _sha256(row["artifact_sha256"], "timing.artifact_sha256"),
        "bindings": _digest_mapping(
            row["bindings"], {"machine_ir_sha256", "candidate_sha256"},
            "timing.bindings",
        ),
        "evidence_classes": _evidence_classes(
            row["evidence_classes"], "timing.evidence_classes"
        ),
        "assumption_ids": _identifier_list(
            row["assumption_ids"], "timing.assumption_ids"
        ),
        "replacement_iteration_seconds": _nonnegative_number(
            row["replacement_iteration_seconds"],
            "timing.replacement_iteration_seconds",
        ),
        "replacement_iteration_limit_seconds": _positive_number(
            row["replacement_iteration_limit_seconds"],
            "timing.replacement_iteration_limit_seconds",
        ),
        "full_runtime_seconds": _nonnegative_number(
            row["full_runtime_seconds"], "timing.full_runtime_seconds"
        ),
        "full_runtime_limit_seconds": _positive_number(
            row["full_runtime_limit_seconds"], "timing.full_runtime_limit_seconds"
        ),
        "issues": [
            _parse_source_issue(issue, f"timing.issues[{index}]")
            for index, issue in enumerate(_list(row["issues"], "timing.issues"))
        ],
    }
    return result


def _parse_execution(value: Any) -> dict[str, Any]:
    row = _object(value, "functional.execution")
    _fields(row, {"command", "session", "headless", "environment"}, "functional.execution")
    command = tuple(
        _nonempty_string(token, f"functional.execution.command[{index}]")
        for index, token in enumerate(_list(row["command"], "functional.execution.command"))
    )
    if not command:
        raise ReconstructionAssuranceError("functional execution command must not be empty")
    session = _nonempty_string(row["session"], "functional.execution.session")
    if session not in {"headless-x", "headless-wayland", "headless-wayland-or-x"}:
        raise ReconstructionAssuranceError(
            "functional execution session must identify a headless X or Wayland session"
        )
    environment_row = _object(row["environment"], "functional.execution.environment")
    environment: dict[str, str] = {}
    for key, item in environment_row.items():
        environment[_nonempty_string(key, "functional execution environment key")] = (
            _nonempty_string(item, f"functional.execution.environment.{key}")
        )
    return {
        "command": list(command),
        "session": session,
        "headless": _boolean(row["headless"], "functional.execution.headless"),
        "environment": dict(sorted(environment.items())),
    }


def _headless_wine_issues(
    issues: list[dict[str, Any]], execution: Mapping[str, Any]
) -> None:
    command = execution["command"]
    wine_present = any(os.path.basename(token).lower().startswith("wine") for token in command)
    if not wine_present:
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "functional", "wine_command_missing",
            "functional command does not identify a Wine executable",
            _location("functional", "$.execution.command"), "Wine command", command,
        ))
    if execution["headless"] is not True:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, "functional", "runtime_not_headless",
            "Wine runtime evidence is not headless",
            _location("functional", "$.execution.headless"), True,
            execution["headless"],
        ))
    display_keys = (
        ("DISPLAY",)
        if execution["session"] == "headless-x"
        else (("WAYLAND_DISPLAY",) if execution["session"] == "headless-wayland" else ("DISPLAY", "WAYLAND_DISPLAY"))
    )
    if not any(key in execution["environment"] for key in display_keys):
        issues.append(_issue(
            AssuranceStatus.INCOMPLETE, "functional", "headless_display_missing",
            f"headless {execution['session']} evidence lacks a display binding",
            _location("functional", "$.execution.environment"), list(display_keys),
            sorted(execution["environment"]),
        ))


def _parse_source_issue(value: Any, field: str) -> dict[str, Any]:
    row = _object(value, field)
    _fields(row, {"status", "code", "message", "location", "expected", "observed"}, field)
    status = _status(row["status"], f"{field}.status")
    if status is AssuranceStatus.QUALIFIED:
        raise ReconstructionAssuranceError(f"{field}.status cannot be qualified")
    return {
        "status": status.value,
        "code": _identifier(row["code"], f"{field}.code"),
        "message": _nonempty_string(row["message"], f"{field}.message"),
        "location": _parse_location(row["location"], f"{field}.location"),
        "expected": _json_value(row["expected"], f"{field}.expected"),
        "observed": _json_value(row["observed"], f"{field}.observed"),
    }


def _parse_output_issues(value: Any, field: str) -> tuple[Mapping[str, Any], ...]:
    result = []
    for index, item in enumerate(_list(value, field)):
        row = _object(item, f"{field}[{index}]")
        _fields(
            row,
            {"id", "status", "family", "code", "message", "location", "expected", "observed"},
            f"{field}[{index}]",
        )
        core = _parse_source_issue(
            {key: row[key] for key in ("status", "code", "message", "location", "expected", "observed")},
            f"{field}[{index}]",
        )
        family = _identifier(row["family"], f"{field}[{index}].family")
        expected_id = _issue_id(family, core)
        if row["id"] != expected_id:
            raise ReconstructionAssuranceError(f"{field}[{index}] has a non-deterministic ID")
        result.append({"id": expected_id, "family": family, **core})
    parsed = tuple(result)
    if parsed != tuple(_sorted_issues(parsed)):
        raise ReconstructionAssuranceError(f"{field} must be deterministically sorted")
    return parsed


def _issue(
    status: AssuranceStatus,
    family: str,
    code: str,
    message: str,
    location: Mapping[str, Any],
    expected: Any,
    observed: Any,
) -> dict[str, Any]:
    core = {
        "status": status.value,
        "code": code,
        "message": message,
        "location": dict(location),
        "expected": copy.deepcopy(expected),
        "observed": copy.deepcopy(observed),
    }
    return {"id": _issue_id(family, core), "family": family, **core}


def _issue_id(family: str, core: Mapping[str, Any]) -> str:
    material = {"family": family, **dict(core)}
    suffix = sha256_bytes(_canonical_json(material))[:16]
    return f"reconstruction.{family}.{core['code']}.{suffix}"


def _location(artifact: str, json_path: str) -> dict[str, Any]:
    return {
        "artifact": artifact,
        "json_path": json_path,
        "unit_id": None,
        "rva": None,
        "source_path": None,
        "source_line": None,
    }


def _parse_location(value: Any, field: str) -> dict[str, Any]:
    row = _object(value, field)
    _fields(
        row,
        {"artifact", "json_path", "unit_id", "rva", "source_path", "source_line"},
        field,
    )
    unit_id = row["unit_id"]
    if unit_id is not None:
        unit_id = _nonempty_string(unit_id, f"{field}.unit_id")
    rva = row["rva"]
    if rva is not None:
        rva = _nonnegative_int(rva, f"{field}.rva")
        if rva > 0xFFFFFFFF:
            raise ReconstructionAssuranceError(f"{field}.rva exceeds PE32 range")
    source_path = row["source_path"]
    if source_path is not None:
        source_path = _nonempty_string(source_path, f"{field}.source_path")
    source_line = row["source_line"]
    if source_line is not None:
        source_line = _positive_int(source_line, f"{field}.source_line")
        if source_path is None:
            raise ReconstructionAssuranceError(
                f"{field}.source_line requires source_path"
            )
    return {
        "artifact": _nonempty_string(row["artifact"], f"{field}.artifact"),
        "json_path": _nonempty_string(row["json_path"], f"{field}.json_path"),
        "unit_id": unit_id,
        "rva": rva,
        "source_path": source_path,
        "source_line": source_line,
    }


def _parse_assumptions(value: Any, field: str) -> tuple[Mapping[str, str], ...]:
    rows = _list(value, field)
    if not rows:
        raise ReconstructionAssuranceError(
            "trust_assumptions must explicitly identify at least one assumption"
        )
    result = []
    for index, item in enumerate(rows):
        row = _object(item, f"{field}[{index}]")
        _fields(row, {"id", "scope", "statement"}, f"{field}[{index}]")
        result.append({
            "id": _identifier(row["id"], f"{field}[{index}].id"),
            "scope": _nonempty_string(row["scope"], f"{field}[{index}].scope"),
            "statement": _nonempty_string(row["statement"], f"{field}[{index}].statement"),
        })
    result.sort(key=lambda row: row["id"])
    ids = [row["id"] for row in result]
    if len(ids) != len(set(ids)):
        raise ReconstructionAssuranceError("trust assumption IDs must be unique")
    return tuple(result)


def _validate_local_count_bounds(family: str, counts: Mapping[str, int]) -> None:
    bounds: tuple[tuple[str, str], ...] = ()
    if family == "machine_ir":
        bounds = (
            ("classified_executable_bytes", "executable_bytes"),
            ("reachable_units", "units"),
            ("closed_indirect_sites", "indirect_sites"),
            ("closed_external_sites", "external_sites"),
            ("closed_callbacks", "callbacks"),
        )
    elif family == "isa":
        bounds = (("qualified_forms", "required_forms"),)
    elif family == "lowering":
        bounds = (("lowered_units", "reachable_units"),)
    elif family == "external_protocol":
        bounds = (
            ("closed_external_sites", "external_sites"),
            ("closed_callbacks", "callbacks"),
        )
    elif family == "source_binding":
        bounds = (("bound_units", "reachable_units"),)
    elif family == "build_binding":
        bounds = (("bound_source_artifacts", "source_artifacts"),)
    elif family == "mutations":
        bounds = (
            ("detected", "mutations"),
            ("not_detected", "mutations"),
        )
    elif family == "regional_replacements":
        bounds = (
            ("qualified", "replacements"),
            ("incomplete", "replacements"),
            ("violated", "replacements"),
        )
    elif family == "cache":
        bounds = (
            ("substituted_no_change", "artifacts"),
            ("rebuilt_on_region_change", "artifacts"),
            ("reused_on_region_change", "artifacts"),
        )
    for child, parent in bounds:
        if counts[child] > counts[parent]:
            raise ReconstructionAssuranceError(
                f"{family}.{child} exceeds {parent}"
            )


def _require_count(
    issues: list[dict[str, Any]],
    family: str,
    code: str,
    expected: int,
    observed: int,
    json_path: str,
    *,
    severity: AssuranceStatus = AssuranceStatus.INCOMPLETE,
) -> None:
    if expected != observed:
        issues.append(_issue(
            severity, family, code, f"{family} count is not closed",
            _location(family, json_path), expected, observed,
        ))


def _count_drift_issue(
    issues: list[dict[str, Any]], family: str, field: str,
    expected: int, observed: int,
) -> None:
    if expected != observed:
        issues.append(_issue(
            AssuranceStatus.VIOLATED, family, "count_drift",
            f"{field} differs from the canonical machine IR inventory",
            _location(family, f"$.counts.{field}"), expected, observed,
        ))


def _aggregate_status(issues: Sequence[Mapping[str, Any]]) -> AssuranceStatus:
    if not issues:
        return AssuranceStatus.QUALIFIED
    return max(
        (AssuranceStatus(issue["status"]) for issue in issues),
        key=_STATUS_PRECEDENCE.__getitem__,
    )


def _aggregate_counts(
    evidence: Mapping[str, Mapping[str, Any]], issues: Sequence[Mapping[str, Any]]
) -> dict[str, int]:
    statuses = [AssuranceStatus(row["status"]) for row in evidence.values()]
    return {
        "families": len(statuses),
        "qualified": statuses.count(AssuranceStatus.QUALIFIED),
        "incomplete": statuses.count(AssuranceStatus.INCOMPLETE),
        "violated": statuses.count(AssuranceStatus.VIOLATED),
        "issues": len(issues),
    }


def _assurance_counts(
    qualification: ReconstructionQualification,
    evidence: Mapping[str, Mapping[str, Any]],
    issues: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    statuses = [qualification.status]
    statuses.extend(AssuranceStatus(row["status"]) for row in evidence.values())
    return {
        "families": len(statuses),
        "qualified": statuses.count(AssuranceStatus.QUALIFIED),
        "incomplete": statuses.count(AssuranceStatus.INCOMPLETE),
        "violated": statuses.count(AssuranceStatus.VIOLATED),
        "issues": len(issues),
    }


def _sorted_issues(issues: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    deduplicated = {str(issue["id"]): copy.deepcopy(dict(issue)) for issue in issues}
    return sorted(
        deduplicated.values(),
        key=lambda issue: (
            -_STATUS_PRECEDENCE[AssuranceStatus(issue["status"])],
            issue["family"], issue["location"]["json_path"], issue["code"], issue["id"],
        ),
    )


def _content_sha256(payload: Mapping[str, Any]) -> str:
    core = {key: value for key, value in payload.items() if key != "content_sha256"}
    return sha256_bytes(_canonical_json(core))


def _validate_content_sha256(payload: Mapping[str, Any], field: str) -> None:
    observed = _sha256(payload["content_sha256"], f"{field}.content_sha256")
    expected = _content_sha256(payload)
    if observed != expected:
        raise ReconstructionAssuranceError(f"{field} content digest mismatch")


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ReconstructionAssuranceError("artifact is not canonical JSON data") from exc


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ReconstructionAssuranceError(f"{field} must be an object")
    return dict(value)


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReconstructionAssuranceError(f"{field} must be a list")
    return value


def _fields(value: Mapping[str, Any], expected: set[str] | frozenset[str], field: str) -> None:
    actual = set(value)
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        extra = sorted(actual - set(expected))
        raise ReconstructionAssuranceError(
            f"{field} fields differ; missing={missing}, extra={extra}"
        )


def _status(value: Any, field: str) -> AssuranceStatus:
    try:
        return AssuranceStatus(value)
    except (TypeError, ValueError) as exc:
        raise ReconstructionAssuranceError(
            f"{field} must be qualified, incomplete, or violated"
        ) from exc


def _nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReconstructionAssuranceError(f"{field} must be a non-empty string")
    return value


def _identifier(value: Any, field: str) -> str:
    result = _nonempty_string(value, field)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for character in result):
        raise ReconstructionAssuranceError(
            f"{field} must be a lowercase stable identifier"
        )
    return result


def _identifier_list(value: Any, field: str) -> list[str]:
    result = [
        _identifier(item, f"{field}[{index}]")
        for index, item in enumerate(_list(value, field))
    ]
    if len(set(result)) != len(result):
        raise ReconstructionAssuranceError(f"{field} contains duplicates")
    return sorted(result)


def _evidence_classes(value: Any, field: str) -> list[str]:
    result = _identifier_list(value, field)
    if not result:
        raise ReconstructionAssuranceError(f"{field} must not be empty")
    unknown = sorted(set(result) - _EVIDENCE_CLASSES)
    if unknown:
        raise ReconstructionAssuranceError(
            f"{field} contains unsupported evidence classes {unknown}"
        )
    return result


def _sha256(value: Any, field: str) -> str:
    result = _nonempty_string(value, field)
    if len(result) != _DIGEST_LENGTH or any(
        character not in "0123456789abcdef" for character in result
    ):
        raise ReconstructionAssuranceError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return result


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ReconstructionAssuranceError(f"{field} must be a boolean")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReconstructionAssuranceError(f"{field} must be a non-negative integer")
    return value


def _positive_int(value: Any, field: str) -> int:
    result = _nonnegative_int(value, field)
    if result == 0:
        raise ReconstructionAssuranceError(f"{field} must be positive")
    return result


def _nonnegative_number(value: Any, field: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ReconstructionAssuranceError(f"{field} must be a non-negative number")
    if value != value or value in {float("inf"), float("-inf")}:
        raise ReconstructionAssuranceError(f"{field} must be finite")
    return value


def _positive_number(value: Any, field: str) -> float | int:
    result = _nonnegative_number(value, field)
    if result == 0:
        raise ReconstructionAssuranceError(f"{field} must be positive")
    return result


def _digest_mapping(value: Any, fields: set[str] | frozenset[str], field: str) -> dict[str, str]:
    row = _object(value, field)
    _fields(row, fields, field)
    return {key: _sha256(row[key], f"{field}.{key}") for key in sorted(fields)}


def _count_mapping(value: Any, fields: set[str] | frozenset[str], field: str) -> dict[str, int]:
    row = _object(value, field)
    _fields(row, fields, field)
    return {
        key: _nonnegative_int(row[key], f"{field}.{key}")
        for key in sorted(fields)
    }


def _json_value(value: Any, field: str) -> Any:
    try:
        encoded = _canonical_json(value)
        return json.loads(encoded.decode("ascii"))
    except ReconstructionAssuranceError:
        raise
    except Exception as exc:  # pragma: no cover - defensive JSON boundary
        raise ReconstructionAssuranceError(f"{field} must be JSON data") from exc
