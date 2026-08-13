"""Qualify a validation-backed portable source reconstruction.

This adapter deliberately consumes explicit source-interface, dependency, and
candidate-only behavior artifacts.  A diagnostic audit status is never an
authority input, and a complete validation-backed qualification never claims
machine-to-source semantic equivalence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .lift_qualification_v1 import (
    LiftQualificationV1,
    QualificationAssuranceClassV1,
    QualificationEvidenceV1,
    QualificationStatusV1,
    QualificationSubjectKindV1,
)
from .util import sha256_file


_REQUIRED_ASSUMPTIONS = frozenset(
    {
        "integration_coverage_is_not_exhaustive",
        "machine_to_source_component_equivalence_not_proven",
    }
)


class SourceQualificationV1Error(ValueError):
    """Source qualification inputs are malformed or mutually stale."""


def _resolve(path: Path, filename: str) -> Path:
    candidate = path / filename if path.is_dir() else path
    if not candidate.is_file():
        raise SourceQualificationV1Error(
            f"required artifact is missing: {candidate}"
        )
    return candidate


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _read(
    path: Path,
    expected_format: str,
    context: str,
    *,
    hash_field: str,
) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceQualificationV1Error(
            f"cannot read {context} {path}: {exc}"
        ) from exc
    if not isinstance(value, Mapping) or value.get("format") != expected_format:
        raise SourceQualificationV1Error(f"{context} has the wrong format")
    core = copy.deepcopy(dict(value))
    observed = core.pop(hash_field, None)
    if observed != _canonical_sha256(core):
        raise SourceQualificationV1Error(
            f"{context} has a stale {hash_field}"
        )
    return value


def _status(*, complete: bool, violated: bool = False) -> QualificationStatusV1:
    if violated:
        return QualificationStatusV1.VIOLATED
    return (
        QualificationStatusV1.COMPLETE
        if complete
        else QualificationStatusV1.INCOMPLETE
    )


def _evidence(
    evidence_class: str,
    *,
    artifact_kind: str,
    artifact_id: str,
    path: Path,
    complete: bool,
    violated: bool = False,
) -> QualificationEvidenceV1:
    return QualificationEvidenceV1(
        evidence_class=evidence_class,
        artifact_kind=artifact_kind,
        artifact_id=artifact_id,
        artifact_sha256=sha256_file(path),
        status=_status(complete=complete, violated=violated),
    )


def build_source_qualification_v1(
    *,
    source_binding: Path,
    component_assurance: Path,
    source_call_report: Path,
    candidate_dependency_audit: Path,
) -> LiftQualificationV1:
    binding_path = _resolve(source_binding, "source-project-binding.json")
    assurance_path = _resolve(
        component_assurance, "source-component-assurance.json"
    )
    call_report_path = _resolve(
        source_call_report, "source-call-binding-report.json"
    )
    dependency_path = _resolve(
        candidate_dependency_audit, "candidate-dependency-audit.json"
    )
    binding = _read(
        binding_path,
        "stage-b-source-project-binding-v1",
        "source-project binding",
        hash_field="binding_sha256",
    )
    assurance = _read(
        assurance_path,
        "stage-b-source-component-assurance-v1",
        "source-component assurance",
        hash_field="assurance_sha256",
    )
    call_report = _read(
        call_report_path,
        "stage-b-source-call-binding-report-v1",
        "source-call binding report",
        hash_field="report_sha256",
    )
    dependency = _read(
        dependency_path,
        "stage-b-candidate-dependency-audit-v1",
        "candidate dependency audit",
        hash_field="audit_sha256",
    )

    program_id = binding.get("program_id")
    coverage = binding.get("coverage")
    if (
        not isinstance(program_id, str)
        or not program_id
        or not isinstance(coverage, Mapping)
    ):
        raise SourceQualificationV1Error(
            "source binding has no program or coverage"
        )
    unit_ids = coverage.get("source_bound_unit_ids")
    if not isinstance(unit_ids, list) or not unit_ids or any(
        not isinstance(item, str) or not item for item in unit_ids
    ):
        raise SourceQualificationV1Error(
            "source binding has malformed unit coverage"
        )

    assurance_bindings = assurance.get("bindings")
    call_bindings = call_report.get("bindings")
    dependency_bindings = dependency.get("bindings")
    if not all(
        isinstance(value, Mapping)
        for value in (
            assurance_bindings,
            call_bindings,
            dependency_bindings,
        )
    ):
        raise SourceQualificationV1Error(
            "source qualification evidence has malformed bindings"
        )
    assert isinstance(assurance_bindings, Mapping)
    assert isinstance(call_bindings, Mapping)
    assert isinstance(dependency_bindings, Mapping)
    if (
        assurance.get("program_id") != program_id
        or assurance_bindings.get("source_project_binding_sha256")
        != binding.get("binding_sha256")
        or assurance_bindings.get("source_call_report_sha256")
        != call_report.get("report_sha256")
        or assurance_bindings.get("candidate_binary_sha256")
        != dependency_bindings.get("candidate_sha256")
    ):
        raise SourceQualificationV1Error(
            "source qualification evidence does not bind one candidate project"
        )
    if assurance.get("equivalence_status") != "not_proven":
        raise SourceQualificationV1Error(
            "validation-backed assurance overstates semantic equivalence"
        )
    assurance_authority = assurance.get("authority")
    if not isinstance(assurance_authority, Mapping) or (
        assurance_authority.get("proves_equivalence") is not False
        or assurance_authority.get("can_authorize_machine_override") is not False
    ):
        raise SourceQualificationV1Error(
            "source-component assurance has invalid authority metadata"
        )

    reviewed = coverage.get("reviewed_scope")
    boundary_complete = (
        isinstance(reviewed, Mapping)
        and reviewed.get("fully_source_bound") is True
        and reviewed.get("remaining_machine_units") == 0
    )
    counts = assurance.get("counts")
    if not isinstance(counts, Mapping):
        raise SourceQualificationV1Error(
            "source-component assurance has no counts"
        )
    behavior_complete = (
        assurance.get("status") == "behavior_validated"
        and counts.get("components") == len(binding.get("islands", []))
        and counts.get("behavior_validated") == counts.get("components")
        and counts.get("incomplete_or_violated") == 0
    )
    behavior_violated = assurance.get("status") == "violated"

    call_counts = call_report.get("counts")
    if not isinstance(call_counts, Mapping):
        raise SourceQualificationV1Error("source-call report has no counts")
    call_issues = call_report.get("issues")
    if not isinstance(call_issues, list) or any(
        not isinstance(row, Mapping) for row in call_issues
    ):
        raise SourceQualificationV1Error(
            "source-call report has malformed issues"
        )
    source_calls_complete = (
        call_counts.get("source_calls") == counts.get("source_calls")
        and call_counts.get("source_calls") == counts.get("covered_source_calls")
        and call_counts.get("unbound_source_local") == 0
        and all(
            row.get("status") == "incomplete"
            and row.get("code") == "call_plan_not_ready"
            for row in call_issues
        )
    )
    source_calls_violated = (
        call_report.get("status") == "violated"
        or any(row.get("status") == "violated" for row in call_issues)
    )

    dependency_complete = (
        dependency.get("status") == "pass"
        and isinstance(dependency.get("counts"), Mapping)
        and dependency["counts"].get("unexpected") == 0
    )
    dependency_violated = dependency.get("status") == "violated"
    assumptions = assurance.get("accepted_assumptions")
    assumptions_complete = (
        isinstance(assumptions, list)
        and frozenset(assumptions) == _REQUIRED_ASSUMPTIONS
    )

    return LiftQualificationV1.create(
        subject_kind=QualificationSubjectKindV1.SOURCE_PROJECT,
        assurance_class=(
            QualificationAssuranceClassV1.VALIDATION_BACKED_RECONSTRUCTION
        ),
        subject_id=program_id,
        implementation_sha256=sha256_file(binding_path),
        unit_ids=tuple(unit_ids),
        evidence=(
            _evidence(
                "boundary_coverage",
                artifact_kind="source-project-binding-v1",
                artifact_id=program_id,
                path=binding_path,
                complete=boundary_complete,
            ),
            _evidence(
                "candidate_behavior",
                artifact_kind="source-component-assurance-v1",
                artifact_id=program_id,
                path=assurance_path,
                complete=behavior_complete,
                violated=behavior_violated,
            ),
            _evidence(
                "dependency_envelope",
                artifact_kind="candidate-dependency-audit-v1",
                artifact_id=program_id,
                path=dependency_path,
                complete=dependency_complete,
                violated=dependency_violated,
            ),
            _evidence(
                "reconstruction_assumptions",
                artifact_kind="source-component-assurance-v1",
                artifact_id=program_id,
                path=assurance_path,
                complete=assumptions_complete,
            ),
            _evidence(
                "source_call_coverage",
                artifact_kind="source-call-binding-report-v1",
                artifact_id=program_id,
                path=call_report_path,
                complete=source_calls_complete,
                violated=source_calls_violated,
            ),
        ),
    )


def emit_source_qualification_v1(
    *,
    source_binding: Path,
    component_assurance: Path,
    source_call_report: Path,
    candidate_dependency_audit: Path,
    output_directory: Path,
) -> LiftQualificationV1:
    qualification = build_source_qualification_v1(
        source_binding=source_binding,
        component_assurance=component_assurance,
        source_call_report=source_call_report,
        candidate_dependency_audit=candidate_dependency_audit,
    )
    output_directory.mkdir(parents=True, exist_ok=False)
    (output_directory / "lift-qualification-v1.json").write_text(
        qualification.to_json(), encoding="ascii"
    )
    return qualification


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify a validation-backed portable source project"
    )
    parser.add_argument("--source-binding", type=Path, required=True)
    parser.add_argument("--component-assurance", type=Path, required=True)
    parser.add_argument("--source-call-report", type=Path, required=True)
    parser.add_argument(
        "--candidate-dependency-audit", type=Path, required=True
    )
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_source_qualification_v1(
        source_binding=arguments.source_binding,
        component_assurance=arguments.component_assurance,
        source_call_report=arguments.source_call_report,
        candidate_dependency_audit=arguments.candidate_dependency_audit,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
