"""Qualify one validation-backed substitution for a pinned linked runtime."""

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


RUNTIME_SUBSTITUTION_PLAN_FORMAT = (
    "spaghetti-extractor-runtime-substitution-plan-v1"
)
_REQUIRED_ASSUMPTIONS = frozenset(
    {
        "candidate_validation_is_not_exhaustive",
        "linked_runtime_machine_to_source_equivalence_not_proven",
    }
)


class RuntimeQualificationV1Error(ValueError):
    """Pinned-runtime qualification inputs are malformed or stale."""


def _resolve(path: Path, filename: str) -> Path:
    candidate = path / filename if path.is_dir() else path
    if not candidate.is_file():
        raise RuntimeQualificationV1Error(
            f"required artifact is missing: {candidate}"
        )
    return candidate


def _read(path: Path, expected_format: str, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeQualificationV1Error(
            f"cannot read {context} {path}: {exc}"
        ) from exc
    if not isinstance(value, Mapping) or value.get("format") != expected_format:
        raise RuntimeQualificationV1Error(f"{context} has the wrong format")
    return value


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _check_self_hash(
    value: Mapping[str, Any], field: str, context: str
) -> None:
    core = copy.deepcopy(dict(value))
    observed = core.pop(field, None)
    if observed != _canonical_sha256(core):
        raise RuntimeQualificationV1Error(f"{context} has a stale {field}")


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
        status=(
            QualificationStatusV1.VIOLATED
            if violated
            else QualificationStatusV1.COMPLETE
            if complete
            else QualificationStatusV1.INCOMPLETE
        ),
    )


def build_runtime_qualification_v1(
    *,
    linked_islands: Path,
    runtime_lock: Path,
    candidate_dependency_audit: Path,
    component_assurance: Path,
    substitution_plan: Path,
) -> LiftQualificationV1:
    linked_path = _resolve(linked_islands, "linked-islands.json")
    lock_path = _resolve(runtime_lock, "runtime-lock-v1.json")
    dependency_path = _resolve(
        candidate_dependency_audit, "candidate-dependency-audit.json"
    )
    assurance_path = _resolve(
        component_assurance, "source-component-assurance.json"
    )
    plan_path = _resolve(substitution_plan, "runtime-substitution.json")

    linked = _read(
        linked_path,
        "stage-b-linked-island-manifest-v2",
        "linked-island manifest",
    )
    dependency = _read(
        dependency_path,
        "stage-b-candidate-dependency-audit-v1",
        "candidate dependency audit",
    )
    assurance = _read(
        assurance_path,
        "stage-b-source-component-assurance-v1",
        "source-component assurance",
    )
    lock = _read(
        lock_path,
        "spaghetti-extractor-runtime-lock-v1",
        "runtime lock",
    )
    plan = _read(
        plan_path,
        RUNTIME_SUBSTITUTION_PLAN_FORMAT,
        "runtime substitution plan",
    )
    _check_self_hash(linked, "manifest_sha256", "linked-island manifest")
    _check_self_hash(dependency, "audit_sha256", "candidate dependency audit")
    _check_self_hash(assurance, "assurance_sha256", "component assurance")

    runtime_id = plan.get("runtime_id")
    assumptions = plan.get("accepted_assumptions")
    if not isinstance(runtime_id, str) or not runtime_id:
        raise RuntimeQualificationV1Error(
            "runtime substitution plan has no runtime ID"
        )
    assumptions_complete = (
        isinstance(assumptions, list)
        and frozenset(assumptions) == _REQUIRED_ASSUMPTIONS
    )
    raw_islands = linked.get("islands")
    if not isinstance(raw_islands, list) or any(
        not isinstance(row, Mapping) for row in raw_islands
    ):
        raise RuntimeQualificationV1Error(
            "linked-island manifest has malformed islands"
        )
    unknown = [row for row in raw_islands if row.get("kind") == "unknown"]
    units = tuple(
        sorted(
            str(unit_id)
            for row in raw_islands
            if row.get("kind") != "application"
            for unit_id in row.get("unit_ids", [])
        )
    )
    if not units:
        raise RuntimeQualificationV1Error(
            "linked runtime owns no structural units"
        )
    dependency_bindings = dependency.get("bindings")
    assurance_bindings = assurance.get("bindings")
    if not isinstance(dependency_bindings, Mapping) or not isinstance(
        assurance_bindings, Mapping
    ):
        raise RuntimeQualificationV1Error(
            "runtime evidence has malformed candidate bindings"
        )
    if (
        dependency_bindings.get("candidate_sha256")
        != assurance_bindings.get("candidate_binary_sha256")
    ):
        raise RuntimeQualificationV1Error(
            "runtime evidence binds different candidates"
        )
    dependency_complete = (
        dependency.get("status") == "pass"
        and isinstance(dependency.get("counts"), Mapping)
        and dependency["counts"].get("unexpected") == 0
    )
    behavior_complete = assurance.get("status") == "behavior_validated"
    lock_complete = lock.get("status") == "complete"
    return LiftQualificationV1.create(
        subject_kind=QualificationSubjectKindV1.LINKED_RUNTIME,
        assurance_class=(
            QualificationAssuranceClassV1.PINNED_RUNTIME_SUBSTITUTION
        ),
        subject_id=runtime_id,
        implementation_sha256=sha256_file(linked_path),
        unit_ids=units,
        evidence=(
            _evidence(
                "candidate_behavior",
                artifact_kind="source-component-assurance-v1",
                artifact_id=runtime_id,
                path=assurance_path,
                complete=behavior_complete,
                violated=assurance.get("status") == "violated",
            ),
            _evidence(
                "dependency_envelope",
                artifact_kind="candidate-dependency-audit-v1",
                artifact_id=runtime_id,
                path=dependency_path,
                complete=dependency_complete,
                violated=dependency.get("status") == "violated",
            ),
            _evidence(
                "linked_unit_coverage",
                artifact_kind="linked-island-manifest-v2",
                artifact_id=runtime_id,
                path=linked_path,
                complete=not unknown and linked.get("status") == "classified",
            ),
            _evidence(
                "reconstruction_assumptions",
                artifact_kind="runtime-substitution-plan-v1",
                artifact_id=runtime_id,
                path=plan_path,
                complete=assumptions_complete,
            ),
            _evidence(
                "runtime_lock",
                artifact_kind="runtime-lock-v1",
                artifact_id=runtime_id,
                path=lock_path,
                complete=lock_complete,
            ),
        ),
    )


def emit_runtime_qualification_v1(
    *, output_directory: Path, **arguments: Any
) -> LiftQualificationV1:
    qualification = build_runtime_qualification_v1(**arguments)
    output_directory.mkdir(parents=True, exist_ok=False)
    (output_directory / "lift-qualification-v1.json").write_text(
        qualification.to_json(), encoding="ascii"
    )
    return qualification


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify one validation-backed pinned runtime"
    )
    parser.add_argument("--linked-islands", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument(
        "--candidate-dependency-audit", type=Path, required=True
    )
    parser.add_argument("--component-assurance", type=Path, required=True)
    parser.add_argument("--substitution-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_runtime_qualification_v1(
        linked_islands=arguments.linked_islands,
        runtime_lock=arguments.runtime_lock,
        candidate_dependency_audit=arguments.candidate_dependency_audit,
        component_assurance=arguments.component_assurance,
        substitution_plan=arguments.substitution_plan,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
