"""Build the canonical implementation ledger from generic lift artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .authority_bindings_v2 import BinaryBinding, UnitBinding, canonical_json_bytes
from .implementation_ledger_v2 import (
    ArtifactIdentityV2,
    CompletionProfileV2,
    ImplementationLedgerV2,
    ImplementationOwnerKindV2,
    ImplementationOwnerV2,
    UnitOwnershipRecordV2,
)
from .lift_qualification_v1 import (
    LiftQualificationV1,
    QualificationAssuranceClassV1,
    QualificationStatusV1,
    QualificationSubjectKindV1,
)
from .machine_ir_authority_v2 import build_machine_ir_authority_bindings
from .util import sha256_file


OWNERSHIP_LEDGER_REPORT_V2_FORMAT = (
    "spaghetti-extractor-implementation-ledger-report-v2"
)


class OwnershipLedgerV2Error(ValueError):
    """Lift artifacts cannot be combined into one exact ownership ledger."""


def _resolve(path: Path, filename: str) -> Path:
    return path / filename if path.is_dir() else path


def _read(path: Path, expected_format: str, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OwnershipLedgerV2Error(f"cannot read {context} {path}: {exc}") from exc
    if not isinstance(value, Mapping) or value.get("format") != expected_format:
        raise OwnershipLedgerV2Error(f"{context} has the wrong format")
    return value


def _machine_rows(path: Path) -> tuple[Mapping[str, Any], ...]:
    source = _resolve(path, "machine-ir.jsonl")
    rows: list[Mapping[str, Any]] = []
    try:
        with source.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                value = json.loads(line)
                if not isinstance(value, Mapping):
                    raise OwnershipLedgerV2Error(
                        f"machine-IR line {line_number} is not an object"
                    )
                rows.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise OwnershipLedgerV2Error(f"cannot read machine IR {source}: {exc}") from exc
    return tuple(rows)


def _identity(
    artifact_kind: str, artifact_id: str, payload: Any
) -> ArtifactIdentityV2:
    return ArtifactIdentityV2(
        artifact_kind,
        artifact_id,
        hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
    )


def _file_identity(
    artifact_kind: str, artifact_id: str, path: Path
) -> ArtifactIdentityV2:
    return ArtifactIdentityV2(artifact_kind, artifact_id, sha256_file(path))


def _source_owner(
    source_binding_path: Path,
    qualification_path: Path | None,
    profile: CompletionProfileV2,
) -> tuple[ImplementationOwnerV2, tuple[str, ...]]:
    source = _read(
        source_binding_path,
        "stage-b-source-project-binding-v1",
        "source-project binding",
    )
    program_id = source.get("program_id")
    if not isinstance(program_id, str) or not program_id:
        raise OwnershipLedgerV2Error("source-project binding has no program ID")
    coverage = source.get("coverage")
    if not isinstance(coverage, Mapping):
        raise OwnershipLedgerV2Error("source-project binding has no coverage")
    unit_ids = coverage.get("source_bound_unit_ids")
    if not isinstance(unit_ids, list) or any(
        not isinstance(item, str) or not item for item in unit_ids
    ):
        raise OwnershipLedgerV2Error("source-project unit inventory is malformed")
    implementation = _file_identity(
        "source-project-binding-v1", program_id, source_binding_path
    )
    qualification = None
    if qualification_path is not None:
        checked = LiftQualificationV1.parse(
            _read(
                qualification_path,
                "spaghetti-extractor-lift-qualification-v1",
                "source qualification",
            )
        )
        if (
            checked.subject_kind is not QualificationSubjectKindV1.SOURCE_PROJECT
            or checked.subject_id != program_id
            or checked.implementation_sha256 != implementation.sha256
            or checked.unit_ids != tuple(sorted(set(unit_ids)))
        ):
            raise OwnershipLedgerV2Error(
                "source qualification contradicts the exact source binding"
            )
        allowed_classes = {
            CompletionProfileV2.PORTABLE_APPLICATION: {
                QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
            },
            CompletionProfileV2.VALIDATION_QUALIFIED: {
                QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT,
                QualificationAssuranceClassV1.VALIDATION_BACKED_RECONSTRUCTION,
            },
            CompletionProfileV2.STATIC_BASELINE: set(),
        }[profile]
        if checked.assurance_class not in allowed_classes:
            raise OwnershipLedgerV2Error(
                "source qualification assurance class is not allowed by the "
                f"{profile.value} profile"
            )
        if checked.status is QualificationStatusV1.COMPLETE:
            qualification = _file_identity(
                "source-qualification-v1",
                checked.qualification_id,
                qualification_path,
            )
    return (
        ImplementationOwnerV2(
            ImplementationOwnerKindV2.PORTABLE_COMPONENT,
            implementation,
            qualification,
        ),
        tuple(sorted(set(unit_ids))),
    )


def _library_owners(
    linked_islands_path: Path,
    qualification_paths: Sequence[Path],
    profile: CompletionProfileV2,
) -> tuple[tuple[ImplementationOwnerV2, tuple[str, ...]], ...]:
    linked = _read(
        linked_islands_path,
        "stage-b-linked-island-manifest-v2",
        "linked-island manifest",
    )
    raw_islands = linked.get("islands")
    if not isinstance(raw_islands, list):
        raise OwnershipLedgerV2Error("linked-island inventory is malformed")
    qualifications: dict[str, tuple[LiftQualificationV1, Path]] = {}
    linked_runtime: tuple[LiftQualificationV1, Path] | None = None
    for path in qualification_paths:
        checked = LiftQualificationV1.parse(
            _read(
                path,
                "spaghetti-extractor-lift-qualification-v1",
                "library qualification",
            )
        )
        if checked.subject_kind is QualificationSubjectKindV1.LINKED_RUNTIME:
            if linked_runtime is not None:
                raise OwnershipLedgerV2Error(
                    "linked-runtime qualification is duplicated"
                )
            linked_runtime = (checked, path)
            continue
        if checked.subject_kind is not QualificationSubjectKindV1.LIBRARY_ISLAND:
            raise OwnershipLedgerV2Error(
                "library qualification has a non-library subject"
            )
        if checked.subject_id in qualifications:
            raise OwnershipLedgerV2Error(
                f"library qualification is duplicated: {checked.subject_id!r}"
            )
        qualifications[checked.subject_id] = (checked, path)
    non_application_units = tuple(
        sorted(
            str(unit_id)
            for raw in raw_islands
            if isinstance(raw, Mapping) and raw.get("kind") != "application"
            for unit_id in raw.get("unit_ids", [])
        )
    )
    aggregate_owner: ImplementationOwnerV2 | None = None
    if linked_runtime is not None:
        checked, qualification_path = linked_runtime
        if profile is not CompletionProfileV2.VALIDATION_QUALIFIED:
            raise OwnershipLedgerV2Error(
                "pinned runtime substitution is allowed only by the "
                "validation-qualified profile"
            )
        if any(
            isinstance(raw, Mapping) and raw.get("kind") == "unknown"
            for raw in raw_islands
        ):
            raise OwnershipLedgerV2Error(
                "linked-runtime qualification cannot cover unknown linked units"
            )
        if (
            checked.assurance_class
            is not QualificationAssuranceClassV1.PINNED_RUNTIME_SUBSTITUTION
            or checked.implementation_sha256 != sha256_file(linked_islands_path)
            or checked.unit_ids != non_application_units
        ):
            raise OwnershipLedgerV2Error(
                "linked-runtime qualification contradicts the exact linked "
                "unit universe"
            )
        implementation = _file_identity(
            "linked-runtime-substitution-v1",
            checked.subject_id,
            linked_islands_path,
        )
        aggregate_owner = ImplementationOwnerV2(
            ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION,
            implementation,
            (
                _file_identity(
                    "library-qualification-v1",
                    checked.qualification_id,
                    qualification_path,
                )
                if checked.status is QualificationStatusV1.COMPLETE
                else None
            ),
        )
    result: list[tuple[ImplementationOwnerV2, tuple[str, ...]]] = []
    for raw in raw_islands:
        if not isinstance(raw, Mapping) or raw.get("kind") == "application":
            continue
        island_id = raw.get("id")
        unit_ids = raw.get("unit_ids")
        if (
            not isinstance(island_id, str)
            or not island_id
            or not isinstance(unit_ids, list)
            or any(not isinstance(item, str) or not item for item in unit_ids)
        ):
            raise OwnershipLedgerV2Error("linked-island ownership is malformed")
        if aggregate_owner is not None:
            result.append((aggregate_owner, tuple(sorted(set(unit_ids)))))
            continue
        kind = (
            ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION
            if raw.get("kind") != "unknown"
            else ImplementationOwnerKindV2.UNASSIGNED
        )
        implementation = (
            _identity("library-substitution-v1", island_id, raw)
            if kind is ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION
            else None
        )
        qualification = None
        supplied = qualifications.pop(island_id, None)
        if supplied is not None:
            checked, qualification_path = supplied
            if implementation is None:
                raise OwnershipLedgerV2Error(
                    f"qualification names unrecognized library island {island_id!r}"
                )
            if (
                checked.assurance_class
                is not QualificationAssuranceClassV1.CHECKED_SEMANTIC_REFINEMENT
                or checked.implementation_sha256 != implementation.sha256
                or checked.unit_ids != tuple(sorted(set(unit_ids)))
            ):
                raise OwnershipLedgerV2Error(
                    f"library qualification for {island_id!r} contradicts its island"
                )
            if checked.status is QualificationStatusV1.COMPLETE:
                qualification = _file_identity(
                    "library-qualification-v1",
                    checked.qualification_id,
                    qualification_path,
                )
        result.append(
            (
                ImplementationOwnerV2(kind, implementation, qualification),
                tuple(sorted(set(unit_ids))),
            )
        )
    if qualifications:
        raise OwnershipLedgerV2Error(
            "library qualifications name absent islands: "
            + ", ".join(sorted(qualifications))
        )
    return tuple(result)


def build_implementation_ledger_v2(
    *,
    machine_ir: Path,
    profile: CompletionProfileV2,
    source_binding: Path | None = None,
    source_qualification: Path | None = None,
    linked_islands: Path | None = None,
    library_qualifications: Sequence[Path] = (),
    fallback_coverage: Path | None = None,
) -> ImplementationLedgerV2:
    """Derive one exact owner for every structural unit."""

    manifest_path = _resolve(machine_ir, "machine-ir-manifest.json")
    manifest = _read(manifest_path, "stage-a-machine-ir-v2", "machine-IR manifest")
    binary_row = manifest.get("binary")
    if not isinstance(binary_row, Mapping) or not isinstance(
        binary_row.get("sha256"), str
    ):
        raise OwnershipLedgerV2Error("machine-IR manifest has no PE digest")
    rows = _machine_rows(machine_ir)
    authority = build_machine_ir_authority_bindings(
        rows, pe_sha256=str(binary_row["sha256"])
    )
    binary = BinaryBinding.parse(authority["binary"])
    units = tuple(UnitBinding.parse(row) for row in authority["units"])
    units_by_id = {unit.unit_id: unit for unit in units}
    if len(units_by_id) != len(units):
        raise OwnershipLedgerV2Error("machine-IR structural unit IDs are duplicated")

    assignments: dict[str, ImplementationOwnerV2] = {}

    def assign(owner: ImplementationOwnerV2, unit_ids: Sequence[str]) -> None:
        for unit_id in unit_ids:
            if unit_id not in units_by_id:
                raise OwnershipLedgerV2Error(
                    f"ownership input names unknown unit {unit_id!r}"
                )
            existing = assignments.get(unit_id)
            if existing is not None and existing != owner:
                raise OwnershipLedgerV2Error(
                    f"unit {unit_id!r} has conflicting proposed owners"
                )
            assignments[unit_id] = owner

    if source_binding is not None:
        owner, unit_ids = _source_owner(
            _resolve(source_binding, "source-project-binding.json"),
            (
                None
                if source_qualification is None
                else _resolve(source_qualification, "lift-qualification-v1.json")
            ),
            profile,
        )
        assign(owner, unit_ids)
    if linked_islands is not None:
        for owner, unit_ids in _library_owners(
            _resolve(linked_islands, "linked-islands.json"),
            tuple(
                _resolve(path, "lift-qualification-v1.json")
                for path in library_qualifications
            ),
            profile,
        ):
            assign(owner, tuple(unit_id for unit_id in unit_ids if unit_id not in assignments))

    unclaimed = tuple(sorted(set(units_by_id) - set(assignments)))
    if unclaimed:
        if profile is CompletionProfileV2.STATIC_BASELINE:
            identity = (
                _file_identity(
                    "fallback-coverage-v3",
                    "machine-ir-fallback",
                    _resolve(fallback_coverage, "manifest.json"),
                )
                if fallback_coverage is not None
                else None
            )
            owner = ImplementationOwnerV2(
                ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
                identity,
                identity,
            )
        else:
            owner = ImplementationOwnerV2(
                ImplementationOwnerKindV2.UNASSIGNED, None, None
            )
        assign(owner, unclaimed)

    grouped: dict[ImplementationOwnerV2, list[UnitBinding]] = {}
    for unit_id, owner in assignments.items():
        grouped.setdefault(owner, []).append(units_by_id[unit_id])
    ownership = tuple(
        UnitOwnershipRecordV2.create(owner=owner, units=owner_units)
        for owner, owner_units in grouped.items()
    )
    return ImplementationLedgerV2.create(
        profile=profile,
        binary=binary,
        structural_units=units,
        ownership_records=ownership,
    )


def emit_implementation_ledger_v2(
    *,
    machine_ir: Path,
    profile: CompletionProfileV2,
    output_directory: Path,
    source_binding: Path | None = None,
    source_qualification: Path | None = None,
    linked_islands: Path | None = None,
    library_qualifications: Sequence[Path] = (),
    fallback_coverage: Path | None = None,
) -> dict[str, Any]:
    ledger = build_implementation_ledger_v2(
        machine_ir=machine_ir,
        profile=profile,
        source_binding=source_binding,
        source_qualification=source_qualification,
        linked_islands=linked_islands,
        library_qualifications=library_qualifications,
        fallback_coverage=fallback_coverage,
    )
    output_directory.mkdir(parents=True, exist_ok=False)
    (output_directory / "implementation-ledger-v2.json").write_text(
        ledger.to_json(), encoding="ascii"
    )
    grouped_issues: dict[tuple[str, str], list[Any]] = {}
    for issue in ledger.issues:
        grouped_issues.setdefault((issue.status.value, issue.code), []).append(issue)
    report = {
        "format": OWNERSHIP_LEDGER_REPORT_V2_FORMAT,
        "profile": profile.value,
        "status": ledger.status.value,
        "ledger_id": ledger.ledger_id,
        "structural_unit_count": len(ledger.structural_units),
        "ownership_record_count": len(ledger.ownership_records),
        "owners_by_kind": {
            kind.value: sum(
                len(record.units)
                for record in ledger.ownership_records
                if record.owner.kind is kind
            )
            for kind in ImplementationOwnerKindV2
        },
        "issue_count": len(ledger.issues),
        "primary_frontiers": [
            {
                "status": status,
                "code": code,
                "count": len(issues),
                "examples": [issue.to_payload() for issue in issues[:5]],
            }
            for (status, code), issues in sorted(grouped_issues.items())
        ],
    }
    (output_directory / "implementation-ledger-report-v2.json").write_bytes(
        canonical_json_bytes(report)
    )
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an exact implementation ledger")
    parser.add_argument("--machine-ir", type=Path, required=True)
    parser.add_argument(
        "--profile", choices=[row.value for row in CompletionProfileV2], required=True
    )
    parser.add_argument("--source-binding", type=Path)
    parser.add_argument("--source-qualification", type=Path)
    parser.add_argument("--linked-islands", type=Path)
    parser.add_argument("--library-qualification", type=Path, action="append", default=[])
    parser.add_argument("--fallback-coverage", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_implementation_ledger_v2(
        machine_ir=arguments.machine_ir,
        profile=CompletionProfileV2(arguments.profile),
        source_binding=arguments.source_binding,
        source_qualification=arguments.source_qualification,
        linked_islands=arguments.linked_islands,
        library_qualifications=arguments.library_qualification,
        fallback_coverage=arguments.fallback_coverage,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
