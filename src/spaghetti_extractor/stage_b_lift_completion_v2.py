"""Assemble one fail-closed receipt for a target lifting workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .artifact_set_v3 import (
    ArtifactInputReaderV3,
    ArtifactSetReaderV3,
    open_artifact_reader_v3,
)
from .authority_bindings_v2 import canonical_json_bytes
from .implementation_ledger_v2 import (
    ArtifactIdentityV2,
    CompletionProfileV2,
    CompletionStatusV2,
    ImplementationLedgerV2,
)
from .lift_completion_receipt_v2 import (
    CandidateIdentityV2,
    CandidatePlatformV2,
    CompletionEvidenceV2,
    FinalAuthorityEvidenceV2,
    LiftCompletionReceiptV2,
    ValidationEvidenceV2,
)
from .util import sha256_file


LIFT_COMPLETION_REPORT_V2_FORMAT = (
    "spaghetti-extractor-lift-completion-report-v2"
)


class LiftCompletionAdapterError(ValueError):
    """Exact workflow artifacts cannot be joined into one receipt."""


def _resolve(path: Path, filename: str) -> Path:
    candidate = path / filename if path.is_dir() else path
    if not candidate.is_file():
        raise LiftCompletionAdapterError(f"required artifact is missing: {candidate}")
    return candidate


def _artifact_root(path: Path) -> Path:
    if (path / "manifest.json").is_file():
        return path
    if (path / "artifact" / "manifest.json").is_file():
        return path / "artifact"
    raise LiftCompletionAdapterError(f"not an artifact-set-v3 output: {path}")


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiftCompletionAdapterError(f"cannot read {context} {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise LiftCompletionAdapterError(f"{context} is not a JSON object")
    return value


def _completion_status(value: Any, context: str) -> CompletionStatusV2:
    try:
        return CompletionStatusV2(value)
    except (TypeError, ValueError) as exc:
        raise LiftCompletionAdapterError(f"{context} has invalid status {value!r}") from exc


def _artifact_status(reader: ArtifactInputReaderV3) -> CompletionStatusV2:
    statuses: list[CompletionStatusV2] = []
    for record in reader.iter_records():
        value = record.value.to_value()
        if not isinstance(value, Mapping) or "status" not in value:
            continue
        statuses.append(_completion_status(value["status"], record.record_id))
    if not statuses:
        return CompletionStatusV2.INCOMPLETE
    if CompletionStatusV2.VIOLATED in statuses:
        return CompletionStatusV2.VIOLATED
    if CompletionStatusV2.INCOMPLETE in statuses:
        return CompletionStatusV2.INCOMPLETE
    return CompletionStatusV2.COMPLETE


def _artifact_identity(
    reader: ArtifactInputReaderV3, *, artifact_kind: str | None = None
) -> ArtifactIdentityV2:
    return ArtifactIdentityV2(
        artifact_kind or reader.manifest.artifact_kind,
        reader.manifest.artifact_id,
        reader.manifest_sha256,
    )


def _final_authority(path: Path) -> FinalAuthorityEvidenceV2:
    reader = ArtifactSetReaderV3(_artifact_root(path))
    if reader.manifest.artifact_kind != "final-authority-v3":
        raise LiftCompletionAdapterError("final authority artifact has the wrong kind")
    records = tuple(reader.iter_records())
    if len(records) != 1:
        raise LiftCompletionAdapterError("final authority must contain exactly one record")
    value = records[0].value.to_value()
    if not isinstance(value, Mapping):
        raise LiftCompletionAdapterError("final authority record is malformed")
    binary = value.get("binary")
    if not isinstance(binary, Mapping) or not isinstance(binary.get("pe_sha256"), str):
        raise LiftCompletionAdapterError("final authority lacks its PE binding")
    status = _completion_status(value.get("status"), "final authority")
    authorizing = value.get("authorizing")
    if not isinstance(authorizing, bool):
        raise LiftCompletionAdapterError("final authority decision is not Boolean")
    return FinalAuthorityEvidenceV2(
        identity=_artifact_identity(reader),
        status=status,
        authorizing=authorizing,
        original_pe_sha256=binary["pe_sha256"],
    )


def _fallback(path: Path) -> CompletionEvidenceV2:
    reader = open_artifact_reader_v3(path)
    if reader.manifest.artifact_kind != "fallback-coverage-v3":
        raise LiftCompletionAdapterError("fallback coverage artifact has the wrong kind")
    return CompletionEvidenceV2(_artifact_identity(reader), _artifact_status(reader))


def _runtime_lock(path: Path) -> CompletionEvidenceV2:
    source = _resolve(path, "runtime-lock-v1.json")
    value = _read_json(source, "runtime lock")
    if value.get("format") != "spaghetti-extractor-runtime-lock-v1":
        raise LiftCompletionAdapterError("runtime lock has the wrong format")
    lock_id = value.get("lock_id")
    if not isinstance(lock_id, str) or not lock_id:
        raise LiftCompletionAdapterError("runtime lock has no stable ID")
    return CompletionEvidenceV2(
        ArtifactIdentityV2("runtime-lock-v1", lock_id, sha256_file(source)),
        _completion_status(value.get("status"), "runtime lock"),
    )


def _candidate(path: Path) -> CandidateIdentityV2:
    source = _resolve(path, "portable-c-candidate-v1.json")
    value = _read_json(source, "portable candidate")
    if value.get("format") != "spaghetti-extractor-portable-c-candidate-v1":
        raise LiftCompletionAdapterError("portable candidate has the wrong format")
    output = value.get("output")
    if not isinstance(output, Mapping):
        raise LiftCompletionAdapterError("portable candidate has no output binding")
    platform = CandidatePlatformV2(value.get("platform"))
    architecture = value.get("architecture")
    target_triple = value.get("target_triple")
    source_sha = value.get("source_project_sha256")
    source_binding_id = value.get("source_project_binding_sha256")
    runtime_sha = value.get("runtime_lock_sha256")
    binary_sha = output.get("sha256")
    if not all(
        isinstance(row, str) and row
        for row in (
            architecture,
            target_triple,
            source_sha,
            source_binding_id,
            runtime_sha,
            binary_sha,
        )
    ):
        raise LiftCompletionAdapterError("portable candidate binding is incomplete")
    root = source.parent.resolve()
    relative_binary = output.get("path")
    if not isinstance(relative_binary, str) or not relative_binary:
        raise LiftCompletionAdapterError("portable candidate has no binary path")
    binary = (root / relative_binary).resolve()
    binding = (
        root / "share/spaghetti-extractor/source-project-binding.json"
    ).resolve()
    runtime_lock = (
        root / "share/spaghetti-extractor/runtime-lock-v1.json"
    ).resolve()
    for checked, context in (
        (binary, "candidate binary"),
        (binding, "source-project binding"),
        (runtime_lock, "runtime lock"),
    ):
        try:
            checked.relative_to(root)
        except ValueError as exc:
            raise LiftCompletionAdapterError(
                f"portable {context} escapes its build"
            ) from exc
        if not checked.is_file():
            raise LiftCompletionAdapterError(f"portable {context} is missing")
    if (
        sha256_file(binary) != binary_sha
        or output.get("bytes") != binary.stat().st_size
        or sha256_file(binding) != source_sha
        or sha256_file(runtime_lock) != runtime_sha
    ):
        raise LiftCompletionAdapterError(
            "portable candidate content differs from its manifest"
        )
    binding_value = _read_json(binding, "candidate source-project binding")
    binding_core = dict(binding_value)
    observed_binding_id = binding_core.pop("binding_sha256", None)
    checked_binding_id = hashlib.sha256(
        canonical_json_bytes(binding_core)
    ).hexdigest()
    if (
        binding_value.get("format") != "stage-b-source-project-binding-v1"
        or observed_binding_id != checked_binding_id
        or observed_binding_id != source_binding_id
    ):
        raise LiftCompletionAdapterError(
            "portable candidate source-project identity is stale"
        )
    manifest_sha = sha256_file(source)
    return CandidateIdentityV2(
        identity=ArtifactIdentityV2(
            "portable-c-candidate-v1",
            f"{platform.value}:{target_triple}:{binary_sha}",
            manifest_sha,
        ),
        platform=platform,
        architecture=architecture,
        target_triple=target_triple,
        binary_sha256=binary_sha,
        build_manifest_sha256=manifest_sha,
        source_project_sha256=source_sha,
        runtime_lock_sha256=runtime_sha,
    )


def _qualification(path: Path, expected_kind: str) -> CompletionEvidenceV2:
    source = path
    if path.is_dir():
        candidates = tuple(sorted(path.glob("*.json")))
        if len(candidates) != 1:
            raise LiftCompletionAdapterError(
                f"qualification directory must contain one JSON file: {path}"
            )
        source = candidates[0]
    value = _read_json(source, "qualification")
    artifact_id = value.get("qualification_id") or value.get("id")
    if not isinstance(artifact_id, str) or not artifact_id:
        raise LiftCompletionAdapterError("qualification has no stable ID")
    return CompletionEvidenceV2(
        ArtifactIdentityV2(expected_kind, artifact_id, sha256_file(source)),
        _completion_status(value.get("status"), "qualification"),
    )


def _validation(path: Path) -> ValidationEvidenceV2:
    source = _resolve(path, "candidate-validation-v1.json")
    value = _read_json(source, "candidate validation")
    if value.get("format") != "spaghetti-extractor-candidate-validation-v1":
        raise LiftCompletionAdapterError(
            "candidate validation has the wrong format"
        )
    validation_id = value.get("validation_id")
    pe32_sha = value.get("pe32_candidate_sha256")
    non_x86_sha = value.get("non_x86_candidate_sha256")
    if not all(
        isinstance(row, str) and row
        for row in (validation_id, pe32_sha, non_x86_sha)
    ):
        raise LiftCompletionAdapterError(
            "candidate validation binding is incomplete"
        )
    return ValidationEvidenceV2(
        identity=ArtifactIdentityV2(
            "candidate-validation-v1", validation_id, sha256_file(source)
        ),
        status=_completion_status(value.get("status"), "candidate validation"),
        pe32_candidate_sha256=pe32_sha,
        non_x86_candidate_sha256=non_x86_sha,
    )


def build_lift_completion_receipt_v2(
    *,
    profile: CompletionProfileV2,
    final_authority: Path,
    fallback_coverage: Path,
    implementation_ledger: Path,
    runtime_lock: Path,
    pe32_candidate: Path | None = None,
    non_x86_candidate: Path | None = None,
    source_qualifications: Sequence[Path] = (),
    library_qualifications: Sequence[Path] = (),
    validation: Path | None = None,
) -> LiftCompletionReceiptV2:
    ledger_path = _resolve(implementation_ledger, "implementation-ledger-v2.json")
    ledger = ImplementationLedgerV2.parse(
        _read_json(ledger_path, "implementation ledger")
    )
    return LiftCompletionReceiptV2.create(
        profile=profile,
        final_authority=_final_authority(final_authority),
        fallback_coverage=_fallback(fallback_coverage),
        implementation_ledger=ledger.to_binding(),
        source_qualifications=tuple(
            _qualification(path, "source-qualification-v1")
            for path in source_qualifications
        ),
        library_qualifications=tuple(
            _qualification(path, "library-qualification-v1")
            for path in library_qualifications
        ),
        runtime_lock=_runtime_lock(runtime_lock),
        pe32_candidate=(None if pe32_candidate is None else _candidate(pe32_candidate)),
        non_x86_candidate=(
            None if non_x86_candidate is None else _candidate(non_x86_candidate)
        ),
        validation=None if validation is None else _validation(validation),
    )


def emit_lift_completion_receipt_v2(
    *,
    output_directory: Path,
    authority_diagnostics: Path | None = None,
    **arguments: Any,
) -> dict[str, Any]:
    receipt = build_lift_completion_receipt_v2(**arguments)
    output_directory.mkdir(parents=True, exist_ok=False)
    (output_directory / "lift-completion-receipt-v2.json").write_text(
        receipt.to_json(), encoding="ascii"
    )
    grouped = Counter((issue.status.value, issue.code) for issue in receipt.issues)
    authority_summary: dict[str, Any] | None = None
    if authority_diagnostics is not None:
        diagnostics = _read_json(
            _resolve(authority_diagnostics, "authority-diagnostics-v3.json"),
            "authority diagnostics",
        )
        raw_frontiers = diagnostics.get("primary_frontiers", [])
        if not isinstance(raw_frontiers, list):
            raise LiftCompletionAdapterError(
                "authority diagnostics has malformed primary frontiers"
            )
        groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
        for raw in raw_frontiers:
            if not isinstance(raw, Mapping):
                raise LiftCompletionAdapterError(
                    "authority diagnostics contains a malformed frontier"
                )
            key = (
                str(raw.get("status", "incomplete")),
                str(raw.get("family", "unknown")),
                str(raw.get("code", "unknown")),
            )
            groups.setdefault(key, []).append(raw)
        authority_summary = {
            "status": diagnostics.get("status"),
            "authorizing": diagnostics.get("authorizing") is True,
            "counts": diagnostics.get("counts"),
            "frontier_groups": [
                {
                    "status": status,
                    "family": family,
                    "code": code,
                    "count": len(rows),
                    "examples": [
                        {
                            "record_id": row.get("record_id"),
                            "source_location": row.get("source_location"),
                        }
                        for row in rows[:5]
                    ],
                }
                for (status, family, code), rows in sorted(groups.items())
            ],
        }
    ledger_report_path = _resolve(
        arguments["implementation_ledger"],
        "implementation-ledger-report-v2.json",
    )
    ledger_report = _read_json(ledger_report_path, "implementation ledger report")
    report = {
        "format": LIFT_COMPLETION_REPORT_V2_FORMAT,
        "profile": receipt.profile.value,
        "status": receipt.status.value,
        "authorizing": receipt.authorizing,
        "receipt_id": receipt.receipt_id,
        "primary_frontiers": [
            {"status": status, "code": code, "count": count}
            for (status, code), count in sorted(grouped.items())
        ],
        "issue_count": len(receipt.issues),
        "authority": authority_summary,
        "ownership": {
            "status": ledger_report.get("status"),
            "owners_by_kind": ledger_report.get("owners_by_kind"),
            "primary_frontiers": ledger_report.get("primary_frontiers"),
        },
    }
    (output_directory / "lift-completion-report-v2.json").write_bytes(
        canonical_json_bytes(report)
    )
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assemble a checked lift receipt")
    parser.add_argument("--profile", choices=[row.value for row in CompletionProfileV2], required=True)
    parser.add_argument("--final-authority", type=Path, required=True)
    parser.add_argument("--fallback-coverage", type=Path, required=True)
    parser.add_argument("--implementation-ledger", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--authority-diagnostics", type=Path)
    parser.add_argument("--pe32-candidate", type=Path)
    parser.add_argument("--non-x86-candidate", type=Path)
    parser.add_argument("--source-qualification", type=Path, action="append", default=[])
    parser.add_argument("--library-qualification", type=Path, action="append", default=[])
    parser.add_argument("--validation", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_lift_completion_receipt_v2(
        output_directory=arguments.out,
        authority_diagnostics=arguments.authority_diagnostics,
        profile=CompletionProfileV2(arguments.profile),
        final_authority=arguments.final_authority,
        fallback_coverage=arguments.fallback_coverage,
        implementation_ledger=arguments.implementation_ledger,
        runtime_lock=arguments.runtime_lock,
        pe32_candidate=arguments.pe32_candidate,
        non_x86_candidate=arguments.non_x86_candidate,
        source_qualifications=arguments.source_qualification,
        library_qualifications=arguments.library_qualification,
        validation=arguments.validation,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
