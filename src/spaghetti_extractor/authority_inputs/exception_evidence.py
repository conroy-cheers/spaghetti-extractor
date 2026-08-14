"""Generate replayable generic exceptional-transition evidence.

The provider never executes the input binary.  It binds exact machine-IR
faults to the checked semantic index, proves only a small constant-expression
fragment locally, and otherwise relies on an explicit bounded launch profile
to classify supported unhandled synchronous processor faults as observable
process termination.  Unsupported predicates, handlers, and fault kinds stay
incomplete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ..authority._schema import mapping, sequence, text, uint
from ..authority.authority_common import PrimaryBlockerV3
from ..authority.exceptional_transitions import (
    EXCEPTION_CLOSURE_CERTIFICATE_V3,
    EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
    EXCEPTION_EVIDENCE_CODEC_V3,
    LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
    TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1,
    ExceptionEvidenceV3,
    checked_static_boolean_v3,
    exceptional_transition_id_v3,
)
from ..authority.semantic_index import SEMANTIC_INDEX_CODEC_V3
from ..artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    open_artifact_reader_v3,
)


EXCEPTION_EVIDENCE_REPORT_V3 = (
    "spaghetti-extractor-exception-evidence-report-v3"
)

_LAUNCH_ASSUMPTIONS = frozenset(
    {"argv", "environment", "fs", "iat", "initial_stack", "relocations"}
)
_FEATURES = frozenset(
    {
        "direct_syscalls",
        "executable_writes",
        "threads",
        "unknown_async_callbacks",
        "unmodelled_seh",
    }
)
_TERMINAL_FAULT_KINDS = frozenset({"divide_error"})


class ExceptionEvidenceProviderV3Error(ValueError):
    """Exact provider inputs are malformed or mutually contradictory."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class _ProfileResult:
    sha256: str
    payload: Mapping[str, Any] | None
    status: str
    code: str | None
    detail: str | None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_launch_profile(path: Path) -> _ProfileResult:
    sha256 = _sha256_file(path)
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {value}")
            ),
        )
        if not isinstance(payload, Mapping) or set(payload) != {
            "assumptions",
            "feature_inventory",
            "format",
            "schema_version",
        }:
            raise ExceptionEvidenceProviderV3Error(
                "launch profile has noncanonical top-level fields"
            )
        if (
            payload.get("format") != LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1
            or payload.get("schema_version") != 1
        ):
            raise ExceptionEvidenceProviderV3Error(
                "launch profile format or schema version is unsupported"
            )
        assumptions = mapping(payload.get("assumptions"), "launch assumptions")
        features = mapping(payload.get("feature_inventory"), "launch features")
        if set(assumptions) != _LAUNCH_ASSUMPTIONS or set(features) != _FEATURES:
            raise ExceptionEvidenceProviderV3Error(
                "launch profile assumption or feature inventory is incomplete"
            )
        if any(not mapping(value, f"launch assumption {name}") for name, value in assumptions.items()):
            raise ExceptionEvidenceProviderV3Error(
                "launch profile assumptions must be nonempty objects"
            )
        feature_values = {
            name: sequence(features[name], f"launch feature {name}")
            for name in sorted(_FEATURES)
        }
        nonempty = [name for name, values in feature_values.items() if values]
        if nonempty:
            return _ProfileResult(
                sha256,
                payload,
                "incomplete",
                "exception_terminal_profile_unsupported_features",
                f"unsupported launch feature inventories are nonempty: {nonempty!r}",
            )
        return _ProfileResult(sha256, payload, "complete", None, None)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        return _ProfileResult(
            sha256,
            None,
            "violated",
            "exception_terminal_profile_violated",
            str(exc),
        )


def _read_machine_units(path: Path) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ExceptionEvidenceProviderV3Error(
            f"cannot read machine IR {path}: {exc}"
        ) from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ExceptionEvidenceProviderV3Error(
                f"machine IR line {line_number} is invalid JSON: {exc}"
            ) from exc
        if not isinstance(value, Mapping) or value.get("record_kind") != "unit":
            continue
        unit_id = value.get("id")
        if not isinstance(unit_id, str) or not unit_id:
            raise ExceptionEvidenceProviderV3Error(
                f"machine IR line {line_number} lacks an exact unit ID"
            )
        if unit_id in result:
            raise ExceptionEvidenceProviderV3Error(
                f"machine IR repeats exact unit ID {unit_id!r}"
            )
        result[unit_id] = value
    if not result:
        raise ExceptionEvidenceProviderV3Error("machine IR contains no exact units")
    return result


def _terminal_certificate(
    *, fault_sha256: str, fault_kind: str, profile: _ProfileResult
) -> CanonicalValueV3:
    assert profile.payload is not None
    return CanonicalValueV3.of(
        {
            "environment_model": TERMINAL_SYNCHRONOUS_FAULT_MODEL_V1,
            "fault_kind": fault_kind,
            "fault_sha256": fault_sha256,
            "feature_inventory": profile.payload["feature_inventory"],
            "format": EXCEPTION_CLOSURE_CERTIFICATE_V3,
            "launch_profile_format": LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
            "launch_profile_sha256": profile.sha256,
            "method": "conditional-unhandled-synchronous-fault-v1",
        }
    )


def _infeasible_certificate(
    *, fault_sha256: str, condition: Mapping[str, Any]
) -> CanonicalValueV3:
    return CanonicalValueV3.of(
        {
            "condition_sha256": canonical_sha256_v3(condition),
            "fault_sha256": fault_sha256,
            "format": EXCEPTION_CLOSURE_CERTIFICATE_V3,
            "method": "static-condition-replay-v1",
            "result": False,
        }
    )


def _incomplete_evidence(
    *,
    record_id: str,
    unit_id: str,
    unit_sha256: str,
    fault_index: int,
    fault_sha256: str,
    status: Literal["incomplete", "violated"],
    code: str,
) -> ExceptionEvidenceV3:
    return ExceptionEvidenceV3(
        record_id=record_id,
        unit_id=unit_id,
        unit_sha256=unit_sha256,
        fault_index=fault_index,
        fault_sha256=fault_sha256,
        status=status,
        disposition=None,
        handler_unit_id=None,
        handler_unit_sha256=None,
        fault=None,
        guard=None,
        certificate=None,
        primary_blocker=PrimaryBlockerV3(status, code),
    )


def emit_exception_evidence_v3(
    *,
    machine_ir: Path,
    semantic_index: Path,
    launch_profile: Path,
    output_directory: Path,
) -> dict[str, Any]:
    semantic = open_artifact_reader_v3(semantic_index)
    if semantic.manifest.artifact_kind != "semantic-index-v3":
        raise ExceptionEvidenceProviderV3Error(
            "semantic-index input has the wrong artifact kind"
        )
    binary_bindings = tuple(
        row
        for row in semantic.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(binary_bindings) != 1:
        raise ExceptionEvidenceProviderV3Error(
            "semantic index must have exactly one binary/pe32 binding"
        )
    units = _read_machine_units(machine_ir)
    profile = _read_launch_profile(launch_profile)
    records: list[ArtifactRecordV3] = []
    report_rows: list[dict[str, Any]] = []
    for source in semantic.iter_records():
        checked_unit = SEMANTIC_INDEX_CODEC_V3.read(source).value
        raw_unit = units.get(checked_unit.record_id)
        if raw_unit is None:
            raise ExceptionEvidenceProviderV3Error(
                f"semantic unit {checked_unit.record_id!r} is absent from machine IR"
            )
        observed_unit_sha256 = canonical_sha256_v3(raw_unit)
        if observed_unit_sha256 != checked_unit.unit_sha256:
            raise ExceptionEvidenceProviderV3Error(
                f"machine IR contradicts semantic unit {checked_unit.record_id!r}"
            )
        semantics = mapping(raw_unit.get("semantics"), "machine-IR semantics")
        faults = sequence(semantics.get("faults"), "machine-IR faults")
        if len(faults) != len(checked_unit.faults):
            raise ExceptionEvidenceProviderV3Error(
                f"fault count contradicts semantic unit {checked_unit.record_id!r}"
            )
        for occurrence in checked_unit.faults:
            raw_fault = mapping(faults[occurrence.index], "machine-IR fault")
            if canonical_sha256_v3(raw_fault) != occurrence.fault_sha256:
                raise ExceptionEvidenceProviderV3Error(
                    f"fault {checked_unit.record_id!r}#{occurrence.index} contradicts its semantic digest"
                )
            fault_kind = text(raw_fault.get("kind"), "machine-IR fault kind")
            uint(raw_fault.get("instruction_rva"), "machine-IR fault RVA")
            condition = mapping(raw_fault.get("condition"), "machine-IR fault condition")
            record_id = exceptional_transition_id_v3(
                checked_unit.record_id,
                occurrence.index,
                occurrence.fault_sha256,
            )
            static_result = checked_static_boolean_v3(condition)
            if static_result is False:
                status = "complete"
                evidence = ExceptionEvidenceV3(
                    record_id=record_id,
                    unit_id=checked_unit.record_id,
                    unit_sha256=checked_unit.unit_sha256,
                    fault_index=occurrence.index,
                    fault_sha256=occurrence.fault_sha256,
                    status=status,
                    disposition="infeasible",
                    handler_unit_id=None,
                    handler_unit_sha256=None,
                    fault=CanonicalValueV3.of(raw_fault),
                    guard=CanonicalValueV3.of(condition),
                    certificate=_infeasible_certificate(
                        fault_sha256=occurrence.fault_sha256,
                        condition=condition,
                    ),
                    primary_blocker=None,
                )
                code = None
            elif fault_kind not in _TERMINAL_FAULT_KINDS:
                status = "incomplete"
                code = "exception_fault_kind_unsupported"
                evidence = _incomplete_evidence(
                    record_id=record_id,
                    unit_id=checked_unit.record_id,
                    unit_sha256=checked_unit.unit_sha256,
                    fault_index=occurrence.index,
                    fault_sha256=occurrence.fault_sha256,
                    status=status,
                    code=code,
                )
            elif profile.status != "complete":
                status = (
                    "violated" if profile.status == "violated" else "incomplete"
                )
                code = str(profile.code)
                evidence = _incomplete_evidence(
                    record_id=record_id,
                    unit_id=checked_unit.record_id,
                    unit_sha256=checked_unit.unit_sha256,
                    fault_index=occurrence.index,
                    fault_sha256=occurrence.fault_sha256,
                    status=status,
                    code=code,
                )
            else:
                status = "complete"
                code = None
                evidence = ExceptionEvidenceV3(
                    record_id=record_id,
                    unit_id=checked_unit.record_id,
                    unit_sha256=checked_unit.unit_sha256,
                    fault_index=occurrence.index,
                    fault_sha256=occurrence.fault_sha256,
                    status=status,
                    disposition="terminates",
                    handler_unit_id=None,
                    handler_unit_sha256=None,
                    fault=CanonicalValueV3.of(raw_fault),
                    guard=CanonicalValueV3.of(condition),
                    certificate=_terminal_certificate(
                        fault_sha256=occurrence.fault_sha256,
                        fault_kind=fault_kind,
                        profile=profile,
                    ),
                    primary_blocker=None,
                )
            records.append(EXCEPTION_EVIDENCE_CODEC_V3.write(record_id, evidence))
            report_rows.append(
                {
                    "code": code,
                    "disposition": evidence.disposition,
                    "fault_index": occurrence.index,
                    "fault_kind": fault_kind,
                    "fault_sha256": occurrence.fault_sha256,
                    "instruction_rva": raw_fault["instruction_rva"],
                    "record_id": record_id,
                    "status": status,
                    "unit_id": checked_unit.record_id,
                }
            )
    output_directory.mkdir(parents=True, exist_ok=False)
    bindings = [
        binary_bindings[0],
        ArtifactBindingV3(
            "machine-ir-source",
            "machine-ir",
            machine_ir.name,
            _sha256_file(machine_ir),
        ),
    ]
    if any(row["disposition"] == "terminates" for row in report_rows):
        bindings.append(
            ArtifactBindingV3(
                "launch-profile-source",
                "launch-assumption-template",
                LAUNCH_ASSUMPTION_TEMPLATE_FORMAT_V1,
                profile.sha256,
            )
        )
    manifest = ArtifactSetWriterV3(
        artifact_kind=EXCEPTION_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=bindings,
    ).write(output_directory / "artifact", records)
    statuses = {str(row["status"]) for row in report_rows}
    status = (
        "violated"
        if "violated" in statuses
        else "incomplete"
        if "incomplete" in statuses
        else "complete"
    )
    metadata = {
        "format": EXCEPTION_EVIDENCE_REPORT_V3,
        "status": status,
        "authorizing": False,
        "artifact_id": manifest.artifact_id,
        "artifact_kind": manifest.artifact_kind,
        "artifact_manifest_sha256": manifest.manifest_sha256,
        "record_ids": [row.record_id for row in records],
        "counts": {
            "complete": sum(row["status"] == "complete" for row in report_rows),
            "faults": len(report_rows),
            "incomplete": sum(row["status"] == "incomplete" for row in report_rows),
            "infeasible": sum(row["disposition"] == "infeasible" for row in report_rows),
            "terminating": sum(row["disposition"] == "terminates" for row in report_rows),
            "violated": sum(row["status"] == "violated" for row in report_rows),
        },
        "launch_profile": {
            "code": profile.code,
            "detail": profile.detail,
            "sha256": profile.sha256,
            "status": profile.status,
        },
        "records": report_rows,
    }
    (output_directory / "metadata.json").write_bytes(
        canonical_json_bytes_v3(metadata)
    )
    return metadata


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate replayable generic v3 exception evidence"
    )
    parser.add_argument("--machine-ir", required=True, type=Path)
    parser.add_argument("--semantic-index", required=True, type=Path)
    parser.add_argument("--launch-profile", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    emit_exception_evidence_v3(
        machine_ir=args.machine_ir,
        semantic_index=args.semantic_index,
        launch_profile=args.launch_profile,
        output_directory=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "EXCEPTION_EVIDENCE_REPORT_V3",
    "ExceptionEvidenceProviderV3Error",
    "emit_exception_evidence_v3",
    "main",
]
