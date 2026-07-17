"""Strict batched subprocess adapter for Bochs ISA conformance evidence.

The runner is an untrusted transport for concrete machine observations.  It
receives one canonical ISA conformance corpus on stdin and emits ordered JSONL
machine records followed by one terminal result record.  Match status is
always computed locally from the corpus masks and expectations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any

from .isa_conformance import (
    BackendDescriptor,
    BackendKind,
    BackendObservation,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    InstructionTestCase,
    ObservationStatus,
    ReportCounts,
    ReportQualification,
    ReportTrust,
    canonical_isa_conformance_corpus_input,
)


BOCHS_BACKEND_ID = "bochs-x86-32-batch-v1"
BOCHS_MACHINE_FORMAT = "stage-a-isa-conformance-bochs-machine-v1"
BOCHS_RESULT_FORMAT = "stage-a-isa-conformance-bochs-result-v1"
DEFAULT_TIMEOUT_SECONDS = 300.0
MAX_STDOUT_BYTES = 64 * 1024 * 1024

_MACHINE_FIELDS = {
    "format",
    "sequence",
    "case_id",
    "status",
    "final_state",
    "memory",
    "actual",
    "detail",
}
_RESULT_FIELDS = {
    "format",
    "corpus_id",
    "input_sha256",
    "backend",
    "case_ids",
    "counts",
}
_BACKEND_FIELDS = {"id", "kind", "version"}
_RAW_COUNT_FIELDS = {"cases", "complete", "unsupported", "errors"}
_RAW_STATUSES = {"complete", "unsupported", "error"}


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAConformanceError(f"{context} must be a JSON object")
    return value


def _exact_fields(
    payload: Mapping[str, Any], fields: set[str], context: str
) -> None:
    missing = fields - set(payload)
    unknown = set(payload) - fields
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append(f"missing fields {sorted(missing)!r}")
    if unknown:
        details.append(f"unknown fields {sorted(unknown)!r}")
    raise ISAConformanceError(f"{context} has " + " and ".join(details))


def _string(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ISAConformanceError(f"{context} must be a string")
    if not allow_empty and (not value or value.strip() != value):
        raise ISAConformanceError(
            f"{context} must be a non-empty string without surrounding whitespace"
        )
    return value


def _count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ISAConformanceError(f"{context} must be a non-negative integer")
    return value


def bochs_backend_descriptor(version: str) -> BackendDescriptor:
    """Return deterministic report metadata for a validated runner version."""
    return BackendDescriptor(
        id=BOCHS_BACKEND_ID,
        kind=BackendKind.EMULATOR,
        version=_string(version, "Bochs runner backend.version"),
    )


def _decode_json_lines(stdout: str) -> list[Mapping[str, Any]]:
    if len(stdout.encode("utf-8")) > MAX_STDOUT_BYTES:
        raise ISAConformanceError(
            f"Bochs runner stdout exceeds the {MAX_STDOUT_BYTES}-byte limit"
        )
    lines = stdout.splitlines()
    if not lines:
        raise ISAConformanceError("Bochs runner produced no stdout records")
    if any(not line.strip() for line in lines):
        raise ISAConformanceError("Bochs runner JSONL contains a blank line")
    records: list[Mapping[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ISAConformanceError(
                f"Bochs runner stdout line {index} is not valid JSON: {exc.msg}"
            ) from exc
        records.append(_object(value, f"Bochs runner stdout line {index}"))
    return records


def _parse_machine_record(
    payload: Mapping[str, Any],
    *,
    sequence: int,
    case_id: str,
) -> tuple[str, BackendObservation]:
    context = f"Bochs machine record {sequence}"
    _exact_fields(payload, _MACHINE_FIELDS, context)
    if payload.get("format") != BOCHS_MACHINE_FORMAT:
        raise ISAConformanceError(f"{context} has an unsupported format")
    if _count(payload.get("sequence"), f"{context}.sequence") != sequence:
        raise ISAConformanceError(f"{context} is out of sequence")
    observed_case_id = _string(payload.get("case_id"), f"{context}.case_id")
    if observed_case_id != case_id:
        raise ISAConformanceError(
            f"{context} names {observed_case_id!r}; expected {case_id!r}"
        )
    raw_status = _string(payload.get("status"), f"{context}.status")
    if raw_status not in _RAW_STATUSES:
        raise ISAConformanceError(
            f"{context}.status must be complete, unsupported, or error"
        )
    detail = _string(
        payload.get("detail"), f"{context}.detail", allow_empty=True
    )
    if detail.strip() != detail:
        raise ISAConformanceError(
            f"{context}.detail must not have surrounding whitespace"
        )
    if raw_status == "complete" and detail:
        raise ISAConformanceError(f"{context} complete status requires empty detail")
    if raw_status != "complete" and not detail:
        raise ISAConformanceError(
            f"{context} {raw_status} status requires a non-empty detail"
        )

    translated_status = {
        "complete": ObservationStatus.MATCH.value,
        "unsupported": ObservationStatus.UNSUPPORTED.value,
        "error": ObservationStatus.ERROR.value,
    }[raw_status]
    translated = {
        "case_id": observed_case_id,
        "status": translated_status,
        "final_state": payload.get("final_state"),
        "memory": payload.get("memory"),
        "actual": payload.get("actual"),
        "detail": detail,
    }
    try:
        observation = BackendObservation.parse(translated)
    except ISAConformanceError as exc:
        raise ISAConformanceError(f"{context} is malformed: {exc}") from exc
    return raw_status, observation


def _parse_result_record(
    payload: Mapping[str, Any],
    *,
    corpus: ISAConformanceCorpus,
    input_sha256: str,
    raw_statuses: list[str],
) -> tuple[BackendDescriptor, str]:
    context = "Bochs terminal result"
    _exact_fields(payload, _RESULT_FIELDS, context)
    if payload.get("format") != BOCHS_RESULT_FORMAT:
        raise ISAConformanceError(f"{context} has an unsupported format")
    if payload.get("corpus_id") != corpus.id:
        raise ISAConformanceError(f"{context} names the wrong corpus")
    returned_input_sha256 = _string(
        payload.get("input_sha256"), f"{context}.input_sha256"
    )
    if returned_input_sha256 != input_sha256:
        raise ISAConformanceError(f"{context} does not bind the canonical input")

    expected_case_ids = [case.id for case in corpus.cases]
    case_ids = payload.get("case_ids")
    if not isinstance(case_ids, list) or any(
        not isinstance(case_id, str) for case_id in case_ids
    ):
        raise ISAConformanceError(f"{context}.case_ids must be a list of strings")
    if case_ids != expected_case_ids:
        raise ISAConformanceError(
            f"{context}.case_ids must exactly match corpus order"
        )

    backend = _object(payload.get("backend"), f"{context}.backend")
    _exact_fields(backend, _BACKEND_FIELDS, f"{context}.backend")
    if backend.get("id") != BOCHS_BACKEND_ID:
        raise ISAConformanceError(f"{context}.backend.id is unsupported")
    if backend.get("kind") != BackendKind.EMULATOR.value:
        raise ISAConformanceError(f"{context}.backend.kind must be emulator")
    descriptor = bochs_backend_descriptor(
        _string(backend.get("version"), f"{context}.backend.version")
    )

    counts = _object(payload.get("counts"), f"{context}.counts")
    _exact_fields(counts, _RAW_COUNT_FIELDS, f"{context}.counts")
    expected_counts = {
        "cases": len(corpus.cases),
        "complete": raw_statuses.count("complete"),
        "unsupported": raw_statuses.count("unsupported"),
        "errors": raw_statuses.count("error"),
    }
    parsed_counts = {
        field: _count(counts.get(field), f"{context}.counts.{field}")
        for field in _RAW_COUNT_FIELDS
    }
    if parsed_counts != expected_counts:
        raise ISAConformanceError(
            f"{context}.counts do not match the machine records"
        )
    return descriptor, returned_input_sha256


def _mechanical_observation(
    case: InstructionTestCase,
    raw_status: str,
    observation: BackendObservation,
) -> BackendObservation:
    if raw_status != "complete":
        return observation
    matches = case.matches(observation)
    return replace(
        observation,
        status=(ObservationStatus.MATCH if matches else ObservationStatus.MISMATCH),
        detail=(
            ""
            if matches
            else "masked Bochs observation differs from expected outcome"
        ),
    )


def _report_counts(
    observations: tuple[BackendObservation, ...],
) -> ReportCounts:
    return ReportCounts(
        cases=len(observations),
        matched=sum(
            row.status is ObservationStatus.MATCH for row in observations
        ),
        mismatched=sum(
            row.status is ObservationStatus.MISMATCH for row in observations
        ),
        unsupported=sum(
            row.status is ObservationStatus.UNSUPPORTED for row in observations
        ),
        errors=sum(row.status is ObservationStatus.ERROR for row in observations),
    )


def run_bochs_corpus(
    corpus: ISAConformanceCorpus,
    *,
    runner: str | os.PathLike[str],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> ISAConformanceReport:
    """Execute a complete corpus through one strict Bochs runner batch."""
    if not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")
    corpus.to_payload()
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ISAConformanceError("timeout_seconds must be finite and positive")
    try:
        runner_path = Path(runner).expanduser()
    except TypeError as exc:
        raise ISAConformanceError("runner must be a filesystem path") from exc
    if not runner_path.is_file():
        raise ISAConformanceError(f"Bochs runner executable is missing: {runner_path}")
    if not os.access(runner_path, os.X_OK):
        raise ISAConformanceError(
            f"Bochs runner is not executable: {runner_path}"
        )

    request = canonical_isa_conformance_corpus_input(corpus)
    input_sha256 = hashlib.sha256(request).hexdigest()
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        completed = subprocess.run(
            [os.fspath(runner_path)],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=float(timeout_seconds),
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise ISAConformanceError(
            f"Bochs runner timed out after {timeout_seconds:g} seconds"
        ) from exc
    except OSError as exc:
        raise ISAConformanceError(f"Bochs runner could not be executed: {exc}") from exc

    try:
        stdout = completed.stdout.decode("utf-8")
        stderr = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ISAConformanceError("Bochs runner output is not UTF-8") from exc
    if completed.returncode != 0:
        detail = stderr.strip() or "no stderr detail"
        raise ISAConformanceError(
            f"Bochs runner exited with status {completed.returncode}: {detail}"
        )
    if stderr:
        raise ISAConformanceError("Bochs runner wrote to stderr on success")

    records = _decode_json_lines(stdout)
    expected_records = len(corpus.cases) + 1
    if len(records) != expected_records:
        raise ISAConformanceError(
            "Bochs runner must emit exactly one machine record per case and "
            "one terminal result"
        )

    raw_statuses: list[str] = []
    observations: list[BackendObservation] = []
    for sequence, (case, record) in enumerate(
        zip(corpus.cases, records[:-1], strict=True)
    ):
        raw_status, observation = _parse_machine_record(
            record, sequence=sequence, case_id=case.id
        )
        raw_statuses.append(raw_status)
        observations.append(_mechanical_observation(case, raw_status, observation))

    descriptor, returned_input_sha256 = _parse_result_record(
        records[-1],
        corpus=corpus,
        input_sha256=input_sha256,
        raw_statuses=raw_statuses,
    )
    typed_observations = tuple(observations)
    counts = _report_counts(typed_observations)
    if counts.mismatched:
        qualification = ReportQualification.VETOED
    elif counts.unsupported or counts.errors:
        qualification = ReportQualification.UNQUALIFIED
    else:
        qualification = ReportQualification.QUALIFIED
    report = ISAConformanceReport(
        corpus_id=corpus.id,
        input_sha256=returned_input_sha256,
        backend=descriptor,
        qualification=qualification,
        observations=typed_observations,
        counts=counts,
        trust=ReportTrust(),
    )
    report.to_payload(corpus=corpus)
    return report


__all__ = [
    "BOCHS_BACKEND_ID",
    "BOCHS_MACHINE_FORMAT",
    "BOCHS_RESULT_FORMAT",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_STDOUT_BYTES",
    "bochs_backend_descriptor",
    "run_bochs_corpus",
]
