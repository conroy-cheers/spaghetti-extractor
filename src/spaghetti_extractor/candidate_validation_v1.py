"""Join exact candidate-only validation for a portable build pair."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .authority_bindings_v2 import canonical_json_bytes
from .util import sha256_file, write_json


CANDIDATE_VALIDATION_V1_FORMAT = (
    "spaghetti-extractor-candidate-validation-v1"
)


class CandidateValidationV1Error(ValueError):
    """Candidate validation inputs are malformed or mutually stale."""


def _resolve(path: Path, filename: str) -> Path:
    candidate = path / filename if path.is_dir() else path
    if not candidate.is_file():
        raise CandidateValidationV1Error(
            f"required artifact is missing: {candidate}"
        )
    return candidate


def _read(path: Path, expected_format: str, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateValidationV1Error(
            f"cannot read {context} {path}: {exc}"
        ) from exc
    if not isinstance(value, Mapping) or value.get("format") != expected_format:
        raise CandidateValidationV1Error(f"{context} has the wrong format")
    return value


def _candidate_sha(report: Mapping[str, Any], context: str) -> str:
    bindings = report.get("binary_bindings")
    candidate = bindings.get("candidate") if isinstance(bindings, Mapping) else None
    digest = candidate.get("sha256") if isinstance(candidate, Mapping) else None
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or candidate.get("provided") is not True
        or candidate.get("exists") is not True
    ):
        raise CandidateValidationV1Error(
            f"{context} has no exact candidate binding"
        )
    return digest


def build_candidate_validation_v1(
    *, pe32_report: Path, non_x86_report: Path
) -> dict[str, Any]:
    pe32_path = _resolve(pe32_report, "functional-report.json")
    native_path = _resolve(non_x86_report, "functional-report.json")
    pe32 = _read(
        pe32_path, "stage-b-functional-report-v1", "PE32 functional report"
    )
    native = _read(
        native_path,
        "stage-b-functional-report-v1",
        "non-x86 functional report",
    )
    pe32_sha = _candidate_sha(pe32, "PE32 functional report")
    native_sha = _candidate_sha(native, "non-x86 functional report")
    if pe32_sha == native_sha:
        raise CandidateValidationV1Error(
            "candidate validation received the same binary twice"
        )
    pe32_cases = pe32.get("cases")
    native_cases = native.get("cases")
    if not isinstance(pe32_cases, list) or not isinstance(native_cases, list):
        raise CandidateValidationV1Error(
            "candidate validation reports have malformed cases"
        )
    pe32_ids = sorted(str(row.get("id")) for row in pe32_cases if isinstance(row, Mapping))
    native_ids = sorted(str(row.get("id")) for row in native_cases if isinstance(row, Mapping))
    case_inventory_matches = (
        len(pe32_ids) == len(pe32_cases)
        and len(native_ids) == len(native_cases)
        and pe32_ids == native_ids
    )
    passed = (
        pe32.get("status") == "pass"
        and native.get("status") == "pass"
        and case_inventory_matches
    )
    core = {
        "format": CANDIDATE_VALIDATION_V1_FORMAT,
        "status": "complete" if passed else "violated",
        "executes_original_binary": False,
        "pe32_candidate_sha256": pe32_sha,
        "non_x86_candidate_sha256": native_sha,
        "reports": {
            "pe32_sha256": sha256_file(pe32_path),
            "non_x86_sha256": sha256_file(native_path),
        },
        "coverage": {
            "case_ids": pe32_ids if case_inventory_matches else [],
            "case_inventory_matches": case_inventory_matches,
            "pe32_status": pe32.get("status"),
            "non_x86_status": native.get("status"),
        },
        "authority": {
            "candidate_only": True,
            "proves_equivalence": False,
            "failure_vetoes_qualification": True,
        },
    }
    return {
        **core,
        "validation_id": "candidate-validation-v1:"
        + hashlib.sha256(canonical_json_bytes(core)).hexdigest(),
    }


def emit_candidate_validation_v1(
    *, pe32_report: Path, non_x86_report: Path, output_directory: Path
) -> dict[str, Any]:
    result = build_candidate_validation_v1(
        pe32_report=pe32_report, non_x86_report=non_x86_report
    )
    output_directory.mkdir(parents=True, exist_ok=False)
    write_json(output_directory / "candidate-validation-v1.json", result)
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Join a candidate-only portable build-pair validation"
    )
    parser.add_argument("--pe32-report", type=Path, required=True)
    parser.add_argument("--non-x86-report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    emit_candidate_validation_v1(
        pe32_report=arguments.pe32_report,
        non_x86_report=arguments.non_x86_report,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
