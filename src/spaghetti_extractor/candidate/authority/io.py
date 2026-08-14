"""Strict parsing and path loading for candidate-authority receipts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ...artifact_set_v3 import ArtifactV3Error, parse_canonical_json_v3
from .model import (
    AUTHORITY,
    CHECK_NAMES,
    POLICY,
    STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT,
    STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION,
    CandidateAuthorityV3Error,
    CandidateAuthorityV3Issue,
    CandidateAuthorityV3Receipt,
    CandidateAuthorityV3Status,
    issue_key,
    json_value,
    status_from_issues,
)


_CONTENT_ID_RE = re.compile(r"stage-b-candidate-authority-v3:[0-9a-f]{64}")


def parse_candidate_authority(
    value: Mapping[str, Any] | str | bytes,
) -> CandidateAuthorityV3Receipt:
    """Parse canonical receipt JSON and rederive every local integrity field."""

    if isinstance(value, (str, bytes)):
        raw = value.encode("ascii") if isinstance(value, str) else value
        try:
            value = parse_canonical_json_v3(raw, location="candidate receipt")
        except (UnicodeError, ArtifactV3Error) as exc:
            raise CandidateAuthorityV3Error(str(exc)) from exc
    row = _strict_object(
        value,
        {
            "format", "schema_version", "status", "authorizing", "authority",
            "policy", "inputs", "checks", "issues", "content_id",
        },
        "candidate receipt",
    )
    if (
        row["format"] != STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT
        or row["schema_version"] != STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION
    ):
        raise CandidateAuthorityV3Error("receipt is not candidate authority v3")
    if row["authority"] != AUTHORITY or row["policy"] != POLICY:
        raise CandidateAuthorityV3Error("candidate scope or policy is stale")
    try:
        status = CandidateAuthorityV3Status(row["status"])
    except (TypeError, ValueError) as exc:
        raise CandidateAuthorityV3Error("candidate status is invalid") from exc
    if row["authorizing"] is not (status is CandidateAuthorityV3Status.AUTHORIZED):
        raise CandidateAuthorityV3Error("candidate authorization bit is stale")
    inputs = _strict_object(
        row["inputs"],
        {
            "final_authority", "machine_ir", "machine_ir_manifest",
            "fallback_coverage_receipt", "component_runtime_package",
        },
        "candidate inputs",
    )
    checks = _strict_object(row["checks"], set(CHECK_NAMES), "candidate checks")
    if any(not isinstance(item, bool) for item in checks.values()):
        raise CandidateAuthorityV3Error("candidate checks must be Boolean")
    raw_issues = row["issues"]
    if not isinstance(raw_issues, list):
        raise CandidateAuthorityV3Error("candidate issues must be an array")
    issues = tuple(_parse_issue(item) for item in raw_issues)
    if issues != tuple(sorted(set(issues), key=issue_key)):
        raise CandidateAuthorityV3Error("candidate issues are not sorted and unique")
    if status_from_issues(issues) is not status:
        raise CandidateAuthorityV3Error("candidate status is stale")
    if status is CandidateAuthorityV3Status.AUTHORIZED and not all(checks.values()):
        raise CandidateAuthorityV3Error("authorized receipt contains a failed check")
    receipt_id = row["content_id"]
    if not isinstance(receipt_id, str) or _CONTENT_ID_RE.fullmatch(receipt_id) is None:
        raise CandidateAuthorityV3Error("candidate content ID is malformed")
    receipt = CandidateAuthorityV3Receipt(
        status=status,
        inputs=json_value(inputs),
        checks=json_value(checks),
        issues=issues,
        content_id=receipt_id,
    )
    if receipt.to_payload() != json_value(row):
        raise CandidateAuthorityV3Error("candidate content ID is stale")
    return receipt


def load_candidate_authority(
    value: Path | str | Mapping[str, Any] | CandidateAuthorityV3Receipt,
) -> CandidateAuthorityV3Receipt:
    """Load a receipt value or path through the same strict parser."""

    if isinstance(value, CandidateAuthorityV3Receipt):
        return parse_candidate_authority(value.to_payload())
    if isinstance(value, Mapping):
        return parse_candidate_authority(value)
    try:
        return parse_candidate_authority(Path(value).read_bytes())
    except OSError as exc:
        raise CandidateAuthorityV3Error(f"cannot read candidate receipt: {exc}") from exc


def _parse_issue(value: Any) -> CandidateAuthorityV3Issue:
    row = _strict_object(value, {"status", "code", "detail"}, "candidate issue")
    try:
        status = CandidateAuthorityV3Status(row["status"])
    except (TypeError, ValueError) as exc:
        raise CandidateAuthorityV3Error("candidate issue status is invalid") from exc
    return CandidateAuthorityV3Issue(
        status=status,
        code=_text(row["code"], "candidate issue code"),
        detail=_text(row["detail"], "candidate issue detail"),
    )


def _strict_object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    row = _mapping(value, context)
    if set(row) != fields:
        raise CandidateAuthorityV3Error(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return row


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CandidateAuthorityV3Error(f"{context} must be an object")
    return value


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 0x20 for char in value):
        raise CandidateAuthorityV3Error(f"{context} must be nonempty text")
    return value


__all__ = ["load_candidate_authority", "parse_candidate_authority"]
