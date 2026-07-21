from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from .register_dataflow_formats import REGISTER_DATAFLOW_PROBLEM_SEED_FORMAT
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a SHA-256 digest")
    return value


def _canonical_rows(
    value: Sequence[Mapping[str, Any]], context: str,
) -> list[dict[str, Any]]:
    rows = [json.loads(json.dumps(dict(row))) for row in value]
    canonical = sorted(
        rows,
        key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")),
    )
    keys = [
        json.dumps(row, sort_keys=True, separators=(",", ":"))
        for row in rows
    ]
    if len(set(keys)) != len(keys):
        raise StageAInputError(f"{context} rows are duplicated")
    if rows != canonical:
        raise StageAInputError(f"{context} rows are not canonical")
    return rows


def register_dataflow_problem_seed_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    contract_sha256: str,
    behaviors_sha256: str,
    indirect_call_candidates: Sequence[Mapping[str, Any]],
    import_call_candidates: Sequence[Mapping[str, Any]],
    callsite_summary_predecessors: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    def sorted_rows(
        value: Sequence[Mapping[str, Any]], context: str,
    ) -> list[dict[str, Any]]:
        rows = [json.loads(json.dumps(dict(row))) for row in value]
        rows.sort(
            key=lambda row: json.dumps(
                row, sort_keys=True, separators=(",", ":")
            )
        )
        _canonical_rows(rows, context)
        return rows

    body = {
        "format": REGISTER_DATAFLOW_PROBLEM_SEED_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": _sha256(original_sha256, "original SHA-256"),
        "candidate_sha256": _sha256(candidate_sha256, "candidate SHA-256"),
        "contract_sha256": _sha256(contract_sha256, "contract SHA-256"),
        "behaviors_sha256": _sha256(
            behaviors_sha256, "behaviors SHA-256",
        ),
        "indirect_call_candidates": sorted_rows(
            indirect_call_candidates, "indirect call candidates",
        ),
        "import_call_candidates": sorted_rows(
            import_call_candidates, "import call candidates",
        ),
        "callsite_summary_predecessors": sorted_rows(
            callsite_summary_predecessors, "callsite summary predecessors",
        ),
    }
    payload = {**body, "seed_sha256": _canonical_sha256(body)}
    parse_register_dataflow_problem_seed(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_contract_sha256=contract_sha256,
        expected_behaviors_sha256=behaviors_sha256,
    )
    return payload


def parse_register_dataflow_problem_seed(
    payload: object,
    *,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_contract_sha256: str,
    expected_behaviors_sha256: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow problem seed must be an object")
    expected_fields = {
        "format", "profile", "model", "status", "acceptance_authority",
        "original_sha256", "candidate_sha256", "contract_sha256",
        "behaviors_sha256", "indirect_call_candidates",
        "import_call_candidates", "callsite_summary_predecessors",
        "seed_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register dataflow problem seed fields do not match")
    body = {key: value for key, value in payload.items() if key != "seed_sha256"}
    if payload["seed_sha256"] != _canonical_sha256(body):
        raise StageAInputError("register dataflow problem seed digest does not match")
    expected_identity = {
        "format": REGISTER_DATAFLOW_PROBLEM_SEED_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": _sha256(
            expected_original_sha256, "expected original SHA-256",
        ),
        "candidate_sha256": _sha256(
            expected_candidate_sha256, "expected candidate SHA-256",
        ),
        "contract_sha256": _sha256(
            expected_contract_sha256, "expected contract SHA-256",
        ),
        "behaviors_sha256": _sha256(
            expected_behaviors_sha256, "expected behaviors SHA-256",
        ),
    }
    for field, expected in expected_identity.items():
        if payload[field] != expected:
            raise StageAInputError(
                f"register dataflow problem seed {field} does not match"
            )
    normalized = json.loads(json.dumps(payload))
    for field in (
        "indirect_call_candidates", "import_call_candidates",
        "callsite_summary_predecessors",
    ):
        raw_rows = payload[field]
        if not isinstance(raw_rows, list):
            raise StageAInputError(
                f"register dataflow problem seed {field} is invalid"
            )
        normalized[field] = _canonical_rows(raw_rows, field)
    return normalized


__all__ = [
    "REGISTER_DATAFLOW_PROBLEM_SEED_FORMAT",
    "parse_register_dataflow_problem_seed",
    "register_dataflow_problem_seed_payload",
]
