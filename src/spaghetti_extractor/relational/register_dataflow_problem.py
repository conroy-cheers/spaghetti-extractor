from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from .analyses.dataflow import parse_stable_dataflow_graph
from .register_dataflow_formats import REGISTER_DATAFLOW_PROBLEM_FORMAT
from .register_transfer_core import parse_register_transfer_programs
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


def _sorted_rows(
    value: Sequence[Mapping[str, Any]], context: str,
) -> list[dict[str, Any]]:
    rows = [json.loads(json.dumps(dict(row))) for row in value]
    if any(not isinstance(row, dict) for row in rows):
        raise StageAInputError(f"{context} rows must be objects")
    canonical = sorted(
        rows,
        key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")),
    )
    if len({
        json.dumps(row, sort_keys=True, separators=(",", ":"))
        for row in rows
    }) != len(rows):
        raise StageAInputError(f"{context} rows are duplicated")
    return canonical


def _canonical_rows(
    value: Sequence[Mapping[str, Any]], context: str,
) -> list[dict[str, Any]]:
    rows = [json.loads(json.dumps(dict(row))) for row in value]
    canonical = _sorted_rows(value, context)
    if rows != canonical:
        raise StageAInputError(f"{context} rows are not canonical")
    return rows


def register_dataflow_problem_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    contract_sha256: str,
    behaviors_sha256: str,
    indirect_call_candidates: Sequence[Mapping[str, Any]],
    import_call_candidates: Sequence[Mapping[str, Any]],
    callsite_summary_predecessors: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    transfer_programs: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "format": REGISTER_DATAFLOW_PROBLEM_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "contract_sha256": contract_sha256,
        "behaviors_sha256": behaviors_sha256,
        "indirect_call_candidates": _sorted_rows(
            indirect_call_candidates, "indirect call candidates",
        ),
        "import_call_candidates": _sorted_rows(
            import_call_candidates, "import call candidates",
        ),
        "callsite_summary_predecessors": _sorted_rows(
            callsite_summary_predecessors, "callsite summary predecessors",
        ),
        "graph": dict(graph),
        "transfer_programs": dict(transfer_programs),
    }
    payload = {**body, "problem_sha256": _canonical_sha256(body)}
    parse_register_dataflow_problem(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_contract_sha256=contract_sha256,
        expected_behaviors_sha256=behaviors_sha256,
    )
    return payload


def parse_register_dataflow_problem(
    payload: object,
    *,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_contract_sha256: str,
    expected_behaviors_sha256: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow problem must be an object")
    expected_fields = {
        "format", "profile", "model", "status", "acceptance_authority",
        "original_sha256", "candidate_sha256", "contract_sha256",
        "behaviors_sha256", "indirect_call_candidates",
        "import_call_candidates", "callsite_summary_predecessors", "graph",
        "transfer_programs", "problem_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register dataflow problem fields do not match")
    body = {key: value for key, value in payload.items() if key != "problem_sha256"}
    if payload["problem_sha256"] != _canonical_sha256(body):
        raise StageAInputError("register dataflow problem digest does not match")
    expected_identity = {
        "format": REGISTER_DATAFLOW_PROBLEM_FORMAT,
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
            raise StageAInputError(f"register dataflow problem {field} does not match")
    graph = parse_stable_dataflow_graph(payload["graph"])
    transfer_programs = parse_register_transfer_programs(
        payload["transfer_programs"],
        expected_original_sha256=expected_original_sha256,
        expected_candidate_sha256=expected_candidate_sha256,
        expected_graph_sha256=graph.graph_sha256,
    )
    candidates = {}
    for field in (
        "indirect_call_candidates", "import_call_candidates",
        "callsite_summary_predecessors",
    ):
        raw_rows = payload[field]
        if not isinstance(raw_rows, list):
            raise StageAInputError(f"register dataflow problem {field} is invalid")
        candidates[field] = _canonical_rows(raw_rows, field)
    program_ids = {
        str(program["region_id"]) for program in transfer_programs["programs"]
    }
    graph_ids = {
        region_id
        for component in graph.components
        for region_id in component.region_ids
    }
    if program_ids != graph_ids:
        raise StageAInputError(
            "register dataflow problem graph does not cover transfer programs"
        )
    return {
        **json.loads(json.dumps(payload)),
        **candidates,
    }


__all__ = [
    "REGISTER_DATAFLOW_PROBLEM_FORMAT",
    "parse_register_dataflow_problem",
    "register_dataflow_problem_payload",
]
