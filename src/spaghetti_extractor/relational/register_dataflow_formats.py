from __future__ import annotations

import hashlib
import json
from typing import Any

from ..errors import StageAInputError


REGISTER_DATAFLOW_PROBLEM_FORMAT = "stage-a-register-dataflow-problem-v1"
REGISTER_DATAFLOW_PROBLEM_SEED_FORMAT = (
    "stage-a-register-dataflow-problem-seed-v2"
)
REGISTER_DATAFLOW_PACK_INPUT_FORMAT = "stage-a-register-dataflow-pack-input-v1"
REGISTER_DATAFLOW_PACK_MANIFEST_FORMAT = (
    "stage-a-register-dataflow-pack-manifest-v1"
)


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def parse_register_dataflow_pack_input(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow pack input must be an object")
    expected_fields = {
        "format",
        "status",
        "acceptance_authority",
        "id",
        "local_semantics_sha256",
        "resource_class",
        "component_ids",
        "predecessor_ids",
        "transfer_context_sha256",
        "components",
        "regions",
        "edges",
        "input_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register dataflow pack input fields do not match")
    if (
        payload["format"] != REGISTER_DATAFLOW_PACK_INPUT_FORMAT
        or payload["status"] != "untrusted_proposal_requires_lean_replay"
        or payload["acceptance_authority"] is not False
    ):
        raise StageAInputError("register dataflow pack input identity is invalid")
    body = {key: value for key, value in payload.items() if key != "input_sha256"}
    if payload["input_sha256"] != _canonical_sha256(body):
        raise StageAInputError("register dataflow pack input digest does not match")
    if not isinstance(payload["id"], str) or not payload["id"]:
        raise StageAInputError("register dataflow pack ID is invalid")
    if not isinstance(payload["regions"], list) or not payload["regions"]:
        raise StageAInputError("register dataflow pack has no regions")
    return json.loads(json.dumps(payload))


def parse_register_dataflow_pack_manifest(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow pack manifest must be an object")
    expected_fields = {
        "format",
        "status",
        "acceptance_authority",
        "original_sha256",
        "candidate_sha256",
        "graph_sha256",
        "transfer_context_sha256",
        "pack_count",
        "topological_pack_ids",
        "packs",
        "manifest_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError(
            "register dataflow pack manifest fields do not match"
        )
    body = {
        key: value for key, value in payload.items()
        if key != "manifest_sha256"
    }
    if payload["manifest_sha256"] != _canonical_sha256(body):
        raise StageAInputError(
            "register dataflow pack manifest digest does not match"
        )
    if (
        payload["format"] != REGISTER_DATAFLOW_PACK_MANIFEST_FORMAT
        or payload["status"] != "untrusted_proposal_requires_lean_replay"
        or payload["acceptance_authority"] is not False
    ):
        raise StageAInputError("register dataflow pack manifest identity is invalid")
    packs = payload["packs"]
    topological_ids = payload["topological_pack_ids"]
    if (
        not isinstance(packs, list)
        or not isinstance(topological_ids, list)
        or payload["pack_count"] != len(packs)
        or [pack.get("id") for pack in packs] != topological_ids
        or len(set(topological_ids)) != len(topological_ids)
    ):
        raise StageAInputError(
            "register dataflow pack manifest inventory is invalid"
        )
    position = {
        pack_id: index for index, pack_id in enumerate(topological_ids)
    }
    for pack in packs:
        if not isinstance(pack, dict) or set(pack) != {
            "id",
            "input_sha256",
            "predecessor_ids",
            "resource_class",
            "region_count",
        }:
            raise StageAInputError("register dataflow manifest pack is malformed")
        predecessors = pack["predecessor_ids"]
        if (
            not isinstance(predecessors, list)
            or predecessors != sorted(set(predecessors))
            or any(
                predecessor not in position
                or position[predecessor] >= position[pack["id"]]
                for predecessor in predecessors
            )
        ):
            raise StageAInputError(
                "register dataflow manifest dependencies are invalid"
            )
    return json.loads(json.dumps(payload))


__all__ = [
    "REGISTER_DATAFLOW_PACK_INPUT_FORMAT",
    "REGISTER_DATAFLOW_PACK_MANIFEST_FORMAT",
    "REGISTER_DATAFLOW_PROBLEM_FORMAT",
    "REGISTER_DATAFLOW_PROBLEM_SEED_FORMAT",
    "parse_register_dataflow_pack_input",
    "parse_register_dataflow_pack_manifest",
]
