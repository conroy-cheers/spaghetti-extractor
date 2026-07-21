from __future__ import annotations

import hashlib
import json
from typing import Any

from ..errors import StageAInputError
from .analyses.register_lattice import _register_relation_payload
from .register_dataflow_artifact import REGISTER_ORDER


REGISTER_DATAFLOW_PACK_SUMMARY_FORMAT = (
    "stage-a-register-dataflow-pack-summary-v1"
)


def canonical_summary_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def parse_register_dataflow_pack_summary(
    payload: object,
    *,
    expected_pack_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow pack summary must be an object")
    expected_fields = {
        "format",
        "status",
        "acceptance_authority",
        "pack_id",
        "regions",
        "summary_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError(
            "register dataflow pack summary fields do not match"
        )
    body = {
        key: value for key, value in payload.items()
        if key != "summary_sha256"
    }
    if payload["summary_sha256"] != canonical_summary_sha256(body):
        raise StageAInputError(
            "register dataflow pack summary digest does not match"
        )
    if payload["format"] != REGISTER_DATAFLOW_PACK_SUMMARY_FORMAT:
        raise StageAInputError("register dataflow pack summary format is invalid")
    if payload["status"] not in {"complete", "incomplete"}:
        raise StageAInputError("register dataflow pack summary status is invalid")
    if payload["acceptance_authority"] is not False:
        raise StageAInputError("register dataflow pack summary claims authority")
    pack_id = payload["pack_id"]
    if not isinstance(pack_id, str) or not pack_id:
        raise StageAInputError("register dataflow pack summary ID is invalid")
    if expected_pack_id is not None and pack_id != expected_pack_id:
        raise StageAInputError("register dataflow pack summary ID does not match")
    raw_regions = payload["regions"]
    if not isinstance(raw_regions, list):
        raise StageAInputError("register dataflow pack summary regions are invalid")
    regions = []
    seen_ids: set[str] = set()
    for index, raw_region in enumerate(raw_regions):
        context = f"register dataflow pack summary region {index}"
        if not isinstance(raw_region, dict) or set(raw_region) != {
            "id", "output_relations",
        }:
            raise StageAInputError(f"{context} fields do not match")
        region_id = raw_region["id"]
        if (
            not isinstance(region_id, str)
            or not region_id
            or region_id in seen_ids
        ):
            raise StageAInputError(f"{context} ID is invalid or ambiguous")
        seen_ids.add(region_id)
        relations = raw_region["output_relations"]
        if not isinstance(relations, list) or [
            relation.get("register") if isinstance(relation, dict) else None
            for relation in relations
        ] != list(REGISTER_ORDER):
            raise StageAInputError(
                f"{context} output relations are not canonical"
            )
        canonical_relations = [
            {
                "register": relation["register"],
                **_register_relation_payload(relation),
            }
            for relation in relations
        ]
        if relations != canonical_relations:
            raise StageAInputError(
                f"{context} output relation payloads are not canonical"
            )
        regions.append({
            "id": region_id,
            "output_relations": json.loads(json.dumps(canonical_relations)),
        })
    if payload["status"] == "incomplete" and regions:
        raise StageAInputError(
            "incomplete register dataflow pack summary contains regions"
        )
    return {**json.loads(json.dumps(payload)), "regions": regions}


def register_dataflow_pack_summary_payload(
    *,
    pack_id: str,
    status: str,
    regions: list[dict[str, Any]],
) -> dict[str, Any]:
    body = {
        "format": REGISTER_DATAFLOW_PACK_SUMMARY_FORMAT,
        "status": status,
        "acceptance_authority": False,
        "pack_id": pack_id,
        "regions": [
            {
                "id": region["id"],
                "output_relations": region["output_relations"],
            }
            for region in regions
        ],
    }
    summary = {
        **body,
        "summary_sha256": canonical_summary_sha256(body),
    }
    return parse_register_dataflow_pack_summary(
        summary,
        expected_pack_id=pack_id,
    )


__all__ = [
    "REGISTER_DATAFLOW_PACK_SUMMARY_FORMAT",
    "canonical_summary_sha256",
    "parse_register_dataflow_pack_summary",
    "register_dataflow_pack_summary_payload",
]
