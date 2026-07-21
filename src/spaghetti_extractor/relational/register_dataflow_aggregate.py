from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Sequence

from ..errors import StageAInputError
from .analyses.register_lattice import _register_relation_payload
from .register_dataflow_artifact import REGISTER_ORDER
from .register_dataflow_formats import parse_register_dataflow_pack_manifest
from .register_dataflow_solver import parse_register_dataflow_pack_result
from .register_dataflow_summary_format import (
    register_dataflow_pack_summary_payload,
)


REGISTER_DATAFLOW_AGGREGATE_FORMAT = "stage-a-register-dataflow-aggregate-v1"
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


def _relations(value: object, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    relations = []
    for index, raw_relation in enumerate(value):
        relation_context = f"{context}[{index}]"
        if not isinstance(raw_relation, dict):
            raise StageAInputError(f"{relation_context} must be an object")
        register = raw_relation.get("register")
        if register not in REGISTER_ORDER:
            raise StageAInputError(
                f"{relation_context} register is not canonical"
            )
        canonical = {
            "register": register,
            **_register_relation_payload(raw_relation),
        }
        if raw_relation != canonical:
            raise StageAInputError(
                f"{relation_context} relation is not canonical"
            )
        relations.append(canonical)
    if [relation["register"] for relation in relations] != list(REGISTER_ORDER):
        raise StageAInputError(
            f"{context} must cover canonical registers in order"
        )
    return relations


def parse_register_dataflow_aggregate(
    payload: object,
    *,
    expected_original_sha256: str | None = None,
    expected_candidate_sha256: str | None = None,
    expected_graph_sha256: str | None = None,
    require_complete: bool = False,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise StageAInputError("register dataflow aggregate must be an object")
    expected_fields = {
        "format", "status", "acceptance_authority", "original_sha256",
        "candidate_sha256", "graph_sha256", "manifest_sha256", "pack_results",
        "region_count", "regions", "gaps", "aggregate_sha256",
    }
    if set(payload) != expected_fields:
        raise StageAInputError("register dataflow aggregate fields do not match")
    body = {key: value for key, value in payload.items() if key != "aggregate_sha256"}
    if payload["aggregate_sha256"] != _canonical_sha256(body):
        raise StageAInputError("register dataflow aggregate digest does not match")
    if payload["format"] != REGISTER_DATAFLOW_AGGREGATE_FORMAT:
        raise StageAInputError("register dataflow aggregate format is invalid")
    if payload["status"] not in {"complete", "incomplete"}:
        raise StageAInputError("register dataflow aggregate status is invalid")
    if require_complete and payload["status"] != "complete":
        raise StageAInputError("register dataflow aggregate is incomplete")
    if payload["acceptance_authority"] is not False:
        raise StageAInputError("register dataflow aggregate claims authority")
    identities = {
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "graph_sha256": expected_graph_sha256,
    }
    for field, expected in identities.items():
        observed = _sha256(payload[field], f"register dataflow aggregate {field}")
        if expected is not None and observed != _sha256(expected, f"expected {field}"):
            raise StageAInputError(
                f"register dataflow aggregate {field} does not match"
            )
    _sha256(payload["manifest_sha256"], "register dataflow aggregate manifest")
    raw_pack_results = payload["pack_results"]
    if not isinstance(raw_pack_results, list):
        raise StageAInputError("register dataflow aggregate packs are invalid")
    pack_ids: set[str] = set()
    pack_results = []
    for index, raw_result in enumerate(raw_pack_results):
        if not isinstance(raw_result, dict) or set(raw_result) != {
            "id", "sha256", "status",
        }:
            raise StageAInputError(
                f"register dataflow aggregate pack {index} is malformed"
            )
        pack_id = raw_result["id"]
        if not isinstance(pack_id, str) or not pack_id or pack_id in pack_ids:
            raise StageAInputError(
                "register dataflow aggregate pack IDs are ambiguous"
            )
        pack_ids.add(pack_id)
        if raw_result["status"] not in {"complete", "incomplete"}:
            raise StageAInputError(
                "register dataflow aggregate pack status is invalid"
            )
        pack_results.append({
            "id": pack_id,
            "sha256": _sha256(
                raw_result["sha256"],
                f"register dataflow aggregate pack {index}",
            ),
            "status": raw_result["status"],
        })
    raw_regions = payload["regions"]
    if not isinstance(raw_regions, list) or payload["region_count"] != len(raw_regions):
        raise StageAInputError("register dataflow aggregate region count differs")
    region_ids: set[str] = set()
    regions = []
    for index, raw_region in enumerate(raw_regions):
        context = f"register dataflow aggregate region {index}"
        if not isinstance(raw_region, dict) or set(raw_region) != {
            "id", "input_relations", "output_relations", "reasons",
        }:
            raise StageAInputError(f"{context} fields do not match")
        region_id = raw_region["id"]
        if (
            not isinstance(region_id, str)
            or not region_id
            or region_id in region_ids
        ):
            raise StageAInputError(
                "register dataflow aggregate region IDs are ambiguous"
            )
        region_ids.add(region_id)
        reasons = raw_region["reasons"]
        if (
            not isinstance(reasons, dict)
            or set(reasons) != set(REGISTER_ORDER)
            or any(not isinstance(reason, str) or not reason for reason in reasons.values())
        ):
            raise StageAInputError(f"{context} reasons are invalid")
        regions.append({
            "id": region_id,
            "input_relations": _relations(
                raw_region["input_relations"], f"{context} inputs",
            ),
            "output_relations": _relations(
                raw_region["output_relations"], f"{context} outputs",
            ),
            "reasons": dict(reasons),
        })
    gaps = payload["gaps"]
    if not isinstance(gaps, list) or any(not isinstance(gap, dict) for gap in gaps):
        raise StageAInputError("register dataflow aggregate gaps are invalid")
    if payload["status"] == "complete" and (
        gaps or any(result["status"] != "complete" for result in pack_results)
    ):
        raise StageAInputError("complete register dataflow aggregate has gaps")
    return {
        **json.loads(json.dumps(payload)),
        "pack_results": pack_results,
        "regions": regions,
    }


def aggregate_register_dataflow_pack_results(
    *, manifest_payload: object, result_payloads: Sequence[object],
) -> dict[str, Any]:
    manifest = parse_register_dataflow_pack_manifest(manifest_payload)
    results = [
        parse_register_dataflow_pack_result(payload)
        for payload in result_payloads
    ]
    result_by_id = {result["pack_id"]: result for result in results}
    summary_by_id = {
        pack_id: register_dataflow_pack_summary_payload(
            pack_id=result["pack_id"],
            status=result["status"],
            regions=result["regions"],
        )
        for pack_id, result in result_by_id.items()
    }
    expected_ids = list(manifest["topological_pack_ids"])
    if len(result_by_id) != len(results) or set(result_by_id) != set(expected_ids):
        raise StageAInputError(
            "register dataflow aggregate result inventory does not match"
        )
    manifest_pack_by_id = {
        pack["id"]: pack for pack in manifest["packs"]
    }
    gaps: list[dict[str, Any]] = []
    region_rows = []
    for pack_id in expected_ids:
        pack = manifest_pack_by_id[pack_id]
        result = result_by_id[pack_id]
        parse_register_dataflow_pack_result(
            result,
            expected_pack_id=pack_id,
            expected_input_sha256=pack["input_sha256"],
        )
        expected_predecessor_results = [
            {
                "id": predecessor_id,
                "sha256": summary_by_id[predecessor_id]["summary_sha256"],
            }
            for predecessor_id in pack["predecessor_ids"]
        ]
        if result["predecessor_results"] != expected_predecessor_results:
            raise StageAInputError(
                f"register dataflow pack {pack_id} predecessor binding differs"
            )
        if result["status"] != "complete":
            gaps.extend({
                "pack_id": pack_id,
                **gap,
            } for gap in result["missing_observations"])
        if result["status"] == "complete" and len(result["regions"]) != (
            pack["region_count"]
        ):
            raise StageAInputError(
                f"register dataflow pack {pack_id} region count differs"
            )
        region_rows.extend(result["regions"])
    region_ids = [region["id"] for region in region_rows]
    expected_region_count = sum(
        int(pack["region_count"]) for pack in manifest["packs"]
    )
    if len(region_ids) != len(set(region_ids)):
        raise StageAInputError("register dataflow aggregate regions are duplicated")
    if not gaps and len(region_ids) != expected_region_count:
        raise StageAInputError("register dataflow aggregate region cover is incomplete")
    body = {
        "format": REGISTER_DATAFLOW_AGGREGATE_FORMAT,
        "status": "complete" if not gaps else "incomplete",
        "acceptance_authority": False,
        "original_sha256": manifest["original_sha256"],
        "candidate_sha256": manifest["candidate_sha256"],
        "graph_sha256": manifest["graph_sha256"],
        "manifest_sha256": manifest["manifest_sha256"],
        "pack_results": [
            {
                "id": pack_id,
                "sha256": result_by_id[pack_id]["result_sha256"],
                "status": result_by_id[pack_id]["status"],
            }
            for pack_id in expected_ids
        ],
        "region_count": len(region_rows),
        "regions": region_rows,
        "gaps": gaps,
    }
    payload = {**body, "aggregate_sha256": _canonical_sha256(body)}
    parse_register_dataflow_aggregate(payload)
    return payload


__all__ = [
    "REGISTER_DATAFLOW_AGGREGATE_FORMAT",
    "aggregate_register_dataflow_pack_results",
    "parse_register_dataflow_aggregate",
]
