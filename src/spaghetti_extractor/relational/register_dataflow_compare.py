from __future__ import annotations

import hashlib
import json
from typing import Any

from ..errors import StageAInputError
from .register_dataflow_artifact import REGISTER_ORDER
from .register_dataflow_aggregate import REGISTER_DATAFLOW_AGGREGATE_FORMAT


REGISTER_DATAFLOW_COMPARISON_FORMAT = "stage-a-register-dataflow-comparison-v1"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def compare_register_dataflow_aggregate(
    *, aggregate_payload: object, register_relations_payload: object,
) -> dict[str, Any]:
    """Compare the sharded replay with the pre-migration global analysis."""
    if not isinstance(aggregate_payload, dict):
        raise StageAInputError("register dataflow aggregate must be an object")
    aggregate = dict(aggregate_payload)
    aggregate_body = {
        key: value for key, value in aggregate.items()
        if key != "aggregate_sha256"
    }
    if (
        aggregate.get("format") != REGISTER_DATAFLOW_AGGREGATE_FORMAT
        or aggregate.get("acceptance_authority") is not False
        or aggregate.get("aggregate_sha256")
            != _canonical_sha256(aggregate_body)
    ):
        raise StageAInputError("register dataflow aggregate is invalid")
    if aggregate.get("status") != "complete":
        raise StageAInputError("register dataflow aggregate is incomplete")
    if not isinstance(register_relations_payload, dict):
        raise StageAInputError("register relation analysis must be an object")
    analysis = dict(register_relations_payload)
    if (
        analysis.get("format")
            != "stage-a-relational-register-relations-v1"
        or analysis.get("dataflow_complete") is not True
        or not isinstance(analysis.get("regions"), list)
    ):
        raise StageAInputError("register relation analysis is incomplete")

    aggregate_regions = aggregate.get("regions")
    if not isinstance(aggregate_regions, list):
        raise StageAInputError("register dataflow aggregate regions are invalid")
    aggregate_by_id = {
        region.get("id"): region
        for region in aggregate_regions
        if isinstance(region, dict)
    }
    analysis_regions = analysis["regions"]
    analysis_by_id = {
        region.get("region_id"): region
        for region in analysis_regions
        if isinstance(region, dict)
    }
    if (
        len(aggregate_by_id) != len(aggregate_regions)
        or len(analysis_by_id) != len(analysis_regions)
        or set(aggregate_by_id) != set(analysis_by_id)
    ):
        raise StageAInputError(
            "register dataflow comparison region inventories differ"
        )

    def canonical_analysis_relations(value: object) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            raise StageAInputError(
                "register relation analysis state must be a list"
            )
        relation_by_register: dict[str, dict[str, Any]] = {}
        for raw_relation in value:
            if not isinstance(raw_relation, dict):
                raise StageAInputError(
                    "register relation analysis entry must be an object"
                )
            original = raw_relation.get("original")
            candidate = raw_relation.get("candidate")
            if original not in REGISTER_ORDER or not isinstance(candidate, str):
                raise StageAInputError(
                    "register relation analysis entry is malformed"
                )
            if original in relation_by_register:
                raise StageAInputError(
                    "register relation analysis state is ambiguous"
                )
            relation_by_register[original] = {
                "register": original,
                **{
                    key: item
                    for key, item in raw_relation.items()
                    if key not in {"original", "candidate"}
                },
            }
        return [
            relation_by_register.get(register, {
                "register": register,
                "relation": "related_word",
            })
            for register in REGISTER_ORDER
        ]

    mismatches: list[dict[str, Any]] = []
    for region_id in sorted(analysis_by_id):
        expected_region = analysis_by_id[region_id]
        observed_region = aggregate_by_id[region_id]
        for aggregate_field, analysis_field in (
            ("input_relations", "inputs"),
            ("output_relations", "outputs"),
        ):
            expected = canonical_analysis_relations(
                expected_region.get(analysis_field)
            )
            observed = observed_region.get(aggregate_field)
            if observed != expected:
                mismatches.append({
                    "region_id": region_id,
                    "relation_family": aggregate_field,
                    "expected": expected,
                    "observed": observed,
                })
    body = {
        "format": REGISTER_DATAFLOW_COMPARISON_FORMAT,
        "status": "match" if not mismatches else "mismatch",
        "acceptance_authority": False,
        "aggregate_sha256": aggregate["aggregate_sha256"],
        "region_count": len(analysis_by_id),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }
    return {**body, "comparison_sha256": _canonical_sha256(body)}


__all__ = [
    "REGISTER_DATAFLOW_COMPARISON_FORMAT",
    "compare_register_dataflow_aggregate",
]
