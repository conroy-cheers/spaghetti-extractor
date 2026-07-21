from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..errors import StageAInputError
from .schema import (
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
)


REGISTER_TRANSFER_TABLE_FORMAT = "stage-a-register-transfer-table-v1"
REGISTER_TRANSFER_TABLE_STATUS = "untrusted_proposal_requires_lean_replay"
REGISTER_ORDER = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_RELATION_KINDS = frozenset({
    "exact",
    "fixed_word",
    "code_pointer",
    "data_pointer",
    "fixed_code_pointer",
    "related_word",
})


@dataclass(frozen=True)
class RegisterTransferTable:
    regions: tuple[dict[str, Any], ...]
    propagation_regions: tuple[dict[str, Any], ...]
    propagation_edges: tuple[dict[str, Any], ...]


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


def _object(value: object, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        raise StageAInputError(f"{context} must be an object")
    return dict(value)


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str,
) -> None:
    actual = set(value)
    if actual != expected:
        raise StageAInputError(
            f"{context} fields mismatch: missing={sorted(expected - actual)} "
            f"unexpected={sorted(actual - expected)}"
        )


def _relation(value: object, context: str) -> dict[str, Any]:
    relation = _object(value, context)
    kind = relation.get("relation")
    if kind not in _RELATION_KINDS:
        raise StageAInputError(f"{context} has unsupported relation kind")
    expected = {"register", "relation"}
    if kind == "fixed_word":
        expected.add("value")
    if kind == "fixed_code_pointer":
        expected.add("target_id")
    _exact_fields(relation, expected, context)
    register = relation["register"]
    if register not in REGISTER_ORDER:
        raise StageAInputError(f"{context} has unsupported register")
    if kind == "fixed_word" and not (
        isinstance(relation["value"], int)
        and not isinstance(relation["value"], bool)
        and 0 <= relation["value"] < 2**32
    ):
        raise StageAInputError(f"{context}.value must be a PE32 word")
    if kind == "fixed_code_pointer" and not (
        isinstance(relation["target_id"], int)
        and not isinstance(relation["target_id"], bool)
        and relation["target_id"] >= 0
    ):
        raise StageAInputError(f"{context}.target_id must be nonnegative")
    return relation


def _relations(value: object, context: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    relations = [
        _relation(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    ]
    if [item["register"] for item in relations] != list(REGISTER_ORDER):
        raise StageAInputError(
            f"{context} must cover each PE32 register in canonical order"
        )
    return relations


def register_transfer_observation_sha256(
    *,
    input_relations: Sequence[Mapping[str, Any]],
    fixed_immutable_probe: Sequence[Mapping[str, Any]],
) -> str:
    return _canonical_sha256({
        "format": "stage-a-register-transfer-observation-v1",
        "input_relations": list(input_relations),
        "fixed_immutable_probe": list(fixed_immutable_probe),
    })


def register_transfer_semantics_sha256(
    *, context_sha256: str, observation_sha256: Sequence[str],
) -> str:
    return _canonical_sha256({
        "format": "stage-a-register-transfer-semantics-v1",
        "context_sha256": context_sha256,
        "observations": sorted(observation_sha256),
    })


def register_transfer_table_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    graph_sha256: str,
    regions: Sequence[Mapping[str, Any]],
    propagation: Mapping[str, Any],
) -> dict[str, Any]:
    payload = {
        "format": REGISTER_TRANSFER_TABLE_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": REGISTER_TRANSFER_TABLE_STATUS,
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "graph_sha256": graph_sha256,
        "region_count": len(regions),
        "regions": [dict(region) for region in regions],
        "propagation": dict(propagation),
    }
    parse_register_transfer_table(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_graph_sha256=graph_sha256,
    )
    return payload


def parse_register_transfer_table(
    payload: object,
    *,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_graph_sha256: str,
) -> RegisterTransferTable:
    table = _object(payload, "register transfer table")
    _exact_fields(table, {
        "format",
        "profile",
        "model",
        "status",
        "acceptance_authority",
        "original_sha256",
        "candidate_sha256",
        "graph_sha256",
        "region_count",
        "regions",
        "propagation",
    }, "register transfer table")
    expected = {
        "format": REGISTER_TRANSFER_TABLE_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": REGISTER_TRANSFER_TABLE_STATUS,
        "acceptance_authority": False,
        "original_sha256": _sha256(
            expected_original_sha256, "expected original SHA-256"
        ),
        "candidate_sha256": _sha256(
            expected_candidate_sha256, "expected candidate SHA-256"
        ),
        "graph_sha256": _sha256(
            expected_graph_sha256, "expected dataflow graph SHA-256"
        ),
    }
    for field, value in expected.items():
        if table[field] != value:
            raise StageAInputError(
                f"register transfer table {field} does not match"
            )
    raw_regions = table["regions"]
    if not isinstance(raw_regions, list):
        raise StageAInputError("register transfer table regions must be a list")
    if table["region_count"] != len(raw_regions):
        raise StageAInputError("register transfer table region count mismatch")

    regions: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for region_index, raw_region in enumerate(raw_regions):
        context = f"register transfer region {region_index}"
        region = _object(raw_region, context)
        _exact_fields(region, {
            "id",
            "context_sha256",
            "transfer_semantics_sha256",
            "observations",
        }, context)
        region_id = region["id"]
        if not isinstance(region_id, str) or not region_id:
            raise StageAInputError(f"{context}.id must be a non-empty string")
        if region_id in seen_ids:
            raise StageAInputError("register transfer region IDs must be unique")
        seen_ids.add(region_id)
        context_sha256 = _sha256(
            region["context_sha256"], f"{context}.context_sha256"
        )
        raw_observations = region["observations"]
        if not isinstance(raw_observations, list) or not raw_observations:
            raise StageAInputError(f"{context}.observations must be non-empty")
        observations = []
        seen_observations: set[str] = set()
        for observation_index, raw_observation in enumerate(raw_observations):
            observation_context = f"{context} observation {observation_index}"
            observation = _object(raw_observation, observation_context)
            _exact_fields(observation, {
                "sha256",
                "input_relations",
                "fixed_immutable_probe",
                "output_relations",
                "reasons",
            }, observation_context)
            input_relations = _relations(
                observation["input_relations"],
                f"{observation_context}.input_relations",
            )
            output_relations = _relations(
                observation["output_relations"],
                f"{observation_context}.output_relations",
            )
            fixed_probe = observation["fixed_immutable_probe"]
            if not isinstance(fixed_probe, list) or not all(
                isinstance(item, dict) for item in fixed_probe
            ):
                raise StageAInputError(
                    f"{observation_context}.fixed_immutable_probe must be a list"
                )
            reasons = _object(
                observation["reasons"], f"{observation_context}.reasons"
            )
            if set(reasons) != set(REGISTER_ORDER) or not all(
                isinstance(reason, str) and reason for reason in reasons.values()
            ):
                raise StageAInputError(
                    f"{observation_context}.reasons must cover every register"
                )
            observation_sha256 = _sha256(
                observation["sha256"], f"{observation_context}.sha256"
            )
            expected_observation_sha256 = (
                register_transfer_observation_sha256(
                    input_relations=input_relations,
                    fixed_immutable_probe=fixed_probe,
                )
            )
            if observation_sha256 != expected_observation_sha256:
                raise StageAInputError(
                    f"{observation_context} digest does not match its inputs"
                )
            if observation_sha256 in seen_observations:
                raise StageAInputError(
                    f"{context} contains duplicate transfer observations"
                )
            seen_observations.add(observation_sha256)
            observations.append({
                "sha256": observation_sha256,
                "input_relations": input_relations,
                "fixed_immutable_probe": fixed_probe,
                "output_relations": output_relations,
                "reasons": reasons,
            })
        expected_semantics_sha256 = register_transfer_semantics_sha256(
            context_sha256=context_sha256,
            observation_sha256=sorted(seen_observations),
        )
        if _sha256(
            region["transfer_semantics_sha256"],
            f"{context}.transfer_semantics_sha256",
        ) != expected_semantics_sha256:
            raise StageAInputError(
                f"{context} transfer semantics digest does not match"
            )
        regions.append({
            "id": region_id,
            "context_sha256": context_sha256,
            "transfer_semantics_sha256": expected_semantics_sha256,
            "observations": observations,
        })
    propagation = _object(
        table["propagation"], "register transfer propagation"
    )
    _exact_fields(
        propagation,
        {"regions", "edges"},
        "register transfer propagation",
    )
    propagation_regions = propagation["regions"]
    if not isinstance(propagation_regions, list):
        raise StageAInputError("register propagation regions must be a list")
    expected_region_ids = [region["id"] for region in regions]
    normalized_propagation_regions = []
    for index, raw_region in enumerate(propagation_regions):
        context = f"register propagation region {index}"
        region = _object(raw_region, context)
        _exact_fields(
            region,
            {"id", "seed_relation", "stack_window_registers"},
            context,
        )
        seed_relation = region["seed_relation"]
        if seed_relation not in {None, "exact", "related_word"}:
            raise StageAInputError(f"{context}.seed_relation is unsupported")
        stack_registers = region["stack_window_registers"]
        if (
            not isinstance(stack_registers, list)
            or stack_registers != sorted(set(stack_registers))
            or any(register not in REGISTER_ORDER for register in stack_registers)
        ):
            raise StageAInputError(
                f"{context}.stack_window_registers must be canonical"
            )
        normalized_propagation_regions.append({
            "id": region["id"],
            "seed_relation": seed_relation,
            "stack_window_registers": stack_registers,
        })
    if [region["id"] for region in normalized_propagation_regions] != (
        expected_region_ids
    ):
        raise StageAInputError(
            "register propagation region inventory does not match transfers"
        )

    raw_edges = propagation["edges"]
    if not isinstance(raw_edges, list):
        raise StageAInputError("register propagation edges must be a list")
    normalized_edges = []
    seen_edges: set[str] = set()
    valid_region_ids = set(expected_region_ids)
    for edge_index, raw_edge in enumerate(raw_edges):
        context = f"register propagation edge {edge_index}"
        edge = _object(raw_edge, context)
        _exact_fields(edge, {
            "source_id",
            "target_id",
            "environment_barrier",
            "kind",
            "preserved_registers",
            "result_relations",
        }, context)
        if (
            edge["source_id"] not in valid_region_ids
            or edge["target_id"] not in valid_region_ids
        ):
            raise StageAInputError(f"{context} references an unknown region")
        if not isinstance(edge["environment_barrier"], bool):
            raise StageAInputError(
                f"{context}.environment_barrier must be Boolean"
            )
        if not isinstance(edge["kind"], str) or not edge["kind"]:
            raise StageAInputError(f"{context}.kind must be non-empty")
        preserved = edge["preserved_registers"]
        if (
            not isinstance(preserved, list)
            or preserved != sorted(set(preserved))
            or any(register not in REGISTER_ORDER for register in preserved)
        ):
            raise StageAInputError(
                f"{context}.preserved_registers must be canonical"
            )
        raw_results = edge["result_relations"]
        if not isinstance(raw_results, list):
            raise StageAInputError(f"{context}.result_relations must be a list")
        results = [
            _relation(result, f"{context}.result_relations[{index}]")
            for index, result in enumerate(raw_results)
        ]
        result_registers = [result["register"] for result in results]
        if result_registers != sorted(
            set(result_registers), key=REGISTER_ORDER.index
        ):
            raise StageAInputError(
                f"{context}.result_relations must be canonical"
            )
        normalized = {
            "source_id": edge["source_id"],
            "target_id": edge["target_id"],
            "environment_barrier": edge["environment_barrier"],
            "kind": edge["kind"],
            "preserved_registers": preserved,
            "result_relations": results,
        }
        key = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        if key in seen_edges:
            raise StageAInputError("register propagation edges must be unique")
        seen_edges.add(key)
        normalized_edges.append(normalized)
    if normalized_edges != sorted(
        normalized_edges,
        key=lambda edge: (
            edge["target_id"], edge["source_id"], edge["kind"],
            json.dumps(edge, sort_keys=True, separators=(",", ":")),
        ),
    ):
        raise StageAInputError("register propagation edges must be canonical")
    return RegisterTransferTable(
        regions=tuple(regions),
        propagation_regions=tuple(normalized_propagation_regions),
        propagation_edges=tuple(normalized_edges),
    )


__all__ = [
    "REGISTER_ORDER",
    "RegisterTransferTable",
    "REGISTER_TRANSFER_TABLE_FORMAT",
    "REGISTER_TRANSFER_TABLE_STATUS",
    "parse_register_transfer_table",
    "register_transfer_observation_sha256",
    "register_transfer_semantics_sha256",
    "register_transfer_table_payload",
]
