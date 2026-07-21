from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from ...stage_binary import StageAInputError
from ..analyses.affine_linked_control import AFFINE_LINKED_CONTROL_FORMAT
from ..artifacts import write_text_if_changed
from .common import _lean_register_relation_pair
from .expressions import (
    _lean_external_target,
    _lean_register_offset_witness,
    _lean_return_slot_offset_pair,
    _lean_semantic_expr,
    _lean_stack_window,
)


AFFINE_LINKED_CONTROL_MODULE = "RelationalAffineLinkedControl"
AFFINE_LINKED_CONTROL_BINDINGS_MODULE = "RelationalAffineLinkedControlBindings"
AFFINE_LINKED_MEMORY_BINDINGS_MODULE = "RelationalAffineLinkedMemoryBindings"
AFFINE_LINKED_CALL_BINDINGS_MODULE = "RelationalAffineLinkedCallBindings"
AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE = (
    "RelationalAffineLinkedExternalCallBindings"
)
_WORD_MODULUS = 2**32
_REGISTERS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
_RELATIONS = frozenset((
    "exact",
    "fixed_word",
    "code_pointer",
    "fixed_code_pointer",
    "data_pointer",
    "related_word",
))


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{field} must be a list")
    return value


def _keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] = frozenset(),
    field: str,
) -> None:
    missing = sorted(required - value.keys())
    unexpected = sorted(value.keys() - required - optional)
    if missing:
        raise StageAInputError(f"{field} is missing fields: {', '.join(missing)}")
    if unexpected:
        raise StageAInputError(
            f"{field} has unsupported fields: {', '.join(unexpected)}"
        )


def _natural(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{field} must be a natural number")
    return value


def _word(value: object, field: str) -> int:
    result = _natural(value, field)
    if result >= _WORD_MODULUS:
        raise StageAInputError(f"{field} must fit in a 32-bit word")
    return result


def _register(value: object, field: str) -> str:
    if not isinstance(value, str) or value not in _REGISTERS:
        raise StageAInputError(f"{field} must be an IA-32 general register")
    return str(value)


def _canonical_rows(value: object, field: str) -> list[Mapping[str, Any]]:
    rows = [_mapping(row, f"{field} row") for row in _list(value, field)]
    ids = [_natural(row.get("id"), f"{field} id") for row in rows]
    if ids != list(range(len(rows))):
        raise StageAInputError(f"{field} ids must be canonical and contiguous")
    return rows


def _normalized_key(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _require_nodup(values: list[dict[str, Any]], field: str) -> None:
    keys = [_normalized_key(value) for value in values]
    if len(set(keys)) != len(keys):
        raise StageAInputError(f"{field} must not contain duplicates")


def _location(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    _keys(
        row,
        required={"original_register", "original", "candidate_register", "candidate"},
        field=field,
    )
    return {
        "original_register": _register(
            row["original_register"], f"{field} original_register"
        ),
        "original": _word(row["original"], f"{field} original offset"),
        "candidate_register": _register(
            row["candidate_register"], f"{field} candidate_register"
        ),
        "candidate": _word(row["candidate"], f"{field} candidate offset"),
    }


def _return_summary_claim(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    witness_fields = {
        "original_call_witness",
        "candidate_call_witness",
        "original_return_slot_witness",
        "candidate_return_slot_witness",
        "original_return_output_witness",
        "candidate_return_output_witness",
    }
    _keys(
        row,
        required={
            "profile", "source", "target", "return_region_index",
            "pop_bytes", *witness_fields,
        },
        field=field,
    )
    if row["profile"] != "return_slot_call_summary_v1":
        raise StageAInputError(f"{field} has an unsupported profile")
    result = {
        "profile": str(row["profile"]),
        "source": _location(row["source"], f"{field} source"),
        "target": _location(row["target"], f"{field} target"),
        "return_region_index": _natural(
            row["return_region_index"], f"{field} return_region_index"
        ),
        "pop_bytes": _natural(row["pop_bytes"], f"{field} pop_bytes"),
    }
    for witness_field in sorted(witness_fields):
        result[witness_field] = dict(_mapping(
            row[witness_field], f"{field} {witness_field}"
        ))
    return result


def _external_return_summary_claim(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    _keys(
        row,
        required={
            "profile", "machine_contract_id", "thunk_region_index",
            "continuation_region_index", "source", "suspended", "target",
            "original_call_witness", "candidate_call_witness", "thunk_transfer",
        },
        field=field,
    )
    if row["profile"] != "external_return_slot_call_summary_v1":
        raise StageAInputError(f"{field} has an unsupported profile")
    thunk_transfer = _mapping(
        row["thunk_transfer"], f"{field} thunk_transfer"
    )
    _keys(
        thunk_transfer,
        required={
            "source", "internal_target", "boundary_target", "internal_rule",
            "result_rule", "memory_claim",
        },
        field=f"{field} thunk_transfer",
    )
    internal_rule = _mapping(
        thunk_transfer["internal_rule"], f"{field} thunk internal_rule"
    )
    _keys(
        internal_rule,
        required={
            "original_source_register", "candidate_source_register",
            "original_target_register", "candidate_target_register",
            "original_output_witness", "candidate_output_witness",
            "original_delta", "candidate_delta",
        },
        field=f"{field} thunk internal_rule",
    )
    result_rule = _mapping(
        thunk_transfer["result_rule"], f"{field} thunk result_rule"
    )
    _keys(
        result_rule,
        required={"source", "target", "original_delta", "candidate_delta"},
        field=f"{field} thunk result_rule",
    )
    memory = _mapping(
        thunk_transfer["memory_claim"], f"{field} thunk memory_claim"
    )
    _keys(
        memory,
        required={
            "offsets", "original_write_witnesses",
            "candidate_write_witnesses",
        },
        field=f"{field} thunk memory_claim",
    )
    return {
        "profile": str(row["profile"]),
        "machine_contract_id": _natural(
            row["machine_contract_id"], f"{field} machine_contract_id"
        ),
        "thunk_region_index": _natural(
            row["thunk_region_index"], f"{field} thunk_region_index"
        ),
        "continuation_region_index": _natural(
            row["continuation_region_index"],
            f"{field} continuation_region_index",
        ),
        "source": _location(row["source"], f"{field} source"),
        "suspended": _location(row["suspended"], f"{field} suspended"),
        "target": _location(row["target"], f"{field} target"),
        "original_call_witness": dict(_mapping(
            row["original_call_witness"], f"{field} original_call_witness"
        )),
        "candidate_call_witness": dict(_mapping(
            row["candidate_call_witness"], f"{field} candidate_call_witness"
        )),
        "thunk_transfer": {
            "source": _location(
                thunk_transfer["source"], f"{field} thunk source"
            ),
            "internal_target": _location(
                thunk_transfer["internal_target"],
                f"{field} thunk internal_target",
            ),
            "boundary_target": _location(
                thunk_transfer["boundary_target"],
                f"{field} thunk boundary_target",
            ),
            "internal_rule": {
                "original_source_register": _register(
                    internal_rule["original_source_register"],
                    f"{field} thunk original_source_register",
                ),
                "candidate_source_register": _register(
                    internal_rule["candidate_source_register"],
                    f"{field} thunk candidate_source_register",
                ),
                "original_target_register": _register(
                    internal_rule["original_target_register"],
                    f"{field} thunk original_target_register",
                ),
                "candidate_target_register": _register(
                    internal_rule["candidate_target_register"],
                    f"{field} thunk candidate_target_register",
                ),
                "original_output_witness": dict(_mapping(
                    internal_rule["original_output_witness"],
                    f"{field} thunk original_output_witness",
                )),
                "candidate_output_witness": dict(_mapping(
                    internal_rule["candidate_output_witness"],
                    f"{field} thunk candidate_output_witness",
                )),
                "original_delta": _word(
                    internal_rule["original_delta"],
                    f"{field} thunk original_delta",
                ),
                "candidate_delta": _word(
                    internal_rule["candidate_delta"],
                    f"{field} thunk candidate_delta",
                ),
            },
            "result_rule": {
                "source": _location(
                    result_rule["source"], f"{field} thunk result source"
                ),
                "target": _location(
                    result_rule["target"], f"{field} thunk result target"
                ),
                "original_delta": _natural(
                    result_rule["original_delta"],
                    f"{field} thunk result original_delta",
                ),
                "candidate_delta": _natural(
                    result_rule["candidate_delta"],
                    f"{field} thunk result candidate_delta",
                ),
            },
            "memory_claim": {
                "offsets": _location(
                    memory["offsets"], f"{field} thunk memory offsets"
                ),
                "original_write_witnesses": [
                    dict(_mapping(witness, f"{field} original write witness"))
                    for witness in _list(
                        memory["original_write_witnesses"],
                        f"{field} original write witnesses",
                    )
                ],
                "candidate_write_witnesses": [
                    dict(_mapping(witness, f"{field} candidate write witness"))
                    for witness in _list(
                        memory["candidate_write_witnesses"],
                        f"{field} candidate write witnesses",
                    )
                ],
            },
        },
    }


def _exact_word(value: object, field: str) -> dict[str, int]:
    row = _mapping(value, field)
    _keys(row, required={"original", "candidate"}, field=field)
    original = _natural(row["original"], f"{field} original offset")
    candidate = _natural(row["candidate"], f"{field} candidate offset")
    if original > 65532 or candidate > 65532:
        raise StageAInputError(f"{field} offsets must be at most 65532")
    return {"original": original, "candidate": candidate}


def _import_target(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    if not isinstance(row.get("dll"), str) or not row["dll"]:
        raise StageAInputError(f"{field} dll must be a nonempty string")
    has_symbol = "symbol" in row
    has_ordinal = "ordinal" in row
    if has_symbol == has_ordinal:
        raise StageAInputError(f"{field} must contain exactly one of symbol or ordinal")
    _keys(
        row,
        required={"dll", "symbol"} if has_symbol else {"dll", "ordinal"},
        field=field,
    )
    if has_symbol:
        if not isinstance(row["symbol"], str) or not row["symbol"]:
            raise StageAInputError(f"{field} symbol must be a nonempty string")
        return {"dll": row["dll"], "symbol": row["symbol"]}
    ordinal = _natural(row["ordinal"], f"{field} ordinal")
    if ordinal > 65535:
        raise StageAInputError(f"{field} ordinal must fit in 16 bits")
    return {"dll": row["dll"], "ordinal": ordinal}


def _import_relation(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    _keys(row, required={"original", "candidate", "import"}, field=field)
    return {
        "original": _register(row["original"], f"{field} original register"),
        "candidate": _register(row["candidate"], f"{field} candidate register"),
        "import": _import_target(row["import"], f"{field} import"),
    }


def _register_relation(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    relation = row.get("relation")
    if relation not in _RELATIONS:
        raise StageAInputError(f"{field} has unsupported relation {relation!r}")
    optional = {"value"} if relation == "fixed_word" else (
        {"target_id"} if relation == "fixed_code_pointer" else set()
    )
    _keys(
        row,
        required={"original", "candidate", "relation"} | optional,
        field=field,
    )
    result: dict[str, Any] = {
        "original": _register(row["original"], f"{field} original register"),
        "candidate": _register(row["candidate"], f"{field} candidate register"),
        "relation": relation,
    }
    if relation == "fixed_word":
        result["value"] = _word(row["value"], f"{field} fixed value")
    elif relation == "fixed_code_pointer":
        result["target_id"] = _natural(
            row["target_id"], f"{field} fixed code target"
        )
    return result


def _bounded_payload_list(
    value: object,
    *,
    field: str,
    maximum: int,
    normalize: Any,
) -> list[dict[str, Any]]:
    rows = [normalize(row, f"{field} row") for row in _list(value, field)]
    if len(rows) > maximum:
        raise StageAInputError(f"{field} exceeds the checked bound of {maximum}")
    _require_nodup(rows, field)
    return rows


def _inventory_shape(
    value: object,
    field: str,
    affine_indexes: dict[int, int],
    artifact_indexes: dict[int, int],
) -> dict[str, Any]:
    row = _mapping(value, field)
    _keys(
        row,
        required={"locations"},
        optional={"exact_words", "preserved_imports", "preserved_relations"},
        field=field,
    )
    locations_row = _mapping(row["locations"], f"{field} locations")
    kind = locations_row.get("kind")
    if kind == "exact":
        _keys(
            locations_row,
            required={"kind", "locations"},
            field=f"{field} locations",
        )
        locations = _bounded_payload_list(
            locations_row["locations"],
            field=f"{field} exact locations",
            maximum=8,
            normalize=_location,
        )
        if not locations:
            raise StageAInputError(f"{field} exact locations must be nonempty")
        location_shape: dict[str, Any] = {"kind": "exact", "locations": locations}
    elif kind == "affine_family":
        _keys(
            locations_row,
            required={"kind", "artifact_state_id", "profile_state_index"},
            field=f"{field} locations",
        )
        artifact_id = _natural(
            locations_row["artifact_state_id"], f"{field} artifact_state_id"
        )
        profile_index = _natural(
            locations_row["profile_state_index"], f"{field} profile_state_index"
        )
        if (
            profile_index in affine_indexes
            and affine_indexes[profile_index] != artifact_id
        ) or (
            artifact_id in artifact_indexes
            and artifact_indexes[artifact_id] != profile_index
        ):
            raise StageAInputError(
                f"{field} has an inconsistent affine artifact/profile state mapping"
            )
        affine_indexes[profile_index] = artifact_id
        artifact_indexes[artifact_id] = profile_index
        location_shape = {
            "kind": "affine_family",
            "artifact_state_id": artifact_id,
            "profile_state_index": profile_index,
        }
    else:
        raise StageAInputError(f"{field} has unsupported location kind {kind!r}")

    exact_words = _bounded_payload_list(
        row.get("exact_words", []),
        field=f"{field} exact_words",
        maximum=16,
        normalize=_exact_word,
    )
    imports = _bounded_payload_list(
        row.get("preserved_imports", []),
        field=f"{field} preserved_imports",
        maximum=8,
        normalize=_import_relation,
    )
    relations = _bounded_payload_list(
        row.get("preserved_relations", []),
        field=f"{field} preserved_relations",
        maximum=8,
        normalize=_register_relation,
    )
    return {
        "locations": location_shape,
        "exact_words": exact_words,
        "preserved_imports": imports,
        "preserved_relations": relations,
    }


def _fallback(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    _keys(
        row,
        required={"owner", "node_id", "reason", "candidate_family_ids"},
        field=field,
    )
    if not isinstance(row["owner"], str) or not row["owner"]:
        raise StageAInputError(f"{field} owner must be a nonempty string")
    if row["reason"] not in {
        "non_singleton_inventory",
        "no_unique_rooted_affine_family",
    }:
        raise StageAInputError(f"{field} has unsupported reason {row['reason']!r}")
    candidates = [
        _natural(item, f"{field} candidate family id")
        for item in _list(row["candidate_family_ids"], f"{field} candidate family ids")
    ]
    if candidates != sorted(set(candidates)):
        raise StageAInputError(f"{field} candidate family ids must be canonical")
    return {
        "owner": row["owner"],
        "node_id": _natural(row["node_id"], f"{field} node_id"),
        "reason": row["reason"],
        "candidate_family_ids": candidates,
    }


def _validated_payload(payload: object) -> dict[str, Any]:
    root = _mapping(payload, "affine linked control payload")
    required_root_fields = {
        "format",
        "status",
        "acceptance_authority",
        "states",
        "links",
        "gaps",
        "exact_fallbacks",
        "counts",
    }
    missing_root_fields = sorted(required_root_fields - root.keys())
    if missing_root_fields:
        raise StageAInputError(
            "affine linked control payload is missing fields: "
            + ", ".join(missing_root_fields)
        )
    if root["format"] != AFFINE_LINKED_CONTROL_FORMAT:
        raise StageAInputError("unsupported affine linked control payload format")
    if not isinstance(root["status"], str) or not root["status"]:
        raise StageAInputError("affine linked control status must be a nonempty string")
    if "shape_projection_status" in root and (
        not isinstance(root["shape_projection_status"], str)
        or not root["shape_projection_status"]
    ):
        raise StageAInputError(
            "affine linked shape_projection_status must be a nonempty string"
        )
    if "control_closure_status" in root and (
        not isinstance(root["control_closure_status"], str)
        or not root["control_closure_status"]
    ):
        raise StageAInputError(
            "affine linked control_closure_status must be a nonempty string"
        )
    if "control_closure_coverage" in root:
        _mapping(
            root["control_closure_coverage"],
            "affine linked control_closure_coverage",
        )
    if "coverage_gaps" in root:
        _mapping(root["coverage_gaps"], "affine linked coverage_gaps")
    if "transition_bindings" in root:
        _list(root["transition_bindings"], "affine linked transition_bindings")
    if "transition_binding_gaps" in root:
        _list(
            root["transition_binding_gaps"],
            "affine linked transition_binding_gaps",
        )
    if root["acceptance_authority"] is not False:
        raise StageAInputError(
            "affine linked control payload must not claim acceptance authority"
        )
    gaps = _list(root["gaps"], "affine linked control gaps")
    if gaps:
        raise StageAInputError("affine linked control payload contains unresolved gaps")

    affine_indexes: dict[int, int] = {}
    artifact_indexes: dict[int, int] = {}
    states: list[dict[str, Any]] = []
    for raw in _canonical_rows(root["states"], "affine linked control states"):
        _keys(
            raw,
            required={
                "id",
                "node_id",
                "continuation_target_id",
                "active_shape",
                "minimum_depth",
            },
            field="affine linked control state",
        )
        continuation = raw["continuation_target_id"]
        active = raw["active_shape"]
        if (continuation is None) != (active is None):
            raise StageAInputError(
                "affine linked state continuation and active shape must appear together"
            )
        minimum_depth = _natural(
            raw["minimum_depth"], "affine linked state minimum_depth"
        )
        if active is None and minimum_depth != 0:
            raise StageAInputError("inactive affine linked state must have depth zero")
        if active is not None and minimum_depth == 0:
            raise StageAInputError("active affine linked state must have positive depth")
        states.append({
            "id": _natural(raw["id"], "affine linked state id"),
            "node_id": _natural(raw["node_id"], "affine linked state node_id"),
            "continuation_target_id": (
                None
                if continuation is None
                else _natural(continuation, "affine linked state continuation")
            ),
            "active_shape": (
                None
                if active is None
                else _inventory_shape(
                    active,
                    "affine linked state active shape",
                    affine_indexes,
                    artifact_indexes,
                )
            ),
            "minimum_depth": minimum_depth,
        })
    _require_nodup(
        [{key: value for key, value in row.items() if key != "id"} for row in states],
        "affine linked control states",
    )

    minimal_states: list[dict[str, Any]] = []
    for raw in _canonical_rows(
        root.get("minimal_active_states", []),
        "minimal affine active control states",
    ):
        _keys(
            raw,
            required={
                "id",
                "affine_state_id",
                "node_id",
                "continuation_target_id",
                "active_shape",
                "minimum_depth",
                "seed_ids",
            },
            field="minimal affine active control state",
        )
        minimum_depth = _natural(
            raw["minimum_depth"], "minimal affine control state minimum_depth"
        )
        if minimum_depth == 0:
            raise StageAInputError(
                "minimal affine active control state must have positive depth"
            )
        seed_ids = [
            _natural(item, "minimal affine control state seed id")
            for item in _list(raw["seed_ids"], "minimal affine control state seed_ids")
        ]
        if seed_ids != sorted(set(seed_ids)):
            raise StageAInputError(
                "minimal affine control state seed ids must be canonical"
            )
        minimal_states.append({
            "id": _natural(raw["id"], "minimal affine control state id"),
            "affine_state_id": _natural(
                raw["affine_state_id"], "minimal affine artifact state id"
            ),
            "node_id": _natural(
                raw["node_id"], "minimal affine control state node_id"
            ),
            "continuation_target_id": _natural(
                raw["continuation_target_id"],
                "minimal affine control state continuation",
            ),
            "active_shape": _inventory_shape(
                raw["active_shape"],
                "minimal affine control state active shape",
                affine_indexes,
                artifact_indexes,
            ),
            "minimum_depth": minimum_depth,
            "seed_ids": seed_ids,
        })
    _require_nodup(
        [
            {key: value for key, value in row.items() if key not in {"id", "seed_ids"}}
            for row in minimal_states
        ],
        "minimal affine active control states",
    )

    minimal_state_by_id = {int(state["id"]): state for state in minimal_states}
    minimal_bindings: list[dict[str, Any]] = []
    for raw in _canonical_rows(
        root.get("minimal_transition_bindings", []),
        "minimal affine control transition bindings",
    ):
        _keys(
            raw,
            required={
                "id",
                "transition_id",
                "edge_id",
                "source_control_state_id",
                "target_control_state_id",
                "continuation_target_id",
                "source_shape",
                "target_shape",
                "profile",
            },
            field="minimal affine control transition binding",
        )
        if raw["profile"] != "ordinary_no_write_affine_control_v1":
            raise StageAInputError(
                "minimal affine control transition binding has an unsupported profile"
            )
        source_id = _natural(
            raw["source_control_state_id"],
            "minimal affine transition source control state id",
        )
        target_id = _natural(
            raw["target_control_state_id"],
            "minimal affine transition target control state id",
        )
        source_state = minimal_state_by_id.get(source_id)
        target_state = minimal_state_by_id.get(target_id)
        if source_state is None or target_state is None:
            raise StageAInputError(
                "minimal affine transition binding references an unknown control state"
            )
        continuation = _natural(
            raw["continuation_target_id"],
            "minimal affine transition continuation target id",
        )
        if (
            source_state["continuation_target_id"] != continuation
            or target_state["continuation_target_id"] != continuation
        ):
            raise StageAInputError(
                "minimal affine transition binding changes its continuation"
            )
        source_shape = _inventory_shape(
            raw["source_shape"],
            "minimal affine transition source shape",
            affine_indexes,
            artifact_indexes,
        )
        target_shape = _inventory_shape(
            raw["target_shape"],
            "minimal affine transition target shape",
            affine_indexes,
            artifact_indexes,
        )
        if (
            source_state["active_shape"] != source_shape
            or target_state["active_shape"] != target_shape
        ):
            raise StageAInputError(
                "minimal affine transition binding shapes do not match its control states"
            )
        minimal_bindings.append({
            "id": _natural(raw["id"], "minimal affine transition binding id"),
            "transition_id": _natural(
                raw["transition_id"], "minimal affine transition id"
            ),
            "edge_id": _natural(raw["edge_id"], "minimal affine transition edge id"),
            "source_control_state_id": source_id,
            "target_control_state_id": target_id,
            "continuation_target_id": continuation,
            "source_shape": source_shape,
            "target_shape": target_shape,
            "profile": raw["profile"],
        })
    _require_nodup(
        [{key: value for key, value in row.items() if key != "id"}
         for row in minimal_bindings],
        "minimal affine control transition bindings",
    )
    semantic_shapes: dict[int, tuple[str, str]] = {}
    for binding in minimal_bindings:
        transition_id = int(binding["transition_id"])
        shapes = (
            _normalized_key(binding["source_shape"]),
            _normalized_key(binding["target_shape"]),
        )
        previous = semantic_shapes.setdefault(transition_id, shapes)
        if previous != shapes:
            raise StageAInputError(
                "one affine semantic transition has inconsistent inventory shapes"
            )

    minimal_memory_bindings: list[dict[str, Any]] = []
    for raw in _canonical_rows(
        root.get("minimal_memory_transition_bindings", []),
        "minimal affine memory transition bindings",
    ):
        _keys(
            raw,
            required={
                "id",
                "transition_id",
                "edge_id",
                "source_control_state_id",
                "target_control_state_id",
                "continuation_target_id",
                "source_shape",
                "target_shape",
                "writes",
                "profile",
            },
            field="minimal affine memory transition binding",
        )
        if raw["profile"] != "ordinary_paired_write_affine_control_v1":
            raise StageAInputError(
                "minimal affine memory transition binding has an unsupported profile"
            )
        source_id = _natural(
            raw["source_control_state_id"],
            "minimal affine memory transition source control state id",
        )
        target_id = _natural(
            raw["target_control_state_id"],
            "minimal affine memory transition target control state id",
        )
        source_state = minimal_state_by_id.get(source_id)
        target_state = minimal_state_by_id.get(target_id)
        if source_state is None or target_state is None:
            raise StageAInputError(
                "minimal affine memory transition binding references an unknown "
                "control state"
            )
        continuation = _natural(
            raw["continuation_target_id"],
            "minimal affine memory transition continuation target id",
        )
        if (
            source_state["continuation_target_id"] != continuation
            or target_state["continuation_target_id"] != continuation
        ):
            raise StageAInputError(
                "minimal affine memory transition binding changes its continuation"
            )
        source_shape = _inventory_shape(
            raw["source_shape"],
            "minimal affine memory transition source shape",
            affine_indexes,
            artifact_indexes,
        )
        target_shape = _inventory_shape(
            raw["target_shape"],
            "minimal affine memory transition target shape",
            affine_indexes,
            artifact_indexes,
        )
        if (
            source_state["active_shape"] != source_shape
            or target_state["active_shape"] != target_shape
        ):
            raise StageAInputError(
                "minimal affine memory transition binding shapes do not match its "
                "control states"
            )
        writes: list[dict[str, Any]] = []
        for write_index, value in enumerate(
            _list(raw["writes"], "minimal affine paired writes")
        ):
            write = _mapping(value, f"minimal affine paired write {write_index}")
            _keys(
                write,
                required={
                    "original_address",
                    "original_value",
                    "candidate_address",
                    "candidate_value",
                },
                field=f"minimal affine paired write {write_index}",
            )
            normalized_write: dict[str, Any] = {}
            for key in (
                "original_address",
                "original_value",
                "candidate_address",
                "candidate_value",
            ):
                expression = dict(_mapping(
                    write[key], f"minimal affine paired write {write_index} {key}"
                ))
                _lean_semantic_expr(expression)
                normalized_write[key] = expression
            writes.append(normalized_write)
        if not writes:
            raise StageAInputError(
                "minimal affine memory transition binding must contain writes"
            )
        minimal_memory_bindings.append({
            "id": _natural(raw["id"], "minimal affine memory transition binding id"),
            "transition_id": _natural(
                raw["transition_id"], "minimal affine memory transition id"
            ),
            "edge_id": _natural(
                raw["edge_id"], "minimal affine memory transition edge id"
            ),
            "source_control_state_id": source_id,
            "target_control_state_id": target_id,
            "continuation_target_id": continuation,
            "source_shape": source_shape,
            "target_shape": target_shape,
            "writes": writes,
            "profile": raw["profile"],
        })
    _require_nodup(
        [
            {key: value for key, value in row.items() if key != "id"}
            for row in minimal_memory_bindings
        ],
        "minimal affine memory transition bindings",
    )

    link_keys = {
        "id",
        "call_edge_id",
        "call_source_node_id",
        "call_source_target_id",
        "inner_inventory_node_id",
        "suspended_inventory_node_id",
        "resume_inventory_node_id",
        "resume_target_id",
        "resume_continuation",
        "inner_shape",
        "suspended_shape",
        "resume_shape",
        "original_gap",
        "candidate_gap",
    }
    def validated_link(
        raw: Mapping[str, Any], field: str
    ) -> dict[str, Any]:
        _keys(raw, required=link_keys, field=field)
        original_gap = _natural(raw["original_gap"], f"{field} original_gap")
        candidate_gap = _natural(raw["candidate_gap"], f"{field} candidate_gap")
        if not 4 <= original_gap < _WORD_MODULUS:
            raise StageAInputError(f"{field} original_gap is outside checked bounds")
        if not 4 <= candidate_gap < _WORD_MODULUS:
            raise StageAInputError(f"{field} candidate_gap is outside checked bounds")
        return {
            "id": _natural(raw["id"], f"{field} id"),
            "call_edge_id": _natural(raw["call_edge_id"], f"{field} call_edge_id"),
            "call_source_node_id": _natural(
                raw["call_source_node_id"], f"{field} call source node"
            ),
            "call_source_target_id": _natural(
                raw["call_source_target_id"], f"{field} call source target"
            ),
            "inner_inventory_node_id": _natural(
                raw["inner_inventory_node_id"], f"{field} inner inventory node"
            ),
            "suspended_inventory_node_id": _natural(
                raw["suspended_inventory_node_id"],
                f"{field} suspended inventory node",
            ),
            "resume_inventory_node_id": _natural(
                raw["resume_inventory_node_id"], f"{field} resume inventory node"
            ),
            "resume_target_id": _natural(
                raw["resume_target_id"], f"{field} resume target"
            ),
            "resume_continuation": _natural(
                raw["resume_continuation"], f"{field} resume continuation"
            ),
            "inner_shape": _inventory_shape(
                raw["inner_shape"],
                f"{field} inner shape",
                affine_indexes,
                artifact_indexes,
            ),
            "suspended_shape": _inventory_shape(
                raw["suspended_shape"],
                f"{field} suspended shape",
                affine_indexes,
                artifact_indexes,
            ),
            "resume_shape": _inventory_shape(
                raw["resume_shape"],
                f"{field} resume shape",
                affine_indexes,
                artifact_indexes,
            ),
            "original_gap": original_gap,
            "candidate_gap": candidate_gap,
        }

    links = [
        validated_link(raw, "affine linked control link")
        for raw in _canonical_rows(root["links"], "affine linked control links")
    ]
    _require_nodup(
        [{key: value for key, value in row.items() if key != "id"} for row in links],
        "affine linked control link shapes",
    )

    for link in links:
        if not any(
            state["node_id"] == link["resume_inventory_node_id"]
            and state["continuation_target_id"] == link["resume_continuation"]
            and state["active_shape"] == link["resume_shape"]
            and state["minimum_depth"] <= 1
            for state in states
        ):
            raise StageAInputError(
                f"affine linked link {link['id']} has no matching resume control state"
            )

    minimal_call_links = [
        validated_link(raw, "minimal affine call link")
        for raw in _canonical_rows(
            root.get("minimal_call_link_shapes", []),
            "minimal affine call link shapes",
        )
    ]
    _require_nodup(
        [
            {key: value for key, value in row.items() if key != "id"}
            for row in minimal_call_links
        ],
        "minimal affine call link shapes",
    )
    minimal_call_link_by_id = {
        int(link["id"]): link for link in minimal_call_links
    }
    minimal_call_bindings: list[dict[str, Any]] = []
    call_binding_fields = {
        "id",
        "transition_id",
        "edge_id",
        "seed_id",
        "source_control_state_id",
        "target_control_state_id",
        "resume_control_state_id",
        "outer_continuation_target_id",
        "call_continuation_target_id",
        "source_shape",
        "suspended_shape",
        "inner_shape",
        "resume_shape",
        "source_location",
        "suspended_location",
        "inner_location",
        "resume_location",
        "source_window",
        "stack_amount",
        "link_shape_id",
        "return_region_indices",
        "return_summaries",
        "external_summary",
        "profile",
    }
    for raw in _canonical_rows(
        root.get("minimal_call_transition_bindings", []),
        "minimal affine call transition bindings",
    ):
        _keys(
            raw,
            required=call_binding_fields,
            field="minimal affine call transition binding",
        )
        if raw["profile"] not in {
            "nested_direct_call_singleton_affine_control_v1",
            "returning_import_direct_call_singleton_affine_control_v1",
        }:
            raise StageAInputError(
                "minimal affine call transition binding has an unsupported profile"
            )
        source_id = _natural(
            raw["source_control_state_id"],
            "minimal affine call source control state id",
        )
        inner_id = _natural(
            raw["target_control_state_id"],
            "minimal affine call inner control state id",
        )
        resume_id = _natural(
            raw["resume_control_state_id"],
            "minimal affine call resume control state id",
        )
        source_state = minimal_state_by_id.get(source_id)
        inner_state = minimal_state_by_id.get(inner_id)
        resume_state = minimal_state_by_id.get(resume_id)
        if source_state is None or inner_state is None or resume_state is None:
            raise StageAInputError(
                "minimal affine call binding references an unknown control state"
            )
        link_id = _natural(
            raw["link_shape_id"], "minimal affine call link_shape_id"
        )
        link = minimal_call_link_by_id.get(link_id)
        if link is None:
            raise StageAInputError(
                "minimal affine call binding references an unknown link shape"
            )
        edge_id = _natural(raw["edge_id"], "minimal affine call edge_id")
        outer_continuation = _natural(
            raw["outer_continuation_target_id"],
            "minimal affine call outer continuation",
        )
        call_continuation = _natural(
            raw["call_continuation_target_id"],
            "minimal affine call continuation",
        )
        source_shape = _inventory_shape(
            raw["source_shape"], "minimal affine call source shape",
            affine_indexes, artifact_indexes,
        )
        suspended_shape = _inventory_shape(
            raw["suspended_shape"], "minimal affine call suspended shape",
            affine_indexes, artifact_indexes,
        )
        inner_shape = _inventory_shape(
            raw["inner_shape"], "minimal affine call inner shape",
            affine_indexes, artifact_indexes,
        )
        resume_shape = _inventory_shape(
            raw["resume_shape"], "minimal affine call resume shape",
            affine_indexes, artifact_indexes,
        )
        if (
            edge_id != link["call_edge_id"]
            or source_state["node_id"] != link["call_source_node_id"]
            or source_state["continuation_target_id"] != outer_continuation
            or source_state["active_shape"] != source_shape
            or inner_state["node_id"] != link["inner_inventory_node_id"]
            or inner_state["continuation_target_id"] != call_continuation
            or inner_state["active_shape"] != inner_shape
            or resume_state["node_id"] != link["resume_inventory_node_id"]
            or resume_state["continuation_target_id"] != outer_continuation
            or resume_state["active_shape"] != resume_shape
            or link["resume_target_id"] != call_continuation
            or link["resume_continuation"] != outer_continuation
            or link["inner_shape"] != inner_shape
            or link["suspended_shape"] != suspended_shape
            or link["resume_shape"] != resume_shape
        ):
            raise StageAInputError(
                "minimal affine call binding disagrees with its control states or link"
            )
        source_window_raw = _mapping(
            raw["source_window"], "minimal affine call source_window"
        )
        _keys(
            source_window_raw,
            required={
                "range_id", "original_register", "candidate_register",
                "bytes_below", "bytes_above",
            },
            field="minimal affine call source_window",
        )
        source_window = {
            "range_id": _natural(
                source_window_raw["range_id"], "minimal affine call range_id"
            ),
            "original_register": _register(
                source_window_raw["original_register"],
                "minimal affine call original stack register",
            ),
            "candidate_register": _register(
                source_window_raw["candidate_register"],
                "minimal affine call candidate stack register",
            ),
            "bytes_below": _natural(
                source_window_raw["bytes_below"],
                "minimal affine call bytes_below",
            ),
            "bytes_above": _natural(
                source_window_raw["bytes_above"],
                "minimal affine call bytes_above",
            ),
        }
        stack_amount_raw = _mapping(
            raw["stack_amount"], "minimal affine call stack_amount"
        )
        _keys(
            stack_amount_raw,
            required={"original", "candidate"},
            field="minimal affine call stack_amount",
        )
        stack_amount = {
            "original": _natural(
                stack_amount_raw["original"],
                "minimal affine call original stack amount",
            ),
            "candidate": _natural(
                stack_amount_raw["candidate"],
                "minimal affine call candidate stack amount",
            ),
        }
        return_regions = [
            _natural(value, "minimal affine call return region index")
            for value in _list(
                raw["return_region_indices"],
                "minimal affine call return region indices",
            )
        ]
        if return_regions != sorted(set(return_regions)):
            raise StageAInputError(
                "minimal affine call return region indices must be canonical"
            )
        return_summaries = []
        for value in _list(
            raw["return_summaries"], "minimal affine call return summaries"
        ):
            summary = _mapping(value, "minimal affine call return summary")
            _keys(
                summary,
                required={"return_region_index", "return_node_id", "claim"},
                field="minimal affine call return summary",
            )
            claim = _return_summary_claim(
                summary["claim"], "minimal affine call return summary claim"
            )
            return_region_index = _natural(
                summary["return_region_index"],
                "minimal affine call return region index",
            )
            if claim["return_region_index"] != return_region_index:
                raise StageAInputError(
                    "minimal affine call return summary region disagrees with claim"
                )
            return_summaries.append({
                "return_region_index": return_region_index,
                "return_node_id": _natural(
                    summary["return_node_id"],
                    "minimal affine call return node id",
                ),
                "claim": claim,
            })
        internal_profile = (
            raw["profile"] == "nested_direct_call_singleton_affine_control_v1"
        )
        if internal_profile and not return_regions:
            raise StageAInputError(
                "internal affine call return regions must be nonempty"
            )
        if internal_profile and not return_summaries:
            raise StageAInputError(
                "minimal affine call return summary claims must be nonempty"
            )
        if not internal_profile and (return_regions or return_summaries):
            raise StageAInputError(
                "external affine call bindings must not cite internal return sites"
            )
        summary_keys = [_normalized_key(claim) for claim in return_summaries]
        if summary_keys != sorted(set(summary_keys)):
            raise StageAInputError(
                "minimal affine call return summary claims must be canonical"
            )
        if sorted({
            int(summary["return_region_index"])
            for summary in return_summaries
        }) != return_regions:
            raise StageAInputError(
                "minimal affine call return summaries disagree with return regions"
            )
        source_location = _location(
            raw["source_location"], "minimal affine call source location"
        )
        resume_location = _location(
            raw["resume_location"], "minimal affine call resume location"
        )
        if any(
            summary["claim"]["source"] != source_location
            or summary["claim"]["target"] != resume_location
            for summary in return_summaries
        ):
            raise StageAInputError(
                "minimal affine call return summaries disagree with frame locations"
            )
        external_summary = None
        if internal_profile:
            if raw["external_summary"] is not None:
                raise StageAInputError(
                    "internal affine call binding must not contain external summary"
                )
        else:
            external_raw = _mapping(
                raw["external_summary"], "minimal affine external call summary"
            )
            _keys(
                external_raw,
                required={
                    "thunk_region_index", "thunk_node_id",
                    "machine_contract_id", "claim",
                },
                field="minimal affine external call summary",
            )
            external_claim = _external_return_summary_claim(
                external_raw["claim"], "minimal affine external call claim"
            )
            external_summary = {
                "thunk_region_index": _natural(
                    external_raw["thunk_region_index"],
                    "minimal affine external thunk region",
                ),
                "thunk_node_id": _natural(
                    external_raw["thunk_node_id"],
                    "minimal affine external thunk node",
                ),
                "machine_contract_id": _natural(
                    external_raw["machine_contract_id"],
                    "minimal affine external machine contract",
                ),
                "claim": external_claim,
            }
            if (
                external_summary["machine_contract_id"]
                    != external_claim["machine_contract_id"]
                or external_summary["thunk_region_index"]
                    != external_claim["thunk_region_index"]
                or external_claim["continuation_region_index"]
                    != call_continuation
                or external_claim["source"] != source_location
                or external_claim["target"] != resume_location
                or external_claim["thunk_transfer"]["source"]
                    != external_claim["suspended"]
                or external_claim["thunk_transfer"]["result_rule"]["source"]
                    != external_claim["thunk_transfer"]["boundary_target"]
                or external_claim["thunk_transfer"]["result_rule"]["target"]
                    != external_claim["target"]
                or external_claim["thunk_transfer"]["memory_claim"]["offsets"]
                    != external_claim["suspended"]
            ):
                raise StageAInputError(
                    "minimal affine external summary is internally inconsistent"
                )
        minimal_call_bindings.append({
            "id": _natural(raw["id"], "minimal affine call binding id"),
            "transition_id": _natural(
                raw["transition_id"], "minimal affine call transition id"
            ),
            "edge_id": edge_id,
            "seed_id": _natural(raw["seed_id"], "minimal affine call seed id"),
            "source_control_state_id": source_id,
            "inner_control_state_id": inner_id,
            "resume_control_state_id": resume_id,
            "outer_continuation_target_id": outer_continuation,
            "call_continuation_target_id": call_continuation,
            "source_shape": source_shape,
            "suspended_shape": suspended_shape,
            "inner_shape": inner_shape,
            "resume_shape": resume_shape,
            "source_location": source_location,
            "suspended_location": _location(
                raw["suspended_location"],
                "minimal affine call suspended location",
            ),
            "inner_location": _location(
                raw["inner_location"], "minimal affine call inner location"
            ),
            "resume_location": resume_location,
            "source_window": source_window,
            "stack_amount": stack_amount,
            "link_shape_id": link_id,
            "return_region_indices": return_regions,
            "return_summaries": return_summaries,
            "external_summary": external_summary,
            "profile": raw["profile"],
        })
    _require_nodup(
        [
            {key: value for key, value in row.items() if key != "id"}
            for row in minimal_call_bindings
        ],
        "minimal affine call transition bindings",
    )

    fallbacks = [
        _fallback(row, "affine linked exact fallback")
        for row in _list(root["exact_fallbacks"], "affine linked exact fallbacks")
    ]
    counts = _mapping(root["counts"], "affine linked control counts")
    required_counts = {"states", "links", "gaps", "affine_shapes", "exact_fallbacks"}
    missing_counts = sorted(required_counts - counts.keys())
    if missing_counts:
        raise StageAInputError(
            "affine linked control counts is missing fields: "
            + ", ".join(missing_counts)
        )
    for key, value in counts.items():
        _natural(value, f"affine linked count {key}")
    affine_shape_count = sum(
        shape is not None and shape["locations"]["kind"] == "affine_family"
        for shape in [
            *(state["active_shape"] for state in states),
            *(link[key] for link in links for key in (
                "inner_shape",
                "suspended_shape",
                "resume_shape",
            )),
        ]
    )
    expected_counts = {
        "states": len(states),
        "links": len(links),
        "gaps": 0,
        "affine_shapes": affine_shape_count,
        "exact_fallbacks": len(fallbacks),
    }
    observed_counts = {
        key: _natural(counts[key], f"affine linked count {key}")
        for key in expected_counts
    }
    if observed_counts != expected_counts:
        raise StageAInputError(
            "affine linked control counts do not match the validated payload"
        )
    if "minimal_active_states" in counts and _natural(
        counts["minimal_active_states"], "affine linked count minimal_active_states"
    ) != len(minimal_states):
        raise StageAInputError(
            "affine linked minimal active state count does not match the payload"
        )
    for key, expected in (
        ("minimal_call_link_shapes", len(minimal_call_links)),
        ("minimal_call_transition_bindings", len(minimal_call_bindings)),
    ):
        if key in counts and _natural(
            counts[key], f"affine linked count {key}"
        ) != expected:
            raise StageAInputError(
                f"affine linked {key} count does not match the payload"
            )
    return {
        "states": states,
        "links": links,
        "minimal_states": minimal_states,
        "minimal_bindings": minimal_bindings,
        "minimal_memory_bindings": minimal_memory_bindings,
        "minimal_call_links": minimal_call_links,
        "minimal_call_bindings": minimal_call_bindings,
    }


def _lean_inventory_shape(shape: Mapping[str, Any]) -> str:
    locations = shape["locations"]
    if locations["kind"] == "affine_family":
        location_source = f"(.affineFamily {locations['profile_state_index']})"
    else:
        location_source = "(.exact [" + ", ".join(
            _lean_return_slot_offset_pair(location)
            for location in locations["locations"]
        ) + "])"
    exact_words = ", ".join(
        "{ originalOffset := " + str(word["original"])
        + ", candidateOffset := " + str(word["candidate"]) + " }"
        for word in shape["exact_words"]
    )
    imports = ", ".join(
        "{ original := ." + relation["original"]
        + ", candidate := ." + relation["candidate"]
        + ", imported := " + _lean_external_target(relation["import"]) + " }"
        for relation in shape["preserved_imports"]
    )
    relations = ", ".join(
        _lean_register_relation_pair(relation)
        for relation in shape["preserved_relations"]
    )
    return (
        "({ locations := " + location_source
        + ", exactWords := [" + exact_words + "]"
        + ", preservedImports := [" + imports + "]"
        + ", preservedRelations := [" + relations
        + "] } : ReturnSlotAffineInventoryShape)"
    )


def _lean_state(state: Mapping[str, Any]) -> str:
    continuation = state["continuation_target_id"]
    active = state["active_shape"]
    return (
        "{ nodeId := " + str(state["node_id"])
        + ", continuation := "
        + ("none" if continuation is None else f"some {continuation}")
        + ", activeShape := "
        + ("none" if active is None else "some " + _lean_inventory_shape(active))
        + ", minimumDepth := " + str(state["minimum_depth"]) + " }"
    )


def _lean_link_shape(link: Mapping[str, Any]) -> str:
    return (
        "{ callEdgeId := " + str(link["call_edge_id"])
        + ", callSourceNodeId := " + str(link["call_source_node_id"])
        + ", callSourceTargetId := " + str(link["call_source_target_id"])
        + ", innerInventoryNodeId := " + str(link["inner_inventory_node_id"])
        + ", suspendedInventoryNodeId := "
        + str(link["suspended_inventory_node_id"])
        + ", resumeInventoryNodeId := " + str(link["resume_inventory_node_id"])
        + ", resumeTargetId := " + str(link["resume_target_id"])
        + ", resumeContinuation := " + str(link["resume_continuation"])
        + ", originalGap := " + str(link["original_gap"])
        + ", candidateGap := " + str(link["candidate_gap"])
        + ", innerShape := " + _lean_inventory_shape(link["inner_shape"])
        + ", suspendedShape := " + _lean_inventory_shape(link["suspended_shape"])
        + ", resumeShape := " + _lean_inventory_shape(link["resume_shape"])
        + " }"
    )


def _lean_return_slot_call_summary_claim(claim: Mapping[str, Any]) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", target := " + _lean_return_slot_offset_pair(claim["target"])
        + ", originalCallEsp := "
        + _lean_register_offset_witness(claim["original_call_witness"])
        + ", candidateCallEsp := "
        + _lean_register_offset_witness(claim["candidate_call_witness"])
        + ", originalReturnSlot := "
        + _lean_register_offset_witness(claim["original_return_slot_witness"])
        + ", candidateReturnSlot := "
        + _lean_register_offset_witness(claim["candidate_return_slot_witness"])
        + ", originalReturnOutput := "
        + _lean_register_offset_witness(claim["original_return_output_witness"])
        + ", candidateReturnOutput := "
        + _lean_register_offset_witness(claim["candidate_return_output_witness"])
        + ", popBytes := " + str(claim["pop_bytes"]) + " }"
    )


def _lean_external_return_slot_result_rule(rule: Mapping[str, Any]) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_pair(rule["source"])
        + ", target := " + _lean_return_slot_offset_pair(rule["target"])
        + ", originalDelta := " + str(rule["original_delta"])
        + ", candidateDelta := " + str(rule["candidate_delta"])
        + " }"
    )


def _lean_external_jump_return_slot_transfer_claim(
    claim: Mapping[str, Any],
) -> str:
    internal = _mapping(claim["internal_rule"], "external thunk internal rule")
    result = _mapping(claim["result_rule"], "external thunk result rule")
    memory = _mapping(claim["memory_claim"], "external thunk memory claim")
    original_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["original_write_witnesses"]
    )
    candidate_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["candidate_write_witnesses"]
    )
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", internalTarget := "
        + _lean_return_slot_offset_pair(claim["internal_target"])
        + ", boundaryTarget := "
        + _lean_return_slot_offset_pair(claim["boundary_target"])
        + ", internalRule := { originalSourceRegister := ."
        + str(internal["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(internal["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(internal["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(internal["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(internal["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(internal["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(internal["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(internal["candidate_delta"]))
        + " }, resultRule := " + _lean_external_return_slot_result_rule(result)
        + ", memory := { offsets := "
        + _lean_return_slot_offset_pair(memory["offsets"])
        + f", originalWrites := [{original_writes}]"
        + f", candidateWrites := [{candidate_writes}] }} }}"
    )


def _lean_external_return_slot_call_summary_claim(
    claim: Mapping[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", suspended := " + _lean_return_slot_offset_pair(claim["suspended"])
        + ", target := " + _lean_return_slot_offset_pair(claim["target"])
        + ", originalCallEsp := "
        + _lean_register_offset_witness(claim["original_call_witness"])
        + ", candidateCallEsp := "
        + _lean_register_offset_witness(claim["candidate_call_witness"])
        + ", thunkTransfer := "
        + _lean_external_jump_return_slot_transfer_claim(claim["thunk_transfer"])
        + " }"
    )


def _inventory_from_shape(
    shape: Mapping[str, Any], location: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "locations": [dict(location)],
        "exact_words": [dict(word) for word in shape["exact_words"]],
        "preserved_imports": [
            dict(relation) for relation in shape["preserved_imports"]
        ],
        "preserved_relations": [
            dict(relation) for relation in shape["preserved_relations"]
        ],
    }


def _lean_offset_inventory(inventory: Mapping[str, Any]) -> str:
    locations = ", ".join(
        _lean_return_slot_offset_pair(location)
        for location in inventory["locations"]
    )
    exact_words = ", ".join(
        "{ originalOffset := " + str(word["original"])
        + ", candidateOffset := " + str(word["candidate"]) + " }"
        for word in inventory["exact_words"]
    )
    preserved_imports = ", ".join(
        "{ original := ." + str(relation["original"])
        + ", candidate := ." + str(relation["candidate"])
        + ", imported := " + _lean_external_target(relation["import"]) + " }"
        for relation in inventory["preserved_imports"]
    )
    preserved_relations = ", ".join(
        _lean_register_relation_pair(relation)
        for relation in inventory["preserved_relations"]
    )
    return (
        "({ locations := [" + locations + "]"
        + ", exactWords := [" + exact_words + "]"
        + ", preservedImports := [" + preserved_imports + "]"
        + ", preservedRelations := [" + preserved_relations + "]"
        + " } : ReturnSlotOffsetInventory)"
    )


def _lean_returning_import_entry_inventory_claim(
    binding: Mapping[str, Any], external_claim: Mapping[str, Any]
) -> str:
    source = _inventory_from_shape(
        _mapping(binding["source_shape"], "external call source shape"),
        _mapping(binding["source_location"], "external call source location"),
    )
    suspended = _inventory_from_shape(
        _mapping(binding["suspended_shape"], "external call suspended shape"),
        _mapping(
            binding["suspended_location"], "external call suspended location"
        ),
    )
    original_witness = _lean_register_offset_witness(
        external_claim["original_call_witness"]
    )
    candidate_witness = _lean_register_offset_witness(
        external_claim["candidate_call_witness"]
    )
    return (
        "{ source := " + _lean_offset_inventory(source)
        + ", target := " + _lean_offset_inventory(suspended)
        + ", transfers := [{ transfer := { source := "
        + _lean_return_slot_offset_pair(binding["source_location"])
        + ", target := "
        + _lean_return_slot_offset_pair(binding["suspended_location"])
        + ", originalOutput := " + original_witness
        + ", candidateOutput := " + candidate_witness
        + " }, memory := .protectedSpan { offsets := "
        + _lean_return_slot_offset_pair(binding["source_location"])
        + ", writes := [.affine (" + original_witness + ") ("
        + candidate_witness + ")] } }], exactWordTransfers := [] }"
    )


def _lean_returning_import_resume_inventory_claim(
    binding: Mapping[str, Any], external_claim: Mapping[str, Any]
) -> str:
    suspended = _inventory_from_shape(
        _mapping(binding["suspended_shape"], "external call suspended shape"),
        _mapping(
            binding["suspended_location"], "external call suspended location"
        ),
    )
    resume = _inventory_from_shape(
        _mapping(binding["resume_shape"], "external call resume shape"),
        _mapping(binding["resume_location"], "external call resume location"),
    )
    return (
        "{ source := " + _lean_offset_inventory(suspended)
        + ", target := " + _lean_offset_inventory(resume)
        + ", transfers := ["
        + _lean_external_jump_return_slot_transfer_claim(
            _mapping(external_claim["thunk_transfer"], "external thunk transfer")
        )
        + "], exactWordTransfers := [] }"
    )


def _control_state_key(state: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        int(state["node_id"]),
        state["continuation_target_id"],
        json.dumps(state["active_shape"], sort_keys=True, separators=(",", ":")),
        int(state["minimum_depth"]),
    )


def relational_affine_linked_control_source(payload: object) -> str:
    validated = _validated_payload(payload)
    states = ",\n  ".join(_lean_state(state) for state in validated["states"])
    links = ",\n  ".join(_lean_link_shape(link) for link in validated["links"])
    minimal_links_by_key: dict[str, Mapping[str, Any]] = {}
    for link in [*validated["links"], *validated["minimal_call_links"]]:
        key = _normalized_key({
            name: value for name, value in link.items() if name != "id"
        })
        minimal_links_by_key.setdefault(key, link)
    minimal_links = ",\n  ".join(
        _lean_link_shape(link) for link in minimal_links_by_key.values()
    )
    minimal_states = ",\n  ".join(
        _lean_state(state) for state in validated["minimal_states"]
    )
    minimal_keys = {
        _control_state_key(state) for state in validated["minimal_states"]
    }
    resume_states: list[Mapping[str, Any]] = []
    resume_keys: set[tuple[object, ...]] = set()
    for link in validated["links"]:
        candidates = [
            state for state in validated["states"]
            if int(state["node_id"]) == int(link["resume_inventory_node_id"])
            and state["continuation_target_id"] == link["resume_continuation"]
            and state["active_shape"] == link["resume_shape"]
            and int(state["minimum_depth"]) <= 1
        ]
        if len(candidates) != 1:
            raise StageAInputError(
                "affine nested link does not have one unique shallow resume state"
            )
        candidate = candidates[0]
        key = _control_state_key(candidate)
        if key not in minimal_keys and key not in resume_keys:
            resume_states.append(candidate)
            resume_keys.add(key)
    resume_state_rows = ",\n  ".join(_lean_state(state) for state in resume_states)
    return (
        "import StageA.RelationalAffineFrameProfile\n"
        "import StageA.RelationalAffineLinkedFrames\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\n"
        "set_option maxHeartbeats 0\n\n"
        "/- This module checks only hybrid control states and nested link shapes.\n"
        "Affine transition bindings and whole control closure are certified by\n"
        "separate integration modules. -/\n\n"
        "def runtimeFrameAffineLinkedControlStates : "
        "List AffineLinkedProductControlState := [\n  "
        + states
        + "\n]\n\n"
        "def runtimeFrameAffineNestedLinkShapes : "
        "List RelationalRuntimeCallFrameAffineLinkShape := [\n  "
        + links
        + "\n]\n\n"
        "def runtimeFrameAffineLinkedControlProfile : "
        "AffineLinkedProductControlProfile := {\n"
        "  states := runtimeFrameAffineLinkedControlStates\n"
        "  linkShapes := runtimeFrameAffineNestedLinkShapes\n"
        "}\n\n"
        "def runtimeFrameAffineLinkedControlProfileCheck : Bool :=\n"
        "  runtimeFrameAffineLinkedControlProfile.checked "
        "runtimeFrameAffineProfile relationalProductGraph\n\n"
        "theorem runtimeFrameAffineLinkedControlProfileChecked :\n"
        "    runtimeFrameAffineLinkedControlProfile.checked "
        "runtimeFrameAffineProfile relationalProductGraph = true := by\n"
        "  native_decide\n\n"
        "def runtimeFrameAffineMinimalActiveControlStates : "
        "List AffineLinkedProductControlState := [\n  "
        + minimal_states
        + "\n]\n\n"
        "def runtimeFrameAffineMinimalActiveControlProfile : "
        "AffineLinkedProductControlProfile := {\n"
        "  states := runtimeFrameAffineMinimalActiveControlStates\n"
        "  linkShapes := []\n"
        "}\n\n"
        "theorem runtimeFrameAffineMinimalActiveControlProfileChecked :\n"
        "    runtimeFrameAffineMinimalActiveControlProfile.checked "
        "runtimeFrameAffineProfile relationalProductGraph = true := by\n"
        "  native_decide\n\n"
        "def runtimeFrameAffineMinimalLinkedControlStates : "
        "List AffineLinkedProductControlState :=\n"
        "  runtimeFrameAffineMinimalActiveControlStates ++ [\n  "
        + resume_state_rows
        + "\n]\n\n"
        "def runtimeFrameAffineMinimalNestedLinkShapes : "
        "List RelationalRuntimeCallFrameAffineLinkShape := [\n  "
        + minimal_links
        + "\n]\n\n"
        "def runtimeFrameAffineMinimalLinkedControlProfile : "
        "AffineLinkedProductControlProfile := {\n"
        "  states := runtimeFrameAffineMinimalLinkedControlStates\n"
        "  linkShapes := runtimeFrameAffineMinimalNestedLinkShapes\n"
        "}\n\n"
        "theorem runtimeFrameAffineMinimalLinkedControlProfileChecked :\n"
        "    runtimeFrameAffineMinimalLinkedControlProfile.checked "
        "runtimeFrameAffineProfile relationalProductGraph = true := by\n"
        "  native_decide\n\n"
        "end StageA.GeneratedRelational\n"
    )


def write_relational_affine_linked_control_module(
    lean_dir: Path, payload: object
) -> str:
    source = relational_affine_linked_control_source(payload)
    write_text_if_changed(
        lean_dir / "StageA" / f"{AFFINE_LINKED_CONTROL_MODULE}.lean",
        source,
    )
    return AFFINE_LINKED_CONTROL_MODULE


def write_relational_affine_linked_control_binding_modules(
    lean_dir: Path, payload: object
) -> list[str]:
    """Emit checked semantic and control-context bindings by semantic owner.

    A transition can occur under many continuation contexts.  The Lean theorem
    is quantified over the dormant frame tail, so those contexts share one
    semantic frame binding.  Each context still receives a small checked
    wrapper tying its submitted state indices and continuation to that proof.
    """

    validated = _validated_payload(payload)
    minimal_state_by_id = {
        int(state["id"]): state for state in validated["minimal_states"]
    }
    unique: dict[int, dict[str, Any]] = {}
    for binding in validated["minimal_bindings"]:
        unique.setdefault(int(binding["transition_id"]), binding)
    if not unique:
        return []

    stage_a = lean_dir / "StageA"
    declaration_pattern = re.compile(
        r"^def runtimeFrameAffineSemanticTransition([0-9]+)\s*:", re.MULTILINE
    )
    owner_by_transition: dict[int, str] = {}
    for source_path in sorted(stage_a.glob("RelationalAffineFrameSemanticChunk*.lean")):
        module = source_path.stem
        for matched in declaration_pattern.findall(
            source_path.read_text(encoding="utf-8")
        ):
            transition_id = int(matched)
            if transition_id in owner_by_transition:
                raise StageAInputError(
                    f"affine semantic transition {transition_id} has multiple owners"
                )
            owner_by_transition[transition_id] = module
    missing = sorted(set(unique) - owner_by_transition.keys())
    if missing:
        raise StageAInputError(
            "affine control bindings reference semantic transitions without generated "
            f"owners: {missing[:8]!r}"
        )

    by_owner: dict[str, list[dict[str, Any]]] = {}
    for binding in validated["minimal_bindings"]:
        transition_id = int(binding["transition_id"])
        by_owner.setdefault(owner_by_transition[transition_id], []).append(binding)

    modules: list[str] = []
    chunk_lists: list[str] = []
    chunk_checks: list[str] = []
    for chunk_index, (owner, bindings) in enumerate(sorted(by_owner.items())):
        module = f"RelationalAffineLinkedControlBindingChunk{chunk_index}"
        list_name = f"runtimeFrameAffineControlBindingChunk{chunk_index}"
        list_checked = f"{list_name}Checked"
        semantic_definitions: list[str] = []
        for transition_id in sorted({
            int(binding["transition_id"]) for binding in bindings
        }):
            representative = unique[transition_id]
            name = f"runtimeFrameAffineFrameTransitionBinding{transition_id}"
            checked_name = f"{name}Checked"
            semantic_definitions.append(
                f"def {name} : ReturnSlotAffineFrameSemanticTransitionBinding := {{\n"
                f"  sourceShape := {_lean_inventory_shape(representative['source_shape'])}\n"
                f"  targetShape := {_lean_inventory_shape(representative['target_shape'])}\n"
                f"  claim := runtimeFrameAffineSemanticTransition{transition_id}\n"
                "}\n\n"
                f"theorem {checked_name} :\n"
                f"    {name}.checked staticProofContext runtimeFrameAffineProfile\n"
                "      relationalProductGraph = true := by\n"
                "  native_decide"
            )
        definitions: list[str] = []
        names: list[str] = []
        checked_names: list[str] = []
        for binding in bindings:
            transition_id = int(binding["transition_id"])
            binding_id = int(binding["id"])
            frame_name = f"runtimeFrameAffineFrameTransitionBinding{transition_id}"
            name = f"runtimeFrameAffineControlTransitionBinding{binding_id}"
            checked_name = f"{name}Checked"
            names.append(name)
            checked_names.append(checked_name)
            definitions.append(
                f"def {name} : AffineLinkedOrdinaryTransitionBinding := {{\n"
                f"  sourceControlStateIndex := {binding['source_control_state_id']}\n"
                f"  targetControlStateIndex := {binding['target_control_state_id']}\n"
                f"  edgeId := {binding['edge_id']}\n"
                f"  continuationTargetId := {binding['continuation_target_id']}\n"
                f"  frameBinding := {frame_name}\n"
                "}\n\n"
                f"theorem {checked_name} :\n"
                f"    {name}.checked staticProofContext\n"
                "      runtimeFrameAffineMinimalLinkedControlProfile\n"
                "      runtimeFrameAffineProfile relationalProductGraph = true := by\n"
                "  native_decide"
            )
        transitions_by_node_edge: dict[tuple[int, int], set[int]] = {}
        for binding in bindings:
            node_edge = (
                int(minimal_state_by_id[int(binding["source_control_state_id"])][
                    "node_id"
                ]),
                int(binding["edge_id"]),
            )
            transitions_by_node_edge.setdefault(node_edge, set()).add(
                int(binding["transition_id"])
            )
        ambiguous_node_edges = {
            node_edge: transition_ids
            for node_edge, transition_ids in transitions_by_node_edge.items()
            if len(transition_ids) != 1
        }
        if ambiguous_node_edges:
            raise StageAInputError(
                "affine ordinary node/edge dispatch does not select one semantic "
                f"transition: {list(ambiguous_node_edges.items())[:4]!r}"
            )
        coverage_theorems = [
            (
                f"theorem {list_name}Node{node_id}Edge{edge_id}Covered :\n"
                "    affineOrdinaryBindingsCoverActiveNodeEdge\n"
                f"      {list_name} runtimeFrameAffineMinimalLinkedControlProfile\n"
                f"      {node_id} {edge_id} "
                f"runtimeFrameAffineFrameTransitionBinding{next(iter(transition_ids))} "
                "= true := by\n"
                "  native_decide"
            )
            for (node_id, edge_id), transition_ids in sorted(
                transitions_by_node_edge.items()
            )
        ]
        source = (
            "import StageA.RelationalAffineLinkedExecution\n"
            "import StageA.RelationalAffineLinkedControl\n"
            f"import StageA.{owner}\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\n"
            "set_option maxHeartbeats 0\n\n"
            + "\n\n".join(semantic_definitions + definitions)
            + "\n\n"
            f"def {list_name} : List "
            "AffineLinkedOrdinaryTransitionBinding := ["
            + ", ".join(names)
            + "]\n\n"
            f"theorem {list_checked} :\n"
            f"    {list_name}.all (fun binding => binding.checked staticProofContext\n"
            "      runtimeFrameAffineMinimalLinkedControlProfile\n"
            "      runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
            f"  simp [{list_name}, {', '.join(checked_names)}]\n\n"
            + "\n\n".join(coverage_theorems)
            + "\n\n"
            "end StageA.GeneratedRelational\n"
        )
        write_text_if_changed(stage_a / f"{module}.lean", source)
        modules.append(module)
        chunk_lists.append(list_name)
        chunk_checks.append(list_checked)

    aggregate_source = (
        "import StageA.RelationalAffineLinkedExecution\n"
        + "".join(f"import StageA.{module}\n" for module in modules)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\n"
        "set_option maxHeartbeats 0\n\n"
        "def runtimeFrameAffineControlTransitionBindings : List\n"
        "    AffineLinkedOrdinaryTransitionBinding :=\n  "
        + " ++ ".join(chunk_lists)
        + "\n\n"
        "theorem runtimeFrameAffineControlTransitionBindingsChecked :\n"
        "    runtimeFrameAffineControlTransitionBindings.all (fun binding =>\n"
        "      binding.checked staticProofContext\n"
        "        runtimeFrameAffineMinimalLinkedControlProfile\n"
        "        runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
        "  simp only [runtimeFrameAffineControlTransitionBindings, List.all_append, "
        "Bool.true_and, Bool.and_true, "
        + ", ".join(chunk_checks)
        + "]\n\n"
        "end StageA.GeneratedRelational\n"
    )
    write_text_if_changed(
        stage_a / f"{AFFINE_LINKED_CONTROL_BINDINGS_MODULE}.lean",
        aggregate_source,
    )
    modules.append(AFFINE_LINKED_CONTROL_BINDINGS_MODULE)
    return modules


def write_relational_affine_linked_call_binding_modules(
    lean_dir: Path, payload: object
) -> list[str]:
    """Emit checked singleton-affine nested-call evidence by semantic owner."""

    validated = _validated_payload(payload)
    bindings = [
        binding for binding in validated["minimal_call_bindings"]
        if binding.get("profile")
            == "nested_direct_call_singleton_affine_control_v1"
    ]
    if not bindings:
        return []
    call_links = {
        int(link["id"]): link for link in validated["minimal_call_links"]
    }
    stage_a = lean_dir / "StageA"
    transition_pattern = re.compile(
        r"^def runtimeFrameAffineSemanticTransition([0-9]+)\s*:", re.MULTILINE
    )
    seed_pattern = re.compile(
        r"^def runtimeFrameAffineSemanticSeed([0-9]+)\s*:", re.MULTILINE
    )
    original_decode_pattern = re.compile(
        r"^theorem originalBehavior([0-9]+)CheckedDecoded\s*:", re.MULTILINE
    )
    candidate_decode_pattern = re.compile(
        r"^theorem candidateBehavior([0-9]+)CheckedDecoded\s*:", re.MULTILINE
    )

    def semantic_owners(pattern: re.Pattern[str], glob: str, field: str) -> dict[int, str]:
        owners: dict[int, str] = {}
        for source_path in sorted(stage_a.glob(glob)):
            module = source_path.stem
            for matched in pattern.findall(source_path.read_text(encoding="utf-8")):
                semantic_id = int(matched)
                if semantic_id in owners:
                    raise StageAInputError(
                        f"affine {field} {semantic_id} has multiple generated owners"
                    )
                owners[semantic_id] = module
        return owners

    transition_owners = semantic_owners(
        transition_pattern,
        "RelationalAffineFrameSemanticChunk*.lean",
        "call transition",
    )
    seed_owners = semantic_owners(
        seed_pattern,
        "RelationalAffineFrameSemanticSeedChunk*.lean",
        "call seed",
    )
    original_decode_owners = semantic_owners(
        original_decode_pattern,
        "RelationalProofOriginalDecodeChunk*.lean",
        "original return decode",
    )
    candidate_decode_owners = semantic_owners(
        candidate_decode_pattern,
        "RelationalProofCandidateDecodeChunk*.lean",
        "candidate return decode",
    )
    missing_transitions = sorted({
        int(binding["transition_id"]) for binding in bindings
    } - transition_owners.keys())
    missing_seeds = sorted({
        int(binding["seed_id"]) for binding in bindings
    } - seed_owners.keys())
    if missing_transitions or missing_seeds:
        raise StageAInputError(
            "affine call bindings reference semantic claims without generated owners: "
            f"transitions={missing_transitions[:8]!r}, seeds={missing_seeds[:8]!r}"
        )
    return_region_ids = {
        int(summary["return_region_index"])
        for binding in bindings
        for summary in binding["return_summaries"]
    }
    missing_original_returns = sorted(
        return_region_ids - original_decode_owners.keys()
    )
    missing_candidate_returns = sorted(
        return_region_ids - candidate_decode_owners.keys()
    )
    if missing_original_returns or missing_candidate_returns:
        raise StageAInputError(
            "affine call bindings reference return regions without generated decode "
            "owners: original="
            f"{missing_original_returns[:8]!r}, candidate="
            f"{missing_candidate_returns[:8]!r}"
        )

    by_owners: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for binding in bindings:
        owner = (
            transition_owners[int(binding["transition_id"])],
            seed_owners[int(binding["seed_id"])],
        )
        by_owners.setdefault(owner, []).append(binding)

    modules: list[str] = []
    chunk_lists: list[str] = []
    chunk_checks: list[str] = []
    for chunk_index, (owners, selected) in enumerate(sorted(by_owners.items())):
        transition_owner, seed_owner = owners
        module = f"RelationalAffineLinkedCallBindingChunk{chunk_index}"
        list_name = f"runtimeFrameAffineCallBindingChunk{chunk_index}"
        list_checked = f"{list_name}Checked"
        definitions: list[str] = []
        names: list[str] = []
        checked_names: list[str] = []
        for binding in selected:
            binding_id = int(binding["id"])
            transition_id = int(binding["transition_id"])
            seed_id = int(binding["seed_id"])
            link = call_links[int(binding["link_shape_id"])]
            name = f"runtimeFrameAffineCallTransitionBinding{binding_id}"
            checked_name = f"{name}Checked"
            names.append(name)
            checked_names.append(checked_name)
            return_summary_names: list[str] = []
            for summary_index, summary in enumerate(
                binding["return_summaries"]
            ):
                return_region_index = int(summary["return_region_index"])
                return_base = (
                    f"runtimeFrameAffineCallBinding{binding_id}Return"
                    f"{summary_index}"
                )
                original_normalized = f"{return_base}OriginalNormalized"
                candidate_normalized = f"{return_base}CandidateNormalized"
                summary_name = f"{return_base}Summary"
                return_summary_names.append(summary_name)
                definitions.append(
                    f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                    "  (normalizeSymbolicBehavior false "
                    f"region{return_region_index}.targets "
                    f"originalBehavior{return_region_index}).get (by decide)\n\n"
                    f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                    "  (normalizeSymbolicBehavior true "
                    f"region{return_region_index}.targets "
                    f"candidateBehavior{return_region_index}).get (by decide)\n\n"
                    f"def {summary_name} : "
                    "SingletonAffineNestedDirectCallReturnSummary := {\n"
                    f"  returnNodeId := {summary['return_node_id']}\n"
                    f"  returnRegion := region{return_region_index}\n"
                    f"  originalBehavior := originalBehavior{return_region_index}\n"
                    f"  candidateBehavior := candidateBehavior{return_region_index}\n"
                    f"  originalNormalized := {original_normalized}\n"
                    f"  candidateNormalized := {candidate_normalized}\n"
                    "  summary := "
                    f"{_lean_return_slot_call_summary_claim(summary['claim'])}\n"
                    "}"
                )
            definitions.append(
                f"def {name} : SingletonAffineNestedDirectCallControlBinding := {{\n"
                f"  sourceControlStateIndex := {binding['source_control_state_id']}\n"
                f"  innerControlStateIndex := {binding['inner_control_state_id']}\n"
                f"  resumeControlStateIndex := {binding['resume_control_state_id']}\n"
                f"  sourceToSuspended := runtimeFrameAffineSemanticTransition{transition_id}\n"
                f"  innerSeed := runtimeFrameAffineSemanticSeed{seed_id}\n"
                f"  linkShape := {_lean_link_shape(link)}\n"
                f"  sourceOffsets := {_lean_return_slot_offset_pair(binding['source_location'])}\n"
                "  suspendedOffsets := "
                f"{_lean_return_slot_offset_pair(binding['suspended_location'])}\n"
                f"  innerOffsets := {_lean_return_slot_offset_pair(binding['inner_location'])}\n"
                f"  resumeOffsets := {_lean_return_slot_offset_pair(binding['resume_location'])}\n"
                "  stackAmount := { original := "
                f"{binding['stack_amount']['original']}, candidate := "
                f"{binding['stack_amount']['candidate']} }}\n"
                f"  sourceWindow := {_lean_stack_window(binding['source_window'])}\n"
                "  returnSummaries := ["
                + ", ".join(return_summary_names)
                + "]\n"
                "}\n\n"
                f"theorem {checked_name} :\n"
                f"    {name}.checked staticProofContext\n"
                f"      {name}.sourceToSuspended.region.inputInvariant\n"
                "      runtimeFrameAffineMinimalLinkedControlProfile\n"
                "      runtimeFrameAffineProfile relationalProductGraph = true := by\n"
                "  native_decide"
            )
        return_owner_modules = sorted({
            original_decode_owners[int(summary["return_region_index"])]
            for binding in selected
            for summary in binding["return_summaries"]
        } | {
            candidate_decode_owners[int(summary["return_region_index"])]
            for binding in selected
            for summary in binding["return_summaries"]
        })
        source = (
            "import StageA.RelationalAffineLinkedControl\n"
            f"import StageA.{transition_owner}\n"
            + (
                "" if seed_owner == transition_owner
                else f"import StageA.{seed_owner}\n"
            )
            + "".join(
                f"import StageA.{owner_module}\n"
                for owner_module in return_owner_modules
                if owner_module not in {transition_owner, seed_owner}
            )
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\n"
            "set_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\n"
            f"def {list_name} : List "
            "SingletonAffineNestedDirectCallControlBinding := ["
            + ", ".join(names)
            + "]\n\n"
            f"theorem {list_checked} :\n"
            f"    {list_name}.all (fun binding => binding.checked staticProofContext\n"
            "      binding.sourceToSuspended.region.inputInvariant\n"
            "      runtimeFrameAffineMinimalLinkedControlProfile\n"
            "      runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
            f"  simp [{list_name}, {', '.join(checked_names)}]\n\n"
            "end StageA.GeneratedRelational\n"
        )
        write_text_if_changed(stage_a / f"{module}.lean", source)
        modules.append(module)
        chunk_lists.append(list_name)
        chunk_checks.append(list_checked)

    aggregate_source = (
        "import StageA.RelationalAffineLinkedControl\n"
        + "".join(f"import StageA.{module}\n" for module in modules)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\n"
        "set_option maxHeartbeats 0\n\n"
        "def runtimeFrameAffineCallTransitionBindings : List\n"
        "    SingletonAffineNestedDirectCallControlBinding :=\n  "
        + " ++ ".join(chunk_lists)
        + "\n\n"
        "theorem runtimeFrameAffineCallTransitionBindingsChecked :\n"
        "    runtimeFrameAffineCallTransitionBindings.all (fun binding =>\n"
        "      binding.checked staticProofContext\n"
        "        binding.sourceToSuspended.region.inputInvariant\n"
        "        runtimeFrameAffineMinimalLinkedControlProfile\n"
        "        runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
        "  simp only [runtimeFrameAffineCallTransitionBindings, List.all_append, "
        "Bool.true_and, Bool.and_true, "
        + ", ".join(chunk_checks)
        + "]\n\n"
        "end StageA.GeneratedRelational\n"
    )
    write_text_if_changed(
        stage_a / f"{AFFINE_LINKED_CALL_BINDINGS_MODULE}.lean",
        aggregate_source,
    )
    modules.append(AFFINE_LINKED_CALL_BINDINGS_MODULE)
    return modules


def write_relational_affine_linked_external_call_binding_modules(
    lean_dir: Path, payload: object
) -> list[str]:
    """Emit checked singleton-affine returning-import call evidence."""

    validated = _validated_payload(payload)
    bindings = [
        binding for binding in validated["minimal_call_bindings"]
        if binding.get("profile")
            == "returning_import_direct_call_singleton_affine_control_v1"
    ]
    if not bindings:
        return []
    call_links = {
        int(link["id"]): link for link in validated["minimal_call_links"]
    }
    stage_a = lean_dir / "StageA"
    transition_pattern = re.compile(
        r"^def runtimeFrameAffineSemanticTransition([0-9]+)\s*:", re.MULTILINE
    )
    seed_pattern = re.compile(
        r"^def runtimeFrameAffineSemanticSeed([0-9]+)\s*:", re.MULTILINE
    )
    original_decode_pattern = re.compile(
        r"^theorem originalBehavior([0-9]+)CheckedDecoded\s*:", re.MULTILINE
    )
    candidate_decode_pattern = re.compile(
        r"^theorem candidateBehavior([0-9]+)CheckedDecoded\s*:", re.MULTILINE
    )

    def semantic_owners(
        pattern: re.Pattern[str], glob: str, field: str
    ) -> dict[int, str]:
        owners: dict[int, str] = {}
        for source_path in sorted(stage_a.glob(glob)):
            module = source_path.stem
            for matched in pattern.findall(source_path.read_text(encoding="utf-8")):
                semantic_id = int(matched)
                if semantic_id in owners:
                    raise StageAInputError(
                        f"affine {field} {semantic_id} has multiple generated owners"
                    )
                owners[semantic_id] = module
        return owners

    transition_owners = semantic_owners(
        transition_pattern,
        "RelationalAffineFrameSemanticChunk*.lean",
        "external call transition",
    )
    seed_owners = semantic_owners(
        seed_pattern,
        "RelationalAffineFrameSemanticSeedChunk*.lean",
        "external call seed",
    )
    original_decode_owners = semantic_owners(
        original_decode_pattern,
        "RelationalProofOriginalDecodeChunk*.lean",
        "original import thunk decode",
    )
    candidate_decode_owners = semantic_owners(
        candidate_decode_pattern,
        "RelationalProofCandidateDecodeChunk*.lean",
        "candidate import thunk decode",
    )

    by_owners: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for binding in bindings:
        transition_id = int(binding["transition_id"])
        seed_id = int(binding["seed_id"])
        external = _mapping(binding.get("external_summary"), "external summary")
        thunk_region = _natural(
            external.get("thunk_region_index"), "external thunk region"
        )
        try:
            owner = (
                transition_owners[transition_id],
                seed_owners[seed_id],
                original_decode_owners[thunk_region],
                candidate_decode_owners[thunk_region],
            )
        except KeyError as error:
            raise StageAInputError(
                "affine external call binding references semantic evidence without "
                f"a generated owner: {error.args[0]}"
            ) from error
        by_owners.setdefault(owner, []).append(binding)

    modules: list[str] = []
    chunk_lists: list[str] = []
    chunk_checks: list[str] = []
    chunk_certificate_lists: list[str] = []
    chunk_certificate_checks: list[str] = []
    minimal_state_by_id = {
        int(state["id"]): state for state in validated["minimal_states"]
    }
    for chunk_index, (owners, selected) in enumerate(sorted(by_owners.items())):
        transition_owner, seed_owner, original_owner, candidate_owner = owners
        module = f"RelationalAffineLinkedExternalCallBindingChunk{chunk_index}"
        list_name = f"runtimeFrameAffineExternalCallBindingChunk{chunk_index}"
        list_checked = f"{list_name}Checked"
        definitions: list[str] = []
        names: list[str] = []
        checked_names: list[str] = []
        certificate_names: list[str] = []
        for binding in selected:
            binding_id = int(binding["id"])
            transition_id = int(binding["transition_id"])
            seed_id = int(binding["seed_id"])
            link = call_links[int(binding["link_shape_id"])]
            external = _mapping(binding["external_summary"], "external summary")
            claim = _mapping(external["claim"], "external summary claim")
            thunk_region = int(external["thunk_region_index"])
            base_name = f"runtimeFrameAffineExternalCallBinding{binding_id}Base"
            summary_name = f"runtimeFrameAffineExternalCallBinding{binding_id}Summary"
            name = f"runtimeFrameAffineExternalCallTransitionBinding{binding_id}"
            checked_name = f"{name}Checked"
            certificate_name = (
                f"runtimeFrameAffineExternalCallExecutionCertificate{binding_id}"
            )
            original_normalized = f"{summary_name}OriginalNormalized"
            candidate_normalized = f"{summary_name}CandidateNormalized"
            names.append(name)
            checked_names.append(checked_name)
            certificate_names.append(certificate_name)
            definitions.append(
                f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                "  (normalizeSymbolicBehavior false "
                f"region{thunk_region}.targets originalBehavior{thunk_region}).get "
                "(by decide)\n\n"
                f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                "  (normalizeSymbolicBehavior true "
                f"region{thunk_region}.targets candidateBehavior{thunk_region}).get "
                "(by decide)\n\n"
                f"def {summary_name} : "
                "SingletonAffineReturningImportDirectCallSummary := {\n"
                f"  thunkNodeId := {external['thunk_node_id']}\n"
                f"  thunkRegion := region{thunk_region}\n"
                f"  originalBehavior := originalBehavior{thunk_region}\n"
                f"  candidateBehavior := candidateBehavior{thunk_region}\n"
                f"  originalNormalized := {original_normalized}\n"
                f"  candidateNormalized := {candidate_normalized}\n"
                f"  machineContractId := {external['machine_contract_id']}\n"
                "  summary := "
                f"{_lean_external_return_slot_call_summary_claim(claim)}\n"
                "}\n\n"
                f"def {base_name} : SingletonAffineNestedDirectCallControlBinding := {{\n"
                f"  sourceControlStateIndex := {binding['source_control_state_id']}\n"
                f"  innerControlStateIndex := {binding['inner_control_state_id']}\n"
                f"  resumeControlStateIndex := {binding['resume_control_state_id']}\n"
                f"  sourceToSuspended := runtimeFrameAffineSemanticTransition{transition_id}\n"
                f"  innerSeed := runtimeFrameAffineSemanticSeed{seed_id}\n"
                f"  linkShape := {_lean_link_shape(link)}\n"
                f"  sourceOffsets := {_lean_return_slot_offset_pair(binding['source_location'])}\n"
                "  suspendedOffsets := "
                f"{_lean_return_slot_offset_pair(binding['suspended_location'])}\n"
                f"  innerOffsets := {_lean_return_slot_offset_pair(binding['inner_location'])}\n"
                f"  resumeOffsets := {_lean_return_slot_offset_pair(binding['resume_location'])}\n"
                "  stackAmount := { original := "
                f"{binding['stack_amount']['original']}, candidate := "
                f"{binding['stack_amount']['candidate']} }}\n"
                f"  sourceWindow := {_lean_stack_window(binding['source_window'])}\n"
                "  returnSummaries := []\n"
                "}\n\n"
                f"def {name} : "
                "SingletonAffineReturningImportDirectCallControlBinding := {\n"
                f"  base := {base_name}\n"
                f"  externalSummary := {summary_name}\n"
                "}\n\n"
                f"theorem {checked_name} :\n"
                f"    {name}.checked staticProofContext\n"
                f"      {name}.base.sourceToSuspended.region.inputInvariant\n"
                "      runtimeFrameAffineMinimalLinkedControlProfile\n"
                "      runtimeFrameAffineProfile relationalProductGraph = true := by\n"
                "  native_decide\n\n"
                f"def {certificate_name} : "
                "SingletonAffineReturningImportDirectCallExecutionCertificate := {\n"
                f"  binding := {name}\n"
                "  entryClaim := "
                f"{_lean_returning_import_entry_inventory_claim(binding, claim)}\n"
                "  resumeClaim := "
                f"{_lean_returning_import_resume_inventory_claim(binding, claim)}\n"
                "}"
            )
        imports = sorted(set(owners))
        source = (
            "import StageA.RelationalAffineLinkedControl\n"
            + "".join(f"import StageA.{owner}\n" for owner in imports)
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\n"
            "set_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\n"
            f"def {list_name} : List "
            "SingletonAffineReturningImportDirectCallControlBinding := ["
            + ", ".join(names)
            + "]\n\n"
            f"theorem {list_checked} :\n"
            f"    {list_name}.all (fun binding => binding.checked staticProofContext\n"
            "      binding.base.sourceToSuspended.region.inputInvariant\n"
            "      runtimeFrameAffineMinimalLinkedControlProfile\n"
            "      runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
            f"  simp [{list_name}, {', '.join(checked_names)}]\n\n"
            f"def {list_name}ExecutionCertificates : List\n"
            "    SingletonAffineReturningImportDirectCallExecutionCertificate := ["
            + ", ".join(certificate_names)
            + "]\n\n"
            f"theorem {list_name}ExecutionCertificatesChecked :\n"
            f"    {list_name}ExecutionCertificates.all (fun certificate =>\n"
            "      certificate.checked staticProofContext\n"
            "        certificate.binding.base.sourceToSuspended.region.inputInvariant\n"
            "        runtimeFrameAffineMinimalLinkedControlProfile\n"
            "        runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
            "  native_decide\n\n"
            "end StageA.GeneratedRelational\n"
        )
        write_text_if_changed(stage_a / f"{module}.lean", source)
        modules.append(module)
        chunk_lists.append(list_name)
        chunk_checks.append(list_checked)
        chunk_certificate_lists.append(f"{list_name}ExecutionCertificates")
        chunk_certificate_checks.append(
            f"{list_name}ExecutionCertificatesChecked"
        )

    node_edges = sorted({
        (
            int(minimal_state_by_id[int(binding["source_control_state_id"])][
                "node_id"
            ]),
            int(binding["edge_id"]),
        )
        for binding in bindings
    })
    coverage_theorems = "\n\n".join(
        f"theorem runtimeFrameAffineExternalCallExecutionCertificatesNode{node_id}"
        f"Edge{edge_id}Covered :\n"
        "    affineReturningImportCertificatesCoverActiveCallNode\n"
        "      runtimeFrameAffineExternalCallExecutionCertificates\n"
        "      runtimeFrameAffineMinimalLinkedControlProfile\n"
        f"      {node_id} {edge_id} = true := by\n"
        "  native_decide"
        for node_id, edge_id in node_edges
    )

    aggregate_source = (
        "import StageA.RelationalAffineLinkedExecution\n"
        "import StageA.RelationalAffineLinkedControl\n"
        + "".join(f"import StageA.{module}\n" for module in modules)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\n"
        "set_option maxHeartbeats 0\n\n"
        "def runtimeFrameAffineExternalCallTransitionBindings : List\n"
        "    SingletonAffineReturningImportDirectCallControlBinding :=\n  "
        + " ++ ".join(chunk_lists)
        + "\n\n"
        "theorem runtimeFrameAffineExternalCallTransitionBindingsChecked :\n"
        "    runtimeFrameAffineExternalCallTransitionBindings.all (fun binding =>\n"
        "      binding.checked staticProofContext\n"
        "        binding.base.sourceToSuspended.region.inputInvariant\n"
        "        runtimeFrameAffineMinimalLinkedControlProfile\n"
        "        runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
        "  simp only [runtimeFrameAffineExternalCallTransitionBindings, "
        "List.all_append, Bool.true_and, Bool.and_true, "
        + ", ".join(chunk_checks)
        + "]\n\n"
        "def runtimeFrameAffineExternalCallExecutionCertificates : List\n"
        "    SingletonAffineReturningImportDirectCallExecutionCertificate :=\n  "
        + " ++ ".join(chunk_certificate_lists)
        + "\n\n"
        "theorem runtimeFrameAffineExternalCallExecutionCertificatesChecked :\n"
        "    runtimeFrameAffineExternalCallExecutionCertificates.all\n"
        "      (fun certificate => certificate.checked staticProofContext\n"
        "        certificate.binding.base.sourceToSuspended.region.inputInvariant\n"
        "        runtimeFrameAffineMinimalLinkedControlProfile\n"
        "        runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
        "  simp only [runtimeFrameAffineExternalCallExecutionCertificates, "
        "List.all_append, Bool.true_and, Bool.and_true, "
        + ", ".join(chunk_certificate_checks)
        + "]\n\n"
        + coverage_theorems
        + "\n\n"
        "end StageA.GeneratedRelational\n"
    )
    write_text_if_changed(
        stage_a / f"{AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE}.lean",
        aggregate_source,
    )
    modules.append(AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE)
    return modules


def _lean_paired_decoded_writes(writes: list[Mapping[str, Any]]) -> str:
    rows = []
    for write in writes:
        rows.append(
            "{ originalAddress := "
            + _lean_semantic_expr(dict(write["original_address"]))
            + ", originalValue := "
            + _lean_semantic_expr(dict(write["original_value"]))
            + ", candidateAddress := "
            + _lean_semantic_expr(dict(write["candidate_address"]))
            + ", candidateValue := "
            + _lean_semantic_expr(dict(write["candidate_value"]))
            + " }"
        )
    return "({ writes := [" + ", ".join(rows) + "] } : PairedDecodedWritesClaim)"


def _lean_stack_relative_expr(value: object, field: str) -> tuple[str, int]:
    expression = _mapping(value, field)
    operation = expression.get("op")
    if operation == "input_reg" and expression.get("reg") == "esp":
        return ".esp", 0
    if operation in {"add", "sub"}:
        right = _mapping(expression.get("right"), f"{field} right")
        if right.get("op") != "constant":
            raise StageAInputError(
                f"{field} is outside the checked ESP-relative write grammar"
            )
        amount = _natural(right.get("value"), f"{field} constant")
        base, base_offset = _lean_stack_relative_expr(
            expression.get("left"), f"{field} left"
        )
        if operation == "add":
            return f".add ({base}) {amount}", (base_offset + amount) % (2**32)
        return f".sub ({base}) {amount}", (base_offset - amount) % (2**32)
    raise StageAInputError(
        f"{field} is outside the checked ESP-relative write grammar"
    )


def _lean_signed_stack_offset(word_offset: int) -> str:
    if word_offset < 2**31:
        return f".above {word_offset}"
    return f".below {2**32 - word_offset}"


def _lean_paired_stack_offsets(writes: list[Mapping[str, Any]]) -> str:
    rows: list[str] = []
    for index, write in enumerate(writes):
        original_expression, original_offset = _lean_stack_relative_expr(
            write["original_address"], f"paired write {index} original address"
        )
        candidate_expression, candidate_offset = _lean_stack_relative_expr(
            write["candidate_address"], f"paired write {index} candidate address"
        )
        rows.append(
            "{ original := { expression := "
            + original_expression
            + ", offset := "
            + _lean_signed_stack_offset(original_offset)
            + " }, candidate := { expression := "
            + candidate_expression
            + ", offset := "
            + _lean_signed_stack_offset(candidate_offset)
            + " } }"
        )
    return "[" + ", ".join(rows) + "]"


def write_relational_affine_linked_memory_binding_modules(
    lean_dir: Path, payload: object
) -> list[str]:
    """Emit checked paired-write bindings, sharded by semantic owner.

    These modules prove exact correspondence to decoded write lists and exact
    control-context coverage.  Lean derives concrete arbitrary-depth frame
    disjointness from each binding's checked stack-window and link-shape
    footprint; Python never asserts the runtime non-aliasing proposition.
    """

    validated = _validated_payload(payload)
    bindings = validated["minimal_memory_bindings"]
    if not bindings:
        return []
    minimal_state_by_id = {
        int(state["id"]): state for state in validated["minimal_states"]
    }
    unique: dict[int, dict[str, Any]] = {}
    for binding in bindings:
        transition_id = int(binding["transition_id"])
        previous = unique.setdefault(transition_id, binding)
        if (
            previous["source_shape"] != binding["source_shape"]
            or previous["target_shape"] != binding["target_shape"]
            or previous["writes"] != binding["writes"]
        ):
            raise StageAInputError(
                "one affine memory semantic transition has inconsistent bindings"
            )

    stage_a = lean_dir / "StageA"
    declaration_pattern = re.compile(
        r"^def runtimeFrameAffineSemanticTransition([0-9]+)\s*:", re.MULTILINE
    )
    owner_by_transition: dict[int, str] = {}
    for source_path in sorted(stage_a.glob("RelationalAffineFrameSemanticChunk*.lean")):
        module = source_path.stem
        for matched in declaration_pattern.findall(
            source_path.read_text(encoding="utf-8")
        ):
            transition_id = int(matched)
            if transition_id in owner_by_transition:
                raise StageAInputError(
                    f"affine semantic transition {transition_id} has multiple owners"
                )
            owner_by_transition[transition_id] = module
    missing = sorted(set(unique) - owner_by_transition.keys())
    if missing:
        raise StageAInputError(
            "affine memory bindings reference semantic transitions without generated "
            f"owners: {missing[:8]!r}"
        )

    by_owner: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings:
        by_owner.setdefault(
            owner_by_transition[int(binding["transition_id"])], []
        ).append(binding)

    modules: list[str] = []
    chunk_lists: list[str] = []
    chunk_checks: list[str] = []
    coverage_owners: dict[tuple[int, int], tuple[str, int]] = {}
    for chunk_index, (owner, owner_bindings) in enumerate(sorted(by_owner.items())):
        module = f"RelationalAffineLinkedMemoryBindingChunk{chunk_index}"
        list_name = f"runtimeFrameAffineMemoryBindingChunk{chunk_index}"
        list_checked = f"{list_name}Checked"
        semantic_definitions: list[str] = []
        for transition_id in sorted({
            int(binding["transition_id"]) for binding in owner_bindings
        }):
            representative = unique[transition_id]
            name = f"runtimeFrameAffineMemoryFrameTransitionBinding{transition_id}"
            checked_name = f"{name}Checked"
            semantic_definitions.append(
                f"def {name} : ReturnSlotAffineLinkedMemoryTransitionBinding := {{\n"
                f"  sourceShape := {_lean_inventory_shape(representative['source_shape'])}\n"
                f"  targetShape := {_lean_inventory_shape(representative['target_shape'])}\n"
                f"  claim := runtimeFrameAffineSemanticTransition{transition_id}\n"
                f"  writes := {_lean_paired_decoded_writes(representative['writes'])}\n"
                f"  stackOffsets := {_lean_paired_stack_offsets(representative['writes'])}\n"
                "}\n\n"
                f"theorem {checked_name} :\n"
                f"    {name}.checked staticProofContext runtimeFrameAffineProfile\n"
                "      relationalProductGraph = true := by\n"
                "  native_decide"
            )
        definitions: list[str] = []
        names: list[str] = []
        checked_names: list[str] = []
        for binding in owner_bindings:
            transition_id = int(binding["transition_id"])
            binding_id = int(binding["id"])
            frame_name = (
                f"runtimeFrameAffineMemoryFrameTransitionBinding{transition_id}"
            )
            name = f"runtimeFrameAffineMemoryControlTransitionBinding{binding_id}"
            checked_name = f"{name}Checked"
            names.append(name)
            checked_names.append(checked_name)
            definitions.append(
                f"def {name} : AffineLinkedOrdinaryMemoryTransitionBinding := {{\n"
                f"  sourceControlStateIndex := {binding['source_control_state_id']}\n"
                f"  targetControlStateIndex := {binding['target_control_state_id']}\n"
                f"  edgeId := {binding['edge_id']}\n"
                f"  continuationTargetId := {binding['continuation_target_id']}\n"
                f"  frameBinding := {frame_name}\n"
                "}\n\n"
                f"theorem {checked_name} :\n"
                f"    {name}.checked staticProofContext\n"
                "      runtimeFrameAffineMinimalLinkedControlProfile\n"
                "      runtimeFrameAffineProfile relationalProductGraph = true := by\n"
                "  native_decide"
            )
        transitions_by_node_edge: dict[tuple[int, int], set[int]] = {}
        for binding in owner_bindings:
            node_edge = (
                int(minimal_state_by_id[int(binding["source_control_state_id"])][
                    "node_id"
                ]),
                int(binding["edge_id"]),
            )
            transitions_by_node_edge.setdefault(node_edge, set()).add(
                int(binding["transition_id"])
            )
        ambiguous_node_edges = {
            node_edge: transition_ids
            for node_edge, transition_ids in transitions_by_node_edge.items()
            if len(transition_ids) != 1
        }
        if ambiguous_node_edges:
            raise StageAInputError(
                "affine memory node/edge dispatch does not select one semantic "
                f"transition: {list(ambiguous_node_edges.items())[:4]!r}"
            )
        coverage_theorems = [
            (
                f"theorem {list_name}Node{node_id}Edge{edge_id}Covered :\n"
                "    affineMemoryBindingsCoverActiveNodeEdge\n"
                f"      {list_name} runtimeFrameAffineMinimalLinkedControlProfile\n"
                f"      {node_id} {edge_id} "
                f"runtimeFrameAffineMemoryFrameTransitionBinding"
                f"{next(iter(transition_ids))} = true := by\n"
                "  native_decide"
            )
            for (node_id, edge_id), transition_ids in sorted(
                transitions_by_node_edge.items()
            )
        ]
        for (node_id, edge_id), transition_ids in transitions_by_node_edge.items():
            coverage_owner = (list_name, next(iter(transition_ids)))
            previous = coverage_owners.setdefault(
                (node_id, edge_id), coverage_owner
            )
            if previous != coverage_owner:
                raise StageAInputError(
                    "affine memory node/edge coverage spans multiple generated "
                    f"chunks: {(node_id, edge_id)!r}"
                )
        source = (
            "import StageA.RelationalAffineLinkedMemory\n"
            "import StageA.RelationalAffineLinkedControl\n"
            f"import StageA.{owner}\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\n"
            "set_option maxHeartbeats 0\n\n"
            + "\n\n".join(semantic_definitions + definitions)
            + "\n\n"
            f"def {list_name} : List "
            "AffineLinkedOrdinaryMemoryTransitionBinding := ["
            + ", ".join(names)
            + "]\n\n"
            f"theorem {list_checked} :\n"
            f"    {list_name}.all (fun binding => binding.checked staticProofContext\n"
            "      runtimeFrameAffineMinimalLinkedControlProfile\n"
            "      runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
            f"  simp [{list_name}, {', '.join(checked_names)}]\n\n"
            + "\n\n".join(coverage_theorems)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        write_text_if_changed(stage_a / f"{module}.lean", source)
        modules.append(module)
        chunk_lists.append(list_name)
        chunk_checks.append(list_checked)

    def aggregate_membership_proof(chunk_index: int) -> str:
        if chunk_index == len(chunk_lists) - 1:
            return "Or.inr (" * chunk_index + "member" + ")" * chunk_index
        return "Or.inr (" * chunk_index + "Or.inl member" + ")" * chunk_index

    def right_associated_append(names: list[str]) -> str:
        expression = names[-1]
        for name in reversed(names[:-1]):
            expression = f"{name} ++ ({expression})"
        return expression

    chunk_membership_theorems = []
    for chunk_index, list_name in enumerate(chunk_lists):
        proof = aggregate_membership_proof(chunk_index)
        chunk_membership_theorems.append(
            f"theorem {list_name}MemberOfAggregate\n"
            "    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)\n"
            f"    (member : binding ∈ {list_name}) :\n"
            "    binding ∈ runtimeFrameAffineMemoryTransitionBindings := by\n"
            "  simp only [runtimeFrameAffineMemoryTransitionBindings, List.mem_append]\n"
            f"  exact {proof}"
        )

    aggregate_coverage_theorems = []
    for (node_id, edge_id), (list_name, transition_id) in sorted(
        coverage_owners.items()
    ):
        aggregate_coverage_theorems.append(
            "theorem runtimeFrameAffineMemoryTransitionBindingsNode"
            f"{node_id}Edge{edge_id}Covered :\n"
            "    affineMemoryBindingsCoverActiveNodeEdge\n"
            "      runtimeFrameAffineMemoryTransitionBindings\n"
            "      runtimeFrameAffineMinimalLinkedControlProfile\n"
            f"      {node_id} {edge_id} "
            f"runtimeFrameAffineMemoryFrameTransitionBinding{transition_id} = true := by\n"
            "  apply affineMemoryBindingsCoverActiveNodeEdge.mono\n"
            f"    {list_name} runtimeFrameAffineMemoryTransitionBindings\n"
            "    runtimeFrameAffineMinimalLinkedControlProfile\n"
            f"    {node_id} {edge_id} "
            f"runtimeFrameAffineMemoryFrameTransitionBinding{transition_id}\n"
            f"    {list_name}Node{node_id}Edge{edge_id}Covered\n"
            f"    {list_name}MemberOfAggregate"
        )

    aggregate_source = (
        "import StageA.RelationalAffineLinkedMemory\n"
        + "".join(f"import StageA.{module}\n" for module in modules)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\n"
        "set_option maxHeartbeats 0\n\n"
        "def runtimeFrameAffineMemoryTransitionBindings : List\n"
        "    AffineLinkedOrdinaryMemoryTransitionBinding :=\n  "
        + right_associated_append(chunk_lists)
        + "\n\n"
        "theorem runtimeFrameAffineMemoryTransitionBindingsChecked :\n"
        "    runtimeFrameAffineMemoryTransitionBindings.all (fun binding =>\n"
        "      binding.checked staticProofContext\n"
        "        runtimeFrameAffineMinimalLinkedControlProfile\n"
        "        runtimeFrameAffineProfile relationalProductGraph) = true := by\n"
        "  simp only [runtimeFrameAffineMemoryTransitionBindings, List.all_append, "
        "Bool.true_and, Bool.and_true, "
        + ", ".join(chunk_checks)
        + "]\n\n"
        + "\n\n".join(chunk_membership_theorems)
        + "\n\n"
        + "\n\n".join(aggregate_coverage_theorems)
        + "\n\n"
        "end StageA.GeneratedRelational\n"
    )
    write_text_if_changed(
        stage_a / f"{AFFINE_LINKED_MEMORY_BINDINGS_MODULE}.lean",
        aggregate_source,
    )
    modules.append(AFFINE_LINKED_MEMORY_BINDINGS_MODULE)
    return modules


__all__ = [
    "AFFINE_LINKED_CALL_BINDINGS_MODULE",
    "AFFINE_LINKED_CONTROL_BINDINGS_MODULE",
    "AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE",
    "AFFINE_LINKED_CONTROL_MODULE",
    "AFFINE_LINKED_MEMORY_BINDINGS_MODULE",
    "relational_affine_linked_control_source",
    "write_relational_affine_linked_call_binding_modules",
    "write_relational_affine_linked_control_binding_modules",
    "write_relational_affine_linked_external_call_binding_modules",
    "write_relational_affine_linked_memory_binding_modules",
    "write_relational_affine_linked_control_module",
]
