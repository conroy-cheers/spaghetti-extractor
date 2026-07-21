from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any, Mapping

from ...stage_binary import StageAInputError
from ..runtime_frame_artifact import RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT


AFFINE_LINKED_CONTROL_FORMAT = "stage-a-affine-linked-control-v1"
_WORD_MODULUS = 2**32


def _copy(value: object) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{field} must be a list")
    return value


def _paired_writes(
    original_writes: list[Any], candidate_writes: list[Any], field: str
) -> list[dict[str, Any]]:
    paired: list[dict[str, Any]] = []
    for index, (original_value, candidate_value) in enumerate(
        zip(original_writes, candidate_writes, strict=True)
    ):
        original = _mapping(original_value, f"{field} original write {index}")
        candidate = _mapping(candidate_value, f"{field} candidate write {index}")
        for side, write in (("original", original), ("candidate", candidate)):
            if set(write) != {"address", "value"}:
                raise StageAInputError(
                    f"{field} {side} write {index} must contain address and value"
                )
            _mapping(write["address"], f"{field} {side} write {index} address")
            _mapping(write["value"], f"{field} {side} write {index} value")
        paired.append({
            "original_address": _copy(original["address"]),
            "original_value": _copy(original["value"]),
            "candidate_address": _copy(candidate["address"]),
            "candidate_value": _copy(candidate["value"]),
        })
    return paired


def _natural(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{field} must be a natural number")
    return value


def _word(value: object, field: str) -> int:
    result = _natural(value, field)
    if result >= _WORD_MODULUS:
        raise StageAInputError(f"{field} must fit in a 32-bit word")
    return result


def _canonical_rows(value: object, field: str) -> tuple[Mapping[str, Any], ...]:
    rows = tuple(_mapping(row, f"{field} row") for row in _list(value, field))
    ids = tuple(_natural(row.get("id"), f"{field} id") for row in rows)
    if ids != tuple(range(len(rows))):
        raise StageAInputError(f"{field} ids must be canonical and contiguous")
    return rows


def _location(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    original_register = row.get("original_register")
    candidate_register = row.get("candidate_register")
    if not isinstance(original_register, str) or not original_register:
        raise StageAInputError(f"{field} original_register must be a register")
    if not isinstance(candidate_register, str) or not candidate_register:
        raise StageAInputError(f"{field} candidate_register must be a register")
    return {
        "original_register": original_register,
        "original": _word(row.get("original"), f"{field} original offset"),
        "candidate_register": candidate_register,
        "candidate": _word(row.get("candidate"), f"{field} candidate offset"),
    }


def _family(value: object, field: str) -> dict[str, Any]:
    row = _mapping(value, field)
    original_register = row.get("original_register")
    candidate_register = row.get("candidate_register")
    if not isinstance(original_register, str) or not original_register:
        raise StageAInputError(f"{field} original_register must be a register")
    if not isinstance(candidate_register, str) or not candidate_register:
        raise StageAInputError(f"{field} candidate_register must be a register")
    stride = _natural(row.get("translation_stride"), f"{field} stride")
    if stride == 0 or _WORD_MODULUS % stride:
        raise StageAInputError(f"{field} stride must divide 2^32")
    return {
        "original_register": original_register,
        "original_base": _word(row.get("original_base"), f"{field} original base"),
        "candidate_register": candidate_register,
        "candidate_base": _word(row.get("candidate_base"), f"{field} candidate base"),
        "translation_stride": stride,
    }


def _family_contains(family: Mapping[str, Any], location: Mapping[str, Any]) -> bool:
    if (
        family["original_register"] != location["original_register"]
        or family["candidate_register"] != location["candidate_register"]
    ):
        return False
    translation = (
        int(location["original"]) - int(family["original_base"])
    ) % _WORD_MODULUS
    return bool(
        translation % int(family["translation_stride"]) == 0
        and (
            int(family["candidate_base"]) + translation
        ) % _WORD_MODULUS == int(location["candidate"])
    )


def _singleton_family_location(
    family: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return the sole member of a full-word-stride affine family.

    Smaller strides denote genuine modular cosets.  Treating their canonical
    base as a concrete stack location would lose the quantified coefficient
    and, in particular, would not justify natural frame ordering.
    """

    if int(family["translation_stride"]) != _WORD_MODULUS:
        return None
    return {
        "original_register": family["original_register"],
        "original": int(family["original_base"]),
        "candidate_register": family["candidate_register"],
        "candidate": int(family["candidate_base"]),
    }


def _esp_subtraction_amount(value: object, field: str) -> int | None:
    """Recognize an exact post-call ESP expression as ``esp - amount``."""

    expression = _mapping(value, field)
    operation = expression.get("op")
    if operation == "input_reg" and expression.get("reg") == "esp":
        return 0
    if operation not in {"add", "sub"}:
        return None
    left = _mapping(expression.get("left"), f"{field} left")
    right = _mapping(expression.get("right"), f"{field} right")
    if right.get("op") != "constant":
        return None
    prior = _esp_subtraction_amount(left, f"{field} left")
    if prior is None:
        return None
    value = _word(right.get("value"), f"{field} constant")
    if operation == "sub":
        return (prior + value) % _WORD_MODULUS
    return (prior - value) % _WORD_MODULUS


def _inventory_shape(
    value: object,
    *,
    node_id: int,
    families_by_node: Mapping[int, tuple[dict[str, Any], ...]],
    fallbacks: list[dict[str, Any]],
    owner: str,
) -> dict[str, Any]:
    inventory = _mapping(value, f"{owner} inventory")
    locations = [
        _location(item, f"{owner} inventory location")
        for item in _list(inventory.get("locations"), f"{owner} inventory locations")
    ]
    location_shape: dict[str, Any]
    matches: list[dict[str, Any]] = []
    if len(locations) == 1:
        matches = [
            family
            for family in families_by_node.get(node_id, ())
            if _family_contains(family["family"], locations[0])
        ]
    if len(matches) == 1:
        location_shape = {
            "kind": "affine_family",
            "artifact_state_id": matches[0]["artifact_state_id"],
            "profile_state_index": matches[0]["profile_state_index"],
        }
    else:
        location_shape = {"kind": "exact", "locations": locations}
        fallbacks.append({
            "owner": owner,
            "node_id": node_id,
            "reason": (
                "non_singleton_inventory" if len(locations) != 1
                else "no_unique_rooted_affine_family"
            ),
            "candidate_family_ids": [
                match["artifact_state_id"] for match in matches
            ],
        })
    shape = {"locations": location_shape}
    exact_words = _list(
        inventory.get("exact_words", []), f"{owner} inventory exact_words"
    )
    if exact_words:
        shape["exact_words"] = [
            {
                "original": _natural(
                    _mapping(row, f"{owner} exact word").get("original"),
                    f"{owner} exact word original",
                ),
                "candidate": _natural(
                    _mapping(row, f"{owner} exact word").get("candidate"),
                    f"{owner} exact word candidate",
                ),
            }
            for row in exact_words
        ]
    preserved_imports = _list(
        inventory.get("preserved_imports", []),
        f"{owner} inventory preserved_imports",
    )
    if preserved_imports:
        normalized_imports: list[dict[str, Any]] = []
        for value in preserved_imports:
            row = _mapping(value, f"{owner} preserved import")
            required = {"original", "candidate", "import"}
            if not required.issubset(row):
                raise StageAInputError(
                    f"{owner} preserved import is missing semantic fields"
                )
            unsupported = set(row) - required - {"origin"}
            if unsupported:
                raise StageAInputError(
                    f"{owner} preserved import has unsupported fields: "
                    + ", ".join(sorted(unsupported))
                )
            normalized_imports.append({key: _copy(row[key]) for key in required})
        shape["preserved_imports"] = normalized_imports
    preserved_relations = _list(
        inventory.get("preserved_relations", []),
        f"{owner} inventory preserved_relations",
    )
    if preserved_relations:
        normalized_relations: list[dict[str, Any]] = []
        for value in preserved_relations:
            row = _mapping(value, f"{owner} preserved relation")
            relation = row.get("relation")
            required = {"original", "candidate", "relation"}
            if relation == "fixed_word":
                required.add("value")
            elif relation == "fixed_code_pointer":
                required.add("target_id")
            if not required.issubset(row):
                raise StageAInputError(
                    f"{owner} preserved relation is missing semantic fields"
                )
            unsupported = set(row) - required - {"origin"}
            if unsupported:
                raise StageAInputError(
                    f"{owner} preserved relation has unsupported fields: "
                    + ", ".join(sorted(unsupported))
                )
            normalized_relations.append({key: _copy(row[key]) for key in required})
        shape["preserved_relations"] = normalized_relations
    return shape


def affine_linked_control_payload(
    *,
    runtime_frame_affine: Mapping[str, Any],
    linked_control: Mapping[str, Any],
    product_graph: Mapping[str, Any],
    behaviors: list[dict[str, Any]] | None = None,
    regions: list[dict[str, Any]] | None = None,
    register_relations: Mapping[str, Any] | None = None,
    physical_state_only_region_indices: set[int] | frozenset[int] = frozenset(),
) -> dict[str, Any]:
    """Project exact linked evidence into a hybrid exact/affine specification.

    This is untrusted proposal construction.  It deliberately retains exact
    locations when an affine family is unavailable or ambiguous; generated Lean
    must check every resulting shape before it can become control authority.
    """

    if runtime_frame_affine.get("format") != RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT:
        raise StageAInputError("unsupported runtime-frame affine artifact format")
    certificate = _mapping(
        runtime_frame_affine.get("certificate"), "runtime-frame affine certificate"
    )
    affine_states = _canonical_rows(
        certificate.get("viable_families"), "viable affine families"
    )
    affine_transitions = _canonical_rows(
        certificate.get("viable_transitions"), "viable affine transitions"
    )
    affine_seeds = _canonical_rows(
        certificate.get("viable_seeds"), "viable affine seeds"
    )
    rooted_ids = tuple(
        _natural(item, "seed-rooted affine state id")
        for item in _list(
            certificate.get("seed_rooted_state_ids"),
            "seed-rooted affine state ids",
        )
    )
    if rooted_ids != tuple(sorted(set(rooted_ids))):
        raise StageAInputError("seed-rooted affine state ids must be canonical")
    if any(item >= len(affine_states) for item in rooted_ids):
        raise StageAInputError("seed-rooted affine state id is out of range")
    rooted_transition_ids = tuple(
        _natural(item, "seed-rooted affine transition id")
        for item in _list(
            certificate.get("seed_rooted_transition_ids"),
            "seed-rooted affine transition ids",
        )
    )
    if rooted_transition_ids != tuple(sorted(set(rooted_transition_ids))):
        raise StageAInputError(
            "seed-rooted affine transition ids must be canonical"
        )
    if any(item >= len(affine_transitions) for item in rooted_transition_ids):
        raise StageAInputError("seed-rooted affine transition id is out of range")
    profile_state_ids = tuple(
        _natural(item, "affine profile state id")
        for item in _list(
            certificate.get("affine_profile_state_ids", list(rooted_ids)),
            "affine profile state ids",
        )
    )
    if profile_state_ids != tuple(sorted(set(profile_state_ids))):
        raise StageAInputError("affine profile state ids must be canonical")
    if any(item >= len(affine_states) for item in profile_state_ids):
        raise StageAInputError("affine profile state id is out of range")
    if not set(rooted_ids).issubset(profile_state_ids):
        raise StageAInputError("affine profile states omit a seed-rooted state")
    profile_transition_ids = tuple(
        _natural(item, "affine profile transition id")
        for item in _list(
            certificate.get(
                "affine_profile_transition_ids", list(rooted_transition_ids)
            ),
            "affine profile transition ids",
        )
    )
    if profile_transition_ids != tuple(sorted(set(profile_transition_ids))):
        raise StageAInputError("affine profile transition ids must be canonical")
    if any(item >= len(affine_transitions) for item in profile_transition_ids):
        raise StageAInputError("affine profile transition id is out of range")
    if not set(rooted_transition_ids).issubset(profile_transition_ids):
        raise StageAInputError(
            "affine profile transitions omit a seed-rooted transition"
        )
    for transition in affine_transitions:
        transition_id = _natural(transition.get("id"), "affine transition id")
        for field in ("source_state_id", "target_state_id"):
            state_id = _natural(
                transition.get(field), f"affine transition {transition_id} {field}"
            )
            if state_id >= len(affine_states):
                raise StageAInputError(
                    f"affine transition {transition_id} references an unknown state"
                )

    families_by_node_mutable: dict[int, list[dict[str, Any]]] = {}
    for profile_index, state_id in enumerate(profile_state_ids):
        state = affine_states[state_id]
        node_id = _natural(state.get("node_id"), "affine state node_id")
        if (state.get("seed_rooted") is True) != (state_id in rooted_ids):
            raise StageAInputError(
                "affine profile state has inconsistent seed-rooted status"
            )
        families_by_node_mutable.setdefault(node_id, []).append({
            "artifact_state_id": state_id,
            "profile_state_index": profile_index,
            "family": _family(state.get("family"), "affine state family"),
        })
    families_by_node = {
        node_id: tuple(rows)
        for node_id, rows in families_by_node_mutable.items()
    }
    profile_index_by_artifact_state_id = {
        state_id: profile_index
        for profile_index, state_id in enumerate(profile_state_ids)
    }

    exact_states = _canonical_rows(linked_control.get("states"), "linked states")
    fallbacks: list[dict[str, Any]] = []
    states: list[dict[str, Any]] = []
    for state in exact_states:
        state_id = _natural(state.get("id"), "linked state id")
        node_id = _natural(state.get("node_id"), "linked state node_id")
        continuation = state.get("continuation_target_id")
        if continuation is not None:
            continuation = _natural(continuation, "linked state continuation")
        active = state.get("active_frame")
        if (continuation is None) != (active is None):
            raise StageAInputError(
                "linked state continuation and active frame must be present together"
            )
        states.append({
            "id": state_id,
            "node_id": node_id,
            "continuation_target_id": continuation,
            "active_shape": (
                None
                if active is None
                else _inventory_shape(
                    active,
                    node_id=node_id,
                    families_by_node=families_by_node,
                    fallbacks=fallbacks,
                    owner=f"state {state_id} active",
                )
            ),
            "minimum_depth": _natural(
                state.get("minimum_depth", 0), "linked state minimum_depth"
            ),
        })

    graph_edges = _canonical_rows(product_graph.get("edges"), "product edges")
    graph_nodes = _canonical_rows(product_graph.get("nodes"), "product nodes")
    node_ids_by_target_id: dict[int, list[int]] = defaultdict(list)
    for node in graph_nodes:
        node_ids_by_target_id[_natural(
            node.get("target_id"), "product node target_id"
        )].append(_natural(node.get("id"), "product node id"))

    register_edges_by_region_pair: dict[tuple[int, int], Mapping[str, Any]] = {}
    if register_relations is not None:
        register_edges = tuple(
            _mapping(row, "register relation edge")
            for row in _list(
                register_relations.get("edges"), "register relation edges"
            )
        )
        for edge in register_edges:
            key = (
                _natural(
                    edge.get("source_region_index"),
                    "register relation source_region_index",
                ),
                _natural(
                    edge.get("target_region_index"),
                    "register relation target_region_index",
                ),
            )
            if key in register_edges_by_region_pair:
                raise StageAInputError(
                    "register relation region-pair edges must be unique"
                )
            register_edges_by_region_pair[key] = edge
    region_rows: tuple[Mapping[str, Any], ...] = ()
    if regions is not None:
        region_rows = tuple(
            _mapping(row, "relation region") for row in regions
        )
    links_value = _list(linked_control.get("links"), "linked links")
    links: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    for position, value in enumerate(links_value):
        link = _mapping(value, "linked link")
        source_state_id = _natural(link.get("source_state_id"), "link source state")
        target_state_id = _natural(link.get("target_state_id"), "link target state")
        resume_state_id = _natural(link.get("resume_state_id"), "link resume state")
        if any(item >= len(states) for item in (
            source_state_id, target_state_id, resume_state_id
        )):
            raise StageAInputError("linked link references an unknown control state")
        source_state = states[source_state_id]
        target_state = states[target_state_id]
        resume_state = states[resume_state_id]
        call_source_target_id = _natural(
            link.get("call_source_target_id"), "link call source target"
        )
        matching_edges = [
            edge
            for edge in graph_edges
            if edge.get("kind") == "call"
            and not edge.get("infeasible")
            and edge.get("source_node_id") == source_state["node_id"]
            and edge.get("target_node_id") == target_state["node_id"]
            and edge.get("source_target_id") == call_source_target_id
        ]
        if len(matching_edges) != 1:
            gaps.append({
                "link_position": position,
                "reason": "call_edge_not_unique",
                "candidate_edge_ids": [edge["id"] for edge in matching_edges],
            })
            continue
        resume_node_id = _natural(link.get("resume_node_id"), "link resume node")
        if resume_node_id != resume_state["node_id"]:
            raise StageAInputError("linked link resume state does not match resume node")
        inner_node_id = target_state["node_id"]
        links.append({
            "id": len(links),
            "call_edge_id": matching_edges[0]["id"],
            "call_source_node_id": source_state["node_id"],
            "call_source_target_id": call_source_target_id,
            "inner_inventory_node_id": inner_node_id,
            "suspended_inventory_node_id": inner_node_id,
            "resume_inventory_node_id": resume_node_id,
            "resume_target_id": _natural(
                link.get("resume_target_id"), "link resume target"
            ),
            "resume_continuation": _natural(
                link.get("resume_continuation"), "link resume continuation"
            ),
            "inner_shape": _inventory_shape(
                link.get("inner_inventory"),
                node_id=inner_node_id,
                families_by_node=families_by_node,
                fallbacks=fallbacks,
                owner=f"link {position} inner",
            ),
            "suspended_shape": _inventory_shape(
                link.get("suspended_inventory"),
                node_id=inner_node_id,
                families_by_node=families_by_node,
                fallbacks=fallbacks,
                owner=f"link {position} suspended",
            ),
            "resume_shape": _inventory_shape(
                link.get("resume_inventory"),
                node_id=resume_node_id,
                families_by_node=families_by_node,
                fallbacks=fallbacks,
                owner=f"link {position} resume",
            ),
            "original_gap": _natural(link.get("original_gap"), "link original gap"),
            "candidate_gap": _natural(
                link.get("candidate_gap"), "link candidate gap"
            ),
        })

    synthesized_resume_state_ids: list[int] = []
    for link in links:
        if any(
            state["node_id"] == link["resume_inventory_node_id"]
            and state["continuation_target_id"] == link["resume_continuation"]
            and state["active_shape"] == link["resume_shape"]
            and state["minimum_depth"] <= 1
            for state in states
        ):
            continue
        state_id = len(states)
        states.append({
            "id": state_id,
            "node_id": link["resume_inventory_node_id"],
            "continuation_target_id": link["resume_continuation"],
            "active_shape": _copy(link["resume_shape"]),
            "minimum_depth": 1,
        })
        synthesized_resume_state_ids.append(state_id)

    shapes = [
        *(state["active_shape"] for state in states
          if state["active_shape"] is not None),
        *(item[key] for item in links
          for key in ("inner_shape", "suspended_shape", "resume_shape")),
    ]
    represented_state_ids = sorted({
        int(shape["locations"]["artifact_state_id"])
        for shape in shapes
        if shape["locations"]["kind"] == "affine_family"
    })
    unrepresented_state_ids = sorted(
        set(profile_state_ids) - set(represented_state_ids)
    )

    control_states_by_affine_state: dict[int, list[dict[str, Any]]] = {}
    for state in states:
        shape = state["active_shape"]
        if (
            shape is not None
            and shape["locations"]["kind"] == "affine_family"
        ):
            control_states_by_affine_state.setdefault(
                int(shape["locations"]["artifact_state_id"]), []
            ).append(state)

    def payload_key(shape: Mapping[str, Any]) -> str:
        return json.dumps({
            "exact_words": shape.get("exact_words", []),
            "preserved_imports": shape.get("preserved_imports", []),
            "preserved_relations": shape.get("preserved_relations", []),
        }, sort_keys=True, separators=(",", ":"))

    transition_bindings: list[dict[str, Any]] = []
    memory_transition_bindings: list[dict[str, Any]] = []
    transition_binding_gaps: list[dict[str, Any]] = []
    for transition_id in profile_transition_ids:
        transition = affine_transitions[transition_id]
        source_state_id = int(transition["source_state_id"])
        target_state_id = int(transition["target_state_id"])
        source_candidates = control_states_by_affine_state.get(source_state_id, [])
        target_candidates = control_states_by_affine_state.get(target_state_id, [])
        pairs = [
            (source, target)
            for source in source_candidates
            for target in target_candidates
            if source["continuation_target_id"] == target["continuation_target_id"]
            and payload_key(source["active_shape"]) == payload_key(target["active_shape"])
        ]
        if len(pairs) != 1:
            transition_binding_gaps.append({
                "transition_id": transition_id,
                "reason": "control_state_pair_not_unique",
                "source_control_state_ids": [
                    int(item["id"]) for item in source_candidates
                ],
                "target_control_state_ids": [
                    int(item["id"]) for item in target_candidates
                ],
                "compatible_pairs": [
                    [int(source["id"]), int(target["id"])]
                    for source, target in pairs
                ],
            })
            continue
        source, target = pairs[0]
        edge_id = _natural(transition.get("edge_index"), "transition edge_index")
        if edge_id >= len(graph_edges):
            raise StageAInputError("affine transition edge is out of range")
        edge = graph_edges[edge_id]
        source_node_id = _natural(
            transition.get("source_node"), "transition source_node"
        )
        target_node_id = _natural(
            transition.get("target_node"), "transition target_node"
        )
        if (
            edge.get("source_node_id") != source_node_id
            or edge.get("target_node_id") != target_node_id
            or source["node_id"] != source_node_id
            or target["node_id"] != target_node_id
        ):
            raise StageAInputError(
                "affine transition control states do not match its product edge"
            )
        if behaviors is None:
            transition_binding_gaps.append({
                "transition_id": transition_id,
                "reason": "decoded_behavior_inventory_missing",
            })
            continue
        if source_node_id >= len(graph_nodes):
            raise StageAInputError("affine transition source node is out of range")
        region_id = _natural(
            graph_nodes[source_node_id].get("target_id"),
            "affine transition source target_id",
        )
        if region_id >= len(behaviors):
            raise StageAInputError("affine transition source region is out of range")
        behavior = _mapping(behaviors[region_id], "affine transition behavior")
        if region_id in physical_state_only_region_indices:
            transition_binding_gaps.append({
                "transition_id": transition_id,
                "reason": "physical_state_only_transition",
            })
            continue
        original_ir = _mapping(
            behavior.get("original_ir"), "affine transition original_ir"
        )
        candidate_ir = _mapping(
            behavior.get("candidate_ir"), "affine transition candidate_ir"
        )
        original_writes = _list(
            original_ir.get("writes"), "affine transition original writes"
        )
        candidate_writes = _list(
            candidate_ir.get("writes"), "affine transition candidate writes"
        )
        base_binding = {
            "id": len(transition_bindings),
            "transition_id": transition_id,
            "edge_id": edge_id,
            "source_control_state_id": int(source["id"]),
            "target_control_state_id": int(target["id"]),
            "source_shape": _copy(source["active_shape"]),
            "target_shape": _copy(target["active_shape"]),
        }
        if original_writes or candidate_writes:
            if len(original_writes) != len(candidate_writes):
                transition_binding_gaps.append({
                    "transition_id": transition_id,
                    "reason": "memory_write_count_mismatch",
                    "original_write_count": len(original_writes),
                    "candidate_write_count": len(candidate_writes),
                })
                continue
            memory_transition_bindings.append({
                **base_binding,
                "id": len(memory_transition_bindings),
                "writes": _paired_writes(
                    original_writes, candidate_writes, "affine transition"
                ),
                "profile": "ordinary_paired_write_affine_control_v1",
            })
            continue
        transition_bindings.append({
            **base_binding,
            "profile": "ordinary_no_write_affine_control_v1",
        })
    bound_transition_ids = sorted(
        {
            int(binding["transition_id"])
            for binding in [*transition_bindings, *memory_transition_bindings]
        }
    )
    unbound_transition_ids = sorted(
        set(profile_transition_ids) - set(bound_transition_ids)
    )

    ordinary_transitions_by_source: dict[int, list[Mapping[str, Any]]] = (
        defaultdict(list)
    )
    call_transitions_by_source: dict[int, list[Mapping[str, Any]]] = (
        defaultdict(list)
    )
    call_transition_ids: list[int] = []
    call_transition_rows: list[dict[str, int]] = []
    for transition_id in profile_transition_ids:
        transition = affine_transitions[transition_id]
        edge_id = int(transition["edge_index"])
        if edge_id >= len(graph_edges):
            raise StageAInputError("affine transition edge is out of range")
        if graph_edges[edge_id].get("kind") == "call":
            call_transition_ids.append(transition_id)
            call_transitions_by_source[
                int(transition["source_state_id"])
            ].append(transition)
            call_transition_rows.append({
                "transition_id": transition_id,
                "edge_id": edge_id,
                "source_node_id": int(transition["source_node"]),
                "target_node_id": int(transition["target_node"]),
            })
        else:
            ordinary_transitions_by_source[
                int(transition["source_state_id"])
            ].append(transition)

    def affine_shape(state_id: int) -> dict[str, Any]:
        return {
            "locations": {
                "kind": "affine_family",
                "artifact_state_id": state_id,
                "profile_state_index": profile_index_by_artifact_state_id[state_id],
            },
        }

    seeds_by_edge: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
    for seed in affine_seeds:
        seeds_by_edge[_natural(seed.get("edge_index"), "affine seed edge_index")].append(
            seed
        )

    call_descriptors: dict[int, dict[str, Any]] = {}
    call_transition_binding_gaps: list[dict[str, Any]] = []

    def call_gap(transition: Mapping[str, Any], reason: str, **detail: Any) -> None:
        call_transition_binding_gaps.append({
            "transition_id": int(transition["id"]),
            "edge_id": int(transition["edge_index"]),
            "source_node_id": int(transition["source_node"]),
            "target_node_id": int(transition["target_node"]),
            "reason": reason,
            **detail,
        })

    for transition_id in call_transition_ids:
        transition = affine_transitions[transition_id]
        edge_id = int(transition["edge_index"])
        if not register_edges_by_region_pair or not region_rows:
            call_gap(transition, "call_contract_inventory_missing")
            continue
        seed_candidates = seeds_by_edge.get(edge_id, [])
        if len(seed_candidates) != 1:
            call_gap(
                transition,
                (
                    "call_seed_missing"
                    if not seed_candidates
                    else "call_seed_ambiguous"
                ),
                candidate_seed_ids=[int(seed["id"]) for seed in seed_candidates],
            )
            continue
        seed = seed_candidates[0]
        source_state_id = int(transition["source_state_id"])
        suspended_state_id = int(transition["target_state_id"])
        inner_state_id = _natural(
            seed.get("target_state_id"), "affine call seed target_state_id"
        )
        if inner_state_id >= len(affine_states):
            raise StageAInputError("affine call seed target state is out of range")
        if (
            int(affine_states[source_state_id]["node_id"])
            != int(transition["source_node"])
            or int(affine_states[suspended_state_id]["node_id"])
            != int(transition["target_node"])
            or int(affine_states[inner_state_id]["node_id"])
            != int(transition["target_node"])
        ):
            raise StageAInputError(
                "affine call states do not match the call product edge"
            )
        source_family = _family(
            affine_states[source_state_id].get("family"), "call source family"
        )
        suspended_family = _family(
            affine_states[suspended_state_id].get("family"),
            "call suspended family",
        )
        inner_family = _family(
            affine_states[inner_state_id].get("family"), "call inner family"
        )
        source_location = _singleton_family_location(source_family)
        suspended_location = _singleton_family_location(suspended_family)
        inner_location = _singleton_family_location(inner_family)
        if source_location is None:
            call_gap(transition, "call_source_family_not_singleton")
            continue
        if suspended_location is None:
            call_gap(transition, "call_suspended_family_not_singleton")
            continue
        if inner_location is None:
            call_gap(transition, "call_inner_family_not_singleton")
            continue

        graph_edge = graph_edges[edge_id]
        relation_edge = register_edges_by_region_pair.get((
            _natural(
                graph_edge.get("source_target_id"),
                "call product edge source_target_id",
            ),
            _natural(
                graph_edge.get("target_target_id"),
                "call product edge target_target_id",
            ),
        ))
        if relation_edge is None:
            call_gap(transition, "call_register_relation_edge_missing")
            continue
        summary_claims = _list(
            relation_edge.get("return_slot_call_summary_claims", []),
            "return-slot call summary claims",
        )
        external_summary_claims = _list(
            relation_edge.get("return_slot_external_call_summary_claims", []),
            "external return-slot call summary claims",
        )
        matching_claims: list[Mapping[str, Any]] = []
        for raw_claim in summary_claims:
            claim = _mapping(raw_claim, "return-slot call summary claim")
            if _location(claim.get("source"), "call summary source") == source_location:
                matching_claims.append(claim)
        matching_external_claims: list[Mapping[str, Any]] = []
        for raw_claim in external_summary_claims:
            claim = _mapping(
                raw_claim, "external return-slot call summary claim"
            )
            if _location(
                claim.get("source"), "external call summary source"
            ) == source_location:
                matching_external_claims.append(claim)
        if matching_claims and matching_external_claims:
            call_gap(
                transition,
                "call_return_summary_kind_ambiguous",
                internal_matching_claim_count=len(matching_claims),
                external_matching_claim_count=len(matching_external_claims),
            )
            continue
        selected_claims = matching_claims or matching_external_claims
        target_locations = {
            json.dumps(
                _location(claim.get("target"), "call summary target"),
                sort_keys=True,
                separators=(",", ":"),
            )
            for claim in selected_claims
        }
        if not selected_claims:
            call_gap(
                transition,
                "call_return_summary_missing",
                matching_claim_count=0,
                target_count=len(target_locations),
            )
            continue
        if len(target_locations) != 1:
            call_gap(
                transition,
                "call_return_summary_ambiguous",
                matching_claim_count=len(matching_claims),
                target_count=len(target_locations),
            )
            continue
        resume_location = json.loads(next(iter(target_locations)))
        return_summaries: list[dict[str, Any]] = []
        external_summary: dict[str, Any] | None = None
        return_summary_invalid = False
        for claim in matching_claims:
            return_region_index = _natural(
                claim.get("return_region_index"),
                "call summary return_region_index",
            )
            if return_region_index >= len(region_rows):
                call_gap(
                    transition,
                    "call_return_region_out_of_range",
                    return_region_index=return_region_index,
                )
                return_summary_invalid = True
                break
            return_target_id = _natural(
                region_rows[return_region_index].get("numeric_id"),
                "call summary return region numeric_id",
            )
            return_node_ids = node_ids_by_target_id.get(return_target_id, [])
            if len(return_node_ids) != 1:
                call_gap(
                    transition,
                    "call_return_node_not_unique",
                    return_region_index=return_region_index,
                    candidate_node_ids=return_node_ids,
                )
                return_summary_invalid = True
                break
            return_summaries.append({
                "return_region_index": return_region_index,
                "return_node_id": return_node_ids[0],
                "claim": _copy(claim),
            })
        if return_summary_invalid:
            continue
        if matching_external_claims:
            if len(matching_external_claims) != 1:
                call_gap(
                    transition,
                    "call_external_return_summary_ambiguous",
                    matching_claim_count=len(matching_external_claims),
                )
                continue
            claim = matching_external_claims[0]
            thunk_region_index = _natural(
                claim.get("thunk_region_index"),
                "external call summary thunk_region_index",
            )
            contract_id = _natural(
                claim.get("machine_contract_id"),
                "external call summary machine_contract_id",
            )
            if (
                claim.get("profile") != "external_return_slot_call_summary_v1"
                or thunk_region_index >= len(region_rows)
                or thunk_region_index
                    != _natural(
                        graph_edge.get("target_target_id"),
                        "external call target target_id",
                    )
                or int(transition["target_node"]) >= len(graph_nodes)
                or _natural(
                    graph_nodes[int(transition["target_node"])] .get("target_id"),
                    "external call target node target_id",
                ) != thunk_region_index
            ):
                call_gap(
                    transition,
                    "call_external_return_summary_target_mismatch",
                    thunk_region_index=thunk_region_index,
                )
                continue
            external_summary = {
                "thunk_region_index": thunk_region_index,
                "thunk_node_id": int(transition["target_node"]),
                "machine_contract_id": contract_id,
                "claim": _copy(claim),
            }
        return_summaries.sort(key=lambda row: json.dumps(
            row, sort_keys=True, separators=(",", ":")
        ))
        push = _mapping(
            seed.get("direct_call_push_claim"), "affine call direct_call_push_claim"
        )
        call_continuation = _natural(
            push.get("continuation_target_id"), "affine call continuation_target_id"
        )
        if external_summary is not None and _natural(
            external_summary["claim"].get("continuation_region_index"),
            "external call summary continuation_region_index",
        ) != call_continuation:
            call_gap(
                transition,
                "call_external_return_summary_continuation_mismatch",
            )
            continue
        resume_nodes = node_ids_by_target_id.get(call_continuation, [])
        if len(resume_nodes) != 1:
            call_gap(
                transition,
                "call_resume_node_not_unique",
                candidate_node_ids=resume_nodes,
            )
            continue
        resume_node_id = resume_nodes[0]
        resume_state_candidates = [
            state_id
            for state_id in profile_state_ids
            if int(affine_states[state_id]["node_id"]) == resume_node_id
            and _family_contains(
                _family(
                    affine_states[state_id].get("family"),
                    "call resume family",
                ),
                resume_location,
            )
        ]
        if len(resume_state_candidates) != 1:
            call_gap(
                transition,
                (
                    "call_resume_affine_state_missing"
                    if not resume_state_candidates
                    else "call_resume_affine_state_ambiguous"
                ),
                candidate_state_ids=resume_state_candidates,
            )
            continue
        resume_state_id = resume_state_candidates[0]

        original_amount = _esp_subtraction_amount(
            push.get("original_stack_address"), "original call stack address"
        )
        candidate_amount = _esp_subtraction_amount(
            push.get("candidate_stack_address"), "candidate call stack address"
        )
        if (
            original_amount is None
            or candidate_amount is None
            or not 4 <= original_amount < _WORD_MODULUS
            or not 4 <= candidate_amount < _WORD_MODULUS
            or original_amount % 4
            or candidate_amount % 4
        ):
            call_gap(
                transition,
                "call_stack_amount_not_paired",
                original_amount=original_amount,
                candidate_amount=candidate_amount,
            )
            continue
        stack_amount = {
            "original": original_amount,
            "candidate": candidate_amount,
        }
        source_node_id = int(transition["source_node"])
        source_region_id = int(graph_nodes[source_node_id]["target_id"])
        if source_region_id >= len(region_rows):
            raise StageAInputError("affine call source region is out of range")
        call_write_gap: dict[str, Any] | None = None
        if behaviors is not None:
            if source_region_id >= len(behaviors):
                raise StageAInputError(
                    "affine call source behavior is out of range"
                )
            source_behavior = _mapping(
                behaviors[source_region_id], "affine call source behavior"
            )
            original_call_ir = _mapping(
                source_behavior.get("original_ir"),
                "affine call original behavior",
            )
            candidate_call_ir = _mapping(
                source_behavior.get("candidate_ir"),
                "affine call candidate behavior",
            )
            original_call_writes = _list(
                original_call_ir.get("writes"),
                "affine call original writes",
            )
            candidate_call_writes = _list(
                candidate_call_ir.get("writes"),
                "affine call candidate writes",
            )
            if len(original_call_writes) != 1 or len(candidate_call_writes) != 1:
                call_write_gap = {
                    "reason": "call_linked_memory_binding_required",
                    "original_write_count": len(original_call_writes),
                    "candidate_write_count": len(candidate_call_writes),
                }
                call_gap(
                    transition,
                    call_write_gap["reason"],
                    original_write_count=call_write_gap["original_write_count"],
                    candidate_write_count=call_write_gap["candidate_write_count"],
                )
        windows = []
        for value in _list(
            region_rows[source_region_id].get("stack_windows", []),
            "affine call source stack windows",
        ):
            window = _mapping(value, "affine call source stack window")
            if (
                window.get("original_register") == source_location["original_register"]
                and window.get("candidate_register")
                == source_location["candidate_register"]
                and original_amount <= int(window.get("bytes_below", -1))
                and candidate_amount <= int(window.get("bytes_below", -1))
                and int(source_location["original"]) + 4
                <= int(window.get("bytes_above", -1))
                and int(source_location["candidate"]) + 4
                <= int(window.get("bytes_above", -1))
            ):
                windows.append({
                    "range_id": _natural(window.get("range_id"), "stack range_id"),
                    "original_register": str(window["original_register"]),
                    "candidate_register": str(window["candidate_register"]),
                    "bytes_below": _natural(
                        window.get("bytes_below"), "stack bytes_below"
                    ),
                    "bytes_above": _natural(
                        window.get("bytes_above"), "stack bytes_above"
                    ),
                })
        if not windows:
            call_gap(
                transition,
                "call_source_stack_window_missing",
                stack_amount=stack_amount,
                source_location=source_location,
            )
            continue
        windows.sort(key=lambda window: (
            int(window["bytes_below"]) + int(window["bytes_above"]),
            json.dumps(window, sort_keys=True, separators=(",", ":")),
        ))
        window = windows[0]

        original_gap = (
            int(suspended_location["original"]) - int(inner_location["original"])
        ) % _WORD_MODULUS
        candidate_gap = (
            int(suspended_location["candidate"]) - int(inner_location["candidate"])
        ) % _WORD_MODULUS
        expected_original_gap = original_amount + int(source_location["original"])
        expected_candidate_gap = candidate_amount + int(source_location["candidate"])
        if (
            original_gap != expected_original_gap
            or candidate_gap != expected_candidate_gap
            or not 4 <= original_gap < 2**31
            or not 4 <= candidate_gap < 2**31
        ):
            call_gap(
                transition,
                "call_frame_gap_mismatch",
                original_gap=original_gap,
                candidate_gap=candidate_gap,
                expected_original_gap=expected_original_gap,
                expected_candidate_gap=expected_candidate_gap,
            )
            continue

        call_descriptors[transition_id] = {
            "transition_id": transition_id,
            "edge_id": edge_id,
            "seed_id": int(seed["id"]),
            "source_state_id": source_state_id,
            "suspended_state_id": suspended_state_id,
            "inner_state_id": inner_state_id,
            "resume_state_id": resume_state_id,
            "source_node_id": source_node_id,
            "source_target_id": int(graph_nodes[source_node_id]["target_id"]),
            "inner_node_id": int(transition["target_node"]),
            "resume_node_id": resume_node_id,
            "call_continuation_target_id": call_continuation,
            "source_shape": affine_shape(source_state_id),
            "suspended_shape": affine_shape(suspended_state_id),
            "inner_shape": affine_shape(inner_state_id),
            "resume_shape": affine_shape(resume_state_id),
            "source_location": source_location,
            "suspended_location": suspended_location,
            "inner_location": inner_location,
            "resume_location": resume_location,
            "stack_amount": stack_amount,
            "source_window": window,
            "original_gap": original_gap,
            "candidate_gap": candidate_gap,
            "return_region_indices": sorted({
                int(summary["return_region_index"])
                for summary in return_summaries
            }),
            "return_summaries": return_summaries,
            "external_summary": external_summary,
            "proof_gap": call_write_gap,
        }

    seed_ids_by_pair: dict[tuple[int, int], list[int]] = defaultdict(list)
    pending_pairs: deque[tuple[int, int]] = deque()
    active_pairs: set[tuple[int, int]] = set()
    for seed in affine_seeds:
        seed_id = _natural(seed.get("id"), "affine seed id")
        state_id = _natural(
            seed.get("target_state_id"), f"affine seed {seed_id} target_state_id"
        )
        if state_id >= len(affine_states) or state_id not in rooted_ids:
            raise StageAInputError("affine seed target is not seed-rooted")
        push = _mapping(
            seed.get("direct_call_push_claim"),
            f"affine seed {seed_id} direct_call_push_claim",
        )
        continuation = _natural(
            push.get("continuation_target_id"),
            f"affine seed {seed_id} continuation_target_id",
        )
        pair = (state_id, continuation)
        seed_ids_by_pair[pair].append(seed_id)
        if pair not in active_pairs:
            active_pairs.add(pair)
            pending_pairs.append(pair)
    while pending_pairs:
        source_state_id, continuation = pending_pairs.popleft()
        for transition in ordinary_transitions_by_source.get(source_state_id, ()):
            target_pair = (int(transition["target_state_id"]), continuation)
            if target_pair not in active_pairs:
                active_pairs.add(target_pair)
                pending_pairs.append(target_pair)
        for transition in call_transitions_by_source.get(source_state_id, ()):
            descriptor = call_descriptors.get(int(transition["id"]))
            if descriptor is None:
                continue
            resume_pair = (int(descriptor["resume_state_id"]), continuation)
            if resume_pair not in active_pairs:
                active_pairs.add(resume_pair)
                pending_pairs.append(resume_pair)

    sorted_active_pairs = sorted(active_pairs)
    minimal_state_id_by_pair = {
        pair: state_id for state_id, pair in enumerate(sorted_active_pairs)
    }
    minimal_active_states: list[dict[str, Any]] = []
    for control_state_id, (affine_state_id, continuation) in enumerate(
        sorted_active_pairs
    ):
        affine_state = affine_states[affine_state_id]
        minimal_active_states.append({
            "id": control_state_id,
            "affine_state_id": affine_state_id,
            "node_id": int(affine_state["node_id"]),
            "continuation_target_id": continuation,
            "active_shape": {
                "locations": {
                    "kind": "affine_family",
                    "artifact_state_id": affine_state_id,
                    "profile_state_index": profile_index_by_artifact_state_id[
                        affine_state_id
                    ],
                },
            },
            "minimum_depth": 1,
            "seed_ids": sorted(seed_ids_by_pair.get(
                (affine_state_id, continuation), []
            )),
        })

    minimal_transition_bindings: list[dict[str, Any]] = []
    minimal_memory_transition_bindings: list[dict[str, Any]] = []
    minimal_transition_binding_gaps: list[dict[str, Any]] = []
    for source_pair in sorted_active_pairs:
        source_state_id, continuation = source_pair
        for transition in ordinary_transitions_by_source.get(source_state_id, ()):
            transition_id = int(transition["id"])
            target_pair = (int(transition["target_state_id"]), continuation)
            source_control_state_id = minimal_state_id_by_pair[source_pair]
            target_control_state_id = minimal_state_id_by_pair[target_pair]
            source_shape = minimal_active_states[source_control_state_id][
                "active_shape"
            ]
            target_shape = minimal_active_states[target_control_state_id][
                "active_shape"
            ]
            gap: dict[str, Any] | None = None
            if behaviors is None:
                gap = {"reason": "decoded_behavior_inventory_missing"}
            else:
                source_node_id = int(transition["source_node"])
                if source_node_id >= len(graph_nodes):
                    raise StageAInputError(
                        "affine transition source node is out of range"
                    )
                region_id = _natural(
                    graph_nodes[source_node_id].get("target_id"),
                    "affine transition source target_id",
                )
                if region_id >= len(behaviors):
                    raise StageAInputError(
                        "affine transition source region is out of range"
                    )
                if region_id in physical_state_only_region_indices:
                    gap = {"reason": "physical_state_only_transition"}
                    behavior = None
                else:
                    behavior = _mapping(
                        behaviors[region_id], "affine transition behavior"
                    )
                if behavior is not None:
                    original_ir = _mapping(
                        behavior.get("original_ir"),
                        "affine transition original_ir",
                    )
                    candidate_ir = _mapping(
                        behavior.get("candidate_ir"),
                        "affine transition candidate_ir",
                    )
                    original_writes = _list(
                        original_ir.get("writes"),
                        "affine transition original writes",
                    )
                    candidate_writes = _list(
                        candidate_ir.get("writes"),
                        "affine transition candidate writes",
                    )
                    if len(original_writes) != len(candidate_writes):
                        gap = {
                            "reason": "memory_write_count_mismatch",
                            "original_write_count": len(original_writes),
                            "candidate_write_count": len(candidate_writes),
                        }
            base = {
                "transition_id": transition_id,
                "edge_id": int(transition["edge_index"]),
                "source_control_state_id": source_control_state_id,
                "target_control_state_id": target_control_state_id,
                "continuation_target_id": continuation,
            }
            if gap is not None:
                minimal_transition_binding_gaps.append({**base, **gap})
                continue
            if original_writes:
                minimal_memory_transition_bindings.append({
                    "id": len(minimal_memory_transition_bindings),
                    **base,
                    "source_shape": _copy(source_shape),
                    "target_shape": _copy(target_shape),
                    "writes": _paired_writes(
                        original_writes,
                        candidate_writes,
                        "minimal affine transition",
                    ),
                    "profile": "ordinary_paired_write_affine_control_v1",
                })
                continue
            minimal_transition_bindings.append({
                "id": len(minimal_transition_bindings),
                **base,
                "source_shape": _copy(source_shape),
                "target_shape": _copy(target_shape),
                "profile": "ordinary_no_write_affine_control_v1",
            })

    minimal_call_transition_bindings: list[dict[str, Any]] = []
    minimal_call_link_shapes: list[dict[str, Any]] = []
    unbound_active_call_contexts: list[dict[str, Any]] = []
    call_gap_by_transition_id = {
        int(gap["transition_id"]): gap for gap in call_transition_binding_gaps
    }
    if len(call_gap_by_transition_id) != len(call_transition_binding_gaps):
        raise StageAInputError(
            "affine call transition gaps must have unique transition ids"
        )
    for source_pair in sorted_active_pairs:
        source_state_id, outer_continuation = source_pair
        for transition in call_transitions_by_source.get(source_state_id, ()):
            descriptor = call_descriptors.get(int(transition["id"]))
            if descriptor is None:
                transition_id = int(transition["id"])
                gap = call_gap_by_transition_id.get(transition_id)
                if gap is None:
                    raise StageAInputError(
                        "unbound affine call transition has no diagnostic gap"
                    )
                unbound_active_call_contexts.append({
                    "id": len(unbound_active_call_contexts),
                    "transition_id": transition_id,
                    "edge_id": int(transition["edge_index"]),
                    "source_control_state_id": minimal_state_id_by_pair[
                        source_pair
                    ],
                    "outer_continuation_target_id": outer_continuation,
                    "reason": str(gap["reason"]),
                })
                continue
            descriptor_gap = descriptor.get("proof_gap")
            if descriptor_gap is not None:
                gap = _mapping(descriptor_gap, "affine call proof gap")
                unbound_active_call_contexts.append({
                    "id": len(unbound_active_call_contexts),
                    "transition_id": int(transition["id"]),
                    "edge_id": int(transition["edge_index"]),
                    "source_control_state_id": minimal_state_id_by_pair[
                        source_pair
                    ],
                    "outer_continuation_target_id": outer_continuation,
                    **_copy(gap),
                })
                continue
            target_pair = (
                int(descriptor["inner_state_id"]),
                int(descriptor["call_continuation_target_id"]),
            )
            resume_pair = (
                int(descriptor["resume_state_id"]),
                outer_continuation,
            )
            # Successful descriptor construction adds the resume pair to the
            # active closure.  The target pair is the affine seed that made the
            # call viable and therefore must already be active as well.
            if target_pair not in minimal_state_id_by_pair:
                raise StageAInputError(
                    "affine call target pair is absent from the active closure"
                )
            if resume_pair not in minimal_state_id_by_pair:
                raise StageAInputError(
                    "affine call resume pair is absent from the active closure"
                )
            source_control_state_id = minimal_state_id_by_pair[source_pair]
            target_control_state_id = minimal_state_id_by_pair[target_pair]
            resume_control_state_id = minimal_state_id_by_pair[resume_pair]
            link_shape = {
                "id": len(minimal_call_link_shapes),
                "call_edge_id": int(descriptor["edge_id"]),
                "call_source_node_id": int(descriptor["source_node_id"]),
                "call_source_target_id": int(descriptor["source_target_id"]),
                "inner_inventory_node_id": int(descriptor["inner_node_id"]),
                "suspended_inventory_node_id": int(descriptor["inner_node_id"]),
                "resume_inventory_node_id": int(descriptor["resume_node_id"]),
                "resume_target_id": int(
                    descriptor["call_continuation_target_id"]
                ),
                "resume_continuation": outer_continuation,
                "inner_shape": _copy(descriptor["inner_shape"]),
                "suspended_shape": _copy(descriptor["suspended_shape"]),
                "resume_shape": _copy(descriptor["resume_shape"]),
                "original_gap": int(descriptor["original_gap"]),
                "candidate_gap": int(descriptor["candidate_gap"]),
            }
            minimal_call_link_shapes.append(link_shape)
            binding_profile = (
                "returning_import_direct_call_singleton_affine_control_v1"
                if descriptor["external_summary"] is not None
                else "nested_direct_call_singleton_affine_control_v1"
            )
            minimal_call_transition_bindings.append({
                "id": len(minimal_call_transition_bindings),
                "transition_id": int(descriptor["transition_id"]),
                "edge_id": int(descriptor["edge_id"]),
                "seed_id": int(descriptor["seed_id"]),
                "source_control_state_id": source_control_state_id,
                "target_control_state_id": target_control_state_id,
                "resume_control_state_id": resume_control_state_id,
                "outer_continuation_target_id": outer_continuation,
                "call_continuation_target_id": int(
                    descriptor["call_continuation_target_id"]
                ),
                "source_shape": _copy(descriptor["source_shape"]),
                "suspended_shape": _copy(descriptor["suspended_shape"]),
                "inner_shape": _copy(descriptor["inner_shape"]),
                "resume_shape": _copy(descriptor["resume_shape"]),
                "source_location": _copy(descriptor["source_location"]),
                "suspended_location": _copy(descriptor["suspended_location"]),
                "inner_location": _copy(descriptor["inner_location"]),
                "resume_location": _copy(descriptor["resume_location"]),
                "source_window": _copy(descriptor["source_window"]),
                "stack_amount": _copy(descriptor["stack_amount"]),
                "link_shape_id": int(link_shape["id"]),
                "return_region_indices": _copy(
                    descriptor["return_region_indices"]
                ),
                "return_summaries": _copy(descriptor["return_summaries"]),
                "external_summary": _copy(descriptor["external_summary"]),
                "profile": binding_profile,
            })

    bound_call_transition_ids = sorted({
        int(binding["transition_id"])
        for binding in minimal_call_transition_bindings
    })
    active_call_transition_ids = sorted({
        int(transition["id"])
        for source_state_id, _ in sorted_active_pairs
        for transition in call_transitions_by_source.get(source_state_id, ())
    })
    unbound_call_transition_ids = sorted(
        set(call_transition_ids) - set(bound_call_transition_ids)
    )
    unbound_call_transition_id_set = set(unbound_call_transition_ids)
    unbound_call_transition_rows = [
        row
        for row in call_transition_rows
        if int(row["transition_id"]) in unbound_call_transition_id_set
    ]

    active_affine_state_ids = sorted({pair[0] for pair in active_pairs})
    dormant_only_affine_state_ids = sorted(
        set(profile_state_ids) - set(active_affine_state_ids)
    )
    control_closure_complete = not (
        unrepresented_state_ids or unbound_transition_ids
    )

    return {
        "format": AFFINE_LINKED_CONTROL_FORMAT,
        "status": (
            "complete_proposal"
            if not gaps and control_closure_complete
            else "incomplete"
        ),
        "shape_projection_status": "complete" if not gaps else "incomplete",
        "control_closure_status": (
            "complete" if control_closure_complete else "incomplete"
        ),
        "minimal_control_closure_status": (
            "complete"
            if (
                not minimal_transition_binding_gaps
                and not unbound_active_call_contexts
            )
            else "incomplete"
        ),
        "acceptance_authority": False,
        "states": states,
        "links": links,
        "transition_bindings": transition_bindings,
        "memory_transition_bindings": memory_transition_bindings,
        "transition_binding_gaps": transition_binding_gaps,
        "minimal_active_states": minimal_active_states,
        "minimal_transition_bindings": minimal_transition_bindings,
        "minimal_memory_transition_bindings": minimal_memory_transition_bindings,
        "minimal_transition_binding_gaps": minimal_transition_binding_gaps,
        "minimal_call_link_shapes": minimal_call_link_shapes,
        "minimal_call_transition_bindings": minimal_call_transition_bindings,
        "call_transition_binding_gaps": call_transition_binding_gaps,
        "gaps": gaps,
        "exact_fallbacks": fallbacks,
        "synthesized_resume_state_ids": synthesized_resume_state_ids,
        "coverage_gaps": {
            "unrepresented_rooted_affine_state_ids": unrepresented_state_ids,
            "unbound_rooted_affine_transition_ids": unbound_transition_ids,
            "unbound_call_transition_ids": unbound_call_transition_ids,
            "unbound_call_transitions": unbound_call_transition_rows,
            "unbound_active_call_contexts": unbound_active_call_contexts,
            "dormant_only_affine_state_ids": dormant_only_affine_state_ids,
        },
        "counts": {
            "states": len(states),
            "links": len(links),
            "gaps": len(gaps),
            "affine_shapes": sum(
                shape["locations"]["kind"] == "affine_family"
                for shape in shapes
            ),
            "exact_fallbacks": len(fallbacks),
            "synthesized_resume_states": len(synthesized_resume_state_ids),
            "rooted_affine_states": len(rooted_ids),
            "profile_affine_states": len(profile_state_ids),
            "represented_rooted_affine_states": len(represented_state_ids),
            "unrepresented_rooted_affine_states": len(unrepresented_state_ids),
            "rooted_affine_transitions": len(rooted_transition_ids),
            "profile_affine_transitions": len(profile_transition_ids),
            "bound_rooted_affine_transitions": len(bound_transition_ids),
            "unbound_rooted_affine_transitions": len(unbound_transition_ids),
            "minimal_active_states": len(minimal_active_states),
            "active_affine_states": len(active_affine_state_ids),
            "dormant_only_affine_states": len(dormant_only_affine_state_ids),
            "minimal_transition_bindings": len(minimal_transition_bindings),
            "minimal_memory_transition_bindings": len(
                minimal_memory_transition_bindings
            ),
            "minimal_transition_binding_gaps": len(
                minimal_transition_binding_gaps
            ),
            "minimal_call_link_shapes": len(minimal_call_link_shapes),
            "minimal_call_transition_bindings": len(
                minimal_call_transition_bindings
            ),
            "call_transition_binding_gaps": len(call_transition_binding_gaps),
            "active_call_transition_variants": len(active_call_transition_ids),
            "dormant_call_transition_variants": (
                len(call_transition_ids) - len(active_call_transition_ids)
            ),
            "active_call_contexts": (
                len(minimal_call_transition_bindings)
                + len(unbound_active_call_contexts)
            ),
            "bound_active_call_contexts": len(
                minimal_call_transition_bindings
            ),
            "unbound_active_call_contexts": len(unbound_active_call_contexts),
            "bound_call_transitions": len(bound_call_transition_ids),
            "unbound_call_transitions": len(unbound_call_transition_ids),
        },
    }


__all__ = ["AFFINE_LINKED_CONTROL_FORMAT", "affine_linked_control_payload"]
