from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any, Mapping

from ..errors import StageAInputError
from .analyses.external import _register_offset_witness
from .analyses.frames import (
    RuntimeFrameAffineFamily,
    RuntimeFrameAffineTransfer,
    RuntimeFrameLocation,
    runtime_frame_affine_family_payload,
    runtime_frame_affine_viability,
    runtime_frame_location_key,
    runtime_frame_location_payload,
)


RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT = (
    "stage-a-runtime-frame-affine-viability-v1"
)
RUNTIME_FRAME_AFFINE_VIABILITY_FILE = (
    "relational-runtime-frame-affine-viability.json"
)

_FRAME_OFFSET_MODULUS = 2**32
_AFFINE_RULE_PROFILES = frozenset({
    "return_slot_affine_transfer_rule_v1",
    "external_return_slot_affine_transfer_rule_v1",
})


def _canonical_key(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _canonical_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical_key(row): row for row in rows}
    return [unique[key] for key in sorted(unique)]


def _valid_index(value: object, bound: int) -> int | None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value >= bound
    ):
        return None
    return value


def _location_from_payload(value: object) -> RuntimeFrameLocation | None:
    if not isinstance(value, Mapping):
        return None
    try:
        location = runtime_frame_location_key(dict(value))
    except (KeyError, TypeError, ValueError):
        return None
    if not (
        0 <= location[1] < _FRAME_OFFSET_MODULUS
        and 0 <= location[3] < _FRAME_OFFSET_MODULUS
    ):
        return None
    return location


def _family_state_key(
    state: tuple[int, RuntimeFrameAffineFamily],
) -> tuple[int, str, int, str, int, int]:
    node_id, family = state
    return (
        node_id,
        family.original_register,
        family.original_base,
        family.candidate_register,
        family.candidate_base,
        family.translation_stride,
    )


def _family_state_payload(
    state: tuple[int, RuntimeFrameAffineFamily],
) -> dict[str, Any]:
    node_id, family = state
    return {
        "node_id": node_id,
        "family": runtime_frame_affine_family_payload(family),
    }


def _seed_key(
    seed: Mapping[str, Any],
) -> tuple[int, int, int, str, int, str, int]:
    location = seed["location"]
    if not isinstance(location, Mapping):
        raise AssertionError("validated affine seed lost its location")
    return (
        int(seed["edge_index"]),
        int(seed["source_node_id"]),
        int(seed["node_id"]),
        str(location["original_register"]),
        int(location["original"]),
        str(location["candidate_register"]),
        int(location["candidate"]),
    )


def _seed_coefficient(
    family: RuntimeFrameAffineFamily,
    location: RuntimeFrameLocation,
) -> int | None:
    if (
        location[0] != family.original_register
        or location[2] != family.candidate_register
    ):
        return None
    translation = (
        int(location[1]) - family.original_base
    ) % _FRAME_OFFSET_MODULUS
    if translation % family.translation_stride != 0:
        return None
    coefficient = translation // family.translation_stride
    if (
        family.original_base
        + coefficient * family.translation_stride
    ) % _FRAME_OFFSET_MODULUS != int(location[1]):
        return None
    if (
        family.candidate_base
        + coefficient * family.translation_stride
    ) % _FRAME_OFFSET_MODULUS != int(location[3]):
        return None
    return coefficient


def _viable_transition_payload(
    transition: tuple[
        tuple[int, RuntimeFrameAffineFamily],
        int,
        RuntimeFrameAffineTransfer,
        tuple[int, RuntimeFrameAffineFamily],
    ],
    rule: Mapping[str, Any],
) -> dict[str, Any]:
    source, edge_index, transfer, target = transition
    source_node, source_family = source
    target_node, target_family = target
    raw_original_base = (
        source_family.original_base + transfer.original_delta
    ) % _FRAME_OFFSET_MODULUS
    raw_candidate_base = (
        source_family.candidate_base + transfer.candidate_delta
    ) % _FRAME_OFFSET_MODULUS
    difference = (
        target_family.original_base - raw_original_base
    ) % _FRAME_OFFSET_MODULUS
    stride = source_family.translation_stride
    if difference % stride != 0:
        raise AssertionError("canonical affine target is outside its raw coset")
    shift_coefficient = difference // stride
    if (
        raw_candidate_base + shift_coefficient * stride
    ) % _FRAME_OFFSET_MODULUS != target_family.candidate_base:
        raise AssertionError("candidate affine target uses a different rebase")
    return {
        "source_node": source_node,
        "source_family": runtime_frame_affine_family_payload(source_family),
        "edge_index": edge_index,
        "rule": dict(rule),
        "transfer": {
            "target_node": transfer.target_node,
            "original_register": transfer.original_register,
            "original_delta": transfer.original_delta,
            "candidate_register": transfer.candidate_register,
            "candidate_delta": transfer.candidate_delta,
        },
        "raw_target_family": {
            "original_register": transfer.original_register,
            "original_base": raw_original_base,
            "candidate_register": transfer.candidate_register,
            "candidate_base": raw_candidate_base,
            "translation_stride": stride,
            "cardinality": _FRAME_OFFSET_MODULUS // stride,
        },
        "canonical_shift_coefficient": shift_coefficient,
        "target_node": target_node,
        "target_family": runtime_frame_affine_family_payload(target_family),
    }


def _family_word_disjoint(
    *, family_base: int, translation_stride: int, write_offset: int
) -> bool:
    for frame_byte in range(4):
        for write_byte in range(4):
            colliding_frame = (
                write_offset + write_byte - frame_byte
            ) % _FRAME_OFFSET_MODULUS
            if (colliding_frame - family_base) % translation_stride == 0:
                return False
    return True


def _universal_write_readiness(
    behavior: object,
    *,
    register: str,
    family_base: int,
    translation_stride: int,
) -> tuple[bool, list[dict[str, Any]]]:
    if not isinstance(behavior, Mapping):
        return False, []
    writes = behavior.get("writes") or []
    if not isinstance(writes, list):
        return False, []
    witnesses: list[dict[str, Any]] = []
    for write_index, write in enumerate(writes):
        if not isinstance(write, Mapping):
            return False, []
        result = _register_offset_witness(write.get("address"), register)
        if result is None:
            return False, []
        witness, write_offset = result
        write_offset = int(write_offset) % _FRAME_OFFSET_MODULUS
        if not _family_word_disjoint(
            family_base=family_base,
            translation_stride=translation_stride,
            write_offset=write_offset,
        ):
            return False, []
        witnesses.append({
            "write_index": write_index,
            "write_offset": write_offset,
            "address_witness": witness,
        })
    return True, witnesses


def runtime_frame_affine_viability_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    relation_contract_sha256: str,
    decoded_behaviors_sha256: str,
    register_relations_sha256: str,
    behaviors: list[dict[str, Any]],
    register_relations: Mapping[str, Any],
    product_graph: Mapping[str, Any] | None = None,
    max_shapes: int = 65536,
    max_families: int = 65536,
) -> dict[str, Any]:
    """Build an exact, proposal-only runtime-frame family certificate.

    Only explicit runtime-frame seeds and translation-equivariant transfer
    rules are admitted. Memory readiness is established for every member of a
    family from decoded affine writes; finite stack windows and concrete-only
    transfer claims are deliberately not widened into universal facts.
    """
    blockers: list[dict[str, Any]] = []
    seed_rows: list[dict[str, Any]] = []
    resume_anchor_rows: list[dict[str, Any]] = []
    required_edge_rows: list[dict[str, Any]] = []
    transfer_rows: list[dict[str, Any]] = []
    seed_states: list[tuple[int, RuntimeFrameLocation]] = []
    resume_anchor_states: list[tuple[int, RuntimeFrameLocation]] = []
    resume_anchor_links: list[tuple[
        int, RuntimeFrameLocation, int, RuntimeFrameLocation
    ]] = []
    required_by_node: dict[int, list[int]] = defaultdict(list)
    transfers_by_edge: dict[int, list[tuple[
        str, str, RuntimeFrameAffineTransfer,
    ]]] = defaultdict(list)
    rules_by_transfer: dict[
        tuple[int, str, str, str, int, str, int],
        list[dict[str, Any]],
    ] = defaultdict(list)
    product_graph_edges: list[object] | None = None

    edges_value = register_relations.get("edges")
    edges = edges_value if isinstance(edges_value, list) else []
    if not isinstance(edges_value, list):
        blockers.append({
            "code": "runtime_frame_affine_edge_inventory_invalid",
            "detail": "register relation edges are not a list",
        })

    for edge_index, edge in enumerate(edges):
        if not isinstance(edge, Mapping):
            blockers.append({
                "code": "runtime_frame_affine_edge_invalid",
                "edge_index": edge_index,
            })
            continue
        source_node = _valid_index(
            edge.get("source_region_index"), len(behaviors)
        )
        target_node = _valid_index(
            edge.get("target_region_index"), len(behaviors)
        )
        if source_node is None or target_node is None:
            blockers.append({
                "code": "runtime_frame_affine_edge_invalid",
                "edge_index": edge_index,
            })
            continue

        seed = edge.get("return_slot_seed")
        if seed is not None:
            direct_call_push = edge.get("direct_call_push_claim")
            if not isinstance(seed, Mapping):
                seed_location = None
                seed_target = None
            else:
                seed_location = _location_from_payload(seed.get("offsets"))
                seed_target = _valid_index(
                    seed.get("target_region_index"), len(behaviors)
                )
            if (
                seed_location is None
                or seed_target != target_node
                or edge.get("kind") != "call"
                or not isinstance(direct_call_push, Mapping)
            ):
                blockers.append({
                    "code": "runtime_frame_affine_seed_invalid",
                    "edge_index": edge_index,
                })
            else:
                seed_states.append((target_node, seed_location))
                seed_rows.append({
                    "edge_index": edge_index,
                    "source_node_id": source_node,
                    "node_id": target_node,
                    "location": runtime_frame_location_payload(seed_location),
                    "direct_call_push_claim": dict(direct_call_push),
                    "profile": str(seed.get("profile", "")),
                })

        summary_claims = edge.get("return_slot_call_summary_claims", [])
        call_push = (
            edge.get("direct_call_push_claim")
            or edge.get("indirect_call_push_claim")
        )
        if not isinstance(summary_claims, list):
            blockers.append({
                "code": "runtime_frame_affine_resume_anchor_inventory_invalid",
                "edge_index": edge_index,
            })
            summary_claims = []
        for claim_index, claim in enumerate(summary_claims):
            continuation = (
                _valid_index(
                    call_push.get("continuation_region_index"), len(behaviors)
                )
                if isinstance(call_push, Mapping)
                else None
            )
            source_location = (
                _location_from_payload(claim.get("source"))
                if isinstance(claim, Mapping)
                else None
            )
            target_location = (
                _location_from_payload(claim.get("target"))
                if isinstance(claim, Mapping)
                else None
            )
            return_region = (
                _valid_index(claim.get("return_region_index"), len(behaviors))
                if isinstance(claim, Mapping)
                else None
            )
            if not (
                isinstance(claim, Mapping)
                and claim.get("profile") == "return_slot_call_summary_v1"
                and edge.get("kind") == "call"
                and not edge.get("infeasible")
                and isinstance(call_push, Mapping)
                and continuation is not None
                and source_location is not None
                and target_location is not None
                and return_region is not None
            ):
                blockers.append({
                    "code": "runtime_frame_affine_resume_anchor_invalid",
                    "edge_index": edge_index,
                    "claim_index": claim_index,
                })
                continue
            resume_anchor_states.append((continuation, target_location))
            resume_anchor_links.append((
                source_node, source_location, continuation, target_location,
            ))
            resume_anchor_rows.append({
                "edge_index": edge_index,
                "claim_index": claim_index,
                "source_node_id": source_node,
                "callee_node_id": target_node,
                "node_id": continuation,
                "return_region_index": return_region,
                "source": runtime_frame_location_payload(source_location),
                "location": runtime_frame_location_payload(target_location),
                "profile": "checked_call_return_summary_resume_anchor_v1",
            })

        external_summary_claims = edge.get(
            "return_slot_external_call_summary_claims", []
        )
        if not isinstance(external_summary_claims, list):
            blockers.append({
                "code": "runtime_frame_affine_external_resume_anchor_inventory_invalid",
                "edge_index": edge_index,
            })
            external_summary_claims = []
        for claim_index, claim in enumerate(external_summary_claims):
            continuation = (
                _valid_index(
                    call_push.get("continuation_region_index"), len(behaviors)
                )
                if isinstance(call_push, Mapping)
                else None
            )
            source_location = (
                _location_from_payload(claim.get("source"))
                if isinstance(claim, Mapping)
                else None
            )
            target_location = (
                _location_from_payload(claim.get("target"))
                if isinstance(claim, Mapping)
                else None
            )
            thunk_region = (
                _valid_index(claim.get("thunk_region_index"), len(behaviors))
                if isinstance(claim, Mapping)
                else None
            )
            claim_continuation = (
                _valid_index(
                    claim.get("continuation_region_index"), len(behaviors)
                )
                if isinstance(claim, Mapping)
                else None
            )
            contract_id = (
                claim.get("machine_contract_id")
                if isinstance(claim, Mapping)
                else None
            )
            edge_contract_id = edge.get("returning_external_thunk_contract_id")
            if not (
                isinstance(claim, Mapping)
                and claim.get("profile")
                    == "external_return_slot_call_summary_v1"
                and edge.get("kind") == "call"
                and not edge.get("infeasible")
                and isinstance(edge.get("direct_call_push_claim"), Mapping)
                and continuation is not None
                and claim_continuation == continuation
                and source_location is not None
                and target_location is not None
                and thunk_region == target_node
                and isinstance(contract_id, int)
                and not isinstance(contract_id, bool)
                and contract_id == edge_contract_id
            ):
                blockers.append({
                    "code": "runtime_frame_affine_external_resume_anchor_invalid",
                    "edge_index": edge_index,
                    "claim_index": claim_index,
                })
                continue
            resume_anchor_states.append((continuation, target_location))
            resume_anchor_links.append((
                source_node, source_location, continuation, target_location,
            ))
            resume_anchor_rows.append({
                "edge_index": edge_index,
                "claim_index": claim_index,
                "source_node_id": source_node,
                "callee_node_id": target_node,
                "node_id": continuation,
                "machine_contract_id": contract_id,
                "source": runtime_frame_location_payload(source_location),
                "location": runtime_frame_location_payload(target_location),
                "profile": "checked_external_call_summary_resume_anchor_v1",
            })

        kind = edge.get("kind")
        if edge.get("infeasible") or kind not in {
            "jump",
            "call",
            "branch_taken",
            "branch_fallthrough",
        }:
            continue
        required_by_node[source_node].append(edge_index)
        external = bool(edge.get("environment_barrier"))
        rule_field = (
            "return_slot_external_transfer_rules"
            if external
            else "return_slot_transfer_rules"
        )
        required_edge_rows.append({
            "edge_index": edge_index,
            "source_node": source_node,
            "target_node": target_node,
            "kind": kind,
            "rule_field": rule_field,
        })
        rules = edge.get(rule_field)
        if not isinstance(rules, list):
            blockers.append({
                "code": "runtime_frame_affine_transfer_inventory_invalid",
                "edge_index": edge_index,
                "rule_field": rule_field,
            })
            continue
        for rule_index, rule in enumerate(rules):
            if not isinstance(rule, Mapping):
                blockers.append({
                    "code": "runtime_frame_affine_transfer_rule_invalid",
                    "edge_index": edge_index,
                    "rule_index": rule_index,
                })
                continue
            profile = rule.get("profile")
            source_original = rule.get("original_source_register")
            source_candidate = rule.get("candidate_source_register")
            target_original = rule.get("original_target_register")
            target_candidate = rule.get("candidate_target_register")
            original_delta = rule.get("original_delta")
            candidate_delta = rule.get("candidate_delta")
            original_output = rule.get("original_output_witness")
            candidate_output = rule.get("candidate_output_witness")
            if not (
                profile in _AFFINE_RULE_PROFILES
                and isinstance(source_original, str)
                and source_original
                and isinstance(source_candidate, str)
                and source_candidate
                and isinstance(target_original, str)
                and target_original
                and isinstance(target_candidate, str)
                and target_candidate
                and isinstance(original_delta, int)
                and not isinstance(original_delta, bool)
                and isinstance(candidate_delta, int)
                and not isinstance(candidate_delta, bool)
                and isinstance(original_output, Mapping)
                and isinstance(candidate_output, Mapping)
            ):
                blockers.append({
                    "code": "runtime_frame_affine_transfer_rule_invalid",
                    "edge_index": edge_index,
                    "rule_index": rule_index,
                })
                continue
            transfer = RuntimeFrameAffineTransfer(
                target_node=target_node,
                original_register=target_original,
                original_delta=(-original_delta) % _FRAME_OFFSET_MODULUS,
                candidate_register=target_candidate,
                candidate_delta=(-candidate_delta) % _FRAME_OFFSET_MODULUS,
            )
            transfers_by_edge[edge_index].append((
                source_original, source_candidate, transfer,
            ))
            rules_by_transfer[(
                edge_index,
                source_original,
                source_candidate,
                target_original,
                transfer.original_delta,
                target_candidate,
                transfer.candidate_delta,
            )].append({
                "original_source_register": source_original,
                "candidate_source_register": source_candidate,
                "original_target_register": target_original,
                "candidate_target_register": target_candidate,
                "original_output_witness": dict(original_output),
                "candidate_output_witness": dict(candidate_output),
                "original_delta": original_delta % _FRAME_OFFSET_MODULUS,
                "candidate_delta": candidate_delta % _FRAME_OFFSET_MODULUS,
            })
            transfer_rows.append({
                "edge_index": edge_index,
                "rule_index": rule_index,
                "profile": profile,
                "source_original_register": source_original,
                "source_candidate_register": source_candidate,
                "target_node": target_node,
                "target_original_register": target_original,
                "target_candidate_register": target_candidate,
                "original_delta": transfer.original_delta,
                "candidate_delta": transfer.candidate_delta,
            })

    if product_graph is not None:
        graph_edges = product_graph.get("edges")
        relation_regions = register_relations.get("regions")
        if not isinstance(graph_edges, list) or not isinstance(
            relation_regions, list
        ):
            blockers.append({
                "code": "runtime_frame_affine_product_graph_invalid",
            })
            graph_edges = []
            relation_regions = []
        product_graph_edges = graph_edges
        required_by_node.clear()
        graph_kinds = {
            "jump",
            "call",
            "branchTaken",
            "branchFallthrough",
        }
        for position, graph_edge_value in enumerate(graph_edges):
            if not isinstance(graph_edge_value, Mapping):
                blockers.append({
                    "code": "runtime_frame_affine_product_edge_invalid",
                    "edge_position": position,
                })
                continue
            graph_edge = graph_edge_value
            edge_id = graph_edge.get("id")
            source_node = _valid_index(
                graph_edge.get("source_node_id"), len(behaviors)
            )
            target_node = _valid_index(
                graph_edge.get("target_node_id"), len(behaviors)
            )
            if (
                not isinstance(edge_id, int)
                or isinstance(edge_id, bool)
                or edge_id < 0
                or edge_id != position
                or source_node is None
                or target_node is None
            ):
                blockers.append({
                    "code": "runtime_frame_affine_product_edge_invalid",
                    "edge_position": position,
                })
                continue
            if graph_edge.get("infeasible") or graph_edge.get("kind") not in graph_kinds:
                continue
            required_by_node[source_node].append(edge_id)
            if transfers_by_edge.get(edge_id):
                continue

            relation_region = (
                relation_regions[source_node]
                if source_node < len(relation_regions)
                else None
            )
            original_behavior = behaviors[source_node].get("original_ir")
            candidate_behavior = behaviors[source_node].get("candidate_ir")
            if not (
                isinstance(relation_region, Mapping)
                and isinstance(original_behavior, Mapping)
                and isinstance(candidate_behavior, Mapping)
                and isinstance(original_behavior.get("registers"), Mapping)
                and isinstance(candidate_behavior.get("registers"), Mapping)
            ):
                continue
            inputs = relation_region.get("inputs")
            outputs = relation_region.get("outputs")
            if not isinstance(inputs, list) or not isinstance(outputs, list):
                continue
            for input_pair in inputs:
                if not isinstance(input_pair, Mapping):
                    continue
                source_original = input_pair.get("original")
                source_candidate = input_pair.get("candidate")
                if not isinstance(source_original, str) or not isinstance(
                    source_candidate, str
                ):
                    continue
                for output_pair in outputs:
                    if not isinstance(output_pair, Mapping):
                        continue
                    target_original = output_pair.get("original")
                    target_candidate = output_pair.get("candidate")
                    if not isinstance(target_original, str) or not isinstance(
                        target_candidate, str
                    ):
                        continue
                    original_result = _register_offset_witness(
                        original_behavior["registers"].get(target_original),
                        source_original,
                    )
                    candidate_result = _register_offset_witness(
                        candidate_behavior["registers"].get(target_candidate),
                        source_candidate,
                    )
                    if original_result is None or candidate_result is None:
                        continue
                    original_witness, original_delta = original_result
                    candidate_witness, candidate_delta = candidate_result
                    transfer = RuntimeFrameAffineTransfer(
                        target_node=target_node,
                        original_register=target_original,
                        original_delta=(-original_delta) % _FRAME_OFFSET_MODULUS,
                        candidate_register=target_candidate,
                        candidate_delta=(-candidate_delta) % _FRAME_OFFSET_MODULUS,
                    )
                    transfers_by_edge[edge_id].append((
                        source_original, source_candidate, transfer,
                    ))
                    rules_by_transfer[(
                        edge_id,
                        source_original,
                        source_candidate,
                        target_original,
                        transfer.original_delta,
                        target_candidate,
                        transfer.candidate_delta,
                    )].append({
                        "original_source_register": source_original,
                        "candidate_source_register": source_candidate,
                        "original_target_register": target_original,
                        "candidate_target_register": target_candidate,
                        "original_output_witness": original_witness,
                        "candidate_output_witness": candidate_witness,
                        "original_delta": original_delta,
                        "candidate_delta": candidate_delta,
                    })

    unique_seeds = tuple(sorted(set(seed_states)))
    unique_analysis_seeds = tuple(sorted(set(
        [*seed_states, *resume_anchor_states]
    )))
    unsupported_transfers: set[tuple[int, str, str, int]] = set()
    memory_facts: dict[
        tuple[int, RuntimeFrameAffineFamily], dict[str, Any]
    ] = {}

    def memory_ready(node_id: int, family: RuntimeFrameAffineFamily) -> bool:
        original_behavior = behaviors[node_id].get("original_ir")
        candidate_behavior = behaviors[node_id].get("candidate_ir")
        original_ready, original_witnesses = _universal_write_readiness(
            original_behavior,
            register=family.original_register,
            family_base=family.original_base,
            translation_stride=family.translation_stride,
        )
        candidate_ready, candidate_witnesses = _universal_write_readiness(
            candidate_behavior,
            register=family.candidate_register,
            family_base=family.candidate_base,
            translation_stride=family.translation_stride,
        )
        ready = original_ready and candidate_ready
        memory_facts[(node_id, family)] = {
            "node_id": node_id,
            "family": runtime_frame_affine_family_payload(family),
            "ready": ready,
            "profile": "universal_decoded_affine_write_separation_v1",
            "original_write_witnesses": original_witnesses,
            "candidate_write_witnesses": candidate_witnesses,
        }
        return ready

    def required_edges(node_id: int) -> tuple[int, ...]:
        return tuple(sorted(set(required_by_node.get(node_id, []))))

    def affine_transfers(
        node_id: int,
        original_register: str,
        candidate_register: str,
        edge_id: int,
    ) -> tuple[RuntimeFrameAffineTransfer, ...]:
        matches = {
            transfer
            for source_original, source_candidate, transfer
            in transfers_by_edge.get(edge_id, [])
            if source_original == original_register
            and source_candidate == candidate_register
        }
        if not matches:
            unsupported_transfers.add((
                node_id, original_register, candidate_register, edge_id,
            ))
        return tuple(sorted(matches, key=lambda transfer: (
            transfer.target_node,
            transfer.original_register,
            transfer.original_delta,
            transfer.candidate_register,
            transfer.candidate_delta,
        )))

    result = None
    if max_shapes <= 0 or max_families <= 0:
        blockers.append({
            "code": "runtime_frame_affine_budget_invalid",
            "max_shapes": max_shapes,
            "max_families": max_families,
        })
    else:
        result = runtime_frame_affine_viability(
            unique_analysis_seeds,
            memory_ready=memory_ready,
            required_edges=required_edges,
            affine_transfers=affine_transfers,
            max_shapes=max_shapes,
            max_families=max_families,
        )

    explored_states = sorted(
        result.explored if result is not None else (),
        key=_family_state_key,
    )
    viable_states = sorted(
        result.viable if result is not None else (),
        key=_family_state_key,
    )
    viable_state_set = set(viable_states)
    state_id_by_state = {
        state: state_id for state_id, state in enumerate(viable_states)
    }
    viable_state_rows = [
        {"id": state_id, **_family_state_payload(state)}
        for state_id, state in enumerate(viable_states)
    ]

    def transition_rule(transition: tuple[
        tuple[int, RuntimeFrameAffineFamily],
        int,
        RuntimeFrameAffineTransfer,
        tuple[int, RuntimeFrameAffineFamily],
    ]) -> dict[str, Any]:
        source, edge_index, transfer, _target = transition
        source_family = source[1]
        matches = rules_by_transfer.get((
            edge_index,
            source_family.original_register,
            source_family.candidate_register,
            transfer.original_register,
            transfer.original_delta,
            transfer.candidate_register,
            transfer.candidate_delta,
        ), [])
        if not matches:
            raise AssertionError("viable affine transition lost its exact rule")
        selected = min(matches, key=_canonical_key)
        canonical = json.loads(_canonical_key(selected))
        if not isinstance(canonical, dict):
            raise AssertionError("canonical affine transition rule is not an object")
        return canonical

    viable_transition_evidence = [
        (transition, transition_rule(transition))
        for transition in (
            result.transitions if result is not None else ()
        )
        if transition[0] in viable_state_set
        and transition[3] in viable_state_set
    ]
    viable_transition_evidence.sort(key=lambda item: (
        _family_state_key(item[0][0]),
        item[0][1],
        _family_state_key(item[0][3]),
        repr(item[1]),
    ))
    viable_transition_rows: list[dict[str, Any]] = []
    for transition_id, (transition, rule) in enumerate(
        viable_transition_evidence
    ):
        source, _edge_index, _transfer, target = transition
        viable_transition_rows.append({
            "id": transition_id,
            "source_state_id": state_id_by_state[source],
            "target_state_id": state_id_by_state[target],
            **_viable_transition_payload(transition, rule),
        })

    unsupported_cycle_shapes = sorted(
        result.unsupported_cycle_shapes if result is not None else ()
    )
    if result is not None and result.budget_exceeded:
        blockers.append({
            "code": (
                "runtime_frame_affine_shape_budget_exceeded"
                if result.budget_kind == "shapes"
                else "runtime_frame_affine_family_budget_exceeded"
            ),
            "budget": (
                max_shapes
                if result.budget_kind == "shapes"
                else max_families
            ),
        })
    blockers.extend({
        "code": "runtime_frame_affine_asymmetric_cycle",
        "node_id": node_id,
        "original_register": original_register,
        "candidate_register": candidate_register,
    } for node_id, original_register, candidate_register
        in unsupported_cycle_shapes)

    unsupported_rows = [
        {
            "node_id": node_id,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "edge_index": edge_index,
        }
        for node_id, original_register, candidate_register, edge_index
        in sorted(unsupported_transfers)
    ]
    blockers.extend({
        "code": "runtime_frame_affine_transfer_unsupported",
        **row,
    } for row in unsupported_rows)

    canonical_seed_by_key: dict[
        tuple[int, int, int, str, int, str, int], dict[str, Any]
    ] = {}
    for row in seed_rows:
        canonical_seed_by_key.setdefault(_seed_key(row), row)
    canonical_seed_rows = [
        canonical_seed_by_key[key] for key in sorted(canonical_seed_by_key)
    ]
    canonical_resume_anchor_rows = _canonical_rows(resume_anchor_rows)

    def seed_matches_call_edge(row: Mapping[str, Any]) -> bool:
        edge_index = int(row["edge_index"])
        if edge_index >= len(edges):
            return False
        edge = edges[edge_index]
        if not isinstance(edge, Mapping):
            return False
        seed = edge.get("return_slot_seed")
        location = _location_from_payload(row.get("location"))
        if not isinstance(seed, Mapping) or location is None:
            return False
        if (
            edge.get("kind") != "call"
            or bool(edge.get("infeasible"))
            or edge.get("source_region_index") != row.get("source_node_id")
            or edge.get("target_region_index") != row.get("node_id")
            or seed.get("target_region_index") != row.get("node_id")
            or _location_from_payload(seed.get("offsets")) != location
            or not isinstance(edge.get("direct_call_push_claim"), Mapping)
        ):
            return False
        if product_graph_edges is None:
            return True
        if edge_index >= len(product_graph_edges):
            return False
        graph_edge = product_graph_edges[edge_index]
        return bool(
            isinstance(graph_edge, Mapping)
            and graph_edge.get("id") == edge_index
            and graph_edge.get("kind") == "call"
            and not graph_edge.get("infeasible")
            and graph_edge.get("source_node_id") == row.get("source_node_id")
            and graph_edge.get("target_node_id") == row.get("node_id")
        )

    viable_seed_rows: list[dict[str, Any]] = []
    fact_seed_rows: list[dict[str, Any]] = []
    for row in canonical_seed_rows:
        location = _location_from_payload(row["location"])
        if location is None:
            raise AssertionError("validated affine seed lost its location")
        if not seed_matches_call_edge(row):
            blockers.append({
                "code": "runtime_frame_affine_seed_binding_missing",
                "edge_index": int(row["edge_index"]),
                "reason": "call_edge",
            })
            fact_seed_rows.append({
                **row,
                "binding_status": "missing_call_edge",
            })
            continue
        candidates = [
            (state_id_by_state[state], coefficient)
            for state in viable_states
            if state[0] == int(row["node_id"])
            and (
                coefficient := _seed_coefficient(state[1], location)
            ) is not None
        ]
        if not candidates:
            blockers.append({
                "code": "runtime_frame_affine_seed_binding_missing",
                "edge_index": int(row["edge_index"]),
                "reason": "target_state",
            })
            fact_seed_rows.append({
                **row,
                "binding_status": "missing_target_state",
            })
            continue
        if len(candidates) != 1:
            candidate_state_ids = [state_id for state_id, _ in candidates]
            blockers.append({
                "code": "runtime_frame_affine_seed_binding_ambiguous",
                "edge_index": int(row["edge_index"]),
                "candidate_target_state_ids": candidate_state_ids,
            })
            fact_seed_rows.append({
                **row,
                "binding_status": "ambiguous",
                "candidate_target_state_ids": candidate_state_ids,
            })
            continue
        target_state_id, coefficient = candidates[0]
        bound_row = {
            **row,
            "id": len(viable_seed_rows),
            "target_state_id": target_state_id,
            "coefficient": coefficient,
        }
        viable_seed_rows.append(bound_row)
        fact_seed_rows.append(bound_row)

    transition_ids_by_required_pair: dict[
        tuple[int, int], list[int]
    ] = defaultdict(list)
    for row in viable_transition_rows:
        transition_ids_by_required_pair[(
            int(row["source_state_id"]), int(row["edge_index"]),
        )].append(int(row["id"]))

    required_transition_bindings: list[dict[str, Any]] = []
    for state in viable_states:
        source_state_id = state_id_by_state[state]
        for edge_index in required_edges(state[0]):
            candidate_transition_ids = sorted(
                transition_ids_by_required_pair.get(
                    (source_state_id, edge_index), []
                )
            )
            binding = {
                "source_state_id": source_state_id,
                "edge_index": edge_index,
                "candidate_transition_ids": candidate_transition_ids,
            }
            if len(candidate_transition_ids) == 1:
                binding.update({
                    "status": "selected",
                    "selected_transition_id": candidate_transition_ids[0],
                })
            elif candidate_transition_ids:
                binding["status"] = "blocked_ambiguity"
                blockers.append({
                    "code": "runtime_frame_affine_transition_binding_ambiguous",
                    **binding,
                })
            else:
                binding["status"] = "missing"
                blockers.append({
                    "code": "runtime_frame_affine_transition_binding_missing",
                    **binding,
                })
            required_transition_bindings.append(binding)

    bindings_by_source_state: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for binding in required_transition_bindings:
        bindings_by_source_state[int(binding["source_state_id"])].append(binding)

    def transition_closure(
        initial_state_ids: set[int],
    ) -> tuple[set[int], set[int]]:
        state_ids: set[int] = set()
        transition_ids: set[int] = set()
        pending_states = deque(sorted(initial_state_ids))
        while pending_states:
            state_id = pending_states.popleft()
            if state_id in state_ids:
                continue
            state_ids.add(state_id)
            for binding in bindings_by_source_state.get(state_id, []):
                for transition_id in binding["candidate_transition_ids"]:
                    transition_ids.add(transition_id)
                    target_state_id = int(
                        viable_transition_rows[transition_id]["target_state_id"]
                    )
                    if target_state_id not in state_ids:
                        pending_states.append(target_state_id)
        return state_ids, transition_ids

    rooted_state_ids, rooted_transition_ids = transition_closure({
        int(seed["target_state_id"]) for seed in viable_seed_rows
    })
    affine_profile_state_ids = set(rooted_state_ids)
    affine_profile_transition_ids = set(rooted_transition_ids)
    resume_anchor_state_ids: set[int] = set()
    while True:
        enabled_targets = {
            state_id_by_state[target_state]
            for source_node, source_location, target_node, target_location
            in resume_anchor_links
            if any(
                viable_states[source_state_id][0] == source_node
                and viable_states[source_state_id][1].contains(source_location)
                for source_state_id in affine_profile_state_ids
            )
            for target_state in viable_states
            if target_state[0] == target_node
            and _seed_coefficient(target_state[1], target_location) is not None
        }
        newly_enabled = enabled_targets - resume_anchor_state_ids
        if not newly_enabled:
            break
        resume_anchor_state_ids.update(newly_enabled)
        new_states, new_transitions = transition_closure(newly_enabled)
        affine_profile_state_ids.update(new_states)
        affine_profile_transition_ids.update(new_transitions)
    resume_anchored_state_ids = affine_profile_state_ids - rooted_state_ids
    resume_anchored_transition_ids = (
        affine_profile_transition_ids - rooted_transition_ids
    )

    seed_rooted_state_ids = sorted(rooted_state_ids)
    seed_rooted_transition_ids = sorted(rooted_transition_ids)
    for row in viable_state_rows:
        row["seed_rooted"] = int(row["id"]) in rooted_state_ids
    for row in viable_transition_rows:
        row["seed_rooted"] = int(row["id"]) in rooted_transition_ids

    proposal_rows: list[dict[str, Any]] = []
    uncovered_seeds: list[tuple[int, RuntimeFrameLocation]] = []
    for node_id, location in unique_seeds:
        families = [
            runtime_frame_affine_family_payload(family)
            for viable_node, family in viable_states
            if viable_node == node_id and family.contains(location)
        ]
        if not families:
            uncovered_seeds.append((node_id, location))
        proposal_rows.append({
            "node_id": node_id,
            "seed": runtime_frame_location_payload(location),
            "viable_families": families,
        })
    blockers.extend({
        "code": "runtime_frame_affine_seed_not_viable",
        "node_id": node_id,
        "seed": runtime_frame_location_payload(location),
    } for node_id, location in uncovered_seeds)
    if uncovered_seeds:
        blockers.extend({
            "code": "runtime_frame_affine_memory_not_universal",
            "node_id": int(row["node_id"]),
            "family": row["family"],
        } for row in memory_facts.values() if not row["ready"])

    canonical_blockers = _canonical_rows(blockers)
    complete = not canonical_blockers
    return {
        "format": RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT,
        "status": (
            "proposal_requires_generated_lean_replay"
            if complete
            else "incomplete"
        ),
        "acceptance_authority": False,
        "semantics": "exact_modular_common_translation_cosets_v1",
        "source": {
            "original_sha256": original_sha256,
            "candidate_sha256": candidate_sha256,
            "relation_contract_sha256": relation_contract_sha256,
            "decoded_behaviors_sha256": decoded_behaviors_sha256,
            "register_relations_sha256": register_relations_sha256,
        },
        "budgets": {
            "max_shapes": max_shapes,
            "max_families": max_families,
        },
        "complete": complete,
        "blockers": canonical_blockers,
        "facts": {
            "seeds": fact_seed_rows,
            "resume_anchors": canonical_resume_anchor_rows,
            "required_edges": _canonical_rows(required_edge_rows),
            "affine_transfers": _canonical_rows(transfer_rows),
            "unsupported_transfers": unsupported_rows,
        },
        "certificate": {
            "finite_window_widening": False,
            "memory_basis": "decoded_affine_writes_only",
            "budget_exceeded": bool(
                result is not None and result.budget_exceeded
            ),
            "budget_kind": result.budget_kind if result is not None else None,
            "unsupported_cycle_shapes": [
                {
                    "node_id": node_id,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                }
                for node_id, original_register, candidate_register
                in unsupported_cycle_shapes
            ],
            "explored_families": [
                _family_state_payload(state) for state in explored_states
            ],
            "viable_families": viable_state_rows,
            "viable_seeds": viable_seed_rows,
            "viable_transitions": viable_transition_rows,
            "required_transition_bindings": required_transition_bindings,
            "seed_rooted_state_ids": seed_rooted_state_ids,
            "seed_rooted_transition_ids": seed_rooted_transition_ids,
            "orphan_state_ids": [
                int(row["id"])
                for row in viable_state_rows
                if not row["seed_rooted"]
            ],
            "orphan_transition_ids": [
                int(row["id"])
                for row in viable_transition_rows
                if not row["seed_rooted"]
            ],
            "resume_anchor_state_ids": sorted(resume_anchor_state_ids),
            "resume_anchored_state_ids": sorted(resume_anchored_state_ids),
            "resume_anchored_transition_ids": sorted(
                resume_anchored_transition_ids
            ),
            "affine_profile_state_ids": sorted(affine_profile_state_ids),
            "affine_profile_transition_ids": sorted(
                affine_profile_transition_ids
            ),
            "memory_readiness": sorted(
                memory_facts.values(),
                key=_canonical_key,
            ),
        },
        "proposals": proposal_rows,
    }


def validate_runtime_frame_affine_viability_payload(
    payload: object,
    *,
    original_sha256: str,
    candidate_sha256: str,
    relation_contract_sha256: str,
    decoded_behaviors_sha256: str,
    register_relations_sha256: str,
    behaviors: list[dict[str, Any]],
    register_relations: Mapping[str, Any],
    product_graph: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise StageAInputError("runtime frame affine artifact must be an object")
    budgets = payload.get("budgets")
    if not isinstance(budgets, Mapping) or set(budgets) != {
        "max_shapes", "max_families",
    }:
        raise StageAInputError("runtime frame affine budgets are malformed")
    max_shapes = budgets.get("max_shapes")
    max_families = budgets.get("max_families")
    if not (
        isinstance(max_shapes, int)
        and not isinstance(max_shapes, bool)
        and isinstance(max_families, int)
        and not isinstance(max_families, bool)
    ):
        raise StageAInputError("runtime frame affine budgets are malformed")
    expected = runtime_frame_affine_viability_payload(
        original_sha256=original_sha256,
        candidate_sha256=candidate_sha256,
        relation_contract_sha256=relation_contract_sha256,
        decoded_behaviors_sha256=decoded_behaviors_sha256,
        register_relations_sha256=register_relations_sha256,
        behaviors=behaviors,
        register_relations=register_relations,
        product_graph=product_graph,
        max_shapes=max_shapes,
        max_families=max_families,
    )
    observed = dict(payload)
    if observed != expected:
        raise StageAInputError(
            "runtime frame affine artifact differs from its bound source facts"
        )
    return expected


__all__ = [
    "RUNTIME_FRAME_AFFINE_VIABILITY_FILE",
    "RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT",
    "runtime_frame_affine_viability_payload",
    "validate_runtime_frame_affine_viability_payload",
]
