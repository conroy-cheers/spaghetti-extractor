from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from ...stage_binary import StageAInputError


def _canonical_key(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class ConcreteControlState:
    node_id: int
    calls: tuple[int, ...]
    frame_offsets: tuple[Mapping[str, Any], ...]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ConcreteControlState":
        node_id = payload.get("node_id")
        calls = payload.get("calls")
        frame_offsets = payload.get("frame_offsets")
        if not isinstance(node_id, int) or node_id < 0:
            raise StageAInputError("control state node_id must be non-negative")
        if (
            not isinstance(calls, list)
            or any(not isinstance(item, int) or item < 0 for item in calls)
        ):
            raise StageAInputError("control state calls must be non-negative integers")
        if (
            not isinstance(frame_offsets, list)
            or any(not isinstance(item, Mapping) for item in frame_offsets)
        ):
            raise StageAInputError("control state frame_offsets must be objects")
        if len(calls) != len(frame_offsets):
            raise StageAInputError(
                "control state calls and frame_offsets must have equal lengths"
            )
        return cls(
            node_id=node_id,
            calls=tuple(calls),
            frame_offsets=tuple(frame_offsets),
        )

    def linked_payload(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "continuation_target_id": self.calls[0] if self.calls else None,
            "active_frame": (
                dict(self.frame_offsets[0]) if self.frame_offsets else None
            ),
        }


def linked_control_state_key(payload: Mapping[str, Any]) -> str:
    """Return the finite linked-state key for a concrete call-stack state.

    Dormant stack tails are deliberately excluded.  Their validity is carried
    by `RelationalLinkedRuntimeCallStackHolds`; generated transition theorems
    quantify over the tail instead of enumerating recursive depths.
    """

    return _canonical_key(ConcreteControlState.parse(payload).linked_payload())


def linked_control_expansion_key(payload: Mapping[str, Any]) -> str:
    """Key one abstract transition context, including its immediate caller.

    A local transition is parametric over deeper dormant frames, but nested
    return/link synthesis needs the adjacent caller frame once.  Retaining that
    frame reaches a fixed point for recursion without enumerating the rest of
    the concrete stack.
    """

    state = ConcreteControlState.parse(payload)
    return _canonical_key({
        **state.linked_payload(),
        "caller_continuation_target_id": (
            state.calls[1] if len(state.calls) > 1 else None
        ),
        "caller_frame": (
            dict(state.frame_offsets[1]) if len(state.frame_offsets) > 1 else None
        ),
    })


def project_linked_control_profile(
    control_states: list[dict[str, Any]],
    *,
    behaviors: list[dict[str, Any]] | None = None,
    nodes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Collapse concrete call stacks to the finite active-frame abstraction.

    This is untrusted proposal generation. Lean subsequently checks profile
    membership and every push, transfer, and pop theorem for arbitrary tails.
    """

    concrete = [ConcreteControlState.parse(raw) for raw in control_states]
    projected: dict[str, dict[str, Any]] = {}
    for state in concrete:
        payload = state.linked_payload()
        key = _canonical_key(payload)
        row = projected.setdefault(key, {
            **payload,
            "representative_depths": [],
            "concrete_state_count": 0,
        })
        depth = len(state.calls)
        if depth not in row["representative_depths"]:
            row["representative_depths"].append(depth)
        row["concrete_state_count"] += 1

    states = sorted(
        projected.values(),
        key=lambda row: (
            int(row["node_id"]),
            -1 if row["continuation_target_id"] is None
            else int(row["continuation_target_id"]),
            _canonical_key(row["active_frame"] or {}),
        ),
    )
    for row in states:
        row["representative_depths"].sort()
        row["minimum_depth"] = min(row["representative_depths"])
    for state_id, row in enumerate(states):
        row["id"] = state_id

    state_id_by_key = {
        _canonical_key({
            "node_id": row["node_id"],
            "continuation_target_id": row["continuation_target_id"],
            "active_frame": row["active_frame"],
        }): int(row["id"])
        for row in states
    }

    links: list[dict[str, Any]] = []
    link_gaps: list[dict[str, Any]] = []
    if (behaviors is None) != (nodes is None):
        raise StageAInputError("linked control needs behaviors and nodes together")
    if behaviors is not None and nodes is not None:
        if len(behaviors) != len(nodes):
            raise StageAInputError("linked control behaviors and nodes differ in length")
        node_by_target = {
            int(node["target_id"]): node_id
            for node_id, node in enumerate(nodes)
        }
        concrete_by_node_calls: dict[
            tuple[int, tuple[int, ...]], list[ConcreteControlState]
        ] = {}
        for state in concrete:
            concrete_by_node_calls.setdefault(
                (state.node_id, state.calls), []
            ).append(state)

        def inferred_gap(
            inner: Mapping[str, Any], outer: Mapping[str, Any]
        ) -> tuple[int, int] | None:
            candidates: set[tuple[int, int]] = set()
            for inner_location in inner.get("locations", []):
                for outer_location in outer.get("locations", []):
                    if (
                        inner_location.get("original_register")
                            != outer_location.get("original_register")
                        or inner_location.get("candidate_register")
                            != outer_location.get("candidate_register")
                    ):
                        continue
                    original_gap = (
                        int(outer_location["original"])
                        - int(inner_location["original"])
                    ) % 2**32
                    candidate_gap = (
                        int(outer_location["candidate"])
                        - int(inner_location["candidate"])
                    ) % 2**32
                    if (
                        4 <= original_gap < 2**31
                        and 4 <= candidate_gap < 2**31
                    ):
                        candidates.add((original_gap, candidate_gap))
            return next(iter(candidates)) if len(candidates) == 1 else None

        link_keys: set[str] = set()
        for source in concrete:
            original = behaviors[source.node_id].get("original_ir") or {}
            candidate = behaviors[source.node_id].get("candidate_ir") or {}
            original_outcome = original.get("outcome") or {}
            candidate_outcome = candidate.get("outcome") or {}
            if original_outcome.get("op") not in {"call", "indirect_call"}:
                continue
            if (
                original_outcome.get("op") != candidate_outcome.get("op")
                or original_outcome.get("continuation")
                    != candidate_outcome.get("continuation")
            ):
                continue
            target = original_outcome.get("target")
            if not isinstance(target, int) or target != candidate_outcome.get("target"):
                continue
            continuation = int(original_outcome["continuation"])
            target_node_id = node_by_target.get(target)
            resume_node_id = node_by_target.get(continuation)
            if target_node_id is None or resume_node_id is None:
                continue
            successor_calls = (continuation, *source.calls)
            successors = concrete_by_node_calls.get(
                (target_node_id, successor_calls), []
            )
            if not source.calls:
                continue
            resumes = concrete_by_node_calls.get(
                (resume_node_id, source.calls), []
            )
            resume_inventories = {
                _canonical_key(state.frame_offsets[0]): state.frame_offsets[0]
                for state in resumes if state.frame_offsets
            }
            for successor in successors:
                if len(successor.frame_offsets) < 2:
                    continue
                gap = inferred_gap(
                    successor.frame_offsets[0], successor.frame_offsets[1]
                )
                if gap is None:
                    link_gaps.append({
                        "source_node_id": source.node_id,
                        "target_node_id": target_node_id,
                        "continuation_target_id": continuation,
                        "reason": "caller_frame_gap_ambiguous",
                    })
                    continue
                if len(resume_inventories) != 1:
                    link_gaps.append({
                        "source_node_id": source.node_id,
                        "target_node_id": target_node_id,
                        "continuation_target_id": continuation,
                        "reason": "resume_inventory_ambiguous",
                        "candidate_count": len(resume_inventories),
                    })
                    continue
                resume_inventory = next(iter(resume_inventories.values()))
                source_state_id = state_id_by_key[
                    _canonical_key(source.linked_payload())
                ]
                target_state_id = state_id_by_key[
                    _canonical_key(successor.linked_payload())
                ]
                resume_payload = {
                    "node_id": resume_node_id,
                    "continuation_target_id": source.calls[0],
                    "active_frame": dict(resume_inventory),
                }
                resume_state_id = state_id_by_key.get(_canonical_key(resume_payload))
                if resume_state_id is None:
                    continue
                link = {
                    "call_source_target_id": int(nodes[source.node_id]["target_id"]),
                    "source_state_id": source_state_id,
                    "target_state_id": target_state_id,
                    "resume_state_id": resume_state_id,
                    "resume_node_id": resume_node_id,
                    "resume_target_id": continuation,
                    "resume_continuation": source.calls[0],
                    "inner_inventory": dict(successor.frame_offsets[0]),
                    "suspended_inventory": dict(successor.frame_offsets[1]),
                    "resume_inventory": dict(resume_inventory),
                    "original_gap": gap[0],
                    "candidate_gap": gap[1],
                    "requires_no_wrap_witness": True,
                }
                key = _canonical_key(link)
                if key not in link_keys:
                    link_keys.add(key)
                    links.append(link)
        links.sort(key=lambda row: (
            row["source_state_id"], row["target_state_id"],
            row["resume_state_id"], _canonical_key(row),
        ))
        link_gaps.sort(key=_canonical_key)

    return {
        "format": "stage-a-linked-control-proposal-v1",
        "status": "profile_ready",
        "profile": "active-frame-and-head-continuation-v1",
        "authority": "untrusted_proposal",
        "states": states,
        "links": links,
        "link_gaps": link_gaps,
        "counts": {
            "concrete_states": len(control_states),
            "linked_states": len(states),
            "collapsed_states": len(control_states) - len(states),
            "multi_depth_states": sum(
                len(row["representative_depths"]) > 1 for row in states
            ),
            "link_candidates": len(links),
            "link_gaps": len(link_gaps),
        },
    }
