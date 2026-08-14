"""Deterministic, non-authoritative semantic-component discovery.

This module proposes overlapping component boundaries from the byte-free
machine IR consumed by Stage B.  Proposals are navigation aids only: they do
not validate a logical interface, authorize a replacement, or execute the
original binary.  Unknown control flow is retained as a localized blocker.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .discovery_checker import (
    _callee_closure,
    _complete_indirect_certificate,
    _epilogue_closure,
    _external_branch_closure,
    _finite_dispatch_closure,
    _internal_call_return,
    _looks_like_epilogue,
    _object_closure,
    _outcome_targets,
    _single_entry_closure,
    _straight_closure,
    _strong_components,
)
from .discovery_model import (
    COMPONENT_PROPOSAL_SET_FORMAT,
    MACHINE_IR_FORMAT,
    PROPOSAL_SET_FORMAT,
    RECONSTRUCTION_PLAN_FORMAT,
    ComponentDiscoveryError,
    _ALTERNATIVE_SAMPLE_LIMIT,
    _Candidate,
    _Edge,
    _Graph,
    _Inputs,
    _canonical_sha256,
    _issue,
    _mapping,
    _ordered_unit_ids,
    _unique_dicts,
    _unit_key,
    _unit_span,
)
from .discovery_render import (
    _boundary_payload,
    _coverage_payload,
    _graph_payload,
    _interface_hints,
    _proposal_payload,
)
from .discovery_schema import _load_inputs


def discover_component_proposals(
    *,
    machine_ir: Path | str,
    reconstruction_plan: Path | str,
    max_units: int = 512,
    max_candidates_per_seed: int = 12,
) -> dict[str, Any]:
    """Build deterministic, overlapping component proposals.

    ``machine_ir`` may name a machine-IR package directory or its manifest.
    The result never confers proof authority.  It remains ``incomplete`` when
    any proposed boundary contains unresolved control.
    """

    if max_units < 1:
        raise ComponentDiscoveryError("max_units must be positive")
    if not 1 <= max_candidates_per_seed <= 12:
        raise ComponentDiscoveryError(
            "max_candidates_per_seed must be between 1 and 12"
        )

    inputs = _load_inputs(Path(machine_ir), Path(reconstruction_plan))
    graph = _build_graph(inputs)
    by_seed: dict[str, list[_Candidate]] = {}
    generation_issues: list[dict[str, Any]] = []
    analysis_cache: dict[tuple[frozenset[str], tuple[str, ...]], dict[str, Any]] = {}

    def analyze(candidate: _Candidate) -> dict[str, Any]:
        key = (
            candidate.members,
            tuple(sorted(str(item.get("id", "")) for item in candidate.extra_blockers)),
        )
        cached = analysis_cache.get(key)
        if cached is None:
            boundary = _boundary_payload(inputs, graph, candidate.members)
            hints = _interface_hints(inputs, graph, candidate.members, boundary=boundary)
            blockers = _candidate_blockers(inputs, graph, candidate)
            cached = {
                "boundary": boundary,
                "hints": hints,
                "blockers": blockers,
                "score": _score_candidate(
                    inputs,
                    graph,
                    candidate,
                    boundary=boundary,
                    hints=hints,
                    blockers=blockers,
                ),
            }
            analysis_cache[key] = cached
        return cached

    for unit_id in _ordered_unit_ids(inputs):
        seed_id = "unit:" + unit_id
        raw = _generate_for_seed(
            inputs,
            graph,
            seed_id=seed_id,
            unit_id=unit_id,
            max_units=max_units,
            issues=generation_issues,
        )
        deduplicated = _deduplicate_candidates(raw)
        scored = [
            (analyze(candidate)["score"], candidate)
            for candidate in deduplicated
        ]
        fronts = _pareto_fronts([score for score, _candidate in scored])
        ordered_all = sorted(
            zip(scored, fronts),
            key=lambda item: _candidate_order_key(
                item[1], item[0][0], item[0][1], inputs
            ),
        )
        ordered = ordered_all[:max_candidates_per_seed]
        singleton = next(
            (
                item
                for item in ordered_all
                if item[0][1].members == frozenset({unit_id})
            ),
            None,
        )
        if singleton is not None and singleton not in ordered:
            ordered[-1] = singleton
            ordered.sort(
                key=lambda item: _candidate_order_key(
                    item[1], item[0][0], item[0][1], inputs
                )
            )
        selected: list[_Candidate] = []
        for rank, ((score, candidate), front) in enumerate(ordered):
            candidate.history.append(
                {
                    "operation": "pareto_selection",
                    "seed_id": seed_id,
                    "front": front,
                    "rank": rank,
                    "candidate_count_before_limit": len(scored),
                    "limit": max_candidates_per_seed,
                }
            )
            selected.append(candidate)
        by_seed[seed_id] = selected

    global_candidates = _merge_selected_candidates(by_seed)
    proposal_cores: dict[str, dict[str, Any]] = {}
    membership_to_id: dict[frozenset[str], str] = {}
    for candidate in global_candidates:
        proposal = _proposal_payload(
            inputs, graph, candidate, by_seed, analysis=analyze(candidate)
        )
        proposal_id = str(proposal["id"])
        proposal_cores[proposal_id] = proposal
        membership_to_id[candidate.members] = proposal_id

    seed_proposal_ids = {
        seed_id: [membership_to_id[item.members] for item in candidates]
        for seed_id, candidates in sorted(by_seed.items())
    }
    _attach_component_call_alternatives(
        proposals=proposal_cores,
        seed_proposal_ids=seed_proposal_ids,
    )
    for proposal_id, proposal in proposal_cores.items():
        members = frozenset(proposal["membership"]["unit_ids"])
        strict_supersets = [
            other
            for other in membership_to_id
            if members < other
        ]
        if strict_supersets:
            minimum_size = min(len(other) for other in strict_supersets)
            parents = [
                membership_to_id[other]
                for other in strict_supersets
                if len(other) == minimum_size
            ]
        else:
            parents = []
        alternatives = {
            candidate_id
            for seed_id in proposal["seeds"]
            for candidate_id in seed_proposal_ids[seed_id]
            if candidate_id != proposal_id
        }
        proposal["parent_ids"] = sorted(parents)
        ordered_alternatives = sorted(alternatives)
        proposal["alternative_ids"] = ordered_alternatives[
            :_ALTERNATIVE_SAMPLE_LIMIT
        ]
        proposal["alternative_count"] = len(ordered_alternatives)
        proposal["alternatives_truncated"] = (
            len(ordered_alternatives) > _ALTERNATIVE_SAMPLE_LIMIT
        )
        proposal["proposal_sha256"] = _canonical_sha256(proposal)

    proposals = sorted(
        proposal_cores.values(),
        key=lambda item: (
            int(item["score"]["front"]),
            int(item["score"]["rank"]),
            int(item["membership"]["rva_start"]),
            len(item["membership"]["unit_ids"]),
            str(item["id"]),
        ),
    )
    coverage = _coverage_payload(inputs, proposals)
    blockers = [
        copy.deepcopy(blocker)
        for proposal in proposals
        for blocker in proposal["blockers"]
    ]
    issues = sorted(
        _unique_dicts(generation_issues + blockers),
        key=lambda item: (
            int(item.get("source_location", {}).get("rva_start", -1)),
            str(item.get("category", "")),
            str(item.get("id", "")),
        ),
    )

    core = {
        "format": PROPOSAL_SET_FORMAT,
        "status": "incomplete" if blockers else "proposed",
        "authority": {
            "class": "untrusted_component_discovery_proposals",
            "can_authorize_replacement": False,
            "requires_operator_selection": True,
            "requires_interface_refinement": True,
        },
        "executes_original_binary": False,
        "bindings": {
            "machine_ir_format": inputs.manifest["format"],
            "machine_ir_sha256": inputs.ir_sha256,
            "machine_ir_manifest_sha256": inputs.manifest_sha256,
            "reconstruction_plan_sha256": inputs.plan["plan_sha256"],
            "reconstruction_plan_file_sha256": inputs.plan_file_sha256,
            "original_binary_sha256": inputs.manifest.get("binary", {}).get(
                "sha256"
            ),
        },
        "limits": {
            "max_units_per_candidate": max_units,
            "max_candidates_per_seed": max_candidates_per_seed,
            "path_search_depth": 64,
        },
        "graph_facts": _graph_payload(inputs, graph),
        "seed_index": [
            {"seed_id": seed_id, "proposal_ids": proposal_ids}
            for seed_id, proposal_ids in seed_proposal_ids.items()
        ],
        "proposals": proposals,
        "coverage": coverage,
        "issues": issues,
    }
    return {**core, "proposal_set_sha256": _canonical_sha256(core)}


def _attach_component_call_alternatives(
    *,
    proposals: Mapping[str, dict[str, Any]],
    seed_proposal_ids: Mapping[str, Sequence[str]],
) -> None:
    """Attach exact, non-authoritative callee choices to call blockers."""

    for proposal in proposals.values():
        grouped: dict[tuple[int, str], list[Mapping[str, Any]]] = defaultdict(list)
        for raw_blocker in proposal.get("blockers", []):
            if (
                not isinstance(raw_blocker, Mapping)
                or raw_blocker.get("category")
                != "unclosed_internal_call_dependency"
            ):
                continue
            observed = raw_blocker.get("observed")
            if not isinstance(observed, Mapping):
                continue
            target_rva = observed.get("target_rva")
            target_unit_id = observed.get("target_unit_id")
            if not isinstance(target_rva, int) or not isinstance(
                target_unit_id, str
            ):
                continue
            grouped[(target_rva, target_unit_id)].append(raw_blocker)

        dependencies: list[dict[str, Any]] = []
        for (target_rva, target_unit_id), blockers in sorted(grouped.items()):
            callsite_unit_ids = []
            for blocker in blockers:
                location = blocker.get("source_location")
                if isinstance(location, Mapping) and isinstance(
                    location.get("unit_id"), str
                ):
                    callsite_unit_ids.append(str(location["unit_id"]))
            alternatives: list[dict[str, Any]] = []
            for candidate_id in seed_proposal_ids.get(
                "unit:" + target_unit_id, ()
            ):
                candidate = proposals[candidate_id]
                membership = candidate.get("membership", {})
                if (
                    not isinstance(membership, Mapping)
                    or membership.get("rva_start") != target_rva
                    or target_unit_id not in membership.get("unit_ids", [])
                ):
                    continue
                blocker_categories = sorted(
                    {
                        str(item.get("category"))
                        for item in candidate.get("blockers", [])
                        if isinstance(item, Mapping)
                    }
                )
                if not blocker_categories:
                    readiness = "ready"
                elif blocker_categories == ["unclosed_internal_call_dependency"]:
                    readiness = "requires_component_calls"
                else:
                    readiness = "blocked"
                alternatives.append(
                    {
                        "proposal_id": candidate_id,
                        "readiness": readiness,
                        "unit_count": membership.get("unit_count"),
                        "blocker_categories": blocker_categories,
                    }
                )
            readiness_rank = {
                "ready": 0,
                "requires_component_calls": 1,
                "blocked": 2,
            }
            alternatives.sort(
                key=lambda item: (
                    readiness_rank[str(item["readiness"])],
                    int(item.get("unit_count") or 0),
                    str(item["proposal_id"]),
                )
            )
            dependencies.append(
                {
                    "target_rva": target_rva,
                    "target_unit_id": target_unit_id,
                    "gap_ids": sorted(str(item.get("id")) for item in blockers),
                    "callsite_unit_ids": sorted(set(callsite_unit_ids)),
                    "resolution": (
                        "selection_required" if alternatives else "unavailable"
                    ),
                    "recommended_proposal_id": (
                        alternatives[0]["proposal_id"] if alternatives else None
                    ),
                    "alternatives": alternatives,
                }
            )
        proposal["component_call_dependencies"] = dependencies


def write_component_proposals(
    *,
    machine_ir: Path | str,
    reconstruction_plan: Path | str,
    out: Path | str,
    max_units: int = 512,
    max_candidates_per_seed: int = 12,
) -> dict[str, Any]:
    """Discover proposals and write their canonical JSON artifact."""

    payload = discover_component_proposals(
        machine_ir=machine_ir,
        reconstruction_plan=reconstruction_plan,
        max_units=max_units,
        max_candidates_per_seed=max_candidates_per_seed,
    )
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return payload


def _build_graph(inputs: _Inputs) -> _Graph:
    edges: list[_Edge] = []
    indirect: dict[str, dict[str, Any]] = {}
    certificates = _mapping(inputs.manifest.get("control", {}), "control inventory").get(
        "recovered_indirect_targets", []
    )
    if not isinstance(certificates, list):
        raise ComponentDiscoveryError("indirect target inventory must be an array")
    for raw in certificates:
        item = _mapping(raw, "indirect target certificate")
        source = item.get("source_unit_id")
        if not isinstance(source, str) or source not in inputs.by_id:
            raise ComponentDiscoveryError("indirect certificate has unknown source unit")
        if source in indirect:
            raise ComponentDiscoveryError(
                f"multiple indirect certificates describe unit {source!r}"
            )
        target_ids = item.get("target_unit_ids", [])
        if not isinstance(target_ids, list) or not all(
            isinstance(target, str) for target in target_ids
        ):
            raise ComponentDiscoveryError("indirect target IDs are malformed")
        unknown = sorted(set(target_ids) - set(inputs.by_id))
        if unknown:
            raise ComponentDiscoveryError(
                f"indirect certificate references unknown targets: {unknown}"
            )
        indirect[source] = copy.deepcopy(dict(item))

    for unit in inputs.units:
        source = str(unit["id"])
        semantics = _mapping(unit.get("semantics"), f"unit {source} semantics")
        outcome = semantics.get("outcome")
        if isinstance(outcome, Mapping):
            for kind, target_rva in _outcome_targets(outcome):
                edges.append(
                    _Edge(kind, source, inputs.by_rva.get(target_rva), target_rva)
                )
        events = semantics.get("external_events", [])
        if not isinstance(events, list):
            raise ComponentDiscoveryError(f"unit {source!r} external events are malformed")
        for index, raw_event in enumerate(events):
            event = _mapping(raw_event, f"unit {source} event {index}")
            if event.get("kind") != "internal_call":
                continue
            target_rva = event.get("target_rva")
            if not isinstance(target_rva, int):
                edges.append(_Edge("internal_call", source, None, None, index))
                continue
            edges.append(
                _Edge(
                    "internal_call",
                    source,
                    inputs.by_rva.get(target_rva),
                    target_rva,
                    index,
                )
            )
        outcome_kind = outcome.get("kind") if isinstance(outcome, Mapping) else None
        if isinstance(outcome_kind, str) and outcome_kind.startswith("indirect"):
            certificate = indirect.get(source)
            if _complete_indirect_certificate(certificate):
                assert certificate is not None
                for target in certificate.get("target_unit_ids", []):
                    edges.append(
                        _Edge(
                            "checked_indirect_control",
                            source,
                            target,
                            _unit_span(inputs.by_id[target])[0],
                            certificate_id=str(certificate.get("id", "")),
                        )
                    )

    edges.sort(
        key=lambda edge: (
            _unit_key(inputs.by_id[edge.source]),
            edge.kind,
            edge.target_rva if edge.target_rva is not None else -1,
            edge.event_index if edge.event_index is not None else -1,
        )
    )
    outgoing_lists: dict[str, list[_Edge]] = defaultdict(list)
    incoming_lists: dict[str, list[_Edge]] = defaultdict(list)
    for edge in edges:
        outgoing_lists[edge.source].append(edge)
        if edge.target is not None:
            incoming_lists[edge.target].append(edge)
    outgoing = {key: tuple(value) for key, value in outgoing_lists.items()}
    incoming = {key: tuple(value) for key, value in incoming_lists.items()}
    control_outgoing = {
        unit_id: tuple(
            edge
            for edge in outgoing.get(unit_id, ())
            if edge.kind != "internal_call"
        )
        for unit_id in inputs.by_id
    }
    sccs, scc_by_unit = _strong_components(inputs, control_outgoing)
    roots: list[str] = []
    raw_roots = _mapping(inputs.manifest.get("control", {}), "control inventory").get(
        "roots", []
    )
    if not isinstance(raw_roots, list):
        raise ComponentDiscoveryError("machine roots must be an array")
    for raw in raw_roots:
        root = _mapping(raw, "machine root")
        rva = root.get("rva")
        if not isinstance(rva, int) or rva not in inputs.by_rva:
            raise ComponentDiscoveryError("machine root does not name an exact unit")
        roots.append(inputs.by_rva[rva])
    return _Graph(
        edges=tuple(edges),
        outgoing=outgoing,
        incoming=incoming,
        control_outgoing=control_outgoing,
        roots=tuple(sorted(set(roots), key=lambda value: _unit_key(inputs.by_id[value]))),
        indirect=indirect,
        scc_by_unit=scc_by_unit,
        sccs=sccs,
    )


def _generate_for_seed(
    inputs: _Inputs,
    graph: _Graph,
    *,
    seed_id: str,
    unit_id: str,
    max_units: int,
    issues: list[dict[str, Any]],
) -> list[_Candidate]:
    result: list[_Candidate] = []

    def add(kind: str, members: Iterable[str], details: Mapping[str, Any]) -> None:
        member_set = frozenset(members)
        if not member_set or unit_id not in member_set:
            return
        if len(member_set) > max_units:
            issues.append(
                _issue(
                    inputs,
                    unit_id,
                    category="candidate_unit_limit_exceeded",
                    message=f"{kind} closure requires {len(member_set)} units",
                    remediation=(
                        "Select the region explicitly or raise the unit limit after reviewing "
                        "its unresolved control and interface complexity."
                    ),
                    observed=len(member_set),
                    expected=f"at most {max_units}",
                )
            )
            return
        result.append(
            _Candidate(
                members=member_set,
                seed_ids={seed_id},
                kinds={kind},
                history=[
                    {
                        "operation": kind,
                        "seed_unit_id": unit_id,
                        "input_unit_count": 1,
                        "output_unit_count": len(member_set),
                        "details": copy.deepcopy(dict(details)),
                    }
                ],
            )
        )

    add("singleton", [unit_id], {"reason": "coverage_floor"})
    straight = _straight_closure(inputs, graph, unit_id, max_units)
    if len(straight) > 1:
        add("straight_line_closure", straight, {"stops_at_control_boundaries": True})
    single_entry = _single_entry_closure(inputs, graph, unit_id, max_units)
    if len(single_entry) > 1:
        add(
            "single_entry_control_closure",
            single_entry,
            {
                "entry_unit_id": unit_id,
                "stops_at_alternate_entries": True,
            },
        )
    scc_id = graph.scc_by_unit[unit_id]
    scc_members = graph.sccs[scc_id]
    if len(scc_members) > 1 or any(
        edge.target == unit_id for edge in graph.control_outgoing.get(unit_id, ())
    ):
        add("scc_loop_closure", scc_members, {"scc_id": scc_id})

    call_sites = [
        edge
        for edge in graph.incoming.get(unit_id, ())
        if edge.kind == "internal_call"
    ]
    if call_sites:
        callable_members = _callee_closure(inputs, graph, unit_id, max_units)
        add(
            "call_target_return_closure",
            callable_members,
            {
                "entry_unit_id": unit_id,
                "caller_unit_ids": sorted(
                    {edge.source for edge in call_sites},
                    key=lambda value: _unit_key(inputs.by_id[value]),
                ),
                "stops_at_terminal_outcomes": True,
            },
        )

    for edge in graph.outgoing.get(unit_id, ()):
        if edge.kind != "internal_call":
            continue
        if edge.target is None:
            continue
        callee = _callee_closure(inputs, graph, edge.target, max_units)
        add(
            "direct_call_closure",
            {unit_id, *callee},
            {
                "callee_entry_unit_id": edge.target,
                "return_rva": _internal_call_return(inputs.by_id[unit_id], edge.event_index),
                "callee_unit_count": len(callee),
            },
        )

    branch = _external_branch_closure(inputs, graph, unit_id)
    if branch is not None:
        members, join = branch
        add(
            "external_event_branch_coarsening",
            members,
            {"common_continuation_unit_id": join, "hides_machine_branch": True},
        )

    dispatch = _finite_dispatch_closure(inputs, graph, unit_id)
    if dispatch is not None:
        members, join, blocker = dispatch
        add(
            "finite_dispatch_closure",
            members,
            {
                "common_continuation_unit_id": join,
                "target_count": len(graph.indirect[unit_id].get("target_unit_ids", [])),
            },
        )
        if blocker is not None:
            result[-1].extra_blockers.append(blocker)

    object_members, object_origins = _object_closure(inputs, unit_id)
    if len(object_members) > 1:
        add(
            "object_footprint_closure",
            object_members,
            {"shared_object_origins": object_origins},
        )

    if _looks_like_epilogue(inputs.by_id[unit_id]):
        epilogue = _epilogue_closure(inputs, graph, unit_id, max_units)
        if len(epilogue) > 1:
            add(
                "epilogue_absorption",
                epilogue,
                {"goal": "hide_stack_restores_and_raw_return_state"},
            )

    for cluster_id in inputs.cluster_by_unit.get(unit_id, ()):
        members = inputs.clusters[cluster_id]
        if len(members) > 1:
            add(
                "reconstruction_cluster_baseline",
                members,
                {"cluster_id": cluster_id},
            )
    return result


def _deduplicate_candidates(candidates: Sequence[_Candidate]) -> list[_Candidate]:
    by_members: dict[frozenset[str], _Candidate] = {}
    for candidate in candidates:
        existing = by_members.get(candidate.members)
        if existing is None:
            by_members[candidate.members] = candidate
            continue
        existing.seed_ids.update(candidate.seed_ids)
        existing.kinds.update(candidate.kinds)
        existing.history.extend(candidate.history)
        existing.extra_blockers.extend(candidate.extra_blockers)
    return list(by_members.values())


def _merge_selected_candidates(by_seed: Mapping[str, Sequence[_Candidate]]) -> list[_Candidate]:
    merged: dict[frozenset[str], _Candidate] = {}
    for seed_id in sorted(by_seed):
        for candidate in by_seed[seed_id]:
            current = merged.get(candidate.members)
            if current is None:
                merged[candidate.members] = _Candidate(
                    candidate.members,
                    set(candidate.seed_ids),
                    set(candidate.kinds),
                    copy.deepcopy(candidate.history),
                    copy.deepcopy(candidate.extra_blockers),
                )
            else:
                current.seed_ids.update(candidate.seed_ids)
                current.kinds.update(candidate.kinds)
                current.history.extend(copy.deepcopy(candidate.history))
                current.extra_blockers.extend(copy.deepcopy(candidate.extra_blockers))
    return list(merged.values())


def _score_candidate(
    inputs: _Inputs,
    graph: _Graph,
    candidate: _Candidate,
    *,
    boundary: Mapping[str, Any],
    hints: Mapping[str, Any],
    blockers: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    members = candidate.members
    branch_count = 0
    memory_count = 0
    external_count = 0
    for unit_id in members:
        semantics = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics")
        outcome = semantics.get("outcome", {})
        if isinstance(outcome, Mapping) and outcome.get("kind") == "branch":
            branch_count += 1
        memory_count += len(semantics.get("memory_events", []))
        external_count += len(
            [
                event
                for event in semantics.get("external_events", [])
                if isinstance(event, Mapping) and event.get("kind") != "internal_call"
            ]
        )
    raw_control = len(boundary["raw_control_targets"])
    raw_flags = len(boundary["exposed_flags"])
    hint_counts = hints["counts"]
    raw_stack = int(hint_counts["stack_state"])
    raw_registers = int(hint_counts["parameters"]) + int(
        hint_counts["results"]
    )
    unresolved_aliases = int(hint_counts["ambiguous_objects"])
    return {
        "hard_blockers": len(blockers),
        "raw_machine_exposure": raw_control + raw_flags + raw_stack + raw_registers,
        "raw_control_targets": raw_control,
        "exposed_flags": raw_flags,
        "exposed_stack_items": raw_stack,
        "exposed_register_items": raw_registers,
        "logical_parameters": int(hint_counts["parameters"]),
        "logical_results": int(hint_counts["results"]),
        "logical_objects": int(hint_counts["objects"]),
        "unresolved_aliases": unresolved_aliases,
        "external_services": int(hint_counts["services"]),
        "unit_count": len(members),
        "branch_count": branch_count,
        "memory_event_count": memory_count,
        "external_event_count": external_count,
        "loop_scc_count": len(
            {
                graph.scc_by_unit[unit_id]
                for unit_id in members
                if len(graph.sccs[graph.scc_by_unit[unit_id]]) > 1
            }
        ),
        "machine_units_eliminated": len(members),
        "internal_adapters_eliminated": int(boundary["internal_edge_count"]),
    }


def _pareto_fronts(scores: Sequence[Mapping[str, int]]) -> list[int]:
    remaining = set(range(len(scores)))
    fronts = [-1] * len(scores)
    front = 0
    while remaining:
        current = {
            index
            for index in remaining
            if not any(
                _dominates(scores[other], scores[index])
                for other in remaining
                if other != index
            )
        }
        for index in current:
            fronts[index] = front
        remaining.difference_update(current)
        front += 1
    return fronts


def _dominates(left: Mapping[str, int], right: Mapping[str, int]) -> bool:
    minimize = (
        "hard_blockers",
        "raw_machine_exposure",
        "raw_control_targets",
        "exposed_flags",
        "exposed_stack_items",
        "exposed_register_items",
        "logical_parameters",
        "logical_results",
        "logical_objects",
        "unresolved_aliases",
    )
    maximize = ("machine_units_eliminated", "internal_adapters_eliminated")
    no_worse = all(left[key] <= right[key] for key in minimize) and all(
        left[key] >= right[key] for key in maximize
    )
    strictly_better = any(left[key] < right[key] for key in minimize) or any(
        left[key] > right[key] for key in maximize
    )
    return no_worse and strictly_better


def _candidate_order_key(
    front: int, score: Mapping[str, int], candidate: _Candidate, inputs: _Inputs
) -> tuple[Any, ...]:
    semantic_priority = min(
        (
            {
                "external_event_branch_coarsening": 0,
                "single_entry_control_closure": 1,
                "direct_call_closure": 2,
                "call_target_return_closure": 3,
                "finite_dispatch_closure": 4,
                "object_footprint_closure": 5,
                "scc_loop_closure": 6,
                "epilogue_absorption": 7,
                "straight_line_closure": 8,
                "reconstruction_cluster_baseline": 9,
                "singleton": 10,
            }.get(kind, 11)
            for kind in candidate.kinds
        ),
        default=11,
    )
    first = min(_unit_key(inputs.by_id[unit_id]) for unit_id in candidate.members)
    return (
        front,
        score["hard_blockers"],
        score["raw_machine_exposure"],
        semantic_priority,
        -score["internal_adapters_eliminated"],
        -score["machine_units_eliminated"],
        score["branch_count"],
        first,
        _canonical_sha256(sorted(candidate.members)),
    )


def _candidate_blockers(
    inputs: _Inputs, graph: _Graph, candidate: _Candidate
) -> list[dict[str, Any]]:
    blockers = copy.deepcopy(candidate.extra_blockers)
    for unit_id in sorted(candidate.members, key=lambda value: _unit_key(inputs.by_id[value])):
        unit = inputs.by_id[unit_id]
        semantics = _mapping(unit.get("semantics"), "semantics")
        outcome = semantics.get("outcome")
        if isinstance(outcome, Mapping) and str(outcome.get("kind", "")).startswith(
            "indirect"
        ):
            certificate = graph.indirect.get(unit_id)
            if not _complete_indirect_certificate(certificate):
                cause = (
                    certificate.get("failure", {}).get("code")
                    if isinstance(certificate, Mapping)
                    and isinstance(certificate.get("failure"), Mapping)
                    else "missing_checked_target_inventory"
                )
                blockers.append(
                    _issue(
                        inputs,
                        unit_id,
                        category="unresolved_indirect_control",
                        message="indirect control has no checked finite target set",
                        remediation=(
                            "Recover and validate every feasible target, then regenerate the "
                            "machine IR indirect-target inventory."
                        ),
                        field="semantics.outcome.target",
                        observed=cause,
                        expected="checked finite target inventory",
                    )
                )
        for edge in graph.outgoing.get(unit_id, ()):
            if (
                edge.kind == "internal_call"
                and edge.target is not None
                and edge.target not in candidate.members
            ):
                blockers.append(
                    _issue(
                        inputs,
                        unit_id,
                        category="unclosed_internal_call_dependency",
                        message="component leaves a known internal callee outside its membership",
                        remediation=(
                            "Select a call-closure proposal containing the callee, or provide "
                            "a separately checked component-call contract before qualification."
                        ),
                        field=f"semantics.external_events[{edge.event_index}].target_rva",
                        observed={
                            "target_rva": edge.target_rva,
                            "target_unit_id": edge.target,
                        },
                        expected="member callee or checked component-call contract",
                    )
                )
                continue
            if edge.target is not None:
                continue
            if edge.kind == "internal_call":
                blockers.append(
                    _issue(
                        inputs,
                        unit_id,
                        category="unresolved_internal_call_target",
                        message="internal call target does not resolve to a machine unit",
                        remediation=(
                            "Recover the direct callee or classify the call as an external "
                            "machine-level service before selecting this proposal."
                        ),
                        field=f"semantics.external_events[{edge.event_index}].target_rva",
                        observed=edge.target_rva,
                        expected="known machine unit RVA",
                    )
                )
            elif edge.kind != "checked_indirect_control":
                blockers.append(
                    _issue(
                        inputs,
                        unit_id,
                        category="unknown_direct_control_target",
                        message="direct control target does not resolve to a machine unit",
                        remediation=(
                            "Repair machine-IR executable coverage or classify the destination "
                            "before selecting this proposal."
                        ),
                        field="semantics.outcome",
                        observed=edge.target_rva,
                        expected="known machine unit RVA",
                    )
                )
    by_id = {item["id"]: item for item in blockers}
    return sorted(
        by_id.values(),
        key=lambda item: (
            int(item["source_location"]["rva_start"]),
            str(item["category"]),
            str(item["id"]),
        ),
    )


__all__ = [
    "COMPONENT_PROPOSAL_SET_FORMAT",
    "ComponentDiscoveryError",
    "PROPOSAL_SET_FORMAT",
    "discover_component_proposals",
    "write_component_proposals",
]
