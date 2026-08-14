"""Artifact rendering for component discovery."""

from __future__ import annotations

import copy
from collections import defaultdict
from typing import Any, Mapping, Sequence

from .discovery_checker import (
    _address_origin,
    _expression_origins,
    _semantic_expressions,
    _stack_event_consumed_by_external,
    _suggested_control_form,
)
from .discovery_model import (
    _INTERFACE_ITEM_LIMIT,
    _Candidate,
    _Graph,
    _Inputs,
    _canonical_sha256,
    _evidence_summary,
    _location,
    _mapping,
    _noncontiguous,
    _ordered_unit_ids,
    _unique_dicts,
    _unit_binding,
    _unit_key,
    _unit_span,
)


def _proposal_payload(
    inputs: _Inputs,
    graph: _Graph,
    candidate: _Candidate,
    by_seed: Mapping[str, Sequence[_Candidate]],
    *,
    analysis: Mapping[str, Any],
) -> dict[str, Any]:
    member_ids = sorted(candidate.members, key=lambda value: _unit_key(inputs.by_id[value]))
    proposal_id = "component-proposal:" + _canonical_sha256(member_ids)[:20]
    blockers = analysis["blockers"]
    score = analysis["score"]
    seed_rankings: list[dict[str, Any]] = []
    for seed_id in sorted(candidate.seed_ids):
        seed_candidates = list(by_seed[seed_id])
        index = next(
            index
            for index, item in enumerate(seed_candidates)
            if item.members == candidate.members
        )
        selection = next(
            entry
            for entry in reversed(seed_candidates[index].history)
            if entry["operation"] == "pareto_selection"
        )
        seed_rankings.append(
            {
                "seed_id": seed_id,
                "front": selection["front"],
                "rank": selection["rank"],
            }
        )
    score_payload = {
        "vector": score,
        "front": min(item["front"] for item in seed_rankings),
        "rank": min(item["rank"] for item in seed_rankings),
        "seed_rankings": seed_rankings,
    }
    starts_ends = [_unit_span(inputs.by_id[unit_id]) for unit_id in member_ids]
    interface_hint = analysis["hints"]
    reachability_values = {
        str(inputs.by_id[unit_id].get("reachability", "unknown"))
        for unit_id in member_ids
    }
    if reachability_values == {"reachable"}:
        reachability = "exact"
    elif reachability_values <= {"potential"}:
        reachability = "potential"
    elif reachability_values <= {"unreachable"}:
        reachability = "unreachable"
    else:
        reachability = "mixed"
    issues = copy.deepcopy(blockers)
    return {
        "id": proposal_id,
        "status": "blocked" if blockers else "proposed",
        "authority": "untrusted_proposal_only",
        "seeds": sorted(candidate.seed_ids),
        "proposal_kinds": sorted(candidate.kinds),
        "membership": {
            "unit_ids": member_ids,
            "unit_count": len(member_ids),
            "rva_start": min(start for start, _end in starts_ends),
            "rva_end": max(end for _start, end in starts_ends),
            "noncontiguous": _noncontiguous(starts_ends),
        },
        "reachability": {
            "classification": reachability,
            "counts": {
                classification: sum(
                    inputs.by_id[unit_id].get("reachability", "unknown")
                    == classification
                    for unit_id in member_ids
                )
                for classification in (
                    "reachable",
                    "potential",
                    "unreachable",
                    "unknown",
                )
            },
        },
        "bindings": {
            "machine_ir_sha256": inputs.ir_sha256,
            "reconstruction_plan_sha256": inputs.plan["plan_sha256"],
            "unit_binding_source": "graph_facts.nodes",
            "membership_bindings_sha256": _canonical_sha256(
                [_unit_binding(inputs.by_id[unit_id]) for unit_id in member_ids]
            ),
        },
        "closure_history": _unique_dicts(candidate.history),
        "boundary": analysis["boundary"],
        "interface_hint": interface_hint,
        "score": score_payload,
        "blockers": blockers,
        "issues": issues,
        "parent_ids": [],
        "alternative_ids": [],
    }


def _boundary_payload(
    inputs: _Inputs, graph: _Graph, members: frozenset[str]
) -> dict[str, Any]:
    entries = []
    exits = []
    internal_edges = 0
    for unit_id in sorted(members, key=lambda value: _unit_key(inputs.by_id[value])):
        outside_incoming = [
            edge for edge in graph.incoming.get(unit_id, ()) if edge.source not in members
        ]
        if outside_incoming or unit_id in graph.roots:
            entries.append(
                {
                    "unit_id": unit_id,
                    "rva": _unit_span(inputs.by_id[unit_id])[0],
                    "root": unit_id in graph.roots,
                    "incoming_count": len(outside_incoming),
                }
            )
        for edge in graph.outgoing.get(unit_id, ()):
            if edge.target in members:
                internal_edges += 1
            elif edge.kind != "internal_call":
                exits.append(
                    {
                        "kind": edge.kind,
                        "source_unit_id": unit_id,
                        "target_unit_id": edge.target,
                        "target_rva": edge.target_rva,
                    }
                )
        outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
            "outcome"
        )
        if isinstance(outcome, Mapping) and outcome.get("kind") in {
            "return",
            "fault",
            "termination",
        }:
            exits.append(
                {
                    "kind": outcome["kind"],
                    "source_unit_id": unit_id,
                    "target_unit_id": None,
                    "target_rva": None,
                }
            )
    raw_targets = sorted(
        {
            int(item["target_rva"])
            for item in exits
            if isinstance(item.get("target_rva"), int)
        }
    )
    exposed_flags: set[str] = set()
    if len(raw_targets) > 1:
        for unit_id in members:
            semantics = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics")
            for write in semantics.get("flag_writes", []):
                if isinstance(write, Mapping) and isinstance(write.get("flag"), str):
                    exposed_flags.add(str(write["flag"]))
    return {
        "entries": entries,
        "exits": sorted(
            exits,
            key=lambda item: (
                _unit_key(inputs.by_id[item["source_unit_id"]]),
                str(item["kind"]),
                item["target_rva"] if item["target_rva"] is not None else -1,
            ),
        ),
        "raw_control_targets": raw_targets,
        "exposed_flags": sorted(exposed_flags),
        "internal_edge_count": internal_edges,
    }


def _interface_hints(
    inputs: _Inputs,
    graph: _Graph,
    members: frozenset[str],
    *,
    boundary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    register_reads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    register_writes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    flags: set[str] = set()
    objects: dict[str, dict[str, Any]] = {}
    services: dict[str, dict[str, Any]] = {}
    stack: dict[str, dict[str, Any]] = {}
    for unit_id in sorted(members, key=lambda value: _unit_key(inputs.by_id[value])):
        facts = _unit_interface_facts(inputs, unit_id)
        for name, evidence in facts["register_reads"].items():
            register_reads[name].extend(evidence)
        for name, evidence in facts["register_writes"].items():
            register_writes[name].extend(evidence)
        flags.update(facts["flags"])
        for service in facts["services"]:
            identity = {
                key: copy.deepcopy(service.get(key))
                for key in (
                    "kind",
                    "dll",
                    "symbol",
                    "ordinal",
                    "argument_count",
                    "confidence",
                )
            }
            aggregate = services.setdefault(
                _canonical_sha256(identity), {**identity, "evidence": []}
            )
            aggregate["evidence"].append(
                {
                    "unit_id": service["unit_id"],
                    "event_index": service["event_index"],
                    "source_location": copy.deepcopy(service["source_location"]),
                }
            )
        for origin, item in facts["objects"].items():
            aggregate = objects.setdefault(
                origin,
                {"origin": origin, "accesses": set(), "widths": set(), "evidence": []},
            )
            aggregate["accesses"].update(item["accesses"])
            aggregate["widths"].update(item["widths"])
            aggregate["evidence"].extend(copy.deepcopy(item["evidence"]))
        for origin, evidence in facts["stack"].items():
            stack.setdefault(
                origin,
                {"origin": origin, "confidence": "machine_exact", "evidence": []},
            )["evidence"].extend(copy.deepcopy(evidence))
    if boundary is None:
        boundary = _boundary_payload(inputs, graph, members)
    exit_sources = {str(item["source_unit_id"]) for item in boundary["exits"]}
    parameters = [
        {
            "kind": "machine_register",
            "register": name,
            "confidence": "conservative_expression_origin",
            **_evidence_summary(evidence),
        }
        for name, evidence in sorted(register_reads.items())
    ]
    results = [
        {
            "kind": "candidate_machine_register_result",
            "register": name,
            "confidence": "boundary_liveness_unchecked",
            **_evidence_summary(
                [entry for entry in evidence if entry["unit_id"] in exit_sources]
                or evidence
            ),
        }
        for name, evidence in sorted(register_writes.items())
        if name not in {"esp", "ebp"}
    ]
    object_payloads = []
    for origin, item in sorted(objects.items()):
        object_payloads.append(
            {
                "origin": origin,
                "accesses": sorted(item["accesses"]),
                "widths": sorted(item["widths"]),
                "confidence": (
                    "ambiguous" if origin == "unknown" else "structural_hint_unchecked"
                ),
                **_evidence_summary(item["evidence"]),
            }
        )
    service_payloads = [
        {**service, **_evidence_summary(service["evidence"])}
        for _key, service in sorted(services.items())
    ]
    stack_payloads = [
        {**value, **_evidence_summary(value["evidence"])}
        for _key, value in sorted(stack.items())
    ]
    return {
        "authority": "synthesized_hint_requires_checked_interface_refinement",
        "status": "proposed",
        "parameters": parameters[:_INTERFACE_ITEM_LIMIT],
        "results": results[:_INTERFACE_ITEM_LIMIT],
        "objects": object_payloads[:_INTERFACE_ITEM_LIMIT],
        "persistent_state": [],
        "services": service_payloads[:_INTERFACE_ITEM_LIMIT],
        "preconditions": [],
        "postconditions": [],
        "observations": [],
        "stack_state": stack_payloads[:_INTERFACE_ITEM_LIMIT],
        "counts": {
            "parameters": len(parameters),
            "results": len(results),
            "objects": len(object_payloads),
            "ambiguous_objects": sum(
                item["confidence"] == "ambiguous" for item in object_payloads
            ),
            "services": len(service_payloads),
            "stack_state": len(stack_payloads),
        },
        "truncated": {
            "parameters": len(parameters) > _INTERFACE_ITEM_LIMIT,
            "results": len(results) > _INTERFACE_ITEM_LIMIT,
            "objects": len(object_payloads) > _INTERFACE_ITEM_LIMIT,
            "services": len(service_payloads) > _INTERFACE_ITEM_LIMIT,
            "stack_state": len(stack_payloads) > _INTERFACE_ITEM_LIMIT,
        },
        "flags_written": sorted(flags),
        "control": {
            "raw_target_rvas": boundary["raw_control_targets"],
            "suggested_form": _suggested_control_form(inputs, graph, members),
        },
    }


def _unit_interface_facts(inputs: _Inputs, unit_id: str) -> dict[str, Any]:
    cached = inputs.unit_hint_facts.get(unit_id)
    if cached is not None:
        return cached
    unit = inputs.by_id[unit_id]
    semantics = _mapping(unit.get("semantics"), "semantics")
    location = _location(inputs, unit_id)
    evidence = {"unit_id": unit_id, "source_location": location}
    register_reads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    register_writes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    flags: set[str] = set()
    objects: dict[str, dict[str, Any]] = {}
    stack: dict[str, list[dict[str, Any]]] = defaultdict(list)
    services: list[dict[str, Any]] = []
    for expression in _semantic_expressions(semantics):
        for kind, name in _expression_origins(expression):
            if kind == "register" and name not in {"esp", "ebp"}:
                register_reads[name].append(copy.deepcopy(evidence))
    for write in semantics.get("register_writes", []):
        if isinstance(write, Mapping) and isinstance(write.get("register"), str):
            register_writes[str(write["register"]).lower()].append(
                copy.deepcopy(evidence)
            )
    for write in semantics.get("flag_writes", []):
        if isinstance(write, Mapping) and isinstance(write.get("flag"), str):
            flags.add(str(write["flag"]).lower())
    for index, event in enumerate(semantics.get("memory_events", [])):
        if not isinstance(event, Mapping):
            continue
        event_evidence = {
            "unit_id": unit_id,
            "event_index": index,
            "source_location": location,
        }
        origin = _address_origin(event.get("address"))
        if origin.startswith("stack:"):
            if not _stack_event_consumed_by_external(semantics, event):
                stack[origin].append(event_evidence)
            continue
        item = objects.setdefault(
            origin,
            {"accesses": set(), "widths": set(), "evidence": []},
        )
        item["accesses"].add(str(event.get("kind", "unknown")))
        if isinstance(event.get("width"), int):
            item["widths"].add(int(event["width"]))
        item["evidence"].append(event_evidence)
    for index, event in enumerate(semantics.get("external_events", [])):
        if not isinstance(event, Mapping) or event.get("kind") == "internal_call":
            continue
        arguments = event.get("arguments", [])
        services.append(
            {
                "kind": event.get("kind"),
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "ordinal": event.get("ordinal"),
                "argument_count": len(arguments) if isinstance(arguments, list) else 0,
                "unit_id": unit_id,
                "event_index": index,
                "source_location": location,
                "confidence": "machine_exact_identity_interface_unchecked",
            }
        )
    result = {
        "register_reads": dict(register_reads),
        "register_writes": dict(register_writes),
        "flags": flags,
        "objects": objects,
        "stack": dict(stack),
        "services": services,
    }
    inputs.unit_hint_facts[unit_id] = result
    return result


def _coverage_payload(inputs: _Inputs, proposals: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    owners: dict[str, list[str]] = defaultdict(list)
    for proposal in proposals:
        for unit_id in proposal["membership"]["unit_ids"]:
            owners[unit_id].append(str(proposal["id"]))
    exact = [
        unit_id
        for unit_id in _ordered_unit_ids(inputs)
        if inputs.by_id[unit_id].get("reachability") == "reachable"
    ]
    potential = [
        unit_id
        for unit_id in _ordered_unit_ids(inputs)
        if inputs.by_id[unit_id].get("reachability") == "potential"
    ]
    unreachable = [
        unit_id
        for unit_id in _ordered_unit_ids(inputs)
        if inputs.by_id[unit_id].get("reachability") == "unreachable"
    ]
    unknown = [
        unit_id
        for unit_id in _ordered_unit_ids(inputs)
        if inputs.by_id[unit_id].get("reachability")
        not in {"reachable", "potential", "unreachable"}
    ]

    def ledger(unit_ids: Sequence[str]) -> dict[str, Any]:
        covered = [unit_id for unit_id in unit_ids if owners.get(unit_id)]
        uncovered = [unit_id for unit_id in unit_ids if not owners.get(unit_id)]
        return {
            "unit_ids": list(unit_ids),
            "covered_unit_ids": covered,
            "uncovered_unit_ids": uncovered,
            "complete": not uncovered,
            "counts": {
                "total": len(unit_ids),
                "covered": len(covered),
                "uncovered": len(uncovered),
            },
        }

    full = _ordered_unit_ids(inputs)
    return {
        "model": "exact-potential-full-machine-unit-ledger-v1",
        "exact": ledger(exact),
        "potential": ledger(potential),
        "unreachable": ledger(unreachable),
        "unknown": ledger(unknown),
        "full": ledger(full),
        "by_unit": [
            {
                "unit_id": unit_id,
                "reachability": inputs.by_id[unit_id].get("reachability", "unknown"),
                "proposal_ids": sorted(owners.get(unit_id, [])),
            }
            for unit_id in full
        ],
    }


def _graph_payload(inputs: _Inputs, graph: _Graph) -> dict[str, Any]:
    edge_payloads = [edge.payload(index) for index, edge in enumerate(graph.edges)]
    outgoing_indices: dict[str, list[int]] = defaultdict(list)
    incoming_indices: dict[str, list[int]] = defaultdict(list)
    for index, edge in enumerate(graph.edges):
        outgoing_indices[edge.source].append(index)
        if edge.target is not None:
            incoming_indices[edge.target].append(index)
    return {
        "nodes": [
            {
                "index": index,
                "unit_id": unit_id,
                "rva_start": _unit_span(inputs.by_id[unit_id])[0],
                "rva_end": _unit_span(inputs.by_id[unit_id])[1],
                "reachability": inputs.by_id[unit_id].get("reachability", "unknown"),
                "scc_id": graph.scc_by_unit[unit_id],
                **_unit_binding(inputs.by_id[unit_id]),
                "incoming_edge_indices": incoming_indices.get(unit_id, []),
                "outgoing_edge_indices": outgoing_indices.get(unit_id, []),
            }
            for index, unit_id in enumerate(_ordered_unit_ids(inputs))
        ],
        "edges": edge_payloads,
        "roots": list(graph.roots),
        "sccs": [
            {"id": scc_id, "unit_ids": list(members), "unit_count": len(members)}
            for scc_id, members in sorted(graph.sccs.items())
        ],
        "counts": {
            "nodes": len(inputs.units),
            "edges": len(graph.edges),
            "sccs": len(graph.sccs),
            "roots": len(graph.roots),
            "indirect_certificates": len(graph.indirect),
            "unresolved_indirect": sum(
                1 for item in graph.indirect.values() if item.get("status") != "recovered"
            ),
        },
    }
