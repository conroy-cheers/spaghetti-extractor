"""Deterministic, non-authoritative semantic-component discovery.

This module proposes overlapping component boundaries from the byte-free
machine IR consumed by Stage B.  Proposals are navigation aids only: they do
not validate a logical interface, authorize a replacement, or execute the
original binary.  Unknown control flow is retained as a localized blocker.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


PROPOSAL_SET_FORMAT = "stage-b-component-proposal-set-v1"
COMPONENT_PROPOSAL_SET_FORMAT = PROPOSAL_SET_FORMAT
MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
RECONSTRUCTION_PLAN_FORMAT = "stage-b-reconstruction-plan-v1"
MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"
MACHINE_IR_FILENAME = "machine-ir.jsonl"
_EVIDENCE_SAMPLE_LIMIT = 1
_INTERFACE_ITEM_LIMIT = 4
_ALTERNATIVE_SAMPLE_LIMIT = 32


class ComponentDiscoveryError(ValueError):
    """Discovery inputs are malformed, stale, or internally inconsistent."""


@dataclass(frozen=True)
class _Inputs:
    manifest_path: Path
    ir_path: Path
    plan_path: Path
    manifest: dict[str, Any]
    plan: dict[str, Any]
    units: tuple[dict[str, Any], ...]
    by_id: dict[str, dict[str, Any]]
    by_rva: dict[int, str]
    cluster_by_unit: dict[str, tuple[str, ...]]
    clusters: dict[str, tuple[str, ...]]
    ir_sha256: str
    manifest_sha256: str
    plan_file_sha256: str
    unit_hint_facts: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class _Edge:
    kind: str
    source: str
    target: str | None
    target_rva: int | None
    event_index: int | None = None
    certificate_id: str | None = None

    def payload(self, index: int) -> dict[str, Any]:
        result: dict[str, Any] = {
            "index": index,
            "id": "component-edge:" + _canonical_sha256(
                {
                    "kind": self.kind,
                    "source": self.source,
                    "target": self.target,
                    "target_rva": self.target_rva,
                    "event_index": self.event_index,
                    "certificate_id": self.certificate_id,
                }
            )[:20],
            "kind": self.kind,
            "source_unit_id": self.source,
        }
        if self.target is not None:
            result["target_unit_id"] = self.target
        if self.target_rva is not None:
            result["target_rva"] = self.target_rva
        if self.event_index is not None:
            result["event_index"] = self.event_index
        if self.certificate_id is not None:
            result["certificate_id"] = self.certificate_id
        return result


@dataclass
class _Candidate:
    members: frozenset[str]
    seed_ids: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    history: list[dict[str, Any]] = field(default_factory=list)
    extra_blockers: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _Graph:
    edges: tuple[_Edge, ...]
    outgoing: dict[str, tuple[_Edge, ...]]
    incoming: dict[str, tuple[_Edge, ...]]
    control_outgoing: dict[str, tuple[_Edge, ...]]
    roots: tuple[str, ...]
    indirect: dict[str, dict[str, Any]]
    scc_by_unit: dict[str, str]
    sccs: dict[str, tuple[str, ...]]


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


def _load_inputs(machine_path: Path, plan_path: Path) -> _Inputs:
    manifest_path = (
        machine_path / MACHINE_IR_MANIFEST_FILENAME
        if machine_path.is_dir()
        else machine_path
    )
    manifest = _read_object(manifest_path, "machine IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise ComponentDiscoveryError("unsupported machine IR manifest format")
    artifacts = _mapping(manifest.get("artifacts"), "machine IR artifacts")
    artifact = _mapping(artifacts.get("machine_ir"), "machine IR artifact")
    relative_ir = artifact.get("path", MACHINE_IR_FILENAME)
    if not isinstance(relative_ir, str) or not relative_ir:
        raise ComponentDiscoveryError("machine IR artifact path is malformed")
    ir_path = (manifest_path.parent / relative_ir).resolve()
    try:
        ir_path.relative_to(manifest_path.parent.resolve())
    except ValueError as error:
        raise ComponentDiscoveryError("machine IR artifact escapes its package") from error
    if not ir_path.is_file():
        raise ComponentDiscoveryError(f"machine IR artifact does not exist: {ir_path}")
    if artifact.get("sha256") != _sha256_file(ir_path):
        raise ComponentDiscoveryError("machine IR artifact hash does not match manifest")

    units = tuple(_read_jsonl(ir_path))
    if not units:
        raise ComponentDiscoveryError("machine IR package contains no units")
    by_id: dict[str, dict[str, Any]] = {}
    by_rva: dict[int, str] = {}
    for unit in units:
        identity = unit.get("id")
        if not isinstance(identity, str) or not identity:
            raise ComponentDiscoveryError("machine IR unit has no stable ID")
        if identity in by_id:
            raise ComponentDiscoveryError(f"duplicate machine IR unit ID {identity!r}")
        start, end = _unit_span(unit)
        if start in by_rva:
            raise ComponentDiscoveryError(f"duplicate machine IR RVA 0x{start:x}")
        if end <= start:
            raise ComponentDiscoveryError(f"machine IR unit {identity!r} has empty span")
        source = _mapping(unit.get("source"), f"machine IR unit {identity} source")
        for digest_name in ("contract_sha256", "instruction_bytes_sha256"):
            digest = source.get(digest_name)
            if not isinstance(digest, str) or len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest
            ):
                raise ComponentDiscoveryError(
                    f"machine IR unit {identity!r} has no exact {digest_name} binding"
                )
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            raise ComponentDiscoveryError(f"machine IR unit {identity!r} has no semantics")
        by_id[identity] = copy.deepcopy(unit)
        by_rva[start] = identity

    resolved_plan = (
        plan_path / "reconstruction-plan.json" if plan_path.is_dir() else plan_path
    )
    plan = _read_object(resolved_plan, "reconstruction plan")
    if plan.get("format") != RECONSTRUCTION_PLAN_FORMAT:
        raise ComponentDiscoveryError("unsupported reconstruction plan format")
    plan_sha = plan.get("plan_sha256")
    if not isinstance(plan_sha, str) or plan_sha != _canonical_sha256(
        {key: value for key, value in plan.items() if key != "plan_sha256"}
    ):
        raise ComponentDiscoveryError("reconstruction plan self hash is stale")
    binding = _mapping(
        _mapping(plan.get("inputs"), "reconstruction plan inputs").get("machine_ir"),
        "reconstruction plan machine IR binding",
    )
    expected_binding = {
        "format": MACHINE_IR_FORMAT,
        "sha256": _sha256_file(ir_path),
        "manifest_sha256": _sha256_file(manifest_path),
    }
    for name, expected in expected_binding.items():
        if binding.get(name) != expected:
            raise ComponentDiscoveryError(
                f"reconstruction plan machine IR {name} binding is stale"
            )

    clusters: dict[str, tuple[str, ...]] = {}
    cluster_by_unit_lists: dict[str, list[str]] = defaultdict(list)
    raw_clusters = plan.get("clusters", [])
    if not isinstance(raw_clusters, list):
        raise ComponentDiscoveryError("reconstruction plan clusters must be an array")
    for index, raw in enumerate(raw_clusters):
        item = _mapping(raw, f"reconstruction cluster {index}")
        identity = item.get("id")
        members = item.get("unit_ids")
        if not isinstance(identity, str) or not identity:
            raise ComponentDiscoveryError(f"reconstruction cluster {index} has no ID")
        if identity in clusters:
            raise ComponentDiscoveryError(f"duplicate reconstruction cluster {identity!r}")
        if not isinstance(members, list) or not all(
            isinstance(value, str) for value in members
        ):
            raise ComponentDiscoveryError(f"cluster {identity!r} unit IDs are malformed")
        unknown = sorted(set(members) - set(by_id))
        if unknown:
            raise ComponentDiscoveryError(
                f"cluster {identity!r} references unknown units: {unknown}"
            )
        ordered = tuple(sorted(set(members), key=lambda value: _unit_key(by_id[value])))
        clusters[identity] = ordered
        for unit_id in ordered:
            cluster_by_unit_lists[unit_id].append(identity)
    cluster_by_unit = {
        unit_id: tuple(sorted(values))
        for unit_id, values in cluster_by_unit_lists.items()
    }
    return _Inputs(
        manifest_path=manifest_path,
        ir_path=ir_path,
        plan_path=resolved_plan,
        manifest=manifest,
        plan=plan,
        units=tuple(by_id[identity] for identity in sorted(by_id, key=lambda value: _unit_key(by_id[value]))),
        by_id=by_id,
        by_rva=by_rva,
        cluster_by_unit=cluster_by_unit,
        clusters=clusters,
        ir_sha256=expected_binding["sha256"],
        manifest_sha256=expected_binding["manifest_sha256"],
        plan_file_sha256=_sha256_file(resolved_plan),
        unit_hint_facts={},
    )


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


def _straight_closure(
    inputs: _Inputs, graph: _Graph, seed: str, max_units: int
) -> frozenset[str]:
    members = {seed}
    current = seed
    while len(members) < max_units:
        unit = inputs.by_id[current]
        semantics = _mapping(unit.get("semantics"), "semantics")
        outcome = semantics.get("outcome")
        if not isinstance(outcome, Mapping) or outcome.get("kind") != "fallthrough":
            break
        if semantics.get("external_events"):
            break
        edges = graph.control_outgoing.get(current, ())
        if len(edges) != 1 or edges[0].target is None:
            break
        target = edges[0].target
        if target in members or len(graph.incoming.get(target, ())) != 1:
            break
        members.add(target)
        current = target
    current = seed
    while len(members) < max_units:
        predecessors = [
            edge
            for edge in graph.incoming.get(current, ())
            if edge.kind == "fallthrough" and edge.source not in members
        ]
        if len(predecessors) != 1:
            break
        predecessor = predecessors[0].source
        semantics = _mapping(inputs.by_id[predecessor].get("semantics"), "semantics")
        if semantics.get("external_events") or len(graph.control_outgoing.get(predecessor, ())) != 1:
            break
        members.add(predecessor)
        current = predecessor
    return frozenset(members)


def _single_entry_closure(
    inputs: _Inputs, graph: _Graph, seed: str, max_units: int
) -> frozenset[str]:
    """Return the seed-reachable region cut at every alternate entry.

    A loop SCC may have more than one incoming edge from the surrounding
    program.  Treating that entire SCC as one component would require a
    multi-entry replacement ABI.  Instead, first find the bounded forward
    closure, identify nodes with predecessors outside that closure, and stop
    traversal at those alternate entries.  The seed itself is always admitted
    because its outside predecessors are precisely its activation sites.
    """

    reachable: set[str] = set()
    queue = deque([seed])
    while queue:
        unit_id = queue.popleft()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        if len(reachable) > max_units:
            return frozenset({seed})
        outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
            "outcome"
        )
        if isinstance(outcome, Mapping) and outcome.get("kind") in {
            "return",
            "fault",
            "termination",
        }:
            continue
        for edge in graph.control_outgoing.get(unit_id, ()):
            if edge.target is not None and edge.target not in reachable:
                queue.append(edge.target)

    alternate_entries = {
        unit_id
        for unit_id in reachable
        if unit_id != seed
        and (
            unit_id in graph.roots
            or any(
                edge.source not in reachable
                for edge in graph.incoming.get(unit_id, ())
            )
        )
    }
    members: set[str] = set()
    queue = deque([seed])
    while queue:
        unit_id = queue.popleft()
        if unit_id in members:
            continue
        members.add(unit_id)
        for edge in graph.control_outgoing.get(unit_id, ()):
            if (
                edge.target is not None
                and edge.target in reachable
                and edge.target not in alternate_entries
                and edge.target not in members
            ):
                queue.append(edge.target)

    # Cutting one alternate entry can expose a second entry that was reachable
    # only through the removed portion of a cycle.  Prune to a fixed point so
    # the proposal's checked boundary, rather than the initial reachability
    # approximation, is guaranteed to have one activation entry.
    while True:
        extra_entries = {
            unit_id
            for unit_id in members
            if unit_id != seed
            and (
                unit_id in graph.roots
                or any(
                    edge.source not in members
                    for edge in graph.incoming.get(unit_id, ())
                )
            )
        }
        if not extra_entries:
            break
        remove: set[str] = set()
        queue = deque(extra_entries)
        while queue:
            unit_id = queue.popleft()
            if unit_id == seed or unit_id in remove or unit_id not in members:
                continue
            remove.add(unit_id)
            for edge in graph.control_outgoing.get(unit_id, ()):
                if edge.target in members and edge.target != seed:
                    queue.append(str(edge.target))
        if not remove:
            break
        members.difference_update(remove)
    return frozenset(members)


def _callee_closure(
    inputs: _Inputs, graph: _Graph, entry: str, max_units: int
) -> frozenset[str]:
    members: set[str] = set()
    queue = deque([entry])
    while queue and len(members) < max_units:
        unit_id = queue.popleft()
        if unit_id in members:
            continue
        members.add(unit_id)
        outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
            "outcome"
        )
        if isinstance(outcome, Mapping) and outcome.get("kind") in {
            "return",
            "fault",
            "termination",
        }:
            continue
        for edge in graph.control_outgoing.get(unit_id, ()):
            if edge.target is not None and edge.target not in members:
                queue.append(edge.target)
    return frozenset(members)


def _external_branch_closure(
    inputs: _Inputs, graph: _Graph, unit_id: str
) -> tuple[frozenset[str], str] | None:
    outcome = _mapping(inputs.by_id[unit_id].get("semantics"), "semantics").get(
        "outcome"
    )
    if not isinstance(outcome, Mapping) or outcome.get("kind") != "branch":
        return None
    targets = [
        inputs.by_rva.get(outcome.get(name))
        for name in ("true_target_rva", "false_target_rva")
        if isinstance(outcome.get(name), int)
    ]
    if len(targets) != 2 or any(target is None for target in targets):
        return None
    paths = [_shortest_paths(graph, str(target), 64) for target in targets]
    common = set(paths[0]) & set(paths[1])
    if not common:
        return None
    join = min(
        common,
        key=lambda item: (
            len(paths[0][item]) + len(paths[1][item]),
            max(len(paths[0][item]), len(paths[1][item])),
            _unit_key(inputs.by_id[item]),
        ),
    )
    members = {unit_id}
    for path_map in paths:
        members.update(path_map[join][:-1])
    if not any(_has_external_event(inputs.by_id[item]) for item in members):
        return None
    return frozenset(members), join


def _finite_dispatch_closure(
    inputs: _Inputs, graph: _Graph, unit_id: str
) -> tuple[frozenset[str], str | None, dict[str, Any] | None] | None:
    certificate = graph.indirect.get(unit_id)
    if not _complete_indirect_certificate(certificate):
        return None
    assert certificate is not None
    targets = [str(value) for value in certificate.get("target_unit_ids", [])]
    if len(targets) < 2:
        return None
    path_maps = [_shortest_paths(graph, target, 64) for target in targets]
    common = set(path_maps[0])
    for path_map in path_maps[1:]:
        common.intersection_update(path_map)
    blocker = None
    members = {unit_id}
    join: str | None = None
    if common:
        join = min(
            common,
            key=lambda item: (
                max(len(path_map[item]) for path_map in path_maps),
                sum(len(path_map[item]) for path_map in path_maps),
                _unit_key(inputs.by_id[item]),
            ),
        )
        for path_map in path_maps:
            members.update(path_map[join][:-1])
    else:
        members.update(targets)
        blocker = _issue(
            inputs,
            unit_id,
            category="dispatch_arms_no_common_continuation",
            message="finite dispatch arms have no bounded common continuation",
            remediation=(
                "Provide an operator boundary for terminal arms or increase the checked path "
                "model before selecting this dispatch component."
            ),
            field="semantics.outcome.target",
            observed=len(targets),
            expected="bounded common continuation",
        )
    return frozenset(members), join, blocker


def _complete_indirect_certificate(
    certificate: Mapping[str, Any] | None,
) -> bool:
    if certificate is None:
        return False
    targets = certificate.get("target_unit_ids")
    return (
        certificate.get("status") == "recovered"
        and certificate.get("closure") == "checked_finite_target_inventory"
        and isinstance(targets, list)
        and bool(targets)
        and all(isinstance(target, str) and target for target in targets)
    )


def _object_closure(
    inputs: _Inputs, unit_id: str
) -> tuple[frozenset[str], list[str]]:
    seed_origins = _unit_object_origins(inputs.by_id[unit_id])
    if not seed_origins:
        return frozenset({unit_id}), []
    members = {unit_id}
    common: set[str] = set()
    for cluster_id in inputs.cluster_by_unit.get(unit_id, ()):
        for other in inputs.clusters[cluster_id]:
            shared = seed_origins & _unit_object_origins(inputs.by_id[other])
            if shared:
                members.add(other)
                common.update(shared)
    return frozenset(members), sorted(common)


def _epilogue_closure(
    inputs: _Inputs, graph: _Graph, unit_id: str, max_units: int
) -> frozenset[str]:
    members = {unit_id}
    current = unit_id
    while len(members) < max_units:
        predecessors = [
            edge
            for edge in graph.incoming.get(current, ())
            if edge.kind != "internal_call" and edge.source not in members
        ]
        if len(predecessors) != 1:
            break
        predecessor = predecessors[0].source
        if _has_external_event(inputs.by_id[predecessor]):
            break
        members.add(predecessor)
        current = predecessor
        if len(graph.incoming.get(current, ())) > 1:
            break
    for cluster_id in inputs.cluster_by_unit.get(unit_id, ()):
        cluster = inputs.clusters[cluster_id]
        if len(cluster) <= max_units and set(members).issubset(cluster):
            members.update(cluster)
            break
    return frozenset(members)


def _shortest_paths(graph: _Graph, start: str, limit: int) -> dict[str, tuple[str, ...]]:
    paths = {start: (start,)}
    queue = deque([start])
    while queue:
        source = queue.popleft()
        path = paths[source]
        if len(path) >= limit:
            continue
        for edge in graph.control_outgoing.get(source, ()):
            target = edge.target
            if target is None or target in paths:
                continue
            paths[target] = path + (target,)
            queue.append(target)
    return paths


def _strong_components(
    inputs: _Inputs, outgoing: Mapping[str, Sequence[_Edge]]
) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[tuple[str, ...]] = []

    def visit(unit_id: str) -> None:
        nonlocal index
        indices[unit_id] = index
        lowlinks[unit_id] = index
        index += 1
        stack.append(unit_id)
        on_stack.add(unit_id)
        for edge in outgoing.get(unit_id, ()):
            target = edge.target
            if target is None:
                continue
            if target not in indices:
                visit(target)
                lowlinks[unit_id] = min(lowlinks[unit_id], lowlinks[target])
            elif target in on_stack:
                lowlinks[unit_id] = min(lowlinks[unit_id], indices[target])
        if lowlinks[unit_id] == indices[unit_id]:
            members: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                members.append(member)
                if member == unit_id:
                    break
            components.append(
                tuple(sorted(members, key=lambda value: _unit_key(inputs.by_id[value])))
            )

    for unit_id in _ordered_unit_ids(inputs):
        if unit_id not in indices:
            visit(unit_id)
    components.sort(key=lambda members: _unit_key(inputs.by_id[members[0]]))
    sccs: dict[str, tuple[str, ...]] = {}
    by_unit: dict[str, str] = {}
    for members in components:
        identity = "scc:" + _canonical_sha256(list(members))[:20]
        sccs[identity] = members
        for member in members:
            by_unit[member] = identity
    return sccs, by_unit


def _outcome_targets(outcome: Mapping[str, Any]) -> list[tuple[str, int]]:
    kind = outcome.get("kind")
    fields = {
        "fallthrough": (("fallthrough", "target_rva"),),
        "jump": (("jump", "target_rva"),),
        "branch": (
            ("branch_true", "true_target_rva"),
            ("branch_false", "false_target_rva"),
        ),
    }.get(kind, ())
    return [
        (edge_kind, int(outcome[field]))
        for edge_kind, field in fields
        if isinstance(outcome.get(field), int)
    ]


def _suggested_control_form(
    inputs: _Inputs, graph: _Graph, members: frozenset[str]
) -> str:
    kinds = {
        str(
            _mapping(inputs.by_id[unit_id].get("semantics"), "semantics")
            .get("outcome", {})
            .get("kind", "")
        )
        for unit_id in members
    }
    if any(
        unit_id in graph.indirect
        and len(graph.indirect[unit_id].get("target_unit_ids", [])) > 1
        for unit_id in members
    ):
        return "finite_switch"
    if any(_has_external_event(inputs.by_id[unit_id]) for unit_id in members) and "branch" in kinds:
        return "conditional_external_service"
    if any(len(graph.sccs[graph.scc_by_unit[unit_id]]) > 1 for unit_id in members):
        return "structured_loop"
    if "branch" in kinds:
        return "conditional"
    if "return" in kinds:
        return "procedure"
    return "straight_line_operation"


def _semantic_expressions(semantics: Mapping[str, Any]) -> Iterable[Any]:
    outcome = semantics.get("outcome")
    if isinstance(outcome, Mapping):
        yield outcome.get("condition")
        yield outcome.get("target")
        yield outcome.get("value")
    for name in ("memory_events", "register_writes", "flag_writes", "external_events"):
        values = semantics.get(name, [])
        if isinstance(values, list):
            for value in values:
                yield value


def _expression_origins(value: Any) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    if isinstance(value, Mapping):
        if value.get("op") == "reg" and isinstance(value.get("name"), str):
            name = str(value["name"]).lower()
            result.add(("stack" if name in {"esp", "ebp"} else "register", name))
        elif value.get("op") == "flag" and isinstance(value.get("name"), str):
            result.add(("flag", str(value["name"]).lower()))
        for nested in value.values():
            result.update(_expression_origins(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(_expression_origins(nested))
    return result


def _address_origin(value: Any) -> str:
    origins = _expression_origins(value)
    stack = sorted(name for kind, name in origins if kind == "stack")
    registers = sorted(name for kind, name in origins if kind == "register")
    if stack:
        return "stack:" + "+".join(stack)
    if len(registers) == 1:
        return "register:" + registers[0]
    if len(registers) > 1:
        return "register-alternatives:" + "+".join(registers)
    constants = sorted(_expression_constants(value))
    if constants:
        return "static:" + "+".join(f"0x{item:x}" for item in constants[:3])
    return "unknown"


def _expression_constants(value: Any) -> set[int]:
    result: set[int] = set()
    if isinstance(value, Mapping):
        if value.get("op") == "const" and isinstance(value.get("value"), int):
            result.add(int(value["value"]))
        for nested in value.values():
            result.update(_expression_constants(nested))
    elif isinstance(value, list):
        for nested in value:
            result.update(_expression_constants(nested))
    return result


def _unit_object_origins(unit: Mapping[str, Any]) -> set[str]:
    semantics = _mapping(unit.get("semantics"), "semantics")
    origins = {
        _address_origin(event.get("address"))
        for event in semantics.get("memory_events", [])
        if isinstance(event, Mapping)
    }
    return {origin for origin in origins if not origin.startswith("stack:") and origin != "unknown"}


def _looks_like_epilogue(unit: Mapping[str, Any]) -> bool:
    semantics = _mapping(unit.get("semantics"), "semantics")
    outcome = semantics.get("outcome", {})
    if isinstance(outcome, Mapping) and outcome.get("kind") == "return":
        return True
    stack_references = sum(
        1
        for expression in _semantic_expressions(semantics)
        if any(kind == "stack" for kind, _name in _expression_origins(expression))
    )
    restored = {
        str(write.get("register", "")).lower()
        for write in semantics.get("register_writes", [])
        if isinstance(write, Mapping)
    }
    return stack_references >= 2 and bool(restored & {"ebx", "esi", "edi", "ebp", "esp"})


def _has_external_event(unit: Mapping[str, Any]) -> bool:
    semantics = _mapping(unit.get("semantics"), "semantics")
    return any(
        isinstance(event, Mapping) and event.get("kind") != "internal_call"
        for event in semantics.get("external_events", [])
    )


def _stack_event_consumed_by_external(
    semantics: Mapping[str, Any], event: Mapping[str, Any]
) -> bool:
    """Recognize stack argument setup that is internal to a checked call event."""

    if event.get("kind") != "write" or "value" not in event:
        return False
    value_hash = _canonical_sha256(event["value"])
    for external in semantics.get("external_events", []):
        if not isinstance(external, Mapping) or external.get("kind") == "internal_call":
            continue
        expressions: list[Any] = []
        arguments = external.get("arguments", [])
        if isinstance(arguments, list):
            expressions.extend(arguments)
        stack_inputs = external.get("stack_inputs", [])
        if isinstance(stack_inputs, list):
            expressions.extend(
                item.get("value")
                for item in stack_inputs
                if isinstance(item, Mapping) and "value" in item
            )
        if any(_canonical_sha256(expression) == value_hash for expression in expressions):
            return True
    return False


def _internal_call_return(unit: Mapping[str, Any], event_index: int | None) -> int | None:
    if event_index is None:
        return None
    events = _mapping(unit.get("semantics"), "semantics").get("external_events", [])
    if isinstance(events, list) and event_index < len(events):
        value = events[event_index].get("return_rva")
        return int(value) if isinstance(value, int) else None
    return None


def _issue(
    inputs: _Inputs,
    unit_id: str,
    *,
    category: str,
    message: str,
    remediation: str,
    field: str = "membership",
    expected: Any = None,
    observed: Any = None,
) -> dict[str, Any]:
    core = {
        "status": "incomplete",
        "category": category,
        "severity": "blocker",
        "message": message,
        "source_location": _location(inputs, unit_id, field=field),
        "expected": expected,
        "observed": observed,
        "remediation": {
            "action": category.replace("_", "-"),
            "details": remediation,
        },
    }
    return {"id": "component-gap:" + _canonical_sha256(core)[:20], **core}


def _location(inputs: _Inputs, unit_id: str, *, field: str | None = None) -> dict[str, Any]:
    start, end = _unit_span(inputs.by_id[unit_id])
    result = {
        "artifact": str(inputs.ir_path),
        "unit_id": unit_id,
        "rva_start": start,
        "rva_end": end,
    }
    if field is not None:
        result["field"] = field
    return result


def _noncontiguous(spans: Sequence[tuple[int, int]]) -> bool:
    ordered = sorted(spans)
    return any(left[1] != right[0] for left, right in zip(ordered, ordered[1:]))


def _unique_dicts(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical_sha256(value): copy.deepcopy(dict(value)) for value in values}
    return [unique[key] for key in sorted(unique)]


def _evidence_summary(
    values: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    evidence = _unique_dicts(
        {
            key: copy.deepcopy(value)
            for key, value in item.items()
            if key != "source_location"
        }
        for item in values
    )
    return {
        "location_source": "graph_facts.nodes_by_unit_id",
        "evidence": evidence[:_EVIDENCE_SAMPLE_LIMIT],
        "evidence_count": len(evidence),
        "evidence_truncated": len(evidence) > _EVIDENCE_SAMPLE_LIMIT,
    }


def _unit_binding(unit: Mapping[str, Any]) -> dict[str, Any]:
    source = unit.get("source", {})
    source = source if isinstance(source, Mapping) else {}
    return {
        "unit_id": str(unit.get("id", "")),
        "contract_sha256": source.get("contract_sha256"),
        "instruction_bytes_sha256": source.get("instruction_bytes_sha256"),
    }


def _ordered_unit_ids(inputs: _Inputs) -> list[str]:
    return sorted(inputs.by_id, key=lambda value: _unit_key(inputs.by_id[value]))


def _unit_key(unit: Mapping[str, Any]) -> tuple[int, int, str]:
    start, end = _unit_span(unit)
    return start, end, str(unit.get("id", ""))


def _unit_span(unit: Mapping[str, Any]) -> tuple[int, int]:
    source = _mapping(unit.get("source"), "machine IR unit source")
    original = _mapping(source.get("original"), "machine IR original source")
    start = original.get("rva_start")
    end = original.get("rva_end")
    if not isinstance(start, int) or not isinstance(end, int):
        raise ComponentDiscoveryError("machine IR unit has no exact original RVA span")
    return start, end


def _read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ComponentDiscoveryError(
                    f"invalid machine IR JSON on line {line_number}"
                ) from error
            if not isinstance(value, dict):
                raise ComponentDiscoveryError(
                    f"machine IR line {line_number} is not an object"
                )
            yield value


def _read_object(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file():
        raise ComponentDiscoveryError(f"{label} does not exist: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComponentDiscoveryError(f"cannot read {label}: {path}") from error
    if not isinstance(value, dict):
        raise ComponentDiscoveryError(f"{label} must be a JSON object")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentDiscoveryError(f"{label} must be an object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "COMPONENT_PROPOSAL_SET_FORMAT",
    "ComponentDiscoveryError",
    "PROPOSAL_SET_FORMAT",
    "discover_component_proposals",
    "write_component_proposals",
]
