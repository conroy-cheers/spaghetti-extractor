"""Fail-closed undefined-value noninterference analysis.

The semantic-transfer IR represents architecturally undefined values with
``undefined_bv`` and ``undefined_flag`` expressions. This module constructs an
untrusted finite dependency graph for each stable undefined value. Lean checks
the graph rules; exact decoded-transfer proofs must discharge the local
dependency-soundness premise before a certificate has proof authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifact_formats import (
    SEMANTIC_IR_FORMAT,
    SEMANTIC_TRANSFER_CONTRACT_FORMAT,
)


DEFINEDNESS_EVIDENCE_FORMAT = "stage-a-definedness-noninterference-v4"
_UNDEFINED_OPS = frozenset({"undefined_bv", "undefined_flag"})
_TRANSFER_FORMAT = SEMANTIC_TRANSFER_CONTRACT_FORMAT
_EXPRESSION_MODEL = SEMANTIC_IR_FORMAT
_REGISTER_NAMES = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})
_FLAG_NAMES = frozenset({"cf", "zf", "sf", "of", "pf", "df"})
_RETURN_KINDS = frozenset({"return"})
_TERMINATION_KINDS = frozenset({"terminate", "termination", "exit", "halt"})

_CLOSURE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "ambiguous_cfg_target": ("a unique decoded transfer at every target RVA",),
    "ambiguous_direct_edges": ("an exhaustive decoded edge inventory agreeing with the outcome",),
    "ambiguous_source_rva": ("one exact PE span for the undefined-value source",),
    "ambiguous_state_writes": ("an ordered semantic write sequence or one final write per location",),
    "ambiguous_transfer_identity": ("a unique stable transfer identifier",),
    "call_argument_dependency": (
        "a machine-level call contract proving argument and footprint independence",
        "or a caller/callee relational summary carrying the dependency through the call",
    ),
    "fault_dependency": ("a decoded fault-condition proof independent of the undefined value",),
    "guard_dependency": ("a proof that every feasible edge guard is independent of the undefined value",),
    "incomplete_reachability": ("checked rooted reachability for the traversed transfer",),
    "incomplete_source_identity": ("a unique source transfer identifier and exact source RVA",),
    "incomplete_source_reachability": ("checked rooted reachability for the undefined-value source",),
    "incomplete_transfer": ("closure of every transfer blocker on the counterexample path",),
    "indirect_control": ("a checked finite indirect-target inventory or an empty live set before transfer",),
    "memory_expression_dependency": (
        "exact memory read/write footprints",
        "a proof that addresses, values, widths, and fault conditions are independent",
    ),
    "missing_cfg_target": ("the decoded direct target transfer in the submitted inventory",),
    "missing_direct_target": ("an exact decoded direct target RVA",),
    "missing_stable_id": ("a stable undefined-value identity bound to exact instruction semantics",),
    "observation_dependency": ("an exact observation expression independent of the undefined value",),
    "return_boundary": ("an empty live dependency set at the machine return boundary",),
    "stable_slot_collision": ("a collision-free undefined-value slot assignment checked in Lean",),
    "state_budget_exceeded": ("a larger finite-state budget or a compact checked invariant",),
    "unsupported_control": ("a checked control-flow rule and complete successor inventory",),
    "unsupported_transfer_schema": ("a complete supported transfer schema and exact Lean semantics binding",),
    "unsupported_synchronized_choice": (
        "a checked value-indexed machine-input derivation or synchronized event contract",
    ),
}


class DefinednessAnalysisError(ValueError):
    """The input is not a readable semantic-transfer JSONL inventory."""


@dataclass(frozen=True, order=True)
class _Location:
    family: str
    name: str

    def payload(self) -> dict[str, str]:
        return {"family": self.family, "name": self.name}


@dataclass(frozen=True)
class _Dependency:
    locations: frozenset[_Location] = frozenset()
    slot: bool = False

    def merge(self, other: _Dependency) -> _Dependency:
        return _Dependency(self.locations | other.locations, self.slot or other.slot)

    def payload(self) -> dict[str, Any]:
        return {
            "locations": [item.payload() for item in sorted(self.locations)],
            "slot": self.slot,
        }

    def depends_on(
        self, live: frozenset[_Location], *, synchronized: bool = False
    ) -> bool:
        return (self.slot and not synchronized) or bool(self.locations & live)


@dataclass(frozen=True)
class _Occurrence:
    undefined_id: str
    explicit_id: bool
    slot: int
    op: str
    reason: str | None
    transfer_id: str
    rva_start: int | None
    pointer: str
    defined_value: Any = None

    def payload(self) -> dict[str, Any]:
        return {
            "transfer_id": self.transfer_id,
            "rva_start": self.rva_start,
            "json_pointer": self.pointer,
            "op": self.op,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class _Node:
    transfer_id: str
    rva_start: int | None
    row: Mapping[str, Any]


def analyze_definedness_jsonl(
    state_machine: str | Path,
    *,
    max_states_per_slot: int = 100_000,
) -> dict[str, Any]:
    path = Path(state_machine)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DefinednessAnalysisError(f"cannot read {path}: {exc}") from exc
    rows: list[Mapping[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            row = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DefinednessAnalysisError(
                f"{path}:{line_number}: invalid semantic-transfer JSON: {exc}"
            ) from exc
        if not isinstance(row, dict):
            raise DefinednessAnalysisError(f"{path}:{line_number}: transfer must be a JSON object")
        rows.append(row)
    return analyze_definedness_rows(
        rows,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        max_states_per_slot=max_states_per_slot,
    )


def analyze_definedness_rows(
    rows: Iterable[Mapping[str, Any]],
    *,
    source_sha256: str | None = None,
    max_states_per_slot: int = 100_000,
) -> dict[str, Any]:
    if isinstance(max_states_per_slot, bool) or max_states_per_slot <= 0:
        raise DefinednessAnalysisError("max_states_per_slot must be positive")
    materialized = list(rows)
    for index, row in enumerate(materialized):
        if not isinstance(row, Mapping):
            raise DefinednessAnalysisError(f"transfer {index} must be an object")
    canonical = _canonical_json(materialized).encode("ascii")
    canonical_sha256 = hashlib.sha256(canonical).hexdigest()
    source_sha256 = canonical_sha256 if source_sha256 is None else source_sha256
    if not _is_sha256(source_sha256):
        raise DefinednessAnalysisError("source_sha256 must be a lowercase SHA-256")

    nodes, nodes_by_rva, duplicate_ids, duplicate_rvas = _build_nodes(materialized)
    occurrences = _collect_occurrences(materialized)
    by_id: dict[str, list[_Occurrence]] = {}
    by_slot: dict[int, set[str]] = {}
    for occurrence in occurrences:
        by_id.setdefault(occurrence.undefined_id, []).append(occurrence)
        by_slot.setdefault(occurrence.slot, set()).add(occurrence.undefined_id)

    slots: list[dict[str, Any]] = []
    classes: Counter[str] = Counter()
    for undefined_id in sorted(by_id, key=lambda value: (_stable_slot(value), value.encode())):
        grouped = sorted(
            by_id[undefined_id],
            key=lambda item: (item.transfer_id, -1 if item.rva_start is None else item.rva_start, item.pointer),
        )
        result = _analyze_slot(
            undefined_id,
            grouped,
            nodes=nodes,
            nodes_by_rva=nodes_by_rva,
            duplicate_ids=duplicate_ids,
            duplicate_rvas=duplicate_rvas,
            slot_collision=len(by_slot[grouped[0].slot]) != 1,
            max_states=max_states_per_slot,
        )
        classes[result["classification"]] += 1
        slots.append(
            {
                "slot": grouped[0].slot,
                "undefined_id": undefined_id,
                "ops": sorted({item.op for item in grouped}),
                "reasons": sorted({item.reason for item in grouped if item.reason is not None}),
                "occurrences": [item.payload() for item in grouped],
                **result,
            }
        )

    body: dict[str, Any] = {
        "format": DEFINEDNESS_EVIDENCE_FORMAT,
        "status": "complete",
        "proof_authority": False,
        "source_sha256": source_sha256,
        "canonical_transfers_sha256": canonical_sha256,
        "analysis_profile": {
            "tracked_state": ["registers", "flags"],
            "observations": ["branch_guards", "call_arguments_and_footprints", "memory_expressions", "faults", "returns", "termination"],
            "cycle_rule": "finite_dependency_graph_fixed_point",
            "max_states_per_slot": max_states_per_slot,
        },
        "counts": {
            "transfers": len(materialized),
            "reachable_transfers": sum(row.get("reachable") is True for row in materialized),
            "undefined_occurrences": len(occurrences),
            "undefined_slots": len(slots),
            "proved_unobserved_slots": classes["unconstrained_noninterfering"],
            "conditionally_unobserved_slots": classes[
                "unconstrained_conditionally_noninterfering"
            ],
            "synchronized_behavior_relevant_slots": classes[
                "synchronized_behavior_relevant"
            ],
            "lean_certifiable_slots": len(slots) - classes["unknown"],
            "unknown_slots": classes["unknown"],
        },
        "slots": slots,
    }
    body["evidence_sha256"] = hashlib.sha256(_canonical_json(body).encode("ascii")).hexdigest()
    return body


def _analyze_slot(
    undefined_id: str,
    occurrences: Sequence[_Occurrence],
    *,
    nodes: Mapping[str, _Node],
    nodes_by_rva: Mapping[int, _Node],
    duplicate_ids: set[str],
    duplicate_rvas: set[int],
    slot_collision: bool,
    max_states: int,
) -> dict[str, Any]:
    blockers: list[dict[str, Any]] = []
    source_ids = sorted({item.transfer_id for item in occurrences})
    if any(not item.explicit_id for item in occurrences):
        blockers.append(_blocker("missing_stable_id", "undefined expression has no explicit stable id", source_ids[:1], nodes))
    if slot_collision:
        blockers.append(_blocker("stable_slot_collision", "distinct undefined ids map to the same 32-bit slot", source_ids[:1], nodes))
    if len({item.op for item in occurrences}) != 1:
        blockers.append(_blocker("inconsistent_undefined_kind", "one undefined id is used as both bitvector and flag", source_ids[:1], nodes))
    for source_id in source_ids:
        if source_id in duplicate_ids:
            blockers.append(_blocker("ambiguous_transfer_identity", "undefined source transfer id is duplicated", [source_id], nodes))
            continue
        node = nodes.get(source_id)
        if node is None or node.rva_start is None:
            blockers.append(_blocker("incomplete_source_identity", "undefined source has no unique id and RVA", [source_id], nodes))
        elif node.rva_start in duplicate_rvas:
            blockers.append(_blocker("ambiguous_source_rva", "undefined source RVA names multiple transfers", [source_id], nodes))
        elif (issue := _schema_issue(node.row)) is not None:
            blockers.append(_blocker("unsupported_transfer_schema", issue, [source_id], nodes))
        elif node.row.get("reachable") is not True:
            blockers.append(_blocker("incomplete_source_reachability", "undefined source is not explicitly reachable", [source_id], nodes))

    graph: dict[str, Any] | None = None
    obligations: list[dict[str, Any]] = []
    relevant_sites: list[dict[str, Any]] = []
    synchronized = False
    if not blockers:
        graph, blockers, obligations, relevant_sites = _build_dependency_graph(
            undefined_id,
            source_ids,
            nodes=nodes,
            nodes_by_rva=nodes_by_rva,
            duplicate_rvas=duplicate_rvas,
            max_states=max_states,
            synchronized=False,
        )
        dependency_codes = {
            "call_argument_dependency",
            "fault_dependency",
            "guard_dependency",
            "memory_expression_dependency",
            "observation_dependency",
            "return_boundary",
        }
        if blockers and any(
            item["reason_code"] in dependency_codes for item in blockers
        ):
            synchronized = True
            arbitrary_relevant_sites = relevant_sites
            graph, blockers, obligations, _ = _build_dependency_graph(
                undefined_id,
                source_ids,
                nodes=nodes,
                nodes_by_rva=nodes_by_rva,
                duplicate_rvas=duplicate_rvas,
                max_states=max_states,
                synchronized=True,
            )
            relevant_sites = arbitrary_relevant_sites
    choice_source: dict[str, Any] | None = None
    if synchronized and not blockers:
        choice_source = _related_machine_input_choice(
            undefined_id, occurrences, nodes=nodes
        )
        if choice_source is None:
            blockers.append(
                _blocker(
                    "unsupported_synchronized_choice",
                    "behavior-relevant undefined value has no checked input derivation",
                    source_ids[:1],
                    nodes,
                )
            )
    blockers = _deduplicate_blockers(blockers)
    if blockers:
        return {
            "classification": "unknown",
            "witness_policy": None,
            "choice_source": None,
            "proof_obligations": _deduplicate_payloads(obligations),
            "behavior_relevant_sites": _deduplicate_payloads(relevant_sites),
            "proof": None,
            "blocking_paths": blockers,
            "closure_requirements": _closure_requirements(blockers),
        }
    assert graph is not None
    classification = (
        "synchronized_behavior_relevant"
        if synchronized
        else (
            "unconstrained_conditionally_noninterfering"
            if obligations
            else "unconstrained_noninterfering"
        )
    )
    return {
        "classification": classification,
        "witness_policy": "synchronized" if synchronized else "zero",
        "choice_source": (
            choice_source
            if synchronized
            else {
                "format": "stage-a-definedness-choice-source-v1",
                "kind": "noninterfering_zero",
                "slot": occurrences[0].slot,
                "undefined_id": undefined_id,
                "requires_semantic_obligations": bool(obligations),
            }
        ),
        "proof_obligations": obligations,
        "behavior_relevant_sites": relevant_sites,
        "proof": {
            "kind": "finite-dependency-graph-noninterference-v2",
            "undefined_id": undefined_id,
            "policy": "synchronized" if synchronized else "arbitrary",
            "graphs": [graph],
        },
        "blocking_paths": [],
        "closure_requirements": [],
    }


def _related_machine_input_choice(
    undefined_id: str,
    occurrences: Sequence[_Occurrence],
    *,
    nodes: Mapping[str, _Node],
) -> dict[str, Any] | None:
    """Propose the reviewed IA-32 BSR zero-source destination value.

    The proposal remains untrusted metadata. Exact decode and instruction
    semantics bind the slot to the pre-instruction destination register. Any
    other behavior-relevant undefined value remains an explicit frontier.
    """

    reasons = {item.reason for item in occurrences}
    if reasons != {"bsr-zero-source"}:
        return None
    match = re.fullmatch(r"([0-9a-fA-F]+):([a-z][a-z0-9]*)", undefined_id)
    if match is None:
        return None
    instruction_rva = int(match.group(1), 16)
    destination = match.group(2)
    if destination not in _REGISTER_NAMES:
        return None
    matching_instructions: list[tuple[str, Mapping[str, Any]]] = []
    for node in nodes.values():
        instructions = node.row.get("instructions")
        if not isinstance(instructions, list):
            continue
        for instruction in instructions:
            if not isinstance(instruction, Mapping):
                continue
            if (
                instruction.get("rva") == instruction_rva
                and instruction.get("mnemonic") == "bsr"
            ):
                matching_instructions.append(("exact_bytes", instruction))
            elif (
                instruction.get("rva_start") == instruction_rva
                and instruction.get("mnemonic") == "bsr"
            ):
                matching_instructions.append(("typed_machine_ir", instruction))
    if len(matching_instructions) != 1:
        return None
    instruction_kind, instruction = matching_instructions[0]
    if instruction_kind == "exact_bytes":
        operands = instruction.get("op_str")
        encoded = instruction.get("bytes")
        if (
            not isinstance(operands, str)
            or operands.split(",", 1)[0].strip() != destination
            or not isinstance(encoded, str)
            or not re.fullmatch(r"[0-9a-f]+", encoded)
            or len(encoded) % 2
        ):
            return None
    else:
        typed_operands = instruction.get("operands")
        instruction_sha256 = instruction.get("instruction_sha256")
        if (
            not isinstance(typed_operands, list)
            or len(typed_operands) != 2
            or not isinstance(typed_operands[0], Mapping)
            or typed_operands[0].get("kind") != "register"
            or typed_operands[0].get("name") != destination
            or typed_operands[0].get("access") != "write"
            or not isinstance(instruction_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", instruction_sha256) is None
        ):
            return None
    defined_values = [item.defined_value for item in occurrences]
    if any(not isinstance(value, Mapping) for value in defined_values):
        return None
    canonical_values = {_canonical_json(value) for value in defined_values}
    if len(canonical_values) != 1:
        return None
    defined_value = defined_values[0]
    if any(
        isinstance(child, Mapping) and child.get("op") in _UNDEFINED_OPS
        for _, child in _walk_json(defined_value)
    ):
        return None
    result = {
        "format": "stage-a-definedness-choice-source-v3",
        "kind": "related_machine_input",
        "slot": occurrences[0].slot,
        "undefined_id": undefined_id,
        "profile": "ia32-bsr-zero-preserves-destination-v1",
        "instruction_rva": instruction_rva,
        "location": {"family": "register", "name": destination},
        "input_expression": defined_value,
        "input_expression_sha256": hashlib.sha256(
            _canonical_json(defined_value).encode("ascii")
        ).hexdigest(),
    }
    if instruction_kind == "exact_bytes":
        result["instruction_bytes"] = encoded
    else:
        result["format"] = "stage-a-definedness-choice-source-v4"
        result["instruction_sha256"] = instruction_sha256
        result["instruction_model"] = "sanitized_typed_machine_ir_v2"
    return result


def _build_dependency_graph(
    undefined_id: str,
    source_ids: Sequence[str],
    *,
    nodes: Mapping[str, _Node],
    nodes_by_rva: Mapping[int, _Node],
    duplicate_rvas: set[int],
    max_states: int,
    synchronized: bool,
) -> tuple[
    dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]
]:
    queue: deque[
        tuple[_Node, frozenset[_Location], tuple[int, ...], tuple[str, ...]]
    ] = deque()
    for source_id in source_ids:
        queue.append((nodes[source_id], frozenset(), (), (source_id,)))
    seen: dict[tuple[str, frozenset[_Location], tuple[int, ...]], str] = {}
    graph_nodes: list[dict[str, Any]] = []
    roots: list[str] = []
    blockers: list[dict[str, Any]] = []
    obligations: list[dict[str, Any]] = []
    relevant_sites: list[dict[str, Any]] = []
    scc_edges = 0

    while queue:
        node, live_in, frames, path = queue.popleft()
        state = (node.transfer_id, live_in, frames)
        key = _state_key(node.transfer_id, live_in, frames)
        if state in seen:
            continue
        if len(seen) >= max_states:
            blockers.append(_blocker("state_budget_exceeded", "finite dependency-state budget exhausted", path, nodes, live=live_in))
            break
        seen[state] = key
        if len(path) == 1:
            roots.append(key)

        barrier = _structural_barrier(node, path, live_in, nodes)
        if barrier is not None:
            if barrier["reason_code"] == "incomplete_transfer" and _is_replay_only_incomplete(node.row):
                obligations.append(
                    _proof_obligation(
                        "exact_replay_transfer",
                        node,
                        "/blocker",
                        str(node.row.get("blocker")),
                    )
                )
            else:
                blockers.append(barrier)
                continue

        internal_call = _single_internal_call(node.row)
        if internal_call is None:
            writes, write_obligations = _write_specs(node.row, undefined_id)
        else:
            writes = _call_entry_write_specs(internal_call, undefined_id)
            write_obligations = []
        obligations.extend(
            _attach_obligation(node, item) for item in write_obligations
        )
        live_out = _live_after(live_in, writes, synchronized=synchronized)
        observations, observation_obligations = _observation_specs(
            node.row,
            undefined_id,
            live_in,
            propagate_internal_call=internal_call is not None,
            observe_return=not frames,
        )
        obligations.extend(
            _attach_obligation(node, item) for item in observation_obligations
        )
        for observation in observations:
            dependency = observation["dependency"]
            if dependency.depends_on(live_in, synchronized=synchronized):
                relevant_sites.append(
                    _relevant_site(
                        node,
                        str(observation["json_pointer"]),
                        _observation_reason(str(observation["kind"])),
                    )
                )
                blockers.append(
                    _blocker(
                        _observation_reason(str(observation["kind"])),
                        f"{observation['kind']} depends on the undefined value",
                        path,
                        nodes,
                        live=live_in,
                    )
                )

        outcome = node.row["outcome"]
        assert isinstance(outcome, Mapping)
        kind = str(outcome.get("kind", ""))
        next_frames = frames
        if internal_call is not None:
            edges, edge_blocker = _internal_call_successor_specs(
                node,
                internal_call,
                path,
                nodes,
                nodes_by_rva,
                duplicate_rvas,
                live_in,
            )
            return_rva = internal_call.get("return_rva")
            assert isinstance(return_rva, int) and not isinstance(return_rva, bool)
            next_frames = (*frames, return_rva)
        elif kind in _RETURN_KINDS and frames:
            return_rva = frames[-1]
            target = nodes_by_rva.get(return_rva)
            if target is None:
                edges = []
                edge_blocker = _blocker(
                    "missing_cfg_target",
                    "internal return continuation is absent from transfer inventory",
                    path,
                    nodes,
                    live=live_in,
                    target_rva=return_rva,
                )
            else:
                edges = [
                    {
                        "target": target,
                        "target_rva": return_rva,
                        "guard": _Dependency(),
                        "json_pointer": "/outcome",
                    }
                ]
                edge_blocker = None
                next_frames = frames[:-1]
        else:
            edges, edge_blocker = _successor_specs(
                node,
                undefined_id,
                path,
                nodes,
                nodes_by_rva,
                duplicate_rvas,
                live_in,
            )
        if edge_blocker is not None:
            blockers.append(edge_blocker)
            edges = []
        for edge in edges:
            dependency = edge["guard"]
            if dependency.depends_on(live_in, synchronized=synchronized):
                relevant_sites.append(
                    _relevant_site(
                        node,
                        str(edge["json_pointer"]),
                        "guard_dependency",
                    )
                )
                blockers.append(_blocker("guard_dependency", "a feasible CFG guard depends on the undefined value", path, nodes, live=live_in, target_rva=edge["target_rva"]))

        terminal = "none"
        if kind in _RETURN_KINDS and not frames:
            terminal = "return"
            if live_out:
                obligations.append(
                    _proof_obligation(
                        "return_continuation_noninterference",
                        node,
                        "/outcome",
                        "the exact caller continuation must not observe live return-state locations: "
                        + ", ".join(
                            f"{item.family}:{item.name}" for item in sorted(live_out)
                        ),
                    )
                )
        elif kind in _TERMINATION_KINDS:
            terminal = "terminate"
        elif "indirect" in kind and live_out:
            blockers.append(_blocker("indirect_control", "live undefined state reaches unresolved indirect control", path, nodes, live=live_out))

        edge_payloads: list[dict[str, Any]] = []
        for edge in edges:
            target = edge.get("target")
            successor_key = ""
            if isinstance(target, _Node):
                successor_key = _state_key(
                    target.transfer_id, live_out, next_frames
                )
                if live_out:
                    target_state = (target.transfer_id, live_out, next_frames)
                    if target_state in seen:
                        scc_edges += 1
                    else:
                        queue.append(
                            (
                                target,
                                live_out,
                                next_frames,
                                (*path, target.transfer_id),
                            )
                        )
            edge_payloads.append(
                {
                    "successor": successor_key,
                    "target_rva": edge["target_rva"],
                    "guard": edge["guard"].payload(),
                }
            )

        graph_nodes.append(
            {
                "key": key,
                "transfer_id": node.transfer_id,
                "rva_start": node.rva_start,
                "live_in": [item.payload() for item in sorted(live_in)],
                "live_out": [item.payload() for item in sorted(live_out)],
                "writes": [
                    {"target": target.payload(), "dependency": dependency.payload()}
                    for target, dependency in writes
                ],
                "observations": [
                    {
                        "kind": item["kind"],
                        "json_pointer": item["json_pointer"],
                        "dependency": item["dependency"].payload(),
                    }
                    for item in observations
                ],
                "edges": edge_payloads,
                "terminal": terminal,
            }
        )

    return {
        "roots": sorted(set(roots)),
        "nodes": sorted(graph_nodes, key=lambda item: item["key"]),
        "fixed_point": {
            "states": len(seen),
            "scc_back_edges": scc_edges,
            "complete": not blockers,
        },
    }, blockers, _deduplicate_payloads(obligations), _deduplicate_payloads(relevant_sites)


def _write_specs(
    row: Mapping[str, Any], undefined_id: str
) -> tuple[list[tuple[_Location, _Dependency]], list[dict[str, Any]]]:
    result: list[tuple[_Location, _Dependency]] = []
    obligations: list[dict[str, Any]] = []
    fault_dominated = bool(row.get("faults"))
    for field, family, key, allowed in (
        ("register_writes", "register", "register", _REGISTER_NAMES),
        ("flag_writes", "flag", "flag", _FLAG_NAMES),
    ):
        raw_writes = row.get(field)
        if not isinstance(raw_writes, list):
            continue
        for index, write in enumerate(raw_writes):
            if not isinstance(write, Mapping):
                continue
            name = write.get(key)
            if isinstance(name, str) and name in allowed and "value" in write:
                value = write["value"]
                suppress_fault = fault_dominated and _contains_undefined_reason(
                    value, undefined_id, "idiv_fault"
                )
                result.append(
                    (
                        _Location(family, name),
                        _expression_dependency(
                            value,
                            undefined_id,
                            suppress_fault_placeholder=suppress_fault,
                        ),
                    )
                )
                if suppress_fault:
                    obligations.append(
                        {
                            "kind": "fault_dominance",
                            "json_pointer": f"/{field}/{index}/value",
                            "detail": (
                                "exact fault semantics must prove the idiv fault "
                                "placeholder is unreachable on the normal successor"
                            ),
                        }
                    )
    return result, obligations


def _single_internal_call(row: Mapping[str, Any]) -> Mapping[str, Any] | None:
    events = [
        event
        for event in row.get("external_events", [])
        if isinstance(event, Mapping) and event.get("kind") == "internal_call"
    ]
    return events[0] if len(events) == 1 else None


def _call_entry_write_specs(
    event: Mapping[str, Any], undefined_id: str
) -> list[tuple[_Location, _Dependency]]:
    result: list[tuple[_Location, _Dependency]] = []
    registers = event.get("register_inputs")
    if isinstance(registers, Mapping):
        for name in sorted(_REGISTER_NAMES):
            if name in registers:
                result.append(
                    (
                        _Location("register", name),
                        _expression_dependency(registers[name], undefined_id),
                    )
                )
    flags = event.get("flag_inputs")
    if isinstance(flags, Mapping):
        for name in sorted(_FLAG_NAMES):
            if name in flags:
                result.append(
                    (
                        _Location("flag", name),
                        _expression_dependency(flags[name], undefined_id),
                    )
                )
    return result


def _live_after(
    live: frozenset[_Location],
    writes: Sequence[tuple[_Location, _Dependency]],
    *,
    synchronized: bool,
) -> frozenset[_Location]:
    result = set(live)
    for target, dependency in writes:
        if dependency.depends_on(live, synchronized=synchronized):
            result.add(target)
        else:
            result.discard(target)
    return frozenset(result)


def _observation_specs(
    row: Mapping[str, Any],
    undefined_id: str,
    live: frozenset[_Location],
    *,
    propagate_internal_call: bool,
    observe_return: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result: list[dict[str, Any]] = []
    obligations: list[dict[str, Any]] = []
    for index, event in enumerate(row.get("memory_events", [])):
        if not isinstance(event, Mapping):
            continue
        values = [event.get("address"), event.get("width")]
        if event.get("kind") == "write":
            values.append(event.get("value"))
        result.append(
            {
                "kind": f"memory_{event.get('kind', 'event')}:{index}",
                "json_pointer": f"/memory_events/{index}",
                "dependency": _values_dependency(values, undefined_id),
            }
        )
    for index, event in enumerate(row.get("external_events", [])):
        if isinstance(event, Mapping):
            relevant = _call_observable_dependency(event, undefined_id)
            result.append(
                {
                    "kind": f"call:{event.get('kind', 'external')}:{index}",
                    "json_pointer": f"/external_events/{index}",
                    "dependency": relevant,
                }
            )
            snapshot = _values_dependency(
                [event.get("register_inputs"), event.get("flag_inputs")],
                undefined_id,
            )
            if (
                not propagate_internal_call
                and snapshot.depends_on(live)
                and not relevant.depends_on(live)
            ):
                obligations.append(
                    {
                        "kind": "call_frame_noninterference",
                        "json_pointer": f"/external_events/{index}",
                        "detail": (
                            "exact callee/import semantics must prove omitted "
                            "register/flag snapshot state is not an ABI argument"
                        ),
                    }
                )
    for index, fault in enumerate(row.get("faults", [])):
        if isinstance(fault, Mapping):
            result.append(
                {
                    "kind": f"fault:{index}",
                    "json_pointer": f"/faults/{index}",
                    "dependency": _expression_dependency(fault, undefined_id),
                }
            )
    outcome = row.get("outcome")
    if isinstance(outcome, Mapping):
        kind = str(outcome.get("kind", ""))
        if kind == "branch":
            result.append(
                {
                    "kind": "branch_outcome",
                    "json_pointer": "/outcome/condition",
                    "dependency": _expression_dependency(
                        outcome.get("condition"), undefined_id
                    ),
                }
            )
        elif kind in _RETURN_KINDS and observe_return:
            result.append(
                {
                    "kind": "return_observation",
                    "json_pointer": "/outcome",
                    "dependency": _expression_dependency(outcome, undefined_id),
                }
            )
        elif kind in _TERMINATION_KINDS:
            result.append(
                {
                    "kind": "termination_observation",
                    "json_pointer": "/outcome",
                    "dependency": _expression_dependency(outcome, undefined_id),
                }
            )
        elif "indirect" in kind:
            result.append(
                {
                    "kind": "indirect_target",
                    "json_pointer": "/outcome",
                    "dependency": _expression_dependency(outcome, undefined_id),
                }
            )
    return result, obligations


def _internal_call_successor_specs(
    node: _Node,
    event: Mapping[str, Any],
    path: Sequence[str],
    nodes: Mapping[str, _Node],
    nodes_by_rva: Mapping[int, _Node],
    duplicate_rvas: set[int],
    live: frozenset[_Location],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    target = event.get("target_rva")
    return_rva = event.get("return_rva")
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in (target, return_rva)
    ):
        return [], _blocker(
            "missing_direct_target",
            "internal call has no concrete target and return RVA",
            path,
            nodes,
            live=live,
        )
    assert isinstance(target, int)
    if target in duplicate_rvas:
        return [], _blocker(
            "ambiguous_cfg_target",
            "internal call target RVA names multiple transfers",
            path,
            nodes,
            live=live,
            target_rva=target,
        )
    match = nodes_by_rva.get(target)
    if match is None:
        return [], _blocker(
            "missing_cfg_target",
            "internal call target is absent from transfer inventory",
            path,
            nodes,
            live=live,
            target_rva=target,
        )
    return [
        {
            "target": match,
            "target_rva": target,
            "guard": _Dependency(),
            "json_pointer": "/external_events/0/target_rva",
        }
    ], None


def _successor_specs(
    node: _Node,
    undefined_id: str,
    path: Sequence[str],
    nodes: Mapping[str, _Node],
    nodes_by_rva: Mapping[int, _Node],
    duplicate_rvas: set[int],
    live: frozenset[_Location],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    outcome = node.row.get("outcome")
    assert isinstance(outcome, Mapping)
    kind = outcome.get("kind")
    if kind in _RETURN_KINDS or kind in _TERMINATION_KINDS or "indirect" in str(kind):
        return [], None
    raw: list[tuple[int | None, Any]]
    if kind == "branch":
        condition = outcome.get("condition")
        raw = [
            (outcome.get("true_target_rva"), condition),
            (outcome.get("false_target_rva"), {"op": "not", "args": [condition]}),
        ]
    elif kind in {"fallthrough", "jump"}:
        raw = [(outcome.get("target_rva"), {"op": "true"})]
    else:
        return [], _blocker("unsupported_control", f"unsupported outcome {kind!r}", path, nodes, live=live)

    conditions = node.row.get("edge_conditions")
    if not isinstance(conditions, list):
        return [], _blocker("unsupported_transfer_schema", "edge_conditions must be a list", path, nodes, live=live)
    submitted = [edge.get("target_rva") for edge in conditions if isinstance(edge, Mapping)]
    expected = [target for target, _ in raw]
    if Counter(submitted) != Counter(expected):
        return [], _blocker("ambiguous_direct_edges", "submitted edges do not match decoded outcome targets", path, nodes, live=live)
    result: list[dict[str, Any]] = []
    for target, fallback_guard in raw:
        if isinstance(target, bool) or not isinstance(target, int):
            return [], _blocker("missing_direct_target", "direct outcome has no concrete target RVA", path, nodes, live=live)
        if target in duplicate_rvas:
            return [], _blocker("ambiguous_cfg_target", "target RVA names multiple transfers", path, nodes, live=live, target_rva=target)
        match = nodes_by_rva.get(target)
        if match is None:
            return [], _blocker("missing_cfg_target", "target RVA is absent from transfer inventory", path, nodes, live=live, target_rva=target)
        submitted_index = next(
            (
                index
                for index, edge in enumerate(conditions)
                if isinstance(edge, Mapping) and edge.get("target_rva") == target
            ),
            None,
        )
        submitted_edge = (
            conditions[submitted_index] if submitted_index is not None else None
        )
        guard = submitted_edge.get("condition") if isinstance(submitted_edge, Mapping) else fallback_guard
        result.append(
            {
                "target": match,
                "target_rva": target,
                "guard": _expression_dependency(guard, undefined_id),
                "json_pointer": (
                    f"/edge_conditions/{submitted_index}/condition"
                    if submitted_index is not None
                    else "/outcome"
                ),
            }
        )
    return result, None


def _call_observable_dependency(
    event: Mapping[str, Any], undefined_id: str
) -> _Dependency:
    """Extract the machine ABI surface, excluding full-state snapshots.

    register_inputs and flag_inputs preserve extraction context for exact call
    proofs. They are not themselves API arguments or trace observations.
    """

    observable_keys = (
        "arguments",
        "stack_inputs",
        "register_arguments",
        "read_footprints",
        "write_footprints",
        "memory_reads",
        "memory_writes",
        "callback_target",
        "callback_targets",
        "target",
        "target_expression",
    )
    return _values_dependency(
        [event.get(key) for key in observable_keys], undefined_id
    )


def _expression_dependency(
    value: Any,
    undefined_id: str,
    *,
    suppress_fault_placeholder: bool = False,
) -> _Dependency:
    if isinstance(value, list):
        result = _Dependency()
        for item in value:
            result = result.merge(
                _expression_dependency(
                    item,
                    undefined_id,
                    suppress_fault_placeholder=suppress_fault_placeholder,
                )
            )
        return result
    if not isinstance(value, Mapping):
        return _Dependency()
    op = value.get("op")
    if op in _UNDEFINED_OPS:
        if (
            suppress_fault_placeholder
            and value.get("id") == undefined_id
            and value.get("reason") == "idiv_fault"
        ):
            return _Dependency()
        return _Dependency(slot=value.get("id") == undefined_id)
    if op == "reg" and value.get("name") in _REGISTER_NAMES:
        return _Dependency(frozenset({_Location("register", str(value["name"]))}))
    if op == "flag" and value.get("name") in _FLAG_NAMES:
        return _Dependency(frozenset({_Location("flag", str(value["name"]))}))
    if op == "ite":
        args = value.get("args")
        if isinstance(args, list) and len(args) == 3:
            condition = _constant(args[0])
            if condition is True:
                return _expression_dependency(
                    args[0],
                    undefined_id,
                    suppress_fault_placeholder=suppress_fault_placeholder,
                ).merge(
                    _expression_dependency(
                        args[1],
                        undefined_id,
                        suppress_fault_placeholder=suppress_fault_placeholder,
                    )
                )
            if condition is False:
                return _expression_dependency(
                    args[0],
                    undefined_id,
                    suppress_fault_placeholder=suppress_fault_placeholder,
                ).merge(
                    _expression_dependency(
                        args[2],
                        undefined_id,
                        suppress_fault_placeholder=suppress_fault_placeholder,
                    )
                )
    result = _Dependency()
    for key, child in value.items():
        if key in {"op", "id", "reason", "name", "register", "flag", "kind", "dll", "symbol", "effect_model", "input_model"}:
            continue
        result = result.merge(
            _expression_dependency(
                child,
                undefined_id,
                suppress_fault_placeholder=suppress_fault_placeholder,
            )
        )
    return result


def _values_dependency(values: Iterable[Any], undefined_id: str) -> _Dependency:
    result = _Dependency()
    for value in values:
        result = result.merge(_expression_dependency(value, undefined_id))
    return result


def _contains_undefined_reason(
    value: Any, undefined_id: str, reason: str
) -> bool:
    return any(
        isinstance(child, Mapping)
        and child.get("op") in _UNDEFINED_OPS
        and child.get("id") == undefined_id
        and child.get("reason") == reason
        for _, child in _walk_json(value)
    )


def _constant(value: Any) -> int | bool | None:
    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op == "true":
        return True
    if op == "false":
        return False
    if op == "const" and isinstance(value.get("value"), int) and not isinstance(value.get("value"), bool):
        return int(value["value"])
    args = value.get("args")
    if not isinstance(args, list):
        return None
    constants = [_constant(arg) for arg in args]
    if op in {"eq", "eq_bool"} and len(constants) == 2 and None not in constants:
        return constants[0] == constants[1]
    if op == "ult32" and len(constants) == 2 and all(isinstance(item, int) and not isinstance(item, bool) for item in constants):
        return (int(constants[0]) & 0xFFFFFFFF) < (int(constants[1]) & 0xFFFFFFFF)
    if op == "not" and len(constants) == 1 and isinstance(constants[0], bool):
        return not constants[0]
    if op in {"and_bool", "or_bool"} and constants and all(isinstance(item, bool) for item in constants):
        return all(constants) if op == "and_bool" else any(constants)
    if op == "ite" and len(args) == 3 and isinstance(constants[0], bool):
        return constants[1] if constants[0] else constants[2]
    if len(constants) == 2 and all(isinstance(item, int) and not isinstance(item, bool) for item in constants):
        left, right = int(constants[0]), int(constants[1])
        if op in {"add32", "sub32", "and32", "or32", "xor32", "shl32", "lshr32"}:
            operations = {
                "add32": lambda: left + right,
                "sub32": lambda: left - right,
                "and32": lambda: left & right,
                "or32": lambda: left | right,
                "xor32": lambda: left ^ right,
                "shl32": lambda: left << (right & 31),
                "lshr32": lambda: (left & 0xFFFFFFFF) >> (right & 31),
            }
            return operations[str(op)]() & 0xFFFFFFFF
    return None


def _structural_barrier(node: _Node, path: Sequence[str], live: frozenset[_Location], nodes: Mapping[str, _Node]) -> dict[str, Any] | None:
    if (issue := _schema_issue(node.row)) is not None:
        return _blocker("unsupported_transfer_schema", issue, path, nodes, live=live)
    if node.row.get("reachable") is not True:
        return _blocker("incomplete_reachability", "traversed transfer is not explicitly reachable", path, nodes, live=live)
    if node.row.get("blocker") is not None or node.row.get("status") in {"blocked", "incomplete"}:
        return _blocker("incomplete_transfer", "traversed transfer carries an unresolved blocker", path, nodes, live=live)
    if _has_ambiguous_state_writes(node.row):
        return _blocker("ambiguous_state_writes", "transfer writes one location more than once", path, nodes, live=live)
    return None


def _observation_reason(kind: str) -> str:
    if kind.startswith("memory_"):
        return "memory_expression_dependency"
    if kind.startswith("call:"):
        return "call_argument_dependency"
    if kind.startswith("fault:"):
        return "fault_dependency"
    if kind == "branch_outcome":
        return "guard_dependency"
    return "observation_dependency"


def _build_nodes(rows: Sequence[Mapping[str, Any]]) -> tuple[dict[str, _Node], dict[int, _Node], set[str], set[int]]:
    id_counts: Counter[str] = Counter()
    rva_counts: Counter[int] = Counter()
    preliminary: list[_Node] = []
    for index, row in enumerate(rows):
        raw_id = row.get("id")
        transfer_id = raw_id if isinstance(raw_id, str) and raw_id else f"<row:{index}>"
        rva = _rva_start(row)
        id_counts[transfer_id] += 1
        if rva is not None:
            rva_counts[rva] += 1
        preliminary.append(_Node(transfer_id, rva, row))
    duplicate_ids = {key for key, count in id_counts.items() if count != 1}
    duplicate_rvas = {key for key, count in rva_counts.items() if count != 1}
    nodes = {node.transfer_id: node for node in preliminary if node.transfer_id not in duplicate_ids}
    nodes_by_rva = {node.rva_start: node for node in nodes.values() if node.rva_start is not None and node.rva_start not in duplicate_rvas}
    return nodes, nodes_by_rva, duplicate_ids, duplicate_rvas


def _collect_occurrences(rows: Sequence[Mapping[str, Any]]) -> list[_Occurrence]:
    result: list[_Occurrence] = []
    for row_index, row in enumerate(rows):
        raw_id = row.get("id")
        transfer_id = raw_id if isinstance(raw_id, str) and raw_id else f"<row:{row_index}>"
        for path, value in _walk_json(row):
            if not isinstance(value, Mapping) or value.get("op") not in _UNDEFINED_OPS:
                continue
            raw_undefined_id = value.get("id")
            explicit = isinstance(raw_undefined_id, str) and bool(raw_undefined_id)
            pointer = _json_pointer(path)
            op = str(value["op"])
            undefined_id = str(raw_undefined_id) if explicit else f"missing-id:{transfer_id}:{pointer}:{op}"
            reason = value.get("reason")
            result.append(
                _Occurrence(
                    undefined_id,
                    explicit,
                    _stable_slot(undefined_id),
                    op,
                    reason if isinstance(reason, str) else None,
                    transfer_id,
                    _rva_start(row),
                    pointer,
                    value.get("defined_value"),
                )
            )
    return result


def _has_ambiguous_state_writes(row: Mapping[str, Any]) -> bool:
    seen: set[_Location] = set()
    writes, _ = _write_specs(row, "<none>")
    for target, _ in writes:
        if target in seen:
            return True
        seen.add(target)
    return False


def _schema_issue(row: Mapping[str, Any]) -> str | None:
    if row.get("format") != _TRANSFER_FORMAT:
        return f"transfer format must be {_TRANSFER_FORMAT}"
    if row.get("expression_model") != _EXPRESSION_MODEL:
        return f"expression model must be {_EXPRESSION_MODEL}"
    for field in ("register_writes", "flag_writes", "memory_events", "external_events", "ordered_events", "faults", "edge_conditions"):
        if not isinstance(row.get(field), list):
            return f"{field} must be a complete list"
    if not isinstance(row.get("outcome"), Mapping):
        return "outcome must be an object"
    if _rva_start(row) is None:
        return "original.rva_start must be a nonnegative integer"
    return None


def _state_key(
    transfer_id: str,
    live: Iterable[_Location],
    frames: Sequence[int] = (),
) -> str:
    suffix = ",".join(f"{item.family}:{item.name}" for item in sorted(live))
    frame_suffix = ",".join(f"{value:x}" for value in frames)
    return f"{transfer_id}|{suffix}|frames:{frame_suffix}"


def _is_replay_only_incomplete(row: Mapping[str, Any]) -> bool:
    return row.get("blocker_category") == (
        "x87_physical_state_requires_native_exact_command_replay"
    )


def _proof_obligation(
    kind: str, node: _Node, json_pointer: str, detail: str
) -> dict[str, Any]:
    return {
        "kind": kind,
        "transfer_id": node.transfer_id,
        "rva_start": node.rva_start,
        "json_pointer": json_pointer,
        "detail": detail,
    }


def _attach_obligation(
    node: _Node, item: Mapping[str, Any]
) -> dict[str, Any]:
    return _proof_obligation(
        str(item.get("kind")),
        node,
        str(item.get("json_pointer", "")),
        str(item.get("detail", "")),
    )


def _relevant_site(
    node: _Node, json_pointer: str, category: str
) -> dict[str, Any]:
    return {
        "transfer_id": node.transfer_id,
        "rva_start": node.rva_start,
        "json_pointer": json_pointer,
        "category": category,
    }


def _deduplicate_payloads(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical_json(item): item for item in items}
    return [unique[key] for key in sorted(unique)]


def _blocker(reason_code: str, detail: str, path: Sequence[str], nodes: Mapping[str, _Node], *, live: Iterable[_Location] = (), target_rva: int | None = None) -> dict[str, Any]:
    return {
        "reason_code": reason_code,
        "detail": detail,
        "counterexample_path": [{"transfer_id": transfer_id, "rva_start": nodes[transfer_id].rva_start if transfer_id in nodes else None} for transfer_id in path],
        "live_locations": [item.payload() for item in sorted(live)],
        "target_rva": target_rva,
    }


def _deduplicate_blockers(blockers: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical_json(item): item for item in blockers}
    return [unique[key] for key in sorted(unique)]


def _closure_requirements(blockers: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    codes = sorted({str(item.get("reason_code")) for item in blockers})
    return [{"reason_code": code, "required_evidence": list(_CLOSURE_REQUIREMENTS.get(code, ("a reviewed Lean rule for this boundary",)))} for code in codes]


def _rva_start(row: Mapping[str, Any]) -> int | None:
    original = row.get("original")
    value = original.get("rva_start") if isinstance(original, Mapping) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _walk_json(value: Any) -> Iterable[tuple[tuple[str | int, ...], Any]]:
    stack: list[tuple[tuple[str | int, ...], Any]] = [((), value)]
    while stack:
        path, current = stack.pop()
        yield path, current
        if isinstance(current, Mapping):
            for key in sorted(current, reverse=True):
                stack.append(((*path, str(key)), current[key]))
        elif isinstance(current, list):
            for index in range(len(current) - 1, -1, -1):
                stack.append(((*path, index), current[index]))


def _json_pointer(path: Sequence[str | int]) -> str:
    return "" if not path else "/" + "/".join(str(item).replace("~", "~0").replace("/", "~1") for item in path)


def _stable_slot(value: str) -> int:
    result = 2166136261
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


__all__ = ["DEFINEDNESS_EVIDENCE_FORMAT", "DefinednessAnalysisError", "analyze_definedness_jsonl", "analyze_definedness_rows"]
