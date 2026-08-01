#!/usr/bin/env python3
"""Emit GNU stack/dynamic authorities from a cached mixed-original projection."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from spaghetti_extractor.relational.lean import (
    nullable_code_pointer_rooted_unreachability as rooted_unreachability,
)
from spaghetti_extractor.relational.lean.original_indirect_control_authority import (
    OriginalIndirectControlAuthorityBinding,
)
from spaghetti_extractor.relational.lean.original_stack_dynamic_control_closure import (
    DynamicCallbackAuthorityHint,
    OriginalStackDynamicControlClosureSpec,
    StackCarryAuthorityHint,
    plan_original_stack_dynamic_control_closure,
    write_original_stack_dynamic_control_closure,
)
from spaghetti_extractor.relational.lean.runtime_value_carry import (
    BINDING_MODULE as RUNTIME_VALUE_CARRY_BINDING_MODULE,
    STRUCTURE_MODULE as RUNTIME_VALUE_CARRY_STRUCTURE_MODULE,
    write_runtime_value_carry_lean,
)
from spaghetti_extractor.relational.lean.scanner import (
    OriginalDecodedScannerRegionProposal,
    OriginalScannerExecutionProposal,
)
from spaghetti_extractor.relational.lean.stack_dynamic_indirect_control import (
    analyze_stack_dynamic_indirect_controls,
    write_stack_dynamic_indirect_control,
)
from spaghetti_extractor.relational.original_cutpoint_graph_ir import (
    OriginalCutpointGraphIR,
    canonical_original_cutpoint_graph_sha256,
    load_original_cutpoint_graph_ir,
)
from spaghetti_extractor.relational.runtime_value_carry_ir import (
    RuntimeValueCarryIR,
    RuntimeValueCarryRoute,
    RuntimeValueFact,
    RuntimeValueLeanTerm,
    RuntimeValueLocation,
    RuntimeValueOrigin,
    RuntimeValueTransfer,
    validate_runtime_value_carry_ir,
)
from spaghetti_extractor.relational.stack_dynamic_control_ir import (
    load_stack_dynamic_control_input,
)
from spaghetti_extractor.util import sha256_file, write_json


class RootedUnreachabilityDriverError(ValueError):
    """Canonical graph evidence cannot support one rooted certificate."""


COMBINED_EVIDENCE_MODULE = (
    "GeneratedRelationalGNUHelloStackDynamicCombinedEvidence"
)
COMBINED_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-stack-dynamic-combined-evidence-v1"
)
COMBINED_EVIDENCE_REPORT = (
    "gnu-hello-stack-dynamic-combined-evidence.json"
)


@dataclass(frozen=True)
class _CombinedEvidencePlan:
    stack_site_index: int
    constructor_site_index: int
    dynamic_site_index: int
    stack_source_target_id: int
    stack_continuation_target_id: int
    stack_target_id: int
    stack_route_index: int
    stack_call_frame_transfer_index: int
    constructor_source_target_id: int
    constructor_table_rva: int
    constructor_branch_target_ids: tuple[int, ...]
    constructor_decoded_outcomes: tuple[tuple[int, tuple[int, ...]], ...]
    dynamic_source_target_id: int
    dynamic_head_rva: int
    entry_target_id: int
    tls_target_ids: tuple[int, int]
    dynamic_branch_target_ids: tuple[int, ...]
    dynamic_decoded_outcomes: tuple[tuple[int, tuple[int, ...]], ...]
    registration_target_ids: tuple[int, int]
    registration_writer_target_ids: tuple[int, int]
    zero_writer_target_id: int


@dataclass(frozen=True)
class _RootedUnreachabilityAuthority:
    site_index: int
    stable_id: str
    source_target_id: int
    instruction_rva: int
    module: str
    namespace: str
    definition_name: str
    original_context_name: str
    empty_indexed_authority_name: str
    root_target_ids: tuple[int, ...]
    root_path_target_ids: tuple[int, ...]
    forward_target_ids: tuple[int, ...]
    scc_target_ids: tuple[int, ...]
    incoming_edges: tuple[rooted_unreachability.OriginalIncomingEdgeProposal, ...]
    scanner_execution: OriginalScannerExecutionProposal

    @property
    def authority_name(self) -> str:
        return f"{self.namespace}.{self.definition_name}Authority"

    @property
    def premise_name(self) -> str:
        return f"{self.namespace}.{self.definition_name}ExecutionAuthority"

    @property
    def source_uninhabited_name(self) -> str:
        return f"{self.namespace}.{self.definition_name}SourceExcluded"

    @property
    def closure_name(self) -> str:
        return f"{self.namespace}.{self.definition_name}SccExclusion"

    def to_json(self) -> dict[str, Any]:
        return {
            "authority_term": self.premise_name,
            "graph_authority_term": self.authority_name,
            "closure_term": self.closure_name,
            "definition_name": self.definition_name,
            "empty_indexed_authority_term": (
                self.empty_indexed_authority_name
            ),
            "incoming_edges": [
                {
                    "source_target_id": edge.source_target_id,
                    "target_target_id": edge.target_target_id,
                }
                for edge in self.incoming_edges
            ],
            "instruction_rva": self.instruction_rva,
            "module": self.module,
            "namespace": self.namespace,
            "original_context_term": self.original_context_name,
            "premise_term": self.premise_name,
            "premise_type": "CheckedRootedScannerSccExecution",
            "forward_target_ids": list(self.forward_target_ids),
            "root_path_target_ids": list(self.root_path_target_ids),
            "root_target_ids": list(self.root_target_ids),
            "scc_target_ids": list(self.scc_target_ids),
            "scanner_execution": {
                "selector_target_id": (
                    self.scanner_execution.selector_region.target_id
                ),
                "zero_target_id": (
                    self.scanner_execution.zero_region.target_id
                ),
                "scanner_target_id": (
                    self.scanner_execution.scanner_region.target_id
                ),
                "bridge_target_id": (
                    self.scanner_execution.bridge_region.target_id
                ),
                "gate_target_id": (
                    self.scanner_execution.gate_region.target_id
                ),
                "dispatch_bridge_target_id": (
                    None
                    if self.scanner_execution.dispatch_bridge_region is None
                    else self.scanner_execution.dispatch_bridge_region.target_id
                ),
                "dispatch_bypass_target_id": (
                    self.scanner_execution.dispatch_bypass_target_id
                ),
                "count_register": self.scanner_execution.count_register,
                "table_base": self.scanner_execution.table_base,
            },
            "source_target_id": self.source_target_id,
            "source_uninhabited_term": self.source_uninhabited_name,
            "stable_id": self.stable_id,
            "status": "lean-checked-execution-exclusion",
        }


def _manifest(
    out: Path,
    inputs: Mapping[str, Path],
    **extra: Any,
) -> None:
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-relational-phase-v1",
            "phase": "mixed-original-stack-dynamic-authority-lean",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                role: {"path": path.name, "sha256": sha256_file(path)}
                for role, path in sorted(inputs.items())
            },
            **extra,
        },
    )


def _canonical_regions(
    graph: OriginalCutpointGraphIR,
) -> dict[int, Any]:
    regions = {
        region.target_id: region
        for region in graph.regions
    }
    if len(regions) != len(graph.regions):
        raise RootedUnreachabilityDriverError(
            "canonical cutpoint graph has ambiguous target IDs"
        )
    return regions


def _require_canonical_edge(
    graph: OriginalCutpointGraphIR,
    source_target_id: int,
    target_target_id: int,
    *,
    context: str,
) -> rooted_unreachability.OriginalIncomingEdgeProposal:
    matching_edges = [
        edge
        for edge in graph.edges
        if edge.source_target_id == source_target_id
        and edge.target_target_id == target_target_id
        and edge.transition_role != "dataflow"
    ]
    if len(matching_edges) != 1:
        raise RootedUnreachabilityDriverError(
            f"{context} edge {source_target_id}->{target_target_id} has no "
            "unique canonical transition record"
        )
    return rooted_unreachability.OriginalIncomingEdgeProposal(
        source_target_id,
        target_target_id,
    )


def _reachable_from(
    regions: Mapping[int, Any],
    starts: tuple[int, ...],
) -> set[int]:
    reached = set(starts)
    pending = list(starts)
    while pending:
        source_target_id = pending.pop(0)
        region = regions.get(source_target_id)
        if region is None:
            raise RootedUnreachabilityDriverError(
                f"reachable target {source_target_id} is absent from the graph"
            )
        for target_target_id in region.successor_target_ids:
            if target_target_id not in regions:
                raise RootedUnreachabilityDriverError(
                    f"successor target {target_target_id} is absent from the graph"
                )
            if target_target_id not in reached:
                reached.add(target_target_id)
                pending.append(target_target_id)
    return reached


def _shortest_root_path(
    graph: OriginalCutpointGraphIR,
    regions: Mapping[int, Any],
    source_target_id: int,
) -> tuple[int, ...]:
    predecessors: dict[int, int | None] = {
        root_target_id: None
        for root_target_id in graph.root_target_ids
    }
    pending = list(graph.root_target_ids)
    while pending and source_target_id not in predecessors:
        predecessor = pending.pop(0)
        for target_target_id in regions[predecessor].successor_target_ids:
            if target_target_id not in predecessors:
                predecessors[target_target_id] = predecessor
                pending.append(target_target_id)
    if source_target_id not in predecessors:
        raise RootedUnreachabilityDriverError(
            f"dispatch source {source_target_id} is absent from rooted closure"
        )
    path: list[int] = []
    cursor: int | None = source_target_id
    while cursor is not None:
        path.append(cursor)
        cursor = predecessors[cursor]
    path.reverse()
    for edge_index, (edge_source, edge_target) in enumerate(
        zip(path, path[1:])
    ):
        _require_canonical_edge(
            graph,
            edge_source,
            edge_target,
            context=f"root path edge {edge_index}",
        )
    return tuple(path)


def _rooted_dispatch_graph(
    graph: OriginalCutpointGraphIR,
    dispatch_target_id: int,
) -> tuple[
    tuple[int, ...],
    tuple[int, ...],
    tuple[int, ...],
    tuple[rooted_unreachability.OriginalIncomingEdgeProposal, ...],
]:
    """Recover the exact rooted path and maximal source SCC."""

    regions = _canonical_regions(graph)
    if dispatch_target_id not in regions:
        raise RootedUnreachabilityDriverError(
            f"dispatch source {dispatch_target_id} is absent from the graph"
        )
    root_path = _shortest_root_path(
        graph, regions, dispatch_target_id
    )
    forward = _reachable_from(regions, (dispatch_target_id,))
    scc_target_ids = tuple(
        target_id
        for target_id in sorted(forward)
        if dispatch_target_id
        in _reachable_from(regions, (target_id,))
    )
    if dispatch_target_id not in scc_target_ids:
        raise RootedUnreachabilityDriverError(
            "dispatch source is absent from its computed SCC"
        )
    if any(target_id in graph.root_target_ids for target_id in scc_target_ids):
        raise RootedUnreachabilityDriverError(
            "dispatch SCC unexpectedly contains a declared root"
        )
    incoming_edges: list[
        rooted_unreachability.OriginalIncomingEdgeProposal
    ] = []
    for target_target_id in scc_target_ids:
        for region in graph.regions:
            if target_target_id in region.successor_target_ids:
                incoming_edges.append(_require_canonical_edge(
                    graph,
                    region.target_id,
                    target_target_id,
                    context="SCC incoming inventory",
                ))
    return (
        root_path,
        tuple(sorted(forward)),
        scc_target_ids,
        tuple(incoming_edges),
    )


def _scanner_region_proposal(
    region: Any,
) -> OriginalDecodedScannerRegionProposal:
    return OriginalDecodedScannerRegionProposal(
        target_id=region.target_id,
        rva=region.rva,
        size=region.size,
    )


def _semantic_transfers_by_rva(
    state_machine: Path,
) -> Mapping[int, Mapping[str, Any]]:
    rows: dict[int, Mapping[str, Any]] = {}
    with state_machine.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise RootedUnreachabilityDriverError(
                    f"state-machine line {line_number} is invalid JSON"
                ) from error
            if not isinstance(row, Mapping):
                raise RootedUnreachabilityDriverError(
                    f"state-machine line {line_number} is not an object"
                )
            original = row.get("original")
            rva = (
                original.get("rva_start")
                if isinstance(original, Mapping)
                else None
            )
            if (
                not isinstance(rva, int)
                or isinstance(rva, bool)
                or not 0 <= rva < 2**32
            ):
                raise RootedUnreachabilityDriverError(
                    f"state-machine line {line_number} has no PE32 start RVA"
                )
            if rva in rows:
                raise RootedUnreachabilityDriverError(
                    f"state-machine start RVA 0x{rva:x} is duplicated"
                )
            rows[rva] = row
    return rows


def _semantic_register_writes(
    semantic_transfers: Mapping[int, Mapping[str, Any]],
    region: Any,
) -> Mapping[str, Mapping[str, Any]]:
    row = semantic_transfers.get(region.rva)
    if row is None:
        raise RootedUnreachabilityDriverError(
            f"scanner region 0x{region.rva:x} has no semantic transfer"
        )
    raw_writes = row.get("register_writes")
    if not isinstance(raw_writes, list):
        raise RootedUnreachabilityDriverError(
            f"scanner region 0x{region.rva:x} has no register-write inventory"
        )
    writes: dict[str, Mapping[str, Any]] = {}
    for index, raw_write in enumerate(raw_writes):
        if not isinstance(raw_write, Mapping):
            raise RootedUnreachabilityDriverError(
                f"scanner region 0x{region.rva:x} register write {index} "
                "is malformed"
            )
        register = raw_write.get("register")
        value = raw_write.get("value")
        if (
            not isinstance(register, str)
            or not isinstance(value, Mapping)
            or register in writes
        ):
            raise RootedUnreachabilityDriverError(
                f"scanner region 0x{region.rva:x} has ambiguous register writes"
            )
        writes[register] = value
    return writes


def _semantic_register(
    name: str,
) -> dict[str, Any]:
    return {"name": name, "op": "reg", "width": 32}


def _semantic_constant(value: int) -> dict[str, Any]:
    return {"op": "const", "value": value, "width": 32}


def _rooted_scanner_execution(
    graph: OriginalCutpointGraphIR,
    site: Any,
    scc_target_ids: tuple[int, ...],
    incoming_edges: tuple[
        rooted_unreachability.OriginalIncomingEdgeProposal, ...
    ],
    semantic_transfers: Mapping[int, Mapping[str, Any]],
) -> OriginalScannerExecutionProposal:
    """Recover the untrusted scanner binding from canonical graph shape.

    Lean independently decodes every proposed span and rejects any register or
    transfer mismatch. This routine only chooses fixture identities.
    """

    regions = _canonical_regions(graph)
    source_target_id = site.finding.source_target_id
    outside_incoming = [
        edge
        for edge in incoming_edges
        if edge.source_target_id not in scc_target_ids
    ]
    if (
        len(outside_incoming) != 1
        or outside_incoming[0].target_target_id != source_target_id
    ):
        raise RootedUnreachabilityDriverError(
            "nullable dispatch SCC must have one outside gate edge"
        )
    dispatch_predecessor = regions[outside_incoming[0].source_target_id]
    dispatch_bridge = None
    if tuple(dispatch_predecessor.successor_target_ids) == (source_target_id,):
        dispatch_bridge = dispatch_predecessor
        bridge_predecessors = [
            region
            for region in graph.regions
            if dispatch_bridge.target_id in region.successor_target_ids
        ]
        if len(bridge_predecessors) != 1:
            raise RootedUnreachabilityDriverError(
                "nullable dispatch bridge has no unique gate predecessor"
            )
        gate = bridge_predecessors[0]
    else:
        gate = dispatch_predecessor
    gate_successors = set(gate.successor_target_ids)
    dispatch_entry_target_id = (
        source_target_id
        if dispatch_bridge is None
        else dispatch_bridge.target_id
    )
    if (
        dispatch_entry_target_id not in gate_successors
        or len(gate_successors) != 2
    ):
        raise RootedUnreachabilityDriverError(
            "nullable dispatch gate must have source and bypass successors"
        )
    bypass_target_id = next(
        target_id
        for target_id in gate_successors
        if target_id != dispatch_entry_target_id
    )

    gate_predecessors = [
        region
        for region in graph.regions
        if gate.target_id in region.successor_target_ids
    ]
    selectors = [
        region
        for region in gate_predecessors
        if len(set(region.successor_target_ids)) == 2
        and gate.target_id in region.successor_target_ids
    ]
    bridges = [
        region
        for region in gate_predecessors
        if tuple(region.successor_target_ids) == (gate.target_id,)
    ]
    if len(selectors) != 1 or len(bridges) != 1:
        raise RootedUnreachabilityDriverError(
            "nullable dispatch has no unique selector and scanner bridge"
        )
    selector = selectors[0]
    bridge = bridges[0]
    zero_target_ids = [
        target_id
        for target_id in selector.successor_target_ids
        if target_id != gate.target_id
    ]
    if len(zero_target_ids) != 1:
        raise RootedUnreachabilityDriverError(
            "nullable selector has no unique zeroing successor"
        )
    zero = regions[zero_target_ids[0]]
    if len(set(zero.successor_target_ids)) != 1:
        raise RootedUnreachabilityDriverError(
            "nullable zeroing block has no unique scanner successor"
        )
    scanner = regions[zero.successor_target_ids[0]]
    if set(scanner.successor_target_ids) != {
        scanner.target_id,
        bridge.target_id,
    }:
        raise RootedUnreachabilityDriverError(
            "nullable scanner does not have exact loop and bridge successors"
        )

    facts = site.finding.static_facts
    table_base = facts.get("table_base_va")
    count_register = facts.get("index_register")
    if (
        isinstance(table_base, bool)
        or not isinstance(table_base, int)
        or not 0 <= table_base < 2**32
        or not isinstance(count_register, str)
    ):
        raise RootedUnreachabilityDriverError(
            "nullable scanner table or count-register binding is malformed"
        )

    selector_writes = _semantic_register_writes(
        semantic_transfers, selector
    )
    selector_count = selector_writes.get(count_register)
    if selector_count != {
        "address": _semantic_constant(table_base),
        "op": "load",
        "width": 4,
    }:
        raise RootedUnreachabilityDriverError(
            "nullable selector does not load the table header into the count "
            "register"
        )

    zero_writes = _semantic_register_writes(semantic_transfers, zero)
    scanner_registers = [
        register
        for register, value in zero_writes.items()
        if value == _semantic_constant(0)
    ]
    if len(scanner_registers) != 1:
        raise RootedUnreachabilityDriverError(
            "nullable zeroing block has no unique zeroed cursor register"
        )
    scanner_register = scanner_registers[0]

    scanner_writes = _semantic_register_writes(
        semantic_transfers, scanner
    )
    scanner_increment = scanner_writes.get(scanner_register)
    increment_arguments = (
        scanner_increment.get("args")
        if isinstance(scanner_increment, Mapping)
        else None
    )
    if (
        not isinstance(scanner_increment, Mapping)
        or scanner_increment.get("op") != "add32"
        or not isinstance(increment_arguments, list)
        or len(increment_arguments) != 2
        or _semantic_register(scanner_register) not in increment_arguments
        or _semantic_constant(1) not in increment_arguments
        or scanner_writes.get(count_register)
        != _semantic_register(scanner_register)
    ):
        raise RootedUnreachabilityDriverError(
            "nullable scanner has no exact cursor increment/count copy"
        )
    loaded_registers = [
        register
        for register, value in scanner_writes.items()
        if value.get("op") == "load" and value.get("width") == 4
    ]
    if len(loaded_registers) != 1:
        raise RootedUnreachabilityDriverError(
            "nullable scanner has no unique loaded-word register"
        )
    loaded_register = loaded_registers[0]

    return OriginalScannerExecutionProposal(
        table_base=table_base,
        scanner_register=scanner_register,
        count_register=count_register,
        loaded_register=loaded_register,
        selector_region=_scanner_region_proposal(selector),
        zero_region=_scanner_region_proposal(zero),
        scanner_region=_scanner_region_proposal(scanner),
        bridge_region=_scanner_region_proposal(bridge),
        gate_region=_scanner_region_proposal(gate),
        dispatch_source_target_id=source_target_id,
        dispatch_bypass_target_id=bypass_target_id,
        dispatch_bridge_region=(
            None
            if dispatch_bridge is None
            else _scanner_region_proposal(dispatch_bridge)
        ),
    )


def _checked_empty_indexed_site(site: Any, site_index: int) -> None:
    if site.closure_mode != "empty_indexed_source":
        raise RootedUnreachabilityDriverError(
            f"site {site_index} is not an empty indexed source"
        )
    if site.allowed_target_ids:
        raise RootedUnreachabilityDriverError(
            f"empty indexed site {site_index} submits nonempty targets"
        )
    finding = site.finding
    table = finding.indexed_empty_table
    facts = finding.static_facts
    if table is None or not isinstance(facts, Mapping):
        raise RootedUnreachabilityDriverError(
            f"empty indexed site {site_index} has no exact table evidence"
        )
    if (
        table.address_scale != 4
        or table.header_words != (2**32 - 1,)
        or facts.get("word_0") != 2**32 - 1
        or facts.get("word_1") != 0
        or facts.get("checked_empty_interval_candidate") is not True
    ):
        raise RootedUnreachabilityDriverError(
            f"empty indexed site {site_index} is not the exact PE32 "
            "reverse-sentinel empty table"
        )


def _rooted_unreachability_authorities(
    *,
    out: Path,
    closure: Any,
    graph: OriginalCutpointGraphIR,
    semantic_transfers: Mapping[int, Mapping[str, Any]],
) -> tuple[
    tuple[_RootedUnreachabilityAuthority, ...],
    Path,
    Mapping[str, Mapping[str, int | str]],
]:
    roots = graph.root_target_ids
    if not roots or tuple(sorted(set(roots))) != roots:
        raise RootedUnreachabilityDriverError(
            "canonical cutpoint roots are empty, duplicated, or unordered"
        )
    regions = {
        region.target_id: region
        for region in graph.regions
    }
    if len(regions) != len(graph.regions):
        raise RootedUnreachabilityDriverError(
            "canonical cutpoint graph has ambiguous target IDs"
        )
    if any(
        target_id not in regions or not regions[target_id].root
        for target_id in roots
    ):
        raise RootedUnreachabilityDriverError(
            "canonical root names or region flags are inconsistent"
        )
    declared_roots = tuple(
        region.target_id for region in graph.regions if region.root
    )
    if declared_roots != roots:
        raise RootedUnreachabilityDriverError(
            "canonical root inventory is incomplete or ambiguous"
        )

    authorities: list[_RootedUnreachabilityAuthority] = []
    resources: dict[str, Mapping[str, int | str]] = {}
    stable_ids: set[str] = set()
    for site_index, site in enumerate(closure.sites):
        if site.closure_mode != "empty_indexed_source":
            continue
        _checked_empty_indexed_site(site, site_index)
        finding = site.finding
        if (
            not isinstance(finding.stable_id, str)
            or not finding.stable_id
        ):
            raise RootedUnreachabilityDriverError(
                f"empty indexed site {site_index} has no stable name"
            )
        if finding.stable_id in stable_ids:
            raise RootedUnreachabilityDriverError(
                "empty indexed sites have an ambiguous stable name: "
                f"{finding.stable_id}"
            )
        stable_ids.add(finding.stable_id)
        (
            root_path_target_ids,
            forward_target_ids,
            scc_target_ids,
            incoming_edges,
        ) = _rooted_dispatch_graph(
            graph, finding.source_target_id
        )
        scanner_execution = _rooted_scanner_execution(
            graph,
            site,
            scc_target_ids,
            incoming_edges,
            semantic_transfers,
        )
        module_stem = (
            "GeneratedRelationalNullableCodePointerRootedUnreachability"
            f"{site_index}"
        )
        module = f"StageA.{module_stem}"
        namespace = (
            "StageA.Generated.RelationalNullableCodePointer"
            f"RootedUnreachability.Site{site_index}"
        )
        definition_name = (
            "generatedNullableCodePointerRootedUnreachability"
            f"{site_index}"
        )
        closure_prefix = (
            "StageA.GeneratedRelational."
            "OriginalStackDynamicControlClosure."
            f"generatedOriginalStackDynamicClosure{site_index}"
        )
        empty_indexed_authority_name = (
            f"{closure_prefix}EmptyIndexedAuthority"
        )
        authority = _RootedUnreachabilityAuthority(
            site_index=site_index,
            stable_id=finding.stable_id,
            source_target_id=finding.source_target_id,
            instruction_rva=finding.instruction_rva,
            module=module,
            namespace=namespace,
            definition_name=definition_name,
            original_context_name=(
                "StageA.GeneratedRelational."
                "InterpreterMixedOriginalBase.generatedOriginalStaticContext"
            ),
            empty_indexed_authority_name=empty_indexed_authority_name,
            root_target_ids=roots,
            root_path_target_ids=root_path_target_ids,
            forward_target_ids=forward_target_ids,
            scc_target_ids=scc_target_ids,
            incoming_edges=incoming_edges,
            scanner_execution=scanner_execution,
        )
        spec = rooted_unreachability.NullableCodePointerRootedUnreachabilitySpec(
            definition_name=authority.definition_name,
            original_context_name=authority.original_context_name,
            empty_indexed_authority_name=(
                authority.empty_indexed_authority_name
            ),
            root_target_ids=authority.root_target_ids,
            root_path_target_ids=authority.root_path_target_ids,
            forward_target_ids=authority.forward_target_ids,
            scc_target_ids=authority.scc_target_ids,
            incoming_edges=authority.incoming_edges,
            scanner_execution=authority.scanner_execution,
            namespace=authority.namespace,
            imports=(
                "StageA."
                "GeneratedRelationalInterpreterMixedOriginalBaseCarrierData",
                "StageA."
                "GeneratedRelationalOriginalStackDynamicControlClosure",
            ),
        )
        rooted_unreachability.write_nullable_code_pointer_rooted_unreachability_module(
            out / "StageA" / f"{module_stem}.lean",
            spec,
        )
        resources[module_stem] = {
            "resource_class": "large-memory",
            "estimated_memory_mb": 8192,
        }
        authorities.append(authority)

    report_path = (
        out / "nullable-code-pointer-rooted-unreachability.json"
    )
    payload = {
        "format": (
            rooted_unreachability
            .NULLABLE_CODE_POINTER_ROOTED_UNREACHABILITY_FORMAT
        ),
        "artifact_role": {
            "acceptance_authority": False,
            "graph_facts_rechecked_by_lean": True,
            "report_status_closes_obligations": False,
        },
        "inputs": {
            "cutpoint_graph_content_sha256": (
                canonical_original_cutpoint_graph_sha256(graph)
            ),
            "original_pe_sha256": graph.original_pe_sha256,
            "state_machine_sha256": graph.state_machine_sha256,
        },
        "entries": [authority.to_json() for authority in authorities],
        "status": (
            "lean-checked-execution-exclusion"
            if authorities
            else "not-applicable"
        ),
    }
    write_json(report_path, payload)
    return tuple(authorities), report_path, resources


def _runtime_frontiers(
    closure: Any,
    rooted_authorities: tuple[_RootedUnreachabilityAuthority, ...] = (),
) -> list[dict[str, Any]]:
    rooted_by_site = {
        authority.site_index: authority
        for authority in rooted_authorities
    }
    frontiers: list[dict[str, Any]] = []
    for site_index, site in enumerate(closure.sites):
        authority = rooted_by_site.get(site_index)
        if site.closure_mode == "empty_indexed_source" and authority is not None:
            frontiers.append({
                "authority_term": authority.premise_name,
                "graph_authority_term": authority.authority_name,
                "closure_term": authority.closure_name,
                "closure_mode": site.closure_mode,
                "empty_indexed_authority_term": (
                    authority.empty_indexed_authority_name
                ),
                "instruction_rva": site.finding.instruction_rva,
                "premise_term": authority.premise_name,
                "premise_type": "CheckedRootedScannerSccExecution",
                "stable_id": site.finding.stable_id,
            })
        else:
            frontiers.append({
                "stable_id": site.finding.stable_id,
                "instruction_rva": site.finding.instruction_rva,
                "premise_type": site.premise_type,
                "closure_mode": site.closure_mode,
            })
    return frontiers


def _target_id_by_rva(plan: Any, rva: object, context: str) -> int:
    if (
        not isinstance(rva, int)
        or isinstance(rva, bool)
        or not 0 <= rva < 2**32
    ):
        raise ValueError(f"{context} is not a PE32 RVA")
    matches = [
        region.target_id for region in plan.regions if region.rva == rva
    ]
    if len(matches) != 1:
        raise ValueError(f"{context} has no unique canonical code target")
    return matches[0]


def _closure_spec(
    plan: Any,
    hints_path: Path,
    original_sha256: str,
) -> OriginalStackDynamicControlClosureSpec:
    hints = json.loads(hints_path.read_text(encoding="utf-8"))
    if (
        not isinstance(hints, Mapping)
        or hints.get("format")
        != "stage-a-stack-dynamic-closure-hints-v2"
        or hints.get("original_sha256") != original_sha256
    ):
        raise ValueError(
            "stack/dynamic hints have the wrong format or original identity"
        )
    stack_rows = hints.get("stack_hints")
    dynamic_rows = hints.get("dynamic_hints")
    if not isinstance(stack_rows, list) or not isinstance(dynamic_rows, list):
        raise ValueError("stack/dynamic hints must contain both hint lists")

    stack_hints: list[StackCarryAuthorityHint] = []
    for index, row in enumerate(stack_rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"stack hint {index} is not an object")
        stable_id = row.get("stable_id")
        slot_rva = row.get("seed_slot_rva")
        if (
            not isinstance(stable_id, str)
            or not isinstance(slot_rva, int)
            or isinstance(slot_rva, bool)
        ):
            raise ValueError(f"stack hint {index} is malformed")
        stack_hints.append(StackCarryAuthorityHint(
            stable_id=stable_id,
            seed_slot_rva=slot_rva,
            seed_target_id=_target_id_by_rva(
                plan,
                row.get("seed_target_rva"),
                f"stack hint {index} seed target",
            ),
        ))

    dynamic_hints: list[DynamicCallbackAuthorityHint] = []
    for index, row in enumerate(dynamic_rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"dynamic hint {index} is not an object")
        stable_id = row.get("stable_id")
        mode = row.get("mode")
        allowed_rvas = row.get("allowed_target_rvas")
        if (
            not isinstance(stable_id, str)
            or mode not in {"finite_callbacks", "source_uninhabited"}
            or not isinstance(allowed_rvas, list)
        ):
            raise ValueError(f"dynamic hint {index} is malformed")
        dynamic_hints.append(DynamicCallbackAuthorityHint(
            stable_id=stable_id,
            mode=mode,
            allowed_target_ids=tuple(
                _target_id_by_rva(
                    plan,
                    rva,
                    f"dynamic hint {index} target",
                )
                for rva in allowed_rvas
            ),
        ))
    return OriginalStackDynamicControlClosureSpec(
        stack_hints=tuple(stack_hints),
        dynamic_hints=tuple(dynamic_hints),
    )


def _kernel_check_for_term(
    *,
    out: Path,
    term: Mapping[str, str],
    kernel_checks: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    if kernel_checks is None:
        return None
    module = term["module"]
    source = out / "StageA" / (
        module.removeprefix("StageA.").replace(".", "/") + ".lean"
    )
    row = kernel_checks.get(module)
    if not source.is_file() or not isinstance(row, Mapping):
        return None
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    olean_sha256 = row.get("olean_sha256")
    if (
        row.get("status") != "checked"
        or row.get("source_sha256") != source_sha256
        or row.get("term") != dict(term)
        or not isinstance(olean_sha256, str)
        or len(olean_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in olean_sha256
        )
    ):
        return None
    return {
        "module": module,
        "olean_sha256": olean_sha256,
        "source_sha256": source_sha256,
        "status": "checked",
        "term": dict(term),
    }


def _stack_adjustment_from_address(
    expression: Mapping[str, Any],
    *,
    source_rva: int,
) -> tuple[str, int]:
    """Return the normalized ESP-relative address used by Lean semantics."""

    if expression.get("op") == "reg" and expression.get("name") == "esp":
        return ("identity", 0)
    if expression.get("op") not in {"add32", "sub32"}:
        raise ValueError(
            f"stack call source 0x{source_rva:x} has a non-ESP-relative write"
        )
    arguments = expression.get("args")
    if not isinstance(arguments, list) or len(arguments) != 2:
        raise ValueError(
            f"stack call source 0x{source_rva:x} has a malformed write address"
        )
    register_rows = [
        item
        for item in arguments
        if isinstance(item, Mapping)
        and item.get("op") == "reg"
        and item.get("name") == "esp"
    ]
    constant_rows = [
        item
        for item in arguments
        if isinstance(item, Mapping)
        and item.get("op") == "const"
        and isinstance(item.get("value"), int)
        and not isinstance(item.get("value"), bool)
    ]
    if len(register_rows) != 1 or len(constant_rows) != 1:
        raise ValueError(
            f"stack call source 0x{source_rva:x} has a non-affine ESP write"
        )
    amount = int(constant_rows[0]["value"]) % (1 << 32)
    if expression["op"] == "sub32":
        if arguments[0] != register_rows[0]:
            raise ValueError(
                f"stack call source 0x{source_rva:x} subtracts ESP from a value"
            )
        amount = (-amount) % (1 << 32)
    return ("identity", 0) if amount == 0 else ("add", amount)


def _stack_call_write_adjustments(
    state_machine: Path,
    *,
    source_rva: int,
) -> tuple[tuple[str, int], ...]:
    """Recover the complete normalized write-address inventory for one call."""

    matched: Mapping[str, Any] | None = None
    with state_machine.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"state-machine line {line_number} is invalid JSON"
                ) from error
            if not isinstance(row, Mapping):
                raise ValueError(
                    f"state-machine line {line_number} is not an object"
                )
            original = row.get("original")
            if (
                isinstance(original, Mapping)
                and original.get("rva_start") == source_rva
            ):
                if matched is not None:
                    raise ValueError(
                        f"stack call source 0x{source_rva:x} is duplicated"
                    )
                matched = row
    if matched is None:
        raise ValueError(
            f"stack call source 0x{source_rva:x} is absent from the state machine"
        )
    memory_events = matched.get("memory_events")
    instructions = matched.get("instructions")
    if not isinstance(memory_events, list) or not isinstance(
        instructions, list
    ):
        raise ValueError(
            f"stack call source 0x{source_rva:x} has no semantic inventories"
        )
    writes: list[tuple[str, int]] = []
    for event_index, event in enumerate(memory_events):
        if not isinstance(event, Mapping):
            raise ValueError(
                f"stack call source 0x{source_rva:x} memory event "
                f"{event_index} is malformed"
            )
        if event.get("kind") != "write":
            continue
        address = event.get("address")
        if not isinstance(address, Mapping) or event.get("width") != 4:
            raise ValueError(
                f"stack call source 0x{source_rva:x} has a non-word write"
            )
        writes.append(
            _stack_adjustment_from_address(address, source_rva=source_rva)
        )
    terminal_calls = [
        instruction
        for instruction in instructions
        if isinstance(instruction, Mapping)
        and instruction.get("mnemonic") == "call"
    ]
    if (
        len(terminal_calls) != 1
        or terminal_calls[0] != instructions[-1]
    ):
        raise ValueError(
            f"stack call source 0x{source_rva:x} has no unique terminal call"
        )
    # Normalized call semantics materialize the pushed return address.
    writes.append(("add", (1 << 32) - 4))
    return tuple(writes)


def _lean_stack_adjustment(adjustment: tuple[str, int]) -> str:
    kind, amount = adjustment
    if kind == "identity":
        return ".identity"
    if kind == "add":
        return f".add {amount}"
    raise ValueError(f"unsupported normalized stack adjustment {adjustment!r}")


def _stack_entry_source(
    *,
    namespace: str,
    static_term: Mapping[str, str],
    source_target_id: int,
    source_rva: int,
    source_size: int,
    continuation_target_id: int,
    callee_target_id: int,
    caller_frame_word_offset: int,
    target_address: int,
    writes: tuple[tuple[str, int], ...],
) -> str:
    authority = (
        f"{static_term['namespace']}.{static_term['symbol']}"
    )
    write_terms = ", ".join(
        _lean_stack_adjustment(adjustment) for adjustment in writes
    )
    bytes_above = caller_frame_word_offset + 4
    return f"""import StageA.RelationalRuntimeValueCarrySemantics
import StageA.GeneratedRelationalInterpreterMixedOriginalBaseCarrierData
import {static_term["module"]}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.IndirectExitAdapters
open StageA.Relational.RuntimeValueCarrySemantics

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedContext : StaticProofContext :=
  StageA.GeneratedRelational.InterpreterMixedOriginalBase.generatedOriginalCarrierContext

def generatedStaticAuthority :=
  {authority}

def generatedContinuationTarget : CodeTargetPair :=
  (generatedContext.codeMap.get? {continuation_target_id}).get
    (by decide +kernel)

def generatedCalleeTarget : CodeTargetPair :=
  (generatedContext.codeMap.get? {callee_target_id}).get
    (by decide +kernel)

def generatedSourceRegion : RegionRelation := {{
  id := {source_target_id}
  original := {{ start := {source_rva}, size := {source_size} }}
  candidate := {{ start := {source_rva}, size := {source_size} }}
  root := false
  inputs := []
  outputs := []
  inputRelations := []
  stackWindows := [{{
    rangeId := 0
    originalRegister := .esp
    candidateRegister := .esp
    bytesBelow := 0
    bytesAbove := {bytes_above}
  }}]
  predicates := [{{
    original := .equal
      (.read32 (.add (.inputReg .esp)
        (.constant {caller_frame_word_offset})))
      (.constant {target_address})
    candidate := .equal
      (.read32 (.add (.inputReg .esp)
        (.constant {caller_frame_word_offset})))
      (.constant {target_address})
  }}]
  targets := [generatedContinuationTarget, generatedCalleeTarget]
}}

def generatedBehavior : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts
    generatedContext.originalPe
    generatedContext.originalImports
    generatedContext.machineImportCallContracts
    generatedSourceRegion.original).get (by decide +kernel)

theorem generatedBehaviorDecoded :
    regionBehaviorWithMachineCallContracts
      generatedContext.originalPe
      generatedContext.originalImports
      generatedContext.machineImportCallContracts
      generatedSourceRegion.original = some generatedBehavior := by
  decide +kernel

def generatedOriginalNormalized : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false generatedSourceRegion.targets
    generatedBehavior).get (by decide +kernel)

def generatedCandidateNormalized : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior true generatedSourceRegion.targets
    generatedBehavior).get (by decide +kernel)

def generatedClaim : StackSlotFixedCodePointerIndirectCallClaim := {{
  stackRead := {{
    window := {{
      rangeId := 0
      originalRegister := .esp
      candidateRegister := .esp
      bytesBelow := 0
      bytesAbove := {bytes_above}
    }}
    adjustment := .add {caller_frame_word_offset}
  }}
  targetId := {callee_target_id}
  originalTargetAddress := {target_address}
  candidateTargetAddress := {target_address}
  continuationTargetId := {continuation_target_id}
  writes := {{
    original := [{write_terms}]
    candidate := [{write_terms}]
  }}
}}

theorem generatedClaimChecked :
    generatedClaim.checked generatedContext
      generatedSourceRegion.inputInvariant generatedOriginalNormalized
      generatedCandidateNormalized = true := by
  decide +kernel

theorem generatedGenericCertificateChecked :
    (stackFixedIndirectCertificate generatedClaim).checked generatedContext =
      true := by
  decide +kernel

def generatedIndirectExitCertificate :
    ValueProvenance.CheckedIndirectExitCertificate generatedContext
      generatedSourceRegion.inputInvariant generatedOriginalNormalized
      generatedCandidateNormalized :=
  checkedStackFiniteOriginCallEntryCertificate generatedContext
    generatedSourceRegion.inputInvariant generatedOriginalNormalized
    generatedCandidateNormalized generatedClaim generatedClaimChecked
    generatedGenericCertificateChecked

theorem generatedIndirectExitCertificateExact :
    generatedIndirectExitCertificate.certificate =
      stackFixedIndirectCertificate generatedClaim := rfl

theorem generatedStaticRouteBinding :
    generatedStaticAuthority.static.claim.site.sourceTargetId =
        {source_target_id} /\\
      generatedStaticAuthority.static.claim.seed.targetId =
        generatedClaim.targetId /\\
      generatedStaticAuthority.static.claim.site.target =
        .stackRead .esp (.add {caller_frame_word_offset}) /\\
      generatedClaim.originalTargetAddress =
        (generatedStaticAuthority.static.claim.seed.word
          StageA.GeneratedRelational.InterpreterMixedOriginalBase.generatedOriginalStaticContext).toNat := by
  decide +kernel

#print axioms generatedClaimChecked
#print axioms generatedGenericCertificateChecked
#print axioms generatedIndirectExitCertificate
#print axioms generatedStaticRouteBinding

end {namespace}
"""


def _stack_entry_authorities(
    *,
    out: Path,
    closure: Any,
    graph: OriginalCutpointGraphIR,
    hints: Mapping[str, Any],
    state_machine: Path,
    image_base: int,
    original_sha256: str,
    state_machine_sha256: str,
    kernel_checks: Mapping[str, Any] | None,
) -> tuple[Mapping[str, Any], Mapping[str, Mapping[str, Any]]]:
    route_rows = hints.get("runtime_value_carry_routes")
    if not isinstance(route_rows, list):
        raise ValueError("stack/dynamic hints have no value-carry routes")
    region_by_target = {
        region.target_id: region for region in graph.regions
    }
    entries: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    for site_index, site in enumerate(closure.sites):
        if site.closure_mode != "finite_stack_target":
            continue
        finding = site.finding
        if (
            finding.continuation_target_id is None
            or len(site.allowed_target_ids) != 1
        ):
            raise ValueError(
                "finite stack authority has no exact continuation or target"
            )
        continuation = region_by_target.get(
            finding.continuation_target_id
        )
        callee = region_by_target.get(site.allowed_target_ids[0])
        if continuation is None or callee is None:
            raise ValueError(
                "finite stack authority references an unknown code target"
            )
        matching_offsets: set[int] = set()
        for route_index, route in enumerate(route_rows):
            if not isinstance(route, Mapping):
                raise ValueError(
                    f"value-carry route {route_index} is not an object"
                )
            fact_rows = route.get("facts")
            transfer_rows = route.get("transfers")
            if not isinstance(fact_rows, list) or not isinstance(
                transfer_rows, list
            ):
                raise ValueError(
                    f"value-carry route {route_index} has invalid inventories"
                )
            locations: dict[int, tuple[str, str, int]] = {}
            for fact_index, fact in enumerate(fact_rows):
                if not isinstance(fact, Mapping):
                    raise ValueError(
                        f"value-carry route {route_index} fact "
                        f"{fact_index} is not an object"
                    )
                rva = fact.get("target_rva")
                location = fact.get("location")
                if not isinstance(rva, int) or isinstance(rva, bool):
                    raise ValueError("value-carry fact has no exact target RVA")
                if not isinstance(location, Mapping):
                    raise ValueError("value-carry fact has no location")
                kind = location.get("kind")
                register = location.get("register")
                offset = location.get("offset")
                if (
                    not isinstance(kind, str)
                    or not isinstance(register, str)
                    or not isinstance(offset, int)
                    or isinstance(offset, bool)
                ):
                    raise ValueError("value-carry fact location is invalid")
                locations[rva] = (kind, register, offset)
            for transfer in transfer_rows:
                if (
                    isinstance(transfer, Mapping)
                    and transfer.get("kind") == "call_frame_word_preserve"
                    and transfer.get("source_rva") == finding.source_rva
                    and transfer.get("target_rva") == continuation.rva
                ):
                    source_location = locations.get(finding.source_rva)
                    target_location = locations.get(continuation.rva)
                    if (
                        source_location is None
                        or source_location != target_location
                        or source_location[0:2] != ("frame_word", "esp")
                    ):
                        raise ValueError(
                            "finite stack call route does not preserve one "
                            "exact ESP frame word"
                        )
                    matching_offsets.add(source_location[2])
        if len(matching_offsets) != 1:
            raise ValueError(
                "finite stack authority has no unique value-carry frame offset"
            )
        term = {
            "module": (
                "StageA."
                "GeneratedRelationalOriginalStackDynamicControlClosure"
            ),
            "namespace": (
                "StageA.GeneratedRelational."
                "OriginalStackDynamicControlClosure"
            ),
            "symbol": (
                f"generatedOriginalStackDynamicClosure{site_index}"
                "StackAuthority"
            ),
        }
        static_kernel_check = _kernel_check_for_term(
            out=out,
            term=term,
            kernel_checks=kernel_checks,
        )
        module_name = (
            "GeneratedRelationalStackFiniteOriginCallEntry"
            f"{finding.source_target_id:08d}"
        )
        module = f"StageA.{module_name}"
        namespace = (
            "StageA.Generated.StackFiniteOriginCallEntry"
            f"{finding.source_target_id:08d}"
        )
        entry_term = {
            "module": module,
            "namespace": namespace,
            "symbol": "generatedIndirectExitCertificate",
        }
        source_region = region_by_target.get(finding.source_target_id)
        if source_region is None or source_region.rva != finding.source_rva:
            raise ValueError(
                "finite stack authority source is absent from the cutpoint graph"
            )
        writes = _stack_call_write_adjustments(
            state_machine,
            source_rva=finding.source_rva,
        )
        source = _stack_entry_source(
            namespace=namespace,
            static_term=term,
            source_target_id=finding.source_target_id,
            source_rva=finding.source_rva,
            source_size=source_region.size,
            continuation_target_id=finding.continuation_target_id,
            callee_target_id=callee.target_id,
            caller_frame_word_offset=next(iter(matching_offsets)),
            target_address=image_base + callee.rva,
            writes=writes,
        )
        source_path = out / "StageA" / f"{module_name}.lean"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(source, encoding="utf-8")
        entry_kernel_check = _kernel_check_for_term(
            out=out,
            term=entry_term,
            kernel_checks=kernel_checks,
        )
        requests.extend(({"term": term}, {"term": entry_term}))
        entries.append({
            "source_rva": finding.source_rva,
            "instruction_rva": finding.instruction_rva,
            "continuation_rva": continuation.rva,
            "source_target_id": finding.source_target_id,
            "continuation_target_id": finding.continuation_target_id,
            "callee_target_id": callee.target_id,
            "callee_rva": callee.rva,
            "caller_frame_word_offset": next(iter(matching_offsets)),
            "static_stack_authority_term": term,
            "static_stack_authority_kernel_check": (
                {
                    "module": term["module"],
                    "status": "kernel_compile_required",
                    "term": term,
                }
                if static_kernel_check is None
                else static_kernel_check
            ),
            "indirect_exit_authority_module": module,
            "indirect_exit_authority_term": entry_term,
            "indirect_exit_authority_kernel_check": (
                {
                    "module": module,
                    "status": "kernel_compile_required",
                    "term": entry_term,
                }
                if entry_kernel_check is None
                else entry_kernel_check
            ),
            "indirect_exit_certificate_exact_term": (
                f"{namespace}.generatedIndirectExitCertificateExact"
            ),
            "certificate_constructor": (
                "StageA.Relational.IndirectExitAdapters."
                "checkedStackFixedIndirectCertificate"
            ),
        })
    write_json(
        out / "kernel-check-requests.json",
        {
            "format": "stage-a-lean-kernel-check-requests-v1",
            "requests": requests,
        },
    )
    payload = {
        "format": (
            "stage-a-checked-stack-finite-origin-call-entry-authorities-v1"
        ),
        "inputs": {
            "original_sha256": original_sha256,
            "state_machine_sha256": state_machine_sha256,
        },
        "entries": entries,
        "status": (
            "checked"
            if entries
            and all(
                entry["static_stack_authority_kernel_check"]["status"]
                    == "checked"
                and entry["indirect_exit_authority_kernel_check"]["status"]
                    == "checked"
                for entry in entries
            )
            else "kernel_compile_required"
        ),
    }
    write_json(
        out / "checked-stack-finite-origin-call-entry-authorities.json",
        payload,
    )
    return payload, {
        entry["indirect_exit_authority_module"].removeprefix("StageA."): {
            "resource_class": "medium",
            "estimated_memory_mb": 4096,
        }
        for entry in entries
    }


def _runtime_value_carry_ir(
    graph: OriginalCutpointGraphIR,
    graph_path: Path,
    hints_path: Path,
    direct_call_authority: Mapping[str, Any],
    direct_call_authority_path: Path,
    stack_dynamic_authority_path: Path,
) -> RuntimeValueCarryIR:
    hints = json.loads(hints_path.read_text(encoding="utf-8"))
    if not isinstance(hints, Mapping):
        raise ValueError("stack/dynamic hints are not an object")
    route_rows = hints.get("runtime_value_carry_routes")
    if not isinstance(route_rows, list) or not route_rows:
        raise ValueError("stack/dynamic hints have no value-carry routes")

    contract_rows = direct_call_authority.get("contracts")
    if not isinstance(contract_rows, list):
        raise ValueError("direct-call authority has no contract inventory")
    calls: dict[tuple[int, int], Mapping[str, Any]] = {}
    for index, item in enumerate(contract_rows):
        if not isinstance(item, Mapping):
            raise ValueError(f"direct-call contract {index} is not an object")
        key = (
            item.get("source_target_id"),
            item.get("continuation_target_id"),
        )
        if (
            any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in key
            )
            or key in calls
        ):
            raise ValueError(
                f"direct-call contract {index} has no unique cutpoint pair"
            )
        calls[key] = item

    region_by_target = {
        region.target_id: region for region in graph.regions
    }
    routes: list[RuntimeValueCarryRoute] = []
    for route_index, item in enumerate(route_rows):
        if not isinstance(item, Mapping):
            raise ValueError(f"value-carry route {route_index} is not an object")
        fact_rows = item.get("facts")
        transfer_rows = item.get("transfers")
        if not isinstance(fact_rows, list) or not isinstance(
            transfer_rows, list
        ):
            raise ValueError(
                f"value-carry route {route_index} has invalid inventories"
            )

        location_keys: set[tuple[str, str, int]] = set()
        raw_facts: list[tuple[int, tuple[str, str, int]]] = []
        for fact_index, fact_item in enumerate(fact_rows):
            if not isinstance(fact_item, Mapping):
                raise ValueError(
                    f"value-carry route {route_index} fact {fact_index} "
                    "is not an object"
                )
            location = fact_item.get("location")
            if not isinstance(location, Mapping):
                raise ValueError(
                    f"value-carry route {route_index} fact {fact_index} "
                    "has no location"
                )
            kind = location.get("kind")
            register = location.get("register")
            offset = location.get("offset")
            if (
                kind not in {"register", "frame_word"}
                or register not in {
                    "eax", "ebx", "ecx", "edx",
                    "esi", "edi", "ebp", "esp",
                }
                or isinstance(offset, bool)
                or not isinstance(offset, int)
                or offset < 0
            ):
                raise ValueError(
                    f"value-carry route {route_index} fact {fact_index} "
                    "has an invalid location"
                )
            location_key = (kind, register, offset)
            target_id = _target_id_by_rva(
                graph,
                fact_item.get("target_rva"),
                f"value-carry route {route_index} fact {fact_index}",
            )
            location_keys.add(location_key)
            raw_facts.append((target_id, location_key))

        ordered_locations = sorted(location_keys)
        location_id = {
            location: index
            for index, location in enumerate(ordered_locations)
        }
        locations = tuple(
            RuntimeValueLocation(index, kind, register, offset)
            for index, (kind, register, offset) in enumerate(
                ordered_locations
            )
        )
        facts = tuple(sorted(
            RuntimeValueFact(target_id, location_id[location])
            for target_id, location in raw_facts
        ))
        facts_by_target: dict[int, RuntimeValueFact] = {}
        for fact in facts:
            if fact.target_id in facts_by_target:
                raise ValueError(
                    f"value-carry route {route_index} has multiple facts "
                    f"at target {fact.target_id}"
                )
            facts_by_target[fact.target_id] = fact

        pending_transfers: list[
            tuple[
                int, int, int, str, int | None, int, str, int | None,
                str, str, str | None, int | None,
                RuntimeValueLeanTerm | None, str | None, str | None,
            ]
        ] = []
        for transfer_index, transfer_item in enumerate(transfer_rows):
            if not isinstance(transfer_item, Mapping):
                raise ValueError(
                    f"value-carry route {route_index} transfer "
                    f"{transfer_index} is not an object"
                )
            source_target_id = _target_id_by_rva(
                graph,
                transfer_item.get("source_rva"),
                f"value-carry route {route_index} transfer "
                f"{transfer_index} source",
            )
            target_target_id = _target_id_by_rva(
                graph,
                transfer_item.get("target_rva"),
                f"value-carry route {route_index} transfer "
                f"{transfer_index} target",
            )
            kind = transfer_item.get("kind")
            if not isinstance(kind, str):
                raise ValueError(
                    f"value-carry route {route_index} transfer "
                    f"{transfer_index} has no kind"
                )
            target_fact = facts_by_target.get(target_target_id)
            source_fact = facts_by_target.get(source_target_id)
            if target_fact is None or (
                kind != "finite_origin_call_result" and source_fact is None
            ):
                raise ValueError(
                    f"value-carry route {route_index} transfer "
                    f"{transfer_index} has no endpoint fact"
                )
            edge_index = graph.edge_index(
                source_target_id, target_target_id
            )
            call = calls.get((source_target_id, target_target_id))
            authority_status = "checked_dependency"
            authority_contract_id: int | None = None
            if kind in {
                "finite_origin_call_result",
                "direct_call_register_preserve",
            }:
                if call is None:
                    raise ValueError(
                        f"value-carry route {route_index} transfer "
                        f"{transfer_index} has no direct-call authority"
                    )
                authority_contract_id = int(call["contract_id"])
            elif kind == "call_frame_word_preserve":
                target_location = locations[target_fact.location_id]
                preserved_offsets = (
                    call.get("preserved_caller_frame_word_offsets")
                    if call is not None
                    else None
                )
                if (
                    call is not None
                    and isinstance(preserved_offsets, list)
                    and target_location.offset in preserved_offsets
                    and call.get("remaining_semantic_premises") == []
                    and isinstance(
                        call.get(
                            "caller_frame_word_authorizing_lean_term"
                        ),
                        Mapping,
                    )
                ):
                    authority_contract_id = int(call["contract_id"])
                else:
                    authority_status = "required"
            authority_origin: str | None = None
            authority_callee_target_id: int | None = None
            authority_lean_term: RuntimeValueLeanTerm | None = None
            authority_kernel_source_sha256: str | None = None
            authority_kernel_olean_sha256: str | None = None
            if authority_contract_id is not None:
                if call is None:
                    raise ValueError(
                        f"value-carry route {route_index} transfer "
                        f"{transfer_index} lost its direct-call authority"
                    )
                term = call.get("authorizing_lean_term")
                kernel_check = call.get("kernel_check")
                if not isinstance(term, Mapping) or not isinstance(
                    kernel_check, Mapping
                ):
                    raise ValueError(
                        f"value-carry route {route_index} transfer "
                        f"{transfer_index} has no exact checked Lean authority"
                    )
                authority_origin = str(call.get("origin"))
                authority_callee_target_id = int(call["callee_target_id"])
                authority_lean_term = RuntimeValueLeanTerm(
                    module=str(term.get("module")),
                    namespace=str(term.get("namespace")),
                    symbol=str(term.get("symbol")),
                )
                authority_kernel_source_sha256 = str(
                    kernel_check.get("source_sha256")
                )
                authority_kernel_olean_sha256 = str(
                    kernel_check.get("olean_sha256")
                )
            source_region = region_by_target[source_target_id]
            if (
                source_region.semantic_contract_sha256 is None
                or source_region.instruction_bytes_sha256 is None
            ):
                raise ValueError(
                    f"value-carry route {route_index} transfer "
                    f"{transfer_index} has no source semantic identity"
                )
            pending_transfers.append((
                edge_index,
                source_target_id,
                target_target_id,
                kind,
                None if source_fact is None else source_fact.location_id,
                target_fact.location_id,
                authority_status,
                authority_contract_id,
                source_region.semantic_contract_sha256,
                source_region.instruction_bytes_sha256,
                authority_origin,
                authority_callee_target_id,
                authority_lean_term,
                authority_kernel_source_sha256,
                authority_kernel_olean_sha256,
            ))

        pending_transfers.sort(key=lambda row: (
            row[0],
            row[1],
            row[2],
            row[3],
            -1 if row[4] is None else row[4],
            row[5],
        ))
        transfers = tuple(
            RuntimeValueTransfer(
                transfer_id=index,
                edge_index=row[0],
                source_target_id=row[1],
                target_target_id=row[2],
                kind=row[3],
                source_location_id=row[4],
                target_location_id=row[5],
                authority_status=row[6],
                authority_contract_id=row[7],
                source_semantic_contract_sha256=row[8],
                source_instruction_bytes_sha256=row[9],
                authority_origin=row[10],
                authority_callee_target_id=row[11],
                authority_lean_term=row[12],
                authority_kernel_source_sha256=row[13],
                authority_kernel_olean_sha256=row[14],
            )
            for index, row in enumerate(pending_transfers)
        )
        target_id = _target_id_by_rva(
            graph,
            item.get("target_source_rva"),
            f"value-carry route {route_index} target source",
        )
        target_fact = facts_by_target.get(target_id)
        if target_fact is None:
            raise ValueError(
                f"value-carry route {route_index} has no target fact"
            )
        routes.append(RuntimeValueCarryRoute(
            stable_id=str(item.get("stable_id")),
            origin=RuntimeValueOrigin(
                "static_code_target",
                _target_id_by_rva(
                    graph,
                    item.get("origin_target_rva"),
                    f"value-carry route {route_index} origin",
                ),
            ),
            locations=locations,
            facts=facts,
            transfers=transfers,
            target_fact=target_fact,
        ))

    value = RuntimeValueCarryIR(
        original_pe_sha256=graph.original_pe_sha256,
        state_machine_sha256=graph.state_machine_sha256,
        cutpoint_graph_content_sha256=(
            canonical_original_cutpoint_graph_sha256(graph)
        ),
        cutpoint_graph_artifact_sha256=sha256_file(graph_path),
        direct_call_authority_sha256=sha256_file(
            direct_call_authority_path
        ),
        stack_dynamic_authority_sha256=sha256_file(
            stack_dynamic_authority_path
        ),
        routes=tuple(sorted(routes, key=lambda route: route.stable_id)),
    )
    return validate_runtime_value_carry_ir(
        value,
        graph=graph,
        direct_call_authority=direct_call_authority,
    )


def _region_at_rva(
    graph: OriginalCutpointGraphIR,
    rva: int,
    context: str,
) -> Any:
    matches = [region for region in graph.regions if region.rva == rva]
    if len(matches) != 1:
        raise ValueError(f"{context} has no unique canonical region at 0x{rva:x}")
    return matches[0]


def _closure_site_index(
    closure: Any,
    *,
    instruction_rva: int,
    closure_mode: str,
) -> int:
    matches = [
        index
        for index, site in enumerate(closure.sites)
        if site.finding.instruction_rva == instruction_rva
        and site.closure_mode == closure_mode
    ]
    if len(matches) != 1:
        raise ValueError(
            f"GNU hello requires one {closure_mode} site at "
            f"RVA 0x{instruction_rva:x}"
        )
    return matches[0]


def _require_semantic_block(
    semantic_transfers: Mapping[int, Mapping[str, Any]],
    *,
    rva: int,
    instruction_bytes: str,
    outcome: Mapping[str, Any],
) -> Mapping[str, Any]:
    row = semantic_transfers.get(rva)
    if row is None:
        raise ValueError(f"semantic block 0x{rva:x} is absent")
    instructions = row.get("instructions")
    if not isinstance(instructions, list) or any(
        not isinstance(instruction, Mapping) for instruction in instructions
    ):
        raise ValueError(f"semantic block 0x{rva:x} has no instruction inventory")
    actual_bytes = "".join(str(instruction.get("bytes")) for instruction in instructions)
    if actual_bytes != instruction_bytes:
        raise ValueError(
            f"semantic block 0x{rva:x} has unexpected exact instruction bytes"
        )
    actual_outcome = row.get("outcome")
    if not isinstance(actual_outcome, Mapping) or any(
        actual_outcome.get(key) != value for key, value in outcome.items()
    ):
        raise ValueError(f"semantic block 0x{rva:x} has an unexpected outcome")
    return row


def _require_exact_edge_by_rva(
    graph: OriginalCutpointGraphIR,
    source_rva: int,
    target_rva: int,
    context: str,
) -> None:
    source = _region_at_rva(graph, source_rva, f"{context} source")
    target = _region_at_rva(graph, target_rva, f"{context} target")
    _require_canonical_edge(
        graph,
        source.target_id,
        target.target_id,
        context=context,
    )


def _preferred_image_zero_word(
    original: Path,
    rva: int,
) -> None:
    import pefile

    image = pefile.PE(str(original), fast_load=True)
    try:
        section = image.get_section_by_rva(rva)
        if section is None:
            raise ValueError(f"RVA 0x{rva:x} is not mapped by the exact PE")
        offset = rva - int(section.VirtualAddress)
        mapped_size = max(
            int(section.Misc_VirtualSize),
            int(section.SizeOfRawData),
        )
        if offset < 0 or offset + 4 > mapped_size:
            raise ValueError(f"RVA 0x{rva:x} is not a complete mapped PE word")
        raw_size = int(section.SizeOfRawData)
        if offset < raw_size and image.get_data(rva, 4) != b"\x00" * 4:
            raise ValueError(f"RVA 0x{rva:x} is not launch-zero in the exact PE")
    finally:
        image.close()


def _immutable_pe_words(
    original: Path,
    rva: int,
    expected: bytes,
) -> None:
    import pefile

    image = pefile.PE(str(original), fast_load=True)
    try:
        section = image.get_section_by_rva(rva)
        if section is None or image.get_data(rva, len(expected)) != expected:
            raise ValueError(
                f"immutable table at RVA 0x{rva:x} has unexpected exact bytes"
            )
        if int(section.Characteristics) & 0x80000000:
            raise ValueError(
                f"table at RVA 0x{rva:x} is in a writable PE section"
            )
    finally:
        image.close()


def _combined_evidence_plan(
    *,
    original: Path,
    closure: Any,
    graph: OriginalCutpointGraphIR,
    semantic_transfers: Mapping[int, Mapping[str, Any]],
    runtime_value_carry: RuntimeValueCarryIR,
) -> _CombinedEvidencePlan:
    stack_site_index = _closure_site_index(
        closure,
        instruction_rva=0x203C,
        closure_mode="finite_stack_target",
    )
    constructor_site_index = _closure_site_index(
        closure,
        instruction_rva=0xA220,
        closure_mode="empty_indexed_source",
    )
    dynamic_site_index = _closure_site_index(
        closure,
        instruction_rva=0xAB8C,
        closure_mode="uninhabited_dynamic_source",
    )
    stack_site = closure.sites[stack_site_index]
    constructor_site = closure.sites[constructor_site_index]
    dynamic_site = closure.sites[dynamic_site_index]
    if len(stack_site.allowed_target_ids) != 1:
        raise ValueError("GNU hello stack site does not have one finite target")

    stack_source = _region_at_rva(graph, 0x2033, "stack source")
    stack_continuation = _region_at_rva(graph, 0x2040, "stack continuation")
    if (
        stack_site.finding.source_target_id != stack_source.target_id
        or stack_site.finding.continuation_target_id
        != stack_continuation.target_id
    ):
        raise ValueError("GNU hello stack site is not bound to its exact call edge")
    route_matches = [
        (index, route)
        for index, route in enumerate(runtime_value_carry.routes)
        if route.target_fact.target_id == stack_source.target_id
        and route.origin.target_id == stack_site.allowed_target_ids[0]
    ]
    if len(route_matches) != 1:
        raise ValueError("GNU hello stack site has no unique exact value-carry route")
    stack_route_index, stack_route = route_matches[0]
    stack_transfers = [
        (index, transfer)
        for index, transfer in enumerate(stack_route.transfers)
        if transfer.source_target_id == stack_source.target_id
        and transfer.target_target_id == stack_continuation.target_id
        and transfer.kind == "call_frame_word_preserve"
        and transfer.authority_origin
        == "checked_finite_origin_call_caller_frame_word_summary"
        and transfer.authority_status == "checked_dependency"
    ]
    if len(stack_transfers) != 1:
        raise ValueError(
            "GNU hello stack route has no unique checked finite-origin "
            "caller-frame transfer"
        )
    stack_transfer_index, _stack_transfer = stack_transfers[0]

    constructor_source = _region_at_rva(graph, 0xA220, "constructor source")
    if constructor_site.finding.source_target_id != constructor_source.target_id:
        raise ValueError("GNU hello constructor site has the wrong source target")
    constructor_path_rvas = (
        0xA200,
        0xA248,
        0xA250,
        0xA260,
        0xA20F,
        0xA22C,
        0xA220,
        0xA227,
    )
    _immutable_pe_words(
        original,
        0x280E8,
        bytes.fromhex("ffffffff00000000"),
    )
    _require_semantic_block(
        semantic_transfers,
        rva=0xA200,
        instruction_bytes="5383ec188b1de880420083fbff7439",
        outcome={
            "kind": "branch",
            "true_target_rva": 0xA248,
            "false_target_rva": 0xA20F,
        },
    )
    _require_semantic_block(
        semantic_transfers,
        rva=0xA248,
        instruction_bytes="31c08db600000000",
        outcome={"kind": "fallthrough", "target_rva": 0xA250},
    )
    _require_semantic_block(
        semantic_transfers,
        rva=0xA250,
        instruction_bytes="89c383c0018b1485e880420085d275f0",
        outcome={
            "kind": "branch",
            "true_target_rva": 0xA250,
            "false_target_rva": 0xA260,
        },
    )
    _require_semantic_block(
        semantic_transfers,
        rva=0xA260,
        instruction_bytes="ebad",
        outcome={"kind": "jump", "target_rva": 0xA20F},
    )
    _require_semantic_block(
        semantic_transfers,
        rva=0xA20F,
        instruction_bytes="85db7419",
        outcome={
            "kind": "branch",
            "true_target_rva": 0xA22C,
            "false_target_rva": 0xA213,
        },
    )
    for source_rva, target_rva in (
        (0xA200, 0xA248),
        (0xA248, 0xA250),
        (0xA250, 0xA260),
        (0xA260, 0xA20F),
        (0xA20F, 0xA22C),
    ):
        _require_exact_edge_by_rva(
            graph,
            source_rva,
            target_rva,
            "constructor immutable-word path",
        )

    dynamic_source = _region_at_rva(graph, 0xAB86, "dynamic source")
    if dynamic_site.finding.source_target_id != dynamic_source.target_id:
        raise ValueError("GNU hello dynamic site has the wrong source target")
    entry_roots = [
        region for region in graph.regions if region.root and region.rva == 0x1420
    ]
    if len(entry_roots) != 1:
        raise ValueError("GNU hello has no unique PE entry root")
    tls_regions = tuple(
        _region_at_rva(graph, rva, "TLS callback")
        for rva in (0xA2F0, 0xA2A0)
    )
    if not all(region.root for region in tls_regions):
        raise ValueError("GNU hello TLS callbacks are not exact graph roots")
    exact_roots = {entry_roots[0].target_id, *(r.target_id for r in tls_regions)}
    if set(graph.root_target_ids) != exact_roots:
        raise ValueError("GNU hello cutpoint graph has unexpected launch roots")

    _preferred_image_zero_word(original, 0x30364)
    for rva, instruction_bytes, outcome in (
        (
            0xA2A0,
            "83ec1c8b44242483f8037414",
            {
                "kind": "branch",
                "true_target_rva": 0xA2C0,
                "false_target_rva": 0xA2AC,
            },
        ),
        (
            0xA2AC,
            "85c07410",
            {
                "kind": "branch",
                "true_target_rva": 0xA2C0,
                "false_target_rva": 0xA2B0,
            },
        ),
        (
            0xA310,
            "83f801743b",
            {
                "kind": "branch",
                "true_target_rva": 0xA350,
                "false_target_rva": 0xA315,
            },
        ),
        (
            0xACD0,
            "83ec2c8b44243483f8020f84b8000000",
            {
                "kind": "branch",
                "true_target_rva": 0xAD98,
                "false_target_rva": 0xACE0,
            },
        ),
        (
            0xACE2,
            "85c07442",
            {
                "kind": "branch",
                "true_target_rva": 0xAD28,
                "false_target_rva": 0xACE6,
            },
        ),
        (
            0xAB54,
            "8b1d6403430083ec0485db7434",
            {
                "kind": "branch",
                "true_target_rva": 0xAB95,
                "false_target_rva": 0xAB61,
            },
        ),
    ):
        _require_semantic_block(
            semantic_transfers,
            rva=rva,
            instruction_bytes=instruction_bytes,
            outcome=outcome,
        )

    registration_regions = tuple(
        _region_at_rva(graph, rva, "callback-list mutator")
        for rva in (0xABB0, 0xAC30)
    )
    for region in registration_regions:
        incoming = [
            edge
            for edge in graph.edges
            if edge.target_target_id == region.target_id
            and edge.transition_role != "dataflow"
        ]
        if incoming or region.target_id in graph.reachable_target_ids or region.root:
            raise ValueError(
                "callback-list mutator is reachable in the exact launch graph"
            )
    head_address = 0x400000 + 0x30364
    writer_rvas: set[int] = set()
    for block_rva, row in semantic_transfers.items():
        memory_events = row.get("memory_events")
        if not isinstance(memory_events, list):
            raise ValueError(f"semantic block 0x{block_rva:x} has no memory events")
        for event in memory_events:
            if (
                isinstance(event, Mapping)
                and event.get("kind") == "write"
                and event.get("address") == _semantic_constant(head_address)
            ):
                writer_rvas.add(block_rva)
    if writer_rvas != {0xABF9, 0xACC0, 0xAD69}:
        raise ValueError("dynamic head has an unexpected exact static writer set")
    registration_writer_regions = tuple(
        _region_at_rva(graph, rva, "callback-list writer")
        for rva in (0xABF9, 0xACC0)
    )
    if any(
        region.target_id in graph.reachable_target_ids
        for region in registration_writer_regions
    ):
        raise ValueError("a callback-list nonzero writer is statically reachable")
    zero_writer = _region_at_rva(graph, 0xAD69, "TLS zero writer")

    dynamic_branch_rvas = (
        0xA2A0,
        0xA2AC,
        0xA2B0,
        0xA2F0,
        0xA310,
        0xA350,
        0xACD0,
        0xACE0,
        0xACE2,
        0xACE6,
        0xACFD,
        0xAB54,
        0xAB61,
        0xAB86,
        0xAB95,
    )
    return _CombinedEvidencePlan(
        stack_site_index=stack_site_index,
        constructor_site_index=constructor_site_index,
        dynamic_site_index=dynamic_site_index,
        stack_source_target_id=stack_source.target_id,
        stack_continuation_target_id=stack_continuation.target_id,
        stack_target_id=stack_site.allowed_target_ids[0],
        stack_route_index=stack_route_index,
        stack_call_frame_transfer_index=stack_transfer_index,
        constructor_source_target_id=constructor_source.target_id,
        constructor_table_rva=0x280E8,
        constructor_branch_target_ids=tuple(
            _region_at_rva(graph, rva, "constructor branch").target_id
            for rva in constructor_path_rvas
        ),
        constructor_decoded_outcomes=tuple(
            (
                _region_at_rva(graph, source_rva, "constructor outcome").target_id,
                target_rvas,
            )
            for source_rva, target_rvas in (
                (0xA200, (0xA248, 0xA20F)),
                (0xA248, (0xA250,)),
                (0xA250, (0xA250, 0xA260)),
                (0xA260, (0xA20F,)),
                (0xA20F, (0xA22C, 0xA213)),
            )
        ),
        dynamic_source_target_id=dynamic_source.target_id,
        dynamic_head_rva=0x30364,
        entry_target_id=entry_roots[0].target_id,
        tls_target_ids=(tls_regions[0].target_id, tls_regions[1].target_id),
        dynamic_branch_target_ids=tuple(
            _region_at_rva(graph, rva, "dynamic branch").target_id
            for rva in dynamic_branch_rvas
        ),
        dynamic_decoded_outcomes=tuple(
            (
                _region_at_rva(graph, source_rva, "dynamic outcome").target_id,
                target_rvas,
            )
            for source_rva, target_rvas in (
                (0xA2A0, (0xA2C0, 0xA2AC)),
                (0xA2AC, (0xA2C0, 0xA2B0)),
                (0xA310, (0xA350, 0xA315)),
                (0xACD0, (0xAD98, 0xACE0)),
                (0xACE2, (0xAD28, 0xACE6)),
                (0xAB54, (0xAB95, 0xAB61)),
            )
        ),
        registration_target_ids=(
            registration_regions[0].target_id,
            registration_regions[1].target_id,
        ),
        registration_writer_target_ids=(
            registration_writer_regions[0].target_id,
            registration_writer_regions[1].target_id,
        ),
        zero_writer_target_id=zero_writer.target_id,
    )


def _lean_target_rva_pairs(
    graph: OriginalCutpointGraphIR,
    target_ids: tuple[int, ...],
) -> str:
    regions = _canonical_regions(graph)
    return ", ".join(
        f"({target_id}, {regions[target_id].rva})" for target_id in target_ids
    )


def _lean_decoded_outcomes(
    outcomes: tuple[tuple[int, tuple[int, ...]], ...],
) -> str:
    return ", ".join(
        f"({target_id}, [{', '.join(str(rva) for rva in target_rvas)}])"
        for target_id, target_rvas in outcomes
    )


def _combined_evidence_source(
    plan: _CombinedEvidencePlan,
    graph: OriginalCutpointGraphIR,
) -> str:
    namespace = "StageA.GeneratedRelational.GNUHelloStackDynamicCombinedEvidence"
    closure_namespace = (
        "StageA.GeneratedRelational.OriginalStackDynamicControlClosure"
    )
    stack_entry_module = (
        "GeneratedRelationalStackFiniteOriginCallEntry"
        f"{plan.stack_source_target_id:08d}"
    )
    stack_entry_namespace = (
        "StageA.Generated.StackFiniteOriginCallEntry"
        f"{plan.stack_source_target_id:08d}"
    )
    constructor_pairs = _lean_target_rva_pairs(
        graph, plan.constructor_branch_target_ids
    )
    dynamic_pairs = _lean_target_rva_pairs(
        graph,
        (
            *plan.dynamic_branch_target_ids,
            *plan.registration_target_ids,
            *plan.registration_writer_target_ids,
            plan.zero_writer_target_id,
        ),
    )
    constructor_outcomes = _lean_decoded_outcomes(
        plan.constructor_decoded_outcomes
    )
    dynamic_outcomes = _lean_decoded_outcomes(plan.dynamic_decoded_outcomes)
    tls0, tls1 = plan.tls_target_ids
    table_address = 0x400000 + plan.constructor_table_rva
    head_rva = plan.dynamic_head_rva
    return f"""import StageA.RelationalOriginalCombinedExecutionInvariant
import StageA.GeneratedRelationalOriginalStackDynamicControlClosure
import StageA.GeneratedRelationalRuntimeValueCarrySemantics
import StageA.{stack_entry_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.StackDynamicIndirectControl

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedContext :=
  StageA.GeneratedRelational.InterpreterMixedOriginalBase.generatedOriginalStaticContext

def generatedCarrierContext :=
  StageA.GeneratedRelational.InterpreterMixedOriginalBase.generatedOriginalCarrierContext

def generatedStackAuthority :=
  {closure_namespace}.generatedOriginalStackDynamicClosure{plan.stack_site_index}StackAuthority

def generatedConstructorAuthority :=
  {closure_namespace}.generatedOriginalStackDynamicClosure{plan.constructor_site_index}EmptyIndexedAuthority

def generatedDynamicSite :=
  {closure_namespace}.generatedOriginalStackDynamicClosure{plan.dynamic_site_index}Site

def generatedStackCallEntryCertificate :=
  {stack_entry_namespace}.generatedIndirectExitCertificate

def generatedStackCallFrameTransferAuthority :=
  StageA.GeneratedRelational.RuntimeValueCarry.generatedRuntimeValueCarryRoute{plan.stack_route_index}Transfer{plan.stack_call_frame_transfer_index}Authority

def generatedCodeTargetRvaChecked (targetId rva : Nat) : Bool :=
  match generatedContext.codeMap.get? targetId with
  | none => false
  | some target => target.rva == rva

def generatedDecodedOutcomeTargetRvas? (targetId : Nat) : Option (List Nat) := do
  let source <- generatedContext.source? targetId
  let behavior <- regionBehaviorWithMachineCallContracts generatedContext.pe
    generatedContext.imports generatedContext.machineImportCallContracts
    source.region.span
  let outcome <- behavior.outcome
  match outcome with
  | .jump targetRva => some [targetRva]
  | .branch _ trueTargetRva falseTargetRva =>
      some [trueTargetRva, falseTargetRva]
  | _ => none

def generatedDecodedOutcomesChecked
    (expected : List (Nat × List Nat)) : Bool :=
  expected.all fun row =>
    generatedDecodedOutcomeTargetRvas? row.1 == some row.2

def generatedExactLaunchRootTargetIds : List Nat :=
  generatedContext.regions.toList.filterMap fun region =>
    if region.root then some region.id else none

def generatedTargetHasIncomingControlEdge (targetId : Nat) : Bool :=
  generatedContext.regions.toList.any fun region =>
    region.targets.contains targetId

def generatedStackRuntimeFact (world : RelationalWorld)
    (state : MachineState) : Prop :=
  StackRelocatedCodePointerRuntime generatedContext
    generatedStackAuthority.static.claim world state

def generatedStackRequirement :
    OriginalStackDynamicTargetRequirement generatedContext := {{
  site := generatedStackAuthority.static.claim.site
  allowedTargetIds := [generatedStackAuthority.static.claim.seed.targetId]
  allowedTargetsChecked := generatedStackAuthority.allowedTargetsChecked
  sourceFact := generatedStackRuntimeFact
  sourceFactResolves := by
    intro world state runtime
    obtain ⟨resolved, targetIdExact⟩ :=
      originalResolvedCodeTarget_of_checked generatedContext
        generatedStackAuthority.static.claim.site state
        generatedStackAuthority.static.claim.seed.targetId
        (generatedStackAuthority.static.claim.seed.word generatedContext)
        runtime.targetValue generatedStackAuthority.targetAddressChecked
    exact ⟨resolved, by simpa [targetIdExact]⟩
}}

def generatedConstructorRequirement :
    OriginalStackDynamicTargetRequirement generatedContext := {{
  site := generatedConstructorAuthority.site
  allowedTargetIds := []
  allowedTargetsChecked := by decide +kernel
  sourceFact := fun _world _state => False
  sourceFactResolves := by
    intro _world _state impossible
    exact False.elim impossible
}}

def generatedDynamicRequirement :
    OriginalStackDynamicTargetRequirement generatedContext := {{
  site := generatedDynamicSite
  allowedTargetIds := []
  allowedTargetsChecked := by decide +kernel
  sourceFact := fun _world _state => False
  sourceFactResolves := by
    intro _world _state impossible
    exact False.elim impossible
}}

def generatedCombinedRequirements :
    List (OriginalStackDynamicTargetRequirement generatedContext) :=
  [generatedStackRequirement, generatedConstructorRequirement,
    generatedDynamicRequirement]

def generatedStackCallFrameRouteChecked : Bool :=
  let route :=
    StageA.GeneratedRelational.RuntimeValueCarry.generatedRuntimeValueCarryRoute{plan.stack_route_index}
  route.originTargetId == {plan.stack_target_id} &&
    route.targetFact.targetId == {plan.stack_source_target_id} &&
    route.locations[route.targetFact.locationId]? ==
      some (.inFrameWord .esp (.add 32)) &&
    match route.transfers[{plan.stack_call_frame_transfer_index}]? with
    | none => false
    | some transfer =>
        transfer.sourceTargetId == {plan.stack_source_target_id} &&
          transfer.targetTargetId == {plan.stack_continuation_target_id} &&
          transfer.kind == .callFrameWordPreserve

theorem generatedStackEvidenceChecked :
    generatedStackCallFrameRouteChecked = true /\\
      generatedStackRequirement.site.sourceTargetId = {plan.stack_source_target_id} /\\
      generatedStackRequirement.allowedTargetIds = [{plan.stack_target_id}] /\\
      generatedStackCallFrameTransferAuthority.transfer.sourceTargetId =
        {plan.stack_source_target_id} := by
  decide +kernel

def generatedConstructorBranchTargets : List (Nat × Nat) :=
  [{constructor_pairs}]

def generatedConstructorBranchTargetsChecked : Bool :=
  generatedConstructorBranchTargets.all fun pair =>
    generatedCodeTargetRvaChecked pair.1 pair.2

def generatedConstructorDecodedOutcomes : List (Nat × List Nat) :=
  [{constructor_outcomes}]

theorem generatedConstructorDecodedOutcomesExact :
    generatedDecodedOutcomesChecked generatedConstructorDecodedOutcomes = true := by
  decide +kernel

theorem generatedConstructorImageWordsExact :
    readImmutableImageWord generatedContext.pe {table_address} 4 =
        some 4294967295 /\\
      readImmutableImageWord generatedContext.pe {table_address + 4} 4 =
        some 0 := by
  decide +kernel

theorem generatedConstructorImageWordsHold (memory : Memory)
    (immutable : ImmutableImageWordMemory generatedContext.pe memory) :
    Memory.read32 memory (BitVec.ofNat 32 {table_address}) =
        BitVec.ofNat 32 4294967295 /\\
      Memory.read32 memory (BitVec.ofNat 32 {table_address + 4}) =
        BitVec.ofNat 32 0 := by
  exact ⟨
    ImmutableImageWordMemory.read32_of_checked generatedContext.pe memory
      {table_address} 4294967295 immutable generatedConstructorImageWordsExact.1,
    ImmutableImageWordMemory.read32_of_checked generatedContext.pe memory
      {table_address + 4} 0 immutable generatedConstructorImageWordsExact.2⟩

theorem generatedConstructorEvidenceChecked :
    generatedConstructorBranchTargetsChecked = true /\\
      generatedDecodedOutcomesChecked generatedConstructorDecodedOutcomes = true /\\
      generatedConstructorRequirement.site.sourceTargetId =
        {plan.constructor_source_target_id} /\\
      generatedConstructorRequirement.allowedTargetIds = [] := by
  decide +kernel

def generatedDynamicBranchTargets : List (Nat × Nat) :=
  [{dynamic_pairs}]

def generatedDynamicBranchTargetsChecked : Bool :=
  generatedDynamicBranchTargets.all fun pair =>
    generatedCodeTargetRvaChecked pair.1 pair.2

def generatedDynamicDecodedOutcomes : List (Nat × List Nat) :=
  [{dynamic_outcomes}]

theorem generatedDynamicDecodedOutcomesExact :
    generatedDecodedOutcomesChecked generatedDynamicDecodedOutcomes = true := by
  decide +kernel

def generatedLaunchRootTargetIds : List Nat :=
  [{plan.entry_target_id}, {tls0}, {tls1}]

def generatedNoRegistrationTargetIds : List Nat :=
  [{plan.registration_target_ids[0]}, {plan.registration_target_ids[1]}]

def generatedNoRegistrationWriterTargetIds : List Nat :=
  [{plan.registration_writer_target_ids[0]},
    {plan.registration_writer_target_ids[1]}]

def generatedLaunchRootsChecked : Bool :=
  generatedExactLaunchRootTargetIds.length ==
      generatedLaunchRootTargetIds.length &&
    generatedLaunchRootTargetIds.all
      generatedExactLaunchRootTargetIds.contains

def generatedNoRegistrationEntriesChecked : Bool :=
  generatedNoRegistrationTargetIds.all fun targetId =>
    !generatedExactLaunchRootTargetIds.contains targetId &&
      !generatedTargetHasIncomingControlEdge targetId

theorem generatedDynamicHeadImageBytesZero :
    rvaByte generatedCarrierContext.originalPe {head_rva} = some 0 /\\
      rvaByte generatedCarrierContext.originalPe {head_rva + 1} = some 0 /\\
      rvaByte generatedCarrierContext.originalPe {head_rva + 2} = some 0 /\\
      rvaByte generatedCarrierContext.originalPe {head_rva + 3} = some 0 := by
  decide +kernel

theorem generatedDynamicHeadLaunchZero (memory : Memory)
    (mapped : PreferredBaseImageMemory generatedCarrierContext.originalPe
      generatedCarrierContext.originalImports memory) :
    Memory.read32 memory
      (BitVec.ofNat 32
        (generatedCarrierContext.originalPe.imageBase + {head_rva})) =
      BitVec.ofNat 32 0 := by
  have byte0 := mapped {head_rva} 0 (by decide +kernel)
    (by decide +kernel) generatedDynamicHeadImageBytesZero.1
  have byte1 := mapped {head_rva + 1} 0 (by decide +kernel)
    (by decide +kernel) generatedDynamicHeadImageBytesZero.2.1
  have byte2 := mapped {head_rva + 2} 0 (by decide +kernel)
    (by decide +kernel) generatedDynamicHeadImageBytesZero.2.2.1
  have byte3 := mapped {head_rva + 3} 0 (by decide +kernel)
    (by decide +kernel) generatedDynamicHeadImageBytesZero.2.2.2
  simp only [Memory.read32]
  rw [byte0]
  have address1 :
      BitVec.ofNat 32
          (generatedCarrierContext.originalPe.imageBase + {head_rva}) +
          BitVec.ofNat 32 1 =
        BitVec.ofNat 32
          (generatedCarrierContext.originalPe.imageBase + {head_rva + 1}) := by
    decide +kernel
  have address2 :
      BitVec.ofNat 32
          (generatedCarrierContext.originalPe.imageBase + {head_rva}) +
          BitVec.ofNat 32 2 =
        BitVec.ofNat 32
          (generatedCarrierContext.originalPe.imageBase + {head_rva + 2}) := by
    decide +kernel
  have address3 :
      BitVec.ofNat 32
          (generatedCarrierContext.originalPe.imageBase + {head_rva}) +
          BitVec.ofNat 32 3 =
        BitVec.ofNat 32
          (generatedCarrierContext.originalPe.imageBase + {head_rva + 3}) := by
    decide +kernel
  rw [address1, address2, address3, byte1, byte2, byte3]
  decide +kernel

theorem generatedTlsHeadReasonIsProcessAttach
    (original candidate : MachineState)
    (targetIds : List Nat) (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (holds : PE32TlsProcessAttachArgumentsHold generatedCarrierContext
      original candidate ({tls0} :: targetIds) (frame :: frames)) :
    Memory.read32 original.memory
      (frame.originalStackAddress + BitVec.ofNat 32 8) = BitVec.ofNat 32 1 :=
  holds.2.2.1

theorem generatedLaunchHasNoRegisteredCallbacks (world : RelationalWorld)
    (valid : PE32ConsoleLaunchWorldV1.Valid generatedCarrierContext world) :
    world.registeredCallbacks = [] :=
  valid.2.2.2.2.1

theorem generatedUnknownCallbackRejected
    (callback : WorldExternalCallbackRuntime)
    (empty : callback.suspension.world.registeredCallbacks = []) :
    Not (KnownCallbackRuntime generatedCarrierContext callback) := by
  rintro ⟨registered, member, _target, _valid⟩
  rw [empty] at member
  exact List.not_mem_nil registered member

theorem generatedDynamicEvidenceChecked :
    generatedDynamicBranchTargetsChecked = true /\\
      generatedDecodedOutcomesChecked generatedDynamicDecodedOutcomes = true /\\
      generatedCarrierContext.tlsCallbackTargetIds = [{tls0}, {tls1}] /\\
      generatedLaunchRootsChecked = true /\\
      generatedNoRegistrationEntriesChecked = true /\\
      generatedNoRegistrationWriterTargetIds.all
        (fun targetId => !generatedLaunchRootTargetIds.contains targetId) = true /\\
      generatedDynamicRequirement.site.sourceTargetId =
        {plan.dynamic_source_target_id} /\\
      generatedDynamicRequirement.allowedTargetIds = [] := by
  decide +kernel

theorem generatedCombinedRequirementsChecked :
    generatedCombinedRequirements.length = 3 /\\
      generatedCombinedRequirements.map
        (fun requirement => requirement.site.sourceTargetId) =
        [{plan.stack_source_target_id}, {plan.constructor_source_target_id},
          {plan.dynamic_source_target_id}] := by
  decide +kernel

theorem generatedCombinedEvidenceChecked :
    generatedStackCallFrameRouteChecked = true /\\
      generatedConstructorBranchTargetsChecked = true /\\
      generatedDecodedOutcomesChecked generatedConstructorDecodedOutcomes = true /\\
      generatedDynamicBranchTargetsChecked = true /\\
      generatedDecodedOutcomesChecked generatedDynamicDecodedOutcomes = true /\\
      generatedLaunchRootsChecked = true /\\
      generatedNoRegistrationEntriesChecked = true /\\
      generatedCombinedRequirements.length = 3 := by
  exact ⟨generatedStackEvidenceChecked.1,
    generatedConstructorEvidenceChecked.1,
    generatedConstructorEvidenceChecked.2.1,
    generatedDynamicEvidenceChecked.1,
    generatedDynamicEvidenceChecked.2.1,
    generatedDynamicEvidenceChecked.2.2.2.1,
    generatedDynamicEvidenceChecked.2.2.2.2.1,
    generatedCombinedRequirementsChecked.1⟩

#print axioms generatedStackEvidenceChecked
#print axioms generatedConstructorImageWordsExact
#print axioms generatedConstructorImageWordsHold
#print axioms generatedConstructorDecodedOutcomesExact
#print axioms generatedDynamicHeadLaunchZero
#print axioms generatedDynamicDecodedOutcomesExact
#print axioms generatedTlsHeadReasonIsProcessAttach
#print axioms generatedUnknownCallbackRejected
#print axioms generatedCombinedEvidenceChecked

end {namespace}
"""


def _append_kernel_check_requests(
    out: Path,
    terms: list[Mapping[str, str]],
) -> None:
    path = out / "kernel-check-requests.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or not isinstance(
        payload.get("requests"), list
    ):
        raise ValueError("kernel-check request inventory is malformed")
    requests = list(payload["requests"])
    seen = {
        json.dumps(request.get("term"), sort_keys=True)
        for request in requests
        if isinstance(request, Mapping)
    }
    for term in terms:
        key = json.dumps(dict(term), sort_keys=True)
        if key not in seen:
            requests.append({"term": dict(term)})
            seen.add(key)
    write_json(
        path,
        {
            "format": "stage-a-lean-kernel-check-requests-v1",
            "requests": requests,
        },
    )


def _write_combined_evidence(
    *,
    out: Path,
    plan: _CombinedEvidencePlan,
    graph: OriginalCutpointGraphIR,
    stack_entry_authorities: Mapping[str, Any],
    runtime_value_carry_report: Path,
    kernel_checks: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    source_path = out / "StageA" / f"{COMBINED_EVIDENCE_MODULE}.lean"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_text(
        _combined_evidence_source(plan, graph),
        encoding="utf-8",
    )
    term = {
        "module": f"StageA.{COMBINED_EVIDENCE_MODULE}",
        "namespace": (
            "StageA.GeneratedRelational."
            "GNUHelloStackDynamicCombinedEvidence"
        ),
        "symbol": "generatedCombinedEvidenceChecked",
    }
    stack_terms = [
        entry[term_field]
        for entry in stack_entry_authorities["entries"]
        for term_field in (
            "static_stack_authority_term",
            "indirect_exit_authority_term",
        )
    ]
    _append_kernel_check_requests(out, [*stack_terms, term])
    kernel_check = _kernel_check_for_term(
        out=out,
        term=term,
        kernel_checks=kernel_checks,
    )
    runtime_report = json.loads(runtime_value_carry_report.read_text(encoding="utf-8"))
    if not isinstance(runtime_report, Mapping):
        raise ValueError("runtime value-carry Lean report is malformed")
    stack_checked = stack_entry_authorities.get("status") == "checked"
    route_checked = runtime_report.get("semantic_authority_complete") is True
    evidence_checked = kernel_check is not None
    status = (
        "checked"
        if stack_checked and route_checked and evidence_checked
        else "kernel_compile_required"
    )
    kernel_row = (
        {
            "module": term["module"],
            "status": "kernel_compile_required",
            "term": term,
        }
        if kernel_check is None
        else kernel_check
    )
    sites = [
        {
            "instruction_rva": 0x203C,
            "source_target_id": plan.stack_source_target_id,
            "proof_path": "finite-origin-carry-and-call-frame",
            "combined_requirement_term": (
                f"{term['namespace']}.generatedStackRequirement"
            ),
            "checked_dependencies": [
                f"{term['namespace']}.generatedStackCallEntryCertificate",
                f"{term['namespace']}.generatedStackCallFrameTransferAuthority",
            ],
            "runtime_callback_or_allocation_invariant_required": False,
            "kernel_check": kernel_row,
        },
        {
            "instruction_rva": 0xA220,
            "source_target_id": plan.constructor_source_target_id,
            "proof_path": "immutable-image-static-word-unreachability",
            "combined_requirement_term": (
                f"{term['namespace']}.generatedConstructorRequirement"
            ),
            "checked_dependencies": [
                f"{term['namespace']}.generatedConstructorImageWordsExact",
                f"{term['namespace']}.generatedConstructorImageWordsHold",
                f"{term['namespace']}.generatedConstructorDecodedOutcomesExact",
            ],
            "static_words": [
                {"rva": plan.constructor_table_rva, "value": 0xFFFFFFFF},
                {"rva": plan.constructor_table_rva + 4, "value": 0},
            ],
            "branch_target_ids": list(plan.constructor_branch_target_ids),
            "reachability_assumed": False,
            "runtime_callback_or_allocation_invariant_required": False,
            "kernel_check": kernel_row,
        },
        {
            "instruction_rva": 0xAB8C,
            "source_target_id": plan.dynamic_source_target_id,
            "proof_path": "launch-tls-arguments-and-no-registration",
            "combined_requirement_term": (
                f"{term['namespace']}.generatedDynamicRequirement"
            ),
            "checked_dependencies": [
                f"{term['namespace']}.generatedDynamicHeadLaunchZero",
                f"{term['namespace']}.generatedDynamicDecodedOutcomesExact",
                f"{term['namespace']}.generatedTlsHeadReasonIsProcessAttach",
                f"{term['namespace']}.generatedLaunchHasNoRegisteredCallbacks",
                f"{term['namespace']}.generatedUnknownCallbackRejected",
            ],
            "head_rva": plan.dynamic_head_rva,
            "tls_target_ids": list(plan.tls_target_ids),
            "tls_reason": 1,
            "registration_target_ids": list(plan.registration_target_ids),
            "registration_writer_target_ids": list(
                plan.registration_writer_target_ids
            ),
            "zero_writer_target_id": plan.zero_writer_target_id,
            "reachability_assumed": False,
            "runtime_callback_or_allocation_invariant_required": False,
            "kernel_check": kernel_row,
        },
    ]
    payload = {
        "format": COMBINED_EVIDENCE_FORMAT,
        "status": status,
        "proof_authority": False,
        "report_status_is_authority": False,
        "combined_invariant_compatible": True,
        "combined_invariant_step_closure_required": True,
        "runtime_premises_required": 0,
        "kernel_check": kernel_row,
        "sites": sites,
    }
    write_json(out / COMBINED_EVIDENCE_REPORT, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    parser.add_argument("--state-machine", required=True)
    parser.add_argument("--proof-input", required=True)
    parser.add_argument("--cutpoint-graph", required=True)
    parser.add_argument("--direct-call-authority")
    parser.add_argument("--hints", required=True)
    parser.add_argument("--kernel-checks")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    original = Path(args.original)
    state_machine = Path(args.state_machine)
    proof_input_path = Path(args.proof_input)
    plan = load_stack_dynamic_control_input(
        proof_input_path,
        original_pe_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    cutpoint_graph_path = Path(args.cutpoint_graph)
    cutpoint_graph = load_original_cutpoint_graph_ir(
        cutpoint_graph_path,
        original_pe=original,
        state_machine=state_machine,
    )
    cutpoint_regions = tuple(
        (region.target_id, region.rva)
        for region in cutpoint_graph.regions
    )
    stack_regions = tuple(
        (region.target_id, region.rva)
        for region in plan.regions
    )
    if cutpoint_regions != stack_regions:
        raise ValueError(
            "stack/dynamic input and original cutpoint graph differ"
        )
    proposal = analyze_stack_dynamic_indirect_controls(
        original,
        state_machine,
        plan,
    )
    hints_path = Path(args.hints)
    closure = plan_original_stack_dynamic_control_closure(
        proposal,
        _closure_spec(plan, hints_path, sha256_file(original)),
        original_pe_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
    )
    binding = OriginalIndirectControlAuthorityBinding(
        dependency_module=(
            "StageA."
            "GeneratedRelationalInterpreterMixedOriginalBaseCarrierData"
        ),
        namespace=(
            "StageA.GeneratedRelational."
            "OriginalStackDynamicControlClosure"
        ),
        context_name=(
            "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
            "generatedOriginalStaticContext"
        ),
        authority_name=(
            "StageA.GeneratedRelational.InterpreterMixedOriginalBase."
            "generatedExactOriginalDecodedAuthority"
        ),
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    normalized_hints = out / "stack-dynamic-hints.json"
    normalized_hints.write_bytes(hints_path.read_bytes())
    normalized_cutpoint_graph = out / "original-cutpoint-graph-ir.json"
    write_json(normalized_cutpoint_graph, cutpoint_graph.to_json())
    proposal_report, proposal_lean = write_stack_dynamic_indirect_control(
        out,
        proposal,
        binding,
    )
    closure_report, closure_lean = write_original_stack_dynamic_control_closure(
        out,
        closure,
        binding,
    )
    semantic_transfers = _semantic_transfers_by_rva(state_machine)
    (
        rooted_authorities,
        rooted_report,
        rooted_resources,
    ) = _rooted_unreachability_authorities(
        out=out,
        closure=closure,
        graph=cutpoint_graph,
        semantic_transfers=semantic_transfers,
    )
    kernel_checks: Mapping[str, Any] | None = None
    if args.kernel_checks is not None:
        kernel_checks_value = json.loads(
            Path(args.kernel_checks).read_text(encoding="utf-8")
        )
        if not isinstance(kernel_checks_value, Mapping):
            raise ValueError("kernel-check inventory is not an object")
        kernel_checks = kernel_checks_value
    hints_payload = json.loads(hints_path.read_text(encoding="utf-8"))
    if not isinstance(hints_payload, Mapping):
        raise ValueError("stack/dynamic hints are not an object")
    import pefile

    original_image = pefile.PE(str(original), fast_load=True)
    try:
        original_image_base = int(original_image.OPTIONAL_HEADER.ImageBase)
    finally:
        original_image.close()
    (
        stack_entry_authorities,
        stack_entry_resources,
    ) = _stack_entry_authorities(
        out=out,
        closure=closure,
        graph=cutpoint_graph,
        hints=hints_payload,
        state_machine=state_machine,
        image_base=original_image_base,
        original_sha256=sha256_file(original),
        state_machine_sha256=sha256_file(state_machine),
        kernel_checks=kernel_checks,
    )
    static_resources = {
        proposal_lean.stem: {
            "resource_class": "medium",
            "estimated_memory_mb": 4096,
        },
        closure_lean.stem: {
            "resource_class": "medium",
            "estimated_memory_mb": 6144,
        },
        **rooted_resources,
        **stack_entry_resources,
    }
    if args.static_only:
        write_json(out / "module-resources.json", static_resources)
        _manifest(
            out,
            {
                "original_pe": original,
                "state_machine": state_machine,
                "hints": normalized_hints,
                "proof_input": proof_input_path,
                "cutpoint_graph": normalized_cutpoint_graph,
            },
            status=stack_entry_authorities["status"],
            proof_authority=False,
            report_status_is_authority=False,
            public_outputs={
                "proposal": proposal_report.name,
                "closure": closure_report.name,
                "checked_stack_entries": (
                    "checked-stack-finite-origin-call-entry-authorities.json"
                ),
                "rooted_scc": rooted_report.name,
                "kernel_check_requests": "kernel-check-requests.json",
                "module_resources": "module-resources.json",
            },
            modules=sorted(static_resources),
            targets=sorted(static_resources),
            counts={
                "sites": len(closure.sites),
                "rooted_unreachability_sites": len(rooted_authorities),
                "stack_entries": len(stack_entry_authorities["entries"]),
                "kernel_checked_stack_entries": sum(
                    entry["static_stack_authority_kernel_check"]["status"]
                    == "checked"
                    for entry in stack_entry_authorities["entries"]
                ),
                "kernel_checked_indirect_exit_entries": sum(
                    entry["indirect_exit_authority_kernel_check"]["status"]
                    == "checked"
                    for entry in stack_entry_authorities["entries"]
                ),
            },
        )
        return
    if args.direct_call_authority is None:
        raise ValueError(
            "--direct-call-authority is required outside --static-only mode"
        )
    direct_call_authority_path = Path(args.direct_call_authority)
    direct_call_authority = json.loads(
        direct_call_authority_path.read_text(encoding="utf-8")
    )
    if not isinstance(direct_call_authority, Mapping):
        raise ValueError("direct-call authority is not an object")
    runtime_value_carry = _runtime_value_carry_ir(
        cutpoint_graph,
        normalized_cutpoint_graph,
        hints_path,
        direct_call_authority,
        direct_call_authority_path,
        closure_report,
    )
    runtime_value_carry_path = out / "runtime-value-carry-ir.json"
    write_json(runtime_value_carry_path, runtime_value_carry.to_json())
    (
        runtime_value_carry_structure,
        runtime_value_carry_binding,
        runtime_value_carry_lean_report,
    ) = write_runtime_value_carry_lean(
        out,
        runtime_value_carry,
        kernel_checks=kernel_checks,
        graph=cutpoint_graph,
    )
    combined_plan = _combined_evidence_plan(
        original=original,
        closure=closure,
        graph=cutpoint_graph,
        semantic_transfers=semantic_transfers,
        runtime_value_carry=runtime_value_carry,
    )
    combined_evidence = _write_combined_evidence(
        out=out,
        plan=combined_plan,
        graph=cutpoint_graph,
        stack_entry_authorities=stack_entry_authorities,
        runtime_value_carry_report=runtime_value_carry_lean_report,
        kernel_checks=kernel_checks,
    )
    resources = {
        **static_resources,
        RUNTIME_VALUE_CARRY_STRUCTURE_MODULE: {
            "resource_class": "light",
            "estimated_memory_mb": 768,
        },
        RUNTIME_VALUE_CARRY_BINDING_MODULE: {
            "resource_class": "medium",
            "estimated_memory_mb": 2048,
        },
        "GeneratedRelationalRuntimeValueCarrySemantics": {
            "resource_class": "medium",
            "estimated_memory_mb": 2048,
        },
        COMBINED_EVIDENCE_MODULE: {
            "resource_class": "medium",
            "estimated_memory_mb": 4096,
        },
    }
    write_json(out / "module-resources.json", resources)
    _manifest(
        out,
        {
            "original_pe": original,
            "state_machine": state_machine,
            "hints": normalized_hints,
            "proof_input": proof_input_path,
            "cutpoint_graph": normalized_cutpoint_graph,
            "direct_call_authority": direct_call_authority_path,
            "runtime_value_carry": runtime_value_carry_path,
            "runtime_value_carry_structure": runtime_value_carry_structure,
            "runtime_value_carry_binding": runtime_value_carry_binding,
            "runtime_value_carry_lean_report": runtime_value_carry_lean_report,
        },
        status=combined_evidence["status"],
        proof_authority=False,
        report_status_is_authority=False,
        runtime_closure_required=False,
        combined_invariant_step_closure_required=True,
        public_outputs={
            "proposal": proposal_report.name,
            "closure": closure_report.name,
            "runtime_value_carry": runtime_value_carry_path.name,
            "runtime_value_carry_lean": runtime_value_carry_lean_report.name,
            "combined_evidence": COMBINED_EVIDENCE_REPORT,
            "checked_stack_entries": (
                "checked-stack-finite-origin-call-entry-authorities.json"
            ),
            "rooted_scc": rooted_report.name,
            "kernel_check_requests": "kernel-check-requests.json",
            "module_resources": "module-resources.json",
        },
        modules=sorted(resources),
        targets=sorted(resources),
        counts={
            "sites": len(closure.sites),
            "static_authorities": len(closure.sites),
            "runtime_premises_required": combined_evidence[
                "runtime_premises_required"
            ],
            "kernel_checked_combined_evidence_sites": sum(
                site["kernel_check"]["status"] == "checked"
                for site in combined_evidence["sites"]
            ),
            "cutpoint_regions": len(cutpoint_graph.regions),
            "cutpoint_edges": len(cutpoint_graph.edges),
            "stack_sites": sum(
                site.closure_mode == "finite_stack_target"
                for site in closure.sites
            ),
            "indexed_table_sites": sum(
                site.closure_mode == "empty_indexed_source"
                for site in closure.sites
            ),
            "rooted_unreachability_sites": len(rooted_authorities),
            "dynamic_callback_sites": sum(
                site.closure_mode
                in {
                    "finite_dynamic_targets",
                    "uninhabited_dynamic_source",
                }
                for site in closure.sites
            ),
            "runtime_value_carry_routes": len(runtime_value_carry.routes),
            "runtime_value_carry_required_transfers": sum(
                transfer.authority_status == "required"
                for route in runtime_value_carry.routes
                for transfer in route.transfers
            ),
        },
        runtime_frontiers=[],
        combined_invariant_requirements=combined_evidence["sites"],
        cutpoint_graph_sha256=(
            canonical_original_cutpoint_graph_sha256(cutpoint_graph)
        ),
    )


if __name__ == "__main__":
    main()
