#!/usr/bin/env python3
"""Emit GNU stack/dynamic authorities from a cached mixed-original projection."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

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
    RuntimeValueLocation,
    RuntimeValueOrigin,
    RuntimeValueTransfer,
    validate_runtime_value_carry_ir,
)
from spaghetti_extractor.relational.stack_dynamic_control_ir import (
    load_stack_dynamic_control_input,
)
from spaghetti_extractor.util import sha256_file, write_json


def _manifest(
    out: Path,
    inputs: Mapping[str, Path],
    **extra: Any,
) -> None:
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-gnu-hello-roundtrip-phase-v1",
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
                str, str,
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
            ))

        pending_transfers.sort()
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    parser.add_argument("--state-machine", required=True)
    parser.add_argument("--proof-input", required=True)
    parser.add_argument("--cutpoint-graph", required=True)
    parser.add_argument("--direct-call-authority", required=True)
    parser.add_argument("--hints", required=True)
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
    ) = write_runtime_value_carry_lean(out, runtime_value_carry)
    resources = {
        proposal_lean.stem: {
            "resource_class": "medium",
            "estimated_memory_mb": 4096,
        },
        closure_lean.stem: {
            "resource_class": "medium",
            "estimated_memory_mb": 6144,
        },
        RUNTIME_VALUE_CARRY_STRUCTURE_MODULE: {
            "resource_class": "light",
            "estimated_memory_mb": 768,
        },
        RUNTIME_VALUE_CARRY_BINDING_MODULE: {
            "resource_class": "medium",
            "estimated_memory_mb": 2048,
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
        status="runtime-premises-required",
        proof_authority=False,
        report_status_is_authority=False,
        runtime_closure_required=True,
        public_outputs={
            "proposal": proposal_report.name,
            "closure": closure_report.name,
            "runtime_value_carry": runtime_value_carry_path.name,
            "runtime_value_carry_lean": runtime_value_carry_lean_report.name,
            "module_resources": "module-resources.json",
        },
        modules=sorted(resources),
        targets=sorted(resources),
        counts={
            "sites": len(closure.sites),
            "static_authorities": len(closure.sites),
            "runtime_premises_required": len(closure.sites),
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
        runtime_frontiers=[
            {
                "stable_id": site.finding.stable_id,
                "instruction_rva": site.finding.instruction_rva,
                "premise_type": site.premise_type,
                "closure_mode": site.closure_mode,
            }
            for site in closure.sites
        ],
        cutpoint_graph_sha256=(
            canonical_original_cutpoint_graph_sha256(cutpoint_graph)
        ),
    )


if __name__ == "__main__":
    main()
