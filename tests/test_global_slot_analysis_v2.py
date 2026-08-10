from __future__ import annotations

import copy
import json
import unittest
from typing import Any, Sequence

from spaghetti_extractor.global_slot_analysis_v2 import (
    CHECKED_MEMORY_RANGE_FACT_V2_FORMAT,
    GLOBAL_SLOT_ANALYSIS_V2_FORMAT,
    analyze_global_slots_v2,
)
from spaghetti_extractor.entry_state_analysis_v2 import propose_global_slot_invariant
from spaghetti_extractor.hybrid_authority_v2 import BinaryBinding, UnitBinding
from spaghetti_extractor.checked_memory_access_v2 import (
    MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
    prepare_checked_memory_access_facts_v2,
    seal_checked_memory_access_facts_v2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.stack_range_analysis_v2 import (
    derive_stack_range_analysis_v2,
)


IMAGE_BASE = 0x400000
IMAGE_SIZE = 0x10000
SLOT = 0x403000
PE_SHA256 = "a" * 64
INTERPROCEDURAL_SHA256 = "d" * 64


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _add(left: dict[str, object], right: int) -> dict[str, object]:
    return {"op": "add32", "args": [left, _const(right)]}


def _read(address: object = None) -> dict[str, object]:
    return {
        "kind": "read",
        "width": 4,
        "address": _const(SLOT) if address is None else address,
    }


def _write(value: object, address: object = None) -> dict[str, object]:
    return {
        "kind": "write",
        "width": 4,
        "address": _const(SLOT) if address is None else address,
        "value": value,
    }


def _unit(
    unit_id: str,
    rva: int,
    events: list[dict[str, object]],
    *,
    direct_targets: list[int] | None = None,
    indirect: bool = False,
    external_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "id": unit_id,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 4},
            "contract_sha256": (f"{rva:064x}")[-64:],
            "instruction_bytes_sha256": (f"{rva + 1:064x}")[-64:],
        },
        "semantics": {
            "memory_events": copy.deepcopy(events),
            "external_events": copy.deepcopy(external_events or []),
        },
        "control": {
            "direct_targets": list(direct_targets or []),
            "has_indirect_target": indirect,
        },
    }


def _graph(
    units: list[dict[str, object]],
    *,
    roots: list[object] | None = None,
    edges: Sequence[tuple[str, str]] = (),
    indirect: list[dict[str, object]] | None = None,
) -> dict[str, Any]:
    return {
        "format": "stage-a-rooted-control-graph-v2",
        "id": "fixture-graph",
        "status": "complete",
        "roots": [str(units[0]["id"])] if roots is None else roots,
        "direct_edges": [
            {"source_unit_id": source, "target_unit_id": target}
            for source, target in edges
        ],
        "indirect_exits": copy.deepcopy([] if indirect is None else indirect),
    }


def _analyze(
    units: list[dict[str, object]],
    graph: dict[str, Any],
    *,
    budget: int = 32,
    entry_ranges: list[dict[str, object]] | None = None,
    world_ranges: list[dict[str, object]] | None = None,
    relevant_reads: list[dict[str, object]] | None = None,
    launch_initial_values: dict[int, int] | None = None,
    slot: int = SLOT,
    checked_access_facts: list[dict[str, object]] | None = None,
    checked_spatial_facts: list[dict[str, object]] | None = None,
    call_site_effects: list[dict[str, object]] | None = None,
    range_binding: dict[str, object] | None = None,
) -> dict[str, Any]:
    machine_sha = machine_ir_sha256(units)
    return analyze_global_slots_v2(
        units=units,
        graph=graph,
        candidate_slot_addresses=[slot],
        image_base=IMAGE_BASE,
        size_of_image=IMAGE_SIZE,
        entry_range_facts=[] if entry_ranges is None else entry_ranges,
        world_range_facts=[] if world_ranges is None else world_ranges,
        range_authority_binding=(
            {
                "pe_sha256": "a" * 64,
                "machine_ir_sha256": "b" * 64,
                "rooted_graph_id": graph["id"],
                "launch_assumptions_sha256": "c" * 64,
                "image_base": IMAGE_BASE,
                "size_of_image": IMAGE_SIZE,
            }
            if range_binding is None
            else range_binding
        ),
        relevant_read_dependencies=relevant_reads,
        launch_initial_values=launch_initial_values,
        checked_memory_access_facts=(
            [] if checked_access_facts is None else checked_access_facts
        ),
        call_site_effects=(
            [] if call_site_effects is None else call_site_effects
        ),
        checked_memory_spatial_facts=(
            [] if checked_spatial_facts is None else checked_spatial_facts
        ),
        pe_sha256=PE_SHA256,
        machine_ir_sha256=machine_sha,
        interprocedural_authority_sha256=INTERPROCEDURAL_SHA256,
        alternative_budget=budget,
    )


def _checked_access_facts(
    units: list[dict[str, object]],
    *,
    origin: dict[str, object] | None = None,
    origins: list[dict[str, object]] | None = None,
) -> list[dict[str, object]]:
    if (origin is None) == (origins is None):
        raise ValueError("exactly one of origin or origins is required")
    address_origins = [origin] if origin is not None else list(origins or ())
    event = units[0]["semantics"]["memory_events"][0]
    proposal = {
        "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
        "status": "complete",
        "unit_id": units[0]["id"],
        "event_index": 0,
        "memory_kind": event["kind"],
        "width_bytes": event["width"],
        "address_expression": copy.deepcopy(event["address"]),
        "address_origins": address_origins,
        "authority_dependencies": sorted({
            str(dependency)
            for value in address_origins
            for dependency in value.get("authority_dependencies", [])
        }),
    }
    prepared = prepare_checked_memory_access_facts_v2(
        [proposal],
        units=units,
        binary=BinaryBinding(PE_SHA256, machine_ir_sha256(units)),
    )
    return list(seal_checked_memory_access_facts_v2(
        prepared,
        interprocedural_authority_sha256=INTERPROCEDURAL_SHA256,
    ))


def _codes(result: dict[str, Any]) -> set[str]:
    slot = result["slots"][0]
    return {str(issue["code"]) for issue in slot["issues"]}


def _incoming(
    result: dict[str, Any], unit_id: str, event_index: int
) -> dict[str, Any]:
    reads = result["global_slot_evidence"][0]["relevant_reads"]
    return next(
        row["incoming"]
        for row in reads
        if row["site"]["unit_id"] == unit_id
        and row["site"]["event_index"] == event_index
    )


def _call_effect(
    unit_id: str,
    *,
    output_address: int | None = None,
    memory_complete: bool = True,
) -> dict[str, object]:
    outputs = []
    writes = []
    if output_address is not None:
        outputs.append({
            "location": {"kind": "exact", "key": [output_address]},
            "origins": [{
                "kind": "interface_object",
                "key": ["f" * 64, "ITestInterface"],
            }],
        })
        writes.append({
            "base": {"kind": "exact", "key": [output_address]},
            "size": 4,
        })
    failure_codes = [] if memory_complete else ["memory_frame_unknown"]
    return {
        "format": "stage-a-call-site-effect-v2",
        "unit_id": unit_id,
        "event_index": 0,
        "transfer_kind": "external_call",
        "status": "complete" if memory_complete else "incomplete",
        "register_frame": {
            "status": "complete",
            "preserved_registers": [],
        },
        "stack_frame": {
            "status": "complete",
            "stack_cleanup_bytes": 0,
        },
        "result_frame": {"status": "complete", "outputs": outputs},
        "memory_frame": {
            "status": "complete" if memory_complete else "incomplete",
            "preserved": memory_complete and not writes,
            "writes": writes if memory_complete else [],
        },
        "abi": None,
        "argument_words": None,
        "dependencies": [],
        "failure_codes": failure_codes,
    }


class GlobalSlotAnalysisV2Tests(unittest.TestCase):
    def test_call_output_is_a_point_sensitive_global_slot_write(self) -> None:
        factory = _unit(
            "factory",
            0x1000,
            [],
            external_events=[{
                "kind": "external_call",
                "instruction_rva": 0x1000,
            }],
        )
        use = _unit("use", 0x1010, [_read()])
        units = [factory, use]
        result = _analyze(
            units,
            _graph(units, edges=[("factory", "use")]),
            launch_initial_values={SLOT: 0},
            call_site_effects=[_call_effect("factory", output_address=SLOT)],
        )

        self.assertEqual(result["status"], "complete", result["issues"])
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(
            {row["kind"] for row in evidence["alternatives"]},
            {"exact_bits", "interface_object"},
        )
        self.assertIn(
            "interprocedural_authority",
            {row["kind"] for row in evidence["dependencies"]},
        )
        self.assertEqual(result["counts"]["call_site_effects"], 1)
        self.assertEqual(result["cold_replay"]["status"], "complete")

    def test_incomplete_call_memory_frame_taints_slot(self) -> None:
        call = _unit(
            "call",
            0x1000,
            [],
            external_events=[{
                "kind": "external_call",
                "instruction_rva": 0x1000,
            }],
        )
        use = _unit("use", 0x1010, [_read()])
        units = [call, use]
        result = _analyze(
            units,
            _graph(units, edges=[("call", "use")]),
            launch_initial_values={SLOT: 0},
            call_site_effects=[_call_effect("call", memory_complete=False)],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("global_slot_unknown_write_taint", _codes(result))

    def test_call_effect_requires_exact_event_and_authority_binding(self) -> None:
        unit = _unit("call", 0x1000, [])
        malformed = _analyze(
            [unit],
            _graph([unit]),
            launch_initial_values={SLOT: 0},
            call_site_effects=[_call_effect("call", output_address=SLOT)],
        )
        self.assertEqual(malformed["status"], "violated")
        self.assertIn("call_site_effect_event_binding_invalid", _codes(malformed))

        call = _unit(
            "bound",
            0x1010,
            [],
            external_events=[{
                "kind": "external_call",
                "instruction_rva": 0x1010,
            }],
        )
        missing_authority = analyze_global_slots_v2(
            units=[call],
            graph=_graph([call]),
            candidate_slot_addresses=[SLOT],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            launch_initial_values={SLOT: 0},
            call_site_effects=[_call_effect("bound", output_address=SLOT)],
        )
        self.assertEqual(missing_authority["status"], "violated")
        self.assertIn(
            "call_site_effect_authority_binding_missing",
            _codes(missing_authority),
        )

    def test_checked_event_bound_stack_spatial_fact_excludes_image_slot(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [_write(_const(7), address=_add(_reg("esp"), 12))],
        )]
        graph = _graph(units)
        launch = {
            "assumptions": {
                "initial_stack": {
                    "contract": "private-non-image-stack-range-v2",
                    "mapped_separately_from_image": True,
                    "minimum_accessible_bytes_below": 0x1000,
                    "minimum_accessible_bytes_above": 0x1000,
                }
            }
        }
        stack = derive_stack_range_analysis_v2(
            units=units,
            graph=graph,
            launch_assumptions=launch,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=machine_ir_sha256(units),
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        result = _analyze(
            units,
            graph,
            launch_initial_values={SLOT: 0},
            checked_spatial_facts=stack["checked_spatial_facts"],
            range_binding=stack["binding"],
        )

        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(result["counts"]["checked_memory_spatial_facts"], 1)
        dependency_kinds = {
            row["kind"]
            for row in result["global_slot_evidence"][0]["dependencies"]
        }
        self.assertIn("checked_memory_spatial_fact", dependency_kinds)

        corrupted = copy.deepcopy(stack["checked_spatial_facts"])
        corrupted[0]["maximum_start_offset"] += 4
        rejected = _analyze(
            units,
            graph,
            launch_initial_values={SLOT: 0},
            checked_spatial_facts=corrupted,
            range_binding=stack["binding"],
        )
        self.assertEqual(rejected["status"], "violated")
        self.assertIn("checked_memory_spatial_fact_invalid", _codes(rejected))

    def test_checked_stack_origin_requires_spatial_range_witness(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [_write(_const(7), address=_reg("eax"))],
        )]
        without_fact = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0},
        )
        facts = _checked_access_facts(
            units,
            origin={"kind": "stack_location", "key": [12]},
        )

        with_fact = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0},
            checked_access_facts=facts,
        )

        self.assertEqual(without_fact["status"], "complete")
        self.assertEqual(with_fact["status"], "complete")
        self.assertEqual(with_fact["counts"]["checked_memory_access_facts"], 1)
        aliasing = with_fact["global_slot_evidence"][0][
            "reachable_write_inventory"
        ]["aliasing_writes"]
        self.assertEqual(
            aliasing[0]["reason"],
            "checked_non_image_origin_lacks_spatial_witness",
        )

    def test_checked_exact_access_still_excludes_a_disjoint_address(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [_write(_const(7), address=_reg("eax"))],
        )]
        facts = _checked_access_facts(
            units,
            origin={"kind": "exact", "key": [SLOT + 8]},
        )

        result = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0},
            checked_access_facts=facts,
        )

        self.assertEqual(result["status"], "complete", result["issues"])
        dependency_kinds = {
            row["kind"]
            for row in result["global_slot_evidence"][0]["dependencies"]
        }
        self.assertIn("checked_memory_access_fact", dependency_kinds)

    def test_checked_finite_origins_do_not_authorize_read_coverage(self) -> None:
        units = [_unit("dispatch", 0x1000, [_read(_reg("esi"))])]
        facts = _checked_access_facts(
            units,
            origins=[
                {"kind": "exact", "key": [SLOT]},
                {"kind": "exact", "key": [SLOT + 4]},
            ],
        )

        result = _analyze(
            units,
            _graph(units),
            relevant_reads=[{
                "slot_rva": SLOT - IMAGE_BASE,
                "exit_id": "indirect-exit:dispatch",
                "unit_id": "dispatch",
                "event_index": 0,
            }],
            launch_initial_values={SLOT: 0x401020},
            checked_access_facts=facts,
        )

        self.assertEqual(result["status"], "incomplete", result["issues"])
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(
            evidence["read_inventory"][0]["classification"],
            "alias",
        )
        self.assertIn("global_slot_read_alias_unresolved", _codes(result))
        self.assertEqual(
            evidence["target_dependencies"],
            [{
                "exit_id": "indirect-exit:dispatch",
                "unit_id": "dispatch",
                "event_index": 0,
            }],
        )

    def test_corrupt_checked_access_fact_is_violated(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [_write(_const(7), address=_reg("eax"))],
        )]
        facts = _checked_access_facts(
            units,
            origin={"kind": "stack_location", "key": [12]},
        )
        facts[0] = copy.deepcopy(facts[0])
        facts[0]["width_bytes"] = 8

        result = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0},
            checked_access_facts=facts,
        )

        self.assertEqual(result["status"], "violated")
        self.assertIn("checked_memory_access_fact_invalid", _codes(result))

    def test_empty_candidate_inventory_is_not_applicable(self) -> None:
        units = [_unit("entry", 0x1000, [])]

        result = analyze_global_slots_v2(
            units=units,
            graph=_graph(units),
            candidate_slot_addresses=[],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["counts"]["candidate_slots"], 0)
        self.assertEqual(result["global_slot_evidence"], [])

    def test_external_only_indirect_exit_is_a_complete_graph_certificate(self) -> None:
        units = [_unit("entry", 0x1000, [], indirect=True)]
        graph = _graph(
            units,
            indirect=[{
                "source_unit_id": "entry",
                "status": "complete",
                "target_unit_ids": [],
                "external_targets": [{"dll": "kernel32.dll", "symbol": "ExitProcess"}],
            }],
        )

        result = analyze_global_slots_v2(
            units=units,
            graph=graph,
            candidate_slot_addresses=[],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        self.assertEqual(result["status"], "complete", result["issues"])

    def test_known_write_emits_consumer_replay_shape_and_cold_hash(self) -> None:
        units = [_unit("init", 0x1000, [_write(_const(0x401020)), _read()])]
        result = _analyze(units, _graph(units))

        self.assertEqual(result["format"], GLOBAL_SLOT_ANALYSIS_V2_FORMAT)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["cold_replay"]["status"], "complete")
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(evidence["reachable_write_inventory"]["status"], "complete")
        self.assertEqual(
            evidence["reachable_write_inventory"]["writes"][0]["classification"],
            "initializer",
        )
        self.assertEqual(
            evidence["relevant_reads"][0]["dominated_by"],
            evidence["reachable_write_inventory"]["writes"][0]["site"],
        )
        self.assertEqual(
            evidence["cold_replay_sha256"], result["cold_replay"]["replay_sha256"]
        )
        self.assertEqual(
            json.dumps(result, sort_keys=True),
            json.dumps(_analyze(copy.deepcopy(units), _graph(units)), sort_keys=True),
        )
        promoted = propose_global_slot_invariant(
            evidence,
            interface_slot={
                "address": SLOT,
                "origins": copy.deepcopy(evidence["alternatives"]),
                "tainted": False,
            },
            unit_bindings={
                "init": UnitBinding(
                    binary=BinaryBinding(
                        pe_sha256="a" * 64,
                        machine_ir_sha256=result["bindings"]["machine_ir_sha256"],
                    ),
                    unit_id="init",
                    rva_start=0x1000,
                    rva_end=0x1004,
                    unit_sha256="b" * 64,
                    instruction_bytes_sha256=f"{0x1001:064x}",
                )
            },
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )
        self.assertEqual(promoted["status"], "complete")
        self.assertIsNotNone(promoted["proposal"])

    def test_launch_initialized_slot_needs_no_machine_initializer(self) -> None:
        units = [_unit("read", 0x1000, [_read()])]

        result = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0x401020},
        )

        self.assertEqual(result["status"], "complete", result["slots"][0]["issues"])
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(
            evidence["launch_initializer"]["value_origin"],
            {"kind": "exact_bits", "value": 0x401020, "width_bits": 32},
        )
        self.assertEqual(evidence["reachable_write_inventory"]["writes"], [])
        self.assertEqual(
            evidence["relevant_reads"][0]["dominated_by"],
            {"kind": "launch_image", "address": SLOT},
        )

    def test_launch_initialized_slot_is_tainted_by_unknown_overwrite(self) -> None:
        units = [_unit("write", 0x1000, [_write(_reg("eax")), _read()])]

        result = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0x401020},
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("global_slot_unknown_write_taint", _codes(result))
        self.assertIn("global_slot_read_reached_by_tainted_value", _codes(result))

    def test_proposal_origin_witness_can_scope_launch_slot_without_event_site(self) -> None:
        units = [_unit("dispatch", 0x1000, [])]

        result = _analyze(
            units,
            _graph(units),
            relevant_reads=[{
                "slot_rva": SLOT - IMAGE_BASE,
                "exit_id": "indirect-exit:fixture",
                "witness_only": True,
            }],
            launch_initial_values={SLOT: 0x401020},
        )

        self.assertEqual(result["status"], "complete", result["slots"][0]["issues"])
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(evidence["relevant_reads"], [])
        self.assertEqual(evidence["target_dependencies"], [{
            "exit_id": "indirect-exit:fixture",
            "witness_only": True,
        }])

    def test_explicit_target_read_dependencies_exclude_unrelated_reads(self) -> None:
        units = [
            _unit(
                "init",
                0x1000,
                [
                    _write(_const(0x401020)),
                    _read(_reg("eax")),
                    _read(),
                ],
            )
        ]

        broad = _analyze(units, _graph(units))
        scoped = _analyze(
            units,
            _graph(units),
            relevant_reads=[{
                "slot_rva": SLOT - IMAGE_BASE,
                "exit_id": "indirect-exit:fixture",
                "unit_id": "init",
                "event_index": 2,
            }],
        )

        self.assertEqual(broad["status"], "incomplete")
        self.assertIn("global_slot_read_alias_unresolved", _codes(broad))
        self.assertEqual(scoped["status"], "complete", scoped["slots"][0]["issues"])
        evidence = scoped["global_slot_evidence"][0]
        self.assertEqual(len(evidence["relevant_reads"]), 1)
        self.assertEqual(
            evidence["target_dependencies"],
            [{
                "exit_id": "indirect-exit:fixture",
                "unit_id": "init",
                "event_index": 2,
            }],
        )

    def test_one_exit_retains_multiple_exact_read_dependencies(self) -> None:
        units = [_unit(
            "dispatch",
            0x1000,
            [_write(_const(0x401020)), _read(), _read()],
        )]
        result = _analyze(
            units,
            _graph(units),
            relevant_reads=[
                {
                    "slot_rva": SLOT - IMAGE_BASE,
                    "exit_id": "indirect-exit:fixture",
                    "unit_id": "dispatch",
                    "event_index": event_index,
                }
                for event_index in (1, 2)
            ],
        )

        self.assertEqual(result["status"], "complete", result["slots"][0]["issues"])
        self.assertEqual(
            result["global_slot_evidence"][0]["target_dependencies"],
            [
                {
                    "exit_id": "indirect-exit:fixture",
                    "unit_id": "dispatch",
                    "event_index": event_index,
                }
                for event_index in (1, 2)
            ],
        )

    def test_unknown_overwrite_taints_downstream_read(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                [_write(_const(1)), _write(_reg("eax")), _read()],
            )
        ]
        result = _analyze(units, _graph(units))

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("global_slot_unknown_write_taint", _codes(result))
        self.assertIn("global_slot_read_reached_by_tainted_value", _codes(result))
        inventory = result["global_slot_evidence"][0]["reachable_write_inventory"]
        self.assertEqual(len(inventory["unknown_writes"]), 1)

    def test_unknown_write_after_read_is_diagnostic_only(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                [_write(_const(1)), _read(), _write(_reg("eax"))],
            )
        ]

        result = _analyze(units, _graph(units))

        self.assertEqual(result["status"], "complete", result["slots"][0]["issues"])
        self.assertNotIn("global_slot_unknown_write_taint", _codes(result))
        self.assertFalse(result["slots"][0]["tainted"])
        incoming = _incoming(result, "entry", 1)
        self.assertEqual(incoming["status"], "complete")
        self.assertTrue(incoming["initialized"])
        self.assertFalse(incoming["tainted"])
        self.assertFalse(incoming["overflow"])
        self.assertEqual(
            incoming["alternatives"],
            [{"kind": "exact_bits", "value": 1, "width_bits": 32}],
        )
        self.assertEqual(incoming["unknown_writes"], [])
        evidence = result["global_slot_evidence"][0]
        replay_read = evidence["read_inventory"][0]
        self.assertEqual(replay_read["status"], incoming["status"])
        self.assertEqual(replay_read["state"]["alternatives"], incoming["alternatives"])
        self.assertEqual(
            replay_read["reaching_write_inventory"]["unknown_writes"], []
        )
        self.assertEqual(
            evidence["diagnostic_inventory"]["counts"]["unknown_writes"], 1
        )
        self.assertEqual(
            evidence["reachable_write_inventory"]["status"], "incomplete"
        )

    def test_unknown_write_on_unrelated_branch_does_not_taint_read(self) -> None:
        units = [
            _unit(
                "branch",
                0x1000,
                [],
                direct_targets=[0x1010, 0x1020],
            ),
            _unit("clean", 0x1010, [_write(_const(2)), _read()]),
            _unit("unrelated", 0x1020, [_write(_reg("eax"))]),
        ]
        edges = [("branch", "clean"), ("branch", "unrelated")]

        result = _analyze(units, _graph(units, edges=edges))

        self.assertEqual(result["status"], "complete", result["slots"][0]["issues"])
        self.assertNotIn("global_slot_unknown_write_taint", _codes(result))
        incoming = _incoming(result, "clean", 1)
        self.assertEqual(incoming["status"], "complete")
        self.assertFalse(incoming["tainted"])
        self.assertEqual(incoming["unknown_writes"], [])
        counts = result["global_slot_evidence"][0]["diagnostic_inventory"]["counts"]
        self.assertEqual(counts["unknown_writes"], 1)

    def test_alias_write_before_exact_strong_update_does_not_reach_read(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                [
                    _write(_const(9), address=_reg("eax")),
                    _write(_const(3)),
                    _read(),
                ],
            )
        ]

        result = _analyze(units, _graph(units))

        self.assertEqual(result["status"], "complete", result["slots"][0]["issues"])
        self.assertNotIn("global_slot_aliasing_write_taint", _codes(result))
        incoming = _incoming(result, "entry", 2)
        self.assertEqual(incoming["status"], "complete")
        self.assertFalse(incoming["tainted"])
        self.assertEqual(incoming["aliasing_writes"], [])
        self.assertEqual(
            [row["site"]["event_index"] for row in incoming["writes"]],
            [1],
        )
        counts = result["global_slot_evidence"][0]["diagnostic_inventory"]["counts"]
        self.assertEqual(counts["aliasing_writes"], 1)

    def test_tainted_predecessor_keeps_joined_read_incomplete(self) -> None:
        units = [
            _unit("init", 0x1000, [_write(_const(0))], direct_targets=[0x1010]),
            _unit(
                "branch",
                0x1010,
                [],
                direct_targets=[0x1020, 0x1030],
            ),
            _unit("clean", 0x1020, [], direct_targets=[0x1040]),
            _unit(
                "tainted",
                0x1030,
                [_write(_reg("eax"))],
                direct_targets=[0x1040],
            ),
            _unit("join", 0x1040, [_read()]),
        ]
        edges = [
            ("init", "branch"),
            ("branch", "clean"),
            ("branch", "tainted"),
            ("clean", "join"),
            ("tainted", "join"),
        ]

        result = _analyze(units, _graph(units, edges=edges))

        self.assertEqual(result["status"], "incomplete")
        incoming = _incoming(result, "join", 0)
        self.assertEqual(incoming["status"], "incomplete")
        self.assertTrue(incoming["initialized"])
        self.assertTrue(incoming["tainted"])
        self.assertEqual(len(incoming["unknown_writes"]), 1)
        self.assertIn(
            "global_slot_read_reached_by_tainted_value",
            {issue["code"] for issue in incoming["issues"]},
        )

    def test_sibling_reads_retain_independent_incoming_statuses(self) -> None:
        units = [
            _unit("init", 0x1000, [_write(_const(0))], direct_targets=[0x1010]),
            _unit(
                "branch",
                0x1010,
                [],
                direct_targets=[0x1020, 0x1030],
            ),
            _unit("clean", 0x1020, [_read()]),
            _unit("tainted", 0x1030, [_write(_reg("eax")), _read()]),
        ]
        edges = [
            ("init", "branch"),
            ("branch", "clean"),
            ("branch", "tainted"),
        ]

        result = _analyze(units, _graph(units, edges=edges))

        self.assertEqual(result["status"], "incomplete")
        clean = _incoming(result, "clean", 0)
        tainted = _incoming(result, "tainted", 1)
        self.assertEqual(clean["status"], "complete")
        self.assertFalse(clean["tainted"])
        self.assertEqual(clean["unknown_writes"], [])
        self.assertEqual(tainted["status"], "incomplete")
        self.assertTrue(tainted["tainted"])
        self.assertEqual(len(tainted["unknown_writes"]), 1)

    def test_finite_branch_join_preserves_bounded_alternatives(self) -> None:
        units = [
            _unit("init", 0x1000, [_write(_const(0))], direct_targets=[0x1010]),
            _unit("branch", 0x1010, [], direct_targets=[0x1020, 0x1030]),
            _unit("left", 0x1020, [_write(_const(1))], direct_targets=[0x1040]),
            _unit("right", 0x1030, [_write(_const(2))], direct_targets=[0x1040]),
            _unit("join", 0x1040, [_read()]),
        ]
        edges = [
            ("init", "branch"),
            ("branch", "left"),
            ("branch", "right"),
            ("left", "join"),
            ("right", "join"),
        ]
        result = _analyze(units, _graph(units, edges=edges))

        self.assertEqual(result["status"], "complete")
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(len(evidence["alternatives"]), 3)
        classifications = [
            write["classification"]
            for write in evidence["reachable_write_inventory"]["writes"]
        ]
        self.assertEqual(classifications.count("initializer"), 1)
        self.assertEqual(classifications.count("bounded_alternatives"), 2)

    def test_initialization_must_dominate_every_read(self) -> None:
        units = [
            _unit("branch", 0x1000, [], direct_targets=[0x1010, 0x1020]),
            _unit("write", 0x1010, [_write(_const(1))], direct_targets=[0x1030]),
            _unit("skip", 0x1020, [], direct_targets=[0x1030]),
            _unit("read", 0x1030, [_read()]),
        ]
        edges = [
            ("branch", "write"),
            ("branch", "skip"),
            ("write", "read"),
            ("skip", "read"),
        ]
        result = _analyze(units, _graph(units, edges=edges))

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("global_slot_initialization_does_not_dominate_reads", _codes(result))
        self.assertIn("global_slot_read_before_dominated_initialization", _codes(result))

    def test_unreplayed_unit_range_cannot_authorize_alias_exclusion(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                [_write(_const(1)), _write(_const(7), _add(_reg("esp"), 8)), _read()],
            )
        ]
        graph = _graph(units)
        unresolved = _analyze(units, graph)
        self.assertIn("global_slot_aliasing_write_taint", _codes(unresolved))

        fact = {
            "format": CHECKED_MEMORY_RANGE_FACT_V2_FORMAT,
            "id": "entry-stack-range",
            "status": "complete",
            "range_kind": "stack",
            "base_expression": _reg("esp"),
            "offset_start": 0,
            "offset_end": 64,
            "applies_to_unit_ids": ["entry"],
            "disjoint_from_image": {
                "image_base": IMAGE_BASE,
                "size_of_image": IMAGE_SIZE,
            },
            "authority_binding": {
                "pe_sha256": "a" * 64,
                "machine_ir_sha256": "b" * 64,
                "rooted_graph_id": graph["id"],
                "launch_assumptions_sha256": "c" * 64,
                "image_base": IMAGE_BASE,
                "size_of_image": IMAGE_SIZE,
            },
        }
        resolved = _analyze(units, graph, entry_ranges=[fact])
        self.assertEqual(resolved["status"], "incomplete")
        dependencies = resolved["global_slot_evidence"][0]["dependencies"]
        self.assertNotIn("entry-stack-range", {item["id"] for item in dependencies})

        stale = copy.deepcopy(fact)
        stale["authority_binding"]["rooted_graph_id"] = "another-graph"
        rejected = _analyze(units, graph, entry_ranges=[stale])
        self.assertEqual(rejected["status"], "violated")
        self.assertIn(
            "checked_range_fact_invalid",
            {issue["code"] for issue in rejected["issues"]},
        )

    def test_unreplayed_nested_stack_range_remains_non_authorizing(self) -> None:
        nested_stack_address = {
            "op": "sub32",
            "args": [
                {
                    "op": "sub32",
                    "args": [_reg("esp"), _const(4)],
                },
                _const(4),
            ],
        }
        units = [
            _unit(
                "entry",
                0x1000,
                [_write(_const(1)), _write(_const(7), nested_stack_address), _read()],
            )
        ]
        graph = _graph(units)
        fact = {
            "format": CHECKED_MEMORY_RANGE_FACT_V2_FORMAT,
            "id": "entry-nested-stack-range",
            "status": "complete",
            "range_kind": "stack",
            "base_expression": _reg("esp"),
            "offset_start": -8,
            "offset_end": -4,
            "applies_to_unit_ids": ["entry"],
            "disjoint_from_image": {
                "image_base": IMAGE_BASE,
                "size_of_image": IMAGE_SIZE,
            },
            "authority_binding": {
                "pe_sha256": "a" * 64,
                "machine_ir_sha256": "b" * 64,
                "rooted_graph_id": graph["id"],
                "launch_assumptions_sha256": "c" * 64,
                "image_base": IMAGE_BASE,
                "size_of_image": IMAGE_SIZE,
            },
        }

        result = _analyze(units, graph, entry_ranges=[fact])

        self.assertEqual(result["status"], "incomplete")
        dependencies = result["global_slot_evidence"][0]["dependencies"]
        self.assertNotIn(
            "entry-nested-stack-range",
            {item["id"] for item in dependencies},
        )

    def test_loop_scc_converges_without_path_unrolling(self) -> None:
        units = [
            _unit("init", 0x1000, [_write(_const(0))], direct_targets=[0x1010]),
            _unit(
                "loop",
                0x1010,
                [_read(), _write({"op": "ite", "args": [_reg("eax"), _const(1), _const(2)]})],
                direct_targets=[0x1010, 0x1020],
            ),
            _unit("exit", 0x1020, [_read()]),
        ]
        edges = [("init", "loop"), ("loop", "loop"), ("loop", "exit")]
        result = _analyze(units, _graph(units, edges=edges))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["cold_replay"]["status"], "complete")
        self.assertEqual(len(result["global_slot_evidence"][0]["alternatives"]), 3)

    def test_callback_read_without_global_invariant_is_incomplete(self) -> None:
        units = [_unit("callback", 0x2000, [_read()])]
        graph = _graph(
            units,
            roots=[{"unit_id": "callback", "kind": "callback"}],
        )
        result = _analyze(units, graph)

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("callback_entry_global_slot_invariant_missing", _codes(result))
        self.assertIn("global_slot_exact_write_missing", _codes(result))

    def test_finite_alternative_budget_overflow_is_incomplete(self) -> None:
        alternatives = [
            {"kind": "exact_bits", "value": value, "width_bits": 32}
            for value in range(4)
        ]
        write = _write(_const(0))
        write["value_origins"] = alternatives
        units = [_unit("entry", 0x1000, [write, _read()])]
        result = _analyze(units, _graph(units), budget=3)

        self.assertEqual(result["status"], "incomplete")
        self.assertIn("global_slot_alternative_budget_exceeded", _codes(result))
        self.assertEqual(
            len(result["global_slot_evidence"][0]["reachable_write_inventory"]["writes"][0]["alternatives"]),
            4,
        )

    def test_complete_indirect_certificate_expands_reachable_inventory(self) -> None:
        units = [
            _unit("dispatch", 0x1000, [], indirect=True),
            _unit("target", 0x1010, [_write(_const(9)), _read()]),
        ]
        complete = _graph(
            units,
            indirect=[
                {
                    "source_unit_id": "dispatch",
                    "status": "complete",
                    "target_unit_ids": ["target"],
                }
            ],
        )
        accepted = _analyze(units, complete)
        self.assertEqual(accepted["status"], "complete")
        self.assertEqual(accepted["counts"]["reachable_units"], 2)

        incomplete = copy.deepcopy(complete)
        incomplete["indirect_exits"][0]["status"] = "incomplete"
        rejected = _analyze(units, incomplete)
        self.assertEqual(rejected["status"], "incomplete")
        self.assertIn(
            "indirect_exit_certificate_incomplete",
            {issue["code"] for issue in rejected["issues"]},
        )

    def test_inductive_slot_fact_can_help_close_its_control_frontier(self) -> None:
        units = [
            _unit(
                "dispatch",
                0x1000,
                [_write(_const(0x401010)), _read()],
                indirect=True,
            ),
            _unit("target", 0x1010, []),
        ]
        graph = _graph(
            units,
            indirect=[{
                "source_unit_id": "dispatch",
                "status": "incomplete",
                "target_unit_ids": [],
            }],
        )
        graph["status"] = "incomplete"

        result = _analyze(units, graph)

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["slots"][0]["status"], "complete")
        evidence = result["global_slot_evidence"][0]
        self.assertEqual(
            {row["code"] for row in evidence["inductive_control_frontiers"]},
            {
                "rooted_control_graph_incomplete",
                "indirect_exit_certificate_incomplete",
            },
        )
        self.assertEqual(
            evidence["reachable_write_inventory"]["status"], "complete"
        )

    def test_unreachable_units_do_not_create_rooted_edge_obligations(self) -> None:
        units = [
            _unit("entry", 0x1000, [_write(_const(7)), _read()]),
            _unit(
                "dead",
                0x2000,
                [],
                direct_targets=[0x2010],
                indirect=True,
            ),
            _unit("dead-target", 0x2010, []),
        ]

        result = _analyze(units, _graph(units))

        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(result["slots"][0]["status"], "complete")

    def test_reachable_omitted_direct_edge_blocks_slot_promotion(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                [_write(_const(7)), _read()],
                direct_targets=[0x1010],
            ),
            _unit("target", 0x1010, []),
        ]

        result = _analyze(units, _graph(units))

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["slots"][0]["status"], "incomplete")
        self.assertIn("decoded_direct_edge_omitted", _codes(result))


if __name__ == "__main__":
    unittest.main()
