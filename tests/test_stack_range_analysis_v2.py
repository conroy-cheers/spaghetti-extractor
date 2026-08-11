from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifact_identity_v2 import canonical_sha256
from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.checked_memory_access_v2 import (
    MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
    prepare_checked_memory_access_facts_v2,
    seal_checked_memory_access_facts_v2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.stack_range_analysis_v2 import (
    CHECKED_CALL_STACK_WRITE_SPATIAL_FACT_V2_FORMAT,
    CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT,
    CHECKED_STACK_SPATIAL_FACT_V2_FORMAT,
    STACK_RANGE_ANALYSIS_V2_FORMAT,
    derive_stack_range_analysis_v2,
    validate_checked_stack_range_facts_v2,
    validate_stack_range_analysis_v2,
)


PE_SHA = "a" * 64
MACHINE_SHA = "b" * 64
IMAGE_BASE = 0x400000
IMAGE_SIZE = 0x10000
INTERPROCEDURAL_SHA = "c" * 64


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value & 0xFFFFFFFF, "width": 32}


def _add(value: int) -> dict[str, object]:
    return {"op": "add32", "args": [_reg("esp"), _const(value)]}


def _add_register(name: str, value: int) -> dict[str, object]:
    return {"op": "add32", "args": [_reg(name), _const(value)]}


def _checked_stack_access(
    units: list[dict[str, object]],
    *,
    unit_id: str,
    event_index: int,
    offset: int,
) -> list[dict[str, object]]:
    unit = next(row for row in units if row["id"] == unit_id)
    event = unit["semantics"]["memory_events"][event_index]
    proposal = {
        "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
        "status": "complete",
        "unit_id": unit_id,
        "event_index": event_index,
        "memory_kind": event["kind"],
        "width_bytes": event["width"],
        "address_expression": copy.deepcopy(event["address"]),
        "address_origins": [{"kind": "stack_location", "key": [offset]}],
        "authority_dependencies": [],
    }
    prepared = prepare_checked_memory_access_facts_v2(
        [proposal],
        units=units,
        binary=BinaryBinding(PE_SHA, machine_ir_sha256(units)),
    )
    return list(seal_checked_memory_access_facts_v2(
        prepared,
        interprocedural_authority_sha256=INTERPROCEDURAL_SHA,
    ))


def _unit(
    unit_id: str,
    rva: int,
    *,
    target_rvas: list[int] = [],
    stack_delta: int | None = 0,
    memory_offsets: list[int] = [],
    external_events: list[dict[str, object]] = [],
) -> dict[str, object]:
    stack = (
        {"status": "unknown", "expression": {"op": "call_response"}}
        if stack_delta is None
        else {
            "status": "derived",
            "net_bytes": stack_delta,
            "expression": _add(stack_delta),
        }
    )
    return {
        "format": "stage-a-machine-ir-v2",
        "id": unit_id,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 4},
            "contract_sha256": f"{rva:064x}",
            "instruction_bytes_sha256": f"{rva + 1:064x}",
        },
        "semantics": {
            "stack_delta": stack,
            "memory_events": [
                {
                    "kind": "write",
                    "width": 4,
                    "address": _add(offset),
                    "value": _const(0),
                }
                for offset in memory_offsets
            ],
            "external_events": copy.deepcopy(external_events),
        },
        "control": {
            "direct_targets": target_rvas,
            "has_indirect_target": False,
        },
    }


def _graph(root: str) -> dict[str, object]:
    return {
        "format": "stage-a-rooted-control-graph-v2",
        "id": "rooted-control-graph-v2:fixture",
        "status": "incomplete",
        "roots": [{"unit_id": root, "kind": "pe_entrypoint"}],
        "direct_edges": [],
        "indirect_exits": [],
    }


def _launch() -> dict[str, object]:
    return {
        "assumptions": {
            "initial_stack": {
                "contract": "private-non-image-stack-range-v2",
                "mapped_separately_from_image": True,
                "minimum_accessible_bytes_below": 0x1000,
                "minimum_accessible_bytes_above": 0x1000,
            }
        }
    }


def _call_effect(
    unit_id: str,
    *,
    transfer_kind: str,
    cleanup_bytes: int | None,
    memory_writes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    complete = cleanup_bytes is not None
    writes = [] if memory_writes is None else copy.deepcopy(memory_writes)
    return {
        "format": "stage-a-call-site-effect-v2",
        "unit_id": unit_id,
        "event_index": 0,
        "transfer_kind": transfer_kind,
        "status": "complete" if complete else "incomplete",
        "register_frame": {
            "status": "not_applicable",
            "preserved_registers": [],
        },
        "stack_frame": {
            "status": "complete" if complete else "incomplete",
            "stack_cleanup_bytes": cleanup_bytes,
        },
        "result_frame": {"status": "not_applicable", "outputs": []},
        "memory_frame": {
            "status": "complete" if memory_writes is not None else "not_applicable",
            "preserved": memory_writes == [],
            "writes": writes,
        },
        "abi": None,
        "argument_words": None,
        "dependencies": [],
        "failure_codes": [] if complete else ["call_stack_frame_incomplete"],
    }


def _derive(
    units: list[dict[str, object]],
    *,
    summaries: dict[str, object] | None = None,
    recoveries: list[dict[str, object]] | None = None,
    call_site_effects: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return derive_stack_range_analysis_v2(
        units=units,
        graph=_graph(str(units[0]["id"])),
        launch_assumptions=_launch(),
        pe_sha256=PE_SHA,
        machine_ir_sha256=MACHINE_SHA,
        image_base=IMAGE_BASE,
        size_of_image=IMAGE_SIZE,
        call_summaries=summaries,
        indirect_recoveries=[] if recoveries is None else recoveries,
        call_site_effects=(
            [] if call_site_effects is None else call_site_effects
        ),
    )


class StackRangeAnalysisV2Tests(unittest.TestCase):
    def test_direct_affine_path_emits_binary_bound_range_facts(self) -> None:
        units = [
            _unit("entry", 0x1000, target_rvas=[0x1010], stack_delta=-8, memory_offsets=[-8]),
            _unit("next", 0x1010, memory_offsets=[0, 12]),
        ]

        result = _derive(units)

        self.assertEqual(result["format"], STACK_RANGE_ANALYSIS_V2_FORMAT)
        self.assertEqual(result["cold_replay"]["status"], "complete")
        self.assertEqual(result["entry_offsets"], {"entry": [0], "next": [-8]})
        facts = {row["applies_to_unit_ids"][0]: row for row in result["checked_range_facts"]}
        self.assertEqual((facts["entry"]["offset_start"], facts["entry"]["offset_end"]), (-8, -4))
        self.assertEqual((facts["next"]["offset_start"], facts["next"]["offset_end"]), (0, 16))
        self.assertEqual(facts["next"]["authority_binding"]["pe_sha256"], PE_SHA)
        spatial = {
            (row["unit_id"], row["event_index"]): row
            for row in result["checked_spatial_facts"]
        }
        self.assertEqual(len(spatial), 3)
        self.assertEqual(
            spatial[("next", 1)]["format"],
            CHECKED_STACK_SPATIAL_FACT_V2_FORMAT,
        )
        self.assertEqual(
            (
                spatial[("next", 1)]["minimum_start_offset"],
                spatial[("next", 1)]["maximum_start_offset"],
            ),
            (4, 4),
        )

        replayed = validate_stack_range_analysis_v2(
            result,
            units=units,
            graph=_graph("entry"),
            launch_assumptions=_launch(),
            pe_sha256=PE_SHA,
            machine_ir_sha256=MACHINE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )
        self.assertEqual(
            set(replayed),
            {"event:entry:0", "event:next:0", "event:next:1"},
        )

        corrupted = copy.deepcopy(result)
        corrupted["checked_spatial_facts"][0]["minimum_start_offset"] -= 4
        with self.assertRaisesRegex(ValueError, "does not replay exactly"):
            validate_stack_range_analysis_v2(
                corrupted,
                units=units,
                graph=_graph("entry"),
                launch_assumptions=_launch(),
                pe_sha256=PE_SHA,
                machine_ir_sha256=MACHINE_SHA,
                image_base=IMAGE_BASE,
                size_of_image=IMAGE_SIZE,
            )

    def test_call_summary_stack_writes_receive_event_bound_spatial_facts(
        self,
    ) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _reg("esp")},
            "abi_contract": {
                "template": "pe32-cdecl-v1",
                "argument_words": 0,
                "disposition": "returns",
            },
        }
        unit = _unit(
            "call",
            0x1000,
            stack_delta=None,
            external_events=[call],
        )
        effect = _call_effect(
            "call",
            transfer_kind="external_call",
            cleanup_bytes=0,
            memory_writes=[
                {
                    "base": {"kind": "stack_location", "key": [0xFFFFFFDC]},
                    "size": 4,
                },
                {
                    "base": {"kind": "stack_location", "key": [0xFFFFFFE4]},
                    "size": 2,
                },
            ],
        )

        result = _derive([unit], call_site_effects=[effect])
        facts = result["checked_spatial_facts"]

        self.assertEqual(len(facts), 2)
        self.assertTrue(all(
            row["format"] == CHECKED_CALL_STACK_WRITE_SPATIAL_FACT_V2_FORMAT
            for row in facts
        ))
        self.assertEqual(
            [(row["write_index"], row["address_frame_offset"], row["width_bytes"])
             for row in facts],
            [(0, -36, 4), (1, -28, 2)],
        )
        self.assertTrue(all(row["frame_base_offsets"] == [0] for row in facts))
        replayed = validate_stack_range_analysis_v2(
            result,
            units=[unit],
            graph=_graph("call"),
            launch_assumptions=_launch(),
            pe_sha256=PE_SHA,
            machine_ir_sha256=MACHINE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            call_site_effects=[effect],
        )
        self.assertEqual(
            set(replayed),
            {"call-memory-write:call:0:0", "call-memory-write:call:0:1"},
        )

        corrupted = copy.deepcopy(result)
        corrupted["checked_spatial_facts"][0]["write_index"] = 1
        with self.assertRaisesRegex(ValueError, "does not replay exactly"):
            validate_stack_range_analysis_v2(
                corrupted,
                units=[unit],
                graph=_graph("call"),
                launch_assumptions=_launch(),
                pe_sha256=PE_SHA,
                machine_ir_sha256=MACHINE_SHA,
                image_base=IMAGE_BASE,
                size_of_image=IMAGE_SIZE,
                call_site_effects=[effect],
            )

    def test_call_summary_stack_write_requires_checked_frame_and_span(
        self,
    ) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _reg("esp")},
            "abi_contract": {
                "template": "pe32-cdecl-v1",
                "argument_words": 0,
                "disposition": "returns",
            },
        }
        entry = _unit("entry", 0x1000, target_rvas=[0x1010], stack_delta=None)
        call_unit = _unit(
            "call",
            0x1010,
            stack_delta=None,
            external_events=[call],
        )
        checked = _call_effect(
            "call",
            transfer_kind="external_call",
            cleanup_bytes=0,
            memory_writes=[{
                "base": {"kind": "stack_location", "key": [12]},
                "size": 4,
            }],
        )

        no_frame = _derive([entry, call_unit], call_site_effects=[checked])
        self.assertEqual(no_frame["checked_spatial_facts"], [])

        malformed_spans = (
            {"base": {"kind": "stack_location", "key": [12]}, "size": None},
            {"base": {"kind": "exact", "key": [0x500000]}, "size": 4},
            {"base": {"kind": "stack_location", "key": [0xFFFFE000]}, "size": 4},
        )
        rooted_call = copy.deepcopy(call_unit)
        for span in malformed_spans:
            with self.subTest(span=span):
                effect = _call_effect(
                    "call",
                    transfer_kind="external_call",
                    cleanup_bytes=0,
                    memory_writes=[span],
                )
                result = _derive([rooted_call], call_site_effects=[effect])
                self.assertEqual(result["checked_spatial_facts"], [])

    def test_checked_range_facts_replay_exactly_and_reject_corruption(self) -> None:
        units = [_unit("entry", 0x1000, memory_offsets=[-4])]
        facts = _derive(units)["checked_range_facts"]
        expected = validate_checked_stack_range_facts_v2(
            facts,
            units=units,
            pe_sha256=PE_SHA,
            machine_ir_sha256=MACHINE_SHA,
            rooted_graph_id="rooted-control-graph-v2:fixture",
            launch_assumptions_sha256=canonical_sha256(_launch()),
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )
        self.assertEqual(expected, frozenset({"entry"}))

        corruptions = []
        wrong_span = copy.deepcopy(facts)
        wrong_span[0]["offset_start"] -= 4
        corruptions.append(wrong_span)
        wrong_binary = copy.deepcopy(facts)
        wrong_binary[0]["authority_binding"]["pe_sha256"] = "f" * 64
        corruptions.append(wrong_binary)
        wrong_id = copy.deepcopy(facts)
        wrong_id[0]["id"] = "checked-stack-range-v2:" + "0" * 64
        corruptions.append(wrong_id)

        for corrupted in corruptions:
            with self.subTest(corrupted=corrupted[0]["id"]):
                with self.assertRaises(ValueError):
                    validate_checked_stack_range_facts_v2(
                        corrupted,
                        units=units,
                        pe_sha256=PE_SHA,
                        machine_ir_sha256=MACHINE_SHA,
                        rooted_graph_id="rooted-control-graph-v2:fixture",
                        launch_assumptions_sha256=canonical_sha256(_launch()),
                        image_base=IMAGE_BASE,
                        size_of_image=IMAGE_SIZE,
                    )

        with self.assertRaises(ValueError):
            validate_checked_stack_range_facts_v2(
                facts,
                units=units,
                pe_sha256=PE_SHA,
                machine_ir_sha256=MACHINE_SHA,
                rooted_graph_id="rooted-control-graph-v2:fixture",
                launch_assumptions_sha256="e" * 64,
                image_base=IMAGE_BASE,
                size_of_image=IMAGE_SIZE,
            )

    def test_non_affine_stack_transition_stops_propagation(self) -> None:
        units = [
            _unit("entry", 0x1000, target_rvas=[0x1010], stack_delta=None),
            _unit("next", 0x1010, memory_offsets=[0]),
        ]

        result = _derive(units)

        self.assertNotIn("next", result["entry_offsets"])
        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "non_affine_stack_transition",
            {row["code"] for row in result["frontiers"]},
        )

    def test_checked_frame_pointer_closes_standard_leave_epilogue(self) -> None:
        prologue = _unit(
            "prologue", 0x1000, target_rvas=[0x1010], stack_delta=-4
        )
        prologue["semantics"]["register_writes"] = [{
            "register": "ebp",
            "value": _add(-4),
        }]
        epilogue = _unit(
            "epilogue", 0x1010, target_rvas=[0x1020], stack_delta=None
        )
        epilogue["semantics"]["stack_delta"] = {
            "status": "unknown",
            "expression": _add_register("ebp", 4),
        }
        epilogue["semantics"]["register_writes"] = [{
            "register": "ebp",
            "value": {"op": "load", "address": _reg("ebp"), "width": 4},
        }]
        units = [prologue, epilogue, _unit("next", 0x1020, memory_offsets=[0])]

        result = _derive(units)

        self.assertEqual(result["entry_offsets"]["epilogue"], [-4])
        self.assertEqual(result["entry_offsets"]["next"], [0])
        self.assertNotIn(
            "non_affine_stack_transition",
            {row["code"] for row in result["frontiers"]},
        )

    def test_unwitnessed_frame_pointer_epilogue_still_fails_closed(self) -> None:
        epilogue = _unit(
            "epilogue", 0x1000, target_rvas=[0x1010], stack_delta=None
        )
        epilogue["semantics"]["stack_delta"] = {
            "status": "unknown",
            "expression": _add_register("ebp", 4),
        }
        units = [epilogue, _unit("next", 0x1010, memory_offsets=[0])]

        result = _derive(units)

        self.assertNotIn("next", result["entry_offsets"])
        self.assertIn(
            "non_affine_stack_transition",
            {row["code"] for row in result["frontiers"]},
        )

    def test_frame_pointer_clobber_invalidates_epilogue_relation(self) -> None:
        prologue = _unit(
            "prologue", 0x1000, target_rvas=[0x1010], stack_delta=-4
        )
        prologue["semantics"]["register_writes"] = [{
            "register": "ebp",
            "value": _add(-4),
        }]
        clobber = _unit(
            "clobber", 0x1010, target_rvas=[0x1020], stack_delta=0
        )
        clobber["semantics"]["register_writes"] = [{
            "register": "ebp",
            "value": {"op": "unknown", "width": 32},
        }]
        epilogue = _unit(
            "epilogue", 0x1020, target_rvas=[0x1030], stack_delta=None
        )
        epilogue["semantics"]["stack_delta"] = {
            "status": "unknown",
            "expression": _add_register("ebp", 4),
        }
        units = [
            prologue,
            clobber,
            epilogue,
            _unit("next", 0x1030, memory_offsets=[0]),
        ]

        result = _derive(units)

        self.assertNotIn("next", result["entry_offsets"])
        self.assertIn(
            "non_affine_stack_transition",
            {row["code"] for row in result["frontiers"]},
        )

    def test_checked_stdcall_frame_reaches_continuation(self) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _add(-8)},
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 2,
                "disposition": "returns",
            },
        }
        units = [
            _unit("entry", 0x1000, target_rvas=[0x1010], stack_delta=None, external_events=[call]),
            _unit("next", 0x1010, memory_offsets=[0]),
        ]

        result = _derive(units)

        self.assertEqual(result["entry_offsets"]["next"], [0])

    def test_checked_external_call_effect_does_not_require_raw_disposition(self) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _reg("esp")},
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 0,
            },
        }
        units = [
            _unit(
                "entry",
                0x1000,
                target_rvas=[0x1010],
                stack_delta=None,
                external_events=[call],
            ),
            _unit("next", 0x1010, memory_offsets=[0]),
        ]
        effect = _call_effect(
            "entry",
            transfer_kind="external_call",
            cleanup_bytes=0,
        )

        result = _derive(units, call_site_effects=[effect])

        self.assertEqual(result["entry_offsets"]["next"], [0])
        self.assertNotIn(
            "external_call_frame_incomplete",
            {row["code"] for row in result["frontiers"]},
        )

    def test_terminal_external_transfer_needs_no_return_frame(self) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _reg("esp")},
        }
        units = [
            _unit(
                "tail",
                0x1000,
                target_rvas=[],
                stack_delta=None,
                external_events=[call],
            ),
        ]

        result = _derive(units)

        self.assertEqual(result["entry_offsets"]["tail"], [0])
        self.assertNotIn(
            "external_call_frame_incomplete",
            {row["code"] for row in result["frontiers"]},
        )

    def test_returning_external_transfer_still_needs_a_frame(self) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _reg("esp")},
        }
        units = [
            _unit(
                "call",
                0x1000,
                target_rvas=[0x1010],
                stack_delta=None,
                external_events=[call],
            ),
            _unit("continuation", 0x1010, memory_offsets=[0]),
        ]

        result = _derive(units)

        self.assertNotIn("continuation", result["entry_offsets"])
        self.assertIn(
            "external_call_frame_incomplete",
            {row["code"] for row in result["frontiers"]},
        )

    def test_incomplete_external_call_effect_cannot_use_raw_fallback(self) -> None:
        call = {
            "kind": "external_call",
            "register_inputs": {"esp": _reg("esp")},
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 0,
                "disposition": "returns",
            },
        }
        units = [
            _unit(
                "entry",
                0x1000,
                target_rvas=[0x1010],
                stack_delta=None,
                external_events=[call],
            ),
            _unit("next", 0x1010, memory_offsets=[0]),
        ]

        result = _derive(
            units,
            call_site_effects=[_call_effect(
                "entry",
                transfer_kind="external_call",
                cleanup_bytes=None,
            )],
        )

        self.assertNotIn("next", result["entry_offsets"])
        self.assertIn(
            "external_call_frame_incomplete",
            {row["code"] for row in result["frontiers"]},
        )

    def test_internal_call_requires_summary_only_for_continuation(self) -> None:
        call = {
            "kind": "internal_call",
            "target_rva": 0x2000,
            "register_inputs": {"esp": _add(-4)},
        }
        units = [
            _unit("caller", 0x1000, target_rvas=[0x1010], stack_delta=None, external_events=[call]),
            _unit("continuation", 0x1010, memory_offsets=[0]),
            _unit("callee", 0x2000, memory_offsets=[0]),
        ]

        incomplete = _derive(units)
        self.assertEqual(incomplete["entry_offsets"]["callee"], [-8])
        self.assertNotIn("continuation", incomplete["entry_offsets"])

        complete = _derive(
            units,
            summaries={
                "summaries": [{
                    "status": "complete",
                    "target_rva": 0x2000,
                    "stack_cleanup": {"status": "complete", "stack_delta": 4},
                }]
            },
        )
        self.assertEqual(complete["entry_offsets"]["continuation"], [0])

        partial = _derive(
            units,
            summaries={
                "summaries": [{
                    "status": "incomplete",
                    "target_rva": 0x2000,
                    "stack_cleanup": {"status": "complete", "stack_delta": 4},
                    "register_preservation": {"status": "incomplete"},
                }]
            },
        )
        self.assertEqual(partial["entry_offsets"]["continuation"], [0])

        instruction_only = _derive(
            units,
            summaries={
                "summaries": [{
                    "status": "incomplete",
                    "target_rva": 0x2000,
                    "stack_cleanup": {
                        "status": "incomplete",
                        "stack_delta": None,
                    },
                    "return_instruction_cleanup": {
                        "status": "complete",
                        "cleanup_bytes": 4,
                        "return_unit_ids": ["callee"],
                    },
                }]
            },
        )
        self.assertEqual(instruction_only["entry_offsets"]["continuation"], [0])

        conflicting = _derive(
            units,
            summaries={
                "summaries": [{
                    "status": "incomplete",
                    "target_rva": 0x2000,
                    "stack_cleanup": {"status": "complete", "stack_delta": 0},
                    "return_instruction_cleanup": {
                        "status": "complete",
                        "cleanup_bytes": 4,
                    },
                }]
            },
        )
        self.assertNotIn("continuation", conflicting["entry_offsets"])

    def test_checked_stack_origin_uses_active_callee_frame_base(self) -> None:
        call = {
            "kind": "internal_call",
            "target_rva": 0x2000,
            "register_inputs": {"esp": _add(-4)},
        }
        units = [
            _unit(
                "caller",
                0x1000,
                target_rvas=[0x1010],
                stack_delta=None,
                external_events=[call],
            ),
            _unit("continuation", 0x1010),
            _unit("callee", 0x2000, target_rvas=[0x2010], stack_delta=-8),
            _unit("callee-body", 0x2010, memory_offsets=[0]),
        ]
        units[-1]["semantics"]["memory_events"][0]["address"] = (
            _add_register("ebp", -12)
        )
        access_facts = _checked_stack_access(
            units,
            unit_id="callee-body",
            event_index=0,
            offset=12,
        )
        machine_sha = machine_ir_sha256(units)

        result = derive_stack_range_analysis_v2(
            units=units,
            graph=_graph("caller"),
            launch_assumptions=_launch(),
            pe_sha256=PE_SHA,
            machine_ir_sha256=machine_sha,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            checked_memory_access_facts=access_facts,
            interprocedural_authority_sha256=INTERPROCEDURAL_SHA,
        )

        self.assertEqual(result["entry_offsets"]["callee-body"], [-16])
        self.assertEqual(result["frame_base_offsets"]["callee-body"], [-8])
        fact = next(
            row
            for row in result["checked_spatial_facts"]
            if row["unit_id"] == "callee-body"
        )
        self.assertEqual(
            fact["format"], CHECKED_STACK_ORIGIN_SPATIAL_FACT_V2_FORMAT
        )
        self.assertEqual(fact["frame_base_offsets"], [-8])
        self.assertEqual(
            (fact["minimum_start_offset"], fact["maximum_start_offset"]),
            (4, 4),
        )

        replayed = validate_stack_range_analysis_v2(
            result,
            units=units,
            graph=_graph("caller"),
            launch_assumptions=_launch(),
            pe_sha256=PE_SHA,
            machine_ir_sha256=machine_sha,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            checked_memory_access_facts=access_facts,
            interprocedural_authority_sha256=INTERPROCEDURAL_SHA,
        )
        self.assertIn("event:callee-body:0", replayed)

        with self.assertRaisesRegex(
            ValueError, "interprocedural authority"
        ):
            derive_stack_range_analysis_v2(
                units=units,
                graph=_graph("caller"),
                launch_assumptions=_launch(),
                pe_sha256=PE_SHA,
                machine_ir_sha256=machine_sha,
                image_base=IMAGE_BASE,
                size_of_image=IMAGE_SIZE,
                checked_memory_access_facts=access_facts,
            )

    def test_stack_window_overflow_fails_closed(self) -> None:
        units = [_unit("entry", 0x1000, memory_offsets=[-0x2000])]

        result = _derive(units)

        self.assertEqual(result["checked_range_facts"], [])
        self.assertIn(
            "stack_access_outside_launch_window",
            {row["code"] for row in result["frontiers"]},
        )

    def test_finite_offset_overflow_withholds_partial_entry_authority(self) -> None:
        units = [
            _unit(
                "loop",
                0x1000,
                target_rvas=[0x1000],
                stack_delta=4,
                memory_offsets=[0],
            )
        ]

        result = derive_stack_range_analysis_v2(
            units=units,
            graph=_graph("loop"),
            launch_assumptions=_launch(),
            pe_sha256=PE_SHA,
            machine_ir_sha256=MACHINE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            finite_offset_budget=2,
        )

        self.assertNotIn("loop", result["entry_offsets"])
        self.assertEqual(result["checked_range_facts"], [])
        self.assertIn(
            "stack_offset_alternative_budget_exceeded",
            {row["code"] for row in result["frontiers"]},
        )

    def test_cold_recovered_indirect_external_call_reaches_continuation(self) -> None:
        call = {
            "kind": "indirect_call",
            "target": _reg("edi"),
            "register_inputs": {"esp": _add(-4)},
        }
        units = [
            _unit("caller", 0x1000, target_rvas=[0x1010], stack_delta=None, external_events=[call]),
            _unit("continuation", 0x1010, memory_offsets=[0]),
        ]
        from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2

        exit_id = exact_control_inventory_v2(units)["indirect_exits"][0]["id"]
        result = _derive(
            units,
            recoveries=[{
                "id": exit_id,
                "status": "recovered",
                "kind": "indirect_call",
                "target_unit_ids": [],
                "target_rvas": [],
                "external_targets": [{
                    "argument_words": 1,
                    "disposition": "returns",
                    "abi": {
                        "template": "pe32-stdcall-v1",
                        "callee_cleanup": True,
                    },
                }],
            }],
        )

        self.assertEqual(result["entry_offsets"]["continuation"], [0])

        unresolved = _derive(
            units,
            recoveries=[{
                "id": exit_id,
                "status": "recovered",
                "kind": "indirect_call",
                "target_unit_ids": [],
                "target_rvas": [],
                "external_targets": [{
                    "argument_words": 1,
                    "abi": {
                        "template": "pe32-stdcall-v1",
                        "callee_cleanup": True,
                    },
                }],
            }],
        )
        self.assertNotIn("continuation", unresolved["entry_offsets"])
        self.assertIn(
            "indirect_call_frame_unresolved",
            {row["code"] for row in unresolved["frontiers"]},
        )

    def test_checked_call_effect_carries_stack_frame_across_indirect_call(self) -> None:
        call = {
            "kind": "indirect_call",
            "target": _reg("edi"),
            "register_inputs": {"esp": _add(-4)},
        }
        units = [
            _unit(
                "caller",
                0x1000,
                target_rvas=[0x1010],
                stack_delta=None,
                external_events=[call],
            ),
            _unit("continuation", 0x1010, memory_offsets=[0]),
        ]
        effect = _call_effect(
            "caller",
            transfer_kind="indirect_call",
            cleanup_bytes=4,
        )

        result = _derive(units, call_site_effects=[effect])

        self.assertEqual(result["entry_offsets"]["continuation"], [0])
        self.assertEqual(
            result["binding"]["call_site_effects_sha256"],
            canonical_sha256([effect]),
        )
        self.assertNotIn(
            "indirect_call_frame_unresolved",
            {row["code"] for row in result["frontiers"]},
        )

    def test_incomplete_call_effect_cannot_fall_back_to_recovery_abi(self) -> None:
        call = {
            "kind": "indirect_call",
            "target": _reg("edi"),
            "register_inputs": {"esp": _add(-4)},
        }
        units = [
            _unit(
                "caller",
                0x1000,
                target_rvas=[0x1010],
                stack_delta=None,
                external_events=[call],
            ),
            _unit("continuation", 0x1010, memory_offsets=[0]),
        ]
        from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2

        exit_id = exact_control_inventory_v2(units)["indirect_exits"][0]["id"]
        recovery = {
            "id": exit_id,
            "status": "recovered",
            "kind": "indirect_call",
            "target_unit_ids": [],
            "target_rvas": [],
            "external_targets": [{
                "argument_words": 1,
                "disposition": "returns",
                "abi": {
                    "template": "pe32-stdcall-v1",
                    "callee_cleanup": True,
                },
            }],
        }

        result = _derive(
            units,
            recoveries=[recovery],
            call_site_effects=[_call_effect(
                "caller",
                transfer_kind="indirect_call",
                cleanup_bytes=None,
            )],
        )

        self.assertNotIn("continuation", result["entry_offsets"])
        self.assertIn(
            "indirect_call_frame_unresolved",
            {row["code"] for row in result["frontiers"]},
        )

    def test_call_effect_requires_its_exact_machine_event(self) -> None:
        units = [_unit("entry", 0x1000)]

        with self.assertRaisesRegex(ValueError, "exact stack transition"):
            _derive(
                units,
                call_site_effects=[_call_effect(
                    "entry",
                    transfer_kind="indirect_call",
                    cleanup_bytes=0,
                )],
            )


if __name__ == "__main__":
    unittest.main()
