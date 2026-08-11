from __future__ import annotations

import unittest

from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.internal_call_summaries import (
    INTERNAL_CALL_SUMMARY_FORMAT,
    derive_internal_call_preservation_summaries,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def add(left: object, right: object) -> dict[str, object]:
    return {"op": "add32", "args": [left, right]}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "address": address, "width": 4}


def unit(
    identifier: str,
    rva: int,
    *,
    outcome: str,
    outcome_details: dict[str, object] | None = None,
    disposition: dict[str, object] | None = None,
    writes: list[dict[str, object]] | None = None,
    memory: list[dict[str, object]] | None = None,
    events: list[dict[str, object]] | None = None,
    stack_delta: int | None = None,
) -> dict[str, object]:
    effective_writes = list(writes or [])
    if outcome == "return" and not any(
        write.get("register") == "esp" for write in effective_writes
    ):
        effective_writes.append({
            "register": "esp",
            "value": add(reg("esp"), const(4)),
        })
    result = {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": (
            [{"mnemonic": "ret", "operands": []}]
            if outcome == "return"
            else []
        ),
        "semantics": {
            "outcome": {"kind": outcome, **(outcome_details or {})},
            "register_writes": effective_writes,
            "memory_events": memory or [],
            "external_events": events or [],
            **(
                {"stack_delta": {"status": "derived", "net_bytes": stack_delta}}
                if stack_delta is not None
                else {}
            ),
        },
    }
    if disposition is not None:
        result["control"] = {"disposition": disposition}
    return result


def internal_call(
    target_rva: int, *, return_rva: int | None = None
) -> dict[str, object]:
    result = {
        "kind": "internal_call",
        "target_rva": target_rva,
        "register_inputs": {register: reg(register) for register in REGISTERS},
    }
    if return_rva is not None:
        result["return_rva"] = return_rva
    return result


class InternalCallSummaryTests(unittest.TestCase):
    def test_callee_private_stack_write_does_not_escape_memory_frame(self) -> None:
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": sub(reg("esp"), const(4)),
                        "value": reg("eax"),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["caller_memory_frame"],
            {"status": "complete", "preserved": True, "writes": []},
        )

    def test_caller_stack_write_is_exported_from_memory_frame(self) -> None:
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": add(reg("esp"), const(4)),
                        "value": reg("eax"),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["caller_memory_frame"],
            {
                "status": "complete",
                "preserved": False,
                "writes": [{
                    "base": {"kind": "stack_location", "key": [4]},
                    "size": 4,
                }],
            },
        )

    def test_parametric_out_pointer_write_is_exported(self) -> None:
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee-load",
                    0x2000,
                    outcome="fallthrough",
                    writes=[{
                        "register": "eax",
                        "value": load(add(reg("esp"), const(4))),
                    }],
                ),
                unit(
                    "callee-write",
                    0x2001,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": reg("eax"),
                        "value": const(1),
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee-load", "callee-write"),
            ],
            calls=[self._call_edge("root", "callee-load", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        frame = self._summary(result, "callee-load")["caller_memory_frame"]
        self.assertEqual(frame["status"], "complete")
        self.assertFalse(frame["preserved"])
        self.assertEqual(frame["writes"][0]["base"]["kind"], "parametric_location")
        self.assertEqual(frame["writes"][0]["size"], 4)

    def test_unknown_memory_write_fails_closed(self) -> None:
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": {"op": "unsupported"},
                        "value": const(1),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["caller_memory_frame"],
            {"status": "incomplete", "preserved": False, "writes": []},
        )

    def test_nested_memory_frame_composes_exact_write(self) -> None:
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "wrapper",
                    0x2000,
                    outcome="fallthrough",
                    events=[internal_call(0x3000)],
                ),
                unit("wrapper-return", 0x2001, outcome="return"),
                unit(
                    "leaf",
                    0x3000,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": const(0x440000),
                        "value": const(1),
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("wrapper", "wrapper-return"),
            ],
            calls=[
                self._call_edge("root", "wrapper", 0),
                self._call_edge("wrapper", "leaf", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        expected = {
            "status": "complete",
            "preserved": False,
            "writes": [{
                "base": {"kind": "exact", "key": [0x440000]},
                "size": 4,
            }],
        }
        self.assertEqual(
            self._summary(result, "leaf")["caller_memory_frame"], expected
        )
        self.assertEqual(
            self._summary(result, "wrapper")["caller_memory_frame"], expected
        )

    def test_input_relative_result_is_instantiated_at_call_site(self) -> None:
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{"register": "eax", "value": reg("ecx")}],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        callee = self._summary(result, "callee")
        root = self._summary(result, "root")
        self.assertEqual(
            callee["result_register_origins"]["registers"]["eax"],
            {"kind": "input_register", "register": "ecx"},
        )
        self.assertEqual(
            root["result_register_origins"]["registers"]["eax"],
            {"kind": "input_register", "register": "ecx"},
        )

    def test_declared_internal_contract_is_an_opaque_callee_summary(self) -> None:
        declaration = {
            "status": "complete",
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "register_preservation": {"status": "complete"},
            "result_register_origins": {
                "status": "complete",
                "registers": {
                    "eax": {
                        "kind": "internal_contract_result",
                        "contract_id": "fixture-allocator",
                        "relation": "dynamic_range_base",
                        "nullable": True,
                        "size": {
                            "kind": "input_stack_word",
                            "offset": 4,
                            "scale": 1,
                        },
                    }
                },
            },
            "stack_cleanup": {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
            "return_behavior": {
                "status": "complete",
                "may_return": True,
                "may_not_return": False,
            },
            "reached_units": 0,
            "transfer_evaluations": 0,
            "return_nodes": 0,
            "return_unit_ids": [],
            "nonreturning_nodes": 0,
            "blocker_codes": [],
        }
        units = [
            unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("allocator", 0x2000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("done", 0x1001, outcome="return"),
        ]
        result = derive_internal_call_preservation_summaries(
            units=units,
            roots=["root"],
            direct_edges=[self._edge("root", "done")],
            internal_call_edges=[
                self._call_edge("root", "allocator", 0),
                self._call_edge("allocator", "allocator", 0),
            ],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            declared_summaries={"allocator": declaration},
        )

        allocator = self._summary(result, "allocator")
        self.assertEqual(allocator["status"], "complete")
        self.assertEqual(
            allocator["result_register_origins"]["registers"]["eax"]["kind"],
            "internal_contract_result",
        )
        self.assertEqual(
            allocator["result_register_origins"]["registers"]["eax"]["size"],
            {"kind": "input_stack_word", "offset": 4, "scale": 1},
        )
        self.assertNotIn("allocator", result["recursive_summary_roots"])

    def test_declared_affine_stack_transform_composes_at_call_site(self) -> None:
        declaration = {
            "status": "complete",
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "register_preservation": {"status": "complete"},
            "result_register_origins": {"status": "complete", "registers": {}},
            "stack_cleanup": {
                "status": "complete",
                "stack_delta": None,
                "return_stack_offset": None,
                "transform": {
                    "format": "stage-a-affine-stack-transform-v1",
                    "constant": 0,
                    "register_terms": [
                        {"register": "eax", "coefficient": -1}
                    ],
                },
            },
            "return_behavior": {
                "status": "complete",
                "may_return": True,
                "may_not_return": False,
            },
            "reached_units": 0,
            "transfer_evaluations": 0,
            "return_nodes": 0,
            "return_unit_ids": [],
            "nonreturning_nodes": 0,
            "blocker_codes": [],
        }
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("root-return", 0x1001, outcome="return"),
                unit("outer", 0x2000, outcome="fallthrough", events=[internal_call(0x3000)]),
                unit("outer-return", 0x2001, outcome="return"),
                unit("stack-probe", 0x3000, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                self._edge("root", "root-return"),
                self._edge("outer", "outer-return"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            declared_summaries={"stack-probe": declaration},
        )

        outer = self._summary(result, "outer")
        self.assertEqual(outer["status"], "complete")
        self.assertEqual(
            outer["stack_cleanup"]["transform"],
            declaration["stack_cleanup"]["transform"],
        )

    def test_leaf_callee_preserves_untouched_nonvolatile_registers(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="return"),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(result["format"], INTERNAL_CALL_SUMMARY_FORMAT)
        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["preserved_registers"], ["ebp", "ebx", "edi", "esi"])
        self.assertEqual(summary["return_unit_ids"], ["callee"])

    def test_return_stack_effect_produces_exact_cleanup_summary(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(4)),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"],
            {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
        )

    def test_ret_immediate_produces_callee_cleanup_bytes(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(12)),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"]["stack_delta"], 8
        )

    def test_exact_semantic_stack_deltas_compose_past_opaque_expressions(self) -> None:
        opaque = {"op": "opaque_stack_expression"}
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="fallthrough",
                    writes=[{"register": "esp", "value": opaque}],
                    stack_delta=-8,
                ),
                unit(
                    "callee_return",
                    0x2001,
                    outcome="return",
                    writes=[{"register": "esp", "value": opaque}],
                    stack_delta=12,
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"],
            {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
        )

    def test_contradictory_semantic_stack_delta_fails_closed(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(4)),
                    }],
                    stack_delta=8,
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertIn("stack_delta_evidence_inconsistent", summary["blocker_codes"])
        self.assertIn("return_stack_delta_unknown", summary["blocker_codes"])

    def test_exact_stack_delta_does_not_close_unresolved_call_control(self) -> None:
        event = {
            "kind": "indirect_call",
            "register_inputs": {register: reg(register) for register in REGISTERS},
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="fallthrough",
                    events=[event],
                    stack_delta=0,
                ),
                unit("callee_return", 0x2001, outcome="return", stack_delta=4),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["stack_cleanup"]["status"], "complete")
        self.assertIn("indirect_call_target_unresolved", summary["blocker_codes"])
        self.assertIn("call_return_behavior_incomplete", summary["blocker_codes"])

    def test_explicit_write_removes_only_that_preservation_claim(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{"register": "esi", "value": const(7)}],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["preserved_registers"],
            ["ebp", "ebx", "edi"],
        )

    def test_unsupported_instruction_invalidates_its_decoded_register_writes(self) -> None:
        callee = unit("callee", 0x2000, outcome="return")
        callee["instructions"] = [{
            "mnemonic": "inc",
            "registers_written": ["eflags", "esi"],
            "operands": [{
                "kind": "register",
                "name": "esi",
                "access": "read_write",
            }],
        }]
        callee["semantics"]["instruction_effect_schedule"] = {
            "status": "incomplete",
            "blockers": [{"index": 0}],
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                callee,
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertNotIn("esi", self._summary(result, "callee")["preserved_registers"])

    def test_stack_save_and_restore_recovers_register_origin(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "save",
                    0x2000,
                    outcome="fallthrough",
                    writes=[{"register": "esp", "value": sub(reg("esp"), const(4))}],
                    memory=[{
                        "kind": "write",
                        "address": sub(reg("esp"), const(4)),
                        "value": reg("esi"),
                        "width": 4,
                    }],
                ),
                unit(
                    "restore",
                    0x2001,
                    outcome="return",
                    writes=[
                        {"register": "esi", "value": load(reg("esp"))},
                        {"register": "esp", "value": add(reg("esp"), const(8))},
                    ],
                ),
            ],
            direct=[self._edge("root", "done"), self._edge("save", "restore")],
            calls=[self._call_edge("root", "save", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertIn("esi", self._summary(result, "save")["preserved_registers"])

    def test_all_return_paths_must_preserve_the_register(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("branch", 0x2000, outcome="branch"),
                unit("same", 0x2001, outcome="return"),
                unit(
                    "different",
                    0x2002,
                    outcome="return",
                    writes=[{"register": "esi", "value": const(1)}],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("branch", "same"),
                self._edge("branch", "different"),
            ],
            calls=[self._call_edge("root", "branch", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertNotIn("esi", self._summary(result, "branch")["preserved_registers"])

    def test_nested_direct_calls_compose_at_fixed_point(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("outer", 0x2000, outcome="fallthrough", events=[internal_call(0x3000)]),
                unit("outer_return", 0x2001, outcome="return"),
                unit("inner", 0x3000, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer", "outer_return"),
            ],
            calls=[
                self._call_edge("root", "outer", 0),
                self._call_edge("outer", "inner", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(result["fixed_point_rounds"], 1)
        self.assertIn("esi", self._summary(result, "inner")["preserved_registers"])
        self.assertIn("esi", self._summary(result, "outer")["preserved_registers"])

    def test_checked_register_atom_crosses_incomplete_nested_summary(self) -> None:
        partial = {
            "status": "incomplete",
            "preserved_registers": ["esi"],
            "register_preservation": {
                "status": "incomplete",
                "checked_preserved_registers": ["esi"],
            },
            "result_register_origins": {"status": "incomplete", "registers": {}},
            "result_memory_origins": {"status": "incomplete", "locations": []},
            "caller_memory_frame": {
                "status": "incomplete",
                "preserved": False,
                "writes": [],
            },
            "stack_cleanup": {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
            "return_behavior": {
                "status": "complete",
                "may_return": True,
                "may_not_return": False,
            },
            "reached_units": 0,
            "transfer_evaluations": 0,
            "return_nodes": 1,
            "return_unit_ids": ["leaf"],
            "nonreturning_nodes": 0,
            "blocker_codes": ["memory_frame_unknown"],
        }
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("wrapper", 0x2000, outcome="fallthrough", events=[internal_call(0x3000)]),
                unit("wrapper-return", 0x2001, outcome="return"),
                unit("leaf", 0x3000, outcome="return"),
                unit("done", 0x1001, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("wrapper", "wrapper-return"),
            ],
            internal_call_edges=[
                self._call_edge("root", "wrapper", 0),
                self._call_edge("wrapper", "leaf", 0),
            ],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            declared_summaries={"leaf": partial},
        )

        wrapper = self._summary(result, "wrapper")
        self.assertEqual(wrapper["register_preservation"]["status"], "incomplete")
        self.assertEqual(
            wrapper["register_preservation"]["checked_preserved_registers"],
            ["esi"],
        )
        self.assertEqual(wrapper["preserved_registers"], ["esi"])
        self.assertEqual(self._summary(result, "root")["preserved_registers"], ["esi"])

    def test_malformed_partial_register_inventory_fails_closed(self) -> None:
        partial = {
            "status": "incomplete",
            "preserved_registers": ["esi"],
            "register_preservation": {
                "status": "incomplete",
                "checked_preserved_registers": ["edi"],
            },
            "result_register_origins": {"status": "incomplete", "registers": {}},
            "result_memory_origins": {"status": "incomplete", "locations": []},
            "stack_cleanup": {"status": "complete", "stack_delta": 0},
            "return_behavior": {
                "status": "complete",
                "may_return": True,
                "may_not_return": False,
            },
            "blocker_codes": ["fixture_incomplete"],
        }
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("leaf", 0x2000, outcome="return"),
                unit("done", 0x1001, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[self._edge("root", "done")],
            internal_call_edges=[self._call_edge("root", "leaf", 0)],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            declared_summaries={"leaf": partial},
        )

        self.assertEqual(self._summary(result, "root")["preserved_registers"], [])

    def test_exact_direct_call_event_does_not_require_redundant_edge(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="return"),
            ],
            direct=[self._edge("root", "done")],
            calls=[],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(result["counts"]["call_targets"], 1)
        self.assertEqual(self._summary(result, "callee")["status"], "complete")

    def test_ambiguous_direct_call_rva_fails_closed(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee-a", 0x2000, outcome="return"),
                unit("callee-b", 0x2000, outcome="return"),
            ],
            direct=[self._edge("root", "done")],
            calls=[],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(result["counts"]["call_targets"], 0)
        self.assertIn(
            "internal_call_target_unresolved",
            self._summary(result, "root")["blocker_codes"],
        )

    def test_conflicting_direct_call_edge_fails_closed(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("decoded-target", 0x2000, outcome="return"),
                unit("edge-target", 0x3000, outcome="return"),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "edge-target", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(result["counts"]["call_targets"], 0)
        self.assertIn(
            "internal_call_target_unresolved",
            self._summary(result, "root")["blocker_codes"],
        )

    def test_deep_acyclic_call_graph_is_not_round_depth_limited(self) -> None:
        depth = 80
        units = [
            unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("done", 0x1001, outcome="return"),
        ]
        direct = [self._edge("root", "done")]
        for index in range(depth):
            identifier = f"callee-{index}"
            rva = 0x2000 + index * 0x10
            if index + 1 == depth:
                units.append(unit(identifier, rva, outcome="return"))
                continue
            continuation = f"return-{index}"
            units.extend([
                unit(
                    identifier,
                    rva,
                    outcome="fallthrough",
                    events=[internal_call(rva + 0x10)],
                ),
                unit(continuation, rva + 1, outcome="return"),
            ])
            direct.append(self._edge(identifier, continuation))

        result = derive_internal_call_preservation_summaries(
            units=units,
            roots=["root"],
            direct_edges=direct,
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            max_fixed_point_rounds=1,
        )

        self.assertTrue(result["fixed_point_complete"])
        self.assertEqual(result["fixed_point_rounds"], 1)
        self.assertEqual(result["counts"]["call_targets"], depth)
        self.assertEqual(result["counts"]["incomplete_summaries"], 0)

    def test_acyclic_diamond_is_not_classified_as_recursive(self) -> None:
        result = derive_internal_call_preservation_summaries(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit("done", 0x1001, outcome="return"),
                unit(
                    "a",
                    0x2000,
                    outcome="fallthrough",
                    events=[internal_call(0x3000)],
                ),
                unit("a-call-b", 0x2001, outcome="fallthrough", events=[internal_call(0x4000)]),
                unit("a-return", 0x2002, outcome="return"),
                unit(
                    "b",
                    0x3000,
                    outcome="fallthrough",
                    events=[internal_call(0x4000)],
                ),
                unit("b-return", 0x3001, outcome="return"),
                unit("c", 0x4000, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("a", "a-call-b"),
                self._edge("a-call-b", "a-return"),
                self._edge("b", "b-return"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            max_fixed_point_rounds=1,
        )

        self.assertEqual(result["recursive_summary_roots"], [])
        self.assertTrue(result["fixed_point_complete"])
        self.assertEqual(result["counts"]["incomplete_summaries"], 0)

    def test_recursive_direct_calls_without_a_base_case_are_nonreturning(self) -> None:
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("done", 0x1001, outcome="return"),
                unit("a", 0x2000, outcome="fallthrough", events=[internal_call(0x3000)]),
                unit("a-return", 0x2001, outcome="return"),
                unit("b", 0x3000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("b-return", 0x3001, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("a", "a-return"),
                self._edge("b", "b-return"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
        )

        self.assertEqual(result["recursive_summary_roots"], ["a", "b"])
        for target in ("a", "b"):
            summary = self._summary(result, target)
            self.assertEqual(summary["status"], "complete", summary)
            self.assertEqual(
                summary["return_behavior"],
                {"status": "complete", "may_return": False, "may_not_return": True},
            )
            self.assertEqual(summary["recursive_induction"]["status"], "complete")

    def test_recursive_component_discovers_and_composes_base_returns(self) -> None:
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("done", 0x1001, outcome="return"),
                unit("a", 0x2000, outcome="branch"),
                unit("a-base", 0x2001, outcome="return"),
                unit("a-recurse", 0x2002, outcome="fallthrough", events=[internal_call(0x3000)]),
                unit("a-after", 0x2003, outcome="return"),
                unit("b", 0x3000, outcome="branch"),
                unit("b-base", 0x3001, outcome="return"),
                unit("b-recurse", 0x3002, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("b-after", 0x3003, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("a", "a-base"),
                self._edge("a", "a-recurse"),
                self._edge("a-recurse", "a-after"),
                self._edge("b", "b-base"),
                self._edge("b", "b-recurse"),
                self._edge("b-recurse", "b-after"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
        )

        self.assertTrue(result["fixed_point_complete"])
        self.assertGreaterEqual(result["fixed_point_rounds"], 2)
        for target in ("a", "b"):
            summary = self._summary(result, target)
            self.assertEqual(summary["status"], "complete", summary)
            self.assertEqual(summary["stack_cleanup"]["stack_delta"], 0)
            self.assertEqual(
                summary["return_behavior"],
                {"status": "complete", "may_return": True, "may_not_return": True},
            )
            self.assertEqual(
                summary["preserved_registers"],
                ["ebp", "ebx", "edi", "esi"],
            )

    def test_recursive_component_iterates_preservation_to_stability(self) -> None:
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("done", 0x1001, outcome="return"),
                unit("callee", 0x2000, outcome="branch"),
                unit("base", 0x2001, outcome="return"),
                unit("recurse", 0x2002, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "after",
                    0x2003,
                    outcome="return",
                    writes=[{"register": "ebx", "value": const(7)}],
                ),
            ],
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("callee", "base"),
                self._edge("callee", "recurse"),
                self._edge("recurse", "after"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "complete", summary)
        self.assertNotIn("ebx", summary["preserved_registers"])
        self.assertGreaterEqual(summary["recursive_induction"]["rounds"], 3)

    def test_nested_cdecl_call_composes_caller_cleanup(self) -> None:
        call = internal_call(0x3000)
        call["register_inputs"]["esp"] = sub(reg("esp"), const(8))
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("outer_call", 0x2000, outcome="fallthrough", events=[call]),
                unit(
                    "outer_return",
                    0x2001,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(12)),
                    }],
                ),
                unit("inner", 0x3000, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer_call", "outer_return"),
            ],
            calls=[
                self._call_edge("root", "outer_call", 0),
                self._call_edge("outer_call", "inner", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        outer = self._summary(result, "outer_call")
        self.assertEqual(outer["status"], "complete")
        self.assertEqual(outer["stack_cleanup"]["stack_delta"], 0)

    def test_nested_stdcall_ret_immediate_composes_callee_cleanup(self) -> None:
        call = internal_call(0x3000)
        call["register_inputs"]["esp"] = sub(reg("esp"), const(8))
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("outer_call", 0x2000, outcome="fallthrough", events=[call]),
                unit("outer_return", 0x2001, outcome="return"),
                unit(
                    "inner",
                    0x3000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(12)),
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer_call", "outer_return"),
            ],
            calls=[
                self._call_edge("root", "outer_call", 0),
                self._call_edge("outer_call", "inner", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        outer = self._summary(result, "outer_call")
        self.assertEqual(outer["status"], "complete")
        self.assertEqual(outer["stack_cleanup"]["stack_delta"], 0)

    def test_inconsistent_return_stack_deltas_fail_closed(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="branch"),
                unit("cdecl_return", 0x2001, outcome="return"),
                unit(
                    "stdcall_return",
                    0x2002,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(12)),
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "cdecl_return"),
                self._edge("callee", "stdcall_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["stack_cleanup"]["status"], "incomplete")
        self.assertEqual(summary["stack_cleanup"]["return_stack_offsets"], [4, 12])
        self.assertIn("inconsistent_return_stack_delta", summary["blocker_codes"])

    def test_unresolved_indirect_call_return_behavior_fails_closed(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="fallthrough",
                    events=[{
                        "kind": "indirect_call",
                        "register_inputs": {
                            register: reg(register) for register in REGISTERS
                        },
                    }],
                ),
                unit("callee_return", 0x2001, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(summary["return_behavior"]["status"], "incomplete")
        self.assertIn("indirect_call_target_unresolved", summary["blocker_codes"])
        self.assertIn("call_return_behavior_incomplete", summary["blocker_codes"])

    def test_caller_spill_survives_nested_call_outside_argument_frame(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "save",
                    0x2000,
                    outcome="fallthrough",
                    writes=[{"register": "esp", "value": sub(reg("esp"), const(4))}],
                    memory=[{
                        "kind": "write",
                        "address": sub(reg("esp"), const(4)),
                        "value": reg("ebx"),
                        "width": 4,
                    }],
                ),
                unit(
                    "nested_call",
                    0x2001,
                    outcome="fallthrough",
                    events=[internal_call(0x3000)],
                ),
                unit(
                    "restore",
                    0x2002,
                    outcome="return",
                    writes=[
                        {"register": "ebx", "value": load(reg("esp"))},
                        {"register": "esp", "value": add(reg("esp"), const(8))},
                    ],
                ),
                unit(
                    "inner",
                    0x3000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(4)),
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("save", "nested_call"),
                self._edge("nested_call", "restore"),
            ],
            calls=[
                self._call_edge("root", "save", 0),
                self._call_edge("nested_call", "inner", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertIn("ebx", self._summary(result, "save")["preserved_registers"])

    def test_parent_can_restore_frame_after_child_with_unknown_stack_delta(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "outer_save",
                    0x2000,
                    outcome="fallthrough",
                    writes=[{"register": "ebp", "value": reg("esp")}],
                ),
                unit(
                    "outer_call",
                    0x2001,
                    outcome="fallthrough",
                    events=[internal_call(0x3000)],
                ),
                unit(
                    "outer_restore",
                    0x2002,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("ebp"), const(4)),
                    }],
                ),
                unit(
                    "inner_dynamic",
                    0x3000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": {
                            "op": "sub32",
                            "args": [reg("esp"), reg("eax")],
                        },
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer_save", "outer_call"),
                self._edge("outer_call", "outer_restore"),
            ],
            calls=[
                self._call_edge("root", "outer_save", 0),
                self._call_edge("outer_call", "inner_dynamic", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        inner = self._summary(result, "inner_dynamic")
        outer = self._summary(result, "outer_save")
        self.assertEqual(inner["status"], "incomplete")
        self.assertEqual(inner["register_preservation"]["status"], "complete")
        self.assertIn("ebp", inner["preserved_registers"])
        self.assertEqual(outer["status"], "complete")
        self.assertEqual(outer["stack_cleanup"]["stack_delta"], 0)

    def test_profiled_external_call_preserves_nonvolatile_registers(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "GetTickCount")
        event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "register_inputs": {register: reg(register) for register in REGISTERS},
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="fallthrough", events=[event]),
                unit("callee_return", 0x2001, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: self._selected_abi(identity)},
        )

        self.assertIn("esi", self._summary(result, "callee")["preserved_registers"])

    def test_allocator_result_origin_composes_through_internal_wrapper(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "HeapAlloc")
        event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "register_inputs": {register: reg(register) for register in REGISTERS},
        }
        selected = self._selected_abi(
            identity,
            argument_words=3,
            contract={
                "result_register_relations": [{
                    "register": "eax",
                    "relation": "dynamic_range_base",
                    "nullable": True,
                }],
            },
        )
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("wrapper", 0x2000, outcome="fallthrough", events=[event]),
                unit("wrapper_return", 0x2001, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("wrapper", "wrapper_return"),
            ],
            calls=[self._call_edge("root", "wrapper", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: selected},
        )

        wrapper = self._summary(result, "wrapper")
        self.assertEqual(wrapper["status"], "complete")
        self.assertEqual(
            wrapper["result_register_origins"]["registers"]["eax"],
            {
                "kind": "external_result",
                "producer_unit_id": "wrapper",
                "event_index": 0,
                "import": {"dll": "kernel32.dll", "symbol": "HeapAlloc"},
                "relation": "dynamic_range_base",
                "nullable": True,
            },
        )

    def test_profiled_cdecl_call_composes_explicit_caller_cleanup(self) -> None:
        identity = MachineImportIdentity("msvcrt.dll", "symbol", "puts")
        event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "register_inputs": {
                **{register: reg(register) for register in REGISTERS},
                "esp": sub(reg("esp"), const(4)),
            },
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="fallthrough", events=[event]),
                unit(
                    "callee_return",
                    0x2001,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(8)),
                    }],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={
                identity: self._selected_abi(
                    identity,
                    argument_words=1,
                    template="pe32-cdecl-v1",
                )
            },
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["stack_cleanup"]["stack_delta"], 0)

    def test_checked_termination_closes_one_path_beside_a_return(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "ExitProcess")
        terminating_event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "return_rva": 0x2003,
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="branch"),
                unit(
                    "return",
                    0x2001,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(4)),
                    }],
                ),
                unit(
                    "terminate",
                    0x2002,
                    outcome="fallthrough",
                    outcome_details={"target_rva": 0x2003},
                    disposition={
                        "kind": "terminates_after_external_event",
                        "authority": "external_profile_machine_import_contract",
                    },
                    events=[terminating_event],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "return"),
                self._edge("callee", "terminate"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: self._selected_abi(identity, argument_words=1)},
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["blocker_codes"], [])
        self.assertEqual(summary["return_nodes"], 1)
        self.assertEqual(summary["nonreturning_nodes"], 1)
        self.assertEqual(
            summary["return_behavior"],
            {"status": "complete", "may_return": True, "may_not_return": True},
        )

    def test_nonreturning_internal_call_suppresses_its_continuation(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "ExitProcess")
        terminating_event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "return_rva": 0x3001,
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "outer",
                    0x2000,
                    outcome="fallthrough",
                    outcome_details={"target_rva": 0x2001},
                    events=[internal_call(0x3000, return_rva=0x2001)],
                ),
                unit("dead_continuation", 0x2001, outcome="fallthrough"),
                unit(
                    "terminal",
                    0x3000,
                    outcome="fallthrough",
                    outcome_details={"target_rva": 0x3001},
                    disposition={
                        "kind": "terminates_after_external_event",
                        "authority": "external_profile_machine_import_contract",
                    },
                    events=[terminating_event],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer", "dead_continuation"),
            ],
            calls=[
                self._call_edge("root", "outer", 0),
                self._call_edge("outer", "terminal", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: self._selected_abi(identity, argument_words=1)},
        )

        terminal = self._summary(result, "terminal")
        outer = self._summary(result, "outer")
        self.assertEqual(terminal["status"], "complete")
        self.assertEqual(terminal["return_nodes"], 0)
        self.assertEqual(
            terminal["return_behavior"],
            {"status": "complete", "may_return": False, "may_not_return": True},
        )
        self.assertEqual(outer["status"], "complete")
        self.assertEqual(outer["reached_units"], 1)
        self.assertEqual(outer["return_nodes"], 0)
        self.assertEqual(outer["nonreturning_nodes"], 1)

    def test_mixed_nested_call_propagates_return_and_nonreturn_paths(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "ExitProcess")
        terminating_event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "return_rva": 0x3003,
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "outer",
                    0x2000,
                    outcome="fallthrough",
                    outcome_details={"target_rva": 0x2001},
                    events=[internal_call(0x3000, return_rva=0x2001)],
                ),
                unit("outer_return", 0x2001, outcome="return"),
                unit("inner", 0x3000, outcome="branch"),
                unit("inner_return", 0x3001, outcome="return"),
                unit(
                    "inner_terminate",
                    0x3002,
                    outcome="fallthrough",
                    outcome_details={"target_rva": 0x3003},
                    disposition={
                        "kind": "terminates_after_external_event",
                        "authority": "external_profile_machine_import_contract",
                    },
                    events=[terminating_event],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer", "outer_return"),
                self._edge("inner", "inner_return"),
                self._edge("inner", "inner_terminate"),
            ],
            calls=[
                self._call_edge("root", "outer", 0),
                self._call_edge("outer", "inner", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: self._selected_abi(identity, argument_words=1)},
        )

        outer = self._summary(result, "outer")
        self.assertEqual(outer["status"], "complete")
        self.assertEqual(
            outer["return_behavior"],
            {"status": "complete", "may_return": True, "may_not_return": True},
        )

    def test_profiled_external_tail_jump_contributes_a_return_path(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "GetACP")
        tail_event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "return_rva": 0x2003,
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="branch"),
                unit(
                    "return",
                    0x2001,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(4)),
                    }],
                ),
                unit(
                    "tail",
                    0x2002,
                    outcome="external_jump",
                    outcome_details={"dll": identity.dll, "symbol": identity.value},
                    events=[tail_event],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "return"),
                self._edge("callee", "tail"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: self._selected_abi(identity, argument_words=0)},
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["return_nodes"], 2)
        self.assertEqual(
            summary["return_behavior"],
            {"status": "complete", "may_return": True, "may_not_return": False},
        )
        self.assertEqual(
            summary["stack_cleanup"],
            {"status": "complete", "stack_delta": 0, "return_stack_offset": 4},
        )
        self.assertEqual(
            summary["preserved_registers"], ["ebp", "ebx", "edi", "esi"]
        )

    def test_unprofiled_external_tail_jump_fails_closed(self) -> None:
        identity = MachineImportIdentity("unknown.dll", "symbol", "Unknown")
        event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "return_rva": 0x2001,
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="external_jump",
                    outcome_details={"dll": identity.dll, "symbol": identity.value},
                    events=[event],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertIn("unterminated_control_path", summary["blocker_codes"])
        self.assertIn("return_inventory_empty", summary["blocker_codes"])

    def test_recovered_fixed_arity_import_composes_stack_cleanup(self) -> None:
        identity = MachineImportIdentity("user32.dll", "symbol", "ShowWindow")
        event = {
            "kind": "indirect_call",
            "register_inputs": {
                **{register: reg(register) for register in REGISTERS},
                "esp": sub(reg("esp"), const(8)),
            },
        }
        units = [
            unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("callee", 0x2000, outcome="fallthrough", events=[event]),
            unit(
                "callee_return",
                0x2001,
                outcome="return",
                writes=[{
                    "register": "esp",
                    "value": add(reg("esp"), const(4)),
                }],
            ),
            unit("done", 0x1001, outcome="return"),
        ]
        result = derive_internal_call_preservation_summaries(
            units=units,
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            internal_call_edges=[self._call_edge("root", "callee", 0)],
            recovered_indirect_targets=[{
                "id": "exit:callee",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "import": {"dll": identity.dll, "symbol": identity.value},
                }],
            }],
            indirect_exits=[{
                "id": "exit:callee",
                "source_unit_id": "callee",
                "source_event_index": 0,
                "kind": "indirect_call",
            }],
            import_abis={identity: self._selected_abi(identity, argument_words=2)},
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"],
            {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
        )

    def test_unresolved_indirect_jump_fails_closed(self) -> None:
        units = [
            unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("callee", 0x2000, outcome="indirect_jump"),
            unit("done", 0x1001, outcome="return"),
        ]
        result = derive_internal_call_preservation_summaries(
            units=units,
            roots=["root"],
            direct_edges=[self._edge("root", "done")],
            internal_call_edges=[self._call_edge("root", "callee", 0)],
            recovered_indirect_targets=[],
            indirect_exits=[{
                "id": "exit",
                "source_unit_id": "callee",
                "source_event_index": None,
                "kind": "indirect_jump",
            }],
            import_abis={},
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertIn("unresolved_indirect_jump", summary["blocker_codes"])
        self.assertEqual(summary["preserved_registers"], [])
        self.assertEqual(summary["return_instruction_cleanup"]["status"], "incomplete")
        self.assertIn(
            "return_instruction_indirect_frontier_open",
            summary["return_instruction_cleanup"]["blocker_codes"],
        )

    def test_return_instruction_cleanup_is_independent_of_other_families(
        self,
    ) -> None:
        unknown_external = {
            "kind": "external_call",
            "dll": "unknown.dll",
            "symbol": "OpaqueCall",
            "register_inputs": {register: reg(register) for register in REGISTERS},
        }
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee",
                    0x2000,
                    outcome="fallthrough",
                    events=[unknown_external],
                ),
                unit("callee-return", 0x2001, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee-return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertEqual(
            summary["return_instruction_cleanup"],
            {
                "status": "complete",
                "cleanup_bytes": 0,
                "return_unit_ids": ["callee-return"],
                "reached_units": 2,
                "blocker_codes": [],
            },
        )

    def test_structural_nonreturn_is_independent_of_nested_call_frame(self) -> None:
        unknown_external = {
            "kind": "external_call",
            "dll": "unknown.dll",
            "symbol": "OpaqueCall",
            "register_inputs": {
                register: reg(register) for register in REGISTERS
            },
        }
        result = self._derive(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "callee",
                    0x2000,
                    outcome="fallthrough",
                    events=[unknown_external],
                ),
                unit("terminal", 0x2001, outcome="halt"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "terminal"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertIn("external_call_abi_unresolved", summary["blocker_codes"])
        self.assertEqual(summary["return_instruction_cleanup"], {
            "status": "not_applicable",
            "cleanup_bytes": None,
            "return_unit_ids": [],
            "reached_units": 2,
            "blocker_codes": [],
        })
        self.assertEqual(summary["return_behavior"], {
            "status": "complete",
            "may_return": False,
            "may_not_return": True,
        })

    def _derive(
        self,
        *,
        units: list[dict[str, object]],
        direct: list[dict[str, object]],
        calls: list[dict[str, object]],
        extra_units: list[dict[str, object]],
        import_abis: dict[MachineImportIdentity, SelectedImportABI] | None = None,
    ) -> dict[str, object]:
        return derive_internal_call_preservation_summaries(
            units=[*units, *extra_units],
            roots=["root"],
            direct_edges=direct,
            internal_call_edges=calls,
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis=import_abis or {},
        )

    @staticmethod
    def _edge(source: str, target: str) -> dict[str, object]:
        return {
            "kind": "direct_control",
            "source_unit_id": source,
            "resolved_unit_id": target,
            "status": "resolved",
        }

    @staticmethod
    def _call_edge(source: str, target: str, event_index: int) -> dict[str, object]:
        return {
            "kind": "internal_call",
            "source_unit_id": source,
            "source_event_index": event_index,
            "resolved_unit_id": target,
            "status": "resolved",
        }

    @staticmethod
    def _summary(result: dict[str, object], target: str) -> dict[str, object]:
        summaries = result["summaries"]
        assert isinstance(summaries, list)
        return next(row for row in summaries if row["target_unit_id"] == target)

    @staticmethod
    def _selected_abi(
        identity: MachineImportIdentity,
        *,
        argument_words: int | None = None,
        template: str = "pe32-stdcall-v1",
        contract: dict[str, object] | None = None,
    ) -> SelectedImportABI:
        abi = resolve_machine_call_abi(template)
        assert abi is not None
        return SelectedImportABI(
            identity=identity,
            abi=abi,
            profile_id="test",
            profile_sha256="0" * 64,
            entry_key="test",
            entry_index=0,
            argument_words=argument_words,
            contract=contract,
        )


if __name__ == "__main__":
    unittest.main()
