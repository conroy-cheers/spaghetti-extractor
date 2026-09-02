from __future__ import annotations

import json
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from typing import Any

from spaghetti_extractor.transfer.closure import (
    ExecutionClosureContextV1,
    execution_closure_context_with_roots_v1,
    _execution_closure_kernel_context_payload_v1,
    _reference_state_kernel_payload_v1,
    build_module_execution_closure_v1,
    check_module_execution_closure_v1,
    join_reference_states_v1,
    write_module_execution_closure_v1,
)
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.transfer.formats import EXECUTABLE_TRANSFER_PLAN_FORMAT
from spaghetti_extractor.transfer.exception_semantics import (
    CheckedExceptionTransitionV1,
)
from spaghetti_extractor.transfer.operations import operation_registry_payload_v2
from spaghetti_extractor.transfer.operations import (
    EFFECT_OPERATIONS_V2,
    EXPRESSION_OPERATIONS_V2,
    TERMINATOR_OPERATIONS_V2,
)
from spaghetti_extractor.transfer.plan import _transfer_from_payload
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.transfer.provenance import (
    CONFLICT_REFERENCE_V1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    UNKNOWN_SCALAR_REFERENCE_V1,
    ReferenceAtomV1,
    ReferenceCatalogV1,
    ObjectRangeV1,
    ReferenceStateV1,
    ReferenceValueV1,
    ScalarFlagRelationV1,
    apply_reference_effects_v1,
    finite_reference_value_v1,
    interpret_reference_expressions_v1,
)
from spaghetti_extractor.transfer.x87 import (
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
    typed_x87_operation_from_micro_op,
)

try:
    import spaghetti_extractor_transfer_native as native
except ImportError:  # pragma: no cover - host shells need not carry the extension
    native = None
else:  # pragma: no cover - an older installed extension is also unavailable
    if not all(hasattr(native, name) for name in (
        "join_reference_state_batches", "inspect_reference_transfer_plan",
        "inspect_reference_closure_inputs",
        "evaluate_reference_root_expressions",
        "evaluate_reference_root_effects",
        "evaluate_reference_closure_frontier",
        "evaluate_reference_closure_summary",
        "evaluate_reference_closure_receipt",
        "REFERENCE_KERNEL_OPERATION_REGISTRY_SHA256",
    )):
        native = None


def _value_payload(value: ReferenceValueV1) -> dict[str, Any]:
    return value.payload()


def _key_payload(key: tuple[str, str, int, int]) -> dict[str, Any]:
    return {
        "kind": key[0],
        "identity": key[1],
        "offset": key[2],
        "width": key[3],
    }


def _native_joins(
    cases: list[tuple[ReferenceStateV1, ReferenceStateV1]],
    *,
    baseline: dict[tuple[str, str, int, int], ReferenceValueV1],
    alternative_limit: int = 16,
) -> list[dict[str, Any]]:
    assert native is not None
    payload = {
        "alternative_limit": alternative_limit,
        "baseline_memory": [
            {**_key_payload(key), "value": _value_payload(value)}
            for key, value in sorted(baseline.items())
        ],
        "cases": [
            {
                "left": _reference_state_kernel_payload_v1(left),
                "right": _reference_state_kernel_payload_v1(right),
            }
            for left, right in cases
        ],
    }
    return json.loads(native.join_reference_state_batches(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ))["results"]


@unittest.skipIf(native is None, "native extension is unavailable")
class NativeReferenceKernelTests(unittest.TestCase):
    @staticmethod
    def _minimal_transfer_plan() -> dict[str, Any]:
        registry_sha256 = canonical_sha256_v3(operation_registry_payload_v2())
        plan = {
            "format": EXECUTABLE_TRANSFER_PLAN_FORMAT,
            "status": "complete",
            "bindings": {},
            "unit_inventory": [],
            "transfers": [{
                "identity": "semantic-transfer:native-fixture",
                "source": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1001,
                    "contract_sha256": "a" * 64,
                    "instruction_bytes_sha256": "b" * 64,
                    "unit_ir_sha256": "e" * 64,
                },
                "expressions": [{
                    "id": 0,
                    "op": "const",
                    "operands": [],
                    "result_sort": "bitvector",
                    "width_bits": 32,
                    "parameters": {
                        "aux": 0,
                        "immediate": 7,
                        "identity": None,
                    },
                }],
                "effects": [{
                    "id": 0,
                    "op": "set_reg",
                    "operands": [0],
                    "parameters": {"aux": 0},
                }],
                "calls": [],
                "exception_occurrences": [],
                "x87_intrinsics": [],
                "terminator": {
                    "op": "outcome_return",
                    "operands": [0],
                    "parameters": {"aux": 0},
                },
            }],
            "direct_control_edges": [],
            "finite_control_routes": [],
            "atomic_effect_authority": [],
            "entry_targets": [0x1000],
            "runtime_provider_requirements": [],
            "operation_registry_sha256": registry_sha256,
            "diagnostics": {},
            "semantic_blockers": [],
            "counts": {},
            "authority": "exact_machine_semantics_only",
        }
        plan["plan_sha256"] = canonical_sha256_v3(plan)
        return plan

    def test_component_boundary_exit_records_routes_without_expanding(self) -> None:
        plan = self._minimal_transfer_plan()
        indirect = plan["transfers"][0]
        indirect["identity"] = "semantic-transfer:finite-boundary"
        indirect["expressions"][0] = {
            "id": 0, "op": "reg", "operands": [],
            "result_sort": "bitvector", "width_bits": 32,
            "parameters": {
                "aux": 0, "immediate": 0, "identity": None,
            },
        }
        indirect["effects"] = []
        indirect["terminator"] = {
            "op": "outcome_indirect", "operands": [0],
            "parameters": {"aux": 0},
        }
        target = copy.deepcopy(self._minimal_transfer_plan()["transfers"][0])
        target["identity"] = "semantic-transfer:finite-target"
        target["source"]["rva_start"] = 0x1100
        target["source"]["rva_end"] = 0x1101
        plan["transfers"] = [indirect, target]
        plan["entry_targets"] = [0x1000, 0x1100]
        route_core = {
            "unit_id": indirect["identity"],
            "source_rva": 0x1000,
            "routes": [{
                "selector_value": 0,
                "target_rva": 0x1100,
                "target_address": 0x401100,
            }],
        }
        plan["finite_control_routes"] = [{
            **route_core,
            "route_inventory_sha256": canonical_sha256_v3(route_core),
        }]
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x1100}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            boundary_exit_rvas=(0x1000,),
        )

        observed = json.loads(native.evaluate_reference_closure_receipt(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))

        self.assertEqual(observed["status"], "complete", observed["blockers"])
        self.assertEqual(
            [row["rva"] for row in observed["reachable_units"]], [0x1000]
        )
        self.assertEqual(observed["indirect_targets"][0]["targets"], [0x1100])
        self.assertEqual(observed["analysis_policy"]["boundary_exit_rvas"], [0x1000])

    def test_native_internal_call_return_summary_matches_python_fixed_point(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        caller = plan["transfers"][0]
        expressions = []
        for index in range(8):
            expressions.append({
                "id": len(expressions), "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": index, "immediate": 1, "identity": None,
                },
            })
        for index in range(6):
            expressions.append({
                "id": len(expressions), "op": "flag", "operands": [],
                "result_sort": "predicate", "width_bits": 1,
                "parameters": {
                    "aux": index, "immediate": 1, "identity": None,
                },
            })
        expressions.append({
            "id": len(expressions), "op": "call_response", "operands": [],
            "result_sort": "bitvector", "width_bits": 32,
            "parameters": {"aux": 0, "immediate": 1, "identity": None},
        })
        caller["expressions"] = expressions
        caller["effects"] = [
            {"id": 0, "op": "call", "operands": [0], "parameters": {"aux": 0}},
            {"id": 1, "op": "set_reg", "operands": [14], "parameters": {"aux": 0}},
        ]
        caller["calls"] = [{
            "id": 0, "kind": "internal_call",
            "instruction_rva": 0x1000, "event_index": 0,
            "target_node": None, "target_rva": 0x2000,
            "return_rva": 0x3000, "dll": None, "symbol": None,
            "ordinal": None, "register_nodes": list(range(8)),
            "flag_nodes": list(range(8, 14)), "argument_nodes": [],
            "stack_inputs": [],
        }]
        caller["terminator"] = {
            "op": "outcome_fallthrough", "operands": [0x3000],
            "parameters": {"aux": 0},
        }

        def leaf(rva: int, immediate: int, *, assign: bool) -> dict[str, Any]:
            row = copy.deepcopy(self._minimal_transfer_plan()["transfers"][0])
            row["identity"] = f"semantic-transfer:native-call-{rva:08x}"
            row["source"]["rva_start"] = rva
            row["source"]["rva_end"] = rva + 1
            row["source"]["contract_sha256"] = ("d" if assign else "e") * 64
            row["expressions"][0]["parameters"]["immediate"] = immediate
            row["effects"] = ([{
                "id": 0, "op": "set_reg", "operands": [0],
                "parameters": {"aux": 0},
            }] if assign else [])
            row["terminator"]["operands"] = [0]
            return row

        callee = leaf(0x2000, 42, assign=True)
        callee["expressions"].extend([
            {
                "id": 1, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {"aux": 1, "immediate": 1, "identity": None},
            },
            {
                "id": 2, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {"aux": 0, "immediate": 99, "identity": None},
            },
        ])
        callee["effects"].append({
            "id": 1, "op": "memory_write", "operands": [1, 2],
            "parameters": {"aux": 4},
        })
        plan["transfers"] = [
            caller, callee, leaf(0x3000, 7, assign=False),
        ]
        plan["entry_targets"] = [0x1000, 0x2000, 0x3000]
        registers = list(ReferenceStateV1().registers)
        registers[1] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:ancestor", 8),
        ))
        registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:root"),
        ))
        initial = ReferenceStateV1(
            registers=tuple(registers),
            memory={
                ("object", "captured_stack_frame:ancestor", 8, 4):
                finite_reference_value_v1(scalars=(1,)),
            },
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: initial},
        )
        transfers = tuple(
            _transfer_from_payload(row) for row in plan["transfers"]
        )
        diagnostic_states = {}
        expected_closure = build_module_execution_closure_v1(
            transfer_plan_sha256="c" * 64,
            transfers=transfers,
            context=context,
            diagnostic_states=diagnostic_states,
            dynamic_scheduling=False,
        )
        observed = json.loads(native.evaluate_reference_closure_frontier(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected_states = [{
            "rva": rva,
            "root_rva": function_context.root_rva,
            "function_entry_rva": function_context.function_entry_rva,
            "call_string": list(function_context.call_string),
            "state": _reference_state_kernel_payload_v1(state),
        } for (rva, function_context), state in sorted(
            diagnostic_states.items()
        )]
        self.assertEqual(observed["states"], expected_states)
        self.assertEqual(
            observed["reachable_edges"], expected_closure["reachable_edges"],
        )
        self.assertEqual(observed["blockers"], [])

    def test_batched_state_joins_match_python_reference(self) -> None:
        baseline_key = ("object", "image:data", 0, 4)
        baseline = {
            baseline_key: finite_reference_value_v1(references=(
                ReferenceAtomV1("guest_code", "rva:00002000"),
            )),
        }
        left_registers = list(ReferenceStateV1().registers)
        right_registers = list(left_registers)
        left_registers[0] = finite_reference_value_v1(scalars=(1,))
        right_registers[0] = finite_reference_value_v1(scalars=(2,))
        left_registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:left", 0),
        ))
        right_registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:right", 0),
        ))
        written_key = ("object", "allocation:fixture", 4, 4)
        left = ReferenceStateV1(
            registers=tuple(left_registers),
            memory={
                baseline_key: baseline[baseline_key],
                written_key: finite_reference_value_v1(scalars=(3,)),
            },
            callback_registry={
                "callback:one": finite_reference_value_v1(references=(
                    ReferenceAtomV1("guest_code", "rva:00003000"),
                )),
            },
            flag_relations=(
                ScalarFlagRelationV1(0, 0xFF, "eq", 1),
                *(None for _index in range(6)),
            ),
            scalar_constraints={(0, 0xFF): frozenset({1})},
            relational_object_bindings={
                "call_parameter_object:fixture:register:3":
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", "allocation:fixture"),
                )),
            },
            written_memory_keys=frozenset({written_key}),
            possible_allocation_identities=frozenset({
                "allocation:fixture",
            }),
        )
        right = ReferenceStateV1(
            registers=tuple(right_registers),
            memory={
                written_key: finite_reference_value_v1(scalars=(4,)),
            },
            invalidated_memory_ranges=frozenset({
                ("object", "image:data", 0, 4),
            }),
            callback_registry={
                "callback:one": CONFLICT_REFERENCE_V1,
            },
            flag_relations=(None,) * 7,
            scalar_constraints={(0, 0xFF): frozenset({2})},
            preserves_inherited_memory=False,
            effect_invalidated_memory_ranges=frozenset({
                ("object", "image:data", 0, 4),
            }),
            possible_allocation_identities=frozenset({
                "allocation:fixture",
            }),
        )
        cases = [
            (ReferenceStateV1(), ReferenceStateV1()),
            (left, right),
            (right, left),
            (replace(left, all_memory_invalidated=True), right),
        ]
        expected = [
            _reference_state_kernel_payload_v1(join_reference_states_v1(
                one,
                two,
                alternative_limit=16,
                baseline_memory=baseline,
            ))
            for one, two in cases
        ]
        self.assertEqual(
            _native_joins(cases, baseline=baseline),
            expected,
        )

    def test_malformed_batch_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "alternative limit"):
            native.join_reference_state_batches(json.dumps({
                "alternative_limit": 0,
                "baseline_memory": [],
                "cases": [],
            }).encode())

        state = _reference_state_kernel_payload_v1(ReferenceStateV1())
        key = _key_payload(("object", "allocation:fixture", 0, 4))
        state["written_memory_keys"] = [key, key]
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            native.join_reference_state_batches(json.dumps({
                "alternative_limit": 16,
                "baseline_memory": [],
                "cases": [{"left": state, "right": state}],
            }).encode())

        state = _reference_state_kernel_payload_v1(ReferenceStateV1())
        state["possible_allocation_identities"] = [
            "allocation:fixture", "allocation:fixture",
        ]
        with self.assertRaisesRegex(ValueError, "duplicate identity"):
            native.join_reference_state_batches(json.dumps({
                "alternative_limit": 16,
                "baseline_memory": [],
                "cases": [{"left": state, "right": state}],
            }).encode())
