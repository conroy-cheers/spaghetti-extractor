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
    validate_module_execution_closure_v1,
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
from spaghetti_extractor.transfer.model import TransferPlanError
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


def _effect_exception_occurrence(
    operation: str, *, effect_index: int = 0, fault_sha256: str = "e" * 64,
) -> dict[str, Any]:
    return {
        "fault_index": 0,
        "fault_sha256": fault_sha256,
        "occurrence_kind": "effect",
        "effect_index": effect_index,
        "operation": operation,
        "call_id": None,
        "call_event_index": None,
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

    def test_native_projection_retains_structurally_incomplete_plan(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        plan["status"] = "incomplete"
        plan["semantic_blockers"] = [{
            "code": "machine_ir_semantics_incomplete",
            "transfer_id": "semantic-transfer:omitted-fixture",
        }]
        plan["plan_sha256"] = canonical_sha256_v3({
            key: value for key, value in plan.items()
            if key != "plan_sha256"
        })
        receipt = json.loads(native.inspect_reference_transfer_plan(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode()
        ))
        self.assertEqual(receipt["transfers"], 1)

    def test_native_direct_branch_frontier_matches_python_fixed_point(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        root = plan["transfers"][0]
        root["expressions"] = [
            {
                "id": 0, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 1, "identity": None,
                },
            },
            {
                "id": 1, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0, "identity": None,
                },
            },
            {
                "id": 2, "op": "eq", "operands": [0, 1],
                "result_sort": "predicate", "width_bits": 1,
                "parameters": {
                    "aux": 0, "immediate": 0, "identity": None,
                },
            },
        ]
        root["effects"] = []
        root["terminator"] = {
            "op": "outcome_branch", "operands": [2, 0x2000, 0x3000],
            "parameters": {"aux": 0},
        }

        def return_transfer(rva: int, immediate: int) -> dict[str, Any]:
            row = copy.deepcopy(self._minimal_transfer_plan()["transfers"][0])
            row["identity"] = f"semantic-transfer:native-fixture-{rva:08x}"
            row["source"]["rva_start"] = rva
            row["source"]["rva_end"] = rva + 1
            row["source"]["contract_sha256"] = f"{immediate:x}" * 64
            row["expressions"][0]["parameters"]["immediate"] = immediate
            row["effects"] = []
            row["terminator"]["operands"] = [0]
            return row

        plan["transfers"] = [
            root, return_transfer(0x2000, 1), return_transfer(0x3000, 2),
        ]
        plan["entry_targets"] = [0x1000, 0x2000, 0x3000]
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(scalars=(0, 7))
        initial = ReferenceStateV1(registers=tuple(registers))
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
        summary = json.loads(native.evaluate_reference_closure_summary(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True,
        ).encode()
        receipt = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected_receipt = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=transfers,
            context=context,
            dynamic_scheduling=True,
        )
        expected_static_receipt = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=transfers,
            context=context,
            dynamic_scheduling=False,
        )
        expected_states = [{
            "rva": rva,
            "root_rva": function_context.root_rva,
            "function_entry_rva": function_context.function_entry_rva,
            "call_string": list(function_context.call_string),
            "state": _reference_state_kernel_payload_v1(state),
        } for (rva, function_context), state in sorted(
            diagnostic_states.items()
        )]
        self.assertEqual(observed, {
            "worklist_steps": 3,
            "states": expected_states,
            "reachable_edges": expected_closure["reachable_edges"],
            "blockers": [],
        })
        self.assertEqual(summary, {
            "worklist_steps": 3,
            "state_contexts": 3,
            "reachable_rvas": [0x1000, 0x2000, 0x3000],
            "reachable_edges": expected_closure["reachable_edges"],
            "blockers": [],
        })
        for payload in (
            receipt, expected_receipt, expected_static_receipt,
        ):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(receipt, expected_receipt)
        self.assertEqual(expected_static_receipt, expected_receipt)

    def test_reachable_divide_fault_fails_closed_until_outcome_is_checked(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        plan["transfers"][0]["effects"] = [{
            "id": 0,
            "op": "divide_if",
            "operands": [0],
            "parameters": {"aux": 0},
        }]
        plan["transfers"][0]["exception_occurrences"] = [
            _effect_exception_occurrence("divide_if")
        ]
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True,
        ).encode()
        encoded_context = json.dumps(
            _execution_closure_kernel_context_payload_v1(context),
            separators=(",", ":"), sort_keys=True,
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan, encoded_context,
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(observed, expected)
        self.assertFalse(observed["authorizes_execution"])
        self.assertEqual(observed["exception_continuations"], [])
        self.assertEqual(observed["blockers"], [{
            "code": "reachable_exception_outcome_unresolved",
            "source_rva": 0x1000,
            "effect_index": 0,
            "operation": "divide_if",
        }])

    def test_declared_nonlocal_blocker_matches_python_fixed_point(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer = plan["transfers"][0]
        transfer["expressions"] = [
            {
                "id": index, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": immediate, "identity": None,
                },
            }
            for index, immediate in enumerate((0x2000, 9))
        ]
        transfer["effects"] = []
        transfer["terminator"] = {
            "op": "outcome_nonlocal",
            "operands": [0, 1],
            "parameters": {"aux": 0},
        }
        source = _transfer_from_payload(transfer)
        context = ExecutionClosureContextV1(
            roots=(source.rva_start,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({source.rva_start}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True,
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=(source,),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(observed, expected)
        self.assertEqual(observed["status"], "incomplete")
        self.assertEqual(
            observed["blockers"][0]["code"],
            "reachable_nonlocal_outcome_authority_missing",
        )

    def test_declared_nonlocal_resolves_one_active_ancestor_in_both_kernels(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        caller = plan["transfers"][0]
        caller["expressions"] = [
            {
                "id": index, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": index, "immediate": 1, "identity": None,
                },
            }
            for index in range(8)
        ] + [
            {
                "id": 8 + index, "op": "flag", "operands": [],
                "result_sort": "predicate", "width_bits": 1,
                "parameters": {
                    "aux": index, "immediate": 1, "identity": None,
                },
            }
            for index in range(6)
        ]
        caller["effects"] = [{
            "id": 0, "op": "call", "operands": [0],
            "parameters": {"aux": 0},
        }]
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

        callee = copy.deepcopy(self._minimal_transfer_plan()["transfers"][0])
        callee["identity"] = "semantic-transfer:native-nonlocal-callee"
        callee["source"]["rva_start"] = 0x2000
        callee["source"]["rva_end"] = 0x2001
        callee["source"]["contract_sha256"] = "d" * 64
        callee["expressions"] = [
            {
                "id": index, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": immediate, "identity": None,
                },
            }
            for index, immediate in enumerate((0x3000, 9))
        ]
        callee["effects"] = []
        callee["calls"] = []
        callee["terminator"] = {
            "op": "outcome_nonlocal", "operands": [0, 1],
            "parameters": {"aux": 0},
        }

        continuation = copy.deepcopy(
            self._minimal_transfer_plan()["transfers"][0]
        )
        continuation["identity"] = (
            "semantic-transfer:native-nonlocal-continuation"
        )
        continuation["source"]["rva_start"] = 0x3000
        continuation["source"]["rva_end"] = 0x3001
        continuation["source"]["contract_sha256"] = "e" * 64
        continuation["effects"] = []
        continuation["calls"] = []
        continuation["terminator"] = {
            "op": "outcome_return", "operands": [0],
            "parameters": {"aux": 0},
        }
        plan["transfers"] = [caller, callee, continuation]
        plan["entry_targets"] = [0x1000, 0x2000, 0x3000]

        registers = list(ReferenceStateV1().registers)
        registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack:root:00001000"),
        ))
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={
                0x1000: ReferenceStateV1(registers=tuple(registers)),
            },
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True,
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(observed, expected)
        self.assertEqual(observed["status"], "complete", observed["blockers"])
        self.assertEqual(
            observed["reachable_edges"],
            [
                {
                    "source_rva": 0x1000, "target_rva": 0x2000,
                    "kind": "internal_call",
                },
                {
                    "source_rva": 0x2000, "target_rva": 0x3000,
                    "kind": "nonlocal_control",
                },
            ],
        )
        transition = observed["nonlocal_transitions"][0]
        self.assertEqual(transition["source_rva"], 0x2000)
        self.assertEqual(transition["target_rva"], 0x3000)
        self.assertEqual(transition["target_function_entry_rva"], 0x1000)
        self.assertEqual(
            transition["cleanup"]["kind"],
            "expire_abandoned_stack_frames",
        )

        unknown_value = copy.deepcopy(observed)
        unknown_transition = unknown_value["nonlocal_transitions"][0]
        unknown_transition["value"] = {
            "kind": "unknown_scalar", "scalars": [], "references": [],
        }
        unknown_core = {
            key: value for key, value in unknown_transition.items()
            if key != "id"
        }
        unknown_transition["id"] = (
            "checked-nonlocal-transition-v1:"
            + canonical_sha256_v3(unknown_core)
        )
        unknown_value["closure_sha256"] = canonical_sha256_v3({
            key: value for key, value in unknown_value.items()
            if key != "closure_sha256"
        })
        validate_module_execution_closure_v1(unknown_value)

        malformed_value = copy.deepcopy(unknown_value)
        malformed_transition = malformed_value["nonlocal_transitions"][0]
        malformed_transition["value"] = {
            "kind": "finite", "scalars": [True], "references": [],
        }
        malformed_core = {
            key: value for key, value in malformed_transition.items()
            if key != "id"
        }
        malformed_transition["id"] = (
            "checked-nonlocal-transition-v1:"
            + canonical_sha256_v3(malformed_core)
        )
        malformed_value["closure_sha256"] = canonical_sha256_v3({
            key: value for key, value in malformed_value.items()
            if key != "closure_sha256"
        })
        with self.assertRaisesRegex(
            TransferPlanError, "nonlocal transitions are malformed"
        ):
            validate_module_execution_closure_v1(malformed_value)

    def test_checked_access_violation_matches_python_and_preserves_root_causality(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        plan["transfers"][0]["expressions"].extend([
            {
                "id": 1,
                "op": "const",
                "operands": [],
                "result_sort": "bitvector",
                "width_bits": 32,
                "parameters": {
                    "aux": 0,
                    "immediate": 1,
                    "identity": None,
                },
            },
            {
                "id": 2,
                "op": "const",
                "operands": [],
                "result_sort": "bitvector",
                "width_bits": 32,
                "parameters": {
                    "aux": 0,
                    "immediate": 0x1BADB002,
                    "identity": None,
                },
            },
        ])
        plan["transfers"][0]["effects"] = [{
            "id": 0,
            "op": "access_violation_if",
            "operands": [0, 1, 2],
            "parameters": {"aux": 0},
        }]
        plan["transfers"][0]["exception_occurrences"] = [
            _effect_exception_occurrence("access_violation_if")
        ]
        transition = CheckedExceptionTransitionV1(
            unit_id="semantic-transfer:native-fixture",
            source_rva=0x1000,
            effect_index=0,
            fault_index=0,
            fault_sha256="e" * 64,
            transition_id="exceptional-transition-v3:" + "c" * 64,
            transition_sha256="f" * 64,
            authorizing=True,
            disposition="terminates",
            handler_unit_id=None,
            handler_rva=None,
            guard={"op": "true"},
            blocker_code=None,
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000}),
            ),
            authority_bindings={
                "exceptional_transitions_manifest_sha256": "d" * 64,
            },
            checked_exception_transitions=(transition,),
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True,
        ).encode()
        encoded_context = json.dumps(
            _execution_closure_kernel_context_payload_v1(context),
            separators=(",", ":"), sort_keys=True,
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan, encoded_context,
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(observed, expected)
        self.assertTrue(
            observed["authorizes_execution"], observed["blockers"]
        )
        self.assertEqual(
            observed["exception_continuations"][0]["root_rvas"],
            [0x1000],
        )
        self.assertEqual(
            observed["exception_continuations"][0]["transition_sha256"],
            "f" * 64,
        )
        self.assertEqual(
            observed["exception_continuations"][0]["operation"],
            "access_violation_if",
        )

    def test_checked_call_exception_matches_python_fixed_point(self) -> None:
        row = transfer_row()
        call = {
            "family": "external",
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "target_rva": 0,
            "return_rva": 0x1003,
            "dll": "kernel32.dll",
            "symbol": "RaiseException",
            "ordinal": None,
            "register_inputs": {
                name: {"op": "reg", "name": name, "width": 32}
                for name in (
                    "eax", "ebx", "ecx", "edx",
                    "esi", "edi", "ebp", "esp",
                )
            },
            "flag_inputs": {
                name: {"op": "flag", "name": name}
                for name in ("cf", "zf", "sf", "of", "pf", "df")
            },
            "arguments": [],
            "stack_inputs": [],
            "native_exception_operations": ["divide_if"],
        }
        row["external_events"] = [call]
        row["ordered_events"] = [call]
        row["outcome"] = {
            "kind": "return",
            "value": {"op": "const", "value": 0, "width": 32},
        }
        handler_row = transfer_row(expression={
            "op": "const", "value": 7, "width": 32,
        })
        handler_row["id"] = "semantic-transfer:fixture-exception-handler"
        handler_row["contract_sha256"] = "7" * 64
        handler_row["original"] = {
            "rva_start": 0x1100, "rva_end": 0x1103, "size": 3,
        }
        handler_row["outcome"] = {
            "kind": "return",
            "value": {"op": "const", "value": 7, "width": 32},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine.jsonl"
            machine.write_text(
                "\n".join(
                    json.dumps(as_machine_ir_unit(item), sort_keys=True)
                    for item in (row, handler_row)
                ) + "\n",
                encoding="utf-8",
            )
            plan_path = write_fixture_transfer_plan(
                machine, pe_sha256="a" * 64
            )
            plan = json.loads(plan_path.read_text(encoding="utf-8"))

        transfers = tuple(
            _transfer_from_payload(item) for item in plan["transfers"]
        )
        source = next(
            item for item in transfers
            if item.identity == "semantic-transfer:fixture"
        )
        handler = next(
            item for item in transfers
            if item.identity == "semantic-transfer:fixture-exception-handler"
        )
        effect_index = next(
            index for index, effect in enumerate(
                next(
                    item for item in plan["transfers"]
                    if item["identity"] == source.identity
                )["effects"]
            )
            if effect["op"] == "call"
        )
        transition = CheckedExceptionTransitionV1(
            unit_id=source.identity,
            source_rva=source.rva_start,
            effect_index=effect_index,
            fault_index=0,
            fault_sha256="e" * 64,
            transition_id="exceptional-transition-v3:" + "c" * 64,
            transition_sha256="f" * 64,
            authorizing=True,
            disposition="handled",
            handler_unit_id=handler.identity,
            handler_rva=handler.rva_start,
            guard={"op": "true"},
            blocker_code=None,
            state_projection={
                "registers": [],
                "flags": [],
                "x87": [],
                "stack": [],
                "exception_record": [
                    "ExceptionRecord[1].ExceptionCode",
                ],
                "context": [],
            },
            native_exception_code=0xC0000094,
            native_exception_flags=0,
            native_exception_parameter_count=0,
            native_exception_continuable=True,
            occurrence_kind="call",
            operation="divide_if",
            call_index=0,
        )
        context = ExecutionClosureContextV1(
            roots=(source.rva_start,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({
                    source.rva_start, handler.rva_start,
                }),
                external_calls={
                    ("kernel32.dll", "RaiseException"): ExternalCallRuleV1()
                },
            ),
            authority_bindings={
                "exceptional_transitions_manifest_sha256": "d" * 64,
            },
            checked_exception_transitions=(transition,),
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=transfers,
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(observed, expected)
        self.assertTrue(
            observed["authorizes_execution"], observed["blockers"]
        )
        self.assertEqual(
            observed["exception_continuations"][0]["occurrence_kind"],
            "call",
        )
        self.assertEqual(
            observed["exception_continuations"][0]["operation"],
            "divide_if",
        )
        self.assertEqual(
            observed["exception_continuations"][0]["handler_rva"],
            handler.rva_start,
        )

    def test_checked_handler_projection_matches_python_fixed_point(self) -> None:
        plan = self._minimal_transfer_plan()
        source = plan["transfers"][0]
        source["expressions"].append({
            "id": 1,
            "op": "const",
            "operands": [],
            "result_sort": "bitvector",
            "width_bits": 32,
            "parameters": {"aux": 0, "immediate": 0, "identity": None},
        })
        source["effects"] = [
            {
                "id": 0,
                "op": "set_reg",
                "operands": [0],
                "parameters": {"aux": 0},
            },
            {
                "id": 1,
                "op": "divide_if",
                "operands": [1],
                "parameters": {"aux": 0},
            },
        ]
        inner = copy.deepcopy(source)
        inner["identity"] = "semantic-transfer:native-unwind-inner"
        inner["source"]["rva_start"] = 0x1100
        inner["source"]["rva_end"] = 0x1101
        inner["source"]["contract_sha256"] = "7" * 64
        inner["expressions"] = [copy.deepcopy(source["expressions"][0])]
        inner["expressions"][0]["parameters"]["immediate"] = 8
        inner["effects"] = [{
            "id": 0, "op": "set_reg", "operands": [0],
            "parameters": {"aux": 0},
        }]
        inner["terminator"]["operands"] = [0]
        outer = copy.deepcopy(source)
        outer["identity"] = "semantic-transfer:native-unwind-outer"
        outer["source"]["rva_start"] = 0x1200
        outer["source"]["rva_end"] = 0x1201
        outer["source"]["contract_sha256"] = "8" * 64
        outer["expressions"] = [
            {
                "id": 0, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {"aux": 0, "immediate": 0, "identity": None},
            },
            {
                "id": 1, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {"aux": 0, "immediate": 1, "identity": None},
            },
            {
                "id": 2, "op": "add32", "operands": [0, 1],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {"aux": 0, "immediate": 0, "identity": None},
            },
        ]
        outer["effects"] = [{
            "id": 0, "op": "set_reg", "operands": [2],
            "parameters": {"aux": 0},
        }]
        outer["terminator"]["operands"] = [2]
        handler = copy.deepcopy(source)
        handler["identity"] = "semantic-transfer:native-handler"
        handler["source"]["rva_start"] = 0x1300
        handler["source"]["rva_end"] = 0x1301
        handler["source"]["contract_sha256"] = "9" * 64
        handler["effects"] = []
        handler["terminator"]["operands"] = [0]
        resumption = copy.deepcopy(handler)
        resumption["identity"] = "semantic-transfer:native-resumption"
        resumption["source"]["rva_start"] = 0x1400
        resumption["source"]["rva_end"] = 0x1401
        resumption["source"]["contract_sha256"] = "a" * 64
        source["exception_occurrences"] = [
            _effect_exception_occurrence("divide_if", effect_index=1)
        ]
        plan["transfers"] = [source, inner, outer, handler, resumption]
        plan["entry_targets"] = [0x1000, 0x1100, 0x1200, 0x1300, 0x1400]
        transition = CheckedExceptionTransitionV1(
            unit_id="semantic-transfer:native-fixture",
            source_rva=0x1000,
            effect_index=1,
            fault_index=0,
            fault_sha256="e" * 64,
            transition_id="exceptional-transition-v3:" + "c" * 64,
            transition_sha256="f" * 64,
            authorizing=True,
            disposition="handled",
            handler_unit_id="semantic-transfer:native-handler",
            handler_rva=0x1300,
            resumption_unit_id="semantic-transfer:native-resumption",
            resumption_rva=0x1400,
            guard={"op": "true"},
            blocker_code=None,
            unwind_unit_ids=(
                "semantic-transfer:native-unwind-inner",
                "semantic-transfer:native-unwind-outer",
            ),
            state_projection={
                "registers": ["eax"],
                "flags": [],
                "x87": ["all"],
                "stack": [],
                "exception_record": ["ExceptionCode"],
                "context": ["eax"],
            },
            native_exception_code=0xC0000094,
            native_exception_flags=0,
            native_exception_parameter_count=0,
            native_exception_continuable=True,
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({
                    0x1000, 0x1100, 0x1200, 0x1300, 0x1400,
                }),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            checked_exception_transitions=(transition,),
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True,
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)
        self.assertEqual(observed, expected)
        self.assertTrue(observed["authorizes_execution"])
        self.assertEqual([
            (row["source_rva"], row["target_rva"], row["kind"])
            for row in observed["reachable_edges"]
            if row["kind"].startswith("exception_")
        ], [
            (0x1000, 0x1100, "exception_unwind"),
            (0x1100, 0x1200, "exception_unwind"),
            (0x1200, 0x1300, "exception_handler"),
            (0x1300, 0x1400, "exception_resumption"),
        ])

    def test_native_control_target_widening_matches_python_fixed_point(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        root = plan["transfers"][0]
        root["expressions"] = [
            {
                "id": 0, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 1, "identity": None,
                },
            },
            {
                "id": 1, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 4, "identity": None,
                },
            },
            {
                "id": 2, "op": "mul32", "operands": [0, 1],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0, "identity": None,
                },
            },
            {
                "id": 3, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0x4000,
                    "identity": None,
                },
            },
            {
                "id": 4, "op": "add32", "operands": [3, 2],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0, "identity": None,
                },
            },
            {
                "id": 5, "op": "load", "operands": [4],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 4, "immediate": 0, "identity": None,
                },
            },
        ]
        root["effects"] = []
        root["terminator"] = {
            "op": "outcome_indirect", "operands": [5],
            "parameters": {"aux": 0},
        }
        targets = tuple(0x2000 + index * 0x10 for index in range(24))
        leaves = []
        for index, rva in enumerate(targets):
            leaf = copy.deepcopy(self._minimal_transfer_plan()["transfers"][0])
            leaf["identity"] = f"semantic-transfer:target-{rva:08x}"
            leaf["source"]["rva_start"] = rva
            leaf["source"]["rva_end"] = rva + 1
            leaf["source"]["contract_sha256"] = f"{index + 1:064x}"
            leaf["expressions"][0]["parameters"]["immediate"] = rva
            leaf["effects"] = []
            leaf["terminator"]["operands"] = [0]
            leaves.append(leaf)
        plan["transfers"] = [root, *leaves]
        plan["entry_targets"] = [0x1000, *targets]
        initial_memory = {
            ("absolute", "", 0x4000 + index * 4, 4):
            finite_reference_value_v1(references=(
                ReferenceAtomV1("guest_code", f"rva:{rva:08x}"),
            ))
            for index, rva in enumerate(targets)
        }
        initial = ReferenceStateV1(scalar_constraints={
            (0, 0xFFFF_FFFF): frozenset(range(len(targets))),
        })
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset((0x1000, *targets)),
                initial_memory=initial_memory,
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: initial},
        )
        diagnostic_states = {}
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256="c" * 64,
            transfers=tuple(_transfer_from_payload(row) for row in plan["transfers"]),
            context=context,
            diagnostic_states=diagnostic_states,
            dynamic_scheduling=False,
        )
        observed = json.loads(native.evaluate_reference_closure_summary(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {
            "worklist_steps": len(targets) + 1,
            "state_contexts": len(targets) + 1,
            "reachable_rvas": [0x1000, *targets],
            "reachable_edges": expected["reachable_edges"],
            "blockers": [],
        })

    def test_native_indirect_blocker_aggregates_contextual_provenance(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()

        def jump_transfer(rva: int) -> dict[str, Any]:
            row = copy.deepcopy(plan["transfers"][0])
            row["identity"] = f"semantic-transfer:root-{rva:08x}"
            row["source"]["rva_start"] = rva
            row["source"]["rva_end"] = rva + 1
            row["source"]["contract_sha256"] = f"{rva:064x}"
            row["effects"] = []
            row["terminator"] = {
                "op": "outcome_jump", "operands": [0x1200],
                "parameters": {"aux": 0},
            }
            return row

        indirect = copy.deepcopy(plan["transfers"][0])
        indirect["identity"] = "semantic-transfer:shared-indirect"
        indirect["source"]["rva_start"] = 0x1200
        indirect["source"]["rva_end"] = 0x1201
        indirect["source"]["contract_sha256"] = "e" * 64
        indirect["expressions"] = [{
            "id": 0, "op": "reg", "operands": [],
            "result_sort": "bitvector", "width_bits": 32,
            "parameters": {"aux": 0, "immediate": 1, "identity": None},
        }]
        indirect["effects"] = []
        indirect["terminator"] = {
            "op": "outcome_indirect", "operands": [0],
            "parameters": {"aux": 0},
        }
        plan["transfers"] = [
            jump_transfer(0x1000), jump_transfer(0x1100), indirect,
        ]
        plan["entry_targets"] = [0x1000, 0x1100, 0x1200]
        conflict_registers = list(ReferenceStateV1().registers)
        conflict_registers[0] = CONFLICT_REFERENCE_V1
        context = ExecutionClosureContextV1(
            roots=(0x1000, 0x1100),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x1100, 0x1200}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={
                0x1000: ReferenceStateV1(),
                0x1100: ReferenceStateV1(
                    registers=tuple(conflict_registers),
                ),
            },
        )
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256="c" * 64,
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        observed = json.loads(native.evaluate_reference_closure_summary(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed["blockers"], expected["blockers"])
        self.assertEqual(observed["blockers"], [{
            "code": "unresolved_reachable_indirect_target",
            "source_rva": 0x1200,
            "site": "terminator",
            "provenance": [
                CONFLICT_REFERENCE_V1.payload(),
                UNKNOWN_SCALAR_REFERENCE_V1.payload(),
            ],
        }])

    def test_native_closure_uses_canonical_finite_control_routes(self) -> None:
        plan = self._minimal_transfer_plan()
        indirect = plan["transfers"][0]
        indirect["identity"] = "semantic-transfer:finite-dispatch"
        indirect["expressions"] = [{
            "id": 0, "op": "reg", "operands": [],
            "result_sort": "bitvector", "width_bits": 32,
            "parameters": {
                "aux": 0, "immediate": 0, "identity": None,
            },
        }]
        indirect["effects"] = []
        indirect["terminator"] = {
            "op": "outcome_indirect", "operands": [0],
            "parameters": {"aux": 0},
        }

        def target(rva: int) -> dict[str, Any]:
            row = copy.deepcopy(self._minimal_transfer_plan()["transfers"][0])
            row["identity"] = f"semantic-transfer:target-{rva:08x}"
            row["source"]["rva_start"] = rva
            row["source"]["rva_end"] = rva + 1
            row["source"]["contract_sha256"] = f"{rva:064x}"
            return row

        plan["transfers"] = [indirect, target(0x1100), target(0x1200)]
        plan["entry_targets"] = [0x1000, 0x1100, 0x1200]
        route_core = {
            "unit_id": indirect["identity"],
            "source_rva": 0x1000,
            "routes": [
                {
                    "selector_value": 0,
                    "target_rva": 0x1100,
                    "target_address": 0x401100,
                },
                {
                    "selector_value": 1,
                    "target_rva": 0x1200,
                    "target_address": 0x401200,
                },
            ],
        }
        plan["finite_control_routes"] = [{
            **route_core,
            "route_inventory_sha256": canonical_sha256_v3(route_core),
        }]
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x1100, 0x1200}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            finite_control_targets={0x1000: (0x1100, 0x1200)},
        )

        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)

        self.assertEqual(observed, expected)
        self.assertEqual(observed["status"], "complete", observed["blockers"])
        self.assertEqual(
            [row["rva"] for row in observed["reachable_units"]],
            [0x1000, 0x1100, 0x1200],
        )
        self.assertEqual(observed["indirect_targets"], [{
            "source_rva": 0x1000,
            "site": "terminator",
            "targets": [0x1100, 0x1200],
            "external_targets": [],
            "provenance": [UNKNOWN_SCALAR_REFERENCE_V1.payload()],
        }])
