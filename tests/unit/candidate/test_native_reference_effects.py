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
    ExternalMemoryCopyV1,
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

    def test_native_projection_consumes_transfer_plan_v2_directly(self) -> None:
        plan = self._minimal_transfer_plan()
        receipt = json.loads(native.inspect_reference_transfer_plan(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode()
        ))
        self.assertEqual(
            native.REFERENCE_KERNEL_OPERATION_REGISTRY_SHA256,
            canonical_sha256_v3(operation_registry_payload_v2()),
        )
        self.assertEqual(receipt, {
            "operation_registry_sha256": plan["operation_registry_sha256"],
            "transfers": 1,
            "expressions": 1,
            "effects": 1,
            "calls": 0,
            "x87_intrinsics": 0,
            "expression_operations": {"const": 1},
            "effect_operations": {"set_reg": 1},
            "terminator_operations": {"outcome_return": 1},
            "supported_expression_operations": sorted(
                EXPRESSION_OPERATIONS_V2
            ),
            "supported_effect_operations": sorted(EFFECT_OPERATIONS_V2),
            "supported_terminator_operations": sorted(
                TERMINATOR_OPERATIONS_V2
            ),
        })

        plan["transfers"][0]["expressions"][0]["op"] = "trench_coat_ir"
        with self.assertRaisesRegex(ValueError, "unsupported operation"):
            native.inspect_reference_transfer_plan(json.dumps(
                plan, separators=(",", ":"), sort_keys=True,
            ).encode())

    def test_production_closure_writer_uses_native_receipt_kernel(self) -> None:
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row()
            row["outcome"] = {"kind": "fallthrough", "target_rva": 0x1000}
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            plan_path = write_fixture_transfer_plan(machine_ir)
            plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
            context = replace(
                context,
                runtime_provider_requirements=tuple(
                    plan_payload["runtime_provider_requirements"]
                ),
            )
            receipt = write_module_execution_closure_v1(
                transfer_plan=plan_path,
                context=context,
                out=root / "closure",
            )
            self.assertEqual(
                json.loads(
                    (root / "closure/module-execution-closure.json")
                    .read_text(encoding="utf-8")
                ),
                receipt,
            )
            check_module_execution_closure_v1(
                receipt, transfer_plan=plan_path, context=context,
            )

    def test_native_closure_input_is_a_private_projection_of_checked_context(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: ReferenceStateV1()},
        )
        context_payload = _execution_closure_kernel_context_payload_v1(
            context
        )
        receipt = json.loads(native.inspect_reference_closure_inputs(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                context_payload, separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(receipt, {
            "transfers": 1,
            "roots": 1,
            "guest_code_rvas": 1,
            "objects": 0,
            "external_calls": 0,
            "external_declarations": 0,
            "initial_memory_cells": 0,
            "object_byte_owners": 0,
            "initial_states": 1,
            "preexisting_blockers": 0,
            "checked_exception_transitions": 0,
        })

        context_payload["roots"] = [0x2000]
        with self.assertRaisesRegex(ValueError, "outside the guest-code"):
            native.inspect_reference_closure_inputs(
                json.dumps(
                    plan, separators=(",", ":"), sort_keys=True,
                ).encode(),
                json.dumps(
                    context_payload, separators=(",", ":"), sort_keys=True,
                ).encode(),
            )

    def test_native_root_expression_values_match_python_reference(self) -> None:
        plan = self._minimal_transfer_plan()

        def expression(
            operation: str, operands: list[int], *, aux: int = 0,
            immediate: int = 0,
        ) -> dict[str, Any]:
            spec = EXPRESSION_OPERATIONS_V2[operation]
            return {
                "id": len(plan["transfers"][0]["expressions"]),
                "op": operation,
                "operands": operands,
                "result_sort": spec.result_sort,
                "width_bits": spec.width_bits,
                "parameters": {
                    "aux": aux,
                    "immediate": immediate,
                    "identity": None,
                },
            }

        transfer_payload = plan["transfers"][0]
        transfer_payload["expressions"] = []
        for operation, operands, parameters in (
            ("const", [], {"immediate": 0x4004}),
            ("const", [], {"immediate": 4}),
            ("add32", [0, 1], {}),
            ("load", [2], {"aux": 4}),
            ("const", [], {"immediate": 10}),
            ("ult32", [3, 4], {}),
            ("const", [], {"immediate": 0}),
            ("ite", [5, 3, 6], {}),
            ("sub32", [2, 0], {}),
            ("and32", [4, 8], {}),
        ):
            transfer_payload["expressions"].append(expression(
                operation, operands, **parameters,
            ))
        transfer_payload["effects"] = []
        transfer_payload["terminator"]["operands"] = [7]
        baseline = {
            ("object", "image:data", 8, 4):
            finite_reference_value_v1(scalars=(9,)),
        }
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
            objects=(ObjectRangeV1("image:data", 0x4000, 0x100),),
            initial_memory=baseline,
        )
        state = ReferenceStateV1()
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected = [
            value.payload() for value in interpret_reference_expressions_v1(
                _transfer_from_payload(transfer_payload), state, catalog
            )
        ]
        observed = json.loads(native.evaluate_reference_root_expressions(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {
            "roots": [{"rva": 0x1000, "values": expected}],
        })

    def test_native_stack_alignment_uses_one_canonical_coordinate(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]

        def expression(
            index: int, operation: str, operands: list[int], *,
            aux: int = 0, immediate: int = 0,
        ) -> dict[str, Any]:
            spec = EXPRESSION_OPERATIONS_V2[operation]
            return {
                "id": index,
                "op": operation,
                "operands": operands,
                "result_sort": spec.result_sort,
                "width_bits": spec.width_bits,
                "parameters": {
                    "aux": aux,
                    "immediate": immediate,
                    "identity": None,
                },
            }

        transfer_payload["expressions"] = [
            expression(0, "reg", [], aux=7, immediate=1),
            expression(1, "const", [], immediate=0xFFFF_FFF0),
            expression(2, "and32", [0, 1]),
            expression(3, "const", [], immediate=7),
            expression(4, "add32", [2, 3]),
            expression(5, "and32", [4, 1]),
        ]
        transfer_payload["effects"] = []
        transfer_payload["terminator"]["operands"] = [5]
        registers = list(ReferenceStateV1().registers)
        registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1(
                "object", "captured_stack_frame:caller", -16,
            ),
        ))
        state = ReferenceStateV1(registers=tuple(registers))
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected = [
            value.payload() for value in interpret_reference_expressions_v1(
                _transfer_from_payload(transfer_payload), state, catalog
            )
        ]
        observed = json.loads(native.evaluate_reference_root_expressions(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {
            "roots": [{"rva": 0x1000, "values": expected}],
        })
        aligned = expected[2]["references"]
        self.assertEqual(aligned, [{
            "kind": "object",
            "identity": (
                "aligned:fffffff0:captured_stack_frame:caller:-16"
            ),
            "offset": 0,
        }])
        self.assertEqual(expected[5]["references"], aligned)

    def test_native_memory_range_wire_codec_preserves_extended_endpoints(
        self,
    ) -> None:
        lower = -(1 << 63)
        upper = 1 << 63
        state = ReferenceStateV1(
            invalidated_memory_ranges=frozenset({(
                "object", "extended", upper, upper + 128,
            )}),
            effect_invalidated_memory_ranges=frozenset({(
                "object", "extended", lower, upper,
            )}),
        )

        [observed] = _native_joins([(state, state)], baseline={})

        self.assertEqual(observed["invalidated_memory_ranges"], [{
            "kind": "object",
            "identity": "extended",
            "start": upper,
            "end": upper + 128,
        }])
        self.assertEqual(observed["effect_invalidated_memory_ranges"], [{
            "kind": "object",
            "identity": "extended",
            "start": lower,
            "end": upper,
        }])

    def test_native_root_effect_state_matches_python_reference(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer = _transfer_from_payload(plan["transfers"][0])
        state = ReferenceStateV1()
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected_state, expected_values = apply_reference_effects_v1(
            transfer, state, catalog
        )
        observed = json.loads(native.evaluate_reference_root_effects(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {"roots": [{
            "rva": 0x1000,
            "state": _reference_state_kernel_payload_v1(expected_state),
            "values": [value.payload() for value in expected_values],
        }]})

    def test_native_unknown_repeat_write_is_object_scoped(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
        transfer_payload["expressions"] = [
            {
                "id": index, "op": operation, "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": aux, "immediate": immediate, "identity": None,
                },
            }
            for index, (operation, aux, immediate) in enumerate((
                ("reg", 0, 0),
                ("reg", 1, 0),
                ("reg", 2, 0),
                ("const", 0, 0),
            ))
        ]
        transfer_payload["effects"] = [{
            "id": 0,
            "op": "rep_movs",
            "operands": [0, 1, 2, 3],
            "parameters": {"aux": 4},
        }]
        transfer_payload["terminator"]["operands"] = [3]
        registers = list(ReferenceStateV1().registers)
        registers[1] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "image:.bss", 16),
        ))
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        state = ReferenceStateV1(
            registers=tuple(registers),
            memory={
                ("object", "image:.bss", 32, 4): target,
                ("object", "image:.data", 12, 4): target,
            },
        )
        catalog = ReferenceCatalogV1(guest_code_rvas=frozenset({0x1000}))
        context = ExecutionClosureContextV1(
            roots=(0x1000,), catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected_state, expected_values = apply_reference_effects_v1(
            _transfer_from_payload(transfer_payload), state, catalog
        )

        observed = json.loads(native.evaluate_reference_root_effects(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))

        self.assertFalse(expected_state.all_memory_invalidated)
        self.assertEqual(observed, {"roots": [{
            "rva": 0x1000,
            "state": _reference_state_kernel_payload_v1(expected_state),
            "values": [value.payload() for value in expected_values],
        }]})

    def test_native_coarse_write_invalidation_preserves_immutable_image(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
        transfer_payload["expressions"] = [
            {
                "id": 0, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0x4000, "identity": None,
                },
            },
            {
                "id": 1, "op": "load", "operands": [0],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 4, "immediate": 0, "identity": None,
                },
            },
            {
                "id": 2, "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0x5000, "identity": None,
                },
            },
            {
                "id": 3, "op": "load", "operands": [2],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 4, "immediate": 0, "identity": None,
                },
            },
        ]
        transfer_payload["effects"] = []
        transfer_payload["terminator"]["operands"] = [1]
        immutable_value = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002000"),
        ))
        writable_value = finite_reference_value_v1(scalars=(7,))
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000, 0x2000}),
            objects=(
                ObjectRangeV1("image:rdata", 0x4000, 0x100, writable=False),
                ObjectRangeV1("image:data", 0x5000, 0x100),
            ),
            initial_memory={
                ("object", "image:rdata", 0, 4): immutable_value,
                ("object", "image:data", 0, 4): writable_value,
            },
        )
        state = ReferenceStateV1(all_memory_invalidated=True)
        context = ExecutionClosureContextV1(
            roots=(0x1000,), catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected = [
            value.payload() for value in interpret_reference_expressions_v1(
                _transfer_from_payload(transfer_payload), state, catalog
            )
        ]
        self.assertEqual(expected[1], immutable_value.payload())
        self.assertEqual(expected[3], UNKNOWN_SCALAR_REFERENCE_V1.payload())
        observed = json.loads(native.evaluate_reference_root_expressions(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {
            "roots": [{"rva": 0x1000, "values": expected}],
        })

    def test_native_dynamic_stack_region_matches_python_reference(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
        transfer_payload["expressions"] = [
            {
                "id": 0, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 7, "immediate": 1, "identity": None,
                },
            },
            {
                "id": 1, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 1, "identity": None,
                },
            },
            {
                "id": 2, "op": "sub32", "operands": [0, 1],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 0, "identity": None,
                },
            },
        ]
        transfer_payload["effects"] = [
            {
                "id": index, "op": operation, "operands": operands,
                "parameters": {"aux": aux},
            }
            for index, (operation, operands, aux) in enumerate((
                ("eval_word", [0], 0),
                ("eval_word", [1], 0),
                ("eval_word", [2], 0),
                ("set_reg", [2], 7),
            ))
        ]
        transfer_payload["terminator"]["operands"] = [0]
        registers = list(ReferenceStateV1().registers)
        registers[7] = finite_reference_value_v1(references=(
            ReferenceAtomV1(
                "object", "captured_stack_frame:fixture", 32,
            ),
        ))
        state = ReferenceStateV1(registers=tuple(registers))
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,), catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected_state, expected_values = apply_reference_effects_v1(
            _transfer_from_payload(transfer_payload), state, catalog
        )
        observed = json.loads(native.evaluate_reference_root_effects(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {"roots": [{
            "rva": 0x1000,
            "state": _reference_state_kernel_payload_v1(expected_state),
            "values": [value.payload() for value in expected_values],
        }]})

        repeated_state, repeated_values = apply_reference_effects_v1(
            _transfer_from_payload(transfer_payload), expected_state, catalog
        )
        self.assertEqual(repeated_state.registers[7], expected_state.registers[7])
        repeated_context = replace(
            context, initial_states={0x1000: expected_state}
        )
        repeated_observed = json.loads(native.evaluate_reference_root_effects(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(
                    repeated_context
                ),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(repeated_observed, {"roots": [{
            "rva": 0x1000,
            "state": _reference_state_kernel_payload_v1(repeated_state),
            "values": [value.payload() for value in repeated_values],
        }]})

    def test_native_repeated_memory_effect_matches_python_reference(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
        transfer_payload["expressions"] = [
            {
                "id": index,
                "op": "const",
                "operands": [],
                "result_sort": "bitvector",
                "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": immediate, "identity": None,
                },
            }
            for index, immediate in enumerate((0x4000, 7, 3, 0))
        ]
        transfer_payload["effects"] = [{
            "id": 0,
            "op": "rep_stos",
            "operands": [0, 1, 2, 3],
            "parameters": {"aux": 4},
        }]
        transfer_payload["terminator"]["operands"] = [1]
        transfer = _transfer_from_payload(transfer_payload)
        state = ReferenceStateV1()
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
            objects=(ObjectRangeV1("image:data", 0x4000, 0x100),),
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected_state, expected_values = apply_reference_effects_v1(
            transfer, state, catalog
        )
        observed = json.loads(native.evaluate_reference_root_effects(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {"roots": [{
            "rva": 0x1000,
            "state": _reference_state_kernel_payload_v1(expected_state),
            "values": [value.payload() for value in expected_values],
        }]})

    def test_native_external_call_effect_matches_python_reference(self) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
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
        for immediate in (0x4000, 0x5000, 8):
            expressions.append({
                "id": len(expressions), "op": "const", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": immediate, "identity": None,
                },
            })
        transfer_payload["expressions"] = expressions
        transfer_payload["effects"] = [{
            "id": 0, "op": "call", "operands": [0],
            "parameters": {"aux": 0},
        }]
        transfer_payload["calls"] = [{
            "id": 0,
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "event_index": 0,
            "target_node": None,
            "target_rva": 0,
            "return_rva": 0x1001,
            "dll": "fixture.dll",
            "symbol": "mutate",
            "ordinal": None,
            "register_nodes": list(range(8)),
            "flag_nodes": list(range(8, 14)),
            "argument_nodes": [14, 15, 16],
            "stack_inputs": [],
        }]
        transfer_payload["terminator"]["operands"] = [0]
        transfer = _transfer_from_payload(transfer_payload)
        registers = list(ReferenceStateV1().registers)
        registers[1] = finite_reference_value_v1(scalars=(3,))
        state = ReferenceStateV1(registers=tuple(registers))
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
            objects=(
                ObjectRangeV1("image:data", 0x4000, 0x100),
                ObjectRangeV1("image:source", 0x5000, 0x100),
            ),
            external_calls={
                ("fixture.dll", "mutate"): ExternalCallRuleV1(
                    preserved_registers=frozenset({1}),
                    argument_words=3,
                    allocation_result_register=0,
                    allocation_nullable=True,
                    write_footprints=(ExternalMemoryWriteV1(
                        base_argument=0,
                        offset=0,
                        size_argument=2,
                        authority_selector="image:data",
                    ),),
                    memory_copies=(ExternalMemoryCopyV1(0, 1, 2),),
                ),
            },
            initial_memory={
                ("object", "image:source", 4, 4):
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("guest_code", "rva:00001000"),
                )),
            },
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        expected_state, expected_values = apply_reference_effects_v1(
            transfer, state, catalog
        )
        observed = json.loads(native.evaluate_reference_root_effects(
            json.dumps(plan, separators=(",", ":"), sort_keys=True).encode(),
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        self.assertEqual(observed, {"roots": [{
            "rva": 0x1000,
            "state": _reference_state_kernel_payload_v1(expected_state),
            "values": [value.payload() for value in expected_values],
        }]})
