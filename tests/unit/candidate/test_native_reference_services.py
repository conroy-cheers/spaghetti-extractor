"""Loader, x87, and relational memory cases for the native reference kernel."""

from __future__ import annotations

import unittest

from . import test_native_reference_effects as support
from .test_native_reference_effects import (
    ExecutionClosureContextV1,
    ExternalCallRuleV1,
    ObjectRangeV1,
    ReferenceAtomV1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
    _execution_closure_kernel_context_payload_v1,
    _reference_state_kernel_payload_v1,
    _transfer_from_payload,
    apply_reference_effects_v1,
    finite_reference_value_v1,
    interpret_reference_expressions_v1,
    json,
    native,
    typed_x87_operation_from_micro_op,
)


@unittest.skipIf(native is None, "native extension is unavailable")
class NativeReferenceKernelServiceTests(unittest.TestCase):
    @staticmethod
    def _minimal_transfer_plan():
        return support.NativeReferenceKernelTests._minimal_transfer_plan()
    def test_native_loader_service_and_indirect_external_call_match_python(
        self,
    ) -> None:
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
        for operation, aux, immediate in (
            ("const", 0, 0x4000),
            ("call_response", 0, 1),
            ("const", 0, 0x4010),
            ("call_response", 0, 1),
            ("call_response", 0, 1),
        ):
            expressions.append({
                "id": len(expressions), "op": operation, "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": aux, "immediate": immediate, "identity": None,
                },
            })
        transfer_payload["expressions"] = expressions
        transfer_payload["effects"] = [
            {
                "id": index, "op": "call", "operands": [index],
                "parameters": {"aux": 0},
            }
            for index in range(3)
        ]
        transfer_payload["calls"] = [
            {
                "id": 0, "kind": "external_call",
                "instruction_rva": 0x1000, "event_index": 0,
                "target_node": None, "target_rva": 0,
                "return_rva": 0x1001, "dll": "kernel32.dll",
                "symbol": "LoadLibraryA", "ordinal": None,
                "register_nodes": list(range(8)),
                "flag_nodes": list(range(8, 14)),
                "argument_nodes": [14], "stack_inputs": [],
            },
            {
                "id": 1, "kind": "external_call",
                "instruction_rva": 0x1001, "event_index": 1,
                "target_node": None, "target_rva": 0,
                "return_rva": 0x1002, "dll": "kernel32.dll",
                "symbol": "GetProcAddress", "ordinal": None,
                "register_nodes": list(range(8)),
                "flag_nodes": list(range(8, 14)),
                "argument_nodes": [15, 16], "stack_inputs": [],
            },
            {
                "id": 2, "kind": "indirect_call",
                "instruction_rva": 0x1002, "event_index": 2,
                "target_node": 17, "target_rva": 0,
                "return_rva": 0x1003, "dll": None,
                "symbol": None, "ordinal": None,
                "register_nodes": list(range(8)),
                "flag_nodes": list(range(8, 14)),
                "argument_nodes": [], "stack_inputs": [],
            },
        ]
        transfer_payload["terminator"]["operands"] = [18]
        transfer = _transfer_from_payload(transfer_payload)
        function_identity = "loader-function:fixture.dll!mutate"
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
            objects=(ObjectRangeV1("image:names", 0x4000, 0x100),),
            object_bytes={
                "image:names": (
                    b"Fixture.DLL\0".ljust(16, b"\0") + b"mutate\0"
                ),
            },
            external_function_contracts={
                function_identity: ("fixture.dll", "mutate"),
            },
            external_calls={
                ("kernel32.dll", "LoadLibraryA"): ExternalCallRuleV1(
                    argument_words=1,
                    module_handle_name_argument=0,
                ),
                ("kernel32.dll", "GetProcAddress"): ExternalCallRuleV1(
                    argument_words=2,
                    dynamic_export_handle_argument=0,
                    dynamic_export_name_argument=1,
                    dynamic_export_results={
                        ("fixture.dll", "mutate"): function_identity,
                    },
                ),
                ("fixture.dll", "mutate"): ExternalCallRuleV1(
                    allocation_result_register=0,
                    allocation_nullable=False,
                ),
            },
        )
        state = ReferenceStateV1()
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

    def test_native_typed_x87_memory_effect_matches_python_reference(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
        transfer_payload["source"]["rva_end"] = 0x1003
        operation = typed_x87_operation_from_micro_op({
            "format": "spaghetti-extractor-x87-micro-op-v1",
            "mnemonic": "fstp",
            "operands": [{
                "kind": "memory", "width_bits": 32,
                "segment": None, "base": "eax", "index": None,
                "scale": 1, "displacement": 4,
            }],
            "size": 3,
        }, image_base=0x400000)
        transfer_payload["x87_intrinsics"] = [{
            "id": 0,
            "contract_sha256": "e" * 64,
            "image_base": 0x400000,
            "rva_start": 0x1000,
            "rva_end": 0x1003,
            "operation": operation.payload(),
            "checked_decoder": X87_CHECKED_DECODER,
            "checked_executor": X87_CHECKED_EXECUTOR,
        }]
        transfer_payload["effects"] = [{
            "id": 0, "op": "typed_x87", "operands": [0],
            "parameters": {"aux": 0},
        }]
        transfer = _transfer_from_payload(transfer_payload)
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "image:data"),
        ))
        state = ReferenceStateV1(registers=tuple(registers))
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

    def test_native_relational_memory_load_matches_python_reference(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        transfer_payload = plan["transfers"][0]
        transfer_payload["expressions"] = [
            {
                "id": 0, "op": "reg", "operands": [],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 0, "immediate": 1, "identity": None,
                },
            },
            {
                "id": 1, "op": "load", "operands": [0],
                "result_sort": "bitvector", "width_bits": 32,
                "parameters": {
                    "aux": 4, "immediate": 0, "identity": None,
                },
            },
        ]
        transfer_payload["effects"] = []
        transfer_payload["terminator"]["operands"] = [1]
        parameter = "call_parameter_object:fixture:register:0"
        actual = "captured_stack_frame:caller"
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", parameter, 4),
        ))
        state = ReferenceStateV1(
            registers=tuple(registers),
            memory={
                ("object", actual, 12, 4): finite_reference_value_v1(
                    references=(ReferenceAtomV1("object", actual, 16),),
                ),
            },
            relational_object_bindings={
                parameter: finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", actual, 8),
                )),
            },
        )
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000}),
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=catalog,
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: state},
        )
        transfer = _transfer_from_payload(transfer_payload)
        expected = [
            value.payload() for value in interpret_reference_expressions_v1(
                transfer, state, catalog
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
