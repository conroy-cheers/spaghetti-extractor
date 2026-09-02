from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import unittest

import z3

from spaghetti_extractor.candidate.behavioral_c_render import (
    behavioral_c_operation_coverage_v2,
)
from spaghetti_extractor.transfer.definedness import (
    definedness_operation_coverage_v2,
)
from spaghetti_extractor.transfer.closure import (
    ExecutionClosureContextV1,
    ExecutionFunctionContextV1,
    OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1,
    _explicit_outgoing_stack_cells_v1,
    _external_write_authority_selector_v1,
    _outgoing_stack_projection_exceeds_limit_v1,
    _return_state_for_caller_v1,
    build_module_execution_closure_v1,
    join_reference_states_v1,
    validate_module_execution_closure_v1,
)
from spaghetti_extractor.transfer.evaluator import concrete_operation_coverage_v2
from spaghetti_extractor.transfer.interpretation import (
    DomainOperationCoverageV2,
    operation_coverage_matrix_v2,
)
from spaghetti_extractor.transfer.model import (
    TransferPlanError,
    _Action,
    _Call,
    _Node,
    _Transfer,
)
from spaghetti_extractor.transfer.operations import (
    EFFECT_OPERATIONS_V2,
    EXPRESSION_OPERATIONS_V2,
    TERMINATOR_OPERATIONS_V2,
)
from spaghetti_extractor.transfer.provenance import (
    CONFLICT_REFERENCE_V1,
    ExternalCallbackRuleV1,
    ExternalCallRuleV1,
    ExternalMemoryCopyV1,
    ExternalMemoryWriteV1,
    ExternalOutPointerV1,
    ObjectRangeV1,
    ReferenceAtomV1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    apply_reference_effects_v1,
    finite_reference_value_v1,
    indirect_targets_v1,
    join_reference_values_v1,
    reference_operation_coverage_v2,
    refine_reference_state_for_branch_v1,
)
from spaghetti_extractor.transfer.z3_domain import (
    reconstruct_expressions_z3_v2,
    z3_operation_coverage_v2,
)


def _transfer(nodes: tuple[_Node, ...]) -> _Transfer:
    return _Transfer(
        identity="semantic-transfer:interpretation-fixture",
        contract_sha256="a" * 64,
        instruction_bytes_sha256="b" * 64,
        rva_start=0x1000,
        nodes=nodes,
        x87_nodes=(),
        actions=(_Action("outcome_return", (0,)),),
        calls=(),
        x87_operations=(),
    )


class TransferInterpretationTests(unittest.TestCase):
    @staticmethod
    def _call(
        kind: str, *, target_rva: int = 0, dll: str | None = None,
        symbol: str | None = None,
    ) -> _Call:
        return _Call(
            kind=kind,
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=target_rva,
            return_rva=0x1008,
            dll=dll,
            symbol=symbol,
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(),
            stack_inputs=(),
        )
    @staticmethod
    def _call_input_nodes() -> tuple[_Node, ...]:
        return (
            *(_Node("reg", aux=index) for index in range(8)),
            *(_Node("flag", aux=index) for index in range(6)),
        )

    def test_internal_return_override_does_not_rewrite_call_input_snapshot(
        self,
    ) -> None:
        call = self._call("internal_call", target_rva=0x2000)
        transfer = _Transfer(
            "semantic-transfer:call-input-snapshot",
            "a" * 64,
            "b" * 64,
            0x1000,
            (
                *self._call_input_nodes(),
                _Node("call_response", aux=0),
            ),
            (),
            (
                _Action("call", (0,)),
                _Action("outcome_return", (14,)),
            ),
            (call,),
            (),
        )
        before = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        after = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00004000"),
        ))
        inputs: dict[int, ReferenceStateV1] = {}
        output, _values = apply_reference_effects_v1(
            transfer,
            ReferenceStateV1(callback_registry={"handler": before}),
            ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x3000, 0x4000}),
            ),
            call_result_overrides={
                0: ReferenceStateV1(callback_registry={"handler": after}),
            },
            call_input_states=inputs,
        )

        self.assertEqual(inputs[0].callback_registry, {"handler": before})
        self.assertEqual(output.callback_registry, {"handler": after})
        self.assertIsNot(
            inputs[0].callback_registry, output.callback_registry,
        )

    def test_loader_written_iat_function_is_typed_external_target(self) -> None:
        call = _Call(
            kind="indirect_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=15,
            target_rva=0,
            return_rva=0x1008,
            dll=None,
            symbol=None,
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(),
            stack_inputs=(),
        )
        transfer = _Transfer(
            "semantic-transfer:iat-call", "a" * 64, "b" * 64, 0x1000,
            (
                *self._call_input_nodes(),
                _Node("const", immediate=0x4010),
                _Node("load", (14,), aux=4),
                _Node("call_response", aux=7),
            ), (),
            (
                _Action("eval_word", (15,)),
                _Action("call", (0,)),
                _Action("set_reg", (16,), aux=7),
                _Action("outcome_return", (0,)),
            ),
            (call,), (),
        )
        slot_id = "fixture.exe:iat:00004010"
        key = ("kernel32.dll", "VirtualProtect")
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(transfer,),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000}),
                    objects=(ObjectRangeV1("imports", 0x4000, 0x100),),
                    external_function_contracts={slot_id: key},
                    external_calls={key: ExternalCallRuleV1(
                        preserved_registers=frozenset({1, 4, 5, 6, 7}),
                        stack_cleanup_bytes=16,
                    )},
                    initial_memory={
                        ("object", "imports", 0x10, 4):
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1("external_function", slot_id),
                        )),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["indirect_targets"], [{
            "source_rva": 0x1000,
            "site": "call:00001004:0",
            "targets": [],
            "external_targets": [{
                "dll": "kernel32.dll", "identity": "VirtualProtect",
            }],
            "provenance": [{
                "kind": "finite",
                "scalars": [],
                "references": [{
                    "kind": "external_function",
                    "identity": slot_id,
                    "offset": 0,
                }],
            }],
        }])

    def test_callback_sentinel_branches_are_narrowed_before_indirect_use(
        self,
    ) -> None:
        inputs = self._call_input_nodes()
        signal_call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0x1008,
            dll="msvcrt.dll",
            symbol="signal",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(14, 15),
            stack_inputs=(),
        )
        register = _Transfer(
            "semantic-transfer:signal", "a" * 64, "b" * 64, 0x1000,
            (
                *inputs,
                _Node("const", immediate=4),
                _Node("const", immediate=0),
                _Node("call_response", aux=0),
            ), (),
            (
                _Action("call", (0,)),
                _Action("set_reg", (16,), aux=0),
                _Action("outcome_fallthrough", (0x1008,)),
            ),
            (signal_call,), (),
        )

        def compare(rva: int, constant: int, yes: int, no: int) -> _Transfer:
            return _Transfer(
                f"semantic-transfer:compare-{constant}",
                str(constant + 1) * 64,
                str(constant + 2) * 64,
                rva,
                (
                    _Node("reg", aux=0, immediate=1),
                    _Node("const", immediate=constant),
                    _Node("sub32", (0, 1)),
                    _Node("const", immediate=0),
                    _Node("eq", (2, 3)),
                    _Node("flag", aux=1, immediate=1),
                ), (),
                (
                    _Action("set_flag", (4,), aux=1),
                    _Action("eval_word", (5,)),
                    _Action("outcome_branch", (5, yes, no)),
                ), (), (),
            )

        dispatch = _Transfer(
            "semantic-transfer:unreachable-dispatch",
            "c" * 64, "d" * 64, 0x1020,
            (_Node("reg", aux=0, immediate=1),), (),
            (_Action("outcome_indirect", (0,)),), (), (),
        )
        done = _Transfer(
            "semantic-transfer:done", "e" * 64, "f" * 64, 0x2000,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(
                register,
                compare(0x1008, 1, 0x2000, 0x1010),
                compare(0x1010, 0, 0x2000, 0x1020),
                dispatch,
                done,
            ),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x1000, 0x1008, 0x1010, 0x1020, 0x2000,
                    }),
                    external_calls={
                        ("msvcrt.dll", "signal"): ExternalCallRuleV1(
                            argument_words=2,
                            callback=ExternalCallbackRuleV1(
                                protocol_id="signal",
                                source_argument=1,
                                sentinels=frozenset({0, 1}),
                                action="replace",
                                instance_argument=0,
                                previous_result_register=0,
                                previous_sentinels=frozenset({0, 1}),
                            ),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertNotIn(
            0x1020, [row["rva"] for row in closure["reachable_units"]]
        )
        self.assertEqual(closure["indirect_targets"], [])

    def test_callback_target_is_loaded_from_checked_argument_pointee(self) -> None:
        inputs = self._call_input_nodes()
        call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0x1008,
            dll="user32.dll",
            symbol="RegisterClassA",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(14,),
            stack_inputs=(),
        )
        register = _Transfer(
            "semantic-transfer:register-class", "a" * 64, "b" * 64,
            0x1000,
            (*inputs, _Node("const", immediate=0x7000)),
            (),
            (
                _Action("call", (0,)),
                _Action("outcome_fallthrough", (0x1008,)),
            ),
            (call,),
            (),
        )
        continuation = _Transfer(
            "semantic-transfer:register-class-continuation",
            "c" * 64, "d" * 64, 0x1008,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        callback_target = _Transfer(
            "semantic-transfer:window-procedure",
            "e" * 64, "f" * 64, 0x2200,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(register, continuation, callback_target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x1008, 0x2200}),
                    objects=(ObjectRangeV1("wndclass", 0x7000, 40),),
                    initial_memory={
                        ("object", "wndclass", 4, 4):
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1(
                                "guest_code", "rva:00002200"
                            ),
                        )),
                    },
                    external_calls={
                        ("user32.dll", "RegisterClassA"):
                        ExternalCallRuleV1(
                            argument_words=1,
                            callback=ExternalCallbackRuleV1(
                                protocol_id="win32-window-procedure-ansi",
                                source_argument=0,
                                source_kind="argument_pointee",
                                source_offset=4,
                                instance_kind="provider_resource",
                                instance_argument=0,
                            ),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["callback_escapes"][0]["targets"], [0x2200])
        self.assertIn(
            0x2200, [row["rva"] for row in closure["reachable_units"]]
        )

    def test_unknown_write_extent_remains_within_destination_object(self) -> None:
        inputs = self._call_input_nodes()
        call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0x1010,
            dll="msvcrt.dll",
            symbol="memcpy",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(14, 15, 0),
            stack_inputs=(),
        )
        copy = _Transfer(
            "semantic-transfer:object-local-copy",
            "a" * 64, "b" * 64, 0x1000,
            (
                *inputs,
                _Node("const", immediate=0x4010),
                _Node("const", immediate=0),
            ), (),
            (_Action("call", (0,)), _Action("outcome_fallthrough", (0x1010,))),
            (call,), (),
        )
        dispatch = _Transfer(
            "semantic-transfer:unrelated-table",
            "c" * 64, "d" * 64, 0x1010,
            (_Node("const", immediate=0x5010), _Node("load", (0,), aux=4)),
            (), (_Action("outcome_indirect", (1,)),), (), (),
        )
        target = _Transfer(
            "semantic-transfer:target", "e" * 64, "f" * 64, 0x2200,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(copy, dispatch, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x1010, 0x2200}),
                    objects=(
                        ObjectRangeV1("buffer", 0x4000, 0x100),
                        ObjectRangeV1("dispatch-table", 0x5000, 0x100),
                    ),
                    external_calls={
                        ("msvcrt.dll", "memcpy"): ExternalCallRuleV1(
                            argument_words=3,
                            write_footprints=(ExternalMemoryWriteV1(
                                base_argument=0,
                                offset=0,
                                size_argument=2,
                                authority_selector="buffer",
                            ),),
                        ),
                    },
                    initial_memory={
                        ("object", "dispatch-table", 0x10, 4):
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1("guest_code", "rva:00002200"),
                        )),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(
            [row["rva"] for row in closure["reachable_units"]],
            [0x1000, 0x1010, 0x2200],
        )

    def test_checked_external_byte_copy_transfers_reference_words(self) -> None:
        inputs = self._call_input_nodes()
        call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0,
            dll="msvcrt.dll",
            symbol="memcpy",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(14, 15, 16),
            stack_inputs=(),
        )
        transfer = _Transfer(
            "semantic-transfer:checked-copy",
            "a" * 64,
            "b" * 64,
            0x1000,
            (
                *inputs,
                _Node("const", immediate=0x4000),
                _Node("const", immediate=0x5000),
                _Node("const", immediate=8),
            ),
            (),
            (_Action("call", (0,)), _Action("outcome_return", (0,))),
            (call,),
            (),
        )
        pointer = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002200"),
        ))
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x1000, 0x2200}),
            objects=(
                ObjectRangeV1("destination", 0x4000, 0x100),
                ObjectRangeV1("source", 0x5000, 0x100),
            ),
            external_calls={
                ("msvcrt.dll", "memcpy"): ExternalCallRuleV1(
                    argument_words=3,
                    write_footprints=(ExternalMemoryWriteV1(
                        base_argument=0,
                        offset=0,
                        size_argument=2,
                    ),),
                    memory_copies=(ExternalMemoryCopyV1(0, 1, 2),),
                ),
            },
            initial_memory={("object", "source", 4, 4): pointer},
        )
        result, _values = apply_reference_effects_v1(
            transfer, ReferenceStateV1(), catalog
        )
        self.assertEqual(result.memory[("object", "destination", 4, 4)], pointer)

    def test_external_write_authority_selector_rejects_other_object(
        self,
    ) -> None:
        call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0,
            dll="fixture.dll",
            symbol="mutate",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(14,),
            stack_inputs=(),
        )
        transfer = _Transfer(
            "semantic-transfer:selected-write",
            "a" * 64,
            "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("const", immediate=0x4010)),
            (),
            (_Action("call", (0,)), _Action("outcome_return", (0,))),
            (call,),
            (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(transfer,),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000}),
                    objects=(ObjectRangeV1("image:data", 0x4000, 0x100),),
                    external_calls={
                        ("fixture.dll", "mutate"): ExternalCallRuleV1(
                            argument_words=1,
                            write_footprints=(ExternalMemoryWriteV1(
                                base_argument=0,
                                offset=0,
                                fixed_bytes=4,
                                authority_selector="image:other",
                            ),),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        blockers = [
            row for row in closure["blockers"]
            if row["code"] == "unresolved_external_memory_write_footprint"
        ]
        self.assertEqual(len(blockers), 1)
        self.assertEqual(blockers[0]["instruction_rva"], 0x1004)

    def test_unresolved_external_write_reports_causal_boundary_blocker(
        self,
    ) -> None:
        call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0,
            dll="msvcrt.dll",
            symbol="memcpy",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(0, 1, 2),
            stack_inputs=(),
        )
        transfer = _Transfer(
            "semantic-transfer:unresolved-copy",
            "a" * 64,
            "b" * 64,
            0x1000,
            self._call_input_nodes(),
            (),
            (_Action("call", (0,)), _Action("outcome_return", (0,))),
            (call,),
            (),
        )

        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(transfer,),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000}),
                    external_calls={
                        ("msvcrt.dll", "memcpy"): ExternalCallRuleV1(
                            argument_words=3,
                            write_footprints=(ExternalMemoryWriteV1(
                                base_argument=0,
                                offset=0,
                                size_argument=2,
                            ),),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        blockers = [
            row for row in closure["blockers"]
            if row["code"] == "unresolved_external_memory_write_footprint"
        ]
        self.assertEqual(len(blockers), 1)
        self.assertEqual(blockers[0]["instruction_rva"], 0x1004)
        self.assertEqual(blockers[0]["external_targets"], [{
            "dll": "msvcrt.dll", "identity": "memcpy",
        }])

    def test_tail_external_frame_recovers_callback_after_return_address(self) -> None:
        inputs = self._call_input_nodes()
        call = self._call("external_call", dll="msvcrt.dll", symbol="atexit")
        invoke_wrapper = self._call("internal_call", target_rva=0x1000)
        caller = _Transfer(
            "semantic-transfer:tail-caller", "1" * 64, "2" * 64, 0x0800,
            (*inputs, _Node("const", immediate=0x2200)), (),
            (
                _Action("memory_write", (7, 14), aux=4),
                _Action("call", (0,)),
                _Action("outcome_fallthrough", (0x0900,)),
            ), (invoke_wrapper,), (),
        )
        continuation = _Transfer(
            "semantic-transfer:tail-continuation", "3" * 64, "4" * 64,
            0x0900, (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        register = _Transfer(
            "semantic-transfer:tail-atexit", "a" * 64, "b" * 64, 0x1000,
            (
                *inputs,
                _Node("const", immediate=4),
                _Node("add32", (7, 14)),
                _Node("const", immediate=0x2200),
            ), (),
            (
                _Action("memory_write", (15, 16), aux=4),
                _Action("call", (0,)),
                _Action("outcome_external"),
            ), (call,), (),
        )
        target = _Transfer(
            "semantic-transfer:registered", "c" * 64, "d" * 64, 0x2200,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "stack", 0),
        ))
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(caller, continuation, register, target),
            context=ExecutionClosureContextV1(
                roots=(0x0800,),
                initial_states={
                    0x0800: ReferenceStateV1(registers=(
                        *ReferenceStateV1().registers[:7], stack,
                    )),
                },
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x0800, 0x0900, 0x1000, 0x2200,
                    }),
                    objects=(ObjectRangeV1("stack", 0x7000, 0x100),),
                    external_calls={
                        ("msvcrt.dll", "atexit"): ExternalCallRuleV1(
                            argument_words=1,
                            callback=ExternalCallbackRuleV1(
                                protocol_id="atexit",
                                source_argument=0,
                            ),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["callback_escapes"][0]["targets"], [0x2200])
        self.assertIn(0x2200, [row["rva"] for row in closure["reachable_units"]])
        self.assertIn(0x0900, [row["rva"] for row in closure["reachable_units"]])
        validate_module_execution_closure_v1(closure)

        malformed_escape = deepcopy(closure)
        malformed_escape["callback_escapes"][0]["targets"] = [0xDEAD]
        with self.assertRaisesRegex(
            TransferPlanError, "callback target is not reachable"
        ):
            validate_module_execution_closure_v1(malformed_escape)

    def test_closure_validator_rejects_content_hash_corruption(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:validated", "a" * 64, "b" * 64, 0x1000,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(transfer,),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000})
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )
        validate_module_execution_closure_v1(closure)
        corrupted = deepcopy(closure)
        corrupted["witnesses"][0]["call_string"].append(0xDEAD)

        with self.assertRaisesRegex(
            TransferPlanError, "identity does not match"
        ) as caught:
            validate_module_execution_closure_v1(corrupted)
        self.assertEqual(
            caught.exception.code, "malformed_module_execution_closure"
        )

        transient_state = deepcopy(closure)
        transient_state["witnesses"][0]["state_sha256"] = "3" * 64
        with self.assertRaisesRegex(
            TransferPlanError, "witnesses are malformed"
        ):
            validate_module_execution_closure_v1(transient_state)

    def test_execution_closure_recovers_stored_guest_target(self) -> None:
        store = _Transfer(
            "semantic-transfer:store", "a" * 64, "b" * 64, 0x1000,
            (_Node("const", immediate=0x4010), _Node("const", immediate=0x2200)),
            (),
            (
                _Action("memory_write", (0, 1), aux=4),
                _Action("outcome_jump", (0x1010,)),
            ),
            (), (),
        )
        dispatch = _Transfer(
            "semantic-transfer:dispatch", "c" * 64, "d" * 64, 0x1010,
            (_Node("const", immediate=0x4010), _Node("load", (0,), aux=4)),
            (), (_Action("outcome_indirect", (1,)),), (), (),
        )
        target = _Transfer(
            "semantic-transfer:target", "e" * 64, "f" * 64, 0x2200,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x1010, 0x2200}),
                objects=(ObjectRangeV1("allocation:list", 0x4000, 0x100),),
            ),
            authority_bindings={
                "machine_object_authority_sha256": "2" * 64,
                "resolved_external_environment_sha256": "3" * 64,
            },
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(store, dispatch, target),
            context=context,
        )
        alternate_schedule = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(store, dispatch, target),
            context=context,
            dynamic_scheduling=False,
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertTrue(closure["authorizes_execution"])
        self.assertEqual(
            [row["rva"] for row in closure["reachable_units"]],
            [0x1000, 0x1010, 0x2200],
        )
        self.assertEqual(closure["indirect_targets"], [{
            "source_rva": 0x1010,
            "site": "terminator",
            "targets": [0x2200],
            "external_targets": [],
            "provenance": [{
                "kind": "finite",
                "scalars": [],
                "references": [{
                    "kind": "guest_code",
                    "identity": "rva:00002200",
                    "offset": 0,
                }],
            }],
        }])
        self.assertEqual(
            {
                key: value for key, value in closure.items()
                if key != "metrics"
            },
            {
                key: value for key, value in alternate_schedule.items()
                if key != "metrics"
            },
        )

    def test_execution_closure_blocks_unknown_indirect_target(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:unknown", "a" * 64, "b" * 64, 0x1000,
            (_Node("reg", aux=0),), (),
            (_Action("outcome_indirect", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(transfer,),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({0x1000})),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "incomplete")
        self.assertFalse(closure["authorizes_execution"])
        self.assertEqual(
            closure["blockers"][0]["code"],
            "unresolved_reachable_indirect_target",
        )

    def test_execution_closure_rejects_inferred_target_outside_finite_route(
        self,
    ) -> None:
        dispatch = _Transfer(
            "semantic-transfer:finite-route-conflict",
            "a" * 64,
            "b" * 64,
            0x1000,
            (_Node("reg", aux=0),),
            (),
            (_Action("outcome_indirect", (0,)),),
            (),
            (),
        )
        unauthorized = _Transfer(
            "semantic-transfer:unauthorized-target",
            "c" * 64,
            "d" * 64,
            0x2000,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        authorized = replace(
            unauthorized,
            identity="semantic-transfer:authorized-target",
            rva_start=0x3000,
        )
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002000"),
        ))
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(dispatch, unauthorized, authorized),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000})
                ),
                authority_bindings={"authority_sha256": "2" * 64},
                initial_states={
                    0x1000: ReferenceStateV1(registers=tuple(registers)),
                },
                finite_control_targets={0x1000: (0x3000,)},
            ),
        )

        self.assertEqual(
            {row["code"] for row in closure["blockers"]},
            {
                "finite_control_route_conflict",
                "unresolved_reachable_indirect_target",
            },
        )
        self.assertEqual(
            [row["rva"] for row in closure["reachable_units"]], [0x1000]
        )
        self.assertIsNone(closure["indirect_targets"][0]["targets"])
