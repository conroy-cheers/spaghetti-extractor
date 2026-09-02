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
from spaghetti_extractor.transfer.exception_semantics import (
    CheckedExceptionTransitionV1,
)
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
    ExternalCallbackRuleV1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    ExternalOutPointerV1,
    ObjectRangeV1,
    ReferenceAtomV1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    UNKNOWN_SCALAR_REFERENCE_V1,
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

    def test_checked_exception_seeds_handler_from_exact_pre_fault_state(
        self,
    ) -> None:
        source = _Transfer(
            "semantic-transfer:checked-fault", "a" * 64, "b" * 64, 0x1000,
            (_Node("const", immediate=7), _Node("const", immediate=0)),
            (),
            (
                _Action("set_reg", (0,), aux=0),
                _Action("divide_if", (1,)),
                _Action("outcome_return", (0,)),
            ),
            (),
            (),
        )
        handler = _Transfer(
            "semantic-transfer:checked-handler", "c" * 64, "d" * 64, 0x1100,
            (_Node("reg", aux=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        transition = CheckedExceptionTransitionV1(
            unit_id=source.identity,
            source_rva=source.rva_start,
            effect_index=1,
            fault_index=0,
            fault_sha256="e" * 64,
            transition_id="exceptional-transition-v3:" + "f" * 64,
            transition_sha256="1" * 64,
            authorizing=True,
            disposition="handled",
            handler_unit_id=handler.identity,
            handler_rva=handler.rva_start,
            guard={"op": "true"},
            blocker_code=None,
            state_projection={
                "registers": ["eax"],
                "flags": [],
                "x87": ["all"],
                "stack": [],
                "exception_record": [],
                "context": [],
            },
        )
        diagnostic_states = {}
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="2" * 64,
            transfers=(source, handler),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({source.rva_start, handler.rva_start}),
                ),
                authority_bindings={"authority_sha256": "3" * 64},
                checked_exception_transitions=(transition,),
            ),
            diagnostic_states=diagnostic_states,
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertIn({
            "source_rva": source.rva_start,
            "target_rva": handler.rva_start,
            "kind": "exception_handler",
        }, closure["reachable_edges"])
        handler_state = next(
            state for (rva, _function_context), state in diagnostic_states.items()
            if rva == handler.rva_start
        )
        self.assertEqual(
            handler_state.registers[0], finite_reference_value_v1(scalars=(7,))
        )
        self.assertTrue(all(
            value == UNKNOWN_SCALAR_REFERENCE_V1
            for value in handler_state.registers[1:]
        ))

    def test_reachable_external_call_exception_requires_checked_authority(
        self,
    ) -> None:
        call = replace(
            self._call(
                "external_call", dll="kernel32.dll", symbol="RaiseException"
            ),
            native_exception_operations=("divide_if",),
        )
        source = _Transfer(
            "semantic-transfer:external-exception",
            "a" * 64,
            "b" * 64,
            0x1000,
            self._call_input_nodes(),
            (),
            (
                _Action("call", (0,)),
                _Action("outcome_return", (0,)),
            ),
            (call,),
            (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="2" * 64,
            transfers=(source,),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({source.rva_start}),
                ),
                authority_bindings={"authority_sha256": "3" * 64},
            ),
        )
        self.assertEqual(closure["status"], "incomplete")
        self.assertIn(
            {
                "code": "reachable_call_exception_authority_missing",
                "unit_id": source.identity,
                "source_rva": source.rva_start,
                "instruction_rva": call.instruction_rva,
                "call_index": call.call_index,
                "call_kind": call.kind,
                "native_exception_operations": ["divide_if"],
            },
            closure["blockers"],
        )

    def test_checked_external_call_exception_uses_canonical_transition(
        self,
    ) -> None:
        call = replace(
            self._call(
                "external_call", dll="kernel32.dll", symbol="RaiseException"
            ),
            native_exception_operations=("divide_if",),
        )
        source = _Transfer(
            "semantic-transfer:external-exception",
            "a" * 64,
            "b" * 64,
            0x1000,
            self._call_input_nodes(),
            (),
            (_Action("call", (0,)), _Action("outcome_return", (0,))),
            (call,),
            (),
        )
        handler = _Transfer(
            "semantic-transfer:external-handler",
            "c" * 64,
            "d" * 64,
            0x1100,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        transition = CheckedExceptionTransitionV1(
            unit_id=source.identity,
            source_rva=source.rva_start,
            effect_index=0,
            fault_index=0,
            fault_sha256="e" * 64,
            transition_id="exceptional-transition-v3:" + "f" * 64,
            transition_sha256="1" * 64,
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
            call_index=call.call_index,
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="2" * 64,
            transfers=(source, handler),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        source.rva_start, handler.rva_start,
                    }),
                    external_calls={
                        ("kernel32.dll", "RaiseException"):
                        ExternalCallRuleV1()
                    },
                ),
                authority_bindings={"authority_sha256": "3" * 64},
                checked_exception_transitions=(transition,),
            ),
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(
            closure["exception_continuations"][0]["occurrence_kind"],
            "call",
        )
        self.assertEqual(
            closure["exception_continuations"][0]["call_index"], 0
        )

    def test_checked_exception_composes_ordered_unwind_return_states(self) -> None:
        source = _Transfer(
            "semantic-transfer:ordered-fault", "a" * 64, "b" * 64, 0x1000,
            (_Node("const", immediate=7), _Node("const", immediate=0)),
            (),
            (
                _Action("set_reg", (0,), aux=0),
                _Action("divide_if", (1,)),
                _Action("outcome_return", (0,)),
            ),
            (),
            (),
        )
        inner = _Transfer(
            "semantic-transfer:ordered-inner", "c" * 64, "d" * 64, 0x1100,
            (_Node("const", immediate=8),),
            (),
            (_Action("set_reg", (0,), aux=0), _Action("outcome_return", (0,))),
            (),
            (),
        )
        outer = _Transfer(
            "semantic-transfer:ordered-outer", "e" * 64, "f" * 64, 0x1200,
            (
                _Node("reg", aux=0),
                _Node("const", immediate=1),
                _Node("add32", (0, 1)),
            ),
            (),
            (_Action("set_reg", (2,), aux=0), _Action("outcome_return", (2,))),
            (),
            (),
        )
        handler = _Transfer(
            "semantic-transfer:ordered-handler", "1" * 64, "2" * 64, 0x1300,
            (_Node("reg", aux=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        resumption = _Transfer(
            "semantic-transfer:ordered-resumption",
            "6" * 64,
            "7" * 64,
            0x1400,
            (_Node("reg", aux=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        transition = CheckedExceptionTransitionV1(
            unit_id=source.identity,
            source_rva=source.rva_start,
            effect_index=1,
            fault_index=0,
            fault_sha256="3" * 64,
            transition_id="exceptional-transition-v3:" + "4" * 64,
            transition_sha256="5" * 64,
            authorizing=True,
            disposition="handled",
            handler_unit_id=handler.identity,
            handler_rva=handler.rva_start,
            resumption_unit_id=resumption.identity,
            resumption_rva=resumption.rva_start,
            guard={"op": "true"},
            blocker_code=None,
            unwind_unit_ids=(inner.identity, outer.identity),
            state_projection={
                "registers": ["eax"],
                "flags": [],
                "x87": [],
                "stack": [],
                "exception_record": [],
                "context": [],
            },
        )
        diagnostic_states = {}
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="6" * 64,
            transfers=(source, inner, outer, handler, resumption),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                    source.rva_start, inner.rva_start,
                    outer.rva_start, handler.rva_start, resumption.rva_start,
                })),
                authority_bindings={"authority_sha256": "7" * 64},
                checked_exception_transitions=(transition,),
            ),
            diagnostic_states=diagnostic_states,
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(
            [
                (row["source_rva"], row["target_rva"], row["kind"])
                for row in closure["reachable_edges"]
                if row["kind"].startswith("exception_")
            ],
            [
                (0x1000, 0x1100, "exception_unwind"),
                (0x1100, 0x1200, "exception_unwind"),
                (0x1200, 0x1300, "exception_handler"),
                (0x1300, 0x1400, "exception_resumption"),
            ],
        )
        handler_state = next(
            state for (rva, _function_context), state in diagnostic_states.items()
            if rva == handler.rva_start
        )
        self.assertEqual(
            handler_state.registers[0], finite_reference_value_v1(scalars=(9,))
        )
        resumption_state = next(
            state for (rva, _function_context), state in diagnostic_states.items()
            if rva == resumption.rva_start
        )
        self.assertEqual(
            resumption_state.registers[0],
            finite_reference_value_v1(scalars=(9,)),
        )

    def test_checked_exception_materializes_exception_record_for_handler(
        self,
    ) -> None:
        source = _Transfer(
            "semantic-transfer:record-fault", "a" * 64, "b" * 64, 0x1000,
            (_Node("const", immediate=7), _Node("const", immediate=0)),
            (),
            (
                _Action("set_reg", (0,), aux=0),
                _Action("divide_if", (1,)),
                _Action("outcome_return", (0,)),
            ),
            (),
            (),
        )
        handler = _Transfer(
            "semantic-transfer:record-handler", "c" * 64, "d" * 64, 0x1100,
            (
                _Node("reg", aux=7),
                _Node("const", immediate=4),
                _Node("add32", (0, 1)),
                _Node("load", (2,), aux=4),
                _Node("load", (3,), aux=4),
                _Node("const", immediate=12),
                _Node("add32", (0, 5)),
                _Node("load", (6,), aux=4),
                _Node("const", immediate=176),
                _Node("add32", (7, 8)),
                _Node("load", (9,), aux=4),
                _Node("add32", (4, 10)),
            ),
            (),
            (
                _Action("set_reg", (11,), aux=0),
                _Action("outcome_jump", (0x1200,)),
            ),
            (),
            (),
        )
        continuation = _Transfer(
            "semantic-transfer:record-continuation",
            "e" * 64,
            "f" * 64,
            0x1200,
            (_Node("reg", aux=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        transition = CheckedExceptionTransitionV1(
            unit_id=source.identity,
            source_rva=source.rva_start,
            effect_index=1,
            fault_index=0,
            fault_sha256="1" * 64,
            transition_id="exceptional-transition-v3:" + "2" * 64,
            transition_sha256="3" * 64,
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
                "exception_record": ["ExceptionCode"],
                "context": ["eax"],
            },
            native_exception_code=0xC0000094,
            native_exception_flags=0,
            native_exception_parameter_count=0,
            native_exception_continuable=True,
        )
        diagnostic_states = {}
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="4" * 64,
            transfers=(source, handler, continuation),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                    source.rva_start, handler.rva_start,
                    continuation.rva_start,
                })),
                authority_bindings={"authority_sha256": "5" * 64},
                checked_exception_transitions=(transition,),
            ),
            diagnostic_states=diagnostic_states,
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        continuation_state = next(
            state for (rva, _function_context), state in diagnostic_states.items()
            if rva == continuation.rva_start
        )
        self.assertEqual(
            continuation_state.registers[0],
            finite_reference_value_v1(scalars=(0xC000009B,)),
        )
        blocked = build_module_execution_closure_v1(
            transfer_plan_sha256="4" * 64,
            transfers=(source, handler, continuation),
            context=replace(
                ExecutionClosureContextV1(
                    roots=(source.rva_start,),
                    catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                        source.rva_start, handler.rva_start,
                        continuation.rva_start,
                    })),
                    authority_bindings={"authority_sha256": "5" * 64},
                    checked_exception_transitions=(transition,),
                ),
                checked_exception_transitions=(replace(
                    transition, native_exception_code=None
                ),),
            ),
        )
        self.assertEqual(blocked["status"], "incomplete")
        self.assertIn(
            "native_exception_metadata_unavailable",
            next(
                row for row in blocked["blockers"]
                if row["code"] == (
                    "checked_exception_handler_state_projection_unsupported"
                )
            )["projection_issues"],
        )
        numeric_address_projection = build_module_execution_closure_v1(
            transfer_plan_sha256="4" * 64,
            transfers=(source, handler, continuation),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                    source.rva_start, handler.rva_start,
                    continuation.rva_start,
                })),
                authority_bindings={"authority_sha256": "5" * 64},
                checked_exception_transitions=(replace(
                    transition,
                    state_projection={
                        **transition.state_projection,
                        "exception_record": ["ExceptionAddress"],
                        "context": ["Eip"],
                    },
                ),),
            ),
        )
        self.assertEqual(
            numeric_address_projection["status"],
            "complete",
            numeric_address_projection["blockers"],
        )
        nested_direct = build_module_execution_closure_v1(
            transfer_plan_sha256="4" * 64,
            transfers=(source, handler, continuation),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                    source.rva_start, handler.rva_start,
                    continuation.rva_start,
                })),
                authority_bindings={"authority_sha256": "5" * 64},
                checked_exception_transitions=(replace(
                    transition,
                    state_projection={
                        **transition.state_projection,
                        "exception_record": [
                            "ExceptionRecord[1].ExceptionCode",
                        ],
                    },
                ),),
            ),
        )
        self.assertIn(
            "nested_exception_record_source_unavailable",
            next(
                row for row in nested_direct["blockers"]
                if row["code"] == (
                    "checked_exception_handler_state_projection_unsupported"
                )
            )["projection_issues"],
        )
        over_depth = build_module_execution_closure_v1(
            transfer_plan_sha256="4" * 64,
            transfers=(source, handler, continuation),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                    source.rva_start, handler.rva_start,
                    continuation.rva_start,
                })),
                authority_bindings={"authority_sha256": "5" * 64},
                checked_exception_transitions=(replace(
                    transition,
                    state_projection={
                        **transition.state_projection,
                        "exception_record": [
                            "ExceptionRecord[4].ExceptionCode",
                        ],
                    },
                    occurrence_kind="call",
                ),),
            ),
        )
        self.assertIn(
            "unsupported_exception_record_depth:exceptionrecord[4].exceptioncode",
            next(
                row for row in over_depth["blockers"]
                if row["code"] == (
                    "checked_exception_handler_state_projection_unsupported"
                )
            )["projection_issues"],
        )
        unsupported_x87 = build_module_execution_closure_v1(
            transfer_plan_sha256="4" * 64,
            transfers=(source, handler, continuation),
            context=ExecutionClosureContextV1(
                roots=(source.rva_start,),
                catalog=ReferenceCatalogV1(guest_code_rvas=frozenset({
                    source.rva_start, handler.rva_start,
                    continuation.rva_start,
                })),
                authority_bindings={"authority_sha256": "5" * 64},
                checked_exception_transitions=(replace(
                    transition,
                    state_projection={
                        **transition.state_projection,
                        "x87": ["invented_x87_field"],
                    },
                ),),
            ),
        )
        self.assertIn(
            "unsupported_x87:invented_x87_field",
            next(
                row for row in unsupported_x87["blockers"]
                if row["code"] == (
                    "checked_exception_handler_state_projection_unsupported"
                )
            )["projection_issues"],
        )

    def test_null_code_capability_is_removed_by_cross_transfer_test(self) -> None:
        compare = _Transfer(
            "semantic-transfer:null-test", "a" * 64, "b" * 64, 0x1000,
            (
                _Node("reg", aux=0, immediate=1),
                _Node("and32", (0, 0)),
                _Node("const", immediate=0),
                _Node("eq", (1, 2)),
            ),
            (),
            (
                _Action("set_flag", (3,), aux=1),
                _Action("outcome_fallthrough", (0x1010,)),
            ),
            (),
            (),
        )
        branch = _Transfer(
            "semantic-transfer:null-branch", "c" * 64, "d" * 64, 0x1010,
            (_Node("flag", aux=1, immediate=1),),
            (),
            (_Action("outcome_branch", (0, 0x2000, 0x1020)),),
            (),
            (),
        )
        dispatch = _Transfer(
            "semantic-transfer:non-null-dispatch", "e" * 64, "f" * 64,
            0x1020,
            (_Node("reg", aux=0, immediate=1),),
            (),
            (_Action("outcome_indirect", (0,)),),
            (),
            (),
        )
        null_return = _Transfer(
            "semantic-transfer:null-return", "1" * 64, "2" * 64, 0x2000,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        dynamic_id = "dynamic-export:fixture.dll!invoke"
        dynamic_key = ("fixture.dll", "invoke")
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(
            scalars=(0,),
            references=(ReferenceAtomV1("external_function", dynamic_id),),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="3" * 64,
            transfers=(compare, branch, dispatch, null_return),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x1000, 0x1010, 0x1020, 0x2000,
                    }),
                    external_calls={dynamic_key: ExternalCallRuleV1()},
                    external_function_contracts={dynamic_id: dynamic_key},
                ),
                authority_bindings={"authority_sha256": "4" * 64},
                initial_states={
                    0x1000: ReferenceStateV1(registers=tuple(registers)),
                },
            ),
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        site = next(
            row for row in closure["indirect_targets"]
            if row["source_rva"] == 0x1020
        )
        self.assertEqual(site["targets"], [])
        self.assertEqual(site["external_targets"], [{
            "dll": "fixture.dll", "identity": "invoke",
        }])

    def test_tail_dispatch_can_share_guest_and_external_capabilities(self) -> None:
        dynamic_id = "dynamic-export:fixture.dll!invoke"
        dynamic_key = ("fixture.dll", "invoke")
        dispatch = _Transfer(
            "semantic-transfer:mixed-tail-dispatch", "a" * 64, "b" * 64,
            0x1000,
            (_Node("reg", aux=0, immediate=1),),
            (),
            (_Action("outcome_indirect", (0,)),),
            (),
            (),
        )
        guest = _Transfer(
            "semantic-transfer:mixed-tail-guest", "c" * 64, "d" * 64,
            0x2000,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002000"),
            ReferenceAtomV1("external_function", dynamic_id),
        ))
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="5" * 64,
            transfers=(dispatch, guest),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000}),
                    external_calls={dynamic_key: ExternalCallRuleV1()},
                    external_function_contracts={dynamic_id: dynamic_key},
                ),
                authority_bindings={"authority_sha256": "6" * 64},
                initial_states={
                    0x1000: ReferenceStateV1(registers=tuple(registers)),
                },
            ),
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        site = closure["indirect_targets"][0]
        self.assertEqual(site["targets"], [0x2000])
        self.assertEqual(site["external_targets"], [{
            "dll": "fixture.dll", "identity": "invoke",
        }])

    def test_external_tail_return_propagates_provider_object(self) -> None:
        provider_id = "dynamic-export:msvcrt.dll!__p__iob"
        provider_key = ("msvcrt.dll", "__p__iob")
        caller = _Transfer(
            "semantic-transfer:tail-provider-caller", "a" * 64, "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("call_response", aux=0)),
            (),
            (
                _Action("call", (0,)),
                _Action("set_reg", (14,), aux=0),
                _Action("outcome_return", (14,)),
            ),
            (self._call("internal_call", target_rva=0x2000),),
            (),
        )
        tail = _Transfer(
            "semantic-transfer:tail-provider", "c" * 64, "d" * 64, 0x2000,
            (_Node("const", immediate=0x5000),),
            (),
            (_Action("outcome_indirect", (0,)),),
            (),
            (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="7" * 64,
            transfers=(caller, tail),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000}),
                    external_functions={0x5000: provider_id},
                    external_function_contracts={provider_id: provider_key},
                    external_calls={provider_key: ExternalCallRuleV1(
                        preserved_registers=frozenset({1, 4, 5, 6, 7}),
                        allocation_result_register=0,
                    )},
                ),
                authority_bindings={"authority_sha256": "8" * 64},
            ),
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["metrics"]["return_summaries"], 2)

    def test_internal_callee_uses_pre_call_memory_not_old_return_summary(
        self,
    ) -> None:
        call = self._call("internal_call", target_rva=0x2000)
        caller = _Transfer(
            "semantic-transfer:fixed-point-caller",
            "a" * 64,
            "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("reg", aux=0)),
            (),
            (
                _Action("call", (0,)),
                _Action("outcome_branch", (14, 0x1010, 0x1020)),
            ),
            (call,),
            (),
        )
        publish = _Transfer(
            "semantic-transfer:publish-state",
            "c" * 64,
            "d" * 64,
            0x1010,
            (_Node("const", immediate=0x4010), _Node("const", immediate=1)),
            (),
            (
                _Action("memory_write", (0, 1), aux=4),
                _Action("outcome_jump", (0x1000,)),
            ),
            (),
            (),
        )
        done = _Transfer(
            "semantic-transfer:caller-done", "e" * 64, "f" * 64, 0x1020,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        callee = _Transfer(
            "semantic-transfer:stateful-callee",
            "1" * 64,
            "2" * 64,
            0x2000,
            (
                _Node("const", immediate=0x4010),
                _Node("load", (0,), aux=4),
                _Node("const", immediate=1),
                _Node("eq", (1, 2)),
            ),
            (),
            (_Action("outcome_branch", (3, 0x2010, 0x2020)),),
            (),
            (),
        )
        observed_new_state = _Transfer(
            "semantic-transfer:observed-new-state",
            "3" * 64,
            "4" * 64,
            0x2010,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        observed_initial_state = _Transfer(
            "semantic-transfer:observed-initial-state",
            "5" * 64,
            "6" * 64,
            0x2020,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="7" * 64,
            transfers=(
                caller,
                publish,
                done,
                callee,
                observed_new_state,
                observed_initial_state,
            ),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x1000, 0x1010, 0x1020, 0x2000, 0x2010, 0x2020,
                    }),
                    objects=(ObjectRangeV1("state", 0x4000, 0x100),),
                    initial_memory={
                        ("object", "state", 0x10, 4):
                        finite_reference_value_v1(scalars=(0,)),
                    },
                ),
                authority_bindings={"authority_sha256": "8" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertIn(
            0x2010, [row["rva"] for row in closure["reachable_units"]]
        )

    def test_z3_rejection_is_explicit_and_non_authorizing(self) -> None:
        transfer = _transfer((_Node("fpu_control"),))
        with self.assertRaisesRegex(
            TransferPlanError, "Z3 reconstruction rejects"
        ) as caught:
            reconstruct_expressions_z3_v2(transfer)
        self.assertEqual(
            caught.exception.code, "z3_transfer_operation_unavailable"
        )
