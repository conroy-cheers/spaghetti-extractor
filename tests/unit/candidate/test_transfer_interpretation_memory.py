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
    _parameterized_call_inputs_v1,
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

    def test_external_out_pointer_writes_canonical_object_reference(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:out-pointer", "a" * 64, "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("const", immediate=0)),
            (),
            (
                _Action("call", (0,)),
                _Action("outcome_return", (14,)),
            ),
            (self._call(
                "external_call", dll="fixture.dll", symbol="produce"
            ),), (),
        )
        frame = "captured_stack_frame:caller"
        stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", frame),
        ))
        destination = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", frame, 16),
        ))
        state = ReferenceStateV1(
            registers=(*ReferenceStateV1().registers[:7], stack),
            memory={("object", frame, 0, 4): destination},
        )
        unresolved: dict[int, tuple] = {}

        output, _values = apply_reference_effects_v1(
            transfer,
            state,
            ReferenceCatalogV1(external_calls={
                ("fixture.dll", "produce"): ExternalCallRuleV1(
                    argument_words=1,
                    write_footprints=(ExternalMemoryWriteV1(
                        base_argument=0, offset=0, fixed_bytes=4,
                    ),),
                    out_pointers=(ExternalOutPointerV1(
                        argument=0,
                        offset=0,
                        nullable=True,
                        max_elements=16,
                        element_unit_bytes=1,
                        element_max_units=64,
                    ),),
                ),
            }),
            unresolved_external_writes=unresolved,
        )

        self.assertEqual(unresolved, {})
        written = output.memory[("object", frame, 16, 4)]
        self.assertEqual(written.scalars, frozenset({0}))
        self.assertEqual(len(written.references), 1)
        self.assertTrue(
            next(iter(written.references)).identity.startswith(
                "external-out-pointer:"
            )
        )

    def test_internal_call_instantiates_parameter_write_in_caller_memory(
        self,
    ) -> None:
        inputs = self._call_input_nodes()
        caller = _Transfer(
            "semantic-transfer:parameter-write-caller", "a" * 64,
            "b" * 64, 0x1000,
            (
                *inputs,
                _Node("const", immediate=16),
                _Node("add32", (7, 14)),
                _Node("const", immediate=0x3000),
                _Node("load", (15,), aux=4),
            ),
            (),
            (
                _Action("memory_write", (15, 16), aux=4),
                _Action("memory_write", (7, 15), aux=4),
                _Action("call", (0,)),
                _Action("outcome_indirect", (17,)),
            ),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        callee_call = _Call(
            kind="external_call",
            instruction_rva=0x2004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0x2008,
            dll="fixture.dll",
            symbol="overwrite",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(),
            stack_inputs=((0, 4, 16),),
        )
        callee = _Transfer(
            "semantic-transfer:parameter-write-callee", "c" * 64,
            "d" * 64, 0x2000,
            (
                *inputs,
                _Node("const", immediate=4),
                _Node("add32", (7, 14)),
                _Node("load", (15,), aux=4),
            ),
            (),
            (
                _Action("memory_write", (7, 16), aux=4),
                _Action("call", (0,)),
                _Action("outcome_return", (0,)),
            ),
            (callee_call,), (),
        )
        target = _Transfer(
            "semantic-transfer:parameter-write-target", "e" * 64,
            "f" * 64, 0x3000,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="5" * 64,
            transfers=(caller, callee, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
                    external_calls={
                        ("fixture.dll", "overwrite"): ExternalCallRuleV1(
                            argument_words=1,
                            write_footprints=(ExternalMemoryWriteV1(
                                base_argument=0, offset=0, fixed_bytes=4,
                            ),),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "6" * 64},
                initial_states={
                    0x1000: ReferenceStateV1(registers=(
                        *ReferenceStateV1().registers[:7],
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1(
                                "object", "captured_stack_frame:root"
                            ),
                        )),
                    )),
                },
            ),
        )

        codes = {row["code"] for row in closure["blockers"]}
        self.assertNotIn("unresolved_external_memory_write_footprint", codes)
        self.assertIn("unresolved_reachable_indirect_target", codes)

    def test_distinct_relational_parameters_may_alias(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:parameter-equality", "a" * 64, "b" * 64,
            0x1000,
            (
                _Node("reg", aux=0),
                _Node("reg", aux=1),
                _Node("eq", (0, 1)),
            ),
            (),
            (_Action("outcome_return", (2,)),), (), (),
        )
        state = ReferenceStateV1(registers=(
            finite_reference_value_v1(references=(ReferenceAtomV1(
                "object", "call_parameter_object:context:register:0"
            ),)),
            finite_reference_value_v1(references=(ReferenceAtomV1(
                "object", "call_parameter_object:context:register:1"
            ),)),
            *ReferenceStateV1().registers[2:],
        ))

        _output, values = apply_reference_effects_v1(
            transfer, state, ReferenceCatalogV1()
        )

        self.assertEqual(values[2].scalars, frozenset({0, 1}))

    def test_sparse_relational_binding_absence_is_join_bottom(self) -> None:
        identity = "call_parameter_object:context:register:0"
        binding = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:caller", 8),
        ))

        joined = join_reference_states_v1(
            ReferenceStateV1(),
            ReferenceStateV1(relational_object_bindings={identity: binding}),
            alternative_limit=16,
        )

        self.assertEqual(joined.relational_object_bindings[identity], binding)

    def test_relational_parameter_memory_resolves_without_restart(
        self,
    ) -> None:
        caller = _Transfer(
            "semantic-transfer:demand-caller", "a" * 64, "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("call_response", aux=0)),
            (),
            (
                _Action("call", (0,)),
                _Action("outcome_indirect", (14,)),
            ),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        callee = _Transfer(
            "semantic-transfer:demand-callee", "c" * 64, "d" * 64,
            0x2000,
            (
                _Node("reg", aux=0),
                _Node("load", (0,), aux=4),
            ),
            (),
            (
                _Action("set_reg", (1,), aux=0),
                _Action("outcome_return", (1,)),
            ),
            (), (),
        )
        target = _Transfer(
            "semantic-transfer:demand-target", "e" * 64, "f" * 64,
            0x3000, (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        ancestor = "captured_stack_frame:ancestor"
        current = "captured_stack_frame:current"
        state = ReferenceStateV1(
            registers=(
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", ancestor, 12),
                )),
                *ReferenceStateV1().registers[1:7],
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", current),
                )),
            ),
            memory={
                ("object", ancestor, 12, 4): finite_reference_value_v1(
                    references=(ReferenceAtomV1(
                        "guest_code", "rva:00003000"
                    ),)
                ),
            },
        )

        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="7" * 64,
            transfers=(caller, callee, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
                ),
                authority_bindings={"authority_sha256": "8" * 64},
                initial_states={0x1000: state},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["indirect_targets"][0]["targets"], [0x3000])
        # The callee frame and loaded argument account for two bindings.  The
        # four PE32 callee-saved words are also represented relationally so a
        # shared helper summary can prove preservation without depending on
        # the current caller value or worklist order.
        self.assertEqual(closure["metrics"]["relational_object_bindings"], 6)

    def test_aligned_relational_parameter_memory_resolves_exact_target(
        self,
    ) -> None:
        caller = _Transfer(
            "semantic-transfer:aligned-caller", "a" * 64, "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("call_response", aux=0)),
            (),
            (_Action("call", (0,)), _Action("outcome_indirect", (14,))),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        callee = _Transfer(
            "semantic-transfer:aligned-callee", "c" * 64, "d" * 64,
            0x2000,
            (
                _Node("reg", aux=0),
                _Node("const", immediate=0xFFFF_FFF0),
                _Node("and32", (0, 1)),
                _Node("load", (2,), aux=4),
            ),
            (),
            (
                _Action("set_reg", (3,), aux=0),
                _Action("outcome_return", (3,)),
            ),
            (), (),
        )
        target = _Transfer(
            "semantic-transfer:aligned-target", "e" * 64, "f" * 64,
            0x3000, (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        ancestor = "captured_stack_frame:aligned-ancestor"
        current = "captured_stack_frame:aligned-current"
        aligned = f"aligned:fffffff0:{ancestor}:15"
        state = ReferenceStateV1(
            registers=(
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", ancestor, 15),
                )),
                *ReferenceStateV1().registers[1:7],
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", current),
                )),
            ),
            memory={
                ("object", aligned, 0, 4): finite_reference_value_v1(
                    references=(ReferenceAtomV1(
                        "guest_code", "rva:00003000"
                    ),)
                ),
            },
        )

        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="9" * 64,
            transfers=(caller, callee, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
                ),
                authority_bindings={"authority_sha256": "a" * 64},
                initial_states={0x1000: state},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["indirect_targets"][0]["targets"], [0x3000])

    def test_callee_stack_cell_resolves_lazily_from_caller_frame(self) -> None:
        caller = _Transfer(
            "semantic-transfer:lazy-frame-caller", "a" * 64, "b" * 64,
            0x1000,
            (*self._call_input_nodes(), _Node("call_response", aux=0)),
            (),
            (_Action("call", (0,)), _Action("outcome_indirect", (14,))),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        callee = _Transfer(
            "semantic-transfer:lazy-frame-callee", "c" * 64, "d" * 64,
            0x2000,
            (
                _Node("reg", aux=7),
                _Node("const", immediate=8),
                _Node("add32", (0, 1)),
                _Node("load", (2,), aux=4),
            ),
            (),
            (
                _Action("set_reg", (3,), aux=0),
                _Action("outcome_return", (3,)),
            ),
            (), (),
        )
        target = _Transfer(
            "semantic-transfer:lazy-frame-target", "e" * 64, "f" * 64,
            0x3000, (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        frame = "captured_stack_frame:lazy-root"
        state = ReferenceStateV1(
            registers=(
                *ReferenceStateV1().registers[:7],
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", frame),
                )),
            ),
            memory={
                ("object", frame, 4, 4): finite_reference_value_v1(
                    references=(ReferenceAtomV1(
                        "guest_code", "rva:00003000"
                    ),)
                ),
            },
        )

        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="b" * 64,
            transfers=(caller, callee, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
                ),
                authority_bindings={"authority_sha256": "c" * 64},
                initial_states={0x1000: state},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["indirect_targets"][0]["targets"], [0x3000])

    def test_unused_expired_callee_stack_reference_is_not_a_blocker(
        self,
    ) -> None:
        caller = _Transfer(
            "semantic-transfer:stack-expiry-caller",
            "a" * 64,
            "b" * 64,
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
        callee = _Transfer(
            "semantic-transfer:stack-expiry-callee",
            "c" * 64,
            "d" * 64,
            0x2000,
            (
                _Node("reg", aux=7),
                _Node("const", immediate=4),
                _Node("add32", (0, 1)),
                _Node("const", immediate=0),
            ),
            (),
            (
                _Action("set_reg", (2,), aux=2),
                _Action("outcome_return", (3,)),
            ),
            (),
            (),
        )

        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(caller, callee),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000}),
                ),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["blockers"], [])

    def test_bounded_switch_constraint_crosses_transfer_boundary(self) -> None:
        compare = _Transfer(
            "semantic-transfer:switch-compare",
            "a" * 64,
            "b" * 64,
            0x1000,
            (
                _Node("reg", aux=0, immediate=1),
                _Node("const", immediate=2),
                _Node("ult32", (0, 1)),
                _Node("sub32", (0, 1)),
                _Node("const", immediate=0),
                _Node("eq", (3, 4)),
            ),
            (),
            (
                _Action("set_flag", (2,), aux=0),
                _Action("set_flag", (5,), aux=1),
                _Action("outcome_fallthrough", (0x1010,)),
            ),
            (),
            (),
        )
        branch = _Transfer(
            "semantic-transfer:switch-branch",
            "c" * 64,
            "d" * 64,
            0x1010,
            (
                _Node("flag", aux=0, immediate=1),
                _Node("not", (0,)),
                _Node("flag", aux=1, immediate=1),
                _Node("not", (2,)),
                _Node("and_bool", (1, 3)),
            ),
            (),
            (_Action("outcome_branch", (4, 0x1020, 0x1030)),),
            (),
            (),
        )
        outside = _Transfer(
            "semantic-transfer:switch-outside",
            "e" * 64,
            "f" * 64,
            0x1020,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
            (),
            (),
        )
        dispatch = _Transfer(
            "semantic-transfer:switch-dispatch",
            "1" * 64,
            "2" * 64,
            0x1030,
            (
                _Node("reg", aux=0, immediate=1),
                _Node("const", immediate=4),
                _Node("mul32", (0, 1)),
                _Node("const", immediate=0x4000),
                _Node("add32", (2, 3)),
                _Node("load", (4,), aux=4),
            ),
            (),
            (_Action("outcome_indirect", (5,)),),
            (),
            (),
        )
        targets = tuple(
            _Transfer(
                f"semantic-transfer:switch-target-{rva:04x}",
                str(index + 3) * 64,
                str(index + 4) * 64,
                rva,
                (_Node("const", immediate=0),),
                (),
                (_Action("outcome_return", (0,)),),
                (),
                (),
            )
            for index, rva in enumerate((0x2000, 0x2010))
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="5" * 64,
            transfers=(compare, branch, outside, dispatch, *targets),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x1000, 0x1010, 0x1020, 0x1030, 0x2000, 0x2010,
                    }),
                    initial_memory={
                        ("absolute", "", 0x4000, 4):
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1("guest_code", "rva:00002000"),
                        )),
                        ("absolute", "", 0x4004, 4):
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1("guest_code", "rva:00002010"),
                        )),
                        ("absolute", "", 0x4008, 4):
                        finite_reference_value_v1(references=(
                            ReferenceAtomV1("guest_code", "rva:00002000"),
                        )),
                    },
                ),
                authority_bindings={"authority_sha256": "6" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(
            next(
                row for row in closure["indirect_targets"]
                if row["source_rva"] == 0x1030
            )["targets"],
            [0x2000, 0x2010],
        )

    def test_catalog_normalizes_initialized_image_va_to_guest_rva(self) -> None:
        catalog = ReferenceCatalogV1(
            guest_code_rvas=frozenset({0x2200}),
            guest_image_base=0x400000,
        )

        self.assertEqual(
            catalog.classify_scalar(0x402200).references,
            frozenset({ReferenceAtomV1("guest_code", "rva:00002200")}),
        )

    def test_reference_actions_preserve_sequence_points_and_pointer_arithmetic(
        self,
    ) -> None:
        state = ReferenceStateV1(registers=(
            *ReferenceStateV1().registers[:1],
            finite_reference_value_v1(references=(
                ReferenceAtomV1("object", "array", 8),
            )),
            *ReferenceStateV1().registers[2:7],
            finite_reference_value_v1(references=(
                ReferenceAtomV1("object", "stack", -8),
            )),
        ))
        transfer = _Transfer(
            "semantic-transfer:sequence", "a" * 64, "b" * 64, 0x1000,
            (
                *self._call_input_nodes(),
                _Node("const", immediate=4),
                _Node("add32", (14, 1)),
                _Node("const", immediate=0x4010),
                _Node("ult32", (1, 16)),
            ), (),
            (
                _Action("eval_word", (7,)),
                _Action("call", (0,)),
                _Action("set_reg", (7,), aux=4),
                _Action("set_reg", (15,), aux=5),
                _Action("set_flag", (17,), aux=0),
                _Action("outcome_return", (14,)),
            ),
            (self._call("external_call", dll="kernel32.dll", symbol="opaque"),),
            (),
        )

        output, _values = apply_reference_effects_v1(
            transfer,
            state,
            ReferenceCatalogV1(objects=(
                ObjectRangeV1("array", 0x4000, 0x100),
            )),
        )

        self.assertEqual(output.registers[4], state.registers[7])
        self.assertEqual(
            output.registers[5].references,
            frozenset({ReferenceAtomV1("object", "array", 12)}),
        )
        self.assertEqual(output.flags[0].scalars, frozenset({1}))

    def test_repeated_stack_alignment_has_a_stable_object_identity(self) -> None:
        stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack:root", -100),
        ))
        transfer = _transfer((
            _Node("reg", aux=7),
            _Node("const", immediate=0xFFFF_FFF0),
            _Node("and32", (0, 1)),
            _Node("and32", (2, 1)),
        ))

        values = apply_reference_effects_v1(
            transfer,
            ReferenceStateV1(registers=(
                *ReferenceStateV1().registers[:7], stack,
            )),
            ReferenceCatalogV1(),
        )[1]

        self.assertEqual(values[2], values[3])
        atom = next(iter(values[3].references))
        self.assertEqual(atom.identity.count("aligned:"), 1)

    def test_stdcall_cleanup_and_terminating_disposition_are_contract_driven(
        self,
    ) -> None:
        inputs = self._call_input_nodes()
        returning = _Transfer(
            "semantic-transfer:stdcall", "a" * 64, "b" * 64, 0x1000,
            (*inputs, _Node("call_response", aux=7)), (),
            (
                _Action("call", (0,)),
                _Action("set_reg", (14,), aux=7),
                _Action("outcome_return", (0,)),
            ),
            (self._call("external_call", dll="kernel32.dll", symbol="Sleep"),),
            (),
        )
        stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "stack", -8),
        ))
        state = ReferenceStateV1(registers=(
            *ReferenceStateV1().registers[:7], stack,
        ))
        catalog = ReferenceCatalogV1(external_calls={
            ("kernel32.dll", "Sleep"): ExternalCallRuleV1(
                preserved_registers=frozenset({1, 4, 5, 6, 7}),
                stack_cleanup_bytes=4,
            ),
        })
        output, _values = apply_reference_effects_v1(returning, state, catalog)
        self.assertEqual(
            output.registers[7].references,
            frozenset({ReferenceAtomV1("object", "stack", -4)}),
        )

        terminating = _Transfer(
            "semantic-transfer:exit", "c" * 64, "d" * 64, 0x2000,
            inputs, (),
            (_Action("call", (0,)), _Action("outcome_fallthrough", (0x2008,))),
            (self._call("external_call", dll="msvcrt.dll", symbol="exit"),),
            (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(terminating,),
            context=ExecutionClosureContextV1(
                roots=(0x2000,),
                catalog=ReferenceCatalogV1(external_calls={
                    ("msvcrt.dll", "exit"): ExternalCallRuleV1(
                        disposition="terminates"
                    ),
                }),
                authority_bindings={"authority_sha256": "2" * 64},
            ),
        )
        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["lifecycle_effects"], [{
            "kind": "external_termination",
            "source_rva": 0x2000,
            "dll": "msvcrt.dll",
            "identity": "exit",
        }])

    def test_checked_loader_services_resolve_one_dynamic_code_export(self) -> None:
        inputs = self._call_input_nodes()

        def loader_call(
            *, identity: str, arguments: tuple[int, ...], rva: int,
        ) -> _Transfer:
            call = _Call(
                kind="external_call",
                instruction_rva=rva + 4,
                call_index=0,
                target_node=None,
                target_rva=0,
                return_rva=rva + 8,
                dll="kernel32.dll",
                symbol=identity,
                ordinal=None,
                register_nodes=tuple(range(8)),
                flag_nodes=tuple(range(8, 14)),
                argument_nodes=arguments,
                stack_inputs=(),
            )
            return _Transfer(
                f"semantic-transfer:{identity}", "a" * 64, "b" * 64, rva,
                (
                    *inputs,
                    _Node("const", immediate=0x4000),
                    _Node("const", immediate=0x4020),
                    _Node("call_response", aux=0),
                ),
                (),
                (
                    _Action("call", (0,)),
                    _Action("set_reg", (16,), aux=0),
                    _Action("outcome_return", (0,)),
                ),
                (call,),
                (),
            )

        dynamic_id = "dynamic-export:msvcrt.dll!___lc_codepage_func"
        dynamic_key = ("msvcrt.dll", "___lc_codepage_func")
        catalog = ReferenceCatalogV1(
            objects=(ObjectRangeV1("strings", 0x4000, 0x100),),
            object_bytes={
                "strings": (
                    b"msvcrt.dll\0" + b"\0" * 21
                    + b"___lc_codepage_func\0"
                ),
            },
            external_calls={
                ("kernel32.dll", "GetModuleHandleA"): ExternalCallRuleV1(
                    argument_words=1,
                    module_handle_name_argument=0,
                    module_handle_nullable_name=True,
                ),
                ("kernel32.dll", "GetProcAddress"): ExternalCallRuleV1(
                    argument_words=2,
                    dynamic_export_handle_argument=0,
                    dynamic_export_name_argument=1,
                    dynamic_export_results={dynamic_key: dynamic_id},
                ),
                dynamic_key: ExternalCallRuleV1(),
            },
            external_function_contracts={dynamic_id: dynamic_key},
        )
        module = loader_call(
            identity="GetModuleHandleA", arguments=(14,), rva=0x1000
        )
        module_state, _ = apply_reference_effects_v1(
            module, ReferenceStateV1(), catalog
        )
        self.assertEqual(
            module_state.registers[0].references,
            frozenset({ReferenceAtomV1("loader_module", "msvcrt.dll")}),
        )
        registers = list(module_state.registers)
        registers[0] = finite_reference_value_v1(
            references=(ReferenceAtomV1("loader_module", "msvcrt.dll"),)
        )
        procedure = loader_call(
            identity="GetProcAddress", arguments=(0, 15), rva=0x1100
        )
        procedure_state, _ = apply_reference_effects_v1(
            procedure,
            ReferenceStateV1(registers=tuple(registers)),
            catalog,
        )
        self.assertEqual(
            procedure_state.registers[0].references,
            frozenset({ReferenceAtomV1("external_function", dynamic_id)}),
        )
        self.assertEqual(procedure_state.registers[0].scalars, frozenset({0}))
