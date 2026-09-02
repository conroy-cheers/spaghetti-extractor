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
from spaghetti_extractor.transfer.closure_calls import (
    _conservative_return_state_for_caller_v1,
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

    def test_required_domains_have_total_explicit_operation_coverage(self) -> None:
        matrix = operation_coverage_matrix_v2((
            behavioral_c_operation_coverage_v2(),
            concrete_operation_coverage_v2(),
            definedness_operation_coverage_v2(),
            reference_operation_coverage_v2(),
            z3_operation_coverage_v2(),
        ))

        self.assertEqual(matrix["status"], "complete")
        self.assertEqual(matrix["domain_ids"], [
            "behavioral_c",
            "concrete_evaluator",
            "definedness",
            "reference_provenance",
            "z3_reconstruction",
        ])
        self.assertEqual(
            matrix["counts"]["operations"],
            len(EXPRESSION_OPERATIONS_V2)
            + len(EFFECT_OPERATIONS_V2)
            + len(TERMINATOR_OPERATIONS_V2),
        )
        z3_effects = [
            row for row in matrix["operations"] if row["category"] == "effect"
        ]
        self.assertTrue(z3_effects)
        self.assertTrue(all(
            row["domains"]["z3_reconstruction"] == "rejected"
            for row in z3_effects
        ))

    def test_external_write_authority_selector_fails_closed(self) -> None:
        blockers: list[dict[str, object]] = []
        selector, valid = _external_write_authority_selector_v1(
            "image:missing",
            authority_rule_ids=frozenset({"image:data"}),
            contract_index=3,
            blockers=blockers,
        )

        self.assertIsNone(selector)
        self.assertFalse(valid)
        self.assertEqual(blockers, [{
            "code": "external_memory_write_authority_selector_unknown",
            "contract_index": 3,
            "authority_selector": "image:missing",
        }])

    def test_missing_domain_handler_is_a_stable_veto(self) -> None:
        expressions = frozenset(EXPRESSION_OPERATIONS_V2)
        missing = sorted(expressions)[0]
        with self.assertRaisesRegex(
            TransferPlanError, "coverage is not total"
        ) as caught:
            DomainOperationCoverageV2(
                domain="broken",
                handled_expressions=expressions - {missing},
                rejected_expressions=frozenset(),
                handled_effects=frozenset(EFFECT_OPERATIONS_V2),
                rejected_effects=frozenset(),
                handled_terminators=frozenset(TERMINATOR_OPERATIONS_V2),
                rejected_terminators=frozenset(),
            )
        self.assertEqual(
            caught.exception.code, "transfer_domain_coverage_incomplete"
        )

    def test_z3_reconstructs_supported_bitvector_and_predicate_terms(self) -> None:
        transfer = _transfer((
            _Node("const", immediate=40),
            _Node("const", immediate=2),
            _Node("add32", (0, 1)),
            _Node("const", immediate=43),
            _Node("ult32", (2, 3)),
        ))
        values = reconstruct_expressions_z3_v2(transfer)

        self.assertTrue(z3.is_true(z3.simplify(values[2] == 42)))
        self.assertTrue(z3.is_true(z3.simplify(values[4])))

    def test_reference_survives_object_store_load_and_indirect_use(self) -> None:
        transfer = _Transfer(
            identity="semantic-transfer:stored-function-pointer",
            contract_sha256="a" * 64,
            instruction_bytes_sha256="b" * 64,
            rva_start=0x1000,
            nodes=(
                _Node("const", immediate=0x4010),
                _Node("const", immediate=0x2200),
                _Node("load", (0,), aux=4),
            ),
            x87_nodes=(),
            actions=(
                _Action("memory_write", (0, 1), aux=4),
                _Action("outcome_indirect", (2,)),
            ),
            calls=(),
            x87_operations=(),
        )
        state, values = apply_reference_effects_v1(
            transfer,
            ReferenceStateV1(),
            ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x2200}),
                objects=(ObjectRangeV1("allocation:list", 0x4000, 0x100),),
            ),
        )

        self.assertEqual(
            state.memory[("object", "allocation:list", 0x10, 4)].payload(),
            {
                "kind": "finite",
                "scalars": [],
                "references": [{
                    "kind": "guest_code", "identity": "rva:00002200", "offset": 0,
                }],
            },
        )
        self.assertEqual(indirect_targets_v1(transfer, values), (0x2200,))

    def test_nullable_absent_allocation_does_not_erase_success_fields(
        self,
    ) -> None:
        identity = "allocation:semantic-transfer:calloc:00001004:0"
        key = ("object", identity, 4, 4)
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002200"),
        ))
        success = ReferenceStateV1(memory={key: target})
        failure = ReferenceStateV1()

        joined = join_reference_states_v1(
            success, failure, alternative_limit=16
        )

        self.assertEqual(joined.memory[key], target)

        existing_but_unwritten = ReferenceStateV1(registers=(
            finite_reference_value_v1(references=(
                ReferenceAtomV1("object", identity),
            )),
            *ReferenceStateV1().registers[1:],
        ))
        imprecise = join_reference_states_v1(
            success, existing_but_unwritten, alternative_limit=16
        )
        self.assertEqual(imprecise.memory[key].kind, "conflict")

    def test_zero_branch_drops_only_disproved_nullable_allocation(self) -> None:
        identity = "allocation:semantic-transfer:calloc:00001004:0"
        allocation = ReferenceAtomV1("object", identity)
        registers = list(ReferenceStateV1().registers)
        registers[0] = finite_reference_value_v1(
            scalars=(0,), references=(allocation,)
        )
        state = ReferenceStateV1(registers=tuple(registers))
        transfer = _Transfer(
            "semantic-transfer:nullable-allocation-branch", "a" * 64,
            "b" * 64, 0x1000,
            (
                _Node("reg", aux=0, immediate=1),
                _Node("const", immediate=0),
                _Node("eq", (0, 1)),
            ),
            (),
            (_Action("outcome_branch", (2, 0x2000, 0x3000)),),
            (), (),
        )
        output, values = apply_reference_effects_v1(
            transfer, state, ReferenceCatalogV1()
        )

        failure = refine_reference_state_for_branch_v1(
            transfer, output, values, taken=True
        )
        success = refine_reference_state_for_branch_v1(
            transfer, output, values, taken=False
        )
        assert failure is not None and success is not None
        self.assertNotIn(identity, failure.possible_allocation_identities)
        self.assertIn(identity, success.possible_allocation_identities)

        key = ("object", identity, 4, 4)
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002200"),
        ))
        joined = join_reference_states_v1(
            replace(success, memory={key: target}),
            failure,
            alternative_limit=16,
        )
        self.assertEqual(joined.memory[key], target)

    def test_allocation_existence_is_join_associative(self) -> None:
        identity = "allocation:join-order"
        key = ("object", identity, 4, 4)
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002200"),
        ))
        empty = ReferenceStateV1()
        live = ReferenceStateV1(registers=(
            finite_reference_value_v1(references=(
                ReferenceAtomV1("object", identity),
            )),
            *empty.registers[1:],
        ))
        initialized = ReferenceStateV1(memory={key: target})

        left_grouped = join_reference_states_v1(
            join_reference_states_v1(
                empty, live, alternative_limit=16
            ),
            initialized,
            alternative_limit=16,
        )
        right_grouped = join_reference_states_v1(
            empty,
            join_reference_states_v1(
                live, initialized, alternative_limit=16
            ),
            alternative_limit=16,
        )

        self.assertEqual(left_grouped, right_grouped)
        self.assertEqual(left_grouped.memory[key].kind, "conflict")
        self.assertEqual(
            left_grouped.possible_allocation_identities,
            frozenset({identity}),
        )

    def test_conditional_write_summary_joins_write_with_entry_value(
        self,
    ) -> None:
        key = ("object", "image:.data", 12, 4)
        original = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002000"),
        ))
        replacement = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        preserved_path = ReferenceStateV1()
        written_path = ReferenceStateV1(
            memory={key: replacement}, preserves_inherited_memory=False
        )

        joined = join_reference_states_v1(
            preserved_path,
            written_path,
            alternative_limit=16,
            baseline_memory={key: original},
        )

        self.assertFalse(joined.preserves_inherited_memory)
        self.assertEqual(
            joined.memory[key].references,
            original.references | replacement.references,
        )

    def test_baseline_invalidation_join_is_associative(self) -> None:
        key = ("object", "image:.data", 12, 4)
        original = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00002000"),
        ))
        baseline = {key: original}
        implicit = ReferenceStateV1()
        explicit = ReferenceStateV1(memory={key: original})
        invalidated = ReferenceStateV1(
            invalidated_memory_ranges=frozenset({(
                "object", "image:.data", 8, 20,
            )}),
        )

        def join(
            left: ReferenceStateV1, right: ReferenceStateV1,
        ) -> ReferenceStateV1:
            return join_reference_states_v1(
                left,
                right,
                alternative_limit=16,
                baseline_memory=baseline,
            )

        left_grouped = join(join(implicit, explicit), invalidated)
        right_grouped = join(implicit, join(explicit, invalidated))

        self.assertEqual(left_grouped, right_grouped)
        self.assertEqual(left_grouped.memory[key].kind, "conflict")

    def test_bounded_rep_movs_preserves_copied_code_reference(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:rep-copy", "a" * 64, "b" * 64, 0x1000,
            (
                _Node("reg", aux=0),
                _Node("reg", aux=1),
                _Node("const", immediate=1),
                _Node("const", immediate=0),
            ),
            (),
            (
                _Action("rep_movs", (0, 1, 2, 3), aux=4),
                _Action("outcome_return", (2,)),
            ),
            (), (),
        )
        source = "image:.rdata"
        destination = "image:.data"
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        state = ReferenceStateV1(
            registers=(
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", source, 8),
                )),
                finite_reference_value_v1(references=(
                    ReferenceAtomV1("object", destination, 12),
                )),
                *ReferenceStateV1().registers[2:],
            ),
            memory={("object", source, 8, 4): target},
        )

        output, _values = apply_reference_effects_v1(
            transfer, state, ReferenceCatalogV1()
        )

        self.assertEqual(output.memory[("object", destination, 12, 4)], target)
        self.assertFalse(output.preserves_inherited_memory)

    def test_unknown_rep_movs_count_invalidates_only_destination_object(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:unknown-rep-copy", "a" * 64, "b" * 64,
            0x1000,
            (
                _Node("reg", aux=0),
                _Node("reg", aux=1),
                _Node("reg", aux=2),
                _Node("const", immediate=0),
            ),
            (),
            (
                _Action("rep_movs", (0, 1, 2, 3), aux=4),
                _Action("outcome_return", (3,)),
            ),
            (), (),
        )
        destination = "image:.bss"
        unrelated = "image:.data"
        destination_key = ("object", destination, 32, 4)
        unrelated_key = ("object", unrelated, 12, 4)
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        registers = list(ReferenceStateV1().registers)
        registers[1] = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", destination, 16),
        ))
        state = ReferenceStateV1(
            registers=tuple(registers),
            memory={destination_key: target, unrelated_key: target},
        )

        output, _values = apply_reference_effects_v1(
            transfer, state, ReferenceCatalogV1()
        )

        self.assertFalse(output.all_memory_invalidated)
        self.assertNotIn(destination_key, output.memory)
        self.assertEqual(output.memory[unrelated_key], target)
        self.assertEqual(output.invalidated_memory_ranges, frozenset({(
            "object", destination, 16, 1 << 63,
        )}))
        self.assertFalse(output.preserves_inherited_memory)

    def test_variable_stack_adjustment_creates_owned_dynamic_region(self) -> None:
        transfer = _Transfer(
            "semantic-transfer:dynamic-stack", "a" * 64, "b" * 64,
            0x1000,
            (
                _Node("reg", aux=7),
                _Node("reg", aux=0),
                _Node("sub32", (0, 1)),
                _Node("reg", immediate=1, aux=7),
                _Node("const", immediate=16),
                _Node("add32", (3, 4)),
                _Node("const", immediate=7),
            ),
            (),
            (
                _Action("set_reg", (2,), aux=7),
                _Action("memory_write", (5, 6), aux=4),
                _Action("outcome_return", (6,)),
            ),
            (), (),
        )
        frame = "captured_stack_frame:dynamic-caller"
        state = ReferenceStateV1(registers=(
            *ReferenceStateV1().registers[:7],
            finite_reference_value_v1(references=(
                ReferenceAtomV1("object", frame),
            )),
        ))

        output, _values = apply_reference_effects_v1(
            transfer, state, ReferenceCatalogV1()
        )

        stack = next(iter(output.registers[7].references))
        self.assertEqual(
            stack.identity,
            "dynamic_stack_region:"
            f"{frame}|semantic-transfer:dynamic-stack:2",
        )
        self.assertEqual(
            output.memory[("object", stack.identity, 16, 4)].scalars,
            frozenset({7}),
        )

        repeated, _values = apply_reference_effects_v1(
            transfer, output, ReferenceCatalogV1()
        )
        self.assertEqual(repeated.registers[7], output.registers[7])

    def test_object_offset_overflow_retains_only_object_identity(self) -> None:
        value = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "allocation:array", offset)
            for offset in range(0, 20 * 32, 32)
        ))

        self.assertEqual(value.kind, "finite")
        self.assertEqual(value.references, frozenset({
            ReferenceAtomV1("object_view", "allocation:array"),
        }))

        code = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", f"rva:{offset:08x}")
            for offset in range(17)
        ))
        self.assertEqual(code.kind, "conflict")

    def test_object_view_abstraction_is_join_associative(self) -> None:
        overflowed = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "object:a", offset)
            for offset in range(17)
        ))
        other = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "object:b", 4),
        ))
        incremental = join_reference_values_v1(
            overflowed, other, alternative_limit=16
        )
        direct = finite_reference_value_v1(references=(
            *(
                ReferenceAtomV1("object", "object:a", offset)
                for offset in range(17)
            ),
            ReferenceAtomV1("object", "object:b", 4),
        ))

        self.assertEqual(incremental, direct)
        self.assertEqual(incremental.references, frozenset({
            ReferenceAtomV1("object_view", "object:a"),
            ReferenceAtomV1("object_view", "object:b"),
        }))

    def test_stack_pointer_join_retains_exact_offsets_beyond_value_limit(
        self,
    ) -> None:
        state = ReferenceStateV1(registers=(
            *ReferenceStateV1().registers[:7],
            finite_reference_value_v1(references=(
                ReferenceAtomV1("object", "captured_stack:root", 0),
            )),
        ))
        for offset in range(4, 32 * 4, 4):
            other = ReferenceStateV1(registers=(
                *ReferenceStateV1().registers[:7],
                finite_reference_value_v1(references=(
                    ReferenceAtomV1(
                        "object", "captured_stack:root", offset
                    ),
                )),
            ))
            state = join_reference_states_v1(
                state, other, alternative_limit=16
            )

        self.assertEqual(state.registers[7].kind, "finite")
        self.assertEqual(len(state.registers[7].references), 32)
        self.assertNotIn(
            ReferenceAtomV1("object_view", "captured_stack:root"),
            state.registers[7].references,
        )

    def test_memory_preserving_summary_restores_exact_caller_memory(
        self,
    ) -> None:
        context = ExecutionFunctionContextV1(0x1000, 0x2000, (0x1010,))
        caller_frame = "captured_stack_frame:caller"
        caller_stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", caller_frame),
        ))
        caller_key = ("object", caller_frame, 12, 4)
        target = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        caller = ReferenceStateV1(
            registers=(
                *ReferenceStateV1().registers[:7], caller_stack,
            ),
            memory={caller_key: target},
        )
        callee_stack = finite_reference_value_v1(references=(
            ReferenceAtomV1(
                "object", f"captured_stack_frame:{context.identity}"
            ),
        ))
        stale_key = ("object", "captured_stack_frame:other-caller", 12, 4)
        summary = ReferenceStateV1(
            registers=(
                *ReferenceStateV1().registers[:7], callee_stack,
            ),
            memory={stale_key: finite_reference_value_v1(scalars=(7,))},
            preserves_inherited_memory=True,
        )

        returned, escaped = _return_state_for_caller_v1(
            summary,
            callee_context=context,
            caller_state=caller,
            caller_esp=caller_stack,
        )

        self.assertFalse(escaped)
        self.assertEqual(returned.memory, caller.memory)
        self.assertEqual(returned.memory[caller_key], target)

    def test_missing_relational_return_binding_defers_instead_of_poisoning(
        self,
    ) -> None:
        context = ExecutionFunctionContextV1(0x1000, 0x2000, (0x1010,))
        caller_stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:caller"),
        ))
        parameter = (
            f"call_parameter_object:{context.identity}:register:3"
        )
        summary = ReferenceStateV1(
            memory={
                ("object", parameter, 32, 4):
                finite_reference_value_v1(scalars=(7,))
            },
            written_memory_keys=frozenset({
                ("object", parameter, 32, 4)
            }),
        )

        returned, escaped = _return_state_for_caller_v1(
            summary,
            callee_context=context,
            caller_state=ReferenceStateV1(),
            caller_esp=caller_stack,
        )

        self.assertIsNone(returned)
        self.assertFalse(escaped)

    def test_missing_relational_return_binding_has_reachable_fallback(
        self,
    ) -> None:
        context = ExecutionFunctionContextV1(0x1000, 0x2000, (0x1010,))
        caller_stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", "captured_stack_frame:caller"),
        ))
        parameter = f"call_parameter_object:{context.identity}:register:3"
        summary = ReferenceStateV1(
            registers=(
                finite_reference_value_v1(scalars=(7,)),
                *ReferenceStateV1().registers[1:],
            ),
            memory={
                ("object", parameter, 32, 4):
                finite_reference_value_v1(scalars=(9,))
            },
        )

        returned = _conservative_return_state_for_caller_v1(
            summary,
            callee_context=context,
            caller_state=ReferenceStateV1(),
            caller_esp=caller_stack,
        )

        self.assertEqual(
            returned.registers[0], finite_reference_value_v1(scalars=(7,))
        )
        self.assertEqual(returned.registers[7], caller_stack)
        self.assertEqual(returned.memory, {})
        self.assertTrue(returned.all_memory_invalidated)
        self.assertTrue(returned.effect_all_memory_invalidated)
        self.assertFalse(returned.preserves_inherited_memory)

    def test_finite_reference_values_are_canonical_immutable_instances(
        self,
    ) -> None:
        left = finite_reference_value_v1(
            scalars=(3, 1),
            references=(ReferenceAtomV1("guest_code", "rva:00002000"),),
        )
        right = finite_reference_value_v1(
            scalars=(1, 3),
            references=(ReferenceAtomV1("guest_code", "rva:00002000"),),
        )

        self.assertIs(left, right)

    def test_internal_call_projects_complete_outgoing_stack_memory(
        self,
    ) -> None:
        inputs = self._call_input_nodes()
        caller = _Transfer(
            "semantic-transfer:complete-stack-caller", "a" * 64,
            "b" * 64, 0x1000,
            (
                *inputs,
                _Node("const", immediate=0x3000),
                _Node("call_response", aux=0),
            ),
            (),
            (
                _Action("memory_write", (7, 14), aux=4),
                _Action("call", (0,)),
                _Action("outcome_indirect", (15,)),
            ),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        callee = _Transfer(
            "semantic-transfer:complete-stack-callee", "c" * 64,
            "d" * 64, 0x2000,
            (
                _Node("reg", aux=7),
                _Node("const", immediate=4),
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
            "semantic-transfer:complete-stack-target", "e" * 64,
            "f" * 64, 0x3000,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )

        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="1" * 64,
            transfers=(caller, callee, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x2000, 0x3000}),
                ),
                authority_bindings={"authority_sha256": "2" * 64},
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

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(closure["indirect_targets"][0]["targets"], [0x3000])

    def test_outgoing_stack_projection_fails_closed_beyond_qualified_window(
        self,
    ) -> None:
        frame = "captured_stack_frame:sparse-root"
        stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", frame, 32),
        ))
        value = finite_reference_value_v1(references=(
            ReferenceAtomV1("guest_code", "rva:00003000"),
        ))
        state = ReferenceStateV1(memory={
            ("object", frame, 32 + 8192, 4): value,
        })
        values = (*ReferenceStateV1().registers[:7], stack)

        call = self._call("internal_call", target_rva=0x2000)
        self.assertEqual(
            _explicit_outgoing_stack_cells_v1(
                call,
                values,
                state,
                ReferenceCatalogV1(),
            ),
            {},
        )
        self.assertTrue(
            _outgoing_stack_projection_exceeds_limit_v1(
                call, values, state
            )
        )
        self.assertEqual(OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1, 4096)

        caller = _Transfer(
            "semantic-transfer:bounded-stack-caller",
            "a" * 64,
            "b" * 64,
            0x1000,
            self._call_input_nodes(),
            (),
            (_Action("call", (0,)), _Action("outcome_return", (0,))),
            (call,),
            (),
        )
        callee = _Transfer(
            "semantic-transfer:bounded-stack-callee",
            "c" * 64,
            "d" * 64,
            0x2000,
            (_Node("const", immediate=0),),
            (),
            (_Action("outcome_return", (0,)),),
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
                initial_states={0x1000: ReferenceStateV1(
                    registers=(
                        *ReferenceStateV1().registers[:7], stack,
                    ),
                    memory=state.memory,
                )},
            ),
        )
        self.assertIn(
            "outgoing_stack_projection_bound_exceeded",
            {row["code"] for row in closure["blockers"]},
        )

    def test_nonlocal_and_repeated_writes_are_not_memory_preserving(
        self,
    ) -> None:
        frame = "captured_stack_frame:callee"
        stack = finite_reference_value_v1(references=(
            ReferenceAtomV1("object", frame),
        ))
        initial = ReferenceStateV1(registers=(
            *ReferenceStateV1().registers[:7], stack,
        ))
        catalog = ReferenceCatalogV1(objects=(
            ObjectRangeV1("shared", 0x4000, 0x100),
        ))
        direct = _Transfer(
            "semantic-transfer:nonlocal-write", "a" * 64, "b" * 64,
            0x1000,
            (_Node("const", immediate=0x4010), _Node("const", immediate=1)),
            (),
            (
                _Action("memory_write", (0, 1), aux=4),
                _Action("outcome_return", (1,)),
            ),
            (), (),
        )
        direct_state, _values = apply_reference_effects_v1(
            direct, initial, catalog
        )
        self.assertFalse(direct_state.preserves_inherited_memory)

        repeated = _Transfer(
            "semantic-transfer:nonlocal-repeat", "c" * 64, "d" * 64,
            0x1010,
            (
                _Node("const", immediate=0x4010),
                _Node("const", immediate=0),
                _Node("const", immediate=2),
                _Node("const", immediate=0),
            ),
            (),
            (
                _Action("rep_stos", (0, 1, 2, 3), aux=4),
                _Action("outcome_return", (1,)),
            ),
            (), (),
        )
        repeated_state, _values = apply_reference_effects_v1(
            repeated, initial, catalog
        )
        self.assertFalse(repeated_state.preserves_inherited_memory)
        self.assertIn(
            ("object", "shared", 0x10, 0x18),
            repeated_state.invalidated_memory_ranges,
        )

    def test_internal_call_propagates_unknown_memory_write_veto(self) -> None:
        caller = _Transfer(
            "semantic-transfer:write-propagation-caller", "a" * 64,
            "b" * 64, 0x1000,
            self._call_input_nodes(), (),
            (
                _Action("call", (0,)),
                _Action("outcome_fallthrough", (0x1010,)),
            ),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        continuation = _Transfer(
            "semantic-transfer:write-propagation-dispatch", "c" * 64,
            "d" * 64, 0x1010,
            (_Node("const", immediate=0x4010), _Node("load", (0,), aux=4)),
            (), (_Action("outcome_indirect", (1,)),), (), (),
        )
        callee = _Transfer(
            "semantic-transfer:write-propagation-callee", "e" * 64,
            "f" * 64, 0x2000,
            self._call_input_nodes(), (),
            (
                _Action("call", (0,)),
                _Action("outcome_return", (0,)),
            ),
            (self._call(
                "external_call", dll="fixture.dll", symbol="mutate"
            ),), (),
        )
        target = _Transfer(
            "semantic-transfer:write-propagation-target", "1" * 64,
            "2" * 64, 0x3000,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        dispatch_key = ("object", "dispatch-table", 0x10, 4)
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="3" * 64,
            transfers=(caller, continuation, callee, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x1000, 0x1010, 0x2000, 0x3000,
                    }),
                    objects=(
                        ObjectRangeV1("dispatch-table", 0x4000, 0x100),
                    ),
                    initial_memory={
                        dispatch_key: finite_reference_value_v1(references=(
                            ReferenceAtomV1(
                                "guest_code", "rva:00003000"
                            ),
                        )),
                    },
                    external_calls={
                        ("fixture.dll", "mutate"): ExternalCallRuleV1(
                            unknown_guest_memory_write=True,
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "4" * 64},
            ),
        )

        self.assertEqual(closure["status"], "incomplete")
        codes = {row["code"] for row in closure["blockers"]}
        self.assertIn("unresolved_external_memory_write_footprint", codes)
        self.assertIn("unresolved_reachable_indirect_target", codes)
