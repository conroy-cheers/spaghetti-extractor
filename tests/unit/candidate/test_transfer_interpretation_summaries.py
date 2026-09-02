"""Allocation and correlated helper-summary transfer-closure cases."""

from __future__ import annotations

import unittest
from dataclasses import replace

from . import test_transfer_interpretation_services as support
from .test_transfer_interpretation_services import (
    CONFLICT_REFERENCE_V1,
    ExecutionClosureContextV1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    ObjectRangeV1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    _Action,
    _Node,
    _Transfer,
    build_module_execution_closure_v1,
)


class TransferInterpretationSummaryTests(unittest.TestCase):
    _call = staticmethod(support.TransferInterpretationTests._call)
    _call_input_nodes = staticmethod(
        support.TransferInterpretationTests._call_input_nodes
    )
    def test_execution_closure_propagates_allocation_return_across_calls(self) -> None:
        allocator = _Transfer(
            "semantic-transfer:allocator", "a" * 64, "b" * 64, 0x2000,
            (*self._call_input_nodes(), _Node("call_response", aux=0)), (),
            (
                _Action("call", (0,), aux=0),
                _Action("set_reg", (14,), aux=0),
                _Action("outcome_return", (14,)),
            ),
            (self._call("external_call", dll="msvcrt.dll", symbol="calloc"),),
            (),
        )
        register = _Transfer(
            "semantic-transfer:register", "c" * 64, "d" * 64, 0x1000,
            (
                *self._call_input_nodes(),
                _Node("call_response", aux=0),
                _Node("const", immediate=4),
                _Node("add32", (14, 15)),
                _Node("const", immediate=0x2200),
            ), (),
            (
                _Action("call", (0,), aux=0),
                _Action("set_reg", (14,), aux=1),
                _Action("memory_write", (16, 17), aux=4),
                _Action("outcome_jump", (0x1100,)),
            ),
            (self._call("internal_call", target_rva=0x2000),), (),
        )
        dispatch = _Transfer(
            "semantic-transfer:dispatch", "e" * 64, "f" * 64, 0x1100,
            (
                _Node("reg", aux=1), _Node("const", immediate=4),
                _Node("add32", (0, 1)), _Node("load", (2,), aux=4),
            ), (), (_Action("outcome_indirect", (3,)),), (), (),
        )
        target = _Transfer(
            "semantic-transfer:target", "1" * 64, "2" * 64, 0x2200,
            (_Node("const", immediate=0),), (),
            (_Action("outcome_return", (0,)),), (), (),
        )
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="3" * 64,
            transfers=(register, dispatch, allocator, target),
            context=ExecutionClosureContextV1(
                roots=(0x1000,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({0x1000, 0x1100, 0x2000, 0x2200}),
                    external_calls={
                        ("msvcrt.dll", "calloc"): ExternalCallRuleV1(
                            preserved_registers=frozenset({1, 4, 5, 6, 7}),
                            allocation_result_register=0,
                            allocation_nullable=True,
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "4" * 64},
            ),
        )

        self.assertEqual(closure["status"], "complete", closure["blockers"])
        self.assertEqual(
            next(
                row for row in closure["indirect_targets"]
                if row["source_rva"] == 0x1100
            )["targets"],
            [0x2200],
        )

    def test_shared_helper_summary_keeps_callee_saved_word_correlation(
        self,
    ) -> None:
        branch = _Transfer(
            "semantic-transfer:relational-branch",
            "1" * 64, "2" * 64, 0x0800,
            (_Node("flag", aux=1, immediate=1),), (),
            (_Action("outcome_branch", (0, 0x1000, 0x1100)),), (), (),
        )
        precise_setup = _Transfer(
            "semantic-transfer:precise-setup",
            "3" * 64, "4" * 64, 0x1000,
            (_Node("const", immediate=0x4010),), (),
            (
                _Action("set_reg", (0,), aux=1),
                _Action("outcome_fallthrough", (0x1010,)),
            ), (), (),
        )

        def internal_caller(rva: int, instruction_rva: int) -> _Transfer:
            call = replace(
                self._call("internal_call", target_rva=0x2000),
                instruction_rva=instruction_rva,
                return_rva=rva + 8,
            )
            return _Transfer(
                f"semantic-transfer:caller-{rva:08x}",
                "5" * 64, "6" * 64, rva,
                (
                    *self._call_input_nodes(),
                    *(_Node("call_response", aux=index) for index in range(8)),
                ), (),
                (
                    _Action("call", (0,), aux=0),
                    *(
                        _Action("set_reg", (14 + index,), aux=index)
                        for index in range(8)
                    ),
                    _Action("outcome_return", (14,)),
                ),
                (call,), (),
            )

        wrapper_call = replace(
            self._call("internal_call", target_rva=0x3000),
            instruction_rva=0x2004,
            return_rva=0x2010,
        )
        wrapper = _Transfer(
            "semantic-transfer:shared-wrapper",
            "7" * 64, "8" * 64, 0x2000,
            (
                *self._call_input_nodes(),
                *(_Node("call_response", aux=index) for index in range(8)),
            ), (),
            (
                _Action("call", (0,), aux=0),
                *(
                    _Action("set_reg", (14 + index,), aux=index)
                    for index in range(8)
                ),
                _Action("outcome_fallthrough", (0x2010,)),
            ),
            (wrapper_call,), (),
        )
        write_call = replace(
            self._call(
                "external_call", dll="fixture.dll", symbol="write"
            ),
            instruction_rva=0x2014,
            return_rva=0x2018,
            argument_nodes=(15,),
        )
        write = _Transfer(
            "semantic-transfer:write-after-helper",
            "9" * 64, "a" * 64, 0x2010,
            (
                *self._call_input_nodes(),
                _Node("const", immediate=0x20),
                _Node("add32", (1, 14)),
            ), (),
            (
                _Action("call", (0,), aux=0),
                _Action("outcome_return", (0,)),
            ),
            (write_call,), (),
        )
        preserve_call = replace(
            self._call(
                "external_call", dll="fixture.dll", symbol="preserve"
            ),
            instruction_rva=0x3004,
            return_rva=0x3008,
        )
        helper = _Transfer(
            "semantic-transfer:shared-helper",
            "b" * 64, "c" * 64, 0x3000,
            (
                *self._call_input_nodes(),
                *(_Node("call_response", aux=index) for index in range(8)),
            ), (),
            (
                _Action("call", (0,), aux=0),
                *(
                    _Action("set_reg", (14 + index,), aux=index)
                    for index in range(8)
                ),
                _Action("outcome_return", (14,)),
            ),
            (preserve_call,), (),
        )
        registers = list(ReferenceStateV1().registers)
        registers[1] = CONFLICT_REFERENCE_V1
        closure = build_module_execution_closure_v1(
            transfer_plan_sha256="d" * 64,
            transfers=(
                branch,
                precise_setup,
                internal_caller(0x1010, 0x1014),
                internal_caller(0x1100, 0x1104),
                wrapper,
                write,
                helper,
            ),
            context=ExecutionClosureContextV1(
                roots=(0x0800,),
                catalog=ReferenceCatalogV1(
                    guest_code_rvas=frozenset({
                        0x0800, 0x1000, 0x1010, 0x1100,
                        0x2000, 0x2010, 0x3000,
                    }),
                    objects=(ObjectRangeV1("allocation:list", 0x4000, 0x100),),
                    external_calls={
                        ("fixture.dll", "preserve"): ExternalCallRuleV1(
                            preserved_registers=frozenset({1, 7}),
                        ),
                        ("fixture.dll", "write"): ExternalCallRuleV1(
                            argument_words=1,
                            write_footprints=(ExternalMemoryWriteV1(
                                base_argument=0,
                                offset=0,
                                fixed_bytes=4,
                            ),),
                        ),
                    },
                ),
                authority_bindings={"authority_sha256": "e" * 64},
                initial_states={
                    0x0800: ReferenceStateV1(registers=tuple(registers)),
                },
            ),
        )

        blockers = [
            row for row in closure["blockers"]
            if row["code"] == "unresolved_callee_effect_instantiation"
        ]
        self.assertEqual(len(blockers), 1, closure["blockers"])
        self.assertEqual(blockers[0]["instruction_rva"], 0x1104)
