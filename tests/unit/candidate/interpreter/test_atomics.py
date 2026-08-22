from __future__ import annotations

import unittest

from spaghetti_extractor.artifacts.formats import (
    INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
)
from spaghetti_extractor.candidate.interpreter_compiler import _TransferCompiler
from spaghetti_extractor.machine_ir.memory_actions import build_memory_action_graph


class AtomicInterpreterLoweringTests(unittest.TestCase):
    def test_compare_exchange_is_one_runtime_action_without_a_second_load(self) -> None:
        address = {"op": "const", "value": 0x430324, "width": 32}
        observed = {"op": "load", "address": address, "width": 4}
        expected = {"op": "reg", "name": "eax", "width": 32}
        desired = {"op": "reg", "name": "ebx", "width": 32}
        condition = {"op": "eq", "args": [observed, expected]}
        events = [
            {"kind": "read", "address": address, "width": 4},
            {
                "kind": "write",
                "address": address,
                "width": 4,
                "value": {"op": "ite", "args": [condition, desired, observed]},
            },
        ]
        ordered = [
            {"family": "memory", "instruction_rva": 0x1052, **event}
            for event in events
        ]
        instruction = {
            "rva_start": 0x1052,
            "mnemonic": "lock cmpxchg",
            "operands": [
                {
                    "kind": "memory",
                    "segment": None,
                    "base": None,
                    "index": None,
                    "scale": 1,
                    "displacement": 0x430324,
                    "width_bits": 32,
                },
                {"kind": "register", "name": "ebx", "width_bits": 32},
            ],
        }
        graph = build_memory_action_graph(
            instructions=[instruction],
            memory_events=events,
            ordered_events=ordered,
        )
        effects = {
            "ordered_events": ordered,
            "register_writes": [
                {
                    "register": "eax",
                    "value": {"op": "ite", "args": [condition, expected, observed]},
                }
            ],
            "defined_flag_writes": [{"flag": "zf", "value": condition}],
            "undefined_flag_writes": [],
            "control": {"kind": "fallthrough", "target_rva": 0x105A},
        }
        row = {
            "id": "semantic-transfer:atomic",
            "contract_sha256": "a" * 64,
            "instruction_bytes_sha256": "b" * 64,
            "original": {"rva_start": 0x1052, "rva_end": 0x105A, "size": 8},
            "instructions": [instruction],
            "ordered_events": ordered,
            "register_writes": effects["register_writes"],
            "flag_writes": effects["defined_flag_writes"],
            "fpu_state": None,
            "outcome": effects["control"],
            "memory_actions": graph,
            "_machine_ir_x87_micro_ops": [],
            "instruction_effect_schedule": {
                "format": INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
                "status": "complete",
                "proof_authority": False,
                "blockers": [],
                "ordering": "strict_contiguous_rva_order",
                "rva_start": 0x1052,
                "rva_end": 0x105A,
                "records": [
                    {
                        "rva_start": 0x1052,
                        "rva_end": 0x105A,
                        "instruction_class": "ordinary_symbolic_instruction",
                        "classification": {
                            "status": "proposal_requires_lean_exact_byte_replay",
                            "proof_authority": False,
                            "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                            "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
                        },
                        "effects": effects,
                    }
                ],
                "counts": {"instructions": 1, "blockers": 0, "x87_singletons": 0, "ordinary_instructions": 1},
            },
        }

        transfer = _TransferCompiler(row).compile()

        atomic = [action for action in transfer.actions if action.op == "atomic_compare_exchange"]
        self.assertEqual(len(atomic), 1)
        self.assertNotIn("memory_write", {action.op for action in transfer.actions})
        load_nodes = {index for index, node in enumerate(transfer.nodes) if node.op == "load"}
        evaluated = {
            action.args[0]
            for action in transfer.actions
            if action.op == "eval_word"
        }
        self.assertTrue(load_nodes)
        self.assertTrue(load_nodes.isdisjoint(evaluated))

    def test_exchange_is_one_runtime_action_without_a_second_load(self) -> None:
        address = {"op": "const", "value": 0x430320, "width": 32}
        observed = {"op": "load", "address": address, "width": 4}
        desired = {"op": "reg", "name": "edx", "width": 32}
        events = [
            {"kind": "read", "address": address, "width": 4},
            {"kind": "write", "address": address, "width": 4, "value": desired},
        ]
        ordered = [
            {"family": "memory", "instruction_rva": 0x1328, **event}
            for event in events
        ]
        instruction = {
            "rva_start": 0x1328,
            "mnemonic": "xchg",
            "operands": [
                {
                    "kind": "memory",
                    "segment": None,
                    "base": None,
                    "index": None,
                    "scale": 1,
                    "displacement": 0x430320,
                    "width_bits": 32,
                },
                {"kind": "register", "name": "edx", "width_bits": 32},
            ],
        }
        graph = build_memory_action_graph(
            instructions=[instruction],
            memory_events=events,
            ordered_events=ordered,
        )
        effects = {
            "ordered_events": ordered,
            "register_writes": [{"register": "edx", "value": observed}],
            "defined_flag_writes": [],
            "undefined_flag_writes": [],
            "control": {"kind": "fallthrough", "target_rva": 0x1329},
        }
        row = {
            "id": "semantic-transfer:exchange",
            "contract_sha256": "a" * 64,
            "instruction_bytes_sha256": "b" * 64,
            "original": {"rva_start": 0x1328, "rva_end": 0x1329, "size": 1},
            "instructions": [instruction],
            "ordered_events": ordered,
            "register_writes": effects["register_writes"],
            "flag_writes": [],
            "fpu_state": None,
            "outcome": effects["control"],
            "memory_actions": graph,
            "_machine_ir_x87_micro_ops": [],
            "instruction_effect_schedule": {
                "format": INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
                "status": "complete",
                "proof_authority": False,
                "blockers": [],
                "ordering": "strict_contiguous_rva_order",
                "rva_start": 0x1328,
                "rva_end": 0x1329,
                "records": [
                    {
                        "rva_start": 0x1328,
                        "rva_end": 0x1329,
                        "instruction_class": "ordinary_symbolic_instruction",
                        "classification": {
                            "status": "proposal_requires_lean_exact_byte_replay",
                            "proof_authority": False,
                            "checked_decoder": "SpaghettiExtractor.ISA.Formal.decodeInstructionExact",
                            "checked_executor": "SpaghettiExtractor.ISA.Formal.executeInstruction",
                        },
                        "effects": effects,
                    }
                ],
                "counts": {
                    "instructions": 1,
                    "blockers": 0,
                    "x87_singletons": 0,
                    "ordinary_instructions": 1,
                },
            },
        }

        transfer = _TransferCompiler(row).compile()

        atomic = [
            action for action in transfer.actions if action.op == "atomic_exchange"
        ]
        self.assertEqual(len(atomic), 1)
        self.assertNotIn("memory_write", {action.op for action in transfer.actions})
        load_nodes = {
            index for index, node in enumerate(transfer.nodes) if node.op == "load"
        }
        evaluated = {
            action.args[0]
            for action in transfer.actions
            if action.op == "eval_word"
        }
        self.assertTrue(load_nodes)
        self.assertTrue(load_nodes.isdisjoint(evaluated))


if __name__ == "__main__":
    unittest.main()
