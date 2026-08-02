from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.contract_tools import (
    BlockMapping,
    _semantic_fpu_state_from_observables,
    _semantic_transfer_contract,
)
from spaghetti_extractor.relational.reference_contract import REFERENCE_CONTRACT_MODEL_ID
from spaghetti_extractor.stage_binary import BlockSide, _parse_stage_a_pe
from spaghetti_extractor.stage_b_state_machine import normalize_stage_a_semantic_transfer
from spaghetti_extractor.util import sha256_bytes

from pe_fixtures import pe32_image


def _fpu(op: str, *args: object) -> tuple[object, ...]:
    return (op, *args)


def _physical_observables() -> dict[str, object]:
    return {
        "fpu_stack": tuple(_fpu("fpu_reg", index) for index in range(8)),
        "fpu_tags": tuple(_fpu("fpu_tag", index) for index in range(8)),
        "fpu_control": _fpu("fpu_control"),
        "fpu_status": _fpu("fpu_status"),
        "fpu_pending_exception": _fpu("fpu_pending_exception"),
        "fpu_last_opcode": _fpu("fpu_last_opcode"),
        "fpu_instruction_pointer": _fpu("fpu_instruction_pointer"),
        "fpu_code_selector": _fpu("fpu_code_selector"),
        "fpu_data_pointer": _fpu("fpu_data_pointer"),
        "fpu_data_selector": _fpu("fpu_data_selector"),
    }


class StageAX87SemanticExportTests(unittest.TestCase):
    def test_complete_physical_observables_are_preserved_for_stage_b(self) -> None:
        state = _semantic_fpu_state_from_observables(_physical_observables())

        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(state["model"], "symbolic_x87_stack_v1")
        self.assertEqual(len(state["stack"]), 8)
        self.assertEqual(len(state["tags"]), 8)
        self.assertEqual(state["tags"][3], {"op": "fpu_tag", "args": [3]})
        self.assertEqual(
            set(state),
            {
                "model",
                "stack",
                "tags",
                "control",
                "status",
                "pending_exception",
                "last_opcode",
                "instruction_pointer",
                "code_selector",
                "data_pointer",
                "data_selector",
            },
        )

    def test_logical_only_observables_require_checked_exact_command_replay(self) -> None:
        state = _semantic_fpu_state_from_observables(
            {
                "fpu_stack": tuple(_fpu("fpu_reg", index) for index in range(8)),
                "fpu_control": _fpu("fpu_control"),
                "fpu_status": _fpu("fpu_status"),
            },
            native_exact_command_replay={
                "rva_start": 0x1000,
                "rva_end": 0x1002,
                "bytes": "d9e8",
                "bytes_sha256": sha256_bytes(bytes.fromhex("d9e8")),
            },
        )

        self.assertIsNotNone(state)
        assert state is not None
        self.assertEqual(
            state["model"], "native_exact_x87_command_replay_obligation_v1"
        )
        self.assertEqual(
            state["missing_or_invalid_fields"],
            [
                "tags",
                "pending_exception",
                "last_opcode",
                "instruction_pointer",
                "code_selector",
                "data_pointer",
                "data_selector",
            ],
        )
        self.assertNotIn("tags", state)
        self.assertNotIn("pending_exception", state)
        self.assertEqual(state["replay"]["bytes"], "d9e8")
        self.assertEqual(
            state["replay"]["checked_executor"],
            "StageA.Relational.X87.executeSingletonCommand",
        )
        self.assertEqual(
            state["replay"]["checked_decoder_scope"],
            "each_x87_singleton_instruction",
        )
        self.assertEqual(
            state["replay"]["checked_executor_scope"],
            "each_x87_singleton_instruction",
        )
        normalized = normalize_stage_a_semantic_transfer(
            {"status": "incomplete", "fpu_state": state}
        )
        self.assertEqual(normalized["fpu_state"], state)

    def test_x87_transfer_fails_closed_with_exact_byte_bound_obligation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encoded = bytes.fromhex("d9e8")
            original = root / "original.exe"
            original.write_bytes(pe32_image(encoded))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1002)
            mapping = BlockMapping(
                id="x87-command",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "x87_command"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "x87_command",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

        self.assertEqual(transfer["status"], "incomplete")
        self.assertEqual(
            transfer["blocker_category"],
            "x87_physical_state_requires_native_exact_command_replay",
        )
        replay = transfer["fpu_state"]["replay"]
        self.assertEqual(replay["rva_start"], 0x1000)
        self.assertEqual(replay["rva_end"], 0x1002)
        self.assertEqual(replay["bytes"], encoded.hex())
        self.assertEqual(replay["bytes_sha256"], sha256_bytes(encoded))
        self.assertEqual(replay["instructions"], [
            {"rva": 0x1000, "size": 2, "bytes": "d9e8"}
        ])
        self.assertNotIn("tags", transfer["fpu_state"])

    def test_mixed_transfer_exports_ordered_hash_bound_effects(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encoded = bytes.fromhex(
                "b807000000"  # mov eax, 7
                "83f807"      # cmp eax, 7
                "d901"        # fld dword ptr [ecx]
                "dfe0"        # fnstsw ax
                "f7f9"        # idiv ecx
                "e800000000"  # call next instruction
            )
            original = root / "original.exe"
            original.write_bytes(pe32_image(encoded))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="mixed-x87-command",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "mixed_x87_command"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "mixed_x87_command",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )
            repeated = _semantic_transfer_contract(
                binary,
                mapping,
                "mixed_x87_command",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

        self.assertEqual(transfer["status"], "incomplete")
        schedule = transfer["instruction_effect_schedule"]
        self.assertEqual(schedule, repeated["instruction_effect_schedule"])
        self.assertEqual(schedule["status"], "complete")
        self.assertFalse(schedule["proof_authority"])
        self.assertEqual(
            schedule["counts"],
            {
                "instructions": 6,
                "x87_singletons": 2,
                "ordinary_instructions": 4,
                "blockers": 0,
            },
        )
        records = schedule["records"]
        self.assertEqual(
            [record["instruction_class"] for record in records],
            [
                "ordinary_symbolic_instruction",
                "ordinary_symbolic_instruction",
                "x87_singleton_checked_replay",
                "x87_singleton_checked_replay",
                "ordinary_symbolic_instruction",
                "ordinary_symbolic_instruction",
            ],
        )
        self.assertEqual(
            [record["rva_start"] for record in records],
            [0x1000, 0x1005, 0x1008, 0x100A, 0x100C, 0x100E],
        )
        self.assertEqual(records[0]["effects"]["counts"]["register_writes"], 1)
        self.assertEqual(
            records[1]["effects"]["counts"]["defined_flag_writes"], 5
        )
        self.assertEqual(records[2]["effects"]["counts"]["memory_events"], 1)
        self.assertEqual(records[3]["effects"]["counts"]["register_writes"], 1)
        self.assertEqual(records[4]["effects"]["counts"]["faults"], 1)
        self.assertEqual(records[4]["effects"]["counts"]["undefined_flags"], 5)
        self.assertEqual(records[5]["effects"]["counts"]["call_effects"], 1)
        self.assertEqual(records[5]["effects"]["call_effects"][0]["kind"], "internal_call")
        for record in records:
            unhashed = dict(record)
            digest = unhashed.pop("record_sha256")
            self.assertEqual(
                digest,
                sha256_bytes(
                    json.dumps(
                        unhashed, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
            )
            self.assertFalse(record["classification"]["proof_authority"])
        x87_record = records[2]
        self.assertEqual(
            x87_record["classification"]["checked_decoder"],
            "StageA.Relational.X87.decodeSingletonCommand",
        )
        self.assertNotIn("tags", x87_record["x87_singleton_replay"])
        self.assertEqual(
            x87_record["x87_singleton_replay"]["physical_state_effect"],
            "produced_by_checked_executor_not_inferred_by_exporter",
        )
        replay_schedule = transfer["fpu_state"]["replay"][
            "instruction_effect_schedule"
        ]
        self.assertEqual(replay_schedule["schedule_sha256"], schedule["schedule_sha256"])

    def test_mixed_transfer_reports_exact_rva_when_effect_is_unrepresentable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encoded = bytes.fromhex("d9e840")  # fld1; inc eax
            original = root / "original.exe"
            original.write_bytes(pe32_image(encoded))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="blocked-mixed-x87-command",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "blocked_mixed_x87_command"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "blocked_mixed_x87_command",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

        schedule = transfer["instruction_effect_schedule"]
        self.assertEqual(schedule["status"], "incomplete")
        self.assertEqual(schedule["counts"]["instructions"], 1)
        self.assertEqual(schedule["counts"]["blockers"], 1)
        blocker = schedule["blockers"][0]
        self.assertEqual(blocker["rva"], 0x1002)
        self.assertEqual(blocker["bytes"], "40")
        self.assertEqual(blocker["bytes_sha256"], sha256_bytes(b"\x40"))
        self.assertEqual(blocker["category"], "unsupported_semantics")
        self.assertIn("instruction inc", blocker["blocker"])

    def test_non_x87_transfer_remains_reimplementable_without_fpu_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            original.write_bytes(pe32_image(b"\x90"))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1001)
            mapping = BlockMapping(
                id="ordinary-command",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "ordinary_command"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "ordinary_command",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

        self.assertEqual(transfer["status"], "reimplementable")
        self.assertIsNone(transfer["fpu_state"])
        self.assertIsNone(transfer["blocker_category"])

    def test_multi_instruction_transfer_exports_ordered_ordinary_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encoded = bytes.fromhex(
                "b804000000"  # mov eax, 4
                "83c001"      # add eax, 1
            )
            original = root / "original.exe"
            original.write_bytes(pe32_image(encoded))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="ordinary-ordered-effects",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "ordinary_ordered_effects"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "ordinary_ordered_effects",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

        self.assertEqual(transfer["status"], "reimplementable", transfer)
        self.assertIsNone(transfer["fpu_state"])
        schedule = transfer["instruction_effect_schedule"]
        self.assertEqual(schedule["status"], "complete")
        self.assertEqual(schedule["counts"], {
            "instructions": 2,
            "x87_singletons": 0,
            "ordinary_instructions": 2,
            "blockers": 0,
        })
        self.assertEqual(
            [record["instruction_class"] for record in schedule["records"]],
            ["ordinary_symbolic_instruction", "ordinary_symbolic_instruction"],
        )


if __name__ == "__main__":
    unittest.main()
