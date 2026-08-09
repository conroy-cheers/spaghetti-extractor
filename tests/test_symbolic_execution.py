from __future__ import annotations

from types import SimpleNamespace
import unittest

from spaghetti_extractor._contract_tools.common import BlockMapping
from spaghetti_extractor._contract_tools.reference_contract import (
    _semantic_transfer_contract,
)
from spaghetti_extractor._contract_tools.symbolic_execution import _symbolic_execute
from spaghetti_extractor.stage_binary import BlockSide


def _execute(encoded: bytes) -> dict[str, object]:
    side = BlockSide(0x1000, 0x1000 + len(encoded))
    mapping = BlockMapping(
        id="fixture",
        original=side,
        candidate=side,
        kind="fixture",
        reachable=True,
        invariant_checked=True,
        source={},
    )
    binary = SimpleNamespace(bitness=32, image_base=0x400000)
    return _symbolic_execute(binary, side, encoded, "fixture", mapping)


class SymbolicExecutionInstructionTests(unittest.TestCase):
    def test_single_instruction_transfer_emits_exact_effect_schedule(self) -> None:
        encoded = b"\x90"
        side = BlockSide(0x1000, 0x1001)
        mapping = BlockMapping(
            id="fixture",
            original=side,
            candidate=side,
            kind="fixture",
            reachable=True,
            invariant_checked=True,
            source={},
        )
        binary = SimpleNamespace(
            bitness=32,
            image_base=0x400000,
            pe=SimpleNamespace(get_data=lambda rva, size: encoded),
        )

        contract = _semantic_transfer_contract(
            binary,
            mapping,
            "fixture",
            {"format": "fixture"},
        )

        self.assertEqual(contract["status"], "reimplementable")
        schedule = contract["instruction_effect_schedule"]
        self.assertEqual(schedule["status"], "complete")
        self.assertEqual(schedule["counts"]["instructions"], 1)
        self.assertEqual(schedule["records"][0]["rva_start"], 0x1000)

    def test_byte_register_increment_preserves_parent_bits_and_carry(self) -> None:
        result = _execute(b"\xfe\xc0")  # inc al

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        eax = observables["reg:eax"]
        self.assertEqual(eax[:4], ("write_bits", ("reg", "eax"), 0, 8))
        self.assertEqual(observables["flag:cf"], ("flag", "cf"))
        self.assertEqual(observables["flag:sf"][0:2], ("msb_w", 8))
        self.assertEqual(observables["flag:pf"][0:2], ("parity", 8))

    def test_word_memory_increment_uses_word_accesses_and_preserves_carry(self) -> None:
        result = _execute(b"\x66\xff\x00")  # inc word ptr [eax]

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        events = observables["memory_events"]
        self.assertEqual(events[0], ("read", ("mem", 16, ("reg", "eax"))))
        self.assertEqual(events[1][0:2], ("write", ("mem", 16, ("reg", "eax"))))
        self.assertEqual(observables["flag:cf"], ("flag", "cf"))
        self.assertEqual(observables["flag:sf"][0:2], ("msb_w", 16))

    def test_rotate_through_carry_right_one_updates_only_cf_of_and_destination(self) -> None:
        result = _execute(b"\xd1\xdb")  # rcr ebx, 1

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        self.assertEqual(observables["reg:ebx"][0], "or")
        self.assertEqual(observables["flag:cf"][0], "bool_eq")
        self.assertEqual(observables["flag:of"][0], "bool_xor")
        for flag in ("zf", "sf", "pf", "df"):
            self.assertEqual(observables[f"flag:{flag}"], ("flag", flag))

    def test_pop_fs_memory_reads_stack_then_writes_segmented_destination(self) -> None:
        result = _execute(b"\x64\x8f\x05\x00\x00\x00\x00")

        self.assertEqual(result["status"], "ok")
        observables = result["observables"]
        self.assertEqual(
            observables["memory_events"],
            (
                ("read", ("mem32", ("reg", "esp"))),
                (
                    "write",
                    ("mem32", ("fs_base",)),
                    ("mem32", ("reg", "esp")),
                ),
            ),
        )
        self.assertEqual(observables["reg:esp"][0], "add")

    def test_pop_esp_uses_popped_value_without_postincrementing_it(self) -> None:
        result = _execute(b"\x5c")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            result["observables"]["reg:esp"],
            ("mem32", ("reg", "esp")),
        )


if __name__ == "__main__":
    unittest.main()
