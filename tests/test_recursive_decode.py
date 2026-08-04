from __future__ import annotations

import unittest
from dataclasses import dataclass

from spaghetti_extractor.recursive_decode import (
    ROOTED_INSTRUCTION_VIEW_FORMAT,
    discover_rooted_instruction_views,
)


@dataclass(frozen=True)
class _Section:
    rva_start: int
    rva_end: int
    executable: bool = True


class _Image:
    bitness = 32
    image_base = 0x400000

    def __init__(self, rva_start: int, data: bytes) -> None:
        self._rva_start = rva_start
        self._data = data
        self.sections = (_Section(rva_start, rva_start + len(data)),)
        self.reads: list[int] = []

    def read_rva(self, rva: int, size: int) -> bytes:
        self.reads.append(rva)
        offset = rva - self._rva_start
        if not 0 <= offset < len(self._data):
            return b""
        return self._data[offset : offset + size]


def _discover(
    encoded: bytes,
    *,
    seeds: tuple[int, ...] = (0x1000,),
    existing: tuple[int, ...] = (),
    budget: int = 32,
) -> tuple[_Image, dict]:
    image = _Image(0x1000, encoded)
    return image, discover_rooted_instruction_views(
        image,
        seeds,
        existing,
        budget,
    )


class RootedInstructionViewTests(unittest.TestCase):
    def test_target_inside_false_linear_decode_preserves_overlapping_view(self) -> None:
        _image, result = _discover(
            bytes.fromhex("b8c3909090c3ebf9"),
            seeds=(0x1006, 0x1000),
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [view["rva_start"] for view in result["views"]],
            [0x1000, 0x1001, 0x1005, 0x1006],
        )
        overlapping = result["views"][1]
        self.assertEqual(overlapping["bytes"], "c3")
        self.assertEqual(
            overlapping["provenance"],
            {
                "is_seed": False,
                "seed_rvas": [0x1006],
                "predecessors": [
                    {"source_rva": 0x1006, "edge_kind": "jump"}
                ],
            },
        )

    def test_direct_call_follows_callee_and_return_continuation(self) -> None:
        _image, result = _discover(bytes.fromhex("e803000000c39090c3"))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [view["rva_start"] for view in result["views"]],
            [0x1000, 0x1005, 0x1008],
        )
        self.assertEqual(
            result["views"][0]["control"],
            {
                "kind": "direct_call",
                "successors": [
                    {"kind": "call_target", "target_rva": 0x1008},
                    {"kind": "call_continuation", "target_rva": 0x1005},
                ],
            },
        )
        self.assertEqual(
            [view["control"]["kind"] for view in result["views"][1:]],
            ["return", "return"],
        )

    def test_conditional_branch_follows_taken_and_fallthrough(self) -> None:
        _image, result = _discover(bytes.fromhex("7502c390c3"))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [view["rva_start"] for view in result["views"]],
            [0x1000, 0x1002, 0x1004],
        )
        self.assertEqual(
            result["views"][0]["control"],
            {
                "kind": "conditional_branch",
                "successors": [
                    {"kind": "branch_taken", "target_rva": 0x1004},
                    {"kind": "branch_fallthrough", "target_rva": 0x1002},
                ],
            },
        )

    def test_existing_start_is_a_checked_merge_not_a_view(self) -> None:
        image, result = _discover(
            bytes.fromhex("90c3"),
            existing=(0x1001,),
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual([view["rva_start"] for view in result["views"]], [0x1000])
        self.assertEqual(image.reads, [0x1000])
        self.assertEqual(
            result["merge_destinations"],
            [
                {
                    "rva": 0x1001,
                    "provenance": {
                        "is_seed": False,
                        "seed_rvas": [0x1000],
                        "predecessors": [
                            {"source_rva": 0x1000, "edge_kind": "fallthrough"}
                        ],
                    },
                }
            ],
        )

    def test_direct_target_outside_executable_section_is_incomplete(self) -> None:
        for encoded, target_rva in (
            (bytes.fromhex("e9fb0f0000"), 0x2000),
            (bytes.fromhex("e9ebefffff"), -0x10),
        ):
            with self.subTest(target_rva=target_rva):
                _image, result = _discover(encoded)

                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(len(result["views"]), 1)
                self.assertEqual(
                    result["issues"][0]["code"],
                    "target_outside_executable_section",
                )
                self.assertEqual(result["issues"][0]["rva"], target_rva)
                self.assertEqual(
                    result["issues"][0]["provenance"]["predecessors"],
                    [{"source_rva": 0x1000, "edge_kind": "jump"}],
                )

    def test_budget_failure_is_deterministic_across_seed_order(self) -> None:
        first = _discover(
            bytes.fromhex("909090c3"),
            seeds=(0x1002, 0x1000),
            budget=2,
        )[1]
        second = _discover(
            bytes.fromhex("909090c3"),
            seeds=(0x1000, 0x1002),
            budget=2,
        )[1]

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "incomplete")
        self.assertEqual(
            [view["rva_start"] for view in first["views"]],
            [0x1000, 0x1001],
        )
        self.assertEqual(first["issues"][0]["code"], "instruction_budget_exhausted")
        self.assertEqual(first["issues"][0]["rva"], 0x1002)
        self.assertEqual(first["issues"][0]["pending_rvas"], [0x1002])

    def test_indirect_call_continues_and_indirect_jump_stops(self) -> None:
        _image, call = _discover(bytes.fromhex("ffd0c3"))
        _image, jump = _discover(bytes.fromhex("ffe0"))

        self.assertEqual(
            [view["control"]["kind"] for view in call["views"]],
            ["indirect_call", "return"],
        )
        self.assertEqual(call["issues"], [])
        self.assertEqual(
            jump["views"][0]["control"],
            {"kind": "indirect_jump", "successors": []},
        )
        self.assertEqual(jump["issues"], [])

    def test_invalid_seed_and_undecodable_instruction_are_explicit(self) -> None:
        _image, invalid_seed = _discover(b"\xc3", seeds=(0x2000,))
        _image, undecodable = _discover(b"\x0f")

        self.assertEqual(
            invalid_seed["issues"][0]["code"],
            "seed_outside_executable_section",
        )
        self.assertEqual(
            undecodable["issues"][0]["code"],
            "undecodable_instruction",
        )

    def test_far_and_system_control_are_incomplete_terminals(self) -> None:
        for encoded, code in (
            (bytes.fromhex("ea001000000800"), "unsupported_far_control"),
            (bytes.fromhex("0f34"), "unsupported_system_control"),
        ):
            with self.subTest(code=code):
                _image, result = _discover(encoded)
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(len(result["views"]), 1)
                self.assertEqual(result["views"][0]["control"]["successors"], [])
                self.assertEqual(result["issues"][0]["code"], code)

    def test_result_schema_identifies_proposal_format(self) -> None:
        _image, result = _discover(b"\xc3")

        self.assertEqual(result["format"], ROOTED_INSTRUCTION_VIEW_FORMAT)
        self.assertEqual(result["decoded_instruction_count"], 1)
        self.assertEqual(result["instruction_budget"], 32)


if __name__ == "__main__":
    unittest.main()
