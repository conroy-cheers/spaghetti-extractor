from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.target_cutpoint_materialization_v2 import (
    TARGET_CUTPOINT_PLAN_V2_FORMAT,
    plan_recovered_target_cutpoints_v2,
)

from tests.pe_fixtures import pe32_image


def _unit(
    identity: str,
    start: int,
    end: int,
    instructions: list[tuple[int, int]],
) -> dict:
    return {
        "id": identity,
        "source": {"original": {"rva_start": start, "rva_end": end}},
        "instructions": [
            {"rva_start": insn_start, "rva_end": insn_end}
            for insn_start, insn_end in instructions
        ],
    }


def _recovery(*targets: int) -> dict:
    return {
        "id": "indirect:fixture",
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "recovery_kind": "pe32_indexed_absolute_jump_table",
        "failure": None,
        "target_rvas": list(targets),
    }


class TargetCutpointMaterializationV2Tests(unittest.TestCase):
    def _plan(
        self,
        code: bytes,
        *,
        units: list[dict],
        target: int,
        data_ranges: list[dict] | None = None,
    ) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            binary = _parse_stage_a_pe(original)
            try:
                return plan_recovered_target_cutpoints_v2(
                    binary=binary,
                    units=units,
                    recoveries=[_recovery(target)],
                    immutable_data_ranges=data_ranges or [],
                )
            finally:
                binary.pe.close()

    def test_materializes_suffix_at_existing_instruction_boundary(self) -> None:
        report = self._plan(
            b"\x90\x90\xc3",
            units=[_unit("whole", 0x1000, 0x1003, [(0x1000, 0x1001), (0x1001, 0x1002), (0x1002, 0x1003)])],
            target=0x1001,
        )

        self.assertEqual(report["format"], TARGET_CUTPOINT_PLAN_V2_FORMAT)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(
            report["targets"][0]["regions"],
            [{"rva_start": 0x1001, "rva_end": 0x1003, "size": 2}],
        )
        self.assertEqual(
            report["targets"][0]["evidence"], "existing_instruction_boundary"
        )

    def test_decodes_target_immediately_after_embedded_data(self) -> None:
        report = self._plan(
            b"\x04\x10\x40\x00\x90\xc3",
            units=[_unit("linear-data-view", 0x1000, 0x1005, [(0x1000, 0x1005)])],
            target=0x1004,
            data_ranges=[{"rva_start": 0x1000, "rva_end": 0x1004}],
        )

        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["targets"][0]["disposition"], "materialize")
        self.assertEqual(
            report["targets"][0]["regions"],
            [{"rva_start": 0x1004, "rva_end": 0x1006, "size": 2}],
        )
        self.assertEqual(
            report["targets"][0]["evidence"], "decoded_control_boundary"
        )

    def test_rejects_target_in_middle_of_instruction(self) -> None:
        report = self._plan(
            b"\xb8\x01\x00\x00\x00\xc3",
            units=[_unit("whole", 0x1000, 0x1006, [(0x1000, 0x1005), (0x1005, 0x1006)])],
            target=0x1002,
        )

        self.assertEqual(report["status"], "violated")
        self.assertEqual(
            report["issues"][0]["code"], "recovered_target_inside_instruction"
        )
        self.assertEqual(report["targets"][0]["regions"], [])

    def test_rejects_ambiguous_overlapping_decode_views(self) -> None:
        report = self._plan(
            b"\x90\xc3",
            units=[
                _unit("boundary-view", 0x1000, 0x1002, [(0x1000, 0x1001), (0x1001, 0x1002)]),
                _unit("interior-view", 0x1000, 0x1002, [(0x1000, 0x1002)]),
            ],
            target=0x1001,
        )

        self.assertEqual(report["status"], "violated")
        self.assertEqual(
            report["issues"][0]["code"], "ambiguous_overlapping_target_decode"
        )


if __name__ == "__main__":
    unittest.main()
