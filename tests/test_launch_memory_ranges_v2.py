from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.launch_memory_ranges_v2 import (
    CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT,
    derive_launch_memory_range_analysis_v2,
    validate_launch_memory_range_analysis_v2,
)


PE_SHA256 = "a" * 64
MACHINE_SHA256 = "b" * 64
IMAGE_BASE = 0x400000
IMAGE_SIZE = 0x10000


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value & 0xFFFF_FFFF, "width": 32}


def _fs(offset: int = 0) -> dict[str, object]:
    base: dict[str, object] = {"op": "fs_base", "width": 32}
    return (
        base
        if offset == 0
        else {"op": "add32", "args": [base, _const(offset)]}
    )


def _unit() -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "id": "entry",
        "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1004}},
        "semantics": {
            "memory_events": [
                {"kind": "write", "width": 4, "address": _fs()},
                {"kind": "read", "width": 4, "address": _fs(0x20)},
                {"kind": "read", "width": 4, "address": _fs(0x1000)},
                {
                    "kind": "read",
                    "width": 4,
                    "address": {"op": "reg", "name": "eax", "width": 32},
                },
            ]
        },
        "control": {"direct_targets": [], "has_indirect_target": False},
    }


def _launch() -> dict[str, object]:
    return {
        "assumptions": {
            "fs": {
                "contract": "pe32-user-thread-fs-v1",
                "teb_fields": "profiled-accesses-only",
                "range_contract": (
                    "private-non-image-thread-environment-range-v1"
                ),
                "mapped_separately_from_image": True,
                "minimum_accessible_bytes": 0x1000,
            }
        }
    }


def _derive(
    *, launch: dict[str, object] | None = None
) -> dict[str, object]:
    return derive_launch_memory_range_analysis_v2(
        units=[_unit()],
        launch_assumptions=_launch() if launch is None else launch,
        pe_sha256=PE_SHA256,
        machine_ir_sha256=MACHINE_SHA256,
        image_base=IMAGE_BASE,
        size_of_image=IMAGE_SIZE,
    )


class LaunchMemoryRangeAnalysisV2Tests(unittest.TestCase):
    def test_emits_only_in_range_fs_relative_events(self) -> None:
        analysis = _derive()

        self.assertEqual(analysis["status"], "complete")
        facts = analysis["checked_spatial_facts"]
        self.assertEqual(len(facts), 2)
        self.assertEqual([row["event_index"] for row in facts], [0, 1])
        self.assertTrue(all(
            row["format"] == CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT
            for row in facts
        ))
        self.assertEqual(facts[1]["address_base_offset"], 0x20)
        self.assertEqual(
            facts[0]["disjoint_from_image"],
            {"image_base": IMAGE_BASE, "size_of_image": IMAGE_SIZE},
        )

    def test_missing_explicit_range_contract_fails_closed(self) -> None:
        launch = _launch()
        del launch["assumptions"]["fs"]["mapped_separately_from_image"]

        analysis = _derive(launch=launch)

        self.assertEqual(analysis["status"], "incomplete")
        self.assertEqual(analysis["checked_spatial_facts"], [])
        self.assertEqual(
            analysis["issues"][0]["code"],
            "fs_launch_range_contract_missing",
        )

    def test_invalid_range_size_is_violated(self) -> None:
        launch = _launch()
        launch["assumptions"]["fs"]["minimum_accessible_bytes"] = 0

        analysis = _derive(launch=launch)

        self.assertEqual(analysis["status"], "violated")
        self.assertEqual(analysis["checked_spatial_facts"], [])

    def test_validator_replays_exact_units_and_profile(self) -> None:
        analysis = _derive()
        indexed = validate_launch_memory_range_analysis_v2(
            analysis,
            units=[_unit()],
            launch_assumptions=_launch(),
            pe_sha256=PE_SHA256,
            machine_ir_sha256=MACHINE_SHA256,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )
        self.assertEqual(
            sorted(indexed), ["event:entry:0", "event:entry:1"]
        )

        corrupted = copy.deepcopy(analysis)
        corrupted["checked_spatial_facts"][0]["address_base_offset"] = 4
        with self.assertRaisesRegex(ValueError, "does not replay exactly"):
            validate_launch_memory_range_analysis_v2(
                corrupted,
                units=[_unit()],
                launch_assumptions=_launch(),
                pe_sha256=PE_SHA256,
                machine_ir_sha256=MACHINE_SHA256,
                image_base=IMAGE_BASE,
                size_of_image=IMAGE_SIZE,
            )


if __name__ == "__main__":
    unittest.main()
