from __future__ import annotations

import time
import unittest

from spaghetti_extractor.qualified_platform.requirements import (
    build_machine_ir_isa_extraction_request_v2,
)


REGION_COUNT = 20_000
MAX_SECONDS = 5.0


class ISARequestPlanningPerformanceTests(unittest.TestCase):
    def test_large_disjoint_inventory_is_planned_near_linearly(self) -> None:
        base_rva = 0x1000
        units = [
            {
                "id": f"unit-{index:08x}",
                "reachable": True,
                "source": {
                    "original": {
                        "rva_start": base_rva + index,
                        "rva_end": base_rva + index + 1,
                    }
                },
                "instructions": [
                    {
                        "rva_start": base_rva + index,
                        "rva_end": base_rva + index + 1,
                    }
                ],
            }
            for index in range(REGION_COUNT)
        ]

        started = time.monotonic()
        request = build_machine_ir_isa_extraction_request_v2(
            units=units,
            binary_sha256="a" * 64,
        )
        elapsed = time.monotonic() - started

        self.assertEqual(len(request["regions"]), REGION_COUNT)
        self.assertEqual(request["regions"][0]["span"]["rva_start"], base_rva)
        self.assertEqual(
            request["regions"][-1]["span"]["rva_start"],
            base_rva + REGION_COUNT - 1,
        )
        self.assertLess(elapsed, MAX_SECONDS)


if __name__ == "__main__":
    unittest.main()
