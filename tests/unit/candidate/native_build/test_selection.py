from __future__ import annotations

from tests.unit.candidate.native_build._support import *


class NativeSummarySelectionTests(unittest.TestCase):
    def test_complete_rows_survive_unrelated_global_incompleteness(self) -> None:
        payload = {
            "control": {
                "internal_call_preservation": {
                    "format": "stage-a-internal-call-preservation-v1",
                    "status": "incomplete",
                    "fixed_point_complete": False,
                    "summaries": [
                        {
                            "status": "complete",
                            "target_rva": 0x1000,
                            "preserved_registers": ["ebx", "esi"],
                        },
                        {
                            "status": "incomplete",
                            "target_rva": 0x2000,
                            "preserved_registers": [],
                        },
                    ],
                }
            }
        }

        self.assertEqual(
            _machine_ir_internal_call_preservation(payload),
            {0x1000: frozenset({"ebx", "esi"})},
        )


if __name__ == "__main__":
    unittest.main()
