import unittest
from types import SimpleNamespace

from spaghetti_extractor.relational.analyses.stack import (
    _attach_stack_window_invariants,
)


class StageAStackCleanupTests(unittest.TestCase):
    def setUp(self):
        self.binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        self.imported = {
            "dll": list(b"fixture.dll"),
            "name": {"op": "symbol", "bytes": list(b"Cleanup")},
        }
        self.machine_contract = {
            "id": 0,
            "import": {"dll": "fixture.dll", "symbol": "Cleanup"},
            "stack_argument_offsets": [],
            "stack_result_delta": 4,
        }

    @staticmethod
    def _identity(register):
        return {"op": "input_reg", "reg": register}

    @staticmethod
    def _write(register, offset=0):
        address = {"op": "input_reg", "reg": register}
        if offset:
            address = {
                "op": "add",
                "left": address,
                "right": {"op": "constant", "value": offset},
            }
        return {"address": address, "value": {"op": "constant", "value": 1}}

    def _pair(self, ir):
        return {"original_ir": ir, "candidate_ir": ir}

    def test_cleanup_does_not_create_ebp_plus_four_cycle(self):
        call = {
            "registers": {"ebp": self._identity("ebp")},
            "writes": [self._write("ebp", 4)],
            "outcome": {
                "op": "external_call",
                "import": self.imported,
                "arguments": [],
            },
        }
        contract = {
            "machine_import_call_contracts": [self.machine_contract],
            "regions": [
                {"id": "prologue", "address_separations": []},
                {"id": "call-loop", "address_separations": []},
            ],
        }
        relations = {"edges": [
            {
                "source_region_index": 0,
                "target_region_index": 1,
                "environment_barrier": False,
            },
            {
                "source_region_index": 1,
                "target_region_index": 1,
                "environment_barrier": True,
            },
        ]}
        prologue = {"registers": {"ebp": self._identity("esp")}}

        refined, analysis = _attach_stack_window_invariants(
            contract,
            [self._pair(prologue), self._pair(call)],
            relations,
            self.binary,
            self.binary,
        )

        self.assertEqual(analysis["nonzero_stack_delta_cycle_nodes"], 0)
        self.assertNotIn(
            "nonzero_stack_delta_cycle_requires_relational_frame",
            {item["reason"] for item in analysis["frontier"]},
        )
        self.assertEqual(
            refined["regions"][1]["stack_windows"],
            [{
                "range_id": 0,
                "original_register": "ebp",
                "candidate_register": "ebp",
                "bytes_below": 0,
                "bytes_above": 8,
                "source": "paired_memory_write_seed",
            }],
        )
        self.assertEqual(
            refined["regions"][0]["stack_windows"][0]["original_register"],
            "esp",
        )

    def test_cleanup_still_adjusts_esp_window(self):
        call = {
            "registers": {"esp": self._identity("esp")},
            "outcome": {
                "op": "external_call",
                "import": self.imported,
                "arguments": [],
            },
        }
        sink = {
            "registers": {},
            "writes": [self._write("esp")],
        }
        contract = {
            "machine_import_call_contracts": [self.machine_contract],
            "regions": [
                {"id": "call", "address_separations": []},
                {"id": "sink", "address_separations": []},
            ],
        }
        relations = {"edges": [{
            "source_region_index": 0,
            "target_region_index": 1,
            "environment_barrier": True,
        }]}

        refined, analysis = _attach_stack_window_invariants(
            contract,
            [self._pair(call), self._pair(sink)],
            relations,
            self.binary,
            self.binary,
        )

        self.assertEqual(analysis["nonzero_stack_delta_cycle_nodes"], 0)
        self.assertEqual(
            [
                (window["bytes_below"], window["bytes_above"])
                for region in refined["regions"]
                for window in region["stack_windows"]
            ],
            [(0, 8), (0, 4)],
        )


if __name__ == "__main__":
    unittest.main()
