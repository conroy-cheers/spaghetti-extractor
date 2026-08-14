from __future__ import annotations

import unittest
from pathlib import Path

from spaghetti_extractor.reconstruction_plan import MachineIRInput


class ReconstructionPlanTests(unittest.TestCase):
    def test_machine_ir_input_is_an_immutable_value(self) -> None:
        value = MachineIRInput(
            root=Path("machine-ir"),
            manifest_path=Path("machine-ir/manifest.json"),
            machine_ir_path=Path("machine-ir/machine-ir.jsonl"),
            manifest={"status": "qualified"},
            units=(),
            machine_ir_sha256="0" * 64,
        )

        self.assertEqual(value.units, ())
        with self.assertRaises(AttributeError):
            value.root = Path("other")  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
