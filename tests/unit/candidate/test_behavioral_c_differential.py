from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit as _test_machine_ir_unit,
    transfer_row as _row,
    write_fixture_transfer_plan as _write_transfer_plan,
)

from spaghetti_extractor.candidate.behavioral_c import (
    write_spx_behavioral_c_package,
)
from spaghetti_extractor.candidate.behavioral_c_differential import (
    run_behavioral_c_differential,
)
class BehavioralCDifferentialTests(unittest.TestCase):
    def test_behavioral_c_matches_host_evaluator(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = _row()
            row["outcome"] = {
                "kind": "return",
                "value": {"op": "reg", "name": "eax", "width": 32},
            }
            machine = root / "machine-ir.jsonl"
            machine.write_text(
                json.dumps(_test_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            transfer = _write_transfer_plan(machine)
            behavioral = root / "behavioral"
            write_spx_behavioral_c_package(
                transfer_plan=transfer, out=behavioral,
            )
            receipt = run_behavioral_c_differential(
                transfer_plan=transfer,
                behavioral_c_package=behavioral,
                compiler=Path(compiler),
                out=root / "receipt",
            )

        self.assertEqual(receipt["status"], "match")
        self.assertEqual(receipt["mismatches"], [])
        self.assertEqual(
            set(receipt["backends"]),
            {"behavioral_c"},
        )
        self.assertEqual(len(receipt["case_ids"]), 4)


if __name__ == "__main__":
    unittest.main()
