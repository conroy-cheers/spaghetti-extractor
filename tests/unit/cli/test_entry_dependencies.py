"""Retained machine IR can be queried without realizing a target or provider."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.cli import main
from spaghetti_extractor.testkit.transfer_fixture import as_machine_ir_unit, transfer_row

TESTKIT = {"commands": ("expert semantic-diagnose",)}


class EntryDependencyCommandTests(unittest.TestCase):
    def test_real_input_and_invalid_queries_through_public_command(self):
        row = transfer_row()
        row.update(memory_events=[], external_events=[], faults=[], edge_conditions=[])
        row["flag_writes"] = [{"flag": "cf", "value": {"op": "false"}}]
        row["outcome"] = {"kind": "terminate"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "machine-ir.jsonl"
            path.write_text(json.dumps(as_machine_ir_unit(row)) + "\n")
            command = ["expert", "semantic-diagnose", "--view", "entry-dependencies",
                       "--machine-ir", str(path), "--entry-unit", row["id"], "--flag", "cf"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(command), 0)
            report = json.loads(output.getvalue())
            self.assertFalse(report["authority"])
            self.assertTrue(report["analysis_complete"])
            self.assertEqual(report["classification"], "requires_semantic_proof")
            self.assertEqual(len(report["machine_ir_sha256"]), 64)
            row["outcome"] = {"kind": "fallthrough", "target_rva": 0x1003}
            path.write_text(json.dumps(as_machine_ir_unit(row)) + "\n")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(command), 1)
            self.assertFalse(json.loads(output.getvalue())["analysis_complete"])
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(command + ["--max-states", "0"]), 2)
                self.assertEqual(main(command + ["--entry-unit", "absent"]), 2)
                path.write_text("[]\n")
                self.assertEqual(main(command), 2)
