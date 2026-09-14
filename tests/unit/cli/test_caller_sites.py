"""Public navigation to caller sites retains input and uncertainty boundaries."""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.cli import main
from spaghetti_extractor.machine_ir.call_sites import direct_caller_sites
from spaghetti_extractor.machine_ir.definedness import DefinednessAnalysisError
from spaghetti_extractor.testkit.transfer_fixture import as_machine_ir_unit, transfer_row

TESTKIT = {"commands": ("expert semantic-diagnose",)}


def _row(identity, start, *, target=None, indirect=False):
    row = transfer_row()
    row.update(id=identity, original={"rva_start": start, "rva_end": start + 6, "size": 6},
               memory_events=[], external_events=[], faults=[], edge_conditions=[],
               outcome={"kind": "terminate"})
    if target is not None or indirect:
        row["external_events"] = [{
            "kind": "indirect_call" if indirect else "internal_call",
            "instruction_rva": start + 1, "target_rva": target,
            "return_rva": start + 6,
            "register_inputs": {"esi": {"op": "reg", "name": "esi", "width": 32}},
            "flag_inputs": {}, "stack_inputs": [],
        }]
    return row


class CallerSiteTests(unittest.TestCase):
    def setUp(self):
        self.rows = [_row("callee", 0x2000), _row("second", 0x4000),
                     _row("caller", 0x1000, target=0x2000),
                     _row("another", 0x3000, target=0x2000),
                     _row("indirect", 0x5000, indirect=True)]

    def test_direct_inventory_preserves_inputs_and_does_not_claim_caller_closure(self):
        self.rows[2]["reachable"] = False
        self.rows[2]["status"] = "incomplete"
        report = direct_caller_sites(self.rows, entry_unit_ids=["second", "callee"])
        self.assertFalse(report["authority"])
        self.assertTrue(report["analysis_complete"])
        self.assertFalse(report["caller_set_complete"])
        self.assertEqual(report["unresolved_indirect_site_count"], 1)
        self.assertEqual(report["total_direct_sites"], 2)
        self.assertEqual([site["instruction_rva"] for site in report["sites"]], [0x1001, 0x3001])
        site = report["sites"][0]
        self.assertEqual(site["caller_transfer_status"], "incomplete")
        self.assertEqual(site["input_expressions"]["register_inputs"]["esi"],
                         {"op": "reg", "name": "esi", "width": 32})
        self.assertEqual(site["source_span"]["rva_start"], 0x1000)
        self.assertEqual(site["json_pointer"], "/external_events/0")
        self.assertEqual(len(site["caller_transfer_sha256"]), 64)
        self.assertEqual(report, direct_caller_sites(list(reversed(self.rows)),
                                                    entry_unit_ids=["callee", "second"]))
        changed = copy.deepcopy(self.rows)
        changed[2]["external_events"][0]["register_inputs"]["esi"]["name"] = "ebx"
        new = direct_caller_sites(changed, entry_unit_ids=["callee", "second"])
        for key in ("semantic_transfers_sha256",):
            self.assertNotEqual(new[key], report[key])
        for key in ("caller_transfer_sha256", "call_sha256"):
            self.assertNotEqual(new["sites"][0][key], site[key])

    def test_truncation_and_empty_results_remain_explicit(self):
        report = direct_caller_sites(self.rows, entry_unit_ids=["callee"], max_sites=1)
        self.assertFalse(report["analysis_complete"])
        self.assertTrue(report["truncated"])
        self.assertEqual(report["total_direct_sites"], 2)
        self.assertEqual(len(report["sites"]), 1)
        empty = direct_caller_sites(self.rows, entry_unit_ids=["second"])
        self.assertTrue(empty["analysis_complete"])
        self.assertEqual(empty["sites"], [])
        self.assertFalse(empty["caller_set_complete"])
        self.assertFalse(empty["policy"]["tail_branches_included"])

    def test_ambiguous_and_malformed_inputs_are_not_silently_dropped(self):
        cases = [(self.rows, ["absent"], 64), (self.rows, ["callee", "callee"], 64),
                 (self.rows + [self.rows[0]], ["callee"], 64),
                 (self.rows + [_row("alias", 0x2000)], ["callee"], 64)]
        for limit in (0, -1, True, 4097):
            cases.append((self.rows, ["callee"], limit))
        for field, value in (("target_rva", None), ("target_rva", True),
                             ("instruction_rva", 0x1006)):
            rows = copy.deepcopy(self.rows)
            rows[2]["external_events"][0][field] = value
            cases.append((rows, ["callee"], 64))
        rows = copy.deepcopy(self.rows)
        rows[2]["external_events"] = {}
        cases.append((rows, ["callee"], 64))
        rows = copy.deepcopy(self.rows)
        rows[2]["original"]["rva_end"] = "invalid"
        cases.append((rows, ["callee"], 64))
        for rows, roots, limit in cases:
            with self.subTest(roots=roots, limit=limit), self.assertRaises(DefinednessAnalysisError):
                direct_caller_sites(rows, entry_unit_ids=roots, max_sites=limit)
        ambiguous = direct_caller_sites(self.rows + [_row("overlap", 0x1000, target=0x2000)],
                                        entry_unit_ids=["callee"])
        self.assertEqual(sum(site["caller_rva_ambiguous"] for site in ambiguous["sites"]), 2)

    def test_public_command_uses_retained_machine_ir(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "machine-ir.jsonl"
            path.write_text("\n".join(json.dumps(as_machine_ir_unit(row)) for row in self.rows) + "\n")
            command = ["expert", "semantic-diagnose", "--view", "callers",
                       "--machine-ir", str(path), "--entry-unit", "callee"]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(command), 0)
            report = json.loads(output.getvalue())
            self.assertFalse(report["authority"])
            self.assertEqual(report["total_direct_sites"], 2)
            self.assertEqual(len(report["machine_ir_sha256"]), 64)
            self.assertEqual(report["sites"][0]["machine_ir_location"], {
                "file": str(path.resolve()), "line": 3,
                "json_pointer": "/semantics/external_events/0"})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(command + ["--max-sites", "1"]), 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(command + ["--entry-unit", "absent"]), 2)
                self.assertEqual(main(command + ["--max-sites", "0"]), 2)
                self.assertEqual(main(command + ["--register", "esi"]), 2)
                path.write_text("[]\n")
                self.assertEqual(main(command), 2)
