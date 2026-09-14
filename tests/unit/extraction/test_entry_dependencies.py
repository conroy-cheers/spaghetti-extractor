from copy import deepcopy
import unittest

from spaghetti_extractor.machine_ir.definedness import DefinednessAnalysisError
from spaghetti_extractor.machine_ir.entry_dependencies import analyze_entry_state_dependencies
from tests.unit.extraction.test_definedness import _row


def row():
    result = _row(escapes=False)
    result.update(id="entry", reachable=True, flag_writes=[], instruction_effect_schedule=None,
                  edge_conditions=[], outcome={"kind": "terminate"})
    return result


class EntryDependencyTests(unittest.TestCase):
    def analyze(self, rows, *, name="ecx", family="register", **kwargs):
        return analyze_entry_state_dependencies(rows, entry_unit_ids=["entry"],
            locations=[{"family": family, "name": name}], **kwargs)

    def test_overwrite_starts_at_real_unit_and_never_grants_authority(self):
        entry = row();entry["flag_writes"] = [{"flag": "cf", "value": {"op": "false"}}]
        report = self.analyze([entry], family="flag", name="cf")
        self.assertTrue(report["analysis_complete"])
        self.assertFalse(report["authority"])
        self.assertEqual(report["classification"], "requires_semantic_proof")
        self.assertEqual(report["proof_obligations"], [])
        self.assertEqual(len(report["graph"]["nodes"]), 1)
        node = report["graph"]["nodes"][0]
        self.assertEqual(node["transfer_id"], "entry")
        self.assertEqual(node["live_in"], [{"family": "flag", "name": "cf"}])
        self.assertEqual(node["live_out"], [])

    def test_memory_use_is_a_blocker_even_when_register_is_later_overwritten(self):
        entry = row()
        entry["memory_events"] = [{"kind": "write", "address": {"op": "const", "width": 32, "value": 8192},
            "width": 4, "value": {"op": "reg", "name": "ecx", "width": 32}}]
        entry["register_writes"] = [{"register": "ecx", "value": {"op": "const", "width": 32, "value": 0}}]
        report = self.analyze([entry])
        self.assertFalse(report["analysis_complete"])
        self.assertTrue(report["behavior_relevant_sites"])

    def test_call_snapshot_keeps_the_callee_noninterference_obligation(self):
        entry = row()
        entry["register_writes"] = [{"register": "ecx", "value": {"op": "const", "width": 32, "value": 0}}]
        entry["external_events"] = [{"kind": "external_import_call", "arguments": [],
            "register_inputs": {"ecx": {"op": "reg", "name": "ecx", "width": 32}}}]
        report = self.analyze([entry])
        self.assertTrue(report["analysis_complete"])
        self.assertFalse(report["authority"])
        self.assertEqual([item["kind"] for item in report["proof_obligations"]], ["call_frame_noninterference"])

    def test_missing_successor_or_budget_exhaustion_is_incomplete(self):
        entry = row();entry["outcome"] = {"kind": "fallthrough", "target_rva": 4101}
        entry["edge_conditions"] = [{"target_rva": 4101, "condition": {"op": "true"}}]
        report = self.analyze([entry])
        self.assertFalse(report["analysis_complete"])
        successor = deepcopy(entry);successor["id"] = "successor"
        successor["original"] = {"rva_start": 4101, "rva_end": 4102, "size": 1}
        successor["edge_conditions"] = [];successor["outcome"] = {"kind": "terminate"}
        report = self.analyze([entry, successor], max_states=1)
        self.assertIn("state_budget_exceeded", [item["reason_code"] for item in report["blocking_paths"]])

    def test_invalid_inputs_cannot_form_a_query(self):
        baseline = {"entry_unit_ids": ["entry"], "locations": [{"family": "register", "name": "ecx"}]}
        for changes in ({"entry_unit_ids": ["absent"]}, {"entry_unit_ids": ["entry", "entry"]},
                        {"max_states": True}, {"locations": []},
                        {"locations": [{"family": "register", "name": "cl"}]},
                        {"locations": baseline["locations"] * 2}):
            with self.subTest(changes=changes), self.assertRaises(DefinednessAnalysisError):
                analyze_entry_state_dependencies([row()], **{**baseline, **changes})
        with self.assertRaises(DefinednessAnalysisError):
            analyze_entry_state_dependencies([row(), row()], **baseline)

    def test_each_root_retains_its_own_observations(self):
        overwritten = row()
        overwritten["register_writes"] = [
            {"register": "ecx", "value": {"op": "const", "width": 32, "value": 0}}
        ]
        observed = row()
        observed["id"] = "other-entry"
        observed["original"] = {"rva_start": 8192, "rva_end": 8193, "size": 1}
        observed["memory_events"] = [{
            "kind": "write", "address": {"op": "reg", "name": "ecx", "width": 32},
            "width": 1, "value": {"op": "const", "width": 8, "value": 0},
        }]
        report = analyze_entry_state_dependencies(
            [overwritten, observed], entry_unit_ids=["entry", "other-entry"],
            locations=[{"family": "register", "name": "ecx"}],
        )
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(len(report["graph"]["nodes"]), 2)
        self.assertTrue(report["behavior_relevant_sites"])

    def test_incomplete_transfer_cannot_be_reported_as_closed(self):
        entry = row()
        entry["status"] = "incomplete"
        report = self.analyze([entry])
        self.assertFalse(report["analysis_complete"])
        self.assertEqual(report["classification"], "unknown")
        self.assertTrue(report["blocking_paths"])
