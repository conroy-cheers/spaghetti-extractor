import copy
import unittest

from spaghetti_extractor.relational.analyses.callsite import (
    CALLSITE_PRESERVATION_CERTIFICATE_FORMAT,
    propose_callsite_preserved_register_summary,
)


REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")


def _behavior(outcome):
    return {
        "format": "stage-a-normalized-behavior-v1",
        "registers": {
            register: {"op": "input_reg", "reg": register}
            for register in REGISTERS
        },
        "x87": {},
        "writes": [],
        "flags": None,
        "outcome": outcome,
    }


def _pair(node_id, outcome, candidate_outcome=None):
    return {
        "node_id": node_id,
        "original_ir": _behavior(outcome),
        "candidate_ir": _behavior(candidate_outcome or outcome),
    }


class StageACallsitePreservationTests(unittest.TestCase):
    def setUp(self):
        self.relations = [{
            "original": "esi",
            "candidate": "esi",
            "import": {
                "dll": list(b"kernel32.dll"),
                "name": {
                    "op": "symbol",
                    "bytes": list(b"WideCharToMultiByte"),
                },
            },
        }]
        self.behaviors = [
            _pair(10, {"op": "jump", "target": 11}),
            _pair(11, {
                "op": "branch",
                "condition": {"op": "bool_constant", "value": True},
                "taken": 11,
                "fallthrough": 12,
            }),
            _pair(12, {
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
        ]
        self.control = [
            {"node_id": 10, "successors": [11], "exit": {"kind": "direct"}},
            {
                "node_id": 11,
                "successors": [11, 12],
                "exit": {"kind": "direct"},
            },
            {"node_id": 12, "successors": [], "exit": {"kind": "return"}},
        ]

    def _analyze(self, **overrides):
        arguments = {
            "callsite_id": 1,
            "callee_entry": 10,
            "return_inventory": [{
                "return_node_id": 12,
                "continuation_id": 100,
            }],
            "requested_relations": self.relations,
            "behaviors": self.behaviors,
            "control": self.control,
        }
        arguments.update(overrides)
        return propose_callsite_preserved_register_summary(**arguments)

    def assertIncomplete(self, analysis, reason):
        self.assertEqual(analysis["status"], "incomplete", analysis)
        self.assertIsNone(analysis["certificate"])
        self.assertIn(reason, analysis["reason_codes"])

    def test_real_loop_shared_by_two_callers_gets_distinct_closed_summaries(self):
        first = self._analyze()
        second = self._analyze(
            callsite_id=2,
            return_inventory=[{
                "return_node_id": 12,
                "continuation_id": 200,
            }],
        )

        self.assertEqual(first["status"], "satisfied", first)
        self.assertEqual(second["status"], "satisfied", second)
        self.assertEqual(
            first["certificate"]["format"],
            CALLSITE_PRESERVATION_CERTIFICATE_FORMAT,
        )
        self.assertEqual(first["certificate"]["reachable_node_ids"], [10, 11, 12])
        self.assertEqual(first["certificate"]["cyclic_node_ids"], [11])
        self.assertEqual(
            first["certificate"]["return_inventory"][0]["continuation_id"],
            100,
        )
        self.assertEqual(
            second["certificate"]["return_inventory"][0]["continuation_id"],
            200,
        )
        self.assertNotEqual(
            first["certificate"]["id"],
            second["certificate"]["id"],
        )
        self.assertNotEqual(
            first["certificate"]["certificate_hash"],
            second["certificate"]["certificate_hash"],
        )
        reordered = self._analyze(
            behaviors=list(reversed(self.behaviors)),
            control=list(reversed(self.control)),
        )
        self.assertEqual(reordered["certificate"], first["certificate"])

    def test_clobbered_requested_register_fails_closed(self):
        behaviors = copy.deepcopy(self.behaviors)
        behaviors[1]["candidate_ir"]["registers"]["esi"] = {
            "op": "constant", "value": 0,
        }

        self.assertIncomplete(
            self._analyze(behaviors=behaviors),
            "register_clobbered",
        )

    def test_unresolved_indirect_control_fails_closed(self):
        behaviors = copy.deepcopy(self.behaviors)
        behaviors[1]["original_ir"]["outcome"] = {
            "op": "indirect_jump",
            "target": {"op": "input_reg", "reg": "eax"},
        }
        behaviors[1]["candidate_ir"]["outcome"] = copy.deepcopy(
            behaviors[1]["original_ir"]["outcome"]
        )
        control = copy.deepcopy(self.control)
        control[1] = {
            "node_id": 11,
            "successors": [],
            "exit": {"kind": "unresolved_indirect"},
        }

        self.assertIncomplete(
            self._analyze(behaviors=behaviors, control=control),
            "unresolved_indirect_control",
        )

    def test_mismatched_return_fails_closed(self):
        behaviors = copy.deepcopy(self.behaviors)
        behaviors[2]["candidate_ir"]["outcome"] = {
            "op": "jump", "target": 12,
        }

        self.assertIncomplete(
            self._analyze(behaviors=behaviors),
            "mismatched_return",
        )

    def test_missing_nested_summary_fails_closed(self):
        behaviors = [
            _pair(10, {"op": "jump", "target": 11}),
            _pair(11, {"op": "call", "target": 20, "continuation": 12}),
            self.behaviors[2],
        ]
        control = [
            self.control[0],
            {
                "node_id": 11,
                "successors": [12],
                "exit": {"kind": "nested_call", "summary_id": "nested"},
            },
            self.control[2],
        ]

        self.assertIncomplete(
            self._analyze(behaviors=behaviors, control=control),
            "nested_summary_missing",
        )

    def test_mismatched_nested_target_fails_closed(self):
        behaviors = [
            _pair(10, {"op": "jump", "target": 11}),
            _pair(
                11,
                {"op": "call", "target": 20, "continuation": 12},
                {"op": "call", "target": 30, "continuation": 12},
            ),
            self.behaviors[2],
        ]
        control = [
            self.control[0],
            {
                "node_id": 11,
                "successors": [12],
                "exit": {"kind": "nested_call", "summary_id": "nested"},
            },
            self.control[2],
        ]

        self.assertIncomplete(
            self._analyze(behaviors=behaviors, control=control),
            "paired_nested_target_mismatch",
        )

    def test_checked_nested_summary_preserves_the_requested_relation(self):
        nested_behaviors = [
            _pair(20, {"op": "jump", "target": 21}),
            _pair(21, {
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
        ]
        nested_control = [
            {"node_id": 20, "successors": [21], "exit": {"kind": "direct"}},
            {"node_id": 21, "successors": [], "exit": {"kind": "return"}},
        ]
        nested = propose_callsite_preserved_register_summary(
            callsite_id=11,
            callee_entry=20,
            return_inventory=[{
                "return_node_id": 21,
                "continuation_id": 12,
            }],
            requested_relations=self.relations,
            behaviors=nested_behaviors,
            control=nested_control,
        )
        self.assertEqual(nested["status"], "satisfied", nested)
        behaviors = [
            _pair(10, {"op": "jump", "target": 11}),
            _pair(11, {"op": "call", "target": 20, "continuation": 12}),
            self.behaviors[2],
            *nested_behaviors,
        ]
        control = [
            self.control[0],
            {
                "node_id": 11,
                "successors": [12],
                "exit": {
                    "kind": "nested_call",
                    "summary_id": nested["certificate"]["id"],
                },
            },
            self.control[2],
            *nested_control,
        ]

        analysis = self._analyze(
            behaviors=behaviors,
            control=control,
            nested_summaries=[nested],
        )

        self.assertEqual(analysis["status"], "satisfied", analysis)
        self.assertEqual(
            analysis["certificate"]["nested_dependencies"],
            [{
                "node_id": 11,
                "summary_id": nested["certificate"]["id"],
                "certificate_hash": nested["certificate"]["certificate_hash"],
            }],
        )

    def test_duplicates_ambiguity_and_budget_overflow_have_stable_codes(self):
        duplicate_successor = copy.deepcopy(self.control)
        duplicate_successor[0]["successors"] = [11, 11]
        self.assertIncomplete(
            self._analyze(control=duplicate_successor),
            "successor_duplicate",
        )
        ambiguous_relations = [
            *self.relations,
            {
                "original": "esi",
                "candidate": "edi",
                "import": {"dll": [1], "name": {"op": "ordinal", "value": 1}},
            },
        ]
        self.assertIncomplete(
            self._analyze(requested_relations=ambiguous_relations),
            "requested_relation_ambiguous",
        )
        self.assertIncomplete(
            self._analyze(max_nodes=2),
            "node_budget_overflow",
        )

    def test_missing_reachable_node_fails_closed(self):
        behaviors = copy.deepcopy(self.behaviors)
        behaviors[0]["original_ir"]["outcome"] = {"op": "jump", "target": 99}
        behaviors[0]["candidate_ir"]["outcome"] = {"op": "jump", "target": 99}
        control = copy.deepcopy(self.control)
        control[0]["successors"] = [99]

        self.assertIncomplete(
            self._analyze(behaviors=behaviors, control=control),
            "successor_node_missing",
        )

    def test_cycle_without_a_path_to_a_matched_return_fails_closed(self):
        behaviors = copy.deepcopy(self.behaviors)
        behaviors[1]["original_ir"]["outcome"] = {"op": "jump", "target": 11}
        behaviors[1]["candidate_ir"]["outcome"] = {"op": "jump", "target": 11}
        control = copy.deepcopy(self.control)
        control[1]["successors"] = [11]

        self.assertIncomplete(
            self._analyze(behaviors=behaviors, control=control),
            "cycle_without_return_closure",
        )


if __name__ == "__main__":
    unittest.main()
