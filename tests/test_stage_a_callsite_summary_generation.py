import copy
import unittest

from spaghetti_extractor.relational.analyses.registers import (
    _infer_import_register_invariants,
    _propose_internal_callsite_preservation_summaries,
)
from spaghetti_extractor.relational.callsite_preservation import (
    callsite_preservation_artifact_hash,
    parse_callsite_preservation_artifact,
    serialize_callsite_preservation_artifact,
)


REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
IMPORT = {
    "dll": "kernel32.dll",
    "symbol": "WideCharToMultiByte",
}


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


def _pair(outcome):
    behavior = _behavior(outcome)
    return {
        "original_ir": behavior,
        "candidate_ir": copy.deepcopy(behavior),
    }


def _summary(callsite, callee, continuation, returns, *, closed=True):
    return {
        "callsite_region_index": callsite,
        "callee_region_index": callee,
        "continuation_region_index": continuation,
        "return_region_indices": returns,
        "closed": closed,
    }


class StageACallsiteSummaryGenerationTests(unittest.TestCase):
    def setUp(self):
        self.contract = {
            "regions": [
                {"numeric_id": 100},
                {"numeric_id": 200},
                {"numeric_id": 300},
                {"numeric_id": 400},
                {"numeric_id": 500},
                {"numeric_id": 600},
            ],
        }
        self.behaviors = [
            _pair({"op": "call", "target": 300, "continuation": 200}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
            _pair({"op": "jump", "target": 400}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
            _pair({"op": "call", "target": 300, "continuation": 600}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
        ]
        self.import_analysis = {
            "relations": [
                {
                    "region_index": callsite,
                    "original_register": "esi",
                    "candidate_register": "esi",
                    "import": IMPORT,
                }
                for callsite in (0, 4)
            ],
        }
        self.register_relations = {
            "return_slot_analysis": {
                "call_summary_analysis": {
                    "summaries": [
                        _summary(0, 2, 1, [3]),
                        _summary(4, 2, 5, [3]),
                    ],
                },
            },
        }

    def _generate(self, **overrides):
        arguments = {
            "contract": self.contract,
            "behaviors": self.behaviors,
            "import_register_analysis": self.import_analysis,
            "register_relations": self.register_relations,
        }
        arguments.update(overrides)
        return _propose_internal_callsite_preservation_summaries(**arguments)

    def test_shared_callee_produces_distinct_deterministic_summary_edges(self):
        analysis = self._generate()

        self.assertEqual(analysis["counts"]["satisfied"], 2, analysis)
        self.assertEqual(
            [
                (edge["source_region_index"], edge["target_region_index"])
                for edge in analysis["proposal_edges"]
            ],
            [(0, 1), (4, 5)],
        )
        certificates = [
            row["analysis"]["certificate"] for row in analysis["summaries"]
        ]
        self.assertEqual(
            [certificate["callee_entry"] for certificate in certificates],
            [2, 2],
        )
        self.assertEqual(
            [certificate["return_inventory"] for certificate in certificates],
            [
                [{"return_node_id": 3, "continuation_id": 1}],
                [{"return_node_id": 3, "continuation_id": 5}],
            ],
        )
        self.assertNotEqual(certificates[0]["id"], certificates[1]["id"])

        reordered_relations = copy.deepcopy(self.register_relations)
        reordered_relations["return_slot_analysis"]["call_summary_analysis"][
            "summaries"
        ].reverse()
        self.assertEqual(
            analysis,
            self._generate(register_relations=reordered_relations),
        )

    def test_relation_input_order_keeps_cache_keys_and_hashes_stable(self):
        import_analysis = copy.deepcopy(self.import_analysis)
        import_analysis["relations"].extend({
            "region_index": callsite,
            "original_register": "ebx",
            "candidate_register": "ebx",
            "import": IMPORT,
        } for callsite in (0, 4))

        first = self._generate(import_register_analysis=import_analysis)
        import_analysis["relations"].reverse()
        second = self._generate(import_register_analysis=import_analysis)

        self.assertEqual(first, second)
        self.assertEqual(
            [row["certificate_hash"] for row in first["certificates"]],
            [row["certificate_hash"] for row in second["certificates"]],
        )
        parsed = parse_callsite_preservation_artifact(first, region_count=6)
        self.assertEqual(
            callsite_preservation_artifact_hash(first, region_count=6),
            callsite_preservation_artifact_hash(parsed),
        )
        self.assertEqual(
            serialize_callsite_preservation_artifact(parsed),
            first,
        )

    def test_satisfied_edges_are_relation_scoped_untrusted_proposals(self):
        generated = self._generate()
        seeds = [
            {
                "region_index": callsite,
                "original_register": "esi",
                "candidate_register": "esi",
                "import": IMPORT,
            }
            for callsite in (0, 4)
        ]

        inferred = _infer_import_register_invariants(
            self.contract,
            self.behaviors,
            seeds,
            callsite_summary_predecessors=generated["proposal_edges"],
        )

        continuation_rows = [
            row for row in inferred["relations"]
            if row["region_index"] in {1, 5}
        ]
        self.assertEqual(
            [row["region_index"] for row in continuation_rows], [1, 5]
        )
        self.assertTrue(all(
            row["incoming_edges"][0]["kind"]
                == "internal_callsite_preservation_summary"
            and row["incoming_edges"][0]["proposal_only"] is True
            for row in continuation_rows
        ))
        self.assertEqual(
            inferred["counts"]["callsite_summary_predecessors"], 2
        )

    def test_clobbered_register_does_not_emit_a_summary_edge(self):
        behaviors = copy.deepcopy(self.behaviors)
        behaviors[2]["candidate_ir"]["registers"]["esi"] = {
            "op": "constant", "value": 0,
        }

        analysis = self._generate(behaviors=behaviors)

        self.assertEqual(analysis["counts"]["incomplete"], 2)
        self.assertEqual(analysis["proposal_edges"], [])
        self.assertTrue(all(
            "register_clobbered" in row["reason_codes"]
            for row in analysis["summaries"]
        ))

    def test_unresolved_control_does_not_emit_a_summary_edge(self):
        behaviors = copy.deepcopy(self.behaviors)
        unresolved = {
            "op": "indirect_jump",
            "target": {"op": "input_reg", "reg": "eax"},
        }
        behaviors[2]["original_ir"]["outcome"] = unresolved
        behaviors[2]["candidate_ir"]["outcome"] = copy.deepcopy(unresolved)

        analysis = self._generate(behaviors=behaviors)

        self.assertEqual(analysis["proposal_edges"], [])
        self.assertTrue(all(
            "unresolved_indirect_control" in row["reason_codes"]
            for row in analysis["summaries"]
        ))

    def test_nested_internal_call_is_supplied_recursively(self):
        contract = {
            "regions": [
                {"numeric_id": 10},
                {"numeric_id": 20},
                {"numeric_id": 30},
                {"numeric_id": 40},
                {"numeric_id": 50},
            ],
        }
        behaviors = [
            _pair({"op": "call", "target": 30, "continuation": 20}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
            _pair({"op": "call", "target": 50, "continuation": 40}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
        ]
        import_analysis = {
            "relations": [{
                "region_index": 0,
                "original_register": "esi",
                "candidate_register": "esi",
                "import": IMPORT,
            }],
        }
        register_relations = {
            "return_slot_analysis": {
                "call_summary_analysis": {
                    "summaries": [
                        _summary(0, 2, 1, [3]),
                        _summary(2, 4, 3, [4]),
                    ],
                },
            },
        }

        analysis = _propose_internal_callsite_preservation_summaries(
            contract, behaviors, import_analysis, register_relations
        )

        outer = analysis["summaries"][0]["analysis"]
        self.assertEqual(outer["status"], "satisfied", outer)
        self.assertEqual(
            outer["certificate"]["nested_dependencies"][0]["node_id"], 2
        )
        self.assertEqual(analysis["counts"]["proposal_edges"], 1)
        self.assertEqual(analysis["counts"]["certificates"], 2)
        self.assertEqual(analysis["summaries"][1]["status"], "not_applicable")

    def test_recursive_nested_summary_dependency_fails_closed(self):
        contract = {
            "regions": [
                {"numeric_id": 10},
                {"numeric_id": 20},
                {"numeric_id": 30},
                {"numeric_id": 40},
            ],
        }
        behaviors = [
            _pair({"op": "call", "target": 30, "continuation": 20}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
            _pair({"op": "call", "target": 30, "continuation": 40}),
            _pair({
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            }),
        ]
        import_analysis = {
            "relations": [{
                "region_index": callsite,
                "original_register": "esi",
                "candidate_register": "esi",
                "import": IMPORT,
            } for callsite in (0, 2)],
        }
        register_relations = {
            "return_slot_analysis": {
                "call_summary_analysis": {
                    "summaries": [
                        _summary(0, 2, 1, [3]),
                        _summary(2, 2, 3, [3]),
                    ],
                },
            },
        }

        analysis = _propose_internal_callsite_preservation_summaries(
            contract, behaviors, import_analysis, register_relations
        )

        self.assertEqual(analysis["proposal_edges"], [])
        self.assertTrue(any(
            "recursive_callsite_summary_dependency"
                in issue.get("nested_reason_codes", [])
            for row in analysis["summaries"]
            for issue in (row["analysis"] or {}).get("issues", [])
        ))


if __name__ == "__main__":
    unittest.main()
