from __future__ import annotations

from ._support import *

class OverlappingInstructionStartTests(unittest.TestCase):
    def test_excludes_untargeted_speculative_start_inside_reached_instruction(self) -> None:
        result = classify_overlapping_instruction_starts(
            units=[
                {
                    "id": "rooted",
                    "rva": 0x1000,
                    "instructions": [{
                        "rva_start": 0x1000,
                        "rva_end": 0x1005,
                        "instruction_sha256": "a" * 64,
                    }],
                },
                {"id": "speculative", "rva": 0x1002, "instructions": []},
            ],
            reachable_unit_ids=["rooted"],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            [row["unit_id"] for row in result["excluded_units"]],
            ["speculative"],
        )
        self.assertEqual(result["conflicts"], [])
        self.assertEqual(
            result["excluded_units"][0]["instruction_evidence"][0][
                "instruction_sha256"
            ],
            "a" * 64,
        )

    def test_independently_targeted_inner_start_fails_closed(self) -> None:
        result = classify_overlapping_instruction_starts(
            units=[
                {
                    "id": "rooted",
                    "rva": 0x1000,
                    "instructions": [{
                        "rva_start": 0x1000,
                        "rva_end": 0x1005,
                        "instruction_sha256": "a" * 64,
                    }],
                },
                {"id": "inner", "rva": 0x1002, "instructions": []},
            ],
            reachable_unit_ids=["rooted"],
            target_sources={0x1002: ["direct_control"]},
        )

        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["excluded_units"], [])
        self.assertEqual(result["conflicts"][0]["unit_id"], "inner")
        self.assertEqual(
            result["conflicts"][0]["target_sources"], ["direct_control"]
        )


class SemanticClusterTests(unittest.TestCase):
    def test_loop_scc_and_maximal_chains_stop_at_cutpoints(self) -> None:
        unit_ids = [
            "root",
            "work",
            "call",
            "continuation",
            "callee",
            "loop-a",
            "loop-b",
            "after-loop",
            "chain-a",
            "chain-b",
            "chain-c",
            "indirect",
            "unreachable",
        ]
        result = propose_semantic_clusters(
            units=unit_ids,
            reachable_units=(
                unit_id for unit_id in unit_ids if unit_id != "unreachable"
            ),
            roots=["root", "chain-a", "callee", "indirect"],
            direct_edges=[
                {"source_unit_id": "root", "target_unit_id": "work"},
                {"source_unit_id": "work", "target_unit_id": "call"},
                {"source_unit_id": "call", "target_unit_id": "continuation"},
                {
                    "source_unit_id": "continuation",
                    "target_unit_id": "loop-a",
                },
                {"source_unit_id": "loop-a", "target_unit_id": "loop-b"},
                {"source_unit_id": "loop-b", "target_unit_id": "loop-a"},
                {
                    "source_unit_id": "loop-b",
                    "target_unit_id": "after-loop",
                },
                {"source_unit_id": "chain-a", "target_unit_id": "chain-b"},
                {"source_unit_id": "chain-b", "target_unit_id": "chain-c"},
            ],
            internal_call_edges=[
                {"source_unit_id": "call", "target_unit_id": "callee"}
            ],
            external_exits=[{"source_unit_id": "after-loop"}, "chain-c"],
            fault_exits=[{"source_unit_id": "callee"}],
            indirect_exits=[{"source_unit_id": "indirect"}],
            max_cluster_units=4,
        )

        by_members = {
            tuple(cluster["unit_ids"]): cluster for cluster in result["clusters"]
        }
        self.assertEqual(result["status"], "complete")
        self.assertEqual(by_members[("loop-a", "loop-b")]["kind"], "loop_scc")
        self.assertIn(("root", "work", "call"), by_members)
        self.assertNotIn("continuation", by_members[("root", "work", "call")]["unit_ids"])
        self.assertIn(("chain-a", "chain-b", "chain-c"), by_members)
        self.assertEqual(result["excluded_unit_ids"], ["unreachable"])
        self.assertEqual(
            {(row["source_unit_id"], row["kind"]) for row in result["cutpoints"]},
            {
                ("after-loop", "external"),
                ("call", "call"),
                ("callee", "fault"),
                ("chain-c", "external"),
                ("indirect", "indirect"),
            },
        )

    def test_size_bound_splits_chains_but_not_loop_sccs(self) -> None:
        chain = propose_semantic_clusters(
            units=["a", "b", "c"],
            direct_edges=[
                {"source_unit_id": "a", "target_unit_id": "b"},
                {"source_unit_id": "b", "target_unit_id": "c"},
            ],
            max_cluster_units=2,
        )
        oversized_loop = propose_semantic_clusters(
            units=["a", "b", "c"],
            direct_edges=[
                {"source_unit_id": "a", "target_unit_id": "b"},
                {"source_unit_id": "b", "target_unit_id": "c"},
                {"source_unit_id": "c", "target_unit_id": "a"},
            ],
            max_cluster_units=2,
        )

        self.assertEqual(
            [cluster["unit_ids"] for cluster in chain["clusters"]],
            [["a", "b"], ["c"]],
        )
        self.assertEqual(chain["status"], "complete")
        self.assertEqual(oversized_loop["status"], "incomplete")
        self.assertEqual(oversized_loop["clusters"], [])
        self.assertEqual(oversized_loop["unclustered_unit_ids"], ["a", "b", "c"])
        self.assertEqual(oversized_loop["issues"][0]["code"], "oversized_loop_scc")
