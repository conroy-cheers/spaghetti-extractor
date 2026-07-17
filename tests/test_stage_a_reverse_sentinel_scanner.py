from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.analyses.control import (
    _attach_reverse_sentinel_table_source_invariants,
    _split_reverse_sentinel_scanner_cluster_evidence,
)
from spaghetti_extractor.relational.analyses.segments import (
    _register_zero_guard_contradiction_claim,
    _reverse_sentinel_scanner_claims_by_edge,
    _reverse_sentinel_scanner_guard_claim,
    _segment_refinement_candidates,
)
from spaghetti_extractor.relational.lean.segments import (
    _write_relational_segment_refinement_modules,
)


class StageAReverseSentinelScannerTests(unittest.TestCase):
    ORIGINAL_BASE = 0x402000
    CANDIDATE_BASE = 0x403000

    @staticmethod
    def _input(register: str) -> dict[str, Any]:
        return {"op": "input_reg", "reg": register}

    @staticmethod
    def _constant(value: int) -> dict[str, Any]:
        return {"op": "constant", "value": value}

    @classmethod
    def _side_body(cls, base: int) -> dict[str, Any]:
        next_index = {
            "op": "add",
            "left": cls._input("ecx"),
            "right": cls._constant(1),
        }
        loaded = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": next_index,
                    "amount": 2,
                },
                "right": cls._constant(base),
            },
        }
        return {
            "registers": {
                "eax": cls._input("ecx"),
                "ecx": next_index,
                "edx": loaded,
            },
            "flags": {
                "zero": {
                    "op": "equal",
                    "left": loaded,
                    "right": cls._constant(0),
                },
            },
            "writes": [],
            "outcome": {"op": "jump", "target": 6},
        }

    @classmethod
    def _fixture(cls) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        regions = [
            {"id": f"region-{index}", "numeric_id": index, "function_id": "f"}
            for index in range(10)
        ]
        behaviors = [
            {
                "original_ir": {"writes": [], "outcome": {"op": "returned"}},
                "candidate_ir": {"writes": [], "outcome": {"op": "returned"}},
            }
            for _ in regions
        ]
        behaviors[2] = {
            "original_ir": {"writes": [], "outcome": {"op": "jump", "target": 3}},
            "candidate_ir": {"writes": [], "outcome": {"op": "jump", "target": 3}},
        }
        header_branch = {
            "writes": [],
            "outcome": {
                "op": "branch",
                "condition": {"op": "input_flag", "index": 6},
                "taken": 4,
                "fallthrough": 8,
            },
        }
        behaviors[3] = {
            "original_ir": copy.deepcopy(header_branch),
            "candidate_ir": copy.deepcopy(header_branch),
        }
        behaviors[4] = {
            "original_ir": {
                "registers": {"ecx": cls._constant(0)},
                "writes": [],
                "outcome": {"op": "jump", "target": 5},
            },
            "candidate_ir": {
                "registers": {"ecx": cls._constant(0)},
                "writes": [],
                "outcome": {"op": "jump", "target": 5},
            },
        }
        behaviors[5] = {
            "original_ir": cls._side_body(cls.ORIGINAL_BASE),
            "candidate_ir": cls._side_body(cls.CANDIDATE_BASE),
        }
        test = {
            "writes": [],
            "outcome": {
                "op": "branch",
                "condition": {
                    "op": "not",
                    "value": {"op": "input_flag", "index": 6},
                },
                "taken": 5,
                "fallthrough": 7,
            },
        }
        behaviors[6] = {
            "original_ir": copy.deepcopy(test),
            "candidate_ir": copy.deepcopy(test),
        }
        behaviors[7] = {
            "original_ir": {"writes": [], "outcome": {"op": "jump", "target": 8}},
            "candidate_ir": {"writes": [], "outcome": {"op": "jump", "target": 8}},
        }
        return {"regions": regions}, behaviors

    def _cluster(self) -> dict[str, Any] | None:
        contract, behaviors = self._fixture()
        return _split_reverse_sentinel_scanner_cluster_evidence(
            contract,
            behaviors,
            header_producer_region_index=2,
            gate_region_index=8,
            initializer_region_index=4,
            scanner_region_index=5,
            test_region_index=6,
            original_count_register="eax",
            candidate_count_register="eax",
            original_scanner_register="ecx",
            candidate_scanner_register="ecx",
            original_loaded_register="edx",
            candidate_loaded_register="edx",
            original_base=self.ORIGINAL_BASE,
            candidate_base=self.CANDIDATE_BASE,
        )

    def test_split_scanner_requires_connected_exact_dataflow(self) -> None:
        cluster = self._cluster()
        self.assertIsNotNone(cluster)
        assert cluster is not None
        self.assertEqual(cluster["header_branch_region_index"], 3)
        self.assertEqual(cluster["bridge_region_index"], 7)
        self.assertEqual(cluster["zero_flag_bit"], 6)

    def test_unrelated_branch_flag_fails_closed(self) -> None:
        contract, behaviors = self._fixture()
        behaviors[6]["candidate_ir"]["outcome"]["condition"]["value"]["index"] = 0
        cluster = _split_reverse_sentinel_scanner_cluster_evidence(
            contract, behaviors, 2, 8, 4, 5, 6,
            "eax", "eax", "ecx", "ecx", "edx", "edx",
            self.ORIGINAL_BASE, self.CANDIDATE_BASE,
        )
        self.assertIsNone(cluster)

    def test_disconnected_header_producer_fails_closed(self) -> None:
        contract, behaviors = self._fixture()
        behaviors[2]["candidate_ir"]["outcome"]["target"] = 9
        cluster = _split_reverse_sentinel_scanner_cluster_evidence(
            contract, behaviors, 2, 8, 4, 5, 6,
            "eax", "eax", "ecx", "ecx", "edx", "edx",
            self.ORIGINAL_BASE, self.CANDIDATE_BASE,
        )
        self.assertIsNone(cluster)

    def test_scanner_invariants_are_attached_without_acceptance_authority(self) -> None:
        contract, _ = self._fixture()
        cluster = self._cluster()
        assert cluster is not None
        proposal = {
            "profile": "immutable_code_pointer_table_call_v1",
            "shape": "direct_indexed_table_read",
            "source_region_index": 0,
            "original_index_expression": self._input("eax"),
            "candidate_index_expression": self._input("eax"),
            "ranges": [{"row_count": 2}],
            "index_evidence": {
                "kind": "paired_sentinel_terminated_reverse_count",
                "scanner_cluster": cluster,
            },
        }
        refined = _attach_reverse_sentinel_table_source_invariants(contract, [proposal])
        self.assertEqual(refined["regions"][5]["bounds"][0]["unsigned_lt"], 2)
        post = refined["regions"][6]["state_predicates"][0]
        self.assertEqual(post["source"], "generated_reverse_sentinel_scanner_post_state")
        self.assertEqual(
            post["original"]["right"]["left"]["value"]["op"], "xor"
        )
        self.assertEqual(
            refined["regions"][7]["state_predicates"],
            refined["regions"][8]["state_predicates"],
        )
        self.assertNotIn("acceptance_authority", post)

    def test_sentinel_only_table_uses_explicit_uninhabited_call_state(self) -> None:
        contract, _ = self._fixture()
        cluster = self._cluster()
        assert cluster is not None
        proposal = {
            "profile": "immutable_code_pointer_table_call_v1",
            "shape": "direct_indexed_table_read",
            "source_region_index": 0,
            "original_index_expression": self._input("eax"),
            "candidate_index_expression": self._input("eax"),
            "ranges": [{"row_count": 1}],
            "index_evidence": {
                "kind": "paired_sentinel_terminated_reverse_count",
                "scanner_cluster": cluster,
            },
        }

        refined = _attach_reverse_sentinel_table_source_invariants(
            contract, [proposal]
        )
        self.assertNotIn("bounds", refined["regions"][0])
        self.assertEqual(
            refined["regions"][0]["state_predicates"],
            [{
                "original": {"op": "bool_constant", "value": False},
                "candidate": {"op": "bool_constant", "value": False},
                "source": "generated_uninhabited_control_state",
            }],
        )
        self.assertEqual(refined["regions"][5]["bounds"][0]["unsigned_lt"], 1)
        self.assertEqual(
            refined["regions"][7]["state_predicates"][0]["original"]["right"],
            {"op": "constant", "value": 0},
        )
        self.assertEqual(
            refined["regions"][8]["state_predicates"],
            refined["regions"][7]["state_predicates"],
        )

    def test_zero_guard_contradiction_requires_checked_source_and_bottom_target(
        self,
    ) -> None:
        zero = {
            "original": {
                "op": "equal",
                "left": self._input("ebx"),
                "right": self._constant(0),
            },
            "candidate": {
                "op": "equal",
                "left": self._input("ecx"),
                "right": self._constant(0),
            },
        }
        def guard(register: str) -> dict[str, Any]:
            return {
                "op": "not",
                "value": {
                    "op": "equal",
                    "left": {
                        "op": "bit_and",
                        "left": self._input(register),
                        "right": self._input(register),
                    },
                    "right": self._constant(0),
                },
            }
        bottom = {
            "original": {"op": "bool_constant", "value": False},
            "candidate": {"op": "bool_constant", "value": False},
            "source": "generated_uninhabited_control_state",
        }
        source = {"state_predicates": [zero]}
        target = {"state_predicates": [bottom]}

        self.assertEqual(
            _register_zero_guard_contradiction_claim(
                source, target, guard("ebx"), guard("ecx")
            ),
            {
                "profile": "register_zero_guard_contradiction_v1",
                "original_register": "ebx",
                "candidate_register": "ecx",
            },
        )
        self.assertIsNone(
            _register_zero_guard_contradiction_claim(
                {}, target, guard("ebx"), guard("ecx")
            )
        )
        self.assertIsNone(
            _register_zero_guard_contradiction_claim(
                source, {}, guard("ebx"), guard("ecx")
            )
        )
        self.assertIsNone(
            _register_zero_guard_contradiction_claim(
                source, target, {"op": "bool_constant", "value": True},
                guard("ecx")
            )
        )

    def test_scanner_guard_claim_requires_the_exact_loop_or_exit_guard(self) -> None:
        claim = {"zero_flag_bit": 6}
        loop_guard = {
            "op": "not",
            "value": {"op": "input_flag", "index": 6},
        }
        exit_guard = {"op": "not", "value": loop_guard}

        self.assertEqual(
            _reverse_sentinel_scanner_guard_claim(
                "loop", claim, loop_guard, loop_guard
            ),
            {
                "profile": "reverse_sentinel_scanner_guard_v1",
                "role": "loop",
            },
        )
        self.assertEqual(
            _reverse_sentinel_scanner_guard_claim(
                "exit", claim, exit_guard, exit_guard
            ),
            {
                "profile": "reverse_sentinel_scanner_guard_v1",
                "role": "exit",
            },
        )
        self.assertIsNone(
            _reverse_sentinel_scanner_guard_claim(
                "loop", claim, loop_guard, exit_guard
            )
        )
        self.assertIsNone(
            _reverse_sentinel_scanner_guard_claim(
                "loop", {"zero_flag_bit": 0}, loop_guard, loop_guard
            )
        )

    def test_canonical_table_input_produces_exact_scanner_edge_claim(self) -> None:
        contract, _ = self._fixture()
        for index, region in enumerate(contract["regions"]):
            region["original"] = {"rva_start": 0x1000 + index * 0x10}
            region["candidate"] = {"rva_start": 0x2000 + index * 0x10}
        contract["code_targets"] = [
            {
                "id": index + 20,
                "region_index": index,
                "original_rva": 0x1000 + index * 0x10,
                "candidate_rva": 0x2000 + index * 0x10,
            }
            for index in range(10)
        ]
        cluster = self._cluster()
        assert cluster is not None
        table = {
            "input_contract": "bounded_immutable_code_pointer_table_call_v1",
            "source_region_index": 0,
            "value_target_id": 4,
            "table_offset": 8,
            "original_base": self.ORIGINAL_BASE,
            "candidate_base": self.CANDIDATE_BASE,
            "layout": "sentinelTerminatedReverseCount",
            "upper_exclusive": 2,
            "original_index_register": "eax",
            "candidate_index_register": "eax",
            "continuation_target_id": 9,
            "rows": [{"original_index": 1, "target_id": 31}],
            "index_evidence": {
                "kind": "paired_sentinel_terminated_reverse_count",
                "scanner_cluster": cluster,
            },
        }

        claims = _reverse_sentinel_scanner_claims_by_edge(contract, [table])

        self.assertEqual(set(claims), {(5, 6), (6, 5), (6, 7)})
        self.assertEqual(claims[(5, 6)]["role"], "body")
        self.assertEqual(claims[(6, 5)]["role"], "loop")
        self.assertEqual(claims[(6, 7)]["role"], "exit")
        claim = claims[(5, 6)]["claim"]
        self.assertEqual(claim["test_target_id"], 26)
        self.assertEqual(claim["table"]["rows"], [
            {"original_index": 1, "target_id": 31},
        ])
        self.assertEqual(claim["original_count_register"], "eax")
        self.assertEqual(claim["zero_flag_bit"], 6)

    def test_ambiguous_scanner_claim_or_target_fails_closed(self) -> None:
        contract, _ = self._fixture()
        for index, region in enumerate(contract["regions"]):
            region["original"] = {"rva_start": 0x1000 + index * 0x10}
            region["candidate"] = {"rva_start": 0x2000 + index * 0x10}
        contract["code_targets"] = [
            {
                "id": index + 20,
                "region_index": index,
                "original_rva": 0x1000 + index * 0x10,
                "candidate_rva": 0x2000 + index * 0x10,
            }
            for index in range(10)
        ]
        cluster = self._cluster()
        assert cluster is not None
        table = {
            "input_contract": "bounded_immutable_code_pointer_table_call_v1",
            "value_target_id": 4,
            "table_offset": 8,
            "original_base": self.ORIGINAL_BASE,
            "candidate_base": self.CANDIDATE_BASE,
            "layout": "sentinelTerminatedReverseCount",
            "upper_exclusive": 2,
            "original_index_register": "eax",
            "candidate_index_register": "eax",
            "continuation_target_id": 9,
            "rows": [{"original_index": 1, "target_id": 31}],
            "index_evidence": {
                "kind": "paired_sentinel_terminated_reverse_count",
                "scanner_cluster": cluster,
            },
        }
        duplicate = copy.deepcopy(table)
        contract_with_ambiguous_target = copy.deepcopy(contract)
        contract_with_ambiguous_target["code_targets"].append(
            copy.deepcopy(contract_with_ambiguous_target["code_targets"][6])
        )

        self.assertEqual(
            _reverse_sentinel_scanner_claims_by_edge(contract, [table, duplicate]),
            {},
        )
        self.assertEqual(
            _reverse_sentinel_scanner_claims_by_edge(
                contract_with_ambiguous_target, [table]
            ),
            {},
        )

    def test_scanner_body_uses_dedicated_composable_segment_profile(self) -> None:
        contract, behaviors = self._fixture()
        for pair in behaviors:
            pair["original"] = "{ x87 := none, writes := [] }"
            pair["candidate"] = "{ x87 := none, writes := [] }"
        for index, region in enumerate(contract["regions"]):
            region.update({
                "original": {"rva_start": 0x1000 + index * 0x10},
                "candidate": {"rva_start": 0x2000 + index * 0x10},
                "input_relations": [],
                "output_relations": [],
                "bounds": [],
                "stack_windows": [],
                "flag_inputs": [],
                "code_targets": [],
                "values": [],
            })
        contract["code_targets"] = [
            {
                "id": index + 20,
                "region_index": index,
                "original_rva": 0x1000 + index * 0x10,
                "candidate_rva": 0x2000 + index * 0x10,
            }
            for index in range(10)
        ]
        for index, region in enumerate(contract["regions"]):
            region["code_targets"] = [contract["code_targets"][index]]
        contract["regions"][5]["input_relations"] = [{
            "original": "ecx", "candidate": "ecx", "relation": "exact",
        }]
        cluster = self._cluster()
        assert cluster is not None
        proposal = {
            "profile": "immutable_code_pointer_table_call_v1",
            "shape": "direct_indexed_table_read",
            "source_region_index": 0,
            "original_index_expression": self._input("eax"),
            "candidate_index_expression": self._input("eax"),
            "ranges": [{"row_count": 2}],
            "index_evidence": {
                "kind": "paired_sentinel_terminated_reverse_count",
                "scanner_cluster": cluster,
            },
        }
        contract = _attach_reverse_sentinel_table_source_invariants(
            contract, [proposal]
        )
        table = {
            "input_contract": "bounded_immutable_code_pointer_table_call_v1",
            "value_target_id": 4,
            "table_offset": 8,
            "original_base": self.ORIGINAL_BASE,
            "candidate_base": self.CANDIDATE_BASE,
            "layout": "sentinelTerminatedReverseCount",
            "upper_exclusive": 2,
            "original_index_register": "eax",
            "candidate_index_register": "eax",
            "continuation_target_id": 9,
            "rows": [{"original_index": 1, "target_id": 31}],
            "index_evidence": {
                "kind": "paired_sentinel_terminated_reverse_count",
                "scanner_cluster": cluster,
            },
        }
        edge = {
            "source_region_index": 5,
            "target_region_index": 6,
            "kind": "jump",
            "relation_preservation_proposed": True,
            "environment_barrier": False,
            "requires_call_stack_proof": False,
            "original_guard": {"op": "bool_constant", "value": True},
            "candidate_guard": {"op": "bool_constant", "value": True},
        }
        memory_regions = [
            {
                "successors": {"outcome": "returned", "direct": []},
                "candidate_successors": {"outcome": "returned", "direct": []},
                "writes": {"original_count": 0, "candidate_count": 0},
            }
            for _ in contract["regions"]
        ]
        memory_regions[5] = {
            "successors": {"outcome": "jump", "direct": [6]},
            "candidate_successors": {"outcome": "jump", "direct": [6]},
            "writes": {"original_count": 0, "candidate_count": 0},
        }
        register_regions = [
            {"inputs": [], "outputs": [], "output_claims": []}
            for _ in contract["regions"]
        ]

        diagnostics: list[dict[str, Any]] = []
        candidates = _segment_refinement_candidates(
            contract,
            behaviors,
            {"regions": memory_regions},
            {"regions": register_regions, "edges": [edge]},
            diagnostics=diagnostics,
            bounded_table_call_candidates=[table],
        )

        self.assertEqual(len(candidates), 1, diagnostics)
        self.assertEqual(
            candidates[0]["certificate_profile"],
            "composable_reverse_sentinel_scanner_v1",
        )
        self.assertEqual(
            candidates[0]["reverse_sentinel_scanner_claim"]["test_target_id"],
            26,
        )

        contract["regions"][6]["input_relations"] = [
            {"original": "eax", "candidate": "eax", "relation": "exact"},
            {"original": "ecx", "candidate": "ecx", "relation": "exact"},
        ]
        register_regions[5]["inputs"] = [{
            "original": "ecx", "candidate": "ecx", "relation": "exact",
        }]
        register_regions[6].update({
            "inputs": copy.deepcopy(contract["regions"][6]["input_relations"]),
            "outputs": copy.deepcopy(contract["regions"][6]["input_relations"]),
            "exact_output_claims": [
                {"register": "eax", "expression": self._input("eax")},
                {"register": "ecx", "expression": self._input("ecx")},
            ],
        })
        loop_guard = {
            "op": "not",
            "value": {"op": "input_flag", "index": 6},
        }
        branch_edges = [
            {
                **edge,
                "source_region_index": 6,
                "target_region_index": 5,
                "kind": "branch_taken",
                "original_guard": loop_guard,
                "candidate_guard": loop_guard,
            },
            {
                **edge,
                "source_region_index": 6,
                "target_region_index": 7,
                "kind": "branch_fallthrough",
                "original_guard": {"op": "not", "value": loop_guard},
                "candidate_guard": {"op": "not", "value": loop_guard},
            },
        ]
        memory_regions[6] = {
            "successors": {"outcome": "branch", "direct": [5, 7]},
            "candidate_successors": {"outcome": "branch", "direct": [5, 7]},
            "writes": {"original_count": 0, "candidate_count": 0},
        }
        diagnostics = []
        branch_candidates = _segment_refinement_candidates(
            contract,
            behaviors,
            {"regions": memory_regions},
            {"regions": register_regions, "edges": branch_edges},
            diagnostics=diagnostics,
            bounded_table_call_candidates=[table],
        )
        self.assertEqual(len(branch_candidates), 2, diagnostics)
        self.assertEqual(
            [candidate["certificate_profile"] for candidate in branch_candidates],
            [
                "composable_reverse_sentinel_scanner_loop_v1",
                "composable_reverse_sentinel_scanner_exit_v1",
            ],
        )
        self.assertEqual(
            [
                candidate["guard_relation_claim"]["profile"]
                for candidate in branch_candidates
            ],
            [
                "reverse_sentinel_scanner_guard_v1",
                "reverse_sentinel_scanner_guard_v1",
            ],
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            (lean_dir / "StageA").mkdir()
            modules = _write_relational_segment_refinement_modules(
                lean_dir,
                contract,
                behaviors,
                {"regions": memory_regions},
                {"regions": register_regions, "edges": branch_edges},
                {"evidence": {"decoded_control_candidates": []}},
                [list(range(len(contract["regions"])))],
                [],
                branch_candidates,
            )
            self.assertEqual(len(modules), 1)
            generated = (
                lean_dir / "StageA" / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
        self.assertEqual(
            generated.count("reverseSentinelScannerGuardsAgree_of_checked"), 2
        )
        self.assertIn(".loopChecked", generated)
        self.assertIn(".exitChecked", generated)
        self.assertNotIn("DynamicClaim", generated)


if __name__ == "__main__":
    unittest.main()
