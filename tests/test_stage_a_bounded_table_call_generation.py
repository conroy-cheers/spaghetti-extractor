from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.analyses.control import (
    _bounded_immutable_code_pointer_table_call_inputs,
    _immutable_code_pointer_table_call_candidates,
    _relational_product_graph,
)
from spaghetti_extractor.relational.lean.composition import (
    _lean_bounded_immutable_code_pointer_table_call_claim,
    _write_relational_product_graph_modules,
)
from spaghetti_extractor.stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
)


class StageABoundedTableCallGenerationTests(unittest.TestCase):
    @staticmethod
    def _target(base: int) -> dict[str, Any]:
        return {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": {"op": "input_reg", "reg": "eax"},
                    "amount": 2,
                },
                "right": {"op": "constant", "value": base},
            },
        }

    @classmethod
    def _fixture(
        cls, root: Path,
    ) -> tuple[StageABinary, StageABinary, dict[str, Any], list[dict[str, Any]]]:
        original_path = root / "original.exe"
        candidate_path = root / "candidate.exe"
        original_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x2000, callee_rva=0x1030,
        ))
        candidate_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x3000, callee_rva=0x1030,
        ))
        original = _parse_stage_a_pe(original_path)
        candidate = _parse_stage_a_pe(candidate_path)
        targets = [
            {
                "id": 0, "region_index": 0,
                "original_rva": 0x1000, "candidate_rva": 0x1000,
                "original_aliases": [], "candidate_aliases": [],
            },
            {
                "id": 1, "region_index": 1,
                "original_rva": 0x101D, "candidate_rva": 0x101D,
                "original_aliases": [], "candidate_aliases": [],
            },
            {
                "id": 2, "region_index": 2,
                "original_rva": 0x1030, "candidate_rva": 0x1030,
                "original_aliases": [], "candidate_aliases": [],
            },
        ]
        contract = {
            "code_targets": targets,
            "value_targets": [{
                "id": 0,
                "original_value": original.image_base + 0x2000,
                "candidate_value": candidate.image_base + 0x3000,
                "original_relocation_rva": 0x2000,
                "candidate_relocation_rva": 0x3000,
                "mapped_size": 4,
                "relocation_offsets": [0],
            }],
            "regions": [
                {
                    "id": "table-call", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                    "bounds": [{
                        "original": "eax", "candidate": "eax", "unsigned_lt": 1,
                    }],
                    "input_relations": [{
                        "original": "eax", "candidate": "eax", "relation": "exact",
                    }],
                    "code_targets": [targets[2]],
                },
                {
                    "id": "continuation", "numeric_id": 1,
                    "original": {"rva_start": 0x101D},
                    "candidate": {"rva_start": 0x101D},
                    "bounds": [], "code_targets": [],
                },
                {
                    "id": "callee", "numeric_id": 2,
                    "original": {"rva_start": 0x1030},
                    "candidate": {"rva_start": 0x1030},
                    "bounds": [], "code_targets": [],
                },
            ],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 1,
                    "target": cls._target(original.image_base + 0x2000),
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 1,
                    "target": cls._target(candidate.image_base + 0x3000),
                }},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
        ]
        return original, candidate, contract, behaviors

    @staticmethod
    def _inputs(
        original: StageABinary,
        candidate: StageABinary,
        contract: dict[str, Any],
        behaviors: list[dict[str, Any]],
        proposals: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return _bounded_immutable_code_pointer_table_call_inputs(
            contract,
            behaviors,
            proposals,
            original_image_base=original.image_base,
            candidate_image_base=candidate.image_base,
        )

    def test_direct_bounded_table_call_generates_finite_graph_and_lean_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, behaviors = self._fixture(root)
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )
            analysis = self._inputs(
                original, candidate, contract, behaviors, proposals
            )
            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_call_candidates=analysis["candidates"],
            )
            lean_dir = root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)
            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0, 1, 2]]
            )
            decoded_source = (
                lean_dir / "StageA" / "RelationalProductDecodedControlChunk0.lean"
            ).read_text()

        self.assertEqual(analysis["status"], "candidate_requires_lean_replay")
        self.assertFalse(analysis["acceptance_authority"])
        self.assertEqual(analysis["incomplete"], [])
        accepted = analysis["candidates"][0]
        self.assertEqual(accepted["entry_target_ids"], [2])
        self.assertEqual(accepted["target_ids"], [2])
        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
        self.assertEqual(graph["edges"][0]["kind"], "call")
        self.assertEqual(graph["edges"][0]["target_node_id"], 2)
        self.assertEqual(graph["edges"][0]["original_guard"], {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 0},
        })
        self.assertEqual(graph["edges"][0]["candidate_guard"], {
            "op": "equal",
            "left": {"op": "input_reg", "reg": "eax"},
            "right": {"op": "constant", "value": 0},
        })
        self.assertEqual(
            graph["evidence"][
                "bounded_immutable_code_pointer_table_call_edge_groups"
            ],
            [{"source_node_id": 0, "candidate_index": 0, "edge_ids": [0]}],
        )
        self.assertIn(0, graph["evidence"]["decoded_control_complete_node_ids"])
        self.assertEqual(
            graph["evidence"]["runtime_call_continuations"],
            [{"source_node_id": 0, "continuation_node_ids": [1]}],
        )
        self.assertEqual(
            graph["evidence"]["reachable_decoded_control_frontier_node_ids"], []
        )
        self.assertIn("ImmutableCodePointerTableRow", decoded_source)
        self.assertIn("BoundedImmutableCodePointerTableCallClaim", decoded_source)
        self.assertIn("BoundedImmutableCodePointerTableCallTargetsClosed", decoded_source)
        self.assertIn(
            "NodeBoundedImmutableCodePointerTableCallEdgesComplete", decoded_source
        )
        self.assertIn("valueTargetId := 0", decoded_source)
        self.assertIn("tableOffset := 0", decoded_source)
        self.assertIn("originalIndexRegister := .eax", decoded_source)
        self.assertIn("{ index := 0, targetId := 2 }", decoded_source)
        self.assertIn("continuationTargetId := 1", decoded_source)
        serialized = _lean_bounded_immutable_code_pointer_table_call_claim(accepted)
        self.assertIn("upperExclusive := 1", serialized)
        self.assertIn("rows := [{ index := 0, targetId := 2 }]", serialized)

    def test_proposal_status_has_no_acceptance_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))
            proposal = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )[0]
            proposal["status"] = "pass"
            proposal["acceptance_authority"] = True

            analysis = self._inputs(
                original, candidate, contract, behaviors, [proposal]
            )

        self.assertEqual(len(analysis["candidates"]), 1)
        self.assertEqual(
            analysis["candidates"][0]["status"], "candidate_requires_lean_replay"
        )
        self.assertFalse(analysis["candidates"][0]["acceptance_authority"])

    def test_unsupported_or_ambiguous_inputs_remain_explicit_incomplete(self) -> None:
        mutations: list[tuple[str, Any, str]] = [
            (
                "cursor",
                lambda proposal, contract, behaviors: proposal.update(
                    {"shape": "cursor_loaded_table_word"}
                ),
                "cursor_loaded_or_non_direct_table_not_supported",
            ),
            (
                "sentinel",
                lambda proposal, contract, behaviors: proposal["index_evidence"].update(
                    {"kind": "reverse_sentinel_table_index"}
                ),
                "unique_checked_unsigned_bound_required",
            ),
            (
                "null",
                lambda proposal, contract, behaviors: proposal["rows"][0].update({
                    "kind": "null", "relocation_backed": False,
                    "original_word": 0, "candidate_word": 0,
                }),
                "null_sentinel_or_non_relocation_row_not_supported",
            ),
            (
                "missing-row",
                lambda proposal, contract, behaviors: proposal.update({"rows": []}),
                "table_rows_do_not_cover_bound",
            ),
            (
                "bad-target",
                lambda proposal, contract, behaviors: (
                    proposal["rows"][0].update({"target_id": 99}),
                    proposal.update({"target_ids": [99]}),
                ),
                "table_row_target_id_is_not_unique",
            ),
            (
                "bad-continuation",
                lambda proposal, contract, behaviors: proposal.update(
                    {"continuation_target_id": 2}
                ),
                "proposal_continuation_is_not_exact",
            ),
            (
                "missing-bound",
                lambda proposal, contract, behaviors: contract["regions"][0].update(
                    {"bounds": []}
                ),
                "unique_checked_unsigned_bound_required",
            ),
            (
                "missing-value-target",
                lambda proposal, contract, behaviors: contract.update(
                    {"value_targets": []}
                ),
                "unique_relocation_backed_value_target_required",
            ),
            (
                "missing-exact-index-relation",
                lambda proposal, contract, behaviors: contract["regions"][0].update(
                    {"input_relations": []}
                ),
                "unique_exact_index_register_relation_required",
            ),
        ]
        for name, mutate, expected_reason in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                original, candidate, contract, behaviors = self._fixture(Path(temporary))
                proposal = _immutable_code_pointer_table_call_candidates(
                    original, candidate, contract, behaviors
                )[0]
                mutate(proposal, contract, behaviors)

                analysis = self._inputs(
                    original, candidate, contract, behaviors, [proposal]
                )
                graph = _relational_product_graph(
                    contract,
                    behaviors,
                    {"edges": []},
                    [],
                    original_image_base=original.image_base,
                    candidate_image_base=candidate.image_base,
                    bounded_table_call_candidates=analysis["candidates"],
                )

                self.assertEqual(analysis["status"], "incomplete")
                self.assertEqual(analysis["candidates"], [])
                self.assertEqual(analysis["incomplete"][0]["reason"], expected_reason)
                self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [])
                self.assertIn(
                    0,
                    graph["evidence"][
                        "reachable_decoded_control_frontier_node_ids"
                    ],
                )

    def test_duplicate_proposals_and_raw_proposals_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))
            proposal = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )[0]
            duplicate_analysis = self._inputs(
                original,
                candidate,
                contract,
                behaviors,
                [proposal, copy.deepcopy(proposal)],
            )

            self.assertEqual(duplicate_analysis["candidates"], [])
            self.assertEqual(
                [row["reason"] for row in duplicate_analysis["incomplete"]],
                ["ambiguous_source_proposals", "ambiguous_source_proposals"],
            )
            with self.assertRaisesRegex(
                StageAInputError, "non-canonical bounded immutable"
            ):
                _relational_product_graph(
                    contract,
                    behaviors,
                    {"edges": []},
                    [],
                    original_image_base=original.image_base,
                    candidate_image_base=candidate.image_base,
                    bounded_table_call_candidates=[proposal],
                )


if __name__ == "__main__":
    unittest.main()
