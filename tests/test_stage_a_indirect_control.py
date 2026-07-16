from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.analyses.control import (
    _bounded_immutable_relocation_table_jump_candidates,
    _indirect_control_expression_provenance,
    _relational_product_graph,
)
from spaghetti_extractor.relational.lean.definitions import (
    _lean_bounded_immutable_relocation_table_jump_claim,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
)


class StageAIndirectControlTests(unittest.TestCase):
    @staticmethod
    def _table_target(base: int) -> dict[str, object]:
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
        cls,
        root: Path,
        *,
        writable_original: bool = False,
    ) -> tuple[object, object, dict[str, object], list[dict[str, object]]]:
        root.mkdir(parents=True, exist_ok=True)
        original_path = root / "original.exe"
        candidate_path = root / "candidate.exe"
        original_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x2000,
            callee_rva=0x1030,
            writable=writable_original,
            jump=True,
        ))
        candidate_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x3000,
            callee_rva=0x1030,
            jump=True,
        ))
        original = _parse_stage_a_pe(original_path)
        candidate = _parse_stage_a_pe(candidate_path)
        source_target = {
            "id": 0,
            "region_index": 0,
            "original_rva": 0x1000,
            "candidate_rva": 0x1000,
            "original_aliases": [],
            "candidate_aliases": [],
        }
        callee_target = {
            "id": 1,
            "region_index": 1,
            "original_rva": 0x1030,
            "candidate_rva": 0x1030,
            "original_aliases": [],
            "candidate_aliases": [],
        }
        source_region = {
            "id": "bounded-table-jump",
            "numeric_id": 0,
            "root": True,
            "original": {"rva_start": 0x1000},
            "candidate": {"rva_start": 0x1000},
            "bounds": [{
                "original": "eax",
                "candidate": "eax",
                "unsigned_lt": 1,
            }],
            "code_targets": [callee_target],
        }
        target_region = {
            "id": "callee",
            "numeric_id": 1,
            "root": False,
            "original": {"rva_start": 0x1030},
            "candidate": {"rva_start": 0x1030},
            "bounds": [],
            "code_targets": [],
        }
        contract = {
            "code_targets": [source_target, callee_target],
            "value_targets": [{
                "id": 0,
                "original_value": original.image_base + 0x2000,
                "candidate_value": candidate.image_base + 0x3000,
                "original_relocation_rva": 0x2000,
                "candidate_relocation_rva": 0x3000,
                "mapped_size": 4,
                "relocation_offsets": [0],
            }],
            "regions": [source_region, target_region],
        }
        source_behavior = {
            "original_ir": {
                "outcome": {
                    "op": "indirect_jump",
                    "target": cls._table_target(original.image_base + 0x2000),
                },
            },
            "candidate_ir": {
                "outcome": {
                    "op": "indirect_jump",
                    "target": cls._table_target(candidate.image_base + 0x3000),
                },
            },
        }
        terminal_behavior = {
            "original_ir": {"outcome": {"op": "returned"}},
            "candidate_ir": {"outcome": {"op": "returned"}},
        }
        return original, candidate, contract, [source_behavior, terminal_behavior]

    def test_bounded_immutable_relocation_table_has_finite_graph_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))

            candidates = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, behaviors
            )

            self.assertEqual(len(candidates), 1)
            claim = candidates[0]
            self.assertEqual(
                claim["profile"],
                "bounded_immutable_relocation_table_jump_v1",
            )
            self.assertEqual(claim["entry_target_ids"], [1])
            self.assertEqual(claim["target_ids"], [1])
            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_candidates=candidates,
            )
            self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
            self.assertEqual(graph["edges"][0]["target_node_id"], 1)
            self.assertIn(0, graph["evidence"]["decoded_control_complete_node_ids"])
            self.assertEqual(graph["evidence"]["potential_control_cuts"], [])
            lean_claim = _lean_bounded_immutable_relocation_table_jump_claim(claim)
            self.assertIn("valueTargetId := 0", lean_claim)
            self.assertIn("entryTargetIds := [1]", lean_claim)
            self.assertIn("finiteTargetIds := [1]", lean_claim)

    def test_bounded_table_fails_closed_without_complete_static_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, behaviors = self._fixture(root)

            no_bound = {**contract, "regions": [
                {**contract["regions"][0], "bounds": []},
                contract["regions"][1],
            ]}
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, no_bound, behaviors
                ),
                [],
            )

            no_relocation = {**contract, "value_targets": [{
                **contract["value_targets"][0],
                "relocation_offsets": [],
            }]}
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, no_relocation, behaviors
                ),
                [],
            )

            duplicate_target = {
                **contract["code_targets"][1],
                "id": 2,
                "region_index": 1,
            }
            ambiguous = {
                **contract,
                "code_targets": [*contract["code_targets"], duplicate_target],
                "regions": [{
                    **contract["regions"][0],
                    "code_targets": [
                        *contract["regions"][0]["code_targets"],
                        duplicate_target,
                    ],
                }, contract["regions"][1]],
            }
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, ambiguous, behaviors
                ),
                [],
            )

            writable, candidate, writable_contract, writable_behaviors = self._fixture(
                root / "writable",
                writable_original=True,
            )
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    writable,
                    candidate,
                    writable_contract,
                    writable_behaviors,
                ),
                [],
            )

    def test_unresolved_provenance_distinguishes_stack_register_and_static_words(self) -> None:
        self.assertEqual(
            _indirect_control_expression_provenance(
                {"op": "input_reg", "reg": "eax"}, "indirect_call"
            ),
            "register_word_without_producer_certificate",
        )
        self.assertEqual(
            _indirect_control_expression_provenance(
                {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": "esp"},
                        "right": {"op": "constant", "value": 12},
                    },
                },
                "indirect_call",
            ),
            "stack_word_without_code_pointer_producer",
        )
        self.assertEqual(
            _indirect_control_expression_provenance(
                {
                    "op": "read32",
                    "address": {"op": "constant", "value": 0x401000},
                },
                "indirect_jump",
            ),
            "static_word_without_immutability_certificate",
        )

        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))
            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
            )
            self.assertEqual(
                graph["evidence"]["potential_control_cuts"][0]["provenance"],
                ["indexed_static_word_without_finite_table_certificate"],
            )
            self.assertEqual(
                graph["evidence"]["potential_control_cuts"][0]["target_scope"],
                "all_canonical_code_targets",
            )


if __name__ == "__main__":
    unittest.main()
