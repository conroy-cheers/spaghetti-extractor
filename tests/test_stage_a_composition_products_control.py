from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.composition_products import (
    _composition_product_graph,
)
from spaghetti_extractor.relational.lean.composition import (
    _paired_pure_expression_witness,
    _write_relational_product_graph_modules,
)
from spaghetti_extractor.stage_binary import StageABinary, _parse_stage_a_pe
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
)


class StageACompositionProductsControlTests(unittest.TestCase):
    @staticmethod
    def _table_target(base: int) -> dict[str, Any]:
        return {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": {"op": "input_reg", "reg": "edi"},
                    "amount": 2,
                },
                "right": {"op": "constant", "value": base},
            },
        }

    @classmethod
    def _fixture(
        cls, root: Path
    ) -> tuple[
        StageABinary,
        StageABinary,
        dict[str, Any],
        list[dict[str, Any]],
    ]:
        original_path = root / "original.exe"
        candidate_path = root / "candidate.exe"
        original_path.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x2000,
            callee_rva=0x1030,
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
            "regions": [{
                "id": "bounded-table-jump",
                "numeric_id": 0,
                "root": True,
                "original": {"rva_start": 0x1000},
                "candidate": {"rva_start": 0x1000},
                "bounds": [{
                    "original": "edi",
                    "candidate": "edi",
                    "unsigned_lt": 1,
                }],
                "code_targets": [callee_target],
            }, {
                "id": "callee",
                "numeric_id": 1,
                "root": False,
                "original": {"rva_start": 0x1030},
                "candidate": {"rva_start": 0x1030},
                "bounds": [],
                "code_targets": [],
            }],
        }
        behaviors = [{
            "original_ir": {"outcome": {
                "op": "indirect_jump",
                "target": cls._table_target(original.image_base + 0x2000),
            }},
            "candidate_ir": {"outcome": {
                "op": "indirect_jump",
                "target": cls._table_target(candidate.image_base + 0x3000),
            }},
        }, {
            "original_ir": {"outcome": {"op": "returned"}},
            "candidate_ir": {"outcome": {"op": "returned"}},
        }]
        return original, candidate, contract, behaviors

    @staticmethod
    def _graph(
        original: StageABinary,
        candidate: StageABinary,
        contract: dict[str, Any],
        behaviors: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return _composition_product_graph(
            original_bin=original,
            candidate_bin=candidate,
            normalized=contract,
            behaviors=behaviors,
            register_relations={"edges": []},
            segment_candidates=[],
            indirect_call_candidates=[],
            bounded_table_call_candidates=[],
            dynamic_call_candidates=[],
            import_register_seeds=[],
            import_call_candidates=[],
            external_call_candidates=[],
        )

    def test_composition_includes_bounded_immutable_jump_table_candidates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )

            graph = self._graph(original, candidate, contract, behaviors)

        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
        self.assertEqual(graph["edges"][0]["target_node_id"], 1)
        self.assertEqual(
            graph["evidence"][
                "bounded_immutable_relocation_table_edge_groups"
            ],
            [{"source_node_id": 0, "candidate_index": 0, "edge_ids": [0]}],
        )
        self.assertEqual(
            graph["evidence"]["decoded_control_candidates"][0]["profile"],
            "bounded_immutable_relocation_table_jump_v1",
        )
        self.assertEqual(graph["evidence"]["potential_control_cuts"], [])

    def test_bounded_jump_table_emits_lean_checked_control_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, behaviors = self._fixture(root)
            graph = self._graph(original, candidate, contract, behaviors)
            lean_dir = root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)

            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0], [1]],
            )
            source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((lean_dir / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                ))
            )

        self.assertIn(
            "BoundedImmutableRelocationTableJumpControlClaim", source,
        )
        self.assertIn(
            "boundedImmutableRelocationTableJumpTargetsClosed_of_checked", source,
        )
        self.assertIn(
            "nodeBoundedImmutableRelocationTableJumpEdgesComplete_of_checked", source,
        )
        self.assertIn("PairedExactExprWitness.inputReg .edi .edi", source)
        self.assertIn("original := .edi", source)
        self.assertIn("candidate := .edi", source)
        self.assertNotIn(
            "Or.inl ⟨originalBehavior0CheckedDecoded, "
            "candidateBehavior0CheckedDecoded, by decide⟩",
            source,
        )

    def test_bounded_jump_expression_witness_fails_closed_on_memory_index(self) -> None:
        memory_index = {
            "op": "read32",
            "address": {"op": "input_reg", "reg": "esp"},
        }
        self.assertIsNone(
            _paired_pure_expression_witness(memory_index, memory_index)
        )

    def test_ambiguous_and_unsupported_jump_tables_remain_unresolved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )
            source_region = contract["regions"][0]
            ambiguous_contract = {
                **contract,
                "regions": [{
                    **source_region,
                    "bounds": [
                        *source_region["bounds"],
                        dict(source_region["bounds"][0]),
                    ],
                }, contract["regions"][1]],
            }
            unsupported_behaviors = [
                {
                    "original_ir": {"outcome": {
                        "op": "indirect_jump",
                        "target": {"op": "input_reg", "reg": "eax"},
                    }},
                    "candidate_ir": {"outcome": {
                        "op": "indirect_jump",
                        "target": {"op": "input_reg", "reg": "eax"},
                    }},
                },
                behaviors[1],
            ]

            cases = {
                "ambiguous_bounds": self._graph(
                    original, candidate, ambiguous_contract, behaviors
                ),
                "unsupported_target": self._graph(
                    original, candidate, contract, unsupported_behaviors
                ),
            }

        for name, graph in cases.items():
            with self.subTest(name=name):
                self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [])
                self.assertEqual(
                    graph["evidence"][
                        "bounded_immutable_relocation_table_edge_groups"
                    ],
                    [],
                )
                self.assertNotIn(
                    0,
                    graph["evidence"]["decoded_control_complete_node_ids"],
                )
                self.assertEqual(
                    graph["evidence"]["potential_control_cuts"][0]["node_id"],
                    0,
                )


if __name__ == "__main__":
    unittest.main()
