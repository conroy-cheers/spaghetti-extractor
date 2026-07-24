from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from spaghetti_extractor.relational.analyses.control import (
    _bounded_immutable_relocation_table_jump_candidates,
    _relational_product_graph,
)
from spaghetti_extractor.stage_binary import StageABinary, _parse_stage_a_pe
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
)


class StageAIndirectTargetRecoveryTests(unittest.TestCase):
    @staticmethod
    def _index() -> dict[str, Any]:
        return {"op": "input_reg", "reg": "eax"}

    @classmethod
    def _greater_than_zero(cls) -> dict[str, Any]:
        index = cls._index()
        return {
            "op": "and",
            "left": {
                "op": "not",
                "value": {
                    "op": "unsigned_less",
                    "left": index,
                    "right": {"op": "constant", "value": 0},
                },
            },
            "right": {
                "op": "not",
                "value": {
                    "op": "equal",
                    "left": {
                        "op": "sub",
                        "left": index,
                        "right": {"op": "constant", "value": 0},
                    },
                    "right": {"op": "constant", "value": 0},
                },
            },
        }

    @classmethod
    def _table_target(cls, base: int) -> dict[str, Any]:
        return {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": cls._index(),
                    "amount": 2,
                },
                "right": {"op": "constant", "value": base},
            },
        }

    @classmethod
    def _fixture(
        cls, root: Path, *, writable_original: bool = False,
    ) -> tuple[
        StageABinary,
        StageABinary,
        dict[str, Any],
        list[dict[str, Any]],
    ]:
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
        targets = [
            {
                "id": 0,
                "region_index": 0,
                "original_rva": 0x1000,
                "candidate_rva": 0x1000,
                "original_aliases": [],
                "candidate_aliases": [],
            },
            {
                "id": 1,
                "region_index": 1,
                "original_rva": 0x1010,
                "candidate_rva": 0x1010,
                "original_aliases": [],
                "candidate_aliases": [],
            },
            {
                "id": 2,
                "region_index": 2,
                "original_rva": 0x1030,
                "candidate_rva": 0x1030,
                "original_aliases": [],
                "candidate_aliases": [],
            },
        ]
        regions = [
            {
                "id": "bound-predecessor",
                "numeric_id": 0,
                "root": True,
                "function_entry": True,
                "original": {"rva_start": 0x1000},
                "candidate": {"rva_start": 0x1000},
                "bounds": [],
                "code_targets": [targets[1], targets[2]],
            },
            {
                "id": "table-dispatch",
                "numeric_id": 1,
                "root": False,
                "function_entry": False,
                "original": {"rva_start": 0x1010},
                "candidate": {"rva_start": 0x1010},
                "bounds": [],
                "code_targets": [],
            },
            {
                "id": "callee",
                "numeric_id": 2,
                "root": False,
                "function_entry": False,
                "original": {"rva_start": 0x1030},
                "candidate": {"rva_start": 0x1030},
                "bounds": [],
                "code_targets": [],
            },
        ]
        predecessor = {
            "registers": {"eax": cls._index()},
            "writes": [],
            "outcome": {
                "op": "branch",
                "condition": cls._greater_than_zero(),
                "taken": 2,
                "fallthrough": 1,
            },
        }
        dispatch = {
            "registers": {"eax": cls._index()},
            "writes": [],
            "outcome": {
                "op": "indirect_jump",
                "target": cls._table_target(original.image_base + 0x2000),
            },
        }
        candidate_dispatch = {
            **dispatch,
            "outcome": {
                "op": "indirect_jump",
                "target": cls._table_target(candidate.image_base + 0x3000),
            },
        }
        terminal = {
            "registers": {"eax": cls._index()},
            "writes": [],
            "outcome": {"op": "returned"},
        }
        contract = {
            "regions": regions,
            "code_targets": targets,
            "value_targets": [],
        }
        behaviors = [
            {"original_ir": predecessor, "candidate_ir": predecessor},
            {
                "original_ir": dispatch,
                "candidate_ir": candidate_dispatch,
            },
            {"original_ir": terminal, "candidate_ir": terminal},
        ]
        return original, candidate, contract, behaviors

    @classmethod
    def _flag_dataflow_fixture(
        cls, root: Path,
    ) -> tuple[
        StageABinary,
        StageABinary,
        dict[str, Any],
        list[dict[str, Any]],
    ]:
        original, candidate, _, _ = cls._fixture(root)
        targets = [
            {
                "id": target_id,
                "region_index": target_id,
                "original_rva": rva,
                "candidate_rva": rva,
                "original_aliases": [],
                "candidate_aliases": [],
            }
            for target_id, rva in enumerate((0x1000, 0x1008, 0x1010, 0x1030))
        ]
        regions = [
            {
                "numeric_id": index,
                "root": index == 0,
                "function_entry": index == 0,
                "original": {"rva_start": target["original_rva"]},
                "candidate": {"rva_start": target["candidate_rva"]},
                "bounds": [],
                "code_targets": (
                    [targets[1]] if index == 0
                    else [targets[2], targets[3]] if index == 1
                    else []
                ),
            }
            for index, target in enumerate(targets)
        ]
        producer = {
            "registers": {"eax": cls._index()},
            "flags": {
                "carry": {
                    "op": "unsigned_less",
                    "left": cls._index(),
                    "right": {"op": "constant", "value": 0},
                },
                "zero": {
                    "op": "equal",
                    "left": {
                        "op": "sub",
                        "left": cls._index(),
                        "right": {"op": "constant", "value": 0},
                    },
                    "right": {"op": "constant", "value": 0},
                },
            },
            "writes": [],
            "outcome": {"op": "jump", "target": 1},
        }
        flag_branch = {
            "registers": {"eax": cls._index()},
            "writes": [],
            "outcome": {
                "op": "branch",
                "condition": {
                    "op": "and",
                    "left": {
                        "op": "not",
                        "value": {"op": "input_flag", "index": 0},
                    },
                    "right": {
                        "op": "not",
                        "value": {"op": "input_flag", "index": 6},
                    },
                },
                "taken": 3,
                "fallthrough": 2,
            },
        }
        dispatch = {
            "registers": {"eax": cls._index()},
            "writes": [],
            "outcome": {
                "op": "indirect_jump",
                "target": cls._table_target(original.image_base + 0x2000),
            },
        }
        candidate_dispatch = {
            **dispatch,
            "outcome": {
                "op": "indirect_jump",
                "target": cls._table_target(candidate.image_base + 0x3000),
            },
        }
        terminal = {
            "registers": {"eax": cls._index()},
            "writes": [],
            "outcome": {"op": "returned"},
        }
        return original, candidate, {
            "regions": regions,
            "code_targets": targets,
            "value_targets": [],
        }, [
            {"original_ir": producer, "candidate_ir": producer},
            {"original_ir": flag_branch, "candidate_ir": flag_branch},
            {"original_ir": dispatch, "candidate_ir": candidate_dispatch},
            {"original_ir": terminal, "candidate_ir": terminal},
        ]

    def test_predecessor_bound_recovers_exact_relocated_target_inventory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )

            first = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, behaviors
            )
            second = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, behaviors
            )

        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True, separators=(",", ":")),
            json.dumps(second, sort_keys=True, separators=(",", ":")),
        )
        self.assertEqual(len(first), 1)
        proposal = first[0]
        self.assertEqual(
            proposal["profile"],
            "predecessor_bounded_immutable_relocation_table_jump_v1",
        )
        self.assertEqual(proposal["status"], "candidate_requires_lean_replay")
        self.assertFalse(proposal["acceptance_authority"])
        self.assertEqual(proposal["upper_exclusive"], 1)
        self.assertEqual(proposal["entry_target_ids"], [2])
        self.assertEqual(proposal["target_ids"], [2])
        self.assertEqual(proposal["target_inventory"], [{
            "target_id": 2,
            "target_region_index": 2,
            "original_rva": 0x1030,
            "candidate_rva": 0x1030,
            "original_aliases": [],
            "candidate_aliases": [],
        }])
        provenance = proposal["provenance"]
        self.assertEqual(
            provenance["profile"],
            "paired_bounded_immutable_relocation_rows_v1",
        )
        self.assertEqual(
            provenance["bound"]["profile"],
            "paired_direct_predecessor_unsigned_bound_v1",
        )
        self.assertEqual(
            provenance["rows"],
            [{
                "index": 0,
                "target_id": 2,
                "original_slot": original.image_base + 0x2000,
                "candidate_slot": candidate.image_base + 0x3000,
                "original_relocation_rva": 0x2000,
                "candidate_relocation_rva": 0x3000,
                "original_word": original.image_base + 0x1030,
                "candidate_word": candidate.image_base + 0x1030,
            }],
        )

    def test_finite_proposal_adds_only_inventory_targets_to_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )
            proposals = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, behaviors
            )

            graph = _relational_product_graph(
                contract,
                behaviors,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_candidates=proposals,
            )

        edge_ids = graph["nodes"][1]["outgoing_edge_ids"]
        self.assertEqual(edge_ids, [0])
        self.assertEqual(
            [graph["edges"][edge_id]["target_target_id"] for edge_id in edge_ids],
            [2],
        )
        self.assertIn(1, graph["evidence"]["decoded_control_complete_node_ids"])
        group = graph["evidence"][
            "bounded_immutable_relocation_table_edge_groups"
        ][0]
        self.assertEqual(group["target_ids"], [2])
        self.assertEqual(group["profile"], proposals[0]["profile"])

    def test_flag_predecessor_dataflow_recovers_exact_table_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = (
                self._flag_dataflow_fixture(Path(temporary))
            )
            proposals = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, behaviors
            )

            broken_behaviors = json.loads(json.dumps(behaviors))
            broken_behaviors[0]["candidate_ir"]["flags"]["zero"] = None
            rejected = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, broken_behaviors
            )
            rooted_carrier = {
                **contract,
                "regions": [
                    contract["regions"][0],
                    {**contract["regions"][1], "root": True},
                    *contract["regions"][2:],
                ],
            }
            rooted_rejected = (
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, rooted_carrier, behaviors
                )
            )

        self.assertEqual(len(proposals), 1)
        proposal = proposals[0]
        self.assertEqual(proposal["source_region_index"], 2)
        self.assertEqual(proposal["upper_exclusive"], 1)
        self.assertEqual(proposal["target_ids"], [3])
        bound = proposal["provenance"]["bound"]
        self.assertEqual(
            bound["profile"], "paired_flag_dataflow_unsigned_bound_v1"
        )
        self.assertEqual(bound["predecessors"][0]["region_index"], 1)
        flag_dataflow = bound["predecessors"][0]["flag_dataflow"]
        self.assertEqual(
            flag_dataflow["profile"],
            "paired_flag_predecessor_unsigned_bound_v1",
        )
        self.assertEqual(flag_dataflow["branch_region_index"], 1)
        self.assertEqual(
            [row["region_index"] for row in flag_dataflow["producers"]],
            [0],
        )
        self.assertEqual(rejected, [])
        self.assertEqual(rooted_rejected, [])

    def test_recovery_fails_closed_on_unbounded_or_mutable_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary) / "root"
            )
            rooted = {
                **contract,
                "regions": [
                    contract["regions"][0],
                    {**contract["regions"][1], "root": True},
                    contract["regions"][2],
                ],
            }
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, rooted, behaviors
                ),
                [],
            )

            writable, candidate, writable_contract, writable_behaviors = (
                self._fixture(
                    Path(temporary) / "writable", writable_original=True
                )
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

            extra_predecessor = {
                **contract,
                "regions": [
                    contract["regions"][0],
                    contract["regions"][1],
                    {
                        **contract["regions"][2],
                        "code_targets": [contract["code_targets"][1]],
                    },
                ],
            }
            extra_behaviors = [*behaviors]
            extra_terminal = {
                **behaviors[2]["original_ir"],
                "outcome": {"op": "jump", "target": 1},
            }
            extra_behaviors[2] = {
                "original_ir": extra_terminal,
                "candidate_ir": extra_terminal,
            }
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, extra_predecessor, extra_behaviors
                ),
                [],
            )

    def test_duplicate_relocation_and_register_only_target_stay_incomplete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )
            duplicate = [
                {"rva": 0x2000, "type": 3},
                {"rva": 0x2000, "type": 3},
            ]
            candidate_relocation = [{"rva": 0x3000, "type": 3}]
            with patch(
                "spaghetti_extractor.relational.analyses.control."
                "_raw_base_relocations",
                side_effect=[duplicate, candidate_relocation],
            ):
                self.assertEqual(
                    _bounded_immutable_relocation_table_jump_candidates(
                        original, candidate, contract, behaviors
                    ),
                    [],
                )

            register_only = [*behaviors]
            register_only[1] = {
                "original_ir": {
                    **behaviors[1]["original_ir"],
                    "outcome": {
                        "op": "indirect_jump",
                        "target": self._index(),
                    },
                },
                "candidate_ir": {
                    **behaviors[1]["candidate_ir"],
                    "outcome": {
                        "op": "indirect_jump",
                        "target": self._index(),
                    },
                },
            }
            self.assertEqual(
                _bounded_immutable_relocation_table_jump_candidates(
                    original, candidate, contract, register_only
                ),
                [],
            )
            graph = _relational_product_graph(
                contract,
                register_only,
                {"edges": []},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                bounded_table_candidates=[],
            )
            self.assertNotIn(
                1,
                graph["evidence"]["decoded_control_complete_node_ids"],
            )


if __name__ == "__main__":
    unittest.main()
