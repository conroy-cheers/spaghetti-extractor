from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.analyses.control import (
    _immutable_code_pointer_table_call_candidates,
    _immutable_indirect_call_candidates,
    _immutable_image_u32,
)
from spaghetti_extractor.relational.pipeline import (
    _indirect_call_target_artifact,
)
from spaghetti_extractor.stage_binary import (
    StageABinary,
    StageAImport,
    _parse_stage_a_pe,
)
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
)


class StageAControlProvenanceTests(unittest.TestCase):
    def test_final_indirect_artifact_preserves_table_proposals(self) -> None:
        proposal = {
            "profile": "immutable_code_pointer_table_call_v1",
            "acceptance_authority": False,
        }
        artifact = _indirect_call_target_artifact(
            status="proposal_requires_generated_lean_replay",
            candidates=[],
            table_call_proposals=[proposal],
            dynamic_range_candidates=[],
            fixed_register_candidates=[],
            fixed_register_call_fixed_point={"status": "converged"},
        )
        self.assertEqual(artifact["table_call_proposals"], [proposal])
        self.assertFalse(
            artifact["table_call_proposals"][0]["acceptance_authority"]
        )

    @staticmethod
    def _target(base: int, register: str = "eax") -> dict[str, Any]:
        return {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": {"op": "input_reg", "reg": register},
                    "amount": 2,
                },
                "right": {"op": "constant", "value": base},
            },
        }

    @classmethod
    def _direct_fixture(
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
            0x2000, callee_rva=0x1030, writable=writable_original,
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
            "regions": [
                {
                    "id": "table-call", "numeric_id": 0,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                    "bounds": [{
                        "original": "eax", "candidate": "eax",
                        "unsigned_lt": 1,
                    }],
                    "code_targets": [targets[1]],
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

    def test_direct_finite_table_call_emits_explicit_checked_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._direct_fixture(
                Path(temporary)
            )

            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )

        self.assertEqual(len(proposals), 1)
        proposal = proposals[0]
        self.assertEqual(
            proposal["profile"], "immutable_code_pointer_table_call_v1"
        )
        self.assertEqual(proposal["status"], "candidate_requires_lean_replay")
        self.assertFalse(proposal["acceptance_authority"])
        self.assertEqual(proposal["shape"], "direct_indexed_table_read")
        self.assertEqual(proposal["continuation_target_id"], 1)
        self.assertEqual(proposal["target_ids"], [2])
        self.assertEqual(proposal["ranges"][0]["row_count"], 1)
        self.assertEqual(proposal["rows"], [{
            "kind": "code_pointer",
            "target_id": 2,
            "original_slot": original.image_base + 0x2000,
            "candidate_slot": candidate.image_base + 0x3000,
            "original_rva": 0x2000,
            "candidate_rva": 0x3000,
            "original_index": 0,
            "candidate_index": 0,
            "original_word": original.image_base + 0x1030,
            "candidate_word": candidate.image_base + 0x1030,
            "original_relocation_rva": 0x2000,
            "candidate_relocation_rva": 0x3000,
            "relocation_backed": True,
            "range_index": 0,
        }])

    def test_table_proposals_remain_separate_from_accepted_candidates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._direct_fixture(
                Path(temporary)
            )

            accepted = _immutable_indirect_call_candidates(
                original, candidate, contract, behaviors
            )
            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )

        self.assertEqual(accepted, [])
        self.assertEqual(len(proposals), 1)
        proposal = proposals[0]
        self.assertEqual(
            proposal["profile"], "immutable_code_pointer_table_call_v1"
        )
        self.assertFalse(proposal["acceptance_authority"])

    def test_cursor_call_uses_only_paired_static_caller_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, direct_contract, _ = self._direct_fixture(
                Path(temporary)
            )
            targets = [
                {
                    "id": index, "region_index": index,
                    "original_rva": 0x1000 + index * 4,
                    "candidate_rva": 0x1000 + index * 4,
                    "original_aliases": [], "candidate_aliases": [],
                }
                for index in range(7)
            ]
            targets[6] = direct_contract["code_targets"][2]
            regions = [
                {
                    "id": f"walker-{index}", "numeric_id": index,
                    "function_id": "walker" if index < 5 else f"other-{index}",
                    "function_entry": index == 0,
                    "original": {"rva_start": 0x1000 + index * 4},
                    "candidate": {"rva_start": 0x1000 + index * 4},
                    "bounds": [], "code_targets": [],
                }
                for index in range(7)
            ]
            contract = {"code_targets": targets, "regions": regions}
            read_original = {
                "op": "read32",
                "address": {"op": "input_reg", "reg": "ebx"},
            }
            read_candidate = {
                "op": "read32",
                "address": {"op": "input_reg", "reg": "ebx"},
            }
            zero_original = {
                "op": "equal",
                "left": {
                    "op": "bit_and", "left": read_original,
                    "right": read_original,
                },
                "right": {"op": "constant", "value": 0},
            }
            zero_candidate = {
                "op": "equal",
                "left": {
                    "op": "bit_and", "left": read_candidate,
                    "right": read_candidate,
                },
                "right": {"op": "constant", "value": 0},
            }
            step = {
                "op": "add", "left": {"op": "input_reg", "reg": "ebx"},
                "right": {"op": "constant", "value": 4},
            }
            behaviors = [
                {
                    "original_ir": {"outcome": {"op": "jump", "target": 1}},
                    "candidate_ir": {"outcome": {"op": "jump", "target": 1}},
                },
                {
                    "original_ir": {
                        "registers": {"eax": read_original},
                        "outcome": {
                            "op": "branch", "condition": zero_original,
                            "taken": 4, "fallthrough": 2,
                        },
                    },
                    "candidate_ir": {
                        "registers": {"eax": read_candidate},
                        "outcome": {
                            "op": "branch", "condition": zero_candidate,
                            "taken": 4, "fallthrough": 2,
                        },
                    },
                },
                {
                    "original_ir": {"outcome": {
                        "op": "indirect_call", "continuation": 3,
                        "target": {"op": "input_reg", "reg": "eax"},
                    }},
                    "candidate_ir": {"outcome": {
                        "op": "indirect_call", "continuation": 3,
                        "target": {"op": "input_reg", "reg": "eax"},
                    }},
                },
                {
                    "original_ir": {"outcome": {"op": "jump", "target": 4}},
                    "candidate_ir": {"outcome": {"op": "jump", "target": 4}},
                },
                {
                    "original_ir": {
                        "registers": {"ebx": step},
                        "outcome": {
                            "op": "branch", "taken": 1, "fallthrough": 3,
                            "condition": {
                                "op": "unsigned_less", "left": step,
                                "right": {"op": "input_reg", "reg": "esi"},
                            },
                        },
                    },
                    "candidate_ir": {
                        "registers": {"ebx": step},
                        "outcome": {
                            "op": "branch", "taken": 1, "fallthrough": 3,
                            "condition": {
                                "op": "unsigned_less", "left": step,
                                "right": {"op": "input_reg", "reg": "esi"},
                            },
                        },
                    },
                },
                {
                    "original_ir": {
                        "writes": [
                            {
                                "address": {"op": "input_reg", "reg": "esp"},
                                "value": {"op": "constant", "value": 0x402000},
                            },
                            {
                                "address": {
                                    "op": "add",
                                    "left": {"op": "input_reg", "reg": "esp"},
                                    "right": {"op": "constant", "value": 4},
                                },
                                "value": {"op": "constant", "value": 0x402004},
                            },
                        ],
                        "outcome": {"op": "call", "target": 0},
                    },
                    "candidate_ir": {
                        "writes": [
                            {
                                "address": {"op": "input_reg", "reg": "esp"},
                                "value": {"op": "constant", "value": 0x403000},
                            },
                            {
                                "address": {
                                    "op": "add",
                                    "left": {"op": "input_reg", "reg": "esp"},
                                    "right": {"op": "constant", "value": 4},
                                },
                                "value": {"op": "constant", "value": 0x403004},
                            },
                        ],
                        "outcome": {"op": "call", "target": 0},
                    },
                },
                {
                    "original_ir": {"outcome": {"op": "returned"}},
                    "candidate_ir": {"outcome": {"op": "returned"}},
                },
            ]

            proposals = _immutable_code_pointer_table_call_candidates(
                original, candidate, contract, behaviors
            )

        self.assertEqual(len(proposals), 1)
        proposal = proposals[0]
        self.assertEqual(proposal["source_region_index"], 2)
        self.assertEqual(proposal["shape"], "cursor_loaded_table_word")
        self.assertEqual(proposal["target_ids"], [2])
        self.assertEqual(
            proposal["index_evidence"]["callsite_region_indices"], [5]
        )
        self.assertEqual(proposal["rows"][0]["target_id"], 2)

    def test_table_calls_fail_closed_on_incomplete_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, behaviors = self._direct_fixture(root)

            without_relocations = replace(original)
            setattr(without_relocations.pe, "DIRECTORY_ENTRY_BASERELOC", [])
            self.assertEqual(
                _immutable_code_pointer_table_call_candidates(
                    without_relocations, candidate, contract, behaviors
                ),
                [],
            )

            original, candidate, contract, behaviors = self._direct_fixture(
                root / "iat"
            )
            iat_original = replace(original, imports=(StageAImport(
                dll="example.dll", symbol="Callback", ordinal=None,
                thunk_rva=0x2000,
            ),))
            self.assertIsNone(
                _immutable_image_u32(iat_original, original.image_base + 0x2000)
            )
            self.assertEqual(
                _immutable_code_pointer_table_call_candidates(
                    iat_original, candidate, contract, behaviors
                ),
                [],
            )

            writable, candidate, contract, behaviors = self._direct_fixture(
                root / "writable", writable_original=True
            )
            self.assertEqual(
                _immutable_code_pointer_table_call_candidates(
                    writable, candidate, contract, behaviors
                ),
                [],
            )

            original, candidate, contract, behaviors = self._direct_fixture(
                root / "unbounded"
            )
            unbounded_contract = {
                **contract,
                "regions": [
                    {**contract["regions"][0], "bounds": []},
                    *contract["regions"][1:],
                ],
            }
            self.assertEqual(
                _immutable_code_pointer_table_call_candidates(
                    original, candidate, unbounded_contract, behaviors
                ),
                [],
            )

            mismatched = [dict(row) for row in behaviors]
            mismatched[0] = {
                **mismatched[0],
                "candidate_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 1,
                    "target": self._target(
                        candidate.image_base + 0x3000, register="edx"
                    ),
                }},
            }
            self.assertEqual(
                _immutable_code_pointer_table_call_candidates(
                    original, candidate, contract, mismatched
                ),
                [],
            )


if __name__ == "__main__":
    unittest.main()
