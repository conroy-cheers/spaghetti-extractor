from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.analyses.control import (
    _bounded_immutable_relocation_table_jump_candidates,
    _immutable_indirect_call_candidates,
    _indirect_control_expression_provenance,
    _relational_product_graph,
)
from spaghetti_extractor.relational.analyses.external import (
    _semantic_externalize_register_import_call,
)
from spaghetti_extractor.relational.analyses.memory import (
    _attach_initial_static_code_pointer_slots,
)
from spaghetti_extractor.relational.analyses.registers import (
    _infer_import_register_invariants,
)
from spaghetti_extractor.relational.lean.definitions import (
    _lean_bounded_immutable_relocation_table_jump_claim,
)
from spaghetti_extractor.relational.lean.composition import (
    _write_relational_product_graph_modules,
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

    def test_bounded_table_prefers_unique_exact_start_value_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(Path(temporary))
            exact = contract["value_targets"][0]
            containing = {
                **exact,
                "id": 1,
                "original_value": int(exact["original_value"]) - 4,
                "candidate_value": int(exact["candidate_value"]) - 4,
                "mapped_size": 8,
                "relocation_offsets": [4],
            }
            contract = {
                **contract,
                "value_targets": [containing, exact],
            }

            candidates = _bounded_immutable_relocation_table_jump_candidates(
                original, candidate, contract, behaviors
            )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["value_target_id"], 0)
            self.assertEqual(candidates[0]["table_offset"], 0)

    def test_fixed_static_code_pointer_has_one_checked_call_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_path = root / "original.exe"
            candidate_path = root / "candidate.exe"
            original_path.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030, writable=True,
            ))
            candidate_path.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x3000, callee_rva=0x1030, writable=True,
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
                    "original_rva": 0x1030, "candidate_rva": 0x1030,
                    "original_aliases": [], "candidate_aliases": [],
                },
                {
                    "id": 2, "region_index": 2,
                    "original_rva": 0x101D, "candidate_rva": 0x101D,
                    "original_aliases": [], "candidate_aliases": [],
                },
            ]
            regions = [
                {
                    "id": "fixed-static-call", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                    "bounds": [], "address_separations": [],
                    "code_targets": targets[1:],
                },
                {
                    "id": "callee", "numeric_id": 1, "root": False,
                    "original": {"rva_start": 0x1030},
                    "candidate": {"rva_start": 0x1030},
                    "bounds": [], "code_targets": [],
                },
                {
                    "id": "continuation", "numeric_id": 2, "root": False,
                    "original": {"rva_start": 0x101D},
                    "candidate": {"rva_start": 0x101D},
                    "bounds": [], "code_targets": [],
                },
            ]
            behaviors = [{
                "original_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 2,
                    "target": {"op": "read32", "address": {
                        "op": "constant", "value": original.image_base + 0x2000,
                    }},
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_call", "continuation": 2,
                    "target": {"op": "read32", "address": {
                        "op": "constant", "value": candidate.image_base + 0x3000,
                    }},
                }},
            }, {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            }, {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            }]
            contract, analysis = _attach_initial_static_code_pointer_slots(
                {"code_targets": targets, "regions": regions},
                behaviors, original, candidate,
            )
            self.assertEqual(analysis["counts"]["inferred"], 1)
            candidates = _immutable_indirect_call_candidates(
                original, candidate, contract, behaviors,
            )
            self.assertEqual(len(candidates), 1)
            self.assertEqual(
                candidates[0]["profile"],
                "fixed_static_function_pointer_call_v1",
            )
            self.assertEqual(candidates[0]["target_id"], 1)
            graph = _relational_product_graph(
                contract, behaviors,
                {"edges": [{
                    "source_region_index": 0,
                    "target_region_index": 1,
                    "kind": "call",
                    "original_guard": {"op": "bool_constant", "value": True},
                    "candidate_guard": {"op": "bool_constant", "value": True},
                }]},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                indirect_call_candidates=candidates,
            )
            self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
            self.assertIn(0, graph["evidence"]["decoded_control_complete_node_ids"])
            lean_dir = root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)
            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0], [1], [2]],
            )
            decoded_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((lean_dir / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                ))
            )
            self.assertIn("StaticWordSlotIndirectCallTargetClaim", decoded_source)
            self.assertIn(
                "staticWordSlotIndirectCallTargetsClosed_of_checked",
                decoded_source,
            )
            self.assertIn(
                "immutableIndirectCallTargetsClosed_of_staticWordSlot",
                decoded_source,
            )

    def test_fixed_static_code_pointer_has_one_checked_jump_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_path = root / "original.exe"
            candidate_path = root / "candidate.exe"
            original_path.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030, writable=True, jump=True,
            ))
            candidate_path.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x3000, callee_rva=0x1030, writable=True, jump=True,
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
                    "original_rva": 0x1030, "candidate_rva": 0x1030,
                    "original_aliases": [], "candidate_aliases": [],
                },
            ]
            regions = [
                {
                    "id": "fixed-static-jump", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                    "bounds": [], "address_separations": [],
                    "code_targets": [targets[1]],
                },
                {
                    "id": "callee", "numeric_id": 1, "root": False,
                    "original": {"rva_start": 0x1030},
                    "candidate": {"rva_start": 0x1030},
                    "bounds": [], "code_targets": [],
                },
            ]
            behaviors = [{
                "original_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": {"op": "read32", "address": {
                        "op": "constant", "value": original.image_base + 0x2000,
                    }},
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": {"op": "read32", "address": {
                        "op": "constant", "value": candidate.image_base + 0x3000,
                    }},
                }},
            }, {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            }]
            contract, analysis = _attach_initial_static_code_pointer_slots(
                {"code_targets": targets, "regions": regions},
                behaviors, original, candidate,
            )
            self.assertEqual(analysis["counts"]["inferred"], 1)

            candidates = _immutable_indirect_call_candidates(
                original, candidate, contract, behaviors,
            )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(
                candidates[0]["profile"],
                "fixed_static_function_pointer_jump_v1",
            )
            self.assertEqual(candidates[0]["target_id"], 1)
            graph = _relational_product_graph(
                contract, behaviors,
                {"edges": [{
                    "source_region_index": 0,
                    "target_region_index": 1,
                    "kind": "jump",
                    "original_guard": {"op": "bool_constant", "value": True},
                    "candidate_guard": {"op": "bool_constant", "value": True},
                }]},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                indirect_call_candidates=candidates,
            )
            self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
            self.assertIn(0, graph["evidence"]["decoded_control_complete_node_ids"])
            lean_dir = root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)
            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0], [1]],
            )
            decoded_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((lean_dir / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                ))
            )
            self.assertIn("StaticWordSlotIndirectJumpTargetClaim", decoded_source)
            self.assertIn(
                "staticWordSlotIndirectJumpTargetsClosed_of_checked",
                decoded_source,
            )
            self.assertIn(
                "immutableIndirectJumpTargetsClosed_of_staticWordSlot",
                decoded_source,
            )

            contract["code_targets"][1]["original_aliases"] = [{"rva": 0x102F}]
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    original, candidate, contract, behaviors,
                ),
                [],
            )

    def test_same_region_iat_seed_closes_one_external_call_target(self) -> None:
        target_expression = {
            "op": "read32",
            "address": {"op": "constant", "value": 0x402000},
        }
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        registers["ebx"] = target_expression
        source_behavior = {
            "registers": registers,
            "outcome": {
                "op": "indirect_call",
                "target": target_expression,
                "continuation": 1,
            },
        }
        terminal_behavior = {
            "registers": {
                register: {"op": "input_reg", "reg": register}
                for register in registers
            },
            "outcome": {"op": "returned"},
        }
        behaviors = [{
            "original_ir": source_behavior,
            "candidate_ir": source_behavior,
        }, {
            "original_ir": terminal_behavior,
            "candidate_ir": terminal_behavior,
        }]
        seed = {
            "profile": "iat_register_seed_v1",
            "region_index": 0,
            "original_register": "ebx",
            "candidate_register": "ebx",
            "original_iat_rva": 0x2000,
            "candidate_iat_rva": 0x2000,
            "original_absolute_address": 0x402000,
            "candidate_absolute_address": 0x402000,
            "assembled_read": False,
            "original_writes": [],
            "candidate_writes": [],
            "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
        }
        contract = {
            "regions": [{
                "id": "seeded-call", "numeric_id": 0, "root": True,
                "original": {"rva_start": 0x1000},
                "candidate": {"rva_start": 0x1000},
            }, {
                "id": "continuation", "numeric_id": 1, "root": False,
                "original": {"rva_start": 0x1010},
                "candidate": {"rva_start": 0x1010},
            }],
            "code_targets": [{
                "id": 0, "region_index": 0,
                "original_rva": 0x1000, "candidate_rva": 0x1000,
                "original_aliases": [], "candidate_aliases": [],
            }, {
                "id": 1, "region_index": 1,
                "original_rva": 0x1010, "candidate_rva": 0x1010,
                "original_aliases": [], "candidate_aliases": [],
            }],
        }

        analysis = _infer_import_register_invariants(contract, behaviors, [seed])

        self.assertEqual(len(analysis["indirect_import_calls"]), 1)
        call = analysis["indirect_import_calls"][0]
        self.assertEqual(call["profile"], "seeded_iat_register_call_v1")
        self.assertEqual(call["seed"], seed)
        graph = _relational_product_graph(
            contract,
            behaviors,
            {"edges": [{
                "source_region_index": 0,
                "target_region_index": 1,
                "kind": "external_call",
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
            }]},
            [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
            import_register_seeds=[seed],
            import_call_candidates=analysis["indirect_import_calls"],
        )
        self.assertIn(0, graph["evidence"]["decoded_control_complete_node_ids"])
        self.assertEqual(
            graph["evidence"]["decoded_control_candidates"][0]["profile"],
            "seeded_iat_register_call_v1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            (lean_dir / "StageA").mkdir()
            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0], [1]],
            )
            decoded_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((lean_dir / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                ))
            )
            self.assertIn("ImportRegisterSeedClaim", decoded_source)
            self.assertIn(
                "importRegisterIndirectCallTargetsClosed_of_seed_checked",
                decoded_source,
            )

        ambiguous = _infer_import_register_invariants(
            contract, behaviors, [seed, dict(seed)],
        )
        self.assertEqual(ambiguous["indirect_import_calls"], [])

    def test_externalizer_accepts_checked_output_register_dispatch(self) -> None:
        target = {
            "op": "read32",
            "address": {"op": "constant", "value": 0x402000},
        }
        pushed_esp = {
            "op": "sub",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 4},
        }
        behavior = {
            "registers": {"ebx": target, "esp": pushed_esp},
            "writes": [{
                "address": pushed_esp,
                "value": {"op": "constant", "value": 0x401020},
            }],
            "outcome": {
                "op": "indirect_call",
                "target": target,
                "continuation": 1,
            },
        }
        contract = {"stack_argument_offsets": []}
        imported = {"dll": "kernel32.dll", "symbol": "GetTickCount"}

        externalized = _semantic_externalize_register_import_call(
            behavior, contract, "ebx", imported,
        )

        self.assertIsNotNone(externalized)
        self.assertEqual(externalized["outcome"], {
            "op": "external_call",
            "import": imported,
            "arguments": [],
            "continuation": 1,
        })
        mismatched = dict(behavior)
        mismatched["outcome"] = {
            **behavior["outcome"],
            "target": {"op": "input_reg", "reg": "eax"},
        }
        self.assertIsNone(_semantic_externalize_register_import_call(
            mismatched, contract, "ebx", imported,
        ))

    def test_fixed_code_address_jump_has_one_lean_checked_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, candidate, contract, _behaviors = self._fixture(root)
            target = contract["code_targets"][1]
            behaviors = [{
                "original_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": {
                        "op": "constant",
                        "value": original.image_base + int(target["original_rva"]),
                    },
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": {
                        "op": "constant",
                        "value": candidate.image_base + int(target["candidate_rva"]),
                    },
                }},
            }, {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            }]

            candidates = _immutable_indirect_call_candidates(
                original, candidate, contract, behaviors,
            )

            self.assertEqual(len(candidates), 1)
            self.assertEqual(
                candidates[0]["profile"],
                "fixed_code_address_indirect_jump_v1",
            )
            self.assertEqual(candidates[0]["target_id"], 1)
            graph = _relational_product_graph(
                contract, behaviors,
                {"edges": [{
                    "source_region_index": 0,
                    "target_region_index": 1,
                    "kind": "jump",
                    "original_guard": {"op": "bool_constant", "value": True},
                    "candidate_guard": {"op": "bool_constant", "value": True},
                }]},
                [],
                original_image_base=original.image_base,
                candidate_image_base=candidate.image_base,
                indirect_call_candidates=candidates,
            )
            self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0])
            self.assertIn(
                0, graph["evidence"]["decoded_control_complete_node_ids"]
            )
            self.assertEqual(graph["evidence"]["potential_control_cuts"], [])
            lean_dir = root / "lean"
            (lean_dir / "StageA").mkdir(parents=True)
            _write_relational_product_graph_modules(
                lean_dir, graph, [], [], [[0], [1]],
            )
            decoded_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((lean_dir / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                ))
            )
            self.assertIn(
                "FixedCodeAddressIndirectJumpTargetClaim", decoded_source
            )
            self.assertIn(
                "fixedCodeAddressIndirectJumpTargetsClosed_of_checked",
                decoded_source,
            )

            ambiguous = {
                **contract,
                "code_targets": [
                    *contract["code_targets"],
                    {**target, "id": 2},
                ],
            }
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    original, candidate, ambiguous, behaviors,
                ),
                [],
            )

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
