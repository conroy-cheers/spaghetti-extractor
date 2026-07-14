import json
import os
import shutil
import struct
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from threading import Event, Timer
from types import SimpleNamespace
from unittest.mock import patch

from wincr.stage_a_relational import (
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_KERNEL_MODULES,
    RELATIONAL_OBSERVATIONS,
    RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
    _attach_import_register_analysis,
    _attach_import_seed_address_separations,
    _attach_dynamic_indirect_call_analysis,
    _attach_external_call_site_analysis,
    _attach_return_write_address_separations,
    _attach_return_slot_contracts,
    _attach_stack_window_invariants,
    _attach_register_relation_analysis,
    _assembled_iat_read_candidates,
    _cached_behavior_affected_by_machine_contracts,
    _compact_acceptance_blockers,
    _composition_progress,
    _direct_call_push_claim,
    _dynamic_range_indirect_call_candidates,
    _dynamic_pointer_traversal_diagnostic,
    _dynamic_range_register_output_claims,
    _dynamic_range_relations,
    _dynamic_range_transfer_claims,
    _external_argument_relation_claims,
    _external_call_site_candidates,
    _external_register_policy_replay_candidate,
    _finalize_nix_proof_ir,
    _immutable_indirect_call_candidates,
    _iat_import_register_seed_candidates,
    _import_register_transfer_claims,
    _infer_import_register_invariants,
    _iat_read_classification,
    _lean_identical_state_only_write_registers,
    _lean_identical_state_only_writes_component,
    _lower_stack_register_relations,
    _machine_import_call_contract_analysis,
    _machine_import_call_contracts,
    _mapped_relocation_offsets,
    _normalize_contract,
    _normalized_behavior_fast_path,
    _nonzero_word_guard,
    _partition_proof_shards,
    _persistent_olean_path,
    _paired_stack_guard_claim,
    _paired_stack_word_write_claim,
    _paired_stack_word_writes_claim,
    _relational_nix_build_command,
    _return_pop_claim,
    _relational_extraction_semantics_sha256,
    _related_word_zero_guard_claim,
    _relational_product_graph,
    _run_lean_relational,
    _semantic_affine_word_read,
    _semantic_memory_pullback_support,
    _semantic_read32_after_writes,
    _semantic_constant_bool,
    _semantic_x87_load_pullback_supported,
    _stack_read32_sub_output_claim,
    _stack_window_transfer_claims,
    _static_dynamic_pointer_slots,
    _static_dynamic_pointer_slot_guard_claim,
    _static_dynamic_pointer_seed_diagnostic,
    _synthesize_register_relations,
    _synthesize_relational_invariants,
    _validate_relational_module_graph,
    _validate_prepared_relational,
    _write_reachable_product_local_certificate,
    stage_a_build_relational,
    stage_a_check_relational_proof,
    stage_a_generate_relation_contract,
    stage_a_prepare_relational,
    stage_a_prove_relational,
)
from wincr.stage_binary import StageAImport, StageAInputError, _parse_stage_a_pe


class StageARelationalTests(unittest.TestCase):
    def test_paired_stack_word_write_proposal_fails_closed(self):
        source = {
            "stack_windows": [{
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 0,
                "bytes_above": 16,
            }],
        }

        def behavior(amount: int, candidate_value: int = 7) -> dict[str, object]:
            def write(value: int) -> dict[str, object]:
                return {
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": "esp"},
                        "right": {"op": "constant", "value": amount},
                    },
                    "value": {"op": "constant", "value": value},
                }

            return {
                "original_ir": {"writes": [write(7)]},
                "candidate_ir": {"writes": [write(candidate_value)]},
            }

        claim = _paired_stack_word_write_claim(source, behavior(8))
        self.assertIsNotNone(claim)
        self.assertEqual(claim["amount"], 8)
        self.assertIsNone(_paired_stack_word_write_claim(source, behavior(2)))
        self.assertIsNone(
            _paired_stack_word_write_claim(source, behavior(8, candidate_value=9))
        )

        def writes_behavior(
            amounts: list[int], *, candidate_value: int = 7,
        ) -> dict[str, object]:
            def address(amount: int) -> dict[str, object]:
                if amount == 0:
                    return {"op": "input_reg", "reg": "esp"}
                return {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": "esp"},
                    "right": {"op": "constant", "value": amount},
                }

            return {
                "original_ir": {"writes": [{
                    "address": address(amount),
                    "value": {"op": "constant", "value": 7},
                } for amount in amounts]},
                "candidate_ir": {"writes": [{
                    "address": address(amount),
                    "value": {
                        "op": "constant",
                        "value": candidate_value if index == 0 else 7,
                    },
                } for index, amount in enumerate(amounts)]},
            }

        writes_claim = _paired_stack_word_writes_claim(
            source, writes_behavior([0, 4, 8])
        )
        self.assertIsNotNone(writes_claim)
        self.assertEqual(
            [write["amount"] for write in writes_claim["writes"]],
            [0, 4, 8],
        )
        self.assertIsNone(
            _paired_stack_word_writes_claim(source, writes_behavior([8]))
        )
        self.assertIsNone(
            _paired_stack_word_writes_claim(source, writes_behavior([0, 2]))
        )
        self.assertIsNone(_paired_stack_word_writes_claim(
            source, writes_behavior([0, 4], candidate_value=9)
        ))

        related_source = {
            **source,
            "input_relations": [{
                "original": "eax",
                "candidate": "ecx",
                "relation": "related_word",
            }],
        }

        def related_behavior(*, offset: int = 0) -> dict[str, object]:
            def value(register: str) -> dict[str, object]:
                expression: dict[str, object] = {
                    "op": "input_reg",
                    "reg": register,
                }
                if offset:
                    expression = {
                        "op": "add",
                        "left": expression,
                        "right": {"op": "constant", "value": offset},
                    }
                return expression

            def write(register: str) -> dict[str, object]:
                return {
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": "esp"},
                        "right": {"op": "constant", "value": 8},
                    },
                    "value": value(register),
                }

            return {
                "original_ir": {"writes": [write("eax")]},
                "candidate_ir": {"writes": [write("ecx")]},
            }

        related_claim = _paired_stack_word_write_claim(
            related_source, related_behavior()
        )
        self.assertIsNotNone(related_claim)
        self.assertEqual(
            related_claim["value"]["profile"], "register_argument_v1"
        )
        self.assertEqual(
            related_claim["value"]["claim"]["relation"],
            related_source["input_relations"][0],
        )
        self.assertIsNone(_paired_stack_word_write_claim(
            related_source, related_behavior(offset=4)
        ))

    def test_acceptance_blockers_are_compacted_without_losing_counts(self):
        compact = _compact_acceptance_blockers([
            {
                "code": "return_node_profile_unmet",
                "message": f"return node {node_id} is incomplete",
                "next_action": "close the runtime frame",
            }
            for node_id in range(12)
        ] + [{
            "code": "environment_pending",
            "message": "the external edge is incomplete",
            "next_action": "close environment refinement",
        }])

        self.assertEqual([item["code"] for item in compact], [
            "return_node_profile_unmet", "environment_pending",
        ])
        self.assertEqual(compact[0]["count"], 12)
        self.assertEqual(len(compact[0]["examples"]), 10)
        self.assertEqual(compact[0]["omitted_examples"], 2)
        self.assertEqual(compact[1]["count"], 1)
        self.assertEqual(compact[1]["message"], "the external edge is incomplete")

    def test_potential_reachability_expands_unresolved_indirect_control(self):
        regions = [
            {
                "id": "indirect",
                "numeric_id": 0,
                "root": True,
                "original": {"rva_start": 0x1000},
                "candidate": {"rva_start": 0x1000},
            },
            {
                "id": "target",
                "numeric_id": 1,
                "root": False,
                "original": {"rva_start": 0x1010},
                "candidate": {"rva_start": 0x1020},
            },
        ]
        contract = {
            "regions": regions,
            "code_targets": [
                {
                    "id": 0, "region_index": 0,
                    "original_rva": 0x1000, "candidate_rva": 0x1000,
                },
                {
                    "id": 1, "region_index": 1,
                    "original_rva": 0x1010, "candidate_rva": 0x1020,
                },
            ],
        }
        indirect_outcome = {
            "op": "indirect_call",
            "target": {"op": "input_reg", "reg": "eax"},
            "continuation": 1,
        }
        returned_outcome = {
            "op": "returned",
            "target": {"op": "input_reg", "reg": "eax"},
        }
        graph = _relational_product_graph(
            contract,
            [
                {
                    "original_ir": {"outcome": indirect_outcome},
                    "candidate_ir": {"outcome": indirect_outcome},
                },
                {
                    "original_ir": {"outcome": returned_outcome},
                    "candidate_ir": {"outcome": returned_outcome},
                },
            ],
            {"edges": []},
            [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        self.assertEqual(graph["evidence"]["declared_reachable_node_ids"], [0])
        self.assertEqual(graph["evidence"]["potential_reachable_node_ids"], [0, 1])
        self.assertEqual(graph["evidence"]["potential_control_cuts"], [{
            "node_id": 0,
            "operations": ["indirect_call"],
            "reason": "unresolved_indirect_control_all_canonical_targets",
            "potential_target_count": 2,
            "target_scope": "all_canonical_code_targets",
        }])
        self.assertTrue(
            graph["counts"]["reachability_truncated_by_control_frontier"]
        )
        self.assertEqual(graph["counts"]["potential_reachable_nodes"], 2)
        self.assertEqual(
            graph["counts"]["potential_unrepresented_control_edges"], 2
        )
        progress = _composition_progress(
            graph,
            {
                "status": "supported", "issues": [],
                "counts": {"issues": 0, "by_category": {}},
            },
            {
                "format": "stage-a-relational-external-call-sites-v1",
                "status": "candidate_requires_lean_replay",
                "candidates": [], "gaps": [],
                "counts": {"candidates": 0, "gaps": 0},
            },
            {
                "status": "incomplete", "profile": None, "theorem": None,
                "blockers": [{
                    "code": "unresolved_control",
                    "next_action": "classify the indirect target",
                }],
            },
        )
        self.assertEqual(progress["status"], "incomplete")
        self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 1)
        self.assertEqual(progress["counts"]["potential_reachable_nodes"], 2)
        self.assertEqual(
            progress["counts"]["unresolved_indirect_control_nodes"], 1
        )
        self.assertTrue(progress["reachability"]["truncated_by_control_frontier"])
        self.assertEqual(
            [item["category"] for item in progress["next_work"]],
            ["unresolved_indirect_control"],
        )
        frame_progress = _composition_progress(
            graph,
            {
                "status": "supported", "issues": [],
                "counts": {"issues": 0, "by_category": {}},
            },
            {
                "format": "stage-a-relational-external-call-sites-v1",
                "status": "candidate_requires_lean_replay",
                "candidates": [], "gaps": [],
                "counts": {"candidates": 0, "gaps": 0},
            },
            {
                "status": "incomplete", "profile": None, "theorem": None,
                "blockers": [],
            },
            {
                "frontier": [{
                    "region_index": 0,
                    "original_register": "esp",
                    "candidate_register": "esp",
                    "bytes_below": 4,
                    "bytes_above": 8,
                    "reason":
                        "nonzero_stack_delta_cycle_requires_relational_frame",
                }],
            },
        )
        self.assertEqual(
            frame_progress["counts"]
            ["rooted_relational_call_frame_frontier_nodes"],
            1,
        )
        self.assertEqual(
            [item["category"] for item in frame_progress["next_work"]],
            ["unresolved_indirect_control", "relational_call_frame_frontier"],
        )

    def test_dynamic_indirect_call_adds_exact_guarded_code_map_fanout(self):
        contract = {
            "regions": [
                {
                    "id": "indirect", "numeric_id": 0, "root": True,
                    "original": {"rva_start": 0x1000},
                    "candidate": {"rva_start": 0x1000},
                },
                {
                    "id": "target", "numeric_id": 1, "root": False,
                    "original": {"rva_start": 0x1010},
                    "candidate": {"rva_start": 0x1020},
                },
            ],
            "code_targets": [
                {
                    "id": 0, "region_index": 0,
                    "original_rva": 0x1000, "candidate_rva": 0x1000,
                    "original_aliases": [0x1004],
                    "candidate_aliases": [0x1008],
                },
                {
                    "id": 1, "region_index": 1,
                    "original_rva": 0x1010, "candidate_rva": 0x1020,
                    "original_aliases": [], "candidate_aliases": [],
                },
            ],
        }
        original_target = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "ebx"},
                "right": {"op": "constant", "value": 4},
            },
        }
        candidate_target = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esi"},
                "right": {"op": "constant", "value": 4},
            },
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_call", "target": original_target,
                    "continuation": 1,
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_call", "target": candidate_target,
                    "continuation": 1,
                }},
            },
            {
                "original_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "eax"},
                }},
                "candidate_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "eax"},
                }},
            },
        ]
        dynamic_candidate = {
            "profile": "dynamic_range_code_pointer_call_v1",
            "source_region_index": 0,
            "range_relation": {
                "original": "ebx", "candidate": "esi",
                "original_offset": 8, "candidate_offset": 8,
                "required_words": [{"offset": 12, "kind": "codePointer"}],
            },
            "word_offset": 4,
            "continuation_target_id": 1,
        }
        graph = _relational_product_graph(
            contract, behaviors, {"edges": []}, [],
            original_image_base=0x400000,
            candidate_image_base=0x500000,
            dynamic_call_candidates=[dynamic_candidate],
        )

        self.assertEqual(graph["nodes"][0]["outgoing_edge_ids"], [0, 1])
        self.assertEqual(
            [edge["target_target_id"] for edge in graph["edges"]], [0, 1]
        )
        self.assertEqual(
            graph["edges"][0]["original_guard"],
            {
                "op": "or",
                "left": {
                    "op": "equal", "left": original_target,
                    "right": {"op": "constant", "value": 0x401004},
                },
                "right": {
                    "op": "equal", "left": original_target,
                    "right": {"op": "constant", "value": 0x401000},
                },
            },
        )
        self.assertEqual(
            graph["evidence"]["dynamic_range_indirect_call_edge_groups"],
            [{"source_node_id": 0, "candidate_index": 0, "edge_ids": [0, 1]}],
        )
        self.assertEqual(graph["evidence"]["declared_reachable_node_ids"], [0, 1])
        self.assertEqual(
            graph["evidence"]["decoded_control_complete_node_ids"], [0, 1]
        )
        self.assertEqual(graph["evidence"]["potential_control_cuts"], [])

        with self.assertRaisesRegex(StageAInputError, "duplicate dynamic"):
            _relational_product_graph(
                contract, behaviors, {"edges": []}, [],
                original_image_base=0x400000,
                candidate_image_base=0x500000,
                dynamic_call_candidates=[dynamic_candidate, dynamic_candidate],
            )

    def test_direct_call_reachability_includes_runtime_continuation_without_symbols(self):
        true_guard = {"op": "bool_constant", "value": True}
        regions = [
            {
                "id": name, "numeric_id": index, "root": index == 0,
                "original": {"rva_start": 0x1000 + index * 0x10},
                "candidate": {"rva_start": 0x1000 + index * 0x10},
            }
            for index, name in enumerate(("caller", "continuation", "callee"))
        ]
        contract = {
            "regions": regions,
            "code_targets": [
                {
                    "id": index, "region_index": index,
                    "original_rva": 0x1000 + index * 0x10,
                    "candidate_rva": 0x1000 + index * 0x10,
                }
                for index in range(3)
            ],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "call", "target": 2, "continuation": 1,
                }},
                "candidate_ir": {"outcome": {
                    "op": "call", "target": 2, "continuation": 1,
                }},
            },
            {
                "original_ir": {"outcome": {"op": "jump", "target": 0}},
                "candidate_ir": {"outcome": {"op": "jump", "target": 0}},
            },
            {
                "original_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "esp"},
                }},
                "candidate_ir": {"outcome": {
                    "op": "returned", "target": {"op": "input_reg", "reg": "esp"},
                }},
            },
        ]
        register_relations = {
            "edges": [
                {
                    "source_region_index": 0,
                    "target_region_index": 2,
                    "kind": "call",
                    "original_guard": true_guard,
                    "candidate_guard": true_guard,
                    "direct_call_push_claim": {
                        "continuation_region_index": 1,
                    },
                },
                {
                    "source_region_index": 1,
                    "target_region_index": 0,
                    "kind": "jump",
                    "original_guard": true_guard,
                    "candidate_guard": true_guard,
                    "direct_call_push_claim": None,
                },
            ],
        }

        graph = _relational_product_graph(
            contract, behaviors, register_relations, [],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        self.assertEqual(
            graph["evidence"]["declared_reachable_node_ids"], [0, 1, 2]
        )
        self.assertEqual(graph["evidence"]["runtime_call_continuations"], [{
            "source_node_id": 0,
            "continuation_node_ids": [1],
        }])
        self.assertNotIn("callReturn", [edge["kind"] for edge in graph["edges"]])

    def test_reachable_product_local_certificate_is_fail_closed_and_external_exact(self):
        base_evidence = {
            "declared_reachable_node_ids": [0],
            "decoded_control_complete_node_ids": [],
            "decoded_control_candidates": [],
            "reachable_locally_refined_edge_ids": [],
            "proved_edge_ids": [],
            "reachable_product_local_complete": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            (lean_dir / "StageA").mkdir()
            _write_reachable_product_local_certificate(
                lean_dir,
                {"evidence": base_evidence},
                [],
                [],
            )
            incomplete = (
                lean_dir / "StageA" /
                "RelationalReachableProductLocalCertificate.lean"
            ).read_text(encoding="utf-8")
            incomplete_evidence = (
                lean_dir / "StageA" /
                "RelationalReachableProductLocalEvidence.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "relationalProductLocalDecodedNodeIdsIncreasingChecked",
                incomplete_evidence,
            )
            self.assertNotIn(
                "RelationalProductGraphContext",
                incomplete_evidence,
            )
            self.assertNotIn("def reachableProductLocalCertificate", incomplete)

            external_evidence = {
                **base_evidence,
                "decoded_control_complete_node_ids": [0],
                "decoded_control_candidates": [{
                    "node_id": 0,
                    "region_index": 0,
                }],
                "reachable_locally_refined_edge_ids": [7],
                "reachable_product_local_complete": True,
            }
            _write_reachable_product_local_certificate(
                lean_dir,
                {"evidence": external_evidence},
                [],
                [{
                    "module": "RelationalExternalCallRefinementEdge7",
                    "edge_id": 7,
                    "source_region_index": 0,
                    "theorem": "externalCallEdge7ProductRefinementChecked",
                }],
            )
            external = (
                lean_dir / "StageA" /
                "RelationalReachableProductLocalCertificate.lean"
            ).read_text(encoding="utf-8")
            external_edge_chunk = (
                lean_dir / "StageA" /
                "RelationalReachableProductEdgeChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalExternalCallRefinementEdge7",
                external_edge_chunk,
            )
            self.assertIn(
                "externalCallEdge7ProductRefinementChecked",
                external_edge_chunk,
            )
            self.assertIn(
                "reachableProductEdgeChunk0ValidityChecked",
                external_edge_chunk,
            )
            self.assertIn("def reachableProductLocalCertificate", external)

            with self.assertRaisesRegex(
                StageAInputError,
                "lacks generated external refinement modules for 7",
            ):
                _write_reachable_product_local_certificate(
                    lean_dir,
                    {"evidence": external_evidence},
                    [],
                    [],
                )

    def test_external_register_argument_claims_fail_closed_on_affine_related_words(self):
        exact_source = {
            "input_relations": [{
                "original": "ebx", "candidate": "esi", "relation": "exact",
            }],
        }
        related_source = {
            "input_relations": [{
                "original": "ebx", "candidate": "esi", "relation": "related_word",
            }],
        }
        original = {
            "op": "add", "left": {"op": "input_reg", "reg": "ebx"},
            "right": {"op": "constant", "value": 32},
        }
        candidate = {
            "op": "add", "left": {"op": "input_reg", "reg": "esi"},
            "right": {"op": "constant", "value": 32},
        }

        claims, blocker = _external_argument_relation_claims(
            exact_source, [original], [candidate]
        )
        self.assertIsNone(blocker)
        self.assertEqual(claims, [{
            "kind": "register_word",
            "relation": exact_source["input_relations"][0],
            "offset": 32,
            "original_expression": original,
            "candidate_expression": candidate,
        }])

        claims, blocker = _external_argument_relation_claims(
            related_source, [original], [candidate]
        )
        self.assertIsNone(claims)
        self.assertIn("checked mapped-range witness", blocker)

    def test_external_stack_word_argument_claim_is_explicit_and_bounded(self):
        address = {
            "op": "add",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 4},
        }
        direct = {"op": "read32", "address": address}
        assembled = _semantic_affine_word_read("esp", 4)
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 0,
            "bytes_above": 16,
        }
        source = {"stack_windows": [window]}

        claims, blocker = _external_argument_relation_claims(
            source, [direct], [assembled]
        )

        self.assertIsNone(blocker)
        self.assertEqual(claims, [{
            "kind": "stack_word_read",
            "window": window,
            "offset": 4,
            "original_assembled_read": False,
            "candidate_assembled_read": True,
            "original_expression": direct,
            "candidate_expression": assembled,
        }])

        claims, blocker = _external_argument_relation_claims(
            {"stack_windows": [{**window, "bytes_above": 7}]},
            [direct], [assembled],
        )
        self.assertIsNone(claims)
        self.assertIn("lacks one checked source stack-window relation", blocker)

    def test_persistent_olean_cache_tracks_compiled_dependency_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            source = stage_a / "Consumer.lean"
            dependency_source = stage_a / "Dependency.lean"
            dependency_olean = stage_a / "Dependency.olean"
            (stage_a / "Formal.lean").write_text("def formal := 1\n")
            source.write_text("import StageA.Dependency\n")
            dependency_source.write_text("def dependency := 1\n")
            dependency_olean.write_bytes(b"compiled-v1")
            with patch.dict(os.environ, {
                "WINCR_STAGE_A_RELATIONAL_CACHE": str(root / "cache"),
            }):
                first = _persistent_olean_path(
                    root, "Consumer", source, [dependency_olean]
                )
                dependency_olean.write_bytes(b"compiled-v2")
                second = _persistent_olean_path(
                    root, "Consumer", source, [dependency_olean]
                )
            self.assertNotEqual(first, second)

    def test_relational_nix_build_command_disables_local_jobs_for_builders_file(self):
        builders_file = Path("/tmp/stage-a-builders")

        remote_command = _relational_nix_build_command("proof-expression", builders_file)
        local_command = _relational_nix_build_command("proof-expression", None)

        self.assertEqual(
            remote_command[:10],
            [
                "nix", "build", "--max-jobs", "0", "--cores", "2", "--builders",
                "@/tmp/stage-a-builders", "--no-link", "--json",
            ],
        )
        self.assertNotIn("--max-jobs", local_command)
        self.assertNotIn("--builders", local_command)

    def test_relational_nix_graph_does_not_prefer_local_derivations(self):
        evaluator = (
            Path(__file__).parents[1] / "nix" / "stage-a-lean-graph.nix"
        ).read_text(encoding="utf-8")

        self.assertNotIn("preferLocalBuild = true", evaluator)
        self.assertGreaterEqual(evaluator.count("preferLocalBuild = false"), 3)
        self.assertEqual(evaluator.count("lean -j 2"), 3)
        self.assertEqual(evaluator.count("ulimit -s unlimited"), 2)
        self.assertNotIn("dependencyClosures", evaluator)
        self.assertIn("node.dependencies", evaluator)
        self.assertIn("inherited-olean-index", evaluator)
        self.assertIn("inherited-node-result-index", evaluator)
        detached = evaluator.split("selectedNodeResults =", 1)[1].split(
            "\nin\n", 1
        )[0]
        self.assertIn("-detached", detached)
        self.assertIn('cp -L "${source}"/StageA/*.olean', detached)
        self.assertIn('cp "${source}/module-result.json"', detached)
        self.assertNotIn("inherited-olean-index", detached)
        self.assertNotIn("inherited-node-result-index", detached)

    def test_nix_finalization_closes_only_checked_external_call_candidates(self):
        proof_ir = {
            "status": "incomplete",
            "families": [],
            "obligations": [
                {
                    "id": "external-call-edge:7",
                    "kind": "external_call_product_edge_refinement",
                    "status": "pending_lean",
                    "edge_id": 7,
                },
                {
                    "id": "external-call-edge:8",
                    "kind": "external_call_product_edge_refinement",
                    "status": "incomplete",
                    "edge_id": 8,
                    "blocker": "missing contract",
                },
            ],
        }

        finalized = _finalize_nix_proof_ir(
            proof_ir,
            theorem_checked=True,
            theorem="StageA.GeneratedRelational.candidateRelationalImageCertificate",
            result_path=Path("/nix/store/stage-a-test"),
        )

        checked, gap = finalized["obligations"]
        self.assertEqual(checked["status"], "proved")
        self.assertEqual(
            checked["evidence"]["theorem"],
            "StageA.GeneratedRelational.externalCallEdge7ProductRefinementChecked",
        )
        self.assertEqual(gap["status"], "incomplete")
        self.assertEqual(finalized["status"], "incomplete")
        external_family = next(
            family for family in finalized["families"]
            if family["family"] == "paired_external_environment_refinement"
        )
        self.assertEqual(external_family["status"], "incomplete")

        proved_only = _finalize_nix_proof_ir(
            {**proof_ir, "obligations": [proof_ir["obligations"][0]]},
            theorem_checked=True,
            theorem="StageA.GeneratedRelational.candidateRelationalImageCertificate",
            result_path=Path("/nix/store/stage-a-test"),
        )
        proved_family = next(
            family for family in proved_only["families"]
            if family["family"] == "paired_external_environment_refinement"
        )
        self.assertEqual(proved_family["status"], "satisfied")

    def test_behavior_cache_hash_is_owned_by_decode_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "RelationalDecode.lean"
            source.write_text(
                "def decoderVersion := 1\n",
                encoding="utf-8",
            )
            initial = _relational_extraction_semantics_sha256(source)
            proof_source = Path(temporary) / "Relational.lean"
            proof_source.write_text("def proofVersion := 1\n", encoding="utf-8")
            proof_source.write_text("def proofVersion := 2\n", encoding="utf-8")
            self.assertEqual(
                _relational_extraction_semantics_sha256(source), initial
            )
            source.write_text(
                "def decoderVersion := 2\n",
                encoding="utf-8",
            )
            self.assertNotEqual(
                _relational_extraction_semantics_sha256(source), initial
            )

    def test_dynamic_range_indirect_call_requires_unique_typed_word(self):
        def read_target(register: str, offset: int) -> dict:
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": offset},
                },
            }

        behaviors = [{
            "original_ir": {
                "outcome": {
                    "op": "indirect_call", "target": read_target("ebx", 4),
                    "continuation": 9,
                },
            },
            "candidate_ir": {
                "outcome": {
                    "op": "indirect_call", "target": read_target("esi", 4),
                    "continuation": 9,
                },
            },
        }]
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 8, "candidate_offset": 8,
            "required_words": [{"offset": 12, "kind": "codePointer"}],
        }
        contract = {"regions": [{
            "id": "callback", "input_dynamic_range_relations": [relation],
        }]}

        candidates = _dynamic_range_indirect_call_candidates(contract, behaviors)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["word_offset"], 4)
        self.assertEqual(candidates[0]["range_relation"], relation)
        missing = {"regions": [{
            "id": "callback", "input_dynamic_range_relations": [],
        }]}
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(missing, behaviors), []
        )
        ambiguous = json.loads(json.dumps(contract))
        duplicate = json.loads(json.dumps(relation))
        duplicate["required_words"].append({"offset": 16, "kind": "dataPointer"})
        ambiguous["regions"][0]["input_dynamic_range_relations"].append(duplicate)
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(ambiguous, behaviors), []
        )
        mismatched = json.loads(json.dumps(behaviors))
        mismatched[0]["candidate_ir"]["outcome"]["target"] = read_target("esi", 8)
        self.assertEqual(
            _dynamic_range_indirect_call_candidates(contract, mismatched), []
        )

    def test_dynamic_range_relation_validation_fails_closed(self):
        valid = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 8, "kind": "codePointer"},
                {"offset": 4, "kind": "relatedWord"},
            ],
        }
        issues = []
        self.assertEqual(
            _dynamic_range_relations([valid], issues, "region", "input"),
            [{**valid, "required_words": list(reversed(valid["required_words"]))}],
        )
        self.assertEqual(issues, [])

        for malformed in (
            {**valid, "required_words": [{"offset": 4, "kind": "unknown"}]},
            {**valid, "required_words": [
                {"offset": 4, "kind": "relatedWord"},
                {"offset": 4, "kind": "codePointer"},
            ]},
            {**valid, "original_offset": 2**32},
        ):
            malformed_issues = []
            self.assertEqual(
                _dynamic_range_relations(
                    [malformed], malformed_issues, "region", "input"
                ),
                [],
            )
            self.assertEqual(malformed_issues[0]["severity"], "hard")

        duplicate_issues = []
        self.assertEqual(
            len(_dynamic_range_relations(
                [valid, valid], duplicate_issues, "region", "input"
            )),
            1,
        )
        self.assertEqual(duplicate_issues[0]["severity"], "hard")

    def test_static_dynamic_pointer_slot_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_path = root / "original.exe"
            candidate_path = root / "candidate.exe"
            original_path.write_bytes(_pe32_image_with_relocated_data(0x3000))
            candidate_path.write_bytes(_pe32_image_with_relocated_data(0x3000))
            original = _parse_stage_a_pe(original_path)
            candidate = _parse_stage_a_pe(candidate_path)
            valid = {
                "id": 3,
                "original_address": 0x403000,
                "candidate_address": 0x403000,
                "required_words": [
                    {"offset": 4, "kind": "codePointer"},
                    {"offset": 8, "kind": "nullableDynamicPointer"},
                ],
            }

            issues: list[dict] = []
            self.assertEqual(
                _static_dynamic_pointer_slots([valid], original, candidate, issues),
                [valid],
            )
            self.assertEqual(issues, [])

            malformed_cases = (
                ({**valid, "original_address": 0x401000},
                 "static_dynamic_pointer_slot_not_writable_data"),
                ({**valid, "required_words": [
                    {"offset": 4, "kind": "codePointer"},
                    {"offset": 6, "kind": "dataPointer"},
                ]}, "static_dynamic_pointer_slot_invalid"),
                ([valid, {**valid, "id": 4}],
                 "static_dynamic_pointer_slot_overlap"),
            )
            for malformed, category in malformed_cases:
                malformed_issues: list[dict] = []
                rows = malformed if isinstance(malformed, list) else [malformed]
                _static_dynamic_pointer_slots(
                    rows, original, candidate, malformed_issues
                )
                self.assertIn(
                    category, {issue["category"] for issue in malformed_issues}
                )
                self.assertTrue(all(
                    issue.get("severity") == "hard" for issue in malformed_issues
                ))

            iat_import = StageAImport(
                dll="fixture.dll", symbol="fixture", ordinal=None,
                thunk_rva=0x3000,
            )
            iat_issues: list[dict] = []
            _static_dynamic_pointer_slots(
                [valid], replace(original, imports=(iat_import,)), candidate,
                iat_issues,
            )
            self.assertIn(
                "static_dynamic_pointer_slot_overlaps_iat",
                {issue["category"] for issue in iat_issues},
            )

    def test_machine_import_call_contract_validation_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "fixture.exe"
            image.write_bytes(_pe32_image_with_relocated_data(0x3000))
            binary = replace(
                _parse_stage_a_pe(image),
                imports=(StageAImport(
                    dll="KERNEL32.dll", symbol="EnterCriticalSection",
                    ordinal=None, thunk_rva=0x3010,
                ),),
            )
            write_footprint = {
                "access": "write",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "fixed", "bytes": 24},
                "nullable": False,
            }
            valid = {
                "id": 4,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "stack_argument_offsets": [0],
                "stack_result_delta": 4,
                "preserved_registers": ["ebx", "esi", "edi", "ebp"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "memory_effect": "argumentRanges",
                "memory_footprints": [write_footprint],
                "world_effect": "opaqueResources",
            }
            issues: list[dict] = []
            normalized = _machine_import_call_contracts(
                [valid], binary, binary, issues
            )
            self.assertEqual(issues, [])
            self.assertEqual(normalized[0]["import"], {
                "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
            })
            self.assertEqual(
                normalized[0]["memory_footprints"], [write_footprint]
            )

            optional = {
                **valid,
                "memory_footprints": [{**write_footprint, "nullable": True}],
            }
            optional_issues: list[dict] = []
            normalized_optional = _machine_import_call_contracts(
                [optional], binary, binary, optional_issues
            )
            self.assertEqual(optional_issues, [])
            self.assertTrue(
                normalized_optional[0]["memory_footprints"][0]["nullable"]
            )

            templated = {
                "id": 4,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "memory_effect": "argumentRanges",
                "memory_footprints": [write_footprint],
                "world_effect": "opaqueResources",
            }
            template_issues: list[dict] = []
            normalized_template = _machine_import_call_contracts(
                [templated], binary, binary, template_issues
            )
            self.assertEqual(template_issues, [])
            self.assertEqual(
                normalized_template[0]["stack_argument_offsets"], [0]
            )
            self.assertEqual(normalized_template[0]["stack_result_delta"], 4)
            self.assertEqual(
                normalized_template[0]["preserved_registers"],
                ["ebp", "ebx", "edi", "esi"],
            )
            self.assertEqual(
                normalized_template[0]["clobbered_registers"],
                ["eax", "ecx", "edx"],
            )
            self.assertNotIn("abi_template", normalized_template[0])
            self.assertNotIn("argument_words", normalized_template[0])
            replay_issues: list[dict] = []
            self.assertEqual(
                _machine_import_call_contracts(
                    normalized_template, binary, binary, replay_issues
                ),
                normalized_template,
            )
            self.assertEqual(replay_issues, [])

            cdecl = {
                **templated,
                "abi_template": "pe32-cdecl-v1",
                "argument_words": 3,
            }
            cdecl_issues: list[dict] = []
            normalized_cdecl = _machine_import_call_contracts(
                [cdecl], binary, binary, cdecl_issues
            )
            self.assertEqual(cdecl_issues, [])
            self.assertEqual(
                normalized_cdecl[0]["stack_argument_offsets"], [0, 4, 8]
            )
            self.assertEqual(normalized_cdecl[0]["stack_result_delta"], 0)

            malformed_cases = (
                {**valid, "stack_argument_offsets": [2]},
                {**valid, "preserved_registers": ["ebx"]},
                {**valid, "memory_effect": "anything"},
                {**valid, "memory_effect": "opaqueStatic"},
                {**valid, "memory_footprints": []},
                {**valid, "memory_footprints": [{
                    **write_footprint, "base_argument": 1,
                }]},
                {**valid, "memory_footprints": [{
                    **write_footprint,
                    "size": {"kind": "fixed", "bytes": 0},
                }]},
                {**valid, "memory_footprints": [{
                    **write_footprint, "nullable": 1,
                }]},
                {**valid, "memory_footprints": [
                    write_footprint, write_footprint,
                ]},
                {**valid, "memory_footprints": [
                    write_footprint, {**write_footprint, "nullable": True},
                ]},
                {**valid, "memory_effect": "none"},
                {**valid, "memory_effect": "readOnly"},
                {**valid, "memory_footprints": [{
                    **write_footprint,
                    "size": {
                        "kind": "argument", "argument": 1, "scale": 1,
                    },
                }]},
                {**templated, "abi_template": "pe32-fastcall-v1"},
                {**templated, "memory_effect": None},
                {**templated, "stack_result_delta": 4},
                {**templated, "argument_words": 1025},
            )
            for malformed in malformed_cases:
                malformed_issues: list[dict] = []
                self.assertEqual(
                    _machine_import_call_contracts(
                        [malformed], binary, binary, malformed_issues
                    ),
                    [],
                )
                self.assertEqual(
                    malformed_issues[0]["category"],
                    "machine_import_call_contract_invalid",
                )
                self.assertEqual(malformed_issues[0]["severity"], "hard")

            missing_issues: list[dict] = []
            missing = {**valid, "import": {
                "dll": "kernel32.dll", "symbol": "TlsGetValue",
            }}
            self.assertEqual(
                _machine_import_call_contracts(
                    [missing], binary, binary, missing_issues
                ),
                [],
            )
            self.assertEqual(
                missing_issues[0]["category"],
                "machine_import_call_contract_import_mismatch",
            )

    def test_machine_import_call_analysis_requires_recovered_arguments(self):
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"EnterCriticalSection")},
        }
        contract = {
            "machine_import_call_contracts": [{
                "id": 4,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "stack_argument_offsets": [0],
            }],
            "regions": [{"id": "external"}],
        }
        behavior = {
            "outcome": {
                "op": "external_call", "import": imported,
                "arguments": [{"op": "constant", "value": 0x410064}],
                "continuation": 1,
            },
        }

        recovered = _machine_import_call_contract_analysis(contract, [{
            "original_ir": behavior, "candidate_ir": behavior,
        }])
        missing = _machine_import_call_contract_analysis(
            {**contract, "machine_import_call_contracts": []}, [{
                "original_ir": behavior, "candidate_ir": behavior,
            }],
        )

        self.assertEqual(recovered["counts"]["argument_recovery_candidates"], 1)
        self.assertTrue(recovered["calls"][0]["arguments_recovered"])
        self.assertEqual(missing["counts"]["incomplete_call_sites"], 1)
        self.assertIsNone(missing["calls"][0]["contract_id"])

    def test_machine_import_contract_cache_invalidation_is_region_local(self):
        contract = {
            "import": {
                "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
            },
        }
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"EnterCriticalSection")},
        }
        unrelated = {
            "semantic_ir": {"outcome": {"op": "jump", "target": 1}},
        }
        matching = {
            "semantic_ir": {
                "outcome": {"op": "external_call", "import": imported},
            },
        }

        self.assertFalse(
            _cached_behavior_affected_by_machine_contracts(unrelated, [contract])
        )
        self.assertTrue(
            _cached_behavior_affected_by_machine_contracts(matching, [contract])
        )

    def test_dynamic_range_transfer_requires_unique_identity_preservation(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [{"offset": 4, "kind": "codePointer"}],
        }
        contract = {"regions": [
            {"input_dynamic_range_relations": [relation]},
            {"input_dynamic_range_relations": [relation]},
        ]}
        identity = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        behaviors = [{
            "original_ir": {"registers": identity},
            "candidate_ir": {"registers": identity},
        }]

        claims = _dynamic_range_transfer_claims(contract, behaviors, 0, 1, {}, {})

        self.assertEqual(claims, [{
            "kind": "preserve",
            "source_relation": relation, "target_relation": relation,
        }])
        missing = json.loads(json.dumps(contract))
        missing["regions"][0]["input_dynamic_range_relations"] = []
        self.assertIsNone(
            _dynamic_range_transfer_claims(missing, behaviors, 0, 1, {}, {})
        )
        ambiguous = json.loads(json.dumps(contract))
        ambiguous["regions"][0]["input_dynamic_range_relations"].append(
            json.loads(json.dumps(relation))
        )
        self.assertIsNone(
            _dynamic_range_transfer_claims(ambiguous, behaviors, 0, 1, {}, {})
        )
        stronger_target = json.loads(json.dumps(contract))
        stronger_target["regions"][1]["input_dynamic_range_relations"][0][
            "required_words"
        ].append({"offset": 8, "kind": "dataPointer"})
        self.assertIsNone(
            _dynamic_range_transfer_claims(
                stronger_target, behaviors, 0, 1, {}, {}
            )
        )

    def test_dynamic_range_transfer_accepts_checked_nullable_next_pointer(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 4, "kind": "codePointer"},
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }
        contract = {"regions": [
            {"input_dynamic_range_relations": [relation]},
            {"input_dynamic_range_relations": [relation]},
        ]}

        def read(register):
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": 8},
                },
            }

        def nonzero(value):
            return {
                "op": "not",
                "value": {
                    "op": "equal",
                    "left": {"op": "bit_and", "left": value, "right": value},
                    "right": {"op": "constant", "value": 0},
                },
            }

        original_read = read("ebx")
        candidate_read = read("esi")
        behaviors = [{
            "original_ir": {"registers": {"ebx": original_read}},
            "candidate_ir": {"registers": {"esi": candidate_read}},
        }]
        claims = _dynamic_range_transfer_claims(
            contract, behaviors, 0, 1,
            nonzero(original_read), nonzero(candidate_read),
        )
        self.assertEqual(claims, [{
            "kind": "nullable_pointer",
            "source_relation": relation,
            "target_relation": relation,
            "pointer_offset": 8,
        }])

        bad_guard = {"op": "constant", "value": True}
        self.assertIsNone(_dynamic_range_transfer_claims(
            contract, behaviors, 0, 1, bad_guard, bad_guard,
        ))

    def test_dynamic_range_transfer_accepts_checked_static_pointer_seed(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 4, "kind": "codePointer"},
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }
        slot = {
            "id": 5,
            "original_address": 0x41005C,
            "candidate_address": 0x42006C,
            "required_words": relation["required_words"],
        }
        contract = {
            "static_dynamic_pointer_slots": [slot],
            "regions": [
                {"input_dynamic_range_relations": []},
                {"input_dynamic_range_relations": [relation]},
            ],
        }
        original_read = {
            "op": "read32",
            "address": {"op": "constant", "value": slot["original_address"]},
        }
        candidate_read = {
            "op": "read32",
            "address": {"op": "constant", "value": slot["candidate_address"]},
        }
        original_guard = _nonzero_word_guard(original_read)
        candidate_guard = _nonzero_word_guard(candidate_read)
        behaviors = [{
            "original_ir": {"registers": {"ebx": original_read}},
            "candidate_ir": {"registers": {"esi": candidate_read}},
        }]

        claims = _dynamic_range_transfer_claims(
            contract, behaviors, 0, 1, original_guard, candidate_guard,
        )

        self.assertEqual(claims, [{
            "kind": "static_pointer_seed",
            "slot": slot,
            "target_relation": relation,
        }])
        self.assertEqual(
            _static_dynamic_pointer_slot_guard_claim(
                contract, original_guard, candidate_guard,
            ),
            {
                "profile": "static_dynamic_pointer_guard_v1",
                "kind": "nonzero",
                "slot": slot,
            },
        )
        self.assertEqual(
            _static_dynamic_pointer_slot_guard_claim(
                contract, original_guard["value"], candidate_guard["value"],
            )["kind"],
            "zero",
        )
        self.assertEqual(
            _dynamic_range_register_output_claims(
                {"outputs": [{
                    "original": "ebx", "candidate": "esi",
                    "relation": "related_word",
                }], "output_claims": []},
                claims,
            )[0]["claim"]["kind"],
            "static_pointer_seed",
        )
        missing_slot_contract = json.loads(json.dumps(contract))
        missing_slot_contract["static_dynamic_pointer_slots"] = []
        diagnostic = _static_dynamic_pointer_seed_diagnostic(
            missing_slot_contract, behaviors,
            {"regions": [{"outputs": [{
                "original": "ebx", "candidate": "esi",
                "relation": "related_word",
            }]}]},
            {
                "original_guard": original_guard,
                "candidate_guard": candidate_guard,
            },
            0, 1,
        )
        self.assertEqual(diagnostic["status"], "incomplete")
        self.assertIn(
            "static_dynamic_pointer_slot_not_unique", diagnostic["blockers"]
        )
        self.assertIn("0x0041005c", diagnostic["next_action"])

    def test_dynamic_range_output_bridge_covers_only_matching_missing_word(self):
        output_eax = {
            "original": "eax", "candidate": "eax", "relation": "related_word",
        }
        output_ebx = {
            "original": "ebx", "candidate": "esi", "relation": "related_word",
        }
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }
        register_region = {
            "outputs": [output_eax, output_ebx],
            "output_claims": [{"kind": "identity", "output": output_eax}],
        }
        next_claim = {
            "kind": "nullable_pointer",
            "source_relation": relation,
            "target_relation": relation,
            "pointer_offset": 8,
        }
        self.assertEqual(
            _dynamic_range_register_output_claims(register_region, [next_claim]),
            [{"output": output_ebx, "claim": next_claim}],
        )

        unrelated = json.loads(json.dumps(next_claim))
        unrelated["target_relation"]["candidate"] = "ebx"
        self.assertIsNone(
            _dynamic_range_register_output_claims(register_region, [unrelated])
        )
        exact_output = json.loads(json.dumps(register_region))
        exact_output["outputs"][1]["relation"] = "exact"
        self.assertIsNone(
            _dynamic_range_register_output_claims(exact_output, [next_claim])
        )

    def test_dynamic_pointer_feedback_names_missing_range_shape_and_guard(self):
        relation = {
            "original": "ebx", "candidate": "esi",
            "original_offset": 0, "candidate_offset": 0,
            "required_words": [
                {"offset": 8, "kind": "nullableDynamicPointer"},
            ],
        }

        def read(register):
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": 8},
                },
            }

        original_read = read("ebx")
        candidate_read = read("esi")
        behaviors = [{
            "original_ir": {"registers": {"ebx": original_read}},
            "candidate_ir": {"registers": {"esi": candidate_read}},
        }]
        register_relations = {"regions": [{"outputs": [{
            "original": "ebx", "candidate": "esi", "relation": "related_word",
        }]}]}
        self.assertIsNone(_dynamic_pointer_traversal_diagnostic(
            {"regions": [{}, {}]}, behaviors, register_relations,
            {
                "original_guard": _nonzero_word_guard(original_read),
                "candidate_guard": _nonzero_word_guard(candidate_read),
            },
            0, 1,
        ))
        edge = {
            "original_guard": _nonzero_word_guard(original_read),
            "candidate_guard": _nonzero_word_guard(candidate_read),
        }
        missing = _dynamic_pointer_traversal_diagnostic(
            {"regions": [
                {"input_dynamic_range_relations": [relation]},
                {},
            ]},
            behaviors, register_relations, edge, 0, 1,
        )
        self.assertEqual(missing["status"], "incomplete")
        self.assertEqual(missing["word_offset"], 8)
        self.assertEqual(missing["original_source_register"], "ebx")
        self.assertEqual(missing["candidate_output_register"], "esi")
        self.assertEqual(missing["blockers"], [
            "successor_dynamic_range_relation_not_unique",
        ])
        self.assertIn("word offset 8", missing["next_action"])

        edge["original_guard"] = {"op": "bool_constant", "value": True}
        edge["candidate_guard"] = {"op": "bool_constant", "value": True}
        bad_guard = _dynamic_pointer_traversal_diagnostic(
            {"regions": [
                {"input_dynamic_range_relations": [relation]},
                {"input_dynamic_range_relations": [relation]},
            ]},
            behaviors, register_relations, edge, 0, 1,
        )
        self.assertEqual(
            bad_guard["blockers"], ["paired_nonzero_guard_not_exact"]
        )

        edge["original_guard"] = _nonzero_word_guard(original_read)
        edge["candidate_guard"] = _nonzero_word_guard(candidate_read)
        ready = _dynamic_pointer_traversal_diagnostic(
            {"regions": [
                {"input_dynamic_range_relations": [relation]},
                {"input_dynamic_range_relations": [relation]},
            ]},
            behaviors, register_relations, edge, 0, 1,
        )
        self.assertEqual(ready["status"], "ready_for_lean_replay")
        self.assertEqual(ready["blockers"], [])

    def test_dynamic_indirect_call_feedback_identifies_missing_world_evidence(self):
        target = {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {"op": "input_reg", "reg": "ebx"},
                "right": {"op": "constant", "value": 4},
            },
        }
        behaviors = [{
            "original_ir": {"outcome": {
                "op": "indirect_call", "target": target, "continuation": 1,
            }},
            "candidate_ir": {"outcome": {
                "op": "indirect_call", "target": target, "continuation": 1,
            }},
        }]
        attached = _attach_dynamic_indirect_call_analysis(
            {"obligations": [], "families": [], "status": "incomplete"},
            {"regions": [{"id": "dynamic-callback"}]},
            behaviors,
            [],
            {"evidence": {"reachable_decoded_control_frontier_node_ids": [0]}},
        )

        obligation = attached["obligations"][0]
        self.assertEqual(obligation["status"], "incomplete")
        self.assertEqual(
            obligation["repair_class"], "memory_loaded_code_pointer_relation"
        )
        self.assertIn("DynamicRegisterRangeRelation", obligation["next_action"])

    def test_relocated_readonly_function_pointer_call_emits_checked_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(
                _pe32_image_with_immutable_indirect_call(0x2000, callee_rva=0x1030)
            )
            candidate.write_bytes(
                _pe32_image_with_immutable_indirect_call(0x3000, callee_rva=0x1040)
            )
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "indirect-call",
                    "kind": "code",
                    "original": {"rva": 0x1000, "size": 29},
                    "candidate": {"rva": 0x1000, "size": 29},
                },
                {
                    "id": "continuation",
                    "kind": "code",
                    "original": {"rva": 0x101D, "size": 2},
                    "candidate": {"rva": 0x101D, "size": 2},
                },
                {
                    "id": "callee",
                    "kind": "code",
                    "original": {"rva": 0x1030, "size": 1},
                    "candidate": {"rva": 0x1040, "size": 1},
                },
                {
                    "id": "alignment-padding",
                    "kind": "padding",
                    "original": {"rva": 0x101F, "size": 17},
                    "candidate": {"rva": 0x101F, "size": 33},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"
            stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )

            report = root / "report"
            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["status"], "prepared", result)
            indirect = json.loads(
                (report / "relational-indirect-call-targets.json").read_text(
                    encoding="utf-8"
                )
            )["candidates"]
            self.assertEqual(len(indirect), 1)
            self.assertEqual(indirect[0]["profile"],
                             "immutable_relocated_function_pointer_call_v1")
            graph = json.loads(
                (report / "relational-product-graph.json").read_text(encoding="utf-8")
            )
            self.assertIn(
                indirect[0]["source_region_index"],
                graph["evidence"]["decoded_control_complete_node_ids"],
            )
            generated = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                )
            )
            self.assertIn("immutableIndirectCallTargetsClosed_of_checked", generated)
            self.assertIn("ImmutableIndirectCallTargetsClosed", generated)
            dynamic_certificate = (
                report
                / "lean"
                / "StageA"
                / "RelationalDynamicRangeIndirectCallCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("import StageA.RelationalComposition", dynamic_certificate)
            self.assertNotIn(
                "import StageA.RelationalProductGraphContext", dynamic_certificate
            )

            semantic = json.loads(
                (report / "relational-semantic-ir.json").read_text(encoding="utf-8")
            )
            behaviors = [
                {"original_ir": row["original"], "candidate_ir": row["candidate"]}
                for row in semantic["regions"]
            ]
            normalized = json.loads(
                (report / "relation-contract.json").read_text(encoding="utf-8")
            )
            normalized["regions"][indirect[0]["source_region_index"]][
                "address_separations"
            ] = []
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    _parse_stage_a_pe(original), _parse_stage_a_pe(candidate),
                    normalized, behaviors,
                ),
                [],
            )

            ambiguous = json.loads(
                (report / "relation-contract.json").read_text(encoding="utf-8")
            )
            duplicate = dict(ambiguous["code_targets"][indirect[0]["target_id"]])
            duplicate["id"] = max(
                target["id"] for target in ambiguous["code_targets"]
            ) + 1
            ambiguous["code_targets"].append(duplicate)
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    _parse_stage_a_pe(original), _parse_stage_a_pe(candidate),
                    ambiguous, behaviors,
                ),
                [],
            )

            writable = root / "writable.exe"
            writable.write_bytes(
                _pe32_image_with_immutable_indirect_call(0x2000, writable=True)
            )
            self.assertEqual(
                _immutable_indirect_call_candidates(
                    _parse_stage_a_pe(writable), _parse_stage_a_pe(candidate),
                    json.loads((report / "relation-contract.json").read_text()),
                    behaviors,
                ),
                [],
            )

    def test_relocated_readonly_function_pointer_jump_emits_checked_certificate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(
                _pe32_image_with_immutable_indirect_call(
                    0x2000, callee_rva=0x1030, jump=True,
                )
            )
            candidate.write_bytes(
                _pe32_image_with_immutable_indirect_call(
                    0x3000, callee_rva=0x1040, jump=True,
                )
            )
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "indirect-jump",
                    "kind": "code",
                    "original": {"rva": 0x1000, "size": 6},
                    "candidate": {"rva": 0x1000, "size": 6},
                },
                {
                    "id": "callee",
                    "kind": "code",
                    "original": {"rva": 0x1030, "size": 1},
                    "candidate": {"rva": 0x1040, "size": 1},
                },
                {
                    "id": "alignment-padding",
                    "kind": "padding",
                    "original": {"rva": 0x1006, "size": 42},
                    "candidate": {"rva": 0x1006, "size": 58},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"
            stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )

            report = root / "report"
            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["status"], "prepared", result)
            candidates = json.loads(
                (report / "relational-indirect-call-targets.json").read_text(
                    encoding="utf-8"
                )
            )["candidates"]
            self.assertEqual(len(candidates), 1)
            self.assertEqual(
                candidates[0]["profile"],
                "immutable_relocated_function_pointer_jump_v1",
            )
            graph = json.loads(
                (report / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(graph["edges"][0]["kind"], "jump")
            self.assertEqual(graph["counts"]["declared_reachable_nodes"], 2)
            self.assertEqual(
                graph["counts"]["reachable_decoded_control_frontier_nodes"], 0
            )
            segment_summary = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )["segment_refinement_summary"]
            self.assertEqual(segment_summary["proved"], 1)
            self.assertEqual(segment_summary["incomplete"], 0)
            acceptance = json.loads(
                (report / "whole-program-acceptance.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(acceptance["status"], "ready", acceptance)
            self.assertEqual(
                acceptance["theorem"],
                "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
            )
            progress = json.loads(
                (report / "composition-progress.json").read_text(encoding="utf-8")
            )
            self.assertEqual(progress["frontiers"]["decoded_control_node_ids"], [])
            self.assertEqual(progress["frontiers"]["segment_edge_ids"], [])
            generated = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalProductDecodedControlChunk*.lean"
                )
            )
            self.assertIn(
                "immutableIndirectJumpTargetsClosed_of_checked", generated
            )
            self.assertIn("ImmutableIndirectJumpTargetsClosed", generated)
            generated_segment = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (report / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementChunk*.lean"
                )
            )
            self.assertIn(
                "productNode0ImmutableIndirectJumpClosed", generated_segment
            )
            checked = _run_lean_relational(
                report / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(checked["status"], "checked", checked)

    def test_constant_guard_classifier_fails_closed(self):
        self.assertFalse(_semantic_constant_bool({
            "op": "not",
            "value": {
                "op": "equal",
                "left": {"op": "constant", "value": 0},
                "right": {"op": "constant", "value": 0},
            },
        }))
        self.assertIsNone(_semantic_constant_bool({
            "op": "not", "value": {"op": "input_flag", "index": 6},
        }))
        self.assertIsNone(_semantic_constant_bool({
            "op": "equal",
            "left": {"op": "read32", "address": {"op": "input_reg", "reg": "eax"}},
            "right": {"op": "constant", "value": 0},
        }))

    def test_iat_import_register_seeds_require_unique_matching_imports(self):
        def imported(symbol: str, thunk_rva: int):
            return SimpleNamespace(
                dll="kernel32.dll", symbol=symbol, ordinal=None,
                thunk_rva=thunk_rva,
            )

        original = SimpleNamespace(
            image_base=0x400000,
            imports=(imported("TlsGetValue", 0x2000),),
        )
        candidate = SimpleNamespace(
            image_base=0x500000,
            imports=(imported("TlsGetValue", 0x3000),),
        )
        behaviors = [{
            "original_ir": {"registers": {
                "ebp": {"op": "read32", "address": {
                    "op": "constant", "value": 0x402000,
                }},
            }},
            "candidate_ir": {"registers": {
                "edi": {"op": "read32", "address": {
                    "op": "constant", "value": 0x503000,
                }},
            }},
        }]

        seeds = _iat_import_register_seed_candidates(
            original, candidate, behaviors
        )
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["original_register"], "ebp")
        self.assertEqual(seeds[0]["candidate_register"], "edi")
        self.assertEqual(seeds[0]["import"]["symbol"], "TlsGetValue")

        duplicate = SimpleNamespace(
            image_base=0x400000,
            imports=(
                imported("TlsGetValue", 0x2000),
                imported("TlsGetValue", 0x2000),
            ),
        )
        self.assertEqual(
            _iat_import_register_seed_candidates(duplicate, candidate, behaviors),
            [],
        )
        mismatch = SimpleNamespace(
            image_base=0x500000,
            imports=(imported("GetLastError", 0x3000),),
        )
        self.assertEqual(
            _iat_import_register_seed_candidates(original, mismatch, behaviors),
            [],
        )

    def test_assembled_iat_import_seed_emits_complete_write_separations(self):
        def imported(thunk_rva: int):
            return SimpleNamespace(
                dll="msvcrt.dll", symbol="_errno", ordinal=None,
                thunk_rva=thunk_rva,
            )

        original = SimpleNamespace(
            image_base=0x400000, imports=(imported(0x2000),),
        )
        candidate = SimpleNamespace(
            image_base=0x500000, imports=(imported(0x3000),),
        )

        def assembled(base: int, register: str):
            write = {
                "write_address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": 1152},
                },
                "write_value": {"op": "constant", "value": 0},
            }

            def byte(offset: int, shift: int):
                read = {
                    "op": "read8_after_write",
                    "prior": {
                        "op": "read8",
                        "address": {"op": "constant", "value": base + offset},
                    },
                    **write,
                }
                return read if shift == 0 else {
                    "op": "shift_left", "value": read, "amount": shift,
                }

            return {
                "op": "bit_or",
                "left": {
                    "op": "bit_or", "left": byte(0, 0), "right": byte(1, 8),
                },
                "right": {
                    "op": "bit_or", "left": byte(2, 16), "right": byte(3, 24),
                },
            }

        behaviors = [{
            "original_ir": {"registers": {"ecx": assembled(0x402000, "esp")}},
            "candidate_ir": {"registers": {"ecx": assembled(0x503000, "esp")}},
        }]
        seeds = _iat_import_register_seed_candidates(original, candidate, behaviors)
        self.assertEqual(len(seeds), 1)
        self.assertEqual(seeds[0]["profile"], "assembled_iat_register_seed_v1")
        self.assertTrue(seeds[0]["assembled_read"])
        self.assertEqual(len(seeds[0]["original_writes"]), 1)

        contract = {"regions": [{"address_separations": []}]}
        refined = _attach_import_seed_address_separations(contract, seeds)
        separations = refined["regions"][0]["address_separations"]
        self.assertEqual(len(separations), 16)
        self.assertEqual(
            {
                (row["original_offset"], row["original_address"])
                for row in separations
            },
            {
                (1152 + write_byte, 0x402000 + word_byte)
                for word_byte in range(4) for write_byte in range(4)
            },
        )

        incomplete = json.loads(json.dumps(seeds[0]))
        incomplete["candidate_writes"] = []
        unchanged = _attach_import_seed_address_separations(contract, [incomplete])
        self.assertEqual(unchanged, contract)

    def test_stack_windows_propagate_identity_edges_and_fail_closed_at_frontier(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        separation = {
            "original_register": "esp", "candidate_register": "esp",
            "original_offset": 1155, "candidate_offset": 1155,
            "original_address": 0x402000, "candidate_address": 0x402000,
        }
        contract = {"regions": [
            {"id": "source", "address_separations": []},
            {"id": "middle", "address_separations": []},
            {"id": "sink", "address_separations": [separation]},
        ]}
        identity = {"op": "input_reg", "reg": "esp"}
        behaviors = [
            {
                "original_ir": {"registers": {"esp": identity}},
                "candidate_ir": {"registers": {"esp": identity}},
            }
            for _ in contract["regions"]
        ]
        edges = {"edges": [
            {"source_region_index": 0, "target_region_index": 1,
             "environment_barrier": False},
            {"source_region_index": 1, "target_region_index": 2,
             "environment_barrier": False},
        ]}
        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, edges, binary, binary
        )
        self.assertEqual(analysis["windows"], 3)
        self.assertEqual(analysis["separation_claims"], 1)
        self.assertEqual(
            [region["stack_windows"][0]["bytes_above"] for region in refined["regions"]],
            [1156, 1156, 1156],
        )
        self.assertEqual(analysis["frontier"], [{
            "region_index": 0,
            "original_register": "esp",
            "candidate_register": "esp",
            "bytes_below": 0,
            "bytes_above": 1156,
            "reason": "no_checked_incoming_edge",
        }])

        affine = json.loads(json.dumps(behaviors))
        adjustment = {
            "op": "sub", "left": identity,
            "right": {"op": "constant", "value": 4},
        }
        affine[1]["original_ir"]["registers"]["esp"] = adjustment
        affine[1]["candidate_ir"]["registers"]["esp"] = adjustment
        adjusted, adjusted_analysis = _attach_stack_window_invariants(
            contract, affine, edges, binary, binary
        )
        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in adjusted["regions"]
        ], [(4, 1152), (4, 1152), (0, 1156)])
        self.assertEqual(adjusted_analysis["frontier"][0]["bytes_below"], 4)
        identity_claims = _stack_window_transfer_claims(
            adjusted["regions"][0], adjusted["regions"][1], affine[0]
        )
        self.assertEqual(identity_claims[0]["adjustment"]["kind"], "identity")
        affine_claims = _stack_window_transfer_claims(
            adjusted["regions"][1], adjusted["regions"][2], affine[1]
        )
        self.assertEqual(affine_claims[0]["adjustment"], {
            "kind": "subtract", "amount": 4,
        })

        relation_rows = {
            "regions": [
                {
                    "inputs": [{"original": "esp", "candidate": "esp",
                                "relation": "related_word"}],
                    "outputs": [{"original": "esp", "candidate": "esp",
                                 "relation": "related_word"}],
                    "exact_output_claims": [],
                    "output_claims": [{
                        "kind": "identity",
                        "input": {"original": "esp", "candidate": "esp",
                                  "relation": "related_word"},
                        "output": {"original": "esp", "candidate": "esp",
                                   "relation": "related_word"},
                    }],
                }
                for _ in adjusted["regions"]
            ],
            "edges": edges["edges"],
        }
        for region in adjusted["regions"]:
            region["input_relations"] = [{
                "original": "esp", "candidate": "esp", "relation": "related_word",
            }]
            region["output_relations"] = [{
                "original": "esp", "candidate": "esp", "relation": "related_word",
            }]
        lowered, lowered_rows = _lower_stack_register_relations(
            adjusted, relation_rows
        )
        self.assertEqual(lowered["regions"][1]["input_relations"], [])
        self.assertEqual(lowered_rows["regions"][1]["inputs"], [])
        self.assertEqual(lowered_rows["regions"][1]["outputs"], [])
        self.assertTrue(
            lowered_rows["regions"][1]["fully_supported_output_transfer"]
        )
        self.assertEqual(lowered_rows["regions"][2]["output_claims"], [])
        self.assertFalse(
            lowered_rows["regions"][2]["fully_supported_output_transfer"]
        )

        nonidentity = json.loads(json.dumps(behaviors))
        nonidentity[1]["candidate_ir"]["registers"]["esp"] = {
            "op": "sub", "left": identity,
            "right": {"op": "constant", "value": 4},
        }
        stopped, stopped_analysis = _attach_stack_window_invariants(
            contract, nonidentity, edges, binary, binary
        )
        self.assertEqual(stopped["regions"][0]["stack_windows"], [])
        self.assertEqual(
            stopped_analysis["frontier"][0]["reason"],
            "non_identity_or_environment_stack_transfer",
        )

        outside = json.loads(json.dumps(contract))
        outside["regions"][2]["address_separations"][0]["original_address"] = 0x500000
        ignored, ignored_analysis = _attach_stack_window_invariants(
            outside, behaviors, edges, binary, binary
        )
        self.assertEqual(ignored_analysis["windows"], 0)
        self.assertTrue(all(not region["stack_windows"] for region in ignored["regions"]))

    def test_stack_window_cycles_require_zero_net_stack_delta(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        identity = {"op": "input_reg", "reg": "esp"}

        def adjusted(operation: str, amount: int) -> dict[str, object]:
            return {
                "op": operation,
                "left": identity,
                "right": {"op": "constant", "value": amount},
            }

        def behavior(stack, *, seed=False):
            ir = {"registers": {"esp": stack}}
            if seed:
                ir["writes"] = [{
                    "address": identity,
                    "value": {"op": "constant", "value": 1},
                }]
            return {
                "original_ir": json.loads(json.dumps(ir)),
                "candidate_ir": json.loads(json.dumps(ir)),
            }

        contract = {"regions": [
            {"id": "first", "address_separations": []},
            {"id": "second", "address_separations": []},
        ]}
        edges = {"edges": [
            {"source_region_index": 0, "target_region_index": 1,
             "environment_barrier": False},
            {"source_region_index": 1, "target_region_index": 0,
             "environment_barrier": False},
        ]}

        zero_net, zero_net_analysis = _attach_stack_window_invariants(
            contract,
            [
                behavior(adjusted("sub", 4)),
                behavior(adjusted("add", 4), seed=True),
            ],
            edges, binary, binary,
        )
        self.assertEqual(zero_net_analysis["nonzero_stack_delta_cycle_nodes"], 0)
        self.assertNotIn(
            "nonzero_stack_delta_cycle_requires_relational_frame",
            {row["reason"] for row in zero_net_analysis["frontier"]},
        )
        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in zero_net["regions"]
        ], [(4, 1), (0, 5)])

        nonzero, nonzero_analysis = _attach_stack_window_invariants(
            contract,
            [behavior(adjusted("sub", 4)), behavior(identity, seed=True)],
            edges, binary, binary,
        )
        self.assertEqual(nonzero_analysis["nonzero_stack_delta_cycle_nodes"], 2)
        self.assertEqual(nonzero_analysis["requirement_updates"], 0)
        self.assertEqual(
            {row["reason"] for row in nonzero_analysis["frontier"]},
            {"nonzero_stack_delta_cycle_requires_relational_frame"},
        )
        self.assertEqual(nonzero["regions"][0]["stack_windows"], [])
        self.assertEqual(
            (nonzero["regions"][1]["stack_windows"][0]["bytes_below"],
             nonzero["regions"][1]["stack_windows"][0]["bytes_above"]),
            (0, 4),
        )

    def test_stack_windows_propagate_across_machine_call_stack_cleanup(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            pe=SimpleNamespace(
                OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x10000),
            ),
        )
        imported = {
            "dll": list(b"kernel32.dll"),
            "name": {"op": "symbol", "bytes": list(b"EnterCriticalSection")},
        }
        identity = {"op": "input_reg", "reg": "esp"}

        def subtract(amount):
            return {
                "op": "sub", "left": identity,
                "right": {"op": "constant", "value": amount},
            }

        contract = {
            "machine_import_call_contracts": [{
                "id": 0,
                "import": {
                    "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
                },
                "stack_result_delta": 4,
            }],
            "regions": [
                {"id": "call", "numeric_id": 0, "address_separations": [],
                 "output_relations": []},
                {"id": "continuation", "numeric_id": 1,
                 "address_separations": []},
                {"id": "sink", "numeric_id": 2,
                 "address_separations": []},
            ],
        }
        call_outcome = {"op": "external_call", "import": imported}
        behaviors = [
            {
                "original_ir": {
                    "registers": {"esp": subtract(28)},
                    "outcome": call_outcome,
                },
                "candidate_ir": {
                    "registers": {"esp": subtract(28)},
                    "outcome": call_outcome,
                },
            },
            {
                "original_ir": {"registers": {"esp": subtract(4)}},
                "candidate_ir": {"registers": {"esp": subtract(4)}},
            },
            {
                "original_ir": {
                    "registers": {"esp": identity},
                    "writes": [{
                        "address": {"op": "add", "left": identity,
                                    "right": {"op": "constant", "value": 0}},
                        "value": {"op": "constant", "value": 1},
                    }],
                },
                "candidate_ir": {
                    "registers": {"esp": identity},
                    "writes": [{
                        "address": {"op": "add", "left": identity,
                                    "right": {"op": "constant", "value": 0}},
                        "value": {"op": "constant", "value": 1},
                    }],
                },
            },
        ]
        unconditional = {"op": "bool_constant", "value": True}
        edges = {
            "regions": [{"output_claims": []}, {}, {}],
            "edges": [
            {"source_region_index": 0, "target_region_index": 1,
             "environment_barrier": True,
             "original_guard": unconditional,
             "candidate_guard": unconditional},
            {"source_region_index": 1, "target_region_index": 2,
             "environment_barrier": False},
        ]}

        refined, analysis = _attach_stack_window_invariants(
            contract, behaviors, edges, binary, binary
        )

        self.assertEqual([
            (region["stack_windows"][0]["bytes_below"],
             region["stack_windows"][0]["bytes_above"])
            for region in refined["regions"]
        ], [(28, 1), (4, 1), (0, 4)])
        self.assertNotIn(
            "unsupported_environment_stack_transfer",
            {item["reason"] for item in analysis["frontier"]},
        )
        sites = _external_call_site_candidates(
            refined, behaviors, edges
        )
        self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
        self.assertEqual(
            sites["candidates"][0]["boundary_invariant"]["stack_windows"][0]
            ["bytes_below"],
            0,
        )
        self.assertEqual(
            sites["candidates"][0]["boundary_invariant"]["stack_windows"][0]
            ["bytes_above"],
            29,
        )
        self.assertEqual(
            sites["candidates"][0]["stack_transfer_claims"][0]["adjustment"],
            {"kind": "subtract", "amount": 28},
        )
        self.assertEqual(
            sites["candidates"][0]["proof_profile"],
            "paired_constant_arguments_external_call_v1",
        )
        attached = _attach_external_call_site_analysis(
            {"obligations": [], "families": []}, sites
        )
        self.assertEqual(
            attached["external_call_summary"], {"candidates": 1, "gaps": 0}
        )
        self.assertEqual(
            attached["obligations"][0]["status"], "pending_lean"
        )
        self.assertEqual(
            attached["obligations"][0]["edge_id"], 0
        )

        unresolved = json.loads(json.dumps(behaviors))
        unresolved_argument = {"op": "input_reg", "reg": "esp"}
        unresolved[0]["original_ir"]["outcome"]["arguments"] = [
            unresolved_argument
        ]
        unresolved[0]["candidate_ir"]["outcome"]["arguments"] = [
            unresolved_argument
        ]
        incomplete = _external_call_site_candidates(
            refined, unresolved, edges
        )
        self.assertEqual(incomplete["counts"], {"candidates": 0, "gaps": 1})
        self.assertEqual(
            incomplete["gaps"][0]["reason"],
            "external argument 0 lacks one unambiguous source register relation",
        )
        incomplete_attached = _attach_external_call_site_analysis(
            {"obligations": [], "families": []}, incomplete
        )
        self.assertEqual(
            incomplete_attached["obligations"][0]["status"], "incomplete"
        )
        self.assertIn(
            "argument expressions related",
            incomplete_attached["obligations"][0]["next_action"],
        )

        uncontracted = json.loads(json.dumps(refined))
        uncontracted["machine_import_call_contracts"] = []
        missing_contract = _external_call_site_candidates(
            uncontracted, behaviors, edges
        )
        self.assertEqual(missing_contract["counts"], {"candidates": 0, "gaps": 1})
        self.assertEqual(missing_contract["gaps"][0]["original_import"], {
            "dll": "kernel32.dll", "symbol": "EnterCriticalSection",
        })
        missing_attached = _attach_external_call_site_analysis(
            {"obligations": [], "families": []}, missing_contract
        )
        self.assertIn(
            "kernel32.dll!EnterCriticalSection",
            missing_attached["obligations"][0]["next_action"],
        )
        self.assertIn(
            "explicitly declare memory and world effects",
            missing_attached["obligations"][0]["next_action"],
        )

    def test_register_import_call_is_externalized_only_with_checked_target(self):
        stack = {"op": "input_reg", "reg": "esp"}
        pushed_stack = {
            "op": "add", "left": stack,
            "right": {"op": "constant", "value": 2**32 - 4},
        }
        behavior = {
            "registers": {
                "esp": pushed_stack,
                "ebp": {"op": "input_reg", "reg": "ebp"},
                "ebx": {"op": "input_reg", "reg": "ebx"},
                "edi": {"op": "input_reg", "reg": "edi"},
                "esi": {"op": "input_reg", "reg": "esi"},
            },
            "writes": [
                {"address": stack, "value": {"op": "constant", "value": 7}},
                {"address": pushed_stack,
                 "value": {"op": "constant", "value": 0x401234}},
            ],
            "outcome": {
                "op": "indirect_call",
                "target": {"op": "input_reg", "reg": "ebp"},
                "continuation": 1,
            },
            "x87": {},
        }
        contract = {
            "machine_import_call_contracts": [{
                "id": 4,
                "import": {"dll": "kernel32.dll", "symbol": "TlsGetValue"},
                "stack_argument_offsets": [0],
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            }],
            "regions": [
                {
                    "id": "call", "numeric_id": 0,
                    "input_relations": [
                        {"original": register, "candidate": register,
                         "relation": "related_word"}
                        for register in ("ebx", "edi", "esi")
                    ],
                    "input_import_relations": [{
                        "original": "ebp", "candidate": "ebp",
                        "import": {
                            "dll": "kernel32.dll", "symbol": "TlsGetValue",
                        },
                    }],
                    "output_relations": [], "output_import_relations": [],
                    "output_dynamic_range_relations": [], "flag_outputs": [],
                },
                {"id": "continuation", "numeric_id": 1},
            ],
        }
        relations = {
            "regions": [{"output_claims": [
                {
                    "kind": "identity",
                    "input": {"original": register, "candidate": register,
                              "relation": "related_word"},
                    "output": {"original": register, "candidate": register,
                               "relation": "related_word"},
                }
                for register in ("ebx", "edi", "esi")
            ]}, {}],
            "edges": [{
                "source_region_index": 0,
                "target_region_index": 1,
                "environment_barrier": True,
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
            }],
        }
        call = {
            "profile": "inductive_iat_register_call_v1",
            "source_region_index": 0,
            "continuation_region_index": 1,
            "original_register": "ebp",
            "candidate_register": "ebp",
            "import": {"dll": "kernel32.dll", "symbol": "TlsGetValue"},
        }
        analysis = _external_call_site_candidates(
            contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            relations,
            [call],
        )
        self.assertEqual(analysis["counts"], {"candidates": 1, "gaps": 0})
        self.assertEqual(
            analysis["candidates"][0]["dispatch_profile"],
            "checked_import_register",
        )
        self.assertEqual(
            analysis["candidates"][0]["dispatch_registers"],
            {"original": "ebp", "candidate": "ebp"},
        )
        self.assertEqual(analysis["candidates"][0]["argument_values"], [7])

        missing_target = _external_call_site_candidates(
            contract,
            [{"original_ir": behavior, "candidate_ir": behavior}],
            relations,
            [],
        )
        self.assertEqual(missing_target["counts"], {"candidates": 0, "gaps": 1})
        self.assertIn("unambiguous checked import-register target",
                      missing_target["gaps"][0]["reason"])

    def test_iat_read_classification_fails_closed(self):
        binary = SimpleNamespace(
            image_base=0x400000,
            imports=[SimpleNamespace(
                thunk_rva=0x2000,
                dll="kernel32.dll",
                symbol="TlsGetValue",
                ordinal=None,
            )],
        )

        exact = _iat_read_classification(binary, {
            "constant_address": 0x402000, "width": 4,
        })
        self.assertEqual(exact, {
            "status": "exact_iat_cell",
            "proof_role": "requires_import_address_pair_witness",
            "iat_rva": 0x2000,
            "import": {"dll": "kernel32.dll", "symbol": "TlsGetValue"},
        })
        self.assertEqual(
            _iat_read_classification(binary, {
                "constant_address": 0x401000, "width": 4,
            })["status"],
            "statically_outside_iat",
        )
        self.assertEqual(
            _iat_read_classification(binary, {
                "constant_address": 0x402001, "width": 1,
            })["status"],
            "partial_iat_overlap_unsupported",
        )
        self.assertEqual(
            _iat_read_classification(binary, {
                "constant_address": None, "width": 4,
            })["status"],
            "dynamic_address_requires_non_iat_proof",
        )

        def byte(offset, shift):
            read = {
                "op": "read8",
                "address": {"op": "constant", "value": 0x402000 + offset},
            }
            return read if shift == 0 else {
                "op": "shift_left", "value": read, "amount": shift,
            }

        assembled = {
            "op": "bit_or",
            "left": {
                "op": "bit_or", "left": byte(0, 0), "right": byte(1, 8),
            },
            "right": {
                "op": "bit_or", "left": byte(2, 16), "right": byte(3, 24),
            },
        }
        self.assertEqual(
            _assembled_iat_read_candidates(binary, {
                "registers": {"ecx": assembled},
            })[0]["status"],
            "exact_iat_cell",
        )

    def test_assembled_iat_write_separation_is_a_first_class_obligation(self):
        candidate = {
            "register": "ecx",
            "iat_rva": 0x2000,
            "import": {"dll": "msvcrt.dll", "symbol": "_errno"},
            "intervening_register_writes": 1,
            "status": "requires_intervening_write_separation",
            "next_action": "prove separation",
        }
        attached = _attach_import_register_analysis(
            {"obligations": [], "families": [], "status": "incomplete"},
            [],
            {
                "counts": {"seeds": 0, "relations": 0, "indirect_import_calls": 0},
                "relations": [],
                "indirect_import_calls": [],
            },
            [],
            {"regions": [{
                "index": 7,
                "id": "assembled-iat",
                "assembled_iat_read_candidates": {
                    "original": [candidate], "candidate": [candidate],
                },
            }]},
        )

        obligation = next(
            item for item in attached["obligations"]
            if item["kind"] == "assembled_iat_register_seed"
        )
        self.assertEqual(obligation["region_index"], 7)
        self.assertEqual(obligation["register"], "ecx")
        self.assertEqual(obligation["status"], "incomplete")

    def test_import_register_inference_requires_inductive_abi_preservation(self):
        imported = {"dll": "kernel32.dll", "symbol": "TlsGetValue"}

        def identity_registers():
            return {
                register: {"op": "input_reg", "reg": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            }

        contract = {"regions": [
            {"numeric_id": 0}, {"numeric_id": 1}, {"numeric_id": 2},
        ]}
        behaviors = [
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "ebp"},
                        "continuation": 2,
                    },
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {
                        "op": "indirect_call",
                        "target": {"op": "input_reg", "reg": "edi"},
                        "continuation": 2,
                    },
                },
            },
            {
                "original_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
                "candidate_ir": {
                    "registers": identity_registers(),
                    "outcome": {"op": "jump", "target": 1},
                },
            },
        ]
        seeds = [{
            "region_index": 0,
            "original_register": "ebp",
            "candidate_register": "edi",
            "import": imported,
        }]
        analysis = _infer_import_register_invariants(contract, behaviors, seeds)
        self.assertEqual(analysis["counts"]["indirect_import_calls"], 1, analysis)
        self.assertEqual(
            {row["region_index"] for row in analysis["relations"]}, {1, 2}
        )

        volatile_seeds = [{
            "region_index": 0,
            "original_register": "eax",
            "candidate_register": "eax",
            "import": imported,
        }]
        volatile_behaviors = json.loads(json.dumps(behaviors))
        for side in ("original_ir", "candidate_ir"):
            volatile_behaviors[1][side]["outcome"]["target"]["reg"] = "eax"
        volatile = _infer_import_register_invariants(
            contract, volatile_behaviors, volatile_seeds
        )
        self.assertEqual(volatile["relations"], [], volatile)
        self.assertEqual(volatile["indirect_import_calls"], [], volatile)

    def test_import_register_transfer_claims_are_unique_and_fail_closed(self):
        imported = {"dll": "kernel32.dll", "symbol": "TlsGetValue"}
        relation = {
            "original": "ebp", "candidate": "edi", "import": imported,
        }
        contract = {"regions": [
            {"input_import_relations": []},
            {"input_import_relations": [relation]},
        ]}
        behaviors = [{
            "original_ir": {"registers": {"ebp": {"op": "input_reg", "reg": "ebp"}}},
            "candidate_ir": {"registers": {"edi": {"op": "input_reg", "reg": "edi"}}},
        }, {"original_ir": {}, "candidate_ir": {}}]
        seed = {
            "profile": "iat_register_seed_v1",
            "region_index": 0,
            "original_register": "ebp",
            "candidate_register": "edi",
            "original_iat_rva": 0x2200,
            "candidate_iat_rva": 0x2300,
            "import": imported,
        }
        claims = _import_register_transfer_claims(contract, behaviors, 0, 1, [seed])
        self.assertEqual([claim["kind"] for claim in claims or []], ["seed"])
        self.assertIsNone(
            _import_register_transfer_claims(contract, behaviors, 0, 1, [seed, seed])
        )

        contract["regions"][0]["input_import_relations"] = [relation]
        claims = _import_register_transfer_claims(contract, behaviors, 0, 1, [])
        self.assertEqual([claim["kind"] for claim in claims or []], ["preserve"])
        self.assertIsNone(
            _import_register_transfer_claims(contract, behaviors, 0, 1, [seed])
        )
        behaviors[0]["candidate_ir"]["registers"]["edi"] = {
            "op": "input_reg", "reg": "eax",
        }
        self.assertIsNone(
            _import_register_transfer_claims(contract, behaviors, 0, 1, [])
        )

    def test_related_word_zero_guard_claim_supports_negation_but_not_other_shapes(self):
        source = {"input_relations": [{
            "original": "esi", "candidate": "edi", "relation": "related_word",
        }]}
        zero = {
            "op": "equal",
            "left": {
                "op": "bit_and",
                "left": {"op": "input_reg", "reg": "esi"},
                "right": {"op": "input_reg", "reg": "esi"},
            },
            "right": {"op": "constant", "value": 0},
        }
        candidate_zero = json.loads(json.dumps(zero))
        candidate_zero["left"]["left"]["reg"] = "edi"
        candidate_zero["left"]["right"]["reg"] = "edi"
        claim = _related_word_zero_guard_claim(
            source, {"op": "not", "value": zero},
            {"op": "not", "value": candidate_zero},
        )
        self.assertEqual(claim, {
            "profile": "related_word_zero_guard_v1",
            "original_register": "esi",
            "candidate_register": "edi",
            "value_relation": "related_word",
            "not_count": 1,
        })
        mismatched = json.loads(json.dumps(candidate_zero))
        mismatched["right"]["value"] = 1
        self.assertIsNone(_related_word_zero_guard_claim(source, zero, mismatched))

    def test_paired_stack_guard_claim_requires_unique_covered_reads(self):
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "ebp",
            "bytes_below": 0,
            "bytes_above": 128,
        }
        source = {"stack_windows": [window]}

        def read(register, offset):
            return {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": register},
                    "right": {"op": "constant", "value": offset},
                },
            }

        def zero_guard(register, offset, not_count=0):
            value = read(register, offset)
            expression = {
                "op": "equal",
                "left": {"op": "bit_and", "left": value, "right": value},
                "right": {"op": "constant", "value": 0},
            }
            for _ in range(not_count):
                expression = {"op": "not", "value": expression}
            return expression

        original = zero_guard("esp", 76, not_count=1)
        candidate = zero_guard("ebp", 76, not_count=1)
        claim = _paired_stack_guard_claim(source, original, candidate)
        self.assertEqual(claim["profile"], "paired_stack_read_guard_v1")
        self.assertEqual(claim["window"], window)
        self.assertEqual(claim["offset"], 76)
        self.assertEqual(claim["not_count"], 1)

        mismatched = zero_guard("ebp", 80, not_count=1)
        self.assertIsNone(_paired_stack_guard_claim(source, original, mismatched))
        self.assertIsNone(_paired_stack_guard_claim(
            {"stack_windows": [window, dict(window)]}, original, candidate,
        ))
        self.assertIsNone(_paired_stack_guard_claim(
            {"stack_windows": [{**window, "bytes_above": 79}]}, original, candidate,
        ))

        arithmetic_original = {
            "op": "equal",
            "left": {
                "op": "sub",
                "left": read("esp", 76),
                "right": read("esp", 12),
            },
            "right": {"op": "constant", "value": 0},
        }
        arithmetic_candidate = {
            "op": "equal",
            "left": {
                "op": "sub",
                "left": read("ebp", 76),
                "right": read("ebp", 12),
            },
            "right": {"op": "constant", "value": 0},
        }
        self.assertIsNone(
            _paired_stack_guard_claim(source, arithmetic_original, arithmetic_candidate)
        )

    def test_stack_read32_sub_output_claim_requires_checked_window(self):
        window = {
            "range_id": 0,
            "original_register": "esp",
            "candidate_register": "ebp",
            "bytes_below": 0,
            "bytes_above": 84,
        }
        output = {"original": "eax", "candidate": "ecx", "relation": "related_word"}

        def expression(register, offset=76, subtract=1):
            return {
                "op": "sub",
                "left": {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {"op": "input_reg", "reg": register},
                        "right": {"op": "constant", "value": offset},
                    },
                },
                "right": {"op": "constant", "value": subtract},
            }

        claim = _stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            expression("esp"), expression("ebp"),
        )
        self.assertEqual(claim["kind"], "stack_read32_sub")
        self.assertEqual(claim["offset"], 76)
        self.assertEqual(claim["subtract"], 1)
        self.assertIsNone(_stack_read32_sub_output_claim(
            {"stack_windows": [{**window, "bytes_above": 79}]}, output,
            expression("esp"), expression("ebp"),
        ))
        self.assertIsNone(_stack_read32_sub_output_claim(
            {"stack_windows": [window]}, output,
            expression("esp"), expression("ebp", subtract=2),
        ))

    def test_direct_call_push_requires_unique_mapped_final_stack_write(self):
        stack = {
            "op": "sub",
            "left": {"op": "input_reg", "reg": "esp"},
            "right": {"op": "constant", "value": 4},
        }
        region = {"code_targets": [
            {
                "id": 7, "region_index": 7,
                "original_rva": 0x700, "candidate_rva": 0x900,
            },
            {
                "id": 8, "region_index": 8,
                "original_rva": 0x800, "candidate_rva": 0xA00,
            },
        ]}
        behavior = {
            "original_ir": {
                "registers": {"esp": stack},
                "writes": [{
                    "address": stack,
                    "value": {"op": "constant", "value": 0x400800},
                }],
                "outcome": {"op": "call", "target": 7, "continuation": 8},
            },
            "candidate_ir": {
                "registers": {"esp": stack},
                "writes": [{
                    "address": stack,
                    "value": {"op": "constant", "value": 0x500A00},
                }],
                "outcome": {"op": "call", "target": 7, "continuation": 8},
            },
        }
        claim = _direct_call_push_claim(
            region, behavior,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        )
        self.assertEqual(claim, {
            "profile": "mapped_direct_call_push_v1",
            "callee_target_id": 7,
            "continuation_target_id": 8,
            "continuation_region_index": 8,
            "original_return_address": 0x400800,
            "candidate_return_address": 0x500A00,
            "original_stack_address": stack,
            "candidate_stack_address": stack,
        })

        wrong_return = json.loads(json.dumps(behavior))
        wrong_return["candidate_ir"]["writes"][-1]["value"]["value"] += 4
        self.assertIsNone(_direct_call_push_claim(
            region, wrong_return,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        ))

        overwritten = json.loads(json.dumps(behavior))
        overwritten["original_ir"]["writes"].append({
            "address": stack, "value": {"op": "constant", "value": 0},
        })
        self.assertIsNone(_direct_call_push_claim(
            region, overwritten,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        ))

        ambiguous = json.loads(json.dumps(region))
        ambiguous["code_targets"].append(dict(ambiguous["code_targets"][1]))
        self.assertIsNone(_direct_call_push_claim(
            ambiguous, behavior,
            original_image_base=0x400000,
            candidate_image_base=0x500000,
        ))

    def test_return_pop_requires_matching_esp_relative_slot_and_delta(self):
        def offset(value):
            return {
                "op": "add",
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": value},
            }

        behavior = {
            "original_ir": {
                "registers": {"esp": offset(20)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
            "candidate_ir": {
                "registers": {"esp": offset(20)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
        }
        self.assertEqual(_return_pop_claim(behavior), {
            "profile": "esp_relative_return_pop_v1",
            "original_stack_address": offset(8),
            "candidate_stack_address": offset(8),
            "original_stack_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 8,
            },
            "candidate_stack_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 8,
            },
            "original_stack_offset": 8,
            "candidate_stack_offset": 8,
            "original_output_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 20,
            },
            "candidate_output_witness": {
                "kind": "add_right", "prior": {"kind": "input"}, "value": 20,
            },
            "original_output_offset": 20,
            "candidate_output_offset": 20,
            "pop_bytes": 8,
        })

        mismatched = json.loads(json.dumps(behavior))
        mismatched["candidate_ir"]["registers"]["esp"]["right"]["value"] = 24
        self.assertIsNone(_return_pop_claim(mismatched))

        transformed = json.loads(json.dumps(behavior))
        transformed["original_ir"]["outcome"]["target"] = {
            "op": "bit_or", "left": {"op": "constant", "value": 0},
            "right": {"op": "read32", "address": offset(8)},
        }
        self.assertIsNone(_return_pop_claim(transformed))

    def test_return_after_static_write_requires_complete_image_separations(self):
        stack = {"op": "input_reg", "reg": "esp"}
        output = {
            "op": "add", "left": stack,
            "right": {"op": "constant", "value": 4},
        }
        original_write = {
            "address": {"op": "constant", "value": 0x401000},
            "value": {"op": "read32", "address": output},
        }
        candidate_write = {
            "address": {"op": "constant", "value": 0x501000},
            "value": {"op": "read32", "address": output},
        }
        behavior = {
            "original_ir": {
                "registers": {"esp": output},
                "writes": [original_write],
                "outcome": {
                    "op": "returned",
                    "target": _semantic_read32_after_writes(
                        stack, [original_write]
                    ),
                },
            },
            "candidate_ir": {
                "registers": {"esp": output},
                "writes": [candidate_write],
                "outcome": {
                    "op": "returned",
                    "target": _semantic_read32_after_writes(
                        stack, [candidate_write]
                    ),
                },
            },
        }
        binary = lambda base: SimpleNamespace(
            image_base=base,
            pe=SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(SizeOfImage=0x3000)),
        )
        contract = {"regions": [{"address_separations": []}]}
        refined = _attach_return_write_address_separations(
            contract, [behavior], binary(0x400000), binary(0x500000)
        )
        region = refined["regions"][0]

        self.assertEqual(len(region["address_separations"]), 16)
        claim = _return_pop_claim(behavior, region=region)
        self.assertIsNotNone(claim)
        self.assertEqual(
            claim["profile"], "esp_relative_return_after_static_writes_v1"
        )
        self.assertEqual(claim["pop_bytes"], 0)

        missing = json.loads(json.dumps(region))
        missing["address_separations"].pop()
        self.assertIsNone(_return_pop_claim(behavior, region=missing))

        dynamic = json.loads(json.dumps(behavior))
        dynamic["original_ir"]["writes"][0]["address"] = stack
        dynamic["original_ir"]["outcome"]["target"] = (
            _semantic_read32_after_writes(
                stack, dynamic["original_ir"]["writes"]
            )
        )
        dynamic_contract = _attach_return_write_address_separations(
            contract, [dynamic], binary(0x400000), binary(0x500000)
        )
        self.assertIsNone(_return_pop_claim(
            dynamic, region=dynamic_contract["regions"][0]
        ))

        outside = json.loads(json.dumps(behavior))
        outside["candidate_ir"]["writes"][0]["address"]["value"] = 0x600000
        outside["candidate_ir"]["outcome"]["target"] = (
            _semantic_read32_after_writes(
                stack, outside["candidate_ir"]["writes"]
            )
        )
        outside_contract = _attach_return_write_address_separations(
            contract, [outside], binary(0x400000), binary(0x500000)
        )
        self.assertIsNone(_return_pop_claim(
            outside, region=outside_contract["regions"][0]
        ))

        malformed = json.loads(json.dumps(behavior))
        malformed["original_ir"]["outcome"]["target"]["right"]["right"][
            "amount"
        ] = 23
        self.assertIsNone(_return_pop_claim(malformed, region=region))

    def test_return_slot_contracts_seed_transfer_and_align_a_return(self):
        def offset(value):
            operation = "add" if value >= 0 else "sub"
            return {
                "op": operation,
                "left": {"op": "input_reg", "reg": "esp"},
                "right": {"op": "constant", "value": abs(value)},
            }

        identity_registers = {"esp": offset(0)}
        return_behavior = {
            "original_ir": {
                "registers": {"esp": offset(12)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
            "candidate_ir": {
                "registers": {"esp": offset(12)},
                "outcome": {
                    "op": "returned",
                    "target": {"op": "read32", "address": offset(8)},
                },
            },
        }
        behaviors = [
            {"original_ir": {"registers": identity_registers},
             "candidate_ir": {"registers": identity_registers}},
            {"original_ir": {"registers": {"esp": offset(-8)}},
             "candidate_ir": {"registers": {"esp": offset(-8)}}},
            return_behavior,
        ]
        rows = [
            {"region_index": 0, "is_return": False, "return_pop_claim": None},
            {"region_index": 1, "is_return": False, "return_pop_claim": None},
            {"region_index": 2, "is_return": True,
             "return_pop_claim": _return_pop_claim(return_behavior)},
        ]
        edges = [
            {
                "source_region_index": 0, "target_region_index": 1,
                "kind": "call", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": {
                    "checked": True, "continuation_region_index": 2,
                },
            },
            {
                "source_region_index": 1, "target_region_index": 2,
                "kind": "jump", "environment_barrier": False,
                "requires_call_stack_proof": False,
                "direct_call_push_claim": None,
            },
        ]

        analysis = _attach_return_slot_contracts(behaviors, rows, edges)

        self.assertTrue(analysis["converged"])
        self.assertEqual(analysis["seed_edges"], 1)
        self.assertEqual(rows[1]["return_slot_offsets"], [
            {"original": 0, "candidate": 0},
        ])
        self.assertEqual(rows[2]["return_slot_offsets"], [
            {"original": 8, "candidate": 8},
        ])
        self.assertEqual(rows[2]["return_slot_status"], "satisfied")
        self.assertEqual(len(edges[1]["return_slot_transfer_claims"]), 1)
        self.assertEqual(len(rows[2]["return_pop_frame_claims"]), 1)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for call-boundary proofs")
    def test_machine_import_call_arguments_are_recovered_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            )
            for name in ("Formal.lean", "RelationalDecode.lean"):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "MachineCallBoundary.lean").write_text(
                """import StageA.RelationalDecode

namespace StageA.MachineCallBoundary

open StageA.Formal StageA.Relational

def imported : PEImport := {
  dll := [75, 69, 82, 78, 69, 76, 51, 50, 46, 100, 108, 108]
  name := .symbol [69, 110, 116, 101, 114, 67, 114, 105, 116, 105, 99,
    97, 108, 83, 101, 99, 116, 105, 111, 110]
  iatRva := 4096
}

def contract : MachineImportCallContract := {
  id := 1
  imported := normalizeImport imported
  stackArgumentOffsets := [0]
  stackResultDelta := 4
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax, .ecx, .edx]
  memoryEffect := .argumentRanges
  memoryFootprints := [{
    access := .write
    baseArgument := 0
    offset := 0
    size := .fixed 24
  }]
  worldEffect := .opaqueResources
}

def behavior : SymbolicBehavior := {
  initialSymbolic with
  writes := [(.inputReg .esp, .constant 4259940)]
  outcome := some (.externalCall imported [] 8192)
}

def indirectBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := initialSymbolic.registers.set .esp
    ((Expr.inputReg .esp).offset (2^32 - 4))
  writes := [
    (Expr.inputReg .esp, Expr.constant 7),
    ((Expr.inputReg .esp).offset (2^32 - 4), Expr.constant 4202496)
  ]
  outcome := some (.indirectCall (.inputReg .ebp) 8192 4202496)
}

def preadjustedIndirectBehavior : SymbolicBehavior := {
  initialSymbolic with
  registers := initialSymbolic.registers.set .esp
    ((Expr.inputReg .esp).offset (2^32 - 8))
  writes := [
    ((Expr.inputReg .esp).offset (2^32 - 8), Expr.constant 4202500)
  ]
  outcome := some (.indirectCall (.inputReg .ebp) 8196 4202500)
}

def recoveredArgumentChecked : Bool :=
  match applyMachineImportCallContracts [contract] behavior with
  | some recovered =>
      match recovered.outcome with
      | some (.externalCall recoveredImport arguments continuation) =>
          normalizeImport recoveredImport == contract.imported &&
            arguments == contract.arguments behavior && continuation == 8192
      | _ => false
  | none => false

def recoveredArgumentIsDirectWord : Bool :=
  match applyMachineImportCallContracts [contract] behavior with
  | some { outcome := some (.externalCall _ arguments _), .. } =>
      arguments == [.constant 4259940]
  | _ => false

def indirectCallExternalized : Bool :=
  match externalizeRegisterImportCall contract .ebp indirectBehavior with
  | some externalized =>
      externalized.registers.esp == .inputReg .esp &&
        externalized.writes == [(Expr.inputReg .esp, Expr.constant 7)] &&
        externalized.outcome == some (.externalCall contract.imported.syntheticImport
          [.constant 7] 8192)
  | none => false

example : contract.shapeValid = true := by decide
example : recoveredArgumentChecked = true := by decide
example : recoveredArgumentIsDirectWord = true := by decide
example : applyMachineImportCallContracts [contract, contract] behavior = none := by decide
example : indirectCallExternalized = true := by decide
example : externalizeRegisterImportCall contract .edi indirectBehavior = none := by decide
example :
    (externalizeRegisterImportCall { contract with stackArgumentOffsets := [] }
      .ebp preadjustedIndirectBehavior).map (fun behavior => behavior.registers.esp) =
      some ((Expr.inputReg .esp).offset (2^32 - 4)) := by decide

end StageA.MachineCallBoundary
""",
                encoding="utf-8",
            )
            decode = _run_lean_relational(
                lean_dir, bundle="RelationalDecode"
            )
            self.assertEqual(decode["status"], "checked", decode)
            result = _run_lean_relational(
                lean_dir, bundle="MachineCallBoundary"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for dynamic-call proofs")
    def test_dynamic_range_indirect_call_witness_is_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            )
            for name in (
                "Formal.lean", "RelationalDecode.lean", "RelationalMachine.lean",
                "Relational.lean", "RelationalSegment.lean",
                "RelationalComposition.lean",
            ):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "DynamicCallWitness.lean").write_text(
                """import StageA.RelationalComposition

namespace StageA.DynamicCallWitness

open StageA.Formal StageA.Relational

def rangeRelation : DynamicRegisterRangeRelation := {
  original := .ebx
  candidate := .esi
  originalOffset := 8
  candidateOffset := 8
  requiredWords := [{ offset := 12, kind := .codePointer }]
}

def rangePair : DynamicAddressRangePair := {
  id := 1
  originalBase := BitVec.ofNat 32 4096
  candidateBase := BitVec.ofNat 32 8192
  size := 32
  wordRelations := rangeRelation.requiredWords
}

def overlappingRangePair : DynamicAddressRangePair := {
  id := 2
  originalBase := BitVec.ofNat 32 4112
  candidateBase := BitVec.ofNat 32 12288
  size := 32
}

def duplicateWordRangePair : DynamicAddressRangePair := {
  rangePair with
  wordRelations := [
    { offset := 12, kind := .codePointer },
    { offset := 12, kind := .dataPointer }
  ]
}

def opaqueWorld : RelationalWorld := {
  opaqueResources := [{
    id := 1
    original := BitVec.ofNat 32 4096
    candidate := BitVec.ofNat 32 8192
  }]
}

def duplicateOpaqueWorld : RelationalWorld := {
  opaqueResources := [
    { id := 1, original := BitVec.ofNat 32 4096,
      candidate := BitVec.ofNat 32 8192 },
    { id := 2, original := BitVec.ofNat 32 4096,
      candidate := BitVec.ofNat 32 12288 }
  ]
}

example : rangePair.wordRelationsValid = true := by decide

example : duplicateWordRangePair.wordRelationsValid = false := by decide

example : opaqueWorld.opaqueResourcesValid = true := by decide

example : duplicateOpaqueWorld.opaqueResourcesValid = false := by decide

example : dynamicAddressRangesDisjointOn false
    [rangePair, overlappingRangePair] = false := by decide

def invariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [rangeRelation]
}

def registers : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def originalBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall
    (.read32 (.add (.inputReg .ebx) (.constant 4))) 9
}

def candidateBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall
    (.read32 (.add (.inputReg .esi) (.constant 4))) 9
}

def claim : DynamicRangeIndirectCallClaim := {
  rangeRelation
  wordOffset := 4
  continuationTargetId := 9
}

def preserveClaim : DynamicRegisterRangePreserveClaim := {
  sourceRelation := rangeRelation
  targetRelation := rangeRelation
}

example : claim.checked invariant originalBehavior candidateBehavior = true := by
  decide

example : DynamicRangeIndirectCallTargetsClosed invariant originalBehavior
    candidateBehavior claim :=
  dynamicRangeIndirectCallTargetsClosed_of_checked invariant originalBehavior
    candidateBehavior claim (by decide)

example : preserveClaim.checked invariant invariant originalBehavior
    originalBehavior = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world invariant originalState candidateState) :
    preserveClaim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (originalBehavior.eval candidateState).registers = true :=
  dynamicRegisterRangePreserveOutputHolds_of_checked context world invariant invariant
    originalBehavior originalBehavior preserveClaim (by decide) originalState
    candidateState related

def argumentRangeRelation : DynamicRegisterRangeRelation := {
  original := .ebx
  candidate := .esi
  originalOffset := 8
  candidateOffset := 8
  requiredWords := [{ offset := 12, kind := .relatedWord }]
}

def argumentInvariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [argumentRangeRelation]
}

def argumentClaim : DynamicRangeArgumentClaim := {
  rangeRelation := argumentRangeRelation
  wordRelation := { offset := 12, kind := .relatedWord }
  originalReadOffset := 4
  candidateReadOffset := 4
}

example : argumentClaim.checked argumentInvariant
    (dynamicRangeArgumentExpression .ebx 4)
    (dynamicRangeArgumentExpression .esi 4) = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world argumentInvariant originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((dynamicRangeArgumentExpression .ebx 4).eval originalState)
      ((dynamicRangeArgumentExpression .esi 4).eval candidateState) = true :=
  dynamicRangeArgumentWordsRelated_of_checked context world argumentInvariant
    (dynamicRangeArgumentExpression .ebx 4)
    (dynamicRangeArgumentExpression .esi 4) argumentClaim (by decide)
    originalState candidateState related

def exactRegisterArgumentInvariant : StateInvariant := {
  registerRelations := [{ original := .ebx, candidate := .esi, relation := .exact }]
}

def exactRegisterArgumentClaim : RegisterArgumentClaim := {
  relation := { original := .ebx, candidate := .esi, relation := .exact }
  offset := 32
}

example : exactRegisterArgumentClaim.checked exactRegisterArgumentInvariant
    (registerArgumentExpression .ebx 32)
    (registerArgumentExpression .esi 32) = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world exactRegisterArgumentInvariant
      originalState candidateState) :
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      ((registerArgumentExpression .ebx 32).eval originalState)
      ((registerArgumentExpression .esi 32).eval candidateState) = true :=
  registerArgumentWordsRelated_of_checked context world exactRegisterArgumentInvariant
    (registerArgumentExpression .ebx 32) (registerArgumentExpression .esi 32)
    exactRegisterArgumentClaim (by decide) originalState candidateState related

def relatedRegisterArgumentInvariant : StateInvariant := {
  registerRelations := [
    { original := .ebx, candidate := .esi, relation := .relatedWord }
  ]
}

def relatedRegisterArgumentClaim : RegisterArgumentClaim := {
  relation := { original := .ebx, candidate := .esi, relation := .relatedWord }
  offset := 0
}

example : relatedRegisterArgumentClaim.checked relatedRegisterArgumentInvariant
    (registerArgumentExpression .ebx 0)
    (registerArgumentExpression .esi 0) = true := by decide

example : ({ relatedRegisterArgumentClaim with offset := 4 }).checked
    relatedRegisterArgumentInvariant (registerArgumentExpression .ebx 4)
    (registerArgumentExpression .esi 4) = false := by decide

def nextRelation : DynamicRegisterRangeRelation := {
  original := .ebx
  candidate := .esi
  requiredWords := [
    { offset := 4, kind := .codePointer },
    { offset := 8, kind := .nullableDynamicPointer }
  ]
}

def nextInvariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [nextRelation]
}

def originalNextRegisters : Registers Expr := {
  registers with
  ebx := dynamicPointerReadExpression .ebx 8
}

def candidateNextRegisters : Registers Expr := {
  registers with
  esi := dynamicPointerReadExpression .esi 8
}

def originalNextBehavior : NormalizedSymbolicBehavior := {
  registers := originalNextRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def candidateNextBehavior : NormalizedSymbolicBehavior := {
  registers := candidateNextRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def originalNextGuard : BoolExpr := dynamicPointerNonzeroGuard .ebx 8
def candidateNextGuard : BoolExpr := dynamicPointerNonzeroGuard .esi 8

def nextClaim : DynamicRegisterRangeNextClaim := {
  sourceRelation := nextRelation
  targetRelation := nextRelation
  pointerOffset := 8
}

example : nextClaim.checked nextInvariant nextInvariant originalNextBehavior
    candidateNextBehavior originalNextGuard candidateNextGuard = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world nextInvariant originalState candidateState)
    (guardTrue : originalNextGuard.eval originalState = true) :
    nextClaim.targetRelation.holds world
      (originalNextBehavior.eval originalState).registers
      (candidateNextBehavior.eval candidateState).registers = true :=
  dynamicRegisterRangeNextOutputHolds_of_checked context world nextInvariant
    nextInvariant originalNextBehavior candidateNextBehavior originalNextGuard
    candidateNextGuard nextClaim (by decide) originalState candidateState related
    guardTrue

def staticSlot : StaticDynamicPointerSlotPair := {
  id := 7
  originalAddress := BitVec.ofNat 32 12288
  candidateAddress := BitVec.ofNat 32 16384
  requiredWords := nextRelation.requiredWords
}

def staticContext (context : StaticProofContext) : StaticProofContext := {
  context with staticDynamicPointerSlots := [staticSlot]
}

def staticOriginalRegisters : Registers Expr := {
  registers with
  ebx := staticDynamicPointerReadExpression staticSlot.originalAddress
}

def staticCandidateRegisters : Registers Expr := {
  registers with
  esi := staticDynamicPointerReadExpression staticSlot.candidateAddress
}

def staticOriginalBehavior : NormalizedSymbolicBehavior := {
  registers := staticOriginalRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def staticCandidateBehavior : NormalizedSymbolicBehavior := {
  registers := staticCandidateRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .returned (.constant 0)
}

def staticInvariant : StateInvariant := {
  registerRelations := []
  dynamicRegisterRangeRelations := [nextRelation]
}

def staticOriginalGuard : BoolExpr :=
  staticDynamicPointerNonzeroGuard staticSlot.originalAddress

def staticCandidateGuard : BoolExpr :=
  staticDynamicPointerNonzeroGuard staticSlot.candidateAddress

def staticSeedClaim : StaticDynamicPointerSeedClaim := {
  slot := staticSlot
  targetRelation := nextRelation
}

def staticZeroGuardClaim : StaticDynamicPointerGuardClaim := {
  slot := staticSlot
  kind := .zero
}

example (context : StaticProofContext) :
    staticSeedClaim.checked (staticContext context) staticInvariant
      staticOriginalBehavior staticCandidateBehavior staticOriginalGuard
      staticCandidateGuard = true := by rfl

example (context : StaticProofContext) :
    staticZeroGuardClaim.checked (staticContext context)
      (staticDynamicPointerZeroGuard staticSlot.originalAddress)
      (staticDynamicPointerZeroGuard staticSlot.candidateAddress) = true := by rfl

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel (staticContext context) world nextInvariant
      originalState candidateState)
    (guardTrue : staticOriginalGuard.eval originalState = true) :
    staticSeedClaim.targetRelation.holds world
      (staticOriginalBehavior.eval originalState).registers
      (staticCandidateBehavior.eval candidateState).registers = true :=
  staticDynamicPointerSeedOutputHolds_of_checked (staticContext context) world
    nextInvariant staticInvariant staticOriginalBehavior staticCandidateBehavior
    staticOriginalGuard staticCandidateGuard staticSeedClaim (by rfl)
    originalState candidateState related guardTrue

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel (staticContext context) world nextInvariant
      originalState candidateState) :
    (staticDynamicPointerZeroGuard staticSlot.originalAddress).eval originalState =
      (staticDynamicPointerZeroGuard staticSlot.candidateAddress).eval candidateState :=
  staticDynamicPointerGuardsAgree_of_checked (staticContext context) world
    nextInvariant (staticDynamicPointerZeroGuard staticSlot.originalAddress)
    (staticDynamicPointerZeroGuard staticSlot.candidateAddress) staticZeroGuardClaim
    (by rfl) originalState candidateState related

end StageA.DynamicCallWitness
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(
                lean_dir, bundle="DynamicCallWitness"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-call proofs")
    def test_import_register_indirect_call_witness_is_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            )
            for name in (
                "Formal.lean", "RelationalDecode.lean", "RelationalMachine.lean",
                "Relational.lean", "RelationalSegment.lean",
                "RelationalComposition.lean", "RelationalEnvironment.lean",
            ):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "ImportCallWitness.lean").write_text(
                """import StageA.RelationalEnvironment

namespace StageA.ImportCallWitness

open StageA.Formal StageA.Relational

def callerBufferFootprint : MachineCallMemoryFootprint := {
  access := .write
  baseArgument := 0
  offset := 4
  size := .fixed 8
}

def callerBufferContract : MachineImportCallContract := {
  id := 0
  imported := {
    dll := [102, 105, 120, 116, 117, 114, 101, 46, 100, 108, 108]
    name := .symbol [102, 105, 108, 108]
  }
  stackArgumentOffsets := [0]
  stackResultDelta := 4
  preservedRegisters := [.ebx, .esi, .edi, .ebp]
  clobberedRegisters := [.eax, .ecx, .edx]
  memoryEffect := .argumentRanges
  memoryFootprints := [callerBufferFootprint]
  worldEffect := .none
}

def optionalCallerBufferFootprint : MachineCallMemoryFootprint := {
  callerBufferFootprint with nullable := true
}

def optionalCallerBufferContract : MachineImportCallContract := {
  callerBufferContract with memoryFootprints := [optionalCallerBufferFootprint]
}

def stackArgumentWindow : StackWindowPair := {
  rangeId := 0
  originalRegister := .esp
  candidateRegister := .esp
  bytesBelow := 0
  bytesAbove := 16
}

def stackArgumentInvariant : StateInvariant := {
  registerRelations := []
  stackWindows := [stackArgumentWindow]
}

def directStackArgument : Expr :=
  .read32 ((Expr.inputReg .esp).offset 4)

def assembledStackArgument : Expr :=
  stackWindowAssembledArgument .esp 4

def decodedAssembledStackArgument : Expr :=
  .bitOr
    (.bitOr (.read8 ((Expr.inputReg .esp).offset 4))
      (.shiftLeft (.read8 ((Expr.inputReg .esp).offset 5)) 8))
    (.bitOr (.shiftLeft (.read8 ((Expr.inputReg .esp).offset 6)) 16)
      (.shiftLeft (.read8 ((Expr.inputReg .esp).offset 7)) 24))

def stackArgumentClaim : StackWindowArgumentClaim := {
  window := stackArgumentWindow
  offset := 4
  originalAssembledRead := false
  candidateAssembledRead := true
}

example : callerBufferContract.shapeValid = true := by decide
example : callerBufferFootprint.range? [BitVec.ofNat 32 4096] = some (4100, 4108) := by
  decide
example : callerBufferFootprint.contains [BitVec.ofNat 32 4096]
    (BitVec.ofNat 32 4104) = true := by decide
example : callerBufferFootprint.contains [BitVec.ofNat 32 4096]
    (BitVec.ofNat 32 4108) = false := by decide
example : callerBufferFootprint.range? [BitVec.ofNat 32 (2^32 - 8)] = none := by
  decide
example : callerBufferFootprint.range? [BitVec.ofNat 32 0] = none := by decide
example : optionalCallerBufferContract.shapeValid = true := by decide
example : optionalCallerBufferFootprint.range? [BitVec.ofNat 32 0] = some (0, 0) := by
  decide
example : optionalCallerBufferFootprint.contains [BitVec.ofNat 32 0]
    (BitVec.ofNat 32 0) = false := by decide
example : stackArgumentClaim.checked stackArgumentInvariant directStackArgument
    assembledStackArgument = true := by decide
example : assembledStackArgument = decodedAssembledStackArgument := by decide
example (before after : Memory)
    (holds : machineCallMemoryEffectHolds callerBufferContract
      [BitVec.ofNat 32 4096] before after) :
    after (BitVec.ofNat 32 4108) = before (BitVec.ofNat 32 4108) := by
  exact holds.2 _ (by decide)
example (before after : Memory)
    (holds : machineCallMemoryEffectHolds optionalCallerBufferContract
      [BitVec.ofNat 32 0] before after) (address : Word) :
    after address = before address := by
  apply holds.2
  have emptyRange : optionalCallerBufferFootprint.range? [BitVec.ofNat 32 0] =
      some (0, 0) := by decide
  have outside : optionalCallerBufferFootprint.contains [BitVec.ofNat 32 0]
      address = false := by
    simp [MachineCallMemoryFootprint.contains, emptyRange]
  simpa [optionalCallerBufferContract, optionalCallerBufferFootprint,
    callerBufferFootprint] using outside

example : normalizeDllName [75, 69, 82, 78, 69, 76, 51, 50, 46, 100, 108, 108] =
    [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108] := by decide

def imported : ExternalTarget := {
  dll := [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108]
  name := .symbol [84, 108, 115, 71, 101, 116, 86, 97, 108, 117, 101]
}

def fixtureImport : PEImport := {
  dll := [107, 101, 114, 110, 101, 108, 51, 50, 46, 100, 108, 108]
  name := .symbol [84, 108, 115, 71, 101, 116, 86, 97, 108, 117, 101]
  iatRva := 8192
}

example (context : StaticProofContext) (world : RelationalWorld)
    (targets : List CodeTargetPair) (original excludedValues : Memory) :
    ordinaryMemoryRelated context world targets [] original
      (ordinaryMemoryCandidateProjection context world [] original excludedValues) :=
  ordinaryMemoryRelated_projection_without_relocations context world targets []
    original excludedValues (by rfl)

example (context : StaticProofContext) (world : RelationalWorld)
    (original excludedValues : Memory) (address : Word)
    (excluded : ordinaryMemoryAddressExcluded context world [] address = true) :
    ordinaryMemoryCandidateProjection context world [] original excludedValues address =
      excludedValues address := by
  simp [ordinaryMemoryCandidateProjection, excluded]

example (context : StaticProofContext)
    (originalImports : context.originalImports = [fixtureImport]) :
    RelationalWorld.empty.importAddressesComplete context = false := by
  simp [RelationalWorld.importAddressesComplete, RelationalWorld.empty,
    originalImports]

def registers : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def originalBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall (.inputReg .ebp) 7
}

def candidateBehavior : NormalizedSymbolicBehavior := {
  registers
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .indirectCall (.inputReg .edi) 7
}

def invariant : StateInvariant := {
  registerRelations := [{
    original := .ebp
    candidate := .edi
    relation := .relatedWord
  }]
  importRegisterRelations := [{
    original := .ebp
    candidate := .edi
    imported
  }]
}

def claim : ImportRegisterIndirectCallClaim := {
  imported
  originalRegister := .ebp
  candidateRegister := .edi
  continuationTargetId := 7
}

def preserveClaim : ImportRegisterPreserveClaim := {
  imported
  sourceOriginalRegister := .ebp
  sourceCandidateRegister := .edi
  targetOriginalRegister := .ebp
  targetCandidateRegister := .edi
}

    def zeroGuardClaim : RelatedWordZeroGuardClaim := {
      originalRegister := .ebp
      candidateRegister := .edi
      valueRelation := .relatedWord
      notCount := 0
    }

    def sourceStackWindow : StackWindowPair := {
      rangeId := 0
      originalRegister := .esp
      candidateRegister := .esp
      bytesBelow := 4
      bytesAbove := 44
    }

    def targetStackWindow : StackWindowPair := {
      rangeId := 0
      originalRegister := .esp
      candidateRegister := .esp
      bytesBelow := 0
      bytesAbove := 48
    }

    def sourceStackInvariant : StateInvariant := {
      registerRelations := []
      stackWindows := [sourceStackWindow]
    }

    def targetStackInvariant : StateInvariant := {
      registerRelations := []
      stackWindows := [targetStackWindow]
    }

    def adjustedRegisters : Registers Expr := {
      registers with
      esp := .sub (.inputReg .esp) (.constant 4)
    }

    def adjustedBehavior : NormalizedSymbolicBehavior := {
      originalBehavior with registers := adjustedRegisters
    }

    def stackAdjustmentClaim : StackWindowAffineTransferClaim := {
      source := sourceStackWindow
      target := targetStackWindow
      adjustment := .subtract 4
    }

    example : stackAdjustmentClaim.checked sourceStackInvariant targetStackInvariant
        adjustedBehavior adjustedBehavior = true := by decide

    example (context : StaticProofContext) (world : RelationalWorld)
        (originalState candidateState : MachineState)
        (rangesValid : world.stackRangesValid context = true)
        (sourceRelated : stackWindowsRelated world sourceStackInvariant.stackWindows
          originalState.registers candidateState.registers = true) :
        targetStackWindow.holds world
          (adjustedBehavior.eval originalState).registers
          (adjustedBehavior.eval candidateState).registers = true :=
      stackWindowAffineTransferHolds_of_checked context world sourceStackInvariant
        targetStackInvariant adjustedBehavior adjustedBehavior stackAdjustmentClaim
        originalState candidateState rangesValid sourceRelated (by decide)

    example : claim.checked invariant originalBehavior candidateBehavior = true := by decide

example : ImportRegisterIndirectCallTargetsClosed invariant originalBehavior
    candidateBehavior claim :=
  importRegisterIndirectCallTargetsClosed_of_checked invariant originalBehavior
    candidateBehavior claim (by decide)

example : preserveClaim.checked invariant invariant originalBehavior
    candidateBehavior = true := by decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world invariant originalState candidateState) :
    preserveClaim.targetRelation.holds world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true :=
  importRegisterPreserveOutputHolds_of_checked context world invariant invariant
    originalBehavior candidateBehavior preserveClaim (by decide) originalState
    candidateState related

example : zeroGuardClaim.checked invariant
    (relatedWordZeroGuard .ebp false) (relatedWordZeroGuard .edi false) = true := by
  decide

example (context : StaticProofContext) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (related : StateRel context world invariant originalState candidateState) :
    (relatedWordZeroGuard .ebp false).eval originalState =
      (relatedWordZeroGuard .edi false).eval candidateState :=
  relatedWordZeroGuard_eval_equal_of_checked context world invariant
    (relatedWordZeroGuard .ebp false) (relatedWordZeroGuard .edi false)
    zeroGuardClaim (by decide) originalState candidateState related

def minusEightWitness : RegisterOffsetWitness :=
  .subRight .input 8

def returnSlotTransferClaim : ReturnSlotTransferClaim := {
  source := ReturnSlotOffsetPair.zero
  target := {
    originalOffset := BitVec.ofNat 32 8
    candidateOffset := BitVec.ofNat 32 8
  }
  originalEsp := minusEightWitness
  candidateEsp := minusEightWitness
}

example : returnSlotTransferClaim.checked adjustedBehavior adjustedBehavior = false := by
  decide

def minusEightRegisters : Registers Expr := {
  registers with
  esp := .sub (.inputReg .esp) (.constant 8)
}

def minusEightBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with registers := minusEightRegisters
}

example : returnSlotTransferClaim.checked minusEightBehavior minusEightBehavior = true := by
  decide

example (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (sourceHolds : ReturnSlotOffsetPair.zero.holds frame originalState.registers
      candidateState.registers) :
    returnSlotTransferClaim.target.holds frame
      (minusEightBehavior.eval originalState).registers
      (minusEightBehavior.eval candidateState).registers :=
  returnSlotTransferHolds_of_checked minusEightBehavior minusEightBehavior
    returnSlotTransferClaim frame originalState candidateState (by decide) sourceHolds

def returnPopClaim : ReturnPopClaim := {
  originalStackAddress := .add (.inputReg .esp) (.constant 8)
  candidateStackAddress := .add (.inputReg .esp) (.constant 8)
  popBytes := 0
}

def returnPopFrameClaim : ReturnPopFrameClaim := {
  offsets := {
    originalOffset := BitVec.ofNat 32 8
    candidateOffset := BitVec.ofNat 32 8
  }
  originalSlot := .addRight .input 8
  candidateSlot := .addRight .input 8
}

example : ReturnPopFrameClaimClosed returnPopClaim returnPopFrameClaim :=
  returnPopFrameClaimClosed_of_checked returnPopClaim returnPopFrameClaim (by decide)

def wrongReturnPopFrameClaim : ReturnPopFrameClaim := {
  returnPopFrameClaim with
  candidateSlot := .addRight .input 12
}

example : wrongReturnPopFrameClaim.checked returnPopClaim = false := by decide

def summaryCallClaim : DirectCallPushClaim := {
  calleeTargetId := 1
  continuationTargetId := 2
  originalReturnAddress := 4096
  candidateReturnAddress := 8192
  originalStackAddress := .sub (.inputReg .esp) (.constant 4)
  candidateStackAddress := .sub (.inputReg .esp) (.constant 4)
}

def summaryReturnRegisters : Registers Expr := {
  registers with
  esp := .add (.inputReg .esp) (.constant 12)
}

def summaryReturnBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with
  registers := summaryReturnRegisters
  outcome := .returned (.read32 (.add (.inputReg .esp) (.constant 8)))
}

def callSummaryClaim : ReturnSlotCallSummaryClaim := {
  source := ReturnSlotOffsetPair.zero
  target := ReturnSlotOffsetPair.zero
  originalCallEsp := .subRight .input 4
  candidateCallEsp := .subRight .input 4
  originalReturnSlot := .addRight .input 8
  candidateReturnSlot := .addRight .input 8
  originalReturnOutput := .addRight .input 12
  candidateReturnOutput := .addRight .input 12
  popBytes := 0
}

example : ReturnSlotCallSummaryClosed adjustedBehavior adjustedBehavior
    summaryReturnBehavior summaryReturnBehavior summaryCallClaim callSummaryClaim :=
  returnSlotCallSummaryClosed_of_checked adjustedBehavior adjustedBehavior
    summaryReturnBehavior summaryReturnBehavior summaryCallClaim callSummaryClaim (by decide)

def wrongCallSummaryClaim : ReturnSlotCallSummaryClaim := {
  callSummaryClaim with popBytes := 4
}

example : wrongCallSummaryClaim.checked adjustedBehavior adjustedBehavior
    summaryReturnBehavior summaryReturnBehavior summaryCallClaim = false := by decide

def returnAfterWriteSeparations : List AddressSeparationPair :=
  (List.range 4).flatMap fun wordByte =>
    (List.range 4).map fun writeByte => {
      originalRegister := .esp
      candidateRegister := .esp
      originalOffset := wordByte
      candidateOffset := wordByte
      originalAddress := 4198400 + writeByte
      candidateAddress := 5246976 + writeByte
    }

def returnAfterWriteInvariant : StateInvariant := {
  registerRelations := []
  addressSeparations := returnAfterWriteSeparations
}

def originalStaticWrite : Expr × Expr :=
  (.constant 4198400, .read32 (.add (.inputReg .esp) (.constant 4)))

def candidateStaticWrite : Expr × Expr :=
  (.constant 5246976, .read32 (.add (.inputReg .esp) (.constant 4)))

def returnAfterWriteRegisters : Registers Expr := {
  registers with esp := .add (.inputReg .esp) (.constant 4)
}

def originalReturnAfterWriteBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with
  registers := returnAfterWriteRegisters
  writes := [originalStaticWrite]
  outcome := .returned ((Expr.inputReg .esp).read32AfterWrites [originalStaticWrite])
}

def candidateReturnAfterWriteBehavior : NormalizedSymbolicBehavior := {
  originalBehavior with
  registers := returnAfterWriteRegisters
  writes := [candidateStaticWrite]
  outcome := .returned ((Expr.inputReg .esp).read32AfterWrites [candidateStaticWrite])
}

def returnAfterWriteClaim : ReturnPopAfterWritesClaim := {
  originalStack := .input
  candidateStack := .input
  originalOutput := .addRight .input 4
  candidateOutput := .addRight .input 4
  popBytes := 0
}

def returnAfterWriteFrameClaim : ReturnPopFrameClaim := {
  offsets := ReturnSlotOffsetPair.zero
  originalSlot := .input
  candidateSlot := .input
}

example : returnAfterWriteClaim.checked returnAfterWriteInvariant
    originalReturnAfterWriteBehavior candidateReturnAfterWriteBehavior = true := by decide

example : ReturnPopAfterWritesFrameClaimClosed returnAfterWriteClaim
    returnAfterWriteFrameClaim :=
  returnPopAfterWritesFrameClaimClosed_of_checked returnAfterWriteClaim
    returnAfterWriteFrameClaim (by decide)

example (context : StaticProofContext) (world : RelationalWorld)
    (frame : RelationalRuntimeCallFrame) (originalState candidateState : MachineState)
    (related : StateRel context world returnAfterWriteInvariant originalState candidateState)
    (offsetsHold : ReturnSlotOffsetPair.zero.holds frame originalState.registers
      candidateState.registers)
    (memoryHolds : frame.memoryHolds originalState.memory candidateState.memory) :
    originalReturnAfterWriteBehavior.outcome.eval originalState =
        .returned frame.originalReturnAddress ∧
      candidateReturnAfterWriteBehavior.outcome.eval candidateState =
        .returned frame.candidateReturnAddress :=
  returnPopAfterWritesTargetsRuntimeFrame_of_checked context world
    returnAfterWriteInvariant originalReturnAfterWriteBehavior
    candidateReturnAfterWriteBehavior returnAfterWriteClaim returnAfterWriteFrameClaim
    frame originalState candidateState (by decide) (by decide) related offsetsHold memoryHolds

end StageA.ImportCallWitness
""",
                encoding="utf-8",
            )
            for module in (
                "Formal", "RelationalDecode", "RelationalMachine", "Relational",
                "RelationalSegment", "RelationalComposition", "RelationalEnvironment",
                "ImportCallWitness",
            ):
                result = _run_lean_relational(lean_dir, bundle=module)
                self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for reachability proofs")
    def test_constant_false_edge_is_excluded_by_checked_reachability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("39c07502ebfeebfe")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": "constant-branch",
                    "kind": "code",
                    "reachable": True,
                    "root": {"kind": "fixture_function", "checked": True},
                    "original": {"rva": 0x1000, "size": 4},
                    "candidate": {"rva": 0x1000, "size": 4},
                },
                {
                    "id": "fallthrough-loop",
                    "kind": "code",
                    "reachable": True,
                    "original": {"rva": 0x1004, "size": 2},
                    "candidate": {"rva": 0x1004, "size": 2},
                },
                {
                    "id": "infeasible-loop",
                    "kind": "code",
                    "reachable": True,
                    "original": {"rva": 0x1006, "size": 2},
                    "candidate": {"rva": 0x1006, "size": 2},
                },
            ]}), encoding="utf-8")
            contract = root / "relation.json"
            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            self.assertEqual(generated["status"], "generated", generated)

            report = root / "report"
            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            graph = json.loads(
                (report / "relational-product-graph.json").read_text(encoding="utf-8")
            )
            infeasible = [edge for edge in graph["edges"] if edge["infeasible"]]
            self.assertEqual(len(infeasible), 1, graph)
            self.assertNotIn(
                infeasible[0]["target_node_id"],
                graph["evidence"]["declared_reachable_node_ids"],
            )
            reachability = (
                report / "lean" / "StageA" /
                "RelationalProductReachabilityCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("SoundlyClosed", reachability)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for branch refinement proofs")
    def test_related_word_zero_branch_segments_are_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("85c07402ebfeebfe")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            spans = [(0x1000, 4), (0x1004, 2), (0x1006, 2)]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, (rva, _) in enumerate(spans)
                ],
                "regions": [
                    {
                        "id": f"zero-branch-{index}",
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                        "flag_inputs": [10],
                        "flag_outputs": [10],
                    }
                    for index, (rva, size) in enumerate(spans)
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")
            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            graph = json.loads(
                (root / "report" / "relational-product-graph.json").read_text()
            )
            self.assertGreaterEqual(graph["counts"]["proved_edges"], 2, graph)
            segment_source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementChunk*.lean"
                )
            )
            self.assertIn("RelatedWordZeroGuardClaim", segment_source)

    def test_exact_memory_register_claim_requires_empty_global_value_map(self):
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        registers["eax"] = {
            "op": "read32",
            "address": {"op": "input_reg", "reg": "ebx"},
        }
        behavior = {
            "format": "stage-a-normalized-behavior-v1",
            "registers": registers,
            "x87": {},
            "writes": [],
            "flags": {},
            "outcome": {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
        }
        pairs = [
            {"original": register, "candidate": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        contract = {
            "code_targets": [],
            "value_targets": [],
            "regions": [{
                "id": "entry",
                "numeric_id": 0,
                "root": True,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
            }],
        }
        behaviors = [{"original_ir": behavior, "candidate_ir": behavior}]

        _, identity_memory = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        self.assertEqual(identity_memory["counts"]["register_output_claims"], 8)
        self.assertIn(
            "exact_memory",
            {claim["kind"] for claim in identity_memory["regions"][0]["output_claims"]},
        )

        contract["value_targets"] = [{
            "id": 0,
            "original_value": 0x402000,
            "candidate_value": 0x403000,
            "mapped_size": 16,
        }]
        _, mapped_memory = _synthesize_register_relations(
            contract,
            behaviors,
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        self.assertEqual(mapped_memory["counts"]["register_output_claims"], 7)
        self.assertEqual(
            mapped_memory["regions"][0]["outputs"][0]["relation"],
            "related_word",
        )
        self.assertNotIn(
            "exact_memory",
            {claim["kind"] for claim in mapped_memory["regions"][0]["output_claims"]},
        )

    def test_external_call_register_policy_preserves_win32_nonvolatile_relations(self):
        register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }
        source = {
            "registers": registers,
            "outcome": {
                "op": "external_call",
                "import": {"dll": [], "name": {"op": "ordinal", "value": 1}},
                "arguments": [],
                "continuation": 1,
            },
        }
        target = {
            "registers": registers,
            "outcome": {
                "op": "returned",
                "target": {"op": "input_reg", "reg": "eax"},
            },
        }
        pairs = [
            {"original": register, "candidate": register}
            for register in register_names
        ]
        contract = {
            "code_targets": [],
            "value_targets": [],
            "regions": [
                {
                    "id": "call",
                    "numeric_id": 0,
                    "root": True,
                    "inputs": pairs,
                    "outputs": pairs,
                    "values": [],
                },
                {
                    "id": "continuation",
                    "numeric_id": 1,
                    "root": False,
                    "inputs": pairs,
                    "outputs": pairs,
                    "values": [],
                },
            ],
        }
        _, relations = _synthesize_register_relations(
            contract,
            [
                {"original_ir": source, "candidate_ir": source},
                {"original_ir": target, "candidate_ir": target},
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        continuation = {
            relation["original"]: relation["relation"]
            for relation in relations["regions"][1]["inputs"]
        }
        self.assertEqual(
            {register for register, relation in continuation.items() if relation == "exact"},
            {"ebx", "esi", "edi", "ebp", "esp"},
        )
        self.assertEqual(
            {register for register, relation in continuation.items() if relation == "related_word"},
            {"eax", "ecx", "edx"},
        )
        self.assertEqual(
            relations["edges"][0]["environment_register_policy"]["id"],
            "win32-cdecl-stdcall-registers-v1",
        )
        self.assertEqual(relations["counts"]["environment_register_policy_edges"], 1)

    def test_indirect_import_is_not_replayed_as_a_direct_external_call(self):
        contract = {"regions": [{}, {}]}
        direct = {
            "environment_barrier": True,
            "source_region_index": 0,
            "target_region_index": 1,
        }
        indirect = {
            **direct,
            "indirect_target_profile": "inductive_iat_register_call_v1",
        }

        self.assertTrue(_external_register_policy_replay_candidate(contract, direct))
        self.assertFalse(_external_register_policy_replay_candidate(contract, indirect))

        contract["regions"][1]["input_import_relations"] = [{
            "original": "ebp", "candidate": "edi",
        }]
        self.assertFalse(_external_register_policy_replay_candidate(contract, direct))

    def test_import_register_atoms_replace_redundant_related_word_atoms(self):
        register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        pairs = [
            {"original": register, "candidate": register}
            for register in register_names
        ]
        source_registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }
        source_registers["ebp"] = {
            "op": "read32", "address": {"op": "constant", "value": 0x402200},
        }
        target_registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }
        imported = {"dll": "kernel32.dll", "symbol": "TlsGetValue"}
        contract = {
            "code_targets": [],
            "value_targets": [],
            "regions": [
                {
                    "id": "seed", "numeric_id": 0, "root": True,
                    "inputs": pairs, "outputs": pairs, "values": [],
                    "input_import_relations": [],
                },
                {
                    "id": "use", "numeric_id": 1, "root": False,
                    "inputs": pairs, "outputs": pairs, "values": [],
                    "input_import_relations": [{
                        "original": "ebp", "candidate": "ebp", "import": imported,
                    }],
                },
            ],
        }
        _, relations = _synthesize_register_relations(
            contract,
            [
                {
                    "original_ir": {
                        "registers": source_registers,
                        "outcome": {"op": "jump", "target": 1},
                    },
                    "candidate_ir": {
                        "registers": source_registers,
                        "outcome": {"op": "jump", "target": 1},
                    },
                },
                {
                    "original_ir": {
                        "registers": target_registers,
                        "outcome": {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
                    },
                    "candidate_ir": {
                        "registers": target_registers,
                        "outcome": {"op": "returned", "target": {"op": "input_reg", "reg": "eax"}},
                    },
                },
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )
        self.assertNotIn(
            "ebp", {relation["original"] for relation in relations["regions"][0]["outputs"]}
        )
        self.assertNotIn(
            "ebp", {relation["original"] for relation in relations["regions"][1]["inputs"]}
        )
        self.assertTrue(relations["regions"][0]["fully_supported_output_transfer"])
        self.assertTrue(relations["edges"][0]["relation_preservation_proposed"])

    def test_function_metadata_adds_explicit_call_return_proposal_edges(self):
        register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in register_names
        }

        def behavior(outcome):
            return {"registers": registers, "outcome": outcome}

        pairs = [
            {"original": register, "candidate": register}
            for register in register_names
        ]
        regions = [
            {
                "id": "caller",
                "numeric_id": 0,
                "root": True,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
            },
            {
                "id": "callee-entry",
                "numeric_id": 1,
                "root": False,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
                "function_id": "callee",
                "function_entry": True,
            },
            {
                "id": "callee-return",
                "numeric_id": 2,
                "root": False,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
                "function_id": "callee",
                "function_entry": False,
            },
            {
                "id": "continuation",
                "numeric_id": 3,
                "root": False,
                "inputs": pairs,
                "outputs": pairs,
                "values": [],
            },
        ]
        behaviors = [
            behavior({"op": "call", "target": 1, "continuation": 3}),
            behavior({"op": "jump", "target": 2}),
            behavior({"op": "returned", "target": {"op": "input_reg", "reg": "eax"}}),
            behavior({"op": "returned", "target": {"op": "input_reg", "reg": "eax"}}),
        ]
        _, relations = _synthesize_register_relations(
            {"code_targets": [], "value_targets": [], "regions": regions},
            [
                {"original_ir": item, "candidate_ir": item}
                for item in behaviors
            ],
            original_image_base=0x400000,
            candidate_image_base=0x400000,
        )

        call_return = next(
            edge for edge in relations["edges"] if edge["kind"] == "call_return"
        )
        self.assertEqual(call_return["source_region_index"], 2)
        self.assertEqual(call_return["target_region_index"], 3)
        self.assertEqual(call_return["callsite_region_index"], 0)
        self.assertEqual(call_return["callee_entry_region_index"], 1)
        self.assertTrue(call_return["requires_call_stack_proof"])
        self.assertFalse(call_return["relation_preservation_proposed"])
        self.assertEqual(relations["counts"]["call_return_edges"], 1)
        self.assertTrue(all(
            relation["relation"] == "exact"
            for relation in relations["regions"][3]["inputs"]
        ))
        proof_ir = _attach_register_relation_analysis(
            {"obligations": []}, relations
        )
        call_return_obligation = next(
            obligation
            for obligation in proof_ir["obligations"]
            if obligation["kind"] == "call_return_stack_composition"
        )
        self.assertEqual(call_return_obligation["status"], "incomplete")
        self.assertEqual(call_return_obligation["return_region_index"], 2)
        self.assertIn("return-address", call_return_obligation["blocker"])

    def test_memory_pullback_support_recurses_through_local_write_reads(self):
        register = lambda name: {"op": "input_reg", "reg": name}
        prior = {"op": "read8", "address": register("ebx")}
        nested = {
            "op": "read8_after_write",
            "address": register("ebx"),
            "write_address": register("esp"),
            "write_value": register("eax"),
            "prior": prior,
        }
        self.assertEqual(
            _semantic_memory_pullback_support(nested),
            ("lean_pullback_supported", None),
        )
        nested["prior"] = {
            "op": "read8",
            "address": {"op": "input_flag_value", "bit": 5},
        }
        status, blocker = _semantic_memory_pullback_support(nested)
        self.assertEqual(status, "unsupported_nested_post_write_read")
        self.assertIn("flag-dependent", blocker)

    def test_x87_load_pullback_accepts_predecessor_control_replacement(self):
        register = lambda name: {"op": "input_reg", "reg": name}
        observation = {
            "op": "load",
            "format": "float64",
            "address": {"op": "add", "left": register("esp"),
                        "right": {"op": "constant", "value": 8}},
            "control": {"op": "input_x87_control"},
        }
        source = {
            "x87": {
                "control": {"op": "read32", "address": register("eax")},
                "status": {"op": "input_x87_status"},
            }
        }
        self.assertTrue(_semantic_x87_load_pullback_supported(observation, source))
        observation["control"] = {"op": "input_x87_status"}
        self.assertFalse(_semantic_x87_load_pullback_supported(observation, source))

    def test_weakest_precondition_synthesizes_compare_branch_bound_invariant(self):
        registers = {
            register: {"op": "input_reg", "reg": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        }
        truth_flags = {
            "zero": None,
            "carry": None,
            "sign": None,
            "overflow": None,
            "parity": None,
        }
        compare_flags = {
            **truth_flags,
            "zero": {
                "op": "equal",
                "left": {"op": "input_reg", "reg": "ecx"},
                "right": {"op": "constant", "value": 90},
            },
            "carry": {
                "op": "unsigned_less",
                "left": {"op": "input_reg", "reg": "ecx"},
                "right": {"op": "constant", "value": 90},
            },
        }
        branch = {
            "op": "and",
            "left": {"op": "not", "value": {"op": "input_flag", "index": 0}},
            "right": {"op": "not", "value": {"op": "input_flag", "index": 6}},
        }

        def behavior(outcome, flags=truth_flags):
            return {
                "format": "stage-a-normalized-behavior-v1",
                "registers": registers,
                "x87": {},
                "writes": [],
                "flags": flags,
                "outcome": outcome,
            }

        regions = [
            {"id": "compare", "numeric_id": 0, "root": True, "bounds": [], "address_separations": []},
            {"id": "branch", "numeric_id": 1, "root": False, "bounds": [], "address_separations": []},
            {
                "id": "table",
                "numeric_id": 2,
                "root": False,
                "bounds": [{"original": "ecx", "candidate": "ecx", "unsigned_lt": 91}],
                "address_separations": [],
            },
        ]
        compare = behavior({"op": "jump", "target": 1}, compare_flags)
        choose = behavior({
            "op": "branch", "condition": branch, "taken": 99, "fallthrough": 2,
        })
        table = behavior({"op": "jump", "target": 99})
        synthesis = _synthesize_relational_invariants(
            {"regions": regions},
            [
                {"original_ir": compare, "candidate_ir": compare},
                {"original_ir": choose, "candidate_ir": choose},
                {"original_ir": table, "candidate_ir": table},
            ],
        )

        self.assertEqual(synthesis["counts"]["seeds"], 2)
        self.assertEqual(synthesis["counts"]["region_invariants"], 4)
        self.assertEqual(synthesis["counts"]["edge_obligations"], 4)
        self.assertEqual(synthesis["counts"]["candidate_tautology_edges"], 2)
        self.assertEqual(synthesis["counts"]["barriers"], 0)
        self.assertEqual(
            synthesis["obligations"][0]["status"],
            "candidate_requires_lean_replay",
        )
        proved_edges = [
            edge for edge in synthesis["edge_obligations"]
            if edge["analysis_status"] == "candidate_tautology"
        ]
        self.assertEqual({edge["source_id"] for edge in proved_edges}, {"compare"})
        self.assertTrue(all(edge["lean_status"] == "pending" for edge in proved_edges))

        missing_compare = behavior({"op": "jump", "target": 1})
        incomplete = _synthesize_relational_invariants(
            {"regions": regions},
            [
                {"original_ir": missing_compare, "candidate_ir": missing_compare},
                {"original_ir": choose, "candidate_ir": choose},
                {"original_ir": table, "candidate_ir": table},
            ],
        )
        self.assertIn(
            "loader_entry_assumption_required",
            {barrier["kind"] for barrier in incomplete["barriers"]},
        )
        self.assertTrue(all(
            obligation["status"] == "incomplete"
            for obligation in incomplete["obligations"]
        ))

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for invariant replay")
    def test_compare_branch_bound_invariant_is_replayed_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("83f95aeb007702ebfeebfe")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            spans = [(0x1000, 5), (0x1005, 2), (0x1007, 2), (0x1009, 2)]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, (rva, _) in enumerate(spans)
                ],
                "regions": [
                    {
                        "id": f"region-{index}",
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                        **({
                            "bounds": [{
                                "original": "ecx", "candidate": "ecx", "unsigned_lt": 91,
                            }],
                        } if index == 2 else {}),
                    }
                    for index, (rva, size) in enumerate(spans)
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")

            with patch.dict(os.environ, {"WINCR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=root / "report",
                )

            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            synthesis = json.loads(
                (root / "report" / "relational-invariants.json").read_text(encoding="utf-8")
            )
            self.assertEqual(synthesis["counts"]["barriers"], 0)
            self.assertEqual(
                synthesis["obligations"][0]["status"],
                "candidate_requires_lean_replay",
            )
            invariant_module = root / "report" / "lean" / "StageA" / "RelationalInvariantFamily0.lean"
            self.assertTrue(invariant_module.is_file())
            source = invariant_module.read_text(encoding="utf-8")
            self.assertIn("NormalizedInvariantPredicateEdgeClosed", source)
            self.assertIn("invariantPredicateEdgeClosed_of_wp", source)
            self.assertIn("successorRangePredicate", source)
            self.assertNotIn("evalNormalizedX87", source)
            self.assertIn("invariantFamily0Checked", source)
            inventory_modules = sorted(
                (root / "report" / "lean" / "StageA").glob(
                    "RelationalInvariantFamily0Inventory*.lean"
                )
            )
            self.assertEqual(len(inventory_modules), 2)
            self.assertTrue(all(
                "invariantEdgeInventoryClosed" in path.read_text(encoding="utf-8")
                for path in inventory_modules
            ))
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("GeneratedInvariantCertificate", bundle)
            self.assertIn("invariantFamily0Checked", bundle)
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            bound = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "cfg_bound_invariant"
            )
            self.assertEqual(bound["status"], "proved")
            self.assertEqual(
                bound["evidence"]["kind"],
                "lean_checked_inductive_invariant_family",
            )

            inventory_with_edge = next(
                path for path in inventory_modules
                if "ClaimedEdges : List InvariantEdgeSpec := [{"
                in path.read_text(encoding="utf-8")
            )
            inventory_lines = inventory_with_edge.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(inventory_lines):
                if "ClaimedEdges : List InvariantEdgeSpec := [{" in line:
                    inventory_lines[index] = line.split(":=", 1)[0] + ":= []"
                    break
            inventory_with_edge.write_text(
                "\n".join(inventory_lines) + "\n", encoding="utf-8"
            )
            inventory_with_edge.with_suffix(".olean").unlink(missing_ok=True)
            rejected = _run_lean_relational(
                root / "report" / "lean", bundle=inventory_with_edge.stem,
            )
            self.assertEqual(rejected["status"], "failed")
            self.assertIn("proved that the proposition", rejected["stdout"])

    def test_mapped_relocation_offsets_reject_duplicate_loader_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocation_pointer_table(0x2000))
            candidate.write_bytes(
                _pe32_image_with_relocation_pointer_table(0x3000, duplicate_data_entry=True)
            )
            issues = []

            offsets = _mapped_relocation_offsets(
                _parse_stage_a_pe(original),
                _parse_stage_a_pe(candidate),
                {
                    "id": 7,
                    "original_value": 0x402000,
                    "candidate_value": 0x403000,
                    "mapped_size": 8,
                },
                issues,
            )

            self.assertEqual(offsets, [])
            self.assertEqual(issues[0]["category"], "mapped_object_relocation_duplicate")
            self.assertEqual(issues[0]["duplicates"]["candidate"], [0])

    def test_normalized_fast_path_accepts_only_mapped_control_flow_differences(self):
        pairs = [
            {"original": register, "candidate": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        region = {
            "inputs": pairs,
            "outputs": pairs,
            "bounds": [],
            "values": [],
            "code_targets": [
                {"id": 1, "original_rva": 0x1000, "candidate_rva": 0x2000},
                {"id": 2, "original_rva": 0x1010, "candidate_rva": 0x2020},
            ],
        }
        core = "{ registers := shared"
        behaviors = {
            "original": core + ", outcome := some (StageA.Formal.OutcomeExpr.branch condition 4096 4112) }",
            "candidate": core + ", outcome := some (StageA.Formal.OutcomeExpr.branch condition 8192 8224) }",
        }
        self.assertTrue(_normalized_behavior_fast_path(region, behaviors))

        behaviors["candidate"] = core + ", outcome := some (StageA.Formal.OutcomeExpr.branch condition 8192 8225) }"
        self.assertFalse(_normalized_behavior_fast_path(region, behaviors))

    def test_identical_state_only_writes_use_compositional_checked_proof(self):
        write = (
            "[(StageA.Formal.Expr.add (StageA.Formal.Expr.inputReg "
            "(StageA.Formal.Reg.esp)) (StageA.Formal.Expr.constant 4), "
            "StageA.Formal.Expr.constant 7)]"
        )
        behavior = "{ registers := shared, writes := " + write + ", comparison := none }"
        behaviors = {"original": behavior, "candidate": behavior}
        region = {
            "inputs": [
                {"original": "eax", "candidate": "eax"},
                {"original": "esp", "candidate": "esp"},
            ],
        }

        self.assertEqual(
            _lean_identical_state_only_write_registers(region, behaviors),
            ["esp"],
        )
        source = _lean_identical_state_only_writes_component(7, region, behaviors)
        self.assertIsNotNone(source)
        assert source is not None
        self.assertIn("espGetRelated", source)
        self.assertIn("apply writesRelated_self", source)
        self.assertNotIn("memoryRelated", source)
        self.assertNotIn("addressSeparationsRelated", source)

        memory_behavior = behavior.replace(
            "StageA.Formal.Expr.constant 7",
            "StageA.Formal.Expr.read32 (StageA.Formal.Expr.constant 7)",
        )
        self.assertIsNone(_lean_identical_state_only_write_registers(
            region,
            {"original": memory_behavior, "candidate": memory_behavior},
        ))
        self.assertIsNone(_lean_identical_state_only_write_registers(
            region,
            {"original": behavior, "candidate": behavior.replace("constant 7", "constant 8")},
        ))
        self.assertIsNone(_lean_identical_state_only_write_registers(
            {"inputs": [{"original": "esp", "candidate": "ebp"}]},
            behaviors,
        ))

    def test_proof_shards_are_bounded_by_region_count_and_estimated_source_size(self):
        self.assertEqual(
            _partition_proof_shards(
                [100, 100, 450, 100, 100, 100],
                max_regions=3,
                target_bytes=500,
            ),
            [[0, 1], [2], [3, 4, 5]],
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for sharded relational proofs")
    def test_sharded_local_proof_does_not_import_raw_pe_attestations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xd8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            report = root / "report"

            with patch.dict(os.environ, {"WINCR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            shard = (report / "lean" / "StageA" / "RelationalProofShard0.lean").read_text(
                encoding="utf-8"
            )
            definitions = (
                report / "lean" / "StageA" / "RelationalDefinitionsShard0.lean"
            ).read_text(encoding="utf-8")
            bundle = (report / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            static_context = (
                report / "lean" / "StageA" / "RelationalStaticContext.lean"
            ).read_text(encoding="utf-8")
            closure_data = (
                report / "lean" / "StageA" / "RelationalProofClosureData.lean"
            ).read_text(encoding="utf-8")
            static_usage = (
                report / "lean" / "StageA" /
                "RelationalProofStaticUsageCertificate.lean"
            ).read_text(encoding="utf-8")
            static_usage_leaf = (
                report / "lean" / "StageA" /
                "RelationalProofStaticUsageLeaf0.lean"
            ).read_text(encoding="utf-8")
            static_usage_chunk = (
                report / "lean" / "StageA" /
                "RelationalProofStaticUsageChunk0.lean"
            ).read_text(encoding="utf-8")
            region_index_data = (
                report / "lean" / "StageA" /
                "RelationalProofRegionIndexData.lean"
            ).read_text(encoding="utf-8")
            original_coverage_data = (
                report / "lean" / "StageA" /
                "RelationalProofOriginalCoverageData.lean"
            ).read_text(encoding="utf-8")
            candidate_coverage_data = (
                report / "lean" / "StageA" /
                "RelationalProofCandidateCoverageData.lean"
            ).read_text(encoding="utf-8")
            original_decode = (
                report / "lean" / "StageA" / "RelationalProofOriginalDecodeChunk0.lean"
            ).read_text(encoding="utf-8")
            candidate_decode = (
                report / "lean" / "StageA" / "RelationalProofCandidateDecodeChunk0.lean"
            ).read_text(encoding="utf-8")
            direct = (
                report / "lean" / "StageA" / "RelationalProofDirectChunk0.lean"
            ).read_text(encoding="utf-8")
            region_chunk = (
                report / "lean" / "StageA" / "RelationalRegionChunk0.lean"
            ).read_text(encoding="utf-8")
            region_chunks = (
                report / "lean" / "StageA" / "RelationalRegionChunks.lean"
            ).read_text(encoding="utf-8")
            external_call_sites = (
                report / "lean" / "StageA" / "RelationalExternalCallSites.lean"
            ).read_text(encoding="utf-8")
            closure = (
                report / "lean" / "StageA" / "RelationalProofClosureBase.lean"
            ).read_text(encoding="utf-8")
            pullback = (
                report / "lean" / "StageA" / "RelationalMemoryPullbackChunk0.lean"
            ).read_text(encoding="utf-8")
            segment_refinement = (
                report / "lean" / "StageA" / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            proof_ir = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            product_graph = json.loads(
                (report / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIn("import StageA.RelationalDefinitionsShard0\n", shard)
            self.assertIn("import StageA.Relational\n", definitions)
            self.assertNotIn("RelationalProofBase", shard)
            self.assertNotIn("originalPe", shard)
            self.assertNotIn("originalPe", definitions)
            self.assertIn("import StageA.RelationalProofOriginal", original_decode)
            self.assertIn("originalBehavior0CheckedDecoded", original_decode)
            self.assertNotIn("candidatePe", original_decode)
            self.assertIn("import StageA.RelationalProofCandidate", candidate_decode)
            self.assertIn("candidateBehavior0CheckedDecoded", candidate_decode)
            self.assertNotIn("originalPe", candidate_decode)
            self.assertIn("regionEquivalentWithImports_of_decoded", direct)
            self.assertIn("region0CheckedDirect", direct)
            self.assertIn("directRegionChunk0Checked", direct)
            self.assertIn("import StageA.RelationalRegionChunk0", direct)
            self.assertNotIn("import StageA.RelationalRegionChunks\n", direct)
            self.assertIn("import StageA.RelationalDefinitionsShard0", region_chunk)
            self.assertIn("def regionChunk0", region_chunk)
            self.assertIn("import StageA.RelationalRegionChunk0", region_chunks)
            self.assertIn(
                "import StageA.RelationalEnvironment", external_call_sites
            )
            self.assertIn(
                "externalCallSitesStructurallyValid", external_call_sites
            )
            self.assertIn("structuralChecked", closure)
            self.assertIn("allDirectRegionsChecked", bundle)
            self.assertIn("allRegionsChecked", bundle)
            self.assertIn("staticProofContextChecked", static_context)
            self.assertIn("StaticProofContext.StructurallyValid staticProofContext", bundle)
            self.assertIn("allRegionsUseStaticContextChecked", static_usage)
            self.assertIn("regionChunk0UsesStaticContextChecked", static_usage)
            self.assertIn("staticUsageLeaf0Checked", static_usage_leaf)
            self.assertIn("regionChunk0StaticUsagePartition", static_usage_chunk)
            self.assertIn("regionIndexChunk0", region_index_data)
            self.assertIn("def originalCoverage", original_coverage_data)
            self.assertIn("def candidateCoverage", candidate_coverage_data)
            self.assertIn(
                "import StageA.RelationalProofOriginalCoverageData", closure_data
            )
            self.assertIn(
                "import StageA.RelationalProofCandidateCoverageData", closure_data
            )
            self.assertNotIn("SortedSpanCertificate := {", closure_data)
            self.assertNotIn("def allRegionIndex", closure_data)
            self.assertLess(len(closure_data), 5000)
            self.assertIn("segmentRefinementEdge0Checked", segment_refinement)
            self.assertIn("RelationalSegmentRefinement", segment_refinement)
            self.assertIn("localCodeTargetIds := [0]", segment_refinement)
            self.assertIn("localValueTargetIds := []", segment_refinement)
            self.assertIn("LocalCodeTargetsResolved", segment_refinement)
            self.assertIn("codeMap.resolveIds", segment_refinement)
            self.assertIn(
                "import StageA.RelationalStaticContextBase", segment_refinement
            )
            self.assertNotIn(
                "import StageA.RelationalStaticContext\n", segment_refinement
            )
            segment_certificate = (
                report / "lean" / "StageA" /
                "RelationalSegmentRefinementCertificate.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "import StageA.RelationalSegmentRefinementChunk0",
                segment_certificate,
            )
            self.assertIn(
                "generatedSegmentRefinementCertificateChecked",
                segment_certificate,
            )
            self.assertIn(
                "import StageA.RelationalSegmentRefinementCertificate",
                bundle,
            )
            self.assertIn("GeneratedSegmentRefinementCertificate", bundle)
            self.assertIn(
                "import StageA.RelationalProductNodeCoverageCertificate", bundle
            )
            product_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductGraphCertificate.lean"
            ).read_text(encoding="utf-8")
            edge_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductEdgeRefinementCertificate.lean"
            ).read_text(encoding="utf-8")
            node_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductNodeCoverageCertificate.lean"
            ).read_text(encoding="utf-8")
            edge_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductEdgeRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            node_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductNodeCoverageChunk0.lean"
            ).read_text(encoding="utf-8")
            reachability_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductReachabilityCertificate.lean"
            ).read_text(encoding="utf-8")
            reachability_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductReachabilityChunk0.lean"
            ).read_text(encoding="utf-8")
            decoded_control_certificate = (
                report / "lean" / "StageA" /
                "RelationalProductDecodedControlCertificate.lean"
            ).read_text(encoding="utf-8")
            decoded_control_chunk = (
                report / "lean" / "StageA" /
                "RelationalProductDecodedControlChunk0.lean"
            ).read_text(encoding="utf-8")
            reachable_local_certificate = (
                report / "lean" / "StageA" /
                "RelationalReachableProductLocalCertificate.lean"
            ).read_text(encoding="utf-8")
            reachable_node_chunk = (
                report / "lean" / "StageA" /
                "RelationalReachableProductNodeChunk0.lean"
            ).read_text(encoding="utf-8")
            reachable_edge_chunk = (
                report / "lean" / "StageA" /
                "RelationalReachableProductEdgeChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertNotIn("segmentRefinementEdge0Spec", product_certificate)
            self.assertIn(
                "CompleteProductEdgeRefinementCertificate", edge_certificate
            )
            self.assertIn("allProductEdgesRefinedChecked", edge_certificate)
            self.assertIn(
                "GeneratedPartialProductEdgeRefinementCertificate", edge_certificate
            )
            self.assertIn("productEdge0Refined", edge_chunk)
            self.assertIn(
                "GeneratedPartialProductNodeCoverageCertificate", node_certificate
            )
            self.assertIn("allCoveredProductNodesChecked", node_certificate)
            self.assertIn("productNode0UnconditionalBehaviorCovered", node_chunk)
            self.assertIn(
                "GeneratedDeclaredGraphReachabilityCertificate",
                reachability_certificate,
            )
            self.assertIn("productReachabilityNodesChecked", reachability_certificate)
            self.assertIn("nodeClosedAt", reachability_chunk)
            self.assertIn(
                "GeneratedPartialDecodedControlCompletenessCertificate",
                decoded_control_certificate,
            )
            self.assertIn(
                "productNode0DecodedControlEdgesComplete", decoded_control_chunk
            )
            self.assertIn("originalBehavior0CheckedDecoded", decoded_control_chunk)
            self.assertIn(
                "GeneratedPartialReachableProductLocalCertificate",
                reachable_local_certificate,
            )
            self.assertIn(
                "def reachableProductLocalCertificate",
                reachable_local_certificate,
            )
            self.assertIn(
                "productNode0DecodedControlEdgesComplete",
                reachable_node_chunk,
            )
            self.assertIn("productEdge0Refined", reachable_edge_chunk)
            self.assertIn(
                "generatedPartialReachableProductLocalCertificateChecked",
                bundle,
            )
            self.assertEqual(
                product_graph["counts"],
                {
                    "covered_nodes": 1,
                    "declared_reachability_control_closed": True,
                    "decoded_control_complete_nodes": 1,
                    "decoded_control_incomplete_nodes": 0,
                    "edges": 1,
                    "external_proved_edges": 0,
                    "incomplete_edges": 0,
                    "locally_refined_edges": 1,
                    "nodes": 1,
                    "proved_edges": 1,
                    "declared_reachable_covered_nodes": 1,
                    "declared_reachable_nodes": 1,
                    "declared_reachable_uncovered_nodes": 0,
                    "declared_unreachable_nodes": 0,
                    "potential_reachable_nodes": 1,
                    "potential_reachable_feasible_edges": 1,
                    "potential_unrepresented_control_edges": 0,
                    "reachability_truncated_by_control_frontier": False,
                    "reachable_decoded_control_frontier_nodes": 0,
                    "reachable_feasible_edges": 1,
                    "reachable_local_refinement_frontier_edges": 0,
                    "reachable_locally_refined_edges": 1,
                    "reachable_product_local_complete": True,
                    "roots": 1,
                    "uncovered_nodes": 0,
                },
            )
            self.assertTrue(product_graph["evidence"]["complete"])
            self.assertEqual(product_graph["evidence"]["covered_node_ids"], [0])
            self.assertEqual(
                product_graph["evidence"]["declared_reachable_node_ids"], [0]
            )
            self.assertEqual(
                product_graph["evidence"]["declared_reachable_bits"], [True]
            )
            self.assertEqual(
                product_graph["evidence"]["decoded_control_complete_node_ids"], [0]
            )
            self.assertTrue(
                product_graph["evidence"]["reachable_product_local_complete"]
            )
            self.assertEqual(
                product_graph["evidence"][
                    "reachable_decoded_control_frontier_node_ids"
                ],
                [],
            )
            self.assertEqual(
                product_graph["edges"][0]["original_guard"],
                {"op": "bool_constant", "value": True},
            )
            self.assertEqual(
                product_graph["edges"][0]["candidate_guard"],
                {"op": "bool_constant", "value": True},
            )
            self.assertEqual(
                proof_ir["product_graph_summary"]["proved_edges"], 1
            )
            self.assertEqual(
                proof_ir["segment_refinement_summary"],
                {
                    "edges": 1,
                    "incomplete": 0,
                    "interface": "StageA.Relational.RelationalSegmentRefinement",
                    "proved": 1,
                },
            )
            self.assertFalse(
                (report / "lean" / "StageA" / "RelationalProofGoalChunk0.lean").exists()
            )

            negative = report / "lean" / "StageA" / "RelationalStaticContextNegative.lean"
            negative.write_text(
                "import StageA.RelationalStaticContext\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "def ambiguousCodeMap : StaticCodeMap := {\n"
                "  entries := #[\n"
                "    { id := 0, regionIndex := 0, originalRva := 4096, candidateRva := 4096 },\n"
                "    { id := 1, regionIndex := 0, originalRva := 4096, candidateRva := 4096 }]\n"
                "  originalAddresses := #[\n"
                "    { targetId := 0, kind := .canonical },\n"
                "    { targetId := 1, kind := .canonical }]\n"
                "  candidateAddresses := #[\n"
                "    { targetId := 0, kind := .canonical },\n"
                "    { targetId := 1, kind := .canonical }]\n"
                "}\n\n"
                "theorem ambiguousCodeMapRejected :\n"
                "    ambiguousCodeMap.valid originalPe candidatePe = false := by decide\n\n"
                "def compatibleOverlappingDataMap : StaticDataMap := {\n"
                "  entries := #[\n"
                "    { id := 0, originalValue := 4198400, candidateValue := 4198400, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 },\n"
                "    { id := 1, originalValue := 4198400, candidateValue := 4198400, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 }]\n"
                "  originalOrder := [0, 1]\n"
                "  candidateOrder := [0, 1]\n"
                "}\n\n"
                "def ambiguousOverlappingDataMap : StaticDataMap := {\n"
                "  entries := #[\n"
                "    { id := 0, originalValue := 4198400, candidateValue := 4198400, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 },\n"
                "    { id := 1, originalValue := 4198400, candidateValue := 4198404, originalRelocationRva := 0, candidateRelocationRva := 0, mappedSize := 4 }]\n"
                "  originalOrder := [0, 1]\n"
                "  candidateOrder := [0, 1]\n"
                "}\n\n"
                "theorem compatibleOverlappingDataMapAccepted :\n"
                "    compatibleOverlappingDataMap.valid originalPe candidatePe = true := by decide\n\n"
                "theorem ambiguousOverlappingDataMapRejected :\n"
                "    ambiguousOverlappingDataMap.valid originalPe candidatePe = false := by decide\n\n"
                "end StageA.GeneratedRelational\n",
                encoding="utf-8",
            )
            negative_result = _run_lean_relational(
                report / "lean", bundle="RelationalStaticContextNegative"
            )
            self.assertEqual(negative_result["status"], "checked", negative_result)

            product_negative = (
                report / "lean" / "StageA" /
                "RelationalProductGraphNegative.lean"
            )
            product_negative.write_text(
                "import StageA.RelationalProductNodeCoverageCertificate\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "def omittedReachableProductEdgeGraph : RelationalProductGraph := {\n"
                "  relationalProductGraph with\n"
                "  nodes := #[{ id := 0, targetId := 0, root := true, "
                "outgoingEdgeIds := [] }]\n"
                "}\n\n"
                "theorem omittedReachableProductEdgeRejected :\n"
                "    omittedReachableProductEdgeGraph.edgeAtValid 0 = false := by decide\n\n"
                "theorem omittedDecodedControlExitRejected :\n"
                "    decodedControlEdgesMatch omittedReachableProductEdgeGraph 0 region0\n"
                "      originalBehavior0 candidateBehavior0 = false := by decide\n\n"
                "def falseGuardProductGraph : RelationalProductGraph := {\n"
                "  relationalProductGraph with\n"
                "  edges := #[{ relationalProductGraph.edges[0] with\n"
                "    originalGuard := .equal (.constant 0) (.constant 1) }]\n"
                "}\n\n"
                "theorem falseGuardCoverageRejected :\n"
                "    ¬ UnconditionalProductNodeBehaviorCovered staticProofContext\n"
                "      falseGuardProductGraph 0 0 segmentRefinementEdge0Spec\n"
                "      region0.inputInvariant region0.inputInvariant := by\n"
                "  intro covered\n"
                "  unfold UnconditionalProductNodeBehaviorCovered at covered\n"
                "  have nodeResolved : falseGuardProductGraph.getNode? 0 =\n"
                "      some falseGuardProductGraph.nodes[0] := by decide\n"
                "  have edgeResolved : falseGuardProductGraph.getEdge? 0 =\n"
                "      some falseGuardProductGraph.edges[0] := by decide\n"
                "  rw [nodeResolved, edgeResolved] at covered\n"
                "  rcases covered with ⟨_, _, guard, _⟩\n"
                "  have guardDiffers : falseGuardProductGraph.edges[0].originalGuard ≠\n"
                "      unconditionalProductGuard := by decide\n"
                "  exact guardDiffers guard\n\n"
                "theorem falseGuardDecodedControlExitRejected :\n"
                "    decodedControlEdgesMatch falseGuardProductGraph 0 region0\n"
                "      originalBehavior0 candidateBehavior0 = false := by decide\n\n"
                "def omittedReachableTargetGraph : RelationalProductGraph := {\n"
                "  nodes := #[\n"
                "    { id := 0, targetId := 0, root := true, outgoingEdgeIds := [0] },\n"
                "    { id := 1, targetId := 0, root := false, outgoingEdgeIds := [] }]\n"
                "  edges := #[RelationalProductEdge.mk 0 0 1 0 0 .jump\n"
                "    unconditionalProductGuard unconditionalProductGuard false]\n"
                "  rootNodeIds := [0]\n"
                "}\n\n"
                "def omittedReachableTargetEvidence :\n"
                "    RelationalProductReachabilityEvidence := {\n"
                "  reachable := #[true, false]\n"
                "}\n\n"
                "theorem omittedReachableTargetRejected :\n"
                "    RelationalProductReachabilityEvidence.nodeClosedAt\n"
                "      omittedReachableTargetGraph omittedReachableTargetEvidence 0 = false :=\n"
                "  by decide\n\n"
                "end StageA.GeneratedRelational\n",
                encoding="utf-8",
            )
            product_negative_result = _run_lean_relational(
                report / "lean", bundle="RelationalProductGraphNegative"
            )
            self.assertEqual(
                product_negative_result["status"],
                "checked",
                product_negative_result,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_whole_program_equivalence_kernel_checks_without_sorry(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            source = (stage_a / "RelationalCertificates.lean").read_text(
                encoding="utf-8"
            )
            self.assertIn("theorem pe32ProgramsEquivalent", source)
            self.assertIn("ProductStepRefinement", source)
            self.assertNotIn("sorry", source)
            result = _run_lean_relational(
                lean_dir, bundle="RelationalCertificates"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_loop_emits_and_checks_closed_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(root / "relation.json", region_size=2)
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["acceptance"]["status"], "ready")
            self.assertEqual(
                result["expected_final_theorem"], RELATIONAL_ACCEPTANCE_THEOREM
            )
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(graph["root_module"], "RelationalAcceptance")
            self.assertEqual(graph["acceptance"]["profile"], "direct-no-write-jump-v1")
            self.assertIn("RelationalAcceptance", graph["modules"])
            self.assertIn("RelationalAcceptanceChunk0", graph["modules"])
            acceptance_source = (
                prepared / "lean" / "StageA" / "RelationalAcceptance.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("theorem candidatePE32ProgramsEquivalent", acceptance_source)
            self.assertNotIn("sorry", acceptance_source)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("._native.", lean["stdout"])
            self.assertNotIn("sorryAx", lean["stdout"])

            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            finalized = _finalize_nix_proof_ir(
                proof_ir,
                theorem_checked=True,
                theorem=RELATIONAL_ACCEPTANCE_THEOREM,
                result_path=Path("/nix/store/test-whole-program-proof"),
            )
            self.assertEqual(finalized["status"], "satisfied")
            self.assertTrue(all(
                obligation["status"] == "proved"
                for obligation in finalized["obligations"]
            ))
            self.assertTrue(all(
                family["status"] in {"satisfied", "not_applicable"}
                for family in finalized["families"]
            ))

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for memory-write proofs")
    def test_paired_stack_word_write_loop_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("c744240800000000ebf6")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json", region_size=len(code)
            )
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"],
                "paired-stack-write-control-v1",
            )
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            segment_source = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("PairedStackWordWriteClaim", segment_source)
            self.assertIn(
                "segmentTransitionClosed_of_paired_stack_word_write",
                segment_source,
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for memory-write proofs")
    def test_paired_stack_word_writes_loop_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("89042489542404ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json", region_size=len(code)
            )
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"],
                "paired-stack-write-control-v1",
            )
            self.assertEqual(
                result["composition_progress"]["counts"][
                    "rooted_segment_refinement_frontier_edges"
                ],
                0,
            )
            segment_source = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("PairedStackWordWritesClaim", segment_source)
            self.assertIn(
                "segmentTransitionClosed_of_paired_stack_word_writes",
                segment_source,
            )
            proof_ir = json.loads(
                (prepared / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            segment_obligations = [
                obligation for obligation in proof_ir["obligations"]
                if obligation.get("kind") == "relational_segment_refinement"
                and obligation.get("status") == "proved"
            ]
            self.assertEqual(len(segment_obligations), 1)
            certificate = segment_obligations[0]["analysis"]["certificate"]
            self.assertEqual(
                certificate["format"], RELATIONAL_SEGMENT_CERTIFICATE_FORMAT
            )
            self.assertEqual(
                certificate["certificate_profile"],
                "composable_paired_stack_word_writes_v1",
            )
            self.assertEqual(
                len(certificate["paired_stack_writes_claim"]["writes"]), 2
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_local_proof_driver_passes_only_on_replayable_acceptance_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(root / "relation.json", region_size=2)
            report = root / "report"

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(
                result["proof"]["theorem"], RELATIONAL_ACCEPTANCE_THEOREM
            )
            self.assertTrue(
                result["claim_scope"]["whole_program_observational_equivalence"]
            )
            self.assertTrue(result["claim_scope"]["acceptance_eligible"])
            graph = _validate_relational_module_graph(report)
            self.assertEqual(graph["root_module"], "RelationalAcceptance")
            self.assertEqual(
                graph["expected_final_theorem"], RELATIONAL_ACCEPTANCE_THEOREM
            )

            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "pass", replay)
            self.assertEqual(
                replay["lean_check"]["theorem"], RELATIONAL_ACCEPTANCE_THEOREM
            )

            acceptance_source = (
                report / "lean" / "StageA" / "RelationalAcceptance.lean"
            )
            acceptance_source.write_text(
                acceptance_source.read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            tampered = stage_a_check_relational_proof(report=report)
            self.assertEqual(tampered["status"], "incomplete")
            self.assertFalse(tampered["checks"]["module_graph_valid"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_direct_call_return_loop_checks_runtime_frames_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = b"\xe8\x02\x00\x00\x00\xeb\xf9\xc3"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                    {"id": 2, "original_rva": 0x1007, "candidate_rva": 0x1007},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x1007, "size": 1},
                        "candidate": {"rva": 0x1007, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(result["acceptance"]["status"], "ready")
            self.assertEqual(result["acceptance"]["profile"], "finite-call-return-v1")
            progress = json.loads(
                (prepared / "composition-progress.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["composition_progress"], progress)
            self.assertEqual(progress["status"], "ready_for_lean")
            self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 3)
            self.assertEqual(
                progress["counts"]["rooted_reachable_feasible_edges"], 2
            )
            self.assertEqual(progress["counts"]["rooted_refined_segments"], 2)
            self.assertEqual(progress["next_work"], [])
            self.assertEqual(
                result["acceptance"]["control_states"],
                [
                    {"node_id": 0, "calls": [], "frame_offsets": []},
                    {
                        "node_id": 2,
                        "calls": [1],
                        "frame_offsets": [{"original": 0, "candidate": 0}],
                    },
                    {"node_id": 1, "calls": [], "frame_offsets": []},
                ],
            )
            normalized = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(normalized["regions"][1]["stack_windows"][0]["bytes_above"], 1)
            self.assertEqual(normalized["regions"][2]["stack_windows"][0]["bytes_above"], 5)

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms",
                lean["stdout"],
            )
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_external_call_loop_checks_paired_environment_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = b"\xff\x15" + struct.pack("<I", iat_address) + b"\xeb\xf8"
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount",
            ))
            candidate.write_bytes(_pe32_import_image(
                code, symbol="GetTickCount",
            ))
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            contract = root / "relation.json"
            contract.write_text(json.dumps({
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1006, "candidate_rva": 0x1006},
                ],
                "regions": [
                    {
                        "id": "import-call", "root": True,
                        "original": {"rva": 0x1000, "size": 6},
                        "candidate": {"rva": 0x1000, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1006, "size": 2},
                        "candidate": {"rva": 0x1006, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {
                        "dll": "kernel32.dll", "symbol": "GetTickCount",
                    },
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"], "paired-external-call-v1"
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["external_call", "jump"],
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_top_level_return_checks_terminal_invariant_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            contract = self._write_contract(root / "relation.json", region_size=1)
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["node_steps"][0]["kind"], "terminate"
            )
            self.assertEqual(
                result["acceptance"]["terminal_invariant"]["stack_windows"], []
            )
            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_guarded_branch_emits_and_checks_closed_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = b"\x85\xc0\x74\x02\xeb\xfa\xeb\xf8"
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [
                {"original": register, "candidate": register}
                for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            ]
            relation = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": index, "original_rva": rva, "candidate_rva": rva}
                    for index, rva in enumerate((0x1000, 0x1004, 0x1006))
                ],
                "regions": [
                    {
                        "id": name,
                        "root": index == 0,
                        "original": {"rva": rva, "size": size},
                        "candidate": {"rva": rva, "size": size},
                        "inputs": pairs,
                        "outputs": pairs,
                    }
                    for index, (name, rva, size) in enumerate((
                        ("condition", 0x1000, 4),
                        ("fallthrough", 0x1004, 2),
                        ("taken", 0x1006, 2),
                    ))
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(relation), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready")
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(
                graph["acceptance"]["profile"], "guarded-no-write-control-v1"
            )
            condition_step = graph["acceptance"]["node_steps"][0]
            self.assertEqual(condition_step["kind"], "branch")
            self.assertEqual(
                [edge["edge_id"] for edge in condition_step["edges"]], [0, 1]
            )

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertNotIn("sorryAx", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_representative_control_slice_closes_whole_program_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_representative_control_image(0x3000))
            candidate.write_bytes(
                _pe32_representative_control_image(0x4000, terminal_rva=0x1030)
            )
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [
                {
                    "id": name,
                    "kind": "code",
                    "original": {"rva": rva, "size": size},
                    "candidate": {"rva": rva, "size": size},
                }
                for name, rva, size in (
                    ("internal-call", 0x1000, 5),
                    ("import-call", 0x1005, 6),
                    ("conditional-loop", 0x100B, 4),
                    ("indirect-jump", 0x100F, 6),
                    ("internal-return", 0x1015, 1),
                )
            ] + [{
                "id": "terminal-return",
                "kind": "code",
                "original": {"rva": 0x1020, "size": 1},
                "candidate": {"rva": 0x1030, "size": 1},
            }, {
                "id": "alignment-padding",
                "kind": "padding",
                "original": {"rva": 0x1016, "size": 10},
                "candidate": {"rva": 0x1016, "size": 26},
            }]}), encoding="utf-8")
            contract = root / "relation.json"
            stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            payload["machine_import_call_contracts"] = [{
                "id": 0,
                "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 0,
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }]
            contract.write_text(json.dumps(payload), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["acceptance"]["status"], "ready", result)
            self.assertEqual(
                result["acceptance"]["profile"],
                "representative-compositional-control-v1",
            )
            self.assertEqual(
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "external_call", "branch", "indirect_jump", "return", "terminate"],
            )
            progress = result["composition_progress"]
            self.assertEqual(progress["counts"]["rooted_reachable_nodes"], 6)
            self.assertEqual(progress["counts"]["rooted_reachable_feasible_edges"], 5)
            self.assertEqual(progress["counts"]["rooted_decoded_control_frontier_nodes"], 0)
            self.assertEqual(progress["counts"]["rooted_segment_refinement_frontier_edges"], 0)
            self.assertEqual(progress["frontiers"]["acceptance_blockers"], [])

            lean = _run_lean_relational(
                prepared / "lean", bundle="RelationalAcceptance"
            )
            self.assertEqual(lean["status"], "checked", lean)
            self.assertIn(
                "candidatePE32ProgramsEquivalent' depends on axioms", lean["stdout"]
            )
            self.assertNotIn("sorryAx", lean["stdout"])
            self.assertNotIn("._native.", lean["stdout"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for relational preparation")
    def test_prepare_emits_valid_source_only_derivation_graph_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x8b\x03\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8b\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertEqual(list(prepared.rglob("*.olean")), [])
            progress = json.loads(
                (prepared / "composition-progress.json").read_text(encoding="utf-8")
            )
            self.assertEqual(result["composition_progress"], progress)
            self.assertEqual(progress["status"], "incomplete")
            self.assertEqual(
                progress["metric_policy"]["primary"],
                "rooted_product_composition",
            )
            self.assertTrue(
                progress["metric_policy"]["local_proof_counts_are_secondary"]
            )
            graph = _validate_prepared_relational(prepared)
            self.assertEqual(graph["lean"]["trust"], 0)
            self.assertEqual(graph["root_module"], "RelationalBundle")
            self.assertIsNone(graph["expected_final_theorem"])
            self.assertEqual(graph["acceptance"]["status"], "incomplete")
            self.assertEqual(
                graph["acceptance"]["required_theorem"],
                "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
            )
            self.assertEqual(
                graph["acceptance"]["blockers"][0]["code"],
                "reachable_product_local_incomplete",
            )
            self.assertEqual(graph["acceptance"]["blockers"][0]["count"], 1)
            self.assertEqual(
                graph["modules"]["RelationalDecode"]["imports"], ["Formal"]
            )
            self.assertIn(
                "RelationalDecode", graph["modules"]["RelationalMachine"]["imports"]
            )
            self.assertIn(
                "RelationalMachine", graph["modules"]["Relational"]["imports"]
            )
            self.assertIn(
                "RelationalStaticContext", graph["modules"]
            )
            self.assertIn("RelationalSegment", graph["modules"])
            self.assertIn("RelationalComposition", graph["modules"])
            self.assertIn("RelationalEnvironment", graph["modules"])
            self.assertIn("RelationalCertificates", graph["modules"])
            self.assertIn(
                "RelationalSegmentRefinementCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductGraphCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductEdgeRefinementCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductNodeCoverageCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductReachabilityCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalProductDecodedControlCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductLocalCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductLocalEvidence", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductNodeCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductEdgeCertificate", graph["modules"]
            )
            self.assertIn(
                "RelationalReachableProductNodeChunk0", graph["modules"]
            )
            for module in (
                "RelationalProofRequiredInputsData",
                "RelationalProofPaddingData",
                "RelationalProofRegionIndexChunk0",
                "RelationalProofRegionIndexData",
                "RelationalProofRegionInventoryData",
                "RelationalProofStaticUsageLeaf0",
                "RelationalProofStaticUsageChunk0",
                "RelationalProofStaticUsageCertificate",
                "RelationalProofOriginalCoverageData",
                "RelationalProofCandidateCoverageData",
                "RelationalProofClosureData",
            ):
                self.assertIn(module, graph["modules"])
            self.assertNotIn(
                "RelationalSegment",
                graph["modules"]["RelationalStaticContextBase"]["imports"],
            )
            nodes = {node["id"]: node for node in graph["nodes"]}
            static_closure: set[str] = set()

            def include_static(node_id: str) -> None:
                if node_id in static_closure:
                    return
                static_closure.add(node_id)
                for dependency in nodes[node_id]["dependencies"]:
                    include_static(dependency)

            include_static("relationalstaticcontext")
            self.assertNotIn("relationalsegment", static_closure)
            segment_node = nodes["relationalsegmentrefinementcertificate"]
            self.assertNotIn(
                "relationalsegmentrefinementchunk0",
                segment_node["dependencies"],
            )
            self.assertEqual(segment_node["dependencies"], ["relationalsegment"])
            product_node = nodes["relationalproductgraphcertificate"]
            self.assertIn("relationalproductgraphchunk0", product_node["dependencies"])
            edge_node = nodes["relationalproductedgerefinementcertificate"]
            self.assertNotIn(
                "relationalproductedgerefinementchunk0",
                edge_node["dependencies"],
            )
            coverage_node = nodes["relationalproductnodecoveragecertificate"]
            self.assertNotIn(
                "relationalproductnodecoveragechunk0",
                coverage_node["dependencies"],
            )
            reachability_node = nodes["relationalproductreachabilitycertificate"]
            self.assertIn(
                "relationalproductreachabilitychunk0",
                reachability_node["dependencies"],
            )
            decoded_control_node = nodes[
                "relationalproductdecodedcontrolcertificate"
            ]
            self.assertIn(
                "relationalproductdecodedcontrolchunk0",
                decoded_control_node["dependencies"],
            )
            reachable_local_node = nodes[
                "relationalreachableproductlocalcertificate"
            ]
            self.assertIn(
                "relationalreachableproductlocalevidence",
                reachable_local_node["dependencies"],
            )
            self.assertIn(
                "relationalreachableproductnodecertificate",
                reachable_local_node["dependencies"],
            )
            self.assertIn(
                "relationalreachableproductedgecertificate",
                reachable_local_node["dependencies"],
            )
            self.assertNotIn(
                "relationalproductdecodedcontrolcertificate",
                reachable_local_node["dependencies"],
            )
            self.assertEqual(
                reachable_local_node["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalreachableproductnodechunk0"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalreachableproductedgecertificate"]["resource_class"],
                "high-memory",
            )
            self.assertNotIn("relationalproductedgerefinementchunk0", nodes)
            self.assertNotIn("relationalproductnodecoveragechunk0", nodes)
            self.assertEqual(
                nodes["relationalproductreachabilitychunk0"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalproductdecodedcontrolchunk0"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalprooforiginalcoveragedata"]["resource_class"],
                "high-memory",
            )
            self.assertEqual(
                nodes["relationalproofcandidatecoveragedata"]["resource_class"],
                "high-memory",
            )
            static_usage_pack = next(
                node for node in graph["nodes"]
                if "RelationalProofStaticUsageLeaf0" in node["modules"]
            )
            self.assertTrue(static_usage_pack["id"].startswith("static-usage-pack-"))
            self.assertEqual(static_usage_pack["resource_class"], "high-memory")
            self.assertEqual(
                nodes["relationalproofstaticusagechunk0"]["resource_class"],
                "medium",
            )
            self.assertIn(
                static_usage_pack["id"],
                nodes["relationalproofstaticusagechunk0"]["dependencies"],
            )
            self.assertEqual(
                nodes["relationalproofregionindexchunk0"]["resource_class"],
                "medium",
            )
            closure_node = nodes["relationalproofclosuredata"]
            self.assertIn(
                "relationalprooforiginalcoveragedata",
                closure_node["dependencies"],
            )
            self.assertIn(
                "relationalproofcandidatecoveragedata",
                closure_node["dependencies"],
            )
            with self.assertRaisesRegex(StageAInputError, "has no node"):
                stage_a_build_relational(
                    prepared=prepared,
                    out=root / "missing-node",
                    target_node="does-not-exist",
                )
            existing_node = graph["nodes"][0]["id"]
            with self.assertRaisesRegex(StageAInputError, "contains duplicates"):
                stage_a_build_relational(
                    prepared=prepared,
                    out=root / "duplicate-nodes",
                    target_nodes=[existing_node, existing_node],
                )
            full_build = stage_a_build_relational(
                prepared=prepared,
                out=root / "full-build",
            )
            self.assertEqual(full_build["status"], "incomplete")
            self.assertFalse(full_build["checks"]["whole_program_acceptance_ready"])
            self.assertFalse(full_build["checks"]["nix_graph_built"])
            self.assertGreater(graph["counts"]["derivations"], 1)
            self.assertTrue(any(node["id"].startswith("definitions-pack-") for node in graph["nodes"]))
            proof_pack = next(node for node in graph["nodes"] if node["id"].startswith("local-proof-pack-"))
            self.assertEqual(proof_pack["resource_class"], "medium")
            semantic_ir = json.loads(
                (prepared / "relational-semantic-ir.json").read_text(encoding="utf-8")
            )
            self.assertEqual(semantic_ir["format"], "stage-a-relational-semantic-ir-v1")
            self.assertEqual(semantic_ir["trust"]["role"], "analysis_and_proof_proposal_only")
            self.assertEqual(len(semantic_ir["regions"]), 1)
            extracted = semantic_ir["regions"][0]
            self.assertEqual(extracted["original"]["format"], "stage-a-normalized-behavior-v1")
            self.assertEqual(extracted["original"]["registers"]["eax"]["op"], "read32")
            self.assertEqual(
                extracted["original"]["registers"]["eax"]["address"],
                {"op": "input_reg", "reg": "ebx"},
            )
            self.assertEqual(extracted["original"]["outcome"]["op"], "jump")
            self.assertEqual(extracted["original"]["outcome"]["target"], 0)
            memory_contracts = json.loads(
                (prepared / "relational-memory-contracts.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                memory_contracts["format"], "stage-a-relational-memory-contracts-v1"
            )
            self.assertEqual(memory_contracts["counts"]["regions"], 1)
            self.assertEqual(memory_contracts["counts"]["read_observations"], 1)
            self.assertEqual(
                memory_contracts["counts"]["exact_pullback_pair_claims"], 1
            )
            self.assertEqual(
                memory_contracts["counts"]["edges_with_exact_pullback_pair_claims"], 1
            )
            read = memory_contracts["regions"][0]["reads"][0]
            self.assertEqual(read["status"], "paired_shape")
            self.assertEqual(
                read["original"]["pullback_support"], "lean_pullback_supported"
            )
            self.assertEqual(
                read["candidate"]["pullback_support"], "lean_pullback_supported"
            )
            self.assertEqual(
                memory_contracts["counts"]["pullback"]["original"],
                {
                    "ordinary_observations": 1,
                    "lean_pullback_supported": 1,
                    "regions_all_ordinary_reads_supported": 1,
                },
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                register_relations["format"],
                "stage-a-relational-register-relations-v1",
            )
            self.assertTrue(register_relations["converged"])
            self.assertEqual(
                register_relations["trust"]["role"],
                "analysis_and_proof_proposal_only",
            )
            self.assertEqual(
                register_relations["counts"]["lean_exact_output_claims"], 7
            )
            self.assertEqual(
                register_relations["regions"][0]["outputs"][0]["relation"],
                "exact",
            )
            self.assertEqual(
                register_relations["counts"]["register_output_claims"], 8
            )
            self.assertEqual(
                register_relations["counts"]["fully_supported_output_regions"], 1
            )
            self.assertEqual(
                {
                    claim["register"]
                    for claim in register_relations["regions"][0][
                        "exact_output_claims"
                    ]
                },
                {"ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"},
            )
            pullback_module = (
                prepared / "lean" / "StageA" / "RelationalMemoryPullbackChunk0.lean"
            )
            self.assertTrue(pullback_module.is_file())
            pullback_source = pullback_module.read_text(encoding="utf-8")
            self.assertIn("MemoryReadPullbackEdgeClosed", pullback_source)
            self.assertIn("memoryReadPullbackEdgeClosed_of_checked", pullback_source)
            self.assertIn("ExactMemoryReadPullbackPairEdgeClosed", pullback_source)
            self.assertIn(
                "exactMemoryReadPullbackPairEdgeClosed_of_checked", pullback_source
            )
            register_module = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalRegisterRelationsChunk0.lean"
            )
            register_source = register_module.read_text(encoding="utf-8")
            self.assertIn("RegisterOutputClaim.exactMemory", register_source)
            self.assertIn(
                "import StageA.RelationalGlobalMappingContext", register_source
            )
            self.assertIn("globalCodeTargets globalValueTargets", register_source)
            global_context = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalGlobalMappingContext.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("import StageA.RelationalMachine", global_context)
            self.assertNotIn("import StageA.Relational\n", global_context)
            self.assertIn("def globalCodeTargets", global_context)
            self.assertIn("def globalValueTargets", global_context)
            global_node = next(
                node
                for node in graph["nodes"]
                if node["id"] == "relationalglobalmappingcontext"
            )
            register_node = next(
                node
                for node in graph["nodes"]
                if node["id"] == "relationalregisterrelationschunk0"
            )
            self.assertIn(global_node["id"], register_node["dependencies"])
            bundle = (
                prepared / "lean" / "StageA" / "RelationalBundle.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "GeneratedOrdinaryMemoryReadPullbackCertificate", bundle
            )
            self.assertIn(
                "import StageA.RelationalMemoryPullbackChunk0", bundle
            )
            register_module = (
                prepared
                / "lean"
                / "StageA"
                / "RelationalRegisterRelationsChunk0.lean"
            )
            self.assertTrue(register_module.is_file())
            register_source = register_module.read_text(encoding="utf-8")
            self.assertIn("ExactRegisterOutputClaim", register_source)
            self.assertIn("allExactRegisterOutputClaims_of_checked", register_source)
            self.assertIn(
                "GeneratedExactRegisterRelationCertificate", bundle
            )
            self.assertIn(
                "import StageA.RelationalRegisterRelationsChunk0", bundle
            )

            second = root / "prepared-second"
            stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=second,
            )
            self.assertEqual(
                (prepared / "module-graph.json").read_bytes(),
                (second / "module-graph.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "prepared-proof.json").read_bytes(),
                (second / "prepared-proof.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "relational-semantic-ir.json").read_bytes(),
                (second / "relational-semantic-ir.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "relational-memory-contracts.json").read_bytes(),
                (second / "relational-memory-contracts.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "relational-register-relations.json").read_bytes(),
                (second / "relational-register-relations.json").read_bytes(),
            )
            self.assertEqual(
                (prepared / "composition-progress.json").read_bytes(),
                (second / "composition-progress.json").read_bytes(),
            )

            progress_path = prepared / "composition-progress.json"
            progress_bytes = progress_path.read_bytes()
            progress_path.write_bytes(progress_bytes + b"\n")
            with self.assertRaisesRegex(
                StageAInputError, "composition-progress.json"
            ):
                _validate_prepared_relational(prepared)
            progress_path.write_bytes(progress_bytes)

            manifest_path = prepared / "prepared-proof.json"
            manifest_bytes = manifest_path.read_bytes()
            manifest = json.loads(manifest_bytes)
            manifest["composition_progress"]["status"] = "inconsistent"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                StageAInputError, "composition progress does not match"
            ):
                _validate_prepared_relational(prepared)
            manifest_path.write_bytes(manifest_bytes)

            memory_contract_path = prepared / "relational-memory-contracts.json"
            memory_contract_bytes = memory_contract_path.read_bytes()
            memory_contract_path.write_bytes(memory_contract_bytes + b"\n")
            with self.assertRaisesRegex(
                StageAInputError, "relational-memory-contracts.json"
            ):
                _validate_prepared_relational(prepared)
            memory_contract_path.write_bytes(memory_contract_bytes)

            source = prepared / "lean" / "StageA" / "RelationalBundle.lean"
            source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "source hash does not match"):
                _validate_prepared_relational(prepared)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for relational proofs")
    def test_exact_register_transfer_and_cfg_edge_are_checked_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(
                root / "original.exe", bytes.fromhex("89442404ebfa")
            )
            candidate = self._write_pe(
                root / "candidate.exe", bytes.fromhex("89442404ebfa")
            )
            contract = self._write_contract(root / "relation.json", region_size=6)
            report = root / "report"

            with patch.dict(
                os.environ, {"WINCR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}
            ):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            relations = json.loads(
                (report / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(relations["counts"]["fully_exact_output_regions"], 1)
            self.assertEqual(relations["counts"]["fully_exact_edge_proposals"], 1)
            self.assertEqual(relations["counts"]["exact_pair_edge_claims"], 8)
            self.assertEqual(relations["counts"]["register_output_claims"], 8)
            self.assertEqual(relations["counts"]["fully_supported_output_regions"], 1)
            source = (
                report
                / "lean"
                / "StageA"
                / "RelationalRegisterRelationsChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn("ExactRegisterTransferClosed", source)
            self.assertIn("ExactRegisterRelationEdgeClosed", source)
            self.assertIn("exactRegisterRelationEdgeClosed_of_checked", source)
            self.assertIn("ExactRegisterRelationPairEdgeClosed", source)
            self.assertIn("exactRegisterRelationPairEdgeClosed_of_checked", source)
            self.assertIn("RegisterOutputClaim.identity", source)
            self.assertIn("RegisterTransferClosed", source)
            self.assertIn("registerTransferClosed_of_checked", source)
            proof_ir = json.loads(
                (report / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            transition = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "memory_transition_preservation"
            )
            self.assertEqual(transition["status"], "proved")
            self.assertEqual(
                transition["evidence"]["kind"],
                "lean_checked_exact_memory_pullback_transition",
            )
            memory_contracts = json.loads(
                (report / "relational-memory-contracts.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                memory_contracts["counts"]["exact_memory_transition_edges"], 1
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for call-return proofs")
    def test_call_return_shape_is_reconstructed_from_pe_bytes_by_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("e802000000ebfec3")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            blocks = [
                ("caller-call", 0x1000, 5, "caller", 0, True),
                ("caller-continuation", 0x1005, 2, "caller", 1, False),
                ("callee-return", 0x1007, 1, "callee", 0, True),
            ]
            mapping = root / "mapping.json"
            mapping.write_text(
                json.dumps({
                    "blocks": [
                        {
                            "id": block_id,
                            "kind": "code",
                            "original": {"rva": rva, "size": size},
                            "candidate": {"rva": rva, "size": size},
                            "source": {
                                "kind": "linker_map_capstone_block_match_v1",
                                "function": function,
                                "function_block_index": block_index,
                            },
                            **({
                                "root": {
                                    "checked": True,
                                    "kind": "linker_map_function",
                                    "symbol": function,
                                },
                            } if function_entry else {}),
                        }
                        for block_id, rva, size, function, block_index, function_entry
                        in blocks
                    ],
                }),
                encoding="utf-8",
            )
            contract = root / "relation.json"
            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            self.assertEqual(generated["status"], "generated", generated)

            with patch.dict(
                os.environ, {"WINCR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}
            ):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=root / "report",
                )

            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            relations = json.loads(
                (root / "report" / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(relations["counts"]["call_return_edges"], 1)
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(
                    encoding="utf-8"
                )
            )
            call_return = next(
                obligation
                for obligation in proof_ir["obligations"]
                if obligation["kind"] == "call_return_stack_composition"
            )
            self.assertEqual(call_return["status"], "incomplete")
            segment_obligations = [
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "relational_segment_refinement"
            ]
            self.assertGreaterEqual(len(segment_obligations), 1)
            self.assertIn(
                "call_stack_and_return_address",
                {obligation["repair_class"] for obligation in segment_obligations},
            )
            self.assertEqual(
                proof_ir["segment_refinement_summary"]["proved"], 1
            )
            proved_segments = [
                obligation for obligation in segment_obligations
                if obligation["status"] == "proved"
            ]
            self.assertEqual(len(proved_segments), 1)
            self.assertEqual(
                proved_segments[0]["analysis"]["certificate_profile"],
                "composable_local_no_write_v1",
            )
            register_sources = [
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob(
                    "RelationalRegisterRelationsChunk*.lean"
                )
            ]
            self.assertTrue(any(
                "CallReturnEdgeShapeClosed" in source
                for source in register_sources
            ))
            self.assertTrue(any(
                "callReturnEdgeShapeClosed_of_checked" in source
                for source in register_sources
            ))

    @unittest.skipUnless(
        shutil.which("lean") and shutil.which("nix") and os.environ.get("WINCR_RUN_NIX_INTEGRATION") == "1",
        "set WINCR_RUN_NIX_INTEGRATION=1 to run the Nix derivation graph",
    )
    def test_nix_executor_builds_and_trust_zero_audits_prepared_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            prepared = root / "prepared"
            stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=prepared,
            )

            result = stage_a_build_relational(
                prepared=prepared,
                out=root / "report",
                flake=Path(__file__).parents[1],
            )

            self.assertEqual(result["status"], "incomplete", result)
            self.assertTrue(result["checks"]["lean_trust_zero"])
            self.assertEqual(result["lean_audit"]["unexpected_axioms"], [])
            self.assertGreater(result["provenance"]["node_derivations"], 1)
            self.assertEqual(result["provenance"]["nix_paths"], 1)
            self.assertGreater(result["provenance"]["dependency_pack_bytes"], 0)
            provenance = json.loads(
                (root / "report" / "nix-provenance.json").read_text(encoding="utf-8")
            )
            self.assertTrue(provenance["nodes"])
            self.assertNotIn("out_path", provenance["nodes"][0])
            self.assertRegex(
                provenance["nodes"][0]["outputs"][0]["olean_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                provenance["dependency_pack"]["node_count"],
                result["provenance"]["node_derivations"] - 1,
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for process cancellation")
    def test_relational_lean_process_is_terminated_on_cancellation(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            for name in ("Formal.lean", "Relational.lean"):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "Slow.lean").write_text(
                "import StageA.Relational\n\n#eval IO.sleep 10000\n",
                encoding="utf-8",
            )
            cancellation = Event()
            timer = Timer(0.2, cancellation.set)
            started = time.monotonic()
            timer.start()
            try:
                result = _run_lean_relational(
                    lean_dir,
                    bundle="Slow",
                    cancel_event=cancellation,
                )
            finally:
                timer.cancel()

            self.assertEqual(result["status"], "cancelled", result)
            self.assertLess(time.monotonic() - started, 3)

    def test_relation_contract_generator_projects_complete_block_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 4},
                "candidate": {"rva": 0x1000, "size": 4},
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": "entry_loop",
                    "function_block_index": 0,
                },
                "root": {
                    "checked": True,
                    "kind": "linker_map_function",
                    "symbol": "entry_loop",
                },
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )

            self.assertEqual(result["status"], "generated")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertTrue(payload["regions"][0]["root"])
            self.assertEqual(payload["regions"][0]["function_id"], "entry_loop")
            self.assertEqual(payload["regions"][0]["function_block_index"], 0)
            self.assertEqual(payload["regions"][0]["function_cut_index"], 0)
            self.assertTrue(payload["regions"][0]["function_entry"])
            self.assertEqual(
                payload["regions"][0]["function_root_kind"],
                "linker_map_function",
            )
            self.assertEqual(payload["environment"]["id"], RELATIONAL_ENVIRONMENT_ID)
            self.assertEqual(payload["memory_relation"]["mode"], "identity")

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            renormalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            self.assertEqual(
                [region["target_ids"] for region in renormalized["regions"]],
                [region["target_ids"] for region in payload["regions"]],
            )
            self.assertEqual(
                [region["code_targets"] for region in renormalized["regions"]],
                [region["code_targets"] for region in payload["regions"]],
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for string-copy relational proofs")
    def test_relation_generator_splits_and_checks_symbolic_rep_movsd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("b904000000f3a5ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "copy-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(len(payload["regions"]), 2)
            self.assertEqual(
                (payload["regions"][0]["original"]["rva_start"], payload["regions"][0]["original"]["size"]),
                (0x1000, 7),
            )
            self.assertEqual(
                (payload["regions"][1]["original"]["rva_start"], payload["regions"][1]["original"]["size"]),
                (0x1007, 2),
            )

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )

    def test_contract_rejects_executable_coverage_gap_before_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json", region_size=2)

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertIn("executable_coverage_gap", {issue["category"] for issue in result["issues"]})

    def test_contract_rejects_unresolved_logical_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json", target_rva=0x1002)

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertIn("unresolved_code_target", {issue["category"] for issue in result["issues"]})

    def test_contract_requires_explicit_adversarial_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            del payload["environment"]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertIn("environment_contract_missing", {issue["category"] for issue in result["issues"]})

    def test_unsupported_instruction_emits_actionable_semantic_gap_before_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("0f57c0ebfb")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=5)
            report = root / "report"

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["diagnostic"]["category"], "semantic_preflight_incomplete")
            gaps = json.loads((report / "semantic-gaps.json").read_text(encoding="utf-8"))
            self.assertEqual(gaps["issues"][0]["category"], "formal_instruction_unsupported")
            self.assertIn("Lean decoder", gaps["issues"][0]["next_action"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for exact-byte relational replay")
    def test_exact_byte_region_proof_passes_and_tampering_fails_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("8b03894304ebf9"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("8b4300894304ebf8"))
            contract = self._write_contract(root / "relation.json", region_size=7, candidate_region_size=8)
            report = root / "report"

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertFalse(result["claim_scope"]["acceptance_eligible"])
            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "incomplete")
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(proof_ir["obligations"][0]["status"], "proved")
            self.assertEqual(proof_ir["obligations"][0]["evidence"]["kind"], "lean_normalization")

            normalized = json.loads((report / "relation-contract.json").read_text(encoding="utf-8"))
            normalized["regions"][0]["outputs"] = normalized["regions"][0]["outputs"][:-1]
            (report / "relation-contract.json").write_text(json.dumps(normalized), encoding="utf-8")
            tampered = stage_a_check_relational_proof(report=report)
            self.assertEqual(tampered["status"], "incomplete")
            self.assertFalse(tampered["checks"]["contract_hash_matches"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for checked counterexamples")
    def test_semantic_mutation_produces_lean_checked_counterexample(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xc8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "fail")
            self.assertEqual(result["proof"]["theorem"], "StageA.GeneratedRelationalCounterexample.exactCounterexample")
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )
            self.assertEqual(result["diagnostic"]["category"], "checked_relational_counterexample")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for width-aware relational proofs")
    def test_word_test_and_compare_zero_are_exactly_equivalent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("84c074006685f67400ebf5"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("3c0074006683fe007400ebf4"))
            contract = self._write_contract(root / "relation.json", region_size=11, candidate_region_size=12)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            pairs = payload["regions"][0]["inputs"]
            payload["code_targets"] = [
                {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                {"id": 1, "original_rva": 0x1004, "candidate_rva": 0x1004},
                {"id": 2, "original_rva": 0x1009, "candidate_rva": 0x100A},
            ]
            payload["regions"] = [
                {
                    "id": "byte-condition",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 4},
                    "candidate": {"rva": 0x1000, "size": 4},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "word-condition",
                    "root": False,
                    "original": {"rva": 0x1004, "size": 5},
                    "candidate": {"rva": 0x1004, "size": 6},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "loop-back",
                    "root": False,
                    "original": {"rva": 0x1009, "size": 2},
                    "candidate": {"rva": 0x100A, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
            ]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for condition-code relational proofs")
    def test_setcc_and_cmovcc_compose_across_equivalent_flag_producers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("83f9000f94c00f44c3ebf5"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("85c90f94c00f44c3ebf6"))
            contract = self._write_contract(
                root / "relation.json",
                region_size=11,
                candidate_region_size=10,
            )

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    def test_normalized_register_reflexivity_bridge_is_emitted_for_cmov_expression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("eb0039fa89d00f4cc783c01b7cf4c3")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json",
                region_size=len(code),
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            pairs = payload["regions"][0]["inputs"]
            payload["code_targets"] = [
                {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                {"id": 1, "original_rva": 0x1002, "candidate_rva": 0x1002},
                {"id": 2, "original_rva": 0x100E, "candidate_rva": 0x100E},
            ]
            payload["regions"] = [
                {
                    "id": "entry",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 2},
                    "candidate": {"rva": 0x1000, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "cmov-loop",
                    "root": False,
                    "original": {"rva": 0x1002, "size": len(code) - 3},
                    "candidate": {"rva": 0x1002, "size": len(code) - 3},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "fallthrough",
                    "root": False,
                    "original": {"rva": 0x100E, "size": 1},
                    "candidate": {"rva": 0x100E, "size": 1},
                    "inputs": pairs,
                    "outputs": pairs,
                },
            ]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared", result)
            proof = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((root / "report" / "lean" / "StageA").glob(
                    "RelationalProofShard*.lean"
                ))
            )
            self.assertIn("registersRelatedValues_self_of_identity", proof)
            self.assertIn("OriginalWritesEmpty", proof)
            self.assertIn("writes = [] := by rfl", proof)
            self.assertIn("OutcomeConditionWithin", proof)
            self.assertIn("outcomesRelated_normalized_branch_of_agreement", proof)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for cross-region flag execution")
    def test_logical_execution_carries_computed_flags_into_the_next_region(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "wincr" / "lean" / "StageA"
            for name in ("Formal.lean",):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "FlagsCompose.lean").write_text(
                """import StageA.Formal

namespace StageA.FlagsCompose

open StageA.Formal

def inputRegisters : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def concreteRegisters (ecx : Nat) : Registers Word := {
  eax := BitVec.ofNat 32 0
  ebx := BitVec.ofNat 32 0
  ecx := BitVec.ofNat 32 ecx
  edx := BitVec.ofNat 32 0
  esi := BitVec.ofNat 32 0
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := BitVec.ofNat 32 0
}

def compare : LogicalBehavior := {
  registers := inputRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := some (subtractionFlags (.inputReg .ecx) (.constant 0) (.inputReg .ecx))
  outcome := .jump 1
}

def branch : LogicalBehavior := {
  registers := inputRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .branch (.inputFlag 6) 2 3
}

def environment : Environment := { result := fun _ event => event.state }

def initial (ecx : Nat) : MachineState := {
  registers := concreteRegisters ecx
  memory := fun _ => BitVec.ofNat 8 0
  eflags := BitVec.ofNat 32 0
}

def selectedRegion (ecx : Nat) : Nat :=
  let behaviors := [some compare, some branch, none, none]
  let first := stepExecution environment behaviors (.running 0 (initial ecx) [] 0 [])
  match stepExecution environment behaviors first with
  | .running region _ _ _ _ => region
  | _ => 99

example : selectedRegion 0 = 2 := by decide
example : selectedRegion 1 = 3 := by decide

end StageA.FlagsCompose
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(lean_dir, bundle="FlagsCompose")
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bit-scan relational proofs")
    def test_bsr_and_tzcnt_have_checked_partial_flag_and_undefined_value_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("0fbdc3ebfbf30fbcc3ebfa")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [{"original": register, "candidate": register} for register in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
            )]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                ],
                "regions": [
                    {
                        "id": "bsr-loop", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "tzcnt-loop", "root": True,
                        "original": {"rva": 0x1005, "size": 6},
                        "candidate": {"rva": 0x1005, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_proofs = "\n".join(
                path.read_text(encoding="utf-8")
                for pattern in ("RelationalDefinitionsShard*.lean", "RelationalProofShard*.lean")
                for path in sorted((root / "report" / "lean" / "StageA").glob(pattern))
            )
            self.assertIn("highestSetBit", generated_proofs)
            self.assertIn("lowestSetBit", generated_proofs)
            self.assertNotIn("highestSetBitExpression", generated_proofs)
            self.assertNotIn("lowestSetBitExpression", generated_proofs)
            self.assertLess(len(bundle), 500_000)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for read-after-write relational proofs")
    def test_ambiguous_read_after_write_uses_compact_checked_expression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("8b44242cc7442460000000008b400483c001ebec")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_proofs = "\n".join(
                path.read_text(encoding="utf-8")
                for pattern in ("RelationalDefinitionsShard*.lean", "RelationalProofShard*.lean")
                for path in sorted((root / "report" / "lean" / "StageA").glob(pattern))
            )
            self.assertIn("read8AfterWrite", generated_proofs)
            self.assertLess(len(bundle), 300_000)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 relational proofs")
    def test_x87_stack_and_arithmetic_state_is_part_of_the_checked_relation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("d9e8d9eed9c9dec1ddd8ebf4")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 memory proofs")
    def test_x87_memory_conversion_and_writes_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("dd0424dd5c2408ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for mapped static-data proofs")
    def test_relocated_x87_static_data_uses_checked_memory_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocated_data(0x2000))
            candidate.write_bytes(_pe32_image_with_relocated_data(0x3000))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "x87-static-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 8},
                "candidate": {"rva": 0x1000, "size": 8},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))

            self.assertEqual(generated["status"], "generated")
            self.assertEqual(len(payload["value_targets"]), 1)
            self.assertEqual(payload["value_targets"][0]["mapped_size"], 8)
            self.assertEqual(payload["value_targets"][0]["original_value"], 0x402000)
            self.assertEqual(payload["value_targets"][0]["candidate_value"], 0x403000)

            result = stage_a_prove_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for immutable image-data proofs")
    def test_relocated_readonly_x87_data_is_decoded_from_exact_pe_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocated_data(0x2000, writable=False))
            candidate.write_bytes(_pe32_image_with_relocated_data(0x3000, writable=False))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "x87-immutable-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 8},
                "candidate": {"rva": 0x1000, "size": 8},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(payload["value_targets"], [])

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "incomplete")
            self.assertEqual(result["proof"]["lean"]["status"], "checked")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for indexed mapped-memory proofs")
    def test_relocation_pointer_table_emits_and_checks_bounded_index_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocation_pointer_table(0x2000, mask_index=True))
            candidate.write_bytes(_pe32_image_with_relocation_pointer_table(0x3000, mask_index=True))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "pointer-table-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 12},
                "candidate": {"rva": 0x1000, "size": 12},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(payload["regions"][0]["bounds"], [{
                "original": "edx", "candidate": "edx", "unsigned_lt": 2,
            }])
            mapped = [target for target in payload["value_targets"] if target["mapped_size"] > 0]
            self.assertEqual(len(mapped), 1)
            self.assertEqual(mapped[0]["mapped_size"], 8)

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            normalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            normalized_mapped = [
                target for target in normalized["value_targets"] if target["mapped_size"] > 0
            ]
            self.assertEqual(normalized_mapped[0]["relocation_offsets"], [0, 4])

            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked")
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            assumption_kinds = {
                obligation["kind"]: obligation["status"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {
                "cfg_bound_invariant": "incomplete",
                "cfg_register_relation_preservation": "incomplete",
                "mapped_relocation_image_relation": "proved",
                "relational_product_graph_decoded_exit_completeness": "candidate_requires_lean_replay",
                "relational_product_graph_declared_edge_refinement": "incomplete",
                "relational_product_graph_reachable_local_refinement": "incomplete",
                "relational_product_graph_structure": "candidate_requires_lean_replay",
                "relational_segment_refinement": "incomplete",
                "static_proof_context": "proved",
                "whole_program_bisimulation": "incomplete",
            })
            self.assertEqual(proof_ir["status"], "incomplete")
            self.assertEqual(result["counts"]["incomplete_assumptions"], 8)
            relocation = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "mapped_relocation_image_relation"
            )
            self.assertEqual(
                relocation["evidence"]["kind"],
                "lean_checked_mapped_relocation_image_relation",
            )
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_sources = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob("*.lean")
            )
            self.assertIn("GeneratedMappedRelocationImageCertificate", bundle)
            self.assertIn("MappedIndexedAddress", generated_sources)
            self.assertIn("originalExpression := some", generated_sources)
            self.assertIn("Expr.bitAnd", generated_sources)
            self.assertIn("boundsSatisfied", generated_sources)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for address-separation proofs")
    def test_relocated_read_after_stack_write_requires_cfg_address_separation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_stack_write_and_relocated_read(0x2000))
            candidate.write_bytes(_pe32_image_with_stack_write_and_relocated_read(0x3000))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "stack-write-relocated-read-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 15},
                "candidate": {"rva": 0x1000, "size": 15},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            self.assertEqual(generated["status"], "generated")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            normalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            self.assertEqual(len(normalized["regions"][0]["address_separations"]), 16)

            report = root / "report"
            result = stage_a_prove_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["verdict"], "incomplete", result)
            self.assertEqual(
                result["proof"]["lean"]["status"], "checked",
                result["proof"]["lean"],
            )
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            assumption_kinds = {
                obligation["kind"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {
                "cfg_address_separation_invariant",
                "cfg_register_relation_preservation",
                "memory_transition_preservation",
                "paired_stack_range_world",
                "relational_product_graph_decoded_exit_completeness",
                "relational_product_graph_declared_edge_refinement",
                "relational_product_graph_reachable_local_refinement",
                "relational_product_graph_structure",
                "relational_segment_refinement",
                "stack_address_separation_inventory",
                "static_proof_context",
                "whole_program_bisimulation",
            })
            transition = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "memory_transition_preservation"
            )
            self.assertEqual(
                transition["id"],
                "memory-transition:stack-write-relocated-read-loop",
            )
            self.assertEqual(
                transition["repair_class"], "identical_symbolic_write_pullback"
            )
            self.assertEqual(
                proof_ir["memory_transition_summary"]["transition_obligations"], 1
            )
            self.assertEqual(proof_ir["status"], "incomplete")

            replay = stage_a_check_relational_proof(report=report)
            self.assertEqual(replay["status"], "incomplete")
            self.assertFalse(replay["checks"]["proof_ir_satisfied"])
            self.assertFalse(replay["checks"]["no_incomplete_assumptions"])
            self.assertFalse(replay["checks"]["contract_families_closed"])

    def _write_contract(
        self,
        path: Path,
        *,
        region_size: int = 4,
        candidate_region_size: int | None = None,
        target_rva: int = 0x1000,
    ) -> Path:
        candidate_region_size = candidate_region_size or region_size
        pairs = [{"original": register, "candidate": register} for register in (
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
        )]
        payload = {
            "format": "stage-a-relation-contract-v1",
            "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
            "observations": RELATIONAL_OBSERVATIONS,
            "code_targets": [{"id": 0, "original_rva": target_rva, "candidate_rva": target_rva}],
            "regions": [{
                "id": "entry-loop",
                "root": True,
                "original": {"rva": 0x1000, "size": region_size},
                "candidate": {"rva": 0x1000, "size": candidate_region_size},
                "inputs": pairs,
                "outputs": pairs,
            }],
            "padding": [],
            "memory_relation": {"mode": "identity"},
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    @staticmethod
    def _write_pe(path: Path, code: bytes) -> Path:
        path.write_bytes(_pe32_image(code))
        return path


def _pe32_image(code: bytes) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw_size = _align(len(code), file_alignment)
    size_of_image = _align(text_rva + len(code), section_alignment)
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, 0, 0, text_rva, text_rva, 0, 0x400000,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, size_of_image,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, text_raw_size,
        headers_size, 0, 0, 0, 0, 0x60000020,
    )
    headers = (bytes(dos) + b"PE\0\0" + coff + optional + section).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0")


def _pe32_import_image(
    code: bytes, *, symbol: str, dll: str = "KERNEL32.dll", iat_offset: int = 0x40,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    idata_raw = text_raw + text_raw_size
    idata_raw_size = 0x200
    size_of_image = _align(idata_rva + idata_raw_size, section_alignment)

    int_rva = idata_rva + 0x30
    iat_rva = idata_rva + iat_offset
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(idata_raw_size)
    struct.pack_into("<IIIII", idata, 0, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, iat_offset, import_name_rva, 0)
    idata[0x50 : 0x50 + len(dll) + 1] = dll.encode("ascii") + b"\0"
    name = symbol.encode("ascii")
    struct.pack_into("<H", idata, 0x80, 0)
    idata[0x82 : 0x82 + len(name) + 1] = name + b"\0"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, text_raw_size, idata_raw_size, 0, text_rva, text_rva,
        idata_rva, image_base, section_alignment, file_alignment, 4, 0, 0, 0,
        4, 0, 0, size_of_image, headers_size, 0, 3, 0, 0x100000, 0x1000,
        0x100000, 0x1000, 0, 16,
    )
    optional = bytearray(optional_prefix + (b"\0" * (16 * 8)))
    struct.pack_into("<II", optional, len(optional_prefix) + 8, idata_rva, 40)
    text_section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, text_raw_size,
        text_raw, 0, 0, 0, 0, 0x60000020,
    )
    idata_section = struct.pack(
        "<8sIIIIIIHHI", b".idata\0\0", idata_raw_size, idata_rva,
        idata_raw_size, idata_raw, 0, 0, 0, 0, 0x40000040,
    )
    headers = (
        bytes(dos) + b"PE\0\0" + coff + bytes(optional)
        + text_section + idata_section
    ).ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(idata)


def _pe32_representative_control_image(
    data_rva: int, *, terminal_rva: int = 0x1020,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x400
    image_base = 0x400000
    text_rva = 0x1000
    idata_rva = 0x2000
    reloc_rva = 0x5000
    text_raw = headers_size
    idata_raw = text_raw + 0x200
    data_raw = idata_raw + 0x200
    reloc_raw = data_raw + 0x200
    iat_rva = idata_rva + 0x40

    code = bytearray()
    code += b"\xe8\x10\x00\x00\x00"
    code += b"\xff\x15" + struct.pack("<I", image_base + iat_rva)
    code += b"\x85\xc0\x75\xfc"
    code += b"\xff\x25" + struct.pack("<I", image_base + data_rva)
    code += b"\xc3"
    code += b"\x90" * (terminal_rva - 0x1016)
    code += b"\xc3"

    int_rva = idata_rva + 0x30
    dll_name_rva = idata_rva + 0x50
    import_name_rva = idata_rva + 0x80
    idata = bytearray(0x200)
    struct.pack_into("<IIIII", idata, 0, int_rva, 0, 0, dll_name_rva, iat_rva)
    struct.pack_into("<II", idata, 0x30, import_name_rva, 0)
    struct.pack_into("<II", idata, 0x40, import_name_rva, 0)
    idata[0x50:0x5D] = b"KERNEL32.dll\0"
    struct.pack_into("<H", idata, 0x80, 0)
    idata[0x82:0x8F] = b"GetTickCount\0"
    data = struct.pack("<I", image_base + terminal_rva)

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + 2 * len(entries))
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    relocations = (
        relocation_block(text_rva, [7, 17])
        + relocation_block(data_rva, [0])
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 4, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x600, 0, text_rva, text_rva, idata_rva,
        image_base, section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0,
        0x6000, headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000,
        0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 1 * 8, idata_rva, 40)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".idata\0\0", len(idata), idata_rva, 0x200,
            idata_raw, 0, 0, 0, 0, 0x40000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".rdata\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, 0x40000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories)
        + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + bytes(code).ljust(0x200, b"\0")
        + bytes(idata) + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_relocated_data(data_rva: int, *, writable: bool = True) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x4000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    code = b"\xdd\x05" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf8"
    data = struct.pack("<d", 1.5)
    relocations = struct.pack("<IIHH", text_rva, 12, 0x3002, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x5000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, text_raw, 0, 0, 0, 0, 0x60000020),
        struct.pack(
            "<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200, data_raw,
            0, 0, 0, 0, 0xC0000040 if writable else 0x40000040,
        ),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, reloc_raw, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections).ljust(headers_size, b"\0")
    return headers + code.ljust(0x200, b"\0") + data.ljust(0x200, b"\0") + relocations.ljust(0x200, b"\0")


def _pe32_image_with_relocation_pointer_table(
    data_rva: int,
    *,
    mask_index: bool = False,
    duplicate_data_entry: bool = False,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x5000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    if mask_index:
        code = b"\x83\xe2\xff\x8b\x1c\x95" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf4"
        relocation_offset = 6
    else:
        code = b"\x8b\x1c\x95" + struct.pack("<I", image_base + data_rva) + b"\xeb\xf7"
        relocation_offset = 3
    data = bytearray(0x40)
    struct.pack_into("<II", data, 0, image_base + data_rva + 0x20, image_base + data_rva + 0x30)
    data[0x20:0x26] = b"first\0"
    data[0x30:0x37] = b"second\0"

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        size = 8 + 2 * len(entries)
        return struct.pack("<II", page_rva, size) + struct.pack("<" + "H" * len(entries), *entries)

    data_relocations = [0, 0, 4] if duplicate_data_entry else [0, 4]
    relocations = relocation_block(text_rva, [relocation_offset]) + relocation_block(
        data_rva, data_relocations
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x400, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x6000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200, text_raw, 0, 0, 0, 0, 0x60000020),
        struct.pack("<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200, data_raw, 0, 0, 0, 0, 0xC0000040),
        struct.pack("<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200, reloc_raw, 0, 0, 0, 0, 0x42000040),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + bytes(data).ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_immutable_indirect_call(
    data_rva: int, *, callee_rva: int = 0x1030, writable: bool = False,
    jump: bool = False,
) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x5000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    source = (
        b"\xff\x25" + struct.pack("<I", image_base + data_rva)
        if jump else
        b"\xc7\x44\x24\x08\x00\x00\x00\x00"
        b"\xc7\x44\x24\x04\x02\x00\x00\x00"
        b"\xc7\x04\x24\x00\x00\x00\x00"
        b"\xff\x15" + struct.pack("<I", image_base + data_rva)
    )
    code = bytearray(b"\x90" * (callee_rva - text_rva + 1))
    code[:len(source)] = source
    if not jump:
        code[0x1D:0x1F] = b"\xeb\xfe"
    code[callee_rva - text_rva] = 0xC3
    data = struct.pack("<I", image_base + callee_rva)

    def relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + 2 * len(entries))
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    relocations = (
        relocation_block(text_rva, [2 if jump else 25])
        + relocation_block(data_rva, [0])
    )
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x200, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x6000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    data_characteristics = 0xC0000040 if writable else 0x40000040
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".rdata\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, data_characteristics,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + bytes(code).ljust(0x200, b"\0") + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _pe32_image_with_stack_write_and_relocated_read(data_rva: int) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    reloc_rva = 0x4000
    text_raw = 0x200
    data_raw = 0x400
    reloc_raw = 0x600
    image_base = 0x400000
    code = b"\xc7\x44\x24\x08\x00\x00\x00\x00\xa1" + struct.pack(
        "<I", image_base + data_rva
    ) + b"\xeb\xf1"
    data = struct.pack("<I", 0x12345678)
    relocations = struct.pack("<IIHH", text_rva, 12, 0x3009, 0)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B, 0, 0, 0x200, 0x200, 0, text_rva, text_rva, data_rva, image_base,
        section_alignment, file_alignment, 4, 0, 0, 0, 4, 0, 0, 0x5000,
        headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(16 * 8)
    struct.pack_into("<II", directories, 5 * 8, reloc_rva, len(relocations))
    sections = b"".join((
        struct.pack(
            "<8sIIIIIIHHI", b".text\0\0\0", len(code), text_rva, 0x200,
            text_raw, 0, 0, 0, 0, 0x60000020,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".data\0\0\0", len(data), data_rva, 0x200,
            data_raw, 0, 0, 0, 0, 0xC0000040,
        ),
        struct.pack(
            "<8sIIIIIIHHI", b".reloc\0\0", len(relocations), reloc_rva, 0x200,
            reloc_raw, 0, 0, 0, 0, 0x42000040,
        ),
    ))
    headers = (
        bytes(dos) + b"PE\0\0" + coff + optional_prefix + bytes(directories) + sections
    ).ljust(headers_size, b"\0")
    return (
        headers + code.ljust(0x200, b"\0") + data.ljust(0x200, b"\0")
        + relocations.ljust(0x200, b"\0")
    )


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment


if __name__ == "__main__":
    unittest.main()
