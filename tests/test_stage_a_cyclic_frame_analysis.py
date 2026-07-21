import unittest
from copy import deepcopy
from pathlib import Path
import tempfile

from spaghetti_extractor.relational.analyses.frames import (
    RuntimeFrameAffineTransfer,
    runtime_frame_affine_viability,
)
from spaghetti_extractor.relational.runtime_frame_artifact import (
    runtime_frame_affine_viability_payload,
)
from spaghetti_extractor.relational.lean.affine_frames import (
    relational_affine_frame_profile_source,
    write_relational_affine_frame_profile_module,
    write_relational_affine_frame_semantic_modules,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageACyclicFrameAnalysisTests(unittest.TestCase):
    @staticmethod
    def _behavior(write_offset=None):
        writes = []
        if write_offset is not None:
            address = {"op": "input_reg", "reg": "esp"}
            if write_offset:
                address = {
                    "op": "add",
                    "left": address,
                    "right": {"op": "constant", "value": write_offset},
                }
            writes.append({
                "address": address,
                "value": {"op": "constant", "value": 0},
            })
        return {
            "original_ir": {"writes": writes},
            "candidate_ir": {"writes": writes},
        }

    @staticmethod
    def _cycle_edge(original_delta=-4, candidate_delta=-4, *, rules=True):
        def witness(delta):
            if delta == 0:
                return {"kind": "input"}
            return {
                "kind": "add_right" if delta > 0 else "sub_right",
                "prior": {"kind": "input"},
                "value": abs(delta),
            }

        transfer_rules = []
        if rules:
            transfer_rules.append({
                "profile": "return_slot_affine_transfer_rule_v1",
                "original_source_register": "esp",
                "candidate_source_register": "esp",
                "original_target_register": "esp",
                "candidate_target_register": "esp",
                "original_delta": original_delta,
                "candidate_delta": candidate_delta,
                "original_output_witness": witness(original_delta),
                "candidate_output_witness": witness(candidate_delta),
            })
        return {
            "source_region_index": 0,
            "target_region_index": 0,
            "kind": "call",
            "environment_barrier": False,
            "direct_call_push_claim": {
                "profile": "mapped_direct_call_push_v1",
                "callee_target_id": 0,
                "continuation_target_id": 0,
                "original_return_address": 0,
                "candidate_return_address": 0,
                "original_stack_address": {"op": "input_reg", "reg": "esp"},
                "candidate_stack_address": {"op": "input_reg", "reg": "esp"},
            },
            "return_slot_seed": {
                "profile": "direct_call_runtime_frame_seed_v1",
                "target_region_index": 0,
                "offsets": {
                    "original_register": "esp",
                    "original": 0,
                    "candidate_register": "esp",
                    "candidate": 0,
                },
            },
            "return_slot_transfer_rules": transfer_rules,
            "return_slot_transfer_claims": [],
        }

    def _artifact(self, edges, *, behaviors=None, **budgets):
        return runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations_sha256="4" * 64,
            behaviors=behaviors or [self._behavior()],
            register_relations={"edges": edges},
            **budgets,
        )

    def test_common_translation_cycle_is_one_exact_affine_family(self) -> None:
        result = runtime_frame_affine_viability(
            ((0, ("esp", 0, "esp", 8)),),
            memory_ready=lambda _node, _family: True,
            required_edges=lambda _node: (0,),
            affine_transfers=lambda node, original, candidate, _edge: (
                RuntimeFrameAffineTransfer(
                    node, original, 4, candidate, 4,
                ),
            ),
            max_families=2,
        )

        self.assertTrue(result.complete)
        self.assertEqual(len(result.viable), 1)
        _, family = next(iter(result.viable))
        self.assertEqual(family.translation_stride, 4)
        self.assertEqual(family.cardinality, 2**30)
        self.assertTrue(family.contains(("esp", 0, "esp", 8)))
        self.assertTrue(family.contains(("esp", 0xFFFFFFFC, "esp", 4)))
        self.assertFalse(family.contains(("esp", 2, "esp", 10)))
        self.assertEqual(len(result.transitions), 1)

    def test_feasible_branch_successors_are_required_affine_transitions(self) -> None:
        call = self._cycle_edge(original_delta=0, candidate_delta=0)
        branch = deepcopy(call)
        branch["kind"] = "branch_taken"
        branch.pop("direct_call_push_claim")
        branch.pop("return_slot_seed")

        artifact = self._artifact([call, branch])

        self.assertTrue(artifact["certificate"]["viable_families"])
        self.assertEqual(
            {row["edge_index"] for row in artifact["certificate"]["viable_transitions"]},
            {0, 1},
        )

    def test_product_graph_synthetic_edge_gets_decoded_affine_transfer(self) -> None:
        call = self._cycle_edge(original_delta=0, candidate_delta=0)
        register_relations = {"edges": [call], "regions": [{
            "inputs": [{"original": "esp", "candidate": "esp"}],
            "outputs": [{"original": "esp", "candidate": "esp"}],
        }]}
        product_graph = {
            "nodes": [{"id": 0, "outgoing_edge_ids": [0, 1]}],
            "edges": [
                {
                    "id": 0,
                    "source_node_id": 0,
                    "target_node_id": 0,
                    "kind": "call",
                    "infeasible": False,
                },
                {
                    "id": 1,
                    "source_node_id": 0,
                    "target_node_id": 0,
                    "kind": "jump",
                    "infeasible": False,
                },
            ],
        }
        behavior = self._behavior()
        for side in ("original_ir", "candidate_ir"):
            behavior[side]["registers"] = {
                "esp": {"op": "input_reg", "reg": "esp"},
            }

        artifact = runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations_sha256="4" * 64,
            behaviors=[behavior],
            register_relations=register_relations,
            product_graph=product_graph,
        )

        self.assertEqual(
            {row["edge_index"] for row in artifact["certificate"]["viable_transitions"]},
            {0, 1},
        )

    def test_two_node_nonzero_cycle_propagates_without_enumerating(self) -> None:
        def transfers(node, original, candidate, _edge):
            target, delta = ((1, -8) if node == 0 else (0, 12))
            return (RuntimeFrameAffineTransfer(
                target, original, delta, candidate, delta,
            ),)

        result = runtime_frame_affine_viability(
            ((0, ("ebp", 1, "ebp", 9)),),
            memory_ready=lambda _node, _family: True,
            required_edges=lambda _node: (0,),
            affine_transfers=transfers,
            max_families=2,
        )

        self.assertTrue(result.complete)
        self.assertEqual(len(result.viable), 2)
        self.assertEqual(
            {family.translation_stride for _, family in result.viable}, {4}
        )
        self.assertTrue(all(
            family.cardinality == 2**30 for _, family in result.viable
        ))

    def test_zero_net_cycle_keeps_singleton_locations(self) -> None:
        def transfers(node, original, candidate, _edge):
            target, delta = ((1, -8) if node == 0 else (0, 8))
            return (RuntimeFrameAffineTransfer(
                target, original, delta, candidate, delta,
            ),)

        result = runtime_frame_affine_viability(
            ((0, ("esp", 16, "esp", 20)),),
            memory_ready=lambda _node, _family: True,
            required_edges=lambda _node: (0,),
            affine_transfers=transfers,
        )

        self.assertTrue(result.complete)
        self.assertEqual(len(result.viable), 2)
        self.assertTrue(all(
            family.cardinality == 1 for _, family in result.viable
        ))

    def test_viability_requires_every_branch_to_reach_ready_family(self) -> None:
        targets = {10: 1, 11: 2}
        result = runtime_frame_affine_viability(
            ((0, ("esp", 0, "esp", 0)),),
            memory_ready=lambda node, _family: node != 2,
            required_edges=lambda node: (10, 11) if node == 0 else (),
            affine_transfers=lambda _node, original, candidate, edge: (
                RuntimeFrameAffineTransfer(
                    targets[edge], original, 0, candidate, 0,
                ),
            ),
        )

        self.assertTrue(result.complete)
        self.assertEqual({node for node, _ in result.viable}, {1})

    def test_asymmetric_relational_cycle_fails_closed(self) -> None:
        result = runtime_frame_affine_viability(
            ((0, ("esp", 0, "esp", 0)),),
            memory_ready=lambda _node, _family: True,
            required_edges=lambda _node: (0,),
            affine_transfers=lambda node, original, candidate, _edge: (
                RuntimeFrameAffineTransfer(
                    node, original, 4, candidate, 8,
                ),
            ),
        )

        self.assertFalse(result.complete)
        self.assertEqual(result.viable, frozenset())
        self.assertEqual(
            result.unsupported_cycle_shapes,
            frozenset({(0, "esp", "esp")}),
        )

    def test_symbolic_family_budget_fails_closed(self) -> None:
        result = runtime_frame_affine_viability(
            (
                (0, ("esp", 0, "esp", 0)),
                (0, ("esp", 2, "esp", 2)),
            ),
            memory_ready=lambda _node, _family: True,
            required_edges=lambda _node: (),
            affine_transfers=lambda _node, _original, _candidate, _edge: (),
            max_families=1,
        )

        self.assertTrue(result.budget_exceeded)
        self.assertFalse(result.complete)
        self.assertEqual(result.viable, frozenset())

    def test_current_runtime_frame_facts_emit_exact_family_proposal(self) -> None:
        edge = self._cycle_edge()
        artifact = self._artifact([edge])

        self.assertTrue(artifact["complete"])
        self.assertEqual(
            artifact["status"], "proposal_requires_generated_lean_replay"
        )
        self.assertFalse(
            artifact["certificate"]["finite_window_widening"]
        )
        family = artifact["proposals"][0]["viable_families"][0]
        self.assertEqual(family["translation_stride"], 4)
        self.assertEqual(family["cardinality"], 2**30)
        transition = artifact["certificate"]["viable_transitions"][0]
        self.assertEqual(
            artifact["certificate"]["viable_seeds"],
            artifact["facts"]["seeds"],
        )
        self.assertEqual(transition["source_node"], 0)
        self.assertEqual(transition["target_node"], 0)
        self.assertEqual(
            transition["canonical_shift_coefficient"], 2**30 - 1
        )
        self.assertEqual(
            transition["target_family"], transition["source_family"]
        )
        self.assertEqual(
            transition["rule"]["original_output_witness"],
            {"kind": "sub_right", "prior": {"kind": "input"}, "value": 4},
        )
        self.assertEqual(artifact, self._artifact([edge]))

        source = relational_affine_frame_profile_source(artifact)
        self.assertIn("def runtimeFrameAffineProfile", source)
        self.assertIn("theorem runtimeFrameAffineProfileChecked", source)
        self.assertIn("originalOutput := RegisterOffsetWitness.subRight", source)
        self.assertIn("coefficient := BitVec.ofNat 32 0", source)
        self.assertEqual(
            source, relational_affine_frame_profile_source(artifact)
        )

    def test_lean_profile_generation_rejects_transition_without_rule(self) -> None:
        artifact = self._artifact([self._cycle_edge()])
        malformed = deepcopy(artifact)
        del malformed["certificate"]["viable_transitions"][0]["rule"]

        with self.assertRaisesRegex(StageAInputError, "affine transfer rule"):
            relational_affine_frame_profile_source(malformed)

    def test_equal_seed_offsets_on_distinct_call_edges_remain_distinct(self) -> None:
        artifact = self._artifact([self._cycle_edge(), self._cycle_edge()])

        self.assertTrue(artifact["complete"])
        self.assertEqual(
            [seed["edge_index"] for seed in artifact["certificate"]["viable_seeds"]],
            [0, 1],
        )
        source = relational_affine_frame_profile_source(artifact)
        self.assertEqual(source.count("{ edgeId := 0,"), 1)
        self.assertEqual(source.count("{ edgeId := 1,"), 1)

    def test_viable_subprofile_proof_is_not_gated_by_global_blockers(self) -> None:
        artifact = self._artifact([self._cycle_edge()])
        artifact["complete"] = False
        artifact["status"] = "incomplete"
        artifact["blockers"] = [{"code": "uncovered_disjoint_seed"}]

        source = relational_affine_frame_profile_source(artifact)

        self.assertIn("theorem runtimeFrameAffineProfileChecked", source)

    def test_lean_semantic_replay_covers_every_viable_transition(self) -> None:
        artifact = self._artifact([self._cycle_edge()])
        contract = {"regions": [{"id": 0}]}
        product_graph = {
            "nodes": [{"id": 0, "target_id": 0}],
            "edges": [{
                "id": 0,
                "source_node_id": 0,
                "target_node_id": 0,
            }],
        }

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            write_relational_affine_frame_profile_module(lean_dir, artifact)
            modules = write_relational_affine_frame_semantic_modules(
                lean_dir,
                artifact,
                contract=contract,
                product_graph=product_graph,
                decode_chunk_regions=[[0]],
            )
            profile = (
                lean_dir / "StageA" / "RelationalAffineFrameProfile.lean"
            ).read_text(encoding="utf-8")
            chunk = (
                lean_dir / "StageA" / "RelationalAffineFrameSemanticChunk0.lean"
            ).read_text(encoding="utf-8")
            seed_chunk = (
                lean_dir
                / "StageA"
                / "RelationalAffineFrameSemanticSeedChunk0.lean"
            ).read_text(encoding="utf-8")
            aggregate = (
                lean_dir / "StageA" / "RelationalAffineFrameSemanticProfile.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(modules[-1], "RelationalAffineFrameSemanticProfile")
        self.assertIn("def runtimeFrameAffineTransition0", profile)
        self.assertIn("originalBehavior0CheckedDecoded", chunk)
        self.assertIn("candidateBehavior0CheckedDecoded", chunk)
        self.assertIn("runtimeFrameAffineSemanticTransition0Checked", chunk)
        self.assertIn("runtimeFrameAffineSemanticSeed0Checked", seed_chunk)
        self.assertIn("runtimeFrameAffineSeedCallPush0", seed_chunk)
        self.assertIn("runtimeFrameAffineSemanticProfileChecked", aggregate)
        self.assertIn(
            "transitionClaims := runtimeFrameAffineSemanticTransitionClaims",
            aggregate,
        )
        self.assertIn("seedClaims := runtimeFrameAffineSemanticSeedClaims", aggregate)

    def test_physical_x87_affine_transition_uses_exact_state_only_check(self) -> None:
        artifact = self._artifact([
            self._cycle_edge(original_delta=0, candidate_delta=0)
        ])
        contract = {"regions": [{"id": 0}]}
        product_graph = {
            "nodes": [{"id": 0, "target_id": 0}],
            "edges": [{
                "id": 0,
                "source_node_id": 0,
                "target_node_id": 0,
            }],
        }

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            write_relational_affine_frame_profile_module(lean_dir, artifact)
            write_relational_affine_frame_semantic_modules(
                lean_dir,
                artifact,
                contract=contract,
                product_graph=product_graph,
                decode_chunk_regions=[[0]],
                physical_state_only_region_indices={0},
            )
            chunk = (
                lean_dir / "StageA" / "RelationalAffineFrameSemanticChunk0.lean"
            ).read_text(encoding="utf-8")

        self.assertIn("physicalStateOnly := true", chunk)
        self.assertIn("checked_physical_of_evidence", chunk)
        self.assertNotIn("originalBehavior0CheckedDecoded", chunk)
        self.assertNotIn("candidateBehavior0CheckedDecoded", chunk)

    def test_artifact_asymmetric_drift_is_incomplete(self) -> None:
        artifact = self._artifact([
            self._cycle_edge(original_delta=-4, candidate_delta=-8)
        ])

        self.assertFalse(artifact["complete"])
        self.assertIn(
            "runtime_frame_affine_asymmetric_cycle",
            {blocker["code"] for blocker in artifact["blockers"]},
        )
        self.assertEqual(artifact["certificate"]["viable_families"], [])

    def test_artifact_concrete_only_transfer_is_incomplete(self) -> None:
        edge = self._cycle_edge(rules=False)
        edge["return_slot_transfer_claims"] = [{
            "profile": "return_slot_affine_transfer_v2",
            "source": edge["return_slot_seed"]["offsets"],
            "target": edge["return_slot_seed"]["offsets"],
        }]
        artifact = self._artifact([edge])

        self.assertFalse(artifact["complete"])
        self.assertIn(
            "runtime_frame_affine_transfer_unsupported",
            {blocker["code"] for blocker in artifact["blockers"]},
        )

    def test_finite_stack_window_does_not_widen_memory_readiness(self) -> None:
        edge = self._cycle_edge()
        relations = {
            "edges": [edge],
            "regions": [{
                "stack_windows": [{
                    "original_register": "esp",
                    "candidate_register": "esp",
                    "bytes_below": 4096,
                    "bytes_above": 4096,
                }],
            }],
        }
        artifact = runtime_frame_affine_viability_payload(
            original_sha256="0" * 64,
            candidate_sha256="1" * 64,
            relation_contract_sha256="2" * 64,
            decoded_behaviors_sha256="3" * 64,
            register_relations_sha256="4" * 64,
            behaviors=[self._behavior(write_offset=0)],
            register_relations=relations,
        )

        self.assertFalse(artifact["complete"])
        self.assertIn(
            "runtime_frame_affine_memory_not_universal",
            {blocker["code"] for blocker in artifact["blockers"]},
        )
        self.assertEqual(artifact["certificate"]["memory_basis"], (
            "decoded_affine_writes_only"
        ))

    def test_artifact_shape_budget_is_incomplete(self) -> None:
        def seed_edge(edge_index, target):
            edge = self._cycle_edge(rules=False)
            edge.update({
                "source_region_index": 2,
                "target_region_index": target,
                "kind": "call",
            })
            edge["return_slot_seed"] = {
                **edge["return_slot_seed"],
                "target_region_index": target,
            }
            return edge

        artifact = self._artifact(
            [seed_edge(0, 0), seed_edge(1, 1)],
            behaviors=[self._behavior() for _ in range(3)],
            max_shapes=1,
        )

        self.assertFalse(artifact["complete"])
        self.assertEqual(artifact["certificate"]["budget_kind"], "shapes")
        self.assertIn(
            "runtime_frame_affine_shape_budget_exceeded",
            {blocker["code"] for blocker in artifact["blockers"]},
        )


if __name__ == "__main__":
    unittest.main()
