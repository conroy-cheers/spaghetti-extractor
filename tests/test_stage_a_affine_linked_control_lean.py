from copy import deepcopy

from tests.stage_a_relational_support import *

from spaghetti_extractor.relational.lean.affine_linked_control import (
    AFFINE_LINKED_CALL_BINDINGS_MODULE,
    AFFINE_LINKED_CONTROL_BINDINGS_MODULE,
    AFFINE_LINKED_CONTROL_MODULE,
    AFFINE_LINKED_MEMORY_BINDINGS_MODULE,
    AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE,
    relational_affine_linked_control_source,
    write_relational_affine_linked_call_binding_modules,
    write_relational_affine_linked_control_binding_modules,
    write_relational_affine_linked_external_call_binding_modules,
    write_relational_affine_linked_memory_binding_modules,
    write_relational_affine_linked_control_module,
)
from spaghetti_extractor.relational.analyses.affine_linked_control import (
    affine_linked_control_payload,
)
from tests.test_stage_a_affine_linked_control import (
    StageAAffineLinkedControlTests,
)


class StageAAffineLinkedControlLeanTests(StageARelationalTestBase):
    @staticmethod
    def _exact_shape():
        return {
            "locations": {
                "kind": "exact",
                "locations": [{
                    "original_register": "esp",
                    "original": 8,
                    "candidate_register": "esp",
                    "candidate": 16,
                }],
            },
            "exact_words": [{"original": 4, "candidate": 8}],
            "preserved_imports": [{
                "original": "esi",
                "candidate": "edi",
                "import": {"dll": "test.dll", "symbol": "fixture_word"},
            }],
            "preserved_relations": [{
                "original": "ebx",
                "candidate": "ecx",
                "relation": "exact",
            }],
        }

    @staticmethod
    def _affine_shape(artifact_state_id, profile_state_index):
        return {
            "locations": {
                "kind": "affine_family",
                "artifact_state_id": artifact_state_id,
                "profile_state_index": profile_state_index,
            },
        }

    @classmethod
    def _payload(cls):
        exact = cls._exact_shape()
        inner = cls._affine_shape(0, 0)
        resume = cls._affine_shape(1, 1)
        return {
            "format": "stage-a-affine-linked-control-v1",
            "status": "complete_proposal",
            "shape_projection_status": "complete",
            "control_closure_status": "complete",
            "acceptance_authority": False,
            "states": [
                {
                    "id": 0,
                    "node_id": 1,
                    "continuation_target_id": 11,
                    "active_shape": exact,
                    "minimum_depth": 1,
                },
                {
                    "id": 1,
                    "node_id": 2,
                    "continuation_target_id": 99,
                    "active_shape": resume,
                    "minimum_depth": 1,
                },
            ],
            "links": [{
                "id": 0,
                "call_edge_id": 0,
                "call_source_node_id": 0,
                "call_source_target_id": 10,
                "inner_inventory_node_id": 1,
                "suspended_inventory_node_id": 1,
                "resume_inventory_node_id": 2,
                "resume_target_id": 12,
                "resume_continuation": 99,
                "inner_shape": inner,
                "suspended_shape": deepcopy(exact),
                "resume_shape": deepcopy(resume),
                "original_gap": 8,
                "candidate_gap": 8,
            }],
            "transition_bindings": [],
            "transition_binding_gaps": [],
            "minimal_active_states": [{
                "id": 0,
                "affine_state_id": 0,
                "node_id": 1,
                "continuation_target_id": 11,
                "active_shape": deepcopy(inner),
                "minimum_depth": 1,
                "seed_ids": [0],
            }],
            "gaps": [],
            "exact_fallbacks": [
                {
                    "owner": "state 0 active",
                    "node_id": 1,
                    "reason": "no_unique_rooted_affine_family",
                    "candidate_family_ids": [],
                },
                {
                    "owner": "link 0 suspended",
                    "node_id": 1,
                    "reason": "non_singleton_inventory",
                    "candidate_family_ids": [],
                },
            ],
            "coverage_gaps": {
                "unrepresented_rooted_affine_state_ids": [],
                "unbound_rooted_affine_transition_ids": [],
            },
            "counts": {
                "states": 2,
                "links": 1,
                "gaps": 0,
                "affine_shapes": 3,
                "exact_fallbacks": 2,
                "rooted_affine_states": 2,
                "represented_rooted_affine_states": 2,
                "unrepresented_rooted_affine_states": 0,
                "rooted_affine_transitions": 0,
                "bound_rooted_affine_transitions": 0,
                "unbound_rooted_affine_transitions": 0,
                "minimal_active_states": 1,
            },
        }

    @staticmethod
    def _product_graph_source():
        return """import StageA.RelationalAffineLinkedFrames

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational

def relationalProductGraph : RelationalProductGraph := {
  nodes := #[
    { id := 0, targetId := 10, root := true, outgoingEdgeIds := [0] },
    { id := 1, targetId := 11, root := false, outgoingEdgeIds := [] },
    { id := 2, targetId := 12, root := false, outgoingEdgeIds := [] }
  ]
  edges := #[{
    id := 0
    sourceNodeId := 0
    targetNodeId := 1
    sourceTargetId := 10
    targetTargetId := 11
    kind := .call
    originalGuard := unconditionalProductGuard
    candidateGuard := unconditionalProductGuard
    infeasible := false
  }]
  rootNodeIds := [0]
}

end StageA.GeneratedRelational
"""

    @staticmethod
    def _affine_profile_source():
        return """import StageA.RelationalProductGraphContext

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational

def runtimeFrameAffineStates : List ReturnSlotAffineFrameState := [
  {
    nodeId := 1
    family := {
      originalRegister := .esp
      originalBase := BitVec.ofNat 32 0
      candidateRegister := .esp
      candidateBase := BitVec.ofNat 32 0
      translationStride := 4
    }
  },
  {
    nodeId := 2
    family := {
      originalRegister := .esp
      originalBase := BitVec.ofNat 32 0
      candidateRegister := .esp
      candidateBase := BitVec.ofNat 32 0
      translationStride := 4
    }
  }
]

def runtimeFrameAffineProfile : ReturnSlotAffineFrameProfile := {
  states := runtimeFrameAffineStates
  transitions := []
  seeds := []
}

theorem runtimeFrameAffineProfileChecked :
    runtimeFrameAffineProfile.checked relationalProductGraph = true := by
  native_decide

end StageA.GeneratedRelational
"""

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for affine control")
    def test_generated_hybrid_profile_with_nested_link_is_lean_checked(self):
        payload = self._payload()
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = (
                Path(__file__).parents[1]
                / "src" / "spaghetti_extractor" / "lean" / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
            (stage_a / "RelationalProductGraphContext.lean").write_text(
                self._product_graph_source(), encoding="utf-8"
            )
            (stage_a / "RelationalAffineFrameProfile.lean").write_text(
                self._affine_profile_source(), encoding="utf-8"
            )

            module = write_relational_affine_linked_control_module(
                lean_dir, payload
            )
            source = (
                stage_a / "RelationalAffineLinkedControl.lean"
            ).read_text(encoding="utf-8")
            result = _run_lean_relational(lean_dir, bundle=module)

        self.assertEqual(module, AFFINE_LINKED_CONTROL_MODULE)
        self.assertIn("(.exact [{ originalRegister := .esp", source)
        self.assertIn("(.affineFamily 0)", source)
        self.assertIn("(.affineFamily 1)", source)
        self.assertIn("exactWords := [{ originalOffset := 4", source)
        self.assertIn("preservedImports := [{ original := .esi", source)
        self.assertIn("preservedRelations := [{ original := .ebx", source)
        self.assertIn("suspendedInventoryNodeId := 1", source)
        self.assertIn("runtimeFrameAffineMinimalActiveControlStates", source)
        self.assertIn("runtimeFrameAffineMinimalActiveControlProfileChecked", source)
        self.assertIn("runtimeFrameAffineMinimalLinkedControlStates", source)
        self.assertIn("runtimeFrameAffineMinimalLinkedControlProfileChecked", source)
        self.assertNotIn("runtimeFrameAffineSemanticTransition", source)
        self.assertNotIn("ReturnSlotAffineFrameSemanticTransitionBinding", source)
        self.assertNotIn("authority", source.lower())
        self.assertNotIn("acceptance", source.lower())
        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])

    def test_malformed_or_gapped_payloads_fail_closed(self):
        cases = []

        gaps = self._payload()
        gaps["gaps"] = [{"reason": "call_edge_not_unique"}]
        cases.append(("gap", gaps, "unresolved gaps"))

        gapped_ids = self._payload()
        gapped_ids["states"][1]["id"] = 2
        cases.append(("gapped ids", gapped_ids, "canonical and contiguous"))

        bad_count = self._payload()
        bad_count["counts"]["affine_shapes"] = 4
        cases.append(("bad count", bad_count, "counts do not match"))

        bad_mapping = self._payload()
        bad_mapping["links"][0]["resume_shape"]["locations"][
            "profile_state_index"
        ] = 0
        cases.append(("bad affine mapping", bad_mapping, "inconsistent affine"))

        claimed_authority = self._payload()
        claimed_authority["acceptance_authority"] = True
        cases.append(("authority", claimed_authority, "must not claim"))

        malformed_bindings = self._payload()
        malformed_bindings["transition_bindings"] = {}
        cases.append(("binding container", malformed_bindings, "must be a list"))

        for name, payload, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(StageAInputError, message):
                    relational_affine_linked_control_source(payload)

    def test_singleton_call_binding_is_validated_and_emitted_by_semantic_owner(self):
        (
            affine,
            linked,
            graph,
            regions,
            register_relations,
        ) = StageAAffineLinkedControlTests._call_inputs()
        payload = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        control_source = relational_affine_linked_control_source(payload)
        self.assertIn("runtimeFrameAffineMinimalNestedLinkShapes", control_source)
        self.assertIn("originalGap := 16", control_source)
        self.assertIn("candidateGap := 24", control_source)

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            (stage_a / "RelationalAffineFrameSemanticChunk0.lean").write_text(
                "def runtimeFrameAffineSemanticTransition0 : Nat := 0\n",
                encoding="utf-8",
            )
            (stage_a / "RelationalAffineFrameSemanticSeedChunk0.lean").write_text(
                "def runtimeFrameAffineSemanticSeed0 : Nat := 0\n",
                encoding="utf-8",
            )
            (stage_a / "RelationalProofOriginalDecodeChunk0.lean").write_text(
                "theorem originalBehavior2CheckedDecoded : True := by trivial\n",
                encoding="utf-8",
            )
            (stage_a / "RelationalProofCandidateDecodeChunk0.lean").write_text(
                "theorem candidateBehavior2CheckedDecoded : True := by trivial\n",
                encoding="utf-8",
            )
            modules = write_relational_affine_linked_call_binding_modules(
                lean_dir, payload
            )
            chunk = (
                stage_a / "RelationalAffineLinkedCallBindingChunk0.lean"
            ).read_text(encoding="utf-8")
            aggregate = (
                stage_a / f"{AFFINE_LINKED_CALL_BINDINGS_MODULE}.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(modules[-1], AFFINE_LINKED_CALL_BINDINGS_MODULE)
        self.assertIn(
            "SingletonAffineNestedDirectCallControlBinding", chunk
        )
        self.assertIn("sourceControlStateIndex :=", chunk)
        self.assertIn("innerSeed := runtimeFrameAffineSemanticSeed0", chunk)
        self.assertIn(
            "stackAmount := { original := 12, candidate := 12 }", chunk
        )
        self.assertIn("returnSummaries := [", chunk)
        self.assertIn("SingletonAffineNestedDirectCallReturnSummary", chunk)
        self.assertIn("returnNodeId := 2", chunk)
        self.assertIn(
            "runtimeFrameAffineCallTransitionBinding0.sourceToSuspended.region.inputInvariant",
            chunk,
        )
        self.assertIn("runtimeFrameAffineCallTransitionBindingsChecked", aggregate)

        malformed = deepcopy(payload)
        malformed["minimal_call_transition_bindings"][0][
            "outer_continuation_target_id"
        ] = 100
        with self.assertRaisesRegex(StageAInputError, "control states or link"):
            relational_affine_linked_control_source(malformed)

    def test_returning_import_call_binding_has_separate_checked_owner(self):
        affine, linked, graph, regions, register_relations = (
            StageAAffineLinkedControlTests._call_inputs()
        )
        relation_edge = register_relations["edges"][0]
        internal = relation_edge["return_slot_call_summary_claims"].pop()
        relation_edge["return_slot_external_call_summary_claims"] = [{
            "profile": "external_return_slot_call_summary_v1",
            "machine_contract_id": 4,
            "thunk_region_index": 1,
            "continuation_region_index": 2,
            "source": deepcopy(internal["source"]),
            "suspended": deepcopy(internal["source"]),
            "target": deepcopy(internal["target"]),
            "original_call_witness": {"kind": "input"},
            "candidate_call_witness": {"kind": "input"},
            "thunk_transfer": {
                "source": deepcopy(internal["source"]),
                "internal_target": deepcopy(internal["target"]),
                "boundary_target": deepcopy(internal["target"]),
                "internal_rule": {
                    "original_source_register": "esp",
                    "candidate_source_register": "esp",
                    "original_target_register": "esp",
                    "candidate_target_register": "esp",
                    "original_output_witness": {"kind": "input"},
                    "candidate_output_witness": {"kind": "input"},
                    "original_delta": 0,
                    "candidate_delta": 0,
                },
                "result_rule": {
                    "source": deepcopy(internal["target"]),
                    "target": deepcopy(internal["target"]),
                    "original_delta": 0,
                    "candidate_delta": 0,
                },
                "memory_claim": {
                    "offsets": deepcopy(internal["source"]),
                    "original_write_witnesses": [],
                    "candidate_write_witnesses": [],
                },
            },
        }]
        payload = affine_linked_control_payload(
            runtime_frame_affine=affine,
            linked_control=linked,
            product_graph=graph,
            regions=regions,
            register_relations=register_relations,
        )

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            (stage_a / "RelationalAffineFrameSemanticChunk0.lean").write_text(
                "def runtimeFrameAffineSemanticTransition0 : Nat := 0\n",
                encoding="utf-8",
            )
            (stage_a / "RelationalAffineFrameSemanticSeedChunk0.lean").write_text(
                "def runtimeFrameAffineSemanticSeed0 : Nat := 0\n",
                encoding="utf-8",
            )
            (stage_a / "RelationalProofOriginalDecodeChunk0.lean").write_text(
                "theorem originalBehavior1CheckedDecoded : True := by trivial\n",
                encoding="utf-8",
            )
            (stage_a / "RelationalProofCandidateDecodeChunk0.lean").write_text(
                "theorem candidateBehavior1CheckedDecoded : True := by trivial\n",
                encoding="utf-8",
            )
            modules = write_relational_affine_linked_external_call_binding_modules(
                lean_dir, payload
            )
            chunk = (
                stage_a / "RelationalAffineLinkedExternalCallBindingChunk0.lean"
            ).read_text(encoding="utf-8")
            aggregate = (
                stage_a / f"{AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE}.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(
            modules[-1], AFFINE_LINKED_EXTERNAL_CALL_BINDINGS_MODULE
        )
        self.assertIn(
            "SingletonAffineReturningImportDirectCallControlBinding", chunk
        )
        self.assertIn("machineContractId := 4", chunk)
        self.assertIn("thunkRegion := region1", chunk)
        self.assertIn("returnSummaries := []", chunk)
        self.assertIn(
            "SingletonAffineReturningImportDirectCallExecutionCertificate",
            chunk,
        )
        self.assertIn("entryClaim := { source :=", chunk)
        self.assertIn("memory := .protectedSpan", chunk)
        self.assertIn("resumeClaim := { source :=", chunk)
        self.assertIn(
            "runtimeFrameAffineExternalCallExecutionCertificatesChecked",
            aggregate,
        )
        self.assertIn(
            "affineReturningImportCertificatesCoverActiveCallNode",
            aggregate,
        )
        self.assertIn(
            "runtimeFrameAffineExternalCallExecutionCertificatesNode0Edge0Covered",
            aggregate,
        )
        self.assertIn(
            "runtimeFrameAffineExternalCallTransitionBindingsChecked", aggregate
        )

    def test_incomplete_control_closure_does_not_block_checked_shape_projection(self):
        payload = self._payload()
        payload["status"] = "incomplete"
        payload["shape_projection_status"] = "complete"
        payload["control_closure_status"] = "incomplete"
        payload["control_closure_coverage"] = {
            "seed_rooted_affine_states": 1189,
            "represented_states": 2,
        }
        payload["transition_bindings"] = [{
            "id": 0,
            "transition_id": 4,
            "source_control_state_id": 0,
            "target_control_state_id": 1,
        }]
        payload["transition_binding_gaps"] = [{
            "transition_id": 8,
            "reason": "control_state_pair_not_unique",
        }]
        payload["coverage_gaps"] = {
            "unrepresented_rooted_affine_state_ids": [7],
            "unbound_rooted_affine_transition_ids": [8],
        }
        payload["future_diagnostic"] = {"schema": "not-proof-relevant"}
        payload["counts"]["seed_rooted_affine_states"] = 1189
        payload["counts"]["represented_states"] = 2

        source = relational_affine_linked_control_source(payload)

        self.assertIn("runtimeFrameAffineLinkedControlProfileChecked", source)
        self.assertNotIn("runtimeFrameAffineSemanticTransition4", source)
        self.assertNotIn("ReturnSlotAffineFrameSemanticTransitionBinding", source)
        self.assertNotIn("authority", source.lower())
        self.assertNotIn("acceptance", source.lower())

    def test_minimal_bindings_are_deduplicated_by_semantic_transition_owner(self):
        payload = self._payload()
        payload["minimal_active_states"].append({
            "id": 1,
            "affine_state_id": 1,
            "node_id": 2,
            "continuation_target_id": 11,
            "active_shape": self._affine_shape(1, 1),
            "minimum_depth": 1,
            "seed_ids": [],
        })
        payload["counts"]["minimal_active_states"] = 2
        binding = {
            "id": 0,
            "transition_id": 7,
            "edge_id": 3,
            "source_control_state_id": 0,
            "target_control_state_id": 1,
            "continuation_target_id": 11,
            "source_shape": self._affine_shape(0, 0),
            "target_shape": self._affine_shape(1, 1),
            "profile": "ordinary_no_write_affine_control_v1",
        }
        payload["minimal_transition_bindings"] = [binding]

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            (stage_a / "RelationalAffineFrameSemanticChunk4.lean").write_text(
                "def runtimeFrameAffineSemanticTransition7 : Nat := 0\n",
                encoding="utf-8",
            )
            modules = write_relational_affine_linked_control_binding_modules(
                lean_dir, payload
            )
            chunk = (
                stage_a / "RelationalAffineLinkedControlBindingChunk0.lean"
            ).read_text(encoding="utf-8")
            aggregate = (
                stage_a / f"{AFFINE_LINKED_CONTROL_BINDINGS_MODULE}.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(modules[-1], AFFINE_LINKED_CONTROL_BINDINGS_MODULE)
        self.assertIn("import StageA.RelationalAffineFrameSemanticChunk4", chunk)
        self.assertEqual(
            chunk.count("def runtimeFrameAffineFrameTransitionBinding7 "), 1
        )
        self.assertIn("def runtimeFrameAffineControlTransitionBinding0 ", chunk)
        self.assertIn("sourceControlStateIndex := 0", chunk)
        self.assertIn("targetControlStateIndex := 1", chunk)
        self.assertIn("continuationTargetId := 11", chunk)
        self.assertIn(
            "runtimeFrameAffineControlBindingChunk0Node1Edge3Covered", chunk
        )
        self.assertIn(
            "affineOrdinaryBindingsCoverActiveNodeEdge", chunk
        )
        self.assertIn(
            "runtimeFrameAffineControlTransitionBindingsChecked", aggregate
        )

    def test_minimal_binding_context_and_semantic_owner_fail_closed(self):
        payload = self._payload()
        payload["minimal_transition_bindings"] = [{
            "id": 0,
            "transition_id": 7,
            "edge_id": 3,
            "source_control_state_id": 0,
            "target_control_state_id": 0,
            "continuation_target_id": 12,
            "source_shape": self._affine_shape(0, 0),
            "target_shape": self._affine_shape(0, 0),
            "profile": "ordinary_no_write_affine_control_v1",
        }]
        with self.assertRaisesRegex(StageAInputError, "changes its continuation"):
            relational_affine_linked_control_source(payload)

        payload["minimal_transition_bindings"][0]["continuation_target_id"] = 11
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            (lean_dir / "StageA").mkdir()
            with self.assertRaisesRegex(StageAInputError, "without generated owners"):
                write_relational_affine_linked_control_binding_modules(
                    lean_dir, payload
                )

    def test_memory_bindings_emit_exact_decoded_writes_and_coverage(self):
        payload = self._payload()
        payload["minimal_active_states"].append({
            "id": 1,
            "affine_state_id": 1,
            "node_id": 2,
            "continuation_target_id": 11,
            "active_shape": self._affine_shape(1, 1),
            "minimum_depth": 1,
            "seed_ids": [],
        })
        payload["counts"]["minimal_active_states"] = 2
        payload["minimal_memory_transition_bindings"] = [{
            "id": 0,
            "transition_id": 7,
            "edge_id": 3,
            "source_control_state_id": 0,
            "target_control_state_id": 1,
            "continuation_target_id": 11,
            "source_shape": self._affine_shape(0, 0),
            "target_shape": self._affine_shape(1, 1),
            "writes": [{
                "original_address": {"op": "input_reg", "reg": "esp"},
                "original_value": {"op": "input_reg", "reg": "eax"},
                "candidate_address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": "esp"},
                    "right": {"op": "constant", "value": 4},
                },
                "candidate_value": {"op": "input_reg", "reg": "ebx"},
            }, {
                "original_address": {
                    "op": "add",
                    "left": {"op": "input_reg", "reg": "esp"},
                    "right": {"op": "constant", "value": 2**32 - 2},
                },
                "original_value": {"op": "input_reg", "reg": "ecx"},
                "candidate_address": {
                    "op": "sub",
                    "left": {"op": "input_reg", "reg": "esp"},
                    "right": {"op": "constant", "value": 2},
                },
                "candidate_value": {"op": "input_reg", "reg": "edx"},
            }],
            "profile": "ordinary_paired_write_affine_control_v1",
        }]

        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            (stage_a / "RelationalAffineFrameSemanticChunk4.lean").write_text(
                "def runtimeFrameAffineSemanticTransition7 : Nat := 0\n",
                encoding="utf-8",
            )
            modules = write_relational_affine_linked_memory_binding_modules(
                lean_dir, payload
            )
            chunk = (
                stage_a / "RelationalAffineLinkedMemoryBindingChunk0.lean"
            ).read_text(encoding="utf-8")
            aggregate = (
                stage_a / f"{AFFINE_LINKED_MEMORY_BINDINGS_MODULE}.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(modules[-1], AFFINE_LINKED_MEMORY_BINDINGS_MODULE)
        self.assertIn("ReturnSlotAffineLinkedMemoryTransitionBinding", chunk)
        self.assertIn("originalAddress := StageA.Formal.Expr.inputReg", chunk)
        self.assertIn("candidateValue := StageA.Formal.Expr.inputReg", chunk)
        self.assertIn("offset := .below 2", chunk)
        self.assertIn("expression := .sub (.esp) 2", chunk)
        self.assertIn("affineMemoryBindingsCoverActiveNodeEdge", chunk)
        self.assertIn("runtimeFrameAffineMemoryTransitionBindingsChecked", aggregate)
        self.assertIn("runtimeFrameAffineMemoryBindingChunk0MemberOfAggregate", aggregate)
        self.assertIn(
            "runtimeFrameAffineMemoryTransitionBindingsNode1Edge3Covered",
            aggregate,
        )
        self.assertIn("affineMemoryBindingsCoverActiveNodeEdge.mono", aggregate)


if __name__ == "__main__":
    unittest.main()
