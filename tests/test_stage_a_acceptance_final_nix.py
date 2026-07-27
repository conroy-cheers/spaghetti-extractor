from tests.stage_a_relational_support import *
from spaghetti_extractor.relational.schema import (
    PROTOCOL_CALLBACK_CONTROL_FORMAT,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
)
from spaghetti_extractor.relational.lean.acceptance import (
    _acceptance_segment_imports,
    _frame_relations_requiring_internal_preservation,
    _lean_frame_exact_word_register_output_claim,
    _lean_acceptance_linked_shallow_lift,
    _lean_acceptance_linked_shallow_node,
    _lean_return_slot_frame_transfer_claim,
    _lean_runtime_call_import_transfer_claim,
    _launch_check_ranges,
    _launch_state_predicates_structurally_true,
    _launch_structural_image_ranges,
    _runtime_frame_protected_bytes,
    _segment_module_ownership,
    _semantic_bool_is_structural_tautology,
)
from spaghetti_extractor.relational.lean.expressions import (
    _lean_direct_call_prepared_exact_word_seed_claim,
)
from typing import Any


class StageAAcceptanceFinalNixTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for sharded relational proofs")
    def test_sharded_preparation_uses_canonical_static_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xd8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            report = root / "report"

            with patch.dict(os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prepare_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["status"], "prepared", result)
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
            self.assertNotIn("RelationalProofDirectChunk", bundle)
            self.assertNotIn("allDirectRegionsChecked", bundle)
            self.assertIn("candidateRelationalEvidenceBundle", bundle)
            self.assertNotIn("RelationalImageCertificate proofBundle", bundle)
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
                    "outside_declared_reachability_nodes": 0,
                    "potential_reachable_nodes": 1,
                    "potential_reachable_feasible_edges": 1,
                    "potential_unrepresented_control_edges": 0,
                    "terminating_call_continuations": 0,
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
                    "certificate_format": "stage-a-relational-segment-certificate-v1",
                    "edges": 1,
                    "incomplete": 0,
                    "incomplete_reason_counts": {},
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
                Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
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
            self.assertIn("def PE32ConsoleLaunchWorldV1.Valid", source)
            self.assertIn("structure PE32ConsoleLaunchStateRel", source)
            self.assertIn("originalImageMapped : PreferredBaseImageMemory", source)
            self.assertIn("candidateImageMapped : PreferredBaseImageMemory", source)
            self.assertNotIn("sorry", source)
            result = _run_lean_relational(
                lean_dir, bundle="RelationalCertificates"
            )
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for whole-program proofs")
    def test_preparation_selects_the_replayable_acceptance_theorem(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\xeb\xfe")
            candidate = self._write_pe(root / "candidate.exe", b"\xeb\xfe")
            contract = self._write_contract(root / "relation.json", region_size=2)
            report = root / "report"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["status"], "prepared", result)
            graph = _validate_relational_module_graph(report)
            self.assertEqual(graph["root_module"], "RelationalAcceptance")
            self.assertEqual(
                graph["expected_final_theorem"],
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
            )

            self.assertFalse((report / "verdict.json").exists())

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
                graph["modules"]["RelationalDecode"]["imports"],
                ["Formal", "RelationalX87Decode"],
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
                    target_nodes=["does-not-exist"],
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
            proof_packs = [
                node for node in graph["nodes"]
                if node["id"].startswith("local-proof-pack-")
            ]
            proof_shards = [
                module for module in graph["modules"]
                if module.startswith("RelationalProofShard")
                and module.removeprefix("RelationalProofShard").isdigit()
            ]
            self.assertEqual(bool(proof_packs), bool(proof_shards))
            self.assertTrue(all(
                node["resource_class"] == "medium" for node in proof_packs
            ))
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
            self.assertTrue(register_relations["dataflow_complete"])
            dataflow_graph = json.loads(
                (prepared / "relational-register-dataflow-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                dataflow_graph["format"],
                "stage-a-register-dataflow-graph-v1",
            )
            self.assertFalse(dataflow_graph["acceptance_authority"])
            transfer_table = json.loads(
                (prepared / "relational-register-transfer-table.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                transfer_table["format"],
                "stage-a-register-transfer-table-v1",
            )
            self.assertEqual(
                transfer_table["graph_sha256"], dataflow_graph["graph_sha256"]
            )
            self.assertFalse(transfer_table["acceptance_authority"])
            program_graph = json.loads(
                (
                    prepared
                    / "relational-register-program-dataflow-graph.json"
                ).read_text(encoding="utf-8")
            )
            transfer_programs = json.loads(
                (
                    prepared / "relational-register-transfer-programs.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                transfer_programs["format"],
                "stage-a-register-transfer-programs-v1",
            )
            self.assertEqual(
                transfer_programs["graph_sha256"],
                program_graph["graph_sha256"],
            )
            self.assertEqual(
                program_graph, register_relations["dataflow_graph"]
            )
            self.assertEqual(transfer_programs["region_count"], 1)
            self.assertEqual(
                len(transfer_programs["propagation"]["regions"]), 1,
            )
            self.assertFalse(transfer_programs["acceptance_authority"])
            self.assertFalse(
                (prepared / "relational-register-dataflow-problem.json").exists()
            )
            dataflow_problem_seed = json.loads(
                (
                    prepared
                    / "relational-register-dataflow-problem-seed.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                dataflow_problem_seed["format"],
                "stage-a-register-dataflow-problem-seed-v2",
            )
            self.assertEqual(
                dataflow_problem_seed["original_sha256"],
                transfer_programs["original_sha256"],
            )
            self.assertEqual(
                dataflow_problem_seed["candidate_sha256"],
                transfer_programs["candidate_sha256"],
            )
            self.assertFalse(dataflow_problem_seed["acceptance_authority"])
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
                (prepared / "relational-static-word-relations.json").read_bytes(),
                (second / "relational-static-word-relations.json").read_bytes(),
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

            static_relations_path = (
                prepared / "relational-static-word-relations.json"
            )
            static_relations_bytes = static_relations_path.read_bytes()
            static_relations_path.write_bytes(static_relations_bytes + b"\n")
            with self.assertRaisesRegex(
                StageAInputError, "relational-static-word-relations.json"
            ):
                _validate_prepared_relational(prepared)
            static_relations_path.write_bytes(static_relations_bytes)

            source = prepared / "lean" / "StageA" / "RelationalBundle.lean"
            source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "source hash does not match"):
                _validate_prepared_relational(prepared)

    @unittest.skipUnless(
        shutil.which("lean") and shutil.which("nix") and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 to run the Nix derivation graph",
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
                builders_file=(
                    Path(builders)
                    if (
                        builders := os.environ.get(
                            "SPAGHETTI_EXTRACTOR_STAGE_A_TEST_BUILDERS"
                        )
                    )
                    else None
                ),
            )

            self.assertEqual(result["status"], "pass", result)
            self.assertTrue(result["checks"]["lean_trust_zero"])
            self.assertEqual(result["lean_audit"]["unexpected_axioms"], [])
            self.assertGreater(result["provenance"]["node_derivations"], 1)
            self.assertEqual(result["provenance"]["nix_paths"], 1)
            self.assertEqual(result["provenance"]["dependency_archive_bytes"], 0)
            self.assertEqual(
                result["provenance"]["materialized_dependency_oleans"],
                0,
            )
            self.assertGreater(result["provenance"]["dependency_references"], 1)
            provenance = json.loads(
                (root / "report" / "nix-provenance.json").read_text(encoding="utf-8")
            )
            self.assertTrue(provenance["nodes"])
            self.assertNotIn("out_path", provenance["nodes"][0])
            self.assertRegex(
                provenance["nodes"][0]["outputs"][0]["olean_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertRegex(
                provenance["nodes"][0]["semantic_id"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                provenance["dependency_view"]["node_count"],
                result["provenance"]["node_derivations"] - 1,
            )
            source_reference = json.loads(
                (root / "report" / "lean-source-reference.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(source_reference["materialized"])
            self.assertEqual(
                source_reference["module_count"],
                result["counts"]["logical_modules"],
            )
            semantic_reference = json.loads(
                (
                    root / "report" / "semantic-graph-reference.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                semantic_reference["format"],
                "stage-a-lean-semantic-graph-reference-v1",
            )
            self.assertRegex(
                semantic_reference["root_semantic_id"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                provenance["semantic_graph_reference"],
                semantic_reference,
            )
            self.assertFalse((root / "report" / "lean").exists())

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for process cancellation")
    def test_relational_lean_process_is_terminated_on_cancellation(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )
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
