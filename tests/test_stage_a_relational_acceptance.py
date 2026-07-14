from tests.stage_a_relational_support import *


class StageARelationalAcceptanceTests(StageARelationalTestBase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for sharded relational proofs")
    def test_sharded_local_proof_uses_canonical_static_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xd8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            report = root / "report"

            with patch.dict(os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}):
                result = stage_a_prove_relational(
                    original=original,
                    candidate=candidate,
                    relation_contract=contract,
                    out=report,
                )

            self.assertEqual(result["verdict"], "pass", result)
            self.assertEqual(result["proof"]["lean"]["status"], "checked", result)
            self.assertTrue(
                result["claim_scope"]["whole_program_observational_equivalence"]
            )
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
            self.assertIn(
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
                    "certificate_format": "stage-a-relational-segment-certificate-v1",
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
            self.assertEqual(result["acceptance"]["status"], "ready", result)
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
            code = (
                b"\x83\xec\x0c"              # sub esp, 12
                b"\xe8\x05\x00\x00\x00"  # call callee-return
                b"\x83\xc4\x0c"              # add esp, 12
                b"\xeb\xf3"                    # loop to caller
                b"\xc3"                          # callee-return: ret
            )
            original = self._write_pe(root / "original.exe", code)
            candidate_image = bytearray(_pe32_image(b"\x90" + code))
            struct.pack_into("<I", candidate_image, 0xA8, 0x1001)
            candidate = root / "candidate.exe"
            candidate.write_bytes(candidate_image)
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
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1001},
                    {"id": 1, "original_rva": 0x1008, "candidate_rva": 0x1009},
                    {"id": 2, "original_rva": 0x100D, "candidate_rva": 0x100E},
                ],
                "regions": [
                    {
                        "id": "caller", "root": True,
                        "original": {"rva": 0x1000, "size": 8},
                        "candidate": {"rva": 0x1001, "size": 8},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "continuation", "root": False,
                        "original": {"rva": 0x1008, "size": 5},
                        "candidate": {"rva": 0x1009, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "callee-return", "root": False,
                        "original": {"rva": 0x100D, "size": 1},
                        "candidate": {"rva": 0x100E, "size": 1},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [{
                    "id": "candidate-entry-padding",
                    "side": "candidate",
                    "rva": 0x1000,
                    "size": 1,
                }],
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
            self.assertEqual(result["acceptance"]["status"], "ready", result)
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
            self.assertEqual(
                progress["counts"]["rooted_stack_invariant_frontier_nodes"], 0
            )
            self.assertEqual(progress["next_work"], [])
            self.assertEqual(
                result["acceptance"]["control_states"],
                [
                    {"node_id": 0, "calls": [], "frame_offsets": []},
                    {
                        "node_id": 2,
                        "calls": [1],
                        "frame_offsets": [{
                            "original_register": "esp", "original": 0,
                            "candidate_register": "esp", "candidate": 0,
                        }],
                    },
                    {"node_id": 1, "calls": [], "frame_offsets": []},
                ],
            )
            normalized = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                normalized["regions"][0]["stack_windows"][0]["bytes_below"], 16
            )
            self.assertEqual(
                normalized["regions"][1]["stack_windows"][0],
                {
                    "range_id": 0,
                    "original_register": "esp",
                    "candidate_register": "esp",
                    "bytes_below": 4,
                    "bytes_above": 13,
                    "source": "backward_identity_stack_window",
                },
            )
            self.assertEqual(
                normalized["regions"][2]["stack_windows"][0]["bytes_above"], 17
            )
            direct_call = next(
                obligation["analysis"]["certificate"]
                for obligation in json.loads(
                    (prepared / "relational-proof-ir.json").read_text(
                        encoding="utf-8"
                    )
                )["obligations"]
                if obligation["kind"] == "relational_segment_refinement"
                and obligation["analysis"].get("certificate", {}).get(
                    "certificate_profile"
                ) == "composable_direct_call_v1"
            )
            self.assertEqual(direct_call["original_return_address"], 0x401008)
            self.assertEqual(direct_call["candidate_return_address"], 0x401009)
            self.assertEqual(direct_call["stack_amount"], 16)
            segment_source = (
                prepared / "lean" / "StageA" /
                "RelationalSegmentRefinementChunk0.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "segmentRefinementEdge0OriginalNormalizedBehavior",
                segment_source,
            )
            self.assertIn(
                "segmentRefinementEdge0CandidateNormalizedBehavior",
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

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for import-thunk proofs")
    def test_direct_import_thunk_checks_runtime_frame_and_environment_end_to_end(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            iat_address = 0x400000 + 0x2000 + 0x40
            code = (
                b"\xe8\x02\x00\x00\x00"
                b"\xeb\xfe"
                b"\xff\x25" + struct.pack("<I", iat_address)
            )
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
            candidate.write_bytes(_pe32_import_image(code, symbol="GetTickCount"))
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
                        "id": "continuation-loop", "root": False,
                        "original": {"rva": 0x1005, "size": 2},
                        "candidate": {"rva": 0x1005, "size": 2},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "get-tick-count-import-thunk", "root": False,
                        "original": {"rva": 0x1007, "size": 6},
                        "candidate": {"rva": 0x1007, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "machine_import_call_contracts": [{
                    "id": 0,
                    "import": {"dll": "kernel32.dll", "symbol": "GetTickCount"},
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
                [step["kind"] for step in result["acceptance"]["node_steps"]],
                ["call", "jump", "external_jump"],
            )
            sites = json.loads(
                (prepared / "relational-external-call-sites.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(sites["counts"], {"candidates": 1, "gaps": 0})
            self.assertEqual(
                sites["candidates"][0]["dispatch_profile"],
                "checked_direct_import_thunk",
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
                os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}
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
                os.environ, {"SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_SHARD_THRESHOLD": "1"}
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
            self.assertEqual(relations["counts"]["call_return_edges"], 0)
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertFalse(any(
                obligation["kind"] == "call_return_stack_composition"
                for obligation in proof_ir["obligations"]
            ))
            product_graph = json.loads(
                (root / "report" / "relational-product-graph.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                product_graph["evidence"]["runtime_call_continuations"],
                [{"source_node_id": 0, "continuation_node_ids": [1]}],
            )
            segment_obligations = [
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "relational_segment_refinement"
            ]
            self.assertGreaterEqual(len(segment_obligations), 1)
            self.assertIn(
                "successor_state_composition",
                {obligation["repair_class"] for obligation in segment_obligations},
            )
            self.assertGreaterEqual(
                proof_ir["segment_refinement_summary"]["proved"], 1
            )
            proved_segments = [
                obligation for obligation in segment_obligations
                if obligation["status"] == "proved"
            ]
            self.assertTrue(any(
                obligation["analysis"]["certificate_profile"]
                    == "composable_local_no_write_v1"
                for obligation in proved_segments
            ))
            register_sources = [
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob(
                    "RelationalRegisterRelationsChunk*.lean"
                )
            ]
            self.assertFalse(any(
                "CallReturnEdgeShapeClosed" in source
                for source in register_sources
            ))

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
