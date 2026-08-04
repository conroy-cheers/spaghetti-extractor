from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_launch_binding import (
    GNU_HELLO_ACTIVE_BRIDGE_RVA,
    GNU_HELLO_ENTRY_RVA,
    GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID,
    GNU_HELLO_ORIGINAL_TLS_TARGET_IDS,
    GNU_HELLO_TLS_CALLBACK_RVAS,
    GnuHelloLaunchBindingSpec,
    build_gnu_hello_launch_binding_plan,
    gnu_hello_launch_binding_source,
    write_gnu_hello_launch_binding,
)
from spaghetti_extractor_target_gnu_hello.gnu_hello_acceptance_requirements import (
    build_gnu_hello_acceptance_requirements_plan,
    gnu_hello_acceptance_requirements_source,
)


class StageAGnuHelloLaunchBindingTests(unittest.TestCase):
    def test_default_binding_closes_exact_root_replay_and_capture(self) -> None:
        plan = build_gnu_hello_launch_binding_plan()
        source = gnu_hello_launch_binding_source(plan)
        payload = plan.payload()

        self.assertTrue(plan.complete)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["status"], "source-ready")
        self.assertFalse(payload["acceptance_authority"])
        self.assertTrue(payload["lean_check_required"])
        self.assertEqual(payload["blocking_obligations"], [])
        self.assertEqual(
            payload["exact_roots"],
            {
                "entry_rva": GNU_HELLO_ENTRY_RVA,
                "tls_callback_rvas": list(GNU_HELLO_TLS_CALLBACK_RVAS),
                "original_entry_target_id": (
                    GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID
                ),
                "original_tls_target_ids": list(
                    GNU_HELLO_ORIGINAL_TLS_TARGET_IDS
                ),
            },
        )
        self.assertEqual(
            payload["public_terms"],
            {
                "launch_wrapper_refinements": (
                    "generatedAcceptanceLaunchWrapperRefinements"
                ),
                "launch_realizable": (
                    "RuntimeFoundation.generatedLaunchRealizable"
                ),
                "launch_prefix": "generatedAcceptanceLaunchPrefix",
                "exact_binding": (
                    "generatedExactCanonicalLaunchWrapperBinding"
                ),
            },
        )
        self.assertEqual(
            payload["dynamic_evidence_fields"],
            {
                "launch_realizable": {
                    "status": "constructed",
                    "term": "RuntimeFoundation.generatedLaunchRealizable",
                },
                "launch_wrapper_refinements": {
                    "status": "constructed",
                    "term": "generatedAcceptanceLaunchWrapperRefinements",
                },
                "launch_prefix": {
                    "status": "constructed",
                    "term": "generatedAcceptanceLaunchPrefix",
                },
            },
        )
        serialized_payload = json.dumps(payload, sort_keys=True)
        self.assertNotIn("incomplete", serialized_payload)
        self.assertNotIn("delegated", serialized_payload)
        self.assertNotIn("roots_related", serialized_payload)
        self.assertNotIn(
            "launch_chunk_requires_original_stutter",
            serialized_payload,
        )
        self.assertNotIn("runtime_phase_endpoint", serialized_payload)
        self.assertNotIn(
            "generatedReplayEstablishesRuntimePhaseStateFacts",
            serialized_payload,
        )

        for required in (
            "generatedCandidatePeExact",
            "generatedCandidateImportsExact",
            "generatedCandidateLaunchRootsExact",
            "generatedCanonicalRootRoute",
            "generatedExactNativeLaunchRuntime",
            "generatedEntryOriginalSourceExact",
            "generatedTls0OriginalSourceExact",
            "generatedTls1OriginalSourceExact",
            "generatedEntryOriginalReachable",
            "generatedTls0OriginalReachable",
            "generatedTls1OriginalReachable",
            "generatedEntryReplayCapture",
            "generatedTls0ReplayCapture",
            "generatedTls1ReplayCapture",
            "generatedLaunchRootPhaseStateFacts",
            "generatedLaunchCarrierCanonicalExecutions",
            "ExactConstructiveMixedLaunchCarrier",
            "ExactConstructiveMixedLaunchCarrier.canonicalExecutions",
            "ConstructiveMixedKernelRuntimeEvidence",
            "ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact",
            "generatedCanonicalRootFrameFacts",
            "generatedReplayEstablishesRuntimePhaseStateFacts",
            "generatedLaunchWrapperRefinements",
            "generatedAcceptanceLaunchWrapperRefinements",
            "generatedRuntimeBoundaryClassified",
            "generatedAcceptanceLaunchPrefixEndpoint",
            "generatedAcceptanceLaunchPrefix",
            "generatedExactCanonicalLaunchWrapperBinding",
            "ConstructiveMixedKernelPhaseStateFacts",
            "ConstructiveMixedKernelSourceEvidence",
            "OriginalEngineStateHolds.of_launch_exact",
            "canonicalMixedRuntimeStatesRelated_of_inputEngine",
            "generatedExactOriginalDecodedStaticReachability.targetIds",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "CheckedLaunchSemanticFactsBinding",
            "semantic_facts",
            "generatedGnuHelloCanonicalMixedLaunchRootFrameFacts",
            "(replayPresent :",
            "manifest status",
            "report status",
        ):
            self.assertNotIn(forbidden, source)
        replay_signature = source.split(
            "theorem generatedReplayEstablishesRuntimePhaseStateFacts", 1
        )[1].split(":= by", 1)[0]
        self.assertNotIn("(runtimeRelated :", replay_signature)
        prefix_signature = source.split(
            "noncomputable def generatedAcceptanceLaunchPrefix\n", 1
        )[1].split(":= by", 1)[0]
        self.assertIn("(environmentRefines :", prefix_signature)
        for forbidden in (
            "(replayed :",
            "(runtimeRelated :",
            "(launchRelated :",
            "(candidateAfter :",
            "(originalPath :",
            "(candidatePath :",
            "(postState :",
        ):
            self.assertNotIn(forbidden, prefix_signature)
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source), forbidden)

    def test_phase_transition_is_launch_at_root_and_runtime_after_replay(
        self,
    ) -> None:
        source = gnu_hello_launch_binding_source(
            build_gnu_hello_launch_binding_plan()
        )
        payload = build_gnu_hello_launch_binding_plan().payload()

        self.assertIn(
            "launchRelated : MixedLaunchStatesRelated", source
        )
        self.assertIn(
            "replayEstablishesRuntime :=", source
        )
        self.assertIn(
            "ConstructiveMixedKernelPhaseStateFacts\n"
            "            (generatedCore requirements).contract evidence",
            source,
        )
        self.assertNotIn(
            "MixedExecutionMachineStatesRelated.ofRuntime runtimeRelated",
            source,
        )
        self.assertIn(
            "ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact evidence",
            source,
        )
        self.assertNotIn(
            "ConstructiveMixedKernelStateFacts contract", source
        )
        self.assertEqual(
            payload["phase_policy"],
            {
                "root_relation": "launchStatesRelated",
                "root_classifier": (
                    "ConstructiveMixedKernelSourceEvidence.launch"
                ),
                "root_carrier": "ExactConstructiveMixedLaunchCarrier",
                "root_carrier_projection": (
                    "ExactConstructiveMixedLaunchCarrier.canonicalExecutions"
                ),
                "wrapper_endpoint_relation": "runtimeStatesRelated",
                "wrapper_endpoint_constructor": (
                    "ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact"
                ),
                "classifier_wide_policy_owned_by": (
                    "constructive-mixed-source-classifier"
                ),
            },
        )
        self.assertEqual(payload["blocking_obligations"], [])
        self.assertNotIn("roots_related", json.dumps(payload))
        self.assertNotIn("delegated", json.dumps(payload))
        self.assertNotIn("incomplete", json.dumps(payload))
        self.assertNotIn(
            "launch_chunk_requires_original_stutter",
            json.dumps(payload),
        )

    def test_exact_constants_are_checked_inside_lean(self) -> None:
        source = gnu_hello_launch_binding_source(
            build_gnu_hello_launch_binding_plan()
        )

        self.assertIn(f"entryRva := {GNU_HELLO_ENTRY_RVA}", source)
        self.assertIn(
            "tlsCallbackRvas := "
            f"[{GNU_HELLO_TLS_CALLBACK_RVAS[0]}, "
            f"{GNU_HELLO_TLS_CALLBACK_RVAS[1]}]",
            source,
        )
        self.assertIn(
            f"source? {GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID}", source
        )
        for target_id in GNU_HELLO_ORIGINAL_TLS_TARGET_IDS:
            self.assertIn(f"source? {target_id}", source)
        self.assertIn(
            f"pair.candidateLoaderZeroFill {GNU_HELLO_ACTIVE_BRIDGE_RVA}",
            source,
        )
        self.assertGreaterEqual(source.count("decide +kernel"), 10)

    def test_launch_prefix_tracks_the_checked_runtime_composition(self) -> None:
        acceptance = gnu_hello_acceptance_requirements_source(
            build_gnu_hello_acceptance_requirements_plan()
        )
        launch_prefix = next(
            line
            for line in acceptance.splitlines()
            if line.startswith("  launch_prefix :")
        )

        self.assertIn("MixedWorldLaunchPrefixCertificate", launch_prefix)
        self.assertIn(
            "(environment_compositions originalEnvironment "
            "candidateEnvironment environmentRefines).invariant",
            launch_prefix,
        )
        self.assertIn(
            "ExactOneToOneMixedExternalEnvironmentsRefine", launch_prefix
        )
        self.assertNotIn("MixedKernelChunkPaths", launch_prefix)
        self.assertNotIn("launch_chunk", acceptance)
        self.assertNotIn("roots_related", acceptance)

    def test_writer_emits_closed_launch_source_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = write_gnu_hello_launch_binding(root)
            source_path = (
                root / "StageA" / f"{plan.spec.module_name}.lean"
            )
            manifest_path = root / "gnu-hello-launch-binding.json"
            source = source_path.read_text(encoding="utf-8")
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertIn("generatedCanonicalRootFrameFacts", source)
        self.assertIn(
            "generatedReplayEstablishesRuntimePhaseStateFacts", source
        )
        self.assertIn("generatedLaunchWrapperRefinements", source)
        self.assertIn("generatedAcceptanceLaunchPrefix", source)
        self.assertTrue(payload["complete"])
        self.assertEqual(payload["status"], "source-ready")
        self.assertEqual(payload["failure_mode"], "fail-closed")
        self.assertEqual(payload["blocking_obligations"], [])
        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["executes_original_binary"])
        self.assertFalse(payload["executes_candidate_binary"])

    def test_rejects_noncanonical_reachability_namespace(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "reachability_namespace must be a Lean name"
        ):
            build_gnu_hello_launch_binding_plan(
                GnuHelloLaunchBindingSpec(
                    reachability_namespace="not a Lean namespace"
                )
            )


if __name__ == "__main__":
    unittest.main()
