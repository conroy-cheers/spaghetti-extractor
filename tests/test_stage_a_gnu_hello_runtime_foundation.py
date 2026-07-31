from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.gnu_hello_runtime_foundation import (
    GNU_HELLO_RUNTIME_FOUNDATION_MANIFEST,
    GnuHelloRuntimeFoundationSpec,
    build_gnu_hello_runtime_foundation_plan,
    gnu_hello_runtime_foundation_source,
    write_gnu_hello_runtime_foundation,
)


class StageAGnuHelloRuntimeFoundationTests(unittest.TestCase):
    def test_emits_exact_frames_and_concrete_launch_witness(self) -> None:
        source = gnu_hello_runtime_foundation_source(
            build_gnu_hello_runtime_foundation_plan()
        )

        for declaration in (
            "generatedContinuationTargetsRelated",
            "generatedCallbackReturnAddressesRelated",
            "generatedExternalFrames",
            "generatedNestedExternalFrames",
            "generatedExternalFramesCallbacksEmpty",
            "generatedLaunchImportAddresses",
            "generatedLaunchWorld",
            "generatedLaunchRangeWrites",
            "generatedOriginalLaunchMemory",
            "generatedCandidateLaunchMemory",
            "generatedLaunchWorldValid",
            "generatedLaunchWorldShape",
            "generatedRangeMemoryChecked",
            "generatedImportMemoryChecked",
            "generatedOriginalImageMemory",
            "generatedCandidateImageMemory",
            "generatedConcreteLaunchPair",
            "generatedLaunchRelated",
            "generatedLaunchRealizable",
        ):
            self.assertIn(declaration, source)
        self.assertIn("exactMixedExternalFrameContract", source)
        self.assertIn("exactMixedNestedExternalFrameContract", source)
        self.assertIn(
            "canonicalMixedRangeMemoryRelated_of_exact_checked", source
        )
        self.assertIn(
            "canonicalMixedImportAddressesMemoryHold_of_checked", source
        )
        self.assertIn("mixedLaunchRealizable_of_related", source)
        self.assertIn("PreferredBaseImageMemory.afterMixedLaunchRangeWrites", source)
        self.assertNotIn("GeneratedRootsRelatedEvidence", source)
        self.assertNotIn("generatedRootsRelated", source)
        self.assertNotIn("generatedLaunchRealizableFromRoot", source)
        self.assertNotIn(": True", source)
        launch_realizable_signature = source.split(
            "def generatedLaunchRealizable", 1
        )[1].split(":=", 1)[0]
        for forbidden in (
            "launchRelated",
            "rootRelated",
            "runtimeRelated",
            "replayed",
            "path",
            "postState",
        ):
            self.assertNotIn(forbidden, launch_realizable_signature)
        for forbidden in ("axiom", "sorry", "native_decide", "unsafe"):
            self.assertIsNone(re.search(rf"\b{forbidden}\b", source), forbidden)

    def test_manifest_has_no_launch_blockers_or_delegated_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = write_gnu_hello_runtime_foundation(root)
            payload = json.loads(
                (root / GNU_HELLO_RUNTIME_FOUNDATION_MANIFEST).read_text(
                    encoding="utf-8"
                )
            )
            source = (
                root / "StageA" / f"{plan.spec.module_name}.lean"
            ).read_text(encoding="utf-8")

        self.assertTrue(payload["complete"])
        self.assertEqual(payload["status"], "source-ready")
        self.assertFalse(payload["acceptance_authority"])
        self.assertFalse(payload["report_authority"])
        self.assertEqual(payload["failure_mode"], "fail-closed")
        self.assertEqual(payload["blocking_obligations"], [])
        self.assertEqual(
            payload["constructed_terms"]["launch_realizable"],
            "generatedLaunchRealizable",
        )
        self.assertEqual(
            payload["gnu_profile"]["parent_external_callbacks"],
            "must-be-empty",
        )
        self.assertEqual(
            payload["gnu_profile"]["root_bootstrap_relation"],
            "launch",
        )
        self.assertNotIn(
            "pre_wrapper_root_requires_runtime_engine_state",
            json.dumps(payload),
        )
        self.assertNotIn("roots_related", json.dumps(payload))
        self.assertNotIn("delegated", json.dumps(payload))
        self.assertNotIn("incomplete", json.dumps(payload))
        self.assertNotIn(
            "launch_chunk_requires_original_stutter",
            json.dumps(payload),
        )
        self.assertIn("generatedExternalFrames", source)

    def test_rejects_noncanonical_module_name(self) -> None:
        with self.assertRaises(StageAInputError):
            build_gnu_hello_runtime_foundation_plan(
                GnuHelloRuntimeFoundationSpec(module_name="bad/name")
            )


if __name__ == "__main__":
    unittest.main()
