from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_ROOT = Path(__file__).parents[1]
_DRIVER = _ROOT / "nix/gnu-hello-roundtrip-driver.py"
_NIX = _ROOT / "nix/gnu-hello-roundtrip.nix"
_CANDIDATE_ROOT = Path(
    "/nix/store/hwabmhf3h9ps6gcsxnji81pisdij1lg9-"
    "stage-b-gnu-hello-roundtrip-candidate"
)
_CANDIDATE = _CANDIDATE_ROOT / "candidate.exe"
_BUILD_MANIFEST = _CANDIDATE_ROOT / "interpreter-native-build-manifest.json"
_ENGINE_PLAN = Path(
    "/nix/store/1g0649s09cyqwbj5fdx81v0vq79dcic8-"
    "stage-b-gnu-hello-roundtrip-native-engine/native-engine-plan.json"
)
_CANDIDATE_SHA256 = (
    "953a4e7ea653785dd89d74fa629dc8941657cf1b40faabdb475ccc7740ae6362"
)


@unittest.skipUnless(
    _CANDIDATE.is_file() and _BUILD_MANIFEST.is_file() and _ENGINE_PLAN.is_file(),
    "pinned GNU hello candidate artifacts are not in the Nix store",
)
class StageAGnuRoundtripX87ReplayBridgeTargetWiringTests(unittest.TestCase):
    def test_driver_emits_all_exact_target_terms_and_frame_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            subprocess.run(
                [
                    sys.executable,
                    str(_DRIVER),
                    "x87-replay-bridge-target-sources",
                    "--candidate",
                    str(_CANDIDATE),
                    "--build-manifest",
                    str(_BUILD_MANIFEST),
                    "--native-engine-plan",
                    str(_ENGINE_PLAN),
                    "--candidate-data-module",
                    "GeneratedInterpreterKernelDataBase",
                    "--pack-size",
                    "32",
                    "--out",
                    str(output),
                ],
                cwd=_ROOT,
                check=True,
            )

            manifest = json.loads(
                (output / "phase-manifest.json").read_text(encoding="utf-8")
            )
            plan = json.loads(
                (output / "x87-replay-bridge-target-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            bundle = (
                output
                / "StageA/GeneratedRelationalInterpreterX87ReplayBridgeTarget.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["status"], "source-ready")
        self.assertEqual(manifest["candidate_sha256"], _CANDIDATE_SHA256)
        self.assertEqual(
            manifest["counts"],
            {
                "descriptors": 313,
                "dynamic_frame_mappings": 313,
                "finite_targets": 313,
                "runtime_refinement_goals": 313,
                "static_frontiers": 0,
            },
        )
        self.assertEqual(len(plan["table"]["frame_mappings"]), 313)
        self.assertIsNone(plan["requested_call_site_rva"])
        self.assertEqual(plan["table"]["call_site_rva"], 0x48F20)
        self.assertEqual(
            plan["table"]["frame_mappings"][0]["instruction_rva"],
            0x4D000,
        )
        self.assertIn(_CANDIDATE_SHA256, bundle)
        self.assertIn("generatedX87ReplayBridgeTargetBinding0000", bundle)
        self.assertIn("generatedX87ReplayBridgeTargetBinding0312", bundle)
        self.assertIn(
            "generatedX87ReplayBridgeTargetBinding0312RuntimeGoal",
            bundle,
        )
        self.assertIn("generatedX87ReplayBridgeTargetInventory", bundle)

    def test_gnu_proof_source_aggregate_includes_bridge_terms(self) -> None:
        source = _NIX.read_text(encoding="utf-8")

        self.assertIn("x87ReplayBridgeTargetLean = mkPhase", source)
        self.assertIn("--source ${x87ReplayBridgeTargetLean}", source)
        self.assertIn(
            "--target GeneratedRelationalInterpreterX87ReplayBridgeTarget",
            source,
        )
        self.assertIn("x87ReplayBridgeTargetProofSources", source)


if __name__ == "__main__":
    unittest.main()
