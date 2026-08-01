import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class GnuHelloNativeSourceStaticAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).parents[1]
        self.driver = (
            self.repo / "nix" / "gnu-hello-native-source-static-authority.py"
        )
        self.lane = self.repo / "nix" / "gnu-hello-roundtrip.nix"
        self.flake = self.repo / "flake.nix"

    @staticmethod
    def _inventory(candidate: bytes) -> dict[str, object]:
        return {
            "format": "stage-a-interpreter-kernel-data-inventory-v9",
            "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
            "candidate_bytes": len(candidate),
            "counts": {
                "relocation_packs": 2,
                "relocation_blocks": 3,
            },
            "modules": [
                {"name": "GeneratedInterpreterKernelDataBase",
                 "role": "candidate-pe-binding"},
                {"name": "GeneratedInterpreterKernelDataRelocationBundle",
                 "role": "candidate-relocation-bundle"},
            ],
        }

    def _run(
        self, root: Path, candidate_bytes: bytes, inventory: dict[str, object]
    ) -> subprocess.CompletedProcess[str]:
        candidate = root / "candidate.exe"
        inventory_path = root / "module-inventory.json"
        out = root / "out"
        candidate.write_bytes(candidate_bytes)
        inventory_path.write_text(
            json.dumps(inventory), encoding="utf-8"
        )
        return subprocess.run(
            [
                sys.executable,
                str(self.driver),
                "--candidate",
                str(candidate),
                "--kernel-data-inventory",
                str(inventory_path),
                "--out",
                str(out),
            ],
            text=True,
            capture_output=True,
        )

    def test_emits_exact_parameterized_static_authority(self) -> None:
        candidate = b"MZ" + bytes(range(1, 65))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self._run(root, candidate, self._inventory(candidate))
            self.assertEqual(result.returncode, 0, result.stderr)

            source = (
                root
                / "out"
                / "StageA"
                / "GeneratedGnuHelloNativeSourceCandidateStaticAuthority.lean"
            ).read_text(encoding="ascii")
            manifest = json.loads(
                (root / "out" / "phase-manifest.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertIn(hashlib.sha256(candidate).hexdigest(), source)
        self.assertIn(f"byteLength := {len(candidate)}", source)
        self.assertIn("candidateParsed", source)
        self.assertIn("generatedInterpreterKernelRelocationsParsed", source)
        self.assertIn("preferredBaseLoaderImageValid", source)
        self.assertIn("(environment : NativeWorldEnvironment)", source)
        self.assertIn("(indirectTargetsValid :", source)
        self.assertNotIn("def generatedEnvironment", source)
        self.assertFalse(
            manifest["trust"]["indirect_target_completeness_proved"]
        )
        self.assertFalse(manifest["trust"]["whole_program_acceptance_authority"])
        self.assertTrue(manifest["trust"]["environment_parameterized"])

    def test_rejects_candidate_identity_mismatch(self) -> None:
        candidate = b"MZ-candidate"
        inventory = self._inventory(candidate)
        inventory["candidate_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            result = self._run(Path(temporary), candidate, inventory)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binds a different candidate", result.stderr)

    def test_nix_lane_uses_composed_source_candidate(self) -> None:
        lane = self.lane.read_text(encoding="utf-8")
        start = lane.index("sourceCandidateKernelDataLean =")
        end = lane.index("sourceCompilationAttestation =", start)
        static_lane = lane[start:end]

        self.assertIn(
            "--candidate ${sourceCandidate}/candidate.exe", static_lane
        )
        self.assertIn("--linker-map ${sourceCandidate}/payload.map", static_lane)
        self.assertNotIn("--candidate ${candidate}/candidate.exe", static_lane)
        self.assertNotIn("/payload.exe", static_lane)
        self.assertIn("sourceCandidateStaticAuthorityProof", static_lane)

        flake = self.flake.read_text(encoding="utf-8")
        for name in (
            "stage-a-gnu-hello-native-source-candidate-kernel-data",
            "stage-a-gnu-hello-native-source-candidate-static-authority",
            "stage-a-gnu-hello-native-source-candidate-static-authority-proof-sources",
            "stage-a-gnu-hello-native-source-candidate-static-authority-proof",
        ):
            self.assertIn(name, flake)


if __name__ == "__main__":
    unittest.main()
