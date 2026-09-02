from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.artifacts.build_formats import (
    CA_PHASE_MANIFEST_FORMAT,
    CA_RECEIPT_GATE_FORMAT,
)
from spaghetti_extractor.artifacts.build_manifest import (
    content_identity,
    phase_manifest,
    receipt_gate_manifest,
)


class BuildManifestTests(unittest.TestCase):
    def test_non_store_input_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Nix store path"):
                content_identity(path)

    def test_phase_and_gate_manifests_are_veto_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            closure_path = Path(temporary) / "closure.json"
            closure_path.write_text(
                json.dumps(
                    {
                        "format": (
                            "spaghetti-extractor-python-module-closure-v2"
                        ),
                        "files": [],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            artifact = {
                "format": "spaghetti-extractor-behavioral-c-package-v2",
                "status": "ready",
            }
            artifact_bytes = (json.dumps(artifact) + "\n").encode("utf-8")
            phase = phase_manifest(
                phase="fixture",
                content_addressed=True,
                artifact_name="artifact.json",
                artifact=artifact,
                artifact_bytes=artifact_bytes,
                inputs={},
                python_closure_manifest=closure_path,
            )
            gate = receipt_gate_manifest(
                gate="fixture",
                phase_role="developer",
                artifact_name="artifact.json",
                artifact=artifact,
                artifact_bytes=artifact_bytes,
                inputs={},
                python_closure_manifest=closure_path,
            )
        self.assertEqual(phase["format"], CA_PHASE_MANIFEST_FORMAT)
        self.assertTrue(phase["content_addressed"])
        self.assertEqual(gate["format"], CA_RECEIPT_GATE_FORMAT)
        self.assertEqual(gate["acceptance_authority"], "none")
        self.assertNotIn("acceptance_authority", phase)

    def test_malformed_python_closure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            closure_path = Path(temporary) / "closure.json"
            closure_path.write_text('{"format": "wrong", "files": []}\n')
            with self.assertRaisesRegex(ValueError, "closure manifest"):
                phase_manifest(
                    phase="fixture",
                    content_addressed=True,
                    artifact_name="artifact.json",
                    artifact={"format": "fixture", "status": "ready"},
                    artifact_bytes=b"{}\n",
                    inputs={},
                    python_closure_manifest=closure_path,
                )


if __name__ == "__main__":
    unittest.main()
