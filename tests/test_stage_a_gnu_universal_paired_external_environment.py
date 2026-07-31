from __future__ import annotations

import unittest
from pathlib import Path


class StageAGnuUniversalPairedExternalEnvironmentTests(unittest.TestCase):
    def test_gnu_source_phase_is_isolated_and_fail_closed(self) -> None:
        root = Path(__file__).parents[1]
        nix = (root / "nix/gnu-hello-roundtrip.nix").read_text(
            encoding="utf-8"
        )
        flake = (root / "flake.nix").read_text(encoding="utf-8")
        driver = (
            root / "nix/gnu-hello-universal-paired-external-environment.py"
        ).read_text(encoding="utf-8")

        attribute = (
            "stage-a-gnu-hello-roundtrip-"
            "universal-paired-external-environment-source"
        )
        self.assertIn(attribute, flake)
        self.assertIn(
            "universalPairedExternalEnvironmentLean = mkPhase", nix
        )
        self.assertIn(
            "--source ${universalPairedExternalEnvironmentLean}", nix
        )
        self.assertIn(
            "each_returning_site_has_a_universally_sound_response_relation",
            nix,
        )
        self.assertIn(
            "GeneratedGnuHelloExternalCandidatePE", driver
        )
        self.assertIn(
            "GeneratedGnuHelloUniversalPairedExternalEnvironment", driver
        )
        self.assertNotIn("subprocess", driver)
        self.assertNotIn("wine", driver.lower())
        self.assertNotIn("environment :=", driver)

    def test_gnu_phase_keeps_protocol_refinement_explicit(self) -> None:
        root = Path(__file__).parents[1]
        emitter = (
            root
            / "src/spaghetti_extractor/relational/lean/"
            "universal_paired_external_environment.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "protocol_and_callback_actions_have_separate_nested_frame_refinement",
            emitter,
        )
        self.assertIn('"mixed_component_composition"', emitter)
        self.assertIn('"proof_authority": False', emitter)


if __name__ == "__main__":
    unittest.main()
