import json
import subprocess
import sys
import unittest
from pathlib import Path

from haloce_catalog.behavior import load_json_file
from haloce_catalog.roles import classify_pe
from haloce_catalog.target import load_target_config
from haloce_catalog.util import json_dumps, sha256_text


ROOT = Path(__file__).resolve().parents[1]
REFERENCE_DIR = ROOT / "tools" / "reference-games" / "wincr-3d-game"


class ReferenceGameFixtureTests(unittest.TestCase):
    def test_target_contract_and_expected_transcripts_are_stable(self):
        target = load_target_config(REFERENCE_DIR / "target.toml")
        contract = load_json_file(REFERENCE_DIR / "behavior-contract.json")
        orbit = load_json_file(REFERENCE_DIR / "expected" / "orbit-seed7-180.json")
        collect = load_json_file(REFERENCE_DIR / "expected" / "collect-seed11-150.json")
        collecting = load_json_file(REFERENCE_DIR / "expected" / "collect-seed2-64.json")
        dive = load_json_file(REFERENCE_DIR / "expected" / "dive-seed7-64.json")
        orbit_miss = load_json_file(REFERENCE_DIR / "expected" / "orbit-seed1-64.json")
        burnout = load_json_file(REFERENCE_DIR / "expected" / "burnout-seed7-360.json")
        aim_miss = load_json_file(REFERENCE_DIR / "expected" / "aim-miss-seed1-4.json")

        self.assertEqual(target.project_id, "wincr-3d-reference-game")
        self.assertEqual(classify_pe("bin/wincr-3d-game.exe", target).scope, "included")
        self.assertEqual(classify_pe("bin/wincr-3d-game-window.exe", target).scope, "excluded")
        self.assertEqual(target.trace_target("json-orbit").args, ("--json", "--scenario", "orbit", "--frames", "180", "--seed", "7"))
        self.assertEqual(target.trace_target("json-collect-hit").args, ("--json", "--scenario", "collect", "--frames", "64", "--seed", "2"))
        self.assertEqual(target.trace_target("json-dive").args, ("--json", "--scenario", "dive", "--frames", "64", "--seed", "7"))
        self.assertEqual(target.trace_target("json-orbit-miss").args, ("--json", "--scenario", "orbit", "--frames", "64", "--seed", "1"))
        self.assertEqual(target.trace_target("json-burnout").args, ("--json", "--scenario", "burnout", "--frames", "360", "--seed", "7"))
        self.assertEqual(target.trace_target("json-aim-miss").args, ("--json", "--scenario", "aim_miss", "--frames", "4", "--seed", "1"))
        self.assertTrue(target.trace_target("windowed-smoke").display_required)
        self.assertEqual(target.trace_target("windowed-smoke").executable, "wincr-3d-game-window.exe")
        self.assertEqual(target.trace_target("windowed-smoke").args[0], "--window-smoke")

        self.assertEqual(contract["format"], "wincr-behavior-contract-v1")
        self.assertEqual(contract["target"]["primary_binary"], "wincr-3d-game.exe")
        self.assertEqual(contract["target"]["window_fixture_binary"], "wincr-3d-game-window.exe")
        self.assertIn("--window-smoke", contract["command_line"]["usage"])
        self.assertIn("wrong_state_transition", target.required_mutation_kinds)
        self.assertIn("transcript", target.data_state_round_trip_kinds)

        self.assertEqual(orbit["format"], "wincr-3d-game-transcript-v1")
        self.assertEqual(orbit["final"]["score"], 25)
        self.assertEqual(orbit["aggregate_hash"], 2644509393)
        self.assertEqual(len(orbit["samples"]), 22)
        self.assertEqual(sha256_text(json_dumps(orbit)), "78789ddf24a989d923ec0c5abc7e94311905c9ab564a491f603c0df27d2ca123")

        self.assertEqual(collect["scenario"], "collect")
        self.assertEqual(collect["aggregate_hash"], 3824672047)
        self.assertEqual(len(collect["samples"]), 21)
        self.assertEqual(sha256_text(json_dumps(collect)), "a83d04f7ab0b0a7c6e76c209e3b34f060a239934ec5c2e52c30d2aed3e68d46d")

        self.assertEqual(collecting["scenario"], "collect")
        self.assertEqual(collecting["final"]["collected_mask"], 4)
        self.assertEqual(collecting["final"]["score"], 250)
        self.assertEqual(collecting["aggregate_hash"], 2571063141)
        self.assertEqual(len(collecting["samples"]), 19)
        self.assertEqual(sha256_text(json_dumps(collecting)), "d6b1567e4f394677fcf693b2812af5b81c83f65e6fe94cff3e10e203231ce214")

        self.assertEqual(dive["scenario"], "dive")
        self.assertEqual(dive["final"]["z"], 0)
        self.assertEqual(dive["final"]["health"], 755)
        self.assertEqual(dive["aggregate_hash"], 1350983531)
        self.assertEqual(len(dive["samples"]), 19)
        self.assertEqual(sha256_text(json_dumps(dive)), "c98a36b54a5dc04a6f9ebf0307a0ba4c5e6c9c180869dee18c23a8612e0cdc6d")

        self.assertEqual(orbit_miss["scenario"], "orbit")
        self.assertEqual(orbit_miss["seed"], 1)
        self.assertEqual(orbit_miss["final"]["score"], 25)
        self.assertEqual(orbit_miss["aggregate_hash"], 993443657)
        self.assertEqual(len(orbit_miss["samples"]), 19)
        self.assertEqual(sha256_text(json_dumps(orbit_miss)), "69c1710f5badbf3040cbcfca0487324457445ccfb7185bab4b0f624c988e4e4c")

        self.assertEqual(burnout["scenario"], "burnout")
        self.assertEqual(burnout["final"]["energy"], 0)
        self.assertEqual(burnout["final"]["score"], 0)
        self.assertEqual(burnout["aggregate_hash"], 1537148971)
        self.assertEqual(len(burnout["samples"]), 28)
        self.assertEqual(sha256_text(json_dumps(burnout)), "d092ed4425cd97dd04203f43613f31bdfab31dffa54ee9e7fce7dab7bd3af103")

        self.assertEqual(aim_miss["scenario"], "aim_miss")
        self.assertEqual(aim_miss["seed"], 1)
        self.assertEqual(aim_miss["frames"], 4)
        self.assertEqual(aim_miss["final"]["score"], 0)
        self.assertEqual(aim_miss["final"]["cooldown"], 0)
        self.assertEqual(aim_miss["aggregate_hash"], 4238318459)
        self.assertEqual(len(aim_miss["samples"]), 4)
        self.assertEqual(sha256_text(json_dumps(aim_miss)), "3389373087ad94ac2fac68d7460b44efbe00043747cd81d2f75ad1713fb6eeb6")

    def test_cleanroom_candidate_matches_expected_transcripts_and_mutants_diverge(self):
        contract = REFERENCE_DIR / "behavior-contract.json"
        candidate = REFERENCE_DIR / "cleanroom_candidate.py"
        cases = [
            ("orbit", "180", "7", REFERENCE_DIR / "expected" / "orbit-seed7-180.json"),
            ("collect", "150", "11", REFERENCE_DIR / "expected" / "collect-seed11-150.json"),
            ("collect", "64", "2", REFERENCE_DIR / "expected" / "collect-seed2-64.json"),
            ("dive", "64", "7", REFERENCE_DIR / "expected" / "dive-seed7-64.json"),
            ("orbit", "64", "1", REFERENCE_DIR / "expected" / "orbit-seed1-64.json"),
            ("burnout", "360", "7", REFERENCE_DIR / "expected" / "burnout-seed7-360.json"),
            ("aim_miss", "4", "1", REFERENCE_DIR / "expected" / "aim-miss-seed1-4.json"),
        ]

        for scenario, frames, seed, expected_path in cases:
            expected = load_json_file(expected_path)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(candidate),
                    "--contract",
                    str(contract),
                    "--json",
                    "--scenario",
                    scenario,
                    "--frames",
                    frames,
                    "--seed",
                    seed,
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertEqual(json.loads(completed.stdout), expected)

        expected = load_json_file(REFERENCE_DIR / "expected" / "orbit-seed7-180.json")
        for mutant in [
            "wrong_state_transition",
            "bad_projection",
            "bad_input_schedule",
            "bad_frame_hash",
            "bad_target_generation",
        ]:
            completed = subprocess.run(
                [
                    sys.executable,
                    str(candidate),
                    "--contract",
                    str(contract),
                    "--json",
                    "--scenario",
                    "orbit",
                    "--frames",
                    "180",
                    "--seed",
                    "7",
                    "--mutant",
                    mutant,
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertNotEqual(json.loads(completed.stdout), expected, mutant)


if __name__ == "__main__":
    unittest.main()
