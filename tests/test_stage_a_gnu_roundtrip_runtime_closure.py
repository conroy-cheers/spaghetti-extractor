from __future__ import annotations

import unittest
from pathlib import Path


class StageAGnuRoundtripRuntimeClosureTests(unittest.TestCase):
    def test_candidate_phases_use_only_the_explicit_runtime_closure(self) -> None:
        lane = (
            Path(__file__).resolve().parents[1] / "nix" / "gnu-hello-roundtrip.nix"
        ).read_text(encoding="utf-8")
        runtime_start = lane.index("runtimePythonSource =")
        runtime_end = lane.index("stackDynamicProofPythonFiles =", runtime_start)
        runtime = lane[runtime_start:runtime_end]

        self.assertIn("stage_b_interpreter_native_build.py", runtime)
        self.assertIn("artifact_formats.py", runtime)
        self.assertIn("relational/definedness.py", runtime)
        self.assertIn("spaghetti_extractor/_contract_tools", runtime)
        self.assertNotIn("relational/lean", runtime)
        self.assertNotIn("spaghetti_extractor/lean", runtime)
        self.assertNotIn("relational/engine_segments.py", runtime)
        self.assertNotIn("cli.py", runtime)

        for phase in (
            "staticExport",
            "interpreter",
            "nativeEngine",
            "nativeRuntime",
            "candidate",
        ):
            start = lane.index(f"{phase} = mkPhase")
            end = lane.index(";", start) + 1
            source = lane[start:end]
            self.assertIn("${runtimeDriver}", source)
            self.assertNotIn("${driver}", source)
            self.assertNotIn("-m spaghetti_extractor", source)


if __name__ == "__main__":
    unittest.main()
