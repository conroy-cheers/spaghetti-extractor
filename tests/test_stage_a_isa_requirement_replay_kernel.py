from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.executor import _run_lean_relational
from spaghetti_extractor.relational.lean.common import (
    _lean_byte_tree_definitions,
    _lean_pe,
)
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.stage_a_relational_support import _pe32_image


class StageAISARequirementReplayKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_exact_pe_replay_accepts_exact_bytes_and_rejects_tampering(self) -> None:
        image = _pe32_image(b"\x01\xd8\xc3")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image_path = root / "fixture.exe"
            image_path.write_bytes(image)
            parsed = _parse_stage_a_pe(image_path)
            lean_dir = root / "lean"
            stage_a = lean_dir / "StageA"
            stage_a.mkdir(parents=True)
            source_root = (
                Path(__file__).parents[1]
                / "src"
                / "spaghetti_extractor"
                / "lean"
                / "StageA"
            )
            for module in RELATIONAL_KERNEL_MODULES:
                shutil.copyfile(
                    source_root / f"{module}.lean",
                    stage_a / f"{module}.lean",
                )

            source = (
                "import StageA.RelationalISAQualification\n\n"
                "namespace StageA.ISARequirementReplayKernelTests\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\n"
                "set_option maxHeartbeats 0\n\n"
                + _lean_byte_tree_definitions("fixtureBytes", image)
                + "\n\n"
                + f"def fixturePe : PE32 := {_lean_pe(parsed, 'fixtureBytes')}\n\n"
                "def fixtureRegion : RegionRelation := {\n"
                "  id := 0\n"
                "  original := { start := 4096, size := 3 }\n"
                "  candidate := { start := 4096, size := 3 }\n"
                "  root := true\n"
                "  inputs := []\n"
                "  outputs := []\n"
                "  targets := []\n"
                "}\n\n"
                "def exactRequirement : ISARequirementRegion := {\n"
                "  nodeId := 0\n"
                "  occurrences := [\n"
                "    ⟨4096, 2, [0x01, 0xd8], .binary .add .register .register⟩,\n"
                "    ⟨4098, 1, [0xc3], .ret⟩\n"
                "  ]\n"
                "}\n\n"
                "def tamperedRequirement : ISARequirementRegion := {\n"
                "  nodeId := 0\n"
                "  occurrences := [\n"
                "    ⟨4096, 2, [0x01, 0xd9], .binary .add .register .register⟩,\n"
                "    ⟨4098, 1, [0xc3], .ret⟩\n"
                "  ]\n"
                "}\n\n"
                "example : exactRequirement.Replays fixturePe false fixtureRegion := by\n"
                "  unfold ISARequirementRegion.Replays\n"
                "  decide\n\n"
                "example : ¬ tamperedRequirement.Replays fixturePe false fixtureRegion := by\n"
                "  unfold ISARequirementRegion.Replays\n"
                "  decide\n\n"
                "def replayCertificate : ISARequirementReplayCertificate fixturePe "
                "fixturePe [fixtureRegion] := {\n"
                "  originalRequirements := [exactRequirement]\n"
                "  candidateRequirements := [exactRequirement]\n"
                "  originalReplayed := by\n"
                "    exact ⟨by unfold ISARequirementRegion.Replays; decide, True.intro⟩\n"
                "  candidateReplayed := by\n"
                "    exact ⟨by unfold ISARequirementRegion.Replays; decide, True.intro⟩\n"
                "}\n\n"
                "#print axioms replayCertificate\n\n"
                "end StageA.ISARequirementReplayKernelTests\n"
            )
            (stage_a / "ISARequirementReplayKernel.lean").write_text(
                source, encoding="utf-8"
            )
            result = _run_lean_relational(
                lean_dir,
                bundle="ISARequirementReplayKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
