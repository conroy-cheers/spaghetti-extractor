from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import (
    _run_lean_relational,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


class StageARuntimeValueCarryKernelTests(unittest.TestCase):
    def test_checked_route_covers_every_tracked_predecessor(self) -> None:
        source_root = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "spaghetti_extractor"
            / "lean"
            / "StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary) / "lean"
            stage_a = lean_dir / "StageA"
            stage_a.mkdir(parents=True)
            _copy_module_closure(
                source_root, stage_a, "RelationalRuntimeValueCarry"
            )
            (stage_a / "RuntimeValueCarryKernel.lean").write_text(
                """import StageA.RelationalRuntimeValueCarry

namespace StageA.Relational.RuntimeValueCarry

def exampleGraph : CutpointGraph := {
  targetIds := [0, 1, 2, 3]
  edges := [
    { edgeId := 10, sourceTargetId := 0, targetTargetId := 1 },
    { edgeId := 11, sourceTargetId := 1, targetTargetId := 2 },
    { edgeId := 12, sourceTargetId := 2, targetTargetId := 3 }
  ]
}

def exampleRoute : Route := {
  originTargetId := 3
  locations := [
    .inRegister .ebx,
    .inFrameWord .esp (.add 32)
  ]
  facts := [
    { targetId := 1, locationId := 0 },
    { targetId := 2, locationId := 0 },
    { targetId := 3, locationId := 1 }
  ]
  transfers := [
    {
      edgeId := 10
      sourceTargetId := 0
      targetTargetId := 1
      kind := .finiteOriginCallResult
      sourceLocationId := none
      targetLocationId := 0
    },
    {
      edgeId := 11
      sourceTargetId := 1
      targetTargetId := 2
      kind := .decodedPreserve
      sourceLocationId := some 0
      targetLocationId := 0
    },
    {
      edgeId := 12
      sourceTargetId := 2
      targetTargetId := 3
      kind := .decodedRegisterToFrame
      sourceLocationId := some 0
      targetLocationId := 1
    }
  ]
  targetFact := { targetId := 3, locationId := 1 }
}

def missingIncomingRoute : Route :=
  { exampleRoute with transfers := exampleRoute.transfers.dropLast }

example : exampleGraph.checked = true := by native_decide
example : exampleRoute.incomingCovered exampleGraph = true := by native_decide
example : missingIncomingRoute.incomingCovered exampleGraph = false := by
  native_decide

example
    (context :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext)
    (checked : exampleRoute.checked context exampleGraph = true) :
    exists transfer, transfer ∈ exampleRoute.transfers /\\
      transfer.edgeId = 12 /\\ transfer.sourceTargetId = 2 /\\
      transfer.targetTargetId = 3 := by
  exact exampleRoute.transfer_exists_for_incoming context exampleGraph checked
    { edgeId := 12, sourceTargetId := 2, targetTargetId := 3 }
    (by simp [exampleGraph]) (by native_decide)

end StageA.Relational.RuntimeValueCarry
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(
                lean_dir, bundle="RuntimeValueCarryKernel"
            )

        self.assertEqual(result["status"], "checked", result)


if __name__ == "__main__":
    unittest.main()
