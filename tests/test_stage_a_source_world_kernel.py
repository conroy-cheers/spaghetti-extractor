from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageASourceWorldKernelTests(unittest.TestCase):
    def test_one_sided_source_world_composition_and_raw_lift_are_checked(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalSourceRawEIP")
            (stage_a / "SourceWorldKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceWorldKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn("ChunkComposition.chunksRefine", output)
        self.assertIn("chunkedSimulation_rawEipLeft_of_logical", output)
        self.assertIn("runRelatedSteps_rawEip_of_logical", output)

        raw_eip_module = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalSourceRawEIP.lean"
        ).read_text(encoding="utf-8")
        self.assertIn("domain.holds logical", raw_eip_module)
        self.assertIn("domain.stepClosed logical member", raw_eip_module)


_KERNEL_FIXTURE = r"""import StageA.RelationalSourceRawEIP

namespace StageA.SourceWorldKernelFixture

open StageA.Relational
open StageA.Relational.SourceWorld

example {program : DecodedWorldProgram} {root : WorldExecution}
    (domain : CheckedExecutionDomain program root) (execution : WorldExecution)
    (member : domain.holds execution) :
    ExecutionsMatch domain execution (.ofWorldExecution execution) := by
  exact ExecutionsMatch.exact domain execution member

example {original : DecodedWorldProgram} {kernel : Kernel}
    {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent original kernel
      root domain := by
  exact composition.chunksRefine

example {original : DecodedWorldProgram} {kernel : Kernel}
    {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain)
    (closed : RawEipLeftStepClosed original root domain) :
    ExactRawOriginalPESourceKernelObservationallyEquivalent original kernel
      root domain := by
  exact chunkedSimulation_rawEipLeft_of_logical composition closed

example {original : DecodedWorldProgram} {root logical : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    {raw : RawEipWorldExecution}
    (closed : RawEipLeftStepClosed original root domain)
    (member : domain.holds logical)
    (current : logical.ConcretizesToRawEip original raw) :
    exists rawNext,
      (original.pe32TransitionSystem.step logical).next.ConcretizesToRawEip
        original rawNext := by
  exact closed logical raw member current

example {original : DecodedWorldProgram} (reason : ExecutionBlock) :
    Not (worldRelationalObservationsRelated original.context
      (some (.proofBlocked reason)) (some (.proofBlocked reason))) := by
  simp [worldRelationalObservationsRelated]

#print axioms Execution.toWorldExecution_ofWorldExecution
#print axioms NonemptyKernelPath.toRelatedPath
#print axioms ChunkComposition.chunksRefine
#print axioms runRelatedSteps_rawEip_of_logical
#print axioms chunkedSimulation_rawEipLeft_of_logical

end StageA.SourceWorldKernelFixture
"""


if __name__ == "__main__":
    unittest.main()
