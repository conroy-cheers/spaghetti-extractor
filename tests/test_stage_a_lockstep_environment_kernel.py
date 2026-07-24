from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.schema import RELATIONAL_KERNEL_MODULES


class StageALockstepEnvironmentKernelTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
    def test_prototype_free_lockstep_environment_is_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        source = (source_root / "RelationalLockstepEnvironment.lean").read_text(
            encoding="utf-8"
        )
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            for module in (*RELATIONAL_KERNEL_MODULES, "RelationalLockstepEnvironment"):
                shutil.copyfile(source_root / f"{module}.lean", stage_a / f"{module}.lean")
            (stage_a / "LockstepEnvironmentKernel.lean").write_text(
                """import StageA.RelationalLockstepEnvironment

namespace StageA.LockstepEnvironmentKernel
open StageA.Formal StageA.Relational

example (context : StaticProofContext) (site : FullMachineLockstepCallSite)
    (original candidate : WorldExternalEvent)
    (related : FullMachineLockstepBoundaryRelated context site original candidate) :
    original.imported = candidate.imported :=
  related.import_identity context site

example (context : StaticProofContext) (sites : List FullMachineLockstepCallSite)
    (original candidate : WorldExternalEnvironment)
    (refines : FullMachineLockstepEnvironmentsRefined context sites original candidate)
    (site : FullMachineLockstepCallSite) (member : site \u2208 sites) :
    FullMachineLockstepEnvironmentRefinesAt context site original candidate :=
  refines.at context sites original candidate site member

example (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment)
    (checked : CheckedExactLockstepExternalReturn context site contract
      original candidate) :
    ExternalEnvironmentRefinesAt context site contract original candidate :=
  externalEnvironmentRefinesAt_of_checkedExactLockstep context site contract
    original candidate checked

example (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment)
    (checked : CheckedExactLockstepExternalReturn context site contract
      original candidate)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ExternalCallBoundaryRelated context site contract
      originalEvent candidateEvent) :
    let originalResult := original.result eventIndex originalEvent
    let candidateResult := candidate.result eventIndex candidateEvent
    originalResult.world = candidateResult.world ∧
      machineCallResultConforms false context contract originalEvent originalResult ∧
      machineCallResultConforms true context contract candidateEvent candidateResult ∧
      machineCallResultRegistersRelated context originalResult.world contract
        originalEvent.arguments originalResult.state candidateResult.state = true ∧
      StateRel context originalResult.world site.targetInvariant
        originalResult.state candidateResult.state ∧
      ExternalRuntimeFramesPreserved originalEvent candidateEvent
        originalResult candidateResult :=
  externalCallResultsRelated context site contract original candidate
    (externalEnvironmentRefinesAt_of_checkedExactLockstep context site contract
      original candidate checked)
    checked.returns eventIndex originalEvent candidateEvent boundary

#print axioms fullMachineLockstepResultsRelated
#print axioms FullMachineLockstepBoundaryRelated.import_identity
#print axioms externalEnvironmentRefinesAt_of_checkedExactLockstep

end StageA.LockstepEnvironmentKernel
""",
                encoding="utf-8",
            )
            result = _run_lean_relational(root, bundle="LockstepEnvironmentKernel")

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])


if __name__ == "__main__":
    unittest.main()
