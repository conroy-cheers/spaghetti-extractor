from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)


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


_FIXTURE = r'''import StageA.RelationalOriginalReachableBoundaryAdmissibility

namespace StageA.OriginalReachableBoundaryAdmissibilityKernel

open StageA.Formal StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.OriginalReachableBoundaryAdmissibility

theorem releaseEvidenceClosesBothSides
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent)
    (effect : contract.worldEffect = .dynamicRangeRelease 0)
    (memory : CheckedPairedMachineMemoryInput context contract original candidate)
    (release : CheckedPairedDynamicRangeReleaseInput 0 original.arguments
      candidate.arguments original.world candidate.world) :
    MachineResponseInputAdmissible false context contract original /\
      MachineResponseInputAdmissible true context contract candidate := by
  apply CheckedPairedMachineResponseInput.admissible
  refine { memory, world := ?_ }
  simpa [CheckedPairedMachineWorldInput, effect] using release

theorem callbackEvidenceClosesBothSides
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEvent)
    (effect : contract.worldEffect = .callbackRegistration 1)
    (memory : CheckedPairedMachineMemoryInput context contract original candidate)
    (callback : CheckedPairedCallbackRegistrationInput context 1
      original.arguments candidate.arguments) :
    MachineResponseInputAdmissible false context contract original /\
      MachineResponseInputAdmissible true context contract candidate := by
  apply CheckedPairedMachineResponseInput.admissible
  refine { memory, world := ?_ }
  simpa [CheckedPairedMachineWorldInput, effect] using callback

def ordinaryProviderConstructsAuthority
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}
    {inventory :
      StageA.Relational.OriginalCombinedExecutionInvariant.OriginalCombinedExecutionInventory
        program originalContext}
    {sites : List OpaqueLockstepCallSite}
    (provider : CheckedOriginalCombinedReachableBoundaryInputs context program
      originalContext inventory sites) :
    CheckedOriginalCombinedReachableBoundaryDomain context program originalContext
      inventory sites :=
  provider.toDomain

def protocolProviderConstructsAuthority
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNestedNativeWorldProgram}
    {mixed :
      StageA.Relational.InterpreterMixedContext.MixedRelationContract}
    {frames :
      StageA.Relational.InterpreterMixedEnvironment.MixedNestedExternalFrameContract}
    {originalContext :
      StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext}
    {inventory :
      StageA.Relational.OriginalCombinedExecutionInvariant.OriginalCombinedExecutionInventory
        program originalContext}
    (provider : CheckedOriginalCombinedReachableProtocolInputs context program
      candidate mixed frames originalContext inventory) :
    CheckedReachableWorldNativeProtocolBoundaryDomain context program candidate
      mixed frames originalContext inventory :=
  provider.toDomain

#print axioms releaseEvidenceClosesBothSides
#print axioms callbackEvidenceClosesBothSides
#print axioms ordinaryProviderConstructsAuthority
#print axioms protocolProviderConstructsAuthority

end StageA.OriginalReachableBoundaryAdmissibilityKernel
'''


class StageAOriginalReachableBoundaryAdmissibilityKernelTests(unittest.TestCase):
    def test_generic_reachable_boundary_admissibility_compiles(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalReachableBoundaryAdmissibility",
            )
            (stage_a / "OriginalReachableBoundaryAdmissibilityKernel.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            checked = _run_lean_relational(
                root, bundle="OriginalReachableBoundaryAdmissibilityKernel"
            )

        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {name.strip() for name in report.split(",") if name.strip()}
            self.assertLessEqual(
                used, {"propext", "Classical.choice", "Quot.sound"}, report
            )


if __name__ == "__main__":
    unittest.main()
