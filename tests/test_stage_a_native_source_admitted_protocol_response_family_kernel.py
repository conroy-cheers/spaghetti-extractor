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


_FIXTURE = r'''import StageA.RelationalNativeSourceAdmittedProtocolResponseFamily

namespace StageA.NativeSourceAdmittedProtocolResponseFamilyKernel

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NativeSource
open StageA.Relational.StaticMachineImportContracts

def returningSignature : StaticMachineImportSignature := {
  id := 1
  imported := { dll := [114], name := .symbol [1] }
  abi := .cdecl
  arity := .fixed 0
  memoryEffect := .none
  worldEffect := .none
}

def returningContract : MachineImportCallContract :=
  returningSignature.contract 0

example : MachineExternalResponseMode.synchronous.matches returningSignature
    returningContract = true := by native_decide

def registrationSignature : StaticMachineImportSignature := {
  id := 2
  imported := { dll := [114], name := .symbol [2] }
  abi := .cdecl
  arity := .fixed 1
  memoryEffect := .none
  worldEffect := .callbackRegistration 0
  callbackMode := .registration
}

def registrationContract : MachineImportCallContract :=
  registrationSignature.contract 1

example : (MachineExternalResponseMode.registration 0).matches
    registrationSignature registrationContract = true := by native_decide

example : MachineExternalResponseMode.synchronous.matches
    registrationSignature registrationContract = false := by native_decide

def protocolSignature : StaticMachineImportSignature := {
  id := 3
  imported := { dll := [114], name := .symbol [3] }
  abi := .cdecl
  arity := .fixed 0
  disposition := .protocol
  memoryEffect := .relationalState
  worldEffect := .none
  callbackMode := .nestedFrames
}

def protocolContract : MachineImportCallContract :=
  protocolSignature.contract 0

example : MachineExternalResponseMode.nestedFrames.matches protocolSignature
    protocolContract = true := by native_decide

example : MachineExternalResponseMode.synchronous.matches protocolSignature
    protocolContract = false := by native_decide

def orphanClassification : CheckedMachineExternalSite := {
  boundaryId := 99
  signatureId := 99
  mode := .nestedFrames
}

example : checkedMachineExternalSitesValid [] [] [] [orphanClassification] =
    false := by native_decide

example {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : ExactNestedNativeWorldProgram}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {sourceEnvironment : WorldExternalEnvironment}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (schedule : CheckedWorldNativeProtocolResponseSchedule context program
      candidate classified ordinarySites sourceEnvironment mixed frames)
    (request : WorldNativeProtocolBoundaryRequest candidate)
    (admitted : schedule.protocolBoundaryDomain.Admits request) :
    MixedNestedExternalEnvironmentActionsRelated candidate mixed frames
      (program.protocolEnvironment.action request.suspension.request)
      request.boundary.action :=
  schedule.nestedRefines request admitted

example (compilation : ExactNativeCompilation)
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) :
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment).project.worldProgram.environment =
        sourceEnvironment.ordinary := by
  rfl

example (compilation : ExactNativeCompilation)
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) :
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment).project.worldProgram.protocolEnvironment =
        sourceEnvironment.protocol := by
  rfl

example {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    {family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames}
    (completion : family.Completion) :
    exists sourceEnvironment nativeEnvironment,
      family.Related sourceEnvironment nativeEnvironment :=
  completion.realizable

#print axioms MachineExternalResponseMode.matches
#print axioms machineExternalSitesCoverProgram
#print axioms CheckedWorldNativeProtocolResponseSchedule.registrationResponse
#print axioms CheckedWorldNativeAdmittedProtocolResponseFamily.Completion.realizable

end StageA.NativeSourceAdmittedProtocolResponseFamilyKernel
'''


class StageANativeSourceAdmittedProtocolResponseFamilyKernelTests(
    unittest.TestCase
):
    def test_kernel_compiles_and_fails_closed_on_unknown_shapes(self) -> None:
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
                "RelationalNativeSourceAdmittedProtocolResponseFamily",
            )
            (stage_a / "NativeSourceAdmittedProtocolResponseFamilyKernel.lean").write_text(
                _FIXTURE, encoding="ascii"
            )
            checked = _run_lean_relational(
                root, bundle="NativeSourceAdmittedProtocolResponseFamilyKernel"
            )
        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 4, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",") if name.strip()}
                <= {"propext", "Classical.choice", "Quot.sound"}
                for inventory in inventories
            ),
            output,
        )


if __name__ == "__main__":
    unittest.main()
