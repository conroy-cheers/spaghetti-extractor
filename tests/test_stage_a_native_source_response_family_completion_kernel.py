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


_FIXTURE = r'''import StageA.RelationalNativeSourceResponseRequirements

namespace StageA.NativeSourceResponseFamilyCompletionKernel

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.NativeSource

def argument : Word := BitVec.ofNat 32 1

example : Not (DynamicRangeReleaseInputAdmissible false 0 [argument]
    RelationalWorld.empty) := by
  simp [DynamicRangeReleaseInputAdmissible, argument, RelationalWorld.empty]

example (context : StaticProofContext) :
    externalCallArgumentsRelated context RelationalWorld.empty [argument]
      [argument] = true :=
  exactArgumentsDoNotProveDynamicRangeOwnership context argument

example : forall after,
    Not (dynamicRangeReleaseHolds false 0 [argument]
      RelationalWorld.empty after) := by
  apply noDynamicRangeReleaseWithoutOwnedArgument false 0 [argument]
    RelationalWorld.empty argument
  · rfl
  · native_decide
  · intro range member
    change range ∈ ([] : List DynamicAddressRangePair) at member
    exact False.elim (List.not_mem_nil member)

example (context : StaticProofContext) (before : RelationalWorld)
    (unchecked : forall callback : RegisteredCallbackPair,
      callback.originalAddress = argument -> callback.valid context ≠ true) :
    forall after, Not (callbackRegistrationHolds false context 0 [argument]
      before after) := by
  exact noCallbackRegistrationWithoutCheckedTarget false context 0 [argument]
    before argument rfl unchecked

example {candidate : Bool} {context : StaticProofContext}
    {contract : MachineImportCallContract} {event : WorldExternalEvent}
    {result : WorldExternalResult}
    (conforms : machineCallResultConforms candidate context contract event result) :
    MachineWorldEffectInputAdmissible candidate context contract.worldEffect
      event.arguments event.world :=
  machineCallResultConforms_inputAdmissible candidate context contract event result
    conforms

def releaseContract : MachineImportCallContract := {
  id := 7
  imported := { dll := [], name := .symbol [] }
  stackArgumentOffsets := [0]
  stackResultDelta := 0
  preservedRegisters := []
  clobberedRegisters := []
  resultRegisterRelations := [{
    register := .eax
    relation := .dynamicRangeBase (.fixed 8) 8 [] false
  }]
  memoryEffect := .readOnly
  memoryFootprints := []
  worldEffect := .dynamicRangeRelease 0
}

example : machineResponseRequirementsForContract 7 releaseContract = [
    { boundaryId := 7, kind := .runtimeMemoryFootprints },
    { boundaryId := 7, kind := .dynamicRangeRelease 0 },
    { boundaryId := 7, kind := .nonnullableDynamicRangeResult .eax }
  ] := by native_decide

def registrationContract : MachineImportCallContract := {
  id := 8
  imported := { dll := [], name := .symbol [] }
  stackArgumentOffsets := [0]
  stackResultDelta := 0
  preservedRegisters := []
  clobberedRegisters := []
  memoryEffect := .none
  worldEffect := .callbackRegistration 0
}

example : machineResponseRequirementsForContract 8 registrationContract = [
    { boundaryId := 8, kind := .callbackRegistration 0 }
  ] := by native_decide

example {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    {family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames}
    (definitions : CheckedTotalProtocolResponseDefinitions family) :
    family.Completion :=
  definitions.toCompletion

#print axioms machineCallResultConforms_inputAdmissible
#print axioms noMachineCallResultConformsOfInadmissible
#print axioms noDynamicRangeReleaseWithoutOwnedArgument
#print axioms noCallbackRegistrationWithoutCheckedTarget
#print axioms CheckedWorldNativeResponseAt.machineEffectInputAdmissible
#print axioms CheckedWorldNativeResponseAt.responseInputsAdmissible
#print axioms noCheckedWorldNativeResponseAtOfInadmissibleBoundary
#print axioms CheckedReachableWorldNativeProtocolBoundaryDomain.everySuspensionAdmitted
#print axioms CheckedTotalProtocolResponseDefinitions.toCompletion

end StageA.NativeSourceResponseFamilyCompletionKernel
'''


class StageANativeSourceResponseFamilyCompletionKernelTests(unittest.TestCase):
    def test_effect_input_obligations_compile_without_new_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        kernel_source = (
            source_root / "RelationalNativeSourceResponseFamilyCompletion.lean"
        ).read_text(encoding="utf-8")
        for api_name in (
            "SetUnhandledExceptionFilter",
            "__setusermatherr",
            "atexit",
            "free",
        ):
            self.assertNotIn(api_name, kernel_source)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalNativeSourceResponseRequirements",
            )
            fixture = stage_a / "NativeSourceResponseFamilyCompletionKernel.lean"
            fixture.write_text(_FIXTURE, encoding="utf-8")
            checked = _run_lean_relational(
                root, bundle="NativeSourceResponseFamilyCompletionKernel"
            )

        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 9, output)
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
