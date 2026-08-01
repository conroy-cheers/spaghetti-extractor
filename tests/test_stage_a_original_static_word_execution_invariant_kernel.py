from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound", "Classical.choice"}


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


_KERNEL = r'''import StageA.RelationalOriginalStaticWordExecutionInvariant

namespace StageA.OriginalStaticWordExecutionInvariantKernel

open StageA.Formal StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalStaticWordExecutionInvariant

theorem finiteRequirementReadsConcreteMemory
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (mode : requirement.admissibility = .finiteWords)
    (holds : requirement.Holds context world memory) :
    Memory.read32 memory requirement.slot.originalAddress ∈
      requirement.allowedOriginalWords := by
  simpa [OriginalStaticWordRequirement.WordAdmissible, mode] using holds.2.1

theorem imageSeedUsesExactLoadedImage
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (mapped : PreferredBaseImageMemory context.originalPe
      context.originalImports memory)
    (seed : OriginalStaticWordImageSeed context world requirement) :
    requirement.Holds context world memory :=
  requirement.holdsOfImageSeed context world memory mapped seed

theorem importSeedUsesExactIatWord
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (valid : requirement.Valid context)
    (binding : ImportAddressPair) (member : binding ∈ world.importAddresses)
    (mode : requirement.admissibility = .finiteWords)
    (slotExact : requirement.slot.originalAddress =
      BitVec.ofNat 32
        (context.originalPe.imageBase + binding.originalIatRva))
    (allowed : binding.originalAddress ∈ requirement.allowedOriginalWords)
    (origin : ValueOriginAtom.importTarget binding.imported ∈
      requirement.origins)
    (iat : forall selected, selected ∈ world.importAddresses ->
      Memory.read32 memory
          (BitVec.ofNat 32
            (context.originalPe.imageBase + selected.originalIatRva)) =
        selected.originalAddress) :
    requirement.Holds context world memory :=
  requirement.holdsOfImportSeed context world memory valid binding member
    slotExact
    (requirement.wordAdmissibleOfFinite context world binding.originalAddress
      mode allowed)
    origin iat

theorem importSeedUsesWorldSelectedIatWord
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (valid : requirement.Valid context)
    (mode : requirement.admissibility = .worldOrigins)
    (binding : ImportAddressPair) (member : binding ∈ world.importAddresses)
    (slotExact : requirement.slot.originalAddress =
      BitVec.ofNat 32
        (context.originalPe.imageBase + binding.originalIatRva))
    (origin : ValueOriginAtom.importTarget binding.imported ∈
      requirement.origins)
    (iat : forall selected, selected ∈ world.importAddresses ->
      Memory.read32 memory
          (BitVec.ofNat 32
            (context.originalPe.imageBase + selected.originalIatRva)) =
        selected.originalAddress) :
    requirement.Holds context world memory :=
  requirement.holdsOfImportSeedFromWorldOrigin context world memory valid mode
    binding member slotExact origin iat

theorem opaqueResourceWordNeedsNoConcreteInventoryEntry
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (valid : requirement.Valid context)
    (mode : requirement.admissibility = .worldOrigins)
    (resource : OpaqueResourcePair) (resourceMember : resource ∈ world.opaqueResources)
    (originMember : ValueOriginAtom.opaqueResource resource.id ∈
      requirement.origins)
    (readExact :
      Memory.read32 memory requirement.slot.originalAddress = resource.original) :
    requirement.Holds context world memory := by
  apply requirement.holdsOfWorldOrigin context world memory valid mode
    (.opaqueResource resource.id) originMember
  exact ⟨resource.candidate, resource, resourceMember, rfl, readExact, rfl⟩

theorem disjointWritesPreserveFiniteRequirement
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory : Memory) (writes : List (Word × Word))
    (requirement : OriginalStaticWordRequirement)
    (before : requirement.Holds context beforeWorld beforeMemory)
    (avoids : WritesAvoidWord requirement.slot.originalAddress writes)
    (origins : requirement.OriginsPreserved context beforeWorld afterWorld) :
    requirement.Holds context afterWorld
      (applyConcreteWrites beforeMemory writes) :=
  requirement.afterInternalWrites context beforeWorld afterWorld beforeMemory
    writes before (.disjoint avoids origins)

theorem blockedExecutionCannotSatisfyInventory
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (reason : ExecutionBlock) :
    Not (inventory.Holds context (.blocked reason)) :=
  inventory.blockedFalse context reason

theorem unknownNestedCallbackCannotSatisfyInventory
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (unknown : Not
      (StageA.Relational.OriginalCallFrameExecutionInvariant.KnownCallbackRuntime
        context callback)) :
    Not (inventory.Holds context
      (.callbackRunning targetId state calls eventIndex world
        (callback :: callbacks))) :=
  inventory.unknownCallbackFalse context targetId state calls eventIndex world
    callback callbacks unknown

def checkedAdapterIsTheOnlyWholeStepBridge
    {program : DecodedWorldProgram}
    {inventory : OriginalStaticWordInventory}
    (checked : CheckedOriginalStaticWordExecutionInvariant program inventory) :
    OriginalWorldExecutionInvariant program :=
  checked.toOriginalInvariant

#print axioms finiteRequirementReadsConcreteMemory
#print axioms imageSeedUsesExactLoadedImage
#print axioms importSeedUsesExactIatWord
#print axioms importSeedUsesWorldSelectedIatWord
#print axioms opaqueResourceWordNeedsNoConcreteInventoryEntry
#print axioms disjointWritesPreserveFiniteRequirement
#print axioms blockedExecutionCannotSatisfyInventory
#print axioms unknownNestedCallbackCannotSatisfyInventory
#print axioms checkedAdapterIsTheOnlyWholeStepBridge
#print axioms OriginalStaticWordRequirement.afterMachineCall
#print axioms OriginalStaticWordInventory.internalExactWrites
#print axioms OriginalStaticWordInventory.externalReturnedByMachineFrames
#print axioms OriginalStaticWordInventory.externalCallbackEntry
#print axioms OriginalStaticWordInventory.callbackReturnRestored

end StageA.OriginalStaticWordExecutionInvariantKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalStaticWordExecutionInvariantKernelTests(unittest.TestCase):
    def test_generic_one_sided_static_word_foundation_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root
            / "RelationalOriginalStaticWordExecutionInvariant.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bGnu\b",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "OriginalStaticWordRequirement.Valid",
            "OriginalStaticWordAdmissibility",
            "OriginalStaticWordRequirement.WordAdmissible",
            "OriginalStaticWordRequirement.Holds",
            "OriginalStaticWordLaunchFacts",
            "holdsOfImageSeed",
            "holdsOfImportSeed",
            "holdsOfImportSeedFromWorldOrigin",
            "OriginalStaticWordWriteFrame",
            "afterInternalWrites",
            "afterMachineCall",
            "SuspendedOriginalStaticWordsHold",
            "OriginalStaticWordInventory.internalExactWrites",
            "OriginalStaticWordInventory.externalReturnedByMachineFrames",
            "OriginalStaticWordInventory.externalCallbackEntry",
            "OriginalStaticWordInventory.callbackReturnRestored",
            "OriginalStaticWordInventory.blockedFalse",
            "CheckedOriginalStaticWordExecutionInvariant.toOriginalInvariant",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalStaticWordExecutionInvariant",
            )
            (stage_a / "OriginalStaticWordExecutionInvariantKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="OriginalStaticWordExecutionInvariantKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 14, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
