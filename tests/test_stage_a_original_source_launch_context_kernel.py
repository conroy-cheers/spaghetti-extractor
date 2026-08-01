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


_KERNEL = r'''import StageA.RelationalOriginalSourceLaunchContext

namespace StageA.OriginalSourceLaunchContextKernel

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalSourceLaunchContext
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

theorem launchSeedIsComponentComplete
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (seed : OriginalCombinedPE32ConsoleLaunchSeed project originalContext
      inventory)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    inventory.Holds sourceRoot.toWorldExecution :=
  seed.holds sourceRoot launch

theorem externalPreservationOnlyEntersThroughTheHook
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (preservation : OriginalCombinedAwaitingExternalPreservation
      originalContext inventory) :
    OriginalSourceAwaitingExternalHook originalContext inventory :=
  { preservation := preservation }

theorem closedContextProducesExactKernelCompatibility
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    ProgramRecordKernelMatchesDecodedSemantics project.program
      (context.launchFamilyEvidence.domainAtLaunch sourceRoot launch) :=
  context.programRecordKernelCompatibility sourceRoot launch

theorem closedContextProducesTheSourceLaunchFamily
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory) : CheckedNativeSourceLaunchFamily project :=
  context.toCheckedNativeSourceLaunchFamily

#print axioms launchSeedIsComponentComplete
#print axioms externalPreservationOnlyEntersThroughTheHook
#print axioms closedContextProducesExactKernelCompatibility
#print axioms closedContextProducesTheSourceLaunchFamily

end StageA.OriginalSourceLaunchContextKernel
'''

_CONSTRUCTION_KERNEL = r'''import StageA.RelationalOriginalSourceLaunchConstruction

namespace StageA.OriginalSourceLaunchConstructionKernel

open StageA.Relational
open StageA.Relational.OriginalSourceLaunchConstruction

theorem checkedLaunchSeedClosesAllComponents
    (project : NativeSource.NativeSourceProject)
    (originalContext : InterpreterMixedContext.OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInvariant.OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext)
    (contextValid : project.program.worldProgram.context.StructurallyValid)
    (staticRequirementsValid : forall requirement,
      requirement ∈ inventory.staticWords.requirements ->
        requirement.Valid project.program.worldProgram.context)
    (checked : combinedLaunchSeedChecked project originalContext inventory = true) :
    OriginalSourceLaunchContext.OriginalCombinedPE32ConsoleLaunchSeed project
      originalContext inventory :=
  combinedLaunchSeedChecked_sound project originalContext inventory
    contextValid staticRequirementsValid checked

#print axioms checkedLaunchSeedClosesAllComponents

end StageA.OriginalSourceLaunchConstructionKernel
'''


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalSourceLaunchContextKernelTests(unittest.TestCase):
    def test_launch_context_is_generic_checked_and_api_parametric(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalSourceLaunchContext.lean"
        ).read_text(encoding="utf-8")

        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bopaque\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"GNU|Gnu|gnu",
            r"authorizing_lean_terms",
            r"status\s*==",
        ):
            self.assertNotRegex(module_text, forbidden)

        for required in (
            "OriginalCombinedPE32ConsoleLaunchSeed",
            "runtimeMemory",
            "CheckedOriginalSourceStaticLaunchContext",
            "OriginalSourceAwaitingExternalHook",
            "CheckedOriginalSourceLaunchContext",
            "combinedInvariantAtLaunch",
            "programRecordKernelCompatibility",
            "CheckedNativeSourcePE32ConsoleLaunch",
            "ActiveTargetTransitionIndex",
            "OriginalCombinedTargetStepIndex",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalOriginalSourceLaunchContext"
            )
            (stage_a / "OriginalSourceLaunchContextKernel.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="OriginalSourceLaunchContextKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)

    def test_launch_construction_checker_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalOriginalSourceLaunchConstruction.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bopaque\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"GNU|Gnu|gnu",
        ):
            self.assertNotRegex(module_text, forbidden)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalSourceLaunchConstruction",
            )
            (stage_a / "OriginalSourceLaunchConstructionKernel.lean").write_text(
                _CONSTRUCTION_KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="OriginalSourceLaunchConstructionKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 1, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
