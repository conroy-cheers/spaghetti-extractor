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


_FIXTURE = r'''import StageA.RelationalNativeSourceAdmittedResponseFamily

namespace StageA.NativeSourceAdmittedResponseFamilyKernel

open StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge

example {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {sites : List OpaqueLockstepCallSite}
    {sourceEnvironment : WorldExternalEnvironment}
    (schedule : CheckedWorldNativeResponseSchedule context program candidate
      sites sourceEnvironment) :
    ExactWorldNativeExternalEvidence context program candidate sites
      sourceEnvironment :=
  schedule.externalEvidence

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (family : CheckedWorldNativeAdmittedResponseFamily context sites compilation) :
    CheckedNativeSourceAdmittedPairEvidence context sites compilation
      family.Related :=
  family.admittedEvidence

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (family : CheckedWorldNativeAdmittedResponseFamily context sites compilation)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (related : family.Related sourceEnvironment nativeEnvironment) :
    ExactWorldNativeExternalEvidence context
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments compilation sourceEnvironment
        nativeEnvironment).machineAuthority.program sites sourceEnvironment :=
  by
    cases related with
    | intro admitted => exact admitted.responseSchedule.externalEvidence

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (family : CheckedWorldNativeAdmittedResponseFamily context sites compilation) :
    CheckedConcreteWorldNativeEnvironmentPair context sites compilation :=
  family.canonicalConcretePair

#print axioms CheckedWorldNativeResponseAt.refines
#print axioms CheckedWorldNativeResponseSchedule.externalEvidence
#print axioms CheckedWorldNativeAdmittedResponseFamily.realizable
#print axioms CheckedWorldNativeAdmittedResponseFamily.admittedEvidence
#print axioms CheckedWorldNativeAdmittedResponseFamily.canonicalConcretePair

end StageA.NativeSourceAdmittedResponseFamilyKernel
'''


class StageANativeSourceAdmittedResponseFamilyKernelTests(unittest.TestCase):
    def test_kernel_compiles_and_audits_without_project_axioms(self) -> None:
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
                "RelationalNativeSourceAdmittedResponseFamily",
            )
            (stage_a / "NativeSourceAdmittedResponseFamilyKernel.lean").write_text(
                _FIXTURE, encoding="ascii"
            )
            checked = _run_lean_relational(
                root, bundle="NativeSourceAdmittedResponseFamilyKernel"
            )
        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 5, output)
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
