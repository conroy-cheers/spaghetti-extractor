from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


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
class StageANativeSourceLaunchFamilyKernelTests(unittest.TestCase):
    def test_static_evidence_derives_every_checked_launch(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalNativeSourceLaunchFamily.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"candidate[A-Z]",
            r"CompiledArtifact",
            r"GNU|gnu",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "CheckedOriginalInvariantFamilyEvidence",
            "CheckedOriginalReachabilityFamilyEvidence",
            "CheckedNativeSourceInvariantLaunchFamilyEvidence",
            "invariantAtLaunch",
            "domainAtLaunch",
            "ExactBinding",
            "ActiveTargetTransitionIndex",
            "ActiveTargetDomainCoverage",
            "CheckedNativeSourceProject",
            "CheckedNativeSourceLaunchFamily",
        ):
            self.assertIn(required, module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalNativeSourceLaunchFamily"
            )
            (stage_a / "NativeSourceLaunchFamilyKernelFixture.lean").write_text(
                _KERNEL, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="NativeSourceLaunchFamilyKernelFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 4, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",")}
                <= _APPROVED_AXIOMS
                for inventory in inventories
            ),
            output,
        )


_KERNEL = r'''import StageA.RelationalNativeSourceLaunchFamily

namespace StageA.NativeSourceLaunchFamilyKernelFixture

open StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.SourceWorld

example {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project) :
    CheckedNativeSourceLaunchFamily project :=
  evidence.toCheckedNativeSourceLaunchFamily

example {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    Nonempty (CheckedNativeSourceLaunch project sourceRoot) :=
  evidence.toCheckedNativeSourceLaunchFamily.source sourceRoot launch

example {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot)
    (execution : WorldExecution) :
    (evidence.domainAtLaunch sourceRoot launch).holds execution <->
      evidence.original.invariant.holds execution :=
  evidence.domainAtLaunch_holds_iff sourceRoot launch execution

example {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project) :
    CheckedNativeSourceInvariantLaunchFamilyEvidence project :=
  evidence.toInvariantLaunchFamilyEvidence

example {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project) :
    CheckedNativeSourceLaunchFamily project :=
  evidence.toCheckedNativeSourceLaunchFamily

example {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    Nonempty (CheckedNativeSourceLaunch project sourceRoot) :=
  evidence.toCheckedNativeSourceLaunchFamily.source sourceRoot launch

#print axioms StaticNativeSourceLaunchFamilyEvidence.domainAtRoot_holds_iff
#print axioms CheckedNativeSourceInvariantLaunchFamilyEvidence.domainAtLaunch_holds_iff
#print axioms CheckedNativeSourceInvariantLaunchFamilyEvidence.activeTargetCoverageAtLaunch
#print axioms CheckedNativeSourceInvariantLaunchFamilyEvidence.checkedProjectAtLaunch
#print axioms CheckedNativeSourceInvariantLaunchFamilyEvidence.toCheckedNativeSourceLaunchFamily
#print axioms StaticNativeSourceLaunchFamilyEvidence.activeTargetCoverageAtRoot
#print axioms StaticNativeSourceLaunchFamilyEvidence.checkedProjectAtRoot
#print axioms StaticNativeSourceLaunchFamilyEvidence.toCheckedNativeSourceLaunchFamily

end StageA.NativeSourceLaunchFamilyKernelFixture
'''


if __name__ == "__main__":
    unittest.main()
