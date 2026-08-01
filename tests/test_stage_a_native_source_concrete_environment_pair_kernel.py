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


_FIXTURE = r'''import StageA.RelationalNativeSourceConcreteEnvironmentPair

namespace StageA.NativeSourceConcreteEnvironmentPairKernel

open StageA.Relational
open StageA.Relational.NativeSource

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation) :
    exists sourceEnvironment nativeEnvironment,
      pair.Related sourceEnvironment nativeEnvironment :=
  pair.realizable

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    (pair : CheckedConcreteWorldNativeEnvironmentPair context sites compilation) :
    CheckedNativeSourceAdmittedPairEvidence context sites compilation pair.Related :=
  pair.admittedEvidence

#print axioms CheckedConcreteWorldNativeEnvironmentPair.realizable
#print axioms CheckedConcreteWorldNativeEnvironmentPair.externalEvidenceAt
#print axioms CheckedConcreteWorldNativeEnvironmentPair.admittedEvidence

end StageA.NativeSourceConcreteEnvironmentPairKernel
'''


class StageANativeSourceConcreteEnvironmentPairKernelTests(unittest.TestCase):
    def test_kernel_compiles_without_project_axioms(self) -> None:
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
                "RelationalNativeSourceConcreteEnvironmentPair",
            )
            (stage_a / "NativeSourceConcreteEnvironmentPairKernel.lean").write_text(
                _FIXTURE, encoding="ascii"
            )
            checked = _run_lean_relational(
                root, bundle="NativeSourceConcreteEnvironmentPairKernel"
            )
        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 3, output)
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
