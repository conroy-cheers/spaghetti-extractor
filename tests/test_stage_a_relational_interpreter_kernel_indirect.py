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


class StageARelationalInterpreterKernelIndirectTests(unittest.TestCase):
    def test_kernel_has_no_unchecked_acceptance_constructs(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalInterpreterKernelIndirect.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        self.assertIn("RelocationTargetSectionKind", source)
        self.assertIn("parseRelocations pe", source)
        self.assertIn("parseImports pe == some imports", source)
        self.assertIn("ClassifiedIATIndirectSite.operandChecked", source)
        self.assertIn("RuntimeValuesBounded", source)
        self.assertIn("WritableCellsPreserved", source)
        self.assertIn("ExactCDeclCallHolds", source)
        self.assertIn("ExactCallbackTargetExecution", source)
        self.assertIn("NestedMixedFrameRelationPreserved", source)
        self.assertIn("ClassifiedKernelIndirectInventory.coversProgram", source)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for indirect checks")
    def test_generic_indirect_primitives_compile_and_audit_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalInterpreterKernelIndirect"
            )
            (stage_a / "RelationalInterpreterKernelIndirectFixture.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            result = _run_lean_relational(
                root, bundle="RelationalInterpreterKernelIndirectFixture"
            )

        self.assertEqual(result["status"], "checked", result)
        self.assertNotIn("sorryAx", result["stdout"])
        self.assertNotIn("declaration uses 'axiom'", result["stdout"])


_FIXTURE = r"""import StageA.RelationalInterpreterKernelIndirect

namespace StageA.Relational.InterpreterKernelIndirectFixture

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelIndirect

example (pe : PE32) (targets : CallbackTargetSet) :
    ({ cells := [] } : ClassifiedRelocationTargetInventory).checked pe targets =
      false := by
  cases parsed : parseRelocations pe <;>
    simp [ClassifiedRelocationTargetInventory.checked,
      ClassifiedRelocationTargetInventory.erased,
      RelocationBackedCallbackTargetInventory.checked, parsed]

example {context : StaticProofContext} {world : RelationalWorld}
    {classified : ClassifiedFiniteIndirectSite}
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {environment : NativeEnvironment} {contract : KernelCallbackTargetContract}
    {sourceInvariant : MachineState -> Prop}
    {runs : KernelCallbackExecutionTrace -> Prop}
    (certificate : ClassifiedFiniteIndirectRefinement context world classified
      program pe imports environment contract sourceInvariant runs)
    (trace : KernelCallbackExecutionTrace) (executed : runs trace)
    (source : sourceInvariant trace.run.caller) :
    exists target, List.Mem target classified.site.targets.entries /\
      trace.run.target = target.address pe /\
      classified.site.targetWord trace.run.caller = target.address pe /\
      ExactCDeclCallHolds pe classified.site trace.run /\
      ExactCallbackTargetExecution classified.site target pe imports environment
        trace :=
  certificate.sound trace executed source

#print axioms ClassifiedFiniteIndirectRefinement.sound

end StageA.Relational.InterpreterKernelIndirectFixture
"""


if __name__ == "__main__":
    unittest.main()
