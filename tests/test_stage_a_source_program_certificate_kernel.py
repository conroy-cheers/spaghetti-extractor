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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageASourceProgramCertificateKernelTests(unittest.TestCase):
    def test_checked_target_inventory_closes_whole_domain_step_equality(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalSourceProgramCertificate.lean"
        ).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*axiom\b", module_text, re.MULTILINE))
        self.assertNotIn("sorry", module_text)
        self.assertNotIn("unsafe", module_text)
        self.assertNotIn("native_decide", module_text)
        self.assertIn("ActiveTargetTransitionCertificate", module_text)
        self.assertIn("ActiveTargetDomainCoverage", module_text)
        self.assertIn("ExactBoundActiveTargetTransitionIndex", module_text)
        self.assertIn("find?_isSome_of_target_mem", module_text)
        self.assertIn("ofTargetMembership", module_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalSourceProgramCertificate",
            )
            (stage_a / "SourceProgramCertificateKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="SourceProgramCertificateKernelFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("Classical.choice", output)
        axiom_inventories = re.findall(
            r"depends on axioms: \[([^\]]*)\]",
            output,
            re.MULTILINE,
        )
        self.assertEqual(len(axiom_inventories), 2, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",")}
                == {"propext", "Quot.sound"}
                for inventory in axiom_inventories
            ),
            output,
        )
        self.assertIn(
            "programRecordKernelMatchesDecodedSemantics_of_checkedTargets",
            output,
        )
        self.assertIn("findTargetCertificate?_targetExact", output)


_KERNEL_FIXTURE = r'''import StageA.RelationalSourceProgramCertificate

namespace StageA.SourceProgramCertificateKernelFixture

open StageA.Relational
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

example {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    (head tail : ActiveTargetTransitionCertificate binding)
    (different : head.targetId ≠ tail.targetId) :
    ([(head), (tail)].map (fun certificate => certificate.targetId)).Nodup := by
  simp [different]

example {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    (index : ActiveTargetTransitionIndex binding)
    {targetId : Nat}
    {certificate : ActiveTargetTransitionCertificate binding}
    (found : index.find? targetId = some certificate) :
    certificate.targetId = targetId := by
  exact index.find?_targetExact found

example {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    (index : ActiveTargetTransitionIndex binding) {targetId : Nat}
    (member : targetId ∈
      index.certificates.map (fun certificate => certificate.targetId)) :
    exists certificate, index.find? targetId = some certificate := by
  exact index.find?_isSome_of_target_mem member

example {pe : StageA.Formal.PE32} {program : Program}
    (binding : ExactBinding pe program)
    (index : ActiveTargetTransitionIndex binding) :
    ExactBoundActiveTargetTransitionIndex binding := by
  exact { index := index }

example {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} {root : WorldExecution}
    (index : ActiveTargetTransitionIndex binding)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (targetIds : List Nat)
    (targetsExact :
      index.certificates.map (fun certificate => certificate.targetId) =
        targetIds)
    (runningTargetMember : forall targetId state calls eventIndex world,
      domain.holds (.running targetId state calls eventIndex world) ->
        targetId ∈ targetIds)
    (callbackTargetMember :
      forall targetId state calls eventIndex world callbacks,
        domain.holds
          (.callbackRunning targetId state calls eventIndex world callbacks) ->
          targetId ∈ targetIds) :
    ActiveTargetDomainCoverage index domain := by
  exact ActiveTargetDomainCoverage.ofTargetMembership index domain targetIds
    targetsExact runningTargetMember callbackTargetMember

example {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} {root : WorldExecution}
    (index : ActiveTargetTransitionIndex binding)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (coverage : ActiveTargetDomainCoverage index domain) :
    ProgramRecordKernelMatchesDecodedSemantics program domain := by
  exact programRecordKernelMatchesDecodedSemantics_of_checkedTargets
    index domain coverage

#print axioms findTargetCertificate?_targetExact
#print axioms programRecordKernelMatchesDecodedSemantics_of_checkedTargets

end StageA.SourceProgramCertificateKernelFixture
'''


if __name__ == "__main__":
    unittest.main()
