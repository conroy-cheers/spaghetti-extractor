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


_KERNEL = r"""import StageA.RelationalRegisterTargetValueProvenance

namespace StageA.RegisterTargetValueProvenanceKernel

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.RegisterTargetValueProvenance

theorem importedTargetSurvivesPairedFrame
    {context : OriginalDecodedStaticContext}
    {beforeWorld afterWorld : RelationalWorld}
    {before after : MachineState}
    {register : Reg} {iatRva : Nat} {identity : ExternalTarget}
    (member : RuntimeTargetMember context beforeWorld
      (before.registers.get register) (.importedAddress iatRva identity))
    (frame : RegisterTargetWorldFrame beforeWorld afterWorld)
    (preserved :
      after.registers.get register = before.registers.get register) :
    RuntimeTargetMember context afterWorld
      (after.registers.get register) (.importedAddress iatRva identity) :=
  member.of_registerAndWorldFrame frame preserved

theorem callbackTargetSurvivesPairedFrame
    {context : OriginalDecodedStaticContext}
    {beforeWorld afterWorld : RelationalWorld}
    {before after : MachineState}
    {register : Reg} {slotRva : Nat} {targetIds : List Nat}
    (member : RuntimeTargetMember context beforeWorld
      (before.registers.get register)
      (.registeredCallbackSlot slotRva targetIds))
    (frame : RegisterTargetWorldFrame beforeWorld afterWorld)
    (preserved :
      after.registers.get register = before.registers.get register) :
    RuntimeTargetMember context afterWorld
      (after.registers.get register)
      (.registeredCallbackSlot slotRva targetIds) :=
  member.of_registerAndWorldFrame frame preserved

theorem resolverTargetSurvivesPairedFrame
    {context : OriginalDecodedStaticContext}
    {beforeWorld afterWorld : RelationalWorld}
    {before after : MachineState}
    {register : Reg} {queries : List ResolverQuery}
    {targetIds : List Nat}
    (member : RuntimeTargetMember context beforeWorld
      (before.registers.get register) (.resolverResults queries targetIds))
    (frame : RegisterTargetWorldFrame beforeWorld afterWorld)
    (preserved :
      after.registers.get register = before.registers.get register) :
    RuntimeTargetMember context afterWorld
      (after.registers.get register) (.resolverResults queries targetIds) :=
  member.of_registerAndWorldFrame frame preserved

theorem importedRegisterSurvivesCheckedExternalCall
    {context : StaticProofContext}
    {contract : MachineImportCallContract}
    {relation : ImportRegisterRelation}
    {originalEvent candidateEvent : WorldExternalEvent}
    {originalResult candidateResult : WorldExternalResult}
    (frame : CheckedImportedRegisterCallFrame context contract relation)
    (sourceHolds : relation.holds originalEvent.world
      originalEvent.state.registers candidateEvent.state.registers = true)
    (pairConforms : ExactExternalCallPairConforms context contract
      originalEvent candidateEvent originalResult candidateResult) :
    relation.holds originalResult.world originalResult.state.registers
      candidateResult.state.registers = true :=
  frame.afterExternal originalEvent candidateEvent originalResult
    candidateResult sourceHolds pairConforms

#print axioms importedTargetSurvivesPairedFrame
#print axioms callbackTargetSurvivesPairedFrame
#print axioms resolverTargetSurvivesPairedFrame
#print axioms importedRegisterSurvivesCheckedExternalCall

end StageA.RegisterTargetValueProvenanceKernel
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageARegisterTargetValueProvenanceKernelTests(unittest.TestCase):
    def test_generic_target_provenance_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root / "RelationalRegisterTargetValueProvenance.lean"
        ).read_text(encoding="utf-8")
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)
        for expected in (
            "RegisterTargetWorldFrame",
            "CheckedImportedRegisterCallFrame",
            "importOrigin_toRuntimeTargetMember",
            "callbackOrigin_toRuntimeTargetMember",
            "ResolverCapabilityResultRelated.runtimeTargetMember",
        ):
            self.assertIn(expected, layer)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalRegisterTargetValueProvenance",
            )
            (stage_a / "RegisterTargetValueProvenanceKernel.lean").write_text(
                _KERNEL,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="RegisterTargetValueProvenanceKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
