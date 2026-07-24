from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Quot.sound"}


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


_KERNEL = r"""import StageA.RelationalOriginalIndirectOperationalComposition

namespace StageA.OriginalIndirectOperationalCompositionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.RegisterIndirectMixedOriginalComposition
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition
open StageA.Relational.OriginalIndirectOperationalComposition

theorem sourceCarriesActualInvariant
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {sourceTargetId : Nat} {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (source : ActualMixedOriginalOperationalSource invariant sourceTargetId
      world state before) :
    ActualMixedOriginalRegisterSource invariant sourceTargetId world state /\
      ActualMixedOriginalStackDynamicSource invariant sourceTargetId world state :=
  ⟨source.toRegisterSource, source.toStackDynamicSource⟩

theorem exactStepProducesPath
    {program : DecodedWorldProgram} {site : OriginalIndirectControlSite}
    {before : WorldExecution} {targetId : Nat}
    {afterState : MachineState} {after : WorldExecution}
    (premise : ExactOriginalIndirectStepPremise program site before targetId
      afterState after) :
    NonemptyRelatedPath program.pe32TransitionSystem before [] after :=
  premise.toChunk.path

theorem resolvedTargetUsesExactProgramMap
    {context : OriginalDecodedStaticContext}
    {program : DecodedWorldProgram}
    {site : OriginalIndirectControlSite} {state : MachineState}
    (binding : ExactDecodedOriginalCarrierBinding context program)
    (authority : ExactOriginalDecodedAuthority context)
    (resolved : OriginalResolvedCodeTarget context site state) :
    program.context.codeMap.resolveRawEip program.candidate
        (if program.candidate then program.context.candidatePe.imageBase
         else program.context.originalPe.imageBase)
        (site.target.expression.eval state) =
      some resolved.targetId :=
  originalResolvedCodeTarget_resolvesInProgram binding authority resolved

theorem registerCompositionClassifiesActualSource
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    {authority : CheckedAuthority context}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : RegisterIndirectMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.certificate.certificate.site.sourceTargetId world state before)
    (expression : RegisterTargetExpressionPremise authority state) :
    RegisterIndirectOperationalTarget context authority world state :=
  OriginalIndirectOperationalComposition.RegisterIndirectMixedOriginalComposition.operationalTarget
    composition source expression

theorem stackCompositionResolvesActualSource
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    {authority : CheckedStackCarryAuthority context}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : StackCarryMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.static.claim.site.sourceTargetId world state before) :
    Nonempty
      (MixedOriginalStackCarryTarget context authority world state) :=
  OriginalIndirectOperationalComposition.StackCarryMixedOriginalComposition.operationalTarget
    composition source

theorem dynamicCompositionResolvesActualSource
    {context : OriginalDecodedStaticContext}
    {reachabilityTargetIds : List Nat} {contract : MixedRelationContract}
    {authority : CheckedDynamicCallbackAuthority context}
    {invariant : MixedExecutionInvariant reachabilityTargetIds contract}
    {world : RelationalWorld} {state : MachineState}
    {before : WorldExecution}
    (composition : DynamicCallbackMixedOriginalComposition authority invariant)
    (source : ActualMixedOriginalOperationalSource invariant
      authority.static.claim.site.sourceTargetId world state before) :
    Nonempty
      (MixedOriginalDynamicCallbackTarget context authority world state) :=
  OriginalIndirectOperationalComposition.DynamicCallbackMixedOriginalComposition.operationalTarget
    composition source

#print axioms sourceCarriesActualInvariant
#print axioms exactStepProducesPath
#print axioms resolvedTargetUsesExactProgramMap
#print axioms registerCompositionClassifiesActualSource
#print axioms stackCompositionResolvesActualSource
#print axioms dynamicCompositionResolvesActualSource

end StageA.OriginalIndirectOperationalCompositionKernel
"""


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAOriginalIndirectOperationalCompositionKernelTests(
    unittest.TestCase
):
    def test_generic_operational_composition_is_kernel_checked(self) -> None:
        source_root = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
        )
        layer = (
            source_root
            / "RelationalOriginalIndirectOperationalComposition.lean"
        ).read_text(encoding="utf-8")
        for marker in (
            "sorry",
            "axiom",
            "unsafe",
            "native_decide",
            "report.status",
        ):
            self.assertIsNone(re.search(rf"\b{re.escape(marker)}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalOriginalIndirectOperationalComposition",
            )
            kernel = stage_a / "OriginalIndirectOperationalCompositionKernel.lean"
            kernel.write_text(_KERNEL, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle="OriginalIndirectOperationalCompositionKernel",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 6, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


if __name__ == "__main__":
    unittest.main()
