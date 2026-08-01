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


_FIXTURE = r'''import StageA.RelationalNativeSourceReachableBoundaryDomain

namespace StageA.NativeSourceReachableBoundaryDomainKernel

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.SourceWorld

theorem ordinaryReachabilityEntersDomain
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {sites : List OpaqueLockstepCallSite}
    (checked : CheckedOriginalCombinedReachableBoundaryDomain context program
      originalContext inventory sites)
    (site : OpaqueLockstepCallSite) (member : site ∈ sites)
    (request : WorldNativeBoundaryRequest)
    (reached : OriginalBoundaryRequestReachable inventory site request.eventIndex
      request.originalEvent)
    (related : request.BoundaryRelated context site) :
    (checked.domain site member).Admits request :=
  checked.reachedAdmitted site member request reached related

theorem protocolReachabilityEntersDomain
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : InterpreterNativeWorld.ExactNestedNativeWorldProgram}
    {mixed : MixedRelationContract} {frames : MixedNestedExternalFrameContract}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (domain : CheckedReachableWorldNativeProtocolBoundaryDomain context program
      candidate mixed frames originalContext inventory)
    (request : WorldNativeProtocolBoundaryRequest candidate)
    (holds : inventory.Holds
      (.awaitingExternal request.suspension request.callbacks))
    (related : request.Related mixed frames) :
    domain.Admits request :=
  domain.everySuspensionAdmitted request holds related

theorem admittedProtocolReturnHasCurrentInputs
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : InterpreterNativeWorld.ExactNestedNativeWorldProgram}
    {mixed : MixedRelationContract} {frames : MixedNestedExternalFrameContract}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (domain : CheckedReachableWorldNativeProtocolBoundaryDomain context program
      candidate mixed frames originalContext inventory)
    (request : WorldNativeProtocolBoundaryRequest candidate)
    (admitted : domain.Admits request)
    (contract : MachineImportCallContract)
    (boundary : CheckedOriginalMachineProtocolBoundary program request.suspension
      contract) :
    MachineResponseInputAdmissible false context (protocolReturnContract contract)
        request.suspension.currentEvent /\
      MachineResponseInputAdmissible true context (protocolReturnContract contract)
        (request.boundary.suspension.currentWorldEvent
          request.suspension.siteId) :=
  domain.returningInputs request admitted contract boundary

theorem checkedPathEntersProtocolDomain
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : InterpreterNativeWorld.ExactNestedNativeWorldProgram}
    {mixed : MixedRelationContract} {frames : MixedNestedExternalFrameContract}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {root : WorldExecution}
    (domain : CheckedReachableWorldNativeProtocolBoundaryDomain context program
      candidate mixed frames originalContext inventory)
    (executionDomain : CheckedExecutionDomain program root)
    (projects : forall execution, executionDomain.holds execution ->
      inventory.Holds execution)
    (request : WorldNativeProtocolBoundaryRequest candidate)
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath program.pe32TransitionSystem root observations
      (.awaitingExternal request.suspension request.callbacks))
    (related : request.Related mixed frames) :
    domain.Admits request :=
  domain.pathSuspensionAdmitted executionDomain projects request path related

#print axioms ordinaryReachabilityEntersDomain
#print axioms protocolReachabilityEntersDomain
#print axioms admittedProtocolReturnHasCurrentInputs
#print axioms checkedPathEntersProtocolDomain

end StageA.NativeSourceReachableBoundaryDomainKernel
'''


class StageANativeSourceReachableBoundaryDomainKernelTests(unittest.TestCase):
    def test_reachable_domains_compile_and_are_current_state_indexed(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalNativeSourceReachableBoundaryDomain.lean"
        ).read_text(encoding="utf-8")
        self.assertIn("stateExact : originalExecutionMachine?", module_text)
        self.assertIn("request.suspension.currentEvent", module_text)
        self.assertNotIn("| suspended\n", module_text)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalNativeSourceReachableBoundaryDomain",
            )
            (stage_a / "NativeSourceReachableBoundaryDomainKernel.lean").write_text(
                _FIXTURE, encoding="utf-8"
            )
            checked = _run_lean_relational(
                root, bundle="NativeSourceReachableBoundaryDomainKernel"
            )

        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        reports = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(reports), 4, output)
        for report in reports:
            used = {name.strip() for name in report.split(",") if name.strip()}
            self.assertLessEqual(
                used, {"propext", "Classical.choice", "Quot.sound"}, report
            )


if __name__ == "__main__":
    unittest.main()
