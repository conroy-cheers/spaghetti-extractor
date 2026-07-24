from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.callable_external_capability import (
    relational_callable_external_capability_source,
)
from spaghetti_extractor.relational.lean.callable_external_execution import (
    relational_callable_external_execution_source,
)
from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from tests.test_stage_a_callable_external_capability import _artifact
from tests.test_stage_a_callable_external_execution import _execution_artifact


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_REPORT = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageACallableExternalExecutionKernelTests(unittest.TestCase):
    def test_runtime_wrapper_and_interleaved_trace_are_kernel_checked(self) -> None:
        source_root = Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        layer = (
            source_root / "RelationalCallableExternalExecution.lean"
        ).read_text(encoding="utf-8")
        self.assertNotIn("native_decide", layer)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", layer), marker)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root, stage_a, "RelationalCallableExternalExecution"
            )
            (stage_a / "GeneratedCallableExternalCapability.lean").write_text(
                relational_callable_external_capability_source(_artifact()),
                encoding="utf-8",
            )
            (stage_a / "GeneratedCallableExternalExecution.lean").write_text(
                relational_callable_external_execution_source(
                    _execution_artifact()
                ).replace(
                    "import StageA.RelationalCallableExternalExecution",
                    "import StageA.GeneratedCallableExternalCapability",
                ),
                encoding="utf-8",
            )
            (stage_a / "CallableExternalExecutionKernel.lean").write_text(
                _KERNEL_SOURCE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root, bundle="CallableExternalExecutionKernel"
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        reports = _AXIOM_REPORT.findall(output)
        self.assertGreaterEqual(len(reports), 6, output)
        for report in reports:
            used = {item.strip() for item in report.split(",") if item.strip()}
            self.assertLessEqual(used, _APPROVED_AXIOMS, report)


_KERNEL_SOURCE = r"""import StageA.GeneratedCallableExternalExecution

namespace StageA.CallableExternalExecutionKernel

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalExecution
open StageA.Relational.InterpreterKernel
open StageA.GeneratedRelational.CallableExternalCapability
open StageA.GeneratedRelational.CallableExternalExecution

def importedIdentity : ExternalTarget := {
  dll := [114, 117, 110, 116, 105, 109, 101, 46, 100, 108, 108]
  name := .symbol [105, 110, 118, 111, 107, 101]
}

def importBinding : ImportAddressPair := {
  id := 12
  imported := importedIdentity
  originalIatRva := 4096
  candidateIatRva := 8192
  originalAddress := BitVec.ofNat 32 1610612752
  candidateAddress := BitVec.ofNat 32 1627389984
}

def callableResource : OpaqueResourcePair := {
  id := 41
  original := BitVec.ofNat 32 1879048208
  candidate := BitVec.ofNat 32 1895825440
}

example : classifyOriginalIndirectMatches [7] [] []
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .internal 7 := by decide

example : classifyOriginalIndirectMatches [] [importBinding] []
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .imported importBinding := by decide

example : classifyOriginalIndirectMatches [] [] [callableResource]
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .callable callableExternalCapability41 resolvedExternalABIContract50
      callableResource := by decide

example : classifyOriginalIndirectMatches [7] [importBinding] []
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .ambiguous := by decide

example : classifyOriginalIndirectMatches [7] [] [callableResource]
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .ambiguous := by decide

example : classifyOriginalIndirectMatches [] [importBinding] [callableResource]
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .ambiguous := by decide

example : classifyOriginalIndirectMatches [] [] [callableResource, callableResource]
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .ambiguous := by decide

example : classifyOriginalIndirectMatches [] []
    [{ callableResource with id := 42 }]
    callableExternalCapabilities resolvedExternalABIContracts .call =
    .invalidCallable := by decide

example : originalExternalSiteIdsUnique originalExternalSites = true := by decide

example (program : OriginalCallableProgram) (world : RelationalWorld)
    (target : Word) (transfer : ResolvedExternalTransfer)
    (invalid : callableExternalWorldValid program.context world != true) :
    resolveOriginalIndirect program world target transfer = .invalidWorld := by
  simp [resolveOriginalIndirect, resolveDecodedCallableIndirect, invalid]

/-- Resolver, ordinary import, and resolved capability observations are
constructed by three successful runtime call transitions at one shared index. -/
theorem interleavedRuntimeTrace
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (start : OriginalCallableExecutionState)
    (resolverOutcome importOutcome resolvedOutcome : ConcreteOutcome)
    (resolverEvent importEvent resolvedEvent : CallableRuntimeExternalEvent)
    (resolverContinuation importContinuation resolvedContinuation : Nat)
    (programValid : program.Valid)
    (resolverWorldValid : callableExternalWorldValid program.context start.world = true)
    (resolverDispatch : OriginalCallableCallDispatch program start resolverOutcome
      resolverEvent resolverContinuation)
    (resolverConforms : OriginalCallableResultConforms program resolverEvent
      (environment.result start.globalExternalIndex resolverEvent))
    (resolverIdentity : resolverEvent.identity = .resolver 8 3 41)
    (importWorldValid :
      callableExternalWorldValid program.context
        (start.afterExternalCall resolverContinuation resolverEvent
          (environment.result start.globalExternalIndex resolverEvent)).world = true)
    (importDispatch : OriginalCallableCallDispatch program
      (start.afterExternalCall resolverContinuation resolverEvent
        (environment.result start.globalExternalIndex resolverEvent)) importOutcome
      importEvent importContinuation)
    (importConforms : OriginalCallableResultConforms program importEvent
      (environment.result (start.globalExternalIndex + 1) importEvent))
    (importIdentity : importEvent.identity =
      .imported 4 12 importedIdentity .call)
    (resolvedWorldValid :
      callableExternalWorldValid program.context
        ((start.afterExternalCall resolverContinuation resolverEvent
          (environment.result start.globalExternalIndex resolverEvent)).afterExternalCall
            importContinuation importEvent
            (environment.result (start.globalExternalIndex + 1) importEvent)).world = true)
    (resolvedDispatch : OriginalCallableCallDispatch program
      ((start.afterExternalCall resolverContinuation resolverEvent
        (environment.result start.globalExternalIndex resolverEvent)).afterExternalCall
          importContinuation importEvent
          (environment.result (start.globalExternalIndex + 1) importEvent))
      resolvedOutcome resolvedEvent resolvedContinuation)
    (resolvedConforms : OriginalCallableResultConforms program resolvedEvent
      (environment.result (start.globalExternalIndex + 2) resolvedEvent))
    (resolvedIdentity : resolvedEvent.identity = .resolved 41 41 50 .call)
    (consistent : start.RuntimeTraceConsistent) :
    let first := start.afterExternalCall resolverContinuation resolverEvent
      (environment.result start.globalExternalIndex resolverEvent)
    let second := first.afterExternalCall importContinuation importEvent
      (environment.result first.globalExternalIndex importEvent)
    let third := second.afterExternalCall resolvedContinuation resolvedEvent
      (environment.result second.globalExternalIndex resolvedEvent)
    third.RuntimeTraceConsistent ∧
      third.externalTrace = start.externalTrace ++ [
        resolverEvent.observe start.globalExternalIndex,
        importEvent.observe (start.globalExternalIndex + 1),
        resolvedEvent.observe (start.globalExternalIndex + 2)] ∧
      resolverEvent.identity = .resolver 8 3 41 ∧
      importEvent.identity = .imported 4 12 importedIdentity .call ∧
      resolvedEvent.identity = .resolved 41 41 50 .call := by
  dsimp
  let first := start.afterExternalCall resolverContinuation resolverEvent
    (environment.result start.globalExternalIndex resolverEvent)
  let second := first.afterExternalCall importContinuation importEvent
    (environment.result first.globalExternalIndex importEvent)
  let third := second.afterExternalCall resolvedContinuation resolvedEvent
    (environment.result second.globalExternalIndex resolvedEvent)
  have stepOne : OriginalCallableExternalStep program environment start
      resolverOutcome first :=
    .call start resolverOutcome resolverEvent resolverContinuation
      (environment.result start.globalExternalIndex resolverEvent) programValid
      resolverWorldValid resolverDispatch rfl resolverConforms
  have stepTwo : OriginalCallableExternalStep program environment first
      importOutcome second :=
    .call first importOutcome importEvent importContinuation
      (environment.result first.globalExternalIndex importEvent) programValid
      importWorldValid importDispatch rfl (by simpa [first] using importConforms)
  have stepThree : OriginalCallableExternalStep program environment second
      resolvedOutcome third :=
    .call second resolvedOutcome resolvedEvent resolvedContinuation
      (environment.result second.globalExternalIndex resolvedEvent) programValid
      resolvedWorldValid resolvedDispatch rfl (by
        simpa [first, second, OriginalCallableExecutionState.afterExternalCall]
          using resolvedConforms)
  have steps : OriginalCallableExternalSteps program environment start third :=
    .step stepOne (.step stepTwo (.step stepThree (.refl third)))
  refine ⟨?_, ?_, resolverIdentity, importIdentity, resolvedIdentity⟩
  · exact steps.preservesRuntimeTraceConsistency program environment start third
      consistent
  · simp [first, second, third,
      OriginalCallableExecutionState.afterExternalCall]

#print axioms classifyOriginalIndirectMatches
#print axioms OriginalCallableExternalStep.preservesRuntimeTraceConsistency
#print axioms OriginalCallableExternalStep.appendsRuntimeObservation
#print axioms OriginalCallableExternalStep.indirectCallResumesExactContinuation
#print axioms OriginalCallableExternalStep.indirectTailRequiresRuntimeFrame
#print axioms OriginalCallableExternalSteps.preservesRuntimeTraceConsistency
#print axioms runtimeCallableTracesRejectOmittedEvent
#print axioms runtimeCallableTracesRejectReorderedEvents
#print axioms runtimeCallableTracesRejectMismatchedArguments
#print axioms composeOriginalWithCandidateRuntimeTrace
#print axioms interleavedRuntimeTrace

end StageA.CallableExternalExecutionKernel
"""


if __name__ == "__main__":
    unittest.main()
