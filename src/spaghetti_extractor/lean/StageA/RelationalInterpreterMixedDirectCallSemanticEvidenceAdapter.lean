import StageA.RelationalInterpreterMixedDirectCallReplayAdapter
import StageA.RelationalInterpreterMixedFusedSemanticEvidenceAdapter

namespace StageA.Relational.InterpreterMixedDirectCallSemanticEvidenceAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedDirectCallReplayAdapter
open StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterTransfer

/-!
# Direct-call mixed semantic evidence

This adapter closes the direct-call/return variant of a mixed semantic
operation. The original path is selected only by an exact PE-backed
`ActualDirectCallReturnExecution`; the candidate path starts at the exact
native `candidateBefore` world and is computed by `CheckedNativeOperationPath`.

No path fuel, endpoint, observation list, or completion status is accepted.
The call-aware interpreter derivation remains explicit because it is the
semantic call tree for the exact source record. The equality connecting its
result to the operational summary is stated against the summary's computed
exit state, not against a caller-supplied endpoint.
-/

theorem WorldExecutionPoint.originalExecutionMachineExact
    (point : WorldExecutionPoint) :
    originalExecutionMachine? point.execution = some point.state := by
  rcases point with ⟨targetId, state, calls, eventIndex, world, callbacks⟩
  cases callbacks <;> rfl

/-- Select the unique proof-relevant execution supplied by operational
completeness. The caller supplies only a related source; path length, endpoint,
and observations are recovered from the checked call-tree classifier. -/
noncomputable def checkedActualDirectCallForSource
    {staticContext : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises staticContext tree)
    (summarySource : RelatedDirectCallSource staticContext tree
      premises.callEntry) :
    ActualDirectCallReturnExecution staticContext tree premises.callEntry
      premises.operational.originalProgram
      premises.operational.candidateProgram :=
  Classical.choose
    (premises.operational.returnsFromEverySource summarySource)

theorem checkedActualDirectCallForSource_sourceExact
    {staticContext : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises staticContext tree)
    (summarySource : RelatedDirectCallSource staticContext tree
      premises.callEntry) :
    (checkedActualDirectCallForSource premises summarySource).source =
      summarySource :=
  Classical.choose_spec
    (premises.operational.returnsFromEverySource summarySource)

/-- State-indexed facts for one direct-call/return semantic operation.

`actual` owns the exact original start and complete PE call/return execution.
The static equalities prevent a summary from a different image or source from
being reused. Candidate replay and endpoint closure remain dynamic proof
obligations and are both indexed by the exact `candidateBefore` world. -/
structure CheckedDirectCallMixedSemanticOperationInput
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (staticContext : StaticProofContext)
    (tree : SummaryTree)
    (premises : IntegratedSummaryPremises staticContext tree)
    (summarySource : RelatedDirectCallSource staticContext tree
      premises.callEntry)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachability.targetIds contract)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (checked :
      CheckedFusedOriginalSemanticTransferBinding context authority launch root
        reachability candidate candidateAuthority source)
    (entryRva : Nat)
    (candidateBefore : NativeWorldExecution)
    (ClassificationEvidence : Prop)
    (beforeRelated : invariant.holds
      (checkedActualDirectCallForSource premises
        summarySource).source.original.execution
        candidateBefore)
    (classified : ClassificationEvidence)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) where
  staticOriginalPeExact : staticContext.originalPe = context.pe
  staticOriginalImportsExact : staticContext.originalImports = context.imports
  sourceTargetExact : source.targetId = premises.callEntry.sourceTargetId
  sourceRvaExact :
    source.source.target.rva = tree.certificate.callsite.original.start
  result : MacroResult
  resultExact :
    source.record.interpret environment
        (machineFromFormal
          (checkedActualDirectCallForSource premises
            summarySource).source.original.state) =
      some result
  derivation : CheckedInterpreterStepDerivation
    candidateAuthority.semanticRecords environment resolveCodeTarget
    source.source.target.rva
    (machineFromFormal
      (checkedActualDirectCallForSource premises
        summarySource).source.original.state)
    (some result)
  semanticResultAtOriginalExit :
    machineFromFormal
      (checkedActualDirectCallForSource premises
        summarySource).originalExit.state =
        result.state
  runtimeContextRestored :
    CheckedOriginalDirectCallRuntimeContextRestored
      (checkedActualDirectCallForSource premises summarySource)
  candidateMachine : MachineState
  candidateMachineExact :
    candidateBefore.machine? = some candidateMachine
  requestRelated :
    abi.requestRelated
      (.interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva
        (machineFromFormal
          (checkedActualDirectCallForSource premises
            summarySource).source.original.state))
      candidateMachine
  candidateReplay : forall afterMachine nativeEvents,
    CheckedCandidateKernelDispatchAtBefore dispatches entryRva candidateBefore
      candidateMachine afterMachine nativeEvents ->
      Nonempty (CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents)
  close : forall afterMachine nativeEvents
      (_dispatchAtBefore :
        CheckedCandidateKernelDispatchAtBefore dispatches entryRva
          candidateBefore candidateMachine afterMachine nativeEvents)
      (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents),
    CheckedMixedSemanticOperationClosure
      premises.operational.originalProgram candidate contract invariant
      (checkedActualDirectCallForSource premises
        summarySource).source.original.execution
      candidateBefore
      (ActualDirectCallReturnExecution.checkedOriginalReplay
        (checkedActualDirectCallForSource premises summarySource)).path replay

/-- The semantic interpreter result agrees with the machine at the computed
PE call/return endpoint. -/
theorem CheckedDirectCallMixedSemanticOperationInput.endpointMatches
    (input : CheckedDirectCallMixedSemanticOperationInput context authority
      launch root reachability staticContext tree premises summarySource
      candidate candidateAuthority contract invariant program abi dispatches
      source checked entryRva candidateBefore
      ClassificationEvidence beforeRelated classified environment
      resolveCodeTarget) :
    ExactOriginalSemanticKernelEffect.EndpointMatches
      (ExactOriginalSemanticKernelEffect.interpreterStep environment
        resolveCodeTarget (some input.result) input.resultExact input.derivation)
      (ActualDirectCallReturnExecution.checkedOriginalReplay
        (checkedActualDirectCallForSource premises summarySource)).path.after := by
  let actual := checkedActualDirectCallForSource premises summarySource
  refine ⟨actual.originalExit.state, ?_, input.semanticResultAtOriginalExit⟩
  rw [
    (ActualDirectCallReturnExecution.checkedOriginalReplay actual).afterExact
  ]
  exact WorldExecutionPoint.originalExecutionMachineExact actual.originalExit

/-- Construct checked mixed evidence without accepting an independently chosen
original start or replay. The exact call summary fixes both. -/
noncomputable def CheckedDirectCallMixedSemanticOperationInput.toEvidence
    (input : CheckedDirectCallMixedSemanticOperationInput context authority
      launch root reachability staticContext tree premises summarySource
      candidate candidateAuthority contract invariant program abi dispatches
      source checked entryRva candidateBefore
      ClassificationEvidence beforeRelated classified environment
      resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence
      premises.operational.originalProgram candidate candidateAuthority contract
      invariant program abi dispatches source.source.target.rva source.record
      .interpreterStep entryRva
      (checkedActualDirectCallForSource premises
        summarySource).source.original.execution
      candidateBefore ClassificationEvidence beforeRelated classified := by
  let actual := checkedActualDirectCallForSource premises summarySource
  let originalReplay :=
    ActualDirectCallReturnExecution.checkedOriginalReplay actual
  let effect :=
    ExactOriginalSemanticKernelEffect.interpreterStep environment
      resolveCodeTarget (some input.result) input.resultExact input.derivation
  exact {
    before := {
      originalState := actual.source.original.state
      originalMachineExact :=
        WorldExecutionPoint.originalExecutionMachineExact
          actual.source.original
      beforeMachine := input.candidateMachine
      candidateMachineExact := input.candidateMachineExact
      request := .interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva
        (machineFromFormal actual.source.original.state)
      response := .interpreterStep (some input.result)
      effect
      requestOperationExact := rfl
      requestRelated := input.requestRelated
      originalReplay := originalReplay.path
      originalPathShape :=
        originalReplay.pathShape input.runtimeContextRestored
      originalEffectAfterExact := input.endpointMatches
    }
    candidateReplay := by
      intro afterMachine nativeEvents dispatched
      exact input.candidateReplay afterMachine nativeEvents {
        beforeMachineExact := input.candidateMachineExact
        dispatched
      }
    close := by
      intro afterMachine nativeEvents dispatched replay
      exact input.close afterMachine nativeEvents {
        beforeMachineExact := input.candidateMachineExact
        dispatched
      } replay
  }

#print axioms WorldExecutionPoint.originalExecutionMachineExact
#print axioms checkedActualDirectCallForSource
#print axioms checkedActualDirectCallForSource_sourceExact
#print axioms
  CheckedDirectCallMixedSemanticOperationInput.endpointMatches
#print axioms CheckedDirectCallMixedSemanticOperationInput.toEvidence

end StageA.Relational.InterpreterMixedDirectCallSemanticEvidenceAdapter
