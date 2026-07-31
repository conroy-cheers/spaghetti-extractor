import StageA.RelationalInterpreterKernelCdeclEpilogueExternalPayload
import StageA.RelationalInterpreterMixedFusedSemanticEvidenceAdapter

namespace StageA.Relational.InterpreterMixedExternalTailSemanticEvidenceAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedOriginalSemanticReplay
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterTransfer

/-!
# Imported external-tail semantic evidence

This adapter covers exact semantic transfers which issue one imported call and
finish with `SemanticOutcome.externalJump`. The external jump remains an
ordinary mixed `semanticTransfer` classifier case. It is not an
`externalOperation` or `externalBoundary` classifier case.

The original world transition consumes the continuation already present in the
call stack. It does not synthesize a continuation from the semantic record's
span end. Operational completeness therefore proves the active continuation,
the exact import-site resolution, and the resulting one-step transition for
every actual source state.

No generated datum may supply replay fuel, an endpoint, observations, or a
completion status. The only retained original replay is the definitionally
one-step PE transition. Candidate replay and relational closure remain
state-indexed proof obligations.
-/

def externalTailSemanticCallTarget? (call : SemanticCall) :
    Option ExternalTarget := do
  if call.kind != .external then none else
  let dll <- call.dll
  let name : ImportName <- match call.symbol, call.ordinal with
    | some symbol, none =>
        some (.symbol (stringBytes symbol))
    | none, some ordinal => some (.ordinal ordinal)
    | _, _ => none
  some {
    dll := normalizeDllName (stringBytes dll)
    name
  }

/-- Exact static binding for an imported external-tail semantic transfer.

The import identity is checked against the canonical machine-call contract.
The exact normalization certificate independently binds the transfer, call
boundary, and terminal outcome to the PE bytes. -/
structure CheckedExternalTailStaticBinding
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (staticContext : StaticProofContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (checked :
      CheckedFusedOriginalSemanticTransferBinding context authority launch root
        reachability candidate candidateAuthority source) where
  originalCarrier : ExactDecodedOriginalCarrierBinding context original
  originalPeExact : staticContext.originalPe = context.pe
  originalImportsExact : staticContext.originalImports = context.imports
  originalRelocationsExact :
    staticContext.originalRelocations = context.relocations
  originalMachineContractsExact :
    staticContext.machineImportCallContracts =
      context.machineImportCallContracts
  call : SemanticCall
  boundary : ExactCallBoundarySpec
  contract : MachineImportCallContract
  singleCall : checked.binding.transfer.calls = [call]
  singleBoundary : checked.binding.path.callBoundaries = [boundary]
  transferOutcome : checked.binding.transfer.outcome = .externalJump
  pathTerminal : checked.binding.path.terminal = .externalJump
  callKind : call.kind = .external
  callIdentity :
    externalTailSemanticCallTarget? call = some contract.imported
  contractResolved :
    machineImportCallContractById? staticContext contract.id = some contract
  contractReturns : contract.disposition = .returns
  boundaryInstruction :
    ExactCallBoundarySpec.instructionRva boundary = call.instructionRva
  boundaryCallIndex :
    ExactCallBoundarySpec.callIndex boundary = call.callIndex

/-- The exact imported event used by one original external-tail transition. -/
def checkedExternalTailEvent
    (static : CheckedExternalTailStaticBinding context authority launch root
      reachability staticContext original candidate candidateAuthority source
      checked)
    (before :
      ExactOriginalSemanticBefore source.targetId originalBefore)
    (site : ExternalCallSiteContract)
    (arguments : List Word) (boundaryState : MachineState) :
    WorldExternalEvent := {
  siteId := site.id
  imported := static.contract.imported
  arguments
  state := boundaryState
  world := before.world
}

/-- One exact PE-backed external-tail step.

`stepExact` fixes the complete transition returned by the decoded world
semantics. In particular, it proves that the transition is not blocked, that
the checked site is selected for the active continuation, that the external
event has the normalized import identity, and that the existing call frame is
consumed. The endpoint is the transition result, never a submitted value. -/
structure CheckedExternalTailOriginalExecution
    (static : CheckedExternalTailStaticBinding context authority launch root
      reachability staticContext original candidate candidateAuthority source
      checked)
    (originalBefore : WorldExecution) : Type where
  atSource :
    originalExecutionAtTargetId source.targetId originalBefore
  before :
    ExactOriginalSemanticBefore source.targetId originalBefore
  continuationTargetId : Nat
  outerCalls : List Nat
  callsExact : before.calls = continuationTargetId :: outerCalls
  site : ExternalCallSiteContract
  siteMember : site ∈ original.externalCallSites
  siteSource : site.sourceTargetId = source.targetId
  siteContinuation : site.continuationTargetId = continuationTargetId
  siteContract : site.machineContractId = static.contract.id
  siteResolved :
    resolveExternalCallSite original.context original.externalCallSites
        source.targetId continuationTargetId static.contract.imported =
      some site.id
  resolvedContract :
    resolvedExternalCallContract? original.context original.externalCallSites
        site.id =
      some static.contract
  arguments : List Word
  boundaryState : MachineState
  stepExact :
    original.pe32TransitionSystem.step originalBefore = {
      next := resumeWorldExecution before.callbacks continuationTargetId
        (original.environment.result before.eventIndex
          (checkedExternalTailEvent static before site arguments
            boundaryState)).state
        outerCalls (before.eventIndex + 1)
        (original.environment.result before.eventIndex
          (checkedExternalTailEvent static before site arguments
            boundaryState)).world
      observation :=
        some (.external before.world static.contract.imported arguments)
    }

def CheckedExternalTailOriginalExecution.replay
    (_execution : CheckedExternalTailOriginalExecution static originalBefore) :
    CheckedOriginalSemanticOperationPath original originalBefore :=
  CheckedOriginalSemanticOperationPath.one original originalBefore

def CheckedExternalTailOriginalExecution.pathShape
    (execution : CheckedExternalTailOriginalExecution static originalBefore) :
    CheckedOriginalSemanticOperationPathShape original originalBefore
      execution.replay :=
  .singleStep rfl

/-- Every actual source admitted by composition has a resolved, returning,
one-step imported-tail execution. The existential witness is selected inside
the adapter; a caller cannot choose replay fuel or an endpoint. -/
def ExactExternalTailOperationalCompleteness
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (checked :
      CheckedFusedOriginalSemanticTransferBinding context authority launch root
        reachability candidate candidateAuthority source)
    (static : CheckedExternalTailStaticBinding context authority launch root
      reachability staticContext original candidate candidateAuthority source
      checked) : Prop :=
  forall originalBefore
      (_atSource :
        originalExecutionAtTargetId source.targetId originalBefore),
    Nonempty (CheckedExternalTailOriginalExecution static originalBefore)

noncomputable def checkedExternalTailExecutionForSource
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (checked :
      CheckedFusedOriginalSemanticTransferBinding context authority launch root
        reachability candidate candidateAuthority source)
    (static : CheckedExternalTailStaticBinding context authority launch root
      reachability staticContext original candidate candidateAuthority source
      checked)
    (complete :
      ExactExternalTailOperationalCompleteness source checked static)
    (originalBefore : WorldExecution)
    (atSource :
      originalExecutionAtTargetId source.targetId originalBefore) :
    CheckedExternalTailOriginalExecution static originalBefore :=
  Classical.choice (complete originalBefore atSource)

/-- State-indexed obligations remaining after exact source, import, site, and
original replay selection.

The checked response trace preserves the exact one-to-one external event
sequence. The mixed observation proof relates the decoded-world event to the
candidate event, while `afterRelated` re-establishes the target invariant at
the two computed endpoints. -/
structure CheckedExternalTailMixedSemanticOperationInput
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (staticContext : StaticProofContext)
    (original : DecodedWorldProgram)
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
    (static :
      CheckedExternalTailStaticBinding context authority launch root
        reachability staticContext original candidate candidateAuthority source
        checked)
    (operational :
      ExactExternalTailOperationalCompleteness source checked static)
    (entryRva : Nat)
    (originalBefore : WorldExecution)
    (atSource :
      originalExecutionAtTargetId source.targetId originalBefore)
    (candidateBefore : NativeWorldExecution)
    (ClassificationEvidence : Prop)
    (beforeRelated : invariant.holds originalBefore candidateBefore)
    (classified : ClassificationEvidence)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) where
  originalState : MachineState
  originalMachineExact :
    originalExecutionMachine? originalBefore = some originalState
  result : MacroResult
  resultExact :
    source.record.interpret environment
        (machineFromFormal originalState) =
      some result
  derivation : CheckedInterpreterStepDerivation
    candidateAuthority.semanticRecords environment resolveCodeTarget
    source.source.target.rva (machineFromFormal originalState)
    (some result)
  semanticResultAtOriginalExit :
    ∃ afterState,
      originalExecutionMachine?
          (CheckedOriginalSemanticOperationPath.one original
            originalBefore).after =
        some afterState ∧
      machineFromFormal afterState = result.state
  candidateMachine : MachineState
  candidateMachineExact :
    candidateBefore.machine? = some candidateMachine
  requestRelated :
    abi.requestRelated
      (.interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva (machineFromFormal originalState))
      candidateMachine
  candidateReplay : forall afterMachine nativeEvents,
    CheckedCandidateKernelDispatchAtBefore dispatches entryRva candidateBefore
      candidateMachine afterMachine nativeEvents ->
      Nonempty (CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents)
  externalTrace : forall afterMachine nativeEvents
      (_dispatchAtBefore :
        CheckedCandidateKernelDispatchAtBefore dispatches entryRva
          candidateBefore candidateMachine afterMachine nativeEvents)
      (_replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents),
    CheckedResponseExternalTrace
      (.interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva (machineFromFormal originalState))
      (.interpreterStep (some result)) nativeEvents
  observationsRelated : forall afterMachine nativeEvents
      (_dispatchAtBefore :
        CheckedCandidateKernelDispatchAtBefore dispatches entryRva
          candidateBefore candidateMachine afterMachine nativeEvents)
      (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents),
    CheckedMixedKernelObservations contract
      (CheckedOriginalSemanticOperationPath.one original
        originalBefore).observations
      replay.path.observations
  afterRelated : forall afterMachine nativeEvents
      (_dispatchAtBefore :
        CheckedCandidateKernelDispatchAtBefore dispatches entryRva
          candidateBefore candidateMachine afterMachine nativeEvents)
      (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents),
    invariant.holds
      (CheckedOriginalSemanticOperationPath.one original
        originalBefore).after
      replay.path.after

noncomputable def CheckedExternalTailMixedSemanticOperationInput.toEvidence
    (input : CheckedExternalTailMixedSemanticOperationInput context authority
      launch root reachability staticContext original candidate
      candidateAuthority contract invariant program abi dispatches source
      checked static operational entryRva originalBefore atSource
      candidateBefore ClassificationEvidence beforeRelated classified
      environment resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence original candidate candidateAuthority
      contract invariant program abi dispatches source.source.target.rva
      source.record .interpreterStep entryRva originalBefore candidateBefore
      ClassificationEvidence beforeRelated classified := by
  let _selected :=
    checkedExternalTailExecutionForSource source checked static operational
      originalBefore atSource
  let originalReplay : CheckedOriginalSemanticOperationPath original
      originalBefore :=
    _selected.replay
  let effect :=
    ExactOriginalSemanticKernelEffect.interpreterStep environment
      resolveCodeTarget (some input.result) input.resultExact input.derivation
  exact {
    before := {
      originalState := input.originalState
      originalMachineExact := input.originalMachineExact
      beforeMachine := input.candidateMachine
      candidateMachineExact := input.candidateMachineExact
      request := .interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva (machineFromFormal input.originalState)
      response := .interpreterStep (some input.result)
      effect
      requestOperationExact := rfl
      requestRelated := input.requestRelated
      originalReplay
      originalPathShape := .singleStep rfl
      originalEffectAfterExact := input.semanticResultAtOriginalExit
    }
    candidateReplay := by
      intro afterMachine nativeEvents dispatched
      exact input.candidateReplay afterMachine nativeEvents {
        beforeMachineExact := input.candidateMachineExact
        dispatched
      }
    close := by
      intro afterMachine nativeEvents dispatched replay
      have dispatchAtBefore : CheckedCandidateKernelDispatchAtBefore dispatches
          entryRva candidateBefore input.candidateMachine afterMachine
          nativeEvents := {
        beforeMachineExact := input.candidateMachineExact
        dispatched
      }
      have _trace := input.externalTrace afterMachine nativeEvents
        dispatchAtBefore replay
      exact {
        observationsChecked :=
          input.observationsRelated afterMachine nativeEvents dispatchAtBefore
            replay
        afterRelated :=
          input.afterRelated afterMachine nativeEvents dispatchAtBefore replay
      }
  }

#print axioms externalTailSemanticCallTarget?
#print axioms checkedExternalTailEvent
#print axioms CheckedExternalTailOriginalExecution.replay
#print axioms CheckedExternalTailOriginalExecution.pathShape
#print axioms checkedExternalTailExecutionForSource
#print axioms CheckedExternalTailMixedSemanticOperationInput.toEvidence

end StageA.Relational.InterpreterMixedExternalTailSemanticEvidenceAdapter
