import StageA.RelationalInterpreterMixedOriginalSemanticReplay

namespace StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedOriginalSemanticReplay
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.InterpreterTransfer

/-!
# Fused semantic evidence adapter

Generated exact-span shards prove the universal machine equality between one
fused PE span and its checked semantic transfer. This module retains that
theorem alongside the exact source binding, then uses it to construct the
original half of an ordinary one-step mixed operation.

The adapter accepts no path, endpoint, observation list, or completion status.
Both paths are computed by the existing checked runners. Candidate replay and
the endpoint invariant remain explicit relational proof obligations.
-/

/-- An exact source binding paired with the cached fused-span theorem for the
same source span and transfer. -/
structure CheckedFusedOriginalSemanticTransferBinding
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority) where
  binding : ExactOriginalSemanticTransferBinding context authority launch root
    reachability candidate candidateAuthority source
  fused :
    ExactSemanticTransferFusedMachineRefinement context.pe context.imports
      source.source.region.span binding.transfer

theorem CheckedFusedOriginalSemanticTransferBinding.sequentialFusion
    (checked : CheckedFusedOriginalSemanticTransferBinding context authority
      launch root reachability candidate candidateAuthority source)
    (sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source) :
    ExactOriginalSemanticSequentialFusion context authority launch root
      reachability candidate candidateAuthority source checked.binding original
      sourceFacts :=
  ExactOriginalSemanticSequentialFusion.ofFusedMachineRefinement
    checked.binding sourceFacts checked.fused

/-- A machine-level dispatch explicitly anchored to the machine extracted from
one exact candidate world. `KernelDispatchRelation` itself is not world-indexed;
this checked wrapper is the premise used when lifting it to an exact native
path from `candidateBefore`. -/
structure CheckedCandidateKernelDispatchAtBefore
    (dispatches : KernelDispatchRelation)
    (entryRva : Nat)
    (candidateBefore : NativeWorldExecution)
    (beforeMachine afterMachine : MachineState)
    (nativeEvents : List NativeExternalEvent) : Prop where
  beforeMachineExact : candidateBefore.machine? = some beforeMachine
  dispatched :
    dispatches entryRva beforeMachine afterMachine nativeEvents

/-- The retained native operation path starts at the exact candidate world,
not merely at a submitted machine state. -/
theorem CheckedCandidateKernelOperationReplay.pathFromCandidateBefore
    (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
      afterMachine nativeEvents) :
    NonemptyRelatedPath candidate.transitionSystem candidateBefore
      replay.path.observations replay.path.after :=
  replay.path.path

/-- Remaining state-indexed facts for one ordinary interpreter-step operation.
The original result and endpoint are recomputed from the exact record and PE
transition. The candidate path and relational closure cannot be inferred from
static source data and therefore remain proof fields. -/
structure CheckedOrdinaryMixedSemanticOperationInput
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
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
    (entryRva : Nat)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution)
    (ClassificationEvidence : Prop)
    (beforeRelated : invariant.holds originalBefore candidateBefore)
    (classified : ClassificationEvidence)
    (sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source)
    (stepFacts : ExactOrdinaryOriginalSemanticStepFacts original source.targetId
      sourceFacts originalBefore)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) where
  result : MacroResult
  resultExact :
    source.record.interpret environment
        (machineFromFormal stepFacts.before.state) =
      some result
  derivation : CheckedInterpreterStepDerivation
    candidateAuthority.semanticRecords environment resolveCodeTarget
    source.source.target.rva (machineFromFormal stepFacts.before.state)
    (some result)
  candidateMachine : MachineState
  candidateMachineExact :
    candidateBefore.machine? = some candidateMachine
  requestRelated :
    abi.requestRelated
      (.interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva
        (machineFromFormal stepFacts.before.state))
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
    CheckedMixedSemanticOperationClosure original candidate contract invariant
      originalBefore candidateBefore
      (checkedOrdinaryOriginalSemanticPath original originalBefore) replay

/-- Construct ordinary one-step mixed evidence from the cached fused theorem.
The original replay has fuel one by construction, and its endpoint equality is
derived by `CheckedOrdinaryOriginalInterpreterStepReplay.ofExact`. -/
noncomputable def CheckedOrdinaryMixedSemanticOperationInput.toEvidence
    (input : CheckedOrdinaryMixedSemanticOperationInput context authority launch
      root reachability original candidate candidateAuthority contract invariant
      program abi dispatches source checked entryRva originalBefore
      candidateBefore ClassificationEvidence beforeRelated classified
      sourceFacts stepFacts environment resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence original candidate candidateAuthority
      contract invariant program abi dispatches source.source.target.rva
      source.record .interpreterStep entryRva originalBefore candidateBefore
      ClassificationEvidence beforeRelated classified := by
  let effect := exactOrdinaryOriginalInterpreterStepEffect candidateAuthority
    source stepFacts.before.state environment resolveCodeTarget input.result
    input.resultExact input.derivation
  have originalReplay :=
    CheckedOrdinaryOriginalInterpreterStepReplay.ofExact checked.binding
      (checked.sequentialFusion sourceFacts) input.resultExact input.derivation
  exact {
    before := {
      originalState := stepFacts.before.state
      originalMachineExact := stepFacts.originalMachineExact
      beforeMachine := input.candidateMachine
      candidateMachineExact := input.candidateMachineExact
      request := .interpreterStep candidateAuthority.semanticRecords environment
        source.source.target.rva
        (machineFromFormal stepFacts.before.state)
      response := .interpreterStep (some input.result)
      effect
      requestOperationExact := rfl
      requestRelated := input.requestRelated
      originalReplay :=
        checkedOrdinaryOriginalSemanticPath original originalBefore
      originalPathShape :=
        checkedOrdinaryOriginalSemanticPathShape original originalBefore
      originalEffectAfterExact := originalReplay.endpointMatches
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

#print axioms
  CheckedFusedOriginalSemanticTransferBinding.sequentialFusion
#print axioms
  CheckedCandidateKernelOperationReplay.pathFromCandidateBefore
#print axioms CheckedOrdinaryMixedSemanticOperationInput.toEvidence

end StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
