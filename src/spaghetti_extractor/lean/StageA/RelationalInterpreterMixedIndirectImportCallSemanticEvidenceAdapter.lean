import StageA.RelationalCallableExternalIndirectExit
import StageA.RelationalInterpreterKernelCdeclEpilogueMixedEnvironmentAdapter
import StageA.RelationalInterpreterMixedFusedSemanticEvidenceAdapter

namespace StageA.Relational.InterpreterMixedIndirectImportCallSemanticEvidenceAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalExecution
open StageA.Relational.CallableExternalIndirectExit
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterTransfer
open StageA.Relational.ValueProvenance

/-!
# Indirect and imported call semantic evidence

This module is the generic adapter for a semantic transfer containing exactly
one imported, internal, or runtime-indirect call. Exact normalization binds the
semantic call and call boundary to PE bytes. A checked route then binds that
call to the static import table, code map, or generic finite indirect-control
certificate.

Operational completeness supplies an existential PE-backed replay for each
actual source. The adapter selects that replay internally. Consequently no
caller or generated module can submit path fuel, an endpoint, observations, or
a completion status.

The remaining dynamic premises are intentional:

* the semantic interpreter result must equal the machine at the computed
  original endpoint;
* candidate execution starts at the exact `candidateBefore` world;
* external events must have a checked response trace and related observations;
* the two computed endpoints must re-establish the mixed invariant.
-/

def semanticCallExternalTarget? (call : SemanticCall) :
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

/-- Static route authority for the one exact call in a normalized PE span.

The imported constructor is bound to the checked machine-call and external-site
inventories. The internal constructor is bound to the canonical code map. The
indirect constructors reuse the generic finite-target and callable-capability
certificates, including their universal target-evaluation theorem. -/
inductive CheckedIndirectOrImportSemanticCallRoute
    (context : StaticProofContext) (sourceInvariant : StateInvariant)
    (original : DecodedWorldProgram) (call : SemanticCall) : Type where
  | imported
      (contract : MachineImportCallContract)
      (site : ExternalCallSiteContract)
      (contractMember : contract ∈ context.machineImportCallContracts)
      (siteMember : site ∈ original.externalCallSites)
      (identityExact :
        semanticCallExternalTarget? call = some contract.imported)
      (siteContract : site.machineContractId = contract.id)
      (siteContinuationRva : CodeTargetPair)
      (siteContinuationFound :
        context.codeMap.get? site.continuationTargetId =
          some siteContinuationRva)
      (continuationExact : siteContinuationRva.originalRva = call.returnRva) :
      CheckedIndirectOrImportSemanticCallRoute context sourceInvariant original
        call
  | internal
      (targetId continuationTargetId : Nat)
      (target continuation : CodeTargetPair)
      (kindExact : call.kind = .internal)
      (targetFound : context.codeMap.get? targetId = some target)
      (continuationFound :
        context.codeMap.get? continuationTargetId = some continuation)
      (targetExact : target.originalRva = call.targetRva)
      (continuationExact : continuation.originalRva = call.returnRva) :
      CheckedIndirectOrImportSemanticCallRoute context sourceInvariant original
        call
  | finiteIndirect
      (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
      (certificate : CheckedIndirectExitCertificate context sourceInvariant
        originalBehavior candidateBehavior)
      (continuationTargetId : Nat)
      (kindExact : call.kind = .indirect)
      (transferExact :
        certificate.certificate.transfer =
          .call continuationTargetId) :
      CheckedIndirectOrImportSemanticCallRoute context sourceInvariant original
        call
  | callableIndirect
      (program : OriginalCallableProgram)
      (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
      (certificate : CheckedCallableIndirectExitCertificate program
        sourceInvariant originalBehavior candidateBehavior)
      (contextExact : program.context = context)
      (continuationTargetId : Nat)
      (kindExact : call.kind = .indirect)
      (transferExact :
        certificate.route.indirectCertificate.transfer =
          .call continuationTargetId) :
      CheckedIndirectOrImportSemanticCallRoute context sourceInvariant original
        call

/-- Exact call and call-boundary binding for one fused semantic source.

`singleCall` and `singleBoundary` are propositions over the constants checked
by `ExactProgramRecordNormalizationCertificate`; they cannot be replaced by a
JSON count. -/
structure CheckedIndirectOrImportCallStaticBinding
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (staticContext : StaticProofContext)
    (sourceInvariant : StateInvariant)
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
  singleCall : checked.binding.transfer.calls = [call]
  singleBoundary : checked.binding.path.callBoundaries = [boundary]
  boundaryInstruction :
    ExactCallBoundarySpec.instructionRva boundary = call.instructionRva
  boundaryCallIndex :
    ExactCallBoundarySpec.callIndex boundary = call.callIndex
  route :
    CheckedIndirectOrImportSemanticCallRoute staticContext sourceInvariant
      original call

/-- A computed original replay selected by operational PE/CFG completeness.

The only executable datum is `replay.fuel`; its endpoint and observations are
definitions obtained by running `original.pe32TransitionSystem`. The checked
path shape records either the exact one-step import transition or a complete
call/return cluster with restored call frames. -/
structure CheckedIndirectOrImportOriginalExecution
    (original : DecodedWorldProgram)
    (sourceTargetId : Nat)
    (originalBefore : WorldExecution) : Type where
  atSource : originalExecutionAtTargetId sourceTargetId originalBefore
  replay : CheckedOriginalSemanticOperationPath original originalBefore
  pathShape :
    CheckedOriginalSemanticOperationPathShape original originalBefore replay

/-- Every actual source admitted by composition has a checked returning
execution. This is the proof-producing CFG/call-frame frontier. It returns an
existential checked execution rather than accepting a selected path. -/
def ExactIndirectOrImportCallOperationalCompleteness
    (original : DecodedWorldProgram) (sourceTargetId : Nat) : Prop :=
  forall originalBefore,
    originalExecutionAtTargetId sourceTargetId originalBefore ->
      Nonempty (CheckedIndirectOrImportOriginalExecution original sourceTargetId
        originalBefore)

noncomputable def checkedIndirectOrImportExecutionForSource
    (complete : ExactIndirectOrImportCallOperationalCompleteness original
      sourceTargetId)
    (originalBefore : WorldExecution)
    (atSource : originalExecutionAtTargetId sourceTargetId originalBefore) :
    CheckedIndirectOrImportOriginalExecution original sourceTargetId
      originalBefore :=
  Classical.choice (complete originalBefore atSource)

/-- State-indexed facts that remain after exact source, route, and operational
path selection.

The checked response trace is required separately from observation
relatedness. It ties native external events to the exact semantic call events;
the mixed observation premise then relates their worlds and arguments.
-/
structure CheckedIndirectOrImportMixedSemanticOperationInput
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (reachability :
      ExactOriginalDecodedReachability context authority launch root)
    (staticContext : StaticProofContext)
    (sourceInvariant : StateInvariant)
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
      CheckedIndirectOrImportCallStaticBinding context authority launch root
        reachability staticContext sourceInvariant original candidate
        candidateAuthority source checked)
    (operational :
      ExactIndirectOrImportCallOperationalCompleteness original source.targetId)
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
          (checkedIndirectOrImportExecutionForSource operational originalBefore
            atSource).replay.after =
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
      (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
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
      (checkedIndirectOrImportExecutionForSource operational originalBefore
        atSource).replay.observations
      replay.path.observations
  afterRelated : forall afterMachine nativeEvents
      (_dispatchAtBefore :
        CheckedCandidateKernelDispatchAtBefore dispatches entryRva
          candidateBefore candidateMachine afterMachine nativeEvents)
      (replay : CheckedCandidateKernelOperationReplay candidate candidateBefore
        afterMachine nativeEvents),
    invariant.holds
      (checkedIndirectOrImportExecutionForSource operational originalBefore
        atSource).replay.after
      replay.path.after

/-- Construct mixed semantic evidence from the exact static route and
operational completeness. Candidate replay is anchored at the exact native
world; event trace and invariant closure remain explicit environment/state
premises. -/
noncomputable def CheckedIndirectOrImportMixedSemanticOperationInput.toEvidence
    (input : CheckedIndirectOrImportMixedSemanticOperationInput context
      authority launch root reachability staticContext sourceInvariant original
      candidate candidateAuthority contract invariant program abi dispatches
      source checked static operational entryRva originalBefore atSource
      candidateBefore ClassificationEvidence beforeRelated classified
      environment resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence original candidate candidateAuthority
      contract invariant program abi dispatches source.source.target.rva
      source.record .interpreterStep entryRva originalBefore candidateBefore
      ClassificationEvidence beforeRelated classified := by
  let selected :=
    checkedIndirectOrImportExecutionForSource operational originalBefore
      atSource
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
      originalReplay := selected.replay
      originalPathShape := selected.pathShape
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

#print axioms semanticCallExternalTarget?
#print axioms checkedIndirectOrImportExecutionForSource
#print axioms
  CheckedIndirectOrImportMixedSemanticOperationInput.toEvidence

end StageA.Relational.InterpreterMixedIndirectImportCallSemanticEvidenceAdapter
