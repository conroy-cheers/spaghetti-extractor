import StageA.RelationalInterpreterAcceptance
import StageA.RelationalInterpreterNativeLaunch
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterWorldBridge

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterAcceptance
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87

/-! # Typed decoded-world to native-world composition

The original side executes a `DecodedWorldProgram`; the candidate side executes
an `ExactNativeWorldProgram` at raw candidate RVAs.  This module only composes
typed path proofs supplied by a caller.  It never derives a path from generated
unchecked metadata.
-/

/-- Exact static binding between the decoded original and native candidate.
The two environment types have different operational interfaces and are not
equated. -/
structure ExactWorldNativeProgramBinding (context : StaticProofContext)
    (original : DecodedWorldProgram) (candidate : ExactNativeWorldProgram)
    (originalEnvironment : WorldExternalEnvironment) : Prop where
  originalContext : original.context = context
  originalRole : original.candidate = false
  originalEnvironment : original.environment = originalEnvironment
  candidatePe : candidate.pe = context.candidatePe
  candidateImports : candidate.imports = context.candidateImports

namespace WorldNativeExecution

/-- Terminal decoded/native executions that may take paired silent steps. -/
def QuiescentPair : WorldExecution -> NativeWorldExecution -> Prop
  | .returned _ _, .returned _ _ _ => True
  | .terminated _, .terminated _ _ => True
  | .fault originalCause, .fault candidateCause =>
      originalCause = candidateCause
  | .blocked originalReason, .blocked candidateReason =>
      originalReason = candidateReason
  | _, _ => False

/-- The relational world carried by a live or successfully completed native
execution.  Faulted and blocked states do not carry one. -/
def AtWorld (expected : RelationalWorld) : NativeWorldExecution -> Prop
  | .running _ _ _ _ _ _ world | .returned _ _ world |
      .terminated _ world => world = expected
  | _ => False

end WorldNativeExecution

/-- Re-express a raw native event at a named opaque site so the existing
machine-level boundary relation can compare it with the decoded-world event. -/
def nativeExternalEventToWorldExternalEvent (event : NativeExternalEvent)
    (siteId : Nat) (world : RelationalWorld) : WorldExternalEvent := {
  siteId
  imported := normalizeImport event.imported
  arguments := event.arguments
  state := event.state
  world
}

/-- Pointwise evidence connecting the named decoded-world environment to the
native candidate action semantics.  Returning calls relate the actual results;
terminating calls preserve the current relational world. -/
def WorldNativeExternalEnvironmentRefinesAt (context : StaticProofContext)
    (site : OpaqueLockstepCallSite)
    (original : WorldExternalEnvironment)
    (candidate : NativeWorldEnvironment) : Prop :=
  match site.disposition with
  | .returns =>
      forall eventIndex originalEvent candidateEvent,
        OpaqueLockstepBoundaryRelated context site originalEvent
            (nativeExternalEventToWorldExternalEvent candidateEvent site.id
              originalEvent.world) ->
          exists candidateResult,
            candidate.action eventIndex candidateEvent originalEvent.world =
                .returned candidateResult /\
              OpaqueLockstepResultRelated context site originalEvent
                (nativeExternalEventToWorldExternalEvent candidateEvent site.id
                  originalEvent.world)
                (original.result eventIndex originalEvent) candidateResult
  | .terminates =>
      forall eventIndex originalEvent candidateEvent,
        OpaqueLockstepBoundaryRelated context site originalEvent
            (nativeExternalEventToWorldExternalEvent candidateEvent site.id
              originalEvent.world) ->
          candidate.action eventIndex candidateEvent originalEvent.world =
            .terminated originalEvent.world

/-- Exact external inventory and environment evidence for the heterogeneous
execution pair. -/
structure ExactWorldNativeExternalEvidence (context : StaticProofContext)
    (original : DecodedWorldProgram) (candidate : ExactNativeWorldProgram)
    (sites : List OpaqueLockstepCallSite)
    (originalEnvironment : WorldExternalEnvironment) : Prop where
  contextValid : context.StructurallyValid
  originalCovered : opaqueLockstepCallSitesCoverExternalSites context
    original.externalCallSites sites = true
  sitesUnique : opaqueLockstepCallSiteIdsUnique sites = true
  sitesValid : sites.all (OpaqueLockstepCallSite.staticValid context) = true
  refines : forall site, site ∈ sites ->
    WorldNativeExternalEnvironmentRefinesAt context site originalEnvironment
      candidate.environment

/-- Environment-free compiled-kernel authority.  This retains exact artifact,
CFG, ABI, block-soundness, and semantic-table facts without selecting a fixed
`NativeEnvironment`. -/
structure ExactCompiledInterpreterKernelCore (context : StaticProofContext)
    (programTable : ExactCompiledProgramTable context) where
  binding : KernelArtifactBinding
  program : CompiledKernelProgram
  abi : KernelABIRelation
  artifacts : binding.Valid context.candidatePe
  exactCfg : program.checked context.candidatePe context.candidateImports = true
  blocksSound : forall function, function ∈ program.functions -> forall block,
    block ∈ function.blocks ->
      block.SymbolicExecutionSound context.candidatePe context.candidateImports
  semanticProgram : List ProgramRecord
  semanticProgramBound : semanticProgram = programTable.semanticRecords

/-- The existing fixed-environment certificate can be projected to the
structural core, but contributes no dispatch authority after projection. -/
def ExactCompiledInterpreterKernel.toStructuralCore
    {context : StaticProofContext} {programTable : ExactCompiledProgramTable context}
    (compiledKernel : ExactCompiledInterpreterKernel context programTable) :
    ExactCompiledInterpreterKernelCore context programTable := {
  binding := compiledKernel.binding
  program := compiledKernel.program
  abi := compiledKernel.abi
  artifacts := compiledKernel.certificate.artifacts
  exactCfg := compiledKernel.certificate.exactCfg
  blocksSound := compiledKernel.certificate.blocksSound
  semanticProgram := compiledKernel.semanticProgram
  semanticProgramBound := compiledKernel.semanticProgramBound
}

/-- An approved world-aware dispatch family refines every structural-kernel
operation and is realized by nonempty paths under the exact candidate's actual
`NativeWorldEnvironment`. -/
structure ApprovedCompiledKernelDispatchSemantics
    (context : StaticProofContext)
    (candidate : ExactNativeWorldProgram)
    (programTable : ExactCompiledProgramTable context)
    (kernelCore : ExactCompiledInterpreterKernelCore context programTable) where
  dispatches : RelationalWorld -> KernelDispatchRelation
  operations : forall world operation,
    KernelOperationRefinesUsing kernelCore.program kernelCore.abi
      (dispatches world) operation
  realized : forall world entryRva before after events,
    dispatches world entryRva before after events ->
      exists afterWorld observations,
        NativeWorldDispatches candidate entryRva before world after events
          afterWorld observations

/-- Authorization for a mixed chunk, indexed by every lower proof product that
can affect its semantics. -/
def WorldNativeAuthorized
    (context : StaticProofContext)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (kernelCore : ExactCompiledInterpreterKernelCore context programTable)
    (dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context
      candidate programTable kernelCore)
    (sites : List OpaqueLockstepCallSite)
    (externalEvidence : ExactWorldNativeExternalEvidence context original candidate
      sites originalEnvironment)
    (candidateX87Handler : CandidateReplayHandler)
    (candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
      context.candidatePe context.candidateImports programTable.relocations
      programTable.tableRva programTable.countRva programTable.semanticRecords
      originalX87.witnesses programTable.certificate candidateX87Handler)
    (candidateBefore : NativeWorldExecution) :
    RoundTripChunkKind -> Prop
  | .ordinary sourceRva =>
      sourceRva ∈ originalTransfers.requiredSourceRvas /\
        ExactOriginalTransferRefinementAt context sourceRva /\
        ExactCompiledProgramRecordAt programTable sourceRva /\
        kernelCore.semanticProgram = programTable.semanticRecords /\
        exists world, WorldNativeExecution.AtWorld world candidateBefore /\
          (forall operation, KernelOperationRefinesUsing kernelCore.program
            kernelCore.abi (dispatchSemantics.dispatches world) operation)
  | .x87 sourceRva =>
      sourceRva ∈ originalX87.requiredSourceRvas /\
        (exists witness, witness ∈ originalX87.witnesses /\
          witness.schedule.sourceRva = sourceRva) /\
        ExactCompiledProgramRecordAt programTable sourceRva /\
        kernelCore.semanticProgram = programTable.semanticRecords /\
        (exists world, WorldNativeExecution.AtWorld world candidateBefore /\
          (forall operation, KernelOperationRefinesUsing kernelCore.program
            kernelCore.abi (dispatchSemantics.dispatches world) operation)) /\
        ExactCandidateX87ReplayInventory context.originalPe context.candidatePe
          context.candidateImports programTable.relocations programTable.tableRva
          programTable.countRva programTable.semanticRecords originalX87.witnesses
          programTable.certificate candidateX87Handler
  | .opaqueExternal siteId =>
      exists site, site ∈ sites /\
        site.id = siteId /\
        WorldNativeExternalEnvironmentRefinesAt context site originalEnvironment
          candidate.environment /\
        exists world, WorldNativeExecution.AtWorld world candidateBefore /\
          (forall operation, KernelOperationRefinesUsing kernelCore.program
            kernelCore.abi (dispatchSemantics.dispatches world) operation)
  | .quiescent => True

/-- Classification uses the original decoded source and the observations
actually emitted by both finite paths. -/
def WorldNativeClassifies (context : StaticProofContext)
    (sites : List OpaqueLockstepCallSite)
    (originalBefore : WorldExecution) (candidateBefore : NativeWorldExecution)
    (originalObservations candidateObservations :
      List WorldRelationalObservable) : RoundTripChunkKind -> Prop
  | .ordinary sourceRva | .x87 sourceRva =>
      WorldExecution.AtOriginalRva context sourceRva originalBefore /\
        ¬ ContainsAnyExternalObservation originalObservations /\
        ¬ ContainsAnyExternalObservation candidateObservations
  | .opaqueExternal siteId =>
      exists site, site ∈ sites /\
        site.id = siteId /\
        ContainsExternalObservation site.imported originalObservations /\
        ContainsExternalObservation site.imported candidateObservations
  | .quiescent =>
      WorldNativeExecution.QuiescentPair originalBefore candidateBefore /\
        originalObservations = [] /\ candidateObservations = []

/-- Exhaustive source classification for a related decoded/native state pair. -/
inductive WorldNativeRelatedSourceCase (context : StaticProofContext)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (sites : List OpaqueLockstepCallSite)
    (originalBefore : WorldExecution) (candidateBefore : NativeWorldExecution) : Type where
  | ordinary (sourceRva : Nat)
      (atSource : WorldExecution.AtOriginalRva context sourceRva originalBefore)
      (required : sourceRva ∈ originalTransfers.requiredSourceRvas)
      (world : RelationalWorld)
      (candidateWorld : WorldNativeExecution.AtWorld world candidateBefore)
  | x87 (sourceRva : Nat)
      (atSource : WorldExecution.AtOriginalRva context sourceRva originalBefore)
      (required : sourceRva ∈ originalX87.requiredSourceRvas)
      (witness : ExactInterpreterX87ScheduleWitness context.originalPe)
      (witnessMember : witness ∈ originalX87.witnesses)
      (witnessSource : witness.schedule.sourceRva = sourceRva)
      (world : RelationalWorld)
      (candidateWorld : WorldNativeExecution.AtWorld world candidateBefore)
  | opaqueExternal (site : OpaqueLockstepCallSite)
      (member : site ∈ sites)
      (atSite : WorldExecution.AtTargetId site.sourceTargetId originalBefore)
      (world : RelationalWorld)
      (candidateWorld : WorldNativeExecution.AtWorld world candidateBefore)
  | quiescent
      (paired : WorldNativeExecution.QuiescentPair originalBefore candidateBefore)

/-- One pair of real nonempty paths across the heterogeneous transition
systems. -/
structure WorldNativeComponentChunkRefinement
    (context : StaticProofContext)
    (original : DecodedWorldProgram) (candidate : ExactNativeWorldProgram)
    (executionRelation : WorldExecution -> NativeWorldExecution -> Prop)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (kernelCore : ExactCompiledInterpreterKernelCore context programTable)
    (programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable)
    (dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
      programTable kernelCore)
    (sites : List OpaqueLockstepCallSite)
    (originalEnvironment : WorldExternalEnvironment)
    (externalEvidence : ExactWorldNativeExternalEvidence context original candidate
      sites originalEnvironment)
    (candidateX87Handler : CandidateReplayHandler)
    (candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
      context.candidatePe context.candidateImports programTable.relocations
      programTable.tableRva programTable.countRva programTable.semanticRecords
      originalX87.witnesses programTable.certificate candidateX87Handler)
    (originalBefore : WorldExecution) (candidateBefore : NativeWorldExecution)
    (kind : RoundTripChunkKind) where
  authorized : WorldNativeAuthorized context originalTransfers originalX87
    programTable kernelCore dispatchSemantics sites externalEvidence
    candidateX87Handler candidateX87Replay candidateBefore kind
  originalObservations : List WorldRelationalObservable
  candidateObservations : List WorldRelationalObservable
  originalAfter : WorldExecution
  candidateAfter : NativeWorldExecution
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem originalBefore
    originalObservations originalAfter
  candidatePath : NonemptyRelatedPath candidate.transitionSystem candidateBefore
    candidateObservations candidateAfter
  observationsRelated : RelatedObservationLists
    (worldRelationalObservationsRelated context) originalObservations
    candidateObservations
  classified : WorldNativeClassifies context sites originalBefore candidateBefore
    originalObservations candidateObservations kind
  afterRelated : executionRelation originalAfter candidateAfter

/-- Component-directed composition over decoded original states and raw native
candidate states. -/
structure WorldNativeChunkComposition
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch)
    (original : DecodedWorldProgram) (candidate : ExactNativeWorldProgram)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (kernelCore : ExactCompiledInterpreterKernelCore context programTable)
    (programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable)
    (dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
      programTable kernelCore)
    (sites : List OpaqueLockstepCallSite)
    (originalEnvironment : WorldExternalEnvironment)
    (externalEvidence : ExactWorldNativeExternalEvidence context original candidate
      sites originalEnvironment)
    (programBinding : ExactWorldNativeProgramBinding context original candidate
      originalEnvironment)
    (candidateX87Handler : CandidateReplayHandler)
    (candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
      context.candidatePe context.candidateImports programTable.relocations
      programTable.tableRva programTable.countRva programTable.semanticRecords
      originalX87.witnesses programTable.certificate candidateX87Handler)
    (candidateRootRva : Nat)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva) where
  executionRelation : WorldExecution -> NativeWorldExecution -> Prop
  rootsRelated : forall world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState candidateState ->
      executionRelation
        (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
        (.running candidateRootRva 0 candidateState [] 0 [] world)
  classify : forall originalBefore candidateBefore,
    launch.Valid context graph invariants ->
    launch.Realizable context graph reachability ->
    context.StructurallyValid ->
    ExactWorldNativeProgramBinding context original candidate originalEnvironment ->
    DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva ->
    executionRelation originalBefore candidateBefore ->
      WorldNativeRelatedSourceCase context originalTransfers originalX87 sites
        originalBefore candidateBefore
  ordinaryChunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore -> forall sourceRva,
      WorldExecution.AtOriginalRva context sourceRva originalBefore ->
      sourceRva ∈ originalTransfers.requiredSourceRvas ->
      ExactOriginalTransferRefinementAt context sourceRva ->
      ExactCompiledProgramRecordAt programTable sourceRva ->
      forall world, WorldNativeExecution.AtWorld world candidateBefore ->
      (forall operation, KernelOperationRefinesUsing kernelCore.program
        kernelCore.abi (dispatchSemantics.dispatches world) operation) ->
      WorldNativeComponentChunkRefinement context original candidate
        executionRelation originalTransfers originalX87 programTable kernelCore
        programCoverage dispatchSemantics sites originalEnvironment externalEvidence
        candidateX87Handler candidateX87Replay originalBefore candidateBefore
        (.ordinary sourceRva)
  x87Chunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore -> forall sourceRva,
      WorldExecution.AtOriginalRva context sourceRva originalBefore ->
      sourceRva ∈ originalX87.requiredSourceRvas -> forall witness,
      witness ∈ originalX87.witnesses ->
      witness.schedule.sourceRva = sourceRva ->
      ExactCompiledProgramRecordAt programTable sourceRva ->
      forall world, WorldNativeExecution.AtWorld world candidateBefore ->
      (forall operation, KernelOperationRefinesUsing kernelCore.program
        kernelCore.abi (dispatchSemantics.dispatches world) operation) ->
      ExactCandidateX87ReplayInventory context.originalPe context.candidatePe
        context.candidateImports programTable.relocations programTable.tableRva
        programTable.countRva programTable.semanticRecords originalX87.witnesses
        programTable.certificate candidateX87Handler ->
      WorldNativeComponentChunkRefinement context original candidate
        executionRelation originalTransfers originalX87 programTable kernelCore
        programCoverage dispatchSemantics sites originalEnvironment externalEvidence
        candidateX87Handler candidateX87Replay originalBefore candidateBefore
        (.x87 sourceRva)
  opaqueExternalChunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore -> forall site,
      site ∈ sites ->
      WorldExecution.AtTargetId site.sourceTargetId originalBefore ->
      WorldNativeExternalEnvironmentRefinesAt context site originalEnvironment
        candidate.environment ->
      forall world, WorldNativeExecution.AtWorld world candidateBefore ->
      (forall operation, KernelOperationRefinesUsing kernelCore.program
        kernelCore.abi (dispatchSemantics.dispatches world) operation) ->
      WorldNativeComponentChunkRefinement context original candidate
        executionRelation originalTransfers originalX87 programTable kernelCore
        programCoverage dispatchSemantics sites originalEnvironment externalEvidence
        candidateX87Handler candidateX87Replay originalBefore candidateBefore
        (.opaqueExternal site.id)
  quiescentChunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore ->
      WorldNativeExecution.QuiescentPair originalBefore candidateBefore ->
      WorldNativeComponentChunkRefinement context original candidate
        executionRelation originalTransfers originalX87 programTable kernelCore
        programCoverage dispatchSemantics sites originalEnvironment externalEvidence
        candidateX87Handler candidateX87Replay originalBefore candidateBefore .quiescent

def WorldNativeChunkComposition.componentChunk
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch}
    {original : DecodedWorldProgram} {candidate : ExactNativeWorldProgram}
    {originalTransfers : ExactOriginalTransferInventory context}
    {originalX87 : ExactOriginalX87Inventory context}
    {programTable : ExactCompiledProgramTable context}
    {kernelCore : ExactCompiledInterpreterKernelCore context programTable}
    {programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable}
    {dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
      programTable kernelCore}
    {sites : List OpaqueLockstepCallSite}
    {originalEnvironment : WorldExternalEnvironment}
    {externalEvidence : ExactWorldNativeExternalEvidence context original candidate
      sites originalEnvironment}
    {programBinding : ExactWorldNativeProgramBinding context original candidate
      originalEnvironment}
    {candidateX87Handler : CandidateReplayHandler}
    {candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
      context.candidatePe context.candidateImports programTable.relocations
      programTable.tableRva programTable.countRva programTable.semanticRecords
      originalX87.witnesses programTable.certificate candidateX87Handler}
    {candidateRootRva : Nat}
    {candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva}
    (composition : WorldNativeChunkComposition context graph invariants reachability
      control launch launchChecked original candidate originalTransfers originalX87
      programTable kernelCore programCoverage dispatchSemantics sites
      originalEnvironment externalEvidence programBinding candidateX87Handler
      candidateX87Replay candidateRootRva candidateRoot)
    (originalBefore : WorldExecution) (candidateBefore : NativeWorldExecution)
    (related : composition.executionRelation originalBefore candidateBefore) :
    Sigma fun kind => WorldNativeComponentChunkRefinement context original candidate
      composition.executionRelation originalTransfers originalX87 programTable
      kernelCore programCoverage dispatchSemantics sites originalEnvironment
      externalEvidence candidateX87Handler candidateX87Replay originalBefore
      candidateBefore kind := by
  cases sourceCase : composition.classify originalBefore candidateBefore
      launchChecked.valid launchChecked.realizable externalEvidence.contextValid
      programBinding candidateRoot related with
  | ordinary sourceRva atSource required world candidateWorld =>
      exact ⟨.ordinary sourceRva,
        composition.ordinaryChunk originalBefore candidateBefore related sourceRva
          atSource required (originalTransfers.refinementAt sourceRva required)
          (programCoverage.ordinaryPresent sourceRva required)
          world candidateWorld (dispatchSemantics.operations world)⟩
  | x87 sourceRva atSource required witness witnessMember witnessSource world
      candidateWorld =>
      exact ⟨.x87 sourceRva,
        composition.x87Chunk originalBefore candidateBefore related sourceRva
          atSource required witness witnessMember witnessSource
          (programCoverage.x87Present sourceRva required)
          world candidateWorld (dispatchSemantics.operations world)
          candidateX87Replay⟩
  | opaqueExternal site member atSite world candidateWorld =>
      exact ⟨.opaqueExternal site.id,
        composition.opaqueExternalChunk originalBefore candidateBefore related site
          member atSite (externalEvidence.refines site member)
          world candidateWorld (dispatchSemantics.operations world)⟩
  | quiescent paired =>
      exact ⟨.quiescent,
        composition.quiescentChunk originalBefore candidateBefore related paired⟩

/-- A complete mixed composition is a heterogeneous chunked bisimulation over
the exact decoded and native transition systems. -/
theorem WorldNativeChunkComposition.chunksRefine
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch}
    {original : DecodedWorldProgram} {candidate : ExactNativeWorldProgram}
    {originalTransfers : ExactOriginalTransferInventory context}
    {originalX87 : ExactOriginalX87Inventory context}
    {programTable : ExactCompiledProgramTable context}
    {kernelCore : ExactCompiledInterpreterKernelCore context programTable}
    {programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable}
    {dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
      programTable kernelCore}
    {sites : List OpaqueLockstepCallSite}
    {originalEnvironment : WorldExternalEnvironment}
    {externalEvidence : ExactWorldNativeExternalEvidence context original candidate
      sites originalEnvironment}
    {programBinding : ExactWorldNativeProgramBinding context original candidate
      originalEnvironment}
    {candidateX87Handler : CandidateReplayHandler}
    {candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
      context.candidatePe context.candidateImports programTable.relocations
      programTable.tableRva programTable.countRva programTable.semanticRecords
      originalX87.witnesses programTable.certificate candidateX87Handler}
    {candidateRootRva : Nat}
    {candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva}
    (composition : WorldNativeChunkComposition context graph invariants reachability
      control launch launchChecked original candidate originalTransfers originalX87
      programTable kernelCore programCoverage dispatchSemantics sites
      originalEnvironment externalEvidence programBinding candidateX87Handler
      candidateX87Replay candidateRootRva candidateRoot) :
    ChunkedRelationalBisimulation original.pe32TransitionSystem
      candidate.transitionSystem composition.executionRelation
      (worldRelationalObservationsRelated context) := by
  intro originalBefore candidateBefore related
  obtain ⟨kind, chunk⟩ := composition.componentChunk originalBefore
    candidateBefore related
  exact ⟨chunk.originalObservations, chunk.candidateObservations,
    chunk.originalAfter, chunk.candidateAfter, chunk.originalPath,
    chunk.candidatePath, chunk.observationsRelated, chunk.afterRelated⟩

/-- All exact products needed to assemble the heterogeneous acceptance proof. -/
structure WorldNativeAcceptanceCertificate
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (original : DecodedWorldProgram) (candidate : ExactNativeWorldProgram)
    (originalEnvironment : WorldExternalEnvironment) where
  originalTransfers : ExactOriginalTransferInventory context
  originalX87 : ExactOriginalX87Inventory context
  programTable : ExactCompiledProgramTable context
  kernelCore : ExactCompiledInterpreterKernelCore context programTable
  programCoverage : ExactRoundTripProgramCoverage context originalTransfers
    originalX87 programTable
  dispatchSemantics : ApprovedCompiledKernelDispatchSemantics context candidate
    programTable kernelCore
  sites : List OpaqueLockstepCallSite
  externalEvidence : ExactWorldNativeExternalEvidence context original candidate
    sites originalEnvironment
  programBinding : ExactWorldNativeProgramBinding context original candidate
    originalEnvironment
  candidateX87Handler : CandidateReplayHandler
  candidateX87Replay : ExactCandidateX87ReplayInventory context.originalPe
    context.candidatePe context.candidateImports programTable.relocations
    programTable.tableRva programTable.countRva programTable.semanticRecords
    originalX87.witnesses programTable.certificate candidateX87Handler
  candidateRootRva : Nat
  candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
    candidateRootRva
  launchRoots : ExactRoundTripLaunchRoots context launch
  launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch
  composition : WorldNativeChunkComposition context graph invariants reachability
    control launch launchChecked original candidate originalTransfers originalX87
    programTable kernelCore programCoverage dispatchSemantics sites
    originalEnvironment externalEvidence programBinding candidateX87Handler
    candidateX87Replay candidateRootRva candidateRoot

/-- Exact launch provenance plus a mixed-state chunked bisimulation. -/
def ExactWorldNativeProgramsChunkObservationallyEquivalent
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (original : DecodedWorldProgram) (candidate : ExactNativeWorldProgram)
    (originalEnvironment : WorldExternalEnvironment) : Prop :=
  ExactRoundTripLaunchRoots context launch /\
    ExactWorldNativeProgramBinding context original candidate originalEnvironment /\
    exists candidateRootRva,
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva /\
      launch.Realizable context graph reachability /\
      exists executionRelation : WorldExecution -> NativeWorldExecution -> Prop,
        (forall world originalState candidateState,
          launch.StatesRelated context graph reachability world originalState
              candidateState ->
            executionRelation
              (.running launch.rootTargetId originalState
                launch.continuationTargetIds 0 world)
              (.running candidateRootRva 0 candidateState [] 0 [] world)) /\
        ChunkedRelationalBisimulation original.pe32TransitionSystem
          candidate.transitionSystem executionRelation
          (worldRelationalObservationsRelated context)

/-- Final mixed-state acceptance theorem. -/
theorem worldNativeProgramsEquivalent
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {original : DecodedWorldProgram} {candidate : ExactNativeWorldProgram}
    {originalEnvironment : WorldExternalEnvironment}
    (certificate : WorldNativeAcceptanceCertificate context graph invariants
      reachability control launch original candidate originalEnvironment) :
    ExactWorldNativeProgramsChunkObservationallyEquivalent context graph invariants
      reachability control launch original candidate originalEnvironment := by
  exact ⟨certificate.launchRoots, certificate.programBinding,
    certificate.candidateRootRva, certificate.candidateRoot,
    certificate.launchChecked.realizable,
    certificate.composition.executionRelation,
    certificate.composition.rootsRelated,
    certificate.composition.chunksRefine⟩

/-- Operational form of the acceptance guarantee.  Every pair admitted by the
checked launch relation has related finite observation traces through the exact
original and candidate transition systems. -/
theorem worldNativeProgramsEquivalent_trace
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {original : DecodedWorldProgram} {candidate : ExactNativeWorldProgram}
    {originalEnvironment : WorldExternalEnvironment}
    (certificate : WorldNativeAcceptanceCertificate context graph invariants
      reachability control launch original candidate originalEnvironment)
    (fuel : Nat) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (initial : launch.StatesRelated context graph reachability world
      originalState candidateState) :
    ChunkedRelatedTrace original.pe32TransitionSystem candidate.transitionSystem
      certificate.composition.executionRelation
      (worldRelationalObservationsRelated context) fuel
      (.running launch.rootTargetId originalState
        launch.continuationTargetIds 0 world)
      (.running certificate.candidateRootRva 0 candidateState [] 0 [] world) := by
  apply chunkedRelationalBisimulation_trace original.pe32TransitionSystem
    candidate.transitionSystem certificate.composition.executionRelation
    (worldRelationalObservationsRelated context)
    certificate.composition.chunksRefine fuel
  exact certificate.composition.rootsRelated world originalState candidateState
    initial

#print axioms WorldNativeChunkComposition.chunksRefine
#print axioms worldNativeProgramsEquivalent
#print axioms worldNativeProgramsEquivalent_trace

end StageA.Relational.InterpreterWorldBridge
