import StageA.RelationalInterpreterMixedContext
import StageA.RelationalInterpreterNativeLaunch

namespace StageA.Relational.InterpreterMixedWorldBridge

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Mixed-authority decoded/native acceptance

The decoded original still uses `DecodedWorldProgram`, whose historical value
type contains a paired `StaticProofContext`.  That context is admitted here
only through original-side projections checked against
`ExactOriginalDecodedAuthority`.  Candidate execution, launch roots, imports,
relocations, and program-table facts come exclusively from the exact native
candidate and never from the carrier's candidate code map.

The final theorem is operational: a checked local chunk composition is
iterated into a finite trace over the exact original and candidate transition
systems.  A proof-blocked transition cannot occur in an accepted chunk because
the mixed observation relation rejects it and the execution invariant excludes
blocked endpoints.
-/

/-- Match target identifiers to exact original RVAs without consulting a
paired code map. -/
def OriginalTargetIdsMatchRvas (mapping : OriginalCodeMap) :
    List Nat -> List Nat -> Prop
  | [], [] => True
  | targetId :: targetIds, rva :: rvas =>
      (exists target, mapping.get? targetId = some target /\ target.rva = rva) /\
        OriginalTargetIdsMatchRvas mapping targetIds rvas
  | _, _ => False

/-- The original launch schedule is parsed from the exact original PE and
resolved through its one-sided source index. -/
structure DirectExactOriginalDecodedLaunchRoot
    (context : OriginalDecodedStaticContext)
    (launch : PE32ConsoleLaunchV2) where
  roots : CandidatePELaunchRoots
  rootsParsed : candidatePELaunchRoots? context.pe = some roots
  entryExact : exists target,
    context.codeMap.get? launch.entryTargetId = some target /\
      target.rva = roots.entryRva
  tlsExact : OriginalTargetIdsMatchRvas context.codeMap
    launch.tlsCallbackTargetIds roots.tlsCallbackRvas
  initialExact : launch.rootTargetId = launch.initialTargetId
  rootsDecoded : forall targetId,
    targetId = launch.entryTargetId \/ targetId ∈ launch.tlsCallbackTargetIds ->
      exists source, context.source? targetId = some source /\
        source.region.root = true

/-- Closed over-approximation of original decoded reachability.  Every root is
present and every decoded successor of a reachable source remains present.
Unknown or missing sources cannot be hidden by the inventory. -/
structure ExactOriginalDecodedReachability
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch) where
  targetIds : List Nat
  unique : targetIds.Nodup
  entryReachable : launch.entryTargetId ∈ targetIds
  tlsReachable : forall targetId, targetId ∈ launch.tlsCallbackTargetIds ->
    targetId ∈ targetIds
  sourcesExist : forall targetId, targetId ∈ targetIds ->
    exists source, context.source? targetId = some source
  successorsClosed : forall targetId source,
    targetId ∈ targetIds -> context.source? targetId = some source ->
      forall successor, successor ∈ source.region.targets ->
        successor ∈ targetIds

/-- Exact original-side projection of the legacy decoded-program carrier.
No candidate PE, candidate address, or candidate code-map lookup appears in
this interface.  Both concrete return lookup and indexed indirect lookup are
required to agree with the one-sided original authority. -/
structure ExactDecodedOriginalCarrierBinding
    (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) : Prop where
  originalRole : original.candidate = false
  peBound : original.context.originalPe = context.pe
  importsBound : original.context.originalImports = context.imports
  machineContractsBound :
    original.context.machineImportCallContracts =
      context.machineImportCallContracts
  sourceRegionsBound : forall targetId source,
    context.source? targetId = some source ->
      exists region, regionById original.regions targetId = some region /\
        region.id = source.target.id /\
        region.original = source.region.span /\
        region.root = source.region.root /\
        region.targets.map (fun target => target.id) = source.region.targets
  regionsHaveSources : forall region, region ∈ original.regions ->
    exists source, context.source? region.id = some source /\
      region.original = source.region.span /\
      region.targets.map (fun target => target.id) = source.region.targets
  originalTargetsBound : forall region, region ∈ original.regions ->
    forall target, target ∈ region.targets ->
      exists originalTarget, context.codeMap.get? target.id = some originalTarget /\
        target.originalRva = originalTarget.rva /\
        target.originalAliases = originalTarget.aliases
  indexedIndirectResolutionBound : forall address,
    original.context.codeMap.resolveRawEip false context.pe.imageBase address =
      context.codeMap.resolveRawEip context.pe.imageBase address
  concreteReturnResolutionBound : forall address,
    resolveMappedCodeTarget false context.pe.imageBase
        original.context.codeMap.entries.toList address =
      context.codeMap.resolveRawEip context.pe.imageBase address

/-- The legacy carrier contributes only the original artifact projections
listed above.  In particular, the native candidate is bound directly to its
own exact authority. -/
structure ExactMixedProgramBinding
    (originalContext : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) : Prop where
  original : ExactDecodedOriginalCarrierBinding originalContext original

/-- Attach callable-resource execution to an already checked decoded carrier.
The static PE, decoded regions, ordinary external environment, and protocol
environment are preserved definitionally. -/
def decodedWorldProgramWithCallable
    (decoded : DecodedWorldProgram)
    (program :
      StageA.Relational.CallableExternalExecution.OriginalCallableProgram)
    (environment :
      StageA.Relational.CallableExternalExecution.OriginalCallableExternalEnvironment) :
    DecodedWorldProgram := {
  decoded with
  callableProgram := some program
  callableEnvironment := some environment
}

def ExactDecodedOriginalCarrierBinding.withCallable
    (binding : ExactDecodedOriginalCarrierBinding context decoded)
    (program :
      StageA.Relational.CallableExternalExecution.OriginalCallableProgram)
    (environment :
      StageA.Relational.CallableExternalExecution.OriginalCallableExternalEnvironment) :
    ExactDecodedOriginalCarrierBinding context
      (decodedWorldProgramWithCallable decoded program environment) := {
  originalRole := binding.originalRole
  peBound := binding.peBound
  importsBound := binding.importsBound
  machineContractsBound := binding.machineContractsBound
  sourceRegionsBound := binding.sourceRegionsBound
  regionsHaveSources := binding.regionsHaveSources
  originalTargetsBound := binding.originalTargetsBound
  indexedIndirectResolutionBound := binding.indexedIndirectResolutionBound
  concreteReturnResolutionBound := binding.concreteReturnResolutionBound
}

def ExactMixedProgramBinding.withCallable
    (binding : ExactMixedProgramBinding context decoded)
    (program :
      StageA.Relational.CallableExternalExecution.OriginalCallableProgram)
    (environment :
      StageA.Relational.CallableExternalExecution.OriginalCallableExternalEnvironment) :
    ExactMixedProgramBinding context
      (decodedWorldProgramWithCallable decoded program environment) := {
  original := binding.original.withCallable program environment
}

/-- Initial states for the mixed theorem.  This replaces the historical
paired launch-state predicate. -/
def MixedLaunchStatesRelated
    (originalContext : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) : Prop :=
  PreferredBaseImageMemory originalContext.pe originalContext.imports
      originalState.memory /\
    PreferredBaseImageMemory candidate.pe candidate.imports
      candidateState.memory /\
    contract.worldsRelated originalWorld candidateWorld /\
    contract.launchStatesRelated originalWorld candidateWorld
      originalState candidateState

def MixedLaunchRealizable
    (originalContext : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract) : Prop :=
  exists originalWorld candidateWorld originalState candidateState,
    MixedLaunchStatesRelated originalContext candidate contract
      originalWorld candidateWorld originalState candidateState

def originalCallbackTargetsReachable (targetIds : List Nat) :
    List WorldExternalCallbackRuntime -> Prop
  | [] => True
  | callback :: callbacks =>
      callback.entry.targetId ∈ targetIds /\
        originalCallbackTargetsReachable targetIds callbacks

/-- Original executions remain inside the checked reachable closure.  A
proof-blocked state is never considered reachable proof state. -/
def OriginalExecutionReachable (targetIds : List Nat) : WorldExecution -> Prop
  | .running targetId _ calls _ _ =>
      targetId ∈ targetIds /\
        forall continuation, continuation ∈ calls -> continuation ∈ targetIds
  | .callbackRunning targetId _ calls _ _ callbacks =>
      targetId ∈ targetIds /\
        (forall continuation, continuation ∈ calls -> continuation ∈ targetIds) /\
        originalCallbackTargetsReachable targetIds callbacks
  | .awaitingExternal suspension callbacks =>
      suspension.sourceTargetId ∈ targetIds /\
        suspension.continuationTargetId ∈ targetIds /\
        (forall continuation, continuation ∈ suspension.calls ->
          continuation ∈ targetIds) /\
        originalCallbackTargetsReachable targetIds callbacks
  | .returned .. | .terminated .. | .fault .. => True
  | .blocked _ => False

def NativeExecutionProofOpen : NativeWorldExecution -> Prop
  | .blocked _ => False
  | _ => True

def originalExecutionWorld? : WorldExecution -> Option RelationalWorld
  | .running _ _ _ _ world | .returned _ world | .terminated world |
      .callbackRunning _ _ _ _ world _ => some world
  | .awaitingExternal suspension _ => some suspension.world
  | .fault _ | .blocked _ => none

def originalExecutionMachine? : WorldExecution -> Option MachineState
  | .running _ state .. | .returned state _ |
      .callbackRunning _ state .. => some state
  | .awaitingExternal suspension _ => some suspension.state
  | .terminated _ | .fault _ | .blocked _ => none

def nativeExecutionWorld? : NativeWorldExecution -> Option RelationalWorld
  | .running _ _ _ _ _ _ world | .returned _ _ world |
      .terminated _ world => some world
  | .fault _ | .blocked _ => none

/-- A proof invariant over heterogeneous execution states.  Its runtime facts
are expressed only through `MixedRelationContract`; it cannot inherit the
legacy paired state relation. -/
structure MixedExecutionInvariant
    (reachabilityTargetIds : List Nat)
    (contract : MixedRelationContract) where
  holds : WorldExecution -> NativeWorldExecution -> Prop
  originalReachable : forall original candidate,
    holds original candidate -> OriginalExecutionReachable reachabilityTargetIds original
  candidateProofOpen : forall original candidate,
    holds original candidate -> NativeExecutionProofOpen candidate
  worldsRelated : forall original candidate originalWorld candidateWorld,
    holds original candidate ->
      originalExecutionWorld? original = some originalWorld ->
      nativeExecutionWorld? candidate = some candidateWorld ->
      contract.worldsRelated originalWorld candidateWorld
  runtimeStatesRelated : forall original candidate originalWorld candidateWorld
      originalState candidateState,
    holds original candidate ->
      originalExecutionWorld? original = some originalWorld ->
      nativeExecutionWorld? candidate = some candidateWorld ->
      originalExecutionMachine? original = some originalState ->
      candidate.machine? = some candidateState ->
      contract.runtimeStatesRelated originalWorld candidateWorld
        originalState candidateState

/-- One checked pair of nonempty operational paths.  Observations are related
pointwise by the mixed contract, and the successor must re-establish the same
proof invariant. -/
structure MixedWorldComponentChunkRefinement
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (invariant : MixedExecutionInvariant reachabilityTargetIds contract)
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) where
  beforeRelated : invariant.holds originalBefore candidateBefore
  originalObservations : List WorldRelationalObservable
  candidateObservations : List WorldRelationalObservable
  originalAfter : WorldExecution
  candidateAfter : NativeWorldExecution
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem
    originalBefore originalObservations originalAfter
  candidatePath : NonemptyRelatedPath candidate.transitionSystem
    candidateBefore candidateObservations candidateAfter
  observationsRelated : RelatedObservationLists
    contract.eventObservationsRelated originalObservations candidateObservations
  afterRelated : invariant.holds originalAfter candidateAfter

/-- Complete local composition, indexed by both exact authorities and both
direct launch-root proofs.  The only submitted semantic objects are nonempty
path refinements and their inductive invariant. -/
structure MixedWorldChunkComposition
    (originalContext : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority originalContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (programBinding : ExactMixedProgramBinding originalContext original)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch)
    (reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot)
    (candidateRootRva : Nat)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva) where
  invariant : MixedExecutionInvariant reachability.targetIds contract
  candidateLaunchCalls : MachineState -> List NativeCallFrame
  candidateLaunchCallsExact : forall candidateState,
    candidateNativeLaunchCallFrames? candidate launch candidateState =
      some (candidateLaunchCalls candidateState)
  rootsRelated : forall originalWorld candidateWorld originalState candidateState,
    MixedLaunchStatesRelated originalContext candidate contract
        originalWorld candidateWorld originalState candidateState ->
      invariant.holds
        (.running launch.rootTargetId originalState
          launch.continuationTargetIds 0 originalWorld)
        (.running candidateRootRva 0 candidateState
          (candidateLaunchCalls candidateState) 0 [] candidateWorld)
  component : forall originalBefore candidateBefore,
    invariant.holds originalBefore candidateBefore ->
      MixedWorldComponentChunkRefinement original candidate contract invariant
        originalBefore candidateBefore

theorem MixedWorldChunkComposition.chunksRefine
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva}
    (composition : MixedWorldChunkComposition originalContext originalAuthority
      original candidate candidateAuthority programBinding contract launch originalRoot
      reachability candidateRootRva candidateRoot) :
    ChunkedRelationalBisimulation original.pe32TransitionSystem
      candidate.transitionSystem composition.invariant.holds
      contract.eventObservationsRelated := by
  intro originalBefore candidateBefore related
  let chunk := composition.component originalBefore candidateBefore related
  exact ⟨chunk.originalObservations, chunk.candidateObservations,
    chunk.originalAfter, chunk.candidateAfter, chunk.originalPath,
    chunk.candidatePath, chunk.observationsRelated, chunk.afterRelated⟩

/-- All immutable authorities and compositional evidence required for mixed
decoded/native acceptance.  There are no submitted verdict or status fields. -/
structure MixedWorldAcceptanceCertificate
    (originalContext : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2) where
  originalAuthority : ExactOriginalDecodedAuthority originalContext
  candidateAuthority : ExactNativeCandidateAuthority candidate
  programBinding : ExactMixedProgramBinding originalContext original
  originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch
  reachability : ExactOriginalDecodedReachability originalContext
    originalAuthority launch originalRoot
  candidateRootRva : Nat
  candidateRoot : DirectExactCandidateNativeLaunchRoot candidate launch
    candidateRootRva
  launchRealizable : MixedLaunchRealizable originalContext candidate contract
  composition : MixedWorldChunkComposition originalContext originalAuthority
    original candidate candidateAuthority programBinding contract launch originalRoot
    reachability candidateRootRva candidateRoot

/-- The structural acceptance result exposed to downstream theorem bundles. -/
def ExactMixedWorldProgramsChunkObservationallyEquivalent
    (originalContext : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2) : Prop :=
  MixedLaunchRealizable originalContext candidate contract /\
    ExactMixedProgramBinding originalContext original /\
    exists originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext launch,
      exists originalAuthority : ExactOriginalDecodedAuthority originalContext,
        exists reachability : ExactOriginalDecodedReachability originalContext
            originalAuthority launch originalRoot,
          Nonempty (ExactNativeCandidateAuthority candidate) /\
            exists candidateRootRva,
              DirectExactCandidateNativeLaunchRoot candidate launch
                  candidateRootRva /\
                exists candidateLaunchCalls : MachineState -> List NativeCallFrame,
                  (forall candidateState,
                    candidateNativeLaunchCallFrames? candidate launch candidateState =
                      some (candidateLaunchCalls candidateState)) /\
                  exists invariant : MixedExecutionInvariant
                      reachability.targetIds contract,
                    (forall originalWorld candidateWorld originalState candidateState,
                      MixedLaunchStatesRelated originalContext candidate contract
                          originalWorld candidateWorld originalState candidateState ->
                        invariant.holds
                          (.running launch.rootTargetId originalState
                            launch.continuationTargetIds 0 originalWorld)
                          (.running candidateRootRva 0 candidateState
                            (candidateLaunchCalls candidateState) 0 []
                            candidateWorld)) /\
                      ChunkedRelationalBisimulation original.pe32TransitionSystem
                        candidate.transitionSystem invariant.holds
                        contract.eventObservationsRelated

theorem mixedWorldProgramsEquivalent
    {originalContext : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    (certificate : MixedWorldAcceptanceCertificate originalContext original
      candidate contract launch) :
    ExactMixedWorldProgramsChunkObservationallyEquivalent originalContext
      original candidate contract launch := by
  exact ⟨certificate.launchRealizable, certificate.programBinding,
    certificate.originalRoot, certificate.originalAuthority,
    certificate.reachability, ⟨certificate.candidateAuthority⟩,
    certificate.candidateRootRva, certificate.candidateRoot,
    certificate.composition.candidateLaunchCalls,
    certificate.composition.candidateLaunchCallsExact,
    certificate.composition.invariant,
    certificate.composition.rootsRelated,
    certificate.composition.chunksRefine⟩

/-- Operational finite-trace consequence of the mixed acceptance certificate.
Both roots come from exact PE parsing, and every emitted event is related
pointwise by `MixedRelationContract.eventObservationsRelated`. -/
theorem mixedWorldProgramsEquivalent_trace
    {originalContext : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate : ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    (certificate : MixedWorldAcceptanceCertificate originalContext original
      candidate contract launch)
    (fuel : Nat)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState)
    (initial : MixedLaunchStatesRelated originalContext candidate contract
      originalWorld candidateWorld originalState candidateState) :
    ChunkedRelatedTrace original.pe32TransitionSystem candidate.transitionSystem
      certificate.composition.invariant.holds
      contract.eventObservationsRelated fuel
      (.running launch.rootTargetId originalState
        launch.continuationTargetIds 0 originalWorld)
      (.running certificate.candidateRootRva 0 candidateState
        (certificate.composition.candidateLaunchCalls candidateState) 0 []
        candidateWorld) := by
  apply chunkedRelationalBisimulation_trace original.pe32TransitionSystem
    candidate.transitionSystem certificate.composition.invariant.holds
    contract.eventObservationsRelated
    certificate.composition.chunksRefine fuel
  exact certificate.composition.rootsRelated originalWorld candidateWorld
    originalState candidateState initial

#print axioms MixedWorldChunkComposition.chunksRefine
#print axioms mixedWorldProgramsEquivalent
#print axioms mixedWorldProgramsEquivalent_trace

end StageA.Relational.InterpreterMixedWorldBridge
