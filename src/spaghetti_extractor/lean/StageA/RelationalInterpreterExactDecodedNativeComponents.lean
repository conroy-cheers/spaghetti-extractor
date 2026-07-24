import StageA.RelationalInterpreterExactDecodedNativeAdapter
import StageA.RelationalInterpreterKernelX87Execution

namespace StageA.Relational.InterpreterExactDecodedNativeComponents

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterExactDecodedNativeAdapter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelX87Execution
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWholeProgramAcceptance
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget

/-!
# Checked exact decoded/native component assembly

This layer replaces generator-supplied arbitrary chunk factories with four
typed execution-certificate families.  A deterministic classifier examines
the exact candidate decoded behavior and the checked kernel inventory.  A
totality proof may only return one of those checked families or one of the
three exact terminal shapes; there is no unknown or fallback constructor.

The family certificates remain local.  They contain nonempty paths produced
by the existing launch replay, operation, external-boundary, and x87 replay
interfaces.  Exact observation equality and re-establishment of the carrier
relation are checked before a certificate can become an acceptance chunk.
-/

/-- Equality on the exact candidate carrier, expressed through the existing
mixed component interfaces. -/
def exactDecodedNativeIdentityContract : MixedRelationContract := {
  worldsRelated := fun original candidate => original = candidate
  launchStatesRelated := fun originalWorld candidateWorld original candidate =>
    originalWorld = candidateWorld /\ original = candidate
  runtimeStatesRelated := fun originalWorld candidateWorld original candidate =>
    originalWorld = candidateWorld /\ original = candidate
  valuesRelated := fun originalWorld candidateWorld original candidate =>
    originalWorld = candidateWorld /\ original = candidate
  callbackTargetsRelated := fun original candidate => original = candidate
}

theorem mixedValuesRelated_identity_eq
    {originalWorld candidateWorld : RelationalWorld}
    {original candidate : List Word}
    (related : mixedValuesRelated
      (exactDecodedNativeIdentityContract.valuesRelated
        originalWorld candidateWorld)
      original candidate) :
    original = candidate := by
  induction original generalizing candidate with
  | nil =>
      cases candidate <;>
        simp_all [mixedValuesRelated]
  | cons head tail induction =>
      cases candidate with
      | nil => simp [mixedValuesRelated] at related
      | cons candidateHead candidateTail =>
          simp only [mixedValuesRelated] at related
          rcases related with ⟨headRelated, tailRelated⟩
          have headExact : head = candidateHead := by
            exact headRelated.2
          have tailExact : tail = candidateTail := induction tailRelated
          simp [headExact, tailExact]

theorem exactDecodedNativeIdentityObservation_eq
    {original candidate : Option WorldRelationalObservable}
    (related :
      exactDecodedNativeIdentityContract.eventObservationsRelated
        original candidate) :
    original = candidate := by
  cases original with
  | none =>
      cases candidate <;>
        simp_all [MixedRelationContract.eventObservationsRelated]
  | some original =>
      cases candidate with
      | none =>
          simp [MixedRelationContract.eventObservationsRelated] at related
      | some candidate =>
          cases original <;> cases candidate <;>
            simp_all [MixedRelationContract.eventObservationsRelated,
              exactDecodedNativeIdentityContract]
          case external.external originalWorld originalImport originalArguments
              candidateWorld candidateImport candidateArguments =>
            have argumentsExact : originalArguments = candidateArguments := by
              exact mixedValuesRelated_identity_eq related.2.2
            cases related.1
            cases related.2.1
            cases argumentsExact
            rfl
          case callableExternal.callableExternal originalEvent candidateEvent =>
            have argumentsExact :
                originalEvent.arguments = candidateEvent.arguments := by
              exact mixedValuesRelated_identity_eq related.2.2.2
            cases originalEvent
            cases candidateEvent
            simp_all

theorem exactDecodedNativeIdentityObservationLists_eq
    {original candidate : List WorldRelationalObservable}
    (related : RelatedObservationLists
      exactDecodedNativeIdentityContract.eventObservationsRelated
      original candidate) :
    original = candidate := by
  induction original generalizing candidate with
  | nil =>
      cases candidate <;> simp_all [RelatedObservationLists]
  | cons head tail induction =>
      cases candidate with
      | nil => simp [RelatedObservationLists] at related
      | cons candidateHead candidateTail =>
          rcases related with ⟨headRelated, tailRelated⟩
          have headExact : head = candidateHead :=
            Option.some.inj
              (exactDecodedNativeIdentityObservation_eq headRelated)
          have tailExact : tail = candidateTail := induction tailRelated
          simp [headExact, tailExact]

inductive ExactDecodedNativeExecutableFamily where
  | launchWrapper
  | kernelOperation (operation : KernelOperation) (entryRva : Nat)
  | externalBoundary
  | x87Replay
deriving Repr, DecidableEq

def exactDecodedNativeOperationForRole? : KernelRole ->
    Option KernelOperation
  | .programLookup => some .programLookup
  | .interpreterStep => some .interpreterStep
  | .runFunction => some .runFunction
  | .invokeCall => some .invokeCall
  | .helper _ => none

/-- Resolve an RVA to one required operation only when exactly one checked
kernel function owns that node. -/
def exactDecodedNativeOperationAtNode?
    (program : CompiledKernelProgram) (rva : Nat) :
    Option (KernelOperation × Nat) :=
  match program.functions.filter fun function =>
      function.nodeEntries.contains rva with
  | [function] => do
      let operation <- exactDecodedNativeOperationForRole? function.role
      pure (operation, function.span.start)
  | _ => none

def exactDecodedNativeOutcomeIsExternal : PureOutcome -> Bool
  | .externalCall .. | .externalJump .. => true
  | _ => false

/-- Closed executable-family decision from exact candidate PE behavior.

Failure to find a region, decode its exact bytes, uniquely assign a kernel
node, or recognize one of the four supported families returns `none`.
-/
def exactDecodedNativeExecutableFamily?
    (decoded : DecodedWorldProgram)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2)
    (targetId : Nat) (state : MachineState) (calls : List Nat) :
    Option ExactDecodedNativeExecutableFamily := do
  let region <- regionById decoded.regions targetId
  let behavior <-
    pe32WorldRegionBehaviorWithCalls decoded targetId state calls
  if targetId == launch.rootTargetId then
    pure .launchWrapper
  else if StageA.Relational.X87.spanStartsWithX87Command
      decoded.context.candidatePe region.candidate then
    pure .x87Replay
  else if exactDecodedNativeOutcomeIsExternal behavior.outcome then
    pure .externalBoundary
  else
    let (operation, entryRva) <-
      exactDecodedNativeOperationAtNode? program region.candidate.start
    pure (.kernelOperation operation entryRva)

def ExactDecodedNativeExecutableFamily.Valid
    (program : CompiledKernelProgram) :
    ExactDecodedNativeExecutableFamily -> Prop
  | .kernelOperation operation entryRva =>
      program.functionEntry? operation.role = some entryRva
  | .launchWrapper | .externalBoundary | .x87Replay => True

/-- Dependent classifier result.  Executable cases carry the equation returned
by the exact behavior classifier and the operation-entry fact needed by the
kernel theorem.  Terminal constructors preserve their exact carrier shapes.
There are deliberately no callback, suspension, blocked, or catch-all cases
in the base native profile. -/
inductive ExactDecodedNativeCheckedSourceCase
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2) :
    WorldExecution -> NativeWorldExecution -> Type where
  | executable
      (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (nativeBefore : NativeWorldExecution)
      (family : ExactDecodedNativeExecutableFamily)
      (classified : exactDecodedNativeExecutableFamily? decoded program launch
        targetId state calls = some family)
      (valid : family.Valid program) :
      ExactDecodedNativeCheckedSourceCase decoded native program launch
        (.running targetId state calls eventIndex world) nativeBefore
  | returned
      (decodedState nativeState : MachineState)
      (world : RelationalWorld) (events : List NativeExternalEvent) :
      ExactDecodedNativeCheckedSourceCase decoded native program launch
        (.returned decodedState world)
        (.returned nativeState events world)
  | terminated (world : RelationalWorld)
      (events : List NativeExternalEvent) :
      ExactDecodedNativeCheckedSourceCase decoded native program launch
        (.terminated world) (.terminated events world)
  | fault (cause : ModeledFault) :
      ExactDecodedNativeCheckedSourceCase decoded native program launch
        (.fault cause) (.fault cause)

/-- Total only over states admitted by the carrier invariant.  Since the
codomain has no unsupported constructor, a blocked, callback, suspension, or
unclassified executable state makes this proposition uninhabitable. -/
structure ExactDecodedNativeTotalClassifier
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (program : CompiledKernelProgram)
    (launch : PE32ConsoleLaunchV2)
    (relation : WorldExecution -> NativeWorldExecution -> Prop) where
  classify : forall decodedBefore nativeBefore,
    relation decodedBefore nativeBefore ->
      ExactDecodedNativeCheckedSourceCase decoded native program launch
        decodedBefore nativeBefore

def ExactDecodedNativeCheckedSourceCase.toAdapterCase
    (source : ExactDecodedNativeCheckedSourceCase decoded native program launch
      decodedBefore nativeBefore) :
    ExactDecodedNativeSourceCase program decodedBefore nativeBefore := by
  cases source with
  | executable targetId state calls eventIndex world nativeBefore family
      classified valid =>
      cases family with
      | launchWrapper => exact .launchWrapper
      | kernelOperation operation entryRva =>
          exact .kernelOperation operation entryRva valid
      | externalBoundary => exact .externalBoundary
      | x87Replay => exact .x87Replay
  | returned decodedState nativeState world events =>
      exact .returned decodedState nativeState world events
  | terminated world events => exact .terminated world events
  | fault cause => exact .fault cause

/-- Finite path whose endpoint and observations are computed from the exact
transition system.  Generated evidence supplies only positive fuel. -/
structure ExactComputedNonemptySegment
    {state observation : Type}
    (system : RelatedTransitionSystem state observation)
    (before : state) where
  fuel : Nat
  positive : 0 < fuel

def ExactComputedNonemptySegment.result
    {state observation : Type}
    {system : RelatedTransitionSystem state observation}
    {before : state}
    (segment : ExactComputedNonemptySegment system before) :
    state × List observation :=
  runRelatedSteps system segment.fuel before

def ExactComputedNonemptySegment.after
    {state observation : Type}
    {system : RelatedTransitionSystem state observation}
    {before : state}
    (segment : ExactComputedNonemptySegment system before) : state :=
  segment.result.1

def ExactComputedNonemptySegment.observations
    {state observation : Type}
    {system : RelatedTransitionSystem state observation}
    {before : state}
    (segment : ExactComputedNonemptySegment system before) :
    List observation :=
  segment.result.2

theorem ExactComputedNonemptySegment.path
    {state observation : Type}
    {system : RelatedTransitionSystem state observation}
    {before : state}
    (segment : ExactComputedNonemptySegment system before) :
    NonemptyRelatedPath system before segment.observations segment.after :=
  ⟨segment.fuel, segment.positive, rfl⟩

/-- Launch-side execution is supplied by the reflected exact-native launch
certificate; only the decoded-side positive fuel and cross-carrier endpoint
facts remain upstream obligations. -/
structure ExactDecodedNativeLaunchComponentCertificate
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (relation : WorldExecution -> NativeWorldExecution -> Prop)
    (decodedBefore : WorldExecution)
    (nativeBefore : NativeWorldExecution) where
  cutpoints : List StableInterpreterCutpoint
  reflected : ReflectedNativeLaunchPathCertificate
  replay : ReflectedNativeLaunchPathReplay
  replayed :
    reflected.replay? native cutpoints nativeBefore = some replay
  decodedSegment :
    ExactComputedNonemptySegment decoded.pe32TransitionSystem decodedBefore
  observationsExact :
    decodedSegment.observations = replay.observations
  afterRelated : relation decodedSegment.after replay.after

def ExactDecodedNativeLaunchComponentCertificate.toChunk
    (certificate : ExactDecodedNativeLaunchComponentCertificate decoded native
      relation decodedBefore nativeBefore) :
    ExactDecodedNativeComponentChunk decoded native relation decodedBefore
      nativeBefore := by
  have nativePath :=
    (certificate.reflected.replay?_sound native certificate.cutpoints
      nativeBefore certificate.replay certificate.replayed).2.2
  exact {
    decodedObservations := certificate.decodedSegment.observations
    nativeObservations := certificate.replay.observations
    decodedAfter := certificate.decodedSegment.after
    nativeAfter := certificate.replay.after
    decodedPath := certificate.decodedSegment.path
    nativePath
    observationsExact := certificate.observationsExact
    afterRelated := certificate.afterRelated
  }

/-- Operation certificates retain the exact abstract request/transition,
checked native dispatch, ABI response, memory frame, and both nonempty paths
already carried by `MixedKernelOperationComponentCertificate`. -/
structure ExactDecodedNativeOperationComponentCertificate
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (program : CompiledKernelProgram)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (authority : ExactNativeCandidateAuthority native)
    (operation : KernelOperation) (entryRva : Nat)
    (decodedBefore : WorldExecution)
    (nativeBefore : NativeWorldExecution) where
  sourceRva : Nat
  checked : MixedKernelOperationComponentCertificate decoded native
    exactDecodedNativeIdentityContract invariant program abi dispatches
    authority sourceRva operation entryRva decodedBefore nativeBefore

def ExactDecodedNativeOperationComponentCertificate.toChunk
    (certificate : ExactDecodedNativeOperationComponentCertificate decoded native
      invariant program abi dispatches authority operation entryRva
      decodedBefore nativeBefore) :
    ExactDecodedNativeComponentChunk decoded native invariant.holds
      decodedBefore nativeBefore := {
  decodedObservations := certificate.checked.paths.originalObservations
  nativeObservations := certificate.checked.paths.candidateObservations
  decodedAfter := certificate.checked.paths.originalAfter
  nativeAfter := certificate.checked.paths.candidateAfter
  decodedPath := certificate.checked.paths.originalPath
  nativePath := certificate.checked.paths.candidatePath
  observationsExact :=
    exactDecodedNativeIdentityObservationLists_eq
      certificate.checked.paths.observationsChecked.pointwise
  afterRelated := certificate.checked.paths.afterRelated
}

/-- Existing one-to-one external interaction plus the one remaining carrier
endpoint fact.  Exact observation equality follows from the identity contract,
not from a submitted observation list. -/
structure ExactDecodedNativeExternalComponentCertificate
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (invariant : MixedExecutionInvariant reachabilityTargetIds
      exactDecodedNativeIdentityContract)
    (decodedBefore : WorldExecution)
    (nativeBefore : NativeWorldExecution) where
  frames : MixedExternalFrameContract
  suspension : WorldExternalSuspension
  callbacks : List WorldExternalCallbackRuntime
  dispatch : ExactNativeExternalDispatch native
  nativeBeforeExact : dispatch.before = nativeBefore
  interaction : ExactMixedExternalInteractionChunk decoded native
    exactDecodedNativeIdentityContract frames decodedBefore suspension callbacks
    dispatch
  afterRelated : invariant.holds
    (originalExternalAfter decoded suspension callbacks) dispatch.after

def ExactDecodedNativeExternalComponentCertificate.toChunk
    (certificate : ExactDecodedNativeExternalComponentCertificate decoded native
      invariant decodedBefore nativeBefore) :
    ExactDecodedNativeComponentChunk decoded native invariant.holds
      decodedBefore nativeBefore := {
  decodedObservations := [originalExternalObservation certificate.suspension]
  nativeObservations := [certificate.dispatch.observation]
  decodedAfter :=
    originalExternalAfter decoded certificate.suspension certificate.callbacks
  nativeAfter := certificate.dispatch.after
  decodedPath := certificate.interaction.originalPath
  nativePath := by
    simpa [certificate.nativeBeforeExact] using
      certificate.interaction.candidatePath
  observationsExact :=
    exactDecodedNativeIdentityObservationLists_eq
      certificate.interaction.observationsRelated
  afterRelated := certificate.afterRelated
}

/-- Project the callback-free nested carrier used by the x87 replay theorem
onto the base exact-native carrier used by whole-program acceptance. -/
def exactNestedNativeBaseExecution? :
    NestedNativeWorldExecution -> Option NativeWorldExecution
  | .running rva undefinedSlot state calls eventIndex events world [] =>
      some (.running rva undefinedSlot state calls eventIndex events world)
  | .running _ _ _ _ _ _ _ (_ :: _) => none
  | .awaitingExternal .. => none
  | .returned state events world => some (.returned state events world)
  | .terminated events world => some (.terminated events world)
  | .fault cause => some (.fault cause)
  | .blocked reason => some (.blocked reason)

/-- The checked replay run fixes the target, x87 frame effect, and nested exact
path.  The only additional execution premise is a positive exact base-carrier
segment connecting the projected endpoints; this is the explicit bridge that
the current nested replay theorem cannot yet derive. -/
structure ExactDecodedNativeX87ComponentCertificate
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (relation : WorldExecution -> NativeWorldExecution -> Prop)
    (decodedBefore : WorldExecution)
    (nativeBefore : NativeWorldExecution) where
  nested : ExactNestedNativeWorldProgram
  nestedBaseExact : nested.base = native
  table : NativeX87ReplayBridgeTable
  handler : CandidateReplayHandler
  run : ExactNativeX87ReplayBridgeRun nested table handler
  nestedBeforeExact :
    exactNestedNativeBaseExecution? run.before = some nativeBefore
  nativeSegment :
    ExactComputedNonemptySegment native.transitionSystem nativeBefore
  nestedAfterExact :
    exactNestedNativeBaseExecution? run.after = some nativeSegment.after
  nativeSilent : nativeSegment.observations = []
  decodedSegment :
    ExactComputedNonemptySegment decoded.pe32TransitionSystem decodedBefore
  decodedSilent : decodedSegment.observations = []
  afterRelated : relation decodedSegment.after nativeSegment.after

def ExactDecodedNativeX87ComponentCertificate.toChunk
    (certificate : ExactDecodedNativeX87ComponentCertificate decoded native
      relation decodedBefore nativeBefore) :
    ExactDecodedNativeComponentChunk decoded native relation decodedBefore
      nativeBefore := by
  have _nestedPath := certificate.run.exactEventFreePath
  exact {
    decodedObservations := certificate.decodedSegment.observations
    nativeObservations := certificate.nativeSegment.observations
    decodedAfter := certificate.decodedSegment.after
    nativeAfter := certificate.nativeSegment.after
    decodedPath := certificate.decodedSegment.path
    nativePath := certificate.nativeSegment.path
    observationsExact := by
      rw [certificate.decodedSilent, certificate.nativeSilent]
    afterRelated := certificate.afterRelated
  }

private def exactTerminalReturnedChunk
    (beforeRelated : relation
      (.returned decodedState world)
      (.returned nativeState events world)) :
    ExactDecodedNativeComponentChunk decoded native relation
      (.returned decodedState world)
      (.returned nativeState events world) := {
  decodedObservations := []
  nativeObservations := []
  decodedAfter := .returned decodedState world
  nativeAfter := .returned nativeState events world
  decodedPath := by
    simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one decoded.pe32TransitionSystem
        (.returned decodedState world))
  nativePath := by
    simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one native.transitionSystem
        (.returned nativeState events world))
  observationsExact := rfl
  afterRelated := beforeRelated
}

private def exactTerminalTerminatedChunk
    (beforeRelated : relation
      (.terminated world) (.terminated events world)) :
    ExactDecodedNativeComponentChunk decoded native relation
      (.terminated world) (.terminated events world) := {
  decodedObservations := []
  nativeObservations := []
  decodedAfter := .terminated world
  nativeAfter := .terminated events world
  decodedPath := by
    simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one decoded.pe32TransitionSystem
        (.terminated world))
  nativePath := by
    simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one native.transitionSystem
        (.terminated events world))
  observationsExact := rfl
  afterRelated := beforeRelated
}

private def exactTerminalFaultChunk
    (beforeRelated : relation (.fault cause) (.fault cause)) :
    ExactDecodedNativeComponentChunk decoded native relation
      (.fault cause) (.fault cause) := {
  decodedObservations := []
  nativeObservations := []
  decodedAfter := .fault cause
  nativeAfter := .fault cause
  decodedPath := by
    simpa [DecodedWorldProgram.pe32TransitionSystem,
      stepPE32WorldExecution] using
      (nonemptyRelatedPath_one decoded.pe32TransitionSystem (.fault cause))
  nativePath := by
    simpa [ExactNativeWorldProgram.transitionSystem,
      stepPE32NativeWorldExecution] using
      (nonemptyRelatedPath_one native.transitionSystem (.fault cause))
  observationsExact := rfl
  afterRelated := beforeRelated
}

/-- Smallest family-indexed upstream interface.  Every field is tied to the
deterministic classifier equation for its decoded source.  Operation evidence
is indexed by the checked combined dispatch relation; external evidence uses
the exact one-to-one boundary chunk; x87 evidence names the checked replay run.
-/
structure ExactDecodedNativeComponentAssembly
    (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2)
    (decoded : DecodedWorldProgram)
    (native : ExactNativeWorldProgram)
    (evidence : ExactDecodedNativeKernelEvidence context native)
    (candidateRootRva : Nat)
    (candidateRoot : DirectExactCandidateNativeLaunchRoot native launch
      candidateRootRva)
    (frameCount : launch.frameOffsets.length =
      launch.continuationTargetIds.length)
    (reachabilityTargetIds : List Nat) where
  invariant : MixedExecutionInvariant reachabilityTargetIds
    exactDecodedNativeIdentityContract
  classifier : ExactDecodedNativeTotalClassifier decoded native
    evidence.kernelCore.program launch invariant.holds
  rootsRelated : forall world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState
        candidateState ->
      invariant.holds
        (.running launch.rootTargetId candidateState
          launch.continuationTargetIds 0 world)
        (.running candidateRootRva 0 candidateState
          (exactDecodedNativeLaunchCalls candidateRoot frameCount candidateState)
          0 [] world)
  launchComponent : forall targetId state calls eventIndex world nativeBefore,
    invariant.holds
        (.running targetId state calls eventIndex world) nativeBefore ->
      exactDecodedNativeExecutableFamily? decoded evidence.kernelCore.program
          launch targetId state calls = some .launchWrapper ->
      ExactDecodedNativeLaunchComponentCertificate decoded native
        invariant.holds (.running targetId state calls eventIndex world)
        nativeBefore
  operationComponent :
    forall targetId state calls eventIndex world nativeBefore operation entryRva,
      invariant.holds
          (.running targetId state calls eventIndex world) nativeBefore ->
        exactDecodedNativeExecutableFamily? decoded evidence.kernelCore.program
            launch targetId state calls =
          some (.kernelOperation operation entryRva) ->
        evidence.kernelCore.program.functionEntry? operation.role =
          some entryRva ->
        ExactDecodedNativeOperationComponentCertificate decoded native invariant
          evidence.kernelCore.program evidence.kernelCore.abi
          (combinedKernelDispatchRelation evidence.operations.dispatchFamily)
          evidence.nativeAuthority operation entryRva
          (.running targetId state calls eventIndex world) nativeBefore
  externalComponent : forall targetId state calls eventIndex world nativeBefore,
    invariant.holds
        (.running targetId state calls eventIndex world) nativeBefore ->
      exactDecodedNativeExecutableFamily? decoded evidence.kernelCore.program
          launch targetId state calls = some .externalBoundary ->
      ExactDecodedNativeExternalComponentCertificate decoded native invariant
        (.running targetId state calls eventIndex world) nativeBefore
  x87Component : forall targetId state calls eventIndex world nativeBefore,
    invariant.holds
        (.running targetId state calls eventIndex world) nativeBefore ->
      exactDecodedNativeExecutableFamily? decoded evidence.kernelCore.program
          launch targetId state calls = some .x87Replay ->
      ExactDecodedNativeX87ComponentCertificate decoded native invariant.holds
        (.running targetId state calls eventIndex world) nativeBefore

def ExactDecodedNativeComponentAssembly.component
    (assembly : ExactDecodedNativeComponentAssembly context graph reachability
      launch decoded native evidence candidateRootRva candidateRoot frameCount
      reachabilityTargetIds)
    (decodedBefore : WorldExecution) (nativeBefore : NativeWorldExecution)
    (beforeRelated : assembly.invariant.holds decodedBefore nativeBefore) :
    ExactDecodedNativeComponentChunk decoded native assembly.invariant.holds
      decodedBefore nativeBefore := by
  cases assembly.classifier.classify decodedBefore nativeBefore beforeRelated with
  | executable targetId state calls eventIndex world nativeBefore family
      classified valid =>
      cases family with
      | launchWrapper =>
          exact (assembly.launchComponent targetId state calls eventIndex world
            nativeBefore beforeRelated classified).toChunk
      | kernelOperation operation entryRva =>
          exact (assembly.operationComponent targetId state calls eventIndex
            world nativeBefore operation entryRva beforeRelated classified
            valid).toChunk
      | externalBoundary =>
          exact (assembly.externalComponent targetId state calls eventIndex
            world nativeBefore beforeRelated classified).toChunk
      | x87Replay =>
          exact (assembly.x87Component targetId state calls eventIndex world
            nativeBefore beforeRelated classified).toChunk
  | returned decodedState nativeState world events =>
      exact exactTerminalReturnedChunk beforeRelated
  | terminated world events =>
      exact exactTerminalTerminatedChunk beforeRelated
  | fault cause => exact exactTerminalFaultChunk beforeRelated

/-- Mechanical compatibility projection into the acceptance adapter.  The
four legacy chunk fields all delegate to the same checked classifier and
family assembly; generated code no longer supplies those broad functions. -/
def ExactDecodedNativeComponentAssembly.toComponentPremises
    (assembly : ExactDecodedNativeComponentAssembly context graph reachability
      launch decoded native evidence candidateRootRva candidateRoot frameCount
      reachabilityTargetIds) :
    ExactDecodedNativeComponentPremises context graph reachability launch decoded
      native evidence candidateRootRva candidateRoot frameCount := {
  relation := assembly.invariant.holds
  classify := fun decodedBefore nativeBefore related =>
    (assembly.classifier.classify decodedBefore nativeBefore related).toAdapterCase
  rootsRelated := assembly.rootsRelated
  launchChunk := fun decodedBefore nativeBefore related =>
    assembly.component decodedBefore nativeBefore related
  kernelChunk := fun decodedBefore nativeBefore related _ _ _ _ =>
    assembly.component decodedBefore nativeBefore related
  externalBoundaryChunk := fun decodedBefore nativeBefore related =>
    assembly.component decodedBefore nativeBefore related
  x87ReplayChunk := fun decodedBefore nativeBefore related =>
    assembly.component decodedBefore nativeBefore related
}

#print axioms exactDecodedNativeIdentityObservationLists_eq
#print axioms ExactComputedNonemptySegment.path
#print axioms ExactDecodedNativeLaunchComponentCertificate.toChunk
#print axioms ExactDecodedNativeOperationComponentCertificate.toChunk
#print axioms ExactDecodedNativeExternalComponentCertificate.toChunk
#print axioms ExactDecodedNativeX87ComponentCertificate.toChunk
#print axioms ExactDecodedNativeComponentAssembly.component
#print axioms ExactDecodedNativeComponentAssembly.toComponentPremises

end StageA.Relational.InterpreterExactDecodedNativeComponents
