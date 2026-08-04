import StageA.RelationalInterpreterNativeLaunch
import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterMixedConstructiveSourceClassifier

namespace StageA.Relational.InterpreterMixedLaunchRefinement

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterKernelABI

/-! # Guard-complete native launch-wrapper refinement

The older launch certificate submits one linear path for each source.  That is
not a total certificate for a wrapper containing a data-dependent branch.
This module instead reflects the complete finite instruction graph.  Every
ordinary successor is re-derived from exact PE bytes, every internal edge must
decrease a checked rank, and replay follows the concrete branch selected by the
native transition system.

Static graph data is not itself a claim that every launch state reaches the
destination or establishes the engine relation.  `ExactNativeLaunchGraphRuntime`
must prove that the exact finite replay succeeds for its explicit admitted
states, while profile-level launch-frame facts establish admission and the
engine relation from that computed result.
-/

inductive NativeLaunchGraphInstructionKind where
  | ordinary
  | x87Frame (operation : KernelX87FrameOperation)
deriving Repr, DecidableEq

inductive NativeLaunchGraphTerminal where
  | dispatch
  | returned
  | terminated
deriving Repr, DecidableEq

structure ReflectedNativeLaunchGraphNode where
  instruction : KernelInstruction
  kind : NativeLaunchGraphInstructionKind
  successors : List Nat
  rank : Nat
  terminal : Option NativeLaunchGraphTerminal := none
deriving Repr, DecidableEq

def nativeLaunchImmediateSuccessors : OutcomeExpr -> Option (List Nat)
  | .returned _ => some []
  | .jump target => some [target]
  | .branch _ taken fallthrough => some [taken, fallthrough]
  | .call target _ _ => some [target]
  | .externalCall .. | .externalJump .. => some []
  | .bulkCopy _ continuation => some [continuation]
  | .bulkFill _ continuation => some [continuation]
  | .bulkScan _ continuation => some [continuation]
  | .atomicCompareExchange _ _ _ continuation => some [continuation]
  | .checkedContinue .. | .indirectCall .. | .indirectJump .. => none

def ordinaryNativeLaunchSuccessors? (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) : Option (List Nat) := do
  let decoded <- instruction.decode? pe
  let result <- executeInstruction pe imports instruction.rva 0 decoded initialSymbolic
  match result with
  | .next _ => some [instruction.rva + decoded.size]
  | .stop behavior => do
      let outcome <- behavior.outcome
      nativeLaunchImmediateSuccessors outcome

def x87FrameNativeLaunchSuccessors? (pe : PE32)
    (instruction : KernelInstruction) (operation : KernelX87FrameOperation) :
    Option (List Nat) := do
  let decoded <- ({
    rva := instruction.rva
    bytes := instruction.bytes
    operation
  } : KernelX87FrameInstruction).decode? pe
  pure [instruction.rva + decoded.size]

def ReflectedNativeLaunchGraphNode.staticSuccessors?
    (node : ReflectedNativeLaunchGraphNode) (pe : PE32)
    (imports : List PEImport) : Option (List Nat) :=
  match node.kind with
  | .ordinary => ordinaryNativeLaunchSuccessors? pe imports node.instruction
  | .x87Frame operation =>
      x87FrameNativeLaunchSuccessors? pe node.instruction operation

def nativeLaunchGraphTerminalChecked (pe : PE32) (imports : List PEImport)
    (cutpoints : List StableInterpreterCutpoint)
    (destination : NativeLaunchPathDestination)
    (node : ReflectedNativeLaunchGraphNode) : Bool :=
  match destination, node.terminal with
  | .stableCutpoint index, some .dispatch =>
      cutpoints[index]?.map (fun cutpoint =>
        cutpoint.kind == .dispatch && node.successors == [cutpoint.rva])
        |>.getD false
  | .returned, some .returned =>
      match node.instruction.semantics? pe imports with
      | some (.stop behavior) =>
          match behavior.outcome with
          | some (.returned _) => node.successors.isEmpty
          | _ => false
      | _ => false
  | .terminated, some .terminated =>
      match node.instruction.semantics? pe imports with
      | some (.stop behavior) =>
          match behavior.outcome with
          | some (.externalCall ..) | some (.externalJump ..) =>
              node.successors.isEmpty
          | _ => false
      | _ => false
  | _, none => true
  | _, _ => false

structure ReflectedNativeLaunchGraphRoute where
  source : NativeLaunchPathSource
  destination : NativeLaunchPathDestination
  nodes : List ReflectedNativeLaunchGraphNode
deriving Repr, DecidableEq

def ReflectedNativeLaunchGraphRoute.node?
    (route : ReflectedNativeLaunchGraphRoute) (rva : Nat) :
    Option ReflectedNativeLaunchGraphNode :=
  match route.nodes.filter (fun node => node.instruction.rva == rva) with
  | [node] => some node
  | _ => none

def ReflectedNativeLaunchGraphRoute.internalRvas
    (route : ReflectedNativeLaunchGraphRoute) : List Nat :=
  route.nodes.map (fun node => node.instruction.rva)

def closeNativeLaunchGraph (route : ReflectedNativeLaunchGraphRoute) :
    Nat -> List Nat -> List Nat
  | 0, reached => reached.eraseDups
  | fuel + 1, reached =>
      let next := route.nodes.flatMap fun node =>
        if reached.contains node.instruction.rva then
          node.successors.filter route.internalRvas.contains
        else []
      closeNativeLaunchGraph route fuel (reached ++ next).eraseDups

def ReflectedNativeLaunchGraphRoute.staticChecked
    (route : ReflectedNativeLaunchGraphRoute) (pe : PE32)
    (imports : List PEImport)
    (cutpoints : List StableInterpreterCutpoint) : Bool :=
  route.source.shapeChecked cutpoints route.destination &&
    !route.nodes.isEmpty &&
    decide route.internalRvas.Nodup &&
    route.nodes.any (fun node => node.terminal.isSome) &&
    match route.source.rva? pe cutpoints with
    | none => false
    | some sourceRva =>
        route.internalRvas.contains sourceRva &&
          route.nodes.all (fun node =>
            node.rank > 0 &&
              node.staticSuccessors? pe imports == some node.successors &&
              nativeLaunchGraphTerminalChecked pe imports cutpoints
                route.destination node &&
              (node.terminal.isSome || !node.successors.isEmpty) &&
              node.successors.all (fun successor =>
                match route.node? successor with
                | some target => target.rank < node.rank
                | none =>
                    node.terminal == some .dispatch &&
                      match route.destination with
                      | .stableCutpoint index =>
                          cutpoints[index]?.map (fun cutpoint =>
                            cutpoint.rva == successor) |>.getD false
                      | _ => false)) &&
          route.internalRvas.all
            (closeNativeLaunchGraph route route.nodes.length [sourceRva]).contains

structure NativeLaunchGraphReplay where
  fuel : Nat
  after : NativeWorldExecution
  observations : List WorldRelationalObservable

def ReflectedNativeLaunchGraphRoute.additionalFuel?
    (route : ReflectedNativeLaunchGraphRoute)
    (program : ExactNativeWorldProgram)
    (cutpoints : List StableInterpreterCutpoint) :
    Nat -> NativeWorldExecution -> Option Nat
  | 0, _ => none
  | fuel + 1, before => do
      let rva <- before.rva?
      let node <- route.node? rva
      let transition := program.transitionSystem.step before
      if route.destination.matches cutpoints transition.next then
        some 0
      else do
        let nextRva <- transition.next.rva?
        if !node.successors.contains nextRva then none else
        let tail <- route.additionalFuel? program cutpoints fuel transition.next
        some (tail + 1)

def ReflectedNativeLaunchGraphRoute.replay?
    (route : ReflectedNativeLaunchGraphRoute)
    (program : ExactNativeWorldProgram)
    (cutpoints : List StableInterpreterCutpoint)
    (before : NativeWorldExecution) : Option NativeLaunchGraphReplay :=
  if route.staticChecked program.pe program.imports cutpoints &&
      route.source.matches program.pe cutpoints before then
    do
      let additional <- route.additionalFuel? program cutpoints
        (route.nodes.length + 1) before
      let fuel := additional + 1
      let replay := runRelatedSteps program.transitionSystem fuel before
      if route.destination.matches cutpoints replay.1 then
        some { fuel, after := replay.1, observations := replay.2 }
      else none
  else none

theorem ReflectedNativeLaunchGraphRoute.replay?_sound
    (route : ReflectedNativeLaunchGraphRoute)
    (program : ExactNativeWorldProgram)
    (cutpoints : List StableInterpreterCutpoint)
    (before : NativeWorldExecution) (result : NativeLaunchGraphReplay)
    (replayed : route.replay? program cutpoints before = some result) :
    route.source.matches program.pe cutpoints before = true /\
      route.destination.matches cutpoints result.after = true /\
      NonemptyRelatedPath program.transitionSystem before result.observations
        result.after := by
  unfold ReflectedNativeLaunchGraphRoute.replay? at replayed
  split at replayed <;> try contradiction
  rename_i checked
  have sourceExact :
      route.source.matches program.pe cutpoints before = true := by
    cases sourceExact :
        route.source.matches program.pe cutpoints before with
    | false => simp [sourceExact] at checked
    | true => rfl
  cases additionalExact : route.additionalFuel? program cutpoints
      (route.nodes.length + 1) before with
  | none => simp [additionalExact] at replayed
  | some additional =>
      rw [additionalExact] at replayed
      change (if route.destination.matches cutpoints
          (runRelatedSteps program.transitionSystem (additional + 1) before).1 then
        some {
          fuel := additional + 1
          after :=
            (runRelatedSteps program.transitionSystem (additional + 1) before).1
          observations :=
            (runRelatedSteps program.transitionSystem (additional + 1) before).2
        }
      else none) = some result at replayed
      split at replayed <;> try contradiction
      rename_i destinationExact
      cases replayed
      exact ⟨sourceExact, destinationExact,
        ⟨additional + 1, Nat.zero_lt_succ additional, rfl⟩⟩

/-- Select the canonical root that the bounded loader executes first. -/
def canonicalNativeInitialLaunchRoot (candidate : ExactNativeWorldProgram) :
    CanonicalNativeLaunchRoot :=
  match candidatePELaunchRoots? candidate.pe with
  | some roots =>
      match roots.tlsCallbackRvas with
      | [] => .entry
      | _ :: _ => .tlsCallback 0
  | none => .entry

/-- The direct launch root selected from the parsed candidate inventory is the
canonical initial root used to index reflected wrapper routes. -/
theorem directExactCandidateNativeLaunchRoot_canonicalRootExact
    {candidate : ExactNativeWorldProgram} {launch : PE32ConsoleLaunchV2}
    {candidateRootRva : Nat}
    (exact : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva) :
    (canonicalNativeInitialLaunchRoot candidate).rva? candidate.pe =
      some candidateRootRva := by
  rcases exact with ⟨roots, rootsExact, _, rootExact⟩
  cases callbacksExact : roots.tlsCallbackRvas with
  | nil =>
      simpa [canonicalNativeInitialLaunchRoot,
        CanonicalNativeLaunchRoot.rva?, rootsExact,
        CandidatePELaunchRoots.initialRva, callbacksExact] using
        congrArg some rootExact.symm
  | cons callback callbacks =>
      simpa [canonicalNativeInitialLaunchRoot,
        CanonicalNativeLaunchRoot.rva?, rootsExact,
        CandidatePELaunchRoots.initialRva, callbacksExact] using
        congrArg some rootExact.symm

structure ExactNativeLaunchGraphCertificate where
  cutpoints : List StableInterpreterCutpoint
  routes : List ReflectedNativeLaunchGraphRoute
deriving Repr, DecidableEq

def ExactNativeLaunchGraphCertificate.expectedSources?
    (certificate : ExactNativeLaunchGraphCertificate) (pe : PE32) :
    Option (List NativeLaunchPathSource) := do
  let roots <- canonicalNativeLaunchRoots? pe
  pure (
    roots.map (fun root => .canonicalRoot root) ++
    (stableInterpreterCutpointIndices .returnWrapper certificate.cutpoints).map
      (fun index => .stableCutpoint index) ++
    (stableInterpreterCutpointIndices .terminationWrapper certificate.cutpoints).map
      (fun index => .stableCutpoint index))

def ExactNativeLaunchGraphCertificate.staticChecked
    (certificate : ExactNativeLaunchGraphCertificate) (pe : PE32)
    (imports : List PEImport) : Bool :=
  !certificate.cutpoints.isEmpty &&
    decide (certificate.cutpoints.map (fun cutpoint => cutpoint.rva)).Nodup &&
    (certificate.cutpoints.all fun cutpoint =>
      rvaInExecutableSection pe cutpoint.rva) &&
    some (certificate.routes.map (fun route => route.source)) ==
      certificate.expectedSources? pe &&
    certificate.routes.all fun route =>
      route.staticChecked pe imports certificate.cutpoints

/-- A generated launch graph bundled with the exact PE/import context in which
its reflected static checks were accepted.  This package makes the checked
context explicit, but deliberately contains no runtime replay or state-relation
claim. -/
structure CheckedExactNativeLaunchGraph where
  candidatePe : PE32
  candidateImports : List PEImport
  certificate : ExactNativeLaunchGraphCertificate
  staticChecked :
    certificate.staticChecked candidatePe candidateImports = true

/-- A root with an exact parsed RVA belongs to the canonical root inventory
recovered from the same PE. -/
theorem canonicalNativeLaunchRoot_mem_of_rva?_eq_some
    (root : CanonicalNativeLaunchRoot) (pe : PE32) (rva : Nat)
    (exact : root.rva? pe = some rva) :
    exists roots,
      canonicalNativeLaunchRoots? pe = some roots /\
        root ∈ roots := by
  cases parsed : candidatePELaunchRoots? pe with
  | none =>
      cases root <;>
        simp [CanonicalNativeLaunchRoot.rva?, parsed] at exact
  | some roots =>
      refine ⟨.entry ::
        (List.range roots.tlsCallbackRvas.length).map (.tlsCallback ·), ?_, ?_⟩
      · simp [canonicalNativeLaunchRoots?, parsed]
      · cases root with
        | entry => simp
        | tlsCallback index =>
            have bounded : index < roots.tlsCallbackRvas.length :=
              List.getElem?_eq_some_iff.mp (by
                simpa [CanonicalNativeLaunchRoot.rva?, parsed] using exact) |>.1
            exact List.mem_cons_of_mem _ <|
              List.mem_map.mpr ⟨index, List.mem_range.mpr bounded, rfl⟩

/-- Static graph checking already proves that every parsed canonical root is
represented by one submitted route.  Generated binary bindings should consume
this theorem instead of re-enumerating entry and TLS roots. -/
theorem CheckedExactNativeLaunchGraph.canonicalRootRoute
    (checked : CheckedExactNativeLaunchGraph)
    (candidate : ExactNativeWorldProgram)
    (candidatePeExact : checked.candidatePe = candidate.pe) :
    forall root rootRva,
      root.rva? candidate.pe = some rootRva ->
        exists route,
          route ∈ checked.certificate.routes /\
            route.source = .canonicalRoot root := by
  intro root rootRva rootExact
  obtain ⟨roots, rootsExact, rootMember⟩ :=
    canonicalNativeLaunchRoot_mem_of_rva?_eq_some root candidate.pe rootRva
      rootExact
  have staticChecked :
      checked.certificate.staticChecked candidate.pe
        checked.candidateImports = true := by
    rw [← candidatePeExact]
    exact checked.staticChecked
  simp only [ExactNativeLaunchGraphCertificate.staticChecked,
    Bool.and_eq_true, beq_iff_eq] at staticChecked
  have sourcesExact := staticChecked.1.2
  have sourcesExact' :
      checked.certificate.routes.map (fun route => route.source) =
        roots.map (fun value => NativeLaunchPathSource.canonicalRoot value) ++
          (stableInterpreterCutpointIndices .returnWrapper
            checked.certificate.cutpoints).map
              (fun index => NativeLaunchPathSource.stableCutpoint index) ++
          (stableInterpreterCutpointIndices .terminationWrapper
            checked.certificate.cutpoints).map
              (fun index => NativeLaunchPathSource.stableCutpoint index) := by
    simpa [ExactNativeLaunchGraphCertificate.expectedSources?, rootsExact]
      using sourcesExact
  have sourceMember :
      NativeLaunchPathSource.canonicalRoot root ∈
        checked.certificate.routes.map (fun route => route.source) := by
    rw [sourcesExact']
    exact List.mem_append_left _ <| List.mem_append_left _ <|
      List.mem_map.mpr ⟨root, rootMember, rfl⟩
  rcases List.mem_map.mp sourceMember with
    ⟨route, routeMember, sourceExact⟩
  exact ⟨route, routeMember, sourceExact⟩

/-- Runtime evidence for one statically checked launch graph.  The only
execution claim is a positive result from `replay?`, whose implementation runs
the exact native transition system over the PE bytes bound by `checked`.
Generated modules may prove `replayChecked` by symbolic simplification and
launch-frame facts, but cannot replace it with a report status. -/
structure ExactNativeLaunchGraphRuntime
    (checked : CheckedExactNativeLaunchGraph)
    (candidate : ExactNativeWorldProgram) where
  candidatePeExact : checked.candidatePe = candidate.pe
  candidateImportsExact : checked.candidateImports = candidate.imports
  routeReady : ReflectedNativeLaunchGraphRoute -> NativeWorldExecution -> Prop
  canonicalRootRoute : forall root rootRva,
    root.rva? candidate.pe = some rootRva ->
      exists route,
        route ∈ checked.certificate.routes /\
          route.source = .canonicalRoot root
  readySourceMatches : forall route, route ∈ checked.certificate.routes ->
    forall before,
      routeReady route before ->
        route.source.matches candidate.pe checked.certificate.cutpoints before =
          true
  replayChecked : forall route, route ∈ checked.certificate.routes ->
    forall before,
      routeReady route before ->
      (route.replay? candidate checked.certificate.cutpoints before).isSome =
        true

/-- Canonical readiness predicate for generated binaries.  It contains no
semantic summary: readiness is exactly successful execution by `replay?` from
a matching source state. -/
def exactNativeLaunchReplayReady
    (checked : CheckedExactNativeLaunchGraph)
    (candidate : ExactNativeWorldProgram)
    (route : ReflectedNativeLaunchGraphRoute)
    (before : NativeWorldExecution) : Prop :=
  route.source.matches candidate.pe checked.certificate.cutpoints before =
      true /\
    (route.replay? candidate checked.certificate.cutpoints before).isSome =
      true

/-- Construct runtime totality from the exact replay predicate.  The remaining
structural input is the finite canonical-root route lookup; generated modules
prove it against their reflected route list. -/
def ExactNativeLaunchGraphRuntime.ofExactReplay
    (candidatePeExact : checked.candidatePe = candidate.pe)
    (candidateImportsExact : checked.candidateImports = candidate.imports)
    (canonicalRootRoute : forall root rootRva,
      root.rva? candidate.pe = some rootRva ->
        exists route,
          route ∈ checked.certificate.routes /\
            route.source = .canonicalRoot root) :
    ExactNativeLaunchGraphRuntime checked candidate := {
  candidatePeExact
  candidateImportsExact
  routeReady := exactNativeLaunchReplayReady checked candidate
  canonicalRootRoute
  readySourceMatches := by
    intro route _ before ready
    exact ready.1
  replayChecked := by
    intro route _ before ready
    exact ready.2
}

theorem ExactNativeLaunchGraphRuntime.staticChecked
    (runtime : ExactNativeLaunchGraphRuntime checked candidate) :
    checked.certificate.staticChecked candidate.pe candidate.imports = true := by
  rw [← runtime.candidatePeExact, ← runtime.candidateImportsExact]
  exact checked.staticChecked

/-- Extract the exact replay result from the checked finite executor. -/
theorem ExactNativeLaunchGraphRuntime.replayTotal
    (runtime : ExactNativeLaunchGraphRuntime checked candidate) :
    forall route, route ∈ checked.certificate.routes -> forall before,
      runtime.routeReady route before ->
      exists result,
        route.replay? candidate checked.certificate.cutpoints before =
          some result := by
  intro route routeMember before ready
  have present := runtime.replayChecked route routeMember before ready
  cases replayed :
      route.replay? candidate checked.certificate.cutpoints before with
  | none => simp [replayed] at present
  | some result => exact ⟨result, rfl⟩

/-! ## Exact launch capture

The native wrapper first records the candidate launch state in the checked
engine allocation.  The console-launch relation already proves that every
machine component represented by that allocation is exactly equal on the
original side.  The following lemmas perform that transfer once, independently
of any generated binary or wrapper layout.
-/

/-- Engine bytes are unchanged when the represented launch components are
exact.  Ordinary memory is intentionally absent from `engineRepAt`; this lemma
therefore covers precisely the registers, flags, FS base, x87 state, and source
RVA represented by the native engine. -/
theorem engineRepAt_fieldBytes_eq_of_launch_exact
    (layout : EngineLayout) (base : Word) (sourceRva : Nat)
    (original candidate : MachineState)
    (registersExact : original.registers = candidate.registers)
    (flagsExact : original.eflags = candidate.eflags)
    (x87Exact : MachineX87Exact original candidate)
    (fsBaseExact : original.fsBase = candidate.fsBase)
    (field : EngineField) :
    (engineRepAt layout base original.x87Semantics).fieldBytes original
        sourceRva field =
      (engineRepAt layout base candidate.x87Semantics).fieldBytes candidate
        sourceRva field := by
  rcases x87Exact with ⟨_, x87PhysicalExact, x87SemanticsExact⟩
  cases field <;>
    simp [EngineRep.fieldBytes, registersExact, flagsExact, fsBaseExact,
      x87PhysicalExact, x87SemanticsExact]

/-- A native wrapper capture of the candidate launch state is also an exact
capture of the related original launch state.  This is a semantic theorem over
the concrete engine bytes, not an address- or report-level shortcut. -/
theorem OriginalEngineStateHolds.of_launch_exact
    (layout : EngineLayout) (base : Word) (sourceRva : Nat)
    (original candidateBefore candidateAfter : MachineState)
    (registersExact : original.registers = candidateBefore.registers)
    (flagsExact : original.eflags = candidateBefore.eflags)
    (x87Exact : MachineX87Exact original candidateBefore)
    (fsBaseExact : original.fsBase = candidateBefore.fsBase)
    (captured : OriginalEngineStateHolds layout base sourceRva
      candidateBefore candidateAfter) :
    OriginalEngineStateHolds layout base sourceRva original candidateAfter := by
  rcases captured with ⟨repValid, fields, memory, control,
    candidateBeforeSemantics, candidateAfterSemantics⟩
  refine {
    repValid := ?_
    fields := ?_
    memory := ?_
    control := control
    originalSemantics := ?_
    candidateSemantics := ?_
  }
  · simpa [engineRepAt, x87Exact.2.2] using repValid
  · intro entry member
    have capturedField := fields entry member
    unfold EngineFieldHolds at capturedField ⊢
    rw [engineRepAt_fieldBytes_eq_of_launch_exact layout base sourceRva
      original candidateBefore registersExact flagsExact x87Exact fsBaseExact
      entry.field]
    simpa [engineRepAt, x87Exact.2.2] using capturedField
  · intro originalAddress candidateAddress mapped
    simp [engineRepAt] at mapped
  · rfl
  · simpa [engineRepAt, x87Exact.2.2] using candidateAfterSemantics

/-! ## Classifier-indexed launch/runtime phases -/

/-- Bind the launch relation to the exact worlds and machines carried by a
literal launch-classifier witness.  The base state facts deliberately carry no
second copy of this relation. -/
def ConstructiveMixedKernelPhaseStateFacts.ofLaunchExact
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {contract : MixedRelationContract}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    (source : ExactOriginalSemanticSource originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority)
    (sourceIsRoot : source.targetId = launchProfile.rootTargetId)
    (originalAtSource :
      originalExecutionAtTargetId source.targetId originalBefore)
    (candidateAtRoot :
      nativeExecutionAtRva candidateRootRva candidateBefore)
    (carrier : ExactConstructiveMixedLaunchCarrier candidate launchProfile
      candidateRootRva originalBefore candidateBefore)
    {originalWorld candidateWorld : RelationalWorld}
    {originalState candidateState : MachineState}
    (originalWorldExact :
      originalExecutionWorld? originalBefore = some originalWorld)
    (candidateWorldExact :
      nativeExecutionWorld? candidateBefore = some candidateWorld)
    (originalStateExact :
      originalExecutionMachine? originalBefore = some originalState)
    (candidateStateExact :
      candidateBefore.machine? = some candidateState)
    (launchRelated :
      MixedLaunchStatesRelated originalContext candidate contract
        originalWorld candidateWorld originalState candidateState) :
    ConstructiveMixedKernelPhaseStateFacts contract
      (ConstructiveMixedKernelSourceEvidence.launch
        (program := program) (candidateRootRva := candidateRootRva)
        source sourceIsRoot originalAtSource candidateAtRoot carrier) := by
  refine { machineStatesRelated := ?_ }
  intro actualOriginalWorld actualCandidateWorld actualOriginalState
    actualCandidateState actualOriginalWorldExact actualCandidateWorldExact
    actualOriginalStateExact actualCandidateStateExact
  have originalWorldEq : originalWorld = actualOriginalWorld :=
    Option.some.inj (originalWorldExact.symm.trans actualOriginalWorldExact)
  have candidateWorldEq : candidateWorld = actualCandidateWorld :=
    Option.some.inj (candidateWorldExact.symm.trans actualCandidateWorldExact)
  have originalStateEq : originalState = actualOriginalState :=
    Option.some.inj (originalStateExact.symm.trans actualOriginalStateExact)
  have candidateStateEq : candidateState = actualCandidateState :=
    Option.some.inj (candidateStateExact.symm.trans actualCandidateStateExact)
  subst actualOriginalWorld
  subst actualCandidateWorld
  subst actualOriginalState
  subst actualCandidateState
  simpa [ConstructiveMixedKernelPhaseMachineStatesRelated,
    ConstructiveMixedKernelSourceEvidence.phase] using launchRelated

/-- Recover the complete launch relation from facts indexed by the literal
launch classifier arm.  This is the elimination counterpart of
`ofLaunchExact`; consumers do not need to project through the weaker
`MixedExecutionMachineStatesRelated` disjunction. -/
theorem ConstructiveMixedKernelPhaseStateFacts.launchRelated
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {contract : MixedRelationContract}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    {source : ExactOriginalSemanticSource originalContext originalAuthority
      launchProfile originalRoot reachability candidate candidateAuthority}
    {sourceIsRoot : source.targetId = launchProfile.rootTargetId}
    {originalAtSource :
      originalExecutionAtTargetId source.targetId originalBefore}
    {candidateAtRoot :
      nativeExecutionAtRva candidateRootRva candidateBefore}
    {carrier : ExactConstructiveMixedLaunchCarrier candidate launchProfile
      candidateRootRva originalBefore candidateBefore}
    (facts : ConstructiveMixedKernelPhaseStateFacts contract
      (ConstructiveMixedKernelSourceEvidence.launch
        (program := program) (candidateRootRva := candidateRootRva)
        source sourceIsRoot originalAtSource candidateAtRoot carrier))
    (originalWorldExact :
      originalExecutionWorld? originalBefore = some originalWorld)
    (candidateWorldExact :
      nativeExecutionWorld? candidateBefore = some candidateWorld)
    (originalStateExact :
      originalExecutionMachine? originalBefore = some originalState)
    (candidateStateExact :
      candidateBefore.machine? = some candidateState) :
    MixedLaunchStatesRelated originalContext candidate contract
      originalWorld candidateWorld originalState candidateState := by
  simpa [ConstructiveMixedKernelPhaseMachineStatesRelated,
    ConstructiveMixedKernelSourceEvidence.phase] using
      facts.machineStatesRelated originalWorld candidateWorld originalState
        candidateState originalWorldExact candidateWorldExact originalStateExact
        candidateStateExact

/-- Project the exact canonical launch executions carried by the checked launch
classifier witness.  Component bindings can recover the loader-derived call
frames and empty external-event history without reconstructing them from weak
control-location predicates. -/
theorem ExactConstructiveMixedLaunchCarrier.canonicalExecutions
    {candidate : ExactNativeWorldProgram}
    {launchProfile : PE32ConsoleLaunchV2}
    {candidateRootRva : Nat}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    (carrier : ExactConstructiveMixedLaunchCarrier candidate launchProfile
      candidateRootRva originalBefore candidateBefore) :
    exists originalState candidateState originalWorld candidateWorld calls,
      originalBefore =
          .running launchProfile.rootTargetId originalState
            launchProfile.continuationTargetIds 0 originalWorld /\
        candidateBefore =
          .running candidateRootRva 0 candidateState calls 0 [] candidateWorld /\
        candidateNativeLaunchCallFrames? candidate launchProfile
            candidateState = some calls := by
  cases carrier with
  | canonical originalState candidateState originalWorld candidateWorld calls
      callsExact =>
      exact ⟨originalState, candidateState, originalWorld, candidateWorld, calls,
        rfl, rfl, callsExact⟩

/-- A source-classifier witness uses the runtime relation exactly when it is
not the unique launch constructor. -/
def ConstructiveMixedKernelRuntimeEvidence
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore) : Prop :=
  evidence.phase = .runtime

/-- Bind the runtime relation to the exact worlds and machines carried by any
checked non-launch classifier witness. -/
def ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {launchProfile : PE32ConsoleLaunchV2}
    {originalRoot : DirectExactOriginalDecodedLaunchRoot originalContext
      launchProfile}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launchProfile originalRoot}
    {candidate : ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {program : CompiledKernelProgram}
    {candidateRootRva : Nat}
    {contract : MixedRelationContract}
    {originalBefore : WorldExecution}
    {candidateBefore : NativeWorldExecution}
    (evidence : ConstructiveMixedKernelSourceEvidence originalContext
      originalAuthority launchProfile originalRoot reachability candidate
      candidateAuthority program candidateRootRva originalBefore
      candidateBefore)
    (runtimeEvidence : ConstructiveMixedKernelRuntimeEvidence evidence)
    {originalWorld candidateWorld : RelationalWorld}
    {originalState candidateState : MachineState}
    (originalWorldExact :
      originalExecutionWorld? originalBefore = some originalWorld)
    (candidateWorldExact :
      nativeExecutionWorld? candidateBefore = some candidateWorld)
    (originalStateExact :
      originalExecutionMachine? originalBefore = some originalState)
    (candidateStateExact :
      candidateBefore.machine? = some candidateState)
    (runtimeRelated :
      contract.runtimeStatesRelated originalWorld candidateWorld
        originalState candidateState) :
    ConstructiveMixedKernelPhaseStateFacts contract evidence := by
  refine { machineStatesRelated := ?_ }
  intro actualOriginalWorld actualCandidateWorld actualOriginalState
    actualCandidateState actualOriginalWorldExact actualCandidateWorldExact
    actualOriginalStateExact actualCandidateStateExact
  have originalWorldEq : originalWorld = actualOriginalWorld :=
    Option.some.inj (originalWorldExact.symm.trans actualOriginalWorldExact)
  have candidateWorldEq : candidateWorld = actualCandidateWorld :=
    Option.some.inj (candidateWorldExact.symm.trans actualCandidateWorldExact)
  have originalStateEq : originalState = actualOriginalState :=
    Option.some.inj (originalStateExact.symm.trans actualOriginalStateExact)
  have candidateStateEq : candidateState = actualCandidateState :=
    Option.some.inj (candidateStateExact.symm.trans actualCandidateStateExact)
  subst actualOriginalWorld
  subst actualCandidateWorld
  subst actualOriginalState
  subst actualCandidateState
  cases evidence with
  | launch =>
      exact False.elim
        (by simpa [ConstructiveMixedKernelRuntimeEvidence,
          ConstructiveMixedKernelSourceEvidence.phase] using runtimeEvidence)
  | semanticTransfer | externalOperation | externalBoundary | returned |
      terminated | matchingFault =>
      simpa [ConstructiveMixedKernelPhaseMachineStatesRelated] using
        runtimeRelated

#print axioms ReflectedNativeLaunchGraphRoute.replay?_sound
#print axioms directExactCandidateNativeLaunchRoot_canonicalRootExact
#print axioms ExactNativeLaunchGraphRuntime.replayTotal
#print axioms OriginalEngineStateHolds.of_launch_exact
#print axioms ConstructiveMixedKernelPhaseStateFacts.ofLaunchExact
#print axioms ConstructiveMixedKernelPhaseStateFacts.launchRelated
#print axioms ExactConstructiveMixedLaunchCarrier.canonicalExecutions
#print axioms ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact

end StageA.Relational.InterpreterMixedLaunchRefinement
