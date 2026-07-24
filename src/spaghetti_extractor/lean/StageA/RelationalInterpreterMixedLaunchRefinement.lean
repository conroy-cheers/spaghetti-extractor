import StageA.RelationalInterpreterNativeLaunch

namespace StageA.Relational.InterpreterMixedLaunchRefinement

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Guard-complete native launch-wrapper refinement

The older launch certificate submits one linear path for each source.  That is
not a total certificate for a wrapper containing a data-dependent branch.
This module instead reflects the complete finite instruction graph.  Every
ordinary successor is re-derived from exact PE bytes, every internal edge must
decrease a checked rank, and replay follows the concrete branch selected by the
native transition system.

Static graph data is not itself a claim that every launch state reaches the
destination or establishes the engine relation.  Those remain explicit fields
of `ExactMixedLaunchGraphRefinement`; successful replay is the only source of
the path proposition used by those fields.
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

#print axioms ReflectedNativeLaunchGraphRoute.replay?_sound
#print axioms directExactCandidateNativeLaunchRoot_canonicalRootExact

end StageA.Relational.InterpreterMixedLaunchRefinement
