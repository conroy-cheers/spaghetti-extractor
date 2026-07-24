import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterNativeLaunch

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeWorld

/-! # Exact native launch-wrapper certificates

The certificate payload below is only a finite list of RVAs and exact bytes.
Static checking re-reads and decodes those bytes from the candidate PE.  The
semantic theorem then replays the same list with the candidate native-world
transition system.  There is deliberately no field containing a submitted
path proposition.
-/

inductive StableInterpreterCutpointKind where
  | dispatch
  | returnWrapper
  | terminationWrapper
deriving Repr, DecidableEq

structure StableInterpreterCutpoint where
  kind : StableInterpreterCutpointKind
  rva : Nat
deriving Repr, DecidableEq

/-- The exact launch-root inventory of one candidate PE. -/
structure CandidatePELaunchRoots where
  entryRva : Nat
  tlsCallbackRvas : List Nat
deriving Repr, DecidableEq

def CandidatePELaunchRoots.initialRva (roots : CandidatePELaunchRoots) : Nat :=
  roots.tlsCallbackRvas.head?.getD roots.entryRva

/-- Continuations supplied by the bounded loader profile after the initial
root.  Each TLS callback continues at the next callback, and the final TLS
callback continues at the PE entrypoint. -/
def CandidatePELaunchRoots.continuationRvas
    (roots : CandidatePELaunchRoots) : List Nat :=
  match roots.tlsCallbackRvas with
  | [] => []
  | _ :: callbacks => callbacks ++ [roots.entryRva]

/-- Parse candidate roots directly from the candidate PE.  The TLS array must
be immutable so an earlier callback cannot rewrite a later launch root. -/
def candidatePELaunchRoots? (pe : PE32) : Option CandidatePELaunchRoots := do
  if pe.entrypointRva == 0 || !tlsCallbackArrayImmutable pe then none else
  let tlsCallbackRvas <- parseTlsCallbackRvas pe
  pure { entryRva := pe.entrypointRva, tlsCallbackRvas }

/-- Candidate launch roots are selected from parsed PE data, never from a
linker label or a caller-supplied RVA. -/
inductive CanonicalNativeLaunchRoot where
  | entry
  | tlsCallback (index : Nat)
deriving Repr, DecidableEq

def CanonicalNativeLaunchRoot.rva? (pe : PE32) :
    CanonicalNativeLaunchRoot -> Option Nat
  | .entry => (candidatePELaunchRoots? pe).map (fun roots => roots.entryRva)
  | .tlsCallback index => do
      let roots <- candidatePELaunchRoots? pe
      roots.tlsCallbackRvas[index]?

def canonicalNativeLaunchRoots? (pe : PE32) :
    Option (List CanonicalNativeLaunchRoot) := do
  let roots <- candidatePELaunchRoots? pe
  pure (.entry ::
    (List.range roots.tlsCallbackRvas.length).map (.tlsCallback ·))

/-! This is the bridge-facing replacement for a candidate root obtained from
the paired static code map.  Only the callback count is synchronized with the
original-side launch schedule; no original target identifier is interpreted as
a private candidate RVA. -/

def DirectExactCandidateNativeLaunchRoot
    (candidate : ExactNativeWorldProgram) (launch : PE32ConsoleLaunchV2)
    (candidateRootRva : Nat) : Prop :=
  exists roots,
    candidatePELaunchRoots? candidate.pe = some roots /\
      roots.tlsCallbackRvas.length = launch.tlsCallbackTargetIds.length /\
      candidateRootRva = roots.initialRva

def directExactCandidateNativeLaunchRootChecked
    (candidate : ExactNativeWorldProgram) (launch : PE32ConsoleLaunchV2)
    (candidateRootRva : Nat) : Bool :=
  match candidatePELaunchRoots? candidate.pe with
  | none => false
  | some roots =>
      roots.tlsCallbackRvas.length == launch.tlsCallbackTargetIds.length &&
        candidateRootRva == roots.initialRva

theorem directExactCandidateNativeLaunchRootChecked_iff
    (candidate : ExactNativeWorldProgram) (launch : PE32ConsoleLaunchV2)
    (candidateRootRva : Nat) :
    directExactCandidateNativeLaunchRootChecked candidate launch
        candidateRootRva = true ↔
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva := by
  unfold directExactCandidateNativeLaunchRootChecked
  unfold DirectExactCandidateNativeLaunchRoot
  cases rootsExact : candidatePELaunchRoots? candidate.pe with
  | none => simp [rootsExact]
  | some roots => simp [rootsExact]

theorem DirectExactCandidateNativeLaunchRoot.resolvesFromCandidatePE
    {candidate : ExactNativeWorldProgram} {launch : PE32ConsoleLaunchV2}
    {candidateRootRva : Nat}
    (exact : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva) :
    (candidatePELaunchRoots? candidate.pe).map
        CandidatePELaunchRoots.initialRva = some candidateRootRva := by
  rcases exact with ⟨roots, rootsExact, _, rootExact⟩
  simp [rootsExact, rootExact]

/-- Recover the candidate return-slot address selected by one checked launch
frame inventory.  The return word itself remains concrete machine memory and
is verified by `transitionFromNativeWorldOutcome` when the root returns. -/
def candidateNativeLaunchFrame (state : MachineState)
    (continuationRva : Nat) (inventory : ReturnSlotOffsetInventory) :
    NativeCallFrame :=
  let location := inventory.representative
  let slot := state.registers.get location.candidateRegister +
    location.candidateOffset
  { continuationRva, returnAddress := Memory.read32 state.memory slot }

/-- Exact candidate loader continuations for one initial machine state.  The
parser fixes callback order and the launch inventory fixes every return-slot
location.  Length disagreement fails closed instead of truncating `List.zip`.
-/
def candidateNativeLaunchCallFrames?
    (candidate : ExactNativeWorldProgram) (launch : PE32ConsoleLaunchV2)
    (state : MachineState) : Option (List NativeCallFrame) := do
  let roots <- candidatePELaunchRoots? candidate.pe
  if roots.tlsCallbackRvas.length != launch.tlsCallbackTargetIds.length then
    none
  else if roots.continuationRvas.length != launch.frameOffsets.length then
    none
  else
    pure ((List.zip roots.continuationRvas launch.frameOffsets).map
      (fun pair => candidateNativeLaunchFrame state pair.1 pair.2))

theorem candidateNativeLaunchCallFrames?_exists
    {candidate : ExactNativeWorldProgram} {launch : PE32ConsoleLaunchV2}
    {candidateRootRva : Nat}
    (root : DirectExactCandidateNativeLaunchRoot candidate launch
      candidateRootRva)
    (frameCount : launch.frameOffsets.length =
      launch.continuationTargetIds.length) :
    forall state, exists calls,
      candidateNativeLaunchCallFrames? candidate launch state = some calls := by
  intro state
  rcases root with ⟨roots, rootsExact, callbackCount, _⟩
  have continuationCount : roots.continuationRvas.length =
      launch.continuationTargetIds.length := by
    simp only [CandidatePELaunchRoots.continuationRvas,
      PE32ConsoleLaunchV2.continuationTargetIds]
    cases originalCallbacks : launch.tlsCallbackTargetIds with
    | nil =>
        cases candidateCallbacks : roots.tlsCallbackRvas with
        | nil => simp [CandidatePELaunchRoots.continuationRvas,
            PE32ConsoleLaunchV2.continuationTargetIds, candidateCallbacks,
            originalCallbacks]
        | cons candidateHead candidateTail =>
            simp [candidateCallbacks, originalCallbacks] at callbackCount
    | cons originalHead originalTail =>
        cases candidateCallbacks : roots.tlsCallbackRvas with
        | nil => simp [candidateCallbacks, originalCallbacks] at callbackCount
        | cons candidateHead candidateTail =>
            simp only [candidateCallbacks, originalCallbacks, List.length_cons,
              List.length_append, List.length_singleton] at callbackCount ⊢
            omega
  refine ⟨(List.zip roots.continuationRvas launch.frameOffsets).map
      (fun pair => candidateNativeLaunchFrame state pair.1 pair.2), ?_⟩
  simp [candidateNativeLaunchCallFrames?, rootsExact, callbackCount,
    continuationCount, frameCount]

inductive NativeLaunchPathSource where
  | canonicalRoot (root : CanonicalNativeLaunchRoot)
  | stableCutpoint (index : Nat)
deriving Repr, DecidableEq

inductive NativeLaunchPathDestination where
  | stableCutpoint (index : Nat)
  | returned
  | terminated
deriving Repr, DecidableEq

def NativeLaunchPathSource.rva? (pe : PE32)
    (cutpoints : List StableInterpreterCutpoint) :
    NativeLaunchPathSource -> Option Nat
  | .canonicalRoot root => root.rva? pe
  | .stableCutpoint index => cutpoints[index]?.map (·.rva)

def NativeLaunchPathSource.matches (pe : PE32)
    (cutpoints : List StableInterpreterCutpoint)
    (source : NativeLaunchPathSource) : NativeWorldExecution -> Bool
  | .running rva .. => source.rva? pe cutpoints == some rva
  | _ => false

def NativeLaunchPathDestination.matches
    (cutpoints : List StableInterpreterCutpoint)
    (destination : NativeLaunchPathDestination) : NativeWorldExecution -> Bool
  | .running rva .. =>
      match destination with
      | .stableCutpoint index => cutpoints[index]?.map (·.rva) == some rva
      | _ => false
  | .returned .. => destination == .returned
  | .terminated .. => destination == .terminated
  | _ => false

def NativeLaunchPathSource.shapeChecked
    (cutpoints : List StableInterpreterCutpoint)
    (source : NativeLaunchPathSource)
    (destination : NativeLaunchPathDestination) : Bool :=
  match source, destination with
  | .canonicalRoot _, .stableCutpoint index =>
      cutpoints[index]?.map (·.kind) == some .dispatch
  | .stableCutpoint index, .returned =>
      cutpoints[index]?.map (·.kind) == some .returnWrapper
  | .stableCutpoint index, .terminated =>
      cutpoints[index]?.map (·.kind) == some .terminationWrapper
  | _, _ => false

/-- The reviewed wrapper profile excludes both forms of indirect control.  An
indirect call is not accepted merely because its continuation is statically
known. -/
def nativeWrapperInstructionSupported (pe : PE32)
    (imports : List PEImport) (instruction : KernelInstruction) : Bool :=
  match instruction.semantics? pe imports with
  | some (.next _) => true
  | some (.stop behavior) =>
      match behavior.outcome with
      | some (.indirectCall ..) | some (.indirectJump ..) => false
      | some _ => true
      | none => false
  | none => false

def nativeWrapperInstructionCanFinishAt (pe : PE32)
    (imports : List PEImport) (cutpoints : List StableInterpreterCutpoint)
    (instruction : KernelInstruction) : NativeLaunchPathDestination -> Bool
  | .stableCutpoint index =>
      match cutpoints[index]?, instruction.staticSuccessors? pe imports with
      | some cutpoint, some successors => successors.contains cutpoint.rva
      | _, _ => false
  | .returned =>
      match instruction.semantics? pe imports with
      | some (.stop behavior) =>
          match behavior.outcome with
          | some (.returned _) => true
          | _ => false
      | _ => false
  | .terminated =>
      match instruction.semantics? pe imports with
      | some (.stop behavior) =>
          match behavior.outcome with
          | some (.externalCall ..) | some (.externalJump ..) => true
          | _ => false
      | _ => false

def exactNativeWrapperInstructionsChecked (pe : PE32)
    (imports : List PEImport) (cutpoints : List StableInterpreterCutpoint)
    (destination : NativeLaunchPathDestination) :
    List KernelInstruction -> Bool
  | [] => false
  | [instruction] =>
      nativeWrapperInstructionSupported pe imports instruction &&
        nativeWrapperInstructionCanFinishAt pe imports cutpoints instruction
          destination
  | instruction :: next :: tail =>
      nativeWrapperInstructionSupported pe imports instruction &&
        match instruction.staticSuccessors? pe imports with
        | some successors =>
            successors.contains next.rva &&
              exactNativeWrapperInstructionsChecked pe imports cutpoints
                destination (next :: tail)
        | none => false

/-- Compact reflected path data.  `steps` contains only exact instruction
bytes, not intermediate machine states or a claimed semantic path. -/
structure ReflectedNativeLaunchPathCertificate where
  source : NativeLaunchPathSource
  destination : NativeLaunchPathDestination
  steps : List KernelInstruction
deriving Repr, DecidableEq

def ReflectedNativeLaunchPathCertificate.staticChecked
    (path : ReflectedNativeLaunchPathCertificate) (pe : PE32)
    (imports : List PEImport)
    (cutpoints : List StableInterpreterCutpoint) : Bool :=
  path.source.shapeChecked cutpoints path.destination &&
    match path.steps.head? with
    | none => false
    | some first =>
        path.source.rva? pe cutpoints == some first.rva &&
          exactNativeWrapperInstructionsChecked pe imports cutpoints
            path.destination path.steps

/-- Check that each reflected instruction is exactly the instruction at the
current native-world state and that every non-final step remains executable.
Faults, proof blocks, and premature terminal states fail closed. -/
def exactNativeWrapperRuntimeStepsChecked (program : ExactNativeWorldProgram) :
    NativeWorldExecution -> List KernelInstruction -> Bool
  | _, [] => true
  | before, instruction :: tail =>
      match before with
      | .running rva .. =>
          rva == instruction.rva &&
            (instruction.decode? program.pe).isSome &&
              let transition := program.transitionSystem.step before
              match transition.next with
              | .fault _ | .blocked _ => false
              | next =>
                  if tail.isEmpty then true
                  else exactNativeWrapperRuntimeStepsChecked program next tail
      | _ => false

structure ReflectedNativeLaunchPathReplay where
  after : NativeWorldExecution
  observations : List WorldRelationalObservable

def ReflectedNativeLaunchPathCertificate.replay?
    (path : ReflectedNativeLaunchPathCertificate)
    (program : ExactNativeWorldProgram)
    (cutpoints : List StableInterpreterCutpoint)
    (before : NativeWorldExecution) :
    Option ReflectedNativeLaunchPathReplay :=
  if path.staticChecked program.pe program.imports cutpoints then
    if path.source.matches program.pe cutpoints before then
      if exactNativeWrapperRuntimeStepsChecked program before path.steps then
        let replay := runRelatedSteps program.transitionSystem path.steps.length before
        if path.destination.matches cutpoints replay.1 then
          some { after := replay.1, observations := replay.2 }
        else none
      else none
    else none
  else none

/-- Successful reflection is semantic authority: its positive finite path is
derived from `runRelatedSteps` over the exact candidate transition system. -/
theorem ReflectedNativeLaunchPathCertificate.replay?_sound
    (path : ReflectedNativeLaunchPathCertificate)
    (program : ExactNativeWorldProgram)
    (cutpoints : List StableInterpreterCutpoint)
    (before : NativeWorldExecution) (result : ReflectedNativeLaunchPathReplay)
    (replayed : path.replay? program cutpoints before = some result) :
    path.source.matches program.pe cutpoints before = true /\
      path.destination.matches cutpoints result.after = true /\
      NonemptyRelatedPath program.transitionSystem before result.observations
        result.after := by
  unfold ReflectedNativeLaunchPathCertificate.replay? at replayed
  split at replayed <;> try contradiction
  rename_i staticPassed
  split at replayed <;> try contradiction
  rename_i sourcePassed
  split at replayed <;> try contradiction
  rename_i runtimePassed
  change (if path.destination.matches cutpoints
      (runRelatedSteps program.transitionSystem path.steps.length before).1 then
        some {
          after :=
            (runRelatedSteps program.transitionSystem path.steps.length before).1
          observations :=
            (runRelatedSteps program.transitionSystem path.steps.length before).2
        }
      else none) = some result at replayed
  split at replayed <;> try contradiction
  rename_i destinationPassed
  have stepsNonempty : path.steps ≠ [] := by
    intro noSteps
    simp [ReflectedNativeLaunchPathCertificate.staticChecked, noSteps] at staticPassed
  have nonempty : path.steps.length > 0 := by
    cases stepsExact : path.steps with
    | nil => exact False.elim (stepsNonempty stepsExact)
    | cons => simp
  cases replayed
  refine ⟨sourcePassed, destinationPassed, ?_⟩
  exact ⟨path.steps.length, nonempty, rfl⟩

def stableInterpreterCutpointIndices
  (kind : StableInterpreterCutpointKind)
    (cutpoints : List StableInterpreterCutpoint) : List Nat :=
  (List.range cutpoints.length).filter fun index =>
    cutpoints[index]?.map (fun cutpoint => cutpoint.kind) == some kind

structure ExactNativeLaunchWrapperCertificate where
  cutpoints : List StableInterpreterCutpoint
  paths : List ReflectedNativeLaunchPathCertificate
deriving Repr, DecidableEq

def ExactNativeLaunchWrapperCertificate.expectedSources?
    (certificate : ExactNativeLaunchWrapperCertificate) (pe : PE32) :
    Option (List NativeLaunchPathSource) := do
  let roots <- canonicalNativeLaunchRoots? pe
  pure (
    roots.map (fun root => .canonicalRoot root) ++
    (stableInterpreterCutpointIndices .returnWrapper certificate.cutpoints).map
      (fun index => .stableCutpoint index) ++
    (stableInterpreterCutpointIndices .terminationWrapper certificate.cutpoints).map
      (fun index => .stableCutpoint index))

/-- Complete finite coverage consists of one path for the PE entry, one for
each parsed TLS callback in image order, and one checked outbound path for each
declared return/termination wrapper cutpoint. -/
def ExactNativeLaunchWrapperCertificate.staticChecked
    (certificate : ExactNativeLaunchWrapperCertificate) (pe : PE32)
    (imports : List PEImport) : Bool :=
  !certificate.cutpoints.isEmpty &&
    decide (certificate.cutpoints.map (fun cutpoint => cutpoint.rva)).Nodup &&
    (certificate.cutpoints.all fun cutpoint =>
      rvaInExecutableSection pe cutpoint.rva) &&
    some (certificate.paths.map (fun path => path.source)) ==
      certificate.expectedSources? pe &&
    certificate.paths.all fun path =>
      path.staticChecked pe imports certificate.cutpoints

def ExactNativeLaunchWrapperCertificate.SemanticallySound
    (certificate : ExactNativeLaunchWrapperCertificate)
    (program : ExactNativeWorldProgram) : Prop :=
  forall path, path ∈ certificate.paths ->
    forall before result,
      path.replay? program certificate.cutpoints before = some result ->
        path.source.matches program.pe certificate.cutpoints before = true /\
          path.destination.matches certificate.cutpoints result.after = true /\
          NonemptyRelatedPath program.transitionSystem before result.observations
            result.after

theorem ExactNativeLaunchWrapperCertificate.semanticSound
    (certificate : ExactNativeLaunchWrapperCertificate)
    (program : ExactNativeWorldProgram) :
    certificate.SemanticallySound program := by
  intro path _ before result replayed
  exact path.replay?_sound program certificate.cutpoints before result replayed

#print axioms ReflectedNativeLaunchPathCertificate.replay?_sound
#print axioms ExactNativeLaunchWrapperCertificate.semanticSound

end StageA.Relational.InterpreterNativeLaunch
