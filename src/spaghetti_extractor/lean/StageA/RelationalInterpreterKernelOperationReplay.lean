import StageA.RelationalInterpreterKernelMixedReplayWorld

namespace StageA.Relational.InterpreterKernelOperationReplay

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelMixedReplay
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SymbolicSoundness

/-!
# Checked native-operation replay

Operation proofs use finite internal paths repeatedly: prologues, branch arms,
call preparation, call completion, loop bodies, and epilogues.  This module
provides one exact replay object for all of them.  Its endpoint and observations
are computed by the native transition system; generated artifacts cannot submit
either value.

The mixed-instruction replay remains the byte-level authority.  A successful
internal replay is lifted into the ordinary native-world transition system
without changing call frames, external events, or the relational world.
-/

/-- A finite native path with a computed endpoint. -/
structure CheckedNativeOperationPath
    (candidate : ExactNativeWorldProgram)
    (before : NativeWorldExecution) where
  fuel : Nat
  positive : 0 < fuel

def CheckedNativeOperationPath.result
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (path : CheckedNativeOperationPath candidate before) :
    NativeWorldExecution × List WorldRelationalObservable :=
  runRelatedSteps candidate.transitionSystem path.fuel before

def CheckedNativeOperationPath.after
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (path : CheckedNativeOperationPath candidate before) :
    NativeWorldExecution :=
  path.result.1

def CheckedNativeOperationPath.observations
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (path : CheckedNativeOperationPath candidate before) :
    List WorldRelationalObservable :=
  path.result.2

theorem CheckedNativeOperationPath.path
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (path : CheckedNativeOperationPath candidate before) :
    NonemptyRelatedPath candidate.transitionSystem before path.observations
      path.after :=
  ⟨path.fuel, path.positive, rfl⟩

/-- Repackage an already-proved finite path as a computed path handle.  The
fuel is the witness carried by `NonemptyRelatedPath`; no endpoint,
observations, or post-state are accepted independently. -/
noncomputable def CheckedNativeOperationPath.ofNonempty
    {candidate : ExactNativeWorldProgram} {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath candidate.transitionSystem before observations
      after) :
    CheckedNativeOperationPath candidate before := {
  fuel := Classical.choose path
  positive := (Classical.choose_spec path).1
}

theorem CheckedNativeOperationPath.ofNonempty_after
    {candidate : ExactNativeWorldProgram} {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath candidate.transitionSystem before observations
      after) :
    (CheckedNativeOperationPath.ofNonempty path).after = after := by
  exact congrArg Prod.fst (Classical.choose_spec path).2

theorem CheckedNativeOperationPath.ofNonempty_observations
    {candidate : ExactNativeWorldProgram} {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath candidate.transitionSystem before observations
      after) :
    (CheckedNativeOperationPath.ofNonempty path).observations =
      observations := by
  exact congrArg Prod.snd (Classical.choose_spec path).2

/-- Typed views of a computed endpoint.  The view contains no state supplied by
the certificate: each payload is extracted from `path.after`. -/
inductive NativeOperationEndpointView where
  | running (rva undefinedSlot : Nat) (state : MachineState)
      (calls : List NativeCallFrame) (eventIndex : Nat)
      (events : List NativeExternalEvent) (world : RelationalWorld)
  | returned (state : MachineState) (events : List NativeExternalEvent)
      (world : RelationalWorld)
  | terminated (events : List NativeExternalEvent) (world : RelationalWorld)
  | fault (cause : ModeledFault)
  | blocked (reason : ExecutionBlock)

def nativeOperationEndpointView :
    NativeWorldExecution -> NativeOperationEndpointView
  | .running rva undefinedSlot state calls eventIndex events world =>
      .running rva undefinedSlot state calls eventIndex events world
  | .returned state events world => .returned state events world
  | .terminated events world => .terminated events world
  | .fault cause => .fault cause
  | .blocked reason => .blocked reason

def NativeOperationEndpointView.execution :
    NativeOperationEndpointView -> NativeWorldExecution
  | .running rva undefinedSlot state calls eventIndex events world =>
      .running rva undefinedSlot state calls eventIndex events world
  | .returned state events world => .returned state events world
  | .terminated events world => .terminated events world
  | .fault cause => .fault cause
  | .blocked reason => .blocked reason

@[simp] theorem nativeOperationEndpointView_execution
    (execution : NativeWorldExecution) :
    (nativeOperationEndpointView execution).execution = execution := by
  cases execution <;> rfl

def CheckedNativeOperationPath.endpointView
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (path : CheckedNativeOperationPath candidate before) :
    NativeOperationEndpointView :=
  nativeOperationEndpointView path.after

@[simp] theorem CheckedNativeOperationPath.endpointView_execution
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (path : CheckedNativeOperationPath candidate before) :
    path.endpointView.execution = path.after :=
  nativeOperationEndpointView_execution path.after

/-! ## Checked instruction leaves

The reusable symbolic proof unit is one exact instruction.  Larger fused
symbolic summaries require a separate naturality theorem and are therefore not
accepted by this layer.  Long operation paths compose these leaves and retain
calls, returns, branches, x87 protocol operations, and external events as
explicit cutpoints.
-/

/-- Reflectively check one proposed decode and symbolic result against the
exact PE.  The proposal is data only: all equalities used by the soundness
proof are recovered from this Boolean result. -/
def checkedNativeOperationInstructionReplayStatic
    (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (fetched : Bytes) (decoded : DecodedInstruction) : Bool :=
  executableInstructionWindow pe instruction.rva == some fetched &&
    decodeKernelX87FrameExact fetched == none &&
    StageA.Relational.X87.decodeCommandExact fetched == none &&
    instruction.decode? pe == some decoded &&
    (executeInstruction pe imports instruction.rva
      undefinedSlot decoded initialSymbolic).isSome

/-- Runtime environments do not participate in exact instruction decoding or
symbolic semantics.  Keep the historical candidate-indexed spelling as a thin
projection over the static checker. -/
def checkedNativeOperationInstructionReplay
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (fetched : Bytes) (decoded : DecodedInstruction) : Bool :=
  checkedNativeOperationInstructionReplayStatic candidate.pe candidate.imports
    instruction undefinedSlot fetched decoded

/-- Exact decoder and reviewed symbolic-semantics result for one instruction.
No execution equality is a certificate field. -/
structure CheckedNativeOperationInstructionReplay
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat) where
  fetched : Bytes
  decoded : DecodedInstruction
  checked : checkedNativeOperationInstructionReplay candidate instruction
    undefinedSlot fetched decoded = true

private def defaultNativeOperationDecodedInstruction : DecodedInstruction := {
  instruction := .nop
  size := 1
  trailing := []
}

def canonicalNativeOperationFetchedStatic
    (pe : PE32)
    (instruction : KernelInstruction) : Bytes :=
  (executableInstructionWindow pe instruction.rva).getD []

def canonicalNativeOperationDecodedStatic
    (pe : PE32)
    (instruction : KernelInstruction) : DecodedInstruction :=
  (instruction.decode? pe).getD
    defaultNativeOperationDecodedInstruction

def canonicalNativeOperationInstructionCheckedStatic
    (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) (undefinedSlot : Nat) : Bool :=
  checkedNativeOperationInstructionReplayStatic pe imports instruction
    undefinedSlot
    (canonicalNativeOperationFetchedStatic pe instruction)
    (canonicalNativeOperationDecodedStatic pe instruction)

def canonicalNativeOperationFetched
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) : Bytes :=
  canonicalNativeOperationFetchedStatic candidate.pe instruction

def canonicalNativeOperationDecoded
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) : DecodedInstruction :=
  canonicalNativeOperationDecodedStatic candidate.pe instruction

def canonicalNativeOperationInstructionChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat) : Bool :=
  canonicalNativeOperationInstructionCheckedStatic candidate.pe
    candidate.imports instruction undefinedSlot

/-- Canonical checked leaf used by generated modules.  Generated code supplies
only the exact instruction and a reducible Boolean proof; fetched bytes,
decode, and symbolic execution are all computed here. -/
def CheckedNativeOperationInstructionReplay.ofCanonicalChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (checked : canonicalNativeOperationInstructionChecked candidate instruction
      undefinedSlot = true) :
    CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot := {
  fetched := canonicalNativeOperationFetched candidate instruction
  decoded := canonicalNativeOperationDecoded candidate instruction
  checked
}

/-- Bind one environment-independent checked instruction to an arbitrary
runtime environment carrying the same exact PE and import table. -/
def CheckedNativeOperationInstructionReplay.ofCanonicalStaticChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (checked :
      canonicalNativeOperationInstructionCheckedStatic candidate.pe
        candidate.imports instruction undefinedSlot = true) :
    CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot :=
  .ofCanonicalChecked candidate instruction undefinedSlot checked

def CheckedNativeOperationInstructionReplay.result?
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot) : Option InstructionResult :=
  executeInstruction candidate.pe candidate.imports instruction.rva
    undefinedSlot replay.decoded initialSymbolic

def CheckedNativeOperationInstructionReplay.symbolic
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot) : InstructionResult :=
  replay.result?.getD (.next initialSymbolic)

def canonicalNativeOperationInstructionResultStatic
    (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) (undefinedSlot : Nat) :
    InstructionResult :=
  (executeInstruction pe imports instruction.rva undefinedSlot
    (canonicalNativeOperationDecodedStatic pe instruction)
    initialSymbolic).getD (.next initialSymbolic)

/-- Forget whether exact symbolic execution stopped at a control boundary while
retaining the behavior shared by both instruction-result constructors. -/
def instructionResultBehavior : InstructionResult -> SymbolicBehavior
  | .next behavior | .stop behavior => behavior

def canonicalNativeOperationInstructionBehaviorStatic
    (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) (undefinedSlot : Nat) :
    SymbolicBehavior :=
  instructionResultBehavior
    (canonicalNativeOperationInstructionResultStatic pe imports instruction
      undefinedSlot)

theorem CheckedNativeOperationInstructionReplay.facts
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot) :
    executableInstructionWindow candidate.pe instruction.rva =
        some replay.fetched ∧
      decodeKernelX87FrameExact replay.fetched = none ∧
      StageA.Relational.X87.decodeCommandExact replay.fetched = none ∧
      instruction.decode? candidate.pe = some replay.decoded ∧
      executeInstruction candidate.pe candidate.imports instruction.rva
        undefinedSlot replay.decoded initialSymbolic = some replay.symbolic := by
  have checked := replay.checked
  simp only [checkedNativeOperationInstructionReplay,
    checkedNativeOperationInstructionReplayStatic, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨⟨⟨fetched, frame⟩, command⟩, decoded⟩, executed⟩
  refine ⟨fetched, frame, command, decoded, ?_⟩
  change replay.result?.isSome = true at executed
  change replay.result? = some replay.symbolic
  cases resultExact : replay.result? with
  | none =>
      simp [resultExact] at executed
  | some result =>
      simp [CheckedNativeOperationInstructionReplay.symbolic, resultExact]

def CheckedNativeOperationInstructionReplay.behavior
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot) : SymbolicBehavior :=
  instructionResultBehavior replay.symbolic

/-- A running instruction leaf additionally checks that the symbolic result
does not carry a control outcome. -/
def checkedNativeOperationRunningResult : InstructionResult -> Bool
  | .next behavior => behavior.outcome.isNone
  | .stop _ => false

structure CheckedNativeOperationRunningInstruction
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    extends CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot where
  runningChecked :
    checkedNativeOperationRunningResult
      toCheckedNativeOperationInstructionReplay.symbolic = true

def CheckedNativeOperationRunningInstruction.ofCanonicalChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (instructionChecked :
      canonicalNativeOperationInstructionChecked candidate instruction
        undefinedSlot = true)
    (runningChecked :
      checkedNativeOperationRunningResult
        ((CheckedNativeOperationInstructionReplay.ofCanonicalChecked candidate
          instruction undefinedSlot instructionChecked).symbolic) = true) :
    CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot := {
  toCheckedNativeOperationInstructionReplay :=
    .ofCanonicalChecked candidate instruction undefinedSlot instructionChecked
  runningChecked
}

def CheckedNativeOperationRunningInstruction.ofCanonicalStaticChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (instructionChecked :
      canonicalNativeOperationInstructionCheckedStatic candidate.pe
        candidate.imports instruction undefinedSlot = true)
    (runningChecked :
      checkedNativeOperationRunningResult
        (canonicalNativeOperationInstructionResultStatic candidate.pe
          candidate.imports instruction undefinedSlot) = true) :
    CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot :=
  .ofCanonicalChecked candidate instruction undefinedSlot instructionChecked
    runningChecked

@[simp] theorem
    CheckedNativeOperationRunningInstruction.ofCanonicalStaticChecked_behavior
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (instructionChecked :
      canonicalNativeOperationInstructionCheckedStatic candidate.pe
        candidate.imports instruction undefinedSlot = true)
    (runningChecked :
      checkedNativeOperationRunningResult
        (canonicalNativeOperationInstructionResultStatic candidate.pe
          candidate.imports instruction undefinedSlot) = true) :
    (CheckedNativeOperationRunningInstruction.ofCanonicalStaticChecked
      candidate instruction undefinedSlot instructionChecked
      runningChecked).behavior =
        canonicalNativeOperationInstructionBehaviorStatic candidate.pe
          candidate.imports instruction undefinedSlot := by
  rfl

theorem CheckedNativeOperationRunningInstruction.resultFacts
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot) :
    replay.symbolic = .next replay.behavior ∧
      replay.behavior.outcome = none := by
  cases symbolicExact : replay.symbolic with
  | next behavior =>
      have outcomeExact : behavior.outcome = none := by
        simpa [checkedNativeOperationRunningResult, symbolicExact,
          Option.isNone_iff_eq_none] using replay.runningChecked
      constructor
      · simpa [CheckedNativeOperationInstructionReplay.behavior,
          instructionResultBehavior, symbolicExact]
          using symbolicExact
      · simpa [CheckedNativeOperationInstructionReplay.behavior,
          instructionResultBehavior, symbolicExact]
          using outcomeExact
  | stop behavior =>
      have impossible : False := by
        simpa [checkedNativeOperationRunningResult, symbolicExact] using
          replay.runningChecked
      exact False.elim impossible

theorem CheckedNativeOperationRunningInstruction.stepExact
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot)
    (input : MachineState) :
    stepKernelPE32Instruction candidate.pe candidate.imports
        (.running instruction.rva undefinedSlot input) =
      .running (instruction.rva + replay.decoded.size) (undefinedSlot + 1)
        (concreteBehaviorNextMachineState
          (replay.behavior.eval input) input) := by
  have composed := executeInstruction_composes candidate.pe candidate.imports
    undefinedSlot input instruction replay.decoded replay.facts.2.2.2.1
  simp only [stepKernelPE32Instruction, replay.facts.1,
    replay.facts.2.1, replay.facts.2.2.1]
  rw [← composed]
  unfold KernelInstruction.semanticStep
  simp only [replay.facts.2.2.2.1]
  rw [replay.facts.2.2.2.2, replay.resultFacts.1]
  simp [executeInstructionResult, replay.resultFacts.2,
    SymbolicBehavior.eval]

theorem CheckedNativeOperationRunningInstruction.worldStepExact
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot)
    (input : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    candidate.transitionSystem.step
        (.running instruction.rva undefinedSlot input calls eventIndex events
          world) =
      {
        next := .running (instruction.rva + replay.decoded.size)
          (undefinedSlot + 1)
          (concreteBehaviorNextMachineState (replay.behavior.eval input) input)
          calls eventIndex events world
        observation := none
      } := by
  simp [ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, replay.stepExact]

theorem CheckedNativeOperationRunningInstruction.path
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot)
    (input : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running instruction.rva undefinedSlot input calls eventIndex events
        world) []
      (.running (instruction.rva + replay.decoded.size) (undefinedSlot + 1)
        (concreteBehaviorNextMachineState (replay.behavior.eval input) input)
        calls eventIndex events world) := by
  refine ⟨1, Nat.zero_lt_succ 0, ?_⟩
  simp [runRelatedSteps, replay.worldStepExact]

/-- A stopped instruction leaf retains the exact symbolic outcome selected by
the reviewed instruction semantics. -/
def checkedNativeOperationStoppedResult : InstructionResult -> Bool
  | .next _ => false
  | .stop behavior => behavior.outcome.isSome

structure CheckedNativeOperationStoppedInstruction
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    extends CheckedNativeOperationInstructionReplay candidate instruction
      undefinedSlot where
  stoppedChecked :
    checkedNativeOperationStoppedResult
      toCheckedNativeOperationInstructionReplay.symbolic = true

def CheckedNativeOperationStoppedInstruction.ofCanonicalChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (instructionChecked :
      canonicalNativeOperationInstructionChecked candidate instruction
        undefinedSlot = true)
    (stoppedChecked :
      checkedNativeOperationStoppedResult
        ((CheckedNativeOperationInstructionReplay.ofCanonicalChecked candidate
          instruction undefinedSlot instructionChecked).symbolic) = true) :
    CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot := {
  toCheckedNativeOperationInstructionReplay :=
    .ofCanonicalChecked candidate instruction undefinedSlot instructionChecked
  stoppedChecked
}

def CheckedNativeOperationStoppedInstruction.ofCanonicalStaticChecked
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (instructionChecked :
      canonicalNativeOperationInstructionCheckedStatic candidate.pe
        candidate.imports instruction undefinedSlot = true)
    (stoppedChecked :
      checkedNativeOperationStoppedResult
        (canonicalNativeOperationInstructionResultStatic candidate.pe
          candidate.imports instruction undefinedSlot) = true) :
    CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot :=
  .ofCanonicalChecked candidate instruction undefinedSlot instructionChecked
    stoppedChecked

@[simp] theorem
    CheckedNativeOperationStoppedInstruction.ofCanonicalStaticChecked_behavior
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelInstruction) (undefinedSlot : Nat)
    (instructionChecked :
      canonicalNativeOperationInstructionCheckedStatic candidate.pe
        candidate.imports instruction undefinedSlot = true)
    (stoppedChecked :
      checkedNativeOperationStoppedResult
        (canonicalNativeOperationInstructionResultStatic candidate.pe
          candidate.imports instruction undefinedSlot) = true) :
    (CheckedNativeOperationStoppedInstruction.ofCanonicalStaticChecked
      candidate instruction undefinedSlot instructionChecked
      stoppedChecked).behavior =
        canonicalNativeOperationInstructionBehaviorStatic candidate.pe
          candidate.imports instruction undefinedSlot := by
  rfl

theorem CheckedNativeOperationStoppedInstruction.resultFacts
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot) :
    replay.symbolic = .stop replay.behavior ∧
      replay.behavior.outcome.isSome = true := by
  cases symbolicExact : replay.symbolic with
  | next behavior =>
      have impossible : False := by
        simpa [checkedNativeOperationStoppedResult, symbolicExact] using
          replay.stoppedChecked
      exact False.elim impossible
  | stop behavior =>
      constructor
      · simpa [CheckedNativeOperationInstructionReplay.behavior,
          instructionResultBehavior, symbolicExact]
          using symbolicExact
      · simpa [CheckedNativeOperationInstructionReplay.behavior,
          instructionResultBehavior, symbolicExact,
          checkedNativeOperationStoppedResult] using replay.stoppedChecked

theorem CheckedNativeOperationStoppedInstruction.stepExact
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (input : MachineState) :
    stepKernelPE32Instruction candidate.pe candidate.imports
        (.running instruction.rva undefinedSlot input) =
      .stopped ((replay.behavior.eval input).outcome.getD (.jump 0))
        (concreteBehaviorNextMachineState
          (replay.behavior.eval input) input) := by
  have composed := executeInstruction_composes candidate.pe candidate.imports
    undefinedSlot input instruction replay.decoded replay.facts.2.2.2.1
  simp only [stepKernelPE32Instruction, replay.facts.1,
    replay.facts.2.1, replay.facts.2.2.1]
  rw [← composed]
  unfold KernelInstruction.semanticStep
  simp only [replay.facts.2.2.2.1]
  rw [replay.facts.2.2.2.2, replay.resultFacts.1]
  cases outcomeExact : replay.behavior.outcome with
  | none =>
      have impossible := replay.resultFacts.2
      simp [outcomeExact] at impossible
  | some outcome =>
      simp [executeInstructionResult, outcomeExact, SymbolicBehavior.eval]

theorem CheckedNativeOperationStoppedInstruction.worldStepExact
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (input : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    candidate.transitionSystem.step
        (.running instruction.rva undefinedSlot input calls eventIndex events
          world) =
      transitionFromNativeWorldOutcome candidate.pe candidate.environment
        candidate.callableExternal candidate.indirectTargets instruction.rva
        (concreteBehaviorNextMachineState (replay.behavior.eval input) input)
        calls eventIndex events world
        ((replay.behavior.eval input).outcome.getD (.jump 0)) := by
  simp [ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, replay.stepExact]

/-- One stopped instruction always contributes exactly one computed
native-world transition.  The transition function, rather than generated data,
selects the call frame, external event, fault, return, or next cutpoint. -/
theorem CheckedNativeOperationStoppedInstruction.path
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (input : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    let before : NativeWorldExecution :=
      .running instruction.rva undefinedSlot input calls eventIndex events world
    NonemptyRelatedPath candidate.transitionSystem before
      (candidate.transitionSystem.step before).observation.toList
      (candidate.transitionSystem.step before).next := by
  exact exactNativeWorldStepIsNonempty candidate
    (.running instruction.rva undefinedSlot input calls eventIndex events world)

/-! ## Exact function replay inventories -/

def canonicalNativeOperationFunctionEntries
    (candidate : ExactNativeWorldProgram) (entryRva byteLength : Nat) :
    List (CheckedKernelMixedReplayInstruction candidate.pe candidate.imports) :=
  (checkedKernelMixedReplaySpan? candidate.pe candidate.imports entryRva
    byteLength).getD []

def canonicalNativeOperationFunctionCheckedStatic
    (pe : PE32) (imports : List PEImport)
    (entryRva byteLength : Nat) : Bool :=
  (checkedKernelMixedReplaySpan? pe imports entryRva
    byteLength).isSome

def canonicalNativeOperationFunctionChecked
    (candidate : ExactNativeWorldProgram) (entryRva byteLength : Nat) : Bool :=
  canonicalNativeOperationFunctionCheckedStatic candidate.pe candidate.imports
    entryRva byteLength

/-- A complete mixed-decoder inventory for one contiguous native function.
The entry list is computed from exact PE bytes; generated artifacts submit only
the range and the reducible success check. -/
structure CheckedNativeOperationFunctionReplay
    (candidate : ExactNativeWorldProgram) where
  entryRva : Nat
  byteLength : Nat
  positive : 0 < byteLength
  checked :
    canonicalNativeOperationFunctionChecked candidate entryRva byteLength = true

def CheckedNativeOperationFunctionReplay.ofStaticChecked
    (candidate : ExactNativeWorldProgram)
    (entryRva byteLength : Nat) (positive : 0 < byteLength)
    (checked :
      canonicalNativeOperationFunctionCheckedStatic candidate.pe
        candidate.imports entryRva byteLength = true) :
    CheckedNativeOperationFunctionReplay candidate := {
  entryRva
  byteLength
  positive
  checked
}

def CheckedNativeOperationFunctionReplay.entries
    {candidate : ExactNativeWorldProgram}
    (replay : CheckedNativeOperationFunctionReplay candidate) :
    List (CheckedKernelMixedReplayInstruction candidate.pe candidate.imports) :=
  canonicalNativeOperationFunctionEntries candidate replay.entryRva
    replay.byteLength

theorem CheckedNativeOperationFunctionReplay.entriesExact
    {candidate : ExactNativeWorldProgram}
    (replay : CheckedNativeOperationFunctionReplay candidate) :
    checkedKernelMixedReplaySpan? candidate.pe candidate.imports replay.entryRva
      replay.byteLength = some replay.entries := by
  have checked := replay.checked
  unfold canonicalNativeOperationFunctionChecked
    canonicalNativeOperationFunctionCheckedStatic at checked
  unfold CheckedNativeOperationFunctionReplay.entries
    canonicalNativeOperationFunctionEntries
  cases exact : checkedKernelMixedReplaySpan? candidate.pe candidate.imports
      replay.entryRva replay.byteLength with
  | none => simp [exact] at checked
  | some entries => simp [exact]

theorem CheckedNativeOperationFunctionReplay.exactInventory
    {candidate : ExactNativeWorldProgram}
    (replay : CheckedNativeOperationFunctionReplay candidate) :
    ExactMixedReplayInventory candidate.pe candidate.imports
      (checkedKernelMixedReplayInstructions replay.entries) :=
  checkedKernelMixedReplayInstructions_exact replay.entries

/-- Exact mixed replay used for an internal path leaf.  The leaf contains only
the checked instructions and its concrete input.  Its result is computed below;
generated data cannot supply an endpoint equation. -/
structure CheckedNativeOperationInternalReplay
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelMixedReplayInstruction)
    (tail : List KernelMixedReplayInstruction)
    (undefinedSlot : Nat) (input : MachineState) where
  inventory : ∀ member, member ∈ instruction :: tail ->
    member.checked candidate.pe candidate.imports = true

def CheckedNativeOperationInternalReplay.result
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (_replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input) : PE32InstructionExecution :=
    runKernelMixedReplayConcrete candidate.pe candidate.imports undefinedSlot
      input (instruction :: tail)

/-- A dependent running endpoint extracted from the computed replay result. -/
structure CheckedNativeOperationRunningEndpoint
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input) where
  finalRva : Nat
  finalSlot : Nat
  after : MachineState
  exact : replay.result = .running finalRva finalSlot after

def CheckedNativeOperationInternalReplay.runningEndpoint?
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input) :
    Option (CheckedNativeOperationRunningEndpoint replay) :=
  match exact : replay.result with
  | .running finalRva finalSlot after =>
      some { finalRva, finalSlot, after, exact }
  | .stopped .. | .fault => none

theorem CheckedNativeOperationInternalReplay.runningEndpoint?_sound
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input)
    (endpoint : CheckedNativeOperationRunningEndpoint replay)
    (checked : replay.runningEndpoint? = some endpoint) :
    replay.result =
      .running endpoint.finalRva endpoint.finalSlot endpoint.after := by
  unfold CheckedNativeOperationInternalReplay.runningEndpoint? at checked
  split at checked <;> try contradiction
  injection checked with endpointExact
  subst endpoint
  assumption

/-- Ordinary native-world counterpart of
`runRelatedSteps_mixedReplay_running`.  Calls, returns, external boundaries,
faults, and blocked transitions are deliberately absent from this theorem and
must be separate replay cutpoints. -/
theorem runRelatedSteps_mixedReplay_running
    (candidate : ExactNativeWorldProgram)
    (instruction : KernelMixedReplayInstruction)
    (tail : List KernelMixedReplayInstruction)
    (undefinedSlot finalSlot : Nat)
    (input after : MachineState) (finalRva : Nat)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld)
    (executed :
      runKernelMixedReplayConcrete candidate.pe candidate.imports undefinedSlot
        input (instruction :: tail) =
          .running finalRva finalSlot after) :
    runRelatedSteps candidate.transitionSystem (instruction :: tail).length
        (.running instruction.rva undefinedSlot input calls eventIndex events
          world) =
      (.running finalRva finalSlot after calls eventIndex events world, []) := by
  induction tail generalizing instruction undefinedSlot input with
  | nil =>
      simp only [runKernelMixedReplayConcrete] at executed
      simp only [List.length_cons, List.length_nil, runRelatedSteps,
        ExactNativeWorldProgram.transitionSystem,
        stepPE32NativeWorldExecution, executed, Option.toList_none,
        List.nil_append]
  | cons next rest induction =>
      cases first :
          stepKernelPE32Instruction candidate.pe candidate.imports
            (.running instruction.rva undefinedSlot input) with
      | running nextRva nextSlot nextState =>
          simp only [runKernelMixedReplayConcrete, first] at executed
          split at executed
          next contiguous =>
            have rvaExact : nextRva = next.rva := beq_iff_eq.mp contiguous
            have tailExecuted :
                runKernelMixedReplayConcrete candidate.pe candidate.imports
                    nextSlot nextState (next :: rest) =
                  .running finalRva finalSlot after :=
              executed
            have tailPath := induction next nextSlot nextState tailExecuted
            subst nextRva
            simp only [List.length_cons, runRelatedSteps,
              ExactNativeWorldProgram.transitionSystem,
              stepPE32NativeWorldExecution, first, Option.toList_none,
              List.nil_append]
            exact tailPath
          next _ => contradiction
      | stopped outcome nextState =>
          simp [runKernelMixedReplayConcrete, first] at executed
      | fault =>
          simp [runKernelMixedReplayConcrete, first] at executed

def CheckedNativeOperationInternalReplay.toPath
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) :
    CheckedNativeOperationPath candidate
      (.running instruction.rva undefinedSlot input calls eventIndex
        events world) := {
  fuel := (instruction :: tail).length
  positive := by simp
}

theorem CheckedNativeOperationInternalReplay.result_exact
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input)
    (endpoint : CheckedNativeOperationRunningEndpoint replay)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) :
    (replay.toPath calls eventIndex events world).result =
      (.running endpoint.finalRva endpoint.finalSlot endpoint.after calls
        eventIndex events world, []) := by
  simpa [CheckedNativeOperationPath.result,
    CheckedNativeOperationInternalReplay.toPath,
    CheckedNativeOperationInternalReplay.result] using
    runRelatedSteps_mixedReplay_running candidate instruction tail undefinedSlot
      endpoint.finalSlot input endpoint.after endpoint.finalRva calls eventIndex
      events world endpoint.exact

/-- Concatenate two exact computed paths.  This is the common composition rule
for prologue/body/epilogue replay and does not re-run either leaf checker. -/
def CheckedNativeOperationPath.trans
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (first : CheckedNativeOperationPath candidate before)
    (second : CheckedNativeOperationPath candidate first.after) :
    CheckedNativeOperationPath candidate before := {
  fuel := first.fuel + second.fuel
  positive := Nat.add_pos_left first.positive second.fuel
}

theorem CheckedNativeOperationPath.trans_result
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (first : CheckedNativeOperationPath candidate before)
    (second : CheckedNativeOperationPath candidate first.after) :
    (first.trans second).result =
      (second.after, first.observations ++ second.observations) := by
  unfold CheckedNativeOperationPath.trans CheckedNativeOperationPath.result
    CheckedNativeOperationPath.after CheckedNativeOperationPath.observations
  change
    runRelatedSteps candidate.transitionSystem (first.fuel + second.fuel)
        before =
      ((runRelatedSteps candidate.transitionSystem second.fuel
          (runRelatedSteps candidate.transitionSystem first.fuel before).1).1,
        (runRelatedSteps candidate.transitionSystem first.fuel before).2 ++
          (runRelatedSteps candidate.transitionSystem second.fuel
            (runRelatedSteps candidate.transitionSystem first.fuel before).1).2)
  rw [runRelatedSteps_add]

theorem CheckedNativeOperationPath.trans_after
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (first : CheckedNativeOperationPath candidate before)
    (second : CheckedNativeOperationPath candidate first.after) :
    (first.trans second).after = second.after := by
  unfold CheckedNativeOperationPath.after CheckedNativeOperationPath.result
  change
    (runRelatedSteps candidate.transitionSystem (first.fuel + second.fuel)
      before).1 =
    (runRelatedSteps candidate.transitionSystem second.fuel first.after).1
  rw [runRelatedSteps_add]
  rfl

theorem CheckedNativeOperationPath.trans_observations
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (first : CheckedNativeOperationPath candidate before)
    (second : CheckedNativeOperationPath candidate first.after) :
    (first.trans second).observations =
      first.observations ++ second.observations := by
  unfold CheckedNativeOperationPath.observations
    CheckedNativeOperationPath.result
  change
    (runRelatedSteps candidate.transitionSystem (first.fuel + second.fuel)
      before).2 =
    (runRelatedSteps candidate.transitionSystem first.fuel before).2 ++
      (runRelatedSteps candidate.transitionSystem second.fuel first.after).2
  rw [runRelatedSteps_add]
  rfl

#print axioms CheckedNativeOperationPath.path
#print axioms CheckedNativeOperationInstructionReplay.facts
#print axioms CheckedNativeOperationRunningInstruction.stepExact
#print axioms CheckedNativeOperationRunningInstruction.worldStepExact
#print axioms CheckedNativeOperationRunningInstruction.path
#print axioms CheckedNativeOperationStoppedInstruction.stepExact
#print axioms CheckedNativeOperationStoppedInstruction.worldStepExact
#print axioms CheckedNativeOperationStoppedInstruction.path
#print axioms CheckedNativeOperationFunctionReplay.entriesExact
#print axioms CheckedNativeOperationFunctionReplay.exactInventory
#print axioms runRelatedSteps_mixedReplay_running
#print axioms
  CheckedNativeOperationInternalReplay.runningEndpoint?_sound
#print axioms CheckedNativeOperationInternalReplay.result_exact
#print axioms CheckedNativeOperationPath.trans_result
#print axioms CheckedNativeOperationPath.trans_after
#print axioms CheckedNativeOperationPath.trans_observations
#print axioms CheckedNativeOperationPath.ofNonempty_after
#print axioms CheckedNativeOperationPath.ofNonempty_observations

end StageA.Relational.InterpreterKernelOperationReplay
