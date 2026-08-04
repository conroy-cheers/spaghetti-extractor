import StageA.RelationalSourceWorld
import StageA.RelationalInterpreterNormalization
import StageA.RelationalInterpreterX87

namespace StageA.Relational.SourceWorld.InterpreterKernel

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterX87

/-!
A world-aware source interpreter kernel.

The kernel below executes `ProgramRecord` semantics.  It does not fetch or
decode instructions from a PE image.  Exact original bytes enter only through
`ExactBinding`, whose ordinary and x87 fields are proof obligations consumed by
the heterogeneous original-to-source proof.

Internal, indirect, and imported calls are cutpoints.  The record prefix is
evaluated up to its sole call action and the resulting call boundary is routed
through `transitionFromWorldOutcome`.  Consequently the existing runtime call
stack, external protocol suspension, callback stack, observations, faults, and
termination rules remain authoritative.
-/

/-- Source-level x87 semantics are explicit.  A source implementation may use
any representation, but acceptance requires `ExactBinding.x87` to prove that
this function agrees with a checked x87 schedule for every input state. -/
structure X87Provider where
  execute : Nat -> MachineState -> Option ScheduleResult

def findX87Witness? {pe : PE32}
    (witnesses : List (ExactInterpreterX87ScheduleWitness pe))
    (sourceRva : Nat) : Option (ExactInterpreterX87ScheduleWitness pe) :=
  witnesses.find? fun witness => witness.schedule.sourceRva == sourceRva

/-- The checked x87 inventory has unique source RVAs, so its executable
provider selects exactly the witness named by any membership proof. -/
theorem findX87Witness?_eq_some_of_member
    {pe : PE32} {witnesses : List (ExactInterpreterX87ScheduleWitness pe)}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    (unique : (witnesses.map (fun item => item.schedule.sourceRva)).Nodup)
    (member : witness ∈ witnesses) :
    findX87Witness? witnesses witness.schedule.sourceRva = some witness := by
  induction witnesses with
  | nil => simp at member
  | cons head tail ih =>
      simp only [List.map_cons, List.nodup_cons] at unique
      rcases unique with ⟨headFresh, tailUnique⟩
      simp only [List.mem_cons] at member
      rcases member with rfl | member
      · simp [findX87Witness?]
      · have sourceNe : head.schedule.sourceRva ≠ witness.schedule.sourceRva := by
          intro sourceExact
          apply headFresh
          rw [sourceExact]
          exact List.mem_map.mpr ⟨witness, member, rfl⟩
        have tailFound := ih tailUnique member
        unfold findX87Witness? at tailFound
        simpa [findX87Witness?, sourceNe] using tailFound

def exactX87Provider {pe : PE32}
    (witnesses : List (ExactInterpreterX87ScheduleWitness pe)) : X87Provider := {
  execute := fun sourceRva state => do
    let witness <- findX87Witness? witnesses sourceRva
    runExactInterpreter pe witness.schedule state
}

theorem exactX87Provider_execute
    {pe : PE32} {witnesses : List (ExactInterpreterX87ScheduleWitness pe)}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    (unique : (witnesses.map (fun item => item.schedule.sourceRva)).Nodup)
    (member : witness ∈ witnesses) (state : MachineState) :
    (exactX87Provider witnesses).execute witness.schedule.sourceRva state =
      runExactInterpreter pe witness.schedule state := by
  simp [exactX87Provider, findX87Witness?_eq_some_of_member unique member]

/-- The semantic source artifact.  `worldProgram` contributes only canonical
code-address resolution and the external protocol.  Its PE region evaluator is
never called by this module. -/
structure Program where
  worldProgram : DecodedWorldProgram
  records : List ProgramRecord
  x87SourceRvas : List Nat
  x87Provider : X87Provider

def recordsAt (records : List ProgramRecord) (sourceRva : Nat) :
    List ProgramRecord :=
  records.filter fun record => record.sourceRva == sourceRva

/-- Exact-one lookup.  Both missing and duplicate records fail closed. -/
def lookupRecord? (records : List ProgramRecord) (sourceRva : Nat) :
    Option ProgramRecord :=
  match recordsAt records sourceRva with
  | [record] => some record
  | _ => none

/-- Exact-one x87 classification.  Duplicate x87 declarations fail closed. -/
def x87Classified (program : Program) (sourceRva : Nat) : Option Bool :=
  match program.x87SourceRvas.filter (· == sourceRva) with
  | [] => some false
  | [_] => some true
  | _ => none

def sourceRvaForTarget? (program : Program) (targetId : Nat) : Option Nat := do
  let target <- program.worldProgram.context.codeMap.get? targetId
  pure target.originalRva

/-- Resolve a source RVA through the canonical, ambiguity-detecting static code
map. -/
def targetIdForRva? (program : Program) (sourceRva : Nat) : Option Nat :=
  program.worldProgram.context.codeMap.resolveRawEip false
    program.worldProgram.context.originalPe.imageBase
    (BitVec.ofNat 32
      (program.worldProgram.context.originalPe.imageBase + sourceRva))

/-- Undefined values come from the semantic source state.  Calls cannot be
executed by this local environment: they are intercepted at their boundary and
delegated to the world protocol. -/
def localEnvironment (state : MachineState) : Interpreter.Environment := {
  undefinedValue := state.undefinedValue
  invokeCall := fun _ input => { status := .unimplemented, state := input }
}

def metadataEnvironment : Interpreter.Environment := {
  undefinedValue := fun _ => 0
  invokeCall := fun _ input => { status := .unimplemented, state := input }
}

structure CallBoundary where
  event : CallEvent
  state : InterpreterMachine
  prefixEvents : List InterpreterEvent

def callActionIndices (transfer : SemanticTransfer) : List Nat :=
  transfer.body.zipIdx.filterMap fun item =>
    match item.1 with
    | .call _ => some item.2
    | _ => none

/-- The initial profile admits one call at the end of a record.  Post-call
projections require a resumable mid-record control state and are rejected until
that state is represented explicitly. -/
def terminalCallIndex? (transfer : SemanticTransfer) : Option Nat := do
  let index <- match callActionIndices transfer with
    | [index] => some index
    | _ => none
  if index + 1 == transfer.body.length then some index else none

def terminalCallOutcomeShapeChecked (transfer : SemanticTransfer)
    (event : CallEvent) : Bool :=
  if event.returnRva = 0 then
    transfer.outcome == .externalJump
  else
    transfer.outcome == .fallthrough event.returnRva

def callBoundary? (transfer : SemanticTransfer) (state : MachineState) :
    Option CallBoundary := do
  if !transfer.checked then none else
  let actionIndex <- terminalCallIndex? transfer
  let action <- transfer.body[actionIndex]?
  let callIndex <- match action with
    | .call callIndex => some callIndex
    | _ => none
  let environment := localEnvironment state
  let prefixResult <- transfer.executeBody environment
    (InterpreterTransfer.initialRuntime (machineFromFormal state))
    (transfer.body.take actionIndex)
  let runtime <- match prefixResult with
    | .inl _ => none
    | .inr runtime => some runtime
  let call <- transfer.calls[callIndex]?
  let (event, boundaryState) <- call.event runtime
  if !terminalCallOutcomeShapeChecked transfer event then none else
  pure { event, state := boundaryState, prefixEvents := runtime.events }

def completionForCall (event : CallEvent) : Completion :=
  if event.returnRva = 0 then .externalJump else .fallthrough event.returnRva

def callBoundaryMacroResult (boundary : CallBoundary) : MacroResult := {
  state := boundary.state
  events := boundary.prefixEvents ++ [.call boundary.event]
  completion := completionForCall boundary.event
}

def callBoundaryOutcome? (program : Program) (boundary : CallBoundary) :
    Option PureOutcome :=
  match boundary.event.kind with
  | .external => do
      let imported <- callEventExternalTarget boundary.event
      if boundary.event.returnRva = 0 then
        pure (.externalJump imported boundary.event.arguments)
      else
        let continuation <- targetIdForRva? program boundary.event.returnRva
        pure (.externalCall imported boundary.event.arguments continuation)
  | .internal => do
      let target <- targetIdForRva? program boundary.event.targetRva.toNat
      if boundary.event.returnRva = 0 then
        pure (.callUnmappedReturn target)
      else
        let continuation <- targetIdForRva? program boundary.event.returnRva
        pure (.call target continuation)
  | .indirect =>
      if boundary.event.returnRva = 0 then
        some (.indirectJump boundary.event.targetRva)
      else do
        let continuation <- targetIdForRva? program boundary.event.returnRva
        pure (.indirectCall boundary.event.targetRva continuation)

def completionOutcome? (program : Program) : Completion -> Option PureOutcome
  | .fallthrough sourceRva | .jump sourceRva | .branch sourceRva => do
      let targetId <- targetIdForRva? program sourceRva
      pure (.jump targetId)
  | .returned target => some (.returned target)
  | .indirectJump target => some (.indirectJump target)
  | .externalJump | .divideError | .memoryFault | .externalFault |
      .unimplemented => none

inductive EvaluatedEffect where
  | outcome (state : MachineState) (outcome : PureOutcome)
  | fault (cause : ModeledFault)

structure EvaluatedStep where
  effect : EvaluatedEffect
  macroResult : Option MacroResult

/-- Canonical local effect of an independently decoded region behavior.  The
world router consumes only this state/outcome-or-fault projection; interpreter
metadata remains available separately in `EvaluatedStep.macroResult`. -/
def evaluatedEffectOfBehavior (input : MachineState)
    (behavior : RelationalBehavior) : EvaluatedEffect :=
  match behavior.x87Fault with
  | some .floatingPoint => .fault .x87FloatingPoint
  | none => .outcome (behavior.nextMachineState input) behavior.outcome

def ordinaryStep? (program : Program) (record : ProgramRecord)
    (state : MachineState) : Option EvaluatedStep := do
  let transfer <- record.decode
  if !transfer.checked then none else
  match callActionIndices transfer with
  | [] => do
      let result <- record.interpret (localEnvironment state) (machineFromFormal state)
      match result.completion with
      | .divideError => pure {
          effect := .fault .checkedContinue
          macroResult := some result
        }
      | .memoryFault | .externalFault | .unimplemented => none
      | completion => do
          let outcome <- completionOutcome? program completion
          pure {
            effect := .outcome
              (InterpreterMachineBridge.formalFromInterpreter state result.state)
              outcome
            macroResult := some result
          }
  | [_] => do
      let boundary <- callBoundary? transfer state
      let outcome <- callBoundaryOutcome? program boundary
      pure {
        effect := .outcome
          (InterpreterMachineBridge.formalFromInterpreter state boundary.state)
          outcome
        macroResult := some (callBoundaryMacroResult boundary)
      }
  | _ => none

/-- Apply the same machine-level import-argument contract used by the exact
decoded evaluator to a source outcome.  The source record remains authoritative
for the imported identity, continuation, and post-prefix machine state; only
the ABI argument projection is normalized from that state. -/
def applyOrdinaryMachineImportContracts?
    (contracts : List MachineImportCallContract) (state : MachineState) :
    PureOutcome -> Option PureOutcome
  | .externalCall imported arguments continuation =>
      match contracts.filter (fun contract => contract.imported == imported) with
      | [] => some (.externalCall imported arguments continuation)
      | [contract] => some (.externalCall imported
          (machineImportArgumentsAtState contract state) continuation)
      | _ => none
  | .externalJump imported arguments =>
      match contracts.filter (fun contract => contract.imported == imported) with
      | [] => some (.externalJump imported arguments)
      | [contract] => do
          let arguments <- machineImportThunkArgumentsAtState? contract state
          pure (.externalJump imported arguments)
      | _ => none
  | outcome => some outcome

/-- Refine only the externally visible ABI arguments of a successful source
step.  Faults and all non-import control outcomes are unchanged. -/
def applyOrdinaryMachineImportContractsToStep?
    (contracts : List MachineImportCallContract) (step : EvaluatedStep) :
    Option EvaluatedStep :=
  match step.effect with
  | .fault _ => some step
  | .outcome state outcome => do
      let outcome <- applyOrdinaryMachineImportContracts? contracts state outcome
      pure { step with effect := .outcome state outcome }

/-- Call-stack-sensitive ordinary evaluation.  Contract selection uses the
same target and active continuation stack as `decodedWorldRegionBehaviorWithCalls`.
The raw `ordinaryStep?` remains available for exact source-record evidence. -/
def ordinaryStepWithCalls? (program : Program) (targetId : Nat)
    (record : ProgramRecord) (state : MachineState) (calls : List Nat) :
    Option EvaluatedStep := do
  let step <- ordinaryStep? program record state
  applyOrdinaryMachineImportContractsToStep?
    (program.worldProgram.machineImportContractsAt targetId calls) step

def mapScheduleOutcome? (program : Program) : PureOutcome -> Option PureOutcome
  | .returned target => some (.returned target)
  | .jump sourceRva => (.jump ·) <$> targetIdForRva? program sourceRva
  | .branch condition taken fallthrough => do
      let taken <- targetIdForRva? program taken
      let fallthrough <- targetIdForRva? program fallthrough
      pure (.branch condition taken fallthrough)
  | .call target continuation => do
      let target <- targetIdForRva? program target
      let continuation <- targetIdForRva? program continuation
      pure (.call target continuation)
  | .callUnmappedReturn target =>
      (.callUnmappedReturn ·) <$> targetIdForRva? program target
  | .externalCall imported arguments continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.externalCall imported arguments continuation)
  | .externalJump imported arguments =>
      some (.externalJump imported arguments)
  | .bulkCopy destination source count direction continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.bulkCopy destination source count direction continuation)
  | .bulkFill destination value count direction continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.bulkFill destination value count direction continuation)
  | .bulkScan accumulator destination count direction continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.bulkScan accumulator destination count direction continuation)
  | .indirectCall target continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.indirectCall target continuation)
  | .indirectJump target => some (.indirectJump target)
  | .checkedContinue valid continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.checkedContinue valid continuation)
  | .atomicCompareExchange address expected replacement continuation => do
      let continuation <- targetIdForRva? program continuation
      pure (.atomicCompareExchange address expected replacement continuation)

def lastControl? (result : ScheduleResult) : Option StepControl :=
  result.trace.controls.reverse.head?

def scheduleMacroResult? (result : ScheduleResult) : Option MacroResult := do
  let control <- lastControl? result
  let completion <- match control with
    | .fallthrough sourceRva => some (.fallthrough sourceRva)
    | .stop (.returned target) => some (.returned target)
    | .stop (.jump sourceRva) => some (.jump sourceRva)
    | .stop (.branch condition taken fallthrough) =>
        some (.branch (if condition then taken else fallthrough))
    | .stop (.indirectJump target) => some (.indirectJump target)
    | .stop (.externalJump _ _) => some .externalJump
    | .stop (.call _ continuation) |
        .stop (.externalCall _ _ continuation) |
        .stop (.bulkCopy _ _ _ _ continuation) |
        .stop (.bulkFill _ _ _ _ continuation) |
        .stop (.bulkScan _ _ _ _ continuation) |
        .stop (.indirectCall _ continuation) |
        .stop (.checkedContinue _ continuation) |
        .stop (.atomicCompareExchange _ _ _ continuation) =>
          some (.fallthrough continuation)
    | .stop (.callUnmappedReturn _) => some .externalJump
  pure {
    state := machineFromFormal result.state
    events := result.trace.calls.map (.call ·)
    completion
  }

def x87Step? (program : Program) (sourceRva : Nat) (state : MachineState) :
    Option EvaluatedStep := do
  let result <- program.x87Provider.execute sourceRva state
  let macroResult <- scheduleMacroResult? result
  if !result.trace.calls.isEmpty then none else
  match result.trace.faults with
  | [] => do
      let control <- lastControl? result
      let rawOutcome <- match control with
        | .fallthrough target => some (.jump target)
        | .stop outcome => some outcome
      let outcome <- mapScheduleOutcome? program rawOutcome
      pure {
        effect := .outcome result.state outcome
        macroResult := some macroResult
      }
  | [.x87 .floatingPoint] =>
      pure {
        effect := .fault .x87FloatingPoint
        macroResult := some macroResult
      }
  | _ => none

def withoutMacro (transition : RelatedTransition WorldExecution
    WorldRelationalObservable) : KernelTransition := {
  next := Execution.ofWorldExecution transition.next
  observation := transition.observation
  macroResult := none
  interpreterEvents := []
  completion := none
  metadataExact := by simp
}

def withMacro (transition : RelatedTransition WorldExecution
    WorldRelationalObservable) (result : MacroResult) : KernelTransition := {
  next := Execution.ofWorldExecution transition.next
  observation := transition.observation
  macroResult := some result
  interpreterEvents := result.events
  completion := some result.completion
  metadataExact := by simp
}

def blocked (targetId : Nat) : KernelTransition :=
  withoutMacro (blockedWorldTransition (.missingRegionBehavior targetId))

/-- Route a canonical local effect through the authoritative decoded-world
transition function.  Source and decoded execution share this function. -/
def transitionFromEvaluatedEffect (program : Program) (sourceTargetId : Nat)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) : EvaluatedEffect ->
    RelatedTransition WorldExecution WorldRelationalObservable
  | .outcome state outcome =>
      transitionFromWorldOutcome program.worldProgram sourceTargetId state calls
        eventIndex world callbacks outcome
  | .fault cause =>
      { next := .fault cause, observation := some (.fault cause) }

/-- Decoded behavior and its canonical effect invoke exactly the same world
router. -/
theorem transitionFromEvaluatedEffect_of_behavior
    (program : Program) (sourceTargetId : Nat) (input : MachineState)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (behavior : RelationalBehavior) :
    transitionFromEvaluatedEffect program sourceTargetId calls eventIndex world
        callbacks (evaluatedEffectOfBehavior input behavior) =
      transitionFromWorldBehavior program.worldProgram sourceTargetId input calls
        eventIndex world callbacks behavior := by
  cases fault : behavior.x87Fault with
  | none =>
      simp [evaluatedEffectOfBehavior, transitionFromEvaluatedEffect,
        transitionFromWorldBehavior, fault]
  | some faultValue =>
      cases faultValue
      simp [evaluatedEffectOfBehavior, transitionFromEvaluatedEffect,
        transitionFromWorldBehavior, fault]

def applyEvaluated (program : Program) (sourceTargetId : Nat)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime) (step : EvaluatedStep) :
    KernelTransition :=
  let transition := transitionFromEvaluatedEffect program sourceTargetId calls
    eventIndex world callbacks step.effect
  match step.macroResult with
  | none => withoutMacro transition
  | some result => withMacro transition result

/-- Target-local execution before world routing.  Extracting this function
keeps target lookup, ordinary/x87 selection, and local semantic replay separate
from call stacks, external worlds, and callback frames. -/
def targetStepWithCalls? (program : Program) (sourceTargetId : Nat)
    (state : MachineState) (calls : List Nat) : Option EvaluatedStep :=
  match sourceRvaForTarget? program sourceTargetId with
  | none => none
  | some sourceRva =>
      match x87Classified program sourceRva with
      | some true => x87Step? program sourceRva state
      | some false => do
          let record <- lookupRecord? program.records sourceRva
          ordinaryStepWithCalls? program sourceTargetId record state calls
      | none => none

/-- Compatibility projection for callers that do not carry a return stack.
Whole-program execution and acceptance use `targetStepWithCalls?` directly. -/
def targetStep? (program : Program) (sourceTargetId : Nat)
    (state : MachineState) : Option EvaluatedStep :=
  targetStepWithCalls? program sourceTargetId state []

def stepRunning (program : Program) (sourceTargetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime) :
    KernelTransition :=
  match targetStepWithCalls? program sourceTargetId state calls with
  | some evaluated => applyEvaluated program sourceTargetId calls eventIndex
      world callbacks evaluated
  | none => blocked sourceTargetId

def step (program : Program) : Execution -> KernelTransition
  | .running targetId state calls eventIndex world =>
      stepRunning program targetId state calls eventIndex world []
  | .callbackRunning targetId state calls eventIndex world callbacks =>
      stepRunning program targetId state calls eventIndex world callbacks
  | .awaitingExternal suspension callbacks =>
      withoutMacro
        (stepWorldExternalSuspension program.worldProgram suspension callbacks)
  | .returned state world =>
      withoutMacro { next := .returned state world, observation := none }
  | .terminated world =>
      withoutMacro { next := .terminated world, observation := none }
  | .fault cause =>
      withoutMacro { next := .fault cause, observation := none }
  | .blocked reason =>
      withoutMacro { next := .blocked reason, observation := none }

def Program.kernel (program : Program) : SourceWorld.Kernel := {
  records := program.records
  environment := metadataEnvironment
  step := step program
}

/-! ## Exact PE to decoded semantic bridge

This bridge is deliberately independent of `Program` and `ExactBinding`.  It
connects exact PE execution to the repository's already checked, non-PE
`DecodedWorldProgram` transition system.  It is not evidence that generated C,
or even a `ProgramRecord` inventory, implements that transition system.

`InstructionSemanticsAdequate` alone is not enough: it permits both evaluators
to fail at the same location, while `proofBlocked` is intentionally unrelated
to itself.  `DecodedSemanticStepsAdmissible` is the separate closure premise
that rules out that false acceptance path and discharges any self-related
external-argument requirements.
-/

def decodedSemanticKernel (program : DecodedWorldProgram) : SourceWorld.Kernel := {
  records := []
  environment := metadataEnvironment
  step := fun execution =>
    withoutMacro (stepWorldExecution program execution.toWorldExecution)
}

def DecodedSemanticStepsAdmissible {root : WorldExecution}
    (program : DecodedWorldProgram)
    (domain : CheckedExecutionDomain program root) : Prop :=
  forall execution, domain.holds execution ->
    let observation := (stepWorldExecution program execution).observation
    RelatedObservationLists
      sourceObservationsRelated
      observation.toList observation.toList

def decodedSemanticChunkComposition
    (program : DecodedWorldProgram)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program root)
    (adequate : program.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program domain) :
    ChunkComposition program (decodedSemanticKernel program) root domain := {
  chunk := by
    intro originalBefore sourceBefore beforeMatches
    have sourceExact : sourceBefore = Execution.ofWorldExecution originalBefore := by
      calc
        sourceBefore = Execution.ofWorldExecution sourceBefore.toWorldExecution := by
          symm
          exact Execution.ofWorldExecution_toWorldExecution sourceBefore
        _ = Execution.ofWorldExecution originalBefore := by
          rw [beforeMatches.1]
    subst sourceBefore
    let transition := stepWorldExecution program originalBefore
    refine {
      originalObservations := transition.observation.toList
      sourceObservations := transition.observation.toList
      sourceInterpreterEvents := []
      sourceCompletions := []
      originalAfter := transition.next
      sourceAfter := Execution.ofWorldExecution transition.next
      originalPath := ?_
      sourcePath := ?_
      observationsRelated := admissible originalBefore beforeMatches.2
      afterProjection := by simp
    }
    · refine ⟨1, by omega, ?_⟩
      rw [program.pe32TransitionSystem_eq_transitionSystem adequate]
      simp [runRelatedSteps, DecodedWorldProgram.transitionSystem, transition]
    · refine ⟨1, by omega, ?_⟩
      simp [runKernelSteps, decodedSemanticKernel, withoutMacro, transition]
}

theorem decodedSemanticKernelObservationallyEquivalent
    (program : DecodedWorldProgram)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program root)
    (adequate : program.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent program
      (decodedSemanticKernel program) root domain :=
  (decodedSemanticChunkComposition program root domain adequate
    admissible).chunksRefine

/-- Fixed semantic equality required between the ProgramRecord-driven kernel
and the repository's decoded source semantics.  It compares the complete next
execution state and observation; therefore call stacks, callback frames,
external suspensions, worlds, faults, and termination cannot be projected away.
Interpreter-only metadata is intentionally outside whole-program observation. -/
def ProgramRecordKernelMatchesDecodedSemantics {root : WorldExecution}
    (program : Program)
    (domain : CheckedExecutionDomain program.worldProgram root) : Prop :=
  forall execution, domain.holds execution.toWorldExecution ->
    let recordTransition := program.kernel.step execution
    let decodedTransition := (decodedSemanticKernel program.worldProgram).step execution
    recordTransition.next = decodedTransition.next ∧
      recordTransition.observation = decodedTransition.observation

/-- Exact-PE-to-ProgramRecord composition once concrete step equality has been
proved.  `ExactBinding` below supplies the per-record proof ingredients, but it
does not assert this whole-inventory equality by itself. -/
def programRecordKernelChunkComposition
    (program : Program)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program.worldProgram domain)
    (stepMatches : ProgramRecordKernelMatchesDecodedSemantics program domain) :
    ChunkComposition program.worldProgram program.kernel root domain := {
  chunk := by
    intro originalBefore sourceBefore beforeMatches
    have sourceExact : sourceBefore = Execution.ofWorldExecution originalBefore := by
      calc
        sourceBefore = Execution.ofWorldExecution sourceBefore.toWorldExecution := by
          symm
          exact Execution.ofWorldExecution_toWorldExecution sourceBefore
        _ = Execution.ofWorldExecution originalBefore := by
          rw [beforeMatches.1]
    subst sourceBefore
    let originalTransition := stepWorldExecution program.worldProgram originalBefore
    let sourceTransition := program.kernel.step
      (Execution.ofWorldExecution originalBefore)
    have transitionMatches := stepMatches
      (Execution.ofWorldExecution originalBefore) (by simpa using beforeMatches.2)
    have nextMatches :
        sourceTransition.next = Execution.ofWorldExecution originalTransition.next := by
      simpa [sourceTransition, originalTransition, decodedSemanticKernel,
        withoutMacro] using transitionMatches.1
    have observationMatches :
        sourceTransition.observation = originalTransition.observation := by
      simpa [sourceTransition, originalTransition, decodedSemanticKernel,
        withoutMacro] using transitionMatches.2
    refine {
      originalObservations := originalTransition.observation.toList
      sourceObservations := sourceTransition.observation.toList
      sourceInterpreterEvents := sourceTransition.interpreterEvents
      sourceCompletions := sourceTransition.completion.toList
      originalAfter := originalTransition.next
      sourceAfter := sourceTransition.next
      originalPath := ?_
      sourcePath := ?_
      observationsRelated := ?_
      afterProjection := ?_
    }
    · refine ⟨1, by omega, ?_⟩
      rw [program.worldProgram.pe32TransitionSystem_eq_transitionSystem adequate]
      simp [runRelatedSteps, DecodedWorldProgram.transitionSystem,
        originalTransition]
    · refine ⟨1, by omega, ?_⟩
      simp [runKernelSteps, sourceTransition]
    · rw [observationMatches]
      exact admissible originalBefore beforeMatches.2
    · simpa [nextMatches]
}

theorem programRecordKernelObservationallyEquivalentFromStepEquality
    (program : Program)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program.worldProgram domain)
    (stepMatches : ProgramRecordKernelMatchesDecodedSemantics program domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent program.worldProgram
      program.kernel root domain :=
  (programRecordKernelChunkComposition program root domain adequate admissible
    stepMatches).chunksRefine

/-- Complete proof boundary between an exact original PE and one semantic source
program.  Ordinary records are bound through exact normalized paths.  x87 is
bound separately and universally; a provider result cannot be accepted merely
because an RVA was labelled x87. -/
structure ExactOrdinaryRecordBinding (pe : PE32) where
  path : ExactNormalizedTransferPath
  transfer : SemanticTransfer
  sourceExact : path.sourceRva = path.record.sourceRva
  certificate : ExactProgramRecordNormalizationCertificate pe path transfer

structure ExactBinding (pe : PE32) (program : Program) where
  originalSide : program.worldProgram.candidate = false
  originalPeExact : program.worldProgram.context.originalPe = pe
  recordsUnique : (program.records.map (·.sourceRva)).Nodup
  x87SourcesUnique : program.x87SourceRvas.Nodup
  witnesses : List (ExactInterpreterX87ScheduleWitness pe)
  ordinary : forall record,
    record ∈ program.records -> record.sourceRva ∉ program.x87SourceRvas ->
      exists path transfer,
        path.record = record ∧ path.sourceRva = record.sourceRva ∧
          ExactProgramRecordNormalizationCertificate pe path transfer
  x87 : forall sourceRva,
    sourceRva ∈ program.x87SourceRvas ->
      exists witness,
        witness ∈ witnesses ∧ witness.schedule.sourceRva = sourceRva ∧
          (forall state,
          program.x87Provider.execute sourceRva state =
            runExactInterpreter pe witness.schedule state)

/-- Compact finite partition consumed by generated whole-program source
certificates.  It keeps list traversal and record selection out of every local
proof while retaining universal ordinary and x87 semantic obligations. -/
structure ExactBindingPartition (pe : PE32) (program : Program) where
  ordinaryBindings : List (ExactOrdinaryRecordBinding pe)
  ordinaryRecordsExact :
    ordinaryBindings.map (fun binding => binding.path.record) =
      program.records
  recordsUnique : (program.records.map (·.sourceRva)).Nodup
  x87SourcesUnique : program.x87SourceRvas.Nodup
  x87Witnesses : List (ExactInterpreterX87ScheduleWitness pe)
  x87WitnessesCovered : forall sourceRva,
    sourceRva ∈ program.x87SourceRvas ->
      exists witness, witness ∈ x87Witnesses /\
        witness.schedule.sourceRva = sourceRva
  x87ProviderExact : forall sourceRva,
    sourceRva ∈ program.x87SourceRvas ->
      forall witness, witness ∈ x87Witnesses ->
        witness.schedule.sourceRva = sourceRva ->
          forall state,
            program.x87Provider.execute sourceRva state =
              runExactInterpreter pe witness.schedule state

def ExactBindingPartition.toExactBinding
    (partition : ExactBindingPartition pe program)
    (originalSide : program.worldProgram.candidate = false)
    (originalPeExact : program.worldProgram.context.originalPe = pe) :
    ExactBinding pe program where
  originalSide
  originalPeExact
  recordsUnique := partition.recordsUnique
  x87SourcesUnique := partition.x87SourcesUnique
  witnesses := partition.x87Witnesses
  ordinary := by
    intro record member notX87
    rw [← partition.ordinaryRecordsExact] at member
    rcases List.mem_map.mp member with ⟨binding, _bindingMember, recordExact⟩
    subst record
    exact ⟨binding.path, binding.transfer, rfl, binding.sourceExact,
      binding.certificate⟩
  x87 := by
    intro sourceRva classified
    rcases partition.x87WitnessesCovered sourceRva classified with
      ⟨witness, witnessMember, witnessSource⟩
    exact ⟨witness, witnessMember, witnessSource,
      partition.x87ProviderExact sourceRva classified witness witnessMember
        witnessSource⟩

theorem ExactBinding.ordinaryMacroStepExact
    {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    {record : ProgramRecord} (member : record ∈ program.records)
    (notX87 : record.sourceRva ∉ program.x87SourceRvas)
    (state : MachineState) :
    exists path transfer,
      path.record = record ∧ path.sourceRva = record.sourceRva ∧
        ExactProgramRecordNormalizationCertificate pe path transfer ∧
        record.interpret (localEnvironment state) (machineFromFormal state) =
          runExactNormalizedPath pe path (localEnvironment state) state := by
  rcases binding.ordinary record member notX87 with
    ⟨path, transfer, recordExact, sourceExact, certificate⟩
  refine ⟨path, transfer, recordExact, sourceExact, certificate, ?_⟩
  rw [← recordExact]
  exact certificate.rawMacroStep (localEnvironment state) state

theorem ExactBinding.x87ProviderExact
    {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    {sourceRva : Nat} (classified : sourceRva ∈ program.x87SourceRvas)
    (state : MachineState) :
    exists witness,
      witness ∈ binding.witnesses ∧ witness.schedule.sourceRva = sourceRva ∧
      program.x87Provider.execute sourceRva state =
        runExactInterpreter pe witness.schedule state := by
  rcases binding.x87 sourceRva classified with
    ⟨witness, member, sourceExact, providerExact⟩
  exact ⟨witness, member, sourceExact, providerExact state⟩

/-! ## Exact-bound target step aggregation

`ExactBinding` establishes that every selected ordinary record and x87 provider
is semantically tied to the exact PE.  It cannot by itself prove that the
`ProgramRecord` kernel and `DecodedWorldProgram` select and lift the same local
transition at a reachable target: that additionally depends on region lookup,
call-contract selection, target normalization, and world-transition routing.

The interface below isolates precisely that missing fact.  A target certificate
must first show which exact-bound ordinary record or x87 source the executable
kernel selects.  It must then prove complete next-state and observation
equality for that target, universally over machine state, call stack, external
event position, relational world, and nested callback frames.  The final
aggregation theorem is structural and consumes no generated status field.
-/

/-- Operational selection of one source target from the inventory governed by
`ExactBinding`.  The equalities name the actual branches taken by
`stepRunning`; list membership supplies the corresponding exact semantic proof
from the binding. -/
inductive BoundTargetSelection (program : Program) (targetId : Nat) : Prop where
  | ordinary (sourceRva : Nat) (record : ProgramRecord)
      (sourceExact : sourceRvaForTarget? program targetId = some sourceRva)
      (classificationExact : x87Classified program sourceRva = some false)
      (lookupExact : lookupRecord? program.records sourceRva = some record)
      (recordMember : record ∈ program.records)
      (notX87 : sourceRva ∉ program.x87SourceRvas) :
      BoundTargetSelection program targetId
  | x87 (sourceRva : Nat)
      (sourceExact : sourceRvaForTarget? program targetId = some sourceRva)
      (classificationExact : x87Classified program sourceRva = some true)
      (classified : sourceRva ∈ program.x87SourceRvas) :
      BoundTargetSelection program targetId

/-- Full world-routing agreement at one target.  Exact local instruction
semantics do not imply this property on their own: target lookup, import-call
contract selection, continuations, callback frames, external worlds, faults,
and observations are all part of the two equalities below.

Keeping this as one target-independent interface lets generated artifacts
reuse checked routing theorems without emitting a bespoke proof script for
every active target. -/
structure TargetWorldRoutingExact (program : Program) (targetId : Nat) : Prop where
  running : forall state calls eventIndex world,
    let sourceTransition := program.kernel.step
      (.running targetId state calls eventIndex world)
    let decodedTransition :=
      (decodedSemanticKernel program.worldProgram).step
        (.running targetId state calls eventIndex world)
    sourceTransition.next = decodedTransition.next ∧
      sourceTransition.observation = decodedTransition.observation
  callbackRunning : forall state calls eventIndex world callbacks,
    let sourceTransition := program.kernel.step
      (.callbackRunning targetId state calls eventIndex world callbacks)
    let decodedTransition :=
      (decodedSemanticKernel program.worldProgram).step
        (.callbackRunning targetId state calls eventIndex world callbacks)
    sourceTransition.next = decodedTransition.next ∧
      sourceTransition.observation = decodedTransition.observation

/-- Compact target-local routing certificate.  It compares only independently
computed local effects.  Lookup failure must agree on both sides; successful
execution must agree on the exact machine state, `PureOutcome`, or modeled
fault before any world transition is applied. -/
structure TargetLocalEffectExact (program : Program) (targetId : Nat) : Prop where
  effect : forall state calls,
    match targetStepWithCalls? program targetId state calls,
        decodedWorldRegionBehaviorWithCalls program.worldProgram targetId state
          calls with
    | none, none => True
    | some sourceStep, some decodedBehavior =>
        sourceStep.effect = evaluatedEffectOfBehavior state decodedBehavior
    | _, _ => False

/-- Checked successful-evaluation components for one active target.  The two
function fields are data only; the exactness fields bind them to the actual
source and independently decoded evaluators, while `effectsExact` is the
remaining local semantic equality. -/
structure SuccessfulTargetEffectComponents
    (program : Program) (targetId : Nat) where
  sourceStep : MachineState -> List Nat -> EvaluatedStep
  decodedBehavior : MachineState -> List Nat -> RelationalBehavior
  sourceStepExact : forall state calls,
    targetStepWithCalls? program targetId state calls =
      some (sourceStep state calls)
  decodedBehaviorExact : forall state calls,
    decodedWorldRegionBehaviorWithCalls program.worldProgram targetId state calls =
      some (decodedBehavior state calls)
  effectsExact : forall state calls,
    (sourceStep state calls).effect =
      evaluatedEffectOfBehavior state (decodedBehavior state calls)

/-- Successful checked evaluator components close the compact local routing
certificate by structural rewriting only. -/
def SuccessfulTargetEffectComponents.toLocalEffectExact
    {program : Program} {targetId : Nat}
    (components : SuccessfulTargetEffectComponents program targetId) :
    TargetLocalEffectExact program targetId where
  effect := by
    intro state calls
    rw [components.sourceStepExact state calls,
      components.decodedBehaviorExact state calls]
    exact components.effectsExact state calls

/-- Interpreter metadata cannot alter the successor or observation produced by
the shared world router. -/
theorem applyEvaluated_next_observation_of_effect
    (program : Program) (targetId : Nat) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (sourceStep : EvaluatedStep) (decodedBehavior : RelationalBehavior)
    (effectExact :
      sourceStep.effect = evaluatedEffectOfBehavior state decodedBehavior) :
    let sourceTransition := applyEvaluated program targetId calls eventIndex
      world callbacks sourceStep
    let decodedTransition := withoutMacro
      (transitionFromWorldBehavior program.worldProgram targetId state calls
        eventIndex world callbacks decodedBehavior)
    sourceTransition.next = decodedTransition.next ∧
      sourceTransition.observation = decodedTransition.observation := by
  have routedExact := transitionFromEvaluatedEffect_of_behavior program targetId
    state calls eventIndex world callbacks decodedBehavior
  cases sourceStep with
  | mk effect macroResult =>
      simp only at effectExact
      subst effect
      cases macroResult <;>
        simp [applyEvaluated, withMacro, withoutMacro, routedExact]

/-- Structural composition theorem from target-local effect equality to full
world routing.  The proof is universal over external environments, call
stacks, event indices, worlds, and nested callback frames because both sides
invoke the same decoded-world router after local effect equality is known. -/
def TargetLocalEffectExact.toWorldRoutingExact
    {program : Program} {targetId : Nat}
    (certificate : TargetLocalEffectExact program targetId) :
    TargetWorldRoutingExact program targetId where
  running := by
    intro state calls eventIndex world
    have effectExact := certificate.effect state calls
    cases sourceExact : targetStepWithCalls? program targetId state calls with
    | none =>
        cases decodedExact : decodedWorldRegionBehaviorWithCalls
            program.worldProgram targetId state calls with
        | none =>
            simp [Program.kernel, step, stepRunning, sourceExact,
              decodedSemanticKernel, stepWorldExecution, decodedExact, blocked,
              withoutMacro, Execution.toWorldExecution,
              Execution.ofWorldExecution]
        | some decodedBehavior =>
            simp [sourceExact, decodedExact] at effectExact
    | some sourceStep =>
        cases decodedExact : decodedWorldRegionBehaviorWithCalls
            program.worldProgram targetId state calls with
        | none =>
            simp [sourceExact, decodedExact] at effectExact
        | some decodedBehavior =>
            have routed := applyEvaluated_next_observation_of_effect program
              targetId state calls eventIndex world [] sourceStep decodedBehavior
              (by simpa [sourceExact, decodedExact] using effectExact)
            simpa [Program.kernel, step, stepRunning, sourceExact,
              decodedSemanticKernel, stepWorldExecution, decodedExact,
              Execution.toWorldExecution,
              Execution.ofWorldExecution] using routed
  callbackRunning := by
    intro state calls eventIndex world callbacks
    have effectExact := certificate.effect state calls
    cases sourceExact : targetStepWithCalls? program targetId state calls with
    | none =>
        cases decodedExact : decodedWorldRegionBehaviorWithCalls
            program.worldProgram targetId state calls with
        | none =>
            simp [Program.kernel, step, stepRunning, sourceExact,
              decodedSemanticKernel, stepWorldExecution, decodedExact, blocked,
              withoutMacro, Execution.toWorldExecution,
              Execution.ofWorldExecution]
        | some decodedBehavior =>
            simp [sourceExact, decodedExact] at effectExact
    | some sourceStep =>
        cases decodedExact : decodedWorldRegionBehaviorWithCalls
            program.worldProgram targetId state calls with
        | none =>
            simp [sourceExact, decodedExact] at effectExact
        | some decodedBehavior =>
            have routed := applyEvaluated_next_observation_of_effect program
              targetId state calls eventIndex world callbacks sourceStep
              decodedBehavior
              (by simpa [sourceExact, decodedExact] using effectExact)
            simpa [Program.kernel, step, stepRunning, sourceExact,
              decodedSemanticKernel, stepWorldExecution, decodedExact,
              Execution.toWorldExecution,
              Execution.ofWorldExecution] using routed
/-- The exact-bound local-to-world equality for one target.  Selection ties
the operational branch to the exact PE binding; routing ties the resulting
world transition to independently decoded PE behavior. -/
structure ExactBoundTargetStepEquality
    {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    (targetId : Nat) : Prop where
  selection : BoundTargetSelection program targetId
  running : forall state calls eventIndex world,
    let sourceTransition := program.kernel.step
      (.running targetId state calls eventIndex world)
    let decodedTransition :=
      (decodedSemanticKernel program.worldProgram).step
        (.running targetId state calls eventIndex world)
    sourceTransition.next = decodedTransition.next ∧
      sourceTransition.observation = decodedTransition.observation
  callbackRunning : forall state calls eventIndex world callbacks,
    let sourceTransition := program.kernel.step
      (.callbackRunning targetId state calls eventIndex world callbacks)
    let decodedTransition :=
      (decodedSemanticKernel program.worldProgram).step
        (.callbackRunning targetId state calls eventIndex world callbacks)
    sourceTransition.next = decodedTransition.next ∧
      sourceTransition.observation = decodedTransition.observation

/-- Assemble an exact-bound target equality from the two independent checked
ingredients.  This theorem is intentionally generic: generated modules only
name selection and routing facts, and perform no per-target symbolic replay. -/
def ExactBoundTargetStepEquality.ofSelectionAndRouting
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    {targetId : Nat}
    (selection : BoundTargetSelection program targetId)
    (routing : TargetWorldRoutingExact program targetId) :
    ExactBoundTargetStepEquality binding targetId where
  selection := selection
  running := routing.running
  callbackRunning := routing.callbackRunning

/-- A target is active when the checked domain admits either ordinary or
callback-mode execution at it. -/
def TargetActiveInDomain {program : Program} {root : WorldExecution}
    (domain : CheckedExecutionDomain program.worldProgram root)
    (targetId : Nat) : Prop :=
  (∃ state calls eventIndex world,
    domain.holds (.running targetId state calls eventIndex world)) ∨
  (∃ state calls eventIndex world callbacks,
    domain.holds
      (.callbackRunning targetId state calls eventIndex world callbacks))

/-- Coverage is intentionally stated once per active target, independently of
the particular state that demonstrated reachability.  Generated finite indexes
may implement this interface, but cannot replace its proof obligations. -/
structure ExactBindingDomainTargetStepCoverage
    {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    {root : WorldExecution}
    (domain : CheckedExecutionDomain program.worldProgram root) : Prop where
  target : forall targetId,
    TargetActiveInDomain domain targetId ->
      ExactBoundTargetStepEquality binding targetId

/-- Aggregate exact-bound per-target equalities into the fixed whole-domain
kernel equality.  Non-running constructors are definitionally shared by the
two kernels; running constructors are authorized only by a target certificate
whose selection is tied to `binding`. -/
theorem ExactBinding.programRecordKernelMatchesDecodedSemantics
    {pe : PE32} {program : Program} (binding : ExactBinding pe program)
    {root : WorldExecution}
    (domain : CheckedExecutionDomain program.worldProgram root)
    (coverage : ExactBindingDomainTargetStepCoverage binding domain) :
    ProgramRecordKernelMatchesDecodedSemantics program domain := by
  intro execution executionInDomain
  cases execution with
  | running targetId state calls eventIndex world =>
      have active : TargetActiveInDomain domain targetId :=
        Or.inl ⟨state, calls, eventIndex, world, executionInDomain⟩
      exact (coverage.target targetId active).running state calls eventIndex world
  | callbackRunning targetId state calls eventIndex world callbacks =>
      have active : TargetActiveInDomain domain targetId :=
        Or.inr ⟨state, calls, eventIndex, world, callbacks, executionInDomain⟩
      exact (coverage.target targetId active).callbackRunning state calls
        eventIndex world callbacks
  | awaitingExternal suspension callbacks => exact ⟨rfl, rfl⟩
  | returned state world => exact ⟨rfl, rfl⟩
  | terminated world => exact ⟨rfl, rfl⟩
  | fault cause => exact ⟨rfl, rfl⟩
  | blocked reason => exact ⟨rfl, rfl⟩

/-- Acceptance-facing kernel theorem.  The fixed step equality proves semantic
agreement, while `binding` separately prevents a caller from replacing the
ProgramRecord inventory or x87 provider with an unbound source artifact. -/
theorem ExactBinding.kernelObservationallyEquivalent
    {program : Program}
    (binding : ExactBinding program.worldProgram.context.originalPe program)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (admissible : DecodedSemanticStepsAdmissible program.worldProgram domain)
    (stepMatches : ProgramRecordKernelMatchesDecodedSemantics program domain) :
    ExactOriginalPESourceKernelObservationallyEquivalent program.worldProgram
      program.kernel root domain := by
  have _originalSide := binding.originalSide
  exact programRecordKernelObservationallyEquivalentFromStepEquality program
    root domain adequate admissible stepMatches

end StageA.Relational.SourceWorld.InterpreterKernel
