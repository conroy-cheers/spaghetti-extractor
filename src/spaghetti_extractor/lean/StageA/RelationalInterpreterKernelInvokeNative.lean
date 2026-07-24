import StageA.RelationalInterpreterKernelInvoke
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelInvokeNative

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelInvoke
open StageA.Relational.InterpreterNativeWorld

/-!
Native-world execution bridge for the reflected `invokeCall` wrapper.

Wrapper prefixes and epilogues are represented by a fuel count only.  Their
endpoint and observation list are computed by the exact candidate transition
system, and `ExactComputedNativeWorldSegment.path` derives the path theorem.
No generated or caller-provided path can replace that computation.

Calls are interpreted with a continuation-aware dispatch.  This permits the
already-proved `runFunction` operation to execute beneath the wrapper's real
native call frame.  Resolver callbacks and the external helper use the same
interface once their exact callback/environment semantics are available.
-/

/-- Projection used by the whole-program dispatch family. -/
def NativeWorldKernelDispatches (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) : KernelDispatchRelation :=
  fun entryRva before after events =>
    exists afterWorld observations,
      NativeWorldDispatches candidate entryRva before world after events
        afterWorld observations

/-- Detailed nested result hidden by `KernelDispatchRelation`.  Retaining the
successor world here lets an enclosing exact path resume without equating
unrelated worlds or trusting a generated world assertion. -/
structure NativeWorldSubroutineResult (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) (continuationRva : Nat)
    (returnAddress : Word) (entryRva : Nat) (before after : MachineState)
    (events : List NativeExternalEvent) where
  afterWorld : RelationalWorld
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem
    (.running entryRva 0 before
      [{ continuationRva, returnAddress }] 0 [] world)
    observations
    (.running continuationRva 0 after [] events.length events afterWorld)

/-- Exact nested-call dispatch.  The callee starts with the hardware return
word already pushed in `before` and one logical native call frame installed.
The returned state is observed at the caller continuation, before the wrapper
epilogue executes. -/
def NativeWorldSubroutineDispatches (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) (continuationRva : Nat)
    (returnAddress : Word) : KernelDispatchRelation :=
  fun entryRva before after events =>
    Nonempty (NativeWorldSubroutineResult candidate world continuationRva
      returnAddress entryRva before after events)

/-- A finite exact segment contains no submitted endpoint, observation list, or
path.  All three are projections of `runRelatedSteps`. -/
structure ExactComputedNativeWorldSegment
    (candidate : ExactNativeWorldProgram) (before : NativeWorldExecution) where
  fuel : Nat
  positive : 0 < fuel

def ExactComputedNativeWorldSegment.result
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (segment : ExactComputedNativeWorldSegment candidate before) :
    NativeWorldExecution × List WorldRelationalObservable :=
  runRelatedSteps candidate.transitionSystem segment.fuel before

def ExactComputedNativeWorldSegment.after
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (segment : ExactComputedNativeWorldSegment candidate before) :
    NativeWorldExecution := segment.result.1

def ExactComputedNativeWorldSegment.observations
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (segment : ExactComputedNativeWorldSegment candidate before) :
    List WorldRelationalObservable := segment.result.2

theorem ExactComputedNativeWorldSegment.path
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (segment : ExactComputedNativeWorldSegment candidate before) :
    NonemptyRelatedPath candidate.transitionSystem before segment.observations
      segment.after := by
  exact ⟨segment.fuel, segment.positive, rfl⟩

/-- One complete invoke arm consists of an exact computed wrapper prefix, one
semantically justified subroutine dispatch, and an exact computed epilogue.
Only endpoint-shape equalities connect the pieces.  There is no whole-arm path,
response relation, or memory-frame member. -/
structure InvokeCallNativeArmExecution
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (invokeEntryRva subroutineEntryRva continuationRva : Nat)
    (returnAddress : Word) (before subroutineBefore subroutineAfter after : MachineState)
    (events : List NativeExternalEvent) where
  prelude : ExactComputedNativeWorldSegment candidate
    (.running invokeEntryRva 0 before [] 0 [] world)
  preludeAtSubroutine : prelude.after =
    .running subroutineEntryRva 0 subroutineBefore
      [{ continuationRva, returnAddress }] 0 [] world
  preludeSilent : prelude.observations = []
  subroutine : NativeWorldSubroutineResult candidate world continuationRva
    returnAddress subroutineEntryRva subroutineBefore subroutineAfter events
  epilogue : ExactComputedNativeWorldSegment candidate
    (.running continuationRva 0 subroutineAfter [] events.length events
      subroutine.afterWorld)
  epilogueReturned : epilogue.after =
    .returned after events subroutine.afterWorld

theorem InvokeCallNativeArmExecution.nativeWorldDispatches
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva subroutineEntryRva continuationRva : Nat}
    {returnAddress : Word} {before subroutineBefore subroutineAfter after : MachineState}
    {events : List NativeExternalEvent}
    (execution : InvokeCallNativeArmExecution candidate world invokeEntryRva
      subroutineEntryRva continuationRva returnAddress before subroutineBefore
      subroutineAfter after events) :
    NativeWorldDispatches candidate invokeEntryRva before world after events
      execution.subroutine.afterWorld
      (execution.subroutine.observations ++
        execution.epilogue.observations) := by
  have preludePath := execution.prelude.path
  rw [execution.preludeAtSubroutine, execution.preludeSilent] at preludePath
  have epiloguePath := execution.epilogue.path
  rw [execution.epilogueReturned] at epiloguePath
  simpa only [List.nil_append, List.append_assoc] using
    ((preludePath.trans execution.subroutine.path).trans epiloguePath)

theorem InvokeCallNativeArmExecution.kernelDispatches
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva subroutineEntryRva continuationRva : Nat}
    {returnAddress : Word} {before subroutineBefore subroutineAfter after : MachineState}
    {events : List NativeExternalEvent}
    (execution : InvokeCallNativeArmExecution candidate world invokeEntryRva
      subroutineEntryRva continuationRva returnAddress before subroutineBefore
      subroutineAfter after events) :
    NativeWorldKernelDispatches candidate world invokeEntryRva before after events := by
  exact ⟨execution.subroutine.afterWorld,
    execution.subroutine.observations ++ execution.epilogue.observations,
    execution.nativeWorldDispatches⟩

/-- Extract a nested native-world run from a proved `runFunction` operation.
The path, ABI response, and frame are outputs of that theorem, never premises of
this bridge. -/
theorem runFunctionSubroutine_of_operation_refinement
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {continuationRva : Nat} {returnAddress : Word}
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {before : MachineState} {result : CallResult}
    (operation : KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva returnAddress)
      .runFunction)
    (related : abi.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical) before)
    (abstractRun : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result) :
    exists entryRva after nativeEvents,
      program.functionEntry? .runFunction = some entryRva /\
      NativeWorldSubroutineDispatches candidate world continuationRva returnAddress
        entryRva before after nativeEvents /\
      abi.responseRelated
        (.runFunction records environment resolveCodeTarget sourceRva logical)
        (.call result) after nativeEvents /\
      MemoryAgreesOutside
        (abi.scratchFootprint
          (.runFunction records environment resolveCodeTarget sourceRva logical))
        after.memory before.memory := by
  exact operation
    (.runFunction records environment resolveCodeTarget sourceRva logical) before rfl
    related (.call result)
      (.runFunction records environment resolveCodeTarget sourceRva logical result
        abstractRun)

/-- Internal invoke-arm composition starts from the proved runFunction
operation.  The assembler receives the exact nested result produced by that
theorem; it cannot submit a replacement path, ABI response, or memory frame. -/
theorem internalKernelDispatches_of_runFunctionRefinement
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva continuationRva : Nat} {returnAddress : Word}
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {invokeBefore runFunctionBefore : MachineState}
    {result : CallResult}
    (operation : KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva returnAddress)
      .runFunction)
    (related : abi.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      runFunctionBefore)
    (abstractRun : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result)
    (assemble : ∀ entryRva runFunctionAfter nativeEvents,
      program.functionEntry? .runFunction = some entryRva ->
      NativeWorldSubroutineResult candidate world continuationRva returnAddress
        entryRva runFunctionBefore runFunctionAfter nativeEvents ->
      ∃ after, Nonempty (InvokeCallNativeArmExecution candidate world
        invokeEntryRva entryRva continuationRva returnAddress invokeBefore
        runFunctionBefore runFunctionAfter after nativeEvents)) :
    ∃ after nativeEvents,
      NativeWorldKernelDispatches candidate world invokeEntryRva invokeBefore
        after nativeEvents := by
  obtain ⟨entryRva, runFunctionAfter, nativeEvents, entryExact,
      ⟨subroutine⟩, _, _⟩ :=
    runFunctionSubroutine_of_operation_refinement operation related abstractRun
  obtain ⟨after, ⟨execution⟩⟩ :=
    assemble entryRva runFunctionAfter nativeEvents entryExact subroutine
  exact ⟨after, nativeEvents, execution.kernelDispatches⟩

/-- A checked environment action closes one exact external instruction step.
This is the primitive needed by an external-helper proof; it does not assume a
multi-instruction helper path. -/
theorem exactExternalInstructionStep
    (candidate : ExactNativeWorldProgram) (rva undefinedSlot : Nat)
    (state nextState : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) (imported : PEImport) (arguments : List Word)
    (continuation : Nat)
    (exact : stepKernelPE32Instruction candidate.pe candidate.imports
      (.running rva undefinedSlot state) =
        .stopped (.externalCall imported arguments continuation) nextState) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running rva undefinedSlot state calls eventIndex events world)
      (applyNativeWorldExternalAction continuation calls eventIndex events
        { imported, arguments, state := nextState } world
        (candidate.environment.action eventIndex
          { imported, arguments, state := nextState } world)).observation.toList
      (applyNativeWorldExternalAction continuation calls eventIndex events
        { imported, arguments, state := nextState } world
        (candidate.environment.action eventIndex
          { imported, arguments, state := nextState } world)).next := by
  have one := exactNativeWorldStepIsNonempty candidate
    (.running rva undefinedSlot state calls eventIndex events world)
  simpa [ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, exact, transitionFromNativeWorldOutcome]
    using one

/-! ## External invoke arm

The helper's wrapper code is reduced by exact finite segments.  The only
semantic synchronization point is the environment action selected by the
decoded external-call instruction. -/

structure InvokeCallNativeExternalArmExecution
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (invokeEntryRva externalInstructionRva externalContinuationRva : Nat)
    (before externalBefore decodedAfter after : MachineState)
    (calls : List NativeCallFrame) (imported : PEImport)
    (arguments : List Word) where
  prelude : ExactComputedNativeWorldSegment candidate
    (.running invokeEntryRva 0 before [] 0 [] world)
  preludeAtExternal : prelude.after =
    .running externalInstructionRva 0 externalBefore calls 0 [] world
  preludeSilent : prelude.observations = []
  decodedExternal : stepKernelPE32Instruction candidate.pe candidate.imports
    (.running externalInstructionRva 0 externalBefore) =
      .stopped (.externalCall imported arguments externalContinuationRva)
        decodedAfter
  result : WorldExternalResult
  environmentReturned : candidate.environment.action 0
    { imported, arguments, state := decodedAfter } world = .returned result
  epilogue : ExactComputedNativeWorldSegment candidate
    (.running externalContinuationRva 0 result.state calls 1
      [{ imported, arguments, state := decodedAfter }] result.world)
  epilogueReturned : epilogue.after =
    .returned after [{ imported, arguments, state := decodedAfter }] result.world

theorem InvokeCallNativeExternalArmExecution.nativeWorldDispatches
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva externalInstructionRva externalContinuationRva : Nat}
    {before externalBefore decodedAfter after : MachineState}
    {calls : List NativeCallFrame} {imported : PEImport}
    {arguments : List Word}
    (execution : InvokeCallNativeExternalArmExecution candidate world
      invokeEntryRva externalInstructionRva externalContinuationRva before
      externalBefore decodedAfter after calls imported arguments) :
    NativeWorldDispatches candidate invokeEntryRva before world after
      [{ imported, arguments, state := decodedAfter }] execution.result.world
      ([.external world (normalizeImport imported) arguments] ++
        execution.epilogue.observations) := by
  have preludePath := execution.prelude.path
  rw [execution.preludeAtExternal, execution.preludeSilent] at preludePath
  have externalPath := exactExternalInstructionStep candidate
    externalInstructionRva 0 externalBefore decodedAfter calls 0 [] world
    imported arguments externalContinuationRva execution.decodedExternal
  rw [execution.environmentReturned] at externalPath
  have epiloguePath := execution.epilogue.path
  rw [execution.epilogueReturned] at epiloguePath
  simpa only [List.nil_append, List.append_assoc] using
    ((preludePath.trans externalPath).trans epiloguePath)

theorem InvokeCallNativeExternalArmExecution.kernelDispatches
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva externalInstructionRva externalContinuationRva : Nat}
    {before externalBefore decodedAfter after : MachineState}
    {calls : List NativeCallFrame} {imported : PEImport}
    {arguments : List Word}
    (execution : InvokeCallNativeExternalArmExecution candidate world
      invokeEntryRva externalInstructionRva externalContinuationRva before
      externalBefore decodedAfter after calls imported arguments) :
    NativeWorldKernelDispatches candidate world invokeEntryRva before after
      [{ imported, arguments, state := decodedAfter }] := by
  exact ⟨execution.result.world,
    [.external world (normalizeImport imported) arguments] ++
      execution.epilogue.observations,
    execution.nativeWorldDispatches⟩

/-! ## Indirect invoke arm

The resolver callback is split out so the selected machine target must be a
member of the checked callback inventory.  Its one-instruction dispatch,
callback body, continuation-to-runFunction path, runFunction refinement, and
wrapper epilogue remain separately cacheable exact segments. -/

def callbackSiteAt? (inventory : KernelCallbackInventory) (rva : Nat) :
    Option KernelIndirectCallbackSite :=
  inventory.sites.find? fun site => site.instruction.rva == rva

structure InvokeCallNativeIndirectArmExecution
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (program : CompiledKernelProgram) (inventory : KernelCallbackInventory)
    (invokeEntryRva runFunctionEntryRva runFunctionContinuationRva : Nat)
    (before resolverBefore callbackBefore callbackAfter runFunctionBefore
      runFunctionAfter after : MachineState)
    (site : KernelIndirectCallbackSite) (target : CallbackTargetEntry)
    (runFunctionEvents : List NativeExternalEvent) where
  inventoryChecked : inventory.checked program candidate.pe candidate.imports = true
  resolverSiteExact : callbackSiteAt? inventory site.instruction.rva = some site
  resolverAtExpectedRva : site.instruction.rva = invokeEntryRva + 124
  targetMember : target ∈ site.targets.entries
  targetSelected : site.targetWord resolverBefore = target.address candidate.pe
  prelude : ExactComputedNativeWorldSegment candidate
    (.running invokeEntryRva 0 before [] 0 [] world)
  preludeAtResolver : prelude.after =
    .running site.instruction.rva 0 resolverBefore [] 0 [] world
  preludeSilent : prelude.observations = []
  resolverStep : ExactComputedNativeWorldSegment candidate
    (.running site.instruction.rva 0 resolverBefore [] 0 [] world)
  resolverStepOne : resolverStep.fuel = 1
  resolverAtTarget : resolverStep.after =
    .running target.entry.rva 0 callbackBefore
      [callbackNativeFrame candidate.pe site] 0 [] world
  resolverSilent : resolverStep.observations = []
  callbackBody : ExactComputedNativeWorldSegment candidate
    (.running target.entry.rva 0 callbackBefore
      [callbackNativeFrame candidate.pe site] 0 [] world)
  callbackReturned : callbackBody.after =
    .running site.continuationRva 0 callbackAfter [] 0 [] world
  callbackSilent : callbackBody.observations = []
  toRunFunction : ExactComputedNativeWorldSegment candidate
    (.running site.continuationRva 0 callbackAfter [] 0 [] world)
  atRunFunction : toRunFunction.after =
    .running runFunctionEntryRva 0 runFunctionBefore
      [{ continuationRva := runFunctionContinuationRva,
         returnAddress := BitVec.ofNat 32
          (candidate.pe.imageBase + runFunctionContinuationRva) }] 0 [] world
  toRunFunctionSilent : toRunFunction.observations = []
  runFunction : NativeWorldSubroutineResult candidate world
    runFunctionContinuationRva
    (BitVec.ofNat 32 (candidate.pe.imageBase + runFunctionContinuationRva))
    runFunctionEntryRva runFunctionBefore runFunctionAfter runFunctionEvents
  epilogue : ExactComputedNativeWorldSegment candidate
    (.running runFunctionContinuationRva 0 runFunctionAfter []
      runFunctionEvents.length runFunctionEvents runFunction.afterWorld)
  epilogueReturned : epilogue.after =
    .returned after runFunctionEvents runFunction.afterWorld

theorem InvokeCallNativeIndirectArmExecution.nativeWorldDispatches
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {program : CompiledKernelProgram} {inventory : KernelCallbackInventory}
    {invokeEntryRva runFunctionEntryRva runFunctionContinuationRva : Nat}
    {before resolverBefore callbackBefore callbackAfter runFunctionBefore
      runFunctionAfter after : MachineState}
    {site : KernelIndirectCallbackSite} {target : CallbackTargetEntry}
    {runFunctionEvents : List NativeExternalEvent}
    (execution : InvokeCallNativeIndirectArmExecution candidate world program
      inventory invokeEntryRva runFunctionEntryRva runFunctionContinuationRva
      before resolverBefore callbackBefore callbackAfter runFunctionBefore
      runFunctionAfter after site target runFunctionEvents) :
    NativeWorldDispatches candidate invokeEntryRva before world after
      runFunctionEvents execution.runFunction.afterWorld
      (execution.runFunction.observations ++ execution.epilogue.observations) := by
  have preludePath := execution.prelude.path
  rw [execution.preludeAtResolver, execution.preludeSilent] at preludePath
  have resolverPath := execution.resolverStep.path
  rw [execution.resolverAtTarget, execution.resolverSilent] at resolverPath
  have callbackPath := execution.callbackBody.path
  rw [execution.callbackReturned, execution.callbackSilent] at callbackPath
  have middlePath := execution.toRunFunction.path
  rw [execution.atRunFunction, execution.toRunFunctionSilent] at middlePath
  have epiloguePath := execution.epilogue.path
  rw [execution.epilogueReturned] at epiloguePath
  simpa only [List.nil_append, List.append_assoc] using
    (((((preludePath.trans resolverPath).trans callbackPath).trans middlePath).trans
      execution.runFunction.path).trans epiloguePath)

theorem InvokeCallNativeIndirectArmExecution.kernelDispatches
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {program : CompiledKernelProgram} {inventory : KernelCallbackInventory}
    {invokeEntryRva runFunctionEntryRva runFunctionContinuationRva : Nat}
    {before resolverBefore callbackBefore callbackAfter runFunctionBefore
      runFunctionAfter after : MachineState}
    {site : KernelIndirectCallbackSite} {target : CallbackTargetEntry}
    {runFunctionEvents : List NativeExternalEvent}
    (execution : InvokeCallNativeIndirectArmExecution candidate world program
      inventory invokeEntryRva runFunctionEntryRva runFunctionContinuationRva
      before resolverBefore callbackBefore callbackAfter runFunctionBefore
      runFunctionAfter after site target runFunctionEvents) :
    NativeWorldKernelDispatches candidate world invokeEntryRva before after
      runFunctionEvents := by
  exact ⟨execution.runFunction.afterWorld,
    execution.runFunction.observations ++ execution.epilogue.observations,
    execution.nativeWorldDispatches⟩

/-- Indirect-arm specialization of the operation bridge.  The checked
inventory, resolver step, callback body, and exact wrapper pieces are supplied
only by the arm assembler; the runFunction path itself is extracted from the
operation theorem. -/
theorem indirectKernelDispatches_of_runFunctionRefinement
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {inventory : KernelCallbackInventory}
    {invokeEntryRva continuationRva : Nat}
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine}
    {invokeBefore resolverBefore callbackBefore callbackAfter
      runFunctionBefore : MachineState}
    {site : KernelIndirectCallbackSite} {target : CallbackTargetEntry}
    {result : CallResult}
    (operation : KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva
        (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)))
      .runFunction)
    (related : abi.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      runFunctionBefore)
    (abstractRun : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result)
    (assemble : ∀ entryRva runFunctionAfter nativeEvents,
      program.functionEntry? .runFunction = some entryRva ->
      NativeWorldSubroutineResult candidate world continuationRva
        (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)) entryRva
        runFunctionBefore runFunctionAfter nativeEvents ->
      ∃ after, Nonempty (InvokeCallNativeIndirectArmExecution candidate world
        program inventory invokeEntryRva entryRva continuationRva invokeBefore
        resolverBefore callbackBefore callbackAfter runFunctionBefore
        runFunctionAfter after site target nativeEvents)) :
    ∃ after nativeEvents,
      NativeWorldKernelDispatches candidate world invokeEntryRva invokeBefore
        after nativeEvents := by
  obtain ⟨entryRva, runFunctionAfter, nativeEvents, entryExact,
      ⟨subroutine⟩, _, _⟩ :=
    runFunctionSubroutine_of_operation_refinement operation related abstractRun
  obtain ⟨after, ⟨execution⟩⟩ :=
    assemble entryRva runFunctionAfter nativeEvents entryExact subroutine
  exact ⟨after, nativeEvents, execution.kernelDispatches⟩

#print axioms ExactComputedNativeWorldSegment.path
#print axioms InvokeCallNativeArmExecution.nativeWorldDispatches
#print axioms InvokeCallNativeArmExecution.kernelDispatches
#print axioms runFunctionSubroutine_of_operation_refinement
#print axioms internalKernelDispatches_of_runFunctionRefinement
#print axioms exactExternalInstructionStep
#print axioms InvokeCallNativeExternalArmExecution.nativeWorldDispatches
#print axioms InvokeCallNativeExternalArmExecution.kernelDispatches
#print axioms InvokeCallNativeIndirectArmExecution.nativeWorldDispatches
#print axioms InvokeCallNativeIndirectArmExecution.kernelDispatches
#print axioms indirectKernelDispatches_of_runFunctionRefinement

end StageA.Relational.InterpreterKernelInvokeNative
