import StageA.RelationalInterpreterKernelInvokeNative
import StageA.RelationalInterpreterKernelHelperPath
import StageA.RelationalInterpreterKernelProgramLookupOperation
import StageA.RelationalInterpreterKernelRunOperation

namespace StageA.Relational.InterpreterKernelInvokeOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelInvoke
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelHelperPath
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SymbolicSoundness

/-!
Composable authority for one exact native `invokeCall` implementation.

The static wrapper and concrete ABI identity are checked independently.  The
three dynamic arms expose exact native execution objects, ABI response proofs,
and scratch-memory frames.  Internal and indirect arms must assemble around the
exact nested `runFunction` result extracted from a separately proved operation;
they cannot submit a whole-arm dispatch path.
-/

/-- Exact PE-backed wrapper and callback-inventory authority. -/
structure InvokeCallNativeStaticBinding
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram) where
  function : KernelFunction
  reflected : InvokeCallTemplateCertificate program candidate.pe
    candidate.imports function
  entryRvaExact :
    program.functionEntry? .invokeCall = some function.span.start

/-- Concrete cdecl request authority.  Keeping this separate from branch
execution makes the generated static/ABI proof independently cacheable. -/
structure InvokeCallNativeABIEntryAuthority
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord) : Prop where
  recordsExact : forall records environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall records environment resolveCodeTarget event logical) before ->
      records = semanticRecords

def concreteInvokeCallABIEntryAuthority
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords) :
    InvokeCallNativeABIEntryAuthority abi.relation semanticRecords := {
  recordsExact := by
    intro records environment resolveCodeTarget event logical before related
    exact related.payload.1
}

/-- The two nested `runFunction` frames encoded by the checked wrapper. -/
def InvokeCallNativeStaticBinding.internalContinuationRva
    (static : InvokeCallNativeStaticBinding program candidate) : Nat :=
  static.reflected.template.entryRva + 67

def InvokeCallNativeStaticBinding.internalReturnAddress
    (static : InvokeCallNativeStaticBinding program candidate) : Word :=
  BitVec.ofNat 32 (candidate.pe.imageBase + static.internalContinuationRva)

def InvokeCallNativeStaticBinding.indirectContinuationRva
    (static : InvokeCallNativeStaticBinding program candidate) : Nat :=
  static.reflected.template.entryRva + 162

def InvokeCallNativeStaticBinding.indirectReturnAddress
    (static : InvokeCallNativeStaticBinding program candidate) : Word :=
  BitVec.ofNat 32 (candidate.pe.imageBase + static.indirectContinuationRva)

/-- Minimal `runFunction` theorem surface for only the two native call frames
that the reflected `invokeCall` wrapper can reach.  Invoke composition does not
depend on the implementation-specific certificate records used to prove these
theorems. -/
structure InvokeCallNativeRunFunctionRefinements
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  internal : KernelOperationRefinesUsing program abi
    (NativeWorldSubroutineDispatches candidate world
      static.internalContinuationRva static.internalReturnAddress) .runFunction
  indirect : KernelOperationRefinesUsing program abi
    (NativeWorldSubroutineDispatches candidate world
      static.indirectContinuationRva static.indirectReturnAddress) .runFunction

/-- The wrapper's direct helper call returns to the checked cdecl epilogue. -/
def InvokeCallNativeStaticBinding.externalContinuationRva
    (static : InvokeCallNativeStaticBinding program candidate) : Nat :=
  static.reflected.template.entryRva + 196

def InvokeCallNativeStaticBinding.externalReturnAddress
    (static : InvokeCallNativeStaticBinding program candidate) : Word :=
  BitVec.ofNat 32 (candidate.pe.imageBase + static.externalContinuationRva)

def InvokeCallNativeStaticBinding.externalFrame
    (static : InvokeCallNativeStaticBinding program candidate) : NativeCallFrame := {
  continuationRva := static.externalContinuationRva
  returnAddress := static.externalReturnAddress
}

/-- Unique PE-backed helper reached by the reflected direct call.  Function
names and map provenance are not trusted: the role, entry, exact bytes, and
every decoded instruction are checked against the candidate image. -/
structure InvokeCallNativeExternalHelperBinding
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InvokeCallNativeStaticBinding program candidate) where
  helper : KernelFunction
  uniqueAtEntry :
    program.functions.filter (fun function =>
      function.span.start == static.reflected.template.externalDispatchRva) =
        [helper]
  roleExact :
    helper.role = .helper static.reflected.template.externalDispatchRva
  entryExact :
    helper.span.start = static.reflected.template.externalDispatchRva
  checked : helper.checked candidate.pe candidate.imports = true
  exactDecodes : ExactDecodeInventory candidate.pe helper.instructions

/-- Exact candidate execution split at the helper entry.  This prevents a
computed path to an unrelated external instruction from satisfying the branch:
the native run must first enter the uniquely byte-checked helper through the
wrapper's exact hardware return frame. -/
structure InvokeCallNativeExternalHelperArmExecution
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (graph : HelperPathGraph)
    (before : MachineState) where
  helperBefore : MachineState
  after : MachineState
  wrapperPrelude : ExactComputedNativeWorldSegment candidate
    (.running static.function.span.start 0 before [] 0 [] world)
  wrapperAtHelper : wrapperPrelude.after =
    .running helper.helper.span.start 0 helperBefore [static.externalFrame] 0 []
      world
  wrapperSilent : wrapperPrelude.observations = []
  graphEntryExact : graph.helperEntryRva = helper.helper.span.start
  helperExecution : ExactComputedHelperPathExecution candidate graph helperBefore
    [static.externalFrame] 0 [] world
  result : WorldExternalResult
  environmentReturned : candidate.environment.action 0
    { imported := helperExecution.boundary.imported
      arguments := helperExecution.boundary.arguments
      state := helperExecution.boundary.decodedAfter } world = .returned result
  epilogue : ExactComputedNativeWorldSegment candidate
    (.running helperExecution.boundary.continuationRva 0 result.state
      helperExecution.boundary.calls 1
      [{ imported := helperExecution.boundary.imported
         arguments := helperExecution.boundary.arguments
         state := helperExecution.boundary.decodedAfter }] result.world)
  epilogueReturned : epilogue.after =
    .returned after
      [{ imported := helperExecution.boundary.imported
         arguments := helperExecution.boundary.arguments
         state := helperExecution.boundary.decodedAfter }] result.world

def InvokeCallNativeExternalHelperArmExecution.nativeEvent
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before) : NativeExternalEvent := {
  imported := execution.helperExecution.boundary.imported
  arguments := execution.helperExecution.boundary.arguments
  state := execution.helperExecution.boundary.decodedAfter
}

theorem InvokeCallNativeExternalHelperArmExecution.nativeWorldDispatches
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before) :
    NativeWorldDispatches candidate static.function.span.start before world
      execution.after [execution.nativeEvent] execution.result.world
      ([.external world
          (normalizeImport execution.helperExecution.boundary.imported)
          execution.helperExecution.boundary.arguments] ++
        execution.epilogue.observations) := by
  have wrapperPath := execution.wrapperPrelude.path
  rw [execution.wrapperAtHelper, execution.wrapperSilent] at wrapperPath
  rw [← execution.graphEntryExact] at wrapperPath
  have helperPath := execution.helperExecution.pathToBoundary
  have externalPath := exactExternalInstructionStep candidate
    execution.helperExecution.boundary.instruction.rva
    execution.helperExecution.boundary.undefinedSlot
    execution.helperExecution.boundary.state
    execution.helperExecution.boundary.decodedAfter
    execution.helperExecution.boundary.calls 0 [] world
    execution.helperExecution.boundary.imported
    execution.helperExecution.boundary.arguments
    execution.helperExecution.boundary.continuationRva
    execution.helperExecution.boundary.decodedExact
  rw [execution.environmentReturned] at externalPath
  have epiloguePath := execution.epilogue.path
  rw [execution.epilogueReturned] at epiloguePath
  simpa only [List.nil_append, List.append_assoc] using
    (((wrapperPath.trans helperPath).trans externalPath).trans epiloguePath)

theorem InvokeCallNativeExternalHelperArmExecution.kernelDispatches
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before) :
    NativeWorldKernelDispatches candidate world static.function.span.start before
      execution.after [execution.nativeEvent] := by
  exact ⟨execution.result.world,
    [.external world
      (normalizeImport execution.helperExecution.boundary.imported)
      execution.helperExecution.boundary.arguments] ++
      execution.epilogue.observations,
    execution.nativeWorldDispatches⟩

/-- Wrapper execution stops exactly at the checked helper entry and establishes
the entry predicate consumed by the universal helper-path certificate. -/
structure InvokeCallNativeExternalHelperPrepared
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (graph : HelperPathGraph) (precondition : HelperPathEntryPrecondition)
    (before : MachineState) where
  helperBefore : MachineState
  wrapperPrelude : ExactComputedNativeWorldSegment candidate
    (.running static.function.span.start 0 before [] 0 [] world)
  wrapperAtHelper : wrapperPrelude.after =
    .running helper.helper.span.start 0 helperBefore [static.externalFrame] 0 []
      world
  wrapperSilent : wrapperPrelude.observations = []
  helperInput :
    precondition helperBefore [static.externalFrame] 0 [] world

structure InvokeCallNativeExternalHelperPreparedCompletion
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (graph : HelperPathGraph) (precondition : HelperPathEntryPrecondition)
    (before : MachineState)
    (prepared : InvokeCallNativeExternalHelperPrepared program abi semanticRecords
      candidate world static helper graph precondition before)
    (helperExecution : ExactComputedHelperPathExecution candidate graph
      prepared.helperBefore [static.externalFrame] 0 [] world) where
  execution : InvokeCallNativeExternalHelperArmExecution program candidate world
    static helper graph before
  helperBeforeExact : execution.helperBefore = prepared.helperBefore
  wrapperExact : execution.wrapperPrelude = prepared.wrapperPrelude
  helperExecutionExact : HEq execution.helperExecution helperExecution

/-- Candidate authority is split around the generic helper-path certificate.
The completion may add the exact environment action and epilogue, but it must
reuse both the prepared wrapper and the helper execution returned by that
certificate. -/
structure InvokeCallNativeExternalHelperExecutionAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static) where
  graph : HelperPathGraph
  precondition : HelperPathEntryPrecondition
  graphEntryExact : graph.helperEntryRva = helper.helper.span.start
  path : UniversalHelperPathExecutionCertificate program candidate graph
    precondition
  prepare : forall environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .external ->
    Nonempty (InvokeCallNativeExternalHelperPrepared program abi semanticRecords
      candidate world static helper graph precondition before)
  finish : forall environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .external ->
    (prepared : InvokeCallNativeExternalHelperPrepared program abi semanticRecords
      candidate world static helper graph precondition before) ->
    (helperExecution : ExactComputedHelperPathExecution candidate graph
      prepared.helperBefore [static.externalFrame] 0 [] world) ->
    Nonempty (InvokeCallNativeExternalHelperPreparedCompletion program candidate
      world static helper graph precondition before prepared helperExecution)

theorem InvokeCallNativeExternalHelperExecutionAuthority.execute
    (authority : InvokeCallNativeExternalHelperExecutionAuthority program abi
      semanticRecords candidate world static helper) :
    forall environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .external ->
    Nonempty (InvokeCallNativeExternalHelperArmExecution program candidate world
      static helper authority.graph before) := by
  intro environment resolveCodeTarget event logical before related kind
  obtain ⟨prepared⟩ :=
    authority.prepare environment resolveCodeTarget event logical before
      related kind
  obtain ⟨helperExecution⟩ :=
    authority.path.execute prepared.helperInput
  obtain ⟨completion⟩ :=
    authority.finish environment resolveCodeTarget event logical before related
      kind prepared helperExecution
  exact ⟨completion.execution⟩

/-- Smallest missing semantic bridge.  Exact execution determines the endpoint,
native event, environment result, and observed import.  This refinement may
only prove that the semantic external result is represented by that endpoint
and that its actual writes fit the ABI's declared scratch footprint. -/
structure InvokeCallNativeExternalEnvironmentRefinement
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (graph : HelperPathGraph) :
    Prop where
  complete : forall environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .external ->
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before) ->
    NativeExternalEventShape event execution.nativeEvent /\
      abi.responseRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        (.call (environment.invokeCall event logical)) execution.after
        [execution.nativeEvent] /\
      MemoryAgreesOutside
        (abi.scratchFootprint
          (.invokeCall semanticRecords environment resolveCodeTarget event logical))
        execution.after.memory before.memory

/-- Completion around the exact nested result produced by the proved
`runFunction` operation.  `subroutineExact` prevents an assembler from
substituting an unrelated path with the same endpoints. -/
structure InvokeCallNativeInternalCompletion
    (abi : KernelABIRelation) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) (invokeEntryRva subroutineEntryRva
      continuationRva : Nat) (returnAddress : Word)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (before subroutineBefore subroutineAfter : MachineState)
    (events : List NativeExternalEvent)
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      returnAddress subroutineEntryRva subroutineBefore subroutineAfter events) where
  after : MachineState
  execution : InvokeCallNativeArmExecution candidate world invokeEntryRva
    subroutineEntryRva continuationRva returnAddress before subroutineBefore
    subroutineAfter after events
  subroutineExact : execution.subroutine = subroutine
  responseRelated : abi.responseRelated request response after events
  memoryFrame : MemoryAgreesOutside (abi.scratchFootprint request)
    after.memory before.memory

def InvokeCallNativeInternalCompletion.toBranchResult
    (completion : InvokeCallNativeInternalCompletion abi candidate world
      entryRva subroutineEntryRva continuationRva returnAddress request response
      before subroutineBefore subroutineAfter events subroutine) :
    InvokeCallBranchResult abi (NativeWorldKernelDispatches candidate world)
      entryRva request response before := {
  after := completion.after
  nativeEvents := events
  path := completion.execution.kernelDispatches
  responseRelated := completion.responseRelated
  memoryFrame := completion.memoryFrame
}

/-- An internal semantic arm prepared at the exact nested call boundary. -/
structure InvokeCallNativeInternalPrepared
    (program : CompiledKernelProgram)
    (operationABI runABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (invokeEntryRva continuationRva : Nat) (returnAddress : Word)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (invokeBefore : MachineState)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse) where
  runFunctionBefore : MachineState
  requestRelated : runABI.requestRelated
    (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
    runFunctionBefore
  assemble : forall entryRva runFunctionAfter events,
    program.functionEntry? .runFunction = some entryRva ->
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      returnAddress entryRva runFunctionBefore runFunctionAfter events) ->
    Nonempty (InvokeCallNativeInternalCompletion operationABI candidate world
      invokeEntryRva entryRva continuationRva returnAddress request response
      invokeBefore runFunctionBefore runFunctionAfter events subroutine)

/-- Internal arm authority.  The abstract `runFunction` derivation is an
explicit input and therefore stays synchronized with the semantic transition
being refined. -/
structure InvokeCallNativeInternalBranchAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  continuationRva : Nat
  continuationExact :
    continuationRva = static.reflected.template.entryRva + 67
  returnAddress : Word
  returnAddressExact :
    returnAddress =
      BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)
  prepare : forall environment resolveCodeTarget event logical before result,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .internal ->
    AbstractRunFunction semanticRecords environment resolveCodeTarget
      event.targetRva.toNat logical result ->
    Nonempty (InvokeCallNativeInternalPrepared program abi abi semanticRecords
      candidate world static.function.span.start continuationRva returnAddress
      environment resolveCodeTarget event.targetRva.toNat logical result before
      (.invokeCall semanticRecords environment resolveCodeTarget event logical)
      (.call result))

/-- Indirect-arm completion around the exact nested `runFunction` result. -/
structure InvokeCallNativeIndirectCompletion
    (program : CompiledKernelProgram) (inventory : KernelCallbackInventory)
    (abi : KernelABIRelation) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) (invokeEntryRva runFunctionEntryRva
      continuationRva : Nat)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (before runFunctionBefore runFunctionAfter : MachineState)
    (events : List NativeExternalEvent)
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))
      runFunctionEntryRva runFunctionBefore runFunctionAfter events) where
  resolverBefore : MachineState
  callbackBefore : MachineState
  callbackAfter : MachineState
  after : MachineState
  site : KernelIndirectCallbackSite
  target : CallbackTargetEntry
  execution : InvokeCallNativeIndirectArmExecution candidate world program
    inventory invokeEntryRva runFunctionEntryRva continuationRva before
    resolverBefore callbackBefore callbackAfter runFunctionBefore
    runFunctionAfter after site target events
  subroutineExact : execution.runFunction = subroutine
  responseRelated : abi.responseRelated request response after events
  memoryFrame : MemoryAgreesOutside (abi.scratchFootprint request)
    after.memory before.memory

def InvokeCallNativeIndirectCompletion.toBranchResult
    (completion : InvokeCallNativeIndirectCompletion program inventory abi
      candidate world entryRva runFunctionEntryRva continuationRva request response
      before runFunctionBefore runFunctionAfter events subroutine) :
    InvokeCallBranchResult abi (NativeWorldKernelDispatches candidate world)
      entryRva request response before := {
  after := completion.after
  nativeEvents := events
  path := completion.execution.kernelDispatches
  responseRelated := completion.responseRelated
  memoryFrame := completion.memoryFrame
}

structure InvokeCallNativeIndirectPrepared
    (program : CompiledKernelProgram) (inventory : KernelCallbackInventory)
    (operationABI runABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (invokeEntryRva continuationRva targetRva : Nat)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine)
    (result : CallResult) (invokeBefore : MachineState)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse) where
  runFunctionBefore : MachineState
  requestRelated : runABI.requestRelated
    (.runFunction semanticRecords environment resolveCodeTarget targetRva logical)
    runFunctionBefore
  assemble : forall entryRva runFunctionAfter events,
    program.functionEntry? .runFunction = some entryRva ->
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)) entryRva
      runFunctionBefore runFunctionAfter events) ->
    Nonempty (InvokeCallNativeIndirectCompletion program inventory operationABI
      candidate
      world invokeEntryRva entryRva continuationRva request response invokeBefore
      runFunctionBefore runFunctionAfter events subroutine)

structure InvokeCallNativeIndirectBranchAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  continuationRva : Nat
  continuationExact :
    continuationRva = static.reflected.template.entryRva + 162
  prepare : forall environment resolveCodeTarget event logical before target result,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .indirect ->
    resolveCodeTarget event.targetRva = some target ->
    AbstractRunFunction semanticRecords environment resolveCodeTarget target logical
      result ->
    Nonempty (InvokeCallNativeIndirectPrepared program
      static.reflected.callbacks abi abi semanticRecords candidate world
      static.function.span.start continuationRva target environment
      resolveCodeTarget logical result before
      (.invokeCall semanticRecords environment resolveCodeTarget event logical)
      (.call result))

structure InvokeCallNativeExternalBranchAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  helper : InvokeCallNativeExternalHelperBinding program candidate static
  execution : InvokeCallNativeExternalHelperExecutionAuthority program abi
    semanticRecords candidate world static helper
  environment : InvokeCallNativeExternalEnvironmentRefinement program abi
    semanticRecords candidate world static helper execution.graph

theorem InvokeCallNativeExternalBranchAuthority.execute
    (authority : InvokeCallNativeExternalBranchAuthority program abi
      semanticRecords candidate world static) :
    forall environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .external ->
    Nonempty (InvokeCallBranchResult abi
      (NativeWorldKernelDispatches candidate world) static.function.span.start
      (.invokeCall semanticRecords environment resolveCodeTarget event logical)
      (.call (environment.invokeCall event logical)) before) := by
  intro environment resolveCodeTarget event logical before related kind
  obtain ⟨execution⟩ :=
    authority.execution.execute environment resolveCodeTarget event logical before
      related kind
  obtain ⟨_, response, frame⟩ :=
    authority.environment.complete environment resolveCodeTarget event logical
      before related kind execution
  exact ⟨{
    after := execution.after
    nativeEvents := [execution.nativeEvent]
    path := execution.kernelDispatches
    responseRelated := response
    memoryFrame := frame
  }⟩

theorem InvokeCallNativeRunFunctionRefinements.internalForAuthority
    (refinements : InvokeCallNativeRunFunctionRefinements program abi
      candidate world static)
    (authority : InvokeCallNativeInternalBranchAuthority program abi
      semanticRecords candidate world static) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world authority.continuationRva
        authority.returnAddress) .runFunction := by
  simpa [InvokeCallNativeStaticBinding.internalContinuationRva,
    InvokeCallNativeStaticBinding.internalReturnAddress,
    authority.continuationExact, authority.returnAddressExact] using
    refinements.internal

theorem InvokeCallNativeRunFunctionRefinements.indirectForAuthority
    (refinements : InvokeCallNativeRunFunctionRefinements program abi
      candidate world static)
    (authority : InvokeCallNativeIndirectBranchAuthority program abi
      semanticRecords candidate world static) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world authority.continuationRva
        (BitVec.ofNat 32
          (candidate.pe.imageBase + authority.continuationRva))) .runFunction := by
  simpa [InvokeCallNativeStaticBinding.indirectContinuationRva,
    InvokeCallNativeStaticBinding.indirectReturnAddress,
    authority.continuationExact] using refinements.indirect

/-- Exact-candidate invoke operation assembled from static evidence, concrete
ABI identity, one nested operation theorem, and the three typed arm
authorities. -/
structure InvokeCallNativeOperationCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) where
  static : InvokeCallNativeStaticBinding program candidate
  abiEntry : InvokeCallNativeABIEntryAuthority abi semanticRecords
  external : InvokeCallNativeExternalBranchAuthority program abi semanticRecords
    candidate world static
  internal : InvokeCallNativeInternalBranchAuthority program abi semanticRecords
    candidate world static
  indirect : InvokeCallNativeIndirectBranchAuthority program abi semanticRecords
    candidate world static
  runFunction : InvokeCallNativeRunFunctionRefinements program abi
    candidate world static

def InvokeCallNativeOperationCertificate.branches
    (certificate : InvokeCallNativeOperationCertificate program abi
      semanticRecords candidate world) :
    InvokeCallBranchExecutions abi (NativeWorldKernelDispatches candidate world)
      certificate.static.function.span.start semanticRecords := {
  external := by
    intro environment resolveCodeTarget event logical before related kind
    obtain ⟨result⟩ :=
      certificate.external.execute environment resolveCodeTarget event logical
        before related kind
    exact ⟨result⟩
  internal := by
    intro environment resolveCodeTarget event logical before result related kind run
    obtain ⟨prepared⟩ :=
      certificate.internal.prepare environment resolveCodeTarget event logical
        before result related kind run
    obtain ⟨entryRva, after, events, entryExact, ⟨subroutine⟩, _, _⟩ :=
      runFunctionSubroutine_of_operation_refinement
        (certificate.runFunction.internalForAuthority certificate.internal)
        prepared.requestRelated run
    obtain ⟨completion⟩ :=
      prepared.assemble entryRva after events entryExact subroutine
    exact ⟨completion.toBranchResult⟩
  indirect := by
    intro environment resolveCodeTarget event logical before target result related
      kind resolved run
    obtain ⟨prepared⟩ :=
      certificate.indirect.prepare environment resolveCodeTarget event logical
        before target result related kind resolved run
    obtain ⟨entryRva, after, events, entryExact, ⟨subroutine⟩, _, _⟩ :=
      runFunctionSubroutine_of_operation_refinement
        (certificate.runFunction.indirectForAuthority certificate.indirect)
        prepared.requestRelated run
    obtain ⟨completion⟩ :=
      prepared.assemble entryRva after events entryExact subroutine
    exact ⟨completion.toBranchResult⟩
}

def InvokeCallNativeOperationCertificate.toMachineCertificate
    (certificate : InvokeCallNativeOperationCertificate program abi
      semanticRecords candidate world) :
    InvokeCallMachineCertificate program candidate.pe candidate.imports abi
      semanticRecords (NativeWorldKernelDispatches candidate world) := {
  function := certificate.static.function
  reflected := certificate.static.reflected
  entryRvaExact := certificate.static.entryRvaExact
  recordsExact := certificate.abiEntry.recordsExact
  branches := certificate.branches
}

theorem InvokeCallNativeOperationCertificate.refines
    (certificate : InvokeCallNativeOperationCertificate program abi
      semanticRecords candidate world) :
    KernelOperationRefinesUsing program abi
      (NativeWorldKernelDispatches candidate world) .invokeCall :=
  certificate.toMachineCertificate.refines

/-! ## Request-local closed-call-tree adapter

The compatibility certificate above accepts two universally quantified Run
theorems.  New proofs instead retain the exact checked Invoke derivation and
the checked Run tree nested in each internal or indirect constructor.
-/

/-- Structural completeness for Invoke transitions.  This authority may only
turn an authoritative abstract transition into a finite checked call tree.  In
particular, the checked tree retains the exact environment result, indirect
target lookup, and nested Run derivation; it contains no native execution or
status assertion. -/
structure InvokeCallClosedCallTreeAuthority
    (records : List ProgramRecord) : Prop where
  close : ∀ environment resolveCodeTarget event logical response,
    AbstractKernelTransition
        (.invokeCall records environment resolveCodeTarget event logical)
        response ->
      ∃ result,
        response = .call result ∧
          CheckedInvokeCallDerivation records environment resolveCodeTarget
            event logical result

def InvokeCallClosedCallTreeAuthority.ofClosure
    (closure : CheckedSemanticCallTreeClosure records) :
    InvokeCallClosedCallTreeAuthority records := {
  close := closure.invoke
}

/-- Extract the exact native subroutine produced for one retained checked Run
tree.  This is the request-local counterpart of
`runFunctionSubroutine_of_operation_refinement`: it executes the supplied tree
directly and never appeals to a universal Run theorem. -/
theorem runFunctionSubroutine_of_checked_derivation
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {semanticRecords : List ProgramRecord}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {continuationRva : Nat} {returnAddress : Word}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {before : MachineState}
    {result : CallResult}
    (certificate : RunFunctionNativeCheckedOperationCertificate program abi
      semanticRecords candidate world continuationRva returnAddress)
    (derivation : CheckedRunFunctionDerivation semanticRecords environment
      resolveCodeTarget sourceRva logical result)
    (related : abi.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before) :
    ∃ entryRva after nativeEvents,
      program.functionEntry? .runFunction = some entryRva ∧
      NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress entryRva before after nativeEvents ∧
      abi.responseRelated
        (.runFunction semanticRecords environment resolveCodeTarget sourceRva
          logical)
        (.call result) after nativeEvents ∧
      MemoryAgreesOutside
        (abi.scratchFootprint
          (.runFunction semanticRecords environment resolveCodeTarget sourceRva
            logical))
        after.memory before.memory := by
  let entryPhase := certificate.entry.entry environment resolveCodeTarget
    sourceRva logical before related
  let initialRuntime : RunFunctionNativeRuntime := {
    calls := [runFunctionNativeOuterFrame continuationRva returnAddress]
    eventIndex := 0
    events := []
    world := world
  }
  have entryInvariant : certificate.semantics.invariant sourceRva logical
      (initialRuntime.running
        certificate.static.reflected.reflected.template.loopHeaderRva
        entryPhase.loopState) := by
    have invariant := entryPhase.invariantHolds
    rw [entryPhase.atLoop] at invariant
    simpa [initialRuntime, RunFunctionNativeRuntime.running] using invariant
  obtain ⟨loopResult⟩ := certificate.semantics.execute
    certificate.static.stepEntryExact derivation entryInvariant
  let epilogue := certificate.epilogue.epilogue environment resolveCodeTarget
    sourceRva logical result before related derivation entryPhase
    loopResult
  have entryPath := entryPhase.chunk.path
  rw [entryPhase.atLoop, entryPhase.silent] at entryPath
  have loopPath := loopResult.path
  change NonemptyRelatedPath candidate.transitionSystem
    (.running
      certificate.static.reflected.reflected.template.loopHeaderRva
      0 entryPhase.loopState
      [runFunctionNativeOuterFrame continuationRva returnAddress]
      0 [] world) loopResult.observations loopResult.afterLoop at loopPath
  have epiloguePath := epilogue.chunk.path
  rw [epilogue.atCaller, epilogue.silent] at epiloguePath
  have completePath := (entryPath.trans loopPath).trans epiloguePath
  refine ⟨certificate.static.function.span.start, epilogue.after,
    epilogue.nativeEvents, certificate.static.entryRvaExact, ?_,
    epilogue.responseRelated, epilogue.memoryFrame⟩
  refine ⟨{
    afterWorld := epilogue.afterWorld
    observations := loopResult.observations
    path := ?_
  }⟩
  rw [← certificate.static.templateEntryExact]
  simpa only [List.nil_append, List.append_nil] using completePath

/-- Exact checked Run certificates at the two native continuation frames
encoded by the reflected Invoke wrapper. -/
structure InvokeCallNativeCheckedRunFunctionRefinements
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (internal : InvokeCallNativeInternalBranchAuthority program abi
      semanticRecords candidate world static)
    (indirect : InvokeCallNativeIndirectBranchAuthority program abi
      semanticRecords candidate world static) where
  internalRun : RunFunctionNativeCheckedOperationCertificate program abi
    semanticRecords candidate world internal.continuationRva
    internal.returnAddress
  indirectRun : RunFunctionNativeCheckedOperationCertificate program abi
    semanticRecords candidate world indirect.continuationRva
    (BitVec.ofNat 32
      (candidate.pe.imageBase + indirect.continuationRva))

/-- One exact internal Invoke arm and the nested Run certificate selected for
its computed call frame. -/
structure InvokeCallNativeCheckedInternalFrame
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (invokeEntryRva continuationRva : Nat) (returnAddress : Word)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (invokeBefore : MachineState)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse) where
  runABI : KernelABIRelation
  prepared : InvokeCallNativeInternalPrepared program operationABI runABI
    semanticRecords candidate world invokeEntryRva continuationRva returnAddress
    environment resolveCodeTarget sourceRva logical result invokeBefore request
    response
  runCertificate : RunFunctionNativeCheckedOperationCertificate program runABI
    semanticRecords candidate world continuationRva returnAddress

structure InvokeCallNativeCheckedInternalBranchAuthority
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  continuationRva : Nat
  continuationExact :
    continuationRva = static.reflected.template.entryRva + 67
  returnAddress : Word
  returnAddressExact :
    returnAddress =
      BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)
  prepare : forall environment resolveCodeTarget event logical before result
      (run : CheckedRunFunctionDerivation semanticRecords environment
        resolveCodeTarget event.targetRva.toNat logical result),
    operationABI.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .internal ->
    Nonempty (InvokeCallNativeCheckedInternalFrame program operationABI
      semanticRecords candidate world static.function.span.start continuationRva
      returnAddress environment resolveCodeTarget event.targetRva.toNat logical
      result before
      (.invokeCall semanticRecords environment resolveCodeTarget event logical)
      (.call result))

/-- One exact indirect Invoke arm, including callback preparation and the
nested Run certificate at the resolved target. -/
structure InvokeCallNativeCheckedIndirectFrame
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (continuationRva targetRva : Nat)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine)
    (result : CallResult) (invokeBefore : MachineState)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse) where
  runABI : KernelABIRelation
  prepared : InvokeCallNativeIndirectPrepared program
    static.reflected.callbacks operationABI runABI semanticRecords candidate
    world static.function.span.start continuationRva targetRva environment
    resolveCodeTarget logical result invokeBefore request response
  runCertificate : RunFunctionNativeCheckedOperationCertificate program runABI
    semanticRecords candidate world continuationRva
    (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))

structure InvokeCallNativeCheckedIndirectBranchAuthority
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate) where
  continuationRva : Nat
  continuationExact :
    continuationRva = static.reflected.template.entryRva + 162
  prepare : forall environment resolveCodeTarget event logical before target
      result
      (run : CheckedRunFunctionDerivation semanticRecords environment
        resolveCodeTarget target logical result),
    operationABI.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
    event.kind = .indirect ->
    resolveCodeTarget event.targetRva = some target ->
    Nonempty (InvokeCallNativeCheckedIndirectFrame program operationABI
      semanticRecords candidate world static continuationRva target environment
      resolveCodeTarget logical result before
      (.invokeCall semanticRecords environment resolveCodeTarget event logical)
      (.call result))

/-- Invoke operation assembled from one finite checked Invoke tree.  Internal
and indirect arms execute the exact nested Run derivation stored in that tree;
the external constructor's result remains definitionally
`environment.invokeCall event logical`. -/
structure InvokeCallNativeCheckedOperationCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) where
  static : InvokeCallNativeStaticBinding program candidate
  abiEntry : InvokeCallNativeABIEntryAuthority abi semanticRecords
  closedTree : InvokeCallClosedCallTreeAuthority semanticRecords
  external : InvokeCallNativeExternalBranchAuthority program abi semanticRecords
    candidate world static
  internal : InvokeCallNativeCheckedInternalBranchAuthority program abi
    semanticRecords candidate world static
  indirect : InvokeCallNativeCheckedIndirectBranchAuthority program abi
    semanticRecords candidate world static

/-- Request-local native refinement for one retained checked Invoke tree. -/
theorem InvokeCallNativeCheckedOperationCertificate.refinesDerivation
    (certificate : InvokeCallNativeCheckedOperationCertificate program abi
      semanticRecords candidate world)
    (derivation : CheckedInvokeCallDerivation semanticRecords environment
      resolveCodeTarget event logical result) :
    ∀ before,
      abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before ->
      ∃ entryRva after nativeEvents,
        program.functionEntry? .invokeCall = some entryRva ∧
        NativeWorldKernelDispatches candidate world entryRva before after
          nativeEvents ∧
        abi.responseRelated
          (.invokeCall semanticRecords environment resolveCodeTarget event logical)
          (.call result) after nativeEvents ∧
        MemoryAgreesOutside
          (abi.scratchFootprint
            (.invokeCall semanticRecords environment resolveCodeTarget event
              logical))
          after.memory before.memory := by
  intro before related
  cases derivation with
  | external event logical kindExact =>
      obtain ⟨branch⟩ := certificate.external.execute environment
        resolveCodeTarget event logical before related kindExact
      exact ⟨certificate.static.function.span.start, branch.after,
        branch.nativeEvents, certificate.static.entryRvaExact, branch.path,
        branch.responseRelated, branch.memoryFrame⟩
  | internal event logical result kindExact run =>
      obtain ⟨frame⟩ := certificate.internal.prepare environment
        resolveCodeTarget event logical before result run related kindExact
      obtain ⟨entryRva, after, events, entryExact, ⟨subroutine⟩, _, _⟩ :=
        runFunctionSubroutine_of_checked_derivation
          frame.runCertificate run frame.prepared.requestRelated
      obtain ⟨completion⟩ :=
        frame.prepared.assemble entryRva after events entryExact subroutine
      exact ⟨certificate.static.function.span.start, completion.after, events,
        certificate.static.entryRvaExact, completion.execution.kernelDispatches,
        completion.responseRelated, completion.memoryFrame⟩
  | indirect event logical target result kindExact targetExact run =>
      obtain ⟨frame⟩ := certificate.indirect.prepare environment
        resolveCodeTarget event logical before target result run related kindExact
        targetExact
      obtain ⟨entryRva, after, events, entryExact, ⟨subroutine⟩, _, _⟩ :=
        runFunctionSubroutine_of_checked_derivation
          frame.runCertificate run frame.prepared.requestRelated
      obtain ⟨completion⟩ :=
        frame.prepared.assemble entryRva after events entryExact subroutine
      exact ⟨certificate.static.function.span.start, completion.after, events,
        certificate.static.entryRvaExact, completion.execution.kernelDispatches,
        completion.responseRelated, completion.memoryFrame⟩

/-- Compatibility with the existing whole-operation interface.  The only
universal premise is structural closure into checked Invoke trees; native Run
execution is selected request by request from each tree. -/
theorem InvokeCallNativeCheckedOperationCertificate.refines
    (certificate : InvokeCallNativeCheckedOperationCertificate program abi
      semanticRecords candidate world) :
    KernelOperationRefinesUsing program abi
      (NativeWorldKernelDispatches candidate world) .invokeCall := by
  intro request before operationMatches related response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      have recordsExact := certificate.abiEntry.recordsExact records environment
        resolveCodeTarget event logical before related
      subst records
      obtain ⟨result, responseExact, checked⟩ :=
        certificate.closedTree.close environment resolveCodeTarget event logical
          response transition
      subst response
      exact certificate.refinesDerivation checked before related

#print axioms concreteInvokeCallABIEntryAuthority
#print axioms InvokeCallNativeExternalHelperArmExecution.nativeWorldDispatches
#print axioms InvokeCallNativeExternalHelperArmExecution.kernelDispatches
#print axioms InvokeCallNativeExternalBranchAuthority.execute
#print axioms InvokeCallNativeInternalCompletion.toBranchResult
#print axioms InvokeCallNativeIndirectCompletion.toBranchResult
#print axioms InvokeCallNativeRunFunctionRefinements.internalForAuthority
#print axioms InvokeCallNativeRunFunctionRefinements.indirectForAuthority
#print axioms InvokeCallNativeOperationCertificate.branches
#print axioms InvokeCallNativeOperationCertificate.refines
#print axioms runFunctionSubroutine_of_checked_derivation
#print axioms InvokeCallNativeCheckedOperationCertificate.refinesDerivation
#print axioms InvokeCallNativeCheckedOperationCertificate.refines

end StageA.Relational.InterpreterKernelInvokeOperation
