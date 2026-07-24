import StageA.RelationalInterpreterKernelStepProgramLookupCallClosure

namespace StageA.Relational.InterpreterKernelStepProgramLookupExactComputation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact executor replay for the Step to ProgramLookup call

This layer turns equations about the checked candidate executor into the
existing Step/ProgramLookup closure objects.  Fuel selects a finite
computation; paths, observations, and endpoints are always projections of
`runRelatedSteps`.

The remaining equations are intentionally propositions over the exact
executor.  They cannot in general be decided from bytes alone because the
initial memory and a nested operation result are symbolic.  ABI entry facts and
the operation-selected response remain separate premises.
-/

/-- A finite replay whose complete result is fixed by the exact candidate
transition system.  No endpoint, observation list, or path is stored. -/
structure ExactNativeWorldReplay
    (candidate : ExactNativeWorldProgram) (before : NativeWorldExecution) where
  fuel : Nat
  positive : 0 < fuel

def ExactNativeWorldReplay.segment
    (replay : ExactNativeWorldReplay candidate before) :
    ExactComputedNativeWorldSegment candidate before := {
  fuel := replay.fuel
  positive := replay.positive
}

def ExactNativeWorldReplay.after
    (replay : ExactNativeWorldReplay candidate before) :
    NativeWorldExecution :=
  (runRelatedSteps candidate.transitionSystem replay.fuel before).1

def ExactNativeWorldReplay.observations
    (replay : ExactNativeWorldReplay candidate before) :
    List WorldRelationalObservable :=
  (runRelatedSteps candidate.transitionSystem replay.fuel before).2

theorem ExactNativeWorldReplay.segmentAfter
    (replay : ExactNativeWorldReplay candidate before) :
    replay.segment.after = replay.after := rfl

theorem ExactNativeWorldReplay.segmentObservations
    (replay : ExactNativeWorldReplay candidate before) :
    replay.segment.observations = replay.observations := rfl

/-- A helper endpoint is not submitted as a path.  The exact executor computes
it, while the two RVAs remain constrained by the checked Step template. -/
structure ExactInterpreterStepHelperReplay
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (targetRva continuationRva : Nat) (before : NativeWorldExecution) where
  boundaryAllowed :
    template.subroutineBoundaryAllowed targetRva continuationRva
  continuationAllowed : continuationRva ∈ template.cutpointRvas
  startsAt : before.rva? = some targetRva
  replay : ExactNativeWorldReplay candidate before
  undefinedSlot : Nat
  state : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  observations : List WorldRelationalObservable
  executorExact :
    runRelatedSteps candidate.transitionSystem replay.fuel before =
      (.running continuationRva undefinedSlot state calls eventIndex events world,
        observations)

theorem ExactInterpreterStepHelperReplay.endpointExact
    (replay : ExactInterpreterStepHelperReplay template candidate targetRva
      continuationRva before) :
    replay.replay.after.rva? = some continuationRva := by
  have afterExact :
      replay.replay.after =
        .running continuationRva replay.undefinedSlot replay.state replay.calls
          replay.eventIndex replay.events replay.world :=
    congrArg Prod.fst replay.executorExact
  rw [afterExact]
  rfl

theorem ExactInterpreterStepHelperReplay.observationsExact
    (replay : ExactInterpreterStepHelperReplay template candidate targetRva
      continuationRva before) :
    replay.replay.observations = replay.observations := by
  exact congrArg Prod.snd replay.executorExact

def ExactInterpreterStepHelperReplay.toSubroutine
    (replay : ExactInterpreterStepHelperReplay template candidate targetRva
      continuationRva before) :
    ExactComputedInterpreterStepSubroutine template candidate before := {
  targetRva
  continuationRva
  boundaryAllowed := replay.boundaryAllowed
  continuationAllowed := replay.continuationAllowed
  startsAt := replay.startsAt
  segment := replay.replay.segment
  finishesAt := by
    rw [replay.replay.segmentAfter]
    exact replay.endpointExact
}

def ExactInterpreterStepHelperReplay.toPath
    (replay : ExactInterpreterStepHelperReplay template candidate targetRva
      continuationRva before) :
    ExactComputedInterpreterStepPath template candidate before
      replay.replay.observations replay.replay.after := by
  change ExactComputedInterpreterStepPath template candidate before
    replay.replay.segment.observations replay.replay.segment.after
  exact ExactComputedInterpreterStepPath.subroutine replay.toSubroutine

/-- Static call-chunk facts plus one exact executor equation.  The chunk fuel
is the checked block instruction count; neither fuel nor the nested endpoint is
accepted from generated metadata. -/
structure ExactInterpreterStepProgramLookupCallReplay
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (world : RelationalWorld) (callBefore : NativeWorldExecution) where
  cutpoint : InterpreterStepNativeCutpoint
  cutpointMember : cutpoint ∈ static.reflected.template.cutpoints
  startsAt : callBefore.rva? = some cutpoint.entryRva
  positive : 0 < cutpoint.instructionCount
  effectExact : cutpoint.effect = .programLookupCall
  destinationAllowed : site.parameters.targetRva ∈ cutpoint.allowedRvas
  lookupBefore : MachineState
  observations : List WorldRelationalObservable
  executorExact :
    runRelatedSteps candidate.transitionSystem cutpoint.instructionCount
        callBefore =
      (.running site.parameters.targetRva 0 lookupBefore
        [{
          continuationRva := site.parameters.continuationRva
          returnAddress := site.parameters.returnAddress candidate.pe
        }] 0 [] world, observations)

def ExactInterpreterStepProgramLookupCallReplay.chunk
    (replay : ExactInterpreterStepProgramLookupCallReplay program candidate
      static site world callBefore) :
    InterpreterStepNativeChunk static.reflected.template candidate callBefore := {
  cutpoint := replay.cutpoint
  cutpointMember := replay.cutpointMember
  startsAt := replay.startsAt
  positive := replay.positive
}

theorem ExactInterpreterStepProgramLookupCallReplay.chunkAfter
    (replay : ExactInterpreterStepProgramLookupCallReplay program candidate
      static site world callBefore) :
    replay.chunk.after =
      .running site.parameters.targetRva 0 replay.lookupBefore
        [{
          continuationRva := site.parameters.continuationRva
          returnAddress := site.parameters.returnAddress candidate.pe
        }] 0 [] world := by
  exact congrArg Prod.fst replay.executorExact

theorem ExactInterpreterStepProgramLookupCallReplay.chunkObservations
    (replay : ExactInterpreterStepProgramLookupCallReplay program candidate
      static site world callBefore) :
    replay.chunk.observations = replay.observations := by
  exact congrArg Prod.snd replay.executorExact

def ExactInterpreterStepProgramLookupCallReplay.toCallChunk
    (replay : ExactInterpreterStepProgramLookupCallReplay program candidate
      static site world callBefore) :
    ExactComputedInterpreterStepProgramLookupCallChunk program candidate static
      site world callBefore := {
  lookupBefore := replay.lookupBefore
  chunk := replay.chunk
  effectExact := replay.effectExact
  frameExact := replay.chunkAfter
  destinationAllowed := replay.destinationAllowed
}

/-- Return fuel is a constructive witness.  The returned endpoint and
observations are checked against the exact executor result selected by that
fuel.  `lookupAfter` and `nativeEvents` are parameters supplied by the already
proved ProgramLookup operation, not generated guesses. -/
structure ExactInterpreterStepProgramLookupReturnReplay
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (continuationRva : Nat) (lookupAfter : MachineState)
    (nativeEvents : List NativeExternalEvent)
    (before : NativeWorldExecution) where
  replay : ExactNativeWorldReplay candidate before
  observations : List WorldRelationalObservable
  executorExact :
    runRelatedSteps candidate.transitionSystem replay.fuel before =
      (.running continuationRva 0 lookupAfter [] nativeEvents.length nativeEvents
        world, observations)

theorem ExactInterpreterStepProgramLookupReturnReplay.afterExact
    (replay : ExactInterpreterStepProgramLookupReturnReplay candidate world
      continuationRva lookupAfter nativeEvents before) :
    replay.replay.after =
      .running continuationRva 0 lookupAfter [] nativeEvents.length nativeEvents
        world := by
  exact congrArg Prod.fst replay.executorExact

theorem ExactInterpreterStepProgramLookupReturnReplay.observationsExact
    (replay : ExactInterpreterStepProgramLookupReturnReplay candidate world
      continuationRva lookupAfter nativeEvents before) :
    replay.replay.observations = replay.observations := by
  exact congrArg Prod.snd replay.executorExact

def ExactInterpreterStepProgramLookupReturnReplay.toReturn
    (replay : ExactInterpreterStepProgramLookupReturnReplay candidate world
      continuationRva lookupAfter nativeEvents before) :
    ExactComputedInterpreterStepProgramLookupReturn candidate world
      continuationRva lookupAfter nativeEvents before := {
  segment := replay.replay.segment
  returnedAtContinuation := by
    rw [replay.replay.segmentAfter]
    exact replay.afterExact
}

/-- The constructive caller closure.  Exact prefix leaves and helper endpoints
must be built with the checked path language above.  The nested cdecl/image
facts and operation-dependent replay are explicit and universally quantified. -/
structure ExecutorClosedInterpreterStepProgramLookupCallerFrame
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState) where
  callBefore : NativeWorldExecution
  prefixObservations : List WorldRelationalObservable
  prefixExecution :
    ExactComputedInterpreterStepPath static.reflected.template candidate
      (.running static.reflected.template.machine.entryRva 0 stepBefore [] 0 []
        world)
      prefixObservations callBefore
  call :
    ExactInterpreterStepProgramLookupCallReplay program candidate static site
      world callBefore
  nestedRequest :
    ConcreteProgramLookupNestedRequestFacts semanticRecords abi sourceRva
      call.lookupBefore
  returnReplay : forall lookupAfter nativeEvents,
    NativeDispatches candidate.pe candidate.imports
        eventIdentityNativeEnvironment site.parameters.targetRva
        call.lookupBefore lookupAfter nativeEvents ->
      abi.relation.responseRelated (.programLookup semanticRecords sourceRva)
        (.programLookup (lookupProgramRecord semanticRecords sourceRva))
        lookupAfter nativeEvents ->
      MemoryAgreesOutside
        (abi.relation.scratchFootprint
          (.programLookup semanticRecords sourceRva))
        lookupAfter.memory call.lookupBefore.memory ->
      ExactInterpreterStepProgramLookupReturnReplay candidate world
        site.parameters.continuationRva lookupAfter nativeEvents
        call.chunk.after

def ExecutorClosedInterpreterStepProgramLookupCallerFrame.toClosed
    (closed : ExecutorClosedInterpreterStepProgramLookupCallerFrame program
      semanticRecords abi candidate world static site sourceRva stepBefore) :
    SymbolicallyClosedInterpreterStepProgramLookupCallerFrame program
      semanticRecords abi candidate world static site sourceRva stepBefore := {
  execution := {
    callBefore := closed.callBefore
    prefixObservations := closed.prefixObservations
    prefixExecution := closed.prefixExecution
    callExecution := closed.call.toCallChunk
  }
  nestedRequest := closed.nestedRequest
  replay := by
    intro lookupAfter nativeEvents dispatch response memoryFrame
    exact (closed.returnReplay lookupAfter nativeEvents dispatch response
      memoryFrame).toReturn
}

#print axioms ExactNativeWorldReplay.segmentAfter
#print axioms ExactInterpreterStepHelperReplay.endpointExact
#print axioms ExactInterpreterStepHelperReplay.toSubroutine
#print axioms ExactInterpreterStepProgramLookupCallReplay.chunkAfter
#print axioms ExactInterpreterStepProgramLookupReturnReplay.toReturn
#print axioms ExecutorClosedInterpreterStepProgramLookupCallerFrame.toClosed

end StageA.Relational.InterpreterKernelStepProgramLookupExactComputation
