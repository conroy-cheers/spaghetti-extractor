import StageA.RelationalInterpreterKernelInvokeNative
import StageA.RelationalInterpreterKernelStepProgramLookupCall

namespace StageA.Relational.InterpreterKernelStepProgramLookupCallClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact computed closure for the Step to ProgramLookup call

The checked call-site certificate identifies the exact direct call but leaves
three dynamic premises: the caller prefix and call chunk, the nested ABI
request, and the callee return path. This module narrows those premises to
exact transition computations and concrete ABI frame facts.

No path, nested request relation, or return endpoint can be submitted directly:

* local Step chunks are the fixed-fuel chunks from the checked template;
* subroutine pieces are projections of `runRelatedSteps`;
* the nested request is constructed from the concrete cdecl/image/table facts;
* the return path is projected from another exact `runRelatedSteps` segment.

Runtime endpoint equalities, image/table preservation, and the amount of fuel
needed by a data-dependent callee remain explicit proof obligations.
-/

/-- A checked local subroutine whose endpoint and observations are computed by
the exact native-world transition system. -/
structure ExactComputedInterpreterStepSubroutine
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (before : NativeWorldExecution) where
  targetRva : Nat
  continuationRva : Nat
  boundaryAllowed :
    template.subroutineBoundaryAllowed targetRva continuationRva
  continuationAllowed : continuationRva ∈ template.cutpointRvas
  startsAt : before.rva? = some targetRva
  segment : ExactComputedNativeWorldSegment candidate before
  finishesAt : segment.after.rva? = some continuationRva

def ExactComputedInterpreterStepSubroutine.toLocal
    (execution : ExactComputedInterpreterStepSubroutine template candidate
      before) :
    InterpreterStepNativeLocalSubroutine template candidate before
      execution.segment.after execution.segment.observations := {
  targetRva := execution.targetRva
  continuationRva := execution.continuationRva
  boundaryAllowed := execution.boundaryAllowed
  continuationAllowed := execution.continuationAllowed
  startsAt := execution.startsAt
  finishesAt := execution.finishesAt
  path := execution.segment.path
}

/-- A restricted path language whose only leaves are fixed-fuel Step chunks and
exactly computed, boundary-checked local subroutines. -/
inductive ExactComputedInterpreterStepPath
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram) :
    NativeWorldExecution -> List WorldRelationalObservable ->
      NativeWorldExecution -> Prop
  | chunk {before}
      (execution : InterpreterStepNativeChunk template candidate before)
      (destinationChecked : execution.destinationChecked) :
      ExactComputedInterpreterStepPath template candidate before
        execution.observations execution.after
  | subroutine {before}
      (execution : ExactComputedInterpreterStepSubroutine template candidate
        before) :
      ExactComputedInterpreterStepPath template candidate before
        execution.segment.observations execution.segment.after
  | trans {before middle after leftObservations rightObservations}
      (left : ExactComputedInterpreterStepPath template candidate before
        leftObservations middle)
      (right : ExactComputedInterpreterStepPath template candidate middle
        rightObservations after) :
      ExactComputedInterpreterStepPath template candidate before
        (leftObservations ++ rightObservations) after

theorem ExactComputedInterpreterStepPath.toNativePath
    (path : ExactComputedInterpreterStepPath template candidate before
      observations after) :
    InterpreterStepNativePath template candidate before observations after := by
  induction path with
  | chunk execution destinationChecked =>
      exact .chunk execution destinationChecked
  | subroutine execution =>
      exact .subroutine execution.toLocal
  | trans left right leftClosed rightClosed =>
      exact .trans leftClosed rightClosed

/-- The exact checked call block and the nested native frame it computes. The
machine state and endpoint are outputs of the exact fixed-fuel chunk. -/
structure ExactComputedInterpreterStepProgramLookupCallChunk
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (world : RelationalWorld) (callBefore : NativeWorldExecution) where
  lookupBefore : MachineState
  chunk : InterpreterStepNativeChunk static.reflected.template candidate
    callBefore
  effectExact : chunk.cutpoint.effect = .programLookupCall
  frameExact : chunk.after =
    .running site.parameters.targetRva 0 lookupBefore
      [{
        continuationRva := site.parameters.continuationRva
        returnAddress := site.parameters.returnAddress candidate.pe
      }] 0 [] world
  destinationAllowed : site.parameters.targetRva ∈ chunk.cutpoint.allowedRvas

theorem ExactComputedInterpreterStepProgramLookupCallChunk.destinationChecked
    (execution :
      ExactComputedInterpreterStepProgramLookupCallChunk program candidate
        static site world callBefore) :
    execution.chunk.destinationChecked := by
  simp only [InterpreterStepNativeChunk.destinationChecked,
    execution.frameExact, NativeWorldExecution.rva?]
  exact execution.destinationAllowed

/-- Exact computed execution from the Step entry through the checked call
instruction. The prefix may contain checked helper subroutines, but it cannot
contain a submitted whole-operation path. -/
structure ExactComputedInterpreterStepProgramLookupCallerPrefix
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (world : RelationalWorld) (stepBefore : MachineState) where
  callBefore : NativeWorldExecution
  prefixObservations : List WorldRelationalObservable
  prefixExecution :
    ExactComputedInterpreterStepPath static.reflected.template candidate
    (.running static.reflected.template.machine.entryRva 0 stepBefore [] 0 []
      world)
    prefixObservations callBefore
  callExecution :
    ExactComputedInterpreterStepProgramLookupCallChunk program candidate static
      site world callBefore

/-- Concrete machine-level facts sufficient to construct the nested
ProgramLookup request. The source offset bound follows from the outer Step
request in normal use, while the cdecl and memory-preservation facts are
checked at the exact state produced by the call chunk. -/
structure ConcreteProgramLookupNestedRequestFacts
    (records : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (lookupBefore : MachineState) : Prop where
  cdecl :
    CDeclEntryFrameHolds abi (.programLookup records sourceRva) lookupBefore
  candidateImage :
    LoadedCandidateImageMemory pe imports relocations lookupBefore.memory
  originalProgramTable : LoadedOriginalProgramTable abi lookupBefore.memory
  sourceFits : sourceRva < 2 ^ 32

def ConcreteProgramLookupNestedRequestFacts.toRequestRelated
    (facts : ConcreteProgramLookupNestedRequestFacts records abi sourceRva
      lookupBefore) :
    abi.relation.requestRelated (.programLookup records sourceRva)
      lookupBefore := {
  cdecl := facts.cdecl
  candidateImage := facts.candidateImage
  originalProgramTable := facts.originalProgramTable
  payload := ⟨rfl, facts.sourceFits⟩
}

/-- Return replay selected after the closed ProgramLookup operation has fixed
the callee result. Fuel is allowed to depend on that result, but the path and
endpoint are computed by the exact candidate transition system. -/
structure ExactComputedInterpreterStepProgramLookupReturn
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (continuationRva : Nat) (lookupAfter : MachineState)
    (nativeEvents : List NativeExternalEvent)
    (before : NativeWorldExecution) where
  segment : ExactComputedNativeWorldSegment candidate before
  returnedAtContinuation : segment.after =
    .running continuationRva 0 lookupAfter [] nativeEvents.length nativeEvents
      world

def ExactComputedInterpreterStepProgramLookupReturn.toReturnPath
    (execution : ExactComputedInterpreterStepProgramLookupReturn candidate world
      continuationRva lookupAfter nativeEvents before) :
    InterpreterStepNativeProgramLookupReturnPath candidate world continuationRva
      lookupAfter nativeEvents before := {
  observations := execution.segment.observations
  path := by
    have path := execution.segment.path
    rw [execution.returnedAtContinuation] at path
    exact path
}

/-- The original caller-frame premise reconstructed from exact computation and
concrete ABI facts. The closed ProgramLookup operation still selects
`lookupAfter`; the replay factory must execute to that exact selected state. -/
structure SymbolicallyClosedInterpreterStepProgramLookupCallerFrame
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState) where
  execution :
    ExactComputedInterpreterStepProgramLookupCallerPrefix program candidate
      static site world stepBefore
  nestedRequest :
    ConcreteProgramLookupNestedRequestFacts semanticRecords abi sourceRva
      execution.callExecution.lookupBefore
  replay : forall lookupAfter nativeEvents,
    NativeDispatches candidate.pe candidate.imports
        eventIdentityNativeEnvironment site.parameters.targetRva
        execution.callExecution.lookupBefore lookupAfter nativeEvents ->
      abi.relation.responseRelated (.programLookup semanticRecords sourceRva)
        (.programLookup (lookupProgramRecord semanticRecords sourceRva))
        lookupAfter nativeEvents ->
      MemoryAgreesOutside
        (abi.relation.scratchFootprint
          (.programLookup semanticRecords sourceRva))
        lookupAfter.memory execution.callExecution.lookupBefore.memory ->
      ExactComputedInterpreterStepProgramLookupReturn candidate world
        site.parameters.continuationRva lookupAfter nativeEvents
        execution.callExecution.chunk.after

def SymbolicallyClosedInterpreterStepProgramLookupCallerFrame.toCallerFrame
    (closed :
      SymbolicallyClosedInterpreterStepProgramLookupCallerFrame program
        semanticRecords abi candidate world static site sourceRva stepBefore) :
    InterpreterStepNativeProgramLookupCallerFrame program abi.relation
      semanticRecords candidate world static site sourceRva stepBefore := {
  lookupBefore := closed.execution.callExecution.lookupBefore
  callBefore := closed.execution.callBefore
  prefixObservations := closed.execution.prefixObservations
  prefixPath := closed.execution.prefixExecution.toNativePath
  callChunk := closed.execution.callExecution.chunk
  callChunkEffect := closed.execution.callExecution.effectExact
  callFrameExact := closed.execution.callExecution.frameExact
  callDestinationAllowed := closed.execution.callExecution.destinationAllowed
  requestRelated := closed.nestedRequest.toRequestRelated
  resume := by
    intro lookupAfter nativeEvents dispatch response memoryFrame
    exact (closed.replay lookupAfter nativeEvents dispatch response
      memoryFrame).toReturnPath
}

/-- Universal closure family used by the existing composition interface. -/
structure SymbolicallyClosedInterpreterStepProgramLookupCallComposition
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static) where
  caller : forall environment sourceRva logical before,
    abi.relation.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      SymbolicallyClosedInterpreterStepProgramLookupCallerFrame program
        semanticRecords abi candidate world static site sourceRva before

def SymbolicallyClosedInterpreterStepProgramLookupCallComposition.toComposition
    (closed :
      SymbolicallyClosedInterpreterStepProgramLookupCallComposition program
        semanticRecords abi candidate world static site) :
    InterpreterStepNativeProgramLookupCallComposition program abi.relation
      semanticRecords candidate world static site := {
  callerFrame := by
    intro environment sourceRva logical before related
    exact (closed.caller environment sourceRva logical before
      related).toCallerFrame
}

#print axioms ExactComputedInterpreterStepPath.toNativePath
#print axioms ConcreteProgramLookupNestedRequestFacts.toRequestRelated
#print axioms ExactComputedInterpreterStepProgramLookupReturn.toReturnPath
#print axioms SymbolicallyClosedInterpreterStepProgramLookupCallerFrame.toCallerFrame
#print axioms SymbolicallyClosedInterpreterStepProgramLookupCallComposition.toComposition

end StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
