import StageA.RelationalInterpreterKernelStepOperation

namespace StageA.Relational.InterpreterKernelStepProgramLookupCall

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked `interpreterStep` to `programLookup` call composition

This module closes the generic internal-call gap left by the Step operation
surface.  Static evidence is a finite check over the exact decoded Step
instruction inventory and reflected direct-call table.  Dynamic evidence is
restricted to the exact caller prefix, installed native frame, callee ABI
request, and a return path whose dispatch, response, and memory-frame
arguments are the values produced by the closed `programLookup` theorem.

There is no status field, submitted callee result, or whole-Step path.
-/

def ExactDecodedInterpreterStepInternalCall
    (pe : PE32) (function : KernelFunction)
    (callSiteRva targetRva continuationRva : Nat) : Prop :=
  Exists fun instruction : KernelInstruction =>
    instruction ∈ function.instructions ∧
      instruction.rva = callSiteRva ∧
      Exists fun decoded : DecodedInstruction =>
        instruction.decode? pe = some decoded ∧
          Exists fun displacement : Nat =>
            decoded.instruction = .callRel32 displacement ∧
              relativeTarget32 (instruction.rva + decoded.size) displacement =
                targetRva ∧
              instruction.rva + decoded.size = continuationRva

def decodedInterpreterStepInternalCallChecked
    (pe : PE32) (function : KernelFunction)
    (callSiteRva targetRva continuationRva : Nat) : Bool :=
  function.instructions.any fun instruction =>
    instruction.rva == callSiteRva &&
      match instruction.decode? pe with
      | some decoded =>
          match decoded.instruction with
          | .callRel32 displacement =>
              relativeTarget32 (instruction.rva + decoded.size) displacement ==
                  targetRva &&
                instruction.rva + decoded.size == continuationRva
          | _ => false
      | none => false

theorem decodedInterpreterStepInternalCallChecked_sound
    (checked : decodedInterpreterStepInternalCallChecked pe function
      callSiteRva targetRva continuationRva = true) :
    ExactDecodedInterpreterStepInternalCall pe function callSiteRva targetRva
      continuationRva := by
  simp only [decodedInterpreterStepInternalCallChecked, List.any_eq_true] at checked
  obtain ⟨instruction, instructionMember, checked⟩ := checked
  simp only [Bool.and_eq_true, beq_iff_eq] at checked
  rcases checked with ⟨callSiteExact, checked⟩
  cases decodedExact : instruction.decode? pe with
  | none => simp [decodedExact] at checked
  | some decoded =>
      cases instructionExact : decoded.instruction <;>
        simp [decodedExact, instructionExact, Bool.and_eq_true, beq_iff_eq] at checked
      case callRel32 displacement =>
        exact ⟨instruction, instructionMember, callSiteExact, decoded,
          decodedExact, displacement, instructionExact, checked.1, checked.2⟩

structure InterpreterStepProgramLookupCallSiteParameters where
  callSiteRva : Nat
  targetRva : Nat
  continuationRva : Nat
deriving Repr, DecidableEq

def InterpreterStepProgramLookupCallSiteParameters.returnAddress
    (parameters : InterpreterStepProgramLookupCallSiteParameters)
    (pe : PE32) : Word :=
  BitVec.ofNat 32 (pe.imageBase + parameters.continuationRva)

def InterpreterStepProgramLookupCallSiteParameters.checked
    (parameters : InterpreterStepProgramLookupCallSiteParameters)
    (program : CompiledKernelProgram) (pe : PE32)
    (function : KernelFunction) (template : InterpreterStepNativeTemplate) : Bool :=
  parameters.callSiteRva ==
      template.machine.entryRva + template.programLookupCallOffset &&
    (decodedInterpreterStepInternalCallChecked pe function parameters.callSiteRva
        parameters.targetRva parameters.continuationRva &&
      ((program.functionEntry? .programLookup == some parameters.targetRva) &&
        ((template.directCalls.any fun call =>
            call.offset == template.programLookupCallOffset &&
              (call.targetRva == parameters.targetRva &&
                template.machine.entryRva + call.continuationOffset ==
                  parameters.continuationRva)) &&
          template.cutpointRvas.contains parameters.continuationRva)))

structure InterpreterStepProgramLookupCallSiteCertificate
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate) where
  parameters : InterpreterStepProgramLookupCallSiteParameters
  checked : parameters.checked program candidate.pe static.function
    static.reflected.template = true

theorem InterpreterStepProgramLookupCallSiteCertificate.decoded
    (certificate : InterpreterStepProgramLookupCallSiteCertificate program
      candidate static) :
    ExactDecodedInterpreterStepInternalCall candidate.pe static.function
      certificate.parameters.callSiteRva certificate.parameters.targetRva
      certificate.parameters.continuationRva := by
  have facts := certificate.checked
  simp only [InterpreterStepProgramLookupCallSiteParameters.checked,
    Bool.and_eq_true, beq_iff_eq] at facts
  exact decodedInterpreterStepInternalCallChecked_sound facts.2.1

theorem InterpreterStepProgramLookupCallSiteCertificate.callSiteExact
    (certificate : InterpreterStepProgramLookupCallSiteCertificate program
      candidate static) :
    certificate.parameters.callSiteRva =
      static.reflected.template.machine.entryRva +
        static.reflected.template.programLookupCallOffset := by
  have facts := certificate.checked
  simp only [InterpreterStepProgramLookupCallSiteParameters.checked,
    Bool.and_eq_true, beq_iff_eq] at facts
  exact facts.1

theorem InterpreterStepProgramLookupCallSiteCertificate.entryExact
    (certificate : InterpreterStepProgramLookupCallSiteCertificate program
      candidate static) :
    program.functionEntry? .programLookup =
      some certificate.parameters.targetRva := by
  have facts := certificate.checked
  simp only [InterpreterStepProgramLookupCallSiteParameters.checked,
    Bool.and_eq_true, beq_iff_eq] at facts
  exact facts.2.2.1

theorem InterpreterStepProgramLookupCallSiteCertificate.boundaryAllowed
    (certificate : InterpreterStepProgramLookupCallSiteCertificate program
      candidate static) :
    static.reflected.template.subroutineBoundaryAllowed
      certificate.parameters.targetRva
      certificate.parameters.continuationRva := by
  have facts := certificate.checked
  simp only [InterpreterStepProgramLookupCallSiteParameters.checked,
    Bool.and_eq_true, beq_iff_eq, List.any_eq_true] at facts
  obtain ⟨call, callMember, _, targetExact, continuationExact⟩ :=
    facts.2.2.2.1
  exact Or.inl ⟨call, callMember, targetExact, continuationExact⟩

theorem InterpreterStepProgramLookupCallSiteCertificate.continuationAllowed
    (certificate : InterpreterStepProgramLookupCallSiteCertificate program
      candidate static) :
    certificate.parameters.continuationRva ∈
      static.reflected.template.cutpointRvas := by
  have facts := certificate.checked
  simp only [InterpreterStepProgramLookupCallSiteParameters.checked,
    Bool.and_eq_true, beq_iff_eq] at facts
  exact List.contains_iff_mem.mp facts.2.2.2.2

structure InterpreterStepNativeProgramLookupReturnPath
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (continuationRva : Nat) (lookupAfter : MachineState)
    (nativeEvents : List NativeExternalEvent)
    (before : NativeWorldExecution) where
  observations : List WorldRelationalObservable
  path : NonemptyRelatedPath candidate.transitionSystem before observations
    (.running continuationRva 0 lookupAfter [] nativeEvents.length nativeEvents
      world)

/-- Runtime evidence before and after one exact checked nested call.  The
`resume` function receives the dispatch, response, and memory frame selected
by the closed operation theorem, so it cannot substitute another callee
result. -/
structure InterpreterStepNativeProgramLookupCallerFrame
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState) where
  lookupBefore : MachineState
  callBefore : NativeWorldExecution
  prefixObservations : List WorldRelationalObservable
  prefixPath : InterpreterStepNativePath static.reflected.template candidate
    (.running static.reflected.template.machine.entryRva 0 stepBefore [] 0 []
      world)
    prefixObservations callBefore
  callChunk : InterpreterStepNativeChunk static.reflected.template candidate
    callBefore
  callChunkEffect : callChunk.cutpoint.effect = .programLookupCall
  callFrameExact : callChunk.after =
    .running site.parameters.targetRva 0 lookupBefore
      [{
        continuationRva := site.parameters.continuationRva
        returnAddress := site.parameters.returnAddress candidate.pe
      }] 0 [] world
  callDestinationAllowed :
    site.parameters.targetRva ∈ callChunk.cutpoint.allowedRvas
  requestRelated :
    abi.requestRelated (.programLookup semanticRecords sourceRva) lookupBefore
  resume : forall lookupAfter nativeEvents,
    NativeDispatches candidate.pe candidate.imports
        eventIdentityNativeEnvironment site.parameters.targetRva lookupBefore
        lookupAfter nativeEvents ->
      abi.responseRelated (.programLookup semanticRecords sourceRva)
        (.programLookup (lookupProgramRecord semanticRecords sourceRva))
        lookupAfter nativeEvents ->
      MemoryAgreesOutside
        (abi.scratchFootprint (.programLookup semanticRecords sourceRva))
        lookupAfter.memory lookupBefore.memory ->
      InterpreterStepNativeProgramLookupReturnPath candidate world
        site.parameters.continuationRva lookupAfter nativeEvents callChunk.after

def InterpreterStepNativeProgramLookupCallerFrame.lookupPhase
    (frame : InterpreterStepNativeProgramLookupCallerFrame program abi
      semanticRecords candidate world static site sourceRva stepBefore)
    {lookupAfter : MachineState} {nativeEvents : List NativeExternalEvent}
    (dispatch : NativeDispatches candidate.pe candidate.imports
      eventIdentityNativeEnvironment site.parameters.targetRva frame.lookupBefore
      lookupAfter nativeEvents)
    (response : abi.responseRelated (.programLookup semanticRecords sourceRva)
      (.programLookup (lookupProgramRecord semanticRecords sourceRva))
      lookupAfter nativeEvents)
    (memoryFrame : MemoryAgreesOutside
      (abi.scratchFootprint (.programLookup semanticRecords sourceRva))
      lookupAfter.memory frame.lookupBefore.memory) :
    InterpreterStepNativeLookupPhase static.reflected.template candidate
      semanticRecords sourceRva stepBefore world := by
  let resumed := frame.resume lookupAfter nativeEvents dispatch response memoryFrame
  let returned : NativeWorldExecution :=
    .running site.parameters.continuationRva 0 lookupAfter []
      nativeEvents.length nativeEvents world
  have chunkDestination : frame.callChunk.destinationChecked := by
    simp only [InterpreterStepNativeChunk.destinationChecked,
      frame.callFrameExact, NativeWorldExecution.rva?]
    exact frame.callDestinationAllowed
  have chunkPath : InterpreterStepNativePath static.reflected.template candidate
      frame.callBefore frame.callChunk.observations frame.callChunk.after :=
    .chunk frame.callChunk chunkDestination
  have nested : InterpreterStepNativeLocalSubroutine
      static.reflected.template candidate frame.callChunk.after returned
      resumed.observations := {
    targetRva := site.parameters.targetRva
    continuationRva := site.parameters.continuationRva
    boundaryAllowed := site.boundaryAllowed
    continuationAllowed := site.continuationAllowed
    startsAt := by
      rw [frame.callFrameExact]
      rfl
    finishesAt := by
      rfl
    path := by simpa [returned] using resumed.path
  }
  exact {
    record := lookupProgramRecord semanticRecords sourceRva
    afterLookup := returned
    observations :=
      frame.prefixObservations ++
        (frame.callChunk.observations ++ resumed.observations)
    path := frame.prefixPath.trans (chunkPath.trans (.subroutine nested))
    recordExact := rfl
  }

def InterpreterStepNativeProgramLookupCallerFrame.prepared
    (frame : InterpreterStepNativeProgramLookupCallerFrame program abi
      semanticRecords candidate world static site sourceRva stepBefore) :
    InterpreterStepNativeProgramLookupPrepared program abi semanticRecords
      candidate world static sourceRva stepBefore := {
  lookupBefore := frame.lookupBefore
  requestRelated := frame.requestRelated
  finish := by
    intro entryRva lookupAfter nativeEvents entryExact dispatch response memoryFrame
    have targetExact : entryRva = site.parameters.targetRva := by
      rw [site.entryExact] at entryExact
      exact (Option.some.inj entryExact).symm
    subst entryRva
    exact frame.lookupPhase dispatch response memoryFrame
}

/-- The remaining dynamic family.  It cannot contain the ProgramLookup
operation result: that result is supplied only after this structure has
produced the exact caller frame. -/
structure InterpreterStepNativeProgramLookupCallComposition
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static) where
  callerFrame : forall environment sourceRva logical before,
    abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      InterpreterStepNativeProgramLookupCallerFrame program abi semanticRecords
        candidate world static site sourceRva before

def InterpreterStepNativeProgramLookupCallComposition.toAuthority
    (composition : InterpreterStepNativeProgramLookupCallComposition program abi
      semanticRecords candidate world static site)
    (operation : InterpreterStepProgramLookupOperation program abi candidate) :
    InterpreterStepNativeProgramLookupCallAuthority program abi semanticRecords
      candidate world static operation := {
  prepare := by
    intro environment sourceRva logical before related
    exact (composition.callerFrame environment sourceRva logical before
      related).prepared
}

/-- Direct closure theorem for the Step lookup phase.  The only callee
execution, response, and memory frame used here are chosen by `operation`. -/
noncomputable def InterpreterStepNativeProgramLookupCallComposition.lookup
    (composition : InterpreterStepNativeProgramLookupCallComposition program abi
      semanticRecords candidate world static site)
    (operation : InterpreterStepProgramLookupOperation program abi candidate)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (related : abi.requestRelated
      (.interpreterStep semanticRecords environment sourceRva logical) before) :
    InterpreterStepNativeLookupPhase static.reflected.template candidate
      semanticRecords sourceRva before world :=
  (composition.toAuthority operation).lookup environment sourceRva logical before
    related

#print axioms decodedInterpreterStepInternalCallChecked_sound
#print axioms InterpreterStepProgramLookupCallSiteCertificate.decoded
#print axioms InterpreterStepNativeProgramLookupCallerFrame.lookupPhase
#print axioms InterpreterStepNativeProgramLookupCallComposition.lookup

end StageA.Relational.InterpreterKernelStepProgramLookupCall
