import StageA.RelationalInterpreterKernelStep
import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelStepNative

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelStep
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SymbolicSoundness

/-!
Exact native-world bridge for the compiled `interpreterStep` operation.

Generated data identifies bytes, blocks, calls, and local cutpoints.  It cannot
submit an execution path, final state, or operation result.  A local block
chunk always executes exactly the number of instructions in its checked basic
block through `ExactNativeWorldProgram.transitionSystem`.  Calls that leave the
function are represented separately and must start and finish at checked
native call boundaries.
-/

inductive InterpreterStepNativeBlockEffect where
  | internal
  | loopHeader
  | loopLatch
  | directHelperCall
  | programLookupCall
  | invokeCallCall
  | indirectCallbackCall
  | return
deriving Repr, DecidableEq

structure InterpreterStepNativeDirectCall where
  offset : Nat
  targetRva : Nat
  continuationOffset : Nat
deriving Repr, DecidableEq

structure InterpreterStepNativeIndirectCall where
  offset : Nat
  continuationOffset : Nat
  targetRvas : List Nat
deriving Repr, DecidableEq

structure InterpreterStepNativeCutpoint where
  entryRva : Nat
  instructionCount : Nat
  effect : InterpreterStepNativeBlockEffect
  allowedRvas : List Nat
deriving Repr, DecidableEq

def decodedInterpreterStepDirectCalls (pe : PE32) (entryRva : Nat)
    (function : KernelFunction) : List InterpreterStepNativeDirectCall :=
  function.instructions.filterMap fun instruction =>
    match instruction.decode? pe with
    | some decoded =>
        match decoded.instruction with
        | .callRel32 displacement =>
            some {
              offset := instruction.rva - entryRva
              targetRva := relativeTarget32
                (instruction.rva + decoded.size) displacement
              continuationOffset := instruction.rva + decoded.size - entryRva
            }
        | _ => none
    | none => none

def relativeBlockContainsOffset (entryRva : Nat)
    (block : KernelBlock) (offset : Nat) : Bool :=
  block.instructions.any fun instruction => instruction.rva == entryRva + offset

def relativeBlockContainsAnyOffset (entryRva : Nat)
    (block : KernelBlock) (offsets : List Nat) : Bool :=
  offsets.any (relativeBlockContainsOffset entryRva block)

structure InterpreterStepNativeTemplate where
  machine : InterpreterStepMachineTemplate
  directCalls : List InterpreterStepNativeDirectCall
  indirectCalls : List InterpreterStepNativeIndirectCall
  programLookupCallOffset : Nat
  invokeCallOffset : Nat
  helperTargetRvas : List Nat
  cutpoints : List InterpreterStepNativeCutpoint
deriving Repr, DecidableEq

def InterpreterStepNativeTemplate.directCallOffsets
    (template : InterpreterStepNativeTemplate) : List Nat :=
  template.directCalls.map (fun call => call.offset)

def InterpreterStepNativeTemplate.localSubroutineTargets
    (template : InterpreterStepNativeTemplate) : List Nat :=
  template.helperTargetRvas ++ template.indirectCalls.flatMap
    (fun call => call.targetRvas)

def InterpreterStepNativeTemplate.cutpointRvas
    (template : InterpreterStepNativeTemplate) : List Nat :=
  template.cutpoints.map (fun cutpoint => cutpoint.entryRva)

def InterpreterStepNativeTemplate.blockEffect
    (template : InterpreterStepNativeTemplate) (function : KernelFunction)
    (block : KernelBlock) : InterpreterStepNativeBlockEffect :=
  if relativeBlockContainsOffset template.machine.entryRva block
      template.programLookupCallOffset then
    .programLookupCall
  else if relativeBlockContainsOffset template.machine.entryRva block
      template.invokeCallOffset then
    .invokeCallCall
  else if relativeBlockContainsAnyOffset template.machine.entryRva block
      (template.indirectCalls.map fun call => call.offset) then
    .indirectCallbackCall
  else if relativeBlockContainsAnyOffset template.machine.entryRva block
      template.directCallOffsets then
    .directHelperCall
  else if relativeBlockContainsAnyOffset template.machine.entryRva block
      template.machine.returnOffsets then
    .return
  else if function.loops.any (fun loop => loop.headerRva == block.entryRva) then
    .loopHeader
  else if function.loops.any (fun loop => loop.latchRva == block.entryRva) then
    .loopLatch
  else
    .internal

def InterpreterStepNativeTemplate.cutpointOfBlock
    (template : InterpreterStepNativeTemplate) (function : KernelFunction)
    (block : KernelBlock) : InterpreterStepNativeCutpoint :=
  let callbackTargets :=
    template.indirectCalls.filter
      (fun call => relativeBlockContainsOffset template.machine.entryRva block
        call.offset) |>.flatMap (fun call => call.targetRvas)
  {
    entryRva := block.entryRva
    instructionCount := block.instructions.length
    effect := template.blockEffect function block
    allowedRvas := block.successors ++ callbackTargets
  }

def InterpreterStepNativeTemplate.callAtTarget
    (template : InterpreterStepNativeTemplate) (offset targetRva : Nat) : Bool :=
  template.directCalls.any fun call =>
    call.offset == offset && call.targetRva == targetRva

def interpreterStepNativeCallbackSiteAt?
    (callbacks : KernelCallbackInventory) (rva : Nat) :
    Option KernelIndirectCallbackSite :=
  callbacks.sites.find? fun site => site.instruction.rva == rva

def InterpreterStepNativeIndirectCall.checked
    (call : InterpreterStepNativeIndirectCall) (entryRva : Nat)
    (callbacks : KernelCallbackInventory) : Bool :=
  (callbacks.sites.filter
      (fun site => site.instruction.rva == entryRva + call.offset)).length == 1 &&
    (match interpreterStepNativeCallbackSiteAt? callbacks
        (entryRva + call.offset) with
    | some site =>
        site.continuationRva == entryRva + call.continuationOffset &&
          call.targetRvas == site.targets.entries.map (fun target => target.entry.rva)
    | none => false)

def InterpreterStepNativeTemplate.subroutineBoundaryAllowed
    (template : InterpreterStepNativeTemplate) (targetRva continuationRva : Nat) :
    Prop :=
  (∃ call ∈ template.directCalls,
      call.targetRva = targetRva ∧
      template.machine.entryRva + call.continuationOffset = continuationRva) ∨
    (∃ call ∈ template.indirectCalls,
      targetRva ∈ call.targetRvas ∧
      template.machine.entryRva + call.continuationOffset = continuationRva)

def InterpreterStepNativeTemplate.checked
    (template : InterpreterStepNativeTemplate)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (callbacks : KernelCallbackInventory) (function : KernelFunction) : Bool :=
  template.machine.checked program pe imports function &&
    function.x87Commands.isEmpty &&
    decodedInterpreterStepDirectCalls pe template.machine.entryRva function ==
      template.directCalls &&
    template.directCallOffsets == template.machine.callOffsets.filter
      (fun offset => !template.machine.indirectCallOffsets.contains offset) &&
    template.indirectCalls.map (fun call => call.offset) ==
      template.machine.indirectCallOffsets &&
    template.cutpoints ==
      function.blocks.map (template.cutpointOfBlock function) &&
    template.cutpoints.all (fun cutpoint => 0 < cutpoint.instructionCount) &&
    template.helperTargetRvas.all (fun target =>
      program.functions.any fun candidate => candidate.span.start == target) &&
    callbacks.checked program pe imports &&
    template.indirectCalls.all (fun call =>
      call.checked template.machine.entryRva callbacks) &&
    template.indirectCalls.all (fun call => !call.targetRvas.isEmpty) &&
    (match program.functionEntry? .programLookup,
        program.functionEntry? .invokeCall with
    | some lookupRva, some invokeRva =>
        (template.directCalls.filter
            (fun call => call.offset == template.programLookupCallOffset &&
              call.targetRva == lookupRva)).length == 1 &&
          (template.directCalls.filter
            (fun call => call.offset == template.invokeCallOffset &&
              call.targetRva == invokeRva)).length == 1 &&
          template.helperTargetRvas ==
            ((template.directCalls.filter
              (fun call => call.targetRva != lookupRva &&
                call.targetRva != invokeRva)).map
                  (fun call => call.targetRva)).eraseDups
    | _, _ => false)

structure InterpreterStepNativeTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  template : InterpreterStepNativeTemplate
  callbacks : KernelCallbackInventory
  checked : template.checked program pe imports callbacks function = true
  exactDecodes : ExactDecodeInventory pe function.instructions

def InterpreterStepNativeDispatches (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) : KernelDispatchRelation :=
  fun entryRva before after events =>
    exists afterWorld observations,
      NativeWorldDispatches candidate entryRva before world after events
        afterWorld observations

/-! ## Exact local executions -/

structure InterpreterStepNativeChunk
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram) (before : NativeWorldExecution) where
  cutpoint : InterpreterStepNativeCutpoint
  cutpointMember : cutpoint ∈ template.cutpoints
  startsAt : before.rva? = some cutpoint.entryRva
  positive : 0 < cutpoint.instructionCount

def InterpreterStepNativeChunk.result
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (chunk : InterpreterStepNativeChunk template candidate before) :
    NativeWorldExecution × List WorldRelationalObservable :=
  runRelatedSteps candidate.transitionSystem chunk.cutpoint.instructionCount before

def InterpreterStepNativeChunk.after
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (chunk : InterpreterStepNativeChunk template candidate before) :
    NativeWorldExecution := chunk.result.1

def InterpreterStepNativeChunk.observations
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (chunk : InterpreterStepNativeChunk template candidate before) :
    List WorldRelationalObservable := chunk.result.2

def InterpreterStepNativeChunk.destinationChecked
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (chunk : InterpreterStepNativeChunk template candidate before) : Prop :=
  match chunk.after.rva? with
  | some rva => rva ∈ chunk.cutpoint.allowedRvas
  | none => chunk.cutpoint.effect = .return

theorem InterpreterStepNativeChunk.path
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram} {before : NativeWorldExecution}
    (chunk : InterpreterStepNativeChunk template candidate before) :
    NonemptyRelatedPath candidate.transitionSystem before chunk.observations
      chunk.after := by
  exact ⟨chunk.cutpoint.instructionCount, chunk.positive, rfl⟩

/-- Calls outside the Step function remain local obligations.  Their endpoints
are restricted to checked helper/callback targets and Step cutpoints; the path
itself must still be built from the exact native transition system. -/
structure InterpreterStepNativeLocalSubroutine
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (before after : NativeWorldExecution)
    (observations : List WorldRelationalObservable) where
  targetRva : Nat
  continuationRva : Nat
  boundaryAllowed : template.subroutineBoundaryAllowed targetRva continuationRva
  continuationAllowed : continuationRva ∈ template.cutpointRvas
  startsAt : before.rva? = some targetRva
  finishesAt : after.rva? = some continuationRva
  path : NonemptyRelatedPath candidate.transitionSystem before observations after

/-- This is the only path language accepted by the Step operation theorem.
Whole-operation paths cannot be inserted: paths are assembled from fixed-fuel
checked blocks and target-restricted local subroutines. -/
inductive InterpreterStepNativePath
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram) :
    NativeWorldExecution -> List WorldRelationalObservable ->
      NativeWorldExecution -> Prop
  | chunk {before} (execution : InterpreterStepNativeChunk template candidate before)
      (destinationChecked : execution.destinationChecked) :
      InterpreterStepNativePath template candidate before execution.observations
        execution.after
  | subroutine {before after observations}
      (execution : InterpreterStepNativeLocalSubroutine template candidate before
        after observations) :
      InterpreterStepNativePath template candidate before observations after
  | trans {before middle after leftObservations rightObservations}
      (left : InterpreterStepNativePath template candidate before leftObservations
        middle)
      (right : InterpreterStepNativePath template candidate middle rightObservations
        after) :
      InterpreterStepNativePath template candidate before
        (leftObservations ++ rightObservations) after

theorem InterpreterStepNativePath.sound
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram}
    {before after : NativeWorldExecution}
    {observations : List WorldRelationalObservable}
    (path : InterpreterStepNativePath template candidate before observations after) :
    NonemptyRelatedPath candidate.transitionSystem before observations after := by
  induction path with
  | chunk execution destinationChecked => exact execution.path
  | subroutine execution => exact execution.path
  | trans left right leftSound rightSound => exact leftSound.trans rightSound

/-! ## Semantic phase composition -/

structure InterpreterStepNativeLookupPhase
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram) (records : List ProgramRecord)
    (sourceRva : Nat) (before : MachineState) (world : RelationalWorld) where
  record : Option ProgramRecord
  afterLookup : NativeWorldExecution
  observations : List WorldRelationalObservable
  path : InterpreterStepNativePath template candidate
    (.running template.machine.entryRva 0 before [] 0 [] world)
    observations afterLookup
  recordExact : record = lookupProgramRecord records sourceRva

structure InterpreterStepNativeActionPhase
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (environment : StageA.Relational.Interpreter.Environment)
    (logical : InterpreterMachine) {records : List ProgramRecord}
    {sourceRva : Nat} {before : MachineState} {world : RelationalWorld}
    (lookup : InterpreterStepNativeLookupPhase template candidate records
      sourceRva before world) where
  result : Option MacroResult
  afterActions : NativeWorldExecution
  observations : List WorldRelationalObservable
  path : InterpreterStepNativePath template candidate lookup.afterLookup
    observations afterActions

structure InterpreterStepNativeEpiloguePhase
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram) (abi : KernelABIRelation)
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    {world : RelationalWorld}
    {lookup : InterpreterStepNativeLookupPhase template candidate records
      sourceRva before world}
    (actions : InterpreterStepNativeActionPhase template candidate environment
      logical lookup) where
  after : MachineState
  nativeEvents : List NativeExternalEvent
  afterWorld : RelationalWorld
  observations : List WorldRelationalObservable
  path : InterpreterStepNativePath template candidate actions.afterActions
    observations (.returned after nativeEvents afterWorld)
  responseRelated : abi.responseRelated
    (.interpreterStep records environment sourceRva logical)
    (.interpreterStep actions.result) after nativeEvents
  memoryFrame : MemoryAgreesOutside
    (abi.scratchFootprint
      (.interpreterStep records environment sourceRva logical))
    after.memory before.memory

/-- The generated module can only ask for this certificate.  Each phase path
must be assembled from checked block chunks and local subroutines; no field has
the type of the final operation theorem or a whole-operation path. -/
structure InterpreterStepNativeMachineCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) where
  function : KernelFunction
  reflected : InterpreterStepNativeTemplateCertificate program candidate.pe
    candidate.imports function
  entryRvaExact :
    program.functionEntry? .interpreterStep = some function.span.start
  templateEntryExact : reflected.template.machine.entryRva = function.span.start
  establishRecords : forall records environment sourceRva logical before,
    abi.requestRelated (.interpreterStep records environment sourceRva logical)
        before ->
      records = semanticRecords
  lookup : forall environment sourceRva logical before,
    abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      InterpreterStepNativeLookupPhase reflected.template candidate
        semanticRecords sourceRva before world
  actions : forall environment sourceRva logical before
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepNativeLookupPhase reflected.template candidate
        semanticRecords sourceRva before world),
    InterpreterStepNativeActionPhase reflected.template candidate environment
      logical lookupPhase
  epilogue : forall environment sourceRva logical before
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepNativeLookupPhase reflected.template candidate
        semanticRecords sourceRva before world)
      (actionPhase : InterpreterStepNativeActionPhase reflected.template candidate
        environment logical lookupPhase),
    InterpreterStepNativeEpiloguePhase reflected.template candidate abi
      semanticRecords environment sourceRva logical before actionPhase

#print axioms InterpreterStepNativeChunk.path
#print axioms InterpreterStepNativePath.sound

end StageA.Relational.InterpreterKernelStepNative
