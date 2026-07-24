import StageA.RelationalInterpreterKernelCallback
import StageA.RelationalSymbolicSoundness

namespace StageA.Relational.InterpreterKernelStep

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.SymbolicSoundness

/-!
Reflective and semantic certificate for the compiled `interpreterStep`
operation.  Generated data may describe the candidate's exact relative CFG,
but cannot provide an operation-level simulation theorem.  The semantic proof
is split at three stable machine boundaries: lookup, action execution, and the
ABI epilogue.  Lean composes those paths into the final operation refinement.
-/

structure RelativeKernelInstructionShape where
  offset : Nat
  bytes : Bytes
deriving Repr, DecidableEq

structure RelativeKernelBlockShape where
  entryOffset : Nat
  instructions : List RelativeKernelInstructionShape
  successorOffsets : List Int
deriving Repr, DecidableEq

structure RelativeKernelLoopShape where
  headerOffset : Nat
  latchOffset : Nat
  bodyOffsets : List Nat
deriving Repr, DecidableEq

def relativeInstructionShape (entryRva : Nat)
    (instruction : KernelInstruction) : RelativeKernelInstructionShape := {
  offset := instruction.rva - entryRva
  bytes := instruction.bytes
}

def relativeBlockShape (entryRva : Nat)
    (block : KernelBlock) : RelativeKernelBlockShape := {
  entryOffset := block.entryRva - entryRva
  instructions := block.instructions.map (relativeInstructionShape entryRva)
  successorOffsets := block.successors.map fun target =>
    Int.ofNat target - Int.ofNat entryRva
}

def relativeLoopShape (entryRva : Nat)
    (loop : KernelLoop) : RelativeKernelLoopShape := {
  headerOffset := loop.headerRva - entryRva
  latchOffset := loop.latchRva - entryRva
  bodyOffsets := loop.bodyEntries.map (fun target => target - entryRva)
}

def decodedCallOffsets (pe : PE32) (entryRva : Nat)
    (function : KernelFunction) : List Nat :=
  function.instructions.filterMap fun instruction =>
    match instruction.decode? pe with
    | some decoded =>
        match decoded.instruction with
        | .callRel32 _ | .callIndirect _ => some (instruction.rva - entryRva)
        | _ => none
    | none => none

def decodedIndirectCallOffsets (pe : PE32) (entryRva : Nat)
    (function : KernelFunction) : List Nat :=
  function.instructions.filterMap fun instruction =>
    match instruction.decode? pe with
    | some decoded =>
        match decoded.instruction with
        | .callIndirect _ => some (instruction.rva - entryRva)
        | _ => none
    | none => none

def decodedReturnOffsets (pe : PE32) (entryRva : Nat)
    (function : KernelFunction) : List Nat :=
  function.instructions.filterMap fun instruction =>
    match instruction.decode? pe with
    | some decoded =>
        match decoded.instruction with
        | .ret | .retPop _ => some (instruction.rva - entryRva)
        | _ => none
    | none => none

/-- Candidate-parametric description of the reviewed O0 interpreter-step
machine template.  The fields are data only.  `checked` below re-reads the
candidate PE, re-decodes every instruction through `KernelFunction.checked`,
and compares the complete byte and CFG inventory. -/
structure InterpreterStepMachineTemplate where
  entryRva : Nat
  functionBytes : Bytes
  blocks : List RelativeKernelBlockShape
  loops : List RelativeKernelLoopShape
  callOffsets : List Nat
  indirectCallOffsets : List Nat
  returnOffsets : List Nat
deriving Repr, DecidableEq

def InterpreterStepMachineTemplate.checked
    (template : InterpreterStepMachineTemplate)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) : Bool :=
  function ∈ program.functions &&
    function.role == .interpreterStep &&
    function.span.start == template.entryRva &&
    function.span.size == template.functionBytes.length &&
    function.bytes == template.functionBytes &&
    spanBytes pe function.span == some template.functionBytes &&
    function.x87Frames.isEmpty && function.padding.isEmpty &&
    function.checked pe imports &&
    function.blocks.map (relativeBlockShape template.entryRva) ==
      template.blocks &&
    function.loops.map (relativeLoopShape template.entryRva) ==
      template.loops &&
    decodedCallOffsets pe template.entryRva function == template.callOffsets &&
    decodedIndirectCallOffsets pe template.entryRva function ==
      template.indirectCallOffsets &&
    decodedReturnOffsets pe template.entryRva function == template.returnOffsets &&
    template.returnOffsets.length == 1 &&
    template.indirectCallOffsets.length <= template.callOffsets.length

structure InterpreterStepTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  template : InterpreterStepMachineTemplate
  checked : template.checked program pe imports function = true
  exactDecodes : ExactDecodeInventory pe function.instructions

/-- A relation used for phase-local traces.  The laws are intentionally only
composition and conversion to the concrete dispatch relation.  They can be
instantiated by the callback-aware or world-aware executor without changing
the operation proof. -/
structure ComposableKernelExecution
    (steps : NativeExecution -> NativeExecution -> Prop)
    (dispatches : KernelDispatchRelation) : Prop where
  refl : forall state, steps state state
  trans : forall {before middle after},
    steps before middle -> steps middle after -> steps before after
  dispatch : forall entryRva before after events,
    steps (.running entryRva 0 before [] 0 []) (.returned after events) ->
      dispatches entryRva before after events

structure InterpreterStepEntryInvariant
    (semanticRecords records : List ProgramRecord) : Prop where
  recordsExact : records = semanticRecords

structure InterpreterStepLookupPhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (records : List ProgramRecord) (entryRva sourceRva : Nat)
    (before : MachineState) where
  record : Option ProgramRecord
  afterLookup : NativeExecution
  path : steps (.running entryRva 0 before [] 0 []) afterLookup
  recordExact : record = lookupProgramRecord records sourceRva

/-- Exhaustive semantic classifications for the selected immutable program
record.  Each constructor carries a local machine path plus the exact
definition-level reason for the result.  There is no freely chosen result
postcondition: `resultExact` below is derived by cases. -/
inductive InterpreterStepRecordTrace
    (steps : NativeExecution -> NativeExecution -> Prop)
    (environment : StageA.Relational.Interpreter.Environment)
    (logical : InterpreterMachine) :
    Option ProgramRecord -> NativeExecution -> NativeExecution ->
      Option MacroResult -> Prop
  | missing (before after)
      (path : steps before after) :
      InterpreterStepRecordTrace steps environment logical none before after none
  | decodeRejected (record before after)
      (path : steps before after)
      (rejected : record.decode = none) :
      InterpreterStepRecordTrace steps environment logical (some record)
        before after none
  | structuralRejected (record transfer before after)
      (path : steps before after)
      (decoded : record.decode = some transfer)
      (rejected : transfer.checked = false) :
      InterpreterStepRecordTrace steps environment logical (some record)
        before after none
  | executionRejected (record transfer before after)
      (path : steps before after)
      (decoded : record.decode = some transfer)
      (checked : transfer.checked = true)
      (rejected : transfer.execute environment logical = none) :
      InterpreterStepRecordTrace steps environment logical (some record)
        before after none
  | executed (record transfer result before after)
      (path : steps before after)
      (decoded : record.decode = some transfer)
      (checked : transfer.checked = true)
      (execution : transfer.execute environment logical = some result) :
      InterpreterStepRecordTrace steps environment logical (some record)
        before after (some result)

theorem InterpreterStepRecordTrace.path
    {steps : NativeExecution -> NativeExecution -> Prop}
    {environment : StageA.Relational.Interpreter.Environment}
    {logical : InterpreterMachine} {record : Option ProgramRecord}
    {before after : NativeExecution} {result : Option MacroResult}
    (trace : InterpreterStepRecordTrace steps environment logical record before
      after result) : steps before after := by
  cases trace <;> assumption

theorem InterpreterStepRecordTrace.resultExact
    {steps : NativeExecution -> NativeExecution -> Prop}
    {environment : StageA.Relational.Interpreter.Environment}
    {logical : InterpreterMachine} {record : Option ProgramRecord}
    {before after : NativeExecution} {result : Option MacroResult}
    (trace : InterpreterStepRecordTrace steps environment logical record before
      after result) :
    result = record.bind (fun selected => selected.interpret environment logical) := by
  cases trace with
  | missing => rfl
  | decodeRejected record before after path rejected =>
      simp [ProgramRecord.interpret, rejected]
  | structuralRejected record transfer before after path decoded rejected =>
      simp [ProgramRecord.interpret, decoded, rejected]
  | executionRejected record transfer before after path decoded checked rejected =>
      simp [ProgramRecord.interpret, decoded, checked, rejected]
  | executed record transfer result before after path decoded checked execution =>
      simp [ProgramRecord.interpret, decoded, checked, execution]

/-- The action phase begins after the exact lookup call and ends before the ABI
epilogue.  The result is justified only by the closed trace above. -/
structure InterpreterStepActionPhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (environment : StageA.Relational.Interpreter.Environment) (sourceRva : Nat)
    (logical : InterpreterMachine) {records : List ProgramRecord}
    {entryRva : Nat} {before : MachineState}
    (lookup : InterpreterStepLookupPhase steps records entryRva sourceRva before) where
  result : Option MacroResult
  afterActions : NativeExecution
  trace : InterpreterStepRecordTrace steps environment logical lookup.record
    lookup.afterLookup afterActions result

structure InterpreterStepEpiloguePhase
    (steps : NativeExecution -> NativeExecution -> Prop)
    (abi : KernelABIRelation) (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment) (sourceRva : Nat)
    (logical : InterpreterMachine) (before : MachineState)
    {entryRva : Nat}
    {lookup : InterpreterStepLookupPhase steps records entryRva sourceRva before}
    (actions : InterpreterStepActionPhase steps environment sourceRva logical lookup) where
  after : MachineState
  nativeEvents : List NativeExternalEvent
  path : steps actions.afterActions (.returned after nativeEvents)
  responseRelated : abi.responseRelated
    (.interpreterStep records environment sourceRva logical)
    (.interpreterStep actions.result) after nativeEvents
  memoryFrame : MemoryAgreesOutside
    (abi.scratchFootprint
      (.interpreterStep records environment sourceRva logical))
    after.memory before.memory

/-- A complete reviewed proof is assembled from static reflection and three
phase-local proof producers.  There is intentionally no `simulate` member and
no member whose type is `KernelOperationRefinesUsing`. -/
structure InterpreterStepMachineCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord)
    (steps : NativeExecution -> NativeExecution -> Prop)
    (dispatches : KernelDispatchRelation) where
  function : KernelFunction
  reflected : InterpreterStepTemplateCertificate program pe imports function
  execution : ComposableKernelExecution steps dispatches
  entryRvaExact :
    program.functionEntry? .interpreterStep = some function.span.start
  establishEntry : forall records environment sourceRva logical before,
    abi.requestRelated
        (.interpreterStep records environment sourceRva logical) before ->
      InterpreterStepEntryInvariant semanticRecords records
  lookup : forall environment sourceRva logical before,
    abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      InterpreterStepLookupPhase steps semanticRecords function.span.start
        sourceRva before
  actions : forall environment sourceRva logical before
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepLookupPhase steps semanticRecords
        function.span.start sourceRva before),
    InterpreterStepActionPhase steps environment sourceRva logical lookupPhase
  epilogue : forall environment sourceRva logical before
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepLookupPhase steps semanticRecords
        function.span.start sourceRva before)
      (actionPhase : InterpreterStepActionPhase steps environment sourceRva
        logical lookupPhase),
    InterpreterStepEpiloguePhase steps abi semanticRecords environment sourceRva
      logical before actionPhase

theorem abstractInterpreterStep_eq_bind_lookup
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) :
    abstractInterpreterStep records environment sourceRva logical =
      (lookupProgramRecord records sourceRva).bind
        (fun record => record.interpret environment logical) := by
  rfl

theorem InterpreterStepMachineCertificate.refines
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {abi : KernelABIRelation} {semanticRecords : List ProgramRecord}
    {steps : NativeExecution -> NativeExecution -> Prop}
    {dispatches : KernelDispatchRelation}
    (certificate : InterpreterStepMachineCertificate program pe imports abi
      semanticRecords steps dispatches) :
    KernelOperationRefinesUsing program abi dispatches .interpreterStep := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      have entry := certificate.establishEntry records environment sourceRva
        logical before requestRelated
      have recordsExact := entry.recordsExact
      subst records
      cases transition
      let lookupPhase := certificate.lookup environment sourceRva logical before
        requestRelated
      let actionPhase := certificate.actions environment sourceRva logical before
        requestRelated lookupPhase
      let epilogue := certificate.epilogue environment sourceRva logical before
        requestRelated lookupPhase actionPhase
      have combinedPhases : steps
          (.running certificate.function.span.start 0 before [] 0 [])
          actionPhase.afterActions :=
        certificate.execution.trans lookupPhase.path actionPhase.trace.path
      have complete : steps
          (.running certificate.function.span.start 0 before [] 0 [])
          (.returned epilogue.after epilogue.nativeEvents) :=
        certificate.execution.trans combinedPhases epilogue.path
      have resultExact : actionPhase.result =
          abstractInterpreterStep semanticRecords environment sourceRva logical := by
        rw [abstractInterpreterStep_eq_bind_lookup, <- lookupPhase.recordExact]
        exact actionPhase.trace.resultExact
      refine ⟨certificate.function.span.start, epilogue.after,
        epilogue.nativeEvents, certificate.entryRvaExact,
        certificate.execution.dispatch certificate.function.span.start before
          epilogue.after epilogue.nativeEvents complete, ?_, epilogue.memoryFrame⟩
      simpa [resultExact] using epilogue.responseRelated

#print axioms abstractInterpreterStep_eq_bind_lookup
#print axioms InterpreterStepRecordTrace.resultExact
#print axioms InterpreterStepMachineCertificate.refines

end StageA.Relational.InterpreterKernelStep
