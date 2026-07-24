import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterKernelCallback
import StageA.RelationalInterpreterKernelIndirect
import StageA.RelationalInterpreterKernelStep

namespace StageA.Relational.InterpreterKernelInvoke

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelStep
open StageA.Relational.SymbolicSoundness

/-!
Reflective proof interface for the small O0 cdecl `invokeCall` dispatcher used by
the compiled semantic engine.  The reviewed template is independent of symbol
names and absolute RVAs.  Relative-call displacements are masked, then checked
separately against the required `runFunction` entry and one explicit external
dispatch helper.  The register-carried resolver call must occur in a complete,
exactly decoded callback inventory.

The final theorem is assembled from three branch-local machine executions.
There is no operation-level simulation or refinement field in any certificate.
The branch executions remain genuine proof obligations over the selected exact
dispatch relation; generated JSON cannot inhabit them.
-/

structure InvokeCallBlockShape where
  entryOffset : Nat
  instructionOffsets : List Nat
  localSuccessorOffsets : List Nat
deriving Repr, DecidableEq

def InvokeCallBlockShape.ofBlock (function : KernelFunction)
    (block : KernelBlock) : InvokeCallBlockShape := {
  entryOffset := block.entryRva - function.span.start
  instructionOffsets := block.instructions.map
    (fun instruction => instruction.rva - function.span.start)
  localSuccessorOffsets := block.successors.filterMap fun target =>
    if function.span.start <= target && target < function.span.stop then
      some (target - function.span.start)
    else none
}

def invokeCallRelocationByteOffsets : List Nat :=
  [63, 64, 65, 66, 158, 159, 160, 161, 192, 193, 194, 195]

def normalizeInvokeCallBytes : Nat -> Bytes -> Bytes
  | _, [] => []
  | offset, byte :: tail =>
      (if invokeCallRelocationByteOffsets.contains offset then 0 else byte) ::
        normalizeInvokeCallBytes (offset + 1) tail

/-- Reviewed GCC/MinGW O0 instruction skeleton.  Only the three direct-call
rel32 payloads are abstracted; their decoded targets are checked below. -/
def reviewedInvokeCallBytes : Bytes := [
  0x55, 0x89, 0xe5, 0x83, 0xec, 0x28, 0x83, 0x7d, 0x0c, 0x00, 0x75, 0x0a,
  0xb8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0xae, 0x00, 0x00, 0x00, 0x8b, 0x45,
  0x0c, 0x8b, 0x00, 0x83, 0xf8, 0x01, 0x75, 0x25, 0x8b, 0x45, 0x0c, 0x8b,
  0x40, 0x0c, 0x8b, 0x55, 0x14, 0x89, 0x54, 0x24, 0x0c, 0x8b, 0x55, 0x10,
  0x89, 0x54, 0x24, 0x08, 0x89, 0x44, 0x24, 0x04, 0x8b, 0x45, 0x08, 0x89,
  0x04, 0x24, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x7f, 0x8b, 0x45, 0x0c,
  0x8b, 0x00, 0x83, 0xf8, 0x02, 0x75, 0x55, 0x83, 0x7d, 0x08, 0x00, 0x74,
  0x4f, 0x8b, 0x45, 0x08, 0x8b, 0x40, 0x14, 0x85, 0xc0, 0x74, 0x45, 0x8b,
  0x45, 0x08, 0x8b, 0x40, 0x14, 0x8b, 0x55, 0x0c, 0x8b, 0x52, 0x0c, 0x8d,
  0x4d, 0xf4, 0x89, 0x4c, 0x24, 0x08, 0x89, 0x54, 0x24, 0x04, 0x8b, 0x55,
  0x08, 0x89, 0x14, 0x24, 0xff, 0xd0, 0x85, 0xc0, 0x75, 0x22, 0x8b, 0x45,
  0xf4, 0x8b, 0x55, 0x14, 0x89, 0x54, 0x24, 0x0c, 0x8b, 0x55, 0x10, 0x89,
  0x54, 0x24, 0x08, 0x89, 0x44, 0x24, 0x04, 0x8b, 0x45, 0x08, 0x89, 0x04,
  0x24, 0xe8, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x20, 0x8b, 0x45, 0x14, 0x89,
  0x44, 0x24, 0x0c, 0x8b, 0x45, 0x10, 0x89, 0x44, 0x24, 0x08, 0x8b, 0x45,
  0x0c, 0x89, 0x44, 0x24, 0x04, 0x8b, 0x45, 0x08, 0x89, 0x04, 0x24, 0xe8,
  0x00, 0x00, 0x00, 0x00, 0xc9, 0x31, 0xd2, 0x31, 0xc9, 0xc3]

def reviewedInvokeCallBlocks : List InvokeCallBlockShape := [
  { entryOffset := 0, instructionOffsets := [0, 1, 3, 6, 10],
    localSuccessorOffsets := [22, 12] },
  { entryOffset := 12, instructionOffsets := [12, 17],
    localSuccessorOffsets := [196] },
  { entryOffset := 22, instructionOffsets := [22, 25, 27, 30],
    localSuccessorOffsets := [69, 32] },
  { entryOffset := 32,
    instructionOffsets := [32, 35, 38, 41, 45, 48, 52, 56, 59, 62],
    localSuccessorOffsets := [67] },
  { entryOffset := 67, instructionOffsets := [67],
    localSuccessorOffsets := [196] },
  { entryOffset := 69, instructionOffsets := [69, 72, 74, 77],
    localSuccessorOffsets := [164, 79] },
  { entryOffset := 79, instructionOffsets := [79, 83],
    localSuccessorOffsets := [164, 85] },
  { entryOffset := 85, instructionOffsets := [85, 88, 91, 93],
    localSuccessorOffsets := [164, 95] },
  { entryOffset := 95,
    instructionOffsets := [95, 98, 101, 104, 107, 110, 114, 118, 121, 124],
    localSuccessorOffsets := [126] },
  { entryOffset := 126, instructionOffsets := [126, 128],
    localSuccessorOffsets := [164, 130] },
  { entryOffset := 130,
    instructionOffsets := [130, 133, 136, 140, 143, 147, 151, 154, 157],
    localSuccessorOffsets := [162] },
  { entryOffset := 162, instructionOffsets := [162],
    localSuccessorOffsets := [196] },
  { entryOffset := 164,
    instructionOffsets := [164, 167, 171, 174, 178, 181, 185, 188, 191],
    localSuccessorOffsets := [196] },
  { entryOffset := 196, instructionOffsets := [196, 197, 199, 201],
    localSuccessorOffsets := [] }]

def decodedDirectCallTargets (pe : PE32) (function : KernelFunction) : List Nat :=
  function.instructions.filterMap fun instruction =>
    match instruction.decode? pe with
    | some decoded =>
        match decoded.instruction with
        | .callRel32 displacement =>
            some (relativeTarget32 (instruction.rva + decoded.size) displacement)
        | _ => none
    | none => none

structure InvokeCallMachineTemplate where
  entryRva : Nat
  functionBytes : Bytes
  externalDispatchRva : Nat
deriving Repr, DecidableEq

def InvokeCallMachineTemplate.checked
    (template : InvokeCallMachineTemplate)
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (callbacks : KernelCallbackInventory) (function : KernelFunction) : Bool :=
  function ∈ program.functions && function.role == .invokeCall &&
    function.span.start == template.entryRva &&
    function.span.size == template.functionBytes.length &&
    function.bytes == template.functionBytes &&
    spanBytes pe function.span == some template.functionBytes &&
    normalizeInvokeCallBytes 0 template.functionBytes == reviewedInvokeCallBytes &&
    function.blocks.map (InvokeCallBlockShape.ofBlock function) ==
      reviewedInvokeCallBlocks &&
    function.loops.isEmpty && function.x87Frames.isEmpty &&
    function.x87Commands.isEmpty && function.padding.isEmpty &&
    function.frame.required && function.frame.pushRva == template.entryRva &&
    function.frame.setupRva == template.entryRva + 1 &&
    function.frame.teardownRvas == [template.entryRva + 196] &&
    function.frame.returnRvas == [template.entryRva + 201] &&
    function.checked pe imports &&
    decodedCallOffsets pe template.entryRva function == [62, 124, 157, 191] &&
    decodedIndirectCallOffsets pe template.entryRva function == [124] &&
    decodedReturnOffsets pe template.entryRva function == [201] &&
    match program.functionEntry? .runFunction with
    | none => false
    | some runFunctionRva =>
        decodedDirectCallTargets pe function ==
          [runFunctionRva, runFunctionRva, template.externalDispatchRva] &&
        program.functions.any
          (fun candidate => candidate.span.start == template.externalDispatchRva) &&
        callbacks.checked program pe imports &&
        callbackSitesContainRva callbacks.sites (template.entryRva + 124)

structure InvokeCallTemplateCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (function : KernelFunction) where
  template : InvokeCallMachineTemplate
  callbacks : KernelCallbackInventory
  checked : template.checked program pe imports callbacks function = true
  exactDecodes : ExactDecodeInventory pe function.instructions

structure InvokeCallBranchResult (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation) (entryRva : Nat)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (before : MachineState) where
  after : MachineState
  nativeEvents : List NativeExternalEvent
  path : dispatches entryRva before after nativeEvents
  responseRelated : abi.responseRelated request response after nativeEvents
  memoryFrame : MemoryAgreesOutside (abi.scratchFootprint request)
    after.memory before.memory

/-- Branch-local proof interface.  Each field is tied to one constructor of
`AbstractKernelTransition`, and therefore cannot choose a different result or
silently merge external, internal, and indirect behavior. -/
structure InvokeCallBranchExecutions (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation) (entryRva : Nat)
    (semanticRecords : List ProgramRecord) : Prop where
  external : forall environment resolveCodeTarget event logical before,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before -> event.kind = .external ->
      Nonempty (InvokeCallBranchResult abi dispatches entryRva
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        (.call (environment.invokeCall event logical)) before)
  internal : forall environment resolveCodeTarget event logical before result,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before -> event.kind = .internal ->
      AbstractRunFunction semanticRecords environment resolveCodeTarget
        event.targetRva.toNat logical result ->
      Nonempty (InvokeCallBranchResult abi dispatches entryRva
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        (.call result) before)
  indirect : forall environment resolveCodeTarget event logical before target result,
    abi.requestRelated
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        before -> event.kind = .indirect ->
      resolveCodeTarget event.targetRva = some target ->
      AbstractRunFunction semanticRecords environment resolveCodeTarget target logical
        result ->
      Nonempty (InvokeCallBranchResult abi dispatches entryRva
        (.invokeCall semanticRecords environment resolveCodeTarget event logical)
        (.call result) before)

/-- Complete invoke-call proof assembled from static reflection, exact ABI
record binding, and the three exhaustive branch executions. -/
structure InvokeCallMachineCertificate
    (program : CompiledKernelProgram) (pe : PE32) (imports : List PEImport)
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord)
    (dispatches : KernelDispatchRelation) where
  function : KernelFunction
  reflected : InvokeCallTemplateCertificate program pe imports function
  entryRvaExact : program.functionEntry? .invokeCall = some function.span.start
  recordsExact : forall records environment resolveCodeTarget event logical before,
    abi.requestRelated (.invokeCall records environment resolveCodeTarget event logical)
      before -> records = semanticRecords
  branches : InvokeCallBranchExecutions abi dispatches function.span.start
    semanticRecords

theorem InvokeCallMachineCertificate.refines
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {abi : KernelABIRelation} {semanticRecords : List ProgramRecord}
    {dispatches : KernelDispatchRelation}
    (certificate : InvokeCallMachineCertificate program pe imports abi
      semanticRecords dispatches) :
    KernelOperationRefinesUsing program abi dispatches .invokeCall := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      have recordsExact := certificate.recordsExact records environment
        resolveCodeTarget event logical before requestRelated
      subst records
      cases transition with
      | invokeExternal _ _ _ _ _ externalKind =>
          obtain ⟨result⟩ := certificate.branches.external environment
            resolveCodeTarget event logical before requestRelated externalKind
          exact ⟨certificate.function.span.start, result.after,
            result.nativeEvents, certificate.entryRvaExact, result.path,
            result.responseRelated, result.memoryFrame⟩
      | invokeInternal _ _ _ _ _ result internalKind run =>
          obtain ⟨branch⟩ := certificate.branches.internal environment
            resolveCodeTarget event logical before result requestRelated internalKind run
          exact ⟨certificate.function.span.start, branch.after,
            branch.nativeEvents, certificate.entryRvaExact, branch.path,
            branch.responseRelated, branch.memoryFrame⟩
      | invokeIndirect _ _ _ _ _ target result indirectKind resolved run =>
          obtain ⟨branch⟩ := certificate.branches.indirect environment
            resolveCodeTarget event logical before target result requestRelated
            indirectKind resolved run
          exact ⟨certificate.function.span.start, branch.after,
            branch.nativeEvents, certificate.entryRvaExact, branch.path,
            branch.responseRelated, branch.memoryFrame⟩

/-- Concrete-ABI specialization.  The semantic record inventory is recovered
from `ABIRequestFacts.payload`; callers cannot provide a separate record-binding
law for this acceptance path. -/
structure ConcreteInvokeCallMachineCertificate
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {semanticRecords : List ProgramRecord}
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords) (dispatches : KernelDispatchRelation) where
  function : KernelFunction
  reflected : InvokeCallTemplateCertificate abi.program pe imports function
  entryRvaExact : abi.program.functionEntry? .invokeCall = some function.span.start
  branches : InvokeCallBranchExecutions abi.relation dispatches function.span.start
    semanticRecords

theorem ConcreteInvokeCallMachineCertificate.refines
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {semanticRecords : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords} {dispatches : KernelDispatchRelation}
    (certificate : ConcreteInvokeCallMachineCertificate abi dispatches) :
    KernelOperationRefinesUsing abi.program abi.relation dispatches .invokeCall := by
  apply InvokeCallMachineCertificate.refines {
    function := certificate.function
    reflected := certificate.reflected
    entryRvaExact := certificate.entryRvaExact
    recordsExact := ?_
    branches := certificate.branches
  }
  intro records environment resolveCodeTarget event logical before related
  exact related.payload.1

#print axioms InvokeCallMachineCertificate.refines
#print axioms ConcreteInvokeCallMachineCertificate.refines

end StageA.Relational.InterpreterKernelInvoke
