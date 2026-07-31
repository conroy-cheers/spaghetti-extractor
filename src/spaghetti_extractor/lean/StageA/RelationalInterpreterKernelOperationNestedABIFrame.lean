import StageA.RelationalInterpreterKernelCdeclEpilogueStaticPreservation
import StageA.RelationalInterpreterKernelOperationABIFrame

namespace StageA.Relational.InterpreterKernelOperationNestedABIFrame

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueStaticPreservation
open StageA.Relational.InterpreterKernelOperationABIFrame

/-!
# Nested operation ABI frames

An internal call computes a fresh cdecl entry state inside a caller-owned
stack reservation.  This module packages the common proof boundary: exact
call semantics provide the words, frame validity, direction flag, and a
workspace-framed memory update; the generic theorem reconstructs the callee
entry facts and preserves immutable image and program-table authority.
-/

/-- Checked evidence for one operation entry reached from another operation.
The frame is recovered from the exact callee state, so generated code cannot
submit preserved-register values or a return word independently. -/
structure KernelOperationNestedEntryProjection
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation}
    {tableOffset countOffset : Nat} {records : List ProgramRecord}
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest)
    (stackSpan : Span) (before after : MachineState) : Prop where
  frameValid :
    (kernelOperationABIFrameAtInStackSpan abi.parameters.writableWorkspace
      stackSpan request.operation after).Valid
        abi.parameters.writableWorkspace abi.engineLayout
  words :
    let frame :=
      kernelOperationABIFrameAtInStackSpan
        abi.parameters.writableWorkspace stackSpan request.operation after
    WordsAt after.memory frame.entryEsp
      (frame.returnAddress :: frame.requestArguments request)
  stackRange :
    addressRangeInSpan abi.parameters.writableWorkspace
      (word32 stackSpan.start) stackSpan.size
  directionFlagClear : DirectionFlagClear after
  memoryFrame :
    MemoryAgreesOutside
      (addressInSpan abi.parameters.writableWorkspace)
      after.memory before.memory
  payload :
    let frame :=
      kernelOperationABIFrameAtInStackSpan
        abi.parameters.writableWorkspace stackSpan request.operation after
    frame.RequestPayloadHolds abi request after

/-- Reconstruct the exact nested cdecl frame and all entry facts consumed by a
callee operation theorem.  Static facts come only from the checked workspace
frame and the caller's already established image/table facts. -/
def KernelOperationNestedEntryProjection.toEntryFacts
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation}
    {tableOffset countOffset : Nat} {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {request : AbstractKernelRequest} {stackSpan : Span}
    {before after : MachineState}
    (projection :
      KernelOperationNestedEntryProjection abi request stackSpan before after)
    (candidateImage :
      LoadedCandidateImageMemory pe imports relocations before.memory)
    (originalProgramTable :
      LoadedOriginalProgramTable abi before.memory) :
    let frame :=
      kernelOperationABIFrameAtInStackSpan
        abi.parameters.writableWorkspace stackSpan request.operation after
    frame.EntryFacts abi request after := by
  let frame :=
    kernelOperationABIFrameAtInStackSpan
      abi.parameters.writableWorkspace stackSpan request.operation after
  have cdecl : frame.CDeclEntryHolds abi request after := by
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, projection.words, projection.stackRange⟩
    · cases request <;> rfl
    · cases request <;> rfl
    · cases request <;> rfl
    · cases request <;> rfl
    · cases request <;> rfl
    · cases request <;> rfl
  exact {
    frameValid := projection.frameValid
    cdecl
    directionFlagClear := projection.directionFlagClear
    candidateImage :=
      workspaceFrame_preservesCandidateImage
        (pe := pe) (imports := imports) (relocations := relocations)
        abi projection.memoryFrame candidateImage
    originalProgramTable :=
      workspaceFrame_preservesOriginalProgramTable
        (pe := pe) (imports := imports) (relocations := relocations)
        abi projection.memoryFrame originalProgramTable
    payload := projection.payload
  }

def KernelOperationNestedEntryProjection.toRequestFacts
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation}
    {tableOffset countOffset : Nat} {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {request : AbstractKernelRequest} {stackSpan : Span}
    {before after : MachineState}
    (projection :
      KernelOperationNestedEntryProjection abi request stackSpan before after)
    (candidateImage :
      LoadedCandidateImageMemory pe imports relocations before.memory)
    (originalProgramTable :
      LoadedOriginalProgramTable abi before.memory) :
    let frame :=
      kernelOperationABIFrameAtInStackSpan
        abi.parameters.writableWorkspace stackSpan request.operation after
    frame.RequestFacts abi request after :=
  (projection.toEntryFacts candidateImage originalProgramTable).toRequestFacts

#print axioms KernelOperationNestedEntryProjection.toEntryFacts
#print axioms KernelOperationNestedEntryProjection.toRequestFacts

end StageA.Relational.InterpreterKernelOperationNestedABIFrame
