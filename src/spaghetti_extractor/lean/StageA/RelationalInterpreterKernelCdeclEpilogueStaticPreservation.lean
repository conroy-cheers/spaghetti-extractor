import StageA.RelationalInterpreterKernelCdeclEpilogueSymbolicClosure
import StageA.RelationalInterpreterKernelLookupABI

namespace StageA.Relational.InterpreterKernelCdeclEpilogueStaticPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelLookupABI
open StageA.Relational.InterpreterNativeWorld

/-!
# Static-memory preservation for checked cdecl epilogues

Exact symbolic execution already provides a finite write footprint and a
memory frame.  The checked ABI places that footprint in a writable workspace
which is disjoint from the loaded candidate image.  This module composes those
facts to derive preservation of the immutable candidate image and the
original-program table.  Neither preservation result is submitted by a
certificate author.

The environment-indexed response payload intentionally remains explicit.
-/

structure CDeclStaticPreservationFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) : Prop where
  imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32
  workspaceImageDisjoint :
    spanDisjoint abi.parameters.writableWorkspace
      { start := pe.imageBase, size := pe.sizeOfImage } = true
  tableBounded :
    tableOffset + abi.tableCertificate.transferCount * transferRecordSize <=
      pe.sizeOfImage
  countBounded : countOffset + 4 <= pe.sizeOfImage

theorem ConcreteKernelABI.cdeclStaticPreservationFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    CDeclStaticPreservationFacts abi := by
  let facts := ConcreteKernelABI.programLookupStaticFacts abi
  exact {
    imageBounded := facts.imageBounded
    workspaceImageDisjoint := facts.workspaceImageDisjoint
    tableBounded := facts.tableBounded
    countBounded := facts.countBounded
  }

theorem checkedCDeclWriteFootprint_avoidsLoadedImage
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true)
    (rva : Nat) (rvaBefore : rva < pe.sizeOfImage) :
    ¬ footprint.contains (word32 (pe.imageBase + rva)) := by
  intro changed
  have workspace : addressInSpan abi.parameters.writableWorkspace
      (word32 (pe.imageBase + rva)) :=
    footprint.insideScratch abi request checked _ changed
  let facts := ConcreteKernelABI.cdeclStaticPreservationFacts abi
  have imageBounded := facts.imageBounded
  have imageAddressBounded : pe.imageBase + rva < 2 ^ 32 := by
    omega
  have imageAddressExact : (word32 (pe.imageBase + rva)).toNat =
      pe.imageBase + rva := by
    simp [word32, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt imageAddressBounded]
  have disjoint := facts.workspaceImageDisjoint
  simp only [spanDisjoint, Bool.or_eq_true, decide_eq_true_eq, Span.stop] at disjoint
  rcases workspace with ⟨workspaceLower, workspaceUpper, _⟩
  have workspaceLower' : abi.parameters.writableWorkspace.start <=
      pe.imageBase + rva := by
    simpa only [imageAddressExact] using workspaceLower
  have workspaceUpper' : pe.imageBase + rva <
      abi.parameters.writableWorkspace.stop := by
    simpa only [imageAddressExact] using workspaceUpper
  rcases disjoint with workspaceBefore | imageBefore
  · have beforeBase : pe.imageBase + rva < pe.imageBase :=
      Nat.lt_of_lt_of_le workspaceUpper' workspaceBefore
    exact (Nat.not_lt_of_ge (Nat.le_add_right pe.imageBase rva)) beforeBase
  · have beforeWorkspace : pe.imageBase + pe.sizeOfImage <=
        pe.imageBase + rva := Nat.le_trans imageBefore workspaceLower'
    have beforeImageEnd : pe.imageBase + rva <
        pe.imageBase + pe.sizeOfImage := Nat.add_lt_add_left rvaBefore pe.imageBase
    exact (Nat.not_lt_of_ge beforeWorkspace) beforeImageEnd

theorem memoryFrame_preservesLoadedSpan
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true)
    (frame : MemoryAgreesOutside footprint.contains after before)
    (span : Span)
    (loaded : LoadedSpanHolds pe relocations pe.imageBase span before)
    (spanBounded : span.stop <= pe.sizeOfImage) :
    LoadedSpanHolds pe relocations pe.imageBase span after := by
  intro offset offsetBefore expected expectedLoaded
  rw [frame]
  · exact loaded offset offsetBefore expected expectedLoaded
  · simpa [Nat.add_assoc] using
      (checkedCDeclWriteFootprint_avoidsLoadedImage footprint abi request checked
        (span.start + offset) (by
          simp only [Span.stop] at spanBounded
          omega))

theorem memoryFrame_preservesCandidateImage
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true)
    (frame : MemoryAgreesOutside footprint.contains after before)
    (loaded : LoadedCandidateImageMemory pe imports relocations before) :
    LoadedCandidateImageMemory pe imports relocations after := by
  intro rva raw immutable expected loadedByte
  rw [frame]
  · exact loaded rva raw immutable expected loadedByte
  · exact checkedCDeclWriteFootprint_avoidsLoadedImage footprint abi request
      checked rva
      (immutableRvaBytesOne_bounded pe imports rva raw immutable)

theorem memoryFrame_preservesImageRead32
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true)
    (frame : MemoryAgreesOutside footprint.contains after before)
    (rva : Nat) (rvaBounded : rva + 4 <= pe.sizeOfImage) :
    Memory.read32 after (word32 (pe.imageBase + rva)) =
      Memory.read32 before (word32 (pe.imageBase + rva)) := by
  unfold Memory.read32
  have address (extra : Nat) :
      word32 (pe.imageBase + rva) + word32 extra =
        word32 (pe.imageBase + (rva + extra)) := by
    simp [word32, ← BitVec.ofNat_add, Nat.add_assoc]
  have address1 :
      word32 (pe.imageBase + rva) + BitVec.ofNat 32 1 =
        word32 (pe.imageBase + (rva + 1)) := by
    simpa [word32] using address 1
  have address2 :
      word32 (pe.imageBase + rva) + BitVec.ofNat 32 2 =
        word32 (pe.imageBase + (rva + 2)) := by
    simpa [word32] using address 2
  have address3 :
      word32 (pe.imageBase + rva) + BitVec.ofNat 32 3 =
        word32 (pe.imageBase + (rva + 3)) := by
    simpa [word32] using address 3
  rw [frame]
  · rw [address1, frame]
    · rw [address2, frame]
      · rw [address3, frame]
        exact checkedCDeclWriteFootprint_avoidsLoadedImage footprint abi request
          checked (rva + 3) (by omega)
      · simpa only [address2] using
          (checkedCDeclWriteFootprint_avoidsLoadedImage footprint abi request
            checked (rva + 2) (by omega))
    · simpa only [address1] using
        (checkedCDeclWriteFootprint_avoidsLoadedImage footprint abi request
          checked (rva + 1) (by omega))
  · exact checkedCDeclWriteFootprint_avoidsLoadedImage footprint abi request
      checked rva (by omega)

theorem memoryFrame_preservesOriginalProgramTable
    (footprint : CheckedCDeclWriteFootprint)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest)
    (checked : footprint.checked abi request = true)
    (frame : MemoryAgreesOutside footprint.contains after before)
    (loaded : LoadedOriginalProgramTable abi before) :
    LoadedOriginalProgramTable abi after := by
  let facts := ConcreteKernelABI.cdeclStaticPreservationFacts abi
  refine {
    tableSpan := ?_
    countSpan := ?_
    countWord := ?_
    sourceWords := ?_
  }
  · apply memoryFrame_preservesLoadedSpan footprint abi request checked frame
      abi.tableSpan loaded.tableSpan
    simpa [ConcreteKernelABI.tableSpan, Span.stop] using facts.tableBounded
  · apply memoryFrame_preservesLoadedSpan footprint abi request checked frame
      abi.countSpan loaded.countSpan
    simpa [ConcreteKernelABI.countSpan, Span.stop] using facts.countBounded
  · rw [memoryFrame_preservesImageRead32 footprint abi request checked frame
      countOffset
      facts.countBounded]
    exact loaded.countWord
  · intro index record recordAt
    have indexBefore : index < records.length :=
      List.getElem?_eq_some_iff.mp recordAt |>.1
    have transferCountExact :=
      programTableCertificate_transferCount_eq_records_length
        abi.tableCertificate
    rw [Nat.add_assoc pe.imageBase tableOffset
      (index * transferRecordSize)]
    rw [memoryFrame_preservesImageRead32 footprint abi request checked frame
      (tableOffset + index * transferRecordSize)]
    · simpa [Nat.add_assoc] using loaded.sourceWords index record recordAt
    · have tableBounded := facts.tableBounded
      simp only [transferRecordSize] at tableBounded ⊢
      omega

/-- A cdecl epilogue certificate whose only residual premise is the
environment-indexed typed response payload. -/
structure StaticallyPreservedCDeclEpilogueCertificate
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (candidate : ExactNativeWorldProgram)
    (static : CheckedKernelCDeclEpilogue program candidate function)
    (disposition : CDeclReturnDisposition)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (entryBefore epilogueBefore : MachineState) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) where
  operationExact : request.operation = static.inventory.operation
  entry : ABIRequestFacts abi request entryBefore
  execution : ExactComputedCDeclEpilogue candidate static disposition
    epilogueBefore eventIndex events world
  symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore
  frame : CDeclSymbolicFrameExpressions
  frameFacts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
    symbolic.behavior frame
  environmentalPayload :
    ResponsePayloadHolds abi request response execution.returnedState events

def StaticallyPreservedCDeclEpilogueCertificate.toSymbolicallyClosed
    (certificate : StaticallyPreservedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    SymbolicallyClosedCDeclEpilogueCertificate abi candidate static disposition
      request response entryBefore epilogueBefore eventIndex events world := {
  operationExact := certificate.operationExact
  entry := certificate.entry
  execution := certificate.execution
  symbolic := certificate.symbolic
  frame := certificate.frame
  frameFacts := certificate.frameFacts
  remaining := {
    candidateImagePreserved :=
      memoryFrame_preservesCandidateImage
        (symbolicWriteFootprint certificate.symbolic.behavior entryBefore)
        abi request certificate.frameFacts.footprintChecked
        certificate.symbolic.exactWriteFootprint
        certificate.entry.candidateImage
    originalProgramTablePreserved :=
      memoryFrame_preservesOriginalProgramTable
        (symbolicWriteFootprint certificate.symbolic.behavior entryBefore)
        abi request certificate.frameFacts.footprintChecked
        certificate.symbolic.exactWriteFootprint
        certificate.entry.originalProgramTable
    environmentalPayload := certificate.environmentalPayload
  }
}

def StaticallyPreservedCDeclEpilogueCertificate.toChecked
    (certificate : StaticallyPreservedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    CheckedCDeclEpilogueCertificate abi candidate static disposition request
      response entryBefore epilogueBefore eventIndex events world :=
  certificate.toSymbolicallyClosed.toChecked

theorem StaticallyPreservedCDeclEpilogueCertificate.responseRelated
    (certificate : StaticallyPreservedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    abi.relation.responseRelated request response
      certificate.execution.returnedState events :=
  certificate.toChecked.responseRelated

theorem StaticallyPreservedCDeclEpilogueCertificate.memoryFrame
    (certificate : StaticallyPreservedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    MemoryAgreesOutside (abi.relation.scratchFootprint request)
      certificate.execution.returnedState.memory entryBefore.memory :=
  certificate.toChecked.memoryFrame

theorem StaticallyPreservedCDeclEpilogueCertificate.path
    (certificate : StaticallyPreservedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    NonemptyRelatedPath candidate.transitionSystem certificate.execution.start
      certificate.execution.observations certificate.execution.after :=
  certificate.toChecked.path

#print axioms ConcreteKernelABI.cdeclStaticPreservationFacts
#print axioms checkedCDeclWriteFootprint_avoidsLoadedImage
#print axioms memoryFrame_preservesLoadedSpan
#print axioms memoryFrame_preservesCandidateImage
#print axioms memoryFrame_preservesImageRead32
#print axioms memoryFrame_preservesOriginalProgramTable
#print axioms StaticallyPreservedCDeclEpilogueCertificate.toSymbolicallyClosed
#print axioms StaticallyPreservedCDeclEpilogueCertificate.toChecked
#print axioms StaticallyPreservedCDeclEpilogueCertificate.responseRelated
#print axioms StaticallyPreservedCDeclEpilogueCertificate.memoryFrame
#print axioms StaticallyPreservedCDeclEpilogueCertificate.path

end StageA.Relational.InterpreterKernelCdeclEpilogueStaticPreservation
