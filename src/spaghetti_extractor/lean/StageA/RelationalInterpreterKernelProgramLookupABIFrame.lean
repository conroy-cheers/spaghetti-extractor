import StageA.RelationalInterpreterKernelLookupNative
import StageA.RelationalInterpreterKernelOperationABIFrame

namespace StageA.Relational.InterpreterKernelProgramLookupABIFrame

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelLookupABI
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterKernelSummary

variable {pe : PE32} {imports : List PEImport}
  {relocations : List BaseRelocation}
  {tableOffset countOffset : Nat}
  {records : List ProgramRecord}

/-!
# ProgramLookup under a nested ABI frame

The native `programLookup` semantics are independent of the caller's concrete
stack address.  This adapter reconstructs the checked native ABI from one
`KernelOperationABIFrame.RequestFacts` witness.  It does not reuse the
canonical launch relation or assume that a nested ESP equals the launch ESP.
-/

theorem programLookupFrameInWorkspaceForRequest
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    {sourceRva : Nat} {before : MachineState}
    (request : KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before)
    (address : Word)
    (inside : programLookupFrameFootprint before.registers.esp address) :
    addressInSpan abi.parameters.writableWorkspace address := by
  have operationExact : frame.operation = .programLookup := by
    simpa [AbstractKernelRequest.operation] using request.cdecl.1.symm
  have espExact : before.registers.esp = frame.entryEsp :=
    request.cdecl.2.1
  have valid := request.frameValid
  unfold KernelOperationABIFrame.Valid at valid
  rw [operationExact] at valid
  rw [espExact] at inside
  exact valid.2.2.2.2 address inside

theorem programLookupStackHasFrameForRequest
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    {sourceRva : Nat} {before : MachineState}
    (request : KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before) :
    20 <= before.registers.esp.toNat := by
  have operationExact : frame.operation = .programLookup := by
    simpa [AbstractKernelRequest.operation] using request.cdecl.1.symm
  have espExact : before.registers.esp = frame.entryEsp :=
    request.cdecl.2.1
  have valid := request.frameValid
  unfold KernelOperationABIFrame.Valid at valid
  rw [operationExact] at valid
  rw [espExact]
  exact valid.2.2.2.1

theorem programLookupFrameAvoidsImageForRequest
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    {sourceRva : Nat} {before : MachineState}
    (request : KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before)
    (rva : Nat) (bounded : rva < pe.sizeOfImage) :
    ¬ programLookupFrameFootprint before.registers.esp
      (word32 (pe.imageBase + rva)) := by
  intro inside
  have workspace := programLookupFrameInWorkspaceForRequest frame abi request
    (word32 (pe.imageBase + rva)) inside
  let facts := ConcreteKernelABI.programLookupStaticFacts abi
  have imageAddressBounded : pe.imageBase + rva < 2 ^ 32 := by
    have imageBounded := facts.imageBounded
    omega
  have imageAddressExact :
      (word32 (pe.imageBase + rva)).toNat = pe.imageBase + rva := by
    simp [word32, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt imageAddressBounded]
  have disjoint := facts.workspaceImageDisjoint
  simp only [spanDisjoint, Bool.or_eq_true, decide_eq_true_eq, Span.stop]
    at disjoint
  unfold addressInSpan at workspace
  rcases workspace with
    ⟨workspaceLower, workspaceUpper, workspaceBounded⟩
  have workspaceLower' :
      abi.parameters.writableWorkspace.start <= pe.imageBase + rva := by
    simpa only [imageAddressExact] using workspaceLower
  have workspaceUpper' :
      pe.imageBase + rva < abi.parameters.writableWorkspace.stop := by
    simpa only [imageAddressExact] using workspaceUpper
  rcases disjoint with workspaceBefore | imageBefore
  · have beforeBase : pe.imageBase + rva < pe.imageBase :=
      Nat.lt_of_lt_of_le workspaceUpper' workspaceBefore
    exact (Nat.not_lt_of_ge (Nat.le_add_right pe.imageBase rva)) beforeBase
  · have afterImage : pe.imageBase + pe.sizeOfImage <= pe.imageBase + rva :=
      Nat.le_trans imageBefore workspaceLower'
    omega

theorem preservesLoadedSpanForFrame
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    {sourceRva : Nat} {before after : MachineState}
    {parameters : ProgramLookupTemplateParameters}
    (request : KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before)
    (returned : ProgramLookupNativeReturnState pe parameters records sourceRva
      before after)
    (span : Span)
    (loaded : LoadedSpanHolds pe relocations pe.imageBase span before.memory)
    (bounded : span.stop <= pe.sizeOfImage) :
    LoadedSpanHolds pe relocations pe.imageBase span after.memory := by
  intro offset offsetBefore expected decoded
  rw [returned.memoryFrame]
  · exact loaded offset offsetBefore expected decoded
  · have outside := programLookupFrameAvoidsImageForRequest frame abi request
      (span.start + offset) (by
      simp only [Span.stop] at bounded
      omega)
    simpa [word32, Nat.add_assoc, ← BitVec.ofNat_add] using outside

theorem preservesImageRead32ForFrame
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    {sourceRva : Nat} {before after : MachineState}
    {parameters : ProgramLookupTemplateParameters}
    (request : KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before)
    (returned : ProgramLookupNativeReturnState pe parameters records sourceRva
      before after)
    (rva : Nat) (bounded : rva + 4 <= pe.sizeOfImage) :
    Memory.read32 after.memory (word32 (pe.imageBase + rva)) =
      Memory.read32 before.memory (word32 (pe.imageBase + rva)) := by
  apply MemoryAgreesOutside.read32_of_bytesOutside returned.memoryFrame
  intro byte byteBefore
  have addressExact :
      word32 (pe.imageBase + rva) + word32 byte =
        word32 (pe.imageBase + (rva + byte)) := by
    simp [word32, ← BitVec.ofNat_add, Nat.add_assoc]
  change ¬ programLookupFrameFootprint before.registers.esp
    (word32 (pe.imageBase + rva) + word32 byte)
  rw [addressExact]
  exact programLookupFrameAvoidsImageForRequest frame abi request
    (rva + byte) (by omega)

theorem responseFactsForFrame
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    {function : KernelFunction}
    (certificate : ProgramLookupTemplateCertificate abi.program pe imports
      function)
    {sourceRva : Nat} {before after : MachineState}
    (request : KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before)
    (returned : ProgramLookupNativeReturnState pe certificate.parameters records
      sourceRva before after)
    (tableExact : certificate.parameters.tableRva = tableOffset) :
    KernelOperationABIFrame.ResponseFacts frame abi
      (.programLookup records sourceRva)
      (.programLookup
        (StageA.Relational.InterpreterKernel.lookupProgramRecord records
          sourceRva)) after [] := by
  have cdecl := request.cdecl
  rcases cdecl with
    ⟨operationExact, espExact, ebxExact, esiExact, ediExact, ebpExact,
      words, stackRange⟩
  simp only [KernelOperationABIFrame.requestArguments, WordsAt] at words
  refine {
    frameValid := request.frameValid
    cdecl := ?_
    directionFlagClear := returned.directionFlagPreserved.trans
      request.directionFlagClear
    candidateImage := ?_
    originalProgramTable := ?_
    payload := ?_
  }
  · unfold KernelOperationABIFrame.CDeclReturnHolds
    simp only [KernelOperationABIFrame.requestArguments, WordsAt]
    refine ⟨operationExact, ?_, ?_, ?_, ?_, ?_, ?_, ?_, trivial⟩
    · rw [returned.stackPopped, espExact]
      simp [word32]
    · exact returned.ebxPreserved.trans ebxExact
    · exact returned.esiPreserved.trans esiExact
    · exact returned.ediPreserved.trans ediExact
    · exact returned.framePointerRestored.trans ebpExact
    · rw [← espExact]
      have preserved :=
        programLookupNativeFrame_preservesRead32 before.registers.esp
          before.memory after.memory returned.memoryFrame 0 (by omega)
      simp [word32] at preserved
      rw [preserved, espExact]
      exact words.1
    · rw [← espExact]
      rw [programLookupNativeFrame_preservesRead32 before.registers.esp
        before.memory after.memory returned.memoryFrame 4 (by omega)]
      rw [espExact]
      exact words.2.1
  · intro rva size bytes immutable offset expected offsetBefore indexed
    rw [returned.memoryFrame]
    · exact request.candidateImage rva size bytes immutable offset expected
        offsetBefore indexed
    · simpa [Nat.add_assoc] using
        (programLookupFrameAvoidsImageForRequest frame abi request
          (rva + offset) (by
            have bounded := immutableRvaBytes_bounded immutable
            omega))
  · refine {
      tableSpan := preservesLoadedSpanForFrame frame abi request returned
        abi.tableSpan
        request.originalProgramTable.tableSpan (by
          let facts := ConcreteKernelABI.programLookupStaticFacts abi
          simpa [ConcreteKernelABI.tableSpan, Span.stop] using
            facts.tableBounded)
      countSpan := preservesLoadedSpanForFrame frame abi request returned
        abi.countSpan
        request.originalProgramTable.countSpan (by
          let facts := ConcreteKernelABI.programLookupStaticFacts abi
          simpa [ConcreteKernelABI.countSpan, Span.stop] using
            facts.countBounded)
      countWord := ?_
      sourceWords := ?_
    }
    · rw [preservesImageRead32ForFrame frame abi request returned countOffset
        (ConcreteKernelABI.programLookupStaticFacts abi).countBounded]
      exact request.originalProgramTable.countWord
    · intro index record recordAt
      have indexBefore : index < records.length :=
        List.getElem?_eq_some_iff.mp recordAt |>.1
      rw [Nat.add_assoc pe.imageBase tableOffset
        (index * transferRecordSize)]
      rw [preservesImageRead32ForFrame frame abi request returned
        (tableOffset + index * transferRecordSize)]
      · simpa [Nat.add_assoc] using
          request.originalProgramTable.sourceWords index record recordAt
      · let facts := ConcreteKernelABI.programLookupStaticFacts abi
        have tableBounded := facts.tableBounded
        have transferCountExact :=
          programTableCertificate_transferCount_eq_records_length
            abi.tableCertificate
        simp only [StageA.Relational.InterpreterKernelData.transferRecordSize]
          at tableBounded ⊢
        omega
  · change after.registers.eax =
        lookupResultPointer records pe.imageBase tableOffset sourceRva ∧
      ([] : List NativeExternalEvent) = []
    exact ⟨by
      rw [returned.eaxExact, tableExact]
      rfl, rfl⟩

noncomputable def programLookupNativeConcreteABIForFrame
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupNativeTemplateCertificate abi.program pe imports
      function)
    (tableExact : certificate.template.parameters.tableRva = tableOffset)
    (countExact : certificate.template.parameters.countRva = countOffset)
    (recordSourcesFit : programLookupRecordSourcesFit records = true) :
    ProgramLookupNativeConcreteABI pe (frame.relation abi) records
      abi.tableCertificate.transferCount certificate := {
  requestEntry := by
    intro requestRecords sourceRva before related
    change KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup requestRecords sourceRva) before at related
    have recordsExact : requestRecords = records := related.payload.1
    subst requestRecords
    have cdecl := related.cdecl
    rcases cdecl with
      ⟨operationExact, espExact, ebxExact, esiExact, ediExact, ebpExact,
        words, stackRange⟩
    simp only [KernelOperationABIFrame.requestArguments, WordsAt] at words
    refine ⟨rfl, ⟨{
      loaded := {
        sourceFits := related.payload.2
        transferCountExact :=
          programTableCertificate_transferCount_eq_records_length
            abi.tableCertificate
        stackHasFrame :=
          programLookupStackHasFrameForRequest frame abi related
        returnAddress := frame.returnAddress
        returnAddressLoaded := by simpa [espExact] using words.1
        sourceArgumentLoaded := by simpa [espExact] using words.2.1
        countLoaded := by
          rw [countExact]
          exact related.originalProgramTable.countWord
        tableLoaded := by
          intro index record recordAt
          rw [tableExact]
          simpa [programLookupTableAddress, Nat.add_assoc] using
            related.originalProgramTable.sourceWords index record
              (listAt?_eq_some_to_getElem?_eq_some records index record
                recordAt)
        frameDisjointFromTable := by
          intro frameOffset tableIndex frameBefore tableBefore
          apply bne_iff_ne.mpr
          intro overlap
          have inside : programLookupFrameFootprint before.registers.esp
              (programLookupFrameByte before.registers.esp frameOffset) :=
            ⟨frameOffset, frameBefore, rfl⟩
          have tableRvaBefore :
              tableOffset + tableIndex * transferRecordSize <
                pe.sizeOfImage := by
            let facts := ConcreteKernelABI.programLookupStaticFacts abi
            have tableBounded := facts.tableBounded
            simp only [
              StageA.Relational.InterpreterKernelData.transferRecordSize]
              at tableBounded ⊢
            omega
          apply programLookupFrameAvoidsImageForRequest frame abi related
            (tableOffset + tableIndex * transferRecordSize) tableRvaBefore
          have addressExact :
              word32 (pe.imageBase +
                (tableOffset + tableIndex * transferRecordSize)) =
                programLookupFrameByte before.registers.esp frameOffset := by
            rw [← tableExact]
            simpa [programLookupTableAddress, Nat.add_assoc] using overlap.symm
          rw [addressExact]
          exact inside
      }
      transferCountFits := by
        let facts := ConcreteKernelABI.programLookupStaticFacts abi
        have tableBounded := facts.tableBounded
        have imageBounded := facts.imageBounded
        simp only [transferRecordSize] at tableBounded
        omega
      recordSourcesFit
      frameDisjointFromCount := by
        intro frameOffset byteOffset frameBefore byteBefore overlap
        have inside : programLookupFrameFootprint before.registers.esp
            (programLookupFrameByte before.registers.esp frameOffset) :=
          ⟨frameOffset, frameBefore, rfl⟩
        apply programLookupFrameAvoidsImageForRequest frame abi related
          (countOffset + byteOffset) (by
            have bounded :=
              (ConcreteKernelABI.programLookupStaticFacts abi).countBounded
            omega)
        have addressExact :
            word32 (pe.imageBase + (countOffset + byteOffset)) =
              programLookupFrameByte before.registers.esp frameOffset := by
          rw [← countExact]
          simpa [word32, Nat.add_assoc] using overlap.symm
        rw [addressExact]
        exact inside
      frameDisjointFromTable := by
        intro frameOffset tableIndex byteOffset frameBefore indexBefore
          byteBefore overlap
        have inside : programLookupFrameFootprint before.registers.esp
            (programLookupFrameByte before.registers.esp frameOffset) :=
          ⟨frameOffset, frameBefore, rfl⟩
        apply programLookupFrameAvoidsImageForRequest frame abi related
          (tableOffset + tableIndex * transferRecordSize + byteOffset) (by
            let facts := ConcreteKernelABI.programLookupStaticFacts abi
            have tableBounded := facts.tableBounded
            have transferCountExact :=
              programTableCertificate_transferCount_eq_records_length
                abi.tableCertificate
            simp only [
              StageA.Relational.InterpreterKernelData.transferRecordSize]
              at tableBounded ⊢
            omega)
        have addressExact :
            word32 (pe.imageBase +
              (tableOffset + tableIndex * transferRecordSize + byteOffset)) =
                programLookupFrameByte before.registers.esp frameOffset := by
          rw [← tableExact]
          simpa [programLookupTableAddress, word32, Nat.add_assoc,
            ← BitVec.ofNat_add] using overlap.symm
        rw [addressExact]
        exact inside
    }⟩⟩
  responseExit := by
    intro sourceRva before after related returned
    change KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before at related
    exact responseFactsForFrame frame abi certificate.template related returned
      tableExact
  scratchContainsFrame := by
    intro sourceRva before address related loaded inside
    change KernelOperationABIFrame.RequestFacts frame abi
      (.programLookup records sourceRva) before at related
    exact programLookupFrameInWorkspaceForRequest frame abi related address
      inside
}

#print axioms
  programLookupFrameInWorkspaceForRequest
#print axioms
  programLookupFrameAvoidsImageForRequest
#print axioms responseFactsForFrame
#print axioms programLookupNativeConcreteABIForFrame

end StageA.Relational.InterpreterKernelProgramLookupABIFrame
