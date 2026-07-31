import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterKernelSummary

namespace StageA.Relational.InterpreterKernelLookupABI

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterKernelLoop
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.SymbolicSoundness

/-! Concrete cdecl adapter for the reflected `programLookup` implementation.
Every dynamic premise is retained in `ProgramLookupConcreteEntry`, which is
constructed only from `ABIRequestFacts`.  The adapter therefore derives result,
preservation, and scratch facts for that exact request state. -/

/-! Static facts projected from the single checked ABI Boolean. -/

structure ProgramLookupStaticFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) : Prop where
  imageBounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32
  stackReserve : 4096 <= abi.parameters.stackReserve
  workspaceCapacity :
    abi.parameters.requiredBytes abi.engineLayout <=
      abi.parameters.writableWorkspace.size
  workspaceBounded : abi.parameters.writableWorkspace.stop <= 2 ^ 32
  workspaceImageDisjoint :
    spanDisjoint abi.parameters.writableWorkspace
      { start := pe.imageBase, size := pe.sizeOfImage } = true
  tableBounded :
    tableOffset + abi.tableCertificate.transferCount * transferRecordSize <=
      pe.sizeOfImage
  countBounded : countOffset + 4 <= pe.sizeOfImage

theorem ConcreteKernelABI.programLookupStaticFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) : ProgramLookupStaticFacts abi := by
  have checked := abi.staticChecked
  simp only [KernelABIParameters.checked, Bool.and_eq_true,
    decide_eq_true_eq] at checked
  refine {
    imageBounded := checked.1.1.1.1.1.1.1.1.1.1.2
    stackReserve := checked.1.1.1.1.1.1.1.2
    workspaceCapacity := checked.1.1.1.1.1.1.2
    workspaceBounded := checked.1.1.1.1.1.2
    workspaceImageDisjoint := checked.1.1.1.1.2
    tableBounded := checked.1.2
    countBounded := checked.2
  }

theorem programLookupFrameInWorkspace
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord) (sourceRva : Nat)
    (before : MachineState)
    (entry : ABIRequestFacts abi
      (.programLookup requestRecords sourceRva) before)
    (address : Word)
    (inFrame : programLookupFrameFootprint before.registers.esp address) :
    addressInSpan abi.parameters.writableWorkspace address := by
  let facts := ConcreteKernelABI.programLookupStaticFacts abi
  have cdecl := entry.cdecl
  change CDeclEntryFrameHolds abi (.programLookup requestRecords sourceRva)
    before at cdecl
  rcases cdecl with ⟨espExact, preserved, words, stackRange⟩
  simp only [AbstractKernelRequest.operation] at espExact stackRange
  rcases inFrame with ⟨offset, offsetBefore, rfl⟩
  have reserveLower := facts.stackReserve
  have stackReservePositive : 0 < abi.parameters.stackReserve := by
    omega
  have stackStartBounded :
      abi.parameters.stackStart abi.engineLayout .programLookup +
          abi.parameters.stackReserve <=
        abi.parameters.writableWorkspace.stop := by
    have capacity := facts.workspaceCapacity
    simp only [KernelABIParameters.stackStart,
      KernelABIParameters.requiredBytes, KernelABIParameters.fixedBytes,
      operationIndex, Span.stop] at capacity ⊢
    omega
  have entryAddressBounded :
      abi.parameters.stackStart abi.engineLayout .programLookup +
          abi.parameters.stackReserve - 20 < 2 ^ 32 := by
    have := facts.workspaceBounded
    omega
  have frameAddressBounded :
      abi.parameters.stackStart abi.engineLayout .programLookup +
          abi.parameters.stackReserve - 40 + offset < 2 ^ 32 := by
    omega
  have frameAddressExact :
      (programLookupFrameByte before.registers.esp offset).toNat =
        abi.parameters.stackStart abi.engineLayout .programLookup +
          abi.parameters.stackReserve - 40 + offset := by
    rw [espExact]
    simp only [KernelABIParameters.entryEsp, programLookupFrameByte, word32,
      BitVec.toNat_add, BitVec.toNat_ofNat]
    rw [Nat.mod_eq_of_lt entryAddressBounded]
    have subtractionWord : (2 ^ 32 - 20 + offset) % 2 ^ 32 =
        2 ^ 32 - 20 + offset := by
      apply Nat.mod_eq_of_lt
      omega
    rw [subtractionWord]
    have sumExact :
        abi.parameters.stackStart abi.engineLayout .programLookup +
              abi.parameters.stackReserve - 20 + (2 ^ 32 - 20 + offset) =
          2 ^ 32 +
            (abi.parameters.stackStart abi.engineLayout .programLookup +
              abi.parameters.stackReserve - 40 + offset) := by
      omega
    rw [sumExact, Nat.add_mod, Nat.mod_self, Nat.zero_add,
      Nat.mod_eq_of_lt frameAddressBounded]
    rw [Nat.mod_eq_of_lt frameAddressBounded]
  constructor
  · rw [frameAddressExact]
    simp only [KernelABIParameters.stackStart, operationIndex]
    omega
  constructor
  · rw [frameAddressExact]
    omega
  · exact facts.workspaceBounded

theorem programLookupStackHasFrame
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord) (sourceRva : Nat)
    (before : MachineState)
    (entry : ABIRequestFacts abi
      (.programLookup requestRecords sourceRva) before) :
    20 <= before.registers.esp.toNat := by
  let facts := ConcreteKernelABI.programLookupStaticFacts abi
  have cdecl := entry.cdecl
  change CDeclEntryFrameHolds abi (.programLookup requestRecords sourceRva)
    before at cdecl
  have espExact := cdecl.1
  simp only [AbstractKernelRequest.operation] at espExact
  rw [espExact]
  simp only [KernelABIParameters.entryEsp, KernelABIParameters.stackStart,
    operationIndex, word32, BitVec.toNat_ofNat]
  simp only [Nat.zero_mul, Nat.add_zero]
  have stackEndBounded :
      abi.parameters.writableWorkspace.start +
          abi.parameters.fixedBytes abi.engineLayout +
          abi.parameters.stackReserve <= 2 ^ 32 := by
    have capacity := facts.workspaceCapacity
    have bounded := facts.workspaceBounded
    simp only [KernelABIParameters.requiredBytes, Span.stop] at capacity bounded
    omega
  have reserveLower := facts.stackReserve
  change 20 <= (abi.parameters.writableWorkspace.start +
    abi.parameters.fixedBytes abi.engineLayout +
    abi.parameters.stackReserve - 20) % 2 ^ 32
  rw [Nat.mod_eq_of_lt (by omega :
    abi.parameters.writableWorkspace.start +
        abi.parameters.fixedBytes abi.engineLayout +
        abi.parameters.stackReserve - 20 < 2 ^ 32)]
  omega

theorem programLookupFrameAvoidsStackSuffix
    (stackPointer : Word) (frameOffset suffixOffset : Nat)
    (frameBefore : frameOffset < 20) (suffixBefore : suffixOffset < 8) :
    stackPointer + word32 suffixOffset ≠
      programLookupFrameByte stackPointer frameOffset := by
  intro overlap
  have cancelled := congrArg (fun value => value - stackPointer) overlap
  simp only [programLookupFrameByte, word32, BitVec.add_comm stackPointer,
    BitVec.add_sub_cancel] at cancelled
  have wordsEqual := congrArg BitVec.toNat cancelled
  simp only [BitVec.toNat_ofNat] at wordsEqual
  rw [Nat.mod_eq_of_lt (by omega : suffixOffset < 2 ^ 32)] at wordsEqual
  rw [Nat.mod_eq_of_lt (by omega :
    2 ^ 32 - 20 + frameOffset < 2 ^ 32)] at wordsEqual
  omega

theorem programLookupFrameMemory_preservesStackSuffix
    (stackPointer : Word) (memory : Memory) (suffixOffset : Nat)
    (suffixBefore : suffixOffset < 8) :
    programLookupTemplateFrameMemory stackPointer memory
        (stackPointer + word32 suffixOffset) =
      memory (stackPointer + word32 suffixOffset) := by
  apply programLookupTemplateFrameMemory_agreesOutside
  intro inFrame
  rcases inFrame with ⟨frameOffset, frameBefore, overlap⟩
  exact programLookupFrameAvoidsStackSuffix stackPointer frameOffset suffixOffset
    frameBefore suffixBefore overlap

theorem programLookupFrameMemory_preservesRead32
    (stackPointer : Word) (memory : Memory) (suffixOffset : Nat)
    (suffixEnd : suffixOffset + 4 <= 8) :
    Memory.read32 (programLookupTemplateFrameMemory stackPointer memory)
        (stackPointer + word32 suffixOffset) =
      Memory.read32 memory (stackPointer + word32 suffixOffset) := by
  unfold Memory.read32
  have address (extra : Nat) :
      (stackPointer + word32 suffixOffset) + word32 extra =
        stackPointer + word32 (suffixOffset + extra) := by
    unfold word32
    rw [BitVec.add_assoc, ← BitVec.ofNat_add]
  have address1 :
      (stackPointer + word32 suffixOffset) + BitVec.ofNat 32 1 =
        stackPointer + word32 (suffixOffset + 1) := by
    simpa [word32] using address 1
  have address2 :
      (stackPointer + word32 suffixOffset) + BitVec.ofNat 32 2 =
        stackPointer + word32 (suffixOffset + 2) := by
    simpa [word32] using address 2
  have address3 :
      (stackPointer + word32 suffixOffset) + BitVec.ofNat 32 3 =
        stackPointer + word32 (suffixOffset + 3) := by
    simpa [word32] using address 3
  rw [programLookupFrameMemory_preservesStackSuffix stackPointer memory
      suffixOffset (by omega)]
  rw [address1, programLookupFrameMemory_preservesStackSuffix stackPointer memory
      (suffixOffset + 1) (by omega)]
  rw [address2, programLookupFrameMemory_preservesStackSuffix stackPointer memory
      (suffixOffset + 2) (by omega)]
  rw [address3, programLookupFrameMemory_preservesStackSuffix stackPointer memory
      (suffixOffset + 3) (by omega)]

theorem programLookupReturnedFrameHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (before : MachineState)
    (entry : ABIRequestFacts abi (.programLookup records sourceRva) before) :
    CDeclReturnFrameHolds abi (.programLookup records sourceRva)
      (programLookupTemplateReturnedState pe tableOffset records sourceRva
        before) := by
  have cdecl := entry.cdecl
  change CDeclEntryFrameHolds abi (.programLookup records sourceRva) before at cdecl
  rcases cdecl with ⟨espExact, preserved, words, stackRange⟩
  simp only [AbstractKernelRequest.operation] at espExact words
  unfold CDeclReturnFrameHolds
  simp only [AbstractKernelRequest.operation]
  constructor
  · simp [programLookupTemplateReturnedState, Registers.set, espExact, word32]
  constructor
  · simpa [programLookupTemplateReturnedState, preservedRegistersAreCanonical,
      Registers.set] using preserved
  · simp only [requestArguments, WordsAt] at words ⊢
    constructor
    · simp only [programLookupTemplateReturnedState]
      rw [← espExact]
      have preservedRead := programLookupFrameMemory_preservesRead32
        before.registers.esp before.memory 0 (by omega)
      simp [word32] at preservedRead
      rw [preservedRead, espExact]
      exact words.1
    constructor
    · simp only [programLookupTemplateReturnedState]
      rw [← espExact]
      rw [programLookupFrameMemory_preservesRead32
        before.registers.esp before.memory 4 (by omega)]
      rw [espExact]
      exact words.2.1
    · trivial

theorem programLookupFrameAvoidsImage
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord) (sourceRva : Nat)
    (before : MachineState)
    (entry : ABIRequestFacts abi
      (.programLookup requestRecords sourceRva) before)
    (rva : Nat) (rvaBefore : rva < pe.sizeOfImage) :
    ¬ programLookupFrameFootprint before.registers.esp
      (word32 (pe.imageBase + rva)) := by
  intro inFrame
  have workspace := programLookupFrameInWorkspace abi requestRecords sourceRva
    before entry (word32 (pe.imageBase + rva)) inFrame
  let facts := ConcreteKernelABI.programLookupStaticFacts abi
  have imageBound := facts.imageBounded
  have imageAddressBounded : pe.imageBase + rva < 2 ^ 32 := by
    omega
  have imageAddressExact : (word32 (pe.imageBase + rva)).toNat =
      pe.imageBase + rva := by
    simp [word32, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt imageAddressBounded]
  have disjoint := facts.workspaceImageDisjoint
  simp only [spanDisjoint, Bool.or_eq_true, decide_eq_true_eq, Span.stop] at disjoint
  unfold addressInSpan at workspace
  rcases workspace with ⟨workspaceLower, workspaceUpper, workspaceBounded⟩
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

theorem programLookupFrameMemory_preservesLoadedSpan
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord) (sourceRva : Nat)
    (before : MachineState)
    (entry : ABIRequestFacts abi
      (.programLookup requestRecords sourceRva) before)
    (span : Span)
    (loaded : LoadedSpanHolds pe relocations pe.imageBase span before.memory)
    (spanBounded : span.stop <= pe.sizeOfImage) :
    LoadedSpanHolds pe relocations pe.imageBase span
      (programLookupTemplateFrameMemory before.registers.esp before.memory) := by
  intro offset offsetBefore expected expectedLoaded
  rw [programLookupTemplateFrameMemory_agreesOutside]
  · exact loaded offset offsetBefore expected expectedLoaded
  · simpa [Nat.add_assoc] using
      (programLookupFrameAvoidsImage abi requestRecords sourceRva before entry
        (span.start + offset) (by
          simp only [Span.stop] at spanBounded
          omega))

theorem immutableRvaBytesOne_bounded
    (pe : PE32) (imports : List PEImport) (rva raw : Nat)
    (exactBytes : immutableRvaBytes pe imports rva 1 = some [raw]) :
    rva < pe.sizeOfImage := by
  have bounded := immutableRvaBytes_bounded exactBytes
  omega

theorem programLookupFrameMemory_preservesCandidateImage
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (before : MachineState)
    (entry : ABIRequestFacts abi (.programLookup records sourceRva) before) :
    LoadedCandidateImageMemory pe imports relocations
      (programLookupTemplateFrameMemory before.registers.esp before.memory) := by
  intro rva size bytes immutable offset expected offsetBefore indexed
  rw [programLookupTemplateFrameMemory_agreesOutside]
  · exact entry.candidateImage rva size bytes immutable offset expected
      offsetBefore indexed
  · simpa [Nat.add_assoc] using
      (programLookupFrameAvoidsImage abi records sourceRva before entry
        (rva + offset) (by
          have bounded := immutableRvaBytes_bounded immutable
          omega))

theorem programLookupFrameMemory_preservesImageRead32
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (before : MachineState)
    (entry : ABIRequestFacts abi (.programLookup records sourceRva) before)
    (rva : Nat) (rvaBounded : rva + 4 <= pe.sizeOfImage) :
    Memory.read32
        (programLookupTemplateFrameMemory before.registers.esp before.memory)
        (word32 (pe.imageBase + rva)) =
      Memory.read32 before.memory (word32 (pe.imageBase + rva)) := by
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
  rw [programLookupTemplateFrameMemory_agreesOutside]
  · rw [address1, programLookupTemplateFrameMemory_agreesOutside]
    · rw [address2, programLookupTemplateFrameMemory_agreesOutside]
      · rw [address3, programLookupTemplateFrameMemory_agreesOutside]
        exact programLookupFrameAvoidsImage abi records sourceRva before entry
          (rva + 3) (by omega)
      · simpa [address2] using
          (programLookupFrameAvoidsImage abi records sourceRva before entry
            (rva + 2) (by omega))
    · simpa [address1] using
        (programLookupFrameAvoidsImage abi records sourceRva before entry
          (rva + 1) (by omega))
  · exact programLookupFrameAvoidsImage abi records sourceRva before entry rva
      (by omega)

theorem programLookupFrameMemory_preservesProgramTable
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (before : MachineState)
    (entry : ABIRequestFacts abi (.programLookup records sourceRva) before) :
    LoadedOriginalProgramTable abi
      (programLookupTemplateFrameMemory before.registers.esp before.memory) := by
  refine {
    tableSpan := ?_
    countSpan := ?_
    countWord := ?_
    sourceWords := ?_
  }
  · apply programLookupFrameMemory_preservesLoadedSpan abi records sourceRva
      before entry abi.tableSpan entry.originalProgramTable.tableSpan
    let facts := ConcreteKernelABI.programLookupStaticFacts abi
    simpa [ConcreteKernelABI.tableSpan, Span.stop] using facts.tableBounded
  · apply programLookupFrameMemory_preservesLoadedSpan abi records sourceRva
      before entry abi.countSpan entry.originalProgramTable.countSpan
    let facts := ConcreteKernelABI.programLookupStaticFacts abi
    simpa [ConcreteKernelABI.countSpan, Span.stop] using facts.countBounded
  · rw [programLookupFrameMemory_preservesImageRead32 abi sourceRva before
      entry countOffset]
    · exact entry.originalProgramTable.countWord
    · exact (ConcreteKernelABI.programLookupStaticFacts abi).countBounded
  · intro index record recordAt
    have indexBefore : index < records.length :=
      List.getElem?_eq_some_iff.mp recordAt |>.1
    have transferCountExact :=
      programTableCertificate_transferCount_eq_records_length
        abi.tableCertificate
    rw [Nat.add_assoc pe.imageBase tableOffset
      (index * transferRecordSize)]
    rw [programLookupFrameMemory_preservesImageRead32 abi sourceRva before entry
      (tableOffset + index * transferRecordSize)]
    · simpa [Nat.add_assoc] using
        entry.originalProgramTable.sourceWords index record recordAt
    · let facts := ConcreteKernelABI.programLookupStaticFacts abi
      have tableBounded := facts.tableBounded
      simp only [transferRecordSize] at tableBounded ⊢
      omega

theorem listAt?_eq_some_to_getElem?_eq_some
    {Value : Type} (values : List Value) (index : Nat) (value : Value)
    (found : listAt? values index = some value) :
    values[index]? = some value := by
  induction values generalizing index with
  | nil => simp [listAt?] at found
  | cons head tail induction =>
      cases index with
      | zero => simpa [listAt?] using found
      | succ index =>
          simp only [listAt?] at found
          simpa using induction index found

structure ConcreteProgramLookupInvocation
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupTemplateCertificate abi.program pe imports
      function)
    (sourceRva : Nat) (before : MachineState) where
  entry : ProgramLookupConcreteEntry pe (ConcreteKernelABI.relation abi) records
    abi.tableCertificate.transferCount sourceRva before certificate
  response : ABIResponseFacts abi (.programLookup records sourceRva)
    (.programLookup
      (StageA.Relational.InterpreterKernel.lookupProgramRecord records sourceRva))
    (programLookupTemplateReturnedState pe certificate.parameters.tableRva
      records sourceRva before) []
  frameInScratch : forall address,
    programLookupFrameFootprint before.registers.esp address ->
      abi.scratchFootprint (.programLookup records sourceRva) address

noncomputable def concreteProgramLookupInvocation
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupTemplateCertificate abi.program pe imports
      function)
    (tableExact : certificate.parameters.tableRva = tableOffset)
    (countExact : certificate.parameters.countRva = countOffset)
    (sourceRva : Nat) (before : MachineState)
    (request : ABIRequestFacts abi (.programLookup records sourceRva) before) :
    ConcreteProgramLookupInvocation abi certificate sourceRva before := by
  have cdecl := request.cdecl
  change CDeclEntryFrameHolds abi (.programLookup records sourceRva) before at cdecl
  rcases cdecl with ⟨espExact, preserved, words, stackRange⟩
  simp only [AbstractKernelRequest.operation, requestArguments, WordsAt] at words
  have loadedEntry : ProgramLookupLoadedEntry pe certificate.parameters records
      abi.tableCertificate.transferCount sourceRva before := by
    refine {
      sourceFits := request.payload.2
      transferCountExact :=
        programTableCertificate_transferCount_eq_records_length
          abi.tableCertificate
      stackHasFrame := programLookupStackHasFrame abi records sourceRva before request
      returnAddress := abi.parameters.returnAddress pe
      returnAddressLoaded := ?_
      sourceArgumentLoaded := ?_
      countLoaded := ?_
      tableLoaded := ?_
      frameDisjointFromTable := ?_
    }
    · simpa [espExact] using words.1
    · simpa [espExact] using words.2.1
    · rw [countExact]
      exact request.originalProgramTable.countWord
    · intro index record recordAt
      rw [tableExact]
      simpa [programLookupTableAddress, Nat.add_assoc] using
        request.originalProgramTable.sourceWords index record
          (listAt?_eq_some_to_getElem?_eq_some records index record recordAt)
    · intro frameOffset tableIndex frameBefore tableBefore
      apply bne_iff_ne.mpr
      intro overlap
      have inFrame : programLookupFrameFootprint before.registers.esp
          (programLookupFrameByte before.registers.esp frameOffset) :=
        ⟨frameOffset, frameBefore, rfl⟩
      have tableRvaBefore :
          tableOffset + tableIndex * transferRecordSize < pe.sizeOfImage := by
        let facts := ConcreteKernelABI.programLookupStaticFacts abi
        have tableBounded := facts.tableBounded
        simp only [transferRecordSize] at tableBounded ⊢
        omega
      have tableAddressExact :
          programLookupFrameByte before.registers.esp frameOffset =
            word32 (pe.imageBase +
              (tableOffset + tableIndex * transferRecordSize)) := by
        rw [tableExact] at overlap
        simpa [programLookupTableAddress, Nat.add_assoc] using overlap
      apply programLookupFrameAvoidsImage abi records sourceRva before request
        (tableOffset + tableIndex * transferRecordSize) tableRvaBefore
      rw [← tableAddressExact]
      exact inFrame
  have response : ABIResponseFacts abi (.programLookup records sourceRva)
      (.programLookup
        (StageA.Relational.InterpreterKernel.lookupProgramRecord records sourceRva))
      (programLookupTemplateReturnedState pe certificate.parameters.tableRva
        records sourceRva before) [] := by
    rw [tableExact]
    refine {
      cdecl := programLookupReturnedFrameHolds abi sourceRva before request
      directionFlagClear := ?_
      candidateImage :=
        programLookupFrameMemory_preservesCandidateImage abi sourceRva before request
      originalProgramTable :=
        programLookupFrameMemory_preservesProgramTable abi sourceRva before request
      payload := ?_
    }
    · simpa [DirectionFlagClear, programLookupTemplateReturnedState] using
        request.directionFlagClear
    change
      (programLookupTemplateReturnedState pe tableOffset records sourceRva before).registers.eax =
          lookupResultPointer records pe.imageBase tableOffset sourceRva ∧
        ([] : List NativeExternalEvent) = []
    constructor
    · simp [programLookupTemplateReturnedState, programLookupReturnWord,
        Registers.set]
    · rfl
  have concreteEntry : ProgramLookupConcreteEntry pe
      (ConcreteKernelABI.relation abi) records
      abi.tableCertificate.transferCount sourceRva before certificate := {
    requestRelated := request
    loaded := loadedEntry
  }
  refine {
    entry := concreteEntry
    response
    frameInScratch := ?_
  }
  intro address inFrame
  change addressInSpan abi.parameters.writableWorkspace address
  exact programLookupFrameInWorkspace abi records sourceRva before request address
    inFrame

/-! Exact constructor for the shared `ProgramLookupConcreteABI`.  Every exit
and frame proof is rebuilt from the request relation retained by the entry. -/
noncomputable def ConcreteKernelABI.programLookupConcreteABI
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupTemplateCertificate abi.program pe imports
      function)
    (tableExact : certificate.parameters.tableRva = tableOffset)
    (countExact : certificate.parameters.countRva = countOffset) :
    ProgramLookupConcreteABI pe (ConcreteKernelABI.relation abi) records
      abi.tableCertificate.transferCount certificate := {
  requestEntry := by
    intro requestRecords sourceRva before related
    change ABIRequestFacts abi (.programLookup requestRecords sourceRva) before
      at related
    have recordsExact : requestRecords = records := related.payload.1
    subst requestRecords
    let invocation := concreteProgramLookupInvocation abi certificate tableExact
      countExact sourceRva before related
    exact ⟨rfl, ⟨invocation.entry⟩⟩
  responseExit := by
    intro sourceRva before entry
    have request := entry.requestRelated
    change ABIRequestFacts abi (.programLookup records sourceRva) before at request
    let invocation := concreteProgramLookupInvocation abi certificate tableExact
      countExact sourceRva before request
    exact invocation.response
  scratchContainsFrame := by
    intro sourceRva before address entry inFrame
    have request := entry.requestRelated
    change ABIRequestFacts abi (.programLookup records sourceRva) before at request
    let invocation := concreteProgramLookupInvocation abi certificate tableExact
      countExact sourceRva before request
    exact invocation.frameInScratch address inFrame
}

theorem ConcreteKernelABI.programLookupConcreteABISpecializes
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (certificate : ProgramLookupTemplateCertificate abi.program pe imports
      function)
    (tableExact : certificate.parameters.tableRva = tableOffset)
    (countExact : certificate.parameters.countRva = countOffset) :
    Nonempty (ProgramLookupConcreteABI pe (ConcreteKernelABI.relation abi)
      records abi.tableCertificate.transferCount certificate) :=
  ⟨ConcreteKernelABI.programLookupConcreteABI abi certificate tableExact
    countExact⟩

/-! All summary fields except the concrete ABI adapter.  Generated modules can
construct this core from exact PE/template/data evidence, then use
`withConcreteABI` to populate the authoritative `KernelFunctionSummary` field. -/
structure KernelFunctionSummaryCore
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (function : KernelFunction) where
  candidateParsed : parsePE32Tree pe.bytes = some pe
  templateCertificate :
    ProgramLookupTemplateCertificate abi.program pe imports function
  tableParameterExact : templateCertificate.parameters.tableRva = tableOffset
  countParameterExact : templateCertificate.parameters.countRva = countOffset
  instructionDecodes : ExactDecodeInventory pe function.instructions
  sourceRvasSorted : sourceRvasStrictlySorted records
  entryRvaExact : abi.program.functionEntry? .programLookup =
    some templateCertificate.parameters.entryRva

noncomputable def KernelFunctionSummaryCore.withConcreteABI
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {function : KernelFunction}
    (core : KernelFunctionSummaryCore abi function) :
    KernelFunctionSummary abi.program pe imports
      (ConcreteKernelABI.relation abi) relocations tableOffset countOffset records
      function := {
  candidateParsed := core.candidateParsed
  templateCertificate := core.templateCertificate
  tableParameterExact := core.tableParameterExact
  countParameterExact := core.countParameterExact
  instructionDecodes := core.instructionDecodes
  dataCertificate := abi.tableCertificate
  transferCountExact := programTableCertificate_transferCount_eq_records_length
    abi.tableCertificate
  sourceRvasSorted := core.sourceRvasSorted
  entryRvaExact := core.entryRvaExact
  concreteABI := ConcreteKernelABI.programLookupConcreteABI abi
    core.templateCertificate core.tableParameterExact core.countParameterExact
}

theorem KernelFunctionSummaryCore.concreteABISpecializes
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {function : KernelFunction}
    (core : KernelFunctionSummaryCore abi function) :
    Nonempty (KernelFunctionSummary abi.program pe imports
      (ConcreteKernelABI.relation abi) relocations tableOffset countOffset records
      function) :=
  ⟨core.withConcreteABI⟩

noncomputable def KernelFunctionSummary.concreteLookupInvocation
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord} {function : KernelFunction}
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (summary : KernelFunctionSummary abi.program pe imports
      (ConcreteKernelABI.relation abi) relocations tableOffset countOffset records
      function)
    (sourceRva : Nat) (before : MachineState)
    (request : ABIRequestFacts abi (.programLookup records sourceRva) before) :
    ConcreteProgramLookupInvocation abi summary.templateCertificate sourceRva
      before := by
  exact concreteProgramLookupInvocation abi summary.templateCertificate
    summary.tableParameterExact summary.countParameterExact sourceRva before
    request

#print axioms ConcreteKernelABI.programLookupStaticFacts
#print axioms programLookupFrameInWorkspace
#print axioms programLookupReturnedFrameHolds
#print axioms programLookupFrameMemory_preservesProgramTable
#print axioms concreteProgramLookupInvocation
#print axioms ConcreteKernelABI.programLookupConcreteABI
#print axioms ConcreteKernelABI.programLookupConcreteABISpecializes
#print axioms KernelFunctionSummaryCore.withConcreteABI
#print axioms KernelFunctionSummaryCore.concreteABISpecializes
#print axioms KernelFunctionSummary.concreteLookupInvocation

end StageA.Relational.InterpreterKernelLookupABI
