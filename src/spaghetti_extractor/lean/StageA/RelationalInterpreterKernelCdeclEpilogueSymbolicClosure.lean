import StageA.RelationalInterpreterKernelCdeclEpilogue

namespace StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterNativeWorld

/-!
# Symbolic closure for checked cdecl epilogues

This module turns one exact decoded execution summary and its ABI frame facts
into the mechanical fields of `CheckedCDeclEpilogueCertificate`.  In
particular, callers do not submit a return word, a final register/ESP summary,
or an independently chosen finite write footprint.

The symbolic summary is tied to `ExactComputedCDeclEpilogue.returnedState`,
which is itself computed by the exact candidate executor.  Loaded-image/table
preservation and the typed response payload remain explicit because they may
depend on the surrounding operation and external environment.
-/

structure CDeclSymbolicFrameExpressions where
  callerEsp : Expr
  savedEbx : Expr
  savedEsi : Expr
  savedEdi : Expr
  savedEbp : Expr
deriving Repr, DecidableEq

def CDeclSymbolicFrameExpressions.checked
    (frame : CDeclSymbolicFrameExpressions)
    (behavior : SymbolicBehavior) : Bool :=
  behavior.registers.ebx == frame.savedEbx &&
    behavior.registers.esi == frame.savedEsi &&
    behavior.registers.edi == frame.savedEdi &&
    behavior.registers.ebp == frame.savedEbp &&
    behavior.registers.esp == frame.callerEsp.offset 4 &&
    behavior.outcome == some (.returned (.read32 frame.callerEsp))

structure CDeclSymbolicShape
    (frame : CDeclSymbolicFrameExpressions)
    (behavior : SymbolicBehavior) : Prop where
  ebx : behavior.registers.ebx = frame.savedEbx
  esi : behavior.registers.esi = frame.savedEsi
  edi : behavior.registers.edi = frame.savedEdi
  ebp : behavior.registers.ebp = frame.savedEbp
  esp : behavior.registers.esp = frame.callerEsp.offset 4
  outcome : behavior.outcome =
    some (.returned (.read32 frame.callerEsp))

theorem CDeclSymbolicFrameExpressions.shape_of_checked
    (frame : CDeclSymbolicFrameExpressions)
    (behavior : SymbolicBehavior)
    (checked : frame.checked behavior = true) :
    CDeclSymbolicShape frame behavior := by
  simp only [CDeclSymbolicFrameExpressions.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact {
    ebx := checked.1.1.1.1.1
    esi := checked.1.1.1.1.2
    edi := checked.1.1.1.2
    ebp := checked.1.1.2
    esp := checked.1.2
    outcome := checked.2
  }

def symbolicWriteBytes (behavior : SymbolicBehavior)
    (input : MachineState) : List Word :=
  behavior.writes.flatMap fun write =>
    wordByteAddresses (write.1.eval input)

def deduplicateWords : List Word -> List Word
  | [] => []
  | head :: tail =>
      let deduplicated := deduplicateWords tail
      if head ∈ deduplicated then deduplicated else head :: deduplicated

theorem deduplicateWords_nodup (values : List Word) :
    (deduplicateWords values).Nodup := by
  induction values with
  | nil => exact List.nodup_nil
  | cons head tail induction =>
      simp only [deduplicateWords]
      split
      · exact induction
      · apply List.nodup_cons.mpr
        exact ⟨by assumption, induction⟩

theorem mem_deduplicateWords (address : Word) (values : List Word) :
    address ∈ deduplicateWords values ↔ address ∈ values := by
  induction values with
  | nil => simp [deduplicateWords]
  | cons value rest induction =>
      simp only [deduplicateWords]
      split
      · rename_i present
        constructor
        · intro member
          exact List.mem_cons_of_mem value (induction.mp member)
        · intro member
          rcases List.mem_cons.mp member with equal | restMember
          · rw [equal]
            exact present
          · exact induction.mpr restMember
      · simp [induction]

def symbolicWriteFootprint (behavior : SymbolicBehavior)
    (input : MachineState) : CheckedCDeclWriteFootprint := {
  bytes := deduplicateWords (symbolicWriteBytes behavior input)
}

structure ExactDecodedCDeclSymbolicExecution
    (execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world)
    (entryBefore : MachineState) where
  behavior : SymbolicBehavior
  returnedStateExact :
    execution.returnedState =
      concreteBehaviorNextMachineState (behavior.eval entryBefore) entryBefore
  returnOutcomeExact :
    (behavior.eval entryBefore).outcome =
      some (.returned
        (Memory.read32 execution.returnBefore.memory
          execution.returnBefore.registers.esp))

/-- Dynamic frame facts are stated at the symbolic input, before the computed
return state exists.  The strict private/caller boundary is enough to derive
finite caller-frame disjointness; no footprint list is supplied here. -/
structure CDeclSymbolicABIFrameFacts
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (disposition : CDeclReturnDisposition)
    (request : AbstractKernelRequest)
    (entryBefore : MachineState)
    (behavior : SymbolicBehavior)
    (frame : CDeclSymbolicFrameExpressions) : Prop where
  shapeChecked : frame.checked behavior = true
  callerEsp :
    frame.callerEsp.eval entryBefore =
      abi.parameters.entryEsp abi.engineLayout request.operation
  savedEbx : frame.savedEbx.eval entryBefore = entryBefore.registers.ebx
  savedEsi : frame.savedEsi.eval entryBefore = entryBefore.registers.esi
  savedEdi : frame.savedEdi.eval entryBefore = entryBefore.registers.edi
  savedEbp : frame.savedEbp.eval entryBefore = entryBefore.registers.ebp
  stackAfter :
    (frame.callerEsp.offset 4).eval entryBefore =
      entryBefore.registers.esp + word32 4
  writeBytesInsideWorkspace :
    ∀ address, address ∈ symbolicWriteBytes behavior entryBefore ->
      addressInSpan abi.parameters.writableWorkspace address
  writeBytesBelowCaller :
    ∀ address, address ∈ symbolicWriteBytes behavior entryBefore ->
      address.toNat <
        (abi.parameters.entryEsp abi.engineLayout request.operation).toNat
  callerFrameAtOrAbove :
    ∀ address, address ∈ cdeclCallerFrameBytes abi request ->
      (abi.parameters.entryEsp abi.engineLayout request.operation).toNat <=
        address.toNat
  returnAccepted :
    disposition.accepts (abi.parameters.returnAddress pe)

private theorem Memory.write32_apply_of_not_mem_wordByteAddresses
    (memory : Memory) (writeAddress value query : Word)
    (outside : query ∉ wordByteAddresses writeAddress) :
    memory.write32 writeAddress value query = memory query := by
  simp only [Memory.write32]
  split
  · rename_i equal
    exact (outside (by simp [wordByteAddresses, equal])).elim
  · split
    · rename_i equal
      exact (outside (by simp [wordByteAddresses, word32, equal])).elim
    · split
      · rename_i equal
        exact (outside (by simp [wordByteAddresses, word32, equal])).elim
      · split
        · rename_i equal
          exact (outside (by simp [wordByteAddresses, word32, equal])).elim
        · rfl

private theorem foldl_write32_agrees_outside
    (input : MachineState) (writes : List (Expr × Expr))
    (memory : Memory) (address : Word)
    (outside :
      address ∉ writes.flatMap fun write =>
        wordByteAddresses (write.1.eval input)) :
    (writes.foldl (fun current write =>
      current.write32 (write.1.eval input) (write.2.eval input)) memory)
        address =
      memory address := by
  induction writes generalizing memory with
  | nil => rfl
  | cons write tail induction =>
      simp only [List.foldl_cons]
      have headOutside :
          address ∉ wordByteAddresses (write.1.eval input) := by
        intro member
        apply outside
        simp only [List.flatMap_cons, List.mem_append]
        exact Or.inl member
      have tailOutside :
          address ∉ tail.flatMap fun next =>
            wordByteAddresses (next.1.eval input) := by
        intro member
        apply outside
        simp only [List.flatMap_cons, List.mem_append]
        exact Or.inr member
      rw [induction _ tailOutside]
      exact Memory.write32_apply_of_not_mem_wordByteAddresses
        memory (write.1.eval input) (write.2.eval input) address headOutside

theorem symbolicWriteFootprint.memoryFrame
    (behavior : SymbolicBehavior) (input : MachineState) :
    MemoryAgreesOutside (symbolicWriteFootprint behavior input).contains
      (applyWrites input behavior.writes) input.memory := by
  intro address outside
  apply foldl_write32_agrees_outside input behavior.writes input.memory address
  intro member
  apply outside
  change address ∈
    deduplicateWords (symbolicWriteBytes behavior input)
  exact (mem_deduplicateWords address _).mpr member

private theorem addressInSpanChecked_eq_true
    (span : Span) (address : Word)
    (inside : addressInSpan span address) :
    addressInSpanChecked span address = true := by
  rcases inside with ⟨start, stop, bounded⟩
  simp [addressInSpanChecked, start, stop, bounded]

theorem CDeclSymbolicABIFrameFacts.footprintChecked
    (facts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
      behavior frame) :
    (symbolicWriteFootprint behavior entryBefore).checked abi request = true := by
  simp only [CheckedCDeclWriteFootprint.checked, Bool.and_eq_true]
  constructor
  · rw [decide_eq_true_eq]
    exact deduplicateWords_nodup _
  · apply List.all_eq_true.mpr
    intro address member
    have rawMember : address ∈ symbolicWriteBytes behavior entryBefore := by
      exact (mem_deduplicateWords address _).mp member
    have inside := addressInSpanChecked_eq_true
      abi.parameters.writableWorkspace address
      (facts.writeBytesInsideWorkspace address rawMember)
    have callerAbsent : address ∉ cdeclCallerFrameBytes abi request := by
      intro callerMember
      have below := facts.writeBytesBelowCaller address rawMember
      have above := facts.callerFrameAtOrAbove address callerMember
      omega
    simp only [Bool.and_eq_true]
    exact ⟨inside, by simpa using callerAbsent⟩

theorem ExactDecodedCDeclSymbolicExecution.stackReturnWord
    {pe : PE32} {imports : List PEImport}
    {relocations : List BaseRelocation} {tableOffset countOffset : Nat}
    {records : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    (symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore)
    (entry : ABIRequestFacts abi request entryBefore)
    (facts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
      symbolic.behavior frame) :
    Memory.read32 execution.returnBefore.memory
        execution.returnBefore.registers.esp =
      abi.parameters.returnAddress pe := by
  have shape := frame.shape_of_checked symbolic.behavior facts.shapeChecked
  have evaluated :
      (symbolic.behavior.eval entryBefore).outcome =
        some (.returned
          (Memory.read32 entryBefore.memory
            (frame.callerEsp.eval entryBefore))) := by
    simp [SymbolicBehavior.eval, shape.outcome, Expr.eval]
  have targets :
      Memory.read32 entryBefore.memory (frame.callerEsp.eval entryBefore) =
        Memory.read32 execution.returnBefore.memory
          execution.returnBefore.registers.esp := by
    simpa using Option.some.inj
      (evaluated.symm.trans symbolic.returnOutcomeExact)
  calc
    Memory.read32 execution.returnBefore.memory
        execution.returnBefore.registers.esp =
        Memory.read32 entryBefore.memory (frame.callerEsp.eval entryBefore) :=
      targets.symm
    _ = Memory.read32 entryBefore.memory
        (abi.parameters.entryEsp abi.engineLayout request.operation) := by
      rw [facts.callerEsp]
    _ = abi.parameters.returnAddress pe := entry.cdecl.2.2.1.1

theorem ExactDecodedCDeclSymbolicExecution.preservedRegisters
    (symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore)
    (facts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
      symbolic.behavior frame) :
    CDeclPreservedRegisters entryBefore execution.returnedState := by
  have shape := frame.shape_of_checked symbolic.behavior facts.shapeChecked
  rw [symbolic.returnedStateExact]
  change
    symbolic.behavior.registers.ebx.eval entryBefore =
        entryBefore.registers.ebx ∧
      symbolic.behavior.registers.esi.eval entryBefore =
        entryBefore.registers.esi ∧
      symbolic.behavior.registers.edi.eval entryBefore =
        entryBefore.registers.edi ∧
      symbolic.behavior.registers.ebp.eval entryBefore =
        entryBefore.registers.ebp
  exact ⟨by rw [shape.ebx]; exact facts.savedEbx,
    by rw [shape.esi]; exact facts.savedEsi,
    by rw [shape.edi]; exact facts.savedEdi,
    by rw [shape.ebp]; exact facts.savedEbp⟩

theorem ExactDecodedCDeclSymbolicExecution.stackPopped
    (symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore)
    (facts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
      symbolic.behavior frame) :
    execution.returnedState.registers.esp =
      entryBefore.registers.esp + word32 4 := by
  have shape := frame.shape_of_checked symbolic.behavior facts.shapeChecked
  rw [symbolic.returnedStateExact]
  change symbolic.behavior.registers.esp.eval entryBefore =
    entryBefore.registers.esp + word32 4
  rw [shape.esp]
  exact facts.stackAfter

theorem ExactDecodedCDeclSymbolicExecution.exactWriteFootprint
    (symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore) :
    MemoryAgreesOutside
      (symbolicWriteFootprint symbolic.behavior entryBefore).contains
      execution.returnedState.memory entryBefore.memory := by
  rw [symbolic.returnedStateExact]
  exact symbolicWriteFootprint.memoryFrame symbolic.behavior entryBefore

/-- The intentionally narrow residual premises after symbolic closure. -/
structure CDeclSymbolicClosureRemaining
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (state : MachineState) (events : List NativeExternalEvent) : Prop where
  candidateImagePreserved :
    LoadedCandidateImageMemory pe imports relocations state.memory
  originalProgramTablePreserved :
    LoadedOriginalProgramTable abi state.memory
  environmentalPayload :
    ResponsePayloadHolds abi request response state events

structure SymbolicallyClosedCDeclEpilogueCertificate
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
  remaining : CDeclSymbolicClosureRemaining abi request response
    execution.returnedState events

def SymbolicallyClosedCDeclEpilogueCertificate.toChecked
    (certificate : SymbolicallyClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    CheckedCDeclEpilogueCertificate abi candidate static disposition request
      response entryBefore epilogueBefore eventIndex events world := {
  operationExact := certificate.operationExact
  entry := certificate.entry
  execution := certificate.execution
  stackReturnWord := certificate.symbolic.stackReturnWord certificate.entry
    certificate.frameFacts
  returnAccepted := certificate.frameFacts.returnAccepted
  preservedRegisters := certificate.symbolic.preservedRegisters
    certificate.frameFacts
  stackPopped := certificate.symbolic.stackPopped certificate.frameFacts
  footprint := symbolicWriteFootprint certificate.symbolic.behavior entryBefore
  footprintChecked := certificate.frameFacts.footprintChecked
  exactWriteFootprint := certificate.symbolic.exactWriteFootprint
  candidateImagePreserved := certificate.remaining.candidateImagePreserved
  originalProgramTablePreserved :=
    certificate.remaining.originalProgramTablePreserved
  payload := certificate.remaining.environmentalPayload
}

theorem SymbolicallyClosedCDeclEpilogueCertificate.responseRelated
    (certificate : SymbolicallyClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    abi.relation.responseRelated request response
      certificate.execution.returnedState events :=
  certificate.toChecked.responseRelated

theorem SymbolicallyClosedCDeclEpilogueCertificate.memoryFrame
    (certificate : SymbolicallyClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    MemoryAgreesOutside (abi.relation.scratchFootprint request)
      certificate.execution.returnedState.memory entryBefore.memory :=
  certificate.toChecked.memoryFrame

theorem SymbolicallyClosedCDeclEpilogueCertificate.path
    (certificate : SymbolicallyClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    NonemptyRelatedPath candidate.transitionSystem certificate.execution.start
      certificate.execution.observations certificate.execution.after :=
  certificate.toChecked.path

#print axioms symbolicWriteFootprint.memoryFrame
#print axioms CDeclSymbolicABIFrameFacts.footprintChecked
#print axioms ExactDecodedCDeclSymbolicExecution.stackReturnWord
#print axioms ExactDecodedCDeclSymbolicExecution.preservedRegisters
#print axioms ExactDecodedCDeclSymbolicExecution.stackPopped
#print axioms ExactDecodedCDeclSymbolicExecution.exactWriteFootprint
#print axioms SymbolicallyClosedCDeclEpilogueCertificate.toChecked
#print axioms SymbolicallyClosedCDeclEpilogueCertificate.responseRelated
#print axioms SymbolicallyClosedCDeclEpilogueCertificate.memoryFrame
#print axioms SymbolicallyClosedCDeclEpilogueCertificate.path

end StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
