import StageA.Relational
import StageA.RelationalX87Decode

namespace StageA.Relational.X87

open StageA.Formal

def effectiveAddress (addressing : Addressing) (state : MachineState) : Word :=
  (addressing.expression initialSymbolic.registers).eval state

def commandDataAddress (descriptor : DecodedCommand)
    (state : MachineState) : Option Word :=
  descriptor.memoryOperand.map fun addressing => effectiveAddress addressing state

theorem commandDataAddress_of_expression (descriptor : DecodedCommand)
    (expression : Expr) (state : MachineState)
    (checked : descriptor.memoryOperand.map
      (fun addressing => addressing.expression initialSymbolic.registers) =
        some expression) :
    commandDataAddress descriptor state = some (expression.eval state) := by
  cases operand : descriptor.memoryOperand with
  | none => simp [operand] at checked
  | some addressing =>
      simp only [operand, Option.map_some, Option.some.injEq] at checked
      subst expression
      simp [commandDataAddress, operand, effectiveAddress]

def commandStepInput (pe : PE32) (rva : Nat) (descriptor : DecodedCommand)
    (state : MachineState) : StageA.X87.StepInput :=
  let operandBytes := descriptor.command.expectedOperandBytes.getD 0
  let dataAddress := (commandDataAddress descriptor state).getD
    state.x87Physical.dataPointer
  {
    operandBits := if operandBytes = 0 then BitVec.ofNat 80 0
      else state.readX87Word dataAddress operandBytes
    operandBytes
    opcode := descriptor.opcode
    instructionPointer := BitVec.ofNat 32 (pe.imageBase + rva)
    codeSelector := BitVec.ofNat 16 0
    dataPointer := dataAddress
    dataSelector := BitVec.ofNat 16 0
  }

private theorem foldX87Word_toNat_lt_width (state : MachineState)
    (address : Word) (bytes : Nat) (bounded : bytes ≤ 10)
    (indices : List Nat) (accumulator : X87Word)
    (accumulatorBound : accumulator.toNat < 2 ^ (8 * bytes))
    (indicesBound : ∀ index ∈ indices, index < bytes) :
    (indices.foldl (fun result index =>
      result ||| (BitVec.zeroExtend 80
        (state.memory (address + BitVec.ofNat 32 index))).shiftLeft (index * 8))
      accumulator).toNat < 2 ^ (8 * bytes) := by
  induction indices generalizing accumulator with
  | nil => simpa using accumulatorBound
  | cons index rest ih =>
      simp only [List.foldl_cons]
      apply ih
      · rw [BitVec.toNat_or]
        apply Nat.or_lt_two_pow accumulatorBound
        have indexBound : index < bytes :=
          indicesBound index (by simp)
        have byteBound :
            (state.memory (address + BitVec.ofNat 32 index)).toNat < 2 ^ 8 :=
          (state.memory (address + BitVec.ofNat 32 index)).isLt
        have shiftedBound :
            (state.memory (address + BitVec.ofNat 32 index)).toNat <<<
                (index * 8) < 2 ^ (8 * bytes) := by
          rw [Nat.shiftLeft_eq]
          have productBound :
              (state.memory (address + BitVec.ofNat 32 index)).toNat *
                  2 ^ (index * 8) < 2 ^ 8 * 2 ^ (index * 8) :=
            (Nat.mul_lt_mul_right (Nat.two_pow_pos (index * 8))).2 byteBound
          rw [← Nat.pow_add] at productBound
          exact Nat.lt_of_lt_of_le productBound
            ((Nat.pow_le_pow_iff_right (by decide : 1 < 2)).2 (by omega))
        have shiftedWidthBound :
            (state.memory (address + BitVec.ofNat 32 index)).toNat <<<
                (index * 8) < 2 ^ 80 := by
          exact Nat.lt_of_lt_of_le shiftedBound
            ((Nat.pow_le_pow_iff_right (by decide : 1 < 2)).2 (by omega))
        have byteWidthBound :
            (state.memory (address + BitVec.ofNat 32 index)).toNat < 2 ^ 80 :=
          Nat.lt_of_lt_of_le byteBound
            ((Nat.pow_le_pow_iff_right (by decide : 1 < 2)).2 (by decide))
        change ((BitVec.zeroExtend 80
          (state.memory (address + BitVec.ofNat 32 index))) <<<
            (index * 8)).toNat < 2 ^ (8 * bytes)
        rw [BitVec.toNat_shiftLeft, BitVec.toNat_setWidth,
          Nat.mod_eq_of_lt byteWidthBound,
          Nat.mod_eq_of_lt shiftedWidthBound]
        exact shiftedBound
      · intro item member
        exact indicesBound item (by simp [member])

theorem readX87Word_toNat_lt_width (state : MachineState) (address : Word)
    (bytes : Nat) (bounded : bytes ≤ 10) :
    (state.readX87Word address bytes).toNat < 2 ^ (8 * bytes) := by
  unfold MachineState.readX87Word
  apply foldX87Word_toNat_lt_width state address bytes bounded
  · simpa using Nat.two_pow_pos (8 * bytes)
  · intro index member
    simpa using member

theorem commandStepInput_valid_of_operand_bytes
    (pe : PE32) (rva : Nat) (descriptor : DecodedCommand)
    (state : MachineState) (bytes : Nat)
    (operandBytes : descriptor.command.expectedOperandBytes = some bytes)
    (positive : 0 < bytes) (bounded : bytes ≤ 10) :
    (commandStepInput pe rva descriptor state).validFor descriptor.command := by
  constructor
  · simp [commandStepInput, operandBytes]
  · simp only [commandStepInput, operandBytes, Option.getD_some,
      if_neg (Nat.ne_of_gt positive)]
    exact readX87Word_toNat_lt_width state
      ((commandDataAddress descriptor state).getD state.x87Physical.dataPointer)
      bytes bounded

/-- Every command accepted by the x87 decoder uses either no operand or one of
the finite architectural widths supported by the concrete 80-bit reader. -/
theorem commandStepInput_valid
    (pe : PE32) (rva : Nat) (descriptor : DecodedCommand)
    (state : MachineState) :
    (commandStepInput pe rva descriptor state).validFor
      descriptor.command := by
  have supported :
      descriptor.command.expectedOperandBytes = none ∨
      descriptor.command.expectedOperandBytes = some 2 ∨
      descriptor.command.expectedOperandBytes = some 4 ∨
      descriptor.command.expectedOperandBytes = some 8 ∨
      descriptor.command.expectedOperandBytes = some 10 := by
    cases descriptor.command <;> try simp [StageA.X87.Command.expectedOperandBytes]
    all_goals
      first
      | (rename_i format; cases format <;>
          simp [StageA.X87.LoadFormat.byteWidth])
      | (rename_i _operation format; cases format <;>
          simp [StageA.X87.LoadFormat.byteWidth])
  rcases supported with noOperand | twoBytes | fourBytes | eightBytes | tenBytes
  · constructor <;> simp [commandStepInput, noOperand]
  · exact commandStepInput_valid_of_operand_bytes pe rva descriptor state 2
      twoBytes (by decide) (by decide)
  · exact commandStepInput_valid_of_operand_bytes pe rva descriptor state 4
      fourBytes (by decide) (by decide)
  · exact commandStepInput_valid_of_operand_bytes pe rva descriptor state 8
      eightBytes (by decide) (by decide)
  · exact commandStepInput_valid_of_operand_bytes pe rva descriptor state 10
      tenBytes (by decide) (by decide)

def legacyConcreteState (state : MachineState) : ConcreteX87State := {
  stack := (List.range 8).map state.x87.stack
  control := state.x87.control
  status := state.x87.status
}

theorem commandStepInput_related_of_no_memory
    (context : StaticProofContext) (world : RelationalWorld)
    (descriptor : DecodedCommand) (originalRva candidateRva : Nat)
    (originalState candidateState : MachineState)
    (noMemory : descriptor.memoryOperand = none)
    (noOperand : descriptor.command.expectedOperandBytes = none)
    (states : StateRelated (x87AddressRelation context world)
      originalState.x87Physical candidateState.x87Physical)
    (code : (x87AddressRelation context world).code
      (BitVec.ofNat 32 (context.originalPe.imageBase + originalRva))
      (BitVec.ofNat 32 (context.candidatePe.imageBase + candidateRva))) :
    InputRelated (x87AddressRelation context world)
      (commandStepInput context.originalPe originalRva descriptor originalState)
      (commandStepInput context.candidatePe candidateRva descriptor candidateState) := by
  rcases states with ⟨_core, metadata⟩
  rcases metadata with
    ⟨_opcode, _instruction, _codeSelector, data, _dataSelector⟩
  simp [InputRelated, commandStepInput, commandDataAddress, noMemory,
    noOperand, code]
  exact ⟨rfl, data⟩

theorem commandStepInput_related_of_exact_memory
    (context : StaticProofContext) (world : RelationalWorld)
    (descriptor : DecodedCommand) (originalRva candidateRva : Nat)
    (originalState candidateState : MachineState) (bytes : Nat)
    (operandBytes : descriptor.command.expectedOperandBytes = some bytes)
    (originalAddress candidateAddress : Word)
    (originalDataAddress : commandDataAddress descriptor originalState =
      some originalAddress)
    (candidateDataAddress : commandDataAddress descriptor candidateState =
      some candidateAddress)
    (operandExact : originalState.readX87Word originalAddress bytes =
      candidateState.readX87Word candidateAddress bytes)
    (data : (x87AddressRelation context world).data
      originalAddress candidateAddress)
    (code : (x87AddressRelation context world).code
      (BitVec.ofNat 32 (context.originalPe.imageBase + originalRva))
      (BitVec.ofNat 32 (context.candidatePe.imageBase + candidateRva))) :
    InputRelated (x87AddressRelation context world)
      (commandStepInput context.originalPe originalRva descriptor originalState)
      (commandStepInput context.candidatePe candidateRva descriptor candidateState) := by
  simp [InputRelated, commandStepInput, StageA.X87.StepInput.operand,
    operandBytes, originalDataAddress, candidateDataAddress, operandExact,
    code, data]

theorem commandStepInput_related_of_exact_stack_memory
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (descriptor : DecodedCommand)
    (originalRva candidateRva : Nat) (originalState candidateState : MachineState)
    (predicate : PairedStatePredicate) (read : PairedExactMemoryRead)
    (window : StackWindowPair) (offset bytes : Nat)
    (related : StateRel context world invariant originalState candidateState)
    (predicateMember : predicate ∈ invariant.predicates)
    (readMember : read ∈ predicate.exactMemoryReads)
    (windowMember : window ∈ invariant.stackWindows)
    (operandBytes : descriptor.command.expectedOperandBytes = some bytes)
    (readBytes : read.bytes = bytes)
    (originalDataAddress : commandDataAddress descriptor originalState =
      some (read.originalAddress.eval originalState))
    (candidateDataAddress : commandDataAddress descriptor candidateState =
      some (read.candidateAddress.eval candidateState))
    (originalAddressShape : read.originalAddress.eval originalState =
      originalState.registers.get window.originalRegister + BitVec.ofNat 32 offset)
    (candidateAddressShape : read.candidateAddress.eval candidateState =
      candidateState.registers.get window.candidateRegister + BitVec.ofNat 32 offset)
    (fourBytes : 4 ≤ bytes) (inside : offset + bytes ≤ window.bytesAbove)
    (aligned : offset % 4 = 0)
    (code : (x87AddressRelation context world).code
      (BitVec.ofNat 32 (context.originalPe.imageBase + originalRva))
      (BitVec.ofNat 32 (context.candidatePe.imageBase + candidateRva))) :
    InputRelated (x87AddressRelation context world)
      (commandStepInput context.originalPe originalRva descriptor originalState)
      (commandStepInput context.candidatePe candidateRva descriptor candidateState) := by
  have operandExact :
      originalState.readX87Word (read.originalAddress.eval originalState) bytes =
        candidateState.readX87Word (read.candidateAddress.eval candidateState) bytes := by
    simpa [readBytes] using related.exactMemoryRead context world invariant
      originalState candidateState predicate read predicateMember readMember
  have windows := related.stackWindowsHold context world invariant
    originalState candidateState
  simp only [stackWindowsRelated, List.all_eq_true] at windows
  have windowHolds := windows window windowMember
  have enoughAbove : offset + 4 ≤ window.bytesAbove := by omega
  rcases pairedStackWordLocation_above_window context world window
      originalState.registers candidateState.registers
      (related.stackRangesValid context world invariant originalState candidateState)
      windowHolds offset aligned enoughAbove with
    ⟨location, originalLocation, candidateLocation⟩
  have rangesValid := related.stackRangesValid context world invariant
    originalState candidateState
  simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
    List.all_eq_true] at rangesValid
  have rangeValid : location.range.disjointFromImages context = true :=
    (rangesValid.1.1.2 location.range location.rangeMember).1.1.1
  have data := location.addressesWordRelated context world rangeValid
  rw [originalLocation, candidateLocation, ← originalAddressShape,
    ← candidateAddressShape] at data
  exact commandStepInput_related_of_exact_memory context world descriptor
    originalRva candidateRva originalState candidateState bytes operandBytes
    (read.originalAddress.eval originalState)
    (read.candidateAddress.eval candidateState) originalDataAddress
    candidateDataAddress operandExact data code

def singletonBehavior (state : MachineState) (response : StageA.X87.Response)
    (memoryAddress : Option Word) (continuation : Nat) : RelationalBehavior := {
  registers := state.registers
  x87 := legacyConcreteState state
  x87Effect := some { response, memoryAddress }
  x87Fault := response.fault
  writes := []
  eflags := state.eflags
  outcome := .jump continuation
}

theorem singletonBehavior_nextMachineState_of_state_only
    (state : MachineState) (response : StageA.X87.Response)
    (continuation : Nat)
    (noStore : response.store = none)
    (noRegister : response.register = none)
    (noFlags : response.eflagsWriteMask = BitVec.ofNat 32 0) :
    (singletonBehavior state response none continuation).nextMachineState state =
      { state with x87Physical := response.nextState } := by
  simp [singletonBehavior, RelationalBehavior.nextMachineState,
    applyConcreteWrites, applyX87MemoryEffect, applyX87RegisterEffect,
    applyX87FlagsEffect, noStore, noRegister, noFlags]
  have mask : (BitVec.ofNat 32 4294967295) = BitVec.allOnes 32 := by decide
  rw [mask, BitVec.and_allOnes]

def executeSingletonCommand (candidate : Bool) (pe : PE32)
    (span : Span) (targets : List CodeTargetPair) (state : MachineState) :
    Option RelationalBehavior := do
  let descriptor <- decodeSingletonCommand pe span
  let continuation <- normalizeCodeTarget candidate targets span.stop
  let input := commandStepInput pe span.start descriptor state
  if !input.checkedFor descriptor.command then none else
  if !descriptor.command.waitModeChecked descriptor.waitMode then none else
  let response := state.x87Semantics.execute descriptor.command descriptor.waitMode
    state.x87Physical input
  if !response.checkedFor descriptor.command descriptor.waitMode then none else
  let memoryAddress <- match response.store with
    | none => some none
    | some _ => (commandDataAddress descriptor state).map some
  pure (singletonBehavior state response memoryAddress continuation)

/-- A successful singleton execution always resumes at the continuation that
the checked static code map resolved for the end of the instruction span. -/
theorem executeSingletonCommand_outcome_of_continuation
    (candidate : Bool) (pe : PE32) (span : Span)
    (targets : List CodeTargetPair) (state : MachineState)
    (behavior : RelationalBehavior) (continuation : Nat)
    (continuationResolved : normalizeCodeTarget candidate targets span.stop =
      some continuation)
    (executed : executeSingletonCommand candidate pe span targets state =
      some behavior) :
    behavior.outcome = .jump continuation := by
  unfold executeSingletonCommand at executed
  rw [continuationResolved] at executed
  cases descriptorFound : decodeSingletonCommand pe span with
  | none => simp [descriptorFound] at executed
  | some descriptor =>
      simp [descriptorFound, singletonBehavior] at executed
      rcases executed with ⟨_, _, _, executed⟩
      cases storeFound : (state.x87Semantics.execute descriptor.command
          descriptor.waitMode state.x87Physical
          (commandStepInput pe span.start descriptor state)).store with
      | none =>
          simp [storeFound] at executed
          subst behavior
          rfl
      | some store =>
          cases addressFound : commandDataAddress descriptor state with
          | none => simp [storeFound, addressFound] at executed
          | some address =>
              simp [storeFound, addressFound] at executed
              subst behavior
              rfl

/-- Successful x87 singleton execution always carries the physical machine
effect produced by the qualified x87 semantics. -/
theorem executeSingletonCommand_effect_isSome
    (candidate : Bool) (pe : PE32) (span : Span)
    (targets : List CodeTargetPair) (state : MachineState)
    (behavior : RelationalBehavior)
    (executed : executeSingletonCommand candidate pe span targets state =
      some behavior) :
    behavior.x87Effect.isSome = true := by
  unfold executeSingletonCommand at executed
  cases descriptorFound : decodeSingletonCommand pe span with
  | none => simp [descriptorFound] at executed
  | some descriptor =>
      simp only [descriptorFound] at executed
      cases continuationFound : normalizeCodeTarget candidate targets span.stop with
      | none => simp [continuationFound] at executed
      | some continuation =>
          simp [continuationFound, singletonBehavior] at executed
          rcases executed with ⟨_, _, _, executed⟩
          cases storeFound : (state.x87Semantics.execute descriptor.command
              descriptor.waitMode state.x87Physical
              (commandStepInput pe span.start descriptor state)).store with
          | none =>
              simp [storeFound] at executed
              subst behavior
              rfl
          | some store =>
              cases addressFound : commandDataAddress descriptor state with
              | none => simp [storeFound, addressFound] at executed
              | some address =>
                  simp [storeFound, addressFound] at executed
                  subst behavior
                  rfl

def spanStartsWithX87Command (pe : PE32) (span : Span) : Bool :=
  (decodeSingletonCommand pe span).isSome

end StageA.Relational.X87
