import StageA.RelationalSymbolicSoundness

namespace StageA.Relational.InterpreterKernelMixedReplay

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.SymbolicSoundness

/-! # Exact mixed native-instruction replay

The compiled native kernel gives physical x87 frame operations and ordinary x87
commands precedence over the ordinary symbolic decoder.  This module exposes
that precedence through one checked instruction type and proves that its compact
replay transition is exactly `stepKernelPE32Instruction`.

Generated bridge certificates can therefore decode each immutable instruction
once and compose the resulting checked transitions without invoking three
partially overlapping decoders at every downstream proof layer.
-/

inductive KernelMixedReplayInstruction where
  | ordinary (instruction : KernelInstruction)
  | x87Frame (instruction : KernelX87FrameInstruction)
  | x87Command (instruction : KernelX87CommandInstruction)
deriving Repr, DecidableEq

def KernelMixedReplayInstruction.rva : KernelMixedReplayInstruction -> Nat
  | .ordinary instruction => instruction.rva
  | .x87Frame instruction => instruction.rva
  | .x87Command instruction => instruction.rva

def KernelMixedReplayInstruction.bytes : KernelMixedReplayInstruction -> Bytes
  | .ordinary instruction => instruction.bytes
  | .x87Frame instruction => instruction.bytes
  | .x87Command instruction => instruction.bytes

def KernelMixedReplayInstruction.specializedDecodersClear
    (pe : PE32) (instruction : KernelInstruction) : Bool :=
  match executableInstructionWindow pe instruction.rva with
  | none => false
  | some fetched =>
      (decodeKernelX87FrameExact fetched).isNone &&
        (StageA.Relational.X87.decodeCommandExact fetched).isNone

def KernelMixedReplayInstruction.frameDecoderClear
    (pe : PE32) (instruction : KernelX87CommandInstruction) : Bool :=
  match executableInstructionWindow pe instruction.rva with
  | none => false
  | some fetched => (decodeKernelX87FrameExact fetched).isNone

/-- Exact capability check respecting the same decoder precedence as the native
kernel.  An instruction accepted by two semantic classes is rejected rather
than silently assigned to whichever checker happened to run first. -/
def KernelMixedReplayInstruction.checked (pe : PE32) (imports : List PEImport) :
    KernelMixedReplayInstruction -> Bool
  | .ordinary instruction =>
      instruction.checked pe imports &&
        KernelMixedReplayInstruction.specializedDecodersClear pe instruction
  | .x87Frame instruction => instruction.checked pe
  | .x87Command instruction =>
      instruction.checked pe &&
        KernelMixedReplayInstruction.frameDecoderClear pe instruction

structure CheckedKernelMixedReplayInstruction
    (pe : PE32) (imports : List PEImport) where
  instruction : KernelMixedReplayInstruction
  checked : instruction.checked pe imports = true

/-- Compact transition selected by a checked mixed instruction.  Ordinary
instructions consume the reviewed symbolic semantics; x87 frame and command
instructions consume their reviewed physical-state semantics. -/
def KernelMixedReplayInstruction.semanticStep
    (pe : PE32) (imports : List PEImport) (undefinedSlot : Nat)
    (state : MachineState) :
    KernelMixedReplayInstruction -> PE32InstructionExecution
  | .ordinary instruction =>
      StageA.Relational.SymbolicSoundness.KernelInstruction.semanticStep
        pe imports undefinedSlot state instruction
  | .x87Frame instruction =>
      match instruction.decode? pe with
      | none => .fault
      | some decoded =>
          match executeKernelX87Frame? decoded state with
          | none => .fault
          | some after =>
              .running (instruction.rva + decoded.size) (undefinedSlot + 1) after
  | .x87Command instruction =>
      match instruction.decode? pe with
      | none => .fault
      | some descriptor =>
          match executeKernelX87Command? pe instruction.rva undefinedSlot state
              descriptor with
          | none => .fault
          | some after => after

/-- Classify one exact executable instruction using the native kernel's decoder
precedence, bound it to its immutable PE bytes, and retain the checked proof in
the returned artifact. -/
def checkedKernelMixedReplayInstruction?
    (pe : PE32) (imports : List PEImport) (rva maxBytes : Nat) :
    Option (CheckedKernelMixedReplayInstruction pe imports) := do
  if maxBytes == 0 then none else
  let fetched <- executableInstructionWindow pe rva
  let instruction <-
    match decodeKernelX87FrameExact fetched with
    | some decoded =>
        some (.x87Frame {
          rva
          bytes := fetched.take decoded.size
          operation := decoded.operation
        })
    | none =>
        match StageA.Relational.X87.decodeCommandExact fetched with
        | some decoded =>
            some (.x87Command {
              rva
              bytes := fetched.take decoded.size
            })
        | none => do
            let decoded <- decodeInstructionExact fetched
            some (.ordinary {
              rva
              bytes := fetched.take decoded.size
            })
  if instruction.bytes.isEmpty ||
      instruction.bytes.length > maxBytes then none else
  if exact : instruction.checked pe imports = true then
    some { instruction, checked := exact }
  else none

/-- Decode a complete bounded phase.  Fuel is internal and derives solely from
the submitted byte length; returning `some` means every byte belongs to one
checked instruction and no decoder crossed the phase boundary. -/
def checkedKernelMixedReplaySpanFuel
    (pe : PE32) (imports : List PEImport) :
    Nat -> Nat -> Nat ->
      Option (List (CheckedKernelMixedReplayInstruction pe imports))
  | 0, _, 0 => some []
  | 0, _, _ + 1 => none
  | _ + 1, _, 0 => some []
  | fuel + 1, rva, remaining@(_ + 1) => do
      let current <- checkedKernelMixedReplayInstruction?
        pe imports rva remaining
      let size := current.instruction.bytes.length
      let tail <- checkedKernelMixedReplaySpanFuel pe imports fuel
        (rva + size) (remaining - size)
      some (current :: tail)

def checkedKernelMixedReplaySpan?
    (pe : PE32) (imports : List PEImport) (rva byteLength : Nat) :
    Option (List (CheckedKernelMixedReplayInstruction pe imports)) :=
  checkedKernelMixedReplaySpanFuel pe imports (byteLength + 1) rva byteLength

def checkedKernelMixedReplayInstructions
    (entries : List (CheckedKernelMixedReplayInstruction pe imports)) :
    List KernelMixedReplayInstruction :=
  entries.map (·.instruction)

theorem KernelMixedReplayInstruction.semanticStep_exact
    (pe : PE32) (imports : List PEImport) (undefinedSlot : Nat)
    (state : MachineState) (instruction : KernelMixedReplayInstruction)
    (checked : instruction.checked pe imports = true) :
    instruction.semanticStep pe imports undefinedSlot state =
      stepKernelPE32Instruction pe imports
        (.running instruction.rva undefinedSlot state) := by
  cases instruction with
  | ordinary instruction =>
      simp only [KernelMixedReplayInstruction.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨ordinaryChecked, specializedClear⟩
      unfold KernelInstruction.checked at ordinaryChecked
      cases decodedExact : instruction.decode? pe with
      | none => simp [KernelInstruction.semantics?, decodedExact] at ordinaryChecked
      | some decoded =>
          have ordinaryExact := executeInstruction_composes pe imports
            undefinedSlot state instruction decoded decodedExact
          unfold KernelMixedReplayInstruction.specializedDecodersClear at specializedClear
          cases fetchedExact :
              executableInstructionWindow pe instruction.rva with
          | none => simp [fetchedExact] at specializedClear
          | some fetched =>
              simp only [fetchedExact] at specializedClear
              simp only [Bool.and_eq_true, Option.isNone_iff_eq_none] at specializedClear
              rcases specializedClear with ⟨frameClear, commandClear⟩
              simpa [KernelMixedReplayInstruction.semanticStep,
                KernelMixedReplayInstruction.rva, stepKernelPE32Instruction,
                fetchedExact, frameClear, commandClear]
                using ordinaryExact
  | x87Frame instruction =>
      unfold KernelMixedReplayInstruction.checked at checked
      unfold KernelX87FrameInstruction.checked at checked
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at checked
      | some decoded =>
          have instructionDecoded := decodedExact
          unfold KernelX87FrameInstruction.decode? at decodedExact
          split at decodedExact <;> try contradiction
          rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decodedExact
          obtain ⟨exactBytes, _exactBytesRead, decodedExact⟩ := decodedExact
          split at decodedExact <;> try contradiction
          rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decodedExact
          obtain ⟨fetched, fetchedRead, decodedExact⟩ := decodedExact
          rw [Option.bind_eq_some_iff] at decodedExact
          obtain ⟨observed, frameDecoded, decodedExact⟩ := decodedExact
          split at decodedExact <;> try contradiction
          simp only [Option.some.injEq] at decodedExact
          subst observed
          change (match instruction.decode? pe with
            | none => PE32InstructionExecution.fault
            | some decoded =>
                match executeKernelX87Frame? decoded state with
                | none => PE32InstructionExecution.fault
                | some after => .running
                    (instruction.rva + decoded.size) (undefinedSlot + 1) after) =
              stepKernelPE32Instruction pe imports
                (.running instruction.rva undefinedSlot state)
          simp only [instructionDecoded, stepKernelPE32Instruction,
            fetchedRead, frameDecoded]
          generalize executeExact :
              executeKernelX87Frame? decoded state = result
          cases result <;> rfl
  | x87Command instruction =>
      simp only [KernelMixedReplayInstruction.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨commandChecked, frameClear⟩
      unfold KernelX87CommandInstruction.checked at commandChecked
      cases decodedExact : instruction.decode? pe with
      | none => simp [decodedExact] at commandChecked
      | some decoded =>
          have instructionDecoded := decodedExact
          unfold KernelX87CommandInstruction.decode? at decodedExact
          split at decodedExact <;> try contradiction
          rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decodedExact
          obtain ⟨exactBytes, _exactBytesRead, decodedExact⟩ := decodedExact
          split at decodedExact <;> try contradiction
          rw [Option.bind_eq_bind, Option.bind_eq_some_iff] at decodedExact
          obtain ⟨fetched, fetchedRead, decodedExact⟩ := decodedExact
          rw [Option.bind_eq_some_iff] at decodedExact
          obtain ⟨observed, commandDecoded, decodedExact⟩ := decodedExact
          split at decodedExact <;> try contradiction
          simp only [Option.some.injEq] at decodedExact
          subst observed
          unfold KernelMixedReplayInstruction.frameDecoderClear at frameClear
          simp only [fetchedRead, Option.isNone_iff_eq_none] at frameClear
          change (match instruction.decode? pe with
            | none => PE32InstructionExecution.fault
            | some descriptor =>
                match executeKernelX87Command? pe instruction.rva undefinedSlot
                    state descriptor with
                | none => PE32InstructionExecution.fault
                | some after => after) =
              stepKernelPE32Instruction pe imports
                (.running instruction.rva undefinedSlot state)
          simp only [instructionDecoded, stepKernelPE32Instruction,
            fetchedRead, frameClear, commandDecoded]
          generalize executeExact :
              executeKernelX87Command? pe instruction.rva undefinedSlot state
                decoded = result
          cases result <;> rfl

/-- Every successful checked mixed-replay instruction preserves the selected
x87 semantics implementation.  Frame instructions update only the physical
x87 state, command instructions execute through the existing implementation,
and ordinary instructions cannot replace it.  Keeping this fact at the mixed
instruction boundary lets bridge proofs compose parametric x87 execution
without comparing function-valued semantics objects computationally. -/
theorem KernelMixedReplayInstruction.semanticStep_running_x87Semantics
    (pe : PE32) (imports : List PEImport) (undefinedSlot nextSlot nextRva : Nat)
    (input after : MachineState)
    (instruction : KernelMixedReplayInstruction)
    (executed :
      instruction.semanticStep pe imports undefinedSlot input =
        .running nextRva nextSlot after) :
    after.x87Semantics = input.x87Semantics := by
  cases instruction with
  | ordinary instruction =>
      simp only [KernelMixedReplayInstruction.semanticStep] at executed
      unfold StageA.Relational.SymbolicSoundness.KernelInstruction.semanticStep
        at executed
      split at executed <;> try contradiction
      split at executed <;> try contradiction
      rename_i result resultExact
      cases result with
      | next symbolic =>
          simp only [
            StageA.Relational.SymbolicSoundness.executeInstructionResult]
            at executed
          split at executed <;> try contradiction
          injection executed with _nextRva _nextSlot afterExact
          subst after
          rfl
      | stop symbolic =>
          simp only [
            StageA.Relational.SymbolicSoundness.executeInstructionResult]
            at executed
          split at executed <;> contradiction
  | x87Frame instruction =>
      simp only [KernelMixedReplayInstruction.semanticStep] at executed
      split at executed <;> try contradiction
      rename_i decoded decodedExact
      split at executed <;> try contradiction
      rename_i result resultExact
      injection executed with _ _ afterExact
      subst after
      exact executeKernelX87Frame?_x87Semantics decoded input result resultExact
  | x87Command instruction =>
      simp only [KernelMixedReplayInstruction.semanticStep] at executed
      split at executed <;> try contradiction
      rename_i descriptor descriptorExact
      split at executed <;> try contradiction
      rename_i result resultExact
      cases result with
      | running actualRva actualSlot actualAfter =>
          injection executed with _ _ afterExact
          subst after
          exact executeKernelX87Command?_running_x87Semantics pe
            instruction.rva undefinedSlot actualRva actualSlot input actualAfter
            descriptor resultExact
      | stopped outcome state => contradiction
      | fault => contradiction

def runKernelMixedReplaySemantic (pe : PE32) (imports : List PEImport) :
    Nat -> MachineState -> List KernelMixedReplayInstruction ->
      PE32InstructionExecution
  | undefinedSlot, state, [] => .running 0 undefinedSlot state
  | undefinedSlot, state, [instruction] =>
      instruction.semanticStep pe imports undefinedSlot state
  | undefinedSlot, state, instruction :: next :: tail =>
      match instruction.semanticStep pe imports undefinedSlot state with
      | .running nextRva nextSlot nextState =>
          if nextRva == next.rva then
            runKernelMixedReplaySemantic pe imports nextSlot nextState (next :: tail)
          else .fault
      | .stopped outcome nextState => .stopped outcome nextState
      | .fault => .fault

def runKernelMixedReplayConcrete (pe : PE32) (imports : List PEImport) :
    Nat -> MachineState -> List KernelMixedReplayInstruction ->
      PE32InstructionExecution
  | undefinedSlot, state, [] => .running 0 undefinedSlot state
  | undefinedSlot, state, [instruction] =>
      stepKernelPE32Instruction pe imports
        (.running instruction.rva undefinedSlot state)
  | undefinedSlot, state, instruction :: next :: tail =>
      match stepKernelPE32Instruction pe imports
          (.running instruction.rva undefinedSlot state) with
      | .running nextRva nextSlot nextState =>
          if nextRva == next.rva then
            runKernelMixedReplayConcrete pe imports nextSlot nextState (next :: tail)
          else .fault
      | .stopped outcome nextState => .stopped outcome nextState
      | .fault => .fault

def ExactMixedReplayInventory (pe : PE32) (imports : List PEImport)
    (instructions : List KernelMixedReplayInstruction) : Prop :=
  ∀ instruction, instruction ∈ instructions ->
    instruction.checked pe imports = true

theorem checkedKernelMixedReplayInstructions_exact
    (entries : List (CheckedKernelMixedReplayInstruction pe imports)) :
    ExactMixedReplayInventory pe imports
      (checkedKernelMixedReplayInstructions entries) := by
  intro instruction member
  rcases List.mem_map.mp member with ⟨entry, _entryMember, rfl⟩
  exact entry.checked

/-- Sequential soundness for a heterogeneous native instruction path.  Every
instruction is checked once against exact PE bytes, and downstream phase proofs
compose the opaque transition equality. -/
theorem runKernelMixedReplayConcrete_composes
    (pe : PE32) (imports : List PEImport)
    (instructions : List KernelMixedReplayInstruction)
    (inventory : ExactMixedReplayInventory pe imports instructions) :
    ∀ undefinedSlot input,
      runKernelMixedReplayConcrete pe imports undefinedSlot input instructions =
        runKernelMixedReplaySemantic pe imports undefinedSlot input instructions := by
  induction instructions with
  | nil =>
      intro undefinedSlot input
      rfl
  | cons instruction tail inductionHypothesis =>
      intro undefinedSlot input
      have instructionChecked := inventory instruction (by simp)
      cases tail with
      | nil =>
          simpa [runKernelMixedReplayConcrete, runKernelMixedReplaySemantic] using
            (instruction.semanticStep_exact pe imports undefinedSlot input
              instructionChecked).symm
      | cons next rest =>
          have tailInventory : ExactMixedReplayInventory pe imports
              (next :: rest) := by
            intro candidate member
            exact inventory candidate (by simp [member])
          have tailSound := inductionHypothesis tailInventory
          rw [runKernelMixedReplayConcrete, runKernelMixedReplaySemantic,
            <- instruction.semanticStep_exact pe imports undefinedSlot input
              instructionChecked]
          generalize semanticResult :
              instruction.semanticStep pe imports undefinedSlot input = result
          cases result with
          | running nextRva nextSlot nextState =>
              simp only [semanticResult]
              split
              · exact tailSound nextSlot nextState
              · rfl
          | stopped outcome nextState => simp [semanticResult]
          | fault => simp [semanticResult]

/-- A successful mixed-replay path retains the same parametric x87 semantics
implementation from its first state to its last state. -/
theorem runKernelMixedReplaySemantic_running_x87Semantics
    (pe : PE32) (imports : List PEImport)
    (instructions : List KernelMixedReplayInstruction) :
    ∀ undefinedSlot input nextRva nextSlot after,
      runKernelMixedReplaySemantic pe imports undefinedSlot input instructions =
          .running nextRva nextSlot after ->
        after.x87Semantics = input.x87Semantics := by
  induction instructions with
  | nil =>
      intro undefinedSlot input nextRva nextSlot after executed
      simp only [runKernelMixedReplaySemantic] at executed
      injection executed with _nextRva _nextSlot afterExact
      subst after
      rfl
  | cons instruction tail induction =>
      intro undefinedSlot input nextRva nextSlot after executed
      cases tail with
      | nil =>
          simp only [runKernelMixedReplaySemantic] at executed
          exact instruction.semanticStep_running_x87Semantics pe imports
            undefinedSlot nextSlot nextRva input after executed
      | cons next rest =>
          simp only [runKernelMixedReplaySemantic] at executed
          cases firstExact :
              instruction.semanticStep pe imports undefinedSlot input with
          | running firstRva firstSlot firstState =>
              simp only [firstExact] at executed
              split at executed <;> try contradiction
              have tailSemantics := induction firstSlot firstState nextRva
                nextSlot after executed
              exact tailSemantics.trans
                (instruction.semanticStep_running_x87Semantics pe imports
                  undefinedSlot firstSlot firstRva input firstState firstExact)
          | stopped outcome state => simp [firstExact] at executed
          | fault => simp [firstExact] at executed

/-- Concrete exact-PE replay inherits semantics preservation through the
checked semantic composition theorem. -/
theorem runKernelMixedReplayConcrete_running_x87Semantics
    (pe : PE32) (imports : List PEImport)
    (instructions : List KernelMixedReplayInstruction)
    (inventory : ExactMixedReplayInventory pe imports instructions)
    (undefinedSlot nextRva nextSlot : Nat) (input after : MachineState)
    (executed :
      runKernelMixedReplayConcrete pe imports undefinedSlot input instructions =
        .running nextRva nextSlot after) :
    after.x87Semantics = input.x87Semantics := by
  rw [runKernelMixedReplayConcrete_composes pe imports instructions inventory]
    at executed
  exact runKernelMixedReplaySemantic_running_x87Semantics pe imports
    instructions undefinedSlot input nextRva nextSlot after executed

#print axioms KernelMixedReplayInstruction.semanticStep_exact
#print axioms runKernelMixedReplayConcrete_composes
#print axioms
  KernelMixedReplayInstruction.semanticStep_running_x87Semantics
#print axioms runKernelMixedReplayConcrete_running_x87Semantics

end StageA.Relational.InterpreterKernelMixedReplay
