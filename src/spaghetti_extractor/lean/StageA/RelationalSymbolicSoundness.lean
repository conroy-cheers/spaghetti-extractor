import StageA.RelationalInterpreterKernel

namespace StageA.Relational.SymbolicSoundness

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

/-!
This module closes the generic trust boundary between exact candidate-PE
instruction decoding and the symbolic interpreter.

The authoritative proof unit is one decoded instruction.  This is deliberate:
`executeInstruction` is already the reviewed symbolic semantics, while
composition of two symbolic instructions additionally needs substitution
lemmas for symbolic memory and x87 state.  Requiring those optional fusion
lemmas must not exclude an otherwise supported instruction from whole-program
proofs.  A candidate kernel can therefore always be partitioned at instruction
boundaries, and larger blocks may be admitted by separate naturality proofs.
-/

/-- Exact capability check for the generic instruction-granular theorem.  It
re-decodes the instruction from immutable PE bytes and accepts precisely when
the reviewed `executeInstruction` semantics produces a result. -/
def kernelInstructionCompositionChecked (pe : PE32) (imports : List PEImport)
    (instruction : KernelInstruction) : Bool :=
  (instruction.semantics? pe imports).isSome

/-- The generic bridge admits a block directly when it is exactly one checked
instruction.  Multi-instruction blocks need an explicit fusion theorem; they
are never silently treated as sound. -/
def kernelBlockCompositionChecked (pe : PE32) (imports : List PEImport)
    (block : KernelBlock) : Bool :=
  match block.instructions with
  | [instruction] => kernelInstructionCompositionChecked pe imports instruction
  | _ => false

/-- A successful `KernelInstruction.decode?` contains the same exact decoder
result used by `stepPE32Instruction`. -/
theorem KernelInstruction.decode?_exactWindow (pe : PE32)
    (instruction : KernelInstruction) (decoded : DecodedInstruction)
    (checked : instruction.decode? pe = some decoded) :
    (do
      let fetched <- executableInstructionWindow pe instruction.rva
      decodeInstructionExact fetched) = some decoded := by
  unfold KernelInstruction.decode? at checked
  split at checked <;> try contradiction
  rw [Option.bind_eq_bind] at checked
  rw [Option.bind_eq_some_iff] at checked
  obtain ⟨exact, exactRead, checked⟩ := checked
  split at checked <;> try contradiction
  rw [Option.bind_eq_bind] at checked
  rw [Option.bind_eq_some_iff] at checked
  obtain ⟨fetched, fetchedRead, checked⟩ := checked
  rw [Option.bind_eq_some_iff] at checked
  obtain ⟨observed, decodedRead, checked⟩ := checked
  split at checked <;> try contradiction
  simp only [Option.some.injEq] at checked
  subst observed
  exact Option.bind_eq_some_iff.mpr ⟨fetched, fetchedRead, decodedRead⟩

/-- Concrete interpretation of one result from the reviewed symbolic machine.
This is the result conversion used by `stepPE32Instruction`, factored out so
the exact-byte and sequential-composition theorems share one definition. -/
def executeInstructionResult (nextRva undefinedSlot : Nat)
    (input : MachineState) : InstructionResult -> PE32InstructionExecution
  | .next symbolic =>
      let concrete := symbolic.eval input
      match concrete.outcome with
      | some _ => .fault
      | none => .running nextRva (undefinedSlot + 1)
          (concreteBehaviorNextMachineState concrete input)
  | .stop symbolic =>
      let concrete := symbolic.eval input
      match concrete.outcome with
      | none => .fault
      | some outcome => .stopped outcome
          (concreteBehaviorNextMachineState concrete input)

/-- Re-decode the submitted bytes and execute the corresponding reviewed
instruction semantics.  Unsupported decoder forms and semantic forms fault. -/
def KernelInstruction.semanticStep (pe : PE32) (imports : List PEImport)
    (undefinedSlot : Nat) (input : MachineState)
    (instruction : KernelInstruction) : PE32InstructionExecution :=
  match instruction.decode? pe with
  | none => .fault
  | some decoded =>
      match executeInstruction pe imports instruction.rva undefinedSlot decoded
          initialSymbolic with
      | none => .fault
      | some result => executeInstructionResult
          (instruction.rva + decoded.size) undefinedSlot input result

/-- Trust-zero instruction soundness.  For every decoder constructor and every
instruction form accepted by `executeInstruction`, executing through the
submitted exact bytes is definitionally the same transition as exact PE
fetch/decode/step.  The proof does not enumerate or trust instruction names. -/
theorem executeInstruction_composes
    (pe : PE32) (imports : List PEImport) (undefinedSlot : Nat)
    (input : MachineState) (instruction : KernelInstruction)
    (decoded : DecodedInstruction)
    (checked : instruction.decode? pe = some decoded) :
    KernelInstruction.semanticStep pe imports undefinedSlot input instruction =
      stepPE32Instruction pe imports
        (.running instruction.rva undefinedSlot input) := by
  have exact := KernelInstruction.decode?_exactWindow pe instruction decoded checked
  rw [Option.bind_eq_bind] at exact
  rw [Option.bind_eq_some_iff] at exact
  obtain ⟨fetched, fetchedExact, decodedExact⟩ := exact
  simp [KernelInstruction.semanticStep, checked, stepPE32Instruction,
    fetchedExact, decodedExact, executeInstructionResult]
  generalize resultExact :
      executeInstruction pe imports instruction.rva undefinedSlot decoded
        initialSymbolic = result
  cases result with
  | none => rfl
  | some result => cases result <;> rfl

/-- A block runner expressed only through independently exact, reviewed
instruction steps.  It deliberately does not consume a fused symbolic summary;
that summary needs its own naturality certificate. -/
def runKernelBlockSemantic (pe : PE32) (imports : List PEImport) :
    Nat -> MachineState -> List KernelInstruction -> PE32InstructionExecution
  | undefinedSlot, state, [] => .running 0 undefinedSlot state
  | undefinedSlot, state, [instruction] =>
      KernelInstruction.semanticStep pe imports undefinedSlot state instruction
  | undefinedSlot, state, instruction :: next :: tail =>
      match KernelInstruction.semanticStep pe imports undefinedSlot state
          instruction with
      | PE32InstructionExecution.running nextRva nextSlot nextState =>
          if nextRva == next.rva then
            runKernelBlockSemantic pe imports nextSlot nextState (next :: tail)
          else .fault
      | PE32InstructionExecution.stopped outcome nextState =>
          .stopped outcome nextState
      | PE32InstructionExecution.fault => .fault

/-- Every instruction submitted to a block has an exact immutable-PE decode. -/
def ExactDecodeInventory (pe : PE32)
    (instructions : List KernelInstruction) : Prop :=
  ∀ instruction, instruction ∈ instructions ->
    ∃ decoded, instruction.decode? pe = some decoded

/-- Sequential block soundness.  Under exact decode evidence for every member,
`runKernelBlockConcrete` is exactly the composition of the generic
single-instruction theorem above. -/
theorem runKernelBlockConcrete_composes
    (pe : PE32) (imports : List PEImport)
    (instructions : List KernelInstruction)
    (inventory : ExactDecodeInventory pe instructions) :
    ∀ undefinedSlot input,
      runKernelBlockConcrete pe imports undefinedSlot input instructions =
        runKernelBlockSemantic pe imports undefinedSlot input instructions := by
  induction instructions with
  | nil =>
      intro undefinedSlot input
      rfl
  | cons instruction tail inductionHypothesis =>
      intro undefinedSlot input
      obtain ⟨decoded, checked⟩ := inventory instruction (by simp)
      cases tail with
      | nil =>
          simpa [runKernelBlockConcrete, runKernelBlockSemantic] using
            (executeInstruction_composes pe imports undefinedSlot input
              instruction decoded checked).symm
      | cons next rest =>
          have tailInventory : ExactDecodeInventory pe (next :: rest) := by
            intro candidate member
            exact inventory candidate (by simp [member])
          have tailSound := inductionHypothesis tailInventory
          rw [runKernelBlockConcrete, runKernelBlockSemantic,
            <- executeInstruction_composes pe imports undefinedSlot input
              instruction decoded checked]
          generalize semanticResult :
              KernelInstruction.semanticStep pe imports undefinedSlot input
                instruction = result
          cases result with
          | running nextRva nextSlot nextState =>
              simp only [semanticResult]
              split
              · exact tailSound nextSlot nextState
              · rfl
          | stopped outcome nextState => simp [semanticResult]
          | fault => simp [semanticResult]

end StageA.Relational.SymbolicSoundness
