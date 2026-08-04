import StageA.Formal
import StageA.RelationalX87

namespace StageA.Relational.X87

open StageA.Formal

structure InstructionDescriptor where
  command : StageA.X87.Command
  waitMode : StageA.X87.WaitMode
  memoryOperand : Option Addressing
deriving Repr, DecidableEq

structure DecodedCommand extends InstructionDescriptor where
  opcode : BitVec 11
  size : Nat
deriving Repr, DecidableEq

def loadFormat : X87LoadFormat -> StageA.X87.LoadFormat
  | .float32 => .float32
  | .float64 => .float64
  | .float80 => .float80
  | .int32 => .int32

def storeFormat : X87StoreFormat -> StageA.X87.StoreFormat
  | .float32 => .float32
  | .float64 => .float64
  | .float80 => .float80
  | .int32 => .int32

def unaryOperation : X87UnaryOperation -> StageA.X87.UnaryOperation
  | .negate => .negate
  | .sine => .sine
  | .cosine => .cosine

def binaryOperation : X87BinaryOperation -> StageA.X87.BinaryOperation
  | .add => .add
  | .multiply => .multiply
  | .subtract => .subtract
  | .reverseSubtract => .reverseSubtract
  | .divide => .divide
  | .reverseDivide => .reverseDivide

def instructionDescriptor? : Instruction -> Option InstructionDescriptor
  | .x87LoadStack index => some {
      command := .loadStack index
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87LoadConstant value => some {
      command := .loadConstant (BitVec.ofNat 80 value)
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87Exchange index => some {
      command := .exchange index
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87StoreStack index pop => some {
      command := .storeStack index pop
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87Unary operation => some {
      command := .unary (unaryOperation operation)
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87BinaryStack operation destination source pop => some {
      command := .binaryStack (binaryOperation operation) destination source pop
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87CompareStack mode destination index pop => some {
      command := .compareStack mode destination index pop
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87CompareMemory mode format source pop => some {
      command := .compareMemory mode (loadFormat format) pop
      waitMode := .waiting
      memoryOperand := some source
    }
  | .x87LoadMemory format source => some {
      command := .loadMemory (loadFormat format)
      waitMode := .waiting
      memoryOperand := some source
    }
  | .x87StoreMemory format destination pop => some {
      command := .storeMemory (storeFormat format) .controlWord pop
      waitMode := .waiting
      memoryOperand := some destination
    }
  | .x87BinaryMemory operation format source => some {
      command := .binaryMemory (binaryOperation operation) (loadFormat format)
      waitMode := .waiting
      memoryOperand := some source
    }
  | .x87LoadControl source => some {
      command := .loadControl
      waitMode := .waiting
      memoryOperand := some source
    }
  | .x87StoreControl destination => some {
      command := .storeControl
      waitMode := .noWait
      memoryOperand := some destination
    }
  | .x87Wait => some {
      command := .wait
      waitMode := .waiting
      memoryOperand := none
    }
  | .x87Initialize => some {
      command := .initialize
      waitMode := .noWait
      memoryOperand := none
    }
  | .x87StoreStatusAx => some {
      command := .storeStatusAx
      waitMode := .noWait
      memoryOperand := none
    }
  | .x87Examine => some {
      command := .examine
      waitMode := .waiting
      memoryOperand := none
    }
  | _ => none

theorem instructionDescriptor_waitModeValid (instruction : Instruction)
    (descriptor : InstructionDescriptor)
    (decoded : instructionDescriptor? instruction = some descriptor) :
    descriptor.command.waitModeValid descriptor.waitMode := by
  cases instruction <;> simp [instructionDescriptor?] at decoded
  all_goals
    subst descriptor
    simp [StageA.X87.Command.waitModeValid,
      StageA.X87.Command.expectedWaitMode]

/-- The architectural x87 FOP field consists of the low three bits of the
primary D8-DF opcode followed by the complete ModR/M byte. -/
def encodedOpcode? : Bytes -> Option (BitVec 11)
  | 0x9b :: _ => some (BitVec.ofNat 11 0)
  | primary :: modrm :: _ =>
      if 0xd8 <= primary && primary <= 0xdf && modrm < 0x100 then
        some (BitVec.ofNat 11 (((primary - 0xd8) * 0x100) + modrm))
      else
        none
  | _ => none

def decodeCommandExact (bytes : Bytes) : Option DecodedCommand := do
  let decoded <- decodeInstructionExact bytes
  let descriptor <- instructionDescriptor? decoded.instruction
  let opcode <- encodedOpcode? bytes
  pure {
    command := descriptor.command
    waitMode := descriptor.waitMode
    memoryOperand := descriptor.memoryOperand
    opcode
    size := decoded.size
  }

/-- Exact decoding cannot admit a command under the wrong x87 wait mode. -/
theorem decodeCommandExact_waitModeValid
    (bytes : Bytes) (descriptor : DecodedCommand)
    (decoded : decodeCommandExact bytes = some descriptor) :
    descriptor.command.waitModeValid descriptor.waitMode := by
  unfold decodeCommandExact at decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨instruction, instructionExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨instructionDescriptor, descriptorExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨_opcode, _opcodeExact, decoded⟩ := decoded
  cases decoded
  exact instructionDescriptor_waitModeValid instruction.instruction
    instructionDescriptor descriptorExact

def decodeSingletonCommand (pe : PE32) (span : Span) : Option DecodedCommand := do
  let bytes <- spanBytes pe span
  let decoded <- decodeCommandExact bytes
  if decoded.size == span.size then some decoded else none

/-- The span wrapper preserves the wait-mode fact checked by exact decoding. -/
theorem decodeSingletonCommand_waitModeValid
    (pe : PE32) (span : Span) (descriptor : DecodedCommand)
    (decoded : decodeSingletonCommand pe span = some descriptor) :
    descriptor.command.waitModeValid descriptor.waitMode := by
  unfold decodeSingletonCommand at decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨bytes, _bytesExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨decodedDescriptor, descriptorExact, decoded⟩ := decoded
  split at decoded <;> try contradiction
  simp only [Option.some.injEq] at decoded
  subst descriptor
  exact decodeCommandExact_waitModeValid bytes decodedDescriptor descriptorExact

/-- Exact decoding preserves whether the x87 command has an addressed memory
operand. -/
theorem instructionDescriptor_memoryOperand
    (instruction : Instruction)
    (descriptor : InstructionDescriptor)
    (decoded : instructionDescriptor? instruction = some descriptor) :
    descriptor.command.usesMemoryOperand = descriptor.memoryOperand.isSome := by
  cases instruction <;> simp [instructionDescriptor?] at decoded
  all_goals
    subst descriptor
    simp [StageA.X87.Command.usesMemoryOperand]

theorem decodeCommandExact_memoryOperand
    (bytes : Bytes) (descriptor : DecodedCommand)
    (decoded : decodeCommandExact bytes = some descriptor) :
    descriptor.command.usesMemoryOperand = descriptor.memoryOperand.isSome := by
  unfold decodeCommandExact at decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨instruction, instructionExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨instructionDescriptor, descriptorExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨_opcode, _opcodeExact, decoded⟩ := decoded
  cases decoded
  exact instructionDescriptor_memoryOperand instruction.instruction
    instructionDescriptor descriptorExact

theorem decodeSingletonCommand_memoryOperand
    (pe : PE32) (span : Span) (descriptor : DecodedCommand)
    (decoded : decodeSingletonCommand pe span = some descriptor) :
    descriptor.command.usesMemoryOperand = descriptor.memoryOperand.isSome := by
  unfold decodeSingletonCommand at decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨bytes, _bytesExact, decoded⟩ := decoded
  rw [Option.bind_eq_bind] at decoded
  rw [Option.bind_eq_some_iff] at decoded
  obtain ⟨decodedDescriptor, descriptorExact, decoded⟩ := decoded
  split at decoded <;> try contradiction
  simp only [Option.some.injEq] at decoded
  subst descriptor
  exact decodeCommandExact_memoryOperand bytes decodedDescriptor descriptorExact

def stateOnlySingletonCommandChecked (pe : PE32) (span : Span) : Bool :=
  match decodeSingletonCommand pe span with
  | none => false
  | some descriptor =>
      descriptor.memoryOperand.isNone &&
        descriptor.command.expectedOperandBytes.isNone &&
        descriptor.command.expectedStoreKind.isNone &&
        descriptor.command.expectedRegisterTarget.isNone &&
        descriptor.command.eflagsWriteMask == BitVec.ofNat 32 0 &&
        descriptor.command.waitModeChecked descriptor.waitMode

end StageA.Relational.X87
