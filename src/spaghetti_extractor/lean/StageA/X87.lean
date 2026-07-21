import Std

namespace StageA.X87

abbrev Word := BitVec 80

inductive Tag where
  | valid
  | zero
  | special
deriving Repr, DecidableEq

inductive Slot where
  | empty
  | occupied (tag : Tag) (value : Word)
deriving Repr, DecidableEq

inductive LoadFormat where
  | float32
  | float64
  | float80
  | int32
deriving Repr, DecidableEq

def LoadFormat.byteWidth : LoadFormat -> Nat
  | .float32 | .int32 => 4
  | .float64 => 8
  | .float80 => 10

inductive StoreFormat where
  | float32
  | float64
  | float80
  | int32
deriving Repr, DecidableEq

def StoreFormat.byteWidth : StoreFormat -> Nat
  | .float32 | .int32 => 4
  | .float64 => 8
  | .float80 => 10

inductive UnaryOperation where
  | negate
deriving Repr, DecidableEq

inductive BinaryOperation where
  | add
  | multiply
  | subtract
  | reverseSubtract
  | divide
  | reverseDivide
deriving Repr, DecidableEq

inductive CompareMode where
  | ordered
  | unordered
deriving Repr, DecidableEq

inductive CompareDestination where
  | status
  | eflags
deriving Repr, DecidableEq

inductive RoundingMode where
  | controlWord
  | truncate
deriving Repr, DecidableEq

inductive WaitMode where
  | waiting
  | noWait
deriving Repr, DecidableEq

/-- Physical x87 state. Logical ST(i) access is derived from TOP in `status`;
it is not represented by shifting the eight physical slots. -/
structure PhysicalState where
  slots : Vector Slot 8
  control : BitVec 16
  status : BitVec 16
  pendingException : Bool
  lastOpcode : BitVec 11
  instructionPointer : BitVec 32
  codeSelector : BitVec 16
  dataPointer : BitVec 32
  dataSelector : BitVec 16
deriving Repr, DecidableEq

/-- Arithmetic state is separated from concrete instruction/data metadata so
the shared numerical semantics cannot distinguish relocated implementations. -/
structure CoreState where
  slots : Vector Slot 8
  control : BitVec 16
  status : BitVec 16
  pendingException : Bool
deriving Repr, DecidableEq

structure MetadataState where
  lastOpcode : BitVec 11
  instructionPointer : BitVec 32
  codeSelector : BitVec 16
  dataPointer : BitVec 32
  dataSelector : BitVec 16
deriving Repr, DecidableEq

def PhysicalState.core (state : PhysicalState) : CoreState := {
  slots := state.slots
  control := state.control
  status := state.status
  pendingException := state.pendingException
}

def PhysicalState.metadata (state : PhysicalState) : MetadataState := {
  lastOpcode := state.lastOpcode
  instructionPointer := state.instructionPointer
  codeSelector := state.codeSelector
  dataPointer := state.dataPointer
  dataSelector := state.dataSelector
}

def PhysicalState.withCoreAndMetadata (_state : PhysicalState)
    (core : CoreState) (metadata : MetadataState) : PhysicalState := {
  slots := core.slots
  control := core.control
  status := core.status
  pendingException := core.pendingException
  lastOpcode := metadata.lastOpcode
  instructionPointer := metadata.instructionPointer
  codeSelector := metadata.codeSelector
  dataPointer := metadata.dataPointer
  dataSelector := metadata.dataSelector
}

def initialPhysicalState : PhysicalState := {
  slots := Vector.replicate 8 .empty
  control := BitVec.ofNat 16 0x037f
  status := BitVec.ofNat 16 0
  pendingException := false
  lastOpcode := BitVec.ofNat 11 0
  instructionPointer := BitVec.ofNat 32 0
  codeSelector := BitVec.ofNat 16 0
  dataPointer := BitVec.ofNat 32 0
  dataSelector := BitVec.ofNat 16 0
}

def PhysicalState.top (state : PhysicalState) : Nat :=
  (state.status.toNat / (2 ^ 11)) % 8

def PhysicalState.physicalIndex (state : PhysicalState) (logical : Nat) : Fin 8 :=
  ⟨(state.top + logical) % 8, Nat.mod_lt _ (by decide)⟩

def PhysicalState.logicalSlot (state : PhysicalState) (logical : Nat) : Slot :=
  state.slots[state.physicalIndex logical]

inductive Command where
  | wait
  | initialize
  | loadStack (index : Nat)
  | loadConstant (value : Word)
  | exchange (index : Nat)
  | storeStack (index : Nat) (pop : Bool)
  | unary (operation : UnaryOperation)
  | binaryStack (operation : BinaryOperation)
      (destination source : Nat) (pop : Bool)
  | compareStack (mode : CompareMode) (destination : CompareDestination)
      (index : Nat) (pop : Bool)
  | loadMemory (format : LoadFormat)
  | storeMemory (format : StoreFormat) (rounding : RoundingMode) (pop : Bool)
  | binaryMemory (operation : BinaryOperation) (format : LoadFormat)
  | loadControl
  | storeControl
  | storeStatusAx
  | examine
deriving Repr, DecidableEq

/-- Raw machine inputs supplied by the checked instruction layer. Memory
addresses and access checks remain in the flat x86 machine model. -/
structure StepInput where
  operandBits : Word
  operandBytes : Nat
  opcode : BitVec 11
  instructionPointer : BitVec 32
  codeSelector : BitVec 16
  dataPointer : BitVec 32
  dataSelector : BitVec 16
deriving Repr, DecidableEq

structure OperandInput where
  bits : Word
  bytes : Nat
deriving Repr, DecidableEq

def StepInput.operand (input : StepInput) : OperandInput := {
  bits := input.operandBits
  bytes := input.operandBytes
}

inductive Fault where
  | floatingPoint
deriving Repr, DecidableEq

inductive StoreKind where
  | numeric (format : StoreFormat)
  | controlWord
deriving Repr, DecidableEq

def StoreKind.byteWidth : StoreKind -> Nat
  | .numeric format => format.byteWidth
  | .controlWord => 2

structure StoreResult where
  kind : StoreKind
  bits : Word
deriving Repr, DecidableEq

inductive RegisterTarget where
  | ax
deriving Repr, DecidableEq

structure RegisterResult where
  target : RegisterTarget
  value : BitVec 32
deriving Repr, DecidableEq

/-- Definedness is explicit so poison cannot silently flow into control,
addresses, observations, stores, returns, or fault selection. -/
structure Definedness where
  slotMasks : Vector Word 8
  statusMask : BitVec 16
  eflagsMask : BitVec 32
  storeMask : Word
  registerMask : BitVec 32
deriving Repr, DecidableEq

structure Response where
  nextState : PhysicalState
  store : Option StoreResult
  register : Option RegisterResult
  eflagsValue : BitVec 32
  eflagsWriteMask : BitVec 32
  definedness : Definedness
  fault : Option Fault
deriving Repr, DecidableEq

structure CoreResponse where
  nextState : CoreState
  store : Option StoreResult
  register : Option RegisterResult
  eflagsValue : BitVec 32
  eflagsWriteMask : BitVec 32
  definedness : Definedness
  fault : Option Fault
deriving Repr, DecidableEq

structure MachineEffect where
  response : Response
  memoryAddress : Option (BitVec 32)
deriving Repr, DecidableEq

def Command.expectedOperandBytes : Command -> Option Nat
  | .loadMemory format | .binaryMemory _ format => some format.byteWidth
  | .loadControl => some 2
  | _ => none

def Command.expectedStoreKind : Command -> Option StoreKind
  | .storeMemory format _ _ => some (.numeric format)
  | .storeControl => some .controlWord
  | _ => none

def Command.expectedRegisterTarget : Command -> Option RegisterTarget
  | .storeStatusAx => some .ax
  | _ => none

def Command.eflagsWriteMask : Command -> BitVec 32
  | .compareStack _ .eflags _ _ => BitVec.ofNat 32 0x8d5
  | _ => BitVec.ofNat 32 0

def Command.usesMemoryOperand : Command -> Bool
  | .loadMemory _ | .storeMemory _ _ _ | .binaryMemory _ _ |
      .loadControl | .storeControl => true
  | _ => false

def Command.expectedWaitMode : Command -> WaitMode
  | .initialize | .storeControl | .storeStatusAx => .noWait
  | _ => .waiting

def Command.waitModeValid (command : Command) (waitMode : WaitMode) : Prop :=
  waitMode = command.expectedWaitMode

def Command.waitModeChecked (command : Command) (waitMode : WaitMode) : Bool :=
  waitMode == command.expectedWaitMode

theorem Command.waitModeValid_of_checked (command : Command)
    (waitMode : WaitMode) (checked : command.waitModeChecked waitMode = true) :
    command.waitModeValid waitMode := by
  simpa [Command.waitModeChecked, Command.waitModeValid] using checked

theorem Command.waitModeChecked_of_valid (command : Command)
    (waitMode : WaitMode) (valid : command.waitModeValid waitMode) :
    command.waitModeChecked waitMode = true := by
  simpa [Command.waitModeChecked, Command.waitModeValid] using valid

def MetadataState.after (previous : MetadataState) (command : Command)
    (input : StepInput) : MetadataState := {
  lastOpcode := input.opcode
  instructionPointer := input.instructionPointer
  codeSelector := input.codeSelector
  dataPointer := if command.usesMemoryOperand then input.dataPointer
    else previous.dataPointer
  dataSelector := if command.usesMemoryOperand then input.dataSelector
    else previous.dataSelector
}

def StepInput.validFor (input : StepInput) (command : Command) : Prop :=
  input.operandBytes = command.expectedOperandBytes.getD 0 ∧
    input.operandBits.toNat < 2 ^ (8 * input.operandBytes)

def OperandInput.validFor (input : OperandInput) (command : Command) : Prop :=
  input.bytes = command.expectedOperandBytes.getD 0 ∧
    input.bits.toNat < 2 ^ (8 * input.bytes)

theorem StepInput.operand_validFor (input : StepInput) (command : Command)
    (valid : input.validFor command) : input.operand.validFor command :=
  valid

def StoreResult.valid (store : StoreResult) : Prop :=
  store.bits.toNat < 2 ^ (8 * store.kind.byteWidth)

def StoreResult.checked (store : StoreResult) : Bool :=
  decide (store.bits.toNat < 2 ^ (8 * store.kind.byteWidth))

theorem StoreResult.valid_of_checked (store : StoreResult)
    (checked : store.checked = true) : store.valid := by
  simpa [StoreResult.checked, StoreResult.valid] using checked

def Response.structurallyValid (response : Response) (command : Command)
    (waitMode : WaitMode) : Prop :=
  response.store.map StoreResult.kind = command.expectedStoreKind ∧
  response.store.all StoreResult.checked = true ∧
  response.register.map RegisterResult.target = command.expectedRegisterTarget ∧
  response.eflagsWriteMask = command.eflagsWriteMask ∧
  response.definedness.eflagsMask = response.eflagsWriteMask ∧
  (response.store.isNone → response.definedness.storeMask = BitVec.ofNat 80 0) ∧
  (response.register.isNone →
    response.definedness.registerMask = BitVec.ofNat 32 0) ∧
  (response.fault.isSome → waitMode = .waiting) ∧
  (command = .wait → waitMode = .waiting)

def CoreResponse.structurallyValid (response : CoreResponse) (command : Command)
    (waitMode : WaitMode) : Prop :=
  response.store.map StoreResult.kind = command.expectedStoreKind ∧
  response.store.all StoreResult.checked = true ∧
  response.register.map RegisterResult.target = command.expectedRegisterTarget ∧
  response.eflagsWriteMask = command.eflagsWriteMask ∧
  response.definedness.eflagsMask = response.eflagsWriteMask ∧
  (response.store.isNone → response.definedness.storeMask = BitVec.ofNat 80 0) ∧
  (response.register.isNone →
    response.definedness.registerMask = BitVec.ofNat 32 0) ∧
  (response.fault.isSome → waitMode = .waiting) ∧
  (command = .wait → waitMode = .waiting)

def CoreResponse.toResponse (response : CoreResponse) (previous : PhysicalState)
    (command : Command) (input : StepInput) : Response := {
  nextState := previous.withCoreAndMetadata response.nextState
    (previous.metadata.after command input)
  store := response.store
  register := response.register
  eflagsValue := response.eflagsValue
  eflagsWriteMask := response.eflagsWriteMask
  definedness := response.definedness
  fault := response.fault
}

theorem CoreResponse.toResponse_structurallyValid (response : CoreResponse)
    (previous : PhysicalState) (command : Command) (input : StepInput)
    (waitMode : WaitMode) (valid : response.structurallyValid command waitMode) :
    (response.toResponse previous command input).structurallyValid command waitMode :=
  by
    simpa [CoreResponse.toResponse, Response.structurallyValid,
      CoreResponse.structurallyValid] using valid

def StepInput.checkedFor (input : StepInput) (command : Command) : Bool :=
  input.operandBytes == command.expectedOperandBytes.getD 0 &&
    decide (input.operandBits.toNat < 2 ^ (8 * input.operandBytes))

theorem StepInput.validFor_of_checked (input : StepInput) (command : Command)
    (checked : input.checkedFor command = true) : input.validFor command := by
  simpa [StepInput.checkedFor, StepInput.validFor, Bool.and_eq_true] using checked

theorem StepInput.checkedFor_of_valid (input : StepInput) (command : Command)
    (valid : input.validFor command) : input.checkedFor command = true := by
  simpa [StepInput.checkedFor, StepInput.validFor, Bool.and_eq_true,
    decide_eq_true_eq] using valid

def Response.checkedFor (response : Response) (command : Command)
    (waitMode : WaitMode) : Bool :=
  decide (response.store.map StoreResult.kind = command.expectedStoreKind) &&
    (response.store.all StoreResult.checked &&
    (decide (response.register.map RegisterResult.target =
      command.expectedRegisterTarget) &&
    (decide (response.eflagsWriteMask = command.eflagsWriteMask) &&
    (decide (response.definedness.eflagsMask = response.eflagsWriteMask) &&
    (decide (response.store.isNone →
      response.definedness.storeMask = BitVec.ofNat 80 0) &&
    (decide (response.register.isNone →
      response.definedness.registerMask = BitVec.ofNat 32 0) &&
    (decide (response.fault.isSome → waitMode = .waiting) &&
      decide (command = .wait → waitMode = .waiting))))))))

theorem Response.structurallyValid_of_checked (response : Response)
    (command : Command) (waitMode : WaitMode)
    (checked : response.checkedFor command waitMode = true) :
    response.structurallyValid command waitMode := by
  simpa only [Response.checkedFor, Response.structurallyValid,
    Bool.and_eq_true, decide_eq_true_eq] using checked

theorem Response.checkedFor_of_structurallyValid (response : Response)
    (command : Command) (waitMode : WaitMode)
    (valid : response.structurallyValid command waitMode) :
    response.checkedFor command waitMode = true := by
  simpa only [Response.checkedFor, Response.structurallyValid,
    Bool.and_eq_true, decide_eq_true_eq] using valid

/-- Numeric behavior is parametric. Initial relational proofs require identical
commands and related raw inputs, then use congruence of this shared deterministic
step function. No placeholder IEEE-754 result is trusted. -/
structure Semantics where
  step : Command -> WaitMode -> CoreState -> OperandInput -> CoreResponse
  qualified : ∀ command waitMode state input,
    command.waitModeValid waitMode →
    input.validFor command →
      (step command waitMode state input).structurallyValid command waitMode

def Semantics.execute (semantics : Semantics) (command : Command)
    (waitMode : WaitMode) (state : PhysicalState) (input : StepInput) : Response :=
  (semantics.step command waitMode state.core input.operand).toResponse
    state command input

def Semantics.Complies (semantics : Semantics) : Prop :=
  ∀ command waitMode state input,
    command.waitModeValid waitMode →
    input.validFor command →
      (semantics.step command waitMode state input).structurallyValid command waitMode

theorem Semantics.complies (semantics : Semantics) : semantics.Complies :=
  semantics.qualified

theorem Semantics.step_congr (semantics : Semantics)
    {originalCommand candidateCommand : Command}
    {originalWait candidateWait : WaitMode}
    {originalState candidateState : CoreState}
    {originalInput candidateInput : OperandInput}
    (command : originalCommand = candidateCommand)
    (waitMode : originalWait = candidateWait)
    (state : originalState = candidateState)
    (input : originalInput = candidateInput) :
    semantics.step originalCommand originalWait originalState originalInput =
      semantics.step candidateCommand candidateWait candidateState candidateInput := by
  subst candidateCommand
  subst candidateWait
  subst candidateState
  subst candidateInput
  rfl

theorem Semantics.step_structurallyValid (semantics : Semantics)
    (complies : semantics.Complies) (command : Command) (waitMode : WaitMode)
    (state : CoreState) (input : OperandInput)
    (modeValid : command.waitModeValid waitMode)
    (valid : input.validFor command) :
    (semantics.step command waitMode state input).structurallyValid command waitMode :=
  complies command waitMode state input modeValid valid

theorem Semantics.execute_structurallyValid (semantics : Semantics)
    (complies : semantics.Complies) (command : Command) (waitMode : WaitMode)
    (state : PhysicalState) (input : StepInput)
    (modeValid : command.waitModeValid waitMode)
    (valid : input.validFor command) :
    (semantics.execute command waitMode state input).structurallyValid command waitMode := by
  apply CoreResponse.toResponse_structurallyValid
  exact semantics.step_structurallyValid complies command waitMode state.core
    input.operand modeValid (input.operand_validFor command valid)

def zeroDefinedness (command : Command) : Definedness := {
  slotMasks := Vector.replicate 8 (BitVec.ofNat 80 0)
  statusMask := BitVec.ofNat 16 0
  eflagsMask := command.eflagsWriteMask
  storeMask := BitVec.ofNat 80 0
  registerMask := BitVec.ofNat 32 0
}

/-- A deterministic constructor default, not an architectural x87 model.
Acceptance quantifies over the shared semantics carried by the program and
never treats this value as qualification evidence. -/
def defaultSemantics : Semantics := {
  step := fun command _ state _ => {
    nextState := state
    store := command.expectedStoreKind.map fun kind => {
      kind
      bits := BitVec.ofNat 80 0
    }
    register := command.expectedRegisterTarget.map fun target => {
      target
      value := BitVec.ofNat 32 0
    }
    eflagsValue := BitVec.ofNat 32 0
    eflagsWriteMask := command.eflagsWriteMask
    definedness := zeroDefinedness command
    fault := none
  }
  qualified := by
    intro command waitMode state input modeValid inputValid
    cases command <;>
      simp_all [CoreResponse.structurallyValid, zeroDefinedness,
        Command.expectedStoreKind, Command.expectedRegisterTarget,
        Command.eflagsWriteMask, Command.waitModeValid,
        Command.expectedWaitMode, StoreResult.checked]
    all_goals
      apply Nat.pow_pos
      decide
}

end StageA.X87
