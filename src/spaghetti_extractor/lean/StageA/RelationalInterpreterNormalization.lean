import StageA.RelationalInterpreterTransfer
import StageA.RelationalPEMachineStep

namespace StageA.Relational.InterpreterNormalization

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterMachineBridge

/-!
The data in this module is intentionally boring.  An extractor may propose an
instruction partition and a raw interpreter record, but the Boolean checker
below re-reads the PE, re-decodes every instruction, checks the complete path
partition, decodes the raw record, and compares the resulting typed transfer.
No Python status or named semantic theorem is an input to the checker.

`runExactNormalizedPath` is the executable semantics of the exact decoded
path.  It never reads the proposed `ProgramRecord`.  Shape checking remains a
useful diagnostic, but proof authority comes only from the universal equality
stored in `ExactNormalizationCertificate`.  That equality ranges over every
machine state and environment, including every `CallStatus` result.
-/

structure ExactDecodedInstruction where
  rva : Nat
  bytes : Bytes
deriving Repr, DecidableEq

def ExactDecodedInstruction.span (instruction : ExactDecodedInstruction) : Span := {
  start := instruction.rva
  size := instruction.bytes.length
}

/-- Fetch and decode one instruction from the exact immutable PE image. -/
def ExactDecodedInstruction.decode? (pe : PE32)
    (instruction : ExactDecodedInstruction) : Option DecodedInstruction := do
  if instruction.bytes.isEmpty || instruction.bytes.length > 15 then none else
  let exact <- exactRvaBytes pe instruction.rva instruction.bytes.length
  if exact != instruction.bytes then none else
  let decoded <- decodeInstructionExact instruction.bytes
  if decoded.size != instruction.bytes.length then none else
  some decoded

def ExactDecodedInstruction.checked (pe : PE32)
    (instruction : ExactDecodedInstruction) : Bool :=
  (instruction.decode? pe).isSome

structure ExactNormalizedChunk where
  span : Span
  instructions : List ExactDecodedInstruction
deriving Repr, DecidableEq

private def instructionOrderChecked :
    List ExactDecodedInstruction -> Nat -> Nat -> Bool
  | [], expected, stop => expected == stop
  | instruction :: tail, expected, stop =>
      instruction.rva == expected && !instruction.bytes.isEmpty &&
        instructionOrderChecked tail
          (instruction.rva + instruction.bytes.length) stop

def ExactNormalizedChunk.checked (pe : PE32)
    (chunk : ExactNormalizedChunk) : Bool :=
  !chunk.instructions.isEmpty &&
    instructionOrderChecked chunk.instructions chunk.span.start chunk.span.stop &&
    chunk.instructions.all (ExactDecodedInstruction.checked pe)

private def chunkOrderChecked : List ExactNormalizedChunk -> Nat -> Nat -> Bool
  | [], expected, stop => expected == stop
  | chunk :: tail, expected, stop =>
      chunk.span.start == expected &&
        chunkOrderChecked tail chunk.span.stop stop

inductive TransferTerminal where
  | fallthrough (targetRva : Nat)
  | jump (targetRva : Nat)
  | branch (trueTargetRva falseTargetRva : Nat)
  | returned
  | indirectJump
  | externalJump
deriving Repr, DecidableEq

def TransferTerminal.ofOutcome : SemanticOutcome -> TransferTerminal
  | .fallthrough target => .fallthrough target
  | .jump target => .jump target
  | .branch _ trueTarget falseTarget => .branch trueTarget falseTarget
  | .returned _ => .returned
  | .indirectJump _ => .indirectJump
  | .externalJump => .externalJump

inductive OrderedEffectKind where
  | read (width : MemoryWidth)
  | write (width : MemoryWidth)
  | call (kind : CallKind)
  | divideGuard
  | repMovsd
  | repStosd
deriving Repr, DecidableEq

private def operand32ReadEffect : Operand32 -> List OrderedEffectKind
  | .memory _ => [.read .dword]
  | .register _ | .immediate _ => []

private def operand32WriteEffect : Operand32 -> List OrderedEffectKind
  | .memory _ => [.write .dword]
  | .register _ | .immediate _ => []

private def operandWidthReadEffect (width : OperandWidth) :
    Operand32 -> List OrderedEffectKind
  | .memory _ => [.read (match width with
      | .byte => .byte
      | .word => .word)]
  | .register _ | .immediate _ => []

private def operandWidthWriteEffect (width : OperandWidth) :
    Operand32 -> List OrderedEffectKind
  | .memory _ => [.write (match width with
      | .byte => .byte
      | .word => .word)]
  | .register _ | .immediate _ => []

private def operand8ReadEffect : Operand8 -> List OrderedEffectKind
  | .memory _ => [.read .byte]
  | .register _ | .immediate _ => []

private def operand8WriteEffect : Operand8 -> List OrderedEffectKind
  | .memory _ => [.write .byte]
  | .register _ | .immediate _ => []

/-- A reviewed architectural effect inventory for the non-x87 instruction
forms accepted by the normalization checker.  Returning `none` is a proof
frontier, never an implicit no-effect classification. -/
def decodedOrderedEffects? (pe : PE32) (imports : List PEImport)
    (instruction : ExactDecodedInstruction) (decoded : DecodedInstruction) :
    Option (List OrderedEffectKind) :=
  match decoded.instruction with
  | .nop | .movRegImm .. | .movRegReg .. | .addZero .. | .subZero .. |
      .cmpImm .. | .branchEqual .. | .jumpRel8 .. | .jumpRel32 .. |
      .lea .. | .zeroReg .. | .leaAddress .. | .branchCondition .. |
      .convertWordToDword | .convertDwordToQuad | .bitTestRegister .. =>
      some []
  | .ret | .retPop _ | .popReg _ | .popFlags | .leave =>
      some [.read .dword]
  | .popAll => some (List.replicate 8 (.read .dword))
  | .pushReg _ | .pushFlags => some [.write .dword]
  | .pushAll => some (List.replicate 8 (.write .dword))
  | .clearDirection => some []
  | .load32 .. | .movFs32 .. => some [.read .dword]
  | .store32 .. => some [.write .dword]
  | .callRel32 _ => some [.write .dword, .call .internal]
  | .callImport absoluteAddress =>
      if (importAtAbsoluteAddressFrom pe.imageBase imports absoluteAddress).isSome then
        some [.call .external]
      else
        some [.read .dword, .write .dword, .call .indirect]
  | .jumpImport absoluteAddress =>
      if (importAtAbsoluteAddressFrom pe.imageBase imports absoluteAddress).isSome then
        some []
      else some [.read .dword]
  | .movFromOperand _ source => some (operand32ReadEffect source)
  | .movToOperand destination _ => some (operand32WriteEffect destination)
  | .movImmediate destination _ => some (operand32WriteEffect destination)
  | .binary operation destination source =>
      let reads := operand32ReadEffect destination ++ operand32ReadEffect source
      let writes := match operation with
        | .compare | .test => []
        | _ => operand32WriteEffect destination
      some (reads ++ writes)
  | .shift _ destination _ | .unary _ destination =>
      some (operand32ReadEffect destination ++ operand32WriteEffect destination)
  | .shiftWidth width _ destination _ =>
      some (operandWidthReadEffect width destination ++
        operandWidthWriteEffect width destination)
  | .shift8 _ destination _ =>
      some (operand8ReadEffect destination ++ operand8WriteEffect destination)
  | .movZeroExtend _ source _ | .movSignExtend _ source _ =>
      some (operand32ReadEffect source)
  | .movSignExtend8 _ source => some (operand8ReadEffect source)
  | .movSignExtend8ToWord _ source => some (operand8ReadEffect source)
  | .movFromOperandWidth width _ source => some (operandWidthReadEffect width source)
  | .movToOperandWidth width destination _ |
      .movImmediateWidth width destination _ =>
      some (operandWidthWriteEffect width destination)
  | .binaryWidth width operation destination source =>
      let reads := operandWidthReadEffect width destination ++
        operandWidthReadEffect width source
      let writes := match operation with
        | .compare | .test => []
        | _ => operandWidthWriteEffect width destination
      some (reads ++ writes)
  | .movFromOperand8 _ source => some (operand8ReadEffect source)
  | .movToOperand8 destination _ | .movImmediate8 destination _ =>
      some (operand8WriteEffect destination)
  | .binary8 operation destination source =>
      let reads := operand8ReadEffect destination ++ operand8ReadEffect source
      let writes := match operation with
        | .compare | .test => []
        | _ => operand8WriteEffect destination
      some (reads ++ writes)
  | .conditionalMove _ _ source => some (operand32ReadEffect source)
  | .setCondition _ destination => some (operand8WriteEffect destination)
  | .exchange destination _ =>
      some (operand32ReadEffect destination ++ operand32WriteEffect destination)
  | .binaryCarry _ destination source =>
      some (operand32ReadEffect destination ++ operand32ReadEffect source ++
        operand32WriteEffect destination)
  | .multiplyFull _ source => some (operand32ReadEffect source)
  | .multiplyLow _ source _ => some (operand32ReadEffect source)
  | .doubleShift _ destination _ _ =>
      some (operand32ReadEffect destination ++ operand32WriteEffect destination)
  | .bitScan _ _ source => some (operand32ReadEffect source)
  | .moveDwords _ => some [.repMovsd]
  | .storeDwords _ => some [.repStosd]
  | .callIndirect target =>
      some (operand32ReadEffect target ++ [.write .dword, .call .indirect])
  | .jumpIndirect target => some (operand32ReadEffect target)
  | .pushOperand source =>
      some (operand32ReadEffect source ++ [.write .dword])
  | .divideUnsigned source | .divideSigned source =>
      some (operand32ReadEffect source ++ [.divideGuard])
  | .atomicCompareExchange destination _ =>
      some [.read .dword, .write .dword]
  | .x87LoadStack .. | .x87LoadConstant .. | .x87Exchange .. |
      .x87StoreStack .. | .x87Unary .. | .x87BinaryStack .. |
      .x87CompareStack .. | .x87LoadMemory .. | .x87StoreMemory .. |
      .x87BinaryMemory .. | .x87LoadControl .. | .x87StoreControl .. |
      .x87SaveState .. | .x87RestoreState .. | .x87Wait | .x87Initialize |
      .x87StoreStatusAx | .x87Examine => none

private def pureTerminal : OutcomeExpr -> TransferTerminal
  | .returned _ => .returned
  | .jump target => .jump target
  | .branch _ taken fallthrough => .branch taken fallthrough
  | .call _ continuation _ | .externalCall _ _ continuation |
      .bulkCopy _ continuation | .bulkFill _ continuation |
      .indirectCall _ continuation _ |
      .checkedContinue _ continuation |
      .atomicCompareExchange _ _ _ continuation => .fallthrough continuation
  | .externalJump _ _ => .externalJump
  | .indirectJump _ => .indirectJump

def decodedTerminal? (pe : PE32) (imports : List PEImport)
    (instruction : ExactDecodedInstruction) (decoded : DecodedInstruction) :
    Option TransferTerminal := do
  let result <- executeInstruction pe imports instruction.rva 0 decoded initialSymbolic
  match result with
  | .next _ => some (.fallthrough (instruction.rva + decoded.size))
  | .stop behavior => behavior.outcome.map pureTerminal

private def exactInstructionInventory? (pe : PE32) (imports : List PEImport) :
    List ExactDecodedInstruction -> Option (List OrderedEffectKind × TransferTerminal)
  | [] => none
  | [instruction] => do
      let decoded <- instruction.decode? pe
      let effects <- decodedOrderedEffects? pe imports instruction decoded
      let terminal <- decodedTerminal? pe imports instruction decoded
      some (effects, terminal)
  | instruction :: tail => do
      let decoded <- instruction.decode? pe
      let effects <- decodedOrderedEffects? pe imports instruction decoded
      let terminal <- decodedTerminal? pe imports instruction decoded
      if terminal != .fallthrough (instruction.rva + decoded.size) then none else
      let remaining <- exactInstructionInventory? pe imports tail
      some (effects ++ remaining.1, remaining.2)

def semanticTransferOrderedEffectKinds
    (transfer : SemanticTransfer) : List OrderedEffectKind :=
  transfer.body.flatMap fun action =>
    match action with
    | .evalWord nodeIndex =>
        match transfer.wordNodes[nodeIndex]? with
        | some { op := .load, aux, .. } =>
            (MemoryWidth.ofBytes? aux).toList.map .read
        | _ => []
    | .memoryWrite _ _ width => [.write width]
    | .call callIndex =>
        match transfer.calls[callIndex]? with
        | some call => [.call call.kind]
        | none => []
    | .divideIf _ => [.divideGuard]
    | .repMovsd .. => [.repMovsd]
    | .repStosd .. => [.repStosd]
    | .setRegister .. | .setFlag .. | .syncEflags => []

def semanticTransferCallActionIndices
    (transfer : SemanticTransfer) : List Nat :=
  transfer.body.zipIdx.filterMap fun item =>
    match item.1 with
    | .call _ => some item.2
    | _ => none

def semanticTransferPostCallProjectionChecked
    (transfer : SemanticTransfer) : Bool :=
  match semanticTransferCallActionIndices transfer with
  | [] => true
  | [actionIndex] =>
      let suffix := transfer.body.drop (actionIndex + 1)
      let callIndex := match transfer.body[actionIndex]? with
        | some (.call index) => index
        | _ => transfer.calls.length
      let responseNodes := suffix.filterMap fun action =>
        match action with
        | .evalWord node => some node
        | _ => none
      let responseShape := responseNodes.all fun nodeIndex =>
        match transfer.wordNodes[nodeIndex]? with
        | some node =>
            match node.op with
            | .callResponse | .callFlag =>
                match transfer.calls[callIndex]? with
                | some call => node.immediate == call.callIndex
                | none => false
            | _ => false
        | _ => false
      let nonEvaluationShape := suffix.all fun action =>
        match action with
        | .evalWord _ | .setRegister _ _ | .setFlag _ _ | .syncEflags => true
        | _ => false
      responseShape && nonEvaluationShape
  | _ => false

structure ExactStackInputSpec where
  offset : Nat
  width : MemoryWidth
deriving Repr, DecidableEq

structure ExactCallBoundarySpec where
  instructionRva : Nat
  callIndex : Nat
  argumentOffsets : List Nat := []
  stackInputs : List ExactStackInputSpec := []
deriving Repr, DecidableEq

structure ExactNormalizedTransferPath where
  sourceRva : Nat
  stopRva : Nat
  chunks : List ExactNormalizedChunk
  terminal : TransferTerminal
  orderedEffects : List OrderedEffectKind
  record : ProgramRecord
  callBoundaries : List ExactCallBoundarySpec := []
deriving Repr, DecidableEq

def ExactNormalizedTransferPath.instructions
    (path : ExactNormalizedTransferPath) : List ExactDecodedInstruction :=
  path.chunks.flatMap (fun chunk => chunk.instructions)

def ExactNormalizedTransferPath.partitionChecked
    (path : ExactNormalizedTransferPath) : Bool :=
  !path.chunks.isEmpty && path.sourceRva < path.stopRva &&
    chunkOrderChecked path.chunks path.sourceRva path.stopRva &&
    path.chunks.all fun chunk =>
      chunk.span.start < chunk.span.stop &&
        chunk.span.start >= path.sourceRva && chunk.span.stop <= path.stopRva

def ExactNormalizedTransferPath.exactDecodeChecked
    (pe : PE32) (path : ExactNormalizedTransferPath) : Bool :=
  path.partitionChecked && path.chunks.all (ExactNormalizedChunk.checked pe)

/--
The normalization result is computed by Lean from the raw record.  Successful
compilation additionally checks source/terminal/effect inventories and the
only currently legal call continuation shape.  The record's Python status is
not represented in this type.
-/
def ExactNormalizedTransferPath.diagnosticCompile? (pe : PE32)
    (path : ExactNormalizedTransferPath) : Option SemanticTransfer := do
  if !path.exactDecodeChecked pe || path.record.sourceRva != path.sourceRva then
    none
  else
    let imports <- parseImports pe
    let exactInventory <- exactInstructionInventory? pe imports path.instructions
    if exactInventory.1 != path.orderedEffects ||
        exactInventory.2 != path.terminal then none else
    let transfer <- path.record.decode
    if !transfer.checked || transfer.sourceRva != path.sourceRva ||
        TransferTerminal.ofOutcome transfer.outcome != path.terminal ||
        semanticTransferOrderedEffectKinds transfer != path.orderedEffects ||
        !semanticTransferPostCallProjectionChecked transfer then
      none
    else
      some transfer

def diagnosticTransferShapeChecked (pe : PE32)
    (path : ExactNormalizedTransferPath) (transfer : SemanticTransfer) : Bool :=
  path.diagnosticCompile? pe == some transfer

/-! Exact decoded execution.  This is deliberately independent of the raw
`ProgramRecord`: every step starts from exact PE bytes and the reviewed Formal
instruction semantics. -/

private def addressOf (state : MachineState) (addressing : Addressing) : Word :=
  (addressing.expression initialSymbolic.registers).eval state

private def operand32Address? (state : MachineState) : Operand32 -> Option Word
  | .memory addressing => some (addressOf state addressing)
  | .register _ | .immediate _ => none

private def operand8Address? (state : MachineState) : Operand8 -> Option Word
  | .memory addressing => some (addressOf state addressing)
  | .register _ | .immediate _ => none

/-- Canonical ordinary-memory read observation used by exact path replay. -/
def exactReadEvent (state : MachineState) (address : Word)
    (width : MemoryWidth) : InterpreterEvent :=
  .memoryRead address width (readMemory state.memory address width)

/-- Canonical ordinary-memory write observation used by exact path replay. -/
def exactWriteEvent (state : MachineState) (address : Word)
    (width : MemoryWidth) : InterpreterEvent :=
  .memoryWrite address width (readMemory state.memory address width)

private abbrev readEvent := exactReadEvent
private abbrev writeEvent := exactWriteEvent

private def operand32ReadEvents (state : MachineState)
    (operand : Operand32) : List InterpreterEvent :=
  (operand32Address? state operand).toList.map fun address =>
    readEvent state address .dword

private def operand32WriteEvents (state : MachineState)
    (operand : Operand32) : List InterpreterEvent :=
  (operand32Address? state operand).toList.map fun address =>
    writeEvent state address .dword

private def operandWidthMemoryWidth : OperandWidth -> MemoryWidth
  | .byte => .byte
  | .word => .word

private def operandWidthReadEvents (state : MachineState)
    (width : OperandWidth) (operand : Operand32) : List InterpreterEvent :=
  (operand32Address? state operand).toList.map fun address =>
    readEvent state address (operandWidthMemoryWidth width)

private def operandWidthWriteEvents (state : MachineState)
    (width : OperandWidth) (operand : Operand32) : List InterpreterEvent :=
  (operand32Address? state operand).toList.map fun address =>
    writeEvent state address (operandWidthMemoryWidth width)

private def operand8ReadEvents (state : MachineState)
    (operand : Operand8) : List InterpreterEvent :=
  (operand8Address? state operand).toList.map fun address =>
    readEvent state address .byte

private def operand8WriteEvents (state : MachineState)
    (operand : Operand8) : List InterpreterEvent :=
  (operand8Address? state operand).toList.map fun address =>
    writeEvent state address .byte

/-- Compute the ordered ordinary-memory observations of one decoded
instruction.  Unsupported x87 accesses and any unreviewed form fail closed. -/
def exactInstructionMemoryEvents? (pe : PE32) (imports : List PEImport)
    (decoded : DecodedInstruction) (before after : MachineState) :
    Option (List InterpreterEvent) :=
  match decoded.instruction with
  | .nop | .movRegImm .. | .movRegReg .. | .addZero .. | .subZero .. |
      .cmpImm .. | .branchEqual .. | .jumpRel8 .. | .jumpRel32 .. |
      .lea .. | .zeroReg .. | .leaAddress .. | .branchCondition .. |
      .convertWordToDword | .convertDwordToQuad | .bitTestRegister .. |
      .clearDirection | .moveDwords _ | .storeDwords _ => some []
  | .ret | .retPop _ =>
      some [readEvent before before.registers.esp .dword]
  | .popReg _ => some [readEvent before before.registers.esp .dword]
  | .popFlags => some [readEvent before before.registers.esp .dword]
  | .popAll =>
      some ((List.range 8).map fun index =>
        readEvent before
          (before.registers.esp + BitVec.ofNat 32 (index * 4)) .dword)
  | .leave => some [readEvent before before.registers.ebp .dword]
  | .pushReg _ => some [writeEvent after after.registers.esp .dword]
  | .pushFlags => some [writeEvent after after.registers.esp .dword]
  | .pushAll =>
      some ((List.range 8).map fun index =>
        writeEvent after
          (before.registers.esp - BitVec.ofNat 32 ((index + 1) * 4)) .dword)
  | .load32 _ base offset =>
      some [readEvent before (before.registers.get base + BitVec.ofNat 32 offset) .dword]
  | .store32 base offset _ =>
      some [writeEvent after (before.registers.get base + BitVec.ofNat 32 offset) .dword]
  | .callRel32 _ => some [writeEvent after after.registers.esp .dword]
  | .callImport absoluteAddress =>
      if (importAtAbsoluteAddressFrom pe.imageBase imports absoluteAddress).isSome then
        some []
      else some [readEvent before (BitVec.ofNat 32 absoluteAddress) .dword,
        writeEvent after after.registers.esp .dword]
  | .jumpImport absoluteAddress =>
      if (importAtAbsoluteAddressFrom pe.imageBase imports absoluteAddress).isSome then
        some []
      else some [readEvent before (BitVec.ofNat 32 absoluteAddress) .dword]
  | .movFromOperand _ source => some (operand32ReadEvents before source)
  | .movToOperand destination _ => some (operand32WriteEvents after destination)
  | .movImmediate destination _ => some (operand32WriteEvents after destination)
  | .binary operation destination source =>
      let reads := operand32ReadEvents before destination ++
        operand32ReadEvents before source
      let writes := match operation with
        | .compare | .test => []
        | _ => operand32WriteEvents after destination
      some (reads ++ writes)
  | .shift _ destination _ | .unary _ destination =>
      some (operand32ReadEvents before destination ++
        operand32WriteEvents after destination)
  | .shiftWidth width _ destination _ =>
      some (operandWidthReadEvents before width destination ++
        operandWidthWriteEvents after width destination)
  | .shift8 _ destination _ =>
      some (operand8ReadEvents before destination ++ operand8WriteEvents after destination)
  | .movZeroExtend _ source _ | .movSignExtend _ source _ =>
      some (operand32ReadEvents before source)
  | .movSignExtend8 _ source | .movSignExtend8ToWord _ source =>
      some (operand8ReadEvents before source)
  | .movFromOperandWidth width _ source =>
      some (operandWidthReadEvents before width source)
  | .movToOperandWidth width destination _ |
      .movImmediateWidth width destination _ =>
      some (operandWidthWriteEvents after width destination)
  | .binaryWidth width operation destination source =>
      let reads := operandWidthReadEvents before width destination ++
        operandWidthReadEvents before width source
      let writes := match operation with
        | .compare | .test => []
        | _ => operandWidthWriteEvents after width destination
      some (reads ++ writes)
  | .movFromOperand8 _ source => some (operand8ReadEvents before source)
  | .movToOperand8 destination _ | .movImmediate8 destination _ =>
      some (operand8WriteEvents after destination)
  | .binary8 operation destination source =>
      let reads := operand8ReadEvents before destination ++ operand8ReadEvents before source
      let writes := match operation with
        | .compare | .test => []
        | _ => operand8WriteEvents after destination
      some (reads ++ writes)
  | .conditionalMove _ _ source => some (operand32ReadEvents before source)
  | .setCondition _ destination => some (operand8WriteEvents after destination)
  | .exchange destination _ =>
      some (operand32ReadEvents before destination ++
        operand32WriteEvents after destination)
  | .binaryCarry _ destination source =>
      some (operand32ReadEvents before destination ++ operand32ReadEvents before source ++
        operand32WriteEvents after destination)
  | .multiplyFull _ source | .multiplyLow _ source _ |
      .bitScan _ _ source => some (operand32ReadEvents before source)
  | .doubleShift _ destination _ _ =>
      some (operand32ReadEvents before destination ++
        operand32WriteEvents after destination)
  | .callIndirect target =>
      some (operand32ReadEvents before target ++
        [writeEvent after after.registers.esp .dword])
  | .jumpIndirect target => some (operand32ReadEvents before target)
  | .pushOperand source =>
      some (operand32ReadEvents before source ++
        [writeEvent after after.registers.esp .dword])
  | .movFs32 _ source =>
      let address := before.fsBase + addressOf before source
      some [readEvent before address .dword]
  | .divideUnsigned source | .divideSigned source =>
      some (operand32ReadEvents before source)
  | .atomicCompareExchange destination _ =>
      let address := addressOf before destination
      some [readEvent before address .dword, writeEvent after address .dword]
  | .x87LoadStack .. | .x87LoadConstant .. | .x87Exchange .. |
      .x87StoreStack .. | .x87Unary .. | .x87BinaryStack .. |
      .x87CompareStack .. | .x87LoadMemory .. | .x87StoreMemory .. |
      .x87BinaryMemory .. | .x87LoadControl .. | .x87StoreControl .. |
      .x87SaveState .. | .x87RestoreState .. | .x87Wait | .x87Initialize |
      .x87StoreStatusAx | .x87Examine => none

private def bytesString (bytes : Bytes) : String :=
  String.ofList (bytes.map Char.ofNat)

private def importFields (imported : PEImport) :
    String × Option String × Option Nat :=
  match imported.name with
  | .symbol name => (bytesString imported.dll, some (bytesString name), none)
  | .ordinal ordinal => (bytesString imported.dll, none, some ordinal)

private def ExactNormalizedTransferPath.callBoundary?
    (path : ExactNormalizedTransferPath) (instructionRva : Nat) :
    Option ExactCallBoundarySpec :=
  match path.callBoundaries.filter (fun boundary =>
      boundary.instructionRva == instructionRva) with
  | [boundary] => some boundary
  | _ => none

private def stackAddress (state : InterpreterMachine) (offset : Nat) : Word :=
  state.registers .esp + BitVec.ofNat 32 offset

private def makeCallEvent (path : ExactNormalizedTransferPath)
    (instructionRva : Nat) (kind : CallKind) (target : Word)
    (returnRva : Nat) (imported : Option PEImport)
    (state : InterpreterMachine) : Option CallEvent := do
  let boundary <- path.callBoundary? instructionRva
  let arguments := boundary.argumentOffsets.map fun offset =>
    readMemory state.memory (stackAddress state offset) .dword
  let stackInputs := boundary.stackInputs.map fun input =>
    (input.offset, input.width,
      readMemory state.memory (stackAddress state input.offset) input.width)
  let fields := imported.map importFields
  some {
    kind
    instructionRva
    callIndex := boundary.callIndex
    targetRva := target
    returnRva
    dll := fields.map (·.1)
    symbol := fields.bind (·.2.1)
    ordinal := fields.bind (·.2.2)
    arguments
    stackInputs
  }

private def completionOfStatus : CallStatus -> Option Completion
  | .ok => none
  | .divideError => some .divideError
  | .memoryFault => some .memoryFault
  | .externalFault => some .externalFault
  | .unimplemented => some .unimplemented

def exactResult (state : MachineState) (events : List InterpreterEvent)
    (completion : Completion) : MacroResult := {
  state := StageA.Relational.InterpreterTransfer.machineFromFormal state
  events
  completion
}

private def exactCallResult (events : List InterpreterEvent)
    (event : CallEvent) (result : CallResult) : MacroResult := {
  state := result.state
  events := events ++ [.call event]
  completion := (completionOfStatus result.status).getD .unimplemented
}

/-- Execute one instruction obtained from the exact bytes named by the path.
This is the same reviewed instruction semantics used by PE execution, but the
fetch is deliberately bounded to the submitted instruction span.  The span is
only a proposal: `ExactDecodedInstruction.decode?` re-reads every byte from the
immutable PE before decoding it. -/
def executeExactDecodedInstruction? (pe : PE32) (imports : List PEImport)
    (instruction : ExactDecodedInstruction) (undefinedSlot : Nat)
    (state : MachineState) :
    Option (DecodedInstruction × PE32InstructionExecution) := do
  let decoded <- instruction.decode? pe
  let result <- executeInstruction pe imports instruction.rva undefinedSlot
    decoded initialSymbolic
  match result with
  | .next symbolic =>
      let concrete := symbolic.eval state
      match concrete.outcome with
      | some _ => none
      | none =>
          some (decoded, .running (instruction.rva + decoded.size)
            (undefinedSlot + 1)
            (concreteBehaviorNextMachineState concrete state))
  | .stop symbolic =>
      let concrete := symbolic.eval state
      match concrete.outcome with
      | none => none
      | some outcome =>
          some (decoded, .stopped outcome
            (concreteBehaviorNextMachineState concrete state))

def runExactDecodedInstructions (pe : PE32) (imports : List PEImport)
    (path : ExactNormalizedTransferPath)
    (environment : StageA.Relational.Interpreter.Environment) :
    Nat -> List ExactDecodedInstruction -> MachineState -> List InterpreterEvent ->
      Option MacroResult
  | _, [], state, events => some (exactResult state events (.fallthrough path.stopRva))
  | undefinedSlot, instruction :: tail, state, events => do
      let (decoded, stepped) <-
        executeExactDecodedInstruction? pe imports instruction undefinedSlot state
      match stepped with
      | .fault => none
      | .running nextRva nextSlot nextState => do
          let memoryEvents <- exactInstructionMemoryEvents? pe imports decoded state nextState
          let events := events ++ memoryEvents
          match tail with
          | [] => some (exactResult nextState events (.fallthrough nextRva))
          | next :: _ =>
              if next.rva != nextRva then none else
              runExactDecodedInstructions pe imports path environment nextSlot tail
                nextState events
      | .stopped outcome nextState => do
          let memoryEvents <- exactInstructionMemoryEvents? pe imports decoded state nextState
          let events := events ++ memoryEvents
          match outcome with
          | .returned target =>
              if !tail.isEmpty then none else
              some (exactResult nextState events (.returned target))
          | .jump target =>
              if !tail.isEmpty then none else
              some (exactResult nextState events (.jump target))
          | .branch condition taken fallthrough =>
              if !tail.isEmpty then none else
              some (exactResult nextState events
                (.branch (if condition then taken else fallthrough)))
          | .indirectJump target =>
              if !tail.isEmpty then none else
              some (exactResult nextState events (.indirectJump target))
          | .call target continuation _ => do
              let input := StageA.Relational.InterpreterTransfer.machineFromFormal nextState
              let event <- makeCallEvent path instruction.rva .internal
                (BitVec.ofNat 32 target) continuation none input
              let result := environment.invokeCall event input
              match completionOfStatus result.status with
              | some _ => some (exactCallResult events event result)
              | none =>
                  let after := formalFromInterpreter nextState result.state
                  match tail with
                  | [] => some {
                      state := result.state
                      events := events ++ [.call event]
                      completion := .fallthrough continuation
                    }
                  | next :: _ =>
                      if next.rva != continuation then none else
                      runExactDecodedInstructions pe imports path environment 0 tail after
                        (events ++ [.call event])
          | .externalCall imported arguments continuation => do
              let input := StageA.Relational.InterpreterTransfer.machineFromFormal nextState
              let event <- makeCallEvent path instruction.rva .external
                (BitVec.ofNat 32 0) continuation (some imported) input
              if event.arguments != arguments then none else
              let result := environment.invokeCall event input
              match completionOfStatus result.status with
              | some _ => some (exactCallResult events event result)
              | none =>
                  let after := formalFromInterpreter nextState result.state
                  match tail with
                  | [] => some {
                      state := result.state
                      events := events ++ [.call event]
                      completion := .fallthrough continuation
                    }
                  | next :: _ =>
                      if next.rva != continuation then none else
                      runExactDecodedInstructions pe imports path environment 0 tail after
                        (events ++ [.call event])
          | .indirectCall target continuation _ => do
              let input := StageA.Relational.InterpreterTransfer.machineFromFormal nextState
              let event <- makeCallEvent path instruction.rva .indirect target continuation none input
              let result := environment.invokeCall event input
              match completionOfStatus result.status with
              | some _ => some (exactCallResult events event result)
              | none =>
                  let after := formalFromInterpreter nextState result.state
                  match tail with
                  | [] => some {
                      state := result.state
                      events := events ++ [.call event]
                      completion := .fallthrough continuation
                    }
                  | next :: _ =>
                      if next.rva != continuation then none else
                      runExactDecodedInstructions pe imports path environment 0 tail after
                        (events ++ [.call event])
          | .externalJump imported arguments => do
              if !tail.isEmpty then none else
              let input := StageA.Relational.InterpreterTransfer.machineFromFormal nextState
              let event <- makeCallEvent path instruction.rva .external
                (BitVec.ofNat 32 0) 0 (some imported) input
              if event.arguments != arguments then none else
              let result := environment.invokeCall event input
              match completionOfStatus result.status with
              | some _ => some (exactCallResult events event result)
              | none => some {
                  state := result.state
                  events := events ++ [.call event]
                  completion := .externalJump
                }
          | .bulkCopy destination source count direction continuation =>
              let input := StageA.Relational.InterpreterTransfer.machineFromFormal nextState
              let copied := repMovsd input source destination direction count.toNat
              let events := events ++ [.repMovsd source destination count direction]
              match tail with
              | [] => some { state := copied, events, completion := .fallthrough continuation }
              | next :: _ =>
                  if next.rva != continuation then none else
                  runExactDecodedInstructions pe imports path environment 0 tail
                    (formalFromInterpreter nextState copied) events
          | .bulkFill destination value count direction continuation =>
              let input :=
                StageA.Relational.InterpreterTransfer.machineFromFormal nextState
              let filled := repStosd input destination value direction count.toNat
              let events :=
                events ++ [.repStosd destination value count direction]
              match tail with
              | [] =>
                  some {
                    state := filled
                    events
                    completion := .fallthrough continuation
                  }
              | next :: _ =>
                  if next.rva != continuation then none else
                  runExactDecodedInstructions pe imports path environment 0 tail
                    (formalFromInterpreter nextState filled) events
          | .checkedContinue valid continuation =>
              if !valid then some (exactResult nextState events .divideError) else
              match tail with
              | [] => some (exactResult nextState events (.fallthrough continuation))
              | next :: _ =>
                  if next.rva != continuation then none else
                  runExactDecodedInstructions pe imports path environment 0 tail nextState events
          | .atomicCompareExchange _ _ _ continuation =>
              match tail with
              | [] => some (exactResult nextState events (.fallthrough continuation))
              | next :: _ =>
                  if next.rva != continuation then none else
                  runExactDecodedInstructions pe imports path environment 0 tail nextState events

/-- Authoritative exact-path execution.  No `ProgramRecord` field is read. -/
def runExactNormalizedPath (pe : PE32) (path : ExactNormalizedTransferPath)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : MachineState) : Option MacroResult := do
  if !path.exactDecodeChecked pe then none else
  let imports <- parseImports pe
  runExactDecodedInstructions pe imports path environment 0 path.instructions state []

theorem runExactNormalizedPath_of_checked (pe : PE32)
    (path : ExactNormalizedTransferPath)
    (imports : List PEImport)
    (pathChecked : path.exactDecodeChecked pe = true)
    (importsParsed : parseImports pe = some imports)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : MachineState) :
    runExactNormalizedPath pe path environment state =
      runExactDecodedInstructions pe imports path environment 0
        path.instructions state [] := by
  simp [runExactNormalizedPath, pathChecked, importsParsed]

/-- This is the actual semantic obligation.  Inventory/shape checks do not
imply it and are intentionally absent from whole-program acceptance. -/
def SemanticTransferRefinesExactPath (pe : PE32)
    (path : ExactNormalizedTransferPath) (transfer : SemanticTransfer) : Prop :=
  forall state environment,
    transfer.execute environment
        (StageA.Relational.InterpreterTransfer.machineFromFormal state) =
      runExactNormalizedPath pe path environment state

/-- Proof-producing normalization boundary.  The Boolean field is deliberately
insufficient: it catches malformed data early, while `semanticRefinement` is
the universal theorem that authorizes the transfer. -/
structure ExactNormalizationCertificate (pe : PE32)
    (path : ExactNormalizedTransferPath) (transfer : SemanticTransfer) : Prop where
  diagnosticShape : diagnosticTransferShapeChecked pe path transfer = true
  semanticRefinement : SemanticTransferRefinesExactPath pe path transfer

theorem ExactNormalizationCertificate.sound
    {pe : PE32} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer}
    (certificate : ExactNormalizationCertificate pe path transfer) :
    SemanticTransferRefinesExactPath pe path transfer :=
  certificate.semanticRefinement

/-- A raw record contributes no semantics until Lean decodes it to the same
typed transfer and checks a semantic certificate against exact PE execution. -/
structure ExactProgramRecordNormalizationCertificate (pe : PE32)
    (path : ExactNormalizedTransferPath) (transfer : SemanticTransfer) : Prop where
  recordDecoded : path.record.decode = some transfer
  transferChecked : transfer.checked = true
  normalization : ExactNormalizationCertificate pe path transfer

theorem ExactProgramRecordNormalizationCertificate.rawMacroStep
    {pe : PE32} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer}
    (certificate : ExactProgramRecordNormalizationCertificate pe path transfer)
    (environment : StageA.Relational.Interpreter.Environment)
    (state : MachineState) :
    path.record.interpret environment
        (StageA.Relational.InterpreterTransfer.machineFromFormal state) =
      runExactNormalizedPath pe path environment state := by
  rw [ProgramRecord.macroStep_semantic_correspondence path.record transfer
    certificate.recordDecoded certificate.transferChecked]
  exact certificate.normalization.semanticRefinement state environment

end StageA.Relational.InterpreterNormalization
