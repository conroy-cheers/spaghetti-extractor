import StageA.RelationalInterpreterMachineBridge

namespace StageA.Relational.Source

open StageA.Formal
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterMachineBridge

/-! Stable C0 source AST, canonical renderer, and executable source semantics. -/

private def encodeOption (encode : α -> List Nat) : Option α -> List Nat
  | none => [0]
  | some value => 1 :: encode value

private def encodeList (encode : α -> List Nat) (values : List α) : List Nat :=
  values.length :: values.flatMap encode

private def encodeNat (value : Nat) : List Nat := [value]

private def encodeString (value : String) : List Nat :=
  encodeList (fun character => [character.toNat]) value.toList

private def encodeRawWordNode (node : RawWordNode) : List Nat :=
  [node.op, node.arity, node.aux, node.immediate] ++
    encodeList encodeNat node.args

private def encodeRawStackInput (input : RawStackInput) : List Nat :=
  [input.offset, input.width, input.valueNode]

private def encodeRawCall (call : RawCall) : List Nat :=
  [call.kind, call.instructionRva, call.callIndex] ++
    encodeOption encodeNat call.targetNode ++
    [call.targetRva, call.returnRva] ++
    encodeOption encodeString call.dll ++
    encodeOption encodeString call.symbol ++
    encodeOption encodeNat call.ordinal ++
    encodeList encodeNat call.registerNodes ++
    encodeList encodeNat call.flagNodes ++
    encodeList encodeNat call.argumentNodes ++
    encodeList encodeRawStackInput call.stackInputs

private def encodeRawAction (action : RawAction) : List Nat :=
  [action.op, action.arity, action.aux] ++ encodeList encodeNat action.args

def encodeProgramRecord (record : ProgramRecord) : List Nat :=
  [record.sourceRva] ++
    encodeList encodeRawWordNode record.wordNodes ++
    encodeList encodeRawWordNode record.x87Nodes ++
    encodeList encodeRawCall record.calls ++
    encodeList encodeRawAction record.actions

structure C0Program where
  entryRva : Nat
  records : List ProgramRecord
deriving Repr, DecidableEq

def C0Program.encoding (program : C0Program) : List Nat :=
  [1, program.entryRva] ++ encodeList encodeProgramRecord program.records

private def renderWord (value : Nat) : String := toString value ++ "u"

private def renderWords (values : List Nat) : String :=
  String.intercalate ", " (values.map renderWord)

def C0Program.canonicalSource (program : C0Program) : String :=
  "#include <stdint.h>\n" ++
  "#include \"spaghetti-c0-runtime-v1.h\"\n\n" ++
  "static const uint32_t spaghetti_c0_program[] = {\n  " ++
  renderWords program.encoding ++ "\n};\n\n" ++
  "int mainCRTStartup(void) {\n" ++
  "  return spaghetti_c0_run(spaghetti_c0_program, " ++
  renderWord program.encoding.length ++ ", " ++
  renderWord program.entryRva ++ ");\n" ++
  "}\n"

def C0Program.sourceRvas (program : C0Program) : List Nat :=
  program.records.map (fun record => record.sourceRva)

def SemanticOutcome.directTargets : SemanticOutcome -> Option (List Nat)
  | .fallthrough target | .jump target => some [target]
  | .branch _ taken fallthrough => some [taken, fallthrough]
  | .returned _ | .externalJump => some []
  | .indirectJump _ => none

def ProgramRecord.directTargets (record : ProgramRecord) : Option (List Nat) := do
  let transfer <- record.decode
  SemanticOutcome.directTargets transfer.outcome

def C0Program.closed (program : C0Program) : Bool :=
  !program.records.isEmpty &&
    program.records.all ProgramRecord.checked &&
    decide program.sourceRvas.Nodup &&
    program.sourceRvas.contains program.entryRva &&
    program.records.all fun record =>
      match ProgramRecord.directTargets record with
      | none => false
      | some targets => targets.all program.sourceRvas.contains

structure CheckedC0Source (program : C0Program) (source : String) : Prop where
  programClosed : program.closed = true
  sourceExact : source = program.canonicalSource

def sourceStep : List ProgramRecord -> Nat -> Interpreter.Environment ->
    MachineState -> Option MacroResult
  | [], _, _, _ => none
  | record :: tail, rva, environment, state =>
      if record.sourceRva == rva then
        record.interpret environment (machineFromFormal state)
      else sourceStep tail rva environment state

structure WholeExecution where
  currentRva : Option Nat
  state : MachineState
  events : List InterpreterEvent
  completion : Option Completion

def WholeExecution.launch (entryRva : Nat) (state : MachineState) :
    WholeExecution := {
  currentRva := some entryRva
  state := state
  events := []
  completion := none
}

def WholeExecution.advance (execution : WholeExecution)
    (result : MacroResult) : WholeExecution :=
  let events := execution.events ++ result.events
  match result.completion with
  | .fallthrough target | .jump target | .branch target => {
      currentRva := some target
      state := formalFromInterpreter execution.state result.state
      events := events
      completion := none
    }
  | completion => {
      currentRva := none
      state := formalFromInterpreter execution.state result.state
      events := events
      completion := some completion
    }

def runWithStep
    (step : Nat -> Interpreter.Environment -> MachineState -> Option MacroResult)
    (environment : Interpreter.Environment) : Nat -> WholeExecution -> WholeExecution
  | 0, execution => execution
  | fuel + 1, execution =>
      match execution.currentRva with
      | none => execution
      | some rva =>
          match step rva environment execution.state with
          | none => execution
          | some result =>
              runWithStep step environment fuel (execution.advance result)

structure PinnedC0ToolchainProfile where
  identifier : String
  derivation : String
  compilerSha256 : String
  assemblerSha256 : String
  linkerSha256 : String
  runtimeSha256 : String
deriving Repr, DecidableEq

structure CompiledArtifact where
  bytes : ByteTree
  pe : PE32
  parsedExactly : parsePE32Tree bytes = some pe

/-- The explicit trusted hypothesis for C0 lowering and the pinned toolchain. -/
def CorrectPinnedCompilation
    (profile : PinnedC0ToolchainProfile) (program : C0Program)
    (artifact : CompiledArtifact)
    (compiledRun : Interpreter.Environment -> Nat -> WholeExecution -> WholeExecution) : Prop :=
  profile.identifier != "" ∧
  profile.derivation != "" ∧
  profile.compilerSha256.length = 64 ∧
  profile.assemblerSha256.length = 64 ∧
  profile.linkerSha256.length = 64 ∧
  profile.runtimeSha256.length = 64 ∧
  artifact.bytes.length > 0 ∧
  forall environment fuel launch,
    runWithStep (sourceStep program.records) environment fuel launch =
      compiledRun environment fuel launch

end StageA.Relational.Source
