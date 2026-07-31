import StageA.RelationalInterpreter

namespace StageA.Relational.InterpreterMachineBridge

open StageA.Formal
open StageA.Relational.Interpreter

def formalRegister : Register -> Reg
  | .eax => .eax | .ebx => .ebx | .ecx => .ecx | .edx => .edx
  | .esi => .esi | .edi => .edi | .ebp => .ebp | .esp => .esp

def formalFlagBit : Flag -> Nat
  | .cf => 0 | .zf => 6 | .sf => 7 | .ofl => 11 | .pf => 2 | .df => 10

def flagsFromEflags (eflags : Word) : Flag -> Word := fun flag =>
  BitVec.zeroExtend 32 (eflags.extractLsb' (formalFlagBit flag) 1)

def machineFromFormal (state : MachineState) : InterpreterMachine := {
  registers := fun register => state.registers.get (formalRegister register)
  flags := flagsFromEflags state.eflags
  memory := state.memory
  eflags := state.eflags
}

/-- EFLAGS synchronization is independent of registers and memory when the
interpreter flag view was extracted from the same concrete EFLAGS word. -/
@[simp] theorem flagsFromEflags_syncEflags
    (registers : Register -> Word) (memory : Memory) (eflags : Word) :
    ({ registers := registers, flags := flagsFromEflags eflags,
       memory := memory, eflags := eflags } : InterpreterMachine).syncEflags =
      { registers := registers, flags := flagsFromEflags eflags,
        memory := memory, eflags := eflags } := by
  simp [InterpreterMachine.syncEflags, flagsFromEflags, formalFlagBit,
    Flag.eflagsBit]
  apply BitVec.eq_of_getElem_eq
  intro index bounded
  have possible :
      index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
      index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 ∨
      index = 8 ∨ index = 9 ∨ index = 10 ∨ index = 11 ∨
      index = 12 ∨ index = 13 ∨ index = 14 ∨ index = 15 ∨
      index = 16 ∨ index = 17 ∨ index = 18 ∨ index = 19 ∨
      index = 20 ∨ index = 21 ∨ index = 22 ∨ index = 23 ∨
      index = 24 ∨ index = 25 ∨ index = 26 ∨ index = 27 ∨
      index = 28 ∨ index = 29 ∨ index = 30 ∨ index = 31 := by
    omega
  rcases possible with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp

/-- Specialization of `flagsFromEflags_syncEflags` to a translated formal
machine state. -/
@[simp] theorem machineFromFormal_syncEflags (state : MachineState) :
    (machineFromFormal state).syncEflags = machineFromFormal state := by
  simpa [machineFromFormal] using
    flagsFromEflags_syncEflags
      (fun register => state.registers.get (formalRegister register))
      state.memory state.eflags

def formalFromInterpreter (prior : MachineState)
    (state : InterpreterMachine) : MachineState := {
  registers := {
    eax := state.registers .eax
    ebx := state.registers .ebx
    ecx := state.registers .ecx
    edx := state.registers .edx
    esi := state.registers .esi
    edi := state.registers .edi
    ebp := state.registers .ebp
    esp := state.registers .esp
  }
  memory := state.memory
  undefinedValue := prior.undefinedValue
  x87 := prior.x87
  x87Physical := prior.x87Physical
  x87Semantics := prior.x87Semantics
  eflags := state.eflags
  fsBase := prior.fsBase
}

@[simp] theorem formalFromInterpreter_machineFromFormal (state : MachineState) :
    formalFromInterpreter state (machineFromFormal state) = state := by
  cases state
  rfl

end StageA.Relational.InterpreterMachineBridge
