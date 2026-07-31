import StageA.Formal

namespace StageA.Relational

open StageA.Formal

/-!
The ordinary concrete PE-step vocabulary is kept below the x87 and relational
composition layers.  Exact interpreter certificates need these definitions,
but must not inherit the full whole-program proof closure merely to state one
checked instruction transition.
-/

def concreteBehaviorNextMachineState
    (behavior : ConcreteBehavior) (input : MachineState) : MachineState := {
  registers := behavior.registers
  memory := behavior.memory
  undefinedValue := input.undefinedValue
  x87 := {
    stack := fun index =>
      (behavior.x87.stack.drop index).head?.getD (BitVec.ofNat 80 0)
    control := behavior.x87.control
    status := behavior.x87.status
    semantics := input.x87.semantics
  }
  x87Physical := input.x87Physical
  x87Semantics := input.x87Semantics
  eflags := behavior.eflags
  fsBase := input.fsBase
}

/-- One exact instruction step selected by a concrete PE-relative program
counter. Internal fallthrough remains `running`; every decoded control effect
is exposed as a concrete outcome for the world semantics to handle. -/
inductive PE32InstructionExecution where
  | running (rva undefinedSlot : Nat) (state : MachineState)
  | stopped (outcome : ConcreteOutcome) (state : MachineState)
  | fault

end StageA.Relational
