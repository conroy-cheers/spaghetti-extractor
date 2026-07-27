import StageA.Formal

namespace StageA.Relational.X87StateOnly

open StageA.Formal

/-!
# Stable state-only x87 decode profile

This module deliberately classifies only singleton x87 instructions whose
machine-visible effects exclude general-purpose registers, EFLAGS, and flat
memory.  It is a structural decode profile, not an execution-semantics
authority: x87 success, faults, and x87-state refinement remain separate
composition obligations.

Keeping this small classifier independent of the evolving x87 execution
modules prevents structural direct-call certificates from rebuilding whenever
the richer x87 semantics change.
-/

def instructionChecked : Instruction -> Bool
  | .x87LoadStack _ => true
  | .x87LoadConstant _ => true
  | .x87Exchange _ => true
  | .x87StoreStack _ _ => true
  | .x87Unary _ => true
  | .x87BinaryStack _ _ _ _ => true
  | .x87CompareStack _ .status _ _ => true
  | .x87Wait => true
  | .x87Initialize => true
  | .x87Examine => true
  | _ => false

def singletonCommandChecked (pe : PE32) (span : Span) : Bool :=
  match spanBytes pe span with
  | none => false
  | some bytes =>
      match decodeInstructionExact bytes with
      | none => false
      | some decoded =>
          decoded.size == span.size &&
            instructionChecked decoded.instruction

end StageA.Relational.X87StateOnly
