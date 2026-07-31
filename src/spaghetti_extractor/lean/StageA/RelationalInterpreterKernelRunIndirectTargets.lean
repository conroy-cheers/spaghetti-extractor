import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelRunEndpointReplay

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked Run indirect targets

This module isolates the exact finite-target authority used by Run's resolver
call.  It depends only on the native transition system, so target inventory
changes do not require rebuilding the Run operation or ABI proof layers.
-/

/-- The exact two-byte form used by the resolver boundary is the
register-indirect `call eax` machine instruction. -/
theorem runFunctionResolverCallEaxDecodeExact :
    decodeInstructionExact [0xff, 0xd0] =
      some {
        instruction := .callIndirect (.register .eax)
        size := 2
        trailing := []
      } := by
  decide +kernel

/-- Check one resolver site's authoritative finite target set.  A missing,
ambiguous, non-executable, or differently classified target fails closed. -/
def nativeRunResolverTargetInventoryChecked
    (candidate : ExactNativeWorldProgram) (sourceRva : Nat)
    (expectedTargets : List Nat) : Bool :=
  candidate.indirectTargets.valid candidate.pe &&
    match candidate.indirectTargets.targetSet? sourceRva .call with
    | none => false
    | some targetSet =>
        targetSet.shapeValid candidate.pe &&
          targetSet.targets ==
            expectedTargets.map NativeIndirectTargetDescriptor.internalRva

theorem nativeRunResolverTargetInventoryChecked_targetSetExact
    (candidate : ExactNativeWorldProgram) (sourceRva : Nat)
    (expectedTargets : List Nat)
    (checked :
      nativeRunResolverTargetInventoryChecked candidate sourceRva
        expectedTargets = true) :
    ∃ targetSet,
      candidate.indirectTargets.targetSet? sourceRva .call = some targetSet ∧
        targetSet.shapeValid candidate.pe = true ∧
        targetSet.targets =
          expectedTargets.map NativeIndirectTargetDescriptor.internalRva := by
  simp only [nativeRunResolverTargetInventoryChecked, Bool.and_eq_true] at checked
  split at checked
  case h_1 =>
    simp at checked
  case h_2 targetSet targetSetExact =>
    simp only [Bool.and_eq_true] at checked
    exact ⟨targetSet, targetSetExact, checked.2.1,
      beq_iff_eq.mp checked.2.2⟩

#print axioms runFunctionResolverCallEaxDecodeExact
#print axioms nativeRunResolverTargetInventoryChecked_targetSetExact

end StageA.Relational.InterpreterKernelRunEndpointReplay
