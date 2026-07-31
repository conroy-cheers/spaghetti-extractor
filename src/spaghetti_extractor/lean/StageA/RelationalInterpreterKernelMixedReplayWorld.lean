import StageA.RelationalInterpreterKernelMixedReplay
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterKernelMixedReplayWorld

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelMixedReplay
open StageA.Relational.InterpreterNativeWorld

/-! # Mixed replay in the nested native world

This module deliberately sits above both the compact mixed-instruction kernel
and the larger native-world model.  Keeping the lift here prevents edits to the
small instruction-composition theorem from invalidating external-environment
and whole-program modules.
-/

/-- Lift a successful exact mixed-instruction path into the nested native-world
transition system.  Internal machine steps cannot create external events or
alter the call/resource envelopes; calls, returns, and other stopped outcomes
are intentionally excluded and handled at their explicit cutpoints. -/
theorem runRelatedSteps_mixedReplay_running
    (program : ExactNestedNativeWorldProgram)
    (instruction : KernelMixedReplayInstruction)
    (tail : List KernelMixedReplayInstruction)
    (undefinedSlot finalSlot : Nat)
    (input after : MachineState)
    (finalRva : Nat)
    (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (externalFrames : List NativeWorldExternalCallbackRuntime)
    (executed :
      runKernelMixedReplayConcrete program.pe program.imports undefinedSlot input
        (instruction :: tail) =
          .running finalRva finalSlot after) :
    runRelatedSteps program.transitionSystem (instruction :: tail).length
        (.running instruction.rva undefinedSlot input calls eventIndex events
          world externalFrames) =
      (.running finalRva finalSlot after calls eventIndex events world
        externalFrames, []) := by
  induction tail generalizing instruction undefinedSlot input with
  | nil =>
      simp only [runKernelMixedReplayConcrete] at executed
      simp only [List.length_cons, List.length_nil, runRelatedSteps,
        ExactNestedNativeWorldProgram.transitionSystem,
        stepPE32NestedNativeWorldExecution, executed, Option.toList_none,
        List.nil_append]
  | cons next rest induction =>
      cases first :
          stepKernelPE32Instruction program.pe program.imports
            (.running instruction.rva undefinedSlot input) with
      | running nextRva nextSlot nextState =>
          simp only [runKernelMixedReplayConcrete, first] at executed
          split at executed
          next contiguous =>
            have rvaExact : nextRva = next.rva := by
              exact beq_iff_eq.mp contiguous
            have tailExecuted :
                runKernelMixedReplayConcrete program.pe program.imports nextSlot
                    nextState (next :: rest) =
                  .running finalRva finalSlot after :=
              executed
            have tailPath := induction next nextSlot nextState tailExecuted
            subst nextRva
            simp only [List.length_cons, runRelatedSteps,
              ExactNestedNativeWorldProgram.transitionSystem,
              stepPE32NestedNativeWorldExecution, first, Option.toList_none,
              List.nil_append]
            exact tailPath
          next discontinuous => contradiction
      | stopped outcome nextState =>
          simp [runKernelMixedReplayConcrete, first] at executed
      | fault =>
          simp [runKernelMixedReplayConcrete, first] at executed

#print axioms runRelatedSteps_mixedReplay_running

end StageA.Relational.InterpreterKernelMixedReplayWorld
