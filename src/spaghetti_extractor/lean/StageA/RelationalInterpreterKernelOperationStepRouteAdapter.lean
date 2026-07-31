import StageA.RelationalInterpreterKernelOperationBoundedStateRoute
import StageA.RelationalInterpreterKernelOperationStateBoundaryChecker
import StageA.RelationalInterpreterKernelStepProgramLookupExactComputation

namespace StageA.Relational.InterpreterKernelOperationStepRouteAdapter

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelOperationStateBoundaryChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
open StageA.Relational.InterpreterKernelStepProgramLookupExactComputation
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked operation routes as Step proof objects

The whole-operation checker and the older Step proof surface use the same
exact native transition system, but package finite execution differently.
This module is the single bridge between them:

* one checked operation block becomes one fixed-fuel Step chunk;
* one checked boundary route becomes one exact helper subroutine; and
* the ProgramLookup call block becomes the existing exact call replay.

No endpoint, observation list, state, or fuel is re-evaluated.  Every result is
projected from a checked block or route, and all template membership facts
remain explicit.
-/

/-- A checked operation block identified with one reflected Step cutpoint. -/
structure CheckedInterpreterStepBlockBinding
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (block : CheckedNativeOperationBlock candidate) where
  cutpoint : InterpreterStepNativeCutpoint
  cutpointMember : cutpoint ∈ template.cutpoints
  entryRvaExact : block.entryRva = cutpoint.entryRva
  entrySlotExact : block.entrySlot = 0
  fuelExact : block.fuel = cutpoint.instructionCount

def CheckedInterpreterStepBlockBinding.chunk
    (binding : CheckedInterpreterStepBlockBinding template candidate block)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    InterpreterStepNativeChunk template candidate
      (.running binding.cutpoint.entryRva 0 state calls eventIndex events
        world) := {
  cutpoint := binding.cutpoint
  cutpointMember := binding.cutpointMember
  startsAt := rfl
  positive := by
    rw [← binding.fuelExact]
    cases runningExact : block.running <;>
      simp [CheckedNativeOperationBlock.fuel, runningExact]
}

theorem CheckedInterpreterStepBlockBinding.resultExact
    (binding : CheckedInterpreterStepBlockBinding template candidate block)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    (binding.chunk state calls eventIndex events world).result =
      (block.after state calls eventIndex events world,
        block.observations state calls eventIndex events world) := by
  change
    runRelatedSteps candidate.transitionSystem
        binding.cutpoint.instructionCount
        (.running binding.cutpoint.entryRva 0 state calls eventIndex events
          world) =
      _
  rw [← binding.fuelExact, ← binding.entryRvaExact,
    ← binding.entrySlotExact]
  exact block.runExact state calls eventIndex events world

theorem CheckedInterpreterStepBlockBinding.afterExact
    (binding : CheckedInterpreterStepBlockBinding template candidate block)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    (binding.chunk state calls eventIndex events world).after =
      block.after state calls eventIndex events world :=
  congrArg Prod.fst
    (binding.resultExact state calls eventIndex events world)

theorem CheckedInterpreterStepBlockBinding.observationsExact
    (binding : CheckedInterpreterStepBlockBinding template candidate block)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    (binding.chunk state calls eventIndex events world).observations =
      block.observations state calls eventIndex events world :=
  congrArg Prod.snd
    (binding.resultExact state calls eventIndex events world)

/-- A checked block with a proved allowed destination is an exact Step path
leaf.  The destination is still computed by the candidate transition system. -/
def CheckedInterpreterStepBlockBinding.toExactPath
    (binding : CheckedInterpreterStepBlockBinding template candidate block)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (destinationChecked :
      (binding.chunk state calls eventIndex events world).destinationChecked) :
    ExactComputedInterpreterStepPath template candidate
      (.running binding.cutpoint.entryRva 0 state calls eventIndex events world)
      (binding.chunk state calls eventIndex events world).observations
      (binding.chunk state calls eventIndex events world).after :=
  .chunk (binding.chunk state calls eventIndex events world)
    destinationChecked

/-- Repackage a checked boundary route as an exact computed segment.  Its fuel
is the witness selected by the route's already-proved nonempty path. -/
noncomputable def exactSegmentOfCheckedStateBoundaryRoute
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    ExactComputedNativeWorldSegment candidate before := {
  fuel := route.toCheckedPath.fuel
  positive := route.toCheckedPath.positive
}

theorem exactSegmentOfCheckedStateBoundaryRoute_after
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    (exactSegmentOfCheckedStateBoundaryRoute route).after = after := by
  exact route.toCheckedPath_after

theorem exactSegmentOfCheckedStateBoundaryRoute_observations
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after) :
    (exactSegmentOfCheckedStateBoundaryRoute route).observations =
      observations := by
  exact route.toCheckedPath_observations

/-- A boundary route between a checked helper target and its continuation is
the exact helper leaf accepted by the Step proof. -/
noncomputable def exactInterpreterStepSubroutineOfCheckedStateBoundaryRoute
    (template : InterpreterStepNativeTemplate)
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after)
    (targetRva continuationRva : Nat)
    (boundaryAllowed :
      template.subroutineBoundaryAllowed targetRva continuationRva)
    (continuationAllowed : continuationRva ∈ template.cutpointRvas)
    (startsAt : before.rva? = some targetRva)
    (finishesAt : after.rva? = some continuationRva) :
    ExactComputedInterpreterStepSubroutine template candidate before := {
  targetRva
  continuationRva
  boundaryAllowed
  continuationAllowed
  startsAt
  segment := exactSegmentOfCheckedStateBoundaryRoute route
  finishesAt := by
    rw [exactSegmentOfCheckedStateBoundaryRoute_after route]
    exact finishesAt
}

theorem
    exactInterpreterStepSubroutineOfCheckedStateBoundaryRoute_observations
    (template : InterpreterStepNativeTemplate)
    (route : CheckedNativeOperationStateBoundaryRoute candidate blocks before
      observations after)
    (targetRva continuationRva : Nat)
    (boundaryAllowed :
      template.subroutineBoundaryAllowed targetRva continuationRva)
    (continuationAllowed : continuationRva ∈ template.cutpointRvas)
    (startsAt : before.rva? = some targetRva)
    (finishesAt : after.rva? = some continuationRva) :
    (exactInterpreterStepSubroutineOfCheckedStateBoundaryRoute template route
      targetRva continuationRva boundaryAllowed continuationAllowed startsAt
      finishesAt).segment.observations = observations :=
  exactSegmentOfCheckedStateBoundaryRoute_observations route

/-- Construct the existing exact ProgramLookup call replay from the checked
operation block that contains the direct call instruction. -/
def exactInterpreterStepProgramLookupCallReplayOfCheckedBlock
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (world : RelationalWorld)
    (block : CheckedNativeOperationBlock candidate)
    (binding : CheckedInterpreterStepBlockBinding static.reflected.template
      candidate block)
    (callBeforeState lookupBefore : MachineState)
    (effectExact : binding.cutpoint.effect = .programLookupCall)
    (destinationAllowed :
      site.parameters.targetRva ∈ binding.cutpoint.allowedRvas)
    (afterExact :
      block.after callBeforeState [] 0 [] world =
        .running site.parameters.targetRva 0 lookupBefore
          [{
            continuationRva := site.parameters.continuationRva
            returnAddress := site.parameters.returnAddress candidate.pe
          }] 0 [] world) :
    ExactInterpreterStepProgramLookupCallReplay program candidate static site
      world
      (.running binding.cutpoint.entryRva 0 callBeforeState [] 0 [] world) := {
  cutpoint := binding.cutpoint
  cutpointMember := binding.cutpointMember
  startsAt := rfl
  positive := (binding.chunk callBeforeState [] 0 [] world).positive
  effectExact
  destinationAllowed
  lookupBefore
  observations := block.observations callBeforeState [] 0 [] world
  executorExact := by
    change
      (binding.chunk callBeforeState [] 0 [] world).result =
        (.running site.parameters.targetRva 0 lookupBefore
          [{
            continuationRva := site.parameters.continuationRva
            returnAddress := site.parameters.returnAddress candidate.pe
          }] 0 [] world,
          block.observations callBeforeState [] 0 [] world)
    rw [binding.resultExact callBeforeState [] 0 [] world]
    rw [afterExact]
}

#print axioms CheckedInterpreterStepBlockBinding.resultExact
#print axioms CheckedInterpreterStepBlockBinding.toExactPath
#print axioms exactSegmentOfCheckedStateBoundaryRoute_after
#print axioms
  exactInterpreterStepSubroutineOfCheckedStateBoundaryRoute_observations
#print axioms exactInterpreterStepProgramLookupCallReplayOfCheckedBlock

end StageA.Relational.InterpreterKernelOperationStepRouteAdapter
