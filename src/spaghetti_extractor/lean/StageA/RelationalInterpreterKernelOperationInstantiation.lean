import StageA.RelationalInterpreterKernelInvokeOperation
import StageA.RelationalInterpreterKernelRunOperation
import StageA.RelationalInterpreterKernelStepOperation
import StageA.RelationalInterpreterMixedComponentComposition

namespace StageA.Relational.InterpreterKernelOperationInstantiation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterMixedComponentComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked operation instantiation

This module is the stable target for a generated concrete operation closure.
The generated artifact must provide finite semantic closure plus native
certificates at every continuation frame.  None of these fields is a status
assertion or an unchecked whole-operation premise.
-/

/-- Exact native endpoints needed after semantic call-tree closure. -/
structure CheckedKernelOperationNativeEndpoints
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (records : List ProgramRecord) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) where
  programLookup : KernelOperationRefinesUsing program abi
    (NativeWorldKernelDispatches candidate world) .programLookup
  run : forall continuationRva returnAddress,
    RunFunctionNativeCheckedOperationCertificate program abi records candidate
      world continuationRva returnAddress
  invoke :
    InvokeCallNativeCheckedOperationCertificate program abi records candidate
      world
  step :
    InterpreterStepNativeCheckedOperationCertificate program abi records
      candidate world

/-- Whole-program Run dispatch with its exact nested-call coordinates retained.
The existential witness is a `NativeWorldSubroutineResult`, so aggregation
cannot erase the checked finite path or its continuation endpoint. -/
def NativeWorldCheckedRunFunctionDispatches
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) :
    KernelDispatchRelation :=
  fun entryRva before after events =>
    ∃ continuationRva returnAddress,
      NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress entryRva before after events

/-- One common NativeWorld dispatch family for all four kernel operations.
Run remains continuation-indexed inside its dispatch witness; the other three
operations use the ordinary top-level NativeWorld relation. -/
def checkedNativeWorldKernelOperationDispatchFamily
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) :
    KernelOperationDispatchFamily
  | .programLookup => NativeWorldKernelDispatches candidate world
  | .interpreterStep => NativeWorldKernelDispatches candidate world
  | .runFunction => NativeWorldCheckedRunFunctionDispatches candidate world
  | .invokeCall => NativeWorldKernelDispatches candidate world

/-- One concrete semantic and native closure for all three recursive kernel
operations.  Environment and world remain parameters of the generated term. -/
structure CheckedKernelOperationInstantiation
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (records : List ProgramRecord) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) where
  semantic : CheckedSemanticCallTreeClosure records
  native : CheckedKernelOperationNativeEndpoints program abi records candidate
    world

theorem CheckedKernelOperationInstantiation.runRefines
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world)
    (continuationRva : Nat) (returnAddress : Word) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress) .runFunction :=
  (instantiation.native.run continuationRva returnAddress).refines

/-- Detailed Run execution retained for paired finite-cutpoint composition.
Unlike the operation dispatch projection, this result exposes the exact entry,
loop, and epilogue paths and the concrete caller continuation endpoint. -/
noncomputable def CheckedKernelOperationInstantiation.runCutpointCluster
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world)
    (continuationRva : Nat) (returnAddress : Word)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState)
    (requestRelated : abi.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      before)
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result) :
    RunFunctionNativeCheckedCutpointCluster
      (instantiation.native.run continuationRva returnAddress)
      environment resolveCodeTarget sourceRva logical result before
      requestRelated derivation :=
  (instantiation.native.run continuationRva returnAddress).execute environment
    resolveCodeTarget sourceRva logical result before requestRelated derivation

theorem CheckedKernelOperationInstantiation.programLookupRefinesUsingClosed
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    KernelOperationRefinesUsing program abi
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .programLookup) .programLookup :=
  instantiation.native.programLookup

theorem CheckedKernelOperationInstantiation.invokeRefines
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    KernelOperationRefinesUsing program abi
      (NativeWorldKernelDispatches candidate world) .invokeCall :=
  instantiation.native.invoke.refines

theorem CheckedKernelOperationInstantiation.stepRefines
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    KernelOperationRefinesUsing program abi
      (InterpreterStepNativeDispatches candidate world) .interpreterStep :=
  instantiation.native.step.refines

/-- Common-family Run theorem. The selected exact subroutine path remains
available by destructing the dispatch witness into its continuation RVA,
return word, and `NativeWorldSubroutineResult`. -/
theorem CheckedKernelOperationInstantiation.runRefinesUsingClosed
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    KernelOperationRefinesUsing program abi
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .runFunction) .runFunction := by
  intro request before operationExact requestRelated response transition
  let continuationRva := 0
  let returnAddress : Word := 0
  obtain ⟨entryRva, after, events, entryExact, dispatched, responseRelated,
      frame⟩ :=
    instantiation.runRefines continuationRva returnAddress request before
      operationExact requestRelated response transition
  exact ⟨entryRva, after, events, entryExact,
    ⟨continuationRva, returnAddress, dispatched⟩, responseRelated, frame⟩

theorem CheckedKernelOperationInstantiation.invokeRefinesUsingClosed
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    KernelOperationRefinesUsing program abi
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .invokeCall) .invokeCall :=
  instantiation.invokeRefines

theorem CheckedKernelOperationInstantiation.stepRefinesUsingClosed
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    KernelOperationRefinesUsing program abi
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .interpreterStep) .interpreterStep := by
  simpa [checkedNativeWorldKernelOperationDispatchFamily,
    InterpreterStepNativeDispatches, NativeWorldKernelDispatches] using
    instantiation.stepRefines

def CheckedKernelOperationInstantiation.refinementFamily
    (instantiation : CheckedKernelOperationInstantiation program abi records
      candidate world) :
    CheckedKernelOperationRefinementFamily program abi := {
  programLookupDispatch :=
    checkedNativeWorldKernelOperationDispatchFamily candidate world
      .programLookup
  interpreterStepDispatch :=
    checkedNativeWorldKernelOperationDispatchFamily candidate world
      .interpreterStep
  runFunctionDispatch :=
    checkedNativeWorldKernelOperationDispatchFamily candidate world
      .runFunction
  invokeCallDispatch :=
    checkedNativeWorldKernelOperationDispatchFamily candidate world
      .invokeCall
  programLookupRefines := instantiation.programLookupRefinesUsingClosed
  interpreterStepRefines := instantiation.stepRefinesUsingClosed
  runFunctionRefines := instantiation.runRefinesUsingClosed
  invokeCallRefines := instantiation.invokeRefinesUsingClosed
}

/-- Semantic closure is generic after call ownership is represented correctly:
only the external Invoke arm consults `environment.invokeCall`. -/
def checkedKernelSemanticClosure (records : List ProgramRecord) :
    CheckedSemanticCallTreeClosure records :=
  checkedSemanticCallTreeClosure records

#print axioms CheckedKernelOperationInstantiation.runRefines
#print axioms CheckedKernelOperationInstantiation.runCutpointCluster
#print axioms checkedNativeWorldKernelOperationDispatchFamily
#print axioms
  CheckedKernelOperationInstantiation.programLookupRefinesUsingClosed
#print axioms CheckedKernelOperationInstantiation.runRefinesUsingClosed
#print axioms CheckedKernelOperationInstantiation.invokeRefines
#print axioms CheckedKernelOperationInstantiation.invokeRefinesUsingClosed
#print axioms CheckedKernelOperationInstantiation.stepRefines
#print axioms CheckedKernelOperationInstantiation.stepRefinesUsingClosed
#print axioms CheckedKernelOperationInstantiation.refinementFamily
#print axioms checkedKernelSemanticClosure

end StageA.Relational.InterpreterKernelOperationInstantiation
