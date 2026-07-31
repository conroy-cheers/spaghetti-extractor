import StageA.RelationalInterpreterKernelStepActionSimulation
import StageA.RelationalInterpreterKernelStepWorldProgramLookup

namespace StageA.Relational.InterpreterKernelStepWorldActionSimulation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelStepActionSimulation
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepOperationClosure
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterKernelStepWorldProgramLookup
open StageA.Relational.InterpreterNativeWorld

/-!
# Prop-valued world-indexed Step action simulation

Checked semantic derivations are propositions.  Generated proofs therefore
need a Prop-valued action-path interface in order to inspect those derivations
and compose one native iteration at a time.  The existing final Step
certificate is Type-valued because it retains computed endpoints.

This module bridges the two without weakening the path language.  Classical
choice selects only an endpoint and observation list already accompanied by an
`ExactComputedInterpreterStepPath`; it cannot submit either one independently.
-/

structure InterpreterStepNativeWorldCheckedActionSimulationAuthority
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (outerABI : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (operationABI : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (invokeCall : InterpreterStepNativeInvokeCallStaticBinding program candidate
      static.reflected.template)
    (x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
      static.reflected.template) : Prop where
  actions : forall environment (resolveCodeTarget : Word -> Option Nat)
      sourceRva logical result before
      (derivation : CheckedInterpreterStepDerivation semanticRecords environment
        resolveCodeTarget sourceRva logical result)
      (requestRelated : operationABI.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (caller : InterpreterStepNativeWorldProgramLookupCallerFrame program
        semanticRecords outerABI candidate world static site sourceRva before)
      (lookup : InterpreterStepNativeWorldProgramLookupResult program
        semanticRecords outerABI candidate world static site sourceRva before
        caller)
      (invokeCallRefines :
        InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
          world derivation),
    CheckedInterpreterNativeActionExecution static.reflected.template candidate
      lookup.phase

/-- Convert the composable Prop-valued proof into the existing exact action
closure consumed by the Step operation certificate. -/
noncomputable def
    InterpreterStepNativeWorldCheckedActionSimulationAuthority.toExactClosure
    (authority :
      InterpreterStepNativeWorldCheckedActionSimulationAuthority program
        semanticRecords outerABI operationABI candidate world static site
        invokeCall x87Replay) :
    InterpreterStepNativeWorldExactActionClosure program semanticRecords
      outerABI operationABI candidate world static site invokeCall x87Replay := {
  path := by
    intro environment resolveCodeTarget sourceRva logical result before
      derivation requestRelated caller lookup invokeCallRefines
    exact (authority.actions environment resolveCodeTarget sourceRva logical
      result before derivation requestRelated caller lookup
      invokeCallRefines).toExact
}

/-- Direct projection to the authority consumed by whole-Step composition. -/
noncomputable def
    InterpreterStepNativeWorldCheckedActionSimulationAuthority.toAuthority
    (authority :
      InterpreterStepNativeWorldCheckedActionSimulationAuthority program
        semanticRecords outerABI operationABI candidate world static site
        invokeCall x87Replay) :
    InterpreterStepNativeWorldCheckedActionLoopAuthority program semanticRecords
      outerABI operationABI candidate world static site invokeCall x87Replay :=
  authority.toExactClosure.toAuthority

#print axioms
  InterpreterStepNativeWorldCheckedActionSimulationAuthority.toExactClosure
#print axioms
  InterpreterStepNativeWorldCheckedActionSimulationAuthority.toAuthority

end StageA.Relational.InterpreterKernelStepWorldActionSimulation
