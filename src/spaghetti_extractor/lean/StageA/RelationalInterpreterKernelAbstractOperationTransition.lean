import StageA.RelationalInterpreterKernelOperationResultEncoding

namespace StageA.Relational.InterpreterKernelAbstractOperationTransition

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked abstract-operation transitions

`AbstractKernelTransition` is authoritative, but downstream certificates need
a branch-specific way to construct it without accepting a submitted transition
or response.  This dependent derivation contains only the semantic facts that
are not definitionally determined by the request:

* lookup and Step carry no residual fact;
* Run carries its existing `AbstractRunFunction` derivation;
* external Invoke carries only the checked branch discriminator;
* internal Invoke carries its branch discriminator and nested Run derivation;
* indirect Invoke additionally carries the exact resolver result.

The response is fixed by each constructor's result index.
-/

inductive CheckedAbstractOperationDerivation :
    AbstractKernelRequest -> AbstractKernelResponse -> Prop
  | programLookup (records sourceRva) :
      CheckedAbstractOperationDerivation
        (.programLookup records sourceRva)
        (.programLookup (lookupProgramRecord records sourceRva))
  | interpreterStep (records environment sourceRva state) :
      CheckedAbstractOperationDerivation
        (.interpreterStep records environment sourceRva state)
        (.interpreterStep
          (abstractInterpreterStep records environment sourceRva state))
  | runFunction
      (derivation : AbstractRunFunction records environment resolveCodeTarget
        sourceRva state result) :
      CheckedAbstractOperationDerivation
        (.runFunction records environment resolveCodeTarget sourceRva state)
        (.call result)
  | invokeExternal
      (kind : event.kind = .external) :
      CheckedAbstractOperationDerivation
        (.invokeCall records environment resolveCodeTarget event state)
        (.call (environment.invokeCall event state))
  | invokeInternal
      (kind : event.kind = .internal)
      (derivation : AbstractRunFunction records environment resolveCodeTarget
        event.targetRva.toNat state result) :
      CheckedAbstractOperationDerivation
        (.invokeCall records environment resolveCodeTarget event state)
        (.call result)
  | invokeIndirect
      (kind : event.kind = .indirect)
      (targetExact : resolveCodeTarget event.targetRva = some target)
      (derivation : AbstractRunFunction records environment resolveCodeTarget
        target state result) :
      CheckedAbstractOperationDerivation
        (.invokeCall records environment resolveCodeTarget event state)
        (.call result)

def CheckedAbstractOperationDerivation.toTransition
    (derivation : CheckedAbstractOperationDerivation request response) :
    AbstractKernelTransition request response := by
  cases derivation with
  | programLookup records sourceRva =>
      exact .programLookup records sourceRva
  | interpreterStep records environment sourceRva state =>
      exact .interpreterStep records environment sourceRva state
  | runFunction abstractRun =>
      exact .runFunction _ _ _ _ _ _ abstractRun
  | invokeExternal kind =>
      exact .invokeExternal _ _ _ _ _ kind
  | invokeInternal kind abstractRun =>
      exact .invokeInternal _ _ _ _ _ _ kind abstractRun
  | invokeIndirect kind targetExact abstractRun =>
      exact .invokeIndirect _ _ _ _ _ _ _ kind targetExact abstractRun

/-! The following constructors expose the operation-specific interface without
requiring callers to mention the dependent inductive directly. -/

def programLookupTransition (records : List ProgramRecord) (sourceRva : Nat) :
    AbstractKernelTransition
      (.programLookup records sourceRva)
      (.programLookup (lookupProgramRecord records sourceRva)) :=
  (CheckedAbstractOperationDerivation.programLookup records sourceRva).toTransition

def interpreterStepTransition
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (state : InterpreterMachine) :
    AbstractKernelTransition
      (.interpreterStep records environment sourceRva state)
      (.interpreterStep
        (abstractInterpreterStep records environment sourceRva state)) :=
  (CheckedAbstractOperationDerivation.interpreterStep records environment
    sourceRva state).toTransition

def AbstractRunFunction.toKernelTransition
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      sourceRva state result) :
    AbstractKernelTransition
      (.runFunction records environment resolveCodeTarget sourceRva state)
      (.call result) :=
  (CheckedAbstractOperationDerivation.runFunction derivation).toTransition

def invokeExternalTransition
    (kind : event.kind = .external) :
    AbstractKernelTransition
      (.invokeCall records environment resolveCodeTarget event state)
      (.call (environment.invokeCall event state)) :=
  (CheckedAbstractOperationDerivation.invokeExternal kind).toTransition

def invokeInternalTransition
    (kind : event.kind = .internal)
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      event.targetRva.toNat state result) :
    AbstractKernelTransition
      (.invokeCall records environment resolveCodeTarget event state)
      (.call result) :=
  (CheckedAbstractOperationDerivation.invokeInternal kind derivation).toTransition

def invokeIndirectTransition
    (kind : event.kind = .indirect)
    (targetExact : resolveCodeTarget event.targetRva = some target)
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      target state result) :
    AbstractKernelTransition
      (.invokeCall records environment resolveCodeTarget event state)
      (.call result) :=
  (CheckedAbstractOperationDerivation.invokeIndirect kind targetExact
    derivation).toTransition

/-- Semantic transition evidence and exact endpoint encoding are kept together
without admitting a response relation or a caller-selected endpoint. -/
structure ExactAbstractOperationResultClosure
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (state : MachineState) : Prop where
  derivation : CheckedAbstractOperationDerivation request response
  operationResult : CheckedOperationResultEvidence abi request response state

def ExactAbstractOperationResultClosure.transition
    (closure : ExactAbstractOperationResultClosure abi request response state) :
    AbstractKernelTransition request response :=
  closure.derivation.toTransition

/-- Construct the environment-closed cdecl certificate from the checked
semantic derivation and exact endpoint encoding.  The endpoint remains fixed by
`execution.returnedState`; this adapter accepts neither a response relation nor
a status/report assertion. -/
def ExactAbstractOperationResultClosure.toEnvironmentClosedCDeclEpilogue
    (operationExact : request.operation = static.inventory.operation)
    (entry : ABIRequestFacts abi request entryBefore)
    (execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world)
    (symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore)
    (frame : CDeclSymbolicFrameExpressions)
    (frameFacts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
      symbolic.behavior frame)
    (closure : ExactAbstractOperationResultClosure abi request response
      execution.returnedState)
    (externalTrace : CheckedResponseExternalTrace request response events) :
    EnvironmentClosedCDeclEpilogueCertificate abi candidate static disposition
      request response entryBefore epilogueBefore eventIndex events world := {
  operationExact
  transition := closure.transition
  entry
  execution
  symbolic
  frame
  frameFacts
  operationResult := closure.operationResult
  externalTrace
}

#print axioms CheckedAbstractOperationDerivation.toTransition
#print axioms programLookupTransition
#print axioms interpreterStepTransition
#print axioms AbstractRunFunction.toKernelTransition
#print axioms invokeExternalTransition
#print axioms invokeInternalTransition
#print axioms invokeIndirectTransition
#print axioms ExactAbstractOperationResultClosure.transition
#print axioms
  ExactAbstractOperationResultClosure.toEnvironmentClosedCDeclEpilogue

end StageA.Relational.InterpreterKernelAbstractOperationTransition
