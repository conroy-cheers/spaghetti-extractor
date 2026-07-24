import StageA.RelationalInterpreterKernelCdeclEpilogueStaticPreservation
import StageA.RelationalLockstepEnvironment

namespace StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueStaticPreservation
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterNativeWorld

/-!
# Environment-indexed cdecl response payloads

`ResponsePayloadHolds` combines two independent facts:

* the exact native endpoint encodes the selected abstract response in registers
  and the engine workspace; and
* the native external-event list is the exact one-to-one image of the
  abstract external-call trace.

The lockstep environment contract closes the second fact, including the actual
candidate response and nested call frame.  It cannot establish the first fact:
that is a candidate operation-execution theorem, not an external API law.  This
module exposes that exact machine encoding as the smallest typed residual.
-/

def nativeWorldExternalEvent
    (native : NativeExternalEvent) (site : ExternalCallSiteContract)
    (world : RelationalWorld) : WorldExternalEvent := {
  siteId := site.id
  imported := normalizeImport native.imported
  arguments := native.arguments
  state := native.state
  world
}

/-- One actual native external response tied to a checked exact 1:1 machine
contract.  The candidate environment result and the native-world action are
both fixed to the same result; a report or status field cannot stand in for
either equality. -/
structure CheckedOneToOneKernelExternalResponse
    (semantic : CallEvent) (native : NativeExternalEvent) where
  context : StaticProofContext
  site : ExternalCallSiteContract
  contract : MachineImportCallContract
  originalEnvironment : WorldExternalEnvironment
  candidateEnvironment : WorldExternalEnvironment
  nativeEnvironment : NativeWorldEnvironment
  world : RelationalWorld
  eventIndex : Nat
  originalEvent : WorldExternalEvent
  candidateEvent : WorldExternalEvent
  candidateEventExact :
    candidateEvent = nativeWorldExternalEvent native site world
  candidateResult : WorldExternalResult
  checked : CheckedExactLockstepExternalReturn context site contract
    originalEnvironment candidateEnvironment
  boundary :
    ExternalCallBoundaryRelated context site contract originalEvent
      candidateEvent
  candidateResultExact :
    candidateEnvironment.result eventIndex candidateEvent = candidateResult
  nativeReturned :
    nativeEnvironment.action eventIndex native world =
      .returned candidateResult
  semanticKind : semantic.kind = .external
  importMatches : ImportMatchesCallEvent native.imported semantic
  argumentsExact : native.arguments = semantic.arguments

theorem CheckedOneToOneKernelExternalResponse.nativeEventShape
    (response : CheckedOneToOneKernelExternalResponse semantic native) :
    NativeExternalEventShape semantic native :=
  ⟨response.importMatches, response.argumentsExact⟩

/-- The response used by exact native execution is the candidate half of the
checked paired machine result. -/
theorem CheckedOneToOneKernelExternalResponse.pairedMachineResult
    (response : CheckedOneToOneKernelExternalResponse semantic native) :
    let originalResult :=
      response.originalEnvironment.result response.eventIndex
        response.originalEvent
    originalResult.world = response.candidateResult.world ∧
      machineCallResultConforms false response.context response.contract
        response.originalEvent originalResult ∧
      machineCallResultConforms true response.context response.contract
        response.candidateEvent response.candidateResult ∧
      machineCallResultRegistersRelated response.context
        originalResult.world response.contract response.originalEvent.arguments
        originalResult.state response.candidateResult.state = true ∧
      StateRel response.context originalResult.world
        response.site.targetInvariant originalResult.state
        response.candidateResult.state ∧
      ExternalRuntimeFramesPreserved response.originalEvent
        response.candidateEvent originalResult response.candidateResult := by
  have refined := externalEnvironmentRefinesAt_of_checkedExactLockstep
    response.context response.site response.contract
    response.originalEnvironment response.candidateEnvironment response.checked
  unfold ExternalEnvironmentRefinesAt at refined
  rw [response.checked.returns] at refined
  have related := refined response.eventIndex response.originalEvent
    response.candidateEvent response.boundary
  rw [response.candidateResultExact] at related
  exact related

inductive CheckedOneToOneExternalResponseTrace :
    List CallEvent -> List NativeExternalEvent -> Prop
  | nil : CheckedOneToOneExternalResponseTrace [] []
  | cons
      (head : CheckedOneToOneKernelExternalResponse semantic native)
      (tail : CheckedOneToOneExternalResponseTrace semantics natives) :
      CheckedOneToOneExternalResponseTrace
        (semantic :: semantics) (native :: natives)

theorem CheckedOneToOneExternalResponseTrace.nativeEventListShape
    (trace : CheckedOneToOneExternalResponseTrace semantics natives) :
    NativeEventListShape semantics natives := by
  induction trace with
  | nil => trivial
  | cons head tail induction =>
      exact ⟨head.nativeEventShape, induction⟩

/-- Candidate-only register and engine-buffer encoding.  External event shape
is deliberately absent; it is derived from the paired trace below. -/
def ResponseMachinePayloadHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    AbstractKernelRequest -> AbstractKernelResponse -> MachineState -> Prop
  | .programLookup _ sourceOffset, .programLookup _, state =>
      state.registers.eax =
        lookupResultPointer records pe.imageBase tableOffset sourceOffset
  | .interpreterStep _ _ sourceOffset _, .interpreterStep result, state =>
      state.registers.eax = abi.parameters.resultAddress abi.engineLayout ∧
        WordsAt state.memory (abi.parameters.resultAddress abi.engineLayout)
          (stepResultWords result) ∧
        match result with
        | none => True
        | some macroResult =>
            EngineStateHolds abi.engineLayout abi.parameters.inputAddress
              macroResult.state sourceOffset state
  | .runFunction _ _ _ sourceOffset _, .call result, state =>
      state.registers.eax = callStatusWord result.status ∧
        EngineStateHolds abi.engineLayout
          (abi.parameters.outputAddress abi.engineLayout)
          result.state sourceOffset state
  | .invokeCall _ _ _ event _, .call result, state =>
      state.registers.eax = callStatusWord result.status ∧
        EngineStateHolds abi.engineLayout
          (abi.parameters.outputAddress abi.engineLayout)
          result.state event.targetRva.toNat state
  | _, _, _ => False

/-- Case-specific operation-result evidence over the computed return state.
These constructors expose the exact facts an operation executor must prove;
none accepts a replacement endpoint or a preassembled response relation. -/
inductive CheckedOperationResultEvidence
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records) :
    AbstractKernelRequest -> AbstractKernelResponse -> MachineState -> Prop
  | programLookup
      (eaxExact :
        state.registers.eax =
          lookupResultPointer records pe.imageBase tableOffset sourceOffset) :
      CheckedOperationResultEvidence abi
        (.programLookup requestRecords sourceOffset)
        (.programLookup record) state
  | interpreterStepNone
      (eaxExact :
        state.registers.eax =
          abi.parameters.resultAddress abi.engineLayout)
      (resultWords :
        WordsAt state.memory
          (abi.parameters.resultAddress abi.engineLayout)
          (stepResultWords none)) :
      CheckedOperationResultEvidence abi
        (.interpreterStep requestRecords environment sourceOffset logical)
        (.interpreterStep none) state
  | interpreterStepSome
      (eaxExact :
        state.registers.eax =
          abi.parameters.resultAddress abi.engineLayout)
      (resultWords :
        WordsAt state.memory
          (abi.parameters.resultAddress abi.engineLayout)
          (stepResultWords (some result)))
      (engineState :
        EngineStateHolds abi.engineLayout abi.parameters.inputAddress
          result.state sourceOffset state) :
      CheckedOperationResultEvidence abi
        (.interpreterStep requestRecords environment sourceOffset logical)
        (.interpreterStep (some result)) state
  | runFunction
      (eaxExact : state.registers.eax = callStatusWord result.status)
      (engineState :
        EngineStateHolds abi.engineLayout
          (abi.parameters.outputAddress abi.engineLayout)
          result.state sourceOffset state) :
      CheckedOperationResultEvidence abi
        (.runFunction requestRecords environment resolveCodeTarget sourceOffset
          logical)
        (.call result) state
  | invokeCall
      (eaxExact : state.registers.eax = callStatusWord result.status)
      (engineState :
        EngineStateHolds abi.engineLayout
          (abi.parameters.outputAddress abi.engineLayout)
          result.state event.targetRva.toNat state) :
      CheckedOperationResultEvidence abi
        (.invokeCall requestRecords environment resolveCodeTarget event logical)
        (.call result) state

theorem CheckedOperationResultEvidence.machinePayload
    (evidence : CheckedOperationResultEvidence abi request response state) :
    ResponseMachinePayloadHolds abi request response state := by
  cases evidence <;> simp_all [ResponseMachinePayloadHolds]

def ResponseExternalTraceHolds :
    AbstractKernelRequest -> AbstractKernelResponse ->
      List NativeExternalEvent -> Prop
  | .programLookup .., .programLookup _, nativeEvents =>
      nativeEvents = []
  | .interpreterStep _ _ _ _, .interpreterStep result, nativeEvents =>
      match result with
      | none => nativeEvents = []
      | some macroResult =>
          NativeEventListShape
            (externalCallEvents macroResult.events) nativeEvents
  | .runFunction .., .call _, nativeEvents =>
      nativeEvents = []
  | .invokeCall _ _ _ event _, .call _, nativeEvents =>
      if event.kind == .external then
        ∃ native, nativeEvents = [native] ∧
          NativeExternalEventShape event native
      else nativeEvents = []
  | _, _, _ => False

theorem responsePayloadHolds_of_components
    (machine : ResponseMachinePayloadHolds abi request response state)
    (trace : ResponseExternalTraceHolds request response nativeEvents) :
    ResponsePayloadHolds abi request response state nativeEvents := by
  cases request <;> cases response <;>
    simp_all [ResponseMachinePayloadHolds, ResponseExternalTraceHolds,
      ResponsePayloadHolds]
  next result =>
    cases result <;>
      simp_all [ResponseMachinePayloadHolds, ResponseExternalTraceHolds,
        ResponsePayloadHolds]

/-- Checked trace evidence for every response family.  Empty traces are exact
equalities through the index.  Nonempty traces require one checked paired
machine response per semantic external call. -/
inductive CheckedResponseExternalTrace :
    AbstractKernelRequest -> AbstractKernelResponse ->
      List NativeExternalEvent -> Prop
  | programLookup (records sourceOffset record) :
      CheckedResponseExternalTrace
        (.programLookup records sourceOffset) (.programLookup record) []
  | interpreterStepNone (records environment sourceOffset logical) :
      CheckedResponseExternalTrace
        (.interpreterStep records environment sourceOffset logical)
        (.interpreterStep none) []
  | interpreterStepSome
      (trace : CheckedOneToOneExternalResponseTrace
        (externalCallEvents result.events) nativeEvents) :
      CheckedResponseExternalTrace
        (.interpreterStep records environment sourceOffset logical)
        (.interpreterStep (some result)) nativeEvents
  | runFunction (records environment resolveCodeTarget sourceOffset logical
      result) :
      CheckedResponseExternalTrace
        (.runFunction records environment resolveCodeTarget sourceOffset logical)
        (.call result) []
  | invokeExternal
      (responseExact : result = environment.invokeCall event logical)
      (trace : CheckedOneToOneExternalResponseTrace [event] nativeEvents) :
      CheckedResponseExternalTrace
        (.invokeCall records environment resolveCodeTarget event logical)
        (.call result) nativeEvents
  | invokeNonExternal
      (notExternal : event.kind ≠ .external) :
      CheckedResponseExternalTrace
        (.invokeCall records environment resolveCodeTarget event logical)
        (.call result) []

theorem CheckedResponseExternalTrace.holds
    (trace : CheckedResponseExternalTrace request response nativeEvents) :
    ResponseExternalTraceHolds request response nativeEvents := by
  cases trace with
  | programLookup => rfl
  | interpreterStepNone => rfl
  | interpreterStepSome checked =>
      exact checked.nativeEventListShape
  | runFunction => rfl
  | invokeExternal responseExact checked =>
      cases checked with
      | cons head tail =>
          cases tail
          simp only [ResponseExternalTraceHolds, head.semanticKind, beq_self_eq_true,
            ↓reduceIte]
          exact ⟨_, rfl, head.nativeEventShape⟩
  | invokeNonExternal notExternal =>
      simp [ResponseExternalTraceHolds, notExternal]

/-- `environmentalPayload` is now constructed.  The residual fields are the
authoritative semantic transition, exact endpoint encoding, and checked
one-to-one trace evidence. -/
structure EnvironmentClosedCDeclEpilogueCertificate
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (candidate : ExactNativeWorldProgram)
    (static : CheckedKernelCDeclEpilogue program candidate function)
    (disposition : CDeclReturnDisposition)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (entryBefore epilogueBefore : MachineState) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) where
  operationExact : request.operation = static.inventory.operation
  transition : AbstractKernelTransition request response
  entry : ABIRequestFacts abi request entryBefore
  execution : ExactComputedCDeclEpilogue candidate static disposition
    epilogueBefore eventIndex events world
  symbolic : ExactDecodedCDeclSymbolicExecution execution entryBefore
  frame : CDeclSymbolicFrameExpressions
  frameFacts : CDeclSymbolicABIFrameFacts abi disposition request entryBefore
    symbolic.behavior frame
  operationResult :
    CheckedOperationResultEvidence abi request response execution.returnedState
  externalTrace : CheckedResponseExternalTrace request response events

def EnvironmentClosedCDeclEpilogueCertificate.toStaticallyPreserved
    (certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    StaticallyPreservedCDeclEpilogueCertificate abi candidate static disposition
      request response entryBefore epilogueBefore eventIndex events world := {
  operationExact := certificate.operationExact
  entry := certificate.entry
  execution := certificate.execution
  symbolic := certificate.symbolic
  frame := certificate.frame
  frameFacts := certificate.frameFacts
  environmentalPayload := responsePayloadHolds_of_components
    certificate.operationResult.machinePayload certificate.externalTrace.holds
}

def EnvironmentClosedCDeclEpilogueCertificate.toChecked
    (certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    CheckedCDeclEpilogueCertificate abi candidate static disposition request
      response entryBefore epilogueBefore eventIndex events world :=
  certificate.toStaticallyPreserved.toChecked

theorem EnvironmentClosedCDeclEpilogueCertificate.responseRelated
    (certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    abi.relation.responseRelated request response
      certificate.execution.returnedState events :=
  certificate.toChecked.responseRelated

theorem EnvironmentClosedCDeclEpilogueCertificate.memoryFrame
    (certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    MemoryAgreesOutside (abi.relation.scratchFootprint request)
      certificate.execution.returnedState.memory entryBefore.memory :=
  certificate.toChecked.memoryFrame

theorem EnvironmentClosedCDeclEpilogueCertificate.path
    (certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate
      static disposition request response entryBefore epilogueBefore eventIndex
      events world) :
    NonemptyRelatedPath candidate.transitionSystem certificate.execution.start
      certificate.execution.observations certificate.execution.after :=
  certificate.toChecked.path

#print axioms CheckedOneToOneKernelExternalResponse.nativeEventShape
#print axioms CheckedOneToOneKernelExternalResponse.pairedMachineResult
#print axioms CheckedOneToOneExternalResponseTrace.nativeEventListShape
#print axioms CheckedOperationResultEvidence.machinePayload
#print axioms responsePayloadHolds_of_components
#print axioms CheckedResponseExternalTrace.holds
#print axioms EnvironmentClosedCDeclEpilogueCertificate.toStaticallyPreserved
#print axioms EnvironmentClosedCDeclEpilogueCertificate.toChecked
#print axioms EnvironmentClosedCDeclEpilogueCertificate.responseRelated
#print axioms EnvironmentClosedCDeclEpilogueCertificate.memoryFrame
#print axioms EnvironmentClosedCDeclEpilogueCertificate.path

end StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
