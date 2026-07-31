import StageA.RelationalInterpreterKernel

namespace StageA.Relational.InterpreterKernelClosedCallTree

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel

/-!
# Closed semantic call trees

The kernel's abstract semantics are intentionally split across Step, Run, and
Invoke.  The relations below reconnect those operations without changing their
authoritative definitions:

* Run contains the checked Step derivation used at each loop iteration;
* every interpreter call action contains a trace edge to checked Invoke;
* internal and indirect Invoke contain the checked Run derivation for the
  selected target.

Only the external Invoke arm uses the external environment result.  Internal
and indirect arms obtain their result from the nested Run derivation, matching
the authoritative call-aware `AbstractKernelTransition` semantics.
-/

def checkedInterpreterInitialRuntime
    (state : InterpreterMachine) : RuntimeState := {
  input := state
  current := state
  callOutput := state
  words := fun _ => none
  events := []
}

def checkedInterpreterCallRuntime (runtime : RuntimeState)
    (event : CallEvent) (result : CallResult) : RuntimeState := {
  runtime with
  current := result.state
  callOutput := result.state
  events := runtime.events ++ [.call event]
}

def checkedInterpreterCallOutcome (runtime : RuntimeState)
    (event : CallEvent) (result : CallResult) :
    Option (Sum MacroResult RuntimeState) :=
  let next := checkedInterpreterCallRuntime runtime event result
  match result.status with
  | .ok => some (.inr next)
  | .divideError => some (.inl (halted next .divideError))
  | .memoryFault => some (.inl (halted next .memoryFault))
  | .externalFault => some (.inl (halted next .externalFault))
  | .unimplemented => some (.inl (halted next .unimplemented))

def checkedInterpreterTransferOutcome (outcome : SemanticOutcome) :
    Option (Sum MacroResult RuntimeState) -> Option MacroResult
  | none => none
  | some (.inl result) => some result
  | some (.inr runtime) => outcome.complete runtime

mutual
  /-- Checked evidence for one abstract interpreter Step.  Successful transfer
  execution is expanded through the action list so calls cannot bypass the
  Invoke edge below. -/
  inductive CheckedInterpreterStepDerivation
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      Nat -> InterpreterMachine -> Option MacroResult -> Prop
    | lookupUnavailable (sourceRva state)
        (lookupExact : lookupProgramRecord records sourceRva = none) :
        CheckedInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state none
    | decodeUnavailable (sourceRva state record)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = none) :
        CheckedInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state none
    | unchecked (sourceRva state record transfer)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = false) :
        CheckedInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state none
    | execute (sourceRva state record transfer result)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = true)
        (execution : CheckedSemanticTransferDerivation records environment
          resolveCodeTarget transfer state result) :
        CheckedInterpreterStepDerivation records environment resolveCodeTarget
          sourceRva state result

  /-- Checked execution of a decoded transfer. -/
  inductive CheckedSemanticTransferDerivation
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> InterpreterMachine -> Option MacroResult -> Prop
    | execute (transfer state bodyResult)
        (body : CheckedInterpreterBodyDerivation records environment
          resolveCodeTarget transfer (checkedInterpreterInitialRuntime state)
          transfer.body bodyResult) :
        CheckedSemanticTransferDerivation records environment resolveCodeTarget
          transfer state
          (checkedInterpreterTransferOutcome transfer.outcome bodyResult)

  /-- Checked left-to-right execution of an interpreter action list. -/
  inductive CheckedInterpreterBodyDerivation
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> List SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | done (runtime) :
        CheckedInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime [] (some (.inr runtime))
    | actionUnavailable (runtime action tail)
        (head : CheckedInterpreterActionDerivation records environment
          resolveCodeTarget transfer runtime action none) :
        CheckedInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime (action :: tail) none
    | actionHalted (runtime action tail result)
        (head : CheckedInterpreterActionDerivation records environment
          resolveCodeTarget transfer runtime action (some (.inl result))) :
        CheckedInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime (action :: tail) (some (.inl result))
    | actionNext (runtime action tail next result)
        (head : CheckedInterpreterActionDerivation records environment
          resolveCodeTarget transfer runtime action (some (.inr next)))
        (rest : CheckedInterpreterBodyDerivation records environment
          resolveCodeTarget transfer next tail result) :
        CheckedInterpreterBodyDerivation records environment resolveCodeTarget
          transfer runtime (action :: tail) result

  /-- Checked execution of one action.  The non-call constructor explicitly
  excludes `.call`; every call must use `call` and therefore carry the trace
  edge into Invoke. -/
  inductive CheckedInterpreterActionDerivation
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | nonCall (runtime action result)
        (notCall : forall callIndex, action != .call callIndex)
        (resultExact :
          transfer.executeAction environment runtime action = result) :
        CheckedInterpreterActionDerivation records environment resolveCodeTarget
          transfer runtime action result
    | call (runtime callIndex result)
        (edge : CheckedInterpreterCallTraceEdge records environment
          resolveCodeTarget transfer runtime callIndex result) :
        CheckedInterpreterActionDerivation records environment resolveCodeTarget
          transfer runtime (.call callIndex) result

  /-- The call-bearing trace edge from interpreter Step execution to Invoke.
  The decoded call and its exact input state are retained, so the nested Invoke
  derivation is about the call that `executeAction` actually performs. -/
  inductive CheckedInterpreterCallTraceEdge
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> Nat ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | invoke (runtime callIndex call event input result)
        (callExact : transfer.calls[callIndex]? = some call)
        (eventExact : call.event runtime = some (event, input))
        (invocation : CheckedInvokeCallDerivation records environment
          resolveCodeTarget event input result) :
        CheckedInterpreterCallTraceEdge records environment resolveCodeTarget
          transfer runtime callIndex
          (checkedInterpreterCallOutcome runtime event result)

  /-- Checked finite Run derivations with every Step kept in the tree. -/
  inductive CheckedRunFunctionDerivation
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      Nat -> InterpreterMachine -> CallResult -> Prop
    | unavailable (sourceRva state)
        (step : CheckedInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state none) :
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          sourceRva state { status := .unimplemented, state := state }
    | terminal (sourceRva state result status)
        (step : CheckedInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state (some result))
        (statusExact : completionCallStatus? result.completion = some status) :
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          sourceRva state { status := status, state := result.state }
    | next (sourceRva state result continuation final)
        (step : CheckedInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state (some result))
        (continuationExact :
          completionContinuation? resolveCodeTarget result.completion =
            some continuation)
        (rest : CheckedRunFunctionDerivation records environment
          resolveCodeTarget continuation result.state final) :
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          sourceRva state final

  /-- Checked Invoke derivations.  Only external calls are interpreted by the
  external environment; internal and indirect results come from nested Run. -/
  inductive CheckedInvokeCallDerivation
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      CallEvent -> InterpreterMachine -> CallResult -> Prop
    | external (event state)
        (kindExact : event.kind = .external) :
        CheckedInvokeCallDerivation records environment resolveCodeTarget event
          state (environment.invokeCall event state)
    | internal (event state result)
        (kindExact : event.kind = .internal)
        (run : CheckedRunFunctionDerivation records environment
          resolveCodeTarget event.targetRva.toNat state result) :
        CheckedInvokeCallDerivation records environment resolveCodeTarget event
          state result
    | indirect (event state target result)
        (kindExact : event.kind = .indirect)
        (targetExact : resolveCodeTarget event.targetRva = some target)
        (run : CheckedRunFunctionDerivation records environment
          resolveCodeTarget target state result) :
        CheckedInvokeCallDerivation records environment resolveCodeTarget event
          state result
end

/-! ## Rank-free construction from finite nested evidence

The checked derivations above are already finite proof trees.  Construction
therefore does not require a source-address rank: Run continuation follows the
finite `AbstractRunFunction` derivation, while every actual call action carries
the exact nested semantic Run that it invokes.

The evidence layer below keeps the authoritative `AbstractRunFunction` proof
explicit.  Its indirect constructor retains the resolver equation.  Converting
the evidence to the checked relations is structural recursion over the finite
nested evidence only.
-/

mutual
  inductive FiniteCheckedInterpreterStepEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      Nat -> InterpreterMachine -> Option MacroResult -> Prop
    | lookupUnavailable (sourceRva state)
        (lookupExact : lookupProgramRecord records sourceRva = none) :
        FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state none
    | decodeUnavailable (sourceRva state record)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = none) :
        FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state none
    | unchecked (sourceRva state record transfer)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = false) :
        FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state none
    | execute (sourceRva state record transfer result)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = true)
        (execution : FiniteCheckedSemanticTransferEvidence records environment
          resolveCodeTarget transfer state result) :
        FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state result

  inductive FiniteCheckedSemanticTransferEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> InterpreterMachine -> Option MacroResult -> Prop
    | execute (transfer state bodyResult)
        (body : FiniteCheckedInterpreterBodyEvidence records environment
          resolveCodeTarget transfer (checkedInterpreterInitialRuntime state)
          transfer.body bodyResult) :
        FiniteCheckedSemanticTransferEvidence records environment
          resolveCodeTarget transfer state
          (checkedInterpreterTransferOutcome transfer.outcome bodyResult)

  inductive FiniteCheckedInterpreterBodyEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> List SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | done (runtime) :
        FiniteCheckedInterpreterBodyEvidence records environment
          resolveCodeTarget transfer runtime [] (some (.inr runtime))
    | actionUnavailable (runtime action tail)
        (head : FiniteCheckedInterpreterActionEvidence records environment
          resolveCodeTarget transfer runtime action none) :
        FiniteCheckedInterpreterBodyEvidence records environment
          resolveCodeTarget transfer runtime (action :: tail) none
    | actionHalted (runtime action tail result)
        (head : FiniteCheckedInterpreterActionEvidence records environment
          resolveCodeTarget transfer runtime action (some (.inl result))) :
        FiniteCheckedInterpreterBodyEvidence records environment
          resolveCodeTarget transfer runtime (action :: tail) (some (.inl result))
    | actionNext (runtime action tail next result)
        (head : FiniteCheckedInterpreterActionEvidence records environment
          resolveCodeTarget transfer runtime action (some (.inr next)))
        (rest : FiniteCheckedInterpreterBodyEvidence records environment
          resolveCodeTarget transfer next tail result) :
        FiniteCheckedInterpreterBodyEvidence records environment
          resolveCodeTarget transfer runtime (action :: tail) result

  inductive FiniteCheckedInterpreterActionEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | nonCall (runtime action result)
        (notCall : forall callIndex, action != .call callIndex)
        (resultExact :
          transfer.executeAction environment runtime action = result) :
        FiniteCheckedInterpreterActionEvidence records environment
          resolveCodeTarget transfer runtime action result
    | call (runtime callIndex result)
        (edge : FiniteCheckedInterpreterCallEvidence records environment
          resolveCodeTarget transfer runtime callIndex result) :
        FiniteCheckedInterpreterActionEvidence records environment
          resolveCodeTarget transfer runtime (.call callIndex) result

  inductive FiniteCheckedInterpreterCallEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      SemanticTransfer -> RuntimeState -> Nat ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | invoke (runtime callIndex call event input result)
        (callExact : transfer.calls[callIndex]? = some call)
        (eventExact : call.event runtime = some (event, input))
        (invocation : FiniteCheckedInvokeCallEvidence records environment
          resolveCodeTarget event input result) :
        FiniteCheckedInterpreterCallEvidence records environment
          resolveCodeTarget transfer runtime callIndex
          (checkedInterpreterCallOutcome runtime event result)

  inductive FiniteCheckedInvokeCallEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      CallEvent -> InterpreterMachine -> CallResult -> Prop
    | external (event state)
        (kindExact : event.kind = .external) :
        FiniteCheckedInvokeCallEvidence records environment resolveCodeTarget
          event state (environment.invokeCall event state)
    | internal (event state result)
        (kindExact : event.kind = .internal)
        (run : AbstractRunFunction records environment resolveCodeTarget
          event.targetRva.toNat state result)
        (nested : FiniteCheckedRunFunctionEvidence records environment
          resolveCodeTarget event.targetRva.toNat state result run) :
        FiniteCheckedInvokeCallEvidence records environment resolveCodeTarget
          event state result
    | indirect (event state target result)
        (kindExact : event.kind = .indirect)
        (targetExact : resolveCodeTarget event.targetRva = some target)
        (run : AbstractRunFunction records environment resolveCodeTarget
          target state result)
        (nested : FiniteCheckedRunFunctionEvidence records environment
          resolveCodeTarget target state result run) :
        FiniteCheckedInvokeCallEvidence records environment resolveCodeTarget
          event state result

  inductive FiniteCheckedRunFunctionEvidence
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat) :
      ∀ sourceRva state result,
        AbstractRunFunction records environment resolveCodeTarget sourceRva state
          result -> Prop
    | unavailable (sourceRva state)
        (abstractStep : AbstractInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state none)
        (step : FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state none) :
        FiniteCheckedRunFunctionEvidence records environment resolveCodeTarget
          sourceRva state { status := .unimplemented, state := state }
          (.unavailable sourceRva state abstractStep)
    | terminal (sourceRva state result status)
        (abstractStep : AbstractInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state (some result))
        (statusExact : completionCallStatus? result.completion = some status)
        (step : FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state (some result)) :
        FiniteCheckedRunFunctionEvidence records environment resolveCodeTarget
          sourceRva state { status := status, state := result.state }
          (.terminal sourceRva state result status abstractStep statusExact)
    | next (sourceRva state result continuation final)
        (abstractStep : AbstractInterpreterStepDerivation records environment
          resolveCodeTarget sourceRva state (some result))
        (continuationExact :
          completionContinuation? resolveCodeTarget result.completion =
            some continuation)
        (rest : AbstractRunFunction records environment resolveCodeTarget
          continuation result.state final)
        (step : FiniteCheckedInterpreterStepEvidence records environment
          resolveCodeTarget sourceRva state (some result))
        (tail : FiniteCheckedRunFunctionEvidence records environment
          resolveCodeTarget continuation result.state final rest) :
        FiniteCheckedRunFunctionEvidence records environment resolveCodeTarget
          sourceRva state final
          (.next sourceRva state result continuation final abstractStep
            continuationExact rest)
end

mutual
  def FiniteCheckedInterpreterStepEvidence.toCheckedInterpreterStepDerivation
      (evidence : FiniteCheckedInterpreterStepEvidence records environment
        resolveCodeTarget sourceRva state result) :
      CheckedInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result :=
    match evidence with
    | .lookupUnavailable sourceRva state lookupExact =>
        .lookupUnavailable sourceRva state lookupExact
    | .decodeUnavailable sourceRva state record lookupExact decodeExact =>
        .decodeUnavailable sourceRva state record lookupExact decodeExact
    | .unchecked sourceRva state record transfer lookupExact decodeExact
        checkedExact =>
        .unchecked sourceRva state record transfer lookupExact decodeExact
          checkedExact
    | .execute sourceRva state record transfer result lookupExact decodeExact
        checkedExact execution =>
        .execute sourceRva state record transfer result lookupExact decodeExact
          checkedExact execution.toCheckedSemanticTransferDerivation

  def FiniteCheckedSemanticTransferEvidence.toCheckedSemanticTransferDerivation
      (evidence : FiniteCheckedSemanticTransferEvidence records environment
        resolveCodeTarget transfer state result) :
      CheckedSemanticTransferDerivation records environment resolveCodeTarget
        transfer state result :=
    match evidence with
    | .execute transfer state bodyResult body =>
        .execute transfer state bodyResult
          body.toCheckedInterpreterBodyDerivation

  def FiniteCheckedInterpreterBodyEvidence.toCheckedInterpreterBodyDerivation
      (evidence : FiniteCheckedInterpreterBodyEvidence records environment
        resolveCodeTarget transfer runtime actions result) :
      CheckedInterpreterBodyDerivation records environment resolveCodeTarget
        transfer runtime actions result :=
    match evidence with
    | .done runtime => .done runtime
    | .actionUnavailable runtime action tail head =>
        .actionUnavailable runtime action tail
          head.toCheckedInterpreterActionDerivation
    | .actionHalted runtime action tail result head =>
        .actionHalted runtime action tail result
          head.toCheckedInterpreterActionDerivation
    | .actionNext runtime action tail next result head rest =>
        .actionNext runtime action tail next result
          head.toCheckedInterpreterActionDerivation
          rest.toCheckedInterpreterBodyDerivation

  def FiniteCheckedInterpreterActionEvidence.toCheckedInterpreterActionDerivation
      (evidence : FiniteCheckedInterpreterActionEvidence records environment
        resolveCodeTarget transfer runtime action result) :
      CheckedInterpreterActionDerivation records environment resolveCodeTarget
        transfer runtime action result :=
    match evidence with
    | .nonCall runtime action result notCall resultExact =>
        .nonCall runtime action result notCall resultExact
    | .call runtime callIndex result edge =>
        .call runtime callIndex result
          edge.toCheckedInterpreterCallTraceEdge

  def FiniteCheckedInterpreterCallEvidence.toCheckedInterpreterCallTraceEdge
      (evidence : FiniteCheckedInterpreterCallEvidence records environment
        resolveCodeTarget transfer runtime callIndex result) :
      CheckedInterpreterCallTraceEdge records environment resolveCodeTarget
        transfer runtime callIndex result :=
    match evidence with
    | .invoke runtime callIndex call event input result callExact eventExact
        invocation =>
        .invoke runtime callIndex call event input result callExact eventExact
          invocation.toCheckedInvokeCallDerivation

  def FiniteCheckedInvokeCallEvidence.toCheckedInvokeCallDerivation
      (evidence : FiniteCheckedInvokeCallEvidence records environment
        resolveCodeTarget event state result) :
      CheckedInvokeCallDerivation records environment resolveCodeTarget event
        state result :=
    match evidence with
    | .external event state kindExact =>
        .external event state kindExact
    | .internal event state result kindExact _run nested =>
        .internal event state result kindExact
          nested.toCheckedRunFunctionDerivation
    | .indirect event state target result kindExact targetExact _run nested =>
        .indirect event state target result kindExact targetExact
          nested.toCheckedRunFunctionDerivation

  def FiniteCheckedRunFunctionEvidence.toCheckedRunFunctionDerivation
      {derivation : AbstractRunFunction records environment resolveCodeTarget
        sourceRva state result}
      (evidence : FiniteCheckedRunFunctionEvidence records environment
        resolveCodeTarget sourceRva state result derivation) :
      CheckedRunFunctionDerivation records environment resolveCodeTarget
        sourceRva state result :=
    match evidence with
    | .unavailable sourceRva state _stepExact step =>
        .unavailable sourceRva state
          step.toCheckedInterpreterStepDerivation
    | .terminal sourceRva state result status _stepExact statusExact step =>
        .terminal sourceRva state result status
          step.toCheckedInterpreterStepDerivation statusExact
    | .next sourceRva state result continuation final _stepExact
        continuationExact _rest step tail =>
        .next sourceRva state result continuation final
          step.toCheckedInterpreterStepDerivation continuationExact
          tail.toCheckedRunFunctionDerivation
end

mutual
  def abstractInterpreterStepToChecked
      (derivation : AbstractInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva state result) :
      CheckedInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result :=
    match derivation with
    | .lookupUnavailable sourceRva state lookupExact =>
        .lookupUnavailable sourceRva state lookupExact
    | .decodeUnavailable sourceRva state record lookupExact decodeExact =>
        .decodeUnavailable sourceRva state record lookupExact decodeExact
    | .unchecked sourceRva state record transfer lookupExact decodeExact checkedExact =>
        .unchecked sourceRva state record transfer lookupExact decodeExact checkedExact
    | .execute sourceRva state record transfer result lookupExact decodeExact
        checkedExact execution =>
        .execute sourceRva state record transfer result lookupExact decodeExact
          checkedExact (abstractSemanticTransferToChecked execution)

  def abstractSemanticTransferToChecked
      (derivation : AbstractSemanticTransferDerivation records environment
        resolveCodeTarget transfer state result) :
      CheckedSemanticTransferDerivation records environment resolveCodeTarget
        transfer state result :=
    match derivation with
    | .execute transfer state bodyResult body => by
        simpa [checkedInterpreterInitialRuntime,
          abstractInterpreterInitialRuntime, checkedInterpreterTransferOutcome,
          abstractInterpreterTransferOutcome] using
          (CheckedSemanticTransferDerivation.execute transfer state bodyResult
            (abstractInterpreterBodyToChecked body))

  def abstractInterpreterBodyToChecked
      (derivation : AbstractInterpreterBodyDerivation records environment
        resolveCodeTarget transfer runtime actions result) :
      CheckedInterpreterBodyDerivation records environment resolveCodeTarget
        transfer runtime actions result :=
    match derivation with
    | .done runtime => .done runtime
    | .actionUnavailable runtime action tail head =>
        .actionUnavailable runtime action tail
          (abstractInterpreterActionToChecked head)
    | .actionHalted runtime action tail result head =>
        .actionHalted runtime action tail result
          (abstractInterpreterActionToChecked head)
    | .actionNext runtime action tail next result head rest =>
        .actionNext runtime action tail next result
          (abstractInterpreterActionToChecked head)
          (abstractInterpreterBodyToChecked rest)

  def abstractInterpreterActionToChecked
      (derivation : AbstractInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action result) :
      CheckedInterpreterActionDerivation records environment resolveCodeTarget
        transfer runtime action result :=
    match derivation with
    | .nonCall runtime action result notCall resultExact =>
        .nonCall runtime action result notCall resultExact
    | .call runtime callIndex result edge =>
        .call runtime callIndex result
          (abstractInterpreterCallTraceToChecked edge)

  def abstractInterpreterCallTraceToChecked
      (edge : AbstractInterpreterCallTraceEdge records environment
        resolveCodeTarget transfer runtime callIndex result) :
      CheckedInterpreterCallTraceEdge records environment resolveCodeTarget
        transfer runtime callIndex result :=
    match edge with
    | .invoke runtime callIndex call event input callResult callExact eventExact
        invocation => by
        simpa [checkedInterpreterCallOutcome, checkedInterpreterCallRuntime,
          abstractInterpreterCallOutcome, abstractInterpreterCallRuntime] using
          (CheckedInterpreterCallTraceEdge.invoke runtime callIndex call event
            input callResult callExact eventExact
              (abstractInvokeCallToChecked invocation))

  def abstractInvokeCallToChecked
      (derivation : AbstractInvokeCallDerivation records environment
        resolveCodeTarget event state result) :
      CheckedInvokeCallDerivation records environment resolveCodeTarget event
        state result :=
    match derivation with
    | .external event state kindExact => .external event state kindExact
    | .internal event state result kindExact run =>
        .internal event state result kindExact (abstractRunFunctionToChecked run)
    | .indirect event state target result kindExact targetExact run =>
        .indirect event state target result kindExact targetExact
          (abstractRunFunctionToChecked run)

  def abstractRunFunctionToChecked
      (derivation : AbstractRunFunction records environment resolveCodeTarget
        sourceRva state result) :
      CheckedRunFunctionDerivation records environment resolveCodeTarget sourceRva
        state result :=
    match derivation with
    | .unavailable sourceRva state step =>
        .unavailable sourceRva state (abstractInterpreterStepToChecked step)
    | .terminal sourceRva state result status step statusExact =>
        .terminal sourceRva state result status
          (abstractInterpreterStepToChecked step) statusExact
    | .next sourceRva state result continuation final step continuationExact rest =>
        .next sourceRva state result continuation final
          (abstractInterpreterStepToChecked step) continuationExact
          (abstractRunFunctionToChecked rest)
end

/-- Canonical finite semantic closure shared by the Run, Invoke, and Step
operation adapters.  Each field converts an authoritative abstract transition
into a checked finite derivation.  It contains no native execution evidence,
ABI response, frame fact, or external-event correspondence. -/
structure CheckedSemanticCallTreeClosure
    (records : List ProgramRecord) : Prop where
  run : forall environment resolveCodeTarget sourceRva state result,
    AbstractRunFunction records environment resolveCodeTarget sourceRva state
        result ->
      CheckedRunFunctionDerivation records environment resolveCodeTarget
        sourceRva state result
  invoke : forall environment resolveCodeTarget event state response,
    AbstractKernelTransition
        (.invokeCall records environment resolveCodeTarget event state)
        response ->
      exists result,
        response = .call result /\
          CheckedInvokeCallDerivation records environment resolveCodeTarget
            event state result
  step : forall environment sourceRva state response,
    AbstractKernelTransition
        (.interpreterStep records environment sourceRva state)
        response ->
      exists result resolveCodeTarget,
        response = .interpreterStep result /\
          CheckedInterpreterStepDerivation records environment
            resolveCodeTarget sourceRva state result

/-- The call-aware abstract and checked relations are structurally equivalent,
so semantic closure is generic.  Binary-specific generated data remains
responsible for binding `records` to exact PE bytes; it does not restate the
semantic recursion as thousands of premises. -/
def checkedSemanticCallTreeClosure (records : List ProgramRecord) :
    CheckedSemanticCallTreeClosure records := {
  run := by
    intro environment resolveCodeTarget sourceRva state result derivation
    exact abstractRunFunctionToChecked derivation
  invoke := by
    intro environment resolveCodeTarget event state response transition
    cases transition with
    | invokeExternal _ _ _ _ _ kindExact =>
        exact ⟨environment.invokeCall event state, rfl,
          .external event state kindExact⟩
    | invokeInternal _ _ _ _ _ result kindExact run =>
        exact ⟨result, rfl,
          .internal event state result kindExact
            (abstractRunFunctionToChecked run)⟩
    | invokeIndirect _ _ _ _ _ target result kindExact targetExact run =>
        exact ⟨result, rfl,
          .indirect event state target result kindExact targetExact
            (abstractRunFunctionToChecked run)⟩
  step := by
    intro environment sourceRva state response transition
    cases transition with
    | interpreterStep _ _ resolveCodeTarget _ _ result derivation =>
        exact ⟨result, resolveCodeTarget, rfl,
          abstractInterpreterStepToChecked derivation⟩
}

/-! ## Well-founded construction from exact semantic records

The checked derivations above are the closed proof object consumed by the
request-local native adapters.  The records below are deliberately one layer
weaker: they retain exact Step/Run execution, but an internal call records only
its exact callee frame and a strict decrease in a supplied well-founded
ranking.  Closing the record follows those edges recursively.

There is no constructor for an unresolved indirect call.  Cyclic call graphs
are accepted only when every dynamic edge carries a decrease proof for the
same well-founded relation.
-/

/-- The exact semantic invocation used as the unit of call-tree recursion. -/
structure CheckedSemanticCallFrame where
  sourceRva : Nat
  state : InterpreterMachine
  result : CallResult

/-- An explicit ranking for semantic call frames.  The rank need not be a
natural number; callers supply both the relation and its well-foundedness. -/
structure CheckedSemanticCallRanking where
  Rank : Type
  relation : Rank -> Rank -> Prop
  wellFounded : WellFounded relation
  rank : CheckedSemanticCallFrame -> Rank

/-- Exact terminal-completion evidence.  The call status is fixed by the
completion constructor rather than submitted as an independent assertion. -/
inductive ExactCheckedTerminalCompletion : Completion -> CallStatus -> Prop
  | returned (value) : ExactCheckedTerminalCompletion (.returned value) .ok
  | externalJump : ExactCheckedTerminalCompletion .externalJump .ok
  | divideError : ExactCheckedTerminalCompletion .divideError .divideError
  | memoryFault : ExactCheckedTerminalCompletion .memoryFault .memoryFault
  | externalFault : ExactCheckedTerminalCompletion .externalFault .externalFault
  | unimplemented : ExactCheckedTerminalCompletion .unimplemented .unimplemented

theorem ExactCheckedTerminalCompletion.toCompletionCallStatus
    (completion : ExactCheckedTerminalCompletion result status) :
    completionCallStatus? result = some status := by
  cases completion <;> rfl

mutual
  /-- Exact Step evidence with call sites left open for ranked closure. -/
  inductive ExactCheckedInterpreterStepRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      Nat -> InterpreterMachine -> Option MacroResult -> Prop
    | execute (sourceRva state record transfer result)
        (lookupExact : lookupProgramRecord records sourceRva = some record)
        (decodeExact : record.decode = some transfer)
        (checkedExact : transfer.checked = true)
        (execution : ExactCheckedSemanticTransferRecord records environment
          resolveCodeTarget available ranking parent transfer state result) :
        ExactCheckedInterpreterStepRecord records environment resolveCodeTarget
          available ranking parent sourceRva state result

  /-- Exact transfer execution whose call actions retain ranked open edges. -/
  inductive ExactCheckedSemanticTransferRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      SemanticTransfer -> InterpreterMachine -> Option MacroResult -> Prop
    | execute (transfer state bodyResult)
        (body : ExactCheckedInterpreterBodyRecord records environment
          resolveCodeTarget available ranking parent transfer
          (checkedInterpreterInitialRuntime state) transfer.body bodyResult) :
        ExactCheckedSemanticTransferRecord records environment resolveCodeTarget
          available ranking parent transfer state
          (checkedInterpreterTransferOutcome transfer.outcome bodyResult)

  /-- Exact left-to-right action execution with ranked call placeholders. -/
  inductive ExactCheckedInterpreterBodyRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      SemanticTransfer -> RuntimeState -> List SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | done (runtime) :
        ExactCheckedInterpreterBodyRecord records environment resolveCodeTarget
          available ranking parent transfer runtime [] (some (.inr runtime))
    | actionUnavailable (runtime action tail)
        (head : ExactCheckedInterpreterActionRecord records environment
          resolveCodeTarget available ranking parent transfer runtime action
          none) :
        ExactCheckedInterpreterBodyRecord records environment resolveCodeTarget
          available ranking parent transfer runtime (action :: tail) none
    | actionHalted (runtime action tail result)
        (head : ExactCheckedInterpreterActionRecord records environment
          resolveCodeTarget available ranking parent transfer runtime action
          (some (.inl result))) :
        ExactCheckedInterpreterBodyRecord records environment resolveCodeTarget
          available ranking parent transfer runtime (action :: tail)
          (some (.inl result))
    | actionNext (runtime action tail next result)
        (head : ExactCheckedInterpreterActionRecord records environment
          resolveCodeTarget available ranking parent transfer runtime action
          (some (.inr next)))
        (rest : ExactCheckedInterpreterBodyRecord records environment
          resolveCodeTarget available ranking parent transfer next tail result) :
        ExactCheckedInterpreterBodyRecord records environment resolveCodeTarget
          available ranking parent transfer runtime (action :: tail) result

  /-- Exact action execution.  Calls cannot use `nonCall`. -/
  inductive ExactCheckedInterpreterActionRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      SemanticTransfer -> RuntimeState -> SemanticAction ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | nonCall (runtime action result)
        (notCall : forall callIndex, action != .call callIndex)
        (resultExact :
          transfer.executeAction environment runtime action = result) :
        ExactCheckedInterpreterActionRecord records environment
          resolveCodeTarget available ranking parent transfer runtime action
          result
    | call (runtime callIndex result)
        (edge : ExactCheckedInterpreterCallRecord records environment
          resolveCodeTarget available ranking parent transfer runtime callIndex
          result) :
        ExactCheckedInterpreterActionRecord records environment
          resolveCodeTarget available ranking parent transfer runtime
          (.call callIndex) result

  /-- Exact call decoding plus a ranked semantic Invoke record. -/
  inductive ExactCheckedInterpreterCallRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      SemanticTransfer -> RuntimeState -> Nat ->
        Option (Sum MacroResult RuntimeState) -> Prop
    | invoke (runtime callIndex call event input result)
        (callExact : transfer.calls[callIndex]? = some call)
        (eventExact : call.event runtime = some (event, input))
        (invocation : RankedExactCheckedInvokeCallRecord records environment
          resolveCodeTarget available ranking parent event input result) :
        ExactCheckedInterpreterCallRecord records environment resolveCodeTarget
          available ranking parent transfer runtime callIndex
          (checkedInterpreterCallOutcome runtime event result)

  /-- An exact Invoke record at a call site.  Internal and indirect arms retain
  membership of the exact callee frame and strict rank decrease. -/
  inductive RankedExactCheckedInvokeCallRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      CallEvent -> InterpreterMachine -> CallResult -> Prop
    | external (event state)
        (kindExact : event.kind = .external) :
        RankedExactCheckedInvokeCallRecord records environment resolveCodeTarget
          available ranking parent event state
          (environment.invokeCall event state)
    | internal (event state result)
        (kindExact : event.kind = .internal)
        (calleeAvailable : available {
          sourceRva := event.targetRva.toNat
          state := state
          result := result
        })
        (decreases : ranking.relation
          (ranking.rank {
            sourceRva := event.targetRva.toNat
            state := state
            result := result
          })
          (ranking.rank parent)) :
        RankedExactCheckedInvokeCallRecord records environment resolveCodeTarget
          available ranking parent event state result
    | indirect (event state target result)
        (kindExact : event.kind = .indirect)
        (targetExact : resolveCodeTarget event.targetRva = some target)
        (calleeAvailable : available {
          sourceRva := target
          state := state
          result := result
        })
        (decreases : ranking.relation
          (ranking.rank {
            sourceRva := target
            state := state
            result := result
          })
          (ranking.rank parent)) :
        RankedExactCheckedInvokeCallRecord records environment resolveCodeTarget
          available ranking parent event state result

  /-- One exact finite semantic function run.  It is open only at the ranked
  Invoke records retained by its Step records. -/
  inductive ExactCheckedRunFunctionRecord
      (records : List ProgramRecord) (environment : Environment)
      (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
      (available : CheckedSemanticCallFrame -> Type)
      (ranking : CheckedSemanticCallRanking)
      (parent : CheckedSemanticCallFrame) :
      Nat -> InterpreterMachine -> CallResult -> Prop
    | unavailable (sourceRva state)
        (step : ExactCheckedInterpreterStepRecord records environment
          resolveCodeTarget available ranking parent sourceRva state none) :
        ExactCheckedRunFunctionRecord records environment resolveCodeTarget
          available ranking parent sourceRva state
          { status := .unimplemented, state := state }
    | terminal (sourceRva state result status)
        (step : ExactCheckedInterpreterStepRecord records environment
          resolveCodeTarget available ranking parent sourceRva state
          (some result))
        (completion :
          ExactCheckedTerminalCompletion result.completion status) :
        ExactCheckedRunFunctionRecord records environment resolveCodeTarget
          available ranking parent sourceRva state
          { status := status, state := result.state }
    | next (sourceRva state result continuation final)
        (step : ExactCheckedInterpreterStepRecord records environment
          resolveCodeTarget available ranking parent sourceRva state
          (some result))
        (continuationExact :
          completionContinuation? resolveCodeTarget result.completion =
            some continuation)
        (rest : ExactCheckedRunFunctionRecord records environment
          resolveCodeTarget available ranking parent continuation result.state
          final) :
        ExactCheckedRunFunctionRecord records environment resolveCodeTarget
          available ranking parent sourceRva state final
end

/-- A caller-supplied exact function record at one admitted semantic frame. -/
structure ExactCheckedSemanticFunctionRecord
    (records : List ProgramRecord) (environment : Environment)
    (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
    (available : CheckedSemanticCallFrame -> Type)
    (ranking : CheckedSemanticCallRanking)
    (frame : CheckedSemanticCallFrame) where
  rawRecord : ProgramRecord
  transfer : SemanticTransfer
  lookupExact :
    lookupProgramRecord records frame.sourceRva = some rawRecord
  decodeExact : rawRecord.decode = some transfer
  checkedExact : transfer.checked = true
  run : ExactCheckedRunFunctionRecord records environment resolveCodeTarget
    available ranking frame frame.sourceRva frame.state frame.result

/-- The exact semantic records admitted for closure.  `record` is semantic
proof data, not a status or native-refinement premise. -/
structure ExactCheckedSemanticFunctionRecords
    (records : List ProgramRecord) (environment : Environment)
    (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
    (ranking : CheckedSemanticCallRanking) where
  available : CheckedSemanticCallFrame -> Type
  record : ∀ frame, available frame ->
    ExactCheckedSemanticFunctionRecord records environment resolveCodeTarget
      available ranking frame

mutual
  private def ExactCheckedInterpreterStepRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {sourceRva state result}
      (record : ExactCheckedInterpreterStepRecord records environment
        resolveCodeTarget available ranking parent sourceRva state result) :
      CheckedInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result :=
    match record with
    | .execute sourceRva state raw transfer result lookupExact decodeExact
        checkedExact execution =>
        .execute sourceRva state raw transfer result lookupExact decodeExact
          checkedExact (execution.close closeCallee)

  private def ExactCheckedSemanticTransferRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {transfer state result}
      (record : ExactCheckedSemanticTransferRecord records environment
        resolveCodeTarget available ranking parent transfer state result) :
      CheckedSemanticTransferDerivation records environment resolveCodeTarget
        transfer state result :=
    match record with
    | .execute transfer state bodyResult body =>
        .execute transfer state bodyResult (body.close closeCallee)

  private def ExactCheckedInterpreterBodyRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {transfer runtime actions result}
      (record : ExactCheckedInterpreterBodyRecord records environment
        resolveCodeTarget available ranking parent transfer runtime actions
        result) :
      CheckedInterpreterBodyDerivation records environment resolveCodeTarget
        transfer runtime actions result :=
    match record with
    | .done runtime => .done runtime
    | .actionUnavailable runtime action tail head =>
        .actionUnavailable runtime action tail (head.close closeCallee)
    | .actionHalted runtime action tail result head =>
        .actionHalted runtime action tail result (head.close closeCallee)
    | .actionNext runtime action tail next result head rest =>
        .actionNext runtime action tail next result (head.close closeCallee)
          (rest.close closeCallee)

  private def ExactCheckedInterpreterActionRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {transfer runtime action result}
      (record : ExactCheckedInterpreterActionRecord records environment
        resolveCodeTarget available ranking parent transfer runtime action
        result) :
      CheckedInterpreterActionDerivation records environment resolveCodeTarget
        transfer runtime action result :=
    match record with
    | .nonCall runtime action result notCall resultExact =>
        .nonCall runtime action result notCall resultExact
    | .call runtime callIndex result edge =>
        .call runtime callIndex result (edge.close closeCallee)

  private def ExactCheckedInterpreterCallRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {transfer runtime callIndex result}
      (record : ExactCheckedInterpreterCallRecord records environment
        resolveCodeTarget available ranking parent transfer runtime callIndex
        result) :
      CheckedInterpreterCallTraceEdge records environment resolveCodeTarget
        transfer runtime callIndex result :=
    match record with
    | .invoke runtime callIndex call event input result callExact eventExact
        invocation =>
        .invoke runtime callIndex call event input result callExact eventExact
          (invocation.close closeCallee)

  private def RankedExactCheckedInvokeCallRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {event state result}
      (record : RankedExactCheckedInvokeCallRecord records environment
        resolveCodeTarget available ranking parent event state result) :
      CheckedInvokeCallDerivation records environment resolveCodeTarget event
        state result :=
    match record with
    | .external event state kindExact => .external event state kindExact
    | .internal event state result kindExact childAvailable decreases =>
        .internal event state result kindExact
          (closeCallee
            {
              sourceRva := event.targetRva.toNat
              state := state
              result := result
            }
            childAvailable decreases)
    | .indirect event state target result kindExact targetExact childAvailable
        decreases =>
        .indirect event state target result kindExact targetExact
          (closeCallee
            {
              sourceRva := target
              state := state
              result := result
            }
            childAvailable decreases)

  private def ExactCheckedRunFunctionRecord.close
      (closeCallee : ∀ child,
        available child ->
        ranking.relation (ranking.rank child) (ranking.rank parent) ->
        CheckedRunFunctionDerivation records environment resolveCodeTarget
          child.sourceRva child.state child.result)
      {sourceRva state result}
      (record : ExactCheckedRunFunctionRecord records environment
        resolveCodeTarget available ranking parent sourceRva state result) :
      CheckedRunFunctionDerivation records environment resolveCodeTarget
        sourceRva state result :=
    match record with
    | .unavailable sourceRva state step =>
        .unavailable sourceRva state (step.close closeCallee)
    | .terminal sourceRva state result status step completion =>
        .terminal sourceRva state result status (step.close closeCallee)
          completion.toCompletionCallStatus
    | .next sourceRva state result continuation final step continuationExact
        rest =>
        .next sourceRva state result continuation final
          (step.close closeCallee) continuationExact (rest.close closeCallee)
end

/-- Close one admitted exact semantic function record by recursion over the
supplied well-founded call ranking. -/
def ExactCheckedSemanticFunctionRecords.constructRun
    (functions : ExactCheckedSemanticFunctionRecords records environment
      resolveCodeTarget ranking)
    (frame : CheckedSemanticCallFrame)
    (member : functions.available frame) :
    CheckedRunFunctionDerivation records environment resolveCodeTarget
      frame.sourceRva frame.state frame.result :=
  let closeAt := ranking.wellFounded.fix
    (C := fun current => ∀ frame,
      ranking.rank frame = current ->
      functions.available frame ->
      CheckedRunFunctionDerivation records environment resolveCodeTarget
        frame.sourceRva frame.state frame.result)
    (fun _current descend frame frameRank frameAvailable =>
      (functions.record frame frameAvailable).run.close
        (fun child childAvailable decreases =>
          descend (ranking.rank child) (frameRank ▸ decreases) child rfl
            childAvailable))
    (ranking.rank frame)
  closeAt frame rfl member

/-- Exact root Invoke proof data.  Internal and indirect roots select an
admitted semantic function record; recursive calls below that root are checked
by `constructRun` and the supplied ranking. -/
inductive ExactCheckedInvokeCallRecord
    (records : List ProgramRecord) (environment : Environment)
    (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
    (functions : ExactCheckedSemanticFunctionRecords records environment
      resolveCodeTarget ranking) :
    CallEvent -> InterpreterMachine -> CallResult -> Prop
  | external (event state)
      (kindExact : event.kind = .external) :
      ExactCheckedInvokeCallRecord records environment resolveCodeTarget
        functions event state (environment.invokeCall event state)
  | internal (event state result)
      (kindExact : event.kind = .internal)
      (calleeAvailable : functions.available {
        sourceRva := event.targetRva.toNat
        state := state
        result := result
      }) :
      ExactCheckedInvokeCallRecord records environment resolveCodeTarget
        functions event state result
  | indirect (event state target result)
      (kindExact : event.kind = .indirect)
      (targetExact : resolveCodeTarget event.targetRva = some target)
      (calleeAvailable : functions.available {
        sourceRva := target
        state := state
        result := result
      }) :
      ExactCheckedInvokeCallRecord records environment resolveCodeTarget
        functions event state result

/-- Turn exact root Invoke proof data into the closed checked derivation. -/
def ExactCheckedSemanticFunctionRecords.constructInvoke
    (functions : ExactCheckedSemanticFunctionRecords records environment
      resolveCodeTarget ranking)
    (record : ExactCheckedInvokeCallRecord records environment
      resolveCodeTarget functions event state result) :
    CheckedInvokeCallDerivation records environment resolveCodeTarget event
      state result := by
  cases record with
  | external kindExact =>
      exact .external event state kindExact
  | internal result kindExact calleeAvailable =>
      exact .internal event state result kindExact
        (functions.constructRun
          {
            sourceRva := event.targetRva.toNat
            state := state
            result := result
          }
          calleeAvailable)
  | indirect target result kindExact targetExact calleeAvailable =>
      exact .indirect event state target result kindExact targetExact
        (functions.constructRun
          {
            sourceRva := target
            state := state
            result := result
          }
          calleeAvailable)

mutual
  /-- Checked and abstract Step evidence are two views of the same call-aware
  finite derivation.  Conversion is structural and never consults the external
  environment for an internal or indirect result. -/
  def CheckedInterpreterStepDerivation.toAbstract
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva state result) :
      AbstractInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result :=
    match derivation with
    | .lookupUnavailable sourceRva state lookupExact =>
        .lookupUnavailable sourceRva state lookupExact
    | .decodeUnavailable sourceRva state record lookupExact decodeExact =>
        .decodeUnavailable sourceRva state record lookupExact decodeExact
    | .unchecked sourceRva state record transfer lookupExact decodeExact checkedExact =>
        .unchecked sourceRva state record transfer lookupExact decodeExact checkedExact
    | .execute sourceRva state record transfer result lookupExact decodeExact
        checkedExact execution =>
        .execute sourceRva state record transfer result lookupExact decodeExact
          checkedExact execution.toAbstract

  def CheckedSemanticTransferDerivation.toAbstract
      (derivation : CheckedSemanticTransferDerivation records environment
        resolveCodeTarget transfer state result) :
      AbstractSemanticTransferDerivation records environment resolveCodeTarget
        transfer state result :=
    match derivation with
    | .execute transfer state bodyResult body => by
        simpa [checkedInterpreterInitialRuntime,
          abstractInterpreterInitialRuntime, checkedInterpreterTransferOutcome,
          abstractInterpreterTransferOutcome] using
          (AbstractSemanticTransferDerivation.execute transfer state bodyResult
            body.toAbstract)

  def CheckedInterpreterBodyDerivation.toAbstract
      (derivation : CheckedInterpreterBodyDerivation records environment
        resolveCodeTarget transfer runtime actions result) :
      AbstractInterpreterBodyDerivation records environment resolveCodeTarget
        transfer runtime actions result :=
    match derivation with
    | .done runtime => .done runtime
    | .actionUnavailable runtime action tail head =>
        .actionUnavailable runtime action tail head.toAbstract
    | .actionHalted runtime action tail result head =>
        .actionHalted runtime action tail result head.toAbstract
    | .actionNext runtime action tail next result head rest =>
        .actionNext runtime action tail next result head.toAbstract rest.toAbstract

  def CheckedInterpreterActionDerivation.toAbstract
      (derivation : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action result) :
      AbstractInterpreterActionDerivation records environment resolveCodeTarget
        transfer runtime action result :=
    match derivation with
    | .nonCall runtime action result notCall resultExact =>
        .nonCall runtime action result notCall resultExact
    | .call runtime callIndex result edge =>
        .call runtime callIndex result edge.toAbstract

  def CheckedInterpreterCallTraceEdge.toAbstract
      (edge : CheckedInterpreterCallTraceEdge records environment
        resolveCodeTarget transfer runtime callIndex result) :
      AbstractInterpreterCallTraceEdge records environment resolveCodeTarget
        transfer runtime callIndex result :=
    match edge with
    | .invoke runtime callIndex call event input callResult callExact eventExact
        invocation => by
        simpa [checkedInterpreterCallOutcome, checkedInterpreterCallRuntime,
          abstractInterpreterCallOutcome, abstractInterpreterCallRuntime] using
          (AbstractInterpreterCallTraceEdge.invoke runtime callIndex call event
            input callResult callExact eventExact invocation.toAbstract)

  def CheckedInvokeCallDerivation.toAbstract
      (derivation : CheckedInvokeCallDerivation records environment
        resolveCodeTarget event state result) :
      AbstractInvokeCallDerivation records environment resolveCodeTarget event
        state result :=
    match derivation with
    | .external event state kindExact => .external event state kindExact
    | .internal event state result kindExact run =>
        .internal event state result kindExact run.toAbstractRunFunction
    | .indirect event state target result kindExact targetExact run =>
        .indirect event state target result kindExact targetExact
          run.toAbstractRunFunction

  /-- Sound projection of the closed Run tree to the authoritative finite Run
  relation. -/
  def CheckedRunFunctionDerivation.toAbstractRunFunction
    (derivation : CheckedRunFunctionDerivation records environment
      resolveCodeTarget sourceRva state result) :
      AbstractRunFunction records environment resolveCodeTarget sourceRva state
        result :=
    match derivation with
    | .unavailable sourceRva state step =>
        .unavailable sourceRva state step.toAbstract
    | .terminal sourceRva state result status step statusExact =>
        .terminal sourceRva state result status step.toAbstract statusExact
    | .next sourceRva state result continuation final step continuationExact rest =>
        .next sourceRva state result continuation final step.toAbstract
          continuationExact rest.toAbstractRunFunction
end

/-- Sound projection of checked Invoke evidence to the authoritative kernel
transition. -/
theorem CheckedInvokeCallDerivation.toAbstractKernelTransition
    (derivation : CheckedInvokeCallDerivation records environment
      resolveCodeTarget event state result) :
    AbstractKernelTransition
      (.invokeCall records environment resolveCodeTarget event state)
      (.call result) := by
  cases derivation with
  | external event state kindExact =>
      exact .invokeExternal records environment resolveCodeTarget event state
        kindExact
  | internal event state result kindExact run =>
      exact .invokeInternal records environment resolveCodeTarget event state
        result kindExact run.toAbstractRunFunction
  | indirect event state target result kindExact targetExact run =>
      exact .invokeIndirect records environment resolveCodeTarget event state
        target result kindExact targetExact run.toAbstractRunFunction

def CheckedInterpreterStepDerivation.toAbstractKernelTransition
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva state result) :
    AbstractKernelTransition
      (.interpreterStep records environment sourceRva state)
      (.interpreterStep result) :=
  .interpreterStep records environment resolveCodeTarget sourceRva state result
    derivation.toAbstract

def CheckedRunFunctionDerivation.toAbstractKernelTransition
    (derivation : CheckedRunFunctionDerivation records environment
      resolveCodeTarget sourceRva state result) :
    AbstractKernelTransition
      (.runFunction records environment resolveCodeTarget sourceRva state)
      (.call result) :=
  .runFunction records environment resolveCodeTarget sourceRva state result
    derivation.toAbstractRunFunction

theorem checkedInvokeCall_iff_abstractKernelTransition :
    CheckedInvokeCallDerivation records environment resolveCodeTarget event state
        result ↔
      AbstractKernelTransition
        (.invokeCall records environment resolveCodeTarget event state)
        (.call result) := by
  constructor
  · exact CheckedInvokeCallDerivation.toAbstractKernelTransition
  · intro transition
    obtain ⟨actual, responseExact, checked⟩ :=
      (checkedSemanticCallTreeClosure records).invoke environment
        resolveCodeTarget event state (.call result) transition
    cases responseExact
    exact checked

theorem checkedInterpreterStep_iff_abstractKernelTransition :
    (Exists fun resolveCodeTarget =>
      CheckedInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result) ↔
      AbstractKernelTransition
        (.interpreterStep records environment sourceRva state)
        (.interpreterStep result) := by
  constructor
  · rintro ⟨resolveCodeTarget, checked⟩
    exact checked.toAbstractKernelTransition
  · intro transition
    obtain ⟨actual, resolveCodeTarget, responseExact, checked⟩ :=
      (checkedSemanticCallTreeClosure records).step environment sourceRva state
        (.interpreterStep result) transition
    cases responseExact
    exact ⟨resolveCodeTarget, checked⟩

theorem checkedRunFunction_iff_abstractKernelTransition :
    CheckedRunFunctionDerivation records environment resolveCodeTarget sourceRva
        state result ↔
      AbstractKernelTransition
        (.runFunction records environment resolveCodeTarget sourceRva state)
        (.call result) := by
  constructor
  · exact CheckedRunFunctionDerivation.toAbstractKernelTransition
  · intro transition
    cases transition with
    | runFunction _ _ _ _ _ _ derivation =>
        exact abstractRunFunctionToChecked derivation

#print axioms CheckedInterpreterStepDerivation.toAbstract
#print axioms CheckedRunFunctionDerivation.toAbstractRunFunction
#print axioms CheckedInvokeCallDerivation.toAbstractKernelTransition
#print axioms CheckedInterpreterStepDerivation.toAbstractKernelTransition
#print axioms CheckedRunFunctionDerivation.toAbstractKernelTransition
#print axioms checkedInvokeCall_iff_abstractKernelTransition
#print axioms checkedInterpreterStep_iff_abstractKernelTransition
#print axioms checkedRunFunction_iff_abstractKernelTransition
#print axioms FiniteCheckedRunFunctionEvidence.toCheckedRunFunctionDerivation
#print axioms FiniteCheckedInvokeCallEvidence.toCheckedInvokeCallDerivation
#print axioms ExactCheckedSemanticFunctionRecords.constructRun
#print axioms ExactCheckedSemanticFunctionRecords.constructInvoke

end StageA.Relational.InterpreterKernelClosedCallTree
