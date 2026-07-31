import StageA.RelationalInterpreterKernelProgramLookupOperation
import StageA.RelationalInterpreterKernelOperationABIFrame
import StageA.RelationalInterpreterKernelClosedCallTree
import StageA.RelationalInterpreterKernelInvokeNative
import StageA.RelationalInterpreterKernelStepNative
import StageA.RelationalInterpreterX87ReplayBridgeTarget

namespace StageA.Relational.InterpreterKernelStepOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget

/-!
Composable authority for one exact native `interpreterStep` implementation.

The existing native Step theorem deliberately accepts one large machine
certificate.  This module splits that certificate into the proof objects that
can be generated and cached independently:

* exact static bytes, function entry, blocks, and finite callback inventory;
* concrete cdecl entry and semantic record identity;
* the already-proved `programLookup` operation plus its nested-call adapter;
* helper, `invokeCall`, and x87 replay subroutine authorities;
* action-loop chunks assembled from those subroutine authorities; and
* the cdecl epilogue, response, and memory frame.

No structure contains a status field or a whole-operation path.  The final
path is still assembled by `InterpreterStepNativeMachineCertificate.refines`.
-/

/-- Exact static authority for the selected Step function. -/
structure InterpreterStepNativeStaticBinding
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram) where
  function : KernelFunction
  reflected : InterpreterStepNativeTemplateCertificate program candidate.pe
    candidate.imports function
  entryRvaExact :
    program.functionEntry? .interpreterStep = some function.span.start
  templateEntryExact : reflected.template.machine.entryRva = function.span.start

/-- The standalone native executor's external result is irrelevant to a
proved `programLookup`, because that operation has no external transition.
Using a fixed environment gives the nested-call adapter one canonical theorem
term rather than an arbitrary caller-selected environment. -/
def eventIdentityNativeEnvironment : NativeEnvironment := {
  result := fun _ event => event.state
}

/-- Closed, exact-candidate `programLookup` operation family. -/
structure InterpreterStepProgramLookupOperation
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) : Prop where
  refines : ∀ environment : NativeEnvironment,
    KernelOperationRefinesUsing program abi
      (NativeDispatches candidate.pe candidate.imports environment)
      .programLookup

/-- Concrete cdecl entry authority.  This is separated from path authority so
ABI/data changes do not invalidate action-loop certificates. -/
structure InterpreterStepNativeABIEntryAuthority
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord) : Prop where
  establishRecords : ∀ records environment sourceRva logical before,
    abi.requestRelated (.interpreterStep records environment sourceRva logical)
        before ->
      records = semanticRecords

theorem concreteInterpreterStepRecordsExact
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords)
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {sourceRva : Nat} {logical : InterpreterMachine} {before : MachineState}
    (related : abi.relation.requestRelated
      (.interpreterStep records environment sourceRva logical) before) :
    records = semanticRecords := by
  change ABIRequestFacts abi
    (.interpreterStep records environment sourceRva logical) before at related
  have payload := related.payload
  simp only [RequestPayloadHolds] at payload
  exact payload.1

def concreteInterpreterStepABIEntryAuthority
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords) :
    InterpreterStepNativeABIEntryAuthority abi.relation semanticRecords := {
  establishRecords := by
    intro records environment sourceRva logical before related
    exact concreteInterpreterStepRecordsExact abi related
}

/-- Per-call cdecl entry authority.  Nested Step calls use caller-owned
locations and preserved-register values, so their record identity must be
recovered from the checked frame relation rather than the canonical launch
ABI. -/
def framedInterpreterStepABIEntryAuthority
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords) :
    InterpreterStepNativeABIEntryAuthority (frame.relation abi)
      semanticRecords := {
  establishRecords := by
    intro records environment sourceRva logical before related
    change frame.RequestFacts abi
      (.interpreterStep records environment sourceRva logical) before at related
    exact related.payload.1
}

/-- The exact caller-side data needed to splice one `programLookup` result
into the Step path.  The callee entry, execution, response, and memory frame
are not fields: they are supplied by the proved `programLookup` operation to
`finish`. -/
structure InterpreterStepNativeProgramLookupPrepared
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (sourceRva : Nat) (stepBefore : MachineState) where
  lookupBefore : MachineState
  requestRelated :
    abi.requestRelated (.programLookup semanticRecords sourceRva) lookupBefore
  finish : forall entryRva lookupAfter nativeEvents,
    program.functionEntry? .programLookup = some entryRva ->
      NativeDispatches candidate.pe candidate.imports
        eventIdentityNativeEnvironment entryRva lookupBefore lookupAfter
        nativeEvents ->
      abi.responseRelated (.programLookup semanticRecords sourceRva)
        (.programLookup (lookupProgramRecord semanticRecords sourceRva))
        lookupAfter nativeEvents ->
      MemoryAgreesOutside
        (abi.scratchFootprint (.programLookup semanticRecords sourceRva))
        lookupAfter.memory lookupBefore.memory ->
      InterpreterStepNativeLookupPhase static.reflected.template candidate
        semanticRecords sourceRva stepBefore world

/-- Caller-frame adapter for the independently proved `programLookup`
operation.  It may establish the real nested call frame and splice the exact
callee result into the Step path, but it cannot invent or replace that result. -/
structure InterpreterStepNativeProgramLookupCallAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (operation : InterpreterStepProgramLookupOperation program abi candidate) where
  prepare : forall environment sourceRva logical before,
    abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      InterpreterStepNativeProgramLookupPrepared program abi semanticRecords
        candidate world static sourceRva before

noncomputable def InterpreterStepNativeProgramLookupCallAuthority.lookup
    (authority : InterpreterStepNativeProgramLookupCallAuthority program abi
      semanticRecords candidate world static operation)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (related : abi.requestRelated
      (.interpreterStep semanticRecords environment sourceRva logical) before) :
    InterpreterStepNativeLookupPhase static.reflected.template candidate
      semanticRecords sourceRva before world := by
  classical
  let prepared :=
    authority.prepare environment sourceRva logical before related
  have operationResult :=
    operation.refines eventIdentityNativeEnvironment
        (.programLookup semanticRecords sourceRva) prepared.lookupBefore rfl
        prepared.requestRelated
        (.programLookup (lookupProgramRecord semanticRecords sourceRva))
        (.programLookup semanticRecords sourceRva)
  let entryRva := Classical.choose operationResult
  have entryWitness := Classical.choose_spec operationResult
  let lookupAfter := Classical.choose entryWitness
  have lookupWitness := Classical.choose_spec entryWitness
  let nativeEvents := Classical.choose lookupWitness
  have facts := Classical.choose_spec lookupWitness
  exact prepared.finish entryRva lookupAfter nativeEvents facts.1 facts.2.1
    facts.2.2.1 facts.2.2.2

/-- Exact event-free executions for the ordinary helper targets called by
Step.  Each result is constrained by the reflected direct-call boundary. -/
structure InterpreterStepNativeHelperSubroutineAuthority
    (candidate : ExactNativeWorldProgram)
    (template : InterpreterStepNativeTemplate) where
  targetRvas : List Nat
  targetsExact : targetRvas = template.helperTargetRvas
  execute : ∀ targetRva continuationRva before,
    targetRva ∈ targetRvas ->
      template.subroutineBoundaryAllowed targetRva continuationRva ->
      before.rva? = some targetRva ->
      ∃ after observations,
        Nonempty (InterpreterStepNativeLocalSubroutine template candidate before
          after observations)

/-- Nested `invokeCall` operation authority at every checked Step call frame.
The continuation and return word remain quantified because action paths may
reach the operation from different native states. -/
structure InterpreterStepNativeInvokeCallAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (template : InterpreterStepNativeTemplate) where
  invokeEntryRva : Nat
  entryExact : program.functionEntry? .invokeCall = some invokeEntryRva
  callExact : template.callAtTarget template.invokeCallOffset invokeEntryRva
  refines : ∀ continuationRva returnAddress,
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world continuationRva
        returnAddress) .invokeCall

/-- Static half of the nested `invokeCall` authority.  Checked action loops
need the exact call target but obtain execution evidence request by request. -/
structure InterpreterStepNativeInvokeCallStaticBinding
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (template : InterpreterStepNativeTemplate) where
  invokeEntryRva : Nat
  entryExact : program.functionEntry? .invokeCall = some invokeEntryRva
  callExact : template.callAtTarget template.invokeCallOffset invokeEntryRva

def InterpreterStepNativeInvokeCallAuthority.staticBinding
    (authority : InterpreterStepNativeInvokeCallAuthority program abi candidate
      world template) :
    InterpreterStepNativeInvokeCallStaticBinding program candidate template := {
  invokeEntryRva := authority.invokeEntryRva
  entryExact := authority.entryExact
  callExact := authority.callExact
}

/-- One semantic Invoke request retained by a checked Step derivation. -/
structure CheckedInterpreterStepInvokeSite
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) where
  event : CallEvent
  input : InterpreterMachine
  result : CallResult
  derivation : CheckedInvokeCallDerivation records environment resolveCodeTarget
    event input result

/-- Proof that one checked Invoke site is the call retained by a trace edge. -/
inductive CheckedInterpreterCallTraceEdgeContainsInvoke
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) :
    ∀ (site : CheckedInterpreterStepInvokeSite records environment
        resolveCodeTarget)
      {transfer runtime callIndex result},
      CheckedInterpreterCallTraceEdge records environment resolveCodeTarget
        transfer runtime callIndex result -> Prop
  | here (transfer : SemanticTransfer) (runtime callIndex call event input
      callResult)
      (callExact : transfer.calls[callIndex]? = some call)
      (eventExact : call.event runtime = some (event, input))
      (invocation : CheckedInvokeCallDerivation records environment
        resolveCodeTarget event input callResult) :
      CheckedInterpreterCallTraceEdgeContainsInvoke records environment
        resolveCodeTarget
        ⟨event, input, callResult, invocation⟩
        (.invoke runtime callIndex call event input callResult callExact
          eventExact invocation)

/-- Lift a checked Invoke occurrence through one action derivation. -/
inductive CheckedInterpreterActionDerivationContainsInvoke
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) :
    ∀ (site : CheckedInterpreterStepInvokeSite records environment
        resolveCodeTarget)
      {transfer runtime action result},
      CheckedInterpreterActionDerivation records environment resolveCodeTarget
        transfer runtime action result -> Prop
  | call (runtime callIndex result)
      (edge : CheckedInterpreterCallTraceEdge records environment
        resolveCodeTarget transfer runtime callIndex result)
      (contains : CheckedInterpreterCallTraceEdgeContainsInvoke records
        environment resolveCodeTarget site edge) :
      CheckedInterpreterActionDerivationContainsInvoke records environment
        resolveCodeTarget site (.call runtime callIndex result edge)

/-- Lift a checked Invoke occurrence through the left-to-right action body. -/
inductive CheckedInterpreterBodyDerivationContainsInvoke
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) :
    ∀ (site : CheckedInterpreterStepInvokeSite records environment
        resolveCodeTarget)
      {transfer runtime actions result},
      CheckedInterpreterBodyDerivation records environment resolveCodeTarget
        transfer runtime actions result -> Prop
  | actionUnavailable (runtime action tail)
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action none)
      (contains : CheckedInterpreterActionDerivationContainsInvoke records
        environment resolveCodeTarget site head) :
      CheckedInterpreterBodyDerivationContainsInvoke records environment
        resolveCodeTarget site
        (.actionUnavailable runtime action tail head)
  | actionHalted (runtime action tail result)
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action (some (.inl result)))
      (contains : CheckedInterpreterActionDerivationContainsInvoke records
        environment resolveCodeTarget site head) :
      CheckedInterpreterBodyDerivationContainsInvoke records environment
        resolveCodeTarget site
        (.actionHalted runtime action tail result head)
  | actionNextHead (runtime action tail next result)
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action (some (.inr next)))
      (rest : CheckedInterpreterBodyDerivation records environment
        resolveCodeTarget transfer next tail result)
      (contains : CheckedInterpreterActionDerivationContainsInvoke records
        environment resolveCodeTarget site head) :
      CheckedInterpreterBodyDerivationContainsInvoke records environment
        resolveCodeTarget site
        (.actionNext runtime action tail next result head rest)
  | actionNextTail (runtime action tail next result)
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action (some (.inr next)))
      (rest : CheckedInterpreterBodyDerivation records environment
        resolveCodeTarget transfer next tail result)
      (contains : CheckedInterpreterBodyDerivationContainsInvoke records
        environment resolveCodeTarget site rest) :
      CheckedInterpreterBodyDerivationContainsInvoke records environment
        resolveCodeTarget site
        (.actionNext runtime action tail next result head rest)

/-- Lift a checked Invoke occurrence through transfer execution. -/
inductive CheckedSemanticTransferDerivationContainsInvoke
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) :
    ∀ (site : CheckedInterpreterStepInvokeSite records environment
        resolveCodeTarget)
      {transfer state result},
      CheckedSemanticTransferDerivation records environment resolveCodeTarget
        transfer state result -> Prop
  | execute (transfer state bodyResult)
      (body : CheckedInterpreterBodyDerivation records environment
        resolveCodeTarget transfer (checkedInterpreterInitialRuntime state)
        transfer.body bodyResult)
      (contains : CheckedInterpreterBodyDerivationContainsInvoke records
        environment resolveCodeTarget site body) :
      CheckedSemanticTransferDerivationContainsInvoke records environment
        resolveCodeTarget site (.execute transfer state bodyResult body)

/-- A request-local membership proof for one Invoke site in one checked Step. -/
inductive CheckedInterpreterStepDerivationContainsInvoke
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) :
    ∀ (site : CheckedInterpreterStepInvokeSite records environment
        resolveCodeTarget)
      {sourceRva state result},
      CheckedInterpreterStepDerivation records environment resolveCodeTarget
        sourceRva state result -> Prop
  | execute (sourceRva state record transfer result)
      (lookupExact : lookupProgramRecord records sourceRva = some record)
      (decodeExact : record.decode = some transfer)
      (checkedExact : transfer.checked = true)
      (execution : CheckedSemanticTransferDerivation records environment
        resolveCodeTarget transfer state result)
      (contains : CheckedSemanticTransferDerivationContainsInvoke records
        environment resolveCodeTarget site execution) :
      CheckedInterpreterStepDerivationContainsInvoke records environment
        resolveCodeTarget site
        (.execute sourceRva state record transfer result lookupExact decodeExact
          checkedExact execution)

def CheckedInterpreterStepInvokeSite.request
    (site : CheckedInterpreterStepInvokeSite records environment
      resolveCodeTarget) : AbstractKernelRequest :=
  .invokeCall records environment resolveCodeTarget site.event site.input

def CheckedInterpreterStepInvokeSite.response
    (site : CheckedInterpreterStepInvokeSite records environment
      resolveCodeTarget) : AbstractKernelResponse :=
  .call site.result

/-- Refinement of one checked Invoke request.  Unlike
`KernelOperationRefinesUsing`, the abstract request, response, and transition
are fixed by `site`; only a related concrete call frame remains quantified. -/
def CheckedInvokeCallRequestRefinesUsing
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (site : CheckedInterpreterStepInvokeSite records environment
      resolveCodeTarget) : Prop :=
  ∀ before, abi.requestRelated site.request before ->
    ∃ entryRva after nativeEvents,
      program.functionEntry? .invokeCall = some entryRva ∧
      dispatches entryRva before after nativeEvents ∧
      abi.responseRelated site.request site.response after nativeEvents ∧
      MemoryAgreesOutside (abi.scratchFootprint site.request)
        after.memory before.memory

/-- A whole-operation theorem can still feed the checked interface, but the
checked interface itself never needs that universally quantified premise. -/
theorem checkedInvokeCallRequestRefinesUsing_of_operationRefinement
    (operation : KernelOperationRefinesUsing program abi dispatches .invokeCall)
    (site : CheckedInterpreterStepInvokeSite records environment
      resolveCodeTarget) :
    CheckedInvokeCallRequestRefinesUsing program abi dispatches site := by
  intro before requestRelated
  exact operation site.request before rfl requestRelated site.response
    site.derivation.toAbstractKernelTransition

/-- Exactly the Invoke requests present in one checked Step tree, specialized
to the native continuation and return word selected by the action path. -/
def InterpreterStepNativeRequestLocalInvokeEvidence
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) : Prop :=
  ∀ site,
    CheckedInterpreterStepDerivationContainsInvoke records environment
      resolveCodeTarget site derivation ->
    ∀ continuationRva returnAddress,
      CheckedInvokeCallRequestRefinesUsing program abi
        (NativeWorldSubroutineDispatches candidate world continuationRva
          returnAddress) site

/-- Request-local Invoke evidence with one exact ABI relation per concrete
nested call frame. -/
def InterpreterStepNativeFramedRequestLocalInvokeEvidence
    (program : CompiledKernelProgram)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) : Prop :=
  ∀ site,
    CheckedInterpreterStepDerivationContainsInvoke records environment
      resolveCodeTarget site derivation ->
    ∀ continuationRva returnAddress,
      ∃ invokeABI : KernelABIRelation,
        CheckedInvokeCallRequestRefinesUsing program invokeABI
          (NativeWorldSubroutineDispatches candidate world continuationRva
            returnAddress) site

/-- Static x87 replay authority tied to an exact relocation-checked replay
table.  Dynamic replay evidence is request-local to the checked action path:
requiring execution from every state at the helper RVA would discard the frame
and value-origin preconditions that make the replay valid. -/
structure InterpreterStepNativeX87ReplayAuthority
    (candidate : ExactNativeWorldProgram)
    (template : InterpreterStepNativeTemplate) where
  table : NativeX87ReplayBridgeTable
  relocations : List BaseRelocation
  packs : List (NativeX87ReplayBridgeDescriptorPack candidate.pe
    candidate.imports relocations)
  static : ExactNativeX87ReplayBridgeStaticCertificate table candidate.pe
    candidate.imports relocations packs
  replayHelperTargetRva : Nat
  replayHelperChecked : replayHelperTargetRva ∈
    template.indirectCalls.flatMap (fun call => call.targetRvas)

/-- Per-action loop composition.  The helper, invoke, and replay terms are
indices of this certificate, preventing a generated action proof from being
accepted without the exact subroutine authorities it claims to compose. -/
structure InterpreterStepNativeActionLoopAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (helpers : InterpreterStepNativeHelperSubroutineAuthority candidate
      static.reflected.template)
    (invokeCall : InterpreterStepNativeInvokeCallAuthority program abi candidate
      world static.reflected.template)
    (x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
      static.reflected.template) where
  actions : ∀ environment sourceRva logical before
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepNativeLookupPhase
        static.reflected.template candidate semanticRecords sourceRva before
        world)
      (executeHelper : forall targetRva continuationRva helperBefore,
        targetRva ∈ helpers.targetRvas ->
          static.reflected.template.subroutineBoundaryAllowed targetRva
            continuationRva ->
          helperBefore.rva? = some targetRva ->
          exists helperAfter observations,
            Nonempty (InterpreterStepNativeLocalSubroutine
              static.reflected.template candidate helperBefore helperAfter
              observations))
      (invokeCallRefines : forall continuationRva returnAddress,
        KernelOperationRefinesUsing program abi
          (NativeWorldSubroutineDispatches candidate world continuationRva
            returnAddress) .invokeCall),
    InterpreterStepNativeActionPhase static.reflected.template candidate
      environment logical lookupPhase

def InterpreterStepNativeActionLoopAuthority.compose
    (authority : InterpreterStepNativeActionLoopAuthority program abi
      semanticRecords candidate world static helpers invokeCall x87Replay)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (requestRelated : abi.requestRelated
      (.interpreterStep semanticRecords environment sourceRva logical) before)
    (lookupPhase : InterpreterStepNativeLookupPhase static.reflected.template
      candidate semanticRecords sourceRva before world) :
    InterpreterStepNativeActionPhase static.reflected.template candidate
      environment logical lookupPhase :=
  authority.actions environment sourceRva logical before requestRelated
    lookupPhase helpers.execute invokeCall.refines

/-- The concrete fact not supplied by a checked semantic derivation: a native
path from the completed lookup to the completed action loop.  The semantic
result is deliberately absent and is recovered by the adapter below. -/
structure InterpreterStepNativeCheckedActionPath
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    {records : List ProgramRecord} {sourceRva : Nat} {before : MachineState}
    {world : RelationalWorld}
    (lookupPhase : InterpreterStepNativeLookupPhase template candidate records
      sourceRva before world) where
  afterActions : NativeWorldExecution
  observations : List WorldRelationalObservable
  path : InterpreterStepNativePath template candidate lookupPhase.afterLookup
    observations afterActions

/-- Sound adapter from a checked semantic Step plus its native action path to
the existing native phase.  The semantic result is the derivation index; it is
not recomputed with the external-call-only functional evaluator. -/
def InterpreterStepNativeCheckedActionPath.toActionPhase
    (checkedPath : InterpreterStepNativeCheckedActionPath template candidate
      (records := records) (sourceRva := sourceRva) lookupPhase)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) :
    InterpreterStepNativeActionPhase template candidate environment logical
      lookupPhase := {
  result := result
  afterActions := checkedPath.afterActions
  observations := checkedPath.observations
  path := checkedPath.path
}

/-- Request-local checked action-loop composition.  It consumes one exact
`CheckedInterpreterStepDerivation` and native Invoke refinements only for sites
proved to occur in that derivation.  The old whole-operation interface remains
available above for generated certificates that have not migrated yet. -/
structure InterpreterStepNativeCheckedActionLoopAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (invokeCall : InterpreterStepNativeInvokeCallStaticBinding program candidate
      static.reflected.template)
    (x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
      static.reflected.template) where
  actions : ∀ environment (resolveCodeTarget : Word -> Option Nat) sourceRva
      logical result before
      (derivation : CheckedInterpreterStepDerivation semanticRecords environment
        resolveCodeTarget sourceRva logical result)
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepNativeLookupPhase
        static.reflected.template candidate semanticRecords sourceRva before
        world)
      (invokeCallRefines :
        InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
          world derivation),
    InterpreterStepNativeCheckedActionPath static.reflected.template candidate
      lookupPhase

def InterpreterStepNativeCheckedActionLoopAuthority.compose
    (authority : InterpreterStepNativeCheckedActionLoopAuthority program abi
      semanticRecords candidate world static invokeCall x87Replay)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (result : Option MacroResult) (before : MachineState)
    (derivation : CheckedInterpreterStepDerivation semanticRecords environment
      resolveCodeTarget sourceRva logical result)
    (requestRelated : abi.requestRelated
      (.interpreterStep semanticRecords environment sourceRva logical) before)
    (lookupPhase : InterpreterStepNativeLookupPhase static.reflected.template
      candidate semanticRecords sourceRva before world)
    (invokeCallRefines :
      InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
        world derivation) :
    InterpreterStepNativeActionPhase static.reflected.template candidate
      environment logical lookupPhase :=
  (authority.actions environment resolveCodeTarget sourceRva logical result
    before derivation requestRelated lookupPhase
    invokeCallRefines).toActionPhase derivation

/-- Backwards-compatible embedding of the original action-loop authority.  New
checked authorities do not need this embedding or its global Invoke theorem. -/
def InterpreterStepNativeActionLoopAuthority.toChecked
    (authority : InterpreterStepNativeActionLoopAuthority program abi
      semanticRecords candidate world static helpers invokeCall x87Replay) :
    InterpreterStepNativeCheckedActionLoopAuthority program abi semanticRecords
      candidate world static invokeCall.staticBinding x87Replay := {
  actions := by
    intro environment _ sourceRva logical _ before _ requestRelated lookupPhase
      _invokeCallRefines
    let phase := authority.actions environment sourceRva logical before
      requestRelated lookupPhase helpers.execute invokeCall.refines
    exact {
      afterActions := phase.afterActions
      observations := phase.observations
      path := phase.path
    }
}

/-- Exact cdecl epilogue and result framing. -/
structure InterpreterStepNativeCDeclEpilogueAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate) where
  epilogue : ∀ environment sourceRva logical before
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepNativeLookupPhase
        static.reflected.template candidate semanticRecords sourceRva before
        world)
      (actionPhase : InterpreterStepNativeActionPhase
        static.reflected.template candidate environment logical lookupPhase),
    InterpreterStepNativeEpiloguePhase static.reflected.template candidate abi
      semanticRecords environment sourceRva logical before actionPhase

/-- The compositional operation certificate.  This is the only new proof
object needed by downstream whole-kernel composition. -/
structure InterpreterStepNativeOperationCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) where
  static : InterpreterStepNativeStaticBinding program candidate
  abiEntry : InterpreterStepNativeABIEntryAuthority abi semanticRecords
  programLookupOperation :
    InterpreterStepProgramLookupOperation program abi candidate
  programLookupCall : InterpreterStepNativeProgramLookupCallAuthority program
    abi semanticRecords candidate world static programLookupOperation
  helpers : InterpreterStepNativeHelperSubroutineAuthority candidate
    static.reflected.template
  invokeCall : InterpreterStepNativeInvokeCallAuthority program abi candidate
    world static.reflected.template
  x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
    static.reflected.template
  actionLoops : InterpreterStepNativeActionLoopAuthority program abi
    semanticRecords candidate world static helpers invokeCall x87Replay
  epilogue : InterpreterStepNativeCDeclEpilogueAuthority program abi
    semanticRecords candidate world static

noncomputable def InterpreterStepNativeOperationCertificate.toMachineCertificate
    (certificate : InterpreterStepNativeOperationCertificate program abi
      semanticRecords candidate world) :
    InterpreterStepNativeMachineCertificate program abi semanticRecords
      candidate world := {
  function := certificate.static.function
  reflected := certificate.static.reflected
  entryRvaExact := certificate.static.entryRvaExact
  templateEntryExact := certificate.static.templateEntryExact
  establishRecords := certificate.abiEntry.establishRecords
  lookup := by
    intro environment sourceRva logical before related
    exact certificate.programLookupCall.lookup environment sourceRva logical
      before related
  actions := certificate.actionLoops.compose
  epilogue := certificate.epilogue.epilogue
}

/- Legacy whole-operation adapter over the functional Step evaluator.
theorem InterpreterStepNativeOperationCertificate.refines
    (certificate : InterpreterStepNativeOperationCertificate program abi
      semanticRecords candidate world) :
    KernelOperationRefinesUsing program abi
      (InterpreterStepNativeDispatches candidate world) .interpreterStep :=
  certificate.toMachineCertificate.refines
-/

/-! ## Request-local closed-call-tree adapter

The compatibility certificate above accepts a universally quantified Invoke
operation theorem.  The checked certificate below instead consumes one finite
checked Step tree and Invoke refinements only for call sites retained by that
tree.
-/

/-- Structural completeness for Step transitions.  Since the abstract Step
request does not carry an indirect resolver, closure returns the resolver
together with the finite checked derivation that uses it. -/
structure InterpreterStepClosedCallTreeAuthority
    (records : List ProgramRecord) : Prop where
  close : ∀ environment sourceRva logical response,
    AbstractKernelTransition
        (.interpreterStep records environment sourceRva logical)
        response ->
      ∃ result resolveCodeTarget,
        response = .interpreterStep result ∧
          CheckedInterpreterStepDerivation records environment resolveCodeTarget
            sourceRva logical result

def InterpreterStepClosedCallTreeAuthority.ofClosure
    (closure : CheckedSemanticCallTreeClosure records) :
    InterpreterStepClosedCallTreeAuthority records := {
  close := closure.step
}

structure InterpreterStepNativeCheckedProgramLookupFrame
    (program : CompiledKernelProgram) (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (sourceRva : Nat) (before : MachineState) where
  abi : KernelABIRelation
  operation : InterpreterStepProgramLookupOperation program abi candidate
  prepared : InterpreterStepNativeProgramLookupPrepared program abi
    semanticRecords candidate world static sourceRva before

/-- A nested programLookup call selects its ABI relation from the exact callee
state.  The operation theorem and caller splice are retained in the same
package, preventing a relation chosen for one concrete frame from being reused
at another frame. -/
structure InterpreterStepNativeCheckedProgramLookupCallAuthority
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate) where
  prepare : forall environment sourceRva logical before,
    operationABI.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      InterpreterStepNativeCheckedProgramLookupFrame program semanticRecords
        candidate world static sourceRva before

noncomputable def
    InterpreterStepNativeCheckedProgramLookupCallAuthority.lookup
    (authority : InterpreterStepNativeCheckedProgramLookupCallAuthority program
      operationABI semanticRecords candidate world static)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (related : operationABI.requestRelated
      (.interpreterStep semanticRecords environment sourceRva logical) before) :
    InterpreterStepNativeLookupPhase static.reflected.template candidate
      semanticRecords sourceRva before world := by
  classical
  let frame := authority.prepare environment sourceRva logical before related
  have operationResult :=
    frame.operation.refines eventIdentityNativeEnvironment
      (.programLookup semanticRecords sourceRva) frame.prepared.lookupBefore rfl
      frame.prepared.requestRelated
      (.programLookup (lookupProgramRecord semanticRecords sourceRva))
      (.programLookup semanticRecords sourceRva)
  let entryRva := Classical.choose operationResult
  have entryWitness := Classical.choose_spec operationResult
  let lookupAfter := Classical.choose entryWitness
  have lookupWitness := Classical.choose_spec entryWitness
  let nativeEvents := Classical.choose lookupWitness
  have facts := Classical.choose_spec lookupWitness
  exact frame.prepared.finish entryRva lookupAfter nativeEvents facts.1 facts.2.1
    facts.2.2.1 facts.2.2.2

/-- Whole native Step certificate driven by finite checked semantic trees.
`invokeCallRefines` is request-local: it covers exactly the Invoke sites
retained by the supplied checked Step derivation. -/
structure InterpreterStepNativeCheckedOperationCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) where
  static : InterpreterStepNativeStaticBinding program candidate
  abiEntry : InterpreterStepNativeABIEntryAuthority abi semanticRecords
  closedTree : InterpreterStepClosedCallTreeAuthority semanticRecords
  programLookupCall :
    InterpreterStepNativeCheckedProgramLookupCallAuthority program abi
      semanticRecords candidate world static
  invokeCall : InterpreterStepNativeInvokeCallStaticBinding program candidate
    static.reflected.template
  invokeCallRefines : ∀ environment resolveCodeTarget sourceRva logical result
      (derivation : CheckedInterpreterStepDerivation semanticRecords environment
        resolveCodeTarget sourceRva logical result),
    InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
      world derivation
  x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
    static.reflected.template
  actionLoops : InterpreterStepNativeCheckedActionLoopAuthority program abi
    semanticRecords candidate world static invokeCall x87Replay
  epilogue : InterpreterStepNativeCDeclEpilogueAuthority program abi
    semanticRecords candidate world static

/-- Request-local native refinement for one retained checked Step tree. -/
theorem InterpreterStepNativeCheckedOperationCertificate.refinesDerivation
    (certificate : InterpreterStepNativeCheckedOperationCertificate program abi
      semanticRecords candidate world)
    (derivation : CheckedInterpreterStepDerivation semanticRecords environment
      resolveCodeTarget sourceRva logical result) :
    ∀ before,
      abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      ∃ entryRva after nativeEvents,
        program.functionEntry? .interpreterStep = some entryRva ∧
        InterpreterStepNativeDispatches candidate world entryRva before after
          nativeEvents ∧
        abi.responseRelated
          (.interpreterStep semanticRecords environment sourceRva logical)
          (.interpreterStep result) after nativeEvents ∧
        MemoryAgreesOutside
          (abi.scratchFootprint
            (.interpreterStep semanticRecords environment sourceRva logical))
          after.memory before.memory := by
  intro before requestRelated
  let lookupPhase := certificate.programLookupCall.lookup environment sourceRva
    logical before requestRelated
  let actionPhase := certificate.actionLoops.compose environment
    resolveCodeTarget sourceRva logical result before derivation requestRelated
    lookupPhase
    (certificate.invokeCallRefines environment resolveCodeTarget sourceRva logical
      result derivation)
  let epiloguePhase := certificate.epilogue.epilogue environment sourceRva logical
    before requestRelated lookupPhase actionPhase
  have completePath : InterpreterStepNativePath
      certificate.static.reflected.template candidate
      (.running certificate.static.reflected.template.machine.entryRva 0 before
        [] 0 [] world)
      (lookupPhase.observations ++ actionPhase.observations ++
        epiloguePhase.observations)
      (.returned epiloguePhase.after epiloguePhase.nativeEvents
        epiloguePhase.afterWorld) :=
    .trans (.trans lookupPhase.path actionPhase.path) epiloguePhase.path
  refine ⟨certificate.static.function.span.start, epiloguePhase.after,
    epiloguePhase.nativeEvents, certificate.static.entryRvaExact, ?_, ?_,
    epiloguePhase.memoryFrame⟩
  · refine ⟨epiloguePhase.afterWorld,
      lookupPhase.observations ++ actionPhase.observations ++
        epiloguePhase.observations, ?_⟩
    rw [← certificate.static.templateEntryExact]
    exact completePath.sound
  · exact epiloguePhase.responseRelated

/-- Compatibility with `KernelOperationRefinesUsing`.  Native execution is
selected request by request from the checked derivation returned by
`closedTree`; no universal Invoke theorem is a field of this certificate. -/
theorem InterpreterStepNativeCheckedOperationCertificate.refines
    (certificate : InterpreterStepNativeCheckedOperationCertificate program abi
      semanticRecords candidate world) :
    KernelOperationRefinesUsing program abi
      (InterpreterStepNativeDispatches candidate world) .interpreterStep := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      have recordsExact := certificate.abiEntry.establishRecords records
        environment sourceRva logical before requestRelated
      subst records
      obtain ⟨result, resolveCodeTarget, responseExact, checked⟩ :=
        certificate.closedTree.close environment sourceRva logical response
          transition
      subst response
      exact certificate.refinesDerivation checked before requestRelated

/-- Embed a compatibility Step certificate once finite checked-tree closure is
available.  This preserves generated terms while allowing new integrations to
construct the checked certificate directly. -/
def InterpreterStepNativeOperationCertificate.toChecked
    (certificate : InterpreterStepNativeOperationCertificate program abi
      semanticRecords candidate world)
    (closedTree : InterpreterStepClosedCallTreeAuthority semanticRecords) :
    InterpreterStepNativeCheckedOperationCertificate program abi semanticRecords
      candidate world := {
  static := certificate.static
  abiEntry := certificate.abiEntry
  closedTree := closedTree
  programLookupCall := {
    prepare := by
      intro environment sourceRva logical before related
      exact {
        abi := abi
        operation := certificate.programLookupOperation
        prepared := certificate.programLookupCall.prepare environment sourceRva
          logical before related
      }
  }
  invokeCall := certificate.invokeCall.staticBinding
  invokeCallRefines := by
    intro environment resolveCodeTarget sourceRva logical result derivation site
      _contains continuationRva returnAddress
    exact ⟨abi,
      checkedInvokeCallRequestRefinesUsing_of_operationRefinement
        (certificate.invokeCall.refines continuationRva returnAddress) site⟩
  x87Replay := certificate.x87Replay
  actionLoops := certificate.actionLoops.toChecked
  epilogue := certificate.epilogue
}

#print axioms concreteInterpreterStepRecordsExact
#print axioms InterpreterStepNativeProgramLookupCallAuthority.lookup
#print axioms InterpreterStepNativeActionLoopAuthority.compose
#print axioms checkedInvokeCallRequestRefinesUsing_of_operationRefinement
#print axioms InterpreterStepNativeCheckedActionPath.toActionPhase
#print axioms InterpreterStepNativeCheckedActionLoopAuthority.compose
#print axioms InterpreterStepNativeActionLoopAuthority.toChecked
#print axioms InterpreterStepNativeOperationCertificate.toMachineCertificate
#print axioms InterpreterStepNativeCheckedOperationCertificate.refinesDerivation
#print axioms InterpreterStepNativeCheckedOperationCertificate.refines
#print axioms InterpreterStepNativeOperationCertificate.toChecked

end StageA.Relational.InterpreterKernelStepOperation
