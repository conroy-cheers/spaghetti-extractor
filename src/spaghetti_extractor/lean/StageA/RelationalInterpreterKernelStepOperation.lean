import StageA.RelationalInterpreterKernelProgramLookupOperation
import StageA.RelationalInterpreterKernelInvokeNative
import StageA.RelationalInterpreterKernelStepNative
import StageA.RelationalInterpreterX87ReplayBridgeTarget

namespace StageA.Relational.InterpreterKernelStepOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelInvokeNative
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

/-- Runtime x87 replay authority tied to an exact relocation-checked replay
table.  The static table does not imply execution: `execute` must still supply
the checked nested helper path for every reflected Step callback target. -/
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
  execute : ∀ call before,
    call ∈ template.indirectCalls ->
      replayHelperTargetRva ∈ call.targetRvas ->
      before.rva? = some replayHelperTargetRva ->
      ∃ after observations,
        Nonempty (InterpreterStepNativeLocalSubroutine template candidate before
          after observations)

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
            returnAddress) .invokeCall)
      (executeX87Replay : forall call replayBefore,
        call ∈ static.reflected.template.indirectCalls ->
          x87Replay.replayHelperTargetRva ∈ call.targetRvas ->
          replayBefore.rva? = some x87Replay.replayHelperTargetRva ->
          exists replayAfter observations,
            Nonempty (InterpreterStepNativeLocalSubroutine
              static.reflected.template candidate replayBefore replayAfter
              observations)),
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
    lookupPhase helpers.execute invokeCall.refines x87Replay.execute

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

theorem InterpreterStepNativeOperationCertificate.refines
    (certificate : InterpreterStepNativeOperationCertificate program abi
      semanticRecords candidate world) :
    KernelOperationRefinesUsing program abi
      (InterpreterStepNativeDispatches candidate world) .interpreterStep :=
  certificate.toMachineCertificate.refines

#print axioms concreteInterpreterStepRecordsExact
#print axioms InterpreterStepNativeProgramLookupCallAuthority.lookup
#print axioms InterpreterStepNativeActionLoopAuthority.compose
#print axioms InterpreterStepNativeOperationCertificate.toMachineCertificate
#print axioms InterpreterStepNativeOperationCertificate.refines

end StageA.Relational.InterpreterKernelStepOperation
