import StageA.RelationalInterpreterKernelOperationABIFrame
import StageA.RelationalInterpreterKernelOperationInstantiation
import StageA.RelationalInterpreterKernelStepOperationClosure

namespace StageA.Relational.InterpreterKernelStepWorldProgramLookup

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterKernelOperationInstantiation
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepOperationClosure
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
open StageA.Relational.InterpreterKernelStepProgramLookupExactComputation
open StageA.Relational.InterpreterNativeWorld

/-!
# World-indexed Step to ProgramLookup composition

The public kernel ABI describes a top-level launch frame.  A ProgramLookup
called by Step has a different ESP, return word, and set of caller-owned stack
locations.  Consequently a top-level ProgramLookup theorem cannot soundly be
reused for the nested call.

This module composes the checked Step prefix with a ProgramLookup theorem over
one explicit `KernelOperationABIFrame`.  The callee theorem executes below the
exact continuation and return word installed by the checked call instruction.
No top-level ABI specialization, submitted endpoint, or assumed world equality
is involved.
-/

/-- Exact Step prefix and one per-call ProgramLookup theorem.  The caller path
is restricted to checked Step chunks and exact helper subroutines.  The call
chunk endpoint is computed by the candidate transition system. -/
structure InterpreterStepNativeWorldProgramLookupCallerSetup
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (outerABI : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState) where
  callBefore : NativeWorldExecution
  prefixObservations : List WorldRelationalObservable
  prefixPath :
    ExactComputedInterpreterStepPrefix static.reflected.template candidate
      (.running static.reflected.template.machine.entryRva 0 stepBefore [] 0 []
        world)
      prefixObservations callBefore
  call :
    ExactInterpreterStepProgramLookupCallReplay program candidate static site
      world callBefore
  frame : KernelOperationABIFrame
  returnAddressExact :
    frame.returnAddress = site.parameters.returnAddress candidate.pe
  requestRelated :
    (frame.relation outerABI).requestRelated
      (.programLookup semanticRecords sourceRva) call.lookupBefore

structure InterpreterStepNativeWorldProgramLookupCallerFrame
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (outerABI : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState) where
  callBefore : NativeWorldExecution
  prefixObservations : List WorldRelationalObservable
  prefixPath :
    ExactComputedInterpreterStepPrefix static.reflected.template candidate
      (.running static.reflected.template.machine.entryRva 0 stepBefore [] 0 []
        world)
      prefixObservations callBefore
  call :
    ExactInterpreterStepProgramLookupCallReplay program candidate static site
      world callBefore
  frame : KernelOperationABIFrame
  returnAddressExact :
    frame.returnAddress = site.parameters.returnAddress candidate.pe
  requestRelated :
    (frame.relation outerABI).requestRelated
      (.programLookup semanticRecords sourceRva) call.lookupBefore
  operation :
    KernelOperationRefinesUsing program (frame.relation outerABI)
      (NativeWorldSubroutineDispatches candidate world
        site.parameters.continuationRva
        (site.parameters.returnAddress candidate.pe))
      .programLookup

def InterpreterStepNativeWorldProgramLookupCallerSetup.withOperation
    (setup :
      InterpreterStepNativeWorldProgramLookupCallerSetup program semanticRecords
        outerABI candidate world static site sourceRva stepBefore)
    (operation :
      KernelOperationRefinesUsing program (setup.frame.relation outerABI)
        (NativeWorldSubroutineDispatches candidate world
          site.parameters.continuationRva
          (site.parameters.returnAddress candidate.pe))
        .programLookup) :
    InterpreterStepNativeWorldProgramLookupCallerFrame program semanticRecords
      outerABI candidate world static site sourceRva stepBefore := {
  callBefore := setup.callBefore
  prefixObservations := setup.prefixObservations
  prefixPath := setup.prefixPath
  call := setup.call
  frame := setup.frame
  returnAddressExact := setup.returnAddressExact
  requestRelated := setup.requestRelated
  operation
}

/-- Strong lookup result retained at the world-indexed boundary.  In addition
to the exact Step path, it keeps the nested ABI response and scratch-memory
frame selected by the ProgramLookup theorem. -/
structure InterpreterStepNativeWorldProgramLookupResult
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (outerABI : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static)
    (sourceRva : Nat) (stepBefore : MachineState)
    (caller : InterpreterStepNativeWorldProgramLookupCallerFrame program
      semanticRecords outerABI candidate world static site sourceRva
      stepBefore) where
  lookupAfter : MachineState
  nativeEvents : List NativeExternalEvent
  phase : InterpreterStepNativeLookupPhase static.reflected.template candidate
    semanticRecords sourceRva stepBefore world
  responseRelated :
    (caller.frame.relation outerABI).responseRelated
      (.programLookup semanticRecords sourceRva)
      (.programLookup (lookupProgramRecord semanticRecords sourceRva))
      lookupAfter nativeEvents
  memoryFrame :
    MemoryAgreesOutside
      ((caller.frame.relation outerABI).scratchFootprint
        (.programLookup semanticRecords sourceRva))
      lookupAfter.memory caller.call.lookupBefore.memory

/-! ## Action composition retaining the checked lookup result

The ordinary Step action interface only receives `phase.afterLookup`. That is
enough to concatenate paths, but it discards the nested ProgramLookup response
facts that establish the returned record pointer, loaded image and program
table, cdecl frame, and scratch-memory preservation. Compiled interpreter
loops consume exactly those facts, so the world-indexed interface retains the
complete checked result.
-/

structure InterpreterStepNativeWorldCheckedActionLoopAuthority
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
      static.reflected.template) where
  actions : forall environment (resolveCodeTarget : Word -> Option Nat) sourceRva
      logical result before
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
    InterpreterStepNativeCheckedActionPath static.reflected.template candidate
      lookup.phase

def InterpreterStepNativeWorldCheckedActionLoopAuthority.compose
    (authority : InterpreterStepNativeWorldCheckedActionLoopAuthority program
      semanticRecords outerABI operationABI candidate world static site
      invokeCall x87Replay)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (result : Option MacroResult) (before : MachineState)
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
        world derivation) :
    InterpreterStepNativeActionPhase static.reflected.template candidate
      environment logical lookup.phase :=
  (authority.actions environment resolveCodeTarget sourceRva logical result
    before derivation requestRelated caller lookup invokeCallRefines
    ).toActionPhase derivation

/-- Compatibility adapter for existing exact-action producers. New binary
proofs should implement the world-indexed authority directly so they can use
the checked ProgramLookup response. -/
def InterpreterStepNativeCheckedActionLoopAuthority.toWorld
    (authority : InterpreterStepNativeCheckedActionLoopAuthority program
      operationABI semanticRecords candidate world static invokeCall x87Replay) :
    InterpreterStepNativeWorldCheckedActionLoopAuthority program semanticRecords
      outerABI operationABI candidate world static site invokeCall x87Replay := {
  actions := by
    intro environment resolveCodeTarget sourceRva logical result before
      derivation requestRelated _caller lookup invokeCallRefines
    exact authority.actions environment resolveCodeTarget sourceRva logical
      result before derivation requestRelated lookup.phase invokeCallRefines
}

/-- Exact candidate action execution with the complete checked nested lookup
result in scope. The path remains a projection of exact candidate execution. -/
structure InterpreterStepNativeWorldExactActionClosure
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
      static.reflected.template) where
  path : forall environment (resolveCodeTarget : Word -> Option Nat) sourceRva
      logical result before
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
    InterpreterStepExactActionExecution static.reflected.template candidate
      lookup.phase

def InterpreterStepNativeWorldExactActionClosure.toAuthority
    (closure : InterpreterStepNativeWorldExactActionClosure program
      semanticRecords outerABI operationABI candidate world static site
      invokeCall x87Replay) :
    InterpreterStepNativeWorldCheckedActionLoopAuthority program semanticRecords
      outerABI operationABI candidate world static site invokeCall x87Replay := {
  actions := by
    intro environment resolveCodeTarget sourceRva logical result before
      derivation requestRelated caller lookup invokeCallRefines
    let execution :=
      closure.path environment resolveCodeTarget sourceRva logical result before
        derivation requestRelated caller lookup invokeCallRefines
    exact {
      afterActions := execution.after
      observations := execution.observations
      path := execution.path.toNativePath
    }
}

/-- The nested theorem supplies the only callee endpoint.  Its exact
subroutine path is spliced after the checked prefix and call chunk, while its
ABI response and memory-frame results remain available in the returned
object. -/
noncomputable def InterpreterStepNativeWorldProgramLookupCallerFrame.lookupResult
    (frame :
      InterpreterStepNativeWorldProgramLookupCallerFrame program semanticRecords
        outerABI candidate world static site sourceRva stepBefore) :
    InterpreterStepNativeWorldProgramLookupResult program semanticRecords
      outerABI candidate world static site sourceRva stepBefore frame := by
  classical
  have operationResult :=
    frame.operation
      (.programLookup semanticRecords sourceRva) frame.call.lookupBefore rfl
      frame.requestRelated
      (.programLookup (lookupProgramRecord semanticRecords sourceRva))
      (.programLookup semanticRecords sourceRva)
  let entryRva := Classical.choose operationResult
  have entryWitness := Classical.choose_spec operationResult
  let lookupAfter := Classical.choose entryWitness
  have lookupWitness := Classical.choose_spec entryWitness
  let nativeEvents := Classical.choose lookupWitness
  have facts := Classical.choose_spec lookupWitness
  have entryExact : entryRva = site.parameters.targetRva := by
    have operationEntry :
        program.functionEntry? .programLookup = some entryRva := by
      simpa [KernelOperation.role, entryRva] using facts.1
    exact Option.some.inj (operationEntry.symm.trans site.entryExact)
  have nestedDispatch :
      NativeWorldSubroutineDispatches candidate world
        site.parameters.continuationRva
        (site.parameters.returnAddress candidate.pe) entryRva
        frame.call.lookupBefore lookupAfter nativeEvents := by
    simpa [entryRva, lookupAfter, nativeEvents] using facts.2.1
  have targetDispatch :
      NativeWorldSubroutineDispatches candidate world
        site.parameters.continuationRva
        (site.parameters.returnAddress candidate.pe) site.parameters.targetRva
        frame.call.lookupBefore lookupAfter nativeEvents := by
    simpa [entryExact] using nestedDispatch
  let nested := Classical.choice targetDispatch
  let returned : NativeWorldExecution :=
    .running site.parameters.continuationRva 0 lookupAfter []
      nativeEvents.length nativeEvents nested.afterWorld
  have callDestination : frame.call.chunk.destinationChecked := by
    simp only [InterpreterStepNativeChunk.destinationChecked,
      frame.call.chunkAfter, NativeWorldExecution.rva?]
    exact frame.call.destinationAllowed
  have callPath : ExactComputedInterpreterStepPath
      static.reflected.template candidate frame.callBefore
      frame.call.chunk.observations frame.call.chunk.after :=
    .chunk frame.call.chunk callDestination
  have nestedPath : InterpreterStepNativeLocalSubroutine
      static.reflected.template candidate frame.call.chunk.after returned
      nested.observations := {
    targetRva := site.parameters.targetRva
    continuationRva := site.parameters.continuationRva
    boundaryAllowed := site.boundaryAllowed
    continuationAllowed := site.continuationAllowed
    startsAt := by
      rw [frame.call.chunkAfter]
      rfl
    finishesAt := rfl
    path := by
      rw [frame.call.chunkAfter]
      simpa [returned, lookupAfter, nativeEvents] using nested.path
  }
  exact {
    lookupAfter
    nativeEvents
    phase := {
      record := lookupProgramRecord semanticRecords sourceRva
      afterLookup := returned
      observations :=
        (frame.prefixObservations ++ frame.call.chunk.observations) ++
          nested.observations
      path :=
        (frame.prefixPath.append callPath).toNativePath.trans
          (.subroutine nestedPath)
      recordExact := rfl
    }
    responseRelated := facts.2.2.1
    memoryFrame := facts.2.2.2
  }

noncomputable def InterpreterStepNativeWorldProgramLookupCallerFrame.lookupPhase
    (frame :
      InterpreterStepNativeWorldProgramLookupCallerFrame program semanticRecords
        outerABI candidate world static site sourceRva stepBefore) :
    InterpreterStepNativeLookupPhase static.reflected.template candidate
      semanticRecords sourceRva stepBefore world :=
  frame.lookupResult.phase

/-- Universal caller family for the exact Step entry relation. -/
structure InterpreterStepNativeWorldProgramLookupCallAuthority
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (outerABI : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (operationABI : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static) where
  prepare : forall environment sourceRva logical before,
    operationABI.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      InterpreterStepNativeWorldProgramLookupCallerFrame program semanticRecords
        outerABI candidate world static site sourceRva before

noncomputable def InterpreterStepNativeWorldProgramLookupCallAuthority.lookup
    (authority :
      InterpreterStepNativeWorldProgramLookupCallAuthority program
        semanticRecords outerABI operationABI candidate world static site)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (related : operationABI.requestRelated
      (.interpreterStep semanticRecords environment sourceRva logical) before) :
    InterpreterStepNativeLookupPhase static.reflected.template candidate
      semanticRecords sourceRva before world :=
  (authority.prepare environment sourceRva logical before related).lookupPhase

/-! ## Whole Step certificate over the world-indexed nested call

This variant differs from `InterpreterStepNativeCheckedOperationCertificate`
only at the lookup field. Helper execution is retained inside the exact
request-local action path; it is not required from arbitrary machine states.
-/

structure InterpreterStepNativeWorldCheckedOperationCertificate
    (program : CompiledKernelProgram)
    (semanticRecords : List ProgramRecord)
    (outerABI : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (operationABI : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) where
  static : InterpreterStepNativeStaticBinding program candidate
  abiEntry :
    InterpreterStepNativeABIEntryAuthority operationABI semanticRecords
  closedTree : InterpreterStepClosedCallTreeAuthority semanticRecords
  programLookupSite :
    InterpreterStepProgramLookupCallSiteCertificate program candidate static
  programLookupCall :
    InterpreterStepNativeWorldProgramLookupCallAuthority program semanticRecords
      outerABI operationABI candidate world static programLookupSite
  invokeCall : InterpreterStepNativeInvokeCallStaticBinding program candidate
    static.reflected.template
  invokeCallRefines : forall environment resolveCodeTarget sourceRva logical
      result
      (derivation : CheckedInterpreterStepDerivation semanticRecords environment
        resolveCodeTarget sourceRva logical result),
    InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
      world derivation
  x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
    static.reflected.template
  actionLoops : InterpreterStepNativeWorldCheckedActionLoopAuthority program
    semanticRecords outerABI operationABI candidate world static
    programLookupSite invokeCall x87Replay
  epilogue : InterpreterStepNativeCDeclEpilogueAuthority program
    operationABI semanticRecords candidate world static

theorem InterpreterStepNativeWorldCheckedOperationCertificate.refinesDerivation
    (certificate :
      InterpreterStepNativeWorldCheckedOperationCertificate program
        semanticRecords outerABI operationABI candidate world)
    (derivation : CheckedInterpreterStepDerivation semanticRecords environment
      resolveCodeTarget sourceRva logical result) :
    forall before,
      operationABI.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      exists entryRva after nativeEvents,
        program.functionEntry? .interpreterStep = some entryRva /\
        InterpreterStepNativeDispatches candidate world entryRva before after
          nativeEvents /\
        operationABI.responseRelated
          (.interpreterStep semanticRecords environment sourceRva logical)
          (.interpreterStep result) after nativeEvents /\
        MemoryAgreesOutside
          (operationABI.scratchFootprint
            (.interpreterStep semanticRecords environment sourceRva logical))
          after.memory before.memory := by
  intro before requestRelated
  let lookupCaller := certificate.programLookupCall.prepare environment sourceRva
    logical before requestRelated
  let lookupResult := lookupCaller.lookupResult
  let lookupPhase := lookupResult.phase
  let actionPhase := certificate.actionLoops.compose environment
    resolveCodeTarget sourceRva logical result before derivation requestRelated
    lookupCaller lookupResult
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

theorem InterpreterStepNativeWorldCheckedOperationCertificate.refines
    (certificate :
      InterpreterStepNativeWorldCheckedOperationCertificate program
        semanticRecords outerABI operationABI candidate world) :
    KernelOperationRefinesUsing program operationABI
      (InterpreterStepNativeDispatches candidate world) .interpreterStep := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records requestEnvironment resolveCodeTarget sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records requestEnvironment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records requestEnvironment sourceRva logical =>
      have recordsExact := certificate.abiEntry.establishRecords records
        requestEnvironment sourceRva logical before requestRelated
      subst records
      obtain ⟨result, resolveCodeTarget, responseExact, checked⟩ :=
        certificate.closedTree.close requestEnvironment sourceRva logical
          response transition
      subst response
      exact certificate.refinesDerivation checked before requestRelated

/-- Authoritative world-indexed dispatch-family form consumed by mixed
acceptance.  This is only a definitional projection of the exact Step
certificate; it introduces no endpoint or launch-world premise. -/
theorem InterpreterStepNativeWorldCheckedOperationCertificate.refinesCheckedFamily
    (certificate :
      InterpreterStepNativeWorldCheckedOperationCertificate program
        semanticRecords outerABI operationABI candidate world) :
    KernelOperationRefinesUsing program operationABI
      (checkedNativeWorldKernelOperationDispatchFamily candidate world
        .interpreterStep) .interpreterStep := by
  simpa [checkedNativeWorldKernelOperationDispatchFamily,
    InterpreterStepNativeDispatches, NativeWorldKernelDispatches] using
    certificate.refines

#print axioms
  InterpreterStepNativeWorldProgramLookupCallerFrame.lookupResult
#print axioms
  InterpreterStepNativeWorldProgramLookupCallerFrame.lookupPhase
#print axioms InterpreterStepNativeWorldProgramLookupCallAuthority.lookup
#print axioms InterpreterStepNativeWorldCheckedActionLoopAuthority.compose
#print axioms InterpreterStepNativeCheckedActionLoopAuthority.toWorld
#print axioms InterpreterStepNativeWorldExactActionClosure.toAuthority
#print axioms
  InterpreterStepNativeWorldCheckedOperationCertificate.refinesDerivation
#print axioms InterpreterStepNativeWorldCheckedOperationCertificate.refines
#print axioms
  InterpreterStepNativeWorldCheckedOperationCertificate.refinesCheckedFamily

end StageA.Relational.InterpreterKernelStepWorldProgramLookup
