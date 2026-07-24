import StageA.RelationalInterpreterX87ReplayBridgeRuntime

namespace StageA.Relational.InterpreterKernelX87Execution

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.Relational.InterpreterX87ReplayBridgeRuntime

/-! # Exact x87 replay-kernel execution

This module is the dynamic boundary between the exact candidate instruction
semantics and the generic replay-bridge runtime theorem.  A certificate cannot
submit paths or observations.  It gives equations for `runRelatedSteps` over the
exact `ExactNestedNativeWorldProgram.transitionSystem`; the theorem below
computes every endpoint, silence fact, and path from those equations.

The endpoint authority remains an explicit premise because the current kernel
layers do not yet prove symbolic execution of the native frame setup, x87
instruction, capture, and return for every state satisfying an arbitrary source
invariant.  The premise is deliberately typed and fail-closed: it must also
relate the native output to the logical replay handler and supply the existing
checked frame-effect predicate.
-/

structure ExactNativeX87ReplayKernelProgramBinding
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram) : Prop where
  peExact : program.pe = pe
  importsExact : program.imports = imports
  targetInventory : program.indirectTargets.targetSet?
    table.callInstruction.rva .call = some table.nativeTargetSet

/-- Exact semantic equations for one replay target and one source state.

The target descriptor, bridge layout, replay operand, relocation, and candidate
bytes are already indexed by `runtimeTarget`.  This certificate adds no path
witness.  Each phase is replayed by the exact candidate transition function,
and the common theorem below projects its endpoint and empty observation list.
-/
structure ExactNativeX87ReplayKernelEndpointCertificate
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (caller logicalInput : MachineState) where
  result : StepResult
  handlerResult :
    handler runtimeTarget.target.descriptor.replay logicalInput = some result
  calleeEntry : MachineState
  instructionEntryState : MachineState
  captureEntryState : MachineState
  returnEntryState : MachineState
  returned : MachineState
  calls : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  externalFrames : List NativeWorldExternalCallbackRuntime
  callTarget :
    table.callSite.targetWord caller =
      runtimeTarget.target.descriptor.bridge.address program.pe
  entryFuel : Nat
  entryFuelPositive : 0 < entryFuel
  instructionFuel : Nat
  instructionFuelPositive : 0 < instructionFuel
  captureFuel : Nat
  captureFuelPositive : 0 < captureFuel
  returnFuel : Nat
  returnFuelPositive : 0 < returnFuel
  callRun :
    runRelatedSteps program.transitionSystem 1
        (.running table.callInstruction.rva 0 caller calls eventIndex events
          world externalFrames) =
      (.running runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  entryRun :
    runRelatedSteps program.transitionSystem entryFuel
        (.running runtimeTarget.target.descriptor.bridge.entry.rva 0 calleeEntry
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running runtimeTarget.target.frameMapping.instructionRva 0
        instructionEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  instructionRun :
    runRelatedSteps program.transitionSystem instructionFuel
        (.running runtimeTarget.target.frameMapping.instructionRva 0
          instructionEntryState
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running runtimeTarget.target.frameMapping.captureRva 0 captureEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  captureRun :
    runRelatedSteps program.transitionSystem captureFuel
        (.running runtimeTarget.target.frameMapping.captureRva 0
          captureEntryState
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running runtimeTarget.target.frameMapping.returnRva 0 returnEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } :: calls)
        eventIndex events world externalFrames, [])
  returnRun :
    runRelatedSteps program.transitionSystem returnFuel
        (.running runtimeTarget.target.frameMapping.returnRva 0 returnEntryState
          ({ continuationRva := table.continuationRva,
             returnAddress := BitVec.ofNat 32
               (program.pe.imageBase + table.continuationRva) } :: calls)
          eventIndex events world externalFrames) =
      (.running table.continuationRva 0 returned calls eventIndex events world
        externalFrames, [])
  frameEffect : NativeX87ReplayNestedFrameEffect table program.pe
    runtimeTarget.target.descriptor caller returned logicalInput result

private theorem exactSilentEndpoint
    {system : RelatedTransitionSystem state observation}
    {fuel : Nat} {before after : state}
    (exact : runRelatedSteps system fuel before = (after, [])) :
    (runRelatedSteps system fuel before).1 = after :=
  congrArg Prod.fst exact

private theorem exactSilentObservations
    {system : RelatedTransitionSystem state observation}
    {fuel : Nat} {before after : state}
    (exact : runRelatedSteps system fuel before = (after, [])) :
    (runRelatedSteps system fuel before).2 = [] :=
  congrArg Prod.snd exact

/-- Construct the runtime reduction from exact candidate execution equations.
No submitted path, report field, or solver status participates in the proof. -/
def ExactNativeX87ReplayKernelEndpointCertificate.toKernelReduction
    {runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    {caller logicalInput : MachineState}
    (certificate : ExactNativeX87ReplayKernelEndpointCertificate
      runtimeTarget program handler caller logicalInput) :
    ExactNativeX87ReplayBridgeKernelReduction
      runtimeTarget program handler caller logicalInput := by
  let call : ExactComputedNestedNativeWorldSegment program
      (.running table.callInstruction.rva 0 caller certificate.calls
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := 1
    positive := Nat.zero_lt_succ 0
  }
  let entry : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.descriptor.bridge.entry.rva 0
        certificate.calleeEntry
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.entryFuel
    positive := certificate.entryFuelPositive
  }
  let instruction : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.frameMapping.instructionRva 0
        certificate.instructionEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.instructionFuel
    positive := certificate.instructionFuelPositive
  }
  let capture : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.frameMapping.captureRva 0
        certificate.captureEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.captureFuel
    positive := certificate.captureFuelPositive
  }
  let returnSegment : ExactComputedNestedNativeWorldSegment program
      (.running runtimeTarget.target.frameMapping.returnRva 0
        certificate.returnEntryState
        ({ continuationRva := table.continuationRva,
           returnAddress := BitVec.ofNat 32
             (program.pe.imageBase + table.continuationRva) } ::
          certificate.calls)
        certificate.eventIndex certificate.events certificate.world
        certificate.externalFrames) := {
    fuel := certificate.returnFuel
    positive := certificate.returnFuelPositive
  }
  exact {
    result := certificate.result
    handlerResult := certificate.handlerResult
    calleeEntry := certificate.calleeEntry
    instructionEntryState := certificate.instructionEntryState
    captureEntryState := certificate.captureEntryState
    returnEntryState := certificate.returnEntryState
    returned := certificate.returned
    calls := certificate.calls
    eventIndex := certificate.eventIndex
    events := certificate.events
    world := certificate.world
    externalFrames := certificate.externalFrames
    sourceTarget := ⟨runtimeTarget.target.descriptorMember,
      certificate.callTarget, certificate.frameEffect.targetBefore⟩
    call
    callOne := rfl
    callAtTarget := by
      simpa [call, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.callRun
    callSilent := by
      simpa [call, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.callRun
    entry
    entryAtInstruction := by
      simpa [entry, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.entryRun
    entrySilent := by
      simpa [entry, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.entryRun
    instruction
    instructionAtCapture := by
      simpa [instruction, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.instructionRun
    instructionSilent := by
      simpa [instruction, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.instructionRun
    capture
    captureAtReturn := by
      simpa [capture, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.captureRun
    captureSilent := by
      simpa [capture, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.captureRun
    returnSegment
    returnedAtContinuation := by
      simpa [returnSegment, ExactComputedNestedNativeWorldSegment.after,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentEndpoint certificate.returnRun
    returnSilent := by
      simpa [returnSegment, ExactComputedNestedNativeWorldSegment.observations,
        ExactComputedNestedNativeWorldSegment.result] using
        exactSilentObservations certificate.returnRun
    frameEffect := certificate.frameEffect
  }

/-- The sole upstream dynamic premise.  Static candidate/kernel binding is
stated once; the source target predicate is derived from the checked descriptor,
the dynamic call target, and the typed frame effect.  Per-target evidence
otherwise consists only of exact semantic equations and handler/frame
correspondence. -/
structure ExactNativeX87ReplayKernelEndpointAuthority
    (inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop where
  programBinding : ExactNativeX87ReplayKernelProgramBinding inventory program
  execute : ∀ runtimeTarget ∈ inventory.targets,
    ∀ caller logicalInput,
      sourceInvariant runtimeTarget.target.descriptor caller logicalInput ->
        Nonempty (ExactNativeX87ReplayKernelEndpointCertificate
          runtimeTarget program handler caller logicalInput)

/-- Generic construction of the runtime kernel execution goal. -/
theorem ExactNativeX87ReplayKernelEndpointAuthority.kernelExecution
    {inventory : ExactNativeX87ReplayRuntimeInventory
      table pe imports relocations packs}
    {program : ExactNestedNativeWorldProgram}
    {handler : CandidateReplayHandler}
    {sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop}
    (authority : ExactNativeX87ReplayKernelEndpointAuthority
      inventory program handler sourceInvariant) :
    ExactNativeX87ReplayBridgeKernelExecution
      inventory program handler sourceInvariant := by
  refine { reduce := ?_ }
  intro runtimeTarget member caller logicalInput source
  rcases authority.execute runtimeTarget member caller logicalInput source with
    ⟨certificate⟩
  exact ⟨certificate.toKernelReduction⟩

#print axioms ExactNativeX87ReplayKernelEndpointCertificate.toKernelReduction
#print axioms ExactNativeX87ReplayKernelEndpointAuthority.kernelExecution

end StageA.Relational.InterpreterKernelX87Execution
