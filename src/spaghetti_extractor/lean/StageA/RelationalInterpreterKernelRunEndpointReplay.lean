import StageA.RelationalInterpreterKernelOperationReplay
import StageA.RelationalInterpreterKernelRunOperation
import StageA.RelationalInterpreterKernelRunIndirectTargets

namespace StageA.Relational.InterpreterKernelRunEndpointReplay

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelMixedReplay
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked Run endpoint replay

This module binds the generic operation replay checker to the native
`runFunction` template.  The certificate contains only an exact-byte replay and
a manifest checked against the reflected template.  It cannot submit endpoint
states, paths, semantic statuses, or a replacement Run relation.
-/

/-- Critical native cutpoints and fixed local replay lengths for one reflected
Run template. -/
structure RunFunctionNativeEndpointManifest where
  entryRva : Nat
  loopHeaderRva : Nat
  stepContinuationRva : Nat
  resolverContinuationRva : Nat
  epilogueRva : Nat
  functionBytes : Nat
  entryFuel : Nat
  stepPreludeFuel : Nat
  directContinuationFuel : Nat
  resolverPreludeFuel : Nat
  resolverSuffixFuel : Nat
  epilogueFuel : Nat
deriving Repr, DecidableEq

def canonicalRunFunctionNativeEndpointManifest
    (template : RunFunctionMachineTemplate) :
    RunFunctionNativeEndpointManifest := {
  entryRva := template.entryRva
  loopHeaderRva := template.loopHeaderRva
  stepContinuationRva := template.stepContinuationRva
  resolverContinuationRva := template.resolverContinuationRva
  epilogueRva := template.epilogueRva
  functionBytes := template.functionBytes.length
  entryFuel := runFunctionNativeEntryFuel template
  stepPreludeFuel := runFunctionNativeStepPreludeFuel template
  directContinuationFuel := runFunctionNativeDirectContinuationFuel template
  resolverPreludeFuel := runFunctionNativeResolverPreludeFuel template
  resolverSuffixFuel := runFunctionNativeResolverSuffixFuel template
  epilogueFuel := runFunctionNativeEpilogueFuel template
}

/-- Check the exact candidate-byte replay range and every Run cutpoint against
the already-reflected native template. -/
def runFunctionNativeEndpointReplayChecked
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    (static : RunFunctionNativeStaticBinding program candidate)
    (functionReplay : CheckedNativeOperationFunctionReplay candidate)
    (manifest : RunFunctionNativeEndpointManifest) : Bool :=
  functionReplay.entryRva == static.function.span.start &&
    functionReplay.byteLength == static.function.span.size &&
    manifest ==
      canonicalRunFunctionNativeEndpointManifest
        static.reflected.reflected.template

/-- Compact checked evidence for the complete native Run byte range and its
critical endpoint manifest.  The instruction inventory is computed from the
exact PE by `CheckedNativeOperationFunctionReplay`; the manifest is accepted
only when it is the canonical projection of the reflected template. -/
structure RunFunctionNativeCheckedEndpointReplay
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    (static : RunFunctionNativeStaticBinding program candidate) where
  functionReplay : CheckedNativeOperationFunctionReplay candidate
  manifest : RunFunctionNativeEndpointManifest
  checked :
    runFunctionNativeEndpointReplayChecked static functionReplay manifest = true

/-- Generated modules use this constructor with one reducible Boolean proof.
No manifest field can be selected independently. -/
def RunFunctionNativeCheckedEndpointReplay.ofCanonicalChecked
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    (static : RunFunctionNativeStaticBinding program candidate)
    (functionReplay : CheckedNativeOperationFunctionReplay candidate)
    (checked :
      runFunctionNativeEndpointReplayChecked static functionReplay
        (canonicalRunFunctionNativeEndpointManifest
          static.reflected.reflected.template) = true) :
    RunFunctionNativeCheckedEndpointReplay static := {
  functionReplay
  manifest :=
    canonicalRunFunctionNativeEndpointManifest
      static.reflected.reflected.template
  checked
}

theorem RunFunctionNativeCheckedEndpointReplay.rangeExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.functionReplay.entryRva = static.function.span.start ∧
      replay.functionReplay.byteLength = static.function.span.size := by
  have checked := replay.checked
  simp only [runFunctionNativeEndpointReplayChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact checked.1

theorem RunFunctionNativeCheckedEndpointReplay.manifestExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest =
      canonicalRunFunctionNativeEndpointManifest
        static.reflected.reflected.template := by
  have checked := replay.checked
  simp only [runFunctionNativeEndpointReplayChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact checked.2

theorem RunFunctionNativeCheckedEndpointReplay.exactCandidateBytes
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    ExactMixedReplayInventory candidate.pe candidate.imports
      (checkedKernelMixedReplayInstructions replay.functionReplay.entries) :=
  replay.functionReplay.exactInventory

theorem RunFunctionNativeCheckedEndpointReplay.entryRvaExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest.entryRva = static.function.span.start := by
  rw [replay.manifestExact]
  exact static.templateEntryExact

theorem RunFunctionNativeCheckedEndpointReplay.loopHeaderRvaExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest.loopHeaderRva =
      static.reflected.reflected.template.loopHeaderRva := by
  rw [replay.manifestExact]
  rfl

theorem RunFunctionNativeCheckedEndpointReplay.stepContinuationRvaExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest.stepContinuationRva =
      static.reflected.reflected.template.stepContinuationRva := by
  rw [replay.manifestExact]
  rfl

theorem RunFunctionNativeCheckedEndpointReplay.resolverContinuationRvaExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest.resolverContinuationRva =
      static.reflected.reflected.template.resolverContinuationRva := by
  rw [replay.manifestExact]
  rfl

theorem RunFunctionNativeCheckedEndpointReplay.epilogueRvaExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest.epilogueRva =
      static.reflected.reflected.template.epilogueRva := by
  rw [replay.manifestExact]
  rfl

theorem RunFunctionNativeCheckedEndpointReplay.fuelsExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {static : RunFunctionNativeStaticBinding program candidate}
    (replay : RunFunctionNativeCheckedEndpointReplay static) :
    replay.manifest.entryFuel =
        runFunctionNativeEntryFuel static.reflected.reflected.template ∧
      replay.manifest.stepPreludeFuel =
        runFunctionNativeStepPreludeFuel static.reflected.reflected.template ∧
      replay.manifest.directContinuationFuel =
        runFunctionNativeDirectContinuationFuel
          static.reflected.reflected.template ∧
      replay.manifest.resolverPreludeFuel =
        runFunctionNativeResolverPreludeFuel
          static.reflected.reflected.template ∧
      replay.manifest.resolverSuffixFuel =
        runFunctionNativeResolverSuffixFuel
          static.reflected.reflected.template ∧
      replay.manifest.epilogueFuel =
        runFunctionNativeEpilogueFuel
          static.reflected.reflected.template := by
  rw [replay.manifestExact]
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩

/-! ## Resolver target closure -/

/-- The checked native program must expose the exact finite target set used by
`transitionSystem.step` at Run's `call eax` resolver boundary.  The target
RVAs come from the template's exact-byte callback inventory; the executable
descriptors come from the candidate's authoritative indirect-target inventory.
-/
def runFunctionNativeResolverTargetInventoryChecked
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    (static : RunFunctionNativeStaticBinding program candidate) : Bool :=
  nativeRunResolverTargetInventoryChecked candidate
    (static.reflected.reflected.template.entryRva +
      runFunctionNativeResolverCallOffset static.reflected.reflected.template)
    static.reflected.resolverTargets

theorem runFunctionNativeResolverTargetInventoryChecked_targetSetExact
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    (static : RunFunctionNativeStaticBinding program candidate)
    (checked :
      runFunctionNativeResolverTargetInventoryChecked static = true) :
    ∃ targetSet,
      candidate.indirectTargets.targetSet?
          (static.reflected.reflected.template.entryRva +
            runFunctionNativeResolverCallOffset
              static.reflected.reflected.template)
          .call = some targetSet ∧
        targetSet.shapeValid candidate.pe = true ∧
        targetSet.targets =
          static.reflected.resolverTargets.map
            NativeIndirectTargetDescriptor.internalRva := by
  exact nativeRunResolverTargetInventoryChecked_targetSetExact candidate
    (static.reflected.reflected.template.entryRva +
      runFunctionNativeResolverCallOffset
        static.reflected.reflected.template)
    static.reflected.resolverTargets checked

/-! ## Computed local segment endpoints -/

/-- Check a concrete internal replay against an expected Run segment.  The
endpoint is inspected only after exact mixed replay computes it. -/
def runFunctionNativeInternalSegmentChecked
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelMixedReplayInstruction}
    {tail : List KernelMixedReplayInstruction}
    {undefinedSlot : Nat} {input : MachineState}
    (replay : CheckedNativeOperationInternalReplay candidate instruction tail
      undefinedSlot input)
    (expectedEntryRva expectedExitRva expectedFuel : Nat) : Bool :=
  instruction.rva == expectedEntryRva &&
    undefinedSlot == 0 &&
    (instruction :: tail).length == expectedFuel &&
    match replay.runningEndpoint? with
    | none => false
    | some endpoint =>
        endpoint.finalRva == expectedExitRva &&
          endpoint.finalSlot == 0

/-- A local Run segment with exact candidate instructions, fixed cutpoints, and
a computed running endpoint.  Neither a path nor an endpoint state is a field. -/
structure RunFunctionNativeCheckedInternalSegment
    (candidate : ExactNativeWorldProgram) (input : MachineState)
    (expectedEntryRva expectedExitRva expectedFuel : Nat) where
  instruction : KernelMixedReplayInstruction
  tail : List KernelMixedReplayInstruction
  undefinedSlot : Nat
  replay : CheckedNativeOperationInternalReplay candidate instruction tail
    undefinedSlot input
  checked :
    runFunctionNativeInternalSegmentChecked replay expectedEntryRva
      expectedExitRva expectedFuel = true

theorem RunFunctionNativeCheckedInternalSegment.entryExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    segment.instruction.rva = expectedEntryRva := by
  have checked := segment.checked
  simp only [runFunctionNativeInternalSegmentChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact checked.1.1.1

theorem RunFunctionNativeCheckedInternalSegment.slotExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    segment.undefinedSlot = 0 := by
  have checked := segment.checked
  simp only [runFunctionNativeInternalSegmentChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact checked.1.1.2

theorem RunFunctionNativeCheckedInternalSegment.fuelExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    (segment.instruction :: segment.tail).length = expectedFuel := by
  have checked := segment.checked
  simp only [runFunctionNativeInternalSegmentChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  exact checked.1.2

theorem RunFunctionNativeCheckedInternalSegment.endpointPresent
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    segment.replay.runningEndpoint?.isSome = true := by
  have checked := segment.checked
  simp only [runFunctionNativeInternalSegmentChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  cases endpointExact : segment.replay.runningEndpoint? with
  | none =>
      simp [endpointExact] at checked
  | some endpoint =>
      simp

/-- The endpoint is obtained by eliminating the successful computed replay
result.  It is not supplied by the certificate. -/
noncomputable def RunFunctionNativeCheckedInternalSegment.endpoint
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    CheckedNativeOperationRunningEndpoint segment.replay := by
  exact segment.replay.runningEndpoint?.get (by exact segment.endpointPresent)

theorem RunFunctionNativeCheckedInternalSegment.endpointOptionExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    segment.replay.runningEndpoint? = some segment.endpoint := by
  have present := segment.endpointPresent
  cases exact : segment.replay.runningEndpoint? with
  | none => simp [exact] at present
  | some endpoint =>
      have endpointExact : segment.endpoint = endpoint := by
        simp [RunFunctionNativeCheckedInternalSegment.endpoint, exact]
      simp [endpointExact]

theorem RunFunctionNativeCheckedInternalSegment.exitExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    segment.endpoint.finalRva = expectedExitRva := by
  have checked := segment.checked
  simp only [runFunctionNativeInternalSegmentChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rw [segment.endpointOptionExact] at checked
  simp only [Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.2.1

theorem RunFunctionNativeCheckedInternalSegment.finalSlotExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel) :
    segment.endpoint.finalSlot = 0 := by
  have checked := segment.checked
  simp only [runFunctionNativeInternalSegmentChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rw [segment.endpointOptionExact] at checked
  simp only [Bool.and_eq_true, beq_iff_eq] at checked
  exact checked.2.2

def RunFunctionNativeCheckedInternalSegment.chunk
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) :
    RunFunctionNativeChunk candidate
      (.running expectedEntryRva 0 input calls eventIndex events world)
      expectedFuel := {
  positive := by
    rw [← segment.fuelExact]
    simp
}

theorem RunFunctionNativeCheckedInternalSegment.chunkResultExact
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {expectedEntryRva expectedExitRva expectedFuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      expectedEntryRva expectedExitRva expectedFuel)
    (calls : List NativeCallFrame) (eventIndex : Nat)
    (events : List NativeExternalEvent) (world : RelationalWorld) :
    (segment.chunk calls eventIndex events world).result =
      (.running expectedExitRva 0 segment.endpoint.after calls eventIndex events
        world, []) := by
  have result := segment.replay.result_exact segment.endpoint calls eventIndex
    events world
  unfold CheckedNativeOperationPath.result
    CheckedNativeOperationInternalReplay.toPath at result
  unfold RunFunctionNativeChunk.result
  simpa only [segment.entryExact, segment.slotExact, segment.fuelExact,
    segment.exitExact, segment.finalSlotExact] using result

/-- Construct one terminal Run phase from exact internal replay.  The semantic
result and status are indices fixed by the checked derivation.  The execution
length comes from the exact replay rather than a compiler-template constant. -/
noncomputable def RunFunctionNativeCheckedInternalSegment.terminalPhase
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {template : RunFunctionMachineTemplate}
    {result : Option MacroResult} {status : CallStatus} {fuel : Nat}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      template.stepContinuationRva template.epilogueRva fuel)
    (runtime : RunFunctionNativeRuntime) :
    RunFunctionNativeTerminalPhase candidate template result status input
      runtime := {
  fuel
  chunk := segment.chunk runtime.calls runtime.eventIndex runtime.events
    runtime.world
  epilogueState := segment.endpoint.after
  atEpilogue := congrArg Prod.fst
    (segment.chunkResultExact runtime.calls runtime.eventIndex runtime.events
      runtime.world)
  silent := congrArg Prod.snd
    (segment.chunkResultExact runtime.calls runtime.eventIndex runtime.events
      runtime.world)
}

/-- Construct the fixed direct continuation backedge from computed replay. -/
noncomputable def RunFunctionNativeCheckedInternalSegment.directContinuation
    {candidate : ExactNativeWorldProgram} {input : MachineState}
    {template : RunFunctionMachineTemplate}
    (segment : RunFunctionNativeCheckedInternalSegment candidate input
      template.stepContinuationRva template.loopHeaderRva
      (runFunctionNativeDirectContinuationFuel template))
    (runtime : RunFunctionNativeRuntime) :
    RunFunctionNativeDirectContinuationExecution candidate template input
      runtime := {
  fuel := runFunctionNativeDirectContinuationFuel template
  chunk := segment.chunk runtime.calls runtime.eventIndex runtime.events
    runtime.world
  nextState := segment.endpoint.after
  atLoop := congrArg Prod.fst
    (segment.chunkResultExact runtime.calls runtime.eventIndex runtime.events
      runtime.world)
  silent := congrArg Prod.snd
    (segment.chunkResultExact runtime.calls runtime.eventIndex runtime.events
      runtime.world)
}

#print axioms RunFunctionNativeCheckedEndpointReplay.rangeExact
#print axioms RunFunctionNativeCheckedEndpointReplay.manifestExact
#print axioms RunFunctionNativeCheckedEndpointReplay.exactCandidateBytes
#print axioms RunFunctionNativeCheckedEndpointReplay.entryRvaExact
#print axioms RunFunctionNativeCheckedEndpointReplay.loopHeaderRvaExact
#print axioms RunFunctionNativeCheckedEndpointReplay.stepContinuationRvaExact
#print axioms
  RunFunctionNativeCheckedEndpointReplay.resolverContinuationRvaExact
#print axioms RunFunctionNativeCheckedEndpointReplay.epilogueRvaExact
#print axioms RunFunctionNativeCheckedEndpointReplay.fuelsExact
#print axioms runFunctionResolverCallEaxDecodeExact
#print axioms
  runFunctionNativeResolverTargetInventoryChecked_targetSetExact
#print axioms RunFunctionNativeCheckedInternalSegment.entryExact
#print axioms RunFunctionNativeCheckedInternalSegment.slotExact
#print axioms RunFunctionNativeCheckedInternalSegment.fuelExact
#print axioms RunFunctionNativeCheckedInternalSegment.endpointPresent
#print axioms RunFunctionNativeCheckedInternalSegment.endpointOptionExact
#print axioms RunFunctionNativeCheckedInternalSegment.exitExact
#print axioms RunFunctionNativeCheckedInternalSegment.finalSlotExact
#print axioms RunFunctionNativeCheckedInternalSegment.chunkResultExact
#print axioms RunFunctionNativeCheckedInternalSegment.terminalPhase
#print axioms RunFunctionNativeCheckedInternalSegment.directContinuation

end StageA.Relational.InterpreterKernelRunEndpointReplay
