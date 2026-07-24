import StageA.RelationalCallableExternalMixedBridge
import StageA.RelationalInternalDirectCallComposition
import StageA.RelationalReachableStaticPointerSlot
import StageA.RelationalLockstepEnvironment

namespace StageA.Relational.ExternalTailStaticPointerSlotComposition

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.ReachableStaticPointerSlot

/-!
# Framed external-tail composition for writable static pointer slots

This layer closes a common PE32 wrapper shape:

* a caller places a checked code pointer in a runtime-frame argument;
* an internal wrapper copies that argument into a writable static word;
* the wrapper tail-jumps through an exact import binding;
* the returning external call resumes the caller's runtime continuation.

The operational path is always a path of `DecodedWorldProgram.pe32TransitionSystem`,
so every internal step is fetched from the exact PE bytes.  The external result
is accepted only through the existing one-to-one environment refinement and
machine ABI contract.  In particular, this module has no constructor for a
protocol action, callback, blocked result, or an unbounded memory effect.
-/

inductive ExternalTailRouteKind where
  | directImport
  | iatIndirect
deriving Repr, DecidableEq

/-- Stable metadata selected by a generator.  It is an index of the semantic
certificate below, not a Boolean proof report. -/
structure ExternalTailStaticPointerSlotSpec where
  sourceTargetId : Nat
  wrapperTargetId : Nat
  continuationTargetId : Nat
  sourceRva : Nat
  callsiteRva : Nat
  callInstructionSize : Nat
  wrapperRva : Nat
  continuationRva : Nat
  routeKind : ExternalTailRouteKind
  iatRva : Option Nat
  slotRva : Nat
  slotTargetId : Nat
  slotValue : Nat
  siteId : Nat
  machineContractId : Nat
  imported : ExternalTarget
  originalFrameArgumentOffset : Nat
  candidateFrameArgumentOffset : Nat
  stackArgumentOffsets : List Nat
  stackResultDelta : Nat
  preservedRegisters : List Reg
  clobberedRegisters : List Reg
deriving Repr, DecidableEq

/-- One exact original running point.  Callback execution uses a different
carrier and cannot inhabit this type. -/
structure OriginalRunningPoint where
  targetId : Nat
  state : MachineState
  calls : List Nat
  eventIndex : Nat
  world : RelationalWorld

def OriginalRunningPoint.execution (point : OriginalRunningPoint) :
    WorldExecution :=
  .running point.targetId point.state point.calls point.eventIndex point.world

/-- Exact decoded direct-call entry and its paired runtime-frame witness.  The
candidate states are used only to establish the relational frame and argument
memory; candidate execution remains the responsibility of mixed composition.
The original transition itself is fetched from the exact PE bytes. -/
structure ExactOriginalFramedDirectCallEntry
    (context : StaticProofContext)
    (program : DecodedWorldProgram)
    (spec : ExternalTailStaticPointerSlotSpec)
    (source entry : OriginalRunningPoint)
    (frame : RelationalRuntimeCallFrame)
    (candidateSource candidateEntry : MachineState) where
  originalRole : program.candidate = false
  contextExact : program.context = context
  sourceTarget : source.targetId = spec.sourceTargetId
  callsiteReturn :
    spec.callsiteRva + spec.callInstructionSize = spec.continuationRva
  callInstructionNonempty : 0 < spec.callInstructionSize
  behavior : RelationalBehavior
  behaviorExact : pe32WorldRegionBehaviorWithCalls program source.targetId
    source.state source.calls = some behavior
  outcomeExact : behavior.outcome =
    .call spec.wrapperTargetId spec.continuationTargetId
  transitionExact : program.pe32TransitionSystem.step source.execution = {
    next := entry.execution
    observation := none
  }
  entryState : entry.state = behavior.nextMachineState source.state
  entryTarget : entry.targetId = spec.wrapperTargetId
  entryCalls : entry.calls = spec.continuationTargetId :: source.calls
  entryEventIndex : entry.eventIndex = source.eventIndex
  entryWorld : entry.world = source.world
  callPush : DirectCallPushClaim
  callPushCallee : callPush.calleeTargetId = spec.wrapperTargetId
  callPushContinuation :
    callPush.continuationTargetId = spec.continuationTargetId
  originalReturnAddress :
    callPush.originalReturnAddress =
      context.originalPe.imageBase + spec.continuationRva
  candidateReturnAddress :
    callPush.candidateReturnAddress =
      context.candidatePe.imageBase + spec.continuationRva
  runtimeFrame : callPush.runtimeFrame context source.state candidateSource =
    some frame
  frameValid : frame.valid context = true
  frameContinuation : frame.continuationTargetId = spec.continuationTargetId
  frameOriginalStack : frame.originalStackAddress = entry.state.registers.esp
  frameCandidateStack :
    frame.candidateStackAddress = candidateEntry.registers.esp
  frameMemory : frame.memoryHolds entry.state.memory candidateEntry.memory

theorem ExactOriginalFramedDirectCallEntry.path
    (call : ExactOriginalFramedDirectCallEntry context program spec source entry
      frame candidateSource candidateEntry) :
    NonemptyRelatedPath program.pe32TransitionSystem source.execution []
      entry.execution := by
  have path := nonemptyRelatedPath_one program.pe32TransitionSystem
    source.execution
  rw [call.transitionExact] at path
  simpa using path

/-- The exact original context is generated separately from the paired static
context.  This bridge prevents a slot certificate from being replayed against
different PE bytes, imports, relocations, or machine-call contracts. -/
structure ExactOriginalStaticContextBridge
    (context : StaticProofContext)
    (original : OriginalDecodedStaticContext) : Prop where
  pe : original.pe = context.originalPe
  imports : original.imports = context.originalImports
  relocations : original.relocations = context.originalRelocations
  machineContracts :
    original.machineImportCallContracts = context.machineImportCallContracts

/-- Every source location in the stable request is checked against the exact
one-sided original code map. -/
structure ExactOriginalSpecCodeBinding
    (original : OriginalDecodedStaticContext)
    (spec : ExternalTailStaticPointerSlotSpec) where
  source : OriginalCodeTarget
  wrapper : OriginalCodeTarget
  continuation : OriginalCodeTarget
  sourceFound : original.codeMap.get? spec.sourceTargetId = some source
  wrapperFound : original.codeMap.get? spec.wrapperTargetId = some wrapper
  continuationFound : original.codeMap.get? spec.continuationTargetId =
    some continuation
  sourceId : source.id = spec.sourceTargetId
  wrapperId : wrapper.id = spec.wrapperTargetId
  continuationId : continuation.id = spec.continuationTargetId
  sourceRva : source.rva = spec.sourceRva
  wrapperRva : wrapper.rva = spec.wrapperRva
  continuationRva : continuation.rva = spec.continuationRva

/-- Local, kernel-checked facts about one writable slot and its canonical code
target.  Unlike `ReachableStaticPointerSlot.KernelEvidence`, this object does
not claim that every reachable transition in the whole program preserves the
slot.  That stronger claim is composed transition by transition.  Keeping the
local macro independent avoids making one proof depend on every unrelated
dynamic write in the image. -/
structure ExactLocalStaticPointerSlotEvidence
    (original : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (targetIds : List Nat) (targetId expectedValue : Nat) where
  authority : ExactOriginalDecodedAuthority original
  allowedExact : certificate.allowedTargetIds = .exact targetIds
  targetMember : targetId ∈ targetIds
  initialZero : initialZeroChecked original certificate = true
  targetsChecked : allowedTargetsChecked original targetIds = true
  canonicalWord : Nat
  canonical : targetCanonicalWord? original targetId = some canonicalWord
  canonicalExact : canonicalWord = expectedValue

/-- Static authority exported to the mixed-original planner.  It binds a named
term to exact PE bytes and stable request metadata without pretending that a
runtime source state, external result, or candidate execution already exists. -/
structure ExternalTailStaticPointerSlotStaticAuthority
    (context : StaticProofContext)
    (original : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (spec : ExternalTailStaticPointerSlotSpec) where
  staticContext : ExactOriginalStaticContextBridge context original
  codeBinding : ExactOriginalSpecCodeBinding original spec
  targetIds : List Nat
  slotEvidence : ExactLocalStaticPointerSlotEvidence original certificate
    targetIds spec.slotTargetId spec.slotValue
  certificateSlot : certificate.slotRva = spec.slotRva

/-- Exact import-tail classification of the decoded wrapper outcome.  The
indirect constructor additionally binds the concrete IAT pair and its runtime
address; an import name alone is never sufficient. -/
inductive ExactOriginalImportedTailTransfer
    (program : DecodedWorldProgram) (point : OriginalRunningPoint)
    (behavior : RelationalBehavior) (imported : ExternalTarget)
    (arguments : List Word) : ExternalTailRouteKind -> Option Nat -> Prop where
  | direct
      (outcome : behavior.outcome = .externalJump imported arguments) :
      ExactOriginalImportedTailTransfer program point behavior imported arguments
        .directImport none
  | indirect
      (iatRva : Nat) (target : Word) (binding : ImportAddressPair)
      (outcome : behavior.outcome = .indirectJump target)
      (worldValid : CallableWorldValidity program.context point.world)
      (bindingMember : binding ∈ point.world.importAddresses)
      (bindingImport : binding.imported = imported)
      (bindingIat : binding.originalIatRva = iatRva)
      (bindingAddress : binding.originalAddress = target)
      (resolved : resolveWorldImportCall false program.context point.world target
        (normalizeImportReturnSlotState
          (behavior.nextMachineState point.state)) = some (imported, arguments)) :
      ExactOriginalImportedTailTransfer program point behavior imported arguments
        .iatIndirect (some iatRva)

theorem ExactOriginalImportedTailTransfer.indirectWorldValid
    (transfer : ExactOriginalImportedTailTransfer program point behavior imported
      arguments .iatIndirect (some iatRva)) :
    CallableWorldValidity program.context point.world := by
  cases transfer with
  | indirect _ _ _ _ worldValid _ _ _ _ _ => exact worldValid

/-- Exact decoded boundary immediately before the environment result is
applied. -/
structure ExactOriginalExternalTailBoundary
    (context : StaticProofContext)
    (program : DecodedWorldProgram)
    (spec : ExternalTailStaticPointerSlotSpec)
    (point : OriginalRunningPoint) where
  originalRole : program.candidate = false
  contextExact : program.context = context
  sourceTarget : point.targetId = spec.wrapperTargetId
  continuation : Nat
  outerCalls : List Nat
  callsExact : point.calls = continuation :: outerCalls
  continuationExact : continuation = spec.continuationTargetId
  behavior : RelationalBehavior
  behaviorExact : pe32WorldRegionBehaviorWithCalls program point.targetId
    point.state point.calls = some behavior
  arguments : List Word
  site : ExternalCallSiteContract
  contract : MachineImportCallContract
  siteMember : site ∈ program.externalCallSites
  siteId : site.id = spec.siteId
  siteSource : site.sourceTargetId = spec.wrapperTargetId
  siteContinuation : site.continuationTargetId = spec.continuationTargetId
  siteContract : site.machineContractId = spec.machineContractId
  siteResolved : resolveExternalCallSite context program.externalCallSites
    point.targetId continuation spec.imported = some site.id
  contractResolved : machineImportCallContractById? context
    site.machineContractId = some contract
  contractId : contract.id = spec.machineContractId
  contractImport : contract.imported = spec.imported
  contractArguments : contract.stackArgumentOffsets = spec.stackArgumentOffsets
  contractStackResult : contract.stackResultDelta = spec.stackResultDelta
  contractPreserved : contract.preservedRegisters = spec.preservedRegisters
  contractClobbered : contract.clobberedRegisters = spec.clobberedRegisters
  contractShape : contract.shapeValid = true
  transfer : ExactOriginalImportedTailTransfer program point behavior
    spec.imported arguments spec.routeKind spec.iatRva

def ExactOriginalExternalTailBoundary.boundaryState
    (boundary : ExactOriginalExternalTailBoundary context program spec point) :
    MachineState :=
  normalizeImportReturnSlotState
    (boundary.behavior.nextMachineState point.state)

def ExactOriginalExternalTailBoundary.event
    (boundary : ExactOriginalExternalTailBoundary context program spec point) :
    WorldExternalEvent := {
  siteId := boundary.site.id
  imported := boundary.contract.imported
  arguments := boundary.arguments
  state := boundary.boundaryState
  world := point.world
}

def ExactOriginalExternalTailBoundary.observation
    (boundary : ExactOriginalExternalTailBoundary context program spec point) :
    WorldRelationalObservable :=
  .external point.world boundary.contract.imported boundary.arguments

/-- The existing direct-call frame-copy witness is specialized to one checked
original slot.  The extra canonical-word equality is the exact caller argument
fact: it rules out using a merely related but wrong function pointer. -/
structure ExactFrameArgumentStaticPointerSlotWrite
    (context : StaticProofContext)
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (targetIds : List Nat) (targetId expectedValue : Nat)
    (frame : RelationalRuntimeCallFrame)
    (word : RuntimeFrameArgumentWord)
    (slot : StaticWordRelationSlotPair)
    (entryOriginal entryCandidate boundaryOriginal boundaryCandidate : Memory)
    (world : RelationalWorld) where
  allowedExact : certificate.allowedTargetIds = .exact targetIds
  targetMember : targetId ∈ targetIds
  canonicalWord : Nat
  canonical : targetCanonicalWord? originalContext targetId = some canonicalWord
  canonicalExact : canonicalWord = expectedValue
  wordRelation : word.relation = .fixedCodePointer targetId
  slotRelation : slot.relation = .fixedCodePointer targetId
  slotAddress : slot.originalAddress =
    BitVec.ofNat 32 (ReachableStaticPointerSlot.slotAddress originalContext certificate)
  argumentHolds : word.holds context world frame entryOriginal entryCandidate = true
  argumentCanonical : Memory.read32 entryOriginal
    (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset) =
      BitVec.ofNat 32 canonicalWord
  copied : RuntimeFrameArgumentStaticWrite word slot frame
    entryOriginal entryCandidate boundaryOriginal boundaryCandidate

theorem ExactFrameArgumentStaticPointerSlotWrite.staticRelationHolds
    (write : ExactFrameArgumentStaticPointerSlotWrite context originalContext
      certificate targetIds targetId expectedValue frame word slot entryOriginal
      entryCandidate boundaryOriginal boundaryCandidate world) :
    slot.memoryHolds context world boundaryOriginal boundaryCandidate = true := by
  exact write.copied.slotHolds write.argumentHolds

theorem ExactFrameArgumentStaticPointerSlotWrite.originalSlotAllowed
    (write : ExactFrameArgumentStaticPointerSlotWrite context originalContext
      certificate targetIds targetId expectedValue frame word slot entryOriginal
      entryCandidate boundaryOriginal boundaryCandidate world) :
    SlotValueAllowed originalContext certificate boundaryOriginal := by
  unfold SlotValueAllowed
  rw [write.allowedExact]
  rw [← write.slotAddress, write.copied.originalCopied, write.argumentCanonical]
  simp only [allowedWords, List.mem_cons]
  right
  apply List.mem_map.mpr
  refine ⟨write.canonicalWord, ?_, rfl⟩
  apply List.mem_filterMap.mpr
  exact ⟨targetId, write.targetMember, write.canonical⟩

theorem ExactFrameArgumentStaticPointerSlotWrite.originalSlotEqualsExpected
    (write : ExactFrameArgumentStaticPointerSlotWrite context originalContext
      certificate targetIds targetId expectedValue frame word slot entryOriginal
      entryCandidate boundaryOriginal boundaryCandidate world) :
    Memory.read32 boundaryOriginal
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate)) =
      BitVec.ofNat 32 expectedValue := by
  rw [← write.slotAddress, write.copied.originalCopied,
    write.argumentCanonical, write.canonicalExact]

/-- Complete authority for a returning framed external tail.  `candidateEvent`
is the one event emitted by the native side; its concrete transition remains a
separate candidate authority, while this object proves the decoded-original
macro and the shared external result contract. -/
structure CheckedExternalTailStaticPointerSlotReturn
    (context : StaticProofContext)
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (spec : ExternalTailStaticPointerSlotSpec) where
  staticAuthority : ExternalTailStaticPointerSlotStaticAuthority context
    originalContext certificate spec
  program : DecodedWorldProgram
  originalCarrier :
    StageA.Relational.InterpreterMixedOriginal.GeneratedOriginalFiniteCarrierBinding
      originalContext program
  source : OriginalRunningPoint
  boundaryPoint : OriginalRunningPoint
  frame : RelationalRuntimeCallFrame
  candidateSourceState : MachineState
  candidateEntryState : MachineState
  callEntry : ExactOriginalFramedDirectCallEntry context program spec source
    boundaryPoint frame candidateSourceState candidateEntryState
  boundary : ExactOriginalExternalTailBoundary context program spec boundaryPoint
  boundaryOuterCalls : boundary.outerCalls = source.calls
  contractReturns : boundary.contract.disposition = .returns
  argumentWord : RuntimeFrameArgumentWord
  argumentWordChecked : argumentWord.checked context = true
  argumentWordOriginalOffset :
    argumentWord.originalOffset = spec.originalFrameArgumentOffset
  argumentWordCandidateOffset :
    argumentWord.candidateOffset = spec.candidateFrameArgumentOffset
  staticSlot : StaticWordRelationSlotPair
  staticSlotMember : staticSlot ∈ context.staticWordRelationSlots
  candidateEvent : WorldExternalEvent
  frameWrite : ExactFrameArgumentStaticPointerSlotWrite context originalContext
    certificate staticAuthority.targetIds spec.slotTargetId spec.slotValue frame
    argumentWord staticSlot boundaryPoint.state.memory candidateEntryState.memory
    boundary.event.state.memory candidateEvent.state.memory boundaryPoint.world
  frameAtBoundary : frame.memoryHolds boundary.event.state.memory
    candidateEvent.state.memory
  candidateEnvironment : WorldExternalEnvironment
  candidateEventIndex : Nat
  sameEventIndex : boundaryPoint.eventIndex = candidateEventIndex
  boundaryRelated : ExternalCallBoundaryRelated context boundary.site
    boundary.contract boundary.event candidateEvent
  environmentsRefine : ExternalEnvironmentRefinesAt context boundary.site
    boundary.contract program.environment candidateEnvironment
  externalFootprintBounded :
    MachineCallMemoryEffectFootprintBounded boundary.contract.memoryEffect
  externalFootprintsAvoidSlot : ExternalWriteFootprintsAvoidWord
    boundary.contract.memoryFootprints boundary.event.state.memory
    boundary.event.arguments
    (BitVec.ofNat 32
      (ReachableStaticPointerSlot.slotAddress originalContext certificate))
  transitionExact : program.pe32TransitionSystem.step boundaryPoint.execution = {
    next := .running spec.continuationTargetId
      (program.environment.result boundaryPoint.eventIndex boundary.event).state
      source.calls (boundaryPoint.eventIndex + 1)
      (program.environment.result boundaryPoint.eventIndex boundary.event).world
    observation := some boundary.observation
  }

def CheckedExternalTailStaticPointerSlotReturn.originalResult
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) : WorldExternalResult :=
  checked.program.environment.result checked.boundaryPoint.eventIndex
    checked.boundary.event

def CheckedExternalTailStaticPointerSlotReturn.candidateResult
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) : WorldExternalResult :=
  checked.candidateEnvironment.result checked.candidateEventIndex
    checked.candidateEvent

def CheckedExternalTailStaticPointerSlotReturn.after
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) : WorldExecution :=
  .running spec.continuationTargetId checked.originalResult.state
    checked.source.calls (checked.boundaryPoint.eventIndex + 1)
    checked.originalResult.world

theorem CheckedExternalTailStaticPointerSlotReturn.resultsRelated
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    checked.originalResult.world = checked.candidateResult.world /\
      machineCallResultConforms false context checked.boundary.contract
        checked.boundary.event checked.originalResult /\
      machineCallResultConforms true context checked.boundary.contract
        checked.candidateEvent checked.candidateResult /\
      machineCallResultRegistersRelated context checked.originalResult.world
        checked.boundary.contract checked.boundary.event.arguments
        checked.originalResult.state checked.candidateResult.state = true /\
      StateRel context checked.originalResult.world
        checked.boundary.site.targetInvariant checked.originalResult.state
        checked.candidateResult.state /\
      ExternalRuntimeFramesPreserved checked.boundary.event checked.candidateEvent
        checked.originalResult checked.candidateResult := by
  have related := externalCallResultsRelated context checked.boundary.site
    checked.boundary.contract checked.program.environment
    checked.candidateEnvironment checked.environmentsRefine
    checked.contractReturns checked.candidateEventIndex
    checked.boundary.event checked.candidateEvent checked.boundaryRelated
  simpa [CheckedExternalTailStaticPointerSlotReturn.originalResult,
    CheckedExternalTailStaticPointerSlotReturn.candidateResult,
    checked.sameEventIndex] using related

theorem CheckedExternalTailStaticPointerSlotReturn.slotAllowedAtBoundary
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    SlotValueAllowed originalContext certificate
      checked.boundary.event.state.memory :=
  checked.frameWrite.originalSlotAllowed

theorem CheckedExternalTailStaticPointerSlotReturn.slotAllowedAfterExternal
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    SlotValueAllowed originalContext certificate
      checked.originalResult.state.memory := by
  have conforms := checked.resultsRelated.2.1
  exact machineCallResultConforms_preservesReachableStaticPointerSlot false
    context originalContext certificate checked.staticAuthority.targetIds
    checked.boundary.contract checked.boundary.event checked.originalResult
    checked.frameWrite.allowedExact conforms (.footprints checked.externalFootprintBounded
      checked.externalFootprintsAvoidSlot) checked.slotAllowedAtBoundary

theorem CheckedExternalTailStaticPointerSlotReturn.slotEqualsExpectedAtBoundary
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    Memory.read32 checked.boundary.event.state.memory
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate)) =
      BitVec.ofNat 32 spec.slotValue :=
  checked.frameWrite.originalSlotEqualsExpected

theorem CheckedExternalTailStaticPointerSlotReturn.callFrameAfterExternal
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    checked.frame.memoryHolds checked.originalResult.state.memory
      checked.candidateResult.state.memory := by
  have preserved := checked.resultsRelated.2.2.2.2.2 checked.frame
    ReturnSlotOffsetInventory.zero checked.frameAtBoundary
  apply (preserved ?_).1
  have emptyExactWords : ReturnSlotOffsetInventory.zero.exactWords = [] := rfl
  rw [ReturnSlotOffsetInventory.exactWordsHold, emptyExactWords]
  simp

theorem CheckedExternalTailStaticPointerSlotReturn.observationsRelated
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    worldRelationalObservationsRelated context
      (some checked.boundary.observation)
      (some (.external checked.candidateEvent.world
        checked.candidateEvent.imported checked.candidateEvent.arguments)) := by
  simp only [ExactOriginalExternalTailBoundary.observation,
    worldRelationalObservationsRelated]
  rcases checked.boundaryRelated with
    ⟨_originalSite, _candidateSite, worlds, originalImport, candidateImport,
      _states, arguments⟩
  exact ⟨worlds, originalImport.trans candidateImport.symm, arguments⟩

theorem CheckedExternalTailStaticPointerSlotReturn.worldExecutionPath
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) :
    NonemptyRelatedPath checked.program.pe32TransitionSystem
      checked.source.execution [checked.boundary.observation] checked.after := by
  have tail := nonemptyRelatedPath_one checked.program.pe32TransitionSystem
    checked.boundaryPoint.execution
  rw [checked.transitionExact] at tail
  simpa [CheckedExternalTailStaticPointerSlotReturn.after,
    CheckedExternalTailStaticPointerSlotReturn.originalResult] using
    checked.callEntry.path.trans tail

/-- A compact bundle consumed by mixed composition. -/
structure ExternalTailStaticPointerSlotReturnResult
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) : Prop where
  originalPath : NonemptyRelatedPath checked.program.pe32TransitionSystem
    checked.source.execution [checked.boundary.observation] checked.after
  observationsRelated : worldRelationalObservationsRelated context
    (some checked.boundary.observation)
    (some (.external checked.candidateEvent.world checked.candidateEvent.imported
      checked.candidateEvent.arguments))
  slotAtBoundary : SlotValueAllowed originalContext certificate
    checked.boundary.event.state.memory
  slotEqualsExpectedAtBoundary :
    Memory.read32 checked.boundary.event.state.memory
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate)) =
      BitVec.ofNat 32 spec.slotValue
  slotAfterExternal : SlotValueAllowed originalContext certificate
    checked.originalResult.state.memory
  resultWorldsRelated : checked.originalResult.world = checked.candidateResult.world
  continuationStateRelated : StateRel context checked.originalResult.world
    checked.boundary.site.targetInvariant checked.originalResult.state
    checked.candidateResult.state
  runtimeFramesPreserved : ExternalRuntimeFramesPreserved checked.boundary.event
    checked.candidateEvent checked.originalResult checked.candidateResult
  directCallFrameAtBoundary : checked.frame.memoryHolds
    checked.boundary.event.state.memory checked.candidateEvent.state.memory
  directCallFrameAfterExternal : checked.frame.memoryHolds
    checked.originalResult.state.memory checked.candidateResult.state.memory

def CheckedExternalTailStaticPointerSlotReturn.result
    (checked : CheckedExternalTailStaticPointerSlotReturn context originalContext
      certificate spec) : ExternalTailStaticPointerSlotReturnResult checked := {
  originalPath := checked.worldExecutionPath
  observationsRelated := checked.observationsRelated
  slotAtBoundary := checked.slotAllowedAtBoundary
  slotEqualsExpectedAtBoundary := checked.slotEqualsExpectedAtBoundary
  slotAfterExternal := checked.slotAllowedAfterExternal
  resultWorldsRelated := checked.resultsRelated.1
  continuationStateRelated := checked.resultsRelated.2.2.2.2.1
  runtimeFramesPreserved := checked.resultsRelated.2.2.2.2.2
  directCallFrameAtBoundary := checked.frameAtBoundary
  directCallFrameAfterExternal := checked.callFrameAfterExternal
}

/-- Terminating imports have no successor machine state to frame.  They still
require the exact framed call, exact decoded boundary, exact singleton
external observation, checked slot value at the boundary, and a related native
event.  Protocol and callback dispositions remain uninhabited. -/
structure CheckedExternalTailStaticPointerSlotTermination
    (context : StaticProofContext)
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (spec : ExternalTailStaticPointerSlotSpec) where
  staticAuthority : ExternalTailStaticPointerSlotStaticAuthority context
    originalContext certificate spec
  program : DecodedWorldProgram
  originalCarrier :
    StageA.Relational.InterpreterMixedOriginal.GeneratedOriginalFiniteCarrierBinding
      originalContext program
  source : OriginalRunningPoint
  boundaryPoint : OriginalRunningPoint
  frame : RelationalRuntimeCallFrame
  candidateSourceState : MachineState
  candidateEntryState : MachineState
  callEntry : ExactOriginalFramedDirectCallEntry context program spec source
    boundaryPoint frame candidateSourceState candidateEntryState
  boundary : ExactOriginalExternalTailBoundary context program spec boundaryPoint
  boundaryOuterCalls : boundary.outerCalls = source.calls
  dispositionTerminates : boundary.contract.disposition = .terminates
  argumentWord : RuntimeFrameArgumentWord
  argumentWordChecked : argumentWord.checked context = true
  argumentWordOriginalOffset :
    argumentWord.originalOffset = spec.originalFrameArgumentOffset
  argumentWordCandidateOffset :
    argumentWord.candidateOffset = spec.candidateFrameArgumentOffset
  staticSlot : StaticWordRelationSlotPair
  staticSlotMember : staticSlot ∈ context.staticWordRelationSlots
  candidateEvent : WorldExternalEvent
  frameWrite : ExactFrameArgumentStaticPointerSlotWrite context originalContext
    certificate staticAuthority.targetIds spec.slotTargetId spec.slotValue frame
    argumentWord staticSlot boundaryPoint.state.memory candidateEntryState.memory
    boundary.event.state.memory candidateEvent.state.memory boundaryPoint.world
  frameAtBoundary : frame.memoryHolds boundary.event.state.memory
    candidateEvent.state.memory
  candidateEventIndex : Nat
  sameEventIndex : boundaryPoint.eventIndex = candidateEventIndex
  boundaryRelated : ExternalCallBoundaryRelated context boundary.site
    boundary.contract boundary.event candidateEvent
  transitionExact : program.pe32TransitionSystem.step boundaryPoint.execution = {
    next := .terminated boundaryPoint.world
    observation := some boundary.observation
  }

theorem CheckedExternalTailStaticPointerSlotTermination.slotAllowedAtBoundary
    (checked : CheckedExternalTailStaticPointerSlotTermination context originalContext
      certificate spec) :
    SlotValueAllowed originalContext certificate
      checked.boundary.event.state.memory :=
  checked.frameWrite.originalSlotAllowed

theorem CheckedExternalTailStaticPointerSlotTermination.slotEqualsExpectedAtBoundary
    (checked : CheckedExternalTailStaticPointerSlotTermination context originalContext
      certificate spec) :
    Memory.read32 checked.boundary.event.state.memory
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate)) =
      BitVec.ofNat 32 spec.slotValue :=
  checked.frameWrite.originalSlotEqualsExpected

theorem CheckedExternalTailStaticPointerSlotTermination.observationsRelated
    (checked : CheckedExternalTailStaticPointerSlotTermination context originalContext
      certificate spec) :
    worldRelationalObservationsRelated context
      (some checked.boundary.observation)
      (some (.external checked.candidateEvent.world checked.candidateEvent.imported
        checked.candidateEvent.arguments)) := by
  simp only [ExactOriginalExternalTailBoundary.observation,
    worldRelationalObservationsRelated]
  rcases checked.boundaryRelated with
    ⟨_originalSite, _candidateSite, worlds, originalImport, candidateImport,
      _states, arguments⟩
  exact ⟨worlds, originalImport.trans candidateImport.symm, arguments⟩

theorem CheckedExternalTailStaticPointerSlotTermination.terminationWorldRelated
    (checked : CheckedExternalTailStaticPointerSlotTermination context originalContext
      certificate spec) :
    checked.boundaryPoint.world = checked.candidateEvent.world := by
  exact checked.boundaryRelated.2.2.1

theorem CheckedExternalTailStaticPointerSlotTermination.worldExecutionPath
    (checked : CheckedExternalTailStaticPointerSlotTermination context originalContext
      certificate spec) :
    NonemptyRelatedPath checked.program.pe32TransitionSystem
      checked.source.execution [checked.boundary.observation]
      (.terminated checked.boundaryPoint.world) := by
  have tail := nonemptyRelatedPath_one checked.program.pe32TransitionSystem
    checked.boundaryPoint.execution
  rw [checked.transitionExact] at tail
  simpa using checked.callEntry.path.trans tail

/-- The returning authority cannot be built for a protocol contract. -/
theorem noReturningAuthority_of_protocol
    (protocol : specDisposition = MachineCallDisposition.protocol)
    (returns : specDisposition = MachineCallDisposition.returns) : False := by
  rw [protocol] at returns
  cases returns

/-- The terminating authority likewise excludes nested callback protocols. -/
theorem noTerminatingAuthority_of_protocol
    (protocol : specDisposition = MachineCallDisposition.protocol)
    (terminates : specDisposition = MachineCallDisposition.terminates) : False := by
  rw [protocol] at terminates
  cases terminates

#print axioms ExactOriginalFramedDirectCallEntry.path
#print axioms ExactFrameArgumentStaticPointerSlotWrite.staticRelationHolds
#print axioms ExactFrameArgumentStaticPointerSlotWrite.originalSlotAllowed
#print axioms CheckedExternalTailStaticPointerSlotReturn.resultsRelated
#print axioms CheckedExternalTailStaticPointerSlotReturn.slotAllowedAfterExternal
#print axioms CheckedExternalTailStaticPointerSlotReturn.callFrameAfterExternal
#print axioms CheckedExternalTailStaticPointerSlotReturn.worldExecutionPath
#print axioms CheckedExternalTailStaticPointerSlotReturn.result
#print axioms CheckedExternalTailStaticPointerSlotTermination.worldExecutionPath

end StageA.Relational.ExternalTailStaticPointerSlotComposition
