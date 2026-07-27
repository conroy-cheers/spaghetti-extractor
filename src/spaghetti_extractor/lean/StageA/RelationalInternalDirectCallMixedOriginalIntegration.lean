import StageA.RelationalInternalDirectCallComposition
import StageA.RelationalRegisterControlProvenance

namespace StageA.Relational.InternalDirectCallMixedOriginalIntegration

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition

abbrev RegisterControlRegister :=
  StageA.Relational.RegisterControlProvenance.X86Register
abbrev RegisterControlPair :=
  StageA.Relational.RegisterControlProvenance.RegisterPair
abbrev RegisterControlEdge :=
  StageA.Relational.RegisterControlProvenance.RegionEdge
abbrev RegisterControlCallContract :=
  StageA.Relational.RegisterControlProvenance.CallContract

def registerControlRegister : Reg -> RegisterControlRegister
  | .eax => .eax
  | .ebx => .ebx
  | .ecx => .ecx
  | .edx => .edx
  | .esi => .esi
  | .edi => .edi
  | .ebp => .ebp
  | .esp => .esp

def registerControlPair (register : Reg) : RegisterControlPair := {
  original := registerControlRegister register
  candidate := registerControlRegister register
}

/-- Concrete execution of the exact decoded direct-call entry segment.  This
object names the callee-entry states consumed by the semantic summary, rather
than treating the structural call edge as an execution theorem. -/
structure ExactDirectCallEntryExecution
    {context : StaticProofContext}
    (provenance : CheckedDirectCallSummaryProvenance context)
    (world : RelationalWorld)
    (sourceOriginal sourceCandidate entryOriginal entryCandidate : MachineState)
    (frame : RelationalRuntimeCallFrame) where
  sourceRelated : StateRel context world
    provenance.premises.callEntry.sourceInvariant sourceOriginal sourceCandidate
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalResult : RelationalBehavior
  candidateResult : RelationalBehavior
  originalDecoded :
    regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
      context.machineImportCallContracts provenance.tree.certificate.callsite.original =
        some originalBehavior
  candidateDecoded :
    regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
      context.machineImportCallContracts provenance.tree.certificate.callsite.candidate =
        some candidateBehavior
  originalEvaluated :
    evalBehavior false context.codeMap.entries.toList sourceOriginal originalBehavior =
      some originalResult
  candidateEvaluated :
    evalBehavior true context.codeMap.entries.toList sourceCandidate candidateBehavior =
      some candidateResult
  runtimeFrame : provenance.premises.callEntry.callPush.runtimeFrame context
    sourceOriginal sourceCandidate = some frame
  frameValid : frame.valid context = true
  frameMemory : frame.memoryHolds
    (originalResult.nextMachineState sourceOriginal).memory
    (candidateResult.nextMachineState sourceCandidate).memory
  originalEntry : entryOriginal = originalResult.nextMachineState sourceOriginal
  candidateEntry : entryCandidate = candidateResult.nextMachineState sourceCandidate
  entryRelated : StateRel context world provenance.premises.callEntry.entryInvariant
    entryOriginal entryCandidate

def CallEntryRegistersPreserved
    {context : StaticProofContext}
    (provenance : CheckedDirectCallSummaryProvenance context)
    (registers : List Reg) : Prop :=
  forall register, register ∈ registers ->
    forall world sourceOriginal sourceCandidate entryOriginal entryCandidate frame,
      ExactDirectCallEntryExecution provenance world sourceOriginal sourceCandidate
          entryOriginal entryCandidate frame ->
        entryOriginal.registers.get register = sourceOriginal.registers.get register /\
          entryCandidate.registers.get register = sourceCandidate.registers.get register

/-- Register-control authority for an exact internal call-return edge.  Unlike
the complete callee contract below, this object is intentionally conditional
on an exact returning execution.  It is therefore sufficient for propagating
a value across a call-return edge without claiming that every invocation
terminates. -/
structure CheckedDirectCallRegisterControlContract (context : StaticProofContext) where
  tree : SummaryTree
  returning : CheckedReturningRegisterCertificate context tree
  edge : RegisterControlEdge
  contract : RegisterControlCallContract
  requestedRegisters : List Reg
  sourceInvariant : StateInvariant
  sourceTargetId : Nat
  continuationTargetId : Nat
  edgeKind : edge.kind = .callReturn
  edgeSource : edge.sourceRegion = sourceTargetId
  edgeTarget : edge.targetRegion = continuationTargetId
  sourceMapped : exists target,
    context.codeMap.get? sourceTargetId = some target /\
      target.originalRva = tree.certificate.callsite.original.start /\
      target.candidateRva = tree.certificate.callsite.candidate.start
  continuationMapped : exists target,
    context.codeMap.get? continuationTargetId = some target /\
      target.originalRva = tree.certificate.continuation.original.start /\
      target.candidateRva = tree.certificate.continuation.candidate.start
  edgeContract : edge.machineContractId = some contract.contractId
  noImportResults : contract.importResults = []
  preservedRegistersExact :
    contract.preservedRegisters = requestedRegisters.map registerControlPair
  requestedRegistersExact : requestedRegisters = returning.registers

/-- Caller-frame dataflow authority for an exact internal call-return edge.
Like the register-control authority, this is conditional on an admitted finite
return and does not assert total call progress. -/
structure CheckedDirectCallCallerFrameWordControlContract
    (context : StaticProofContext) where
  tree : SummaryTree
  returning : CheckedReturningCallerFrameWordCertificate context tree
  returningStackPointer : CheckedReturningStackPointerCertificate context tree
  edge : RegisterControlEdge
  originalBehavior : NormalizedSymbolicBehavior
  candidateBehavior : NormalizedSymbolicBehavior
  behaviorsExact : directCallNormalizedBehaviors? context tree =
    some (originalBehavior, candidateBehavior)
  entryClaims : List CallerFrameWordEntryClaim
  entryClaimsChecked : entryClaims.all (fun claim =>
    claim.checked originalBehavior candidateBehavior) = true
  requestedWords : List ReturnSlotExactWordPair
  sourceTargetId : Nat
  continuationTargetId : Nat
  edgeKind : edge.kind = .callReturn
  edgeSource : edge.sourceRegion = sourceTargetId
  edgeTarget : edge.targetRegion = continuationTargetId
  sourceMapped : exists target,
    context.codeMap.get? sourceTargetId = some target /\
      target.originalRva = tree.certificate.callsite.original.start /\
      target.candidateRva = tree.certificate.callsite.candidate.start
  continuationMapped : exists target,
    context.codeMap.get? continuationTargetId = some target /\
      target.originalRva = tree.certificate.continuation.original.start /\
      target.candidateRva = tree.certificate.continuation.candidate.start
  requestedWordsExact : requestedWords = entryClaims.map (·.source)
  entryWordsExact : returning.words = entryClaims.map (·.entry)
  entryOffsetsRestore : forall claim, claim ∈ entryClaims ->
    BitVec.ofNat 32 claim.entry.originalOffset =
        BitVec.ofNat 32 4 + BitVec.ofNat 32 claim.source.originalOffset /\
      BitVec.ofNat 32 claim.entry.candidateOffset =
        BitVec.ofNat 32 4 + BitVec.ofNat 32 claim.source.candidateOffset

/-- Checked entry authority for the initial singleton finite-origin indirect
call profile.  The Boolean checker binds the exact source and continuation,
the selected code-map target, both decoded indirect-call outcomes, and the
value-provenance certificate.  Authorities with more than one destination
remain incomplete until the target-indexed bundle checker is available. -/
structure CheckedFiniteOriginCallEntryAuthority
    (context : StaticProofContext) where
  tree : SummaryTree
  sourceInvariant : StateInvariant
  originalBehavior : NormalizedSymbolicBehavior
  candidateBehavior : NormalizedSymbolicBehavior
  authority : ValueProvenance.CheckedIndirectExitCertificate context
    sourceInvariant originalBehavior candidateBehavior
  sourceTargetId : Nat
  calleeTargetId : Nat
  continuationTargetId : Nat
  structuralChecked : tree.checked context.originalPe context.candidatePe
    context.originalImports context.candidateImports = true
  authorityChecked :
    tree.certificate.finiteOriginCallEntryAuthorityChecked sourceTargetId
      calleeTargetId continuationTargetId authority context.originalPe
      context.candidatePe context.originalImports context.candidateImports = true

/-- Constructor with inferred semantic indices.  Generated modules name the
checked indirect-exit authority but do not duplicate its source invariant or
normalized behaviors merely to satisfy dependent structure fields. -/
def checkedFiniteOriginCallEntryAuthority_of_checked
    (context : StaticProofContext) (tree : SummaryTree)
    {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (sourceTargetId calleeTargetId continuationTargetId : Nat)
    (structuralChecked : tree.checked context.originalPe context.candidatePe
      context.originalImports context.candidateImports = true)
    (authorityChecked :
      tree.certificate.finiteOriginCallEntryAuthorityChecked sourceTargetId
        calleeTargetId continuationTargetId authority context.originalPe
        context.candidatePe context.originalImports context.candidateImports =
          true) :
    CheckedFiniteOriginCallEntryAuthority context := {
  tree
  sourceInvariant
  originalBehavior
  candidateBehavior
  authority
  sourceTargetId
  calleeTargetId
  continuationTargetId
  structuralChecked
  authorityChecked
}

/-- Register-control contract for a returning finite-origin internal call.
Like the direct-call contract, this proves preservation only for executions
which actually return.  Whole-program progress remains a graph obligation. -/
structure CheckedFiniteOriginCallRegisterControlContract
    (context : StaticProofContext) where
  entry : CheckedFiniteOriginCallEntryAuthority context
  returning : CheckedReturningRegisterCertificate context entry.tree
  edge : RegisterControlEdge
  contract : RegisterControlCallContract
  requestedRegisters : List Reg
  sourceInvariant : StateInvariant
  sourceInvariantExact : sourceInvariant = entry.sourceInvariant
  edgeKind : edge.kind = .callReturn
  edgeSource : edge.sourceRegion = entry.sourceTargetId
  edgeTarget : edge.targetRegion = entry.continuationTargetId
  edgeContract : edge.machineContractId = some contract.contractId
  noImportResults : contract.importResults = []
  preservedRegistersExact :
    contract.preservedRegisters = requestedRegisters.map registerControlPair
  requestedRegistersExact : requestedRegisters = returning.registers
  targetRegister : Reg
  targetRegisterRequested : targetRegister ∈ requestedRegisters
  /-- A finite-origin call may compute its indirect target before entering the
  callee.  This check records that the selected target expression is also the
  value left in the register whose provenance crosses the return edge. -/
  targetRegisterOutputChecked :
    (entry.originalBehavior.registers.get targetRegister ==
        entry.authority.certificate.target.original) &&
      (entry.candidateBehavior.registers.get targetRegister ==
        entry.authority.certificate.target.candidate) = true

/-- Caller-frame dataflow contract for a returning finite-origin internal call.
The indirect-entry authority supplies the checked target provenance; this
contract adds only the callee's same-side preservation of explicitly requested
caller-owned words. -/
structure CheckedFiniteOriginCallCallerFrameWordControlContract
    (context : StaticProofContext) where
  entry : CheckedFiniteOriginCallEntryAuthority context
  returning : CheckedReturningCallerFrameWordCertificate context entry.tree
  returningStackPointer :
    CheckedReturningStackPointerCertificate context entry.tree
  edge : RegisterControlEdge
  entryClaims : List CallerFrameWordEntryClaim
  entryClaimsChecked : entryClaims.all (fun claim =>
    claim.checked entry.originalBehavior entry.candidateBehavior) = true
  requestedWords : List ReturnSlotExactWordPair
  edgeKind : edge.kind = .callReturn
  edgeSource : edge.sourceRegion = entry.sourceTargetId
  edgeTarget : edge.targetRegion = entry.continuationTargetId
  requestedWordsExact : requestedWords = entryClaims.map (·.source)
  entryWordsExact : returning.words = entryClaims.map (·.entry)
  entryOffsetsRestore : forall claim, claim ∈ entryClaims ->
    BitVec.ofNat 32 claim.entry.originalOffset =
        BitVec.ofNat 32 4 + BitVec.ofNat 32 claim.source.originalOffset /\
      BitVec.ofNat 32 claim.entry.candidateOffset =
        BitVec.ofNat 32 4 + BitVec.ofNat 32 claim.source.candidateOffset

/-- The older complete authority remains available for nested semantic calls,
frame postconditions, and static writes.  It additionally proves total
call-to-return execution and is deliberately not required for register-only
control provenance. -/
structure CheckedCompleteDirectCallRegisterControlContract
    (context : StaticProofContext) where
  provenance : CheckedDirectCallSummaryProvenance context
  edge : RegisterControlEdge
  contract : RegisterControlCallContract
  requestedRegisters : List Reg
  sourceInvariant : StateInvariant
  sourceInvariantExact :
    sourceInvariant = provenance.premises.callEntry.sourceInvariant
  edgeKind : edge.kind = .callReturn
  edgeSource : edge.sourceRegion = provenance.premises.callEntry.sourceTargetId
  edgeTarget :
    edge.targetRegion = provenance.premises.callEntry.continuationTargetId
  edgeContract : edge.machineContractId = some contract.contractId
  noImportResults : contract.importResults = []
  preservedRegistersExact :
    contract.preservedRegisters = requestedRegisters.map registerControlPair
  requestedRegistersUnique : requestedRegisters.Nodup
  requestedRegistersExcludeStackPointer : .esp ∉ requestedRegisters
  requestedBySummary : forall register, register ∈ requestedRegisters ->
    register ∈ provenance.tree.certificate.requestedRegisters
  callEntryPreserved : CallEntryRegistersPreserved provenance requestedRegisters

/-- One acceptance-facing package for a finite internal direct call.  The
operational path is obtained from `IntegratedSummaryPremises`; it cannot be
replaced by a Python completion flag.  `staticWrite` is quantified over every
actual invocation admitted by those premises, so a concrete trace is not
sufficient to inhabit this structure. -/
structure CheckedDirectCallFiniteEvidence (context : StaticProofContext) where
  authority : CheckedCompleteDirectCallRegisterControlContract context
  argumentWord : RuntimeFrameArgumentWord
  argumentWordMember : argumentWord ∈
    authority.provenance.premises.callEntry.argumentWords
  staticSlot : StaticWordRelationSlotPair
  staticSlotMember : staticSlot ∈ context.staticWordRelationSlots
  sameRelation : argumentWord.relation = staticSlot.relation
  staticWrite : forall actual : ActualDirectCallReturnExecution context
      authority.provenance.tree
      authority.provenance.premises.callEntry
      authority.provenance.premises.operational.originalProgram
      authority.provenance.premises.operational.candidateProgram,
    RuntimeFrameArgumentStaticWrite argumentWord staticSlot actual.frame
      actual.originalEntry.state.memory actual.candidateEntry.state.memory
      actual.originalExit.state.memory actual.candidateExit.state.memory

def CheckedDirectCallFiniteEvidence.entry
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context) :
    ExactDirectCallEntryBinding context evidence.authority.provenance.tree :=
  evidence.authority.provenance.premises.callEntry

def CheckedDirectCallFiniteEvidence.operational
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context) :
    OperationalCallReturnCompleteness context evidence.authority.provenance.tree
      evidence.entry :=
  evidence.authority.provenance.premises.operational

def CheckedDirectCallFiniteEvidence.executionForSource
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context)
    (source : RelatedDirectCallSource context evidence.authority.provenance.tree
      evidence.entry) :
    CheckedFiniteCallRegionExecution context evidence.authority.provenance.tree
      evidence.entry evidence.operational.originalProgram
      evidence.operational.candidateProgram source
      (evidence.operational.entryForSource source) :=
  evidence.operational.executionForSource source

/-- The finite returning execution is derived by the canonical classifier and
ranking.  No caller may submit it independently. -/
noncomputable def CheckedDirectCallFiniteEvidence.finiteReturningExecutionForSource
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context)
    (source : RelatedDirectCallSource context evidence.authority.provenance.tree
      evidence.entry) :
    FiniteReturningExecution context evidence.authority.provenance.tree
      (evidence.operational.entryForSource source).point.cursor :=
  ((evidence.executionForSource source).returns
    (evidence.operational.entryForSource source).point .entry).finiteExecution

theorem CheckedDirectCallFiniteEvidence.argumentToStaticSlot
    {context : StaticProofContext}
    (evidence : CheckedDirectCallFiniteEvidence context)
    (actual : ActualDirectCallReturnExecution context
      evidence.authority.provenance.tree evidence.entry
      evidence.operational.originalProgram evidence.operational.candidateProgram) :
    evidence.argumentWord.holds context actual.source.original.world actual.frame
          actual.originalEntry.state.memory actual.candidateEntry.state.memory = true /\
      evidence.staticSlot.memoryHolds context actual.source.original.world
          actual.originalExit.state.memory actual.candidateExit.state.memory = true :=
  actualDirectCallReturn_argumentToStaticSlot
    evidence.authority.provenance.premises actual evidence.argumentWord
    evidence.argumentWordMember evidence.staticSlot evidence.staticSlotMember
    (evidence.staticWrite actual)

structure CheckedCompleteDirectCallReturnExecution
    {context : StaticProofContext}
    (binding : CheckedCompleteDirectCallRegisterControlContract context)
    (sourceOriginal sourceCandidate entryOriginal entryCandidate
      exitOriginal exitCandidate : MachineState)
    (world : RelationalWorld) (frame : RelationalRuntimeCallFrame) where
  entry : ExactDirectCallEntryExecution binding.provenance world
    sourceOriginal sourceCandidate entryOriginal entryCandidate frame
  invoked : binding.provenance.contract.invocation entryOriginal entryCandidate
    exitOriginal exitCandidate world frame

/-- One exact operational invocation of a checked finite-origin call.  The
value-provenance match selects the singleton callee, while the canonical world
transition and call stack bind the selected summary to executable PE bytes. -/
structure ActualFiniteOriginCallReturnExecution
    {context : StaticProofContext}
    (binding : CheckedFiniteOriginCallEntryAuthority context)
    (originalProgram candidateProgram : DecodedWorldProgram) where
  sourceOriginal : WorldExecutionPoint
  sourceCandidate : WorldExecutionPoint
  originalEntry : WorldExecutionPoint
  candidateEntry : WorldExecutionPoint
  originalExit : WorldExecutionPoint
  candidateExit : WorldExecutionPoint
  sourceTargets :
    sourceOriginal.targetId = binding.sourceTargetId /\
      sourceCandidate.targetId = binding.sourceTargetId
  sharedWorld : sourceOriginal.world = sourceCandidate.world
  sourceRelated : StateRel context sourceOriginal.world binding.sourceInvariant
    sourceOriginal.state sourceCandidate.state
  selectedTarget :
    (ValueProvenance.IndirectDestination.internalCode
      binding.calleeTargetId).Matches context sourceOriginal.world
        (binding.authority.certificate.target.original.eval sourceOriginal.state)
        (binding.authority.certificate.target.candidate.eval sourceCandidate.state)
  originalCallStep : originalProgram.pe32TransitionSystem.step
    sourceOriginal.execution = {
      next := originalEntry.execution
      observation := none
    }
  candidateCallStep : candidateProgram.pe32TransitionSystem.step
    sourceCandidate.execution = {
      next := candidateEntry.execution
      observation := none
    }
  entryTargets :
    originalEntry.targetId = binding.calleeTargetId /\
      candidateEntry.targetId = binding.calleeTargetId
  exitTargets :
    originalExit.targetId = binding.continuationTargetId /\
      candidateExit.targetId = binding.continuationTargetId
  entryCalls :
    originalEntry.calls =
        binding.continuationTargetId :: sourceOriginal.calls /\
      candidateEntry.calls =
        binding.continuationTargetId :: sourceCandidate.calls
  exitCalls :
    originalExit.calls = sourceOriginal.calls /\
      candidateExit.calls = sourceCandidate.calls
  entryWorld :
    originalEntry.world = sourceOriginal.world /\
      candidateEntry.world = sourceOriginal.world
  exitWorld :
    originalExit.world = sourceOriginal.world /\
      candidateExit.world = sourceOriginal.world
  /-- The operational call step is tied to the exact normalized behavior
  checked by the finite-origin entry authority.  This is intentionally not a
  source-register identity claim: the callsite may compute the target
  register before entering the callee. -/
  entryStates :
    originalEntry.state =
        ((binding.originalBehavior.eval sourceOriginal.state).nextMachineState
          sourceOriginal.state) /\
      candidateEntry.state =
        ((binding.candidateBehavior.eval sourceCandidate.state).nextMachineState
          sourceCandidate.state)
  finiteExecution : FiniteReturningExecution context binding.tree {
    regionId := binding.tree.certificate.calleeEntry.id
    original := originalEntry.state
    candidate := candidateEntry.state
    world := sourceOriginal.world
  }
  finiteOriginalExitExact :
    finiteExecution.returning.afterOriginal = originalExit.state
  finiteCandidateExitExact :
    finiteExecution.returning.afterCandidate = candidateExit.state

def requestedRegisterPreserved
    (register : Reg)
    (sourceOriginal sourceCandidate exitOriginal exitCandidate : MachineState) : Prop :=
  exitOriginal.registers.get register = sourceOriginal.registers.get register /\
    exitCandidate.registers.get register = sourceCandidate.registers.get register

def requestedRegisterPreservedFromEntry
    (register : Reg)
    (entryOriginal entryCandidate exitOriginal exitCandidate : MachineState) : Prop :=
  exitOriginal.registers.get register = entryOriginal.registers.get register /\
    exitCandidate.registers.get register = entryCandidate.registers.get register

/-- Semantic consequence consumed by the mixed-original provenance adapter.
It composes exact call-entry execution with the checked callee summary and
produces precisely the source-to-continuation register relation represented by
the abstract `callReturn` edge. -/
theorem CheckedCompleteDirectCallRegisterControlContract.preserves
    {context : StaticProofContext}
    {binding : CheckedCompleteDirectCallRegisterControlContract context}
    {sourceOriginal sourceCandidate entryOriginal entryCandidate
      exitOriginal exitCandidate : MachineState}
    {world : RelationalWorld} {frame : RelationalRuntimeCallFrame}
    (execution : CheckedCompleteDirectCallReturnExecution binding sourceOriginal
      sourceCandidate entryOriginal entryCandidate exitOriginal exitCandidate
      world frame)
    (register : Reg) (member : register ∈ binding.requestedRegisters) :
    requestedRegisterPreserved register sourceOriginal sourceCandidate
      exitOriginal exitCandidate := by
  have entryPreserved := binding.callEntryPreserved register member _ _ _ _ _ _
    execution.entry
  have summaryPreserved := binding.provenance.contract.preserves
    entryOriginal entryCandidate exitOriginal exitCandidate world frame
    execution.invoked register (binding.requestedBySummary register member)
  exact ⟨summaryPreserved.1.trans entryPreserved.1,
    summaryPreserved.2.trans entryPreserved.2⟩

/-- Conditional preservation theorem consumed by the mixed-original
register-control analysis.  The execution is exact and byte-bound, but no
total-termination premise is needed: reaching the continuation already
supplies the finite returning execution whose register effects are checked. -/
theorem CheckedDirectCallRegisterControlContract.preserves
    {context : StaticProofContext}
    (binding : CheckedDirectCallRegisterControlContract context)
    {entryBinding : ExactDirectCallEntryBinding context binding.tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context binding.tree entryBinding
      originalProgram candidateProgram)
    (register : Reg) (member : register ∈ binding.requestedRegisters) :
    requestedRegisterPreserved register actual.source.original.state
      actual.source.candidate.state actual.originalExit.state
      actual.candidateExit.state := by
  have certificateMember : register ∈ binding.returning.registers := by
    rw [← binding.requestedRegistersExact]
    exact member
  let lifted := actual.finite
  have returned := binding.returning.preserves actual.entryCursor rfl
    lifted.execution register certificateMember
  rw [lifted.originalExitExact, lifted.candidateExitExact] at returned
  have requested := binding.returning.requestedBySummary register certificateMember
  have entry := actual.entryRegisters register requested
  have registerNotEsp : register ≠ .esp := by
    intro equal
    apply binding.returning.registersExcludeStackPointer
    simpa [← equal] using certificateMember
  have registerNotEspBool : (register == .esp) = false :=
    beq_eq_false_iff_ne.mpr registerNotEsp
  simp only [callEntryRegistersHold, registerNotEspBool, if_false] at entry
  exact ⟨returned.1.trans entry.1, returned.2.trans entry.2⟩

/-- Caller-relative word preservation for an ordinary exact direct call. The
contract and operational entry binding are independently tied to the same
decoded normalized callsite, so their behaviors agree by constructor
injectivity rather than by a submitted compatibility flag. -/
theorem CheckedDirectCallCallerFrameWordControlContract.preserves
    {context : StaticProofContext}
    (binding : CheckedDirectCallCallerFrameWordControlContract context)
    {entryBinding : ExactDirectCallEntryBinding context binding.tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context binding.tree entryBinding
      originalProgram candidateProgram)
    (word : ReturnSlotExactWordPair)
    (member : word ∈ binding.requestedWords) :
    Memory.read32 actual.originalExit.state.memory
          (actual.originalExit.state.registers.esp +
            BitVec.ofNat 32 word.originalOffset) =
        Memory.read32 actual.source.original.state.memory
          (actual.source.original.state.registers.esp +
            BitVec.ofNat 32 word.originalOffset) /\
      Memory.read32 actual.candidateExit.state.memory
          (actual.candidateExit.state.registers.esp +
            BitVec.ofNat 32 word.candidateOffset) =
        Memory.read32 actual.source.candidate.state.memory
          (actual.source.candidate.state.registers.esp +
            BitVec.ofNat 32 word.candidateOffset) := by
  have behaviorOption := binding.behaviorsExact
  rw [entryBinding.normalizedExact] at behaviorOption
  have behaviorPair :
      (entryBinding.originalNormalized, entryBinding.candidateNormalized) =
        (binding.originalBehavior, binding.candidateBehavior) :=
    Option.some.inj behaviorOption
  have originalBehaviorExact :
      entryBinding.originalNormalized = binding.originalBehavior := by
    simpa using congrArg Prod.fst behaviorPair
  have candidateBehaviorExact :
      entryBinding.candidateNormalized = binding.candidateBehavior := by
    simpa using congrArg Prod.snd behaviorPair
  have mappedMember : word ∈ binding.entryClaims.map (·.source) := by
    rw [← binding.requestedWordsExact]
    exact member
  rcases List.mem_map.mp mappedMember with ⟨claim, claimMember, sourceExact⟩
  subst word
  have claimChecked :=
    List.all_eq_true.mp binding.entryClaimsChecked claim claimMember
  have entered := claim.memoryPreserved_of_checked binding.originalBehavior
    binding.candidateBehavior actual.source.original.state
      actual.source.candidate.state claimChecked
  rw [← originalBehaviorExact, ← candidateBehaviorExact] at entered
  rw [← actual.entryStates.1, ← actual.entryStates.2] at entered
  have entryMember : claim.entry ∈ binding.returning.words := by
    rw [binding.entryWordsExact]
    exact List.mem_map_of_mem claimMember
  have returned := binding.returning.preserves actual.entryCursor rfl
    actual.finite.execution claim.entry entryMember
  rw [actual.finite.originalExitExact, actual.finite.candidateExitExact] at returned
  simp only [ActualDirectCallReturnExecution.entryCursor] at returned
  have restored := binding.returningStackPointer.restores actual.entryCursor rfl
    actual.finite.execution
  rw [actual.finite.originalExitExact, actual.finite.candidateExitExact] at restored
  simp only [ActualDirectCallReturnExecution.entryCursor] at restored
  have offsets := binding.entryOffsetsRestore claim claimMember
  have originalAddress :
      actual.originalExit.state.registers.esp +
          BitVec.ofNat 32 claim.source.originalOffset =
        actual.originalEntry.state.registers.esp +
          BitVec.ofNat 32 claim.entry.originalOffset := by
    rw [restored.1, offsets.1]
    simp only [BitVec.add_assoc]
  have candidateAddress :
      actual.candidateExit.state.registers.esp +
          BitVec.ofNat 32 claim.source.candidateOffset =
        actual.candidateEntry.state.registers.esp +
          BitVec.ofNat 32 claim.entry.candidateOffset := by
    rw [restored.2, offsets.2]
    simp only [BitVec.add_assoc]
  constructor
  · rw [originalAddress, returned.1, entered.1]
  · rw [candidateAddress, returned.2, entered.2]

/-- The returning summary proves preservation from callee entry to callee
exit.  It deliberately says nothing about equality with the caller source
state, because a finite-origin callsite may compute the target register before
the architectural call transition. -/
theorem CheckedFiniteOriginCallRegisterControlContract.calleePreserves
    {context : StaticProofContext}
    (binding : CheckedFiniteOriginCallRegisterControlContract context)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution binding.entry
      originalProgram candidateProgram)
    (register : Reg) (member : register ∈ binding.requestedRegisters) :
    requestedRegisterPreservedFromEntry register actual.originalEntry.state
      actual.candidateEntry.state actual.originalExit.state
      actual.candidateExit.state := by
  have certificateMember : register ∈ binding.returning.registers := by
    rw [← binding.requestedRegistersExact]
    exact member
  have returned := binding.returning.preserves
    {
      regionId := binding.entry.tree.certificate.calleeEntry.id
      original := actual.originalEntry.state
      candidate := actual.candidateEntry.state
      world := actual.sourceOriginal.world
    }
    rfl actual.finiteExecution register certificateMember
  rw [actual.finiteOriginalExitExact, actual.finiteCandidateExitExact] at returned
  exact returned

/-- The checked callsite output and callee preservation compose to carry the
finite target's value origin to the continuation.  This is the semantic fact
needed by register-to-stack and later indirect-call provenance; it does not
misstate the target register as equal to its caller-source value. -/
theorem CheckedFiniteOriginCallRegisterControlContract.carriesTarget
    {context : StaticProofContext}
    (binding : CheckedFiniteOriginCallRegisterControlContract context)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution binding.entry
      originalProgram candidateProgram) :
    binding.entry.authority.certificate.target.origin.Holds context
      actual.sourceOriginal.world
      (actual.originalExit.state.registers.get binding.targetRegister)
      (actual.candidateExit.state.registers.get binding.targetRegister) := by
  have preserved := binding.calleePreserves actual binding.targetRegister
    binding.targetRegisterRequested
  have outputChecked := binding.targetRegisterOutputChecked
  simp only [Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at outputChecked
  have originalAtEntry :
      actual.originalEntry.state.registers.get binding.targetRegister =
        binding.entry.authority.certificate.target.original.eval
          actual.sourceOriginal.state := by
    rw [actual.entryStates.1]
    simp [RelationalBehavior.nextMachineState, outputChecked.1]
  have candidateAtEntry :
      actual.candidateEntry.state.registers.get binding.targetRegister =
        binding.entry.authority.certificate.target.candidate.eval
          actual.sourceCandidate.state := by
    rw [actual.entryStates.2]
    simp [RelationalBehavior.nextMachineState, outputChecked.2]
  have targetAtSource :=
    (binding.entry.authority.targetEvaluation actual.sourceOriginal.world
      actual.sourceOriginal.state actual.sourceCandidate.state
      actual.sourceRelated).1
  rw [preserved.1, preserved.2, originalAtEntry, candidateAtEntry]
  exact targetAtSource

/-- A caller-relative word survives an exact finite-origin call and is again
addressable at the same caller-relative offset at the continuation. The proof
composes the checked call-entry affine transform, same-address callee
preservation, and semantic stack-pointer restoration. -/
theorem CheckedFiniteOriginCallCallerFrameWordControlContract.preserves
    {context : StaticProofContext}
    (binding : CheckedFiniteOriginCallCallerFrameWordControlContract context)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution binding.entry
      originalProgram candidateProgram)
    (word : ReturnSlotExactWordPair)
    (member : word ∈ binding.requestedWords) :
    Memory.read32 actual.originalExit.state.memory
          (actual.originalExit.state.registers.esp +
            BitVec.ofNat 32 word.originalOffset) =
        Memory.read32 actual.sourceOriginal.state.memory
          (actual.sourceOriginal.state.registers.esp +
            BitVec.ofNat 32 word.originalOffset) /\
      Memory.read32 actual.candidateExit.state.memory
          (actual.candidateExit.state.registers.esp +
            BitVec.ofNat 32 word.candidateOffset) =
        Memory.read32 actual.sourceCandidate.state.memory
          (actual.sourceCandidate.state.registers.esp +
            BitVec.ofNat 32 word.candidateOffset) := by
  have mappedMember : word ∈ binding.entryClaims.map (·.source) := by
    rw [← binding.requestedWordsExact]
    exact member
  rcases List.mem_map.mp mappedMember with ⟨claim, claimMember, sourceExact⟩
  subst word
  have claimChecked :=
    List.all_eq_true.mp binding.entryClaimsChecked claim claimMember
  have entered := claim.memoryPreserved_of_checked binding.entry.originalBehavior
    binding.entry.candidateBehavior actual.sourceOriginal.state
      actual.sourceCandidate.state claimChecked
  rw [← actual.entryStates.1, ← actual.entryStates.2] at entered
  have entryMember : claim.entry ∈ binding.returning.words := by
    rw [binding.entryWordsExact]
    exact List.mem_map_of_mem claimMember
  have returned := binding.returning.preserves {
      regionId := binding.entry.tree.certificate.calleeEntry.id
      original := actual.originalEntry.state
      candidate := actual.candidateEntry.state
      world := actual.sourceOriginal.world
    } rfl actual.finiteExecution claim.entry entryMember
  rw [actual.finiteOriginalExitExact, actual.finiteCandidateExitExact] at returned
  have restored := binding.returningStackPointer.restores {
      regionId := binding.entry.tree.certificate.calleeEntry.id
      original := actual.originalEntry.state
      candidate := actual.candidateEntry.state
      world := actual.sourceOriginal.world
    } rfl actual.finiteExecution
  rw [actual.finiteOriginalExitExact, actual.finiteCandidateExitExact] at restored
  have offsets := binding.entryOffsetsRestore claim claimMember
  have originalAddress :
      actual.originalExit.state.registers.esp +
          BitVec.ofNat 32 claim.source.originalOffset =
        actual.originalEntry.state.registers.esp +
          BitVec.ofNat 32 claim.entry.originalOffset := by
    rw [restored.1, offsets.1]
    simp only [BitVec.add_assoc]
  have candidateAddress :
      actual.candidateExit.state.registers.esp +
          BitVec.ofNat 32 claim.source.candidateOffset =
        actual.candidateEntry.state.registers.esp +
          BitVec.ofNat 32 claim.entry.candidateOffset := by
    rw [restored.2, offsets.2]
    simp only [BitVec.add_assoc]
  constructor
  · rw [originalAddress, returned.1, entered.1]
  · rw [candidateAddress, returned.2, entered.2]

#print axioms CheckedCompleteDirectCallRegisterControlContract.preserves
#print axioms CheckedDirectCallRegisterControlContract.preserves
#print axioms CheckedDirectCallCallerFrameWordControlContract.preserves
#print axioms CheckedFiniteOriginCallRegisterControlContract.calleePreserves
#print axioms CheckedFiniteOriginCallRegisterControlContract.carriesTarget
#print axioms CheckedFiniteOriginCallCallerFrameWordControlContract.preserves
#print axioms CheckedDirectCallFiniteEvidence.finiteReturningExecutionForSource
#print axioms CheckedDirectCallFiniteEvidence.argumentToStaticSlot

end StageA.Relational.InternalDirectCallMixedOriginalIntegration
