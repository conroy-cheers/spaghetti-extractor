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

/-- The sole authority accepted by mixed-original for an internal direct-call
register-preservation edge.  The abstract register contract and edge are tied
to the exact call entry from `IntegratedSummaryPremises`; the final field is a
semantic theorem about the decoded call-entry execution, not a Boolean report. -/
structure CheckedDirectCallRegisterControlContract (context : StaticProofContext) where
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
  authority : CheckedDirectCallRegisterControlContract context
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

structure CheckedDirectCallReturnExecution
    {context : StaticProofContext}
    (binding : CheckedDirectCallRegisterControlContract context)
    (sourceOriginal sourceCandidate entryOriginal entryCandidate
      exitOriginal exitCandidate : MachineState)
    (world : RelationalWorld) (frame : RelationalRuntimeCallFrame) where
  entry : ExactDirectCallEntryExecution binding.provenance world
    sourceOriginal sourceCandidate entryOriginal entryCandidate frame
  invoked : binding.provenance.contract.invocation entryOriginal entryCandidate
    exitOriginal exitCandidate world frame

def requestedRegisterPreserved
    (register : Reg)
    (sourceOriginal sourceCandidate exitOriginal exitCandidate : MachineState) : Prop :=
  exitOriginal.registers.get register = sourceOriginal.registers.get register /\
    exitCandidate.registers.get register = sourceCandidate.registers.get register

/-- Semantic consequence consumed by the mixed-original provenance adapter.
It composes exact call-entry execution with the checked callee summary and
produces precisely the source-to-continuation register relation represented by
the abstract `callReturn` edge. -/
theorem CheckedDirectCallRegisterControlContract.preserves
    {context : StaticProofContext}
    {binding : CheckedDirectCallRegisterControlContract context}
    {sourceOriginal sourceCandidate entryOriginal entryCandidate
      exitOriginal exitCandidate : MachineState}
    {world : RelationalWorld} {frame : RelationalRuntimeCallFrame}
    (execution : CheckedDirectCallReturnExecution binding sourceOriginal
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

#print axioms CheckedDirectCallRegisterControlContract.preserves
#print axioms CheckedDirectCallFiniteEvidence.finiteReturningExecutionForSource
#print axioms CheckedDirectCallFiniteEvidence.argumentToStaticSlot

end StageA.Relational.InternalDirectCallMixedOriginalIntegration
