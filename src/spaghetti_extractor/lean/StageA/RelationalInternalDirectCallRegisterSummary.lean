import StageA.RelationalStaticMachineImportContracts
import StageA.RelationalCallableExternalIndirectExit
import StageA.RelationalValueProvenance
import StageA.RelationalX87StateOnlyDecode

namespace StageA.Relational.InternalDirectCallRegisterSummary

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalIndirectExit

/-!
# Exact internal direct-call register summaries

This module checks a finite, standalone summary tree.  Every region is decoded
again from the supplied PE values.  Python may propose the tree, but it cannot
assert inventory closure, dependency validity, or register preservation.

The checker is intentionally narrower than the whole-program interpreter.  It
accepts direct, branch, returning, nested-direct-call, statically grounded
machine-import, and exact finite-table edges.  Any other control form remains
unrepresentable and is therefore rejected.
-/

structure ExactRegionPair where
  id : Nat
  original : Span
  candidate : Span
deriving Repr, DecidableEq

def ExactRegionPair.span (candidate : Bool) (region : ExactRegionPair) : Span :=
  if candidate then region.candidate else region.original

def ExactRegionPair.behavior? (candidate : Bool)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (region : ExactRegionPair) : Option SymbolicBehavior :=
  if candidate then
    regionBehaviorWithImports candidatePe candidateImports region.candidate
  else
    regionBehaviorWithImports originalPe originalImports region.original

def exactRegionPairDecodes (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (region : ExactRegionPair) : Bool :=
  region.original.size > 0 && region.candidate.size > 0 &&
    (regionBehaviorWithImports originalPe originalImports region.original).isSome &&
    (regionBehaviorWithImports candidatePe candidateImports region.candidate).isSome

/-- Exact x87 singleton accepted by the register-summary layer.  This is
strictly narrower than general x87 execution: the decoded command has no
machine-memory operand, GPR target, EFLAGS write, or implicit stack effect.
Fault/success correspondence remains a semantic composition obligation. -/
def stateOnlyX87RegionChecked (pe : PE32) (span : Span) : Bool :=
  StageA.Relational.X87StateOnly.singletonCommandChecked pe span

def exactSummaryRegionPairDecodes (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (region : ExactRegionPair) : Bool :=
  exactRegionPairDecodes originalPe candidatePe originalImports candidateImports
      region ||
    (region.original.size > 0 && region.candidate.size > 0 &&
      stateOnlyX87RegionChecked originalPe region.original &&
      stateOnlyX87RegionChecked candidatePe region.candidate)

inductive CalleeEdgeKind where
  | direct
  | directTail
  | branchTaken
  | branchFallthrough
  | nestedSummary (dependencyId : Nat)
  | machineImport (dependencyId : Nat)
  | machineImportTail (dependencyId : Nat)
  | finiteIndirect (dependencyId : Nat)
  | finiteOriginCall (dependencyId : Nat)
  | finiteOriginTail (dependencyId : Nat)
  | constantIndirect
deriving Repr, DecidableEq

structure CalleeEdge where
  sourceRegionId : Nat
  targetRegionId : Nat
  kind : CalleeEdgeKind
deriving Repr, DecidableEq

structure ReturnInventoryEntry where
  returnRegionId : Nat
  continuationRegionId : Nat
deriving Repr, DecidableEq

structure NestedSummaryDependency where
  id : Nat
  callRegionId : Nat
  continuationRegionId : Nat
  summaryId : Nat
deriving Repr, DecidableEq

/-- A machine-import dependency carries the complete static grounding on both
sides.  `staticMachineImportProfilesValid` reparses each import table and
`StaticMachineImportBoundary.valid` re-decodes the exact direct boundary. -/
structure MachineImportDependency where
  id : Nat
  sourceRegionId : Nat
  continuationRegionId : Nat
  originalRequired : List ExternalTarget
  candidateRequired : List ExternalTarget
  originalSignatures : List StaticMachineImportSignature
  candidateSignatures : List StaticMachineImportSignature
  originalBoundary : StaticMachineImportBoundary
  candidateBoundary : StaticMachineImportBoundary
deriving Repr, DecidableEq

/-- An external jump at the end of an internal tail chain.  The exact source
span is re-decoded with the canonical machine-import signature; the live
runtime call frame supplies the continuation during semantic composition. -/
structure MachineImportTailDependency where
  id : Nat
  sourceRegionId : Nat
  signatureId : Nat
  argumentWords : Nat
  originalRequired : List ExternalTarget
  candidateRequired : List ExternalTarget
  originalSignatures : List StaticMachineImportSignature
  candidateSignatures : List StaticMachineImportSignature
deriving Repr, DecidableEq

/-- One exact imported call whose checked machine contract terminates the
current execution.  It is a completion leaf, not a synthetic return edge. -/
structure MachineImportTerminalDependency where
  id : Nat
  sourceRegionId : Nat
  originalRequired : List ExternalTarget
  candidateRequired : List ExternalTarget
  originalSignatures : List StaticMachineImportSignature
  candidateSignatures : List StaticMachineImportSignature
  originalBoundary : StaticMachineImportBoundary
  candidateBoundary : StaticMachineImportBoundary
deriving Repr, DecidableEq

/-- Exact finite pointer-table inventory for one indirect jump.  This checks
the PE table words and graph targets, but deliberately leaves the universal
index-bound proof to semantic composition. -/
structure FiniteIndirectJumpDependency where
  id : Nat
  sourceRegionId : Nat
  originalTableBase : Nat
  candidateTableBase : Nat
  upperExclusive : Nat
  originalIndexExpression : Expr
  candidateIndexExpression : Expr
  entryTargetRegionIds : List Nat
deriving Repr, DecidableEq

/-- One canonical code-map target and the direct-call summary region that starts
at its decoded RVA.  Target IDs remain independent of summary-region IDs. -/
structure FiniteOriginTailTarget where
  targetId : Nat
  regionId : Nat
deriving Repr, DecidableEq

/-- A tail jump whose target has a checked finite mixture of internal code
targets and resolver-issued callable resources.  `route` is later tied to a
route-indexed callable authority term in the generated module. -/
structure FiniteOriginTailDependency where
  id : Nat
  sourceRegionId : Nat
  route : CallableIndirectExitRoute
  internalTargets : List FiniteOriginTailTarget
deriving Repr, DecidableEq

/-- A checked internal destination of a returning indirect call and the child
summary which proves that destination's call/return behavior. -/
structure FiniteOriginCallTarget where
  targetId : Nat
  regionId : Nat
  summaryId : Nat
deriving Repr, DecidableEq

/-- One returning indirect call whose value-provenance authority supplies a
finite set of internal destinations.  The authority itself is kept outside the
serializable tree and is tied to this inventory by
`SummaryTree.finiteOriginCallAuthorityBound`. -/
structure FiniteOriginCallDependency where
  id : Nat
  sourceRegionId : Nat
  continuationRegionId : Nat
  continuationTargetId : Nat
  internalTargets : List FiniteOriginCallTarget
deriving Repr, DecidableEq

/-- The entry transition represented by one summary.  Indirect-call children
remain structurally distinguishable from ordinary direct-call children. -/
inductive SummaryEntryKind where
  | direct
  | finiteOriginCall (dependencyId targetId : Nat)
deriving Repr, DecidableEq

/-- One root or tail-entered stack frame.  Offsets are positive byte distances
below that frame's entry ESP. -/
structure StackSaveRestoreFrameWitness where
  saveRegionId : Nat
  restoreRegionIds : List Nat
  originalFrameBytes : Nat
  candidateFrameBytes : Nat
  originalSaveOffset : Nat
  candidateSaveOffset : Nat
deriving Repr, DecidableEq

/-- A callee entry may establish a stable frame base such as
`EBP = entry_ESP - 4`.  The witness records that exact modular offset; the
checker separately proves that the decoded entry establishes it and that all
frame-local paths preserve it until an epilogue. -/
structure StackFrameAnchorWitness where
  frameEntryRegionId : Nat
  register : Reg
  originalOffset : Nat
  candidateOffset : Nat
deriving Repr, DecidableEq

def StackFrameAnchorWitness.offset
    (candidate : Bool) (witness : StackFrameAnchorWitness) : Nat :=
  if candidate then witness.candidateOffset else witness.originalOffset

/-- A requested register may cross multiple function-shaped stack frames when
an epilogue performs an exact direct tail jump.  The root fields retain the
original compact representation; `additionalFrames` records each tail-entered
frame without treating untrusted function names as proof authority. -/
structure StackSaveRestoreWitness where
  register : Reg
  saveRegionId : Nat
  restoreRegionIds : List Nat
  originalFrameBytes : Nat
  candidateFrameBytes : Nat
  originalSaveOffset : Nat
  candidateSaveOffset : Nat
  additionalFrames : List StackSaveRestoreFrameWitness := []
  /-- Regions whose exact decoded writes must be proved disjoint from this
  saved word during semantic composition.  This inventory is structural:
  listing a region never grants the disjointness premise. -/
  protectedWriteRegionIds : List Nat := []
  /-- Writing external calls whose checked memory footprints must likewise be
  shown disjoint from the saved word by the external-world refinement. -/
  protectedMachineImportDependencyIds : List Nat := []
deriving Repr, DecidableEq

structure StackEntryOffsetWitness where
  regionId : Nat
  originalOffset : Nat
  candidateOffset : Nat
deriving Repr, DecidableEq

/-- A compact spanning-tree certificate for one callee region.  Forward
parents prove reachability from the entry; reverse successors prove that the
region can reach a return or terminal import.  Strictly decreasing ranks make
both chains well founded without asking the kernel to compute a transitive
closure over the entire graph. -/
structure GraphClosureNodeWitness where
  forwardRank : Nat
  forwardParentRegionIndex : Option Nat := none
  forwardParentEdgeIndex : Option Nat := none
  reverseRank : Nat
  reverseNextRegionIndex : Option Nat := none
  reverseNextEdgeIndex : Option Nat := none
deriving Repr, DecidableEq

structure GraphClosureWitness where
  nodes : List GraphClosureNodeWitness := []
deriving Repr, DecidableEq

structure Certificate where
  summaryId : Nat
  dependencyDepth : Nat := 0
  caller : ExactRegionPair
  callsite : ExactRegionPair
  calleeEntry : ExactRegionPair
  continuation : ExactRegionPair
  calleeRegions : List ExactRegionPair
  edges : List CalleeEdge
  returns : List ReturnInventoryEntry
  requestedRegisters : List Reg
  /-- Caller-owned scalar words, measured from ESP after the architectural
  call push.  These offsets are structural requests only; semantic
  composition must prove that every admitted transition preserves them. -/
  callerFrameWords : List ReturnSlotExactWordPair := []
  entryKind : SummaryEntryKind := .direct
  originalFrameBytes : Nat := 0
  candidateFrameBytes : Nat := 0
  nestedDependencies : List NestedSummaryDependency := []
  machineImportDependencies : List MachineImportDependency := []
  machineImportTailDependencies : List MachineImportTailDependency := []
  machineImportTerminalDependencies : List MachineImportTerminalDependency := []
  finiteIndirectDependencies : List FiniteIndirectJumpDependency := []
  finiteOriginCallDependencies : List FiniteOriginCallDependency := []
  finiteOriginTailDependencies : List FiniteOriginTailDependency := []
  stackFrameAnchors : List StackFrameAnchorWitness := []
  stackWitnesses : List StackSaveRestoreWitness := []
  stackEntryOffsets : List StackEntryOffsetWitness := []
  dynamicStackEntryRegionIds : List Nat := []
  graphClosureWitness : GraphClosureWitness := {}
deriving Repr, DecidableEq

inductive SummaryTree where
  | node (certificate : Certificate) (nested : List SummaryTree)
deriving Repr

/-- Compose independently checked list shards without re-evaluating their
elements in the aggregate module. -/
theorem listAll_flatten_of_parts {α : Type}
    (parts : List (List α)) (predicate : α -> Bool)
    (partsChecked :
      parts.all (fun part => part.all predicate) = true) :
    parts.flatten.all predicate = true := by
  apply List.all_eq_true.mpr
  intro value valueMember
  simp only [List.mem_flatten] at valueMember
  rcases valueMember with ⟨part, partMember, valueMember⟩
  have partChecked :=
    List.all_eq_true.mp partsChecked part partMember
  exact List.all_eq_true.mp partChecked value valueMember

def SummaryTree.certificate : SummaryTree -> Certificate
  | .node certificate _ => certificate

def SummaryTree.children : SummaryTree -> List SummaryTree
  | .node _ nested => nested

def SummaryTree.summaryId (tree : SummaryTree) : Nat :=
  tree.certificate.summaryId

def Certificate.finiteOriginTailRouteBound
    (certificate : Certificate) (dependencyId : Nat)
    (route : CallableIndirectExitRoute) : Bool :=
  certificate.finiteOriginTailDependencies.any fun dependency =>
    dependency.id == dependencyId && dependency.route == route

def SummaryTree.finiteOriginTailRouteBoundFuel
    (dependencyId : Nat) (route : CallableIndirectExitRoute) :
    Nat -> SummaryTree -> Bool
  | 0, _ => false
  | fuel + 1, .node certificate nested =>
      certificate.finiteOriginTailRouteBound dependencyId route ||
      nested.any fun child =>
        child.finiteOriginTailRouteBoundFuel dependencyId route fuel

def SummaryTree.finiteOriginTailRouteBound
    (tree : SummaryTree) (dependencyId : Nat)
    (route : CallableIndirectExitRoute) : Bool :=
  tree.finiteOriginTailRouteBoundFuel dependencyId route
    (tree.certificate.dependencyDepth + 1)

def findRegion? (regions : List ExactRegionPair) (id : Nat) :
    Option ExactRegionPair :=
  regions.find? fun region => region.id == id

def outgoingEdges (edges : List CalleeEdge) (id : Nat) : List CalleeEdge :=
  edges.filter fun edge => edge.sourceRegionId == id

def returnEntries (returns : List ReturnInventoryEntry) (id : Nat) :
    List ReturnInventoryEntry :=
  returns.filter fun entry => entry.returnRegionId == id

def nestedDependenciesAt (dependencies : List NestedSummaryDependency)
    (id : Nat) : List NestedSummaryDependency :=
  dependencies.filter fun dependency => dependency.callRegionId == id

def machineDependenciesAt (dependencies : List MachineImportDependency)
    (id : Nat) : List MachineImportDependency :=
  dependencies.filter fun dependency => dependency.sourceRegionId == id

def machineTailDependenciesAt (dependencies : List MachineImportTailDependency)
    (id : Nat) : List MachineImportTailDependency :=
  dependencies.filter fun dependency => dependency.sourceRegionId == id

def machineTerminalDependenciesAt
    (dependencies : List MachineImportTerminalDependency)
    (id : Nat) : List MachineImportTerminalDependency :=
  dependencies.filter fun dependency => dependency.sourceRegionId == id

def finiteIndirectDependenciesAt
    (dependencies : List FiniteIndirectJumpDependency)
    (id : Nat) : List FiniteIndirectJumpDependency :=
  dependencies.filter fun dependency => dependency.sourceRegionId == id

def finiteOriginCallDependenciesAt
    (dependencies : List FiniteOriginCallDependency)
    (id : Nat) : List FiniteOriginCallDependency :=
  dependencies.filter fun dependency => dependency.sourceRegionId == id

def finiteOriginTailDependenciesAt
    (dependencies : List FiniteOriginTailDependency)
    (id : Nat) : List FiniteOriginTailDependency :=
  dependencies.filter fun dependency => dependency.sourceRegionId == id

def FiniteOriginCallDependency.authorityShapeChecked
    (dependency : FiniteOriginCallDependency)
    (authority : ValueProvenance.IndirectExitCertificate) : Bool :=
  authority.transfer == .call dependency.continuationTargetId &&
    authority.destinations ==
      dependency.internalTargets.map
        (fun target => .internalCode target.targetId)

def FiniteOriginCallDependency.authoritySideChecked
    (dependency : FiniteOriginCallDependency)
    (authority : ValueProvenance.IndirectExitCertificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool)
    (regions : List ExactRegionPair) : Bool :=
  match findRegion? regions dependency.sourceRegionId,
      findRegion? regions dependency.continuationRegionId with
  | some source, some continuation =>
      match regionBehaviorWithImports pe imports (source.span candidate) with
      | some behavior =>
          behavior.outcome == some (.indirectCall
            (if candidate then authority.target.candidate
              else authority.target.original)
            (continuation.span candidate).start
            (pe.imageBase + (continuation.span candidate).start))
      | none => false
  | _, _ => false

def FiniteOriginCallDependency.authorityTargetCertificatesChecked
    (dependency : FiniteOriginCallDependency)
    (context : StaticProofContext) (nested : List Certificate) : Bool :=
  dependency.internalTargets.all fun target =>
    match context.codeMap.get? target.targetId,
        (nested.find? fun child => child.summaryId == target.summaryId) with
    | some mapped, some child =>
        child.calleeEntry.original.start == mapped.originalRva &&
          child.calleeEntry.candidate.start == mapped.candidateRva
    | _, _ => false

def FiniteOriginCallDependency.authorityTargetsChecked
    (dependency : FiniteOriginCallDependency)
    (context : StaticProofContext) (nested : List SummaryTree) : Bool :=
  dependency.authorityTargetCertificatesChecked context
    (nested.map SummaryTree.certificate)

def Certificate.finiteOriginCallAuthorityBoundCertificates
    (certificate : Certificate) (nested : List Certificate)
    (dependencyId : Nat)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  match certificate.finiteOriginCallDependencies.filter
      (fun dependency => dependency.id == dependencyId) with
  | [dependency] =>
      context.originalPe == originalPe &&
        context.candidatePe == candidatePe &&
        context.originalImports == originalImports &&
        context.candidateImports == candidateImports &&
        dependency.authorityShapeChecked authority.certificate &&
        dependency.authorityTargetCertificatesChecked context nested &&
        dependency.authoritySideChecked authority.certificate
          originalPe originalImports
          false certificate.calleeRegions &&
        dependency.authoritySideChecked authority.certificate
          candidatePe candidateImports
          true certificate.calleeRegions
  | _ => false

def Certificate.finiteOriginCallAuthorityBound
    (certificate : Certificate) (nested : List SummaryTree)
    (dependencyId : Nat)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  certificate.finiteOriginCallAuthorityBoundCertificates
    (nested.map SummaryTree.certificate) dependencyId authority
    originalPe candidatePe originalImports candidateImports

def SummaryTree.finiteOriginCallAuthorityBoundFuel
    (dependencyId : Nat)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) :
    Nat -> SummaryTree -> Bool
  | 0, _ => false
  | fuel + 1, .node certificate nested =>
      certificate.finiteOriginCallAuthorityBound nested dependencyId authority
          originalPe candidatePe originalImports candidateImports ||
        nested.any fun child =>
          child.finiteOriginCallAuthorityBoundFuel dependencyId authority
            originalPe candidatePe originalImports candidateImports fuel

def SummaryTree.finiteOriginCallAuthorityBound
    (tree : SummaryTree) (dependencyId : Nat)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  tree.finiteOriginCallAuthorityBoundFuel dependencyId authority
    originalPe candidatePe originalImports candidateImports
    (tree.certificate.dependencyDepth + 1)

/-- Componentized evidence for binding a root finite-origin call summary to
its exact indirect-exit authority.  Keeping the fields separate lets generated
proof leaves report the precise violated premise and cache the two expensive
semantic-side checks independently from the aggregate conjunction. -/
structure FiniteOriginCallEntryCheckReport where
  entryKind : Bool
  target : Bool
  context : Bool
  sourceMapped : Bool
  continuationMapped : Bool
  calleeMapped : Bool
  authorityShape : Bool
  originalSide : Bool
  candidateSide : Bool
deriving Repr, DecidableEq

def FiniteOriginCallEntryCheckReport.checked
    (report : FiniteOriginCallEntryCheckReport) : Bool :=
  report.entryKind &&
    report.target &&
    report.context &&
    report.sourceMapped &&
    report.continuationMapped &&
    report.calleeMapped &&
    report.authorityShape &&
    report.originalSide &&
    report.candidateSide

def FiniteOriginCallEntryCheckReport.rejected :
    FiniteOriginCallEntryCheckReport := {
  entryKind := false
  target := false
  context := false
  sourceMapped := false
  continuationMapped := false
  calleeMapped := false
  authorityShape := false
  originalSide := false
  candidateSide := false
}

/-- Bind a root finite-origin call summary to the exact indirect-exit
authority which selected its singleton internal destination.  Nested
finite-origin calls are checked through `FiniteOriginCallDependency`; this
report covers the analogous root where no parent summary exists. -/
def Certificate.finiteOriginCallEntryCheckReport
    (certificate : Certificate)
    (sourceTargetId calleeTargetId continuationTargetId : Nat)
    {context : StaticProofContext}
    (authority : ValueProvenance.IndirectExitCertificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) :
    FiniteOriginCallEntryCheckReport :=
  match certificate.entryKind with
  | .direct => .rejected
  | .finiteOriginCall dependencyId targetId =>
      let dependency : FiniteOriginCallDependency := {
        id := dependencyId
        sourceRegionId := certificate.callsite.id
        continuationRegionId := certificate.continuation.id
        continuationTargetId
        internalTargets := [{
          targetId
          regionId := certificate.calleeEntry.id
          summaryId := certificate.summaryId
        }]
      }
      let sourceMapped :=
        match context.codeMap.get? sourceTargetId with
        | some target =>
            target.id == sourceTargetId &&
              target.originalRva == certificate.callsite.original.start &&
              target.candidateRva == certificate.callsite.candidate.start
        | none => false
      let continuationMapped :=
        match context.codeMap.get? continuationTargetId with
        | some target =>
            target.id == continuationTargetId &&
              target.originalRva == certificate.continuation.original.start &&
              target.candidateRva == certificate.continuation.candidate.start
        | none => false
      let calleeMapped :=
        match context.codeMap.get? targetId with
        | some target =>
            target.id == targetId &&
              target.originalRva == certificate.calleeEntry.original.start &&
              target.candidateRva == certificate.calleeEntry.candidate.start
        | none => false
      {
        entryKind := true
        target := targetId == calleeTargetId
        context :=
          context.originalPe == originalPe &&
            context.candidatePe == candidatePe &&
            context.originalImports == originalImports &&
            context.candidateImports == candidateImports
        sourceMapped
        continuationMapped
        calleeMapped
        authorityShape := dependency.authorityShapeChecked authority
        originalSide := dependency.authoritySideChecked authority
          originalPe originalImports false
          [certificate.callsite, certificate.continuation]
        candidateSide := dependency.authoritySideChecked authority
          candidatePe candidateImports true
          [certificate.callsite, certificate.continuation]
      }

def Certificate.finiteOriginCallEntryCertificateChecked
    (certificate : Certificate)
    (sourceTargetId calleeTargetId continuationTargetId : Nat)
    {context : StaticProofContext}
    (authority : ValueProvenance.IndirectExitCertificate)
  (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  (certificate.finiteOriginCallEntryCheckReport
    (context := context)
    sourceTargetId calleeTargetId continuationTargetId authority
    originalPe candidatePe originalImports candidateImports).checked

/-- Semantic authorities carry proof fields which should remain opaque once
compiled.  Root-entry structural checking depends only on their compact
certificate data, so downstream modules can rewrite that projection using an
exported producer theorem without replaying the authority proof. -/
def Certificate.finiteOriginCallEntryAuthorityChecked
    (certificate : Certificate)
    (sourceTargetId calleeTargetId continuationTargetId : Nat)
    {context : StaticProofContext} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (authority : ValueProvenance.CheckedIndirectExitCertificate context
      sourceInvariant originalBehavior candidateBehavior)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  certificate.finiteOriginCallEntryCertificateChecked (context := context)
    sourceTargetId
    calleeTargetId continuationTargetId authority.certificate
    originalPe candidatePe originalImports candidateImports

def edgeIdsUniqueSlow (edges : List CalleeEdge) : Bool :=
  edges.all fun edge =>
    (edges.filter fun other =>
      other.sourceRegionId == edge.sourceRegionId &&
        other.targetRegionId == edge.targetRegionId &&
        other.kind == edge.kind).length == 1

def edgeIdsGroupedUnique : List CalleeEdge -> Bool
  | [] => true
  | edge :: rest =>
      (match rest with
      | [] => true
      | next :: _ => edge.sourceRegionId <= next.sourceRegionId) &&
      ((rest.takeWhile fun other =>
        other.sourceRegionId == edge.sourceRegionId).all fun other =>
          !(other.targetRegionId == edge.targetRegionId &&
            other.kind == edge.kind)) &&
      edgeIdsGroupedUnique rest

def edgeIdsUnique (edges : List CalleeEdge) : Bool :=
  edgeIdsGroupedUnique edges || edgeIdsUniqueSlow edges

def natListStrictlyIncreasing : List Nat -> Bool
  | [] => true
  | [_] => true
  | first :: second :: rest =>
      first < second && natListStrictlyIncreasing (second :: rest)

def regionIdsUniqueSlow (regions : List ExactRegionPair) : Bool :=
  regions.all fun region =>
    (regions.filter fun other => other.id == region.id).length == 1

def regionIdsUnique (regions : List ExactRegionPair) : Bool :=
  natListStrictlyIncreasing (regions.map ExactRegionPair.id) ||
    regionIdsUniqueSlow regions

def returnIdsUnique (returns : List ReturnInventoryEntry) : Bool :=
  returns.all fun entry =>
    (returns.filter fun other =>
      other.returnRegionId == entry.returnRegionId).length == 1

def nestedDependencyIdsUnique
    (dependencies : List NestedSummaryDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.callRegionId == dependency.callRegionId).length == 1 &&
      (dependencies.filter fun other =>
        other.summaryId == dependency.summaryId).length == 1

def machineDependencyIdsUnique
    (dependencies : List MachineImportDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.sourceRegionId == dependency.sourceRegionId).length == 1

def machineTailDependencyIdsUnique
    (dependencies : List MachineImportTailDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.sourceRegionId == dependency.sourceRegionId).length == 1

def machineTerminalDependencyIdsUnique
    (dependencies : List MachineImportTerminalDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.sourceRegionId == dependency.sourceRegionId).length == 1

def finiteIndirectDependencyIdsUnique
    (dependencies : List FiniteIndirectJumpDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.sourceRegionId == dependency.sourceRegionId).length == 1

def finiteOriginCallDependencyIdsUnique
    (dependencies : List FiniteOriginCallDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.sourceRegionId == dependency.sourceRegionId).length == 1 &&
      !dependency.internalTargets.isEmpty &&
      dependency.internalTargets.length ==
        dependency.internalTargets.eraseDups.length &&
      (dependency.internalTargets.map (fun target => target.targetId)).length ==
        (dependency.internalTargets.map
          (fun target => target.targetId)).eraseDups.length &&
      (dependency.internalTargets.map (fun target => target.summaryId)).length ==
        (dependency.internalTargets.map
          (fun target => target.summaryId)).eraseDups.length

def finiteOriginTailDependencyIdsUnique
    (dependencies : List FiniteOriginTailDependency) : Bool :=
  dependencies.all fun dependency =>
    (dependencies.filter fun other => other.id == dependency.id).length == 1 &&
      (dependencies.filter fun other =>
        other.sourceRegionId == dependency.sourceRegionId).length == 1

def stackWitnessRegistersUnique
    (witnesses : List StackSaveRestoreWitness) : Bool :=
  witnesses.all fun witness =>
      (witnesses.filter fun other => other.register == witness.register).length == 1

def stackFrameAnchorIdsUnique
    (witnesses : List StackFrameAnchorWitness) : Bool :=
  witnesses.all fun witness =>
    (witnesses.filter fun other =>
      other.frameEntryRegionId == witness.frameEntryRegionId).length == 1

def stackEntryOffsetIdsUniqueSlow
    (witnesses : List StackEntryOffsetWitness) : Bool :=
  witnesses.all fun witness =>
    (witnesses.filter fun other =>
      other.regionId == witness.regionId).length == 1

def stackEntryOffsetIdsUnique
    (witnesses : List StackEntryOffsetWitness) : Bool :=
  natListStrictlyIncreasing
      (witnesses.map StackEntryOffsetWitness.regionId) ||
    stackEntryOffsetIdsUniqueSlow witnesses

def ExactRegionPair.spanStartsAt (candidate : Bool) (region : ExactRegionPair)
    (rva : Nat) : Bool :=
  (region.span candidate).start == rva

def behaviorCalls (pe : PE32) (callee continuation : Span)
    (behavior : SymbolicBehavior) : Bool :=
  match behavior.outcome with
  | some (.call target returnRva returnAddress) =>
      target == callee.start && returnRva == continuation.start &&
        pe.imageBase + returnRva < 2 ^ 32 &&
        returnAddress == pe.imageBase + returnRva
  | _ => false

def behaviorIndirectCalls (pe : PE32) (continuation : Span)
    (behavior : SymbolicBehavior) : Bool :=
  match behavior.outcome with
  | some (.indirectCall _ returnRva returnAddress) =>
      returnRva == continuation.start &&
        pe.imageBase + returnRva < 2 ^ 32 &&
        returnAddress == pe.imageBase + returnRva
  | _ => false

def callerReachesCallsite (caller callsite : ExactRegionPair)
    (candidate : Bool) (behavior : SymbolicBehavior) : Bool :=
  if caller == callsite then true else
    match behavior.outcome with
    | some (.jump target) => callsite.spanStartsAt candidate target
    | some (.branch _ taken fallthrough) =>
        callsite.spanStartsAt candidate taken ||
          callsite.spanStartsAt candidate fallthrough
    | _ => false

def Certificate.endpointsChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  exactRegionPairDecodes originalPe candidatePe originalImports candidateImports
      certificate.caller &&
    exactRegionPairDecodes originalPe candidatePe originalImports candidateImports
      certificate.callsite &&
    exactRegionPairDecodes originalPe candidatePe originalImports candidateImports
      certificate.continuation &&
    match certificate.caller.behavior? false originalPe candidatePe
        originalImports candidateImports,
      certificate.caller.behavior? true originalPe candidatePe
        originalImports candidateImports,
      certificate.callsite.behavior? false originalPe candidatePe
        originalImports candidateImports,
      certificate.callsite.behavior? true originalPe candidatePe
        originalImports candidateImports with
    | some originalCaller, some candidateCaller,
        some originalCall, some candidateCall =>
        callerReachesCallsite certificate.caller certificate.callsite false
            originalCaller &&
          callerReachesCallsite certificate.caller certificate.callsite true
            candidateCaller &&
          match certificate.entryKind with
          | .direct =>
              behaviorCalls originalPe certificate.calleeEntry.original
                  certificate.continuation.original originalCall &&
                behaviorCalls candidatePe certificate.calleeEntry.candidate
                  certificate.continuation.candidate candidateCall
          | .finiteOriginCall _ _ =>
              behaviorIndirectCalls originalPe certificate.continuation.original
                  originalCall &&
                behaviorIndirectCalls candidatePe certificate.continuation.candidate
                  candidateCall
    | _, _, _, _ => false

def directEdgeChecked (candidate : Bool) (regions : List ExactRegionPair)
    (targetRva : Nat) (edges : List CalleeEdge) : Bool :=
  match edges with
  | [edge] =>
      (edge.kind == .direct || edge.kind == .directTail) &&
        match findRegion? regions edge.targetRegionId with
        | some target => target.spanStartsAt candidate targetRva
        | none => false
  | _ => false

def constantIndirectEdgeChecked (pe : PE32) (candidate : Bool)
    (regions : List ExactRegionPair) (target : Expr)
    (edges : List CalleeEdge) : Bool :=
  match edges with
  | [edge] =>
      edge.kind == .constantIndirect &&
        match findRegion? regions edge.targetRegionId with
        | some destination =>
            pe.imageBase + (destination.span candidate).start < 2 ^ 32 &&
              target == .constant
                (pe.imageBase + (destination.span candidate).start)
        | none => false
  | _ => false

def branchEdgesChecked (candidate : Bool) (regions : List ExactRegionPair)
    (takenRva fallthroughRva : Nat) (edges : List CalleeEdge) : Bool :=
  match edges.find? fun edge => edge.kind == .branchTaken,
      edges.find? fun edge => edge.kind == .branchFallthrough with
  | some taken, some fallthrough =>
      edges.length == 2 && taken != fallthrough &&
        match findRegion? regions taken.targetRegionId,
            findRegion? regions fallthrough.targetRegionId with
        | some takenTarget, some fallthroughTarget =>
            takenTarget.spanStartsAt candidate takenRva &&
              fallthroughTarget.spanStartsAt candidate fallthroughRva
        | _, _ => false
  | _, _ => false

def nestedEdgeChecked (pe : PE32) (candidate : Bool)
    (regions : List ExactRegionPair)
    (dependencies : List NestedSummaryDependency)
    (targetRva continuationRva returnAddress : Nat)
    (edges : List CalleeEdge) : Bool :=
  match edges with
  | [{ targetRegionId, kind := .nestedSummary dependencyId, .. }] =>
      match dependencies.find? fun dependency => dependency.id == dependencyId,
          findRegion? regions targetRegionId with
      | some dependency, some continuation =>
          dependency.continuationRegionId == targetRegionId &&
            continuation.spanStartsAt candidate continuationRva &&
            pe.imageBase + continuationRva < 2 ^ 32 &&
            returnAddress == pe.imageBase + continuationRva &&
            targetRva < 2 ^ 32
      | _, _ => false
  | _ => false

def machineRouteEdgeChecked (candidate : Bool) (regions : List ExactRegionPair)
    (dependencies : List MachineImportDependency)
    (source : ExactRegionPair) (edges : List CalleeEdge) : Bool :=
  match dependencies, edges with
  | [dependency],
      [{ targetRegionId, kind := .machineImport dependencyId, .. }] =>
      match findRegion? regions targetRegionId with
      | some continuation =>
          dependency.id == dependencyId &&
            dependency.sourceRegionId == source.id &&
            dependency.continuationRegionId == targetRegionId &&
            source.span candidate ==
              (if candidate then dependency.candidateBoundary.sourceSpan
                else dependency.originalBoundary.sourceSpan) &&
            continuation.spanStartsAt candidate
              (if candidate then dependency.candidateBoundary.continuationRva
                else dependency.originalBoundary.continuationRva)
      | none => false
  | _, _ => false

def machineImportTailHandoffEdgeChecked (candidate : Bool)
    (regions : List ExactRegionPair)
    (dependencies : List MachineImportTailDependency)
    (targetRva : Nat) (edges : List CalleeEdge) : Bool :=
  match edges with
  | [{ targetRegionId, kind := .machineImportTail dependencyId, .. }] =>
      match dependencies.find? fun dependency => dependency.id == dependencyId,
          findRegion? regions targetRegionId with
      | some dependency, some target =>
          dependency.sourceRegionId == targetRegionId &&
            target.spanStartsAt candidate targetRva
      | _, _ => false
  | _ => false

def finiteIndirectTargetExpression (base : Nat) (index : Expr) : Expr :=
  .read32 (.add (.shiftLeft index 2) (.constant base))

def FiniteIndirectJumpDependency.tableBase (candidate : Bool)
    (dependency : FiniteIndirectJumpDependency) : Nat :=
  if candidate then dependency.candidateTableBase
  else dependency.originalTableBase

def FiniteIndirectJumpDependency.indexExpression (candidate : Bool)
    (dependency : FiniteIndirectJumpDependency) : Expr :=
  if candidate then dependency.candidateIndexExpression
  else dependency.originalIndexExpression

def FiniteIndirectJumpDependency.entryChecked (candidate : Bool) (pe : PE32)
    (regions : List ExactRegionPair) (dependency : FiniteIndirectJumpDependency)
    (index : Nat) : Bool :=
  match dependency.entryTargetRegionIds[index]? with
  | none => false
  | some targetRegionId =>
      match findRegion? regions targetRegionId with
      | none => false
      | some target =>
          readImmutableImageWord pe
              (dependency.tableBase candidate + index * 4) 4 ==
            some (pe.imageBase + (target.span candidate).start)

def FiniteIndirectJumpDependency.sideChecked (candidate : Bool) (pe : PE32)
    (regions : List ExactRegionPair) (dependency : FiniteIndirectJumpDependency) :
    Bool :=
  dependency.upperExclusive > 0 &&
    dependency.upperExclusive < 2 ^ 32 &&
    dependency.entryTargetRegionIds.length == dependency.upperExclusive &&
    dependency.tableBase candidate >= pe.imageBase &&
    dependency.tableBase candidate + dependency.upperExclusive * 4 <= 2 ^ 32 &&
    (List.range dependency.upperExclusive).all
      (dependency.entryChecked candidate pe regions)

def FiniteIndirectJumpDependency.behaviorChecked (candidate : Bool)
    (dependency : FiniteIndirectJumpDependency)
    (behavior : SymbolicBehavior) : Bool :=
  behavior.outcome == some (.indirectJump
    (finiteIndirectTargetExpression (dependency.tableBase candidate)
      (dependency.indexExpression candidate)))

def finiteIndirectEdgesChecked (dependency : FiniteIndirectJumpDependency)
    (edges : List CalleeEdge) : Bool :=
  let targets := dependency.entryTargetRegionIds.eraseDups
  edges.length == targets.length &&
    (targets.all fun targetRegionId =>
      (edges.filter fun edge =>
        edge.targetRegionId == targetRegionId &&
          edge.kind == .finiteIndirect dependency.id).length == 1) &&
    (edges.all fun edge =>
      targets.contains edge.targetRegionId &&
        edge.kind == .finiteIndirect dependency.id)

def FiniteIndirectJumpDependency.checked (dependency : FiniteIndirectJumpDependency)
    (certificate : Certificate) (originalPe candidatePe : PE32) : Bool :=
  dependency.entryTargetRegionIds.isEmpty == false &&
    dependency.sideChecked false originalPe certificate.calleeRegions &&
    dependency.sideChecked true candidatePe certificate.calleeRegions

def callableIndirectExternalRouteSummaryShapeChecked
    (external : CallableIndirectExternalRoute) : Bool :=
  external.capability.validFor external.resolver &&
    external.abi.shapeValid &&
    external.abi.capabilityId == external.capability.id &&
    external.abi.transfer == .jump

def callableIndirectExternalRoutePreservesSummaryRegister
    (external : CallableIndirectExternalRoute) (register : Reg) : Bool :=
  register == .esp || external.abi.preservedRegisters.contains register

def FiniteOriginTailDependency.behaviorChecked (candidate : Bool)
    (dependency : FiniteOriginTailDependency)
    (behavior : SymbolicBehavior) : Bool :=
  behavior.outcome == some (.indirectJump
    (if candidate then dependency.route.candidateTarget
      else dependency.route.originalTarget))

def FiniteOriginCallDependency.behaviorChecked
    (candidate : Bool) (dependency : FiniteOriginCallDependency)
    (regions : List ExactRegionPair) (behavior : SymbolicBehavior) : Bool :=
  match findRegion? regions dependency.continuationRegionId,
      behavior.outcome with
  | some continuation, some (.indirectCall _ returnRva _) =>
      returnRva == (continuation.span candidate).start
  | _, _ => false

def finiteOriginCallEdgeChecked (dependency : FiniteOriginCallDependency)
    (edges : List CalleeEdge) : Bool :=
  match edges with
  | [edge] =>
      edge.targetRegionId == dependency.continuationRegionId &&
        edge.kind == .finiteOriginCall dependency.id
  | _ => false

def FiniteOriginCallDependency.checked
    (dependency : FiniteOriginCallDependency)
    (certificate : Certificate) : Bool :=
  !dependency.internalTargets.isEmpty &&
    (findRegion? certificate.calleeRegions dependency.sourceRegionId).isSome &&
    (findRegion? certificate.calleeRegions
      dependency.continuationRegionId).isSome &&
    finiteOriginCallEdgeChecked dependency
      (outgoingEdges certificate.edges dependency.sourceRegionId)

def finiteOriginTailEdgesChecked (dependency : FiniteOriginTailDependency)
    (edges : List CalleeEdge) : Bool :=
  let targets := dependency.internalTargets.map (fun target => target.regionId)
  edges.length == targets.length &&
    (targets.all fun targetRegionId =>
      (edges.filter fun edge =>
        edge.targetRegionId == targetRegionId &&
          edge.kind == .finiteOriginTail dependency.id).length == 1) &&
    (edges.all fun edge =>
      targets.contains edge.targetRegionId &&
        edge.kind == .finiteOriginTail dependency.id)

def FiniteOriginTailDependency.checked (dependency : FiniteOriginTailDependency)
    (certificate : Certificate) : Bool :=
  dependency.route.transfer == .jump &&
    !dependency.route.externalRoutes.isEmpty &&
    !dependency.internalTargets.isEmpty &&
    dependency.route.externalRoutes.all
      callableIndirectExternalRouteSummaryShapeChecked &&
    dependency.route.externalRoutes.length ==
      dependency.route.externalRoutes.eraseDups.length &&
    dependency.route.internalTargetIds ==
      dependency.internalTargets.map (fun target => target.targetId) &&
    dependency.route.internalTargetIds.length ==
      dependency.route.internalTargetIds.eraseDups.length &&
    (dependency.internalTargets.map (fun target => target.regionId)).length ==
      (dependency.internalTargets.map
        (fun target => target.regionId)).eraseDups.length &&
    (dependency.internalTargets.all fun target =>
      (findRegion? certificate.calleeRegions target.regionId).isSome) &&
    (dependency.route.externalRoutes.all fun external =>
      certificate.requestedRegisters.all
        (callableIndirectExternalRoutePreservesSummaryRegister external))

def MachineImportTailDependency.signature?
    (dependency : MachineImportTailDependency) (candidate : Bool) :
    Option StaticMachineImportSignature :=
  let signatures :=
    if candidate then dependency.candidateSignatures
    else dependency.originalSignatures
  signatures.find? fun signature => signature.id == dependency.signatureId

def MachineImportTailDependency.behaviorChecked
    (dependency : MachineImportTailDependency) (pe : PE32)
    (imports : List PEImport) (candidate : Bool) (source : Span) : Bool :=
  match dependency.signature? candidate with
  | none => false
  | some signature =>
      match signature.bridgeContract? dependency.argumentWords with
      | none => false
      | some contract =>
          contract.disposition == .returns &&
            match regionBehaviorWithMachineCallContracts pe imports [contract]
                source with
            | none => false
            | some behavior =>
                staticMachineImportJumpOutcomeValid signature.imported
                  dependency.argumentWords behavior

def regionControlChecked (pe : PE32) (imports : List PEImport) (candidate : Bool)
    (certificate : Certificate) (region : ExactRegionPair)
    (behavior : SymbolicBehavior) : Bool :=
  let edges := outgoingEdges certificate.edges region.id
  let returns := returnEntries certificate.returns region.id
  let machineDependencies :=
    machineDependenciesAt certificate.machineImportDependencies region.id
  let machineTailDependencies :=
    machineTailDependenciesAt certificate.machineImportTailDependencies region.id
  let machineTerminalDependencies :=
    machineTerminalDependenciesAt
      certificate.machineImportTerminalDependencies region.id
  let finiteDependencies :=
    finiteIndirectDependenciesAt certificate.finiteIndirectDependencies region.id
  let finiteOriginCallDependencies :=
    finiteOriginCallDependenciesAt
      certificate.finiteOriginCallDependencies region.id
  let finiteOriginTailDependencies :=
    finiteOriginTailDependenciesAt certificate.finiteOriginTailDependencies region.id
  if !machineTerminalDependencies.isEmpty then
    match machineTerminalDependencies with
    | [_] => edges.isEmpty && returns.isEmpty
    | _ => false
  else if !machineTailDependencies.isEmpty then
    match machineTailDependencies with
    | [dependency] =>
        edges.isEmpty && returns.length == 1 &&
          (returns.all fun entry =>
            entry.continuationRegionId == certificate.continuation.id) &&
          dependency.behaviorChecked pe imports candidate (region.span candidate)
    | _ => false
  else if !machineDependencies.isEmpty then
    returns.isEmpty &&
      machineRouteEdgeChecked candidate certificate.calleeRegions
        machineDependencies region edges
  else if !finiteDependencies.isEmpty then
    returns.isEmpty &&
      match finiteDependencies with
      | [dependency] =>
          dependency.behaviorChecked candidate behavior &&
            finiteIndirectEdgesChecked dependency edges
      | _ => false
  else if !finiteOriginCallDependencies.isEmpty then
    match finiteOriginCallDependencies with
    | [dependency] =>
        returns.isEmpty &&
          dependency.behaviorChecked candidate certificate.calleeRegions behavior &&
          finiteOriginCallEdgeChecked dependency edges
    | _ => false
  else if !finiteOriginTailDependencies.isEmpty then
    match finiteOriginTailDependencies with
    | [dependency] =>
        returns.length == 1 &&
          (returns.all fun entry =>
            entry.continuationRegionId == certificate.continuation.id) &&
          dependency.behaviorChecked candidate behavior &&
          finiteOriginTailEdgesChecked dependency edges
    | _ => false
  else
    match behavior.outcome with
    | some (.jump target) =>
        returns.isEmpty &&
          if edges.any fun edge =>
              match edge.kind with
              | .machineImportTail _ => true
              | _ => false then
            machineImportTailHandoffEdgeChecked candidate
              certificate.calleeRegions certificate.machineImportTailDependencies
              target edges
          else
            directEdgeChecked candidate certificate.calleeRegions target edges
    | some (.branch _ taken fallthrough) =>
        returns.isEmpty &&
          branchEdgesChecked candidate certificate.calleeRegions
            taken fallthrough edges
    | some (.call target continuation returnAddress) =>
        returns.isEmpty &&
          nestedEdgeChecked pe candidate certificate.calleeRegions
            certificate.nestedDependencies target continuation returnAddress edges
    | some (.returned _) =>
        edges.isEmpty && returns.length == 1 &&
          returns.all fun entry =>
            entry.continuationRegionId == certificate.continuation.id
    | some (.indirectJump target) =>
        returns.isEmpty &&
          constantIndirectEdgeChecked pe candidate certificate.calleeRegions
            target edges
    /- These outcomes have one successful internal continuation and one or more
    non-continuing machine outcomes.  The direct edge records only the former;
    operational composition must still prove the checked/faulting alternatives
    correspond before using the returning summary. -/
    | some (.bulkCopy _ continuation)
    | some (.checkedContinue _ continuation)
    | some (.atomicCompareExchange _ _ _ continuation) =>
        returns.isEmpty &&
          directEdgeChecked candidate certificate.calleeRegions
            continuation edges
    | _ => false

def stateOnlyX87RegionControlChecked (pe : PE32) (candidate : Bool)
    (certificate : Certificate) (region : ExactRegionPair) : Bool :=
  stateOnlyX87RegionChecked pe (region.span candidate) &&
    (returnEntries certificate.returns region.id).isEmpty &&
    directEdgeChecked candidate certificate.calleeRegions
      (region.span candidate).stop (outgoingEdges certificate.edges region.id)

def Certificate.inventoryRegionsChecked (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool)
    (regions : List ExactRegionPair) : Bool :=
  regions.all fun region =>
    match regionBehaviorWithImports pe imports (region.span candidate) with
    | some behavior =>
        regionControlChecked pe imports candidate certificate region behavior
    | none =>
        stateOnlyX87RegionControlChecked pe candidate certificate region

def Certificate.inventorySideChecked (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool) : Bool :=
  certificate.inventoryRegionsChecked pe imports candidate
    certificate.calleeRegions

theorem Certificate.inventoryRegionsChecked_flatten
    (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool)
    (parts : List (List ExactRegionPair))
    (partsChecked :
      parts.all (fun part =>
        certificate.inventoryRegionsChecked pe imports candidate part) =
          true) :
    certificate.inventoryRegionsChecked pe imports candidate parts.flatten =
      true := by
  unfold Certificate.inventoryRegionsChecked
  apply List.all_eq_true.mpr
  intro region regionMember
  simp only [List.mem_flatten] at regionMember
  rcases regionMember with ⟨part, partMember, regionMember⟩
  have partChecked :=
    List.all_eq_true.mp partsChecked part partMember
  unfold Certificate.inventoryRegionsChecked at partChecked
  exact List.all_eq_true.mp partChecked region regionMember

theorem Certificate.inventorySideChecked_of_region_parts
    (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool)
    (parts : List (List ExactRegionPair))
    (regionsBound : parts.flatten = certificate.calleeRegions)
    (partsChecked :
      parts.all (fun part =>
        certificate.inventoryRegionsChecked pe imports candidate part) =
          true) :
    certificate.inventorySideChecked pe imports candidate = true := by
  unfold Certificate.inventorySideChecked
  rw [← regionsBound]
  exact certificate.inventoryRegionsChecked_flatten pe imports candidate
    parts partsChecked

def edgeClosureStep (edges : List CalleeEdge) (visited : List Nat) : List Nat :=
  (visited ++ visited.flatMap fun source =>
    (outgoingEdges edges source).map (fun edge => edge.targetRegionId)).eraseDups

def edgeClosure (edges : List CalleeEdge) : Nat -> List Nat -> List Nat
  | 0, visited => visited
  | fuel + 1, visited => edgeClosure edges fuel (edgeClosureStep edges visited)

def reachesWithin (edges : List CalleeEdge) (regionCount source target : Nat) : Bool :=
  (edgeClosure edges regionCount [source]).contains target

def reverseEdgeClosureStep (edges : List CalleeEdge)
    (visited : List Nat) : List Nat :=
  (visited ++ visited.flatMap fun target =>
    (edges.filter fun edge => edge.targetRegionId == target).map
      (fun edge => edge.sourceRegionId)).eraseDups

def reverseEdgeClosure (edges : List CalleeEdge) : Nat -> List Nat -> List Nat
  | 0, visited => visited
  | fuel + 1, visited =>
      reverseEdgeClosure edges fuel (reverseEdgeClosureStep edges visited)

def Certificate.graphShapeChecked (certificate : Certificate) : Bool :=
  let ids := certificate.calleeRegions.map (fun region => region.id)
  ids.contains certificate.calleeEntry.id &&
    certificate.calleeRegions.contains certificate.calleeEntry &&
    (certificate.edges.all fun edge =>
      ids.contains edge.sourceRegionId && ids.contains edge.targetRegionId) &&
    (certificate.returns.all fun entry =>
      ids.contains entry.returnRegionId &&
        entry.continuationRegionId == certificate.continuation.id)

def Certificate.completionRegionIds (certificate : Certificate) : List Nat :=
  certificate.returns.map (fun entry => entry.returnRegionId) ++
    certificate.machineImportTerminalDependencies.map
      (fun dependency => dependency.sourceRegionId)

def GraphClosureWitness.forwardNodeChecked
    (witness : GraphClosureWitness) (certificate : Certificate)
    (regionIndex : Nat) : Bool :=
  match certificate.calleeRegions[regionIndex]?, witness.nodes[regionIndex]? with
  | some region, some node =>
      if region.id == certificate.calleeEntry.id then
        node.forwardRank == 0 &&
          node.forwardParentRegionIndex.isNone &&
          node.forwardParentEdgeIndex.isNone
      else
        match node.forwardParentRegionIndex, node.forwardParentEdgeIndex with
        | some parentIndex, some edgeIndex =>
            match certificate.calleeRegions[parentIndex]?,
                witness.nodes[parentIndex]?, certificate.edges[edgeIndex]? with
            | some parent, some parentNode, some edge =>
                decide (parentNode.forwardRank < node.forwardRank) &&
                  edge.sourceRegionId == parent.id &&
                  edge.targetRegionId == region.id
            | _, _, _ => false
        | _, _ => false
  | _, _ => false

def GraphClosureWitness.reverseNodeChecked
    (witness : GraphClosureWitness) (certificate : Certificate)
    (regionIndex : Nat) : Bool :=
  match certificate.calleeRegions[regionIndex]?, witness.nodes[regionIndex]? with
  | some region, some node =>
      if certificate.completionRegionIds.contains region.id then
        node.reverseRank == 0 &&
          node.reverseNextRegionIndex.isNone &&
          node.reverseNextEdgeIndex.isNone
      else
        match node.reverseNextRegionIndex, node.reverseNextEdgeIndex with
        | some nextIndex, some edgeIndex =>
            match certificate.calleeRegions[nextIndex]?,
                witness.nodes[nextIndex]?, certificate.edges[edgeIndex]? with
            | some next, some nextNode, some edge =>
                decide (nextNode.reverseRank < node.reverseRank) &&
                  edge.sourceRegionId == region.id &&
                  edge.targetRegionId == next.id
            | _, _, _ => false
        | _, _ => false
  | _, _ => false

def GraphClosureWitness.nodeChecked
    (witness : GraphClosureWitness) (certificate : Certificate)
    (regionIndex : Nat) : Bool :=
  witness.forwardNodeChecked certificate regionIndex &&
    witness.reverseNodeChecked certificate regionIndex

def GraphClosureWitness.partChecked
    (witness : GraphClosureWitness) (certificate : Certificate)
    (regionIndices : List Nat) : Bool :=
  regionIndices.all (witness.nodeChecked certificate)

def GraphClosureWitness.checked
    (witness : GraphClosureWitness) (certificate : Certificate) : Bool :=
  witness.nodes.length == certificate.calleeRegions.length &&
    certificate.graphShapeChecked &&
    witness.partChecked certificate
      (List.range certificate.calleeRegions.length)

theorem GraphClosureWitness.partChecked_flatten
    (witness : GraphClosureWitness) (certificate : Certificate)
    (parts : List (List Nat))
    (partsChecked :
      parts.all (fun part => witness.partChecked certificate part) = true) :
    witness.partChecked certificate parts.flatten = true := by
  unfold GraphClosureWitness.partChecked
  apply List.all_eq_true.mpr
  intro regionIndex regionMember
  simp only [List.mem_flatten] at regionMember
  rcases regionMember with ⟨part, partMember, regionMember⟩
  have partChecked :=
    List.all_eq_true.mp partsChecked part partMember
  unfold GraphClosureWitness.partChecked at partChecked
  exact List.all_eq_true.mp partChecked regionIndex regionMember

theorem GraphClosureWitness.checked_of_parts
    (witness : GraphClosureWitness) (certificate : Certificate)
    (parts : List (List Nat))
    (lengthBound :
      witness.nodes.length = certificate.calleeRegions.length)
    (shapeChecked : certificate.graphShapeChecked = true)
    (partsBound :
      parts.flatten = List.range certificate.calleeRegions.length)
    (partsChecked :
      parts.all (fun part => witness.partChecked certificate part) = true) :
    witness.checked certificate = true := by
  have flatChecked :=
    witness.partChecked_flatten certificate parts partsChecked
  have allChecked :
      witness.partChecked certificate
        (List.range certificate.calleeRegions.length) = true :=
    partsBound ▸ flatChecked
  have lengthChecked :
      (witness.nodes.length == certificate.calleeRegions.length) = true :=
    beq_iff_eq.mpr lengthBound
  unfold GraphClosureWitness.checked
  exact Bool.and_eq_true_iff.mpr ⟨
    Bool.and_eq_true_iff.mpr ⟨lengthChecked, shapeChecked⟩,
    allChecked⟩

def Certificate.graphRegionIdsChecked (certificate : Certificate)
    (allIds checkedIds : List Nat) : Bool :=
  checkedIds.all fun id =>
      reachesWithin certificate.edges allIds.length certificate.calleeEntry.id id &&
        (certificate.completionRegionIds.any fun completionId =>
          reachesWithin certificate.edges allIds.length id completionId)

theorem Certificate.graphRegionIdsChecked_flatten
    (certificate : Certificate) (allIds : List Nat)
    (parts : List (List Nat))
    (partsChecked :
      parts.all (fun part =>
        certificate.graphRegionIdsChecked allIds part) = true) :
    certificate.graphRegionIdsChecked allIds parts.flatten = true := by
  unfold Certificate.graphRegionIdsChecked
  apply List.all_eq_true.mpr
  intro regionId regionMember
  simp only [List.mem_flatten] at regionMember
  rcases regionMember with ⟨part, partMember, regionMember⟩
  have partChecked :=
    List.all_eq_true.mp partsChecked part partMember
  unfold Certificate.graphRegionIdsChecked at partChecked
  exact List.all_eq_true.mp partChecked regionId regionMember

def Certificate.graphClosed (certificate : Certificate) : Bool :=
  certificate.graphClosureWitness.checked certificate

def resolvedReturningContract? (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary) : Option MachineImportCallContract := do
  let contract <- boundary.contract? signatures
  if contract.disposition == .returns then
    some contract
  else
    none

def machineContractPreservesRegister (contract : MachineImportCallContract)
    (register : Reg) : Bool :=
  if register == .esp then true
  else contract.preservedRegisters.contains register

def machineDependencySideChecked (pe : PE32) (imports : List PEImport)
    (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary)
    (source continuation : Span) (registers : List Reg) : Bool :=
  staticMachineImportProfilesValid pe imports required signatures &&
    boundary.valid pe imports signatures &&
    boundary.sourceSpan == source &&
    boundary.continuationRva == continuation.start &&
    match resolvedReturningContract? signatures boundary with
    | some contract =>
        required.contains contract.imported &&
          registers.all (machineContractPreservesRegister contract)
    | none => false

def MachineImportDependency.checked (dependency : MachineImportDependency)
    (certificate : Certificate) (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  match findRegion? certificate.calleeRegions dependency.sourceRegionId,
      findRegion? certificate.calleeRegions dependency.continuationRegionId with
  | some source, some continuation =>
      dependency.originalBoundary.id == dependency.id &&
        dependency.candidateBoundary.id == dependency.id &&
        machineDependencySideChecked originalPe originalImports
          dependency.originalRequired dependency.originalSignatures
          dependency.originalBoundary source.original continuation.original
          (.esp :: certificate.requestedRegisters).eraseDups &&
        machineDependencySideChecked candidatePe candidateImports
          dependency.candidateRequired dependency.candidateSignatures
          dependency.candidateBoundary source.candidate continuation.candidate
          (.esp :: certificate.requestedRegisters).eraseDups
  | _, _ => false

def machineImportTailDependencySideChecked
    (pe : PE32) (imports : List PEImport)
    (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature)
    (dependency : MachineImportTailDependency)
    (source : Span) (registers : List Reg) : Bool :=
  staticMachineImportProfilesValid pe imports required signatures &&
    match signatures.find? fun signature =>
        signature.id == dependency.signatureId with
    | none => false
    | some signature =>
        match signature.bridgeContract? dependency.argumentWords with
        | none => false
        | some contract =>
            contract.disposition == .returns &&
              required.contains contract.imported &&
              registers.all (machineContractPreservesRegister contract) &&
              match regionBehaviorWithMachineCallContracts pe imports [contract]
                  source with
              | none => false
              | some behavior =>
                  staticMachineImportJumpOutcomeValid contract.imported
                    dependency.argumentWords behavior

def MachineImportTailDependency.checked
    (dependency : MachineImportTailDependency) (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  match findRegion? certificate.calleeRegions dependency.sourceRegionId with
  | none => false
  | some source =>
      machineImportTailDependencySideChecked originalPe originalImports
          dependency.originalRequired dependency.originalSignatures dependency
          source.original (.esp :: certificate.requestedRegisters).eraseDups &&
        machineImportTailDependencySideChecked candidatePe candidateImports
          dependency.candidateRequired dependency.candidateSignatures dependency
          source.candidate (.esp :: certificate.requestedRegisters).eraseDups

def machineImportTerminalDependencySideChecked
    (pe : PE32) (imports : List PEImport)
    (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary)
    (source : Span) : Bool :=
  staticMachineImportProfilesValid pe imports required signatures &&
    boundary.valid pe imports signatures &&
    boundary.sourceSpan == source &&
    match boundary.contract? signatures with
    | none => false
    | some contract =>
        required.contains contract.imported &&
          contract.disposition == .terminates

def MachineImportTerminalDependency.checked
    (dependency : MachineImportTerminalDependency) (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  match findRegion? certificate.calleeRegions dependency.sourceRegionId with
  | none => false
  | some source =>
      dependency.originalBoundary.id == dependency.id &&
        dependency.candidateBoundary.id == dependency.id &&
        machineImportTerminalDependencySideChecked originalPe originalImports
          dependency.originalRequired dependency.originalSignatures
          dependency.originalBoundary source.original &&
        machineImportTerminalDependencySideChecked candidatePe candidateImports
          dependency.candidateRequired dependency.candidateSignatures
          dependency.candidateBoundary source.candidate

def certificateMatchesNestedDependency (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (parent : Certificate) (dependency : NestedSummaryDependency)
    (child : Certificate) : Bool :=
  match findRegion? parent.calleeRegions dependency.callRegionId,
      findRegion? parent.calleeRegions dependency.continuationRegionId with
  | some callRegion, some continuation =>
      child.summaryId == dependency.summaryId &&
        child.dependencyDepth < parent.dependencyDepth &&
        child.callsite == callRegion && child.continuation == continuation &&
        child.entryKind == .direct &&
        child.requestedRegisters.contains .esp &&
        (parent.requestedRegisters.all fun register =>
          child.requestedRegisters.contains register) &&
        match callRegion.behavior? false originalPe candidatePe
            originalImports candidateImports,
          callRegion.behavior? true originalPe candidatePe
            originalImports candidateImports with
        | some originalCall, some candidateCall =>
            behaviorCalls originalPe child.calleeEntry.original
                child.continuation.original originalCall &&
              behaviorCalls candidatePe child.calleeEntry.candidate
                child.continuation.candidate candidateCall
        | _, _ => false
  | _, _ => false

def treeMatchesNestedDependency (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (parent : Certificate) (dependency : NestedSummaryDependency)
    (tree : SummaryTree) : Bool :=
  certificateMatchesNestedDependency originalPe candidatePe
    originalImports candidateImports parent dependency tree.certificate

def certificateMatchesFiniteOriginCallTarget
    (parent : Certificate) (dependency : FiniteOriginCallDependency)
    (target : FiniteOriginCallTarget) (child : Certificate) : Bool :=
  match findRegion? parent.calleeRegions dependency.sourceRegionId,
      findRegion? parent.calleeRegions dependency.continuationRegionId with
  | some callRegion, some continuation =>
      child.summaryId == target.summaryId &&
        child.dependencyDepth < parent.dependencyDepth &&
        child.callsite == callRegion &&
        child.continuation == continuation &&
        child.calleeEntry.id == target.regionId &&
        child.entryKind == .finiteOriginCall dependency.id target.targetId &&
        child.requestedRegisters.contains .esp &&
        (parent.requestedRegisters.all fun register =>
          child.requestedRegisters.contains register)
  | _, _ => false

def treeMatchesFiniteOriginCallTarget
    (parent : Certificate) (dependency : FiniteOriginCallDependency)
    (target : FiniteOriginCallTarget) (tree : SummaryTree) : Bool :=
  certificateMatchesFiniteOriginCallTarget parent dependency target
    tree.certificate

def finiteOriginCallChildCertificatesChecked
    (parent : Certificate) (dependencies : List FiniteOriginCallDependency)
    (nested : List Certificate) : Bool :=
  dependencies.all fun dependency =>
    dependency.internalTargets.all fun target =>
      let childrenFound :=
        nested.filter fun child => child.summaryId == target.summaryId
      childrenFound.length == 1 &&
        match childrenFound.head? with
        | some child =>
            certificateMatchesFiniteOriginCallTarget parent dependency target
              child
        | none => false

def finiteOriginCallChildrenChecked
    (parent : Certificate) (dependencies : List FiniteOriginCallDependency)
    (nested : List SummaryTree) : Bool :=
  finiteOriginCallChildCertificatesChecked parent dependencies
    (nested.map SummaryTree.certificate)

def Certificate.nestedDependencyCertificatesChecked
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List Certificate) : Bool :=
  let finiteCallTargetCount :=
    (certificate.finiteOriginCallDependencies.map
      (fun dependency => dependency.internalTargets.length)).sum
  nested.length == certificate.nestedDependencies.length + finiteCallTargetCount &&
    (certificate.nestedDependencies.all fun dependency =>
      let childrenFound :=
        nested.filter fun child => child.summaryId == dependency.summaryId
      childrenFound.length == 1 &&
        match childrenFound.head? with
        | some child => certificateMatchesNestedDependency
            originalPe candidatePe originalImports candidateImports
            certificate dependency child
        | none => false) &&
    finiteOriginCallChildCertificatesChecked certificate
      certificate.finiteOriginCallDependencies nested

def Certificate.nestedDependenciesChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List SummaryTree) : Bool :=
  certificate.nestedDependencyCertificatesChecked originalPe candidatePe
    originalImports candidateImports (nested.map SummaryTree.certificate)

def inputEsp : Expr := .inputReg .esp

def registerExprOffset? (base : Reg) : Expr -> Option Word
  | .inputReg register => if register == base then some 0 else none
  | .add expression (.constant amount) =>
      if amount < 2 ^ 32 then
        (registerExprOffset? base expression).map
          (fun offset => offset + BitVec.ofNat 32 amount)
      else none
  | .sub expression (.constant amount) =>
      if amount < 2 ^ 32 then
        (registerExprOffset? base expression).map
          (fun offset => offset - BitVec.ofNat 32 amount)
      else none
  | _ => none

def stackExprOffset? (expression : Expr) : Option Word :=
  registerExprOffset? .esp expression

def StackEntryOffsetWitness.offset
    (candidate : Bool) (witness : StackEntryOffsetWitness) : Nat :=
  if candidate then witness.candidateOffset else witness.originalOffset

def findStackEntryOffset? (witnesses : List StackEntryOffsetWitness)
    (regionId : Nat) : Option StackEntryOffsetWitness :=
  witnesses.find? fun witness => witness.regionId == regionId

def stackSub (amount : Nat) : Expr :=
  if amount == 0 then inputEsp else
    .add inputEsp (.constant (2 ^ 32 - amount))

def stackAdd (amount : Nat) : Expr :=
  if amount == 0 then inputEsp else .add inputEsp (.constant amount)

def lastWriteValueAt? (writes : List (Expr × Expr)) (address : Expr) :
    Option Expr :=
  (writes.reverse.find? fun write => write.1 == address).map Prod.snd

def lastWriteValueAtStackOffset? (writes : List (Expr × Expr))
    (offset : Word) : Option Expr :=
  (writes.reverse.find? fun write =>
    stackExprOffset? write.1 == some offset).map Prod.snd

def stackSaveSideChecked (behavior : SymbolicBehavior) (register : Reg)
    (frameBytes saveOffset : Nat) : Bool :=
  frameBytes > 0 && frameBytes % 4 == 0 && frameBytes < 2 ^ 32 &&
    saveOffset > 0 && saveOffset % 4 == 0 && saveOffset <= frameBytes &&
    behavior.registers.esp == stackSub frameBytes &&
    behavior.writes == [(stackSub saveOffset, .inputReg register)]

def pendingCallFrameBytes : Option OutcomeExpr -> Nat
  | some (.call _ _ _) => 4
  | some (.indirectCall _ _ _) => 4
  | _ => 0

def stackFrameSaveSideChecked (behavior : SymbolicBehavior) (register : Reg)
    (frameBytes saveOffset : Nat) : Bool :=
  let effectiveFrameBytes := frameBytes + pendingCallFrameBytes behavior.outcome
  frameBytes > 0 && frameBytes % 4 == 0 && frameBytes < 2 ^ 32 &&
    effectiveFrameBytes < 2 ^ 32 &&
    saveOffset > 0 && saveOffset % 4 == 0 && saveOffset <= frameBytes &&
    stackExprOffset? behavior.registers.esp ==
      some (0 - BitVec.ofNat 32 effectiveFrameBytes) &&
    lastWriteValueAtStackOffset? behavior.writes
        (0 - BitVec.ofNat 32 saveOffset) ==
      some (.inputReg register)

def stackRead32Offset? : Expr -> Option Word
  | .read32 address => stackExprOffset? address
  | _ => none

def registerRead32Offset? (base : Reg) : Expr -> Option Word
  | .read32 address => registerExprOffset? base address
  | _ => none

def returnedStackRead32Offset? : Option OutcomeExpr -> Option Word
  | some (.returned (.read32 address)) => stackExprOffset? address
  | _ => none

def returnedRegisterRead32Offset? (base : Reg) : Option OutcomeExpr -> Option Word
  | some (.returned (.read32 address)) => registerExprOffset? base address
  | _ => none

/-- Canonical affine address used by the symbolic decoder for a register plus
one wrapped IA-32 offset. -/
def registerOffsetExpr (base : Reg) (offset : Word) : Expr :=
  if offset == 0 then .inputReg base
  else .add (.inputReg base) (.constant offset.toNat)

def symbolicRead32FromWrites (writes : List (Expr × Expr))
    (address : Expr) : Expr :=
  symbolicRead32 { initialSymbolic with writes := writes } address

/-- Exact restore shape when a preceding decoded write could alias the load.
This is only a symbolic-expression check.  The protected-write inventory and
semantic composition must still prove that the writes avoid the saved word. -/
def registerRestoreAfterWritesChecked (behavior : SymbolicBehavior)
    (register base : Reg) (offset : Word) : Bool :=
  !behavior.writes.isEmpty &&
    behavior.registers.get register ==
      symbolicRead32FromWrites behavior.writes (registerOffsetExpr base offset)

def returnedRegisterAfterWritesChecked (behavior : SymbolicBehavior)
    (base : Reg) (offset : Word) : Bool :=
  !behavior.writes.isEmpty &&
    behavior.outcome ==
      some (.returned (symbolicRead32FromWrites behavior.writes
        (registerOffsetExpr base offset)))

def stackRestoreSideChecked (behavior : SymbolicBehavior) (register : Reg)
    (entryOffset saveOffset : Nat) : Bool :=
  stackRead32Offset? (behavior.registers.get register) ==
      some (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 entryOffset)) &&
    stackExprOffset? behavior.registers.esp ==
      some (BitVec.ofNat 32 4 - BitVec.ofNat 32 entryOffset) &&
    returnedStackRead32Offset? behavior.outcome ==
      some (0 - BitVec.ofNat 32 entryOffset)

def stackRestoreAfterWritesSideChecked (behavior : SymbolicBehavior)
    (register : Reg) (entryOffset saveOffset : Nat) : Bool :=
  registerRestoreAfterWritesChecked behavior register .esp
      (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 entryOffset)) &&
    stackExprOffset? behavior.registers.esp ==
      some (BitVec.ofNat 32 4 - BitVec.ofNat 32 entryOffset) &&
    returnedRegisterAfterWritesChecked behavior .esp
      (0 - BitVec.ofNat 32 entryOffset)

def stackTailRestoreSideChecked (behavior : SymbolicBehavior) (register : Reg)
    (entryOffset saveOffset : Nat) : Bool :=
  stackRead32Offset? (behavior.registers.get register) ==
      some (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 entryOffset)) &&
    stackExprOffset? behavior.registers.esp ==
      some (0 - BitVec.ofNat 32 entryOffset) &&
    match behavior.outcome with
    | some (.jump _) => true
    | _ => false

def stackTailRestoreAfterWritesSideChecked (behavior : SymbolicBehavior)
    (register : Reg) (entryOffset saveOffset : Nat) : Bool :=
  registerRestoreAfterWritesChecked behavior register .esp
      (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 entryOffset)) &&
    stackExprOffset? behavior.registers.esp ==
      some (0 - BitVec.ofNat 32 entryOffset) &&
    match behavior.outcome with
    | some (.jump _) => true
    | _ => false

def anchoredStackRestoreSideChecked (behavior : SymbolicBehavior)
    (register anchor : Reg) (anchorOffset saveOffset : Nat) : Bool :=
  registerRead32Offset? anchor (behavior.registers.get register) ==
      some (0 - (BitVec.ofNat 32 saveOffset +
        BitVec.ofNat 32 anchorOffset)) &&
    registerExprOffset? anchor behavior.registers.esp ==
      some (BitVec.ofNat 32 4 - BitVec.ofNat 32 anchorOffset) &&
    returnedRegisterRead32Offset? anchor behavior.outcome ==
      some (0 - BitVec.ofNat 32 anchorOffset)

def anchoredStackRestoreAfterWritesSideChecked (behavior : SymbolicBehavior)
    (register anchor : Reg) (anchorOffset saveOffset : Nat) : Bool :=
  registerRestoreAfterWritesChecked behavior register anchor
      (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 anchorOffset)) &&
    registerExprOffset? anchor behavior.registers.esp ==
      some (BitVec.ofNat 32 4 - BitVec.ofNat 32 anchorOffset) &&
    returnedRegisterAfterWritesChecked behavior anchor
      (0 - BitVec.ofNat 32 anchorOffset)

def anchoredStackTailRestoreSideChecked (behavior : SymbolicBehavior)
    (register anchor : Reg) (anchorOffset saveOffset : Nat) : Bool :=
  registerRead32Offset? anchor (behavior.registers.get register) ==
      some (0 - (BitVec.ofNat 32 saveOffset +
        BitVec.ofNat 32 anchorOffset)) &&
    registerExprOffset? anchor behavior.registers.esp ==
      some (0 - BitVec.ofNat 32 anchorOffset) &&
    match behavior.outcome with
    | some (.jump _) => true
    | _ => false

def anchoredStackTailRestoreAfterWritesSideChecked (behavior : SymbolicBehavior)
    (register anchor : Reg) (anchorOffset saveOffset : Nat) : Bool :=
  registerRestoreAfterWritesChecked behavior register anchor
      (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 anchorOffset)) &&
    registerExprOffset? anchor behavior.registers.esp ==
      some (0 - BitVec.ofNat 32 anchorOffset) &&
    match behavior.outcome with
    | some (.jump _) => true
    | _ => false

def dependencySourceIds (certificate : Certificate) : List Nat :=
  certificate.nestedDependencies.map (fun dependency => dependency.callRegionId) ++
    certificate.machineImportDependencies.map
      (fun dependency => dependency.sourceRegionId) ++
    certificate.machineImportTailDependencies.map
      (fun dependency => dependency.sourceRegionId) ++
    certificate.machineImportTerminalDependencies.map
      (fun dependency => dependency.sourceRegionId) ++
    certificate.finiteOriginCallDependencies.map
      (fun dependency => dependency.sourceRegionId) ++
    certificate.finiteOriginTailDependencies.map
      (fun dependency => dependency.sourceRegionId)

def ordinaryReturnEntries (certificate : Certificate) :
    List ReturnInventoryEntry :=
  let finiteTailSources :=
    certificate.finiteOriginTailDependencies.map
      (fun dependency => dependency.sourceRegionId)
  let machineTailSources :=
    certificate.machineImportTailDependencies.map
      (fun dependency => dependency.sourceRegionId)
  certificate.returns.filter fun entry =>
    !finiteTailSources.contains entry.returnRegionId &&
      !machineTailSources.contains entry.returnRegionId

def directTailEdges (certificate : Certificate) : List CalleeEdge :=
  certificate.edges.filter fun edge => edge.kind == .directTail

def machineImportTailEdges (certificate : Certificate) : List CalleeEdge :=
  certificate.edges.filter fun edge =>
    match edge.kind with
    | .machineImportTail _ => true
    | _ => false

def frameTailHandoffEdges (certificate : Certificate) : List CalleeEdge :=
  directTailEdges certificate ++ machineImportTailEdges certificate

def frameLocalEdges (certificate : Certificate) : List CalleeEdge :=
  certificate.edges.filter fun edge => edge.kind != .directTail

def findStackFrameAnchor? (certificate : Certificate)
    (frameEntryRegionId : Nat) : Option StackFrameAnchorWitness :=
  certificate.stackFrameAnchors.find? fun witness =>
    witness.frameEntryRegionId == frameEntryRegionId

def stackFrameAnchorsForRegion (certificate : Certificate)
    (regionId : Nat) : List StackFrameAnchorWitness :=
  certificate.stackFrameAnchors.filter fun witness =>
    reachesWithin (frameLocalEdges certificate)
      certificate.calleeRegions.length witness.frameEntryRegionId regionId

def findStackFrameAnchorForRegion? (certificate : Certificate)
    (regionId : Nat) : Option StackFrameAnchorWitness :=
  match stackFrameAnchorsForRegion certificate regionId with
  | [witness] => some witness
  | _ => none

def StackSaveRestoreWitness.rootFrame
    (witness : StackSaveRestoreWitness) : StackSaveRestoreFrameWitness := {
  saveRegionId := witness.saveRegionId
  restoreRegionIds := witness.restoreRegionIds
  originalFrameBytes := witness.originalFrameBytes
  candidateFrameBytes := witness.candidateFrameBytes
  originalSaveOffset := witness.originalSaveOffset
  candidateSaveOffset := witness.candidateSaveOffset
}

def StackSaveRestoreWitness.frames
    (witness : StackSaveRestoreWitness) : List StackSaveRestoreFrameWitness :=
  witness.rootFrame :: witness.additionalFrames

def stackFrameSaveIds (witness : StackSaveRestoreWitness) : List Nat :=
  witness.frames.map (fun frame => frame.saveRegionId)

def stackFrameRestoreIds (witness : StackSaveRestoreWitness) : List Nat :=
  witness.frames.flatMap (fun frame => frame.restoreRegionIds)

def certificateFrameRestoreIds (certificate : Certificate)
    (frameEntryRegionId : Nat) : List Nat :=
  (certificate.stackWitnesses.flatMap fun witness =>
    witness.frames.filter (fun frame =>
      frame.saveRegionId == frameEntryRegionId) |>.flatMap
        (fun frame => frame.restoreRegionIds)).eraseDups

def StackFrameAnchorWitness.entrySideChecked
    (witness : StackFrameAnchorWitness) (certificate : Certificate)
    (candidate : Bool) (pe : PE32) (imports : List PEImport) : Bool :=
  witness.offset candidate < 2 ^ 32 &&
    certificate.requestedRegisters.contains witness.register &&
    match findRegion? certificate.calleeRegions witness.frameEntryRegionId with
    | none => false
    | some region =>
        match regionBehaviorWithImports pe imports (region.span candidate) with
        | none => false
        | some behavior =>
            stackExprOffset? (behavior.registers.get witness.register) ==
              some (BitVec.ofNat 32 (witness.offset candidate))

def StackFrameAnchorWitness.interiorSideChecked
    (witness : StackFrameAnchorWitness) (certificate : Certificate)
    (candidate : Bool) (pe : PE32) (imports : List PEImport) : Bool :=
  let exits :=
    certificateFrameRestoreIds certificate witness.frameEntryRegionId
  let dependencySources := dependencySourceIds certificate
  certificate.calleeRegions.all fun region =>
    if !reachesWithin (frameLocalEdges certificate)
        certificate.calleeRegions.length witness.frameEntryRegionId region.id ||
        region.id == witness.frameEntryRegionId ||
        exits.contains region.id ||
        dependencySources.contains region.id then
      true
    else
      match regionBehaviorWithImports pe imports (region.span candidate) with
      | some behavior =>
          behavior.registers.get witness.register == .inputReg witness.register
      | none => stateOnlyX87RegionChecked pe (region.span candidate)

def StackFrameAnchorWitness.checked
    (witness : StackFrameAnchorWitness) (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  let expectedEntries :=
    certificate.calleeEntry.id ::
      (directTailEdges certificate).map (fun edge => edge.targetRegionId)
  expectedEntries.contains witness.frameEntryRegionId &&
    !(certificateFrameRestoreIds certificate
      witness.frameEntryRegionId).isEmpty &&
    witness.entrySideChecked certificate false originalPe originalImports &&
    witness.entrySideChecked certificate true candidatePe candidateImports &&
    witness.interiorSideChecked certificate false originalPe originalImports &&
    witness.interiorSideChecked certificate true candidatePe candidateImports

def stackInteriorSideChecked (certificate : Certificate) (candidate : Bool)
    (pe : PE32) (imports : List PEImport)
    (witness : StackSaveRestoreWitness) : Bool :=
  let dependencySources := dependencySourceIds certificate
  let saveIds := stackFrameSaveIds witness
  let restoreIds := stackFrameRestoreIds witness
  certificate.calleeRegions.all fun region =>
    if saveIds.contains region.id ||
        restoreIds.contains region.id ||
        dependencySources.contains region.id then
      true
    else
      match regionBehaviorWithImports pe imports (region.span candidate) with
      | some behavior =>
          (certificate.stackEntryOffsets.isEmpty == false ||
            behavior.registers.esp == inputEsp)
      | none => stateOnlyX87RegionChecked pe (region.span candidate)

/-- Memory-writing instructions represented by a stopping outcome do not add
an ordinary symbolic write.  Keep the protected-slot inventory aligned with
both exact write representations.  Imported and nested calls are checked by
their dependency contracts and are intentionally not classified here. -/
def behaviorHasInternalMemoryWrite (behavior : SymbolicBehavior) : Bool :=
  !behavior.writes.isEmpty ||
    match behavior.outcome with
    | some (.bulkCopy ..) | some (.atomicCompareExchange ..) => true
    | _ => false

def protectedWriteRegionsSideChecked (certificate : Certificate)
    (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (witness : StackSaveRestoreWitness) : Bool :=
  decide witness.protectedWriteRegionIds.Nodup &&
    (witness.protectedWriteRegionIds.all fun regionId =>
      !(stackFrameSaveIds witness).contains regionId &&
        !(stackFrameRestoreIds witness).contains regionId &&
        (findRegion? certificate.calleeRegions regionId).isSome) &&
    let dependencySources := dependencySourceIds certificate
    let saveIds := stackFrameSaveIds witness
    let restoreIds := stackFrameRestoreIds witness
    certificate.calleeRegions.all fun region =>
      if saveIds.contains region.id ||
          restoreIds.contains region.id ||
          dependencySources.contains region.id then
        true
      else
        match regionBehaviorWithImports pe imports (region.span candidate) with
        | none =>
            stateOnlyX87RegionChecked pe (region.span candidate) &&
              !witness.protectedWriteRegionIds.contains region.id
        | some behavior =>
            behaviorHasInternalMemoryWrite behavior ==
              witness.protectedWriteRegionIds.contains region.id

/-- Check the two region-wide stack-witness predicates from one exact
symbolic behavior.  This avoids decoding and evaluating every region once for
write classification and again for stack-interior preservation. -/
def stackWitnessRegionSideChecked (certificate : Certificate)
    (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (witness : StackSaveRestoreWitness) (region : ExactRegionPair) : Bool :=
  let dependencySources := dependencySourceIds certificate
  let saveIds := stackFrameSaveIds witness
  let restoreIds := stackFrameRestoreIds witness
  if saveIds.contains region.id ||
      restoreIds.contains region.id ||
      dependencySources.contains region.id then
    true
  else
    match regionBehaviorWithImports pe imports (region.span candidate) with
    | none =>
        stateOnlyX87RegionChecked pe (region.span candidate) &&
          !witness.protectedWriteRegionIds.contains region.id
    | some behavior =>
        (behaviorHasInternalMemoryWrite behavior ==
          witness.protectedWriteRegionIds.contains region.id) &&
        (certificate.stackEntryOffsets.isEmpty == false ||
          behavior.registers.esp == inputEsp)

def stackWitnessRegionPartSideChecked (certificate : Certificate)
    (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (witness : StackSaveRestoreWitness)
    (regions : List ExactRegionPair) : Bool :=
  regions.all fun region =>
    stackWitnessRegionSideChecked certificate candidate pe imports witness region

def stackWitnessRegionsSideChecked (certificate : Certificate)
    (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (witness : StackSaveRestoreWitness) : Bool :=
  stackWitnessRegionPartSideChecked certificate candidate pe imports witness
    certificate.calleeRegions

theorem stackWitnessRegionsSideChecked_of_parts
    (certificate : Certificate) (candidate : Bool)
    (pe : PE32) (imports : List PEImport)
    (witness : StackSaveRestoreWitness)
    (parts : List (List ExactRegionPair))
    (regionsBound : parts.flatten = certificate.calleeRegions)
    (partsChecked :
      parts.all (fun part =>
        stackWitnessRegionPartSideChecked certificate candidate pe imports
          witness part) = true) :
    stackWitnessRegionsSideChecked certificate candidate pe imports witness =
      true := by
  unfold stackWitnessRegionsSideChecked stackWitnessRegionPartSideChecked
  rw [← regionsBound]
  exact listAll_flatten_of_parts parts
    (fun region =>
      stackWitnessRegionSideChecked certificate candidate pe imports witness
        region)
    partsChecked

def machineDependencyHasProtectedEffect (candidate : Bool)
    (dependency : MachineImportDependency) : Bool :=
  let signatures :=
    if candidate then dependency.candidateSignatures
    else dependency.originalSignatures
  let boundary :=
    if candidate then dependency.candidateBoundary
    else dependency.originalBoundary
  match resolvedReturningContract? signatures boundary with
  | none => false
  | some contract =>
      !(contract.memoryEffect == .none || contract.memoryEffect == .readOnly)

def protectedMachineImportDependenciesSideChecked (certificate : Certificate)
    (candidate : Bool) (witness : StackSaveRestoreWitness) : Bool :=
  decide witness.protectedMachineImportDependencyIds.Nodup &&
    (witness.protectedMachineImportDependencyIds.all fun dependencyId =>
      (certificate.machineImportDependencies.find? fun dependency =>
        dependency.id == dependencyId).isSome) &&
    (certificate.machineImportDependencies.all fun dependency =>
      witness.protectedMachineImportDependencyIds.contains dependency.id ==
        machineDependencyHasProtectedEffect candidate dependency)

def StackSaveRestoreFrameWitness.restoreSideChecked
    (frame : StackSaveRestoreFrameWitness) (register : Reg)
    (certificate : Certificate) (candidate : Bool)
    (pe : PE32) (imports : List PEImport) (restoreId : Nat) : Bool :=
  let tailEdges :=
    (frameTailHandoffEdges certificate).filter fun edge =>
      edge.sourceRegionId == restoreId
  match findRegion? certificate.calleeRegions restoreId with
  | none => false
  | some restore =>
      match regionBehaviorWithImports pe imports (restore.span candidate) with
      | none => false
      | some behavior =>
          let saveOffset :=
            if candidate then frame.candidateSaveOffset
            else frame.originalSaveOffset
          match findStackFrameAnchor? certificate frame.saveRegionId with
          | some anchor =>
              if tailEdges.isEmpty then
                anchoredStackRestoreSideChecked behavior register anchor.register
                    (anchor.offset candidate) saveOffset ||
                  anchoredStackRestoreAfterWritesSideChecked behavior register
                    anchor.register (anchor.offset candidate) saveOffset
              else
                tailEdges.length == 1 &&
                  (anchoredStackTailRestoreSideChecked behavior register
                      anchor.register (anchor.offset candidate) saveOffset ||
                    anchoredStackTailRestoreAfterWritesSideChecked behavior register
                      anchor.register (anchor.offset candidate) saveOffset)
          | none =>
              match findStackEntryOffset? certificate.stackEntryOffsets restoreId with
              | some entryOffset =>
                  if tailEdges.isEmpty then
                    stackRestoreSideChecked behavior register
                        (entryOffset.offset candidate) saveOffset ||
                      stackRestoreAfterWritesSideChecked behavior register
                        (entryOffset.offset candidate) saveOffset
                  else
                    tailEdges.length == 1 &&
                      (stackTailRestoreSideChecked behavior register
                          (entryOffset.offset candidate) saveOffset ||
                        stackTailRestoreAfterWritesSideChecked behavior register
                          (entryOffset.offset candidate) saveOffset)
              | none =>
                  tailEdges.isEmpty &&
                    (stackRestoreSideChecked behavior register
                        (2 ^ 32 - (if candidate then
                          frame.candidateFrameBytes else frame.originalFrameBytes))
                        saveOffset ||
                      stackRestoreAfterWritesSideChecked behavior register
                        (2 ^ 32 - (if candidate then
                          frame.candidateFrameBytes else frame.originalFrameBytes))
                        saveOffset)

def StackSaveRestoreFrameWitness.sideChecked
    (frame : StackSaveRestoreFrameWitness) (register : Reg)
    (certificate : Certificate) (candidate : Bool)
    (pe : PE32) (imports : List PEImport) : Bool :=
  decide frame.restoreRegionIds.Nodup &&
    !frame.restoreRegionIds.isEmpty &&
    match findRegion? certificate.calleeRegions frame.saveRegionId with
    | none => false
    | some save =>
        match regionBehaviorWithImports pe imports (save.span candidate) with
        | none => false
        | some saveBehavior =>
            stackFrameSaveSideChecked saveBehavior register
                (if candidate then frame.candidateFrameBytes
                  else frame.originalFrameBytes)
                (if candidate then frame.candidateSaveOffset
                  else frame.originalSaveOffset) &&
              frame.restoreRegionIds.all fun restoreId =>
                frame.restoreSideChecked register certificate candidate pe imports
                  restoreId

def StackSaveRestoreWitness.frameTopologyChecked
    (witness : StackSaveRestoreWitness) (certificate : Certificate) : Bool :=
  let frames := witness.frames
  let saveIds := stackFrameSaveIds witness
  let restoreIds := stackFrameRestoreIds witness
  let tails := directTailEdges certificate
  let externalTails := machineImportTailEdges certificate
  let expectedSaveIds :=
    certificate.calleeEntry.id ::
      (tails.map (fun edge => edge.targetRegionId)).eraseDups
  let expectedRestoreIds :=
      (ordinaryReturnEntries certificate).map
        (fun entry => entry.returnRegionId) ++
      tails.map (fun edge => edge.sourceRegionId) ++
      externalTails.map (fun edge => edge.sourceRegionId)
  !frames.isEmpty &&
    decide saveIds.Nodup &&
    decide restoreIds.Nodup &&
    saveIds.length == expectedSaveIds.length &&
    expectedSaveIds.all (fun id => saveIds.contains id) &&
    restoreIds.length == expectedRestoreIds.length &&
    expectedRestoreIds.all (fun id => restoreIds.contains id) &&
    witness.saveRegionId == certificate.calleeEntry.id &&
    witness.originalFrameBytes == certificate.originalFrameBytes &&
    witness.candidateFrameBytes == certificate.candidateFrameBytes &&
    (tails.all fun edge =>
      restoreIds.contains edge.sourceRegionId &&
        saveIds.contains edge.targetRegionId) &&
    (externalTails.all fun edge =>
      restoreIds.contains edge.sourceRegionId)

def StackSaveRestoreWitness.nonRegionalChecked
    (witness : StackSaveRestoreWitness)
    (certificate : Certificate) (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  witness.register != .esp && certificate.requestedRegisters.contains witness.register &&
    witness.frameTopologyChecked certificate &&
    decide witness.protectedWriteRegionIds.Nodup &&
    decide witness.protectedMachineImportDependencyIds.Nodup &&
    protectedMachineImportDependenciesSideChecked certificate false witness &&
    protectedMachineImportDependenciesSideChecked certificate true witness &&
    (witness.frames.all fun frame =>
      frame.sideChecked witness.register certificate false originalPe
        originalImports) &&
    (witness.frames.all fun frame =>
      frame.sideChecked witness.register certificate true candidatePe
        candidateImports)

def StackSaveRestoreWitness.checked (witness : StackSaveRestoreWitness)
    (certificate : Certificate) (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  witness.nonRegionalChecked certificate originalPe candidatePe
      originalImports candidateImports &&
    stackWitnessRegionsSideChecked certificate false originalPe originalImports
      witness &&
    stackWitnessRegionsSideChecked certificate true candidatePe candidateImports
      witness

theorem StackSaveRestoreWitness.checked_of_region_parts
    (witness : StackSaveRestoreWitness)
    (certificate : Certificate) (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nonRegional :
      witness.nonRegionalChecked certificate originalPe candidatePe
        originalImports candidateImports = true)
    (originalRegions :
      stackWitnessRegionsSideChecked certificate false originalPe
        originalImports witness = true)
    (candidateRegions :
      stackWitnessRegionsSideChecked certificate true candidatePe
        candidateImports witness = true) :
    witness.checked certificate originalPe candidatePe
      originalImports candidateImports = true := by
  simp [StackSaveRestoreWitness.checked, nonRegional, originalRegions,
    candidateRegions]

def regionIdentitySideChecked (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg) : Bool :=
  match regionBehaviorWithImports pe imports (region.span candidate) with
  | some behavior => behavior.registers.get register == .inputReg register
  | none => false

def summaryRegionIdentitySideChecked (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg) : Bool :=
  match regionBehaviorWithImports pe imports (region.span candidate) with
  | some behavior => behavior.registers.get register == .inputReg register
  | none => stateOnlyX87RegionChecked pe (region.span candidate)

def Certificate.identityRegisterChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) (register : Reg) : Bool :=
  certificate.calleeRegions.all fun region =>
    summaryRegionIdentitySideChecked originalPe originalImports false region
        register &&
      summaryRegionIdentitySideChecked candidatePe candidateImports true region
        register

def returnStackSideChecked (behavior : SymbolicBehavior) (frameBytes : Nat) : Bool :=
  behavior.registers.esp == stackAdd (frameBytes + 4) &&
    behavior.writes.isEmpty &&
    match behavior.outcome with
    | some (.returned target) => target == .read32 (stackAdd frameBytes)
    | _ => false

def macroStepStackExpr? (behavior : SymbolicBehavior) : Option Expr :=
  match behavior.outcome with
  | some (.call _ _ _) | some (.indirectCall _ _ _) =>
      callPushBase? behavior.registers.esp
  | _ => some behavior.registers.esp

def machineDependencyStackDelta?
    (candidate : Bool) (dependency : MachineImportDependency) :
    Option Nat := do
  let signatures :=
    if candidate then dependency.candidateSignatures
    else dependency.originalSignatures
  let boundary :=
    if candidate then dependency.candidateBoundary
    else dependency.originalBoundary
  let contract <- resolvedReturningContract? signatures boundary
  pure contract.stackResultDelta

def machineTailDependencyStackDelta?
    (candidate : Bool) (dependency : MachineImportTailDependency) :
    Option Nat := do
  let signature <- dependency.signature? candidate
  let contract <- signature.bridgeContract? dependency.argumentWords
  if contract.disposition == .returns then
    pure (4 + contract.stackResultDelta)
  else
    none

inductive StackOffsetResult where
  | fixed (offset : Word)
  | dynamic
deriving Repr, DecidableEq

def dynamicAnchoredStackExpression (anchor : Reg) : Expr -> Bool
  | .sub base (.inputReg amountRegister) =>
      (stackExprOffset? base).isSome && amountRegister != .esp
  | .read32 address => (registerExprOffset? anchor address).isSome
  | _ => false

def regionStackResultOffset? (certificate : Certificate) (candidate : Bool)
    (region : ExactRegionPair) (source : StackEntryOffsetWitness)
    (behavior : SymbolicBehavior) : Option StackOffsetResult := do
  let stackExpression <- macroStepStackExpr? behavior
  let internalResult <-
    match registerExprOffset? .esp stackExpression with
    | some localOffset =>
        if certificate.dynamicStackEntryRegionIds.contains region.id then
          some StackOffsetResult.dynamic
        else
          some (.fixed
            (BitVec.ofNat 32 (source.offset candidate) + localOffset))
    | none => do
        let anchor <- findStackFrameAnchorForRegion? certificate region.id
        match registerExprOffset? anchor.register stackExpression with
        | some localOffset =>
            pure (.fixed
              (BitVec.ofNat 32 (anchor.offset candidate) + localOffset))
        | none =>
            if dynamicAnchoredStackExpression anchor.register stackExpression then
              pure .dynamic
            else none
  match machineDependenciesAt certificate.machineImportDependencies region.id,
      machineTailDependenciesAt certificate.machineImportTailDependencies region.id with
  | [], [] => pure internalResult
  | [dependency], [] => do
      let external <- machineDependencyStackDelta? candidate dependency
      match internalResult with
      | .fixed offset =>
          pure (.fixed (offset + BitVec.ofNat 32 external))
      | .dynamic => pure .dynamic
  | [], [dependency] => do
      let external <- machineTailDependencyStackDelta? candidate dependency
      match internalResult with
      | .fixed offset =>
          pure (.fixed (offset + BitVec.ofNat 32 external))
      | .dynamic => pure .dynamic
  | _, _ => none

def summaryRegionStackResultOffset? (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool)
    (region : ExactRegionPair) (source : StackEntryOffsetWitness) :
    Option StackOffsetResult :=
  match regionBehaviorWithImports pe imports (region.span candidate) with
  | some behavior =>
      regionStackResultOffset? certificate candidate region source behavior
  | none =>
      if stateOnlyX87RegionChecked pe (region.span candidate) then
        some (.fixed (BitVec.ofNat 32 (source.offset candidate)))
      else
        none

def FiniteOriginTailDependency.stackOffsetsChecked
    (dependency : FiniteOriginTailDependency) (certificate : Certificate)
    (candidate : Bool) (source : StackEntryOffsetWitness)
    (internalResult : StackOffsetResult) : Bool :=
  match internalResult with
  | .dynamic => false
  | .fixed offset =>
      let internalChecked :=
        (outgoingEdges certificate.edges dependency.sourceRegionId).all fun edge =>
          match findStackEntryOffset? certificate.stackEntryOffsets edge.targetRegionId with
          | some target =>
              !certificate.dynamicStackEntryRegionIds.contains edge.targetRegionId &&
                BitVec.ofNat 32 (target.offset candidate) == offset
          | none => false
      let externalChecked :=
        dependency.route.externalRoutes.all fun external =>
          offset + BitVec.ofNat 32 external.abi.stackResultDelta ==
            BitVec.ofNat 32 4
      internalChecked && externalChecked

def Certificate.stackEntryOffsetsAlignedSideChecked
    (certificate : Certificate) (candidate : Bool) : Bool :=
  certificate.stackEntryOffsets.length == certificate.calleeRegions.length &&
    (certificate.stackEntryOffsets.zip certificate.calleeRegions).all
      (fun entry =>
        entry.1.regionId == entry.2.id &&
          entry.1.offset candidate < 2 ^ 32)

def Certificate.stackEntryOffsetsMembershipSideChecked
    (certificate : Certificate) (candidate : Bool) : Bool :=
  certificate.stackEntryOffsets.length == certificate.calleeRegions.length &&
    (certificate.stackEntryOffsets.all fun witness =>
      witness.offset candidate < 2 ^ 32 &&
        (findRegion? certificate.calleeRegions witness.regionId).isSome)

def Certificate.stackEntryOffsetsInventorySideChecked
    (certificate : Certificate) (candidate : Bool) : Bool :=
  stackEntryOffsetIdsUnique certificate.stackEntryOffsets &&
    decide certificate.dynamicStackEntryRegionIds.Nodup &&
    (certificate.dynamicStackEntryRegionIds.all fun regionId =>
      regionId != certificate.calleeEntry.id &&
        (findRegion? certificate.calleeRegions regionId).isSome &&
        (findStackFrameAnchorForRegion? certificate regionId).isSome) &&
    (certificate.stackEntryOffsetsAlignedSideChecked candidate ||
      certificate.stackEntryOffsetsMembershipSideChecked candidate) &&
    match findStackEntryOffset? certificate.stackEntryOffsets
        certificate.calleeEntry.id with
    | none => false
    | some entry => entry.offset candidate == 0

def Certificate.stackEntryOffsetRegionSideChecked
    (certificate : Certificate) (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) : Bool :=
  match findStackEntryOffset? certificate.stackEntryOffsets region.id with
  | some source =>
      match summaryRegionStackResultOffset? certificate pe imports
          candidate region source with
      | none => false
      | some result =>
          match finiteOriginTailDependenciesAt
              certificate.finiteOriginTailDependencies region.id with
          | [dependency] =>
              dependency.stackOffsetsChecked certificate candidate source result
          | [] =>
              match result with
              | .fixed offset =>
                  if (certificate.returns.map
                      (fun returned =>
                        returned.returnRegionId)).contains region.id then
                    offset == BitVec.ofNat 32 4
                  else
                    (outgoingEdges certificate.edges region.id).all fun edge =>
                      match findStackEntryOffset?
                          certificate.stackEntryOffsets edge.targetRegionId with
                      | some target =>
                          !certificate.dynamicStackEntryRegionIds.contains
                              edge.targetRegionId &&
                            BitVec.ofNat 32 (target.offset candidate) == offset
                      | none => false
              | .dynamic =>
                  !(certificate.returns.map
                      (fun returned =>
                        returned.returnRegionId)).contains region.id &&
                    (outgoingEdges certificate.edges region.id).all
                      (fun edge =>
                        certificate.dynamicStackEntryRegionIds.contains
                          edge.targetRegionId)
          | _ => false
  | none => false

def Certificate.stackEntryOffsetsSideChecked (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool) : Bool :=
  certificate.stackEntryOffsetsInventorySideChecked candidate &&
    certificate.calleeRegions.all fun region =>
      certificate.stackEntryOffsetRegionSideChecked pe imports candidate region

def Certificate.stackPointerFrameRegionSideChecked
    (certificate : Certificate) (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) : Bool :=
  let dependencySources := dependencySourceIds certificate
  let frameBytes :=
    if candidate then certificate.candidateFrameBytes
    else certificate.originalFrameBytes
  if dependencySources.contains region.id then true else
    match regionBehaviorWithImports pe imports (region.span candidate) with
    | none =>
        region.id != certificate.calleeEntry.id &&
          !(certificate.returns.map
            (fun entry => entry.returnRegionId)).contains region.id &&
          stateOnlyX87RegionChecked pe (region.span candidate)
    | some behavior =>
        if region.id == certificate.calleeEntry.id then
          behavior.registers.esp == stackSub frameBytes
        else if (certificate.returns.map
            (fun entry => entry.returnRegionId)).contains region.id then
          returnStackSideChecked behavior frameBytes
        else
          behavior.registers.esp == inputEsp && behavior.writes.isEmpty

def Certificate.stackPointerFrameSideChecked (certificate : Certificate)
    (pe : PE32) (imports : List PEImport) (candidate : Bool) : Bool :=
  certificate.calleeRegions.all fun region =>
    certificate.stackPointerFrameRegionSideChecked pe imports candidate region

def Certificate.frameShapeChecked (certificate : Certificate) : Bool :=
  certificate.originalFrameBytes < 2 ^ 32 &&
    certificate.candidateFrameBytes < 2 ^ 32 &&
    certificate.originalFrameBytes % 4 == 0 &&
    certificate.candidateFrameBytes % 4 == 0

def Certificate.stackPointerInventorySideChecked
    (certificate : Certificate) (candidate : Bool) : Bool :=
  if certificate.stackEntryOffsets.isEmpty then true
  else certificate.stackEntryOffsetsInventorySideChecked candidate

def Certificate.stackPointerRegionSideChecked
    (certificate : Certificate) (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) : Bool :=
  if certificate.stackEntryOffsets.isEmpty then
    certificate.stackPointerFrameRegionSideChecked pe imports candidate region
  else
    certificate.stackEntryOffsetRegionSideChecked pe imports candidate region

def Certificate.stackPointerRegionPartSideChecked
    (certificate : Certificate) (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (regions : List ExactRegionPair) : Bool :=
  regions.all fun region =>
    certificate.stackPointerRegionSideChecked pe imports candidate region

def Certificate.stackPointerRegionsSideChecked
    (certificate : Certificate) (pe : PE32) (imports : List PEImport)
    (candidate : Bool) : Bool :=
  certificate.stackPointerRegionPartSideChecked pe imports candidate
    certificate.calleeRegions

theorem Certificate.stackPointerRegionsSideChecked_of_parts
    (certificate : Certificate) (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (parts : List (List ExactRegionPair))
    (regionsBound : parts.flatten = certificate.calleeRegions)
    (partsChecked :
      parts.all (fun part =>
        certificate.stackPointerRegionPartSideChecked pe imports candidate
          part) = true) :
    certificate.stackPointerRegionsSideChecked pe imports candidate = true := by
  unfold Certificate.stackPointerRegionsSideChecked
    Certificate.stackPointerRegionPartSideChecked
  rw [← regionsBound]
  exact listAll_flatten_of_parts parts
    (fun region =>
      certificate.stackPointerRegionSideChecked pe imports candidate region)
    partsChecked

def Certificate.stackPointerPreservedChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  certificate.stackPointerInventorySideChecked false &&
    certificate.stackPointerInventorySideChecked true &&
    certificate.stackPointerRegionsSideChecked originalPe originalImports false &&
    certificate.stackPointerRegionsSideChecked candidatePe candidateImports true

theorem Certificate.stackPointerPreservedChecked_of_region_parts
    (certificate : Certificate) (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (originalInventory :
      certificate.stackPointerInventorySideChecked false = true)
    (candidateInventory :
      certificate.stackPointerInventorySideChecked true = true)
    (originalRegions :
      certificate.stackPointerRegionsSideChecked originalPe originalImports
        false = true)
    (candidateRegions :
      certificate.stackPointerRegionsSideChecked candidatePe candidateImports
        true = true) :
    certificate.stackPointerPreservedChecked originalPe candidatePe
      originalImports candidateImports = true := by
  simp [Certificate.stackPointerPreservedChecked, originalInventory,
    candidateInventory, originalRegions, candidateRegions]

def Certificate.registerPreservedChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) (register : Reg) : Bool :=
  if register == .esp then
    certificate.stackPointerPreservedChecked originalPe candidatePe
      originalImports candidateImports
  else
    certificate.identityRegisterChecked originalPe candidatePe
        originalImports candidateImports register ||
      certificate.stackWitnesses.any fun witness =>
        witness.register == register &&
          witness.checked certificate originalPe candidatePe
            originalImports candidateImports

/-- Reuse one checked stack witness when closing the register selected by that
witness.  Generated certificates check each expensive witness once and use
this theorem instead of re-running the complete certificate scan for the
corresponding register. -/
theorem Certificate.registerPreservedChecked_of_stackWitness
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (register : Reg) (witness : StackSaveRestoreWitness)
    (registerNotEsp : register ≠ .esp)
    (member : witness ∈ certificate.stackWitnesses)
    (witnessRegister : witness.register = register)
    (witnessChecked :
      witness.checked certificate originalPe candidatePe
        originalImports candidateImports = true) :
    certificate.registerPreservedChecked originalPe candidatePe
      originalImports candidateImports register = true := by
  unfold Certificate.registerPreservedChecked
  have registerNotEspBool : (register == .esp) = false :=
    beq_eq_false_iff_ne.mpr registerNotEsp
  have stackWitnessSelected :
      (certificate.stackWitnesses.any fun selected =>
        selected.register == register &&
          selected.checked certificate originalPe candidatePe
            originalImports candidateImports) = true := by
    apply List.any_eq_true.mpr
    refine ⟨witness, member, ?_⟩
    simp [witnessRegister, witnessChecked]
  rw [registerNotEspBool]
  simp only [Bool.false_eq_true, ↓reduceIte, stackWitnessSelected, Bool.or_true]

def Certificate.preservationChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  certificate.requestedRegisters.all fun register =>
    certificate.registerPreservedChecked originalPe candidatePe
      originalImports candidateImports register

/-- Fold independently checked register facts into the aggregate preservation
predicate.  This direction is the cache-friendly counterpart of
`preservationChecked_evidence` below. -/
theorem Certificate.preservationChecked_of_registers
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (registersChecked : ∀ register,
      register ∈ certificate.requestedRegisters ->
        certificate.registerPreservedChecked originalPe candidatePe
          originalImports candidateImports register = true) :
    certificate.preservationChecked originalPe candidatePe
      originalImports candidateImports = true := by
  unfold Certificate.preservationChecked
  exact List.all_eq_true.mpr registersChecked

def Certificate.structureShapeChecked
    (certificate : Certificate) : Bool :=
  certificate.requestedRegisters.isEmpty == false &&
    decide certificate.requestedRegisters.Nodup &&
    decide certificate.callerFrameWords.Nodup &&
    certificate.callerFrameWords.all ReturnSlotExactWordPair.checked &&
    regionIdsUnique certificate.calleeRegions &&
    edgeIdsUnique certificate.edges && returnIdsUnique certificate.returns &&
    nestedDependencyIdsUnique certificate.nestedDependencies &&
    machineDependencyIdsUnique certificate.machineImportDependencies &&
    machineTailDependencyIdsUnique certificate.machineImportTailDependencies &&
    machineTerminalDependencyIdsUnique
      certificate.machineImportTerminalDependencies &&
    finiteIndirectDependencyIdsUnique certificate.finiteIndirectDependencies &&
    finiteOriginCallDependencyIdsUnique
      certificate.finiteOriginCallDependencies &&
    finiteOriginTailDependencyIdsUnique
      certificate.finiteOriginTailDependencies &&
    stackFrameAnchorIdsUnique certificate.stackFrameAnchors &&
    stackWitnessRegistersUnique certificate.stackWitnesses &&
    stackEntryOffsetIdsUnique certificate.stackEntryOffsets &&
    certificate.frameShapeChecked &&
    certificate.returns.isEmpty == false

def Certificate.structureDecodeChecked
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  certificate.endpointsChecked originalPe candidatePe
      originalImports candidateImports &&
    (certificate.calleeRegions.all fun region =>
      exactSummaryRegionPairDecodes originalPe candidatePe originalImports
        candidateImports region)

def Certificate.structureControlChecked
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  certificate.graphClosed &&
    certificate.inventorySideChecked originalPe originalImports false &&
    certificate.inventorySideChecked candidatePe candidateImports true

/-- Reconstruct control checking from a graph closure checked once and
independently checked regional inventories. -/
theorem Certificate.structureControlChecked_of_closed_graph_and_region_parts
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (parts : List (List ExactRegionPair))
    (regionsBound : parts.flatten = certificate.calleeRegions)
    (graphClosed : certificate.graphClosed = true)
    (originalParts :
      parts.all (fun part =>
        certificate.inventoryRegionsChecked originalPe originalImports false
          part) = true)
    (candidateParts :
      parts.all (fun part =>
        certificate.inventoryRegionsChecked candidatePe candidateImports true
          part) = true) :
    certificate.structureControlChecked originalPe candidatePe
      originalImports candidateImports = true := by
  have originalInventory :=
    certificate.inventorySideChecked_of_region_parts originalPe
      originalImports false parts regionsBound originalParts
  have candidateInventory :=
    certificate.inventorySideChecked_of_region_parts candidatePe
      candidateImports true parts regionsBound candidateParts
  simp [Certificate.structureControlChecked, graphClosed, originalInventory,
    candidateInventory]

def Certificate.structureDependenciesChecked
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List Certificate) : Bool :=
  certificate.nestedDependencyCertificatesChecked originalPe candidatePe
      originalImports candidateImports nested &&
    (certificate.machineImportDependencies.all fun dependency =>
      dependency.checked certificate originalPe candidatePe
        originalImports candidateImports) &&
    (certificate.machineImportTailDependencies.all fun dependency =>
      dependency.checked certificate originalPe candidatePe
        originalImports candidateImports) &&
    (certificate.machineImportTerminalDependencies.all fun dependency =>
      dependency.checked certificate originalPe candidatePe
        originalImports candidateImports) &&
    (certificate.finiteIndirectDependencies.all fun dependency =>
      dependency.checked certificate originalPe candidatePe) &&
    (certificate.finiteOriginCallDependencies.all fun dependency =>
      dependency.checked certificate) &&
    (certificate.finiteOriginTailDependencies.all fun dependency =>
      dependency.checked certificate)

def Certificate.structureStackChecked
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  (certificate.stackFrameAnchors.all fun witness =>
      witness.checked certificate originalPe candidatePe
        originalImports candidateImports) &&
    (certificate.calleeRegions.all fun region =>
      (stackFrameAnchorsForRegion certificate region.id).length <= 1)

def Certificate.structureCheckedWithChildCertificates
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List Certificate) : Bool :=
  certificate.structureShapeChecked &&
    certificate.structureDecodeChecked originalPe candidatePe
      originalImports candidateImports &&
    certificate.structureControlChecked originalPe candidatePe
      originalImports candidateImports &&
    certificate.structureDependenciesChecked originalPe candidatePe
      originalImports candidateImports nested &&
    certificate.structureStackChecked originalPe candidatePe
      originalImports candidateImports

/-- Recombine separately compiled structural families.  Each premise is an
exact Boolean checker over the submitted certificate; no generated status can
substitute for one of these proofs. -/
theorem Certificate.structureCheckedWithChildCertificates_of_families
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List Certificate)
    (shape :
      certificate.structureShapeChecked = true)
    (decode :
      certificate.structureDecodeChecked originalPe candidatePe
        originalImports candidateImports = true)
    (control :
      certificate.structureControlChecked originalPe candidatePe
        originalImports candidateImports = true)
    (dependencies :
      certificate.structureDependenciesChecked originalPe candidatePe
        originalImports candidateImports nested = true)
    (stack :
      certificate.structureStackChecked originalPe candidatePe
        originalImports candidateImports = true) :
    certificate.structureCheckedWithChildCertificates originalPe candidatePe
      originalImports candidateImports nested = true := by
  simp [Certificate.structureCheckedWithChildCertificates, shape, decode,
    control, dependencies, stack]

def Certificate.structureChecked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List SummaryTree) : Bool :=
  certificate.structureCheckedWithChildCertificates
    originalPe candidatePe originalImports candidateImports
    (nested.map SummaryTree.certificate)

def Certificate.checkedWithChildCertificates (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List Certificate) : Bool :=
  certificate.structureCheckedWithChildCertificates originalPe candidatePe
      originalImports candidateImports nested &&
    certificate.preservationChecked originalPe candidatePe
      originalImports candidateImports

def Certificate.checked (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List SummaryTree) : Bool :=
  certificate.checkedWithChildCertificates originalPe candidatePe
    originalImports candidateImports (nested.map SummaryTree.certificate)

/-- Recombine the two independently cacheable certificate checks without
unfolding either check at every generated summary node. -/
theorem Certificate.checked_of_structure_and_preservation
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List SummaryTree)
    (structureProof :
      certificate.structureChecked originalPe candidatePe
        originalImports candidateImports nested = true)
    (preservationProof :
      certificate.preservationChecked originalPe candidatePe
        originalImports candidateImports = true) :
    certificate.checked originalPe candidatePe
      originalImports candidateImports nested = true := by
  change certificate.structureCheckedWithChildCertificates
      originalPe candidatePe originalImports candidateImports
      (nested.map SummaryTree.certificate) = true at structureProof
  unfold Certificate.checked Certificate.checkedWithChildCertificates
  simp only [structureProof, preservationProof, Bool.and_self]

def SummaryTree.checkedFuel (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) :
    Nat -> SummaryTree -> Bool
  | 0, _ => false
  | fuel + 1, SummaryTree.node certificate nested =>
      certificate.checked originalPe candidatePe originalImports candidateImports nested &&
        nested.all fun child =>
          checkedFuel originalPe candidatePe originalImports candidateImports fuel child

def SummaryTree.checked (tree : SummaryTree) (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Bool :=
  tree.checkedFuel originalPe candidatePe originalImports candidateImports
    (tree.certificate.dependencyDepth + 1)

/-- Increasing the recursion fuel cannot invalidate a checked summary tree.
This lets generated DAG modules check each unique child once at its own depth,
then reuse that theorem wherever the child occurs. -/
theorem SummaryTree.checkedFuel_mono
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (tree : SummaryTree) {lower upper : Nat}
    (fuelLe : lower <= upper)
    (checked : tree.checkedFuel originalPe candidatePe
      originalImports candidateImports lower = true) :
    tree.checkedFuel originalPe candidatePe
      originalImports candidateImports upper = true := by
  induction lower generalizing upper tree with
  | zero =>
      simp [SummaryTree.checkedFuel] at checked
  | succ lower induction =>
      cases upper with
      | zero =>
          exact False.elim (Nat.not_succ_le_zero lower fuelLe)
      | succ upper =>
          cases tree with
          | node certificate nested =>
              simp only [SummaryTree.checkedFuel, Bool.and_eq_true] at checked ⊢
              refine ⟨checked.1, List.all_eq_true.mpr ?_⟩
              intro child member
              exact induction child (Nat.le_of_succ_le_succ fuelLe)
                (List.all_eq_true.mp checked.2 child member)

/-- Compose one locally checked summary node from independently checked,
strictly shallower children.  The depth side condition is deliberately
explicit: generated data cannot smuggle a cyclic proof graph through module
imports. -/
theorem SummaryTree.checked_node_of_certificate_and_children
    (certificate : Certificate) (nested : List SummaryTree)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (certificateChecked :
      certificate.checked originalPe candidatePe
        originalImports candidateImports nested = true)
    (childrenChecked :
      nested.all (fun child =>
        child.checked originalPe candidatePe
          originalImports candidateImports) = true)
    (childrenShallower :
      nested.all (fun child =>
        child.certificate.dependencyDepth < certificate.dependencyDepth) = true) :
    (SummaryTree.node certificate nested).checked
      originalPe candidatePe originalImports candidateImports = true := by
  simp only [SummaryTree.checked, SummaryTree.checkedFuel, Bool.and_eq_true]
  refine ⟨certificateChecked, List.all_eq_true.mpr ?_⟩
  intro child member
  have childChecked := List.all_eq_true.mp childrenChecked child member
  have childShallower : child.certificate.dependencyDepth <
      certificate.dependencyDepth := by
    simpa using List.all_eq_true.mp childrenShallower child member
  exact SummaryTree.checkedFuel_mono originalPe candidatePe
    originalImports candidateImports child
    (Nat.succ_le_iff.mpr childShallower) childChecked

/-- This is checker evidence, not a semantic execution claim.  It records only
that the register-specific structural predicates selected by the certificate
are true. -/
def Certificate.CheckedRegisterEvidence (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Prop :=
  forall register, register ∈ certificate.requestedRegisters ->
    certificate.registerPreservedChecked originalPe candidatePe
      originalImports candidateImports register = true

def Certificate.StructuralCheckerEvidence (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (nested : List SummaryTree) : Prop :=
  certificate.structureChecked originalPe candidatePe
      originalImports candidateImports nested = true /\
    certificate.CheckedRegisterEvidence originalPe candidatePe
      originalImports candidateImports

def SummaryTree.StructuralCheckerEvidence (tree : SummaryTree)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport) : Prop :=
  match tree with
  | .node certificate nested =>
      certificate.StructuralCheckerEvidence originalPe candidatePe
        originalImports candidateImports nested

theorem Certificate.preservationChecked_evidence (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (checked : certificate.preservationChecked originalPe candidatePe
      originalImports candidateImports = true) :
    certificate.CheckedRegisterEvidence originalPe candidatePe
      originalImports candidateImports := by
  intro register member
  exact List.all_eq_true.mp checked register member

theorem SummaryTree.checked_structuralEvidence (tree : SummaryTree)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (checked : tree.checked originalPe candidatePe
      originalImports candidateImports = true) :
    tree.StructuralCheckerEvidence originalPe candidatePe
      originalImports candidateImports := by
  cases tree with
  | node certificate nested =>
      simp only [SummaryTree.checked, SummaryTree.checkedFuel,
        Bool.and_eq_true] at checked
      have certificateChecked := checked.1
      simp only [Certificate.checked,
        Certificate.checkedWithChildCertificates,
        Bool.and_eq_true] at certificateChecked
      exact ⟨certificateChecked.1,
        certificate.preservationChecked_evidence originalPe candidatePe
          originalImports candidateImports certificateChecked.2⟩

/-! ## Local block and path semantics

These definitions execute only a supplied list of decoded symbolic blocks.
They deliberately do not choose control-flow successors or discharge calls,
returns, imports, or loops.  The frontier below records those missing links to
the shared whole-program execution interfaces. -/

def applySymbolicBehavior (behavior : SymbolicBehavior)
    (state : MachineState) : MachineState :=
  let concrete := behavior.eval state
  {
    registers := concrete.registers
    memory := concrete.memory
    undefinedValue := state.undefinedValue
    x87 := {
      stack := fun index =>
        (concrete.x87.stack.drop index).head?.getD (BitVec.ofNat 80 0)
      control := concrete.x87.control
      status := concrete.x87.status
      semantics := state.x87.semantics
    }
    x87Physical := state.x87Physical
    x87Semantics := state.x87Semantics
    eflags := concrete.eflags
    fsBase := state.fsBase
  }

@[simp] theorem applySymbolicBehavior_register (behavior : SymbolicBehavior)
    (state : MachineState) (register : Reg) :
    (applySymbolicBehavior behavior state).registers.get register =
      (behavior.registers.get register).eval state := by
  cases register <;> rfl

def runSymbolicBehaviorPath :
    List SymbolicBehavior -> MachineState -> MachineState
  | [], state => state
  | behavior :: tail, state =>
      runSymbolicBehaviorPath tail (applySymbolicBehavior behavior state)

/-- A genuine path-execution theorem: a register invariant supplied for every
executed block is retained by the finite symbolic-block runner. -/
theorem runSymbolicBehaviorPath_register_preserved
    (behaviors : List SymbolicBehavior) (state : MachineState)
    (register : Reg)
    (stepPreserved : forall behavior, behavior ∈ behaviors -> forall before,
      (applySymbolicBehavior behavior before).registers.get register =
        before.registers.get register) :
    (runSymbolicBehaviorPath behaviors state).registers.get register =
      state.registers.get register := by
  induction behaviors generalizing state with
  | nil => rfl
  | cons behavior tail induction =>
      rw [runSymbolicBehaviorPath]
      calc
        (runSymbolicBehaviorPath tail
            (applySymbolicBehavior behavior state)).registers.get register =
            (applySymbolicBehavior behavior state).registers.get register := by
              apply induction
              intro tailBehavior tailMember before
              exact stepPreserved tailBehavior (by simp [tailMember]) before
        _ = state.registers.get register :=
          stepPreserved behavior (by simp) state

theorem runSymbolicBehaviorPath_identity_preserved
    (behaviors : List SymbolicBehavior) (state : MachineState)
    (register : Reg)
    (identity : forall behavior, behavior ∈ behaviors ->
      behavior.registers.get register = .inputReg register) :
    (runSymbolicBehaviorPath behaviors state).registers.get register =
      state.registers.get register := by
  apply runSymbolicBehaviorPath_register_preserved behaviors state register
  intro behavior member before
  rw [applySymbolicBehavior_register, identity behavior member]
  rfl

theorem registerExprOffset?_eval (base : Reg) (expression : Expr) (offset : Word)
    (checked : registerExprOffset? base expression = some offset)
    (state : MachineState) :
    expression.eval state =
      state.registers.get base + offset := by
  induction expression using Expr.rec (motive_2 := fun _ => True)
      generalizing offset
  case inputReg register =>
    simp [registerExprOffset?] at checked
    rcases checked with ⟨rfl, rfl⟩
    simp [Expr.eval]
  case add left right leftInduction rightInduction =>
    cases right <;> simp [registerExprOffset?] at checked
    case constant amount =>
      rcases checked with ⟨_, prior, priorChecked, rfl⟩
      simp [Expr.eval, leftInduction prior priorChecked, BitVec.add_assoc]
  case sub left right leftInduction rightInduction =>
    cases right <;> simp [registerExprOffset?] at checked
    case constant amount =>
      rcases checked with ⟨_, prior, priorChecked, rfl⟩
      simp [Expr.eval, leftInduction prior priorChecked,
        BitVec.sub_eq_add_neg, BitVec.add_assoc]
  all_goals first
    | simp [registerExprOffset?] at checked
    | trivial

theorem stackExprOffset?_eval (expression : Expr) (offset : Word)
    (checked : stackExprOffset? expression = some offset) (state : MachineState) :
    expression.eval state =
      state.registers.esp + offset := by
  simpa [stackExprOffset?, StageA.Formal.Registers.get] using
    registerExprOffset?_eval .esp expression offset checked state

theorem stackRead32Offset?_eval (expression : Expr) (offset : Word)
    (checked : stackRead32Offset? expression = some offset)
    (state : MachineState) :
    expression.eval state =
      state.read32 (state.registers.esp + offset) := by
  cases expression <;> simp [stackRead32Offset?] at checked
  rename_i address
  simp [Expr.eval, stackExprOffset?_eval address offset checked state]

/-- The save checker exposes an exact concrete stack adjustment and exact
single-write memory effect for the decoded block. -/
theorem stackSaveSideChecked_eval (behavior : SymbolicBehavior) (register : Reg)
    (frameBytes saveOffset : Nat)
    (checked : stackSaveSideChecked behavior register frameBytes saveOffset = true) :
    forall state,
      (behavior.eval state).registers.esp = (stackSub frameBytes).eval state /\
      (behavior.eval state).memory =
        state.memory.write32 ((stackSub saveOffset).eval state)
          (state.registers.get register) := by
  simp only [stackSaveSideChecked, Bool.and_eq_true, beq_iff_eq,
    decide_eq_true_eq] at checked
  have stackPointer : behavior.registers.esp = stackSub frameBytes := by
    exact checked.1.2
  have writes : behavior.writes =
      [(stackSub saveOffset, .inputReg register)] := by
    exact checked.2
  intro state
  constructor
  · simpa [SymbolicBehavior.eval] using
      congrArg (fun expression => expression.eval state) stackPointer
  · simp [SymbolicBehavior.eval, StageA.Formal.applyWrites, writes, Expr.eval]

/-- Select the exact symbolic identity expression established by the checker. -/
theorem regionIdentitySideChecked_expression
    (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg)
    (behavior : SymbolicBehavior)
    (checked : regionIdentitySideChecked pe imports candidate region register = true)
    (decoded : regionBehaviorWithImports pe imports (region.span candidate) =
      some behavior) :
    behavior.registers.get register = .inputReg register := by
  unfold regionIdentitySideChecked at checked
  rw [decoded] at checked
  simpa only [beq_iff_eq] using checked

/-- The identity checker has the expected concrete register consequence for
the exact behavior returned by the decoder. -/
theorem regionIdentitySideChecked_eval (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg)
    (checked : regionIdentitySideChecked pe imports candidate region register = true) :
    exists behavior,
      regionBehaviorWithImports pe imports (region.span candidate) = some behavior /\
      forall state,
        (applySymbolicBehavior behavior state).registers.get register =
          state.registers.get register := by
  unfold regionIdentitySideChecked at checked
  generalize found : regionBehaviorWithImports pe imports
    (region.span candidate) = result at checked
  cases result with
  | none => simp at checked
  | some behavior =>
      simp only [beq_iff_eq] at checked
      refine ⟨behavior, rfl, ?_⟩
      intro state
      rw [applySymbolicBehavior_register, checked]
      rfl

/-- Reuse an identity fact checked against the exact decoder when a semantic
segment was decoded with machine-level import contracts.  Those contracts may
refine external arguments and outcomes, but `RelationalDecode` proves that
they leave the symbolic register transformer unchanged. -/
theorem regionIdentitySideChecked_machine_expression
    (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg)
    (behavior : SymbolicBehavior)
    (checked : regionIdentitySideChecked pe imports candidate region register = true)
    (decoded : regionBehaviorWithMachineCallContracts pe imports contracts
      (region.span candidate) = some behavior) :
    behavior.registers.get register = .inputReg register := by
  unfold regionIdentitySideChecked at checked
  generalize plainDecoded : regionBehaviorWithImports pe imports
    (region.span candidate) = result at checked
  cases result with
  | none => simp at checked
  | some plain =>
      simp only [beq_iff_eq] at checked
      unfold regionBehaviorWithMachineCallContracts at decoded
      rw [plainDecoded] at decoded
      have registers :=
        applyMachineImportCallContracts_registers contracts plain behavior decoded
      rw [registers]
      exact checked

theorem regionIdentitySideChecked_machine_eval
    (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg)
    (behavior : SymbolicBehavior)
    (checked : regionIdentitySideChecked pe imports candidate region register = true)
    (decoded : regionBehaviorWithMachineCallContracts pe imports contracts
      (region.span candidate) = some behavior) :
    forall state,
      (applySymbolicBehavior behavior state).registers.get register =
        state.registers.get register := by
  have identity := regionIdentitySideChecked_machine_expression pe imports contracts
    candidate region register behavior checked decoded
  intro state
  rw [applySymbolicBehavior_register, identity]
  rfl

/-- Select the ordinary symbolic identity expression from the broader summary
checker.  A successful ordinary decoder witness rules out the physical
x87-only branch by construction. -/
theorem summaryRegionIdentitySideChecked_expression
    (pe : PE32) (imports : List PEImport)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg)
    (behavior : SymbolicBehavior)
    (checked :
      summaryRegionIdentitySideChecked pe imports candidate region register =
        true)
    (decoded : regionBehaviorWithImports pe imports (region.span candidate) =
      some behavior) :
    behavior.registers.get register = .inputReg register := by
  unfold summaryRegionIdentitySideChecked at checked
  rw [decoded] at checked
  simpa only [beq_iff_eq] using checked

/-- Machine-call normalization is reachable only from an ordinary symbolic
decode, so an accepted physical x87-only summary region cannot enter this
branch. -/
theorem summaryRegionIdentitySideChecked_machine_expression
    (pe : PE32) (imports : List PEImport)
    (contracts : List MachineImportCallContract)
    (candidate : Bool) (region : ExactRegionPair) (register : Reg)
    (behavior : SymbolicBehavior)
    (checked :
      summaryRegionIdentitySideChecked pe imports candidate region register =
        true)
    (decoded : regionBehaviorWithMachineCallContracts pe imports contracts
      (region.span candidate) = some behavior) :
    behavior.registers.get register = .inputReg register := by
  unfold summaryRegionIdentitySideChecked at checked
  generalize plainDecoded : regionBehaviorWithImports pe imports
    (region.span candidate) = result at checked
  cases result with
  | none =>
      unfold regionBehaviorWithMachineCallContracts at decoded
      rw [plainDecoded] at decoded
      simp at decoded
  | some plain =>
      simp only [beq_iff_eq] at checked
      unfold regionBehaviorWithMachineCallContracts at decoded
      rw [plainDecoded] at decoded
      have registers :=
        applyMachineImportCallContracts_registers contracts plain behavior decoded
      rw [registers]
      exact checked

/-- Select both exact side checks for one region from the aggregate identity
certificate. -/
theorem Certificate.identityRegisterChecked_region
    (certificate : Certificate)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (register : Reg) (region : ExactRegionPair)
    (checked : certificate.identityRegisterChecked originalPe candidatePe
      originalImports candidateImports register = true)
    (member : region ∈ certificate.calleeRegions) :
    summaryRegionIdentitySideChecked originalPe originalImports false region
        register = true /\
      summaryRegionIdentitySideChecked candidatePe candidateImports true region
        register = true := by
  unfold Certificate.identityRegisterChecked at checked
  have selected := List.all_eq_true.mp checked region member
  simpa only [Bool.and_eq_true] using selected

/-- The restore checker exposes the concrete load, stack adjustment, and return
target of the decoded block.  Writes in the same region remain explicit
protected-slot obligations and are not claimed harmless here. -/
theorem stackRestoreSideChecked_eval (behavior : SymbolicBehavior) (register : Reg)
    (entryOffset saveOffset : Nat)
    (checked : stackRestoreSideChecked behavior register entryOffset saveOffset = true) :
    forall state,
      (behavior.eval state).registers.get register =
          state.read32 (state.registers.esp +
            (0 - (BitVec.ofNat 32 saveOffset + BitVec.ofNat 32 entryOffset))) /\
      (behavior.eval state).registers.esp =
          state.registers.esp +
            (BitVec.ofNat 32 4 - BitVec.ofNat 32 entryOffset) /\
      returnedStackRead32Offset? behavior.outcome =
        some (0 - BitVec.ofNat 32 entryOffset) := by
  unfold stackRestoreSideChecked at checked
  simp only [Bool.and_eq_true, beq_iff_eq] at checked
  have registerValue := checked.1.1
  have stackPointer := checked.1.2
  have returned := checked.2
  intro state
  have registerEval := stackRead32Offset?_eval _ _ registerValue state
  have stackEval := stackExprOffset?_eval _ _ stackPointer state
  refine ⟨?_, ?_, ?_⟩
  · cases register <;>
      simpa [SymbolicBehavior.eval, StageA.Formal.Registers.get] using registerEval
  · simpa [SymbolicBehavior.eval] using stackEval
  · exact returned

inductive SemanticIntegrationRequirement where
  | exactInventoryExecutionBridge
  | reachableControlFlowPath
  | stackSaveRestorePathComposition
  | protectedStackSlotWriteSeparation
  | nestedSummaryExecutionComposition
  | machineImportExecutionComposition
  | finiteIndirectTargetEvaluation
  | finiteOriginCallExecutionComposition
  | finiteOriginTailExecutionComposition
  | loopInvariantValidation
deriving Repr, DecidableEq

/-- Explicit frontier between this standalone checker and acceptance authority.
Every listed requirement needs a bridge to shared execution/composition
semantics before a checked summary can be treated as whole-callee evidence. -/
structure SemanticIntegrationRequirements where
  missing : List SemanticIntegrationRequirement
  standaloneAcceptanceAuthority : Bool
deriving Repr, DecidableEq

def semanticIntegrationRequirements : SemanticIntegrationRequirements := {
  missing := [
    .exactInventoryExecutionBridge,
    .reachableControlFlowPath,
    .stackSaveRestorePathComposition,
    .protectedStackSlotWriteSeparation,
    .nestedSummaryExecutionComposition,
    .machineImportExecutionComposition,
    .finiteIndirectTargetEvaluation,
    .finiteOriginCallExecutionComposition,
    .finiteOriginTailExecutionComposition,
    .loopInvariantValidation,
  ]
  standaloneAcceptanceAuthority := false
}

theorem semanticIntegrationRequirements_not_authority :
    semanticIntegrationRequirements.standaloneAcceptanceAuthority = false := rfl
#print axioms Certificate.preservationChecked_evidence
#print axioms SummaryTree.checked_structuralEvidence
#print axioms stackSaveSideChecked_eval
#print axioms regionIdentitySideChecked_eval
#print axioms stackRestoreSideChecked_eval
#print axioms runSymbolicBehaviorPath_register_preserved
#print axioms runSymbolicBehaviorPath_identity_preserved
#print axioms semanticIntegrationRequirements_not_authority

end StageA.Relational.InternalDirectCallRegisterSummary
