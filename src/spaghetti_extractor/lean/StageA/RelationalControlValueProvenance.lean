import StageA.RelationalEnvironment
import StageA.RelationalValueProvenance

namespace StageA.Relational.ControlValueProvenance

open StageA.Formal StageA.Relational
open StageA.Relational.ValueProvenance

inductive Location where
  | register (register : Reg)
  | frameWord (base : Reg) (adjustment : StackAdjustment)
  | staticWord (address : Nat)
  deriving DecidableEq, Repr

structure LocationPair where
  id : Nat
  original : Location
  candidate : Location
  deriving DecidableEq, Repr

/-- Local replay and whole-program composition use the same origin language.
The local certificate accepts only the constructors its exact transfer replay
can justify; unsupported origins fail closed in the relevant checker. -/
abbrev Atom := ValueOriginAtom

inductive Blocker where
  | unknown
  | unmodelledAlias
  | unmodelledWrite
  | unmodelledCall
  | ungroundedClaim
  | disjunctionOverflow
  deriving DecidableEq, Repr

structure Value where
  atoms : List Atom
  blockers : List Blocker := []
  deriving DecidableEq, Repr

structure StateEntry where
  locationId : Nat
  value : Value
  deriving DecidableEq, Repr

abbrev State := List StateEntry

structure StaticSeed where
  id : Nat
  locationId : Nat
  atom : Atom
  deriving DecidableEq, Repr

inductive TransferAction where
  | seed (outputId : Nat) (atom : Atom)
  | assign (outputId inputId : Nat)
  deriving DecidableEq, Repr

structure Region where
  id : Nat
  entry : Bool
  targetId : Nat
  originalSpan : Span
  candidateSpan : Span
  originalBytes : Bytes
  candidateBytes : Bytes
  actions : List TransferAction
  input : Option State
  output : Option State
  deriving DecidableEq, Repr

inductive EdgeKind where
  | direct
  | branchTaken
  | branchFallthrough
  | callReturn
  deriving DecidableEq, Repr

structure Edge where
  id : Nat
  sourceRegion : Nat
  targetRegion : Nat
  kind : EdgeKind
  callReferenceId : Option Nat := none
  deriving DecidableEq, Repr

structure EdgeShape where
  sourceRegion : Nat
  targetRegion : Nat
  kind : EdgeKind
  callReferenceId : Option Nat := none
  deriving DecidableEq, Repr

structure CallReference where
  id : Nat
  regionId : Nat
  externalSiteId : Nat
  machineContractId : Nat
  deriving DecidableEq, Repr

structure BranchGuard where
  id : Nat
  regionId : Nat
  locationId : Nat
  originalCondition : BoolExpr
  candidateCondition : BoolExpr
  observed : Value
  deriving DecidableEq, Repr

structure SCC where
  id : Nat
  regionIds : List Nat
  edgeIds : List Nat
  predecessorIds : List Nat
  successorIds : List Nat
  cyclic : Bool
  deriving DecidableEq, Repr

structure Certificate where
  finiteDisjunctionBudget : Nat
  locations : List LocationPair
  staticSeeds : List StaticSeed
  regions : List Region
  edges : List Edge
  callReferences : List CallReference
  branchGuards : List BranchGuard
  sccs : List SCC
  componentOrder : List Nat
  deriving DecidableEq, Repr

/-- This dependency is deliberately not serializable as certificate data.  A
caller that wants import-call propagation must supply an independently checked
relational environment for canonical external-call sites. -/
structure CallSemanticDependency (context : StaticProofContext) where
  sites : List ExternalCallSiteContract
  originalEnvironment : WorldExternalEnvironment
  candidateEnvironment : WorldExternalEnvironment
  refines : ExternalEnvironmentRefines context sites
    originalEnvironment candidateEnvironment

/-- Exact static inputs consumed by local checking.  This binds a qualified
context to PE bytes, import descriptors/IAT entries, relocation blocks, the
canonical code map, and exact machine-import contracts. -/
structure ExactContextBinding (context : StaticProofContext) : Prop where
  originalParsed : parsePE32Tree context.originalPe.bytes = some context.originalPe
  candidateParsed : parsePE32Tree context.candidatePe.bytes = some context.candidatePe
  originalImportTable :
    importTableValid context.originalPe context.originalImportCertificate = true
  candidateImportTable :
    importTableValid context.candidatePe context.candidateImportCertificate = true
  originalImportsParsed :
    parseImports context.originalPe = some context.originalImportCertificate.imports
  candidateImportsParsed :
    parseImports context.candidatePe = some context.candidateImportCertificate.imports
  originalRelocationsParsed :
    parseRelocations context.originalPe = some context.originalRelocations
  candidateRelocationsParsed :
    parseRelocations context.candidatePe = some context.candidateRelocations
  codeMapChecked :
    context.codeMap.valid context.originalPe context.candidatePe = true
  originalMachineContractsChecked :
    machineImportCallContractsValid context.originalImportCertificate.imports
      context.machineImportCallContracts = true
  candidateMachineContractsChecked :
    machineImportCallContractsValid context.candidateImportCertificate.imports
      context.machineImportCallContracts = true

def noDuplicates [BEq alpha] (items : List alpha) : Bool :=
  items.length == items.eraseDups.length

def sameFiniteSet [BEq alpha] (left right : List alpha) : Bool :=
  noDuplicates left && noDuplicates right &&
    left.all right.contains && right.all left.contains

def State.lookup (state : State) (locationId : Nat) : Option Value :=
  (state.find? fun entry => entry.locationId == locationId).map (·.value)

def State.set (state : State) (locationId : Nat) (value : Value) : State :=
  { locationId := locationId, value := value } ::
    state.filter fun entry => entry.locationId != locationId

def Value.semanticallyEqual (left right : Value) : Bool :=
  sameFiniteSet left.atoms right.atoms &&
    sameFiniteSet left.blockers right.blockers

def State.semanticallyEqual (left right : State) : Bool :=
  sameFiniteSet (left.map (·.locationId)) (right.map (·.locationId)) &&
    left.all fun entry =>
      match right.lookup entry.locationId with
      | some value => entry.value.semanticallyEqual value
      | none => false

def optionalStateSemanticallyEqual (left right : Option State) : Bool :=
  match left, right with
  | none, none => true
  | some leftState, some rightState => leftState.semanticallyEqual rightState
  | _, _ => false

def Certificate.location? (certificate : Certificate) (id : Nat) : Option LocationPair :=
  certificate.locations.find? fun location => location.id == id

def Certificate.region? (certificate : Certificate) (id : Nat) : Option Region :=
  certificate.regions.find? fun region => region.id == id

def Certificate.callReference? (certificate : Certificate) (id : Nat) :
    Option CallReference :=
  certificate.callReferences.find? fun reference => reference.id == id

def Certificate.locationKnown (certificate : Certificate) (id : Nat) : Bool :=
  (certificate.location? id).isSome

def Certificate.contextBoundChecked
    (_certificate : Certificate) (context : StaticProofContext) : Bool :=
  parsePE32Tree context.originalPe.bytes == some context.originalPe &&
    parsePE32Tree context.candidatePe.bytes == some context.candidatePe &&
    importTableValid context.originalPe context.originalImportCertificate &&
    importTableValid context.candidatePe context.candidateImportCertificate &&
    parseImports context.originalPe ==
      some context.originalImportCertificate.imports &&
    parseImports context.candidatePe ==
      some context.candidateImportCertificate.imports &&
    parseRelocations context.originalPe == some context.originalRelocations &&
    parseRelocations context.candidatePe == some context.candidateRelocations &&
    context.codeMap.valid context.originalPe context.candidatePe &&
    machineImportCallContractsValid context.originalImportCertificate.imports
      context.machineImportCallContracts &&
    machineImportCallContractsValid context.candidateImportCertificate.imports
      context.machineImportCallContracts

theorem Certificate.exactContextBinding_of_checked
    (certificate : Certificate) (context : StaticProofContext)
    (checked : certificate.contextBoundChecked context = true) :
    ExactContextBinding context := by
  refine {
    originalParsed := ?_
    candidateParsed := ?_
    originalImportTable := ?_
    candidateImportTable := ?_
    originalImportsParsed := ?_
    candidateImportsParsed := ?_
    originalRelocationsParsed := ?_
    candidateRelocationsParsed := ?_
    codeMapChecked := ?_
    originalMachineContractsChecked := ?_
    candidateMachineContractsChecked := ?_
  } <;> simp_all [Certificate.contextBoundChecked]

def Certificate.atomChecked
    (_certificate : Certificate) (context : StaticProofContext) : Atom -> Bool
  | .exactBits value => value < 2 ^ 32
  | .staticCodeTarget targetId offset =>
      offset == 0 && (context.codeMap.get? targetId).isSome
  | .staticDataLocation targetId offset =>
      match context.dataMap.get? targetId with
      | none => false
      | some target => offset < max 1 target.mappedSize
  | .importTarget identity =>
      context.originalImportCertificate.imports.any (fun imported =>
        normalizeImport imported == identity) &&
      context.candidateImportCertificate.imports.any (fun imported =>
        normalizeImport imported == identity)
  | .stackFrameLocation _ _ | .dynamicRangeLocation _ _ |
      .opaqueResource _ | .registeredCallback _ => false

def Certificate.valueChecked
    (certificate : Certificate) (context : StaticProofContext) (value : Value) : Bool :=
  !value.atoms.isEmpty && noDuplicates value.atoms &&
    value.atoms.length <= certificate.finiteDisjunctionBudget &&
    value.blockers.isEmpty && value.atoms.all (certificate.atomChecked context)

def Certificate.stateChecked
    (certificate : Certificate) (context : StaticProofContext) (state : State) : Bool :=
  noDuplicates (state.map (·.locationId)) &&
    state.all fun entry =>
      certificate.locationKnown entry.locationId &&
        certificate.valueChecked context entry.value

def LocationPair.side (pair : LocationPair) (candidate : Bool) : Location :=
  if candidate then pair.candidate else pair.original

def Location.checked : Location -> Bool
  | .register _ => true
  | .frameWord _ .identity => true
  | .frameWord _ (.add amount) => amount < 2 ^ 32
  | .frameWord _ (.subtract amount) => amount < 2 ^ 32
  | .staticWord address => address < 2 ^ 32

def StackAdjustment.canonicalExpression
    (adjustment : StackAdjustment) (register : Reg) : Expr :=
  match adjustment with
  | .identity => .inputReg register
  | .add amount => .add (.inputReg register) (.constant amount)
  | .subtract amount =>
      if amount < 2 ^ 32 then
        .add (.inputReg register) (.constant (2 ^ 32 - amount))
      else
        .sub (.inputReg register) (.constant amount)

def Location.addressExpr : Location -> Option Expr
  | .register _ => none
  | .frameWord base adjustment =>
      some (StackAdjustment.canonicalExpression adjustment base)
  | .staticWord address => some (.constant address)

def Location.inputExpr : Location -> Expr
  | Location.register reg => .inputReg reg
  | .frameWord base adjustment =>
      .read32 (StackAdjustment.canonicalExpression adjustment base)
  | .staticWord address => .read32 (.constant address)

def Certificate.sideLocation?
    (certificate : Certificate) (candidate : Bool) (locationId : Nat) : Option Location :=
  (certificate.location? locationId).map fun pair => pair.side candidate

def Certificate.codeTargetWord?
    (context : StaticProofContext) (candidate : Bool) (targetId : Nat) : Option Nat := do
  let target <- context.codeMap.get? targetId
  pure <| (if candidate then context.candidatePe.imageBase + target.candidateRva
    else context.originalPe.imageBase + target.originalRva)

def Certificate.atomWord?
    (_certificate : Certificate) (context : StaticProofContext)
    (candidate : Bool) : Atom -> Option Expr
  | .exactBits value => if value < 2 ^ 32 then some (.constant value) else none
  | .staticCodeTarget targetId 0 =>
      (Certificate.codeTargetWord? context candidate targetId).map Expr.constant
  | .staticDataLocation targetId offset => do
      let target <- context.dataMap.get? targetId
      pure (.constant <| (if candidate then target.candidateValue
        else target.originalValue) + offset)
  | .staticCodeTarget _ _ | .importTarget _ |
      .stackFrameLocation _ _ | .dynamicRangeLocation _ _ |
      .opaqueResource _ | .registeredCallback _ => none

def relocationCountAt (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation =>
    relocation.rva == rva && relocation.kind == 3).length

def Certificate.staticSeedChecked
    (certificate : Certificate) (context : StaticProofContext)
    (seed : StaticSeed) : Bool :=
  certificate.atomChecked context seed.atom &&
    match certificate.location? seed.locationId with
    | some pair => match pair.original, pair.candidate with
      | .staticWord originalAddress, .staticWord candidateAddress =>
        if originalAddress < context.originalPe.imageBase ||
            candidateAddress < context.candidatePe.imageBase then false
        else
          let originalRva := originalAddress - context.originalPe.imageBase
          let candidateRva := candidateAddress - context.candidatePe.imageBase
          match seed.atom with
          | .exactBits value =>
              value < 2 ^ 32 &&
                readImmutableImageWord context.originalPe originalAddress 4 ==
                  some value &&
                readImmutableImageWord context.candidatePe candidateAddress 4 ==
                  some value
          | .staticCodeTarget targetId 0 =>
              match Certificate.codeTargetWord? context false targetId,
                  Certificate.codeTargetWord? context true targetId with
              | some originalWord, some candidateWord =>
                  readRvaU32 context.originalPe originalRva == some originalWord &&
                    readRvaU32 context.candidatePe candidateRva == some candidateWord &&
                    relocationCountAt context.originalRelocations originalRva == 1 &&
                    relocationCountAt context.candidateRelocations candidateRva == 1
              | _, _ => false
          | .importTarget identity =>
              context.originalImportCertificate.imports.any (fun imported =>
                imported.iatRva == originalRva && normalizeImport imported == identity) &&
              context.candidateImportCertificate.imports.any (fun imported =>
                imported.iatRva == candidateRva && normalizeImport imported == identity)
          | .staticDataLocation _ _ | .staticCodeTarget _ _ |
              .stackFrameLocation _ _ | .dynamicRangeLocation _ _ |
              .opaqueResource _ | .registeredCallback _ => false
      | _, _ => false
    | none => false

structure ProjectionEntry where
  locationId : Nat
  expression : Expr
  deriving DecidableEq, Repr

structure SideProjection where
  values : List ProjectionEntry
  registers : Registers Expr
  writes : List (Expr × Expr)
  deriving DecidableEq, Repr

def SideProjection.lookup (projection : SideProjection) (locationId : Nat) : Option Expr :=
  (projection.values.find? fun entry => entry.locationId == locationId).map (·.expression)

def SideProjection.setValue
    (projection : SideProjection) (locationId : Nat) (expression : Expr) : SideProjection := {
  projection with
  values := { locationId, expression } ::
    projection.values.filter fun entry => entry.locationId != locationId
}

def appendCanonicalWrite
    (writes : List (Expr × Expr)) (address value : Expr) : List (Expr × Expr) :=
  let retained := writes.filter fun write => write.1 != address
  if value == .read32 address &&
      retained.all fun write => wordWriteAddressesProvablyDisjoint address write.1 then
    retained
  else
    retained ++ [(address, value)]

def SideProjection.writeOutput
    (projection : SideProjection) (location : Location) (value : Expr) : SideProjection :=
  match location with
  | Location.register reg => { projection with
      registers := projection.registers.set reg value }
  | .frameWord base adjustment => { projection with
      writes := appendCanonicalWrite projection.writes
        (StackAdjustment.canonicalExpression adjustment base) value }
  | .staticWord address => { projection with
      writes := appendCanonicalWrite projection.writes (.constant address) value }

def Certificate.initialProjection
    (certificate : Certificate) (candidate : Bool) : SideProjection := {
  values := certificate.locations.map fun pair => {
    locationId := pair.id
    expression := (pair.side candidate).inputExpr
  }
  registers := initialSymbolic.registers
  writes := []
}

def Certificate.applyProjectionAction?
    (certificate : Certificate) (context : StaticProofContext) (candidate : Bool)
    (projection : SideProjection) : TransferAction -> Option SideProjection
  | .seed outputId atom => do
      let output <- certificate.sideLocation? candidate outputId
      let value <- certificate.atomWord? context candidate atom
      pure <| (projection.setValue outputId value).writeOutput output value
  | .assign outputId inputId => do
      let output <- certificate.sideLocation? candidate outputId
      let value <- projection.lookup inputId
      pure <| (projection.setValue outputId value).writeOutput output value

def Certificate.projectActions?
    (certificate : Certificate) (context : StaticProofContext) (candidate : Bool)
    (actions : List TransferAction) : Option SideProjection :=
  actions.foldlM (certificate.applyProjectionAction? context candidate)
    (certificate.initialProjection candidate)

def Certificate.actionChecked
    (certificate : Certificate) (context : StaticProofContext) : TransferAction -> Bool
  | .seed output atom =>
      certificate.locationKnown output && certificate.atomChecked context atom &&
        (certificate.atomWord? context false atom).isSome &&
        (certificate.atomWord? context true atom).isSome
  | .assign output input =>
      certificate.locationKnown output && certificate.locationKnown input

def Certificate.regionDecoded?
    (_certificate : Certificate) (context : StaticProofContext) (region : Region) :
    Option (NormalizedSymbolicBehavior × NormalizedSymbolicBehavior) := do
  let original <- regionBehaviorWithMachineCallContracts context.originalPe
    context.originalImportCertificate.imports context.machineImportCallContracts
    region.originalSpan
  let candidate <- regionBehaviorWithMachineCallContracts context.candidatePe
    context.candidateImportCertificate.imports context.machineImportCallContracts
    region.candidateSpan
  let originalNormalized <- normalizeSymbolicBehavior false
    context.codeMap.entries.toList original
  let candidateNormalized <- normalizeSymbolicBehavior true
    context.codeMap.entries.toList candidate
  pure (originalNormalized, candidateNormalized)

def Certificate.regionBytesAndSpanChecked
    (_certificate : Certificate) (context : StaticProofContext) (region : Region) : Bool :=
  match context.codeMap.get? region.targetId with
  | none => false
  | some target =>
      target.regionIndex == region.id &&
        target.originalRva == region.originalSpan.start &&
        target.candidateRva == region.candidateSpan.start &&
        spanBytes context.originalPe region.originalSpan == some region.originalBytes &&
        spanBytes context.candidatePe region.candidateSpan == some region.candidateBytes

def Certificate.ExactRegionSpanBinding
    (_certificate : Certificate) (context : StaticProofContext) (region : Region) : Prop :=
  ∃ target : CodeTargetPair,
    context.codeMap.get? region.targetId = some target ∧
      target.regionIndex = region.id ∧
      target.originalRva = region.originalSpan.start ∧
      target.candidateRva = region.candidateSpan.start ∧
      spanBytes context.originalPe region.originalSpan = some region.originalBytes ∧
      spanBytes context.candidatePe region.candidateSpan = some region.candidateBytes

theorem Certificate.exactRegionSpanBinding_of_checked
    (certificate : Certificate) (context : StaticProofContext) (region : Region)
    (checked : certificate.regionBytesAndSpanChecked context region = true) :
    certificate.ExactRegionSpanBinding context region := by
  unfold Certificate.regionBytesAndSpanChecked at checked
  generalize resolved : context.codeMap.get? region.targetId = target at checked
  cases target with
  | none => simp at checked
  | some target =>
      refine ⟨target, resolved, ?_, ?_, ?_, ?_, ?_⟩ <;> simp_all

def SideProjection.matchesBehavior
    (projection : SideProjection) (behavior : NormalizedSymbolicBehavior) : Bool :=
  projection.registers == behavior.registers &&
    projection.writes == behavior.writes && behavior.x87 == initialSymbolic.x87

def Certificate.transferMatchesDecodedChecked
    (certificate : Certificate) (context : StaticProofContext) (region : Region) : Bool :=
  region.actions.all (certificate.actionChecked context) &&
    match certificate.regionDecoded? context region,
        certificate.projectActions? context false region.actions,
        certificate.projectActions? context true region.actions with
    | some decoded, some originalProjection, some candidateProjection =>
        originalProjection.matchesBehavior decoded.1 &&
          candidateProjection.matchesBehavior decoded.2
    | _, _, _ => false

def Certificate.ExactRegionTransfer
    (certificate : Certificate) (context : StaticProofContext) (region : Region) : Prop :=
  ∃ (decoded : NormalizedSymbolicBehavior × NormalizedSymbolicBehavior)
      (originalProjection candidateProjection : SideProjection),
    certificate.regionDecoded? context region = some decoded ∧
      certificate.projectActions? context false region.actions = some originalProjection ∧
      certificate.projectActions? context true region.actions = some candidateProjection ∧
      (∀ action ∈ region.actions, certificate.actionChecked context action = true) ∧
      originalProjection.registers = decoded.1.registers ∧
      originalProjection.writes = decoded.1.writes ∧
      decoded.1.x87 = initialSymbolic.x87 ∧
      candidateProjection.registers = decoded.2.registers ∧
      candidateProjection.writes = decoded.2.writes ∧
      decoded.2.x87 = initialSymbolic.x87

theorem Certificate.exactRegionTransfer_of_checked
    (certificate : Certificate) (context : StaticProofContext) (region : Region)
    (checked : certificate.transferMatchesDecodedChecked context region = true) :
    certificate.ExactRegionTransfer context region := by
  unfold Certificate.transferMatchesDecodedChecked at checked
  simp only [Bool.and_eq_true, List.all_eq_true] at checked
  rcases checked with ⟨actionsChecked, transfersChecked⟩
  generalize decodedExact : certificate.regionDecoded? context region = decoded
    at transfersChecked
  cases decoded with
  | none => simp at transfersChecked
  | some decoded =>
      generalize originalExact :
        certificate.projectActions? context false region.actions = original
          at transfersChecked
      cases original with
      | none => simp at transfersChecked
      | some originalProjection =>
          generalize candidateExact :
            certificate.projectActions? context true region.actions = candidate
              at transfersChecked
          cases candidate with
          | none =>
              simp at transfersChecked
          | some candidateProjection =>
              refine ⟨decoded, originalProjection, candidateProjection,
                decodedExact, originalExact, candidateExact, actionsChecked,
                ?_, ?_, ?_, ?_, ?_, ?_⟩ <;>
                simp_all [SideProjection.matchesBehavior]

def Edge.shape (edge : Edge) : EdgeShape := {
  sourceRegion := edge.sourceRegion
  targetRegion := edge.targetRegion
  kind := edge.kind
  callReferenceId := edge.callReferenceId
}

def Certificate.callReferenceChecked
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context))
    (reference : CallReference) : Bool :=
  match dependency,
      certificate.region? reference.regionId,
      machineImportCallContractById? context reference.machineContractId with
  | some semantics, some region, some contract =>
      match semantics.sites.find? fun site => site.id == reference.externalSiteId,
          certificate.regionDecoded? context region with
      | some site, some decoded =>
          site.sourceTargetId == region.targetId &&
            site.machineContractId == reference.machineContractId &&
            match decoded.1.outcome, decoded.2.outcome with
            | .externalCall originalImport _ originalContinuation,
                .externalCall candidateImport _ candidateContinuation =>
                originalImport == contract.imported &&
                  candidateImport == contract.imported &&
                  originalContinuation == site.continuationTargetId &&
                  candidateContinuation == site.continuationTargetId
            | _, _ => false
      | _, _ => false
  | _, _, _ => false

def Certificate.expectedEdgesFor?
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context))
    (region : Region) : Option (List EdgeShape) := do
  let decoded <- certificate.regionDecoded? context region
  match decoded.1.outcome, decoded.2.outcome with
  | .returned _, .returned _ => some []
  | .jump originalTarget, .jump candidateTarget =>
      if originalTarget == candidateTarget then some [{
        sourceRegion := region.id
        targetRegion := originalTarget
        kind := .direct
      }] else none
  | .branch _ originalTaken originalFallthrough,
      .branch _ candidateTaken candidateFallthrough =>
      if originalTaken == candidateTaken &&
          originalFallthrough == candidateFallthrough then some [{
        sourceRegion := region.id
        targetRegion := originalTaken
        kind := .branchTaken
      }, {
        sourceRegion := region.id
        targetRegion := originalFallthrough
        kind := .branchFallthrough
      }] else none
  | .externalCall _ _ originalContinuation,
      .externalCall _ _ candidateContinuation =>
      if originalContinuation != candidateContinuation then none
      else
        match certificate.callReferences.find? fun reference =>
            reference.regionId == region.id with
        | some reference =>
            if certificate.callReferenceChecked context dependency reference then some [{
              sourceRegion := region.id
              targetRegion := originalContinuation
              kind := .callReturn
              callReferenceId := some reference.id
            }] else none
        | none => none
  | _, _ => none

def Certificate.controlMatchesDecodedChecked
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context)) (region : Region) : Bool :=
  match certificate.expectedEdgesFor? context dependency region with
  | none => false
  | some expected => sameFiniteSet
      (certificate.edges.filter (fun edge => edge.sourceRegion == region.id) |>.map Edge.shape)
      expected

def Certificate.regionConcreteChecked
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context)) (region : Region) : Bool :=
  certificate.regionBytesAndSpanChecked context region &&
    certificate.transferMatchesDecodedChecked context region &&
    certificate.controlMatchesDecodedChecked context dependency region

def Certificate.unknownValue (reason : Blocker := .unknown) : Value := {
  atoms := []
  blockers := [reason]
}

def Certificate.applyAction
    (_certificate : Certificate) (state : State) : TransferAction -> State
  | .seed output atom => state.set output { atoms := [atom] }
  | .assign output input =>
      state.set output <| (state.lookup input).getD Certificate.unknownValue

def Certificate.applyActions
    (certificate : Certificate) (state : State) (actions : List TransferAction) : State :=
  actions.foldl certificate.applyAction state

def Certificate.joinValues (certificate : Certificate) (values : List Value) : Value :=
  let blockers := (values.flatMap (·.blockers)).eraseDups
  if !blockers.isEmpty then { atoms := [], blockers := blockers }
  else
    let atoms := (values.flatMap (·.atoms)).eraseDups
    if atoms.length > certificate.finiteDisjunctionBudget then
      Certificate.unknownValue .disjunctionOverflow
    else { atoms := atoms }

def Certificate.joinStates (certificate : Certificate) (states : List State) : State :=
  certificate.locations.filterMap fun location =>
    let values := states.filterMap (·.lookup location.id)
    if values.length == states.length then some {
      locationId := location.id
      value := certificate.joinValues values
    } else none

def Certificate.initialStaticState (certificate : Certificate) : State :=
  certificate.staticSeeds.map fun seed => {
    locationId := seed.locationId
    value := { atoms := [seed.atom] }
  }

def Certificate.edgeState?
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context))
    (edge : Edge) (source : State) : Option State :=
  match edge.kind, edge.callReferenceId, dependency with
  | .callReturn, some referenceId, some _ => do
      let reference <- certificate.callReference? referenceId
      let contract <- machineImportCallContractById? context reference.machineContractId
      pure <| certificate.locations.filterMap fun location =>
        match location.original, location.candidate with
        | .register originalRegister, .register candidateRegister =>
            if originalRegister == candidateRegister &&
                contract.preservedRegisters.contains originalRegister then
              (source.lookup location.id).map fun value => {
                locationId := location.id, value := value }
            else none
        | _, _ => none
  | .callReturn, _, _ => none
  | _, none, _ => some source
  | _, some _, _ => none

def Certificate.expectedInput
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context))
    (region : Region) : Option State :=
  let incoming := certificate.edges.filter fun edge => edge.targetRegion == region.id
  let available := incoming.filterMap fun edge =>
    (certificate.region? edge.sourceRegion).bind fun sourceRegion =>
      sourceRegion.output.bind fun source =>
        certificate.edgeState? context dependency edge source
  let states := if region.entry then certificate.initialStaticState :: available else available
  if states.isEmpty then none else some (certificate.joinStates states)

def Certificate.expectedOutput
    (certificate : Certificate) (region : Region) : Option State :=
  region.input.map fun input => certificate.applyActions input region.actions

def Certificate.regionReplayChecked
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context)) (region : Region) : Bool :=
  optionalStateSemanticallyEqual region.input
      (certificate.expectedInput context dependency region) &&
    optionalStateSemanticallyEqual region.output (certificate.expectedOutput region) &&
    (match region.input with
      | none => true
      | some state => certificate.stateChecked context state) &&
    match region.output with
    | none => true
    | some state => certificate.stateChecked context state

def Certificate.guardChecked
    (certificate : Certificate) (context : StaticProofContext) (guard : BranchGuard) : Bool :=
  certificate.valueChecked context guard.observed &&
    match certificate.region? guard.regionId with
    | none => false
    | some region =>
        match certificate.regionDecoded? context region, region.output with
        | some decoded, some output =>
            match decoded.1.outcome, decoded.2.outcome with
            | .branch originalCondition _ _, .branch candidateCondition _ _ =>
                originalCondition == guard.originalCondition &&
                  candidateCondition == guard.candidateCondition &&
                  match output.lookup guard.locationId with
                  | some value => guard.observed.semanticallyEqual value
                  | none => false
            | _, _ => false
        | _, _ => false

def Certificate.componentFor? (certificate : Certificate) (regionId : Nat) : Option Nat :=
  (certificate.sccs.find? fun component =>
    component.regionIds.contains regionId).map (·.id)

def Certificate.expectedComponentEdges
    (certificate : Certificate) (component : SCC) : List Nat :=
  (certificate.edges.filter fun edge =>
    component.regionIds.contains edge.sourceRegion &&
      component.regionIds.contains edge.targetRegion).map (·.id)

def Certificate.expectedPredecessors
    (certificate : Certificate) (component : SCC) : List Nat :=
  (certificate.edges.filterMap fun edge =>
    match certificate.componentFor? edge.sourceRegion,
        certificate.componentFor? edge.targetRegion with
    | some source, some target =>
        if target == component.id && source != target then some source else none
    | _, _ => none).eraseDups

def Certificate.expectedSuccessors
    (certificate : Certificate) (component : SCC) : List Nat :=
  (certificate.edges.filterMap fun edge =>
    match certificate.componentFor? edge.sourceRegion,
        certificate.componentFor? edge.targetRegion with
    | some source, some target =>
        if source == component.id && source != target then some target else none
    | _, _ => none).eraseDups

def Certificate.expectedCyclic
    (certificate : Certificate) (component : SCC) : Bool :=
  component.regionIds.length > 1 || certificate.edges.any (fun edge =>
    edge.sourceRegion == edge.targetRegion &&
      component.regionIds.contains edge.sourceRegion)

def Certificate.sccChecked (certificate : Certificate) (component : SCC) : Bool :=
  noDuplicates component.regionIds &&
    component.regionIds.all (· < certificate.regions.length) &&
    sameFiniteSet component.edgeIds (certificate.expectedComponentEdges component) &&
    sameFiniteSet component.predecessorIds (certificate.expectedPredecessors component) &&
    sameFiniteSet component.successorIds (certificate.expectedSuccessors component) &&
    component.cyclic == certificate.expectedCyclic component

def indexOf? [BEq alpha] (item : alpha) : List alpha -> Option Nat
  | [] => none
  | head :: tail =>
      if head == item then some 0 else (indexOf? item tail).map Nat.succ

def Certificate.componentOrderChecked (certificate : Certificate) : Bool :=
  sameFiniteSet certificate.componentOrder (certificate.sccs.map (·.id)) &&
    certificate.edges.all fun edge =>
      match certificate.componentFor? edge.sourceRegion,
          certificate.componentFor? edge.targetRegion with
      | some source, some target =>
          source == target ||
            match indexOf? source certificate.componentOrder,
                indexOf? target certificate.componentOrder with
            | some sourceIndex, some targetIndex => sourceIndex < targetIndex
            | _, _ => false
      | _, _ => false

def Certificate.inventoryChecked
    (certificate : Certificate) (context : StaticProofContext) : Bool :=
  certificate.finiteDisjunctionBudget > 0 &&
    !certificate.locations.isEmpty &&
    sameFiniteSet (certificate.locations.map (·.id))
      (List.range certificate.locations.length) &&
    certificate.locations.all (fun pair =>
      pair.original.checked && pair.candidate.checked) &&
    sameFiniteSet (certificate.staticSeeds.map (·.id))
      (List.range certificate.staticSeeds.length) &&
    noDuplicates (certificate.staticSeeds.map (·.locationId)) &&
    certificate.staticSeeds.all (certificate.staticSeedChecked context) &&
    sameFiniteSet (certificate.regions.map (·.id))
      (List.range certificate.regions.length) &&
    sameFiniteSet (certificate.edges.map (·.id))
      (List.range certificate.edges.length) &&
    certificate.edges.all (fun edge =>
      edge.sourceRegion < certificate.regions.length &&
        edge.targetRegion < certificate.regions.length) &&
    sameFiniteSet (certificate.callReferences.map (·.id))
      (List.range certificate.callReferences.length) &&
    noDuplicates (certificate.callReferences.map (·.regionId)) &&
    sameFiniteSet (certificate.branchGuards.map (·.id))
      (List.range certificate.branchGuards.length) &&
    noDuplicates (certificate.branchGuards.map (·.regionId)) &&
    sameFiniteSet (certificate.sccs.map (·.id))
      (List.range certificate.sccs.length) &&
    sameFiniteSet (certificate.sccs.flatMap (·.regionIds))
      (List.range certificate.regions.length)

def Certificate.localChecked
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context)) : Bool :=
  certificate.contextBoundChecked context &&
    certificate.inventoryChecked context &&
    certificate.regions.all (certificate.regionConcreteChecked context dependency) &&
    certificate.regions.all (certificate.regionReplayChecked context dependency) &&
    certificate.callReferences.all
      (certificate.callReferenceChecked context dependency) &&
    certificate.branchGuards.all (certificate.guardChecked context) &&
    certificate.sccs.all certificate.sccChecked && certificate.componentOrderChecked

/-- Honest output of the finite checker.  It deliberately says only that the
qualified PE/context inputs, canonical region decodes, finite replay, calls,
guards, and SCC metadata were locally rechecked. -/
structure Certificate.LocalReplayFacts
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context)) : Prop where
  exactContext : ExactContextBinding context
  inventory : certificate.inventoryChecked context = true
  exactSpans :
    ∀ region ∈ certificate.regions,
      certificate.ExactRegionSpanBinding context region
  exactTransfers :
    ∀ region ∈ certificate.regions,
      certificate.ExactRegionTransfer context region
  controlReplay :
    ∀ region ∈ certificate.regions,
      certificate.controlMatchesDecodedChecked context dependency region = true
  finiteReplay :
    ∀ region ∈ certificate.regions,
      certificate.regionReplayChecked context dependency region = true
  callsGrounded :
    ∀ reference ∈ certificate.callReferences,
      certificate.callReferenceChecked context dependency reference = true
  guards :
    ∀ guard ∈ certificate.branchGuards,
      certificate.guardChecked context guard = true
  sccs : ∀ component ∈ certificate.sccs, certificate.sccChecked component = true
  componentOrder : certificate.componentOrderChecked = true

theorem Certificate.localReplayFacts_of_checked
    {certificate : Certificate} {context : StaticProofContext}
    {dependency : Option (CallSemanticDependency context)}
    (checked : certificate.localChecked context dependency = true) :
    certificate.LocalReplayFacts context dependency := by
  refine {
    exactContext := certificate.exactContextBinding_of_checked context (by
      simp_all [Certificate.localChecked])
    inventory := ?_
    exactSpans := ?_
    exactTransfers := ?_
    controlReplay := ?_
    finiteReplay := ?_
    callsGrounded := ?_
    guards := ?_
    sccs := ?_
    componentOrder := ?_
  }
  · simp_all [Certificate.localChecked]
  · intro region member
    apply certificate.exactRegionSpanBinding_of_checked context region
    simp_all [Certificate.localChecked, Certificate.regionConcreteChecked]
  · intro region member
    apply certificate.exactRegionTransfer_of_checked context region
    simp_all [Certificate.localChecked, Certificate.regionConcreteChecked]
  · simp_all [Certificate.localChecked, Certificate.regionConcreteChecked]
  · simp_all [Certificate.localChecked]
  · simp_all [Certificate.localChecked]
  · simp_all [Certificate.localChecked]
  · simp_all [Certificate.localChecked]
  · simp_all [Certificate.localChecked]

def Location.read (state : MachineState) : Location -> Word
  | Location.register reg => state.registers.get reg
  | .frameWord base adjustment => state.read32 (adjustment.expression base |>.eval state)
  | .staticWord address => state.read32 (BitVec.ofNat 32 address)

def Value.holdsPair
    (context : StaticProofContext) (world : RelationalWorld)
    (originalLocation candidateLocation : Location) (value : Value)
    (originalState candidateState : MachineState) : Prop :=
  value.blockers = [] ∧
    ∃ atom ∈ value.atoms,
      atom.Holds context world (originalLocation.read originalState)
        (candidateLocation.read candidateState)

def State.holds
    (certificate : Certificate) (context : StaticProofContext)
    (world : RelationalWorld) (stateEvidence : State)
    (original candidate : MachineState) : Prop :=
    ∀ entry ∈ stateEvidence,
    ∃ pair, certificate.location? entry.locationId = some pair ∧
      entry.value.holdsPair context world pair.original pair.candidate
        original candidate

def Certificate.RegionTransferClosed
    (certificate : Certificate) (context : StaticProofContext) (region : Region) : Prop :=
  ∀ decoded, certificate.regionDecoded? context region = some decoded →
    ∀ world original candidate input output,
      region.input = some input → region.output = some output →
      State.holds certificate context world input original candidate →
      State.holds certificate context world output
        ((decoded.1.eval original).nextMachineState original)
        ((decoded.2.eval candidate).nextMachineState candidate)

def Certificate.BranchGuardPathRelated
    (certificate : Certificate) (context : StaticProofContext)
    (guard : BranchGuard) : Prop :=
  ∀ region decoded world original candidate input,
    certificate.region? guard.regionId = some region →
    certificate.regionDecoded? context region = some decoded →
    region.input = some input →
    State.holds certificate context world input original candidate →
    match decoded.1.outcome, decoded.2.outcome with
    | .branch originalCondition _ _, .branch candidateCondition _ _ =>
        originalCondition.eval original = candidateCondition.eval candidate
    | _, _ => False

/-- Acceptance remains beyond this module.  An integrator must provide actual
machine-state closure for every decoded transfer and, when calls occur, the
typed relational environment dependency used by local call replay. -/
structure Certificate.AcceptanceIntegrationPremise
    (certificate : Certificate) (context : StaticProofContext)
    (dependency : Option (CallSemanticDependency context)) : Prop where
  exactContext : ExactContextBinding context
  callSemanticsPresent :
    certificate.callReferences.isEmpty = false →
      ∃ semantics, dependency = some semantics
  transferSemantics :
    ∀ region ∈ certificate.regions,
      certificate.RegionTransferClosed context region
  guardSemantics :
    ∀ guard ∈ certificate.branchGuards,
      certificate.BranchGuardPathRelated context guard

end StageA.Relational.ControlValueProvenance
