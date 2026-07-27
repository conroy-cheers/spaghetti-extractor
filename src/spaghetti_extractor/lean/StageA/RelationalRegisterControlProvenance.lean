import Std

namespace StageA.Relational.RegisterControlProvenance

inductive X86Register where
  | eax | ebx | ecx | edx | esi | edi | ebp | esp
  deriving BEq, DecidableEq, Repr

structure RegisterPair where
  original : X86Register
  candidate : X86Register
  deriving BEq, DecidableEq, Repr

inductive ImportSelector where
  | symbol (name : String)
  | ordinal (value : Nat)
  deriving BEq, DecidableEq, Repr

structure ImportIdentity where
  dll : String
  selector : ImportSelector
  deriving BEq, DecidableEq, Repr

inductive ProvenanceAtom where
  | exactCodePointer
      (producerRegion targetId : Nat) (registerPair : RegisterPair)
      (claimKind : String)
  | staticCodePointer
      (producerRegion targetId : Nat) (registerPair : RegisterPair)
      (claimKind : String)
  | importReturn
      (producerRegion machineContractId : Nat)
      (registerPair : RegisterPair) (identity : ImportIdentity)
  deriving BEq, DecidableEq, Repr

inductive Blocker where
  | unknownCall
  | ambiguousWritableLoad
  | disjunctionBudgetExceeded
  | unknownOrClobbered
  | registerPairMismatch
  | fixedPointNotConverged
  | invalidIndirectControlAtom
  deriving BEq, DecidableEq, Repr

structure ProvenanceValue where
  atoms : List ProvenanceAtom
  blockers : List Blocker
  deriving BEq, DecidableEq, Repr

structure RegisterStateEntry where
  registerPair : RegisterPair
  value : ProvenanceValue
  deriving BEq, DecidableEq, Repr

abbrev RegisterState := List RegisterStateEntry

structure RegisterCopy where
  output : RegisterPair
  source : RegisterPair
  deriving BEq, DecidableEq, Repr

structure BlockedOutput where
  output : RegisterPair
  reason : Blocker
  deriving BEq, DecidableEq, Repr

structure RegionTransfer where
  regionIndex : Nat
  copies : List RegisterCopy
  producers : List ProvenanceAtom
  blockedOutputs : List BlockedOutput
  preserveUnmentioned : Bool
  deriving BEq, DecidableEq, Repr

structure ImportResult where
  registerPair : RegisterPair
  identity : ImportIdentity
  deriving BEq, DecidableEq, Repr

structure CallContract where
  contractId : Nat
  preservedRegisters : List RegisterPair
  importResults : List ImportResult
  deriving BEq, DecidableEq, Repr

inductive EdgeKind where
  | direct
  | callReturn
  deriving BEq, DecidableEq, Repr

structure RegionEdge where
  edgeIndex : Nat
  sourceRegion : Nat
  targetRegion : Nat
  kind : EdgeKind
  machineContractId : Option Nat
  deriving BEq, DecidableEq, Repr

structure RegionEvidence where
  regionIndex : Nat
  input : Option RegisterState
  output : Option RegisterState
  deriving BEq, DecidableEq, Repr

structure SCCStateEvidence where
  regionIndex : Nat
  state : Option RegisterState
  deriving BEq, DecidableEq, Repr

structure SCCEvidence where
  componentId : Nat
  regionIndices : List Nat
  predecessorComponentIds : List Nat
  successorComponentIds : List Nat
  edgeIndices : List Nat
  cyclic : Bool
  inputStates : List SCCStateEvidence
  outputStates : List SCCStateEvidence
  deriving BEq, DecidableEq, Repr

inductive UsePurpose where
  | registerState
  | indirectControl
  deriving BEq, DecidableEq, Repr

structure ControlUse where
  useIndex : Nat
  regionIndex : Nat
  registerPair : RegisterPair
  purpose : UsePurpose
  observed : ProvenanceValue
  deriving BEq, DecidableEq, Repr

structure Certificate where
  regionCount : Nat
  finiteDisjunctionBudget : Nat
  fixedPointConverged : Bool
  registerPairs : List RegisterPair
  entryRegionIndices : List Nat
  transfers : List RegionTransfer
  callContracts : List CallContract
  edges : List RegionEdge
  regions : List RegionEvidence
  componentOrder : List Nat
  sccs : List SCCEvidence
  uses : List ControlUse
  deriving BEq, DecidableEq, Repr

def noDuplicates [BEq alpha] (items : List alpha) : Bool :=
  items.length == items.eraseDups.length

def sameFiniteSet [BEq alpha] (left right : List alpha) : Bool :=
  noDuplicates left && noDuplicates right &&
    left.all right.contains && right.all left.contains

def ProvenanceValue.semanticallyEqual
    (left right : ProvenanceValue) : Bool :=
  sameFiniteSet left.atoms right.atoms &&
    sameFiniteSet left.blockers right.blockers

def RegisterState.lookupValue
    (state : RegisterState) (pair : RegisterPair) : Option ProvenanceValue :=
  (state.find? fun entry => entry.registerPair == pair).map (·.value)

def RegisterState.semanticallyEqual
    (left right : RegisterState) : Bool :=
  sameFiniteSet (left.map (·.registerPair)) (right.map (·.registerPair)) &&
    left.all fun entry =>
      match right.lookupValue entry.registerPair with
      | some value => entry.value.semanticallyEqual value
      | none => false

def optionalStateSemanticallyEqual
    (left right : Option RegisterState) : Bool :=
  match left, right with
  | none, none => true
  | some leftState, some rightState => leftState.semanticallyEqual rightState
  | _, _ => false

def ProvenanceAtom.registerPair : ProvenanceAtom -> RegisterPair
  | .exactCodePointer _ _ pair _ => pair
  | .staticCodePointer _ _ pair _ => pair
  | .importReturn _ _ pair _ => pair

def ProvenanceAtom.producerRegion : ProvenanceAtom -> Nat
  | .exactCodePointer region _ _ _ => region
  | .staticCodePointer region _ _ _ => region
  | .importReturn region _ _ _ => region

def ProvenanceAtom.isCodePointer : ProvenanceAtom -> Bool
  | .exactCodePointer _ _ _ _ => true
  | .staticCodePointer _ _ _ _ => true
  | .importReturn _ _ _ _ => false

def ImportIdentity.checked (identity : ImportIdentity) : Bool :=
  !identity.dll.isEmpty &&
    match identity.selector with
    | .symbol name => !name.isEmpty
    | .ordinal _ => true

def Certificate.pairKnown
    (certificate : Certificate) (pair : RegisterPair) : Bool :=
  certificate.registerPairs.contains pair

def Certificate.atomChecked
    (certificate : Certificate) (atom : ProvenanceAtom) : Bool :=
  atom.producerRegion < certificate.regionCount &&
    certificate.pairKnown atom.registerPair &&
    match atom with
    | .exactCodePointer _ _ _ claimKind => !claimKind.isEmpty
    | .staticCodePointer _ _ _ claimKind => !claimKind.isEmpty
    | .importReturn _ contractId pair identity =>
        identity.checked && certificate.callContracts.any (fun contract =>
          contract.contractId == contractId &&
            contract.importResults.any (fun result =>
              result.registerPair == pair && result.identity == identity))

def Certificate.valueChecked
    (certificate : Certificate) (value : ProvenanceValue) : Bool :=
  noDuplicates value.atoms && noDuplicates value.blockers &&
    value.atoms.length <= certificate.finiteDisjunctionBudget &&
    value.atoms.all certificate.atomChecked &&
    !value.blockers.contains .disjunctionBudgetExceeded &&
    !value.blockers.contains .fixedPointNotConverged

def Certificate.stateChecked
    (certificate : Certificate) (state : RegisterState) : Bool :=
  sameFiniteSet (state.map (·.registerPair)) certificate.registerPairs &&
    state.all fun entry => certificate.valueChecked entry.value

def unknownValue : ProvenanceValue := {
  atoms := []
  blockers := [.unknownOrClobbered]
}

def Certificate.atomValue
    (certificate : Certificate) (atoms : List ProvenanceAtom) : ProvenanceValue :=
  let unique := atoms.eraseDups
  if unique.length > certificate.finiteDisjunctionBudget then
    { atoms := [], blockers := [.disjunctionBudgetExceeded] }
  else
    { atoms := unique, blockers := [] }

def Certificate.joinValues
    (certificate : Certificate) (values : List ProvenanceValue) : ProvenanceValue :=
  if values.isEmpty then
    unknownValue
  else
    let blockers := (values.flatMap (·.blockers)).eraseDups
    if blockers.isEmpty then
      certificate.atomValue (values.flatMap (·.atoms))
    else
      { atoms := [], blockers := blockers }

def Certificate.transfer? (certificate : Certificate) (region : Nat) :
    Option RegionTransfer :=
  certificate.transfers.find? fun transfer => transfer.regionIndex == region

def Certificate.contract? (certificate : Certificate) (contractId : Nat) :
    Option CallContract :=
  certificate.callContracts.find? fun contract => contract.contractId == contractId

def Certificate.region? (certificate : Certificate) (region : Nat) :
    Option RegionEvidence :=
  certificate.regions.find? fun evidence => evidence.regionIndex == region

def RegionTransfer.outputPairs (transfer : RegionTransfer) : List RegisterPair :=
  transfer.copies.map (·.output) ++
    transfer.producers.map ProvenanceAtom.registerPair ++
    transfer.blockedOutputs.map (·.output)

def Certificate.transferValue
    (certificate : Certificate) (transfer : RegionTransfer)
    (input : RegisterState) (pair : RegisterPair) : ProvenanceValue :=
  match transfer.copies.find? fun copy => copy.output == pair with
  | some copy => (input.lookupValue copy.source).getD unknownValue
  | none =>
      let produced := transfer.producers.filter fun atom => atom.registerPair == pair
      if !produced.isEmpty then
        certificate.atomValue produced
      else
        match transfer.blockedOutputs.find? fun blocked => blocked.output == pair with
        | some blocked => { atoms := [], blockers := [blocked.reason] }
        | none =>
            if transfer.preserveUnmentioned then
              (input.lookupValue pair).getD unknownValue
            else
              unknownValue

def Certificate.transferState
    (certificate : Certificate) (transfer : RegionTransfer)
    (input : RegisterState) : RegisterState :=
  certificate.registerPairs.map fun pair => {
    registerPair := pair
    value := certificate.transferValue transfer input pair
  }

def Certificate.joinStates
    (certificate : Certificate) (states : List RegisterState) : RegisterState :=
  certificate.registerPairs.map fun pair => {
    registerPair := pair
    value := certificate.joinValues <|
      states.map fun state => (state.lookupValue pair).getD unknownValue
  }

def Certificate.edgeValue
    (certificate : Certificate) (edge : RegionEdge)
    (source : RegisterState) (pair : RegisterPair) : ProvenanceValue :=
  match edge.kind with
  | .direct => (source.lookupValue pair).getD unknownValue
  | .callReturn =>
      match edge.machineContractId.bind certificate.contract? with
      | none => { atoms := [], blockers := [.unknownCall] }
      | some contract =>
          match contract.importResults.find? fun result =>
              result.registerPair == pair with
          | some result => certificate.atomValue [
              .importReturn edge.sourceRegion contract.contractId pair result.identity]
          | none =>
              if contract.preservedRegisters.contains pair then
                (source.lookupValue pair).getD unknownValue
              else
                unknownValue

def Certificate.expectedInput
    (certificate : Certificate) (region : Nat) : Option RegisterState :=
  let incoming := certificate.edges.filter fun edge => edge.targetRegion == region
  let available := incoming.filterMap fun edge =>
    (certificate.region? edge.sourceRegion).bind fun evidence =>
      evidence.output.map fun state => (edge, state)
  if available.isEmpty && !(region ∈ certificate.entryRegionIndices) then
    none
  else
    some <| certificate.registerPairs.map fun pair => {
      registerPair := pair
      value := certificate.joinValues <|
        available.map (fun item => certificate.edgeValue item.1 item.2 pair) ++
          if region ∈ certificate.entryRegionIndices then [unknownValue] else []
    }

def Certificate.expectedOutput
    (certificate : Certificate) (evidence : RegionEvidence) :
    Option RegisterState :=
  match evidence.input, certificate.transfer? evidence.regionIndex with
  | some input, some transfer =>
      let transferred := certificate.transferState transfer input
      some <| match evidence.output with
        | none => transferred
        | some previous => certificate.joinStates [previous, transferred]
  | _, _ => none

def Certificate.regionReplayChecked
    (certificate : Certificate) (evidence : RegionEvidence) : Bool :=
  evidence.regionIndex < certificate.regionCount &&
    optionalStateSemanticallyEqual evidence.input
      (certificate.expectedInput evidence.regionIndex) &&
    optionalStateSemanticallyEqual evidence.output
      (certificate.expectedOutput evidence) &&
    (match evidence.input with
      | none => true
      | some state => certificate.stateChecked state) &&
    match evidence.output with
    | none => true
    | some state => certificate.stateChecked state

def Certificate.transferChecked
    (certificate : Certificate) (transfer : RegionTransfer) : Bool :=
  transfer.regionIndex < certificate.regionCount &&
    noDuplicates transfer.outputPairs && transfer.blockedOutputs.isEmpty &&
    transfer.copies.all (fun copy =>
      certificate.pairKnown copy.output && certificate.pairKnown copy.source) &&
    transfer.producers.all (fun atom =>
      certificate.atomChecked atom && atom.isCodePointer)

def Certificate.contractChecked
    (certificate : Certificate) (contract : CallContract) : Bool :=
  noDuplicates contract.preservedRegisters &&
    noDuplicates (contract.importResults.map (·.registerPair)) &&
    contract.preservedRegisters.all certificate.pairKnown &&
    contract.importResults.all (fun result =>
      certificate.pairKnown result.registerPair && result.identity.checked &&
        !contract.preservedRegisters.contains result.registerPair)

def Certificate.edgeChecked
    (certificate : Certificate) (edge : RegionEdge) : Bool :=
  edge.sourceRegion < certificate.regionCount &&
    edge.targetRegion < certificate.regionCount &&
    match edge.kind, edge.machineContractId with
    | .direct, none => true
    | .callReturn, some contractId =>
        certificate.callContracts.any (fun contract =>
          contract.contractId == contractId)
    | _, _ => false

def Certificate.componentFor? (certificate : Certificate) (region : Nat) :
    Option Nat :=
  (certificate.sccs.find? fun component =>
    region ∈ component.regionIndices).map (·.componentId)

def Certificate.expectedComponentEdges
    (certificate : Certificate) (component : SCCEvidence) : List Nat :=
  (certificate.edges.filter fun edge =>
    edge.sourceRegion ∈ component.regionIndices &&
      edge.targetRegion ∈ component.regionIndices).map (·.edgeIndex)

def Certificate.expectedPredecessors
    (certificate : Certificate) (component : SCCEvidence) : List Nat :=
  (certificate.edges.filterMap fun edge =>
    match certificate.componentFor? edge.sourceRegion,
        certificate.componentFor? edge.targetRegion with
    | some source, some target =>
        if target == component.componentId && source != target then some source else none
    | _, _ => none).eraseDups

def Certificate.expectedSuccessors
    (certificate : Certificate) (component : SCCEvidence) : List Nat :=
  (certificate.edges.filterMap fun edge =>
    match certificate.componentFor? edge.sourceRegion,
        certificate.componentFor? edge.targetRegion with
    | some source, some target =>
        if source == component.componentId && source != target then some target else none
    | _, _ => none).eraseDups

def Certificate.expectedCyclic
    (certificate : Certificate) (component : SCCEvidence) : Bool :=
  component.regionIndices.length > 1 || certificate.edges.any (fun edge =>
    edge.sourceRegion == edge.targetRegion &&
      edge.sourceRegion ∈ component.regionIndices)

def Certificate.sccStateChecked
    (certificate : Certificate) (isInput : Bool)
    (component : SCCEvidence) (state : SCCStateEvidence) : Bool :=
  state.regionIndex ∈ component.regionIndices &&
    match certificate.region? state.regionIndex with
    | none => false
    | some region => optionalStateSemanticallyEqual state.state
        (if isInput then region.input else region.output)

def Certificate.sccChecked
    (certificate : Certificate) (component : SCCEvidence) : Bool :=
  component.componentId < certificate.sccs.length &&
    noDuplicates component.regionIndices &&
    component.regionIndices.all (· < certificate.regionCount) &&
    sameFiniteSet component.edgeIndices
      (certificate.expectedComponentEdges component) &&
    sameFiniteSet component.predecessorComponentIds
      (certificate.expectedPredecessors component) &&
    sameFiniteSet component.successorComponentIds
      (certificate.expectedSuccessors component) &&
    component.cyclic == certificate.expectedCyclic component &&
    sameFiniteSet (component.inputStates.map (·.regionIndex))
      component.regionIndices &&
    sameFiniteSet (component.outputStates.map (·.regionIndex))
      component.regionIndices &&
    component.inputStates.all (certificate.sccStateChecked true component) &&
    component.outputStates.all (certificate.sccStateChecked false component)

def indexOf? [BEq alpha] (item : alpha) : List alpha -> Option Nat
  | [] => none
  | head :: tail =>
      if head == item then some 0 else (indexOf? item tail).map Nat.succ

def Certificate.componentOrderChecked (certificate : Certificate) : Bool :=
  sameFiniteSet certificate.componentOrder
    (certificate.sccs.map (·.componentId)) &&
    certificate.edges.all fun edge =>
      match certificate.componentFor? edge.sourceRegion,
          certificate.componentFor? edge.targetRegion with
      | some source, some target =>
          source == target ||
            match indexOf? source certificate.componentOrder,
                indexOf? target certificate.componentOrder with
            | some sourcePosition, some targetPosition =>
                sourcePosition < targetPosition
            | _, _ => false
      | _, _ => false

def Certificate.useChecked
    (certificate : Certificate) (use : ControlUse) : Bool :=
  use.regionIndex < certificate.regionCount &&
    certificate.pairKnown use.registerPair &&
    certificate.valueChecked use.observed && use.observed.blockers.isEmpty &&
    (match certificate.region? use.regionIndex with
      | none => false
      | some region =>
          match region.input.bind (·.lookupValue use.registerPair) with
          | none => false
          | some value => use.observed.semanticallyEqual value) &&
    match use.purpose with
    | .registerState => true
    | .indirectControl =>
        !use.observed.atoms.isEmpty &&
          use.observed.atoms.all ProvenanceAtom.isCodePointer

def Certificate.inventoryChecked (certificate : Certificate) : Bool :=
  certificate.regionCount > 0 &&
    certificate.finiteDisjunctionBudget > 0 &&
    certificate.fixedPointConverged && !certificate.registerPairs.isEmpty &&
    noDuplicates certificate.registerPairs &&
    noDuplicates (certificate.registerPairs.map (·.original)) &&
    noDuplicates (certificate.registerPairs.map (·.candidate)) &&
    noDuplicates certificate.entryRegionIndices &&
    certificate.entryRegionIndices.all (· < certificate.regionCount) &&
    sameFiniteSet (certificate.transfers.map (·.regionIndex))
      (List.range certificate.regionCount) &&
    certificate.transfers.all certificate.transferChecked &&
    noDuplicates (certificate.callContracts.map (·.contractId)) &&
    certificate.callContracts.all certificate.contractChecked &&
    noDuplicates (certificate.edges.map (·.edgeIndex)) &&
    certificate.edges.all certificate.edgeChecked &&
    sameFiniteSet (certificate.regions.map (·.regionIndex))
      (List.range certificate.regionCount) &&
    sameFiniteSet (certificate.sccs.map (·.componentId))
      (List.range certificate.sccs.length) &&
    sameFiniteSet (certificate.sccs.flatMap (·.regionIndices))
      (List.range certificate.regionCount) &&
    sameFiniteSet (certificate.uses.map (·.useIndex))
      (List.range certificate.uses.length)

def Certificate.fixedPointReplayChecked (certificate : Certificate) : Bool :=
  certificate.regions.all certificate.regionReplayChecked

def Certificate.sccReplayChecked (certificate : Certificate) : Bool :=
  certificate.sccs.all certificate.sccChecked &&
    certificate.componentOrderChecked

def Certificate.usesAdmissibleChecked (certificate : Certificate) : Bool :=
  certificate.uses.all certificate.useChecked

def Certificate.checked (certificate : Certificate) : Bool :=
  certificate.inventoryChecked && certificate.fixedPointReplayChecked &&
    certificate.sccReplayChecked && certificate.usesAdmissibleChecked

def Certificate.FixedPointReplay (certificate : Certificate) : Prop :=
  ∀ region ∈ certificate.regions, certificate.regionReplayChecked region = true

def Certificate.SCCReplay (certificate : Certificate) : Prop :=
  certificate.componentOrderChecked = true ∧
    ∀ component ∈ certificate.sccs, certificate.sccChecked component = true

def Certificate.UsesAdmissible (certificate : Certificate) : Prop :=
  ∀ use ∈ certificate.uses, certificate.useChecked use = true

structure Certificate.SemanticallyValid (certificate : Certificate) : Prop where
  inventory : certificate.inventoryChecked = true
  fixedPoint : certificate.FixedPointReplay
  scc : certificate.SCCReplay
  uses : certificate.UsesAdmissible

theorem Certificate.checked_sound
    {certificate : Certificate} (checked : certificate.checked = true) :
    certificate.SemanticallyValid := by
  simp only [Certificate.checked, Bool.and_eq_true] at checked
  have fixedPointChecked := checked.1.1.2
  have sccChecked := checked.1.2
  have usesChecked := checked.2
  simp only [Certificate.fixedPointReplayChecked, List.all_eq_true]
    at fixedPointChecked
  simp only [Certificate.sccReplayChecked, Bool.and_eq_true,
    List.all_eq_true] at sccChecked
  simp only [Certificate.usesAdmissibleChecked, List.all_eq_true]
    at usesChecked
  exact {
    inventory := checked.1.1.1
    fixedPoint := fixedPointChecked
    scc := ⟨sccChecked.2, sccChecked.1⟩
    uses := usesChecked
  }

theorem Certificate.checked_region_replay
    {certificate : Certificate} (checked : certificate.checked = true)
    {region : RegionEvidence} (member : region ∈ certificate.regions) :
    certificate.regionReplayChecked region = true :=
  (certificate.checked_sound checked).fixedPoint region member

theorem Certificate.checked_scc_replay
    {certificate : Certificate} (checked : certificate.checked = true)
    {component : SCCEvidence} (member : component ∈ certificate.sccs) :
    certificate.sccChecked component = true :=
  (certificate.checked_sound checked).scc.2 component member

theorem Certificate.checked_use_admissible
    {certificate : Certificate} (checked : certificate.checked = true)
    {use : ControlUse} (member : use ∈ certificate.uses) :
    certificate.useChecked use = true :=
  (certificate.checked_sound checked).uses use member

theorem Certificate.checked_indirect_use_classified
    {certificate : Certificate} (checked : certificate.checked = true)
    {use : ControlUse} (member : use ∈ certificate.uses)
    (purpose : use.purpose = .indirectControl) :
    use.observed.blockers.isEmpty = true ∧
      (!use.observed.atoms.isEmpty) = true ∧
      use.observed.atoms.all ProvenanceAtom.isCodePointer = true := by
  have useChecked := certificate.checked_use_admissible checked member
  simp only [Certificate.useChecked, Bool.and_eq_true] at useChecked
  have classification := useChecked.2
  simp only [purpose, Bool.and_eq_true] at classification
  exact ⟨useChecked.1.1.2, classification⟩

end StageA.Relational.RegisterControlProvenance
