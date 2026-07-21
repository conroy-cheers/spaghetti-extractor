import StageA.RelationalCertificates

namespace StageA.Relational

open StageA.Formal

/-- Register-relative facts belong only to the active frame.  Dormant frames
retain their return-slot and exact-word facts through
`RelationalLinkedRuntimeCallStackHolds`; requiring their old register aliases at
every nested depth would recreate the unbounded flat-stack abstraction. -/
def RelationalLinkedRuntimeCallFactsHold (context : StaticProofContext)
    (world : RelationalWorld) :
    Option ReturnSlotOffsetInventory -> Registers Word -> Registers Word -> Prop
  | none, _, _ => True
  | some inventory, originalRegisters, candidateRegisters =>
      inventory.preservedImportsHold world originalRegisters candidateRegisters = true ∧
        inventory.preservedRelationsHold context world originalRegisters
          candidateRegisters = true

@[simp]
theorem RelationalLinkedRuntimeCallFactsHold.none (context : StaticProofContext)
    (world : RelationalWorld) (originalRegisters candidateRegisters : Registers Word) :
    RelationalLinkedRuntimeCallFactsHold context world none originalRegisters
      candidateRegisters := by
  trivial

theorem RelationalLinkedRuntimeCallFactsHold.some_of_singleton
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallFactsHold context world [inventory]
      originalRegisters candidateRegisters) :
    RelationalLinkedRuntimeCallFactsHold context world (some inventory)
      originalRegisters candidateRegisters := by
  exact ⟨holds.1.1, holds.2.1⟩

theorem RelationalLinkedRuntimeCallFactsHold.afterInternal
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : RelationalRuntimeCallImportTransferClaim)
    (originalState candidateState : MachineState)
    (checked : claim.factsChecked context originalBehavior candidateBehavior = true)
    (holds : RelationalLinkedRuntimeCallFactsHold context world (some claim.source)
      originalState.registers candidateState.registers) :
    RelationalLinkedRuntimeCallFactsHold context world (some claim.target)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  have singletonHolds : RelationalRuntimeCallFactsHold context world [claim.source]
      originalState.registers candidateState.registers :=
    ⟨⟨holds.1, by trivial⟩, ⟨holds.2, by trivial⟩⟩
  have transferred := RelationalRuntimeCallFactsHold.afterInternal context world
    originalBehavior candidateBehavior [claim] originalState candidateState
    (by simpa using checked) singletonHolds
  exact RelationalLinkedRuntimeCallFactsHold.some_of_singleton context world
    claim.target (originalBehavior.eval originalState).registers
    (candidateBehavior.eval candidateState).registers transferred

def RelationalRuntimeCallImportTransferClaim.frameFactsChecked
    (context : StaticProofContext)
    (claim : RelationalRuntimeCallImportTransferClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (frameClaims : List FrameExactWordRegisterOutputClaim) : Bool :=
  let carried := claim.carriedRelations.getD claim.source.preservedRelations
  claim.checked originalBehavior candidateBehavior &&
    claim.source.seedsPreservedRelationsFromFrameWords context claim.target
      originalBehavior candidateBehavior carried frameClaims

/-- Transfer the active-frame fact inventory while adding register facts
derived from checked exact frame words.  This is intentionally a linked-frame
rule: ordinary regional `StateRel` proofs do not gain hidden launch or caller
assumptions. -/
theorem RelationalLinkedRuntimeCallFactsHold.afterInternalWithFrameWords
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : RelationalRuntimeCallImportTransferClaim)
    (frameClaims : List FrameExactWordRegisterOutputClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.frameFactsChecked context originalBehavior
      candidateBehavior frameClaims = true)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some claim.source) originalState.registers candidateState.registers)
    (locationsHold : claim.source.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : claim.source.exactWordsHold frame originalState.memory
      candidateState.memory) :
    RelationalLinkedRuntimeCallFactsHold context world (some claim.target)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  simp only [RelationalRuntimeCallImportTransferClaim.frameFactsChecked,
    Bool.and_eq_true] at checked
  have importShape := checked.1
  simp only [RelationalRuntimeCallImportTransferClaim.checked,
    Bool.and_eq_true, beq_iff_eq] at importShape
  rcases importShape with
    ⟨⟨sourceImportsPreserved, _targetChecked⟩, targetImports⟩
  have sourceImportsNext :=
    claim.source.preservedImportsHold_after_of_checked world originalBehavior
      candidateBehavior originalState candidateState sourceImportsPreserved factsHold.1
  have targetImportsNext : claim.target.preservedImportsHold world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
    simpa only [ReturnSlotOffsetInventory.preservedImportsHold,
      targetImports] using sourceImportsNext
  have targetRelationsNext :=
    claim.source.preservedRelationsHold_after_frame_words context world
      claim.target originalBehavior candidateBehavior
      (claim.carriedRelations.getD claim.source.preservedRelations) frameClaims frame
      originalState candidateState checked.2 factsHold.2 locationsHold exactWordsHold
  exact ⟨targetImportsNext, targetRelationsNext⟩

def RelationalRuntimeCallImportTransferClaim.frameEvidenceChecked
    (context : StaticProofContext)
    (claim : RelationalRuntimeCallImportTransferClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (wordClaims : List FrameExactWordRegisterOutputClaim)
    (expressionClaims : List FramePairedExpressionRegisterOutputClaim) : Bool :=
  let carried := claim.carriedRelations.getD claim.source.preservedRelations
  claim.checked originalBehavior candidateBehavior &&
    claim.source.seedsPreservedRelationsFromFrameEvidence context claim.target
      originalBehavior candidateBehavior carried wordClaims expressionClaims

/-- Transfer the active frame while allowing both exact frame-word loads and
paired pure register expressions to refresh its register relation inventory. -/
theorem RelationalLinkedRuntimeCallFactsHold.afterInternalWithFrameEvidence
    (context : StaticProofContext) (world : RelationalWorld)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (claim : RelationalRuntimeCallImportTransferClaim)
    (wordClaims : List FrameExactWordRegisterOutputClaim)
    (expressionClaims : List FramePairedExpressionRegisterOutputClaim)
    (frame : RelationalRuntimeCallFrame)
    (originalState candidateState : MachineState)
    (checked : claim.frameEvidenceChecked context originalBehavior
      candidateBehavior wordClaims expressionClaims = true)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some claim.source) originalState.registers candidateState.registers)
    (locationsHold : claim.source.holds frame originalState.registers
      candidateState.registers)
    (exactWordsHold : claim.source.exactWordsHold frame originalState.memory
      candidateState.memory) :
    RelationalLinkedRuntimeCallFactsHold context world (some claim.target)
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers := by
  simp only [RelationalRuntimeCallImportTransferClaim.frameEvidenceChecked,
    Bool.and_eq_true] at checked
  have importShape := checked.1
  simp only [RelationalRuntimeCallImportTransferClaim.checked,
    Bool.and_eq_true, beq_iff_eq] at importShape
  rcases importShape with
    ⟨⟨sourceImportsPreserved, _targetChecked⟩, targetImports⟩
  have sourceImportsNext :=
    claim.source.preservedImportsHold_after_of_checked world originalBehavior
      candidateBehavior originalState candidateState sourceImportsPreserved factsHold.1
  have targetImportsNext : claim.target.preservedImportsHold world
      (originalBehavior.eval originalState).registers
      (candidateBehavior.eval candidateState).registers = true := by
    simpa only [ReturnSlotOffsetInventory.preservedImportsHold,
      targetImports] using sourceImportsNext
  have targetRelationsNext :=
    claim.source.preservedRelationsHold_after_frame_evidence context world
      claim.target originalBehavior candidateBehavior
      (claim.carriedRelations.getD claim.source.preservedRelations) wordClaims
      expressionClaims frame originalState candidateState checked.2 factsHold.2
      locationsHold exactWordsHold
  exact ⟨targetImportsNext, targetRelationsNext⟩

theorem RelationalLinkedRuntimeCallFactsHold.guardEvalEqual_of_frameExact
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : ReturnSlotOffsetInventory)
    (originalGuard candidateGuard : BoolExpr) (claim : FrameExactGuardClaim)
    (original candidate : MachineState)
    (checked : claim.checked inventory originalGuard candidateGuard = true)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some inventory) original.registers candidate.registers) :
    originalGuard.eval original = candidateGuard.eval candidate := by
  exact claim.eval_equal_of_checked context world inventory originalGuard
    candidateGuard checked original candidate factsHold.2

/-- Make the active frame's proved register facts available to an ordinary
segment refinement.  The strengthened invariant is local to that refinement;
it does not mutate the product graph's authoritative node invariant. -/
theorem RelationalLinkedRuntimeCallFactsHold.strengthenStateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (inventory : ReturnSlotOffsetInventory)
    (original candidate : MachineState)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some inventory) original.registers candidate.registers)
    (related : StateRel context world invariant original candidate) :
    StateRel context world
      (invariant.withAdditionalRegisterRelations inventory.preservedRelations)
      original candidate := by
  apply related.withAdditionalRegisterRelations context world invariant
    inventory.preservedRelations original candidate
  exact factsHold.2

/-- An active-frame fact inventory can be re-established from the target
invariant itself.  This is the natural boundary after a linked return: dormant
register-relative facts are not required while the parent is suspended, and
become meaningful again only after its invariant has been restored. -/
def ReturnSlotOffsetInventory.seededByInvariant
    (inventory : ReturnSlotOffsetInventory) (invariant : StateInvariant) : Bool :=
  inventory.checked &&
    inventory.preservedImports.all invariant.importRegisterRelations.contains &&
    inventory.preservedRelations.all invariant.registerRelations.contains

theorem RelationalLinkedRuntimeCallFactsHold.of_stateRel
    (context : StaticProofContext) (world : RelationalWorld)
    (invariant : StateInvariant) (inventory : ReturnSlotOffsetInventory)
    (original candidate : MachineState)
    (seeded : inventory.seededByInvariant invariant = true)
    (related : StateRel context world invariant original candidate) :
    RelationalLinkedRuntimeCallFactsHold context world (some inventory)
      original.registers candidate.registers := by
  simp only [ReturnSlotOffsetInventory.seededByInvariant,
    Bool.and_eq_true] at seeded
  rcases seeded with ⟨⟨_inventoryChecked, importMembers⟩, relationMembers⟩
  rcases related with
    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,
      _importsComplete, _importsMemory, _originalImmutable,
      _candidateImmutable, core, importRegisters⟩
  constructor
  · unfold ReturnSlotOffsetInventory.preservedImportsHold
    have invariantHolds := importRegisters.1
    unfold importRegisterRelationsHold at invariantHolds ⊢
    simp only [List.all_eq_true] at importMembers invariantHolds ⊢
    intro relation relationMember
    exact invariantHolds relation
      (List.contains_iff_mem.mp (importMembers relation relationMember))
  · unfold ReturnSlotOffsetInventory.preservedRelationsHold
    have invariantHolds := core.1
    unfold registerRelationsHold at invariantHolds ⊢
    simp only [List.all_eq_true] at relationMembers invariantHolds ⊢
    intro relation relationMember
    exact invariantHolds relation
      (List.contains_iff_mem.mp (relationMembers relation relationMember))

/-- The compatibility bridge below is deliberately limited to zero or one
runtime frame.  It is useful while generated local proofs migrate, but cannot
justify recursive or otherwise nested execution. -/
def ShallowRuntimeCallProjection (calls : List Nat)
    (inventories : List ReturnSlotOffsetInventory)
    (active : Option ReturnSlotOffsetInventory) : Prop :=
  (calls = [] ∧ inventories = [] ∧ active = none) ∨
    ∃ continuation inventory,
      calls = [continuation] ∧ inventories = [inventory] ∧ active = some inventory

def ShallowRuntimeCalls (calls : List Nat) : Prop :=
  calls = [] ∨ ∃ continuation, calls = [continuation]

def ProductControlProfilesOldToLinkedShallow
    (old : ProductControlProfile) (linked : LinkedProductControlProfile) : Prop :=
  ∀ nodeId calls inventories,
    old.Allows nodeId calls inventories = true →
      ∃ active, ShallowRuntimeCallProjection calls inventories active ∧
        linked.Allows nodeId calls active = true

def ProductControlProfilesLinkedToOldShallow
    (old : ProductControlProfile) (linked : LinkedProductControlProfile) : Prop :=
  ∀ nodeId calls active,
    linked.Allows nodeId calls active = true →
      ShallowRuntimeCalls calls →
      ∃ inventories, ShallowRuntimeCallProjection calls inventories active ∧
        old.Allows nodeId calls inventories = true

def ProductControlState.toLinkedShallow?
    (state : ProductControlState) : Option LinkedProductControlState :=
  match state.calls, state.frameOffsets with
  | [], [] => some {
      nodeId := state.nodeId, continuation := none, active := none,
      minimumDepth := 0 }
  | [continuation], [inventory] =>
      some {
        nodeId := state.nodeId
        continuation := some continuation
        active := some inventory
        minimumDepth := 1
      }
  | _, _ => none

def LinkedProductControlState.toOldShallow
    (state : LinkedProductControlState) : ProductControlState :=
  match state.continuation, state.active with
  | none, none => { nodeId := state.nodeId, calls := [], frameOffsets := [] }
  | some continuation, some inventory =>
      { nodeId := state.nodeId, calls := [continuation], frameOffsets := [inventory] }
  | _, _ => { nodeId := state.nodeId, calls := [], frameOffsets := [] }

def ProductControlProfilesShallowEquivalent
    (old : ProductControlProfile) (linked : LinkedProductControlProfile) : Bool :=
  old.checked && (linked.checked && (linked.links.isEmpty &&
    (old.states.all fun state =>
      match state.toLinkedShallow? with
      | some projected => linked.states.contains projected
      | none => false) &&
    (linked.states.all fun state =>
      old.states.contains state.toOldShallow)))

theorem ProductControlProfilesShallowEquivalent.oldToLinked
    (old : ProductControlProfile) (linked : LinkedProductControlProfile)
    (checked : ProductControlProfilesShallowEquivalent old linked = true) :
    ProductControlProfilesOldToLinkedShallow old linked := by
  simp only [ProductControlProfilesShallowEquivalent, Bool.and_eq_true] at checked
  have oldChecked := checked.1
  have linkedChecked := checked.2.1
  have forwardChecked := checked.2.2.1.2
  intro nodeId calls inventories allowed
  simp only [ProductControlProfile.Allows, Bool.and_eq_true] at allowed
  let state : ProductControlState := { nodeId, calls, frameOffsets := inventories }
  have member : state ∈ old.states := List.contains_iff_mem.mp allowed.2
  have projected := List.all_eq_true.mp forwardChecked state member
  dsimp [state] at projected
  cases calls with
  | nil =>
      cases inventories with
      | nil =>
          refine ⟨none, Or.inl ⟨rfl, rfl, rfl⟩, ?_⟩
          simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true]
          refine ⟨linkedChecked, List.any_eq_true.mpr ⟨{
            nodeId := nodeId, continuation := none, active := none,
            minimumDepth := 0 }, ?_, by
              simp [LinkedProductControlState.matches]⟩⟩
          exact List.contains_iff_mem.mp (by
            simpa [ProductControlState.toLinkedShallow?] using projected)
      | cons inventory inventories =>
          simp [ProductControlState.toLinkedShallow?] at projected
  | cons continuation calls =>
      cases calls with
      | cons next calls =>
          simp [ProductControlState.toLinkedShallow?] at projected
      | nil =>
          cases inventories with
          | nil => simp [ProductControlState.toLinkedShallow?] at projected
          | cons inventory inventories =>
              cases inventories with
              | cons next inventories =>
                  simp [ProductControlState.toLinkedShallow?] at projected
              | nil =>
                  refine ⟨some inventory,
                    Or.inr ⟨continuation, inventory, rfl, rfl, rfl⟩, ?_⟩
                  simp only [LinkedProductControlProfile.Allows,
                    Bool.and_eq_true]
                  refine ⟨linkedChecked, List.any_eq_true.mpr ⟨{
                    nodeId := nodeId, continuation := some continuation,
                    active := some inventory, minimumDepth := 1 }, ?_, by
                      simp [LinkedProductControlState.matches]⟩⟩
                  exact List.contains_iff_mem.mp (by
                    simpa [ProductControlState.toLinkedShallow?] using projected)

theorem ProductControlProfilesShallowEquivalent.linkedToOld
    (old : ProductControlProfile) (linked : LinkedProductControlProfile)
    (checked : ProductControlProfilesShallowEquivalent old linked = true) :
    ProductControlProfilesLinkedToOldShallow old linked := by
  simp only [ProductControlProfilesShallowEquivalent, Bool.and_eq_true] at checked
  have oldChecked := checked.1
  have reverseChecked := checked.2.2.2
  intro nodeId calls active allowed shallowCalls
  simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true] at allowed
  rcases List.any_eq_true.mp allowed.2 with ⟨state, member, matched⟩
  simp only [Bool.and_eq_true] at matched
  have stateMatch := matched.1
  simp only [LinkedProductControlState.matches, Bool.and_eq_true,
    beq_iff_eq] at stateMatch
  have nodeExact : state.nodeId = nodeId := stateMatch.1.1
  have continuationExact : state.continuation = calls.head? := stateMatch.1.2
  have activeExact : state.active = active := stateMatch.2
  have projected := List.all_eq_true.mp reverseChecked state member
  have statesChecked :
      linked.states.all LinkedProductControlState.checked = true := by
    have profileChecked : linked.checked = true := allowed.1
    simp only [LinkedProductControlProfile.checked, Bool.and_eq_true]
      at profileChecked
    exact profileChecked.1.1.1
  have stateChecked := List.all_eq_true.mp statesChecked state member
  cases calls with
  | nil =>
      cases active with
      | none =>
          refine ⟨[], Or.inl ⟨rfl, rfl, rfl⟩, ?_⟩
          have projectedExact : state.toOldShallow =
              ({ nodeId := nodeId
                 calls := []
                 frameOffsets := [] } :
                ProductControlState) := by
            cases state <;> simp_all [LinkedProductControlState.toOldShallow]
          simpa only [ProductControlProfile.Allows, Bool.and_eq_true]
            using (And.intro oldChecked (by simpa [projectedExact] using projected))
      | some inventory =>
          cases state <;> simp_all [LinkedProductControlState.checked]
  | cons continuation calls =>
      cases calls with
      | cons next calls =>
          rcases shallowCalls with impossible | ⟨selected, impossible⟩
          · simp at impossible
          · simp at impossible
      | nil =>
          cases active with
          | none =>
              cases state <;> simp_all [LinkedProductControlState.checked]
          | some inventory =>
              refine ⟨[inventory],
                Or.inr ⟨continuation, inventory, rfl, rfl, rfl⟩, ?_⟩
              have projectedExact : state.toOldShallow =
                  ({ nodeId := nodeId
                     calls := [continuation]
                     frameOffsets := [inventory] } : ProductControlState) := by
                cases state <;> simp_all [LinkedProductControlState.toOldShallow]
              simpa only [ProductControlProfile.Allows, Bool.and_eq_true]
                using (And.intro oldChecked (by simpa [projectedExact] using projected))

theorem ProductControlProfilesShallowEquivalent.links_eq_nil
    (old : ProductControlProfile) (linked : LinkedProductControlProfile)
    (checked : ProductControlProfilesShallowEquivalent old linked = true) :
    linked.links = [] := by
  simp only [ProductControlProfilesShallowEquivalent, Bool.and_eq_true] at checked
  exact List.isEmpty_iff.mp checked.2.2.1.1

theorem RelationalRuntimeCallStackHolds.toLinkedShallow
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (calls : List Nat)
    (inventories : List ReturnSlotOffsetInventory)
    (active : Option ReturnSlotOffsetInventory)
    (holds : RelationalRuntimeCallStackHolds context original candidate frames calls
      inventories)
    (projection : ShallowRuntimeCallProjection calls inventories active)
    (activeChecked : ∀ inventory, active = some inventory → inventory.checked = true) :
    RelationalLinkedRuntimeCallStackHolds context original candidate frames calls
      active [] := by
  rcases projection with empty | singleton
  · rcases empty with ⟨rfl, rfl, rfl⟩
    cases frames with
    | nil => simp [RelationalLinkedRuntimeCallStackHolds]
    | cons frame frames => simp [RelationalRuntimeCallStackHolds] at holds
  · rcases singleton with ⟨continuation, inventory, rfl, rfl, rfl⟩
    cases frames with
    | nil => simp [RelationalRuntimeCallStackHolds] at holds
    | cons frame frames =>
        cases frames with
        | nil =>
            simp only [RelationalRuntimeCallStackHolds] at holds
            simp only [RelationalLinkedRuntimeCallStackHolds,
              RelationalRuntimeCallFramesHold, RelationalRuntimeCallFrameLinksHold]
            exact ⟨activeChecked inventory rfl, holds.2.2.2.2.1,
              holds.2.2.2.2.2.1,
              ⟨holds.1, holds.2.1, holds.2.2.1, holds.2.2.2.1, True.intro⟩,
              True.intro⟩
        | cons outer frames =>
            simp [RelationalRuntimeCallStackHolds] at holds

theorem RelationalLinkedRuntimeCallStackHolds.toOldShallow
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (calls : List Nat)
    (inventories : List ReturnSlotOffsetInventory)
    (active : Option ReturnSlotOffsetInventory)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate frames calls
      active [])
    (projection : ShallowRuntimeCallProjection calls inventories active) :
    RelationalRuntimeCallStackHolds context original candidate frames calls
      inventories := by
  rcases projection with empty | singleton
  · rcases empty with ⟨rfl, rfl, rfl⟩
    cases frames with
    | nil => simp [RelationalRuntimeCallStackHolds]
    | cons frame frames => simp [RelationalLinkedRuntimeCallStackHolds] at holds
  · rcases singleton with ⟨continuation, inventory, rfl, rfl, rfl⟩
    cases frames with
    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at holds
    | cons frame frames =>
        cases frames with
        | nil =>
            simp only [RelationalLinkedRuntimeCallStackHolds,
              RelationalRuntimeCallFramesHold,
              RelationalRuntimeCallFrameLinksHold] at holds
            simp only [RelationalRuntimeCallStackHolds]
            exact ⟨holds.2.2.2.1.1, holds.2.2.2.1.2.1,
              holds.2.2.2.1.2.2.1, holds.2.2.2.1.2.2.2.1,
              holds.2.1, holds.2.2.1, True.intro⟩
        | cons outer frames =>
            simp [RelationalLinkedRuntimeCallStackHolds,
              RelationalRuntimeCallFramesHold] at holds

theorem RelationalRuntimeCallFactsHold.toLinkedShallow
    (context : StaticProofContext) (world : RelationalWorld)
    (calls : List Nat) (inventories : List ReturnSlotOffsetInventory)
    (active : Option ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalRuntimeCallFactsHold context world inventories
      originalRegisters candidateRegisters)
    (projection : ShallowRuntimeCallProjection calls inventories active) :
    RelationalLinkedRuntimeCallFactsHold context world active originalRegisters
      candidateRegisters := by
  rcases projection with empty | singleton
  · rcases empty with ⟨rfl, rfl, rfl⟩
    simp [RelationalLinkedRuntimeCallFactsHold]
  · rcases singleton with ⟨continuation, inventory, rfl, rfl, rfl⟩
    exact RelationalLinkedRuntimeCallFactsHold.some_of_singleton context world
      inventory originalRegisters candidateRegisters holds

theorem RelationalLinkedRuntimeCallFactsHold.toOldShallow
    (context : StaticProofContext) (world : RelationalWorld)
    (calls : List Nat) (inventories : List ReturnSlotOffsetInventory)
    (active : Option ReturnSlotOffsetInventory)
    (originalRegisters candidateRegisters : Registers Word)
    (holds : RelationalLinkedRuntimeCallFactsHold context world active
      originalRegisters candidateRegisters)
    (projection : ShallowRuntimeCallProjection calls inventories active) :
    RelationalRuntimeCallFactsHold context world inventories originalRegisters
      candidateRegisters := by
  rcases projection with empty | singleton
  · rcases empty with ⟨rfl, rfl, rfl⟩
    exact RelationalRuntimeCallFactsHold.empty context world _ _
  · rcases singleton with ⟨continuation, inventory, rfl, rfl, rfl⟩
    simp only [RelationalLinkedRuntimeCallFactsHold] at holds
    exact RelationalRuntimeCallFactsHold.cons context world inventory [] _ _
      holds.1 holds.2 (RelationalRuntimeCallFactsHold.empty context world _ _)

theorem RelationalLinkedRuntimeCallStackHolds.links_eq_nil_of_shallow
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (calls : List Nat)
    (inventories : List ReturnSlotOffsetInventory)
    (active : Option ReturnSlotOffsetInventory)
    (links : List RelationalRuntimeCallFrameLink)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate frames calls
      active links)
    (projection : ShallowRuntimeCallProjection calls inventories active) :
    links = [] := by
  rcases projection with empty | singleton
  · rcases empty with ⟨rfl, rfl, rfl⟩
    cases frames <;> cases links <;>
      simp_all [RelationalLinkedRuntimeCallStackHolds]
  · rcases singleton with ⟨continuation, inventory, rfl, rfl, rfl⟩
    cases frames with
    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at holds
    | cons frame frames =>
        cases frames with
        | nil =>
            cases links <;>
              simp_all [RelationalLinkedRuntimeCallStackHolds,
                RelationalRuntimeCallFrameLinksHold]
        | cons outer frames =>
            have impossible : False := by
              have framesHold := holds.2.2.2.1
              simp [RelationalRuntimeCallFramesHold] at framesHold
            exact impossible.elim

theorem RelationalLinkedRuntimeCallStackHolds.shallow_calls_of_links_nil
    (context : StaticProofContext) (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (calls : List Nat)
    (active : Option ReturnSlotOffsetInventory)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate frames calls
      active []) :
    ShallowRuntimeCalls calls := by
  cases frames with
  | nil =>
      cases calls with
      | nil => exact Or.inl rfl
      | cons continuation calls =>
          simp [RelationalLinkedRuntimeCallStackHolds] at holds
  | cons frame frames =>
      cases calls with
      | nil =>
          cases active <;> simp [RelationalLinkedRuntimeCallStackHolds] at holds
      | cons continuation calls =>
          cases active with
          | none => simp [RelationalLinkedRuntimeCallStackHolds] at holds
          | some inventory =>
              cases frames with
              | nil =>
                  cases calls with
                  | nil => exact Or.inr ⟨continuation, rfl⟩
                  | cons next calls =>
                      have framesHold := holds.2.2.2.1
                      simp [RelationalRuntimeCallFramesHold] at framesHold
              | cons outer frames =>
                  have linksHold := holds.2.2.2.2
                  simp [RelationalRuntimeCallFrameLinksHold] at linksHold

theorem RelationalLinkedRuntimeCallStackHolds.shallow_calls_of_excluded_resume_target
    (context : StaticProofContext) (profile : LinkedProductControlProfile)
    (original candidate : MachineState)
    (frames : List RelationalRuntimeCallFrame) (calls : List Nat)
    (active : Option ReturnSlotOffsetInventory)
    (links : List RelationalRuntimeCallFrameLink) (continuation : Nat)
    (head : calls.head? = some continuation)
    (excluded : profile.excludesResumeTarget continuation = true)
    (holds : RelationalLinkedRuntimeCallStackHolds context original candidate
      frames calls active links)
    (linksAllowed : profile.LinksAllowed links) :
    ShallowRuntimeCalls calls := by
  cases calls with
  | nil => simp at head
  | cons selected tail =>
      simp only [List.head?_cons, Option.some.injEq] at head
      subst selected
      cases tail with
      | nil => exact Or.inr ⟨continuation, rfl⟩
      | cons next rest =>
          cases frames with
          | nil => simp [RelationalLinkedRuntimeCallStackHolds] at holds
          | cons inner frames =>
              cases active with
              | none => simp [RelationalLinkedRuntimeCallStackHolds] at holds
              | some inventory =>
                  simp only [RelationalLinkedRuntimeCallStackHolds] at holds
                  cases frames with
                  | nil =>
                      have framesHold := holds.2.2.2.1
                      simp [RelationalRuntimeCallFramesHold] at framesHold
                  | cons outer frames =>
                      cases links with
                      | nil =>
                          have linksHold := holds.2.2.2.2
                          simp [RelationalRuntimeCallFrameLinksHold] at linksHold
                      | cons link links =>
                          have frameContinuation := holds.2.2.2.1.1
                          have linkHolds := holds.2.2.2.2.1
                          have linkContinuation := linkHolds.2.1
                          have listed := linksAllowed.2 link (by simp)
                          have member := List.contains_iff_mem.mp listed
                          have excludedRows := excluded
                          simp only [LinkedProductControlProfile.excludesResumeTarget]
                            at excludedRows
                          have excludedLink :=
                            List.all_eq_true.mp excludedRows link member
                          simp only [decide_eq_true_eq] at excludedLink
                          exact False.elim (excludedLink
                            (linkContinuation.symm.trans frameContinuation))

/-- Execution-state relation using a finite active-frame profile and an
inductively checked, arbitrarily deep dormant tail.  The concrete call list is
still authoritative machine state; only its proof inventory is compressed. -/
def LinkedWorldExecutionsRelated (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract) :
    WorldExecution -> WorldExecution -> Prop
  | .running originalTarget originalState originalCalls originalEventIndex originalWorld,
      .running candidateTarget candidateState candidateCalls candidateEventIndex
        candidateWorld =>
      originalTarget = candidateTarget ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧ originalWorld = candidateWorld ∧
        exists nodeId node invariant frames active links,
          graph.getNode? nodeId = some node ∧ node.targetId = originalTarget ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? = some invariant ∧
            control.allows nodeId originalCalls active ∧
            RelationalLinkedRuntimeCallStackHolds context originalState candidateState
              frames originalCalls active links ∧
            control.linksAllowed links ∧
            RelationalLinkedRuntimeCallFactsHold context originalWorld active
              originalState.registers candidateState.registers ∧
            RelationalRuntimeCallTargetsMapped graph reachability originalCalls ∧
            StateRel context originalWorld invariant originalState candidateState
  | .returned originalState originalWorld,
      .returned candidateState candidateWorld =>
      originalWorld = candidateWorld ∧
        StateRel context originalWorld invariants.terminalInvariant
          originalState candidateState
  | .terminated originalWorld, .terminated candidateWorld =>
      originalWorld = candidateWorld
  | .awaitingExternal originalSuspension originalCallbacks,
      .awaitingExternal candidateSuspension candidateCallbacks =>
      WorldExternalSuspensionsRelated context sites originalSuspension
          candidateSuspension ∧
        WorldExternalCallbackRuntimesRelated context graph invariants reachability
          callbackTargets sites originalCallbacks candidateCallbacks ∧
        ∃ callbackFrameOffsets,
          WorldExternalCallbackFramesHold context originalSuspension.world
            originalSuspension.state candidateSuspension.state originalCallbacks
            candidateCallbacks callbackFrameOffsets
  | .callbackRunning originalTarget originalState originalCalls originalEventIndex
      originalWorld originalCallbacks,
      .callbackRunning candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld candidateCallbacks =>
      originalTarget = candidateTarget ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧ originalWorld = candidateWorld ∧
        originalCallbacks ≠ [] ∧
        exists nodeId node invariant frames active links,
          graph.getNode? nodeId = some node ∧
            callbackTargets.contains nodeId = true ∧
            node.targetId = originalTarget ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? = some invariant ∧
            control.allows nodeId originalCalls active ∧
            RelationalLinkedRuntimeCallStackHolds context originalState candidateState
              frames originalCalls active links ∧
            control.linksAllowed links ∧
            RelationalLinkedRuntimeCallFactsHold context originalWorld active
              originalState.registers candidateState.registers ∧
            RelationalRuntimeCallTargetsMapped graph reachability originalCalls ∧
            StateRel context originalWorld invariant originalState candidateState ∧
            WorldExternalCallbackRuntimesRelated context graph invariants reachability
              callbackTargets sites originalCallbacks candidateCallbacks ∧
            WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId
              originalWorld originalState candidateState originalCallbacks candidateCallbacks
  | .fault originalCause, .fault candidateCause =>
      originalCause = candidateCause
  | _, _ => False

theorem WorldExecutionsRelated.toLinkedShallow
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (oldControl : ProductControlProfile)
    (linkedControl : LinkedProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (profiles : ProductControlProfilesOldToLinkedShallow oldControl linkedControl)
    (originalExecution candidateExecution : WorldExecution)
    (related : WorldExecutionsRelated context graph invariants reachability oldControl
      callbackTargets sites originalExecution candidateExecution) :
    LinkedWorldExecutionsRelated context graph invariants reachability linkedControl
      callbackTargets sites originalExecution candidateExecution := by
  cases originalExecution <;> cases candidateExecution
  case running.running originalTarget originalState originalCalls originalEventIndex
      originalWorld candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual,
          nodeId, node, invariant, frames, inventories, nodeFound, targetFound,
          reachable, invariantFound, controlAllowed, stackHolds, frameFactsHold,
          stackTargetsReachable, statesRelated⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      rcases profiles nodeId originalCalls inventories controlAllowed with
        ⟨active, projection, linkedControlAllowed⟩
      have activeChecked : ∀ inventory, active = some inventory →
          inventory.checked = true := by
        intro inventory activeEquals
        subst active
        exact linkedControl.active_checked_of_allows nodeId originalCalls inventory
          linkedControlAllowed
      have linkedStack := RelationalRuntimeCallStackHolds.toLinkedShallow context
        originalState candidateState frames originalCalls inventories active stackHolds
        projection activeChecked
      have linkedFacts := RelationalRuntimeCallFactsHold.toLinkedShallow context
        originalWorld originalCalls inventories active originalState.registers
        candidateState.registers frameFactsHold projection
      have linkedLinks := LinkedProductControlProfile.LinksAllowed.nil linkedControl
        (linkedControl.checked_of_allows nodeId originalCalls active linkedControlAllowed)
      exact ⟨rfl, rfl, rfl, rfl, nodeId, node, invariant, frames, active, [],
        nodeFound, targetFound, reachable, invariantFound, linkedControlAllowed,
        linkedStack, linkedLinks, linkedFacts, stackTargetsReachable, statesRelated⟩
  case returned.returned => exact related
  case terminated.terminated => exact related
  case awaitingExternal.awaitingExternal => exact related
  case callbackRunning.callbackRunning originalTarget originalState originalCalls
      originalEventIndex originalWorld originalCallbacks candidateTarget candidateState
      candidateCalls candidateEventIndex candidateWorld candidateCallbacks =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual, callbacksNonempty,
          nodeId, node, invariant, frames, inventories, nodeFound,
          callbackTargetAllowed, targetFound, reachable, invariantFound, controlAllowed,
          stackHolds, frameFactsHold, stackTargetsReachable, statesRelated,
          callbacksRelated, callbackFramesHold⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      rcases profiles nodeId originalCalls inventories controlAllowed with
        ⟨active, projection, linkedControlAllowed⟩
      have activeChecked : ∀ inventory, active = some inventory →
          inventory.checked = true := by
        intro inventory activeEquals
        subst active
        exact linkedControl.active_checked_of_allows nodeId originalCalls inventory
          linkedControlAllowed
      have linkedStack := RelationalRuntimeCallStackHolds.toLinkedShallow context
        originalState candidateState frames originalCalls inventories active stackHolds
        projection activeChecked
      have linkedFacts := RelationalRuntimeCallFactsHold.toLinkedShallow context
        originalWorld originalCalls inventories active originalState.registers
        candidateState.registers frameFactsHold projection
      have linkedLinks := LinkedProductControlProfile.LinksAllowed.nil linkedControl
        (linkedControl.checked_of_allows nodeId originalCalls active linkedControlAllowed)
      exact ⟨rfl, rfl, rfl, rfl, callbacksNonempty, nodeId, node, invariant,
        frames, active, [], nodeFound, callbackTargetAllowed, targetFound, reachable,
        invariantFound, linkedControlAllowed, linkedStack, linkedLinks, linkedFacts,
        stackTargetsReachable, statesRelated, callbacksRelated, callbackFramesHold⟩
  case fault.fault => exact related
  all_goals simp [WorldExecutionsRelated] at related

/-- Exact 1:1 external actions restore the linked continuation relation.  API
semantics remain abstract, but the environment must provide the resulting
machine, world, callback, and active-frame facts. -/
def LinkedWorldExternalProtocolActionsRelated (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (originalSuspension candidateSuspension : WorldExternalSuspension)
    (originalCallbacks candidateCallbacks : List WorldExternalCallbackRuntime) :
    WorldExternalProtocolAction -> WorldExternalProtocolAction -> Prop
  | .returned originalResult, .returned candidateResult =>
      originalResult.world = candidateResult.world ∧
        ∃ nodeId node frames active links,
          graph.getNode? nodeId = some node ∧
            (originalCallbacks = [] ∨ callbackTargets.contains nodeId = true) ∧
            node.targetId = originalSuspension.continuationTargetId ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? =
              some originalSuspension.site.targetInvariant ∧
            control.allows nodeId originalSuspension.calls active ∧
            RelationalLinkedRuntimeCallStackHolds context originalResult.state
              candidateResult.state frames originalSuspension.calls active links ∧
            control.linksAllowed links ∧
            RelationalLinkedRuntimeCallFactsHold context originalResult.world active
              originalResult.state.registers candidateResult.state.registers ∧
            RelationalRuntimeCallTargetsMapped graph reachability
              originalSuspension.calls ∧
            StateRel context originalResult.world
              originalSuspension.site.targetInvariant originalResult.state
              candidateResult.state ∧
            WorldExternalCallbackRuntimesRelated context graph invariants reachability
              callbackTargets sites originalCallbacks candidateCallbacks ∧
            WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId
              originalResult.world originalResult.state candidateResult.state
              originalCallbacks candidateCallbacks
  | .callback originalEntry, .callback candidateEntry =>
      ExternalCallbackActionsRelated context originalEntry.entryInvariant
          originalSuspension.world originalSuspension.siteId
          originalSuspension.eventIndex originalSuspension.phaseIndex
          originalSuspension.continuationTargetId originalEntry candidateEntry ∧
        ∃ nodeId node,
          graph.getNode? nodeId = some node ∧
            callbackTargets.contains nodeId = true ∧
            callbackTargets.Allows nodeId ReturnSlotOffsetPair.zero
              originalEntry.returnInvariant = true ∧
            node.targetId = originalEntry.targetId ∧
            reachability.contains nodeId = true ∧
            invariants.nodeInvariants[nodeId]? = some originalEntry.entryInvariant ∧
            control.allows nodeId [] none ∧
            control.linksAllowed [] ∧
            WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId
              originalEntry.world originalEntry.state candidateEntry.state
              ({ suspension := originalSuspension, entry := originalEntry } ::
                originalCallbacks)
              ({ suspension := candidateSuspension, entry := candidateEntry } ::
                candidateCallbacks)
  | .terminated originalWorld, .terminated candidateWorld =>
      originalWorld = candidateWorld
  | _, _ => False

def LinkedWorldExternalProtocolEnvironmentsRefine (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalProtocolEnvironment) : Prop :=
  ∀ originalSuspension candidateSuspension originalCallbacks candidateCallbacks
      callbackFrameOffsets,
    WorldExternalSuspensionsRelated context sites originalSuspension
        candidateSuspension →
      WorldExternalCallbackRuntimesRelated context graph invariants reachability
        callbackTargets sites originalCallbacks candidateCallbacks →
      WorldExternalCallbackFramesHold context originalSuspension.world
        originalSuspension.state candidateSuspension.state originalCallbacks
        candidateCallbacks callbackFrameOffsets →
      LinkedWorldExternalProtocolActionsRelated context graph invariants reachability
        control callbackTargets sites originalSuspension candidateSuspension
        originalCallbacks candidateCallbacks
        (original.action originalSuspension.request)
        (candidate.action candidateSuspension.request)

theorem LinkedWorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (originalProtocol candidateProtocol : WorldExternalProtocolEnvironment)
    (noProtocol : externalCallSitesExcludeProtocol context sites = true) :
    LinkedWorldExternalProtocolEnvironmentsRefine context graph invariants reachability
      control callbackTargets sites originalProtocol candidateProtocol := by
  intro originalSuspension candidateSuspension originalCallbacks candidateCallbacks
    callbackFrameOffsets suspensionsRelated callbacksRelated callbackFramesHold
  exact False.elim
    (WorldExternalSuspensionsRelated.impossible_of_no_protocol_sites context sites
      originalSuspension candidateSuspension suspensionsRelated noProtocol)

theorem stepWorldExternalSuspension_linked_related (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : DecodedWorldProgram)
    (originalSuspension candidateSuspension : WorldExternalSuspension)
    (originalCallbacks candidateCallbacks : List WorldExternalCallbackRuntime)
    (suspensionsRelated : WorldExternalSuspensionsRelated context sites
      originalSuspension candidateSuspension)
    (callbacksRelated : WorldExternalCallbackRuntimesRelated context graph invariants
      reachability callbackTargets sites originalCallbacks candidateCallbacks)
    (callbackFrameOffsets : List ReturnSlotOffsetPair)
    (callbackFramesHold : WorldExternalCallbackFramesHold context
      originalSuspension.world originalSuspension.state candidateSuspension.state
      originalCallbacks candidateCallbacks callbackFrameOffsets)
    (actionsRelated : LinkedWorldExternalProtocolActionsRelated context graph invariants
      reachability control callbackTargets sites originalSuspension candidateSuspension
      originalCallbacks candidateCallbacks
      (original.protocolEnvironment.action originalSuspension.request)
      (candidate.protocolEnvironment.action candidateSuspension.request)) :
    worldRelationalObservationsRelated context
        (stepWorldExternalSuspension original originalSuspension
          originalCallbacks).observation
        (stepWorldExternalSuspension candidate candidateSuspension
          candidateCallbacks).observation ∧
      LinkedWorldExecutionsRelated context graph invariants reachability control
        callbackTargets sites
        (stepWorldExternalSuspension original originalSuspension
          originalCallbacks).next
        (stepWorldExternalSuspension candidate candidateSuspension
          candidateCallbacks).next := by
  have suspensionRelation := suspensionsRelated
  rcases suspensionsRelated with
    ⟨_, _, _, _, _, continuationEqual, callsEqual, eventEqual, _, _, _, _, _⟩
  cases originalAction : original.protocolEnvironment.action originalSuspension.request <;>
    cases candidateAction : candidate.protocolEnvironment.action candidateSuspension.request
  case returned.returned originalResult candidateResult =>
      simp only [originalAction, candidateAction,
        LinkedWorldExternalProtocolActionsRelated] at actionsRelated
      rcases actionsRelated with
        ⟨resultWorldEqual, nodeId, node, frames, active, links, nodeFound,
          callbackContinuationAllowed, targetFound, reachable, invariantFound,
          controlAllowed, stackHolds, linksAllowed, frameFactsHold, stackTargetsReachable,
          statesRelated, resultCallbacksRelated, resultCallbackFramesHold⟩
      unfold stepWorldExternalSuspension
      rw [originalAction, candidateAction]
      simp only
      cases originalCallbacks with
      | nil =>
          cases candidateCallbacks with
          | nil =>
              refine ⟨True.intro, continuationEqual, callsEqual, ?_,
                resultWorldEqual, nodeId, node, originalSuspension.site.targetInvariant,
                frames, active, links, nodeFound, targetFound, reachable, invariantFound,
                controlAllowed, stackHolds, linksAllowed, frameFactsHold,
                stackTargetsReachable, statesRelated⟩
              exact congrArg (fun index => index + 1) eventEqual
          | cons candidateCallback candidateCallbacks =>
              simp [WorldExternalCallbackRuntimesRelated] at callbacksRelated
      | cons originalCallback originalCallbacks =>
          have callbackTargetAllowed : callbackTargets.contains nodeId = true := by
            rcases callbackContinuationAllowed with impossible | allowed
            · simp at impossible
            · exact allowed
          cases candidateCallbacks with
          | nil =>
              simp [WorldExternalCallbackRuntimesRelated] at callbacksRelated
          | cons candidateCallback candidateCallbacks =>
              refine ⟨True.intro, continuationEqual, callsEqual, ?_,
                resultWorldEqual, (by simp), nodeId, node,
                originalSuspension.site.targetInvariant, frames, active, links, nodeFound,
                callbackTargetAllowed, targetFound, reachable, invariantFound,
                controlAllowed, stackHolds, linksAllowed, frameFactsHold,
                stackTargetsReachable, statesRelated, resultCallbacksRelated,
                resultCallbackFramesHold⟩
              exact congrArg (fun index => index + 1) eventEqual
  case callback.callback originalEntry candidateEntry =>
      simp only [originalAction, candidateAction,
        LinkedWorldExternalProtocolActionsRelated] at actionsRelated
      rcases actionsRelated with
        ⟨entryRelated, nodeId, node, nodeFound, callbackTargetAllowed,
          callbackControlAllowed, targetFound, reachable, invariantFound,
          controlAllowed, emptyLinksAllowed, callbackContinuationFramesHold⟩
      have entryRelation := entryRelated
      rcases entryRelated with
        ⟨targetEqual, originalInvariant, candidateInvariant, _, _, _, _, entryWorldEqual,
          callback, originalCallbackTarget, callbackEntry⟩
      unfold stepWorldExternalSuspension
      rw [originalAction, candidateAction]
      simp only
      refine ⟨⟨entryWorldEqual, targetEqual⟩, targetEqual, rfl, eventEqual,
        entryWorldEqual, (by simp), nodeId, node, originalEntry.entryInvariant,
        [], none, [], nodeFound, callbackTargetAllowed, targetFound, reachable,
        invariantFound, controlAllowed, ?_, ?_, ?_,
        ?_, callbackEntry.2.2.2.2.2.2.2.2.2, ?_, ?_⟩
      · simp [RelationalLinkedRuntimeCallStackHolds]
      · exact emptyLinksAllowed
      · simp [RelationalLinkedRuntimeCallFactsHold]
      · simp [RelationalRuntimeCallTargetsMapped]
      · simp only [WorldExternalCallbackRuntimesRelated]
        exact ⟨⟨suspensionRelation, entryRelation,
          ⟨nodeId, node, nodeFound, callbackTargetAllowed, callbackControlAllowed,
            targetFound, reachable, invariantFound⟩⟩,
          callbacksRelated⟩
      · exact callbackContinuationFramesHold
  case terminated.terminated originalWorld candidateWorld =>
      simp only [originalAction, candidateAction,
        LinkedWorldExternalProtocolActionsRelated] at actionsRelated
      unfold stepWorldExternalSuspension
      rw [originalAction, candidateAction]
      exact ⟨True.intro, actionsRelated⟩
  all_goals
    simp [originalAction, candidateAction,
      LinkedWorldExternalProtocolActionsRelated] at actionsRelated

def LinkedProductStepRefinement (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  forall originalExecution candidateExecution,
    LinkedWorldExecutionsRelated context graph invariants reachability control
      callbackTargets original.externalCallSites originalExecution candidateExecution ->
    worldRelationalObservationsRelated context
        (original.transitionSystem.step originalExecution).observation
        (candidate.transitionSystem.step candidateExecution).observation ∧
      LinkedWorldExecutionsRelated context graph invariants reachability control
        callbackTargets original.externalCallSites
        (original.transitionSystem.step originalExecution).next
        (candidate.transitionSystem.step candidateExecution).next

def LinkedRunningProductNodeStepRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat) : Prop :=
  match graph.getNode? nodeId, invariants.nodeInvariants[nodeId]? with
  | some node, some invariant =>
      forall frames calls active links eventIndex world originalState candidateState,
        control.allows nodeId calls active ->
        RelationalLinkedRuntimeCallStackHolds context originalState candidateState
          frames calls active links ->
        control.linksAllowed links ->
        RelationalLinkedRuntimeCallFactsHold context world active
          originalState.registers candidateState.registers ->
        RelationalRuntimeCallTargetsMapped graph reachability calls ->
        StateRel context world invariant originalState candidateState ->
        worldRelationalObservationsRelated context
            (original.transitionSystem.step
              (.running node.targetId originalState calls eventIndex world)).observation
            (candidate.transitionSystem.step
              (.running node.targetId candidateState calls eventIndex world)).observation ∧
          LinkedWorldExecutionsRelated context graph invariants reachability control
            callbackTargets original.externalCallSites
            (original.transitionSystem.step
              (.running node.targetId originalState calls eventIndex world)).next
            (candidate.transitionSystem.step
              (.running node.targetId candidateState calls eventIndex world)).next
  | _, _ => False

def LinkedCallbackRunningProductNodeStepRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat) : Prop :=
  match graph.getNode? nodeId, invariants.nodeInvariants[nodeId]? with
  | some node, some invariant =>
      ∀ frames calls active links eventIndex world originalState candidateState
          originalCallbacks candidateCallbacks,
        control.allows nodeId calls active →
        RelationalLinkedRuntimeCallStackHolds context originalState candidateState
          frames calls active links →
        control.linksAllowed links →
        RelationalLinkedRuntimeCallFactsHold context world active
          originalState.registers candidateState.registers →
        RelationalRuntimeCallTargetsMapped graph reachability calls →
        StateRel context world invariant originalState candidateState →
        originalCallbacks ≠ [] →
        WorldExternalCallbackRuntimesRelated context graph invariants reachability
          callbackTargets original.externalCallSites originalCallbacks candidateCallbacks →
        WorldExternalCallbackContinuationFramesHold context callbackTargets nodeId world
          originalState candidateState originalCallbacks candidateCallbacks →
        worldRelationalObservationsRelated context
            (original.transitionSystem.step
              (.callbackRunning node.targetId originalState calls eventIndex world
                originalCallbacks)).observation
            (candidate.transitionSystem.step
              (.callbackRunning node.targetId candidateState calls eventIndex world
                candidateCallbacks)).observation ∧
          LinkedWorldExecutionsRelated context graph invariants reachability control
            callbackTargets original.externalCallSites
            (original.transitionSystem.step
              (.callbackRunning node.targetId originalState calls eventIndex world
                originalCallbacks)).next
            (candidate.transitionSystem.step
              (.callbackRunning node.targetId candidateState calls eventIndex world
                candidateCallbacks)).next
  | _, _ => False

theorem LinkedRunningProductNodeStepRefined.of_shallow
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (oldControl : ProductControlProfile)
    (linkedControl : LinkedProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat)
    (oldToLinked : ProductControlProfilesOldToLinkedShallow oldControl linkedControl)
    (linkedToOld : ProductControlProfilesLinkedToOldShallow oldControl linkedControl)
    (profileLinksEmpty : linkedControl.links = [])
    (oldRefined : RunningProductNodeStepRefined context graph invariants reachability
      oldControl callbackTargets original candidate nodeId) :
    LinkedRunningProductNodeStepRefined context graph invariants reachability
      linkedControl callbackTargets original candidate nodeId := by
  unfold RunningProductNodeStepRefined at oldRefined
  unfold LinkedRunningProductNodeStepRefined
  cases nodeResult : graph.getNode? nodeId with
  | none =>
      simpa [nodeResult] using oldRefined
  | some node =>
      cases invariantResult : invariants.nodeInvariants[nodeId]? with
      | none =>
          simpa [nodeResult, invariantResult] using oldRefined
      | some invariant =>
          simp only [nodeResult, invariantResult] at oldRefined ⊢
          intro frames calls active links eventIndex world originalState candidateState
            linkedControlAllowed linkedStackHolds linksAllowed linkedFrameFacts
            stackTargetsReachable statesRelated
          have linksEmpty :=
            LinkedProductControlProfile.LinksAllowed.eq_nil_of_profile_links
              linkedControl links profileLinksEmpty linksAllowed
          subst links
          have shallowCalls :=
            RelationalLinkedRuntimeCallStackHolds.shallow_calls_of_links_nil context
              originalState candidateState frames calls active linkedStackHolds
          rcases linkedToOld nodeId calls active linkedControlAllowed shallowCalls with
            ⟨inventories, projection, oldControlAllowed⟩
          have oldStackHolds := RelationalLinkedRuntimeCallStackHolds.toOldShallow
            context originalState candidateState frames calls inventories active
            linkedStackHolds projection
          have oldFrameFacts := RelationalLinkedRuntimeCallFactsHold.toOldShallow
            context world calls inventories active originalState.registers
            candidateState.registers linkedFrameFacts projection
          have oldResult := oldRefined frames calls inventories eventIndex world
            originalState candidateState oldControlAllowed oldStackHolds oldFrameFacts
            stackTargetsReachable statesRelated
          exact ⟨oldResult.1,
            WorldExecutionsRelated.toLinkedShallow context graph invariants reachability
              oldControl linkedControl callbackTargets original.externalCallSites
              oldToLinked
              (original.transitionSystem.step
                (.running node.targetId originalState calls eventIndex world)).next
              (candidate.transitionSystem.step
                (.running node.targetId candidateState calls eventIndex world)).next
              oldResult.2⟩

/-- Lift a legacy local proof when this particular source node is known to have
an empty or singleton runtime stack.  Unlike `of_shallow`, the linked profile
may contain link candidates used by other nodes; the concrete source stack
itself proves that no link is present here. -/
theorem LinkedRunningProductNodeStepRefined.of_shallow_source
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (oldControl : ProductControlProfile)
    (linkedControl : LinkedProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeId : Nat)
    (oldToLinked : ProductControlProfilesOldToLinkedShallow oldControl linkedControl)
    (linkedToOld : ProductControlProfilesLinkedToOldShallow oldControl linkedControl)
    (sourceShallow : ∀ frames calls active links originalState candidateState,
      linkedControl.Allows nodeId calls active = true →
      RelationalLinkedRuntimeCallStackHolds context originalState candidateState
        frames calls active links →
      linkedControl.LinksAllowed links → ShallowRuntimeCalls calls)
    (oldRefined : RunningProductNodeStepRefined context graph invariants reachability
      oldControl callbackTargets original candidate nodeId) :
    LinkedRunningProductNodeStepRefined context graph invariants reachability
      linkedControl callbackTargets original candidate nodeId := by
  unfold RunningProductNodeStepRefined at oldRefined
  unfold LinkedRunningProductNodeStepRefined
  cases nodeResult : graph.getNode? nodeId with
  | none =>
      simpa [nodeResult] using oldRefined
  | some node =>
      cases invariantResult : invariants.nodeInvariants[nodeId]? with
      | none =>
          simpa [nodeResult, invariantResult] using oldRefined
      | some invariant =>
          simp only [nodeResult, invariantResult] at oldRefined ⊢
          intro frames calls active links eventIndex world originalState candidateState
            linkedControlAllowed linkedStackHolds linksAllowed linkedFrameFacts
            stackTargetsReachable statesRelated
          have shallowCalls := sourceShallow frames calls active links originalState
            candidateState linkedControlAllowed linkedStackHolds linksAllowed
          rcases linkedToOld nodeId calls active linkedControlAllowed shallowCalls with
            ⟨inventories, projection, oldControlAllowed⟩
          have linksEmpty :=
            RelationalLinkedRuntimeCallStackHolds.links_eq_nil_of_shallow context
              originalState candidateState frames calls inventories active links
              linkedStackHolds projection
          subst links
          have oldStackHolds := RelationalLinkedRuntimeCallStackHolds.toOldShallow
            context originalState candidateState frames calls inventories active
            linkedStackHolds projection
          have oldFrameFacts := RelationalLinkedRuntimeCallFactsHold.toOldShallow
            context world calls inventories active originalState.registers
            candidateState.registers linkedFrameFacts projection
          have oldResult := oldRefined frames calls inventories eventIndex world
            originalState candidateState oldControlAllowed oldStackHolds oldFrameFacts
            stackTargetsReachable statesRelated
          exact ⟨oldResult.1,
            WorldExecutionsRelated.toLinkedShallow context graph invariants reachability
              oldControl linkedControl callbackTargets original.externalCallSites
              oldToLinked
              (original.transitionSystem.step
                (.running node.targetId originalState calls eventIndex world)).next
              (candidate.transitionSystem.step
                (.running node.targetId candidateState calls eventIndex world)).next
              oldResult.2⟩

def ReachableLinkedRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  forall nodeId, nodeId < graph.nodes.size ->
    reachability.contains nodeId = true ->
    LinkedRunningProductNodeStepRefined context graph invariants reachability control
      callbackTargets original candidate nodeId

def ReachableLinkedCallbackRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : Prop :=
  ∀ nodeId, nodeId < graph.nodes.size →
    callbackTargets.contains nodeId = true →
    LinkedCallbackRunningProductNodeStepRefined context graph invariants reachability
      control callbackTargets original candidate nodeId

theorem reachableLinkedCallbackRunningProductNodesRefined_of_no_protocol_sites
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (invariantTableValid : invariants.Valid graph)
    (noProtocol : externalCallSitesExcludeProtocol context
      original.externalCallSites = true) :
    ReachableLinkedCallbackRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate := by
  intro nodeId nodeBefore callbackTargetAllowed
  have invariantBefore : nodeId < invariants.nodeInvariants.size := by
    rw [invariantTableValid]
    exact nodeBefore
  let node := graph.nodes[nodeId]
  let invariant := invariants.nodeInvariants[nodeId]
  have nodeFound : graph.getNode? nodeId = some node := by
    simp [RelationalProductGraph.getNode?, node, nodeBefore]
  have invariantFound : invariants.nodeInvariants[nodeId]? = some invariant := by
    simp [invariant, invariantBefore]
  unfold LinkedCallbackRunningProductNodeStepRefined
  rw [nodeFound, invariantFound]
  intro frames calls active links eventIndex world originalState candidateState
    originalCallbacks candidateCallbacks controlAllowed stackHolds linksAllowed
    frameFactsHold stackTargetsReachable statesRelated callbacksNonempty callbacksRelated
    callbackFramesHold
  exact False.elim
    (WorldExternalCallbackRuntimesRelated.impossible_of_no_protocol_sites context
      graph invariants reachability callbackTargets original.externalCallSites
      originalCallbacks candidateCallbacks callbacksNonempty callbacksRelated noProtocol)

def AllListedLinkedRunningProductNodesRefined (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) : List Nat -> Prop
  | [] => True
  | nodeId :: nodeIds =>
      LinkedRunningProductNodeStepRefined context graph invariants reachability control
          callbackTargets original candidate nodeId ∧
        AllListedLinkedRunningProductNodesRefined context graph invariants reachability
          control callbackTargets original candidate nodeIds

theorem allListedLinkedRunningProductNodesRefined_append
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (left right : List Nat)
    (leftRefined : AllListedLinkedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate left)
    (rightRefined : AllListedLinkedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate right) :
    AllListedLinkedRunningProductNodesRefined context graph invariants reachability
      control callbackTargets original candidate (left ++ right) := by
  induction left with
  | nil => exact rightRefined
  | cons _nodeId _nodeIds ih =>
      exact ⟨leftRefined.1, ih leftRefined.2⟩

theorem allListedLinkedRunningProductNodesRefined_of_mem
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram) (nodeIds : List Nat)
    (listed : AllListedLinkedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate nodeIds) :
    forall nodeId, nodeId ∈ nodeIds ->
      LinkedRunningProductNodeStepRefined context graph invariants reachability control
        callbackTargets original candidate nodeId := by
  induction nodeIds with
  | nil => simp
  | cons head tail ih =>
      intro nodeId member
      rcases listed with ⟨headRefined, tailRefined⟩
      simp only [List.mem_cons] at member
      cases member with
      | inl same => simpa [same] using headRefined
      | inr inTail => exact ih tailRefined nodeId inTail

theorem reachableLinkedRunningProductNodesRefined_of_complete_evidence
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (evidence : RelationalProductLocalEvidence)
    (complete : evidence.complete graph reachability = true)
    (listed : AllListedLinkedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate evidence.decodedNodeIds) :
    ReachableLinkedRunningProductNodesRefined context graph invariants reachability
      control callbackTargets original candidate := by
  simp only [RelationalProductLocalEvidence.complete, Bool.and_eq_true,
    beq_iff_eq] at complete
  intro nodeId before reachable
  apply allListedLinkedRunningProductNodesRefined_of_mem context graph invariants
    reachability control callbackTargets original candidate evidence.decodedNodeIds
    listed nodeId
  rw [complete.1]
  simp [RelationalProductReachabilityEvidence.reachableNodeIds, before, reachable]

theorem linkedProductStepRefinement_of_reachable_nodes
    (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (original candidate : DecodedWorldProgram)
    (_environmentRefines : ExternalEnvironmentRefines context
      original.externalCallSites original.environment candidate.environment)
    (protocolRefines : LinkedWorldExternalProtocolEnvironmentsRefine context graph
      invariants reachability control callbackTargets original.externalCallSites
      original.protocolEnvironment candidate.protocolEnvironment)
    (running : ReachableLinkedRunningProductNodesRefined context graph invariants
      reachability control callbackTargets original candidate)
    (callbackRunning : ReachableLinkedCallbackRunningProductNodesRefined context graph
      invariants reachability control callbackTargets original candidate) :
    LinkedProductStepRefinement context graph invariants reachability control
      callbackTargets original candidate := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution
  case running.running originalTarget originalState originalCalls originalEventIndex
      originalWorld candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual,
          nodeId, node, invariant, frames, active, links, nodeFound, targetFound,
          reachable, invariantFound, controlAllowed, stackHolds, linksAllowed, frameFactsHold,
          stackTargetsReachable, statesRelated⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      have nodeBefore : nodeId < graph.nodes.size := by
        exact Array.getElem?_eq_some_iff.mp nodeFound |>.1
      have nodeStep := running nodeId nodeBefore reachable
      unfold LinkedRunningProductNodeStepRefined at nodeStep
      rw [nodeFound, invariantFound] at nodeStep
      subst originalTarget
      exact nodeStep frames originalCalls active links originalEventIndex originalWorld
        originalState candidateState controlAllowed stackHolds linksAllowed
        frameFactsHold stackTargetsReachable statesRelated
  case returned.returned originalState originalWorld candidateState candidateWorld =>
      rcases related with ⟨worldEqual, statesRelated⟩
      subst candidateWorld
      exact ⟨True.intro, ⟨rfl, statesRelated⟩⟩
  case terminated.terminated originalWorld candidateWorld =>
      subst candidateWorld
      exact ⟨True.intro, rfl⟩
  case awaitingExternal.awaitingExternal originalSuspension originalCallbacks
      candidateSuspension candidateCallbacks =>
      rcases related with
        ⟨suspensionsRelated, callbacksRelated, callbackFrameOffsets,
          callbackFramesHold⟩
      exact stepWorldExternalSuspension_linked_related context graph invariants
        reachability control callbackTargets original.externalCallSites original candidate
        originalSuspension candidateSuspension originalCallbacks candidateCallbacks
        suspensionsRelated callbacksRelated callbackFrameOffsets callbackFramesHold
        (protocolRefines originalSuspension candidateSuspension originalCallbacks
          candidateCallbacks callbackFrameOffsets suspensionsRelated callbacksRelated
          callbackFramesHold)
  case callbackRunning.callbackRunning originalTarget originalState originalCalls
      originalEventIndex originalWorld originalCallbacks candidateTarget candidateState
      candidateCalls candidateEventIndex candidateWorld candidateCallbacks =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual, callbacksNonempty,
          nodeId, node, invariant, frames, active, links, nodeFound,
          callbackTargetAllowed, targetFound, reachable, invariantFound, controlAllowed,
          stackHolds, linksAllowed, frameFactsHold, stackTargetsReachable, statesRelated,
          callbacksRelated, callbackFramesHold⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      have nodeBefore : nodeId < graph.nodes.size := by
        exact Array.getElem?_eq_some_iff.mp nodeFound |>.1
      have nodeStep := callbackRunning nodeId nodeBefore callbackTargetAllowed
      unfold LinkedCallbackRunningProductNodeStepRefined at nodeStep
      rw [nodeFound, invariantFound] at nodeStep
      subst originalTarget
      exact nodeStep frames originalCalls active links originalEventIndex originalWorld
        originalState candidateState originalCallbacks candidateCallbacks
        controlAllowed stackHolds linksAllowed frameFactsHold stackTargetsReachable statesRelated
        callbacksNonempty callbacksRelated callbackFramesHold
  case fault.fault => exact ⟨True.intro, related⟩
  all_goals simp [LinkedWorldExecutionsRelated] at related

/-- Launch relation for the linked runtime-stack model.  The PE loader and
entry-state predicates are unchanged; only the proof inventory for internal
return frames is represented by an active head and a checked link tail. -/
def PE32ConsoleLinkedLaunchStateRelV2 (context : StaticProofContext)
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (launch : PE32ConsoleLaunchV2) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  ∃ frames : List RelationalRuntimeCallFrame,
    ∃ links : List RelationalRuntimeCallFrameLink,
      PE32ConsoleLaunchWorldV1.Valid context world ∧
        PreferredBaseImageMemory context.originalPe context.originalImports
          original.memory ∧
        PreferredBaseImageMemory context.candidatePe context.candidateImports
          candidate.memory ∧
        RelationalLinkedRuntimeCallStackHolds context original candidate frames
          launch.continuationTargetIds launch.frameOffsets.head? links ∧
        control.linksAllowed links ∧
        RelationalLinkedRuntimeCallFactsHold context world launch.frameOffsets.head?
          original.registers candidate.registers ∧
        RelationalRuntimeCallTargetsMapped graph reachability
          launch.continuationTargetIds ∧
        PE32TlsProcessAttachArgumentsHold context original candidate
          launch.tlsCallbackTargetIds frames ∧
        StateRel context world launch.rootInvariant original candidate

def PE32ConsoleLaunchV2.LinkedStatesRelated (launch : PE32ConsoleLaunchV2)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  PE32ConsoleLinkedLaunchStateRelV2 context graph reachability control launch world
    original candidate

def PE32ConsoleLaunchV2.LinkedRealizable (launch : PE32ConsoleLaunchV2)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority) : Prop :=
  exists world originalState candidateState,
    launch.LinkedStatesRelated context graph reachability control world originalState
      candidateState

def PE32ProgramsLinkedObservationallyEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram) : Prop :=
  launch.LinkedRealizable context graph reachability control ∧
    exists executionRelation : WorldExecution -> WorldExecution -> Prop,
      (forall world originalState candidateState,
        launch.LinkedStatesRelated context graph reachability control world
          originalState candidateState ->
        executionRelation
          (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
          (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world)) ∧
      RelationalWeakBisimulation original.pe32TransitionSystem
        candidate.pe32TransitionSystem executionRelation
        (worldRelationalObservationsRelated context)

/-- Whole-program certificate whose only internal call-stack authority is the
linked model.  The older `WholeProgramCertificate` remains a compatibility
surface while generated proofs migrate and cannot construct this certificate
from an enumerated control profile. -/
structure LinkedWholeProgramCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment) where
  imageBundle : ProofBundle
  executableImagesCovered : imageBundle.CoversStaticContext context regions
  originalCodeAliasesSemanticallyValid : context.codeMap.AliasesSemanticallyValid false
    context.originalPe context.originalImports
  candidateCodeAliasesSemanticallyValid : context.codeMap.AliasesSemanticallyValid true
    context.candidatePe context.candidateImports
  originalCodeAliasesInstructionSemanticallyValid :
    context.codeMap.AliasesInstructionSemanticallyValid false
      context.originalPe context.originalImports
  candidateCodeAliasesInstructionSemanticallyValid :
    context.codeMap.AliasesInstructionSemanticallyValid true
      context.candidatePe context.candidateImports
  staticContextValid : context.StructurallyValid
  productGraphValid : graph.IndexedValid context
  regionsUseCanonicalContext : RegionsUseStaticContext context regions
  regionsMatchProductGraph : RegionsMatchProductGraph context graph regions
  invariantTableValid : invariants.Valid graph
  callbackTargetsValid : callbackTargets.Valid graph reachability = true
  reachabilityClosed : reachability.SoundlyClosed context graph
  decodedControlComplete :
    ReachableProductNodesDecodedControlComplete context graph regions reachability
  environmentsRefined : ExternalEnvironmentRefines context externalCallSites
    originalEnvironment candidateEnvironment
  protocolEnvironmentsRefined : LinkedWorldExternalProtocolEnvironmentsRefine context
    graph invariants reachability control callbackTargets externalCallSites
    originalProtocolEnvironment candidateProtocolEnvironment
  launchValid : launch.Valid context graph invariants
  launchRealizable : launch.LinkedRealizable context graph reachability control
  launchControlAllowed : control.allows launch.rootNodeId
    launch.continuationTargetIds launch.frameOffsets.head?
  runningProductNodesRefined : ReachableLinkedRunningProductNodesRefined context graph
    invariants reachability control callbackTargets
    {
      candidate := false
      context
      regions
      externalCallSites
      environment := originalEnvironment
      protocolEnvironment := originalProtocolEnvironment
    }
    {
      candidate := true
      context
      regions
      externalCallSites
      environment := candidateEnvironment
      protocolEnvironment := candidateProtocolEnvironment
    }
  callbackRunningProductNodesRefined :
    ReachableLinkedCallbackRunningProductNodesRefined context graph invariants
      reachability control callbackTargets
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
        protocolEnvironment := originalProtocolEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
        protocolEnvironment := candidateProtocolEnvironment
      }
  originalInstructionSemanticsAdequate :
    ({
      candidate := false
      context
      regions
      externalCallSites
      environment := originalEnvironment
      protocolEnvironment := originalProtocolEnvironment
    } : DecodedWorldProgram).InstructionSemanticsAdequate
  candidateInstructionSemanticsAdequate :
    ({
      candidate := true
      context
      regions
      externalCallSites
      environment := candidateEnvironment
      protocolEnvironment := candidateProtocolEnvironment
    } : DecodedWorldProgram).InstructionSemanticsAdequate

theorem pe32ProgramsEquivalentLinked (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (certificate : LinkedWholeProgramCertificate context graph regions invariants
      reachability control callbackTargets externalCallSites launch originalEnvironment
      candidateEnvironment originalProtocolEnvironment candidateProtocolEnvironment) :
    PE32ProgramsLinkedObservationallyEquivalent context graph invariants reachability
      control launch
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
        protocolEnvironment := originalProtocolEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
        protocolEnvironment := candidateProtocolEnvironment
      } := by
  let original : DecodedWorldProgram := {
    candidate := false
    context
    regions
    externalCallSites
    environment := originalEnvironment
    protocolEnvironment := originalProtocolEnvironment
  }
  let candidate : DecodedWorldProgram := {
    candidate := true
    context
    regions
    externalCallSites
    environment := candidateEnvironment
    protocolEnvironment := candidateProtocolEnvironment
  }
  refine ⟨certificate.launchRealizable,
    LinkedWorldExecutionsRelated context graph invariants reachability control
      callbackTargets externalCallSites, ?_, ?_⟩
  · intro world originalState candidateState related
    rcases related with
      ⟨frames, links, _worldValid, _originalImageMapped, _candidateImageMapped,
        stackHolds, linksAllowed, frameFactsHold, frameTargetsReachable,
        _processAttachArgumentsHold, statesRelated⟩
    rcases certificate.launchValid.2.2.2.2.2.2.2.2.1 with
      ⟨node, nodeFound, targetFound, rootFound, rootListed, invariantFound⟩
    refine ⟨rfl, rfl, rfl, rfl, launch.rootNodeId, node,
      launch.rootInvariant, frames, launch.frameOffsets.head?, links, nodeFound,
      targetFound, ?_, invariantFound, certificate.launchControlAllowed, stackHolds,
      linksAllowed, frameFactsHold, frameTargetsReachable, statesRelated⟩
    have allRoots := certificate.reachabilityClosed.2.1.2.1
    unfold RelationalProductReachabilityEvidence.rootsIncluded at allRoots
    exact List.all_eq_true.mp allRoots launch.rootNodeId
      (List.contains_iff_mem.mp rootListed)
  · exact linkedProductStepRefinement_of_reachable_nodes context graph invariants
      reachability control callbackTargets original candidate
      certificate.environmentsRefined certificate.protocolEnvironmentsRefined
      certificate.runningProductNodesRefined
      certificate.callbackRunningProductNodesRefined
      |> fun decodedBisimulation => by
        rw [original.pe32TransitionSystem_eq_transitionSystem
          certificate.originalInstructionSemanticsAdequate,
          candidate.pe32TransitionSystem_eq_transitionSystem
          certificate.candidateInstructionSemanticsAdequate]
        exact decodedBisimulation

end StageA.Relational
