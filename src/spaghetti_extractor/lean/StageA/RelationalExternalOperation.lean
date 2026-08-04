import StageA.RelationalEnvironment
import StageA.RelationalValueProvenance

namespace StageA.Relational.ExternalOperation

open StageA.Formal StageA.Relational
open StageA.Relational.ValueProvenance

/-! Checked machine-level identities for profiled external operation tables.

This module does not trust profile recognition.  A runtime resolution must bind
an exact target expression to the concrete table word selected by one checked
profile operation.  Environment behavior remains an explicit relational
premise; profile membership alone cannot authorize execution equivalence.
-/

inductive Selector where
  | directImport (target : ExternalTarget)
  | tableSlot (viewId : String) (slot : Nat)
  | resolverResult (resolverOperationId resultId : String)
  | callback (callbackId : String)
deriving Repr, DecidableEq

def Selector.shapeValid : Selector -> Bool
  | .directImport target => !target.dll.isEmpty
  | .tableSlot viewId slot => !viewId.isEmpty && slot < 2^16
  | .resolverResult resolverOperationId resultId =>
      !resolverOperationId.isEmpty && !resultId.isEmpty
  | .callback callbackId => !callbackId.isEmpty

structure Declaration where
  id : String
  selectors : List Selector
  machineContract : MachineImportCallContract
  environmentContractId : String
deriving Repr, DecidableEq

def Declaration.shapeValid (operation : Declaration) : Bool :=
  !operation.id.isEmpty &&
    !operation.selectors.isEmpty &&
    operation.selectors.all fun selector =>
      selector.shapeValid &&
        (operation.selectors.filter (· == selector)).length == 1 &&
    operation.machineContract.shapeValid &&
    !operation.environmentContractId.isEmpty

structure Profile where
  id : String
  digest : List Byte
  operations : List Declaration
deriving Repr, DecidableEq

def Profile.checked (profile : Profile) : Bool :=
  !profile.id.isEmpty && profile.digest.length == 32 &&
    !profile.operations.isEmpty &&
    profile.operations.all fun operation =>
      operation.shapeValid &&
        (profile.operations.filter (·.id == operation.id)).length == 1

structure Profile.CheckedFacts (profile : Profile) : Prop where
  idPresent : profile.id.isEmpty = false
  digestLength : profile.digest.length = 32
  operationsPresent : profile.operations.isEmpty = false
  operationsValid : forall operation, operation ∈ profile.operations ->
    operation.shapeValid = true
  operationIdsUnique : forall operation, operation ∈ profile.operations ->
    (profile.operations.filter (·.id == operation.id)).length = 1

theorem Profile.facts_of_checked (profile : Profile)
    (checked : profile.checked = true) : profile.CheckedFacts := by
  simp only [Profile.checked, Bool.and_eq_true, List.all_eq_true] at checked
  exact {
    idPresent := by simpa using checked.1.1.1
    digestLength := beq_iff_eq.mp checked.1.1.2
    operationsPresent := by simpa using checked.1.2
    operationsValid := fun operation member => (checked.2 operation member).1
    operationIdsUnique := fun operation member =>
      beq_iff_eq.mp (checked.2 operation member).2
  }

theorem Profile.operationValid_of_checked (profile : Profile)
    (operation : Declaration) (checked : profile.checked = true)
    (member : operation ∈ profile.operations) :
    operation.shapeValid = true :=
  (profile.facts_of_checked checked).operationsValid operation member

/-- Exact concrete resolution of the conventional object-vtable-slot shape.
The target expression may have been normalized differently; `targetExact`
binds it extensionally to the same concrete slot word for this state. -/
structure TableSlotResolution
    (profile : Profile) (operation : Declaration)
    (state : MachineState) (targetExpression : Expr) (targetWord : Word) where
  profileChecked : profile.checked = true
  operationMember : operation ∈ profile.operations
  viewId : String
  slot : Nat
  selectorMember : .tableSlot viewId slot ∈ operation.selectors
  receiverExpression : Expr
  tableAddress : Word
  tablePointerExact :
    state.read32 (receiverExpression.eval state) = tableAddress
  slotWordExact :
    state.read32 (tableAddress + BitVec.ofNat 32 (slot * 4)) = targetWord
  targetExact : targetExpression.eval state = targetWord

/-- C operation tables may already be held as the table pointer. -/
structure DirectTableSlotResolution
    (profile : Profile) (operation : Declaration)
    (state : MachineState) (targetExpression : Expr) (targetWord : Word) where
  profileChecked : profile.checked = true
  operationMember : operation ∈ profile.operations
  viewId : String
  slot : Nat
  selectorMember : .tableSlot viewId slot ∈ operation.selectors
  tableExpression : Expr
  slotWordExact :
    state.read32
      (tableExpression.eval state + BitVec.ofNat 32 (slot * 4)) = targetWord
  targetExact : targetExpression.eval state = targetWord

inductive CheckedTargetResolution
    (profile : Profile) (operation : Declaration)
    (state : MachineState) (targetExpression : Expr) (targetWord : Word) : Prop
  | objectTable
      (resolution : TableSlotResolution profile operation state
        targetExpression targetWord) :
      CheckedTargetResolution profile operation state targetExpression targetWord
  | directTable
      (resolution : DirectTableSlotResolution profile operation state
        targetExpression targetWord) :
      CheckedTargetResolution profile operation state targetExpression targetWord

theorem CheckedTargetResolution.targetEvaluation
    {profile : Profile} {operation : Declaration}
    {state : MachineState} {targetExpression : Expr} {targetWord : Word}
    (resolution : CheckedTargetResolution profile operation state
      targetExpression targetWord) :
    targetExpression.eval state = targetWord := by
  cases resolution with
  | objectTable checked => exact checked.targetExact
  | directTable checked => exact checked.targetExact

/-! A table lookup and a provenance-backed callable value are two evidence
forms for the same relational fact: both concrete targets denote one profiled
operation. The environment contract, not the target address, supplies the
operation's behavior. -/

inductive PairedTargetResolution
    (context : StaticProofContext) (world : RelationalWorld)
    (profile : Profile) (operation : Declaration)
    (originalState candidateState : MachineState)
    (originalExpression candidateExpression : Expr) : Prop
  | table
      (originalWord candidateWord : Word)
      (original : CheckedTargetResolution profile operation originalState
        originalExpression originalWord)
      (candidate : CheckedTargetResolution profile operation candidateState
        candidateExpression candidateWord) :
      PairedTargetResolution context world profile operation originalState
        candidateState originalExpression candidateExpression
  | provenance
      (profileChecked : profile.checked = true)
      (operationMember : operation ∈ profile.operations)
      (selector : Selector)
      (selectorMember : selector ∈ operation.selectors)
      (origin : ValueOriginAtom)
      (originChecked : origin.checked context = true)
      (originHolds : origin.Holds context world
        (originalExpression.eval originalState)
        (candidateExpression.eval candidateState)) :
      PairedTargetResolution context world profile operation originalState
        candidateState originalExpression candidateExpression

theorem PairedTargetResolution.operationValid
    {context : StaticProofContext} {world : RelationalWorld}
    {profile : Profile} {operation : Declaration}
    {originalState candidateState : MachineState}
    {originalExpression candidateExpression : Expr}
    (resolution : PairedTargetResolution context world profile operation
      originalState candidateState originalExpression candidateExpression) :
    operation.shapeValid = true := by
  cases resolution with
  | table _ _ original _ =>
      cases original with
      | objectTable checked =>
          exact profile.operationValid_of_checked operation
            checked.profileChecked checked.operationMember
      | directTable checked =>
          exact profile.operationValid_of_checked operation
            checked.profileChecked checked.operationMember
  | provenance checked member _ _ _ _ _ =>
      exact profile.operationValid_of_checked operation checked member

structure Event where
  eventIndex : Nat
  profileId : String
  profileDigest : List Byte
  operationId : String
  environmentContractId : String
  arguments : List Word
  state : MachineState
  world : RelationalWorld

structure Result where
  state : MachineState
  world : RelationalWorld

structure Environment where
  result : Nat -> Event -> Result

/-- The generic core requires the two environments to relate each matching
operation.  API-specific semantics instantiate these predicates outside this
module; exact operation identity and order are retained by the caller. -/
structure EnvironmentRefines
    (original candidate : Environment)
    (argumentsRelated : List Word -> List Word -> Prop)
    (resultsRelated : Result -> Result -> Prop) : Prop where
  paired : forall originalEvent candidateEvent,
    originalEvent.eventIndex = candidateEvent.eventIndex ->
    originalEvent.profileId = candidateEvent.profileId ->
    originalEvent.profileDigest = candidateEvent.profileDigest ->
    originalEvent.operationId = candidateEvent.operationId ->
    originalEvent.environmentContractId =
      candidateEvent.environmentContractId ->
    argumentsRelated originalEvent.arguments candidateEvent.arguments ->
    resultsRelated
      (original.result originalEvent.eventIndex originalEvent)
      (candidate.result candidateEvent.eventIndex candidateEvent)

/-- Resolution plus the environment premise required at one call boundary.
There is deliberately no constructor from profile membership alone. -/
structure CheckedCallBoundary
    (profile : Profile) (operation : Declaration)
    (state : MachineState) (targetExpression : Expr) (targetWord : Word) where
  resolution : CheckedTargetResolution profile operation state
    targetExpression targetWord
  arguments : List Word
  argumentCount : arguments.length = operation.machineContract.stackArgumentOffsets.length

/-- The proof-facing call boundary. Source rendering, recovered prototypes, and
library names are intentionally absent. They cannot authorize this relation. -/
structure PairedCallBoundary
    (context : StaticProofContext) (world : RelationalWorld)
    (profile : Profile) (operation : Declaration)
    (originalState candidateState : MachineState)
    (originalExpression candidateExpression : Expr)
    (argumentsRelated : List Word -> List Word -> Prop) where
  target : PairedTargetResolution context world profile operation
    originalState candidateState originalExpression candidateExpression
  originalArguments : List Word
  candidateArguments : List Word
  originalArgumentCount :
    originalArguments.length = operation.machineContract.stackArgumentOffsets.length
  candidateArgumentCount :
    candidateArguments.length = operation.machineContract.stackArgumentOffsets.length
  related : argumentsRelated originalArguments candidateArguments

end StageA.Relational.ExternalOperation
