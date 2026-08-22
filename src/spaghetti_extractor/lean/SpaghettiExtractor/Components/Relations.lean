import Std

namespace SpaghettiExtractor.Components.Relations

structure Reference where
  domain : Nat
  object : Nat
  generation : Nat
  offset : Nat
  extent : Nat
  deriving DecidableEq, Repr

structure LiveOrigin where
  domain : Nat
  object : Nat
  generation : Nat
  base : Nat
  extent : Nat
  permissions : Nat
  live : Bool
  deriving DecidableEq, Repr

def LiveOrigin.resolve (origin : LiveOrigin) (address requested : Nat) :
    Option Reference :=
  if origin.live = true ∧ origin.base ≤ address ∧
      address - origin.base + requested ≤ origin.extent then
    some {
      domain := origin.domain
      object := origin.object
      generation := origin.generation
      offset := address - origin.base
      extent := origin.extent
    }
  else
    none

def LiveOrigin.realize (origin : LiveOrigin) (reference : Reference) :
    Option Nat :=
  if origin.live = true ∧ reference.domain = origin.domain ∧
      reference.object = origin.object ∧
      reference.generation = origin.generation ∧
      reference.extent = origin.extent ∧ reference.offset ≤ origin.extent then
    some (origin.base + reference.offset)
  else
    none

theorem LiveOrigin.resolve_realize
    (origin : LiveOrigin) (address requested : Nat) (reference : Reference)
    (resolved : origin.resolve address requested = some reference) :
    origin.realize reference = some address := by
  unfold LiveOrigin.resolve at resolved
  split at resolved
  case isFalse => contradiction
  case isTrue resolvedCondition =>
    simp only [Option.some.injEq] at resolved
    subst reference
    unfold LiveOrigin.realize
    rw [if_pos]
    · congr 1
      change origin.base + (address - origin.base) = address
      omega
    · rcases resolvedCondition with ⟨live, baseLe, bounded⟩
      refine ⟨live, rfl, rfl, rfl, rfl, ?_⟩
      change address - origin.base ≤ origin.extent
      omega

theorem LiveOrigin.generation_change_expires
    (origin : LiveOrigin) (reference : Reference)
    (sameDomain : reference.domain = origin.domain)
    (sameObject : reference.object = origin.object)
    (changed : reference.generation ≠ origin.generation) :
    origin.realize reference = none := by
  unfold LiveOrigin.realize
  rw [if_neg]
  intro condition
  exact changed condition.2.2.2.1

def Reference.inBounds (reference : Reference) : Bool :=
  reference.offset ≤ reference.extent

def Reference.sameOrigin (left right : Reference) : Bool :=
  left.domain == right.domain &&
  left.object == right.object &&
  left.generation == right.generation

def Reference.derive (reference : Reference) (delta : Nat) : Option Reference :=
  if reference.offset + delta ≤ reference.extent then
    some { reference with offset := reference.offset + delta }
  else
    none

theorem Reference.derive_preserves_origin
    (reference derived : Reference) (delta : Nat)
    (result : reference.derive delta = some derived) :
    reference.domain = derived.domain ∧
    reference.object = derived.object ∧
    reference.generation = derived.generation := by
  simp [Reference.derive] at result
  rcases result with ⟨_, rfl⟩
  exact ⟨rfl, rfl, rfl⟩

theorem Reference.derive_is_bounded
    (reference derived : Reference) (delta : Nat)
    (result : reference.derive delta = some derived) :
    derived.inBounds = true := by
  simp [Reference.inBounds, Reference.derive] at result ⊢
  rcases result with ⟨bounded, rfl⟩
  exact bounded

def Reference.remaining (reference : Reference) : Nat :=
  reference.extent - reference.offset

theorem Reference.offset_add_remaining
    (reference : Reference) (bounded : reference.inBounds = true) :
    reference.offset + reference.remaining = reference.extent := by
  simp [Reference.inBounds, Reference.remaining] at bounded ⊢
  omega

structure Capability where
  type : Nat
  word : Nat
  generation : Nat
  deriving DecidableEq, Repr

structure LiveCapabilityAuthority where
  type : Nat
  generation : Nat
  live : Bool
  deriving DecidableEq, Repr

def LiveCapabilityAuthority.import
    (authority : LiveCapabilityAuthority) (word : Nat) : Option Capability :=
  if authority.live = true then
    some { type := authority.type, word := word, generation := authority.generation }
  else none

def LiveCapabilityAuthority.export
    (authority : LiveCapabilityAuthority) (capability : Capability) : Option Nat :=
  if authority.live = true ∧ capability.type = authority.type ∧
      capability.generation = authority.generation then
    some capability.word
  else none

theorem LiveCapabilityAuthority.import_export
    (authority : LiveCapabilityAuthority) (word : Nat) (capability : Capability)
    (imported : authority.import word = some capability) :
    authority.export capability = some word := by
  unfold LiveCapabilityAuthority.import at imported
  split at imported
  case isFalse => contradiction
  case isTrue live =>
    simp only [Option.some.injEq] at imported
    subst capability
    unfold LiveCapabilityAuthority.export
    rw [if_pos ⟨live, rfl, rfl⟩]

structure Lens (Machine Logical : Type) where
  observe : Machine → Logical
  realize : Machine → Logical → Machine

structure LawfulLens {Machine Logical : Type}
    (lens : Lens Machine Logical) : Prop where
  observeRealize : ∀ machine logical,
    lens.observe (lens.realize machine logical) = logical
  realizeObserve : ∀ machine,
    lens.realize machine (lens.observe machine) = machine

def identityLens (Value : Type) : Lens Value Value where
  observe := id
  realize := fun _ value => value

theorem identityLens_lawful (Value : Type) :
    LawfulLens (identityLens Value) := by
  constructor <;> intros <;> rfl

def compose {Outer Middle Inner : Type}
    (outer : Lens Outer Middle) (inner : Lens Middle Inner) :
    Lens Outer Inner where
  observe := fun value => inner.observe (outer.observe value)
  realize := fun value logical =>
    outer.realize value (inner.realize (outer.observe value) logical)

theorem compose_lawful {Outer Middle Inner : Type}
    (outer : Lens Outer Middle) (inner : Lens Middle Inner)
    (outerLawful : LawfulLens outer) (innerLawful : LawfulLens inner) :
    LawfulLens (compose outer inner) := by
  constructor
  · intro machine logical
    simp [compose, outerLawful.observeRealize, innerLawful.observeRealize]
  · intro machine
    simp [compose, innerLawful.realizeObserve, outerLawful.realizeObserve]

def decodeBaseOffset (base projected : Nat) : Nat := projected - base
def encodeBaseOffset (base logical : Nat) : Nat := base + logical

theorem baseOffset_observe_realize (base logical : Nat) :
    decodeBaseOffset base (encodeBaseOffset base logical) = logical := by
  simp [decodeBaseOffset, encodeBaseOffset]

theorem baseOffset_realize_observe (base projected : Nat)
    (bounded : base ≤ projected) :
    encodeBaseOffset base (decodeBaseOffset base projected) = projected := by
  simp [decodeBaseOffset, encodeBaseOffset, Nat.add_sub_of_le bounded]

structure ScheduledAction where
  id : String
  sequence : Nat
  deriving DecidableEq, Repr

structure OperationSchedule where
  id : String
  actions : List ScheduledAction
  deriving DecidableEq, Repr

def OperationSchedule.valid (schedule : OperationSchedule) : Bool :=
  schedule.actions.map (·.sequence) == List.range schedule.actions.length &&
  decide ((schedule.actions.map (·.id)).Nodup)

structure BoundaryPlanCertificate where
  operations : List OperationSchedule
  operationCount : Nat
  clauseCount : Nat
  deriving DecidableEq, Repr

def checkBoundaryPlanCertificate (certificate : BoundaryPlanCertificate) : Bool :=
  certificate.operationCount > 0 &&
  certificate.operations.length == certificate.operationCount &&
  (certificate.operations.map (·.actions.length)).sum == certificate.clauseCount &&
  certificate.operations.all OperationSchedule.valid

theorem checkBoundaryPlanCertificate_sound
    (certificate : BoundaryPlanCertificate)
    (checked : checkBoundaryPlanCertificate certificate = true) :
    ((certificate.operationCount > 0 ∧
    certificate.operations.length = certificate.operationCount) ∧
    (certificate.operations.map (·.actions.length)).sum = certificate.clauseCount) ∧
    certificate.operations.all OperationSchedule.valid = true := by
  simpa [checkBoundaryPlanCertificate, Bool.and_eq_true] using checked

end SpaghettiExtractor.Components.Relations
