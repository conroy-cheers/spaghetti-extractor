import StageA.RelationalCallableExternalMixedBridge
import StageA.RelationalOriginalIndirectControlAuthority

namespace StageA.Relational.RelocatedWritableStaticPointerSlot

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterTransfer
open StageA.Relational.OriginalIndirectControlAuthority

/-! # Relocation-backed writable static code-pointer slots

This module checks the static part of an indirect internal call or jump through
a writable PE word. The PE relocation establishes only the launch seed. The
runtime value remains governed by a `StaticWordRelationSlotPair`, so internal
transitions and external calls must preserve that relation explicitly.

The certificate accepts both memory-indirect calls and register-indirect calls.
It checks the normalized behavior of the whole source region, which means a
register load from the slot followed by `call reg` cannot be mistaken for
unrelated register provenance.
-/

structure Certificate where
  sourceTargetId : Nat
  instructionRva : Nat
  instructionBytes : Bytes
  slotRva : Nat
  slotBytes : Bytes
  targetId : Nat
  targetRva : Nat
  continuationTargetId : Nat
  assembledRead : Bool
  writes : List RegisterOffsetWrite
deriving Repr, DecidableEq

def Certificate.slotVa (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : Nat :=
  context.pe.imageBase + certificate.slotRva

def Certificate.slot (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : StaticWordRelationSlotPair := {
  id := certificate.slotRva
  originalAddress := BitVec.ofNat 32 (certificate.slotVa context)
  candidateAddress := BitVec.ofNat 32 (certificate.slotVa context)
  relation := .fixedCodePointer certificate.targetId
}

def Certificate.claim (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : StaticWordSlotIndirectCallTargetClaim := {
  targetId := certificate.targetId
  continuationTargetId := certificate.continuationTargetId
  slot := certificate.slot context
  originalAddress := certificate.slotVa context
  candidateAddress := certificate.slotVa context
  originalAssembledRead := certificate.assembledRead
  candidateAssembledRead := certificate.assembledRead
  originalWrites := certificate.writes
  candidateWrites := certificate.writes
}

def Certificate.binding (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : OriginalStaticWordSlotBinding := {
  sourceTargetId := certificate.sourceTargetId
  instructionRva := certificate.instructionRva
  slotRva := certificate.slotRva
  targetRva := certificate.targetRva
  slotBytes := certificate.slotBytes
  claim := certificate.claim context
}

def Certificate.expectedTarget (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : Expr :=
  immutableWordReadExpression certificate.assembledRead
    (certificate.slotVa context) certificate.writes

def Certificate.instructionMatches (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : Bool :=
  match decodeInstructionExact certificate.instructionBytes with
  | some { instruction := .callImport absoluteAddress, .. } =>
      absoluteAddress == certificate.slotVa context
  | some { instruction := .callIndirect _, .. } => true
  | _ => false

/-- Static authority for one call site.  This rechecks:

* exact instruction bytes and the indirect-call instruction class;
* a writable, non-IAT PE slot containing the preferred code address;
* exactly one HIGHLOW relocation at the slot;
* the canonical code-map target and fixed-code-pointer relation slot; and
* the normalized source behavior, including pre-call writes and continuation.
-/
def Certificate.checked (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext) (certificate : Certificate) : Bool :=
  !certificate.instructionBytes.isEmpty &&
    exactRvaBytes context.pe certificate.instructionRva
      certificate.instructionBytes.length == some certificate.instructionBytes &&
    certificate.instructionMatches context &&
    (certificate.binding context).exactChecked context carrier &&
    match context.source? certificate.sourceTargetId,
        normalizedOriginalBehavior? context certificate.sourceTargetId with
    | some source, some behavior =>
        source.region.targets.contains certificate.targetId &&
          source.region.targets.contains certificate.continuationTargetId &&
          behavior.outcome == .indirectCall
            (certificate.expectedTarget context)
            certificate.continuationTargetId
    | _, _ => false

structure CheckedAuthority
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext) where
  decodedAuthority : ExactOriginalDecodedAuthority context
  certificate : Certificate
  checked : certificate.checked context carrier = true

/-! ## Indirect tail jumps

The jump certificate intentionally mirrors the call certificate's static
checks while using the existing jump-specific normalized-outcome theorem. A
tail jump has no continuation field and therefore cannot be accidentally
reinterpreted as a returning call. -/

structure JumpCertificate where
  sourceTargetId : Nat
  instructionRva : Nat
  instructionBytes : Bytes
  slotRva : Nat
  slotBytes : Bytes
  targetId : Nat
  targetRva : Nat
  assembledRead : Bool
  writes : List RegisterOffsetWrite
deriving Repr, DecidableEq

def JumpCertificate.slotVa (context : OriginalDecodedStaticContext)
    (certificate : JumpCertificate) : Nat :=
  context.pe.imageBase + certificate.slotRva

def JumpCertificate.slot (context : OriginalDecodedStaticContext)
    (certificate : JumpCertificate) : StaticWordRelationSlotPair := {
  id := certificate.slotRva
  originalAddress := BitVec.ofNat 32 (certificate.slotVa context)
  candidateAddress := BitVec.ofNat 32 (certificate.slotVa context)
  relation := .fixedCodePointer certificate.targetId
}

def JumpCertificate.claim (context : OriginalDecodedStaticContext)
    (certificate : JumpCertificate) : StaticWordSlotIndirectJumpTargetClaim := {
  targetId := certificate.targetId
  slot := certificate.slot context
  originalAddress := certificate.slotVa context
  candidateAddress := certificate.slotVa context
  originalAssembledRead := certificate.assembledRead
  candidateAssembledRead := certificate.assembledRead
  originalWrites := certificate.writes
  candidateWrites := certificate.writes
}

def JumpCertificate.binding (context : OriginalDecodedStaticContext)
    (certificate : JumpCertificate) : OriginalStaticWordJumpSlotBinding := {
  sourceTargetId := certificate.sourceTargetId
  instructionRva := certificate.instructionRva
  slotRva := certificate.slotRva
  targetRva := certificate.targetRva
  slotBytes := certificate.slotBytes
  claim := certificate.claim context
}

def JumpCertificate.expectedTarget (context : OriginalDecodedStaticContext)
    (certificate : JumpCertificate) : Expr :=
  immutableWordReadExpression certificate.assembledRead
    (certificate.slotVa context) certificate.writes

def JumpCertificate.instructionMatches
    (context : OriginalDecodedStaticContext)
    (certificate : JumpCertificate) : Bool :=
  match decodeInstructionExact certificate.instructionBytes with
  | some { instruction := .jumpImport absoluteAddress, .. } =>
      absoluteAddress == certificate.slotVa context
  | some { instruction := .jumpIndirect _, .. } => true
  | _ => false

def JumpCertificate.checked (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext) (certificate : JumpCertificate) : Bool :=
  !certificate.instructionBytes.isEmpty &&
    exactRvaBytes context.pe certificate.instructionRva
      certificate.instructionBytes.length == some certificate.instructionBytes &&
    certificate.instructionMatches context &&
    (certificate.binding context).exactChecked context carrier &&
    match context.source? certificate.sourceTargetId,
        normalizedOriginalBehavior? context certificate.sourceTargetId with
    | some source, some behavior =>
        source.region.targets.contains certificate.targetId &&
          behavior.outcome == .indirectJump
            (certificate.expectedTarget context)
    | _, _ => false

structure CheckedJumpAuthority
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext) where
  decodedAuthority : ExactOriginalDecodedAuthority context
  certificate : JumpCertificate
  checked : certificate.checked context carrier = true

/-! ## Finite-origin tail slots

Some lazy-binding slots begin with an internal initializer and are later
updated with either another internal code target or a resolver-issued callable.
The finite certificate checks the common PE seed and exact decoded jump while
leaving callable identity and runtime issuance to the callable-exit layer. -/

structure FiniteJumpCertificate where
  sourceTargetId : Nat
  instructionRva : Nat
  instructionBytes : Bytes
  slotRva : Nat
  slotBytes : Bytes
  initialTargetId : Nat
  initialTargetRva : Nat
  internalTargetIds : List Nat
  externalResourceIds : List Nat
  assembledRead : Bool
  writes : List RegisterOffsetWrite
deriving Repr, DecidableEq

def FiniteJumpCertificate.slotVa (context : OriginalDecodedStaticContext)
    (certificate : FiniteJumpCertificate) : Nat :=
  context.pe.imageBase + certificate.slotRva

def FiniteJumpCertificate.origins
    (certificate : FiniteJumpCertificate) : List ValueOriginAtom :=
  certificate.internalTargetIds.map
      (fun targetId => .staticCodeTarget targetId 0) ++
    certificate.externalResourceIds.map ValueOriginAtom.opaqueResource

def FiniteJumpCertificate.slot (context : OriginalDecodedStaticContext)
    (certificate : FiniteJumpCertificate) : StaticWordRelationSlotPair := {
  id := certificate.slotRva
  originalAddress := BitVec.ofNat 32 (certificate.slotVa context)
  candidateAddress := BitVec.ofNat 32 (certificate.slotVa context)
  relation := .finiteOrigins certificate.origins.length certificate.origins
}

def FiniteJumpCertificate.bindingCore
    (certificate : FiniteJumpCertificate) :
    OriginalStaticWordSlotBindingCore := {
  sourceTargetId := certificate.sourceTargetId
  instructionRva := certificate.instructionRva
  slotRva := certificate.slotRva
  targetRva := certificate.initialTargetRva
  slotBytes := certificate.slotBytes
}

def FiniteJumpCertificate.expectedTarget
    (context : OriginalDecodedStaticContext)
    (certificate : FiniteJumpCertificate) : Expr :=
  immutableWordReadExpression certificate.assembledRead
    (certificate.slotVa context) certificate.writes

def FiniteJumpCertificate.instructionMatches
    (context : OriginalDecodedStaticContext)
    (certificate : FiniteJumpCertificate) : Bool :=
  match decodeInstructionExact certificate.instructionBytes with
  | some { instruction := .jumpImport absoluteAddress, .. } =>
      absoluteAddress == certificate.slotVa context
  | some { instruction := .jumpIndirect _, .. } => true
  | _ => false

def FiniteJumpCertificate.checked (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (certificate : FiniteJumpCertificate) : Bool :=
  !certificate.instructionBytes.isEmpty &&
    exactRvaBytes context.pe certificate.instructionRva
      certificate.instructionBytes.length == some certificate.instructionBytes &&
    certificate.instructionMatches context &&
    !certificate.internalTargetIds.isEmpty &&
    !certificate.externalResourceIds.isEmpty &&
    certificate.internalTargetIds.length ==
      certificate.internalTargetIds.eraseDups.length &&
    certificate.externalResourceIds.length ==
      certificate.externalResourceIds.eraseDups.length &&
    certificate.internalTargetIds.contains certificate.initialTargetId &&
    carrier.staticWordRelationSlots.contains (certificate.slot context) &&
    (certificate.bindingCore.initialValueChecked context carrier
      certificate.initialTargetId (certificate.slot context)) &&
    match context.source? certificate.sourceTargetId,
        normalizedOriginalBehavior? context certificate.sourceTargetId with
    | some source, some behavior =>
        certificate.internalTargetIds.all source.region.targets.contains &&
          behavior.outcome == .indirectJump
            (certificate.expectedTarget context)
    | _, _ => false

structure CheckedFiniteJumpAuthority
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext) where
  decodedAuthority : ExactOriginalDecodedAuthority context
  certificate : FiniteJumpCertificate
  checked : certificate.checked context carrier = true

theorem FiniteJumpCertificate.initialValueChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : FiniteJumpCertificate}
    (checked : certificate.checked context carrier = true) :
    certificate.bindingCore.initialValueChecked context carrier
      certificate.initialTargetId (certificate.slot context) = true := by
  simp only [FiniteJumpCertificate.checked, Bool.and_eq_true] at checked
  exact checked.1.2

theorem FiniteJumpCertificate.slotMember
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : FiniteJumpCertificate}
    (checked : certificate.checked context carrier = true) :
    certificate.slot context ∈ carrier.staticWordRelationSlots := by
  simp only [FiniteJumpCertificate.checked, Bool.and_eq_true] at checked
  exact List.contains_iff_mem.mp checked.1.1.2

theorem JumpCertificate.bindingExactChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : JumpCertificate}
    (checked : certificate.checked context carrier = true) :
    (certificate.binding context).exactChecked context carrier = true := by
  simp only [JumpCertificate.checked, Bool.and_eq_true] at checked
  exact checked.1.2

theorem JumpCertificate.normalizedOutcomeChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : JumpCertificate}
    (checked : certificate.checked context carrier = true) :
    ∃ source behavior,
      context.source? certificate.sourceTargetId = some source /\
      normalizedOriginalBehavior? context certificate.sourceTargetId =
        some behavior /\
      source.region.targets.contains certificate.targetId = true /\
      behavior.outcome = .indirectJump
        (certificate.expectedTarget context) := by
  simp only [JumpCertificate.checked, Bool.and_eq_true] at checked
  have sourceChecked := checked.2
  cases sourceFound : context.source? certificate.sourceTargetId with
  | none => simp [sourceFound] at sourceChecked
  | some source =>
      cases behaviorFound :
          normalizedOriginalBehavior? context certificate.sourceTargetId with
      | none => simp [sourceFound, behaviorFound] at sourceChecked
      | some behavior =>
          simp only [sourceFound, behaviorFound, Bool.and_eq_true,
            beq_iff_eq] at sourceChecked
          exact ⟨source, behavior, rfl, rfl, sourceChecked.1, sourceChecked.2⟩

theorem JumpCertificate.targetsClosed
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : JumpCertificate}
    {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (_staticChecked : certificate.checked context carrier = true)
    (claimChecked :
      (certificate.claim context).checked carrier sourceInvariant
        originalBehavior candidateBehavior = true) :
    StaticWordSlotIndirectJumpTargetsClosed carrier sourceInvariant
      originalBehavior candidateBehavior (certificate.claim context) :=
  staticWordSlotIndirectJumpTargetsClosed_of_checked carrier sourceInvariant
    originalBehavior candidateBehavior (certificate.claim context) claimChecked

theorem Certificate.bindingExactChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : Certificate}
    (checked : certificate.checked context carrier = true) :
    (certificate.binding context).exactChecked context carrier = true := by
  simp only [Certificate.checked, Bool.and_eq_true] at checked
  exact checked.1.2

theorem Certificate.normalizedOutcomeChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : Certificate}
    (checked : certificate.checked context carrier = true) :
    ∃ source behavior,
      context.source? certificate.sourceTargetId = some source /\
      normalizedOriginalBehavior? context certificate.sourceTargetId =
        some behavior /\
      source.region.targets.contains certificate.targetId = true /\
      source.region.targets.contains certificate.continuationTargetId = true /\
      behavior.outcome = .indirectCall
        (certificate.expectedTarget context)
        certificate.continuationTargetId := by
  simp only [Certificate.checked, Bool.and_eq_true] at checked
  have sourceChecked := checked.2
  cases sourceFound : context.source? certificate.sourceTargetId with
  | none => simp [sourceFound] at sourceChecked
  | some source =>
      cases behaviorFound :
          normalizedOriginalBehavior? context certificate.sourceTargetId with
      | none => simp [sourceFound, behaviorFound] at sourceChecked
      | some behavior =>
          simp only [sourceFound, behaviorFound, Bool.and_eq_true,
            beq_iff_eq] at sourceChecked
          exact ⟨source, behavior, rfl, rfl,
            sourceChecked.1.1, sourceChecked.1.2, sourceChecked.2⟩

/-- The checked static certificate and the ordinary source-invariant
separation proof produce the existing composition authority.  Runtime slot
stability is obtained from `StateRel`; this theorem does not infer it from the
on-disk relocation. -/
theorem Certificate.targetsClosed
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext} {certificate : Certificate}
    {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (_staticChecked : certificate.checked context carrier = true)
    (claimChecked :
      (certificate.claim context).checked carrier sourceInvariant
        originalBehavior candidateBehavior = true) :
    StaticWordSlotIndirectCallTargetsClosed carrier sourceInvariant
      originalBehavior candidateBehavior (certificate.claim context) :=
  staticWordSlotIndirectCallTargetsClosed_of_checked carrier sourceInvariant
    originalBehavior candidateBehavior (certificate.claim context) claimChecked

/-- External effects preserve a side of the slot protocol only through an
explicit footprint or finite-set frame.  Broad stateful effects cannot use the
footprint constructor and therefore remain visible proof obligations. -/
theorem preserveSideAcrossMachineCall
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (slot : Word) (allowed : List Word)
    (conforms : machineCallResultConforms candidate context contract event result)
    (frame : MachineCallStaticWordFrame contract event result slot allowed)
    (prior : Memory.read32 event.state.memory slot ∈ allowed) :
    Memory.read32 result.state.memory slot ∈ allowed :=
  machineCallResultConforms_preservesStaticWordInvariant candidate context
    contract event result slot allowed conforms frame prior

end StageA.Relational.RelocatedWritableStaticPointerSlot
