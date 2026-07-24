import StageA.RelationalEnvironment
import StageA.RelationalValueProvenance

namespace StageA.Relational

open StageA.Formal
open StageA.Relational.ValueProvenance

namespace CallRefinement

inductive Kind where
  | internal
  | imported (siteId : Nat)
  | callback (targetId : Nat)
  | tail
deriving Repr, DecidableEq

structure ArgumentPair where
  original : Expr
  candidate : Expr
deriving Repr, DecidableEq

structure Certificate where
  kind : Kind
  continuationTargetId : Nat
  arguments : List ArgumentPair
  results : List PairedValueClaim
  effects : TransitionEffects
  finiteAlternativeBudget : Nat
deriving Repr, DecidableEq

def Certificate.frameChecked (certificate : Certificate) : Bool :=
  match certificate.kind, certificate.effects.frameAction with
  | .internal, .push continuation
  | .callback _, .push continuation
  | .tail, .replace continuation =>
      continuation == certificate.continuationTargetId
  | .imported siteId, .returnExternal observedSite continuation =>
      siteId == observedSite &&
        continuation == certificate.continuationTargetId
  | _, _ => false

def Certificate.checked (context : StaticProofContext)
    (certificate : Certificate) : Bool :=
  certificate.finiteAlternativeBudget > 0 &&
    (context.codeMap.get? certificate.continuationTargetId).isSome &&
    certificate.effects.checked &&
    certificate.frameChecked &&
    certificate.results.all fun result =>
      result.checked context certificate.finiteAlternativeBudget

def ArgumentsRelated (context : StaticProofContext) (world : RelationalWorld)
    (certificate : Certificate)
    (original candidate : MachineState) : Prop :=
  ∀ argument, argument ∈ certificate.arguments ->
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (argument.original.eval original) (argument.candidate.eval candidate) = true

def ResultsHold (context : StaticProofContext) (world : RelationalWorld)
    (certificate : Certificate)
    (original candidate : MachineState) : Prop :=
  ∀ result, result ∈ certificate.results ->
    result.Holds context world original candidate

/-- Internal calls, imported calls, callbacks, and tail calls all close through
this interface.  The evidence source differs, but each producer must establish
the same source relation, ABI argument relation, exact framed update, successor
world, continuation, and target relation. -/
structure Refines
    (context : StaticProofContext)
    (sourceWorld targetWorld : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (certificate : Certificate)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState) :
    Prop where
  certificateChecked : certificate.checked context = true
  sourceRelated :
    StateRel context sourceWorld sourceInvariant originalBefore candidateBefore
  argumentsRelated :
    ArgumentsRelated context sourceWorld certificate originalBefore candidateBefore
  memoryEffects :
    certificate.effects.RuntimeMemoryImplements originalBefore candidateBefore
      originalAfter candidateAfter
  registerEffects :
    certificate.effects.RuntimeRegistersImplement originalBefore candidateBefore
      originalAfter candidateAfter
  successorWorldValid : targetWorld.valid context = true
  resultsHold :
    ResultsHold context targetWorld certificate originalAfter candidateAfter
  targetRelated :
    StateRel context targetWorld targetInvariant originalAfter candidateAfter

theorem Refines.preservesTargetStateRel
    (refinement : Refines context sourceWorld targetWorld sourceInvariant
      targetInvariant certificate originalBefore candidateBefore
      originalAfter candidateAfter) :
    StateRel context targetWorld targetInvariant originalAfter candidateAfter :=
  refinement.targetRelated

/-- A checked call frame transports an origin through a register omitted from
both exact write inventories. This is the common rule for internal calls,
imports, and callbacks whose contracts preserve a register. -/
theorem Refines.preservedRegisterOrigin
    (refinement : Refines context world world sourceInvariant targetInvariant
      certificate originalBefore candidateBefore originalAfter candidateAfter)
    (relation : RegisterValueOriginRelation)
    (sourceMember :
      relation ∈ sourceInvariant.registerValueOriginRelations)
    (originalMissing :
      certificate.effects.originalRegisterEffect? relation.original = none)
    (candidateMissing :
      certificate.effects.candidateRegisterEffect? relation.candidate = none) :
    relation.holds context world originalAfter.registers
      candidateAfter.registers = true := by
  have sourceAll :=
    refinement.sourceRelated.registerValueOriginsHold context world sourceInvariant
  have source :=
    registerValueOriginRelationsHold_member context world
      sourceInvariant.registerValueOriginRelations originalBefore.registers
      candidateBefore.registers relation sourceAll sourceMember
  exact ValueProvenance.RegisterValueOriginRelation.holds_of_preserved context
    world relation originalBefore candidateBefore originalAfter candidateAfter source
    (refinement.registerEffects.originalPreserved certificate.effects
      originalBefore candidateBefore originalAfter candidateAfter
      relation.original originalMissing)
    (refinement.registerEffects.candidatePreserved certificate.effects
      originalBefore candidateBefore originalAfter candidateAfter
      relation.candidate candidateMissing)

/-- Interpret one exact call result through the canonical register-origin
relation. Result production and later indirect-target classification therefore
share the same finite origin inventory. -/
theorem Refines.resultRegisterOrigin
    (refinement : Refines context sourceWorld targetWorld sourceInvariant
      targetInvariant certificate originalBefore candidateBefore
      originalAfter candidateAfter)
    (relation : RegisterValueOriginRelation)
    (claim : PairedValueClaim)
    (claimMember : claim ∈ certificate.results)
    (originalResult : claim.original = .inputReg relation.original)
    (candidateResult : claim.candidate = .inputReg relation.candidate)
    (origins : claim.origin.alternatives = relation.origins) :
    relation.holds context targetWorld originalAfter.registers
      candidateAfter.registers = true :=
  ValueProvenance.RegisterValueOriginRelation.holds_of_valueClaim context
    targetWorld relation claim originalAfter candidateAfter originalResult
      candidateResult origins
      (refinement.resultsHold claim claimMember)

/-- Transport a saved memory-origin witness through a checked call frame.
Unlike a flat stack-window rule, this permits the successor world and the
address expression to change, but requires exact equality of the observed
word and explicit preservation of every admitted origin atom. -/
theorem Refines.rebasedMemoryOrigin
    (refinement : Refines context sourceWorld targetWorld sourceInvariant
      targetInvariant certificate originalBefore candidateBefore
      originalAfter candidateAfter)
    (sourceRelation targetRelation : MemoryValueOriginRelation)
    (sourceMember :
      sourceRelation ∈ sourceInvariant.memoryValueOriginRelations)
    (sameOrigins : sourceRelation.origins = targetRelation.origins)
    (originsPreserved :
      ValueOriginsPreserved context sourceWorld targetWorld
        sourceRelation.origins)
    (originalRead :
      Memory.read32 originalAfter.memory
          (targetRelation.originalAddress.eval originalAfter) =
        Memory.read32 originalBefore.memory
          (sourceRelation.originalAddress.eval originalBefore))
    (candidateRead :
      Memory.read32 candidateAfter.memory
          (targetRelation.candidateAddress.eval candidateAfter) =
        Memory.read32 candidateBefore.memory
          (sourceRelation.candidateAddress.eval candidateBefore)) :
    targetRelation.holds context targetWorld originalAfter candidateAfter =
      true := by
  have sourceAll :=
    refinement.sourceRelated.memoryValueOriginsHold context sourceWorld
      sourceInvariant
  have source :=
    memoryValueOriginRelationsHold_member context sourceWorld
      sourceInvariant.memoryValueOriginRelations originalBefore candidateBefore
      sourceRelation sourceAll sourceMember
  exact MemoryValueOriginRelation.holds_of_rebased_read32_eq context
    sourceWorld targetWorld sourceRelation targetRelation originalBefore
    candidateBefore originalAfter candidateAfter sameOrigins originsPreserved
    source originalRead candidateRead

/-- Complete the common save-call-return-reload protocol. The first pair of
read equalities rebases the saved word across the call frame; the second pair
proves that the reload path preserved it; the final pair binds the exact loads
to the restored registers. -/
theorem Refines.restoredRegisterOrigin
    (refinement : Refines context sourceWorld targetWorld sourceInvariant
      targetInvariant certificate originalBefore candidateBefore
      originalAfter candidateAfter)
    (sourceMemory callMemory reloadMemory : MemoryValueOriginRelation)
    (registerRelation : RegisterValueOriginRelation)
    (sourceMember :
      sourceMemory ∈ sourceInvariant.memoryValueOriginRelations)
    (callOrigins : sourceMemory.origins = callMemory.origins)
    (reloadOrigins : callMemory.origins = reloadMemory.origins)
    (registerOrigins : reloadMemory.origins = registerRelation.origins)
    (originsPreserved :
      ValueOriginsPreserved context sourceWorld targetWorld
        sourceMemory.origins)
    (callOriginalRead :
      Memory.read32 originalAfter.memory
          (callMemory.originalAddress.eval originalAfter) =
        Memory.read32 originalBefore.memory
          (sourceMemory.originalAddress.eval originalBefore))
    (callCandidateRead :
      Memory.read32 candidateAfter.memory
          (callMemory.candidateAddress.eval candidateAfter) =
        Memory.read32 candidateBefore.memory
          (sourceMemory.candidateAddress.eval candidateBefore))
    (originalReloaded candidateReloaded : MachineState)
    (reloadOriginalRead :
      Memory.read32 originalReloaded.memory
          (reloadMemory.originalAddress.eval originalReloaded) =
        Memory.read32 originalAfter.memory
          (callMemory.originalAddress.eval originalAfter))
    (reloadCandidateRead :
      Memory.read32 candidateReloaded.memory
          (reloadMemory.candidateAddress.eval candidateReloaded) =
        Memory.read32 candidateAfter.memory
          (callMemory.candidateAddress.eval candidateAfter))
    (originalLoad :
      originalReloaded.registers.get registerRelation.original =
        Memory.read32 originalReloaded.memory
          (reloadMemory.originalAddress.eval originalReloaded))
    (candidateLoad :
      candidateReloaded.registers.get registerRelation.candidate =
        Memory.read32 candidateReloaded.memory
          (reloadMemory.candidateAddress.eval candidateReloaded)) :
    registerRelation.holds context targetWorld originalReloaded.registers
      candidateReloaded.registers = true := by
  have callHolds := refinement.rebasedMemoryOrigin sourceMemory callMemory
    sourceMember callOrigins originsPreserved callOriginalRead callCandidateRead
  have reloadHolds :=
    MemoryValueOriginRelation.holds_of_rebased_read32_eq context
      targetWorld targetWorld callMemory reloadMemory originalAfter
      candidateAfter originalReloaded candidateReloaded reloadOrigins
      (valueOriginsPreserved_sameWorld context targetWorld callMemory.origins)
      callHolds reloadOriginalRead reloadCandidateRead
  exact RegisterValueOriginRelation.holds_of_memoryLoad context targetWorld
    registerRelation reloadMemory originalReloaded candidateReloaded
    registerOrigins reloadHolds originalLoad candidateLoad

end CallRefinement

end StageA.Relational
