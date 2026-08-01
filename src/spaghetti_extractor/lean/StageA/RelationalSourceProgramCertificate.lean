import StageA.RelationalSourceInterpreterKernel

namespace StageA.Relational.SourceWorld.ProgramCertificate

open StageA.Relational
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

/-!
Checked whole-inventory bridge from `ProgramRecord` execution to decoded PE
semantics.

Generated modules prove one compact certificate for every active target.  This
stable layer checks target lookup, requires explicit coverage of every running
state admitted by the rooted execution domain, and discharges control states
whose source and decoded transitions are definitionally identical.
-/

/-- Full exact-bound world-transition agreement at one active target.  The
selection field prevents a free-standing routing equality from authorizing an
unrelated ProgramRecord or x87 inventory. -/
structure ActiveTargetTransitionCertificate
    {pe : StageA.Formal.PE32} {program : Program}
    (binding : ExactBinding pe program) where
  targetId : Nat
  selection : BoundTargetSelection program targetId
  running : forall state calls eventIndex world,
    let sourceTransition := program.kernel.step
      (.running targetId state calls eventIndex world)
    let decodedTransition :=
      (decodedSemanticKernel program.worldProgram).step
        (.running targetId state calls eventIndex world)
    sourceTransition.next = decodedTransition.next /\
      sourceTransition.observation = decodedTransition.observation
  callbackRunning : forall state calls eventIndex world callbacks,
    let sourceTransition := program.kernel.step
      (.callbackRunning targetId state calls eventIndex world callbacks)
    let decodedTransition :=
      (decodedSemanticKernel program.worldProgram).step
        (.callbackRunning targetId state calls eventIndex world callbacks)
    sourceTransition.next = decodedTransition.next /\
      sourceTransition.observation = decodedTransition.observation

def ActiveTargetTransitionCertificate.ofExactBound
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} {targetId : Nat}
    (exact : ExactBoundTargetStepEquality binding targetId) :
    ActiveTargetTransitionCertificate binding where
  targetId := targetId
  selection := exact.selection
  running := exact.running
  callbackRunning := exact.callbackRunning

/-- Deterministic finite certificate lookup.  The first matching target is
returned; a checked index below rules out duplicate target identifiers. -/
def findTargetCertificate? {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} :
    List (ActiveTargetTransitionCertificate binding) -> Nat ->
      Option (ActiveTargetTransitionCertificate binding)
  | [], _ => none
  | certificate :: certificates, targetId =>
      if certificate.targetId == targetId then
        some certificate
      else
        findTargetCertificate? certificates targetId

/-- Lookup never returns a certificate for a different target. -/
theorem findTargetCertificate?_targetExact
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    {certificates : List (ActiveTargetTransitionCertificate binding)}
    {targetId : Nat}
    {certificate : ActiveTargetTransitionCertificate binding}
    (found : findTargetCertificate? certificates targetId = some certificate) :
    certificate.targetId = targetId := by
  induction certificates with
  | nil => simp [findTargetCertificate?] at found
  | cons head tail induction =>
      simp only [findTargetCertificate?] at found
      split at found <;> simp_all

/-- Every target identifier present in the submitted certificate inventory has
an executable lookup result.  This is the completeness counterpart to
`findTargetCertificate?_targetExact`; generated domain-coverage proofs use it
instead of re-evaluating the certificate list for every running state. -/
theorem findTargetCertificate?_isSome_of_target_mem
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    {certificates : List (ActiveTargetTransitionCertificate binding)}
    {targetId : Nat}
    (member : targetId ∈
      certificates.map (fun certificate => certificate.targetId)) :
    exists certificate,
      findTargetCertificate? certificates targetId = some certificate := by
  induction certificates with
  | nil => simp at member
  | cons head tail induction =>
      simp only [List.map_cons, List.mem_cons] at member
      rcases member with targetExact | member
      · subst targetId
        exact ⟨head, by simp [findTargetCertificate?]⟩
      · rcases induction member with ⟨certificate, found⟩
        by_cases headExact : head.targetId = targetId
        · subst targetId
          exact ⟨head, by simp [findTargetCertificate?]⟩
        · exact ⟨certificate, by
            simp [findTargetCertificate?, headExact, found]⟩

/-- Canonical finite target-certificate inventory.  Uniqueness is checked once
when the generated inventory is assembled, rather than repeatedly by every
local proof. -/
structure ActiveTargetTransitionIndex
    {pe : StageA.Formal.PE32} {program : Program}
    (binding : ExactBinding pe program) where
  certificates : List (ActiveTargetTransitionCertificate binding)
  targetIdsUnique : (certificates.map (fun certificate => certificate.targetId)).Nodup

def ActiveTargetTransitionIndex.find?
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    (index : ActiveTargetTransitionIndex binding) (targetId : Nat) :
    Option (ActiveTargetTransitionCertificate binding) :=
  findTargetCertificate? index.certificates targetId

theorem ActiveTargetTransitionIndex.find?_targetExact
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    (index : ActiveTargetTransitionIndex binding)
    {targetId : Nat}
    {certificate : ActiveTargetTransitionCertificate binding}
    (found : index.find? targetId = some certificate) :
    certificate.targetId = targetId :=
  findTargetCertificate?_targetExact found

theorem ActiveTargetTransitionIndex.find?_isSome_of_target_mem
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program}
    (index : ActiveTargetTransitionIndex binding)
    {targetId : Nat}
    (member : targetId ∈
      index.certificates.map (fun certificate => certificate.targetId)) :
    exists certificate, index.find? targetId = some certificate :=
  findTargetCertificate?_isSome_of_target_mem member

/-- A source program is accepted only when the same exact PE binding and the
complete active-target transition inventory are packaged together.  The
transition certificates compare against `decodedSemanticKernel`; the binding
independently prevents those certificates from authorizing an unrelated
ProgramRecord or x87 inventory. -/
structure ExactBoundActiveTargetTransitionIndex
    {pe : StageA.Formal.PE32} {program : Program}
    (binding : ExactBinding pe program) where
  index : ActiveTargetTransitionIndex binding

/-- Explicit coverage boundary between rooted reachability and the finite
certificate inventory.  It covers both ordinary and callback-mode running
states.  Non-running states require no generated certificate because the two
kernels share their transition definitions. -/
structure ActiveTargetDomainCoverage
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} {root : WorldExecution}
    (index : ActiveTargetTransitionIndex binding)
    (domain : CheckedExecutionDomain program.worldProgram root) : Prop where
  running : forall targetId state calls eventIndex world,
    domain.holds (.running targetId state calls eventIndex world) ->
      exists certificate, index.find? targetId = some certificate
  callbackRunning : forall targetId state calls eventIndex world callbacks,
    domain.holds
      (.callbackRunning targetId state calls eventIndex world callbacks) ->
      exists certificate, index.find? targetId = some certificate

/-- Construct domain coverage from one stable target-membership inventory.
Generated modules supply the finite inventory equality once, while rooted
reachability supplies the two membership implications. -/
def ActiveTargetDomainCoverage.ofTargetMembership
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} {root : WorldExecution}
    (index : ActiveTargetTransitionIndex binding)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (targetIds : List Nat)
    (targetsExact :
      index.certificates.map (fun certificate => certificate.targetId) =
        targetIds)
    (runningTargetMember : forall targetId state calls eventIndex world,
      domain.holds (.running targetId state calls eventIndex world) ->
        targetId ∈ targetIds)
    (callbackTargetMember :
      forall targetId state calls eventIndex world callbacks,
        domain.holds
          (.callbackRunning targetId state calls eventIndex world callbacks) ->
          targetId ∈ targetIds) :
    ActiveTargetDomainCoverage index domain where
  running targetId state calls eventIndex world inDomain := by
    apply index.find?_isSome_of_target_mem
    rw [targetsExact]
    exact runningTargetMember targetId state calls eventIndex world inDomain
  callbackRunning targetId state calls eventIndex world callbacks inDomain := by
    apply index.find?_isSome_of_target_mem
    rw [targetsExact]
    exact callbackTargetMember targetId state calls eventIndex world callbacks
      inDomain

/-- Aggregate checked target certificates into the exact whole-domain step
equality consumed by source-kernel composition. -/
theorem programRecordKernelMatchesDecodedSemantics_of_checkedTargets
    {pe : StageA.Formal.PE32} {program : Program}
    {binding : ExactBinding pe program} {root : WorldExecution}
    (index : ActiveTargetTransitionIndex binding)
    (domain : CheckedExecutionDomain program.worldProgram root)
    (coverage : ActiveTargetDomainCoverage index domain) :
    ProgramRecordKernelMatchesDecodedSemantics program domain := by
  intro execution executionInDomain
  cases execution with
  | running targetId state calls eventIndex world =>
      rcases coverage.running targetId state calls eventIndex world
        executionInDomain with ⟨certificate, found⟩
      have targetExact := index.find?_targetExact found
      simpa [targetExact] using
        certificate.running state calls eventIndex world
  | callbackRunning targetId state calls eventIndex world callbacks =>
      rcases coverage.callbackRunning targetId state calls eventIndex world callbacks
        executionInDomain with ⟨certificate, found⟩
      have targetExact := index.find?_targetExact found
      simpa [targetExact] using
        certificate.callbackRunning state calls eventIndex world callbacks
  | returned state world => exact ⟨rfl, rfl⟩
  | terminated world => exact ⟨rfl, rfl⟩
  | awaitingExternal suspension callbacks => exact ⟨rfl, rfl⟩
  | fault cause => exact ⟨rfl, rfl⟩
  | blocked reason => exact ⟨rfl, rfl⟩

end StageA.Relational.SourceWorld.ProgramCertificate
