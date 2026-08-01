import StageA.RelationalSourceWorld
import StageA.RelationalPEWorldExecution

namespace StageA.Relational.SourceWorld

open StageA.Relational

/-!
Left-only raw-EIP lifting for exact-original-PE to source-kernel simulations.

Unlike the existing binary-to-binary lift, only the original execution has a
raw EIP. The explicit closure premise requires a canonical executable EIP only
for concretized logical states admitted by the checked rooted execution domain;
missing mappings on reachable states therefore remain proof frontiers without
creating obligations for states outside the proved invariant.
-/

/-- Exact closure needed to replay a logical original path through the raw-EIP
transition system. Closure is deliberately restricted to the checked execution
domain used by the source simulation. -/
def RawEipLeftStepClosed (original : DecodedWorldProgram)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain original root) : Prop :=
  forall logical raw,
    domain.holds logical ->
      logical.ConcretizesToRawEip original raw ->
      exists rawNext,
        (original.pe32TransitionSystem.step logical).next.ConcretizesToRawEip
          original rawNext

/-- Fixed lifted state relation. It combines exact raw/logical round-trip
evidence with the repository-defined source-world correspondence. -/
def RawEipSourceExecutionsMatch (original : DecodedWorldProgram)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain original root)
    (raw : RawEipWorldExecution) (source : Execution) : Prop :=
  exists logical,
    logical.ConcretizesToRawEip original raw ∧
      ExecutionsMatch domain logical source

theorem runRelatedSteps_rawEip_of_logical (original : DecodedWorldProgram)
    {root : WorldExecution}
    (domain : CheckedExecutionDomain original root)
    (closed : RawEipLeftStepClosed original root domain) :
    forall fuel logical raw logicalAfter observations,
      domain.holds logical ->
      logical.ConcretizesToRawEip original raw ->
      runRelatedSteps original.pe32TransitionSystem fuel logical =
          (logicalAfter, observations) ->
        exists rawAfter,
          runRelatedSteps original.pe32RawEipTransitionSystem fuel raw =
              (rawAfter, observations) ∧
            logicalAfter.ConcretizesToRawEip original rawAfter := by
  intro fuel
  induction fuel with
  | zero =>
      intro logical raw logicalAfter observations _member current executed
      simp only [runRelatedSteps] at executed
      cases executed
      exact ⟨raw, rfl, current⟩
  | succ fuel induction =>
      intro logical raw logicalAfter observations member current executed
      let logicalTransition := original.pe32TransitionSystem.step logical
      let logicalTail := runRelatedSteps original.pe32TransitionSystem fuel
        logicalTransition.next
      change (logicalTail.1,
          logicalTransition.observation.toList ++ logicalTail.2) =
        (logicalAfter, observations) at executed
      have afterEqual : logicalTail.1 = logicalAfter :=
        congrArg Prod.fst executed
      have observationsEqual :
          logicalTransition.observation.toList ++ logicalTail.2 = observations :=
        congrArg Prod.snd executed
      rcases closed logical raw member current with ⟨rawNext, nextConcrete⟩
      have nextMember : domain.holds logicalTransition.next :=
        domain.stepClosed logical member
      have rawStep :
          original.pe32RawEipTransitionSystem.step raw = {
            next := rawNext
            observation := logicalTransition.observation
          } := by
        exact stepPE32RawEipWorldExecution_of_concretizes original logical raw
          rawNext current nextConcrete
      rcases induction logicalTransition.next rawNext logicalTail.1
          logicalTail.2 nextMember nextConcrete rfl with
        ⟨rawAfter, rawTail, afterConcrete⟩
      refine ⟨rawAfter, ?_, ?_⟩
      · simp only [runRelatedSteps]
        rw [rawStep]
        simp only
        rw [rawTail, observationsEqual]
      · rw [afterEqual] at afterConcrete
        exact afterConcrete

theorem NonemptyRelatedPath.liftRawEipLeft {original : DecodedWorldProgram}
    {root : WorldExecution}
    (domain : CheckedExecutionDomain original root)
    (closed : RawEipLeftStepClosed original root domain)
    {logicalBefore logicalAfter : WorldExecution}
    {rawBefore : RawEipWorldExecution}
    {observations : List WorldRelationalObservable}
    (beforeMember : domain.holds logicalBefore)
    (current : logicalBefore.ConcretizesToRawEip original rawBefore)
    (path : NonemptyRelatedPath original.pe32TransitionSystem logicalBefore
      observations logicalAfter) :
    exists rawAfter,
      NonemptyRelatedPath original.pe32RawEipTransitionSystem rawBefore
        observations rawAfter ∧
      logicalAfter.ConcretizesToRawEip original rawAfter := by
  rcases path with ⟨fuel, positive, executed⟩
  rcases runRelatedSteps_rawEip_of_logical original domain closed fuel
      logicalBefore rawBefore logicalAfter observations beforeMember current
      executed with
    ⟨rawAfter, rawExecuted, afterConcrete⟩
  exact ⟨rawAfter, ⟨fuel, positive, rawExecuted⟩, afterConcrete⟩

/-- Acceptance-facing equivalence with a concrete original EIP and a logical
source-kernel control location. -/
def ExactRawOriginalPESourceKernelObservationallyEquivalent
    (original : DecodedWorldProgram) (kernel : Kernel)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain original root) : Prop :=
  ChunkedRelationalBisimulation original.pe32RawEipTransitionSystem
    kernel.transitionSystem (RawEipSourceExecutionsMatch original root domain)
    sourceObservationsRelated

theorem chunkedSimulation_rawEipLeft_of_logical
    {original : DecodedWorldProgram} {kernel : Kernel}
    {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain)
    (closed : RawEipLeftStepClosed original root domain) :
    ExactRawOriginalPESourceKernelObservationallyEquivalent original kernel root
      domain := by
  intro rawBefore sourceBefore beforeMatches
  rcases beforeMatches with ⟨logicalBefore, current, logicalMatches⟩
  let chunk := composition.chunk logicalBefore sourceBefore logicalMatches
  rcases NonemptyRelatedPath.liftRawEipLeft domain closed logicalMatches.2
      current chunk.originalPath with
    ⟨rawAfter, rawPath, afterConcrete⟩
  exact ⟨chunk.originalObservations, chunk.sourceObservations, rawAfter,
    chunk.sourceAfter, rawPath, chunk.sourcePath.toRelatedPath,
    chunk.observationsRelated,
    ⟨chunk.originalAfter, afterConcrete,
      ⟨chunk.afterProjection,
        domain.pathClosed logicalMatches.2 chunk.originalPath⟩⟩⟩

theorem chunkedSimulation_rawEipLeft_trace
    {original : DecodedWorldProgram} {kernel : Kernel}
    {root : WorldExecution}
    {domain : CheckedExecutionDomain original root}
    (composition : ChunkComposition original kernel root domain)
    (closed : RawEipLeftStepClosed original root domain) :
    forall fuel rawExecution sourceExecution,
      RawEipSourceExecutionsMatch original root domain rawExecution
          sourceExecution ->
        ChunkedRelatedTrace original.pe32RawEipTransitionSystem
          kernel.transitionSystem
          (RawEipSourceExecutionsMatch original root domain)
          sourceObservationsRelated
          fuel rawExecution sourceExecution :=
  chunkedRelationalBisimulation_trace original.pe32RawEipTransitionSystem
    kernel.transitionSystem (RawEipSourceExecutionsMatch original root domain)
    sourceObservationsRelated
    (chunkedSimulation_rawEipLeft_of_logical composition closed)

end StageA.Relational.SourceWorld
