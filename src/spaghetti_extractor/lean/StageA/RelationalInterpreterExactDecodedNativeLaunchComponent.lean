import StageA.RelationalInterpreterExactDecodedNativeComponents

namespace StageA.Relational.InterpreterExactDecodedNativeLaunchComponent

open StageA.Relational
open StageA.Relational.InterpreterExactDecodedNativeComponents
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact decoded/native launch-component bridge

A successful reflected native replay already establishes the checked source,
checked destination, and nonempty native path.  The exact decoded/native bridge
therefore retains only the two cross-system facts that replay cannot imply: a
decoded path with exactly the replayed observations, and the relation between
the two endpoints.
-/

/-- The exact premises not supplied by a successful native launch replay.

`decodedAfter` is a dependent endpoint witness, not a third semantic premise:
the two proof fields are the decoded path and the endpoint relation.
-/
structure ExactDecodedNativeLaunchComponentRemainingPremises
    (decoded : DecodedWorldProgram)
    (relation : WorldExecution -> NativeWorldExecution -> Prop)
    (decodedBefore : WorldExecution)
    (replay : ReflectedNativeLaunchPathReplay) where
  decodedAfter : WorldExecution
  decodedPath : NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
    replay.observations decodedAfter
  afterRelated : relation decodedAfter replay.after

/-- Convert the existing proposition-valued path API into the computed segment
required by `ExactDecodedNativeLaunchComponentCertificate`. -/
noncomputable def exactDecodedNativeLaunchSegmentOfPath
    {decoded : DecodedWorldProgram}
    {decodedBefore decodedAfter : WorldExecution}
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
      observations decodedAfter) :
    ExactComputedNonemptySegment decoded.pe32TransitionSystem decodedBefore := {
  fuel := Classical.choose path
  positive := (Classical.choose_spec path).1
}

theorem exactDecodedNativeLaunchSegmentOfPath_observations
    {decoded : DecodedWorldProgram}
    {decodedBefore decodedAfter : WorldExecution}
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
      observations decodedAfter) :
    (exactDecodedNativeLaunchSegmentOfPath path).observations =
      observations := by
  exact congrArg Prod.snd (Classical.choose_spec path).2

theorem exactDecodedNativeLaunchSegmentOfPath_after
    {decoded : DecodedWorldProgram}
    {decodedBefore decodedAfter : WorldExecution}
    {observations : List WorldRelationalObservable}
    (path : NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
      observations decodedAfter) :
    (exactDecodedNativeLaunchSegmentOfPath path).after = decodedAfter := by
  exact congrArg Prod.fst (Classical.choose_spec path).2

/-- Derive the exact launch component from checked native replay evidence and
the two remaining cross-system premises.

No separate static-check, source-match, destination-match, native-path, fuel,
or observation-equality premise is accepted.  All native facts come from
`replayed`; the decoded observation equality follows from the indexed path.
-/
noncomputable def exactDecodedNativeLaunchComponentCertificateOfCheckedReplay
    {decoded : DecodedWorldProgram}
    {native : ExactNativeWorldProgram}
    {relation : WorldExecution -> NativeWorldExecution -> Prop}
    {decodedBefore : WorldExecution}
    {nativeBefore : NativeWorldExecution}
    (cutpoints : List StableInterpreterCutpoint)
    (reflected : ReflectedNativeLaunchPathCertificate)
    (replay : ReflectedNativeLaunchPathReplay)
    (replayed :
      reflected.replay? native cutpoints nativeBefore = some replay)
    (remaining : ExactDecodedNativeLaunchComponentRemainingPremises decoded
      relation decodedBefore replay) :
    ExactDecodedNativeLaunchComponentCertificate decoded native relation
      decodedBefore nativeBefore := {
  cutpoints
  reflected
  replay
  replayed
  decodedSegment :=
    exactDecodedNativeLaunchSegmentOfPath remaining.decodedPath
  observationsExact :=
    exactDecodedNativeLaunchSegmentOfPath_observations remaining.decodedPath
  afterRelated := by
    rw [exactDecodedNativeLaunchSegmentOfPath_after remaining.decodedPath]
    exact remaining.afterRelated
}

#print axioms exactDecodedNativeLaunchSegmentOfPath_observations
#print axioms exactDecodedNativeLaunchSegmentOfPath_after
#print axioms exactDecodedNativeLaunchComponentCertificateOfCheckedReplay

end StageA.Relational.InterpreterExactDecodedNativeLaunchComponent
