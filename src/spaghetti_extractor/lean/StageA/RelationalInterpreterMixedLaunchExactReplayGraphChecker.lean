import StageA.RelationalInterpreterKernelOperationTraceChecker

namespace StageA.Relational.InterpreterMixedLaunchExactReplayGraphChecker

open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Complete direct-control inventory for exact launch replay

The ordinary operation graph follows a call into its callee and therefore does
not treat the saved continuation as an immediate edge.  A launch replay also
needs a fail-closed inventory of every address embedded in direct control,
including that continuation.  This checker inspects the postcondition obtained
from exact instruction replay and rejects indirect or external exits.

This is structural coverage, not call/return refinement.  A later call-frame
certificate must still prove that a callee return reaches the saved
continuation with the required state relation.
-/

def exactNativeLaunchOutcomeTargets? :
    NativeOperationOutcomePostcondition -> Option (List Nat)
  | .running => none
  | .returned _ => some []
  | .jumped targetRva => some [targetRva]
  | .branched _ trueTarget falseTarget =>
      some [trueTarget, falseTarget]
  | .called targetRva continuationRva _ =>
      some [targetRva, continuationRva]
  | .bulkCopy _ continuationRva
  | .bulkFill _ continuationRva
  | .bulkScan _ continuationRva
  | .checkedContinue _ continuationRva
  | .atomicCompareExchange _ _ _ continuationRva =>
      some [continuationRva]
  | .indirectCall .. | .indirectJump _
  | .externalCall .. | .externalJump .. => none

def exactNativeLaunchTargetCovered
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaries : List Nat) (targetRva : Nat) : Bool :=
  (blocks.any fun block =>
    block.entryRva == targetRva && block.entrySlot == 0) ||
  boundaries.contains targetRva

def checkedExactNativeLaunchControlInventory
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaries : List Nat) : Bool :=
  blocks.all fun block =>
    match exactNativeLaunchOutcomeTargets?
        block.terminal.cutpoint.postcondition.outcome with
    | none => false
    | some targets =>
        targets.all (exactNativeLaunchTargetCovered blocks boundaries)

def exactNativeLaunchTargetCoveredByEntry
    (entries boundaries : List Nat) (targetRva : Nat) : Bool :=
  entries.contains targetRva || boundaries.contains targetRva

def checkedExactNativeLaunchControlInventoryAgainstEntries
    (blocks : List (CheckedNativeOperationBlock candidate))
    (entries boundaries : List Nat) : Bool :=
  blocks.all fun block =>
    match exactNativeLaunchOutcomeTargets?
        block.terminal.cutpoint.postcondition.outcome with
    | none => false
    | some targets =>
        targets.all
          (exactNativeLaunchTargetCoveredByEntry entries boundaries)

def exactNativeLaunchBlockEntries
    (blocks : List (CheckedNativeOperationBlock candidate)) :
    List (Nat × Nat) :=
  blocks.map fun block => (block.entryRva, block.entrySlot)

def exactNativeLaunchDeclaredEntries (entries : List Nat) :
    List (Nat × Nat) :=
  entries.map fun entryRva => (entryRva, 0)

structure CheckedExactNativeLaunchReplayShard
    (candidate : ExactNativeWorldProgram)
    (globalEntries boundaries : List Nat) where
  blocks : List (CheckedNativeOperationBlock candidate)
  entries : List Nat
  entriesExact :
    exactNativeLaunchBlockEntries blocks =
      exactNativeLaunchDeclaredEntries entries
  controlsComplete :
    checkedExactNativeLaunchControlInventoryAgainstEntries blocks
      globalEntries boundaries = true

structure CheckedExactNativeLaunchReplayBundle
    (candidate : ExactNativeWorldProgram) where
  globalEntries : List Nat
  boundaries : List Nat
  shards :
    List (CheckedExactNativeLaunchReplayShard candidate globalEntries
      boundaries)
  entriesUnique : globalEntries.Nodup
  entriesComplete :
    shards.flatMap (fun shard => shard.entries) = globalEntries

theorem checkedExactNativeLaunchControlInventory_supported
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaries : List Nat)
    (checked :
      checkedExactNativeLaunchControlInventory blocks boundaries = true)
    (block : CheckedNativeOperationBlock candidate)
    (member : block ∈ blocks) :
    exists targets,
      exactNativeLaunchOutcomeTargets?
          block.terminal.cutpoint.postcondition.outcome = some targets /\
        forall targetRva,
          targetRva ∈ targets ->
            exactNativeLaunchTargetCovered blocks boundaries targetRva =
              true := by
  simp only [checkedExactNativeLaunchControlInventory, List.all_eq_true]
    at checked
  have blockChecked := checked block member
  cases targetsExact :
      exactNativeLaunchOutcomeTargets?
        block.terminal.cutpoint.postcondition.outcome with
  | none =>
      simp [targetsExact] at blockChecked
  | some targets =>
      refine ⟨targets, rfl, ?_⟩
      simpa [targetsExact, List.all_eq_true] using blockChecked

theorem checkedExactNativeLaunchControlInventoryAgainstEntries_supported
    (blocks : List (CheckedNativeOperationBlock candidate))
    (entries boundaries : List Nat)
    (checked :
      checkedExactNativeLaunchControlInventoryAgainstEntries blocks entries
        boundaries = true)
    (block : CheckedNativeOperationBlock candidate)
    (member : block ∈ blocks) :
    exists targets,
      exactNativeLaunchOutcomeTargets?
          block.terminal.cutpoint.postcondition.outcome = some targets /\
        forall targetRva,
          targetRva ∈ targets ->
            targetRva ∈ entries \/ targetRva ∈ boundaries := by
  simp only [checkedExactNativeLaunchControlInventoryAgainstEntries,
    List.all_eq_true] at checked
  have blockChecked := checked block member
  cases targetsExact :
      exactNativeLaunchOutcomeTargets?
        block.terminal.cutpoint.postcondition.outcome with
  | none =>
      simp [targetsExact] at blockChecked
  | some targets =>
      refine ⟨targets, rfl, ?_⟩
      simp only [targetsExact, List.all_eq_true,
        exactNativeLaunchTargetCoveredByEntry, Bool.or_eq_true] at blockChecked
      intro targetRva targetMember
      simpa using blockChecked targetRva targetMember

theorem CheckedExactNativeLaunchReplayBundle.targetBlock
    (bundle : CheckedExactNativeLaunchReplayBundle candidate)
    (targetRva : Nat)
    (targetMember : targetRva ∈ bundle.globalEntries) :
    exists shard,
      shard ∈ bundle.shards /\
        exists block,
          block ∈ shard.blocks /\
            block.entryRva = targetRva /\
            block.entrySlot = 0 := by
  have flattenedMember :
      targetRva ∈ bundle.shards.flatMap (fun shard => shard.entries) := by
    rw [bundle.entriesComplete]
    exact targetMember
  simp only [List.mem_flatMap] at flattenedMember
  obtain ⟨shard, shardMember, entryMember⟩ := flattenedMember
  have declaredMember :
      (targetRva, 0) ∈ exactNativeLaunchDeclaredEntries shard.entries := by
    simp [exactNativeLaunchDeclaredEntries, entryMember]
  rw [← shard.entriesExact] at declaredMember
  simp only [exactNativeLaunchBlockEntries, List.mem_map] at declaredMember
  obtain ⟨block, blockMember, blockEntryExact⟩ := declaredMember
  refine ⟨shard, shardMember, block, blockMember, ?_, ?_⟩
  · exact congrArg Prod.fst blockEntryExact
  · exact congrArg Prod.snd blockEntryExact

theorem CheckedExactNativeLaunchReplayBundle.controlTargetsCovered
    (bundle : CheckedExactNativeLaunchReplayBundle candidate)
    (shard : CheckedExactNativeLaunchReplayShard candidate
      bundle.globalEntries bundle.boundaries)
    (_shardMember : shard ∈ bundle.shards)
    (block : CheckedNativeOperationBlock candidate)
    (blockMember : block ∈ shard.blocks) :
    exists targets,
      exactNativeLaunchOutcomeTargets?
          block.terminal.cutpoint.postcondition.outcome = some targets /\
        forall targetRva,
          targetRva ∈ targets ->
            (exists targetShard,
              targetShard ∈ bundle.shards /\
                exists targetBlock,
                  targetBlock ∈ targetShard.blocks /\
                    targetBlock.entryRva = targetRva /\
                    targetBlock.entrySlot = 0) \/
              targetRva ∈ bundle.boundaries := by
  obtain ⟨targets, targetsExact, targetsCovered⟩ :=
    checkedExactNativeLaunchControlInventoryAgainstEntries_supported
      shard.blocks bundle.globalEntries bundle.boundaries
      shard.controlsComplete block blockMember
  refine ⟨targets, targetsExact, ?_⟩
  intro targetRva targetMember
  cases targetsCovered targetRva targetMember with
  | inl entryMember =>
      exact .inl (bundle.targetBlock targetRva entryMember)
  | inr boundaryMember =>
      exact .inr boundaryMember

#print axioms checkedExactNativeLaunchControlInventory_supported
#print axioms checkedExactNativeLaunchControlInventoryAgainstEntries_supported
#print axioms CheckedExactNativeLaunchReplayBundle.targetBlock
#print axioms CheckedExactNativeLaunchReplayBundle.controlTargetsCovered

end StageA.Relational.InterpreterMixedLaunchExactReplayGraphChecker
