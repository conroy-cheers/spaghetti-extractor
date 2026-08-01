import StageA.RelationalOriginalTargetControlPreservation

namespace StageA.Relational.OriginalTargetControlConstruction

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalTargetControlPreservation
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

/-!
# Checked construction of ordinary direct-control evidence

These constructors turn the exact normalized outcome retained by an ordinary
target evaluator into the universal control evidence used by target
preservation.  Generated code supplies only reducible equalities for the
normalized outcome and write inventory.  Lean evaluates those equalities
against the exact decoded evaluator.

The no-write constructors cover fallthrough/jump and conditional branch.
Calls, returns, and external transitions use the explicit routed constructor:
their stack/world effects must be supplied by the corresponding checked frame
or environment authority.  Indirect control has no constructor here.
-/

theorem dormantOriginalCallFrameHoldsOfMemoryEq
    (frame : DormantOriginalCallFrame) (context : StaticProofContext)
    (world : RelationalWorld) (before after : MachineState)
    (memoryExact : after.memory = before.memory)
    (holds : frame.Holds context world before) :
    frame.Holds context world after := by
  simpa [DormantOriginalCallFrame.Holds, memoryExact] using holds

theorem ordinaryNoWritesMemoryExact
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (calls : List Nat) (state : MachineState)
    (writesEmpty : (decoded.normalized calls).writes = []) :
    ((decoded.behavior state calls).nextMachineState state).memory =
      state.memory := by
  simp [ExactDecodedOrdinaryTargetEvaluator.behavior,
    RelationalBehavior.nextMachineState, writesEmpty, evalNormalizedWrites,
    applyConcreteWrites]

def ordinaryNoWriteJumpControl
    {pe : PE32} {program : Program} {targetId sourceRva nextTargetId : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (outcomeExact : forall calls,
      (decoded.normalized calls).outcome = .jump nextTargetId)
    (writesEmpty : forall calls, (decoded.normalized calls).writes = [])
    (nextReachable : nextTargetId ∈ inventory.reachableTargets.targetIds) :
    CheckedOriginalTargetControlEvidence originalContext inventory
      (CheckedOriginalTargetEffect.ofOrdinary checked adequate) where
  outcome invocation holds _faultFree := by
    let afterState := (decoded.behavior invocation.state invocation.calls).nextMachineState
      invocation.state
    have concreteOutcome :
        (decoded.behavior invocation.state invocation.calls).outcome =
          .jump nextTargetId := by
      simp [ExactDecodedOrdinaryTargetEvaluator.behavior,
        outcomeExact invocation.calls, NormalizedOutcomeExpr.eval]
    have memoryExact : afterState.memory = invocation.state.memory := by
      exact ordinaryNoWritesMemoryExact checked invocation.calls invocation.state
        (writesEmpty invocation.calls)
    refine {
      control := ?_
      successor := originalNormalizedResume invocation.routingCallbacks
        nextTargetId afterState invocation.calls invocation.eventIndex
        invocation.world
      successorExact := ?_
      post := ?_
    }
    · change CheckedOriginalOutcomeEvidence originalContext
        inventory.reachableTargets.targetIds targetId afterState
          (decoded.behavior invocation.state invocation.calls).outcome
      rw [concreteOutcome]
      exact (CheckedOriginalStaticTargetEvidence.mk nextReachable).jumpControl
    · change
        (transitionFromWorldOutcome program.worldProgram targetId afterState
          invocation.calls invocation.eventIndex invocation.world
          invocation.routingCallbacks
          (decoded.behavior invocation.state invocation.calls).outcome).next = _
      rw [concreteOutcome]
      exact originalNormalizedResume_execution _ _ _ _ _ _ |>.symm
    · exact controlPostOfPreservedFrames invocation holds nextTargetId afterState
        invocation.eventIndex invocation.world nextReachable (fun frame frameHolds =>
          dormantOriginalCallFrameHoldsOfMemoryEq frame
            program.worldProgram.context invocation.world
            invocation.state afterState memoryExact frameHolds)

def ordinaryNoWriteBranchControl
    {pe : PE32} {program : Program} {targetId sourceRva taken fallthrough : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (condition : BoolExpr)
    (outcomeExact : forall calls,
      (decoded.normalized calls).outcome = .branch condition taken fallthrough)
    (writesEmpty : forall calls, (decoded.normalized calls).writes = [])
    (takenReachable : taken ∈ inventory.reachableTargets.targetIds)
    (fallthroughReachable : fallthrough ∈ inventory.reachableTargets.targetIds) :
    CheckedOriginalTargetControlEvidence originalContext inventory
      (CheckedOriginalTargetEffect.ofOrdinary checked adequate) where
  outcome invocation holds _faultFree := by
    let afterState := (decoded.behavior invocation.state invocation.calls).nextMachineState
      invocation.state
    let branchCondition := condition.eval invocation.state
    let nextTargetId := if branchCondition then taken else fallthrough
    have concreteOutcome :
        (decoded.behavior invocation.state invocation.calls).outcome =
          .branch branchCondition taken fallthrough := by
      simp [ExactDecodedOrdinaryTargetEvaluator.behavior,
        outcomeExact invocation.calls, NormalizedOutcomeExpr.eval,
        branchCondition]
    have nextReachable :
        nextTargetId ∈ inventory.reachableTargets.targetIds := by
      simp only [nextTargetId]
      split <;> assumption
    have memoryExact : afterState.memory = invocation.state.memory := by
      exact ordinaryNoWritesMemoryExact checked invocation.calls invocation.state
        (writesEmpty invocation.calls)
    refine {
      control := ?_
      successor := originalNormalizedResume invocation.routingCallbacks
        nextTargetId afterState invocation.calls invocation.eventIndex
        invocation.world
      successorExact := ?_
      post := ?_
    }
    · change CheckedOriginalOutcomeEvidence originalContext
        inventory.reachableTargets.targetIds targetId afterState
          (decoded.behavior invocation.state invocation.calls).outcome
      rw [concreteOutcome]
      exact (CheckedOriginalBranchTargetEvidence.mk takenReachable
        fallthroughReachable).branchControl
    · change
        (transitionFromWorldOutcome program.worldProgram targetId afterState
          invocation.calls invocation.eventIndex invocation.world
          invocation.routingCallbacks
          (decoded.behavior invocation.state invocation.calls).outcome).next = _
      rw [concreteOutcome]
      simp only [transitionFromWorldOutcome]
      exact originalNormalizedResume_execution _ _ _ _ _ _ |>.symm
    · exact controlPostOfPreservedFrames invocation holds nextTargetId afterState
        invocation.eventIndex invocation.world nextReachable (fun frame frameHolds =>
          dormantOriginalCallFrameHoldsOfMemoryEq frame
            program.worldProgram.context invocation.world
            invocation.state afterState memoryExact frameHolds)

/-- Constructor boundary for call, return, and external routes.  The route is
still fully checked: it names the concrete evaluated outcome, exact world
successor, and both control post families.  This adapter exists so generated
targets consume the same universal evidence type as direct no-write targets;
it grants no authority to a Python classification. -/
def ordinaryRoutedControl
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (route : forall (invocation : OriginalTargetInvocation targetId),
      inventory.Holds invocation.execution ->
      let behavior := decoded.behavior invocation.state invocation.calls
      behavior.x87Fault = none ->
        CheckedOriginalRoutedOutcome originalContext inventory invocation
          (behavior.nextMachineState invocation.state) behavior.outcome) :
    CheckedOriginalTargetControlEvidence originalContext inventory
      (CheckedOriginalTargetEffect.ofOrdinary checked adequate) where
  outcome := route

/-- Reflective classifier for local direct control.  The reachable-target list
is the actual inventory consumed by the whole-program invariant. -/
def localDirectOutcomeChecked (targetIds : List Nat) :
    NormalizedOutcomeExpr -> Bool
  | .jump target => targetIds.contains target
  | .branch _ taken fallthrough =>
      targetIds.contains taken && targetIds.contains fallthrough
  | _ => false

theorem localDirectOutcomeChecked_jump
    {targetIds : List Nat} {target : Nat}
    (checked : localDirectOutcomeChecked targetIds (.jump target) = true) :
    target ∈ targetIds := by
  simpa [localDirectOutcomeChecked, List.contains_iff_mem] using checked

theorem localDirectOutcomeChecked_branch
    {targetIds : List Nat} {condition : BoolExpr} {taken fallthrough : Nat}
    (checked : localDirectOutcomeChecked targetIds
      (.branch condition taken fallthrough) = true) :
    taken ∈ targetIds /\ fallthrough ∈ targetIds := by
  simpa [localDirectOutcomeChecked, List.contains_iff_mem] using checked

/-- Construct universal direct-control evidence without trusting Python's
chosen target identifiers.  Lean inspects the exact normalized outcome for
each call-stack specialization and rejects every non-local control class. -/
def ordinaryNoWriteLocalControl
    {pe : PE32} {program : Program} {targetId sourceRva : Nat}
    {record : ProgramRecord} {path : ExactNormalizedTransferPath}
    {transfer : SemanticTransfer} {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (adequate : program.worldProgram.InstructionSemanticsAdequate)
    (controlChecked : forall calls,
      localDirectOutcomeChecked inventory.reachableTargets.targetIds
        (decoded.normalized calls).outcome = true)
    (writesEmpty : forall calls, (decoded.normalized calls).writes = []) :
    CheckedOriginalTargetControlEvidence originalContext inventory
      (CheckedOriginalTargetEffect.ofOrdinary checked adequate) :=
  ordinaryRoutedControl checked adequate (by
    intro invocation holds
    dsimp only
    intro _faultFree
    let normalized := decoded.normalized invocation.calls
    let behavior := decoded.behavior invocation.state invocation.calls
    let afterState := behavior.nextMachineState invocation.state
    have memoryExact : afterState.memory = invocation.state.memory := by
      exact ordinaryNoWritesMemoryExact checked invocation.calls invocation.state
        (writesEmpty invocation.calls)
    cases outcomeExact : normalized.outcome with
    | jump nextTargetId =>
        have nextReachable :
            nextTargetId ∈ inventory.reachableTargets.targetIds :=
          localDirectOutcomeChecked_jump (by
            simpa [normalized, outcomeExact] using controlChecked invocation.calls)
        have concreteOutcome : behavior.outcome = .jump nextTargetId := by
          simp [behavior, ExactDecodedOrdinaryTargetEvaluator.behavior,
            normalized, outcomeExact, NormalizedOutcomeExpr.eval]
        refine {
          control := ?_
          successor := originalNormalizedResume invocation.routingCallbacks
            nextTargetId afterState invocation.calls invocation.eventIndex
            invocation.world
          successorExact := ?_
          post := ?_
        }
        · rw [concreteOutcome]
          exact (CheckedOriginalStaticTargetEvidence.mk nextReachable).jumpControl
        · rw [concreteOutcome]
          exact originalNormalizedResume_execution _ _ _ _ _ _ |>.symm
        · exact controlPostOfPreservedFrames invocation holds nextTargetId
            afterState invocation.eventIndex invocation.world nextReachable
            (fun frame frameHolds =>
              dormantOriginalCallFrameHoldsOfMemoryEq frame
                program.worldProgram.context invocation.world invocation.state
                afterState memoryExact frameHolds)
    | branch condition taken fallthrough =>
        have destinations := localDirectOutcomeChecked_branch (by
          simpa [normalized, outcomeExact] using controlChecked invocation.calls)
        let branchCondition := condition.eval invocation.state
        let nextTargetId := if branchCondition then taken else fallthrough
        have nextReachable :
            nextTargetId ∈ inventory.reachableTargets.targetIds := by
          simp only [nextTargetId]
          split <;> simp_all
        have concreteOutcome :
            behavior.outcome = .branch branchCondition taken fallthrough := by
          simp [behavior, ExactDecodedOrdinaryTargetEvaluator.behavior,
            normalized, outcomeExact, NormalizedOutcomeExpr.eval,
            branchCondition]
        refine {
          control := ?_
          successor := originalNormalizedResume invocation.routingCallbacks
            nextTargetId afterState invocation.calls invocation.eventIndex
            invocation.world
          successorExact := ?_
          post := ?_
        }
        · rw [concreteOutcome]
          exact (CheckedOriginalBranchTargetEvidence.mk destinations.1
            destinations.2).branchControl
        · rw [concreteOutcome]
          simp only [transitionFromWorldOutcome]
          exact originalNormalizedResume_execution _ _ _ _ _ _ |>.symm
        · exact controlPostOfPreservedFrames invocation holds nextTargetId
            afterState invocation.eventIndex invocation.world nextReachable
            (fun frame frameHolds =>
              dormantOriginalCallFrameHoldsOfMemoryEq frame
                program.worldProgram.context invocation.world invocation.state
                afterState memoryExact frameHolds)
    | returned target =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | call target continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | callUnmappedReturn target =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | externalCall imported arguments continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | externalJump imported arguments =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | bulkCopy destination source count direction continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | bulkFill destination value count direction continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | indirectCall target continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | indirectJump target =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | checkedContinue valid continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible
    | atomicCompareExchange address expected replacement continuation =>
        have impossible := controlChecked invocation.calls
        simp [localDirectOutcomeChecked, normalized, outcomeExact] at impossible)

end StageA.Relational.OriginalTargetControlConstruction
