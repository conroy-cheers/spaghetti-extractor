from __future__ import annotations

from typing import Any

from ..schema import SchemaError
from .expressions import (
    _lean_register_offset_witness,
    _lean_return_slot_offset_pair,
    _lean_semantic_expr,
)


def _lean_acceptance_callback_return_node(
    step: dict[str, Any], *, parameterized_environment: bool,
    parameterized_protocol_environment: bool,
) -> str:
    """Emit callback-mode closure for a checked no-write return node."""
    if step.get("kind") != "terminate":
        raise SchemaError(
            "callback-running acceptance currently requires a checked callback return"
        )
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    profile_index = int(step["callback_profile_index"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    original_program = (
        "(originalWorldProgram originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        + "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else "    :\n"
    )
    ordinary_arguments = (
        " originalEnvironment candidateEnvironment"
        + (
            " originalProtocolEnvironment candidateProtocolEnvironment"
            if parameterized_protocol_environment else ""
        )
        + " environmentRefines"
        if parameterized_environment else ""
    )
    behavior_rewrite_arguments = (
        " originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    candidate_behavior_rewrite_arguments = (
        " candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    return_claim = step["return_pop_claim"]
    frame_claim = step["callback_return_frame_claim"]
    return_claim_row = (
        "{ originalStackAddress := "
        + _lean_semantic_expr(return_claim["original_stack_address"])
        + ", candidateStackAddress := "
        + _lean_semantic_expr(return_claim["candidate_stack_address"])
        + f", popBytes := {int(return_claim['pop_bytes'])} }}"
    )
    frame_claim_row = (
        "{ offsets := "
        + _lean_return_slot_offset_pair(frame_claim["offsets"])
        + ", originalSlot := "
        + _lean_register_offset_witness(frame_claim["original_slot_witness"])
        + ", candidateSlot := "
        + _lean_register_offset_witness(frame_claim["candidate_slot_witness"])
        + " }"
    )
    return (
        f"theorem acceptanceCallbackRunningNode{node_id}Refined\n"
        + environment_binders
        + "    CallbackRunningProductNodeStepRefined staticProofContext\n"
        "      relationalProductGraph productInvariantTable\n"
        "      relationalProductReachabilityEvidence productControlProfile\n"
        "      protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold CallbackRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls frameOffsets eventIndex world originalState candidateState\n"
        "    originalCallbacks candidateCallbacks controlAllowed stackHolds\n"
        "    frameImportsHold stackTargetsReachable statesRelated callbacksNonempty callbacksRelated\n"
        "    callbackFramesHold\n"
        "  have callsEmpty : calls = [] := by\n"
        "    cases calls with\n"
        "    | nil => rfl\n"
        "    | cons call tail =>\n"
        "        simp [productControlProfile, ProductControlProfile.Allows]\n"
        "          at controlAllowed\n"
        "  subst calls\n"
        "  have offsetsEmpty : frameOffsets = [] := by\n"
        "    cases frameOffsets with\n"
        "    | nil => rfl\n"
        "    | cons offset tail =>\n"
        "        simp [productControlProfile, ProductControlProfile.Allows]\n"
        "          at controlAllowed\n"
        "  subst frameOffsets\n"
        "  have framesEmpty : frames = [] := by\n"
        "    cases frames with\n"
        "    | nil => rfl\n"
        "    | cons frame tail =>\n"
        "        simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
        "  subst frames\n"
        "  cases originalCallbacks with\n"
        "  | nil => exact False.elim (callbacksNonempty rfl)\n"
        "  | cons originalCallback originalCallbacks =>\n"
        "    cases candidateCallbacks with\n"
        "    | nil => simp [WorldExternalCallbackRuntimesRelated] at callbacksRelated\n"
        "    | cons candidateCallback candidateCallbacks =>\n"
        "      simp only [WorldExternalCallbackRuntimesRelated] at callbacksRelated\n"
        "      simp only [WorldExternalCallbackContinuationFramesHold] at callbackFramesHold\n"
        "      rcases callbackFramesHold with\n"
        "        ⟨activeOffset, outerOffsets, transferredOuterOffsets, transferRules,\n"
        "          callbackControlAllowed, transferRulesFound, offsetsTransferred,\n"
        "          allCallbackFramesHold⟩\n"
        "      have callbackControl := callbackControlAllowed\n"
        "      simp [protocolCallbackTargets, ProtocolCallbackTargetProfile.Allows]\n"
        "        at callbackControl\n"
        "      rcases callbackControl with ⟨activeOffsetZero, returnInvariantTerminal⟩\n"
        "      subst activeOffset\n"
        "      have transferRulesIdentity := transferRulesFound\n"
        "      simp [protocolCallbackTargets,\n"
        "        ProtocolCallbackTargetProfile.transferRules?] at transferRulesIdentity\n"
        "      subst transferRules\n"
        "      simp only [WorldExternalCallbackFramesHold] at allCallbackFramesHold\n"
        "      rcases allCallbackFramesHold with\n"
        "        ⟨registeredCallback, originalCallbackTarget, candidateCallbackTarget,\n"
        "          callbackFrameValid, callbackFrameMemory, callbackArgumentsRelated,\n"
        "          activeFrameHolds, outerCallbackFramesHold⟩\n"
        f"      let returnClaim : ReturnPopClaim := {return_claim_row}\n"
        f"      let frameClaim : ReturnPopFrameClaim := {frame_claim_row}\n"
        "      have returnTargets := returnPopTargetsMixedRuntimeFrame_of_checked\n"
        f"        {original_behavior} {candidate_behavior} returnClaim frameClaim\n"
        "        (.externalCallback (RelationalExternalCallbackFrame.ofActions\n"
        "          originalCallback.suspension.siteId\n"
        "          originalCallback.suspension.eventIndex\n"
        "          originalCallback.suspension.phaseIndex\n"
        "          originalCallback.suspension.continuationTargetId\n"
        "          registeredCallback originalCallback.entry candidateCallback.entry))\n"
        "        originalState candidateState (by decide) (by decide)\n"
        "        activeFrameHolds callbackFrameMemory\n"
        f"      simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id},\n"
        "        NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq]\n"
        "        at returnTargets\n"
        "      have ordinaryRefinement :=\n"
        f"        acceptanceRunningNode{node_id}Refined{ordinary_arguments}\n"
        "      unfold RunningProductNodeStepRefined at ordinaryRefinement\n"
        f"      rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"        some relationalProductGraph.nodes[{node_id}] by decide),\n"
        "        sourceInvariant] at ordinaryRefinement\n"
        "      have ordinaryStep := ordinaryRefinement [] [] [] eventIndex world\n"
        "        originalState candidateState controlAllowed (by\n"
        "          simp [RelationalRuntimeCallStackHolds]) (by\n"
        "          simp [RelationalRuntimeCallImportsHold]) (by\n"
        "          simp [RelationalRuntimeCallTargetsMapped]) statesRelated\n"
        "      have ordinaryNext := ordinaryStep.2\n"
        "      unfold DecodedWorldProgram.transitionSystem at ordinaryNext\n"
        "      simp only [stepWorldExecution] at ordinaryNext\n"
        "      rw [sourceTarget] at ordinaryNext\n"
        f"      rw [originalWorldBehaviorNode{node_id}{behavior_rewrite_arguments},\n"
        f"        candidateWorldBehaviorNode{node_id}{candidate_behavior_rewrite_arguments}]\n"
        "        at ordinaryNext\n"
        "      simp [transitionFromWorldOutcome,\n"
        f"        acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id},\n"
        "        NormalizedOutcomeExpr.eval, WorldExecutionsRelated]\n"
        "        at ordinaryNext\n"
        "      have nextStatesRelated : StateRel staticProofContext world\n"
        "          terminalInvariant\n"
        f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
        "        by simpa [productInvariantTable] using ordinaryNext\n"
        f"      have originalWritesField : {original_behavior}.writes = [] := by decide\n"
        f"      have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
        f"      have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
        "        simp [originalWritesField, evalNormalizedWrites]\n"
        f"      have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
        "        simp [candidateWritesField, evalNormalizedWrites]\n"
        "      have originalMemory :\n"
        f"          (({original_behavior}.eval originalState).nextMachineState originalState).memory =\n"
        "            originalState.memory := by\n"
        "        change applyConcreteWrites originalState.memory\n"
        f"          ({original_behavior}.eval originalState).writes = originalState.memory\n"
        "        rw [originalWrites]\n"
        "        rfl\n"
        "      have candidateMemory :\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory =\n"
        "            candidateState.memory := by\n"
        "        change applyConcreteWrites candidateState.memory\n"
        f"          ({candidate_behavior}.eval candidateState).writes = candidateState.memory\n"
        "        rw [candidateWrites]\n"
        "        rfl\n"
        "      have transferRulesChecked :\n"
        f"          (protocolCallbackTargets.states[{profile_index}].outerFrameTransferRules.all\n"
        "            fun rule =>\n"
        f"              rule.checked {original_behavior} {candidate_behavior}) = true := by decide\n"
        "      have outerCallbackFramesNext :=\n"
        "        WorldExternalCallbackFramesHold.afterInternal staticProofContext world\n"
        f"          {original_behavior} {candidate_behavior}\n"
        f"          protocolCallbackTargets.states[{profile_index}].outerFrameTransferRules\n"
        "          originalState candidateState originalCallbacks candidateCallbacks\n"
        "          outerOffsets transferredOuterOffsets transferRulesChecked\n"
        "          offsetsTransferred originalMemory candidateMemory outerCallbackFramesHold\n"
        "      have callbackEntryRelated := callbacksRelated.1.2.1\n"
        "      have returnedSuspensionsRelated :=\n"
        "        WorldExternalSuspensionsRelated.afterCallbackReturn\n"
        "          staticProofContext externalCallSites originalCallback candidateCallback world\n"
        f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
        "          callbacksRelated.1.1 callbackEntryRelated.2.2.2.1\n"
        "          callbackArgumentsRelated (by\n"
        "            simpa [returnInvariantTerminal] using nextStatesRelated)\n"
        "      unfold DecodedWorldProgram.transitionSystem\n"
        "      simp only [stepWorldExecution]\n"
        f"      rw [originalWorldBehaviorNode{node_id}{behavior_rewrite_arguments},\n"
        f"        candidateWorldBehaviorNode{node_id}{candidate_behavior_rewrite_arguments}]\n"
        "      simp only [transitionFromWorldOutcome,\n"
        "        NormalizedSymbolicBehavior.eval_outcome,\n"
        f"        acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        "      rw [returnTargets.1, returnTargets.2]\n"
        "      simp [RelationalRuntimeFrame.originalReturnAddress,\n"
        "        RelationalRuntimeFrame.candidateReturnAddress,\n"
        "        RelationalExternalCallbackFrame.ofActions]\n"
        "      exact ⟨True.intro, returnedSuspensionsRelated, callbacksRelated.2,\n"
        "        ⟨transferredOuterOffsets, outerCallbackFramesNext⟩⟩"
    )
