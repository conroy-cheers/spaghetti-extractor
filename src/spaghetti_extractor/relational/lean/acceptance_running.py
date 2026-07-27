from __future__ import annotations

from typing import Any

from ...stage_binary import StageAInputError
from ..analyses.external import (
    _machine_import_call_contract_identity,
    _semantic_external_target_identity,
)
from .expressions import (
    _lean_external_target,
    _lean_frame_exact_stack_word_writes_claim,
    _lean_paired_prepared_word_writes_claim,
    _lean_register_offset_witness,
    _lean_register_output_claim,
    _lean_return_slot_offset_pair,
    _lean_semantic_expr,
    _lean_stack_window,
    _lean_stack_window_transfer_claim,
)
from .definitions import _normalized_behavior_fast_path
from .common import _lean_register_relation_pair

def _runtime_frame_protected_bytes(inventory: dict[str, Any]) -> int:
    protected_bytes = 4
    for word in inventory.get("exact_words", []):
        protected_bytes = max(
            protected_bytes,
            max(int(word["original"]), int(word["candidate"])) + 4,
        )
    return protected_bytes

def _lean_return_slot_offset_inventory(inventory: dict[str, Any]) -> str:
    exact_words = inventory.get("exact_words", [])
    exact_words_field = (
        ", exactWords := ["
        + ", ".join(
            "{ originalOffset := " + str(int(word["original"]))
            + ", candidateOffset := " + str(int(word["candidate"])) + " }"
            for word in exact_words
        )
        + "]"
        if exact_words else ""
    )
    preserved_imports = inventory.get("preserved_imports", [])
    preserved_imports_field = (
        ", preservedImports := ["
        + ", ".join(
            "{ original := ." + str(relation["original"])
            + ", candidate := ." + str(relation["candidate"])
            + ", imported := " + _lean_external_target(relation["import"])
            + " }"
            for relation in preserved_imports
        )
        + "]"
        if preserved_imports else ""
    )
    preserved_relations = inventory.get("preserved_relations", [])
    preserved_relations_field = (
        ", preservedRelations := ["
        + ", ".join(
            _lean_register_relation_pair(relation)
            for relation in preserved_relations
        )
        + "]"
        if preserved_relations else ""
    )
    return (
        "({ locations := ["
        + ", ".join(
            _lean_return_slot_offset_pair(location)
            for location in inventory["locations"]
        )
        + "]"
        + exact_words_field
        + preserved_imports_field
        + preserved_relations_field
        + " } : ReturnSlotOffsetInventory)"
    )

def _lean_return_slot_exact_word_transfer_claim(claim: dict[str, Any]) -> str:
    word = claim["word"]
    return (
        "{ word := { originalOffset := " + str(int(word["original"]))
        + ", candidateOffset := " + str(int(word["candidate"]))
        + " }, sourceBase := "
        + _lean_return_slot_offset_pair(claim["source_base"])
        + ", targetBase := "
        + _lean_return_slot_offset_pair(claim["target_base"])
        + ", transfer := "
        + _lean_return_slot_frame_transfer_claim(claim["transfer"])
        + " }"
    )

def _lean_external_return_slot_transfer_claim(claim: dict[str, Any]) -> str:
    internal = claim["internal_rule"]
    result = claim["result_rule"]
    memory = claim["memory_claim"]
    original_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["original_write_witnesses"]
    )
    candidate_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["candidate_write_witnesses"]
    )
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", internalTarget := "
        + _lean_return_slot_offset_pair(claim["internal_target"])
        + ", internalRule := { originalSourceRegister := ."
        + str(internal["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(internal["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(internal["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(internal["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(internal["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(internal["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(internal["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(internal["candidate_delta"]))
        + " }, resultRule := { source := "
        + _lean_return_slot_offset_pair(result["source"])
        + ", target := " + _lean_return_slot_offset_pair(result["target"])
        + ", originalDelta := " + str(int(result["original_delta"]))
        + ", candidateDelta := " + str(int(result["candidate_delta"]))
        + " }, memory := { offsets := "
        + _lean_return_slot_offset_pair(memory["offsets"])
        + f", originalWrites := [{original_writes}]"
        + f", candidateWrites := [{candidate_writes}] }} }}"
    )

def _lean_external_return_slot_inventory_transfer_claim(
    claim: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(claim["source"])
        + ", target := " + _lean_return_slot_offset_inventory(claim["target"])
        + ", transfers := ["
        + ", ".join(
            _lean_external_return_slot_transfer_claim(transfer)
            for transfer in claim["transfers"]
        )
        + "], exactWordTransfers := ["
        + ", ".join(
            _lean_return_slot_exact_word_transfer_claim(transfer)
            for transfer in claim.get("exact_word_transfers", [])
        )
        + "] }"
    )

def _lean_external_jump_return_slot_transfer_claim(
    claim: dict[str, Any],
) -> str:
    internal = claim["internal_rule"]
    result = claim["result_rule"]
    memory = claim["memory_claim"]
    original_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["original_write_witnesses"]
    )
    candidate_writes = ", ".join(
        _lean_register_offset_witness(witness)
        for witness in memory["candidate_write_witnesses"]
    )
    return (
        "{ source := " + _lean_return_slot_offset_pair(claim["source"])
        + ", internalTarget := "
        + _lean_return_slot_offset_pair(claim["internal_target"])
        + ", boundaryTarget := "
        + _lean_return_slot_offset_pair(claim["boundary_target"])
        + ", internalRule := { originalSourceRegister := ."
        + str(internal["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(internal["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(internal["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(internal["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(internal["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(internal["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(internal["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(internal["candidate_delta"]))
        + " }, resultRule := { source := "
        + _lean_return_slot_offset_pair(result["source"])
        + ", target := " + _lean_return_slot_offset_pair(result["target"])
        + ", originalDelta := " + str(int(result["original_delta"]))
        + ", candidateDelta := " + str(int(result["candidate_delta"]))
        + " }, memory := { offsets := "
        + _lean_return_slot_offset_pair(memory["offsets"])
        + f", originalWrites := [{original_writes}]"
        + f", candidateWrites := [{candidate_writes}] }} }}"
    )

def _lean_external_jump_return_slot_inventory_transfer_claim(
    claim: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(claim["source"])
        + ", target := " + _lean_return_slot_offset_inventory(claim["target"])
        + ", transfers := ["
        + ", ".join(
            _lean_external_jump_return_slot_transfer_claim(transfer)
            for transfer in claim["transfers"]
        )
        + "], exactWordTransfers := ["
        + ", ".join(
            _lean_return_slot_exact_word_transfer_claim(transfer)
            for transfer in claim.get("exact_word_transfers", [])
        )
        + "] }"
    )

def _lean_return_slot_frame_transfer_claim(claim: dict[str, Any]) -> str:
    transfer = claim["transfer"]
    memory = claim["memory"]
    if memory.get("profile", "affine_v1") == "affine_v1":
        original_writes = ", ".join(
            _lean_register_offset_witness(witness)
            for witness in memory["original_write_witnesses"]
        )
        candidate_writes = ", ".join(
            _lean_register_offset_witness(witness)
            for witness in memory["candidate_write_witnesses"]
        )
        memory_literal = (
            ".affine { offsets := "
            + _lean_return_slot_offset_pair(memory["offsets"])
            + f", originalWrites := [{original_writes}]"
            + f", candidateWrites := [{candidate_writes}] }}"
        )
    elif memory.get("profile") in {
        "stack_image_separated_v1", "protected_frame_span_v1",
    }:
        writes = []
        for witness in memory["writes"]:
            if witness["kind"] == "affine":
                writes.append(
                    ".affine "
                    + _lean_register_offset_witness(
                        witness["original_witness"]
                    )
                    + " "
                    + _lean_register_offset_witness(
                        witness["candidate_witness"]
                    )
                )
            elif witness["kind"] == "static_word":
                writes.append(f".staticWord {int(witness['slot_id'])}")
            else:
                raise StageAInputError(
                    "unsupported return-slot write witness "
                    f"{witness['kind']!r}"
                )
        if memory["profile"] == "stack_image_separated_v1":
            location = memory["location"]
            memory_literal = (
                ".framed { offsets := "
                + _lean_return_slot_offset_pair(memory["offsets"])
                + ", location := { window := "
                + _lean_stack_window(location["window"])
                + ", direction := ."
                + str(location["direction"])
                + ", amount := "
                + str(int(location["amount"]))
                + " }, writes := ["
                + ", ".join(writes)
                + "] }"
            )
        else:
            memory_literal = (
                ".protectedSpan { offsets := "
                + _lean_return_slot_offset_pair(memory["offsets"])
                + ", writes := [" + ", ".join(writes) + "] }"
            )
    else:
        raise StageAInputError(
            f"unsupported return-slot memory profile {memory.get('profile')!r}"
        )
    return (
        "{ transfer := { source := "
        + _lean_return_slot_offset_pair(transfer["source"])
        + ", target := " + _lean_return_slot_offset_pair(transfer["target"])
        + ", originalOutput := "
        + _lean_register_offset_witness(transfer["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(transfer["candidate_output_witness"])
        + " }, memory := " + memory_literal + " }"
    )

def _lean_return_slot_frame_inventory_transfer_claim(
    claim: dict[str, Any],
) -> str:
    return (
        "{ source := " + _lean_return_slot_offset_inventory(claim["source"])
        + ", target := " + _lean_return_slot_offset_inventory(claim["target"])
        + ", transfers := ["
        + ", ".join(
            _lean_return_slot_frame_transfer_claim(transfer)
            for transfer in claim["transfers"]
        )
        + "], exactWordTransfers := ["
        + ", ".join(
            _lean_return_slot_exact_word_transfer_claim(transfer)
            for transfer in claim.get("exact_word_transfers", [])
        )
        + "] }"
    )

def _lean_runtime_call_import_transfer_claim(
    source: dict[str, Any], target: dict[str, Any],
    carried_relations: list[dict[str, Any]] | None = None,
) -> str:
    carried_field = (
        ", carriedRelations := some ["
        + ", ".join(
            _lean_register_relation_pair(relation)
            for relation in carried_relations
        )
        + "]"
        if carried_relations is not None else ""
    )
    return (
        "{ source := " + _lean_return_slot_offset_inventory(source)
        + ", target := " + _lean_return_slot_offset_inventory(target)
        + carried_field
        + " }"
    )

def _lean_runtime_call_import_transfer_claims(
    claims: list[dict[str, Any]],
) -> str:
    return "[" + ", ".join(
        _lean_runtime_call_import_transfer_claim(
            claim["source"], claim["target"], claim.get("carried_relations")
        )
        for claim in claims
    ) + "]"

def _lean_acceptance_running_target(
    *, node_id: int, region_index: int, edge: dict[str, Any],
    frames: str = "[]", calls: str = "[]", frame_offsets: str = "[]",
    stack_targets_proof: str = "(by simp [RelationalRuntimeCallTargetsMapped])",
    target_control_proof: str = "(by decide)",
    frame_imports_proof: str = (
        "(by simp [RelationalRuntimeCallFactsHold, "
        "RelationalRuntimeCallImportsHold, RelationalRuntimeCallRelationsHold, "
        "ReturnSlotOffsetInventory.zero, ReturnSlotOffsetInventory.singleton, "
        "ReturnSlotOffsetInventory.preservedImportsHold, "
        "ReturnSlotOffsetInventory.preservedRelationsHold, "
        "importRegisterRelationsHold, registerRelationsHold])"
    ),
    observation_proof: str = "True.intro",
    world_equal_proof: str = "rfl",
    states_related_proof: str = "nextStatesRelated",
) -> str:
    target_node_id = int(edge["target_node_id"])
    target_region_index = int(edge["target_region_index"])
    target_target_id = int(edge["target_target_id"])
    return (
        f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
        f"      some region{target_region_index}.inputInvariant := by decide\n"
        f"  have targetNodeTarget : relationalProductGraph.nodes[{target_node_id}].targetId =\n"
        f"      {target_target_id} := by decide\n"
        f"  refine ⟨{observation_proof}, ?_⟩\n"
        f"  refine ⟨rfl, rfl, rfl, {world_equal_proof}, {target_node_id},\n"
        f"    relationalProductGraph.nodes[{target_node_id}],\n"
        f"    region{target_region_index}.inputInvariant, {frames}, {frame_offsets},\n"
        f"    (by decide), targetNodeTarget, ?_, targetInvariant, {target_control_proof},\n"
        f"    stackHoldsNext, {frame_imports_proof}, {stack_targets_proof}, "
        f"{states_related_proof}⟩\n"
        "  decide"
    )

def _lean_acceptance_running_node(
    step: dict[str, Any], regions: list[dict[str, Any]],
    behaviors: list[dict[str, Any]], *,
    parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    running = f"acceptanceRunningNode{node_id}Refined"
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
    acceptance_environment = (
        step.get("kind") == "external_call"
        or bool(step.get("opaque_lockstep_profile"))
        or "opaque_lockstep_site_id" in step
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        + (
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            if acceptance_environment else
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        )
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
    prefix = (
        f"theorem {running}\n"
        + environment_binders
        + ("    " if parameterized_environment else "    :\n")
        + "    RunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      productControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold RunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls frameOffsets eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds frameImportsHold stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [ProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
    )
    if step["kind"] == "control_unrepresented":
        return (
            prefix
            + "  have stateMember :\n"
            "      (show ProductControlState from\n"
            f"        {{ nodeId := {node_id}, calls := calls, "
            "frameOffsets := frameOffsets }) \u2208\n"
            "        productControlProfile.states :=\n"
            "    List.contains_iff_mem.mp controlMember.2\n"
            "  have stateAbsent :\n"
            "      (show ProductControlState from\n"
            f"        {{ nodeId := {node_id}, calls := calls, "
            "frameOffsets := frameOffsets }) \u2209\n"
            "        productControlProfile.states := by\n"
            "    simp [productControlProfile]\n"
            "  exact False.elim (stateAbsent stateMember)\n"
        )
    prefix += (
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}{behavior_rewrite_arguments}, "
        f"candidateWorldBehaviorNode{node_id}{candidate_behavior_rewrite_arguments}]\n"
    )
    if step.get("certificate_profile") != (
        "composable_x87_state_only_singleton_v1"
    ):
        prefix += (
            "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome, "
            "NormalizedSymbolicBehavior.eval_outcome,\n"
            f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
            f"    acceptanceCandidateNormalizedOutcome{node_id}, "
            "NormalizedOutcomeExpr.eval]\n"
        )
    empty_control = (
        "  have controlShape : calls = [] ∧ frameOffsets = [] := by\n"
        "    simpa [productControlProfile] using controlMember.2\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
        "  have framesEmpty : frames = [] := by\n"
        "    cases frames with\n"
        "    | nil => rfl\n"
        "    | cons frame tail =>\n"
        "        simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
        "  subst frames\n"
    )
    control_cases = step.get("cases")
    if control_cases is not None and step["kind"] != "return":
        if not control_cases:
            raise StageAInputError(
                f"acceptance node {node_id} has an empty control-case inventory"
            )
        case_shapes: list[str] = []
        case_bodies: list[str] = []
        for case_index, control_case in enumerate(control_cases):
            control_state = control_case["control_state"]
            calls_literal = "[" + ", ".join(
                str(int(item)) for item in control_state["calls"]
            ) + "]"
            offsets_literal = "[" + ", ".join(
                _lean_return_slot_offset_inventory(item)
                for item in control_state["frame_offsets"]
            ) + "]"
            case_shapes.append(
                f"(calls = {calls_literal} ∧ frameOffsets = {offsets_literal})"
            )
            case_step = {
                **step,
                **control_case,
                "control_already_selected": True,
            }
            case_step.pop("cases", None)
            case_source = _lean_acceptance_running_node(
                case_step,
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
            if not case_source.startswith(prefix):
                raise StageAInputError(
                    f"control case {case_index} did not share its node theorem prefix"
                )
            case_body = case_source[len(prefix):]
            case_bodies.append("\n".join(
                "  " + line for line in case_body.splitlines()
            ))
        return (
            prefix
            + "  have controlShape : "
            + " ∨\n      ".join(case_shapes)
            + " := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with "
            + " | ".join(
                f"controlCase{case_index}"
                for case_index in range(len(control_cases))
            )
            + "\n"
            + "\n".join(
                f"  · rcases controlCase{case_index} with ⟨rfl, rfl⟩\n"
                + case_body
                for case_index, case_body in enumerate(case_bodies)
            )
        )
    if step["kind"] == "call":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        continuation_target_id = int(edge["target_target_id"])
        target_region_index = int(edge["target_region_index"])
        continuation = int(step["continuation_target_id"])
        claim = step["call_push_claim"]
        original_return = int(claim["original_return_address"])
        candidate_return = int(claim["candidate_return_address"])
        stack_amount = int(step["stack_amount"])
        stack_amount_twos_complement = 2**32 - stack_amount
        source_window = _lean_stack_window(step["source_stack_window"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        source_calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        frame_claims = step["return_slot_frame_transfer_claims"]
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            frame_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        seeded_frame_inventory_literal = _lean_return_slot_offset_inventory(
            step["seeded_frame_inventory"]
        )
        protected_bytes = _runtime_frame_protected_bytes(
            step["seeded_frame_inventory"]
        )
        seeded_register_output_claims_literal = ", ".join(
            _lean_register_output_claim(claim)
            for claim in step.get("seeded_register_output_claims", [])
        )
        continuation_node_id = int(step["continuation_node_id"])
        combined_stack_writes = (
            step.get("certificate_profile")
            == "composable_direct_call_stack_writes_v1"
        )
        combined_prepared_writes = (
            step.get("certificate_profile")
            == "composable_direct_call_prepared_writes_v1"
        )
        known_indirect_call = bool(step.get("known_indirect_call"))
        combined_prefix_writes = combined_stack_writes or combined_prepared_writes
        writes_claim_name = (
            f"segmentRefinementEdge{edge_id}DirectCallPreparedWritesClaim"
            if combined_prepared_writes
            else f"segmentRefinementEdge{edge_id}DirectCallStackWritesClaim"
        )
        if known_indirect_call:
            segment_original_behavior = f"productNode{node_id}OriginalNormalized"
            segment_candidate_behavior = f"productNode{node_id}CandidateNormalized"
        elif _normalized_behavior_fast_path(
            regions[region_index], behaviors[region_index]
        ):
            segment_original_behavior = f"region{region_index}NormalizedBehavior"
            segment_candidate_behavior = f"region{region_index}NormalizedBehavior"
        else:
            segment_original_behavior = (
                f"segmentRefinementEdge{edge_id}OriginalNormalizedBehavior"
            )
            segment_candidate_behavior = (
                f"segmentRefinementEdge{edge_id}CandidateNormalizedBehavior"
            )
        exact_word_seed_claims = step.get("exact_word_seed_claims", [])
        seeded_exact_words = step["seeded_frame_inventory"].get(
            "exact_words", []
        )
        if len(exact_word_seed_claims) != len(seeded_exact_words):
            raise StageAInputError(
                f"call edge {edge_id} has mismatched exact-word seed and "
                "runtime-frame inventories"
            )
        if exact_word_seed_claims and not combined_prefix_writes:
            raise StageAInputError(
                f"call edge {edge_id} seeds exact words without a checked "
                "direct-call prepared-write certificate"
            )
        exact_seed_names = [
            f"segmentRefinementEdge{edge_id}DirectCallExactWordSeed{index}"
            for index in range(len(exact_word_seed_claims))
        ]
        exact_seed_type = (
            "DirectCallPreparedExactWordSeedClaim"
            if combined_prepared_writes else "DirectCallStackExactWordSeedClaim"
        )
        if not exact_seed_names:
            active_frame_exact_words = (
                "  have activeFrameExactWords : "
                "activeFrameInventory.boundedExactWordsHold runtimeFrame\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState).memory\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState).memory := by\n"
                "    simp [activeFrameInventory, runtimeFrame, "
                "ReturnSlotOffsetInventory.boundedExactWordsHold, "
                "ReturnSlotOffsetInventory.exactWordsFit, "
                "ReturnSlotOffsetInventory.exactWordsHold]\n"
            )
        else:
            word_cases = " ∨ ".join(
                f"word = {name}.exactWord" for name in exact_seed_names
            )

            def exact_seed_proof(name: str, *, bullet: bool) -> str:
                prefix = "      · " if bullet else "      "
                continuation_prefix = "        " if bullet else "      "
                return (
                    prefix + "have seededWordHolds :=\n"
                    + continuation_prefix
                    + (
                        "  DirectCallPreparedExactWordSeedClaim.holds_of_checked\n"
                        if combined_prepared_writes else
                        "  DirectCallStackExactWordSeedClaim.holds_of_checked\n"
                    )
                    + continuation_prefix
                    + f"    staticProofContext world region{region_index}.inputInvariant\n"
                    + continuation_prefix
                    + f"    {segment_original_behavior} {segment_candidate_behavior}\n"
                    + continuation_prefix
                    + f"    {writes_claim_name} {name} originalState candidateState\n"
                    + continuation_prefix
                    + (
                        "    (by decide) (by decide) statesRelated\n"
                        if combined_prepared_writes else
                        "    (by decide) (by decide) (by decide) statesRelated\n"
                    )
                    + continuation_prefix
                    + "simpa [runtimeFrame, sourceWindow,\n"
                    + continuation_prefix
                    + f"  {writes_claim_name}, "
                    + (
                        "DirectCallPreparedWritesClaim.runtimeFrame,\n"
                        if combined_prepared_writes else
                        "DirectCallStackWritesClaim.runtimeFrame,\n"
                    )
                    + continuation_prefix
                    + "  originalBehaviorSegment, candidateBehaviorSegment]\n"
                    + continuation_prefix
                    + "using seededWordHolds\n"
                )

            if len(exact_seed_names) == 1:
                exact_cases = (
                    "      subst word\n"
                    + exact_seed_proof(exact_seed_names[0], bullet=False)
                )
            else:
                exact_cases = (
                    "      rcases wordCases with "
                    + " | ".join("rfl" for _ in exact_seed_names)
                    + "\n"
                    + "".join(
                        exact_seed_proof(name, bullet=True)
                        for name in exact_seed_names
                    )
                )
            active_frame_exact_words = (
                "  have activeFrameExactWords : "
                "activeFrameInventory.boundedExactWordsHold runtimeFrame\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState).memory\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState).memory := by\n"
                "    constructor\n"
                "    · simp [activeFrameInventory, runtimeFrame, "
                "ReturnSlotOffsetInventory.exactWordsFit]\n"
                "    · intro word wordMember\n"
                f"      have wordCases : {word_cases} := by\n"
                "        simpa [activeFrameInventory, "
                + ", ".join(exact_seed_names)
                + "] using wordMember\n"
                + exact_cases
            )
        known_indirect_setup = ""
        known_indirect_dispatch = ""
        if known_indirect_call:
            decoded_control = step["decoded_control"]
            indirect_target_id = int(edge["target_target_id"])
            target_closed = f"productNode{node_id}ImmutableIndirectCallClosed"
            known_indirect_setup = (
                f"  rcases {target_closed} world originalState candidateState "
                "statesRelated with\n"
                "    ⟨originalTarget, candidateTarget, originalOutcome, "
                "candidateOutcome, originalTargetMatches, "
                "candidateTargetMatches⟩\n"
                "  have originalTargetExpression :\n"
                f"      ({_lean_semantic_expr(decoded_control['original_target_expression'])}).eval "
                "originalState = originalTarget := by\n"
                "    have normalizedOutcome := originalOutcome\n"
                "    rw [← originalBehaviorSegment] at normalizedOutcome\n"
                f"    simp only [acceptanceOriginalNormalizedOutcome{node_id}, "
                "NormalizedOutcomeExpr.eval, PureOutcome.indirectCall.injEq] "
                "at normalizedOutcome\n"
                "    exact normalizedOutcome.1\n"
                "  have candidateTargetExpression :\n"
                f"      ({_lean_semantic_expr(decoded_control['candidate_target_expression'])}).eval "
                "candidateState = candidateTarget := by\n"
                "    have normalizedOutcome := candidateOutcome\n"
                "    rw [← candidateBehaviorSegment] at normalizedOutcome\n"
                f"    simp only [acceptanceCandidateNormalizedOutcome{node_id}, "
                "NormalizedOutcomeExpr.eval, PureOutcome.indirectCall.injEq] "
                "at normalizedOutcome\n"
                "    exact normalizedOutcome.1\n"
                "  have originalTargetResolved :\n"
                "      staticProofContext.codeMap.resolveRawEip false\n"
                "        staticProofContext.originalPe.imageBase originalTarget =\n"
                f"      some {indirect_target_id} := by\n"
                "    exact StaticCodeMap.resolveRawEip_of_codeAddressMatchesAt false\n"
                "      staticProofContext.originalPe staticProofContext.candidatePe\n"
                "      staticProofContext.codeMap\n"
                "      (StaticProofContext.codeMapIndexed_of_structurallyValid\n"
                "        staticProofContext staticProofContextChecked)\n"
                f"      {indirect_target_id} originalTarget "
                "(by simpa using originalTargetMatches)\n"
                "  have candidateTargetResolved :\n"
                "      staticProofContext.codeMap.resolveRawEip true\n"
                "        staticProofContext.candidatePe.imageBase candidateTarget =\n"
                f"      some {indirect_target_id} := by\n"
                "    exact StaticCodeMap.resolveRawEip_of_codeAddressMatchesAt true\n"
                "      staticProofContext.originalPe staticProofContext.candidatePe\n"
                "      staticProofContext.codeMap\n"
                "      (StaticProofContext.codeMapIndexed_of_structurallyValid\n"
                "        staticProofContext staticProofContextChecked)\n"
                f"      {indirect_target_id} candidateTarget "
                "(by simpa using candidateTargetMatches)\n"
            )
            known_indirect_dispatch = (
                "  rw [originalTargetExpression, candidateTargetExpression]\n"
                "  simp only [originalWorldProgram, candidateWorldProgram,\n"
                "    Bool.false_eq_true, if_false, if_true]\n"
                "  rw [originalTargetResolved, candidateTargetResolved]\n"
                "  simp only\n"
            )
        frame_memory_body = (
            (
                "    exact pairedStackWordFinalWriteReadsBack_amount "
                "staticProofContext world\n"
                if combined_prefix_writes else
                "    exact pairedStackWordWriteReadsBack_amount "
                "staticProofContext world\n"
            )
            + f"      region{region_index}.inputInvariant sourceWindow "
            + f"{stack_amount}\n"
            + f"      (BitVec.ofNat 32 {original_return}) "
            + f"(BitVec.ofNat 32 {candidate_return})\n"
            + (
                f"      ({writes_claim_name}.preparedWrites.originalWrites "
                "originalState)\n"
                f"      ({writes_claim_name}.preparedWrites.candidateWrites "
                "candidateState)\n"
                if combined_prepared_writes else
                f"      ({writes_claim_name}.stackWrites.originalWrites "
                "originalState)\n"
                f"      ({writes_claim_name}.stackWrites.candidateWrites "
                "candidateState)\n"
                if combined_stack_writes else ""
            )
            + "      originalState candidateState\n"
            + f"      ({original_behavior}.eval originalState)\n"
            + f"      ({candidate_behavior}.eval candidateState)\n"
            + "      (by simp) (by simp) statesRelated\n"
            + "      (by decide) (by decide) (by decide) (by decide)\n"
            + "      (by simp [sourceWindow,\n"
            + f"        acceptanceOriginalNormalizedWrites{node_id},\n"
            + f"        originalBehavior{region_index}, evalNormalizedWrites, "
            + "Expr.eval,\n"
            + (
                f"        {writes_claim_name}, "
                "DirectCallPreparedWritesClaim.originalWrites,\n"
                "        PairedPreparedWordWritesClaim.originalWrites,\n"
                "        PairedPreparedWordWriteItem.originalAddress, "
                "PairedPreparedWordWriteItem.value, pairedStackWordAddress,\n"
                if combined_prepared_writes else
                f"        {writes_claim_name}, "
                "DirectCallStackWritesClaim.originalWrites,\n"
                "        PairedStackWordWritesClaim.originalWrites,\n"
                "        PairedStackWordWriteItem.originalAddress, "
                "pairedStackWordAddress,\n"
                if combined_stack_writes else ""
            )
            + "        stackAddressRewrite])\n"
            + "      (by simp [sourceWindow,\n"
            + f"        acceptanceCandidateNormalizedWrites{node_id},\n"
            + f"        candidateBehavior{region_index}, evalNormalizedWrites, "
            + "Expr.eval,\n"
            + (
                f"        {writes_claim_name}, "
                "DirectCallPreparedWritesClaim.candidateWrites,\n"
                "        PairedPreparedWordWritesClaim.candidateWrites,\n"
                "        PairedPreparedWordWriteItem.candidateAddress, "
                "PairedPreparedWordWriteItem.value, pairedStackWordAddress,\n"
                if combined_prepared_writes else
                f"        {writes_claim_name}, "
                "DirectCallStackWritesClaim.candidateWrites,\n"
                "        PairedStackWordWritesClaim.candidateWrites,\n"
                "        PairedStackWordWriteItem.candidateAddress, "
                "pairedStackWordAddress,\n"
                if combined_stack_writes else ""
            )
            + "        stackAddressRewrite])\n"
        )
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {source_calls_literal} \u2227\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + f"  let outerFrameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
            f"  let outerFrameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"    {frame_import_claims_literal}\n"
            f"  let activeFrameInventory : ReturnSlotOffsetInventory :=\n"
            f"    {seeded_frame_inventory_literal}\n"
            + f"  let sourceWindow : StackWindowPair := {source_window}\n"
            f"  have stackAddressRewrite (value : Word) :\n"
            f"      value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
            f"        value - BitVec.ofNat 32 {stack_amount} := by\n"
            f"    exact word_add_ia32_twos_complement value {stack_amount} "
            "(by decide)\n"
            f"  have originalBehaviorSegment : {original_behavior} =\n"
            f"      {segment_original_behavior} := by decide\n"
            f"  have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"      {segment_candidate_behavior} := by decide\n"
            + known_indirect_setup
            + "  let runtimeFrame : RelationalRuntimeCallFrame := {\n"
            f"    continuationTargetId := {continuation}\n"
            f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    originalStackAddress := originalState.registers.get\n"
            f"      sourceWindow.originalRegister - BitVec.ofNat 32 {stack_amount}\n"
            "    candidateStackAddress := candidateState.registers.get\n"
            f"      sourceWindow.candidateRegister - BitVec.ofNat 32 {stack_amount}\n"
            f"    protectedBytes := {protected_bytes}\n"
            "  }\n"
            f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            f"      region{target_region_index}.inputInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState) := by\n"
            "    rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "    exact transitioned.2.2.2\n"
            "  have frameMemory : runtimeFrame.memoryHolds\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).memory\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).memory := by\n"
            "    unfold RelationalRuntimeCallFrame.memoryHolds runtimeFrame\n"
            + frame_memory_body
            + "  have frameOffsetsHold : ReturnSlotOffsetPair.zero.holds runtimeFrame\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    simp [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds, runtimeFrame,\n"
            "      sourceWindow,\n"
            f"      acceptanceOriginalNormalizedRegisters{node_id},\n"
            f"      acceptanceCandidateNormalizedRegisters{node_id},\n"
            f"      originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "      evalNormalizedRegisters, evalNormalizedRegisters_get,\n"
            "      StageA.Formal.Registers.get, Expr.eval,\n"
            "      stackAddressRewrite]\n"
            "  have sourceWindows := StateRel.stackWindowsHold staticProofContext world\n"
            f"    region{region_index}.inputInvariant originalState candidateState statesRelated\n"
            "  simp only [stackWindowsRelated, List.all_eq_true] at sourceWindows\n"
            "  have sourceWindowHolds : sourceWindow.holds world originalState.registers\n"
            "      candidateState.registers = true := by\n"
            "    exact sourceWindows sourceWindow (by decide)\n"
            "  have frameProtected : runtimeFrame.protectedSpanValid\n"
            "      staticProofContext = true := by\n"
            "    exact RelationalRuntimeCallFrame.protectedSpanValid_of_window_call\n"
            "      staticProofContext world sourceWindow originalState.registers\n"
            "      candidateState.registers runtimeFrame " + str(stack_amount) + "\n"
            "      (StateRel.stackRangesValid staticProofContext world\n"
            f"        region{region_index}.inputInvariant originalState candidateState\n"
            "        statesRelated) sourceWindowHolds (by decide) (by decide)\n"
            "      (by simp [runtimeFrame]) (by simp [runtimeFrame, sourceWindow])\n"
            "      (by simp [runtimeFrame]) (by simp [runtimeFrame])\n"
            "  have frameValid : runtimeFrame.valid staticProofContext = true := by\n"
            "    unfold RelationalRuntimeCallFrame.valid\n"
            "    simp only [Bool.and_eq_true]\n"
            "    constructor\n"
            "    · change RelationalCallFrame.valid staticProofContext {\n"
            f"      continuationTargetId := {continuation}\n"
            f"      originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"      candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "      } = true\n"
            "      decide\n"
            "    · exact frameProtected\n"
            "  have frameResolves : runtimeFrame.toRelationalCallFrame.resolves\n"
            "      staticProofContext = true := by\n"
            "    change RelationalCallFrame.resolves staticProofContext {\n"
            f"      continuationTargetId := {continuation}\n"
            f"      originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
            f"      candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
            "    } = true\n"
            "    decide\n"
            "  have outerStackHolds : RelationalRuntimeCallStackHolds\n"
            "      staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) frames {source_calls_literal}\n"
            f"      {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      {original_behavior} {candidate_behavior}\n"
            f"      outerFrameClaims frames {source_calls_literal} originalState\n"
            "      candidateState (by decide)\n"
            "      (by simpa [outerFrameClaims] using stackHolds) statesRelated\n"
            "  have outerFrameFactsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      {target_offsets_literal}\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"      {original_behavior} {candidate_behavior} outerFrameImportClaims\n"
            "      originalState candidateState (by decide)\n"
            "      (by simpa [outerFrameImportClaims] using frameImportsHold)\n"
            "  have activeFrameInventoryHolds : activeFrameInventory.holds runtimeFrame\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    refine And.intro (by decide) ?_\n"
            "    intro location locationMember\n"
            "    have locationExact : location = ReturnSlotOffsetPair.zero := by\n"
            "      simpa [activeFrameInventory] using locationMember\n"
            "    subst location\n"
            "    exact frameOffsetsHold\n"
            + active_frame_exact_words
            + "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) (runtimeFrame :: frames)\n"
            f"      ({continuation} :: {source_calls_literal})\n"
            f"      (activeFrameInventory :: {target_offsets_literal}) := by\n"
            "    simp only [RelationalRuntimeCallStackHolds]\n"
            "    exact ⟨rfl, frameValid, frameResolves, frameMemory,\n"
            "      activeFrameInventoryHolds,\n"
            "      activeFrameExactWords,\n"
            "      outerStackHolds⟩\n"
            "  have activeFrameImportSeedChecked :\n"
            "      activeFrameInventory.seedsPreservedImportsFrom\n"
            f"        region{region_index}.inputInvariant {original_behavior}\n"
            f"        {candidate_behavior} = true := by decide\n"
            "  have activeFrameImportsNext : activeFrameInventory.preservedImportsHold\n"
            "      world\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    exact ReturnSlotOffsetInventory."
            "preservedImportsHold_after_stateRel_of_checked\n"
            f"      staticProofContext activeFrameInventory world\n"
            f"      region{region_index}.inputInvariant {original_behavior}\n"
            f"      {candidate_behavior} originalState candidateState\n"
            "      activeFrameImportSeedChecked statesRelated\n"
            "  let activeFrameRegisterClaims : List "
            "InvariantWP.RegisterOutputClaim := ["
            + seeded_register_output_claims_literal
            + "]\n"
            "  have activeFrameRelationSeedChecked :\n"
            "      activeFrameInventory.seedsPreservedRelationsFromOutputClaims\n"
            f"        staticProofContext region{region_index} {original_behavior}\n"
            f"        {candidate_behavior} activeFrameRegisterClaims = true := by decide\n"
            "  have activeFrameRelationsNext :\n"
            "      activeFrameInventory.preservedRelationsHold staticProofContext world\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    exact ReturnSlotOffsetInventory."
            "preservedRelationsHold_after_stateRel_of_outputClaims\n"
            "      staticProofContext activeFrameInventory world\n"
            f"      region{region_index} {original_behavior} {candidate_behavior}\n"
            "      activeFrameRegisterClaims originalState candidateState\n"
            "      activeFrameRelationSeedChecked statesRelated\n"
            "  have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      (activeFrameInventory :: {target_offsets_literal})\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.cons staticProofContext world\n"
            "      activeFrameInventory _ _ _ activeFrameImportsNext\n"
            "      activeFrameRelationsNext outerFrameFactsNext\n"
            + known_indirect_dispatch
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="runtimeFrame :: frames",
                calls=f"{continuation} :: {source_calls_literal}",
                frame_offsets=(
                    "activeFrameInventory :: " + target_offsets_literal
                ),
                stack_targets_proof=(
                    "(by simp only [RelationalRuntimeCallTargetsMapped]; "
                    f"exact ⟨⟨{continuation_node_id}, "
                    f"relationalProductGraph.nodes[{continuation_node_id}], "
                    "by decide, by decide⟩, stackTargetsReachable⟩)"
                ),
                frame_imports_proof="frameImportsNext",
            )
        )
    if step["kind"] == "return":
        return_cases = step.get("cases")
        if return_cases is None:
            return _lean_acceptance_running_node(
                {**step, "kind": "return_case"},
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
        if len(return_cases) == 1:
            selected_return = {
                **step,
                **return_cases[0],
                "kind": "return_case",
            }
            selected_return.pop("cases", None)
            return _lean_acceptance_running_node(
                selected_return,
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
        case_shapes = []
        case_bodies = []
        for case_index, return_case in enumerate(return_cases):
            calls_literal = "[" + ", ".join(
                str(int(item))
                for item in return_case["control_state"]["calls"]
            ) + "]"
            offsets_literal = "[" + ", ".join(
                _lean_return_slot_offset_inventory(item)
                for item in return_case["control_state"]["frame_offsets"]
            ) + "]"
            case_shapes.append(
                f"(calls = {calls_literal} ∧ frameOffsets = {offsets_literal})"
            )
            selected_return = {
                **step,
                **return_case,
                "kind": "return_case",
                "control_already_selected": True,
            }
            selected_return.pop("cases", None)
            case_source = _lean_acceptance_running_node(
                selected_return,
                regions,
                behaviors,
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
            if not case_source.startswith(prefix):
                raise StageAInputError(
                    f"return case {case_index} did not share its node theorem prefix"
                )
            body = case_source[len(prefix):]
            case_bodies.append("\n".join(
                "  " + line for line in body.splitlines()
            ))
        return (
            prefix
            + "  have controlShape : "
            + " ∨\n      ".join(case_shapes)
            + " := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with "
            + " | ".join(
                f"controlCase{case_index}"
                for case_index in range(len(return_cases))
            )
            + "\n"
            + "\n".join(
                f"  · rcases controlCase{case_index} with ⟨rfl, rfl⟩\n"
                + case_body
                for case_index, case_body in enumerate(case_bodies)
            )
        )
    if step["kind"] == "return_case":
        continuation = int(step["target_target_id"])
        target_node_id = int(step["target_node_id"])
        target_region_index = int(step["target_region_index"])
        return_claim = step["return_pop_claim"]
        frame_claim = step["return_frame_claim"]
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
        frame_offsets = _lean_return_slot_offset_pair(frame_claim["offsets"])
        typed_frame_offsets = f"({frame_offsets} : ReturnSlotOffsetPair)"
        frame_inventory = _lean_return_slot_offset_inventory(
            step["return_frame_inventory"]
        )
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        source_calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        target_calls = [
            int(item) for item in step["target_control_state"]["calls"]
        ]
        target_calls_literal = "[" + ", ".join(
            str(item) for item in target_calls
        ) + "]"
        outer_frame_claims = step["return_slot_frame_transfer_claims"]
        outer_frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in outer_frame_claims
        ) + "]"
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in outer_frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims([
            {
                "source": step["return_frame_inventory"],
                "target": step["return_frame_inventory"],
            },
            *outer_frame_claims,
        ])
        output_claims = ", ".join(
            _lean_register_output_claim(claim) for claim in step["output_claims"]
        )
        active_frame_relations_literal = ", ".join(
            _lean_register_relation_pair(relation)
            for relation in step.get("active_frame_relations", [])
        )
        residual_target_relations_literal = ", ".join(
            _lean_register_relation_pair(relation)
            for relation in step.get(
                "residual_target_register_relations", []
            )
        )
        stack_transfers = ", ".join(
            _lean_stack_window_transfer_claim(claim)
            for claim in step["stack_window_transfers"]
        )
        import_claim_rows: list[str] = []
        import_fact_rows: list[str] = []
        import_fact_names: list[str] = []
        import_claim_names: list[str] = []
        for claim_index, claim in enumerate(step["import_transfer_claims"]):
            if claim.get("kind") != "preserve":
                raise StageAInputError(
                    "whole-program return import transfer requires an existing "
                    "source import relation"
                )
            claim_name = f"returnImportClaim{node_id}_{claim_index}"
            fact_name = f"returnImportFact{node_id}_{claim_index}"
            import_claim_names.append(claim_name)
            import_fact_names.append(fact_name)
            import_claim_rows.append(
                f"    let {claim_name} : ImportRegisterPreserveClaim := {{\n"
                f"      imported := {_lean_external_target(claim['import'])}\n"
                f"      sourceOriginalRegister := .{claim['source_original_register']}\n"
                f"      sourceCandidateRegister := .{claim['source_candidate_register']}\n"
                f"      targetOriginalRegister := .{claim['target_original_register']}\n"
                f"      targetCandidateRegister := .{claim['target_candidate_register']}\n"
                "    }"
            )
            import_fact_rows.append(
                f"    have {fact_name} := "
                "importRegisterPreserveOutputHolds_of_checked\n"
                f"      staticProofContext world region{region_index}.inputInvariant\n"
                f"      region{target_region_index}.inputInvariant {original_behavior}\n"
                f"      {candidate_behavior} {claim_name} (by decide)\n"
                "      originalState candidateState relatedForTransfer"
            )
        import_fact_setup = "\n".join([*import_claim_rows, *import_fact_rows])
        if import_fact_setup:
            import_fact_setup += "\n"
        import_output_proof = (
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simpa [activeFrameInventory,\n"
            "        ReturnSlotOffsetInventory.preservedImportsHold,\n"
            f"        RegionRelation.inputInvariant, region{target_region_index}] using\n"
            "        activeFrameImportsNext\n"
            if step["active_frame_imports"] else
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simpa [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        importRegisterRelationsHold, "
            "ImportRegisterPreserveClaim.targetRelation,\n"
            + "        " + ", ".join(import_claim_names) + "] using "
            + (
                import_fact_names[0]
                if len(import_fact_names) == 1
                else "⟨" + ", ".join(import_fact_names) + "⟩"
            )
            + "\n"
            if import_fact_names else
            "    have outputImports : importRegisterRelationsHold world\n"
            f"        region{target_region_index}.inputInvariant.importRegisterRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        importRegisterRelationsHold]\n"
        )
        target_edge = {
            "target_node_id": target_node_id,
            "target_region_index": target_region_index,
            "target_target_id": continuation,
        }
        paired_writes_claim = step.get("paired_prepared_writes_claim")
        frame_exact_writes_claim = step.get("frame_exact_stack_writes_claim")
        if isinstance(paired_writes_claim, dict):
            paired_writes_literal = _lean_paired_prepared_word_writes_claim(
                paired_writes_claim
            )
            memory_transition = (
                "    let pairedWritesClaim : PairedPreparedWordWritesClaim := "
                + paired_writes_literal + "\n"
                f"    have originalWritesField : {original_behavior}.writes =\n"
                "        pairedWritesClaim.originalSymbolicWrites := by decide\n"
                f"    have candidateWritesField : {candidate_behavior}.writes =\n"
                "        pairedWritesClaim.candidateSymbolicWrites := by decide\n"
                f"    have originalWrites : ({original_behavior}.eval originalState).writes =\n"
                "        pairedWritesClaim.originalWrites originalState := by\n"
                "      simp [originalWritesField, evalNormalizedWrites,\n"
                "        PairedPreparedWordWritesClaim.originalSymbolicWrites,\n"
                "        PairedPreparedWordWritesClaim.originalWrites]\n"
                f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes =\n"
                "        pairedWritesClaim.candidateWrites candidateState := by\n"
                "      simp [candidateWritesField, evalNormalizedWrites,\n"
                "        PairedPreparedWordWritesClaim.candidateSymbolicWrites,\n"
                "        PairedPreparedWordWritesClaim.candidateWrites]\n"
                "    have nextStatesRelated : StateRel staticProofContext world\n"
                f"        region{target_region_index}.inputInvariant\n"
                f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
                "      StateRel.afterPairedPreparedWordWritesEvaluation\n"
                "        staticProofContext world\n"
                f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
                f"        originalState candidateState ({original_behavior}.eval originalState)\n"
                f"        ({candidate_behavior}.eval candidateState) pairedWritesClaim\n"
                "        staticProofContextChecked relatedForTransfer (by decide)\n"
                "        originalWrites candidateWrites (by simp) (by simp)\n"
                "        outputRegisters outputBounds outputSeparations\n"
                "        outputStackWindows outputX87 outputFlags outputImports\n"
                "        outputDynamic outputDynamicStack\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          pairedStatePredicatesHold])\n"
            )
        elif isinstance(frame_exact_writes_claim, dict):
            frame_exact_writes_literal = _lean_frame_exact_stack_word_writes_claim(
                frame_exact_writes_claim
            )
            memory_transition = (
                "    let frameExactWritesClaim : FrameExactStackWordWritesClaim := "
                + frame_exact_writes_literal + "\n"
                f"    have originalWritesField : {original_behavior}.writes =\n"
                "        frameExactWritesClaim.originalSymbolicWrites := by decide\n"
                f"    have candidateWritesField : {candidate_behavior}.writes =\n"
                "        frameExactWritesClaim.candidateSymbolicWrites := by decide\n"
                f"    have originalWrites : ({original_behavior}.eval originalState).writes =\n"
                "        frameExactWritesClaim.originalWrites originalState := by\n"
                "      simp [originalWritesField, evalNormalizedWrites,\n"
                "        FrameExactStackWordWritesClaim.originalSymbolicWrites,\n"
                "        FrameExactStackWordWritesClaim.originalWrites]\n"
                f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes =\n"
                "        frameExactWritesClaim.candidateWrites candidateState := by\n"
                "      simp [candidateWritesField, evalNormalizedWrites,\n"
                "        FrameExactStackWordWritesClaim.candidateSymbolicWrites,\n"
                "        FrameExactStackWordWritesClaim.candidateWrites]\n"
                "    have activeFrameExactWords : activeFrameInventory.exactWordsHold frame\n"
                "        originalState.memory candidateState.memory := by\n"
                "      simpa [activeFrameInventory] using stackHolds.2.2.2.2.2.1.2\n"
                "    have nextStatesRelated : StateRel staticProofContext world\n"
                f"        region{target_region_index}.inputInvariant\n"
                f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
                "      StateRel.afterFrameExactStackWordWritesEvaluation\n"
                "        staticProofContext world\n"
                f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
                "        activeFrameInventory frame originalState candidateState\n"
                f"        ({original_behavior}.eval originalState)\n"
                f"        ({candidate_behavior}.eval candidateState) frameExactWritesClaim\n"
                "        staticProofContextChecked relatedForTransfer (by decide)\n"
                "        (by simpa [activeFrameInventory] using frameOffsetsHold)\n"
                "        activeFrameExactWords originalWrites candidateWrites\n"
                "        (by simp) (by simp) outputRegisters outputBounds\n"
                "        outputSeparations outputStackWindows outputX87 outputFlags\n"
                "        outputImports\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          registerValueOriginRelationsHold])\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          memoryValueOriginRelationsHold])\n"
                "        outputDynamic outputDynamicStack\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          pairedStatePredicatesHold])\n"
            )
        else:
            memory_transition = (
                f"    have originalWritesField : {original_behavior}.writes = [] := by decide\n"
                f"    have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
                f"    have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
                "      simp [originalWritesField, evalNormalizedWrites]\n"
                f"    have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
                "      simp [candidateWritesField, evalNormalizedWrites]\n"
                "    have nextStatesRelated : StateRel staticProofContext world\n"
                f"        region{target_region_index}.inputInvariant\n"
                f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
                "      StateRel.afterNoWriteEvaluation staticProofContext world\n"
                f"        region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
                f"        originalState candidateState ({original_behavior}.eval originalState)\n"
                f"        ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
                "        originalWrites candidateWrites (by simp) (by simp)\n"
                "        outputRegisters outputBounds\n"
                "        outputSeparations outputStackWindows outputX87 outputFlags\n"
                "        outputImports\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          registerValueOriginRelationsHold])\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          memoryValueOriginRelationsHold])\n"
                "        outputDynamic outputDynamicStack\n"
                f"        (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
                "          pairedStatePredicatesHold])\n"
            )
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {source_calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + "  cases frames with\n"
            "  | nil => simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "  | cons frame tail =>\n"
            "    simp only [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "    have frameContinuation := stackHolds.1\n"
            "    have frameResolves := stackHolds.2.2.1\n"
            "    have frameMemory := stackHolds.2.2.2.1\n"
            "    have frameOffsetsHold := stackHolds.2.2.2.2.1\n"
            "    have selectedFrameOffsetsHold :\n"
            f"        ({typed_frame_offsets}).holds frame originalState.registers\n"
            "          candidateState.registers := by\n"
            f"      exact frameOffsetsHold.2 ({typed_frame_offsets}) (by decide)\n"
            f"    let returnClaim : ReturnPopClaim := {return_claim_row}\n"
            f"    let frameClaim : ReturnPopFrameClaim := {frame_claim_row}\n"
            "    have returnTargets := returnPopTargetsRuntimeFrame_of_checked\n"
            f"      {original_behavior} {candidate_behavior} returnClaim frameClaim frame\n"
            "      originalState candidateState (by decide) (by decide)\n"
            "      selectedFrameOffsetsHold frameMemory\n"
            f"    simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
            f"      acceptanceCandidateNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq]\n"
            "      at returnTargets\n"
            "    let outerFrameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"      {outer_frame_claims_literal}\n"
            f"    let activeFrameInventory : ReturnSlotOffsetInventory := {frame_inventory}\n"
            "    let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"      {frame_import_claims_literal}\n"
            "    have outerStackHolds : RelationalRuntimeCallStackHolds\n"
            "        staticProofContext\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"          candidateState) tail {target_calls_literal}\n"
            f"        {target_offsets_literal} := by\n"
            "      exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"        staticProofContext world region{region_index}.inputInvariant\n"
            f"        {original_behavior} {candidate_behavior} outerFrameClaims\n"
            f"        tail {target_calls_literal} originalState candidateState\n"
            "        (by decide)\n"
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2.2)\n"
            "        statesRelated\n"
            "    have frameFactsAfterInternal : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"        (activeFrameInventory :: {target_offsets_literal})\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers := by\n"
            "      exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"        {original_behavior} {candidate_behavior} frameImportClaims\n"
            "        originalState candidateState (by decide)\n"
            "        (by simpa [frameImportClaims, activeFrameInventory] using\n"
            "          frameImportsHold)\n"
            "    have activeFrameImportsNext := "
            "RelationalRuntimeCallFactsHold.headImports\n"
            "      staticProofContext world activeFrameInventory _ _ _ "
            "frameFactsAfterInternal\n"
            "    have activeFrameRelationsNext := "
            "RelationalRuntimeCallFactsHold.headRelations\n"
            "      staticProofContext world activeFrameInventory _ _ _ "
            "frameFactsAfterInternal\n"
            "    have outerFrameImportsNext := RelationalRuntimeCallFactsHold.tail\n"
            "      staticProofContext world activeFrameInventory _ _ _ "
            "frameFactsAfterInternal\n"
            "    have relatedForTransfer := statesRelated\n"
            + import_fact_setup
            + "    rcases statesRelated with\n"
            "      ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,\n"
            "        _importsComplete, _importsMemory, _originalImmutable,\n"
            "        _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
            "    rcases relatedCore with\n"
            "      ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,\n"
            "        _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
            "        _inputFlags, _inputFsBase⟩\n"
            f"    let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
            "    let carriedRelations : List RegisterRelationPair := ["
            + active_frame_relations_literal
            + "]\n"
            "    let residualRelations : List RegisterRelationPair := ["
            + residual_target_relations_literal
            + "]\n"
            "    have outputRegisters : registerRelationsHold\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        region{target_region_index}.inputInvariant.registerRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "      have carriedHolds : registerRelationsHold\n"
            "          staticProofContext.originalPe.imageBase\n"
            "          staticProofContext.candidatePe.imageBase\n"
            "          staticProofContext.codeMap.entries.toList\n"
            "          (staticProofContext.relationalValueTargets world)\n"
            "          carriedRelations\n"
            f"          ({original_behavior}.eval originalState).registers\n"
            f"          ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "        simpa [carriedRelations, activeFrameInventory,\n"
            "          ReturnSlotOffsetInventory.preservedRelationsHold] using\n"
            "          activeFrameRelationsNext\n"
            "      have residualHolds : registerRelationsHold\n"
            "          staticProofContext.originalPe.imageBase\n"
            "          staticProofContext.candidatePe.imageBase\n"
            "          staticProofContext.codeMap.entries.toList\n"
            "          (staticProofContext.relationalValueTargets world)\n"
            "          residualRelations\n"
            f"          ({original_behavior}.eval originalState).registers\n"
            f"          ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "        have inventory : outputClaims.map "
            "InvariantWP.RegisterOutputClaim.output = residualRelations := by decide\n"
            "        rw [← inventory]\n"
            "        exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"          staticProofContext world region{region_index} {original_behavior}\n"
            f"          {candidate_behavior} outputClaims (by decide)\n"
            "          originalState candidateState relatedForTransfer\n"
            "      have combinedHolds := registerRelationsHold_append_of_holds\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            "        carriedRelations residualRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers\n"
            "        carriedHolds residualHolds\n"
            "      rw [RegionRelation.inputInvariant]\n"
            "      exact registerRelationsHold_of_perm\n"
            "        staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        (carriedRelations ++ residualRelations) region{target_region_index}.inputRelations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers\n"
            "        (by decide) combinedHolds\n"
            "    have outputBounds : boundsRelated\n"
            f"        region{target_region_index}.inputInvariant.bounds\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index}, boundsRelated]\n"
            "    have outputSeparations : addressSeparationsRelated\n"
            f"        region{target_region_index}.inputInvariant.addressSeparations\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        addressSeparationsRelated]\n"
            f"    let stackTransfers : List StackWindowAffineTransferClaim := [{stack_transfers}]\n"
            "    have outputStackWindows := stackWindowsRelated_after_affine_of_checked\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      region{target_region_index}.inputInvariant {original_behavior}\n"
            f"      {candidate_behavior} stackTransfers originalState candidateState\n"
            "      stackRangesValid inputStackWindows (by decide)\n"
            f"    have originalX87Field : {original_behavior}.x87 =\n"
            f"        originalBehavior{region_index}.x87 := by decide\n"
            f"    have candidateX87Field : {candidate_behavior}.x87 =\n"
            f"        candidateBehavior{region_index}.x87 := by decide\n"
            "    have outputX87 :\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState).x87 =\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "          candidateState).x87 := by\n"
            "      have inputLegacyX87 := inputX87.1\n"
            "      simp [originalX87Field, candidateX87Field,\n"
            f"        originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "        RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
            "        X87Expr.eval, Expr.eval, inputLegacyX87]\n"
            "    have outputFlags : flagsRelated\n"
            f"        region{target_region_index}.inputInvariant.flagBits\n"
            f"        ({original_behavior}.eval originalState).eflags\n"
            f"        ({candidate_behavior}.eval candidateState).eflags = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        flagsRelated]\n"
            + import_output_proof
            + "    have outputDynamic : activeDynamicRegisterRangeRelationsHold "
            "staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant.dynamicRegisterRangeRelations\n"
            f"        (({original_behavior}.eval originalState).nextMachineState "
            "originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState "
            "candidateState) = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        activeDynamicRegisterRangeRelationsHold]\n"
            "    have outputDynamicStack : activeDynamicStackRangeRelationsHold "
            "staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant.dynamicStackRangeRelations\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
            f"      simp [RegionRelation.inputInvariant, region{target_region_index},\n"
            "        activeDynamicStackRangeRelationsHold]\n"
            + memory_transition
            + "    have stackHoldsNext := outerStackHolds\n"
            "    have outerTargetsReachable : RelationalRuntimeCallTargetsMapped\n"
            "        relationalProductGraph relationalProductReachabilityEvidence\n"
            f"        {target_calls_literal} := by\n"
            "      simpa only [RelationalRuntimeCallTargetsMapped] using\n"
            "        stackTargetsReachable.2\n"
            "    simp only [RelationalCallFrame.resolves, Bool.and_eq_true, beq_iff_eq]\n"
            "      at frameResolves\n"
            "    rw [frameContinuation] at frameResolves\n"
            "    simp [originalWorldProgram, candidateWorldProgram]\n"
            "    rw [returnTargets.1, returnTargets.2, frameResolves.1, frameResolves.2]\n"
            "    simp\n"
            + "\n".join(
                "  " + line
                for line in _lean_acceptance_running_target(
                    node_id=node_id,
                    region_index=region_index,
                    edge=target_edge,
                    frames="tail",
                    calls=target_calls_literal,
                    frame_offsets=target_offsets_literal,
                    stack_targets_proof="outerTargetsReachable",
                    frame_imports_proof="outerFrameImportsNext",
                ).splitlines()
            )
        )
    if step["kind"] == "external_terminate":
        site = step["external_site"]
        site_id = int(site["id"])
        continuation = int(site["continuation_target_id"])
        decoded_import_identity = _semantic_external_target_identity(
            step.get("decoded_import") or {}
        )
        if decoded_import_identity is None:
            raise StageAInputError(
                f"external-termination acceptance node {node_id} has no decoded import identity"
            )
        decoded_import_literal = _lean_external_target({
            "dll": decoded_import_identity[0],
            decoded_import_identity[1]: decoded_import_identity[2],
        })
        opaque_site_id = step.get("opaque_lockstep_site_id")
        terminal_opaque_source = ""
        boundary_for_observation = "boundaryKnown"
        if opaque_site_id is not None:
            terminal_opaque_source = (
                "  have opaqueTerminal :=\n"
                "    OpaqueLockstepExternalEnvironmentsRefine.atTerminating\n"
                "      staticProofContext externalCallSites opaqueLockstepCallSites\n"
                "      (opaqueLockstepCallSites.map fun site => site.id)\n"
                "      originalEnvironment candidateEnvironment environmentRefines\n"
                f"      externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
                f"      opaqueLockstepCallSite{int(opaque_site_id)} (by decide) (by decide)\n"
                f"      externalJumpSite{site_id}MachineContractResolved (by decide) (by decide)\n"
                "      eventIndex originalEvent candidateEvent boundaryKnown\n"
            )
            boundary_for_observation = "opaqueTerminal.2"
        control_calls = [
            int(call) for call in step["control_state"]["calls"]
        ]
        calls_literal = "[" + ", ".join(
            str(call) for call in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(offset)
            for offset in step["control_state"]["frame_offsets"]
        ) + "]"
        original_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval originalState"
            for argument in site.get("argument_expressions", [])
        )
        candidate_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval candidateState"
            for argument in site.get("argument_expressions", [])
        )
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      externalJumpSite{site_id}OriginalNormalized := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      externalJumpSite{site_id}CandidateNormalized := by decide\n"
            f"  have closed := externalJumpSite{site_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  simp only [evalBehavior, externalJumpSite{site_id}OriginalNormalizedChecked,\n"
            f"    externalJumpSite{site_id}CandidateNormalizedChecked, Option.bind_some]\n"
            "    at closed\n"
            "  rcases closed with\n"
            "    ⟨originalCallArguments, candidateCallArguments, originalOutcome,\n"
            "      candidateOutcome, boundary⟩\n"
            f"  have originalArgumentsKnown : [{original_arguments}] =\n"
            "      originalCallArguments := by\n"
            "    have decomposed := originalOutcome\n"
            f"    simp only [externalJumpSite{site_id}OriginalOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2\n"
            f"  have candidateArgumentsKnown : [{candidate_arguments}] =\n"
            "      candidateCallArguments := by\n"
            "    have decomposed := candidateOutcome\n"
            f"    simp only [externalJumpSite{site_id}CandidateOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2\n"
            "  subst originalCallArguments\n"
            "  subst candidateCallArguments\n"
            "  let originalEvent : WorldExternalEvent := {\n"
            f"    siteId := {site_id}\n"
            f"    imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"    arguments := [{original_arguments}]\n"
            "    state := normalizeImportReturnSlotState\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            "    world\n"
            "  }\n"
            "  let candidateEvent : WorldExternalEvent := {\n"
            f"    siteId := {site_id}\n"
            f"    imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"    arguments := [{candidate_arguments}]\n"
            "    state := normalizeImportReturnSlotState\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "    world\n"
            "  }\n"
            "  have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"      externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
            "      originalEvent candidateEvent := by\n"
            "    simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "      candidateBehaviorCommon] using boundary\n"
            + terminal_opaque_source
            + f"  have argumentsRelated := {boundary_for_observation}.2.2.2.2.2.2\n"
            "  have observationRelated : worldRelationalObservationsRelated\n"
            "      staticProofContext\n"
            f"      (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"        [{original_arguments}]))\n"
            f"      (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"        [{candidate_arguments}])) := by\n"
            "    exact ⟨rfl, rfl, argumentsRelated⟩\n"
            "  have siteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id} {continuation}\n"
            f"      externalJumpSite{site_id}MachineContract.imported = some {site_id} := by\n"
            "    decide\n"
            "  have contractResolved : resolvedExternalCallContract? staticProofContext\n"
            f"      externalCallSites {site_id} =\n"
            f"        some externalJumpSite{site_id}MachineContract := by\n"
            "    decide\n"
            f"  have importedCommon : ({decoded_import_literal} : ExternalTarget) =\n"
            f"      externalJumpSite{site_id}MachineContract.imported := by decide\n"
            "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
            "  simp only [originalWorldProgram, candidateWorldProgram, importedCommon,\n"
            "    siteResolved, contractResolved]\n"
            "  exact ⟨observationRelated, rfl⟩\n"
        )
    if step["kind"] == "external_jump":
        site = step["external_site"]
        site_id = int(site["id"])
        continuation = int(step["target_target_id"])
        target_node_id = int(step["target_node_id"])
        target_region_index = int(step["target_region_index"])
        decoded_import_identity = _semantic_external_target_identity(
            step.get("decoded_import") or {}
        )
        if decoded_import_identity is None:
            raise StageAInputError(
                f"external-jump acceptance node {node_id} has no decoded import identity"
            )
        decoded_import_literal = _lean_external_target({
            "dll": decoded_import_identity[0],
            decoded_import_identity[1]: decoded_import_identity[2],
        })
        opaque_site_id = step.get("opaque_lockstep_site_id")
        if opaque_site_id is not None:
            tail_environment_source = (
                "    have environmentAt := ExternalEnvironmentRefines.at staticProofContext\n"
                "      externalCallSites originalEnvironment candidateEnvironment\n"
                f"      environmentRefines.externalRefines externalCallSite{site_id}\n"
                f"      externalJumpSite{site_id}MachineContract (by decide)\n"
                f"      externalJumpSite{site_id}MachineContractResolved\n"
                "    have results := externalCallResultsRelated staticProofContext\n"
                f"      externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
                "      originalEnvironment candidateEnvironment environmentAt (by decide) eventIndex\n"
                "      originalEvent candidateEvent boundaryKnown\n"
                "    have opaqueResults :=\n"
                "      OpaqueLockstepExternalEnvironmentsRefine.atReturning\n"
                "        staticProofContext externalCallSites opaqueLockstepCallSites\n"
                "        (opaqueLockstepCallSites.map fun site => site.id)\n"
                "        originalEnvironment candidateEnvironment environmentRefines\n"
                f"        externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
                f"        opaqueLockstepCallSite{int(opaque_site_id)} (by decide) (by decide)\n"
                f"        externalJumpSite{site_id}MachineContractResolved (by decide) (by decide)\n"
                "        eventIndex originalEvent candidateEvent boundaryKnown\n"
                "    dsimp only at results opaqueResults\n"
                "    rcases results with\n"
                "      ⟨_ordinaryWorldsEqual, _originalConforms, _candidateConforms,\n"
                "        _resultRegistersRelated, _ordinaryStatesRelated,\n"
                "        _ordinaryFramesPreserved⟩\n"
                "    rcases opaqueResults with\n"
                "      ⟨resultWorldsEqual, nextStatesRelated, framesPreserved⟩\n"
            )
        else:
            tail_environment_source = (
                "    have environmentAt := ExternalEnvironmentRefines.at staticProofContext\n"
                "      externalCallSites originalEnvironment candidateEnvironment\n"
                f"      environmentRefines externalCallSite{site_id}\n"
                f"      externalJumpSite{site_id}MachineContract (by decide)\n"
                f"      externalJumpSite{site_id}MachineContractResolved\n"
                "    have results := externalCallResultsRelated staticProofContext\n"
                f"      externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
                "      originalEnvironment candidateEnvironment environmentAt (by decide) eventIndex\n"
                "      originalEvent candidateEvent boundaryKnown\n"
                "    dsimp only at results\n"
                "    rcases results with\n"
                "      ⟨resultWorldsEqual, _originalConforms, _candidateConforms,\n"
                "        _resultRegistersRelated, nextStatesRelated, framesPreserved⟩\n"
            )
        control_calls = [
            int(call) for call in step["control_state"]["calls"]
        ]
        outer_calls = control_calls[1:]
        calls_literal = "[" + ", ".join(
            str(call) for call in control_calls
        ) + "]"
        outer_calls_literal = "[" + ", ".join(
            str(call) for call in outer_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(offset)
            for offset in step["control_state"]["frame_offsets"]
        ) + "]"
        outer_claims = step["return_slot_external_jump_transfer_claims"]
        outer_claims_literal = "[" + ", ".join(
            _lean_external_jump_return_slot_inventory_transfer_claim(claim)
            for claim in outer_claims
        ) + "]"
        outer_fact_claims_literal = _lean_runtime_call_import_transfer_claims(
            outer_claims
        )
        active_frame_inventory_literal = _lean_return_slot_offset_inventory(
            step["control_state"]["frame_offsets"][0]
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(claim["target"])
            for claim in outer_claims
        ) + "]"
        original_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval originalState"
            for argument in site.get("argument_expressions", [])
        )
        candidate_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval candidateState"
            for argument in site.get("argument_expressions", [])
        )
        target_edge = {
            "target_node_id": target_node_id,
            "target_region_index": target_region_index,
            "target_target_id": continuation,
        }
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        return (
            prefix
            + selected_control
            + "  cases frames with\n"
            "  | nil => simp [RelationalRuntimeCallStackHolds] at stackHolds\n"
            "  | cons frame outerFrames =>\n"
            "    simp only [RelationalRuntimeCallStackHolds] at stackHolds\n"
            f"    let outerFrameClaims : List "
            "ExternalJumpReturnSlotInventoryTransferClaim := "
            f"{outer_claims_literal}\n"
            "    let outerFrameFactClaims : List "
            "RelationalRuntimeCallImportTransferClaim := "
            f"{outer_fact_claims_literal}\n"
            "    let activeFrameInventory : ReturnSlotOffsetInventory := "
            f"{active_frame_inventory_literal}\n"
            f"    have originalBehaviorCommon : {original_behavior} =\n"
            f"        externalJumpSite{site_id}OriginalNormalized := by decide\n"
            f"    have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"        externalJumpSite{site_id}CandidateNormalized := by decide\n"
            f"    have closed := externalJumpSite{site_id}TransitionChecked world\n"
            "      originalState candidateState statesRelated\n"
            f"    simp only [evalBehavior, externalJumpSite{site_id}OriginalNormalizedChecked,\n"
            f"      externalJumpSite{site_id}CandidateNormalizedChecked, Option.bind_some]\n"
            "      at closed\n"
            "    rcases closed with\n"
            "      ⟨originalCallArguments, candidateCallArguments, originalOutcome,\n"
            "        candidateOutcome, boundary⟩\n"
            f"    have originalArgumentsKnown : [{original_arguments}] =\n"
            "        originalCallArguments := by\n"
            "      have decomposed := originalOutcome\n"
            f"      simp only [externalJumpSite{site_id}OriginalOutcomeChecked,\n"
            "        NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "        Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "      simpa only [List.map] using decomposed.2\n"
            f"    have candidateArgumentsKnown : [{candidate_arguments}] =\n"
            "        candidateCallArguments := by\n"
            "      have decomposed := candidateOutcome\n"
            f"      simp only [externalJumpSite{site_id}CandidateOutcomeChecked,\n"
            "        NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "        Expr.eval, PureOutcome.externalJump.injEq] at decomposed\n"
            "      simpa only [List.map] using decomposed.2\n"
            "    subst originalCallArguments\n"
            "    subst candidateCallArguments\n"
            "    let originalEvent : WorldExternalEvent := {\n"
            f"      siteId := {site_id}\n"
            f"      imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"      arguments := [{original_arguments}]\n"
            "      state := normalizeImportReturnSlotState\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            "      world\n"
            "    }\n"
            "    let candidateEvent : WorldExternalEvent := {\n"
            f"      siteId := {site_id}\n"
            f"      imported := externalJumpSite{site_id}MachineContract.imported\n"
            f"      arguments := [{candidate_arguments}]\n"
            "      state := normalizeImportReturnSlotState\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "      world\n"
            "    }\n"
            "    have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"        externalCallSite{site_id} externalJumpSite{site_id}MachineContract\n"
            "        originalEvent candidateEvent := by\n"
            "      simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "        candidateBehaviorCommon] using boundary\n"
            + tail_environment_source
            + "    have outerSourceFacts := RelationalRuntimeCallFactsHold.tail\n"
            "      staticProofContext world activeFrameInventory _ _ _\n"
            "      (by simpa [activeFrameInventory] using frameImportsHold)\n"
            "    have outerFactsAfterInternal :=\n"
            "      RelationalRuntimeCallFactsHold.afterInternal\n"
            f"        staticProofContext world {original_behavior} {candidate_behavior}\n"
            "        outerFrameFactClaims originalState candidateState (by decide)\n"
            "        (by simpa [outerFrameFactClaims] using outerSourceFacts)\n"
            "    have outerFactsAtBoundary : RelationalRuntimeCallFactsHold\n"
            "        staticProofContext world\n"
            f"        {target_offsets_literal} originalEvent.state.registers\n"
            "        candidateEvent.state.registers := by\n"
            "      have normalized :=\n"
            "        RelationalRuntimeCallFactsHold.normalizeImportReturnSlot\n"
            f"          staticProofContext externalJumpSite{site_id}MachineContract\n"
            f"          {target_offsets_literal} world\n"
            f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "          (by decide)\n"
            "          (by simpa [RelationalBehavior.nextMachineState] using\n"
            "            outerFactsAfterInternal)\n"
            "      simpa [originalEvent, candidateEvent] using normalized\n"
            "    have pairConforms : ExactExternalCallPairConforms staticProofContext\n"
            f"        externalJumpSite{site_id}MachineContract originalEvent candidateEvent\n"
            "        (originalEnvironment.result eventIndex originalEvent)\n"
            "        (candidateEnvironment.result eventIndex candidateEvent) := {\n"
            "      siteId := rfl\n"
            "      originalImported := rfl\n"
            "      candidateImported := rfl\n"
            "      eventWorld := rfl\n"
            "      resultWorld := resultWorldsEqual\n"
            "      originalConforms := _originalConforms\n"
            "      candidateConforms := _candidateConforms\n"
            "    }\n"
            "    have activeImportsAtInput :\n"
            "        activeFrameInventory.preservedImportsHold world\n"
            "          originalState.registers candidateState.registers = true := by\n"
            "      exact RelationalRuntimeCallFactsHold.headImports\n"
            "        staticProofContext world activeFrameInventory _ _ _\n"
            "        (by simpa [activeFrameInventory] using frameImportsHold)\n"
            "    have activeImportsAfterInternal :=\n"
            "      activeFrameInventory.preservedImportsHold_after_of_checked world\n"
            f"        {original_behavior} {candidate_behavior}\n"
            "        originalState candidateState (by decide) activeImportsAtInput\n"
            "    have activeImportsAtBoundary :\n"
            "        activeFrameInventory.preservedImportsHold world\n"
            "          originalEvent.state.registers candidateEvent.state.registers = true := by\n"
            "      have normalized :=\n"
            "        activeFrameInventory.preservedImportsHold_normalizeImportReturnSlot\n"
            f"          staticProofContext externalJumpSite{site_id}MachineContract world\n"
            f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "          (by decide)\n"
            "          (by simpa [RelationalBehavior.nextMachineState] using\n"
            "            activeImportsAfterInternal)\n"
            "      simpa [originalEvent, candidateEvent] using normalized\n"
            "    have activeImportsNext :=\n"
            "      activeFrameInventory.preservedImportsHold_afterExternal\n"
            f"        staticProofContext externalJumpSite{site_id}MachineContract\n"
            "        originalEvent candidateEvent\n"
            "        (originalEnvironment.result eventIndex originalEvent)\n"
            "        (candidateEnvironment.result eventIndex candidateEvent)\n"
            "        (by decide) activeImportsAtBoundary pairConforms\n"
            "    have nextStatesRelatedWithActiveImports :=\n"
            "      StateRel.withAdditionalImportRegisterRelations staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).world\n"
            f"        externalCallSite{site_id}.targetInvariant\n"
            "        activeFrameInventory.preservedImports\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "        nextStatesRelated activeImportsNext\n"
            "    have targetInvariantFromActiveFrame :\n"
            f"        externalCallSite{site_id}.targetInvariant."
            "withAdditionalImportRegisterRelations\n"
            "          activeFrameInventory.preservedImports =\n"
            f"          region{target_region_index}.inputInvariant := by decide\n"
            "    have nextStatesRelatedFull : StateRel staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).world\n"
            f"        region{target_region_index}.inputInvariant\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state := by\n"
            "      rw [← targetInvariantFromActiveFrame]\n"
            "      exact nextStatesRelatedWithActiveImports\n"
            "    have frameImportsNext : RelationalRuntimeCallFactsHold\n"
            "        staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).world\n"
            f"        {target_offsets_literal}\n"
            "        (originalEnvironment.result eventIndex originalEvent).state.registers\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state.registers := by\n"
            "      exact RelationalRuntimeCallFactsHold.afterExternal\n"
            f"        staticProofContext externalJumpSite{site_id}MachineContract\n"
            f"        {target_offsets_literal} originalEvent candidateEvent\n"
            "        (originalEnvironment.result eventIndex originalEvent)\n"
            "        (candidateEnvironment.result eventIndex candidateEvent)\n"
            "        (by decide) outerFactsAtBoundary pairConforms\n"
            "    have argumentsRelated := boundaryKnown.2.2.2.2.2.2\n"
            "    have observationRelated : worldRelationalObservationsRelated\n"
            "        staticProofContext\n"
            f"        (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"          [{original_arguments}]))\n"
            f"        (some (.external world externalJumpSite{site_id}MachineContract.imported\n"
            f"          [{candidate_arguments}])) := by\n"
            "      exact ⟨rfl, rfl, argumentsRelated⟩\n"
            "    have originalSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"        externalCallSites {target_id} {continuation}\n"
            f"        externalJumpSite{site_id}MachineContract.imported = some {site_id} := by\n"
            "      decide\n"
            "    have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"        externalCallSites {target_id} {continuation}\n"
            f"        externalJumpSite{site_id}MachineContract.imported = some {site_id} := by\n"
            "      decide\n"
            "    have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            f"        outerFrames {outer_calls_literal} {target_offsets_literal} := by\n"
            "      exact RelationalRuntimeCallStackHolds.afterExternalJump\n"
            f"        staticProofContext world region{region_index}.inputInvariant\n"
            f"        {original_behavior} {candidate_behavior}\n"
            f"        externalJumpSite{site_id}MachineContract outerFrameClaims\n"
            f"        outerFrames {outer_calls_literal} originalState candidateState\n"
            "        (originalEnvironment.result eventIndex originalEvent).state\n"
            "        (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "        (by decide)\n"
            "        (by simpa [outerFrameClaims] using stackHolds.2.2.2.2.2.2)\n"
            "        (by simpa [originalEvent] using _originalConforms.2.1)\n"
            "        (by simpa [candidateEvent] using _candidateConforms.2.1)\n"
            "        statesRelated\n"
            "        (by\n"
            "          intro outerFrame inventory frameHolds exactWords\n"
            "          exact framesPreserved outerFrame inventory (by\n"
            "            simpa [originalEvent, candidateEvent] using frameHolds) (by\n"
            "            simpa [originalEvent, candidateEvent] using exactWords))\n"
            "    have outerTargetsReachable : RelationalRuntimeCallTargetsMapped\n"
            f"        relationalProductGraph relationalProductReachabilityEvidence\n"
            f"        {outer_calls_literal} := by\n"
            "      simpa only [RelationalRuntimeCallTargetsMapped] using\n"
            "        stackTargetsReachable.2\n"
            "    rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
            "    simp only [originalWorldProgram, candidateWorldProgram]\n"
            f"    have importedCommon : ({decoded_import_literal} : ExternalTarget) =\n"
            f"        externalJumpSite{site_id}MachineContract.imported := by decide\n"
            "    rw [importedCommon, originalSiteResolved]\n"
            "    simp only\n"
            + "\n".join(
                "  " + line
                for line in _lean_acceptance_running_target(
                    node_id=node_id,
                    region_index=region_index,
                    edge=target_edge,
                    frames="outerFrames",
                    calls=outer_calls_literal,
                    frame_offsets=target_offsets_literal,
                    stack_targets_proof="outerTargetsReachable",
                    observation_proof="observationRelated",
                    world_equal_proof="resultWorldsEqual",
                    frame_imports_proof="frameImportsNext",
                    states_related_proof="nextStatesRelatedFull",
                ).splitlines()
            )
        )
    if step["kind"] in {"external_call", "external_protocol"}:
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        site = step["external_site"]
        arguments = ", ".join(
            _lean_semantic_expr(argument)
            for argument in site.get("argument_expressions", [])
        )
        original_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval originalState"
            for argument in site.get("argument_expressions", [])
        )
        candidate_arguments = ", ".join(
            f"({_lean_semantic_expr(argument)}).eval candidateState"
            for argument in site.get("argument_expressions", [])
        )
        imported_identity = _semantic_external_target_identity(
            step.get("external_site", {}).get("original_import")
            or step.get("external_site", {}).get("import")
            or {}
        )
        if imported_identity is None:
            imported_identity = _semantic_external_target_identity(
                step.get("external_site", {}).get("decoded_import")
                or {}
            )
        if imported_identity is None:
            imported_identity = _semantic_external_target_identity(
                step.get("external_site", {}).get("machine_import")
                or {}
            )
        if imported_identity is None:
            # The candidate carries a contract id, while the exact byte-level target
            # remains in the decoded outcome used to construct this node step.
            decoded_import = step.get("decoded_import")
            imported_identity = _semantic_external_target_identity(decoded_import)
        if imported_identity is None:
            # Register-dispatched calls record their checked import in the compact
            # machine-contract form rather than the normalized decoder form.
            imported_identity = _machine_import_call_contract_identity(
                step.get("machine_contract")
            )
        if imported_identity is None:
            raise StageAInputError(
                f"external acceptance node {node_id} has no decoded import identity"
            )
        control_state = step["control_state"]
        calls_literal = "[" + ", ".join(
            str(int(call)) for call in control_state["calls"]
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(offset)
            for offset in control_state["frame_offsets"]
        ) + "]"
        transfer_claims = step["return_slot_external_transfer_claims"]
        transfer_claims_literal = "[" + ", ".join(
            _lean_external_return_slot_inventory_transfer_claim(claim)
            for claim in transfer_claims
        ) + "]"
        frame_fact_claims_literal = _lean_runtime_call_import_transfer_claims(
            transfer_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(claim["target"])
            for claim in transfer_claims
        ) + "]"
        imported_literal = _lean_external_target({
            "dll": imported_identity[0], imported_identity[1]: imported_identity[2],
        })
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧ "
            f"frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        register_dispatch = bool(step.get("register_dispatch"))
        zero_argument_register_dispatch = (
            register_dispatch
            and step["kind"] == "external_call"
            and not site.get("argument_expressions", [])
            and not step.get("machine_contract", {}).get(
                "stack_argument_offsets", []
            )
        )
        proof_original_behavior = original_behavior
        proof_candidate_behavior = candidate_behavior
        original_event_state = (
            f"({original_behavior}.eval originalState).nextMachineState\n"
            "      originalState"
        )
        candidate_event_state = (
            f"({candidate_behavior}.eval candidateState).nextMachineState\n"
            "      candidateState"
        )
        behavior_bridge = (
            f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      externalCallEdge{edge_id}OriginalNormalized := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      externalCallEdge{edge_id}CandidateNormalized := by decide\n"
        )
        boundary_bridge = (
            "    simpa [originalEvent, candidateEvent, originalBehaviorCommon,\n"
            "      candidateBehaviorCommon] using boundary\n"
        )
        final_world_bridge = (
            "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
        )
        frame_event_bridge = ""
        result_abi_bridge = ""
        original_abi_proof = (
            "(by simpa [originalEvent] using _originalConforms.2.1)"
        )
        candidate_abi_proof = (
            "(by simpa [candidateEvent] using _candidateConforms.2.1)"
        )
        imported_world_bridge = (
            f"  have importedCommon : ({imported_literal} : ExternalTarget) =\n"
            f"      externalCallEdge{edge_id}MachineContract.imported := by decide\n"
            "  rw [importedCommon]\n"
        )
        if zero_argument_register_dispatch:
            original_register = str(
                step["decoded_control"]["original_register"]
            )
            candidate_register = str(
                step["decoded_control"]["candidate_register"]
            )
            proof_original_behavior = (
                f"externalCallEdge{edge_id}OriginalNormalized"
            )
            proof_candidate_behavior = (
                f"externalCallEdge{edge_id}CandidateNormalized"
            )
            original_event_state = (
                "normalizeImportReturnSlotState\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState)"
            )
            candidate_event_state = (
                "normalizeImportReturnSlotState\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState)"
            )
            behavior_bridge = (
                f"  have originalDecodedBehaviorCommon : {original_behavior} =\n"
                f"      externalCallEdge{edge_id}OriginalDecodedNormalized := by decide\n"
                f"  have candidateDecodedBehaviorCommon : {candidate_behavior} =\n"
                f"      externalCallEdge{edge_id}CandidateDecodedNormalized := by decide\n"
                f"  have dispatchTargets := externalCallEdge{edge_id}DispatchTargetsClosed\n"
                "    world originalState candidateState statesRelated\n"
                "  rcases dispatchTargets with\n"
                "    ⟨importBinding, importBindingMember, importBindingIdentity,\n"
                "      originalDispatchOutcome, candidateDispatchOutcome⟩\n"
                "  have originalTargetAddress :\n"
                f"      (Expr.inputReg .{original_register}).eval originalState =\n"
                "        importBinding.originalAddress := by\n"
                "    rw [← originalDecodedBehaviorCommon] at originalDispatchOutcome\n"
                f"    simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
                "      NormalizedOutcomeExpr.eval, Expr.eval,\n"
                "      PureOutcome.indirectCall.injEq] at originalDispatchOutcome\n"
                "    exact originalDispatchOutcome.1\n"
                "  have candidateTargetAddress :\n"
                f"      (Expr.inputReg .{candidate_register}).eval candidateState =\n"
                "        importBinding.candidateAddress := by\n"
                "    rw [← candidateDecodedBehaviorCommon] at candidateDispatchOutcome\n"
                f"    simp only [acceptanceCandidateNormalizedOutcome{node_id},\n"
                "      NormalizedOutcomeExpr.eval, Expr.eval,\n"
                "      PureOutcome.indirectCall.injEq] at candidateDispatchOutcome\n"
                "    exact candidateDispatchOutcome.1\n"
                "  have importBindingContractIdentity : importBinding.imported =\n"
                f"      externalCallEdge{edge_id}MachineContract.imported := by\n"
                f"    simpa [externalCallEdge{edge_id}DispatchClaim] using\n"
                "      importBindingIdentity\n"
                "  have importBindingValid := StateRel.importAddressStaticValid\n"
                f"    staticProofContext world region{region_index}.inputInvariant\n"
                "    originalState candidateState statesRelated importBinding\n"
                "    importBindingMember\n"
                "  have originalCodeMissing :=\n"
                "    importBinding.originalCodeUnresolved staticProofContext\n"
                "      importBindingValid\n"
                "  have candidateCodeMissing :=\n"
                "    importBinding.candidateCodeUnresolved staticProofContext\n"
                "      importBindingValid\n"
                "  have importsStatic := StateRel.importAddressesStaticValid\n"
                f"    staticProofContext world region{region_index}.inputInvariant\n"
                "    originalState candidateState statesRelated\n"
                "  have importContractFound :\n"
                "      staticProofContext.machineImportCallContracts.find? (fun candidate =>\n"
                "        candidate.imported == importBinding.imported) =\n"
                f"        some externalCallEdge{edge_id}MachineContract := by\n"
                "    rw [importBindingContractIdentity]\n"
                "    decide\n"
                "  have importContractHasNoArguments :\n"
                f"      externalCallEdge{edge_id}MachineContract.stackArgumentOffsets = [] := by\n"
                "    decide\n"
                "  have originalImportResolved : resolveWorldImportCall false\n"
                "      staticProofContext world importBinding.originalAddress\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState) =\n"
                f"        some (externalCallEdge{edge_id}MachineContract.imported, []) := by\n"
                "    have resolved := resolveWorldImportCall_zeroArguments_of_binding\n"
                "      false staticProofContext world\n"
                f"      (({original_behavior}.eval originalState).nextMachineState\n"
                "        originalState) importBinding importsStatic importBindingMember\n"
                f"      externalCallEdge{edge_id}MachineContract importContractFound\n"
                "      importContractHasNoArguments\n"
                "    simpa [importBindingContractIdentity] using resolved\n"
                "  have candidateImportResolved : resolveWorldImportCall true\n"
                "      staticProofContext world importBinding.candidateAddress\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState) =\n"
                f"        some (externalCallEdge{edge_id}MachineContract.imported, []) := by\n"
                "    have resolved := resolveWorldImportCall_zeroArguments_of_binding\n"
                "      true staticProofContext world\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "        candidateState) importBinding importsStatic importBindingMember\n"
                f"      externalCallEdge{edge_id}MachineContract importContractFound\n"
                "      importContractHasNoArguments\n"
                "    simpa [importBindingContractIdentity] using resolved\n"
                "  have originalStateCommon :=\n"
                "    normalizeImportReturnSlotState_nextMachineState_eq_of_compatible\n"
                f"      {original_behavior} externalCallEdge{edge_id}OriginalNormalized\n"
                "      originalState (by constructor <;> decide)\n"
                "  have candidateStateCommon :=\n"
                "    normalizeImportReturnSlotState_nextMachineState_eq_of_compatible\n"
                f"      {candidate_behavior} externalCallEdge{edge_id}CandidateNormalized\n"
                "      candidateState (by constructor <;> decide)\n"
            )
            boundary_bridge = (
                "    simpa [originalEvent, candidateEvent, originalStateCommon,\n"
                "      candidateStateCommon] using boundary\n"
            )
            final_world_bridge = (
                "  rw [originalTargetAddress, candidateTargetAddress,\n"
                "    originalCodeMissing, candidateCodeMissing,\n"
                "    originalImportResolved, candidateImportResolved]\n"
            )
            frame_event_bridge = (
                ", originalStateCommon, candidateStateCommon"
            )
            result_abi_bridge = (
                "  have originalAbiNormalized : machineCallAbiResultHolds\n"
                f"      externalCallEdge{edge_id}MachineContract\n"
                "      (normalizeImportReturnSlotState\n"
                f"        (({original_behavior}.eval originalState).nextMachineState\n"
                "          originalState))\n"
                "      (originalEnvironment.result eventIndex originalEvent).state = true := by\n"
                "    exact _originalConforms.2.1\n"
                "  have candidateAbiNormalized : machineCallAbiResultHolds\n"
                f"      externalCallEdge{edge_id}MachineContract\n"
                "      (normalizeImportReturnSlotState\n"
                f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
                "          candidateState))\n"
                "      (candidateEnvironment.result eventIndex candidateEvent).state = true := by\n"
                "    exact _candidateConforms.2.1\n"
            )
            original_abi_proof = (
                "(by rw [← originalStateCommon]; exact originalAbiNormalized)"
            )
            candidate_abi_proof = (
                "(by rw [← candidateStateCommon]; exact candidateAbiNormalized)"
            )
            imported_world_bridge = ""
        common = (
            prefix
            + selected_control
            + f"  let frameClaims : List ExternalReturnSlotInventoryTransferClaim := "
            f"{transfer_claims_literal}\n"
            + "  let frameFactClaims : List "
            "RelationalRuntimeCallImportTransferClaim := "
            f"{frame_fact_claims_literal}\n"
            + behavior_bridge
            + f"  have transition := externalCallEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : externalCallEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [externalCallEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have closed := transition.2 guardTrue\n"
            f"  simp only [evalBehavior, externalCallEdge{edge_id}OriginalNormalizedChecked,\n"
            f"    externalCallEdge{edge_id}CandidateNormalizedChecked, Option.bind_some]\n"
            "    at closed\n"
            "  rcases closed with\n"
            "    ⟨originalCallArguments, candidateCallArguments, originalOutcome,\n"
            "      candidateOutcome, _edgeExit, _outcomesRelated, boundary⟩\n"
            f"  have originalArgumentsKnown : [{original_arguments}] =\n"
            f"      originalCallArguments := by\n"
            f"    have decomposed := originalOutcome\n"
            f"    simp only [externalCallEdge{edge_id}OriginalOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalCall.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2.1\n"
            f"  have candidateArgumentsKnown : [{candidate_arguments}] =\n"
            f"      candidateCallArguments := by\n"
            f"    have decomposed := candidateOutcome\n"
            f"    simp only [externalCallEdge{edge_id}CandidateOutcomeChecked,\n"
            "      NormalizedSymbolicBehavior.eval_outcome, NormalizedOutcomeExpr.eval,\n"
            "      Expr.eval, PureOutcome.externalCall.injEq] at decomposed\n"
            "    simpa only [List.map] using decomposed.2.1\n"
            "  subst originalCallArguments\n"
            "  subst candidateCallArguments\n"
            "  let originalEvent : WorldExternalEvent := {\n"
            f"    siteId := {edge_id}\n"
            f"    imported := externalCallEdge{edge_id}MachineContract.imported\n"
            f"    arguments := [{original_arguments}]\n"
            f"    state := {original_event_state}\n"
            "    world\n"
            "  }\n"
            "  let candidateEvent : WorldExternalEvent := {\n"
            f"    siteId := {edge_id}\n"
            f"    imported := externalCallEdge{edge_id}MachineContract.imported\n"
            f"    arguments := [{candidate_arguments}]\n"
            f"    state := {candidate_event_state}\n"
            "    world\n"
            "  }\n"
            "  have boundaryKnown : ExternalCallBoundaryRelated staticProofContext\n"
            f"      externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
            "      originalEvent candidateEvent := by\n"
            + boundary_bridge
        )
        if step["kind"] == "external_protocol":
            return common + (
                "  have argumentsRelated := boundaryKnown.2.2.2.2.2.2\n"
                "  have observationRelated : worldRelationalObservationsRelated\n"
                "      staticProofContext\n"
                f"      (some (.external world externalCallEdge{edge_id}MachineContract.imported\n"
                f"        [{original_arguments}]))\n"
                f"      (some (.external world externalCallEdge{edge_id}MachineContract.imported\n"
                f"        [{candidate_arguments}])) := by\n"
                "    exact ⟨rfl, rfl, argumentsRelated⟩\n"
                "  have originalSiteResolved : resolveExternalCallSite staticProofContext\n"
                f"      externalCallSites {target_id}\n"
                f"      {int(site['continuation_target_id'])}\n"
                f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
                "    decide\n"
                "  have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
                f"      externalCallSites {target_id}\n"
                f"      {int(site['continuation_target_id'])}\n"
                f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
                "    decide\n"
                f"  have contractDisposition : externalCallEdge{edge_id}MachineContract.disposition =\n"
                "      .protocol := by decide\n"
                f"  have originalWritesField : {original_behavior}.writes = [] := by decide\n"
                f"  have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
                f"  have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
                "    simp [originalWritesField, evalNormalizedWrites]\n"
                f"  have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
                "    simp [candidateWritesField, evalNormalizedWrites]\n"
                "  rcases boundaryKnown.2.2.2.2.2.1 with\n"
                "    ⟨_worldValid, _stackRangesValid, outputRegisters, outputBounds,\n"
                "      outputSeparations, outputStackWindows, _undefinedEqual, outputX87,\n"
                "      outputFlags, _fsBaseEqual, outputImports, outputDynamic,\n"
                "      outputDynamicStack⟩\n"
                "  have suspendedStatesRelated : StateRel staticProofContext world\n"
                f"      externalCallSite{edge_id}.boundaryInvariant originalEvent.state\n"
                "      candidateEvent.state := by\n"
                f"    apply StateRel.afterNoWriteEvaluation staticProofContext world\n"
                f"      region{region_index}.inputInvariant\n"
                f"      externalCallSite{edge_id}.boundaryInvariant originalState candidateState\n"
                f"      ({original_behavior}.eval originalState)\n"
                f"      ({candidate_behavior}.eval candidateState) statesRelated\n"
                "      originalWrites candidateWrites\n"
                "    · simp\n"
                "    · simp\n"
                "    · simpa [originalEvent, candidateEvent] using outputRegisters\n"
                "    · simpa [originalEvent, candidateEvent] using outputBounds\n"
                "    · simpa [originalEvent, candidateEvent] using outputSeparations\n"
                "    · simpa [originalEvent, candidateEvent] using outputStackWindows\n"
                "    · simpa [originalEvent, candidateEvent] using outputX87\n"
                "    · simpa [originalEvent, candidateEvent] using outputFlags\n"
                "    · simpa [originalEvent, candidateEvent] using outputImports\n"
                f"    · simp [externalCallSite{edge_id}, registerValueOriginRelationsHold]\n"
                f"    · simp [externalCallSite{edge_id}, memoryValueOriginRelationsHold]\n"
                "    · simpa [originalEvent, candidateEvent] using outputDynamic\n"
                "    · simpa [originalEvent, candidateEvent] using outputDynamicStack\n"
                f"    · simp [externalCallSite{edge_id}, pairedStatePredicatesHold]\n"
                "  rw [originalBehaviorCommon, candidateBehaviorCommon]\n"
                "  simp only [originalWorldProgram, candidateWorldProgram]\n"
                f"  have importedCommon : ({imported_literal} : ExternalTarget) =\n"
                f"      externalCallEdge{edge_id}MachineContract.imported := by decide\n"
                "  rw [importedCommon]\n"
                "  rw [originalSiteResolved]\n"
                "  simp only [List.map_nil]\n"
                "  refine ⟨observationRelated, ?_⟩\n"
                "  refine ⟨?_, ?_, ⟨[], ?_⟩⟩\n"
                "  · refine ⟨rfl, rfl, rfl, rfl, argumentsRelated, rfl, rfl, rfl,\n"
                "      rfl, rfl, rfl, ?_, ?_⟩\n"
                "    · simpa [originalEvent, candidateEvent] using suspendedStatesRelated\n"
                f"    · refine ⟨externalCallSite{edge_id},\n"
                f"        externalCallEdge{edge_id}MachineContract, rfl, ?_, rfl, rfl, rfl,\n"
                f"        externalCallEdge{edge_id}MachineContractResolved, rfl,\n"
                "        contractDisposition, boundaryKnown, ?_⟩\n"
                "      · decide\n"
                "      · intro _phaseZero\n"
                "        exact ⟨rfl, rfl, rfl, rfl, rfl⟩\n"
                "  · simp [WorldExternalCallbackRuntimesRelated]\n"
                "  · simp [WorldExternalCallbackFramesHold]\n"
            )
        opaque_site_id = step.get("opaque_lockstep_site_id")
        if opaque_site_id is not None:
            environment_result_source = (
                "  have environmentAt := ExternalEnvironmentRefines.at staticProofContext\n"
                "    externalCallSites originalEnvironment candidateEnvironment\n"
                "    environmentRefines.externalRefines\n"
                f"    externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
                "    (by decide) externalCallEdge"
                f"{edge_id}MachineContractResolved\n"
                "  have results := externalCallResultsRelated staticProofContext\n"
                f"    externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
                "    originalEnvironment candidateEnvironment environmentAt (by decide) eventIndex\n"
                "    originalEvent candidateEvent boundaryKnown\n"
                "  have opaqueResults :=\n"
                "    OpaqueLockstepExternalEnvironmentsRefine.atReturning\n"
                "      staticProofContext externalCallSites opaqueLockstepCallSites\n"
                "      (opaqueLockstepCallSites.map fun site => site.id)\n"
                "      originalEnvironment candidateEnvironment environmentRefines\n"
                f"      externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
                f"      opaqueLockstepCallSite{int(opaque_site_id)} (by decide) (by decide)\n"
                f"      externalCallEdge{edge_id}MachineContractResolved (by decide) (by decide)\n"
                "      eventIndex originalEvent candidateEvent boundaryKnown\n"
                "  dsimp only at results opaqueResults\n"
                "  rcases results with\n"
                "    ⟨_ordinaryWorldsEqual, _originalConforms, _candidateConforms,\n"
                "      _resultRegistersRelated, _ordinaryStatesRelated,\n"
                "      _ordinaryFramesPreserved⟩\n"
                "  rcases opaqueResults with\n"
                "    ⟨resultWorldsEqual, nextStatesRelated, framesPreserved⟩\n"
            )
        else:
            environment_result_source = (
                "  have environmentAt :=\n"
                "    ExactLockstepExternalEnvironmentsRefine.atReturning\n"
                "      staticProofContext externalCallSites originalEnvironment\n"
                "      candidateEnvironment environmentRefines\n"
                f"      externalCallSite{edge_id}\n"
                f"      externalCallEdge{edge_id}MachineContract (by decide)\n"
                f"      externalCallEdge{edge_id}MachineContractResolved (by decide)\n"
                "  have results := externalCallResultsRelated staticProofContext\n"
                f"    externalCallSite{edge_id} externalCallEdge{edge_id}MachineContract\n"
                "    originalEnvironment candidateEnvironment environmentAt (by decide) eventIndex\n"
                "    originalEvent candidateEvent boundaryKnown\n"
                "  dsimp only at results\n"
                "  rcases results with\n"
                "    ⟨resultWorldsEqual, _originalConforms, _candidateConforms,\n"
                "      _resultRegistersRelated, nextStatesRelated, framesPreserved⟩\n"
            )
        return common + environment_result_source + (
            result_abi_bridge
            + "  have frameFactsAtBoundary : RelationalRuntimeCallFactsHold\n"
            "      staticProofContext world\n"
            f"      {target_offsets_literal} originalEvent.state.registers\n"
            "      candidateEvent.state.registers := by\n"
            "    have transferred := RelationalRuntimeCallFactsHold.afterInternal\n"
            f"      staticProofContext world {proof_original_behavior} "
            f"{proof_candidate_behavior}\n"
            "      frameFactClaims originalState candidateState (by decide)\n"
            "      (by simpa [frameFactClaims] using frameImportsHold)\n"
            "    simpa [originalEvent, candidateEvent"
            f"{frame_event_bridge},\n"
            "      RelationalBehavior.nextMachineState] using transferred\n"
            "  have pairConforms : ExactExternalCallPairConforms staticProofContext\n"
            f"      externalCallEdge{edge_id}MachineContract originalEvent candidateEvent\n"
            "      (originalEnvironment.result eventIndex originalEvent)\n"
            "      (candidateEnvironment.result eventIndex candidateEvent) := {\n"
            "    siteId := rfl\n"
            "    originalImported := rfl\n"
            "    candidateImported := rfl\n"
            "    eventWorld := rfl\n"
            "    resultWorld := resultWorldsEqual\n"
            "    originalConforms := _originalConforms\n"
            "    candidateConforms := _candidateConforms\n"
            "  }\n"
            "  have frameImportsNext : RelationalRuntimeCallFactsHold\n"
            "      staticProofContext\n"
            "      (originalEnvironment.result eventIndex originalEvent).world\n"
            f"      {target_offsets_literal}\n"
            "      (originalEnvironment.result eventIndex originalEvent).state.registers\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state.registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.afterExternal\n"
            f"      staticProofContext externalCallEdge{edge_id}MachineContract\n"
            f"      {target_offsets_literal} originalEvent candidateEvent\n"
            "      (originalEnvironment.result eventIndex originalEvent)\n"
            "      (candidateEnvironment.result eventIndex candidateEvent)\n"
            "      (by decide) frameFactsAtBoundary pairConforms\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            f"      frames {calls_literal} {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterExternalCall\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      {proof_original_behavior} {proof_candidate_behavior}\n"
            f"      externalCallEdge{edge_id}MachineContract frameClaims frames\n"
            f"      {calls_literal} originalState candidateState\n"
            "      (originalEnvironment.result eventIndex originalEvent).state\n"
            "      (candidateEnvironment.result eventIndex candidateEvent).state\n"
            "      (by decide)\n"
            "      (by simpa [frameClaims] using stackHolds)\n"
            f"      {original_abi_proof}\n"
            f"      {candidate_abi_proof}\n"
            "      statesRelated\n"
            "      (by\n"
            "        intro frame inventory frameHolds exactWords\n"
            "        exact framesPreserved frame inventory (by\n"
            "          simpa [originalEvent, candidateEvent] using frameHolds) (by\n"
            "          simpa [originalEvent, candidateEvent] using exactWords))\n"
            "  have argumentsRelated := boundaryKnown.2.2.2.2.2.2\n"
            "  have observationRelated : worldRelationalObservationsRelated\n"
            "      staticProofContext\n"
            f"      (some (.external world externalCallEdge{edge_id}MachineContract.imported\n"
            f"        [{original_arguments}]))\n"
            f"      (some (.external world externalCallEdge{edge_id}MachineContract.imported\n"
            f"        [{candidate_arguments}])) := by\n"
            "    exact ⟨rfl, rfl, argumentsRelated⟩\n"
            "  have originalSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id}\n"
            f"      {int(site['continuation_target_id'])}\n"
            f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
            "    decide\n"
            "  have candidateSiteResolved : resolveExternalCallSite staticProofContext\n"
            f"      externalCallSites {target_id}\n"
            f"      {int(site['continuation_target_id'])}\n"
            f"      externalCallEdge{edge_id}MachineContract.imported = some {edge_id} := by\n"
            "    decide\n"
            + "  simp only [originalWorldProgram, candidateWorldProgram,\n"
            "    Bool.false_eq_true, if_false, if_true]\n"
            + final_world_bridge
            + imported_world_bridge
            + "  rw [originalSiteResolved]\n"
            "  simp only [List.map_nil]\n"
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                observation_proof="observationRelated",
                world_equal_proof="resultWorldsEqual",
                frame_imports_proof="frameImportsNext",
            )
        )
    if step["kind"] == "terminate":
        output_claims = ", ".join(
            _lean_register_output_claim(claim) for claim in step["output_claims"]
        )
        return (
            prefix
            + empty_control
            + "  have relatedForTransfer := statesRelated\n"
            "  rcases statesRelated with\n"
            "    ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,\n"
            "      _importsComplete, _importsMemory, _originalImmutable,\n"
            "      _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
            "  rcases relatedCore with\n"
            "    ⟨_inputRegisters, _inputBounds, _inputSeparations, _inputStackWindows,\n"
            "      _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
            "      _inputFlags, _inputFsBase⟩\n"
            f"  let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
            "  have outputRegisters : registerRelationsHold\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (staticProofContext.relationalValueTargets world)\n"
            "      terminalInvariant.registerRelations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    have inventory : outputClaims.map InvariantWP.RegisterOutputClaim.output =\n"
            "        terminalInvariant.registerRelations := by decide\n"
            "    rw [← inventory]\n"
            "    exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"      staticProofContext world region{region_index} {original_behavior}\n"
            f"      {candidate_behavior} outputClaims (by decide) originalState\n"
            "      candidateState relatedForTransfer\n"
            "  have outputBounds : boundsRelated\n"
            "      terminalInvariant.bounds\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, boundsRelated]\n"
            "  have outputSeparations : addressSeparationsRelated\n"
            "      terminalInvariant.addressSeparations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, addressSeparationsRelated]\n"
            "  have outputStackWindows : stackWindowsRelated world\n"
            "      terminalInvariant.stackWindows\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, stackWindowsRelated]\n"
            f"  have originalX87Field : {original_behavior}.x87 =\n"
            f"      originalBehavior{region_index}.x87 := by decide\n"
            f"  have candidateX87Field : {candidate_behavior}.x87 =\n"
            f"      candidateBehavior{region_index}.x87 := by decide\n"
            "  have outputX87 :\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).x87 =\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).x87 := by\n"
            "    have inputLegacyX87 := inputX87.1\n"
            "    simp [originalX87Field, candidateX87Field,\n"
            f"      originalBehavior{region_index}, candidateBehavior{region_index},\n"
            "      RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
            "      X87Expr.eval, Expr.eval, inputLegacyX87]\n"
            "  have outputFlags : flagsRelated\n"
            "      terminalInvariant.flagBits\n"
            f"      ({original_behavior}.eval originalState).eflags\n"
            f"      ({candidate_behavior}.eval candidateState).eflags = true := by\n"
            f"    simp [terminalInvariant, region{region_index}, flagsRelated]\n"
            f"  have originalWritesField : {original_behavior}.writes = [] := by decide\n"
            f"  have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
            f"  have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
            "    simp [originalWritesField, evalNormalizedWrites]\n"
            f"  have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
            "    simp [candidateWritesField, evalNormalizedWrites]\n"
            "  have outputImports : importRegisterRelationsHold world\n"
            "      terminalInvariant.importRegisterRelations\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers = true := by\n"
            "    simp [terminalInvariant, importRegisterRelationsHold]\n"
            "  have outputDynamic : activeDynamicRegisterRangeRelationsHold "
            "staticProofContext world\n"
            "      terminalInvariant.dynamicRegisterRangeRelations\n"
            f"      (({original_behavior}.eval originalState).nextMachineState "
            "originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState "
            "candidateState) = true := by\n"
            "    simp [terminalInvariant, activeDynamicRegisterRangeRelationsHold]\n"
            "  have outputDynamicStack : activeDynamicStackRangeRelationsHold "
            "staticProofContext world\n"
            "      terminalInvariant.dynamicStackRangeRelations\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
            "    simp [terminalInvariant, activeDynamicStackRangeRelationsHold]\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            "      terminalInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
            "    StateRel.afterNoWriteEvaluation staticProofContext world\n"
            f"      region{region_index}.inputInvariant terminalInvariant\n"
            f"      originalState candidateState ({original_behavior}.eval originalState)\n"
            f"      ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
            "      originalWrites candidateWrites (by simp) (by simp)\n"
            "      outputRegisters outputBounds\n"
            "      outputSeparations outputStackWindows outputX87 outputFlags\n"
            "      outputImports\n"
            "      (by simp [terminalInvariant, registerValueOriginRelationsHold])\n"
            "      (by simp [terminalInvariant, memoryValueOriginRelationsHold])\n"
            "      outputDynamic outputDynamicStack\n"
            "      (by simp [terminalInvariant, pairedStatePredicatesHold])\n"
            "  have returnCodeEqual :\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState).registers.eax =\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState).registers.eax := by\n"
            "    rcases nextStatesRelated with\n"
            "      ⟨_worldValid, _stackRangesValid, _stackMemory, _importsStatic,\n"
            "        _importsComplete, _importsMemory, _originalImmutable,\n"
            "        _candidateImmutable, outputCore, _outputSpecialRegisters⟩\n"
            "    exact registerRelationsHold_exact_identity\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (staticProofContext.relationalValueTargets world)\n"
            "      terminalInvariant.registerRelations _ _ .eax outputCore.1 (by decide)\n"
            "  simp [originalWorldProgram, candidateWorldProgram,\n"
            "    transitionFromWorldOutcome]\n"
            "  constructor\n"
            "  · exact ⟨rfl, returnCodeEqual⟩\n"
            "  · exact ⟨rfl, nextStatesRelated⟩\n"
        )
    if step["kind"] == "indirect_jump":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        target_id = int(edge["target_target_id"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        frame_claims = step["return_slot_frame_transfer_claims"]
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            frame_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        original_product_behavior = f"productNode{node_id}OriginalNormalized"
        candidate_product_behavior = f"productNode{node_id}CandidateNormalized"
        fixed_code_address = (
            step["decoded_control"].get("profile") ==
            "fixed_code_address_indirect_jump_v1"
        )
        claim = (
            f"productNode{node_id}FixedCodeAddressIndirectJumpClaim"
            if fixed_code_address else
            f"productNode{node_id}ImmutableIndirectJumpClaim"
        )
        target_closed = (
            f"productNode{node_id}FixedCodeAddressIndirectJumpClosed"
            if fixed_code_address else
            f"productNode{node_id}ImmutableIndirectJumpClosed"
        )
        return (
            prefix
            + selected_control
            + f"  let frameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
            "  let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"    {frame_import_claims_literal}\n"
            + f"  have originalBehaviorCommon : {original_behavior} =\n"
            f"      {original_product_behavior} := by decide\n"
            f"  have candidateBehaviorCommon : {candidate_behavior} =\n"
            f"      {candidate_product_behavior} := by decide\n"
            f"  have indirectTargets := {target_closed} world originalState\n"
            "    candidateState statesRelated\n"
            "  have originalTargetExpression :\n"
            f"      ({_lean_semantic_expr(step['decoded_control']['original_target_expression'])}).eval "
            "originalState =\n"
            "        BitVec.ofNat 32 (staticProofContext.originalPe.imageBase +\n"
            f"          staticProofContext.codeMap.entries[{claim}.targetId].originalRva) := by\n"
            "    rw [← originalBehaviorCommon] at indirectTargets\n"
            f"    simpa only [acceptanceOriginalNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.indirectJump.injEq] using\n"
            "      indirectTargets.1\n"
            "  have candidateTargetExpression :\n"
            f"      ({_lean_semantic_expr(step['decoded_control']['candidate_target_expression'])}).eval "
            "candidateState =\n"
            "        BitVec.ofNat 32 (staticProofContext.candidatePe.imageBase +\n"
            f"          staticProofContext.codeMap.entries[{claim}.targetId].candidateRva) := by\n"
            "    rw [← candidateBehaviorCommon] at indirectTargets\n"
            f"    simpa only [acceptanceCandidateNormalizedOutcome{node_id},\n"
            "      NormalizedOutcomeExpr.eval, PureOutcome.indirectJump.injEq] using\n"
            "      indirectTargets.2\n"
            "  have originalTargetResolved : resolveMappedCodeTarget false\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (BitVec.ofNat 32 (staticProofContext.originalPe.imageBase +\n"
            f"        staticProofContext.codeMap.entries[{claim}.targetId].originalRva)) =\n"
            f"        some {target_id} := by decide\n"
            "  have candidateTargetResolved : resolveMappedCodeTarget true\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (BitVec.ofNat 32 (staticProofContext.candidatePe.imageBase +\n"
            f"        staticProofContext.codeMap.entries[{claim}.targetId].candidateRva)) =\n"
            f"        some {target_id} := by decide\n"
            f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            f"      region{target_region_index}.inputInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState) := by\n"
            "    simpa [originalBehaviorCommon, candidateBehaviorCommon] using\n"
            "      transitioned.2.2.2\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "      staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) frames {calls_literal}\n"
            f"      {target_offsets_literal} := by\n"
            "    exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"      staticProofContext world region{region_index}.inputInvariant\n"
            f"      {original_behavior} {candidate_behavior}\n"
            f"      frameClaims frames {calls_literal} originalState candidateState\n"
            "      (by decide) (by simpa [frameClaims] using stackHolds) statesRelated\n"
            "  have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      {target_offsets_literal}\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            "    exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"      {original_behavior} {candidate_behavior} frameImportClaims\n"
            "      originalState candidateState (by decide)\n"
            "      (by simpa [frameImportClaims] using frameImportsHold)\n"
            "  rw [originalTargetExpression, candidateTargetExpression]\n"
            "  simp only [originalWorldProgram, candidateWorldProgram,\n"
            "    Bool.false_eq_true, if_false, if_true]\n"
            "  rw [originalTargetResolved, candidateTargetResolved]\n"
            "  simp only\n"
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                frame_imports_proof="frameImportsNext",
            )
        )
    if (
        step["kind"] == "jump"
        and step.get("certificate_profile")
            == "composable_x87_state_only_singleton_v1"
    ):
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        continuation_target_id = int(edge["target_target_id"])
        target_region_index = int(edge["target_region_index"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["target_control_state"]["frame_offsets"]
        ) + "]"
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        original_execution = (
            "StageA.Relational.X87.executeSingletonCommand false "
            "staticProofContext.originalPe "
            f"segmentRefinementEdge{edge_id}Spec.originalSpan "
            f"region{region_index}.targets originalState"
        )
        candidate_execution = (
            "StageA.Relational.X87.executeSingletonCommand true "
            "staticProofContext.candidatePe "
            f"segmentRefinementEdge{edge_id}Spec.candidateSpan "
            f"region{region_index}.targets candidateState"
        )
        target_proof = _lean_acceptance_running_target(
            node_id=node_id,
            region_index=region_index,
            edge=edge,
            frames="frames",
            calls=calls_literal,
            frame_offsets=target_offsets_literal,
            stack_targets_proof="stackTargetsReachable",
            frame_imports_proof="frameImportsNext",
        )
        return (
            prefix
            + selected_control
            + f"  have transitionClosed := segmentRefinementEdge{edge_id}TransitionChecked\n"
            "  unfold X87SegmentTransitionClosed at transitionClosed\n"
            f"  rw [segmentRefinementEdge{edge_id}LocalCodeTargetsResolved,\n"
            f"    segmentRefinementEdge{edge_id}LocalValuesResolved] at transitionClosed\n"
            "  have transition := transitionClosed world originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            f"  cases originalExecuted : {original_execution} with\n"
            "  | none =>\n"
            "      simp [originalExecuted] at transitioned\n"
            "  | some originalResult =>\n"
            f"      cases candidateExecuted : {candidate_execution} with\n"
            "      | none =>\n"
            "          simp [originalExecuted, candidateExecuted] at transitioned\n"
            "      | some candidateResult =>\n"
            "          rw [originalExecuted, candidateExecuted] at transitioned\n"
            "          simp only at transitioned\n"
            "          have faultsRelated := transitioned.1\n"
            "          simp only\n"
            f"          have originalOutcome : originalResult.outcome = "
            f".jump {continuation_target_id} :=\n"
            "            StageA.Relational.X87."
            "executeSingletonCommand_outcome_of_continuation\n"
            f"              false staticProofContext.originalPe "
            f"segmentRefinementEdge{edge_id}Spec.originalSpan\n"
            f"              region{region_index}.targets originalState "
            f"originalResult {continuation_target_id}\n"
            f"              segmentRefinementEdge{edge_id}OriginalContinuation "
            "originalExecuted\n"
            f"          have candidateOutcome : candidateResult.outcome = "
            f".jump {continuation_target_id} :=\n"
            "            StageA.Relational.X87."
            "executeSingletonCommand_outcome_of_continuation\n"
            f"              true staticProofContext.candidatePe "
            f"segmentRefinementEdge{edge_id}Spec.candidateSpan\n"
            f"              region{region_index}.targets candidateState "
            f"candidateResult {continuation_target_id}\n"
            f"              segmentRefinementEdge{edge_id}CandidateContinuation "
            "candidateExecuted\n"
            "          cases originalFault : originalResult.x87Fault with\n"
            "          | some fault =>\n"
            "              have candidateFault : candidateResult.x87Fault = "
            "some fault := by\n"
            "                rw [← faultsRelated]\n"
            "                exact originalFault\n"
            "              cases fault\n"
            "              simp [transitionFromWorldBehavior, originalFault, "
            "candidateFault,\n"
            "                worldRelationalObservationsRelated, "
            "WorldExecutionsRelated]\n"
            "          | none =>\n"
            "              have candidateFault : candidateResult.x87Fault = none := by\n"
            "                rw [← faultsRelated]\n"
            "                exact originalFault\n"
            "              rw [originalFault, candidateFault] at transitioned\n"
            "              rcases transitioned.2 with\n"
            "                ⟨_originalExit, _candidateExit, _outcomes, "
            "nextStatesRelated,\n"
            "                  originalRegisters, candidateRegisters, "
            "originalMemory, candidateMemory⟩\n"
            "              have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "                  staticProofContext\n"
            "                  (originalResult.nextMachineState originalState)\n"
            "                  (candidateResult.nextMachineState candidateState) "
            f"frames {calls_literal}\n"
            f"                  {target_offsets_literal} := by\n"
            "                cases frames <;>\n"
            "                  simp [RelationalRuntimeCallStackHolds] at "
            "stackHolds ⊢\n"
            "              have frameImportsNext : RelationalRuntimeCallFactsHold\n"
            "                  staticProofContext world "
            f"{target_offsets_literal}\n"
            "                  (originalResult.nextMachineState "
            "originalState).registers\n"
            "                  (candidateResult.nextMachineState "
            "candidateState).registers := by\n"
            "                rw [originalRegisters, candidateRegisters]\n"
            "                simpa using frameImportsHold\n"
            "              unfold transitionFromWorldBehavior\n"
            "              rw [originalFault, candidateFault]\n"
            "              rw [originalOutcome, candidateOutcome]\n"
            "              simp only [transitionFromWorldOutcome]\n"
            + "\n".join("              " + line[2:] if line.startswith("  ") else
                "              " + line for line in target_proof.splitlines())
        )
    if step["kind"] == "jump":
        edge = step["edges"][0]
        edge_id = int(edge["edge_id"])
        target_region_index = int(edge["target_region_index"])
        control_calls = [int(item) for item in step["control_state"]["calls"]]
        calls_literal = "[" + ", ".join(
            str(item) for item in control_calls
        ) + "]"
        source_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in step["control_state"]["frame_offsets"]
        ) + "]"
        frame_claims = step["return_slot_frame_transfer_claims"]
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in frame_claims
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            frame_claims
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item["target"])
            for item in frame_claims
        ) + "]"
        selected_control = (
            ""
            if step.get("control_already_selected") else
            f"  have controlShape : calls = {calls_literal} ∧\n"
            f"      frameOffsets = {source_offsets_literal} := by\n"
            "    simpa [productControlProfile] using controlMember.2\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
        )
        empty_runtime_inventory = (
            not control_calls
            and not step["control_state"]["frame_offsets"]
            and not frame_claims
        )
        if empty_runtime_inventory:
            stack_transfer = (
                "    exact RelationalRuntimeCallStackHolds.emptyInventoryTransition\n"
                "      staticProofContext originalState candidateState\n"
                f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
                f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
                "      frames stackHolds\n"
            )
            facts_transfer = (
                "    exact RelationalRuntimeCallFactsHold.empty staticProofContext world\n"
                f"      ({original_behavior}.eval originalState).registers\n"
                f"      ({candidate_behavior}.eval candidateState).registers\n"
            )
        else:
            stack_transfer = (
                "    exact RelationalRuntimeCallStackHolds.afterInternal\n"
                f"      staticProofContext world region{region_index}.inputInvariant\n"
                f"      {original_behavior} {candidate_behavior}\n"
                f"      frameClaims frames {calls_literal} originalState candidateState\n"
                "      (by decide) (by simpa [frameClaims] using stackHolds) statesRelated\n"
            )
            facts_transfer = (
                "    exact RelationalRuntimeCallFactsHold.afterInternal "
                "staticProofContext world\n"
                f"      {original_behavior} {candidate_behavior} frameImportClaims\n"
                "      originalState candidateState (by decide)\n"
                "      (by simpa [frameImportClaims] using frameImportsHold)\n"
            )
        return (
            prefix
            + selected_control
            + f"  let frameClaims : List ReturnSlotFrameInventoryTransferClaim :=\n"
            f"    {frame_claims_literal}\n"
            f"  let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"    {frame_import_claims_literal}\n"
            + f"  have originalBehaviorSegment : {original_behavior} =\n"
            f"      segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
            f"  have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"      segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
            + f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
            "    originalState candidateState statesRelated\n"
            f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "      originalState = true := by\n"
            f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
            "  have transitioned := transition.2 guardTrue\n"
            "  have nextStatesRelated : StateRel staticProofContext world\n"
            f"      region{target_region_index}.inputInvariant\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "        candidateState) := by\n"
            "    rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "    exact transitioned.2.2.2\n"
            "  have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "      staticProofContext\n"
            f"      (({original_behavior}.eval originalState).nextMachineState\n"
            "        originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"        candidateState) frames {calls_literal}\n"
            f"      {target_offsets_literal} := by\n"
            + stack_transfer
            + "  have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"      {target_offsets_literal}\n"
            f"      ({original_behavior}.eval originalState).registers\n"
            f"      ({candidate_behavior}.eval candidateState).registers := by\n"
            + facts_transfer
            + _lean_acceptance_running_target(
                node_id=node_id,
                region_index=region_index,
                edge=edge,
                frames="frames",
                calls=calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                frame_imports_proof="frameImportsNext",
            )
        )

    taken, fallthrough = step["edges"]
    taken_id = int(taken["edge_id"])
    fallthrough_id = int(fallthrough["edge_id"])
    branch_calls = [int(item) for item in step["control_state"]["calls"]]
    branch_calls_literal = "[" + ", ".join(
        str(item) for item in branch_calls
    ) + "]"
    branch_source_offsets_literal = "[" + ", ".join(
        _lean_return_slot_offset_inventory(item)
        for item in step["control_state"]["frame_offsets"]
    ) + "]"
    branch_control = (
        ""
        if step.get("control_already_selected") else
        f"  have controlShape : calls = {branch_calls_literal} ∧\n"
        f"      frameOffsets = {branch_source_offsets_literal} := by\n"
        "    simpa [productControlProfile] using controlMember.2\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
    )

    def branch_case(edge: dict[str, Any], condition: bool) -> str:
        edge_id = int(edge["edge_id"])
        if edge.get("infeasible") is True:
            return (
                f"    simp [region{region_index}OutcomeCondition, BoolExpr.eval, "
                "Expr.eval] at originalCondition\n"
            )
        target_region_index = int(edge["target_region_index"])
        candidate_condition = bool(
            edge.get("candidate_branch_value", condition)
        )
        candidate_condition_literal = (
            "true" if candidate_condition else "false"
        )
        candidate_condition_name = (
            f"segmentRefinementEdge{edge_id}CandidateOutcomeCondition"
        )
        if _normalized_behavior_fast_path(
            regions[region_index], behaviors[region_index]
        ):
            segment_original_behavior = f"region{region_index}NormalizedBehavior"
            segment_candidate_behavior = f"region{region_index}NormalizedBehavior"
        else:
            segment_original_behavior = (
                f"segmentRefinementEdge{edge_id}OriginalNormalizedBehavior"
            )
            segment_candidate_behavior = (
                f"segmentRefinementEdge{edge_id}CandidateNormalizedBehavior"
            )
        original_guard = (
            "      rw [show "
            f"segmentRefinementEdge{edge_id}Spec.originalGuard = "
            f"normalizedBranchGuard region{region_index}OutcomeCondition "
            f"{'true' if condition else 'false'} by decide]\n"
            "      exact normalizedBranchGuard_eval_of_condition "
            f"region{region_index}OutcomeCondition "
            f"{'true' if condition else 'false'} originalState originalCondition\n"
        )
        frame_claims_literal = "[" + ", ".join(
            _lean_return_slot_frame_inventory_transfer_claim(item)
            for item in edge["return_slot_frame_transfer_claims"]
        ) + "]"
        frame_import_claims_literal = _lean_runtime_call_import_transfer_claims(
            edge["return_slot_frame_transfer_claims"]
        )
        target_offsets_literal = "[" + ", ".join(
            _lean_return_slot_offset_inventory(item)
            for item in edge["target_control_state"]["frame_offsets"]
        ) + "]"
        stack_proof = (
            "    let frameClaims : List "
            "ReturnSlotFrameInventoryTransferClaim :=\n"
            f"      {frame_claims_literal}\n"
            "    let frameImportClaims : List "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"      {frame_import_claims_literal}\n"
            "    have stackHoldsNext : RelationalRuntimeCallStackHolds\n"
            "        staticProofContext\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            f"          candidateState) frames {branch_calls_literal}\n"
            f"        {target_offsets_literal} := by\n"
            "      exact RelationalRuntimeCallStackHolds.afterInternal\n"
            f"        staticProofContext world region{region_index}.inputInvariant\n"
            f"        {original_behavior} {candidate_behavior}\n"
            f"        frameClaims frames {branch_calls_literal} originalState\n"
            "        candidateState (by decide)\n"
            "        (by simpa [frameClaims] using stackHolds) statesRelated\n"
            "    have frameImportsNext : RelationalRuntimeCallFactsHold "
            "staticProofContext world\n"
            f"        {target_offsets_literal}\n"
            f"        ({original_behavior}.eval originalState).registers\n"
            f"        ({candidate_behavior}.eval candidateState).registers := by\n"
            "      exact RelationalRuntimeCallFactsHold.afterInternal "
            "staticProofContext world\n"
            f"        {original_behavior} {candidate_behavior} frameImportClaims\n"
            "        originalState candidateState (by decide)\n"
            "        (by simpa [frameImportClaims] using frameImportsHold)"
        )
        target_proof = "\n".join(
            "  " + line
            for line in _lean_acceptance_running_target(
                node_id=node_id, region_index=region_index, edge=edge,
                frames="frames", calls=branch_calls_literal,
                frame_offsets=target_offsets_literal,
                stack_targets_proof="stackTargetsReachable",
                frame_imports_proof="frameImportsNext",
            ).splitlines()
        )
        return (
            f"    have originalBehaviorSegment : {original_behavior} =\n"
            f"        {segment_original_behavior} := by decide\n"
            f"    have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"        {segment_candidate_behavior} := by decide\n"
            f"    have originalGuard : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
            "        originalState = true := by\n"
            + original_guard
            + f"    have candidateGuard : segmentRefinementEdge{edge_id}Spec.candidateGuard.eval\n"
            "        candidateState = true := by\n"
            f"      rw [← transition{edge_id}.1]\n"
            "      exact originalGuard\n"
            f"    have candidateCondition : {candidate_condition_name}.eval\n"
            f"        candidateState = {candidate_condition_literal} := by\n"
            "      exact normalizedBranchCondition_eval_of_guard_true\n"
            f"        {candidate_condition_name}\n"
            f"        segmentRefinementEdge{edge_id}Spec.candidateGuard\n"
            f"        {candidate_condition_literal} candidateState (by decide) candidateGuard\n"
            f"    have transitioned := transition{edge_id}.2 originalGuard\n"
            "    have nextStatesRelated : StateRel staticProofContext world\n"
            f"        region{target_region_index}.inputInvariant\n"
            f"        (({original_behavior}.eval originalState).nextMachineState\n"
            "          originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "          candidateState) := by\n"
            "      rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "      exact transitioned.2.2.2\n"
            + stack_proof
            + "\n"
            f"    simp only [region{region_index}OutcomeCondition, "
            f"{candidate_condition_name}] at "
            "originalCondition candidateCondition\n"
            "    simp [originalCondition, candidateCondition]\n"
            + target_proof
        )

    return (
        prefix
        + branch_control
        + f"  have transition{taken_id} := segmentRefinementEdge{taken_id}TransitionChecked world\n"
        "    originalState candidateState statesRelated\n"
        f"  have transition{fallthrough_id} := segmentRefinementEdge{fallthrough_id}TransitionChecked world\n"
        "    originalState candidateState statesRelated\n"
        f"  cases originalCondition : region{region_index}OutcomeCondition.eval originalState with\n"
        "  | false =>\n"
        + branch_case(fallthrough, False)
        + "\n  | true =>\n"
        + branch_case(taken, True)
    )
