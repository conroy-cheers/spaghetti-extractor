from __future__ import annotations

import json
import re
import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ..definedness import analyze_definedness_jsonl


RELATIONAL_DEFINEDNESS_LEAN_FORMAT = "stage-a-relational-definedness-lean-v4"
_LEAN_NAMESPACE = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
_LOCATIONS = {
    ("register", name): f".{name}"
    for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
} | {("flag", name): f".{name}" for name in ("cf", "zf", "sf", "of", "pf", "df")}
_TERMINALS = {"none": ".none", "return": ".returnState", "terminate": ".terminate"}
_POLICIES = {"arbitrary": ".arbitrary", "synchronized": ".synchronized"}
_OBLIGATION_KINDS = {
    "exact_replay_transfer": ".exactReplayTransfer",
    "call_frame_noninterference": ".callFrameNoninterference",
    "fault_dominance": ".faultDominance",
    "return_continuation_noninterference": ".returnContinuationNoninterference",
}


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    return value


def _sequence(value: object, context: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a JSON array")
    return value


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _lean_location(value: object, context: str) -> str:
    location = _object(value, context)
    constructor = _LOCATIONS.get((location.get("family"), location.get("name")))
    if constructor is None:
        raise StageAInputError(f"{context} is not a supported register or flag")
    return constructor


def _lean_locations(value: object, context: str) -> str:
    return "[" + ", ".join(
        _lean_location(item, f"{context}[{index}]")
        for index, item in enumerate(_sequence(value, context))
    ) + "]"


def _lean_dependency(value: object, context: str) -> str:
    dependency = _object(value, context)
    slot = dependency.get("slot")
    if not isinstance(slot, bool):
        raise StageAInputError(f"{context}.slot must be Boolean")
    return (
        "{ locations := "
        + _lean_locations(dependency.get("locations"), f"{context}.locations")
        + ", slot := "
        + ("true" if slot else "false")
        + " }"
    )


def _lean_node(value: object, context: str) -> str:
    node = _object(value, context)
    key = node.get("key")
    transfer_id = node.get("transfer_id")
    if not isinstance(key, str) or not key or not isinstance(transfer_id, str) or not transfer_id:
        raise StageAInputError(f"{context} has no stable key and transfer id")
    writes: list[str] = []
    for index, raw in enumerate(_sequence(node.get("writes"), f"{context}.writes")):
        write = _object(raw, f"{context}.writes[{index}]")
        writes.append(
            "{ target := "
            + _lean_location(write.get("target"), f"{context}.writes[{index}].target")
            + ", dependencies := "
            + _lean_dependency(write.get("dependency"), f"{context}.writes[{index}].dependency")
            + " }"
        )
    observations: list[str] = []
    for index, raw in enumerate(_sequence(node.get("observations"), f"{context}.observations")):
        observation = _object(raw, f"{context}.observations[{index}]")
        kind = observation.get("kind")
        if not isinstance(kind, str):
            raise StageAInputError(f"{context}.observations[{index}].kind must be a string")
        observations.append(
            "{ kind := " + _lean_string(kind) + ", dependencies := "
            + _lean_dependency(observation.get("dependency"), f"{context}.observations[{index}].dependency")
            + " }"
        )
    edges: list[str] = []
    for index, raw in enumerate(_sequence(node.get("edges"), f"{context}.edges")):
        edge = _object(raw, f"{context}.edges[{index}]")
        successor = edge.get("successor")
        if not isinstance(successor, str):
            raise StageAInputError(f"{context}.edges[{index}].successor must be a string")
        edges.append(
            "{ successor := " + _lean_string(successor) + ", guard := "
            + _lean_dependency(edge.get("guard"), f"{context}.edges[{index}].guard")
            + " }"
        )
    terminal = _TERMINALS.get(node.get("terminal"))
    if terminal is None:
        raise StageAInputError(f"{context}.terminal is unsupported")
    return "\n".join(
        [
            "{ key := " + _lean_string(key),
            "  step := {",
            "    id := " + _lean_string(transfer_id),
            "    writes := [" + ", ".join(writes) + "]",
            "    observations := [" + ", ".join(observations) + "]",
            "    edges := [" + ", ".join(edges) + "]",
            "    terminal := " + terminal,
            "  }",
            "  liveIn := " + _lean_locations(node.get("live_in"), f"{context}.live_in"),
            "  liveOut := " + _lean_locations(node.get("live_out"), f"{context}.live_out"),
            "}",
        ]
    )


def _lean_graph(value: object, context: str) -> str:
    graph = _object(value, context)
    roots = _sequence(graph.get("roots"), f"{context}.roots")
    if not roots or any(not isinstance(root, str) or not root for root in roots):
        raise StageAInputError(f"{context} has invalid roots")
    nodes = [
        _lean_node(item, f"{context}.nodes[{index}]")
        for index, item in enumerate(_sequence(graph.get("nodes"), f"{context}.nodes"))
    ]
    if not nodes:
        raise StageAInputError(f"{context} has no nodes")
    return (
        "{ roots := [" + ", ".join(_lean_string(str(root)) for root in roots) + "]"
        + ", nodes := [\n" + ",\n".join(nodes) + "] }"
    )


def _lean_relevant_site(value: object, context: str) -> str:
    site = _object(value, context)
    transfer_id = site.get("transfer_id")
    rva = site.get("rva_start")
    pointer = site.get("json_pointer")
    category = site.get("category")
    if not isinstance(transfer_id, str) or not transfer_id:
        raise StageAInputError(f"{context}.transfer_id must be nonempty")
    if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
        raise StageAInputError(f"{context}.rva_start must be nonnegative")
    if not isinstance(pointer, str) or not isinstance(category, str):
        raise StageAInputError(f"{context} pointer/category must be strings")
    return (
        "{ transferId := "
        + _lean_string(transfer_id)
        + f", rva := {rva}, jsonPointer := "
        + _lean_string(pointer)
        + ", category := "
        + _lean_string(category)
        + " }"
    )


def _lean_obligation(value: object, context: str) -> str:
    obligation = _object(value, context)
    kind = obligation.get("kind")
    transfer_id = obligation.get("transfer_id")
    rva = obligation.get("rva_start")
    pointer = obligation.get("json_pointer")
    detail = obligation.get("detail")
    if not all(isinstance(item, str) for item in (kind, transfer_id, pointer, detail)):
        raise StageAInputError(f"{context} string fields are invalid")
    lean_kind = _OBLIGATION_KINDS.get(str(kind))
    if lean_kind is None:
        raise StageAInputError(f"{context}.kind is unsupported")
    if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
        raise StageAInputError(f"{context}.rva_start must be nonnegative")
    return (
        "{ kind := "
        + lean_kind
        + ", transferId := "
        + _lean_string(str(transfer_id))
        + f", rva := {rva}, jsonPointer := "
        + _lean_string(str(pointer))
        + ", detail := "
        + _lean_string(str(detail))
        + " }"
    )


def _lean_choice_source(value: object, context: str, *, policy: str) -> str:
    source = _object(value, context)
    kind = source.get("kind")
    if policy == "arbitrary":
        if (
            source.get("format") != "stage-a-definedness-choice-source-v1"
            or kind != "noninterfering_zero"
        ):
            raise StageAInputError(f"{context} is not a checked zero source")
        return ".noninterferingZero"
    if policy != "synchronized":
        raise StageAInputError(f"{context} has an unsupported policy")
    if (
        source.get("format") != "stage-a-definedness-choice-source-v3"
        or kind != "related_machine_input"
        or source.get("profile") != "ia32-bsr-zero-preserves-destination-v1"
    ):
        raise StageAInputError(
            f"{context} is not a checked related-machine-input source"
        )
    instruction_rva = source.get("instruction_rva")
    instruction_bytes = source.get("instruction_bytes")
    input_expression = source.get("input_expression")
    input_expression_sha256 = source.get("input_expression_sha256")
    if (
        not isinstance(instruction_rva, int)
        or isinstance(instruction_rva, bool)
        or instruction_rva < 0
        or not isinstance(instruction_bytes, str)
        or re.fullmatch(r"[0-9a-f]+", instruction_bytes) is None
        or len(instruction_bytes) % 2
        or not isinstance(input_expression, Mapping)
        or not isinstance(input_expression_sha256, str)
        or hashlib.sha256(
            json.dumps(
                input_expression,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        != input_expression_sha256
    ):
        raise StageAInputError(f"{context} has invalid exact instruction bytes")
    byte_values = ", ".join(
        str(int(instruction_bytes[index : index + 2], 16))
        for index in range(0, len(instruction_bytes), 2)
    )
    return (
        ".relatedMachineInput { location := "
        + _lean_location(source.get("location"), f"{context}.location")
        + f", instructionRva := {instruction_rva}, instructionBytes := [{byte_values}] }}"
    )


def relational_definedness_preflight(state_machine: str | Path) -> dict[str, Any]:
    evidence = analyze_definedness_jsonl(state_machine)
    frontiers: list[dict[str, Any]] = []
    semantic_requirements: list[dict[str, Any]] = []
    derived_choices: list[dict[str, Any]] = []
    for raw_slot in _sequence(evidence.get("slots"), "definedness slots"):
        slot = _object(raw_slot, "definedness slot")
        classification = slot.get("classification")
        obligations = slot.get("proof_obligations")
        relevant = slot.get("behavior_relevant_sites")
        if obligations:
            semantic_requirements.append(
                {
                    "slot": slot.get("slot"),
                    "undefined_id": slot.get("undefined_id"),
                    "obligations": obligations,
                    "closure_rule": "exact-step-dependency-sound-v1",
                }
            )
        if classification == "synchronized_behavior_relevant":
            derived_choices.append(
                {
                    "slot": slot.get("slot"),
                    "undefined_id": slot.get("undefined_id"),
                    "choice_source": slot.get("choice_source"),
                    "exact_instruction_binding_required": True,
                }
            )
        if classification == "unknown":
            frontiers.append(
                {
                    "slot": slot.get("slot"),
                    "undefined_id": slot.get("undefined_id"),
                    "classification": classification,
                    "witness_policy": slot.get("witness_policy"),
                    "choice_source": slot.get("choice_source"),
                    "occurrences": slot.get("occurrences"),
                    "behavior_relevant_sites": relevant or [],
                    "proof_obligations": obligations or [],
                    "blocking_paths": slot.get("blocking_paths"),
                    "closure_requirements": slot.get("closure_requirements"),
                }
            )
    unknown = evidence["counts"]["unknown_slots"]
    undefined_slots = evidence["counts"]["undefined_slots"]
    acceptance_constructible = undefined_slots == 0
    return {
        "format": RELATIONAL_DEFINEDNESS_LEAN_FORMAT,
        "status": (
            "ready"
            if acceptance_constructible
            else ("violated" if unknown else "incomplete")
        ),
        "proof_authority": False,
        "acceptance_constructible": acceptance_constructible,
        "source_sha256": evidence["source_sha256"],
        "canonical_transfers_sha256": evidence["canonical_transfers_sha256"],
        "evidence_sha256": evidence["evidence_sha256"],
        "counts": {
            "undefined_slots": undefined_slots,
            "lean_certificates": evidence["counts"]["lean_certifiable_slots"],
            "unknown_frontiers": unknown,
            # Premise-taking semantic/runtime bindings are composition inputs,
            # not an acceptance proof for the inventoried slots.
            "unresolved_acceptance_slots": undefined_slots,
            "semantic_obligation_slots": len(semantic_requirements),
            "semantic_obligation_records": sum(
                len(item["obligations"]) for item in semantic_requirements
            ),
            "input_derived_slots": len(derived_choices),
            "synchronized_slots": evidence["counts"][
                "synchronized_behavior_relevant_slots"
            ],
        },
        "frontiers": frontiers,
        "semantic_requirements": semantic_requirements,
        "derived_choices": derived_choices,
    }


def relational_definedness_source(
    state_machine: str | Path,
    *,
    namespace: str = "StageA.GeneratedDefinedness",
) -> str:
    if _LEAN_NAMESPACE.fullmatch(namespace) is None:
        raise StageAInputError("definedness namespace is not a valid Lean namespace")
    evidence = analyze_definedness_jsonl(state_machine)
    definitions: list[str] = []
    names: list[str] = []
    for raw_slot in _sequence(evidence.get("slots"), "definedness slots"):
        slot = _object(raw_slot, "definedness slot")
        classification = slot.get("classification")
        if classification == "unknown":
            if slot.get("proof") is not None:
                raise StageAInputError("unknown definedness slot carries a proof")
            continue
        if classification not in {
            "unconstrained_noninterfering",
            "unconstrained_conditionally_noninterfering",
            "synchronized_behavior_relevant",
        }:
            raise StageAInputError("unsupported definedness classification")
        proof = _object(slot.get("proof"), "definedness proof")
        policy = _POLICIES.get(proof.get("policy"))
        if policy is None:
            raise StageAInputError("definedness proof has unsupported slot policy")
        choice_source = _lean_choice_source(
            slot.get("choice_source"),
            "definedness choice source",
            policy=str(proof.get("policy")),
        )
        graphs = [
            _lean_graph(item, f"definedness graph {index}")
            for index, item in enumerate(_sequence(proof.get("graphs"), "definedness graphs"))
        ]
        if not graphs:
            raise StageAInputError("proved definedness slot has no graph")
        slot_number = slot.get("slot")
        undefined_id = slot.get("undefined_id")
        if not isinstance(slot_number, int) or isinstance(slot_number, bool) or slot_number < 0:
            raise StageAInputError("definedness slot number is invalid")
        if not isinstance(undefined_id, str) or not undefined_id:
            raise StageAInputError("definedness undefined id is invalid")
        name = f"definednessCertificate{len(names)}"
        definitions.extend(
            [
                f"def {name} : DefinednessCertificate := {{",
                f"  slot := {slot_number}",
                f"  undefinedId := {_lean_string(undefined_id)}",
                f"  policy := {policy}",
                f"  choiceSource := {choice_source}",
                "  relevantSites := ["
                + ", ".join(
                    _lean_relevant_site(item, f"definedness relevant site {index}")
                    for index, item in enumerate(
                        _sequence(
                            slot.get("behavior_relevant_sites"),
                            "definedness behavior relevant sites",
                        )
                    )
                )
                + "]",
                "  obligations := ["
                + ", ".join(
                    _lean_obligation(item, f"definedness obligation {index}")
                    for index, item in enumerate(
                        _sequence(
                            slot.get("proof_obligations"),
                            "definedness proof obligations",
                        )
                    )
                )
                + "]",
                "  graphs := [" + ",\n".join(graphs) + "]",
                "}",
                f"theorem {name}Checked : {name}.checked = true := by native_decide",
                "",
            ]
        )
        names.append(name)
    return "\n".join(
        [
            "import StageA.RelationalDefinedness",
            "",
            f"namespace {namespace}",
            "",
            "open StageA.Relational.Definedness",
            "",
            *definitions,
            "def checkedDefinednessCertificates : List DefinednessCertificate := [" + ", ".join(names) + "]",
            "theorem checkedDefinednessCertificatesChecked :",
            "    checkedDefinednessCertificates.all DefinednessCertificate.checked = true := by",
            "  native_decide",
            "",
            "def stepDependencySoundObligations (transition : StepTransition) : Prop :=",
            "  forall certificate, certificate \u2208 checkedDefinednessCertificates ->",
            "    forall graph, graph \u2208 certificate.graphs ->",
            "      forall node, node \u2208 graph.nodes ->",
            "        StepDependencySound certificate.policy node.step transition",
            "",
            "theorem generatedDefinednessNoninterference",
            "    (transition : StepTransition)",
            "    (sound : stepDependencySoundObligations transition) :",
            "    forall certificate, certificate \u2208 checkedDefinednessCertificates ->",
            "      forall graph, graph \u2208 certificate.graphs ->",
            "        forall node, node \u2208 graph.nodes ->",
            "          NodeSemanticNoninterference certificate.policy node transition := by",
            "  intro certificate certificateMember",
            "  have certificateChecked := List.all_eq_true.mp",
            "    checkedDefinednessCertificatesChecked certificate certificateMember",
            "  exact certificate.checked_noninterference transition certificateChecked",
            "    (sound certificate certificateMember)",
            "",
            "theorem generatedDefinednessBoundaryObligationsDischarged",
            "    (transition : StepTransition)",
            "    (sound : stepDependencySoundObligations transition) :",
            "    forall certificate, certificate ∈ checkedDefinednessCertificates ->",
            "      forall obligation, obligation ∈ certificate.obligations ->",
            "        obligation.DischargedBy certificate transition := by",
            "  intro certificate certificateMember",
            "  have certificateChecked := List.all_eq_true.mp",
            "    checkedDefinednessCertificatesChecked certificate certificateMember",
            "  exact certificate.obligations_discharged_of_localSound transition",
            "    certificateChecked (sound certificate certificateMember)",
            "",
            "def acceptanceObligations",
            "    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)",
            "    (transition : StepTransition)",
            "    (originalPe : StageA.Formal.PE32) : Prop :=",
            "  forall certificate, certificate \u2208 checkedDefinednessCertificates ->",
            "    certificate.AcceptanceClosed",
            "      originalChoice candidateChoice runtimeChoice transition originalPe",
            "",
            "def runtimeChoiceBindingObligations",
            "    (originalChoice candidateChoice runtimeChoice : ChoiceFunction) : Prop :=",
            "  forall certificate, certificate ∈ checkedDefinednessCertificates ->",
            "    RuntimeChoiceBound certificate originalChoice candidateChoice runtimeChoice",
            "",
            "def choiceInstructionBindingObligations",
            "    (originalPe : StageA.Formal.PE32) : Prop :=",
            "  forall certificate, certificate ∈ checkedDefinednessCertificates ->",
            "    certificate.choiceSource.exactInstructionBound originalPe",
            "",
            "theorem generatedDefinednessAcceptanceClosedFromBindings",
            "    (originalChoice candidateChoice runtimeChoice : ChoiceFunction)",
            "    (transition : StepTransition)",
            "    (originalPe : StageA.Formal.PE32)",
            "    (sound : stepDependencySoundObligations transition)",
            "    (choices : runtimeChoiceBindingObligations",
            "      originalChoice candidateChoice runtimeChoice)",
            "    (choiceInstructions : choiceInstructionBindingObligations originalPe) :",
            "    acceptanceObligations originalChoice candidateChoice runtimeChoice",
            "      transition originalPe := by",
            "  intro certificate certificateMember",
            "  have certificateChecked := List.all_eq_true.mp",
            "    checkedDefinednessCertificatesChecked certificate certificateMember",
            "  exact {",
            "    checked := certificateChecked",
            "    choiceInstruction := choiceInstructions certificate certificateMember",
            "    choice := definednessChoiceBinding_of_runtime_bound certificate",
            "      originalChoice candidateChoice runtimeChoice",
            "      (choices certificate certificateMember)",
            "    semantics := {",
            "      localSound := sound certificate certificateMember",
            "    }",
            "  }",
            "",
            f"def sourceSha256 : String := {_lean_string(evidence['source_sha256'])}",
            f"def evidenceSha256 : String := {_lean_string(evidence['evidence_sha256'])}",
            "",
            f"end {namespace}",
            "",
        ]
    )


__all__ = ["RELATIONAL_DEFINEDNESS_LEAN_FORMAT", "relational_definedness_preflight", "relational_definedness_source"]
