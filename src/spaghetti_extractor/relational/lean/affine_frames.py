from __future__ import annotations

from pathlib import Path
import os
from typing import Any, Mapping

from ...stage_binary import StageAInputError
from ..runtime_frame_artifact import RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT
from ..artifacts import write_text_if_changed
from .expressions import (
    _lean_register_offset_witness,
    _lean_return_slot_offset_pair,
    _lean_semantic_expr,
)


AFFINE_FRAME_PROFILE_MODULE = "RelationalAffineFrameProfile"
_WORD_MODULUS = 2**32


def _uint32(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < _WORD_MODULUS
    ):
        raise StageAInputError(f"{field} must be a 32-bit unsigned integer")
    return value


def _natural(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{field} must be a natural number")
    return value


def _register(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{field} must be a register name")
    return value


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{field} must be an object")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise StageAInputError(f"{field} must be a boolean")
    return value


def _lean_word(value: object, field: str) -> str:
    return f"BitVec.ofNat 32 {_uint32(value, field)}"


def _family_key(family: Mapping[str, Any]) -> tuple[str, int, str, int, int]:
    return (
        _register(family.get("original_register"), "original_register"),
        _uint32(family.get("original_base"), "original_base"),
        _register(family.get("candidate_register"), "candidate_register"),
        _uint32(family.get("candidate_base"), "candidate_base"),
        _natural(family.get("translation_stride"), "translation_stride"),
    )


def _lean_family(value: object) -> str:
    family = _mapping(value, "affine family")
    original_register, original_base, candidate_register, candidate_base, stride = (
        _family_key(family)
    )
    if stride <= 0 or _WORD_MODULUS % stride != 0:
        raise StageAInputError("translation_stride must divide 2^32")
    return (
        "{ originalRegister := ."
        f"{original_register}, originalBase := BitVec.ofNat 32 {original_base}, "
        f"candidateRegister := .{candidate_register}, "
        f"candidateBase := BitVec.ofNat 32 {candidate_base}, "
        f"translationStride := {stride} }}"
    )


def _state_key(value: object) -> tuple[int, tuple[str, int, str, int, int]]:
    state = _mapping(value, "affine frame state")
    return (
        _natural(state.get("node_id"), "node_id"),
        _family_key(_mapping(state.get("family"), "state family")),
    )


def _lean_state(value: object) -> str:
    state = _mapping(value, "affine frame state")
    node_id = _natural(state.get("node_id"), "node_id")
    return f"{{ nodeId := {node_id}, family := {_lean_family(state.get('family'))} }}"


def _lean_rule(value: object) -> str:
    rule = _mapping(value, "affine transfer rule")
    return (
        "{ originalSourceRegister := ."
        + _register(rule.get("original_source_register"), "original_source_register")
        + ", candidateSourceRegister := ."
        + _register(rule.get("candidate_source_register"), "candidate_source_register")
        + ", originalTargetRegister := ."
        + _register(rule.get("original_target_register"), "original_target_register")
        + ", candidateTargetRegister := ."
        + _register(rule.get("candidate_target_register"), "candidate_target_register")
        + ", originalOutput := "
        + _lean_register_offset_witness(dict(_mapping(
            rule.get("original_output_witness"), "original_output_witness"
        )))
        + ", candidateOutput := "
        + _lean_register_offset_witness(dict(_mapping(
            rule.get("candidate_output_witness"), "candidate_output_witness"
        )))
        + ", originalDelta := "
        + _lean_word(rule.get("original_delta"), "original_delta")
        + ", candidateDelta := "
        + _lean_word(rule.get("candidate_delta"), "candidate_delta")
        + " }"
    )


def _lean_transition(
    value: object, states: tuple[Mapping[str, Any], ...]
) -> str:
    transition = _mapping(value, "affine frame transition")
    transition_id = _natural(transition.get("id"), "affine transition id")
    source_state_id = _natural(
        transition.get("source_state_id"),
        f"affine transition {transition_id} source_state_id",
    )
    target_state_id = _natural(
        transition.get("target_state_id"),
        f"affine transition {transition_id} target_state_id",
    )
    source = states[source_state_id]
    target = states[target_state_id]
    return (
        "{ source := "
        + _lean_state(source)
        + f", edgeId := {_natural(transition.get('edge_index'), 'edge_index')}"
        + ", rule := "
        + _lean_rule(transition.get("rule"))
        + ", rawTargetFamily := "
        + _lean_family(transition.get("raw_target_family"))
        + ", canonicalShift := { shiftCoefficient := "
        + _lean_word(
            transition.get("canonical_shift_coefficient"),
            "canonical_shift_coefficient",
        )
        + " }, target := "
        + _lean_state(target)
        + " }"
    )


def _transition_sort_key(
    value: object,
) -> tuple[
    tuple[int, tuple[str, int, str, int, int]],
    int,
    tuple[int, tuple[str, int, str, int, int]],
    str,
]:
    transition = _mapping(value, "affine frame transition")
    return (
        _state_key({
            "node_id": transition.get("source_node"),
            "family": transition.get("source_family"),
        }),
        _natural(transition.get("edge_index"), "edge_index"),
        _state_key({
            "node_id": transition.get("target_node"),
            "family": transition.get("target_family"),
        }),
        repr(transition.get("rule")),
    )


def _family_seed_coefficient(
    family: Mapping[str, Any], location: Mapping[str, Any]
) -> int | None:
    original_register, original_base, candidate_register, candidate_base, stride = (
        _family_key(family)
    )
    if stride <= 0 or _WORD_MODULUS % stride != 0:
        raise StageAInputError("translation_stride must divide 2^32")
    if (
        _register(location.get("original_register"), "seed original_register")
        != original_register
        or _register(location.get("candidate_register"), "seed candidate_register")
        != candidate_register
    ):
        return None
    original = _uint32(location.get("original"), "seed original offset")
    candidate = _uint32(location.get("candidate"), "seed candidate offset")
    translation = (original - original_base) % _WORD_MODULUS
    if (
        translation % stride != 0
        or (candidate_base + translation) % _WORD_MODULUS != candidate
    ):
        return None
    return translation // stride


def _seed_key(value: object) -> tuple[int, int, int, str, int, str, int]:
    seed = _mapping(value, "affine frame seed")
    location = _mapping(seed.get("location"), "seed location")
    return (
        _natural(seed.get("edge_index"), "seed edge_index"),
        _natural(seed.get("source_node_id"), "seed source_node_id"),
        _natural(seed.get("node_id"), "seed node_id"),
        _register(location.get("original_register"), "seed original_register"),
        _uint32(location.get("original"), "seed original offset"),
        _register(location.get("candidate_register"), "seed candidate_register"),
        _uint32(location.get("candidate"), "seed candidate offset"),
    )


def _canonical_id_rows(
    value: object,
    *,
    field: str,
    row_field: str,
    semantic_key: Any,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{field} must be a list")
    rows = tuple(_mapping(row, row_field) for row in value)
    ids = tuple(_natural(row.get("id"), f"{row_field} id") for row in rows)
    if len(set(ids)) != len(ids):
        raise StageAInputError(f"{field} contain duplicate ids")
    if ids != tuple(range(len(rows))):
        raise StageAInputError(f"{field} ids must be canonical and contiguous")
    keys = tuple(semantic_key(row) for row in rows)
    if len(set(keys)) != len(keys):
        raise StageAInputError(f"{field} contain duplicate rows")
    if keys != tuple(sorted(keys)):
        raise StageAInputError(f"{field} ids do not follow canonical row order")
    return rows


def _canonical_reference_ids(
    value: object,
    *,
    field: str,
    upper_bound: int,
) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{field} must be a list")
    ids = tuple(_natural(item, f"{field} entry") for item in value)
    if len(set(ids)) != len(ids):
        raise StageAInputError(f"{field} contains duplicate ids")
    if ids != tuple(sorted(ids)):
        raise StageAInputError(f"{field} must be in canonical id order")
    if any(item >= upper_bound for item in ids):
        raise StageAInputError(f"{field} references an unknown id")
    return ids


def _affine_authority_rows(
    payload: object,
) -> tuple[
    tuple[Mapping[str, Any], ...],
    tuple[Mapping[str, Any], ...],
    tuple[Mapping[str, Any], ...],
]:
    artifact = _mapping(payload, "runtime-frame affine artifact")
    if artifact.get("format") != RUNTIME_FRAME_AFFINE_VIABILITY_FORMAT:
        raise StageAInputError("unsupported runtime-frame affine artifact format")
    certificate = _mapping(artifact.get("certificate"), "affine certificate")
    states = _canonical_id_rows(
        certificate.get("viable_families"),
        field="viable affine families",
        row_field="affine frame state",
        semantic_key=_state_key,
    )
    transitions = _canonical_id_rows(
        certificate.get("viable_transitions"),
        field="viable affine transitions",
        row_field="affine frame transition",
        semantic_key=_transition_sort_key,
    )
    seeds = _canonical_id_rows(
        certificate.get("viable_seeds"),
        field="viable affine seeds",
        row_field="affine frame seed",
        semantic_key=_seed_key,
    )

    for transition in transitions:
        transition_id = _natural(transition.get("id"), "affine transition id")
        source_state_id = _natural(
            transition.get("source_state_id"),
            f"affine transition {transition_id} source_state_id",
        )
        target_state_id = _natural(
            transition.get("target_state_id"),
            f"affine transition {transition_id} target_state_id",
        )
        if source_state_id >= len(states) or target_state_id >= len(states):
            raise StageAInputError(
                f"affine transition {transition_id} references an unknown state"
            )
        source_key = _state_key({
            "node_id": transition.get("source_node"),
            "family": transition.get("source_family"),
        })
        target_key = _state_key({
            "node_id": transition.get("target_node"),
            "family": transition.get("target_family"),
        })
        if source_key != _state_key(states[source_state_id]):
            raise StageAInputError(
                f"affine transition {transition_id} source payload does not match "
                "source_state_id"
            )
        if target_key != _state_key(states[target_state_id]):
            raise StageAInputError(
                f"affine transition {transition_id} target payload does not match "
                "target_state_id"
            )

    for seed in seeds:
        seed_id = _natural(seed.get("id"), "affine seed id")
        target_state_id = _natural(
            seed.get("target_state_id"),
            f"affine seed {seed_id} target_state_id",
        )
        if target_state_id >= len(states):
            raise StageAInputError(
                f"affine seed {seed_id} references an unknown target state"
            )
        target_state = states[target_state_id]
        node_id = _natural(seed.get("node_id"), f"affine seed {seed_id} node_id")
        if node_id != _natural(
            target_state.get("node_id"), f"affine state {target_state_id} node_id"
        ):
            raise StageAInputError(
                f"affine seed {seed_id} node does not match target_state_id"
            )
        coefficient = _uint32(
            seed.get("coefficient"), f"affine seed {seed_id} coefficient"
        )
        location = _mapping(seed.get("location"), "seed location")
        family = _mapping(target_state.get("family"), "seed target family")
        if _family_seed_coefficient(family, location) != coefficient:
            raise StageAInputError(
                f"affine seed {seed_id} coefficient does not realize target_state_id"
            )

    bindings_value = certificate.get("required_transition_bindings")
    if not isinstance(bindings_value, list):
        raise StageAInputError("required affine transition bindings must be a list")
    bindings = tuple(
        _mapping(value, "required affine transition binding")
        for value in bindings_value
    )
    binding_keys: list[tuple[int, int]] = []
    transitions_by_source: dict[int, list[int]] = {}
    referenced_transition_ids: list[int] = []
    for binding in bindings:
        source_state_id = _natural(
            binding.get("source_state_id"), "binding source_state_id"
        )
        edge_id = _natural(binding.get("edge_index"), "binding edge_index")
        if source_state_id >= len(states):
            raise StageAInputError(
                "required affine transition binding references an unknown state"
            )
        binding_keys.append((source_state_id, edge_id))
        candidate_ids = _canonical_reference_ids(
            binding.get("candidate_transition_ids"),
            field="binding candidate_transition_ids",
            upper_bound=len(transitions),
        )
        expected_candidates = tuple(
            _natural(row.get("id"), "affine transition id")
            for row in transitions
            if _natural(row.get("source_state_id"), "source_state_id")
            == source_state_id
            and _natural(row.get("edge_index"), "edge_index") == edge_id
        )
        if candidate_ids != expected_candidates:
            raise StageAInputError(
                "required affine transition binding candidate references are not exact"
            )
        referenced_transition_ids.extend(candidate_ids)
        transitions_by_source.setdefault(source_state_id, []).extend(candidate_ids)
        selected = binding.get("selected_transition_id")
        status = binding.get("status")
        if status == "selected":
            if (
                len(candidate_ids) != 1
                or not isinstance(selected, int)
                or isinstance(selected, bool)
                or selected != candidate_ids[0]
            ):
                raise StageAInputError(
                    "required affine transition binding has an invalid selection"
                )
        elif status == "blocked_ambiguity":
            if len(candidate_ids) < 2 or selected is not None:
                raise StageAInputError(
                    "required affine transition binding has invalid ambiguity evidence"
                )
        elif status == "missing":
            if candidate_ids or selected is not None:
                raise StageAInputError(
                    "required affine transition binding has invalid missing evidence"
                )
        else:
            raise StageAInputError(
                "required affine transition binding has an unknown status"
            )
    if len(set(binding_keys)) != len(binding_keys):
        raise StageAInputError("required affine transition bindings are duplicated")
    if tuple(binding_keys) != tuple(sorted(binding_keys)):
        raise StageAInputError(
            "required affine transition bindings are not in canonical order"
        )
    if tuple(sorted(referenced_transition_ids)) != tuple(range(len(transitions))):
        raise StageAInputError(
            "viable affine transitions are not exactly covered by required bindings"
        )

    rooted_state_ids = _canonical_reference_ids(
        certificate.get("seed_rooted_state_ids"),
        field="seed_rooted_state_ids",
        upper_bound=len(states),
    )
    rooted_transition_ids = _canonical_reference_ids(
        certificate.get("seed_rooted_transition_ids"),
        field="seed_rooted_transition_ids",
        upper_bound=len(transitions),
    )
    pending = [
        _natural(seed.get("target_state_id"), "affine seed target_state_id")
        for seed in seeds
    ]
    expected_rooted_states: set[int] = set()
    expected_rooted_transitions: set[int] = set()
    while pending:
        state_id = pending.pop()
        if state_id in expected_rooted_states:
            continue
        expected_rooted_states.add(state_id)
        for transition_id in transitions_by_source.get(state_id, ()):
            expected_rooted_transitions.add(transition_id)
            pending.append(_natural(
                transitions[transition_id].get("target_state_id"),
                f"affine transition {transition_id} target_state_id",
            ))
    if rooted_state_ids != tuple(sorted(expected_rooted_states)):
        raise StageAInputError("seed_rooted_state_ids are not the exact seed closure")
    if rooted_transition_ids != tuple(sorted(expected_rooted_transitions)):
        raise StageAInputError(
            "seed_rooted_transition_ids are not the exact selected seed closure"
        )

    orphan_state_ids = _canonical_reference_ids(
        certificate.get("orphan_state_ids"),
        field="orphan_state_ids",
        upper_bound=len(states),
    )
    orphan_transition_ids = _canonical_reference_ids(
        certificate.get("orphan_transition_ids"),
        field="orphan_transition_ids",
        upper_bound=len(transitions),
    )
    expected_orphan_states = tuple(
        index for index in range(len(states)) if index not in expected_rooted_states
    )
    expected_orphan_transitions = tuple(
        index
        for index in range(len(transitions))
        if index not in expected_rooted_transitions
    )
    if orphan_state_ids != expected_orphan_states:
        raise StageAInputError("orphan_state_ids do not complement rooted authority")
    if orphan_transition_ids != expected_orphan_transitions:
        raise StageAInputError(
            "orphan_transition_ids do not complement rooted authority"
        )
    for state_id, state in enumerate(states):
        if _boolean(state.get("seed_rooted"), "affine state seed_rooted") != (
            state_id in expected_rooted_states
        ):
            raise StageAInputError(
                f"affine state {state_id} has inconsistent seed_rooted authority"
            )
    for transition_id, transition in enumerate(transitions):
        if _boolean(
            transition.get("seed_rooted"), "affine transition seed_rooted"
        ) != (transition_id in expected_rooted_transitions):
            raise StageAInputError(
                f"affine transition {transition_id} has inconsistent "
                "seed_rooted authority"
            )

    extended_profile_fields = {
        "resume_anchor_state_ids",
        "resume_anchored_state_ids",
        "resume_anchored_transition_ids",
        "affine_profile_state_ids",
        "affine_profile_transition_ids",
    }
    has_extended_profile = any(
        field in certificate for field in extended_profile_fields
    )
    if has_extended_profile and not extended_profile_fields.issubset(certificate):
        raise StageAInputError(
            "affine resume-anchor profile fields must be present together"
        )
    resume_anchor_state_ids = _canonical_reference_ids(
        certificate.get("resume_anchor_state_ids", []),
        field="resume_anchor_state_ids",
        upper_bound=len(states),
    )
    facts = _mapping(artifact.get("facts", {}), "affine facts")
    resume_anchors_value = facts.get("resume_anchors", [])
    if not isinstance(resume_anchors_value, list):
        raise StageAInputError("affine resume_anchors must be a list")
    resume_anchors = tuple(
        _mapping(anchor, "affine resume anchor")
        for anchor in resume_anchors_value
    )
    anchor_keys: list[tuple[object, ...]] = []
    for anchor in resume_anchors:
        profile = anchor.get("profile")
        if profile not in {
            "checked_call_return_summary_resume_anchor_v1",
            "checked_external_call_summary_resume_anchor_v1",
        }:
            raise StageAInputError("affine resume anchor has an unknown profile")
        source = _mapping(anchor.get("source"), "affine resume anchor source")
        target = _mapping(
            anchor.get("location"), "affine resume anchor location"
        )
        anchor_keys.append((
            _natural(anchor.get("edge_index"), "anchor edge_index"),
            _natural(anchor.get("claim_index"), "anchor claim_index"),
            _natural(anchor.get("source_node_id"), "anchor source_node_id"),
            _register(source.get("original_register"), "anchor original register"),
            _uint32(source.get("original"), "anchor original offset"),
            _register(source.get("candidate_register"), "anchor candidate register"),
            _uint32(source.get("candidate"), "anchor candidate offset"),
            _natural(anchor.get("node_id"), "anchor node_id"),
            _register(target.get("original_register"), "anchor target original register"),
            _uint32(target.get("original"), "anchor target original offset"),
            _register(target.get("candidate_register"), "anchor target candidate register"),
            _uint32(target.get("candidate"), "anchor target candidate offset"),
            str(profile),
        ))
    if len(set(anchor_keys)) != len(anchor_keys):
        raise StageAInputError("affine resume anchors contain duplicate rows")

    def transition_closure(initial_state_ids: set[int]) -> tuple[set[int], set[int]]:
        closure_states: set[int] = set()
        closure_transitions: set[int] = set()
        pending_states = list(initial_state_ids)
        while pending_states:
            state_id = pending_states.pop()
            if state_id in closure_states:
                continue
            closure_states.add(state_id)
            for transition_id in transitions_by_source.get(state_id, ()):
                closure_transitions.add(transition_id)
                pending_states.append(_natural(
                    transitions[transition_id].get("target_state_id"),
                    f"affine transition {transition_id} target_state_id",
                ))
        return closure_states, closure_transitions

    expected_profile_states = set(expected_rooted_states)
    expected_profile_transitions = set(expected_rooted_transitions)
    expected_anchor_states: set[int] = set()
    while True:
        enabled_targets: set[int] = set()
        for anchor in resume_anchors:
            source_node_id = _natural(
                anchor.get("source_node_id"), "anchor source_node_id"
            )
            source_location = _mapping(
                anchor.get("source"), "affine resume anchor source"
            )
            source_enabled = any(
                _natural(states[state_id].get("node_id"), "affine state node_id")
                == source_node_id
                and _family_seed_coefficient(
                    _mapping(states[state_id].get("family"), "affine state family"),
                    source_location,
                ) is not None
                for state_id in expected_profile_states
            )
            if not source_enabled:
                continue
            target_node_id = _natural(anchor.get("node_id"), "anchor node_id")
            target_location = _mapping(
                anchor.get("location"), "affine resume anchor location"
            )
            enabled_targets.update(
                state_id
                for state_id, state in enumerate(states)
                if _natural(state.get("node_id"), "affine state node_id")
                == target_node_id
                and _family_seed_coefficient(
                    _mapping(state.get("family"), "affine state family"),
                    target_location,
                ) is not None
            )
        new_anchor_states = enabled_targets - expected_anchor_states
        if not new_anchor_states:
            break
        expected_anchor_states.update(new_anchor_states)
        new_states, new_transitions = transition_closure(new_anchor_states)
        expected_profile_states.update(new_states)
        expected_profile_transitions.update(new_transitions)

    if resume_anchor_state_ids != tuple(sorted(expected_anchor_states)):
        raise StageAInputError(
            "resume_anchor_state_ids are not the exact source-gated anchor set"
        )
    expected_resume_states = expected_profile_states - expected_rooted_states
    expected_resume_transitions = (
        expected_profile_transitions - expected_rooted_transitions
    )
    resume_anchored_state_ids = _canonical_reference_ids(
        certificate.get("resume_anchored_state_ids", []),
        field="resume_anchored_state_ids",
        upper_bound=len(states),
    )
    resume_anchored_transition_ids = _canonical_reference_ids(
        certificate.get("resume_anchored_transition_ids", []),
        field="resume_anchored_transition_ids",
        upper_bound=len(transitions),
    )
    if resume_anchored_state_ids != tuple(sorted(expected_resume_states)):
        raise StageAInputError(
            "resume_anchored_state_ids are not the exact anchor closure"
        )
    if resume_anchored_transition_ids != tuple(
        sorted(expected_resume_transitions)
    ):
        raise StageAInputError(
            "resume_anchored_transition_ids are not the exact anchor closure"
        )
    expected_profile_state_ids = tuple(sorted(expected_profile_states))
    expected_profile_transition_ids = tuple(sorted(expected_profile_transitions))
    affine_profile_state_ids = _canonical_reference_ids(
        certificate.get(
            "affine_profile_state_ids", sorted(expected_rooted_states)
        ),
        field="affine_profile_state_ids",
        upper_bound=len(states),
    )
    affine_profile_transition_ids = _canonical_reference_ids(
        certificate.get(
            "affine_profile_transition_ids", sorted(expected_rooted_transitions)
        ),
        field="affine_profile_transition_ids",
        upper_bound=len(transitions),
    )
    if affine_profile_state_ids != expected_profile_state_ids:
        raise StageAInputError(
            "affine_profile_state_ids are not the exact seed/anchor union"
        )
    if affine_profile_transition_ids != expected_profile_transition_ids:
        raise StageAInputError(
            "affine_profile_transition_ids are not the exact seed/anchor union"
        )

    return (
        tuple(states[index] for index in affine_profile_state_ids),
        tuple(transitions[index] for index in affine_profile_transition_ids),
        seeds,
    )


def _lean_seed(
    seed: Mapping[str, Any],
    states: tuple[Mapping[str, Any], ...],
) -> str:
    (
        _edge_id,
        _source_node_id,
        _declared_node_id,
        _original_register,
        _original,
        _candidate_register,
        _candidate,
    ) = _seed_key(seed)
    location = dict(_mapping(seed.get("location"), "seed location"))
    seed_id = _natural(seed.get("id"), "affine seed id")
    target_state_id = _natural(
        seed.get("target_state_id"), f"affine seed {seed_id} target_state_id"
    )
    node_id = _natural(
        states[target_state_id].get("node_id"),
        f"affine state {target_state_id} node_id",
    )
    coefficient = _uint32(
        seed.get("coefficient"), f"affine seed {seed_id} coefficient"
    )
    return (
        "{ edgeId := "
        + str(_natural(seed.get("edge_index"), "seed edge_index"))
        + f", nodeId := {node_id}, offsets := "
        + _lean_return_slot_offset_pair(location)
        + f", coefficient := BitVec.ofNat 32 {coefficient} }}"
    )


def relational_affine_frame_profile_source(payload: object) -> str:
    states, transitions, seeds = _affine_authority_rows(payload)
    artifact = _mapping(payload, "runtime-frame affine artifact")
    certificate = _mapping(artifact.get("certificate"), "affine certificate")
    all_states = tuple(
        _mapping(state, "affine frame state")
        for state in certificate["viable_families"]
    )

    state_rows = ",\n  ".join(_lean_state(state) for state in states)
    transition_definitions = "\n\n".join(
        f"def runtimeFrameAffineTransition{index} : "
        "ReturnSlotAffineFrameTransitionClaim :=\n  "
        + _lean_transition(transition, all_states)
        for transition in transitions
        for index in [_natural(transition.get("id"), "affine transition id")]
    )
    transition_rows = ",\n  ".join(
        f"runtimeFrameAffineTransition{transition_id}"
        for transition in transitions
        for transition_id in [
            _natural(transition.get("id"), "affine transition id")
        ]
    )
    seed_rows = ",\n  ".join(
        _lean_seed(seed, all_states) for seed in seeds
    )
    complete_theorem = (
        "\ntheorem runtimeFrameAffineProfileChecked :\n"
        "    runtimeFrameAffineProfile.checked relationalProductGraph = true := by\n"
        "  native_decide\n"
    )
    return (
        "import StageA.RelationalProductGraphContext\n"
        "import StageA.RelationalAffineFrames\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def runtimeFrameAffineStates : List ReturnSlotAffineFrameState := [\n  "
        + state_rows
        + "\n]\n\n"
        + transition_definitions
        + ("\n\n" if transition_definitions else "")
        + "def runtimeFrameAffineTransitions : "
        "List ReturnSlotAffineFrameTransitionClaim := [\n  "
        + transition_rows
        + "\n]\n\n"
        + "def runtimeFrameAffineSeeds : List ReturnSlotAffineFrameSeed := [\n  "
        + seed_rows
        + "\n]\n\n"
        + "def runtimeFrameAffineProfile : ReturnSlotAffineFrameProfile := {\n"
        "  states := runtimeFrameAffineStates\n"
        "  transitions := runtimeFrameAffineTransitions\n"
        "  seeds := runtimeFrameAffineSeeds\n"
        "}\n\n"
        "def runtimeFrameAffineProfileCheck : Bool :=\n"
        "  runtimeFrameAffineProfile.checked relationalProductGraph\n"
        + complete_theorem
        + "\nend StageA.GeneratedRelational\n"
    )


def _semantic_transition_source(
    index: int,
    transition: Mapping[str, Any],
    *,
    region_index: int,
    node_id: int,
    physical_state_only: bool,
) -> str:
    original_normalized = f"runtimeFrameAffineOriginalNormalized{index}"
    candidate_normalized = f"runtimeFrameAffineCandidateNormalized{index}"
    claim = f"runtimeFrameAffineSemanticTransition{index}"
    definition = (
        f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
        f"  (normalizeSymbolicBehavior false region{region_index}.targets "
        f"originalBehavior{region_index}).get (by decide)\n\n"
        f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
        f"  (normalizeSymbolicBehavior true region{region_index}.targets "
        f"candidateBehavior{region_index}).get (by decide)\n\n"
        f"def {claim} : ReturnSlotAffineFrameSemanticTransitionClaim := {{\n"
        f"  transition := runtimeFrameAffineTransition{index}\n"
        f"  region := region{region_index}\n"
        f"  originalBehavior := originalBehavior{region_index}\n"
        f"  candidateBehavior := candidateBehavior{region_index}\n"
        f"  originalNormalized := {original_normalized}\n"
        f"  candidateNormalized := {candidate_normalized}\n"
        f"  physicalStateOnly := {'true' if physical_state_only else 'false'}\n"
        "}\n\n"
    )
    if physical_state_only:
        return definition + (
            f"theorem {claim}Checked :\n"
            f"    {claim}.checked staticProofContext relationalProductGraph = true := by\n"
            "  apply ReturnSlotAffineFrameSemanticTransitionClaim."
            "checked_physical_of_evidence\n"
            f"    staticProofContext relationalProductGraph {claim}\n"
            f"    relationalProductGraph.nodes[{node_id}]\n"
            "  · native_decide\n"
            "  · native_decide\n"
            "  · native_decide\n"
            "  · native_decide\n"
            "  · native_decide\n"
            "  · native_decide\n"
            "  · native_decide\n"
            "  · native_decide"
        )
    return definition + (
        f"theorem {claim}Checked :\n"
        f"    {claim}.checked staticProofContext relationalProductGraph = true := by\n"
        "  apply ReturnSlotAffineFrameSemanticTransitionClaim.checked_of_evidence\n"
        f"    staticProofContext relationalProductGraph {claim}\n"
        f"    relationalProductGraph.nodes[{node_id}]\n"
        "  · native_decide\n"
        "  · native_decide\n"
        "  · native_decide\n"
        "  · native_decide\n"
        f"  · simpa [{claim}, staticProofContext] using "
        f"originalBehavior{region_index}CheckedDecoded\n"
        f"  · simpa [{claim}, staticProofContext] using "
        f"candidateBehavior{region_index}CheckedDecoded\n"
        f"  · native_decide\n"
        f"  · native_decide\n"
        f"  · native_decide"
    )


def _lean_direct_call_push_claim(value: object) -> str:
    claim = _mapping(value, "direct call push claim")
    return (
        "{ calleeTargetId := "
        + str(_natural(claim.get("callee_target_id"), "callee_target_id"))
        + ", continuationTargetId := "
        + str(_natural(
            claim.get("continuation_target_id"), "continuation_target_id"
        ))
        + ", originalReturnAddress := "
        + str(_natural(
            claim.get("original_return_address"), "original_return_address"
        ))
        + ", candidateReturnAddress := "
        + str(_natural(
            claim.get("candidate_return_address"), "candidate_return_address"
        ))
        + ", originalStackAddress := "
        + _lean_semantic_expr(dict(_mapping(
            claim.get("original_stack_address"), "original_stack_address"
        )))
        + ", candidateStackAddress := "
        + _lean_semantic_expr(dict(_mapping(
            claim.get("candidate_stack_address"), "candidate_stack_address"
        )))
        + " }"
    )


def _semantic_seed_source(
    index: int,
    seed: Mapping[str, Any],
    *,
    source_region_index: int,
    source_node_id: int,
) -> str:
    original_normalized = f"runtimeFrameAffineSeedOriginalNormalized{index}"
    candidate_normalized = f"runtimeFrameAffineSeedCandidateNormalized{index}"
    push = f"runtimeFrameAffineSeedCallPush{index}"
    claim = f"runtimeFrameAffineSemanticSeed{index}"
    return (
        f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
        f"  (normalizeSymbolicBehavior false region{source_region_index}.targets "
        f"originalBehavior{source_region_index}).get (by decide)\n\n"
        f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
        f"  (normalizeSymbolicBehavior true region{source_region_index}.targets "
        f"candidateBehavior{source_region_index}).get (by decide)\n\n"
        f"def {push} : DirectCallPushClaim :=\n  "
        + _lean_direct_call_push_claim(seed.get("direct_call_push_claim"))
        + "\n\n"
        f"def {claim} : ReturnSlotAffineFrameSemanticSeedClaim := {{\n"
        f"  seed := runtimeFrameAffineSeeds[{index}]\n"
        f"  sourceRegion := region{source_region_index}\n"
        f"  originalBehavior := originalBehavior{source_region_index}\n"
        f"  candidateBehavior := candidateBehavior{source_region_index}\n"
        f"  originalNormalized := {original_normalized}\n"
        f"  candidateNormalized := {candidate_normalized}\n"
        f"  callPush := {push}\n"
        "}\n\n"
        f"theorem {claim}Checked :\n"
        f"    {claim}.checked staticProofContext relationalProductGraph = true := by\n"
        "  apply ReturnSlotAffineFrameSemanticSeedClaim.checked_of_evidence\n"
        f"    staticProofContext relationalProductGraph {claim}\n"
        "    relationalProductGraph.edges["
        + str(_natural(seed.get("edge_index"), "seed edge_index"))
        + "] "
        f"relationalProductGraph.nodes[{source_node_id}]\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        f"  · simpa [{claim}, staticProofContext] using "
        f"originalBehavior{source_region_index}CheckedDecoded\n"
        f"  · simpa [{claim}, staticProofContext] using "
        f"candidateBehavior{source_region_index}CheckedDecoded\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide"
    )


def write_relational_affine_frame_semantic_modules(
    lean_dir: Path,
    payload: object,
    *,
    contract: Mapping[str, Any],
    product_graph: Mapping[str, Any],
    decode_chunk_regions: list[list[int]],
    physical_state_only_region_indices: set[int] | frozenset[int] = frozenset(),
) -> list[str]:
    """Emit exact-byte semantic replay shards for seed-rooted affine authority."""
    _states, transitions, seeds = _affine_authority_rows(payload)
    regions_value = contract.get("regions")
    nodes_value = product_graph.get("nodes")
    edges_value = product_graph.get("edges")
    if (
        not isinstance(regions_value, list)
        or not isinstance(nodes_value, list)
        or not isinstance(edges_value, list)
    ):
        raise StageAInputError("affine semantic replay requires regions and product nodes")
    # Product target ids and the generated Lean RegionRelation.id use the
    # canonical numeric region index.  Source-level region ids are diagnostic
    # labels and may be strings.
    for region_value in regions_value:
        _mapping(region_value, "relation region")
    region_index_by_id = {index: index for index in range(len(regions_value))}
    nodes_by_id: dict[int, Mapping[str, Any]] = {}
    for node_value in nodes_value:
        node = _mapping(node_value, "product node")
        node_id = _natural(node.get("id"), "product node id")
        if node_id in nodes_by_id:
            raise StageAInputError("product node ids must be unique")
        nodes_by_id[node_id] = node
    edges_by_id: dict[int, Mapping[str, Any]] = {}
    for edge_value in edges_value:
        edge = _mapping(edge_value, "product edge")
        edge_id = _natural(edge.get("id"), "product edge id")
        if edge_id in edges_by_id:
            raise StageAInputError("product edge ids must be unique")
        edges_by_id[edge_id] = edge
    decode_chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }

    semantic_rows: list[tuple[int, Mapping[str, Any], int, int]] = []
    for transition in transitions:
        index = _natural(transition.get("id"), "affine transition id")
        node_id = _natural(transition.get("source_node"), "source_node")
        node = nodes_by_id.get(node_id)
        if node is None:
            raise StageAInputError(
                f"affine transition source node {node_id} does not exist"
            )
        target_id = _natural(node.get("target_id"), "product node target_id")
        region_index = region_index_by_id.get(target_id)
        if region_index is None:
            raise StageAInputError(
                f"affine transition source target {target_id} has no relation region"
            )
        if region_index not in decode_chunk_by_region:
            raise StageAInputError(
                f"affine transition region {region_index} has no decode chunk"
            )
        semantic_rows.append((index, transition, node_id, region_index))

    semantic_seed_rows: list[tuple[int, Mapping[str, Any], int, int]] = []
    for seed in seeds:
        index = _natural(seed.get("id"), "affine seed id")
        edge_id = _natural(seed.get("edge_index"), "seed edge_index")
        edge = edges_by_id.get(edge_id)
        if edge is None:
            raise StageAInputError(f"affine seed edge {edge_id} does not exist")
        source_node_id = _natural(edge.get("source_node_id"), "edge source_node_id")
        declared_source = _natural(seed.get("source_node_id"), "seed source_node_id")
        if source_node_id != declared_source:
            raise StageAInputError("affine seed source node does not match its edge")
        source_node = nodes_by_id.get(source_node_id)
        if source_node is None:
            raise StageAInputError(
                f"affine seed source node {source_node_id} does not exist"
            )
        source_target_id = _natural(
            source_node.get("target_id"), "seed source target_id"
        )
        source_region_index = region_index_by_id.get(source_target_id)
        if source_region_index is None:
            raise StageAInputError(
                f"affine seed source target {source_target_id} has no relation region"
            )
        if source_region_index not in decode_chunk_by_region:
            raise StageAInputError(
                f"affine seed source region {source_region_index} has no decode chunk"
            )
        semantic_seed_rows.append((
            index, seed, source_node_id, source_region_index,
        ))

    chunk_size = max(
        1,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_AFFINE_SEMANTIC_CHUNK", "16"
        )),
    )
    modules: list[str] = []
    transition_chunk_names: list[str] = []
    transition_chunk_checks: list[str] = []
    for chunk_index, offset in enumerate(range(0, len(semantic_rows), chunk_size)):
        selected = semantic_rows[offset : offset + chunk_size]
        module = f"RelationalAffineFrameSemanticChunk{chunk_index}"
        chunk_name = f"runtimeFrameAffineSemanticChunk{chunk_index}"
        chunk_check = f"runtimeFrameAffineSemanticChunk{chunk_index}Checked"
        modules.append(module)
        transition_chunk_names.append(chunk_name)
        transition_chunk_checks.append(chunk_check)
        decode_chunks = sorted({
            decode_chunk_by_region[region_index]
            for _, _, _, region_index in selected
        })
        imports = (
            "import StageA.RelationalAffineFrameProfile\n"
            + "".join(
                f"import StageA.RelationalProofOriginalDecodeChunk{index}\n"
                f"import StageA.RelationalProofCandidateDecodeChunk{index}\n"
                for index in decode_chunks
            )
        )
        definitions = "\n\n".join(
            _semantic_transition_source(
                index,
                transition,
                region_index=region_index,
                node_id=node_id,
                physical_state_only=(
                    region_index in physical_state_only_region_indices
                ),
            )
            for index, transition, node_id, region_index in selected
        )
        claims = [
            f"runtimeFrameAffineSemanticTransition{index}"
            for index, _, _, _ in selected
        ]
        checks = [f"{claim}Checked" for claim in claims]
        checked_proof = (
            "  simp only [" + chunk_name + ", List.all_cons, List.all_nil, "
            "Bool.and_eq_true]\n"
            "  exact "
            + "⟨" * len(checks)
            + "True.intro"
            + "⟩" * len(checks)
            if not checks else
            "  simp [" + chunk_name + ", " + ", ".join(checks) + "]"
        )
        source = (
            imports
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + definitions
            + ("\n\n" if definitions else "")
            + f"def {chunk_name} : "
            "List ReturnSlotAffineFrameSemanticTransitionClaim := ["
            + ", ".join(claims)
            + "]\n\n"
            + f"theorem {chunk_check} :\n"
            f"    {chunk_name}.all (fun claim => claim.checked "
            "staticProofContext relationalProductGraph) = true := by\n"
            + checked_proof
            + "\n\nend StageA.GeneratedRelational\n"
        )
        write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    seed_chunk_names: list[str] = []
    seed_chunk_checks: list[str] = []
    for chunk_index, offset in enumerate(
        range(0, len(semantic_seed_rows), chunk_size)
    ):
        selected = semantic_seed_rows[offset : offset + chunk_size]
        module = f"RelationalAffineFrameSemanticSeedChunk{chunk_index}"
        chunk_name = f"runtimeFrameAffineSemanticSeedChunk{chunk_index}"
        chunk_check = f"runtimeFrameAffineSemanticSeedChunk{chunk_index}Checked"
        modules.append(module)
        seed_chunk_names.append(chunk_name)
        seed_chunk_checks.append(chunk_check)
        decode_chunks = sorted({
            decode_chunk_by_region[source_region_index]
            for _, _, _, source_region_index in selected
        })
        imports = (
            "import StageA.RelationalAffineFrameProfile\n"
            + "".join(
                f"import StageA.RelationalProofOriginalDecodeChunk{index}\n"
                f"import StageA.RelationalProofCandidateDecodeChunk{index}\n"
                for index in decode_chunks
            )
        )
        definitions = "\n\n".join(
            _semantic_seed_source(
                index,
                seed,
                source_region_index=source_region_index,
                source_node_id=source_node_id,
            )
            for index, seed, source_node_id, source_region_index in selected
        )
        claims = [
            f"runtimeFrameAffineSemanticSeed{index}"
            for index, _, _, _ in selected
        ]
        checks = [f"{claim}Checked" for claim in claims]
        source = (
            imports
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + definitions
            + ("\n\n" if definitions else "")
            + f"def {chunk_name} : List ReturnSlotAffineFrameSemanticSeedClaim := ["
            + ", ".join(claims)
            + "]\n\n"
            + f"theorem {chunk_check} :\n"
            f"    {chunk_name}.all (fun claim => claim.checked "
            "staticProofContext relationalProductGraph) = true := by\n"
            + "  simp [" + chunk_name + ", " + ", ".join(checks) + "]"
            + "\n\nend StageA.GeneratedRelational\n"
        )
        write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    aggregate_module = "RelationalAffineFrameSemanticProfile"
    imports = (
        "import StageA.RelationalAffineFrameProfile\n"
        + "".join(f"import StageA.{module}\n" for module in modules)
    )
    transition_claims_expression = (
        " ++ ".join(transition_chunk_names)
        if transition_chunk_names else "[]"
    )
    seed_claims_expression = (
        " ++ ".join(seed_chunk_names) if seed_chunk_names else "[]"
    )
    complete_theorem = (
        "\ntheorem runtimeFrameAffineSemanticProfileChecked :\n"
        "    runtimeFrameAffineSemanticProfile.checked staticProofContext\n"
        "      relationalProductGraph = true := by\n"
        "  unfold ReturnSlotAffineFrameSemanticProfile.checked\n"
        "    runtimeFrameAffineSemanticProfile\n"
        "  simp only [runtimeFrameAffineProfileChecked, Bool.true_and,\n"
        "    Bool.and_eq_true, beq_iff_eq]\n"
        "  refine ⟨⟨⟨rfl, ?_⟩, rfl⟩, ?_⟩\n"
        "  · simp [runtimeFrameAffineSemanticTransitionClaims"
        + (
            ", " + ", ".join(
                transition_chunk_names + transition_chunk_checks
            )
            if transition_chunk_names else ""
        )
        + "]\n"
        "  · simp [runtimeFrameAffineSemanticSeedClaims"
        + (
            ", " + ", ".join(seed_chunk_names + seed_chunk_checks)
            if seed_chunk_names else ""
        )
        + "]\n"
    )
    aggregate_source = (
        imports
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def runtimeFrameAffineSemanticTransitionClaims : "
        "List ReturnSlotAffineFrameSemanticTransitionClaim :=\n  "
        + transition_claims_expression
        + "\n\n"
        "def runtimeFrameAffineSemanticSeedClaims : "
        "List ReturnSlotAffineFrameSemanticSeedClaim :=\n  "
        + seed_claims_expression
        + "\n\n"
        "def runtimeFrameAffineSemanticProfile : "
        "ReturnSlotAffineFrameSemanticProfile := {\n"
        "  frameProfile := runtimeFrameAffineProfile\n"
        "  transitionClaims := runtimeFrameAffineSemanticTransitionClaims\n"
        "  seedClaims := runtimeFrameAffineSemanticSeedClaims\n"
        "}\n"
        + complete_theorem
        + "\nend StageA.GeneratedRelational\n"
    )
    write_text_if_changed(
        lean_dir / "StageA" / f"{aggregate_module}.lean", aggregate_source
    )
    modules.append(aggregate_module)
    return modules


def write_relational_affine_frame_profile_module(
    lean_dir: Path, payload: object
) -> str:
    source = relational_affine_frame_profile_source(payload)
    write_text_if_changed(
        lean_dir / "StageA" / f"{AFFINE_FRAME_PROFILE_MODULE}.lean",
        source,
    )
    return AFFINE_FRAME_PROFILE_MODULE


__all__ = [
    "AFFINE_FRAME_PROFILE_MODULE",
    "relational_affine_frame_profile_source",
    "write_relational_affine_frame_profile_module",
    "write_relational_affine_frame_semantic_modules",
]
