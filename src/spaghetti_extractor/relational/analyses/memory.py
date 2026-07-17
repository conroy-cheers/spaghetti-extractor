from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from ...stage_binary import StageABinary
from ..contract import _raw_base_relocations
from ..model import _semantic_constant_word
from .segments import (
    _paired_exact_state_expr_witness,
    _paired_prepared_word_writes_claim,
    _paired_stack_word_value_claim,
)


def _writable_static_word(binary: StageABinary, address: int) -> bool:
    rva = address - binary.image_base
    return 0 < address < 2**32 and address + 4 <= 2**32 and any(
        section.writable
        and not section.executable
        and section.rva_start <= rva
        and rva + 4 <= section.rva_end
        for section in binary.sections
    )


def _static_word_value_relation(claim: dict[str, Any]) -> str | None:
    profile = claim.get("profile")
    if profile in {"exact_inputs_v1", "exact_expression_v1"}:
        return "exact"
    if profile == "mapped_code_target_v1":
        return "code_pointer"
    if profile == "mapped_data_target_v1":
        return "data_pointer"
    if profile == "dynamic_range_v1":
        return "related_word"
    if profile == "register_argument_v1":
        relation = (claim.get("claim") or {}).get("relation") or {}
        if relation.get("relation") == "exact":
            return "exact"
        if relation.get("relation") == "related_word":
            return "related_word"
    return None


def _merge_static_word_relations(relations: set[str]) -> str:
    if len(relations) == 1:
        return next(iter(relations))
    # related_word is the reviewed union relation for exact and mapped words.
    return "related_word"


def _initial_u32(binary: StageABinary, address: int) -> int | None:
    rva = address - binary.image_base
    if rva < 0:
        return None
    raw = bytes(binary.pe.get_data(rva, 4))
    return int.from_bytes(raw, "little") if len(raw) == 4 else None


def _initial_file_u32(binary: StageABinary, address: int) -> int | None:
    """Read one word only when all four bytes are backed by one PE section."""
    rva = address - binary.image_base
    sections = [
        section for section in binary.sections
        if section.rva_start <= rva
        and rva + 4 <= section.rva_start + section.raw_size
    ]
    if len(sections) != 1:
        return None
    raw = bytes(binary.pe.get_data(rva, 4))
    return int.from_bytes(raw, "little") if len(raw) == 4 else None


def _direct_constant_read32_locations(
    value: Any, path: tuple[str, ...] = (),
) -> dict[tuple[str, ...], int]:
    """Collect direct constant-address word reads by normalized IR path."""
    if isinstance(value, list):
        result: dict[tuple[str, ...], int] = {}
        for index, child in enumerate(value):
            result.update(
                _direct_constant_read32_locations(child, (*path, str(index)))
            )
        return result
    if not isinstance(value, dict):
        return {}
    if value.get("op") == "read32":
        address = _semantic_constant_word(value.get("address") or {})
        if address is not None:
            return {path: address}
    result = {}
    for key in sorted(value):
        if key != "op":
            result.update(
                _direct_constant_read32_locations(value[key], (*path, key))
            )
    return result


def _highlow_relocation_count(binary: StageABinary, address: int) -> int:
    rva = address - binary.image_base
    return sum(
        relocation["rva"] == rva and relocation["type"] == 3
        for relocation in _raw_base_relocations(binary)
    )


def _attach_initial_static_code_pointer_slots(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Infer launch-fixed writable code-pointer slots from exact PE evidence.

    This is proposal logic only. It pairs direct reads by normalized semantic
    path and requires a unique canonical code target, raw-file-backed writable
    slots, one HIGHLOW relocation per word, and a one-to-one address mapping.
    Generated Lean support must replay these facts before acceptance.
    """
    updated = deepcopy(contract)
    code_targets = list(updated.get("code_targets", []))
    target_id_counts: dict[int, int] = {}
    for target in code_targets:
        try:
            target_id = int(target["id"])
        except (KeyError, TypeError, ValueError):
            continue
        target_id_counts[target_id] = target_id_counts.get(target_id, 0) + 1

    def matching_targets(side: str, value: int) -> list[tuple[int, dict[str, Any]]]:
        matches: list[tuple[int, dict[str, Any]]] = []
        rva_key = f"{side}_rva"
        image_base = original.image_base if side == "original" else candidate.image_base
        for index, target in enumerate(code_targets):
            try:
                target_value = image_base + int(target[rva_key])
                int(target["id"])
            except (KeyError, TypeError, ValueError):
                continue
            if target_value & 0xFFFFFFFF == value:
                matches.append((index, target))
        return matches

    proposals: dict[tuple[int, int], dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    regions = list(updated.get("regions", []))
    for region_index, behavior in enumerate(behaviors):
        original_reads = _direct_constant_read32_locations(
            behavior.get("original_ir") or {}
        )
        candidate_reads = _direct_constant_read32_locations(
            behavior.get("candidate_ir") or {}
        )
        region_id = (
            regions[region_index].get("id")
            if region_index < len(regions) and isinstance(regions[region_index], dict)
            else None
        )
        for path in sorted(set(original_reads) & set(candidate_reads)):
            original_address = original_reads[path]
            candidate_address = candidate_reads[path]
            original_writable = _writable_static_word(original, original_address)
            candidate_writable = _writable_static_word(candidate, candidate_address)
            # Immutable image words belong to the existing immutable relocation
            # prover, not this writable launch-slot inference.
            if not original_writable and not candidate_writable:
                continue
            original_value = _initial_file_u32(original, original_address)
            candidate_value = _initial_file_u32(candidate, candidate_address)
            if original_value is None and candidate_value is None:
                continue
            original_matches = (
                [] if original_value is None
                else matching_targets("original", original_value)
            )
            candidate_matches = (
                [] if candidate_value is None
                else matching_targets("candidate", candidate_value)
            )
            if not original_matches and not candidate_matches:
                continue
            location = {
                "region_index": region_index,
                "region_id": region_id,
                "semantic_path": list(path),
                "original_address": original_address,
                "candidate_address": candidate_address,
                "original_initial_value": original_value,
                "candidate_initial_value": candidate_value,
            }
            same_target = (
                len(original_matches) == 1
                and len(candidate_matches) == 1
                and original_matches[0][0] == candidate_matches[0][0]
            )
            target_id = (
                int(original_matches[0][1]["id"])
                if same_target else None
            )
            if (
                not same_target
                or target_id is None
                or target_id_counts.get(target_id) != 1
            ):
                rejected.append({
                    **location,
                    "category": "initial_static_code_pointer_target_ambiguous",
                    "severity": "hard",
                    "original_target_ids": sorted({
                        int(target["id"]) for _, target in original_matches
                    }),
                    "candidate_target_ids": sorted({
                        int(target["id"]) for _, target in candidate_matches
                    }),
                    "next_action": (
                        "provide one canonical code-target pair for both initial "
                        "words or repair the static code-target map"
                    ),
                })
                continue
            key = (original_address, candidate_address)
            proposal = proposals.setdefault(key, {
                "original_address": original_address,
                "candidate_address": candidate_address,
                "target_id": target_id,
                "uses": [],
            })
            proposal["uses"].append(location)

    original_to_candidate: dict[int, set[int]] = {}
    candidate_to_original: dict[int, set[int]] = {}
    for original_address, candidate_address in proposals:
        original_to_candidate.setdefault(original_address, set()).add(candidate_address)
        candidate_to_original.setdefault(candidate_address, set()).add(original_address)
    ambiguous_pairs = {
        pair for pair in proposals
        if len(original_to_candidate[pair[0]]) != 1
        or len(candidate_to_original[pair[1]]) != 1
    }

    existing = [dict(slot) for slot in updated.get("static_word_relation_slots", [])]
    dynamic_slots = [
        dict(slot) for slot in updated.get("static_dynamic_pointer_slots", [])
    ]
    next_id = max((int(slot["id"]) for slot in existing), default=-1) + 1
    inferred: list[dict[str, Any]] = []
    already_present: list[dict[str, Any]] = []
    for pair, proposal in sorted(proposals.items()):
        if pair in ambiguous_pairs:
            rejected.append({
                "category": "initial_static_code_pointer_slot_mapping_ambiguous",
                "severity": "hard",
                **proposal,
                "candidate_addresses_for_original": sorted(
                    original_to_candidate[pair[0]]
                ),
                "original_addresses_for_candidate": sorted(
                    candidate_to_original[pair[1]]
                ),
                "next_action": (
                    "provide a one-to-one static slot mapping or repair the "
                    "normalized read pairing"
                ),
            })
            continue
        reason = None
        if not (
            _writable_static_word(original, pair[0])
            and _writable_static_word(candidate, pair[1])
        ):
            reason = "slot is not writable non-executable PE data on both sides"
        elif (
            _initial_file_u32(original, pair[0]) is None
            or _initial_file_u32(candidate, pair[1]) is None
        ):
            reason = "slot word is not fully backed by bytes in one PE section"
        elif (
            _highlow_relocation_count(original, pair[0]) != 1
            or _highlow_relocation_count(candidate, pair[1]) != 1
        ):
            reason = "slot does not have exactly one PE HIGHLOW base relocation per side"
        if reason is not None:
            rejected.append({
                "category": "initial_static_code_pointer_slot_inference_rejected",
                "severity": "hard",
                **proposal,
                "reason": reason,
                "original_highlow_relocations": _highlow_relocation_count(
                    original, pair[0]
                ),
                "candidate_highlow_relocations": _highlow_relocation_count(
                    candidate, pair[1]
                ),
                "next_action": (
                    "repair the PE slot/relocation evidence or declare no "
                    "launch-fixed code-pointer relation for this word"
                ),
            })
            continue
        conflicts = [
            slot for slot in [*existing, *dynamic_slots]
            if int(slot["original_address"]) == pair[0]
            or int(slot["candidate_address"]) == pair[1]
        ]
        expected = {
            "original_address": pair[0],
            "candidate_address": pair[1],
            "relation": "fixed_code_pointer",
            "target_id": proposal["target_id"],
        }
        exact_existing = [
            slot for slot in conflicts
            if all(slot.get(key) == value for key, value in expected.items())
        ]
        if len(conflicts) == 1 and len(exact_existing) == 1:
            already_present.append(exact_existing[0])
            continue
        if conflicts:
            rejected.append({
                "category": "initial_static_code_pointer_existing_slot_conflict",
                "severity": "hard",
                **proposal,
                "conflicting_slots": conflicts,
                "next_action": (
                    "remove the conflicting slot or provide one explicit checked "
                    "relation for this original/candidate word pair"
                ),
            })
            continue
        inferred.append({"id": next_id, **expected})
        next_id += 1

    updated["static_word_relation_slots"] = sorted(
        existing + inferred, key=lambda slot: int(slot["id"])
    )
    rejected = sorted(
        rejected,
        key=lambda item: (
            str(item.get("category", "")),
            int(item.get("region_index", -1)),
            int(item.get("original_address", -1)),
            int(item.get("candidate_address", -1)),
            json.dumps(item.get("semantic_path", []), separators=(",", ":")),
        ),
    )
    return updated, {
        "format": "spaghetti-extractor-initial-static-code-pointer-slots-v1",
        "status": (
            "proposal_requires_generated_lean_replay" if not rejected else "incomplete"
        ),
        "inferred": inferred,
        "already_present": already_present,
        "rejected": rejected,
        "counts": {
            "existing": len(existing),
            "inferred": len(inferred),
            "already_present": len(already_present),
            "rejected": len(rejected),
        },
    }


def _attach_static_dynamic_pointer_slots(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Propose typed nullable static pointer slots from checked publications.

    The proposal is intentionally narrow: both PEs must start with a zero word,
    the address mapping and object shape must be unique, and the written values
    must be the bases of one source dynamic-range relation. Lean subsequently
    checks the concrete write, slot membership, range membership, and shape.
    """
    updated = deepcopy(contract)
    proposals: dict[tuple[int, int], list[dict[str, Any]]] = {}
    rejected: list[dict[str, Any]] = []
    for region_index, (region, behavior) in enumerate(
        zip(updated.get("regions", []), behaviors, strict=True)
    ):
        original_writes = (behavior.get("original_ir") or {}).get("writes") or []
        candidate_writes = (behavior.get("candidate_ir") or {}).get("writes") or []
        if len(original_writes) != len(candidate_writes):
            continue
        for write_index, (original_write, candidate_write) in enumerate(
            zip(original_writes, candidate_writes, strict=True)
        ):
            original_address = _semantic_constant_word(
                original_write.get("address") or {}
            )
            candidate_address = _semantic_constant_word(
                candidate_write.get("address") or {}
            )
            if original_address is None or candidate_address is None:
                continue
            value = _paired_stack_word_value_claim(
                region,
                original_write.get("value") or {},
                candidate_write.get("value") or {},
                original.image_base,
                candidate.image_base,
            )
            if value is None or value.get("profile") != "dynamic_range_v1":
                continue
            relation = value.get("relation") or {}
            required_words = sorted(
                [
                    {"offset": int(word["offset"]), "kind": str(word["kind"])}
                    for word in relation.get("required_words", [])
                ],
                key=lambda word: (word["offset"], word["kind"]),
            )
            location = {
                "region_index": region_index,
                "region_id": region.get("id"),
                "write_index": write_index,
                "original_address": original_address,
                "candidate_address": candidate_address,
            }
            reason = None
            if not required_words:
                reason = "published dynamic range has no checked object-word shape"
            elif not (
                _writable_static_word(original, original_address)
                and _writable_static_word(candidate, candidate_address)
            ):
                reason = "published pointer word is not writable static PE data"
            elif _initial_u32(original, original_address) != 0 or (
                _initial_u32(candidate, candidate_address) != 0
            ):
                reason = "published pointer slot is not initially zero on both sides"
            if reason is not None:
                rejected.append({
                    **location,
                    "category": "static_dynamic_pointer_slot_inference_rejected",
                    "severity": "hard",
                    "reason": reason,
                    "next_action": (
                        "declare a checked nullable static pointer slot and object shape, "
                        "or repair the dynamic-range invariant feeding this write"
                    ),
                })
                continue
            proposals.setdefault((original_address, candidate_address), []).append({
                **location,
                "required_words": required_words,
            })

    existing = [dict(slot) for slot in updated.get("static_dynamic_pointer_slots", [])]
    existing_pairs = {
        (int(slot["original_address"]), int(slot["candidate_address"]))
        for slot in existing
    }
    next_id = max((int(slot["id"]) for slot in existing), default=-1) + 1
    inferred: list[dict[str, Any]] = []
    for addresses, uses in sorted(proposals.items()):
        shapes = {
            tuple((word["offset"], word["kind"]) for word in use["required_words"])
            for use in uses
        }
        if len(shapes) != 1:
            rejected.append({
                "category": "static_dynamic_pointer_slot_shape_ambiguous",
                "severity": "hard",
                "original_address": addresses[0],
                "candidate_address": addresses[1],
                "uses": uses,
                "next_action": "provide one explicit checked object shape for this slot",
            })
            continue
        if addresses in existing_pairs:
            continue
        shape = next(iter(shapes))
        inferred.append({
            "id": next_id,
            "original_address": addresses[0],
            "candidate_address": addresses[1],
            "required_words": [
                {"offset": offset, "kind": kind} for offset, kind in shape
            ],
        })
        next_id += 1

    updated["static_dynamic_pointer_slots"] = sorted(
        existing + inferred, key=lambda slot: int(slot["id"])
    )
    pointer_pairs = {
        (int(slot["original_address"]), int(slot["candidate_address"]))
        for slot in updated["static_dynamic_pointer_slots"]
    }
    promoted_static_words = [
        slot for slot in updated.get("static_word_relation_slots", [])
        if (int(slot["original_address"]), int(slot["candidate_address"]))
        in pointer_pairs
    ]
    updated["static_word_relation_slots"] = [
        slot for slot in updated.get("static_word_relation_slots", [])
        if (int(slot["original_address"]), int(slot["candidate_address"]))
        not in pointer_pairs
    ]
    return updated, {
        "format": "spaghetti-extractor-static-dynamic-pointer-slots-v1",
        "status": (
            "proposal_requires_generated_lean_replay" if not rejected else "incomplete"
        ),
        "inferred": inferred,
        "rejected": rejected,
        "promoted_static_word_slots": promoted_static_words,
        "counts": {
            "existing": len(existing),
            "inferred": len(inferred),
            "rejected": len(rejected),
            "promoted_static_word_slots": len(promoted_static_words),
        },
    }


def _nonzero_guard(expression: dict[str, Any]) -> dict[str, Any]:
    return {
        "op": "not",
        "value": {
            "op": "equal",
            "left": expression,
            "right": {"op": "constant", "value": 0},
        },
    }


def _dynamic_flow_edge_candidates(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    edge: dict[str, Any],
) -> list[dict[str, Any]]:
    if (
        edge.get("environment_barrier")
        or edge.get("requires_call_stack_proof")
        or edge.get("kind") not in {"jump", "branch_taken", "branch_fallthrough"}
    ):
        return []
    source_index = int(edge["source_region_index"])
    target_index = int(edge["target_region_index"])
    source = contract["regions"][source_index]
    target = contract["regions"][target_index]
    original_registers = behaviors[source_index]["original_ir"].get("registers") or {}
    candidate_registers = behaviors[source_index]["candidate_ir"].get("registers") or {}
    original_guard = edge.get("original_guard") or {}
    candidate_guard = edge.get("candidate_guard") or {}
    candidates: list[dict[str, Any]] = []
    prepared_writes = _paired_prepared_word_writes_claim(
        source,
        behaviors[source_index],
        contract.get("static_word_relation_slots", []),
        static_dynamic_pointer_slots=contract.get(
            "static_dynamic_pointer_slots", []
        ),
    )

    def post_active_words(relation: dict[str, Any]) -> list[dict[str, Any]]:
        active = deepcopy(relation.get("active_words", []))
        if prepared_writes is None:
            return active
        for write in prepared_writes.get("writes", []):
            if (
                write.get("kind") == "dynamic_word"
                and write.get("source_relation") == relation
                and write.get("relation") not in active
            ):
                active.append(deepcopy(write["relation"]))
        return sorted(active, key=lambda word: (int(word["offset"]), str(word["kind"])))

    def add(
        register_pair: dict[str, Any], relation: dict[str, Any], kind: str,
        *, active_words: list[dict[str, Any]],
    ) -> None:
        candidates.append({
            "relation": {
                "original": str(register_pair["original"]),
                "candidate": str(register_pair["candidate"]),
                "original_offset": int(relation.get("original_offset", 0)),
                "candidate_offset": int(relation.get("candidate_offset", 0)),
                "required_words": deepcopy(relation.get("required_words", [])),
                "active_words": deepcopy(active_words),
            },
            "kind": kind,
        })

    for register_pair in target.get("inputs", []):
        output_original = str(register_pair["original"])
        output_candidate = str(register_pair["candidate"])
        original_expression = original_registers.get(output_original) or {}
        candidate_expression = candidate_registers.get(output_candidate) or {}
        for source_relation in source.get("input_dynamic_range_relations", []):
            if (
                original_expression == {
                    "op": "input_reg", "reg": str(source_relation["original"]),
                }
                and candidate_expression == {
                    "op": "input_reg", "reg": str(source_relation["candidate"]),
                }
            ):
                add(
                    register_pair, source_relation, "register_preserve",
                    active_words=post_active_words(source_relation),
                )
            if int(source_relation.get("original_offset", 0)) != 0 or (
                int(source_relation.get("candidate_offset", 0)) != 0
            ):
                continue
            for word in source_relation.get("required_words", []):
                if word.get("kind") != "nullableDynamicPointer":
                    continue
                offset = int(word["offset"])
                original_read = {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {
                            "op": "input_reg",
                            "reg": str(source_relation["original"]),
                        },
                        "right": {"op": "constant", "value": offset},
                    },
                }
                candidate_read = {
                    "op": "read32",
                    "address": {
                        "op": "add",
                        "left": {
                            "op": "input_reg",
                            "reg": str(source_relation["candidate"]),
                        },
                        "right": {"op": "constant", "value": offset},
                    },
                }
                if (
                    original_expression == original_read
                    and candidate_expression == candidate_read
                    and original_guard == _nonzero_guard(original_read)
                    and candidate_guard == _nonzero_guard(candidate_read)
                ):
                    add(
                        register_pair, source_relation, "nullable_pointer_follow",
                        active_words=[],
                    )
        for stack_relation in source.get("input_dynamic_stack_range_relations", []):
            stack_offset = int(stack_relation.get("stack_offset", 0))

            def stack_read(register: str) -> dict[str, Any]:
                address: dict[str, Any] = {"op": "input_reg", "reg": register}
                if stack_offset:
                    address = {
                        "op": "add", "left": address,
                        "right": {"op": "constant", "value": stack_offset},
                    }
                return {"op": "read32", "address": address}

            window = stack_relation.get("window") or {}
            if (
                original_expression == stack_read(str(window.get("original_register")))
                and candidate_expression == stack_read(
                    str(window.get("candidate_register"))
                )
            ):
                add(
                    register_pair, stack_relation, "stack_reload",
                    active_words=post_active_words(stack_relation),
                )
        for slot in contract.get("static_dynamic_pointer_slots", []):
            original_read = {
                "op": "read32",
                "address": {
                    "op": "constant", "value": int(slot["original_address"]),
                },
            }
            candidate_read = {
                "op": "read32",
                "address": {
                    "op": "constant", "value": int(slot["candidate_address"]),
                },
            }
            if (
                original_expression == original_read
                and candidate_expression == candidate_read
                and original_guard == _nonzero_guard(original_read)
                and candidate_guard == _nonzero_guard(candidate_read)
            ):
                add(register_pair, {
                    "original_offset": 0,
                    "candidate_offset": 0,
                    "required_words": slot["required_words"],
                }, "static_pointer_seed", active_words=[])
    unique: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        key = json.dumps(candidate["relation"], sort_keys=True, separators=(",", ":"))
        unique[key] = candidate
    return list(unique.values())


def _attach_dynamic_range_flow_invariants(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Discover composable dynamic-range cutpoint invariants.

    This is proposal logic only. Every attached relation is replayed by a
    generated Lean transfer claim, and unsupported incoming edges remain hard
    frontiers in the returned audit.
    """
    updated = deepcopy(contract)
    edges = list(register_relations.get("edges", []))
    attached: list[dict[str, Any]] = []
    max_iterations = max(1, len(updated.get("regions", [])) * 8 + 1)
    for iteration in range(max_iterations):
        changed = False
        proposals: dict[tuple[int, str, str], list[dict[str, Any]]] = {}
        for edge_index, edge in enumerate(edges):
            for candidate in _dynamic_flow_edge_candidates(updated, behaviors, edge):
                relation = candidate["relation"]
                key = (
                    int(edge["target_region_index"]),
                    str(relation["original"]),
                    str(relation["candidate"]),
                )
                proposals.setdefault(key, []).append({
                    **candidate,
                    "edge_index": edge_index,
                    "source_region_index": int(edge["source_region_index"]),
                })
        for (target_index, original_register, candidate_register), rows in sorted(
            proposals.items()
        ):
            relations = {
                json.dumps(row["relation"], sort_keys=True, separators=(",", ":")):
                    row["relation"]
                for row in rows
            }
            if len(relations) != 1:
                continue
            relation = next(iter(relations.values()))
            target_relations = updated["regions"][target_index].setdefault(
                "input_dynamic_range_relations", []
            )
            conflicts = [
                existing for existing in target_relations
                if str(existing["original"]) == original_register
                or str(existing["candidate"]) == candidate_register
            ]
            if conflicts and relation not in conflicts:
                continue
            if relation not in target_relations:
                target_relations.append(relation)
                attached.append({
                    "iteration": iteration,
                    "target_region_index": target_index,
                    "relation": deepcopy(relation),
                    "origins": [
                        {
                            "edge_index": row["edge_index"],
                            "source_region_index": row["source_region_index"],
                            "kind": row["kind"],
                        }
                        for row in rows
                    ],
                })
                changed = True
        if not changed:
            converged = True
            break
    else:
        converged = False
        iteration = max_iterations - 1

    unsupported_incoming: list[dict[str, Any]] = []
    for target_index, target in enumerate(updated.get("regions", [])):
        target_relations = target.get("input_dynamic_range_relations", [])
        if not target_relations:
            continue
        incoming = [
            (edge_index, edge) for edge_index, edge in enumerate(edges)
            if int(edge["target_region_index"]) == target_index
            and not edge.get("environment_barrier")
            and not edge.get("requires_call_stack_proof")
        ]
        for relation in target_relations:
            for edge_index, edge in incoming:
                candidates = _dynamic_flow_edge_candidates(updated, behaviors, edge)
                if not any(candidate["relation"] == relation for candidate in candidates):
                    unsupported_incoming.append({
                        "edge_index": edge_index,
                        "source_region_index": int(edge["source_region_index"]),
                        "target_region_index": target_index,
                        "relation": deepcopy(relation),
                        "category": "dynamic_range_invariant_incoming_edge_unproved",
                        "severity": "hard",
                        "next_action": (
                            "supply a checked transfer, split the cutpoint invariant, "
                            "or remove the unsupported path"
                        ),
                    })
    return updated, {
        "format": "spaghetti-extractor-dynamic-range-flow-v1",
        "status": (
            "proposal_requires_generated_lean_replay"
            if converged and not unsupported_incoming else "incomplete"
        ),
        "converged": converged,
        "iterations": iteration + 1,
        "attached": attached,
        "unsupported_incoming": unsupported_incoming,
        "counts": {
            "attached": len(attached),
            "unsupported_incoming": len(unsupported_incoming),
        },
    }


def _attach_static_word_relation_slots(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    original: StageABinary,
    candidate: StageABinary,
) -> tuple[dict[str, Any], dict[str, Any]]:
    updated = deepcopy(contract)
    proposals: dict[tuple[int, int], dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    original_to_candidate: dict[int, set[int]] = {}
    candidate_to_original: dict[int, set[int]] = {}
    pointer_slots = {
        (int(slot["original_address"]), int(slot["candidate_address"]))
        for slot in updated.get("static_dynamic_pointer_slots", [])
    }
    existing = [dict(slot) for slot in updated.get("static_word_relation_slots", [])]

    for region_index, (region, behavior) in enumerate(
        zip(updated.get("regions", []), behaviors, strict=True)
    ):
        original_writes = (behavior.get("original_ir") or {}).get("writes") or []
        candidate_writes = (behavior.get("candidate_ir") or {}).get("writes") or []
        if len(original_writes) != len(candidate_writes):
            continue
        for write_index, (original_write, candidate_write) in enumerate(
            zip(original_writes, candidate_writes, strict=True)
        ):
            original_address = _semantic_constant_word(
                original_write.get("address") or {}
            )
            candidate_address = _semantic_constant_word(
                candidate_write.get("address") or {}
            )
            if original_address is None or candidate_address is None:
                continue
            if not (
                _writable_static_word(original, original_address)
                and _writable_static_word(candidate, candidate_address)
            ):
                continue
            value_claim = _paired_stack_word_value_claim(
                region,
                original_write.get("value") or {},
                candidate_write.get("value") or {},
                original.image_base,
                candidate.image_base,
                existing,
            )
            if value_claim is None:
                # A slot whose next value is an exact expression over its own
                # prior exact value is an inductive relation candidate.  Lean
                # checks both the expression tree and the slot membership;
                # launch establishment remains a separate acceptance duty.
                provisional_slot = {
                    "id": -1,
                    "original_address": original_address,
                    "candidate_address": candidate_address,
                    "relation": "exact",
                }
                witness = _paired_exact_state_expr_witness(
                    region,
                    original_write.get("value") or {},
                    candidate_write.get("value") or {},
                    [provisional_slot],
                )
                if witness is not None:
                    value_claim = {
                        "profile": "exact_expression_v1",
                        "original": original_write.get("value") or {},
                        "candidate": candidate_write.get("value") or {},
                        "witness": witness,
                    }
            relation = (
                _static_word_value_relation(value_claim)
                if value_claim is not None else None
            )
            location = {
                "region_index": region_index,
                "region_id": region.get("id"),
                "write_index": write_index,
                "original_address": original_address,
                "candidate_address": candidate_address,
            }
            if relation is None:
                rejected.append({
                    **location,
                    "category": "static_word_value_relation_unresolved",
                    "severity": "hard",
                    "next_action": (
                        "supply an exact, related-word, code-pointer, or "
                        "data-pointer value witness for this static write"
                    ),
                })
                continue
            key = (original_address, candidate_address)
            if key in pointer_slots:
                continue
            proposal = proposals.setdefault(key, {
                "original_address": original_address,
                "candidate_address": candidate_address,
                "relations": set(),
                "uses": [],
            })
            proposal["relations"].add(relation)
            proposal["uses"].append({**location, "relation": relation})
            original_to_candidate.setdefault(original_address, set()).add(
                candidate_address
            )
            candidate_to_original.setdefault(candidate_address, set()).add(
                original_address
            )

    ambiguous = {
        key
        for key in proposals
        if len(original_to_candidate[key[0]]) != 1
        or len(candidate_to_original[key[1]]) != 1
    }
    for key in sorted(ambiguous):
        proposal = proposals[key]
        rejected.append({
            "category": "static_word_address_mapping_ambiguous",
            "severity": "hard",
            "original_address": key[0],
            "candidate_address": key[1],
            "uses": proposal["uses"],
            "next_action": (
                "provide an explicit one-to-one static word mapping or repair "
                "the candidate layout"
            ),
        })

    occupied = {
        (int(slot["original_address"]), int(slot["candidate_address"]))
        for slot in existing
    }
    next_id = max((int(slot["id"]) for slot in existing), default=-1) + 1
    inferred: list[dict[str, Any]] = []
    for key in sorted(set(proposals) - ambiguous):
        if key in occupied:
            continue
        proposal = proposals[key]
        inferred.append({
            "id": next_id,
            "original_address": key[0],
            "candidate_address": key[1],
            "relation": _merge_static_word_relations(proposal["relations"]),
        })
        next_id += 1
    updated["static_word_relation_slots"] = sorted(
        existing + inferred, key=lambda slot: int(slot["id"])
    )
    return updated, {
        "format": "spaghetti-extractor-static-word-relations-v1",
        "status": "proposal_requires_generated_lean_replay",
        "inferred": inferred,
        "rejected": rejected,
        "counts": {
            "existing": len(existing),
            "inferred": len(inferred),
            "rejected": len(rejected),
        },
    }
