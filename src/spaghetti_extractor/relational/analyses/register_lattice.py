from __future__ import annotations

from typing import Any


_REGISTER_CODE_POINTER_DISJUNCTION_BUDGET = 8
_REGISTER_RELATION_KINDS = {
    "exact",
    "fixed_word",
    "code_pointer",
    "data_pointer",
    "fixed_code_pointer",
    "related_word",
}
RegisterRelation = str | dict[str, Any]


def _register_code_pointer_producer_witness(
    witness: object,
    *,
    target_id: int,
) -> dict[str, Any] | None:
    if not isinstance(witness, dict) or set(witness) != {
        "profile",
        "region_id",
        "region_index",
        "claim_kind",
        "original_register",
        "candidate_register",
        "target_id",
    }:
        return None
    if (
        witness.get("profile") != "register_code_pointer_producer_v1"
        or not isinstance(witness.get("region_id"), str)
        or not witness["region_id"]
        or not isinstance(witness.get("region_index"), int)
        or isinstance(witness["region_index"], bool)
        or witness["region_index"] < 0
        or not isinstance(witness.get("claim_kind"), str)
        or not witness["claim_kind"]
        or not isinstance(witness.get("original_register"), str)
        or not witness["original_register"]
        or not isinstance(witness.get("candidate_register"), str)
        or not witness["candidate_register"]
        or witness.get("target_id") != target_id
    ):
        return None
    return {
        "profile": "register_code_pointer_producer_v1",
        "region_id": witness["region_id"],
        "region_index": int(witness["region_index"]),
        "claim_kind": witness["claim_kind"],
        "original_register": witness["original_register"],
        "candidate_register": witness["candidate_register"],
        "target_id": target_id,
    }


def _register_code_pointer_provenance_payload(
    relation: RegisterRelation,
) -> dict[str, Any] | None:
    if not (
        isinstance(relation, dict)
        and relation.get("relation") == "fixed_code_pointer"
        and set(relation) == {"relation", "target_alternatives"}
        and isinstance(relation.get("target_alternatives"), list)
        and relation["target_alternatives"]
    ):
        return None
    alternatives = []
    for alternative in relation["target_alternatives"]:
        if not isinstance(alternative, dict) or set(alternative) != {
            "target_id", "producer_witnesses",
        }:
            return None
        target_id = alternative.get("target_id")
        witnesses = alternative.get("producer_witnesses")
        if (
            not isinstance(target_id, int)
            or isinstance(target_id, bool)
            or target_id < 0
            or not isinstance(witnesses, list)
            or not witnesses
        ):
            return None
        canonical_witnesses = []
        for witness in witnesses:
            canonical = _register_code_pointer_producer_witness(
                witness, target_id=target_id,
            )
            if canonical is None:
                return None
            canonical_witnesses.append(canonical)
        unique_witnesses = {
            tuple(sorted(witness.items())): witness
            for witness in canonical_witnesses
        }
        alternatives.append({
            "target_id": target_id,
            "producer_witnesses": sorted(
                unique_witnesses.values(),
                key=lambda witness: (
                    witness["region_index"], witness["region_id"],
                    witness["original_register"], witness["candidate_register"],
                    witness["claim_kind"],
                ),
            ),
        })
    if [item["target_id"] for item in alternatives] != sorted({
        item["target_id"] for item in alternatives
    }):
        return None
    return {
        "relation": "fixed_code_pointer",
        "target_alternatives": alternatives,
    }


def _register_code_pointer_producer_relation(
    *,
    target_id: int,
    region_id: str,
    region_index: int,
    claim_kind: str,
    original_register: str,
    candidate_register: str,
) -> RegisterRelation:
    relation: RegisterRelation = {
        "relation": "fixed_code_pointer",
        "target_alternatives": [{
            "target_id": target_id,
            "producer_witnesses": [{
                "profile": "register_code_pointer_producer_v1",
                "region_id": region_id,
                "region_index": region_index,
                "claim_kind": claim_kind,
                "original_register": original_register,
                "candidate_register": candidate_register,
                "target_id": target_id,
            }],
        }],
    }
    payload = _register_code_pointer_provenance_payload(relation)
    return payload if payload is not None else "related_word"


def _register_relation_kind(relation: RegisterRelation) -> str:
    if isinstance(relation, str):
        return relation
    return str(relation.get("relation", "related_word"))


def _register_relation_payload(relation: RegisterRelation) -> dict[str, Any]:
    kind = _register_relation_kind(relation)
    provenance = _register_code_pointer_provenance_payload(relation)
    if provenance is not None:
        return provenance
    if kind == "fixed_word" and isinstance(relation, dict):
        value = relation.get("value")
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < 2**32
        ):
            return {"relation": kind, "value": int(value)}
    if kind == "fixed_code_pointer" and isinstance(relation, dict):
        target_id = relation.get("target_id")
        if (
            isinstance(target_id, int)
            and not isinstance(target_id, bool)
            and target_id >= 0
        ):
            return {"relation": kind, "target_id": int(target_id)}
    if kind in _REGISTER_RELATION_KINDS - {"fixed_word", "fixed_code_pointer"}:
        return {"relation": kind}
    return {"relation": "related_word"}


def _register_relation_key(
    relation: RegisterRelation,
) -> tuple[Any, ...]:
    payload = _register_relation_payload(relation)
    provenance = _register_code_pointer_provenance_payload(payload)
    if provenance is not None:
        return (
            "fixed_code_pointer",
            tuple(
                (
                    alternative["target_id"],
                    tuple(
                        tuple(sorted(witness.items()))
                        for witness in alternative["producer_witnesses"]
                    ),
                )
                for alternative in provenance["target_alternatives"]
            ),
        )
    return payload["relation"], payload.get(
        "target_id", payload.get("value")
    )


def _register_relation_join(
    relations: list[RegisterRelation],
    *,
    finite_code_pointer_budget: int = _REGISTER_CODE_POINTER_DISJUNCTION_BUDGET,
) -> RegisterRelation:
    if (
        not isinstance(finite_code_pointer_budget, int)
        or isinstance(finite_code_pointer_budget, bool)
        or finite_code_pointer_budget <= 0
    ):
        raise ValueError("finite code-pointer budget must be positive")
    if not relations:
        return "related_word"
    provenance_relations = [
        _register_code_pointer_provenance_payload(relation)
        for relation in relations
    ]
    if any(payload is not None for payload in provenance_relations):
        if any(payload is None for payload in provenance_relations):
            return "related_word"
        by_target: dict[int, dict[tuple[tuple[str, Any], ...], dict[str, Any]]] = {}
        for payload in provenance_relations:
            assert payload is not None
            for alternative in payload["target_alternatives"]:
                target_id = int(alternative["target_id"])
                witnesses = by_target.setdefault(target_id, {})
                for witness in alternative["producer_witnesses"]:
                    witnesses[tuple(sorted(witness.items()))] = witness
        if len(by_target) > finite_code_pointer_budget:
            return "related_word"
        return {
            "relation": "fixed_code_pointer",
            "target_alternatives": [
                {
                    "target_id": target_id,
                    "producer_witnesses": sorted(
                        witnesses.values(),
                        key=lambda witness: (
                            witness["region_index"], witness["region_id"],
                            witness["original_register"],
                            witness["candidate_register"], witness["claim_kind"],
                        ),
                    ),
                }
                for target_id, witnesses in sorted(by_target.items())
            ],
        }
    keys = {_register_relation_key(relation) for relation in relations}
    if len(keys) != 1:
        if all(
            _register_relation_kind(relation) in {"fixed_word", "exact"}
            for relation in relations
        ):
            return "exact"
        return "related_word"
    if _register_relation_kind(relations[0]) in {
        "fixed_word", "fixed_code_pointer",
    }:
        return _register_relation_payload(relations[0])
    return _register_relation_kind(relations[0])


def _register_relation_implies(
    source: RegisterRelation, target: RegisterRelation,
) -> bool:
    source_key = _register_relation_key(source)
    target_key = _register_relation_key(target)
    if source_key == target_key or target_key[0] == "related_word":
        return True
    if source_key[0] == "fixed_word" and target_key[0] == "exact":
        return True
    return source_key[0] == "fixed_code_pointer" and target_key[0] == "code_pointer"


def _register_relation_implies_exact(relation: RegisterRelation) -> bool:
    return _register_relation_kind(relation) in {"exact", "fixed_word"}


__all__ = [
    "RegisterRelation",
    "_REGISTER_CODE_POINTER_DISJUNCTION_BUDGET",
    "_REGISTER_RELATION_KINDS",
    "_register_code_pointer_producer_relation",
    "_register_code_pointer_provenance_payload",
    "_register_relation_implies",
    "_register_relation_implies_exact",
    "_register_relation_join",
    "_register_relation_key",
    "_register_relation_kind",
    "_register_relation_payload",
]
