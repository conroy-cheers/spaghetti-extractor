"""Bind allocation authorities to consistent checked producer-site groups."""

from dataclasses import replace
from typing import Any

from ..external.range_bindings import RangeBindingError, range_object_selectors, range_producer_groups
from .runtime_model import CandidateRuntimeError, NativeExternalRangeRule, NativeObjectAuthorityRule


def allocation_producer_groups(rules: tuple[NativeExternalRangeRule, ...]):
    return range_producer_groups([rule.payload() for rule in rules])


def _bind_dynamic_external_object_rules(
    object_rules: list[NativeObjectAuthorityRule],
    external_range_rules: tuple[NativeExternalRangeRule, ...],
    blockers: list[dict[str, Any]],
) -> list[NativeObjectAuthorityRule]:
    groups, rejected, candidates = allocation_producer_groups(external_range_rules)
    resolved = []
    authorities: dict[int, list[int]] = {}
    for rule in object_rules:
        if rule.locator_kind not in {"external_allocation", "resource"}:
            resolved.append(rule)
            continue
        group = groups.get(rule.locator_identity)
        if group is None:
            blockers.append({
                "category": "runtime_external_allocation_locator_unresolved"
                if rule.locator_kind == "external_allocation" else "runtime_resource_locator_unresolved",
                "rule_id": rule.identity, "allocation_id": rule.locator_identity,
                "matching_range_rules": len(candidates.get(rule.locator_identity, ())),
                "detail": rejected.get(rule.locator_identity, "no checked producer sites"),
            })
            resolved.append(replace(rule, locator_subject_rva=0))
            continue
        # Reuse the existing selector representation. The first producer is a
        # representative, while every member retains its own physical site.
        authorities.setdefault(group[0], []).append(len(resolved))
        resolved.append(replace(rule, locator_subject_rva=group[0]))
    for indexes in authorities.values():
        if len(indexes) == 1:
            continue
        for index in indexes:
            rule = resolved[index]
            blockers.append({
                "category": "runtime_external_allocation_authority_ambiguous"
                if rule.locator_kind == "external_allocation" else "runtime_resource_authority_ambiguous",
                "rule_id": rule.identity, "allocation_id": rule.locator_identity,
            })
            resolved[index] = replace(rule, locator_subject_rva=0)
    return resolved


def allocation_object_selectors(object_rules, external_range_rules):
    try:
        return range_object_selectors([rule.payload() for rule in object_rules],
                                      [rule.payload() for rule in external_range_rules])
    except RangeBindingError as exc:
        raise CandidateRuntimeError(str(exc)) from exc
