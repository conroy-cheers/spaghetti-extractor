"""Shared numeric lowering of one supplied native range and authority inventory.

Selectors are positions in this complete ordered inventory, never semantic
identities or evidence that the supplied inventory is complete. Native planning
and proof correspondence use this same lowering; caller admission is separate.
"""

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from .range_ownership import RangeOwnershipError, parse_range_ownership


class RangeBindingError(ToolkitInputError):
    """A supplied range inventory cannot determine unambiguous bindings."""


_PRODUCERS = frozenset({
    "add_result_range", "add_result_pointee_ranges",
    "add_argument_pointee_ranges", "add_argument_interface_ranges",
})
_SITE_FIELDS = frozenset({
    "instruction_rva", "target_iat_rva", "target_catalog_index", "argument_base_offset",
})


def range_producer_groups(rules):
    """Group repeated sites, never distinct contracts that share a display id.

    A contract can produce several different ranges at a site. Such a contract
    still needs a more specific locator; choosing one output would be unsound.
    """
    candidates: dict[str, list[int]] = {}
    for index, rule in enumerate(rules, 1):
        if rule["action"] in _PRODUCERS:
            candidates.setdefault(rule["contract_id"], []).append(index)
    groups: dict[str, tuple[int, ...]] = {}
    rejected: dict[str, str] = {}
    for identity, indexes in candidates.items():
        selected = [rules[index - 1] for index in indexes]
        if len(selected) > 1:
            digests = {rule.get("contract_identity_sha256") for rule in selected}
            if len(digests) != 1 or any(
                not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)
                for digest in digests
            ):
                rejected[identity] = "producer sites lack one exact checked contract identity"
                continue
            shapes = {canonical_sha256_v3({
                key: value for key, value in rule.items() if key not in _SITE_FIELDS
            }) for rule in selected}
            sites = {(rule["instruction_rva"], rule.get("target_iat_rva") or 0,
                      rule.get("target_catalog_index") or 0) for rule in selected}
            if len(shapes) != 1 or len(sites) != len(selected):
                rejected[identity] = "producer sites have conflicting outputs or duplicate site rules"
                continue
        groups[identity] = tuple(indexes)
    return groups, rejected, candidates


def range_object_selectors(object_rules, external_range_rules):
    """Lower only groups consistent with the bound authority inventory."""
    groups, _, _ = range_producer_groups(external_range_rules)
    selectors: dict[int, int] = {}
    representatives: dict[int, int] = {}
    for object_index, rule in enumerate(object_rules, 1):
        if rule["locator"]["kind"] not in {"external_allocation", "resource"} or rule["locator"]["subject_rva"] == 0:
            continue
        group = groups.get(rule["locator"]["identity"])
        if group is None or group[0] != rule["locator"]["subject_rva"]:
            raise RangeBindingError("allocation authority producer group is missing or stale")
        for member in group:
            if member in selectors:
                raise RangeBindingError("allocation producer group has ambiguous object authorities")
            selectors[member] = object_index
            representatives[member] = group[0]
    return selectors, representatives


def range_ownership_fields(rules):
    ownerships = []
    for rule in rules:
        raw = rule.get("ownership")
        if rule["action"] == "release_argument_range" and (
            not isinstance(rule.get("release"), dict) or rule["release"].get("ownership") != raw
        ):
            raise RangeBindingError("release and range ownership contracts disagree")
        if raw is not None and rule["action"] not in {"add_result_range", "release_argument_range"}:
            raise RangeBindingError("ownership is attached to an unsupported range action")
        try:
            ownerships.append(parse_range_ownership(raw, argument_words=rule["argument_count"],
                                                   context=rule["contract_id"]))
        except RangeOwnershipError as exc:
            raise RangeBindingError(str(exc)) from exc
    families = {name: index for index, name in enumerate(sorted({
        ownership.family for ownership in ownerships if ownership is not None}), 1)}
    rows = [(0, 0) if ownership is None else
            (families[ownership.family], 0 if ownership.owner_argument is None else ownership.owner_argument + 1)
            for ownership in ownerships]
    return rows, families
