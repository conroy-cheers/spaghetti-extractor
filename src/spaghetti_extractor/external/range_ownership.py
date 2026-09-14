"""Checked allocator-family and owner-argument identities for range effects."""

from dataclasses import dataclass
from typing import Any, Mapping

from ..errors import ToolkitInputError


class RangeOwnershipError(ToolkitInputError):
    """Range ownership metadata is malformed or attached to another effect."""


@dataclass(frozen=True, order=True)
class RangeOwnership:
    family: str
    owner_argument: int | None

    def payload(self) -> dict[str, Any]:
        return {"family": self.family, "owner_argument": self.owner_argument}


def parse_range_ownership(value, *, argument_words: int, context: str):
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {"family", "owner_argument"}:
        raise RangeOwnershipError(f"{context} requires explicit family and owner_argument")
    family, owner = value["family"], value["owner_argument"]
    if (not isinstance(family, str) or not 1 <= len(family) <= 96
            or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for char in family)):
        raise RangeOwnershipError(f"{context} has an invalid allocation family")
    if owner is not None and (type(owner) is not int or not 0 <= owner < argument_words):
        raise RangeOwnershipError(f"{context} owner argument is out of bounds")
    return RangeOwnership(family, owner)


def validate_range_ownership_relations(value, *, argument_words, context):
    relations = value.get("result_register_relations", [])
    if not isinstance(relations, list):
        return
    for relation in relations:
        if not isinstance(relation, Mapping) or relation.get("ownership") is None:
            continue
        if relation.get("relation") != "dynamic_range_base":
            raise RangeOwnershipError(f"{context} attaches ownership without a range result")
        if type(argument_words) is not int:
            raise RangeOwnershipError(f"{context} ownership requires a checked argument frame")
        parse_range_ownership(relation["ownership"], argument_words=argument_words, context=context)
