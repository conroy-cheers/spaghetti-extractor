"""Explicit success and admitted-call conditions for whole-range release."""

from dataclasses import dataclass
from typing import Any, Mapping

from .range_ownership import RangeOwnership, RangeOwnershipError, parse_range_ownership
from ..errors import ToolkitInputError


class RangeReleaseError(ToolkitInputError):
    """A release effect lacks an unambiguous executable condition."""


@dataclass(frozen=True, order=True)
class RangeRelease:
    success: str
    argument_equals: tuple[tuple[int, int], ...]
    ownership: RangeOwnership | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "success": self.success,
            **({"ownership": self.ownership.payload()} if self.ownership is not None else {}),
            "argument_equals": [
                {"argument_index": index, "value": value}
                for index, value in self.argument_equals
            ],
        }


def parse_range_release(
    value: Any, *, argument_words: int, context: str,
) -> RangeRelease:
    if not isinstance(value, Mapping) or set(value) - {"ownership"} != {
        "success", "argument_equals",
    }:
        raise RangeReleaseError(
            f"{context} requires explicit release success and argument_equals"
        )
    success = value["success"]
    if not isinstance(success, str) or success not in {
        "always", "eax_zero", "eax_nonzero",
    }:
        raise RangeReleaseError(f"{context} has unsupported release success")
    guards = value["argument_equals"]
    if not isinstance(guards, list) or len(guards) > argument_words:
        raise RangeReleaseError(f"{context} has invalid release argument guards")
    result: dict[int, int] = {}
    for guard in guards:
        if not isinstance(guard, Mapping) or set(guard) != {
            "argument_index", "value",
        }:
            raise RangeReleaseError(f"{context} has malformed release argument guard")
        index, expected = guard["argument_index"], guard["value"]
        if type(index) is not int or not 0 <= index < argument_words:
            raise RangeReleaseError(f"{context} release guard argument is out of bounds")
        if type(expected) is not int or not 0 <= expected <= 0xFFFFFFFF:
            raise RangeReleaseError(f"{context} release guard value must be uint32")
        if index in result:
            raise RangeReleaseError(f"{context} has duplicate release guard argument")
        result[index] = expected
    try:
        ownership = parse_range_ownership(value.get("ownership"), argument_words=argument_words, context=context)
    except RangeOwnershipError as exc:
        raise RangeReleaseError(str(exc)) from exc
    return RangeRelease(success, tuple(sorted(result.items())), ownership)


def machine_range_release(
    value: Mapping[str, Any], *, argument_words: int | None, context: str,
) -> RangeRelease | None:
    """Read the same condition at profile, checked-contract and native intake."""
    raw = value.get("world_effect_release")
    if value.get("world_effect") != "dynamicRangeRelease":
        if raw is not None or value.get("world_effect_argument") is not None:
            raise RangeReleaseError(f"{context} has release metadata without a release effect")
        return None
    argument = value.get("world_effect_argument")
    if (type(argument_words) is not int or not 0 <= argument_words <= 256
            or type(argument) is not int or not 0 <= argument < argument_words):
        raise RangeReleaseError(f"{context} release argument is out of bounds")
    return parse_range_release(raw, argument_words=argument_words, context=context)
