"""Canonical finite bijections between logical and physical machine words."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


class FiniteWordMapError(ValueError):
    """A finite logical/physical word map is malformed."""


@dataclass(frozen=True, order=True)
class FiniteWordMapCase:
    logical_value: int
    physical_value: int

    def to_payload(self) -> dict[str, int]:
        return {
            "logical_value": self.logical_value,
            "physical_value": self.physical_value,
        }


def parse_finite_word_map(
    value: object, *, context: str
) -> tuple[int, tuple[FiniteWordMapCase, ...]]:
    """Parse one total-on-domain finite word map from a service transducer."""

    if not isinstance(value, Mapping):
        raise FiniteWordMapError(f"{context} is not an object")
    if set(value) != {"kind", "parameter_index", "cases"}:
        raise FiniteWordMapError(f"{context} fields differ")
    if value.get("kind") != "finite_word_map":
        raise FiniteWordMapError(f"{context} kind is unsupported")
    parameter_index = _uint(value.get("parameter_index"), f"{context} parameter")
    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 32:
        raise FiniteWordMapError(f"{context} requires 1..32 cases")
    cases: list[FiniteWordMapCase] = []
    for index, raw_case in enumerate(raw_cases):
        case_context = f"{context} case {index}"
        if not isinstance(raw_case, Mapping) or set(raw_case) != {
            "logical_value",
            "physical_value",
        }:
            raise FiniteWordMapError(f"{case_context} fields differ")
        cases.append(
            FiniteWordMapCase(
                _word(raw_case.get("logical_value"), f"{case_context} logical value"),
                _word(
                    raw_case.get("physical_value"),
                    f"{case_context} physical value",
                ),
            )
        )
    result = tuple(cases)
    if result != tuple(sorted(result)):
        raise FiniteWordMapError(f"{context} cases are not canonically ordered")
    if len({item.logical_value for item in result}) != len(result):
        raise FiniteWordMapError(f"{context} logical values are duplicated")
    if len({item.physical_value for item in result}) != len(result):
        raise FiniteWordMapError(f"{context} physical values are duplicated")
    return parameter_index, result


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise FiniteWordMapError(f"{context} is invalid")
    return value


def _word(value: object, context: str) -> int:
    result = _uint(value, context)
    if result > 0xFFFFFFFF:
        raise FiniteWordMapError(f"{context} exceeds one word")
    return result


__all__ = [
    "FiniteWordMapCase",
    "FiniteWordMapError",
    "parse_finite_word_map",
]
