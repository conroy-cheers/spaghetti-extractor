from __future__ import annotations

import copy
import re
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3


_IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:/+-]*[A-Za-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class BoundaryModelError(ValueError):
    """A canonical boundary artifact is malformed, stale, or contradictory."""


def object_(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise BoundaryModelError(f"{context} must be an object")
    return value


def array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise BoundaryModelError(f"{context} must be an array")
    return value


def exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise BoundaryModelError(
            f"{context} fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}"
        )


def text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise BoundaryModelError(f"{context} must be a nonempty string")
    return value


def identifier(value: object, context: str) -> str:
    result = text(value, context)
    if _IDENTIFIER.fullmatch(result) is None:
        raise BoundaryModelError(f"{context} is not canonical")
    return result


def digest(value: object, context: str) -> str:
    result = text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise BoundaryModelError(f"{context} must be a lowercase SHA-256")
    return result


def uint(value: object, context: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise BoundaryModelError(f"{context} must be an integer >= {minimum}")
    return value


def boolean(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise BoundaryModelError(f"{context} must be Boolean")
    return value


def canonical(value: object) -> object:
    return copy.deepcopy(value)


def content_sha256(value: Mapping[str, object]) -> str:
    return canonical_sha256_v3(value)


def content_id(namespace: str, value: Mapping[str, object]) -> str:
    return f"{namespace}:{content_sha256(value)}"


def ordered_identifiers(value: object, context: str) -> tuple[str, ...]:
    result = tuple(identifier(item, context) for item in array(value, context))
    if result != tuple(sorted(set(result))):
        raise BoundaryModelError(f"{context} must be unique and ordered")
    return result
