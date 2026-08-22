from __future__ import annotations

import copy
import re
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3


IDENTIFIER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:/+-]*[A-Za-z0-9])?\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class CallProtocolError(ValueError):
    """A typed call artifact is malformed, stale, or contradictory."""


def object_(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CallProtocolError(f"{context} must be an object")
    return value


def array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise CallProtocolError(f"{context} must be an array")
    return value


def exact(row: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(row) != fields:
        raise CallProtocolError(
            f"{context} fields differ: missing={sorted(fields-set(row))!r}, "
            f"extra={sorted(set(row)-fields)!r}"
        )


def text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CallProtocolError(f"{context} must be a nonempty string")
    return value


def identifier(value: object, context: str) -> str:
    result = text(value, context)
    if IDENTIFIER.fullmatch(result) is None:
        raise CallProtocolError(f"{context} is not canonical")
    return result


def digest(value: object, context: str) -> str:
    result = text(value, context)
    if DIGEST.fullmatch(result) is None:
        raise CallProtocolError(f"{context} must be a lowercase SHA-256")
    return result


def uint(value: object, context: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise CallProtocolError(f"{context} must be an integer >= {minimum}")
    return value


def sint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CallProtocolError(f"{context} must be an integer")
    return value


def boolean(value: object, context: str) -> bool:
    if not isinstance(value, bool):
        raise CallProtocolError(f"{context} must be Boolean")
    return value


def canonical(value: object) -> object:
    return copy.deepcopy(value)


def content_id(namespace: str, core: Mapping[str, object]) -> str:
    return f"{namespace}:{canonical_sha256_v3(core)}"


def verify_content_id(
    observed: object, namespace: str, core: Mapping[str, object], context: str
) -> str:
    result = identifier(observed, f"{context} id")
    if result != content_id(namespace, core):
        raise CallProtocolError(f"{context} id does not bind its contents")
    return result
