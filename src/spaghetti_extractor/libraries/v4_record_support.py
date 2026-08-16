"""Shared strict-codec primitives for V4 library artifacts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Generic, Iterable, Mapping, TypeVar


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
STATUSES = frozenset({"complete", "incomplete", "violated"})
ISSUE_STATUSES = frozenset({"incomplete", "violated"})
ISSUE_FAMILIES = frozenset({"identity", "boundary", "implementation"})


class LibraryV4RecordError(ValueError):
    """A V4 library artifact is malformed or does not bind its contents."""

    def __init__(self, code: str, message: str, *, location: str) -> None:
        super().__init__(f"{location}: {message}")
        self.code = code
        self.location = location


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def stable_id(namespace: str, value: object) -> str:
    return f"{namespace}:{canonical_sha256(value)}"


def fail(code: str, message: str, location: str) -> None:
    raise LibraryV4RecordError(code, message, location=location)


def strict_object(
    value: object,
    required: Iterable[str],
    location: str,
    *,
    optional: Iterable[str] = (),
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        fail("record_type_mismatch", "expected an object", location)
    keys = set(value)
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - keys)
    unknown = sorted(keys - allowed)
    if missing:
        fail("record_fields_missing", f"missing fields {missing!r}", location)
    if unknown:
        fail("record_fields_unknown", f"unknown fields {unknown!r}", location)
    return value


def array(value: object, location: str) -> tuple[Any, ...]:
    if not isinstance(value, list):
        fail("record_type_mismatch", "expected an array", location)
    return tuple(value)


def text(value: object, location: str) -> str:
    if not isinstance(value, str) or not value:
        fail("record_type_mismatch", "expected a nonempty string", location)
    return value


def optional_text(value: object, location: str) -> str | None:
    return None if value is None else text(value, location)


def sha256_text(value: object, location: str) -> str:
    result = text(value, location)
    if SHA256_RE.fullmatch(result) is None:
        fail("record_value_invalid", "expected a lowercase SHA-256", location)
    return result


def integer(value: object, location: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        fail("record_type_mismatch", "expected an integer", location)
    if minimum is not None and value < minimum:
        fail("record_value_invalid", f"must be at least {minimum}", location)
    return value


def choice(value: object, choices: frozenset[str], location: str) -> str:
    result = text(value, location)
    if result not in choices:
        fail("record_value_invalid", f"unsupported value {result!r}", location)
    return result


def text_tuple(
    value: object, location: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    result = tuple(
        text(item, f"{location}[{index}]")
        for index, item in enumerate(array(value, location))
    )
    validate_text_tuple(result, location, nonempty=nonempty)
    return result


def validate_text_tuple(
    values: tuple[str, ...], location: str, *, nonempty: bool = False
) -> None:
    for index, value in enumerate(values):
        text(value, f"{location}[{index}]")
    if nonempty and not values:
        fail("record_value_invalid", "must not be empty", location)
    if tuple(sorted(set(values))) != values:
        fail(
            "record_order_invalid",
            "values must be unique and canonically sorted",
            location,
        )


def status_from(values: Iterable[str]) -> str:
    statuses = set(values)
    if "violated" in statuses:
        return "violated"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


T = TypeVar("T")


@dataclass(frozen=True)
class StrictCodec(Generic[T]):
    encode: Callable[[T], dict[str, Any]]
    decode: Callable[[object, str], T]

    def dumps(self, value: T) -> bytes:
        return canonical_json_bytes(self.encode(value)) + b"\n"

    def loads(self, data: bytes | str, *, location: str = "record") -> T:
        try:
            value = json.loads(data)
        except (TypeError, ValueError) as error:
            raise LibraryV4RecordError(
                "invalid_json", str(error), location=location
            ) from error
        return self.decode(value, location)

    def read(self, path: Path | str) -> T:
        source = Path(path)
        try:
            data = source.read_bytes()
        except OSError as error:
            raise LibraryV4RecordError(
                "artifact_read_failed", str(error), location=str(source)
            ) from error
        return self.loads(data, location=str(source))

    def write(self, path: Path | str, value: T) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.dumps(value))


__all__ = [
    "ISSUE_FAMILIES",
    "ISSUE_STATUSES",
    "STATUSES",
    "LibraryV4RecordError",
    "StrictCodec",
    "array",
    "canonical_json_bytes",
    "canonical_sha256",
    "choice",
    "fail",
    "integer",
    "optional_text",
    "sha256_text",
    "stable_id",
    "status_from",
    "strict_object",
    "text",
    "text_tuple",
    "validate_text_tuple",
]
