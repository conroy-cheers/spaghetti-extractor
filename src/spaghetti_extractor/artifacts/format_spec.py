"""Dependency-free declarations for domain-owned artifact formats."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


_FORMAT = re.compile(r"^spaghetti-extractor-[a-z0-9][a-z0-9-]*-v([1-9][0-9]*)$")
_SYMBOL = re.compile(r"^[A-Z][A-Z0-9_]*_FORMAT$")
_MODULE = re.compile(r"^spaghetti_extractor(?:\.[a-z][a-z0-9_]*)+$")
_ROLE = re.compile(r"^[a-z][a-z0-9_]*$")
_STATES = frozenset({"active", "retired"})


@dataclass(frozen=True)
class FormatSpecV1:
    literal: str
    version: int
    owner: str
    codec: str
    role: str
    state: str
    symbol: str

    def __post_init__(self) -> None:
        match = _FORMAT.fullmatch(self.literal)
        if match is None or int(match.group(1)) != self.version:
            raise ValueError("format literal and declared version disagree")
        if self.version < 1:
            raise ValueError("format version must be positive")
        if _MODULE.fullmatch(self.owner) is None:
            raise ValueError("format owner must be a package module")
        if _MODULE.fullmatch(self.codec) is None:
            raise ValueError("format codec must be a package module")
        if _ROLE.fullmatch(self.role) is None:
            raise ValueError("format role is malformed")
        if self.state not in _STATES:
            raise ValueError("format state must be active or retired")
        if _SYMBOL.fullmatch(self.symbol) is None:
            raise ValueError("format symbol is malformed")

    def to_payload(self) -> dict[str, Any]:
        return {
            "literal": self.literal,
            "version": self.version,
            "owner": self.owner,
            "codec": self.codec,
            "role": self.role,
            "state": self.state,
            "symbol": self.symbol,
        }

    @classmethod
    def parse(cls, raw: Mapping[str, object]) -> "FormatSpecV1":
        expected = {
            "literal", "version", "owner", "codec", "role", "state", "symbol"
        }
        if set(raw) != expected:
            raise ValueError("format specification fields are incomplete")
        version = raw["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise ValueError("format version must be an integer")
        values = {
            key: raw[key]
            for key in expected - {"version"}
        }
        if any(not isinstance(value, str) for value in values.values()):
            raise ValueError("format specification text fields are malformed")
        return cls(version=version, **values)  # type: ignore[arg-type]


__all__ = ["FormatSpecV1"]
