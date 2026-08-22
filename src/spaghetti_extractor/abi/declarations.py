"""Pinned declaration and debug metadata for physical ABI catalogs.

Declarations are strong evidence only because they are content-bound to a
specific toolchain snapshot and source artifact.  Catalog construction still
intersects them with symbol-decoration and machine-derived constraints; a
contradiction is never resolved in favor of a declaration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..artifacts.formats import PHYSICAL_ABI_DECLARATIONS_FORMAT
from .model import (
    AbiModelError,
    BoundaryEffectsV1,
    PhysicalAbiProfileV1,
    PortablePrototypeV1,
    canonical_json_bytes,
    canonical_sha256,
    stable_id,
)


_SOURCE_KINDS = frozenset({"header_ast", "debug_info", "reviewed_definition"})


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AbiModelError(f"{label} must be nonempty")
    return value


def _sha256(value: object, label: str) -> str:
    result = _identifier(value, label)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise AbiModelError(f"{label} must be a lowercase SHA-256")
    return result


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AbiModelError(f"{label} must be an array")
    result = tuple(_identifier(item, label) for item in value)
    if result != tuple(sorted(set(result))):
        raise AbiModelError(f"{label} must be sorted and unique")
    return result


@dataclass(frozen=True)
class PhysicalAbiDeclarationV1:
    declaration_id: str
    symbols: tuple[str, ...]
    source_kind: str
    source_sha256: str
    producer: str
    profile: PhysicalAbiProfileV1
    prototype: PortablePrototypeV1 | None
    effects: BoundaryEffectsV1 | None
    dependency_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        symbols: Iterable[str],
        source_kind: str,
        source_sha256: str,
        producer: str,
        profile: PhysicalAbiProfileV1,
        prototype: PortablePrototypeV1 | None = None,
        effects: BoundaryEffectsV1 | None = None,
        dependency_ids: Iterable[str] = (),
    ) -> "PhysicalAbiDeclarationV1":
        canonical_symbols = tuple(sorted(set(symbols)))
        if not canonical_symbols or any(not symbol for symbol in canonical_symbols):
            raise AbiModelError("physical ABI declaration needs nonempty symbols")
        if source_kind not in _SOURCE_KINDS:
            raise AbiModelError(f"unsupported ABI declaration source {source_kind!r}")
        source_digest = _sha256(source_sha256, "ABI declaration source SHA-256")
        producer_name = _identifier(producer, "ABI declaration producer")
        dependencies = tuple(sorted(set(dependency_ids)))
        if prototype is not None and prototype.physical_profile_id != profile.profile_id:
            raise AbiModelError("portable prototype references another physical profile")
        core = {
            "symbols": list(canonical_symbols),
            "source_kind": source_kind,
            "source_sha256": source_digest,
            "producer": producer_name,
            "profile": profile.to_payload(),
            "prototype": None if prototype is None else prototype.to_payload(),
            "effects": None if effects is None else effects.to_payload(),
            "dependency_ids": list(dependencies),
        }
        return cls(
            stable_id("physical-abi-declaration-v1", core),
            canonical_symbols,
            source_kind,
            source_digest,
            producer_name,
            profile,
            prototype,
            effects,
            dependencies,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.declaration_id,
            "symbols": list(self.symbols),
            "source_kind": self.source_kind,
            "source_sha256": self.source_sha256,
            "producer": self.producer,
            "profile": self.profile.to_payload(),
            "prototype": None if self.prototype is None else self.prototype.to_payload(),
            "effects": None if self.effects is None else self.effects.to_payload(),
            "dependency_ids": list(self.dependency_ids),
        }

    @classmethod
    def parse(cls, value: object) -> "PhysicalAbiDeclarationV1":
        if not isinstance(value, dict) or set(value) != {
            "id",
            "symbols",
            "source_kind",
            "source_sha256",
            "producer",
            "profile",
            "prototype",
            "effects",
            "dependency_ids",
        }:
            raise AbiModelError("physical ABI declaration fields are malformed")
        result = cls.create(
            symbols=_strings(value["symbols"], "ABI declaration symbols"),
            source_kind=str(value["source_kind"]),
            source_sha256=str(value["source_sha256"]),
            producer=str(value["producer"]),
            profile=PhysicalAbiProfileV1.parse(value["profile"]),
            prototype=(
                None
                if value["prototype"] is None
                else PortablePrototypeV1.parse(value["prototype"])
            ),
            effects=(
                None
                if value["effects"] is None
                else BoundaryEffectsV1.parse(value["effects"])
            ),
            dependency_ids=_strings(
                value["dependency_ids"], "ABI declaration dependencies"
            ),
        )
        if result.declaration_id != _identifier(value["id"], "ABI declaration ID"):
            raise AbiModelError("physical ABI declaration ID does not bind its contents")
        return result


@dataclass(frozen=True)
class PhysicalAbiDeclarationSetV1:
    snapshot_id: str
    declarations: tuple[PhysicalAbiDeclarationV1, ...]
    declaration_set_sha256: str

    @classmethod
    def create(
        cls,
        *,
        snapshot_id: str,
        declarations: Iterable[PhysicalAbiDeclarationV1],
    ) -> "PhysicalAbiDeclarationSetV1":
        rows = tuple(sorted(declarations, key=lambda row: row.declaration_id))
        if len({row.declaration_id for row in rows}) != len(rows):
            raise AbiModelError("physical ABI declarations contain duplicate IDs")
        core = {
            "format": PHYSICAL_ABI_DECLARATIONS_FORMAT,
            "snapshot_id": _identifier(snapshot_id, "ABI declaration snapshot"),
            "declarations": [row.to_payload() for row in rows],
        }
        return cls(str(core["snapshot_id"]), rows, canonical_sha256(core))

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PHYSICAL_ABI_DECLARATIONS_FORMAT,
            "snapshot_id": self.snapshot_id,
            "declarations": [row.to_payload() for row in self.declarations],
            "declaration_set_sha256": self.declaration_set_sha256,
        }

    def write(self, path: Path | str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(self.to_payload()) + b"\n")

    @classmethod
    def read(cls, path: Path | str) -> "PhysicalAbiDeclarationSetV1":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "format",
            "snapshot_id",
            "declarations",
            "declaration_set_sha256",
        }:
            raise AbiModelError("physical ABI declaration-set fields are malformed")
        if payload["format"] != PHYSICAL_ABI_DECLARATIONS_FORMAT:
            raise AbiModelError("physical ABI declaration-set format is unsupported")
        raw = payload["declarations"]
        if not isinstance(raw, list):
            raise AbiModelError("physical ABI declarations must be an array")
        result = cls.create(
            snapshot_id=str(payload["snapshot_id"]),
            declarations=(PhysicalAbiDeclarationV1.parse(row) for row in raw),
        )
        if result.declaration_set_sha256 != _sha256(
            payload["declaration_set_sha256"], "ABI declaration-set SHA-256"
        ):
            raise AbiModelError("physical ABI declaration-set hash is stale")
        return result


__all__ = ["PhysicalAbiDeclarationSetV1", "PhysicalAbiDeclarationV1"]
