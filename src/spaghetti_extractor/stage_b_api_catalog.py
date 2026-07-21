from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .util import sha256_file


STAGE_B_MACHINE_CALL_CATALOG_FORMAT = "stage-b-machine-call-catalog-v1"
_CALLING_CONVENTIONS = {"cdecl", "stdcall"}


@dataclass(frozen=True)
class MachineCallSignature:
    catalog_id: str
    dll: str
    symbol: str | None
    ordinal: int | None
    calling_convention: str | None
    stack_argument_offsets: tuple[int, ...]
    stack_result_delta: int
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    disposition: str
    memory_effect: str
    memory_footprints: tuple[dict[str, Any], ...]
    world_effect: str
    world_effect_argument: int | None

    @property
    def identity(self) -> tuple[str, str, str | int]:
        if self.symbol is not None:
            return (self.dll, "symbol", self.symbol)
        assert self.ordinal is not None
        return (self.dll, "ordinal", self.ordinal)

    def as_json(self) -> dict[str, Any]:
        imported: dict[str, Any] = {"dll": self.dll}
        if self.symbol is not None:
            imported["symbol"] = self.symbol
        else:
            imported["ordinal"] = self.ordinal
        return {
            "catalog_id": self.catalog_id,
            "import": imported,
            "calling_convention": self.calling_convention,
            "stack_argument_offsets": list(self.stack_argument_offsets),
            "stack_result_delta": self.stack_result_delta,
            "preserved_registers": list(self.preserved_registers),
            "clobbered_registers": list(self.clobbered_registers),
            "disposition": self.disposition,
            "memory_effect": self.memory_effect,
            "memory_footprints": list(self.memory_footprints),
            "world_effect": self.world_effect,
            "world_effect_argument": self.world_effect_argument,
        }


@dataclass(frozen=True)
class MachineCallCatalog:
    binding: dict[str, str]
    entries: tuple[MachineCallSignature, ...]

    def by_identity(self) -> dict[tuple[str, str, str | int], MachineCallSignature]:
        return {entry.identity: entry for entry in self.entries}


def load_machine_call_catalog(path: Path) -> MachineCallCatalog:
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("machine-call catalog must be a JSON object")
    if payload.get("format") == STAGE_B_MACHINE_CALL_CATALOG_FORMAT:
        raw_entries = payload.get("entries")
    else:
        raw_entries = payload.get("machine_import_call_contracts")
    if not isinstance(raw_entries, list):
        raise ValueError(
            "machine-call catalog must contain entries or normalized machine_import_call_contracts"
        )

    entries: list[MachineCallSignature] = []
    identities: set[tuple[str, str, str | int]] = set()
    for index, raw in enumerate(raw_entries):
        entry = _parse_signature(raw, index)
        if entry.identity in identities:
            raise ValueError(f"machine-call catalog contains duplicate import identity {entry.identity!r}")
        identities.add(entry.identity)
        entries.append(entry)
    return MachineCallCatalog(
        binding={"path": path.name, "sha256": sha256_file(path)},
        entries=tuple(entries),
    )


def _parse_signature(raw: Any, index: int) -> MachineCallSignature:
    if not isinstance(raw, dict):
        raise ValueError(f"machine-call catalog entry {index} must be an object")
    imported = raw.get("import")
    if not isinstance(imported, dict):
        raise ValueError(f"machine-call catalog entry {index} is missing import identity")
    dll = imported.get("dll")
    symbol = imported.get("symbol")
    ordinal = imported.get("ordinal")
    if not isinstance(dll, str) or not dll:
        raise ValueError(f"machine-call catalog entry {index} has invalid DLL identity")
    if (isinstance(symbol, str) and bool(symbol)) == (
        isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal >= 0
    ):
        raise ValueError(f"machine-call catalog entry {index} must name exactly one symbol or ordinal")

    offsets = raw.get("stack_argument_offsets")
    delta = raw.get("stack_result_delta")
    if (
        not isinstance(offsets, list)
        or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 or value % 4 for value in offsets)
        or len(set(offsets)) != len(offsets)
    ):
        raise ValueError(f"machine-call catalog entry {index} has invalid stack argument offsets")
    if not isinstance(delta, int) or isinstance(delta, bool) or delta < 0 or delta % 4:
        raise ValueError(f"machine-call catalog entry {index} has invalid stack result delta")

    convention = raw.get("calling_convention")
    if convention is None:
        template = raw.get("abi_template")
        if template == "pe32-cdecl-v1":
            convention = "cdecl"
        elif template == "pe32-stdcall-v1":
            convention = "stdcall"
        elif offsets and delta == 0:
            convention = "cdecl"
        elif offsets and delta == len(offsets) * 4:
            convention = "stdcall"
    if convention is not None and convention not in _CALLING_CONVENTIONS:
        raise ValueError(f"machine-call catalog entry {index} has unsupported calling convention")

    preserved = _string_tuple(raw.get("preserved_registers"), index, "preserved_registers")
    clobbered = _string_tuple(raw.get("clobbered_registers"), index, "clobbered_registers")
    footprints = raw.get("memory_footprints", [])
    if not isinstance(footprints, list) or any(not isinstance(item, dict) for item in footprints):
        raise ValueError(f"machine-call catalog entry {index} has invalid memory footprints")
    world_effect_argument = raw.get("world_effect_argument")
    if world_effect_argument is not None and (
        not isinstance(world_effect_argument, int)
        or isinstance(world_effect_argument, bool)
        or world_effect_argument < 0
    ):
        raise ValueError(f"machine-call catalog entry {index} has invalid world-effect argument")
    return MachineCallSignature(
        catalog_id=str(raw.get("id", index)),
        dll=dll.lower(),
        symbol=symbol if isinstance(symbol, str) else None,
        ordinal=ordinal if isinstance(ordinal, int) and not isinstance(ordinal, bool) else None,
        calling_convention=convention,
        stack_argument_offsets=tuple(offsets),
        stack_result_delta=delta,
        preserved_registers=preserved,
        clobbered_registers=clobbered,
        disposition=str(raw.get("disposition") or "returns"),
        memory_effect=str(raw.get("memory_effect") or "unknown"),
        memory_footprints=tuple(dict(item) for item in footprints),
        world_effect=str(raw.get("world_effect") or "unknown"),
        world_effect_argument=world_effect_argument,
    )


def _string_tuple(value: Any, index: int, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"machine-call catalog entry {index} has invalid {field}")
    return tuple(value)
