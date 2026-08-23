"""Exact PE32 import-slot identities used by candidate planning.

An import request is not a storage location.  Several IAT cells may request the
same DLL export and may subsequently be patched independently, so candidate
authority always carries one record per physical cell.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..errors import ToolkitInputError


ImportIdentity = tuple[str, str | int]


@dataclass(frozen=True, order=True)
class NativeImportSlot:
    image_id: str
    descriptor_index: int
    cell_index: int
    dll: str
    symbol: str | None
    ordinal: int | None
    iat_rva: int
    iat_va: int

    def __post_init__(self) -> None:
        if not self.image_id:
            raise ToolkitInputError("import slot image ID must be nonempty")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (self.descriptor_index, self.cell_index)
        ):
            raise ToolkitInputError("import slot indices must be nonnegative")
        if not self.dll or self.dll != self.dll.lower():
            raise ToolkitInputError("import slot DLL must be nonempty and lowercase")
        if (self.symbol is None) == (self.ordinal is None):
            raise ToolkitInputError(
                "import slot must provide exactly one symbol or ordinal"
            )
        if self.symbol is not None and not self.symbol:
            raise ToolkitInputError("import slot symbol must be nonempty")
        if self.ordinal is not None and (
            isinstance(self.ordinal, bool)
            or not isinstance(self.ordinal, int)
            or not 0 <= self.ordinal <= 0xFFFFFFFF
        ):
            raise ToolkitInputError(
                "import slot ordinal must be an unsigned 32-bit integer"
            )
        if (
            isinstance(self.iat_rva, bool)
            or not isinstance(self.iat_rva, int)
            or not 0 <= self.iat_rva <= 0xFFFFFFFF
        ):
            raise ToolkitInputError("import slot RVA must be an unsigned 32-bit value")
        if (
            isinstance(self.iat_va, bool)
            or not isinstance(self.iat_va, int)
            or not 0 <= self.iat_va <= 0xFFFFFFFF
        ):
            raise ToolkitInputError("import slot VA must be an unsigned 32-bit value")

    @property
    def identity(self) -> ImportIdentity:
        value: str | int = self.symbol if self.symbol is not None else int(self.ordinal)
        return self.dll, value

    @property
    def slot_id(self) -> str:
        return f"{self.image_id}:iat:{self.iat_rva:08x}"

    def payload(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "image_id": self.image_id,
            "descriptor_index": self.descriptor_index,
            "cell_index": self.cell_index,
            "iat_rva": self.iat_rva,
            "iat_va": self.iat_va,
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
        }


@dataclass(frozen=True)
class NativeImportSlotIndex:
    slots: tuple[NativeImportSlot, ...]
    by_va: Mapping[int, NativeImportSlot]
    by_id: Mapping[str, NativeImportSlot]
    by_identity: Mapping[ImportIdentity, tuple[NativeImportSlot, ...]]

    @classmethod
    def create(cls, slots: Iterable[NativeImportSlot]) -> "NativeImportSlotIndex":
        ordered = tuple(
            sorted(
                slots,
                key=lambda row: (
                    row.image_id,
                    row.iat_rva,
                    row.descriptor_index,
                    row.cell_index,
                ),
            )
        )
        by_va: dict[int, NativeImportSlot] = {}
        by_id: dict[str, NativeImportSlot] = {}
        by_identity_lists: dict[ImportIdentity, list[NativeImportSlot]] = {}
        for slot in ordered:
            if slot.iat_va in by_va:
                raise ToolkitInputError(
                    f"duplicate physical IAT cell VA {slot.iat_va:#x}"
                )
            if slot.slot_id in by_id:
                raise ToolkitInputError(f"duplicate import slot ID {slot.slot_id!r}")
            by_va[slot.iat_va] = slot
            by_id[slot.slot_id] = slot
            by_identity_lists.setdefault(slot.identity, []).append(slot)
        return cls(
            slots=ordered,
            by_va=by_va,
            by_id=by_id,
            by_identity={
                identity: tuple(rows)
                for identity, rows in sorted(
                    by_identity_lists.items(),
                    key=lambda item: (item[0][0], str(item[0][1])),
                )
            },
        )

    def unique_for_identity(self, identity: ImportIdentity) -> NativeImportSlot | None:
        matches = self.by_identity.get((identity[0].lower(), identity[1]), ())
        return matches[0] if len(matches) == 1 else None


def normalize_native_import_slots(
    import_slots: Iterable[NativeImportSlot | Mapping[str, Any]] | None,
    *,
    legacy_import_iat_vas: Mapping[ImportIdentity, int] | None = None,
    image_id: str = "main",
    preferred_image_base: int | None = None,
) -> NativeImportSlotIndex:
    """Validate exact slots, accepting the former unique map for old callers."""

    if import_slots is not None and legacy_import_iat_vas:
        raise ToolkitInputError(
            "provide exact import slots or the legacy import map, not both"
        )
    rows: list[NativeImportSlot] = []
    if import_slots is not None:
        for index, value in enumerate(import_slots):
            if isinstance(value, NativeImportSlot):
                rows.append(value)
                continue
            if not isinstance(value, Mapping):
                raise ToolkitInputError(f"import slot {index} must be an object")
            symbol = value.get("symbol")
            ordinal = value.get("ordinal")
            rows.append(
                NativeImportSlot(
                    image_id=str(value.get("image_id") or image_id),
                    descriptor_index=_uint(value.get("descriptor_index"), "descriptor index"),
                    cell_index=_uint(value.get("cell_index"), "cell index"),
                    dll=str(value.get("dll") or "").lower(),
                    symbol=symbol if isinstance(symbol, str) else None,
                    ordinal=_optional_uint(ordinal, "import ordinal"),
                    iat_rva=_uint(value.get("iat_rva"), "IAT RVA"),
                    iat_va=_uint(value.get("iat_va"), "IAT VA"),
                )
            )
    elif legacy_import_iat_vas:
        base = preferred_image_base or 0
        for index, ((dll, identity), raw_va) in enumerate(
            sorted(
                legacy_import_iat_vas.items(),
                key=lambda item: (item[0][0].lower(), str(item[0][1]), item[1]),
            )
        ):
            iat_va = _uint(raw_va, "legacy import IAT VA")
            if iat_va < base:
                raise ToolkitInputError("import IAT VA precedes the preferred image base")
            rows.append(
                NativeImportSlot(
                    image_id=image_id,
                    descriptor_index=index,
                    cell_index=0,
                    dll=dll.lower(),
                    symbol=identity if isinstance(identity, str) else None,
                    ordinal=identity if isinstance(identity, int) else None,
                    iat_rva=iat_va - base,
                    iat_va=iat_va,
                )
            )
    return NativeImportSlotIndex.create(rows)


def _uint(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ToolkitInputError(f"{label} must be an unsigned 32-bit integer")
    return value


def _optional_uint(value: Any, label: str) -> int | None:
    return None if value is None else _uint(value, label)


__all__ = [
    "ImportIdentity",
    "NativeImportSlot",
    "NativeImportSlotIndex",
    "normalize_native_import_slots",
]
