"""Exact root-independent PE32 value origins used by provenance analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..artifacts.phases import RecordCodecV3
from ._schema import fail, optional_text, require_stable_id, stable_id, strict_object, text, uint


STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3 = "pe32-static-value-origins-v3"
PE32_STATIC_IMAGE_RECORD_V3_SCHEMA = "spaghetti-extractor-pe32-static-image-record-v3"
PE32_IMPORT_SLOT_RECORD_V3_SCHEMA = "spaghetti-extractor-pe32-import-slot-record-v3"


@dataclass(frozen=True, order=True)
class PE32StaticImageV3:
    record_id: str
    image_base: int
    size_of_image: int

    def __post_init__(self) -> None:
        uint(self.image_base, "PE32 static image base")
        uint(self.size_of_image, "PE32 static image size")
        if self.size_of_image <= 0 or self.image_base + self.size_of_image > 1 << 32:
            fail(
                "record_schema_mismatch",
                "PE32 static image range is invalid",
                "bind one nonempty in-range PE32 image",
            )
        require_stable_id(
            self.record_id,
            "pe32-static-image-v3",
            self.binding_payload,
            "PE32 static image",
        )

    @property
    def binding_payload(self) -> dict[str, int]:
        return {
            "image_base": self.image_base,
            "size_of_image": self.size_of_image,
        }

    @classmethod
    def create(cls, *, image_base: int, size_of_image: int) -> "PE32StaticImageV3":
        payload = {"image_base": image_base, "size_of_image": size_of_image}
        return cls(stable_id("pe32-static-image-v3", payload), **payload)


@dataclass(frozen=True, order=True)
class PE32ImportSlotV3:
    record_id: str
    image_base: int
    slot_rva: int
    slot_va: int
    dll: str
    symbol: str | None
    ordinal: int | None

    def __post_init__(self) -> None:
        uint(self.image_base, "PE32 import image base")
        uint(self.slot_rva, "PE32 import slot RVA")
        uint(self.slot_va, "PE32 import slot VA")
        if self.image_base + self.slot_rva != self.slot_va:
            fail(
                "record_schema_mismatch",
                "PE32 import slot RVA and VA disagree",
                "derive the slot VA from the exact image base and thunk RVA",
            )
        text(self.dll, "PE32 import DLL")
        if self.dll != self.dll.lower():
            fail(
                "record_schema_mismatch",
                "PE32 import DLL is not normalized",
                "lowercase the exact DLL name",
            )
        optional_text(self.symbol, "PE32 import symbol")
        if self.ordinal is not None:
            uint(self.ordinal, "PE32 import ordinal")
        if (self.symbol is None) == (self.ordinal is None):
            fail(
                "record_schema_mismatch",
                "PE32 import slot must name exactly one symbol or ordinal",
                "bind one exact import identity",
            )
        require_stable_id(
            self.record_id,
            "pe32-import-slot-v3",
            self.binding_payload,
            "PE32 import slot",
        )

    @property
    def binding_payload(self) -> dict[str, Any]:
        return {
            "image_base": self.image_base,
            "slot_rva": self.slot_rva,
            "slot_va": self.slot_va,
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
        }

    @classmethod
    def create(
        cls,
        *,
        image_base: int,
        slot_rva: int,
        dll: str,
        symbol: str | None,
        ordinal: int | None,
    ) -> "PE32ImportSlotV3":
        payload = {
            "image_base": image_base,
            "slot_rva": slot_rva,
            "slot_va": image_base + slot_rva,
            "dll": dll.lower(),
            "symbol": symbol,
            "ordinal": ordinal,
        }
        return cls(stable_id("pe32-import-slot-v3", payload), **payload)


def _encode_import_slot(value: PE32ImportSlotV3) -> dict[str, Any]:
    return {
        "schema": PE32_IMPORT_SLOT_RECORD_V3_SCHEMA,
        "id": value.record_id,
        **value.binding_payload,
    }


def _decode_import_slot(value: Any) -> PE32ImportSlotV3:
    row = strict_object(
        value,
        {
            "schema",
            "id",
            "image_base",
            "slot_rva",
            "slot_va",
            "dll",
            "symbol",
            "ordinal",
        },
        "PE32 import slot",
    )
    if row["schema"] != PE32_IMPORT_SLOT_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a PE32 import slot",
            "use PE32_IMPORT_SLOT_CODEC_V3",
        )
    return PE32ImportSlotV3(
        record_id=text(row["id"], "PE32 import slot ID"),
        image_base=uint(row["image_base"], "PE32 import image base"),
        slot_rva=uint(row["slot_rva"], "PE32 import slot RVA"),
        slot_va=uint(row["slot_va"], "PE32 import slot VA"),
        dll=text(row["dll"], "PE32 import DLL"),
        symbol=(
            None
            if row["symbol"] is None
            else text(row["symbol"], "PE32 import symbol")
        ),
        ordinal=(
            None
            if row["ordinal"] is None
            else uint(row["ordinal"], "PE32 import ordinal")
        ),
    )


PE32_IMPORT_SLOT_CODEC_V3 = RecordCodecV3[PE32ImportSlotV3](
    decode=_decode_import_slot,
    encode=_encode_import_slot,
)


def _encode_static_image(value: PE32StaticImageV3) -> dict[str, Any]:
    return {
        "schema": PE32_STATIC_IMAGE_RECORD_V3_SCHEMA,
        "id": value.record_id,
        **value.binding_payload,
    }


def _decode_static_image(value: Any) -> PE32StaticImageV3:
    row = strict_object(
        value,
        {"schema", "id", "image_base", "size_of_image"},
        "PE32 static image",
    )
    if row["schema"] != PE32_STATIC_IMAGE_RECORD_V3_SCHEMA:
        fail(
            "wrong_record_schema",
            "record is not a PE32 static image",
            "use PE32_STATIC_IMAGE_CODEC_V3",
        )
    return PE32StaticImageV3(
        record_id=text(row["id"], "PE32 static image ID"),
        image_base=uint(row["image_base"], "PE32 static image base"),
        size_of_image=uint(row["size_of_image"], "PE32 static image size"),
    )


PE32_STATIC_IMAGE_CODEC_V3 = RecordCodecV3[PE32StaticImageV3](
    decode=_decode_static_image,
    encode=_encode_static_image,
)


__all__ = [
    "PE32_IMPORT_SLOT_CODEC_V3",
    "PE32_IMPORT_SLOT_RECORD_V3_SCHEMA",
    "PE32ImportSlotV3",
    "PE32_STATIC_IMAGE_CODEC_V3",
    "PE32_STATIC_IMAGE_RECORD_V3_SCHEMA",
    "PE32StaticImageV3",
    "STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3",
]
