"""Checked object-relative references shared by semantic and provider layers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum


class CapabilityStatus(IntEnum):
    OK = 0
    FAULT = 1
    EXPIRED = 2
    UNSUPPORTED = 3
    TYPE_MISMATCH = 4


class ReferencePermission(IntEnum):
    READ = 1
    WRITE = 2


@dataclass(frozen=True)
class CheckedReference:
    """Portable object-relative reference; never a machine or host pointer."""

    domain: int
    object_id: int
    generation: int
    offset: int
    extent: int
    permissions: int

    @property
    def is_null(self) -> bool:
        return (
            self.domain == 0
            and self.object_id == 0
            and self.generation == 0
            and self.offset == 0
            and self.extent == 0
            and self.permissions == 0
        )

    def validate(
        self,
        *,
        domain: int,
        object_id: int,
        generation: int,
        extent: int,
        required_permissions: int,
        allow_one_past: bool = False,
        nullable: bool = False,
    ) -> CapabilityStatus:
        if self.is_null:
            return CapabilityStatus.OK if nullable else CapabilityStatus.FAULT
        if self.domain != domain or self.object_id != object_id:
            return CapabilityStatus.TYPE_MISMATCH
        if self.generation != generation:
            return CapabilityStatus.EXPIRED
        if self.extent != extent or self.offset > extent:
            return CapabilityStatus.FAULT
        if self.offset == extent and not allow_one_past:
            return CapabilityStatus.FAULT
        if self.permissions & required_permissions != required_permissions:
            return CapabilityStatus.TYPE_MISMATCH
        return CapabilityStatus.OK

    def derive(
        self, delta: int, *, allow_one_past: bool = False
    ) -> "CheckedReference":
        if self.is_null or delta < 0:
            raise ValueError(
                "cannot derive from a null reference or by a negative delta"
            )
        offset = self.offset + delta
        if offset > self.extent or (offset == self.extent and not allow_one_past):
            raise ValueError("derived reference is outside its origin")
        return replace(self, offset=offset)

    def difference(self, other: "CheckedReference") -> int:
        if (
            self.is_null
            or other.is_null
            or self.domain != other.domain
            or self.object_id != other.object_id
            or self.generation != other.generation
            or self.extent != other.extent
        ):
            raise ValueError("reference difference requires one live origin")
        return self.offset - other.offset


__all__ = [
    "CapabilityStatus",
    "CheckedReference",
    "ReferencePermission",
]
