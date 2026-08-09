"""Stable checked contract for one point-sensitive mutable image slot."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Mapping, TypeAlias

from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    EventBinding,
    ImageSpanBinding,
    ScopeBinding,
    _parse_scope,
    _scope_payload,
    _token,
    _uint,
)
from .authority_record_core_v2 import (
    AuthorityDependency,
    AuthorityRecordMixin,
    AuthorityStatus,
    EvidenceIssue,
    FiniteAlternatives,
    _check_dependencies,
    _check_issues,
    _derive_status,
    _finish_record_parse,
    _has_undeclared_references,
    _parse_record_parts,
    _record_core,
)


GLOBAL_SLOT_INVARIANT_FORMAT = "spaghetti-extractor-global-slot-invariant-v2"
GlobalSlotBinding: TypeAlias = ScopeBinding | ImageSpanBinding


def global_slot_binding_payload(binding: GlobalSlotBinding) -> dict[str, Any]:
    if isinstance(binding, ImageSpanBinding):
        return binding.to_payload()
    return _scope_payload(binding)


def parse_global_slot_binding(value: Any) -> GlobalSlotBinding:
    if isinstance(value, Mapping) and value.get("kind") == "image_span":
        return ImageSpanBinding.parse(value)
    return _parse_scope(value)


def global_slot_binding_binary(binding: GlobalSlotBinding) -> BinaryBinding:
    if isinstance(binding, ImageSpanBinding):
        return binding.binary
    return binding.unit.binary if isinstance(binding, EventBinding) else binding.binary


@dataclass(frozen=True)
class GlobalSlotInvariant(AuthorityRecordMixin):
    binding: GlobalSlotBinding
    slot_rva: int
    width_bytes: int
    invariant_kind: str
    alternatives: FiniteAlternatives | None
    dependencies: tuple[AuthorityDependency, ...] = ()
    issues: tuple[EvidenceIssue, ...] = ()

    KIND: ClassVar[str] = "global_slot_invariant"
    FORMAT: ClassVar[str] = GLOBAL_SLOT_INVARIANT_FORMAT

    def __post_init__(self) -> None:
        global_slot_binding_payload(self.binding)
        _uint(self.slot_rva, "global slot RVA")
        width = _uint(self.width_bytes, "global slot width", maximum=0x10000)
        if width == 0 or self.slot_rva + width > 2**32:
            raise AuthorityDataError("global slot has an invalid exact span")
        if isinstance(self.binding, ImageSpanBinding) and (
            self.binding.rva_start != self.slot_rva
            or self.binding.rva_end != self.slot_rva + width
        ):
            raise AuthorityDataError(
                "launch-initialized global slot must bind its exact image span"
            )
        _token(self.invariant_kind, "global invariant kind")
        if self.alternatives is not None and not isinstance(
            self.alternatives, FiniteAlternatives
        ):
            raise AuthorityDataError("global-slot alternatives are malformed")
        _check_dependencies(self.dependencies)
        _check_issues(self.issues)

    @property
    def status(self) -> AuthorityStatus:
        return _derive_status(
            missing=(
                self.alternatives is None
                or _has_undeclared_references(self.alternatives, self.dependencies)
            ),
            violated=False,
            issues=self.issues,
        )

    @property
    def complete(self) -> bool:
        return self.status is AuthorityStatus.COMPLETE

    def _core_payload(self) -> dict[str, Any]:
        return _record_core(
            format_name=self.FORMAT,
            status=self.status,
            binding=global_slot_binding_payload(self.binding),
            dependencies=self.dependencies,
            alternatives=self.alternatives,
            issues=self.issues,
            fields={
                "slot_rva": self.slot_rva,
                "width_bytes": self.width_bytes,
                "invariant_kind": self.invariant_kind,
            },
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "GlobalSlotInvariant":
        parts = _parse_record_parts(
            value,
            format_name=cls.FORMAT,
            fields={"slot_rva", "width_bytes", "invariant_kind"},
        )
        result = cls(
            binding=parse_global_slot_binding(parts.binding),
            slot_rva=_uint(value["slot_rva"], "global slot RVA"),
            width_bytes=_uint(
                value["width_bytes"], "global slot width", maximum=0x10000
            ),
            invariant_kind=_token(value["invariant_kind"], "global invariant kind"),
            alternatives=parts.alternatives,
            dependencies=parts.dependencies,
            issues=parts.issues,
        )
        _finish_record_parse(result, value)
        return result


__all__ = [
    "GLOBAL_SLOT_INVARIANT_FORMAT",
    "GlobalSlotBinding",
    "GlobalSlotInvariant",
    "global_slot_binding_payload",
    "global_slot_binding_binary",
    "parse_global_slot_binding",
]
