"""Stable checked entry-state contract for PE and callback roots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Mapping

from .authority_bindings_v2 import AuthorityDataError, EventBinding, UnitBinding, _token
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


ENTRY_STATE_CONTRACT_FORMAT = "spaghetti-extractor-entry-state-contract-v2"


@dataclass(frozen=True)
class EntryStateContract(AuthorityRecordMixin):
    entry: UnitBinding
    entry_kind: str
    alternatives: FiniteAlternatives | None
    entry_event: EventBinding | None = None
    dependencies: tuple[AuthorityDependency, ...] = ()
    issues: tuple[EvidenceIssue, ...] = ()

    KIND: ClassVar[str] = "entry_state_contract"
    FORMAT: ClassVar[str] = ENTRY_STATE_CONTRACT_FORMAT

    def __post_init__(self) -> None:
        if not isinstance(self.entry, UnitBinding):
            raise AuthorityDataError("entry state requires an exact unit binding")
        _token(self.entry_kind, "entry kind")
        if self.alternatives is not None and not isinstance(
            self.alternatives, FiniteAlternatives
        ):
            raise AuthorityDataError("entry-state alternatives are malformed")
        if self.entry_event is not None:
            if not isinstance(self.entry_event, EventBinding):
                raise AuthorityDataError("entry-state event binding is malformed")
            if self.entry_event.unit.binary != self.entry.binary:
                raise AuthorityDataError(
                    "entry-state event and target bind different binaries"
                )
        _check_dependencies(self.dependencies)
        _check_issues(self.issues)

    @property
    def status(self) -> AuthorityStatus:
        corrupt = self.alternatives is not None and any(
            not isinstance(value.to_value(), dict)
            for value in self.alternatives.values
        )
        return _derive_status(
            missing=(
                self.alternatives is None
                or (
                    self.entry_kind in {"registered_callback", "event_callback"}
                    and self.entry_event is None
                )
                or _has_undeclared_references(
                    self.alternatives, self.dependencies
                )
            ),
            violated=corrupt,
            issues=self.issues,
        )

    def _core_payload(self) -> dict[str, Any]:
        return _record_core(
            format_name=self.FORMAT,
            status=self.status,
            binding=self.entry.to_payload(),
            dependencies=self.dependencies,
            alternatives=self.alternatives,
            issues=self.issues,
            fields={
                "entry_kind": self.entry_kind,
                "entry_event": (
                    None
                    if self.entry_event is None
                    else self.entry_event.to_payload()
                ),
            },
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "EntryStateContract":
        parts = _parse_record_parts(
            value,
            format_name=cls.FORMAT,
            fields={"entry_kind", "entry_event"},
        )
        result = cls(
            entry=UnitBinding.parse(parts.binding),
            entry_kind=_token(value["entry_kind"], "entry kind"),
            alternatives=parts.alternatives,
            entry_event=(
                None
                if value["entry_event"] is None
                else EventBinding.parse(value["entry_event"])
            ),
            dependencies=parts.dependencies,
            issues=parts.issues,
        )
        _finish_record_parse(result, value)
        return result


__all__ = ["ENTRY_STATE_CONTRACT_FORMAT", "EntryStateContract"]
