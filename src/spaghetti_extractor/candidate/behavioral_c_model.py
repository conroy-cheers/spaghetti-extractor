"""Checked, renderer-neutral control layout for faithful behavioral C."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..artifacts.formats import BEHAVIORAL_C_LAYOUT_INTENT_FORMAT
from .interpreter_model import CandidateInterpreterError


@dataclass(frozen=True)
class BehavioralCLayoutIntent:
    roots: tuple[int, ...] = ()
    names: tuple[tuple[int, str], ...] = ()
    forced_labels: tuple[int, ...] = ()

    @classmethod
    def from_payload(cls, raw: Mapping[str, Any]) -> "BehavioralCLayoutIntent":
        if raw.get("format") != BEHAVIORAL_C_LAYOUT_INTENT_FORMAT:
            raise CandidateInterpreterError(
                "behavioral-C layout intent has an unsupported format",
                code="malformed_behavioral_c_layout_intent",
                next_action="regenerate the sparse layout intent with the current toolkit",
            )
        allowed = {"format", "roots", "names", "forced_labels"}
        extras = sorted(set(raw) - allowed)
        if extras:
            raise CandidateInterpreterError(
                f"behavioral-C layout intent has unknown fields: {', '.join(extras)}",
                code="malformed_behavioral_c_layout_intent",
            )
        roots = _rvas(raw.get("roots", []), "roots")
        forced = _rvas(raw.get("forced_labels", []), "forced_labels")
        names_raw = raw.get("names", {})
        if not isinstance(names_raw, Mapping):
            raise CandidateInterpreterError(
                "behavioral-C layout names must be an RVA-to-name object",
                code="malformed_behavioral_c_layout_intent",
            )
        names: list[tuple[int, str]] = []
        for key, value in names_raw.items():
            try:
                rva = int(str(key), 0)
            except ValueError as exc:
                raise CandidateInterpreterError(
                    f"behavioral-C layout name key {key!r} is not an RVA",
                    code="malformed_behavioral_c_layout_intent",
                ) from exc
            if not isinstance(value, str) or not value.strip():
                raise CandidateInterpreterError(
                    f"behavioral-C layout name for 0x{rva:x} is empty",
                    code="malformed_behavioral_c_layout_intent",
                )
            _check_rva(rva, "layout name RVA")
            names.append((rva, value.strip()))
        if len(dict(names)) != len(names):
            raise CandidateInterpreterError(
                "behavioral-C layout names contain duplicate RVAs",
                code="malformed_behavioral_c_layout_intent",
            )
        return cls(
            roots=tuple(sorted(set(roots))),
            names=tuple(sorted(names)),
            forced_labels=tuple(sorted(set(forced))),
        )

    def name_for(self, rva: int) -> str | None:
        return dict(self.names).get(rva)


@dataclass(frozen=True)
class BehavioralCFunction:
    identity: str
    symbol: str
    entries: tuple[int, ...]
    unit_rvas: tuple[int, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.identity,
            "symbol": self.symbol,
            "entries": list(self.entries),
            "unit_rvas": list(self.unit_rvas),
            "control_form": "direct_labels_and_structured_branches_v1",
        }


@dataclass(frozen=True)
class BehavioralCPlan:
    functions: tuple[BehavioralCFunction, ...]
    roots: tuple[int, ...]
    forced_labels: tuple[int, ...]

    @property
    def unit_rvas(self) -> tuple[int, ...]:
        return tuple(rva for function in self.functions for rva in function.unit_rvas)


def _rvas(raw: Any, field: str) -> list[int]:
    if not isinstance(raw, list):
        raise CandidateInterpreterError(
            f"behavioral-C layout {field} must be a list",
            code="malformed_behavioral_c_layout_intent",
        )
    values: list[int] = []
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, int):
            raise CandidateInterpreterError(
                f"behavioral-C layout {field} contains a non-integer RVA",
                code="malformed_behavioral_c_layout_intent",
            )
        _check_rva(value, f"layout {field} RVA")
        values.append(value)
    return values


def _check_rva(value: int, field: str) -> None:
    if not 0 <= value <= 0xFFFFFFFF:
        raise CandidateInterpreterError(
            f"{field} is outside the PE32 RVA domain",
            code="malformed_behavioral_c_layout_intent",
        )


__all__ = [
    "BehavioralCFunction",
    "BehavioralCLayoutIntent",
    "BehavioralCPlan",
]
