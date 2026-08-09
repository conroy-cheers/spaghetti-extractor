"""Non-authorizing preserved-register hypotheses for call-frame replay."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping


PRESERVED_REGISTER_HYPOTHESIS_FORMAT = (
    "stage-a-preserved-register-hypothesis-v1"
)

_TRANSFER_KINDS = frozenset({"external_call", "indirect_call", "internal_call"})
_REGISTERS = frozenset({
    "eax",
    "ebp",
    "ebx",
    "ecx",
    "edi",
    "edx",
    "esi",
    "esp",
})
_FIELDS = frozenset({
    "format",
    "id",
    "unit_id",
    "event_index",
    "transfer_kind",
    "register",
    "proposal_source",
    "proof_authority",
})


class CallFrameHypothesisError(ValueError):
    """A preserved-register hypothesis is malformed or ambiguous."""


def hypothesis_id(unit_id: str, event_index: int, register: str) -> str:
    """Return the canonical identifier for one call-site/register atom."""

    unit = _nonempty_text(unit_id, "hypothesis unit ID")
    event = _event_index(event_index)
    checked_register = _register(register)
    identity = json.dumps(
        [unit, event, checked_register],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return f"call-frame-hypothesis:{identity}"


@dataclass(frozen=True)
class PreservedRegisterHypothesis:
    id: str
    unit_id: str
    event_index: int
    transfer_kind: str
    register: str
    proposal_source: str
    proof_authority: bool

    def __post_init__(self) -> None:
        unit_id = _nonempty_text(self.unit_id, "hypothesis unit ID")
        event_index = _event_index(self.event_index)
        _transfer_kind(self.transfer_kind)
        register = _register(self.register)
        _nonempty_text(self.proposal_source, "hypothesis proposal source")
        if self.proof_authority is not False:
            raise CallFrameHypothesisError(
                "preserved-register hypothesis cannot carry proof authority"
            )
        expected_id = hypothesis_id(unit_id, event_index, register)
        if self.id != expected_id:
            raise CallFrameHypothesisError(
                "preserved-register hypothesis ID is not canonical"
            )

    def as_json(self) -> dict[str, Any]:
        return {
            "format": PRESERVED_REGISTER_HYPOTHESIS_FORMAT,
            "id": self.id,
            "unit_id": self.unit_id,
            "event_index": self.event_index,
            "transfer_kind": self.transfer_kind,
            "register": self.register,
            "proposal_source": self.proposal_source,
            "proof_authority": self.proof_authority,
        }

    @classmethod
    def parse(cls, value: Any) -> "PreservedRegisterHypothesis":
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise CallFrameHypothesisError(
                "preserved-register hypothesis has unexpected or missing fields"
            )
        if value.get("format") != PRESERVED_REGISTER_HYPOTHESIS_FORMAT:
            raise CallFrameHypothesisError(
                "preserved-register hypothesis has an unsupported format"
            )
        return cls(
            id=_nonempty_text(value.get("id"), "hypothesis ID"),
            unit_id=_nonempty_text(value.get("unit_id"), "hypothesis unit ID"),
            event_index=_event_index(value.get("event_index")),
            transfer_kind=_transfer_kind(value.get("transfer_kind")),
            register=_register(value.get("register")),
            proposal_source=_nonempty_text(
                value.get("proposal_source"), "hypothesis proposal source"
            ),
            proof_authority=_proof_authority(value.get("proof_authority")),
        )


def parse_preserved_register_hypotheses(
    value: Any,
) -> tuple[PreservedRegisterHypothesis, ...]:
    """Parse an exact JSON inventory and reject duplicate atoms."""

    if not isinstance(value, list):
        raise CallFrameHypothesisError(
            "preserved-register hypothesis inventory must be a list"
        )
    result: list[PreservedRegisterHypothesis] = []
    seen_ids: set[str] = set()
    seen_sites: set[tuple[str, int, str]] = set()
    for index, row in enumerate(value):
        try:
            hypothesis = PreservedRegisterHypothesis.parse(row)
        except CallFrameHypothesisError as exc:
            raise CallFrameHypothesisError(
                f"preserved-register hypothesis {index} is invalid: {exc}"
            ) from exc
        site = (hypothesis.unit_id, hypothesis.event_index, hypothesis.register)
        if hypothesis.id in seen_ids or site in seen_sites:
            raise CallFrameHypothesisError(
                "preserved-register hypothesis inventory duplicates an ID or site/register"
            )
        seen_ids.add(hypothesis.id)
        seen_sites.add(site)
        result.append(hypothesis)
    return tuple(result)


def _nonempty_text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CallFrameHypothesisError(f"{context} must be a nonempty string")
    return value


def _event_index(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CallFrameHypothesisError(
            "hypothesis event index must be a nonnegative integer"
        )
    return value


def _transfer_kind(value: Any) -> str:
    if not isinstance(value, str) or value not in _TRANSFER_KINDS:
        raise CallFrameHypothesisError(
            "hypothesis transfer kind must be external_call, indirect_call, or internal_call"
        )
    return value


def _register(value: Any) -> str:
    if not isinstance(value, str) or value not in _REGISTERS:
        raise CallFrameHypothesisError("hypothesis register is invalid")
    if value == "esp":
        raise CallFrameHypothesisError(
            "ESP preservation requires a separate stack-continuation hypothesis"
        )
    return value


def _proof_authority(value: Any) -> bool:
    if value is not False:
        raise CallFrameHypothesisError(
            "preserved-register hypothesis proof_authority must be false"
        )
    return False


__all__ = [
    "CallFrameHypothesisError",
    "PRESERVED_REGISTER_HYPOTHESIS_FORMAT",
    "PreservedRegisterHypothesis",
    "hypothesis_id",
    "parse_preserved_register_hypotheses",
]
