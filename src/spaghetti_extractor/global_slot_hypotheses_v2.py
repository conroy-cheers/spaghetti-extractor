"""Non-authorizing launch hypotheses for cyclic mutable-slot proofs.

Some indirect targets and call summaries form one SCC with the mutable image
slots that contain those targets.  This module may propose the exact loader
value of such a slot as an induction hypothesis.  The proposal is not
authority: the joint fixed-point driver must discard it after the first round
unless point-sensitive global-slot replay reproduces the identical checked
``GlobalSlotInvariant``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Mapping, Sequence

from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import AuthorityDataError
from .authority_record_core_v2 import FiniteAlternatives
from .global_slot_contract_v2 import GlobalSlotInvariant
from .global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    build_image_span_binding_v2,
    loader_initial_bytes_v2,
)
from .mutable_slot_candidates_v2 import writable_image_span
from .stage_binary import StageABinary


GLOBAL_SLOT_INDUCTION_HYPOTHESIS_V2_FORMAT = (
    "spaghetti-extractor-global-slot-induction-hypothesis-v2"
)


class GlobalSlotHypothesisV2Error(ValueError):
    """A proposal cannot be represented as a bounded exact launch hypothesis."""


@dataclass(frozen=True)
class GlobalSlotInductionHypothesisV2:
    """One immutable proposal wrapper around a checked-record-shaped invariant."""

    invariant: GlobalSlotInvariant
    exit_ids: tuple[str, ...]
    dependency_sha256: str

    FORMAT: ClassVar[str] = GLOBAL_SLOT_INDUCTION_HYPOTHESIS_V2_FORMAT

    def __post_init__(self) -> None:
        if self.invariant.status.value != "complete":
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis must contain a complete typed invariant"
            )
        if (
            not isinstance(self.exit_ids, tuple)
            or not self.exit_ids
            or any(not isinstance(value, str) or not value for value in self.exit_ids)
            or self.exit_ids != tuple(sorted(set(self.exit_ids)))
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis exit inventory is not canonical"
            )
        if (
            not isinstance(self.dependency_sha256, str)
            or len(self.dependency_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.dependency_sha256)
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis dependency hash is invalid"
            )

    @property
    def id(self) -> str:
        return "global-slot-induction-hypothesis-v2:" + canonical_sha256(
            self._identity_payload()
        )

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "invariant_content_id": self.invariant.content_id,
            "slot_rva": self.invariant.slot_rva,
            "exit_ids": list(self.exit_ids),
            "dependency_sha256": self.dependency_sha256,
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.FORMAT,
            "id": self.id,
            "status": "prepared",
            "proof_authority": False,
            **self._identity_payload(),
            "invariant": self.invariant.to_payload(),
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "GlobalSlotInductionHypothesisV2":
        expected = {
            "format",
            "id",
            "status",
            "proof_authority",
            "invariant_content_id",
            "slot_rva",
            "exit_ids",
            "dependency_sha256",
            "invariant",
        }
        if set(value) != expected:
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis has an unexpected schema"
            )
        if (
            value.get("format") != cls.FORMAT
            or value.get("status") != "prepared"
            or value.get("proof_authority") is not False
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis is not explicitly non-authorizing"
            )
        raw_exits = value.get("exit_ids")
        raw_invariant = value.get("invariant")
        if (
            not isinstance(raw_exits, list)
            or not isinstance(raw_invariant, Mapping)
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis payload is malformed"
            )
        try:
            invariant = GlobalSlotInvariant.parse(raw_invariant)
        except (AuthorityDataError, TypeError, ValueError) as exc:
            raise GlobalSlotHypothesisV2Error(
                f"slot induction invariant does not parse: {exc}"
            ) from exc
        result = cls(
            invariant=invariant,
            exit_ids=tuple(raw_exits),
            dependency_sha256=str(value.get("dependency_sha256")),
        )
        if (
            value.get("id") != result.id
            or value.get("invariant_content_id") != invariant.content_id
            or value.get("slot_rva") != invariant.slot_rva
        ):
            raise GlobalSlotHypothesisV2Error(
                "slot induction hypothesis identity does not match its invariant"
            )
        return result


def derive_global_slot_induction_hypotheses_v2(
    binary: StageABinary,
    *,
    machine_ir_sha256: str,
    proposal_slot_dependencies: Sequence[Mapping[str, Any]],
    finite_value_budget: int = 32,
) -> tuple[GlobalSlotInductionHypothesisV2, ...]:
    """Derive exact launch-value hypotheses for proposal-dependent slots.

    Every dependency is checked structurally and against writable image memory.
    Unsupported loader spans fail closed rather than producing a weaker value.
    """

    if (
        not isinstance(finite_value_budget, int)
        or isinstance(finite_value_budget, bool)
        or finite_value_budget <= 0
    ):
        raise GlobalSlotHypothesisV2Error(
            "slot induction finite-value budget must be positive"
        )
    grouped: dict[int, list[dict[str, Any]]] = {}
    for index, raw in enumerate(proposal_slot_dependencies):
        row = _normalize_dependency(raw, index=index)
        slot_rva = int(row["slot_rva"])
        address = binary.image_base + slot_rva
        if not writable_image_span(binary, address, 4):
            raise GlobalSlotHypothesisV2Error(
                f"proposal slot dependency {slot_rva:#x} is not writable image data"
            )
        grouped.setdefault(slot_rva, []).append(row)

    result: list[GlobalSlotInductionHypothesisV2] = []
    for slot_rva, rows in sorted(grouped.items()):
        canonical_rows = sorted(
            {canonical_sha256(row): row for row in rows}.values(),
            key=canonical_sha256,
        )
        try:
            data, _initialization_kind = loader_initial_bytes_v2(
                binary,
                rva_start=slot_rva,
                width_bytes=4,
            )
            binding = build_image_span_binding_v2(
                binary,
                machine_ir_sha256=machine_ir_sha256,
                rva_start=slot_rva,
                width_bytes=4,
            )
        except GlobalSlotImageV2Error as exc:
            raise GlobalSlotHypothesisV2Error(
                f"proposal slot {slot_rva:#x} has no exact loader value: {exc}"
            ) from exc
        invariant = GlobalSlotInvariant(
            binding=binding,
            slot_rva=slot_rva,
            width_bytes=4,
            invariant_kind="finite_set",
            alternatives=FiniteAlternatives.of(
                [{
                    "kind": "exact_bits",
                    "value": int.from_bytes(data, "little"),
                    "width_bits": 32,
                }],
                maximum=finite_value_budget,
            ),
        )
        result.append(GlobalSlotInductionHypothesisV2(
            invariant=invariant,
            exit_ids=tuple(sorted({str(row["exit_id"]) for row in canonical_rows})),
            dependency_sha256=canonical_sha256(canonical_rows),
        ))
    return tuple(result)


def _normalize_dependency(raw: Mapping[str, Any], *, index: int) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise GlobalSlotHypothesisV2Error(
            f"proposal slot dependency {index} is not an object"
        )
    witness_only = raw.get("witness_only") is True
    expected = (
        {"slot_rva", "exit_id", "witness_only", "proof_authority"}
        if witness_only
        else {
            "slot_rva",
            "exit_id",
            "unit_id",
            "event_index",
            "proof_authority",
        }
    )
    slot_rva = raw.get("slot_rva")
    exit_id = raw.get("exit_id")
    if (
        set(raw) != expected
        or not isinstance(slot_rva, int)
        or isinstance(slot_rva, bool)
        or not 0 <= slot_rva <= 0xFFFF_FFFB
        or not isinstance(exit_id, str)
        or not exit_id
        or raw.get("proof_authority") is not False
    ):
        raise GlobalSlotHypothesisV2Error(
            f"proposal slot dependency {index} is malformed"
        )
    if not witness_only and (
        not isinstance(raw.get("unit_id"), str)
        or not raw.get("unit_id")
        or not isinstance(raw.get("event_index"), int)
        or isinstance(raw.get("event_index"), bool)
        or raw["event_index"] < 0
    ):
        raise GlobalSlotHypothesisV2Error(
            f"proposal slot dependency {index} has no exact read site"
        )
    return dict(raw)


__all__ = [
    "GLOBAL_SLOT_INDUCTION_HYPOTHESIS_V2_FORMAT",
    "GlobalSlotHypothesisV2Error",
    "GlobalSlotInductionHypothesisV2",
    "derive_global_slot_induction_hypotheses_v2",
]
