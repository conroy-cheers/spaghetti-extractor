"""Canonical root-independent inventory of exact unit transition summaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import AuthorityDataError, BinaryBinding
from .transition_summary_v2 import (
    TransitionSummaryV2,
    TransitionSummaryV2Error,
    check_transition_summary_v2,
    derive_transition_summary_v2,
)


TRANSITION_SUMMARY_INVENTORY_V2_FORMAT = (
    "spaghetti-extractor-transition-summary-inventory-v2"
)


class TransitionSummaryInventoryV2Error(ValueError):
    """An inventory is malformed or contradicts exact machine IR."""


@dataclass(frozen=True)
class TransitionSummaryInventoryV2:
    inventory_id: str
    status: str
    binary: BinaryBinding
    summaries: tuple[TransitionSummaryV2, ...]

    def __post_init__(self) -> None:
        if self.status not in {"complete", "incomplete", "violated"}:
            raise TransitionSummaryInventoryV2Error(
                "transition inventory has an invalid status"
            )
        if not isinstance(self.binary, BinaryBinding):
            raise TransitionSummaryInventoryV2Error(
                "transition inventory has no exact binary binding"
            )
        ordered = tuple(sorted(self.summaries, key=lambda row: row.unit.unit_id))
        if ordered != self.summaries or len({
            row.unit.unit_id for row in self.summaries
        }) != len(self.summaries):
            raise TransitionSummaryInventoryV2Error(
                "transition summaries are duplicated or noncanonical"
            )
        if any(row.unit.binary != self.binary for row in self.summaries):
            raise TransitionSummaryInventoryV2Error(
                "transition summary is bound to another binary"
            )
        expected_status = (
            "incomplete"
            if any(row.status != "complete" for row in self.summaries)
            else "complete"
        )
        if self.status != expected_status:
            raise TransitionSummaryInventoryV2Error(
                "transition inventory status contradicts its summaries"
            )
        expected_id = "transition-summary-inventory-v2:" + canonical_sha256(
            self.identity_payload()
        )
        if self.inventory_id != expected_id:
            raise TransitionSummaryInventoryV2Error(
                "transition inventory identity is stale"
            )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "root_independent": True,
            "status": self.status,
            "binary": self.binary.to_payload(),
            "summary_ids": [row.summary_id for row in self.summaries],
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": TRANSITION_SUMMARY_INVENTORY_V2_FORMAT,
            "id": self.inventory_id,
            "root_independent": True,
            "status": self.status,
            "binary": self.binary.to_payload(),
            "summaries": [row.to_payload() for row in self.summaries],
            "counts": self.counts_payload(),
        }

    def counts_payload(self) -> dict[str, int]:
        return {
            "units": len(self.summaries),
            "complete": sum(
                row.status == "complete" for row in self.summaries
            ),
            "incomplete": sum(
                row.status == "incomplete" for row in self.summaries
            ),
            "unsupported_effects": sum(
                len(row.unsupported_effects) for row in self.summaries
            ),
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "TransitionSummaryInventoryV2":
        expected = {
            "format",
            "id",
            "root_independent",
            "status",
            "binary",
            "summaries",
            "counts",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise TransitionSummaryInventoryV2Error(
                "transition inventory has noncanonical fields"
            )
        if (
            value.get("format") != TRANSITION_SUMMARY_INVENTORY_V2_FORMAT
            or value.get("root_independent") is not True
        ):
            raise TransitionSummaryInventoryV2Error(
                "transition inventory has an invalid format or scope"
            )
        raw = value.get("summaries")
        if not isinstance(raw, list):
            raise TransitionSummaryInventoryV2Error(
                "transition summary inventory is not an array"
            )
        try:
            result = cls(
                inventory_id=str(value.get("id")),
                status=str(value.get("status")),
                binary=BinaryBinding.parse(value.get("binary")),
                summaries=tuple(TransitionSummaryV2.parse(row) for row in raw),
            )
        except (AuthorityDataError, TypeError, ValueError) as exc:
            raise TransitionSummaryInventoryV2Error(
                f"transition inventory is malformed: {exc}"
            ) from exc
        if value.get("counts") != result.counts_payload():
            raise TransitionSummaryInventoryV2Error(
                "transition inventory counts are stale"
            )
        return result


def build_transition_summary_inventory_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
) -> TransitionSummaryInventoryV2:
    """Derive every exact structural summary once, independent of roots."""

    try:
        summaries = tuple(sorted(
            (
                derive_transition_summary_v2(row, binary=binary)
                for row in units
            ),
            key=lambda row: row.unit.unit_id,
        ))
    except (AuthorityDataError, TransitionSummaryV2Error, TypeError, ValueError) as exc:
        raise TransitionSummaryInventoryV2Error(
            f"cannot build transition inventory: {exc}"
        ) from exc
    status = (
        "incomplete"
        if any(row.status != "complete" for row in summaries)
        else "complete"
    )
    identity = {
        "root_independent": True,
        "status": status,
        "binary": binary.to_payload(),
        "summary_ids": [row.summary_id for row in summaries],
    }
    return TransitionSummaryInventoryV2(
        inventory_id="transition-summary-inventory-v2:"
        + canonical_sha256(identity),
        status=status,
        binary=binary,
        summaries=summaries,
    )


def check_transition_summary_inventory_v2(
    value: TransitionSummaryInventoryV2 | Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
) -> TransitionSummaryInventoryV2:
    """Recheck every summary and the closed exact unit inventory."""

    submitted = (
        value
        if isinstance(value, TransitionSummaryInventoryV2)
        else TransitionSummaryInventoryV2.parse(value)
    )
    by_id = {
        str(row.get("id")): row
        for row in units
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    if len(by_id) != len(units) or set(by_id) != {
        row.unit.unit_id for row in submitted.summaries
    }:
        raise TransitionSummaryInventoryV2Error(
            "transition inventory does not cover every exact unit once"
        )
    if submitted.binary != binary:
        raise TransitionSummaryInventoryV2Error(
            "transition inventory is bound to another binary"
        )
    for summary in submitted.summaries:
        check_transition_summary_v2(
            summary,
            unit_row=by_id[summary.unit.unit_id],
            binary=binary,
        )
    expected = build_transition_summary_inventory_v2(
        units=units,
        binary=binary,
    )
    if submitted != expected:
        raise TransitionSummaryInventoryV2Error(
            "transition inventory contradicts exact machine IR"
        )
    return submitted


__all__ = [
    "TRANSITION_SUMMARY_INVENTORY_V2_FORMAT",
    "TransitionSummaryInventoryV2",
    "TransitionSummaryInventoryV2Error",
    "build_transition_summary_inventory_v2",
    "check_transition_summary_inventory_v2",
]
