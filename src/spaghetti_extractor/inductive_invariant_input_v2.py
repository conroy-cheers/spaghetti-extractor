"""Strict non-authorizing inputs for inductive invariant synthesis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import BinaryBinding
from .invariant_certificate_v2 import (
    CutpointInvariantV2,
    ExportRequirementV2,
    InvariantCertificateV2Error,
    InvariantFactV2,
    canonical_sha256,
)


INDUCTIVE_INVARIANT_INPUT_V2_FORMAT = (
    "spaghetti-extractor-inductive-invariant-input-v2"
)


@dataclass(frozen=True)
class InductiveInvariantInputV2:
    """Proposed predicates that gain authority only through induction checks."""

    binary: BinaryBinding
    profile_sha256: str
    cutpoint_invariants: tuple[CutpointInvariantV2, ...]
    required_exports: tuple[ExportRequirementV2, ...]
    input_id: str

    def __post_init__(self) -> None:
        if len(self.profile_sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in self.profile_sha256
        ):
            raise InvariantCertificateV2Error(
                "invariant input profile binding is not a SHA-256 digest"
            )
        if self.cutpoint_invariants != tuple(
            sorted(
                set(self.cutpoint_invariants),
                key=lambda row: row.cutpoint,
            )
        ):
            raise InvariantCertificateV2Error(
                "invariant input cutpoints are not sorted and unique"
            )
        if self.required_exports != tuple(
            sorted(set(self.required_exports), key=lambda row: row.export_id)
        ):
            raise InvariantCertificateV2Error(
                "invariant input exports are not sorted and unique"
            )
        expected = "inductive-invariant-input-v2:" + canonical_sha256(
            self.identity_payload()
        )
        if self.input_id != expected:
            raise InvariantCertificateV2Error("invariant input ID is stale")

    @classmethod
    def create(
        cls,
        *,
        binary: BinaryBinding,
        profile_sha256: str,
        cutpoint_invariants: Sequence[CutpointInvariantV2],
        required_exports: Sequence[ExportRequirementV2] = (),
    ) -> "InductiveInvariantInputV2":
        invariants = tuple(
            sorted(set(cutpoint_invariants), key=lambda row: row.cutpoint)
        )
        exports = tuple(
            sorted(set(required_exports), key=lambda row: row.export_id)
        )
        body = {
            "authorizing": False,
            "binary": binary.to_payload(),
            "cutpoint_invariants": [row.to_payload() for row in invariants],
            "profile_sha256": profile_sha256,
            "required_exports": [row.to_payload() for row in exports],
        }
        return cls(
            binary=binary,
            profile_sha256=profile_sha256,
            cutpoint_invariants=invariants,
            required_exports=exports,
            input_id="inductive-invariant-input-v2:" + canonical_sha256(body),
        )

    def identity_payload(self) -> dict[str, Any]:
        return {
            "authorizing": False,
            "binary": self.binary.to_payload(),
            "cutpoint_invariants": [
                row.to_payload() for row in self.cutpoint_invariants
            ],
            "profile_sha256": self.profile_sha256,
            "required_exports": [
                row.to_payload() for row in self.required_exports
            ],
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": INDUCTIVE_INVARIANT_INPUT_V2_FORMAT,
            "id": self.input_id,
            **self.identity_payload(),
        }

    @classmethod
    def parse(
        cls,
        value: Any,
        *,
        binary: BinaryBinding,
        profile_sha256: str,
        known_cutpoints: Sequence[str],
    ) -> "InductiveInvariantInputV2":
        fields = {
            "authorizing",
            "binary",
            "cutpoint_invariants",
            "format",
            "id",
            "profile_sha256",
            "required_exports",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise InvariantCertificateV2Error(
                "inductive invariant input has noncanonical fields"
            )
        if value["format"] != INDUCTIVE_INVARIANT_INPUT_V2_FORMAT:
            raise InvariantCertificateV2Error(
                "inductive invariant input format is unsupported"
            )
        if value["authorizing"] is not False:
            raise InvariantCertificateV2Error(
                "an invariant proposal cannot claim authority"
            )
        rows = value["cutpoint_invariants"]
        if not isinstance(rows, list):
            raise InvariantCertificateV2Error(
                "inductive invariant cutpoints must be an array"
            )
        result = cls(
            binary=BinaryBinding.parse(value["binary"]),
            profile_sha256=str(value["profile_sha256"]),
            cutpoint_invariants=tuple(
                CutpointInvariantV2.parse(row) for row in rows
            ),
            required_exports=tuple(
                ExportRequirementV2.parse(row)
                for row in _export_rows(value["required_exports"])
            ),
            input_id=str(value["id"]),
        )
        if result.binary != binary or result.profile_sha256 != profile_sha256:
            raise InvariantCertificateV2Error(
                "inductive invariant input binding is stale"
            )
        known = frozenset(known_cutpoints)
        unknown = sorted(
            {
                row.cutpoint
                for row in result.cutpoint_invariants
                if row.cutpoint not in known
            }
            | {
                row.cutpoint
                for row in result.required_exports
                if row.cutpoint not in known
            }
        )
        if unknown:
            raise InvariantCertificateV2Error(
                "inductive invariant input names unknown cutpoints: "
                + ", ".join(unknown)
            )
        return result

    @property
    def cutpoint_facts(self) -> dict[str, tuple[InvariantFactV2, ...]]:
        return {
            row.cutpoint: row.facts for row in self.cutpoint_invariants
        }


def _export_rows(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise InvariantCertificateV2Error(
            "inductive invariant exports must be an array"
        )
    return value


__all__ = [
    "INDUCTIVE_INVARIANT_INPUT_V2_FORMAT",
    "InductiveInvariantInputV2",
]
