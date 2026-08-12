"""Root-independent launch assumptions consumed by structural analysis.

The full launch profile also owns behavioral roots, callback contracts, and
unsupported-environment frontiers.  None of those fields may invalidate the
root-independent interprocedural fixed point.  This module therefore extracts
only the explicit machine-state assumptions and binds them to one exact PE32
image.  The projection is deliberately non-authorizing; final launch-profile
validation remains a separate rooted authority phase.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .authority_bindings_v2 import CanonicalJson, canonical_json_bytes


LAUNCH_ANALYSIS_ASSUMPTIONS_V2_FORMAT = (
    "spaghetti-extractor-launch-analysis-assumptions-v2"
)
LAUNCH_PROFILE_V2_FORMAT = "spaghetti-extractor-pe32-launch-profile-v2"
LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT = (
    "spaghetti-extractor-pe32-launch-assumption-template-v1"
)

_PROFILE_AUTHORITY = "conditional_exact_pe32_launch_profile_v2"
_REQUIRED_ASSUMPTIONS = (
    "initial_stack",
    "argv",
    "environment",
    "fs",
    "iat",
    "relocations",
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


class LaunchAssumptionInputsV2Error(ValueError):
    """A launch-assumption input or projection is malformed."""


@dataclass(frozen=True, order=True)
class PE32LaunchAssumptionBinding:
    pe_sha256: str
    image_base: int
    size_of_image: int

    def __post_init__(self) -> None:
        _digest(self.pe_sha256, "PE SHA-256")
        _uint32(self.image_base, "PE image base")
        _positive_uint32(self.size_of_image, "PE image size")
        if self.image_base + self.size_of_image > 1 << 32:
            raise LaunchAssumptionInputsV2Error(
                "PE launch-assumption binding exceeds the PE32 address space"
            )

    def to_payload(self) -> dict[str, Any]:
        return {
            "pe_sha256": self.pe_sha256,
            "machine": "i386",
            "bitness": 32,
            "image_base": self.image_base,
            "size_of_image": self.size_of_image,
        }

    @classmethod
    def parse(cls, value: Any) -> "PE32LaunchAssumptionBinding":
        row = _object(
            value,
            {"pe_sha256", "machine", "bitness", "image_base", "size_of_image"},
            "PE launch-assumption binding",
        )
        if row["machine"] != "i386" or row["bitness"] != 32:
            raise LaunchAssumptionInputsV2Error(
                "launch-assumption binding is not i386 PE32"
            )
        return cls(
            pe_sha256=_digest(row["pe_sha256"], "PE SHA-256"),
            image_base=_uint32(row["image_base"], "PE image base"),
            size_of_image=_positive_uint32(
                row["size_of_image"], "PE image size"
            ),
        )


@dataclass(frozen=True)
class LaunchAnalysisAssumptionsV2:
    binary: PE32LaunchAssumptionBinding
    assumptions: tuple[tuple[str, CanonicalJson], ...]
    projection_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary, PE32LaunchAssumptionBinding):
            raise LaunchAssumptionInputsV2Error(
                "launch assumptions require an exact PE32 binding"
            )
        if tuple(kind for kind, _value in self.assumptions) != _REQUIRED_ASSUMPTIONS:
            raise LaunchAssumptionInputsV2Error(
                "launch assumptions are incomplete or out of order"
            )
        _validate_assumptions(self.assumptions)
        _digest(self.projection_sha256, "launch-assumption projection SHA-256")

    @property
    def assumption_map(self) -> dict[str, Any]:
        return {kind: value.to_value() for kind, value in self.assumptions}

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": LAUNCH_ANALYSIS_ASSUMPTIONS_V2_FORMAT,
            "schema_version": 2,
            "authority": "non_authorizing_root_independent_projection_v2",
            "proof_authority": False,
            "binary": self.binary.to_payload(),
            "assumptions": self.assumption_map,
            "constraints": {
                "root_and_callback_fields_ignored": True,
                "final_launch_profile_validation_required": True,
                "original_binary_executed": False,
            },
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self._core_payload(), "projection_sha256": self.projection_sha256}


def build_launch_analysis_assumptions_v2(
    value: Any,
    *,
    pe_sha256: str,
    image_base: int,
    size_of_image: int,
) -> LaunchAnalysisAssumptionsV2:
    """Extract the root-independent assumptions from a profile or template."""

    binding = PE32LaunchAssumptionBinding(pe_sha256, image_base, size_of_image)
    assumptions = _extract_assumptions(value, expected_binary=binding)
    provisional = LaunchAnalysisAssumptionsV2(
        binary=binding,
        assumptions=assumptions,
        projection_sha256="0" * 64,
    )
    digest = hashlib.sha256(
        canonical_json_bytes(provisional._core_payload())
    ).hexdigest()
    return parse_launch_analysis_assumptions_v2(
        {**provisional._core_payload(), "projection_sha256": digest}
    )


def parse_launch_analysis_assumptions_v2(
    value: Any,
) -> LaunchAnalysisAssumptionsV2:
    """Strictly replay a canonical root-independent assumption projection."""

    row = _object(
        value,
        {
            "format",
            "schema_version",
            "authority",
            "proof_authority",
            "binary",
            "assumptions",
            "constraints",
            "projection_sha256",
        },
        "launch-analysis assumptions",
    )
    if (
        row["format"] != LAUNCH_ANALYSIS_ASSUMPTIONS_V2_FORMAT
        or row["schema_version"] != 2
        or row["authority"] != "non_authorizing_root_independent_projection_v2"
        or row["proof_authority"] is not False
    ):
        raise LaunchAssumptionInputsV2Error(
            "launch-analysis assumption authority is unsupported"
        )
    constraints = _object(
        row["constraints"],
        {
            "root_and_callback_fields_ignored",
            "final_launch_profile_validation_required",
            "original_binary_executed",
        },
        "launch-analysis assumption constraints",
    )
    if constraints != {
        "root_and_callback_fields_ignored": True,
        "final_launch_profile_validation_required": True,
        "original_binary_executed": False,
    }:
        raise LaunchAssumptionInputsV2Error(
            "launch-analysis assumption constraints are weakened"
        )
    binary = PE32LaunchAssumptionBinding.parse(row["binary"])
    assumptions = _assumptions_from_mapping(row["assumptions"])
    result = LaunchAnalysisAssumptionsV2(
        binary=binary,
        assumptions=assumptions,
        projection_sha256=_digest(
            row["projection_sha256"], "launch-assumption projection SHA-256"
        ),
    )
    expected = hashlib.sha256(
        canonical_json_bytes(result._core_payload())
    ).hexdigest()
    if result.projection_sha256 != expected:
        raise LaunchAssumptionInputsV2Error(
            "launch-assumption projection hash is stale"
        )
    if result.to_payload() != _json_clone(row):
        raise LaunchAssumptionInputsV2Error(
            "launch-assumption projection is noncanonical"
        )
    return result


def _extract_assumptions(
    value: Any,
    *,
    expected_binary: PE32LaunchAssumptionBinding,
) -> tuple[tuple[str, CanonicalJson], ...]:
    if not isinstance(value, Mapping):
        raise LaunchAssumptionInputsV2Error("launch input is not an object")
    format_name = value.get("format")
    if format_name == LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT:
        row = _object(
            value,
            {"format", "schema_version", "assumptions", "feature_inventory"},
            "launch assumption template",
        )
        if row["schema_version"] != 1:
            raise LaunchAssumptionInputsV2Error(
                "launch assumption template version is unsupported"
            )
        return _assumptions_from_mapping(row["assumptions"])
    if format_name != LAUNCH_PROFILE_V2_FORMAT:
        raise LaunchAssumptionInputsV2Error("launch input format is unsupported")
    if value.get("schema_version") != 2 or value.get("authority") != _PROFILE_AUTHORITY:
        raise LaunchAssumptionInputsV2Error("launch profile authority is unsupported")
    observed_binary = PE32LaunchAssumptionBinding.parse(value.get("binary"))
    if observed_binary != expected_binary:
        raise LaunchAssumptionInputsV2Error(
            "launch profile binds a different PE32 image"
        )
    raw = value.get("assumptions")
    if not isinstance(raw, list):
        raise LaunchAssumptionInputsV2Error(
            "launch profile assumption inventory is not an array"
        )
    if len(raw) != len(_REQUIRED_ASSUMPTIONS):
        raise LaunchAssumptionInputsV2Error(
            "launch profile assumptions are incomplete"
        )
    mapped: dict[str, Any] = {}
    for index, item in enumerate(raw):
        row = _object(
            item, {"kind", "source", "value"}, f"launch assumption {index}"
        )
        expected_kind = _REQUIRED_ASSUMPTIONS[index]
        if row["kind"] != expected_kind or row["source"] != "explicit_profile_assumption":
            raise LaunchAssumptionInputsV2Error(
                "launch profile assumptions are noncanonical"
            )
        mapped[expected_kind] = row["value"]
    return _assumptions_from_mapping(mapped)


def _assumptions_from_mapping(
    value: Any,
) -> tuple[tuple[str, CanonicalJson], ...]:
    row = _object(value, set(_REQUIRED_ASSUMPTIONS), "launch assumptions")
    result = tuple(
        (kind, CanonicalJson.of(row[kind])) for kind in _REQUIRED_ASSUMPTIONS
    )
    _validate_assumptions(result)
    return result


def _validate_assumptions(
    assumptions: tuple[tuple[str, CanonicalJson], ...],
) -> None:
    for _kind, value in assumptions:
        if not isinstance(value, CanonicalJson):
            raise LaunchAssumptionInputsV2Error(
                "launch assumption is not immutable canonical JSON"
            )
        decoded = value.to_value()
        if not isinstance(decoded, dict) or not decoded:
            raise LaunchAssumptionInputsV2Error(
                "launch assumption must be a nonempty object"
            )


def _object(value: Any, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise LaunchAssumptionInputsV2Error(f"{context} has noncanonical fields")
    return dict(value)


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise LaunchAssumptionInputsV2Error(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _uint32(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << 32:
        raise LaunchAssumptionInputsV2Error(f"{context} must be an unsigned 32-bit integer")
    return value


def _positive_uint32(value: Any, context: str) -> int:
    result = _uint32(value, context)
    if result == 0:
        raise LaunchAssumptionInputsV2Error(f"{context} must be positive")
    return result


def _json_clone(value: Any) -> Any:
    return CanonicalJson.of(value).to_value()


__all__ = [
    "LAUNCH_ANALYSIS_ASSUMPTIONS_V2_FORMAT",
    "LaunchAnalysisAssumptionsV2",
    "LaunchAssumptionInputsV2Error",
    "PE32LaunchAssumptionBinding",
    "build_launch_analysis_assumptions_v2",
    "parse_launch_analysis_assumptions_v2",
]
