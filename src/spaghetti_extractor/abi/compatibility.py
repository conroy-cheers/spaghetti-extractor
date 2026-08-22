"""Physical ABI compatibility and adapter feasibility checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .model import AbiValueV1, PhysicalAbiProfileV1, stable_id


@dataclass(frozen=True, order=True)
class AbiCompatibilityIssueV1:
    status: str
    code: str
    field: str
    expected: object
    observed: object

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "code": self.code,
            "field": self.field,
            "expected": self.expected,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class AbiCompatibilityV1:
    compatibility_id: str
    status: str
    kind: str
    observed_profile_id: str
    expected_profile_id: str
    issues: tuple[AbiCompatibilityIssueV1, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "format": "spaghetti-extractor-abi-compatibility-v1",
            "id": self.compatibility_id,
            "status": self.status,
            "kind": self.kind,
            "observed_profile_id": self.observed_profile_id,
            "expected_profile_id": self.expected_profile_id,
            "issues": [item.to_payload() for item in self.issues],
        }


def _value_shape(value: AbiValueV1) -> dict[str, object]:
    return {
        "width_bits": value.width_bits,
        "role": value.role,
        "callback_abi_id": value.callback_abi_id,
    }


def _issue(
    rows: list[AbiCompatibilityIssueV1],
    *,
    code: str,
    field: str,
    expected: object,
    observed: object,
) -> None:
    rows.append(
        AbiCompatibilityIssueV1(
            "violated",
            code,
            field,
            expected,
            observed,
        )
    )


def compare_physical_abis(
    observed: PhysicalAbiProfileV1,
    expected: PhysicalAbiProfileV1,
    *,
    allow_adapter: bool = False,
) -> AbiCompatibilityV1:
    """Compare two complete physical profiles.

    Exact library identity requires an identical physical boundary.  Adapter
    compatibility deliberately ignores concrete register/stack locations but
    still requires lossless values, callback contracts, target width, cleanup,
    and at least the preservation guarantees expected by the caller.
    """

    issues: list[AbiCompatibilityIssueV1] = []
    for field in ("target", "stack_cleanup", "variadic"):
        observed_value = getattr(observed, field)
        expected_value = getattr(expected, field)
        observed_payload = (
            observed_value.to_payload()
            if hasattr(observed_value, "to_payload")
            else observed_value
        )
        expected_payload = (
            expected_value.to_payload()
            if hasattr(expected_value, "to_payload")
            else expected_value
        )
        if observed_payload != expected_payload:
            _issue(
                issues,
                code="physical_abi_field_mismatch",
                field=field,
                expected=expected_payload,
                observed=observed_payload,
            )
    if observed.stack_coordinate != expected.stack_coordinate:
        _issue(
            issues,
            code="stack_coordinate_mismatch",
            field="stack_coordinate",
            expected=expected.stack_coordinate,
            observed=observed.stack_coordinate,
        )
    if observed.stack_alignment_bytes < expected.stack_alignment_bytes:
        _issue(
            issues,
            code="stack_alignment_too_weak",
            field="stack_alignment_bytes",
            expected=expected.stack_alignment_bytes,
            observed=observed.stack_alignment_bytes,
        )
    missing_preserved = sorted(
        set(expected.preserved_state) - set(observed.preserved_state)
    )
    if missing_preserved:
        _issue(
            issues,
            code="preservation_guarantee_missing",
            field="preserved_state",
            expected=list(expected.preserved_state),
            observed=list(observed.preserved_state),
        )

    for field in ("arguments", "results"):
        observed_values = getattr(observed, field)
        expected_values = getattr(expected, field)
        if len(observed_values) != len(expected_values):
            _issue(
                issues,
                code="physical_value_count_mismatch",
                field=field,
                expected=len(expected_values),
                observed=len(observed_values),
            )
            continue
        for index, (observed_value, expected_value) in enumerate(
            zip(observed_values, expected_values, strict=True)
        ):
            expected_shape = _value_shape(expected_value)
            observed_shape = _value_shape(observed_value)
            if observed_shape != expected_shape:
                _issue(
                    issues,
                    code="physical_value_shape_mismatch",
                    field=f"{field}[{index}]",
                    expected=expected_shape,
                    observed=observed_shape,
                )
                continue
            if not allow_adapter and (
                tuple(item.to_payload() for item in observed_value.fragments)
                != tuple(item.to_payload() for item in expected_value.fragments)
            ):
                _issue(
                    issues,
                    code="physical_value_location_mismatch",
                    field=f"{field}[{index}].fragments",
                    expected=[item.to_payload() for item in expected_value.fragments],
                    observed=[item.to_payload() for item in observed_value.fragments],
                )

    if not allow_adapter and observed.calling_convention != expected.calling_convention:
        _issue(
            issues,
            code="calling_convention_mismatch",
            field="calling_convention",
            expected=expected.calling_convention,
            observed=observed.calling_convention,
        )

    ordered = tuple(sorted(issues))
    kind = "violated" if ordered else (
        "exact"
        if observed.to_payload() == expected.to_payload()
        else "adapter_compatible"
    )
    status = "violated" if ordered else "complete"
    core = {
        "status": status,
        "kind": kind,
        "observed_profile_id": observed.profile_id,
        "expected_profile_id": expected.profile_id,
        "issues": [item.to_payload() for item in ordered],
    }
    return AbiCompatibilityV1(
        stable_id("abi-compatibility-v1", core),
        status,
        kind,
        observed.profile_id,
        expected.profile_id,
        ordered,
    )


def compatibility_statuses(
    rows: Iterable[AbiCompatibilityV1],
) -> tuple[str, ...]:
    return tuple(row.kind for row in rows)


__all__ = [
    "AbiCompatibilityIssueV1",
    "AbiCompatibilityV1",
    "compare_physical_abis",
    "compatibility_statuses",
]
