"""Typed, fail-closed ownership ledger for portable lifting workflows.

The ledger is deliberately independent of Nix and artifact storage.  It binds
an exact structural unit universe to one implementation owner per unit and
derives all status and issue fields from immutable typed inputs.  Artifact
consumers must still resolve the referenced identities and verify their
content hashes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    UnitBinding,
    _array,
    _json_value,
    _object,
    _sha256,
    _text,
    canonical_json,
    canonical_json_bytes,
)


IMPLEMENTATION_LEDGER_V2_FORMAT = "spaghetti-extractor-implementation-ledger-v2"
IMPLEMENTATION_LEDGER_V2_SCHEMA_VERSION = 2


class CompletionProfileV2(str, Enum):
    STATIC_BASELINE = "static-baseline-v1"
    PORTABLE_APPLICATION = "portable-application-v1"
    VALIDATION_QUALIFIED = "validation-qualified-v1"


class CompletionStatusV2(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


class ImplementationOwnerKindV2(str, Enum):
    PORTABLE_COMPONENT = "portable_component"
    LIBRARY_SUBSTITUTION = "library_substitution"
    MACHINE_IR_FALLBACK = "machine_ir_fallback"
    UNASSIGNED = "unassigned"


def _status(value: Any, context: str) -> CompletionStatusV2:
    try:
        return CompletionStatusV2(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityDataError(f"{context} has an invalid status") from exc


def _profile(value: Any, context: str) -> CompletionProfileV2:
    try:
        return CompletionProfileV2(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityDataError(f"{context} has an invalid profile") from exc


def _owner_kind(value: Any, context: str) -> ImplementationOwnerKindV2:
    try:
        return ImplementationOwnerKindV2(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityDataError(f"{context} has an invalid owner kind") from exc


def _content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}:{_content_sha256(value)}"


@dataclass(frozen=True, order=True)
class ArtifactIdentityV2:
    artifact_kind: str
    artifact_id: str
    sha256: str

    def __post_init__(self) -> None:
        _text(self.artifact_kind, "artifact kind", maximum=128)
        _text(self.artifact_id, "artifact ID", maximum=512)
        _sha256(self.sha256, "artifact SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "artifact_kind": self.artifact_kind,
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "ArtifactIdentityV2":
        row = _object(
            value,
            {"artifact_kind", "artifact_id", "sha256"},
            "artifact identity",
        )
        return cls(
            artifact_kind=_text(row["artifact_kind"], "artifact kind", maximum=128),
            artifact_id=_text(row["artifact_id"], "artifact ID", maximum=512),
            sha256=_sha256(row["sha256"], "artifact SHA-256"),
        )


@dataclass(frozen=True, order=True)
class LedgerIssueV2:
    status: CompletionStatusV2
    code: str
    location: str
    detail: str

    def __post_init__(self) -> None:
        if self.status is CompletionStatusV2.COMPLETE:
            raise AuthorityDataError("ledger issues cannot have complete status")
        _text(self.code, "ledger issue code", maximum=128)
        _text(self.location, "ledger issue location", maximum=512)
        _text(self.detail, "ledger issue detail", maximum=1024)

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status.value,
            "code": self.code,
            "location": self.location,
            "detail": self.detail,
        }

    @classmethod
    def parse(cls, value: Any) -> "LedgerIssueV2":
        row = _object(
            value,
            {"status", "code", "location", "detail"},
            "implementation-ledger issue",
        )
        return cls(
            status=_status(row["status"], "implementation-ledger issue"),
            code=_text(row["code"], "ledger issue code", maximum=128),
            location=_text(row["location"], "ledger issue location", maximum=512),
            detail=_text(row["detail"], "ledger issue detail", maximum=1024),
        )


@dataclass(frozen=True, order=True)
class ImplementationOwnerV2:
    kind: ImplementationOwnerKindV2
    implementation: ArtifactIdentityV2 | None
    qualification: ArtifactIdentityV2 | None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ImplementationOwnerKindV2):
            raise AuthorityDataError("implementation owner kind must be typed")
        if self.implementation is not None and not isinstance(
            self.implementation, ArtifactIdentityV2
        ):
            raise AuthorityDataError("implementation identity must be typed")
        if self.qualification is not None and not isinstance(
            self.qualification, ArtifactIdentityV2
        ):
            raise AuthorityDataError("qualification identity must be typed")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "implementation": (
                None if self.implementation is None else self.implementation.to_payload()
            ),
            "qualification": (
                None if self.qualification is None else self.qualification.to_payload()
            ),
        }

    @classmethod
    def parse(cls, value: Any) -> "ImplementationOwnerV2":
        row = _object(
            value,
            {"kind", "implementation", "qualification"},
            "implementation owner",
        )
        return cls(
            kind=_owner_kind(row["kind"], "implementation owner"),
            implementation=(
                None
                if row["implementation"] is None
                else ArtifactIdentityV2.parse(row["implementation"])
            ),
            qualification=(
                None
                if row["qualification"] is None
                else ArtifactIdentityV2.parse(row["qualification"])
            ),
        )


@dataclass(frozen=True)
class UnitOwnershipRecordV2:
    owner: ImplementationOwnerV2
    units: tuple[UnitBinding, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.owner, ImplementationOwnerV2):
            raise AuthorityDataError("ownership record owner must be typed")
        if not isinstance(self.units, tuple) or any(
            not isinstance(unit, UnitBinding) for unit in self.units
        ):
            raise AuthorityDataError("ownership record units must be a typed tuple")
        if not self.units:
            raise AuthorityDataError("ownership record must claim at least one unit")

    @classmethod
    def create(
        cls,
        *,
        owner: ImplementationOwnerV2,
        units: Sequence[UnitBinding],
    ) -> "UnitOwnershipRecordV2":
        return cls(owner=owner, units=tuple(sorted(units)))

    def _core_payload(self) -> dict[str, Any]:
        return {
            "owner": self.owner.to_payload(),
            "units": [unit.to_payload() for unit in self.units],
        }

    @cached_property
    def record_id(self) -> str:
        return _content_id("implementation-owner-v2", self._core_payload())

    def to_payload(self) -> dict[str, Any]:
        return {"record_id": self.record_id, **self._core_payload()}

    @classmethod
    def parse(cls, value: Any) -> "UnitOwnershipRecordV2":
        row = _object(
            value,
            {"record_id", "owner", "units"},
            "unit ownership record",
        )
        result = cls(
            owner=ImplementationOwnerV2.parse(row["owner"]),
            units=tuple(
                UnitBinding.parse(item)
                for item in _array(row["units"], "ownership record units")
            ),
        )
        if row["record_id"] != result.record_id:
            raise AuthorityDataError("unit ownership record ID is stale")
        return result


def structural_unit_inventory_sha256_v2(
    units: Sequence[UnitBinding],
) -> str:
    return _content_sha256([unit.to_payload() for unit in sorted(units)])


def _issue(
    status: CompletionStatusV2,
    code: str,
    location: str,
    detail: str,
) -> LedgerIssueV2:
    return LedgerIssueV2(status, code, location, detail)


def _derive_status(issues: Sequence[LedgerIssueV2]) -> CompletionStatusV2:
    if any(issue.status is CompletionStatusV2.VIOLATED for issue in issues):
        return CompletionStatusV2.VIOLATED
    if issues:
        return CompletionStatusV2.INCOMPLETE
    return CompletionStatusV2.COMPLETE


@dataclass(frozen=True)
class OwnerQualificationRequirementV2:
    owner_kind: ImplementationOwnerKindV2
    qualification: ArtifactIdentityV2

    def __post_init__(self) -> None:
        if self.owner_kind is ImplementationOwnerKindV2.UNASSIGNED:
            raise AuthorityDataError("unassigned ownership cannot require qualification")
        if not isinstance(self.qualification, ArtifactIdentityV2):
            raise AuthorityDataError("owner qualification must be typed")

    def to_payload(self) -> dict[str, Any]:
        return {
            "owner_kind": self.owner_kind.value,
            "qualification": self.qualification.to_payload(),
        }

    @classmethod
    def parse(cls, value: Any) -> "OwnerQualificationRequirementV2":
        row = _object(
            value,
            {"owner_kind", "qualification"},
            "owner qualification requirement",
        )
        return cls(
            owner_kind=_owner_kind(row["owner_kind"], "owner qualification"),
            qualification=ArtifactIdentityV2.parse(row["qualification"]),
        )


@dataclass(frozen=True)
class ImplementationLedgerBindingV2:
    identity: ArtifactIdentityV2
    profile: CompletionProfileV2
    status: CompletionStatusV2
    binary: BinaryBinding
    exact_unit_inventory_sha256: str
    structural_unit_count: int
    ownership_record_count: int
    qualification_requirements: tuple[OwnerQualificationRequirementV2, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ArtifactIdentityV2):
            raise AuthorityDataError("ledger binding identity must be typed")
        if self.identity.artifact_kind != "implementation-ledger-v2":
            raise AuthorityDataError("ledger binding has the wrong artifact kind")
        if not isinstance(self.profile, CompletionProfileV2):
            raise AuthorityDataError("ledger binding profile must be typed")
        if not isinstance(self.status, CompletionStatusV2):
            raise AuthorityDataError("ledger binding status must be typed")
        if not isinstance(self.binary, BinaryBinding):
            raise AuthorityDataError("ledger binding binary must be typed")
        _sha256(
            self.exact_unit_inventory_sha256,
            "ledger binding exact-unit inventory SHA-256",
        )
        for value, context in (
            (self.structural_unit_count, "structural unit count"),
            (self.ownership_record_count, "ownership record count"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AuthorityDataError(f"ledger binding {context} is invalid")
        if not isinstance(self.qualification_requirements, tuple) or any(
            not isinstance(item, OwnerQualificationRequirementV2)
            for item in self.qualification_requirements
        ):
            raise AuthorityDataError("ledger qualification requirements must be typed")
        if self.qualification_requirements != tuple(
            sorted(set(self.qualification_requirements), key=lambda item: (
                item.owner_kind.value,
                item.qualification,
            ))
        ):
            raise AuthorityDataError(
                "ledger qualification requirements must be sorted and unique"
            )
        if self.status is CompletionStatusV2.COMPLETE:
            if (
                self.structural_unit_count == 0
                or self.ownership_record_count == 0
                or not self.qualification_requirements
            ):
                raise AuthorityDataError(
                    "complete ledger binding must describe nonempty qualified ownership"
                )
            if self.profile in {
                CompletionProfileV2.PORTABLE_APPLICATION,
                CompletionProfileV2.VALIDATION_QUALIFIED,
            } and any(
                item.owner_kind
                in {
                    ImplementationOwnerKindV2.MACHINE_IR_FALLBACK,
                    ImplementationOwnerKindV2.UNASSIGNED,
                }
                for item in self.qualification_requirements
            ):
                raise AuthorityDataError(
                    "complete portable ledger binding contains a forbidden owner"
                )

    def to_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_payload(),
            "profile": self.profile.value,
            "status": self.status.value,
            "binary": self.binary.to_payload(),
            "exact_unit_inventory_sha256": self.exact_unit_inventory_sha256,
            "structural_unit_count": self.structural_unit_count,
            "ownership_record_count": self.ownership_record_count,
            "qualification_requirements": [
                item.to_payload() for item in self.qualification_requirements
            ],
        }

    @classmethod
    def parse(cls, value: Any) -> "ImplementationLedgerBindingV2":
        row = _object(
            value,
            {
                "identity",
                "profile",
                "status",
                "binary",
                "exact_unit_inventory_sha256",
                "structural_unit_count",
                "ownership_record_count",
                "qualification_requirements",
            },
            "implementation-ledger binding",
        )
        return cls(
            identity=ArtifactIdentityV2.parse(row["identity"]),
            profile=_profile(row["profile"], "implementation-ledger binding"),
            status=_status(row["status"], "implementation-ledger binding"),
            binary=BinaryBinding.parse(row["binary"]),
            exact_unit_inventory_sha256=_sha256(
                row["exact_unit_inventory_sha256"],
                "ledger binding exact-unit inventory SHA-256",
            ),
            structural_unit_count=row["structural_unit_count"],
            ownership_record_count=row["ownership_record_count"],
            qualification_requirements=tuple(
                OwnerQualificationRequirementV2.parse(item)
                for item in _array(
                    row["qualification_requirements"],
                    "ledger qualification requirements",
                )
            ),
        )


@dataclass(frozen=True)
class ImplementationLedgerV2:
    profile: CompletionProfileV2
    binary: BinaryBinding
    exact_unit_inventory_sha256: str
    structural_units: tuple[UnitBinding, ...]
    ownership_records: tuple[UnitOwnershipRecordV2, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.profile, CompletionProfileV2):
            raise AuthorityDataError("implementation-ledger profile must be typed")
        if not isinstance(self.binary, BinaryBinding):
            raise AuthorityDataError("implementation-ledger binary must be typed")
        _sha256(
            self.exact_unit_inventory_sha256,
            "implementation-ledger exact-unit inventory SHA-256",
        )
        if not isinstance(self.structural_units, tuple) or any(
            not isinstance(unit, UnitBinding) for unit in self.structural_units
        ):
            raise AuthorityDataError("structural units must be a typed tuple")
        if not isinstance(self.ownership_records, tuple) or any(
            not isinstance(record, UnitOwnershipRecordV2)
            for record in self.ownership_records
        ):
            raise AuthorityDataError("ownership records must be a typed tuple")

    @classmethod
    def create(
        cls,
        *,
        profile: CompletionProfileV2,
        binary: BinaryBinding,
        structural_units: Sequence[UnitBinding],
        ownership_records: Sequence[UnitOwnershipRecordV2],
    ) -> "ImplementationLedgerV2":
        units = tuple(sorted(structural_units))
        records = tuple(sorted(ownership_records, key=lambda item: item.record_id))
        return cls(
            profile=profile,
            binary=binary,
            exact_unit_inventory_sha256=structural_unit_inventory_sha256_v2(units),
            structural_units=units,
            ownership_records=records,
        )

    @cached_property
    def issues(self) -> tuple[LedgerIssueV2, ...]:
        issues: set[LedgerIssueV2] = set()
        expected_by_id: dict[str, UnitBinding] = {}
        duplicate_universe_ids: set[str] = set()

        if not self.structural_units:
            issues.add(_issue(
                CompletionStatusV2.INCOMPLETE,
                "structural_unit_universe_empty",
                "structural_units",
                "no exact structural units are available for ownership",
            ))
        if self.structural_units != tuple(sorted(self.structural_units)):
            issues.add(_issue(
                CompletionStatusV2.VIOLATED,
                "noncanonical_structural_unit_order",
                "structural_units",
                "structural units are not in canonical order",
            ))
        for unit in self.structural_units:
            if unit.binary != self.binary:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "structural_unit_binary_mismatch",
                    unit.unit_id,
                    "structural unit binds a different PE or machine-IR universe",
                ))
            if unit.unit_id in expected_by_id:
                duplicate_universe_ids.add(unit.unit_id)
            else:
                expected_by_id[unit.unit_id] = unit
        for unit_id in duplicate_universe_ids:
            issues.add(_issue(
                CompletionStatusV2.VIOLATED,
                "duplicate_structural_unit",
                unit_id,
                "the exact structural universe contains a duplicate unit ID",
            ))

        observed_inventory = structural_unit_inventory_sha256_v2(
            self.structural_units
        )
        if observed_inventory != self.exact_unit_inventory_sha256:
            issues.add(_issue(
                CompletionStatusV2.VIOLATED,
                "stale_structural_unit_inventory",
                "exact_unit_inventory_sha256",
                "the structural-unit inventory digest does not match its units",
            ))

        if self.ownership_records != tuple(
            sorted(self.ownership_records, key=lambda item: item.record_id)
        ):
            issues.add(_issue(
                CompletionStatusV2.VIOLATED,
                "noncanonical_ownership_record_order",
                "ownership_records",
                "ownership records are not in canonical order",
            ))

        records_by_id: dict[str, int] = {}
        valid_claims: dict[str, set[str]] = {}
        for record in self.ownership_records:
            records_by_id[record.record_id] = records_by_id.get(record.record_id, 0) + 1
            if record.units != tuple(sorted(record.units)):
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "noncanonical_owner_unit_order",
                    record.record_id,
                    "ownership record units are not in canonical order",
                ))
            seen_claims: set[str] = set()
            for claim in record.units:
                if claim.unit_id in seen_claims:
                    issues.add(_issue(
                        CompletionStatusV2.VIOLATED,
                        "duplicate_unit_claim",
                        claim.unit_id,
                        "one ownership record claims the same unit more than once",
                    ))
                seen_claims.add(claim.unit_id)
                expected = expected_by_id.get(claim.unit_id)
                if expected is None:
                    issues.add(_issue(
                        CompletionStatusV2.VIOLATED,
                        "unknown_unit_claim",
                        claim.unit_id,
                        "ownership record claims a unit outside the exact universe",
                    ))
                    continue
                if claim != expected:
                    issues.add(_issue(
                        CompletionStatusV2.VIOLATED,
                        "stale_unit_claim",
                        claim.unit_id,
                        "ownership record unit identity is stale or contradictory",
                    ))
                    continue
                valid_claims.setdefault(claim.unit_id, set()).add(record.record_id)

            owner = record.owner
            if owner.kind is ImplementationOwnerKindV2.UNASSIGNED:
                if owner.implementation is not None or owner.qualification is not None:
                    issues.add(_issue(
                        CompletionStatusV2.VIOLATED,
                        "unassigned_owner_has_evidence",
                        record.record_id,
                        "unassigned ownership cannot bind implementation evidence",
                    ))
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "unit_owner_unassigned",
                    record.record_id,
                    "claimed units do not yet have an implementation owner",
                ))
            else:
                if owner.implementation is None:
                    issues.add(_issue(
                        CompletionStatusV2.INCOMPLETE,
                        "implementation_identity_missing",
                        record.record_id,
                        "implementation owner lacks an implementation identity",
                    ))
                if owner.qualification is None:
                    issues.add(_issue(
                        CompletionStatusV2.INCOMPLETE,
                        "qualification_identity_missing",
                        record.record_id,
                        "implementation owner lacks qualification evidence",
                    ))
            if (
                self.profile
                in {
                    CompletionProfileV2.PORTABLE_APPLICATION,
                    CompletionProfileV2.VALIDATION_QUALIFIED,
                }
                and owner.kind is ImplementationOwnerKindV2.MACHINE_IR_FALLBACK
            ):
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "machine_ir_fallback_forbidden",
                    record.record_id,
                    "portable completion requires replacing machine-IR fallback",
                ))

        for record_id, count in records_by_id.items():
            if count > 1:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "duplicate_ownership_record",
                    record_id,
                    "the same ownership record occurs more than once",
                ))
        for unit_id in sorted(expected_by_id):
            claimers = valid_claims.get(unit_id, set())
            if not claimers:
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "structural_unit_owner_missing",
                    unit_id,
                    "structural unit has no exact implementation owner",
                ))
            elif len(claimers) > 1:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "structural_unit_owner_overlap",
                    unit_id,
                    "structural unit is claimed by multiple implementation owners",
                ))

        return tuple(
            sorted(
                issues,
                key=lambda item: (
                    item.status.value,
                    item.code,
                    item.location,
                    item.detail,
                ),
            )
        )

    @property
    def status(self) -> CompletionStatusV2:
        return _derive_status(self.issues)

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": IMPLEMENTATION_LEDGER_V2_FORMAT,
            "schema_version": IMPLEMENTATION_LEDGER_V2_SCHEMA_VERSION,
            "profile": self.profile.value,
            "status": self.status.value,
            "binary": self.binary.to_payload(),
            "exact_unit_inventory_sha256": self.exact_unit_inventory_sha256,
            "structural_units": [unit.to_payload() for unit in self.structural_units],
            "ownership_records": [
                record.to_payload() for record in self.ownership_records
            ],
            "issues": [issue.to_payload() for issue in self.issues],
        }

    @cached_property
    def ledger_id(self) -> str:
        return _content_id("implementation-ledger-v2", self._core_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._core_payload(), "ledger_id": self.ledger_id}

    def to_json(self) -> str:
        return canonical_json(self.to_payload())

    @cached_property
    def artifact_identity(self) -> ArtifactIdentityV2:
        payload = self.to_payload()
        return ArtifactIdentityV2(
            artifact_kind="implementation-ledger-v2",
            artifact_id=self.ledger_id,
            sha256=_content_sha256(payload),
        )

    def to_binding(self) -> ImplementationLedgerBindingV2:
        requirements = {
            OwnerQualificationRequirementV2(
                owner_kind=record.owner.kind,
                qualification=record.owner.qualification,
            )
            for record in self.ownership_records
            if record.owner.kind is not ImplementationOwnerKindV2.UNASSIGNED
            and record.owner.qualification is not None
        }
        return ImplementationLedgerBindingV2(
            identity=self.artifact_identity,
            profile=self.profile,
            status=self.status,
            binary=self.binary,
            exact_unit_inventory_sha256=self.exact_unit_inventory_sha256,
            structural_unit_count=len(self.structural_units),
            ownership_record_count=len(self.ownership_records),
            qualification_requirements=tuple(
                sorted(
                    requirements,
                    key=lambda item: (
                        item.owner_kind.value,
                        item.qualification,
                    ),
                )
            ),
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "ImplementationLedgerV2":
        row = _object(
            value,
            {
                "format",
                "schema_version",
                "ledger_id",
                "profile",
                "status",
                "binary",
                "exact_unit_inventory_sha256",
                "structural_units",
                "ownership_records",
                "issues",
            },
            "implementation-ledger-v2",
        )
        if (
            row["format"] != IMPLEMENTATION_LEDGER_V2_FORMAT
            or row["schema_version"] != IMPLEMENTATION_LEDGER_V2_SCHEMA_VERSION
        ):
            raise AuthorityDataError("only implementation-ledger-v2 is authorizing")
        result = cls(
            profile=_profile(row["profile"], "implementation-ledger-v2"),
            binary=BinaryBinding.parse(row["binary"]),
            exact_unit_inventory_sha256=_sha256(
                row["exact_unit_inventory_sha256"],
                "implementation-ledger exact-unit inventory SHA-256",
            ),
            structural_units=tuple(
                UnitBinding.parse(item)
                for item in _array(row["structural_units"], "structural units")
            ),
            ownership_records=tuple(
                UnitOwnershipRecordV2.parse(item)
                for item in _array(row["ownership_records"], "ownership records")
            ),
        )
        observed = _json_value(value, context="implementation-ledger-v2")
        if result.to_payload() != observed:
            raise AuthorityDataError(
                "implementation-ledger status, issues, ordering, or ID is stale"
            )
        return result


__all__ = [
    "IMPLEMENTATION_LEDGER_V2_FORMAT",
    "ArtifactIdentityV2",
    "CompletionProfileV2",
    "CompletionStatusV2",
    "ImplementationLedgerBindingV2",
    "ImplementationLedgerV2",
    "ImplementationOwnerKindV2",
    "ImplementationOwnerV2",
    "LedgerIssueV2",
    "OwnerQualificationRequirementV2",
    "UnitOwnershipRecordV2",
    "structural_unit_inventory_sha256_v2",
]
