"""Immutable checked records that can activate portable component source."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import CanonicalValueV3, canonical_sha256_v3
from .formats import (
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
)


class ComponentLifecycleRecordError(ValueError):
    """A source-activation record is malformed or self-contradictory."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ComponentLifecycleRecordError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentLifecycleRecordError(f"{context} must be a nonempty string")
    return value


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ComponentLifecycleRecordError(f"{context} must be a SHA-256 digest")
    return result


def _version(value: object, context: str) -> str | int:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ComponentLifecycleRecordError(
        f"{context} must be a nonempty string or nonnegative integer"
    )


def _canonical_rows(values: object, context: str) -> tuple[CanonicalValueV3, ...]:
    if not isinstance(values, list):
        raise ComponentLifecycleRecordError(f"{context} must be an array")
    return tuple(CanonicalValueV3.of(value) for value in values)


@dataclass(frozen=True)
class QualificationBindingsV3:
    contract_sha256: str
    implementation_sha256: str
    machine_ir_sha256: str
    domain_sha256: str
    adapter_plan_sha256: str
    evidence_sha256: str
    source_entry: CanonicalValueV3
    tool_id: str
    tool_version: str | int

    @classmethod
    def parse(cls, value: object) -> "QualificationBindingsV3":
        row = _object(
            value,
            {
                "contract_sha256",
                "implementation_sha256",
                "machine_ir_sha256",
                "domain_sha256",
                "adapter_plan_sha256",
                "evidence_sha256",
                "source_entry",
                "tool_id",
                "tool_version",
            },
            "component qualification bindings",
        )
        return cls(
            contract_sha256=_digest(row["contract_sha256"], "contract digest"),
            implementation_sha256=_digest(
                row["implementation_sha256"], "implementation digest"
            ),
            machine_ir_sha256=_digest(row["machine_ir_sha256"], "machine-IR digest"),
            domain_sha256=_digest(row["domain_sha256"], "domain digest"),
            adapter_plan_sha256=_digest(
                row["adapter_plan_sha256"], "adapter-plan digest"
            ),
            evidence_sha256=_digest(row["evidence_sha256"], "evidence digest"),
            source_entry=CanonicalValueV3.of(row["source_entry"]),
            tool_id=_text(row["tool_id"], "evidence tool id"),
            tool_version=_version(row["tool_version"], "evidence tool version"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "contract_sha256": self.contract_sha256,
            "implementation_sha256": self.implementation_sha256,
            "machine_ir_sha256": self.machine_ir_sha256,
            "domain_sha256": self.domain_sha256,
            "adapter_plan_sha256": self.adapter_plan_sha256,
            "evidence_sha256": self.evidence_sha256,
            "source_entry": self.source_entry.to_value(),
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
        }


@dataclass(frozen=True)
class ComponentQualificationRecordV3:
    status: str
    lift_unit_id: str
    evidence_profile: str
    bindings: QualificationBindingsV3
    assurance: CanonicalValueV3
    authorized: bool
    issues: tuple[CanonicalValueV3, ...]
    qualification_sha256: str

    @classmethod
    def create(
        cls,
        *,
        status: str,
        lift_unit_id: str,
        evidence_profile: str,
        bindings: object,
        assurance: object,
        issues: Sequence[object],
    ) -> "ComponentQualificationRecordV3":
        core = {
            "format": COMPONENT_QUALIFICATION_V3_FORMAT,
            "status": status,
            "lift_unit_id": lift_unit_id,
            "evidence_profile": evidence_profile,
            "bindings": bindings,
            "assurance": assurance,
            "activation": {
                "authorized": status == "qualified",
                "requires_exact_configuration_ownership": True,
                "fallback_on_unimplemented": False,
            },
            "issues": list(issues),
        }
        return cls.parse({**core, "qualification_sha256": canonical_sha256_v3(core)})

    @classmethod
    def parse(cls, value: object) -> "ComponentQualificationRecordV3":
        row = _object(
            value,
            {
                "format",
                "status",
                "lift_unit_id",
                "evidence_profile",
                "bindings",
                "assurance",
                "activation",
                "issues",
                "qualification_sha256",
            },
            "component qualification",
        )
        if row["format"] != COMPONENT_QUALIFICATION_V3_FORMAT:
            raise ComponentLifecycleRecordError("unsupported component qualification format")
        status = _text(row["status"], "component qualification status")
        if status not in {"qualified", "incomplete", "violated"}:
            raise ComponentLifecycleRecordError("invalid component qualification status")
        activation = _object(
            row["activation"],
            {
                "authorized",
                "requires_exact_configuration_ownership",
                "fallback_on_unimplemented",
            },
            "component qualification activation",
        )
        authorized = activation["authorized"]
        if (
            not isinstance(authorized, bool)
            or authorized is not (status == "qualified")
            or activation["requires_exact_configuration_ownership"] is not True
            or activation["fallback_on_unimplemented"] is not False
        ):
            raise ComponentLifecycleRecordError(
                "component qualification activation contradicts its status"
            )
        issues = _canonical_rows(row["issues"], "component qualification issues")
        if (status == "qualified") != (not issues):
            raise ComponentLifecycleRecordError(
                "component qualification issues contradict its status"
            )
        core = dict(row)
        observed = _digest(core.pop("qualification_sha256"), "qualification digest")
        if observed != canonical_sha256_v3(core):
            raise ComponentLifecycleRecordError("component qualification self-hash is stale")
        return cls(
            status=status,
            lift_unit_id=_text(row["lift_unit_id"], "lift-unit id"),
            evidence_profile=_text(row["evidence_profile"], "evidence profile"),
            bindings=QualificationBindingsV3.parse(row["bindings"]),
            assurance=CanonicalValueV3.of(row["assurance"]),
            authorized=authorized,
            issues=issues,
            qualification_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": COMPONENT_QUALIFICATION_V3_FORMAT,
            "status": self.status,
            "lift_unit_id": self.lift_unit_id,
            "evidence_profile": self.evidence_profile,
            "bindings": self.bindings.to_payload(),
            "assurance": self.assurance.to_value(),
            "activation": {
                "authorized": self.authorized,
                "requires_exact_configuration_ownership": True,
                "fallback_on_unimplemented": False,
            },
            "issues": [row.to_value() for row in self.issues],
            "qualification_sha256": self.qualification_sha256,
        }


@dataclass(frozen=True)
class ActivationEntryV3:
    unit_id: str
    rva: int
    implementation_kind: str
    dispatch_lookup: str | None
    selected_owner: CanonicalValueV3

    @classmethod
    def parse(cls, value: object) -> "ActivationEntryV3":
        row = _object(
            value,
            {"unit_id", "rva", "implementation_kind", "dispatch_lookup", "selected_owner"},
            "component activation entry",
        )
        kind = _text(row["implementation_kind"], "implementation kind")
        if kind not in {"portable_replacement", "machine_ir_fallback", "blocked"}:
            raise ComponentLifecycleRecordError("invalid component implementation kind")
        rva = row["rva"]
        if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
            raise ComponentLifecycleRecordError("component activation RVA is invalid")
        dispatch = row["dispatch_lookup"]
        if dispatch is not None and not isinstance(dispatch, str):
            raise ComponentLifecycleRecordError("component dispatch lookup is invalid")
        expected_dispatch = (
            "spx_region_override_lookup"
            if kind == "portable_replacement"
            else "spx_program_lookup"
            if kind == "machine_ir_fallback"
            else None
        )
        if dispatch != expected_dispatch:
            raise ComponentLifecycleRecordError(
                "component dispatch lookup contradicts implementation ownership"
            )
        return cls(
            unit_id=_text(row["unit_id"], "activation unit id"),
            rva=rva,
            implementation_kind=kind,
            dispatch_lookup=dispatch,
            selected_owner=CanonicalValueV3.of(row["selected_owner"]),
        )


@dataclass(frozen=True)
class ComponentActivationPlanRecordV3:
    status: str
    configuration_id: str
    bindings: CanonicalValueV3
    policy: CanonicalValueV3
    ownership: CanonicalValueV3
    hybrid: CanonicalValueV3
    selections: tuple[CanonicalValueV3, ...]
    entries: tuple[ActivationEntryV3, ...]
    counts: CanonicalValueV3
    issues: tuple[CanonicalValueV3, ...]
    activation_plan_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ComponentActivationPlanRecordV3":
        row = _object(
            value,
            {
                "format",
                "status",
                "configuration_id",
                "bindings",
                "policy",
                "ownership",
                "hybrid",
                "selections",
                "entries",
                "counts",
                "issues",
                "activation_plan_sha256",
            },
            "component activation plan",
        )
        if row["format"] != COMPONENT_ACTIVATION_PLAN_V3_FORMAT:
            raise ComponentLifecycleRecordError("unsupported component activation format")
        status = _text(row["status"], "component activation status")
        if status not in {"checked", "incomplete", "violated"}:
            raise ComponentLifecycleRecordError("invalid component activation status")
        entries_raw = row["entries"]
        if not isinstance(entries_raw, list):
            raise ComponentLifecycleRecordError("component activation entries must be an array")
        entries = tuple(ActivationEntryV3.parse(item) for item in entries_raw)
        unit_ids = [entry.unit_id for entry in entries]
        if len(unit_ids) != len(set(unit_ids)):
            raise ComponentLifecycleRecordError(
                "component activation entries must be unique"
            )
        if list(entries) != sorted(entries, key=lambda entry: (entry.rva, entry.unit_id)):
            raise ComponentLifecycleRecordError(
                "component activation entries must be ordered by RVA and unit id"
            )
        issues = _canonical_rows(row["issues"], "component activation issues")
        core = dict(row)
        observed = _digest(core.pop("activation_plan_sha256"), "activation-plan digest")
        if observed != canonical_sha256_v3(core):
            raise ComponentLifecycleRecordError("component activation self-hash is stale")
        if status == "checked" and (
            issues or any(entry.implementation_kind == "blocked" for entry in entries)
        ):
            raise ComponentLifecycleRecordError(
                "checked component activation contains blocked ownership"
            )
        return cls(
            status=status,
            configuration_id=_text(row["configuration_id"], "configuration id"),
            bindings=CanonicalValueV3.of(row["bindings"]),
            policy=CanonicalValueV3.of(row["policy"]),
            ownership=CanonicalValueV3.of(row["ownership"]),
            hybrid=CanonicalValueV3.of(row["hybrid"]),
            selections=_canonical_rows(row["selections"], "component selections"),
            entries=entries,
            counts=CanonicalValueV3.of(row["counts"]),
            issues=issues,
            activation_plan_sha256=observed,
        )


__all__ = [
    "ActivationEntryV3",
    "ComponentActivationPlanRecordV3",
    "ComponentLifecycleRecordError",
    "ComponentQualificationRecordV3",
    "QualificationBindingsV3",
]
