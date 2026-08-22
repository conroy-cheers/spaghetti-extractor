"""Canonical, architecture-neutral physical ABI records.

The physical call boundary is deliberately separate from portable source types
and from memory/resource effects.  These records describe only how machine
values cross a call boundary and which machine state the caller may rely on.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    ABI_ANALYSIS_BUNDLE_FORMAT,
    ABI_EVIDENCE_FORMAT,
    ABI_FACT_SET_FORMAT,
    BOUNDARY_EFFECTS_FORMAT,
    PHYSICAL_ABI_CERTIFICATE_FORMAT,
    PORTABLE_PROTOTYPE_FORMAT,
    REVIEWED_ABI_ASSUMPTION_FORMAT,
)


ABI_STATUSES = frozenset({"complete", "incomplete", "violated"})
FACT_STATUSES = frozenset({"unknown", "exact", "alternatives", "contradiction"})
SUBJECT_KINDS = frozenset(
    {"function", "import", "callback", "table_slot", "callsite", "library_member"}
)
LOCATION_KINDS = frozenset({"register", "stack", "memory", "none"})
VALUE_ROLES = frozenset(
    {"ordinary", "this", "hidden_sret", "callback", "variadic_control"}
)
CALLING_CONVENTIONS = frozenset(
    {"cdecl", "stdcall", "thiscall", "fastcall", "vectorcall", "custom"}
)
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class AbiModelError(ValueError):
    """A canonical ABI record is malformed, stale, or contradictory."""


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def stable_id(namespace: str, value: object) -> str:
    return f"{namespace}:{canonical_sha256(value)}"


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AbiModelError(f"{label} must be an object")
    return value


def _exact(row: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(row) != fields:
        raise AbiModelError(
            f"{label} fields differ: missing={sorted(fields - set(row))!r}, "
            f"extra={sorted(set(row) - fields)!r}"
        )


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or _ID.fullmatch(value) is None:
        raise AbiModelError(f"{label} is not a canonical identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AbiModelError(f"{label} is not a lowercase SHA-256")
    return value


def _uint(value: object, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise AbiModelError(f"{label} must be an integer >= {minimum}")
    return value


def _signed_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AbiModelError(f"{label} must be an integer")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AbiModelError(f"{label} must be an array")
    result = tuple(_text(item, label) for item in value)
    if result != tuple(sorted(set(result))):
        raise AbiModelError(f"{label} must be sorted and unique")
    return result


def _canonical_values(value: object, label: str) -> tuple[Any, ...]:
    if not isinstance(value, list):
        raise AbiModelError(f"{label} must be an array")
    encoded = sorted({canonical_json_bytes(item) for item in value})
    return tuple(json.loads(item) for item in encoded)


@dataclass(frozen=True, order=True)
class AbiTargetV1:
    architecture: str
    bitness: int
    object_format: str
    pointer_width_bits: int
    byte_order: str = "little"

    def __post_init__(self) -> None:
        _text(self.architecture, "ABI target architecture")
        _uint(self.bitness, "ABI target bitness", minimum=1)
        _text(self.object_format, "ABI target object format")
        _uint(self.pointer_width_bits, "ABI target pointer width", minimum=1)
        if self.byte_order not in {"little", "big"}:
            raise AbiModelError("ABI target byte order is unsupported")

    def to_payload(self) -> dict[str, object]:
        return {
            "architecture": self.architecture,
            "bitness": self.bitness,
            "object_format": self.object_format,
            "pointer_width_bits": self.pointer_width_bits,
            "byte_order": self.byte_order,
        }

    @classmethod
    def parse(cls, value: object) -> "AbiTargetV1":
        row = _mapping(value, "ABI target")
        _exact(
            row,
            {
                "architecture",
                "bitness",
                "object_format",
                "pointer_width_bits",
                "byte_order",
            },
            "ABI target",
        )
        return cls(
            _text(row["architecture"], "ABI target architecture"),
            _uint(row["bitness"], "ABI target bitness", minimum=1),
            _text(row["object_format"], "ABI target object format"),
            _uint(row["pointer_width_bits"], "ABI target pointer width", minimum=1),
            str(row["byte_order"]),
        )


@dataclass(frozen=True, order=True)
class AbiLocationV1:
    kind: str
    width_bits: int
    value_bit_offset: int = 0
    register: str | None = None
    stack_offset: int | None = None
    memory_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in LOCATION_KINDS:
            raise AbiModelError(f"unsupported ABI location kind {self.kind!r}")
        _uint(self.width_bits, "ABI location width", minimum=1)
        _uint(self.value_bit_offset, "ABI location value bit offset")
        coordinates = (self.register, self.stack_offset, self.memory_id)
        if self.kind == "register":
            _text(self.register, "ABI register")
            if self.stack_offset is not None or self.memory_id is not None:
                raise AbiModelError("register ABI location has unrelated coordinates")
        elif self.kind == "stack":
            if not isinstance(self.stack_offset, int) or isinstance(
                self.stack_offset, bool
            ):
                raise AbiModelError("stack ABI location needs an integer offset")
            if self.register is not None or self.memory_id is not None:
                raise AbiModelError("stack ABI location has unrelated coordinates")
        elif self.kind == "memory":
            _text(self.memory_id, "ABI memory identity")
            if self.register is not None or self.stack_offset is not None:
                raise AbiModelError("memory ABI location has unrelated coordinates")
        elif any(item is not None for item in coordinates):
            raise AbiModelError("none ABI location cannot have coordinates")

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "width_bits": self.width_bits,
            "value_bit_offset": self.value_bit_offset,
            "register": self.register,
            "stack_offset": self.stack_offset,
            "memory_id": self.memory_id,
        }

    @classmethod
    def parse(cls, value: object) -> "AbiLocationV1":
        row = _mapping(value, "ABI location")
        _exact(
            row,
            {
                "kind",
                "width_bits",
                "value_bit_offset",
                "register",
                "stack_offset",
                "memory_id",
            },
            "ABI location",
        )
        return cls(
            kind=str(row["kind"]),
            width_bits=_uint(row["width_bits"], "ABI location width", minimum=1),
            value_bit_offset=_uint(
                row["value_bit_offset"], "ABI location value bit offset"
            ),
            register=(
                None
                if row["register"] is None
                else _text(row["register"], "ABI register")
            ),
            stack_offset=(
                None
                if row["stack_offset"] is None
                else _signed_integer(row["stack_offset"], "ABI stack offset")
            ),
            memory_id=(
                None
                if row["memory_id"] is None
                else _text(row["memory_id"], "ABI memory identity")
            ),
        )


@dataclass(frozen=True, order=True)
class AbiValueV1:
    value_id: str
    width_bits: int
    role: str
    fragments: tuple[AbiLocationV1, ...]
    callback_abi_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.value_id, "ABI value ID")
        _uint(self.width_bits, "ABI value width", minimum=1)
        if self.role not in VALUE_ROLES:
            raise AbiModelError(f"unsupported ABI value role {self.role!r}")
        if not self.fragments:
            raise AbiModelError("ABI value must have at least one fragment")
        occupied: list[tuple[int, int]] = []
        for fragment in self.fragments:
            end = fragment.value_bit_offset + fragment.width_bits
            if end > self.width_bits:
                raise AbiModelError("ABI fragment exceeds its logical value")
            occupied.append((fragment.value_bit_offset, end))
        occupied.sort()
        if any(right[0] < left[1] for left, right in zip(occupied, occupied[1:])):
            raise AbiModelError("ABI value fragments overlap")
        if self.callback_abi_id is not None:
            _text(self.callback_abi_id, "callback ABI ID")
        if self.role == "callback" and self.callback_abi_id is None:
            raise AbiModelError("callback ABI value lacks a callback ABI reference")
        if self.role != "callback" and self.callback_abi_id is not None:
            raise AbiModelError("non-callback ABI value has a callback ABI reference")

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.value_id,
            "width_bits": self.width_bits,
            "role": self.role,
            "fragments": [item.to_payload() for item in self.fragments],
            "callback_abi_id": self.callback_abi_id,
        }

    @classmethod
    def parse(cls, value: object) -> "AbiValueV1":
        row = _mapping(value, "ABI value")
        _exact(
            row,
            {
                "id",
                "width_bits",
                "role",
                "fragments",
                "callback_abi_id",
            },
            "ABI value",
        )
        fragments = row["fragments"]
        if not isinstance(fragments, list):
            raise AbiModelError("ABI value fragments must be an array")
        return cls(
            value_id=_text(row["id"], "ABI value ID"),
            width_bits=_uint(row["width_bits"], "ABI value width", minimum=1),
            role=str(row["role"]),
            fragments=tuple(AbiLocationV1.parse(item) for item in fragments),
            callback_abi_id=(
                None
                if row["callback_abi_id"] is None
                else _text(row["callback_abi_id"], "callback ABI ID")
            ),
        )


@dataclass(frozen=True, order=True)
class StackCleanupV1:
    kind: str
    bytes: int | None

    def __post_init__(self) -> None:
        if self.kind not in {"caller", "callee", "none", "custom"}:
            raise AbiModelError(f"unsupported stack cleanup {self.kind!r}")
        if self.bytes is not None:
            _uint(self.bytes, "stack cleanup bytes")
        if self.kind in {"caller", "none"} and self.bytes not in {None, 0}:
            raise AbiModelError("caller/none stack cleanup cannot pop positive bytes")
        if self.kind == "callee" and self.bytes is None:
            raise AbiModelError("callee stack cleanup requires an exact byte count")

    def to_payload(self) -> dict[str, object]:
        return {"kind": self.kind, "bytes": self.bytes}

    @classmethod
    def parse(cls, value: object) -> "StackCleanupV1":
        row = _mapping(value, "stack cleanup")
        _exact(row, {"kind", "bytes"}, "stack cleanup")
        return cls(str(row["kind"]), None if row["bytes"] is None else int(row["bytes"]))


@dataclass(frozen=True, order=True)
class VariadicPolicyV1:
    kind: str
    fixed_argument_count: int
    control_argument_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"none", "c_varargs", "format", "sentinel"}:
            raise AbiModelError(f"unsupported variadic policy {self.kind!r}")
        _uint(self.fixed_argument_count, "fixed argument count")
        if self.control_argument_id is not None:
            _text(self.control_argument_id, "variadic control argument ID")
        if self.kind in {"format", "sentinel"} and self.control_argument_id is None:
            raise AbiModelError("controlled variadic policy lacks its control argument")
        if self.kind in {"none", "c_varargs"} and self.control_argument_id is not None:
            raise AbiModelError("uncontrolled variadic policy names a control argument")

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "fixed_argument_count": self.fixed_argument_count,
            "control_argument_id": self.control_argument_id,
        }

    @classmethod
    def parse(cls, value: object) -> "VariadicPolicyV1":
        row = _mapping(value, "variadic policy")
        _exact(
            row,
            {"kind", "fixed_argument_count", "control_argument_id"},
            "variadic policy",
        )
        return cls(
            str(row["kind"]),
            _uint(row["fixed_argument_count"], "fixed argument count"),
            None
            if row["control_argument_id"] is None
            else _text(row["control_argument_id"], "variadic control argument ID"),
        )


@dataclass(frozen=True)
class PhysicalAbiProfileV1:
    profile_id: str
    target: AbiTargetV1
    calling_convention: str
    stack_coordinate: str
    stack_alignment_bytes: int
    arguments: tuple[AbiValueV1, ...]
    results: tuple[AbiValueV1, ...]
    stack_cleanup: StackCleanupV1
    variadic: VariadicPolicyV1
    preserved_state: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.profile_id, "physical ABI profile ID")
        if self.calling_convention not in CALLING_CONVENTIONS:
            raise AbiModelError(
                f"unsupported calling convention {self.calling_convention!r}"
            )
        if self.stack_coordinate != "callee_entry_esp_v1":
            raise AbiModelError("unsupported ABI stack coordinate system")
        _uint(self.stack_alignment_bytes, "ABI stack alignment", minimum=1)
        argument_ids = tuple(item.value_id for item in self.arguments)
        result_ids = tuple(item.value_id for item in self.results)
        if len(set(argument_ids)) != len(argument_ids):
            raise AbiModelError("ABI argument IDs are duplicated")
        if len(set(result_ids)) != len(result_ids):
            raise AbiModelError("ABI result IDs are duplicated")
        if self.variadic.fixed_argument_count > len(self.arguments):
            raise AbiModelError("variadic fixed prefix exceeds declared arguments")
        if self.variadic.kind == "none" and self.variadic.fixed_argument_count != len(
            self.arguments
        ):
            raise AbiModelError("nonvariadic profile fixed count is not total arity")
        if self.preserved_state != tuple(sorted(set(self.preserved_state))):
            raise AbiModelError("preserved state must be sorted and unique")
        for value in self.preserved_state:
            _text(value, "preserved machine state")

    @property
    def core_payload(self) -> dict[str, object]:
        return {
            "id": self.profile_id,
            "target": self.target.to_payload(),
            "calling_convention": self.calling_convention,
            "stack_coordinate": self.stack_coordinate,
            "stack_alignment_bytes": self.stack_alignment_bytes,
            "arguments": [item.to_payload() for item in self.arguments],
            "results": [item.to_payload() for item in self.results],
            "stack_cleanup": self.stack_cleanup.to_payload(),
            "variadic": self.variadic.to_payload(),
            "preserved_state": list(self.preserved_state),
        }

    @classmethod
    def create(
        cls,
        *,
        target: AbiTargetV1,
        calling_convention: str,
        arguments: Sequence[AbiValueV1],
        results: Sequence[AbiValueV1],
        stack_cleanup: StackCleanupV1,
        variadic: VariadicPolicyV1,
        preserved_state: Sequence[str],
        stack_alignment_bytes: int = 4,
    ) -> "PhysicalAbiProfileV1":
        body = {
            "target": target.to_payload(),
            "calling_convention": calling_convention,
            "stack_coordinate": "callee_entry_esp_v1",
            "stack_alignment_bytes": stack_alignment_bytes,
            "arguments": [item.to_payload() for item in arguments],
            "results": [item.to_payload() for item in results],
            "stack_cleanup": stack_cleanup.to_payload(),
            "variadic": variadic.to_payload(),
            "preserved_state": sorted(set(preserved_state)),
        }
        return cls(
            profile_id=stable_id("physical-abi-profile-v1", body),
            target=target,
            calling_convention=calling_convention,
            stack_coordinate="callee_entry_esp_v1",
            stack_alignment_bytes=stack_alignment_bytes,
            arguments=tuple(arguments),
            results=tuple(results),
            stack_cleanup=stack_cleanup,
            variadic=variadic,
            preserved_state=tuple(sorted(set(preserved_state))),
        )

    def to_payload(self) -> dict[str, object]:
        return self.core_payload

    @classmethod
    def parse(cls, value: object) -> "PhysicalAbiProfileV1":
        row = _mapping(value, "physical ABI profile")
        _exact(
            row,
            {
                "id",
                "target",
                "calling_convention",
                "stack_coordinate",
                "stack_alignment_bytes",
                "arguments",
                "results",
                "stack_cleanup",
                "variadic",
                "preserved_state",
            },
            "physical ABI profile",
        )
        arguments = row["arguments"]
        results = row["results"]
        if not isinstance(arguments, list) or not isinstance(results, list):
            raise AbiModelError("ABI arguments and results must be arrays")
        result = cls(
            profile_id=_text(row["id"], "physical ABI profile ID"),
            target=AbiTargetV1.parse(row["target"]),
            calling_convention=str(row["calling_convention"]),
            stack_coordinate=str(row["stack_coordinate"]),
            stack_alignment_bytes=_uint(
                row["stack_alignment_bytes"], "ABI stack alignment", minimum=1
            ),
            arguments=tuple(AbiValueV1.parse(item) for item in arguments),
            results=tuple(AbiValueV1.parse(item) for item in results),
            stack_cleanup=StackCleanupV1.parse(row["stack_cleanup"]),
            variadic=VariadicPolicyV1.parse(row["variadic"]),
            preserved_state=_strings(row["preserved_state"], "preserved state"),
        )
        expected = PhysicalAbiProfileV1.create(
            target=result.target,
            calling_convention=result.calling_convention,
            arguments=result.arguments,
            results=result.results,
            stack_cleanup=result.stack_cleanup,
            variadic=result.variadic,
            preserved_state=result.preserved_state,
            stack_alignment_bytes=result.stack_alignment_bytes,
        )
        if result.profile_id != expected.profile_id:
            raise AbiModelError("physical ABI profile ID does not bind its contents")
        return result


@dataclass(frozen=True, order=True)
class AbiEvidenceV1:
    evidence_id: str
    kind: str
    producer: str
    subject_kind: str
    subject_id: str
    binary_sha256: str | None
    dependencies: tuple[str, ...]
    payload: Mapping[str, Any]

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        producer: str,
        subject_kind: str,
        subject_id: str,
        payload: Mapping[str, Any],
        binary_sha256: str | None = None,
        dependencies: Iterable[str] = (),
    ) -> "AbiEvidenceV1":
        if subject_kind not in SUBJECT_KINDS:
            raise AbiModelError(f"unsupported ABI subject kind {subject_kind!r}")
        core = {
            "format": ABI_EVIDENCE_FORMAT,
            "kind": _text(kind, "ABI evidence kind"),
            "producer": _text(producer, "ABI evidence producer"),
            "subject": {"kind": subject_kind, "id": _text(subject_id, "ABI subject ID")},
            "binary_sha256": (
                None
                if binary_sha256 is None
                else _digest(binary_sha256, "ABI evidence binary SHA-256")
            ),
            "dependencies": sorted(set(dependencies)),
            "payload": json.loads(canonical_json_bytes(payload)),
        }
        return cls(
            evidence_id=stable_id("abi-evidence-v1", core),
            kind=str(core["kind"]),
            producer=str(core["producer"]),
            subject_kind=subject_kind,
            subject_id=subject_id,
            binary_sha256=core["binary_sha256"],
            dependencies=tuple(core["dependencies"]),
            payload=core["payload"],
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": ABI_EVIDENCE_FORMAT,
            "id": self.evidence_id,
            "kind": self.kind,
            "producer": self.producer,
            "subject": {"kind": self.subject_kind, "id": self.subject_id},
            "binary_sha256": self.binary_sha256,
            "dependencies": list(self.dependencies),
            "payload": json.loads(canonical_json_bytes(self.payload)),
        }

    @classmethod
    def parse(cls, value: object) -> "AbiEvidenceV1":
        row = _mapping(value, "ABI evidence")
        _exact(
            row,
            {
                "format",
                "id",
                "kind",
                "producer",
                "subject",
                "binary_sha256",
                "dependencies",
                "payload",
            },
            "ABI evidence",
        )
        if row["format"] != ABI_EVIDENCE_FORMAT:
            raise AbiModelError("ABI evidence format is unsupported")
        subject = _mapping(row["subject"], "ABI evidence subject")
        _exact(subject, {"kind", "id"}, "ABI evidence subject")
        dependencies = _strings(row["dependencies"], "ABI evidence dependencies")
        payload = _mapping(row["payload"], "ABI evidence payload")
        result = cls.create(
            kind=_text(row["kind"], "ABI evidence kind"),
            producer=_text(row["producer"], "ABI evidence producer"),
            subject_kind=str(subject["kind"]),
            subject_id=_text(subject["id"], "ABI evidence subject ID"),
            binary_sha256=(
                None
                if row["binary_sha256"] is None
                else _digest(row["binary_sha256"], "ABI evidence binary SHA-256")
            ),
            dependencies=dependencies,
            payload=payload,
        )
        if result.evidence_id != _text(row["id"], "ABI evidence ID"):
            raise AbiModelError("ABI evidence ID does not bind its contents")
        return result


@dataclass(frozen=True, order=True)
class AbiFactV1:
    subject_id: str
    field: str
    status: str
    values: tuple[Any, ...]
    evidence_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.subject_id, "ABI fact subject ID")
        _text(self.field, "ABI fact field")
        if self.status not in FACT_STATUSES:
            raise AbiModelError(f"unsupported ABI fact status {self.status!r}")
        canonical = tuple(
            json.loads(item)
            for item in sorted({canonical_json_bytes(value) for value in self.values})
        )
        if canonical != self.values:
            raise AbiModelError("ABI fact values must be canonical and unique")
        expected_counts = {
            "unknown": 0,
            "exact": 1,
            "contradiction": 0,
        }
        if self.status in expected_counts and len(self.values) != expected_counts[self.status]:
            raise AbiModelError(f"ABI fact {self.status} has invalid value count")
        if self.status == "alternatives" and len(self.values) < 2:
            raise AbiModelError("ABI alternatives fact needs at least two values")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise AbiModelError("ABI fact evidence IDs must be sorted and unique")
        if self.dependency_ids != tuple(sorted(set(self.dependency_ids))):
            raise AbiModelError("ABI fact dependencies must be sorted and unique")

    @classmethod
    def create(
        cls,
        *,
        subject_id: str,
        field: str,
        status: str,
        values: Iterable[object] = (),
        evidence_ids: Iterable[str] = (),
        dependency_ids: Iterable[str] = (),
    ) -> "AbiFactV1":
        canonical_values = tuple(
            json.loads(item)
            for item in sorted({canonical_json_bytes(value) for value in values})
        )
        return cls(
            subject_id,
            field,
            status,
            canonical_values,
            tuple(sorted(set(evidence_ids))),
            tuple(sorted(set(dependency_ids))),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "subject_id": self.subject_id,
            "field": self.field,
            "status": self.status,
            "values": list(self.values),
            "evidence_ids": list(self.evidence_ids),
            "dependency_ids": list(self.dependency_ids),
        }

    @classmethod
    def parse(cls, value: object) -> "AbiFactV1":
        row = _mapping(value, "ABI fact")
        _exact(
            row,
            {
                "subject_id",
                "field",
                "status",
                "values",
                "evidence_ids",
                "dependency_ids",
            },
            "ABI fact",
        )
        return cls.create(
            subject_id=_text(row["subject_id"], "ABI fact subject ID"),
            field=_text(row["field"], "ABI fact field"),
            status=str(row["status"]),
            values=_canonical_values(row["values"], "ABI fact values"),
            evidence_ids=_strings(row["evidence_ids"], "ABI fact evidence IDs"),
            dependency_ids=_strings(row["dependency_ids"], "ABI fact dependencies"),
        )


@dataclass(frozen=True)
class PhysicalAbiCertificateV1:
    certificate_id: str
    status: str
    subject_kind: str
    subject_id: str
    profile: PhysicalAbiProfileV1 | None
    facts: tuple[AbiFactV1, ...]
    reviewed_assumption_ids: tuple[str, ...]
    issues: tuple[Mapping[str, Any], ...]
    dependency_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        status: str,
        subject_kind: str,
        subject_id: str,
        profile: PhysicalAbiProfileV1 | None,
        facts: Iterable[AbiFactV1],
        reviewed_assumption_ids: Iterable[str] = (),
        issues: Iterable[Mapping[str, Any]] = (),
        dependency_ids: Iterable[str] = (),
    ) -> "PhysicalAbiCertificateV1":
        if status not in ABI_STATUSES:
            raise AbiModelError(f"unsupported ABI certificate status {status!r}")
        if subject_kind not in SUBJECT_KINDS:
            raise AbiModelError(f"unsupported ABI subject kind {subject_kind!r}")
        ordered_facts = tuple(sorted(facts, key=lambda item: item.field))
        if len({item.field for item in ordered_facts}) != len(ordered_facts):
            raise AbiModelError("ABI certificate has duplicate fact fields")
        if any(item.subject_id != subject_id for item in ordered_facts):
            raise AbiModelError("ABI certificate contains a fact for another subject")
        if status == "complete" and profile is None:
            raise AbiModelError("complete ABI certificate lacks a physical profile")
        if status != "complete" and profile is not None:
            raise AbiModelError("non-complete ABI certificate cannot expose a profile")
        ordered_issues = tuple(
            json.loads(item)
            for item in sorted({canonical_json_bytes(issue) for issue in issues})
        )
        core = {
            "format": PHYSICAL_ABI_CERTIFICATE_FORMAT,
            "status": status,
            "subject": {"kind": subject_kind, "id": subject_id},
            "profile": None if profile is None else profile.to_payload(),
            "facts": [item.to_payload() for item in ordered_facts],
            "reviewed_assumption_ids": sorted(set(reviewed_assumption_ids)),
            "issues": list(ordered_issues),
            "dependency_ids": sorted(set(dependency_ids)),
        }
        return cls(
            certificate_id=stable_id("physical-abi-certificate-v1", core),
            status=status,
            subject_kind=subject_kind,
            subject_id=subject_id,
            profile=profile,
            facts=ordered_facts,
            reviewed_assumption_ids=tuple(core["reviewed_assumption_ids"]),
            issues=ordered_issues,
            dependency_ids=tuple(core["dependency_ids"]),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PHYSICAL_ABI_CERTIFICATE_FORMAT,
            "id": self.certificate_id,
            "status": self.status,
            "subject": {"kind": self.subject_kind, "id": self.subject_id},
            "profile": None if self.profile is None else self.profile.to_payload(),
            "facts": [item.to_payload() for item in self.facts],
            "reviewed_assumption_ids": list(self.reviewed_assumption_ids),
            "issues": list(self.issues),
            "dependency_ids": list(self.dependency_ids),
        }

    def write(self, path: Path | str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(self.to_payload()) + b"\n")

    @classmethod
    def parse(cls, value: object) -> "PhysicalAbiCertificateV1":
        row = _mapping(value, "physical ABI certificate")
        _exact(
            row,
            {
                "format",
                "id",
                "status",
                "subject",
                "profile",
                "facts",
                "reviewed_assumption_ids",
                "issues",
                "dependency_ids",
            },
            "physical ABI certificate",
        )
        if row["format"] != PHYSICAL_ABI_CERTIFICATE_FORMAT:
            raise AbiModelError("physical ABI certificate format is unsupported")
        subject = _mapping(row["subject"], "physical ABI certificate subject")
        _exact(subject, {"kind", "id"}, "physical ABI certificate subject")
        raw_facts = row["facts"]
        raw_issues = row["issues"]
        if not isinstance(raw_facts, list) or not isinstance(raw_issues, list):
            raise AbiModelError("physical ABI certificate facts/issues must be arrays")
        result = cls.create(
            status=str(row["status"]),
            subject_kind=str(subject["kind"]),
            subject_id=_text(subject["id"], "physical ABI certificate subject ID"),
            profile=(
                None
                if row["profile"] is None
                else PhysicalAbiProfileV1.parse(row["profile"])
            ),
            facts=tuple(AbiFactV1.parse(item) for item in raw_facts),
            reviewed_assumption_ids=_strings(
                row["reviewed_assumption_ids"], "reviewed ABI assumption IDs"
            ),
            issues=tuple(_mapping(item, "physical ABI issue") for item in raw_issues),
            dependency_ids=_strings(row["dependency_ids"], "ABI certificate dependencies"),
        )
        if result.certificate_id != _text(row["id"], "physical ABI certificate ID"):
            raise AbiModelError("physical ABI certificate ID does not bind its contents")
        return result


@dataclass(frozen=True)
class ReviewedAbiAssumptionV1:
    """A content-bound operator fact that cannot override contradictory evidence."""

    assumption_id: str
    subject_kind: str
    subject_id: str
    facts: tuple[AbiFactV1, ...]
    rationale: str
    reviewer: str
    binary_sha256: str | None = None

    @classmethod
    def create(
        cls,
        *,
        subject_kind: str,
        subject_id: str,
        facts: Iterable[AbiFactV1],
        rationale: str,
        reviewer: str,
        binary_sha256: str | None = None,
    ) -> "ReviewedAbiAssumptionV1":
        if subject_kind not in SUBJECT_KINDS:
            raise AbiModelError(f"unsupported ABI subject kind {subject_kind!r}")
        ordered = tuple(sorted(facts, key=lambda item: item.field))
        if not ordered or len({item.field for item in ordered}) != len(ordered):
            raise AbiModelError("reviewed ABI assumption needs unique facts")
        if any(item.subject_id != subject_id for item in ordered):
            raise AbiModelError("reviewed ABI assumption contains another subject")
        if any(item.status not in {"exact", "alternatives"} for item in ordered):
            raise AbiModelError("reviewed ABI assumptions must state finite values")
        if not isinstance(rationale, str) or not rationale.strip():
            raise AbiModelError("reviewed ABI assumption rationale must be nonempty")
        core = {
            "format": REVIEWED_ABI_ASSUMPTION_FORMAT,
            "subject": {"kind": subject_kind, "id": subject_id},
            "facts": [item.to_payload() for item in ordered],
            "rationale": rationale,
            "reviewer": _text(reviewer, "ABI assumption reviewer"),
            "binary_sha256": (
                None
                if binary_sha256 is None
                else _digest(binary_sha256, "ABI assumption binary SHA-256")
            ),
        }
        return cls(
            stable_id("reviewed-abi-assumption-v1", core),
            subject_kind,
            subject_id,
            ordered,
            rationale,
            reviewer,
            core["binary_sha256"],
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": REVIEWED_ABI_ASSUMPTION_FORMAT,
            "id": self.assumption_id,
            "subject": {"kind": self.subject_kind, "id": self.subject_id},
            "facts": [item.to_payload() for item in self.facts],
            "rationale": self.rationale,
            "reviewer": self.reviewer,
            "binary_sha256": self.binary_sha256,
        }

    @classmethod
    def parse(cls, value: object) -> "ReviewedAbiAssumptionV1":
        row = _mapping(value, "reviewed ABI assumption")
        _exact(
            row,
            {"format", "id", "subject", "facts", "rationale", "reviewer", "binary_sha256"},
            "reviewed ABI assumption",
        )
        if row["format"] != REVIEWED_ABI_ASSUMPTION_FORMAT:
            raise AbiModelError("reviewed ABI assumption format is unsupported")
        subject = _mapping(row["subject"], "reviewed ABI assumption subject")
        _exact(subject, {"kind", "id"}, "reviewed ABI assumption subject")
        raw_facts = row["facts"]
        if not isinstance(raw_facts, list):
            raise AbiModelError("reviewed ABI assumption facts must be an array")
        result = cls.create(
            subject_kind=str(subject["kind"]),
            subject_id=_text(subject["id"], "reviewed ABI assumption subject ID"),
            facts=tuple(AbiFactV1.parse(item) for item in raw_facts),
            rationale=str(row["rationale"]),
            reviewer=str(row["reviewer"]),
            binary_sha256=(
                None
                if row["binary_sha256"] is None
                else _digest(row["binary_sha256"], "ABI assumption binary SHA-256")
            ),
        )
        if result.assumption_id != _text(row["id"], "reviewed ABI assumption ID"):
            raise AbiModelError("reviewed ABI assumption ID does not bind its contents")
        return result


@dataclass(frozen=True)
class PortablePrototypeV1:
    """Optional source-level naming and type metadata for a physical ABI."""

    prototype_id: str
    subject_id: str
    physical_profile_id: str
    symbol: str
    return_type: str
    parameter_types: tuple[str, ...]
    parameter_names: tuple[str, ...]
    variadic: bool
    dependency_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        subject_id: str,
        physical_profile_id: str,
        symbol: str,
        return_type: str,
        parameter_types: Sequence[str],
        parameter_names: Sequence[str],
        variadic: bool,
        dependency_ids: Iterable[str] = (),
    ) -> "PortablePrototypeV1":
        if len(parameter_types) != len(parameter_names):
            raise AbiModelError("portable prototype parameter inventories disagree")
        if not all(isinstance(item, str) and item for item in parameter_types):
            raise AbiModelError("portable prototype has an empty parameter type")
        if not all(isinstance(item, str) and item for item in parameter_names):
            raise AbiModelError("portable prototype has an empty parameter name")
        if not isinstance(symbol, str) or not symbol:
            raise AbiModelError("portable prototype symbol must be nonempty")
        if not isinstance(return_type, str) or not return_type:
            raise AbiModelError("portable prototype return type must be nonempty")
        core = {
            "format": PORTABLE_PROTOTYPE_FORMAT,
            "subject_id": _text(subject_id, "portable prototype subject"),
            "physical_profile_id": _text(
                physical_profile_id, "portable prototype physical profile"
            ),
            "symbol": symbol,
            "return_type": return_type,
            "parameter_types": list(parameter_types),
            "parameter_names": list(parameter_names),
            "variadic": bool(variadic),
            "dependency_ids": sorted(set(dependency_ids)),
        }
        return cls(
            stable_id("portable-prototype-v1", core),
            subject_id,
            physical_profile_id,
            symbol,
            return_type,
            tuple(parameter_types),
            tuple(parameter_names),
            bool(variadic),
            tuple(core["dependency_ids"]),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PORTABLE_PROTOTYPE_FORMAT,
            "id": self.prototype_id,
            "subject_id": self.subject_id,
            "physical_profile_id": self.physical_profile_id,
            "symbol": self.symbol,
            "return_type": self.return_type,
            "parameter_types": list(self.parameter_types),
            "parameter_names": list(self.parameter_names),
            "variadic": self.variadic,
            "dependency_ids": list(self.dependency_ids),
        }

    @classmethod
    def parse(cls, value: object) -> "PortablePrototypeV1":
        row = _mapping(value, "portable prototype")
        _exact(
            row,
            {
                "format",
                "id",
                "subject_id",
                "physical_profile_id",
                "symbol",
                "return_type",
                "parameter_types",
                "parameter_names",
                "variadic",
                "dependency_ids",
            },
            "portable prototype",
        )
        if row["format"] != PORTABLE_PROTOTYPE_FORMAT:
            raise AbiModelError("portable prototype format is unsupported")
        parameter_types = row["parameter_types"]
        parameter_names = row["parameter_names"]
        if not isinstance(parameter_types, list) or not isinstance(
            parameter_names, list
        ):
            raise AbiModelError("portable prototype parameters must be arrays")
        if not isinstance(row["variadic"], bool):
            raise AbiModelError("portable prototype variadic flag must be Boolean")
        result = cls.create(
            subject_id=_text(row["subject_id"], "portable prototype subject"),
            physical_profile_id=_text(
                row["physical_profile_id"], "portable prototype physical profile"
            ),
            symbol=str(row["symbol"]),
            return_type=str(row["return_type"]),
            parameter_types=tuple(str(item) for item in parameter_types),
            parameter_names=tuple(str(item) for item in parameter_names),
            variadic=row["variadic"],
            dependency_ids=_strings(
                row["dependency_ids"], "portable prototype dependencies"
            ),
        )
        if result.prototype_id != _text(row["id"], "portable prototype ID"):
            raise AbiModelError("portable prototype ID does not bind its contents")
        return result


@dataclass(frozen=True)
class BoundaryEffectsV1:
    """Call effects kept separate from value transport and source types."""

    effects_id: str
    subject_id: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    resource_actions: tuple[str, ...]
    callback_actions: tuple[str, ...]
    dependency_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        subject_id: str,
        reads: Iterable[str] = (),
        writes: Iterable[str] = (),
        resource_actions: Iterable[str] = (),
        callback_actions: Iterable[str] = (),
        dependency_ids: Iterable[str] = (),
    ) -> "BoundaryEffectsV1":
        core = {
            "format": BOUNDARY_EFFECTS_FORMAT,
            "subject_id": _text(subject_id, "boundary-effects subject"),
            "reads": sorted(set(reads)),
            "writes": sorted(set(writes)),
            "resource_actions": sorted(set(resource_actions)),
            "callback_actions": sorted(set(callback_actions)),
            "dependency_ids": sorted(set(dependency_ids)),
        }
        for field in ("reads", "writes", "resource_actions", "callback_actions"):
            for value in core[field]:
                _text(value, f"boundary effect {field}")
        return cls(
            stable_id("boundary-effects-v1", core),
            subject_id,
            tuple(core["reads"]),
            tuple(core["writes"]),
            tuple(core["resource_actions"]),
            tuple(core["callback_actions"]),
            tuple(core["dependency_ids"]),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": BOUNDARY_EFFECTS_FORMAT,
            "id": self.effects_id,
            "subject_id": self.subject_id,
            "reads": list(self.reads),
            "writes": list(self.writes),
            "resource_actions": list(self.resource_actions),
            "callback_actions": list(self.callback_actions),
            "dependency_ids": list(self.dependency_ids),
        }

    @classmethod
    def parse(cls, value: object) -> "BoundaryEffectsV1":
        row = _mapping(value, "boundary effects")
        _exact(
            row,
            {
                "format",
                "id",
                "subject_id",
                "reads",
                "writes",
                "resource_actions",
                "callback_actions",
                "dependency_ids",
            },
            "boundary effects",
        )
        if row["format"] != BOUNDARY_EFFECTS_FORMAT:
            raise AbiModelError("boundary-effects format is unsupported")
        result = cls.create(
            subject_id=_text(row["subject_id"], "boundary-effects subject"),
            reads=_strings(row["reads"], "boundary-effect reads"),
            writes=_strings(row["writes"], "boundary-effect writes"),
            resource_actions=_strings(
                row["resource_actions"], "boundary-effect resource actions"
            ),
            callback_actions=_strings(
                row["callback_actions"], "boundary-effect callback actions"
            ),
            dependency_ids=_strings(
                row["dependency_ids"], "boundary-effect dependencies"
            ),
        )
        if result.effects_id != _text(row["id"], "boundary-effects ID"):
            raise AbiModelError("boundary-effects ID does not bind its contents")
        return result


PE32_TARGET_V1 = AbiTargetV1("x86", 32, "pe32", 32)


__all__ = [
    "ABI_EVIDENCE_FORMAT",
    "ABI_ANALYSIS_BUNDLE_FORMAT",
    "ABI_FACT_SET_FORMAT",
    "BOUNDARY_EFFECTS_FORMAT",
    "PHYSICAL_ABI_CERTIFICATE_FORMAT",
    "PORTABLE_PROTOTYPE_FORMAT",
    "AbiEvidenceV1",
    "AbiFactV1",
    "AbiLocationV1",
    "AbiModelError",
    "AbiTargetV1",
    "AbiValueV1",
    "BoundaryEffectsV1",
    "PE32_TARGET_V1",
    "PhysicalAbiCertificateV1",
    "PhysicalAbiProfileV1",
    "PortablePrototypeV1",
    "ReviewedAbiAssumptionV1",
    "StackCleanupV1",
    "VariadicPolicyV1",
    "canonical_json_bytes",
    "canonical_sha256",
    "stable_id",
]
