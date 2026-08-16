"""Immutable records for ABI-first linked-library recognition.

The records in this module are the file boundary between independently cached
recognition phases.  Decoders reject unknown and missing schema fields.  Lack
of analysis evidence is represented by an ``incomplete`` issue in a phase
artifact; malformed records are never interpreted as incomplete evidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Generic, Iterable, Mapping, TypeVar

from ..artifacts.formats import (
    LIBRARY_ABI_CATALOG_V3_FORMAT as ABI_CATALOG_V3_FORMAT,
    LIBRARY_CATALOG_SEARCH_INDEX_V3_FORMAT as CATALOG_SEARCH_INDEX_V3_FORMAT,
    LIBRARY_CONSTELLATION_HYPOTHESES_V3_FORMAT as CONSTELLATION_HYPOTHESES_V3_FORMAT,
    LIBRARY_TARGET_SIGNATURE_GRAPH_V3_FORMAT as TARGET_SIGNATURE_GRAPH_V3_FORMAT,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STATUSES = frozenset({"complete", "incomplete", "violated"})
_ISSUE_STATUSES = frozenset({"incomplete", "violated"})
_CALLING_CONVENTIONS = frozenset(
    {"cdecl", "stdcall", "thiscall", "fastcall", "vectorcall", "custom"}
)
_STACK_CLEANUP_KINDS = frozenset({"caller", "callee", "none", "custom"})
_LOCATION_KINDS = frozenset({"register", "stack", "memory", "none"})
_VARIADIC_KINDS = frozenset({"none", "c_varargs", "format", "sentinel"})
_EDGE_KINDS = frozenset(
    {
        "call",
        "callback",
        "data",
        "global",
        "resource",
    }
)
_DIRECTIONS = frozenset({"inbound", "outbound"})


class LibraryAbiError(ValueError):
    """An ABI-first artifact is malformed, stale, or contradictory."""

    def __init__(self, code: str, message: str, *, location: str) -> None:
        super().__init__(f"{location}: {message}")
        self.code = code
        self.location = location


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def canonical_sha256(value: object) -> str:
    return sha256(canonical_json_bytes(value)).hexdigest()


def stable_id(namespace: str, value: object) -> str:
    return f"{namespace}:{canonical_sha256(value)}"


def _fail(code: str, message: str, location: str) -> None:
    raise LibraryAbiError(code, message, location=location)


def _object(
    value: object,
    required: Iterable[str],
    optional: Iterable[str],
    location: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("record_type_mismatch", "expected an object", location)
    keys = set(value)
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - keys)
    unknown = sorted(keys - allowed)
    if missing:
        _fail("record_fields_missing", f"missing fields {missing!r}", location)
    if unknown:
        _fail("record_fields_unknown", f"unknown fields {unknown!r}", location)
    return value


def _array(value: object, location: str) -> tuple[Any, ...]:
    if not isinstance(value, list):
        _fail("record_type_mismatch", "expected an array", location)
    return tuple(value)


def _text(value: object, location: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("record_type_mismatch", "expected a nonempty string", location)
    return value


def _optional_text(value: object, location: str) -> str | None:
    return None if value is None else _text(value, location)


def _integer(value: object, location: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail("record_type_mismatch", "expected an integer", location)
    if minimum is not None and value < minimum:
        _fail("record_value_invalid", f"must be at least {minimum}", location)
    return value


def _boolean(value: object, location: str) -> bool:
    if not isinstance(value, bool):
        _fail("record_type_mismatch", "expected a Boolean", location)
    return value


def _sha256(value: object, location: str) -> str:
    result = _text(value, location)
    if not _SHA256_RE.fullmatch(result):
        _fail("record_value_invalid", "expected a lowercase SHA-256", location)
    return result


def _optional_sha256(value: object, location: str) -> str | None:
    return None if value is None else _sha256(value, location)


def _texts(value: object, location: str) -> tuple[str, ...]:
    result = tuple(_text(item, f"{location}[{index}]") for index, item in enumerate(_array(value, location)))
    if tuple(sorted(set(result))) != result:
        _fail(
            "record_order_invalid",
            "strings must be unique and canonically sorted",
            location,
        )
    return result


def _integers(value: object, location: str) -> tuple[int, ...]:
    result = tuple(
        _integer(item, f"{location}[{index}]")
        for index, item in enumerate(_array(value, location))
    )
    if tuple(sorted(set(result))) != result:
        _fail(
            "record_order_invalid",
            "integers must be unique and canonically sorted",
            location,
        )
    return result


def _check_choice(value: str, choices: frozenset[str], location: str) -> str:
    if value not in choices:
        _fail("record_value_invalid", f"unsupported value {value!r}", location)
    return value


def phase_status(issues: Iterable["LibraryIssueV3"]) -> str:
    statuses = {issue.status for issue in issues}
    if "violated" in statuses:
        return "violated"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


T = TypeVar("T")


@dataclass(frozen=True)
class StrictCodec(Generic[T]):
    """Small strict codec used by both file and in-memory phase APIs."""

    encode: Callable[[T], dict[str, Any]]
    decode: Callable[[object, str], T]

    def dumps(self, value: T) -> bytes:
        return canonical_json_bytes(self.encode(value)) + b"\n"

    def loads(self, data: bytes | str, *, location: str = "record") -> T:
        try:
            raw = json.loads(data)
        except (TypeError, ValueError) as error:
            raise LibraryAbiError(
                "invalid_json", str(error), location=location
            ) from error
        return self.decode(raw, location)

    def read(self, path: Path | str) -> T:
        source = Path(path)
        try:
            data = source.read_bytes()
        except OSError as error:
            raise LibraryAbiError(
                "artifact_read_failed", str(error), location=str(source)
            ) from error
        return self.loads(data, location=str(source))

    def write(self, path: Path | str, value: T) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(self.dumps(value))


@dataclass(frozen=True, order=True)
class LibraryIssueV3:
    status: str
    code: str
    message: str
    location: str

    def __post_init__(self) -> None:
        _check_choice(self.status, _ISSUE_STATUSES, "library issue.status")
        _text(self.code, "library issue.code")
        _text(self.message, "library issue.message")
        _text(self.location, "library issue.location")

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "code": self.code,
            "message": self.message,
            "location": self.location,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryIssueV3":
        row = _object(value, {"status", "code", "message", "location"}, {}, location)
        return cls(
            _text(row["status"], f"{location}.status"),
            _text(row["code"], f"{location}.code"),
            _text(row["message"], f"{location}.message"),
            _text(row["location"], f"{location}.location"),
        )


@dataclass(frozen=True, order=True)
class ValueLocationV3:
    kind: str
    width_bits: int
    register: str | None = None
    stack_offset: int | None = None
    memory_id: str | None = None

    def __post_init__(self) -> None:
        _check_choice(self.kind, _LOCATION_KINDS, "value location.kind")
        _integer(self.width_bits, "value location.width_bits", minimum=1)
        if self.kind == "register":
            _text(self.register, "value location.register")
            if self.stack_offset is not None or self.memory_id is not None:
                _fail("record_value_invalid", "register location has unrelated coordinates", "value location")
        elif self.kind == "stack":
            _integer(self.stack_offset, "value location.stack_offset")
            if self.register is not None or self.memory_id is not None:
                _fail("record_value_invalid", "stack location has unrelated coordinates", "value location")
        elif self.kind == "memory":
            _text(self.memory_id, "value location.memory_id")
            if self.register is not None or self.stack_offset is not None:
                _fail("record_value_invalid", "memory location has unrelated coordinates", "value location")
        elif any(value is not None for value in (self.register, self.stack_offset, self.memory_id)):
            _fail("record_value_invalid", "none location has coordinates", "value location")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "width_bits": self.width_bits,
            "register": self.register,
            "stack_offset": self.stack_offset,
            "memory_id": self.memory_id,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "ValueLocationV3":
        row = _object(value, {"kind", "width_bits", "register", "stack_offset", "memory_id"}, {}, location)
        return cls(
            kind=_text(row["kind"], f"{location}.kind"),
            width_bits=_integer(row["width_bits"], f"{location}.width_bits", minimum=1),
            register=_optional_text(row["register"], f"{location}.register"),
            stack_offset=(None if row["stack_offset"] is None else _integer(row["stack_offset"], f"{location}.stack_offset")),
            memory_id=_optional_text(row["memory_id"], f"{location}.memory_id"),
        )


@dataclass(frozen=True, order=True)
class StackCleanupV3:
    kind: str
    bytes: int | None

    def __post_init__(self) -> None:
        _check_choice(self.kind, _STACK_CLEANUP_KINDS, "stack cleanup.kind")
        if self.bytes is not None:
            _integer(self.bytes, "stack cleanup.bytes", minimum=0)
        if self.kind in {"none", "caller"} and self.bytes not in {None, 0}:
            _fail("record_value_invalid", "caller/none cleanup cannot declare positive callee bytes", "stack cleanup")

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "bytes": self.bytes}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "StackCleanupV3":
        row = _object(value, {"kind", "bytes"}, {}, location)
        return cls(
            _text(row["kind"], f"{location}.kind"),
            None if row["bytes"] is None else _integer(row["bytes"], f"{location}.bytes", minimum=0),
        )


@dataclass(frozen=True, order=True)
class VariadicPolicyV3:
    kind: str
    fixed_arguments: int
    control_argument: int | None

    def __post_init__(self) -> None:
        _check_choice(self.kind, _VARIADIC_KINDS, "variadic policy.kind")
        _integer(self.fixed_arguments, "variadic policy.fixed_arguments", minimum=0)
        if self.kind in {"format", "sentinel"}:
            _integer(self.control_argument, "variadic policy.control_argument", minimum=0)
        elif self.control_argument is not None:
            _fail("record_value_invalid", "non-controlled variadic policy has a control argument", "variadic policy")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "fixed_arguments": self.fixed_arguments,
            "control_argument": self.control_argument,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "VariadicPolicyV3":
        row = _object(value, {"kind", "fixed_arguments", "control_argument"}, {}, location)
        return cls(
            kind=_text(row["kind"], f"{location}.kind"),
            fixed_arguments=_integer(row["fixed_arguments"], f"{location}.fixed_arguments", minimum=0),
            control_argument=(None if row["control_argument"] is None else _integer(row["control_argument"], f"{location}.control_argument", minimum=0)),
        )


@dataclass(frozen=True, order=True)
class CallbackSlotV3:
    argument_index: int
    abi_profile_id: str
    nullable: bool

    def __post_init__(self) -> None:
        _integer(self.argument_index, "callback slot.argument_index", minimum=0)
        _text(self.abi_profile_id, "callback slot.abi_profile_id")
        _boolean(self.nullable, "callback slot.nullable")

    def to_payload(self) -> dict[str, Any]:
        return {
            "argument_index": self.argument_index,
            "abi_profile_id": self.abi_profile_id,
            "nullable": self.nullable,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "CallbackSlotV3":
        row = _object(value, {"argument_index", "abi_profile_id", "nullable"}, {}, location)
        return cls(
            _integer(row["argument_index"], f"{location}.argument_index", minimum=0),
            _text(row["abi_profile_id"], f"{location}.abi_profile_id"),
            _boolean(row["nullable"], f"{location}.nullable"),
        )


@dataclass(frozen=True, order=True)
class BoundaryEffectV3:
    kind: str
    subject: str
    access: str

    def __post_init__(self) -> None:
        _text(self.kind, "boundary effect.kind")
        _text(self.subject, "boundary effect.subject")
        _check_choice(self.access, frozenset({"read", "write", "read_write", "create", "release", "invoke", "register"}), "boundary effect.access")

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "subject": self.subject, "access": self.access}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "BoundaryEffectV3":
        row = _object(value, {"kind", "subject", "access"}, {}, location)
        return cls(
            _text(row["kind"], f"{location}.kind"),
            _text(row["subject"], f"{location}.subject"),
            _text(row["access"], f"{location}.access"),
        )


@dataclass(frozen=True, order=True)
class LibraryAbiProfileV3:
    profile_id: str
    architecture: str
    object_format: str
    calling_convention: str
    stack_cleanup: StackCleanupV3
    arguments: tuple[ValueLocationV3, ...]
    returns: tuple[ValueLocationV3, ...]
    hidden_sret: bool
    variadic: VariadicPolicyV3
    preserved_registers: tuple[str, ...]
    callback_slots: tuple[CallbackSlotV3, ...]
    structure_layout_ids: tuple[str, ...]
    boundary_effects: tuple[BoundaryEffectV3, ...]

    def __post_init__(self) -> None:
        _text(self.profile_id, "ABI profile.id")
        _text(self.architecture, "ABI profile.architecture")
        _text(self.object_format, "ABI profile.object_format")
        _check_choice(self.calling_convention, _CALLING_CONVENTIONS, "ABI profile.calling_convention")
        if tuple(sorted(set(self.preserved_registers))) != self.preserved_registers:
            _fail("record_order_invalid", "preserved registers must be sorted and unique", "ABI profile.preserved_registers")
        if tuple(sorted(set(self.structure_layout_ids))) != self.structure_layout_ids:
            _fail("record_order_invalid", "structure layout IDs must be sorted and unique", "ABI profile.structure_layout_ids")
        callback_indexes = tuple(slot.argument_index for slot in self.callback_slots)
        if tuple(sorted(set(callback_indexes))) != callback_indexes:
            _fail("record_order_invalid", "callback slots must have sorted unique argument indexes", "ABI profile.callback_slots")
        if self.hidden_sret and not self.arguments:
            _fail("record_value_invalid", "hidden sret requires a concrete argument location", "ABI profile.hidden_sret")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.profile_id,
            "architecture": self.architecture,
            "object_format": self.object_format,
            "calling_convention": self.calling_convention,
            "stack_cleanup": self.stack_cleanup.to_payload(),
            "arguments": [item.to_payload() for item in self.arguments],
            "returns": [item.to_payload() for item in self.returns],
            "hidden_sret": self.hidden_sret,
            "variadic": self.variadic.to_payload(),
            "preserved_registers": list(self.preserved_registers),
            "callback_slots": [item.to_payload() for item in self.callback_slots],
            "structure_layout_ids": list(self.structure_layout_ids),
            "boundary_effects": [item.to_payload() for item in self.boundary_effects],
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryAbiProfileV3":
        row = _object(
            value,
            {"id", "architecture", "object_format", "calling_convention", "stack_cleanup", "arguments", "returns", "hidden_sret", "variadic", "preserved_registers", "callback_slots", "structure_layout_ids", "boundary_effects"},
            {},
            location,
        )
        return cls(
            profile_id=_text(row["id"], f"{location}.id"),
            architecture=_text(row["architecture"], f"{location}.architecture"),
            object_format=_text(row["object_format"], f"{location}.object_format"),
            calling_convention=_text(row["calling_convention"], f"{location}.calling_convention"),
            stack_cleanup=StackCleanupV3.from_payload(row["stack_cleanup"], f"{location}.stack_cleanup"),
            arguments=tuple(ValueLocationV3.from_payload(item, f"{location}.arguments[{index}]") for index, item in enumerate(_array(row["arguments"], f"{location}.arguments"))),
            returns=tuple(ValueLocationV3.from_payload(item, f"{location}.returns[{index}]") for index, item in enumerate(_array(row["returns"], f"{location}.returns"))),
            hidden_sret=_boolean(row["hidden_sret"], f"{location}.hidden_sret"),
            variadic=VariadicPolicyV3.from_payload(row["variadic"], f"{location}.variadic"),
            preserved_registers=_texts(row["preserved_registers"], f"{location}.preserved_registers"),
            callback_slots=tuple(CallbackSlotV3.from_payload(item, f"{location}.callback_slots[{index}]") for index, item in enumerate(_array(row["callback_slots"], f"{location}.callback_slots"))),
            structure_layout_ids=_texts(row["structure_layout_ids"], f"{location}.structure_layout_ids"),
            boundary_effects=tuple(BoundaryEffectV3.from_payload(item, f"{location}.boundary_effects[{index}]") for index, item in enumerate(_array(row["boundary_effects"], f"{location}.boundary_effects"))),
        )


@dataclass(frozen=True, order=True)
class LibraryFunctionSignatureV3:
    function_id: str
    catalog_id: str
    family_id: str
    release_id: str
    member_id: str
    symbols: tuple[str, ...]
    normalized_bytes_sha256: str | None
    exact_bytes_sha256: str | None
    unit_merkle_sha256: str | None
    cfg_sha256: str | None
    direct_callees: tuple[str, ...]
    imports: tuple[str, ...]
    constants: tuple[int, ...]
    strings: tuple[str, ...]
    data_refs: tuple[str, ...]
    abi_profile_id: str | None
    object_size: int | None
    masked_bytes_hex: str | None = None
    relocation_holes: tuple[tuple[int, int, str, str], ...] = ()
    fixed_bytes: int | None = None
    match_strength: str | None = None
    retention_model: str = "unknown"
    operation_id: str | None = None

    def __post_init__(self) -> None:
        for label, value in (("id", self.function_id), ("catalog_id", self.catalog_id), ("family_id", self.family_id), ("release_id", self.release_id), ("member_id", self.member_id)):
            _text(value, f"library function.{label}")
        if self.operation_id is not None:
            _text(self.operation_id, "library function.operation_id")
        for label, value in (("normalized_bytes_sha256", self.normalized_bytes_sha256), ("exact_bytes_sha256", self.exact_bytes_sha256), ("unit_merkle_sha256", self.unit_merkle_sha256), ("cfg_sha256", self.cfg_sha256)):
            if value is not None:
                _sha256(value, f"library function.{label}")
        for label, values in (("symbols", self.symbols), ("direct_callees", self.direct_callees), ("imports", self.imports), ("strings", self.strings), ("data_refs", self.data_refs)):
            if tuple(sorted(set(values))) != values:
                _fail("record_order_invalid", f"{label} must be sorted and unique", f"library function.{label}")
        if tuple(sorted(set(self.constants))) != self.constants:
            _fail("record_order_invalid", "constants must be sorted and unique", "library function.constants")
        if self.object_size is not None:
            _integer(self.object_size, "library function.object_size", minimum=1)
        masked: bytes | None = None
        if self.masked_bytes_hex is not None:
            try:
                masked = bytes.fromhex(self.masked_bytes_hex)
            except ValueError as error:
                raise LibraryAbiError(
                    "record_value_invalid",
                    "masked bytes must be lowercase hexadecimal",
                    location="library function.masked_bytes_hex",
                ) from error
            if self.masked_bytes_hex != masked.hex():
                _fail(
                    "record_value_invalid",
                    "masked bytes must be canonical lowercase hexadecimal",
                    "library function.masked_bytes_hex",
                )
            if self.object_size is not None and len(masked) > self.object_size:
                _fail(
                    "record_value_invalid",
                    "masked bytes exceed the containing object size",
                    "library function.masked_bytes_hex",
                )
        previous_end = 0
        for index, (offset, width, kind, target) in enumerate(self.relocation_holes):
            _integer(offset, f"library function.relocation_holes[{index}].offset", minimum=0)
            _integer(width, f"library function.relocation_holes[{index}].width", minimum=1)
            _text(kind, f"library function.relocation_holes[{index}].kind")
            _text(target, f"library function.relocation_holes[{index}].target")
            if offset < previous_end:
                _fail(
                    "record_order_invalid",
                    "relocation holes must be sorted and non-overlapping",
                    "library function.relocation_holes",
                )
            previous_end = offset + width
        if self.masked_bytes_hex is not None and previous_end > len(bytes.fromhex(self.masked_bytes_hex)):
            _fail(
                "record_value_invalid",
                "relocation hole exceeds masked function bytes",
                "library function.relocation_holes",
            )
        if self.fixed_bytes is not None:
            _integer(self.fixed_bytes, "library function.fixed_bytes", minimum=0)
            if masked is not None:
                hole_bytes = sum(width for _offset, width, _kind, _target in self.relocation_holes)
                if self.fixed_bytes != len(masked) - hole_bytes:
                    _fail(
                        "record_value_invalid",
                        "fixed-byte count disagrees with relocation holes",
                        "library function.fixed_bytes",
                    )
        if self.match_strength not in {None, "weak", "strong"}:
            _fail(
                "record_value_invalid",
                "match strength must be weak, strong, or null",
                "library function.match_strength",
            )
        if masked is not None and self.fixed_bytes is not None and self.match_strength is not None:
            expected_strength = (
                "strong"
                if self.fixed_bytes >= max(8, len(masked) // 4)
                else "weak"
            )
            if self.match_strength != expected_strength:
                _fail(
                    "record_value_invalid",
                    "match strength disagrees with fixed-byte evidence",
                    "library function.match_strength",
                )
        _check_choice(
            self.retention_model,
            frozenset({"unknown", "archive_member", "section_gc"}),
            "library function.retention_model",
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.function_id,
            "catalog_id": self.catalog_id,
            "family_id": self.family_id,
            "release_id": self.release_id,
            "member_id": self.member_id,
            "symbols": list(self.symbols),
            "normalized_bytes_sha256": self.normalized_bytes_sha256,
            "exact_bytes_sha256": self.exact_bytes_sha256,
            "unit_merkle_sha256": self.unit_merkle_sha256,
            "cfg_sha256": self.cfg_sha256,
            "direct_callees": list(self.direct_callees),
            "imports": list(self.imports),
            "constants": list(self.constants),
            "strings": list(self.strings),
            "data_refs": list(self.data_refs),
            "abi_profile_id": self.abi_profile_id,
            "object_size": self.object_size,
            "masked_bytes_hex": self.masked_bytes_hex,
            "relocation_holes": [
                {
                    "offset": offset,
                    "width": width,
                    "kind": kind,
                    "target": target,
                }
                for offset, width, kind, target in self.relocation_holes
            ],
            "fixed_bytes": self.fixed_bytes,
            "match_strength": self.match_strength,
            "retention_model": self.retention_model,
            "operation_id": self.operation_id,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryFunctionSignatureV3":
        fields = {"id", "catalog_id", "family_id", "release_id", "member_id", "symbols", "normalized_bytes_sha256", "exact_bytes_sha256", "unit_merkle_sha256", "cfg_sha256", "direct_callees", "imports", "constants", "strings", "data_refs", "abi_profile_id", "object_size"}
        optional = {"masked_bytes_hex", "relocation_holes", "fixed_bytes", "match_strength", "retention_model", "operation_id"}
        row = _object(value, fields, optional, location)
        holes = []
        for index, item in enumerate(_array(row.get("relocation_holes", []), f"{location}.relocation_holes")):
            hole = _object(item, {"offset", "width", "kind", "target"}, {}, f"{location}.relocation_holes[{index}]")
            holes.append(
                (
                    _integer(hole["offset"], f"{location}.relocation_holes[{index}].offset", minimum=0),
                    _integer(hole["width"], f"{location}.relocation_holes[{index}].width", minimum=1),
                    _text(hole["kind"], f"{location}.relocation_holes[{index}].kind"),
                    _text(hole["target"], f"{location}.relocation_holes[{index}].target"),
                )
            )
        return cls(
            function_id=_text(row["id"], f"{location}.id"),
            catalog_id=_text(row["catalog_id"], f"{location}.catalog_id"),
            family_id=_text(row["family_id"], f"{location}.family_id"),
            release_id=_text(row["release_id"], f"{location}.release_id"),
            member_id=_text(row["member_id"], f"{location}.member_id"),
            symbols=_texts(row["symbols"], f"{location}.symbols"),
            normalized_bytes_sha256=_optional_sha256(row["normalized_bytes_sha256"], f"{location}.normalized_bytes_sha256"),
            exact_bytes_sha256=_optional_sha256(row["exact_bytes_sha256"], f"{location}.exact_bytes_sha256"),
            unit_merkle_sha256=_optional_sha256(row["unit_merkle_sha256"], f"{location}.unit_merkle_sha256"),
            cfg_sha256=_optional_sha256(row["cfg_sha256"], f"{location}.cfg_sha256"),
            direct_callees=_texts(row["direct_callees"], f"{location}.direct_callees"),
            imports=_texts(row["imports"], f"{location}.imports"),
            constants=_integers(row["constants"], f"{location}.constants"),
            strings=_texts(row["strings"], f"{location}.strings"),
            data_refs=_texts(row["data_refs"], f"{location}.data_refs"),
            abi_profile_id=_optional_text(row["abi_profile_id"], f"{location}.abi_profile_id"),
            object_size=(None if row["object_size"] is None else _integer(row["object_size"], f"{location}.object_size", minimum=1)),
            masked_bytes_hex=_optional_text(row.get("masked_bytes_hex"), f"{location}.masked_bytes_hex"),
            relocation_holes=tuple(holes),
            fixed_bytes=(None if row.get("fixed_bytes") is None else _integer(row["fixed_bytes"], f"{location}.fixed_bytes", minimum=0)),
            match_strength=_optional_text(row.get("match_strength"), f"{location}.match_strength"),
            retention_model=_text(row.get("retention_model", "unknown"), f"{location}.retention_model"),
            operation_id=_optional_text(row.get("operation_id"), f"{location}.operation_id"),
        )


@dataclass(frozen=True, order=True)
class TargetFunctionSignatureV3:
    function_id: str
    candidate_kind: str
    unit_ids: tuple[str, ...]
    rva_start: int
    rva_end: int
    normalized_bytes_sha256: str | None
    exact_bytes_sha256: str | None
    unit_merkle_sha256: str
    cfg_sha256: str
    direct_call_rvas: tuple[int, ...]
    imports: tuple[str, ...]
    constants: tuple[int, ...]
    strings: tuple[str, ...]
    data_refs: tuple[str, ...]
    abi_profile: LibraryAbiProfileV3 | None
    bytes_hex: str | None = None

    def __post_init__(self) -> None:
        _text(self.function_id, "target function.id")
        _check_choice(self.candidate_kind, frozenset({"explicit_partition", "structural_cfg"}), "target function.candidate_kind")
        if not self.unit_ids or tuple(sorted(set(self.unit_ids))) != self.unit_ids:
            _fail("record_order_invalid", "unit IDs must be nonempty, sorted, and unique", "target function.unit_ids")
        _integer(self.rva_start, "target function.rva_start", minimum=0)
        _integer(self.rva_end, "target function.rva_end", minimum=1)
        if self.rva_end <= self.rva_start:
            _fail("record_value_invalid", "target function span is empty", "target function")
        if self.exact_bytes_sha256 is not None:
            _sha256(self.exact_bytes_sha256, "target function.exact_bytes_sha256")
        _sha256(self.unit_merkle_sha256, "target function.unit_merkle_sha256")
        _sha256(self.cfg_sha256, "target function.cfg_sha256")
        if self.normalized_bytes_sha256 is not None:
            _sha256(self.normalized_bytes_sha256, "target function.normalized_bytes_sha256")
        if self.bytes_hex is not None:
            try:
                raw_bytes = bytes.fromhex(self.bytes_hex)
            except ValueError as error:
                raise LibraryAbiError(
                    "record_value_invalid",
                    "target bytes must be lowercase hexadecimal",
                    location="target function.bytes_hex",
                ) from error
            if self.bytes_hex != raw_bytes.hex() or len(raw_bytes) != self.rva_end - self.rva_start:
                _fail(
                    "record_value_invalid",
                    "target bytes must canonically cover the exact function span",
                    "target function.bytes_hex",
                )
        for label, values in (("imports", self.imports), ("strings", self.strings), ("data_refs", self.data_refs)):
            if tuple(sorted(set(values))) != values:
                _fail("record_order_invalid", f"{label} must be sorted and unique", f"target function.{label}")
        if tuple(sorted(set(self.direct_call_rvas))) != self.direct_call_rvas or tuple(sorted(set(self.constants))) != self.constants:
            _fail("record_order_invalid", "numeric features must be sorted and unique", "target function")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.function_id,
            "candidate_kind": self.candidate_kind,
            "unit_ids": list(self.unit_ids),
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "normalized_bytes_sha256": self.normalized_bytes_sha256,
            "exact_bytes_sha256": self.exact_bytes_sha256,
            "unit_merkle_sha256": self.unit_merkle_sha256,
            "cfg_sha256": self.cfg_sha256,
            "direct_call_rvas": list(self.direct_call_rvas),
            "imports": list(self.imports),
            "constants": list(self.constants),
            "strings": list(self.strings),
            "data_refs": list(self.data_refs),
            "abi_profile": None if self.abi_profile is None else self.abi_profile.to_payload(),
            "bytes_hex": self.bytes_hex,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "TargetFunctionSignatureV3":
        fields = {"id", "candidate_kind", "unit_ids", "rva_start", "rva_end", "normalized_bytes_sha256", "exact_bytes_sha256", "unit_merkle_sha256", "cfg_sha256", "direct_call_rvas", "imports", "constants", "strings", "data_refs", "abi_profile"}
        row = _object(value, fields, {"bytes_hex"}, location)
        return cls(
            function_id=_text(row["id"], f"{location}.id"),
            candidate_kind=_text(row["candidate_kind"], f"{location}.candidate_kind"),
            unit_ids=_texts(row["unit_ids"], f"{location}.unit_ids"),
            rva_start=_integer(row["rva_start"], f"{location}.rva_start", minimum=0),
            rva_end=_integer(row["rva_end"], f"{location}.rva_end", minimum=1),
            normalized_bytes_sha256=_optional_sha256(row["normalized_bytes_sha256"], f"{location}.normalized_bytes_sha256"),
            exact_bytes_sha256=_optional_sha256(row["exact_bytes_sha256"], f"{location}.exact_bytes_sha256"),
            unit_merkle_sha256=_sha256(row["unit_merkle_sha256"], f"{location}.unit_merkle_sha256"),
            cfg_sha256=_sha256(row["cfg_sha256"], f"{location}.cfg_sha256"),
            direct_call_rvas=_integers(row["direct_call_rvas"], f"{location}.direct_call_rvas"),
            imports=_texts(row["imports"], f"{location}.imports"),
            constants=_integers(row["constants"], f"{location}.constants"),
            strings=_texts(row["strings"], f"{location}.strings"),
            data_refs=_texts(row["data_refs"], f"{location}.data_refs"),
            abi_profile=(None if row["abi_profile"] is None else LibraryAbiProfileV3.from_payload(row["abi_profile"], f"{location}.abi_profile")),
            bytes_hex=_optional_text(row.get("bytes_hex"), f"{location}.bytes_hex"),
        )


@dataclass(frozen=True, order=True)
class BehaviorBoundaryV3:
    boundary_id: str
    kind: str
    direction: str
    identity: str
    abi_profile_id: str | None
    required: bool

    def __post_init__(self) -> None:
        _text(self.boundary_id, "behavior boundary.id")
        _check_choice(self.kind, _EDGE_KINDS, "behavior boundary.kind")
        _check_choice(self.direction, _DIRECTIONS, "behavior boundary.direction")
        _text(self.identity, "behavior boundary.identity")
        if self.abi_profile_id is not None:
            _text(self.abi_profile_id, "behavior boundary.abi_profile_id")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.boundary_id,
            "kind": self.kind,
            "direction": self.direction,
            "identity": self.identity,
            "abi_profile_id": self.abi_profile_id,
            "required": self.required,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "BehaviorBoundaryV3":
        row = _object(value, {"id", "kind", "direction", "identity", "abi_profile_id", "required"}, {}, location)
        return cls(
            _text(row["id"], f"{location}.id"),
            _text(row["kind"], f"{location}.kind"),
            _text(row["direction"], f"{location}.direction"),
            _text(row["identity"], f"{location}.identity"),
            _optional_text(row["abi_profile_id"], f"{location}.abi_profile_id"),
            _boolean(row["required"], f"{location}.required"),
        )


@dataclass(frozen=True, order=True)
class CheckedQualificationV3:
    kind: str
    checker_id: str
    certificate_sha256: str
    behavior_entry_id: str
    hypothesis_id: str | None

    def __post_init__(self) -> None:
        _check_choice(self.kind, frozenset({"reusable_certificate", "target_local_refinement"}), "qualification.kind")
        _text(self.checker_id, "qualification.checker_id")
        _sha256(self.certificate_sha256, "qualification.certificate_sha256")
        _text(self.behavior_entry_id, "qualification.behavior_entry_id")
        if self.kind == "target_local_refinement":
            _text(self.hypothesis_id, "qualification.hypothesis_id")
        elif self.hypothesis_id is not None:
            _fail("record_value_invalid", "reusable qualification cannot bind one hypothesis", "qualification.hypothesis_id")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "checker_id": self.checker_id,
            "certificate_sha256": self.certificate_sha256,
            "behavior_entry_id": self.behavior_entry_id,
            "hypothesis_id": self.hypothesis_id,
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "CheckedQualificationV3":
        row = _object(value, {"kind", "checker_id", "certificate_sha256", "behavior_entry_id", "hypothesis_id"}, {}, location)
        return cls(
            _text(row["kind"], f"{location}.kind"),
            _text(row["checker_id"], f"{location}.checker_id"),
            _sha256(row["certificate_sha256"], f"{location}.certificate_sha256"),
            _text(row["behavior_entry_id"], f"{location}.behavior_entry_id"),
            _optional_text(row["hypothesis_id"], f"{location}.hypothesis_id"),
        )


@dataclass(frozen=True, order=True)
class LibraryBehaviorEntryV3:
    behavior_entry_id: str
    family_id: str
    compatible_releases: tuple[str, ...]
    abi_profile_ids: tuple[str, ...]
    portable_symbol: str
    portable_source_sha256: str
    boundaries: tuple[BehaviorBoundaryV3, ...]
    reusable_qualification: CheckedQualificationV3 | None

    def __post_init__(self) -> None:
        for label, value in (("id", self.behavior_entry_id), ("family_id", self.family_id), ("portable_symbol", self.portable_symbol)):
            _text(value, f"behavior entry.{label}")
        _sha256(self.portable_source_sha256, "behavior entry.portable_source_sha256")
        if tuple(sorted(set(self.compatible_releases))) != self.compatible_releases or tuple(sorted(set(self.abi_profile_ids))) != self.abi_profile_ids:
            _fail("record_order_invalid", "behavior compatibility sets must be sorted and unique", "behavior entry")
        boundary_ids = tuple(item.boundary_id for item in self.boundaries)
        if tuple(sorted(set(boundary_ids))) != boundary_ids:
            _fail("record_order_invalid", "behavior boundaries must have sorted unique IDs", "behavior entry.boundaries")
        if self.reusable_qualification is not None and self.reusable_qualification.behavior_entry_id != self.behavior_entry_id:
            _fail("record_value_invalid", "reusable qualification binds another behavior", "behavior entry.reusable_qualification")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.behavior_entry_id,
            "family_id": self.family_id,
            "compatible_releases": list(self.compatible_releases),
            "abi_profile_ids": list(self.abi_profile_ids),
            "portable_symbol": self.portable_symbol,
            "portable_source_sha256": self.portable_source_sha256,
            "boundaries": [item.to_payload() for item in self.boundaries],
            "reusable_qualification": None if self.reusable_qualification is None else self.reusable_qualification.to_payload(),
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryBehaviorEntryV3":
        row = _object(value, {"id", "family_id", "compatible_releases", "abi_profile_ids", "portable_symbol", "portable_source_sha256", "boundaries", "reusable_qualification"}, {}, location)
        return cls(
            behavior_entry_id=_text(row["id"], f"{location}.id"),
            family_id=_text(row["family_id"], f"{location}.family_id"),
            compatible_releases=_texts(row["compatible_releases"], f"{location}.compatible_releases"),
            abi_profile_ids=_texts(row["abi_profile_ids"], f"{location}.abi_profile_ids"),
            portable_symbol=_text(row["portable_symbol"], f"{location}.portable_symbol"),
            portable_source_sha256=_sha256(row["portable_source_sha256"], f"{location}.portable_source_sha256"),
            boundaries=tuple(BehaviorBoundaryV3.from_payload(item, f"{location}.boundaries[{index}]") for index, item in enumerate(_array(row["boundaries"], f"{location}.boundaries"))),
            reusable_qualification=(None if row["reusable_qualification"] is None else CheckedQualificationV3.from_payload(row["reusable_qualification"], f"{location}.reusable_qualification")),
        )


@dataclass(frozen=True, order=True)
class IndexEntryV3:
    key: str
    function_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.key, "index entry.key")
        if not self.function_ids or tuple(sorted(set(self.function_ids))) != self.function_ids:
            _fail("record_order_invalid", "function IDs must be nonempty, sorted, and unique", "index entry.function_ids")

    def to_payload(self) -> dict[str, Any]:
        return {"key": self.key, "function_ids": list(self.function_ids)}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "IndexEntryV3":
        row = _object(value, {"key", "function_ids"}, {}, location)
        return cls(_text(row["key"], f"{location}.key"), _texts(row["function_ids"], f"{location}.function_ids"))


@dataclass(frozen=True, order=True)
class FunctionMatchV3:
    target_function_id: str
    catalog_function_id: str
    evidence: tuple[str, ...]
    abi_status: str

    def __post_init__(self) -> None:
        _text(self.target_function_id, "function match.target_function_id")
        _text(self.catalog_function_id, "function match.catalog_function_id")
        if tuple(sorted(set(self.evidence))) != self.evidence:
            _fail("record_order_invalid", "match evidence must be sorted and unique", "function match.evidence")
        _check_choice(self.abi_status, frozenset({"compatible", "incomplete", "violated"}), "function match.abi_status")

    def to_payload(self) -> dict[str, Any]:
        return {"target_function_id": self.target_function_id, "catalog_function_id": self.catalog_function_id, "evidence": list(self.evidence), "abi_status": self.abi_status}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "FunctionMatchV3":
        row = _object(value, {"target_function_id", "catalog_function_id", "evidence", "abi_status"}, {}, location)
        return cls(_text(row["target_function_id"], f"{location}.target_function_id"), _text(row["catalog_function_id"], f"{location}.catalog_function_id"), _texts(row["evidence"], f"{location}.evidence"), _text(row["abi_status"], f"{location}.abi_status"))


@dataclass(frozen=True, order=True)
class ConstellationHypothesisV3:
    hypothesis_id: str
    family_id: str
    release_id: str
    target_function_ids: tuple[str, ...]
    target_unit_ids: tuple[str, ...]
    catalog_function_ids: tuple[str, ...]
    member_ids: tuple[str, ...]
    matches: tuple[FunctionMatchV3, ...]
    diagnostic_score: int
    status: str
    issues: tuple[LibraryIssueV3, ...]

    def __post_init__(self) -> None:
        _text(self.hypothesis_id, "hypothesis.id")
        _text(self.family_id, "hypothesis.family_id")
        _text(self.release_id, "hypothesis.release_id")
        _check_choice(self.status, _STATUSES, "hypothesis.status")
        _integer(self.diagnostic_score, "hypothesis.diagnostic_score")
        for label, values in (("target_function_ids", self.target_function_ids), ("target_unit_ids", self.target_unit_ids), ("catalog_function_ids", self.catalog_function_ids), ("member_ids", self.member_ids)):
            if tuple(sorted(set(values))) != values:
                _fail("record_order_invalid", f"{label} must be sorted and unique", f"hypothesis.{label}")

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "family_id": self.family_id,
            "release_id": self.release_id,
            "target_function_ids": list(self.target_function_ids),
            "target_unit_ids": list(self.target_unit_ids),
            "catalog_function_ids": list(self.catalog_function_ids),
            "member_ids": list(self.member_ids),
            "matches": [item.to_payload() for item in self.matches],
            "diagnostic_score": self.diagnostic_score,
            "status": self.status,
            "issues": [item.to_payload() for item in self.issues],
        }

    @classmethod
    def from_payload(cls, value: object, location: str) -> "ConstellationHypothesisV3":
        row = _object(value, {"id", "family_id", "release_id", "target_function_ids", "target_unit_ids", "catalog_function_ids", "member_ids", "matches", "diagnostic_score", "status", "issues"}, {}, location)
        return cls(
            hypothesis_id=_text(row["id"], f"{location}.id"),
            family_id=_text(row["family_id"], f"{location}.family_id"),
            release_id=_text(row["release_id"], f"{location}.release_id"),
            target_function_ids=_texts(row["target_function_ids"], f"{location}.target_function_ids"),
            target_unit_ids=_texts(row["target_unit_ids"], f"{location}.target_unit_ids"),
            catalog_function_ids=_texts(row["catalog_function_ids"], f"{location}.catalog_function_ids"),
            member_ids=_texts(row["member_ids"], f"{location}.member_ids"),
            matches=tuple(FunctionMatchV3.from_payload(item, f"{location}.matches[{index}]") for index, item in enumerate(_array(row["matches"], f"{location}.matches"))),
            diagnostic_score=_integer(row["diagnostic_score"], f"{location}.diagnostic_score"),
            status=_text(row["status"], f"{location}.status"),
            issues=tuple(LibraryIssueV3.from_payload(item, f"{location}.issues[{index}]") for index, item in enumerate(_array(row["issues"], f"{location}.issues"))),
        )


LIBRARY_ABI_PROFILE_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), LibraryAbiProfileV3.from_payload
)
LIBRARY_FUNCTION_SIGNATURE_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), LibraryFunctionSignatureV3.from_payload
)
TARGET_FUNCTION_SIGNATURE_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), TargetFunctionSignatureV3.from_payload
)
LIBRARY_BEHAVIOR_ENTRY_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), LibraryBehaviorEntryV3.from_payload
)
CONSTELLATION_HYPOTHESIS_CODEC_V3 = StrictCodec(
    lambda value: value.to_payload(), ConstellationHypothesisV3.from_payload
)
__all__ = [
    "ABI_CATALOG_V3_FORMAT",
    "CATALOG_SEARCH_INDEX_V3_FORMAT",
    "CONSTELLATION_HYPOTHESES_V3_FORMAT",
    "TARGET_SIGNATURE_GRAPH_V3_FORMAT",
    "BehaviorBoundaryV3",
    "BoundaryEffectV3",
    "CONSTELLATION_HYPOTHESIS_CODEC_V3",
    "CallbackSlotV3",
    "CheckedQualificationV3",
    "ConstellationHypothesisV3",
    "FunctionMatchV3",
    "IndexEntryV3",
    "LIBRARY_ABI_PROFILE_CODEC_V3",
    "LIBRARY_BEHAVIOR_ENTRY_CODEC_V3",
    "LIBRARY_FUNCTION_SIGNATURE_CODEC_V3",
    "LibraryAbiError",
    "LibraryAbiProfileV3",
    "LibraryBehaviorEntryV3",
    "LibraryFunctionSignatureV3",
    "LibraryIssueV3",
    "StackCleanupV3",
    "StrictCodec",
    "TARGET_FUNCTION_SIGNATURE_CODEC_V3",
    "TargetFunctionSignatureV3",
    "ValueLocationV3",
    "VariadicPolicyV3",
    "canonical_json_bytes",
    "canonical_sha256",
    "phase_status",
    "stable_id",
]
