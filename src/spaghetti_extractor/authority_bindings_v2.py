"""Stable exact bindings shared by extraction and v2 authority records.

This module intentionally contains no certificate or acceptance record types.
Machine-IR extraction may depend on it without inheriting invalidation from
interprocedural, external-site, or final-authority schema changes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence, TypeAlias


_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class AuthorityDataError(ValueError):
    """A v2 authority object is structurally malformed or noncanonical."""


def _json_value(value: Any, *, context: str = "JSON value") -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise AuthorityDataError(
            f"{context} cannot contain floating-point values"
        )
    # Artifact payloads overwhelmingly use the concrete JSON container types.
    # Handle them before the comparatively expensive collections.abc checks;
    # the generic Mapping fallback remains available for parser adapters.
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityDataError(
                    f"{context} has a non-string object key"
                )
            result[key] = _json_value(item, context=context)
        return result
    if type(value) is list or type(value) is tuple:
        return [_json_value(item, context=context) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityDataError(
                    f"{context} has a non-string object key"
                )
            if key in result:
                raise AuthorityDataError(
                    f"{context} has duplicate key {key!r}"
                )
            result[key] = _json_value(item, context=f"{context}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [
            _json_value(item, context=f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    raise AuthorityDataError(f"{context} is not canonical JSON data")


def canonical_json_bytes(value: Any) -> bytes:
    normalized = _json_value(value)
    return _dump_canonical_json(normalized)


def _dump_canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("ascii")


def indirect_exit_id_v2(value: Mapping[str, Any]) -> str:
    """Return the canonical identity shared by every indirect-control phase."""

    identity = {
        "source_unit_id": value.get("source_unit_id"),
        "source_rva": value.get("source_rva"),
        "source_event_index": value.get("source_event_index"),
        "kind": value.get("kind"),
        "target_expression": value.get("target_expression"),
    }
    return "indirect-exit:" + hashlib.sha256(
        canonical_json_bytes(identity)
    ).hexdigest()[:20]


def _reject_float(value: str) -> Any:
    raise AuthorityDataError(
        f"canonical JSON cannot contain floating-point value {value}"
    )


def _reject_constant(value: str) -> Any:
    raise AuthorityDataError(f"canonical JSON cannot contain constant {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityDataError(f"canonical JSON has duplicate key {key!r}")
        result[key] = value
    return result


def parse_canonical_json(data: str | bytes) -> Any:
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise AuthorityDataError(
                "canonical JSON text is not valid UTF-8"
            ) from exc
    elif isinstance(data, bytes):
        raw = data
    else:
        raise AuthorityDataError("canonical JSON input must be text or bytes")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityDataError("authority data is not valid JSON") from exc
    if _dump_canonical_json(value) != raw:
        raise AuthorityDataError("authority JSON is not canonical")
    return value


@dataclass(frozen=True, order=True)
class CanonicalJson:
    data: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.data, bytes):
            raise AuthorityDataError("CanonicalJson.data must be bytes")
        parse_canonical_json(self.data)

    @classmethod
    def of(cls, value: Any) -> "CanonicalJson":
        data = canonical_json_bytes(value)
        result = object.__new__(cls)
        object.__setattr__(result, "data", data)
        return result

    def to_value(self) -> Any:
        return json.loads(self.data.decode("ascii"))


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise AuthorityDataError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _token(value: Any, context: str) -> str:
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        raise AuthorityDataError(f"{context} must be a lowercase identifier")
    return value


def _text(value: Any, context: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise AuthorityDataError(f"{context} must be nonempty bounded text")
    return value


def _uint(value: Any, context: str, *, maximum: int = 0xFFFFFFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise AuthorityDataError(f"{context} must be an unsigned integer")
    return value


def _object(value: Any, expected: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityDataError(f"{context} must be an object")
    if set(value) != expected:
        raise AuthorityDataError(f"{context} has noncanonical fields")
    if any(not isinstance(key, str) for key in value):
        raise AuthorityDataError(f"{context} has a non-string field")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise AuthorityDataError(f"{context} must be an array")
    return value


@dataclass(frozen=True, order=True)
class BinaryBinding:
    pe_sha256: str
    machine_ir_sha256: str

    def __post_init__(self) -> None:
        _sha256(self.pe_sha256, "PE SHA-256")
        _sha256(self.machine_ir_sha256, "machine-IR SHA-256")

    def to_payload(self) -> dict[str, str]:
        return {
            "pe_sha256": self.pe_sha256,
            "machine_ir_sha256": self.machine_ir_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "BinaryBinding":
        row = _object(
            value, {"pe_sha256", "machine_ir_sha256"}, "binary binding"
        )
        return cls(
            pe_sha256=_sha256(row["pe_sha256"], "PE SHA-256"),
            machine_ir_sha256=_sha256(
                row["machine_ir_sha256"], "machine-IR SHA-256"
            ),
        )


@dataclass(frozen=True, order=True)
class UnitBinding:
    binary: BinaryBinding
    unit_id: str
    rva_start: int
    rva_end: int
    unit_sha256: str
    instruction_bytes_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary, BinaryBinding):
            raise AuthorityDataError("unit binding requires a binary binding")
        _text(self.unit_id, "unit ID", maximum=256)
        _uint(self.rva_start, "unit start RVA")
        _uint(self.rva_end, "unit end RVA")
        if self.rva_end <= self.rva_start:
            raise AuthorityDataError("unit binding has an empty or reversed span")
        _sha256(self.unit_sha256, "unit SHA-256")
        _sha256(self.instruction_bytes_sha256, "instruction-bytes SHA-256")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "unit",
            "binary": self.binary.to_payload(),
            "unit_id": self.unit_id,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "unit_sha256": self.unit_sha256,
            "instruction_bytes_sha256": self.instruction_bytes_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "UnitBinding":
        row = _object(
            value,
            {
                "kind",
                "binary",
                "unit_id",
                "rva_start",
                "rva_end",
                "unit_sha256",
                "instruction_bytes_sha256",
            },
            "unit binding",
        )
        if row["kind"] != "unit":
            raise AuthorityDataError("unit binding has an invalid kind")
        return cls(
            binary=BinaryBinding.parse(row["binary"]),
            unit_id=_text(row["unit_id"], "unit ID", maximum=256),
            rva_start=_uint(row["rva_start"], "unit start RVA"),
            rva_end=_uint(row["rva_end"], "unit end RVA"),
            unit_sha256=_sha256(row["unit_sha256"], "unit SHA-256"),
            instruction_bytes_sha256=_sha256(
                row["instruction_bytes_sha256"], "instruction-bytes SHA-256"
            ),
        )


@dataclass(frozen=True, order=True)
class EventBinding:
    unit: UnitBinding
    event_index: int
    event_kind: str
    instruction_rva: int
    event_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.unit, UnitBinding):
            raise AuthorityDataError("event binding requires a unit binding")
        _uint(self.event_index, "event index")
        _token(self.event_kind, "event kind")
        _uint(self.instruction_rva, "event instruction RVA")
        if not self.unit.rva_start <= self.instruction_rva < self.unit.rva_end:
            raise AuthorityDataError(
                "event instruction RVA is outside its exact unit"
            )
        _sha256(self.event_sha256, "event SHA-256")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "event",
            "unit": self.unit.to_payload(),
            "event_index": self.event_index,
            "event_kind": self.event_kind,
            "instruction_rva": self.instruction_rva,
            "event_sha256": self.event_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "EventBinding":
        row = _object(
            value,
            {
                "kind",
                "unit",
                "event_index",
                "event_kind",
                "instruction_rva",
                "event_sha256",
            },
            "event binding",
        )
        if row["kind"] != "event":
            raise AuthorityDataError("event binding has an invalid kind")
        return cls(
            unit=UnitBinding.parse(row["unit"]),
            event_index=_uint(row["event_index"], "event index"),
            event_kind=_token(row["event_kind"], "event kind"),
            instruction_rva=_uint(
                row["instruction_rva"], "event instruction RVA"
            ),
            event_sha256=_sha256(row["event_sha256"], "event SHA-256"),
        )


@dataclass(frozen=True, order=True)
class IndirectExitBinding:
    """Exact identity of an indirect call/jump in one machine-IR unit.

    ``source_event_index`` is absent for a terminal outcome and present for an
    explicit machine event.  Keeping that distinction prevents an outcome from
    accidentally aliasing the first call event in the same unit.
    """

    unit: UnitBinding
    exit_id: str
    source_event_index: int | None
    transfer_kind: str
    instruction_rva: int
    target_expression: CanonicalJson

    def __post_init__(self) -> None:
        if not isinstance(self.unit, UnitBinding):
            raise AuthorityDataError(
                "indirect-exit binding requires a unit binding"
            )
        _text(self.exit_id, "indirect-exit ID", maximum=64)
        if self.source_event_index is not None:
            _uint(self.source_event_index, "indirect-exit event index")
        if self.transfer_kind not in {"indirect_call", "indirect_jump"}:
            raise AuthorityDataError(
                "indirect-exit binding has an invalid transfer kind"
            )
        _uint(self.instruction_rva, "indirect-exit instruction RVA")
        if not self.unit.rva_start <= self.instruction_rva < self.unit.rva_end:
            raise AuthorityDataError(
                "indirect-exit instruction RVA is outside its exact unit"
            )
        if not isinstance(self.target_expression, CanonicalJson):
            raise AuthorityDataError(
                "indirect-exit binding requires a canonical target expression"
            )
        if not isinstance(self.target_expression.to_value(), Mapping):
            raise AuthorityDataError(
                "indirect-exit target expression must be an object"
            )
        expected = indirect_exit_id_v2(self.identity_payload())
        if self.exit_id != expected:
            raise AuthorityDataError(
                "indirect-exit ID does not match its exact identity"
            )

    @classmethod
    def from_exact(
        cls,
        *,
        unit: UnitBinding,
        source_event_index: int | None,
        transfer_kind: str,
        instruction_rva: int,
        target_expression: Any,
    ) -> "IndirectExitBinding":
        identity = {
            "source_unit_id": unit.unit_id,
            "source_rva": unit.rva_start,
            "source_event_index": source_event_index,
            "kind": transfer_kind,
            "target_expression": target_expression,
        }
        return cls(
            unit=unit,
            exit_id=indirect_exit_id_v2(identity),
            source_event_index=source_event_index,
            transfer_kind=transfer_kind,
            instruction_rva=instruction_rva,
            target_expression=CanonicalJson.of(target_expression),
        )

    @property
    def target_expression_sha256(self) -> str:
        return hashlib.sha256(self.target_expression.data).hexdigest()

    def identity_payload(self) -> dict[str, Any]:
        return {
            "source_unit_id": self.unit.unit_id,
            "source_rva": self.unit.rva_start,
            "source_event_index": self.source_event_index,
            "kind": self.transfer_kind,
            "target_expression": self.target_expression.to_value(),
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "indirect_exit",
            "unit": self.unit.to_payload(),
            "id": self.exit_id,
            "source_event_index": self.source_event_index,
            "transfer_kind": self.transfer_kind,
            "instruction_rva": self.instruction_rva,
            "target_expression": self.target_expression.to_value(),
            "target_expression_sha256": self.target_expression_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "IndirectExitBinding":
        row = _object(
            value,
            {
                "kind",
                "unit",
                "id",
                "source_event_index",
                "transfer_kind",
                "instruction_rva",
                "target_expression",
                "target_expression_sha256",
            },
            "indirect-exit binding",
        )
        if row["kind"] != "indirect_exit":
            raise AuthorityDataError(
                "indirect-exit binding has an invalid kind"
            )
        source_event_index = row["source_event_index"]
        if source_event_index is not None:
            source_event_index = _uint(
                source_event_index, "indirect-exit event index"
            )
        target_expression = CanonicalJson.of(row["target_expression"])
        expected_sha256 = hashlib.sha256(target_expression.data).hexdigest()
        if row["target_expression_sha256"] != expected_sha256:
            raise AuthorityDataError(
                "indirect-exit target-expression digest is stale"
            )
        return cls(
            unit=UnitBinding.parse(row["unit"]),
            exit_id=_text(row["id"], "indirect-exit ID", maximum=64),
            source_event_index=source_event_index,
            transfer_kind=_token(
                row["transfer_kind"], "indirect-exit transfer kind"
            ),
            instruction_rva=_uint(
                row["instruction_rva"], "indirect-exit instruction RVA"
            ),
            target_expression=target_expression,
        )


def match_indirect_recovery_v2(
    rows: Sequence[Any], binding: IndirectExitBinding
) -> tuple[str, Mapping[str, Any] | None, str | None]:
    """Bind one recovery fact to an exact exit without positional aliases."""

    matches = [
        row
        for row in rows
        if isinstance(row, Mapping) and row.get("id") == binding.exit_id
    ]
    if len(matches) > 1:
        return "violated", None, "indirect_recovery_identity_ambiguous"
    if not matches:
        positional = [
            row
            for row in rows
            if isinstance(row, Mapping)
            and row.get("source_unit_id") == binding.unit.unit_id
            and row.get("source_event_index") == binding.source_event_index
            and row.get("kind") == binding.transfer_kind
        ]
        return (
            ("violated", None, "indirect_recovery_identity_mismatch")
            if positional
            else ("incomplete", None, "indirect_recovery_missing")
        )
    recovery = matches[0]
    observed = {
        "source_unit_id": recovery.get("source_unit_id"),
        "source_rva": recovery.get("source_rva"),
        "source_event_index": recovery.get("source_event_index"),
        "kind": recovery.get("kind"),
        "target_expression": recovery.get("target_expression"),
    }
    if canonical_json_bytes(observed) != canonical_json_bytes(
        binding.identity_payload()
    ):
        return "violated", None, "indirect_recovery_binding_mismatch"
    return "complete", recovery, None


@dataclass(frozen=True, order=True)
class ImageSpanBinding:
    """Exact loader-initialized image bytes used by one authority fact.

    The bytes are still interpreted through the launch profile.  In particular,
    ``relocation_kind`` records whether a PE32 HIGHLOW relocation rewrites this
    exact span when the image is loaded away from its preferred base.
    """

    binary: BinaryBinding
    rva_start: int
    rva_end: int
    initial_bytes_sha256: str
    initialization_kind: str
    relocation_kind: str

    def __post_init__(self) -> None:
        if not isinstance(self.binary, BinaryBinding):
            raise AuthorityDataError(
                "image-span binding requires a binary binding"
            )
        _uint(self.rva_start, "image-span start RVA")
        _uint(self.rva_end, "image-span end RVA")
        if self.rva_end <= self.rva_start:
            raise AuthorityDataError(
                "image-span binding has an empty or reversed span"
            )
        _sha256(self.initial_bytes_sha256, "initial image bytes SHA-256")
        _token(self.initialization_kind, "image-span initialization kind")
        _token(self.relocation_kind, "image-span relocation kind")

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": "image_span",
            "binary": self.binary.to_payload(),
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "initial_bytes_sha256": self.initial_bytes_sha256,
            "initialization_kind": self.initialization_kind,
            "relocation_kind": self.relocation_kind,
        }

    @classmethod
    def parse(cls, value: Any) -> "ImageSpanBinding":
        row = _object(
            value,
            {
                "kind",
                "binary",
                "rva_start",
                "rva_end",
                "initial_bytes_sha256",
                "initialization_kind",
                "relocation_kind",
            },
            "image-span binding",
        )
        if row["kind"] != "image_span":
            raise AuthorityDataError(
                "image-span binding has an invalid kind"
            )
        return cls(
            binary=BinaryBinding.parse(row["binary"]),
            rva_start=_uint(row["rva_start"], "image-span start RVA"),
            rva_end=_uint(row["rva_end"], "image-span end RVA"),
            initial_bytes_sha256=_sha256(
                row["initial_bytes_sha256"],
                "initial image bytes SHA-256",
            ),
            initialization_kind=_token(
                row["initialization_kind"],
                "image-span initialization kind",
            ),
            relocation_kind=_token(
                row["relocation_kind"], "image-span relocation kind"
            ),
        )


ScopeBinding: TypeAlias = UnitBinding | EventBinding


def _scope_payload(binding: ScopeBinding) -> dict[str, Any]:
    if isinstance(binding, (UnitBinding, EventBinding)):
        return binding.to_payload()
    raise AuthorityDataError("authority scope must be a unit or event binding")


def _parse_scope(value: Any) -> ScopeBinding:
    if not isinstance(value, Mapping):
        raise AuthorityDataError("authority binding must be an object")
    kind = value.get("kind")
    if kind == "unit":
        return UnitBinding.parse(value)
    if kind == "event":
        return EventBinding.parse(value)
    raise AuthorityDataError("authority binding kind is unsupported")


def _binding_unit(binding: ScopeBinding) -> UnitBinding:
    return binding.unit if isinstance(binding, EventBinding) else binding


__all__ = [
    "AuthorityDataError",
    "BinaryBinding",
    "CanonicalJson",
    "EventBinding",
    "IndirectExitBinding",
    "ImageSpanBinding",
    "ScopeBinding",
    "UnitBinding",
    "canonical_json",
    "canonical_json_bytes",
    "indirect_exit_id_v2",
    "match_indirect_recovery_v2",
    "parse_canonical_json",
]
