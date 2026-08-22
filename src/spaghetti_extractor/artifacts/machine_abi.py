"""Stable machine-level ABI definitions shared by proof and reconstruction paths."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


MACHINE_CALL_ABI_REGISTERS = frozenset({
    "eax", "ebp", "ebx", "ecx", "edi", "edx", "esi",
})
MACHINE_CALL_ABI_TEMPLATES: Mapping[str, Mapping[str, Any]] = {
    "pe32-cdecl-v1": {
        "callee_cleanup": False,
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "clobbered_registers": ["eax", "ecx", "edx"],
    },
    "pe32-stdcall-v1": {
        "callee_cleanup": True,
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "clobbered_registers": ["eax", "ecx", "edx"],
    },
}

NORMAL_CALL_ABI_PREMISE_FORMAT = (
    "spaghetti-extractor-normal-call-abi-premise-v1"
)
PE32_NORMAL_RETURN_NONVOLATILE_PREMISE_ID = (
    "pe32-normal-return-nonvolatile-v1"
)
_NORMAL_CALL_PREMISE_AUTHORITY = "conditional_machine_abi_premise"
_PE32_NONVOLATILE_REGISTERS = ("ebp", "ebx", "edi", "esi")
_PE32_VOLATILE_REGISTERS = ("eax", "ecx", "edx")
_PE32_NORMAL_CALL_PREMISE_TRANSFER_KINDS = (
    "indirect_call",
    "internal_call",
)


@dataclass(frozen=True)
class MachineCallABI:
    template: str
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    callee_cleanup: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "template": self.template,
            "preserved_registers": list(self.preserved_registers),
            "clobbered_registers": list(self.clobbered_registers),
            "callee_cleanup": self.callee_cleanup,
        }


@dataclass(frozen=True)
class NormalCallABIPremise:
    """Explicit conditional ABI premise for an otherwise unresolved call.

    This is deliberately weaker than a full call ABI.  It says only which
    registers survive when a selected call returns normally.  It does not
    establish that the call returns, its stack cleanup, arguments, results,
    memory effects, or target identity.
    """

    premise_id: str
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    transfer_kinds: tuple[str, ...]
    content_sha256: str

    def __post_init__(self) -> None:
        if self.premise_id != PE32_NORMAL_RETURN_NONVOLATILE_PREMISE_ID:
            raise ValueError("normal-call ABI premise ID is unsupported")
        if self.preserved_registers != _PE32_NONVOLATILE_REGISTERS:
            raise ValueError(
                "normal-call ABI premise has unsupported preserved registers"
            )
        if self.clobbered_registers != _PE32_VOLATILE_REGISTERS:
            raise ValueError(
                "normal-call ABI premise has unsupported clobbered registers"
            )
        if self.transfer_kinds != _PE32_NORMAL_CALL_PREMISE_TRANSFER_KINDS:
            raise ValueError("normal-call ABI premise has unsupported transfer scope")
        if (
            len(self.content_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.content_sha256
            )
        ):
            raise ValueError("normal-call ABI premise content hash is malformed")

    @property
    def dependency_id(self) -> str:
        return f"normal-call-abi-premise:{self.content_sha256}"

    def as_json(self) -> dict[str, Any]:
        return {
            **_normal_call_abi_premise_core(
                premise_id=self.premise_id,
                preserved_registers=self.preserved_registers,
                clobbered_registers=self.clobbered_registers,
                transfer_kinds=self.transfer_kinds,
            ),
            "content_sha256": self.content_sha256,
        }


def resolve_machine_call_abi(template: Any) -> MachineCallABI | None:
    if not isinstance(template, str):
        return None
    raw = MACHINE_CALL_ABI_TEMPLATES.get(template)
    if raw is None:
        return None
    preserved = tuple(sorted(str(value) for value in raw["preserved_registers"]))
    clobbered = tuple(sorted(str(value) for value in raw["clobbered_registers"]))
    if (
        set(preserved) | set(clobbered) != set(MACHINE_CALL_ABI_REGISTERS)
        or set(preserved) & set(clobbered)
    ):
        raise ValueError(f"machine ABI template {template!r} is not a partition")
    return MachineCallABI(
        template=template,
        preserved_registers=preserved,
        clobbered_registers=clobbered,
        callee_cleanup=bool(raw["callee_cleanup"]),
    )


def build_pe32_normal_call_abi_premise() -> NormalCallABIPremise:
    """Build the one reviewed PE32 normal-return preservation premise."""

    core = _normal_call_abi_premise_core(
        premise_id=PE32_NORMAL_RETURN_NONVOLATILE_PREMISE_ID,
        preserved_registers=_PE32_NONVOLATILE_REGISTERS,
        clobbered_registers=_PE32_VOLATILE_REGISTERS,
        transfer_kinds=_PE32_NORMAL_CALL_PREMISE_TRANSFER_KINDS,
    )
    digest = hashlib.sha256(_canonical_json_bytes(core)).hexdigest()
    return NormalCallABIPremise(
        premise_id=PE32_NORMAL_RETURN_NONVOLATILE_PREMISE_ID,
        preserved_registers=_PE32_NONVOLATILE_REGISTERS,
        clobbered_registers=_PE32_VOLATILE_REGISTERS,
        transfer_kinds=_PE32_NORMAL_CALL_PREMISE_TRANSFER_KINDS,
        content_sha256=digest,
    )


def parse_normal_call_abi_premise(value: Any) -> NormalCallABIPremise:
    """Strictly parse and replay a conditional normal-call ABI premise."""

    expected_fields = {
        "format",
        "schema_version",
        "authority",
        "id",
        "machine",
        "bitness",
        "applies_when",
        "transfer_kinds",
        "preserved_registers",
        "clobbered_registers",
        "content_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != expected_fields:
        raise ValueError("normal-call ABI premise has noncanonical fields")
    if (
        value.get("format") != NORMAL_CALL_ABI_PREMISE_FORMAT
        or value.get("schema_version") != 1
        or value.get("authority") != _NORMAL_CALL_PREMISE_AUTHORITY
        or value.get("machine") != "i386"
        or value.get("bitness") != 32
        or value.get("applies_when") != "call_returns_normally"
    ):
        raise ValueError("normal-call ABI premise header is unsupported")
    for field in (
        "transfer_kinds",
        "preserved_registers",
        "clobbered_registers",
    ):
        if not isinstance(value.get(field), list) or any(
            not isinstance(item, str) for item in value[field]
        ):
            raise ValueError(f"normal-call ABI premise {field} is malformed")
    result = NormalCallABIPremise(
        premise_id=str(value.get("id")),
        preserved_registers=tuple(value["preserved_registers"]),
        clobbered_registers=tuple(value["clobbered_registers"]),
        transfer_kinds=tuple(value["transfer_kinds"]),
        content_sha256=str(value.get("content_sha256")),
    )
    expected_digest = hashlib.sha256(
        _canonical_json_bytes({
            key: item for key, item in result.as_json().items()
            if key != "content_sha256"
        })
    ).hexdigest()
    if result.content_sha256 != expected_digest:
        raise ValueError("normal-call ABI premise content hash is stale")
    if result.as_json() != json.loads(json.dumps(value)):
        raise ValueError("normal-call ABI premise is noncanonical")
    return result


def load_normal_call_abi_premise(path: str | Path) -> NormalCallABIPremise:
    """Load one canonical normal-call ABI premise from JSON."""

    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"cannot read normal-call ABI premise {source}: {exc}"
        ) from exc
    return parse_normal_call_abi_premise(value)


def _normal_call_abi_premise_core(
    *,
    premise_id: str,
    preserved_registers: tuple[str, ...],
    clobbered_registers: tuple[str, ...],
    transfer_kinds: tuple[str, ...],
) -> dict[str, Any]:
    return {
        "format": NORMAL_CALL_ABI_PREMISE_FORMAT,
        "schema_version": 1,
        "authority": _NORMAL_CALL_PREMISE_AUTHORITY,
        "id": premise_id,
        "machine": "i386",
        "bitness": 32,
        "applies_when": "call_returns_normally",
        "transfer_kinds": list(transfer_kinds),
        "preserved_registers": list(preserved_registers),
        "clobbered_registers": list(clobbered_registers),
    }


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


__all__ = [
    "MACHINE_CALL_ABI_REGISTERS",
    "MACHINE_CALL_ABI_TEMPLATES",
    "NORMAL_CALL_ABI_PREMISE_FORMAT",
    "PE32_NORMAL_RETURN_NONVOLATILE_PREMISE_ID",
    "MachineCallABI",
    "NormalCallABIPremise",
    "build_pe32_normal_call_abi_premise",
    "load_normal_call_abi_premise",
    "parse_normal_call_abi_premise",
    "resolve_machine_call_abi",
]
