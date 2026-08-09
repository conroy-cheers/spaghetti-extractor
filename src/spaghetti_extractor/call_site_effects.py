"""Typed proposal artifacts for one machine-level call transition.

Call-site effects are deliberately not proof authority.  They provide one
validated interchange format for external-profile analysis and internal-call
summary synthesis; Stage A must still replay every consumed fact against the
exact machine semantics and its declared dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .machine_abi import MachineCallABI, resolve_machine_call_abi
from .provenance_domain import (
    FiniteValue,
    ValueOrigin,
    origins_json,
    parse_finite_value,
    parse_value_origin,
)


CALL_SITE_EFFECT_FORMAT = "stage-a-call-site-effect-v2"
CALL_TRANSFER_KINDS = frozenset({
    "external_call",
    "indirect_call",
    "internal_call",
})
CALL_EFFECT_STATUSES = frozenset({"complete", "incomplete"})
CALL_FRAME_STATUSES = frozenset({"complete", "incomplete", "not_applicable"})
CALL_EFFECT_REGISTERS = frozenset({
    "eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp",
})


@dataclass(frozen=True, order=True)
class CallSiteId:
    unit_id: str
    event_index: int

    def __post_init__(self) -> None:
        if not self.unit_id:
            raise ValueError("call-site unit ID must not be empty")
        if self.event_index < 0:
            raise ValueError("call-site event index must not be negative")

    def as_json(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "event_index": self.event_index,
        }


@dataclass(frozen=True, order=True)
class CallWriteSpan:
    base: ValueOrigin
    size: int | None

    def __post_init__(self) -> None:
        if self.size is not None and not 0 <= self.size <= 0xFFFFFFFF:
            raise ValueError("call write-span size is outside the PE32 domain")

    def as_json(self) -> dict[str, Any]:
        return {"base": self.base.as_json(), "size": self.size}


@dataclass(frozen=True)
class CallOutput:
    location: ValueOrigin
    value: FiniteValue

    def __post_init__(self) -> None:
        if self.value is None or not self.value:
            raise ValueError("call output must contain a non-empty finite value")

    def as_json(self) -> dict[str, Any]:
        return {
            "location": self.location.as_json(),
            "origins": origins_json(self.value),
        }


@dataclass(frozen=True)
class CallSiteEffect:
    site: CallSiteId
    transfer_kind: str
    status: str
    register_frame_status: str
    preserved_registers: frozenset[str]
    stack_frame_status: str
    stack_cleanup_bytes: int | None
    result_status: str
    outputs: tuple[CallOutput, ...]
    memory_frame_status: str
    memory_preserved: bool
    memory_writes: tuple[CallWriteSpan, ...]
    abi: MachineCallABI | None = None
    argument_words: int | None = None
    dependencies: tuple[str, ...] = ()
    failure_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.transfer_kind not in CALL_TRANSFER_KINDS:
            raise ValueError(f"unsupported call transfer kind {self.transfer_kind!r}")
        if self.status not in CALL_EFFECT_STATUSES:
            raise ValueError(f"unsupported call-effect status {self.status!r}")
        for family, value in (
            ("register", self.register_frame_status),
            ("stack", self.stack_frame_status),
            ("result", self.result_status),
            ("memory", self.memory_frame_status),
        ):
            if value not in CALL_FRAME_STATUSES:
                raise ValueError(f"unsupported {family} frame status {value!r}")
        if not self.preserved_registers <= CALL_EFFECT_REGISTERS:
            raise ValueError("call effect preserves an unknown register")
        if self.register_frame_status != "complete" and self.preserved_registers:
            raise ValueError("incomplete register frame cannot preserve registers")
        if (
            self.stack_cleanup_bytes is not None
            and not 0 <= self.stack_cleanup_bytes <= 0xFFFFFFFF
        ):
            raise ValueError("call stack cleanup is outside the PE32 domain")
        if (
            self.stack_frame_status == "complete"
            and self.stack_cleanup_bytes is None
        ):
            raise ValueError("complete stack frame requires a cleanup value")
        if (
            self.stack_frame_status != "complete"
            and self.stack_cleanup_bytes is not None
        ):
            raise ValueError("non-complete stack frame cannot carry cleanup")
        if self.result_status != "complete" and self.outputs:
            raise ValueError("incomplete result frame cannot carry outputs")
        if self.memory_frame_status != "complete" and (
            self.memory_preserved or self.memory_writes
        ):
            raise ValueError("incomplete memory frame cannot carry effects")
        if self.argument_words is not None and self.argument_words < 0:
            raise ValueError("call argument-word count must not be negative")
        if tuple(sorted(set(self.dependencies))) != self.dependencies:
            raise ValueError("call-effect dependencies must be sorted and unique")
        if any(not value for value in self.dependencies):
            raise ValueError("call-effect dependencies must not be empty")
        if tuple(sorted(set(self.failure_codes))) != self.failure_codes:
            raise ValueError("call-effect failure codes must be sorted and unique")
        if self.status == "complete" and self.failure_codes:
            raise ValueError("complete call effect cannot carry failure codes")
        if self.status == "complete" and any(
            value == "incomplete"
            for value in (
                self.register_frame_status,
                self.stack_frame_status,
                self.result_status,
                self.memory_frame_status,
            )
        ):
            raise ValueError("complete call effect cannot contain incomplete families")
        output_locations = [output.location for output in self.outputs]
        if len(set(output_locations)) != len(output_locations):
            raise ValueError("call effect contains duplicate output locations")

    def as_json(self) -> dict[str, Any]:
        return {
            "format": CALL_SITE_EFFECT_FORMAT,
            **self.site.as_json(),
            "transfer_kind": self.transfer_kind,
            "status": self.status,
            "register_frame": {
                "status": self.register_frame_status,
                "preserved_registers": sorted(self.preserved_registers),
            },
            "stack_frame": {
                "status": self.stack_frame_status,
                "stack_cleanup_bytes": self.stack_cleanup_bytes,
            },
            "result_frame": {
                "status": self.result_status,
                "outputs": [
                    output.as_json()
                    for output in sorted(
                        self.outputs, key=lambda item: _origin_sort_key(item.location)
                    )
                ],
            },
            "memory_frame": {
                "status": self.memory_frame_status,
                "preserved": self.memory_preserved,
                "writes": [
                    span.as_json()
                    for span in sorted(
                        self.memory_writes,
                        key=lambda item: (
                            _origin_sort_key(item.base),
                            -1 if item.size is None else item.size,
                        ),
                    )
                ],
            },
            "abi": None if self.abi is None else self.abi.as_json(),
            "argument_words": self.argument_words,
            "dependencies": list(self.dependencies),
            "failure_codes": list(self.failure_codes),
        }


def parse_call_site_effect(
    raw: Mapping[str, Any], *, finite_value_budget: int
) -> CallSiteEffect:
    if finite_value_budget <= 0:
        raise ValueError("call-effect finite-value budget must be positive")
    if raw.get("format") != CALL_SITE_EFFECT_FORMAT:
        raise ValueError("call-site effect format is unsupported")
    allowed = {
        "format", "unit_id", "event_index", "transfer_kind", "status",
        "register_frame", "stack_frame", "result_frame", "memory_frame",
        "abi", "argument_words", "dependencies", "failure_codes",
    }
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(
            "call-site effect contains unknown fields: " + ", ".join(sorted(unknown))
        )
    unit_id = raw.get("unit_id")
    event_index = raw.get("event_index")
    if not isinstance(unit_id, str) or not unit_id:
        raise ValueError("call-site effect unit ID is invalid")
    if (
        not isinstance(event_index, int)
        or isinstance(event_index, bool)
        or event_index < 0
    ):
        raise ValueError("call-site effect event index is invalid")

    register_frame = _object(raw.get("register_frame"), "register_frame")
    _require_keys(
        register_frame,
        required={"status", "preserved_registers"},
        context="register_frame",
    )
    preserved = _string_set(
        register_frame["preserved_registers"], "preserved_registers"
    )

    stack_frame = _object(raw.get("stack_frame"), "stack_frame")
    _require_keys(
        stack_frame,
        required={"status", "stack_cleanup_bytes"},
        context="stack_frame",
    )
    cleanup = stack_frame["stack_cleanup_bytes"]
    if cleanup is not None and not _is_int(cleanup):
        raise ValueError("stack cleanup must be an integer or null")

    result_frame = _object(raw.get("result_frame"), "result_frame")
    _require_keys(
        result_frame,
        required={"status", "outputs"},
        context="result_frame",
    )
    raw_outputs = _sequence(result_frame["outputs"], "result outputs")
    outputs: list[CallOutput] = []
    for index, item in enumerate(raw_outputs):
        output = _object(item, f"result output {index}")
        _require_keys(
            output,
            required={"location", "origins"},
            context=f"result output {index}",
        )
        origins = _finite_value_from_json(
            output["origins"],
            finite_value_budget=finite_value_budget,
            context=f"result output {index}",
        )
        outputs.append(CallOutput(
            location=_origin_from_json(
                output["location"], context=f"result output {index} location"
            ),
            value=origins,
        ))

    memory_frame = _object(raw.get("memory_frame"), "memory_frame")
    _require_keys(
        memory_frame,
        required={"status", "preserved", "writes"},
        context="memory_frame",
    )
    if not isinstance(memory_frame["preserved"], bool):
        raise ValueError("memory-frame preserved flag must be a boolean")
    writes: list[CallWriteSpan] = []
    for index, item in enumerate(_sequence(memory_frame["writes"], "memory writes")):
        span = _object(item, f"memory write {index}")
        _require_keys(
            span,
            required={"base", "size"},
            context=f"memory write {index}",
        )
        size = span["size"]
        if size is not None and not _is_int(size):
            raise ValueError("memory write size must be an integer or null")
        writes.append(CallWriteSpan(
            base=_origin_from_json(
                span["base"], context=f"memory write {index} base"
            ),
            size=None if size is None else int(size),
        ))

    raw_abi = raw.get("abi")
    abi = None
    if raw_abi is not None:
        abi_payload = _object(raw_abi, "abi")
        abi = resolve_machine_call_abi(abi_payload.get("template"))
        if abi is None or abi_payload != abi.as_json():
            raise ValueError("call-site ABI does not match a canonical template")
    argument_words = raw.get("argument_words")
    if argument_words is not None and (
        not isinstance(argument_words, int) or isinstance(argument_words, bool)
    ):
        raise ValueError("argument_words must be an integer or null")

    dependencies = _string_tuple(raw.get("dependencies"), "dependencies")
    failure_codes = _string_tuple(raw.get("failure_codes"), "failure_codes")
    return CallSiteEffect(
        site=CallSiteId(unit_id, event_index),
        transfer_kind=str(raw.get("transfer_kind")),
        status=str(raw.get("status")),
        register_frame_status=str(register_frame.get("status")),
        preserved_registers=frozenset(preserved),
        stack_frame_status=str(stack_frame.get("status")),
        stack_cleanup_bytes=None if cleanup is None else int(cleanup),
        result_status=str(result_frame.get("status")),
        outputs=tuple(outputs),
        memory_frame_status=str(memory_frame.get("status")),
        memory_preserved=bool(memory_frame["preserved"]),
        memory_writes=tuple(writes),
        abi=abi,
        argument_words=argument_words,
        dependencies=dependencies,
        failure_codes=failure_codes,
    )


def parse_call_site_effects(
    raw: Iterable[Mapping[str, Any]], *, finite_value_budget: int
) -> dict[CallSiteId, CallSiteEffect]:
    result: dict[CallSiteId, CallSiteEffect] = {}
    for item in raw:
        effect = parse_call_site_effect(
            item, finite_value_budget=finite_value_budget
        )
        if effect.site in result:
            raise ValueError(
                "duplicate call-site effect for "
                f"{effect.site.unit_id}:{effect.site.event_index}"
            )
        result[effect.site] = effect
    return result


def _origin_from_json(raw: Any, *, context: str) -> ValueOrigin:
    return parse_value_origin(raw, context=context)


def _finite_value_from_json(
    raw: Any, *, finite_value_budget: int, context: str
) -> frozenset[ValueOrigin]:
    return parse_finite_value(
        raw,
        finite_value_budget=finite_value_budget,
        context=f"{context} origins",
    )


def _origin_sort_key(origin: ValueOrigin) -> tuple[str, str, tuple[str, ...]]:
    return (origin.kind, repr(origin.key), origin.dependencies)


def _object(raw: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{context} must be an object")
    return raw


def _sequence(raw: Any, context: str) -> Sequence[Any]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError(f"{context} must be an array")
    return raw


def _require_keys(
    raw: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    context: str,
) -> None:
    missing = required - set(raw)
    unknown = set(raw) - required - set(optional or ())
    if missing:
        raise ValueError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _string_set(raw: Any, context: str) -> set[str]:
    return set(_string_tuple(raw, context))


def _string_tuple(raw: Any, context: str) -> tuple[str, ...]:
    values = _sequence(raw, context)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{context} must contain non-empty strings")
    result = tuple(str(value) for value in values)
    if tuple(sorted(set(result))) != result:
        raise ValueError(f"{context} must be sorted and unique")
    return result


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


__all__ = [
    "CALL_EFFECT_REGISTERS",
    "CALL_SITE_EFFECT_FORMAT",
    "CallOutput",
    "CallSiteEffect",
    "CallSiteId",
    "CallWriteSpan",
    "parse_call_site_effect",
    "parse_call_site_effects",
]
