"""Strict, table-driven instruction metadata for PE32 ISA qualification.

The catalog is deliberately semantic-name agnostic.  Enriched ``form_id`` and
``encoding_id`` values are opaque identities.  Raw pinned XED table rows are
canonicalized into semantic identities while preserving decoder-table aliases.
Corpus generation dispatches only on reviewed effect classes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
from typing import Any, TypeAlias

from . import conformance
from .conformance import (
    ControlClass,
    DefinedOutputMasks,
    GPR_NAMES,
    ISAConformanceError,
    MAX_X86_INSTRUCTION_BYTES,
)


ISA_FORM_CATALOG_FORMAT = "spaghetti-extractor-isa-form-catalog-v2"
ISA_FORM_CATALOG_ENTRY_FORMAT = "pe32-i686-form-v2"
XED_INSTRUCTION_CATALOG_FORMAT = "spaghetti-extractor-xed-inst-catalog-v1"
ISA_PROFILE_ID = "pe32-i686-v1"
SUPPORTED_WIDTHS = frozenset({8, 16, 32})
MAX_MEMORY_EFFECT_WIDTH_BITS = 4096


class EffectClass(str, Enum):
    NOOP = "noop"
    REGISTER = "register"
    STATE = "state"
    MEMORY = "memory"
    BRANCH = "branch"
    DIVIDE = "divide"
    X87 = "x87"


class AccessMode(str, Enum):
    READ = "read"
    WRITE = "write"
    READ_WRITE = "read_write"


class AddressSegment(str, Enum):
    FLAT = "flat"
    FS = "fs"


class StateComponent(str, Enum):
    EFLAGS = "eflags"
    FS = "fs"


class PredicateKind(str, Enum):
    EFLAGS = "eflags"
    REGISTER = "register"


class ControlTargetKind(str, Enum):
    FIXED = "fixed"
    REGISTER = "register"
    MEMORY = "memory"


class BranchScenario(str, Enum):
    TAKEN = "taken"
    NOT_TAKEN = "not_taken"


class ProfileDisposition(str, Enum):
    CORE = "core"
    SEPARATELY_QUALIFIED = "separately_qualified"
    EXTERNAL_PLATFORM = "external_platform"
    EXCLUDED_UNSUPPORTED = "excluded_unsupported"


class DispositionReason(str, Enum):
    CORE_STATE = "core_integer_control_memory_state"
    EXTERNAL_EVENT_CATEGORY = "external_event_category"
    UNSUPPORTED_SYSTEM_CATEGORY = "unsupported_system_category"
    PRIVILEGED_ATTRIBUTE = "privileged_attribute"
    PRIVILEGED_OPERAND_CLASS = "privileged_operand_class"
    X87_STATE = "x87_state"
    COMPLEX_FLAG_STATE = "complex_flag_state"
    AMBIGUOUS_SPECIAL_STATE_CATEGORY = "ambiguous_special_state_category"


@dataclass(frozen=True)
class CatalogSource:
    extractor: str
    version: str
    input_sha256: str


@dataclass(frozen=True)
class AddressExpression:
    base: str | None
    index: str | None
    scale: int
    displacement: int
    segment: AddressSegment


@dataclass(frozen=True)
class RegisterLocation:
    register: str
    lsb: int


@dataclass(frozen=True)
class InputPredicate:
    kind: PredicateKind
    mask: int
    value: int
    width_bits: int
    location: RegisterLocation | None


@dataclass(frozen=True)
class RegisterInputValue:
    """A little-endian initial memory value read from an input register slice."""

    location: RegisterLocation
    width_bits: int
    kind: str = "register"


@dataclass(frozen=True)
class MemoryReplayControl:
    """Finite replay strategy for data-dependent repeated memory effects."""

    count_location: RegisterLocation
    count_width_bits: int
    stop_value: RegisterInputValue


@dataclass(frozen=True)
class FixedControlTarget:
    target_eip: int
    kind: ControlTargetKind = ControlTargetKind.FIXED


@dataclass(frozen=True)
class RegisterControlTarget:
    location: RegisterLocation
    kind: ControlTargetKind = ControlTargetKind.REGISTER


@dataclass(frozen=True)
class MemoryControlTarget:
    address: AddressExpression
    kind: ControlTargetKind = ControlTargetKind.MEMORY


ControlTarget: TypeAlias = (
    FixedControlTarget | RegisterControlTarget | MemoryControlTarget
)


@dataclass(frozen=True)
class BranchOutcome:
    scenario: BranchScenario
    eflags_mask: int
    eflags_value: int
    control: ControlClass
    target: ControlTarget | None


@dataclass(frozen=True)
class NoOpEffect:
    id: str
    effect_class: EffectClass = EffectClass.NOOP


@dataclass(frozen=True)
class RegisterEffect:
    id: str
    width_bits: int
    reads: tuple[RegisterLocation, ...]
    writes: tuple[RegisterLocation, ...]
    effect_class: EffectClass = EffectClass.REGISTER


@dataclass(frozen=True)
class StateEffect:
    id: str
    state: StateComponent
    access: AccessMode
    effect_class: EffectClass = EffectClass.STATE


@dataclass(frozen=True)
class MemoryEffect:
    id: str
    width_bits: int
    access: AccessMode
    address: AddressExpression
    condition: InputPredicate | None
    replay_control: MemoryReplayControl | None = None
    effect_class: EffectClass = EffectClass.MEMORY


@dataclass(frozen=True)
class BranchEffect:
    id: str
    outcomes: tuple[BranchOutcome, ...]
    effect_class: EffectClass = EffectClass.BRANCH


@dataclass(frozen=True)
class DivideEffect:
    id: str
    width_bits: int
    signed: bool
    dividend_high: RegisterLocation
    dividend_low: RegisterLocation
    divisor: RegisterLocation | AddressExpression
    effect_class: EffectClass = EffectClass.DIVIDE


@dataclass(frozen=True)
class X87Effect:
    id: str
    stack_inputs: int
    stack_outputs: int
    effect_class: EffectClass = EffectClass.X87


InstructionEffect: TypeAlias = (
    NoOpEffect
    | RegisterEffect
    | StateEffect
    | MemoryEffect
    | BranchEffect
    | DivideEffect
    | X87Effect
)


@dataclass(frozen=True)
class ISAFormCatalogEntry:
    form_id: str
    encoding_id: str
    instruction_bytes: bytes
    required_features: tuple[str, ...]
    effects: tuple[InstructionEffect, ...]
    defined_outputs: DefinedOutputMasks
    format: str = ISA_FORM_CATALOG_ENTRY_FORMAT


@dataclass(frozen=True)
class ISAFormCatalog:
    source: CatalogSource
    entries: tuple[ISAFormCatalogEntry, ...]
    profile: str = ISA_PROFILE_ID
    format: str = ISA_FORM_CATALOG_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAFormCatalog":
        return parse_isa_form_catalog(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_isa_form_catalog(self)


@dataclass(frozen=True)
class XEDCatalogGenerator:
    name: str
    xed_version: str


@dataclass(frozen=True)
class XEDCatalogProfile:
    id: str
    chip: str
    machine_mode: str
    stack_address_width: int
    privilege: str


@dataclass(frozen=True)
class XEDOperandTemplate:
    name: str
    visibility: str
    action: str
    width: str
    xtype: str
    type: str
    nonterminal: str
    register: str
    immediate: int | None


@dataclass(frozen=True)
class XEDInstructionTemplate:
    table_indices: tuple[int, ...]
    form_id: str
    iform: str
    iclass: str
    category: str
    extension: str
    isa_set: str
    cpl: int
    exception: str
    flag_info_index: int
    flag_complex: bool
    attributes: tuple[str, ...]
    operands: tuple[XEDOperandTemplate, ...]
    disposition: ProfileDisposition
    disposition_reasons: tuple[DispositionReason, ...]

    @property
    def table_index(self) -> int:
        """Return the first source alias for concise diagnostics."""
        return self.table_indices[0]


@dataclass(frozen=True)
class XEDInstructionCatalog:
    generator: XEDCatalogGenerator
    profile: XEDCatalogProfile
    templates: tuple[XEDInstructionTemplate, ...]
    format: str = XED_INSTRUCTION_CATALOG_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "XEDInstructionCatalog":
        return parse_xed_instruction_catalog(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_xed_instruction_catalog(self)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAConformanceError(f"{context} must be an object")
    return value


def _objects(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise ISAConformanceError(f"{context} must be a list of objects")
    return list(value)


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str
) -> None:
    missing = expected - set(payload)
    unknown = set(payload) - expected
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append(f"missing fields {sorted(missing)!r}")
    if unknown:
        details.append(f"unknown fields {sorted(unknown, key=str)!r}")
    raise ISAConformanceError(f"{context} has " + " and ".join(details))


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ISAConformanceError(
            f"{context} must be a non-empty string without surrounding whitespace"
        )
    return value


def _possibly_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or any(ord(character) < 0x20 for character in value):
        raise ISAConformanceError(f"{context} must be a string")
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ISAConformanceError(f"{context} must be a lowercase SHA-256 digest")
    return digest


def _uint(value: Any, bits: int, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**bits
    ):
        raise ISAConformanceError(f"{context} must be an unsigned {bits}-bit integer")
    return value


def _signed32(value: Any, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not -(2**31) <= value < 2**31
    ):
        raise ISAConformanceError(f"{context} must be a signed 32-bit integer")
    return value


def _small_count(value: Any, context: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise ISAConformanceError(
            f"{context} must be an integer in the range 0..{maximum}"
        )
    return value


def _enum(enum_type: type[Enum], value: Any, context: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ISAConformanceError(f"{context} is unsupported") from exc


def _width(value: Any, context: str) -> int:
    width = _uint(value, 8, context)
    if width not in SUPPORTED_WIDTHS:
        raise ISAConformanceError(
            f"{context} must be one of {sorted(SUPPORTED_WIDTHS)}"
        )
    return width


def _memory_width(value: Any, context: str) -> int:
    width = _uint(value, 16, context)
    if (
        width < 8
        or width > MAX_MEMORY_EFFECT_WIDTH_BITS
        or width % 8
    ):
        raise ISAConformanceError(
            f"{context} must be a byte-aligned width from 8 through "
            f"{MAX_MEMORY_EFFECT_WIDTH_BITS}"
        )
    return width


def _register(value: Any, context: str) -> str:
    register = _string(value, context)
    if register not in GPR_NAMES:
        raise ISAConformanceError(
            f"{context} must name a canonical 32-bit general register"
        )
    return register


def _parse_register_location(
    value: Any,
    context: str,
    *,
    width_bits: int,
    allow_legacy_name: bool,
) -> RegisterLocation:
    if isinstance(value, str):
        if not allow_legacy_name:
            raise ISAConformanceError(f"{context} must be a register location object")
        return RegisterLocation(register=_register(value, context), lsb=0)
    payload = _object(value, context)
    _exact_fields(payload, {"register", "lsb"}, context)
    lsb = _uint(payload.get("lsb"), 5, f"{context}.lsb")
    if lsb % 8:
        raise ISAConformanceError(f"{context}.lsb must be byte-aligned")
    if lsb + width_bits > 32:
        raise ISAConformanceError(
            f"{context} extends beyond its canonical 32-bit register"
        )
    return RegisterLocation(
        register=_register(payload.get("register"), f"{context}.register"),
        lsb=lsb,
    )


def _register_locations(
    value: Any,
    context: str,
    *,
    width_bits: int,
    allow_empty: bool,
    allow_legacy_names: bool,
) -> tuple[RegisterLocation, ...]:
    if not isinstance(value, list):
        raise ISAConformanceError(f"{context} must be a list")
    result = tuple(
        _parse_register_location(
            item,
            f"{context}[{index}]",
            width_bits=width_bits,
            allow_legacy_name=allow_legacy_names,
        )
        for index, item in enumerate(value)
    )
    if not allow_empty and not result:
        raise ISAConformanceError(f"{context} must not be empty")
    if list(result) != sorted(
        set(result), key=lambda location: (location.register, location.lsb)
    ):
        raise ISAConformanceError(
            f"{context} must be unique and canonically ordered"
        )
    return result


def _parse_predicate(value: Any, context: str) -> InputPredicate:
    payload = _object(value, context)
    kind = _enum(PredicateKind, payload.get("kind"), f"{context}.kind")
    if kind is PredicateKind.EFLAGS:
        _exact_fields(payload, {"kind", "mask", "value"}, context)
        width = 32
        location = None
    else:
        _exact_fields(
            payload,
            {"kind", "location", "width_bits", "mask", "value"},
            context,
        )
        width = _width(payload.get("width_bits"), f"{context}.width_bits")
        location = _parse_register_location(
            payload.get("location"),
            f"{context}.location",
            width_bits=width,
            allow_legacy_name=False,
        )
    mask = _uint(payload.get("mask"), width, f"{context}.mask")
    predicate_value = _uint(payload.get("value"), width, f"{context}.value")
    if mask == 0:
        raise ISAConformanceError(f"{context}.mask must not be zero")
    if predicate_value & ~mask:
        raise ISAConformanceError(f"{context}.value sets bits outside mask")
    return InputPredicate(
        kind=kind,
        mask=mask,
        value=predicate_value,
        width_bits=width,
        location=location,
    )


def _parse_source(value: Any, context: str) -> CatalogSource:
    payload = _object(value, context)
    _exact_fields(payload, {"extractor", "version", "input_sha256"}, context)
    return CatalogSource(
        extractor=_string(payload.get("extractor"), f"{context}.extractor"),
        version=_string(payload.get("version"), f"{context}.version"),
        input_sha256=_sha256(
            payload.get("input_sha256"), f"{context}.input_sha256"
        ),
    )


def _parse_address(value: Any, context: str) -> AddressExpression:
    payload = _object(value, context)
    _exact_fields(
        payload, {"base", "index", "scale", "displacement", "segment"}, context
    )
    raw_base = payload.get("base")
    raw_index = payload.get("index")
    base = None if raw_base is None else _register(raw_base, f"{context}.base")
    index = None if raw_index is None else _register(raw_index, f"{context}.index")
    scale = _uint(payload.get("scale"), 4, f"{context}.scale")
    if scale not in {1, 2, 4, 8}:
        raise ISAConformanceError(f"{context}.scale must be one of [1, 2, 4, 8]")
    if index is None and scale != 1:
        raise ISAConformanceError(f"{context}.scale must be 1 without an index")
    return AddressExpression(
        base=base,
        index=index,
        scale=scale,
        displacement=_signed32(
            payload.get("displacement"), f"{context}.displacement"
        ),
        segment=_enum(
            AddressSegment, payload.get("segment"), f"{context}.segment"
        ),
    )


def _parse_control_target(value: Any, context: str) -> ControlTarget:
    payload = _object(value, context)
    kind = _enum(ControlTargetKind, payload.get("kind"), f"{context}.kind")
    if kind is ControlTargetKind.FIXED:
        _exact_fields(payload, {"kind", "target_eip"}, context)
        return FixedControlTarget(
            target_eip=_uint(payload.get("target_eip"), 32, f"{context}.target_eip")
        )
    if kind is ControlTargetKind.REGISTER:
        _exact_fields(payload, {"kind", "location"}, context)
        return RegisterControlTarget(
            location=_parse_register_location(
                payload.get("location"),
                f"{context}.location",
                width_bits=32,
                allow_legacy_name=False,
            )
        )
    _exact_fields(payload, {"kind", "address"}, context)
    return MemoryControlTarget(
        address=_parse_address(payload.get("address"), f"{context}.address")
    )


def _parse_branch_outcome(
    value: Any,
    context: str,
    *,
    legacy: bool,
    allow_legacy_v2: bool,
) -> BranchOutcome:
    payload = _object(value, context)
    common_fields = {
        "scenario",
        "eflags_mask",
        "eflags_value",
        "control",
    }
    uses_legacy_target = legacy or (
        allow_legacy_v2 and "target_eip" in payload and "target" not in payload
    )
    _exact_fields(
        payload,
        common_fields | ({"target_eip"} if uses_legacy_target else {"target"}),
        context,
    )
    scenario = _enum(
        BranchScenario, payload.get("scenario"), f"{context}.scenario"
    )
    mask = _uint(payload.get("eflags_mask"), 32, f"{context}.eflags_mask")
    flag_value = _uint(
        payload.get("eflags_value"), 32, f"{context}.eflags_value"
    )
    if flag_value & ~mask:
        raise ISAConformanceError(
            f"{context}.eflags_value sets bits outside eflags_mask"
        )
    control = _enum(ControlClass, payload.get("control"), f"{context}.control")
    raw_target = payload.get("target_eip" if uses_legacy_target else "target")
    if raw_target is None:
        target: ControlTarget | None = None
    elif uses_legacy_target:
        target = FixedControlTarget(
            _uint(raw_target, 32, f"{context}.target_eip")
        )
    else:
        target = _parse_control_target(raw_target, f"{context}.target")
    if scenario is BranchScenario.NOT_TAKEN:
        if control is not ControlClass.FALLTHROUGH or target is not None:
            raise ISAConformanceError(
                f"{context} not_taken must be fallthrough without a target"
            )
    elif control in {ControlClass.FALLTHROUGH, ControlClass.FAULT}:
        raise ISAConformanceError(
            f"{context} taken must use a non-fault control transfer"
        )
    elif control is ControlClass.RETURN:
        if target is not None:
            raise ISAConformanceError(
                f"{context} return control must not declare a target"
            )
    elif control in {ControlClass.DIRECT_BRANCH, ControlClass.DIRECT_CALL}:
        if not isinstance(target, FixedControlTarget):
            raise ISAConformanceError(
                f"{context} direct control requires a fixed target"
            )
    elif control in {ControlClass.INDIRECT_BRANCH, ControlClass.INDIRECT_CALL}:
        if not isinstance(target, (RegisterControlTarget, MemoryControlTarget)):
            raise ISAConformanceError(
                f"{context} indirect control requires a register or memory target"
            )
    elif target is None:
        raise ISAConformanceError(
            f"{context} taken control transfer requires target_eip"
        )
    return BranchOutcome(scenario, mask, flag_value, control, target)


def _locations_overlap(
    left: RegisterLocation,
    left_width: int,
    right: RegisterLocation,
    right_width: int,
) -> bool:
    return (
        left.register == right.register
        and left.lsb < right.lsb + right_width
        and right.lsb < left.lsb + left_width
    )


def _parse_divisor(
    value: Any,
    context: str,
    *,
    width_bits: int,
    allow_legacy_name: bool,
) -> RegisterLocation | AddressExpression:
    if isinstance(value, str):
        if not allow_legacy_name:
            raise ISAConformanceError(f"{context} must be a divisor source object")
        return _parse_register_location(
            value,
            context,
            width_bits=width_bits,
            allow_legacy_name=True,
        )
    payload = _object(value, context)
    raw_kind = payload.get("kind")
    if raw_kind == "register":
        _exact_fields(payload, {"kind", "location"}, context)
        return _parse_register_location(
            payload.get("location"),
            f"{context}.location",
            width_bits=width_bits,
            allow_legacy_name=False,
        )
    if raw_kind == "memory":
        _exact_fields(payload, {"kind", "address"}, context)
        return _parse_address(payload.get("address"), f"{context}.address")
    raise ISAConformanceError(f"{context}.kind is unsupported")


def _parse_input_value(
    value: Any,
    context: str,
    *,
    width_bits: int,
) -> RegisterInputValue:
    payload = _object(value, context)
    _exact_fields(payload, {"kind", "location", "width_bits"}, context)
    if payload.get("kind") != "register":
        raise ISAConformanceError(f"{context}.kind is unsupported")
    source_width = _memory_width(
        payload.get("width_bits"), f"{context}.width_bits"
    )
    if source_width != width_bits or source_width > 32:
        raise ISAConformanceError(
            f"{context}.width_bits must equal the memory effect width and fit a GPR"
        )
    return RegisterInputValue(
        location=_parse_register_location(
            payload.get("location"),
            f"{context}.location",
            width_bits=source_width,
            allow_legacy_name=False,
        ),
        width_bits=source_width,
    )


def _parse_memory_replay_control(
    value: Any,
    context: str,
    *,
    memory_width_bits: int,
) -> MemoryReplayControl:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"count_location", "count_width_bits", "stop_value"},
        context,
    )
    count_width = _width(
        payload.get("count_width_bits"), f"{context}.count_width_bits"
    )
    return MemoryReplayControl(
        count_location=_parse_register_location(
            payload.get("count_location"),
            f"{context}.count_location",
            width_bits=count_width,
            allow_legacy_name=False,
        ),
        count_width_bits=count_width,
        stop_value=_parse_input_value(
            payload.get("stop_value"),
            f"{context}.stop_value",
            width_bits=memory_width_bits,
        ),
    )


def _parse_effect(
    value: Any,
    context: str,
    *,
    legacy: bool,
    allow_legacy_v2: bool,
) -> InstructionEffect:
    payload = _object(value, context)
    effect_class = _enum(EffectClass, payload.get("class"), f"{context}.class")
    effect_id = _string(payload.get("id"), f"{context}.id")
    if effect_class is EffectClass.NOOP:
        if legacy:
            raise ISAConformanceError(f"{context}.class is unsupported by catalog v1")
        _exact_fields(payload, {"class", "id"}, context)
        return NoOpEffect(id=effect_id)
    if effect_class is EffectClass.REGISTER:
        _exact_fields(
            payload, {"class", "id", "width_bits", "reads", "writes"}, context
        )
        width = _width(payload.get("width_bits"), f"{context}.width_bits")
        allow_legacy_names = legacy or allow_legacy_v2
        reads = _register_locations(
            payload.get("reads"),
            f"{context}.reads",
            width_bits=width,
            allow_empty=True,
            allow_legacy_names=allow_legacy_names,
        )
        writes = _register_locations(
            payload.get("writes"),
            f"{context}.writes",
            width_bits=width,
            allow_empty=True,
            allow_legacy_names=allow_legacy_names,
        )
        if not reads and not writes:
            raise ISAConformanceError(
                f"{context} register effect must read or write a register"
            )
        return RegisterEffect(
            id=effect_id,
            width_bits=width,
            reads=reads,
            writes=writes,
        )
    if effect_class is EffectClass.STATE:
        if legacy:
            raise ISAConformanceError(f"{context}.class is unsupported by catalog v1")
        _exact_fields(payload, {"class", "id", "state", "access"}, context)
        return StateEffect(
            id=effect_id,
            state=_enum(
                StateComponent, payload.get("state"), f"{context}.state"
            ),
            access=_enum(AccessMode, payload.get("access"), f"{context}.access"),
        )
    if effect_class is EffectClass.MEMORY:
        has_condition = "condition" in payload
        has_replay_control = "replay_control" in payload
        expected_fields = {"class", "id", "width_bits", "access", "address"}
        if not legacy and (has_condition or not allow_legacy_v2):
            expected_fields.add("condition")
        if has_replay_control:
            if legacy:
                raise ISAConformanceError(
                    f"{context}.replay_control is unsupported by catalog v1"
                )
            expected_fields.add("replay_control")
        _exact_fields(payload, expected_fields, context)
        width_bits = (
            _width(payload.get("width_bits"), f"{context}.width_bits")
            if legacy
            else _memory_width(
                payload.get("width_bits"), f"{context}.width_bits"
            )
        )
        return MemoryEffect(
            id=effect_id,
            width_bits=width_bits,
            access=_enum(AccessMode, payload.get("access"), f"{context}.access"),
            address=_parse_address(payload.get("address"), f"{context}.address"),
            condition=(
                None
                if not has_condition or payload.get("condition") is None
                else _parse_predicate(
                    payload.get("condition"), f"{context}.condition"
                )
            ),
            replay_control=(
                None
                if not has_replay_control
                else _parse_memory_replay_control(
                    payload.get("replay_control"),
                    f"{context}.replay_control",
                    memory_width_bits=width_bits,
                )
            ),
        )
    if effect_class is EffectClass.BRANCH:
        _exact_fields(payload, {"class", "id", "outcomes"}, context)
        outcomes = tuple(
            _parse_branch_outcome(
                row,
                f"{context}.outcomes[{index}]",
                legacy=legacy,
                allow_legacy_v2=allow_legacy_v2,
            )
            for index, row in enumerate(
                _objects(payload.get("outcomes"), f"{context}.outcomes")
            )
        )
        if not outcomes:
            raise ISAConformanceError(f"{context}.outcomes must not be empty")
        scenarios = [outcome.scenario.value for outcome in outcomes]
        if scenarios != sorted(set(scenarios)):
            raise ISAConformanceError(
                f"{context}.outcomes must have unique, canonical scenarios"
            )
        return BranchEffect(id=effect_id, outcomes=outcomes)
    if effect_class is EffectClass.DIVIDE:
        _exact_fields(
            payload,
            {
                "class",
                "id",
                "width_bits",
                "signed",
                "dividend_high",
                "dividend_low",
                "divisor",
            },
            context,
        )
        signed = payload.get("signed")
        if not isinstance(signed, bool):
            raise ISAConformanceError(f"{context}.signed must be a boolean")
        width = _width(payload.get("width_bits"), f"{context}.width_bits")
        if legacy and width == 8:
            raise ISAConformanceError(
                f"{context}.width_bits=8 requires subregister dividend locations "
                "not represented by this catalog version"
            )
        allow_legacy_names = legacy or allow_legacy_v2
        high = _parse_register_location(
            payload.get("dividend_high"),
            f"{context}.dividend_high",
            width_bits=width,
            allow_legacy_name=allow_legacy_names,
        )
        low = _parse_register_location(
            payload.get("dividend_low"),
            f"{context}.dividend_low",
            width_bits=width,
            allow_legacy_name=allow_legacy_names,
        )
        divisor = _parse_divisor(
            payload.get("divisor"),
            f"{context}.divisor",
            width_bits=width,
            allow_legacy_name=allow_legacy_names,
        )
        if _locations_overlap(high, width, low, width):
            raise ISAConformanceError(
                f"{context} dividend locations must not overlap"
            )
        if isinstance(divisor, RegisterLocation) and (
            _locations_overlap(divisor, width, high, width)
            or _locations_overlap(divisor, width, low, width)
        ):
            raise ISAConformanceError(
                f"{context} register divisor must not overlap the dividend"
            )
        return DivideEffect(
            id=effect_id,
            width_bits=width,
            signed=signed,
            dividend_high=high,
            dividend_low=low,
            divisor=divisor,
        )
    if effect_class is EffectClass.X87:
        _exact_fields(
            payload, {"class", "id", "stack_inputs", "stack_outputs"}, context
        )
        return X87Effect(
            id=effect_id,
            stack_inputs=_small_count(
                payload.get("stack_inputs"), f"{context}.stack_inputs", 8
            ),
            stack_outputs=_small_count(
                payload.get("stack_outputs"), f"{context}.stack_outputs", 8
            ),
        )
    raise AssertionError("unreachable effect class")


def _parse_entry(value: Any, context: str) -> ISAFormCatalogEntry:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "encoding_id",
            "instruction_bytes",
            "required_features",
            "effects",
            "defined_outputs",
        },
        context,
    )
    entry_format = payload.get("format")
    if entry_format != ISA_FORM_CATALOG_ENTRY_FORMAT:
        raise ISAConformanceError(f"{context}.format is unsupported")
    raw_bytes = payload.get("instruction_bytes")
    if not isinstance(raw_bytes, list) or not raw_bytes:
        raise ISAConformanceError(f"{context}.instruction_bytes must not be empty")
    instruction_bytes = bytes(
        _uint(byte, 8, f"{context}.instruction_bytes[{index}]")
        for index, byte in enumerate(raw_bytes)
    )
    if len(instruction_bytes) > MAX_X86_INSTRUCTION_BYTES:
        raise ISAConformanceError(
            f"{context}.instruction_bytes exceeds the x86 15-byte limit"
        )
    raw_features = payload.get("required_features")
    if not isinstance(raw_features, list):
        raise ISAConformanceError(f"{context}.required_features must be a list")
    features = tuple(
        _string(item, f"{context}.required_features[{index}]")
        for index, item in enumerate(raw_features)
    )
    if list(features) != sorted(set(features)):
        raise ISAConformanceError(
            f"{context}.required_features must be unique and canonically ordered"
        )
    effects = tuple(
        _parse_effect(
            row,
            f"{context}.effects[{index}]",
            legacy=False,
            allow_legacy_v2=False,
        )
        for index, row in enumerate(
            _objects(payload.get("effects"), f"{context}.effects")
        )
    )
    if not effects:
        raise ISAConformanceError(f"{context}.effects must not be empty")
    effect_ids = [effect.id for effect in effects]
    if effect_ids != sorted(set(effect_ids)):
        raise ISAConformanceError(
            f"{context}.effects must have unique, canonically ordered IDs"
        )
    noop_count = sum(isinstance(effect, NoOpEffect) for effect in effects)
    if noop_count and (noop_count != 1 or len(effects) != 1):
        raise ISAConformanceError(
            f"{context} no-op must be the entry's sole effect"
        )
    if sum(isinstance(effect, BranchEffect) for effect in effects) > 1:
        raise ISAConformanceError(f"{context} supports at most one branch effect")
    if sum(isinstance(effect, DivideEffect) for effect in effects) > 1:
        raise ISAConformanceError(f"{context} supports at most one divide effect")
    if sum(isinstance(effect, X87Effect) for effect in effects) > 1:
        raise ISAConformanceError(f"{context} supports at most one x87 effect")
    defined_outputs = conformance._parse_defined_outputs(
        payload.get("defined_outputs"), f"{context}.defined_outputs"
    )
    if defined_outputs.memory:
        raise ISAConformanceError(
            f"{context}.defined_outputs.memory must be empty; generated addresses "
            "are derived from memory effects"
        )
    return ISAFormCatalogEntry(
        form_id=_string(payload.get("form_id"), f"{context}.form_id"),
        encoding_id=_string(payload.get("encoding_id"), f"{context}.encoding_id"),
        instruction_bytes=instruction_bytes,
        required_features=features,
        effects=effects,
        defined_outputs=defined_outputs,
        format=entry_format,
    )


def parse_isa_form_catalog(value: Any) -> ISAFormCatalog:
    """Parse enriched executable-form JSON into a strict profile catalog."""
    payload = _object(value, "ISA form catalog")
    _exact_fields(
        payload, {"format", "profile", "source", "entries"}, "ISA form catalog"
    )
    catalog_format = payload.get("format")
    if catalog_format != ISA_FORM_CATALOG_FORMAT:
        raise ISAConformanceError("unsupported ISA form catalog format")
    if payload.get("profile") != ISA_PROFILE_ID:
        raise ISAConformanceError(
            f"ISA form catalog.profile must be {ISA_PROFILE_ID}"
        )
    entries = tuple(
        _parse_entry(row, f"ISA form catalog.entries[{index}]")
        for index, row in enumerate(
            _objects(payload.get("entries"), "ISA form catalog.entries")
        )
    )
    if not entries:
        raise ISAConformanceError("ISA form catalog.entries must not be empty")
    if any(entry.format != ISA_FORM_CATALOG_ENTRY_FORMAT for entry in entries):
        raise ISAConformanceError(
            "ISA form catalog entries do not match the catalog schema version"
        )
    form_ids = [entry.form_id for entry in entries]
    if form_ids != sorted(set(form_ids)):
        raise ISAConformanceError(
            "ISA form catalog.entries must have unique, canonically ordered form IDs"
        )
    encoding_ids = [entry.encoding_id for entry in entries]
    if len(encoding_ids) != len(set(encoding_ids)):
        raise ISAConformanceError(
            "ISA form catalog.entries contain duplicate encoding IDs"
        )
    return ISAFormCatalog(
        source=_parse_source(payload.get("source"), "ISA form catalog.source"),
        entries=entries,
        format=catalog_format,
    )


def _address_payload(address: AddressExpression) -> dict[str, Any]:
    return {
        "base": address.base,
        "index": address.index,
        "scale": address.scale,
        "displacement": address.displacement,
        "segment": address.segment.value,
    }


def _register_location_payload(location: RegisterLocation) -> dict[str, Any]:
    return {"register": location.register, "lsb": location.lsb}


def _predicate_payload(predicate: InputPredicate) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": predicate.kind.value,
        "mask": predicate.mask,
        "value": predicate.value,
    }
    if predicate.kind is PredicateKind.REGISTER:
        if predicate.location is None:
            raise ISAConformanceError("register predicate has no location")
        payload = {
            "kind": predicate.kind.value,
            "location": _register_location_payload(predicate.location),
            "width_bits": predicate.width_bits,
            "mask": predicate.mask,
            "value": predicate.value,
        }
    return payload


def _control_target_payload(target: ControlTarget) -> dict[str, Any]:
    if isinstance(target, FixedControlTarget):
        return {"kind": target.kind.value, "target_eip": target.target_eip}
    if isinstance(target, RegisterControlTarget):
        return {
            "kind": target.kind.value,
            "location": _register_location_payload(target.location),
        }
    if isinstance(target, MemoryControlTarget):
        return {
            "kind": target.kind.value,
            "address": _address_payload(target.address),
        }
    raise ISAConformanceError("unsupported typed control target")


def _outcome_payload(
    outcome: BranchOutcome, *, legacy: bool
) -> dict[str, Any]:
    payload = {
        "scenario": outcome.scenario.value,
        "eflags_mask": outcome.eflags_mask,
        "eflags_value": outcome.eflags_value,
        "control": outcome.control.value,
    }
    if legacy:
        if outcome.target is not None and not isinstance(
            outcome.target, FixedControlTarget
        ):
            raise ISAConformanceError(
                "catalog v1 cannot serialize a dynamic control target"
            )
        payload["target_eip"] = (
            None
            if outcome.target is None
            else outcome.target.target_eip
        )
    else:
        payload["target"] = (
            None
            if outcome.target is None
            else _control_target_payload(outcome.target)
        )
    return payload


def _effect_payload(
    effect: InstructionEffect, *, legacy: bool
) -> dict[str, Any]:
    if isinstance(effect, NoOpEffect):
        if legacy:
            raise ISAConformanceError("catalog v1 cannot serialize a no-op effect")
        return {"class": effect.effect_class.value, "id": effect.id}
    if isinstance(effect, RegisterEffect):
        if legacy and any(
            location.lsb != 0 for location in (*effect.reads, *effect.writes)
        ):
            raise ISAConformanceError(
                "catalog v1 cannot serialize subregister locations"
            )
        return {
            "class": effect.effect_class.value,
            "id": effect.id,
            "width_bits": effect.width_bits,
            "reads": (
                [location.register for location in effect.reads]
                if legacy
                else [
                    _register_location_payload(location)
                    for location in effect.reads
                ]
            ),
            "writes": (
                [location.register for location in effect.writes]
                if legacy
                else [
                    _register_location_payload(location)
                    for location in effect.writes
                ]
            ),
        }
    if isinstance(effect, StateEffect):
        if legacy:
            raise ISAConformanceError("catalog v1 cannot serialize a state effect")
        return {
            "class": effect.effect_class.value,
            "id": effect.id,
            "state": effect.state.value,
            "access": effect.access.value,
        }
    if isinstance(effect, MemoryEffect):
        if legacy and (
            effect.condition is not None
            or effect.replay_control is not None
            or effect.width_bits not in SUPPORTED_WIDTHS
        ):
            raise ISAConformanceError(
                "catalog v1 cannot serialize this memory effect"
            )
        payload = {
            "class": effect.effect_class.value,
            "id": effect.id,
            "width_bits": effect.width_bits,
            "access": effect.access.value,
            "address": _address_payload(effect.address),
        }
        if not legacy:
            payload["condition"] = (
                None
                if effect.condition is None
                else _predicate_payload(effect.condition)
            )
            if effect.replay_control is not None:
                replay = effect.replay_control
                payload["replay_control"] = {
                    "count_location": _register_location_payload(
                        replay.count_location
                    ),
                    "count_width_bits": replay.count_width_bits,
                    "stop_value": {
                        "kind": replay.stop_value.kind,
                        "location": _register_location_payload(
                            replay.stop_value.location
                        ),
                        "width_bits": replay.stop_value.width_bits,
                    },
                }
        return payload
    if isinstance(effect, BranchEffect):
        return {
            "class": effect.effect_class.value,
            "id": effect.id,
            "outcomes": [
                _outcome_payload(outcome, legacy=legacy)
                for outcome in effect.outcomes
            ],
        }
    if isinstance(effect, DivideEffect):
        if legacy and (
            effect.width_bits == 8
            or effect.dividend_high.lsb != 0
            or effect.dividend_low.lsb != 0
            or not isinstance(effect.divisor, RegisterLocation)
            or effect.divisor.lsb != 0
        ):
            raise ISAConformanceError(
                "catalog v1 cannot serialize this divide effect"
            )
        if isinstance(effect.divisor, RegisterLocation):
            divisor: Any = (
                effect.divisor.register
                if legacy
                else {
                    "kind": "register",
                    "location": _register_location_payload(effect.divisor),
                }
            )
        else:
            divisor = {
                "kind": "memory",
                "address": _address_payload(effect.divisor),
            }
        return {
            "class": effect.effect_class.value,
            "id": effect.id,
            "width_bits": effect.width_bits,
            "signed": effect.signed,
            "dividend_high": (
                effect.dividend_high.register
                if legacy
                else _register_location_payload(effect.dividend_high)
            ),
            "dividend_low": (
                effect.dividend_low.register
                if legacy
                else _register_location_payload(effect.dividend_low)
            ),
            "divisor": divisor,
        }
    if isinstance(effect, X87Effect):
        return {
            "class": effect.effect_class.value,
            "id": effect.id,
            "stack_inputs": effect.stack_inputs,
            "stack_outputs": effect.stack_outputs,
        }
    raise ISAConformanceError("unsupported typed instruction effect")


def _entry_payload(entry: ISAFormCatalogEntry) -> dict[str, Any]:
    if entry.format != ISA_FORM_CATALOG_ENTRY_FORMAT:
        raise ISAConformanceError("catalog entry has an unsupported format")
    return {
        "format": entry.format,
        "form_id": entry.form_id,
        "encoding_id": entry.encoding_id,
        "instruction_bytes": list(entry.instruction_bytes),
        "required_features": list(entry.required_features),
        "effects": [
            _effect_payload(effect, legacy=False) for effect in entry.effects
        ],
        "defined_outputs": conformance._defined_outputs_payload(
            entry.defined_outputs
        ),
    }


def serialize_isa_form_catalog(catalog: ISAFormCatalog) -> dict[str, Any]:
    if not isinstance(catalog, ISAFormCatalog):
        raise ISAConformanceError("catalog must be an ISAFormCatalog")
    payload = {
        "format": catalog.format,
        "profile": catalog.profile,
        "source": {
            "extractor": catalog.source.extractor,
            "version": catalog.source.version,
            "input_sha256": catalog.source.input_sha256,
        },
        "entries": [_entry_payload(entry) for entry in catalog.entries],
    }
    if parse_isa_form_catalog(payload) != catalog:
        raise ISAConformanceError("catalog is not a valid typed instance")
    return payload


def canonical_isa_form_catalog_input(catalog: ISAFormCatalog) -> bytes:
    payload = serialize_isa_form_catalog(catalog)
    return (
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        + b"\n"
    )


def isa_form_catalog_sha256(catalog: ISAFormCatalog) -> str:
    return hashlib.sha256(canonical_isa_form_catalog_input(catalog)).hexdigest()

# Imported after the shared catalog types are initialized so XED parsing can
# route public monkeypatches through this module without a compatibility shim.
from .catalog_xed import (
    canonical_xed_instruction_catalog_input,
    derive_xed_profile_disposition,
    parse_isa_catalog,
    parse_xed_instruction_catalog,
    serialize_xed_instruction_catalog,
    xed_instruction_catalog_sha256,
    xed_template_form_id_from_fields,
)

__all__ = [
    "AccessMode",
    "AddressExpression",
    "AddressSegment",
    "BranchEffect",
    "BranchOutcome",
    "BranchScenario",
    "CatalogSource",
    "ControlTarget",
    "ControlTargetKind",
    "DispositionReason",
    "DivideEffect",
    "EffectClass",
    "FixedControlTarget",
    "InputPredicate",
    "RegisterInputValue",
    "ISA_FORM_CATALOG_ENTRY_FORMAT",
    "ISA_FORM_CATALOG_FORMAT",
    "ISA_PROFILE_ID",
    "ISAFormCatalog",
    "ISAFormCatalogEntry",
    "InstructionEffect",
    "MAX_MEMORY_EFFECT_WIDTH_BITS",
    "MemoryControlTarget",
    "MemoryEffect",
    "MemoryReplayControl",
    "NoOpEffect",
    "PredicateKind",
    "ProfileDisposition",
    "RegisterControlTarget",
    "RegisterEffect",
    "RegisterLocation",
    "StateComponent",
    "StateEffect",
    "XEDCatalogGenerator",
    "XEDCatalogProfile",
    "XEDInstructionCatalog",
    "XEDInstructionTemplate",
    "XEDOperandTemplate",
    "XED_INSTRUCTION_CATALOG_FORMAT",
    "X87Effect",
    "canonical_isa_form_catalog_input",
    "canonical_xed_instruction_catalog_input",
    "derive_xed_profile_disposition",
    "isa_form_catalog_sha256",
    "parse_isa_catalog",
    "parse_isa_form_catalog",
    "parse_xed_instruction_catalog",
    "serialize_isa_form_catalog",
    "serialize_xed_instruction_catalog",
    "xed_instruction_catalog_sha256",
    "xed_template_form_id_from_fields",
]
