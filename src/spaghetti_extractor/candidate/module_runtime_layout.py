"""Typed linked layout metadata for the shared module runtime state."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Iterable, Mapping

from .formats import SPX_RUNTIME_STATE_LAYOUT_FORMAT


SPX_RUNTIME_STATE_LAYOUT_MAGIC_BYTES = b"SRSL"
SPX_RUNTIME_STATE_LAYOUT_MAGIC = int.from_bytes(
    SPX_RUNTIME_STATE_LAYOUT_MAGIC_BYTES, "little"
)
SPX_RUNTIME_STATE_LAYOUT_VERSION = 1
SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS = 10
SPX_RUNTIME_STATE_LAYOUT_RECORD_WORDS = 4
SPX_RUNTIME_STATE_LAYOUT_TABLE_SYMBOL = "spx_runtime_state_layout_table"
SPX_RUNTIME_STATE_LAYOUT_SECTION = ".rdata$SRSL"

_MAX_FIELD_COUNT = 64
_MAX_X87_SLOT_COUNT = 32
_UINT32_MAX = (1 << 32) - 1
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_C_MEMBER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[[0-9]+\])?)*\Z"
)
_C_HEADER = re.compile(r"[A-Za-z0-9_./+-]+\Z")


class RuntimeStateLayoutFormatError(ValueError):
    """An extracted runtime-state-layout table is malformed or incomplete."""


class RuntimeStateRegister(IntEnum):
    EAX = 0
    EBX = 1
    ECX = 2
    EDX = 3
    ESI = 4
    EDI = 5
    EBP = 6
    ESP = 7


class RuntimeStateFlag(IntEnum):
    CF = 0
    PF = 2
    ZF = 6
    SF = 7
    DF = 10
    OF = 11


class RuntimeStateFieldKind(IntEnum):
    REGISTER = 1
    EFLAGS = 2
    FLAG = 3
    X87_STACK = 4
    X87_CONTROL = 5
    X87_STATUS = 6
    FS_BASE = 7
    ORIGINAL_RVA = 8
    X87_EMPTY = 9
    X87_TAG = 10
    X87_PENDING_EXCEPTION = 11
    X87_LAST_OPCODE = 12
    X87_INSTRUCTION_POINTER = 13
    X87_CODE_SELECTOR = 14
    X87_DATA_POINTER = 15
    X87_DATA_SELECTOR = 16


class RuntimeStateLayoutFeature(IntFlag):
    SPLIT_FLAGS = 1 << 0
    PACKED_EFLAGS = 1 << 1
    FS_BASE = 1 << 2
    ORIGINAL_RVA = 1 << 3


_KNOWN_FEATURES = (
    RuntimeStateLayoutFeature.SPLIT_FLAGS
    | RuntimeStateLayoutFeature.PACKED_EFLAGS
    | RuntimeStateLayoutFeature.FS_BASE
    | RuntimeStateLayoutFeature.ORIGINAL_RVA
)


@dataclass(frozen=True)
class RuntimeStateField:
    """A canonical semantic identity, independent of its C member spelling."""

    kind: RuntimeStateFieldKind
    index: int = 0

    def __post_init__(self) -> None:
        try:
            kind = RuntimeStateFieldKind(self.kind)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unknown runtime-state field kind {self.kind!r}") from exc
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise ValueError("runtime-state field index must be an integer")
        object.__setattr__(self, "kind", kind)

        if kind == RuntimeStateFieldKind.REGISTER:
            try:
                RuntimeStateRegister(self.index)
            except ValueError as exc:
                raise ValueError(f"unknown runtime-state register index {self.index}") from exc
        elif kind == RuntimeStateFieldKind.FLAG:
            try:
                RuntimeStateFlag(self.index)
            except ValueError as exc:
                raise ValueError(f"unknown runtime-state flag bit {self.index}") from exc
        elif kind in {
            RuntimeStateFieldKind.X87_STACK,
            RuntimeStateFieldKind.X87_EMPTY,
            RuntimeStateFieldKind.X87_TAG,
        }:
            if not 0 <= self.index < _MAX_X87_SLOT_COUNT:
                raise ValueError(
                    f"{kind.name.lower()} index must be below {_MAX_X87_SLOT_COUNT}"
                )
        elif self.index != 0:
            raise ValueError(f"{kind.name.lower()} field index must be zero")

    @classmethod
    def register(cls, register: RuntimeStateRegister) -> RuntimeStateField:
        return cls(RuntimeStateFieldKind.REGISTER, int(register))

    @classmethod
    def flag(cls, flag: RuntimeStateFlag) -> RuntimeStateField:
        return cls(RuntimeStateFieldKind.FLAG, int(flag))

    @classmethod
    def x87_stack(cls, index: int) -> RuntimeStateField:
        return cls(RuntimeStateFieldKind.X87_STACK, index)

    @classmethod
    def x87_empty(cls, index: int) -> RuntimeStateField:
        return cls(RuntimeStateFieldKind.X87_EMPTY, index)

    @classmethod
    def x87_tag(cls, index: int) -> RuntimeStateField:
        return cls(RuntimeStateFieldKind.X87_TAG, index)

    @property
    def name(self) -> str:
        if self.kind == RuntimeStateFieldKind.REGISTER:
            return f"register:{RuntimeStateRegister(self.index).name.lower()}"
        if self.kind == RuntimeStateFieldKind.FLAG:
            return f"flag:{RuntimeStateFlag(self.index).name.lower()}"
        if self.kind == RuntimeStateFieldKind.X87_STACK:
            return f"x87_stack:{self.index}"
        if self.kind == RuntimeStateFieldKind.X87_EMPTY:
            return f"x87_empty:{self.index}"
        if self.kind == RuntimeStateFieldKind.X87_TAG:
            return f"x87_tag:{self.index}"
        return self.kind.name.lower()


@dataclass(frozen=True)
class RuntimeStateLayoutCField:
    field: RuntimeStateField
    member: str

    def __post_init__(self) -> None:
        if not isinstance(self.field, RuntimeStateField):
            raise TypeError("layout C field must use an RuntimeStateField identity")
        if not isinstance(self.member, str) or _C_MEMBER.fullmatch(self.member) is None:
            raise ValueError(f"invalid C member designator {self.member!r}")


@dataclass(frozen=True)
class RuntimeStateLayoutCSpec:
    """C bindings whose offsets and sizes must be materialized by the compiler."""

    fields: tuple[RuntimeStateLayoutCField, ...]
    x87_slot_count: int = 8
    runtime_header: str = "state-machine-runtime.h"
    state_type: str = "spx_machine_state"
    table_symbol: str = SPX_RUNTIME_STATE_LAYOUT_TABLE_SYMBOL

    def __post_init__(self) -> None:
        fields = tuple(self.fields)
        object.__setattr__(self, "fields", tuple(sorted(fields, key=_c_field_sort_key)))
        _validate_c_token(self.runtime_header, _C_HEADER, "runtime header")
        _validate_c_token(self.state_type, _C_IDENTIFIER, "state type")
        _validate_c_token(self.table_symbol, _C_IDENTIFIER, "table symbol")
        _features_for_fields(self.fields, self.x87_slot_count)

    @property
    def features(self) -> RuntimeStateLayoutFeature:
        return _features_for_fields(self.fields, self.x87_slot_count)


@dataclass(frozen=True)
class RuntimeStateFieldLayout:
    field: RuntimeStateField
    offset: int
    size: int

    @property
    def stop(self) -> int:
        return self.offset + self.size


@dataclass(frozen=True)
class RuntimeStateLayout:
    """Structurally checked layout data with no proof or acceptance authority."""

    version: int
    state_size: int
    x87_slot_count: int
    features: RuntimeStateLayoutFeature
    fields: tuple[RuntimeStateFieldLayout, ...]

    def field_layout(self, field: RuntimeStateField) -> RuntimeStateFieldLayout:
        matches = [entry for entry in self.fields if entry.field == field]
        if len(matches) != 1:
            raise KeyError(field.name)
        return matches[0]

    @property
    def fields_by_identity(self) -> dict[RuntimeStateField, RuntimeStateFieldLayout]:
        return {entry.field: entry for entry in self.fields}


def canonical_spx_machine_state_spec(
    *,
    runtime_header: str = "state-machine-runtime.h",
    state_type: str = "spx_machine_state",
    table_symbol: str = SPX_RUNTIME_STATE_LAYOUT_TABLE_SYMBOL,
    flag_storage: str = "split-and-packed",
    x87_slot_count: int = 8,
    include_fs_base: bool = False,
    include_original_rva: bool = False,
    member_overrides: Mapping[RuntimeStateField, str] | None = None,
) -> RuntimeStateLayoutCSpec:
    """Build canonical semantic bindings for a spx_machine_state variant."""

    if flag_storage not in {"split", "packed", "split-and-packed"}:
        raise ValueError(
            "flag_storage must be 'split', 'packed', or 'split-and-packed'"
        )
    if isinstance(x87_slot_count, bool) or not isinstance(x87_slot_count, int):
        raise ValueError("x87 slot count must be an integer")
    if not 1 <= x87_slot_count <= _MAX_X87_SLOT_COUNT:
        raise ValueError(
            f"x87 slot count must be between 1 and {_MAX_X87_SLOT_COUNT}"
        )

    fields: list[RuntimeStateLayoutCField] = [
        RuntimeStateLayoutCField(RuntimeStateField.register(register), register.name.lower())
        for register in RuntimeStateRegister
    ]
    if flag_storage in {"split", "split-and-packed"}:
        fields.extend(
            RuntimeStateLayoutCField(RuntimeStateField.flag(flag), flag.name.lower())
            for flag in RuntimeStateFlag
        )
    if flag_storage in {"packed", "split-and-packed"}:
        fields.append(RuntimeStateLayoutCField(RuntimeStateField(RuntimeStateFieldKind.EFLAGS), "eflags"))
    fields.extend(
        RuntimeStateLayoutCField(
            RuntimeStateField.x87_stack(index), f"x87_stack[{index}].value_bytes"
        )
        for index in range(x87_slot_count)
    )
    fields.extend(
        RuntimeStateLayoutCField(
            RuntimeStateField.x87_empty(index), f"x87_stack[{index}].empty"
        )
        for index in range(x87_slot_count)
    )
    fields.extend(
        RuntimeStateLayoutCField(
            RuntimeStateField.x87_tag(index), f"x87_stack[{index}].tag"
        )
        for index in range(x87_slot_count)
    )
    fields.extend(
        (
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_CONTROL), "x87_control"
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_STATUS), "x87_status"
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_PENDING_EXCEPTION),
                "x87_pending_exception",
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_LAST_OPCODE), "x87_last_opcode"
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_INSTRUCTION_POINTER),
                "x87_instruction_pointer",
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_CODE_SELECTOR),
                "x87_code_selector",
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_DATA_POINTER), "x87_data_pointer"
            ),
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.X87_DATA_SELECTOR),
                "x87_data_selector",
            ),
        )
    )
    if include_fs_base:
        fields.append(RuntimeStateLayoutCField(RuntimeStateField(RuntimeStateFieldKind.FS_BASE), "fs_base"))
    if include_original_rva:
        fields.append(
            RuntimeStateLayoutCField(
                RuntimeStateField(RuntimeStateFieldKind.ORIGINAL_RVA), "original_rva"
            )
        )

    if member_overrides:
        known = {entry.field for entry in fields}
        unknown = set(member_overrides) - known
        if unknown:
            names = ", ".join(sorted(field.name for field in unknown))
            raise ValueError(f"member overrides name fields absent from the schema: {names}")
        fields = [
            RuntimeStateLayoutCField(entry.field, member_overrides.get(entry.field, entry.member))
            for entry in fields
        ]
    return RuntimeStateLayoutCSpec(
        fields=tuple(fields),
        x87_slot_count=x87_slot_count,
        runtime_header=runtime_header,
        state_type=state_type,
        table_symbol=table_symbol,
    )


def render_spx_runtime_state_layout_c(
    spec: RuntimeStateLayoutCSpec | None = None,
    *,
    runtime_header: str = "state-machine-runtime.h",
    state_type: str = "spx_machine_state",
    table_symbol: str = SPX_RUNTIME_STATE_LAYOUT_TABLE_SYMBOL,
    flag_storage: str = "split-and-packed",
    x87_slot_count: int = 8,
    include_fs_base: bool = False,
    include_original_rva: bool = False,
    member_overrides: Mapping[RuntimeStateField, str] | None = None,
) -> str:
    """Render deterministic C which materializes one layout table."""

    if spec is None:
        spec = canonical_spx_machine_state_spec(
            runtime_header=runtime_header,
            state_type=state_type,
            table_symbol=table_symbol,
            flag_storage=flag_storage,
            x87_slot_count=x87_slot_count,
            include_fs_base=include_fs_base,
            include_original_rva=include_original_rva,
            member_overrides=member_overrides,
        )
    elif (
        runtime_header != "state-machine-runtime.h"
        or state_type != "spx_machine_state"
        or table_symbol != SPX_RUNTIME_STATE_LAYOUT_TABLE_SYMBOL
        or flag_storage != "split-and-packed"
        or x87_slot_count != 8
        or include_fs_base
        or include_original_rva
        or member_overrides is not None
    ):
        raise ValueError("schema options cannot be combined with an explicit C spec")
    if not isinstance(spec, RuntimeStateLayoutCSpec):
        raise TypeError("spec must be an RuntimeStateLayoutCSpec")

    fields = spec.fields
    features = spec.features
    total_words = (
        SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS
        + SPX_RUNTIME_STATE_LAYOUT_RECORD_WORDS * len(fields)
    )
    lines = [
        "/* Generated candidate reconstruction semantic-runtime-state layout metadata.",
        " * This table is structural data only and has no proof or acceptance authority.",
        " */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        f'#include "{spec.runtime_header}"',
        "",
        "#if defined(_MSC_VER)",
        f'#pragma section("{SPX_RUNTIME_STATE_LAYOUT_SECTION}", read)',
        "#define SPX_RUNTIME_STATE_LAYOUT_READ_ONLY \\",
        f'  __declspec(allocate("{SPX_RUNTIME_STATE_LAYOUT_SECTION}"))',
        "#elif defined(__GNUC__) || defined(__clang__)",
        "#define SPX_RUNTIME_STATE_LAYOUT_READ_ONLY \\",
        f'  __attribute__((used, section("{SPX_RUNTIME_STATE_LAYOUT_SECTION}"), aligned(4)))',
        "#else",
        "#define SPX_RUNTIME_STATE_LAYOUT_READ_ONLY",
        "#endif",
        "",
        f"_Static_assert(sizeof({spec.state_type}) <= UINT32_MAX,",
        '    "spx_machine_state size does not fit the layout table");',
    ]
    for entry in fields:
        lines.extend(
            (
                f"_Static_assert(offsetof({spec.state_type}, {entry.member})",
                f"        + sizeof((({spec.state_type} *)0)->{entry.member})",
                f"        <= sizeof({spec.state_type}),",
                f'    "layout member {entry.field.name} is outside spx_machine_state");',
            )
        )
    lines.extend(
        (
            "",
            "SPX_RUNTIME_STATE_LAYOUT_READ_ONLY",
            f"const uint32_t {spec.table_symbol}[{total_words}] = {{",
            f"  0x{SPX_RUNTIME_STATE_LAYOUT_MAGIC:08x}U, /* magic: SRSL */",
            f"  {SPX_RUNTIME_STATE_LAYOUT_VERSION}U, /* version */",
            f"  {total_words}U, /* total words */",
            f"  {SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS}U, /* header words */",
            f"  {SPX_RUNTIME_STATE_LAYOUT_RECORD_WORDS}U, /* words per field */",
            f"  {len(fields)}U, /* field count */",
            f"  (uint32_t)sizeof({spec.state_type}), /* state size */",
            f"  {spec.x87_slot_count}U, /* x87 slot count */",
            f"  {int(features)}U, /* feature flags */",
            "  0U, /* reserved */",
        )
    )
    for entry in fields:
        lines.extend(
            (
                f"  /* {entry.field.name} */",
                f"  {int(entry.field.kind)}U, {entry.field.index}U,",
                f"  (uint32_t)offsetof({spec.state_type}, {entry.member}),",
                f"  (uint32_t)sizeof((({spec.state_type} *)0)->{entry.member}),",
            )
        )
    lines.extend(
        (
            "};",
            "",
            f"const uint32_t {spec.table_symbol}_word_count = {total_words}U;",
            "",
            "#undef SPX_RUNTIME_STATE_LAYOUT_READ_ONLY",
            "",
        )
    )
    return "\n".join(lines)


def parse_spx_runtime_state_layout_payload(
    payload: bytes | bytearray | memoryview,
    *,
    required_fields: Iterable[RuntimeStateField] = (),
    expected_features: RuntimeStateLayoutFeature | None = None,
    expected_x87_slot_count: int | None = None,
) -> RuntimeStateLayout:
    """Parse exact little-endian table bytes extracted from a candidate image."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("runtime-state-layout payload must be bytes-like")
    data = bytes(payload)
    minimum_size = SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS * 4
    maximum_size = (
        SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS
        + SPX_RUNTIME_STATE_LAYOUT_RECORD_WORDS * _MAX_FIELD_COUNT
    ) * 4
    if len(data) < minimum_size:
        raise RuntimeStateLayoutFormatError("runtime-state-layout payload is shorter than its header")
    if len(data) > maximum_size:
        raise RuntimeStateLayoutFormatError("runtime-state-layout payload exceeds the field-count bound")
    if len(data) % 4:
        raise RuntimeStateLayoutFormatError("runtime-state-layout payload is not uint32-aligned")

    words = struct.unpack(f"<{len(data) // 4}I", data)
    (
        magic,
        version,
        total_words,
        header_words,
        record_words,
        field_count,
        state_size,
        x87_slot_count,
        raw_features,
        reserved,
    ) = words[:SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS]
    if magic != SPX_RUNTIME_STATE_LAYOUT_MAGIC:
        raise RuntimeStateLayoutFormatError("runtime-state-layout magic does not match SRSL")
    if version != SPX_RUNTIME_STATE_LAYOUT_VERSION:
        raise RuntimeStateLayoutFormatError(f"unsupported runtime-state-layout version {version}")
    if header_words != SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS:
        raise RuntimeStateLayoutFormatError("runtime-state-layout header size is not canonical")
    if record_words != SPX_RUNTIME_STATE_LAYOUT_RECORD_WORDS:
        raise RuntimeStateLayoutFormatError("runtime-state-layout field-record size is not canonical")
    if total_words != len(words):
        raise RuntimeStateLayoutFormatError("runtime-state-layout declared size does not match its payload")
    expected_words = header_words + record_words * field_count
    if total_words != expected_words:
        raise RuntimeStateLayoutFormatError("runtime-state-layout field count does not match its size")
    if field_count == 0 or field_count > _MAX_FIELD_COUNT:
        raise RuntimeStateLayoutFormatError("runtime-state-layout field count is outside its bound")
    if state_size == 0:
        raise RuntimeStateLayoutFormatError("runtime-state-layout state size must be nonzero")
    if reserved != 0:
        raise RuntimeStateLayoutFormatError("runtime-state-layout reserved header word must be zero")
    if raw_features & ~int(_KNOWN_FEATURES):
        raise RuntimeStateLayoutFormatError("runtime-state-layout contains unknown feature flags")
    features = RuntimeStateLayoutFeature(raw_features)
    flag_modes = features & (
        RuntimeStateLayoutFeature.SPLIT_FLAGS | RuntimeStateLayoutFeature.PACKED_EFLAGS
    )
    if flag_modes == 0:
        raise RuntimeStateLayoutFormatError(
            "runtime-state-layout must declare at least one flag-storage mode"
        )
    if not 1 <= x87_slot_count <= _MAX_X87_SLOT_COUNT:
        raise RuntimeStateLayoutFormatError("runtime-state-layout x87 slot count is outside its bound")
    if expected_features is not None and features != expected_features:
        raise RuntimeStateLayoutFormatError(
            f"runtime-state-layout features {int(features)} do not match expected "
            f"features {int(expected_features)}"
        )
    if (
        expected_x87_slot_count is not None
        and x87_slot_count != expected_x87_slot_count
    ):
        raise RuntimeStateLayoutFormatError(
            "runtime-state-layout x87 slot count does not match the expected count"
        )

    fields: list[RuntimeStateFieldLayout] = []
    identities: set[RuntimeStateField] = set()
    cursor = header_words
    for record_index in range(field_count):
        kind_value, index, offset, size = words[cursor : cursor + record_words]
        cursor += record_words
        try:
            field = RuntimeStateField(RuntimeStateFieldKind(kind_value), index)
        except ValueError as exc:
            raise RuntimeStateLayoutFormatError(
                f"runtime-state-layout field record {record_index} has an invalid identity"
            ) from exc
        if field in identities:
            raise RuntimeStateLayoutFormatError(
                f"runtime-state-layout contains duplicate field {field.name}"
            )
        identities.add(field)
        if size == 0:
            raise RuntimeStateLayoutFormatError(
                f"runtime-state-layout field {field.name} has zero size"
            )
        expected_size = _field_byte_width(field)
        if size != expected_size:
            raise RuntimeStateLayoutFormatError(
                f"runtime-state-layout field {field.name} has size {size}, expected "
                f"{expected_size}"
            )
        stop = offset + size
        if stop > _UINT32_MAX or stop > state_size:
            raise RuntimeStateLayoutFormatError(
                f"runtime-state-layout field {field.name} is outside the state bounds"
            )
        fields.append(RuntimeStateFieldLayout(field=field, offset=offset, size=size))

    canonical = tuple(sorted(fields, key=_layout_sort_key))
    if tuple(fields) != canonical:
        raise RuntimeStateLayoutFormatError("runtime-state-layout field records are not canonical")
    _require_exact_schema(identities, features, x87_slot_count)

    required = tuple(required_fields)
    if any(not isinstance(field, RuntimeStateField) for field in required):
        raise TypeError("required_fields must contain RuntimeStateField values")
    missing_required = set(required) - identities
    if missing_required:
        names = ", ".join(sorted(field.name for field in missing_required))
        raise RuntimeStateLayoutFormatError(
            f"runtime-state-layout is missing caller-required fields: {names}"
        )

    by_offset = sorted(fields, key=lambda entry: (entry.offset, entry.stop))
    for previous, current in zip(by_offset, by_offset[1:]):
        if current.offset < previous.stop:
            raise RuntimeStateLayoutFormatError(
                "runtime-state-layout fields overlap: "
                f"{previous.field.name} and {current.field.name}"
            )
    return RuntimeStateLayout(
        version=version,
        state_size=state_size,
        x87_slot_count=x87_slot_count,
        features=features,
        fields=tuple(fields),
    )




def _validate_c_token(value: str, pattern: re.Pattern[str], label: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"invalid C {label} {value!r}")


def _field_sort_key(field: RuntimeStateField) -> tuple[int, int]:
    order = {
        RuntimeStateFieldKind.REGISTER: 0,
        RuntimeStateFieldKind.EFLAGS: 1,
        RuntimeStateFieldKind.FLAG: 2,
        RuntimeStateFieldKind.X87_STACK: 3,
        RuntimeStateFieldKind.X87_EMPTY: 4,
        RuntimeStateFieldKind.X87_TAG: 5,
        RuntimeStateFieldKind.X87_CONTROL: 6,
        RuntimeStateFieldKind.X87_STATUS: 7,
        RuntimeStateFieldKind.X87_PENDING_EXCEPTION: 8,
        RuntimeStateFieldKind.X87_LAST_OPCODE: 9,
        RuntimeStateFieldKind.X87_INSTRUCTION_POINTER: 10,
        RuntimeStateFieldKind.X87_CODE_SELECTOR: 11,
        RuntimeStateFieldKind.X87_DATA_POINTER: 12,
        RuntimeStateFieldKind.X87_DATA_SELECTOR: 13,
        RuntimeStateFieldKind.FS_BASE: 14,
        RuntimeStateFieldKind.ORIGINAL_RVA: 15,
    }
    return order[field.kind], field.index


def _c_field_sort_key(entry: RuntimeStateLayoutCField) -> tuple[int, int]:
    return _field_sort_key(entry.field)


def _layout_sort_key(entry: RuntimeStateFieldLayout) -> tuple[int, int]:
    return _field_sort_key(entry.field)


def _expected_fields(
    features: RuntimeStateLayoutFeature, x87_slot_count: int
) -> set[RuntimeStateField]:
    result = {RuntimeStateField.register(register) for register in RuntimeStateRegister}
    if features & RuntimeStateLayoutFeature.SPLIT_FLAGS:
        result.update(RuntimeStateField.flag(flag) for flag in RuntimeStateFlag)
    if features & RuntimeStateLayoutFeature.PACKED_EFLAGS:
        result.add(RuntimeStateField(RuntimeStateFieldKind.EFLAGS))
    result.update(RuntimeStateField.x87_stack(index) for index in range(x87_slot_count))
    result.update(RuntimeStateField.x87_empty(index) for index in range(x87_slot_count))
    result.update(RuntimeStateField.x87_tag(index) for index in range(x87_slot_count))
    result.update(
        {
            RuntimeStateField(RuntimeStateFieldKind.X87_CONTROL),
            RuntimeStateField(RuntimeStateFieldKind.X87_STATUS),
            RuntimeStateField(RuntimeStateFieldKind.X87_PENDING_EXCEPTION),
            RuntimeStateField(RuntimeStateFieldKind.X87_LAST_OPCODE),
            RuntimeStateField(RuntimeStateFieldKind.X87_INSTRUCTION_POINTER),
            RuntimeStateField(RuntimeStateFieldKind.X87_CODE_SELECTOR),
            RuntimeStateField(RuntimeStateFieldKind.X87_DATA_POINTER),
            RuntimeStateField(RuntimeStateFieldKind.X87_DATA_SELECTOR),
        }
    )
    if features & RuntimeStateLayoutFeature.FS_BASE:
        result.add(RuntimeStateField(RuntimeStateFieldKind.FS_BASE))
    if features & RuntimeStateLayoutFeature.ORIGINAL_RVA:
        result.add(RuntimeStateField(RuntimeStateFieldKind.ORIGINAL_RVA))
    return result


def _field_byte_width(field: RuntimeStateField) -> int:
    if field.kind == RuntimeStateFieldKind.X87_STACK:
        return 10
    if field.kind in {
        RuntimeStateFieldKind.X87_TAG,
        RuntimeStateFieldKind.X87_PENDING_EXCEPTION,
    }:
        return 1
    if field.kind in {
        RuntimeStateFieldKind.X87_CONTROL,
        RuntimeStateFieldKind.X87_STATUS,
        RuntimeStateFieldKind.X87_LAST_OPCODE,
        RuntimeStateFieldKind.X87_CODE_SELECTOR,
        RuntimeStateFieldKind.X87_DATA_SELECTOR,
    }:
        return 2
    return 4


def _require_exact_schema(
    actual: set[RuntimeStateField],
    features: RuntimeStateLayoutFeature,
    x87_slot_count: int,
) -> None:
    expected = _expected_fields(features, x87_slot_count)
    missing = expected - actual
    unexpected = actual - expected
    if not missing and not unexpected:
        return
    details: list[str] = []
    if missing:
        details.append("missing " + ", ".join(sorted(field.name for field in missing)))
    if unexpected:
        details.append(
            "unexpected " + ", ".join(sorted(field.name for field in unexpected))
        )
    raise RuntimeStateLayoutFormatError("runtime-state-layout schema is incomplete: " + "; ".join(details))


def _features_for_fields(
    fields: tuple[RuntimeStateLayoutCField, ...], x87_slot_count: int
) -> RuntimeStateLayoutFeature:
    if isinstance(x87_slot_count, bool) or not isinstance(x87_slot_count, int):
        raise ValueError("x87 slot count must be an integer")
    if not 1 <= x87_slot_count <= _MAX_X87_SLOT_COUNT:
        raise ValueError(
            f"x87 slot count must be between 1 and {_MAX_X87_SLOT_COUNT}"
        )
    if not fields or len(fields) > _MAX_FIELD_COUNT:
        raise ValueError("layout C field count is outside its bound")
    identities = [entry.field for entry in fields]
    if len(set(identities)) != len(identities):
        raise ValueError("layout C fields contain duplicate semantic identities")
    members = [entry.member for entry in fields]
    if len(set(members)) != len(members):
        raise ValueError("layout C fields contain duplicate member designators")

    identity_set = set(identities)
    has_split = any(field.kind == RuntimeStateFieldKind.FLAG for field in identity_set)
    has_packed = RuntimeStateField(RuntimeStateFieldKind.EFLAGS) in identity_set
    if not has_split and not has_packed:
        raise ValueError("layout C fields must use at least one flag-storage mode")
    features = RuntimeStateLayoutFeature(0)
    if has_split:
        features |= RuntimeStateLayoutFeature.SPLIT_FLAGS
    if has_packed:
        features |= RuntimeStateLayoutFeature.PACKED_EFLAGS
    if RuntimeStateField(RuntimeStateFieldKind.FS_BASE) in identity_set:
        features |= RuntimeStateLayoutFeature.FS_BASE
    if RuntimeStateField(RuntimeStateFieldKind.ORIGINAL_RVA) in identity_set:
        features |= RuntimeStateLayoutFeature.ORIGINAL_RVA
    expected = _expected_fields(features, x87_slot_count)
    if identity_set != expected:
        missing = expected - identity_set
        unexpected = identity_set - expected
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(sorted(field.name for field in missing)))
        if unexpected:
            details.append(
                "unexpected "
                + ", ".join(sorted(field.name for field in unexpected))
            )
        raise ValueError("layout C field schema is incomplete: " + "; ".join(details))
    return features


__all__ = [
    "RuntimeStateField",
    "RuntimeStateFieldKind",
    "RuntimeStateFieldLayout",
    "RuntimeStateFlag",
    "RuntimeStateLayout",
    "RuntimeStateLayoutCField",
    "RuntimeStateLayoutCSpec",
    "RuntimeStateLayoutFeature",
    "RuntimeStateLayoutFormatError",
    "RuntimeStateRegister",
    "SPX_RUNTIME_STATE_LAYOUT_FORMAT",
    "SPX_RUNTIME_STATE_LAYOUT_HEADER_WORDS",
    "SPX_RUNTIME_STATE_LAYOUT_MAGIC",
    "SPX_RUNTIME_STATE_LAYOUT_MAGIC_BYTES",
    "SPX_RUNTIME_STATE_LAYOUT_RECORD_WORDS",
    "SPX_RUNTIME_STATE_LAYOUT_SECTION",
    "SPX_RUNTIME_STATE_LAYOUT_TABLE_SYMBOL",
    "SPX_RUNTIME_STATE_LAYOUT_VERSION",
    "canonical_spx_machine_state_spec",
    "parse_spx_runtime_state_layout_payload",
    "render_spx_runtime_state_layout_c",
]
