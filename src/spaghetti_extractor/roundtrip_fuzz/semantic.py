from __future__ import annotations

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, TypeAlias

from ..stage_binary import StageAInputError
from .model import _exact_fields, _identifier, _integer, _nonempty_string, _object


ROUNDTRIP_SEMANTIC_PROGRAM_FORMAT = "stage-a-roundtrip-semantic-program-v1"


class ValueKind(str, Enum):
    CONSTANT = "constant"
    REGISTER = "register"
    STATIC_ADDRESS = "static_address"


@dataclass(frozen=True)
class ScalarValue:
    kind: ValueKind
    width: int
    value: int | str

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ScalarValue":
        _exact_fields(payload, {"kind", "width", "value"}, context)
        try:
            kind = ValueKind(payload["kind"])
        except (TypeError, ValueError) as exc:
            raise StageAInputError(f"{context}.kind is unsupported") from exc
        width = _integer(payload["width"], f"{context}.width", minimum=1)
        if width not in {8, 16, 32}:
            raise StageAInputError(f"{context}.width must be 8, 16, or 32")
        if kind is ValueKind.CONSTANT:
            value: int | str = _integer(payload["value"], f"{context}.value")
            if value >= 2**width:
                raise StageAInputError(f"{context}.value does not fit its width")
        else:
            value = _identifier(payload["value"], f"{context}.value")
            if kind is ValueKind.REGISTER:
                value = _register_name(value, f"{context}.value")
        return cls(kind=kind, width=width, value=value)

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "width": self.width, "value": self.value}


@dataclass(frozen=True)
class AdjustStack:
    bytes: int
    kind: str = "adjust_stack"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "AdjustStack":
        _exact_fields(payload, {"kind", "bytes"}, context)
        byte_count = payload["bytes"]
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count == 0
            or not -(2**31) < byte_count < 2**31
            or byte_count % 4 != 0
        ):
            raise StageAInputError(f"{context}.bytes must be a nonzero aligned delta")
        return cls(bytes=byte_count)

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "bytes": self.bytes}


@dataclass(frozen=True)
class StoreStack:
    offset: int
    value: ScalarValue
    kind: str = "store_stack"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "StoreStack":
        _exact_fields(payload, {"kind", "offset", "value"}, context)
        offset = payload["offset"]
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not -(2**31) < offset < 2**31
            or offset % 4 != 0
        ):
            raise StageAInputError(f"{context}.offset must be a word-aligned signed value")
        value = ScalarValue.parse(
            _object(payload["value"], f"{context}.value"),
            context=f"{context}.value",
        )
        if value.width != 32:
            raise StageAInputError(f"{context}.value must be a 32-bit word")
        return cls(offset=offset, value=value)

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "offset": self.offset, "value": self.value.to_payload()}


@dataclass(frozen=True)
class Nop:
    kind: str = "nop"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "Nop":
        _exact_fields(payload, {"kind"}, context)
        return cls()

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind}


@dataclass(frozen=True)
class StackArithmetic:
    offset: int
    operator: str
    immediate: int
    kind: str = "stack_arithmetic"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "StackArithmetic":
        _exact_fields(payload, {"kind", "offset", "operator", "immediate"}, context)
        offset = _stack_offset(payload["offset"], f"{context}.offset")
        operator = payload["operator"]
        if operator not in {"add", "sub", "xor"}:
            raise StageAInputError(f"{context}.operator is unsupported")
        immediate = _integer(payload["immediate"], f"{context}.immediate")
        if immediate >= 2**32:
            raise StageAInputError(f"{context}.immediate must be a 32-bit word")
        return cls(offset=offset, operator=str(operator), immediate=immediate)

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "operator": self.operator,
            "immediate": self.immediate,
        }


@dataclass(frozen=True)
class CompareStack:
    offset: int
    immediate: int
    kind: str = "compare_stack"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "CompareStack":
        _exact_fields(payload, {"kind", "offset", "immediate"}, context)
        immediate = _integer(payload["immediate"], f"{context}.immediate")
        if immediate >= 2**32:
            raise StageAInputError(f"{context}.immediate must be a 32-bit word")
        return cls(
            offset=_stack_offset(payload["offset"], f"{context}.offset"),
            immediate=immediate,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "offset": self.offset, "immediate": self.immediate}


@dataclass(frozen=True)
class AssignRegister:
    register: str
    value: ScalarValue
    kind: str = "assign_register"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "AssignRegister":
        _exact_fields(payload, {"kind", "register", "value"}, context)
        value = ScalarValue.parse(
            _object(payload["value"], f"{context}.value"),
            context=f"{context}.value",
        )
        if value.width != 32:
            raise StageAInputError(f"{context}.value must be a 32-bit word")
        return cls(
            register=_register_name(payload["register"], f"{context}.register"),
            value=value,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "register": self.register,
            "value": self.value.to_payload(),
        }


@dataclass(frozen=True)
class RegisterArithmetic:
    register: str
    operator: str
    immediate: int
    kind: str = "register_arithmetic"

    @classmethod
    def parse(
        cls, payload: Mapping[str, Any], *, context: str,
    ) -> "RegisterArithmetic":
        _exact_fields(payload, {"kind", "register", "operator", "immediate"}, context)
        operator = payload["operator"]
        if operator not in {"add", "sub", "xor"}:
            raise StageAInputError(f"{context}.operator is unsupported")
        immediate = _integer(payload["immediate"], f"{context}.immediate")
        if immediate >= 2**32:
            raise StageAInputError(f"{context}.immediate must be a 32-bit word")
        return cls(
            register=_register_name(payload["register"], f"{context}.register"),
            operator=str(operator),
            immediate=immediate,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "register": self.register,
            "operator": self.operator,
            "immediate": self.immediate,
        }


@dataclass(frozen=True)
class CompareRegister:
    register: str
    immediate: int
    kind: str = "compare_register"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "CompareRegister":
        _exact_fields(payload, {"kind", "register", "immediate"}, context)
        immediate = _integer(payload["immediate"], f"{context}.immediate")
        if immediate >= 2**32:
            raise StageAInputError(f"{context}.immediate must be a 32-bit word")
        return cls(
            register=_register_name(payload["register"], f"{context}.register"),
            immediate=immediate,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "register": self.register,
            "immediate": self.immediate,
        }


Operation: TypeAlias = (
    AdjustStack | StoreStack | Nop | StackArithmetic | CompareStack
    | AssignRegister | RegisterArithmetic | CompareRegister
)


def _operation(payload: Mapping[str, Any], *, context: str) -> Operation:
    kind = payload.get("kind")
    if kind == "adjust_stack":
        return AdjustStack.parse(payload, context=context)
    if kind == "store_stack":
        return StoreStack.parse(payload, context=context)
    if kind == "nop":
        return Nop.parse(payload, context=context)
    if kind == "stack_arithmetic":
        return StackArithmetic.parse(payload, context=context)
    if kind == "compare_stack":
        return CompareStack.parse(payload, context=context)
    if kind == "assign_register":
        return AssignRegister.parse(payload, context=context)
    if kind == "register_arithmetic":
        return RegisterArithmetic.parse(payload, context=context)
    if kind == "compare_register":
        return CompareRegister.parse(payload, context=context)
    raise StageAInputError(f"{context}.kind is unsupported")


@dataclass(frozen=True)
class Jump:
    target: str
    kind: str = "jump"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "Jump":
        _exact_fields(payload, {"kind", "target"}, context)
        return cls(target=_identifier(payload["target"], f"{context}.target"))

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind, "target": self.target}


@dataclass(frozen=True)
class ExternalCall:
    dll: str
    symbol: str
    decorated_symbol: str
    argument_words: int
    disposition: str
    continuation: str | None
    kind: str = "external_call"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "ExternalCall":
        _exact_fields(payload, {
            "kind", "dll", "symbol", "decorated_symbol", "argument_words",
            "disposition", "continuation",
        }, context)
        disposition = payload["disposition"]
        if disposition not in {"returns", "terminates"}:
            raise StageAInputError(f"{context}.disposition is unsupported")
        continuation_value = payload["continuation"]
        continuation = (
            None
            if continuation_value is None
            else _identifier(continuation_value, f"{context}.continuation")
        )
        if (disposition == "returns") != (continuation is not None):
            raise StageAInputError(
                f"{context} returning calls require a continuation and terminating calls forbid one"
            )
        return cls(
            dll=_nonempty_string(payload["dll"], f"{context}.dll").lower(),
            symbol=_nonempty_string(payload["symbol"], f"{context}.symbol"),
            decorated_symbol=_nonempty_string(
                payload["decorated_symbol"], f"{context}.decorated_symbol"
            ),
            argument_words=_integer(
                payload["argument_words"], f"{context}.argument_words"
            ),
            disposition=str(disposition),
            continuation=continuation,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "dll": self.dll,
            "symbol": self.symbol,
            "decorated_symbol": self.decorated_symbol,
            "argument_words": self.argument_words,
            "disposition": self.disposition,
            "continuation": self.continuation,
        }


@dataclass(frozen=True)
class Branch:
    condition: str
    true_target: str
    false_target: str
    kind: str = "branch"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "Branch":
        _exact_fields(
            payload, {"kind", "condition", "true_target", "false_target"}, context
        )
        condition = payload["condition"]
        if condition not in {"zero", "nonzero"}:
            raise StageAInputError(f"{context}.condition is unsupported")
        true_target = _identifier(payload["true_target"], f"{context}.true_target")
        false_target = _identifier(payload["false_target"], f"{context}.false_target")
        if true_target == false_target:
            raise StageAInputError(f"{context} branch targets must be distinct")
        return cls(str(condition), true_target, false_target)

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "condition": self.condition,
            "true_target": self.true_target,
            "false_target": self.false_target,
        }


@dataclass(frozen=True)
class InternalCall:
    target: str
    continuation: str
    kind: str = "internal_call"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "InternalCall":
        _exact_fields(payload, {"kind", "target", "continuation"}, context)
        return cls(
            target=_identifier(payload["target"], f"{context}.target"),
            continuation=_identifier(payload["continuation"], f"{context}.continuation"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "continuation": self.continuation,
        }


@dataclass(frozen=True)
class Return:
    kind: str = "return"

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "Return":
        _exact_fields(payload, {"kind"}, context)
        return cls()

    def to_payload(self) -> dict[str, Any]:
        return {"kind": self.kind}


Terminator: TypeAlias = Jump | ExternalCall | Branch | InternalCall | Return


def _terminator(payload: Mapping[str, Any], *, context: str) -> Terminator:
    kind = payload.get("kind")
    if kind == "jump":
        return Jump.parse(payload, context=context)
    if kind == "external_call":
        return ExternalCall.parse(payload, context=context)
    if kind == "branch":
        return Branch.parse(payload, context=context)
    if kind == "internal_call":
        return InternalCall.parse(payload, context=context)
    if kind == "return":
        return Return.parse(payload, context=context)
    raise StageAInputError(f"{context}.kind is unsupported")


@dataclass(frozen=True)
class SemanticBlock:
    id: str
    operations: tuple[Operation, ...]
    terminator: Terminator

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "SemanticBlock":
        _exact_fields(payload, {"id", "operations", "terminator"}, context)
        operations_payload = payload["operations"]
        if not isinstance(operations_payload, list):
            raise StageAInputError(f"{context}.operations must be a list")
        operations = tuple(
            _operation(
                _object(item, f"{context}.operations[{index}]"),
                context=f"{context}.operations[{index}]",
            )
            for index, item in enumerate(operations_payload)
        )
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            operations=operations,
            terminator=_terminator(
                _object(payload["terminator"], f"{context}.terminator"),
                context=f"{context}.terminator",
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "operations": [operation.to_payload() for operation in self.operations],
            "terminator": self.terminator.to_payload(),
        }


@dataclass(frozen=True)
class StaticObject:
    id: str
    section: str
    alignment: int
    data: bytes

    @classmethod
    def parse(cls, payload: Mapping[str, Any], *, context: str) -> "StaticObject":
        _exact_fields(payload, {"id", "section", "alignment", "data_base64"}, context)
        section = payload["section"]
        if section not in {"read_only", "writable"}:
            raise StageAInputError(f"{context}.section is unsupported")
        alignment = _integer(payload["alignment"], f"{context}.alignment", minimum=1)
        if alignment & (alignment - 1) or alignment > 4096:
            raise StageAInputError(f"{context}.alignment must be a power of two <= 4096")
        encoded = _nonempty_string(payload["data_base64"], f"{context}.data_base64")
        try:
            data = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise StageAInputError(f"{context}.data_base64 is malformed") from exc
        if base64.b64encode(data).decode("ascii") != encoded:
            raise StageAInputError(f"{context}.data_base64 is not canonical")
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            section=str(section),
            alignment=alignment,
            data=data,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "section": self.section,
            "alignment": self.alignment,
            "data_base64": base64.b64encode(self.data).decode("ascii"),
        }


@dataclass(frozen=True)
class SemanticProgram:
    id: str
    entry: str
    blocks: tuple[SemanticBlock, ...]
    static_objects: tuple[StaticObject, ...]
    observations: tuple[str, ...]
    capabilities: tuple[str, ...]
    format: str = ROUNDTRIP_SEMANTIC_PROGRAM_FORMAT

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "SemanticProgram":
        context = "round-trip semantic program"
        _exact_fields(payload, {
            "format", "id", "entry", "blocks", "static_objects",
            "observations", "capabilities",
        }, context)
        if payload["format"] != ROUNDTRIP_SEMANTIC_PROGRAM_FORMAT:
            raise StageAInputError("unsupported round-trip semantic program format")
        raw_blocks = payload["blocks"]
        raw_objects = payload["static_objects"]
        if not isinstance(raw_blocks, list) or not raw_blocks:
            raise StageAInputError("round-trip semantic program blocks must be nonempty")
        if not isinstance(raw_objects, list):
            raise StageAInputError("round-trip semantic program static_objects must be a list")
        blocks = tuple(
            SemanticBlock.parse(
                _object(item, f"{context}.blocks[{index}]"),
                context=f"{context}.blocks[{index}]",
            )
            for index, item in enumerate(raw_blocks)
        )
        objects = tuple(
            StaticObject.parse(
                _object(item, f"{context}.static_objects[{index}]"),
                context=f"{context}.static_objects[{index}]",
            )
            for index, item in enumerate(raw_objects)
        )
        block_ids = [block.id for block in blocks]
        object_ids = [item.id for item in objects]
        if len(block_ids) != len(set(block_ids)):
            raise StageAInputError("round-trip semantic block ids must be unique")
        if len(object_ids) != len(set(object_ids)):
            raise StageAInputError("round-trip static object ids must be unique")
        entry = _identifier(payload["entry"], f"{context}.entry")
        if entry not in set(block_ids):
            raise StageAInputError("round-trip semantic entry does not name a block")
        targets: list[str] = []
        static_references: list[str] = []
        for block in blocks:
            if isinstance(block.terminator, Jump):
                targets.append(block.terminator.target)
            elif isinstance(block.terminator, Branch):
                targets.extend((
                    block.terminator.true_target,
                    block.terminator.false_target,
                ))
            elif isinstance(block.terminator, InternalCall):
                targets.extend((block.terminator.target, block.terminator.continuation))
            elif (
                isinstance(block.terminator, ExternalCall)
                and block.terminator.continuation is not None
            ):
                targets.append(block.terminator.continuation)
            for operation in block.operations:
                if (
                    isinstance(operation, StoreStack)
                    and operation.value.kind is ValueKind.STATIC_ADDRESS
                ):
                    static_references.append(str(operation.value.value))
        missing_targets = sorted(set(targets) - set(block_ids))
        missing_objects = sorted(set(static_references) - set(object_ids))
        if missing_targets:
            raise StageAInputError(f"semantic terminators name missing blocks {missing_targets}")
        if missing_objects:
            raise StageAInputError(f"semantic values name missing static objects {missing_objects}")
        observations = _unique_identifiers(payload["observations"], f"{context}.observations")
        capabilities = _unique_identifiers(payload["capabilities"], f"{context}.capabilities")
        return cls(
            id=_identifier(payload["id"], f"{context}.id"),
            entry=entry,
            blocks=blocks,
            static_objects=objects,
            observations=observations,
            capabilities=capabilities,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "id": self.id,
            "entry": self.entry,
            "blocks": [block.to_payload() for block in self.blocks],
            "static_objects": [item.to_payload() for item in self.static_objects],
            "observations": list(self.observations),
            "capabilities": list(self.capabilities),
        }


def _unique_identifiers(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = tuple(
        _identifier(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    )
    if len(result) != len(set(result)):
        raise StageAInputError(f"{context} must not contain duplicates")
    return result


def _stack_offset(value: Any, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not -(2**31) < value < 2**31
        or value % 4 != 0
    ):
        raise StageAInputError(f"{context} must be a word-aligned signed value")
    return value


def _register_name(value: Any, context: str) -> str:
    register = _identifier(value, context)
    if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
        raise StageAInputError(f"{context} is not a supported IA-32 register")
    return register
