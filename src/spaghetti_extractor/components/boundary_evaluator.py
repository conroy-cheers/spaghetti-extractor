"""Deterministic reference evaluator for pure boundary-plan semantics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, MutableMapping, Sequence

from .capabilities import CapabilityStatus, CheckedReference, ReferencePermission
from .object_authority import MachineObjectAuthorityV1, MachineObjectInstanceV1
from .relation_ir import LogicalPathV1, RelationExpressionV1


class BoundaryEvaluationError(ValueError):
    """A boundary expression faults or requests unsupported world behavior."""


@dataclass(frozen=True)
class EvaluatedCapabilityV1:
    kind: str
    type_id: str
    machine_word: int
    generation: int


@dataclass
class BoundaryEvaluationContextV1:
    machine_values: Mapping[str, object]
    logical_values: Mapping[tuple[str, str, tuple[str, ...]], object]
    object_authority: MachineObjectAuthorityV1
    object_instances: Sequence[MachineObjectInstanceV1] = ()
    authority_bindings: Mapping[str, Mapping[str, object]] | None = None
    memory_reader: Callable[[int, int], int] | None = None
    memory_writer: Callable[[int, int, int], None] | None = None


def evaluate_expression(
    expression: RelationExpressionV1,
    context: BoundaryEvaluationContextV1,
) -> object:
    args = [evaluate_expression(item, context) for item in expression.arguments]
    op = expression.op
    width = expression.sort.width
    mask = None if width is None else (1 << width) - 1
    if op == "true":
        return True
    if op == "false":
        return False
    if op == "const":
        return int(expression.attributes["value"])
    if op == "logical":
        path = LogicalPathV1.parse(expression.attributes["path"])
        try:
            return context.logical_values[path.key]
        except KeyError as exc:
            raise BoundaryEvaluationError(f"logical value {path.key!r} is missing") from exc
    if op == "machine":
        from .relation_ir import MachinePlaceV1

        place = MachinePlaceV1.parse(expression.attributes["place"])
        try:
            return context.machine_values[place.key]
        except KeyError as exc:
            raise BoundaryEvaluationError(f"machine place {place.key!r} is missing") from exc
    if op == "projected_value":
        try:
            return context.logical_values[("projected", "value", ())]
        except KeyError as exc:
            raise BoundaryEvaluationError("projected value is missing") from exc
    if op == "null_ref":
        return CheckedReference(0, 0, 0, 0, 0, 0)
    if op == "not":
        return not bool(args[0])
    if op == "and":
        return bool(args[0]) and bool(args[1])
    if op == "or":
        return bool(args[0]) or bool(args[1])
    if op == "eq":
        return args[0] == args[1]
    if op == "ite":
        return args[1] if bool(args[0]) else args[2]
    if op in {"add", "sub", "bit_and", "bit_or", "bit_xor"}:
        left, right = int(args[0]), int(args[1])
        result = {
            "add": left + right,
            "sub": left - right,
            "bit_and": left & right,
            "bit_or": left | right,
            "bit_xor": left ^ right,
        }[op]
        return result if mask is None else result & mask
    if op == "bit_not":
        result = ~int(args[0])
        return result if mask is None else result & mask
    if op in {"zero_extend", "truncate", "bitcast", "x87_decode", "x87_encode"}:
        return int(args[0]) if mask is None else int(args[0]) & mask
    if op == "sign_extend":
        source_width = int(expression.arguments[0].sort.width or 0)
        value = int(args[0]) & ((1 << source_width) - 1)
        if value & (1 << (source_width - 1)):
            value -= 1 << source_width
        return value if mask is None else value & mask
    if op == "concat":
        result = 0
        for argument, item in zip(args, expression.arguments, strict=True):
            result = (result << int(item.sort.width or 0)) | int(argument)
        return result if mask is None else result & mask
    if op == "slice":
        result = int(args[0]) >> int(expression.attributes["offset_bits"])
        return result if mask is None else result & mask
    if op == "unspecified":
        raise BoundaryEvaluationError("unspecified ABI padding has no runtime value")
    if op == "ult":
        return int(args[0]) < int(args[1])
    if op == "ule":
        return int(args[0]) <= int(args[1])
    if op == "make_ref":
        return CheckedReference(
            int(args[0]), int(args[1]), int(args[2]), int(args[3]), int(args[4]),
            _binding_permissions(expression, context),
        )
    if op == "derive_ref":
        if not isinstance(args[0], CheckedReference):
            raise BoundaryEvaluationError("reference derivation source is invalid")
        try:
            return args[0].derive(
                int(args[1]),
                allow_one_past=_binding_bool(expression, context, "allow_one_past"),
            )
        except ValueError as exc:
            raise BoundaryEvaluationError(str(exc)) from exc
    if op == "ref_offset":
        return _reference(args[0]).offset
    if op == "ref_remaining":
        reference = _reference(args[0])
        return reference.extent - reference.offset
    if op == "ref_is_null":
        return _reference(args[0]).is_null
    if op == "same_origin":
        left, right = _origin_reference(args[0]), _origin_reference(args[1])
        return (
            left.domain, left.object_id, left.generation
        ) == (
            right.domain, right.object_id, right.generation
        )
    if op == "pointer_difference":
        try:
            return _reference(args[0]).difference(_reference(args[1]))
        except ValueError as exc:
            raise BoundaryEvaluationError(str(exc)) from exc
    if op == "make_view":
        return {"base": _reference(args[0]), "extent": int(args[1])}
    if op == "view_address":
        return _view(args[0])["base"]
    if op == "view_extent":
        return int(_view(args[0])["extent"])
    if op == "byte_read":
        view = _view(args[0])
        index = int(args[1])
        if index < 0 or index >= int(view["extent"]):
            raise BoundaryEvaluationError("view read is outside its extent")
        if context.memory_reader is None:
            raise BoundaryEvaluationError("byte_read requires a typed memory backend")
        reference = _reference(view["base"])
        try:
            derived = reference.derive(index)
        except ValueError as exc:
            raise BoundaryEvaluationError(str(exc)) from exc
        status, address, code = context.object_authority.realize(
            derived,
            required_permissions=int(ReferencePermission.READ),
            instances=context.object_instances,
        )
        if status is not CapabilityStatus.OK or address is None:
            raise BoundaryEvaluationError(code)
        return int(context.memory_reader(address, 1)) & 0xFF
    if op == "field":
        source = args[0]
        if not isinstance(source, Mapping):
            raise BoundaryEvaluationError("record field source is invalid")
        return source[str(expression.attributes["id"])]
    if op == "record":
        fields = expression.attributes.get("fields")
        if not isinstance(fields, list) or len(fields) != len(args):
            raise BoundaryEvaluationError("record field inventory is invalid")
        return {str(name): value for name, value in zip(fields, args, strict=True)}
    if op == "authority_call":
        return _authority_call(expression, args, context)
    if op == "make_capability":
        raise BoundaryEvaluationError(
            f"{op} requires a typed memory or capability backend"
        )
    raise BoundaryEvaluationError(f"unsupported boundary expression {op!r}")


def realize_writes(
    expressions: Sequence[tuple[str, RelationExpressionV1, RelationExpressionV1]],
    context: BoundaryEvaluationContextV1,
) -> dict[str, object]:
    """Evaluate all guards and values before exposing any staged write."""

    staged: MutableMapping[str, object] = {}
    for place_key, value, guard in expressions:
        if bool(evaluate_expression(guard, context)):
            if place_key in staged:
                raise BoundaryEvaluationError("boundary plan stages one place twice")
            staged[place_key] = evaluate_expression(value, context)
    return dict(staged)


def _authority_call(
    expression: RelationExpressionV1,
    args: Sequence[object],
    context: BoundaryEvaluationContextV1,
) -> object:
    primitive = str(expression.attributes["primitive"])
    policy = _policy(expression, context)
    if primitive == "origin.resolve":
        result = context.object_authority.resolve(
            int(args[0]),
            requested_extent=int(args[1]),
            required_permissions=int(policy.get("permissions", 1)),
            instances=context.object_instances,
            nullable=bool(policy.get("nullable", False)),
            allow_one_past=bool(policy.get("allow_one_past", False)),
        )
        if result.status is not CapabilityStatus.OK or result.reference is None:
            raise BoundaryEvaluationError(result.code)
        return result.reference
    if primitive == "origin.address":
        status, address, code = context.object_authority.realize(
            _reference(args[0]),
            required_permissions=int(policy.get("permissions", 1)),
            instances=context.object_instances,
            nullable=bool(policy.get("nullable", False)),
            allow_one_past=bool(policy.get("allow_one_past", False)),
        )
        if status is not CapabilityStatus.OK or address is None:
            raise BoundaryEvaluationError(code)
        return address
    if primitive == "capability.import":
        return EvaluatedCapabilityV1(
            expression.sort.kind,
            str(expression.sort.type_id),
            int(args[0]),
            int(args[1]) if len(args) > 1 else int(policy.get("generation", 1)),
        )
    if primitive == "capability.export":
        capability = args[0]
        if not isinstance(capability, EvaluatedCapabilityV1):
            raise BoundaryEvaluationError("capability export source is invalid")
        return capability.machine_word
    raise BoundaryEvaluationError(
        f"world primitive {primitive!r} is unavailable in the pure evaluator"
    )


def _policy(
    expression: RelationExpressionV1,
    context: BoundaryEvaluationContextV1,
) -> Mapping[str, object]:
    bindings = context.authority_bindings or {}
    binding_id = str(expression.attributes.get("binding"))
    value = bindings.get(binding_id)
    if value is None:
        raise BoundaryEvaluationError(f"authority binding {binding_id!r} is missing")
    return value


def _binding_permissions(
    expression: RelationExpressionV1,
    context: BoundaryEvaluationContextV1,
) -> int:
    if expression.op != "authority_call":
        return 1
    return int(_policy(expression, context).get("permissions", 1))


def _binding_bool(
    expression: RelationExpressionV1,
    context: BoundaryEvaluationContextV1,
    name: str,
) -> bool:
    if expression.op != "authority_call":
        return False
    return bool(_policy(expression, context).get(name, False))


def _reference(value: object) -> CheckedReference:
    if not isinstance(value, CheckedReference):
        raise BoundaryEvaluationError("value is not a checked reference")
    return value


def _origin_reference(value: object) -> CheckedReference:
    if isinstance(value, CheckedReference):
        return value
    if isinstance(value, Mapping) and set(value) == {"base", "extent"}:
        return _reference(value["base"])
    raise BoundaryEvaluationError("value has no checked object origin")


def _view(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"base", "extent"}:
        raise BoundaryEvaluationError("value is not a checked view")
    _reference(value["base"])
    return value


__all__ = [
    "BoundaryEvaluationContextV1",
    "BoundaryEvaluationError",
    "EvaluatedCapabilityV1",
    "evaluate_expression",
    "realize_writes",
]
