"""Typed certificates for inductive portable-component operation contracts.

This module checks the *shape and closure* of an induction certificate.  It
does not execute CBMC, replay machine semantics, or trust a submitted claim.
An otherwise closed certificate remains incomplete until exact source and
machine checker receipts are bound to the same operation semantic contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence, TypeVar

from ..artifacts.artifact_set import CanonicalValueV3, canonical_sha256_v3
from .inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
    CheckedInductiveSourceReceiptV1,
    InductiveReceiptError,
)


INDUCTIVE_OPERATION_CERTIFICATE_V1 = (
    "spaghetti-extractor-portable-inductive-operation-certificate-v1"
)
INDUCTIVE_OPERATION_CHECK_V1 = (
    "spaghetti-extractor-portable-inductive-operation-check-v1"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,255}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_T = TypeVar("_T")


class InductiveOperationContractError(ValueError):
    """The certificate is malformed rather than merely incomplete."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InductiveOperationContractError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise InductiveOperationContractError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InductiveOperationContractError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _IDENTIFIER.fullmatch(result) is None:
        raise InductiveOperationContractError(f"{context} is not canonical")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise InductiveOperationContractError(f"{context} must be a SHA-256 digest")
    return result


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InductiveOperationContractError(
            f"{context} must be a nonnegative integer"
        )
    return value


def _ordered_unique(
    rows: Sequence[_T], *, key: Callable[[_T], str], context: str
) -> tuple[_T, ...]:
    parsed = tuple(rows)
    keys = [key(row) for row in parsed]
    if len(keys) != len(set(keys)):
        raise InductiveOperationContractError(f"{context} contains duplicates")
    if keys != sorted(keys):
        raise InductiveOperationContractError(
            f"{context} must use deterministic identity ordering"
        )
    return parsed


def _strings(value: object, context: str) -> tuple[str, ...]:
    rows = tuple(_identifier(item, context) for item in _array(value, context))
    return _ordered_unique(rows, key=lambda item: item, context=context)


@dataclass(frozen=True)
class ExpressionV1:
    """A machine-free subset of the normalized expression vocabulary."""

    op: str
    fields: tuple[tuple[str, object], ...]

    @classmethod
    def parse(cls, value: object, context: str = "expression") -> "ExpressionV1":
        if not isinstance(value, Mapping):
            raise InductiveOperationContractError(f"{context} must be an object")
        op = _identifier(value.get("op"), f"{context} operation")
        if op in {"true", "false"}:
            _object(value, {"op"}, context)
            return cls(op, ())
        if op == "const":
            row = _object(value, {"op", "value", "width"}, context)
            width = _uint(row["width"], f"{context} width")
            raw = _uint(row["value"], f"{context} value")
            if width not in {1, 8, 16, 32, 64} or raw >= (1 << width):
                raise InductiveOperationContractError(
                    f"{context} constant is outside its declared width"
                )
            return cls(op, (("value", raw), ("width", width)))
        if op in {"parameter", "state_input", "loop_variable", "byte_extent"}:
            row = _object(value, {"op", "name"}, context)
            return cls(op, (("name", _identifier(row["name"], f"{context} name")),))
        if op == "byte_read":
            row = _object(value, {"op", "name", "index"}, context)
            return cls(
                op,
                (
                    ("name", _identifier(row["name"], f"{context} byte view")),
                    ("index", cls.parse(row["index"], f"{context} byte index")),
                ),
            )
        arities = {
            "not": 1,
            "add32": 2,
            "sub32": 2,
            "and32": 2,
            "or32": 2,
            "xor32": 2,
            "eq": 2,
            "ult32": 2,
            "ule32": 2,
            "and": 2,
            "or": 2,
            "ite": 3,
        }
        if op in arities:
            row = _object(value, {"op", "args"}, context)
            raw_args = _array(row["args"], f"{context} arguments")
            if len(raw_args) != arities[op]:
                raise InductiveOperationContractError(
                    f"{context} operation {op!r} has the wrong arity"
                )
            args = tuple(
                cls.parse(item, f"{context} argument {index}")
                for index, item in enumerate(raw_args)
            )
            return cls(op, (("args", args),))
        # Known normalized operations that are outside the first conservative
        # profile remain representable, but can never authorize completion.
        if op == "service_result":
            row = _object(value, {"op", "index", "width"}, context)
            width = _uint(row["width"], f"{context} width")
            if width not in {1, 8, 16, 32, 64}:
                raise InductiveOperationContractError(
                    f"{context} service result width is unsupported"
                )
            return cls(
                op,
                (
                    ("index", _uint(row["index"], f"{context} index")),
                    ("width", width),
                ),
            )
        if op in {"resource_value", "callback_value"}:
            row = _object(value, {"op", "name"}, context)
            return cls(op, (("name", _identifier(row["name"], f"{context} name")),))
        raise InductiveOperationContractError(
            f"{context} uses unsupported or machine-specific operation {op!r}"
        )

    def to_payload(self) -> dict[str, object]:
        result: dict[str, object] = {"op": self.op}
        for name, value in self.fields:
            if isinstance(value, ExpressionV1):
                result[name] = value.to_payload()
            elif isinstance(value, tuple) and all(
                isinstance(item, ExpressionV1) for item in value
            ):
                result[name] = [item.to_payload() for item in value]
            else:
                result[name] = value
        return result

    def operations(self) -> tuple[str, ...]:
        result = [self.op]
        for _, value in self.fields:
            if isinstance(value, ExpressionV1):
                result.extend(value.operations())
            elif isinstance(value, tuple):
                for item in value:
                    if isinstance(item, ExpressionV1):
                        result.extend(item.operations())
        return tuple(result)

    def references(self, op: str) -> tuple[str, ...]:
        result: list[str] = []
        if self.op == op:
            values = dict(self.fields)
            if isinstance(values.get("name"), str):
                result.append(values["name"])
        for _, value in self.fields:
            if isinstance(value, ExpressionV1):
                result.extend(value.references(op))
            elif isinstance(value, tuple):
                for item in value:
                    if isinstance(item, ExpressionV1):
                        result.extend(item.references(op))
        return tuple(result)

    def sort_errors(self) -> tuple[str, ...]:
        """Return local sort errors for the conservative word/bool language."""

        children: tuple[ExpressionV1, ...] = ()
        values = dict(self.fields)
        if isinstance(values.get("index"), ExpressionV1):
            children = (values["index"],)
        elif isinstance(values.get("args"), tuple):
            children = values["args"]
        errors = [error for child in children for error in child.sort_errors()]
        child_sorts = [child.result_sort() for child in children]
        if self.op in {"add32", "sub32", "and32", "or32", "xor32", "ult32", "ule32"} and child_sorts != ["word", "word"]:
            errors.append(f"{self.op} requires two word operands")
        elif self.op == "eq" and len(set(child_sorts)) != 1:
            errors.append("eq requires operands with the same sort")
        elif self.op == "not" and child_sorts != ["bool"]:
            errors.append("not requires one Boolean operand")
        elif self.op in {"and", "or"} and child_sorts != ["bool", "bool"]:
            errors.append(f"{self.op} requires two Boolean operands")
        elif self.op == "ite" and (
            len(child_sorts) != 3
            or child_sorts[0] != "bool"
            or child_sorts[1] != child_sorts[2]
        ):
            errors.append("ite requires a Boolean guard and equal branch sorts")
        elif self.op == "byte_read" and child_sorts != ["word"]:
            errors.append("byte_read index must be a word")
        return tuple(errors)

    def result_sort(self) -> str:
        if self.op in {"true", "false", "eq", "ult32", "ule32", "not", "and", "or"}:
            return "bool"
        if self.op == "ite":
            args = dict(self.fields).get("args", ())
            if isinstance(args, tuple) and len(args) == 3:
                return args[1].result_sort()
            return "unsupported"
        if self.op in {"resource_value", "callback_value"}:
            return "unsupported"
        return "word"


@dataclass(frozen=True)
class ArtifactBindingsV1:
    interface_id: str
    interface_sha256: str
    operation_id: str
    machine_binding_id: str
    machine_binding_sha256: str
    machine_semantic_contract_id: str
    machine_semantic_contract_sha256: str
    source_plan_sha256: str
    cutpoint_relation_sha256: str
    implementation_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ArtifactBindingsV1":
        row = _object(
            value,
            {
                "interface_id", "interface_sha256", "operation_id",
                "machine_binding_id", "machine_binding_sha256",
                "machine_semantic_contract_id",
                "machine_semantic_contract_sha256",
                "source_plan_sha256",
                "cutpoint_relation_sha256",
                "implementation_sha256",
            },
            "inductive contract bindings",
        )
        return cls(
            _identifier(row["interface_id"], "interface id"),
            _digest(row["interface_sha256"], "interface digest"),
            _identifier(row["operation_id"], "operation id"),
            _identifier(row["machine_binding_id"], "machine binding id"),
            _digest(row["machine_binding_sha256"], "machine binding digest"),
            _identifier(
                row["machine_semantic_contract_id"], "machine semantic contract id"
            ),
            _digest(
                row["machine_semantic_contract_sha256"],
                "machine semantic contract digest",
            ),
            _digest(row["source_plan_sha256"], "source-plan digest"),
            _digest(row["cutpoint_relation_sha256"], "cutpoint relation digest"),
            _digest(row["implementation_sha256"], "implementation digest"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "interface_id": self.interface_id,
            "interface_sha256": self.interface_sha256,
            "operation_id": self.operation_id,
            "machine_binding_id": self.machine_binding_id,
            "machine_binding_sha256": self.machine_binding_sha256,
            "machine_semantic_contract_id": self.machine_semantic_contract_id,
            "machine_semantic_contract_sha256": self.machine_semantic_contract_sha256,
            "source_plan_sha256": self.source_plan_sha256,
            "cutpoint_relation_sha256": self.cutpoint_relation_sha256,
            "implementation_sha256": self.implementation_sha256,
        }


@dataclass(frozen=True)
class ReceiptReferenceV1:
    kind: str
    receipt_id: str
    receipt_sha256: str
    operation_id: str
    semantic_contract_sha256: str

    @classmethod
    def parse(cls, value: object, context: str) -> "ReceiptReferenceV1":
        row = _object(
            value,
            {"kind", "receipt_id", "receipt_sha256", "operation_id", "semantic_contract_sha256"},
            context,
        )
        kind = _text(row["kind"], f"{context} kind")
        if kind not in {"source_semantics", "machine_semantics"}:
            raise InductiveOperationContractError(f"{context} kind is invalid")
        return cls(
            kind,
            _identifier(row["receipt_id"], f"{context} id"),
            _digest(row["receipt_sha256"], f"{context} digest"),
            _identifier(row["operation_id"], f"{context} operation"),
            _digest(row["semantic_contract_sha256"], f"{context} semantic contract"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "operation_id": self.operation_id,
            "semantic_contract_sha256": self.semantic_contract_sha256,
        }


@dataclass(frozen=True)
class ExternalDependencyV1:
    identity: str
    kind: str
    sha256: str

    @classmethod
    def parse(cls, value: object, context: str) -> "ExternalDependencyV1":
        row = _object(value, {"id", "kind", "sha256"}, context)
        return cls(
            _identifier(row["id"], f"{context} id"),
            _identifier(row["kind"], f"{context} kind"),
            _digest(row["sha256"], f"{context} digest"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "kind": self.kind, "sha256": self.sha256}


@dataclass(frozen=True)
class VariableDomainV1:
    kind: str
    payload: CanonicalValueV3

    @classmethod
    def parse(cls, value: object, context: str) -> "VariableDomainV1":
        if not isinstance(value, Mapping):
            raise InductiveOperationContractError(f"{context} must be an object")
        kind = _text(value.get("kind"), f"{context} kind")
        if kind == "unsigned":
            row = _object(value, {"kind", "width", "minimum", "maximum"}, context)
            width = _uint(row["width"], f"{context} width")
            minimum = _uint(row["minimum"], f"{context} minimum")
            maximum = _uint(row["maximum"], f"{context} maximum")
            if width not in {8, 16, 32} or minimum > maximum or maximum >= 1 << width:
                raise InductiveOperationContractError(f"{context} bounds are invalid")
            payload = {"kind": kind, "width": width, "minimum": minimum, "maximum": maximum}
        elif kind == "enum":
            row = _object(value, {"kind", "type_id", "values"}, context)
            values = _array(row["values"], f"{context} values")
            if not values or any(not isinstance(item, (str, int)) or isinstance(item, bool) for item in values):
                raise InductiveOperationContractError(f"{context} enum values are invalid")
            canonical_values = [CanonicalValueV3.of(item).to_value() for item in values]
            if canonical_values != sorted(canonical_values, key=canonical_sha256_v3) or len({canonical_sha256_v3(item) for item in canonical_values}) != len(values):
                raise InductiveOperationContractError(f"{context} enum values must be ordered and unique")
            payload = {"kind": kind, "type_id": _identifier(row["type_id"], f"{context} type"), "values": canonical_values}
        elif kind == "bounded_bytes":
            row = _object(value, {"kind", "extent_variable_id", "access"}, context)
            access = _text(row["access"], f"{context} access")
            if access not in {"read", "write", "read_write"}:
                raise InductiveOperationContractError(f"{context} access is invalid")
            payload = {"kind": kind, "extent_variable_id": _identifier(row["extent_variable_id"], f"{context} extent variable"), "access": access}
        elif kind == "nul_terminated_bytes":
            row = _object(value, {"kind", "extent_variable_id", "access"}, context)
            access = _text(row["access"], f"{context} access")
            if access != "read":
                raise InductiveOperationContractError(
                    f"{context} NUL-terminated bytes must be read-only"
                )
            payload = {"kind": kind, "extent_variable_id": _identifier(row["extent_variable_id"], f"{context} extent variable"), "access": access}
        elif kind == "unsupported":
            row = _object(value, {"kind", "feature"}, context)
            payload = {
                "kind": kind,
                "feature": _identifier(row["feature"], f"{context} feature"),
            }
        else:
            raise InductiveOperationContractError(f"{context} kind is unsupported")
        return cls(kind, CanonicalValueV3.of(payload))

    def to_payload(self) -> dict[str, object]:
        value = self.payload.to_value()
        assert isinstance(value, dict)
        return value


@dataclass(frozen=True)
class VariableOriginV1:
    kind: str
    reference_id: str
    index: ExpressionV1 | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "VariableOriginV1":
        if not isinstance(value, Mapping):
            raise InductiveOperationContractError(f"{context} must be an object")
        kind = _text(value.get("kind"), f"{context} kind")
        field = {
            "operation_parameter": "value_id",
            "operation_state": "value_id",
            "byte_extent": "view_id",
            "cutpoint_value": "cutpoint_id",
        }.get(kind)
        if field is not None:
            row = _object(value, {"kind", field}, context)
            return cls(kind, _identifier(row[field], f"{context} reference"))
        if kind == "read_only_byte":
            row = _object(value, {"kind", "view_id", "index"}, context)
            return cls(
                kind,
                _identifier(row["view_id"], f"{context} byte view"),
                ExpressionV1.parse(row["index"], f"{context} byte index"),
            )
        raise InductiveOperationContractError(f"{context} kind is unsupported")

    def to_payload(self) -> dict[str, object]:
        field = {
            "operation_parameter": "value_id",
            "operation_state": "value_id",
            "byte_extent": "view_id",
            "cutpoint_value": "cutpoint_id",
            "read_only_byte": "view_id",
        }[self.kind]
        result: dict[str, object] = {"kind": self.kind, field: self.reference_id}
        if self.index is not None:
            result["index"] = self.index.to_payload()
        return result


@dataclass(frozen=True)
class LoopVariableV1:
    identity: str
    type_id: str
    domain: VariableDomainV1
    origin: VariableOriginV1

    @classmethod
    def parse(cls, value: object, context: str) -> "LoopVariableV1":
        row = _object(value, {"id", "type_id", "domain", "origin"}, context)
        return cls(
            _identifier(row["id"], f"{context} id"),
            _identifier(row["type_id"], f"{context} type"),
            VariableDomainV1.parse(row["domain"], f"{context} domain"),
            VariableOriginV1.parse(row["origin"], f"{context} origin"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "type_id": self.type_id, "domain": self.domain.to_payload(), "origin": self.origin.to_payload()}


@dataclass(frozen=True)
class PredicateV1:
    identity: str
    scc_id: str
    kind: str
    expression: ExpressionV1

    @classmethod
    def parse(cls, value: object, context: str) -> "PredicateV1":
        row = _object(value, {"id", "scc_id", "kind", "expression"}, context)
        kind = _text(row["kind"], f"{context} kind")
        if kind not in {"invariant", "postcondition"}:
            raise InductiveOperationContractError(f"{context} kind is invalid")
        return cls(
            _identifier(row["id"], f"{context} id"),
            _identifier(row["scc_id"], f"{context} SCC"),
            kind,
            ExpressionV1.parse(row["expression"], f"{context} expression"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "scc_id": self.scc_id, "kind": self.kind, "expression": self.expression.to_payload()}


@dataclass(frozen=True)
class MachineSccV1:
    identity: str
    unit_ids: tuple[str, ...]
    cutpoint_ids: tuple[str, ...]
    entry_cutpoint_ids: tuple[str, ...]
    exit_cutpoint_ids: tuple[str, ...]
    transition_ids: tuple[str, ...]
    bridge_ids: tuple[str, ...]
    completion_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "MachineSccV1":
        row = _object(value, {"id", "unit_ids", "cutpoint_ids", "entry_cutpoint_ids", "exit_cutpoint_ids", "transition_ids", "bridge_ids", "completion_ids"}, context)
        return cls(
            _identifier(row["id"], f"{context} id"),
            _strings(row["unit_ids"], f"{context} units"),
            _strings(row["cutpoint_ids"], f"{context} cutpoints"),
            _strings(row["entry_cutpoint_ids"], f"{context} entry cutpoints"),
            _strings(row["exit_cutpoint_ids"], f"{context} exit cutpoints"),
            _strings(row["transition_ids"], f"{context} transitions"),
            _strings(row["bridge_ids"], f"{context} bridges"),
            _strings(row["completion_ids"], f"{context} completions"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "unit_ids": list(self.unit_ids), "cutpoint_ids": list(self.cutpoint_ids), "entry_cutpoint_ids": list(self.entry_cutpoint_ids), "exit_cutpoint_ids": list(self.exit_cutpoint_ids), "transition_ids": list(self.transition_ids), "bridge_ids": list(self.bridge_ids), "completion_ids": list(self.completion_ids)}


@dataclass(frozen=True)
class InitializationWitnessV1:
    identity: str
    scc_id: str
    cutpoint_id: str
    establishes: tuple[str, ...]
    dependencies: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "InitializationWitnessV1":
        row = _object(value, {"id", "scc_id", "cutpoint_id", "establishes", "dependencies"}, context)
        return cls(_identifier(row["id"], f"{context} id"), _identifier(row["scc_id"], f"{context} SCC"), _identifier(row["cutpoint_id"], f"{context} cutpoint"), _strings(row["establishes"], f"{context} predicates"), _strings(row["dependencies"], f"{context} dependencies"))

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "scc_id": self.scc_id, "cutpoint_id": self.cutpoint_id, "establishes": list(self.establishes), "dependencies": list(self.dependencies)}


@dataclass(frozen=True)
class VariableUpdateV1:
    variable_id: str
    expression: ExpressionV1

    @classmethod
    def parse(cls, value: object, context: str) -> "VariableUpdateV1":
        row = _object(value, {"variable_id", "expression"}, context)
        return cls(_identifier(row["variable_id"], f"{context} variable"), ExpressionV1.parse(row["expression"], f"{context} expression"))

    def to_payload(self) -> dict[str, object]:
        return {"variable_id": self.variable_id, "expression": self.expression.to_payload()}


@dataclass(frozen=True)
class PreservationWitnessV1:
    identity: str
    scc_id: str
    transition_id: str
    source_cutpoint_id: str
    target_cutpoint_id: str
    machine_unit_ids: tuple[str, ...]
    guard: ExpressionV1
    updates: tuple[VariableUpdateV1, ...]
    preserves: tuple[str, ...]
    dependencies: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "PreservationWitnessV1":
        row = _object(value, {"id", "scc_id", "transition_id", "source_cutpoint_id", "target_cutpoint_id", "machine_unit_ids", "guard", "updates", "preserves", "dependencies"}, context)
        updates = tuple(VariableUpdateV1.parse(item, f"{context} update {index}") for index, item in enumerate(_array(row["updates"], f"{context} updates")))
        _ordered_unique(updates, key=lambda item: item.variable_id, context=f"{context} updates")
        return cls(_identifier(row["id"], f"{context} id"), _identifier(row["scc_id"], f"{context} SCC"), _identifier(row["transition_id"], f"{context} transition"), _identifier(row["source_cutpoint_id"], f"{context} source cutpoint"), _identifier(row["target_cutpoint_id"], f"{context} target cutpoint"), _strings(row["machine_unit_ids"], f"{context} machine units"), ExpressionV1.parse(row["guard"], f"{context} guard"), updates, _strings(row["preserves"], f"{context} predicates"), _strings(row["dependencies"], f"{context} dependencies"))

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "scc_id": self.scc_id, "transition_id": self.transition_id, "source_cutpoint_id": self.source_cutpoint_id, "target_cutpoint_id": self.target_cutpoint_id, "machine_unit_ids": list(self.machine_unit_ids), "guard": self.guard.to_payload(), "updates": [item.to_payload() for item in self.updates], "preserves": list(self.preserves), "dependencies": list(self.dependencies)}


@dataclass(frozen=True)
class BridgeWitnessV1:
    identity: str
    transition_id: str
    source_scc_id: str
    target_scc_id: str
    source_cutpoint_id: str
    target_cutpoint_id: str
    machine_unit_ids: tuple[str, ...]
    guard: ExpressionV1
    updates: tuple[VariableUpdateV1, ...]
    establishes: tuple[str, ...]
    dependencies: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "BridgeWitnessV1":
        row = _object(
            value,
            {
                "id",
                "transition_id",
                "source_scc_id",
                "target_scc_id",
                "source_cutpoint_id",
                "target_cutpoint_id",
                "machine_unit_ids",
                "guard",
                "updates",
                "establishes",
                "dependencies",
            },
            context,
        )
        updates = tuple(
            VariableUpdateV1.parse(item, f"{context} update {index}")
            for index, item in enumerate(
                _array(row["updates"], f"{context} updates")
            )
        )
        _ordered_unique(
            updates,
            key=lambda item: item.variable_id,
            context=f"{context} updates",
        )
        source_scc_id = _identifier(
            row["source_scc_id"], f"{context} source SCC"
        )
        target_scc_id = _identifier(
            row["target_scc_id"], f"{context} target SCC"
        )
        if source_scc_id == target_scc_id:
            raise InductiveOperationContractError(
                f"{context} must cross two distinct SCCs"
            )
        return cls(
            _identifier(row["id"], f"{context} id"),
            _identifier(row["transition_id"], f"{context} transition"),
            source_scc_id,
            target_scc_id,
            _identifier(
                row["source_cutpoint_id"], f"{context} source cutpoint"
            ),
            _identifier(
                row["target_cutpoint_id"], f"{context} target cutpoint"
            ),
            _strings(row["machine_unit_ids"], f"{context} machine units"),
            ExpressionV1.parse(row["guard"], f"{context} guard"),
            updates,
            _strings(row["establishes"], f"{context} predicates"),
            _strings(row["dependencies"], f"{context} dependencies"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "transition_id": self.transition_id,
            "source_scc_id": self.source_scc_id,
            "target_scc_id": self.target_scc_id,
            "source_cutpoint_id": self.source_cutpoint_id,
            "target_cutpoint_id": self.target_cutpoint_id,
            "machine_unit_ids": list(self.machine_unit_ids),
            "guard": self.guard.to_payload(),
            "updates": [item.to_payload() for item in self.updates],
            "establishes": list(self.establishes),
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True)
class DecreaseWitnessV1:
    identity: str
    scc_id: str
    transition_id: str
    measure_id: str
    before: ExpressionV1
    after: ExpressionV1
    relation: str
    dependencies: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "DecreaseWitnessV1":
        row = _object(value, {"id", "scc_id", "transition_id", "measure_id", "before", "after", "relation", "dependencies"}, context)
        relation = _text(row["relation"], f"{context} relation")
        if relation != "unsigned_lt":
            raise InductiveOperationContractError(f"{context} relation is unsupported")
        return cls(_identifier(row["id"], f"{context} id"), _identifier(row["scc_id"], f"{context} SCC"), _identifier(row["transition_id"], f"{context} transition"), _identifier(row["measure_id"], f"{context} measure"), ExpressionV1.parse(row["before"], f"{context} before"), ExpressionV1.parse(row["after"], f"{context} after"), relation, _strings(row["dependencies"], f"{context} dependencies"))

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "scc_id": self.scc_id, "transition_id": self.transition_id, "measure_id": self.measure_id, "before": self.before.to_payload(), "after": self.after.to_payload(), "relation": self.relation, "dependencies": list(self.dependencies)}


@dataclass(frozen=True)
class ExitWitnessV1:
    identity: str
    scc_id: str
    cutpoint_id: str
    guard: ExpressionV1
    establishes: tuple[str, ...]
    completion_ids: tuple[str, ...]
    dependencies: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "ExitWitnessV1":
        row = _object(value, {"id", "scc_id", "cutpoint_id", "guard", "establishes", "completion_ids", "dependencies"}, context)
        return cls(_identifier(row["id"], f"{context} id"), _identifier(row["scc_id"], f"{context} SCC"), _identifier(row["cutpoint_id"], f"{context} cutpoint"), ExpressionV1.parse(row["guard"], f"{context} guard"), _strings(row["establishes"], f"{context} predicates"), _strings(row["completion_ids"], f"{context} completions"), _strings(row["dependencies"], f"{context} dependencies"))

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "scc_id": self.scc_id, "cutpoint_id": self.cutpoint_id, "guard": self.guard.to_payload(), "establishes": list(self.establishes), "completion_ids": list(self.completion_ids), "dependencies": list(self.dependencies)}


@dataclass(frozen=True)
class CompletionWitnessV1:
    identity: str
    scc_id: str
    exit_witness_id: str
    kind: str
    machine_unit_ids: tuple[str, ...]
    postcondition_ids: tuple[str, ...]
    dependencies: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "CompletionWitnessV1":
        row = _object(value, {"id", "scc_id", "exit_witness_id", "kind", "machine_unit_ids", "postcondition_ids", "dependencies"}, context)
        kind = _text(row["kind"], f"{context} kind")
        if kind not in {"return", "terminal_fault", "external_event"}:
            raise InductiveOperationContractError(f"{context} kind is invalid")
        return cls(_identifier(row["id"], f"{context} id"), _identifier(row["scc_id"], f"{context} SCC"), _identifier(row["exit_witness_id"], f"{context} exit witness"), kind, _strings(row["machine_unit_ids"], f"{context} machine units"), _strings(row["postcondition_ids"], f"{context} postconditions"), _strings(row["dependencies"], f"{context} dependencies"))

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "scc_id": self.scc_id, "exit_witness_id": self.exit_witness_id, "kind": self.kind, "machine_unit_ids": list(self.machine_unit_ids), "postcondition_ids": list(self.postcondition_ids), "dependencies": list(self.dependencies)}


@dataclass(frozen=True)
class InductiveOperationCertificateV1:
    bindings: ArtifactBindingsV1
    dependencies: tuple[ExternalDependencyV1, ...]
    receipts: tuple[ReceiptReferenceV1, ...]
    machine_unit_ids: tuple[str, ...]
    sccs: tuple[MachineSccV1, ...]
    variables: tuple[LoopVariableV1, ...]
    predicates: tuple[PredicateV1, ...]
    initialization: tuple[InitializationWitnessV1, ...]
    preservation: tuple[PreservationWitnessV1, ...]
    bridges: tuple[BridgeWitnessV1, ...]
    decreases: tuple[DecreaseWitnessV1, ...]
    exits: tuple[ExitWitnessV1, ...]
    completions: tuple[CompletionWitnessV1, ...]
    certificate_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InductiveOperationCertificateV1":
        row = _object(value, {"format", "bindings", "dependencies", "receipts", "machine", "variables", "predicates", "initialization", "preservation", "bridges", "decreases", "exits", "completions", "certificate_sha256"}, "inductive operation certificate")
        if row["format"] != INDUCTIVE_OPERATION_CERTIFICATE_V1:
            raise InductiveOperationContractError("unsupported inductive operation certificate format")
        machine = _object(row["machine"], {"unit_ids", "sccs"}, "certificate machine inventory")

        def rows(
            field: str,
            parser: Callable[[object, str], _T],
            key: Callable[[_T], str],
        ) -> tuple[_T, ...]:
            parsed = tuple(parser(item, f"certificate {field} {index}") for index, item in enumerate(_array(row[field], f"certificate {field}")))
            return _ordered_unique(parsed, key=key, context=f"certificate {field}")

        dependencies = rows("dependencies", ExternalDependencyV1.parse, lambda item: item.identity)
        receipts = rows("receipts", ReceiptReferenceV1.parse, lambda item: item.kind)
        scc_values = tuple(MachineSccV1.parse(item, f"machine SCC {index}") for index, item in enumerate(_array(machine["sccs"], "machine SCCs")))
        sccs = _ordered_unique(scc_values, key=lambda item: item.identity, context="machine SCCs")
        variables = rows("variables", LoopVariableV1.parse, lambda item: item.identity)
        predicates = rows("predicates", PredicateV1.parse, lambda item: item.identity)
        initialization = rows("initialization", InitializationWitnessV1.parse, lambda item: item.identity)
        preservation = rows("preservation", PreservationWitnessV1.parse, lambda item: item.identity)
        bridges = rows("bridges", BridgeWitnessV1.parse, lambda item: item.identity)
        decreases = rows("decreases", DecreaseWitnessV1.parse, lambda item: item.identity)
        exits = rows("exits", ExitWitnessV1.parse, lambda item: item.identity)
        completions = rows("completions", CompletionWitnessV1.parse, lambda item: item.identity)
        core = dict(row)
        observed = _digest(core.pop("certificate_sha256"), "certificate digest")
        if canonical_sha256_v3(core) != observed:
            raise InductiveOperationContractError("inductive operation certificate digest is stale")
        return cls(
            ArtifactBindingsV1.parse(row["bindings"]), dependencies, receipts,
            _strings(machine["unit_ids"], "machine units"), sccs, variables,
            predicates, initialization, preservation, bridges, decreases, exits,
            completions, observed,
        )

    @classmethod
    def create(cls, **fields: object) -> "InductiveOperationCertificateV1":
        core = {"format": INDUCTIVE_OPERATION_CERTIFICATE_V1, **fields}
        return cls.parse({**core, "certificate_sha256": canonical_sha256_v3(core)})

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": INDUCTIVE_OPERATION_CERTIFICATE_V1,
            "bindings": self.bindings.to_payload(),
            "dependencies": [item.to_payload() for item in self.dependencies],
            "receipts": [item.to_payload() for item in self.receipts],
            "machine": {"unit_ids": list(self.machine_unit_ids), "sccs": [item.to_payload() for item in self.sccs]},
            "variables": [item.to_payload() for item in self.variables],
            "predicates": [item.to_payload() for item in self.predicates],
            "initialization": [item.to_payload() for item in self.initialization],
            "preservation": [item.to_payload() for item in self.preservation],
            "bridges": [item.to_payload() for item in self.bridges],
            "decreases": [item.to_payload() for item in self.decreases],
            "exits": [item.to_payload() for item in self.exits],
            "completions": [item.to_payload() for item in self.completions],
        }
        return {**core, "certificate_sha256": self.certificate_sha256}


@dataclass(frozen=True)
class CertificateIssueV1:
    status: str
    code: str
    location: str
    detail: str

    @classmethod
    def parse(cls, value: object, context: str) -> "CertificateIssueV1":
        row = _object(value, {"status", "code", "location", "detail"}, context)
        status = _text(row["status"], f"{context} status")
        if status not in {"incomplete", "violated"}:
            raise InductiveOperationContractError(f"{context} status is invalid")
        return cls(
            status,
            _identifier(row["code"], f"{context} code"),
            _text(row["location"], f"{context} location"),
            _text(row["detail"], f"{context} detail"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"status": self.status, "code": self.code, "location": self.location, "detail": self.detail}


@dataclass(frozen=True)
class InductiveOperationCheckV1:
    status: str
    certificate_sha256: str
    issues: tuple[CertificateIssueV1, ...]
    assurance: CanonicalValueV3
    check_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InductiveOperationCheckV1":
        row = _object(
            value,
            {
                "format", "status", "certificate_sha256", "issues",
                "assurance", "check_sha256",
            },
            "inductive operation check",
        )
        if row["format"] != INDUCTIVE_OPERATION_CHECK_V1:
            raise InductiveOperationContractError(
                "unsupported inductive operation check format"
            )
        status = _text(row["status"], "inductive operation check status")
        if status not in {"complete", "incomplete", "violated"}:
            raise InductiveOperationContractError(
                "inductive operation check status is invalid"
            )
        raw_issues = _array(row["issues"], "inductive operation check issues")
        issues = tuple(
            CertificateIssueV1.parse(item, f"inductive operation check issue {index}")
            for index, item in enumerate(raw_issues)
        )
        issue_keys = [
            (item.status, item.code, item.location, item.detail) for item in issues
        ]
        if issue_keys != sorted(issue_keys) or len(issue_keys) != len(set(issue_keys)):
            raise InductiveOperationContractError(
                "inductive operation check issues must be ordered and unique"
            )
        expected_status = (
            "violated"
            if any(item.status == "violated" for item in issues)
            else "incomplete" if issues else "complete"
        )
        if status != expected_status:
            raise InductiveOperationContractError(
                "inductive operation check status contradicts its issues"
            )
        assurance = _object(
            row["assurance"],
            {
                "certificate_inventory_checked",
                "source_semantics_checked",
                "machine_semantics_checked",
                "receipt_contents_replayed_by_this_checker",
                "raw_c_or_register_expressions_accepted",
                "unsupported_constructs_fail_closed",
            },
            "inductive operation check assurance",
        )
        if any(not isinstance(item, bool) for item in assurance.values()):
            raise InductiveOperationContractError(
                "inductive operation check assurance fields must be Boolean"
            )
        core = dict(row)
        observed = _digest(core.pop("check_sha256"), "inductive operation check digest")
        if canonical_sha256_v3(core) != observed:
            raise InductiveOperationContractError(
                "inductive operation check digest is stale"
            )
        return cls(
            status,
            _digest(row["certificate_sha256"], "checked certificate digest"),
            issues,
            CanonicalValueV3.of(assurance),
            observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {"format": INDUCTIVE_OPERATION_CHECK_V1, "status": self.status, "certificate_sha256": self.certificate_sha256, "issues": [item.to_payload() for item in self.issues], "assurance": self.assurance.to_value()}
        return {**core, "check_sha256": self.check_sha256}


def _witness_matches_exact_segment(
    source_cutpoint_id: str,
    target_cutpoint_id: str,
    machine_unit_ids: Sequence[str],
    segment: Mapping[str, object],
) -> bool:
    source = segment.get("source")
    target = segment.get("target")
    units = segment.get("unit_ids")
    return (
        isinstance(source, Mapping)
        and source.get("kind") == "cutpoint"
        and source.get("id") == source_cutpoint_id
        and isinstance(target, Mapping)
        and target.get("kind") == "cutpoint"
        and target.get("id") == target_cutpoint_id
        and isinstance(units, list)
        and set(machine_unit_ids) == {str(item) for item in units}
    )


def check_inductive_operation_certificate(
    value: object,
    *,
    receipt_payloads: Mapping[str, object] | None = None,
) -> InductiveOperationCheckV1:
    """Check inventory closure and replay supplied authority envelopes."""

    certificate = value if isinstance(value, InductiveOperationCertificateV1) else InductiveOperationCertificateV1.parse(value)
    issues: list[CertificateIssueV1] = []

    def issue(status: str, code: str, location: str, detail: str) -> None:
        issues.append(CertificateIssueV1(status, code, location, detail))

    bindings = certificate.bindings
    receipts = {item.kind: item for item in certificate.receipts}
    valid_receipts: set[str] = set()
    actual_receipts = {} if receipt_payloads is None else dict(receipt_payloads)
    machine_receipt: CheckedInductiveMachineReceiptV1 | None = None
    source_receipt: CheckedInductiveSourceReceiptV1 | None = None
    for kind in ("source_semantics", "machine_semantics"):
        receipt = receipts.get(kind)
        if receipt is None:
            issue("incomplete", "missing_authority_receipt", f"receipts.{kind}", f"exact {kind} receipt is required")
        elif receipt.operation_id != bindings.operation_id or receipt.semantic_contract_sha256 != bindings.machine_semantic_contract_sha256:
            issue("violated", "authority_receipt_binding_mismatch", f"receipts.{kind}", "receipt does not bind the selected operation semantic contract")
        else:
            payload = actual_receipts.get(receipt.receipt_id)
            if payload is None:
                issue(
                    "incomplete",
                    "authority_receipt_contents_missing",
                    f"receipts.{kind}",
                    "the referenced authority receipt payload was not supplied",
                )
                continue
            try:
                if kind == "machine_semantics":
                    machine_receipt = CheckedInductiveMachineReceiptV1.parse(payload)
                    actual_sha256 = machine_receipt.receipt_sha256
                    actual_operation = machine_receipt.operation_id
                    actual_semantic = machine_receipt.semantic_contract_sha256
                else:
                    source_receipt = CheckedInductiveSourceReceiptV1.parse(payload)
                    actual_sha256 = source_receipt.receipt_sha256
                    actual_operation = source_receipt.operation_id
                    actual_semantic = source_receipt.semantic_contract_sha256
            except InductiveReceiptError as exc:
                issue(
                    "violated",
                    "authority_receipt_invalid",
                    f"receipts.{kind}",
                    str(exc),
                )
                continue
            if (
                actual_sha256 != receipt.receipt_sha256
                or actual_operation != bindings.operation_id
                or actual_semantic != bindings.machine_semantic_contract_sha256
            ):
                issue(
                    "violated",
                    "authority_receipt_content_binding_mismatch",
                    f"receipts.{kind}",
                    "the supplied authority receipt differs from its certificate reference",
                )
                continue
            valid_receipts.add(kind)

    exact_segments: dict[str, Mapping[str, object]] = {}
    if machine_receipt is not None:
        shape = machine_receipt.shape.to_value()
        inventory = machine_receipt.segment_inventory.to_value()
        assert isinstance(shape, dict) and isinstance(inventory, dict)
        exact_units = {
            str(row["unit_id"])
            for row in shape["semantic_units"]
            if isinstance(row, Mapping)
        }
        if set(certificate.machine_unit_ids) != exact_units:
            issue(
                "violated",
                "machine_receipt_unit_inventory_mismatch",
                "machine.unit_ids",
                "certificate units differ from the exact machine receipt",
            )
        exact_sccs = {
            str(row["scc_id"]): set(str(item) for item in row["member_unit_ids"])
            for row in shape["cyclic_sccs"]
            if isinstance(row, Mapping)
        }
        submitted_sccs = {
            row.identity: set(row.unit_ids) for row in certificate.sccs
        }
        if submitted_sccs != exact_sccs:
            issue(
                "violated",
                "machine_receipt_scc_inventory_mismatch",
                "machine.sccs",
                "certificate cyclic SCCs differ from the exact machine receipt",
            )
        exact_segments = {
            str(row["segment_id"]): row
            for row in inventory["segments"]
            if isinstance(row, Mapping)
        }
        segment_ids = set(exact_segments)
        for scc in certificate.sccs:
            unknown_segments = (
                set(scc.transition_ids) | set(scc.bridge_ids)
            ) - segment_ids
            if unknown_segments:
                issue(
                    "violated",
                    "unknown_machine_segment",
                    f"sccs.{scc.identity}.segments",
                    f"unknown exact machine segments: {sorted(unknown_segments)!r}",
                )
        cutpoint_owner = {
            cutpoint_id: scc.identity
            for scc in certificate.sccs
            for cutpoint_id in scc.cutpoint_ids
        }
        expected_internal: dict[str, set[str]] = {
            scc.identity: set() for scc in certificate.sccs
        }
        expected_bridges: dict[str, set[str]] = {
            scc.identity: set() for scc in certificate.sccs
        }
        expected_entries: dict[str, set[str]] = {
            scc.identity: set() for scc in certificate.sccs
        }
        expected_exits: dict[str, set[str]] = {
            scc.identity: set() for scc in certificate.sccs
        }
        for segment_id, segment in exact_segments.items():
            source = segment.get("source")
            target = segment.get("target")
            if not isinstance(source, Mapping) or not isinstance(target, Mapping):
                continue
            source_kind = source.get("kind")
            target_kind = target.get("kind")
            if source_kind == "operation_entry" and target_kind == "cutpoint":
                target_owner = cutpoint_owner.get(str(target.get("id")))
                if target_owner is not None:
                    expected_entries[target_owner].add(str(target.get("id")))
            elif source_kind == "cutpoint" and target_kind == "cutpoint":
                source_owner = cutpoint_owner.get(str(source.get("id")))
                target_owner = cutpoint_owner.get(str(target.get("id")))
                if source_owner is not None and target_owner is not None:
                    if source_owner == target_owner:
                        expected_internal[source_owner].add(segment_id)
                    else:
                        expected_bridges[source_owner].add(segment_id)
                        expected_entries[target_owner].add(str(target.get("id")))
            elif source_kind == "cutpoint" and target_kind == "operation_exit":
                source_owner = cutpoint_owner.get(str(source.get("id")))
                if source_owner is not None:
                    expected_exits[source_owner].add(str(source.get("id")))
        for scc in certificate.sccs:
            if set(scc.transition_ids) != expected_internal[scc.identity]:
                issue("violated", "machine_receipt_transition_inventory_mismatch", f"sccs.{scc.identity}.transitions", "internal transition inventory differs from exact segment endpoints")
            if set(scc.bridge_ids) != expected_bridges[scc.identity]:
                issue("violated", "machine_receipt_bridge_inventory_mismatch", f"sccs.{scc.identity}.bridges", "cross-SCC bridge inventory differs from exact segment endpoints")
            if set(scc.entry_cutpoint_ids) != expected_entries[scc.identity]:
                issue("violated", "machine_receipt_entry_inventory_mismatch", f"sccs.{scc.identity}.entries", "SCC entry inventory differs from exact segment endpoints")
            if set(scc.exit_cutpoint_ids) != expected_exits[scc.identity]:
                issue("violated", "machine_receipt_exit_inventory_mismatch", f"sccs.{scc.identity}.exits", "SCC exit inventory differs from exact segment endpoints")

    unit_ids = set(certificate.machine_unit_ids)
    scc_index = {item.identity: item for item in certificate.sccs}
    all_scc_units: set[str] = set()
    unit_owner: dict[str, str] = {}
    for scc in certificate.sccs:
        local_units = set(scc.unit_ids)
        all_scc_units |= local_units
        for unit_id in scc.unit_ids:
            previous = unit_owner.setdefault(unit_id, scc.identity)
            if previous != scc.identity:
                issue("violated", "machine_unit_in_multiple_sccs", f"sccs.{scc.identity}", f"machine unit {unit_id!r} is already owned by {previous!r}")
        if not local_units:
            issue("incomplete", "empty_scc_unit_inventory", f"sccs.{scc.identity}", "SCC has no machine units")
        if not local_units <= unit_ids:
            issue("violated", "unknown_scc_machine_unit", f"sccs.{scc.identity}", "SCC references a unit outside the exact machine inventory")
        cutpoints = set(scc.cutpoint_ids)
        if not set(scc.entry_cutpoint_ids) <= cutpoints or not set(scc.exit_cutpoint_ids) <= cutpoints:
            issue("violated", "unknown_scc_cutpoint", f"sccs.{scc.identity}", "entry or exit lies outside the SCC cutpoint inventory")
        if not scc.transition_ids:
            issue("incomplete", "missing_scc_transitions", f"sccs.{scc.identity}", "SCC has no represented preservation transition")
    # Acyclic prologue, bridge, and epilogue units belong to exact finite
    # segments, not to cyclic invariant records.

    variables = {item.identity: item for item in certificate.variables}
    predicates = {item.identity: item for item in certificate.predicates}
    invariant_ids = {item.identity for item in certificate.predicates if item.kind == "invariant"}
    postcondition_ids = {item.identity for item in certificate.predicates if item.kind == "postcondition"}
    invariants_by_scc = {
        scc_id: {
            item.identity
            for item in certificate.predicates
            if item.scc_id == scc_id and item.kind == "invariant"
        }
        for scc_id in scc_index
    }
    postconditions_by_scc = {
        scc_id: {
            item.identity
            for item in certificate.predicates
            if item.scc_id == scc_id and item.kind == "postcondition"
        }
        for scc_id in scc_index
    }
    for present, code, location, detail in (
        (bool(certificate.sccs), "missing_scc_inventory", "machine.sccs", "inductive certificate has no SCC records"),
        (bool(certificate.variables), "missing_loop_variables", "variables", "inductive certificate has no finite loop variables"),
        (bool(invariant_ids), "missing_invariant_inventory", "predicates", "inductive certificate has no invariant predicates"),
        (bool(postcondition_ids), "missing_postcondition_inventory", "predicates", "inductive certificate has no postconditions"),
        (bool(certificate.completions), "missing_completion_inventory", "completions", "operation has no exact completion inventory"),
    ):
        if not present:
            issue("incomplete", code, location, detail)
    for variable in certificate.variables:
        if variable.domain.kind in {"bounded_bytes", "nul_terminated_bytes"}:
            payload = variable.domain.to_payload()
            extent_id = str(payload["extent_variable_id"])
            extent = variables.get(extent_id)
            if payload["access"] != "read":
                issue("incomplete", "writable_bytes_unsupported", f"variables.{variable.identity}", "initial profile supports only read-only bounded byte facts")
            if extent is None or extent.domain.kind != "unsigned":
                issue("violated", "invalid_byte_extent_variable", f"variables.{variable.identity}", "bounded byte extent is not an unsigned loop variable")
            if variable.domain.kind == "nul_terminated_bytes" and (
                extent is None
                or extent.origin.kind != "byte_extent"
                or extent.origin.reference_id != variable.identity
            ):
                issue("violated", "invalid_nul_extent_origin", f"variables.{variable.identity}", "NUL-terminated extent is not bound to the same byte view")
        elif variable.domain.kind == "unsupported":
            issue("incomplete", "variable_domain_unsupported", f"variables.{variable.identity}", "variable domain is outside the conservative induction profile")
    for predicate in certificate.predicates:
        if predicate.scc_id not in scc_index:
            issue("violated", "unknown_predicate_scc", f"predicates.{predicate.identity}", "predicate references an unknown SCC")
    expressions: list[tuple[str, ExpressionV1]] = []
    expressions.extend((f"predicates.{item.identity}", item.expression) for item in certificate.predicates)
    expressions.extend((f"preservation.{item.identity}.guard", item.guard) for item in certificate.preservation)
    expressions.extend((f"preservation.{item.identity}.updates.{update.variable_id}", update.expression) for item in certificate.preservation for update in item.updates)
    expressions.extend((f"bridges.{item.identity}.guard", item.guard) for item in certificate.bridges)
    expressions.extend((f"bridges.{item.identity}.updates.{update.variable_id}", update.expression) for item in certificate.bridges for update in item.updates)
    expressions.extend((f"decreases.{item.identity}.before", item.before) for item in certificate.decreases)
    expressions.extend((f"decreases.{item.identity}.after", item.after) for item in certificate.decreases)
    expressions.extend((f"exits.{item.identity}.guard", item.guard) for item in certificate.exits)
    for location, expression in expressions:
        for error in expression.sort_errors():
            issue("violated", "expression_sort_mismatch", location, error)
        unsupported = set(expression.operations()) & {"resource_value", "callback_value"}
        if unsupported:
            issue("incomplete", "expression_profile_unsupported", location, f"unsupported logical operations: {sorted(unsupported)!r}")
        missing_vars = set(expression.references("loop_variable")) - variables.keys()
        if missing_vars:
            issue("violated", "unknown_loop_variable", location, f"unknown loop variables: {sorted(missing_vars)!r}")
        missing_views = set(expression.references("byte_read")) - variables.keys()
        for view_id in sorted(missing_views):
            issue("violated", "unknown_byte_view", location, f"unknown byte view {view_id!r}")
        for view_id in set(expression.references("byte_read")) & variables.keys():
            if variables[view_id].domain.kind not in {"bounded_bytes", "nul_terminated_bytes"}:
                issue("violated", "byte_read_non_view", location, f"{view_id!r} is not a bounded byte view")
        extent_views = set(expression.references("byte_extent"))
        for view_id in sorted(extent_views - variables.keys()):
            issue("violated", "unknown_byte_view", location, f"unknown byte view {view_id!r}")
        for view_id in extent_views & variables.keys():
            if variables[view_id].domain.kind not in {"bounded_bytes", "nul_terminated_bytes"}:
                issue("violated", "byte_extent_non_view", location, f"{view_id!r} is not a byte view")
    for predicate in certificate.predicates:
        if predicate.expression.result_sort() != "bool":
            issue("violated", "predicate_not_boolean", f"predicates.{predicate.identity}", "invariant and postcondition expressions must be Boolean")
    for witness in certificate.preservation:
        if witness.guard.result_sort() != "bool":
            issue("violated", "guard_not_boolean", f"preservation.{witness.identity}.guard", "preservation guard must be Boolean")
        for update in witness.updates:
            if update.expression.result_sort() != "word":
                issue("violated", "update_not_scalar", f"preservation.{witness.identity}.updates.{update.variable_id}", "initial profile permits scalar or enum updates only")
    for witness in certificate.bridges:
        if witness.guard.result_sort() != "bool":
            issue("violated", "guard_not_boolean", f"bridges.{witness.identity}.guard", "bridge guard must be Boolean")
        for update in witness.updates:
            if update.expression.result_sort() != "word":
                issue("violated", "update_not_scalar", f"bridges.{witness.identity}.updates.{update.variable_id}", "initial profile permits scalar or enum updates only")
    for witness in certificate.decreases:
        if witness.before.result_sort() != "word" or witness.after.result_sort() != "word":
            issue("violated", "decrease_not_scalar", f"decreases.{witness.identity}", "strict decrease requires scalar expressions")
    for witness in certificate.exits:
        if witness.guard.result_sort() != "bool":
            issue("violated", "guard_not_boolean", f"exits.{witness.identity}.guard", "exit guard must be Boolean")

    init_by_entry = {(item.scc_id, item.cutpoint_id): item for item in certificate.initialization}
    preservation_by_transition = {(item.scc_id, item.transition_id): item for item in certificate.preservation}
    bridge_by_transition = {item.transition_id: item for item in certificate.bridges}
    decrease_by_transition = {(item.scc_id, item.transition_id): item for item in certificate.decreases}
    exit_by_cutpoint = {(item.scc_id, item.cutpoint_id): item for item in certificate.exits}
    completion_index = {item.identity: item for item in certificate.completions}
    for label, rows, keys in (
        ("initialization", certificate.initialization, [(item.scc_id, item.cutpoint_id) for item in certificate.initialization]),
        ("preservation", certificate.preservation, [(item.scc_id, item.transition_id) for item in certificate.preservation]),
        ("bridges", certificate.bridges, [item.transition_id for item in certificate.bridges]),
        ("decreases", certificate.decreases, [(item.scc_id, item.transition_id) for item in certificate.decreases]),
        ("exits", certificate.exits, [(item.scc_id, item.cutpoint_id) for item in certificate.exits]),
    ):
        if len(keys) != len(set(keys)):
            issue("violated", "duplicate_obligation_coverage", label, f"multiple {label} witnesses claim the same SCC obligation")
    for witness in certificate.initialization:
        scc = scc_index.get(witness.scc_id)
        if scc is None or witness.cutpoint_id not in scc.entry_cutpoint_ids:
            issue("violated", "unexpected_initialization_witness", f"initialization.{witness.identity}", "witness does not belong to an SCC entry")
        if not set(witness.establishes) <= invariants_by_scc.get(witness.scc_id, set()):
            issue("violated", "initialization_predicate_mismatch", f"initialization.{witness.identity}", "witness references an unknown or non-invariant predicate")
    for witness in certificate.preservation:
        if witness.scc_id not in scc_index:
            issue("violated", "unknown_preservation_scc", f"preservation.{witness.identity}", "preservation references an unknown SCC")
        exact_segment = exact_segments.get(witness.transition_id)
        if exact_segment is not None and not _witness_matches_exact_segment(
            witness.source_cutpoint_id,
            witness.target_cutpoint_id,
            witness.machine_unit_ids,
            exact_segment,
        ):
            issue("violated", "preservation_exact_segment_mismatch", f"preservation.{witness.identity}", "preservation endpoints or units differ from the exact machine segment")
    for witness in certificate.bridges:
        source_scc = scc_index.get(witness.source_scc_id)
        target_scc = scc_index.get(witness.target_scc_id)
        if source_scc is None or target_scc is None:
            issue("violated", "unknown_bridge_scc", f"bridges.{witness.identity}", "bridge references an unknown SCC")
            continue
        if witness.transition_id not in source_scc.bridge_ids:
            issue("violated", "bridge_inventory_mismatch", f"bridges.{witness.identity}", "bridge is absent from its source SCC inventory")
        if witness.source_cutpoint_id not in source_scc.cutpoint_ids:
            issue("violated", "bridge_source_cutpoint_mismatch", f"bridges.{witness.identity}", "bridge source lies outside its source SCC")
        if witness.target_cutpoint_id not in target_scc.entry_cutpoint_ids:
            issue("violated", "bridge_target_cutpoint_mismatch", f"bridges.{witness.identity}", "bridge target is not a target-SCC entry")
        if set(witness.establishes) != invariants_by_scc.get(witness.target_scc_id, set()):
            issue("incomplete", "bridge_invariant_gap", f"bridges.{witness.identity}", "bridge does not establish the exact target invariant inventory")
        exact_segment = exact_segments.get(witness.transition_id)
        if exact_segment is not None and not _witness_matches_exact_segment(
            witness.source_cutpoint_id,
            witness.target_cutpoint_id,
            witness.machine_unit_ids,
            exact_segment,
        ):
            issue("violated", "bridge_exact_segment_mismatch", f"bridges.{witness.identity}", "bridge endpoints or units differ from the exact machine segment")
        unknown_updates = {item.variable_id for item in witness.updates} - variables.keys()
        if unknown_updates:
            issue("violated", "unknown_updated_variable", f"bridges.{witness.identity}", f"unknown variables: {sorted(unknown_updates)!r}")
    for witness in certificate.decreases:
        if witness.measure_id not in variables:
            issue("violated", "unknown_decrease_measure", f"decreases.{witness.identity}", "strict-decrease measure is not a declared variable")
        if witness.scc_id not in scc_index:
            issue("violated", "unknown_decrease_scc", f"decreases.{witness.identity}", "decrease references an unknown SCC")
    for witness in certificate.exits:
        scc = scc_index.get(witness.scc_id)
        if scc is None or witness.cutpoint_id not in scc.exit_cutpoint_ids:
            issue("violated", "unexpected_exit_witness", f"exits.{witness.identity}", "witness does not belong to an SCC exit")
    for scc in certificate.sccs:
        if not invariants_by_scc[scc.identity]:
            issue("incomplete", "missing_scc_invariant", f"sccs.{scc.identity}", "SCC has no local inductive invariant")
        if scc.completion_ids and not postconditions_by_scc[scc.identity]:
            issue("incomplete", "missing_scc_postcondition", f"sccs.{scc.identity}", "SCC has no local exit postcondition")
        for cutpoint in scc.entry_cutpoint_ids:
            witness = init_by_entry.get((scc.identity, cutpoint))
            incoming = [
                item
                for item in certificate.bridges
                if item.target_scc_id == scc.identity
                and item.target_cutpoint_id == cutpoint
            ]
            if witness is None:
                if not incoming:
                    issue("incomplete", "missing_initialization_witness", f"sccs.{scc.identity}.entries.{cutpoint}", "entry invariant is not initialized")
            elif set(witness.establishes) != invariants_by_scc[scc.identity]:
                issue("incomplete", "initialization_invariant_gap", f"initialization.{witness.identity}", "initialization does not establish the exact invariant inventory")
        for transition_id in scc.transition_ids:
            witness = preservation_by_transition.get((scc.identity, transition_id))
            if witness is None:
                issue("incomplete", "missing_preservation_witness", f"sccs.{scc.identity}.transitions.{transition_id}", "transition has no preservation witness")
            else:
                if witness.source_cutpoint_id not in scc.cutpoint_ids or witness.target_cutpoint_id not in scc.cutpoint_ids:
                    issue("violated", "preservation_cutpoint_mismatch", f"preservation.{witness.identity}", "preservation transition leaves the SCC cutpoint inventory")
                if not set(witness.machine_unit_ids) <= set(scc.unit_ids):
                    issue("violated", "preservation_unit_mismatch", f"preservation.{witness.identity}", "preservation references units outside its SCC")
                if set(witness.preserves) != invariants_by_scc[scc.identity]:
                    issue("incomplete", "preservation_invariant_gap", f"preservation.{witness.identity}", "preservation does not establish the exact invariant inventory")
                unknown_updates = {item.variable_id for item in witness.updates} - variables.keys()
                if unknown_updates:
                    issue("violated", "unknown_updated_variable", f"preservation.{witness.identity}", f"unknown variables: {sorted(unknown_updates)!r}")
            if (scc.identity, transition_id) not in decrease_by_transition:
                issue("incomplete", "missing_strict_decrease_witness", f"sccs.{scc.identity}.transitions.{transition_id}", "loop transition has no strict-decrease witness")
        for bridge_id in scc.bridge_ids:
            if bridge_id not in bridge_by_transition:
                issue("incomplete", "missing_bridge_witness", f"sccs.{scc.identity}.bridges.{bridge_id}", "cross-SCC transition has no bridge witness")
        for cutpoint in scc.exit_cutpoint_ids:
            witness = exit_by_cutpoint.get((scc.identity, cutpoint))
            if witness is None:
                issue("incomplete", "missing_exit_witness", f"sccs.{scc.identity}.exits.{cutpoint}", "exit guard and postcondition are not represented")
            elif not set(witness.establishes) <= postconditions_by_scc[scc.identity]:
                issue("violated", "exit_postcondition_mismatch", f"exits.{witness.identity}", "exit establishes an unknown or invariant predicate")
            elif not set(witness.completion_ids) <= set(scc.completion_ids):
                issue("violated", "exit_completion_mismatch", f"exits.{witness.identity}", "exit references a completion outside its SCC inventory")
        if set(scc.completion_ids) - completion_index.keys():
            issue("incomplete", "missing_completion_witness", f"sccs.{scc.identity}.completions", "exact completion inventory is not represented")
        represented_by_exits = {
            completion_id
            for witness in certificate.exits
            if witness.scc_id == scc.identity
            for completion_id in witness.completion_ids
        }
        if represented_by_exits != set(scc.completion_ids):
            issue("incomplete", "exit_completion_inventory_gap", f"sccs.{scc.identity}.exits", "SCC exits do not jointly cover the exact completion inventory")
        represented_postconditions = {
            predicate_id
            for witness in certificate.exits
            if witness.scc_id == scc.identity
            for predicate_id in witness.establishes
        }
        if represented_postconditions != postconditions_by_scc[scc.identity]:
            issue("incomplete", "exit_postcondition_inventory_gap", f"sccs.{scc.identity}.exits", "SCC exits do not jointly establish the exact postcondition inventory")
        completion_occurrences = [
            completion_id
            for witness in certificate.exits
            if witness.scc_id == scc.identity
            for completion_id in witness.completion_ids
        ]
        if len(completion_occurrences) != len(set(completion_occurrences)):
            issue("violated", "completion_owned_by_multiple_exits", f"sccs.{scc.identity}.exits", "one completion is claimed by multiple exit witnesses")

    expected_preservation = {(s.identity, transition) for s in certificate.sccs for transition in s.transition_ids}
    if set(preservation_by_transition) - expected_preservation:
        issue("violated", "unexpected_preservation_transition", "preservation", "preservation contains a transition absent from the SCC inventory")
    if set(decrease_by_transition) != expected_preservation:
        extra = set(decrease_by_transition) - expected_preservation
        if extra:
            issue("violated", "unexpected_decrease_transition", "decreases", "decrease contains a transition absent from the SCC inventory")
    expected_bridges = {item for scc in certificate.sccs for item in scc.bridge_ids}
    if set(bridge_by_transition) - expected_bridges:
        issue("violated", "unexpected_bridge_transition", "bridges", "bridge contains a transition absent from the SCC inventory")
    expected_completions = {item for scc in certificate.sccs for item in scc.completion_ids}
    if set(completion_index) - expected_completions:
        issue("violated", "unexpected_completion", "completions", "completion is absent from the exact SCC inventory")
    for completion in certificate.completions:
        scc = scc_index.get(completion.scc_id)
        exit_witness = next((item for item in certificate.exits if item.identity == completion.exit_witness_id), None)
        if scc is None or exit_witness is None or exit_witness.scc_id != completion.scc_id or completion.identity not in exit_witness.completion_ids:
            issue("violated", "completion_exit_mismatch", f"completions.{completion.identity}", "completion is not owned by its declared exit witness")
        # Completion segments commonly leave the cyclic SCC through an
        # acyclic epilogue. Their exact unit inventory is authorized by the
        # machine segment receipt rather than SCC membership.
        if not set(completion.postcondition_ids) <= postconditions_by_scc.get(completion.scc_id, set()):
            issue("violated", "completion_postcondition_mismatch", f"completions.{completion.identity}", "completion references an unknown postcondition")
    for scc in certificate.sccs:
        completion_postconditions = {
            predicate_id
            for completion in certificate.completions
            if completion.scc_id == scc.identity
            for predicate_id in completion.postcondition_ids
        }
        if completion_postconditions != postconditions_by_scc[scc.identity]:
            issue("incomplete", "completion_postcondition_inventory_gap", f"sccs.{scc.identity}.completions", "SCC completions do not jointly establish the exact postcondition inventory")

    evidence_nodes = {
        item.identity: item.dependencies
        for rows in (certificate.initialization, certificate.preservation, certificate.bridges, certificate.decreases, certificate.exits, certificate.completions)
        for item in rows
    }
    external_ids = {item.identity for item in certificate.dependencies}
    for node_id, dependencies in evidence_nodes.items():
        unknown = set(dependencies) - evidence_nodes.keys() - external_ids
        if unknown:
            issue("violated", "unknown_evidence_dependency", f"evidence.{node_id}", f"unknown dependencies: {sorted(unknown)!r}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            issue("violated", "self_justifying_dependency_cycle", f"evidence.{node_id}", "evidence depends circularly on its own conclusion")
            return
        visiting.add(node_id)
        for dependency in evidence_nodes.get(node_id, ()):
            if dependency in evidence_nodes:
                visit(dependency)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in sorted(evidence_nodes):
        visit(node_id)

    if machine_receipt is not None and source_receipt is not None:
        if source_receipt.machine_receipt_sha256 != machine_receipt.receipt_sha256:
            issue(
                "violated",
                "source_machine_receipt_binding_mismatch",
                "receipts.source_semantics",
                "source refinement was checked against a different machine receipt",
            )
        if (
            source_receipt.source_plan_sha256 != bindings.source_plan_sha256
            or source_receipt.relation_sha256 != bindings.cutpoint_relation_sha256
            or source_receipt.implementation_sha256 != bindings.implementation_sha256
        ):
            issue(
                "violated",
                "source_receipt_artifact_binding_mismatch",
                "receipts.source_semantics",
                "source refinement was checked against different source or relation artifacts",
            )
        expected_obligations = set(evidence_nodes)
        observed_obligations = {
            item.identity for item in source_receipt.obligations
        }
        if observed_obligations != expected_obligations:
            issue(
                "incomplete",
                "source_obligation_inventory_gap",
                "receipts.source_semantics",
                "source refinement does not cover the exact certificate evidence inventory",
            )
        inventory = machine_receipt.segment_inventory.to_value()
        assert isinstance(inventory, dict)
        machine_segment_ids = {
            str(row["segment_id"])
            for row in inventory["segments"]
            if isinstance(row, Mapping)
        }
        represented_segment_ids = {
            segment_id
            for obligation in source_receipt.obligations
            for segment_id in obligation.segment_ids
        }
        if represented_segment_ids != machine_segment_ids:
            issue(
                "incomplete",
                "source_machine_segment_inventory_gap",
                "receipts.source_semantics",
                "source refinement does not jointly cover every exact machine segment",
            )
        for obligation in source_receipt.obligations:
            unknown_segments = set(obligation.segment_ids) - machine_segment_ids
            if unknown_segments:
                issue(
                    "violated",
                    "source_obligation_unknown_machine_segment",
                    f"source_obligations.{obligation.identity}",
                    f"unknown exact machine segments: {sorted(unknown_segments)!r}",
                )

    issues = list({
        (item.status, item.code, item.location, item.detail): item for item in issues
    }.values())
    issues.sort(key=lambda item: (item.status, item.code, item.location, item.detail))
    status = "violated" if any(item.status == "violated" for item in issues) else "incomplete" if issues else "complete"
    assurance = {
        "certificate_inventory_checked": True,
        "source_semantics_checked": "source_semantics" in valid_receipts,
        "machine_semantics_checked": "machine_semantics" in valid_receipts,
        "receipt_contents_replayed_by_this_checker": bool(
            {"source_semantics", "machine_semantics"} <= valid_receipts
        ),
        "raw_c_or_register_expressions_accepted": False,
        "unsupported_constructs_fail_closed": True,
    }
    core = {"format": INDUCTIVE_OPERATION_CHECK_V1, "status": status, "certificate_sha256": certificate.certificate_sha256, "issues": [item.to_payload() for item in issues], "assurance": assurance}
    return InductiveOperationCheckV1(status, certificate.certificate_sha256, tuple(issues), CanonicalValueV3.of(assurance), canonical_sha256_v3(core))


__all__ = [
    "INDUCTIVE_OPERATION_CERTIFICATE_V1",
    "INDUCTIVE_OPERATION_CHECK_V1",
    "InductiveOperationCertificateV1",
    "InductiveOperationCheckV1",
    "InductiveOperationContractError",
    "check_inductive_operation_certificate",
]
