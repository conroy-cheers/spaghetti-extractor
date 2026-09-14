"""Canonical constructive relations between portable and machine worlds.

The relation language is deliberately small.  Boundary bindings are lenses:
they have an observer, a realizer, and exact footprints.  Assertions can
strengthen a lens or describe an inductive cutpoint, but cannot stand in for
an executable boundary adaptation.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
RELATION_PHASES = frozenset(
    {
        "entry", "exit", "cutpoint", "event_before", "event_after",
        "caller_before", "callee_entry", "callee_exit", "caller_after",
    }
)
RELATION_CLAUSE_KINDS = frozenset({"binding", "assertion", "effect_link"})
RELATION_PATH_ROOTS = frozenset(
    {"parameter", "result", "state", "protocol", "effect", "interaction"}
)
RELATION_PLACE_KINDS = frozenset(
    {
        "register",
        "flag",
        "stack",
        "static_slot",
        "memory",
        "control_target",
        "action_value",
        "capability_slot",
        "x87_register",
        "vector_register",
    }
)
RELATION_SORT_KINDS = frozenset(
    {"bool", "bitvector", "scalar", "enum", "record", "reference", "view", "resource", "callback"}
)

_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class CheckedRelationIRError(ValueError):
    """A relation is malformed, stale, nonconstructive, or ambiguous."""


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CheckedRelationIRError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise CheckedRelationIRError(f"{context} must be an array")
    return value


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise CheckedRelationIRError(
            f"{context} fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}"
        )


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CheckedRelationIRError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _ID.fullmatch(result) is None:
        raise CheckedRelationIRError(f"{context} is not canonical")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise CheckedRelationIRError(f"{context} must be a SHA-256 digest")
    return result


def _uint(value: object, context: str, *, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CheckedRelationIRError(f"{context} must be an unsigned integer")
    if maximum is not None and value > maximum:
        raise CheckedRelationIRError(f"{context} is out of range")
    return value


@dataclass(frozen=True)
class RelationSortV1:
    kind: str
    width: int | None = None
    type_id: str | None = None

    @classmethod
    def parse(cls, value: object, context: str = "relation sort") -> "RelationSortV1":
        row = _object(value, context)
        kind = _text(row.get("kind"), f"{context} kind")
        if kind not in RELATION_SORT_KINDS:
            raise CheckedRelationIRError(f"{context} kind {kind!r} is unsupported")
        if kind == "bool":
            _exact(row, {"kind"}, context)
            return cls(kind)
        if kind == "bitvector":
            _exact(row, {"kind", "width"}, context)
            width = _uint(row["width"], f"{context} width")
            if not 1 <= width <= 65536:
                raise CheckedRelationIRError(f"{context} bitvector width is unsupported")
            return cls(kind, width=width)
        _exact(row, {"kind", "type_id"}, context)
        return cls(kind, type_id=_identifier(row["type_id"], f"{context} type id"))

    def to_payload(self) -> dict[str, object]:
        if self.kind == "bool":
            return {"kind": self.kind}
        if self.kind == "bitvector":
            return {"kind": self.kind, "width": self.width}
        return {"kind": self.kind, "type_id": self.type_id}


BOOL_SORT = RelationSortV1("bool")


@dataclass(frozen=True)
class LogicalPathV1:
    root: str
    identity: str
    fields: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: object, context: str = "logical path") -> "LogicalPathV1":
        row = _object(value, context)
        _exact(row, {"root", "id", "fields"}, context)
        root = _text(row["root"], f"{context} root")
        if root not in RELATION_PATH_ROOTS:
            raise CheckedRelationIRError(f"{context} root is unsupported")
        fields = tuple(
            _identifier(item, f"{context} field {index}")
            for index, item in enumerate(_array(row["fields"], f"{context} fields"))
        )
        return cls(root, _identifier(row["id"], f"{context} id"), fields)

    @property
    def key(self) -> tuple[str, str, tuple[str, ...]]:
        return self.root, self.identity, self.fields

    def to_payload(self) -> dict[str, object]:
        return {"root": self.root, "id": self.identity, "fields": list(self.fields)}


@dataclass(frozen=True)
class MachinePlaceV1:
    kind: str
    phase: str
    width: int | None
    payload: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str = "machine place") -> "MachinePlaceV1":
        row = _object(value, context)
        _exact(row, {"kind", "phase", "width", "selector"}, context)
        kind = _text(row["kind"], f"{context} kind")
        if kind not in RELATION_PLACE_KINDS:
            raise CheckedRelationIRError(f"{context} kind {kind!r} is unsupported")
        phase = _text(row["phase"], f"{context} phase")
        if phase not in RELATION_PHASES:
            raise CheckedRelationIRError(f"{context} phase is unsupported")
        width_value = row["width"]
        width = None if width_value is None else _uint(width_value, f"{context} width")
        if width is not None and not 1 <= width <= 65536:
            raise CheckedRelationIRError(f"{context} width is unsupported")
        selector = _object(row["selector"], f"{context} selector")
        if not selector:
            raise CheckedRelationIRError(f"{context} selector must be nonempty")
        return cls(kind, phase, width, copy.deepcopy(dict(selector)))

    @property
    def key(self) -> str:
        return canonical_sha256_v3(self.to_payload())

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "phase": self.phase,
            "width": self.width,
            "selector": copy.deepcopy(dict(self.payload)),
        }


_NULLARY = frozenset({"true", "false", "projected_value", "null_ref"})
_UNARY = frozenset(
    {
        "not",
        "bit_not",
        "zero_extend",
        "sign_extend",
        "truncate",
        "ref_offset",
        "ref_remaining",
        "view_address",
        "view_extent",
        "view_has_zero",
        "ref_is_null",
        "bitcast",
        "x87_decode",
        "x87_encode",
    }
)
_BINARY = frozenset(
    {
        "add",
        "sub",
        "bit_and",
        "bit_or",
        "bit_xor",
        "eq",
        "ult",
        "ule",
        "and",
        "or",
        "same_origin",
        "borrowed_interior",
        "pointer_difference",
        "derive_ref",
    }
)


@dataclass(frozen=True)
class RelationExpressionV1:
    op: str
    sort: RelationSortV1
    arguments: tuple["RelationExpressionV1", ...]
    attributes: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str = "relation expression") -> "RelationExpressionV1":
        row = _object(value, context)
        _exact(row, {"op", "sort", "args", "attributes"}, context)
        op = _identifier(row["op"], f"{context} operation")
        sort = RelationSortV1.parse(row["sort"], f"{context} sort")
        args = tuple(
            cls.parse(item, f"{context} argument {index}")
            for index, item in enumerate(_array(row["args"], f"{context} arguments"))
        )
        attributes = copy.deepcopy(dict(_object(row["attributes"], f"{context} attributes")))
        result = cls(op, sort, args, attributes)
        result._validate(context)
        return result

    def _validate(self, context: str) -> None:
        arity: int | None
        if self.op in _NULLARY:
            arity = 0
        elif self.op in _UNARY:
            arity = 1
        elif self.op in _BINARY:
            arity = 2
        elif self.op == "ite":
            arity = 3
        elif self.op in {
            "const",
            "logical",
            "machine",
            "field",
            "make_ref",
            "make_view",
            "make_capability",
            "record",
            "byte_read",
            "authority_call",
            "concat",
            "slice",
            "unspecified",
        }:
            arity = None
        else:
            raise CheckedRelationIRError(f"{context} operation {self.op!r} is unsupported")
        if arity is not None and len(self.arguments) != arity:
            raise CheckedRelationIRError(f"{context} operation has the wrong arity")
        if self.op not in {"const", "logical", "machine", "field", "record", "authority_call", "slice", "unspecified"} and self.attributes:
            raise CheckedRelationIRError(
                f"{context} operation {self.op!r} has unsupported attributes"
            )
        if self.op in {"true", "false", "not", "and", "or", "eq", "ult", "ule", "same_origin", "borrowed_interior", "ref_is_null", "view_has_zero"} and self.sort != BOOL_SORT:
            raise CheckedRelationIRError(f"{context} Boolean operation has non-Boolean result")
        if self.op == "view_has_zero" and self.arguments[0].sort.kind != "view":
            raise CheckedRelationIRError(f"{context} current-memory predicate requires a view")
        if self.op in {"not"} and self.arguments[0].sort != BOOL_SORT:
            raise CheckedRelationIRError(f"{context} Boolean operand has the wrong sort")
        if self.op in {"and", "or"} and any(item.sort != BOOL_SORT for item in self.arguments):
            raise CheckedRelationIRError(f"{context} Boolean operands have the wrong sort")
        if self.op in {"eq", "ult", "ule"} and self.arguments[0].sort != self.arguments[1].sort:
            raise CheckedRelationIRError(f"{context} comparison operands differ")
        if self.op == "ite":
            if self.arguments[0].sort != BOOL_SORT or self.arguments[1].sort != self.arguments[2].sort or self.sort != self.arguments[1].sort:
                raise CheckedRelationIRError(f"{context} conditional sorts are incompatible")
        if self.op == "const":
            if self.arguments or set(self.attributes) != {"value"}:
                raise CheckedRelationIRError(f"{context} constant shape is invalid")
            value = _uint(self.attributes["value"], f"{context} value")
            if self.sort.kind == "bitvector" and value >= (1 << int(self.sort.width or 0)):
                raise CheckedRelationIRError(f"{context} constant is outside its width")
        if self.op == "logical":
            if self.arguments or set(self.attributes) != {"path"}:
                raise CheckedRelationIRError(f"{context} logical reference shape is invalid")
            LogicalPathV1.parse(self.attributes["path"], f"{context} logical path")
        if self.op == "machine":
            if self.arguments or set(self.attributes) != {"place"}:
                raise CheckedRelationIRError(f"{context} machine reference shape is invalid")
            place = MachinePlaceV1.parse(self.attributes["place"], f"{context} machine place")
            if self.sort.kind == "bitvector" and place.width != self.sort.width:
                raise CheckedRelationIRError(f"{context} machine place width differs from its sort")
            if self.sort.kind == "bool" and place.kind != "flag":
                raise CheckedRelationIRError(f"{context} Boolean machine value is not a flag")
            if self.sort.kind not in {"bool", "bitvector"} and place.kind != "capability_slot":
                raise CheckedRelationIRError(
                    f"{context} structured machine value lacks a capability projection"
                )
        if self.op in {"add", "sub", "bit_and", "bit_or", "bit_xor"}:
            if self.sort.kind != "bitvector" or any(item.sort != self.sort for item in self.arguments):
                raise CheckedRelationIRError(f"{context} bitvector operands are incompatible")
        if self.op == "bit_not" and (
            self.sort.kind != "bitvector" or self.arguments[0].sort != self.sort
        ):
            raise CheckedRelationIRError(f"{context} bitwise operand is incompatible")
        if self.op in {"zero_extend", "sign_extend", "truncate"}:
            source = self.arguments[0].sort
            if source.kind != "bitvector" or self.sort.kind != "bitvector":
                raise CheckedRelationIRError(f"{context} width conversion is not bitvector typed")
            growing = int(source.width or 0) < int(self.sort.width or 0)
            if (self.op == "truncate" and growing) or (
                self.op != "truncate" and not growing
            ):
                raise CheckedRelationIRError(f"{context} width conversion has the wrong direction")
        if self.op == "bitcast" and (
            self.sort.kind != "bitvector"
            or self.arguments[0].sort.kind != "bitvector"
            or self.sort.width != self.arguments[0].sort.width
        ):
            raise CheckedRelationIRError(f"{context} bitcast must preserve bit width")
        if self.op == "x87_decode" and (
            self.sort.kind != "bitvector"
            or self.sort.width not in {16, 32, 64, 80}
            or self.arguments[0].sort != RelationSortV1("bitvector", width=80)
        ):
            raise CheckedRelationIRError(f"{context} x87 decode shape is invalid")
        if self.op == "x87_encode" and (
            self.sort != RelationSortV1("bitvector", width=80)
            or self.arguments[0].sort.kind != "bitvector"
            or self.arguments[0].sort.width not in {16, 32, 64, 80}
        ):
            raise CheckedRelationIRError(f"{context} x87 encode shape is invalid")
        if self.op == "concat":
            if not self.arguments or self.sort.kind != "bitvector" or any(
                item.sort.kind != "bitvector" for item in self.arguments
            ):
                raise CheckedRelationIRError(f"{context} concatenation is not bitvector typed")
            if self.sort.width != sum(int(item.sort.width or 0) for item in self.arguments):
                raise CheckedRelationIRError(f"{context} concatenation width is incorrect")
        if self.op == "slice":
            if len(self.arguments) != 1 or self.sort.kind != "bitvector" or self.arguments[0].sort.kind != "bitvector" or set(self.attributes) != {"offset_bits"}:
                raise CheckedRelationIRError(f"{context} slice shape is invalid")
            offset = _uint(self.attributes["offset_bits"], f"{context} slice offset")
            if offset + int(self.sort.width or 0) > int(self.arguments[0].sort.width or 0):
                raise CheckedRelationIRError(f"{context} slice exceeds its source")
        if self.op == "unspecified":
            if self.arguments or self.sort.kind != "bitvector" or set(self.attributes) != {"reason"}:
                raise CheckedRelationIRError(f"{context} unspecified value shape is invalid")
            _identifier(self.attributes["reason"], f"{context} unspecified reason")
        if self.op in {"ult", "ule"} and self.arguments[0].sort.kind != "bitvector":
            raise CheckedRelationIRError(f"{context} ordering requires bitvector operands")
        if self.op in {"make_ref", "derive_ref", "null_ref"} and self.sort.kind != "reference":
            raise CheckedRelationIRError(f"{context} reference operation has a non-reference sort")
        if self.op == "make_ref" and len(self.arguments) != 5:
            raise CheckedRelationIRError(f"{context} make_ref requires domain, object, generation, offset, and extent")
        if self.op == "make_ref" and any(item.sort.kind != "bitvector" for item in self.arguments):
            raise CheckedRelationIRError(f"{context} reference origin fields must be bitvectors")
        if self.op == "derive_ref" and (
            self.arguments[0].sort != self.sort
            or self.arguments[1].sort.kind != "bitvector"
        ):
            raise CheckedRelationIRError(f"{context} reference derivation operands are incompatible")
        if self.op == "ref_offset" and (
            self.arguments[0].sort.kind != "reference" or self.sort.kind != "bitvector"
        ):
            raise CheckedRelationIRError(f"{context} reference offset is incorrectly typed")
        if self.op == "ref_remaining" and (
            self.arguments[0].sort.kind != "reference" or self.sort.kind != "bitvector"
        ):
            raise CheckedRelationIRError(f"{context} reference remainder is incorrectly typed")
        if self.op == "ref_is_null" and self.arguments[0].sort.kind != "reference":
            raise CheckedRelationIRError(f"{context} null test requires a reference")
        if self.op == "same_origin" and (
            self.arguments[0].sort.kind not in {"reference", "view"}
            or self.arguments[1].sort.kind not in {"reference", "view"}
        ):
            raise CheckedRelationIRError(f"{context} origin comparison operands are incompatible")
        if self.op == "borrowed_interior" and (
            self.arguments[0].sort.kind != "reference"
            or self.arguments[1].sort.kind not in {"reference", "view"}
        ):
            raise CheckedRelationIRError(
                f"{context} borrowed-interior operands are incompatible"
            )
        if self.op == "pointer_difference" and (
            self.sort.kind != "bitvector"
            or self.arguments[0].sort != self.arguments[1].sort
            or self.arguments[0].sort.kind != "reference"
        ):
            raise CheckedRelationIRError(f"{context} pointer difference operands are incompatible")
        if self.op == "make_view" and (self.sort.kind != "view" or len(self.arguments) != 2):
            raise CheckedRelationIRError(f"{context} make_view requires a reference and extent")
        if self.op == "make_view" and (
            self.arguments[0].sort.kind != "reference"
            or self.arguments[1].sort.kind != "bitvector"
        ):
            raise CheckedRelationIRError(f"{context} view construction operands are incompatible")
        if self.op == "view_address" and (
            self.arguments[0].sort.kind != "view"
            or self.sort.kind not in {"bitvector", "reference"}
        ):
            raise CheckedRelationIRError(f"{context} view address is incorrectly typed")
        if self.op == "view_extent" and (
            self.arguments[0].sort.kind != "view" or self.sort.kind != "bitvector"
        ):
            raise CheckedRelationIRError(f"{context} view extent is incorrectly typed")
        if self.op == "byte_read" and (
            len(self.arguments) != 2
            or self.arguments[0].sort.kind != "view"
            or self.arguments[1].sort.kind != "bitvector"
            or self.sort != RelationSortV1("bitvector", width=8)
        ):
            raise CheckedRelationIRError(f"{context} byte read operands are incompatible")
        if self.op == "make_capability" and (self.sort.kind not in {"resource", "callback"} or len(self.arguments) != 4):
            raise CheckedRelationIRError(f"{context} capability construction is invalid")
        if self.op == "make_capability" and any(item.sort.kind != "bitvector" for item in self.arguments):
            raise CheckedRelationIRError(f"{context} capability origin fields must be bitvectors")
        if self.op == "field" and (len(self.arguments) != 1 or set(self.attributes) != {"id"}):
            raise CheckedRelationIRError(f"{context} field projection is invalid")
        if self.op == "field" and self.arguments[0].sort.kind != "record":
            raise CheckedRelationIRError(f"{context} field source is not a record")
        if self.op == "record" and (
            self.sort.kind != "record" or set(self.attributes) != {"fields"}
        ):
            raise CheckedRelationIRError(f"{context} record construction is invalid")
        if self.op == "authority_call":
            if set(self.attributes) != {"primitive", "binding"}:
                raise CheckedRelationIRError(
                    f"{context} authority call shape is invalid"
                )
            _identifier(
                self.attributes["primitive"],
                f"{context} authority primitive",
            )
            _identifier(
                self.attributes["binding"],
                f"{context} authority binding",
            )

    def walk(self) -> tuple["RelationExpressionV1", ...]:
        return (self,) + tuple(child for arg in self.arguments for child in arg.walk())

    def machine_places(self) -> tuple[MachinePlaceV1, ...]:
        return tuple(
            MachinePlaceV1.parse(item.attributes["place"])
            for item in self.walk()
            if item.op == "machine"
        )

    def logical_paths(self) -> tuple[LogicalPathV1, ...]:
        return tuple(
            LogicalPathV1.parse(item.attributes["path"])
            for item in self.walk()
            if item.op == "logical"
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "op": self.op,
            "sort": self.sort.to_payload(),
            "args": [item.to_payload() for item in self.arguments],
            "attributes": copy.deepcopy(dict(self.attributes)),
        }


@dataclass(frozen=True)
class MachineWriteV1:
    place: MachinePlaceV1
    value: RelationExpressionV1
    guard: RelationExpressionV1

    @classmethod
    def parse(cls, value: object, context: str) -> "MachineWriteV1":
        row = _object(value, context)
        _exact(row, {"place", "value", "guard"}, context)
        place = MachinePlaceV1.parse(row["place"], f"{context} place")
        expression = RelationExpressionV1.parse(row["value"], f"{context} value")
        guard = RelationExpressionV1.parse(row["guard"], f"{context} guard")
        if guard.sort != BOOL_SORT:
            raise CheckedRelationIRError(f"{context} guard must be Boolean")
        if expression.sort.kind == "bitvector" and expression.sort.width != place.width:
            raise CheckedRelationIRError(f"{context} value width differs from its place")
        return cls(place, expression, guard)

    def to_payload(self) -> dict[str, object]:
        return {
            "place": self.place.to_payload(),
            "value": self.value.to_payload(),
            "guard": self.guard.to_payload(),
        }


@dataclass(frozen=True)
class RelationClauseV1:
    identity: str
    kind: str
    phase: str
    logical_path: LogicalPathV1 | None
    observe: RelationExpressionV1 | None
    realize: tuple[MachineWriteV1, ...]
    predicate: RelationExpressionV1 | None
    effect_id: str | None
    machine_event: Mapping[str, object] | None
    reads: tuple[MachinePlaceV1, ...]
    writes: tuple[MachinePlaceV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "RelationClauseV1":
        row = _object(value, context)
        _exact(
            row,
            {"id", "kind", "phase", "logical_path", "observe", "realize", "predicate", "effect_id", "machine_event", "reads", "writes"},
            context,
        )
        kind = _text(row["kind"], f"{context} kind")
        if kind not in RELATION_CLAUSE_KINDS:
            raise CheckedRelationIRError(f"{context} kind is unsupported")
        phase = _text(row["phase"], f"{context} phase")
        if phase not in RELATION_PHASES:
            raise CheckedRelationIRError(f"{context} phase is unsupported")
        path = None if row["logical_path"] is None else LogicalPathV1.parse(row["logical_path"], f"{context} logical path")
        observe = None if row["observe"] is None else RelationExpressionV1.parse(row["observe"], f"{context} observer")
        realize = tuple(
            MachineWriteV1.parse(item, f"{context} realization {index}")
            for index, item in enumerate(_array(row["realize"], f"{context} realization"))
        )
        predicate = None if row["predicate"] is None else RelationExpressionV1.parse(row["predicate"], f"{context} predicate")
        effect_id = None if row["effect_id"] is None else _identifier(row["effect_id"], f"{context} effect id")
        event = None if row["machine_event"] is None else copy.deepcopy(dict(_object(row["machine_event"], f"{context} machine event")))
        reads = tuple(MachinePlaceV1.parse(item, f"{context} read {index}") for index, item in enumerate(_array(row["reads"], f"{context} reads")))
        writes = tuple(MachinePlaceV1.parse(item, f"{context} write {index}") for index, item in enumerate(_array(row["writes"], f"{context} writes")))
        result = cls(_identifier(row["id"], f"{context} id"), kind, phase, path, observe, realize, predicate, effect_id, event, reads, writes)
        result._validate(context)
        return result

    def _validate(self, context: str) -> None:
        if self.kind == "binding":
            if self.logical_path is None or self.observe is None or self.predicate is not None or self.effect_id is not None or self.machine_event is not None:
                raise CheckedRelationIRError(f"{context} binding shape is invalid")
            if self.logical_path.root in {"result", "state"} and self.phase == "exit" and not self.realize:
                raise CheckedRelationIRError(f"{context} exported binding is nonconstructive")
        elif self.kind == "assertion":
            if self.logical_path is not None or self.observe is not None or self.realize or self.predicate is None or self.effect_id is not None or self.machine_event is not None:
                raise CheckedRelationIRError(f"{context} assertion shape is invalid")
            if self.predicate.sort != BOOL_SORT:
                raise CheckedRelationIRError(f"{context} assertion predicate must be Boolean")
        else:
            if self.logical_path is not None or self.observe is not None or self.realize or self.predicate is not None or self.effect_id is None or self.machine_event is None:
                raise CheckedRelationIRError(f"{context} effect link shape is invalid")
        read_keys = [item.key for item in self.reads]
        write_keys = [item.key for item in self.writes]
        if read_keys != sorted(set(read_keys)) or write_keys != sorted(set(write_keys)):
            raise CheckedRelationIRError(f"{context} footprints must be unique and canonically ordered")
        observed_reads = set()
        for expression in (self.observe, self.predicate):
            if expression is not None:
                observed_reads.update(item.key for item in expression.machine_places())
        for write in self.realize:
            observed_reads.update(item.key for item in write.value.machine_places())
            observed_reads.update(item.key for item in write.guard.machine_places())
        if observed_reads - set(read_keys):
            raise CheckedRelationIRError(f"{context} expression reads are absent from its footprint")
        realized_writes = {item.place.key for item in self.realize}
        if realized_writes != set(write_keys):
            raise CheckedRelationIRError(f"{context} realization differs from its write footprint")

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "kind": self.kind,
            "phase": self.phase,
            "logical_path": None if self.logical_path is None else self.logical_path.to_payload(),
            "observe": None if self.observe is None else self.observe.to_payload(),
            "realize": [item.to_payload() for item in self.realize],
            "predicate": None if self.predicate is None else self.predicate.to_payload(),
            "effect_id": self.effect_id,
            "machine_event": None if self.machine_event is None else copy.deepcopy(dict(self.machine_event)),
            "reads": [item.to_payload() for item in self.reads],
            "writes": [item.to_payload() for item in self.writes],
        }


@dataclass(frozen=True)
class RelationInteractionV1:
    """One static interaction site instantiated for each dynamic occurrence."""

    identity: str
    primitive_id: str
    machine_event: Mapping[str, object]
    contract_id: str | None
    contract_sha256: str | None
    contract_receipt_sha256: str | None
    ports: tuple[RelationClauseV1, ...]
    requires: tuple[RelationExpressionV1, ...]
    ensures: tuple[RelationExpressionV1, ...]
    effect_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "RelationInteractionV1":
        row = _object(value, context)
        _exact(
            row,
            {
                "id",
                "primitive_id",
                "machine_event",
                "contract_id",
                "contract_sha256",
                "contract_receipt_sha256",
                "ports",
                "requires",
                "ensures",
                "effect_ids",
            },
            context,
        )
        identity = _identifier(row["id"], f"{context} id")
        event = copy.deepcopy(dict(_object(row["machine_event"], f"{context} machine event")))
        if not event:
            raise CheckedRelationIRError(f"{context} machine event must be nonempty")
        contract_id = (
            None
            if row["contract_id"] is None
            else _identifier(row["contract_id"], f"{context} contract id")
        )
        contract_sha256 = (
            None
            if row["contract_sha256"] is None
            else _digest(row["contract_sha256"], f"{context} contract digest")
        )
        receipt_sha256 = (
            None
            if row["contract_receipt_sha256"] is None
            else _digest(
                row["contract_receipt_sha256"],
                f"{context} contract receipt digest",
            )
        )
        if (contract_id is None) != (contract_sha256 is None) or (
            contract_id is None
        ) != (receipt_sha256 is None):
            raise CheckedRelationIRError(
                f"{context} contract binding must be complete or absent"
            )
        ports = tuple(
            RelationClauseV1.parse(item, f"{context} port {index}")
            for index, item in enumerate(_array(row["ports"], f"{context} ports"))
        )
        port_ids = [item.identity for item in ports]
        if not ports or port_ids != sorted(set(port_ids)):
            raise CheckedRelationIRError(
                f"{context} ports must be nonempty, unique, and ordered"
            )
        paths: list[tuple[str, str, tuple[str, ...]]] = []
        for port in ports:
            if port.kind != "binding" or port.logical_path is None:
                raise CheckedRelationIRError(f"{context} port must be a binding")
            path = port.logical_path
            if (
                path.root != "interaction"
                or path.identity != identity
                or len(path.fields) < 2
                or path.fields[0] not in {"input", "output"}
            ):
                raise CheckedRelationIRError(
                    f"{context} port path does not name this interaction"
                )
            direction = path.fields[0]
            if direction == "input" and (
                port.phase != "event_before" or port.realize
            ):
                raise CheckedRelationIRError(
                    f"{context} input port must be an event-before observation"
                )
            if direction == "output" and (
                port.phase != "event_after" or not port.realize
            ):
                raise CheckedRelationIRError(
                    f"{context} output port must be constructively realized after invocation"
                )
            paths.append(path.key)
        if len(paths) != len(set(paths)):
            raise CheckedRelationIRError(f"{context} binds one port more than once")
        requires = tuple(
            RelationExpressionV1.parse(item, f"{context} requirement {index}")
            for index, item in enumerate(
                _array(row["requires"], f"{context} requirements")
            )
        )
        ensures = tuple(
            RelationExpressionV1.parse(item, f"{context} guarantee {index}")
            for index, item in enumerate(
                _array(row["ensures"], f"{context} guarantees")
            )
        )
        if any(item.sort != BOOL_SORT for item in (*requires, *ensures)):
            raise CheckedRelationIRError(
                f"{context} contract expressions must be Boolean"
            )
        input_paths = {
            item.logical_path.key
            for item in ports
            if item.logical_path is not None and item.logical_path.fields[0] == "input"
        }
        all_paths = set(paths)
        for requirement in requires:
            if set(item.key for item in requirement.logical_paths()) - input_paths:
                raise CheckedRelationIRError(
                    f"{context} requirement references an output or foreign value"
                )
        for guarantee in ensures:
            if set(item.key for item in guarantee.logical_paths()) - all_paths:
                raise CheckedRelationIRError(
                    f"{context} guarantee references a foreign value"
                )
        effect_ids = tuple(
            _identifier(item, f"{context} effect {index}")
            for index, item in enumerate(
                _array(row["effect_ids"], f"{context} effects")
            )
        )
        if effect_ids != tuple(sorted(set(effect_ids))):
            raise CheckedRelationIRError(
                f"{context} effects must be unique and ordered"
            )
        return cls(
            identity,
            _identifier(row["primitive_id"], f"{context} primitive id"),
            event,
            contract_id,
            contract_sha256,
            receipt_sha256,
            ports,
            requires,
            ensures,
            effect_ids,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "primitive_id": self.primitive_id,
            "machine_event": copy.deepcopy(dict(self.machine_event)),
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "contract_receipt_sha256": self.contract_receipt_sha256,
            "ports": [item.to_payload() for item in self.ports],
            "requires": [item.to_payload() for item in self.requires],
            "ensures": [item.to_payload() for item in self.ensures],
            "effect_ids": list(self.effect_ids),
        }


@dataclass(frozen=True)
class OperationRelationV1:
    operation_id: str
    clauses: tuple[RelationClauseV1, ...]
    interactions: tuple[RelationInteractionV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "OperationRelationV1":
        row = _object(value, context)
        _exact(row, {"operation_id", "clauses", "interactions"}, context)
        clauses = tuple(
            RelationClauseV1.parse(item, f"{context} clause {index}")
            for index, item in enumerate(_array(row["clauses"], f"{context} clauses"))
        )
        identities = [item.identity for item in clauses]
        if identities != sorted(set(identities)):
            raise CheckedRelationIRError(f"{context} clauses must be unique and ordered")
        interactions = tuple(
            RelationInteractionV1.parse(item, f"{context} interaction {index}")
            for index, item in enumerate(
                _array(row["interactions"], f"{context} interactions")
            )
        )
        interaction_ids = [item.identity for item in interactions]
        if interaction_ids != sorted(set(interaction_ids)):
            raise CheckedRelationIRError(
                f"{context} interactions must be unique and ordered"
            )
        if not clauses and not interactions:
            raise CheckedRelationIRError(
                f"{context} must contain a boundary clause or interaction"
            )
        bindings = [
            item
            for item in clauses
            if item.kind == "binding" and item.logical_path is not None
        ] + [port for interaction in interactions for port in interaction.ports]
        paths = [item.logical_path.key for item in bindings if item.logical_path is not None]
        if len(paths) != len(set(paths)):
            raise CheckedRelationIRError(f"{context} binds one logical path more than once")
        writers: dict[str, str] = {}
        for clause in (*clauses, *(port for item in interactions for port in item.ports)):
            for place in clause.writes:
                previous = writers.setdefault(place.key, clause.identity)
                if previous != clause.identity:
                    raise CheckedRelationIRError(f"{context} has overlapping writers {previous!r} and {clause.identity!r}")
        return cls(
            _identifier(row["operation_id"], f"{context} operation id"),
            clauses,
            interactions,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "clauses": [item.to_payload() for item in self.clauses],
            "interactions": [item.to_payload() for item in self.interactions],
        }


@dataclass(frozen=True)
class CheckedRelationIRV1:
    component_id: str
    machine_backend: str
    bindings: Mapping[str, str]
    operations: tuple[OperationRelationV1, ...]
    relation_sha256: str

    @classmethod
    def parse(cls, value: object) -> "CheckedRelationIRV1":
        row = _object(value, "component relation IR")
        _exact(row, {"component_id", "machine_backend", "bindings", "operations", "relation_sha256"}, "checked relation IR")
        bindings_row = _object(row["bindings"], "component relation bindings")
        bindings = {
            _identifier(key, "component relation binding id"): _digest(digest, f"component relation binding {key}")
            for key, digest in bindings_row.items()
        }
        required = {
            "interface_sha256",
            "machine_binding_sha256",
            "semantic_contract_sha256",
            "machine_ir_sha256",
            "interaction_inventory_sha256",
            "interaction_contract_catalog_sha256",
        }
        if set(bindings) < required:
            raise CheckedRelationIRError(f"component relation bindings omit {sorted(required-set(bindings))!r}")
        operations = tuple(
            OperationRelationV1.parse(item, f"operation relation {index}")
            for index, item in enumerate(_array(row["operations"], "component relation operations"))
        )
        operation_ids = [item.operation_id for item in operations]
        if not operations or operation_ids != sorted(set(operation_ids)):
            raise CheckedRelationIRError("component relation operations must be nonempty, unique, and ordered")
        core = {key: copy.deepcopy(value) for key, value in row.items() if key != "relation_sha256"}
        observed = _digest(row["relation_sha256"], "component relation digest")
        if canonical_sha256_v3(core) != observed:
            raise CheckedRelationIRError("component relation digest is stale")
        return cls(
            _identifier(row["component_id"], "component relation component id"),
            _identifier(row["machine_backend"], "component relation machine backend"),
            dict(sorted(bindings.items())),
            operations,
            observed,
        )

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        machine_backend: str,
        bindings: Mapping[str, str],
        operations: Sequence[Mapping[str, object] | OperationRelationV1],
    ) -> "CheckedRelationIRV1":
        core = {
            "component_id": component_id,
            "machine_backend": machine_backend,
            "bindings": dict(sorted(bindings.items())),
            "operations": [item.to_payload() if isinstance(item, OperationRelationV1) else copy.deepcopy(dict(item)) for item in operations],
        }
        return cls.parse({**core, "relation_sha256": canonical_sha256_v3(core)})

    def to_payload(self) -> dict[str, object]:
        return {
            "component_id": self.component_id,
            "machine_backend": self.machine_backend,
            "bindings": dict(self.bindings),
            "operations": [item.to_payload() for item in self.operations],
            "relation_sha256": self.relation_sha256,
        }


__all__ = [
    "BOOL_SORT",
    "CheckedRelationIRError",
    "CheckedRelationIRV1",
    "LogicalPathV1",
    "MachinePlaceV1",
    "MachineWriteV1",
    "OperationRelationV1",
    "RelationInteractionV1",
    "RelationClauseV1",
    "RelationExpressionV1",
    "RelationSortV1",
]
