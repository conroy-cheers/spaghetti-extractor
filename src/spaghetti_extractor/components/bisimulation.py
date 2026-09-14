"""Linear proof planning for Portable-C contextual bisimulation.

The operator intent names source synchronization points and the exact machine
units to which they correspond.  It does not describe paths or expected
outcomes.  The proof plan derives control closure from the checked semantic
operation and rejects every exact or source cycle that is not cut.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

if TYPE_CHECKING:
    from .bisimulation_stack_scope import PrivateStackScopeV1
    from .bisimulation_allocation_cuts import AllocationHistoryV1

from ..artifacts.artifact_set import canonical_sha256_v3
from .interface_ir import ProofKernelComponentInterface
from .inductive_relation import (
    CutpointDerivedRelationV1,
    CutpointValueRelationV1,
)
from .semantic_induction import build_inductive_machine_shape
from .bisimulation_continuation import continuation_model


COMPONENT_BISIMULATION_INTENT_V1_FORMAT = (
    "spaghetti-extractor-component-bisimulation-intent-v1"
)
COMPONENT_PROOF_PLAN_V1_FORMAT = "spaghetti-extractor-component-proof-plan-v1"
CONTEXTUAL_REFINEMENT_V2_FORMAT = "spaghetti-extractor-contextual-refinement-v2"

_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,255}\Z")
_C_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ComponentBisimulationError(ValueError):
    """A bisimulation intent or proof plan is malformed or incomplete."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        actual = set(value) if isinstance(value, Mapping) else set()
        raise ComponentBisimulationError(
            f"{context} fields differ: missing={sorted(fields - actual)!r}, "
            f"extra={sorted(actual - fields)!r}"
        )
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise ComponentBisimulationError(f"{context} must be an array of objects")
    return list(value)


def _strings(value: object, context: str) -> list[str]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ComponentBisimulationError(f"{context} must be non-empty strings")
    return list(value)


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ComponentBisimulationError(f"{context} is not a canonical identifier")
    return value


def _c_identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or _C_ID.fullmatch(value) is None:
        raise ComponentBisimulationError(f"{context} is not a C identifier")
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ComponentBisimulationError(f"{context} is not a SHA-256 digest")
    return value


def _canonical(value: object) -> object:
    return copy.deepcopy(value)


def _invariant_expression(
    value: object, context: str
) -> tuple[dict[str, object], str, set[str]]:
    """Parse the closed, side-effect-free expression language used by syncs."""

    if not isinstance(value, Mapping):
        raise ComponentBisimulationError(f"{context} must be an expression")
    op = value.get("op")
    if not isinstance(op, str):
        raise ComponentBisimulationError(f"{context} operation is invalid")
    if op in {"true", "false"}:
        _object(value, {"op"}, context)
        return {"op": op}, "bool", set()
    if op == "const":
        row = _object(value, {"op", "value", "width"}, context)
        raw = row["value"]
        width = row["width"]
        if (
            not isinstance(raw, int)
            or isinstance(raw, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or width not in {1, 8, 16, 32, 64}
            or raw < 0
            or raw >= 1 << width
        ):
            raise ComponentBisimulationError(f"{context} constant is invalid")
        return {"op": op, "value": raw, "width": width}, "word", set()
    if op in {
        "parameter",
        "state_input",
        "loop_variable",
        "bytes_address",
        "byte_extent",
        "resource_identity",
    }:
        row = _object(value, {"op", "name"}, context)
        name = _c_identifier(row["name"], f"{context} name")
        return {"op": op, "name": name}, "word", {name}
    if op == "byte_read":
        row = _object(value, {"op", "name", "index"}, context)
        name = _c_identifier(row["name"], f"{context} byte view")
        index, sort, references = _invariant_expression(
            row["index"], f"{context} byte index"
        )
        if sort != "word":
            raise ComponentBisimulationError(f"{context} byte index is not a word")
        return (
            {"op": op, "name": name, "index": index},
            "word",
            references | {name},
        )
    arities: dict[str, tuple[int, int | None]] = {
        "not": (1, 1),
        "add32": (2, 2),
        "sub32": (2, 2),
        "mul32": (2, 2),
        "and32": (2, 2),
        "or32": (2, 2),
        "xor32": (2, 2),
        "eq": (2, 2),
        "ult32": (2, 2),
        "ule32": (2, 2),
        "and": (2, None),
        "or": (2, None),
        "and_bool": (2, 2),
        "or_bool": (2, 2),
        "ite": (3, 3),
    }
    if op not in arities:
        raise ComponentBisimulationError(
            f"{context} operation {op!r} is unsupported"
        )
    row = _object(value, {"op", "args"}, context)
    arguments = row["args"]
    minimum, maximum = arities[op]
    if (
        not isinstance(arguments, list)
        or len(arguments) < minimum
        or (maximum is not None and len(arguments) > maximum)
    ):
        raise ComponentBisimulationError(f"{context} has the wrong arity")
    parsed = [
        _invariant_expression(item, f"{context} argument {index}")
        for index, item in enumerate(arguments)
    ]
    sorts = [item[1] for item in parsed]
    if op in {"not", "and", "or", "and_bool", "or_bool"}:
        valid = set(sorts) == {"bool"}
        result_sort = "bool"
    elif op in {"eq", "ult32", "ule32"}:
        valid = sorts == ["word", "word"]
        result_sort = "bool"
    elif op == "ite":
        valid = sorts[0] == "bool" and sorts[1] == sorts[2]
        result_sort = sorts[1]
    else:
        valid = sorts == ["word", "word"]
        result_sort = "word"
    if not valid:
        raise ComponentBisimulationError(f"{context} operand sorts are invalid")
    references = set().union(*(item[2] for item in parsed))
    return {"op": op, "args": [item[0] for item in parsed]}, result_sort, references


@dataclass(frozen=True)
class BisimulationSyncV1:
    identity: str
    exact_unit_id: str
    invariant: Mapping[str, object]
    captures: tuple[CutpointValueRelationV1, ...]
    derived: tuple[CutpointDerivedRelationV1, ...]
    shared_capture_count: int = 0
    source_bindings: Mapping[str, Mapping[str, object]] = field(default_factory=dict)
    allocation_history: AllocationHistoryV1 | None = None
    private_stack_scope: PrivateStackScopeV1 | None = None
    memory_facts: tuple[Mapping[str, object], ...] = ()

    @classmethod
    def parse(
        cls,
        value: object,
        context: str,
        *,
        shared_captures: Sequence[CutpointValueRelationV1] = (),
    ) -> "BisimulationSyncV1":
        fields = {"id", "exact_unit_id", "invariant", "captures", "derived"}
        if isinstance(value, Mapping) and "source_bindings" in value:
            fields.add("source_bindings")
        if isinstance(value, Mapping) and "allocation_history" in value:
            fields.add("allocation_history")
        if isinstance(value, Mapping) and "private_stack_scope" in value:
            fields.add("private_stack_scope")
        if isinstance(value, Mapping) and "memory_facts" in value:
            fields.add("memory_facts")
        row = _object(value, fields, context)
        from .bisimulation_stack_scope import PrivateStackScopeV1
        from .bisimulation_allocation_cuts import AllocationHistoryV1
        try:
            private_stack_scope = (PrivateStackScopeV1.parse(row["private_stack_scope"])
                                   if "private_stack_scope" in row else None)
            allocation_history = (AllocationHistoryV1.parse(row["allocation_history"])
                                  if "allocation_history" in row else None)
        except ValueError as error:
            raise ComponentBisimulationError(f"{context}: {error}") from error
        local_captures = tuple(
            CutpointValueRelationV1.parse(item, f"{context} capture {index}")
            for index, item in enumerate(_rows(row["captures"], f"{context} captures"))
        )
        captures = (*shared_captures, *local_captures)
        if not captures:
            raise ComponentBisimulationError(f"{context} must capture its live source values")
        capture_ids = [item.identity for item in captures]
        if len(capture_ids) != len(set(capture_ids)):
            raise ComponentBisimulationError(f"{context} capture identities are duplicated")
        for capture in captures:
            if capture.kind == "parameter" and capture.mode != "native_view" and (
                capture.mode != "machine_codec"
                or capture.encoding not in [
                    {"op": op, "name": capture.identity}
                    for op in ("parameter", "bytes_address", "resource_identity")
                ]
            ):
                raise ComponentBisimulationError(
                    f"{context} parameter {capture.identity!r} requires its canonical argument encoding"
                )
        raw_bindings = row.get("source_bindings", {})
        if not isinstance(raw_bindings, Mapping) or set(raw_bindings) - set(capture_ids):
            raise ComponentBisimulationError(f"{context} source bindings name unknown captures")
        source_bindings = {}
        for identity, raw_binding in sorted(raw_bindings.items()):
            _capture_lvalue(raw_binding, f"{context} source binding {identity!r}")
            source_bindings[identity] = _canonical(raw_binding)
        arguments = [
            _capture_lvalue(source_bindings[identity], context)
            if identity in source_bindings else identity
            for identity in capture_ids
        ]
        if len(arguments) != len(set(arguments)):
            raise ComponentBisimulationError(f"{context} source bindings alias the same capture path")
        for capture, argument in zip(captures, arguments, strict=True):
            if capture.mode == "native_view" and any(
                    other != argument and (other.startswith((argument + ".", argument + "->")) or
                    argument.startswith((other + ".", other + "->"))) for other in arguments):
                raise ComponentBisimulationError(f"{context} native view overlaps another capture's storage")
        invariant, invariant_sort, invariant_references = _invariant_expression(
            row["invariant"], f"{context} invariant"
        )
        if invariant_sort != "bool":
            raise ComponentBisimulationError(f"{context} invariant is not Boolean")
        unknown_invariant_references = sorted(
            invariant_references - set(capture_ids)
        )
        if unknown_invariant_references:
            raise ComponentBisimulationError(
                f"{context} invariant references values outside its capture "
                f"environment: {unknown_invariant_references!r}"
            )
        derived = tuple(
            CutpointDerivedRelationV1.parse(item, f"{context} derived {index}")
            for index, item in enumerate(_rows(row["derived"], f"{context} derived"))
        )
        derived_ids = [item.identity for item in derived]
        if derived_ids != sorted(derived_ids) or len(derived_ids) != len(set(derived_ids)):
            raise ComponentBisimulationError(
                f"{context} derived relations must be ordered and unique"
            )
        from .bisimulation_memory_facts import parse_facts
        try:
            memory_facts = parse_facts(row.get("memory_facts", []), captures, allocation_history)
        except ValueError as error:
            raise ComponentBisimulationError(f"{context}: {error}") from error
        return cls(
            _c_identifier(row["id"], f"{context} id"),
            _identifier(row["exact_unit_id"], f"{context} exact unit"),
            invariant,
            captures,
            derived,
            len(shared_captures),
            source_bindings,
            allocation_history,
            private_stack_scope,
            memory_facts,
        )

    def source_arguments(self) -> tuple[str, ...]:
        return tuple(
            _capture_lvalue(self.source_bindings[capture.identity], "source capture")
            if capture.identity in self.source_bindings else capture.identity
            for capture in self.captures
        )

    def to_payload(self, *, include_shared_captures: bool = True) -> dict[str, object]:
        captures = (
            self.captures
            if include_shared_captures
            else self.captures[self.shared_capture_count :]
        )
        return {
            "id": self.identity,
            "exact_unit_id": self.exact_unit_id,
            "invariant": _canonical(self.invariant),
            "captures": [item.to_payload() for item in captures],
            "derived": [item.to_payload() for item in self.derived],
            **({"source_bindings": _canonical(self.source_bindings)} if self.source_bindings else {}),
            **({"allocation_history": self.allocation_history.to_payload()} if self.allocation_history else {}),
            **({"private_stack_scope": self.private_stack_scope.to_payload()} if self.private_stack_scope else {}),
            **({"memory_facts": [_canonical(fact) for fact in self.memory_facts]} if self.memory_facts else {}),
        }


def _capture_lvalue(value: object, context: str) -> str:
    """Render only a named C object followed by explicit member accesses.

    This describes syntax, not pointer validity or non-aliasing. The generated
    paired proof still checks C definedness and the declared value relation.
    """
    row = _object(value, {"root", "members"}, context)
    result = _c_identifier(row["root"], f"{context} root")
    for index, member in enumerate(_rows(row["members"], f"{context} members")):
        member = _object(member, {"access", "name"}, f"{context} member {index}")
        access = member["access"]
        if not isinstance(access, str) or access not in {"direct", "pointer"}:
            raise ComponentBisimulationError(f"{context} member access is unsupported")
        result += ("." if access == "direct" else "->") + _c_identifier(
            member["name"], f"{context} member name"
        )
    return result


def _source_capture_argument(value: str, context: str) -> str:
    identifier = r"[A-Za-z_][A-Za-z0-9_]*"
    if re.fullmatch(rf"\s*{identifier}(?:\s*(?:\.|->)\s*{identifier})*\s*", value) is None:
        raise ComponentBisimulationError(f"{context} must be an identifier or bound member path")
    return re.sub(r"\s+", "", value)


@dataclass(frozen=True)
class BisimulationOperationV1:
    operation_id: str
    syncs: tuple[BisimulationSyncV1, ...]
    shared_captures: tuple[CutpointValueRelationV1, ...] = ()
    machine_clobbers: tuple[str, ...] = ()
    private_stack_writes: tuple[tuple[int, int], ...] = ()
    private_stack_accesses: tuple[tuple[int, int], ...] | None = None
    reference_origin_capacity: int | None = None
    source_unwind_limit: int | None = None
    entry_allocation_history: AllocationHistoryV1 | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "BisimulationOperationV1":
        if (not isinstance(value, Mapping) or not {"operation_id", "syncs"} <= set(value)
                or set(value) - {"operation_id", "syncs", "shared_captures", "machine_clobbers", "private_stack_writes", "private_stack_accesses", "reference_origin_capacity", "source_unwind_limit", "entry_allocation_history"}):
            actual = set(value) if isinstance(value, Mapping) else set()
            raise ComponentBisimulationError(
                f"{context} fields differ: actual={sorted(actual)!r}"
            )
        row = value
        source_unwind_limit = parse_source_unwind_limit(row["source_unwind_limit"]) if "source_unwind_limit" in row else None
        if "private_stack_accesses" in row and row["private_stack_accesses"] is None:
            raise ComponentBisimulationError("private access footprint must be an explicit range list")
        from .bisimulation_clobber_frame import parse_clobbers
        from .bisimulation_private_frame import parse_stack_writes
        from .bisimulation_image_frame import parse_accesses
        from .bisimulation_reference_origins import parse_capacity
        from .bisimulation_allocation_cuts import AllocationHistoryV1
        try:
            clobbers = parse_clobbers(row.get("machine_clobbers", []))
            private_writes = parse_stack_writes(row.get("private_stack_writes", []))
            private_accesses = parse_accesses(row.get("private_stack_accesses"))
            origin_capacity = parse_capacity(row["reference_origin_capacity"]) if "reference_origin_capacity" in row else None
            entry_history = (AllocationHistoryV1.parse(row["entry_allocation_history"])
                             if "entry_allocation_history" in row else None)
        except ValueError as error:
            raise ComponentBisimulationError(str(error)) from error
        shared_captures = tuple(
            CutpointValueRelationV1.parse(
                item, f"{context} shared capture {index}"
            )
            for index, item in enumerate(
                _rows(row.get("shared_captures", []), f"{context} shared captures")
            )
        )
        shared_ids = [item.identity for item in shared_captures]
        if len(shared_ids) != len(set(shared_ids)):
            raise ComponentBisimulationError(
                f"{context} shared capture identities are duplicated"
            )
        syncs = tuple(
            BisimulationSyncV1.parse(
                item,
                f"{context} sync {index}",
                shared_captures=shared_captures,
            )
            for index, item in enumerate(_rows(row["syncs"], f"{context} syncs"))
        )
        keys = [(item.exact_unit_id, item.identity) for item in syncs]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ComponentBisimulationError(
                f"{context} syncs must be exact-unit ordered and unique"
            )
        identities = [item.identity for item in syncs]
        if len(identities) != len(set(identities)):
            raise ComponentBisimulationError(f"{context} sync ids are duplicated")
        # Each cut has its own live relation. The compiler-derived inventory
        # overapproximates mutable locals before restoring that cut's captures;
        # a local captured at an earlier cut supplies no implicit later fact.
        return cls(
            _identifier(row["operation_id"], f"{context} operation id"),
            syncs,
            shared_captures,
            clobbers,
            private_writes,
            private_accesses,
            origin_capacity,
            source_unwind_limit,
            entry_history,
        )

    def to_payload(self) -> dict[str, object]:
        result = {
            "operation_id": self.operation_id,
            "syncs": [
                item.to_payload(include_shared_captures=not self.shared_captures)
                for item in self.syncs
            ],
        }
        if self.shared_captures:
            result["shared_captures"] = [
                item.to_payload() for item in self.shared_captures
            ]
        if self.machine_clobbers:
            result["machine_clobbers"] = list(self.machine_clobbers)
        if self.private_stack_writes:
            from .bisimulation_private_frame import payload
            result["private_stack_writes"] = payload(self.private_stack_writes)
        if self.private_stack_accesses is not None:
            from .bisimulation_private_frame import payload
            result["private_stack_accesses"] = payload(self.private_stack_accesses)
        if self.reference_origin_capacity is not None:
            result["reference_origin_capacity"] = self.reference_origin_capacity
        if self.source_unwind_limit is not None:
            result["source_unwind_limit"] = self.source_unwind_limit
        if self.entry_allocation_history is not None:
            result["entry_allocation_history"] = self.entry_allocation_history.to_payload()
        return result


@dataclass(frozen=True)
class ComponentBisimulationIntentV1:
    component_id: str
    operations: tuple[BisimulationOperationV1, ...]
    intent_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ComponentBisimulationIntentV1":
        row = _object(
            value,
            {"format", "component_id", "operations", "intent_sha256"},
            "component bisimulation intent",
        )
        if row["format"] != COMPONENT_BISIMULATION_INTENT_V1_FORMAT:
            raise ComponentBisimulationError("unsupported component bisimulation intent")
        operations = tuple(
            BisimulationOperationV1.parse(item, f"bisimulation operation {index}")
            for index, item in enumerate(
                _rows(row["operations"], "bisimulation operations")
            )
        )
        operation_ids = [item.operation_id for item in operations]
        if (
            not operations
            or operation_ids != sorted(operation_ids)
            or len(operation_ids) != len(set(operation_ids))
        ):
            raise ComponentBisimulationError(
                "bisimulation operations must be nonempty, ordered, and unique"
            )
        digest = _digest(row["intent_sha256"], "bisimulation intent digest")
        core = dict(row)
        core.pop("intent_sha256")
        if canonical_sha256_v3(core) != digest:
            raise ComponentBisimulationError("component bisimulation intent digest is stale")
        return cls(
            _identifier(row["component_id"], "bisimulation component id"),
            operations,
            digest,
        )

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        operations: Sequence[Mapping[str, object]],
    ) -> "ComponentBisimulationIntentV1":
        core = {
            "format": COMPONENT_BISIMULATION_INTENT_V1_FORMAT,
            "component_id": component_id,
            "operations": [_canonical(item) for item in operations],
        }
        return cls.parse({**core, "intent_sha256": canonical_sha256_v3(core)})

    def operation_index(self) -> dict[str, BisimulationOperationV1]:
        return {item.operation_id: item for item in self.operations}

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_BISIMULATION_INTENT_V1_FORMAT,
            "component_id": self.component_id,
            "operations": [item.to_payload() for item in self.operations],
        }
        return {**core, "intent_sha256": self.intent_sha256}


@dataclass(frozen=True)
class SourceProofMarkersV1:
    operation_id: str
    begin_count: int
    sync_calls: tuple[tuple[str, tuple[str, ...]], ...]
    loop_count: int
    annotated_loop_count: int
    goto_count: int


def parse_source_unwind_limit(value: object) -> int:
    if type(value) is not int or not 1 <= value <= 65536:
        raise ComponentBisimulationError("source_unwind_limit must be an integer in 1..65536")
    return value


def scan_source_proof_markers(
    source: str, *, operation_id: str, expected_syncs: Sequence[BisimulationSyncV1],
    source_unwind_limit: int | None = None,
) -> SourceProofMarkersV1:
    """Validate the deliberately small source proof-marker language.

    Calls are parsed with comment/string aware balanced-parenthesis scanning.
    Captures are identifiers or explicitly bound member paths. Calls, indexing,
    casts, and side effects cannot become implicit source state.
    """

    if source_unwind_limit is not None:
        parse_source_unwind_limit(source_unwind_limit)
    clean = _mask_comments_and_literals(source)
    goto_count = len(re.findall(r"\bgoto\b", clean))
    if goto_count:
        raise ComponentBisimulationError(
            f"operation {operation_id!r} uses explicit goto control; "
            "source backedges must be structured loops with proof syncs"
        )
    begins = _macro_calls(clean, "SPX_PROOF_BEGIN")
    matching_begins = [args for args in begins if args == [operation_id]]
    if len(matching_begins) != 1 or len(begins) != 1:
        raise ComponentBisimulationError(
            f"operation {operation_id!r} must contain exactly one SPX_PROOF_BEGIN"
        )
    calls = _macro_calls(clean, "SPX_PROOF_SYNC")
    parsed: list[tuple[str, tuple[str, ...]]] = []
    for arguments in calls:
        if len(arguments) < 3:
            raise ComponentBisimulationError(
                "SPX_PROOF_SYNC requires an id, invariant, and live captures"
            )
        identity = _c_identifier(arguments[0], "source proof sync id")
        captures = tuple(
            _source_capture_argument(item, f"source proof sync {identity!r} capture")
            for item in arguments[2:]
        )
        parsed.append((identity, captures))
    expected = {
        sync.identity: sync.source_arguments()
        for sync in expected_syncs
    }
    actual = dict(parsed)
    if len(actual) != len(parsed) or actual != expected:
        raise ComponentBisimulationError(
            f"operation {operation_id!r} source sync inventory differs: "
            f"expected={expected!r}, actual={actual!r}"
        )
    loops = _loop_ranges(clean)
    annotated = sum(
        1
        for start, end in loops
        if any(start <= position < end for position, _args in _macro_calls_with_offsets(
            clean, "SPX_PROOF_SYNC"
        ))
    )
    if annotated != len(loops) and source_unwind_limit is None:
        raise ComponentBisimulationError(
            f"operation {operation_id!r} has an unannotated source cycle"
        )
    return SourceProofMarkersV1(
        operation_id,
        len(begins),
        tuple(parsed),
        len(loops),
        annotated,
        goto_count,
    )


def build_component_proof_plan_v1(
    *,
    component_id: str,
    semantic_contract_sha256: str,
    interface: ProofKernelComponentInterface,
    operations: Sequence[Mapping[str, object]],
    operation_sources: Mapping[str, str],
    source_package_sha256: str,
    intent: ComponentBisimulationIntentV1 | None,
) -> dict[str, object]:
    """Derive a path-free component proof plan from exact control graphs."""

    if component_id.replace("-", "_") != interface.identity:
        raise ComponentBisimulationError("proof component and interface identities differ")
    _digest(semantic_contract_sha256, "semantic contract digest")
    _digest(source_package_sha256, "source package digest")
    if intent is not None and intent.component_id != component_id:
        raise ComponentBisimulationError("bisimulation intent names another component")
    logical = interface.operation_index()
    exact = {str(row.get("operation_id")): row for row in operations}
    if set(exact) != set(logical) or set(operation_sources) != set(logical):
        raise ComponentBisimulationError("proof operation inventory is not total")
    authored = {} if intent is None else intent.operation_index()
    if set(authored) - set(logical):
        raise ComponentBisimulationError("bisimulation intent names an unknown operation")

    operation_plans: list[dict[str, object]] = []
    total_units = 0
    total_edges = 0
    total_obligations = 0
    for operation_id in sorted(logical):
        operation = exact[operation_id]
        from .machine_overlay_result_views import parameter_exit_projections
        parameter_exits = parameter_exit_projections(operation)
        shape = build_inductive_machine_shape(operation)
        semantic_units = [
            dict(item) for item in _rows(shape["semantic_units"], "semantic units")
        ]
        exact_units = [str(item["unit_id"]) for item in semantic_units]
        exact_edges = [dict(item) for item in shape["control_edges"]]
        syncs = authored.get(
            operation_id, BisimulationOperationV1(operation_id, ())
        ).syncs
        sync_unit_ids = [item.exact_unit_id for item in syncs]
        if len(sync_unit_ids) != len(set(sync_unit_ids)):
            raise ComponentBisimulationError(
                f"operation {operation_id!r} maps multiple syncs to one exact unit"
            )
        if set(sync_unit_ids) - set(exact_units):
            raise ComponentBisimulationError(
                f"operation {operation_id!r} syncs name unknown exact units"
            )
        _assert_exact_cycles_cut(shape, set(sync_unit_ids), operation_id)
        markers = scan_source_proof_markers(
            operation_sources[operation_id],
            operation_id=operation_id,
            expected_syncs=syncs,
            source_unwind_limit=authored.get(operation_id, BisimulationOperationV1(operation_id, ())).source_unwind_limit,
        )
        if shape["requires_induction"] and not syncs:
            raise ComponentBisimulationError(
                f"operation {operation_id!r} is cyclic but has no source sync"
            )
        entries = [str(item) for item in shape["entry_unit_ids"]]
        obligations = [
            {
                "id": f"entry:{entry}",
                "source": {"kind": "operation_entry", "id": entry},
                "exact_start_unit_id": entry,
            }
            for entry in entries
        ] + [
            {
                "id": f"sync:{sync.identity}",
                "source": {"kind": "sync", "id": sync.identity},
                "exact_start_unit_id": sync.exact_unit_id,
            }
            for sync in syncs
        ]
        observables = {
            "parameters": [item.identity for item in logical[operation_id].parameters],
            "results": [item.identity for item in logical[operation_id].results],
            "state": [item.identity for item in interface.state],
            "effects": list(logical[operation_id].effect_ids),
            "services": list(logical[operation_id].allowed_service_ids),
            "control": [
                "return",
                "fault",
                "exception",
                "nonlocal",
                "continuation",
            ],
        }
        operation_plans.append(
            {
                "operation_id": operation_id,
                **({'parameter_exit_projections': parameter_exits} if parameter_exits else {}),
                **({"machine_clobbers": list(authored[operation_id].machine_clobbers)}
                   if operation_id in authored and authored[operation_id].machine_clobbers else {}),
                **({"private_stack_writes": authored[operation_id].to_payload()["private_stack_writes"]}
                   if operation_id in authored and authored[operation_id].private_stack_writes else {}),
                **({"private_stack_accesses": authored[operation_id].to_payload()["private_stack_accesses"]}
                   if operation_id in authored and authored[operation_id].private_stack_accesses is not None else {}),
                **({"reference_origin_capacity": authored[operation_id].reference_origin_capacity}
                   if operation_id in authored and authored[operation_id].reference_origin_capacity is not None else {}),
                **({"continuation": continuation_model(operation)}
                   if operation.get("continuation_unit_ids") else {}),
                "exact": {
                    "semantic_units": semantic_units,
                    "control_edges": exact_edges,
                    "cyclic_sccs": list(shape["cyclic_sccs"]),
                    "condensation_edges": list(shape["condensation_edges"]),
                },
                "source": {
                    **({"entry_allocation_history": authored[operation_id].entry_allocation_history.to_payload()}
                       if operation_id in authored and authored[operation_id].entry_allocation_history is not None else {}),
                    **({"source_unwind_limit": authored[operation_id].source_unwind_limit}
                       if operation_id in authored and authored[operation_id].source_unwind_limit is not None else {}),
                    "begin_count": markers.begin_count,
                    "syncs": [item.to_payload() for item in syncs],
                    "loop_count": markers.loop_count,
                    "annotated_loop_count": markers.annotated_loop_count,
                    "goto_count": markers.goto_count,
                },
                "obligations": obligations,
                "observables": observables,
                "closure": {
                    "exact_cycles_cut": True,
                    "source_lexical_loops_cut": (
                        markers.loop_count == markers.annotated_loop_count
                    ),
                    "source_explicit_gotos_absent": markers.goto_count == 0,
                    "remaining_source_cycles_fail_closed_by_unwinding_assertions": True,
                },
            }
        )
        total_units += len(exact_units)
        total_edges += len(exact_edges)
        total_obligations += len(obligations)
    core: dict[str, object] = {
        "format": COMPONENT_PROOF_PLAN_V1_FORMAT,
        "status": "complete",
        "component_id": component_id,
        "bindings": {
            "semantic_contract_sha256": semantic_contract_sha256,
            "interface_sha256": interface.sha256,
            "source_package_sha256": source_package_sha256,
            "bisimulation_intent_sha256": (
                None if intent is None else intent.intent_sha256
            ),
        },
        "operations": operation_plans,
        "cost": {
            "exact_units": total_units,
            "control_edges": total_edges,
            "shards": total_obligations,
            "materialized_paths": 0,
        },
        "policy": {
            "proof_form": "strong_cutpoint_bisimulation",
            "unsegmented_acyclic_operations_use_single_entry_obligation": True,
            "acyclic_and_cyclic_syncs_checked": True,
            "every_exact_cycle_cut": True,
            "arbitrary_shared_world": True,
            "compiler_trusted": True,
            "path_enumeration_authorizes": False,
            "finite_unwinding_authorizes": False,
        },
    }
    return {**core, "plan_sha256": canonical_sha256_v3(core)}


def _assert_exact_cycles_cut(
    shape: Mapping[str, object], sync_units: set[str], operation_id: str
) -> None:
    units = [
        str(item["unit_id"])
        for item in _rows(shape["semantic_units"], "semantic units")
        if str(item["unit_id"]) not in sync_units
    ]
    adjacency = {item: [] for item in units}
    for edge in _rows(shape["control_edges"], "exact control edges"):
        source = str(edge["source_unit_id"])
        target = str(edge["target_unit_id"])
        if source in adjacency and target in adjacency:
            adjacency[source].append(target)
    visiting: set[str] = set()
    visited: set[str] = set()

    def walk(current: str) -> None:
        if current in visiting:
            raise ComponentBisimulationError(
                f"operation {operation_id!r} has an exact cycle without a sync"
            )
        if current in visited:
            return
        visiting.add(current)
        for target in adjacency[current]:
            walk(target)
        visiting.remove(current)
        visited.add(current)

    for unit in units:
        walk(unit)


def _mask_comments_and_literals(source: str) -> str:
    result = list(source)
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            result[index:end] = " " * (end - index)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise ComponentBisimulationError("unterminated C comment")
            end += 2
            for position in range(index, end):
                if result[position] != "\n":
                    result[position] = " "
            index = end
            continue
        if source[index] in {'"', "'"}:
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    result[index] = " "
                    if index + 1 < len(source):
                        result[index + 1] = " "
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                if source[index] != "\n":
                    result[index] = " "
                index += 1
            else:
                raise ComponentBisimulationError("unterminated C literal")
            continue
        index += 1
    return "".join(result)


def _macro_calls(source: str, name: str) -> list[list[str]]:
    return [arguments for _offset, arguments in _macro_calls_with_offsets(source, name)]


def _macro_calls_with_offsets(source: str, name: str) -> list[tuple[int, list[str]]]:
    result: list[tuple[int, list[str]]] = []
    pattern = re.compile(rf"\b{re.escape(name)}\s*\(")
    for match in pattern.finditer(source):
        start = source.find("(", match.start())
        depth = 0
        end = start
        while end < len(source):
            character = source[end]
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        if depth != 0:
            raise ComponentBisimulationError(f"unterminated {name} invocation")
        result.append((match.start(), _split_arguments(source[start + 1 : end])))
    return result


def _split_arguments(value: str) -> list[str]:
    result: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(value):
        if character in "([{":
            depth += 1
        elif character in ")]}":
            depth -= 1
        elif character == "," and depth == 0:
            result.append(value[start:index].strip())
            start = index + 1
    result.append(value[start:].strip())
    return result


def _loop_ranges(source: str) -> list[tuple[int, int]]:
    """Return lexical loop bodies; source-profile C deliberately excludes macros."""

    result: list[tuple[int, int]] = []
    for match in re.finditer(r"\b(?:for|while)\s*\(", source):
        condition_open = source.find("(", match.start())
        condition_end = _balanced_end(source, condition_open, "(", ")")
        body = condition_end + 1
        while body < len(source) and source[body].isspace():
            body += 1
        if body >= len(source):
            raise ComponentBisimulationError("source loop has no body")
        end = (
            _balanced_end(source, body, "{", "}") + 1
            if source[body] == "{"
            else source.find(";", body) + 1
        )
        if end <= body:
            raise ComponentBisimulationError("source loop body is malformed")
        result.append((body, end))
    for match in re.finditer(r"\bdo\s*\{", source):
        body = source.find("{", match.start())
        result.append((body, _balanced_end(source, body, "{", "}") + 1))
    return result


def _balanced_end(source: str, start: int, opening: str, closing: str) -> int:
    if start < 0 or start >= len(source) or source[start] != opening:
        raise ComponentBisimulationError("source delimiter is malformed")
    depth = 0
    for index in range(start, len(source)):
        if source[index] == opening:
            depth += 1
        elif source[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    raise ComponentBisimulationError("source delimiter is unterminated")


def load_component_bisimulation_intent(
    value: Path | str | Mapping[str, object],
) -> ComponentBisimulationIntentV1:
    if isinstance(value, Mapping):
        return ComponentBisimulationIntentV1.parse(value)
    import json

    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentBisimulationError(
            f"cannot read component bisimulation intent: {exc}"
        ) from exc
    return ComponentBisimulationIntentV1.parse(payload)


__all__ = [
    "BisimulationOperationV1",
    "BisimulationSyncV1",
    "COMPONENT_BISIMULATION_INTENT_V1_FORMAT",
    "COMPONENT_PROOF_PLAN_V1_FORMAT",
    "CONTEXTUAL_REFINEMENT_V2_FORMAT",
    "ComponentBisimulationError",
    "ComponentBisimulationIntentV1",
    "build_component_proof_plan_v1",
    "load_component_bisimulation_intent",
    "scan_source_proof_markers",
]
