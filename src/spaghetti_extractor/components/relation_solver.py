"""SMT proofs for finite constructive relation lenses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

import z3

from ..artifacts.artifact_set import canonical_sha256_v3
from .relation_ir import (
    BOOL_SORT,
    LogicalPathV1,
    RelationClauseV1,
    RelationExpressionV1,
    RelationSortV1,
)


@dataclass(frozen=True)
class LensProofV1:
    status: str
    code: str


class _Unsupported(Exception):
    pass


class _Translator:
    def __init__(self) -> None:
        self.atoms: dict[tuple[str, str], z3.ExprRef] = {}

    def expression(
        self,
        value: RelationExpressionV1,
        *,
        machine: Mapping[str, z3.ExprRef] | None = None,
        logical: Mapping[tuple[str, str, tuple[str, ...]], z3.ExprRef] | None = None,
    ) -> z3.ExprRef:
        machine = machine or {}
        logical = logical or {}
        if value.op == "machine":
            key = canonical_sha256_v3(value.attributes["place"])
            replacement = machine.get(key)
            return replacement if replacement is not None else self._atom(
                "machine:" + key, value.sort
            )
        if value.op == "logical":
            path = LogicalPathV1.parse(value.attributes["path"])
            replacement = logical.get(path.key)
            return replacement if replacement is not None else self._atom(
                "logical:" + canonical_sha256_v3(path.to_payload()), value.sort
            )
        if value.op == "const":
            return z3.BitVecVal(int(value.attributes["value"]), int(value.sort.width or 0))
        if value.op == "true":
            return z3.BoolVal(True)
        if value.op == "false":
            return z3.BoolVal(False)
        # Boundary observations of structured values are opaque but stable.
        # Their algebra is supplied by the surrounding bitvector expression;
        # no raw pointer interpretation is assumed here.
        if value.sort.kind in {"bool", "bitvector"} and value.op in {
            "view_address",
            "view_extent",
            "ref_offset",
            "byte_read",
        }:
            return self._atom(
                "observation:" + canonical_sha256_v3(value.to_payload()), value.sort
            )
        args = [self.expression(item, machine=machine, logical=logical) for item in value.arguments]
        if value.op == "not":
            return z3.Not(args[0])
        if value.op == "and":
            return z3.And(args[0], args[1])
        if value.op == "or":
            return z3.Or(args[0], args[1])
        if value.op == "eq":
            return args[0] == args[1]
        if value.op == "ult":
            return z3.ULT(args[0], args[1])
        if value.op == "ule":
            return z3.ULE(args[0], args[1])
        if value.op == "add":
            return args[0] + args[1]
        if value.op == "sub":
            return args[0] - args[1]
        if value.op == "bit_and":
            return args[0] & args[1]
        if value.op == "bit_or":
            return args[0] | args[1]
        if value.op == "bit_xor":
            return args[0] ^ args[1]
        if value.op == "bit_not":
            return ~args[0]
        if value.op == "zero_extend":
            return z3.ZeroExt(int(value.sort.width or 0) - args[0].size(), args[0])
        if value.op == "sign_extend":
            return z3.SignExt(int(value.sort.width or 0) - args[0].size(), args[0])
        if value.op == "truncate":
            return z3.Extract(int(value.sort.width or 0) - 1, 0, args[0])
        if value.op == "bitcast":
            return args[0]
        if value.op == "concat":
            return z3.Concat(*args)
        if value.op == "slice":
            width = int(value.sort.width or 0)
            offset = int(value.attributes["offset_bits"])
            return z3.Extract(offset + width - 1, offset, args[0])
        if value.op == "unspecified":
            return self._atom(
                "unspecified:" + canonical_sha256_v3(value.to_payload()), value.sort
            )
        if value.op == "ite":
            return z3.If(args[0], args[1], args[2])
        raise _Unsupported(value.op)

    def _atom(self, name: str, sort: RelationSortV1) -> z3.ExprRef:
        key = (name, canonical_sha256_v3(sort.to_payload()))
        if key not in self.atoms:
            safe = "spx_" + canonical_sha256_v3({"name": name, "sort": sort.to_payload()})
            if sort == BOOL_SORT:
                self.atoms[key] = z3.Bool(safe)
            elif sort.kind == "bitvector":
                self.atoms[key] = z3.BitVec(safe, int(sort.width or 0))
            else:
                raise _Unsupported(f"sort:{sort.kind}")
        return self.atoms[key]


def prove_binding_lens(clause: RelationClauseV1) -> LensProofV1:
    """Prove GetPut and PutGet for one finite Boolean/bitvector lens."""

    if clause.kind != "binding" or clause.logical_path is None or clause.observe is None:
        return LensProofV1("incomplete", "not_a_boundary_binding")
    if not clause.realize:
        return LensProofV1("checked", "input_observation_requires_no_realizer")
    if _x87_value_lens(clause):
        return LensProofV1("checked", "x87_value_round_trip_proved_by_kernel")
    if _normalized_extension_lens(clause):
        return LensProofV1("checked", "normalized_extension_round_trip_proved_by_kernel")
    if _normalized_control_condition_lens(clause):
        return LensProofV1(
            "checked", "normalized_control_condition_round_trip_proved_by_kernel"
        )
    if _finite_control_target_lens(clause):
        return LensProofV1(
            "checked", "finite_control_target_round_trip_proved_by_kernel"
        )
    if clause.observe.sort.kind not in {"bool", "bitvector"}:
        if _structured_origin_lens(clause):
            return LensProofV1(
                "checked", "structured_origin_round_trip_proved_by_kernel"
            )
        if _structured_capability_lens(clause):
            return LensProofV1(
                "checked", "structured_capability_round_trip_proved_by_kernel"
            )
        return LensProofV1("incomplete", "structured_lens_requires_kernel_theory")
    translator = _Translator()
    try:
        logical_value = translator._atom(
            "put:" + canonical_sha256_v3(clause.logical_path.to_payload()),
            clause.observe.sort,
        )
        logical_override = {clause.logical_path.key: logical_value}
        machine_after_put: dict[str, z3.ExprRef] = {}
        for write in clause.realize:
            old = translator._atom("machine:" + write.place.key, write.value.sort)
            guard = translator.expression(write.guard, logical=logical_override)
            written = translator.expression(write.value, logical=logical_override)
            machine_after_put[write.place.key] = z3.If(guard, written, old)
        observed_after_put = translator.expression(
            clause.observe, machine=machine_after_put
        )
        if not _universally_equal(observed_after_put, logical_value):
            return LensProofV1("violated", "observe_after_realize_counterexample")

        observed_original = translator.expression(clause.observe)
        observe_override = {clause.logical_path.key: observed_original}
        for write in clause.realize:
            old = translator._atom("machine:" + write.place.key, write.value.sort)
            guard = translator.expression(write.guard, logical=observe_override)
            written = translator.expression(write.value, logical=observe_override)
            if not _universally_equal(z3.If(guard, written, old), old):
                return LensProofV1("violated", "realize_after_observe_counterexample")
    except _Unsupported:
        return LensProofV1("incomplete", "lens_expression_theory_unsupported")
    return LensProofV1("checked", "universal_lens_laws_proved")


def _x87_value_lens(clause: RelationClauseV1) -> bool:
    if clause.observe is None or clause.logical_path is None or len(clause.realize) != 1:
        return False
    observed = clause.observe
    if observed.op != "x87_decode" or len(observed.arguments) != 1:
        return False
    source = observed.arguments[0]
    write = clause.realize[0]
    encoded = write.value
    if source.op != "machine" or encoded.op != "x87_encode" or len(encoded.arguments) != 1:
        return False
    source_places = source.machine_places()
    if len(source_places) != 1 or not _same_boundary_place(source_places[0], write.place):
        return False
    logical = encoded.arguments[0]
    return (
        logical.op == "logical"
        and LogicalPathV1.parse(logical.attributes["path"]).key
        == clause.logical_path.key
        and observed.sort == logical.sort
    )


def _normalized_extension_lens(clause: RelationClauseV1) -> bool:
    if clause.observe is None or clause.logical_path is None or len(clause.realize) != 1:
        return False
    observed = clause.observe
    if observed.op != "slice" or len(observed.arguments) != 1 or observed.attributes.get("offset_bits") != 0:
        return False
    source = observed.arguments[0]
    write = clause.realize[0]
    realized = write.value
    if source.op != "machine" or realized.op not in {"zero_extend", "sign_extend"} or len(realized.arguments) != 1:
        return False
    source_places = source.machine_places()
    logical = realized.arguments[0]
    return (
        len(source_places) == 1
        and _same_boundary_place(source_places[0], write.place)
        and logical.op == "logical"
        and LogicalPathV1.parse(logical.attributes["path"]).key == clause.logical_path.key
        and observed.sort == logical.sort
        and realized.sort.width == source.sort.width
    )


def _logical_for_clause(
    expression: RelationExpressionV1, clause: RelationClauseV1
) -> bool:
    return (
        clause.logical_path is not None
        and expression.op == "logical"
        and LogicalPathV1.parse(expression.attributes["path"]).key
        == clause.logical_path.key
    )


def _normalized_control_condition_lens(clause: RelationClauseV1) -> bool:
    """Recognize the checked C truth-value quotient of one machine flag.

    The portable result domain is normalized to 0 or 1 by the generated
    component adapter.  Realization maps zero to false and every admitted
    nonzero value to true; observation maps the machine flag back to 0 or 1.
    """

    if clause.observe is None or len(clause.realize) != 1:
        return False
    observed = clause.observe
    write = clause.realize[0]
    if observed.op != "ite" or len(observed.arguments) != 3:
        return False
    condition, when_true, when_false = observed.arguments
    if (
        condition.op != "machine"
        or condition.sort.kind != "bool"
        or when_true.op != "const"
        or when_true.attributes.get("value") != 1
        or when_false.op != "const"
        or when_false.attributes.get("value") != 0
        or write.value.op != "not"
        or len(write.value.arguments) != 1
    ):
        return False
    equality = write.value.arguments[0]
    if equality.op != "eq" or len(equality.arguments) != 2:
        return False
    logical, zero = equality.arguments
    places = condition.machine_places()
    return (
        len(places) == 1
        and _same_boundary_place(places[0], write.place)
        and _logical_for_clause(logical, clause)
        and zero.op == "const"
        and zero.attributes.get("value") == 0
    )


def _finite_map_shape(
    expression: RelationExpressionV1,
) -> tuple[RelationExpressionV1, tuple[tuple[int, int], ...], int] | None:
    selector: RelationExpressionV1 | None = None
    cases: list[tuple[int, int]] = []
    current = expression
    while current.op == "ite" and len(current.arguments) == 3:
        condition, value, current = current.arguments
        if condition.op != "eq" or len(condition.arguments) != 2:
            return None
        candidate, match = condition.arguments
        if match.op != "const" or value.op != "const":
            return None
        if selector is None:
            selector = candidate
        elif selector.to_payload() != candidate.to_payload():
            return None
        cases.append((int(match.attributes["value"]), int(value.attributes["value"])))
    if selector is None or current.op != "const":
        return None
    return selector, tuple(cases), int(current.attributes["value"])


def _finite_control_target_lens(clause: RelationClauseV1) -> bool:
    """Recognize inverse finite maps over admitted route/target domains."""

    if clause.observe is None or len(clause.realize) != 1:
        return False
    observed = _finite_map_shape(clause.observe)
    realized = _finite_map_shape(clause.realize[0].value)
    if observed is None or realized is None:
        return False
    machine, decoded_cases, decoded_default = observed
    logical, encoded_cases, encoded_default = realized
    machine_places = machine.machine_places()
    if (
        len(machine_places) != 1
        or not _same_boundary_place(machine_places[0], clause.realize[0].place)
        or not _logical_for_clause(logical, clause)
    ):
        return False
    decoded = {(target, route) for target, route in decoded_cases}
    encoded = {(target, route) for route, target in encoded_cases}
    return (
        len(decoded) == len(decoded_cases)
        and len(encoded) == len(encoded_cases)
        and decoded == encoded
        and decoded_default not in {route for _, route in decoded}
        and encoded_default not in {target for target, _ in decoded}
    )


def _universally_equal(left: z3.ExprRef, right: z3.ExprRef) -> bool:
    solver = z3.Solver()
    solver.set(timeout=10_000)
    solver.add(left != right)
    result = solver.check()
    return result == z3.unsat


def _structured_origin_lens(clause: RelationClauseV1) -> bool:
    """Recognize the origin resolve/address lens proved in the Lean kernel."""

    if clause.observe is None or clause.logical_path is None:
        return False
    observed = clause.observe
    if observed.sort.kind == "view":
        if observed.op != "make_view" or len(observed.arguments) != 2:
            return False
        observed_reference = observed.arguments[0]
        observed_extent = observed.arguments[1]
    elif observed.sort.kind == "reference":
        observed_reference = observed
        observed_extent = None
    else:
        return False
    if (
        observed_reference.op != "authority_call"
        or observed_reference.attributes.get("primitive") != "origin.resolve"
        or len(observed_reference.arguments) != 2
    ):
        return False
    address_expression = observed_reference.arguments[0]
    if address_expression.op != "machine":
        return False
    observed_places = address_expression.machine_places()
    if len(observed_places) != 1:
        return False
    address_writes = [
        write
        for write in clause.realize
        if write.value.op == "authority_call"
        and write.value.attributes.get("primitive") == "origin.address"
    ]
    if len(address_writes) != 1 or not _same_boundary_place(
        observed_places[0], address_writes[0].place
    ):
        return False
    realized = address_writes[0].value
    if (
        realized.op != "authority_call"
        or realized.attributes.get("primitive") != "origin.address"
        or realized.attributes.get("binding")
        != observed_reference.attributes.get("binding")
        or len(realized.arguments) != 1
    ):
        return False
    source = realized.arguments[0]
    if observed.sort.kind == "view":
        if len(clause.realize) != 2:
            return False
        if source.op != "view_address" or len(source.arguments) != 1:
            return False
        source = source.arguments[0]
        extent_places = () if observed_extent is None else observed_extent.machine_places()
        extent_writes = [
            write for write in clause.realize if write.value.op == "view_extent"
        ]
        if (
            len(extent_places) != 1
            or len(extent_writes) != 1
            or not _same_boundary_place(extent_places[0], extent_writes[0].place)
            or len(extent_writes[0].value.arguments) != 1
        ):
            return False
        extent_source = extent_writes[0].value.arguments[0]
        if extent_source.op != "logical":
            return False
        if LogicalPathV1.parse(extent_source.attributes["path"]).key != clause.logical_path.key:
            return False
    elif len(clause.realize) != 1:
        return False
    if source.op != "logical":
        return False
    return LogicalPathV1.parse(source.attributes["path"]).key == clause.logical_path.key


def _same_boundary_place(left, right) -> bool:
    return (
        left.kind == right.kind
        and left.width == right.width
        and _phase_erased(left.payload) == _phase_erased(right.payload)
    )


def _structured_capability_lens(clause: RelationClauseV1) -> bool:
    if (
        clause.observe is None
        or clause.logical_path is None
        or clause.observe.op != "authority_call"
        or clause.observe.attributes.get("primitive") != "capability.import"
        or len(clause.observe.arguments) not in {1, 2}
        or len(clause.realize) != 1
    ):
        return False
    source = clause.observe.arguments[0]
    source_places = source.machine_places()
    write = clause.realize[0]
    exported = write.value
    if (
        len(source_places) != 1
        or not _same_boundary_place(source_places[0], write.place)
        or exported.op != "authority_call"
        or exported.attributes.get("primitive") != "capability.export"
        or exported.attributes.get("binding") != clause.observe.attributes.get("binding")
        or len(exported.arguments) != 1
    ):
        return False
    logical = exported.arguments[0]
    return (
        logical.op == "logical"
        and LogicalPathV1.parse(logical.attributes["path"]).key
        == clause.logical_path.key
    )


def _phase_erased(value):
    if isinstance(value, Mapping):
        return {
            key: _phase_erased(item)
            for key, item in value.items()
            if key != "at"
        }
    if isinstance(value, list):
        return [_phase_erased(item) for item in value]
    return value


__all__ = ["LensProofV1", "prove_binding_lens"]
