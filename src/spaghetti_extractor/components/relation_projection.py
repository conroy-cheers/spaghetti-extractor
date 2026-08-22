"""Mechanical projection of checked machine bindings into relation clauses."""

from __future__ import annotations

from typing import Mapping

from .interface_ir import LogicalTypeV1
from .machine_binding import (
    LogicalMachineValueV1,
    MachineProjectionV1,
    OperationMachineBindingV1,
)
from .relation_ir import ComponentRelationIRError


class RelationProjectionError(ComponentRelationIRError):
    """A checked projection cannot be realized constructively."""


def _operation_clauses(
    bound: OperationMachineBindingV1,
    *,
    parameter_types: Mapping[str, LogicalTypeV1],
    result_types: Mapping[str, LogicalTypeV1],
    state_types: Mapping[str, LogicalTypeV1],
) -> list[dict[str, object]]:
    clauses: list[dict[str, object]] = []
    for item in bound.parameters:
        logical_type = _lookup(parameter_types, item.identity, "parameter")
        observe = _observe_projection(item.projection, logical_type)
        reads = list(_expression_places(observe).values())
        clauses.append(
            _binding_clause(
                identity=f"parameter.{item.identity}",
                phase="entry",
                root="parameter",
                value_id=item.identity,
                observe=observe,
                realize=[],
                reads=reads,
                writes=[],
            )
        )
    for item in bound.results:
        logical_type = _lookup(result_types, item.identity, "result")
        logical = _logical_expression("result", item.identity, _logical_sort(logical_type))
        if item.projection.kind in {
            "reference",
            "view",
            "resource",
            "callback_handle",
            "finite_control_target",
        }:
            if item.decoding is not None:
                raise RelationProjectionError(
                    "reference/view projections cannot use scalar value decodings"
                )
            observe = _observe_projection(item.projection, logical_type)
            realize = _realize_projection(item.projection, logical, logical_type)
        else:
            place = _projection_place(item.projection)
            projected = _machine_expression(place, _projection_sort(item.projection))
            if item.decoding is None:
                observe = _coerce_projection(projected, _logical_sort(logical_type))
                encoded = _coerce_projection(logical, _projection_sort(item.projection))
            else:
                observe = _lower_codec(
                    item.decoding,
                    projected=projected,
                    parameter_types=parameter_types,
                    state_types=state_types,
                )
                encoded = _invert_codec(
                    item.decoding,
                    logical=logical,
                    parameter_types=parameter_types,
                    state_types=state_types,
                )
            realize = [{"place": place, "value": encoded, "guard": _true()}]
        reads = {
            **_expression_places(observe),
            **{
                key: value
                for write in realize
                for key, value in _expression_places(write["value"]).items()
            },
        }
        clauses.append(
            _binding_clause(
                identity=f"result.{item.identity}",
                phase="exit",
                root="result",
                value_id=item.identity,
                observe=observe,
                realize=realize,
                reads=list(reads.values()),
                writes=[write["place"] for write in realize],
            )
        )
    state_bindings = {item.identity: item for item in bound.state}
    for state_id, logical_type in sorted(state_types.items()):
        item = state_bindings.get(state_id)
        if item is None:
            continue
        sort = _logical_sort(logical_type)
        observe = _observe_projection(item.entry, logical_type)
        logical = _logical_expression("state", state_id, sort)
        realize = _realize_projection(item.exit, logical, logical_type)
        if item.entry.kind in {
            "reference", "view", "resource", "callback_handle"
        } and (
            _authority_id(item.entry) != _authority_id(item.exit)
        ):
            raise RelationProjectionError(
                f"state {state_id!r} changes origin authority across its boundary"
            )
        clauses.append(
            _binding_clause(
                identity=f"state.{state_id}",
                phase="exit",
                root="state",
                value_id=state_id,
                observe=observe,
                realize=realize,
                reads=list(_expression_places(observe).values()),
                writes=[write["place"] for write in realize],
            )
        )
    for effect in bound.effects:
        clauses.append(
            {
                "id": f"effect.{effect.identity}",
                "kind": "effect_link",
                "phase": "event_after",
                "logical_path": None,
                "observe": None,
                "realize": [],
                "predicate": None,
                "effect_id": effect.effect_id,
                "machine_event": {
                    "unit_id": effect.unit_id,
                    "family": effect.family,
                    "index": effect.index,
                    "fact_sha256": effect.fact_sha256,
                },
                "reads": [],
                "writes": [],
            }
        )
    return sorted(clauses, key=lambda item: str(item["id"]))


def _binding_clause(
    *,
    identity: str,
    phase: str,
    root: str,
    value_id: str,
    observe: Mapping[str, object],
    realize: list[dict[str, object]],
    reads: list[Mapping[str, object]],
    writes: list[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "id": identity,
        "kind": "binding",
        "phase": phase,
        "logical_path": {"root": root, "id": value_id, "fields": []},
        "observe": dict(observe),
        "realize": realize,
        "predicate": None,
        "effect_id": None,
        "machine_event": None,
        "reads": _ordered_places(reads),
        "writes": _ordered_places(writes),
    }


def _lookup(index: Mapping[str, LogicalTypeV1], identity: str, context: str) -> LogicalTypeV1:
    try:
        return index[identity]
    except KeyError as exc:
        raise RelationProjectionError(
            f"{context} binding references unknown value {identity!r}"
        ) from exc


def _logical_sort(logical_type: LogicalTypeV1) -> dict[str, object]:
    if logical_type.kind in {"scalar", "enum"}:
        assert logical_type.c_type is not None
        width = int(logical_type.c_type.removeprefix("uint").removeprefix("int").removesuffix("_t"))
        return {"kind": "bitvector", "width": width}
    kind = "view" if logical_type.kind == "bytes" else logical_type.kind
    return {"kind": kind, "type_id": logical_type.identity}


def _observe_projection(
    projection: MachineProjectionV1,
    logical_type: LogicalTypeV1,
) -> dict[str, object]:
    if projection.kind == "finite_control_target":
        place = _projection_place(projection)
        target = _machine_expression(place, {"kind": "bitvector", "width": 32})
        routes = _finite_control_routes(projection)
        return _finite_map(
            target,
            [(target_address, logical_value) for target_address, logical_value in routes],
            result_sort=_logical_sort(logical_type),
            context="finite control target decoding",
        )
    if projection.kind in {"resource", "callback_handle"}:
        source = MachineProjectionV1.parse(
            projection.payload["source"], f"{projection.kind} source"
        )
        return _authority_call(
            primitive="capability.import",
            binding=_authority_id(projection),
            sort=_logical_sort(logical_type),
            arguments=[_projection_expression(source, {"kind": "bitvector", "width": 32})],
        )
    if projection.kind not in {"reference", "view"}:
        place = _projection_place(projection)
        return _machine_expression(place, _logical_sort(logical_type))
    payload = projection.payload
    source_field = "source" if projection.kind == "reference" else "base"
    source = MachineProjectionV1.parse(
        payload[source_field], f"{projection.kind} address source"
    )
    requested_extent = MachineProjectionV1.parse(
        payload["requested_extent"],
        f"{projection.kind} requested extent",
    )
    reference_sort = {
        "kind": "reference",
        "type_id": (
            logical_type.identity
            if projection.kind == "reference"
            else f"{logical_type.identity}.base"
        ),
    }
    resolved = _authority_call(
        primitive="origin.resolve",
        binding=_authority_id(projection),
        sort=reference_sort,
        arguments=[
            _projection_expression(source, {"kind": "bitvector", "width": 32}),
            _projection_expression(
                requested_extent, {"kind": "bitvector", "width": 32}
            ),
        ],
    )
    if projection.kind == "reference":
        return resolved
    extent = MachineProjectionV1.parse(payload["extent"], "view extent")
    if extent.kind == "origin_remainder":
        extent_expression = {
            "op": "ref_remaining",
            "sort": {"kind": "bitvector", "width": 32},
            "args": [resolved],
            "attributes": {},
        }
    else:
        extent_expression = _projection_expression(
            extent, {"kind": "bitvector", "width": 32}
        )
    return {
        "op": "make_view",
        "sort": _logical_sort(logical_type),
        "args": [
            resolved,
            extent_expression,
        ],
        "attributes": {},
    }


def _realize_projection(
    projection: MachineProjectionV1,
    logical: Mapping[str, object],
    logical_type: LogicalTypeV1,
) -> list[dict[str, object]]:
    if projection.kind == "finite_control_target":
        routes = _finite_control_routes(projection)
        inverse: dict[int, int] = {}
        for target_address, logical_value in routes:
            previous = inverse.setdefault(logical_value, target_address)
            if previous != target_address:
                raise RelationProjectionError(
                    "finite control target has multiple machine targets for one "
                    "logical value"
                )
        encoded = _finite_map(
            logical,
            sorted(inverse.items()),
            result_sort={"kind": "bitvector", "width": 32},
            context="finite control target encoding",
        )
        return [
            {
                "place": _projection_place(projection),
                "value": encoded,
                "guard": _true(),
            }
        ]
    if projection.kind in {"resource", "callback_handle"}:
        source = MachineProjectionV1.parse(
            projection.payload["source"], f"{projection.kind} source"
        )
        return [
            {
                "place": _writable_projection_place(source, f"{projection.kind} source"),
                "value": _authority_call(
                    primitive="capability.export",
                    binding=_authority_id(projection),
                    sort={"kind": "bitvector", "width": 32},
                    arguments=[dict(logical)],
                ),
                "guard": _true(),
            }
        ]
    if projection.kind not in {"reference", "view"}:
        place = _projection_place(projection)
        return [
            {
                "place": place,
                "value": _coerce_projection(
                    logical, _projection_sort(projection)
                ),
                "guard": _true(),
            }
        ]
    payload = projection.payload
    reference = dict(logical)
    writes: list[dict[str, object]] = []
    if projection.kind == "view":
        reference = {
            "op": "view_address",
            "sort": {
                "kind": "reference",
                "type_id": f"{logical_type.identity}.base",
            },
            "args": [dict(logical)],
            "attributes": {},
        }
        extent = MachineProjectionV1.parse(payload["extent"], "view extent")
        writes.append(
            {
                "place": _writable_projection_place(extent, "view extent"),
                "value": {
                    "op": "view_extent",
                    "sort": {"kind": "bitvector", "width": 32},
                    "args": [dict(logical)],
                    "attributes": {},
                },
                "guard": _true(),
            }
        )
    source_field = "source" if projection.kind == "reference" else "base"
    source = MachineProjectionV1.parse(
        payload[source_field], f"{projection.kind} address source"
    )
    writes.insert(
        0,
        {
            "place": _writable_projection_place(source, f"{projection.kind} address"),
            "value": _authority_call(
                primitive="origin.address",
                binding=_authority_id(projection),
                sort={"kind": "bitvector", "width": 32},
                arguments=[reference],
            ),
            "guard": _true(),
        },
    )
    return writes


def _authority_call(
    *,
    primitive: str,
    binding: str,
    sort: Mapping[str, object],
    arguments: list[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "op": "authority_call",
        "sort": dict(sort),
        "args": [dict(item) for item in arguments],
        "attributes": {"primitive": primitive, "binding": binding},
    }


def _authority_id(projection: MachineProjectionV1) -> str:
    if projection.kind == "callback_handle":
        value = projection.payload.get("authority_id")
        if isinstance(value, str):
            return value
    if projection.kind in {"resource", "atomic_object"}:
        value = projection.payload.get("resource_kind")
        if isinstance(value, str):
            return value
    authority = projection.payload.get("authority")
    if not isinstance(authority, Mapping) or not isinstance(authority.get("id"), str):
        raise RelationProjectionError("origin projection has no authority id")
    return str(authority["id"])


def _writable_projection_place(
    projection: MachineProjectionV1,
    context: str,
) -> dict[str, object]:
    if projection.kind not in {"register", "stack", "static_slot", "memory"}:
        raise RelationProjectionError(
            f"{context} projection is not a writable machine place"
        )
    return _projection_place(projection)


def _projection_expression(
    projection: MachineProjectionV1,
    sort: Mapping[str, object],
) -> dict[str, object]:
    if projection.kind == "constant":
        return {
            "op": "const",
            "sort": dict(sort),
            "args": [],
            "attributes": {"value": int(projection.payload["value"])},
        }
    return _machine_expression(_projection_place(projection), sort)


def _projection_sort(projection: MachineProjectionV1) -> dict[str, object]:
    if projection.kind == "control_condition":
        return {"kind": "bool"}
    if projection.kind == "finite_control_target":
        return {"kind": "bitvector", "width": 32}
    width = projection.payload.get("width")
    if isinstance(width, int):
        return {"kind": "bitvector", "width": width}
    if projection.kind in {"bytes_view", "record_view"}:
        return {
            "kind": "view" if projection.kind == "bytes_view" else "record",
            "type_id": f"projection.{projection.kind}",
        }
    if projection.kind == "resource":
        return {"kind": "resource", "type_id": str(projection.payload.get("resource_kind"))}
    if projection.kind == "callback_handle":
        return {"kind": "callback", "type_id": str(projection.payload.get("protocol_id"))}
    return {"kind": "bitvector", "width": 32}


def _projection_place(projection: MachineProjectionV1) -> dict[str, object]:
    payload = projection.to_payload()
    at = payload.get("at")
    if not isinstance(at, str):
        source = payload.get("source") or payload.get("base")
        if isinstance(source, Mapping):
            at = source.get("at")
    phase = at if at in {"entry", "exit"} else "entry"
    if projection.kind == "control_condition":
        kind = "flag"
    elif projection.kind == "finite_control_target":
        kind = "control_target"
    else:
        kind = projection.kind if projection.kind in {"register", "stack", "static_slot", "memory", "control_target", "action_value", "capability_slot"} else "capability_slot"
    width = 32 if projection.kind == "finite_control_target" else payload.get("width")
    return {
        "kind": kind,
        "phase": phase,
        "width": width if isinstance(width, int) else None,
        "selector": payload,
    }


def _machine_expression(place: Mapping[str, object], sort: Mapping[str, object]) -> dict[str, object]:
    return {"op": "machine", "sort": dict(sort), "args": [], "attributes": {"place": dict(place)}}


def _logical_expression(root: str, identity: str, sort: Mapping[str, object]) -> dict[str, object]:
    return {
        "op": "logical",
        "sort": dict(sort),
        "args": [],
        "attributes": {"path": {"root": root, "id": identity, "fields": []}},
    }


def _true() -> dict[str, object]:
    return {"op": "true", "sort": {"kind": "bool"}, "args": [], "attributes": {}}


def _coerce_projection(expression: Mapping[str, object], sort: Mapping[str, object]) -> dict[str, object]:
    if expression["sort"] == sort:
        return dict(expression)
    source = expression["sort"]
    if isinstance(source, Mapping) and source.get("kind") == "bitvector" and sort.get("kind") == "bitvector":
        source_width, target_width = int(source["width"]), int(sort["width"])
        op = "zero_extend" if source_width < target_width else "truncate"
        return {"op": op, "sort": dict(sort), "args": [dict(expression)], "attributes": {}}
    if source == {"kind": "bool"} and sort.get("kind") == "bitvector":
        return {
            "op": "ite",
            "sort": dict(sort),
            "args": [
                dict(expression),
                _constant(1, sort),
                _constant(0, sort),
            ],
            "attributes": {},
        }
    if source.get("kind") == "bitvector" and sort == {"kind": "bool"}:
        return {
            "op": "not",
            "sort": {"kind": "bool"},
            "args": [
                {
                    "op": "eq",
                    "sort": {"kind": "bool"},
                    "args": [dict(expression), _constant(0, source)],
                    "attributes": {},
                }
            ],
            "attributes": {},
        }
    raise RelationProjectionError("projection sort cannot be converted constructively")


def _constant(value: int, sort: Mapping[str, object]) -> dict[str, object]:
    return {
        "op": "const",
        "sort": dict(sort),
        "args": [],
        "attributes": {"value": value},
    }


def _finite_control_routes(
    projection: MachineProjectionV1,
) -> list[tuple[int, int]]:
    routes = projection.payload.get("routes")
    if not isinstance(routes, list) or not routes:
        raise RelationProjectionError("finite control target has no routes")
    result: dict[int, int] = {}
    for raw in routes:
        if not isinstance(raw, Mapping):
            raise RelationProjectionError("finite control target route is malformed")
        target_address = raw.get("target_address")
        logical_value = raw.get("logical_value")
        if not isinstance(target_address, int) or not isinstance(logical_value, int):
            raise RelationProjectionError("finite control target route is malformed")
        previous = result.setdefault(target_address, logical_value)
        if previous != logical_value:
            raise RelationProjectionError(
                "finite control target maps one machine target to multiple logical values"
            )
    return sorted(result.items())


def _finite_map(
    selector: Mapping[str, object],
    cases: list[tuple[int, int]],
    *,
    result_sort: Mapping[str, object],
    context: str,
) -> dict[str, object]:
    if not cases:
        raise RelationProjectionError(f"{context} has no cases")
    selector_sort = selector.get("sort")
    if not isinstance(selector_sort, Mapping) or selector_sort.get("kind") != "bitvector":
        raise RelationProjectionError(f"{context} selector is not a bitvector")
    result = _constant(cases[-1][1], result_sort)
    for match, value in reversed(cases[:-1]):
        result = {
            "op": "ite",
            "sort": dict(result_sort),
            "args": [
                {
                    "op": "eq",
                    "sort": {"kind": "bool"},
                    "args": [dict(selector), _constant(match, selector_sort)],
                    "attributes": {},
                },
                _constant(value, result_sort),
                result,
            ],
            "attributes": {},
        }
    return result


def _lower_codec(
    expression: Mapping[str, object],
    *,
    projected: Mapping[str, object],
    parameter_types: Mapping[str, LogicalTypeV1],
    state_types: Mapping[str, LogicalTypeV1],
) -> dict[str, object]:
    op = expression.get("op")
    word = {"kind": "bitvector", "width": 32}
    if op == "projected_value":
        return _coerce_projection(projected, word)
    if op == "const":
        return {"op": "const", "sort": {"kind": "bitvector", "width": int(expression["width"])}, "args": [], "attributes": {"value": int(expression["value"])}}
    if op in {"parameter", "state_input"}:
        name = str(expression["name"])
        root, types = ("parameter", parameter_types) if op == "parameter" else ("state", state_types)
        return _logical_expression(root, name, _logical_sort(_lookup(types, name, root)))
    if op in {"bytes_address", "byte_extent"}:
        name = str(expression["name"])
        view = _logical_expression("parameter", name, _logical_sort(_lookup(parameter_types, name, "parameter")))
        return {"op": "view_address" if op == "bytes_address" else "view_extent", "sort": word, "args": [view], "attributes": {}}
    if op == "byte_read":
        name = str(expression["name"])
        view = _logical_expression("parameter", name, _logical_sort(_lookup(parameter_types, name, "parameter")))
        index = _lower_codec(expression["index"], projected=projected, parameter_types=parameter_types, state_types=state_types)
        return {"op": "byte_read", "sort": {"kind": "bitvector", "width": 8}, "args": [view, index], "attributes": {}}
    mapped = {"add32": "add", "sub32": "sub", "and32": "bit_and", "or32": "bit_or", "xor32": "bit_xor", "ult32": "ult", "ule32": "ule"}
    if op in mapped or op in {"eq", "and", "or", "not", "ite"}:
        args = [_lower_codec(item, projected=projected, parameter_types=parameter_types, state_types=state_types) for item in expression.get("args", [])]
        result_sort = {"kind": "bool"} if op in {"eq", "ult32", "ule32", "and", "or", "not"} else args[1]["sort"] if op == "ite" else word
        return {"op": mapped.get(str(op), str(op)), "sort": result_sort, "args": args, "attributes": {}}
    raise RelationProjectionError(f"codec operation {op!r} cannot be lowered")


def _invert_codec(
    expression: Mapping[str, object],
    *,
    logical: Mapping[str, object],
    parameter_types: Mapping[str, LogicalTypeV1],
    state_types: Mapping[str, LogicalTypeV1],
) -> dict[str, object]:
    op = expression.get("op")
    if op == "projected_value":
        return dict(logical)
    args = expression.get("args")
    if op in {"sub32", "add32"} and isinstance(args, list) and len(args) == 2 and isinstance(args[0], Mapping) and args[0].get("op") == "projected_value":
        dummy = {"op": "const", "sort": {"kind": "bitvector", "width": 32}, "args": [], "attributes": {"value": 0}}
        other = _lower_codec(args[1], projected=dummy, parameter_types=parameter_types, state_types=state_types)
        return {"op": "add" if op == "sub32" else "sub", "sort": {"kind": "bitvector", "width": 32}, "args": [dict(logical), other], "attributes": {}}
    raise RelationProjectionError("result decoding has no supported total inverse")


def _expression_places(
    expression: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    from ..artifacts.artifact_set import canonical_sha256_v3

    result: dict[str, dict[str, object]] = {}
    if expression.get("op") == "machine":
        place = expression.get("attributes", {}).get("place")
        if isinstance(place, Mapping):
            result[canonical_sha256_v3(place)] = dict(place)
    for child in expression.get("args", []):
        if isinstance(child, Mapping):
            result.update(_expression_places(child))
    return result


def _ordered_places(values: list[Mapping[str, object]]) -> list[dict[str, object]]:
    from ..artifacts.artifact_set import canonical_sha256_v3

    unique = {canonical_sha256_v3(value): dict(value) for value in values}
    return [unique[key] for key in sorted(unique)]


__all__ = ["RelationProjectionError"]
