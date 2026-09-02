"""Checked scalar service world used by inductive refinement harnesses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .interface_ir import ProofKernelComponentInterface


class InductiveWorldError(ValueError):
    """An inductive service world cannot be represented exactly."""


@dataclass(frozen=True)
class InductiveServiceWorld:
    prelude: tuple[str, ...]
    setup: tuple[str, ...]
    service_numbers: Mapping[str, int]


def render_inductive_service_world(
    *,
    interface: ProofKernelComponentInterface,
    operation_id: str,
    model: Mapping[str, object],
    nondeterministic_functions: Mapping[str, str],
    provider_contracts: Mapping[str, Mapping[str, object]] | None = None,
) -> InductiveServiceWorld:
    operation = interface.operation_index()[operation_id]
    enabled = set(operation.allowed_service_ids)
    services = [row for row in interface.services if row.identity in enabled]
    if {row.identity for row in services} != enabled:
        raise InductiveWorldError("inductive service inventory is stale")
    types = interface.type_index()
    for service in services:
        service_types = [types[item] for item in service.parameter_type_ids]
        if service.result_type_id is not None:
            service_types.append(types[service.result_type_id])
        if any(item.kind not in {"scalar", "enum", "resource"} for item in service_types):
            raise InductiveWorldError(
                f"inductive service {service.identity!r} requires a non-scalar world value"
            )

    segments = _rows(model.get("segments"), "inductive segments")
    max_events = max(
        1,
        max(
            (len(_rows(segment.get("trace"), "inductive segment trace")) for segment in segments),
            default=0,
        ),
    )
    max_arguments = max(
        1,
        max((len(service.parameter_type_ids) for service in services), default=0),
    )
    service_numbers = {
        service.identity: index + 1
        for index, service in enumerate(interface.services)
    }
    contracts = provider_contracts or {}
    if set(contracts) - enabled:
        raise InductiveWorldError(
            "inductive provider contract inventory contains an unused service"
        )
    prelude = [
        "typedef struct {",
        "  uint32_t count;",
        "  uint32_t overflow;",
        f"  uint32_t ids[{max_events}];",
        f"  uint32_t argument_counts[{max_events}];",
        f"  uint64_t arguments[{max_events}][{max_arguments}];",
        f"  uint64_t results[{max_events}];",
        "} spx_inductive_oracle_v1;",
        "static spx_inductive_oracle_v1 spx_oracle;",
        "",
    ]
    for service in services:
        result = (
            "void"
            if service.result_type_id is None
            else interface.logical_c_type(service.result_type_id)
        )
        parameters = ["void *opaque"] + [
            f"{interface.logical_c_type(type_id)} argument_{index}"
            for index, type_id in enumerate(service.parameter_type_ids)
        ]
        prelude.extend(
            [
                f"static {result} spx_inductive_service_{service.identity}({', '.join(parameters)}) {{",
                "  spx_inductive_oracle_v1 *oracle = (spx_inductive_oracle_v1 *)opaque;",
                "  uint32_t index = oracle->count++;",
                f"  if (index >= UINT32_C({max_events})) {{ oracle->overflow = UINT32_C(1); index = UINT32_C(0); }}",
                f"  oracle->ids[index] = UINT32_C({service_numbers[service.identity]});",
                f"  oracle->argument_counts[index] = UINT32_C({len(service.parameter_type_ids)});",
            ]
        )
        prelude.extend(
            f"  oracle->arguments[index][{index}] = (uint64_t)argument_{index};"
            for index in range(len(service.parameter_type_ids))
        )
        if result != "void":
            nondet = nondeterministic_functions.get(result)
            if nondet is None:
                raise InductiveWorldError(
                    f"inductive service result type {result!r} has no nondeterministic source"
                )
            prelude.extend(
                [
                    f"  {result} logical_result = {nondet}();",
                    *_render_provider_assumption(
                        service_id=service.identity,
                        result="logical_result",
                        contract=contracts.get(service.identity),
                    ),
                    "  oracle->results[index] = (uint64_t)logical_result;",
                    "  return logical_result;",
                ]
            )
        prelude.extend(["}", ""])

    service_type = f"spx_{interface.identity}_services_v2"
    setup = [
        f"  {service_type} services = {{0}};",
        "  spx_oracle.count = UINT32_C(0);",
        "  spx_oracle.overflow = UINT32_C(0);",
        "  services.context = &spx_oracle;",
        *(
            f"  services.{service.identity} = spx_inductive_service_{service.identity};"
            for service in services
        ),
        "  context.services = &services;",
    ]
    return InductiveServiceWorld(
        prelude=tuple(prelude),
        setup=tuple(setup),
        service_numbers=service_numbers,
    )


def _render_provider_assumption(
    *,
    service_id: str,
    result: str,
    contract: Mapping[str, object] | None,
) -> list[str]:
    if contract is None:
        return []
    parameter_ids = contract.get("parameter_ids")
    result_id = contract.get("result_id")
    paths = contract.get("paths")
    if (
        not isinstance(parameter_ids, list)
        or any(not isinstance(item, str) for item in parameter_ids)
        or not isinstance(result_id, str)
        or not isinstance(paths, list)
        or not paths
        or any(not isinstance(item, Mapping) for item in paths)
    ):
        raise InductiveWorldError(
            f"inductive provider contract for {service_id!r} is malformed"
        )
    parameters = {
        name: f"argument_{index}" for index, name in enumerate(parameter_ids)
    }
    clauses: list[str] = []
    for path in paths:
        guards = _rows(path.get("guards"), "provider path guards")
        results = path.get("results")
        if not isinstance(results, Mapping) or set(results) != {result_id}:
            raise InductiveWorldError(
                f"inductive provider {service_id!r} result inventory differs"
            )
        conditions = [
            *(_render_provider_expression(item, parameters) for item in guards),
            f"({result}) == ({_render_provider_expression(results[result_id], parameters)})",
        ]
        clauses.append(" && ".join(f"({item})" for item in conditions))
    return [
        "  __CPROVER_assume(" + " || ".join(f"({item})" for item in clauses) + ");"
    ]


def _render_provider_expression(
    value: object, parameters: Mapping[str, str]
) -> str:
    if not isinstance(value, Mapping):
        raise InductiveWorldError("provider expression must be an object")
    op = value.get("op")
    if op == "parameter":
        name = value.get("name")
        if not isinstance(name, str) or name not in parameters:
            raise InductiveWorldError("provider expression parameter is stale")
        return parameters[name]
    if op == "const":
        return f"UINT32_C({int(value.get('value', 0)) & 0xFFFFFFFF})"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    arguments = value.get("args")
    if not isinstance(arguments, list):
        raise InductiveWorldError(f"provider expression {op!r} has no arguments")
    rendered = [
        _render_provider_expression(item, parameters)
        if isinstance(item, Mapping)
        else str(item)
        for item in arguments
    ]
    word_binary = {
        "add32": "+",
        "sub32": "-",
        "and32": "&",
        "or32": "|",
        "xor32": "^",
        "mul32": "*",
        "ult32": "<",
        "ule32": "<=",
    }
    logical_binary = {
        "eq": "==",
        "and": "&&",
        "and_bool": "&&",
        "or": "||",
        "or_bool": "||",
    }
    if op in word_binary and len(rendered) == 2:
        return (
            f"(((uint32_t)({rendered[0]})) {word_binary[op]} "
            f"((uint32_t)({rendered[1]})))"
        )
    if op in logical_binary and len(rendered) == 2:
        return f"(({rendered[0]}) {logical_binary[op]} ({rendered[1]}))"
    if op == "not" and len(rendered) == 1:
        return f"(!({rendered[0]}))"
    if op == "ite" and len(rendered) == 3:
        return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
    raise InductiveWorldError(
        f"provider expression operation {op!r} is unsupported"
    )


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise InductiveWorldError(f"{context} must be an array of objects")
    return list(value)


__all__ = [
    "InductiveServiceWorld",
    "InductiveWorldError",
    "render_inductive_service_world",
]
