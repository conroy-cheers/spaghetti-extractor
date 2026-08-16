"""Render checked machine expressions at portable-component boundaries."""

from __future__ import annotations

import json
from collections.abc import Mapping

from ..external.contracts import CheckedExternalSiteContract
from .intent import ComponentIntentError


STATE_FIELDS = (
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "cf",
    "zf",
    "sf",
    "of",
    "pf",
    "df",
)


class CExpression:
    """Render the normalized machine-expression subset used by adapters."""

    def __init__(self, names: Mapping[str, str], *, memory_fault: str) -> None:
        self.names = names
        self.memory_fault = memory_fault

    def render(self, value: object) -> str:
        expression = _object(value, "machine expression")
        op = expression.get("op")
        if op == "const":
            return f"UINT32_C({int(expression.get('value', 0)) & 0xFFFFFFFF})"
        if op in {"reg", "flag"}:
            name = _string(expression.get("name"), "machine state name")
            if name not in self.names:
                raise ComponentIntentError(
                    f"adapter expression uses unsupported state {name}"
                )
            return self.names[name]
        if op == "false":
            return "0U"
        if op == "true":
            return "1U"
        if op == "load":
            return "component_read(rt, {address}, {width}U, &{fault})".format(
                address=self.render(expression.get("address")),
                width=int(expression.get("width", 4)),
                fault=self.memory_fault,
            )
        raw_args = _array(expression.get("args", []), f"{op} arguments")
        args = [
            self.render(arg) if isinstance(arg, Mapping) else str(int(arg))
            for arg in raw_args
        ]
        if op == "add32":
            return "(" + " + ".join(args) + ")"
        if op == "sub32":
            return f"({args[0]} - {args[1]})"
        if op == "and32":
            return f"({args[0]} & {args[1]})"
        if op == "or32":
            return f"({args[0]} | {args[1]})"
        if op == "xor32":
            return f"({args[0]} ^ {args[1]})"
        if op == "eq":
            return f"(({args[0]}) == ({args[1]}))"
        if op == "ult32":
            return f"((uint32_t)({args[0]}) < (uint32_t)({args[1]}))"
        if op == "ite":
            return f"(({args[0]}) ? ({args[1]}) : ({args[2]}))"
        if op == "not":
            return f"(!({args[0]}))"
        if op == "msb":
            return f"((({args[-1]}) >> ({args[0]} - 1U)) & 1U)"
        if op == "parity":
            return f"component_parity({args[-1]})"
        if op == "sub_overflow":
            return f"component_sub_overflow({args[1]}, {args[2]}, {args[3]})"
        if op == "add_overflow":
            return f"component_add_overflow({args[1]}, {args[2]}, {args[3]})"
        raise ComponentIntentError(
            f"adapter expression operation is unsupported: {op}"
        )


class CompletionExpression(CExpression):
    """Render completion expressions with checked external-call results."""

    def __init__(
        self,
        names: Mapping[str, str],
        *,
        memory_fault: str,
        external_results: Mapping[tuple[str, int, str], str],
    ) -> None:
        super().__init__(names, memory_fault=memory_fault)
        self.external_results = external_results

    def render(self, value: object) -> str:
        expression = _object(value, "component completion expression")
        if expression.get("op") == "entry":
            name = _string(expression.get("name"), "completion entry field")
            if name not in self.names:
                raise ComponentIntentError(
                    f"completion expression uses unsupported state {name}"
                )
            return self.names[name]
        if expression.get("op") == "logical_result":
            return "((uint32_t)logical_result)"
        if expression.get("op") == "external_result":
            event_index = expression.get("event_index")
            key = (
                _string(expression.get("unit_id"), "completion external-result unit"),
                event_index,
                _string(
                    expression.get("register"),
                    "completion external-result register",
                ),
            )
            if (
                not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
                or key not in self.external_results
            ):
                raise ComponentIntentError(
                    "completion external-result reference is not available"
                )
            return self.external_results[key]
        return super().render(expression)


def render_external_call(
    *,
    lines: list[str],
    contract: CheckedExternalSiteContract,
    event: Mapping[str, object],
    renderer: CExpression,
    unit_id: str,
    event_index: int,
) -> dict[tuple[str, int, str], str]:
    """Append one checked external call and return named result expressions."""

    identity = contract.identity
    call_name = "external_call_0"
    lines.append(f"  spx_machine_state {call_name}_input = external_replay_state;")
    for field, expression in _object(
        event.get("register_inputs"), "external register inputs"
    ).items():
        if field not in STATE_FIELDS:
            raise ComponentIntentError(
                "component external call register input is invalid"
            )
        lines.append(f"  {call_name}_input.{field} = {renderer.render(expression)};")
    for field, expression in _object(
        event.get("flag_inputs"), "external flag inputs"
    ).items():
        if field not in STATE_FIELDS:
            raise ComponentIntentError("component external call flag input is invalid")
        lines.append(f"  {call_name}_input.{field} = {renderer.render(expression)};")
    call_renderer = CExpression(
        {name: f"{call_name}_input.{name}" for name in STATE_FIELDS},
        memory_fault="memory_fault",
    )
    arguments = [call_renderer.render(value) for value in contract.arguments]
    if arguments:
        lines.append(
            f"  uint32_t {call_name}_arguments[{len(arguments)}] = "
            "{ " + ", ".join(arguments) + " };"
        )
    argument_pointer = f"{call_name}_arguments" if arguments else "0"
    instruction_rva = int(event.get("instruction_rva", 0))
    return_rva = int(event.get("return_rva", 0))
    symbol = "0" if identity.symbol is None else _c_string(identity.symbol)
    ordinal = 0 if identity.ordinal is None else identity.ordinal
    lines.extend(
        [
            f"  spx_call_event {call_name}_event = {{",
            "    SPX_CALL_EXTERNAL_IMPORT,",
            f"    {instruction_rva}U, {event_index}U, 0U, {return_rva}U,",
            f"    {_c_string(identity.dll or '')}, {symbol}, {ordinal}U, "
            f"{1 if identity.ordinal is not None else 0}U,",
            f"    {argument_pointer}, {len(arguments)}U, 0, 0U",
            "  };",
            f"  spx_machine_state {call_name}_output;",
            f"  spx_call_status {call_name}_status = spx_invoke_call(",
            f"      rt, &{call_name}_event, &{call_name}_input, &{call_name}_output);",
            f"  if ({call_name}_status != SPX_CALL_OK) return (spx_step_result){{",
            f"    {call_name}_status == SPX_CALL_DIVIDE_ERROR ? SPX_DIVIDE_ERROR :",
            f"    {call_name}_status == SPX_CALL_MEMORY_FAULT ? SPX_MEMORY_FAULT :",
            f"    {call_name}_status == SPX_CALL_EXTERNAL_FAULT ? SPX_EXTERNAL_FAULT :",
            "    SPX_UNIMPLEMENTED, 0U, 0U };",
        ]
    )
    results: dict[tuple[str, int, str], str] = {}
    for relation in contract.result_register_relations:
        if not isinstance(relation, Mapping) or relation.get("relation") != "exact":
            continue
        register = relation.get("register")
        if isinstance(register, str):
            results[(unit_id, event_index, register)] = (
                f"{call_name}_output.{register}"
            )
    return results


def machine_source_expression(
    parameter: Mapping[str, object],
    members: Mapping[str, Mapping[str, object]],
) -> object:
    """Resolve a logical parameter's checked machine-source expression."""

    source = _object(parameter.get("machine_source"), "logical parameter source")
    if source.get("kind") == "register":
        return {
            "op": "reg",
            "name": source.get("name"),
            "width": source.get("width", 32),
        }
    if source.get("kind") == "expression" and source.get("expression") is not None:
        return source["expression"]
    evidence = _object(source.get("evidence"), "logical parameter evidence")
    unit = members.get(_string(evidence.get("unit_id"), "parameter evidence unit"))
    if unit is None:
        raise ComponentIntentError("parameter evidence is outside the component")
    return json_pointer(
        unit,
        _string(evidence.get("json_pointer"), "parameter evidence pointer"),
    )


def result_register(
    result: Mapping[str, object], members: Mapping[str, Mapping[str, object]]
) -> str:
    """Resolve the exact machine register owned by one logical result."""

    refs = _array(result.get("effect_refs", []), "logical result effect references")
    if len(refs) != 1:
        raise ComponentIntentError("logical result must own one register-write effect")
    ref = _object(refs[0], "logical result effect reference")
    if ref.get("family") != "register_write":
        raise ComponentIntentError("logical result effect is not a register write")
    unit = members.get(_string(ref.get("unit_id"), "logical result effect unit"))
    index = ref.get("index")
    if unit is None or not isinstance(index, int):
        raise ComponentIntentError("logical result effect reference is stale")
    writes = _array(
        _object(unit.get("semantics"), "machine semantics").get(
            "register_writes", []
        ),
        "register writes",
    )
    if index < 0 or index >= len(writes):
        raise ComponentIntentError("logical result effect index is stale")
    return _string(
        _object(writes[index], "register write").get("register"),
        "result register",
    )


def json_pointer(value: object, pointer: str) -> object:
    """Resolve an RFC 6901-style pointer used by checked machine evidence."""

    current = value
    if not pointer.startswith("/"):
        raise ComponentIntentError("machine evidence pointer is malformed")
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise ComponentIntentError("machine evidence pointer traverses a scalar")
    return current


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} is not an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} is not an array")
    return value


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} is not a non-empty string")
    return value


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


__all__ = [
    "CExpression",
    "CompletionExpression",
    "STATE_FIELDS",
    "json_pointer",
    "machine_source_expression",
    "render_external_call",
    "result_register",
]
