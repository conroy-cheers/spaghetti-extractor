"""Stable interface for independently cached semantic-component profiles."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .stage_binary import StageAInputError


_PROFILE_NAME = re.compile(r"[a-z][a-z0-9_]*_v[0-9]+")
_PROFILE_PACKAGE = "spaghetti_extractor_component_profiles"


@dataclass(frozen=True)
class ComponentProfileContext:
    component: Mapping[str, Any]
    cluster: Mapping[str, Any]
    units: Sequence[Mapping[str, Any]]
    machine_ir_manifest: Mapping[str, Any]
    machine_ir_sha256: str
    interface_refinement: Mapping[str, Any]
    static_image: Path | None
    component_dependencies: Sequence[Mapping[str, Any]]


@dataclass(frozen=True)
class PreparedComponentProfile:
    portable_symbol: str
    contract_field: str
    contract_filename: str
    contract_hash_binding: str
    contract: Mapping[str, Any]
    activation_domain: Mapping[str, Any]


class ComponentProfile(Protocol):
    name: str

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]: ...

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile: ...

    def install_sources(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        entry_rva: int,
        prepared: PreparedComponentProfile,
    ) -> None: ...

    def install_cases(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        cluster: Mapping[str, Any],
        prepared: PreparedComponentProfile,
    ) -> None: ...

    def render_cbmc_harness(self, refinement: Mapping[str, Any]) -> str: ...

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int: ...

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool: ...


def load_component_profile(name: str) -> ComponentProfile | None:
    """Load an optional profile plugin without broadening the core source closure."""

    if not _PROFILE_NAME.fullmatch(name):
        raise StageAInputError(f"invalid component proof profile name: {name}")
    module_name = f"{_PROFILE_PACKAGE}.{name}"
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as error:
        if error.name in {_PROFILE_PACKAGE, module_name}:
            return None
        raise
    profile = getattr(module, "PROFILE", None)
    if profile is None or getattr(profile, "name", None) != name:
        raise StageAInputError(
            f"component profile plugin {module_name} does not export PROFILE {name}"
        )
    required = (
        "observable_memory",
        "prepare",
        "install_sources",
        "install_cases",
        "render_cbmc_harness",
        "cbmc_unwind",
        "evidence_scope",
        "activation_scope_matches",
    )
    missing = [field for field in required if not callable(getattr(profile, field, None))]
    if missing:
        raise StageAInputError(
            f"component profile plugin {module_name} omits methods: {', '.join(missing)}"
        )
    return profile


def object_value(value: Any, description: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{description} must be an object")
    return value


def array_value(value: Any, description: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{description} must be an array")
    return value


def machine_eflags_sync_lines(indent: str) -> list[str]:
    return [
        "#ifdef STAGE_B_MACHINE_STATE_HAS_EFLAGS",
        f"{indent}state->eflags =",
        f"{indent}    (state->eflags & ~UINT32_C(0x00000cd5)) |",
        f"{indent}    ((state->cf & 1U) << 0) | ((state->pf & 1U) << 2) |",
        f"{indent}    ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |",
        f"{indent}    ((state->df & 1U) << 10) | ((state->of & 1U) << 11);",
        "#endif",
    ]


def render_scalar_piecewise_returns(
    *, contract: Mapping[str, Any], output_path: tuple[str, ...], indent: str
) -> str:
    paths = array_value(contract.get("paths"), "finite scalar paths")
    if not paths:
        raise StageAInputError("finite scalar contract has no paths")
    lines: list[str] = []
    for index, path in enumerate(paths):
        value: Any = path
        for field in output_path:
            value = object_value(value, f"finite scalar path field {field}").get(field)
        expression = render_scalar_expression(value)
        guards = array_value(path.get("guards"), "finite scalar path guards")
        condition = " && ".join(
            f"({render_scalar_expression(guard)} != UINT32_C(0))"
            for guard in guards
        )
        if condition:
            lines.append(f"{indent}if ({condition}) return {expression};")
        else:
            lines.append(f"{indent}return {expression};")
            if index != len(paths) - 1:
                break
    if not any(line.lstrip().startswith("return ") for line in lines):
        final: Any = paths[-1]
        for field in output_path:
            final = object_value(final, f"finite scalar path field {field}").get(field)
        lines.append(f"{indent}return {render_scalar_expression(final)};")
    return "\n".join(lines)


def render_scalar_expression(value: Any) -> str:
    if not isinstance(value, Mapping):
        raise StageAInputError("finite scalar C expression is malformed")
    op = value.get("op")
    if op == "const":
        constant = value.get("value")
        if not isinstance(constant, int):
            raise StageAInputError("finite scalar constant is malformed")
        return f"UINT32_C(0x{constant & 0xFFFFFFFF:08x})"
    if op == "reg":
        if value.get("name") != "component_input":
            raise StageAInputError("finite scalar C expression has an unknown input")
        return "input"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    args = value.get("args")
    if not isinstance(args, list):
        raise StageAInputError(f"finite scalar operation {op!r} has no arguments")
    if op in {"add32", "sub32", "mul32", "xor32", "and32", "or32"}:
        operator = {
            "add32": "+",
            "sub32": "-",
            "mul32": "*",
            "xor32": "^",
            "and32": "&",
            "or32": "|",
        }[str(op)]
        if len(args) < 2:
            raise StageAInputError(f"finite scalar operation {op!r} is malformed")
        return "(" + f" {operator} ".join(render_scalar_expression(arg) for arg in args) + ")"
    if op in {"ult32", "eq", "eq_bool", "xor_bool"} and len(args) == 2:
        left, right = (render_scalar_expression(arg) for arg in args)
        operator = {"ult32": "<", "eq": "==", "eq_bool": "==", "xor_bool": "!="}[str(op)]
        return f"(({left} {operator} {right}) ? UINT32_C(1) : UINT32_C(0))"
    if op == "ite" and len(args) == 3:
        condition, when_true, when_false = (
            render_scalar_expression(arg) for arg in args
        )
        return f"(({condition} != UINT32_C(0)) ? {when_true} : {when_false})"
    if op in {"not32", "neg32"} and len(args) == 1:
        operator = "~" if op == "not32" else "-"
        return f"({operator}{render_scalar_expression(args[0])})"
    if op == "not" and len(args) == 1:
        child = render_scalar_expression(args[0])
        return f"(({child} == UINT32_C(0)) ? UINT32_C(1) : UINT32_C(0))"
    if op in {"and_bool", "or_bool"} and args:
        operator = "&&" if op == "and_bool" else "||"
        rendered = f" {operator} ".join(
            f"({render_scalar_expression(arg)} != UINT32_C(0))" for arg in args
        )
        return f"(({rendered}) ? UINT32_C(1) : UINT32_C(0))"
    if op == "parity" and len(args) == 2 and args[0] == 32:
        return f"semantic_parity({render_scalar_expression(args[1])})"
    if op == "msb" and len(args) == 2 and args[0] == 32:
        return f"({render_scalar_expression(args[1])} >> 31)"
    raise StageAInputError(
        f"finite scalar operation {op!r} is outside the reviewed C subset"
    )


__all__ = [
    "ComponentProfile",
    "ComponentProfileContext",
    "PreparedComponentProfile",
    "array_value",
    "load_component_profile",
    "machine_eflags_sync_lines",
    "object_value",
    "render_scalar_expression",
    "render_scalar_piecewise_returns",
]
