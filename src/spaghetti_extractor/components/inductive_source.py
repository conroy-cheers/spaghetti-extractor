"""Machine-free source protocol for portable inductive operations.

Operators implement logical initialization, one logical step, and completion.
The framework owns the public wrapper loop, so source code never needs x86
state and an operation with several machine SCCs can expose several phases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .interface_ir import (
    ComponentInterfaceIRError,
    ProofKernelComponentInterface,
    ProofKernelOperation,
)


INDUCTIVE_SOURCE_PLAN_V1 = "spaghetti-extractor-inductive-source-plan-v1"

_PORTABLE_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class InductiveSourceError(ValueError):
    """An inductive source plan is malformed or incompatible."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InductiveSourceError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InductiveSourceError(f"{context} must be a nonempty string")
    return value


def _portable_id(value: object, context: str) -> str:
    result = _text(value, context)
    if _PORTABLE_ID.fullmatch(result) is None:
        raise InductiveSourceError(f"{context} is not a portable identifier")
    return result


def _c_identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _C_IDENTIFIER.fullmatch(result) is None:
        raise InductiveSourceError(f"{context} is not a C identifier")
    return result


def _ids(
    value: object, context: str, *, allow_empty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "an array" if allow_empty else "a nonempty array"
        raise InductiveSourceError(f"{context} must be {qualifier}")
    result = tuple(_portable_id(item, context) for item in value)
    if list(result) != sorted(result) or len(result) != len(set(result)):
        raise InductiveSourceError(f"{context} must be ordered and unique")
    return result


@dataclass(frozen=True)
class InductiveStateFieldV1:
    identity: str
    type_id: str

    @classmethod
    def parse(cls, value: object, context: str) -> "InductiveStateFieldV1":
        row = _object(value, {"id", "type_id"}, context)
        return cls(
            _c_identifier(row["id"], f"{context} id"),
            _portable_id(row["type_id"], f"{context} type"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "type_id": self.type_id}


@dataclass(frozen=True)
class InductiveSourceSymbolsV1:
    wrapper: str
    initialize: str
    step: str
    finish: str

    @classmethod
    def parse(cls, value: object) -> "InductiveSourceSymbolsV1":
        row = _object(
            value,
            {"wrapper", "initialize", "step", "finish"},
            "inductive source symbols",
        )
        result = cls(
            _c_identifier(row["wrapper"], "wrapper symbol"),
            _c_identifier(row["initialize"], "initialize symbol"),
            _c_identifier(row["step"], "step symbol"),
            _c_identifier(row["finish"], "finish symbol"),
        )
        if len({result.wrapper, result.initialize, result.step, result.finish}) != 4:
            raise InductiveSourceError("inductive source symbols must be unique")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "wrapper": self.wrapper,
            "initialize": self.initialize,
            "step": self.step,
            "finish": self.finish,
        }


@dataclass(frozen=True)
class InductiveSourcePlanV1:
    interface_id: str
    interface_sha256: str
    operation_id: str
    state: tuple[InductiveStateFieldV1, ...]
    phase_ids: tuple[str, ...]
    completion_ids: tuple[str, ...]
    symbols: InductiveSourceSymbolsV1
    plan_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InductiveSourcePlanV1":
        row = _object(
            value,
            {
                "format",
                "interface_id",
                "interface_sha256",
                "operation_id",
                "state",
                "phase_ids",
                "completion_ids",
                "symbols",
                "plan_sha256",
            },
            "inductive source plan",
        )
        if row["format"] != INDUCTIVE_SOURCE_PLAN_V1:
            raise InductiveSourceError("unsupported inductive source-plan format")
        raw_state = row["state"]
        if not isinstance(raw_state, list):
            raise InductiveSourceError("inductive source state must be an array")
        state = tuple(
            InductiveStateFieldV1.parse(item, f"inductive state field {index}")
            for index, item in enumerate(raw_state)
        )
        state_ids = [item.identity for item in state]
        if state_ids != sorted(state_ids) or len(state_ids) != len(set(state_ids)):
            raise InductiveSourceError(
                "inductive state fields must use deterministic unique ordering"
            )
        digest = _text(row["plan_sha256"], "inductive source-plan digest")
        if _DIGEST.fullmatch(digest) is None:
            raise InductiveSourceError(
                "inductive source-plan digest must be a SHA-256 digest"
            )
        core = dict(row)
        core.pop("plan_sha256")
        if canonical_sha256_v3(core) != digest:
            raise InductiveSourceError("inductive source-plan digest is stale")
        return cls(
            _portable_id(row["interface_id"], "source-plan interface id"),
            _digest(row["interface_sha256"], "source-plan interface digest"),
            _portable_id(row["operation_id"], "source-plan operation id"),
            state,
            _ids(row["phase_ids"], "inductive phase ids", allow_empty=True),
            _ids(row["completion_ids"], "inductive completion ids"),
            InductiveSourceSymbolsV1.parse(row["symbols"]),
            digest,
        )

    @classmethod
    def create(
        cls,
        *,
        interface: ProofKernelComponentInterface,
        operation_id: str,
        state: Sequence[Mapping[str, object]],
        phase_ids: Sequence[str],
        completion_ids: Sequence[str],
        symbols: Mapping[str, object],
    ) -> "InductiveSourcePlanV1":
        core: dict[str, object] = {
            "format": INDUCTIVE_SOURCE_PLAN_V1,
            "interface_id": interface.identity,
            "interface_sha256": interface.sha256,
            "operation_id": operation_id,
            "state": list(state),
            "phase_ids": list(phase_ids),
            "completion_ids": list(completion_ids),
            "symbols": dict(symbols),
        }
        return cls.parse(
            {**core, "plan_sha256": canonical_sha256_v3(core)}
        )

    def to_payload(self) -> dict[str, object]:
        core: dict[str, object] = {
            "format": INDUCTIVE_SOURCE_PLAN_V1,
            "interface_id": self.interface_id,
            "interface_sha256": self.interface_sha256,
            "operation_id": self.operation_id,
            "state": [item.to_payload() for item in self.state],
            "phase_ids": list(self.phase_ids),
            "completion_ids": list(self.completion_ids),
            "symbols": self.symbols.to_payload(),
        }
        return {**core, "plan_sha256": self.plan_sha256}

    def validate_for(
        self,
        interface: ProofKernelComponentInterface,
        operation_symbols: Mapping[str, object],
    ) -> ProofKernelOperation:
        if self.interface_id != interface.identity or self.interface_sha256 != interface.sha256:
            raise InductiveSourceError(
                "inductive source plan is bound to a different interface"
            )
        try:
            operation = interface.operation_index()[self.operation_id]
        except KeyError as exc:
            raise InductiveSourceError(
                f"inductive source plan references unknown operation {self.operation_id!r}"
            ) from exc
        symbols = interface.validate_operation_symbols(operation_symbols)
        if symbols[self.operation_id] != self.symbols.wrapper:
            raise InductiveSourceError(
                "inductive wrapper differs from the configured public operation symbol"
            )
        type_index = interface.type_index()
        for field in self.state:
            logical_type = type_index.get(field.type_id)
            if logical_type is None:
                raise InductiveSourceError(
                    f"inductive state field {field.identity!r} has unknown type"
                )
            if logical_type.kind not in {"scalar", "enum", "resource"}:
                raise InductiveSourceError(
                    f"inductive state field {field.identity!r} is not a scalar value"
                )
        return operation

    def render_header(
        self,
        interface: ProofKernelComponentInterface,
        operation_symbols: Mapping[str, object],
        *,
        implementation_header: str = "portable-component-implementation.h",
    ) -> str:
        operation = self.validate_for(interface, operation_symbols)
        prefix = _prefix(interface.identity, operation.identity)
        guard = f"{prefix.upper()}_INDUCTIVE_SOURCE_V1_H"
        state_type = f"{prefix}_state_v1"
        control_type = f"{prefix}_control_v1"
        parameters = interface.operation_c_parameters(operation)
        parameter_declarations = _parameter_declarations(parameters)
        parameter_names = _parameter_names(parameters)
        state_parameters = _join_arguments(
            [f"{state_type} *state", *parameter_declarations]
        )
        finish_parameters = _join_arguments(
            [
                f"const {state_type} *state",
                "uint32_t completion_id",
                *parameter_declarations,
            ]
        )
        lines = [
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            f'#include "{implementation_header}"',
            "",
            "enum {",
            f"  {prefix.upper()}_CONTROL_RUNNING = 0u,",
            f"  {prefix.upper()}_CONTROL_COMPLETE = 1u",
            "};",
            "",
        ]
        for index, phase_id in enumerate(self.phase_ids):
            lines.append(
                f"#define {prefix.upper()}_PHASE_{_macro(phase_id)} {index}u"
            )
        for index, completion_id in enumerate(self.completion_ids):
            lines.append(
                f"#define {prefix.upper()}_COMPLETION_{_macro(completion_id)} {index}u"
            )
        lines.extend(
            [
                "",
                f"typedef struct {state_type} {{",
                *(
                    f"  {interface.logical_c_value_type(field.type_id)} {field.identity};"
                    for field in self.state
                ),
                *(() if self.state else ("  uint8_t reserved;",)),
                f"}} {state_type};",
                "",
                f"typedef struct {control_type} {{",
                "  uint32_t kind;",
                "  uint32_t phase_id;",
                "  uint32_t completion_id;",
                f"}} {control_type};",
                "",
                f"{control_type} {self.symbols.initialize}({state_parameters});",
                f"{control_type} {self.symbols.step}({_join_arguments([f'{state_type} *state', 'uint32_t phase_id', *parameter_declarations])});",
                f"{interface.operation_c_result(operation)} {self.symbols.finish}({finish_parameters});",
                "",
                f"#endif /* {guard} */",
                "",
            ]
        )
        del parameter_names
        return "\n".join(lines)

    def render_wrapper(
        self,
        interface: ProofKernelComponentInterface,
        operation_symbols: Mapping[str, object],
        *,
        header: str,
    ) -> str:
        operation = self.validate_for(interface, operation_symbols)
        prefix = _prefix(interface.identity, operation.identity)
        state_type = f"{prefix}_state_v1"
        control_type = f"{prefix}_control_v1"
        parameters = interface.operation_c_parameters(operation)
        declarations = _join_arguments(_parameter_declarations(parameters))
        names = _parameter_names(parameters)
        forwarded = _join_arguments(["&state", *names])
        step_forwarded = _join_arguments(["&state", "control.phase_id", *names])
        finish_forwarded = _join_arguments(
            ["&state", "control.completion_id", *names]
        )
        result_type = interface.operation_c_result(operation)
        lines = [
            f'#include "{header}"',
            "",
            f"{result_type} {self.symbols.wrapper}({declarations}) {{",
            f"  {state_type} state = {{0}};",
            f"  {control_type} control = {self.symbols.initialize}({forwarded});",
            "  for (;;) {",
            f"    if (control.kind == {prefix.upper()}_CONTROL_COMPLETE) {{",
        ]
        if result_type == "void":
            lines.extend(
                [
                    f"      {self.symbols.finish}({finish_forwarded});",
                    "      return;",
                ]
            )
        else:
            lines.append(f"      return {self.symbols.finish}({finish_forwarded});")
        lines.extend(
            [
                "    }",
                f"    if (control.kind != {prefix.upper()}_CONTROL_RUNNING",
                f"        || control.phase_id >= {len(self.phase_ids)}u) {{",
                "      for (;;) { }",
                "    }",
                f"    control = {self.symbols.step}({step_forwarded});",
                "  }",
                "}",
                "",
            ]
        )
        return "\n".join(lines)


def validate_inductive_source_plans(
    plans: Sequence[InductiveSourcePlanV1],
    interface: ProofKernelComponentInterface,
    operation_symbols: Mapping[str, object],
) -> tuple[InductiveSourcePlanV1, ...]:
    parsed = tuple(plans)
    operation_ids = [item.operation_id for item in parsed]
    if operation_ids != sorted(operation_ids) or len(operation_ids) != len(set(operation_ids)):
        raise InductiveSourceError(
            "inductive source plans must use deterministic unique operation ordering"
        )
    helper_symbols: set[str] = set()
    public_symbols = set(interface.validate_operation_symbols(operation_symbols).values())
    for plan in parsed:
        plan.validate_for(interface, operation_symbols)
        helpers = {
            plan.symbols.initialize,
            plan.symbols.step,
            plan.symbols.finish,
        }
        if helpers & public_symbols or helpers & helper_symbols:
            raise InductiveSourceError("inductive helper symbols collide")
        helper_symbols |= helpers
    return parsed


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise InductiveSourceError(f"{context} must be a SHA-256 digest")
    return result


def _prefix(interface_id: str, operation_id: str) -> str:
    return f"spx_{_c_fragment(interface_id)}_{_c_fragment(operation_id)}"


def _c_fragment(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", value)


def _macro(value: str) -> str:
    return _c_fragment(value).upper()


def _parameter_declarations(
    parameters: Sequence[tuple[str, str]],
) -> list[str]:
    return [f"{type_name} {name}" for type_name, name in parameters]


def _parameter_names(parameters: Sequence[tuple[str, str]]) -> list[str]:
    return [name for _type_name, name in parameters]


def _join_arguments(arguments: Sequence[str]) -> str:
    return ", ".join(arguments) if arguments else "void"


__all__ = [
    "INDUCTIVE_SOURCE_PLAN_V1",
    "InductiveSourceError",
    "InductiveSourcePlanV1",
    "InductiveSourceSymbolsV1",
    "InductiveStateFieldV1",
    "validate_inductive_source_plans",
]
