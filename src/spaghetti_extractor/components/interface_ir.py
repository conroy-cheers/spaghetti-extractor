"""Private logical model used only by the checked component proof kernel.

The deployable interface is PortableComponentInterfaceV5.  This module has no
public artifact codec: V5 data is projected into this formatless model in
memory solely to reuse the independently checked CBMC obligations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import CanonicalValueV3, canonical_sha256_v3
from .atomics import ATOMIC_OBJECT_RESOURCE_KIND, interface_uses_atomics


_PROOF_KERNEL_MODEL = "private-proof-kernel"
_RETIRED_INTERFACE_FORMAT = object()
SCALAR_TYPES = frozenset(
    {
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
    }
)
ACCESS_MODES = frozenset({"read", "write", "read_write"})
RESOURCE_OWNERSHIP = frozenset(
    {"borrowed", "created", "retained", "released", "transferred"}
)
SERVICE_EFFECT_KINDS = frozenset(
    {"memory", "resource", "callback", "observable", "control"}
)
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_V2_FORBIDDEN_FIELDS = frozenset(
    {
        "external_id",
        "external_ids",
        "lift_unit_id",
        "machine_projection",
        "machine_projections",
        "machine_ref",
        "machine_refs",
        "operation_identity",
        "unit_id",
        "unit_ids",
    }
)


class ComponentInterfaceIRError(ValueError):
    """A portable component interface is malformed or non-representable."""


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentInterfaceIRError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ComponentInterfaceIRError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentInterfaceIRError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ComponentInterfaceIRError(f"{context} is not a portable identifier")
    return result


def _exact(row: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(row) != fields:
        raise ComponentInterfaceIRError(
            f"{context} fields differ: missing={sorted(fields-set(row))!r}, "
            f"extra={sorted(set(row)-fields)!r}"
        )


@dataclass(frozen=True)
class ProofKernelLogicalField:
    identity: str
    type_id: str


@dataclass(frozen=True)
class ProofKernelLogicalType:
    identity: str
    kind: str
    c_type: str | None = None
    access: str | None = None
    extent_parameter_id: str | None = None
    nul_terminated: bool = False
    fields: tuple[ProofKernelLogicalField, ...] = ()
    resource_kind: str | None = None
    ownership: str | None = None
    abi: str | None = None
    parameter_type_ids: tuple[str, ...] = ()
    result_type_id: str | None = None
    nullable: bool | None = None
    element_type_id: str | None = None
    extent_kind: str | None = None
    fixed_extent: int | None = None
    allow_one_past: bool | None = None
    lifetime: str | None = None



@dataclass(frozen=True)
class ProofKernelLogicalValue:
    identity: str
    type_id: str


@dataclass(frozen=True)
class ProofKernelStateField:
    identity: str
    type_id: str
    initial_value: CanonicalValueV3


@dataclass(frozen=True)
class ProofKernelOperation:
    identity: str
    kind: str
    parameters: tuple[ProofKernelLogicalValue, ...]
    results: tuple[ProofKernelLogicalValue, ...]
    effect_ids: tuple[str, ...]
    allowed_service_ids: tuple[str, ...]
    pre_states: tuple[str, ...]
    post_states: tuple[str, ...]


@dataclass(frozen=True)
class ProofKernelEffect:
    identity: str
    kind: str
    target_id: str | None
    operation: str


@dataclass(frozen=True)
class ProofKernelService:
    identity: str
    parameter_type_ids: tuple[str, ...]
    result_type_id: str | None
    effect_ids: tuple[str, ...]


@dataclass(frozen=True)
class ProofKernelProtocolTransition:
    operation_id: str
    from_state: str
    to_state: str


@dataclass(frozen=True)
class ProofKernelComponentInterface:
    """Machine-free internal model with framework-managed instance state."""

    format_version: str
    identity: str
    types: tuple[ProofKernelLogicalType, ...]
    state: tuple[ProofKernelStateField, ...]
    operations: tuple[ProofKernelOperation, ...]
    effects: tuple[ProofKernelEffect, ...]
    services: tuple[ProofKernelService, ...]
    protocol_states: tuple[str, ...]
    initial_protocol_state: str

    @classmethod
    def parse(cls, value: object) -> "ProofKernelComponentInterface":
        _reject_proof_kernel_machine_fields(value)
        root = _object(value, "component proof-kernel interface")
        _exact(
            root,
            {
                "id",
                "types",
                "state",
                "operations",
                "effects",
                "services",
                "protocol",
            },
            "component proof-kernel interface",
        )
        protocol = _object(root["protocol"], "portable interface protocol")
        _exact(
            protocol,
            {"states", "initial_state"},
            "portable interface protocol",
        )
        result = cls(
            format_version=_PROOF_KERNEL_MODEL,
            identity=_identifier(root["id"], "interface id"),
            types=tuple(
                _parse_type(item, index)
                for index, item in enumerate(_array(root["types"], "interface types"))
            ),
            state=tuple(
                _parse_state_field(item, index)
                for index, item in enumerate(
                    _array(root["state"], "interface state fields")
                )
            ),
            operations=tuple(
                _parse_operation_v2(item, index)
                for index, item in enumerate(
                    _array(root["operations"], "interface operations")
                )
            ),
            effects=tuple(
                _parse_effect_v2(item, index)
                for index, item in enumerate(
                    _array(root["effects"], "interface effects")
                )
            ),
            services=tuple(
                _parse_service_v2(item, index)
                for index, item in enumerate(
                    _array(root["services"], "interface services")
                )
            ),
            protocol_states=tuple(
                _identifier(item, "protocol state")
                for item in _array(protocol["states"], "protocol states")
            ),
            initial_protocol_state=_identifier(
                protocol["initial_state"], "initial protocol state"
            ),
        )
        result.validate()
        return result

    def validate(self) -> None:
        type_ids = _unique((row.identity for row in self.types), "logical type")
        state_ids = _unique((row.identity for row in self.state), "state field")
        operation_ids = _unique(
            (row.identity for row in self.operations), "portable operation"
        )
        effect_ids = _unique((row.identity for row in self.effects), "interface effect")
        service_ids = _unique(
            (row.identity for row in self.services), "service dependency"
        )
        protocol_states = _unique(self.protocol_states, "protocol state")
        if not self.operations:
            raise ComponentInterfaceIRError(
                "portable component interface requires at least one operation"
            )
        if not protocol_states:
            raise ComponentInterfaceIRError(
                "portable component interface requires protocol states"
            )
        if self.initial_protocol_state not in protocol_states:
            raise ComponentInterfaceIRError("initial protocol state is unknown")

        for logical_type in self.types:
            references = [field.type_id for field in logical_type.fields]
            references.extend(logical_type.parameter_type_ids)
            if logical_type.element_type_id is not None:
                references.append(logical_type.element_type_id)
            if logical_type.result_type_id is not None:
                references.append(logical_type.result_type_id)
            for reference in references:
                if reference not in type_ids:
                    raise ComponentInterfaceIRError(
                        f"logical type {logical_type.identity!r} references unknown type {reference!r}"
                    )
        type_index = self.type_index()
        _validate_record_type_graph(type_index)
        for logical_type in self.types:
            if logical_type.element_type_id is None:
                continue
            element = type_index[logical_type.element_type_id]
            if element.kind in {"resource", "callback", "view", "reference"}:
                raise ComponentInterfaceIRError(
                    f"logical type {logical_type.identity!r} has a non-addressable element type"
                )
        for field in self.state:
            if field.type_id not in type_ids:
                raise ComponentInterfaceIRError(
                    f"state field {field.identity!r} references unknown type {field.type_id!r}"
                )
            _validate_portable_value(
                field.initial_value.to_value(),
                type_index[field.type_id],
                type_index,
                f"state field {field.identity!r} initial value",
            )

        operation_value_ids: set[str] = set()
        for operation in self.operations:
            _unique(operation.effect_ids, f"operation {operation.identity} effect")
            _unique(
                operation.allowed_service_ids,
                f"operation {operation.identity} allowed service",
            )
            _unique(operation.pre_states, f"operation {operation.identity} pre-state")
            _unique(
                operation.post_states, f"operation {operation.identity} post-state"
            )
            _unique(
                (row.identity for row in operation.parameters),
                f"operation {operation.identity} parameter",
            )
            _unique(
                (row.identity for row in operation.results),
                f"operation {operation.identity} result",
            )
            overlap = {
                row.identity for row in operation.parameters
            } & {row.identity for row in operation.results}
            if overlap:
                raise ComponentInterfaceIRError(
                    f"operation {operation.identity!r} parameter/result ids overlap"
                )
            parameter_ids = {row.identity for row in operation.parameters}
            for value in operation.parameters + operation.results:
                operation_value_ids.add(value.identity)
                if value.type_id not in type_ids:
                    raise ComponentInterfaceIRError(
                        f"operation {operation.identity!r} references unknown type {value.type_id!r}"
                    )
                for bytes_type in _reachable_bytes_types(
                    type_index[value.type_id], type_index
                ):
                    extent_id = bytes_type.extent_parameter_id
                    if extent_id is not None and extent_id not in parameter_ids:
                        raise ComponentInterfaceIRError(
                            f"operation {operation.identity!r} uses bytes type "
                            f"{bytes_type.identity!r} without its operation-local "
                            f"extent parameter {extent_id!r}"
                        )
            missing_effects = set(operation.effect_ids) - effect_ids
            if missing_effects:
                raise ComponentInterfaceIRError(
                    f"operation {operation.identity!r} references unknown effects {sorted(missing_effects)!r}"
                )
            missing_services = set(operation.allowed_service_ids) - service_ids
            if missing_services:
                raise ComponentInterfaceIRError(
                    f"operation {operation.identity!r} references unknown services {sorted(missing_services)!r}"
                )
            if not operation.pre_states or not operation.post_states:
                raise ComponentInterfaceIRError(
                    f"operation {operation.identity!r} requires pre_states and post_states"
                )
            missing_states = (
                set(operation.pre_states) | set(operation.post_states)
            ) - protocol_states
            if missing_states:
                raise ComponentInterfaceIRError(
                    f"operation {operation.identity!r} references unknown protocol states {sorted(missing_states)!r}"
                )

        valid_targets = state_ids | operation_value_ids
        for effect in self.effects:
            if effect.target_id is not None and effect.target_id not in valid_targets:
                raise ComponentInterfaceIRError(
                    f"effect {effect.identity!r} references unknown portable value"
                )
        for service in self.services:
            for reference in service.parameter_type_ids:
                if reference not in type_ids:
                    raise ComponentInterfaceIRError(
                        f"service {service.identity!r} references unknown parameter type"
                    )
            if service.result_type_id is not None and service.result_type_id not in type_ids:
                raise ComponentInterfaceIRError(
                    f"service {service.identity!r} references unknown result type"
                )
            missing_effects = set(service.effect_ids) - effect_ids
            if missing_effects:
                raise ComponentInterfaceIRError(
                    f"service {service.identity!r} references unknown effects {sorted(missing_effects)!r}"
                )

    def type_index(self) -> dict[str, ProofKernelLogicalType]:
        return {row.identity: row for row in self.types}

    def operation_index(self) -> dict[str, ProofKernelOperation]:
        return {row.identity: row for row in self.operations}

    @property
    def protocol_transitions(self) -> tuple[ProofKernelProtocolTransition, ...]:
        return tuple(
            ProofKernelProtocolTransition(operation.identity, before, after)
            for operation in self.operations
            for before in operation.pre_states
            for after in operation.post_states
        )

    def validate_operation_symbols(
        self, operation_symbols: Mapping[str, object]
    ) -> dict[str, str]:
        if set(operation_symbols) != {row.identity for row in self.operations}:
            raise ComponentInterfaceIRError(
                "operation symbol bindings do not exactly match interface operations"
            )
        result: dict[str, str] = {}
        for operation_id, raw_symbol in operation_symbols.items():
            if not isinstance(raw_symbol, str) or _C_IDENTIFIER.fullmatch(raw_symbol) is None:
                raise ComponentInterfaceIRError(
                    f"operation {operation_id!r} symbol is not a C identifier"
                )
            result[operation_id] = raw_symbol
        if len(set(result.values())) != len(result):
            raise ComponentInterfaceIRError("operation symbols must be unique")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "types": [_type_payload(row) for row in self.types],
            "state": [
                {
                    "id": row.identity,
                    "type_id": row.type_id,
                    "initial": row.initial_value.to_value(),
                }
                for row in self.state
            ],
            "operations": [
                {
                    "id": row.identity,
                    "kind": row.kind,
                    "parameters": [_value_payload_v2(value) for value in row.parameters],
                    "results": [_value_payload_v2(value) for value in row.results],
                    "effect_ids": list(row.effect_ids),
                    "allowed_service_ids": list(row.allowed_service_ids),
                    "pre_states": list(row.pre_states),
                    "post_states": list(row.post_states),
                }
                for row in self.operations
            ],
            "effects": [
                {
                    "id": row.identity,
                    "kind": row.kind,
                    "target_id": row.target_id,
                    "operation": row.operation,
                }
                for row in self.effects
            ],
            "services": [
                {
                    "id": row.identity,
                    "parameter_type_ids": list(row.parameter_type_ids),
                    "result_type_id": row.result_type_id,
                    "effect_ids": list(row.effect_ids),
                }
                for row in self.services
            ],
            "protocol": {
                "states": list(self.protocol_states),
                "initial_state": self.initial_protocol_state,
            },
        }

    @property
    def sha256(self) -> str:
        return canonical_sha256_v3(self.to_payload())

    def render_public_header(self) -> str:
        """Render the architecture-independent framework-facing C header."""

        guard = f"SPX_COMPONENT_{self.identity.upper()}_PUBLIC_V2_H"
        context_type = f"spx_{self.identity}_context_v2"
        lines = [
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            "#include <stdint.h>",
            *(['#include "spx-atomics.h"'] if interface_uses_atomics(self.types) else []),
            "",
            "typedef struct spx_resource_v2 {",
            "  uint32_t type_tag;",
            "  uint32_t generation;",
            "  uint64_t identity;",
            "} spx_resource_v2;",
            "typedef struct {",
            "  void *context;",
            "  uint32_t extent;",
            "  uint32_t (*read_u8)(void *, uint32_t, uint8_t *);",
            "  uint32_t (*write_u8)(void *, uint32_t, uint8_t);",
            "} spx_bytes_view_v2;",
            "",
        ]
        lines.extend(
            [
                    "typedef struct {",
                    "  uint64_t domain;",
                    "  uint64_t object;",
                    "  uint64_t generation;",
                    "  uint64_t offset;",
                    "  uint64_t extent;",
                    "  uint32_t permissions;",
                    "} spx_ref_v1;",
                    "#define SPX_REF_V1_DEFINED 1",
                    "typedef struct {",
                    "  spx_ref_v1 base;",
                    "  uint64_t extent;",
                    "  uint32_t element_width;",
                    "  void *access_context;",
                    "  uint32_t (*read)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t *);",
                    "  uint32_t (*write)(void *, spx_ref_v1, uint64_t, uint32_t, uint64_t);",
                    "} spx_view_v1;",
                    "#define SPX_VIEW_V1_DEFINED 1",
                    '#include "spx-reference-runtime.h"',
                    "",
            ]
        )
        index = self.type_index()
        for logical_type in self.types:
            lines.extend(_render_type_v2(logical_type, index))

        service_type = f"spx_{self.identity}_services_v2"
        lines.append(f"typedef struct {service_type} {{")
        lines.append("  void *context;")
        for service in self.services:
            parameters = ["void *context"] + [
                f"{_c_type_v2(index[type_id])} argument_{position}"
                for position, type_id in enumerate(service.parameter_type_ids)
            ]
            result = (
                "void"
                if service.result_type_id is None
                else _c_value_type_v2(index[service.result_type_id])
            )
            lines.append(
                f"  {result} (*{service.identity})({', '.join(parameters)});"
            )
        lines.extend([f"}} {service_type};", ""])
        lines.extend(
            [
                f"typedef struct {context_type} {context_type};",
                "",
                f"typedef enum spx_{self.identity}_protocol_state_v2 {{",
            ]
        )
        for position, state in enumerate(self.protocol_states):
            lines.append(
                f"  SPX_{self.identity.upper()}_PROTOCOL_{state.upper()} = {position}"
                + ("," if position + 1 < len(self.protocol_states) else "")
            )
        lines.extend(
            [
                f"}} spx_{self.identity}_protocol_state_v2;",
                "",
            ]
        )
        for operation in self.operations:
            lines.extend(self._render_operation_result(operation, index))
            result = self.operation_c_result(operation)
            parameters = [f"{context_type} *context"] + [
                f"{_c_type_v2(index[value.type_id])} {value.identity}"
                for value in operation.parameters
            ]
            lines.extend(
                [
                    f"typedef {result} (*spx_{self.identity}_{operation.identity}_fn_v2)"
                    f"({', '.join(parameters)});",
                    "",
                ]
            )
        lines.extend([f"#endif /* {guard} */", ""])
        return "\n".join(lines)

    def render_public_c_header(self) -> str:
        return self.render_public_header()

    def render_implementation_header(
        self,
        operation_symbols: Mapping[str, object],
        *,
        public_header: str = "portable-component.h",
    ) -> str:
        """Render source declarations for the exact configured operation symbols."""

        symbols = self.validate_operation_symbols(operation_symbols)
        include_name = PurePath(public_header).name
        guard = f"SPX_COMPONENT_{self.identity.upper()}_IMPLEMENTATION_V2_H"
        context_type = f"spx_{self.identity}_context_v2"
        index = self.type_index()
        lines = [
            f"#ifndef {guard}",
            f"#define {guard}",
            "",
            f'#include "{include_name}"',
            "",
            f"struct {context_type} {{",
            f"  const spx_{self.identity}_services_v2 *services;",
            "  struct {",
        ]
        if self.state:
            lines.extend(
                f"    {_c_value_type_v2(index[field.type_id])} {field.identity};"
                for field in self.state
            )
        else:
            lines.append("    uint8_t reserved;")
        lines.extend(
            [
                "  } state;",
                f"  spx_{self.identity}_protocol_state_v2 protocol_state;",
                "};",
                "",
            ]
        )
        for operation in self.operations:
            parameters = [f"{context_type} *context"] + [
                f"{_c_type_v2(index[value.type_id])} {value.identity}"
                for value in operation.parameters
            ]
            lines.extend(
                [
                    f"{self.operation_c_result(operation)} {symbols[operation.identity]}"
                    f"({', '.join(parameters)});",
                    "",
                ]
            )
        lines.extend([f"#endif /* {guard} */", ""])
        return "\n".join(lines)

    def render_implementation_c_header(
        self,
        operation_symbols: Mapping[str, object],
        *,
        public_header: str = "portable-component.h",
    ) -> str:
        return self.render_implementation_header(
            operation_symbols, public_header=public_header
        )

    def render_conformance_translation_unit(
        self,
        operation_symbols: Mapping[str, object],
        *,
        implementation_header: str = "portable-component-implementation.h",
    ) -> str:
        symbols = self.validate_operation_symbols(operation_symbols)
        include_name = PurePath(implementation_header).name
        lines = [f'#include "{include_name}"', ""]
        for operation in self.operations:
            lines.append(
                f"spx_{self.identity}_{operation.identity}_fn_v2 const "
                f"spx_conformance_{operation.identity}_v2 = {symbols[operation.identity]};"
            )
        lines.append("")
        return "\n".join(lines)

    def operation_c_result(self, operation: ProofKernelOperation) -> str:
        index = self.type_index()
        if not operation.results:
            return "void"
        if len(operation.results) == 1:
            return _c_value_type_v2(index[operation.results[0].type_id])
        return f"spx_{self.identity}_{operation.identity}_result_v2"

    def logical_c_type(self, type_id: str) -> str:
        """Return the parameter spelling for one declared logical type."""

        try:
            logical_type = self.type_index()[type_id]
        except KeyError as exc:
            raise ComponentInterfaceIRError(
                f"unknown logical type {type_id!r}"
            ) from exc
        return _c_type_v2(logical_type)

    def logical_c_value_type(self, type_id: str) -> str:
        """Return the by-value spelling for one declared logical type."""

        try:
            logical_type = self.type_index()[type_id]
        except KeyError as exc:
            raise ComponentInterfaceIRError(
                f"unknown logical type {type_id!r}"
            ) from exc
        return _c_value_type_v2(logical_type)

    def operation_c_parameters(
        self,
        operation: ProofKernelOperation,
        *,
        include_context: bool = True,
    ) -> tuple[tuple[str, str], ...]:
        """Return stable C parameter type/name pairs for generated adapters."""

        rows: list[tuple[str, str]] = []
        if include_context:
            rows.append((f"spx_{self.identity}_context_v2 *", "context"))
        rows.extend(
            (self.logical_c_type(value.type_id), value.identity)
            for value in operation.parameters
        )
        return tuple(rows)

    def _render_operation_result(
        self,
        operation: ProofKernelOperation,
        index: Mapping[str, ProofKernelLogicalType],
    ) -> list[str]:
        if len(operation.results) <= 1:
            return []
        result_name = f"spx_{self.identity}_{operation.identity}_result_v2"
        lines = [f"typedef struct {result_name} {{"]
        lines.extend(
            f"  {_c_value_type_v2(index[value.type_id])} {value.identity};"
            for value in operation.results
        )
        lines.extend([f"}} {result_name};", ""])
        return lines


def _reject_proof_kernel_machine_fields(value: object, context: str = "interface") -> None:
    if isinstance(value, Mapping):
        forbidden = sorted(set(value) & _V2_FORBIDDEN_FIELDS)
        if forbidden:
            raise ComponentInterfaceIRError(
                f"portable interface V2 cannot contain machine, unit, or external fields: {forbidden!r}"
            )
        for key, item in value.items():
            _reject_proof_kernel_machine_fields(item, f"{context}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_proof_kernel_machine_fields(item, f"{context}[{index}]")


def _parse_value_v2(value: object, context: str) -> ProofKernelLogicalValue:
    row = _object(value, context)
    _exact(row, {"id", "type_id"}, context)
    return ProofKernelLogicalValue(
        _identifier(row["id"], f"{context} id"),
        _identifier(row["type_id"], f"{context} type"),
    )


def _parse_state_field(value: object, index: int) -> ProofKernelStateField:
    row = _object(value, f"state field {index}")
    _exact(row, {"id", "type_id", "initial"}, f"state field {index}")
    return ProofKernelStateField(
        _identifier(row["id"], f"state field {index} id"),
        _identifier(row["type_id"], f"state field {index} type"),
        CanonicalValueV3.of(row["initial"]),
    )


def _parse_operation_v2(value: object, index: int) -> ProofKernelOperation:
    row = _object(value, f"portable operation {index}")
    _exact(
        row,
        {
            "id",
            "kind",
            "parameters",
            "results",
            "effect_ids",
            "allowed_service_ids",
            "pre_states",
            "post_states",
        },
        f"portable operation {index}",
    )
    kind = _text(row["kind"], f"portable operation {index} kind")
    if kind not in {"operation", "callback"}:
        raise ComponentInterfaceIRError(
            f"unsupported portable operation kind {kind!r}"
        )
    identity = _identifier(row["id"], f"portable operation {index} id")
    return ProofKernelOperation(
        identity=identity,
        kind=kind,
        parameters=tuple(
            _parse_value_v2(item, f"operation {identity} parameter {position}")
            for position, item in enumerate(
                _array(row["parameters"], f"operation {identity} parameters")
            )
        ),
        results=tuple(
            _parse_value_v2(item, f"operation {identity} result {position}")
            for position, item in enumerate(
                _array(row["results"], f"operation {identity} results")
            )
        ),
        effect_ids=tuple(
            _identifier(item, f"operation {identity} effect")
            for item in _array(row["effect_ids"], f"operation {identity} effects")
        ),
        allowed_service_ids=tuple(
            _identifier(item, f"operation {identity} allowed service")
            for item in _array(
                row["allowed_service_ids"],
                f"operation {identity} allowed services",
            )
        ),
        pre_states=tuple(
            _identifier(item, f"operation {identity} pre-state")
            for item in _array(row["pre_states"], f"operation {identity} pre-states")
        ),
        post_states=tuple(
            _identifier(item, f"operation {identity} post-state")
            for item in _array(
                row["post_states"], f"operation {identity} post-states"
            )
        ),
    )


def _parse_effect_v2(value: object, index: int) -> ProofKernelEffect:
    row = _object(value, f"interface effect {index}")
    _exact(
        row,
        {"id", "kind", "target_id", "operation"},
        f"interface effect {index}",
    )
    kind = _text(row["kind"], f"interface effect {index} kind")
    if kind not in SERVICE_EFFECT_KINDS:
        raise ComponentInterfaceIRError(f"unsupported interface effect kind {kind!r}")
    target = row["target_id"]
    return ProofKernelEffect(
        identity=_identifier(row["id"], f"interface effect {index} id"),
        kind=kind,
        target_id=(
            None if target is None else _identifier(target, "interface effect target")
        ),
        operation=_identifier(
            row["operation"], f"interface effect {index} operation"
        ),
    )


def _parse_service_v2(value: object, index: int) -> ProofKernelService:
    row = _object(value, f"service dependency {index}")
    _exact(
        row,
        {"id", "parameter_type_ids", "result_type_id", "effect_ids"},
        f"service dependency {index}",
    )
    result_type = row["result_type_id"]
    return ProofKernelService(
        identity=_identifier(row["id"], f"service dependency {index} id"),
        parameter_type_ids=tuple(
            _identifier(item, f"service dependency {index} parameter type")
            for item in _array(
                row["parameter_type_ids"], f"service dependency {index} parameters"
            )
        ),
        result_type_id=(
            None
            if result_type is None
            else _identifier(result_type, f"service dependency {index} result type")
        ),
        effect_ids=tuple(
            _identifier(item, f"service dependency {index} effect")
            for item in _array(
                row["effect_ids"], f"service dependency {index} effects"
            )
        ),
    )


def _value_payload_v2(value: ProofKernelLogicalValue) -> dict[str, str]:
    return {"id": value.identity, "type_id": value.type_id}


def _unique(values: Sequence[str] | Any, context: str) -> set[str]:
    rows = list(values)
    if len(rows) != len(set(rows)):
        raise ComponentInterfaceIRError(f"{context} ids must be unique")
    return set(rows)


def _validate_record_type_graph(types: Mapping[str, ProofKernelLogicalType]) -> None:
    """Reject recursive by-value records before rendering or projection checks.

    Portable records are emitted as ordinary C values.  A recursive record
    would require an explicit pointer/reference type, which this IR does not
    currently expose, so accepting one would make the interface impossible to
    realize faithfully.
    """

    visiting: list[str] = []
    complete: set[str] = set()

    def visit(type_id: str) -> None:
        logical_type = types[type_id]
        if logical_type.kind != "record" or type_id in complete:
            return
        if type_id in visiting:
            cycle = visiting[visiting.index(type_id) :] + [type_id]
            raise ComponentInterfaceIRError(
                "portable record graph contains a by-value cycle: "
                + " -> ".join(cycle)
            )
        visiting.append(type_id)
        for field in logical_type.fields:
            visit(field.type_id)
        visiting.pop()
        complete.add(type_id)

    for type_id in sorted(types):
        visit(type_id)


def _reachable_bytes_types(
    logical_type: ProofKernelLogicalType,
    types: Mapping[str, ProofKernelLogicalType],
) -> tuple[ProofKernelLogicalType, ...]:
    """Return byte views nested in one finite, acyclic logical value type."""

    if logical_type.kind in {"bytes", "view"}:
        return (logical_type,)
    if logical_type.kind != "record":
        return ()
    result: list[ProofKernelLogicalType] = []
    for field in logical_type.fields:
        result.extend(_reachable_bytes_types(types[field.type_id], types))
    return tuple(result)


def _parse_type(value: object, index: int) -> ProofKernelLogicalType:
    row = _object(value, f"logical type {index}")
    kind = _text(row.get("kind"), f"logical type {index} kind")
    identity = _identifier(row.get("id"), f"logical type {index} id")
    if kind == "scalar":
        _exact(row, {"id", "kind", "c_type"}, f"logical type {identity}")
        c_type = _text(row["c_type"], f"logical type {identity} c_type")
        if c_type not in SCALAR_TYPES:
            raise ComponentInterfaceIRError(f"unsupported scalar type {c_type!r}")
        return ProofKernelLogicalType(identity, kind, c_type=c_type)
    if kind == "enum":
        _exact(row, {"id", "kind", "c_type"}, f"logical type {identity}")
        c_type = _text(row["c_type"], f"logical type {identity} c_type")
        if c_type not in SCALAR_TYPES:
            raise ComponentInterfaceIRError(f"unsupported enum storage {c_type!r}")
        return ProofKernelLogicalType(identity, kind, c_type=c_type)
    if kind == "bytes":
        _exact(
            row,
            {"id", "kind", "access", "extent_parameter_id", "nul_terminated"},
            f"logical type {identity}",
        )
        access = _text(row["access"], f"logical type {identity} access")
        if access not in ACCESS_MODES:
            raise ComponentInterfaceIRError(f"unsupported bytes access {access!r}")
        extent = row["extent_parameter_id"]
        if extent is not None:
            extent = _identifier(extent, f"logical type {identity} extent parameter")
        nul_terminated = row["nul_terminated"]
        if not isinstance(nul_terminated, bool) or (extent is None) == (not nul_terminated):
            raise ComponentInterfaceIRError(
                "bytes types require exactly one of an extent parameter or NUL termination"
            )
        return ProofKernelLogicalType(
            identity,
            kind,
            access=access,
            extent_parameter_id=extent,
            nul_terminated=nul_terminated,
        )
    if kind == "record":
        _exact(row, {"id", "kind", "access", "fields"}, f"logical type {identity}")
        access = _text(row["access"], f"logical type {identity} access")
        if access not in ACCESS_MODES:
            raise ComponentInterfaceIRError(f"unsupported record access {access!r}")
        fields = tuple(
            _parse_field(item, identity, field_index)
            for field_index, item in enumerate(_array(row["fields"], "record fields"))
        )
        _unique((field.identity for field in fields), f"record {identity} field")
        if not fields:
            raise ComponentInterfaceIRError("record types require at least one field")
        return ProofKernelLogicalType(identity, kind, access=access, fields=fields)
    if kind == "resource":
        _exact(
            row,
            {"id", "kind", "resource_kind", "ownership"},
            f"logical type {identity}",
        )
        ownership = _text(row["ownership"], f"logical type {identity} ownership")
        if ownership not in RESOURCE_OWNERSHIP:
            raise ComponentInterfaceIRError(f"unsupported resource ownership {ownership!r}")
        return ProofKernelLogicalType(
            identity,
            kind,
            resource_kind=_identifier(
                row["resource_kind"], f"logical type {identity} resource kind"
            ),
            ownership=ownership,
        )
    if kind == "resource_cell":
        _exact(
            row,
            {"id", "kind", "resource_kind", "ownership", "access"},
            f"logical type {identity}",
        )
        ownership = _text(row["ownership"], f"logical type {identity} ownership")
        access = _text(row["access"], f"logical type {identity} access")
        if ownership not in RESOURCE_OWNERSHIP or access not in {
            "write", "read_write"
        }:
            raise ComponentInterfaceIRError(
                f"logical resource cell {identity!r} has invalid ownership or access"
            )
        return ProofKernelLogicalType(
            identity,
            kind,
            resource_kind=_identifier(
                row["resource_kind"], f"logical type {identity} resource kind"
            ),
            ownership=ownership,
            access=access,
        )
    if kind == "callback":
        _exact(
            row,
            {
                "id", "kind", "ownership", "nullable",
                "parameter_type_ids", "result_type_id",
            },
            f"logical type {identity}",
        )
        ownership = _text(row["ownership"], f"logical type {identity} ownership")
        nullable = row["nullable"]
        if ownership not in {"borrowed", "retained"} or not isinstance(nullable, bool):
            raise ComponentInterfaceIRError(
                f"logical callback type {identity!r} has invalid ownership or nullability"
            )
        result_type = row["result_type_id"]
        return ProofKernelLogicalType(
            identity,
            kind,
            ownership=ownership,
            parameter_type_ids=tuple(
                _identifier(item, f"logical type {identity} callback parameter")
                for item in _array(row["parameter_type_ids"], "callback parameters")
            ),
            result_type_id=None
            if result_type is None
            else _identifier(result_type, f"logical type {identity} callback result"),
            nullable=nullable,
        )
    if kind == "view":
        _exact(
            row,
            {"id", "kind", "element_type_id", "access", "extent", "ownership"},
            f"logical type {identity}",
        )
        access = _text(row["access"], f"logical type {identity} access")
        ownership = _text(row["ownership"], f"logical type {identity} ownership")
        if access not in ACCESS_MODES or ownership not in RESOURCE_OWNERSHIP:
            raise ComponentInterfaceIRError(
                f"logical view type {identity!r} has invalid access or ownership"
            )
        extent = _object(row["extent"], f"logical type {identity} extent")
        extent_kind = _text(extent.get("kind"), f"logical type {identity} extent kind")
        extent_parameter_id = None
        fixed_extent = None
        nul_terminated = False
        if extent_kind == "parameter":
            _exact(extent, {"kind", "parameter_id"}, f"logical type {identity} extent")
            extent_parameter_id = _identifier(
                extent["parameter_id"], f"logical type {identity} extent parameter"
            )
        elif extent_kind == "fixed":
            _exact(extent, {"kind", "elements"}, f"logical type {identity} extent")
            elements = extent["elements"]
            if not isinstance(elements, int) or isinstance(elements, bool) or elements < 0:
                raise ComponentInterfaceIRError(
                    f"logical view type {identity!r} has invalid fixed extent"
                )
            fixed_extent = elements
        elif extent_kind == "nul_terminated":
            _exact(extent, {"kind"}, f"logical type {identity} extent")
            nul_terminated = True
        else:
            raise ComponentInterfaceIRError(
                f"logical view type {identity!r} has unsupported extent policy"
            )
        return ProofKernelLogicalType(
            identity,
            kind,
            access=access,
            extent_parameter_id=extent_parameter_id,
            nul_terminated=nul_terminated,
            ownership=ownership,
            element_type_id=_identifier(
                row["element_type_id"], f"logical type {identity} element type"
            ),
            extent_kind=extent_kind,
            fixed_extent=fixed_extent,
            lifetime="origin",
        )
    if kind == "reference":
        _exact(
            row,
            {
                "id",
                "kind",
                "element_type_id",
                "access",
                "nullable",
                "allow_one_past",
                "lifetime",
            },
            f"logical type {identity}",
        )
        access = _text(row["access"], f"logical type {identity} access")
        nullable = row["nullable"]
        allow_one_past = row["allow_one_past"]
        lifetime = _text(row["lifetime"], f"logical type {identity} lifetime")
        if (
            access not in ACCESS_MODES
            or not isinstance(nullable, bool)
            or not isinstance(allow_one_past, bool)
            or lifetime != "origin"
        ):
            raise ComponentInterfaceIRError(
                f"logical reference type {identity!r} has invalid policy"
            )
        return ProofKernelLogicalType(
            identity,
            kind,
            access=access,
            nullable=nullable,
            element_type_id=_identifier(
                row["element_type_id"], f"logical type {identity} element type"
            ),
            allow_one_past=allow_one_past,
            lifetime=lifetime,
        )
    raise ComponentInterfaceIRError(f"unsupported logical type kind {kind!r}")


def _parse_field(value: object, owner: str, index: int) -> ProofKernelLogicalField:
    row = _object(value, f"record {owner} field {index}")
    _exact(row, {"id", "type_id"}, f"record {owner} field {index}")
    return ProofKernelLogicalField(
        _identifier(row["id"], f"record {owner} field id"),
        _identifier(row["type_id"], f"record {owner} field type"),
    )



def _type_payload(value: ProofKernelLogicalType) -> dict[str, object]:
    result: dict[str, object] = {"id": value.identity, "kind": value.kind}
    if value.kind in {"scalar", "enum"}:
        result["c_type"] = value.c_type
    elif value.kind == "bytes":
        result.update(
            {
                "access": value.access,
                "extent_parameter_id": value.extent_parameter_id,
                "nul_terminated": value.nul_terminated,
            }
        )
    elif value.kind == "record":
        result.update(
            {
                "access": value.access,
                "fields": [
                    {"id": field.identity, "type_id": field.type_id}
                    for field in value.fields
                ],
            }
        )
    elif value.kind in {"resource", "resource_cell"}:
        result.update(
            {
                "resource_kind": value.resource_kind,
                "ownership": value.ownership,
                **({"access": value.access} if value.kind == "resource_cell" else {}),
            }
        )
    elif value.kind == "callback":
        result.update(
            {
                **(
                    {"abi": value.abi}
                    if value.abi is not None
                    else {
                        "ownership": value.ownership,
                        "nullable": value.nullable,
                    }
                ),
                "parameter_type_ids": list(value.parameter_type_ids),
                "result_type_id": value.result_type_id,
            }
        )
    elif value.kind == "view":
        extent: dict[str, object] = {"kind": value.extent_kind}
        if value.extent_kind == "parameter":
            extent["parameter_id"] = value.extent_parameter_id
        elif value.extent_kind == "fixed":
            extent["elements"] = value.fixed_extent
        result.update(
            {
                "element_type_id": value.element_type_id,
                "access": value.access,
                "extent": extent,
                "ownership": value.ownership,
            }
        )
    elif value.kind == "reference":
        result.update(
            {
                "element_type_id": value.element_type_id,
                "access": value.access,
                "nullable": value.nullable,
                "allow_one_past": value.allow_one_past,
                "lifetime": value.lifetime,
            }
        )
    else:
        raise AssertionError(value.kind)
    return result




def _validate_portable_value(
    value: object,
    logical_type: ProofKernelLogicalType,
    types: Mapping[str, ProofKernelLogicalType],
    context: str,
) -> None:
    if logical_type.kind in {"scalar", "enum"}:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ComponentInterfaceIRError(f"{context} must be an integer")
        assert logical_type.c_type is not None
        signed = logical_type.c_type.startswith("int")
        width = int(
            logical_type.c_type.removeprefix("uint")
            .removeprefix("int")
            .removesuffix("_t")
        )
        minimum = -(1 << (width - 1)) if signed else 0
        maximum = (1 << (width - (1 if signed else 0))) - 1
        if value < minimum or value > maximum:
            raise ComponentInterfaceIRError(
                f"{context} is outside its {width}-bit range"
            )
        return
    if logical_type.kind == "resource":
        row = _object(value, context)
        _exact(row, {"id", "kind"}, context)
        resource_id = row["id"]
        if (
            not isinstance(resource_id, int)
            or isinstance(resource_id, bool)
            or resource_id <= 0
            or resource_id > 2**64 - 1
            or row["kind"] != logical_type.resource_kind
        ):
            raise ComponentInterfaceIRError(f"{context} is not a valid resource")
        return
    if logical_type.kind == "resource_cell":
        raise ComponentInterfaceIRError(
            f"{context} is an invocation-local resource cell, not a portable value"
        )
    if logical_type.kind == "record":
        row = _object(value, context)
        if set(row) != {field.identity for field in logical_type.fields}:
            raise ComponentInterfaceIRError(
                f"{context} fields do not match its record type"
            )
        for field in logical_type.fields:
            _validate_portable_value(
                row[field.identity],
                types[field.type_id],
                types,
                f"{context}.{field.identity}",
            )
        return
    if logical_type.kind == "bytes":
        if not isinstance(value, list) or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 0
            or item > 255
            for item in value
        ):
            raise ComponentInterfaceIRError(f"{context} must be a byte array")
        if logical_type.nul_terminated and (not value or 0 not in value):
            raise ComponentInterfaceIRError(
                f"{context} must contain a NUL terminator"
            )
        return
    if logical_type.kind == "callback":
        row = _object(value, context)
        _exact(row, {"id"}, context)
        _text(row["id"], f"{context} callback id")
        return
    if logical_type.kind == "reference":
        row = _object(value, context)
        _exact(
            row,
            {"domain", "object", "generation", "offset", "extent", "permissions"},
            context,
        )
        numbers = []
        for field in ("domain", "object", "generation", "offset", "extent", "permissions"):
            item = row[field]
            if not isinstance(item, int) or isinstance(item, bool) or item < 0 or item > 2**64 - 1:
                raise ComponentInterfaceIRError(f"{context}.{field} is invalid")
            numbers.append(item)
        _, object_id, _, offset, extent, _ = numbers
        if object_id == 0:
            if logical_type.nullable is not True or any(numbers):
                raise ComponentInterfaceIRError(f"{context} is an invalid null reference")
        elif offset > extent or (offset == extent and not logical_type.allow_one_past):
            raise ComponentInterfaceIRError(f"{context} is outside its origin")
        return
    if logical_type.kind == "view":
        row = _object(value, context)
        _exact(row, {"base", "extent"}, context)
        synthetic = ProofKernelLogicalType(
            identity=f"{logical_type.identity}.base",
            kind="reference",
            nullable=False,
            allow_one_past=True,
        )
        _validate_portable_value(row["base"], synthetic, types, f"{context}.base")
        extent = row["extent"]
        if not isinstance(extent, int) or isinstance(extent, bool) or extent < 0:
            raise ComponentInterfaceIRError(f"{context}.extent is invalid")
        return
    raise ComponentInterfaceIRError(
        f"{context} uses unsupported type {logical_type.kind!r}"
    )


def _c_type_v2(logical_type: ProofKernelLogicalType) -> str:
    if logical_type.kind in {"scalar", "enum"}:
        assert logical_type.c_type is not None
        return (
            logical_type.c_type
            if logical_type.kind == "scalar"
            else f"spx_{logical_type.identity}_v2"
        )
    if logical_type.kind == "bytes":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_bytes_view_v2 *"
    if logical_type.kind == "record":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_{logical_type.identity}_v2 *"
    if logical_type.kind == "resource":
        if logical_type.resource_kind == ATOMIC_OBJECT_RESOURCE_KIND:
            return "spx_atomic_object *"
        return "spx_resource_v2"
    if logical_type.kind == "resource_cell":
        return "spx_resource_v2 *"
    if logical_type.kind == "callback":
        return f"spx_callback_{logical_type.identity}_v2 *"
    if logical_type.kind == "reference":
        return "spx_ref_v1"
    if logical_type.kind == "view":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_view_v1 *"
    raise AssertionError(logical_type.kind)


def _c_value_type_v2(logical_type: ProofKernelLogicalType) -> str:
    if logical_type.kind in {
        "scalar", "enum", "resource", "resource_cell", "callback", "reference"
    }:
        return _c_type_v2(logical_type)
    if logical_type.kind == "record":
        return f"spx_{logical_type.identity}_v2"
    if logical_type.kind == "bytes":
        return "spx_bytes_view_v2"
    if logical_type.kind == "view":
        return "spx_view_v1"
    raise AssertionError(logical_type.kind)


def _render_type_v2(
    logical_type: ProofKernelLogicalType, index: Mapping[str, ProofKernelLogicalType]
) -> list[str]:
    if logical_type.kind in {
        "scalar", "bytes", "resource", "resource_cell", "view", "reference"
    }:
        return []
    if logical_type.kind == "enum":
        assert logical_type.c_type is not None
        return [
            f"typedef {logical_type.c_type} spx_{logical_type.identity}_v2;",
            "",
        ]
    if logical_type.kind == "record":
        lines = [f"typedef struct spx_{logical_type.identity}_v2 {{"]
        lines.extend(
            f"  {_c_value_type_v2(index[field.type_id])} {field.identity};"
            for field in logical_type.fields
        )
        lines.extend([f"}} spx_{logical_type.identity}_v2;", ""])
        return lines
    if logical_type.kind == "callback":
        return [
            f"typedef struct spx_callback_{logical_type.identity}_v2 "
            f"spx_callback_{logical_type.identity}_v2;",
            "",
        ]
    raise AssertionError(logical_type.kind)


__all__ = [
    "ACCESS_MODES",
    "ProofKernelStateField",
    "ComponentInterfaceIRError",
    "ProofKernelEffect",
    "ProofKernelLogicalField",
    "ProofKernelLogicalType",
    "ProofKernelLogicalValue",
    "ProofKernelComponentInterface",
    "ProofKernelOperation",
    "ProofKernelProtocolTransition",
    "RESOURCE_OWNERSHIP",
    "SCALAR_TYPES",
    "ProofKernelService",
]
