"""Typed bindings between portable component operations and exact machine IR.

Portable interfaces intentionally contain no x86 facts.  This module is the
only component-layer artifact allowed to relate logical values to registers,
stack slots, image storage, callbacks, resources, and exact external sites.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import ArtifactV3Error, canonical_sha256_v3
from ..artifacts.io import open_artifact_reader_v3
from ..artifacts.formats import MACHINE_IR_FORMAT
from ..artifacts.boundary_claims import read_authorized_callback_protocols_v4
from ..external.site_authority import (
    CanonicalExternalSiteRecordError,
    read_canonical_external_site_ids,
)
from .machine_binding_checks import (
    ComponentMachineBindingError,
    check_component_operation_services as _check_component_operation_services,
    check_operation_view_aliases as _check_operation_view_aliases,
    check_result_decoding as _check_result_decoding,
    interface_payload as _checked_interface_payload,
    logical_scalar_width as _logical_scalar_width,
    machine_manifest_pe_sha256 as _machine_manifest_pe_sha256,
    projection_issue as _projection_issue,
)
from .interface_ir import PortableComponentInterfaceV2
from .value_codec import (
    ValueCodecError,
    copy_value_codec_expression,
    parse_value_codec_expression,
)


COMPONENT_MACHINE_BINDING_V1 = "spaghetti-extractor-component-machine-binding-v1"
COMPONENT_MACHINE_BINDING_DECLARATION_V2 = (
    "spaghetti-extractor-component-machine-binding-declaration-v2"
)
COMPONENT_MACHINE_BINDING_DECLARATION_V3 = (
    "spaghetti-extractor-component-machine-binding-declaration-v3"
)
COMPONENT_MACHINE_BINDING_RECEIPT_V1 = (
    "spaghetti-extractor-component-machine-binding-receipt-v1"
)
_INTERFACE_FORMATS = frozenset(
    {
        "spaghetti-extractor-component-interface-ir-v2",
        "spaghetti-extractor-component-interface-ir-v3",
        "spaghetti-extractor-component-interface-ir-v4",
    }
)
_MACHINE_IR = MACHINE_IR_FORMAT
_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
_ARTIFACT_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")
_REGISTERS = frozenset(
    {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"}
)
_EFFECT_FAMILIES = {
    "memory_event": "memory_events",
    "external_event": "external_events",
    "fault": "faults",
    "register_write": "register_writes",
    "flag_write": "flag_writes",
    "edge_condition": "edge_conditions",
}
_LOGICAL_EFFECT_FAMILIES = {
    "memory": frozenset({"memory_event"}),
    "resource": frozenset({"external_event", "memory_event"}),
    "callback": frozenset({"external_event"}),
    "observable": frozenset({"external_event"}),
    "control": frozenset({"edge_condition", "fault", "external_event"}),
}


@dataclass(frozen=True)
class MachineProjectionV1:
    kind: str
    payload: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str = "machine projection") -> "MachineProjectionV1":
        row = _object(value, context)
        kind = _text(row.get("kind"), f"{context} kind")
        if kind == "register":
            _exact(row, {"kind", "register", "width", "at"}, context)
            register = _text(row["register"], f"{context} register")
            if register not in _REGISTERS:
                raise ComponentMachineBindingError(f"{context} register is unsupported")
            _width(row["width"], context)
            _phase(row["at"], context)
        elif kind == "stack":
            _exact(row, {"kind", "offset", "width", "at"}, context)
            if not isinstance(row["offset"], int) or isinstance(row["offset"], bool):
                raise ComponentMachineBindingError(f"{context} stack offset is invalid")
            _width(row["width"], context)
            _phase(row["at"], context)
        elif kind == "static_slot":
            _exact(row, {"kind", "rva", "width", "at"}, context)
            _uint(row["rva"], f"{context} RVA")
            _width(row["width"], context)
            _phase(row["at"], context)
        elif kind == "memory":
            _exact(row, {"kind", "address", "width", "access", "at"}, context)
            cls.parse(row["address"], f"{context} address")
            _width(row["width"], context)
            if row["access"] not in {"read", "write", "read_write"}:
                raise ComponentMachineBindingError(f"{context} access is invalid")
            _phase(row["at"], context)
        elif kind == "constant":
            _exact(row, {"kind", "value", "width"}, context)
            _uint(row["value"], f"{context} value")
            _width(row["width"], context)
        elif kind == "origin_remainder":
            _exact(row, {"kind"}, context)
        elif kind == "control_condition":
            _exact(row, {"kind", "at"}, context)
            if row["at"] != "exit":
                raise ComponentMachineBindingError(
                    f"{context} control condition must be observed at exit"
                )
        elif kind == "finite_control_target":
            _exact(
                row,
                {
                    "kind",
                    "at",
                    "unit_id",
                    "selector_parameter_id",
                    "target_inventory_sha256",
                    "routes",
                },
                context,
            )
            if row["at"] != "exit":
                raise ComponentMachineBindingError(
                    f"{context} finite control target must be observed at exit"
                )
            _text(row["unit_id"], f"{context} unit id")
            _identifier(
                row["selector_parameter_id"],
                f"{context} selector parameter id",
            )
            _digest(
                row["target_inventory_sha256"],
                f"{context} target inventory digest",
            )
            routes = _array(row["routes"], f"{context} routes")
            parsed_routes: list[tuple[int, int, int, int]] = []
            for index, raw_route in enumerate(routes):
                route = _object(raw_route, f"{context} route {index}")
                _exact(
                    route,
                    {
                        "selector_value",
                        "logical_value",
                        "target_rva",
                        "target_address",
                    },
                    f"{context} route {index}",
                )
                parsed_routes.append(
                    (
                        _uint(
                            route["selector_value"],
                            f"{context} route {index} selector value",
                        ),
                        _uint(
                            route["logical_value"],
                            f"{context} route {index} logical value",
                        ),
                        _uint(
                            route["target_rva"],
                            f"{context} route {index} target RVA",
                        ),
                        _uint(
                            route["target_address"],
                            f"{context} route {index} target address",
                        ),
                    )
                )
            if not routes or parsed_routes != sorted(parsed_routes):
                raise ComponentMachineBindingError(
                    f"{context} routes must be nonempty and canonically ordered"
                )
            if len({row[0] for row in parsed_routes}) != len(parsed_routes):
                raise ComponentMachineBindingError(
                    f"{context} selector values must be unique"
                )
        elif kind == "resource":
            _exact(row, {"kind", "resource_kind", "source"}, context)
            _identifier(row["resource_kind"], f"{context} resource kind")
            cls.parse(row["source"], f"{context} resource source")
        elif kind == "atomic_object":
            _exact(
                row,
                {
                    "kind",
                    "resource_kind",
                    "unit_id",
                    "action_id",
                    "profile_id",
                    "source",
                    "width",
                },
                context,
            )
            if row["resource_kind"] != "atomic_object":
                raise ComponentMachineBindingError(
                    f"{context} atomic resource kind is invalid"
                )
            _text(row["unit_id"], f"{context} unit id")
            _text(row["action_id"], f"{context} action id")
            _text(row["profile_id"], f"{context} profile id")
            cls.parse(row["source"], f"{context} atomic source")
            width = row["width"]
            if width not in {1, 2, 4}:
                raise ComponentMachineBindingError(
                    f"{context} atomic width is unsupported"
                )
        elif kind == "callback_handle":
            _exact(
                row,
                {"kind", "protocol_id", "authority_id", "source", "at"},
                context,
            )
            _text(row["protocol_id"], f"{context} protocol id")
            _text(row["authority_id"], f"{context} authority id")
            cls.parse(row["source"], f"{context} callback source")
            _phase(row["at"], context)
        elif kind == "reference":
            _exact(
                row,
                {"kind", "source", "requested_extent", "authority", "at"},
                context,
            )
            cls.parse(row["source"], f"{context} reference source")
            cls.parse(
                row["requested_extent"],
                f"{context} reference requested extent",
            )
            _origin_authority(row["authority"], f"{context} reference authority")
            _phase(row["at"], context)
        elif kind == "view":
            _exact(
                row,
                {
                    "kind",
                    "base",
                    "extent",
                    "requested_extent",
                    "authority",
                    "at",
                },
                context,
            )
            cls.parse(row["base"], f"{context} view base")
            cls.parse(row["extent"], f"{context} view extent")
            cls.parse(
                row["requested_extent"],
                f"{context} view requested extent",
            )
            _origin_authority(row["authority"], f"{context} view authority")
            _phase(row["at"], context)
        elif kind == "field":
            _exact(row, {"kind", "base", "field_id"}, context)
            cls.parse(row["base"], f"{context} field base")
            _identifier(row["field_id"], f"{context} field id")
        elif kind == "finite_alternatives":
            _exact(row, {"kind", "alternatives"}, context)
            alternatives = _array(row["alternatives"], f"{context} alternatives")
            if not 1 <= len(alternatives) <= 32:
                raise ComponentMachineBindingError(
                    f"{context} alternatives must contain 1..32 entries"
                )
            parsed = [cls.parse(item, f"{context} alternative") for item in alternatives]
            payloads = [item.to_payload() for item in parsed]
            if payloads != sorted(payloads, key=canonical_sha256_v3):
                raise ComponentMachineBindingError(
                    f"{context} alternatives must be canonically ordered"
                )
        elif kind == "offset":
            _exact(row, {"kind", "base", "offset_bytes", "at"}, context)
            cls.parse(row["base"], f"{context} base")
            if not isinstance(row["offset_bytes"], int) or isinstance(
                row["offset_bytes"], bool
            ):
                raise ComponentMachineBindingError(
                    f"{context} byte offset is invalid"
                )
            _phase(row["at"], context)
        elif kind == "bytes_view":
            _exact(row, {"kind", "base", "extent_id", "at"}, context)
            cls.parse(row["base"], f"{context} base")
            if row["extent_id"] is not None:
                _identifier(row["extent_id"], f"{context} extent id")
            _phase(row["at"], context)
        elif kind == "record_view":
            _exact(row, {"kind", "fields", "at"}, context)
            _phase(row["at"], context)
            fields = _array(row["fields"], f"{context} fields")
            identities: list[str] = []
            for index, raw_field in enumerate(fields):
                field = _object(raw_field, f"{context} field {index}")
                _exact(field, {"id", "projection"}, f"{context} field {index}")
                identities.append(
                    _identifier(field["id"], f"{context} field {index} id")
                )
                cls.parse(
                    field["projection"], f"{context} field {identities[-1]} projection"
                )
            if not identities or identities != sorted(set(identities)):
                raise ComponentMachineBindingError(
                    f"{context} fields must be nonempty, unique, and ordered"
                )
        else:
            raise ComponentMachineBindingError(
                f"{context} has unsupported kind {kind!r}"
            )
        return cls(kind, json.loads(json.dumps(row)))

    def to_payload(self) -> dict[str, object]:
        return json.loads(json.dumps(self.payload))


@dataclass(frozen=True)
class LogicalMachineValueV1:
    identity: str
    projection: MachineProjectionV1
    decoding: Mapping[str, object] | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "LogicalMachineValueV1":
        row = _object(value, context)
        if set(row) not in ({"id", "projection"}, {"id", "projection", "decoding"}):
            raise ComponentMachineBindingError(
                f"{context} fields differ from the supported value binding"
            )
        decoding = row.get("decoding")
        parsed_decoding = None
        if decoding is not None:
            try:
                parsed_decoding, sort = parse_value_codec_expression(
                    decoding, f"{context} decoding"
                )
            except ValueCodecError as exc:
                raise ComponentMachineBindingError(str(exc)) from exc
            if sort != "word":
                raise ComponentMachineBindingError(
                    f"{context} decoding must produce a word"
                )
        return cls(
            _identifier(row["id"], f"{context} id"),
            MachineProjectionV1.parse(row["projection"], f"{context} projection"),
            parsed_decoding,
        )

    def to_payload(self) -> dict[str, object]:
        result = {"id": self.identity, "projection": self.projection.to_payload()}
        if self.decoding is not None:
            result["decoding"] = copy_value_codec_expression(self.decoding)
        return result


@dataclass(frozen=True)
class StateMachineBindingV1:
    identity: str
    entry: MachineProjectionV1
    exit: MachineProjectionV1

    @classmethod
    def parse(cls, value: object, context: str) -> "StateMachineBindingV1":
        row = _object(value, context)
        _exact(row, {"id", "entry", "exit"}, context)
        return cls(
            _identifier(row["id"], f"{context} id"),
            MachineProjectionV1.parse(row["entry"], f"{context} entry"),
            MachineProjectionV1.parse(row["exit"], f"{context} exit"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "entry": self.entry.to_payload(),
            "exit": self.exit.to_payload(),
        }


@dataclass(frozen=True)
class MachineEffectReferenceV1:
    effect_id: str
    unit_id: str
    family: str
    index: int
    fact_sha256: str

    @property
    def identity(self) -> str:
        """Stable row identity; one logical effect may cover several facts."""

        return f"{self.effect_id}:{self.unit_id}:{self.family}:{self.index:08d}"

    @classmethod
    def parse(cls, value: object, context: str) -> "MachineEffectReferenceV1":
        row = _object(value, context)
        _exact(
            row,
            {"effect_id", "unit_id", "family", "index", "fact_sha256"},
            context,
        )
        family = _text(row["family"], f"{context} family")
        if family not in _EFFECT_FAMILIES:
            raise ComponentMachineBindingError(
                f"{context} effect family is unsupported"
            )
        return cls(
            _identifier(row["effect_id"], f"{context} effect id"),
            _text(row["unit_id"], f"{context} unit id"),
            family,
            _uint(row["index"], f"{context} fact index"),
            _digest(row["fact_sha256"], f"{context} fact digest"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "effect_id": self.effect_id,
            "unit_id": self.unit_id,
            "family": self.family,
            "index": self.index,
            "fact_sha256": self.fact_sha256,
        }


@dataclass(frozen=True)
class MachineServiceEventV1:
    """One logical service invocation bound to an exact machine-IR event."""

    unit_id: str
    event_index: int
    event_sha256: str
    arguments: tuple[MachineProjectionV1, ...]
    result: MachineProjectionV1 | None

    @classmethod
    def parse(cls, value: object, context: str) -> "MachineServiceEventV1":
        row = _object(value, context)
        _exact(
            row,
            {"unit_id", "event_index", "event_sha256", "arguments", "result"},
            context,
        )
        result = row["result"]
        return cls(
            unit_id=_text(row["unit_id"], f"{context} unit id"),
            event_index=_uint(row["event_index"], f"{context} event index"),
            event_sha256=_digest(row["event_sha256"], f"{context} event digest"),
            arguments=tuple(
                MachineProjectionV1.parse(item, f"{context} argument {index}")
                for index, item in enumerate(
                    _array(row["arguments"], f"{context} arguments")
                )
            ),
            result=(
                None
                if result is None
                else MachineProjectionV1.parse(result, f"{context} result")
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "unit_id": self.unit_id,
            "event_index": self.event_index,
            "event_sha256": self.event_sha256,
            "arguments": [item.to_payload() for item in self.arguments],
            "result": None if self.result is None else self.result.to_payload(),
        }


@dataclass(frozen=True)
class OperationMachineBindingV1:
    operation_id: str
    entry_unit_ids: tuple[str, ...]
    exit_unit_ids: tuple[str, ...]
    parameters: tuple[LogicalMachineValueV1, ...]
    results: tuple[LogicalMachineValueV1, ...]
    state: tuple[StateMachineBindingV1, ...]
    preserved_state_ids: tuple[str, ...]
    effects: tuple[MachineEffectReferenceV1, ...]
    callback_operation_ids: tuple[str, ...]
    continuation_unit_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "OperationMachineBindingV1":
        row = _object(value, context)
        _exact(
            row,
            {
                "operation_id",
                "entry_unit_ids",
                "exit_unit_ids",
                "parameters",
                "results",
                "state",
                "preserved_state_ids",
                "effects",
                "callback_operation_ids",
                "continuation_unit_ids",
            },
            context,
        )
        return cls(
            operation_id=_identifier(row["operation_id"], f"{context} operation id"),
            entry_unit_ids=_strings(row["entry_unit_ids"], f"{context} entries", nonempty=True),
            exit_unit_ids=_strings(row["exit_unit_ids"], f"{context} exits", nonempty=True),
            parameters=_rows(LogicalMachineValueV1.parse, row["parameters"], f"{context} parameter"),
            results=_rows(LogicalMachineValueV1.parse, row["results"], f"{context} result"),
            state=_rows(StateMachineBindingV1.parse, row["state"], f"{context} state"),
            preserved_state_ids=_identifiers(
                row["preserved_state_ids"], f"{context} preserved state"
            ),
            effects=_rows(MachineEffectReferenceV1.parse, row["effects"], f"{context} effect"),
            callback_operation_ids=_identifiers(
                row["callback_operation_ids"], f"{context} callback"
            ),
            continuation_unit_ids=_strings(
                row["continuation_unit_ids"], f"{context} continuations"
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "entry_unit_ids": list(self.entry_unit_ids),
            "exit_unit_ids": list(self.exit_unit_ids),
            "parameters": [row.to_payload() for row in self.parameters],
            "results": [row.to_payload() for row in self.results],
            "state": [row.to_payload() for row in self.state],
            "preserved_state_ids": list(self.preserved_state_ids),
            "effects": [row.to_payload() for row in self.effects],
            "callback_operation_ids": list(self.callback_operation_ids),
            "continuation_unit_ids": list(self.continuation_unit_ids),
        }


@dataclass(frozen=True)
class ServiceMachineBindingV1:
    service_id: str
    provider: Mapping[str, object]
    mediation: str

    @classmethod
    def parse(cls, value: object, context: str) -> "ServiceMachineBindingV1":
        row = _object(value, context)
        _exact(row, {"service_id", "provider", "mediation"}, context)
        provider = _object(row["provider"], f"{context} provider")
        kind = provider.get("kind")
        if kind == "external_site":
            fields = {"kind", "site_id"}
            if "result_projection" in provider:
                fields.add("result_projection")
            if "argument_authority_selectors" in provider:
                fields.add("argument_authority_selectors")
            _exact(provider, fields, f"{context} provider")
            _text(provider["site_id"], f"{context} site id")
            if "argument_authority_selectors" in provider:
                for index, selector in enumerate(
                    _array(
                        provider["argument_authority_selectors"],
                        f"{context} argument authority selectors",
                    )
                ):
                    if selector is not None:
                        _identifier(
                            selector,
                            f"{context} argument authority selector {index}",
                        )
            if "result_projection" in provider:
                MachineProjectionV1.parse(
                    provider["result_projection"],
                    f"{context} external result projection",
                )
        elif kind == "machine_events":
            _exact(provider, {"kind", "events"}, f"{context} provider")
            events = tuple(
                MachineServiceEventV1.parse(
                    item, f"{context} machine event {index}"
                )
                for index, item in enumerate(
                    _array(provider["events"], f"{context} machine events")
                )
            )
            if not events:
                raise ComponentMachineBindingError(
                    f"{context} machine-event provider has no events"
                )
            refs = [(item.unit_id, item.event_index) for item in events]
            if refs != sorted(refs) or len(refs) != len(set(refs)):
                raise ComponentMachineBindingError(
                    f"{context} machine events must be unique and ordered"
                )
        elif kind == "component_operation":
            fields = {"kind", "component_id", "operation_id"}
            if "events" in provider:
                fields.add("events")
            _exact(provider, fields, f"{context} provider")
            _artifact_id(provider["component_id"], f"{context} component id")
            _identifier(provider["operation_id"], f"{context} operation id")
            if "events" in provider:
                events = tuple(
                    MachineServiceEventV1.parse(
                        item, f"{context} component-operation event {index}"
                    )
                    for index, item in enumerate(
                        _array(provider["events"], f"{context} component-operation events")
                    )
                )
                if not events:
                    raise ComponentMachineBindingError(
                        f"{context} component-operation provider has no events"
                    )
                refs = [(item.unit_id, item.event_index) for item in events]
                if refs != sorted(refs) or len(refs) != len(set(refs)):
                    raise ComponentMachineBindingError(
                        f"{context} component-operation events must be unique and ordered"
                    )
        else:
            raise ComponentMachineBindingError(f"{context} provider kind is unsupported")
        mediation = _text(row["mediation"], f"{context} mediation")
        if mediation not in {"direct", "callback", "protocol"}:
            raise ComponentMachineBindingError(
                f"{context} mediation kind is unsupported"
            )
        return cls(
            _identifier(row["service_id"], f"{context} service id"),
            json.loads(json.dumps(provider)),
            mediation,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "service_id": self.service_id,
            "provider": dict(self.provider),
            "mediation": self.mediation,
        }


@dataclass(frozen=True)
class ComponentMachineBindingV1:
    identity: str
    pe_sha256: str
    machine_ir_sha256: str
    interface_id: str
    interface_sha256: str
    unit_ids: tuple[str, ...]
    operations: tuple[OperationMachineBindingV1, ...]
    services: tuple[ServiceMachineBindingV1, ...]
    binding_sha256: str

    @classmethod
    def parse(cls, value: object) -> "ComponentMachineBindingV1":
        row = _object(value, "component machine binding")
        _exact(
            row,
            {
                "format",
                "id",
                "binary",
                "interface",
                "unit_ids",
                "operations",
                "services",
                "binding_sha256",
            },
            "component machine binding",
        )
        if row["format"] != COMPONENT_MACHINE_BINDING_V1:
            raise ComponentMachineBindingError("unsupported component machine-binding format")
        binary = _object(row["binary"], "component machine-binding binary")
        interface = _object(row["interface"], "component machine-binding interface")
        _exact(binary, {"pe_sha256", "machine_ir_sha256"}, "component machine-binding binary")
        _exact(interface, {"id", "sha256"}, "component machine-binding interface")
        core = dict(row)
        observed = _digest(core.pop("binding_sha256"), "component binding digest")
        if canonical_sha256_v3(core) != observed:
            raise ComponentMachineBindingError("component machine-binding digest is stale")
        operations = _rows(
            OperationMachineBindingV1.parse,
            row["operations"],
            "component operation binding",
        )
        services = _rows(
            ServiceMachineBindingV1.parse,
            row["services"],
            "component service binding",
        )
        _unique((item.operation_id for item in operations), "operation binding")
        _unique((item.service_id for item in services), "service binding")
        return cls(
            identity=_artifact_id(row["id"], "component binding id"),
            pe_sha256=_digest(binary["pe_sha256"], "component PE digest"),
            machine_ir_sha256=_digest(binary["machine_ir_sha256"], "component machine-IR digest"),
            interface_id=_identifier(interface["id"], "component interface id"),
            interface_sha256=_digest(interface["sha256"], "component interface digest"),
            unit_ids=_strings(row["unit_ids"], "component machine units", nonempty=True),
            operations=operations,
            services=services,
            binding_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_MACHINE_BINDING_V1,
            "id": self.identity,
            "binary": {
                "pe_sha256": self.pe_sha256,
                "machine_ir_sha256": self.machine_ir_sha256,
            },
            "interface": {"id": self.interface_id, "sha256": self.interface_sha256},
            "unit_ids": list(self.unit_ids),
            "operations": [row.to_payload() for row in self.operations],
            "services": [row.to_payload() for row in self.services],
        }
        return {**core, "binding_sha256": self.binding_sha256}


def create_component_machine_binding_v1(**values: object) -> dict[str, object]:
    core = {"format": COMPONENT_MACHINE_BINDING_V1, **values}
    return {**core, "binding_sha256": canonical_sha256_v3(core)}


def materialize_component_machine_binding(
    *,
    declaration: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object] | object,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    semantic_component_catalog: Path | str | Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Bind an operator mapping declaration to exact generated artifacts."""

    raw = _load(declaration, "component machine-binding declaration")
    if raw.get("format") == COMPONENT_MACHINE_BINDING_V1:
        ComponentMachineBindingV1.parse(raw)
        return raw
    declaration_format = raw.get("format")
    if declaration_format not in {
        COMPONENT_MACHINE_BINDING_DECLARATION_V2,
        COMPONENT_MACHINE_BINDING_DECLARATION_V3,
    }:
        raise ComponentMachineBindingError(
            "unsupported component machine-binding declaration format"
        )
    _exact(
        raw,
        {"format", "id", "unit_ids", "operations", "services"},
        "component machine-binding declaration",
    )
    interface_payload = _interface_payload(interface)
    portable = PortableComponentInterfaceV2.parse(interface_payload)
    machine_path = Path(machine_ir)
    machine_units = _machine_units(machine_path.read_bytes())
    manifest = _load(machine_ir_manifest, "machine-IR manifest")
    pe_sha256 = _machine_manifest_pe_sha256(manifest)
    catalog = (
        None
        if semantic_component_catalog is None
        else _load(semantic_component_catalog, "semantic component catalog")
    )
    component_id = _artifact_id(raw["id"], "component binding declaration id")
    return create_component_machine_binding_v1(
        id=component_id,
        binary={
            "pe_sha256": pe_sha256,
            "machine_ir_sha256": hashlib.sha256(machine_path.read_bytes()).hexdigest(),
        },
        interface={"id": portable.identity, "sha256": portable.sha256},
        unit_ids=list(_strings(raw["unit_ids"], "declared machine units", nonempty=True)),
        operations=[
            _materialize_operation_binding(
                row,
                machine_units,
                component_id=component_id,
                semantic_component_catalog=catalog,
                declaration_format=str(declaration_format),
            ).to_payload()
            for row in _array(raw["operations"], "declared operation bindings")
        ],
        services=[
            _materialize_service_binding(row, machine_units).to_payload()
            for row in _array(raw["services"], "declared service bindings")
        ],
    )


def _materialize_operation_binding(
    value: object,
    machine: Mapping[str, Mapping[str, object]],
    *,
    component_id: str,
    semantic_component_catalog: Mapping[str, object] | None,
    declaration_format: str,
) -> OperationMachineBindingV1:
    """Bind hash-free operator effect references to exact machine facts."""

    row = _object(value, "declared operation binding")
    expected = {
        "operation_id",
        "entry_unit_ids",
        "exit_unit_ids",
        "parameters",
        "results",
        "state",
        "preserved_state_ids",
        "effects",
        "continuation_unit_ids",
    }
    if declaration_format == COMPONENT_MACHINE_BINDING_DECLARATION_V2:
        expected.add("callback_operation_ids")
    _exact(row, expected, "declared operation binding")
    effects: list[dict[str, object]] = []
    for position, raw_effect in enumerate(
        _array(row["effects"], "declared operation effects")
    ):
        effect = _object(raw_effect, f"declared operation effect {position}")
        fields = {"effect_id", "unit_id", "family", "index"}
        if set(effect) not in (fields, fields | {"fact_sha256"}):
            raise ComponentMachineBindingError(
                f"declared operation effect {position} fields differ"
            )
        unit_id = _text(effect["unit_id"], "declared effect unit id")
        unit = machine.get(unit_id)
        if unit is None:
            raise ComponentMachineBindingError(
                f"declared operation effect references unknown unit {unit_id}"
            )
        family = _text(effect["family"], "declared effect family")
        index = _uint(effect["index"], "declared effect index")
        fact = _machine_effect_fact(unit, family, index)
        materialized = {key: value for key, value in effect.items() if key != "fact_sha256"}
        materialized["fact_sha256"] = canonical_sha256_v3(fact)
        effects.append(json.loads(json.dumps(materialized)))
    materialized_results = []
    for position, raw_result in enumerate(
        _array(row["results"], "declared operation results")
    ):
        result = _object(raw_result, f"declared operation result {position}")
        if set(result) not in ({"id", "projection"}, {"id", "projection", "decoding"}):
            raise ComponentMachineBindingError(
                f"declared operation result {position} fields differ"
            )
        materialized_results.append(
            {
                **json.loads(json.dumps(result)),
                "projection": _materialize_finite_control_target(
                    result.get("projection"),
                    component_id=component_id,
                    semantic_component_catalog=semantic_component_catalog,
                ),
            }
        )
    return OperationMachineBindingV1.parse(
        {
            **json.loads(json.dumps(row)),
            "callback_operation_ids": list(row.get("callback_operation_ids", [])),
            "effects": effects,
            "results": materialized_results,
        },
        "materialized operation binding",
    )


def _materialize_finite_control_target(
    value: object,
    *,
    component_id: str,
    semantic_component_catalog: Mapping[str, object] | None,
) -> object:
    projection = _object(value, "declared result projection")
    if projection.get("kind") != "finite_control_target":
        return json.loads(json.dumps(projection))
    _exact(
        projection,
        {
            "kind",
            "at",
            "unit_id",
            "selector_parameter_id",
            "targets",
        },
        "declared finite control target",
    )
    if semantic_component_catalog is None:
        raise ComponentMachineBindingError(
            "finite control target materialization requires the semantic component catalog"
        )
    components = _array(
        semantic_component_catalog.get("components"),
        "semantic component catalog components",
    )
    component_matches = [
        _object(item, "semantic component")
        for item in components
        if isinstance(item, Mapping) and item.get("id") == component_id
    ]
    if len(component_matches) != 1:
        raise ComponentMachineBindingError(
            "finite control target component is absent or ambiguous in the semantic catalog"
        )
    boundary = _object(
        component_matches[0].get("machine_boundary"),
        "finite control target machine boundary",
    )
    unit_id = _text(projection["unit_id"], "finite control target unit id")
    exit_matches = [
        _object(item, "finite control exit")
        for item in _array(boundary.get("exits"), "component boundary exits")
        if isinstance(item, Mapping)
        and item.get("source_unit_id") == unit_id
        and item.get("kind") == "indirect_jump"
    ]
    if len(exit_matches) != 1:
        raise ComponentMachineBindingError(
            "finite control target exit is absent or ambiguous"
        )
    inventory = _object(
        exit_matches[0].get("target_inventory"),
        "finite control target inventory",
    )
    if inventory.get("closure") != "checked_finite_target_inventory":
        raise ComponentMachineBindingError(
            "finite control target inventory is not checked and closed"
        )
    target_values: dict[int, int] = {}
    for index, raw_target in enumerate(
        _array(projection["targets"], "declared finite control targets")
    ):
        target = _object(raw_target, f"declared finite control target {index}")
        _exact(
            target,
            {"target_rva", "logical_value"},
            f"declared finite control target {index}",
        )
        target_rva = _uint(target["target_rva"], "finite control target RVA")
        logical_value = _uint(
            target["logical_value"], "finite control target logical value"
        )
        if target_rva in target_values:
            raise ComponentMachineBindingError(
                "declared finite control target RVAs must be unique"
            )
        target_values[target_rva] = logical_value
    entries = [
        _object(item, "finite control inventory entry")
        for item in _array(inventory.get("entries"), "finite control inventory entries")
    ]
    recovered_targets = {int(item["target_rva"]) for item in entries}
    if set(target_values) != recovered_targets:
        raise ComponentMachineBindingError(
            "declared finite control targets differ from the checked target inventory"
        )
    routes = sorted(
        (
            {
                "selector_value": _uint(item["index"], "finite control selector"),
                "logical_value": target_values[int(item["target_rva"])],
                "target_rva": _uint(item["target_rva"], "finite control target RVA"),
                "target_address": _uint(
                    item["target_address"], "finite control target address"
                ),
            }
            for item in entries
        ),
        key=lambda item: (
            item["selector_value"],
            item["logical_value"],
            item["target_rva"],
            item["target_address"],
        ),
    )
    return {
        "kind": "finite_control_target",
        "at": projection["at"],
        "unit_id": unit_id,
        "selector_parameter_id": projection["selector_parameter_id"],
        "target_inventory_sha256": canonical_sha256_v3(inventory),
        "routes": routes,
    }


def _materialize_service_binding(
    value: object,
    machine: Mapping[str, Mapping[str, object]],
) -> ServiceMachineBindingV1:
    """Bind hash-free operator event references to exact machine semantics."""

    row = _object(value, "declared service binding")
    provider = _object(row.get("provider"), "declared service provider")
    provider_kind = provider.get("kind")
    if provider_kind not in {"machine_events", "component_operation"} or (
        provider_kind == "component_operation" and "events" not in provider
    ):
        return ServiceMachineBindingV1.parse(row, "declared service binding")
    _exact(
        row,
        {"service_id", "provider", "mediation"},
        "declared service binding",
    )
    provider_fields = {"kind", "events"}
    if provider_kind == "component_operation":
        provider_fields.update({"component_id", "operation_id"})
    _exact(provider, provider_fields, "declared machine-event service provider")
    events: list[dict[str, object]] = []
    for index, raw_event in enumerate(
        _array(provider["events"], "declared machine service events")
    ):
        event = _object(raw_event, f"declared machine service event {index}")
        _exact(
            event,
            {"unit_id", "event_index", "arguments", "result"},
            f"declared machine service event {index}",
        )
        unit_id = _text(event["unit_id"], "declared machine service unit id")
        event_index = _uint(
            event["event_index"], "declared machine service event index"
        )
        unit = machine.get(unit_id)
        if unit is None:
            raise ComponentMachineBindingError(
                f"declared machine service event references unknown unit {unit_id}"
            )
        external_events = _array(
            _object(unit.get("semantics"), "machine semantics").get(
                "external_events", []
            ),
            "machine external events",
        )
        if event_index >= len(external_events):
            raise ComponentMachineBindingError(
                f"declared machine service event index is stale for {unit_id}"
            )
        machine_event = _object(
            external_events[event_index], "exact machine external event"
        )
        events.append(
            {
                **json.loads(json.dumps(event)),
                "event_sha256": canonical_sha256_v3(machine_event),
            }
        )
    materialized_provider = {
        key: json.loads(json.dumps(value))
        for key, value in provider.items()
        if key != "events"
    }
    materialized_provider["events"] = events
    materialized = {
        "service_id": row.get("service_id"),
        "provider": materialized_provider,
        "mediation": row.get("mediation"),
    }
    return ServiceMachineBindingV1.parse(
        materialized, "materialized service binding"
    )


def check_component_machine_binding(
    *,
    binding: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object] | object,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    external_site_ids: Sequence[str] = (),
    canonical_external_sites: Path | str | None = None,
    callback_authority: Path | str | None = None,
    component_resolution: Path | str | Mapping[str, object] | None = None,
    semantic_component_catalog: Path | str | Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Check one binding without treating its reviewed proposal as authority."""

    parsed = ComponentMachineBindingV1.parse(_load(binding, "component machine binding"))
    interface_payload = _interface_payload(interface)
    issues: list[dict[str, object]] = []
    machine_path = Path(machine_ir)
    machine_bytes = machine_path.read_bytes()
    machine = _machine_units(machine_bytes)
    machine_sha256 = hashlib.sha256(machine_bytes).hexdigest()
    manifest = _load(machine_ir_manifest, "machine-IR manifest")
    manifest_artifact = _object(
        _object(manifest.get("artifacts"), "machine-IR artifacts").get("machine_ir"),
        "machine-IR artifact binding",
    )
    manifest_machine_sha256 = manifest_artifact.get("sha256")
    pe_sha256 = _machine_manifest_pe_sha256(manifest)
    if manifest_machine_sha256 != machine_sha256:
        _issue(issues, "violated", "machine_ir_manifest_digest_mismatch")
    if parsed.machine_ir_sha256 != machine_sha256:
        _issue(issues, "violated", "machine_ir_digest_mismatch")
    if parsed.pe_sha256 != pe_sha256:
        _issue(issues, "violated", "pe_digest_mismatch")
    interface_id = interface_payload.get("id")
    if parsed.interface_id != interface_id:
        _issue(issues, "violated", "interface_id_mismatch")
    if parsed.interface_sha256 != canonical_sha256_v3(interface_payload):
        _issue(issues, "violated", "interface_digest_mismatch")
    if set(parsed.unit_ids) - set(machine):
        _issue(issues, "violated", "unknown_component_machine_unit")

    operations = _index(interface_payload.get("operations"), "portable operations")
    types = _index(interface_payload.get("types"), "portable types")
    states = _index(interface_payload.get("state", []), "portable state")
    effects = _index(interface_payload.get("effects", []), "portable effects")
    services = _index(interface_payload.get("services", []), "portable services")
    resolution_payload = (
        None
        if component_resolution is None
        else _load(component_resolution, "component resolution")
    )
    catalog_payload = (
        None
        if semantic_component_catalog is None
        else _load(semantic_component_catalog, "semantic component catalog")
    )
    bound_operations = {row.operation_id: row for row in parsed.operations}
    if set(bound_operations) != set(operations):
        _issue(issues, "incomplete", "operation_binding_inventory_mismatch")
    for operation_id, operation in operations.items():
        bound = bound_operations.get(operation_id)
        if bound is None:
            continue
        _check_operation_binding(
            bound,
            operation,
            operations,
            types,
            states,
            effects,
            services,
            machine,
            set(parsed.unit_ids),
            component_id=parsed.identity,
            semantic_component_catalog=catalog_payload,
            issues=issues,
        )
    callback_handles = tuple(
        projection
        for operation in parsed.operations
        for value in (*operation.parameters, *operation.results)
        for projection in _callback_handle_projections(value.projection)
    )
    callback_handles += tuple(
        projection
        for operation in parsed.operations
        for value in operation.state
        for bound in (value.entry, value.exit)
        for projection in _callback_handle_projections(bound)
    )
    callback_authority_manifest_sha256: str | None = None
    if callback_handles:
        if callback_authority is None:
            _issue(issues, "incomplete", "callback_authority_missing")
        else:
            try:
                callback_protocols, callback_authority_manifest_sha256 = (
                    _callback_authority_protocols(
                        callback_authority,
                        authority_ids=frozenset(
                            str(row.payload["authority_id"])
                            for row in callback_handles
                        ),
                    )
                )
            except (ArtifactV3Error, ComponentMachineBindingError, ValueError) as exc:
                _issue(
                    issues,
                    "violated",
                    "callback_authority_invalid",
                    detail=str(exc),
                )
            else:
                for projection in callback_handles:
                    authority_id = str(projection.payload["authority_id"])
                    expected_protocol = callback_protocols.get(authority_id)
                    if expected_protocol is None:
                        _issue(
                            issues,
                            "incomplete",
                            "callback_handle_authority_unresolved",
                            id=authority_id,
                        )
                    elif projection.payload["protocol_id"] != expected_protocol:
                        _issue(
                            issues,
                            "violated",
                            "callback_handle_protocol_contradiction",
                            id=authority_id,
                        )
    bound_services = {row.service_id: row for row in parsed.services}
    if set(bound_services) != set(services):
        _issue(issues, "incomplete", "service_binding_inventory_mismatch")
    known_external = set(external_site_ids)
    if canonical_external_sites is not None and any(
        row.provider.get("kind") == "external_site" for row in parsed.services
    ):
        try:
            known_external.update(
                read_canonical_external_site_ids(
                    canonical_external_sites,
                    record_ids=parsed.unit_ids,
                )
            )
        except (ArtifactV3Error, CanonicalExternalSiteRecordError) as exc:
            _issue(
                issues,
                "violated",
                "canonical_external_sites_invalid",
                detail=str(exc),
            )
    for service in parsed.services:
        provider = service.provider
        if provider.get("kind") == "external_site" and provider.get("site_id") not in known_external:
            _issue(issues, "incomplete", "external_site_provider_unresolved", id=service.service_id)
    _check_component_operation_services(
        component_id=parsed.identity,
        services=parsed.services,
        machine=machine,
        machine_ir_sha256=machine_sha256,
        resolution=resolution_payload,
        catalog=catalog_payload,
        issues=issues,
    )
    _check_machine_service_bindings(parsed, services, machine, issues)
    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    receipt_bindings = {
        "component_machine_binding_sha256": parsed.binding_sha256,
        "interface_sha256": canonical_sha256_v3(interface_payload),
        "machine_ir_sha256": machine_sha256,
        "machine_ir_manifest_sha256": hashlib.sha256(
            Path(machine_ir_manifest).read_bytes()
        ).hexdigest(),
        "pe_sha256": pe_sha256,
        **(
            {
                "callback_authority_manifest_sha256": (
                    callback_authority_manifest_sha256
                ),
            }
            if callback_authority_manifest_sha256 is not None
            else {}
        ),
        **(
            {
                "component_resolution_sha256": resolution_payload.get(
                    "resolution_sha256"
                ),
                "semantic_component_catalog_sha256": catalog_payload.get(
                    "catalog_sha256"
                ),
            }
            if resolution_payload is not None and catalog_payload is not None
            else {}
        ),
    }
    core = {
        "format": COMPONENT_MACHINE_BINDING_RECEIPT_V1,
        "status": status,
        "activation_authorized": status == "checked",
        "bindings": receipt_bindings,
        "counts": {
            "units": len(parsed.unit_ids),
            "operations": len(parsed.operations),
            "services": len(parsed.services),
            "issues": len(issues),
        },
        "policy": {
            "runtime_lowering_is_separate_authority": True,
            "logical_machine_binding_checked": status == "checked",
        },
        "issues": sorted(issues, key=lambda row: (str(row["status"]), str(row["code"]))),
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _callback_handle_projections(
    projection: MachineProjectionV1,
) -> tuple[MachineProjectionV1, ...]:
    result = [projection] if projection.kind == "callback_handle" else []
    for key in ("source", "base", "address"):
        child = projection.payload.get(key)
        if isinstance(child, Mapping):
            result.extend(
                _callback_handle_projections(
                    MachineProjectionV1.parse(child, "nested callback projection")
                )
            )
    return tuple(result)


def _callback_authority_protocols(
    value: Path | str, *, authority_ids: frozenset[str]
) -> tuple[dict[str, str], str]:
    return read_authorized_callback_protocols_v4(
        value, authority_ids=authority_ids
    )


def _check_machine_service_bindings(
    binding: ComponentMachineBindingV1,
    services: Mapping[str, Mapping[str, object]],
    machine: Mapping[str, Mapping[str, object]],
    issues: list[dict[str, object]],
) -> None:
    seen: set[tuple[str, int]] = set()
    selected = set(binding.unit_ids)
    for service_binding in binding.services:
        provider = service_binding.provider
        logical = services.get(service_binding.service_id)
        selectors = provider.get("argument_authority_selectors")
        if selectors is not None and logical is not None:
            parameter_count = len(
                _array(logical.get("parameter_type_ids"), "service parameters")
            )
            if len(_array(selectors, "service argument authority selectors")) != parameter_count:
                _issue(
                    issues,
                    "violated",
                    "service_argument_authority_selector_inventory_mismatch",
                    id=service_binding.service_id,
                    expected=parameter_count,
                    observed=len(
                        _array(selectors, "service argument authority selectors")
                    ),
                )
        if provider.get("kind") not in {"machine_events", "component_operation"}:
            continue
        if "events" not in provider:
            continue
        if logical is None:
            continue
        parameter_count = len(
            _array(logical.get("parameter_type_ids"), "service parameters")
        )
        has_result = logical.get("result_type_id") is not None
        for index, raw in enumerate(
            _array(provider.get("events"), "machine service events")
        ):
            event = MachineServiceEventV1.parse(
                raw, f"service {service_binding.service_id} event {index}"
            )
            reference = (event.unit_id, event.event_index)
            if reference in seen:
                _issue(
                    issues,
                    "violated",
                    "machine_service_event_bound_more_than_once",
                    id=service_binding.service_id,
                    unit_id=event.unit_id,
                    event_index=event.event_index,
                )
                continue
            seen.add(reference)
            if event.unit_id not in selected or event.unit_id not in machine:
                _issue(
                    issues,
                    "violated",
                    "machine_service_event_outside_component",
                    id=service_binding.service_id,
                    unit_id=event.unit_id,
                )
                continue
            external_events = _array(
                _object(
                    machine[event.unit_id].get("semantics"), "machine semantics"
                ).get("external_events", []),
                "machine external events",
            )
            if event.event_index >= len(external_events):
                _issue(
                    issues,
                    "violated",
                    "machine_service_event_index_stale",
                    id=service_binding.service_id,
                    unit_id=event.unit_id,
                )
                continue
            if canonical_sha256_v3(external_events[event.event_index]) != event.event_sha256:
                _issue(
                    issues,
                    "violated",
                    "machine_service_event_digest_stale",
                    id=service_binding.service_id,
                    unit_id=event.unit_id,
                    event_index=event.event_index,
                )
            if len(event.arguments) != parameter_count:
                _issue(
                    issues,
                    "violated",
                    "machine_service_argument_inventory_mismatch",
                    id=service_binding.service_id,
                    unit_id=event.unit_id,
                    expected=parameter_count,
                    observed=len(event.arguments),
                )
            if (event.result is not None) != has_result:
                _issue(
                    issues,
                    "violated",
                    "machine_service_result_inventory_mismatch",
                    id=service_binding.service_id,
                    unit_id=event.unit_id,
                )


def _check_operation_binding(
    bound: OperationMachineBindingV1,
    operation: Mapping[str, object],
    operations: Mapping[str, Mapping[str, object]],
    types: Mapping[str, Mapping[str, object]],
    states: Mapping[str, Mapping[str, object]],
    effects: Mapping[str, Mapping[str, object]],
    services: Mapping[str, Mapping[str, object]],
    machine: Mapping[str, Mapping[str, object]],
    selected_unit_ids: set[str],
    *,
    component_id: str,
    semantic_component_catalog: Mapping[str, object] | None,
    issues: list[dict[str, object]],
) -> None:
    for unit_id in (*bound.entry_unit_ids, *bound.exit_unit_ids, *bound.continuation_unit_ids):
        if unit_id not in machine:
            _issue(issues, "violated", "operation_references_unknown_unit", id=bound.operation_id)
        elif unit_id not in selected_unit_ids:
            _issue(
                issues,
                "violated",
                "operation_references_unit_outside_component",
                id=bound.operation_id,
                unit_id=unit_id,
            )
    expected_parameters = set(_index(operation.get("parameters", []), "operation parameters"))
    expected_results = set(_index(operation.get("results", []), "operation results"))
    if {row.identity for row in bound.parameters} != expected_parameters:
        _issue(issues, "incomplete", "operation_parameter_projection_mismatch", id=bound.operation_id)
    if {row.identity for row in bound.results} != expected_results:
        _issue(issues, "incomplete", "operation_result_projection_mismatch", id=bound.operation_id)
    parameter_index = _index(operation.get("parameters", []), "operation parameters")
    result_index = _index(operation.get("results", []), "operation results")
    for value in bound.parameters:
        logical = parameter_index.get(value.identity)
        if logical is not None:
            if value.decoding is not None:
                _issue(
                    issues,
                    "violated",
                    "operation_parameter_has_result_decoding",
                    id=bound.operation_id,
                    value_id=value.identity,
                )
            _check_logical_projection(
                projection=value.projection,
                logical_value=logical,
                types=types,
                operation_parameters=parameter_index,
                expected_phase="entry",
                role="parameter",
                operation_id=bound.operation_id,
                issues=issues,
            )
            if value.projection.kind == "atomic_object":
                _check_atomic_object_projection(
                    projection=value.projection,
                    logical_value=logical,
                    types=types,
                    machine=machine,
                    selected_unit_ids=selected_unit_ids,
                    operation_id=bound.operation_id,
                    issues=issues,
                )
    for value in bound.results:
        logical = result_index.get(value.identity)
        if logical is not None:
            _check_logical_projection(
                projection=value.projection,
                logical_value=logical,
                types=types,
                operation_parameters=parameter_index,
                expected_phase="exit",
                role="result",
                operation_id=bound.operation_id,
                issues=issues,
            )
            if value.projection.kind == "finite_control_target":
                _check_finite_control_target_projection(
                    projection=value.projection,
                    logical_value=logical,
                    operation_parameters=parameter_index,
                    types=types,
                    bound=bound,
                    machine=machine,
                    component_id=component_id,
                    semantic_component_catalog=semantic_component_catalog,
                    issues=issues,
                )
            _check_result_decoding(
                value=value,
                operation_parameters=parameter_index,
                types=types,
                operation_id=bound.operation_id,
                issues=issues,
            )
    state_ids = {row.identity for row in bound.state}
    if state_ids != set(states):
        _issue(issues, "incomplete", "operation_state_inventory_mismatch", id=bound.operation_id)
    if not set(bound.preserved_state_ids) <= state_ids:
        _issue(
            issues,
            "violated",
            "operation_preserved_state_binding_missing",
            id=bound.operation_id,
        )
    for value in bound.state:
        logical = states.get(value.identity)
        if logical is None:
            continue
        _check_logical_projection(
            projection=value.entry,
            logical_value=logical,
            types=types,
            operation_parameters=parameter_index,
            expected_phase="entry",
            role="state",
            operation_id=bound.operation_id,
            issues=issues,
        )
        _check_logical_projection(
            projection=value.exit,
            logical_value=logical,
            types=types,
            operation_parameters=parameter_index,
            expected_phase="exit",
            role="state",
            operation_id=bound.operation_id,
            issues=issues,
        )
    _check_operation_view_aliases(
        bound=bound,
        parameter_index=parameter_index,
        states=states,
        types=types,
        issues=issues,
    )
    expected_effects = set(operation.get("effect_ids", []))
    service_effects = {
        effect_id
        for service_id in operation.get("allowed_service_ids", [])
        for effect_id in services.get(str(service_id), {}).get("effect_ids", [])
    }
    expected_direct_effects = expected_effects - service_effects
    observed_effects = {row.effect_id for row in bound.effects}
    if (
        observed_effects != expected_direct_effects
        or not expected_effects <= set(effects)
    ):
        _issue(issues, "incomplete", "operation_effect_binding_mismatch", id=bound.operation_id)
    if not set(bound.callback_operation_ids) <= set(operations):
        _issue(issues, "violated", "operation_callback_target_unknown", id=bound.operation_id)
    seen_effects: set[tuple[str, str, str, int]] = set()
    for effect in bound.effects:
        unit = machine.get(effect.unit_id)
        if unit is None:
            _issue(issues, "violated", "effect_references_unknown_unit", id=bound.operation_id)
            continue
        if effect.unit_id not in selected_unit_ids:
            _issue(
                issues,
                "violated",
                "effect_references_unit_outside_component",
                id=bound.operation_id,
            )
        reference = (effect.effect_id, effect.unit_id, effect.family, effect.index)
        if reference in seen_effects:
            _issue(
                issues,
                "violated",
                "effect_machine_fact_bound_more_than_once",
                id=bound.operation_id,
            )
        seen_effects.add(reference)
        logical = effects.get(effect.effect_id)
        logical_kind = None if logical is None else logical.get("kind")
        if effect.family not in _LOGICAL_EFFECT_FAMILIES.get(
            str(logical_kind), frozenset()
        ):
            _issue(
                issues,
                "violated",
                "effect_machine_family_incompatible",
                id=bound.operation_id,
                effect_id=effect.effect_id,
                logical_kind=logical_kind,
                machine_family=effect.family,
            )
        try:
            fact = _machine_effect_fact(unit, effect.family, effect.index)
        except ComponentMachineBindingError:
            _issue(
                issues,
                "violated",
                "effect_fact_index_out_of_range",
                id=bound.operation_id,
                effect_id=effect.effect_id,
            )
            continue
        if canonical_sha256_v3(fact) != effect.fact_sha256:
            _issue(
                issues,
                "violated",
                "effect_fact_digest_stale",
                id=bound.operation_id,
                effect_id=effect.effect_id,
            )


def _check_finite_control_target_projection(
    *,
    projection: MachineProjectionV1,
    logical_value: Mapping[str, object],
    operation_parameters: Mapping[str, Mapping[str, object]],
    types: Mapping[str, Mapping[str, object]],
    bound: OperationMachineBindingV1,
    machine: Mapping[str, Mapping[str, object]],
    component_id: str,
    semantic_component_catalog: Mapping[str, object] | None,
    issues: list[dict[str, object]],
) -> None:
    """Bind a logical route result to one exact recovered selector table."""

    payload = projection.payload
    operation_id = bound.operation_id
    unit_id = str(payload["unit_id"])
    selector_id = str(payload["selector_parameter_id"])
    selector_logical = operation_parameters.get(selector_id)
    selector_bound = next(
        (row for row in bound.parameters if row.identity == selector_id), None
    )
    if selector_logical is None or selector_bound is None:
        _issue(
            issues,
            "violated",
            "finite_control_selector_parameter_missing",
            id=operation_id,
        )
        return
    if selector_bound.projection.kind != "register":
        _issue(
            issues,
            "incomplete",
            "finite_control_selector_projection_unsupported",
            id=operation_id,
            observed=selector_bound.projection.kind,
        )
        return
    selector_payload = selector_bound.projection.payload
    selector_width = int(selector_payload["width"])
    selector_register = str(selector_payload["register"])
    expected_index_expression: dict[str, object]
    if selector_width == 32:
        expected_index_expression = {
            "op": "reg",
            "name": selector_register,
            "width": 32,
        }
    else:
        expected_index_expression = {
            "op": "and32",
            "args": [
                {
                    "op": "const",
                    "value": (1 << selector_width) - 1,
                    "width": 32,
                },
                {"op": "reg", "name": selector_register, "width": 32},
            ],
        }
    if unit_id not in bound.exit_unit_ids or unit_id not in machine:
        _issue(
            issues,
            "violated",
            "finite_control_exit_unit_mismatch",
            id=operation_id,
            unit_id=unit_id,
        )
        return
    semantics = _object(machine[unit_id].get("semantics"), "machine semantics")
    outcome = _object(semantics.get("outcome"), "machine outcome")
    if outcome.get("kind") != "indirect_jump":
        _issue(
            issues,
            "violated",
            "finite_control_exit_is_not_indirect_jump",
            id=operation_id,
            unit_id=unit_id,
        )
        return
    if semantic_component_catalog is None:
        _issue(
            issues,
            "incomplete",
            "finite_control_semantic_catalog_missing",
            id=operation_id,
        )
        return
    components = _array(
        semantic_component_catalog.get("components"),
        "semantic component catalog components",
    )
    component_matches = [
        _object(item, "semantic component")
        for item in components
        if isinstance(item, Mapping) and item.get("id") == component_id
    ]
    if len(component_matches) != 1:
        _issue(
            issues,
            "violated",
            "finite_control_component_catalog_mismatch",
            id=operation_id,
        )
        return
    boundary = _object(
        component_matches[0].get("machine_boundary"),
        "finite control machine boundary",
    )
    exit_matches = [
        _object(item, "finite control boundary exit")
        for item in _array(boundary.get("exits"), "component boundary exits")
        if isinstance(item, Mapping)
        and item.get("source_unit_id") == unit_id
        and item.get("kind") == "indirect_jump"
    ]
    if len(exit_matches) != 1:
        _issue(
            issues,
            "violated",
            "finite_control_boundary_exit_mismatch",
            id=operation_id,
            unit_id=unit_id,
        )
        return
    boundary_exit = exit_matches[0]
    inventory = _object(
        boundary_exit.get("target_inventory"),
        "finite control target inventory",
    )
    if (
        inventory.get("closure") != "checked_finite_target_inventory"
        or boundary_exit.get("target_expression") != outcome.get("target")
        or payload.get("target_inventory_sha256")
        != canonical_sha256_v3(inventory)
    ):
        _issue(
            issues,
            "violated",
            "finite_control_target_inventory_mismatch",
            id=operation_id,
            unit_id=unit_id,
        )
        return
    index = _object(inventory.get("index"), "finite control selector index")
    if index.get("expression") != expected_index_expression:
        _issue(
            issues,
            "incomplete",
            "finite_control_selector_expression_unsupported",
            id=operation_id,
            expected=expected_index_expression,
            observed=index.get("expression"),
        )
    entries = [
        _object(item, "finite control inventory entry")
        for item in _array(inventory.get("entries"), "finite control inventory entries")
    ]
    routes = [
        _object(item, "finite control route")
        for item in _array(payload.get("routes"), "finite control routes")
    ]
    observed_routes = [
        (
            int(item["selector_value"]),
            int(item["target_rva"]),
            int(item["target_address"]),
        )
        for item in routes
    ]
    expected_routes = sorted(
        (
            int(item["index"]),
            int(item["target_rva"]),
            int(item["target_address"]),
        )
        for item in entries
    )
    if observed_routes != expected_routes:
        _issue(
            issues,
            "violated",
            "finite_control_route_inventory_mismatch",
            id=operation_id,
        )
    target_to_logical: dict[int, set[int]] = {}
    logical_to_target: dict[int, set[int]] = {}
    logical_type = types.get(str(logical_value.get("type_id")))
    logical_width = (
        None if logical_type is None else _logical_scalar_width(logical_type)
    )
    for route in routes:
        target = int(route["target_rva"])
        logical = int(route["logical_value"])
        target_to_logical.setdefault(target, set()).add(logical)
        logical_to_target.setdefault(logical, set()).add(target)
        if logical_width is not None and logical >= 1 << logical_width:
            _issue(
                issues,
                "violated",
                "finite_control_logical_value_out_of_range",
                id=operation_id,
                logical_value=logical,
            )
    if any(len(values) != 1 for values in target_to_logical.values()) or any(
        len(values) != 1 for values in logical_to_target.values()
    ):
        _issue(
            issues,
            "violated",
            "finite_control_route_mapping_not_bijective",
            id=operation_id,
        )


def _check_logical_projection(
    *,
    projection: MachineProjectionV1,
    logical_value: Mapping[str, object],
    types: Mapping[str, Mapping[str, object]],
    operation_parameters: Mapping[str, Mapping[str, object]],
    expected_phase: str,
    role: str,
    operation_id: str,
    issues: list[dict[str, object]],
) -> None:
    """Check one recursive logical value projection against its portable type."""

    type_id = logical_value.get("type_id")
    logical_type = types.get(str(type_id))
    if logical_type is None:
        _issue(
            issues,
            "violated",
            "projection_references_unknown_logical_type",
            id=operation_id,
            value_id=logical_value.get("id"),
        )
        return
    kind = logical_type.get("kind")
    payload = projection.payload
    if projection.kind == "finite_alternatives":
        alternatives = [
            MachineProjectionV1.parse(item, "finite projection alternative")
            for item in _array(payload.get("alternatives"), "projection alternatives")
        ]
        digests = [canonical_sha256_v3(item.to_payload()) for item in alternatives]
        if len(digests) != len(set(digests)):
            _issue(
                issues,
                "violated",
                "projection_alternatives_duplicated",
                id=operation_id,
                value_id=logical_value.get("id"),
            )
        for alternative in alternatives:
            _check_logical_projection(
                projection=alternative,
                logical_value=logical_value,
                types=types,
                operation_parameters=operation_parameters,
                expected_phase=expected_phase,
                role=role,
                operation_id=operation_id,
                issues=issues,
            )
        return

    if kind in {"scalar", "enum"}:
        if projection.kind == "control_condition":
            if role != "result" or expected_phase != "exit":
                _projection_issue(
                    issues, operation_id, logical_value,
                    "control_condition_projection_role_invalid",
                )
            return
        if projection.kind == "finite_control_target":
            if role != "result" or expected_phase != "exit":
                _projection_issue(
                    issues,
                    operation_id,
                    logical_value,
                    "finite_control_target_projection_role_invalid",
                )
            return
        if projection.kind == "constant" and role == "parameter":
            _projection_issue(
                issues, operation_id, logical_value,
                "constant_parameter_projection_has_no_input_precondition",
            )
            return
        if projection.kind not in {
            "register", "stack", "static_slot", "memory", "constant"
        }:
            _projection_issue(
                issues, operation_id, logical_value,
                "scalar_projection_kind_mismatch",
                observed=projection.kind,
            )
            return
        expected_width = _logical_scalar_width(logical_type)
        observed_width = payload.get("width")
        if observed_width != expected_width:
            _projection_issue(
                issues, operation_id, logical_value,
                "scalar_projection_width_mismatch",
                expected=expected_width,
                observed=observed_width,
            )
        _check_projection_phase(
            projection, expected_phase, operation_id, logical_value, issues
        )
        if projection.kind == "memory":
            _check_address_projection(
                MachineProjectionV1.parse(
                    payload.get("address"), "scalar memory address"
                ),
                expected_phase,
                operation_id,
                logical_value,
                issues,
            )
        return

    if kind == "resource":
        expected_projection = (
            "atomic_object"
            if logical_type.get("resource_kind") == "atomic_object"
            else "resource"
        )
        if projection.kind != expected_projection:
            _projection_issue(
                issues, operation_id, logical_value,
                "resource_projection_kind_mismatch",
                observed=projection.kind,
            )
            return
        if payload.get("resource_kind") != logical_type.get("resource_kind"):
            _projection_issue(
                issues, operation_id, logical_value,
                "resource_projection_identity_mismatch",
            )
        source = MachineProjectionV1.parse(
            payload.get("source"), "resource source projection"
        )
        _check_address_projection(
            source, expected_phase, operation_id, logical_value, issues
        )
        return

    if kind == "callback":
        if projection.kind != "callback_handle":
            _projection_issue(
                issues, operation_id, logical_value,
                "callback_projection_kind_mismatch",
                observed=projection.kind,
            )
            return
        if payload.get("at") != expected_phase:
            _projection_issue(
                issues, operation_id, logical_value,
                "projection_phase_mismatch",
                expected=expected_phase,
                observed=payload.get("at"),
            )
        _check_address_projection(
            MachineProjectionV1.parse(
                payload.get("source"), "callback-handle source"
            ),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )
        return

    if kind in {"reference", "view"}:
        if projection.kind != kind:
            _projection_issue(
                issues,
                operation_id,
                logical_value,
                f"{kind}_projection_kind_mismatch",
                observed=projection.kind,
            )
            return
        if payload.get("at") != expected_phase:
            _projection_issue(
                issues,
                operation_id,
                logical_value,
                "projection_phase_mismatch",
                expected=expected_phase,
                observed=payload.get("at"),
            )
        address_field = "source" if kind == "reference" else "base"
        _check_address_projection(
            MachineProjectionV1.parse(
                payload.get(address_field), f"{kind} address source"
            ),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )
        extent_fields = (
            ("requested_extent",)
            if kind == "reference"
            else ("extent", "requested_extent")
        )
        for extent_field in extent_fields:
            extent = MachineProjectionV1.parse(
                payload.get(extent_field), f"{kind} {extent_field}"
            )
            if kind == "view" and extent_field == "extent" and extent.kind == "origin_remainder":
                continue
            _check_address_projection(
                extent,
                expected_phase,
                operation_id,
                logical_value,
                issues,
            )
        if kind == "view":
            extent_kind = logical_type.get("extent", {}).get("kind")
            extent_projection = MachineProjectionV1.parse(
                payload.get("extent"), "view extent"
            )
            if extent_kind == "nul_terminated" and extent_projection.kind != "origin_remainder":
                _issue(
                    issues,
                    "incomplete",
                    "nul_terminated_view_requires_origin_remainder_bound",
                    id=operation_id,
                    value_id=logical_value.get("id"),
                )
        return

    if kind == "bytes":
        if projection.kind != "bytes_view":
            _projection_issue(
                issues, operation_id, logical_value,
                "bytes_projection_kind_mismatch",
                observed=projection.kind,
            )
            return
        if payload.get("at") != expected_phase:
            _projection_issue(
                issues, operation_id, logical_value,
                "projection_phase_mismatch",
                expected=expected_phase,
                observed=payload.get("at"),
            )
        extent_id = payload.get("extent_id")
        if extent_id != logical_type.get("extent_parameter_id"):
            _projection_issue(
                issues, operation_id, logical_value,
                "bytes_projection_extent_mismatch",
                expected=logical_type.get("extent_parameter_id"),
                observed=extent_id,
            )
        if not logical_type.get("nul_terminated"):
            extent = operation_parameters.get(str(extent_id))
            extent_type = None if extent is None else types.get(str(extent.get("type_id")))
            if (
                extent_type is None
                or extent_type.get("kind") != "scalar"
                or not str(extent_type.get("c_type", "")).startswith("uint")
            ):
                _projection_issue(
                    issues, operation_id, logical_value,
                    "bytes_projection_extent_not_unsigned_scalar",
                )
        base = MachineProjectionV1.parse(payload.get("base"), "bytes-view base")
        _check_address_projection(
            base, expected_phase, operation_id, logical_value, issues
        )
        return

    if kind == "record":
        if projection.kind != "record_view":
            _projection_issue(
                issues, operation_id, logical_value,
                "record_projection_kind_mismatch",
                observed=projection.kind,
            )
            return
        if payload.get("at") != expected_phase:
            _projection_issue(
                issues, operation_id, logical_value,
                "projection_phase_mismatch",
                expected=expected_phase,
                observed=payload.get("at"),
            )
        logical_fields = _index(logical_type.get("fields"), "logical record fields")
        projected_fields = _index(payload.get("fields"), "record projection fields")
        if set(logical_fields) != set(projected_fields):
            _projection_issue(
                issues, operation_id, logical_value,
                "record_projection_field_inventory_mismatch",
            )
            return
        for field_id, field in logical_fields.items():
            field_type = types.get(str(field.get("type_id")))
            if field_type is None:
                continue
            if field_type.get("kind") not in {"scalar", "enum", "record"}:
                _issue(
                    issues,
                    "incomplete",
                    "aggregate_projection_profile_unsupported",
                    id=operation_id,
                    value_id=logical_value.get("id"),
                    field_id=field_id,
                    logical_kind=field_type.get("kind"),
                )
                continue
            raw_projection = projected_fields[field_id].get("projection")
            _check_logical_projection(
                projection=MachineProjectionV1.parse(
                    raw_projection, f"record field {field_id} projection"
                ),
                logical_value=field,
                types=types,
                operation_parameters=operation_parameters,
                expected_phase=expected_phase,
                role=role,
                operation_id=operation_id,
                issues=issues,
            )
        return

    _issue(
        issues,
        "incomplete",
        "logical_projection_profile_unsupported",
        id=operation_id,
        value_id=logical_value.get("id"),
        logical_kind=kind,
    )


def _check_atomic_object_projection(
    *,
    projection: MachineProjectionV1,
    logical_value: Mapping[str, object],
    types: Mapping[str, Mapping[str, object]],
    machine: Mapping[str, Mapping[str, object]],
    selected_unit_ids: set[str],
    operation_id: str,
    issues: list[dict[str, object]],
) -> None:
    """Bind one opaque capability to one authoritative machine RMW action."""

    payload = projection.payload
    logical_type = types.get(str(logical_value.get("type_id")))
    if logical_type is None or logical_type.get("resource_kind") != "atomic_object":
        _projection_issue(
            issues,
            operation_id,
            logical_value,
            "atomic_projection_requires_atomic_resource",
        )
        return
    unit_id = str(payload.get("unit_id"))
    unit = machine.get(unit_id)
    if unit is None or unit_id not in selected_unit_ids:
        _projection_issue(
            issues,
            operation_id,
            logical_value,
            "atomic_projection_unit_outside_component",
        )
        return
    semantics = _object(unit.get("semantics"), "atomic projection semantics")
    graph = _object(semantics.get("memory_actions"), "atomic memory-action graph")
    authority = _object(graph.get("authority"), "atomic graph authority")
    if graph.get("status") != "complete" or authority.get("authoritative") is not True:
        _projection_issue(
            issues,
            operation_id,
            logical_value,
            "atomic_projection_graph_not_authoritative",
        )
        return
    matches = [
        row
        for row in _array(graph.get("actions"), "atomic actions")
        if isinstance(row, Mapping) and row.get("id") == payload.get("action_id")
    ]
    if len(matches) != 1:
        _projection_issue(
            issues,
            operation_id,
            logical_value,
            "atomic_projection_action_missing",
        )
        return
    action = matches[0]
    source = MachineProjectionV1.parse(payload.get("source"), "atomic source")
    source_payload = source.payload
    expected_address = action.get("address")
    if source.kind != "constant" or expected_address != {
        "op": "const",
        "value": source_payload.get("value"),
        "width": source_payload.get("width"),
    }:
        _projection_issue(
            issues,
            operation_id,
            logical_value,
            "atomic_projection_address_mismatch",
        )
    if (
        action.get("kind") != "rmw"
        or action.get("operation") not in {"compare_exchange", "exchange"}
        or action.get("width_bytes") != payload.get("width")
        or graph.get("profile_id") != payload.get("profile_id")
    ):
        _projection_issue(
            issues,
            operation_id,
            logical_value,
            "atomic_projection_action_mismatch",
        )


def _check_address_projection(
    projection: MachineProjectionV1,
    expected_phase: str,
    operation_id: str,
    logical_value: Mapping[str, object],
    issues: list[dict[str, object]],
) -> None:
    payload = projection.payload
    if projection.kind == "finite_alternatives":
        alternatives = [
            MachineProjectionV1.parse(item, "address alternative")
            for item in _array(payload.get("alternatives"), "address alternatives")
        ]
        digests = [canonical_sha256_v3(item.to_payload()) for item in alternatives]
        if len(digests) != len(set(digests)):
            _projection_issue(
                issues, operation_id, logical_value,
                "projection_alternatives_duplicated",
            )
        for alternative in alternatives:
            _check_address_projection(
                alternative, expected_phase, operation_id, logical_value, issues
            )
        return
    if projection.kind == "offset":
        if payload.get("at") != expected_phase:
            _projection_issue(
                issues, operation_id, logical_value,
                "projection_phase_mismatch",
                expected=expected_phase,
                observed=payload.get("at"),
            )
        _check_address_projection(
            MachineProjectionV1.parse(payload.get("base"), "offset base"),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )
        return
    if projection.kind == "resource":
        _check_address_projection(
            MachineProjectionV1.parse(payload.get("source"), "resource source"),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )
        return
    if projection.kind == "atomic_object":
        _check_address_projection(
            MachineProjectionV1.parse(payload.get("source"), "atomic source"),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )
        return
    if projection.kind == "callback_handle":
        _check_address_projection(
            MachineProjectionV1.parse(payload.get("source"), "callback source"),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )
        return
    if projection.kind not in {
        "register", "stack", "static_slot", "memory", "constant"
    }:
        _projection_issue(
            issues, operation_id, logical_value,
            "address_projection_kind_unsupported",
            observed=projection.kind,
        )
        return
    if payload.get("width") != 32:
        _projection_issue(
            issues, operation_id, logical_value,
            "address_projection_width_mismatch",
            expected=32,
            observed=payload.get("width"),
        )
    _check_projection_phase(
        projection, expected_phase, operation_id, logical_value, issues
    )
    if projection.kind == "memory":
        _check_address_projection(
            MachineProjectionV1.parse(payload.get("address"), "memory address"),
            expected_phase,
            operation_id,
            logical_value,
            issues,
        )


def _check_projection_phase(
    projection: MachineProjectionV1,
    expected_phase: str,
    operation_id: str,
    logical_value: Mapping[str, object],
    issues: list[dict[str, object]],
) -> None:
    observed = projection.payload.get("at")
    if projection.kind == "constant":
        return
    if observed != expected_phase:
        _projection_issue(
            issues, operation_id, logical_value,
            "projection_phase_mismatch",
            expected=expected_phase,
            observed=observed,
        )


def _origin_authority(value: object, context: str) -> Mapping[str, object]:
    row = _object(value, context)
    _exact(row, {"id", "kind", "lifetime"}, context)
    _identifier(row["id"], f"{context} id")
    if row["kind"] not in {
        "image", "static", "stack", "process", "external", "tls", "resource"
    }:
        raise ComponentMachineBindingError(f"{context} kind is unsupported")
    if row["lifetime"] not in {
        "process", "image", "invocation", "thread", "allocation", "resource"
    }:
        raise ComponentMachineBindingError(f"{context} lifetime is unsupported")
    return row


def _machine_effect_fact(
    unit: Mapping[str, object], family: str, index: int
) -> Mapping[str, object]:
    field = _EFFECT_FAMILIES.get(family)
    if field is None:
        raise ComponentMachineBindingError(
            f"machine effect family {family!r} is unsupported"
        )
    semantics = _object(unit.get("semantics"), "machine semantics")
    values = _array(semantics.get(field, []), f"machine {field}")
    if index >= len(values):
        raise ComponentMachineBindingError(
            f"machine effect index {index} is outside {family}"
        )
    return _object(values[index], f"machine {family} fact")


def _machine_units(data: bytes) -> dict[str, Mapping[str, object]]:
    result: dict[str, Mapping[str, object]] = {}
    for line_number, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            continue
        row = _object(json.loads(line), f"machine-IR line {line_number}")
        if row.get("format") != _MACHINE_IR or row.get("record_kind") != "unit":
            raise ComponentMachineBindingError("machine binding requires exact machine-IR v2 units")
        identity = _text(row.get("id"), "machine unit id")
        if identity in result:
            raise ComponentMachineBindingError("machine IR contains duplicate unit ids")
        result[identity] = row
    if not result:
        raise ComponentMachineBindingError("machine IR has no units")
    return result


def _interface_payload(value: Path | str | Mapping[str, object] | object) -> dict[str, object]:
    payload = _load(value, "portable component interface")
    if payload.get("format") not in _INTERFACE_FORMATS:
        raise ComponentMachineBindingError(
            "machine binding requires portable interface v2 or v3"
        )
    return _checked_interface_payload(payload)


from .machine_binding_schema import (
    _array,
    _artifact_id,
    _digest,
    _exact,
    _identifier,
    _identifiers,
    _index,
    _issue,
    _load,
    _object,
    _phase,
    _rows,
    _strings,
    _text,
    _uint,
    _unique,
    _width,
)


__all__ = [
    "COMPONENT_MACHINE_BINDING_DECLARATION_V2",
    "COMPONENT_MACHINE_BINDING_DECLARATION_V3",
    "COMPONENT_MACHINE_BINDING_RECEIPT_V1",
    "COMPONENT_MACHINE_BINDING_V1",
    "ComponentMachineBindingError",
    "ComponentMachineBindingV1",
    "MachineProjectionV1",
    "MachineServiceEventV1",
    "check_component_machine_binding",
    "create_component_machine_binding_v1",
    "materialize_component_machine_binding",
]
