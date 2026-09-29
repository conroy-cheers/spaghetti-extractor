"""Typed bindings between portable component operations and exact machine IR.

Portable interfaces intentionally contain no x86 facts.  This module is the
only component-layer artifact allowed to relate logical values to registers,
stack slots, image storage, callbacks, resources, and exact external sites.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .finite_word_transducers import FiniteWordMapError, parse_finite_word_map
from .machine_binding_schema import (
    ComponentMachineBindingError,
    _array,
    _artifact_id,
    _digest,
    _exact,
    _identifier,
    _identifiers,
    _object,
    _phase,
    _rows,
    _strings,
    _text,
    _uint,
    _unique,
    _width,
    parse_fault_outcomes,
)
from .value_codec import (
    ValueCodecError,
    copy_value_codec_expression,
    parse_value_codec_expression,
)


_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"})
_FLAGS = frozenset({"cf", "zf", "sf", "of", "pf", "df"})
_EFFECT_FAMILIES = {
    "memory_event": "memory_events",
    "external_event": "external_events",
    "fault": "faults",
    "register_write": "register_writes",
    "flag_write": "flag_writes",
    "edge_condition": "edge_conditions",
}


def _origin_authority(value: object, context: str) -> Mapping[str, object]:
    row = _object(value, context)
    _exact(row, {"id", "kind", "lifetime"}, context)
    _identifier(row["id"], f"{context} id")
    if row["kind"] not in {
        "image",
        "static",
        "stack",
        "process",
        "external",
        "tls",
        "resource",
    }:
        raise ComponentMachineBindingError(f"{context} kind is unsupported")
    if row["lifetime"] not in {
        "process",
        "image",
        "invocation",
        "thread",
        "allocation",
        "resource",
    }:
        raise ComponentMachineBindingError(f"{context} lifetime is unsupported")
    return row


@dataclass(frozen=True)
class MachineProjectionV1:
    kind: str
    payload: Mapping[str, object]

    @classmethod
    def parse(
        cls, value: object, context: str = "machine projection"
    ) -> "MachineProjectionV1":
        row = _object(value, context)
        kind = _text(row.get("kind"), f"{context} kind")
        if kind == "register":
            _exact(row, {"kind", "register", "width", "at"}, context)
            register = _text(row["register"], f"{context} register")
            if register not in _REGISTERS:
                raise ComponentMachineBindingError(f"{context} register is unsupported")
            _width(row["width"], context)
            _phase(row["at"], context)
        elif kind == "flag":
            _exact(row, {"kind", "flag", "at"}, context)
            flag = _text(row['flag'], f'{context} flag')
            if flag not in _FLAGS:
                raise ComponentMachineBindingError(f"{context} flag is unsupported")
            _phase(row['at'], context)
        elif kind == "stack":
            _exact(row, {"kind", "offset", "width", "at"}, context)
            if not isinstance(row["offset"], int) or isinstance(row["offset"], bool):
                raise ComponentMachineBindingError(f"{context} stack offset is invalid")
            _width(row["width"], context)
            _phase(row["at"], context)
        elif kind == "service_output":
            _exact(
                row,
                {"kind", "call_index", "output_index", "fallback"},
                context,
            )
            for field in ("call_index", "output_index"):
                if (
                    not isinstance(row[field], int)
                    or isinstance(row[field], bool)
                    or row[field] < 0
                    or row[field] > 255
                ):
                    raise ComponentMachineBindingError(
                        f"{context} {field.replace('_', ' ')} is invalid"
                    )
            fallback = cls.parse(row["fallback"], f"{context} fallback")
            if fallback.kind not in {"register", "stack", "static_slot"}:
                raise ComponentMachineBindingError(
                    f"{context} fallback must be a concrete word projection"
                )
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
                    *({"proof_evidence"} if "proof_evidence" in row else set()),
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
            if "proof_evidence" not in row:
                return cls(kind, json.loads(json.dumps(row)))
            evidence = _object(
                row["proof_evidence"], f"{context} proof evidence"
            )
            _exact(
                evidence,
                {
                    "unit_id",
                    "source_rva",
                    "source_unit_ir_sha256",
                    "outcome_expression_sha256",
                    "index_expression_sha256",
                    "selector_domain_sha256",
                    "index_provenance",
                    "pe_sha256",
                    "image_base",
                    "image_size",
                    "table",
                    "routes",
                    "route_inventory_sha256",
                },
                f"{context} proof evidence",
            )
            index_provenance = _object(
                evidence["index_provenance"],
                f"{context} proof evidence index provenance",
            )
            if index_provenance.get("kind") != "direct_index":
                raise ComponentMachineBindingError(
                    f"{context} remapped finite-control selectors lack a proof model"
                )
            _exact(
                index_provenance,
                {"kind"},
                f"{context} proof evidence index provenance",
            )
            for field in (
                "source_unit_ir_sha256",
                "outcome_expression_sha256",
                "index_expression_sha256",
                "selector_domain_sha256",
                "pe_sha256",
                "route_inventory_sha256",
            ):
                _digest(evidence[field], f"{context} proof evidence {field}")
            if (
                evidence["unit_id"] != row["unit_id"]
                or evidence["route_inventory_sha256"]
                != row["target_inventory_sha256"]
            ):
                raise ComponentMachineBindingError(
                    f"{context} proof evidence names another route inventory"
                )
            _uint(evidence["source_rva"], f"{context} proof source RVA")
            image_base = _uint(
                evidence["image_base"], f"{context} proof image base"
            )
            image_size = _uint(
                evidence["image_size"], f"{context} proof image size"
            )
            if image_size == 0 or image_base + image_size > 0x100000000:
                raise ComponentMachineBindingError(
                    f"{context} proof image geometry is malformed"
                )
            evidence_routes = _array(
                evidence["routes"], f"{context} proof routes"
            )
            evidence_projection: list[tuple[int, int, int]] = []
            for index, raw_evidence_route in enumerate(evidence_routes):
                evidence_route = _object(
                    raw_evidence_route, f"{context} proof route {index}"
                )
                _exact(
                    evidence_route,
                    {
                        "selector_value",
                        "entry_address",
                        "entry_rva",
                        "bytes_le",
                        "target_rva",
                        "target_address",
                    },
                    f"{context} proof route {index}",
                )
                raw_bytes = _array(
                    evidence_route["bytes_le"],
                    f"{context} proof route {index} bytes",
                )
                if len(raw_bytes) != 4 or any(
                    not isinstance(byte, int)
                    or isinstance(byte, bool)
                    or byte < 0
                    or byte > 255
                    for byte in raw_bytes
                ):
                    raise ComponentMachineBindingError(
                        f"{context} proof route {index} bytes are malformed"
                    )
                evidence_projection.append(
                    (
                        _uint(
                            evidence_route["selector_value"],
                            f"{context} proof route {index} selector",
                        ),
                        _uint(
                            evidence_route["target_rva"],
                            f"{context} proof route {index} target RVA",
                        ),
                        _uint(
                            evidence_route["target_address"],
                            f"{context} proof route {index} target address",
                        ),
                    )
                )
            if evidence_projection != [
                (selector, target_rva, target_address)
                for selector, _logical, target_rva, target_address in parsed_routes
            ]:
                raise ComponentMachineBindingError(
                    f"{context} proof routes differ from semantic routes"
                )
            evidence_core = dict(evidence)
            evidence_digest = evidence_core.pop("route_inventory_sha256")
            if evidence_digest != canonical_sha256_v3(evidence_core):
                raise ComponentMachineBindingError(
                    f"{context} proof evidence digest is stale"
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
            parsed = [
                cls.parse(item, f"{context} alternative") for item in alternatives
            ]
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
                raise ComponentMachineBindingError(f"{context} byte offset is invalid")
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
    encoding: Mapping[str, object] | None = None
    fault_outcomes: tuple[Mapping[str, object], ...] = ()
    exit_projection: MachineProjectionV1 | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "LogicalMachineValueV1":
        row = _object(value, context)
        if set(row) - {"fault_outcomes", "exit_projection"} not in (
            {"id", "projection"},
            {"id", "projection", "decoding"},
            {"id", "projection", "encoding"},
            {"id", "projection", "decoding", "encoding"},
        ):
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
        encoding = row.get("encoding")
        parsed_encoding = None
        if encoding is not None:
            try:
                parsed_encoding, sort = parse_value_codec_expression(
                    encoding, f"{context} encoding"
                )
            except ValueCodecError as exc:
                raise ComponentMachineBindingError(str(exc)) from exc
            if sort != "word":
                raise ComponentMachineBindingError(
                    f"{context} encoding must produce a word"
                )
        fault_outcomes = parse_fault_outcomes(row["fault_outcomes"], f"{context} fault outcomes") if "fault_outcomes" in row else ()
        projection = MachineProjectionV1.parse(row["projection"], f"{context} projection")
        exit_projection = None
        if 'exit_projection' in row:
            exit_projection = MachineProjectionV1.parse(row['exit_projection'], f'{context} parameter exit')
            target = exit_projection.payload
            if (target.get('kind') != 'register' or target.get('at') != 'exit' or
                    target.get('width') != 32 or target.get('register') not in
                    {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'} or
                    parsed_encoding is not None or parsed_decoding is not None or fault_outcomes):
                raise ComponentMachineBindingError(f'{context} parameter exit requires an unencoded general register')
            from .machine_overlay_result_views import checked_nullable_input_projection
            checked_nullable_input_projection(projection.payload)
        if fault_outcomes and (projection.kind not in {"register", "stack"} or projection.payload["at"] != "exit"
                               or projection.payload["width"] != 32
                               or parsed_decoding is not None or parsed_encoding is not None):
            raise ComponentMachineBindingError(f"{context} fault outcomes require an unencoded exit word")
        return cls(
            _identifier(row["id"], f"{context} id"),
            projection,
            parsed_decoding,
            parsed_encoding,
            fault_outcomes,
            exit_projection,
        )

    def to_payload(self) -> dict[str, object]:
        result = {"id": self.identity, "projection": self.projection.to_payload()}
        if self.decoding is not None:
            result["decoding"] = copy_value_codec_expression(self.decoding)
        if self.encoding is not None:
            result["encoding"] = copy_value_codec_expression(self.encoding)
        if self.fault_outcomes:
            result["fault_outcomes"] = [dict(row) for row in self.fault_outcomes]
        if self.exit_projection is not None:
            result['exit_projection'] = self.exit_projection.to_payload()
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

    @classmethod
    def parse_rows(cls, value: object, context: str) -> tuple["MachineEffectReferenceV1", ...]:
        rows = tuple(cls.parse(item, f"{context} {index}")
                     for index, item in enumerate(_array(value, context)))
        # A logical effect can occur at several instructions or branches. Its
        # identity alone cannot distinguish the referenced machine facts.
        keys = [(row.effect_id, row.unit_id, row.family, row.index) for row in rows]
        if keys != sorted(set(keys)):
            raise ComponentMachineBindingError(
                f"{context} fact references must be unique and canonically ordered")
        return rows

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
        if any("fault_outcomes" in item for item in _array(row.get("parameters"), f"{context} parameters")
               if isinstance(item, Mapping)):
            raise ComponentMachineBindingError(f"{context} fault outcomes are only supported on results")
        if any('exit_projection' in item for item in _array(row.get('results'), f'{context} results')
               if isinstance(item, Mapping)):
            raise ComponentMachineBindingError(f'{context} exit projections are only supported on parameters')
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
            entry_unit_ids=_strings(
                row["entry_unit_ids"], f"{context} entries", nonempty=True
            ),
            exit_unit_ids=_strings(
                row["exit_unit_ids"], f"{context} exits", nonempty=True
            ),
            parameters=_rows(
                LogicalMachineValueV1.parse, row["parameters"], f"{context} parameter"
            ),
            results=_rows(
                LogicalMachineValueV1.parse, row["results"], f"{context} result"
            ),
            state=_rows(StateMachineBindingV1.parse, row["state"], f"{context} state"),
            preserved_state_ids=_identifiers(
                row["preserved_state_ids"], f"{context} preserved state"
            ),
            effects=MachineEffectReferenceV1.parse_rows(row["effects"], f"{context} effect"),
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


def _validate_argument_transducers(value: object, context: str) -> None:
    transducers = _array(value, f"{context} argument transducers")
    if not transducers:
        raise ComponentMachineBindingError(f"{context} argument transducers are empty")
    for index, raw_transducer in enumerate(transducers):
        transducer = _object(raw_transducer, f"{context} argument transducer {index}")
        transducer_context = f"{context} argument transducer {index}"
        transducer_kind = transducer.get("kind")
        if transducer_kind == "constant":
            _exact(transducer, {"kind", "value"}, transducer_context)
            word = _uint(transducer["value"], f"{transducer_context} value")
            if word > 0xFFFFFFFF:
                raise ComponentMachineBindingError(
                    f"{transducer_context} value exceeds a word"
                )
            continue
        if transducer_kind == "logical_argument":
            _exact(transducer, {"kind", "parameter_index"}, transducer_context)
            _uint(
                transducer["parameter_index"],
                f"{transducer_context} parameter",
            )
            continue
        if transducer_kind == "record_field":
            _exact(
                transducer,
                {"kind", "parameter_index", "field_id"},
                transducer_context,
            )
            _uint(
                transducer["parameter_index"],
                f"{transducer_context} parameter",
            )
            _identifier(
                transducer["field_id"],
                f"{transducer_context} field",
            )
            continue
        if transducer_kind == "aggregate_result":
            _exact(transducer, {"kind", "cell_id"}, transducer_context)
            _identifier(transducer["cell_id"], f"{transducer_context} cell id")
            continue
        if transducer_kind == "finite_word_map":
            try:
                parse_finite_word_map(transducer, context=transducer_context)
            except FiniteWordMapError as exc:
                raise ComponentMachineBindingError(str(exc)) from exc
            continue
        if transducer_kind == "local_cell":
            fields = {"kind", "cell_id", "initial_words"}
            if "local_cell_relation_sha256" in transducer:
                fields.add("local_cell_relation_sha256")
            _exact(
                transducer,
                fields,
                transducer_context,
            )
            _identifier(transducer["cell_id"], f"{transducer_context} cell id")
            words = _array(
                transducer["initial_words"],
                f"{transducer_context} initial words",
            )
            if not words or len(words) > 256:
                raise ComponentMachineBindingError(
                    f"{transducer_context} requires 1..256 initial words"
                )
            for word_index, word in enumerate(words):
                if isinstance(word, Mapping):
                    _exact(
                        word,
                        {"kind", "projection"},
                        f"{transducer_context} initial word {word_index}",
                    )
                    if word.get("kind") != "entry_projection":
                        raise ComponentMachineBindingError(
                            f"{transducer_context} initial word {word_index} kind is unsupported"
                        )
                    projection = MachineProjectionV1.parse(
                        word.get("projection"),
                        f"{transducer_context} initial word {word_index} projection",
                    )
                    if (
                        projection.kind not in {"constant", "register", "stack"}
                        or projection.payload.get("width") != 32
                        or (
                            projection.kind != "constant"
                            and projection.payload.get("at") != "entry"
                        )
                    ):
                        raise ComponentMachineBindingError(
                            f"{transducer_context} initial word {word_index} projection is unsupported"
                        )
                elif word is not None:
                    _uint(
                        word,
                        f"{transducer_context} initial word {word_index}",
                    )
            if "local_cell_relation_sha256" in transducer:
                _digest(
                    transducer["local_cell_relation_sha256"],
                    f"{transducer_context} local-cell relation",
                )
            elif any(word is None for word in words):
                raise ComponentMachineBindingError(
                    f"{transducer_context} partial initialization needs a checked relation"
                )
            continue
        if transducer_kind == "out_interface":
            _exact(
                transducer,
                {
                    "kind",
                    "parameter_index",
                    "out_interface_relation_sha256",
                },
                transducer_context,
            )
            _uint(
                transducer["parameter_index"],
                f"{transducer_context} parameter",
            )
            _digest(
                transducer["out_interface_relation_sha256"],
                f"{transducer_context} relation",
            )
            continue
        raise ComponentMachineBindingError(f"{transducer_context} kind is unsupported")


def _validate_service_result_projection(value: object, context: str) -> None:
    row = _object(value, context)
    if row.get("kind") == "local_cell_record":
        _exact(row, {"kind", "cell_id", "fields"}, context)
        _identifier(row["cell_id"], f"{context} cell id")
        fields = _array(row["fields"], f"{context} fields")
        identities: list[str] = []
        for index, raw_field in enumerate(fields):
            field = _object(raw_field, f"{context} field {index}")
            _exact(field, {"id", "word_index"}, f"{context} field {index}")
            identities.append(
                _identifier(field["id"], f"{context} field {index} id")
            )
            _uint(field["word_index"], f"{context} field {index} word")
        if not identities or len(identities) != len(set(identities)):
            raise ComponentMachineBindingError(
                f"{context} fields are empty or duplicated"
            )
        return
    if row.get("kind") != "local_cell_word":
        MachineProjectionV1.parse(value, context)
        return
    _exact(row, {"kind", "cell_id", "word_index"}, context)
    _identifier(row["cell_id"], f"{context} cell id")
    _uint(row["word_index"], f"{context} word index")


def _validate_service_event_selectors(value: object, context: str) -> None:
    events = tuple(
        _object(item, f"{context} event {index}")
        for index, item in enumerate(_array(value, f"{context} events"))
    )
    if not events:
        raise ComponentMachineBindingError(f"{context} event inventory is empty")
    refs: list[tuple[str, int]] = []
    for index, event in enumerate(events):
        event_context = f"{context} event {index}"
        _exact(event, {"unit_id", "event_index"}, event_context)
        refs.append(
            (
                _text(event["unit_id"], f"{event_context} unit id"),
                _uint(event["event_index"], f"{event_context} event index"),
            )
        )
    if refs != sorted(refs) or len(refs) != len(set(refs)):
        raise ComponentMachineBindingError(
            f"{context} events must be unique and ordered"
        )


def external_target_sampling(value: object, *, has_target: bool) -> str:
    """The address projection and the time of its evaluation are independent."""
    if value not in ("service_call", "operation_entry") or (
        value == "operation_entry" and not has_target
    ):
        raise ComponentMachineBindingError(
            "external target sampling requires service_call or operation_entry with a target projection"
        )
    return str(value)


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
        if kind == "external_call":
            fields = {"kind", "events", "identity"}
            if "target_projection" in provider:
                fields.add("target_projection")
            if "target_sampling" in provider:
                fields.add("target_sampling")
                if "target_projection" not in provider:
                    raise ComponentMachineBindingError("target sampling requires a target projection")
                external_target_sampling(provider["target_sampling"], has_target=True)
            if "result_projection" in provider:
                fields.add("result_projection")
            if "argument_authority_selectors" in provider:
                fields.add("argument_authority_selectors")
            if "argument_transducers" in provider:
                fields.add("argument_transducers")
            _exact(provider, fields, f"{context} provider")
            _validate_service_event_selectors(provider["events"], context)
            identity = _object(provider["identity"], f"{context} import identity")
            _exact(identity, {"dll", "symbol", "ordinal"}, f"{context} import identity")
            _text(identity["dll"], f"{context} import DLL")
            symbol = identity["symbol"]
            ordinal = identity["ordinal"]
            if (symbol is None) == (ordinal is None):
                raise ComponentMachineBindingError(
                    f"{context} import identity requires exactly one symbol or ordinal"
                )
            if symbol is not None:
                _text(symbol, f"{context} import symbol")
            if ordinal is not None:
                _uint(ordinal, f"{context} import ordinal")
            if "target_projection" in provider:
                target = MachineProjectionV1.parse(
                    provider["target_projection"],
                    f"{context} captured external target",
                )
                if (
                    target.kind not in {"register", "stack", "static_slot"}
                    or target.payload.get("width") != 32
                    or target.payload.get("at") != "entry"
                ):
                    raise ComponentMachineBindingError(
                        f"{context} captured external target must be a "
                        "32-bit entry register, stack or image-slot projection"
                    )
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
            if "argument_transducers" in provider:
                _validate_argument_transducers(
                    provider["argument_transducers"], context
                )
            if "result_projection" in provider:
                _validate_service_result_projection(
                    provider["result_projection"],
                    f"{context} external result projection",
                )
        elif kind == "interface_method":
            fields = {
                "kind",
                "events",
                "method_contract_sha256",
            }
            if "argument_transducers" in provider:
                fields.add("argument_transducers")
            if "result_projection" in provider:
                fields.add("result_projection")
            _exact(
                provider,
                fields,
                f"{context} provider",
            )
            _validate_service_event_selectors(provider["events"], context)
            _digest(
                provider["method_contract_sha256"],
                f"{context} interface-method contract",
            )
            if "argument_transducers" in provider:
                _validate_argument_transducers(
                    provider["argument_transducers"], context
                )
            if "result_projection" in provider:
                _validate_service_result_projection(
                    provider["result_projection"],
                    f"{context} interface-method result projection",
                )
        elif kind == "machine_events":
            _exact(provider, {"kind", "events"}, f"{context} provider")
            events = tuple(
                MachineServiceEventV1.parse(item, f"{context} machine event {index}")
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
                        _array(
                            provider["events"], f"{context} component-operation events"
                        )
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
            raise ComponentMachineBindingError(
                f"{context} provider kind is unsupported"
            )
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
class ProofKernelMachineBinding:
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
    def parse(cls, value: object) -> "ProofKernelMachineBinding":
        row = _object(value, "component machine binding")
        _exact(
            row,
            {
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
        binary = _object(row["binary"], "component machine-binding binary")
        interface = _object(row["interface"], "component machine-binding interface")
        _exact(
            binary,
            {"pe_sha256", "machine_ir_sha256"},
            "component machine-binding binary",
        )
        _exact(interface, {"id", "sha256"}, "component machine-binding interface")
        core = dict(row)
        observed = _digest(core.pop("binding_sha256"), "component binding digest")
        if canonical_sha256_v3(core) != observed:
            raise ComponentMachineBindingError(
                "component machine-binding digest is stale"
            )
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
            machine_ir_sha256=_digest(
                binary["machine_ir_sha256"], "component machine-IR digest"
            ),
            interface_id=_identifier(interface["id"], "component interface id"),
            interface_sha256=_digest(interface["sha256"], "component interface digest"),
            unit_ids=_strings(
                row["unit_ids"], "component machine units", nonempty=True
            ),
            operations=operations,
            services=services,
            binding_sha256=observed,
        )

    def to_payload(self) -> dict[str, object]:
        core = {
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


def create_proof_kernel_machine_binding(**values: object) -> dict[str, object]:
    core = dict(values)
    return {**core, "binding_sha256": canonical_sha256_v3(core)}


__all__ = [
    "ComponentMachineBindingError",
    "MachineProjectionV1",
    "MachineServiceEventV1",
    "ProofKernelMachineBinding",
    "create_proof_kernel_machine_binding",
]
