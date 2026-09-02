"""Checked logical-state relations at exact inductive machine cutpoints."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .inductive_receipts import CheckedInductiveMachineReceiptV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelComponentInterface
from .machine_binding import MachineProjectionV1
from .value_codec import (
    ValueCodecError,
    parse_value_codec_expression,
    value_codec_expression_references,
)


INDUCTIVE_CUTPOINT_RELATION_V1 = (
    "spaghetti-extractor-inductive-cutpoint-relation-v1"
)

_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class InductiveRelationError(ValueError):
    """A cutpoint relation is malformed, stale, or incomplete."""


def _object(value: object, fields: set[str], context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise InductiveRelationError(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InductiveRelationError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _ID.fullmatch(result) is None:
        raise InductiveRelationError(f"{context} is not canonical")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise InductiveRelationError(f"{context} must be a SHA-256 digest")
    return result


@dataclass(frozen=True)
class CutpointValueRelationV1:
    kind: str
    identity: str
    mode: str
    projection: MachineProjectionV1 | None
    encoding: Mapping[str, object] | None
    decoding: Mapping[str, object] | None

    @classmethod
    def parse(cls, value: object, context: str) -> "CutpointValueRelationV1":
        row = _object(
            value,
            {"kind", "id", "mode", "projection", "encoding", "decoding"},
            context,
        )
        kind = _text(row["kind"], f"{context} kind")
        if kind not in {"parameter", "source_state"}:
            raise InductiveRelationError(f"{context} kind is unsupported")
        mode = _text(row["mode"], f"{context} mode")
        if mode == "logical_carry":
            if kind != "source_state" or any(
                row[field] is not None
                for field in ("projection", "encoding", "decoding")
            ):
                raise InductiveRelationError(
                    f"{context} logical carry must be an unprojected source state"
                )
            return cls(
                kind,
                _identifier(row["id"], f"{context} id"),
                mode,
                None,
                None,
                None,
            )
        if mode == "logical_definition":
            if (
                kind != "source_state"
                or row["projection"] is not None
                or row["encoding"] is None
                or row["decoding"] is not None
            ):
                raise InductiveRelationError(
                    f"{context} logical definition must be an unprojected source state"
                )
            expression, sort = _parse_relation_expression(
                row["encoding"], f"{context} logical definition"
            )
            if sort != "word":
                raise InductiveRelationError(
                    f"{context} logical definition must be a word"
                )
            return cls(
                kind,
                _identifier(row["id"], f"{context} id"),
                mode,
                None,
                expression,
                None,
            )
        if mode != "machine_codec":
            raise InductiveRelationError(f"{context} mode is unsupported")
        if row["projection"] is None or row["encoding"] is None:
            raise InductiveRelationError(
                f"{context} machine codec requires projection and encoding"
            )
        encoding, encoding_sort = _parse_relation_expression(
            row["encoding"], f"{context} encoding"
        )
        if encoding_sort != "word":
            raise InductiveRelationError(f"{context} encoding must be a word")
        decoding = None
        if kind == "source_state":
            if row["decoding"] is None:
                raise InductiveRelationError(
                    f"{context} source state requires a decoding expression"
                )
            decoding, decoding_sort = _parse_relation_expression(
                row["decoding"], f"{context} decoding"
            )
            if decoding_sort != "word":
                raise InductiveRelationError(
                    f"{context} decoding must be a word"
                )
        elif row["decoding"] is not None:
            raise InductiveRelationError(
                f"{context} parameter decoding must be null"
            )
        return cls(
            kind,
            _identifier(row["id"], f"{context} id"),
            mode,
            MachineProjectionV1.parse(row["projection"], f"{context} projection"),
            encoding,
            decoding,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "id": self.identity,
            "mode": self.mode,
            "projection": (
                None if self.projection is None else self.projection.to_payload()
            ),
            "encoding": None if self.encoding is None else copy.deepcopy(dict(self.encoding)),
            "decoding": None if self.decoding is None else copy.deepcopy(dict(self.decoding)),
        }


@dataclass(frozen=True)
class CutpointDerivedRelationV1:
    identity: str
    projection: MachineProjectionV1
    expression: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str) -> "CutpointDerivedRelationV1":
        row = _object(value, {"id", "projection", "expression"}, context)
        expression, sort = _parse_relation_expression(
            row["expression"], f"{context} expression"
        )
        if sort != "word":
            raise InductiveRelationError(f"{context} expression must be a word")
        return cls(
            _identifier(row["id"], f"{context} id"),
            MachineProjectionV1.parse(row["projection"], f"{context} projection"),
            expression,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "projection": self.projection.to_payload(),
            "expression": copy.deepcopy(dict(self.expression)),
        }


@dataclass(frozen=True)
class CutpointRelationV1:
    unit_id: str
    phase_id: str
    values: tuple[CutpointValueRelationV1, ...]
    derived: tuple[CutpointDerivedRelationV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "CutpointRelationV1":
        row = _object(
            value, {"unit_id", "phase_id", "values", "derived"}, context
        )
        raw_values = row["values"]
        if not isinstance(raw_values, list):
            raise InductiveRelationError(f"{context} values must be an array")
        values = tuple(
            CutpointValueRelationV1.parse(item, f"{context} value {index}")
            for index, item in enumerate(raw_values)
        )
        keys = [(item.kind, item.identity) for item in values]
        if not values or keys != sorted(keys) or len(keys) != len(set(keys)):
            raise InductiveRelationError(
                f"{context} values must be nonempty, ordered, and unique"
            )
        raw_derived = row["derived"]
        if not isinstance(raw_derived, list):
            raise InductiveRelationError(f"{context} derived values must be an array")
        derived = tuple(
            CutpointDerivedRelationV1.parse(
                item, f"{context} derived value {index}"
            )
            for index, item in enumerate(raw_derived)
        )
        derived_ids = [item.identity for item in derived]
        if derived_ids != sorted(derived_ids) or len(derived_ids) != len(set(derived_ids)):
            raise InductiveRelationError(
                f"{context} derived values must be ordered and unique"
            )
        projections = [
            canonical_sha256_v3(item.projection.to_payload())
            for item in (*values, *derived)
            if item.projection is not None
        ]
        if len(projections) != len(set(projections)):
            raise InductiveRelationError(
                f"{context} machine projections must be unique"
            )
        return cls(
            _identifier(row["unit_id"], f"{context} unit"),
            _identifier(row["phase_id"], f"{context} phase"),
            values,
            derived,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "unit_id": self.unit_id,
            "phase_id": self.phase_id,
            "values": [item.to_payload() for item in self.values],
            "derived": [item.to_payload() for item in self.derived],
        }


@dataclass(frozen=True)
class CompletionSegmentRelationV1:
    segment_id: str
    completion_id: str

    @classmethod
    def parse(
        cls, value: object, context: str
    ) -> "CompletionSegmentRelationV1":
        row = _object(value, {"segment_id", "completion_id"}, context)
        return cls(
            _identifier(row["segment_id"], f"{context} segment"),
            _identifier(row["completion_id"], f"{context} completion"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "segment_id": self.segment_id,
            "completion_id": self.completion_id,
        }


@dataclass(frozen=True)
class InductiveCutpointRelationV1:
    operation_id: str
    interface_sha256: str
    source_plan_sha256: str
    machine_receipt_sha256: str
    cutpoints: tuple[CutpointRelationV1, ...]
    completion_segments: tuple[CompletionSegmentRelationV1, ...]
    relation_sha256: str

    @classmethod
    def parse(cls, value: object) -> "InductiveCutpointRelationV1":
        row = _object(
            value,
            {
                "format",
                "operation_id",
                "interface_sha256",
                "source_plan_sha256",
                "machine_receipt_sha256",
                "cutpoints",
                "completion_segments",
                "relation_sha256",
            },
            "inductive cutpoint relation",
        )
        if row["format"] != INDUCTIVE_CUTPOINT_RELATION_V1:
            raise InductiveRelationError("unsupported inductive relation format")
        raw_cutpoints = row["cutpoints"]
        if not isinstance(raw_cutpoints, list):
            raise InductiveRelationError("inductive cutpoints must be an array")
        cutpoints = tuple(
            CutpointRelationV1.parse(item, f"cutpoint relation {index}")
            for index, item in enumerate(raw_cutpoints)
        )
        ids = [item.unit_id for item in cutpoints]
        if not cutpoints or ids != sorted(ids) or len(ids) != len(set(ids)):
            raise InductiveRelationError(
                "cutpoint relations must be nonempty, ordered, and unique"
            )
        raw_completions = row["completion_segments"]
        if not isinstance(raw_completions, list):
            raise InductiveRelationError(
                "completion segment relations must be an array"
            )
        completion_segments = tuple(
            CompletionSegmentRelationV1.parse(
                item, f"completion segment relation {index}"
            )
            for index, item in enumerate(raw_completions)
        )
        segment_ids = [item.segment_id for item in completion_segments]
        if (
            segment_ids != sorted(segment_ids)
            or len(segment_ids) != len(set(segment_ids))
        ):
            raise InductiveRelationError(
                "completion segment relations must be ordered and unique"
            )
        core = dict(row)
        observed = _digest(core.pop("relation_sha256"), "cutpoint relation digest")
        if canonical_sha256_v3(core) != observed:
            raise InductiveRelationError("cutpoint relation digest is stale")
        return cls(
            _identifier(row["operation_id"], "cutpoint relation operation"),
            _digest(row["interface_sha256"], "cutpoint relation interface digest"),
            _digest(row["source_plan_sha256"], "cutpoint relation source-plan digest"),
            _digest(row["machine_receipt_sha256"], "cutpoint relation machine digest"),
            cutpoints,
            completion_segments,
            observed,
        )

    @classmethod
    def create(
        cls,
        *,
        interface: ProofKernelComponentInterface,
        source_plan: InductiveSourcePlanV1,
        machine_receipt: CheckedInductiveMachineReceiptV1,
        cutpoints: Sequence[Mapping[str, object]],
        completion_segments: Sequence[Mapping[str, object]],
    ) -> "InductiveCutpointRelationV1":
        core: dict[str, object] = {
            "format": INDUCTIVE_CUTPOINT_RELATION_V1,
            "operation_id": source_plan.operation_id,
            "interface_sha256": interface.sha256,
            "source_plan_sha256": source_plan.plan_sha256,
            "machine_receipt_sha256": machine_receipt.receipt_sha256,
            "cutpoints": list(cutpoints),
            "completion_segments": list(completion_segments),
        }
        result = cls.parse(
            {**core, "relation_sha256": canonical_sha256_v3(core)}
        )
        result.validate_for(interface, source_plan, machine_receipt)
        return result

    def to_payload(self) -> dict[str, object]:
        core: dict[str, object] = {
            "format": INDUCTIVE_CUTPOINT_RELATION_V1,
            "operation_id": self.operation_id,
            "interface_sha256": self.interface_sha256,
            "source_plan_sha256": self.source_plan_sha256,
            "machine_receipt_sha256": self.machine_receipt_sha256,
            "cutpoints": [item.to_payload() for item in self.cutpoints],
            "completion_segments": [
                item.to_payload() for item in self.completion_segments
            ],
        }
        return {**core, "relation_sha256": self.relation_sha256}

    def validate_for(
        self,
        interface: ProofKernelComponentInterface,
        source_plan: InductiveSourcePlanV1,
        machine_receipt: CheckedInductiveMachineReceiptV1,
    ) -> None:
        if (
            self.operation_id != source_plan.operation_id
            or self.interface_sha256 != interface.sha256
            or self.source_plan_sha256 != source_plan.plan_sha256
            or self.machine_receipt_sha256 != machine_receipt.receipt_sha256
        ):
            raise InductiveRelationError(
                "inductive cutpoint relation artifact bindings are stale"
            )
        operation = interface.operation_index().get(self.operation_id)
        if operation is None:
            raise InductiveRelationError("cutpoint relation operation is unknown")
        inventory = machine_receipt.segment_inventory.to_value()
        assert isinstance(inventory, dict)
        exact_cutpoints = set(str(item) for item in inventory["cutpoint_unit_ids"])
        if {item.unit_id for item in self.cutpoints} != exact_cutpoints:
            raise InductiveRelationError(
                "cutpoint relation inventory differs from exact machine cutpoints"
            )
        parameter_ids = {item.identity for item in operation.parameters}
        state_ids = {item.identity for item in source_plan.state}
        parameter_types = {
            item.identity: interface.type_index()[item.type_id].kind
            for item in operation.parameters
        }
        expected_values = {
            *(('parameter', item) for item in parameter_ids),
            *(('source_state', item) for item in state_ids),
        }
        observed_phases: set[str] = set()
        for cutpoint in self.cutpoints:
            observed_phases.add(cutpoint.phase_id)
            if cutpoint.phase_id not in source_plan.phase_ids:
                raise InductiveRelationError(
                    f"cutpoint {cutpoint.unit_id!r} has an unknown source phase"
                )
            observed_values = {
                (item.kind, item.identity) for item in cutpoint.values
            }
            if observed_values != expected_values:
                raise InductiveRelationError(
                    f"cutpoint {cutpoint.unit_id!r} does not relate every logical value"
                )
            for value in cutpoint.values:
                if value.mode == "logical_carry":
                    continue
                assert value.encoding is not None
                encoding_refs = _relation_expression_references(value.encoding)
                if encoding_refs["parameter"] - parameter_ids:
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                        "encoding references unknown parameters"
                    )
                if encoding_refs["state_input"] - state_ids:
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                        "encoding references unknown source state"
                    )
                if value.mode == "logical_definition":
                    if encoding_refs["state_input"]:
                        raise InductiveRelationError(
                            f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                            "logical definition references prior source state"
                        )
                    if encoding_refs["projected_value"]:
                        raise InductiveRelationError(
                            f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                            "logical definition references a machine projection"
                        )
                    continue
                if encoding_refs["projected_value"]:
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                        "encoding references the projected machine value"
                    )
                if any(
                    parameter_types.get(item) != "bytes"
                    for item in (
                        encoding_refs["bytes_address"]
                        | encoding_refs["byte_extent"]
                        | encoding_refs["byte_read"]
                    )
                ):
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                        "encoding has a non-byte address reference"
                    )
                if value.decoding is not None:
                    decoding_refs = _relation_expression_references(value.decoding)
                    if decoding_refs["state_input"]:
                        raise InductiveRelationError(
                            f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                            "decoding circularly references source state"
                        )
                    if decoding_refs["parameter"] - parameter_ids:
                        raise InductiveRelationError(
                            f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                            "decoding references unknown parameters"
                        )
                    if decoding_refs["projected_value"] != {"value"}:
                        raise InductiveRelationError(
                            f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                            "decoding must use the projected machine value"
                        )
                    if any(
                        parameter_types.get(item) != "bytes"
                        for item in (
                            decoding_refs["bytes_address"]
                            | decoding_refs["byte_extent"]
                            | decoding_refs["byte_read"]
                        )
                    ):
                        raise InductiveRelationError(
                            f"cutpoint {cutpoint.unit_id!r} value {value.identity!r} "
                            "decoding has a non-byte address reference"
                        )
            for derived in cutpoint.derived:
                references = _relation_expression_references(derived.expression)
                if references["parameter"] - parameter_ids:
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} derived value "
                        f"{derived.identity!r} references unknown parameters"
                    )
                if references["state_input"] - state_ids:
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} derived value "
                        f"{derived.identity!r} references unknown source state"
                    )
                byte_parameters = (
                    references["bytes_address"]
                    | references["byte_extent"]
                    | references["byte_read"]
                )
                if any(parameter_types.get(item) != "bytes" for item in byte_parameters):
                    raise InductiveRelationError(
                        f"cutpoint {cutpoint.unit_id!r} derived value "
                        f"{derived.identity!r} has a non-byte address reference"
                    )
        if observed_phases != set(source_plan.phase_ids):
            raise InductiveRelationError(
                "not every source phase is represented by a machine cutpoint"
            )
        segments = [
            item
            for item in inventory["segments"]
            if isinstance(item, Mapping)
        ]
        entry_target_cutpoints = {
            str(item["target"]["id"])
            for item in segments
            if isinstance(item.get("source"), Mapping)
            and item["source"].get("kind") == "operation_entry"
            and isinstance(item.get("target"), Mapping)
            and item["target"].get("kind") == "cutpoint"
        }
        for cutpoint in self.cutpoints:
            if cutpoint.unit_id not in entry_target_cutpoints:
                continue
            carried = sorted(
                item.identity
                for item in cutpoint.values
                if item.mode == "logical_carry"
            )
            if carried:
                raise InductiveRelationError(
                    f"entry-reachable cutpoint {cutpoint.unit_id!r} carries "
                    f"uninitialized logical state: {', '.join(carried)}"
                )
        exact_completion_segments = {
            str(item["segment_id"])
            for item in segments
            if isinstance(item.get("target"), Mapping)
            and item["target"].get("kind") == "operation_exit"
        }
        submitted_completion_segments = {
            item.segment_id for item in self.completion_segments
        }
        if submitted_completion_segments != exact_completion_segments:
            raise InductiveRelationError(
                "completion relation does not cover every exact exit segment"
            )
        for completion in self.completion_segments:
            if completion.completion_id not in source_plan.completion_ids:
                raise InductiveRelationError(
                    f"segment {completion.segment_id!r} has an unknown completion"
                )


def _parse_relation_expression(
    value: object, context: str
) -> tuple[dict[str, object], str]:
    try:
        return parse_value_codec_expression(value, context)
    except ValueCodecError as exc:
        raise InductiveRelationError(str(exc)) from exc


def _relation_expression_references(
    value: Mapping[str, object],
) -> dict[str, set[str]]:
    return value_codec_expression_references(value)


__all__ = [
    "INDUCTIVE_CUTPOINT_RELATION_V1",
    "CutpointRelationV1",
    "CutpointDerivedRelationV1",
    "CutpointValueRelationV1",
    "CompletionSegmentRelationV1",
    "InductiveCutpointRelationV1",
    "InductiveRelationError",
]
