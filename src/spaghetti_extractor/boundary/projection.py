"""Checked mappings from component-facing values to canonical signatures."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import (
    BOUNDARY_PROJECTION_RECEIPT_V1_FORMAT,
    BOUNDARY_PROJECTION_V1_FORMAT,
)
from ._canonical import BoundaryModelError, array, content_sha256, exact, identifier, object_
from .lifecycle import BoundaryValuePathV1
from .model import BoundarySchemaV1, BoundaryValueV1, resolve_field_path_type


BOUNDARY_PROJECTION_V1 = BOUNDARY_PROJECTION_V1_FORMAT
BOUNDARY_PROJECTION_RECEIPT_V1 = BOUNDARY_PROJECTION_RECEIPT_V1_FORMAT


@dataclass(frozen=True)
class BoundaryProjectionEntryV1:
    source_id: str
    target: BoundaryValuePathV1

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryProjectionEntryV1":
        row = object_(value, context)
        exact(row, {"source_id", "target"}, context)
        return cls(identifier(row["source_id"], f"{context} source"), BoundaryValuePathV1.parse(row["target"], f"{context} target"))

    def to_payload(self) -> dict[str, object]:
        return {"source_id": self.source_id, "target": self.target.to_payload()}


@dataclass(frozen=True)
class BoundaryProjectionV1:
    component_id: str
    operation_id: str
    schema_sha256: str
    signature_id: str
    source_values: tuple[BoundaryValueV1, ...]
    entries: tuple[BoundaryProjectionEntryV1, ...]
    projection_sha256: str

    @classmethod
    def create(cls, *, component_id: str, operation_id: str, schema: BoundarySchemaV1, signature_id: str, source_values: Sequence[BoundaryValueV1 | Mapping[str, object]], entries: Sequence[BoundaryProjectionEntryV1 | Mapping[str, object]]) -> "BoundaryProjectionV1":
        if signature_id not in schema.signature_index:
            raise BoundaryModelError("boundary projection names an unknown signature")
        sources = tuple(sorted((item if isinstance(item, BoundaryValueV1) else BoundaryValueV1.parse(item, f"projection source {index}") for index, item in enumerate(source_values)), key=lambda item: item.identity))
        mappings = tuple(sorted((item if isinstance(item, BoundaryProjectionEntryV1) else BoundaryProjectionEntryV1.parse(item, f"projection entry {index}") for index, item in enumerate(entries)), key=lambda item: item.source_id))
        if [item.identity for item in sources] != sorted(set(item.identity for item in sources)) or [item.source_id for item in mappings] != [item.identity for item in sources]:
            raise BoundaryModelError("boundary projection must map every source value exactly once")
        core = {"format": BOUNDARY_PROJECTION_V1, "component_id": identifier(component_id, "projection component"), "operation_id": identifier(operation_id, "projection operation"), "schema_sha256": schema.schema_sha256, "signature_id": signature_id, "source_values": [item.to_payload() for item in sources], "entries": [item.to_payload() for item in mappings]}
        return cls(str(core["component_id"]), str(core["operation_id"]), schema.schema_sha256, signature_id, sources, mappings, content_sha256(core))

    @classmethod
    def parse(
        cls, value: object, *, schema: BoundarySchemaV1
    ) -> "BoundaryProjectionV1":
        row = object_(value, "boundary projection")
        exact(
            row,
            {
                "format", "component_id", "operation_id", "schema_sha256",
                "signature_id", "source_values", "entries", "projection_sha256",
            },
            "boundary projection",
        )
        if (
            row["format"] != BOUNDARY_PROJECTION_V1
            or row["schema_sha256"] != schema.schema_sha256
        ):
            raise BoundaryModelError(
                "boundary projection binds another schema or format"
            )
        source_rows = array(row["source_values"], "projection sources")
        entry_rows = array(row["entries"], "projection entries")
        result = cls.create(
            component_id=str(row["component_id"]),
            operation_id=str(row["operation_id"]),
            schema=schema,
            signature_id=str(row["signature_id"]),
            source_values=[
                BoundaryValueV1.parse(item, f"projection source {index}")
                for index, item in enumerate(source_rows)
            ],
            entries=[
                BoundaryProjectionEntryV1.parse(item, f"projection entry {index}")
                for index, item in enumerate(entry_rows)
            ],
        )
        if row["projection_sha256"] != result.projection_sha256:
            raise BoundaryModelError("boundary projection digest is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        return {"format": BOUNDARY_PROJECTION_V1, "component_id": self.component_id, "operation_id": self.operation_id, "schema_sha256": self.schema_sha256, "signature_id": self.signature_id, "source_values": [item.to_payload() for item in self.source_values], "entries": [item.to_payload() for item in self.entries], "projection_sha256": self.projection_sha256}


@dataclass(frozen=True)
class BoundaryProjectionReceiptV1:
    projection_sha256: str
    status: str
    obligations: tuple[Mapping[str, str], ...]
    receipt_sha256: str

    @classmethod
    def check(cls, projection: BoundaryProjectionV1, *, schema: BoundarySchemaV1) -> "BoundaryProjectionReceiptV1":
        if projection.schema_sha256 != schema.schema_sha256:
            raise BoundaryModelError("boundary projection binds another schema")
        signature = schema.signature_index[projection.signature_id]
        targets = {item.identity: ("parameter", item) for item in signature.parameters} | {item.identity: ("result", item) for item in signature.results}
        obligations: list[Mapping[str, str]] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        sources = {item.identity: item for item in projection.source_values}
        for entry in projection.entries:
            source = sources[entry.source_id]
            target_row = targets.get(entry.target.value_id)
            status, code = "checked", "boundary_value_projection_checked"
            if target_row is None or target_row[0] != entry.target.root:
                status, code = "violated", "boundary_projection_target_invalid"
            else:
                target = target_row[1]
                target_type_id = _path_type_id(schema, target.type_id, entry.target.fields)
                target_interpretation = (
                    target.interpretation if not entry.target.fields else "value"
                )
                if source.type_id != target_type_id or source.interpretation != target_interpretation:
                    status, code = "violated", "boundary_projection_type_mismatch"
            key = (entry.target.root, entry.target.value_id, entry.target.fields)
            if key in seen:
                status, code = "violated", "boundary_projection_target_duplicated"
            seen.add(key)
            obligations.append({"id": entry.source_id, "status": status, "code": code})
        expected = {("parameter", item.identity) for item in signature.parameters} | {("result", item.identity) for item in signature.results}
        covered = {(root, value_id) for root, value_id, _fields in seen}
        if covered != expected:
            obligations.append({"id": "boundary.coverage", "status": "incomplete", "code": "boundary_projection_coverage_incomplete"})
        obligations.sort(key=lambda item: item["id"])
        status = "violated" if any(item["status"] == "violated" for item in obligations) else "incomplete" if any(item["status"] != "checked" for item in obligations) else "complete"
        core = {"format": BOUNDARY_PROJECTION_RECEIPT_V1, "projection_sha256": projection.projection_sha256, "status": status, "obligations": [dict(item) for item in obligations]}
        return cls(projection.projection_sha256, status, tuple(obligations), content_sha256(core))

    def to_payload(self) -> dict[str, object]:
        return {"format": BOUNDARY_PROJECTION_RECEIPT_V1, "projection_sha256": self.projection_sha256, "status": self.status, "obligations": [dict(item) for item in self.obligations], "receipt_sha256": self.receipt_sha256}

    @classmethod
    def parse(
        cls, value: object, *, projection: BoundaryProjectionV1
    ) -> "BoundaryProjectionReceiptV1":
        row = object_(value, "boundary projection receipt")
        exact(
            row,
            {"format", "projection_sha256", "status", "obligations", "receipt_sha256"},
            "boundary projection receipt",
        )
        if (
            row["format"] != BOUNDARY_PROJECTION_RECEIPT_V1
            or row["projection_sha256"] != projection.projection_sha256
        ):
            raise BoundaryModelError(
                "boundary projection receipt binds another projection or format"
            )
        obligations = tuple(
            dict(object_(item, f"projection obligation {index}"))
            for index, item in enumerate(
                array(row["obligations"], "projection obligations")
            )
        )
        core = {
            "format": BOUNDARY_PROJECTION_RECEIPT_V1,
            "projection_sha256": projection.projection_sha256,
            "status": str(row["status"]),
            "obligations": [dict(item) for item in obligations],
        }
        result = cls(
            projection.projection_sha256,
            str(row["status"]),
            obligations,
            content_sha256(core),
        )
        if row["receipt_sha256"] != result.receipt_sha256:
            raise BoundaryModelError("boundary projection receipt digest is stale")
        return result


def _path_type_id(
    schema: BoundarySchemaV1, type_id: str, fields: Sequence[str]
) -> str:
    return resolve_field_path_type(
        schema, type_id, fields, context="boundary projection"
    ).identity


__all__ = ["BoundaryProjectionEntryV1", "BoundaryProjectionReceiptV1", "BoundaryProjectionV1"]
