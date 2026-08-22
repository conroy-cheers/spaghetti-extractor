"""Compilation of physical call frames into the shared constructive relation IR."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    CALL_FRAME_RELATION_RECEIPT_V1_FORMAT,
    CALL_FRAME_RELATION_V1_FORMAT,
)
from ..components.relation_ir import ComponentRelationIRV1
from ..components.relation_solver import prove_binding_lens
from ._canonical import (
    CallProtocolError,
    array,
    content_id,
    digest,
    exact,
    identifier,
    object_,
    text,
    verify_content_id,
)
from .frame import FrameFragmentV2, FrameLocationV2, FrameSlotV2, PhysicalCallFrameV2
from .types import PortableTypeGraphV1, TargetLayoutSetV1


@dataclass(frozen=True)
class CallFrameRelationV1:
    relation_id: str
    type_graph_sha256: str
    layout_set_sha256: str
    physical_frame_sha256: str
    relation_ir: ComponentRelationIRV1

    @classmethod
    def create(
        cls,
        *,
        type_graph: PortableTypeGraphV1,
        layout_set: TargetLayoutSetV1,
        frame: PhysicalCallFrameV2,
        machine_ir_sha256: str,
    ) -> "CallFrameRelationV1":
        graph_digest = type_graph.graph_id.split(":", 1)[1]
        layout_digest = layout_set.layout_id.split(":", 1)[1]
        frame_digest = frame.frame_id.split(":", 1)[1]
        if layout_set.type_graph_sha256 != graph_digest:
            raise CallProtocolError("call frame relation layout set does not bind its type graph")
        clauses = [
            *(_slot_clause(item, logical_root="parameter", phase="callee_entry") for item in frame.arguments),
            *(_slot_clause(item, logical_root="result", phase="callee_exit") for item in frame.results),
        ]
        if not clauses:
            clauses.append(
                {
                    "id": "call.empty-frame",
                    "kind": "assertion",
                    "phase": "callee_entry",
                    "logical_path": None,
                    "observe": None,
                    "realize": [],
                    "predicate": {
                        "op": "true",
                        "sort": {"kind": "bool"},
                        "args": [],
                        "attributes": {},
                    },
                    "effect_id": None,
                    "machine_event": None,
                    "reads": [],
                    "writes": [],
                }
            )
        operations = [{
            "operation_id": "invoke",
            "clauses": sorted(clauses, key=lambda item: str(item["id"])),
            "interactions": [],
        }]
        empty_interactions_sha256 = canonical_sha256_v3(
            {
                "format": "spaghetti-extractor-call-frame-interactions-v1",
                "interactions": [],
            }
        )
        relation = ComponentRelationIRV1.create(
            component_id="call-frame",
            machine_backend=frame.target,
            bindings={
                "interface_sha256": graph_digest,
                "machine_binding_sha256": frame_digest,
                "semantic_contract_sha256": layout_digest,
                "machine_ir_sha256": machine_ir_sha256,
                "interaction_inventory_sha256": empty_interactions_sha256,
                "interaction_contract_catalog_sha256": empty_interactions_sha256,
            },
            operations=operations,
        )
        core = {
            "format": CALL_FRAME_RELATION_V1_FORMAT,
            "type_graph_sha256": graph_digest,
            "layout_set_sha256": layout_digest,
            "physical_frame_sha256": frame_digest,
            "relation_ir": relation.to_payload(),
        }
        return cls(content_id("call-frame-relation-v1", core), graph_digest, layout_digest, frame_digest, relation)

    @classmethod
    def parse(cls, value: object) -> "CallFrameRelationV1":
        row = object_(value, "call frame relation")
        exact(
            row,
            {
                "format",
                "id",
                "type_graph_sha256",
                "layout_set_sha256",
                "physical_frame_sha256",
                "relation_ir",
            },
            "call frame relation",
        )
        if row["format"] != CALL_FRAME_RELATION_V1_FORMAT:
            raise CallProtocolError("unsupported call frame relation format")
        graph_digest = digest(
            row["type_graph_sha256"], "call frame relation type graph digest"
        )
        layout_digest = digest(
            row["layout_set_sha256"], "call frame relation layout set digest"
        )
        frame_digest = digest(
            row["physical_frame_sha256"], "call frame relation physical frame digest"
        )
        relation = ComponentRelationIRV1.parse(row["relation_ir"])
        if relation.component_id != "call-frame":
            raise CallProtocolError("call frame relation uses another component")
        expected_bindings = {
            "interface_sha256": graph_digest,
            "semantic_contract_sha256": layout_digest,
            "machine_binding_sha256": frame_digest,
        }
        if any(relation.bindings.get(key) != value for key, value in expected_bindings.items()):
            raise CallProtocolError(
                "call frame relation IR does not bind its declared artifacts"
            )
        core = {
            "format": CALL_FRAME_RELATION_V1_FORMAT,
            "type_graph_sha256": graph_digest,
            "layout_set_sha256": layout_digest,
            "physical_frame_sha256": frame_digest,
            "relation_ir": relation.to_payload(),
        }
        relation_id = verify_content_id(
            row["id"], "call-frame-relation-v1", core, "call frame relation"
        )
        return cls(
            relation_id, graph_digest, layout_digest, frame_digest, relation
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALL_FRAME_RELATION_V1_FORMAT,
            "id": self.relation_id,
            "type_graph_sha256": self.type_graph_sha256,
            "layout_set_sha256": self.layout_set_sha256,
            "physical_frame_sha256": self.physical_frame_sha256,
            "relation_ir": self.relation_ir.to_payload(),
        }

    @property
    def sha256(self) -> str:
        return self.relation_id.split(":", 1)[1]


@dataclass(frozen=True)
class CallFrameRelationReceiptV1:
    receipt_id: str
    status: str
    relation_sha256: str
    obligations: tuple[Mapping[str, str], ...]

    @classmethod
    def check(cls, relation: CallFrameRelationV1) -> "CallFrameRelationReceiptV1":
        obligations = tuple(
            {
                "id": clause.identity,
                "status": (
                    "checked" if clause.kind == "assertion" else proof.status
                ),
                "code": (
                    "empty_frame_structure_checked"
                    if clause.kind == "assertion"
                    else proof.code
                ),
            }
            for operation in relation.relation_ir.operations
            for clause in operation.clauses
            for proof in (prove_binding_lens(clause),)
        )
        status = (
            "complete"
            if obligations and all(item["status"] == "checked" for item in obligations)
            else "violated"
            if any(item["status"] == "violated" for item in obligations)
            else "incomplete"
        )
        core = {
            "format": CALL_FRAME_RELATION_RECEIPT_V1_FORMAT,
            "status": status,
            "relation_sha256": relation.sha256,
            "obligations": [dict(item) for item in obligations],
        }
        return cls(content_id("call-frame-relation-receipt-v1", core), status, relation.sha256, obligations)

    @classmethod
    def parse(cls, value: object) -> "CallFrameRelationReceiptV1":
        row = object_(value, "call frame relation receipt")
        exact(
            row,
            {"format", "id", "status", "relation_sha256", "obligations"},
            "call frame relation receipt",
        )
        if row["format"] != CALL_FRAME_RELATION_RECEIPT_V1_FORMAT:
            raise CallProtocolError("unsupported call frame relation receipt format")
        status = text(row["status"], "call frame relation receipt status")
        if status not in {"complete", "incomplete", "violated"}:
            raise CallProtocolError("call frame relation receipt status is unsupported")
        obligations = tuple(
            _parse_relation_obligation(item, f"call relation obligation {index}")
            for index, item in enumerate(
                array(row["obligations"], "call frame relation receipt obligations")
            )
        )
        identities = [item["id"] for item in obligations]
        if not obligations or identities != sorted(set(identities)):
            raise CallProtocolError(
                "call frame relation obligations must be nonempty, unique, and ordered"
            )
        derived_status = (
            "violated"
            if any(item["status"] == "violated" for item in obligations)
            else "incomplete"
            if any(item["status"] == "incomplete" for item in obligations)
            else "complete"
        )
        if status != derived_status:
            raise CallProtocolError(
                "call frame relation receipt status disagrees with its obligations"
            )
        relation_sha256 = digest(
            row["relation_sha256"], "call frame relation receipt relation digest"
        )
        core = {
            "format": CALL_FRAME_RELATION_RECEIPT_V1_FORMAT,
            "status": status,
            "relation_sha256": relation_sha256,
            "obligations": [dict(item) for item in obligations],
        }
        receipt_id = verify_content_id(
            row["id"],
            "call-frame-relation-receipt-v1",
            core,
            "call frame relation receipt",
        )
        return cls(receipt_id, status, relation_sha256, obligations)

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALL_FRAME_RELATION_RECEIPT_V1_FORMAT,
            "id": self.receipt_id,
            "status": self.status,
            "relation_sha256": self.relation_sha256,
            "obligations": [dict(item) for item in self.obligations],
        }


def _slot_clause(slot: FrameSlotV2, *, logical_root: str, phase: str) -> dict[str, object]:
    if not slot.fragments:
        raise CallProtocolError(f"call slot {slot.identity!r} has no constructive transport")
    path = {"root": logical_root, "id": slot.identity, "fields": list(slot.logical_path)}
    observe = _observe_slot(slot)
    writes = [_realize_fragment(slot, item, path) for item in slot.fragments if item.specified]
    read_places = sorted(
        {_place_key(item.location): _place(item.location) for item in slot.fragments if item.specified}.values(),
        key=canonical_sha256_v3,
    )
    write_places = sorted(
        {_place_key(item.location): _place(item.location) for item in slot.fragments if item.specified}.values(),
        key=canonical_sha256_v3,
    )
    return {
        "id": f"call.{slot.identity}",
        "kind": "binding",
        "phase": phase,
        "logical_path": path,
        "observe": observe,
        "realize": writes,
        "predicate": None,
        "effect_id": None,
        "machine_event": None,
        "reads": read_places,
        "writes": write_places,
    }


def _parse_relation_obligation(
    value: object, context: str
) -> Mapping[str, str]:
    row = object_(value, context)
    exact(row, {"id", "status", "code"}, context)
    status = text(row["status"], f"{context} status")
    if status not in {"checked", "incomplete", "violated"}:
        raise CallProtocolError(f"{context} status is unsupported")
    return {
        "id": identifier(row["id"], f"{context} id"),
        "status": status,
        "code": identifier(row["code"], f"{context} code"),
    }


def _observe_slot(slot: FrameSlotV2) -> dict[str, object]:
    pieces: list[tuple[int, int, dict[str, object]]] = []
    for fragment in slot.fragments:
        if fragment.specified:
            expression = _read_fragment(fragment)
        else:
            expression = {"op": "unspecified", "sort": _sort(fragment.width_bits), "args": [], "attributes": {"reason": "abi-padding"}}
        pieces.append((fragment.logical_offset_bits, fragment.width_bits, expression))
    occupied = sorted((offset, offset + width) for offset, width, _ in pieces)
    cursor = 0
    for left, right in occupied:
        if left > cursor:
            pieces.append((cursor, left - cursor, {"op": "unspecified", "sort": _sort(left - cursor), "args": [], "attributes": {"reason": "abi-padding"}}))
        cursor = max(cursor, right)
    if cursor < slot.storage_bits:
        pieces.append((cursor, slot.storage_bits - cursor, {"op": "unspecified", "sort": _sort(slot.storage_bits - cursor), "args": [], "attributes": {"reason": "abi-padding"}}))
    pieces.sort(key=lambda item: item[0], reverse=True)
    if len(pieces) == 1 and pieces[0][1] == slot.storage_bits:
        return pieces[0][2]
    return {"op": "concat", "sort": _sort(slot.storage_bits), "args": [item[2] for item in pieces], "attributes": {}}


def _read_fragment(fragment: FrameFragmentV2) -> dict[str, object]:
    place = _place(fragment.location)
    machine = {"op": "machine", "sort": _sort(fragment.location.width_bits), "args": [], "attributes": {"place": place}}
    value = machine
    if fragment.location_offset_bits or fragment.width_bits != fragment.location.width_bits:
        value = {"op": "slice", "sort": _sort(fragment.width_bits), "args": [machine], "attributes": {"offset_bits": fragment.location_offset_bits}}
    if fragment.representation == "x87_storage":
        value = {"op": "x87_decode", "sort": _sort(fragment.width_bits), "args": [machine], "attributes": {}}
    elif fragment.representation == "bitcast":
        value = {"op": "bitcast", "sort": _sort(fragment.width_bits), "args": [value], "attributes": {}}
    return value


def _realize_fragment(slot: FrameSlotV2, fragment: FrameFragmentV2, path: Mapping[str, object]) -> dict[str, object]:
    logical = {"op": "logical", "sort": _sort(slot.storage_bits), "args": [], "attributes": {"path": dict(path)}}
    value = logical
    if fragment.logical_offset_bits or fragment.width_bits != slot.storage_bits:
        value = {"op": "slice", "sort": _sort(fragment.width_bits), "args": [logical], "attributes": {"offset_bits": fragment.logical_offset_bits}}
    if fragment.representation == "x87_storage":
        value = {"op": "x87_encode", "sort": _sort(80), "args": [value], "attributes": {}}
    elif fragment.representation == "bitcast":
        value = {"op": "bitcast", "sort": _sort(fragment.width_bits), "args": [value], "attributes": {}}
    if value["sort"]["width"] < fragment.location.width_bits:
        op = "sign_extend" if fragment.representation == "sign_extend" else "zero_extend"
        value = {"op": op, "sort": _sort(fragment.location.width_bits), "args": [value], "attributes": {}}
    elif value["sort"]["width"] > fragment.location.width_bits:
        value = {"op": "truncate", "sort": _sort(fragment.location.width_bits), "args": [value], "attributes": {}}
    return {"place": _place(fragment.location), "value": value, "guard": {"op": "true", "sort": {"kind": "bool"}, "args": [], "attributes": {}}}


def _sort(width: int) -> dict[str, object]:
    if width <= 0:
        raise CallProtocolError("zero-width call transport is not representable")
    return {"kind": "bitvector", "width": width}


def _place(location: FrameLocationV2) -> dict[str, object]:
    if location.kind == "register":
        kind = "x87_register" if location.bank == "x87" else "vector_register" if location.bank == "xmm" else "register"
        selector = {"bank": location.bank, "name": location.name}
    elif location.kind == "stack":
        kind = "stack"
        selector = {"base": location.stack_base, "offset_bytes": location.stack_offset_bytes}
    elif location.kind == "memory":
        kind = "memory"
        selector = {"slot": location.memory_slot}
    else:
        raise CallProtocolError("none call location cannot participate in a relation")
    return {"kind": kind, "phase": location.phase, "width": location.width_bits, "selector": selector}


def _place_key(location: FrameLocationV2) -> str:
    return canonical_sha256_v3(_place(location))


__all__ = ["CallFrameRelationReceiptV1", "CallFrameRelationV1"]
