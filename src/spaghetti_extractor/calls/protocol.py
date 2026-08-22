"""Composite checked call protocols and operator-reviewed idiomatic views."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import CHECKED_CALL_PROTOCOL_V1_FORMAT, IDIOMATIC_CALL_VIEW_V1_FORMAT
from ._canonical import CallProtocolError, array, content_id, digest, exact, identifier, object_, text
from .frame import PhysicalCallFrameV2
from .lifecycle import CallLifecycleReceiptV1, CallLifecycleV1, ValuePathV1
from .relation import CallFrameRelationReceiptV1
from .types import PortableTypeGraphV1, TargetLayoutSetV1


VIEW_OPERATIONS = frozenset(
    {"identity", "pointer_length_view", "out_parameter_result", "callback_context", "resource_handle", "result_record"}
)


@dataclass(frozen=True)
class IdiomaticProjectionV1:
    identity: str
    operation: str
    sources: tuple[ValuePathV1, ...]
    target_id: str
    target_type_id: str
    relation_receipt_sha256: str

    @classmethod
    def parse(cls, value: object, context: str) -> "IdiomaticProjectionV1":
        row = object_(value, context)
        exact(row, {"id", "operation", "sources", "target_id", "target_type_id", "relation_receipt_sha256"}, context)
        operation = text(row["operation"], f"{context} operation")
        if operation not in VIEW_OPERATIONS:
            raise CallProtocolError(f"{context} operation is unsupported")
        sources = tuple(ValuePathV1.parse(item, f"{context} source {index}") for index, item in enumerate(array(row["sources"], f"{context} sources")))
        if not sources:
            raise CallProtocolError(f"{context} needs at least one source")
        return cls(identifier(row["id"], f"{context} id"), operation, sources, identifier(row["target_id"], f"{context} target id"), identifier(row["target_type_id"], f"{context} target type id"), digest(row["relation_receipt_sha256"], f"{context} relation receipt"))

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "operation": self.operation, "sources": [item.to_payload() for item in self.sources], "target_id": self.target_id, "target_type_id": self.target_type_id, "relation_receipt_sha256": self.relation_receipt_sha256}


@dataclass(frozen=True)
class IdiomaticCallViewV1:
    view_id: str
    faithful_function_type_id: str
    idiomatic_function_type_id: str
    projections: tuple[IdiomaticProjectionV1, ...]

    @classmethod
    def create(cls, *, faithful_function_type_id: str, idiomatic_function_type_id: str, projections: Sequence[IdiomaticProjectionV1 | Mapping[str, object]]) -> "IdiomaticCallViewV1":
        parsed = tuple(item if isinstance(item, IdiomaticProjectionV1) else IdiomaticProjectionV1.parse(item, f"idiomatic projection {index}") for index, item in enumerate(projections))
        ordered = tuple(sorted(parsed, key=lambda item: item.identity))
        if [item.identity for item in ordered] != sorted(set(item.identity for item in ordered)):
            raise CallProtocolError("idiomatic projections must be unique and ordered")
        core = {"format": IDIOMATIC_CALL_VIEW_V1_FORMAT, "faithful_function_type_id": identifier(faithful_function_type_id, "faithful function type"), "idiomatic_function_type_id": identifier(idiomatic_function_type_id, "idiomatic function type"), "projections": [item.to_payload() for item in ordered]}
        return cls(content_id("idiomatic-call-view-v1", core), str(core["faithful_function_type_id"]), str(core["idiomatic_function_type_id"]), ordered)

    @classmethod
    def parse(cls, value: object) -> "IdiomaticCallViewV1":
        row = object_(value, "idiomatic call view")
        exact(row, {"format", "id", "faithful_function_type_id", "idiomatic_function_type_id", "projections"}, "idiomatic call view")
        if row["format"] != IDIOMATIC_CALL_VIEW_V1_FORMAT:
            raise CallProtocolError("unsupported idiomatic call view format")
        result = cls.create(faithful_function_type_id=str(row["faithful_function_type_id"]), idiomatic_function_type_id=str(row["idiomatic_function_type_id"]), projections=[IdiomaticProjectionV1.parse(item, f"idiomatic projection {index}") for index, item in enumerate(array(row["projections"], "idiomatic projections"))])
        if row["id"] != result.view_id:
            raise CallProtocolError("idiomatic call view id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {"format": IDIOMATIC_CALL_VIEW_V1_FORMAT, "id": self.view_id, "faithful_function_type_id": self.faithful_function_type_id, "idiomatic_function_type_id": self.idiomatic_function_type_id, "projections": [item.to_payload() for item in self.projections]}


@dataclass(frozen=True)
class CheckedCallProtocolV1:
    protocol_id: str
    status: str
    faithful_function_type_id: str
    type_graph_sha256: str
    layout_set_sha256: str
    physical_frame_sha256: str
    frame_relation_receipt_sha256: str
    lifecycle_sha256: str
    lifecycle_receipt_sha256: str
    dialect_receipt_sha256: str
    evidence_ids: tuple[str, ...]
    idiomatic_view_sha256: str | None
    issues: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        status: str,
        faithful_function_type_id: str,
        type_graph: PortableTypeGraphV1,
        layout_set: TargetLayoutSetV1,
        frame: PhysicalCallFrameV2,
        frame_relation_receipt: CallFrameRelationReceiptV1,
        lifecycle: CallLifecycleV1,
        lifecycle_receipt: CallLifecycleReceiptV1,
        dialect_receipt_sha256: str,
        evidence_ids: Sequence[str],
        idiomatic_view: IdiomaticCallViewV1 | None = None,
        issues: Sequence[str] = (),
    ) -> "CheckedCallProtocolV1":
        if status not in {"complete", "incomplete", "violated"}:
            raise CallProtocolError("call protocol status is unsupported")
        type_node = type_graph.index.get(faithful_function_type_id)
        if type_node is None or type_node.kind != "function":
            raise CallProtocolError("faithful call type is not a function in the bound type graph")
        graph_digest = type_graph.graph_id.split(":", 1)[1]
        layout_digest = layout_set.layout_id.split(":", 1)[1]
        frame_digest = frame.frame_id.split(":", 1)[1]
        lifecycle_digest = lifecycle.lifecycle_id.split(":", 1)[1]
        if layout_set.type_graph_sha256 != graph_digest:
            raise CallProtocolError("call layout set does not bind the call type graph")
        if frame.abi_dialect != layout_set.abi_dialect or frame.target != layout_set.target:
            raise CallProtocolError("call frame target or dialect differs from its layouts")
        if type_node.body["calling_convention"] != frame.calling_convention:
            raise CallProtocolError("faithful function convention differs from its physical frame")
        if frame_relation_receipt.status != "complete":
            raise CallProtocolError("checked call protocol requires a complete frame relation receipt")
        if (
            lifecycle_receipt.status != "complete"
            or lifecycle_receipt.lifecycle_sha256 != lifecycle_digest
        ):
            raise CallProtocolError(
                "checked call protocol requires a complete matching lifecycle receipt"
            )
        _validate_lifecycle_paths(
            type_graph, frame, lifecycle, faithful_function_type_id
        )
        view_digest = None if idiomatic_view is None else idiomatic_view.view_id.split(":", 1)[1]
        if idiomatic_view is not None and idiomatic_view.faithful_function_type_id != faithful_function_type_id:
            raise CallProtocolError("idiomatic view describes another faithful function")
        evidence = tuple(sorted(set(identifier(item, "call evidence id") for item in evidence_ids)))
        issue_values = tuple(sorted(set(text(item, "call protocol issue") for item in issues)))
        if status == "complete" and issue_values:
            raise CallProtocolError("complete call protocol cannot retain issues")
        if status != "complete" and not issue_values:
            raise CallProtocolError("non-complete call protocol must explain its issues")
        core = {
            "format": CHECKED_CALL_PROTOCOL_V1_FORMAT,
            "status": status,
            "faithful_function_type_id": faithful_function_type_id,
            "type_graph_sha256": graph_digest,
            "layout_set_sha256": layout_digest,
            "physical_frame_sha256": frame_digest,
            "frame_relation_receipt_sha256": frame_relation_receipt.receipt_id.split(":", 1)[1],
            "lifecycle_sha256": lifecycle_digest,
            "lifecycle_receipt_sha256": lifecycle_receipt.receipt_id.split(":", 1)[1],
            "dialect_receipt_sha256": digest(dialect_receipt_sha256, "dialect receipt"),
            "evidence_ids": list(evidence),
            "idiomatic_view_sha256": view_digest,
            "issues": list(issue_values),
        }
        return cls(content_id("checked-call-protocol-v1", core), status, faithful_function_type_id, graph_digest, layout_digest, frame_digest, str(core["frame_relation_receipt_sha256"]), lifecycle_digest, str(core["lifecycle_receipt_sha256"]), str(core["dialect_receipt_sha256"]), evidence, view_digest, issue_values)

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        type_graph: PortableTypeGraphV1,
        layout_set: TargetLayoutSetV1,
        frame: PhysicalCallFrameV2,
        lifecycle: CallLifecycleV1,
        lifecycle_receipt: CallLifecycleReceiptV1,
        frame_relation_receipt: CallFrameRelationReceiptV1,
        idiomatic_view: IdiomaticCallViewV1 | None = None,
    ) -> "CheckedCallProtocolV1":
        row = object_(value, "checked call protocol")
        exact(row, {"format", "id", "status", "faithful_function_type_id", "type_graph_sha256", "layout_set_sha256", "physical_frame_sha256", "frame_relation_receipt_sha256", "lifecycle_sha256", "lifecycle_receipt_sha256", "dialect_receipt_sha256", "evidence_ids", "idiomatic_view_sha256", "issues"}, "checked call protocol")
        if row["format"] != CHECKED_CALL_PROTOCOL_V1_FORMAT:
            raise CallProtocolError("unsupported checked call protocol format")
        result = cls.create(status=str(row["status"]), faithful_function_type_id=str(row["faithful_function_type_id"]), type_graph=type_graph, layout_set=layout_set, frame=frame, frame_relation_receipt=frame_relation_receipt, lifecycle=lifecycle, lifecycle_receipt=lifecycle_receipt, dialect_receipt_sha256=str(row["dialect_receipt_sha256"]), evidence_ids=[str(item) for item in array(row["evidence_ids"], "call evidence ids")], idiomatic_view=idiomatic_view, issues=[str(item) for item in array(row["issues"], "call protocol issues")])
        if row["id"] != result.protocol_id:
            raise CallProtocolError("checked call protocol id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CHECKED_CALL_PROTOCOL_V1_FORMAT,
            "id": self.protocol_id,
            "status": self.status,
            "faithful_function_type_id": self.faithful_function_type_id,
            "type_graph_sha256": self.type_graph_sha256,
            "layout_set_sha256": self.layout_set_sha256,
            "physical_frame_sha256": self.physical_frame_sha256,
            "frame_relation_receipt_sha256": self.frame_relation_receipt_sha256,
            "lifecycle_sha256": self.lifecycle_sha256,
            "lifecycle_receipt_sha256": self.lifecycle_receipt_sha256,
            "dialect_receipt_sha256": self.dialect_receipt_sha256,
            "evidence_ids": list(self.evidence_ids),
            "idiomatic_view_sha256": self.idiomatic_view_sha256,
            "issues": list(self.issues),
        }


def _validate_lifecycle_paths(
    type_graph: PortableTypeGraphV1,
    frame: PhysicalCallFrameV2,
    lifecycle: CallLifecycleV1,
    faithful_function_type_id: str,
) -> None:
    slots = {item.identity: item for item in (*frame.arguments, *frame.results)}
    types = type_graph.index
    function = types[faithful_function_type_id]
    parameter_types = list(function.body["parameter_type_ids"])
    explicit_arguments = [item for item in frame.arguments if item.role not in {"hidden_sret", "variadic_control"}]
    slot_types = {
        slot.identity: str(type_id)
        for slot, type_id in zip(explicit_arguments, parameter_types)
    }
    slot_types.update({item.identity: str(function.body["result_type_id"]) for item in frame.results})
    for binding in lifecycle.bindings:
        slot = slots.get(binding.path.slot_id)
        if slot is None:
            raise CallProtocolError(
                f"lifecycle binding {binding.identity!r} names an unknown call slot"
            )
        if not binding.path.fields:
            continue
        type_id = slot_types.get(slot.identity)
        if type_id is None:
            raise CallProtocolError(
                f"lifecycle binding {binding.identity!r} traverses an untyped slot"
            )
        node = types.get(type_id)
        for field_id in binding.path.fields:
            if node is None or node.kind not in {"record", "union"}:
                raise CallProtocolError(
                    f"lifecycle binding {binding.identity!r} traverses a non-aggregate"
                )
            field = next(
                (item for item in node.body["fields"] if item["id"] == field_id),
                None,
            )
            if field is None:
                raise CallProtocolError(
                    f"lifecycle binding {binding.identity!r} names an unknown field"
                )
            node = types.get(str(field["type_id"]))


__all__ = ["CheckedCallProtocolV1", "IdiomaticCallViewV1", "IdiomaticProjectionV1"]
