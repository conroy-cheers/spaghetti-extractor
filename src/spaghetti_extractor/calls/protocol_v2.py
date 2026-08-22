"""Canonical checked call protocol built on shared boundary artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from ..artifacts.formats import CHECKED_CALL_PROTOCOL_V2_FORMAT
from ..boundary import (
    BoundaryEvidenceReceiptV1,
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
    BoundarySchemaV1,
    TargetDataLayoutV1,
)
from ._canonical import CallProtocolError, array, content_id, exact, object_, text
from .frame import PhysicalCallFrameV3


@dataclass(frozen=True)
class CheckedCallProtocolV2:
    protocol_id: str
    status: str
    schema_id: str
    schema_sha256: str
    layout_sha256: str
    signature_id: str
    physical_frame_id: str
    evidence_receipt_id: str
    lifecycle_sha256: str
    lifecycle_receipt_sha256: str
    projection_sha256: str | None
    projection_receipt_sha256: str | None
    issues: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        schema: BoundarySchemaV1,
        layout: TargetDataLayoutV1,
        signature_id: str,
        frame: PhysicalCallFrameV3,
        evidence_receipt: BoundaryEvidenceReceiptV1,
        lifecycle: BoundaryLifecycleV1,
        lifecycle_receipt: BoundaryLifecycleReceiptV1,
        projection: BoundaryProjectionV1 | None = None,
        projection_receipt: BoundaryProjectionReceiptV1 | None = None,
        issues: Sequence[str] = (),
    ) -> "CheckedCallProtocolV2":
        if signature_id not in schema.signature_index:
            raise CallProtocolError("checked call protocol names an unknown signature")
        if (
            layout.schema_sha256 != schema.schema_sha256
            or frame.schema_sha256 != schema.schema_sha256
            or frame.layout_sha256 != layout.layout_sha256
            or frame.signature_id != signature_id
        ):
            raise CallProtocolError("checked call protocol boundary bindings disagree")
        if lifecycle.schema_sha256 != schema.schema_sha256 or lifecycle.signature_id != signature_id:
            raise CallProtocolError("checked call protocol lifecycle binds another signature")
        if lifecycle_receipt.lifecycle_sha256 != lifecycle.lifecycle_sha256:
            raise CallProtocolError("checked call protocol lifecycle receipt is stale")
        if (projection is None) != (projection_receipt is None):
            raise CallProtocolError("checked call protocol projection and receipt disagree")
        if projection is not None and (
            projection.schema_sha256 != schema.schema_sha256
            or projection.signature_id != signature_id
            or projection_receipt is None
            or projection_receipt.projection_sha256 != projection.projection_sha256
        ):
            raise CallProtocolError("checked call protocol projection bindings disagree")
        issue_values = tuple(sorted(set(text(item, "call protocol issue") for item in issues)))
        dependency_statuses = [evidence_receipt.status, lifecycle_receipt.status]
        if projection_receipt is not None:
            dependency_statuses.append(projection_receipt.status)
        status = (
            "violated"
            if "violated" in dependency_statuses
            else "incomplete"
            if any(item != "complete" for item in dependency_statuses)
            else "complete"
        )
        if status == "complete" and issue_values:
            raise CallProtocolError("complete checked call protocol cannot retain issues")
        if status != "complete" and not issue_values:
            issue_values = tuple(
                sorted(
                    f"{name}:{value}"
                    for name, value in (
                        ("evidence", evidence_receipt.status),
                        ("lifecycle", lifecycle_receipt.status),
                        (
                            "projection",
                            "absent" if projection_receipt is None else projection_receipt.status,
                        ),
                    )
                    if value not in {"complete", "absent"}
                )
            )
        core = {
            "format": CHECKED_CALL_PROTOCOL_V2_FORMAT,
            "status": status,
            "schema_id": schema.schema_id,
            "schema_sha256": schema.schema_sha256,
            "layout_sha256": layout.layout_sha256,
            "signature_id": signature_id,
            "physical_frame_id": frame.frame_id,
            "evidence_receipt_id": evidence_receipt.receipt_id,
            "lifecycle_sha256": lifecycle.lifecycle_sha256,
            "lifecycle_receipt_sha256": lifecycle_receipt.receipt_sha256,
            "projection_sha256": None if projection is None else projection.projection_sha256,
            "projection_receipt_sha256": None if projection_receipt is None else projection_receipt.receipt_sha256,
            "issues": list(issue_values),
        }
        return cls(
            content_id("checked-call-protocol-v2", core),
            status,
            schema.schema_id,
            schema.schema_sha256,
            layout.layout_sha256,
            signature_id,
            frame.frame_id,
            evidence_receipt.receipt_id,
            lifecycle.lifecycle_sha256,
            lifecycle_receipt.receipt_sha256,
            core["projection_sha256"],
            core["projection_receipt_sha256"],
            issue_values,
        )

    @classmethod
    def parse(
        cls,
        value: object,
        *,
        schema: BoundarySchemaV1,
        layout: TargetDataLayoutV1,
        frame: PhysicalCallFrameV3,
        evidence_receipt: BoundaryEvidenceReceiptV1,
        lifecycle: BoundaryLifecycleV1,
        lifecycle_receipt: BoundaryLifecycleReceiptV1,
        projection: BoundaryProjectionV1 | None = None,
        projection_receipt: BoundaryProjectionReceiptV1 | None = None,
    ) -> "CheckedCallProtocolV2":
        row = object_(value, "checked call protocol V2")
        exact(
            row,
            {
                "format", "id", "status", "schema_id", "schema_sha256",
                "layout_sha256", "signature_id", "physical_frame_id",
                "evidence_receipt_id", "lifecycle_sha256",
                "lifecycle_receipt_sha256", "projection_sha256",
                "projection_receipt_sha256", "issues",
            },
            "checked call protocol V2",
        )
        if row["format"] != CHECKED_CALL_PROTOCOL_V2_FORMAT:
            raise CallProtocolError("unsupported checked call protocol V2 format")
        result = cls.create(
            schema=schema,
            layout=layout,
            signature_id=str(row["signature_id"]),
            frame=frame,
            evidence_receipt=evidence_receipt,
            lifecycle=lifecycle,
            lifecycle_receipt=lifecycle_receipt,
            projection=projection,
            projection_receipt=projection_receipt,
            issues=[str(item) for item in array(row["issues"], "call protocol issues")],
        )
        if row["id"] != result.protocol_id or row["status"] != result.status:
            raise CallProtocolError("checked call protocol V2 is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CHECKED_CALL_PROTOCOL_V2_FORMAT,
            "id": self.protocol_id,
            "status": self.status,
            "schema_id": self.schema_id,
            "schema_sha256": self.schema_sha256,
            "layout_sha256": self.layout_sha256,
            "signature_id": self.signature_id,
            "physical_frame_id": self.physical_frame_id,
            "evidence_receipt_id": self.evidence_receipt_id,
            "lifecycle_sha256": self.lifecycle_sha256,
            "lifecycle_receipt_sha256": self.lifecycle_receipt_sha256,
            "projection_sha256": self.projection_sha256,
            "projection_receipt_sha256": self.projection_receipt_sha256,
            "issues": list(self.issues),
        }


__all__ = ["CheckedCallProtocolV2"]
