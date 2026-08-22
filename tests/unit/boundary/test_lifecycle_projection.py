from __future__ import annotations

import unittest

from spaghetti_extractor.boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
)
from tests.unit.boundary._support import schema, value


class BoundaryLifecycleProjectionTests(unittest.TestCase):
    def test_lifecycle_validates_component_state_and_exact_provider_contract(self) -> None:
        boundary_schema = schema()
        resource = value("owned", "u32", interpretation="resource")
        resource.update({"resource_kind": "jq-value", "provider_domain": "libjq"})
        lifecycle = BoundaryLifecycleV1.create(
            schema=boundary_schema,
            signature_id="operation",
            additional_roots={"state": [resource]},
            bindings=[{
                "id": "release-owned", "path": {"root": "state", "value_id": "owned", "fields": []},
                "transition": "release", "resource_kind": "jq-value",
                "provider_domain": "libjq", "service_id": "jv-free",
                "interaction_contract_id": "libjq.jv-free.v1", "condition": None,
            }],
        )
        incomplete = BoundaryLifecycleReceiptV1.check(
            lifecycle, checked_interaction_contract_ids=[]
        )
        complete = BoundaryLifecycleReceiptV1.check(
            lifecycle, checked_interaction_contract_ids=["libjq.jv-free.v1"]
        )
        self.assertEqual(incomplete.status, "incomplete")
        self.assertEqual(complete.status, "complete")
        self.assertEqual(
            BoundaryLifecycleV1.parse(lifecycle.to_payload(), schema=boundary_schema),
            lifecycle,
        )
        self.assertEqual(
            BoundaryLifecycleReceiptV1.parse(
                complete.to_payload(), lifecycle=lifecycle
            ),
            complete,
        )

    def test_projection_supports_idiomatic_values_mapped_to_aggregate_fields(self) -> None:
        boundary_schema = schema()
        projection = BoundaryProjectionV1.create(
            component_id="jq-output", operation_id="dump",
            schema=boundary_schema, signature_id="operation",
            source_values=[value("first", "u32"), value("second", "u32"), value("result", "pair")],
            entries=[
                {"source_id": "first", "target": {"root": "parameter", "value_id": "argument", "fields": ["first"]}},
                {"source_id": "second", "target": {"root": "parameter", "value_id": "argument", "fields": ["second"]}},
                {"source_id": "result", "target": {"root": "result", "value_id": "result", "fields": []}},
            ],
        )
        receipt = BoundaryProjectionReceiptV1.check(
            projection, schema=boundary_schema
        )
        self.assertEqual(receipt.status, "complete")
        self.assertEqual(
            BoundaryProjectionV1.parse(
                projection.to_payload(), schema=boundary_schema
            ),
            projection,
        )
        self.assertEqual(
            BoundaryProjectionReceiptV1.parse(
                receipt.to_payload(), projection=projection
            ),
            receipt,
        )


if __name__ == "__main__":
    unittest.main()
