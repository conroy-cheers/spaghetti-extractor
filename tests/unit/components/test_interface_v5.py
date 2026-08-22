from __future__ import annotations

import unittest

from spaghetti_extractor.boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
)
from spaghetti_extractor.components.interface_v5 import PortableComponentInterfaceV5
from tests.unit.boundary._support import schema, value


class PortableComponentInterfaceV5Tests(unittest.TestCase):
    def test_component_reuses_checked_boundary_schema_projection_and_lifecycle(self) -> None:
        boundary_schema = schema()
        projection = BoundaryProjectionV1.create(
            component_id="jq-output", operation_id="dump",
            schema=boundary_schema, signature_id="operation",
            source_values=[value("argument", "pair"), value("result", "pair")],
            entries=[
                {"source_id": "argument", "target": {"root": "parameter", "value_id": "argument", "fields": []}},
                {"source_id": "result", "target": {"root": "result", "value_id": "result", "fields": []}},
            ],
        )
        projection_receipt = BoundaryProjectionReceiptV1.check(
            projection, schema=boundary_schema
        )
        lifecycle = BoundaryLifecycleV1.create(
            schema=boundary_schema, signature_id="operation", bindings=[]
        )
        lifecycle_receipt = BoundaryLifecycleReceiptV1.check(
            lifecycle, checked_interaction_contract_ids=[]
        )
        interface = PortableComponentInterfaceV5.create(
            identity="jq-output", schema=boundary_schema, state=[],
            operation_policies=[{
                "id": "dump", "effect_ids": ["observe-output"],
                "allowed_service_ids": [], "pre_states": ["ready"],
                "post_states": ["ready"],
            }],
            projections={"dump": projection},
            projection_receipts={"dump": projection_receipt},
            lifecycles={"dump": lifecycle},
            lifecycle_receipts={"dump": lifecycle_receipt},
            effects=[{
                "id": "observe-output", "kind": "observable",
                "operation": "dump",
                "target": {"root": "parameter", "value_id": "argument", "fields": []},
            }],
            services=[], protocol_states=["ready"],
            initial_protocol_state="ready",
        )
        self.assertEqual(interface.schema_sha256, boundary_schema.schema_sha256)
        self.assertEqual(
            PortableComponentInterfaceV5.parse(
                interface.to_payload(), schema=boundary_schema,
                projections={"dump": projection},
                projection_receipts={"dump": projection_receipt},
                lifecycles={"dump": lifecycle},
                lifecycle_receipts={"dump": lifecycle_receipt},
            ),
            interface,
        )


if __name__ == "__main__":
    unittest.main()
