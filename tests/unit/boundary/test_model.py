from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.boundary import (
    BoundaryModelError,
    BoundarySchemaV1,
    TargetDataLayoutV1,
)
from tests.unit.boundary._support import layout, schema


class BoundaryModelTests(unittest.TestCase):
    def test_schema_and_layout_round_trip_with_function_not_stored(self) -> None:
        boundary_schema = schema()
        target_layout = layout(boundary_schema)
        self.assertEqual(
            BoundarySchemaV1.parse(boundary_schema.to_payload()), boundary_schema
        )
        self.assertEqual(
            TargetDataLayoutV1.parse(
                target_layout.to_payload(), schema=boundary_schema
            ),
            target_layout,
        )
        self.assertNotIn("operation-type", target_layout.index)

    def test_void_result_is_resolved_by_kind_not_reserved_identity(self) -> None:
        self.assertEqual(schema(result_type="unit").signature_index["operation"].results, ())

    def test_schema_digest_tampering_fails_closed(self) -> None:
        payload = copy.deepcopy(schema().to_payload())
        next(item for item in payload["types"] if item["id"] == "u32")["signed"] = True
        with self.assertRaisesRegex(BoundaryModelError, "digest"):
            BoundarySchemaV1.parse(payload)

    def test_non_pointer_value_cycle_is_rejected_but_pointer_recursion_is_legal(self) -> None:
        with self.assertRaisesRegex(BoundaryModelError, "value cycle"):
            BoundarySchemaV1.create(
                schema_id="bad-cycle",
                types=[
                    {"id": "unit", "kind": "void"},
                    {
                        "id": "node", "kind": "record", "nominal_id": "node",
                        "fields": [{"id": "next", "type_id": "node", "bit_width": None}],
                    },
                ],
                signatures=[],
            )
        boundary_schema = BoundarySchemaV1.create(
            schema_id="pointer-cycle",
            types=[
                {"id": "unit", "kind": "void"},
                {
                    "id": "node", "kind": "record", "nominal_id": "node",
                    "fields": [{"id": "next", "type_id": "node-pointer", "bit_width": None}],
                },
                {
                    "id": "node-pointer", "kind": "pointer",
                    "pointee_type_id": "node", "qualifiers": [],
                },
            ],
            signatures=[],
        )
        self.assertIn("node", boundary_schema.type_index)

    def test_implicit_record_padding_is_rejected(self) -> None:
        boundary_schema = schema()
        payload = layout(boundary_schema).to_payload()
        payload.pop("layout_sha256")
        pair = next(item for item in payload["layouts"] if item["type_id"] == "pair")
        pair["size_bits"] = 96
        with self.assertRaisesRegex(BoundaryModelError, "explicitly cover"):
            TargetDataLayoutV1.create(
                target=payload["target"],
                abi_dialect=payload["abi_dialect"],
                byte_order=payload["byte_order"],
                pointer_width_bits=payload["pointer_width_bits"],
                packing=payload["packing"],
                schema=boundary_schema,
                layouts=payload["layouts"],
            )


if __name__ == "__main__":
    unittest.main()
