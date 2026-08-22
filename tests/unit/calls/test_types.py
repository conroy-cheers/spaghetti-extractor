from __future__ import annotations

import unittest

from spaghetti_extractor.calls._canonical import CallProtocolError
from spaghetti_extractor.calls.types import PortableTypeGraphV1, TargetLayoutSetV1
from tests.unit.calls._support import graph, layouts


class PortableCallTypeTests(unittest.TestCase):
    def test_graph_and_layout_round_trip_with_content_ids(self) -> None:
        types = graph()
        layout_set = layouts(types)
        self.assertEqual(PortableTypeGraphV1.parse(types.to_payload()), types)
        self.assertEqual(TargetLayoutSetV1.parse(layout_set.to_payload(), type_graph=types), layout_set)
        self.assertEqual(layout_set.type_graph_sha256, types.graph_id.split(":", 1)[1])

    def test_pointer_recursion_is_allowed_but_value_recursion_is_not(self) -> None:
        pointer_recursive = PortableTypeGraphV1.create(
            [
                {"id": "node", "kind": "record", "nominal_id": "node", "fields": [{"id": "next", "type_id": "p_node", "bit_width": None}]},
                {"id": "p_node", "kind": "pointer", "pointee_type_id": "node", "qualifiers": []},
            ]
        )
        self.assertEqual(pointer_recursive.index["p_node"].references(), ("node",))
        with self.assertRaisesRegex(CallProtocolError, "non-pointer recursive"):
            PortableTypeGraphV1.create(
                [{"id": "bad", "kind": "record", "nominal_id": "bad", "fields": [{"id": "self", "type_id": "bad", "bit_width": None}]}]
            )

    def test_non_union_layout_overlap_is_rejected(self) -> None:
        types = graph()
        payload = layouts(types).to_payload()
        pair = next(item for item in payload["layouts"] if item["type_id"] == "pair")
        pair["fields"][1]["offset_bits"] = 16
        payload.pop("id")
        with self.assertRaisesRegex(CallProtocolError, "overlapping"):
            TargetLayoutSetV1.create(type_graph=types, **{key: value for key, value in payload.items() if key not in {"format", "type_graph_sha256"}})


if __name__ == "__main__":
    unittest.main()
