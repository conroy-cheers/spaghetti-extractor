from __future__ import annotations

import unittest

from spaghetti_extractor.relational.lean.expressions import (
    _lean_static_word_relation_slot,
)


class StageAFiniteOriginSerializationTests(unittest.TestCase):
    def test_static_slot_serializes_bounded_origin_inventory(self) -> None:
        source = _lean_static_word_relation_slot({
            "id": 7,
            "original_address": 0x4200AC,
            "candidate_address": 0x4300AC,
            "relation": "finite_origins",
            "finite_alternative_budget": 2,
            "origins": [
                {
                    "kind": "static_code_target",
                    "target_id": 41,
                    "offset": 0,
                },
                {"kind": "opaque_resource", "resource_id": 73},
            ],
        })
        self.assertIn(
            "relation := .finiteOrigins 2 "
            "[.staticCodeTarget 41 0, .opaqueResource 73]",
            source,
        )


if __name__ == "__main__":
    unittest.main()
