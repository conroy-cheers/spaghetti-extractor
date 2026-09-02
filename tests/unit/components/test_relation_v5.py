from __future__ import annotations

import unittest

from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.relation_v5 import (
    ComponentRelationIntentV1,
)


def _intent() -> ComponentRelationIntentV1:
    return ComponentRelationIntentV1.create(
        component_id="basename-selection",
        operations=[{
            "operation_id": "select",
            "requirements": [{
                "id": "interior-result",
                "relation": "borrowed_interior_or_null",
                "service_id": "find_character",
                "origin_parameter_id": "text",
                "result_value_id": "result",
            }],
        }],
        blockers=[{
            "code": "checked-proof-absent",
            "detail": "No checked relation evidence is bound.",
        }],
    )


class ComponentRelationV5Tests(unittest.TestCase):
    def test_intent_is_content_bound_and_never_authorizes(self) -> None:
        intent = _intent()
        self.assertEqual(ComponentRelationIntentV1.parse(intent.to_payload()), intent)
        self.assertEqual(intent.status, "incomplete")
        self.assertEqual(intent.to_payload()["policy"]["intent_authorizes"], False)

    def test_stale_digest_and_unknown_relation_fail_closed(self) -> None:
        stale = _intent().to_payload()
        stale["component_id"] = "different"
        with self.assertRaisesRegex(BoundaryModelError, "digest is stale"):
            ComponentRelationIntentV1.parse(stale)
        unknown = _intent().to_payload()
        unknown["operations"][0]["requirements"][0]["relation"] = "aliases"
        with self.assertRaisesRegex(BoundaryModelError, "unsupported"):
            ComponentRelationIntentV1.create(
                component_id=str(unknown["component_id"]),
                operations=unknown["operations"],
                blockers=unknown["blockers"],
            )


if __name__ == "__main__":
    unittest.main()
