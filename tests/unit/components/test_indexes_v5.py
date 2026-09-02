from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.indexes_v5 import (
    ComponentIntentIndexV5,
    load_component_intent_index_v5,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
)
from tests.unit.components.test_interface_package_v5 import _intent


class ComponentIntentIndexV5Tests(unittest.TestCase):
    def test_index_is_canonical_and_rechecks_child_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = _intent()
            (root / "fixture.json").write_text(
                json.dumps(child.to_payload()), encoding="utf-8"
            )
            index = ComponentIntentIndexV5.create(
                kind="interface",
                components=[{
                    "component_id": child.component_id,
                    "interface_intent": "fixture.json",
                    "intent_sha256": child.intent_sha256,
                }],
                blockers=[],
            )
            (root / "index.json").write_text(
                json.dumps(index.to_payload()), encoding="utf-8"
            )
            self.assertEqual(
                load_component_intent_index_v5(
                    root / "index.json", kind="interface"
                ),
                index,
            )

    def test_stale_index_and_unlisted_children_fail_closed(self) -> None:
        child = _intent()
        index = ComponentIntentIndexV5.create(
            kind="interface",
            components=[{
                "component_id": child.component_id,
                "interface_intent": "fixture.json",
                "intent_sha256": child.intent_sha256,
            }],
            blockers=[],
        )
        stale = index.to_payload()
        stale["status"] = "incomplete"
        with self.assertRaisesRegex(BoundaryModelError, "status is stale"):
            ComponentIntentIndexV5.parse(stale, kind="interface")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "fixture.json").write_text(
                json.dumps(child.to_payload()), encoding="utf-8"
            )
            (root / "extra.json").write_text(
                json.dumps(ComponentInterfaceIntentV1.parse(child.to_payload()).to_payload()),
                encoding="utf-8",
            )
            (root / "index.json").write_text(
                json.dumps(index.to_payload()), encoding="utf-8"
            )
            with self.assertRaisesRegex(BoundaryModelError, "unlisted intent files"):
                load_component_intent_index_v5(
                    root / "index.json", kind="interface"
                )


if __name__ == "__main__":
    unittest.main()
