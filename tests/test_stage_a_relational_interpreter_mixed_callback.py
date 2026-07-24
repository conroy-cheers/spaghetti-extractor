from __future__ import annotations

import re
import unittest
from pathlib import Path


class StageARelationalInterpreterMixedCallbackTests(unittest.TestCase):
    def test_callback_semantics_are_explicit_and_fail_closed(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        native = (source_root / "RelationalInterpreterNativeWorld.lean").read_text(
            encoding="utf-8"
        )
        mixed = (
            source_root / "RelationalInterpreterMixedEnvironment.lean"
        ).read_text(encoding="utf-8")

        for source in (native, mixed):
            for marker in ("sorry", "axiom", "unsafe"):
                self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

        self.assertIn("| callback (entry : NativeWorldExternalCallbackAction)", native)
        self.assertIn("NativeWorldExternalSuspension", native)
        self.assertIn("NativeWorldExternalCallbackRuntime", native)
        self.assertIn("nestedNativeCallbackTargetAllowed", native)
        self.assertIn("invalidCallbackReturn", native)
        self.assertIn("nestedNativeCallbackReturnUnwinds", native)
        self.assertIn("MixedNestedExternalCallbackFramesRelated", mixed)
        self.assertIn("MixedNestedExternalSuspensionsRelated", mixed)
        self.assertIn("ExactMixedNestedExternalInteractionChunk", mixed)
        self.assertIn("ExactMixedNestedExternalCallbackReturnChunk", mixed)
        self.assertNotIn("structure MixedExternalCallbackFrontier", mixed)


if __name__ == "__main__":
    unittest.main()
