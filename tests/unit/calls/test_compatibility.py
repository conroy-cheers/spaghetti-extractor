from __future__ import annotations

import unittest

from spaghetti_extractor.calls.compatibility import CallProtocolCompatibilityV1
from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.calls.lifecycle import CallLifecycleV1
from tests.unit.calls._support import graph, layouts, subject


class LayeredCallCompatibilityTests(unittest.TestCase):
    def test_equal_width_does_not_override_type_or_lifecycle_incompatibility(self) -> None:
        observed_graph = graph(result="u32", parameters=("u32",))
        expected_graph = graph(result="u32", parameters=("f32",))
        observed_layouts = layouts(observed_graph)
        expected_layouts = layouts(expected_graph)
        checker = IA32DialectCheckerV1("pe32-i386-gnu-v1")
        observed_frame = checker.lower(subject=subject(), function_type_id="call", type_graph=observed_graph, layout_set=observed_layouts)
        expected_frame = checker.lower(subject=subject(), function_type_id="call", type_graph=expected_graph, layout_set=expected_layouts)
        result = CallProtocolCompatibilityV1.check(observed_frame=observed_frame, expected_frame=expected_frame, observed_graph=observed_graph, expected_graph=expected_graph, observed_function_type_id="call", expected_function_type_id="call", observed_layouts=observed_layouts, expected_layouts=expected_layouts, observed_lifecycle=CallLifecycleV1.create([]), expected_lifecycle=CallLifecycleV1.create([]))
        self.assertEqual(result.physical, "exact")
        self.assertEqual(result.typed, "incompatible")
        self.assertEqual(result.status, "violated")


if __name__ == "__main__":
    unittest.main()
