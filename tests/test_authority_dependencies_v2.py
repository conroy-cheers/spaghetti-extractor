from __future__ import annotations

import unittest

from spaghetti_extractor.authority_dependencies_v2 import (
    call_frame_dependency_id,
    call_frame_family_dependency_id,
    call_summary_family_node_id,
    canonical_authority_dependencies,
    canonical_authority_dependency,
    parse_call_frame_dependency,
    parse_call_frame_family_dependency,
)


class AuthorityDependenciesV2Tests(unittest.TestCase):
    def test_call_frame_round_trip_and_canonical_provider(self) -> None:
        dependency = call_frame_dependency_id("caller", 3, "callee")

        self.assertEqual(
            parse_call_frame_dependency(dependency),
            ("caller", 3, "callee"),
        )
        self.assertEqual(
            canonical_authority_dependency(dependency),
            "call-summary:callee",
        )

    def test_canonical_set_deduplicates_call_sites_for_one_callee(self) -> None:
        self.assertEqual(
            canonical_authority_dependencies([
                call_frame_dependency_id("left", 0, "callee"),
                call_frame_dependency_id("right", 1, "callee"),
                "indirect-exit:dispatch",
            ]),
            ("call-summary:callee", "indirect-exit:dispatch"),
        )

    def test_register_family_round_trip_and_canonical_provider(self) -> None:
        dependency = call_frame_family_dependency_id(
            "caller", 3, "callee", "register", "edi"
        )

        self.assertEqual(
            parse_call_frame_family_dependency(dependency),
            ("caller", 3, "callee", "register", "edi"),
        )
        self.assertEqual(
            canonical_authority_dependency(dependency),
            call_summary_family_node_id("callee", "register", "edi"),
        )

    def test_family_id_rejects_malformed_scope(self) -> None:
        with self.assertRaises(ValueError):
            call_frame_family_dependency_id(
                "caller", 0, "callee", "register"
            )
        with self.assertRaises(ValueError):
            call_frame_family_dependency_id(
                "caller", 0, "callee", "stack", "esp"
            )
        self.assertIsNone(parse_call_frame_family_dependency(
            'call-frame-family:["caller",0,"callee","register",null]'
        ))

    def test_malformed_or_unknown_dependency_fails_closed_by_identity(self) -> None:
        malformed = 'call-frame:["caller",true,"callee"]'

        self.assertIsNone(parse_call_frame_dependency(malformed))
        self.assertEqual(canonical_authority_dependency(malformed), malformed)
        self.assertEqual(
            canonical_authority_dependency("future-authority:one"),
            "future-authority:one",
        )


if __name__ == "__main__":
    unittest.main()
