from __future__ import annotations

import copy
import unittest
from pathlib import Path

from spaghetti_extractor.machine_abi import (
    build_pe32_normal_call_abi_premise,
    load_normal_call_abi_premise,
    parse_normal_call_abi_premise,
)


class NormalCallABIPremiseTests(unittest.TestCase):
    def test_reviewed_profile_round_trips_canonically(self) -> None:
        built = build_pe32_normal_call_abi_premise()
        parsed = parse_normal_call_abi_premise(built.as_json())
        profile = load_normal_call_abi_premise(
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-normal-return-nonvolatile-v1.json"
        )

        self.assertEqual(parsed, built)
        self.assertEqual(profile, built)
        self.assertEqual(profile.transfer_kinds, ("indirect_call",))
        self.assertEqual(
            profile.preserved_registers,
            ("ebp", "ebx", "edi", "esi"),
        )

    def test_changed_semantics_with_stale_hash_are_rejected(self) -> None:
        payload = build_pe32_normal_call_abi_premise().as_json()
        payload["preserved_registers"] = ["ebp", "ebx", "esi"]

        with self.assertRaisesRegex(ValueError, "preserved registers"):
            parse_normal_call_abi_premise(payload)

        stale = copy.deepcopy(
            build_pe32_normal_call_abi_premise().as_json()
        )
        stale["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "content hash is stale"):
            parse_normal_call_abi_premise(stale)


if __name__ == "__main__":
    unittest.main()
