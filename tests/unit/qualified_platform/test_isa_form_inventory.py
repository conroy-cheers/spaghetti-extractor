from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.qualified_platform.isa_form_inventory import (
    QualifiedPlatformISAFormInventoryError,
    default_qualified_platform_isa_form_inventory_path,
    load_qualified_platform_isa_form_inventory_v1,
    parse_qualified_platform_isa_form_inventory_v1,
)


class QualifiedPlatformISAFormInventoryTests(unittest.TestCase):
    def test_migration_seed_is_intrinsic_and_canonical(self) -> None:
        payload = load_qualified_platform_isa_form_inventory_v1(
            default_qualified_platform_isa_form_inventory_path()
        )
        self.assertEqual(payload["counts"], {"forms": 450, "representatives": 450})
        self.assertEqual(payload["role"], "target_independent_migration_seed")
        self.assertEqual(
            [row["form_id"] for row in payload["forms"]],
            sorted(row["form_id"] for row in payload["forms"]),
        )
        serialized = str(payload).lower()
        for target_identity in ("gnu-hello", "hello-derived", "dxball", "jq"):
            self.assertNotIn(target_identity, serialized)
        keys = set(payload)
        keys.update(key for row in payload["forms"] for key in row)
        for forbidden_field in (
            "campaign_ids",
            "source_occurrence_ids",
            "qualification_sha256",
            "status",
        ):
            self.assertNotIn(forbidden_field, keys)

    def test_stale_form_identity_fails_even_after_outer_rehash(self) -> None:
        payload = load_qualified_platform_isa_form_inventory_v1(
            default_qualified_platform_isa_form_inventory_path()
        )
        changed = copy.deepcopy(payload)
        changed["forms"][0]["semantic_form"] += " changed"
        changed["inventory_sha256"] = canonical_sha256_v3({
            key: value
            for key, value in changed.items()
            if key != "inventory_sha256"
        })
        with self.assertRaisesRegex(
            QualifiedPlatformISAFormInventoryError, "identity is stale"
        ):
            parse_qualified_platform_isa_form_inventory_v1(changed)

    def test_duplicate_representative_fails_closed(self) -> None:
        payload = load_qualified_platform_isa_form_inventory_v1(
            default_qualified_platform_isa_form_inventory_path()
        )
        changed = copy.deepcopy(payload)
        changed["forms"][1]["representative_instruction_hex"] = changed["forms"][0][
            "representative_instruction_hex"
        ]
        changed["inventory_sha256"] = canonical_sha256_v3({
            key: value
            for key, value in changed.items()
            if key != "inventory_sha256"
        })
        with self.assertRaisesRegex(
            QualifiedPlatformISAFormInventoryError,
            "distinct representative encodings",
        ):
            parse_qualified_platform_isa_form_inventory_v1(changed)


if __name__ == "__main__":
    unittest.main()
