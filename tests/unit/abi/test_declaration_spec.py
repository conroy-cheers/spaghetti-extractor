from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.abi.declaration_spec import (
    build_declaration_set_from_spec,
)
from spaghetti_extractor.artifacts.formats import (
    PHYSICAL_ABI_DECLARATION_SPEC_FORMAT,
)
from tests.unit.abi._support import physical_profile


class PhysicalAbiDeclarationSpecTests(unittest.TestCase):
    def test_authored_spec_materializes_content_bound_declarations(self) -> None:
        profile = physical_profile()
        profile_payload = profile.to_payload()
        profile_payload.pop("id")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "spec.json"
            source.write_text(
                json.dumps(
                    {
                        "format": PHYSICAL_ABI_DECLARATION_SPEC_FORMAT,
                        "snapshot_id": "runtime-v1",
                        "source_kind": "reviewed_definition",
                        "source_sha256": "a" * 64,
                        "producer": "fixture-review-v1",
                        "declarations": [
                            {
                                "symbols": ["_run"],
                                "profile": profile_payload,
                                "prototype": {
                                    "symbol": "run",
                                    "return_type": "int",
                                    "parameter_types": ["int"],
                                    "parameter_names": ["value"],
                                    "variadic": False,
                                },
                                "effects": {
                                    "reads": [],
                                    "writes": [],
                                    "resource_actions": [],
                                    "callback_actions": [],
                                },
                                "dependency_ids": ["review:run-v1"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            destination = root / "declarations.json"

            result = build_declaration_set_from_spec(
                spec=source, out=destination
            )

            self.assertEqual(result.snapshot_id, "runtime-v1")
            self.assertEqual(len(result.declarations), 1)
            declaration = result.declarations[0]
            self.assertEqual(declaration.source_sha256, "a" * 64)
            self.assertEqual(declaration.profile, profile)
            self.assertEqual(declaration.prototype.symbol, "run")
            self.assertIsNotNone(declaration.effects)
            self.assertEqual(
                result,
                type(result).read(destination),
            )


if __name__ == "__main__":
    unittest.main()
