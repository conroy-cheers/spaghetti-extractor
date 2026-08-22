from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.abi.declarations import (
    PhysicalAbiDeclarationSetV1,
    PhysicalAbiDeclarationV1,
)
from spaghetti_extractor.abi.model import AbiModelError
from tests.unit.abi._support import physical_profile


class PhysicalAbiDeclarationTests(unittest.TestCase):
    def _declaration(self) -> PhysicalAbiDeclarationV1:
        return PhysicalAbiDeclarationV1.create(
            symbols=("_run@4",),
            source_kind="header_ast",
            source_sha256="a" * 64,
            producer="fixture-header-parser-v1",
            profile=physical_profile(),
            dependency_ids=("toolchain-v1",),
        )

    def test_declaration_id_binds_every_declared_content_field(self) -> None:
        declaration = self._declaration()
        self.assertEqual(
            PhysicalAbiDeclarationV1.parse(declaration.to_payload()),
            declaration,
        )

        stale = declaration.to_payload()
        stale["producer"] = "fixture-header-parser-v2"
        with self.assertRaisesRegex(AbiModelError, "does not bind its contents"):
            PhysicalAbiDeclarationV1.parse(stale)

    def test_declaration_set_rejects_a_stale_content_hash(self) -> None:
        declaration_set = PhysicalAbiDeclarationSetV1.create(
            snapshot_id="runtime-snapshot-v1",
            declarations=(self._declaration(),),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "declarations.json"
            declaration_set.write(path)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["declaration_set_sha256"] = "f" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(AbiModelError, "hash is stale"):
                PhysicalAbiDeclarationSetV1.read(path)


if __name__ == "__main__":
    unittest.main()
