from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.abi.catalog import build_physical_abi_catalog
from spaghetti_extractor.abi.model import StackCleanupV1
from tests.unit.abi._integration_support import (
    write_declaration_set,
    write_declared_catalog,
    write_library_index,
)
from tests.unit.abi._support import physical_profile


class PhysicalAbiCatalogDeclarationTests(unittest.TestCase):
    def test_catalog_hash_binds_declarations_and_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _catalog, _declaration = write_declared_catalog(
                root,
                profile=physical_profile(
                    calling_convention="stdcall",
                    stack_cleanup=StackCleanupV1("callee", 4),
                ),
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["functions"][0]["portable_prototype"] = {"corrupt": True}
            path.write_text(json.dumps(payload), encoding="utf-8")

            from spaghetti_extractor.abi.catalog import PhysicalAbiCatalogV1

            with self.assertRaisesRegex(ValueError, "catalog hash is stale"):
                PhysicalAbiCatalogV1.read(path)

    def test_declarations_must_target_the_indexed_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = write_library_index(
                root,
                snapshot_id="runtime-snapshot-v1",
            )
            declarations_path, _declaration = write_declaration_set(
                root,
                profile=physical_profile(),
                snapshot_id="runtime-snapshot-v2",
            )

            with self.assertRaisesRegex(ValueError, "another library snapshot"):
                build_physical_abi_catalog(
                    artifact_index=index_path,
                    out=root / "catalog.json",
                    decoration_model="pe32-coff-gnu-v1",
                    declarations=declarations_path,
                )

    def test_symbol_and_declaration_contradiction_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _path, catalog, declaration = write_declared_catalog(
                root,
                profile=physical_profile(),
            )

            self.assertEqual(catalog.status, "violated")
            self.assertEqual(
                catalog.function_subjects[0]["declaration_id"],
                declaration.declaration_id,
            )
            self.assertIn(
                "abi_constraint_contradiction",
                {issue.get("code") for issue in catalog.issues},
            )
            self.assertTrue(
                any(certificate.status == "violated" for certificate in catalog.certificates)
            )


if __name__ == "__main__":
    unittest.main()
