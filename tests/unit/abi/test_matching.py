from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.abi.extraction import extract_checked_abi_evidence
from spaghetti_extractor.abi.matching import resolve_library_match_abis
from spaghetti_extractor.abi.model import StackCleanupV1
from tests.unit.abi._integration_support import (
    parametric_summary,
    write_declared_catalog,
    write_release_set,
)
from tests.unit.abi._support import physical_profile


class LibraryMatchFunctionRegionTests(unittest.TestCase):
    def test_multi_unit_region_completes_from_declaration_and_return_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = physical_profile(
                calling_convention="stdcall",
                stack_cleanup=StackCleanupV1("callee", 4),
            )
            catalog_path, catalog, declaration = write_declared_catalog(
                root,
                profile=profile,
            )
            self.assertEqual(catalog.status, "complete")
            self.assertIsNotNone(catalog.declaration_set_sha256)
            self.assertEqual(
                catalog.function_subjects[0]["declaration_id"],
                declaration.declaration_id,
            )
            catalog_function_id = str(
                catalog.function_subjects[0]["function_id"]
            )
            unit_ids = ("block.entry", "block.return")
            extraction = extract_checked_abi_evidence(
                summaries=(
                    parametric_summary(
                        unit_ids,
                        status="complete",
                        cleanup_bytes=4,
                    ),
                ),
            )
            extraction_path = root / "target-abi.json"
            extraction.write(extraction_path)
            release_set = write_release_set(
                root,
                target_function_id="function.run",
                target_unit_ids=unit_ids,
                catalog_function_id=catalog_function_id,
            )

            resolution = resolve_library_match_abis(
                target_abi_evidence=extraction_path,
                physical_abi_catalogs=(catalog_path,),
                release_hypotheses=release_set,
                out=root / "resolution.json",
            )

            self.assertEqual(resolution["status"], "complete")
            self.assertEqual(len(resolution["bindings"]), 1)
            binding = resolution["bindings"][0]
            self.assertEqual(binding["status"], "complete")
            self.assertEqual(binding["target_function_id"], "function.run")
            self.assertEqual(binding["target_unit_ids"], list(unit_ids))
            self.assertEqual(binding["catalog_symbols"], ["_run@4"])
            self.assertEqual(binding["catalog_undecorated_symbol"], "run")
            self.assertEqual(binding["profile"], profile.to_payload())
            self.assertEqual(binding["compatibility"]["kind"], "exact")
            self.assertEqual(len(binding["certificate_ids"]), 2)
            self.assertEqual(binding["issues"], [])

    def test_incomplete_machine_region_is_not_completed_by_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = physical_profile(
                calling_convention="stdcall",
                stack_cleanup=StackCleanupV1("callee", 4),
            )
            catalog_path, catalog, _declaration = write_declared_catalog(
                root,
                profile=profile,
            )
            catalog_function_id = str(
                catalog.function_subjects[0]["function_id"]
            )
            unit_ids = ("block.entry", "block.return")
            extraction = extract_checked_abi_evidence(
                summaries=(
                    parametric_summary(unit_ids, status="incomplete"),
                ),
            )
            extraction_path = root / "target-abi.json"
            extraction.write(extraction_path)
            release_set = write_release_set(
                root,
                target_function_id="function.run",
                target_unit_ids=unit_ids,
                catalog_function_id=catalog_function_id,
            )

            resolution = resolve_library_match_abis(
                target_abi_evidence=extraction_path,
                physical_abi_catalogs=(catalog_path,),
                release_hypotheses=release_set,
                out=root / "resolution.json",
            )

            self.assertEqual(resolution["status"], "incomplete")
            binding = resolution["bindings"][0]
            self.assertEqual(binding["status"], "incomplete")
            self.assertEqual(
                {issue["subject_id"] for issue in binding["issues"]},
                set(unit_ids),
            )
            self.assertTrue(
                all(
                    issue["code"] == "abi_checked_summary_not_authorizing"
                    for issue in binding["issues"]
                )
            )
            self.assertTrue(
                all(issue["catalog_symbols"] == ["_run@4"] for issue in binding["issues"])
            )


if __name__ == "__main__":
    unittest.main()
