from __future__ import annotations

from ._support import *

class LinkedLibraryReplacementTests(LinkedLibraryTestCase):
    def test_identity_only_does_not_authorize_replacement(self) -> None:
        manifest = self._write_single_reviewed_island()
        catalog = self._interface_catalog()
        assignments = bind_linked_interface_assignments(
            {
                "format": LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
                "linked_island_manifest_sha256": manifest["manifest_sha256"],
                "assignments": [
                    {
                        "island_id": "application:all",
                        "contract_id": "byte-transform-v1",
                        "evidence": {"kind": "identity_only"},
                    }
                ],
            }
        )
        qualification = qualify_linked_interfaces(
            linked_islands=self.root / "all-island.json",
            interface_catalog=catalog,
            assignments=assignments,
            out=self.root / "qualification.json",
        )

        self.assertEqual(qualification["status"], "incomplete")
        self.assertEqual(
            qualification["issues"][0]["code"],
            "semantic_qualification_missing",
        )

    def test_checked_interface_enables_portable_replacement(self) -> None:
        manifest = self._write_single_reviewed_island(kind="linked_dependency")
        catalog = self._interface_catalog()
        descriptor = catalog["contracts"][0]["component_contract"]
        implementation = catalog["replacements"][0]["implementation"]
        qualification_core = {
            "format": COMPONENT_QUALIFICATION_FORMAT,
            "status": "qualified",
            "executes_original_binary": False,
            "component_id": "fixture-linked-island",
            "component": {
                "id": "fixture-linked-island",
                "unit_ids": manifest["islands"][0]["unit_ids"],
            },
            "component_contract": descriptor,
            "implementation": implementation,
            "bindings": {},
            "checks": [],
            "counts": {
                "required_families": 0,
                "satisfied": 0,
                "incomplete_or_violated": 0,
            },
            "activation": {
                "authorized": True,
                "backend": "fixture",
                "domain": {"kind": "total"},
            },
        }
        component_qualification = {
            **qualification_core,
            "qualification_sha256": _canonical_sha256(qualification_core),
        }
        qualification_path = self.root / "component-qualification.json"
        write_json(qualification_path, component_qualification)
        assignments = bind_linked_interface_assignments(
            {
                "format": LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
                "linked_island_manifest_sha256": manifest["manifest_sha256"],
                "assignments": [
                    {
                        "island_id": "application:all",
                        "contract_id": "byte-transform-v1",
                        "evidence": {
                            "kind": "component_qualification",
                            "path": str(qualification_path),
                            "file_sha256": sha256_file(qualification_path),
                        },
                    }
                ],
            }
        )
        qualification = qualify_linked_interfaces(
            linked_islands=self.root / "all-island.json",
            interface_catalog=catalog,
            assignments=assignments,
            out=self.root / "qualification.json",
        )
        plan = plan_library_replacements(
            linked_islands=self.root / "all-island.json",
            interface_qualification=self.root / "qualification.json",
            interface_catalog=catalog,
            out=self.root / "replacement-plan.json",
        )

        self.assertEqual(qualification["status"], "qualified")
        self.assertEqual(plan["status"], "complete")
        self.assertTrue(plan["completion"]["idiomatic_source_complete"])
        self.assertEqual(
            plan["islands"][0]["disposition"],
            "replace_by_canonical_interface",
        )

    def test_incomplete_dynamic_callsite_blocks_complete_replacement_plan(self) -> None:
        manifest = self._write_single_reviewed_island(kind="linked_dependency")
        catalog = self._interface_catalog()
        descriptor = catalog["contracts"][0]["component_contract"]
        implementation = catalog["replacements"][0]["implementation"]
        qualification_core = {
            "format": COMPONENT_QUALIFICATION_FORMAT,
            "status": "qualified",
            "executes_original_binary": False,
            "component_id": "fixture-linked-island",
            "component": {
                "id": "fixture-linked-island",
                "unit_ids": manifest["islands"][0]["unit_ids"],
            },
            "component_contract": descriptor,
            "implementation": implementation,
            "bindings": {},
            "checks": [],
            "counts": {
                "required_families": 0,
                "satisfied": 0,
                "incomplete_or_violated": 0,
            },
            "activation": {
                "authorized": True,
                "backend": "fixture",
                "domain": {"kind": "total"},
            },
        }
        qualification_path = self.root / "component-qualification.json"
        write_json(
            qualification_path,
            {
                **qualification_core,
                "qualification_sha256": _canonical_sha256(qualification_core),
            },
        )
        assignments = bind_linked_interface_assignments(
            {
                "format": LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
                "linked_island_manifest_sha256": manifest["manifest_sha256"],
                "assignments": [
                    {
                        "island_id": "application:all",
                        "contract_id": "byte-transform-v1",
                        "evidence": {
                            "kind": "component_qualification",
                            "path": str(qualification_path),
                            "file_sha256": sha256_file(qualification_path),
                        },
                    }
                ],
            }
        )
        qualify_linked_interfaces(
            linked_islands=self.root / "all-island.json",
            interface_catalog=catalog,
            assignments=assignments,
            out=self.root / "qualification.json",
        )
        dynamic_core = {
            "format": DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
            "status": "incomplete",
            "executes_original_binary": False,
            "bindings": {},
            "imports": [],
            "callsites": [
                {
                    "id": "callsite:fixture",
                    "status": "incomplete",
                    "unit_id": None,
                    "instruction_rva": 0x1000,
                    "import": {"dll": "kernel32.dll", "symbol": "WriteFile"},
                    "abi_contract": None,
                }
            ],
            "issues": [],
            "counts": {},
        }
        dynamic_path = self.root / "dynamic-requirements.json"
        write_json(
            dynamic_path,
            {
                **dynamic_core,
                "requirements_sha256": _canonical_sha256(dynamic_core),
            },
        )

        plan = plan_library_replacements(
            linked_islands=self.root / "all-island.json",
            interface_qualification=self.root / "qualification.json",
            interface_catalog=catalog,
            dynamic_requirements=dynamic_path,
            out=self.root / "replacement-plan.json",
        )

        self.assertEqual(plan["status"], "incomplete")
        self.assertFalse(plan["completion"]["idiomatic_source_complete"])
        self.assertEqual(plan["counts"]["incomplete_dynamic_callsites"], 1)

    def test_unchecked_certificate_hash_does_not_authorize_replacement(self) -> None:
        manifest = self._write_single_reviewed_island(kind="linked_dependency")
        catalog = self._interface_catalog()
        descriptor = catalog["contracts"][0]["component_contract"]
        assignments = bind_linked_interface_assignments(
            {
                "format": LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
                "linked_island_manifest_sha256": manifest["manifest_sha256"],
                "assignments": [
                    {
                        "island_id": "application:all",
                        "contract_id": "byte-transform-v1",
                        "evidence": {
                            "kind": "checked_contract_certificate",
                            "component_contract": descriptor,
                            "target_manifest_sha256": manifest["manifest_sha256"],
                            "certificate_sha256": "c" * 64,
                        },
                    }
                ],
            }
        )
        qualification = qualify_linked_interfaces(
            linked_islands=self.root / "all-island.json",
            interface_catalog=catalog,
            assignments=assignments,
            out=self.root / "qualification.json",
        )

        self.assertEqual(qualification["status"], "incomplete")
        self.assertEqual(
            qualification["issues"][0]["code"],
            "certificate_checker_unavailable",
        )

    def test_stale_review_is_rejected(self) -> None:
        review = bind_linked_island_review(
            {
                "format": LINKED_ISLAND_REVIEW_FORMAT,
                "original_binary_sha256": sha256_file(self.original),
                "islands": [],
            }
        )
        review["original_binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(LinkedLibraryError, "self-hash is stale"):
            match_linked_islands(
                original=self.original,
                machine_ir=self.machine,
                catalog_lock=None,
                review=review,
                out=self.root / "linked-islands.json",
            )
