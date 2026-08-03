from __future__ import annotations

import json
import struct
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    COMPONENT_QUALIFICATION_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
)
from spaghetti_extractor.linked_libraries import (
    LinkedLibraryError,
    bind_interface_contract_catalog,
    bind_library_artifact_inputs,
    bind_linked_interface_assignments,
    bind_linked_island_review,
    derive_dynamic_library_requirements,
    index_library_artifacts,
    infer_library_hypotheses,
    lock_library_catalog,
    match_linked_islands,
    plan_library_replacements,
    propose_library_match_evidence,
    qualify_linked_interfaces,
    refine_linked_islands,
)
from spaghetti_extractor.util import sha256_file, write_json
from tests.pe_fixtures import pe32_import_image


_FUNCTION = bytes.fromhex("5589e5b801000000c3")
_APPLICATION = b"\xc3"
_THUNK = bytes.fromhex("ff2540204000")


class LinkedLibraryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.original = self.root / "fixture.exe"
        self.original.write_bytes(
            pe32_import_image(
                _FUNCTION + _APPLICATION + _THUNK,
                symbol="WriteFile",
            )
        )
        self.machine = self.root / "machine-ir"
        self.machine.mkdir()
        self._write_machine_package()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_indexes_archive_and_omf_without_executing_artifacts(self) -> None:
        (self.artifacts / "runtime.a").write_bytes(
            _archive("runtime.obj", _coff_object(_FUNCTION, symbol="_runtime"))
        )
        (self.artifacts / "vintage.obj").write_bytes(
            _omf_record(0x80, b"\x07VINTAGE")
            + _omf_record(0x90, b"\x00\x01\x06legacy\x00\x00\x00")
            + _omf_record(0xA0, b"\x01\x00\x00\x55\x89\xe5\x31\xc0\x40\x5d\xc3")
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "fixture-libraries",
                "artifacts": [
                    {
                        "id": "runtime",
                        "path": "runtime.a",
                        "visibility": "public",
                        "redistributable": True,
                    },
                    {
                        "id": "vintage",
                        "path": "vintage.obj",
                        "visibility": "private",
                        "redistributable": False,
                    },
                ],
            }
        )
        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "index.json",
        )

        self.assertEqual(index["status"], "indexed")
        self.assertFalse(index["executes_original_binary"])
        self.assertEqual(index["counts"]["function_fingerprints"], 2)
        archive = index["artifacts"][0]["index"]
        self.assertEqual(archive["kind"], "archive")
        function = archive["members"][0]["index"]["function_fingerprints"][0]
        self.assertEqual(function["name"], "_runtime")
        self.assertEqual(function["bytes_sha256"], sha256(_FUNCTION).hexdigest())
        omf = index["artifacts"][1]["index"]
        self.assertEqual(omf["kind"], "omf_object")
        self.assertEqual(omf["module_name"], "VINTAGE")
        self.assertTrue(omf["records"][0]["checksum_valid"])
        self.assertEqual(omf["function_fingerprints"][0]["name"], "legacy")
        self.assertTrue(omf["function_fingerprints"][0]["matchable"])

    def test_v2_index_preserves_snapshot_member_and_library_identity(self) -> None:
        (self.artifacts / "runtime.a").write_bytes(
            _archive("runtime.obj", _coff_object(_FUNCTION, symbol="_runtime"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
                "catalog_id": "runtime-catalog",
                "snapshot": {
                    "id": "runtime-build-1",
                    "target": {
                        "architecture": "i686",
                        "object_format": "coff",
                        "abi": "mingw32",
                    },
                },
                "artifacts": [
                    {
                        "id": "runtime",
                        "path": "runtime.a",
                        "retention_model": "archive_member",
                        "library_identity": {
                            "family_id": "fixture-runtime",
                            "component_id": "runtime",
                            "release_id": "1",
                            "abi_id": "mingw32",
                        },
                    }
                ],
            }
        )
        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "v2-index.json",
        )

        self.assertEqual(index["format"], "stage-b-library-artifact-index-v2")
        member = index["artifacts"][0]["index"]["members"][0]
        self.assertTrue(member["member_id"].startswith("member:"))
        fingerprint = member["index"]["function_fingerprints"][0]
        self.assertTrue(fingerprint["fingerprint_id"].startswith("fingerprint:"))
        self.assertEqual(
            index["artifacts"][0]["library_identity"]["family_id"],
            "fixture-runtime",
        )

    def test_coff_fingerprint_separates_return_alignment(self) -> None:
        aligned = bytes.fromhex("8b442404c3909090")
        (self.artifacts / "aligned.a").write_bytes(
            _archive("aligned.obj", _coff_object(aligned, symbol="_aligned"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "aligned-library",
                "artifacts": [{"id": "aligned", "path": "aligned.a"}],
            }
        )

        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "aligned-index.json",
        )

        fingerprint = index["artifacts"][0]["index"]["members"][0]["index"][
            "function_fingerprints"
        ][0]
        self.assertEqual(fingerprint["size"], 5)
        self.assertEqual(fingerprint["object_size"], 8)
        self.assertEqual(fingerprint["trailing_alignment"], "909090")
        self.assertEqual(fingerprint["match_strength"], "weak")

    def test_coff_fingerprint_separates_tail_jump_alignment(self) -> None:
        aligned = bytes.fromhex("31c0e9000000009090")
        (self.artifacts / "tail.a").write_bytes(
            _archive("tail.obj", _coff_object(aligned, symbol="_tail"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "tail-library",
                "artifacts": [{"id": "tail", "path": "tail.a"}],
            }
        )

        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "tail-index.json",
        )

        fingerprint = index["artifacts"][0]["index"]["members"][0]["index"][
            "function_fingerprints"
        ][0]
        self.assertEqual(fingerprint["size"], 7)
        self.assertEqual(fingerprint["trailing_alignment"], "9090")

    def test_constellation_anchor_resolves_shared_member_release(self) -> None:
        common_v1 = _candidate(
            artifact="1" * 64,
            member="member:v1",
            release="1",
            symbol="common",
        )
        common_v2 = _candidate(
            artifact="2" * 64,
            member="member:v2",
            release="2",
            symbol="common",
        )
        unique_v2 = _candidate(
            artifact="2" * 64,
            member="member:v2",
            release="2",
            symbol="unique",
        )
        core = {
            "format": LIBRARY_MATCH_EVIDENCE_FORMAT,
            "status": "proposed",
            "executes_original_binary": False,
            "bindings": {},
            "observations": [
                _observation("common", 0x1000, [common_v1, common_v2]),
                _observation("unique", 0x1010, [unique_v2]),
            ],
            "observed_control_edges": [],
            "counts": {},
            "authority": {
                "matching_is_provenance_evidence_only": True,
                "can_authorize_replacement": False,
            },
        }
        evidence = {**core, "evidence_sha256": _canonical_sha256(core)}
        hypotheses = infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "hypotheses.json",
        )

        common = hypotheses["selected_placements"][0]
        self.assertEqual(common["identity_status"], "exact_artifact")
        self.assertEqual(
            {item["artifact_sha256"] for item in common["candidates"]},
            {"2" * 64},
        )
        self.assertFalse(hypotheses["authority"]["can_authorize_replacement"])

    def test_constellation_aliases_at_one_anchored_member_converge(self) -> None:
        anchor = _candidate(
            artifact="1" * 64,
            member="member:one",
            release="1",
            symbol="anchor",
        )
        alias_a = _candidate(
            artifact="1" * 64,
            member="member:one",
            release="1",
            symbol="alias-a",
        )
        alias_b = _candidate(
            artifact="1" * 64,
            member="member:one",
            release="1",
            symbol="alias-b",
        )
        core = {
            "format": LIBRARY_MATCH_EVIDENCE_FORMAT,
            "status": "proposed",
            "executes_original_binary": False,
            "bindings": {},
            "observations": [
                _observation("anchor", 0x1000, [anchor]),
                _observation("aliases", 0x1010, [alias_a, alias_b]),
            ],
            "observed_control_edges": [],
            "counts": {},
            "authority": {
                "matching_is_provenance_evidence_only": True,
                "can_authorize_replacement": False,
            },
        }
        evidence = {**core, "evidence_sha256": _canonical_sha256(core)}

        hypotheses = infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "alias-hypotheses.json",
        )

        aliases = hypotheses["selected_placements"][1]
        self.assertEqual(aliases["identity_status"], "exact_artifact")
        self.assertEqual(len(aliases["candidates"]), 2)

    def test_weak_fingerprint_requires_a_strong_member_anchor(self) -> None:
        weak = _candidate(
            artifact="1" * 64,
            member="member:one",
            release="1",
            symbol="weak",
        )
        weak["match_strength"] = "weak"
        strong = _candidate(
            artifact="1" * 64,
            member="member:one",
            release="1",
            symbol="strong",
        )
        core = {
            "format": LIBRARY_MATCH_EVIDENCE_FORMAT,
            "status": "proposed",
            "executes_original_binary": False,
            "bindings": {},
            "observations": [
                _observation("strong", 0x1000, [strong]),
                _observation("weak", 0x1010, [weak]),
            ],
            "observed_control_edges": [],
            "counts": {},
            "authority": {
                "matching_is_provenance_evidence_only": True,
                "can_authorize_replacement": False,
            },
        }
        evidence = {**core, "evidence_sha256": _canonical_sha256(core)}

        hypotheses = infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "weak-hypotheses.json",
        )

        self.assertEqual(hypotheses["status"], "incomplete")
        self.assertEqual(
            hypotheses["selected_placements"][1]["identity_status"],
            "unidentified",
        )

    def test_indistinguishable_releases_stop_at_family_abi(self) -> None:
        candidates = [
            _candidate(
                artifact=value * 64,
                member=f"member:{value}",
                release=value,
                symbol="common",
            )
            for value in ("1", "2")
        ]
        core = {
            "format": LIBRARY_MATCH_EVIDENCE_FORMAT,
            "status": "proposed",
            "executes_original_binary": False,
            "bindings": {},
            "observations": [_observation("common", 0x1000, candidates)],
            "observed_control_edges": [],
            "counts": {},
            "authority": {
                "matching_is_provenance_evidence_only": True,
                "can_authorize_replacement": False,
            },
        }
        evidence = {**core, "evidence_sha256": _canonical_sha256(core)}
        hypotheses = infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "family-hypotheses.json",
        )

        self.assertEqual(
            hypotheses["selected_placements"][0]["identity_status"],
            "library_family_abi",
        )

    def test_checked_import_report_preserves_variadic_callsite(self) -> None:
        report = self.root / "machine-import-report.json"
        write_json(
            report,
            {
                "format": "stage-a-static-machine-import-contracts-v1",
                "status": "ready",
                "authority": {
                    "lean_redecodes_boundary_routes": True,
                    "lean_reparses_exact_pe_imports": True,
                    "profile_status_fields_trusted": False,
                },
                "inputs": {
                    "original_sha256": sha256_file(self.original),
                    "reference_contract_sha256": "f" * 64,
                },
                "exact_inventory_matches": True,
                "remaining_premises": [],
                "blockers": [],
                "signatures": [
                    {
                        "id": 7,
                        "profile_id": "fixture-msvcrt",
                        "import": {"dll": "msvcrt.dll", "symbol": "fprintf"},
                        "abi": "cdecl",
                        "arity": {"kind": "variadic", "minimum_words": 2},
                        "bridgeable": True,
                        "disposition": "returns",
                        "memory_effect": "relationalState",
                        "memory_footprints": [],
                        "world_effect": "none",
                        "callback_mode": "none",
                    }
                ],
                "boundaries": [
                    {
                        "id": 3,
                        "signature_id": 7,
                        "import": {"dll": "msvcrt.dll", "symbol": "fprintf"},
                        "argument_evidence": "static_contiguous_variadic_words",
                        "argument_words": 4,
                        "instruction_rva": 0x1000,
                        "source_rva": 0x1000,
                        "continuation_rva": 0x1009,
                        "route": "direct",
                        "thunk_rva": None,
                    }
                ],
            },
        )

        requirements = derive_dynamic_library_requirements(
            machine_ir=self.machine,
            machine_import_report=report,
            out=self.root / "dynamic-requirements.json",
        )

        self.assertEqual(requirements["status"], "qualified")
        self.assertEqual(requirements["counts"]["import_identities"], 1)
        self.assertEqual(requirements["counts"]["callsites"], 1)
        callsite = requirements["callsites"][0]
        self.assertEqual(callsite["argument_words"], 4)
        self.assertEqual(
            callsite["argument_evidence"], "static_contiguous_variadic_words"
        )
        self.assertEqual(callsite["abi_contract"]["arity"]["kind"], "variadic")

    def test_import_report_with_remaining_premise_fails_closed(self) -> None:
        report = self.root / "machine-import-report.json"
        write_json(
            report,
            {
                "format": "stage-a-static-machine-import-contracts-v1",
                "status": "ready",
                "authority": {
                    "lean_redecodes_boundary_routes": True,
                    "lean_reparses_exact_pe_imports": True,
                    "profile_status_fields_trusted": False,
                },
                "inputs": {
                    "original_sha256": sha256_file(self.original),
                    "reference_contract_sha256": "f" * 64,
                },
                "exact_inventory_matches": True,
                "remaining_premises": [{"id": "unclosed"}],
                "blockers": [],
                "signatures": [],
                "boundaries": [],
            },
        )

        with self.assertRaisesRegex(LinkedLibraryError, "remaining premises"):
            derive_dynamic_library_requirements(
                machine_ir=self.machine,
                machine_import_report=report,
                out=self.root / "dynamic-requirements.json",
            )

    def test_partitions_units_with_review_artifact_match_and_import_thunk(self) -> None:
        lock = self._write_runtime_catalog()
        review = bind_linked_island_review(
            {
                "format": LINKED_ISLAND_REVIEW_FORMAT,
                "original_binary_sha256": sha256_file(self.original),
                "islands": [
                    {
                        "id": "application:entry",
                        "kind": "application",
                        "authority": "operator_reviewed_exact_range",
                        "ranges": [
                            {
                                "rva_start": 0x1000 + len(_FUNCTION),
                                "rva_end": 0x1000 + len(_FUNCTION) + 1,
                            }
                        ],
                    }
                ],
            }
        )
        manifest = match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=lock,
            review=review,
            out=self.root / "linked-islands.json",
        )

        self.assertEqual(manifest["status"], "classified")
        self.assertTrue(manifest["coverage"]["classified_exactly_once"])
        self.assertEqual(manifest["coverage"]["unknown_units"], 0)
        self.assertEqual(manifest["counts"]["artifact_matches"], 1)
        by_kind = {row["kind"]: row for row in manifest["islands"]}
        self.assertEqual(by_kind["application"]["unit_ids"], ["unit:1009"])
        self.assertEqual(by_kind["linked_dependency"]["unit_ids"], ["unit:1000"])
        self.assertEqual(by_kind["import_thunk"]["unit_ids"], ["unit:100a"])
        self.assertFalse(by_kind["linked_dependency"]["replacement_authorized"])

    def test_refined_unknowns_split_at_non_call_cfg_boundaries(self) -> None:
        lock_library_catalog(indexes=[], out=self.root / "empty-lock.json")
        evidence = propose_library_match_evidence(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=self.root / "empty-lock.json",
            review=None,
            out=self.root / "empty-evidence.json",
        )
        infer_library_hypotheses(
            match_evidence=evidence,
            out=self.root / "empty-hypotheses.json",
        )

        manifest = refine_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            match_evidence=self.root / "empty-evidence.json",
            hypotheses=self.root / "empty-hypotheses.json",
            review=None,
            out=self.root / "refined-islands.json",
        )

        self.assertTrue(manifest["coverage"]["classified_exactly_once"])
        self.assertEqual(manifest["counts"]["unknown_cfg_components"], 2)
        unknowns = [
            island for island in manifest["islands"] if island["kind"] == "unknown"
        ]
        self.assertEqual([island["unit_count"] for island in unknowns], [1, 1])

    def test_ambiguous_library_identity_fails_closed(self) -> None:
        obj = _coff_object(_FUNCTION, symbol="_runtime")
        (self.artifacts / "one.obj").write_bytes(obj)
        (self.artifacts / "two.obj").write_bytes(obj)
        index_paths = []
        for name in ("one", "two"):
            inputs = bind_library_artifact_inputs(
                {
                    "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                    "catalog_id": name,
                    "artifacts": [{"id": name, "path": f"{name}.obj"}],
                }
            )
            path = self.root / f"{name}-index.json"
            index_library_artifacts(
                inputs=inputs,
                artifact_root=self.artifacts,
                out=path,
            )
            index_paths.append(path)
        lock = lock_library_catalog(indexes=index_paths, out=self.root / "lock.json")
        manifest = match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=self.root / "lock.json",
            review=None,
            out=self.root / "linked-islands.json",
        )

        self.assertEqual(lock["counts"]["catalogs"], 2)
        self.assertEqual(manifest["status"], "incomplete")
        self.assertEqual(manifest["counts"]["ambiguous_artifact_matches"], 1)
        self.assertGreater(manifest["coverage"]["unknown_units"], 0)
        self.assertEqual(manifest["issues"][0]["code"], "ambiguous_artifact_match")

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

    def _write_machine_package(self) -> None:
        start = 0x1000
        units = [
            _unit(start, start + len(_FUNCTION)),
            _unit(start + len(_FUNCTION), start + len(_FUNCTION) + 1),
            _unit(
                start + len(_FUNCTION) + 1,
                start + len(_FUNCTION) + 1 + len(_THUNK),
                control={"kind": "external_jump"},
                events=[
                    {
                        "kind": "external_call",
                        "dll": "KERNEL32.dll",
                        "symbol": "WriteFile",
                        "ordinal": None,
                    }
                ],
            ),
        ]
        ir = self.machine / "machine-ir.jsonl"
        ir.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="utf-8",
        )
        write_json(
            self.machine / "machine-ir-manifest.json",
            {
                "format": "stage-a-machine-ir-v2",
                "binary": {"sha256": sha256_file(self.original)},
                "artifacts": {
                    "machine_ir": {
                        "path": "machine-ir.jsonl",
                        "sha256": sha256_file(ir),
                    }
                },
            },
        )

    def _write_runtime_catalog(self) -> Path:
        (self.artifacts / "runtime.a").write_bytes(
            _archive("runtime.obj", _coff_object(_FUNCTION, symbol="_runtime"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "runtime",
                "artifacts": [{"id": "runtime", "path": "runtime.a"}],
            }
        )
        index = self.root / "runtime-index.json"
        index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=index,
        )
        lock_library_catalog(indexes=[index], out=self.root / "lock.json")
        return self.root / "lock.json"

    def _write_single_reviewed_island(
        self, *, kind: str = "application"
    ) -> dict[str, object]:
        review = bind_linked_island_review(
            {
                "format": LINKED_ISLAND_REVIEW_FORMAT,
                "original_binary_sha256": sha256_file(self.original),
                "islands": [
                    {
                        "id": "application:all",
                        "kind": kind,
                        "authority": "operator_reviewed_exact_range",
                        "ranges": [
                            {
                                "rva_start": 0x1000,
                                "rva_end": 0x1000
                                + len(_FUNCTION)
                                + len(_APPLICATION)
                                + len(_THUNK),
                            }
                        ],
                    }
                ],
            }
        )
        return match_linked_islands(
            original=self.original,
            machine_ir=self.machine,
            catalog_lock=None,
            review=review,
            out=self.root / "all-island.json",
        )

    @staticmethod
    def _interface_catalog() -> dict[str, object]:
        return bind_interface_contract_catalog(
            {
                "format": LIBRARY_INTERFACE_CATALOG_FORMAT,
                "catalog_id": "portable-interfaces",
                "contracts": [
                    {
                        "id": "byte-transform-v1",
                        "component_contract": {
                            "format": "fixture-component-contract-v1",
                            "contract_sha256": "a" * 64,
                        },
                        "domain": {"kind": "total"},
                    }
                ],
                "replacements": [
                    {
                        "id": "portable-byte-transform",
                        "contract_id": "byte-transform-v1",
                        "kind": "replace_by_canonical_interface",
                        "portable": True,
                        "implementation": {
                            "portable_source_sha256": "b" * 64,
                            "portable_symbol": "portable_byte_transform",
                        },
                        "qualification": {"status": "qualified"},
                    }
                ],
            }
        )


def _canonical_sha256(payload: object) -> str:
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


def _candidate(
    *, artifact: str, member: str, release: str, symbol: str
) -> dict[str, object]:
    return {
        "catalog_id": "fixture-catalog",
        "artifact_id": "fixture-runtime",
        "artifact_sha256": artifact,
        "island_kind": "linked_dependency",
        "snapshot": {
            "id": f"snapshot-{release}",
            "target": {
                "architecture": "i686",
                "object_format": "coff",
                "abi": "mingw32",
            },
        },
        "library_identity": {
            "family_id": "fixture-runtime",
            "component_id": "runtime",
            "release_id": release,
            "abi_id": "mingw32",
        },
        "retention_model": "archive_member",
        "member_path": [f"runtime-{release}.obj"],
        "member_id": member,
        "symbols": [symbol],
        "candidate_ids": [f"fixture:{release}:{symbol}"],
        "normalized_sha256": "a" * 64,
        "fixed_bytes": 16,
    }


def _observation(
    identity: str, start: int, candidates: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "id": f"target:{identity}",
        "target": {
            "rva_start": start,
            "rva_end": start + 16,
            "unit_ids": [f"unit:{start:x}"],
            "reachable": True,
        },
        "candidates": candidates,
        "candidate_count": len(candidates),
    }


def _unit(
    start: int,
    end: int,
    *,
    control: dict[str, object] | None = None,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": f"unit:{start:x}",
        "reachable": True,
        "source": {
            "original": {"rva_start": start, "rva_end": end},
            "contract_sha256": sha256(f"contract:{start:x}".encode()).hexdigest(),
            "instruction_bytes_sha256": sha256(f"bytes:{start:x}".encode()).hexdigest(),
        },
        "control": control or {"kind": "return"},
        "semantics": {"external_events": events or []},
    }


def _coff_object(code: bytes, *, symbol: str) -> bytes:
    raw_pointer = 20 + 40
    symbol_pointer = raw_pointer + len(code)
    header = struct.pack("<HHIIIHH", 0x014C, 1, 0, symbol_pointer, 2, 0, 0)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0,
        0,
        len(code),
        raw_pointer,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    encoded_name = symbol.encode("ascii")
    if len(encoded_name) > 8:
        raise ValueError("fixture symbol must fit in the COFF short-name field")
    symbol_row = struct.pack(
        "<8sIhHBB",
        encoded_name.ljust(8, b"\0"),
        0,
        1,
        0x20,
        2,
        1,
    )
    aux = bytearray(18)
    struct.pack_into("<I", aux, 4, len(code))
    return header + section + code + symbol_row + bytes(aux) + struct.pack("<I", 4)


def _archive(name: str, body: bytes) -> bytes:
    encoded_name = (name + "/").encode("ascii")
    header = (
        encoded_name.ljust(16, b" ")
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(body)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    return b"!<arch>\n" + header + body + (b"\n" if len(body) & 1 else b"")


def _omf_record(record_type: int, payload: bytes) -> bytes:
    length = len(payload) + 1
    prefix = bytes([record_type]) + struct.pack("<H", length) + payload
    checksum = (-sum(prefix)) & 0xFF
    return prefix + bytes([checksum])


if __name__ == "__main__":
    unittest.main()
