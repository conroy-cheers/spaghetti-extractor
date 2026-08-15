from __future__ import annotations

from ._support import *

class LinkedLibraryRecognitionTests(LinkedLibraryTestCase):
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

        self.assertEqual(index["format"], "spaghetti-extractor-library-artifact-index-v2")
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
                "format": "spaghetti-extractor-static-machine-import-contracts-v1",
                "status": "ready",
                "authority": {
                    "lean_redecodes_boundary_routes": True,
                    "lean_reparses_exact_pe_imports": True,
                    "profile_status_fields_trusted": False,
                },
                "inputs": {
                    "original_sha256": sha256_file(self.original),
                    "static_program_contract_sha256": "f" * 64,
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
                "format": "spaghetti-extractor-static-machine-import-contracts-v1",
                "status": "ready",
                "authority": {
                    "lean_redecodes_boundary_routes": True,
                    "lean_reparses_exact_pe_imports": True,
                    "profile_status_fields_trusted": False,
                },
                "inputs": {
                    "original_sha256": sha256_file(self.original),
                    "static_program_contract_sha256": "f" * 64,
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
