from tests.stage_a_relational_support import *

from spaghetti_extractor.relational.lean.expressions import (
    _lean_machine_call_memory_size,
    _lean_register_relation_pair,
)
from spaghetti_extractor.relational.lean.common import (
    _lean_register_relation_pair as _lean_common_register_relation_pair,
)
from spaghetti_extractor.relational.model import _semantic_hash
from spaghetti_extractor.relational.pipeline import _extraction_failure_blocker
from spaghetti_extractor.relational.preflight import side_diagnostics
from spaghetti_extractor.relational.x87_profile import (
    qualified_singleton_bytes,
    state_only_singleton_bytes,
)


class StageARelationalPipelineTests(StageARelationalTestBase):
    def test_proof_check_rejects_legacy_report_before_lean_or_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            (report / "verdict.json").write_text(
                json.dumps({"format": "stage-a-relational-verdict-v3"}),
                encoding="utf-8",
            )

            with (
                patch(
                    "spaghetti_extractor.relational.pipeline."
                    "_extract_relational_behaviors"
                ) as extract,
                patch(
                    "spaghetti_extractor.relational.lean.compiler."
                    "_run_lean_relational"
                ) as run_lean,
            ):
                with self.assertRaisesRegex(
                    StageAInputError,
                    "requires a stage-a-relational-nix-build-v1 verdict",
                ):
                    stage_a_check_relational_proof(report=report)

            extract.assert_not_called()
            run_lean.assert_not_called()

    def test_proof_check_delegates_nix_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary)
            out = report / "check.json"
            verdict = {
                "format": "stage-a-relational-nix-build-v1",
                "status": "incomplete",
                "verdict": "incomplete",
            }
            (report / "verdict.json").write_text(
                json.dumps(verdict),
                encoding="utf-8",
            )
            expected = {"status": "pass"}

            with patch(
                "spaghetti_extractor.relational.build."
                "_check_nix_relational_report",
                return_value=expected,
            ) as check_nix:
                result = stage_a_check_relational_proof(report=report, out=out)

            self.assertEqual(result, expected)
            check_nix.assert_called_once_with(
                report=report,
                verdict=verdict,
                out=out,
            )

    def test_x87_memory_effect_is_semantically_qualified_before_composition(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = self._write_pe(root / "x87.exe", bytes.fromhex("dd0424ebfb"))
            mapping = {
                "blocks": [{
                    "id": "x87-loop",
                    "kind": "code",
                    "original": {"rva_start": 0x1000, "rva_end": 0x1005},
                }]
            }

            issues = side_diagnostics("original", binary, mapping)

            self.assertEqual(issues, [])

    def test_x87_state_only_singleton_proposal_is_deliberately_bounded(self):
        for encoded in (
            "9b",       # wait
            "d9e8",     # fld1
            "d9ee",     # fldz
            "d9c9",     # fxch st(1)
            "dec1",     # faddp st(1), st
            "ddd8",     # fstp st(0)
            "dbe3",     # fninit
        ):
            self.assertTrue(state_only_singleton_bytes(bytes.fromhex(encoded)), encoded)

        for encoded in (
            "dd0424",   # fld qword ptr [esp]
            "dd5c2408", # fstp qword ptr [esp + 8]
            "dfe0",     # fnstsw ax
            "dbf1",     # fcomi st, st(1), writes EFLAGS
            "9bd9e8",   # wait prefix plus another command is not one singleton
        ):
            self.assertFalse(state_only_singleton_bytes(bytes.fromhex(encoded)), encoded)

    def test_x87_qualified_singleton_proposal_matches_reviewed_memory_forms(self):
        for encoded in (
            "dd0424",       # fld qword ptr [esp]
            "dd5c2408",     # fstp qword ptr [esp + 8]
            "dc4018",       # fadd qword ptr [eax + 0x18]
            "d93d00104000", # fnstcw word ptr [0x401000]
            "dbe9",         # fucomi st, st(1)
            "dfe0",         # fnstsw ax
        ):
            self.assertTrue(qualified_singleton_bytes(bytes.fromhex(encoded)), encoded)

        for encoded in (
            "9bd9e8", # wait prefix plus another command is not one singleton
            "da00",   # unsupported integer-memory arithmetic family
            "d9d0",   # unsupported register encoding
            "66dd0424", # unsupported prefix form
        ):
            self.assertFalse(qualified_singleton_bytes(bytes.fromhex(encoded)), encoded)

    def test_extraction_normalization_failure_is_not_reported_as_decode_failure(self):
        extraction = {
            "status": "failed",
            "stderr": "uncaught exception: original region 7429 did not normalize\n",
        }

        self.assertIn("could not normalize", _extraction_failure_blocker(extraction))

    def test_fixed_code_pointer_register_relation_emits_target_and_hashes_it(self):
        relation = {
            "original": "esi",
            "candidate": "esi",
            "relation": "fixed_code_pointer",
            "target_id": 222,
        }

        self.assertEqual(
            _lean_register_relation_pair(relation),
            (
                "{ original := .esi, candidate := .esi, "
                "relation := .fixedCodePointer 222 }"
            ),
        )
        self.assertEqual(
            _lean_common_register_relation_pair(relation),
            _lean_register_relation_pair(relation),
        )
        self.assertNotEqual(
            _semantic_hash(relation),
            _semantic_hash({**relation, "target_id": 223}),
        )
        with self.assertRaises(StageAInputError):
            _lean_register_relation_pair({
                key: value for key, value in relation.items()
                if key != "target_id"
            })
        with self.assertRaises(StageAInputError):
            _lean_register_relation_pair({
                **relation, "relation": "code_pointer",
            })

    def test_proof_shards_are_bounded_by_region_count_and_estimated_source_size(self):
        self.assertEqual(
            _partition_proof_shards(
                [100, 100, 450, 100, 100, 100],
                max_regions=3,
                target_bytes=500,
            ),
            [[0, 1], [2], [3, 4, 5]],
        )

    def test_bounded_terminated_memory_sizes_emit_every_field(self):
        bounded = {
            "kind": "bounded_terminated",
            "source_argument": 1,
            "source_offset": 4,
            "unit_bytes": 2,
            "sentinel": [0, 255],
            "max_units": 8,
        }
        selected = {
            "kind": "argument_or_bounded_terminated",
            "length_argument": 0,
            "terminated_value": 0xFFFFFFFF,
            "source_argument": 1,
            "source_offset": 4,
            "unit_bytes": 2,
            "sentinel": [0, 255],
            "max_units": 8,
        }

        self.assertEqual(
            _lean_machine_call_memory_size(bounded),
            ".boundedTerminated 1 4 2 [0, 255] 8",
        )
        self.assertEqual(
            _lean_machine_call_memory_size(selected),
            ".argumentOrBoundedTerminated 0 4294967295 1 4 2 [0, 255] 8",
        )

        replacements = {
            "kind": "different_kind",
            "length_argument": 2,
            "terminated_value": 7,
            "source_argument": 2,
            "source_offset": 12,
            "unit_bytes": 4,
            "sentinel": [1, 255],
            "max_units": 9,
        }
        for size in (bounded, selected):
            base_hash = _semantic_hash(size)
            for field in size:
                with self.subTest(kind=size["kind"], field=field):
                    mutated = {**size, field: replacements[field]}
                    self.assertNotEqual(_semantic_hash(mutated), base_hash)

    def test_relation_contract_generator_projects_complete_block_map(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 4},
                "candidate": {"rva": 0x1000, "size": 4},
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": "entry_loop",
                    "function_block_index": 0,
                },
                "root": {
                    "checked": True,
                    "kind": "linker_map_function",
                    "symbol": "entry_loop",
                },
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )

            self.assertEqual(result["status"], "generated")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertTrue(payload["regions"][0]["root"])
            self.assertEqual(payload["regions"][0]["function_id"], "entry_loop")
            self.assertEqual(payload["regions"][0]["function_block_index"], 0)
            self.assertEqual(payload["regions"][0]["function_cut_index"], 0)
            self.assertTrue(payload["regions"][0]["function_entry"])
            self.assertEqual(
                payload["regions"][0]["function_root_kind"],
                "linker_map_function",
            )
            self.assertEqual(payload["environment"]["id"], RELATIONAL_ENVIRONMENT_ID)
            self.assertEqual(payload["memory_relation"]["mode"], "identity")

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            renormalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            self.assertEqual(
                [region["target_ids"] for region in renormalized["regions"]],
                [region["target_ids"] for region in payload["regions"]],
            )
            self.assertEqual(
                [region["code_targets"] for region in renormalized["regions"]],
                [region["code_targets"] for region in payload["regions"]],
            )

    def test_relation_contract_generator_cuts_after_faulting_signed_divide(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("89f099f77c244089c3")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "signed-divide",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
                "source": {
                    "kind": "linker_map_capstone_block_match_v1",
                    "function": "signed_divide",
                    "function_block_index": 0,
                },
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )

            self.assertEqual(result["status"], "generated", result)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(
                [region["original"]["size"] for region in payload["regions"]],
                [7, 2],
            )
            self.assertEqual(
                [region["candidate"]["size"] for region in payload["regions"]],
                [7, 2],
            )
            self.assertEqual(
                [region["function_cut_index"] for region in payload["regions"]],
                [0, 1],
            )

    def test_relation_contract_generator_selects_shared_external_profile_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("ff1540204000c3")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            profile = root / "external-profile.json"
            profile.write_text(json.dumps({
                "format": "stage-a-external-environment-profile-v1",
                "id": "generic-kernel32-test-v1",
                "machine_import_call_contracts": [{
                    "id": 10,
                    "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }, {
                    "id": 11,
                    "import": {"dll": "kernel32.dll", "symbol": "GetLastError"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
            }), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                external_profile=profile,
                out=contract,
            )

            self.assertEqual(result["status"], "generated", result["issues"])
            self.assertEqual(result["counts"]["machine_import_call_contracts"], 1)
            self.assertEqual(result["external_profile"]["declared_contracts"], 2)
            self.assertEqual(result["external_profile"]["selected_contracts"], 1)
            self.assertEqual(result["external_profile"]["ignored_contracts"], 1)
            self.assertEqual(result["external_profile"]["covered_common_imports"], 1)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["machine_import_call_contracts"][0]["import"],
                {"dll": "kernel32.dll", "symbol": "Sleep"},
            )

    def test_relation_contract_generator_rejects_invalid_external_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("ff1540204000c3")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            profile = root / "external-profile.json"
            duplicate = {
                "id": 4,
                "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            }
            profile.write_text(json.dumps({
                "format": "stage-a-external-environment-profile-v1",
                "id": "duplicate-v1",
                "machine_import_call_contracts": [duplicate, duplicate],
            }), encoding="utf-8")

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                external_profile=profile,
                out=root / "relation.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn(
                "machine_import_call_contract_invalid",
                {issue["category"] for issue in result["issues"]},
            )

    def test_relation_contract_generator_composes_disjoint_external_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("ff1540204000c3")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            ignored_profile = root / "ignored-profile.json"
            ignored_profile.write_text(json.dumps({
                "format": "stage-a-external-environment-profile-v1",
                "id": "generic-errors-v1",
                "machine_import_call_contracts": [{
                    "id": 40,
                    "import": {"dll": "kernel32.dll", "symbol": "GetLastError"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 0,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
            }), encoding="utf-8")
            selected_profile = root / "selected-profile.json"
            selected_profile.write_text(json.dumps({
                "format": "stage-a-external-environment-profile-v1",
                "id": "generic-scheduling-v1",
                "machine_import_call_contracts": [{
                    "id": 90,
                    "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 1,
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
            }), encoding="utf-8")
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                external_profile=[ignored_profile, selected_profile],
                out=contract,
            )

            self.assertEqual(result["status"], "generated", result["issues"])
            self.assertEqual(
                result["external_profile_set"],
                {
                    "format": "stage-a-external-environment-profile-set-v1",
                    "ids": ["generic-errors-v1", "generic-scheduling-v1"],
                    "selected_contracts": 1,
                },
            )
            self.assertNotIn("external_profile", result)
            self.assertEqual(len(result["external_profiles"]), 2)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["machine_import_call_contracts"][0]["id"],
                0,
            )
            self.assertEqual(
                payload["machine_import_call_contracts"][0]["import"],
                {"dll": "kernel32.dll", "symbol": "Sleep"},
            )

    def test_relation_contract_generator_rejects_overlapping_external_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("ff1540204000c3")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            candidate.write_bytes(_pe32_import_image(code, symbol="Sleep"))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "entry",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")

            profiles = []
            for profile_id in ("generic-scheduling-v1", "alternate-scheduling-v1"):
                profile = root / f"{profile_id}.json"
                profile.write_text(json.dumps({
                    "format": "stage-a-external-environment-profile-v1",
                    "id": profile_id,
                    "machine_import_call_contracts": [{
                        "id": 1,
                        "import": {"dll": "kernel32.dll", "symbol": "Sleep"},
                        "abi_template": "pe32-stdcall-v1",
                        "argument_words": 1,
                        "memory_effect": "none",
                        "memory_footprints": [],
                        "world_effect": "none",
                    }],
                }), encoding="utf-8")
                profiles.append(profile)

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                external_profile=profiles,
                out=root / "relation.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn(
                "external_environment_profile_import_duplicate",
                {issue["category"] for issue in result["issues"]},
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for string-copy relational proofs")
    def test_relation_generator_splits_and_checks_symbolic_rep_movsd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("b904000000f3a5ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "copy-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": len(code)},
                "candidate": {"rva": 0x1000, "size": len(code)},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(len(payload["regions"]), 2)
            self.assertEqual(
                (payload["regions"][0]["original"]["rva_start"], payload["regions"][0]["original"]["size"]),
                (0x1000, 7),
            )
            self.assertEqual(
                (payload["regions"][1]["original"]["rva_start"], payload["regions"][1]["original"]["size"]),
                (0x1007, 2),
            )

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["status"], "prepared")

    def test_contract_rejects_executable_coverage_gap_before_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json", region_size=2)

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("executable_coverage_gap", {issue["category"] for issue in result["issues"]})

    def test_contract_rejects_unresolved_logical_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json", target_rva=0x1002)

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("unresolved_code_target", {issue["category"] for issue in result["issues"]})

    def test_contract_requires_explicit_adversarial_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x8d\x03\xeb\xfc")
            contract = self._write_contract(root / "relation.json")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            del payload["environment"]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("environment_contract_missing", {issue["category"] for issue in result["issues"]})

    def test_unsupported_instruction_emits_actionable_semantic_gap_before_lean(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("0f57c0ebfb")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=5)
            report = root / "report"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["reason_code"], "semantic_preflight_incomplete")
            gaps = json.loads((report / "semantic-gaps.json").read_text(encoding="utf-8"))
            self.assertEqual(gaps["issues"][0]["category"], "formal_instruction_unsupported")
            self.assertIn("Lean decoder", gaps["issues"][0]["next_action"])

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for exact-byte relational replay")
    def test_exact_byte_region_proof_rejects_legacy_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("8b03894304ebf9"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("8b4300894304ebf8"))
            contract = self._write_contract(root / "relation.json", region_size=7, candidate_region_size=8)
            report = root / "report"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=report,
            )

            self.assertEqual(result["status"], "prepared")
            self.assertFalse((report / "verdict.json").exists())
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            self.assertEqual(
                proof_ir["obligations"][0]["status"],
                "pending_lrat",
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for checked counterexamples")
    def test_semantic_mutation_is_prepared_for_the_nix_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", b"\x89\xd8\xeb\xfc")
            candidate = self._write_pe(root / "candidate.exe", b"\x89\xc8\xeb\xfc")
            contract = self._write_contract(root / "relation.json")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for width-aware relational proofs")
    def test_word_test_and_compare_zero_are_exactly_equivalent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("84c074006685f67400ebf5"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("3c0074006683fe007400ebf4"))
            contract = self._write_contract(root / "relation.json", region_size=11, candidate_region_size=12)
            payload = json.loads(contract.read_text(encoding="utf-8"))
            pairs = payload["regions"][0]["inputs"]
            payload["code_targets"] = [
                {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                {"id": 1, "original_rva": 0x1004, "candidate_rva": 0x1004},
                {"id": 2, "original_rva": 0x1009, "candidate_rva": 0x100A},
            ]
            payload["regions"] = [
                {
                    "id": "byte-condition",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 4},
                    "candidate": {"rva": 0x1000, "size": 4},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "word-condition",
                    "root": False,
                    "original": {"rva": 0x1004, "size": 5},
                    "candidate": {"rva": 0x1004, "size": 6},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "loop-back",
                    "root": False,
                    "original": {"rva": 0x1009, "size": 2},
                    "candidate": {"rva": 0x100A, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
            ]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for condition-code relational proofs")
    def test_setcc_and_cmovcc_compose_across_equivalent_flag_producers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = self._write_pe(root / "original.exe", bytes.fromhex("83f9000f94c00f44c3ebf5"))
            candidate = self._write_pe(root / "candidate.exe", bytes.fromhex("85c90f94c00f44c3ebf6"))
            contract = self._write_contract(
                root / "relation.json",
                region_size=11,
                candidate_region_size=10,
            )

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared")

    def test_cmov_expression_emits_general_compositional_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("eb0039fa89d00f4cc783c01b7cf4c3")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(
                root / "relation.json",
                region_size=len(code),
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            pairs = payload["regions"][0]["inputs"]
            payload["code_targets"] = [
                {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                {"id": 1, "original_rva": 0x1002, "candidate_rva": 0x1002},
                {"id": 2, "original_rva": 0x100E, "candidate_rva": 0x100E},
            ]
            payload["regions"] = [
                {
                    "id": "entry",
                    "root": True,
                    "original": {"rva": 0x1000, "size": 2},
                    "candidate": {"rva": 0x1000, "size": 2},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "cmov-loop",
                    "root": False,
                    "original": {"rva": 0x1002, "size": len(code) - 3},
                    "candidate": {"rva": 0x1002, "size": len(code) - 3},
                    "inputs": pairs,
                    "outputs": pairs,
                },
                {
                    "id": "fallthrough",
                    "root": False,
                    "original": {"rva": 0x100E, "size": 1},
                    "candidate": {"rva": 0x100E, "size": 1},
                    "inputs": pairs,
                    "outputs": pairs,
                },
            ]
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared", result)
            proof = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((root / "report" / "lean" / "StageA").glob(
                    "RelationalProofShard*.lean"
                ))
            )
            definitions = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted((root / "report" / "lean" / "StageA").glob(
                    "RelationalDefinitionsShard*.lean"
                ))
            )
            self.assertIn("behaviorRegistersEquivalent", proof)
            self.assertIn("behaviorWritesEquivalent", proof)
            self.assertIn("behaviorOutcomeEquivalent", proof)
            self.assertIn("behaviorsEquivalent_of_components", proof)
            self.assertIn("behaviorsEquivalent_of_normalized_components", proof)
            self.assertIn("region1NormalizedBehavior", proof)
            self.assertIn("region2CheckedDirectBehavior", proof)
            self.assertIn("OutcomeConditionWithin", definitions)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for cross-region flag execution")
    def test_logical_execution_carries_computed_flags_into_the_next_region(self):
        with tempfile.TemporaryDirectory() as temporary:
            lean_dir = Path(temporary)
            stage_a = lean_dir / "StageA"
            stage_a.mkdir()
            source_root = Path(__file__).parents[1] / "src" / "spaghetti_extractor" / "lean" / "StageA"
            for name in ("X87.lean", "Formal.lean"):
                shutil.copyfile(source_root / name, stage_a / name)
            (stage_a / "FlagsCompose.lean").write_text(
                """import StageA.Formal

namespace StageA.FlagsCompose

open StageA.Formal

def inputRegisters : Registers Expr := {
  eax := .inputReg .eax
  ebx := .inputReg .ebx
  ecx := .inputReg .ecx
  edx := .inputReg .edx
  esi := .inputReg .esi
  edi := .inputReg .edi
  ebp := .inputReg .ebp
  esp := .inputReg .esp
}

def concreteRegisters (ecx : Nat) : Registers Word := {
  eax := BitVec.ofNat 32 0
  ebx := BitVec.ofNat 32 0
  ecx := BitVec.ofNat 32 ecx
  edx := BitVec.ofNat 32 0
  esi := BitVec.ofNat 32 0
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := BitVec.ofNat 32 0
}

def compare : LogicalBehavior := {
  registers := inputRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := some (subtractionFlags (.inputReg .ecx) (.constant 0) (.inputReg .ecx))
  outcome := .jump 1
}

def branch : LogicalBehavior := {
  registers := inputRegisters
  x87 := initialSymbolicX87
  writes := []
  flags := none
  outcome := .branch (.inputFlag 6) 2 3
}

def environment : Environment := { result := fun _ event => event.state }

def initial (ecx : Nat) : MachineState := {
  registers := concreteRegisters ecx
  memory := fun _ => BitVec.ofNat 8 0
  eflags := BitVec.ofNat 32 0
}

def selectedRegion (ecx : Nat) : Nat :=
  let behaviors := [some compare, some branch, none, none]
  let first := stepExecution environment behaviors (.running 0 (initial ecx) [] 0 [])
  match stepExecution environment behaviors first with
  | .running region _ _ _ _ => region
  | _ => 99

example : selectedRegion 0 = 2 := by decide
example : selectedRegion 1 = 3 := by decide

end StageA.FlagsCompose
""",
                encoding="utf-8",
            )

            result = _run_lean_relational(lean_dir, bundle="FlagsCompose")
            self.assertEqual(result["status"], "checked", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for bit-scan relational proofs")
    def test_bsr_and_tzcnt_have_checked_partial_flag_and_undefined_value_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("0fbdc3ebfbf30fbcc3ebfa")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            pairs = [{"original": register, "candidate": register} for register in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
            )]
            payload = {
                "format": "stage-a-relation-contract-v1",
                "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
                "observations": RELATIONAL_OBSERVATIONS,
                "code_targets": [
                    {"id": 0, "original_rva": 0x1000, "candidate_rva": 0x1000},
                    {"id": 1, "original_rva": 0x1005, "candidate_rva": 0x1005},
                ],
                "regions": [
                    {
                        "id": "bsr-loop", "root": True,
                        "original": {"rva": 0x1000, "size": 5},
                        "candidate": {"rva": 0x1000, "size": 5},
                        "inputs": pairs, "outputs": pairs,
                    },
                    {
                        "id": "tzcnt-loop", "root": True,
                        "original": {"rva": 0x1005, "size": 6},
                        "candidate": {"rva": 0x1005, "size": 6},
                        "inputs": pairs, "outputs": pairs,
                    },
                ],
                "padding": [],
                "memory_relation": {"mode": "identity"},
            }
            contract = root / "relation.json"
            contract.write_text(json.dumps(payload), encoding="utf-8")

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared")
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_proofs = "\n".join(
                path.read_text(encoding="utf-8")
                for pattern in ("RelationalDefinitionsShard*.lean", "RelationalProofShard*.lean")
                for path in sorted((root / "report" / "lean" / "StageA").glob(pattern))
            )
            self.assertIn("highestSetBit", generated_proofs)
            self.assertIn("lowestSetBit", generated_proofs)
            self.assertNotIn("highestSetBitExpression", generated_proofs)
            self.assertNotIn("lowestSetBitExpression", generated_proofs)
            self.assertLess(len(bundle), 500_000)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for read-after-write relational proofs")
    def test_ambiguous_read_after_write_uses_compact_checked_expression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("8b44242cc7442460000000008b400483c001ebec")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["status"], "prepared", result)
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_proofs = "\n".join(
                path.read_text(encoding="utf-8")
                for pattern in ("RelationalDefinitionsShard*.lean", "RelationalProofShard*.lean")
                for path in sorted((root / "report" / "lean" / "StageA").glob(pattern))
            )
            self.assertIn("read8AfterWrite", generated_proofs)
            self.assertLess(len(bundle), 300_000)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 relational proofs")
    def test_x87_stack_and_arithmetic_use_the_qualified_physical_model(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("d9e8d9eed9c9dec1ddd8ebf4")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared", result)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for x87 memory proofs")
    def test_x87_memory_conversion_and_writes_are_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code = bytes.fromhex("dd0424dd5c2408ebf7")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            contract = self._write_contract(root / "relation.json", region_size=len(code))

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )

            self.assertEqual(result["status"], "prepared")
            semantic_gaps = json.loads(
                (root / "report" / "semantic-gaps.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(semantic_gaps["status"], "supported")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for mapped static-data proofs")
    def test_relocated_x87_static_data_uses_checked_memory_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocated_data(0x2000))
            candidate.write_bytes(_pe32_image_with_relocated_data(0x3000))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "x87-static-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 8},
                "candidate": {"rva": 0x1000, "size": 8},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))

            self.assertEqual(generated["status"], "generated")
            self.assertEqual(len(payload["value_targets"]), 1)
            self.assertEqual(payload["value_targets"][0]["mapped_size"], 8)
            self.assertEqual(payload["value_targets"][0]["original_value"], 0x402000)
            self.assertEqual(payload["value_targets"][0]["candidate_value"], 0x403000)

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=contract,
                out=root / "report",
            )
            self.assertEqual(result["status"], "prepared")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for immutable image-data proofs")
    def test_relocated_readonly_x87_data_is_decoded_from_exact_pe_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocated_data(0x2000, writable=False))
            candidate.write_bytes(_pe32_image_with_relocated_data(0x3000, writable=False))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "x87-immutable-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 8},
                "candidate": {"rva": 0x1000, "size": 8},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(payload["value_targets"], [])

            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["status"], "prepared")

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for indexed mapped-memory proofs")
    def test_relocation_pointer_table_emits_and_checks_bounded_index_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_relocation_pointer_table(0x2000, mask_index=True))
            candidate.write_bytes(_pe32_image_with_relocation_pointer_table(0x3000, mask_index=True))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "pointer-table-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 12},
                "candidate": {"rva": 0x1000, "size": 12},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            payload = json.loads(contract.read_text(encoding="utf-8"))
            self.assertEqual(generated["status"], "generated")
            self.assertEqual(payload["regions"][0]["bounds"], [{
                "original": "edx", "candidate": "edx", "unsigned_lt": 2,
            }])
            mapped = [target for target in payload["value_targets"] if target["mapped_size"] > 0]
            self.assertEqual(len(mapped), 1)
            self.assertEqual(mapped[0]["mapped_size"], 8)

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            normalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            normalized_mapped = [
                target for target in normalized["value_targets"] if target["mapped_size"] > 0
            ]
            self.assertEqual(normalized_mapped[0]["relocation_offsets"], [0, 4])

            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=root / "report",
            )
            self.assertEqual(result["status"], "prepared", result)
            proof_ir = json.loads(
                (root / "report" / "relational-proof-ir.json").read_text(encoding="utf-8")
            )
            assumption_kinds = {
                obligation["kind"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {
                "cfg_bound_invariant",
                "cfg_register_relation_preservation",
                "mapped_relocation_image_relation",
                "relational_product_graph_decoded_exit_completeness",
                "relational_product_graph_declared_edge_refinement",
                "relational_product_graph_reachable_local_refinement",
                "relational_product_graph_structure",
                "relational_segment_refinement",
                "static_proof_context",
                "product_graph_composition",
                "whole_program_observational_equivalence",
            })
            self.assertEqual(proof_ir["status"], "incomplete")
            segment_diagnostics = json.loads(
                (root / "report" / "relational-segment-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                segment_diagnostics["format"],
                "stage-a-segment-refinement-diagnostics-v1",
            )
            self.assertEqual(segment_diagnostics["status"], "analysis_only")
            self.assertFalse(segment_diagnostics["edges"][0]["eligible"])
            self.assertIn(
                "target_bound_invariant_required",
                segment_diagnostics["edges"][0]["failed_checks"],
            )
            segment_obligation = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "relational_segment_refinement"
            )
            self.assertEqual(
                segment_obligation["analysis"]["eligibility_diagnostic"],
                segment_diagnostics["edges"][0],
            )
            relocation = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "mapped_relocation_image_relation"
            )
            self.assertEqual(relocation["status"], "pending_lean")
            bundle = (root / "report" / "lean" / "StageA" / "RelationalBundle.lean").read_text(
                encoding="utf-8"
            )
            generated_sources = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "report" / "lean" / "StageA").glob("*.lean")
            )
            self.assertIn("GeneratedMappedRelocationImageCertificate", bundle)
            self.assertIn("MappedIndexedAddress", generated_sources)
            self.assertIn("originalExpression := some", generated_sources)
            self.assertIn("Expr.bitAnd", generated_sources)
            self.assertIn("boundsSatisfied", generated_sources)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for address-separation proofs")
    def test_relocated_read_after_stack_write_requires_cfg_address_separation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(_pe32_image_with_stack_write_and_relocated_read(0x2000))
            candidate.write_bytes(_pe32_image_with_stack_write_and_relocated_read(0x3000))
            mapping = root / "mapping.json"
            mapping.write_text(json.dumps({"blocks": [{
                "id": "stack-write-relocated-read-loop",
                "kind": "code",
                "original": {"rva": 0x1000, "size": 15},
                "candidate": {"rva": 0x1000, "size": 15},
            }]}), encoding="utf-8")
            contract = root / "relation.json"

            generated = stage_a_generate_relation_contract(
                original=original, candidate=candidate, mapping=mapping, out=contract,
            )
            self.assertEqual(generated["status"], "generated")
            payload = json.loads(contract.read_text(encoding="utf-8"))
            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            normalized, issues = _normalize_contract(payload, original_bin, candidate_bin)
            self.assertEqual(issues, [])
            self.assertEqual(len(normalized["regions"][0]["address_separations"]), 16)

            report = root / "report"
            result = stage_a_prepare_relational(
                original=original, candidate=candidate,
                relation_contract=contract, out=report,
            )
            self.assertEqual(result["status"], "prepared", result)
            proof_ir = json.loads((report / "relational-proof-ir.json").read_text(encoding="utf-8"))
            assumption_kinds = {
                obligation["kind"]
                for obligation in proof_ir["obligations"]
                if obligation["kind"] != "relational_region_equivalence"
            }
            self.assertEqual(assumption_kinds, {
                "cfg_address_separation_invariant",
                "cfg_register_relation_preservation",
                "memory_transition_preservation",
                "paired_stack_range_world",
                "relational_product_graph_decoded_exit_completeness",
                "relational_product_graph_declared_edge_refinement",
                "relational_product_graph_reachable_local_refinement",
                "relational_product_graph_structure",
                "relational_segment_refinement",
                "stack_address_separation_inventory",
                "static_proof_context",
                "product_graph_composition",
                "whole_program_observational_equivalence",
            })
            transition = next(
                obligation for obligation in proof_ir["obligations"]
                if obligation["kind"] == "memory_transition_preservation"
            )
            self.assertEqual(
                transition["id"],
                "memory-transition:stack-write-relocated-read-loop",
            )
            self.assertEqual(
                transition["repair_class"], "identical_symbolic_write_pullback"
            )
            self.assertEqual(
                proof_ir["memory_transition_summary"]["transition_obligations"], 1
            )
            self.assertEqual(proof_ir["status"], "incomplete")

            self.assertFalse((report / "verdict.json").exists())
