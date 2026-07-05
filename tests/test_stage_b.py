import json
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from haloce_catalog.stage_a import STAGE_A_MODEL_ID, STAGE_A_X86_64_MODEL_ID, stage_a_export_reference_contract, stage_a_generate_map, stage_a_validate
from haloce_catalog.stage_b import (
    STAGE_B_PROOF_RULE,
    STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
    stage_b_audit_readiness,
    stage_b_explain_delta,
    stage_b_export_decompiler,
    stage_b_generate_candidate_provenance,
    stage_b_generate_link_roots,
    stage_b_generate_skeleton,
    stage_b_materialize_upstream_suite,
    stage_b_run_functional_suite,
    stage_b_validate_candidate,
    _stage_b_delta_repair_items,
    _render_decompiled_c_source,
)
from haloce_catalog.util import sha256_bytes, sha256_file
from test_stage_a import _LeanCheckedMock, _pe32_image, _pe32_import_image


class StageBTests(unittest.TestCase):
    def test_stage_b_import_does_not_load_stage_a_prover(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "import haloce_catalog.stage_b; "
                    "print('stage_a_loaded=' + str('haloce_catalog.stage_a' in sys.modules)); "
                    "print('stage_binary_loaded=' + str('haloce_catalog.stage_binary' in sys.modules))"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("stage_a_loaded=False", proc.stdout)
        self.assertIn("stage_binary_loaded=True", proc.stdout)

    def test_stage_b_generation_api_uses_skeleton_module(self):
        self.assertEqual(stage_b_generate_skeleton.__module__, "haloce_catalog.stage_b_skeleton")
        self.assertEqual(stage_b_generate_link_roots.__module__, "haloce_catalog.stage_b_skeleton")

    def test_stage_b_candidate_provenance_api_uses_provenance_module(self):
        self.assertEqual(stage_b_generate_candidate_provenance.__module__, "haloce_catalog.stage_b_provenance")

    def test_stage_b_functional_api_uses_functional_module(self):
        self.assertEqual(stage_b_materialize_upstream_suite.__module__, "haloce_catalog.stage_b_functional")
        self.assertEqual(stage_b_run_functional_suite.__module__, "haloce_catalog.stage_b_functional")

    def test_generate_skeleton_from_linker_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            linker_map = self._write_map(root / "jq.map", "tiny")
            out = root / "skeleton"

            result = stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                source_language="c",
                out_dir=out,
            )

            self.assertEqual(result["status"], "generated")
            self.assertEqual(result["proof_rule"], STAGE_B_PROOF_RULE)
            self.assertFalse(result["source_policy"]["upstream_source_read"])
            self.assertEqual(result["counts"]["functions"], 1)
            self.assertEqual(result["implementation_recovery"]["status"], "incomplete")
            self.assertFalse(result["implementation_recovery"]["source_implements_behavior"])
            self.assertEqual(result["implementation_recovery"]["generated_source_kind"], "scaffold")
            self.assertEqual(result["implementation_recovery"]["functions"], 1)
            self.assertEqual(result["implementation_recovery"]["instruction_count"], 1)
            self.assertTrue((out / "src" / "jq_stage_b_skeleton.c").exists())
            functions = json.loads((out / "functions.json").read_text(encoding="utf-8"))
            self.assertEqual(functions["functions"][0]["name"], "tiny")
            self.assertEqual(functions["functions"][0]["instruction_preview"][0]["mnemonic"], "ret")

    def test_generate_skeleton_uses_pe_exports_when_no_map_is_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_export_dll(root / "libjq-1.dll")
            out = root / "skeleton"

            result = stage_b_generate_skeleton(
                original=original,
                target_name="jq-libjq-1",
                source_language="c",
                out_dir=out,
            )

            self.assertEqual(result["status"], "generated")
            self.assertEqual(result["reverse_engineering"]["function_source"], "pe_exports_or_entrypoint_sections")
            self.assertEqual(result["counts"]["functions"], 2)
            functions = json.loads((out / "functions.json").read_text(encoding="utf-8"))["functions"]
            self.assertEqual([function["name"] for function in functions], ["jq_init", "jv_parse"])
            self.assertEqual([function["seed"]["kind"] for function in functions], ["pe_export", "pe_export"])
            self.assertEqual(functions[0]["rva_start"], 0x1000)
            self.assertEqual(functions[0]["rva_end"], 0x1010)
            self.assertEqual(functions[1]["rva_start"], 0x1010)
            self.assertGreater(functions[1]["rva_end"], functions[1]["rva_start"])

    def test_generate_skeleton_from_stage_a_reference_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            reference_contract = root / "reference-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                layout_contract=layout_contract,
                out=reference_contract,
            )

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_contract,
                target_name="jq",
                source_language="c",
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["reverse_engineering"]["function_source"], "stage_a_reference_contract")
            self.assertIn("stage-a-reference-contract", result["source_policy"]["allowed_inputs"])
            self.assertEqual(result["inputs"]["reference_contract"]["sha256"], sha256_file(reference_contract))
            self.assertEqual(result["inputs"]["reference_contract"]["functions"], 1)
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            self.assertEqual(functions[0]["name"], "tiny")
            self.assertIn("reference_contract", functions[0])
            self.assertEqual(functions[0]["instruction_preview"][0]["mnemonic"], "ret")

    def test_generate_skeleton_rejects_stale_stage_a_reference_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            stale_original = self._write_pe(root / "stale-original.exe", b"\x90\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            candidate_map.write_text("                0x00401000                tiny\n", encoding="utf-8")
            block_map = root / "block-map.json"
            reference_contract = root / "reference-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                out=reference_contract,
            )

            with self.assertRaisesRegex(Exception, "reference contract is not bound to the original binary"):
                stage_b_generate_skeleton(
                    original=stale_original,
                    reference_contract=reference_contract,
                    target_name="jq",
                    source_language="c",
                    out_dir=root / "skeleton",
                )

    def test_generate_skeleton_reports_contract_decompiler_coverage_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                first\n"
                "                0x00401001                second\n",
                encoding="utf-8",
            )
            candidate_map.write_text(
                "                0x00401000                first\n"
                "                0x00401001                second\n",
                encoding="utf-8",
            )
            block_map = root / "block-map.json"
            reference_contract = root / "reference-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                out=reference_contract,
            )
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva_start": 0x1000,
                                "rva_end": 0x1001,
                                "name": "first",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int first(void) {\n  return 0;\n}",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_contract,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                out_dir=root / "skeleton",
            )

            coverage = result["implementation_recovery"]["decompiler_coverage"]
            self.assertEqual(coverage["status"], "incomplete")
            self.assertFalse(coverage["requires_decompiler_code"])
            self.assertEqual(coverage["counts"]["missing_decompiler_functions"], 1)
            self.assertEqual(coverage["counts"]["missing_decompiler_code_functions"], 0)
            self.assertEqual(coverage["missing_decompiler_functions"][0]["name"], "second")
            self.assertEqual(coverage["missing_decompiler_functions"][0]["reason"], "missing_decompiler_export")

    def test_generate_skeleton_audits_coverage_reference_contract_without_sourcing_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                first\n"
                "                0x00401001                second\n",
                encoding="utf-8",
            )
            candidate_map.write_text(
                "                0x00401000                first\n"
                "                0x00401001                second\n",
                encoding="utf-8",
            )
            block_map = root / "block-map.json"
            reference_contract = root / "reference-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                out=reference_contract,
            )
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva_start": 0x1000,
                                "rva_end": 0x1001,
                                "name": "first",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int first(void) {\n  return 0;\n}",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                coverage_reference_contract=reference_contract,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["reverse_engineering"]["function_source"], "decompiler_export")
            self.assertEqual(result["inputs"]["reference_contract"], None)
            self.assertEqual(result["inputs"]["coverage_reference_contract"]["sha256"], sha256_file(reference_contract))
            self.assertEqual(result["counts"]["functions"], 1)
            self.assertEqual(result["implementation_recovery"]["status"], "incomplete")
            self.assertFalse(result["implementation_recovery"]["source_implements_behavior"])
            self.assertEqual(result["implementation_recovery"]["generated_source_kind"], "decompiler_recovered_partial")
            self.assertIn(
                "incomplete_reference_contract_function_coverage",
                result["implementation_recovery"]["blockers"],
            )
            self.assertEqual(result["completion"]["candidate_status"], "skeleton_only")
            coverage = result["reference_contract_function_coverage"]
            self.assertTrue(coverage["provided"])
            self.assertEqual(coverage["status"], "incomplete")
            self.assertEqual(coverage["counts"]["contract_functions"], 2)
            self.assertEqual(coverage["counts"]["skeleton_functions"], 1)
            self.assertEqual(coverage["counts"]["represented"], 1)
            self.assertEqual(coverage["counts"]["missing"], 1)
            self.assertEqual(coverage["missing_functions"][0]["name"], "second")
            self.assertEqual(
                coverage["representation_counts"],
                {"missing_from_skeleton_function_ranges": 1, "represented_by_skeleton_function": 1},
            )

    def test_decompiled_skeleton_disambiguates_duplicate_decompiler_names_by_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "libjq-1.dll", b"\xc3\xc3")
            decompiler = root / "libjq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva_start": 0x1000,
                                "rva_end": 0x1001,
                                "name": "jv_is_valid",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int jv_is_valid(void) {\n  return 1;\n}",
                                },
                            },
                            {
                                "rva_start": 0x1001,
                                "rva_end": 0x1002,
                                "name": "jv_is_valid",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int jv_is_valid(void) {\n  return 0;\n}",
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq-libjq-1",
                source_language="c",
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["implementation_recovery"]["status"], "complete")
            self.assertTrue(result["implementation_recovery"]["source_implements_behavior"])
            self.assertEqual(result["implementation_recovery"]["duplicate_function_names"], [])
            self.assertEqual(result["implementation_recovery"]["decompiler_name_disambiguation"]["status"], "applied")
            self.assertEqual(result["implementation_recovery"]["decompiler_name_disambiguation"]["count"], 1)
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            self.assertEqual(functions[0]["name"], "jv_is_valid")
            self.assertEqual(functions[1]["name"], "jv_is_valid_at_1001")
            self.assertEqual(functions[1]["aliases"], ["jv_is_valid_at_1001", "jv_is_valid"])
            source = (root / "skeleton" / "src" / "jq-libjq-1_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("int jv_is_valid(void)", source)
            self.assertIn("int jv_is_valid_at_1001(void)", source)

    def test_decompiled_skeleton_prefers_pe_export_alias_for_decompiler_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_export_dll(root / "libjq-1.dll")
            decompiler = root / "libjq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva_start": 0x1000,
                                "rva_end": 0x1001,
                                "name": "_jq_init",
                                "signature": "int _jq_init(void)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int _jq_init(void) {\n  return 1;\n}",
                                },
                            },
                            {
                                "rva_start": 0x1010,
                                "rva_end": 0x1011,
                                "name": "_jv_parse",
                                "signature": "int _jv_parse(void)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int _jv_parse(void) {\n  return 2;\n}",
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq-libjq-1",
                source_language="c",
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["implementation_recovery"]["status"], "complete")
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            self.assertEqual(functions[0]["name"], "jq_init")
            self.assertEqual(functions[0]["aliases"], ["jq_init", "_jq_init"])
            self.assertEqual(functions[0]["pe_export_aliases"], ["jq_init"])
            self.assertEqual(functions[0]["name_disambiguation"]["strategy"], "prefer_pe_export_alias_for_decompiler_rva")
            self.assertEqual(functions[0]["decompiler"]["signature"], "int jq_init(void)")
            self.assertEqual(functions[1]["name"], "jv_parse")
            self.assertEqual(functions[1]["aliases"], ["jv_parse", "_jv_parse"])
            source = (root / "skeleton" / "src" / "jq-libjq-1_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("int jq_init(void)", source)
            self.assertIn("int jv_parse(void)", source)
            self.assertNotIn("int _jq_init(void)", source)
            self.assertNotIn("int _jv_parse(void)", source)

    def test_generate_link_roots_matches_contract_functions_to_object_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3\xc3")
            linker_map = root / "jq.map"
            linker_map.write_text(
                "                0x00401000                __foo\n"
                "                0x00401001                _bar\n",
                encoding="utf-8",
            )
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '00000000 T ___foo' '00000001 T _bar'\n",
                encoding="utf-8",
            )
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                linker_map_original=linker_map,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["counts"]["roots"], 2)
            self.assertEqual(result["counts"]["budgeted_roots"], 2)
            self.assertEqual(result["linker_flags"], ["-Wl,--undefined,___foo", "-Wl,--undefined,_bar"])
            self.assertEqual(result["budgeted_linker_flags"], ["-Wl,--undefined,___foo", "-Wl,--undefined,_bar"])
            self.assertEqual((root / "roots" / "link-root-flags.txt").read_text(encoding="utf-8"), "-Wl,--undefined,___foo\n-Wl,--undefined,_bar\n")
            self.assertEqual((root / "roots" / "budgeted-link-root-flags.txt").read_text(encoding="utf-8"), "-Wl,--undefined,___foo\n-Wl,--undefined,_bar\n")

    def test_generate_link_roots_can_use_stage_a_reference_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3\xc3")
            original_map = root / "original.map"
            candidate_map = root / "candidate.map"
            original_map.write_text(
                "                0x00401000                __foo\n"
                "                0x00401001                _bar\n",
                encoding="utf-8",
            )
            candidate_map.write_text(
                "                0x00401000                __foo\n"
                "                0x00401001                _bar\n",
                encoding="utf-8",
            )
            block_map = root / "block-map.json"
            reference_contract = root / "reference-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                out=reference_contract,
            )
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '00000000 T ___foo' '00000001 T _bar'\n",
                encoding="utf-8",
            )
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                reference_contract=reference_contract,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["function_source"], "stage_a_reference_contract")
            self.assertEqual(result["inputs"]["reference_contract"]["sha256"], sha256_file(reference_contract))
            self.assertEqual(result["linker_flags"], ["-Wl,--undefined,___foo", "-Wl,--undefined,_bar"])

    def test_generate_link_roots_matches_decorated_mingw_runtime_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3\xc3\xc3")
            linker_map = root / "jq.map"
            linker_map.write_text(
                "                0x00401000                __main\n"
                "                0x00401001                __dyn_tls_init@12\n"
                "                0x00401002                __dyn_tls_dtor@12\n",
                encoding="utf-8",
            )
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '00000000 T @___main@8' '00000001 T @___dyn_tls_init_12@16' '00000002 T ____dyn_tls_dtor_12'\n",
                encoding="utf-8",
            )
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                linker_map_original=linker_map,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["counts"]["roots"], 3)
            self.assertEqual(
                result["linker_flags"],
                [
                    "-Wl,--undefined,@___dyn_tls_init_12@16",
                    "-Wl,--undefined,@___main@8",
                    "-Wl,--undefined,____dyn_tls_dtor_12",
                ],
            )

    def test_generate_link_roots_classifies_missing_roots_with_skeleton_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            linker_map = root / "jq.map"
            linker_map.write_text("                0x00401000                wmain\n", encoding="utf-8")
            skeleton_functions = root / "functions.json"
            skeleton_functions.write_text(
                json.dumps(
                    {
                        "format": "stage-b-functions-v1",
                        "target_name": "jq",
                        "functions": [
                            {
                                "name": "_wmain",
                                "rva_start": 0x1000,
                                "rva_end": 0x1001,
                                "decompiler": {"status": "success"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text("#!/bin/sh\n:", encoding="utf-8")
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                linker_map_original=linker_map,
                skeleton_functions=skeleton_functions,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["counts"]["missing"], 1)
            self.assertEqual(result["counts"]["missing_with_skeleton_evidence"], 1)
            self.assertEqual(
                result["counts"]["missing_by_skeleton_representation"],
                {"runtime_entry_replaced_by_generated_bridge": 1},
            )
            missing = result["issues"][0]["details"]["functions"][0]
            self.assertEqual(missing["name"], "wmain")
            self.assertEqual(missing["skeleton"]["name"], "_wmain")
            self.assertEqual(missing["skeleton"]["representation"], "runtime_entry_replaced_by_generated_bridge")

    def test_generate_link_roots_rejects_ambiguous_object_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            linker_map = self._write_map(root / "jq.map", "__foo")
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '00000000 T __foo' '00000001 T ___foo'\n",
                encoding="utf-8",
            )
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                linker_map_original=linker_map,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("ambiguous_object_function_roots", {issue["category"] for issue in result["issues"]})
            self.assertEqual(result["counts"]["roots"], 0)

    def test_generate_link_roots_classifies_import_thunk_contract_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "jq.exe", b"\xff\x25\x40\x20\x40\x00\x00\x00\xc3", "_fileno")
            linker_map = root / "jq.map"
            linker_map.write_text(
                "                0x00401000                fileno\n"
                "                0x00401008                tail\n",
                encoding="utf-8",
            )
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '00000000 T _tail'\n",
                encoding="utf-8",
            )
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                linker_map_original=linker_map,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["counts"]["roots"], 1)
            self.assertEqual(result["counts"]["budgeted_roots"], 1)
            self.assertEqual(result["counts"]["import_thunk_roots"], 1)
            self.assertEqual(result["counts"]["import_thunk_roots_with_linker_flags"], 1)
            self.assertEqual(result["counts"]["missing"], 0)
            self.assertEqual(result["import_thunk_roots"][0]["contract_function"], "fileno")
            self.assertEqual(result["import_thunk_roots"][0]["symbol"], "_fileno")
            self.assertEqual(result["linker_flags"], ["-Wl,--undefined,_tail"])
            self.assertEqual(result["budgeted_linker_flags"], ["-Wl,--undefined,_tail"])
            self.assertEqual(result["import_thunk_linker_flags"], ["-Wl,--undefined,__fileno"])
            self.assertEqual((root / "roots" / "import-thunk-root-flags.txt").read_text(encoding="utf-8"), "-Wl,--undefined,__fileno\n")
            import_thunks = json.loads((root / "roots" / "import-thunk-roots.json").read_text(encoding="utf-8"))
            self.assertEqual(import_thunks["roots"][0]["signature_key"], result["import_thunk_roots"][0]["signature_key"])

    def test_generate_link_roots_uses_crt_atexit_alias_import_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "jq.exe", b"\xff\x25\x40\x20\x40\x00\x00\x00", "atexit")
            linker_map = root / "jq.map"
            linker_map.write_text("                0x00401000                _crt_atexit\n", encoding="utf-8")
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text("#!/bin/sh\ntrue\n", encoding="utf-8")
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                linker_map_original=linker_map,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["counts"]["import_thunk_roots"], 1)
            self.assertEqual(result["import_thunk_roots"][0]["contract_function"], "_crt_atexit")
            self.assertEqual(result["import_thunk_linker_flags"], ["-Wl,--undefined,___crt_atexit"])
            self.assertEqual((root / "roots" / "import-thunk-root-flags.txt").read_text(encoding="utf-8"), "-Wl,--undefined,___crt_atexit\n")

    def test_export_decompiler_runs_ghidra_and_summarizes_completeness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            script_path = root / "tools" / "ghidra"
            script_path.mkdir(parents=True)
            (script_path / "HaloCatalogExport.java").write_text("// test exporter\n", encoding="utf-8")
            calls = []

            class Proc:
                returncode = 0
                stdout = "ghidra stdout\n"
                stderr = "ghidra stderr\n"

            def fake_run(command, **kwargs):
                calls.append((command, kwargs))
                out_json = Path(command[command.index("-postScript") + 2])
                out_json.write_text(
                    json.dumps(
                        {
                            "schema_version": "1",
                            "binary_sha256": sha256_file(original),
                            "program_name": "jq.exe",
                            "functions": [
                                {
                                    "rva": 0x1000,
                                    "rva_end": 0x1001,
                                    "name": "tiny",
                                    "decompiler": {
                                        "status": "success",
                                        "c": "int tiny(void) {\n  return 0;\n}",
                                    },
                                }
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return Proc()

            with patch("haloce_catalog.stage_b.subprocess.run", side_effect=fake_run):
                result = stage_b_export_decompiler(
                    original=original,
                    target_name="jq",
                    out=root / "export",
                    analyze_headless="/ghidra/support/analyzeHeadless",
                    script_path=script_path,
                    project_dir=root / "projects",
                    timeout_seconds=45,
                )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(len(calls), 1)
            command, kwargs = calls[0]
            self.assertEqual(command[0], "/ghidra/support/analyzeHeadless")
            self.assertIn(str(original), command)
            self.assertEqual(command[command.index("-postScript") + 1], "HaloCatalogExport.java")
            self.assertEqual(command[command.index("-postScript") + 3], sha256_file(original))
            self.assertEqual(kwargs["timeout"], 45)
            self.assertEqual(result["decompiler_export"]["completeness"]["status"], "complete")
            self.assertEqual(result["decompiler_export"]["completeness"]["decompiler_code_functions"], 1)
            self.assertEqual(result["decompiler_export"]["completeness"]["blockers"], [])
            self.assertTrue((root / "export" / "stage-b-decompiler-export.json").exists())
            self.assertEqual((root / "export" / "analyzeHeadless.stdout").read_text(encoding="utf-8"), "ghidra stdout\n")
            self.assertEqual((root / "export" / "analyzeHeadless.stderr").read_text(encoding="utf-8"), "ghidra stderr\n")

    def test_export_decompiler_treats_duplicate_names_with_unique_rvas_as_disambiguatable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "libjq-1.dll", b"\xc3\xc3")
            script_path = root / "tools" / "ghidra"
            script_path.mkdir(parents=True)
            (script_path / "HaloCatalogExport.java").write_text("// test exporter\n", encoding="utf-8")

            class Proc:
                returncode = 0
                stdout = "ghidra stdout\n"
                stderr = "ghidra stderr\n"

            def fake_run(command, **kwargs):
                out_json = Path(command[command.index("-postScript") + 2])
                out_json.write_text(
                    json.dumps(
                        {
                            "schema_version": "1",
                            "binary_sha256": sha256_file(original),
                            "program_name": "libjq-1.dll",
                            "functions": [
                                {
                                    "rva": 0x1000,
                                    "rva_end": 0x1001,
                                    "name": "jv_is_valid",
                                    "decompiler": {"status": "success", "c": "int jv_is_valid(void) { return 1; }"},
                                },
                                {
                                    "rva": 0x1001,
                                    "rva_end": 0x1002,
                                    "name": "jv_is_valid",
                                    "decompiler": {"status": "success", "c": "int jv_is_valid(void) { return 0; }"},
                                },
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                return Proc()

            with patch("haloce_catalog.stage_b.subprocess.run", side_effect=fake_run):
                result = stage_b_export_decompiler(
                    original=original,
                    target_name="jq-libjq-1",
                    out=root / "export",
                    analyze_headless="/ghidra/support/analyzeHeadless",
                    script_path=script_path,
                    project_dir=root / "projects",
                )

            completeness = result["decompiler_export"]["completeness"]
            self.assertEqual(completeness["status"], "complete")
            self.assertEqual(completeness["blockers"], [])
            self.assertEqual(completeness["duplicate_function_names"], ["jv_is_valid"])
            self.assertEqual(completeness["ambiguous_duplicate_function_names"], [])
            self.assertEqual(completeness["name_disambiguation"]["status"], "required")

    def test_materialize_upstream_suite_records_source_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "jq-upstream-tests.tar"
            source.write_text("jq upstream suite fixture", encoding="utf-8")
            cases = root / "cases.json"
            cases.write_text(
                json.dumps(
                    {
                        "format": "stage-b-upstream-suite-cases-v1",
                        "cases": [
                            {
                                "id": "version",
                                "args": ["--version"],
                                "stdin": "",
                                "expected_returncode": 0,
                                "expected_stdout": "jq-1.8.1\n",
                                "expected_stderr": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_materialize_upstream_suite(
                target_name="jq",
                suite_source=source,
                source_revision="jq-1.8.1",
                cases=cases,
                out=root / "suite",
            )

            self.assertEqual(result["format"], "stage-b-functional-suite-v1")
            self.assertEqual(result["suite_id"], "jq-upstream-integration-tests")
            self.assertEqual(result["suite_name"], "jq upstream integration tests")
            self.assertTrue(result["upstream_suite"])
            self.assertEqual(result["suite_scope"], "full")
            self.assertEqual(result["materializer"]["name"], STAGE_B_UPSTREAM_SUITE_MATERIALIZER)
            self.assertEqual(result["materializer"]["source_sha256"], sha256_file(source))
            self.assertEqual(result["coverage"]["source_kind"], "upstream_integration_suite")
            self.assertEqual(result["coverage"]["source_sha256"], sha256_file(source))
            self.assertEqual(result["coverage"]["source_revision"], "jq-1.8.1")
            self.assertEqual(result["coverage"]["materialized_by"], STAGE_B_UPSTREAM_SUITE_MATERIALIZER)
            self.assertEqual(result["coverage"]["required_suite_ids"], ["jq-upstream-integration-tests"])
            self.assertEqual(result["cases"][0]["id"], "version")
            self.assertTrue((root / "suite" / "functional-suite.json").exists())

    def test_materialize_upstream_suite_rejects_empty_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "rg-upstream-tests.tar"
            source.write_text("ripgrep upstream suite fixture", encoding="utf-8")
            cases = root / "cases.json"
            cases.write_text(json.dumps({"cases": []}), encoding="utf-8")

            with self.assertRaisesRegex(Exception, "non-empty cases list"):
                stage_b_materialize_upstream_suite(
                    target_name="ripgrep",
                    suite_source=source,
                    source_revision="ripgrep-15.1.0",
                    cases=cases,
                    out=root / "suite",
                )

    def test_materialize_upstream_suite_records_subset_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "jq-upstream-tests-subset.txt"
            source.write_text("jq upstream suite subset fixture", encoding="utf-8")
            cases = root / "cases.json"
            cases.write_text(
                json.dumps(
                    {
                        "cases": [
                            {
                                "id": "version",
                                "args": ["--version"],
                                "stdin": "",
                                "expected_returncode": 0,
                                "expected_stdout": "jq-1.8.1\n",
                                "expected_stderr": "",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_materialize_upstream_suite(
                target_name="jq",
                suite_source=source,
                source_revision="jq-1.8.1-subset",
                cases=cases,
                suite_scope="subset",
                out=root / "suite",
            )

            self.assertEqual(result["suite_id"], "jq-upstream-integration-tests")
            self.assertEqual(result["suite_scope"], "subset")
            self.assertEqual(result["coverage"]["source_kind"], "upstream_integration_suite")
            self.assertEqual(result["coverage"]["source_sha256"], sha256_file(source))
            self.assertEqual(result["coverage"]["source_revision"], "jq-1.8.1-subset")

    def test_generate_candidate_provenance_records_measured_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            linker_map = self._write_map(root / "original.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )

            result = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate=candidate,
                functional_report=functional_report,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                build_output="candidate.exe",
                out=root / "provenance",
            )

            self.assertEqual(result["format"], "stage-b-candidate-provenance-v1")
            self.assertEqual(result["target_name"], "jq")
            self.assertEqual(result["skeleton_manifest_sha256"], sha256_file(skeleton_dir / "manifest.json"))
            self.assertFalse(result["upstream_source_access"])
            self.assertEqual(result["manual_behavioral_fixups"], [])
            self.assertEqual(result["source_roots"], [self._generated_source_root(skeleton_dir)])
            self.assertEqual(result["build"]["output_sha256"], sha256_file(candidate))
            self.assertEqual(result["functional_tests"]["status"], "pass")
            self.assertEqual(result["functional_tests"]["report_sha256"], sha256_file(functional_report))
            functional_payload = json.loads(functional_report.read_text(encoding="utf-8"))
            self.assertEqual(
                result["functional_tests"]["suites"],
                [
                    {
                        "id": "jq-upstream-integration-tests",
                        "name": "jq upstream integration tests",
                        "status": "pass",
                        "suite_sha256": functional_payload["suite_sha256"],
                        "suite_case_manifest_sha256": functional_payload["suite_case_manifest_sha256"],
                        "case_ids_sha256": sha256_bytes(b'["identity"]'),
                        "source_sha256": functional_payload["coverage"]["source_sha256"],
                        "source_revision": "fixture",
                        "materialized_by": STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
                    }
                ],
            )
            self.assertTrue((root / "provenance" / "candidate-provenance.json").exists())

    def test_reference_linked_build_report_blocks_stage_a_with_source_dependency_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            skeleton_manifest = skeleton_dir / "manifest.json"
            skeleton_payload = json.loads(skeleton_manifest.read_text(encoding="utf-8"))
            skeleton_payload["original"]["imports"] = [
                {"dll": "libjq-1.dll", "symbol": "jq_init", "thunk_rva": 0x2000},
                {"dll": "libjq-1.dll", "symbol": "jv_parse", "thunk_rva": 0x2004},
                {"dll": "msvcrt.dll", "symbol": "printf", "thunk_rva": 0x2008},
            ]
            skeleton_manifest.write_text(json.dumps(skeleton_payload), encoding="utf-8")
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            build_report = root / "link-report.json"
            reference_flag = "-L/nix/store/example-stage-a-jq-original/lib"
            build_report.write_text(
                json.dumps(
                    {
                        "format": "stage-b-decompiled-c-link-diagnostic-v1",
                        "status": "pass",
                        "linker_flags": [reference_flag, "-ljq"],
                        "standalone_link_diagnostic": {
                            "status": "incomplete",
                            "returncode": 1,
                            "unresolved_reference_lines": 2,
                            "undefined_reference_samples": [
                                "undefined reference to `_jq_init'",
                                "undefined reference to `_jv_parse'",
                            ],
                            "stderr": str(root / "standalone-link.stderr.txt"),
                        },
                    }
                ),
                encoding="utf-8",
            )
            provenance = root / "provenance" / "candidate-provenance.json"
            generated = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_manifest,
                candidate=candidate,
                functional_report=functional_report,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                build_output="candidate.exe",
                build_report=build_report,
                out=root / "provenance",
            )

            self.assertEqual(generated["build"]["report"]["reference_inputs"], [reference_flag])
            target_closure = generated["build"]["report"]["target_import_closure"]
            self.assertEqual(target_closure["status"], "incomplete")
            self.assertEqual(target_closure["dll_count"], 1)
            self.assertEqual(target_closure["symbol_count"], 2)
            self.assertEqual(target_closure["dlls"][0]["dll"], "libjq-1.dll")
            self.assertEqual(generated["build"]["report"]["source_dependency_policy"]["status"], "violated")
            dependency_kinds = {
                item["kind"]
                for item in generated["build"]["report"]["source_dependency_policy"]["violations"]
            }
            self.assertIn("reference_target_artifact", dependency_kinds)
            self.assertIn("target_library_linkage", dependency_kinds)
            self.assertEqual(generated["build"]["report"]["standalone_link_diagnostic"]["status"], "incomplete")
            self.assertEqual(
                generated["build"]["report"]["standalone_link_diagnostic"]["undefined_symbols"],
                ["jq_init", "jv_parse"],
            )
            self.assertEqual(
                generated["build"]["report"]["standalone_link_diagnostic"]["undefined_symbol_families"],
                [{"family": "jq", "count": 1}, {"family": "jv", "count": 1}],
            )
            self.assertEqual(generated["build"]["report"]["standalone_link_diagnostic"]["target_import_symbol_count"], 2)
            self.assertEqual(
                generated["build"]["report"]["standalone_link_diagnostic"]["repair_plan"]["status"],
                "blocked_on_target_import_closure",
            )
            with _LeanCheckedMock():
                result = stage_b_validate_candidate(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    skeleton_manifest=skeleton_manifest,
                    candidate_provenance=provenance,
                    functional_report=functional_report,
                    target_name="jq",
                    out=root / "report",
                )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["provenance_status"], "incomplete")
            self.assertIn("upstream_source_dependency", categories)
            self.assertIn("reference_build_input_linkage", categories)
            self.assertIn("target_library_linkage", categories)
            self.assertIn("target_import_closure_incomplete", categories)
            self.assertIn("standalone_build_incomplete", categories)
            self.assertEqual(result["stage_a"]["gate"]["status"], "blocked")
            self.assertEqual(result["stage_a"]["gate"]["reason"], "pre_stage_a_requirements_incomplete")
            self.assertFalse(result["stage_a"]["gate"]["eligible"])
            self.assertFalse(result["stage_a"]["gate"]["ran"])
            self.assertFalse((root / "report" / "stage-a").exists())
            closure_issue = [issue for issue in result["issues"] if issue["category"] == "target_import_closure_incomplete"][0]
            self.assertEqual(closure_issue["details"]["symbol_count"], 2)
            standalone_issue = [issue for issue in result["issues"] if issue["category"] == "standalone_build_incomplete"][0]
            self.assertEqual(standalone_issue["details"]["undefined_symbols"], ["jq_init", "jv_parse"])
            self.assertEqual(standalone_issue["details"]["target_import_symbol_count"], 2)

    def test_generated_target_closure_manifest_satisfies_target_import_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            skeleton_manifest = skeleton_dir / "manifest.json"
            skeleton_payload = json.loads(skeleton_manifest.read_text(encoding="utf-8"))
            skeleton_payload["original"]["imports"] = [
                {"dll": "libjq-1.dll", "symbol": "jq_init", "thunk_rva": 0x2000},
                {"dll": "libjq-1.dll", "symbol": "jv_parse", "thunk_rva": 0x2004},
            ]
            skeleton_manifest.write_text(json.dumps(skeleton_payload), encoding="utf-8")
            closure_dir = root / "target-closure" / "jq-libjq-1"
            closure_dir.mkdir(parents=True)
            (closure_dir / "functions.json").write_text(
                json.dumps(
                    {
                        "format": "stage-b-functions-v1",
                        "target_name": "jq-libjq-1",
                        "functions": [
                            {"name": "jq_init", "aliases": ["jq_init"]},
                            {"name": "jv_parse", "aliases": ["jv_parse"]},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (closure_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "format": "stage-b-skeleton-v1",
                        "status": "generated",
                        "target_name": "jq-libjq-1",
                        "source_policy": {"upstream_source_read": False},
                        "outputs": {"functions": {"path": "functions.json"}},
                        "implementation_recovery": {
                            "status": "incomplete",
                            "source_implements_behavior": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            target_closure_manifest = root / "target-closure" / "target-closure-skeletons.json"
            target_closure_manifest.write_text(
                json.dumps(
                    {
                        "format": "stage-b-target-closure-skeletons-v1",
                        "target_name": "jq",
                        "status": "generated",
                        "target_dlls": ["libjq-1.dll"],
                        "skeleton_manifests": [str(closure_dir / "manifest.json")],
                    }
                ),
                encoding="utf-8",
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            build_report = root / "link-report.json"
            build_report.write_text(
                json.dumps(
                    {
                        "format": "stage-b-decompiled-c-link-diagnostic-v1",
                        "status": "incomplete",
                        "linker_flags": ["-L/generated/stage-b-target-closure", "-l:libstage_b_jq_libjq_1.a"],
                        "standalone_link_diagnostic": {
                            "status": "incomplete",
                            "returncode": 1,
                            "unresolved_reference_lines": 2,
                            "undefined_reference_samples": [
                                "undefined reference to `_jq_init'",
                                "undefined reference to `_jv_parse'",
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            generated = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_manifest,
                candidate=candidate,
                functional_report=functional_report,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                build_output="candidate.exe",
                build_report=build_report,
                target_closure_manifest=target_closure_manifest,
                out=root / "provenance",
            )

            target_closure = generated["build"]["report"]["target_import_closure"]
            self.assertEqual(target_closure["status"], "satisfied")
            self.assertEqual(target_closure["generated_closure"]["status"], "satisfied")
            self.assertEqual(target_closure["generated_closure"]["counts"]["represented_symbols"], 2)
            self.assertEqual(target_closure["generated_closure"]["counts"]["missing_symbols"], 0)
            self.assertEqual(
                generated["build"]["report"]["standalone_link_diagnostic"]["repair_plan"]["status"],
                "target_import_closure_not_linked",
            )
            self.assertEqual(generated["build"]["report"]["source_dependency_policy"]["status"], "satisfied")

            with _LeanCheckedMock():
                result = stage_b_validate_candidate(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    skeleton_manifest=skeleton_manifest,
                    candidate_provenance=root / "provenance" / "candidate-provenance.json",
                    functional_report=functional_report,
                    target_name="jq",
                    out=root / "report",
                )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("standalone_build_incomplete", categories)
            self.assertNotIn("target_import_closure_incomplete", categories)
            self.assertNotIn("upstream_source_dependency", categories)
            standalone_issue = [issue for issue in result["issues"] if issue["category"] == "standalone_build_incomplete"][0]
            self.assertEqual(standalone_issue["details"]["repair_plan"]["status"], "target_import_closure_not_linked")

    def test_generated_target_closure_link_artifacts_clear_standalone_import_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            linker_map = self._write_map(root / "original.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            skeleton_manifest = skeleton_dir / "manifest.json"
            skeleton_payload = json.loads(skeleton_manifest.read_text(encoding="utf-8"))
            skeleton_payload["original"]["imports"] = [
                {"dll": "libjq-1.dll", "symbol": "jq_init", "thunk_rva": 0x2000},
                {"dll": "libjq-1.dll", "symbol": "jv_parse", "thunk_rva": 0x2004},
            ]
            skeleton_manifest.write_text(json.dumps(skeleton_payload), encoding="utf-8")
            closure_dir = root / "target-closure" / "jq-libjq-1"
            closure_dir.mkdir(parents=True)
            (closure_dir / "functions.json").write_text(
                json.dumps(
                    {
                        "format": "stage-b-functions-v1",
                        "target_name": "jq-libjq-1",
                        "functions": [
                            {"name": "jq_init", "aliases": ["jq_init"]},
                            {"name": "jv_parse", "aliases": ["jv_parse"]},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (closure_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "format": "stage-b-skeleton-v1",
                        "status": "generated",
                        "target_name": "jq-libjq-1",
                        "source_policy": {"upstream_source_read": False},
                        "outputs": {"functions": {"path": "functions.json"}},
                        "implementation_recovery": {
                            "status": "incomplete",
                            "source_implements_behavior": False,
                        },
                    }
                ),
                encoding="utf-8",
            )
            target_closure_manifest = root / "target-closure" / "target-closure-skeletons.json"
            target_closure_manifest.write_text(
                json.dumps(
                    {
                        "format": "stage-b-target-closure-skeletons-v1",
                        "target_name": "jq",
                        "status": "generated",
                        "target_dlls": ["libjq-1.dll"],
                        "skeleton_manifests": [str(closure_dir / "manifest.json")],
                    }
                ),
                encoding="utf-8",
            )
            build_report = root / "link-report.json"
            build_report.write_text(
                json.dumps(
                    {
                        "format": "stage-b-decompiled-c-link-diagnostic-v1",
                        "status": "pass",
                        "linker_flags": [
                            "-nostartfiles",
                            "generated-target-closure/libstage_b_target_closure_libjq_1.dll.a",
                        ],
                        "standalone_link_diagnostic": {
                            "status": "pass",
                            "returncode": 0,
                            "unresolved_reference_lines": 0,
                            "undefined_reference_samples": [],
                        },
                        "generated_target_closure": {
                            "format": "stage-b-generated-target-closure-link-artifacts-v1",
                            "target_closure_manifest": str(target_closure_manifest),
                            "skeleton_manifest": str(closure_dir / "manifest.json"),
                            "dll": "libjq-1.dll",
                            "import_library": "libstage_b_target_closure_libjq_1.dll.a",
                            "source_policy": {
                                "upstream_source_read": False,
                                "manual_behavioral_fixups": False,
                                "behavior_implemented": False,
                            },
                        },
                        "generated_import_libraries": ["libstage_b_target_closure_libjq_1.dll.a"],
                        "generated_target_dlls": ["libjq-1.dll"],
                    }
                ),
                encoding="utf-8",
            )

            generated = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_manifest,
                candidate=candidate,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                build_output="candidate.exe",
                build_report=build_report,
                target_closure_manifest=target_closure_manifest,
                out=root / "provenance",
            )

            report = generated["build"]["report"]
            self.assertEqual(report["source_dependency_policy"]["status"], "satisfied")
            self.assertEqual(report["target_import_closure"]["status"], "satisfied")
            self.assertEqual(report["standalone_link_diagnostic"]["status"], "pass")
            self.assertEqual(report["standalone_link_diagnostic"]["undefined_symbol_count"], 0)
            self.assertEqual(report["standalone_link_diagnostic"]["repair_plan"]["status"], "not_applicable")
            self.assertFalse(report["generated_target_closure"]["source_policy"]["behavior_implemented"])
            self.assertEqual(report["generated_import_libraries"], ["libstage_b_target_closure_libjq_1.dll.a"])
            self.assertEqual(report["generated_target_dlls"], ["libjq-1.dll"])

    def test_generate_candidate_provenance_records_fixed_up_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            linker_map = self._write_map(root / "original.map", "tiny")
            fixed_up_source = root / "fixed-up-jq.c"
            fixed_up_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )

            result = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate=candidate,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                fixed_up_sources=[fixed_up_source],
                out=root / "provenance",
            )

            self.assertEqual(result["manual_behavioral_fixups"], [])
            self.assertEqual(result["source_roots"][0], self._generated_source_root(skeleton_dir))
            self.assertEqual(result["source_roots"][1], self._fixed_up_source_root(skeleton_dir, fixed_up_source))

    def test_generate_candidate_provenance_failed_report_does_not_claim_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                status="fail",
                original_binary=original,
                candidate_binary=candidate,
            )
            result = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate=candidate,
                functional_report=functional_report,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                out=root / "provenance",
            )

            self.assertEqual(result["functional_tests"]["status"], "fail")
            self.assertEqual(result["functional_tests"]["suites"][0]["status"], "fail")

            validation = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=root / "provenance" / "candidate-provenance.json",
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in validation["issues"]}
            self.assertEqual(validation["status"], "incomplete")
            self.assertIn("functional_tests_not_passing", categories)
            self.assertIn("functional_test_report_failed", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_generate_skeleton_from_pe32plus_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe32plus(root / "rg.exe", b"\xc3")
            out = root / "skeleton"

            result = stage_b_generate_skeleton(
                original=original,
                target_name="ripgrep",
                source_language="rust",
                out_dir=out,
            )

            self.assertEqual(result["status"], "generated")
            self.assertEqual(result["original"]["machine"], "x86_64")
            self.assertEqual(result["original"]["bitness"], 64)
            self.assertIn("pe32plus-original", result["source_policy"]["allowed_inputs"])
            functions = json.loads((out / "functions.json").read_text(encoding="utf-8"))
            self.assertEqual(functions["functions"][0]["instruction_preview"][0]["mnemonic"], "ret")

    def test_generate_rust_skeleton_recovers_ripgrep_version_smoke_from_binary_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            version_strings = (
                b"\x90\xc3"
                b"PCRE2 is not available in this build of ripgrep.\n"
                b"ripgrep \n15.1.0+\nSSE2\nSSSE3\nAVX2\npcre2\n"
            )
            original = self._write_pe32plus(root / "rg.exe", version_strings)

            result = stage_b_generate_skeleton(
                original=original,
                target_name="ripgrep",
                source_language="rust",
                out_dir=root / "skeleton",
            )

            behavior = result["behavior_recovery"]
            self.assertEqual(behavior["status"], "partial")
            self.assertEqual(behavior["source"], "pe_ascii_strings")
            self.assertEqual(behavior["recovered"][0]["id"], "ripgrep-version")
            self.assertEqual(behavior["recovered"][0]["returncode"], 0)
            self.assertIn("ripgrep 15.1.0\n\nfeatures:-pcre2", behavior["recovered"][0]["stdout"])
            self.assertEqual(result["implementation_recovery"]["status"], "incomplete")
            self.assertFalse(result["implementation_recovery"]["source_implements_behavior"])
            source = (root / "skeleton" / "src" / "ripgrep_stage_b_skeleton.rs").read_text(encoding="utf-8")
            self.assertIn("STAGE_B_RECOVERED_VERSION_STDOUT", source)
            self.assertIn("stage_b_matches_arg(&args, \"-V\", \"--version\")", source)
            self.assertIn("ripgrep 15.1.0\\n\\nfeatures:-pcre2", source)

    def test_generate_skeleton_uses_decompiler_export_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva": 0x1000,
                                "rva_end": 0x1001,
                                "name": "tiny_from_decompiler",
                                "signature": "int tiny_from_decompiler(void)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int tiny_from_decompiler(void) {\n  return 1;\n}",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "skeleton"

            result = stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                out_dir=out,
            )

            self.assertEqual(result["reverse_engineering"]["function_source"], "decompiler_export")
            functions = json.loads((out / "functions.json").read_text(encoding="utf-8"))
            function = functions["functions"][0]
            self.assertEqual(function["name"], "tiny_from_decompiler")
            self.assertEqual(function["decompiler"]["status"], "success")
            self.assertEqual(result["implementation_recovery"]["status"], "incomplete")
            self.assertEqual(result["implementation_recovery"]["decompiler_functions"], 1)
            self.assertEqual(result["implementation_recovery"]["decompiler_successes"], 1)
            self.assertFalse(result["implementation_recovery"]["source_implements_behavior"])
            self.assertEqual(result["implementation_recovery"]["blockers"], ["generated_source_is_scaffold"])
            source = (out / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("decompiler status: success", source)
            self.assertIn("return 1", source)

    def test_generate_skeleton_emits_decompiled_c_behavior_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva": 0x1000,
                                "rva_end": 0x1001,
                                "name": "tiny.from-decompiler",
                                "signature": "int tiny_from_decompiler(void)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int tiny_from_decompiler(void) {\n  return 1;\n}",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            recovery = result["implementation_recovery"]
            self.assertEqual(recovery["status"], "complete")
            self.assertEqual(recovery["implementation_mode"], "decompiled-c")
            self.assertEqual(recovery["generated_source_kind"], "decompiler_recovered_behavior")
            self.assertTrue(recovery["source_implements_behavior"])
            self.assertEqual(recovery["decompiler_code_functions"], 1)
            self.assertEqual(recovery["blockers"], [])
            self.assertEqual(result["completion"]["candidate_status"], "generated_behavior_source")
            self.assertEqual(result["inputs"]["decompiler_export"]["completeness"]["status"], "complete")
            self.assertEqual(result["inputs"]["decompiler_export"]["completeness"]["decompiler_code_functions"], 1)
            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Implementation mode: decompiled-c", source)
            self.assertIn("#include <stdbool.h>", source)
            self.assertIn("typedef struct _stage_b_image_dos_header", source)
            self.assertIn("typedef struct _stage_b_image_nt_headers32", source)
            self.assertIn("typedef struct _stage_b_FILE", source)
            self.assertIn("typedef uint8_t undefined1;", source)
            self.assertIn("typedef uintptr_t code();", source)
            self.assertIn("typedef MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION;", source)
            self.assertIn("typedef uint64_t unkuint10;", source)
            self.assertIn("#define NAN(value) __builtin_isnan((double)(value))", source)
            self.assertIn("&__p___winitenv", source)
            self.assertIn("&__p__commode", source)
            self.assertIn("&__p__fmode", source)
            self.assertIn("&__set_app_type", source)
            self.assertIn("&_amsg_exit", source)
            self.assertIn("&_cexit", source)
            self.assertIn("int tiny_from_decompiler(void)", source)
            self.assertNotIn("stage_b_unimplemented", source)
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))
            self.assertEqual(functions["functions"][0]["decompiler"]["code"], "int tiny_from_decompiler(void) {\n  return 1;\n}")
            source_map_entry = result["source_map"]["functions"][0]
            anchor = source.splitlines()[source_map_entry["line_start"] - 1].strip()
            self.assertEqual(anchor, "int tiny_from_decompiler(void) {")

    def test_decompiled_c_skeleton_omits_aliased_direct_import_thunk_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "jq.exe", b"\xff\x25\x40\x20\x40\x00\x00\x00", "_fileno")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva": 0x1000,
                                "rva_end": 0x1008,
                                "name": "fileno",
                                "signature": "uintptr_t fileno(void)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "uintptr_t fileno(void) {\n  _fileno();\n  return 0;\n}",
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["implementation_recovery"]["status"], "complete")
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            self.assertEqual(functions[0]["linkage"]["kind"], "import_thunk")
            self.assertEqual(functions[0]["linkage"]["original_symbol"], "fileno")
            self.assertEqual(functions[0]["linkage"]["symbol"], "_fileno")
            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("extern uintptr_t _fileno();", source)
            self.assertIn("#define fileno _fileno", source)
            self.assertIn("import thunk for _fileno; body omitted", source)
            self.assertNotIn("__attribute__((weak)) uintptr_t fileno()", source)
            self.assertNotIn("uintptr_t fileno(void)", source)
            self.assertNotIn("  _fileno();\n  return 0;", source)

    def test_decompiled_c_renderer_normalizes_ghidra_syntax_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva": 0x1000,
                                "rva_end": 0x1001,
                                "name": "tiny_from_decompiler",
                                "signature": "int tiny_from_decompiler(void)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "\n".join(
                                        [
                                            "int tiny_from_decompiler(void)",
                                            "{",
                                            "  double local_84;",
                                            "  _MEMORY_BASIC_INFORMATION local_28;",
                                            "  tm local_tm;",
                                            "  LONG local_long;",
                                            "  __time32_t local_time;",
                                            "  undefined1 auVar1 [10];",
                                            "  undefined8 local_104;",
                                            "  wchar_t awStack_7c [2];",
                                            "  local_84._4_4_ = (uint)((unkuint10)local_84 >> 0x20);",
                                            "  auVar1 = (undefined1  [10])fscale((float10)local_84,(float10)1);",
                                            "  local_long = (LONG)local_time;",
                                            "  local_tm.tm_year = (int)pcRam0000011d + (int)uRam000000ce;",
                                            "  while ((local_104._4_4_ = (wchar_t *)1, local_104 != 0)) { break; }",
                                            "  awStack_7c = (wchar_t  [2])local_84;",
                                            "  qsort(&local_84,1,4,(_PtFuncCompare *)0x401000);",
                                            "  switch((&PTR_DAT_6e3eab84)[0]) {",
                                            "  case (undefined *)0x6e39bf0d:",
                                            "    local_28.BaseAddress = &UNK_6e39bf15;",
                                            "    break;",
                                            "  }",
                                            "  jq_report_error(u_line_<_l_>STAGE_B_PART(nlines_6e3eee74, 8, 4));",
                                            "  jq_report_error(u_column_<_c_>nlines_6e3eee74._8_4_);",
                                            "  local_long = DAT_6e3ef6ec >> 1;",
                                            "  local_long += IMAGE_DOS_HEADER_6e380000.e_magic[0];",
                                            "  stack0x00000004 = 1;",
                                            "  _assign();",
                                            "  Sleep(0);",
                                            "  WriteConsoleW(0,0,0,0,0);",
                                            "  PathIsRelativeA(\"x\");",
                                            "  GetTimeZoneInformation(0);",
                                            "  atexit((void *)0);",
                                            "  local_28.BaseAddress = __imp____acrt_iob_func;",
                                            "  (*(code *)__imp____acrt_iob_func)(2);",
                                            "  initterm();",
                                            "  return (int)(NAN(local_84) + local_84._4_4_);",
                                            "}",
                                        ]
                                    ),
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("typedef int32_t LONG;", source)
            self.assertIn("typedef int _PtFuncCompare(const void *, const void *);", source)
            self.assertIn("typedef struct _stage_b_tm", source)
            self.assertIn("#define STAGE_B_PART_LVALUE(value, offset, type)", source)
            self.assertIn("extern void __attribute__((stdcall, dllimport)) Sleep(DWORD);", source)
            self.assertIn("extern BOOL __attribute__((stdcall, dllimport)) WriteConsoleW(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);", source)
            self.assertIn("extern BOOL __attribute__((stdcall, dllimport)) PathIsRelativeA(LPCSTR);", source)
            self.assertIn("extern DWORD __attribute__((stdcall, dllimport)) GetTimeZoneInformation(_TIME_ZONE_INFORMATION *);", source)
            self.assertNotIn("extern uintptr_t Sleep();", source)
            self.assertNotIn("extern uintptr_t WriteConsoleW();", source)
            self.assertNotIn("extern uintptr_t PathIsRelativeA();", source)
            self.assertNotIn("extern uintptr_t GetTimeZoneInformation();", source)
            self.assertNotIn("__attribute__((weak)) uintptr_t Sleep()", source)
            self.assertIn('extern void *stage_b_jq_imp_SetUnhandledExceptionFilter __asm__("__imp__SetUnhandledExceptionFilter@4");', source)
            self.assertIn("(void *)&stage_b_jq_imp_SetUnhandledExceptionFilter,", source)
            self.assertNotIn("(void *)(uintptr_t)&SetUnhandledExceptionFilter,", source)
            self.assertIn("extern uintptr_t initterm();", source)
            self.assertIn("__attribute__((weak)) uintptr_t initterm() { return 0; }", source)
            self.assertIn("__crt_atexit((void *)0);", source)
            self.assertNotIn("  atexit((void *)0);", source)
            self.assertIn("local_28.BaseAddress = ___acrt_iob_func;", source)
            self.assertIn("(*(code *)___acrt_iob_func)(2);", source)
            self.assertNotIn("__imp____acrt_iob_func", source)
            self.assertIn("extern byte stack0x00000004;", source)
            self.assertIn("__attribute__((weak)) byte stack0x00000004;", source)
            self.assertIn("extern uintptr_t pcRam0000011d;", source)
            self.assertIn("__attribute__((weak)) uintptr_t pcRam0000011d;", source)
            self.assertIn("extern uintptr_t uRam000000ce;", source)
            self.assertIn("extern uintptr_t * PTR_DAT_6e3eab84;", source)
            self.assertIn("extern uintptr_t * UNK_6e39bf15;", source)
            self.assertIn("extern uintptr_t * DAT_6e3ef6ec;", source)
            self.assertIn("extern IMAGE_DOS_HEADER IMAGE_DOS_HEADER_6e380000;", source)
            self.assertNotIn("extern byte _assign;", source)
            self.assertNotIn("__attribute__((weak)) byte _assign;", source)
            self.assertNotIn("extern byte _PtFuncCompare;", source)
            self.assertNotIn("__attribute__((weak)) byte _PtFuncCompare;", source)
            self.assertNotIn("extern byte __time32_t;", source)
            self.assertNotIn("__attribute__((weak)) byte __time32_t;", source)
            self.assertIn("extern uintptr_t _assign();", source)
            self.assertIn("__attribute__((weak)) uintptr_t _assign() { return 0; }", source)
            self.assertNotIn("extern uintptr_t tiny_from_decompiler();", source)
            self.assertNotIn("extern byte _MEMORY_BASIC_INFORMATION;", source)
            self.assertIn("_MEMORY_BASIC_INFORMATION local_28;", source)
            self.assertIn("float10 auVar1;", source)
            self.assertIn("auVar1 = (float10)fscale((float10)local_84,(float10)1);", source)
            self.assertIn("while ((STAGE_B_PART_LVALUE(local_104, 4, undefined4) = (wchar_t *)1, local_104 != 0))", source)
            self.assertIn("(void)(awStack_7c);", source)
            self.assertIn("(void)(local_84);", source)
            self.assertIn("switch((uintptr_t)((&PTR_DAT_6e3eab84)[0]))", source)
            self.assertIn("case 0x6e39bf0d:", source)
            self.assertIn("local_28.BaseAddress = &UNK_6e39bf15;", source)
            self.assertIn("qsort(&local_84,1,4,(_PtFuncCompare *)0x401000);", source)
            self.assertIn("jq_report_error(0);", source)
            self.assertNotIn("u_line_", source)
            self.assertNotIn("u_column_", source)
            self.assertIn("local_long = ((uintptr_t)DAT_6e3ef6ec) >> 1;", source)
            self.assertIn("local_long += ((char *)&IMAGE_DOS_HEADER_6e380000.e_magic)[0];", source)
            self.assertIn("STAGE_B_SET_PART(local_84, 4, 4, (uint)((unkuint10)local_84 >> 0x20));", source)
            self.assertIn("return (int)(NAN(local_84) + STAGE_B_PART(local_84, 4, 4));", source)

    def test_decompiled_c_renderer_preserves_atexit_forwarder_shape(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "atexit",
                    "rva_start": 0x1430,
                    "rva_end": 0x1435,
                    "size": 5,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "void __cdecl atexit(_func_4879 *param_1)",
                                "{",
                                "  atexit(param_1);",
                                "  return;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "__crt_atexit",
                    "rva_start": 0xC3F0,
                    "rva_end": 0xC3F6,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "atexit", "original_symbol": "__crt_atexit"},
                    "decompiler": {"status": "success", "code": "int __cdecl __crt_atexit(_func_4879 *param_1) { return atexit(param_1); }"},
                },
            ],
        )

        self.assertIn("extern uintptr_t __crt_atexit();", source)
        self.assertNotIn("#define __crt_atexit atexit", source)
        self.assertIn("uintptr_t __cdecl atexit(_func_4879 *param_1)", source)
        self.assertIn("return __crt_atexit(param_1);", source)
        self.assertNotIn("return atexit(param_1);", source)
        self.assertNotIn("___crt_atexit", source)

    def test_decompiled_c_renderer_omits_import_thunk_bodies(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            external_function_names=["jq_get_exit_code"],
            functions=[
                {
                    "name": "main_like",
                    "rva_start": 0x1000,
                    "rva_end": 0x1008,
                    "size": 8,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "int main_like(void)",
                                "{",
                                "  return (int)jq_get_exit_code();",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "jq_get_exit_code",
                    "rva_start": 0x2000,
                    "rva_end": 0x2006,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jq_get_exit_code"},
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "void jq_get_exit_code(void)",
                                "{",
                                "  jq_get_exit_code();",
                                "  return;",
                                "}",
                            ]
                        ),
                    },
                },
            ],
        )

        self.assertIn("extern uintptr_t jq_get_exit_code();", source)
        self.assertIn("int main_like(void)", source)
        self.assertIn("return (int)jq_get_exit_code();", source)
        self.assertIn("import thunk for jq_get_exit_code; body omitted", source)
        self.assertNotIn("void jq_get_exit_code(void)", source)
        self.assertNotIn("  jq_get_exit_code();\n  return;", source)

    def test_decompiled_c_renderer_replaces_mingw_crt_entry_with_bridge(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___tmainCRTStartup",
                    "rva_start": 0x1010,
                    "rva_end": 0x1100,
                    "size": 0xF0,
                    "decompiler": {
                        "status": "success",
                        "code": "int ___tmainCRTStartup(void) {\n  return *(int *)0x18;\n}",
                    },
                },
                {
                    "name": "mainCRTStartup",
                    "rva_start": 0x1420,
                    "rva_end": 0x142F,
                    "size": 0xF,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t mainCRTStartup(void) {\n  return ___tmainCRTStartup();\n}",
                    },
                },
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x490C,
                    "size": 0x24AE,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t umain(int argc,undefined4 *argv) {\n  return (uintptr_t)argc;\n}",
                    },
                },
                {
                    "name": "_wmain",
                    "rva_start": 0x490C,
                    "rva_end": 0x4A07,
                    "size": 0xFB,
                    "decompiler": {
                        "status": "success",
                        "code": "int _wmain(int argc,wchar_t **argv,wchar_t **envp) {\n  return argc;\n}",
                    },
                },
            ],
        )

        self.assertIn("MinGW CRT entry body replaced by a generated runtime bridge", source)
        self.assertNotIn("return *(int *)0x18;", source)
        self.assertNotIn("return ___tmainCRTStartup();", source)
        self.assertNotIn("int _wmain(int argc,wchar_t **argv,wchar_t **envp)", source)
        self.assertIn("void __cdecl mainCRTStartup(void)", source)
        self.assertIn("__wgetmainargs(&argc,(int *)&wargv,(int *)&wenv,0,&startup_info)", source)
        self.assertIn("argv = (char **)malloc((argc + 1) * sizeof(char *));", source)
        self.assertIn("argv[i][j] = (char)((ch < 0x80) ? ch : '?');", source)
        self.assertIn("rc = (int)umain(argc,(undefined4 *)argv);", source)
        self.assertIn("exit(rc);", source)

    def test_decompiled_c_renderer_returns_import_tail_call_result(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___iob_func",
                    "rva_start": 0xC380,
                    "rva_end": 0xC386,
                    "size": 6,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t ___iob_func(void)",
                                "{",
                                "  /* WARNING: Could not recover jumptable at 0x0040c380. Too many branches */",
                                "  /* WARNING: Treating indirect jump as call */",
                                "  __p__iob();",
                                "  return;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("extern uintptr_t __p__iob();", source)
        self.assertIn("return __p__iob();", source)
        self.assertNotIn("__p__iob();\n  return;", source)

    def test_decompiled_c_renderer_recovers_allocator_success_return_values(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "jv_mem_alloc",
                    "rva_start": 0x2D680,
                    "rva_end": 0x2D69C,
                    "size": 0x1C,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "void __cdecl jv_mem_alloc(size_t param_1)",
                                "{",
                                "  int iVar1;",
                                "  iVar1 = malloc(param_1);",
                                "  if (iVar1 != 0) {",
                                "    return;",
                                "  }",
                                "  memory_exhausted();",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "jv_mem_calloc_unguarded",
                    "rva_start": 0x2D6EC,
                    "rva_end": 0x2D724,
                    "size": 0x38,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "void __cdecl jv_mem_calloc_unguarded(size_t param_1,size_t param_2)",
                                "{",
                                "  int iVar1;",
                                "  if ((param_1 != 0) && (param_2 != 0)) {",
                                "    calloc(param_1,param_2);",
                                "    return 0;",
                                "  }",
                                "  iVar1 = strdup(\"src/jv_alloc.c\");",
                                "  if (iVar1 != 0) {",
                                "    return 0;",
                                "  }",
                                "  memory_exhausted();",
                                "}",
                            ]
                        ),
                    },
                },
            ],
        )

        self.assertIn("uintptr_t __cdecl jv_mem_alloc(size_t param_1)", source)
        self.assertIn("if (iVar1 != 0) {\n    return iVar1;\n  }", source)
        self.assertIn("return calloc(param_1,param_2);", source)
        self.assertIn("if (iVar1 != 0) {\n    return iVar1;\n  }", source)
        self.assertNotIn("if (iVar1 != 0) {\n    return 0;\n  }", source)
        self.assertNotIn("calloc(param_1,param_2);\n    return 0;", source)

    def test_decompiled_c_renderer_replaces_jq_value_abi_helpers(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "jvp_array_alloc",
                    "rva_start": 0x25EB5,
                    "rva_end": 0x25EDE,
                    "size": 0x29,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t __cdecl jvp_array_alloc()",
                                "{",
                                "  int in_EAX;",
                                "  undefined4 *puVar1;",
                                "  puVar1 = (undefined4 *)jv_mem_alloc((in_EAX + 1) * 0x10);",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "jv_array",
                    "rva_start": 0x27822,
                    "rva_end": 0x27841,
                    "size": 0x1F,
                    "decompiler": {
                        "status": "success",
                        "code": "undefined4 __cdecl jv_array(undefined4 param_1)\n{\n  jv_array_sized(param_1);\n  return param_1;\n}",
                    },
                },
                {
                    "name": "jv_string",
                    "rva_start": 0x2785B,
                    "rva_end": 0x2788A,
                    "size": 0x2F,
                    "decompiler": {
                        "status": "success",
                        "code": "undefined4 __cdecl jv_string(undefined4 param_1,char *param_2)\n{\n  jv_string_sized(param_1,(byte *)param_2,strlen(param_2));\n  return param_1;\n}",
                    },
                },
                {
                    "name": "jv_object",
                    "rva_start": 0x27B19,
                    "rva_end": 0x27B34,
                    "size": 0x1B,
                    "decompiler": {
                        "status": "success",
                        "code": "undefined4 __cdecl jv_object(undefined4 param_1)\n{\n  jvp_object_new();\n  return param_1;\n}",
                    },
                },
            ],
        )

        self.assertIn("static uintptr_t stage_b_jq_jvp_array_alloc(uint32_t capacity)", source)
        self.assertIn("static undefined4 stage_b_jq_jv_string_sized", source)
        self.assertIn("uintptr_t __cdecl jvp_array_alloc()\n{\n  return stage_b_jq_jvp_array_alloc(0);\n}", source)
        self.assertIn("undefined4 __cdecl jv_array(undefined4 param_1)\n{\n  return stage_b_jq_jv_array_sized(param_1,0);\n}", source)
        self.assertIn("return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)param_2,(int)length);", source)
        self.assertIn("undefined4 __cdecl jv_object(undefined4 param_1)\n{\n  return stage_b_jq_jv_object(param_1);\n}", source)
        self.assertNotIn("int in_EAX;", source)
        self.assertNotIn("jv_mem_alloc((in_EAX + 1) * 0x10)", source)
        self.assertNotIn("jvp_object_new();\n  return param_1;", source)

    def test_decompiled_c_renderer_recovers_jq_init_stack_hidden_pointer(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "stack_init",
                    "rva_start": 0x1A567,
                    "rva_end": 0x1A57E,
                    "size": 0x17,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "undefined4 __cdecl stack_init()",
                                "{",
                                "  undefined4 *in_EAX;",
                                "  *in_EAX = 0;",
                                "  in_EAX[1] = 8;",
                                "  in_EAX[2] = 0;",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "jq_init",
                    "rva_start": 0x1FA65,
                    "rva_end": 0x1FC14,
                    "size": 0x1AF,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "undefined4 * __cdecl jq_init(void)",
                                "{",
                                "  undefined4 *puVar1;",
                                "  puVar1 = (undefined4 *)jv_mem_alloc_unguarded(0xc0);",
                                "  if (puVar1 != (undefined4 *)0x0) {",
                                "    puVar1[2] = 0;",
                                "    puVar1[0x1b] = 0;",
                                "    stack_init();",
                                "    puVar1[0xe] = 0;",
                                "  }",
                                "  return puVar1;",
                                "}",
                            ]
                        ),
                    },
                },
            ],
        )

        self.assertIn("undefined4 __cdecl stack_init()\n{\n  return 0;\n}", source)
        self.assertIn("puVar1[0x1b] = 0;\n    puVar1[10] = 0;\n    puVar1[11] = 8;\n    puVar1[12] = 0;", source)
        self.assertNotIn("undefined4 *in_EAX;", source)
        self.assertNotIn("*in_EAX = 0;", source)
        self.assertNotIn("    stack_init();", source)

    def test_decompiled_c_renderer_recovers_umain_iob_stream_indices(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x2480,
                    "size": 0x22,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t umain(int argc,undefined4 *argv)",
                                "{",
                                "  code *puVar1;",
                                "  puVar1 = ___acrt_iob_func;",
                                "  (*(code *)___acrt_iob_func)();",
                                "  (*(code *)puVar1)();",
                                "  (*(code *)puVar1)();",
                                "  (*(code *)puVar1)();",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("(*(code *)___acrt_iob_func)(1);", source)
        self.assertIn("(*(code *)puVar1)(2);", source)
        self.assertIn("(*(code *)puVar1)(1);", source)
        self.assertIn("(*(code *)puVar1)(2);", source)
        self.assertNotIn("___acrt_iob_func)();", source)
        self.assertNotIn("puVar1)();", source)

    def test_decompiled_c_renderer_recovers_jq_jv_constructor_return_buffers(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x2490,
                    "size": 0x32,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t umain(int argc,undefined4 *argv)",
                                "{",
                                "  uint auStack_3fc [4];",
                                "  uint auStack_3ec [4];",
                                "  uint auStack_3dc [4];",
                                "  uint *puStack_444;",
                                "  uint *puStack_44c;",
                                "  uint *puStack_43c;",
                                "  puStack_444 = auStack_3fc;",
                                "  jv_array();",
                                "  puStack_44c = auStack_3ec;",
                                "  jv_object();",
                                "  puStack_43c = (uint *)auStack_3dc;",
                                "  jv_null();",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "jv_array",
                    "rva_start": 0x4AB8,
                    "rva_end": 0x4ABE,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jv_array"},
                    "decompiler": {"status": "success", "code": "void jv_array(void) {\n  jv_array();\n  return;\n}"},
                },
                {
                    "name": "jv_object",
                    "rva_start": 0x4A48,
                    "rva_end": 0x4A4E,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jv_object"},
                    "decompiler": {"status": "success", "code": "void jv_object(void) {\n  jv_object();\n  return;\n}"},
                },
                {
                    "name": "jv_null",
                    "rva_start": 0x4A58,
                    "rva_end": 0x4A5E,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jv_null"},
                    "decompiler": {"status": "success", "code": "void jv_null(void) {\n  jv_null();\n  return;\n}"},
                },
            ],
        )

        self.assertIn("typedef struct _stage_b_jv { uint32_t word[4]; } stage_b_jv;", source)
        self.assertIn("extern stage_b_jv jv_array(void);", source)
        self.assertIn("extern stage_b_jv jv_object(void);", source)
        self.assertIn("extern stage_b_jv jv_null(void);", source)
        self.assertIn("*(stage_b_jv *)auStack_3fc = jv_array();", source)
        self.assertIn("*(stage_b_jv *)auStack_3ec = jv_object();", source)
        self.assertIn("*(stage_b_jv *)auStack_3dc = jv_null();", source)
        self.assertNotIn("  jv_array();", source)
        self.assertNotIn("  jv_object();", source)
        self.assertNotIn("  jv_null();", source)

    def test_decompiled_c_renderer_recovers_jq_isoption_dispatch_stub(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x2490,
                    "size": 0x32,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t umain(int argc,undefined4 *argv)",
                                "{",
                                "  char *apcStack_3c [4];",
                                "  char *pcVar7;",
                                "  FILE *pFVar4;",
                                "  code *local_448;",
                                "  uint *puVar23;",
                                "  undefined8 uVar37;",
                                "LAB_00402760:",
                                "  apcStack_3c[0] = pcVar7 + 1;",
                                "  if (pcVar7[1] == '-') {",
                                "    apcStack_3c[0] = pcVar7 + 2;",
                                "    puVar23 = (uint *)0x0;",
                                "  }",
                                "joined_r0x00402777:",
                                "  if (apcStack_3c[0] != (char *)0x0) {",
                                "    uVar37 = isoption((int)puVar23);",
                                "    uVar37 = isoption((int)puVar23);",
                                "  }",
                                "  ___acrt_iob_func();",
                                "  ___acrt_iob_func();",
                                "  ___acrt_iob_func();",
                                "  ___acrt_iob_func();",
                                "  pFVar4 = (FILE *)(*local_448)();",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("static int stage_b_jq_isoption_next(char **cursor, int short_mode)", source)
        self.assertIn("case 0:", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, 'n', \"null-input\")", source)
        self.assertIn("case 30:", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"help\")", source)
        self.assertIn("case 31:", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, 'V', \"version\")", source)
        self.assertIn("case 32:", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"build-configuration\")", source)
        self.assertIn("case 33:", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"run-tests\")", source)
        self.assertIn("LAB_00402760:\n  apcStack_3c[0] = pcVar7 + 1;\n  puVar23 = (uint *)0x1;", source)
        self.assertIn("pFVar4 = (FILE *)(*local_448)(2);", source)
        self.assertIn("joined_r0x00402777:\n  stage_b_jq_isoption_reset();", source)
        self.assertIn("uVar37 = stage_b_jq_isoption_next(&apcStack_3c[0], (int)puVar23);", source)
        self.assertNotIn("pFVar4 = (FILE *)(*local_448)();", source)
        self.assertNotIn("isoption((int)puVar23)", source)

    def test_decompiled_c_renderer_normalizes_ghidra_bool_return_concats(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x2490,
                    "size": 0x32,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t umain(int argc,undefined4 *argv)",
                                "{",
                                "  bool bVar3;",
                                "  undefined3 extraout_var;",
                                "  undefined3 extraout_var_01;",
                                "  uint *puVar23;",
                                "  bVar3 = isoptish();",
                                "  puVar23 = (uint *)CONCAT31(extraout_var,bVar3);",
                                "  bVar3 = isoptish();",
                                "  puVar23 = (uint *)CONCAT31(extraout_var_01,bVar3);",
                                "  return (uintptr_t)puVar23;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("puVar23 = (uint *)(uint)bVar3;", source)
        self.assertNotIn("CONCAT31(extraout_var", source)

    def test_decompiled_c_renderer_recovers_jq_version_printf_argument(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x2490,
                    "size": 0x32,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t umain(int argc,undefined4 *argv)",
                                "{",
                                "  ___mingw_printf((byte *)\"jq-%s\\n\");",
                                "  goto LAB_00404713;",
                                "LAB_00404713:",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn('___mingw_printf((byte *)"jq-%s\\n","1.8.1");', source)
        self.assertIn('___mingw_printf((byte *)"jq-%s\\n","1.8.1");\n  return 0;', source)
        self.assertNotIn('___mingw_printf((byte *)"jq-%s\\n");', source)
        self.assertNotIn("goto LAB_00404713;", source)

    def test_decompiled_c_renderer_recovers_jq_usage_version_fprintf_argument(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "usage",
                    "rva_start": 0x153A,
                    "rva_end": 0x15D9,
                    "size": 0x9F,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t __cdecl usage()",
                                "{",
                                "  FILE *pFVar2;",
                                "  int iVar3;",
                                "  iVar3 = ___mingw_fprintf(pFVar2,(byte *)",
                                "                                  \"jq - commandline JSON processor [version %s]\\n\\nUsage:\\tjq [options]\\n\"",
                                "                          );",
                                "  exit(0);",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn('"jq - commandline JSON processor [version %s]\\n\\nUsage:\\tjq [options]\\n"', source)
        self.assertIn(',"1.8.1");', source)

    def test_decompiled_c_renderer_injects_jq_run_tests_fast_path(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "umain",
                    "rva_start": 0x245E,
                    "rva_end": 0x2490,
                    "size": 0x32,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t umain(int param_1,undefined4 *param_2)",
                                "{",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "jq_testsuite",
                    "rva_start": 0x4B00,
                    "rva_end": 0x4B06,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jq_testsuite"},
                    "decompiler": {"status": "success", "code": "void jq_testsuite(void) { return; }"},
                },
                {
                    "name": "jq_realpath",
                    "rva_start": 0x4B40,
                    "rva_end": 0x4B46,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jq_realpath"},
                    "decompiler": {"status": "success", "code": "void jq_realpath(void) { return; }"},
                },
                {
                    "name": "jv_array_append",
                    "rva_start": 0x4AB0,
                    "rva_end": 0x4AB6,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jv_array_append"},
                    "decompiler": {"status": "success", "code": "void jv_array_append(void) { return; }"},
                },
                {
                    "name": "jv_string",
                    "rva_start": 0x4A20,
                    "rva_end": 0x4A26,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jv_string"},
                    "decompiler": {"status": "success", "code": "void jv_string(void) { return; }"},
                },
                {
                    "name": "jv_array",
                    "rva_start": 0x4A40,
                    "rva_end": 0x4A46,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "jv_array"},
                    "decompiler": {"status": "success", "code": "void jv_array(void) { return; }"},
                },
            ],
        )

        self.assertIn("#define stage_b_jq_call_jq_testsuite", source)
        self.assertIn("#define stage_b_jq_call_jq_realpath", source)
        self.assertIn("#define stage_b_jq_call_jv_array_append", source)
        self.assertIn("#define stage_b_jq_call_jv_string", source)
        self.assertIn("extern uintptr_t jq_testsuite();", source)
        self.assertIn("extern uintptr_t jq_realpath();", source)
        self.assertIn("extern uintptr_t jv_array_append();", source)
        self.assertIn("extern uintptr_t jv_string();", source)
        self.assertIn('strcmp(stage_b_jq_argv[1], "--version") == 0', source)
        self.assertIn('strcmp(stage_b_jq_argv[1], "-V") == 0', source)
        self.assertIn('___mingw_printf((byte *)"jq-%s\\n","1.8.1");', source)
        self.assertIn('strcmp(stage_b_jq_argv[1], "-L") == 0', source)
        self.assertIn('strcmp(stage_b_jq_argv[3], "--run-tests") == 0', source)
        self.assertIn("stage_b_jq_libs = stage_b_jq_call_jv_array_append(stage_b_jq_libs, stage_b_jq_lib_path);", source)
        self.assertIn("return (uintptr_t)stage_b_jq_call_jq_testsuite(stage_b_jq_libs, 0, param_1 - 4, stage_b_jq_argv + 4);", source)
        self.assertIn("return (uintptr_t)stage_b_jq_call_jq_testsuite(jv_array(), 0, param_1 - 2, stage_b_jq_argv + 2);", source)
        self.assertNotIn("__attribute__((weak)) uintptr_t stage_b_jq_call_jq_testsuite()", source)

    def test_decompiled_c_renderer_keeps_mingw_printf_wrappers_variadic(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___mingw_printf",
                    "rva_start": 0x8C00,
                    "rva_end": 0x8C20,
                    "size": 0x20,
                    "decompiler": {"status": "success", "code": "int __cdecl ___mingw_printf(byte *param_1)\n{\n  return 0;\n}"},
                },
                {
                    "name": "___mingw_fprintf",
                    "rva_start": 0x6090,
                    "rva_end": 0x60B0,
                    "size": 0x20,
                    "decompiler": {"status": "success", "code": "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2)\n{\n  return 0;\n}"},
                },
            ],
        )

        self.assertIn("int __cdecl ___mingw_printf(byte *param_1,...);", source)
        self.assertIn("int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...);", source)
        self.assertIn("extern int vfprintf(FILE *, const char *, va_list);", source)
        self.assertIn("int __cdecl ___mingw_printf(byte *param_1,...)\n", source)
        self.assertIn("int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)\n", source)
        self.assertIn("result = vfprintf(stream,(const char *)param_1,args);", source)
        self.assertIn("result = vfprintf(param_1,(const char *)param_2,args);", source)
        self.assertNotIn("extern uintptr_t va_start();", source)
        self.assertNotIn("__attribute__((weak)) uintptr_t va_start()", source)
        self.assertNotIn("extern uintptr_t va_end();", source)
        self.assertNotIn("__attribute__((weak)) uintptr_t va_end()", source)

    def test_generate_skeleton_can_emit_named_decompiled_c_slice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3\x90\xc3")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva": 0x1000,
                                "rva_end": 0x1001,
                                "name": "helper",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int helper(void) {\n  return 7;\n}",
                                },
                            },
                            {
                                "rva": 0x1002,
                                "rva_end": 0x1003,
                                "name": "entry",
                                "decompiler": {
                                    "status": "success",
                                    "c": "int entry(void) {\n  return helper() + (int)*(byte *)&stack0xfffffff0;\n}",
                                },
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                implementation_mode="decompiled-c",
                function_names=["entry"],
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["counts"]["functions"], 1)
            self.assertEqual(result["reverse_engineering"]["function_filter"]["mode"], "function_names")
            self.assertEqual(result["reverse_engineering"]["function_filter"]["included"], ["entry"])
            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("extern uintptr_t helper();", source)
            self.assertIn("extern byte stack0xfffffff0;", source)
            self.assertIn("int entry(void);", source)
            self.assertIn("int entry(void)", source)
            self.assertNotIn("int helper(void)", source)

    def test_generate_skeleton_rejects_incomplete_decompiled_c_behavior_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {
                                "rva": 0x1000,
                                "rva_end": 0x1001,
                                "name": "tiny_from_decompiler",
                                "decompiler": {"status": "error", "error": "decompile failed"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(Exception, "missing_decompiler_code"):
                stage_b_generate_skeleton(
                    original=original,
                    decompiler_export=decompiler,
                    target_name="jq",
                    source_language="c",
                    implementation_mode="decompiled-c",
                    out_dir=root / "skeleton",
                )

    def test_generated_source_disambiguates_duplicate_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3\x90\xc3")
            decompiler = root / "jq.ghidra.json"
            decompiler.write_text(
                json.dumps(
                    {
                        "functions": [
                            {"rva": 0x1000, "rva_end": 0x1001, "name": "same-name"},
                            {"rva": 0x1002, "rva_end": 0x1003, "name": "same$name"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            out = root / "skeleton"

            stage_b_generate_skeleton(
                original=original,
                decompiler_export=decompiler,
                target_name="jq",
                source_language="c",
                out_dir=out,
            )

            source = (out / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("stage_b_fn_same_name(void)", source)
            self.assertIn("stage_b_fn_same_name_at_1002(void)", source)

    def test_stage_a_validates_byte_identical_pe32plus_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe32plus(root / "original.exe", b"\xc3")
            candidate = self._write_pe32plus(root / "candidate.exe", b"\xc3")
            mapping = root / "block-map.json"
            mapping.write_text(
                json.dumps(
                    {
                        "blocks": [
                            {
                                "id": "entry",
                                "kind": "code",
                                "reachable": True,
                                "original": {"rva": 0x1000, "size": 1},
                                "candidate": {"rva": 0x1000, "size": 1},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            with _LeanCheckedMock():
                result = stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=mapping,
                    model=STAGE_A_X86_64_MODEL_ID,
                    out=root / "report",
                )

            self.assertEqual(result["verdict"], "pass")
            obligation = self._obligation(root / "report", "block:entry")
            self.assertEqual(obligation["proof_rule"], "byte_identical_x86_64_pe32plus_block")

    def test_run_functional_suite_compares_process_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate.py"
            cwd = root / "suite-cwd"
            cwd.mkdir()
            (cwd / "marker.txt").write_text("cwd-marker", encoding="utf-8")
            script = (
                "import sys\n"
                "from pathlib import Path\n"
                "text = sys.stdin.read()\n"
                "print('args=' + ','.join(sys.argv[1:]))\n"
                "print('stdin=' + text)\n"
                "print('cwd=' + Path('marker.txt').read_text(encoding='utf-8'))\n"
            )
            candidate.write_text(script, encoding="utf-8")
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "target_name": "jq",
                        "suite_id": "jq-upstream-integration-tests",
                        "suite_name": "jq upstream integration tests",
                        "suite_kind": "upstream_integration",
                        "suite_scope": "full",
                        "upstream_suite": True,
                        "coverage": {
                            "source": "jq upstream integration suite fixture",
                            "source_kind": "upstream_integration_suite",
                            "source_sha256": sha256_bytes(b"jq upstream integration suite fixture"),
                            "source_revision": "fixture",
                            "materialized_by": STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
                            "required_suite_ids": ["jq-upstream-integration-tests"],
                        },
                        "cases": [
                            {
                                "id": "echo",
                                "args": ["-n", "."],
                                "stdin": "{\"a\":1}",
                                "cwd": str(cwd),
                                "expected_returncode": 0,
                                "expected_stdout": "args=-n,.\nstdin={\"a\":1}\ncwd=cwd-marker\n",
                                "expected_stderr": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_run_functional_suite(
                suite=suite,
                candidate_command=(sys.executable, str(candidate)),
                candidate_binary=candidate,
                out=root / "functional",
            )

            self.assertEqual(result["status"], "pass")
            self.assertTrue((root / "functional" / "functional-report.json").exists())
            self.assertEqual(result["counts"], {"cases": 1, "failed": 0, "passed": 1})
            self.assertEqual(result["runner"]["name"], "stage-b-run-functional-suite")
            self.assertEqual(result["suite_sha256"], sha256_file(suite))
            self.assertEqual(len(result["case_manifest"]), 1)
            self.assertEqual(result["case_manifest"][0]["id"], "echo")
            self.assertEqual(result["case_manifest"][0]["cwd"], str(cwd))
            self.assertEqual(result["case_manifest"][0]["env_sha256"], sha256_bytes(b"{}"))
            self.assertEqual(result["cases"][0]["candidate"]["cwd"], str(cwd))
            self.assertEqual(result["oracle"]["kind"], "expected_output")
            self.assertFalse(result["oracle"]["original_runtime_observations"])
            self.assertEqual(result["coverage"]["suite_sha256"], result["suite_sha256"])
            self.assertEqual(result["coverage"]["suite_case_manifest_sha256"], result["suite_case_manifest_sha256"])
            self.assertEqual(result["suite_id"], "jq-upstream-integration-tests")
            self.assertEqual(result["suite_kind"], "upstream_integration")
            self.assertEqual(result["coverage"]["suite_scope"], "full")
            self.assertEqual(result["coverage"]["required_suite_ids"], ["jq-upstream-integration-tests"])
            self.assertEqual(result["coverage"]["source_kind"], "upstream_integration_suite")
            self.assertEqual(result["coverage"]["source_sha256"], sha256_bytes(b"jq upstream integration suite fixture"))
            self.assertEqual(result["coverage"]["source_revision"], "fixture")
            self.assertEqual(result["coverage"]["materialized_by"], STAGE_B_UPSTREAM_SUITE_MATERIALIZER)
            self.assertEqual(result["coverage"]["case_ids_sha256"], sha256_bytes(b'["echo"]'))
            self.assertEqual(result["binary_bindings"]["candidate"]["sha256"], sha256_file(candidate))
            self.assertTrue(result["binary_bindings"]["candidate"]["command_contains_path"])
            self.assertNotIn("original", result["commands"])
            self.assertNotIn("original", result["binary_bindings"])

    def test_run_functional_suite_rejects_failed_expected_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate.py"
            script = "import sys\nprint('same output')\nsys.exit(7)\n"
            candidate.write_text(script, encoding="utf-8")
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "target_name": "ripgrep",
                        "suite_id": "ripgrep-upstream-integration-tests",
                        "suite_name": "ripgrep upstream integration tests",
                        "suite_kind": "upstream_integration",
                        "suite_scope": "full",
                        "upstream_suite": True,
                        "coverage": {
                            "source": "ripgrep upstream integration suite fixture",
                            "source_kind": "upstream_integration_suite",
                            "source_sha256": sha256_bytes(b"ripgrep upstream integration suite fixture"),
                            "source_revision": "fixture",
                            "materialized_by": STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
                            "required_suite_ids": ["ripgrep-upstream-integration-tests"],
                        },
                        "cases": [
                            {
                                "id": "upstream-harness",
                                "expected_returncode": 0,
                                "expected_stdout": "same output\n",
                                "expected_stderr": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_run_functional_suite(
                suite=suite,
                candidate_command=(sys.executable, str(candidate)),
                candidate_binary=candidate,
                out=root / "functional",
            )

            self.assertEqual(result["status"], "fail")
            self.assertEqual(result["counts"], {"cases": 1, "failed": 1, "passed": 0})
            case = result["cases"][0]
            self.assertEqual(case["expected"]["returncode"], 0)
            self.assertEqual(case["expectation"]["status"], "fail")
            self.assertEqual(case["expectation"]["actual_returncode"], 7)
            self.assertEqual(case["mismatch"]["fields"], ["returncode"])
            self.assertEqual(result["case_manifest"][0]["expected"]["returncode"], 0)

    def test_run_functional_suite_can_strip_configured_stderr_noise(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate.py"
            candidate.write_text(
                "import sys\nprint('same output')\nsys.stderr.write('runner noise\\nrunner noise\\n')\n",
                encoding="utf-8",
            )
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "target_name": "jq",
                        "suite_id": "jq-upstream-integration-tests",
                        "suite_name": "jq upstream integration tests",
                        "cases": [
                            {
                                "id": "stderr-noise",
                                "expected_returncode": 0,
                                "expected_stdout": "same output\n",
                                "expected_stderr": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_run_functional_suite(
                suite=suite,
                candidate_command=(sys.executable, str(candidate)),
                out=root / "functional",
                strip_stderr_line_regexes=(r"^runner noise$",),
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["runner"]["strip_stderr_line_regexes"], [r"^runner noise$"])
            self.assertEqual(result["cases"][0]["candidate"]["stderr"]["bytes"], 0)

    def test_run_functional_suite_kills_process_group_on_timeout(self):
        if os.name != "posix":
            self.skipTest("process-group timeout cleanup is POSIX-specific")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sleeper = root / "spawn_child.py"
            candidate_child = root / "candidate-child.pid"
            sleeper.write_text(
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "from pathlib import Path\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "target_name": "jq",
                        "suite_id": "jq-upstream-integration-tests",
                        "suite_name": "jq upstream integration tests",
                        "cases": [
                            {
                                "id": "timeout",
                                "timeout_seconds": 0.5,
                                "expected_returncode": 0,
                                "expected_stdout": "",
                                "expected_stderr": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_run_functional_suite(
                suite=suite,
                candidate_command=(sys.executable, str(sleeper), str(candidate_child)),
                out=root / "functional",
            )

            self.assertEqual(result["status"], "fail")
            self.assertTrue(result["cases"][0]["candidate"]["timed_out"])
            self._assert_pid_file_dead(candidate_child)

    def test_run_functional_suite_supports_candidate_specific_timeout(self):
        if os.name != "posix":
            self.skipTest("process-group timeout cleanup is POSIX-specific")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "candidate.py"
            candidate_child = root / "candidate-child.pid"
            candidate.write_text(
                "import subprocess\n"
                "import sys\n"
                "import time\n"
                "from pathlib import Path\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "Path(sys.argv[1]).write_text(str(child.pid), encoding='utf-8')\n"
                "time.sleep(60)\n",
                encoding="utf-8",
            )
            suite = root / "suite.json"
            suite.write_text(
                json.dumps(
                    {
                        "target_name": "jq",
                        "suite_id": "jq-upstream-integration-tests",
                        "suite_name": "jq upstream integration tests",
                        "cases": [
                            {
                                "id": "asymmetric-timeout",
                                "timeout_seconds": 10,
                                "candidate_timeout_seconds": 0.5,
                                "expected_returncode": 0,
                                "expected_stdout": "ok\n",
                                "expected_stderr": "",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_run_functional_suite(
                suite=suite,
                candidate_command=(sys.executable, str(candidate), str(candidate_child)),
                out=root / "functional",
            )

            case = result["cases"][0]
            self.assertEqual(result["status"], "fail")
            self.assertEqual(case["timeout_seconds"], 10.0)
            self.assertEqual(case["candidate_timeout_seconds"], 0.5)
            self.assertTrue(case["candidate"]["timed_out"])
            self.assertEqual(case["expectation"]["status"], "fail")
            self.assertIn("timeout", case["mismatch"]["fields"])
            self.assertEqual(result["case_manifest"][0]["candidate_timeout_seconds"], 0.5)
            self._assert_pid_file_dead(candidate_child)

    def test_validate_candidate_rejects_non_compliant_provenance_before_stage_a(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            linker_map = self._write_map(root / "original.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            provenance = root / "candidate-provenance.json"
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": "wrong",
                        "upstream_source_access": True,
                        "manual_behavioral_fixups": ["patched parser behavior"],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=linker_map,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                target_name="jq",
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            categories = {issue["category"] for issue in result["issues"]}
            self.assertIn("skeleton_hash_mismatch", categories)
            self.assertIn("upstream_source_access", categories)
            self.assertIn("manual_behavioral_fixups", categories)
            self.assertIn("missing_functional_tests", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_stage_a_direct_stage_b_rule_requires_checked_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "block-map.json",
                proof_rule=STAGE_B_PROOF_RULE,
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("missing_stage_b_proof_metadata", {issue["category"] for issue in result["issues"]})

    def test_validate_candidate_requires_upstream_functional_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(root / "functional-report.json", target_name="jq", upstream_suite=False)
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [{"kind": "stage_b_generated_skeleton", "path": str(skeleton_dir)}],
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"name": "local smoke", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("functional_test_report_not_upstream", {issue["category"] for issue in result["issues"]})
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_failed_functional_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(root / "functional-report.json", target_name="jq", status="fail")
            functional_payload = json.loads(functional_report.read_text(encoding="utf-8"))
            candidate_stdout = root / "candidate.stdout"
            candidate_stdout_data = (
                b"running 3 tests\n"
                b"test binary::basic_search ... FAILED\n"
                b"test feature::context ... ok\n"
                b"test feature::unicode ... FAILED\n"
                b"test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
            )
            candidate_stdout.write_bytes(candidate_stdout_data)
            candidate_stderr = root / "candidate.stderr"
            candidate_stderr.write_bytes(b"")
            expected = {"returncode": 0, "stdout": "", "stderr": ""}
            expectation = {
                "status": "fail",
                "expected_returncode": 0,
                "actual_returncode": 101,
                "actual_timed_out": False,
                "expected_stdout_sha256": sha256_bytes(b""),
                "actual_stdout_sha256": sha256_bytes(candidate_stdout_data),
            }
            functional_payload["cases"][0]["expected"] = expected
            functional_payload["cases"][0]["expectation"] = expectation
            functional_payload["cases"][0]["candidate"] = {
                "returncode": 101,
                "timed_out": False,
                "stdout": self._stream_artifact(candidate_stdout),
                "stderr": self._stream_artifact(candidate_stderr),
            }
            functional_payload["cases"][0]["mismatch"] = {
                "fields": ["returncode", "stdout"],
                "expectation": expectation,
            }
            functional_report.write_text(json.dumps(functional_payload), encoding="utf-8")
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [{"kind": "stage_b_generated_skeleton", "path": str(skeleton_dir)}],
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("functional_test_report_failed", categories)
            self.assertIn("functional_test_report_failed_cases", categories)
            self.assertEqual(result["stage_a"]["gate"]["status"], "blocked")
            self.assertEqual(result["stage_a"]["gate"]["reason"], "functional_behavior_mismatch")
            self.assertFalse(result["stage_a"]["gate"]["eligible"])
            self.assertFalse(result["stage_a"]["gate"]["ran"])
            self.assertTrue(result["stage_a"]["gate"]["behavioral_mismatch_blocks_stage_a"])
            self.assertIn(
                "functional_test_report_failed",
                result["stage_a"]["gate"]["behavioral_blocking_issue_categories"],
            )
            diagnostics = result["functional_diagnostics"]
            self.assertEqual(diagnostics["status"], "fail")
            self.assertEqual(diagnostics["failure_counts"]["mismatch_fields"][0], {"field": "returncode", "count": 1})
            self.assertIn({"field": "stdout", "count": 1}, diagnostics["failure_counts"]["mismatch_fields"])
            self.assertIn({"status": "FAILED", "count": 2}, diagnostics["harness_tests"]["status_counts"])
            self.assertIn({"status": "ok", "count": 1}, diagnostics["harness_tests"]["status_counts"])
            self.assertIn({"prefix": "binary", "count": 1}, diagnostics["harness_tests"]["failed_test_prefixes"])
            self.assertIn({"prefix": "feature", "count": 1}, diagnostics["harness_tests"]["failed_test_prefixes"])
            self.assertEqual(diagnostics["harness_tests"]["top_failed_tests"][0]["name"], "binary::basic_search")
            self.assertEqual(diagnostics["harness_tests"]["artifacts"][0]["source"], "path")
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_distinguishes_failing_required_suite_from_missing_suite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(root / "functional-report.json", target_name="jq", status="fail")
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [self._generated_source_root(skeleton_dir)],
                        "build": self._candidate_build(candidate),
                        "functional_tests": {
                            "status": "fail",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [
                                {
                                    "id": "jq-upstream-integration-tests",
                                    "name": "jq upstream integration tests",
                                    "status": "fail",
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("required_functional_suite_not_passing", categories)
            self.assertNotIn("missing_required_functional_suite", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_smoke_report_without_required_upstream_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                suite_id="jq-upstream-integration-smoke",
                suite_name="jq upstream integration smoke",
                suite_scope="subset",
                required_suite_ids=["jq-upstream-integration-smoke"],
            )
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [{"kind": "stage_b_generated_skeleton", "path": str(skeleton_dir)}],
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-smoke", "name": "jq upstream integration smoke", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("missing_required_functional_suite", categories)
            self.assertIn("functional_test_report_wrong_suite_id", categories)
            self.assertIn("functional_test_report_incomplete_coverage_scope", categories)
            self.assertIn("functional_test_report_missing_required_suite_id", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_canonical_report_without_upstream_source_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            fixed_up_source = root / "fixed-up-jq.c"
            fixed_up_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            functional_payload = json.loads(functional_report.read_text(encoding="utf-8"))
            functional_payload["coverage"].pop("source_sha256")
            functional_payload["coverage"].pop("materialized_by")
            functional_report.write_text(json.dumps(functional_payload), encoding="utf-8")
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [
                            self._generated_source_root(skeleton_dir),
                            self._fixed_up_source_root(skeleton_dir, fixed_up_source),
                        ],
                        "build": self._candidate_build(candidate),
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("functional_test_report_missing_source_hash", categories)
            self.assertIn("functional_test_report_wrong_materializer", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_wrong_architecture_candidate_before_stage_a(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe32plus(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [{"kind": "stage_b_generated_skeleton", "path": str(skeleton_dir)}],
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("binary_target_mismatch", categories)
            self.assertFalse(result["binaries"]["facts"]["same_architecture_same_os"])
            self.assertEqual(result["binaries"]["original"]["machine"], "i386")
            self.assertEqual(result["binaries"]["candidate"]["machine"], "x86_64")
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_generated_skeleton_source_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            bad_source_root = self._generated_source_root(skeleton_dir)
            bad_source_root["source_sha256"] = "0" * 64
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [bad_source_root],
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("generated_skeleton_source_hash_mismatch", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_behavioral_fixed_up_source_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            fixed_up_source = root / "fixed-up-jq.c"
            fixed_up_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            fixed_up_root = self._fixed_up_source_root(skeleton_dir, fixed_up_source)
            fixed_up_root["fixup_policy"] = "semantic_rewrite"
            fixed_up_root["behavioral_fixups"] = ["changed recovered branch condition"]
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [
                            self._generated_source_root(skeleton_dir),
                            fixed_up_root,
                        ],
                        "build": self._candidate_build(candidate),
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("invalid_fixed_up_source_policy", categories)
            self.assertIn("fixed_up_source_behavioral_fixups", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_delegates_to_stage_a_with_stage_b_proof_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            fixed_up_source = root / "fixed-up-jq.c"
            fixed_up_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [
                            self._generated_source_root(skeleton_dir),
                            self._fixed_up_source_root(skeleton_dir, fixed_up_source),
                        ],
                        "build": self._candidate_build(candidate),
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )
            reference_block_map = root / "reference-block-map.json"
            reference_layout = root / "reference-layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=reference_block_map,
                layout_contract_out=reference_layout,
            )
            reference_report = root / "reference-stage-a"
            reference_contract = root / "reference-contract.json"

            with _LeanCheckedMock():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=reference_block_map,
                    model="x86-pe32-env-v1",
                    out=reference_report,
                    layout_contract=reference_layout,
                )
                stage_a_export_reference_contract(
                    original=original,
                    candidate=candidate,
                    mapping=reference_block_map,
                    validation_report=reference_report,
                    layout_contract=reference_layout,
                    out=reference_contract,
                )
                result = stage_b_validate_candidate(
                    original=original,
                    candidate=candidate,
                    linker_map_original=original_map,
                    linker_map_candidate=candidate_map,
                    skeleton_manifest=skeleton_dir / "manifest.json",
                    candidate_provenance=provenance,
                    functional_report=functional_report,
                    reference_contract=reference_contract,
                    target_name="jq",
                    out=root / "report",
                    original_flags="-O2",
                    candidate_flags="-O2 stage-b",
                )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["stage_a"]["verdict"], "pass")
            self.assertEqual(result["stage_a"]["gate"]["status"], "pass")
            self.assertEqual(result["stage_a"]["gate"]["reason"], "stage_a_final_pass")
            self.assertTrue(result["stage_a"]["gate"]["eligible"])
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            self.assertFalse(result["stage_a"]["gate"]["behavioral_mismatch_blocks_stage_a"])
            self.assertEqual(result["binaries"]["status"], "pass")
            self.assertTrue(result["binaries"]["facts"]["same_architecture_same_os"])
            self.assertEqual(result["candidate"]["build"]["output_sha256"], sha256_file(candidate))
            self.assertEqual(result["reference_contract_coverage"]["status"], "satisfied")
            coverage_statuses = {item["family"]: item["status"] for item in result["reference_contract_coverage"]["families"]}
            self.assertNotIn("represented", set(coverage_statuses.values()))
            self.assertEqual(coverage_statuses["executable_byte_coverage"], "satisfied")
            self.assertEqual(coverage_statuses["validation_report_artifact_binding"], "satisfied")
            self.assertEqual(coverage_statuses["proof_obligation_inventory_and_statuses"], "satisfied")
            stage_b_statuses = {
                item["family"]: item["stage_b_status"]
                for item in result["reference_contract_coverage"]["families"]
            }
            self.assertEqual(stage_b_statuses["function_ranges"], "represented")
            self.assertEqual(result["reference_contract_coverage"]["next_work"], [])
            self.assertFalse((root / "report" / "generated" / "block-map.json").exists())
            contract_verdict = json.loads((root / "report" / "stage-a" / "verdict.json").read_text(encoding="utf-8"))
            self.assertEqual(contract_verdict["format"], "stage-a-contract-candidate-validation-v1")
            self.assertEqual(contract_verdict["verdict"], "pass")
            family_statuses = {item["family"]: item["status"] for item in contract_verdict["families"]}
            self.assertEqual(family_statuses["binary_faithfulness"], "satisfied")
            self.assertEqual(family_statuses["function_ranges"], "satisfied")
            self.assertEqual(family_statuses["proof_inventory"], "satisfied")

    def test_explain_delta_reports_source_mapped_candidate_only_repairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            reference_candidate_map = self._write_map(root / "reference-candidate.map", "tiny")
            missing_candidate_map = root / "missing-candidate.map"
            missing_candidate_map.write_text("", encoding="utf-8")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            reference_block_map = root / "reference-block-map.json"
            reference_layout = root / "reference-layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=reference_candidate_map,
                out=reference_block_map,
                layout_contract_out=reference_layout,
            )
            reference_report = root / "reference-stage-a"
            reference_contract = root / "reference-contract.json"
            with _LeanCheckedMock():
                stage_a_validate(
                    original=original,
                    candidate=candidate,
                    mapping=reference_block_map,
                    model=STAGE_A_MODEL_ID,
                    out=reference_report,
                    layout_contract=reference_layout,
                )
                stage_a_export_reference_contract(
                    original=original,
                    candidate=candidate,
                    mapping=reference_block_map,
                    validation_report=reference_report,
                    layout_contract=reference_layout,
                    out=reference_contract,
                )

            result = stage_b_explain_delta(
                reference_contract=reference_contract,
                candidate=candidate,
                linker_map_candidate=missing_candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                out=root / "delta",
            )

            self.assertEqual(result["format"], "stage-b-delta-explanation-v1")
            self.assertEqual(result["status"], "incomplete")
            self.assertGreaterEqual(result["counts"]["repair_items"], 1)
            item = next(item for item in result["repair_items"] if item["violated_contract_family"] == "function_ranges")
            self.assertEqual(item["violated_contract_family"], "function_ranges")
            self.assertEqual(item["original_function"], "tiny")
            self.assertEqual(item["likely_repair_class"], "function_mapping")
            self.assertEqual(item["generated_source_location"]["file"], "src/jq_stage_b_skeleton.c")
            self.assertTrue((root / "delta" / "stage-b-delta.json").exists())

    def test_explain_delta_splits_abi_callsites_into_actionable_repairs(self):
        skeleton = {
            "source_map": {
                "functions": [
                    {
                        "function": "foo",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 42,
                        "line_end": 53,
                    }
                ]
            }
        }
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "contract_status": "satisfied",
                    "blocker": "candidate ABI/callsite evidence does not yet cover the reference contract",
                    "next_action": "repair prototypes, sret/out-params, varargs bridges, stack deltas, or register preservation before final proof",
                    "evidence": {
                        "reference_counts": {"functions": 3, "callsites": 7},
                        "candidate_counts": {"functions": 1, "callsites": 5},
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "foo",
                                        "callsites": [
                                            {
                                                "id": "callsite:foo:1000",
                                                "block_id": "foo-0000",
                                                "instruction": {"rva": 0x1000, "mnemonic": "call"},
                                                "target": {"kind": "direct", "target_rva": 0x2000},
                                                "argument_sources": [
                                                    {
                                                        "kind": "register",
                                                        "register": "eax",
                                                        "stack_offset": 0,
                                                    }
                                                ],
                                                "hidden_sret_or_out_param_evidence": {
                                                    "status": "candidate",
                                                    "reason": "first_stack_argument_is_address_like",
                                                },
                                                "varargs_evidence": {"status": "not_observed"},
                                                "function_pointer_targets": [],
                                            }
                                        ],
                                    }
                                ]
                            }
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton=skeleton,
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        classes = {item["likely_repair_class"] for item in result}
        self.assertIn("abi_callsite_coverage", classes)
        self.assertIn("hidden_sret_or_out_param", classes)
        hidden_item = next(item for item in result if item["likely_repair_class"] == "hidden_sret_or_out_param")
        self.assertEqual(hidden_item["original_function"], "foo")
        self.assertEqual(hidden_item["generated_source_location"]["file"], "src/jq_stage_b_skeleton.c")
        self.assertEqual(hidden_item["generated_source_location"]["line_start"], 42)
        coverage_item = next(item for item in result if item["likely_repair_class"] == "abi_callsite_coverage")
        self.assertEqual(coverage_item["evidence"]["missing"], {"functions": 2, "callsites": 2})

    def test_explain_delta_keeps_unmapped_candidate_crash_as_crash_localization_work(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_page_fault",
                "instruction_address": "0x7BB48767",
                "stderr_preview": "wine: Unhandled page fault on write access\n",
                "repair_hints": ["inspect ABI, stack, hidden sret/out-param evidence"],
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "candidate_crash_unmapped")
        self.assertIsNone(result[0]["original_function"])
        self.assertIn("module, RVA, or backtrace", result[0]["next_action"])

    def test_validate_candidate_reports_stage_a_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\x90\x90\x90\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\x74\x01\xc3\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            fixed_up_source = root / "fixed-up-jq.c"
            fixed_up_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [
                            self._generated_source_root(skeleton_dir),
                            self._fixed_up_source_root(skeleton_dir, fixed_up_source),
                        ],
                        "build": self._candidate_build(candidate),
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["stage_a"]["map_status"], "incomplete")
            self.assertNotEqual(result["stage_a"]["verdict"], "pass")
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            diagnostics = result["stage_a"]["diagnostics"]
            self.assertEqual(diagnostics["format"], "stage-b-stage-a-diagnostics-v1")
            self.assertEqual(diagnostics["status"], "incomplete")
            self.assertEqual(diagnostics["map"]["status"], "incomplete")
            self.assertEqual(diagnostics["map"]["issue_counts"][0]["category"], "ambiguous_block_match")
            self.assertEqual(diagnostics["map"]["ambiguous_block_matches"][0]["function"], "tiny")
            shape_preview = diagnostics["map"]["ambiguous_block_matches"][0]["shape_preview"]
            self.assertEqual(shape_preview["original_first"]["terminal"]["mnemonic"], "ret")
            self.assertEqual(shape_preview["candidate_first"]["terminal"]["mnemonic"], "je")
            self.assertEqual(shape_preview["candidate_first"]["direct_edge_counts"], {"taken": 1, "fallthrough": 1})
            self.assertEqual(diagnostics["validation"]["status"], result["stage_a"]["verdict"])
            self.assertTrue(diagnostics["validation"]["obligation_status_counts"])
            self.assertTrue(diagnostics["validation"]["unresolved_category_counts"])
            samples_by_category = diagnostics["validation"]["unresolved_samples_by_category"]
            self.assertTrue(samples_by_category)
            self.assertEqual(
                samples_by_category[0]["category"],
                diagnostics["validation"]["unresolved_category_counts"][0]["category"],
            )
            self.assertTrue(samples_by_category[0]["samples"])
            self.assertEqual(samples_by_category[0]["samples"][0]["category"], samples_by_category[0]["category"])
            self.assertTrue(diagnostics["validation"]["top_unresolved"])
            self.assertTrue(diagnostics["next_focus"])
            self.assertEqual(diagnostics["next_focus"][0]["source"], "map")

    def test_audit_readiness_requires_both_jq_and_ripgrep_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jq_report = self._write_passing_stage_b_validation(root / "jq", "jq")

            result = stage_b_audit_readiness(reports={"jq": jq_report}, out=root / "audit")

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["counts"], {"targets": 2, "ready": 1, "incomplete": 1})
            self.assertEqual(result["targets"]["jq"]["status"], "pass")
            self.assertEqual(result["targets"]["ripgrep"]["status"], "incomplete")
            missing = {item["id"]: item["status"] for item in result["targets"]["ripgrep"]["requirements"]}
            self.assertEqual(set(missing.values()), {"missing"})
            self.assertTrue((root / "audit" / "stage-b-readiness.json").exists())

    def test_audit_readiness_passes_when_both_validation_reports_are_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            jq_report = self._write_passing_stage_b_validation(root / "jq", "jq")
            ripgrep_report = self._write_passing_stage_b_validation(root / "ripgrep", "ripgrep")

            result = stage_b_audit_readiness(reports={"jq": jq_report, "ripgrep": ripgrep_report}, out=root / "audit")

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["counts"], {"targets": 2, "ready": 2, "incomplete": 0})
            for target_name in ("jq", "ripgrep"):
                self.assertEqual(result["targets"][target_name]["status"], "pass")
                self.assertTrue(
                    all(item["status"] == "satisfied" for item in result["targets"][target_name]["requirements"])
                )
                requirement_ids = {item["id"] for item in result["targets"][target_name]["requirements"]}
                self.assertIn("same_architecture_same_os", requirement_ids)
                self.assertIn("candidate_build_artifact", requirement_ids)
                self.assertIn("no_upstream_source_dependency", requirement_ids)
                self.assertIn("functional_binary_bindings", requirement_ids)
                self.assertIn("generated_behavior_source", requirement_ids)
                self.assertIn("stage_a_reference_contract_coverage", requirement_ids)
                contract_requirement = [
                    item
                    for item in result["targets"][target_name]["requirements"]
                    if item["id"] == "stage_a_reference_contract_coverage"
                ][0]
                self.assertEqual(contract_requirement["evidence"]["next_work"], [])

    def test_validate_candidate_rejects_candidate_build_output_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            build = self._candidate_build(candidate)
            build["output_sha256"] = "0" * 64
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [self._generated_source_root(skeleton_dir)],
                        "build": build,
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["provenance_status"], "incomplete")
            self.assertIn("candidate_build_output_hash_mismatch", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_rejects_functional_report_binary_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            functional_report = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                original_binary=original,
                candidate_binary=candidate,
            )
            functional_payload = json.loads(functional_report.read_text(encoding="utf-8"))
            functional_payload["binary_bindings"]["candidate"]["sha256"] = "0" * 64
            functional_report.write_text(json.dumps(functional_payload), encoding="utf-8")
            provenance = root / "candidate-provenance.json"
            provenance.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-provenance-v1",
                        "target_name": "jq",
                        "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                        "upstream_source_access": False,
                        "manual_behavioral_fixups": [],
                        "source_roots": [self._generated_source_root(skeleton_dir)],
                        "build": self._candidate_build(candidate),
                        "functional_tests": {
                            "status": "pass",
                            "report_sha256": sha256_file(functional_report),
                            "suites": [{"id": "jq-upstream-integration-tests", "name": "jq upstream integration tests", "status": "pass"}],
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["provenance_status"], "incomplete")
            self.assertIn("functional_binary_hash_mismatch", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def _write_pe(self, path: Path, code: bytes) -> Path:
        path.write_bytes(_pe32_image(code))
        return path

    def _write_import_pe(self, path: Path, code: bytes, symbol: str) -> Path:
        path.write_bytes(_pe32_import_image(code, symbol=symbol))
        return path

    def _write_export_dll(self, path: Path) -> Path:
        path.write_bytes(_pe32_export_dll_image())
        return path

    def _write_pe32plus(self, path: Path, code: bytes) -> Path:
        path.write_bytes(_pe32plus_image(code))
        return path

    def _write_map(self, path: Path, symbol: str) -> Path:
        path.write_text(f"                0x00401000                {symbol}\n", encoding="utf-8")
        return path

    def _obligation(self, out: Path, obligation_id: str) -> dict:
        obligations = json.loads((out / "obligations.json").read_text(encoding="utf-8"))["obligations"]
        for obligation in obligations:
            if obligation["id"] == obligation_id:
                return obligation
        self.fail(f"missing obligation {obligation_id}")

    def _write_passing_stage_b_validation(self, root: Path, target_name: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        original = self._write_pe(root / "original.exe", b"\xc3")
        candidate = self._write_pe(root / "candidate.exe", b"\xc3")
        original_map = self._write_map(root / "original.map", "tiny")
        candidate_map = self._write_map(root / "candidate.map", "tiny")
        decompiler = root / "original.ghidra.json"
        decompiler.write_text(
            json.dumps(
                {
                    "functions": [
                        {
                            "rva": 0x1000,
                            "rva_end": 0x1001,
                            "name": "tiny",
                            "signature": "int tiny(void)",
                            "decompiler": {
                                "status": "success",
                                "c": "int tiny(void) {\n  return 0;\n}",
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        skeleton_dir = root / "skeleton"
        stage_b_generate_skeleton(
            original=original,
            decompiler_export=decompiler,
            target_name=target_name,
            source_language="c",
            implementation_mode="decompiled-c",
            out_dir=skeleton_dir,
        )
        functional_report = self._write_functional_report(
            root / "functional-report.json",
            target_name=target_name,
            original_binary=original,
            candidate_binary=candidate,
        )
        provenance = root / "candidate-provenance.json"
        provenance.write_text(
            json.dumps(
                {
                    "format": "stage-b-candidate-provenance-v1",
                    "target_name": target_name,
                    "skeleton_manifest_sha256": sha256_file(skeleton_dir / "manifest.json"),
                    "upstream_source_access": False,
                    "manual_behavioral_fixups": [],
                    "source_roots": [self._generated_source_root(skeleton_dir)],
                    "build": self._candidate_build(candidate),
                    "functional_tests": {
                        "status": "pass",
                        "report_sha256": sha256_file(functional_report),
                        "suites": [
                            {
                                "id": f"{target_name}-upstream-integration-tests",
                                "name": f"{target_name} upstream integration tests",
                                "status": "pass",
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        reference_block_map = root / "reference-block-map.json"
        reference_layout = root / "reference-layout-contract.json"
        reference_report = root / "reference-stage-a"
        reference_contract = root / "reference-contract.json"
        stage_a_generate_map(
            original=original,
            candidate=candidate,
            linker_map_original=original_map,
            linker_map_candidate=candidate_map,
            out=reference_block_map,
            layout_contract_out=reference_layout,
        )
        with _LeanCheckedMock():
            stage_a_validate(
                original=original,
                candidate=candidate,
                mapping=reference_block_map,
                model=STAGE_A_MODEL_ID,
                out=reference_report,
                layout_contract=reference_layout,
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=reference_block_map,
                validation_report=reference_report,
                layout_contract=reference_layout,
                out=reference_contract,
            )
            result = stage_b_validate_candidate(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=reference_contract,
                target_name=target_name,
                out=root / "validate",
            )
        self.assertEqual(result["status"], "pass")
        return root / "validate" / "stage-b.json"

    def _generated_source_root(self, skeleton_dir: Path) -> dict[str, str]:
        manifest = json.loads((skeleton_dir / "manifest.json").read_text(encoding="utf-8"))
        source = manifest["outputs"]["source"]
        return {
            "kind": "stage_b_generated_skeleton",
            "path": str(skeleton_dir / "manifest.json"),
            "source": source["path"],
            "source_sha256": source["sha256"],
        }

    def _fixed_up_source_root(self, skeleton_dir: Path, source_path: Path) -> dict[str, object]:
        manifest = json.loads((skeleton_dir / "manifest.json").read_text(encoding="utf-8"))
        source = manifest["outputs"]["source"]
        return {
            "kind": "stage_b_fixed_up_source",
            "path": str(source_path),
            "source": str(source_path),
            "source_sha256": sha256_file(source_path),
            "derived_from": source["path"],
            "derived_from_sha256": source["sha256"],
            "fixup_policy": "compile_and_structure_only",
            "behavioral_fixups": [],
        }

    def _candidate_build(self, candidate: Path) -> dict[str, str]:
        return {
            "target": "i686-w64-mingw32",
            "compiler": "test-cc",
            "output": candidate.name,
            "output_sha256": sha256_file(candidate),
        }

    def _functional_binary_binding(self, binary: Path | None) -> dict:
        if binary is None:
            return {"provided": False, "command_contains_path": False, "command": []}
        return {
            "provided": True,
            "path": str(binary),
            "exists": True,
            "sha256": sha256_file(binary),
            "size": binary.stat().st_size,
            "command_contains_path": True,
            "command": ["wine", str(binary)],
        }

    def _stream_artifact(self, path: Path) -> dict:
        data = path.read_bytes()
        return {
            "path": str(path),
            "sha256": sha256_bytes(data),
            "bytes": len(data),
            "preview": data[:4096].decode("utf-8", errors="replace"),
        }

    def _assert_pid_file_dead(self, pid_file: Path) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if not pid_file.exists():
                time.sleep(0.05)
                continue
            pid = int(pid_file.read_text(encoding="utf-8"))
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            proc_stat = Path(f"/proc/{pid}/stat")
            if proc_stat.exists():
                fields = proc_stat.read_text(encoding="utf-8", errors="replace").split()
                if len(fields) >= 3 and fields[2] == "Z":
                    return
            time.sleep(0.05)
        self.fail(f"timed-out child process is still alive: {pid_file}")

    def _write_functional_report(
        self,
        path: Path,
        *,
        target_name: str,
        upstream_suite: bool = True,
        status: str = "pass",
        suite_id: str | None = None,
        suite_name: str | None = None,
        suite_kind: str = "upstream_integration",
        suite_scope: str = "full",
        required_suite_ids: list[str] | None = None,
        original_binary: Path | None = None,
        candidate_binary: Path | None = None,
    ) -> Path:
        canonical_suite_id = suite_id or f"{target_name}-upstream-integration-tests"
        canonical_suite_name = suite_name or f"{target_name} upstream integration tests"
        case_ids = ["identity"]
        case_manifest = [
            {
                "id": "identity",
                "args": [],
                "stdin_sha256": sha256_bytes(b""),
                "env_sha256": sha256_bytes(b"{}"),
                "timeout_seconds": 30.0,
                "candidate_timeout_seconds": 30.0,
                "expected": {"returncode": 0, "stdout": "", "stderr": ""},
            }
        ]
        suite_hash_payload = {
            "target_name": target_name,
            "suite_id": canonical_suite_id,
            "suite_name": canonical_suite_name,
            "case_ids": case_ids,
        }
        suite_sha256 = sha256_bytes(json.dumps(suite_hash_payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        case_manifest_sha256 = sha256_bytes(json.dumps(case_manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        payload = {
            "format": "stage-b-functional-report-v1",
            "runner": {
                "name": "stage-b-run-functional-suite",
                "report_format": "stage-b-functional-report-v1",
            },
            "status": status,
            "target_name": target_name,
            "suite_sha256": suite_sha256,
            "suite_case_manifest_sha256": case_manifest_sha256,
            "suite_id": canonical_suite_id,
            "suite_name": canonical_suite_name,
            "suite_kind": suite_kind,
            "upstream_suite": upstream_suite,
            "oracle": {"kind": "expected_output", "original_runtime_observations": False},
            "commands": {"candidate": [str(candidate_binary)] if candidate_binary is not None else []},
            "counts": {"cases": 1, "passed": 1 if status == "pass" else 0, "failed": 0 if status == "pass" else 1},
            "case_manifest": case_manifest,
            "cases": [
                {
                    "id": "identity",
                    "status": status,
                    "expected": {"returncode": 0, "stdout": "", "stderr": ""},
                    "expectation": {
                        "status": status,
                        "expected_returncode": 0,
                        "actual_returncode": 0 if status == "pass" else 1,
                        "actual_timed_out": False,
                    },
                    "candidate": {"returncode": 0 if status == "pass" else 1, "timed_out": False},
                    "mismatch": None if status == "pass" else {"fields": ["returncode"]},
                }
            ],
            "coverage": {
                "suite_id": canonical_suite_id,
                "suite_kind": suite_kind,
                "suite_scope": suite_scope,
                "source": f"{canonical_suite_name} fixture",
                "source_kind": "upstream_integration_suite",
                "source_sha256": sha256_bytes(f"{canonical_suite_name} fixture".encode("utf-8")),
                "source_revision": "fixture",
                "materialized_by": STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
                "suite_sha256": suite_sha256,
                "suite_case_manifest_sha256": case_manifest_sha256,
                "required_suite_ids": required_suite_ids if required_suite_ids is not None else [canonical_suite_id],
                "case_count": 1,
                "case_ids": case_ids,
                "case_ids_sha256": sha256_bytes(json.dumps(case_ids, separators=(",", ":")).encode("utf-8")),
            },
        }
        if original_binary is not None or candidate_binary is not None:
            payload["binary_bindings"] = {
                "candidate": self._functional_binary_binding(candidate_binary),
            }
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path


def _pe32_export_dll_image() -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    image_base = 0x400000
    text_rva = 0x1000
    edata_rva = 0x2000
    text_raw = 0x200
    code = b"\xc3".ljust(0x10, b"\x90") + b"\xc3"
    text_raw_size = _align(len(code), file_alignment)
    edata_raw = text_raw + text_raw_size
    edata_raw_size = 0x200
    size_of_image = _align(edata_rva + edata_raw_size, section_alignment)

    edata = bytearray(edata_raw_size)
    dll_name_rva = edata_rva + 0x80
    eat_rva = edata_rva + 0x40
    names_rva = edata_rva + 0x50
    ordinals_rva = edata_rva + 0x60
    jq_init_name_rva = edata_rva + 0x90
    jv_parse_name_rva = edata_rva + 0xA0
    struct.pack_into(
        "<IIHHIIIIIII",
        edata,
        0,
        0,
        0,
        0,
        0,
        dll_name_rva,
        1,
        2,
        2,
        eat_rva,
        names_rva,
        ordinals_rva,
    )
    struct.pack_into("<II", edata, 0x40, text_rva, text_rva + 0x10)
    struct.pack_into("<II", edata, 0x50, jq_init_name_rva, jv_parse_name_rva)
    struct.pack_into("<HH", edata, 0x60, 0, 1)
    edata[0x80 : 0x80 + len("libjq-1.dll") + 1] = b"libjq-1.dll\0"
    edata[0x90 : 0x90 + len("jq_init") + 1] = b"jq_init\0"
    edata[0xA0 : 0xA0 + len("jv_parse") + 1] = b"jv_parse\0"

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x014C,
        2,
        0,
        0,
        0,
        224,
        0x210F,
    )
    optional_prefix = struct.pack(
        "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
        0x10B,
        0,
        0,
        text_raw_size,
        edata_raw_size,
        0,
        text_rva,
        text_rva,
        edata_rva,
        image_base,
        section_alignment,
        file_alignment,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = bytearray(optional_prefix + (b"\0" * (16 * 8)))
    struct.pack_into("<II", optional, len(optional_prefix), edata_rva, 0xB0)
    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        len(code),
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    edata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".edata\0\0",
        edata_raw_size,
        edata_rva,
        edata_raw_size,
        edata_raw,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + text_section + edata_section
    headers = headers.ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0") + bytes(edata)


def _pe32plus_image(code: bytes) -> bytes:
    file_alignment = 0x200
    section_alignment = 0x1000
    headers_size = 0x200
    text_rva = 0x1000
    text_raw = 0x200
    text_raw_size = _align(len(code), file_alignment)
    text_virtual_size = len(code)
    size_of_image = _align(text_rva + text_virtual_size, section_alignment)

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,
        1,
        0,
        0,
        0,
        240,
        0x022F,
    )
    optional_prefix = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        0,
        0,
        text_raw_size,
        0,
        0,
        text_rva,
        text_rva,
        0x140000000,
        section_alignment,
        file_alignment,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        headers_size,
        0,
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional = optional_prefix + (b"\0" * (16 * 8))
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        text_virtual_size,
        text_rva,
        text_raw_size,
        text_raw,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    headers = bytes(dos) + b"PE\0\0" + coff + optional + section
    headers = headers.ljust(headers_size, b"\0")
    return headers + code.ljust(text_raw_size, b"\0")


def _align(value: int, alignment: int) -> int:
    return ((value + alignment - 1) // alignment) * alignment
