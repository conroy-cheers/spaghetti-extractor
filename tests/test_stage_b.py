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

from spaghetti_extractor.relational.mapping import stage_a_generate_map
from spaghetti_extractor.relational.reference_contract import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_export_reference_contract,
)
from spaghetti_extractor.stage_b import (
    STAGE_B_PROOF_RULE,
    STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
    stage_b_diff_delta,
    stage_b_explain_delta,
    stage_b_extract_candidate_crash,
    stage_b_export_decompiler,
    stage_b_validate_candidate,
    _stage_b_abi_coverage_gap_items,
    _count_by_evidence_source,
    _stage_b_delta_repair_items,
    _stage_b_semantic_contract_repair_items,
)
from spaghetti_extractor.stage_b_functional import stage_b_materialize_upstream_suite, stage_b_run_functional_suite
from spaghetti_extractor.stage_b_provenance import stage_b_generate_candidate_provenance
from spaghetti_extractor.stage_b_skeleton import (
    _decompiled_c_contract_direct_call_target_is_asm_linkable,
    _decompiled_c_contract_flow_call_lines,
    _decompiled_c_section_gap_callsite_is_asm_anchorable,
    _decompiled_c_section_gap_target_symbols,
    _render_decompiled_c_source,
    _render_decompiled_c_source as _render_skeleton_decompiled_c_source,
    _skeleton_source_map,
    stage_b_generate_link_roots,
    stage_b_generate_skeleton,
)
from spaghetti_extractor.util import sha256_bytes, sha256_file
from contract_fixtures import write_relational_report
from pe_fixtures import pe32_image as _pe32_image
from pe_fixtures import pe32_import_image as _pe32_import_image


class StageBTests(unittest.TestCase):
    def test_stage_b_import_does_not_load_stage_a_prover(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "import spaghetti_extractor.stage_b; "
                    "print('stage_a_loaded=' + str('spaghetti_extractor.stage_a' in sys.modules)); "
                    "print('stage_binary_loaded=' + str('spaghetti_extractor.stage_binary' in sys.modules))"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertIn("stage_a_loaded=False", proc.stdout)
        self.assertIn("stage_binary_loaded=True", proc.stdout)

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

    def test_generate_skeleton_contract_guided_c_allows_partial_ugly_c_anchors(self):
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
                implementation_mode="contract-guided-c",
                out_dir=out,
            )

            self.assertEqual(result["status"], "generated")
            self.assertEqual(result["implementation_mode"], "contract-guided-c")
            self.assertEqual(result["implementation_recovery"]["generated_source_kind"], "contract_guided_c_partial")
            self.assertFalse(result["implementation_recovery"]["source_implements_behavior"])
            source = (out / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract placeholder", source)
            self.assertEqual(result["source_map"]["functions"][0]["function"], "tiny")

    def test_contract_guided_c_uses_stage_a_semantic_transfer_bytecode_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex("8b 44 24 04 c3")
            original = self._write_pe(root / "jq.exe", body)
            transfer = {
                "format": "stage-a-semantic-transfer-contract-v1",
                "id": "semantic-transfer:arg_echo-0000",
                "function": "arg_echo",
                "block_id": "arg_echo-0000",
                "original": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
                "outcome": {"kind": "return"},
                "instructions": [
                    {
                        "bytes": "8b442404",
                        "mnemonic": "mov",
                        "op_str": "eax, dword ptr [esp + 4]",
                        "rva": 0x1000,
                        "size": 4,
                    },
                    {"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1004, "size": 1},
                ],
            }
            (root / "semantic-transfer-contracts.jsonl").write_text(json.dumps(transfer) + "\n", encoding="utf-8")
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "arg_echo",
                                "original": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
                                "block_ids": ["arg_echo-0000"],
                            }
                        ],
                    }
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided bytecode: contiguous no-call semantic-transfer body", source)
            self.assertIn('".byte 0x8b, 0x44, 0x24, 0x04, 0xc3"', source)
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            self.assertEqual(functions[0]["reference_contract"]["contract_bytecode"]["status"], "reimplementable")
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["arg_echo"]["source_kind"], "generated_contract_guided_bytecode")
            self.assertIn("stage-a-unit-contract-sidecars", result["source_policy"]["allowed_inputs"])

    def test_contract_guided_c_embeds_internal_section_gap_transfers_in_owner_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex("e8 1b 00 00 00 eb 00 c3") + (b"\0" * 0x18) + b"\xc3"
            original = self._write_pe(root / "jq.exe", body)
            transfers = [
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:parent-0000",
                    "function": "parent",
                    "block_id": "parent-0000",
                    "original": {"rva_start": 0x1000, "rva_end": 0x1007, "size": 7},
                    "outcome": {"kind": "jump", "target_rva": 0x1007},
                    "instructions": [
                        {"bytes": "e81b000000", "mnemonic": "call", "op_str": "0x401020", "rva": 0x1000, "size": 5},
                        {"bytes": "eb00", "mnemonic": "jmp", "op_str": "0x401007", "rva": 0x1005, "size": 2},
                    ],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:section-gap--text-0001",
                    "function": "section-gap--text-0001",
                    "block_id": "section-gap--text-0001",
                    "original": {"rva_start": 0x1007, "rva_end": 0x1008, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1007, "size": 1}],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:callee-0000",
                    "function": "callee",
                    "block_id": "callee-0000",
                    "original": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1020, "size": 1}],
                },
            ]
            (root / "semantic-transfer-contracts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in transfers),
                encoding="utf-8",
            )
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "parent",
                                "original": {"rva_start": 0x1000, "rva_end": 0x1008, "size": 8},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x1008, "size": 8},
                                "block_ids": ["parent-0000", "section-gap--text-0001"],
                            },
                            {
                                "name": "callee",
                                "original": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                                "candidate": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                                "block_ids": ["callee-0000"],
                            },
                        ],
                    },
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "parent",
                                    "blocks": [{"block_id": "parent-0000", "rva_start": 0x1000, "rva_end": 0x1007}],
                                    "callsites": [
                                        {
                                            "id": "callsite:parent-0000:1000",
                                            "instruction": {
                                                "rva": 0x1000,
                                                "size": 5,
                                                "bytes": "e81b000000",
                                                "mnemonic": "call",
                                                "op_str": "0x401020",
                                            },
                                            "target": {"kind": "direct", "target_rva": 0x1020},
                                            "argument_inventory": {
                                                "argument_count": 0,
                                                "calling_convention": "cdecl_or_stdcall_stack",
                                                "stack_args": [],
                                            },
                                        }
                                    ],
                                },
                                {
                                    "name": "section-gap--text-0001",
                                    "blocks": [
                                        {
                                            "block_id": "section-gap--text-0001",
                                            "rva_start": 0x1007,
                                            "rva_end": 0x1008,
                                        }
                                    ],
                                    "callsites": [],
                                },
                                {
                                    "name": "callee",
                                    "blocks": [{"block_id": "callee-0000", "rva_start": 0x1020, "rva_end": 0x1021}],
                                    "callsites": [],
                                },
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
            self.assertIn("Stage B embedded section-gap label: stage_b_contract_section_gap__text_0001", source)
            self.assertIn(".Lstageb_parent_1007:", source)
            self.assertNotIn(".globl _stage_b_contract_section_gap__text_0001", source)
            self.assertNotIn("_stage_b_contract_section_gap__text_0001:", source)
            self.assertNotIn(
                "/* original RVA 0x1007, size 1, name stage_b_contract_section_gap__text_0001 */",
                source,
            )
            self.assertEqual(source.count("Stage B embedded section-gap label: stage_b_contract_section_gap__text_0001"), 1)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["parent"]["source_kind"], "generated_contract_guided_flow")
            self.assertEqual(
                by_function["stage_b_contract_section_gap__text_0001"]["source_kind"],
                "generated_contract_guided_flow",
            )

    def test_contract_guided_bytecode_fills_verified_stage_a_padding_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex("c3 90 90 90 31 c0 c3")
            original = self._write_pe(root / "jq.exe", body)
            transfers = [
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:padded-0000",
                    "function": "padded",
                    "block_id": "padded-0000",
                    "original": {"rva_start": 0x1000, "rva_end": 0x1001, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1000, "size": 1}],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:padded-0001",
                    "function": "padded",
                    "block_id": "padded-0001",
                    "original": {"rva_start": 0x1004, "rva_end": 0x1007, "size": 3},
                    "outcome": {"kind": "return"},
                    "instructions": [
                        {"bytes": "31c0", "mnemonic": "xor", "op_str": "eax, eax", "rva": 0x1004, "size": 2},
                        {"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1006, "size": 1},
                    ],
                },
            ]
            (root / "semantic-transfer-contracts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in transfers),
                encoding="utf-8",
            )
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "padded",
                                "original": {"rva_start": 0x1000, "rva_end": 0x1007, "size": 7},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x1007, "size": 7},
                                "block_ids": ["padded-0000", "padded-0001"],
                            }
                        ],
                    },
                    "padding_alignment": {
                        "status": "satisfied",
                        "obligations": [
                            {
                                "id": "waiver:original-padding-1001-1004:original:1001-1004",
                                "status": "waived_noncode",
                                "checks": [
                                    {
                                        "binary": "original",
                                        "status": "verified",
                                        "rva_start": 0x1001,
                                        "rva_end": 0x1004,
                                        "bytes_sha256": sha256_bytes(bytes.fromhex("909090")),
                                        "bytes_hex": "909090",
                                    }
                                ],
                            }
                        ],
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn('".byte 0xc3, 0x90, 0x90, 0x90, 0x31, 0xc0, 0xc3"', source)
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            bytecode = functions[0]["reference_contract"]["contract_bytecode"]
            self.assertEqual(bytecode["status"], "reimplementable")
            self.assertEqual(bytecode["padding_chunks"], 1)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["padded"]["source_kind"], "generated_contract_guided_bytecode")

    def test_contract_guided_c_uses_section_gap_semantic_transfer_bytecode_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex("8b 44 24 04 c3 c3")
            original = self._write_pe(root / "jq.exe", body)
            transfer = {
                "format": "stage-a-semantic-transfer-contract-v1",
                "id": "semantic-transfer:section-gap--text-0000",
                "function": "section-gap--text-0000",
                "block_id": "section-gap--text-0000",
                "original": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
                "outcome": {"kind": "return"},
                "instructions": [
                    {
                        "bytes": "8b442404",
                        "mnemonic": "mov",
                        "op_str": "eax, dword ptr [esp + 4]",
                        "rva": 0x1000,
                        "size": 4,
                    },
                    {"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1004, "size": 1},
                ],
            }
            (root / "semantic-transfer-contracts.jsonl").write_text(json.dumps(transfer) + "\n", encoding="utf-8")
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "dummy",
                                "original": {"rva_start": 0x1005, "rva_end": 0x1006, "size": 1},
                                "candidate": {"rva_start": 0x1005, "rva_end": 0x1006, "size": 1},
                                "block_ids": ["dummy-0000"],
                            }
                        ],
                    },
                    "basic_blocks_and_cfg": {
                        "basic_blocks": [{"id": "section-gap--text-0000"}],
                    },
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "section-gap--text-0000",
                                    "blocks": [
                                        {
                                            "block_id": "section-gap--text-0000",
                                            "rva_start": 0x1000,
                                            "rva_end": 0x1005,
                                        }
                                    ],
                                    "callsites": [],
                                }
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            generated_name = "stage_b_contract_section_gap__text_0000"
            self.assertIn(f"uintptr_t __cdecl {generated_name}()", source)
            self.assertIn("Stage B contract-guided raw flow: exact section-gap bytes", source)
            self.assertIn('".byte 0x8b, 0x44, 0x24, 0x04, 0xc3"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_guided_raw_flow")
            self.assertIn("section-gap--text-0000", by_function[generated_name]["aliases"])

    def test_contract_guided_c_preserves_no_call_section_gap_branch_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex("39 c3 74 03 31 c0 c3 c3 c3")
            original = self._write_pe(root / "jq.exe", body)
            transfer = {
                "format": "stage-a-semantic-transfer-contract-v1",
                "id": "semantic-transfer:section-gap--text-0000",
                "function": "section-gap--text-0000",
                "block_id": "section-gap--text-0000",
                "original": {"rva_start": 0x1000, "rva_end": 0x1004, "size": 4},
                "outcome": {
                    "kind": "branch",
                    "true_target_rva": 0x1007,
                    "false_target_rva": 0x1004,
                },
                "instructions": [
                    {"bytes": "39c3", "mnemonic": "cmp", "op_str": "ebx, eax", "rva": 0x1000, "size": 2},
                    {"bytes": "7403", "mnemonic": "je", "op_str": "0x401007", "rva": 0x1002, "size": 2},
                ],
            }
            (root / "semantic-transfer-contracts.jsonl").write_text(json.dumps(transfer) + "\n", encoding="utf-8")
            section_gap_functions = [
                {
                    "name": "section-gap--text-0000",
                    "blocks": [{"block_id": "section-gap--text-0000", "rva_start": 0x1000, "rva_end": 0x1004}],
                    "callsites": [],
                },
                {
                    "name": "section-gap--text-0001",
                    "blocks": [{"block_id": "section-gap--text-0001", "rva_start": 0x1004, "rva_end": 0x1007}],
                    "callsites": [],
                },
                {
                    "name": "section-gap--text-0002",
                    "blocks": [{"block_id": "section-gap--text-0002", "rva_start": 0x1007, "rva_end": 0x1008}],
                    "callsites": [],
                },
            ]
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "dummy",
                                "original": {"rva_start": 0x1008, "rva_end": 0x1009, "size": 1},
                                "candidate": {"rva_start": 0x1008, "rva_end": 0x1009, "size": 1},
                                "block_ids": ["dummy-0000"],
                            }
                        ],
                    },
                    "basic_blocks_and_cfg": {
                        "basic_blocks": [{"id": item["name"]} for item in section_gap_functions],
                    },
                    "abi_callsites": {"original": {"functions": section_gap_functions}},
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            generated_name = "stage_b_contract_section_gap__text_0000"
            self.assertIn("Stage B contract-guided raw flow: exact section-gap bytes", source)
            self.assertIn('".byte 0x39, 0xc3, 0x74, 0x03"', source)
            self.assertNotIn('"je _stage_b_contract_section_gap__text_0002\\n\\t"', source)
            self.assertNotIn('"jmp _stage_b_contract_section_gap__text_0001"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_guided_raw_flow")
            self.assertIn("section-gap--text-0000", by_function[generated_name]["aliases"])

    def test_contract_guided_c_lowers_single_block_section_gap_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex(
                "c7042401000000"  # mov dword ptr [esp], 1
                "ffd0"  # call eax
                "eb00"  # jmp 0x40100b
                "c3"  # ret
                "c3"  # dummy function body
            )
            original = self._write_pe(root / "jq.exe", body)
            transfer = {
                "format": "stage-a-semantic-transfer-contract-v1",
                "id": "semantic-transfer:section-gap--text-0000",
                "function": "section-gap--text-0000",
                "block_id": "section-gap--text-0000",
                "original": {"rva_start": 0x1000, "rva_end": 0x100B, "size": 11},
                "outcome": {"kind": "jump", "target_rva": 0x100B},
                "instructions": [
                    {
                        "bytes": "c7042401000000",
                        "mnemonic": "mov",
                        "op_str": "dword ptr [esp], 1",
                        "rva": 0x1000,
                        "size": 7,
                    },
                    {"bytes": "ffd0", "mnemonic": "call", "op_str": "eax", "rva": 0x1007, "size": 2},
                    {"bytes": "eb00", "mnemonic": "jmp", "op_str": "0x40100b", "rva": 0x1009, "size": 2},
                ],
            }
            (root / "semantic-transfer-contracts.jsonl").write_text(json.dumps(transfer) + "\n", encoding="utf-8")
            section_gap_functions = [
                {
                    "name": "section-gap--text-0000",
                    "blocks": [{"block_id": "section-gap--text-0000", "rva_start": 0x1000, "rva_end": 0x100B}],
                    "callsites": [
                        {
                            "id": "callsite:section-gap--text-0000:1007",
                            "block_id": "section-gap--text-0000",
                            "instruction": {"rva": 0x1007},
                            "target": {"kind": "function_pointer", "operand": "eax", "status": "unresolved"},
                            "argument_inventory": {"argument_count": 1, "stack_args": []},
                        }
                    ],
                },
                {
                    "name": "section-gap--text-0001",
                    "blocks": [{"block_id": "section-gap--text-0001", "rva_start": 0x100B, "rva_end": 0x100C}],
                    "callsites": [],
                },
            ]
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "dummy",
                                "original": {"rva_start": 0x100C, "rva_end": 0x100D, "size": 1},
                                "candidate": {"rva_start": 0x100C, "rva_end": 0x100D, "size": 1},
                                "block_ids": ["dummy-0000"],
                            }
                        ],
                    },
                    "basic_blocks_and_cfg": {
                        "basic_blocks": [{"id": item["name"]} for item in section_gap_functions],
                    },
                    "abi_callsites": {"original": {"functions": section_gap_functions}},
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            generated_name = "stage_b_contract_section_gap__text_0000"
            self.assertIn("Stage B contract-guided raw flow: exact section-gap bytes", source)
            self.assertIn(
                '".byte 0xc7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00, 0xff, 0xd0, 0xeb, 0x00"',
                source,
            )
            self.assertNotIn('"jmp _stage_b_contract_section_gap__text_0001"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_guided_raw_flow")
            self.assertIn("section-gap--text-0000", by_function[generated_name]["aliases"])

    def test_contract_guided_c_lowers_multiblock_direct_call_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex(
                "b801000000"  # mov eax, 1
                "e816000000"  # call 0x401020
                "85c0"        # test eax, eax
                "7400"        # je 0x40100e
                "c3"          # ret
                + ("90" * 0x11)
                + "c3"        # callee ret at RVA 0x1020
            )
            original = self._write_pe(root / "jq.exe", body)
            transfers = [
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_func-0000",
                    "function": "flow_func",
                    "block_id": "flow_func-0000",
                    "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
                    "outcome": {"kind": "fallthrough", "target_rva": 0x100A},
                    "instructions": [
                        {"bytes": "b801000000", "mnemonic": "mov", "op_str": "eax, 1", "rva": 0x1000, "size": 5},
                        {"bytes": "e816000000", "mnemonic": "call", "op_str": "0x401020", "rva": 0x1005, "size": 5},
                    ],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_func-0001",
                    "function": "flow_func",
                    "block_id": "flow_func-0001",
                    "original": {"rva_start": 0x100A, "rva_end": 0x100E, "size": 4},
                    "outcome": {
                        "kind": "branch",
                        "true_target_rva": 0x100E,
                        "false_target_rva": 0x100E,
                    },
                    "instructions": [
                        {"bytes": "85c0", "mnemonic": "test", "op_str": "eax, eax", "rva": 0x100A, "size": 2},
                        {"bytes": "7400", "mnemonic": "je", "op_str": "0x40100e", "rva": 0x100C, "size": 2},
                    ],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_func-0002",
                    "function": "flow_func",
                    "block_id": "flow_func-0002",
                    "original": {"rva_start": 0x100E, "rva_end": 0x100F, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x100E, "size": 1}],
                },
            ]
            (root / "semantic-transfer-contracts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in transfers),
                encoding="utf-8",
            )
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "flow_func",
                                "original": {"rva_start": 0x1000, "rva_end": 0x100F, "size": 15},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x100F, "size": 15},
                                "block_ids": ["flow_func-0000", "flow_func-0001", "flow_func-0002"],
                            },
                            {
                                "name": "callee",
                                "original": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                                "candidate": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                                "block_ids": ["callee-0000"],
                            },
                        ],
                    },
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "flow_func",
                                    "callsites": [
                                        {
                                            "id": "callsite:flow_func-0000:1005",
                                            "block_id": "flow_func-0000",
                                            "instruction": {"rva": 0x1005},
                                            "target": {"kind": "direct", "target_rva": 0x1020},
                                            "argument_inventory": {"argument_count": 0, "stack_args": []},
                                        }
                                    ],
                                }
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
            self.assertIn('".Lstageb_flow_func_1000:\\n\\t"', source)
            self.assertIn('"call _callee\\n\\t"', source)
            self.assertIn('"je .Lstageb_flow_func_100e\\n\\t"', source)
            self.assertNotIn('"jmp .Lstageb_flow_func_100e\\n\\t"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["flow_func"]["source_kind"], "generated_contract_guided_flow")

    def test_contract_guided_c_keeps_explicit_nonfallthrough_false_edge(self):
        functions = [
            {
                "name": "flow_func",
                "rva_start": 0x1000,
                "rva_end": 0x1006,
                "size": 6,
                "reference_contract": {
                    "semantic_transfer_bytecode": {
                        "transfers": [
                            {
                                "function": "flow_func",
                                "block_id": "flow_func-0000",
                                "rva_start": 0x1000,
                                "rva_end": 0x1004,
                                "outcome": {
                                    "kind": "branch",
                                    "true_target_rva": 0x1004,
                                    "false_target_rva": 0x1005,
                                },
                                "instructions": [
                                    {"bytes": "85c0", "mnemonic": "test", "op_str": "eax, eax", "rva": 0x1000, "size": 2},
                                    {"bytes": "7400", "mnemonic": "je", "op_str": "0x401004", "rva": 0x1002, "size": 2},
                                ],
                            },
                            {
                                "function": "flow_func",
                                "block_id": "flow_func-0001",
                                "rva_start": 0x1004,
                                "rva_end": 0x1005,
                                "outcome": {"kind": "return"},
                                "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1004, "size": 1}],
                            },
                            {
                                "function": "flow_func",
                                "block_id": "flow_func-0002",
                                "rva_start": 0x1005,
                                "rva_end": 0x1006,
                                "outcome": {"kind": "return"},
                                "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1005, "size": 1}],
                            },
                        ]
                    }
                },
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            allow_contract_bytecode=True,
        )

        self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
        self.assertIn('"je .Lstageb_flow_func_1004\\n\\t"', source)
        self.assertIn('"jmp .Lstageb_flow_func_1005\\n\\t"', source)

    def test_contract_guided_c_lowers_direct_import_thunk_flow_symbolically(self):
        functions = [
            {
                "name": "caller",
                "rva_start": 0x1000,
                "rva_end": 0x1006,
                "size": 6,
                "reference_contract": {
                    "semantic_transfer_bytecode": {
                        "transfers": [
                            {
                                "function": "caller",
                                "block_id": "caller-0000",
                                "rva_start": 0x1000,
                                "rva_end": 0x1006,
                                "outcome": {"kind": "return"},
                                "instructions": [
                                    {"bytes": "e8fb0f0000", "mnemonic": "call", "op_str": "0x402000", "rva": 0x1000, "size": 5},
                                    {"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1005, "size": 1},
                                ],
                            }
                        ]
                    },
                    "abi_callsites": [
                        {
                            "id": "callsite:caller-0000:1000",
                            "block_id": "caller-0000",
                            "instruction": {"bytes": "e8fb0f0000", "mnemonic": "call", "op_str": "0x402000", "rva": 0x1000, "size": 5},
                            "target": {"kind": "direct", "target_rva": 0x2000},
                            "argument_inventory": {"argument_count": 0, "stack_args": []},
                        }
                    ],
                },
            },
            {
                "name": "strlen",
                "rva_start": 0x2000,
                "rva_end": 0x2006,
                "size": 6,
                "linkage": {"kind": "import_thunk", "dll": "msvcrt.dll", "symbol": "strlen"},
            },
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            allow_contract_bytecode=True,
        )

        self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
        self.assertIn('"call _strlen\\n\\t"', source)
        self.assertNotIn('".byte 0xe8, 0xfb, 0x0f, 0x00, 0x00\\n\\t"', source)

    def test_contract_guided_c_lowers_section_gap_import_call_symbolically(self):
        functions = [
            {
                "name": "stage_b_contract_section_gap__text_0000",
                "rva_start": 0x1000,
                "rva_end": 0x1009,
                "size": 9,
                "reference_section_gap": {"name": "section-gap--text-0000"},
                "reference_contract": {
                    "semantic_transfer_bytecode": {
                        "transfers": [
                            {
                                "function": "section-gap--text-0000",
                                "block_id": "section-gap--text-0000",
                                "rva_start": 0x1000,
                                "rva_end": 0x1009,
                                "outcome": {"kind": "return"},
                                "instructions": [
                                    {"bytes": "6a01", "mnemonic": "push", "op_str": "1", "rva": 0x1000, "size": 2},
                                    {"bytes": "ff1550344100", "mnemonic": "call", "op_str": "dword ptr [0x413450]", "rva": 0x1002, "size": 6},
                                    {"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1008, "size": 1},
                                ],
                            }
                        ]
                    },
                    "abi_callsites": [
                        {
                            "id": "callsite:section-gap--text-0000:1002",
                            "block_id": "section-gap--text-0000",
                            "instruction": {"bytes": "ff1550344100", "mnemonic": "call", "op_str": "dword ptr [0x413450]", "rva": 0x1002, "size": 6},
                            "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "Sleep"},
                            "argument_inventory": {
                                "argument_count": 1,
                                "stack_args": [
                                    {"index": 0, "role": "immediate", "source": {"kind": "immediate", "value": 1}}
                                ],
                            },
                            "arguments": [{"kind": "immediate", "value": 1, "stack_offset": 0}],
                        }
                    ],
                },
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            allow_contract_bytecode=True,
        )

        self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
        self.assertIn('"call *__imp__Sleep@4\\n\\t"', source)
        self.assertNotIn("Stage B contract-guided raw flow: exact section-gap bytes", source)
        self.assertNotIn('".byte 0xff, 0x15, 0x50, 0x34, 0x41, 0x00\\n\\t"', source)

    def test_contract_guided_c_lowers_flow_branch_into_verified_padding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = (
                bytes.fromhex(
                    "85c0"  # test eax, eax
                    "7402"  # je 0x401006
                    "6690"  # verified alignment padding at false target
                    "e815000000"  # call 0x401020
                    "c3"  # ret
                )
                + (b"\x90" * (0x1020 - 0x100C))
                + b"\xc3"
            )
            original = self._write_pe(root / "jq.exe", body)
            transfers = [
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_pad-0000",
                    "function": "flow_pad",
                    "block_id": "flow_pad-0000",
                    "original": {"rva_start": 0x1000, "rva_end": 0x1004, "size": 4},
                    "outcome": {
                        "kind": "branch",
                        "true_target_rva": 0x1006,
                        "false_target_rva": 0x1004,
                    },
                    "instructions": [
                        {"bytes": "85c0", "mnemonic": "test", "op_str": "eax, eax", "rva": 0x1000, "size": 2},
                        {"bytes": "7402", "mnemonic": "je", "op_str": "0x401006", "rva": 0x1002, "size": 2},
                    ],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_pad-0001",
                    "function": "flow_pad",
                    "block_id": "flow_pad-0001",
                    "original": {"rva_start": 0x1006, "rva_end": 0x100C, "size": 6},
                    "outcome": {"kind": "return"},
                    "instructions": [
                        {"bytes": "e815000000", "mnemonic": "call", "op_str": "0x401020", "rva": 0x1006, "size": 5},
                        {"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x100B, "size": 1},
                    ],
                },
            ]
            (root / "semantic-transfer-contracts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in transfers),
                encoding="utf-8",
            )
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "flow_pad",
                                "original": {"rva_start": 0x1000, "rva_end": 0x100C, "size": 12},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x100C, "size": 12},
                                "block_ids": ["flow_pad-0000", "flow_pad-0001"],
                            },
                            {
                                "name": "callee",
                                "original": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                                "candidate": {"rva_start": 0x1020, "rva_end": 0x1021, "size": 1},
                                "block_ids": ["callee-0000"],
                            }
                        ],
                    },
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "flow_pad",
                                    "callsites": [
                                        {
                                            "id": "callsite:flow_pad-0001:1006",
                                            "block_id": "flow_pad-0001",
                                            "instruction": {"rva": 0x1006},
                                            "target": {"kind": "direct", "target_rva": 0x1020},
                                            "argument_inventory": {"argument_count": 0, "stack_args": []},
                                        }
                                    ],
                                }
                            ]
                        }
                    },
                    "padding_alignment": {
                        "status": "satisfied",
                        "obligations": [
                            {
                                "status": "waived_noncode",
                                "checks": [
                                    {
                                        "binary": "original",
                                        "status": "verified",
                                        "rva_start": 0x1004,
                                        "rva_end": 0x1006,
                                        "bytes_hex": "6690",
                                        "bytes_sha256": sha256_bytes(bytes.fromhex("6690")),
                                    }
                                ],
                            }
                        ],
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
            self.assertIn('"je .Lstageb_flow_pad_1006\\n\\t"', source)
            self.assertNotIn('"jmp .Lstageb_flow_pad_1004\\n\\t"', source)
            self.assertIn('".Lstageb_flow_pad_1004:\\n\\t"', source)
            self.assertIn('".byte 0x66, 0x90\\n\\t"', source)
            self.assertIn('"call _callee\\n\\t"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["flow_pad"]["source_kind"], "generated_contract_guided_flow")

    def test_contract_guided_c_lowers_flow_indirect_call_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex(
                "8b442404"  # mov eax, dword ptr [esp + 4]
                "ffd0"  # call eax
                "c3"  # ret
            )
            original = self._write_pe(root / "jq.exe", body)
            transfers = [
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_indirect-0000",
                    "function": "flow_indirect",
                    "block_id": "flow_indirect-0000",
                    "original": {"rva_start": 0x1000, "rva_end": 0x1006, "size": 6},
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1006},
                    "instructions": [
                        {
                            "bytes": "8b442404",
                            "mnemonic": "mov",
                            "op_str": "eax, dword ptr [esp + 4]",
                            "rva": 0x1000,
                            "size": 4,
                        },
                        {"bytes": "ffd0", "mnemonic": "call", "op_str": "eax", "rva": 0x1004, "size": 2},
                    ],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:flow_indirect-0001",
                    "function": "flow_indirect",
                    "block_id": "flow_indirect-0001",
                    "original": {"rva_start": 0x1006, "rva_end": 0x1007, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x1006, "size": 1}],
                },
            ]
            (root / "semantic-transfer-contracts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in transfers),
                encoding="utf-8",
            )
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "flow_indirect",
                                "original": {"rva_start": 0x1000, "rva_end": 0x1007, "size": 7},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x1007, "size": 7},
                                "block_ids": ["flow_indirect-0000", "flow_indirect-0001"],
                            }
                        ],
                    },
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "flow_indirect",
                                    "callsites": [
                                        {
                                            "id": "callsite:flow_indirect-0000:1004",
                                            "block_id": "flow_indirect-0000",
                                            "instruction": {"rva": 0x1004},
                                            "target": {"kind": "function_pointer", "operand": "eax", "status": "unresolved"},
                                            "argument_inventory": {"argument_count": 0, "stack_args": []},
                                        }
                                    ],
                                }
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
            self.assertIn('".byte 0xff, 0xd0\\n\\t"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["flow_indirect"]["source_kind"], "generated_contract_guided_flow")

    def test_contract_guided_c_lowers_single_block_call_fallthrough_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex(
                "c7042401000000"  # mov dword ptr [esp], 1
                "ffd0"  # call eax
                "c3"  # dummy function body
            )
            original = self._write_pe(root / "jq.exe", body)
            transfer = {
                "format": "stage-a-semantic-transfer-contract-v1",
                "id": "semantic-transfer:section-gap--text-0000",
                "function": "section-gap--text-0000",
                "block_id": "section-gap--text-0000",
                "original": {"rva_start": 0x1000, "rva_end": 0x1009, "size": 9},
                "outcome": {"kind": "fallthrough", "target_rva": 0x1009},
                "instructions": [
                    {
                        "bytes": "c7042401000000",
                        "mnemonic": "mov",
                        "op_str": "dword ptr [esp], 1",
                        "rva": 0x1000,
                        "size": 7,
                    },
                    {"bytes": "ffd0", "mnemonic": "call", "op_str": "eax", "rva": 0x1007, "size": 2},
                ],
            }
            (root / "semantic-transfer-contracts.jsonl").write_text(json.dumps(transfer) + "\n", encoding="utf-8")
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "dummy",
                                "original": {"rva_start": 0x1009, "rva_end": 0x100A, "size": 1},
                                "candidate": {"rva_start": 0x1009, "rva_end": 0x100A, "size": 1},
                                "block_ids": ["dummy-0000"],
                            }
                        ],
                    },
                    "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0000"}]},
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "section-gap--text-0000",
                                    "blocks": [{"block_id": "section-gap--text-0000", "rva_start": 0x1000, "rva_end": 0x1009}],
                                    "callsites": [
                                        {
                                            "id": "callsite:section-gap--text-0000:1007",
                                            "block_id": "section-gap--text-0000",
                                            "instruction": {"rva": 0x1007},
                                            "target": {"kind": "function_pointer", "operand": "eax", "status": "unresolved"},
                                            "argument_inventory": {"argument_count": 0, "stack_args": []},
                                        }
                                    ],
                                }
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            generated_name = "stage_b_contract_section_gap__text_0000"
            self.assertIn("Stage B contract-guided raw flow: exact section-gap bytes", source)
            self.assertIn('".byte 0xc7, 0x04, 0x24, 0x01, 0x00, 0x00, 0x00, 0xff, 0xd0"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_guided_raw_flow")

    def test_contract_branch_target_prefers_import_symbol_over_generic_block_label(self):
        reference_contract = {
            "original": {"imports": [{"thunk_rva": 0x2000, "symbol": "free"}]},
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {"kind": "code", "original": {"rva_start": 0x2000, "rva_end": 0x2006}}
                    ]
                },
                "function_ranges": {
                    "functions": [
                        {
                            "name": "free",
                            "original": {"rva_start": 0x2000, "rva_end": 0x2006},
                            "candidate": {"rva_start": 0x3000, "rva_end": 0x3006},
                        }
                    ]
                },
            },
        }

        targets = _decompiled_c_section_gap_target_symbols(reference_contract, known_symbols=set())

        self.assertEqual(targets[0x2000], "free")

    def test_section_gap_direct_memory_indirect_callsite_is_anchorable_as_raw_bytes(self):
        callsite = {
            "instruction": {
                "bytes": "ff1590f54000",
                "mnemonic": "call",
                "op_str": "dword ptr [0x40f590]",
                "rva": 0x1007,
                "size": 6,
            },
            "target": {"kind": "direct", "target_rva": 0x4CB0},
            "arguments": [{"kind": "immediate", "stack_offset": 0, "value": 0}],
        }
        instruction = callsite["instruction"]

        self.assertTrue(
            _decompiled_c_section_gap_callsite_is_asm_anchorable(
                callsite,
                call_targets={},
                linkable_symbols=set(),
            )
        )
        self.assertEqual(
            _decompiled_c_contract_flow_call_lines(
                instruction,
                callsite=callsite,
                call_targets={},
                call_target_profiles={},
            ),
            [".byte 0xff, 0x15, 0x90, 0xf5, 0x40, 0x00"],
        )

    def test_contract_guided_flow_lowers_external_direct_call_symbolically(self):
        callsite = {
            "instruction": {
                "bytes": "e8c2af0000",
                "mnemonic": "call",
                "op_str": "0x40c3c0",
                "rva": 0x13F9,
                "size": 5,
            },
            "target": {"kind": "direct", "target_rva": 0xC3C0},
            "arguments": [{"kind": "immediate", "stack_offset": 0, "value": 31}],
        }

        self.assertEqual(
            _decompiled_c_contract_flow_call_lines(
                callsite["instruction"],
                callsite=callsite,
                call_targets={0xC3C0: "__amsg_exit"},
                call_target_profiles={"__amsg_exit": {}},
            ),
            ["call ___amsg_exit"],
        )

    def test_contract_guided_c_lowers_flow_indirect_jump_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            body = bytes.fromhex(
                "a334d04000"  # mov dword ptr [0x40d034], eax
                "83c42c"  # add esp, 0x2c
                "ffe0"  # jmp eax
                "c3"  # dummy function body
            )
            original = self._write_pe(root / "jq.exe", body)
            transfer = {
                "format": "stage-a-semantic-transfer-contract-v1",
                "id": "semantic-transfer:section-gap--text-0000",
                "function": "section-gap--text-0000",
                "block_id": "section-gap--text-0000",
                "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
                "outcome": {"kind": "indirect_jump", "target": {"op": "reg", "name": "eax", "width": 32}},
                "instructions": [
                    {
                        "bytes": "a334d04000",
                        "mnemonic": "mov",
                        "op_str": "dword ptr [0x40d034], eax",
                        "rva": 0x1000,
                        "size": 5,
                    },
                    {"bytes": "83c42c", "mnemonic": "add", "op_str": "esp, 0x2c", "rva": 0x1005, "size": 3},
                    {"bytes": "ffe0", "mnemonic": "jmp", "op_str": "eax", "rva": 0x1008, "size": 2},
                ],
            }
            (root / "semantic-transfer-contracts.jsonl").write_text(json.dumps(transfer) + "\n", encoding="utf-8")
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {"sha256": sha256_file(original)},
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "dummy",
                                "original": {"rva_start": 0x100A, "rva_end": 0x100B, "size": 1},
                                "candidate": {"rva_start": 0x100A, "rva_end": 0x100B, "size": 1},
                                "block_ids": ["dummy-0000"],
                            }
                        ],
                    },
                    "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0000"}]},
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "section-gap--text-0000",
                                    "blocks": [{"block_id": "section-gap--text-0000", "rva_start": 0x1000, "rva_end": 0x100A}],
                                    "callsites": [],
                                }
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            generated_name = "stage_b_contract_section_gap__text_0000"
            self.assertIn("Stage B contract-guided raw flow: exact section-gap bytes", source)
            self.assertIn("0xff, 0xe0", source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_guided_raw_flow")

    def test_contract_guided_c_lowers_resolved_jump_table_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            table_rva = 0x3000
            table_va = 0x400000 + table_rva
            dispatch = bytes.fromhex("83e101") + b"\xff\x24\x8d" + struct.pack("<I", table_va)
            body = dispatch + b"\xc3" + b"\xc3"
            original = self._write_pe(root / "jq.exe", body)
            switch_contract = {
                "evidence_status": "derived",
                "kind": "indirect_jump_table_candidate",
                "instruction": {
                    "bytes": "ff248d00304000",
                    "mnemonic": "jmp",
                    "op_str": "dword ptr [ecx*4 + 0x403000]",
                    "rva": 0x1003,
                    "size": 7,
                },
                "index_expression": {"base": None, "index": "ecx", "scale": 4, "disp": table_va},
                "table": {"rva_start": table_rva, "va_start": table_va, "entry_width": 4, "entries": 2},
                "table_bounds": {"lower": 0, "upper": 1, "entries": 2, "source": "and_immediate_mask"},
                "case_targets": [
                    {"entry_rva": table_rva, "entry_va": table_va, "index": 0, "target_rva": 0x100A, "target_va": 0x40100A},
                    {"entry_rva": table_rva + 4, "entry_va": table_va + 4, "index": 1, "target_rva": 0x100B, "target_va": 0x40100B},
                ],
                "default_target_rva": None,
            }
            transfers = [
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:dispatch-0000",
                    "function": "dispatch",
                    "block_id": "dispatch-0000",
                    "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
                    "outcome": {
                        "kind": "indirect_jump",
                        "target": {"op": "read", "width": 4},
                    },
                    "instructions": [
                        {"bytes": "83e101", "mnemonic": "and", "op_str": "ecx, 1", "rva": 0x1000, "size": 3},
                        {
                            "bytes": "ff248d00304000",
                            "mnemonic": "jmp",
                            "op_str": "dword ptr [ecx*4 + 0x403000]",
                            "rva": 0x1003,
                            "size": 7,
                        },
                    ],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:dispatch-0001",
                    "function": "dispatch",
                    "block_id": "dispatch-0001",
                    "original": {"rva_start": 0x100A, "rva_end": 0x100B, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x100A, "size": 1}],
                },
                {
                    "format": "stage-a-semantic-transfer-contract-v1",
                    "id": "semantic-transfer:dispatch-0002",
                    "function": "dispatch",
                    "block_id": "dispatch-0002",
                    "original": {"rva_start": 0x100B, "rva_end": 0x100C, "size": 1},
                    "outcome": {"kind": "return"},
                    "instructions": [{"bytes": "c3", "mnemonic": "ret", "op_str": "", "rva": 0x100B, "size": 1}],
                },
            ]
            (root / "semantic-transfer-contracts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in transfers),
                encoding="utf-8",
            )
            reference_contract = {
                "format": "stage-a-reference-contract-v1",
                "status": "pass",
                "model": "x86-pe32-env-v1",
                "original": {
                    "image_base": 0x400000,
                    "sha256": sha256_file(original),
                    "sections": [
                        {"name": ".text", "rva_start": 0x1000, "rva_end": 0x100C},
                        {"name": ".data", "rva_start": 0x2000, "rva_end": 0x2000},
                        {"name": ".rdata", "rva_start": table_rva, "rva_end": table_rva + 0x20},
                    ],
                },
                "constraints": {
                    "function_ranges": {
                        "status": "satisfied",
                        "functions": [
                            {
                                "name": "dispatch",
                                "original": {"rva_start": 0x1000, "rva_end": 0x100C, "size": 12},
                                "candidate": {"rva_start": 0x1000, "rva_end": 0x100C, "size": 12},
                                "block_ids": ["dispatch-0000", "dispatch-0001", "dispatch-0002"],
                            }
                        ],
                    },
                    "abi_callsites": {
                        "original": {
                            "functions": [
                                {
                                    "name": "dispatch",
                                    "blocks": [
                                        {"block_id": "dispatch-0000", "rva_start": 0x1000, "rva_end": 0x100A},
                                        {"block_id": "dispatch-0001", "rva_start": 0x100A, "rva_end": 0x100B},
                                        {"block_id": "dispatch-0002", "rva_start": 0x100B, "rva_end": 0x100C},
                                    ],
                                    "callsites": [],
                                    "switch_contracts": [switch_contract],
                                }
                            ]
                        }
                    },
                },
                "sidecars": {
                    "unit_contracts": {
                        "directory": ".",
                        "semantic_transfer_contracts": {"path": "semantic-transfer-contracts.jsonl"},
                    }
                },
            }
            reference_path = root / "reference_contract.json"
            reference_path.write_text(json.dumps(reference_contract), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                reference_contract=reference_path,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
            self.assertIn('"jmp *0x403000(,%ecx,4)\\n\\t"', source)
            self.assertIn('".section .rdata$000_stage_b_reference_rdata,\\"dr\\"\\n"', source)
            self.assertIn('"  .long .Lstageb_dispatch_100a\\n"', source)
            self.assertIn('"  .long .Lstageb_dispatch_100b\\n"', source)
            self.assertNotIn(".rdata$stage_b_jump_tables", source)
            self.assertNotIn('"cmpl $0x0, %ecx\\n\\t"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["dispatch"]["source_kind"], "generated_contract_guided_flow")

    def test_contract_guided_c_reimplements_small_jq_leaf_slices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parts = [
                ("__tlregdtor", bytes.fromhex("31 c0 c3")),
                ("_fpreset", bytes.fromhex("db e3 c3")),
                (
                    "_configthreadlocale",
                    bytes.fromhex("83 7c 24 04 01 74 06 b8 02 00 00 00 c3 b8 ff ff ff ff c3"),
                ),
                ("_get_invalid_parameter_handler", bytes.fromhex("a1 50 0a 41 00 c3")),
                ("_set_invalid_parameter_handler", bytes.fromhex("8b 44 24 04 87 05 50 0a 41 00 c3")),
                ("___mb_cur_max_func", bytes.fromhex("83 ec 0c e8 00 00 00 00 8b 00 83 c4 0c c3")),
                (
                    "__acrt_iob_func",
                    bytes.fromhex("83 ec 0c e8 00 00 00 00 8b 54 24 10 83 c4 0c c1 e2 05 01 d0 31 d2 c3"),
                ),
                (
                    "__freedtoa",
                    bytes.fromhex(
                        "8b 44 24 04 ba 01 00 00 00 8b 48 fc 83 e8 04 d3 e2 "
                        "89 48 04 89 50 08 89 44 24 04 e9 00 00 00 00"
                    ),
                ),
            ]
            code = bytearray()
            map_lines = []
            for name, body in parts:
                map_lines.append(f"                0x{0x401000 + len(code):08x}                {name}\n")
                code.extend(body)
            map_lines.append(f"                0x{0x401000 + len(code):08x}                sentinel\n")
            code.extend(b"\xc3")
            original = self._write_pe(root / "jq.exe", bytes(code))
            linker_map = root / "jq.map"
            linker_map.write_text("".join(map_lines), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided leaf: zero-return leaf", source)
            self.assertIn('"xorl %eax, %eax\\n\\t"', source)
            self.assertIn('"fninit\\n\\t"', source)
            self.assertIn("Stage B contract-guided leaf: single-argument branch leaf", source)
            self.assertIn("return *(volatile uintptr_t *)(uintptr_t)0x410a50U;", source)
            self.assertIn('"xchgl %eax, 0x410a50\\n\\t"', source)
            self.assertIn("extern uintptr_t __p___mb_cur_max(void);", source)
            self.assertIn('extern uintptr_t stage_b_msvcrt_iob_func(void) __asm__("___iob_func");', source)
            self.assertIn("((uintptr_t (__cdecl *)())__Bfree_D2A)((uintptr_t)base)", source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            for name, _body in parts:
                self.assertEqual(by_function[name]["source_kind"], "generated_contract_guided_leaf")
            self.assertEqual(by_function["sentinel"]["source_kind"], "generated_contract_placeholder")

    def test_contract_guided_c_reimplements_jq_tls_callback_slices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parts = [
                (
                    "__dyn_tls_dtor@12",
                    bytes.fromhex(
                        "83 ec 1c 8b 44 24 24 83 f8 03 74 14 85 c0 74 10 83 c4 1c 31 c0 31 d2 "
                        "c2 0c 00 8d 36 89 44 24 04 8b 54 24 28 8b 44 24 20 89 54 24 08 89 04 24 "
                        "e8 18 0a 00 00 83 c4 1c 31 c0 31 d2 c2 0c 00"
                    ),
                ),
                (
                    "__dyn_tls_init@12",
                    bytes.fromhex(
                        "53 83 ec 18 8b 44 24 24 83 3d 10 d0 40 00 02 74 0a c7 05 10 d0 40 00 "
                        "02 00 00 00 83 f8 02 74 10 83 f8 01 74 3b 83 c4 18 5b 31 c0 c2 0c 00"
                    ),
                ),
                (
                    "__mingw_TLScallback",
                    bytes.fromhex(
                        "83 ec 2c 8b 44 24 34 83 f8 02 0f 84 b8 00 00 00 0f 87 2a 00 00 00 "
                        "85 c0 74 42 a1 60 00 41 00 85 c0 0f 84 cd 00 00 00 c7 05 60 00 41 00 "
                        "01 00 00 00 b8 01 00 00 00 c3"
                    ),
                ),
            ]
            code = bytearray()
            map_lines = []
            for name, body in parts:
                map_lines.append(f"                0x{0x401000 + len(code):08x}                {name}\n")
                code.extend(body)
            original = self._write_pe(root / "jq.exe", bytes(code))
            linker_map = root / "jq.map"
            linker_map.write_text("".join(map_lines), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided callback: stdcall TLS destructor callback", source)
            self.assertIn("Stage B contract-guided callback: stdcall TLS initializer callback", source)
            self.assertIn("Stage B contract-guided callback: MinGW TLS callback dispatcher", source)
            self.assertIn('"ret $0xc\\n\\t"', source)
            self.assertIn('"call ___mingw_TLScallback\\n\\t"', source)
            self.assertIn('"call _stage_b_contract_section_gap__text_0135\\n\\t"', source)
            self.assertIn('"call *__imp__DeleteCriticalSection@4\\n\\t"', source)
            self.assertIn('"call *__imp__InitializeCriticalSection@4\\n\\t"', source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            for name, _body in parts:
                self.assertEqual(by_function[name]["source_kind"], "generated_contract_guided_callback")

    def test_contract_guided_c_reimplements_jq_indirect_crt_slices(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parts = [
                (
                    "__do_global_dtors",
                    bytes.fromhex(
                        "a1 00 d0 40 00 8b 00 85 c0 74 25 83 ec 0c 66 90 ff d0 a1 00 d0 40 00 "
                        "8d 50 04 8b 40 04 89 15 00 d0 40 00 85 c0 75 e9 83 c4 0c 31 c0 31 d2 "
                        "c3 90 31 c0 31 d2 c3"
                    ),
                ),
                (
                    "__do_global_ctors",
                    bytes.fromhex(
                        "53 83 ec 18 8b 1d 34 ff 40 00 83 fb ff 74 39 85 db 74 19 "
                        "2e 8d 74 26 00 2e 8d b4 26 00 00 00 00 ff 14 9d 34 ff 40 00 "
                        "83 eb 01 75 f4 c7 04 24 90 4b 40 00 e8 28 c8 ff ff 83 c4 18 "
                        "5b 31 c0 31 d2 c3 8d b4 26 00 00 00 00 31 c0 8d b6 00 00 00 00 "
                        "89 c3 83 c0 01 8b 14 85 34 ff 40 00 85 d2 75 f0 eb ad"
                    ),
                ),
                (
                    "__mingw_raise_matherr",
                    bytes.fromhex(
                        "83 ec 3c a1 50 00 41 00 dd 44 24 48 dd 44 24 50 dd 44 24 58 "
                        "85 c0 74 30 d9 ca 8b 54 24 40 dd 5c 24 18 dd 5c 24 20 "
                        "89 54 24 10 8b 54 24 44 dd 5c 24 28 89 54 24 14 8d 54 24 10 "
                        "89 14 24 ff d0 eb 0d 8d b4 26 00 00 00 00 dd d8 dd d8 dd d8 "
                        "83 c4 3c 31 c0 31 d2 c3"
                    ),
                ),
                (
                    "_gnu_exception_handler@4",
                    bytes.fromhex(
                        "53 83 ec 18 8b 5c 24 20 8b 03 8b 00 3d 93 00 00 c0 0f 84 c3 00 00 00 "
                        "77 5f 3d 1d 00 00 c0 74 6a 0f 87 aa 00 00 00 3d 05 00 00 c0 "
                        "75 33 c7 44 24 04 00 00 00 00 c7 04 24 0b 00 00 00 e8 ef 70 00 00 "
                        "83 f8 01 0f 84 16 01 00 00 85 c0 0f 85 ed 00 00 00"
                    ),
                ),
                (
                    "_initterm_e",
                    bytes.fromhex(
                        "56 53 83 ec 04 8b 5c 24 10 8b 74 24 14 39 f3 73 22 "
                        "8d b4 26 00 00 00 00 2e 8d b4 26 00 00 00 00 8b 03 85 c0 74 06 "
                        "ff d0 85 c0 75 09 83 c3 04 39 f3 72 ed 31 c0 83 c4 04 5b 5e c3"
                    ),
                ),
            ]
            code = bytearray()
            map_lines = []
            for name, body in parts:
                map_lines.append(f"                0x{0x401000 + len(code):08x}                {name}\n")
                code.extend(body)
            original = self._write_pe(root / "jq.exe", bytes(code))
            linker_map = root / "jq.map"
            linker_map.write_text("".join(map_lines), encoding="utf-8")

            result = stage_b_generate_skeleton(
                original=original,
                linker_map=linker_map,
                target_name="jq",
                source_language="c",
                implementation_mode="contract-guided-c",
                out_dir=root / "skeleton",
            )

            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("Stage B contract-guided indirect-call slice: global destructor function-pointer walker", source)
            self.assertIn("Stage B contract-guided indirect-call slice: global constructor function-pointer walker", source)
            self.assertIn("Stage B contract-guided indirect-call slice: matherr callback dispatcher", source)
            self.assertIn("Stage B contract-guided indirect-call slice: SEH signal callback dispatcher", source)
            self.assertIn("Stage B contract-guided indirect-call slice: CRT initializer function-pointer walker", source)
            self.assertIn('"call *%eax\\n\\t"', source)
            self.assertIn('"call *0x40ff34(,%ebx,4)\\n\\t"', source)
            self.assertIn('"call _signal\\n\\t"', source)
            self.assertIn('"ret $0x4\\n\\t"', source)
            self.assertNotIn("volatile uintptr_t stage_b_contract_fp", source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            for name, _body in parts:
                self.assertEqual(by_function[name]["source_kind"], "generated_contract_guided_indirect")
            functions = json.loads((root / "skeleton" / "functions.json").read_text(encoding="utf-8"))["functions"]
            ctors = next(item for item in functions if item["name"] == "__do_global_ctors")
            self.assertGreater(len(ctors["instructions"]), len(ctors["instruction_preview"]))
            self.assertEqual(ctors["instruction_count"], len(ctors["instructions"]))

    def test_source_map_does_not_anchor_import_thunk_to_prefixed_helper(self):
        source = "\n".join(
            [
                "/* original RVA 0xc3e0, size 6, name _lock */",
                "/* import thunk for _lock; body omitted so the candidate links to the original import. */",
                "",
                "/* original RVA 0xc240, size 112, name _lock_file */",
                "__attribute__((noinline, used))",
                "uintptr_t __cdecl _lock_file()",
                "{",
                "  /* Stage B contract placeholder for missing decompiler body at RVA 0xc240, size 112. */",
                "  _lock((uintptr_t)0);",
                "  return 0;",
                "}",
                "",
            ]
        )

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[
                {
                    "name": "_lock",
                    "aliases": ["_lock"],
                    "rva_start": 0xC3E0,
                    "rva_end": 0xC3E6,
                    "linkage": {"kind": "import_thunk", "symbol": "_lock"},
                    "instruction_count": 1,
                },
                {
                    "name": "_lock_file",
                    "aliases": ["_lock_file"],
                    "rva_start": 0xC240,
                    "rva_end": 0xC2B0,
                    "instruction_count": 1,
                },
            ],
            source_language="c",
            implementation_mode="contract-guided-c",
            runtime_entry_policy="bridge",
        )

        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["_lock"]["line_start"], 1)
        self.assertEqual(by_function["_lock"]["source_kind"], "omitted_import_thunk")
        self.assertEqual(by_function["_lock_file"]["line_start"], 6)
        self.assertEqual(by_function["_lock_file"]["source_kind"], "generated_contract_placeholder")

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

    def test_decompiled_skeleton_sources_reference_contract_and_emits_missing_decompiler_placeholders(self):
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
                implementation_mode="decompiled-c",
                out_dir=root / "skeleton",
            )

            self.assertEqual(result["reverse_engineering"]["function_source"], "stage_a_reference_contract")
            self.assertEqual(result["counts"]["functions"], 2)
            self.assertEqual(result["reference_contract_function_coverage"]["status"], "complete")
            self.assertEqual(result["reference_contract_function_coverage"]["counts"]["missing"], 0)
            recovery = result["implementation_recovery"]
            self.assertEqual(recovery["status"], "incomplete")
            self.assertFalse(recovery["source_implements_behavior"])
            self.assertIn("missing_decompiler_exports", recovery["blockers"])
            self.assertNotIn("missing_decompiler_code", recovery["blockers"])
            self.assertEqual(recovery["decompiler_coverage"]["counts"]["missing_decompiler_functions"], 1)
            self.assertEqual(recovery["decompiler_coverage"]["counts"]["missing_decompiler_code_functions"], 0)
            source = (root / "skeleton" / "src" / "jq_stage_b_skeleton.c").read_text(encoding="utf-8")
            self.assertIn("int first(void)", source)
            self.assertIn("uintptr_t __cdecl second()", source)
            self.assertIn("Stage B contract placeholder for missing decompiler body", source)
            by_function = {item["function"]: item for item in result["source_map"]["functions"]}
            self.assertEqual(by_function["second"]["source_kind"], "generated_contract_placeholder")

    def test_contract_guided_placeholders_use_unspecified_abi_forward_declarations(self):
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "caller",
                    "rva_start": 0x1000,
                    "rva_end": 0x1008,
                    "size": 8,
                    "instruction_count": 1,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl caller(void)\n{\n  return callee(1, 2);\n}",
                    },
                },
                {
                    "name": "callee",
                    "rva_start": 0x1010,
                    "rva_end": 0x1011,
                    "size": 1,
                    "instruction_count": 1,
                    "instruction_preview": [{"mnemonic": "ret", "op_str": "", "size": 1, "rva": 0x1010}],
                },
            ],
            runtime_entry_policy="bridge",
        )

        self.assertIn("uintptr_t __cdecl callee();", source)
        self.assertIn("uintptr_t __cdecl callee()\n{", source)
        self.assertNotIn("uintptr_t __cdecl callee(void)\n{", source)

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

    def test_generate_link_roots_keeps_generated_contract_and_reference_layout_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            linker_map = root / "jq.map"
            linker_map.write_text("                0x00401000                foo\n", encoding="utf-8")
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' "
                "'00000000 T _foo' "
                "'00000010 T _stage_b_contract_section_gap__text_0001' "
                "'00000000 D _stage_b_jq_reference_data' "
                "'00000000 R _stage_b_jq_reference_rdata'\n",
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
            self.assertEqual(result["counts"]["generated_layout_roots"], 3)
            self.assertEqual(
                result["generated_layout_root_symbols"],
                [
                    "_stage_b_contract_section_gap__text_0001",
                    "_stage_b_jq_reference_data",
                    "_stage_b_jq_reference_rdata",
                ],
            )
            self.assertEqual(
                result["linker_flags"],
                [
                    "-Wl,--undefined,_foo",
                    "-Wl,--undefined,_stage_b_contract_section_gap__text_0001",
                    "-Wl,--undefined,_stage_b_jq_reference_data",
                    "-Wl,--undefined,_stage_b_jq_reference_rdata",
                ],
            )

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

    def test_generate_link_roots_roots_reference_imports_not_present_as_functions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            reference_contract = root / "reference-contract.json"
            reference_contract.write_text(
                json.dumps(
                    {
                        "format": "stage-a-reference-contract-v1",
                        "original": {
                            "sha256": sha256_file(original),
                            "imports": [
                                {
                                    "dll": "kernel32.dll",
                                    "symbol": "TlsGetValue",
                                    "ordinal": None,
                                    "thunk_rva": 0x1234,
                                }
                            ],
                        },
                        "constraints": {
                            "function_ranges": {
                                "status": "satisfied",
                                "functions": [
                                    {
                                        "name": "foo",
                                        "original": {"rva_start": 0x1000, "rva_end": 0x1001},
                                    }
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            obj = root / "candidate.o"
            obj.write_bytes(b"not really coff")
            nm = root / "fake-nm"
            nm.write_text("#!/bin/sh\nprintf '%s\\n' '00000000 T _foo'\n", encoding="utf-8")
            nm.chmod(0o755)

            result = stage_b_generate_link_roots(
                original=original,
                reference_contract=reference_contract,
                object_file=obj,
                nm=str(nm),
                out=root / "roots",
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["counts"]["reference_import_roots"], 1)
            self.assertEqual(result["reference_import_roots"][0]["object_symbol"], "__imp__TlsGetValue@4")
            self.assertIn("-Wl,--undefined,__imp__TlsGetValue@4", result["import_thunk_linker_flags"])
            self.assertIn(
                "-Wl,--undefined,__imp__TlsGetValue@4\n",
                (root / "roots" / "import-thunk-root-flags.txt").read_text(encoding="utf-8"),
            )

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
                {"skeleton_function_not_emitted_as_text_symbol": 1},
            )
            missing = result["issues"][0]["details"]["functions"][0]
            self.assertEqual(missing["name"], "wmain")
            self.assertEqual(missing["skeleton"]["name"], "_wmain")
            self.assertEqual(missing["skeleton"]["representation"], "skeleton_function_not_emitted_as_text_symbol")

    def test_generate_link_roots_classifies_mingw_crt_owned_tls_helpers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            linker_map = root / "jq.map"
            linker_map.write_text("                0x00401000                __dyn_tls_init@12\n", encoding="utf-8")
            skeleton_functions = root / "functions.json"
            skeleton_functions.write_text(
                json.dumps(
                    {
                        "format": "stage-b-functions-v1",
                        "target_name": "jq",
                        "functions": [
                            {
                                "name": "___dyn_tls_init_12",
                                "aliases": ["__dyn_tls_init@12"],
                                "rva_start": 0x1000,
                                "rva_end": 0x1085,
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
            self.assertEqual(
                result["counts"]["missing_by_skeleton_representation"],
                {"runtime_entry_replaced_by_generated_bridge": 1},
            )
            missing = result["issues"][0]["details"]["functions"][0]
            self.assertEqual(missing["skeleton"]["representation"], "runtime_entry_replaced_by_generated_bridge")

    def test_generate_link_roots_emits_forced_roots_for_omitted_mingw_crt_support(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3" * 0x1BEC)
            linker_map = root / "jq.map"
            linker_map.write_text(
                "".join(
                    [
                        "                0x00401000                __mingw_pformat\n",
                        " .text$after    0x00401bec        0x0 synthetic.o\n",
                    ]
                ),
                encoding="utf-8",
            )
            skeleton_functions = root / "functions.json"
            skeleton_functions.write_text(
                json.dumps(
                    {
                        "format": "stage-b-functions-v1",
                        "target_name": "jq",
                        "functions": [
                            {
                                "name": "___mingw_pformat",
                                "aliases": ["__mingw_pformat"],
                                "rva_start": 0x1000,
                                "rva_end": 0x1BEC,
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
            self.assertEqual(result["counts"]["runtime_crt_roots"], 0)
            self.assertEqual(result["runtime_crt_linker_flags"], [])
            self.assertEqual(
                (root / "roots" / "runtime-crt-root-flags.txt").read_text(encoding="utf-8"),
                "",
            )
            self.assertEqual(result["counts"]["budgeted_runtime_crt_roots"], 0)
            self.assertEqual(result["budgeted_runtime_crt_linker_flags"], [])
            self.assertEqual(
                (root / "roots" / "budgeted-runtime-crt-root-flags.txt").read_text(encoding="utf-8"),
                "",
            )
            self.assertEqual(
                {root["contract_function"]: root["object_symbol"] for root in result["runtime_crt_roots"]},
                {},
            )
            self.assertEqual({root["reason"] for root in result["runtime_crt_roots"]}, set())

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

    def test_generate_link_roots_preserves_iob_func_alias_import_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_import_pe(root / "jq.exe", b"\xff\x25\x40\x20\x40\x00\x00\x00", "__p__iob")
            linker_map = root / "jq.map"
            linker_map.write_text("                0x00401000                __iob_func\n", encoding="utf-8")
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
            self.assertEqual(result["import_thunk_roots"][0]["contract_function"], "__iob_func")
            self.assertEqual(result["import_thunk_roots"][0]["symbol"], "__p__iob")
            self.assertEqual(result["import_thunk_linker_flags"], ["-Wl,--undefined,___iob_func"])
            self.assertEqual((root / "roots" / "import-thunk-root-flags.txt").read_text(encoding="utf-8"), "-Wl,--undefined,___iob_func\n")

    def test_export_decompiler_runs_ghidra_and_summarizes_completeness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "jq.exe", b"\xc3")
            script_path = root / "tools" / "ghidra"
            script_path.mkdir(parents=True)
            (script_path / "SpaghettiExtractorStageBExport.java").write_text("// test exporter\n", encoding="utf-8")
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

            with patch("spaghetti_extractor.stage_b.subprocess.run", side_effect=fake_run):
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
            self.assertEqual(command[command.index("-postScript") + 1], "SpaghettiExtractorStageBExport.java")
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
            (script_path / "SpaghettiExtractorStageBExport.java").write_text("// test exporter\n", encoding="utf-8")

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

            with patch("spaghetti_extractor.stage_b.subprocess.run", side_effect=fake_run):
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
            result = stage_b_validate_candidate(
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_manifest,
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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

            result = stage_b_validate_candidate(
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_manifest,
                candidate_provenance=root / "provenance" / "candidate-provenance.json",
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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

    def test_candidate_provenance_preserves_strict_layout_fallback_diagnostic(self):
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
            build_report = root / "link-report.json"
            build_report.write_text(
                json.dumps(
                    {
                        "format": "stage-b-decompiled-c-link-diagnostic-v1",
                        "status": "incomplete",
                        "layout_policy": "diagnostic_fallback",
                        "stage_a_layout_eligible": False,
                        "linker_flags": ["-municode", "-Wl,--section-start,.data=0x40d000"],
                        "strict_layout_link": {
                            "status": "incomplete",
                            "returncode": 1,
                            "stderr": "strict.stderr",
                        },
                        "diagnostic_layout_fallback": {
                            "status": "used",
                            "reason": "strict_stage_a_layout_link_failed",
                            "returncode": 0,
                            "stderr": "fallback.stderr",
                        },
                        "standalone_link_diagnostic": {
                            "status": "incomplete",
                            "returncode": 1,
                            "unresolved_reference_lines": 0,
                            "undefined_reference_samples": [],
                            "repair_plan": {
                                "status": "strict_layout_link_failed",
                                "next_action": "repair section layout before Stage A",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            generated = stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate=candidate,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                build_output="candidate.exe",
                build_report=build_report,
                out=root / "provenance",
            )

            report = generated["build"]["report"]
            self.assertEqual(report["layout_policy"], "diagnostic_fallback")
            self.assertFalse(report["stage_a_layout_eligible"])
            self.assertEqual(report["strict_layout_link"]["status"], "incomplete")
            self.assertEqual(report["diagnostic_layout_fallback"]["status"], "used")
            standalone = report["standalone_link_diagnostic"]
            self.assertEqual(standalone["status"], "incomplete")
            self.assertEqual(standalone["undefined_symbol_count"], 0)
            self.assertEqual(standalone["repair_plan"]["status"], "strict_layout_link_failed")
            self.assertEqual(standalone["repair_plan"]["next_action"], "repair section layout before Stage A")

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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=root / "provenance" / "candidate-provenance.json",
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in validation["issues"]}
            self.assertEqual(validation["status"], "incomplete")
            self.assertIn("functional_tests_not_passing", categories)
            self.assertIn("functional_test_report_failed", categories)
            self.assertTrue(validation["stage_a"]["gate"]["ran"])
            self.assertIn("functional_test_report_failed", validation["stage_a"]["gate"]["non_blocking_issue_categories"])
            self.assertTrue((root / "report" / "stage-a").exists())

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
            self.assertIn('"  .long ___p___winitenv - _stage_b_jq_import_anchor\\n"', source)
            self.assertIn('"  .long ___p__commode - _stage_b_jq_import_anchor\\n"', source)
            self.assertIn('"  .long ___p__fmode - _stage_b_jq_import_anchor\\n"', source)
            self.assertIn('"  .long ___set_app_type - _stage_b_jq_import_anchor\\n"', source)
            self.assertIn('"  .long __amsg_exit - _stage_b_jq_import_anchor\\n"', source)
            self.assertIn('"  .long __cexit - _stage_b_jq_import_anchor\\n"', source)
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
                                            "  (*(code *)__imp_____lc_codepage_func)();",
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
            self.assertIn('"  .long __imp__SetUnhandledExceptionFilter@4 - _stage_b_jq_import_anchor\\n"', source)
            self.assertNotIn("(void *)(uintptr_t)&SetUnhandledExceptionFilter,", source)
            self.assertIn("extern uintptr_t initterm();", source)
            self.assertIn("__attribute__((weak, noinline, used)) uintptr_t initterm() {", source)
            self.assertIn('__asm__ __volatile__("" : : : "memory");', source)
            self.assertIn(".text$stage_b_jq_layout_pad", source)
            self.assertIn(".fill 0,1,0x90", source)
            self.assertIn(".rdata$stage_b_jq_layout_anchor", source)
            self.assertIn('"  .long _stage_b_jq_layout_text_anchor - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn('"  .long _stage_b_jq_import_anchor - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn('"  .long _stage_b_jq_layout_data_tail - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn("stage_b_jq_layout_bss_anchor[2644]", source)
            self.assertIn("stage_b_jq_layout_data_tail[92]", source)
            self.assertIn("stage_b_jq_layout_tls_anchor[8]", source)
            self.assertIn(".idata$stage_b_jq_layout_pad", source)
            self.assertIn("_stage_b_jq_layout_idata_pad", source)
            self.assertNotIn('((void *)stage_b_jq_layout_data_tail)', source)
            self.assertIn("section(\".rdata$stage_b_jq_layout_pad\")", source)
            self.assertIn('"  .long _stage_b_jq_layout_rdata_anchor - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn('"  .long _stage_b_jq_layout_bss_anchor - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn('"  .long _stage_b_jq_layout_tls_anchor - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn('"  .long _stage_b_jq_layout_idata_pad - _stage_b_jq_layout_anchor\\n"', source)
            self.assertIn("stage_b_jq_layout_rdata_anchor[4672]", source)
            self.assertIn('((void *)stage_b_jq_layout_anchor)', source)
            self.assertNotIn('((void *)stage_b_jq_layout_text_anchor)', source)
            self.assertNotIn('((void *)stage_b_jq_layout_bss_anchor)', source)
            self.assertIn("__crt_atexit((void *)0);", source)
            self.assertNotIn("  atexit((void *)0);", source)
            self.assertIn('extern void * __imp_____lc_codepage_func __asm__("__imp_____lc_codepage_func");', source)
            self.assertNotIn("__attribute__((weak)) void * __imp_____lc_codepage_func;", source)
            self.assertIn('extern void * __imp____acrt_iob_func __asm__("__imp____acrt_iob_func");', source)
            self.assertIn("local_28.BaseAddress = __imp____acrt_iob_func;", source)
            self.assertIn("(*(code *)__imp____acrt_iob_func)(2);", source)
            self.assertNotIn("__attribute__((weak)) void * __imp____acrt_iob_func;", source)
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
            self.assertIn("__attribute__((weak, noinline, used)) uintptr_t _assign() {", source)
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

    def test_decompiled_c_renderer_preserves_dtoa_allocator_return_value(self):
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
                                "name": "___Balloc_D2A",
                                "signature": "void __cdecl ___Balloc_D2A(int param_1)",
                                "decompiler": {
                                    "status": "success",
                                    "c": "\n".join(
                                        [
                                            "void __cdecl ___Balloc_D2A(int param_1)",
                                            "{",
                                            "  undefined4 *puVar1;",
                                            "  puVar1 = (undefined4 *)malloc(32);",
                                            "  if (puVar1 == (undefined4 *)0x0) {",
                                            "    return;",
                                            "  }",
                                            "  puVar1[1] = param_1;",
                                            "  puVar1[2] = 1 << (param_1 & 0x1f);",
                                            "  puVar1[4] = 0;",
                                            "  puVar1[3] = 0;",
                                            "  return;",
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
            self.assertIn("uintptr_t __cdecl ___Balloc_D2A(int param_1)", source)
            self.assertIn("  return (uintptr_t)puVar1;", source)
            self.assertIn("    return 0;", source)
            self.assertNotIn("  puVar1[3] = 0;\n  return 0;", source)
            i2b_source = _render_decompiled_c_source(
                target_name="jq",
                functions=[
                    {
                        "name": "___i2b_D2A",
                        "rva_start": 0xAEF0,
                        "rva_end": 0xAF9B,
                        "size": 0xAB,
                        "decompiler": {
                            "status": "success",
                            "code": "\n".join(
                                [
                                    "void __cdecl ___i2b_D2A(undefined4 param_1)",
                                    "{",
                                    "  undefined4 *puVar1;",
                                    "  puVar1[3] = 0;",
                                    "  puVar1[4] = 1;",
                                    "  puVar1[5] = param_1;",
                                    "  return;",
                                    "}",
                                ]
                            ),
                        },
                    }
                ],
            )
            self.assertIn("uintptr_t __cdecl ___i2b_D2A(undefined4 param_1)", i2b_source)
            self.assertIn("  return (uintptr_t)puVar1;", i2b_source)
            self.assertNotIn("  puVar1[5] = param_1;\n  return 0;", i2b_source)

    def test_decompiled_c_placeholder_preserves_reference_contract_direct_callsites(self):
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___Balloc_D2A",
                    "aliases": ["__Balloc_D2A", "___Balloc_D2A"],
                    "rva_start": 0xACA0,
                    "rva_end": 0xAD7F,
                    "size": 0xDF,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t __cdecl ___Balloc_D2A(int param_1)",
                                "{",
                                "  return (uintptr_t)param_1;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "__d2b_D2A",
                    "aliases": ["__d2b_D2A"],
                    "rva_start": 0xB830,
                    "rva_end": 0xB9DE,
                    "size": 0x1AE,
                    "reference_contract": {
                        "abi_callsites": [
                            {
                                "id": "callsite:__d2b_D2A-0000:b846",
                                "instruction": {"rva": 0xB846},
                                "target": {"kind": "direct", "target_rva": 0xACA0},
                                "arguments": [{"kind": "immediate", "value": 1}],
                            }
                        ]
                    },
                },
            ],
        )

        self.assertIn("Stage A direct-call anchor: callsite:__d2b_D2A-0000:b846 at RVA 0xb846", source)
        self.assertIn("___Balloc_D2A(1);", source)
        self.assertNotIn("stage_b_contract_anchor ^= (uintptr_t)0xb846;", source)

    def test_decompiled_c_placeholder_anchors_section_gap_symbol_alias_callsites(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0142",
                            "symbol_aliases": {
                                "original": ["_do_get_path_info", "do_get_path_info"],
                                "candidate": ["_do_get_path_info", "do_get_path_info"],
                            },
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0142",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0142",
                                        "rva_start": 0x5C20,
                                        "rva_end": 0x5C61,
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "basename",
                    "aliases": ["basename"],
                    "rva_start": 0x5F70,
                    "rva_end": 0x5FE0,
                    "size": 0x70,
                    "reference_contract": {
                        "abi_callsites": [
                            {
                                "id": "callsite:basename-0004:5f98",
                                "instruction": {"rva": 0x5F98},
                                "target": {"kind": "direct", "target_rva": 0x5C20},
                                "arguments": [],
                            }
                        ]
                    },
                }
            ],
            external_function_names=["do_get_path_info"],
            reference_contract_payload=reference_contract,
        )

        self.assertIn("Stage A direct-call anchor: callsite:basename-0004:5f98 at RVA 0x5f98", source)
        self.assertIn("do_get_path_info();", source)
        self.assertNotIn("stage_b_contract_anchor ^= (uintptr_t)0x5f98;", source)

    def test_decompiled_c_renderer_materializes_jq_reference_data_sections(self):
        reference_contract = {
            "original": {
                "image_base": 0x400000,
                "sections": [
                    {"name": ".data", "rva_start": 0xD000, "rva_end": 0xD05C},
                    {"name": ".rdata", "rva_start": 0xE000, "rva_end": 0xE100},
                ],
            },
            "constraints": {
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "caller",
                                "callsites": [
                                    {
                                        "instruction": {
                                            "mnemonic": "call",
                                            "op_str": "dword ptr [0x40e020]",
                                            "rva": 0x1010,
                                        },
                                        "target": {"kind": "direct", "target_rva": 0x2000},
                                    }
                                ],
                                "memory_reads": [
                                    {
                                        "memory_rva": 0xE000,
                                        "string_literal": {
                                            "rva": 0xE000,
                                            "size": 3,
                                            "text": "hi",
                                            "sha256": sha256_bytes(b"hi"),
                                        },
                                    },
                                    {
                                        "memory_rva": 0xE020,
                                        "string_literal": {
                                            "rva": 0xE020,
                                            "size": 4,
                                            "text": "\u0000 @",
                                            "sha256": sha256_bytes(b"\x00 @"),
                                        },
                                    },
                                ],
                            }
                        ]
                    }
                }
            },
        }

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {"name": "caller", "rva_start": 0x1000, "rva_end": 0x1020, "size": 0x20},
                {"name": "target_func", "rva_start": 0x2000, "rva_end": 0x2010, "size": 0x10},
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn(".section .data$000_stage_b_reference_data", source)
        self.assertIn(".section .rdata$000_stage_b_reference_rdata", source)
        self.assertIn(".globl _stage_b_jq_reference_rdata", source)
        self.assertIn(".fill 164,1,0", source)
        self.assertIn(".section .CRT$XLC", source)
        self.assertIn(".long ___dyn_tls_init_12", source)
        self.assertIn(".byte 0x68, 0x69, 0x00", source)
        self.assertIn(".long _target_func", source)
        self.assertNotIn("stage_b_layout_keepalive", source)
        self.assertNotIn("stage_b_jq_layout_data_tail", source)
        self.assertNotIn("stage_b_jq_import_anchor", source)
        self.assertNotIn("stage_b_contract_section_gap_anchor", source)

    def test_decompiled_c_renderer_emits_full_jq_layout_normalization_pads(self):
        reference_contract = {
            "original": {
                "image_base": 0x400000,
                "sections": [
                    {"name": ".text", "rva_start": 0x1000, "rva_end": 0xC500},
                    {"name": ".data", "rva_start": 0xD000, "rva_end": 0xD05C},
                    {"name": ".rdata", "rva_start": 0xE000, "rva_end": 0xE100},
                    {"name": ".reloc", "rva_start": 0x14000, "rva_end": 0x145A0},
                ],
            },
        }

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[],
            reference_contract_payload=reference_contract,
        )

        self.assertIn(".text$zz_stage_b_jq_layout_tail_pad", source)
        self.assertIn("_stage_b_jq_layout_text_tail_pad", source)
        self.assertIn(".fill 84,1,0x90", source)
        self.assertIn(".section .reloc", source)
        self.assertIn("_stage_b_jq_reloc_absolute_pad", source)
        self.assertIn(".long 872", source)
        self.assertIn(".fill 432,2,0", source)

    def test_decompiled_c_renderer_preserves_dirname_path_info_out_params(self):
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "dirname",
                    "aliases": ["dirname"],
                    "rva_start": 0x5E50,
                    "rva_end": 0x5F61,
                    "size": 0x111,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "char * __cdecl dirname(char *param_1)",
                                "{",
                                "  char *pcVar2;",
                                "  char *local_20;",
                                "  undefined1 *local_1c;",
                                "  char *local_10;",
                                "  if (param_1 != (char *)0x0) {",
                                "    do_get_path_info();",
                                "    if (local_20 != (char *)0x0) {",
                                "      pcVar2 = (char *)realloc(_static_path_copy_0,2);",
                                "      if (pcVar2 != (char *)0x0) {",
                                "        memcpy(pcVar2,param_1,1);",
                                "      }",
                                "    }",
                                "    if (local_1c != (undefined1 *)0x0) {",
                                "      *local_1c = 0;",
                                "    }",
                                "  }",
                                "  return \".\";",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("do_get_path_info(param_1,&local_20,&local_1c,&local_10);", source)
        self.assertNotIn("    do_get_path_info();", source)

    def test_decompiled_c_renderer_preserves_dtoa_helper_call_boundaries(self):
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___Balloc_D2A",
                    "aliases": ["__Balloc_D2A", "___Balloc_D2A"],
                    "rva_start": 0xACA0,
                    "rva_end": 0xAD7F,
                    "size": 0xDF,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "uintptr_t __cdecl ___Balloc_D2A(int param_1)",
                                "{",
                                "  return (uintptr_t)malloc(param_1);",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "___b2d_D2A",
                    "aliases": ["__b2d_D2A", "___b2d_D2A"],
                    "rva_start": 0xB6E0,
                    "rva_end": 0xB824,
                    "size": 0x144,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "undefined8 __cdecl ___b2d_D2A(int param_1,int *param_2)",
                                "{",
                                "  return ___trailz_D2A(param_1);",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "___rv_alloc_D2A",
                    "aliases": ["__rv_alloc_D2A", "___rv_alloc_D2A"],
                    "rva_start": 0x8C80,
                    "rva_end": 0x8CC2,
                    "size": 0x42,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "int * __cdecl ___rv_alloc_D2A(int param_1)",
                                "{",
                                "  return ___Balloc_D2A(param_1);",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "___Bfree_D2A",
                    "aliases": ["__Bfree_D2A", "___Bfree_D2A"],
                    "rva_start": 0xAD80,
                    "rva_end": 0xADEA,
                    "size": 0x6A,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "undefined4 __cdecl ___Bfree_D2A(undefined4 *param_1)",
                                "{",
                                "  if (param_1 != (undefined4 *)0x0) {",
                                "    *param_1 = 0;",
                                "  }",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "umain",
                    "aliases": ["umain"],
                    "rva_start": 0x245E,
                    "rva_end": 0x496C,
                    "size": 0x250E,
                    "decompiler": {
                        "status": "success",
                        "code": "int __cdecl umain(int param_1,char **param_2)\n{\n  return 0;\n}",
                    },
                },
            ],
        )

        self.assertRegex(
            source,
            r"__attribute__\(\(noinline, noipa, used\)\)\nint \* __cdecl ___rv_alloc_D2A\(int param_1\)",
        )
        self.assertRegex(
            source,
            r"__attribute__\(\(noinline, noipa, used\)\)\nuintptr_t __cdecl ___Balloc_D2A\(int param_1\)",
        )
        self.assertRegex(
            source,
            r"__attribute__\(\(noinline, noipa, used\)\)\nundefined8 __cdecl ___b2d_D2A\(int param_1,int \*param_2\)",
        )
        self.assertRegex(
            source,
            r"__attribute__\(\(noinline, noipa, used\)\)\nundefined4 __cdecl ___Bfree_D2A\(undefined4 \*param_1\)",
        )
        self.assertRegex(
            source,
            r"__attribute__\(\(optimize\(\"Os\"\)\)\)\nint __cdecl umain",
        )
        self.assertNotRegex(
            source,
            r"__attribute__\(\(noinline, noipa, used\)\)\nint __cdecl umain",
        )

    def test_decompiled_c_placeholder_anchors_section_gap_function_pointer_callsites(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0058",
                            "symbol_aliases": {
                                "original": ["die"],
                                "candidate": ["die"],
                            },
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0058",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0058",
                                        "rva_start": 0x14D2,
                                        "rva_end": 0x153A,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0058:14e3",
                                        "block_id": "section-gap--text-0058",
                                        "instruction": {"rva": 0x14E3},
                                        "target": {
                                            "kind": "function_pointer",
                                            "operand": "ebx",
                                            "status": "unresolved",
                                            "memory_rva": 0xD058,
                                            "memory_role": "global_writable_pointer_slot",
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "caller",
                    "rva_start": 0x6000,
                    "rva_end": 0x6010,
                    "size": 0x10,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl caller(void)\n{\n  return die();\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[
                {
                    "name": "caller",
                    "rva_start": 0x6000,
                    "rva_end": 0x6010,
                    "size": 0x10,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl caller(void)\n{\n  return die();\n}",
                    },
                }
            ],
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        self.assertIn("uintptr_t __cdecl die()", source)
        self.assertIn("Stage A function-pointer-call anchor: callsite:section-gap--text-0058:14e3 at RVA 0x14e3", source)
        self.assertIn('__asm__ __volatile__("call *%%ebx" : : : "memory");', source)
        self.assertNotIn('xorl %%eax, %%eax; call *%%eax', source)
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["die"]["source_kind"], "generated_contract_placeholder_from_section_gap_alias")
        self.assertIn("section-gap--text-0058", by_function["die"]["aliases"])

    def test_decompiled_c_external_section_gap_helper_preserves_contract_callsites(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0057",
                            "symbol_aliases": {
                                "original": ["_jv_is_valid", "jv_is_valid"],
                                "candidate": ["_jv_is_valid", "jv_is_valid"],
                            },
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0057",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0057",
                                        "rva_start": 0x149F,
                                        "rva_end": 0x14D2,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0057:14c1",
                                        "instruction": {"rva": 0x14C1},
                                        "target": {"kind": "direct", "target_rva": 0x4A80},
                                        "argument_inventory": {
                                            "argument_count": 2,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "stack_pointer_slot",
                                                    "source": {"kind": "register", "register": "eax"},
                                                },
                                                {
                                                    "index": 1,
                                                    "role": "stack_pointer_slot",
                                                    "source": {"kind": "memory", "addressing": {"base": "esp"}},
                                                },
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
                {
                    "name": "jv_get_kind",
                    "rva_start": 0x4A80,
                    "rva_end": 0x4A86,
                    "size": 6,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl jv_get_kind(uintptr_t param_1, uintptr_t param_2)\n{\n  return param_1 ^ param_2;\n}",
                    },
                },
                {
                    "name": "caller",
                    "rva_start": 0x6000,
                    "rva_end": 0x6010,
                    "size": 0x10,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl caller(void)\n{\n  return jv_is_valid();\n}",
                    },
                },
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        self.assertIn("__attribute__((naked, noinline, used))\nuintptr_t __cdecl jv_is_valid()", source)
        self.assertIn("uintptr_t __cdecl jv_get_kind(uintptr_t param_1, uintptr_t param_2);", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0057:14c1 at RVA 0x14c1", source)
        self.assertIn('"call _jv_get_kind\\n\\t"', source)
        self.assertIn('"setne %al\\n\\t"', source)
        self.assertNotIn("jv_get_kind((uintptr_t)0, (uintptr_t)0);", source)
        self.assertNotIn("__attribute__((weak)) uintptr_t jv_is_valid() { return 0; }", source)
        self.assertIn(
            '"  .long _jv_is_valid - _stage_b_contract_section_gap_anchor\\n"',
            source,
        )
        self.assertNotIn("(void *)(uintptr_t)&jv_is_valid,", source)
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["jv_is_valid"]["source_kind"], "generated_contract_placeholder_from_section_gap_alias")
        self.assertIn("section-gap--text-0057", by_function["jv_is_valid"]["aliases"])

    def test_decompiled_c_synthesizes_unaliased_section_gap_contract_placeholder(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0052",
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0052",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0052",
                                        "rva_start": 0x145F,
                                        "rva_end": 0x1471,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0052:146c",
                                        "instruction": {"rva": 0x146C},
                                        "target": {"kind": "direct", "target_rva": 0xC4B0},
                                        "argument_inventory": {
                                            "argument_count": 2,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "computed_memory",
                                                    "source": {"kind": "register", "register": "eax"},
                                                },
                                                {
                                                    "index": 1,
                                                    "role": "immediate",
                                                    "source": {"kind": "immediate", "value": 7},
                                                },
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "strcmp",
                "rva_start": 0xC4B0,
                "rva_end": 0xC4B6,
                "size": 6,
                "decompiler": {
                    "status": "success",
                    "code": "uintptr_t __cdecl strcmp(uintptr_t param_1, uintptr_t param_2)\n{\n  return param_1 ^ param_2;\n}",
                },
            }
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        generated_name = "stage_b_contract_section_gap__text_0052"
        self.assertIn(f"uintptr_t __cdecl {generated_name}();", source)
        self.assertIn(
            f'"  .long _{generated_name} - _stage_b_contract_section_gap_anchor\\n"',
            source,
        )
        self.assertNotIn(f"(void *)(uintptr_t)&{generated_name},", source)
        self.assertIn('section(".CRT$XCU")', source)
        self.assertIn(f".section .text${generated_name}", source)
        self.assertIn(f"_{generated_name}:\\n", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0052:146c at RVA 0x146c", source)
        self.assertIn('"  pushl $0x7\\n"', source)
        self.assertIn('"  pushl %eax\\n"', source)
        self.assertIn('"  call _strcmp\\n"', source)
        self.assertIn('"  addl $8, %esp\\n"', source)
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_placeholder_from_section_gap")
        self.assertIn("section-gap--text-0052", by_function[generated_name]["aliases"])
        source_lines = source.splitlines()
        self.assertIn(f'"_{generated_name}:\\n"', source_lines[by_function[generated_name]["line_start"] - 1])

    def test_decompiled_c_section_gap_contract_placeholder_preserves_register_definition(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0110"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0110",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0110",
                                        "rva_start": 0x3000,
                                        "rva_end": 0x3020,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0110:3004",
                                        "instruction": {"rva": 0x3004},
                                        "target": {"kind": "direct", "target_rva": 0xC4B0},
                                        "argument_inventory": {
                                            "argument_count": 2,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "computed_address",
                                                    "source": {
                                                        "kind": "register",
                                                        "register": "eax",
                                                        "register_definition": {
                                                            "kind": "address",
                                                            "addressing": {"base": "esp", "disp": 48, "scale": 1},
                                                        },
                                                    },
                                                },
                                                {
                                                    "index": 1,
                                                    "role": "immediate",
                                                    "source": {"kind": "immediate", "value": 3},
                                                },
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "strcmp",
                "rva_start": 0xC4B0,
                "rva_end": 0xC4B6,
                "size": 6,
                "decompiler": {
                    "status": "success",
                    "code": "uintptr_t __cdecl strcmp(uintptr_t param_1, uintptr_t param_2)\n{\n  return param_1 ^ param_2;\n}",
                },
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )

        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0110:3004 at RVA 0x3004", source)
        self.assertIn('"  leal 0x30(%esp), %eax\\n"', source)
        self.assertIn('"  pushl $0x3\\n"', source)
        self.assertIn('"  pushl %eax\\n"', source)
        self.assertIn('"  call _strcmp\\n"', source)
        self.assertIn('"  addl $8, %esp\\n"', source)

    def test_decompiled_c_section_gap_contract_placeholder_preserves_register_carried_arguments(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {"id": "section-gap--text-0202"},
                        {"id": "section-gap--text-0494"},
                        {"id": "section-gap--text-0498"},
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0202",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0202",
                                        "rva_start": 0x61A0,
                                        "rva_end": 0x61E5,
                                    }
                                ],
                                "callsites": [],
                            },
                            {
                                "name": "section-gap--text-0498",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0498",
                                        "rva_start": 0x7300,
                                        "rva_end": 0x7320,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0498:7317",
                                        "instruction": {"rva": 0x7317},
                                        "target": {"kind": "direct", "target_rva": 0x61A0},
                                        "argument_inventory": {
                                            "argument_count": 3,
                                            "calling_convention": "x86_register_carried_internal",
                                            "register_args": [
                                                {
                                                    "register": "eax",
                                                    "role": "computed_out_param_or_hidden_sret",
                                                    "source": {
                                                        "kind": "address",
                                                        "addressing": {"base": "ebx", "disp": 28, "index": None, "scale": 1},
                                                    },
                                                },
                                                {
                                                    "register": "edx",
                                                    "role": "immediate",
                                                    "source": {"kind": "immediate", "value": 1},
                                                },
                                                {
                                                    "register": "ecx",
                                                    "role": "register",
                                                    "source": {"kind": "register", "register": "ebx"},
                                                },
                                            ],
                                            "stack_args": [],
                                        },
                                    }
                                ],
                            },
                        ]
                    }
                },
            }
        }

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "mentions_pformat_alias",
                    "rva_start": 0x9000,
                    "rva_end": 0x9010,
                    "size": 0x10,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl mentions_pformat_alias(void)\n{\n  return ___pformat_wputchars();\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )

        caller_name = "stage_b_contract_section_gap__text_0498"
        callee_name = "stage_b_contract_section_gap__text_0202"
        self.assertIn(f".section .text${caller_name}", source)
        self.assertIn(f".section .text${callee_name}", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0498:7317 at RVA 0x7317", source)
        self.assertIn('"  leal 0x1c(%ebx), %eax\\n"', source)
        self.assertIn('"  movl $0x1, %edx\\n"', source)
        self.assertIn('"  movl %ebx, %ecx\\n"', source)
        self.assertIn(f'"  call _{callee_name}\\n"', source)
        self.assertNotIn('"  call ___pformat_wputchars\\n"', source)
        self.assertNotIn('"  pushl %eax\\n"', source)
        self.assertNotIn('"  addl $12, %esp\\n"', source)

    def test_decompiled_c_section_gap_uses_checked_semantic_region_c_contract(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {"id": "section-gap--text-0202"},
                        {"id": "section-gap--text-0498"},
                    ]
                },
                "semantic_region_contracts": {
                    "format": "stage-a-semantic-region-contracts-v1",
                    "status": "satisfied",
                    "regions": [
                        {
                            "id": "semantic-region:jq-section-gap-0498-to-0202",
                            "status": "checked",
                            "function": "section-gap--text-0498",
                            "block_id": "section-gap--text-0498",
                            "caller": {"function": "section-gap--text-0498", "block_id": "section-gap--text-0498"},
                            "callee": {
                                "function": "section-gap--text-0202",
                                "block_id": "section-gap--text-0202",
                                "original": {"rva_start": 0x61A0, "rva_end": 0x61E5, "size": 0x45},
                            },
                            "post_call_jump": {
                                "function": "section-gap--text-0494",
                                "block_id": "section-gap--text-0494",
                                "original": {"rva_start": 0x72D0, "rva_end": 0x72F3, "size": 0x23},
                            },
                            "ir": {
                                "format": "stage-a-low-level-ir-v1",
                                "status": "checked",
                                "operations": [
                                    {"op": "add32", "dst": "tmp0"},
                                    {"op": "assign", "dst": "eax_call"},
                                    {"op": "assign", "dst": "edx_call"},
                                    {"op": "assign", "dst": "ecx_call"},
                                    {
                                        "op": "direct_call",
                                        "target": "section-gap--text-0202",
                                        "target_block_id": "section-gap--text-0202",
                                        "target_rva": 0x61A0,
                                        "register_arguments": [
                                            {"register": "eax"},
                                            {"register": "edx"},
                                            {"register": "ecx"},
                                        ],
                                    },
                                    {
                                        "op": "direct_jump",
                                        "target": "section-gap--text-0494",
                                        "target_block_id": "section-gap--text-0494",
                                        "target_rva": 0x72D0,
                                    },
                                ],
                            },
                            "c_contract": {"status": "checked"},
                        }
                    ],
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0494",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0494",
                                        "rva_start": 0x72D0,
                                        "rva_end": 0x72F3,
                                    }
                                ],
                                "callsites": [],
                            },
                            {
                                "name": "section-gap--text-0202",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0202",
                                        "rva_start": 0x61A0,
                                        "rva_end": 0x61E5,
                                    }
                                ],
                                "callsites": [],
                            },
                            {
                                "name": "section-gap--text-0498",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0498",
                                        "rva_start": 0x7300,
                                        "rva_end": 0x7320,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0498:7317",
                                        "instruction": {"rva": 0x7317},
                                        "target": {"kind": "direct", "target_rva": 0x61A0},
                                        "argument_inventory": {
                                            "argument_count": 3,
                                            "calling_convention": "x86_register_carried_internal",
                                            "register_args": [
                                                {
                                                    "register": "eax",
                                                    "source": {
                                                        "kind": "address",
                                                        "addressing": {"base": "ebx", "disp": 28, "index": None, "scale": 1},
                                                    },
                                                },
                                                {"register": "edx", "source": {"kind": "immediate", "value": 1}},
                                                {"register": "ecx", "source": {"kind": "register", "register": "ebx"}},
                                            ],
                                        },
                                    }
                                ],
                            },
                        ]
                    }
                },
            }
        }

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[],
            reference_contract_payload=reference_contract,
        )

        self.assertIn("typedef struct stageb_x86_state", source)
        self.assertIn("Stage A checked semantic region: semantic-region:jq-section-gap-0498-to-0202", source)
        self.assertIn("stage_b_contract_section_gap__text_0498_stage_a_c_contract(stageb_x86_state *s)", source)
        self.assertIn("s->eax = (uint32_t)(s->ebx + 0x1cU);", source)
        self.assertIn("s->edx = 1U;", source)
        self.assertIn("s->ecx = s->ebx;", source)
        self.assertIn("register uintptr_t stageb_ebx __asm__(\"ebx\");", source)
        self.assertIn(
            "volatile uintptr_t stageb_call_result = stage_b_contract_section_gap__text_0202((uintptr_t)s->eax, (uintptr_t)s->edx, (uintptr_t)s->ecx);",
            source,
        )
        self.assertIn("return stage_b_contract_section_gap__text_0494();", source)
        self.assertIn("uintptr_t __attribute__((regparm(3))) stage_b_contract_section_gap__text_0202", source)
        self.assertIn("__attribute__((noinline, used, regparm(3)))", source)
        self.assertIn(
            '"  .long _stage_b_contract_section_gap__text_0498 - _stage_b_contract_section_gap_anchor\\n"',
            source,
        )
        self.assertNotIn("uintptr_t __cdecl stage_b_contract_section_gap__text_0202();", source)
        self.assertNotIn("Stage A direct-call anchor: callsite:section-gap--text-0498:7317", source)
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[],
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(
            by_function["stage_b_contract_section_gap__text_0498"]["source_kind"],
            "generated_checked_semantic_region",
        )
        self.assertEqual(
            by_function["stage_b_contract_section_gap__text_0202"]["source_kind"],
            "generated_checked_semantic_region",
        )

    def test_decompiled_c_checked_semantic_callee_with_callsites_prefers_guided_flow(self):
        section_gap_name = "stage_b_contract_section_gap__text_0202"
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {"id": "section-gap--text-0202"},
                        {"id": "section-gap--text-0498"},
                    ]
                },
                "semantic_region_contracts": {
                    "format": "stage-a-semantic-region-contracts-v1",
                    "status": "satisfied",
                    "regions": [
                        {
                            "id": "semantic-region:caller-to-callee",
                            "status": "checked",
                            "function": "section-gap--text-0498",
                            "block_id": "section-gap--text-0498",
                            "caller": {"function": "section-gap--text-0498", "block_id": "section-gap--text-0498"},
                            "callee": {
                                "function": "section-gap--text-0202",
                                "block_id": "section-gap--text-0202",
                                "original": {"rva_start": 0x61A0, "rva_end": 0x61BB, "size": 0x1B},
                            },
                            "ir": {
                                "operations": [
                                    {
                                        "op": "direct_call",
                                        "target": "section-gap--text-0202",
                                        "target_block_id": "section-gap--text-0202",
                                        "target_rva": 0x61A0,
                                        "register_arguments": [
                                            {"register": "eax"},
                                            {"register": "edx"},
                                            {"register": "ecx"},
                                        ],
                                    }
                                ]
                            },
                            "c_contract": {"status": "checked"},
                        }
                    ],
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0202",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0202",
                                        "rva_start": 0x61A0,
                                        "rva_end": 0x61BB,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0202:61b2",
                                        "instruction": {
                                            "rva": 0x61B2,
                                            "size": 5,
                                            "bytes": "e8f99a0000",
                                            "mnemonic": "call",
                                            "op_str": "0x40c4b0",
                                        },
                                        "target": {"kind": "direct", "target_rva": 0xC4B0},
                                        "argument_inventory": {
                                            "argument_count": 3,
                                            "calling_convention": "cdecl_or_stdcall_stack",
                                            "stack_args": [
                                                {"index": 0, "source": {"kind": "register", "register": "edi"}},
                                                {"index": 1, "source": {"kind": "immediate", "value": 0}},
                                                {"index": 2, "source": {"kind": "register", "register": "eax"}},
                                            ],
                                        },
                                    }
                                ],
                            },
                            {
                                "name": "section-gap--text-0498",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0498",
                                        "rva_start": 0x7300,
                                        "rva_end": 0x7310,
                                    }
                                ],
                                "callsites": [],
                            },
                        ]
                    }
                },
            }
        }
        reference_sidecars = {
            "semantic_transfer_contracts": {
                "by_function": {
                    "section-gap--text-0202": [
                        {
                            "id": "section-gap--text-0202",
                            "rva_start": 0x61A0,
                            "rva_end": 0x61BB,
                            "outcome": {"kind": "return"},
                            "instructions": [
                                {"rva": 0x61A0, "size": 3, "bytes": "83ec0c", "mnemonic": "sub", "op_str": "esp, 0xc"},
                                {
                                    "rva": 0x61A3,
                                    "size": 4,
                                    "bytes": "89442408",
                                    "mnemonic": "mov",
                                    "op_str": "dword ptr [esp + 8], eax",
                                },
                                {
                                    "rva": 0x61A7,
                                    "size": 8,
                                    "bytes": "c744240400000000",
                                    "mnemonic": "mov",
                                    "op_str": "dword ptr [esp + 4], 0",
                                },
                                {
                                    "rva": 0x61AF,
                                    "size": 3,
                                    "bytes": "893c24",
                                    "mnemonic": "mov",
                                    "op_str": "dword ptr [esp], edi",
                                },
                                {
                                    "rva": 0x61B2,
                                    "size": 5,
                                    "bytes": "e8f99a0000",
                                    "mnemonic": "call",
                                    "op_str": "0x40c4b0",
                                },
                                {"rva": 0x61B7, "size": 3, "bytes": "83c40c", "mnemonic": "add", "op_str": "esp, 0xc"},
                                {"rva": 0x61BA, "size": 1, "bytes": "c3", "mnemonic": "ret", "op_str": ""},
                            ],
                        }
                    ]
                }
            }
        }
        functions = [
            {
                "name": "strcmp",
                "rva_start": 0xC4B0,
                "rva_end": 0xC4B6,
                "size": 6,
                "decompiler": {
                    "status": "success",
                    "code": "uintptr_t __cdecl strcmp(uintptr_t param_1, uintptr_t param_2)\n{\n  return param_1 ^ param_2;\n}",
                },
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
            reference_contract_sidecars=reference_sidecars,
            allow_contract_bytecode=True,
        )

        self.assertIn(f"uintptr_t __attribute__((regparm(3))) {section_gap_name}", source)
        self.assertIn("Stage B contract-guided flow: semantic-transfer CFG", source)
        self.assertIn(f"_{section_gap_name}:\\n", source)
        self.assertIn('"call _strcmp', source)
        self.assertNotIn("Stage B register-ABI callee placeholder for checked selected-region target", source)
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="contract-guided-c",
            reference_contract_payload=reference_contract,
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function[section_gap_name]["source_kind"], "generated_contract_guided_flow")

    def test_decompiled_c_synthesizes_all_linkable_section_gap_placeholders(self):
        section_gap_functions = []
        for index in range(22):
            name = f"section-gap--text-{index:04d}"
            rva = 0x2000 + index * 0x20
            section_gap_functions.append(
                {
                    "name": name,
                    "blocks": [{"block_id": name, "rva_start": rva, "rva_end": rva + 0x10}],
                    "callsites": [
                        {
                            "id": f"callsite:{name}:{rva + 4:x}",
                            "block_id": name,
                            "instruction": {"rva": rva + 4},
                            "target": {"kind": "direct", "target_rva": 0xC4B0},
                        }
                    ],
                }
            )
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": item["name"]} for item in section_gap_functions]},
                "abi_callsites": {"original": {"functions": section_gap_functions}},
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "strcmp",
                    "rva_start": 0xC4B0,
                    "rva_end": 0xC4B6,
                    "size": 6,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl strcmp(void)\n{\n  return 0;\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn(".section .text$stage_b_contract_section_gap__text_0000", source)
        self.assertIn(".section .text$stage_b_contract_section_gap__text_0021", source)
        self.assertEqual(source.count("Stage B compact contract placeholder for missing decompiler body"), 22)

    def test_decompiled_c_interleaves_synthetic_section_gaps_by_rva(self):
        section_gap_functions = [
            {
                "name": "section-gap--text-0000",
                "blocks": [{"block_id": "section-gap--text-0000", "rva_start": 0x1000, "rva_end": 0x1008}],
                "callsites": [],
            },
            {
                "name": "section-gap--text-0001",
                "blocks": [{"block_id": "section-gap--text-0001", "rva_start": 0x2000, "rva_end": 0x2008}],
                "callsites": [],
            },
        ]
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": item["name"]} for item in section_gap_functions]},
                "abi_callsites": {"original": {"functions": section_gap_functions}},
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "middle",
                    "rva_start": 0x1500,
                    "rva_end": 0x1505,
                    "size": 5,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl middle(void)\n{\n  return 0;\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )

        early = source.index("name stage_b_contract_section_gap__text_0000")
        middle = source.index("name middle")
        late = source.index("name stage_b_contract_section_gap__text_0001")
        self.assertLess(early, middle)
        self.assertLess(middle, late)

    def test_decompiled_c_emits_verified_padding_between_ordered_bodies(self):
        section_gap_functions = [
            {
                "name": "section-gap--text-0000",
                "blocks": [{"block_id": "section-gap--text-0000", "rva_start": 0x1000, "rva_end": 0x1001}],
                "callsites": [],
            },
        ]
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0000"}]},
                "abi_callsites": {"original": {"functions": section_gap_functions}},
                "padding_alignment": {
                    "status": "satisfied",
                    "obligations": [
                        {
                            "status": "waived_noncode",
                            "checks": [
                                {
                                    "binary": "original",
                                    "status": "verified",
                                    "rva_start": 0x1001,
                                    "rva_end": 0x1010,
                                    "bytes_hex": "90" * 15,
                                    "bytes_sha256": sha256_bytes(bytes.fromhex("90" * 15)),
                                }
                            ],
                        }
                    ],
                },
            }
        }
        functions = [
            {
                "name": "middle",
                "rva_start": 0x1010,
                "rva_end": 0x1015,
                "size": 5,
                "decompiler": {
                    "status": "success",
                    "code": "uintptr_t __cdecl middle(void)\n{\n  return 0;\n}",
                },
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )

        early = source.index("name stage_b_contract_section_gap__text_0000")
        padding = source.index("Stage B contract layout padding: verified bytes at RVA 0x1001-0x1010")
        middle = source.index("name middle")
        self.assertLess(early, padding)
        self.assertLess(padding, middle)
        self.assertIn('".byte 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90\\n\\t"', source)
        self.assertIn('".byte 0x90, 0x90, 0x90"', source)

        uncovered_contract = json.loads(json.dumps(reference_contract))
        uncovered_contract["constraints"].pop("padding_alignment")
        uncovered_source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=uncovered_contract,
        )
        self.assertNotIn("Stage B contract layout padding", uncovered_source)

    def test_decompiled_c_synthesizes_no_callsite_section_gap_contract_placeholder(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0513"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0513",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0513",
                                        "rva_start": 0x73CF,
                                        "rva_end": 0x73DD,
                                    }
                                ],
                                "callsites": [],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[],
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[],
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        generated_name = "stage_b_contract_section_gap__text_0513"
        self.assertIn(f"uintptr_t __cdecl {generated_name}();", source)
        self.assertIn(f".section .text${generated_name}", source)
        self.assertIn(f"_{generated_name}:\\n", source)
        self.assertIn('"  ret\\n"', source)
        self.assertIn("extern const int32_t stage_b_contract_section_gap_anchor[];", source)
        self.assertIn(".section .rdata$stage_b_contract_section_gap_anchor", source)
        self.assertIn(
            f'"  .long _{generated_name} - _stage_b_contract_section_gap_anchor\\n"',
            source,
        )
        self.assertIn(
            '"  .long _stage_b_contract_section_gap_anchor - _stage_b_jq_layout_anchor\\n"',
            source,
        )
        self.assertIn(
            '__asm__ __volatile__("" : : "r"((void *)stage_b_jq_layout_anchor) : "memory");',
            source,
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_placeholder_from_section_gap")
        self.assertIn("section-gap--text-0513", by_function[generated_name]["aliases"])

    def test_decompiled_c_section_gap_placeholder_calls_generated_section_gap_target(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {"id": "section-gap--text-0067"},
                        {"id": "section-gap--text-0073"},
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0067",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0067",
                                        "rva_start": 0x15D9,
                                        "rva_end": 0x15E7,
                                    }
                                ],
                                "callsites": [],
                            },
                            {
                                "name": "section-gap--text-0073",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0073",
                                        "rva_start": 0x173B,
                                        "rva_end": 0x17D9,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0073:17cf",
                                        "block_id": "section-gap--text-0073",
                                        "instruction": {"rva": 0x17CF},
                                        "target": {"kind": "direct", "target_rva": 0x15D9},
                                        "argument_inventory": {"argument_count": 0, "stack_args": []},
                                    }
                                ],
                            },
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[],
            reference_contract_payload=reference_contract,
        )

        self.assertIn(".section .text$stage_b_contract_section_gap__text_0067", source)
        self.assertIn(".section .text$stage_b_contract_section_gap__text_0073", source)
        self.assertIn(
            "Stage A direct-call anchor: callsite:section-gap--text-0073:17cf at RVA 0x17cf",
            source,
        )
        self.assertIn('"  call _stage_b_contract_section_gap__text_0067\\n"', source)

    def test_decompiled_c_section_gap_placeholder_calls_aliased_section_gap_target(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0057",
                            "symbol_aliases": {"original": ["jv_is_valid"], "candidate": ["jv_is_valid"]},
                        },
                        {"id": "section-gap--text-0081"},
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0057",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0057",
                                        "rva_start": 0x149F,
                                        "rva_end": 0x14D2,
                                    }
                                ],
                                "callsites": [],
                            },
                            {
                                "name": "section-gap--text-0081",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0081",
                                        "rva_start": 0x19D5,
                                        "rva_end": 0x1A11,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0081:1a04",
                                        "block_id": "section-gap--text-0081",
                                        "instruction": {"rva": 0x1A04},
                                        "target": {"kind": "direct", "target_rva": 0x149F},
                                        "argument_inventory": {
                                            "argument_count": 4,
                                            "stack_args": [
                                                {"index": 0, "role": "stack_pointer_slot", "source": {"kind": "register", "register": "eax"}},
                                                {"index": 1, "role": "stack_pointer_slot", "source": {"kind": "register", "register": "eax"}},
                                                {"index": 2, "role": "stack_pointer_slot", "source": {"kind": "register", "register": "eax"}},
                                                {"index": 3, "role": "stack_pointer_slot", "source": {"kind": "register", "register": "eax"}},
                                            ],
                                        },
                                    }
                                ],
                            },
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "caller",
                    "rva_start": 0x4000,
                    "rva_end": 0x4010,
                    "size": 0x10,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl caller(void)\n{\n  jv_is_valid();\n  return 0;\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn("uintptr_t __cdecl jv_is_valid()", source)
        self.assertIn(".section .text$stage_b_contract_section_gap__text_0081", source)
        self.assertIn(
            "Stage A direct-call anchor: callsite:section-gap--text-0081:1a04 at RVA 0x1a04",
            source,
        )
        self.assertIn('"  call _jv_is_valid\\n"', source)

    def test_decompiled_c_asm_call_target_rejects_stack_probe_helper(self):
        self.assertFalse(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "___chkstk_ms",
                target_profile={},
            )
        )
        self.assertFalse(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "___chkstk",
                target_profile=None,
            )
        )
        self.assertFalse(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "__chkstk_ms",
                target_profile=None,
            )
        )
        self.assertTrue(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "__chkstk_ms",
                target_profile={"runtime_crt_linked": True},
            )
        )
        self.assertTrue(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "_GetPEImageBase",
                target_profile={"runtime_crt_linked": True},
            )
        )
        self.assertFalse(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "__p__fmode",
                target_profile=None,
            )
        )
        self.assertTrue(
            _decompiled_c_contract_direct_call_target_is_asm_linkable(
                "__p__fmode",
                target_profile={"prototype": "extern uintptr_t __p__fmode();"},
            )
        )

    def test_decompiled_c_section_gap_placeholder_calls_runtime_crt_helper_from_contract(self):
        reference_contract = {
            "constraints": {
                "function_ranges": {
                    "functions": [
                        {
                            "name": "__mingw_GetSectionForAddress",
                            "original": {"rva_start": 0x58F0, "rva_end": 0x5971},
                        }
                    ]
                },
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0124"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0124",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0124",
                                        "rva_start": 0x4E6E,
                                        "rva_end": 0x4E80,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0124:4e71",
                                        "block_id": "section-gap--text-0124",
                                        "instruction": {"rva": 0x4E71},
                                        "target": {"kind": "direct", "target_rva": 0x58F0},
                                        "argument_inventory": {
                                            "argument_count": 1,
                                            "stack_args": [
                                                {"index": 0, "role": "register", "source": {"kind": "register", "register": "ebx"}}
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___mingw_GetSectionForAddress",
                    "rva_start": 0x58F0,
                    "rva_end": 0x5971,
                    "size": 0x81,
                    "decompiler": {"status": "missing"},
                }
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn(".section .text$stage_b_contract_section_gap__text_0124", source)
        self.assertIn(
            "Stage A direct-call anchor: callsite:section-gap--text-0124:4e71 at RVA 0x4e71",
            source,
        )
        self.assertIn('"  call ___mingw_GetSectionForAddress\\n"', source)
        self.assertNotIn('"  call ____mingw_GetSectionForAddress\\n"', source)

    def test_decompiled_c_section_gap_placeholder_calls_mingw_runtime_alias_target(self):
        reference_contract = {
            "constraints": {
                "function_ranges": {
                    "functions": [
                        {
                            "name": "__mingw_fprintf",
                            "original": {"rva_start": 0x5FE0, "rva_end": 0x602B},
                        }
                    ]
                },
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0060"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0060",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0060",
                                        "rva_start": 0x155A,
                                        "rva_end": 0x157C,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0060:156d",
                                        "block_id": "section-gap--text-0060",
                                        "instruction": {"rva": 0x156D},
                                        "target": {"kind": "direct", "target_rva": 0x5FE0},
                                        "argument_inventory": {
                                            "argument_count": 3,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "register",
                                                    "source": {"kind": "register", "register": "esi"},
                                                },
                                                {
                                                    "index": 1,
                                                    "role": "immediate",
                                                    "source": {"kind": "immediate", "value": 0x40D078},
                                                },
                                                {
                                                    "index": 2,
                                                    "role": "string_literal",
                                                    "source": {"kind": "immediate", "value": 0x40D072},
                                                },
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[],
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[],
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        generated_name = "stage_b_contract_section_gap__text_0060"
        self.assertIn(f".section .text${generated_name}", source)
        self.assertIn(
            "Stage A direct-call anchor: callsite:section-gap--text-0060:156d at RVA 0x156d",
            source,
        )
        self.assertIn('"  pushl $0x40d072\\n"', source)
        self.assertIn('"  pushl $0x40d078\\n"', source)
        self.assertIn('"  pushl %esi\\n"', source)
        self.assertIn('"  call ___mingw_fprintf\\n"', source)
        self.assertNotIn('"  call ____mingw_fprintf\\n"', source)
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_placeholder_from_section_gap")
        self.assertIn("section-gap--text-0060", by_function[generated_name]["aliases"])

    def test_decompiled_c_section_gap_runtime_crt_profile_upgrades_existing_function(self):
        reference_contract = {
            "constraints": {
                "function_ranges": {
                    "functions": [
                        {
                            "name": "atexit",
                            "original": {"rva_start": 0x1430, "rva_end": 0x1435},
                        }
                    ]
                },
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0732"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0732",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0732",
                                        "rva_start": 0xABDF,
                                        "rva_end": 0xAC0B,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0732:ac06",
                                        "block_id": "section-gap--text-0732",
                                        "instruction": {"rva": 0xAC06},
                                        "target": {"kind": "direct", "target_rva": 0x1430},
                                        "argument_inventory": {
                                            "argument_count": 1,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "immediate",
                                                    "source": {"kind": "immediate", "value": 0x40AC50},
                                                }
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "atexit",
                    "rva_start": 0x1430,
                    "rva_end": 0x1435,
                    "size": 5,
                    "decompiler": {"status": "missing"},
                }
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn(
            "Stage A direct-call anchor: callsite:section-gap--text-0732:ac06 at RVA 0xac06",
            source,
        )
        self.assertIn('"  pushl $0x40ac50\\n"', source)
        self.assertIn('"  call _atexit\\n"', source)

    def test_decompiled_c_section_gap_placeholder_calls_canonical_stack_probe_helper(self):
        reference_contract = {
            "constraints": {
                "function_ranges": {
                    "functions": [
                        {"name": "__chkstk_ms", "original": {"rva_start": 0x5BF0, "rva_end": 0x5C1A}}
                    ]
                },
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0466"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0466",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0466",
                                        "rva_start": 0x4A40,
                                        "rva_end": 0x4A50,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0466:4a41",
                                        "block_id": "section-gap--text-0466",
                                        "instruction": {"rva": 0x4A41},
                                        "target": {"kind": "direct", "target_rva": 0x5BF0},
                                        "argument_inventory": {"argument_count": 0, "stack_args": []},
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___chkstk_ms",
                    "rva_start": 0x5BF0,
                    "rva_end": 0x5C1A,
                    "size": 0x30,
                    "decompiler": {
                        "status": "success",
                        "code": "uint ___chkstk_ms(void)\n{\n  return 0;\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0466:4a41", source)
        self.assertIn('"  call ___chkstk_ms\\n"', source)
        self.assertNotIn("call ____chkstk_ms", source)
        self.assertNotIn("undefined reference", source)

    def test_decompiled_c_contract_placeholder_preserves_import_call_anchor(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0142",
                            "symbol_aliases": {"original": ["do_get_path_info"], "candidate": ["do_get_path_info"]},
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0142",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0142",
                                        "rva_start": 0x5C20,
                                        "rva_end": 0x5C61,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0142:5c2b",
                                        "block_id": "section-gap--text-0142",
                                        "instruction": {"rva": 0x5C2B},
                                        "target": {"kind": "import", "symbol": "AreFileApisANSI", "dll": "kernel32.dll"},
                                        "argument_inventory": {"argument_count": 0, "stack_args": []},
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "caller",
                    "rva_start": 0x4000,
                    "rva_end": 0x4010,
                    "size": 0x10,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __cdecl caller(void)\n{\n  do_get_path_info();\n  return 0;\n}",
                    },
                }
            ],
            reference_contract_payload=reference_contract,
        )

        self.assertIn("uintptr_t __cdecl do_get_path_info()", source)
        self.assertIn(
            "Stage A import-call anchor: callsite:section-gap--text-0142:5c2b at RVA 0x5c2b",
            source,
        )
        self.assertIn("  ((uintptr_t (__cdecl *)())(uintptr_t)AreFileApisANSI)();", source)

    def test_decompiled_c_retains_no_callsite_section_gap_alias_symbol(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0740",
                            "symbol_aliases": {
                                "original": ["___wcrtomb_cp", "wcrtomb_cp"],
                                "candidate": ["___wcrtomb_cp", "wcrtomb_cp"],
                            },
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0740",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0740",
                                        "rva_start": 0xBA70,
                                        "rva_end": 0xBA84,
                                    }
                                ],
                                "callsites": [],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "___wcrtomb_cp",
                "rva_start": 0xBA70,
                "rva_end": 0xBA84,
                "size": 0x14,
                "decompiler": {
                    "status": "success",
                    "code": "uintptr_t __cdecl ___wcrtomb_cp(void)\n{\n  return 0;\n}",
                },
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        self.assertIn("extern const int32_t stage_b_contract_section_gap_anchor[];", source)
        self.assertIn(
            '"  .long ____wcrtomb_cp - _stage_b_contract_section_gap_anchor\\n"',
            source,
        )
        self.assertNotIn("(void *)(uintptr_t)&___wcrtomb_cp,", source)
        self.assertNotIn("static void * const stage_b_contract_section_gap_anchor[]", source)
        self.assertIn(
            '"  .long _stage_b_contract_section_gap_anchor - _stage_b_jq_layout_anchor\\n"',
            source,
        )
        self.assertIn(
            '__asm__ __volatile__("" : : "r"((void *)stage_b_jq_layout_anchor) : "memory");',
            source,
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["___wcrtomb_cp"]["source_kind"], "decompiled_function")
        self.assertNotIn("stage_b_contract_section_gap__text_0740", by_function)

    def test_decompiled_c_synthesizes_unaliased_section_gap_function_pointer_placeholder(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0066",
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0066",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0066",
                                        "rva_start": 0x15CB,
                                        "rva_end": 0x15DC,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0066:15d3",
                                        "block_id": "section-gap--text-0066",
                                        "instruction": {"rva": 0x15D3},
                                        "target": {
                                            "kind": "function_pointer",
                                            "operand": "ebp",
                                            "status": "unresolved",
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "___p__fmode",
                "aliases": ["__p__fmode", "___p__fmode"],
                "rva_start": 0xC4F8,
                "rva_end": 0xC500,
                "size": 8,
                "linkage": {
                    "kind": "import_thunk",
                    "dll": "msvcrt.dll",
                    "symbol": "__p__fmode",
                    "original_symbol": "___p__fmode",
                },
                "decompiler": {
                    "status": "success",
                    "code": "void ___p__fmode(void)\n{\n  __p__fmode();\n}",
                },
            }
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        generated_name = "stage_b_contract_section_gap__text_0066"
        self.assertIn(f".section .text${generated_name}", source)
        self.assertIn("Stage A function-pointer-call anchor: callsite:section-gap--text-0066:15d3 at RVA 0x15d3", source)
        self.assertNotIn('"  xorl %eax, %eax\\n"', source)
        self.assertIn('"  call *%ebp\\n"', source)
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_placeholder_from_section_gap")
        self.assertIn("section-gap--text-0066", by_function[generated_name]["aliases"])
        source_lines = source.splitlines()
        self.assertIn(f'"_{generated_name}:\\n"', source_lines[by_function[generated_name]["line_start"] - 1])

    def test_decompiled_c_synthesizes_unaliased_section_gap_import_placeholder(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0068",
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0068",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0068",
                                        "rva_start": 0x15E0,
                                        "rva_end": 0x1631,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0068:15ee",
                                        "block_id": "section-gap--text-0068",
                                        "instruction": {"rva": 0x15EE},
                                        "target": {"kind": "direct", "target_rva": 0xC4F8},
                                    },
                                    {
                                        "id": "callsite:section-gap--text-0068:15fc",
                                        "block_id": "section-gap--text-0068",
                                        "instruction": {"rva": 0x15FC},
                                        "target": {"kind": "import", "dll": "msvcrt.dll", "symbol": "_get_osfhandle"},
                                        "argument_inventory": {
                                            "argument_count": 1,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "immediate",
                                                    "source": {"kind": "immediate", "value": 1},
                                                }
                                            ],
                                        },
                                    },
                                    {
                                        "id": "callsite:section-gap--text-0068:161b",
                                        "block_id": "section-gap--text-0068",
                                        "instruction": {"rva": 0x161B},
                                        "target": {"kind": "import", "dll": "kernel32.dll", "symbol": "WriteFile"},
                                    },
                                ],
                            }
                        ]
                    }
                },
            }
        }
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[],
            reference_contract_payload=reference_contract,
        )
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[],
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
        )

        generated_name = "stage_b_contract_section_gap__text_0068"
        self.assertIn(f".section .text${generated_name}", source)
        self.assertNotIn("Stage A direct-call anchor: callsite:section-gap--text-0068:15ee", source)
        self.assertIn("Stage A import-call anchor: callsite:section-gap--text-0068:15fc at RVA 0x15fc", source)
        self.assertIn("Stage A import-call anchor: callsite:section-gap--text-0068:161b at RVA 0x161b", source)
        self.assertIn('"  pushl $0x1\\n"', source)
        self.assertIn('"  call *__imp___get_osfhandle\\n"', source)
        self.assertIn('"  addl $4, %esp\\n"', source)
        self.assertIn('"  call *__imp__WriteFile@20\\n"', source)
        self.assertNotIn('"  addl $20, %esp\\n"', source)
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function[generated_name]["source_kind"], "generated_contract_placeholder_from_section_gap")
        self.assertIn("section-gap--text-0068", by_function[generated_name]["aliases"])

    def test_decompiled_c_synthesizes_section_gap_direct_import_thunk_placeholder(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {
                    "basic_blocks": [
                        {
                            "id": "section-gap--text-0068",
                        }
                    ]
                },
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0068",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0068",
                                        "rva_start": 0x15E0,
                                        "rva_end": 0x1631,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0068:15ee",
                                        "block_id": "section-gap--text-0068",
                                        "instruction": {"rva": 0x15EE},
                                        "target": {"kind": "direct", "target_rva": 0xC4F8},
                                        "argument_inventory": {
                                            "argument_count": 1,
                                            "stack_args": [
                                                {
                                                    "index": 0,
                                                    "role": "register",
                                                    "source": {"kind": "register", "register": "ecx"},
                                                }
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "fileno",
                "aliases": ["fileno"],
                "rva_start": 0xC4F8,
                "rva_end": 0xC4FE,
                "size": 6,
                "linkage": {
                    "kind": "import_thunk",
                    "dll": "msvcrt.dll",
                    "symbol": "_fileno",
                    "original_symbol": "fileno",
                },
            }
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )

        generated_name = "stage_b_contract_section_gap__text_0068"
        self.assertIn(f".section .text${generated_name}", source)
        self.assertIn("extern uintptr_t _fileno();", source)
        self.assertIn("#define fileno _fileno", source)
        self.assertIn("import thunk for _fileno; body omitted", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0068:15ee at RVA 0x15ee", source)
        self.assertIn('"  pushl %ecx\\n"', source)
        self.assertIn('"  call __fileno\\n"', source)
        self.assertIn('"  addl $4, %esp\\n"', source)

    def test_decompiled_c_direct_import_thunk_placeholder_uses_header_declared_imports(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0099"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0099",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0099",
                                        "rva_start": 0x2000,
                                        "rva_end": 0x2010,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0099:2004",
                                        "block_id": "section-gap--text-0099",
                                        "instruction": {"rva": 0x2004},
                                        "target": {"kind": "direct", "target_rva": 0xC600},
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "errno",
                "aliases": ["errno"],
                "rva_start": 0xC600,
                "rva_end": 0xC606,
                "size": 6,
                "linkage": {
                    "kind": "import_thunk",
                    "dll": "msvcrt.dll",
                    "symbol": "_errno",
                    "original_symbol": "errno",
                },
            }
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )

        self.assertNotIn("extern uintptr_t _errno();", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0099:2004 at RVA 0x2004", source)
        self.assertIn('"  call __errno\\n"', source)

    def test_decompiled_c_direct_import_thunk_profile_prefers_real_implementation(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0100"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0100",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0100",
                                        "rva_start": 0x2100,
                                        "rva_end": 0x2110,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0100:2104",
                                        "block_id": "section-gap--text-0100",
                                        "instruction": {"rva": 0x2104},
                                        "target": {"kind": "direct", "target_rva": 0xC700},
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "hypot",
                "aliases": ["hypot"],
                "rva_start": 0xC700,
                "rva_end": 0xC706,
                "size": 6,
                "linkage": {
                    "kind": "import_thunk",
                    "dll": "msvcrt.dll",
                    "symbol": "_hypot",
                    "original_symbol": "hypot",
                },
            },
            {
                "name": "_hypot",
                "rva_start": 0xD000,
                "rva_end": 0xD020,
                "size": 0x20,
                "decompiler": {
                    "status": "success",
                    "code": "double __cdecl _hypot(double _X,double _Y)\n{\n  return _X + _Y;\n}",
                },
            },
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )

        self.assertNotIn("extern uintptr_t _hypot();", source)
        self.assertIn("double __cdecl _hypot(double _X,double _Y);", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0100:2104 at RVA 0x2104", source)
        self.assertIn('"  call __hypot\\n"', source)

    def test_decompiled_c_direct_import_thunk_profile_uses_external_abi_for_imports(self):
        reference_contract = {
            "constraints": {
                "basic_blocks_and_cfg": {"basic_blocks": [{"id": "section-gap--text-0101"}]},
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0101",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0101",
                                        "rva_start": 0x2200,
                                        "rva_end": 0x2210,
                                    }
                                ],
                                "callsites": [
                                    {
                                        "id": "callsite:section-gap--text-0101:2204",
                                        "block_id": "section-gap--text-0101",
                                        "instruction": {"rva": 0x2204},
                                        "target": {"kind": "direct", "target_rva": 0xC800},
                                        "argument_inventory": {"argument_count": 1, "stack_args": [{"index": 0, "role": "register"}]},
                                    }
                                ],
                            }
                        ]
                    }
                },
            }
        }
        functions = [
            {
                "name": "jv_array",
                "aliases": ["jv_array"],
                "rva_start": 0xC800,
                "rva_end": 0xC806,
                "size": 6,
                "linkage": {
                    "kind": "import_thunk",
                    "dll": "libjq-1.dll",
                    "symbol": "jv_array",
                    "original_symbol": "jv_array",
                },
                "decompiler": {
                    "status": "success",
                    "code": "undefined4 __cdecl jv_array(undefined4 param_1)\n{\n  return param_1;\n}",
                },
            }
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            reference_contract_payload=reference_contract,
        )

        self.assertIn("extern stage_b_jv jv_array(void);", source)
        self.assertNotIn("undefined4 __cdecl jv_array(undefined4 param_1);", source)
        self.assertIn("Stage A direct-call anchor: callsite:section-gap--text-0101:2204 at RVA 0x2204", source)
        self.assertNotIn('"  pushl $0x0\\n"', source)
        self.assertIn('"  call _jv_array\\n"', source)

    def test_decompiled_c_renderer_materializes_jq_dtoa_lock_helper(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___Bfree_D2A",
                    "rva_start": 0xAD80,
                    "rva_end": 0xADE9,
                    "size": 0x69,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "void __cdecl ___Bfree_D2A(undefined4 *param_1)",
                                "{",
                                "  dtoa_lock();",
                                "  if (_dtoa_CS_init == 2) {",
                                "    LeaveCriticalSection((LPCRITICAL_SECTION)&_dtoa_CritSec);",
                                "  }",
                                "  *(double *)(&___tens_D2A + 8);",
                                "  return;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("#define STAGE_B_JQ_HAS_LAYOUT_BSS_ANCHOR 1", source)
        self.assertIn("extern volatile unsigned char stage_b_jq_layout_bss_anchor[];", source)
        self.assertIn("#define STAGE_B_JQ_RECOVERED_STATE_BASE stage_b_jq_layout_bss_anchor", source)
        self.assertIn("#define _dtoa_CS_init (*(byte *)(STAGE_B_JQ_RECOVERED_STATE_BASE + 0x878U))", source)
        self.assertIn("#define _dtoa_CritSec (*(byte (*)[0x30])(STAGE_B_JQ_RECOVERED_STATE_BASE + 0x840U))", source)
        self.assertNotIn("__attribute__((weak)) byte _dtoa_CS_init;", source)
        self.assertNotIn("__attribute__((weak)) byte _dtoa_CritSec", source)
        self.assertIn('section(".rdata$stage_b_jq_dtoa_tables")', source)
        self.assertIn("static const double stage_b_jq_tens_D2A[24]", source)
        self.assertIn("#define ___tens_D2A (*(const byte *)(const void *)stage_b_jq_tens_D2A)", source)
        self.assertNotIn("__attribute__((weak)) byte ___tens_D2A;", source)
        self.assertIn("extern void __attribute__((stdcall, dllimport)) InitializeCriticalSection(LPCRITICAL_SECTION);", source)
        self.assertIn("extern void __attribute__((stdcall, dllimport)) EnterCriticalSection(LPCRITICAL_SECTION);", source)
        self.assertIn("extern void __attribute__((stdcall, dllimport)) DeleteCriticalSection(LPCRITICAL_SECTION);", source)
        self.assertIn("extern void __attribute__((stdcall, dllimport)) Sleep(DWORD);", source)
        self.assertIn("extern uintptr_t __crt_atexit();", source)
        self.assertIn("static void stage_b_dtoa_lock_cleanup(void)", source)
        self.assertIn("uintptr_t dtoa_lock(void)", source)
        self.assertIn("InitializeCriticalSection((LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + 0x00U));", source)
        self.assertIn("InitializeCriticalSection((LPCRITICAL_SECTION)((byte *)&_dtoa_CritSec + 0x18U));", source)
        self.assertIn("__crt_atexit((void *)stage_b_dtoa_lock_cleanup);", source)
        self.assertIn("Sleep(1);", source)
        self.assertIn("EnterCriticalSection(stage_b_dtoa_lock_section(selector));", source)
        self.assertNotIn("__attribute__((weak)) uintptr_t dtoa_lock() { return 0; }", source)

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
        self.assertIn(".globl ___crt_atexit", source)
        self.assertIn("jmp *__imp__atexit", source)
        self.assertIn("uintptr_t __cdecl atexit(_func_4879 *param_1)", source)
        self.assertIn("return __crt_atexit(param_1);", source)
        self.assertNotIn("return atexit(param_1);", source)

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
        self.assertIn(".globl _jq_get_exit_code", source)
        self.assertIn("jmp *__imp__jq_get_exit_code", source)
        self.assertIn("import thunk for jq_get_exit_code; body omitted", source)
        self.assertNotIn("void jq_get_exit_code(void)", source)
        self.assertNotIn("  jq_get_exit_code();\n  return;", source)

    def test_decompiled_c_renderer_preserves_iob_import_thunk_symbol(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___iob_func",
                    "rva_start": 0xC380,
                    "rva_end": 0xC386,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "__p__iob", "original_symbol": "___iob_func"},
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t ___iob_func(void) { __p__iob(); return; }",
                    },
                },
            ],
        )

        self.assertNotIn("#define ___iob_func __p__iob", source)
        self.assertIn(".globl ___iob_func", source)
        self.assertIn("jmp *__imp____p__iob", source)
        self.assertIn("import thunk for __p__iob; body omitted", source)

    def test_decompiled_c_renderer_preserves_contract_import_thunk_when_import_name_collides(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "__msvcrt_wgetmainargs",
                    "rva_start": 0xC3B8,
                    "rva_end": 0xC3BE,
                    "size": 6,
                    "linkage": {
                        "kind": "import_thunk",
                        "symbol": "__wgetmainargs",
                        "original_symbol": "__msvcrt_wgetmainargs",
                    },
                    "decompiler": {"status": "success", "code": "uintptr_t __msvcrt_wgetmainargs(void) { return __wgetmainargs(); }"},
                },
                {
                    "name": "__wgetmainargs",
                    "rva_start": 0xC1B0,
                    "rva_end": 0xC1B8,
                    "size": 8,
                    "decompiler": {
                        "status": "success",
                        "code": "uintptr_t __wgetmainargs(void) { return __msvcrt_wgetmainargs(); }",
                    },
                },
            ],
        )

        self.assertNotIn("#define __msvcrt_wgetmainargs __wgetmainargs", source)
        self.assertIn("extern uintptr_t __msvcrt_wgetmainargs();", source)
        self.assertIn(".globl ___msvcrt_wgetmainargs", source)
        self.assertIn("jmp *__imp____wgetmainargs", source)
        self.assertIn("return __msvcrt_wgetmainargs();", source)

    def test_decompiled_c_renderer_anchors_jq_reference_import_surface(self):
        source = _render_decompiled_c_source(target_name="jq", functions=[])

        for symbol in [
            "_AreFileApisANSI@0",
            "_GetLastError@0",
            "_GetModuleHandleA@4",
            "_GetProcAddress@8",
            "_IsDBCSLeadByteEx@8",
            "_MultiByteToWideChar@24",
            "_WideCharToMultiByte@32",
            "_Sleep@4",
            "_TlsGetValue@4",
            "_VirtualProtect@16",
            "_VirtualQuery@12",
            "_WriteFile@20",
            "__imp__SetUnhandledExceptionFilter@4",
            "__get_osfhandle",
            "_isalpha",
        ]:
            self.assertIn(
                f'"  .long {symbol} - _stage_b_jq_import_anchor\\n"',
                source,
            )
        self.assertNotIn("static void * const stage_b_jq_import_anchor[]", source)

    def test_decompiled_c_renderer_anchors_jq_atexit_through_import_alias(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            external_function_names=["atexit"],
            functions=[
                {
                    "name": "__crt_atexit",
                    "rva_start": 0xC3F0,
                    "rva_end": 0xC3F6,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "atexit", "original_symbol": "__crt_atexit"},
                    "decompiler": {"status": "success", "code": "int __cdecl __crt_atexit(void *param_1) { return atexit(param_1); }"},
                },
                {
                    "name": "atexit",
                    "rva_start": 0x1430,
                    "rva_end": 0x1435,
                    "size": 5,
                    "decompiler": {"status": "success", "code": "void __cdecl atexit(void *param_1) { atexit(param_1); }"},
                },
            ],
        )

        self.assertIn("extern uintptr_t __crt_atexit();", source)
        self.assertIn(".globl ___crt_atexit", source)
        self.assertIn("jmp *__imp__atexit", source)
        self.assertIn('"  .long ___crt_atexit - _stage_b_jq_import_anchor\\n"', source)
        self.assertNotIn('"  .long _atexit - _stage_b_jq_import_anchor\\n"', source)

    def test_decompiled_c_renderer_exposes_crt_atexit_object_alias_at_same_thunk(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            external_function_names=["atexit"],
            functions=[
                {
                    "name": "_crt_atexit",
                    "rva_start": 0xC3F0,
                    "rva_end": 0xC3F6,
                    "size": 6,
                    "linkage": {"kind": "import_thunk", "symbol": "atexit", "original_symbol": "_crt_atexit"},
                },
            ],
        )

        self.assertIn(".globl ___crt_atexit", source)
        self.assertIn(".globl __crt_atexit", source)
        self.assertIn("___crt_atexit:\\n\"\n\"__crt_atexit:", source)
        self.assertIn("jmp *__imp__atexit", source)

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
        self.assertIn("int _wmain(int argc,wchar_t **argv,wchar_t **envp)", source)
        self.assertIn("void __cdecl ___tmainCRTStartup(void)", source)
        self.assertIn(".globl _mainCRTStartup", source)
        self.assertIn('"movl $0, 0x410040\\n\\t"', source)
        self.assertIn('"jmp ____tmainCRTStartup"', source)
        self.assertIn("__wgetmainargs(&argc,(int *)&wargv,(int *)&wenv,0,&startup_info)", source)
        self.assertIn("argv = (char **)malloc((argc + 1) * sizeof(char *));", source)
        self.assertIn("argv[i][j] = (char)((ch < 0x80) ? ch : '?');", source)
        self.assertIn("rc = (int)umain(argc,(undefined4 *)argv);", source)
        self.assertNotIn("rc = _wmain(argc,wargv,wenv);", source)
        self.assertIn("exit(rc);", source)

    def test_decompiled_c_runtime_bridge_calls_wmain_when_umain_is_unavailable(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
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

        self.assertIn("rc = _wmain(argc,wargv,wenv);", source)
        self.assertNotIn("rc = (int)umain(argc,(undefined4 *)argv);", source)

    def test_decompiled_c_renderer_can_omit_mingw_crt_entries_for_crt_link_policy(self):
        functions = [
            {
                "name": "WinMainCRTStartup",
                "rva_start": 0x1410,
                "rva_end": 0x1420,
                "size": 0x10,
                "decompiler": {"status": "success", "code": "int WinMainCRTStartup(void) { return 1; }"},
            },
            {
                "name": "mainCRTStartup",
                "rva_start": 0x1420,
                "rva_end": 0x1430,
                "size": 0x10,
                "decompiler": {"status": "success", "code": "int mainCRTStartup(void) { return ___tmainCRTStartup(); }"},
            },
            {
                "name": "atexit",
                "rva_start": 0x1430,
                "rva_end": 0x1440,
                "size": 0x10,
                "decompiler": {"status": "success", "code": "int atexit(void) { return 0; }"},
            },
            {
                "name": "_DllMainCRTStartup_12",
                "aliases": ["_DllMainCRTStartup@12"],
                "rva_start": 0x1200,
                "rva_end": 0x1337,
                "size": 0x137,
                "decompiler": {
                    "status": "success",
                    "code": "int _DllMainCRTStartup_12(void) { return 1; }",
                },
            },
            {
                "name": "___do_global_ctors",
                "aliases": ["__do_global_ctors"],
                "rva_start": 0x4BD0,
                "rva_end": 0x4C32,
                "size": 0x62,
                "decompiler": {
                    "status": "success",
                    "code": "int ___do_global_ctors(void) { return 0; }",
                },
            },
            {
                "name": "___main",
                "aliases": ["__main"],
                "rva_start": 0x4C40,
                "rva_end": 0x4C5F,
                "size": 0x1F,
                "decompiler": {
                    "status": "success",
                    "code": "int ___main(void) { return ___do_global_ctors(); }",
                },
            },
            {
                "name": "___dyn_tls_init_12",
                "rva_start": 0x4CB0,
                "rva_end": 0x4D35,
                "size": 0x85,
                "aliases": ["__dyn_tls_init@12"],
                "decompiler": {
                    "status": "success",
                    "code": "ulonglong __fastcall ___dyn_tls_init_12(undefined4 a,uint b,undefined4 c,int d) {\n  return ___mingw_TLScallback(c,d);\n}",
                },
            },
            {
                "name": "___mingw_TLScallback",
                "rva_start": 0x56B0,
                "rva_end": 0x57B5,
                "size": 0x105,
                "decompiler": {
                    "status": "success",
                    "code": "undefined8 __cdecl ___mingw_TLScallback(undefined4 a,uint b) {\n  return 0;\n}",
                },
            },
            {
                "name": "__GetPEImageBase",
                "aliases": ["_GetPEImageBase"],
                "rva_start": 0x5A40,
                "rva_end": 0x5A7C,
                "size": 0x3C,
                "decompiler": {
                    "status": "success",
                    "code": "void *__GetPEImageBase(void) { return (void *)0x400000; }",
                },
            },
            {
                "name": "_gnu_exception_handler@4",
                "aliases": ["_gnu_exception_handler_4"],
                "rva_start": 0x5370,
                "rva_end": 0x5504,
                "size": 0x194,
                "decompiler": {"status": "incomplete", "code": ""},
            },
            {
                "name": "__pei386_runtime_relocator",
                "aliases": ["_pei386_runtime_relocator"],
                "rva_start": 0x4F90,
                "rva_end": 0x52F0,
                "size": 0x360,
                "decompiler": {
                    "status": "success",
                    "code": "int __pei386_runtime_relocator(void) { return 0; }",
                },
            },
            {
                "name": "___mingw_pformat",
                "rva_start": 0x7FF0,
                "rva_end": 0x8BDC,
                "size": 0xBEC,
                "decompiler": {
                    "status": "success",
                    "code": "int __cdecl ___mingw_pformat(uint flags,FILE *stream,int width,byte *fmt,float10 *args) {\n  return width;\n}",
                },
            },
            {
                "name": "__d2b_D2A",
                "rva_start": 0x8BE0,
                "rva_end": 0x8D8E,
                "size": 0x1AE,
                "decompiler": {
                    "status": "success",
                    "code": "int __cdecl __d2b_D2A(double value) {\n  return 0;\n}",
                },
            },
            {
                "name": "__strcp_D2A",
                "rva_start": 0x8D90,
                "rva_end": 0x8DC4,
                "size": 0x34,
                "decompiler": {
                    "status": "success",
                    "code": "char * __cdecl __strcp_D2A(char *dst,char *src) {\n  return dst;\n}",
                },
            },
            {
                "name": "_wmain",
                "aliases": ["wmain"],
                "rva_start": 0x490C,
                "rva_end": 0x4A07,
                "size": 0xFB,
                "decompiler": {
                    "status": "success",
                    "code": "int __cdecl _wmain(int argc,wchar_t **argv,wchar_t **envp) {\n  ___mingw_pformat(0,0,0,0,0);\n  return argc;\n}",
                },
            },
        ]
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            runtime_entry_policy="mingw-crt",
        )

        self.assertIn("MinGW CRT entry body omitted; supplied by the MinGW CRT link policy", source)
        self.assertIn("MinGW CRT support helper body omitted; supplied by the MinGW CRT link policy", source)
        self.assertNotIn("generated runtime bridge", source)
        self.assertNotIn("void __cdecl mainCRTStartup(void)", source)
        self.assertNotIn("__wgetmainargs", source)
        self.assertNotIn("int atexit(void)", source)
        self.assertNotIn("int _DllMainCRTStartup_12(void)", source)
        self.assertNotIn("int ___do_global_ctors(void)", source)
        self.assertNotIn("int ___main(void)", source)
        self.assertNotIn("ulonglong __fastcall ___dyn_tls_init_12", source)
        self.assertNotIn("undefined8 __cdecl ___mingw_TLScallback", source)
        self.assertNotIn("void *__GetPEImageBase(void)", source)
        self.assertNotIn("Stage B contract placeholder for missing decompiler body at RVA 0x5370", source)
        self.assertNotIn("int __pei386_runtime_relocator(void)", source)
        self.assertIn("#define ___main __main", source)
        self.assertIn("#define __pei386_runtime_relocator _pei386_runtime_relocator", source)
        self.assertIn("#define ___mingw_pformat __mingw_pformat", source)
        self.assertNotIn("int __cdecl ___mingw_pformat", source)
        self.assertNotIn("__attribute__((weak, noinline, used)) uintptr_t ___mingw_pformat()", source)
        self.assertNotIn("__attribute__((weak, noinline, used)) uintptr_t __mingw_pformat()", source)
        self.assertNotIn("int __cdecl __d2b_D2A", source)
        self.assertNotIn("char * __cdecl __strcp_D2A", source)
        self.assertIn("original RVA 0x7ff0, size 3052, name ___mingw_pformat", source)
        self.assertIn("original RVA 0x8be0, size 430, name __d2b_D2A", source)
        self.assertIn("original RVA 0x8d90, size 52, name __strcp_D2A", source)
        self.assertIn("int __cdecl wmain(int argc,wchar_t **argv,wchar_t **envp)", source)
        self.assertNotIn("int __cdecl _wmain(int argc,wchar_t **argv,wchar_t **envp)", source)

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["WinMainCRTStartup"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["mainCRTStartup"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["atexit"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["___dyn_tls_init_12"]["source_kind"], "omitted_runtime_helper")
        self.assertEqual(by_function["___mingw_TLScallback"]["source_kind"], "omitted_runtime_helper")
        self.assertEqual(by_function["___mingw_pformat"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["__d2b_D2A"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["__strcp_D2A"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["_wmain"]["source_kind"], "decompiled_function")
        self.assertIn("wmain", by_function["_wmain"]["aliases"])
        wmain_line = source.splitlines()[by_function["_wmain"]["line_start"] - 1]
        self.assertIn("wmain", wmain_line)

    def test_decompiled_c_source_map_marks_generated_and_omitted_runtime_entries(self):
        functions = [
            {
                "name": "___tmainCRTStartup",
                "rva_start": 0x1010,
                "rva_end": 0x1100,
                "size": 0xF0,
                "decompiler": {"status": "success", "code": "int ___tmainCRTStartup(void) { return 1; }"},
            },
            {
                "name": "mainCRTStartup",
                "rva_start": 0x1420,
                "rva_end": 0x142F,
                "size": 0xF,
                "decompiler": {"status": "success", "code": "int mainCRTStartup(void) { return ___tmainCRTStartup(); }"},
            },
            {
                "name": "___wgetmainargs",
                "rva_start": 0xC1B0,
                "rva_end": 0xC235,
                "size": 0x85,
                "decompiler": {"status": "success", "code": "int ___wgetmainargs(void) { return 0; }"},
            },
            {
                "name": "umain",
                "rva_start": 0x245E,
                "rva_end": 0x490C,
                "size": 0x24AE,
                "decompiler": {"status": "success", "code": "uintptr_t umain(int argc,undefined4 *argv) { return argc; }"},
            },
            {
                "name": "_wmain",
                "aliases": ["wmain"],
                "rva_start": 0x490C,
                "rva_end": 0x4A07,
                "size": 0xFB,
                "decompiler": {"status": "success", "code": "int _wmain(int argc,wchar_t **argv,wchar_t **envp) { return argc; }"},
            },
        ]
        source = _render_skeleton_decompiled_c_source(target_name="jq", functions=functions)

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
        )

        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["mainCRTStartup"]["source_kind"], "generated_runtime_entry_stub")
        self.assertEqual(by_function["___tmainCRTStartup"]["source_kind"], "generated_runtime_bridge")
        self.assertEqual(by_function["___wgetmainargs"]["source_kind"], "omitted_runtime_entry")
        self.assertEqual(by_function["_wmain"]["source_kind"], "decompiled_function")
        self.assertEqual(by_function["_wmain"]["aliases"], ["wmain"])
        bridge_line = source.splitlines()[by_function["___tmainCRTStartup"]["line_start"] - 1]
        self.assertIn("void __cdecl ___tmainCRTStartup(void)", bridge_line)

    def test_decompiled_c_skeleton_omits_stack_probe_helper_body(self):
        functions = [
            {
                "name": "___chkstk_ms",
                "rva_start": 0x5BF0,
                "rva_end": 0x5C1A,
                "size": 0x2A,
                "decompiler": {
                    "status": "success",
                    "code": "\n".join(
                        [
                            "uint ___chkstk_ms(void)",
                            "{",
                            "  uint in_EAX;",
                            "  undefined4 *puVar1;",
                            "  puVar1 = (undefined4 *)&stack0x00000004;",
                            "  *(undefined4 *)((int)puVar1 - in_EAX) = *(undefined4 *)((int)puVar1 - in_EAX);",
                            "  return in_EAX;",
                            "}",
                        ]
                    ),
                },
            },
            {
                "name": "_wmain",
                "aliases": ["wmain"],
                "rva_start": 0x490C,
                "rva_end": 0x4A07,
                "size": 0xFB,
                "decompiler": {
                    "status": "success",
                    "code": "int _wmain(int argc,wchar_t **argv,wchar_t **envp) {\n  return (int)___chkstk_ms();\n}",
                },
            },
        ]
        source = _render_skeleton_decompiled_c_source(target_name="jq", functions=functions)

        self.assertIn("static uintptr_t stage_b_stack_probe_size(void)", source)
        self.assertIn("#define ___chkstk_ms() stage_b_stack_probe_size()", source)
        self.assertIn("stack-probe helper body omitted", source)
        self.assertNotIn("extern uintptr_t ___chkstk_ms();", source)
        self.assertNotIn("__attribute__((weak)) uintptr_t ___chkstk_ms()", source)
        self.assertNotIn("uint ___chkstk_ms(void)", source)
        self.assertNotIn("stack0x00000004", source)
        self.assertIn("return (int)___chkstk_ms();", source)

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="decompiled-c",
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["___chkstk_ms"]["source_kind"], "omitted_runtime_helper")
        self.assertEqual(by_function["_wmain"]["source_kind"], "decompiled_function")

    def test_decompiled_c_skeleton_emits_verified_stack_probe_bytecode(self):
        functions = [
            {
                "name": "__chkstk_ms",
                "rva_start": 0x5BF0,
                "rva_end": 0x5C1A,
                "size": 0x2A,
                "reference_contract": {
                    "contract_bytecode": {
                        "status": "reimplementable",
                        "chunks": [
                            "51",
                            "50",
                            "3d00100000",
                            "8d4c240c",
                            "7215",
                            "81e900100000",
                            "830900",
                            "2d00100000",
                            "3d00100000",
                            "77eb",
                            "29c1",
                            "830900",
                            "58",
                            "59",
                            "c3",
                        ],
                    }
                },
                "decompiler": {"status": "missing"},
            }
        ]

        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=functions,
            allow_contract_bytecode=True,
        )

        self.assertIn("Stage B contract-guided bytecode: contiguous no-call semantic-transfer body", source)
        self.assertIn('".globl ___chkstk_ms\\n"', source)
        self.assertIn('".byte 0x51, 0x50, 0x3d, 0x00, 0x10, 0x00, 0x00, 0x8d, 0x4c, 0x24, 0x0c, 0x72\\n\\t"', source)
        self.assertNotIn("stack-probe helper body omitted", source)

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="contract-guided-c",
        )
        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["__chkstk_ms"]["source_kind"], "generated_contract_guided_bytecode")

    def test_decompiled_c_renderer_recovers_mingw_wmain_wide_argv_bridge(self):
        source = _render_skeleton_decompiled_c_source(
            target_name="jq",
            functions=[
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
                        "code": "\n".join(
                            [
                                "int __cdecl _wmain(int _Argc,wchar_t **_Argv,wchar_t **_Env)",
                                "{",
                                "  int iVar2;",
                                "  uint uVar3;",
                                "  UINT *pUVar4;",
                                "  UINT *pUVar5;",
                                "  int iVar8;",
                                "  undefined1 auStack_4c [44];",
                                "  undefined4 local_20;",
                                "  uVar3 = ___chkstk_ms();",
                                "  iVar8 = -uVar3;",
                                "  pUVar4 = (UINT *)(auStack_4c + iVar8);",
                                "  local_20 = (int)&local_20 + iVar8 + 3 & 0xfffffff0;",
                                "  pUVar4[7] = 0;",
                                "  *pUVar4 = 0xfde9;",
                                "  pUVar5 = pUVar4 + -1;",
                                "  WideCharToMultiByte(*pUVar4,pUVar4[1],(LPCWSTR)pUVar4[2],pUVar4[3],",
                                "                      (LPSTR)pUVar4[4],pUVar4[5],(LPCSTR)pUVar4[6],(LPBOOL)pUVar4[7]);",
                                "  uVar3 = ___chkstk_ms();",
                                "  iVar2 = -uVar3;",
                                "  *(uint *)(local_20 + iVar8 * 4) = (uint)((int)pUVar5 + iVar2 + 0xf) & 0xfffffff0;",
                                "  umain(_Argc,(undefined4 *)local_20);",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                },
            ],
        )

        self.assertIn("int __cdecl _wmain(int _Argc,wchar_t **_Argv,wchar_t **_Env)", source)
        self.assertIn("char **stage_b_wmain_argv = (char **)malloc(((size_t)_Argc + 1U) * sizeof(char *));", source)
        self.assertIn("WideCharToMultiByte(65001,0,", source)
        self.assertIn("stage_b_wmain_rc = (int)umain(_Argc,(undefined4 *)stage_b_wmain_argv);", source)
        self.assertIn("free(stage_b_wmain_argv[stage_b_wmain_i]);", source)
        self.assertNotIn("uVar3 = ___chkstk_ms();", source)
        self.assertNotIn("local_20 = (int)&local_20", source)
        self.assertNotIn("*(uint *)(local_20 + iVar8 * 4)", source)

    def test_decompiled_c_source_map_marks_multiline_definition_and_aliases(self):
        source = "\n".join(
            [
                "/* original RVA 0x8f80, size 64, name ___gdtoa */",
                "ulonglong __cdecl",
                "___gdtoa(int *param_1,int param_2,",
                "        uint *param_3)",
                "",
                "{",
                "  return 0;",
                "}",
                "",
                "/* original RVA 0x5370, size 404, name _gnu_exception_handler@4 */",
                "uintptr_t __cdecl _gnu_exception_handler_4(void)",
                "{",
                "  return 0;",
                "}",
            ]
        )

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[
                {
                    "name": "___gdtoa",
                    "aliases": ["__gdtoa"],
                    "rva_start": 0x8F80,
                    "rva_end": 0x8FC0,
                    "decompiler": {"status": "success", "code": source},
                },
                {
                    "name": "_gnu_exception_handler@4",
                    "aliases": ["_gnu_exception_handler@4"],
                    "rva_start": 0x5370,
                    "rva_end": 0x5504,
                    "decompiler": {"status": "incomplete", "code": ""},
                },
            ],
            source_language="c",
            implementation_mode="decompiled-c",
        )

        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["___gdtoa"]["source_kind"], "decompiled_function")
        self.assertEqual(by_function["___gdtoa"]["line_start"], 3)
        self.assertEqual(by_function["___gdtoa"]["aliases"], ["__gdtoa"])
        self.assertEqual(by_function["_gnu_exception_handler@4"]["line_start"], 10)
        self.assertEqual(by_function["_gnu_exception_handler@4"]["aliases"], ["_gnu_exception_handler@4", "_gnu_exception_handler_4"])

    def test_decompiled_c_source_map_aliases_generated_helper_to_section_gap_entry(self):
        source = "\n".join(
            [
                "extern uintptr_t dtoa_lock();",
                "static void stage_b_dtoa_lock_cleanup(void) {",
                "}",
                "uintptr_t dtoa_lock(void) {",
                "  return 0;",
                "}",
            ]
        )
        reference_contract = {
            "constraints": {
                "abi_callsites": {
                    "original": {
                        "functions": [
                            {
                                "name": "section-gap--text-0724",
                                "blocks": [
                                    {
                                        "block_id": "section-gap--text-0724",
                                        "rva_start": 0xAB80,
                                        "rva_end": 0xAB94,
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        }

        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=[],
            source_language="c",
            implementation_mode="decompiled-c",
            reference_contract_payload=reference_contract,
            decompiler_functions=[
                {
                    "name": "dtoa_lock",
                    "aliases": ["dtoa_lock"],
                    "rva_start": 0xAB80,
                    "rva_end": 0xAC13,
                }
            ],
        )

        by_function = {item["function"]: item for item in source_map["functions"]}
        helper = by_function["dtoa_lock"]
        self.assertEqual(helper["source_kind"], "generated_helper_from_decompiler_section_gap")
        self.assertEqual(helper["line_start"], 4)
        self.assertIn("section-gap--text-0724", helper["aliases"])
        self.assertEqual(helper["reference_section_gap"]["name"], "section-gap--text-0724")
        self.assertEqual(helper["rva_start"], 0xAB80)

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
        self.assertIn("if ((uintptr_t)out < (uintptr_t)0x10000U)", source)
        self.assertIn("if (safe_length != 0U && (uintptr_t)data < (uintptr_t)0x10000U)", source)
        self.assertIn("uintptr_t __cdecl jvp_array_alloc()\n{\n  return stage_b_jq_jvp_array_alloc(0);\n}", source)
        self.assertIn("undefined4 __cdecl jv_array(undefined4 param_1)\n{\n  return stage_b_jq_jv_array_sized(param_1,0);\n}", source)
        self.assertIn("if ((uintptr_t)param_1 < (uintptr_t)0x10000U)", source)
        self.assertIn("if ((uintptr_t)param_2 < (uintptr_t)0x10000U)", source)
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
                                "  puVar1 = __imp____acrt_iob_func;",
                                "  (*(code *)__imp____acrt_iob_func)();",
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

        self.assertIn("(*(code *)__imp____acrt_iob_func)(1);", source)
        self.assertIn("(*(code *)puVar1)(2);", source)
        self.assertIn("(*(code *)puVar1)(1);", source)
        self.assertIn("(*(code *)puVar1)(2);", source)
        self.assertNotIn("__imp____acrt_iob_func)();", source)
        self.assertNotIn("puVar1)();", source)

    def test_decompiled_c_renderer_preserves_acrt_iob_func_call_boundary(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___acrt_iob_func",
                    "rva_start": 0xC360,
                    "rva_end": 0xC377,
                    "size": 0x17,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "int __cdecl ___acrt_iob_func(int param_1)",
                                "{",
                                "  int iVar1;",
                                "  iVar1 = ___iob_func();",
                                "  return iVar1 + param_1 * 0x20;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn(
            "__attribute__((noinline, noipa, used))\nint __cdecl ___acrt_iob_func(int param_1)",
            source,
        )

    def test_decompiled_c_renderer_recovers_jq_set_colors_getenv_argument(self):
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
                                "  int iVar5;",
                                "  getenv(\"JQ_COLORS\");",
                                "  iVar5 = jq_set_colors();",
                                "  return iVar5;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn('iVar5 = jq_set_colors((char *)getenv("JQ_COLORS"));', source)
        self.assertNotIn('getenv("JQ_COLORS");\n  iVar5 = jq_set_colors();', source)

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

        self.assertIn('static int __attribute__((optimize("no-jump-tables"))) stage_b_jq_isoption_next(char **cursor, int short_mode)', source)
        self.assertIn("if (index == 0U) {", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, 'n', \"null-input\")", source)
        self.assertIn("if (index == 30U) {", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"help\")", source)
        self.assertIn("if (index == 31U) {", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, 'V', \"version\")", source)
        self.assertIn("if (index == 32U) {", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"build-configuration\")", source)
        self.assertIn("if (index == 33U) {", source)
        self.assertIn("stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"run-tests\")", source)
        self.assertNotIn("switch (index)", source)
        self.assertNotIn("case 30:", source)
        self.assertIn("LAB_00402760:\n  apcStack_3c[0] = pcVar7 + 1;\n  puVar23 = (uint *)0x1;", source)
        self.assertIn("pFVar4 = (FILE *)(*local_448)(2);", source)
        self.assertIn("joined_r0x00402777:\n  stage_b_jq_isoption_reset();", source)
        self.assertIn("uVar37 = stage_b_jq_isoption_next(&apcStack_3c[0], (int)puVar23);", source)
        self.assertNotIn("pFVar4 = (FILE *)(*local_448)();", source)
        self.assertNotIn("isoption((int)puVar23)", source)

    def test_decompiled_c_renderer_recovers_jq_oniguruma_parse_depth_limit_argument(self):
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
                                "  onig_set_parse_depth_limit();",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("onig_set_parse_depth_limit(1024);", source)
        self.assertNotIn("\n  onig_set_parse_depth_limit();\n", source)

    def test_decompiled_c_renderer_recovers_jq_compile_args_filter_lifetime(self):
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
                                "  jv_copy();",
                                "  iVar5 = jq_compile_args();",
                                "  if (iVar5 == 0) {",
                                "    return 1;",
                                "  }",
                                "  iVar5 = jq_compile_args();",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("jv_copy();\n  jv_string_value();\n  iVar5 = jq_compile_args();\n  jv_free();", source)
        self.assertEqual(source.count("\n  jv_string_value();"), 1)
        self.assertEqual(source.count("\n  jv_free();"), 1)
        self.assertEqual(source.count("iVar5 = jq_compile_args();"), 2)

    def test_decompiled_c_renderer_recovers_jq_umain_indirect_stream_arguments(self):
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
                                "  code *local_448;",
                                "  code *pcVar34;",
                                "  code *pcStack_430;",
                                "  code *pcVar2;",
                                "  FILE *pFVar4;",
                                "  int *piVar9;",
                                "  int iVar5;",
                                "  int iVar11;",
                                "  ___acrt_iob_func();",
                                "  ___acrt_iob_func();",
                                "  ___acrt_iob_func();",
                                "  ___acrt_iob_func();",
                                "  pcVar34 = local_448;",
                                "  pFVar4 = (FILE *)(*local_448)();",
                                "  iVar5 = ferror(pFVar4);",
                                "  pFVar4 = (FILE *)(*pcVar34)();",
                                "  iVar11 = fclose(pFVar4);",
                                "  piVar9 = _errno();",
                                "  strerror(*piVar9);",
                                "  pFVar4 = (FILE *)(*pcVar34)();",
                                "  ___mingw_fprintf(pFVar4,(byte *)\"jq: error: writing output failed: %s\\n\");",
                                "  pFVar4 = (FILE *)(*local_448)();",
                                "  ___mingw_fprintf(pFVar4,(byte *)",
                                "                  \"jq: --%s takes two parameters (e.g. --%s varname filename)\\n\"",
                                "          );",
                                "  pFVar4 = (FILE *)(*local_448)();",
                                "  ___mingw_fprintf(pFVar4,(byte *)\"jq: Unknown option --%s\\n\");",
                                "  pFVar4 = (FILE *)(*local_448)();",
                                "  ___mingw_fprintf(pFVar4,(byte *)\"jq: Unknown option -%c\\n\");",
                                "  pFVar4 = (FILE *)(*local_448)();",
                                "  fflush(pFVar4);",
                                "  pFVar4 = (FILE *)(*pcVar34)();",
                                "  fflush(pFVar4);",
                                "  pFVar4 = (FILE *)(*pcVar34)();",
                                "  fileno(pFVar4);",
                                "  pcVar2 = pcStack_430;",
                                "  (*pcStack_430)();",
                                "  pFVar4 = (FILE *)(*pcVar34)();",
                                "  fileno(pFVar4);",
                                "  (*pcVar2)();",
                                "  pFVar4 = (FILE *)(*pcVar34)();",
                                "  fileno(pFVar4);",
                                "  (*pcVar2)();",
                                "  return 0;",
                                "}",
                            ]
                        ),
                    },
                }
            ],
        )

        self.assertIn("#define STAGE_B_JQ_CALL_IOB_SLOT(slot, stream)", source)
        self.assertIn("pFVar4 = (FILE *)(*pcVar34)(2);\n  iVar11 = fclose(pFVar4);", source)
        self.assertIn("pFVar4 = (FILE *)(*pcVar34)(2);\n  ___mingw_fprintf", source)
        self.assertEqual(source.count("pFVar4 = STAGE_B_JQ_CALL_IOB_SLOT(local_448,2);"), 3)
        self.assertIn("pFVar4 = STAGE_B_JQ_CALL_IOB_SLOT(local_448,2);\n  ___mingw_fprintf(pFVar4,(byte *)\n                  \"jq: --%s takes two parameters", source)
        self.assertIn("pFVar4 = STAGE_B_JQ_CALL_IOB_SLOT(local_448,2);\n  ___mingw_fprintf(pFVar4,(byte *)\"jq: Unknown option --%s\\n\");", source)
        self.assertIn("pFVar4 = STAGE_B_JQ_CALL_IOB_SLOT(local_448,2);\n  ___mingw_fprintf(pFVar4,(byte *)\"jq: Unknown option -%c\\n\");", source)
        self.assertIn("pFVar4 = (FILE *)(*local_448)(1);\n  fflush(pFVar4);", source)
        self.assertIn("pFVar4 = (FILE *)(*pcVar34)(0);\n  iVar5 = fileno(pFVar4);", source)
        self.assertIn("(*pcStack_430)(iVar5,0x8000);", source)
        self.assertEqual(source.count("(*pcVar2)(iVar5,0x8000);"), 2)
        self.assertNotIn("pFVar4 = (FILE *)(*pcVar34)();", source)
        self.assertNotIn("(*pcStack_430)();", source)
        self.assertNotIn("(*pcVar2)();", source)

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

    def test_decompiled_c_source_map_classifies_import_thunk_wrapper_label(self):
        functions = [
            {
                "name": "jq_realpath",
                "rva_start": 0x4B40,
                "rva_end": 0x4B46,
                "size": 6,
                "linkage": {
                    "kind": "import_thunk",
                    "symbol": "jq_realpath",
                    "dll": "libjq-1.dll",
                    "ordinal": None,
                    "original_symbol": "jq_realpath",
                    "thunk_rva": 0x12270,
                },
                "decompiler": {"status": "missing"},
            }
        ]
        source = _render_decompiled_c_source(target_name="jq", functions=functions)
        source_map = _skeleton_source_map(
            source,
            source_rel=Path("src/jq_stage_b_skeleton.c"),
            functions=functions,
            source_language="c",
            implementation_mode="contract-guided-c",
        )

        by_function = {item["function"]: item for item in source_map["functions"]}
        self.assertEqual(by_function["jq_realpath"]["source_kind"], "omitted_import_thunk")
        self.assertEqual(source.splitlines()[by_function["jq_realpath"]["line_start"] - 1], '"_jq_realpath:\\n"')

    def test_decompiled_c_renderer_keeps_mingw_printf_wrappers_variadic(self):
        source = _render_decompiled_c_source(
            target_name="jq",
            functions=[
                {
                    "name": "___mingw_printf",
                    "rva_start": 0x8C00,
                    "rva_end": 0x8C20,
                    "size": 0x20,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "int __cdecl ___mingw_printf(byte *param_1)",
                                "{",
                                "  FILE *pFVar1;",
                                "  int iVar2;",
                                "  ",
                                "  pFVar1 = (FILE *)___acrt_iob_func(1);",
                                "  __lock_file(pFVar1);",
                                "  pFVar1 = (FILE *)___acrt_iob_func(1);",
                                "  iVar2 = ___mingw_pformat(0x6000,pFVar1,0,param_1,(float10 *)&stack0x00000008);",
                                "  pFVar1 = (FILE *)___acrt_iob_func(1);",
                                "  __unlock_file(pFVar1);",
                                "  return iVar2;",
                                "}",
                            ]
                        ),
                    },
                },
                {
                    "name": "___mingw_fprintf",
                    "rva_start": 0x6090,
                    "rva_end": 0x60B0,
                    "size": 0x20,
                    "decompiler": {
                        "status": "success",
                        "code": "\n".join(
                            [
                                "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2)",
                                "{",
                                "  int iVar1;",
                                "  ",
                                "  __lock_file(param_1);",
                                "  iVar1 = ___mingw_pformat(0x6000,param_1,0,param_2,(float10 *)&stack0x0000000c);",
                                "  __unlock_file(param_1);",
                                "  return iVar1;",
                                "}",
                            ]
                        ),
                    },
                },
            ],
        )

        self.assertIn("int __cdecl ___mingw_printf(byte *param_1,...);", source)
        self.assertIn("int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...);", source)
        self.assertIn("int __cdecl ___mingw_printf(byte *param_1,...)\n", source)
        self.assertIn("int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)\n", source)
        self.assertIn("va_start(args,param_1);", source)
        self.assertIn("stream = (FILE *)___acrt_iob_func(1);", source)
        self.assertIn("__lock_file(stream);", source)
        self.assertIn("result = ___mingw_pformat(0x6000,stream,0,param_1,(float10 *)args);", source)
        self.assertIn("__unlock_file(stream);", source)
        self.assertIn("va_start(args,param_2);", source)
        self.assertIn("__lock_file(param_1);", source)
        self.assertIn("result = ___mingw_pformat(0x6000,param_1,0,param_2,(float10 *)args);", source)
        self.assertIn("__unlock_file(param_1);", source)
        self.assertNotIn("stack0x00000008", source)
        self.assertNotIn("stack0x0000000c", source)
        self.assertNotIn("extern int vfprintf(FILE *, const char *, va_list);", source)
        self.assertNotIn("vfprintf(", source)
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

            with self.assertRaisesRegex(Exception, "incomplete_decompiler_successes"):
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
                candidate=candidate,
                linker_map_candidate=linker_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            categories = {issue["category"] for issue in result["issues"]}
            self.assertIn("skeleton_hash_mismatch", categories)
            self.assertIn("upstream_source_access", categories)
            self.assertIn("manual_behavioral_fixups", categories)
            self.assertNotIn("missing_functional_tests", categories)
            self.assertFalse((root / "report" / "stage-a").exists())

    def test_validate_candidate_runs_stage_a_contract_before_functional_evidence_gate(self):
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
            provenance_dir = root / "provenance"
            stage_b_generate_candidate_provenance(
                target_name="jq",
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate=candidate,
                build_target="i686-w64-mingw32",
                build_compiler="i686-w64-mingw32-cc",
                out=provenance_dir,
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
            write_relational_report(
                reference_report, original=original, candidate=candidate
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance_dir / "candidate-provenance.json",
                reference_contract=reference_contract,
                target_name="jq",
                out=root / "report",
            )

            self.assertEqual(result["status"], "pass")
            self.assertEqual(result["stage_a"]["verdict"], "pass")
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            self.assertEqual(result["stage_a"]["gate"]["status"], "pass")
            self.assertEqual(result["stage_a_gate"], result["stage_a"]["gate"])
            self.assertEqual(result["iteration_policy"], "stage_a_contract_first")
            self.assertEqual(result["runtime_validation_policy"], "candidate_only_after_stage_a_pass")
            written = json.loads((root / "report" / "stage-b.json").read_text(encoding="utf-8"))
            self.assertEqual(written["stage_a_gate"], written["stage_a"]["gate"])
            self.assertEqual(written["iteration_policy"], "stage_a_contract_first")
            self.assertEqual(written["runtime_validation_policy"], "candidate_only_after_stage_a_pass")
            categories = {issue["category"] for issue in result["issues"]}
            self.assertNotIn("missing_functional_tests", categories)
            self.assertNotIn("missing_functional_test_suites", categories)
            self.assertNotIn("missing_required_functional_suite", categories)
            self.assertNotIn("missing_functional_tests", result["stage_a"]["gate"]["non_blocking_issue_categories"])
            self.assertTrue((root / "report" / "stage-a").exists())

            final_mode = stage_b_validate_candidate(
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance_dir / "candidate-provenance.json",
                reference_contract=reference_contract,
                target_name="jq",
                require_functional_evidence=True,
                out=root / "final-report",
            )
            final_categories = {issue["category"] for issue in final_mode["issues"]}
            self.assertEqual(final_mode["status"], "incomplete")
            self.assertEqual(final_mode["stage_a"]["gate"]["status"], "pass")
            self.assertIn("missing_functional_tests", final_categories)
            self.assertIn("missing_functional_test_suites", final_categories)
            self.assertIn("missing_required_functional_suite", final_categories)
            self.assertIn("missing_functional_tests", final_mode["stage_a"]["gate"]["non_blocking_issue_categories"])

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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("functional_test_report_failed", categories)
            self.assertIn("functional_test_report_failed_cases", categories)
            self.assertEqual(result["stage_a"]["gate"]["status"], "blocked")
            self.assertEqual(result["stage_a"]["gate"]["reason"], "pre_stage_a_requirements_incomplete")
            self.assertFalse(result["stage_a"]["gate"]["eligible"])
            self.assertFalse(result["stage_a"]["gate"]["ran"])
            self.assertFalse(result["stage_a"]["gate"]["behavioral_mismatch_blocks_stage_a"])
            self.assertIn(
                "functional_test_report_failed",
                result["stage_a"]["gate"]["non_blocking_issue_categories"],
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("required_functional_suite_not_passing", categories)
            self.assertNotIn("missing_required_functional_suite", categories)
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            self.assertIn("required_functional_suite_not_passing", result["stage_a"]["gate"]["non_blocking_issue_categories"])
            self.assertTrue((root / "report" / "stage-a").exists())

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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("functional_test_report_missing_source_hash", categories)
            self.assertIn("functional_test_report_wrong_materializer", categories)
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            self.assertIn("functional_test_report_wrong_materializer", result["stage_a"]["gate"]["non_blocking_issue_categories"])
            self.assertTrue((root / "report" / "stage-a").exists())

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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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

            write_relational_report(
                reference_report, original=original, candidate=candidate
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=reference_contract,
                target_name="jq",
                out=root / "report",
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
            write_relational_report(
                reference_report, original=original, candidate=candidate
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
            self.assertEqual(item["likely_repair_class"], "missing_decompiler_body")
            self.assertEqual(item["generated_source_location"]["file"], "src/jq_stage_b_skeleton.c")
            self.assertTrue((root / "delta" / "stage-b-delta.json").exists())

    def test_explain_delta_reuses_validation_and_can_emit_focused_only_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            candidate_map = self._write_map(root / "candidate.map", "selected_fn")
            reference_contract = root / "reference-contract.json"
            skeleton_manifest = root / "manifest.json"
            reference_contract.write_text(
                json.dumps({"format": "stage-a-reference-contract-v1", "model": REFERENCE_CONTRACT_MODEL_ID, "families": []}),
                encoding="utf-8",
            )
            skeleton_manifest.write_text(json.dumps({"format": "stage-b-skeleton-v1", "source_map": {"functions": []}}), encoding="utf-8")
            validation = {
                "format": "stage-a-contract-candidate-validation-v1",
                "status": "incomplete",
                "verdict": "incomplete",
                "families": [],
                "issues": [],
                "counts": {"families": 0, "issues": 0},
            }
            repair_items = [
                {
                    "id": "repair:selected",
                    "violated_contract_family": "cfg",
                    "original_function": "selected_fn",
                    "likely_repair_class": "cfg_repair",
                    "next_action": "repair selected_fn",
                },
                {
                    "id": "repair:other",
                    "violated_contract_family": "cfg",
                    "original_function": "other_fn",
                    "likely_repair_class": "cfg_repair",
                    "next_action": "repair other_fn",
                },
            ]

            with patch("spaghetti_extractor.stage_b.stage_b_check_contract") as validate_candidate, patch(
                "spaghetti_extractor.stage_b._stage_b_delta_repair_items", return_value=repair_items
            ):
                result = stage_b_explain_delta(
                    reference_contract=reference_contract,
                    candidate=candidate,
                    linker_map_candidate=candidate_map,
                    skeleton_manifest=skeleton_manifest,
                    contract_candidate_validation=validation,
                    focus="selected",
                    focused_only=True,
                    out=root / "delta",
                )

            validate_candidate.assert_not_called()
            self.assertEqual(result["scope"], "focused")
            self.assertEqual(result["contract_candidate_validation_source"], "provided")
            self.assertEqual(result["candidate_contract_status"], "incomplete")
            self.assertEqual(result["counts"]["repair_items"], 1)
            self.assertEqual(result["source_counts"]["repair_items"], 2)
            self.assertEqual(result["repair_items"][0]["original_function"], "selected_fn")

    def test_diff_delta_reports_resolved_items_and_layout_synthesis(self):
        def section_item(name: str, expected_end: int, candidate_end: int) -> dict:
            expected_start = 0xE000 if name == ".rdata" else 0x1000
            candidate_start = expected_start
            return {
                "violated_contract_family": "binary_faithfulness",
                "original_function": None,
                "original_block": None,
                "generated_source_location": None,
                "likely_repair_class": "pe_section_span_layout",
                "next_action": f"adjust candidate section {name}",
                "evidence": {
                    "source": "stage-a-contract-candidate-validation",
                    "section_delta": {
                        "name": name,
                        "expected": {
                            "name": name,
                            "rva_start": expected_start,
                            "rva_end": expected_end,
                            "readable": True,
                            "writable": False,
                            "executable": False,
                        },
                        "candidate": {
                            "name": name,
                            "rva_start": candidate_start,
                            "rva_end": candidate_end,
                            "readable": True,
                            "writable": False,
                            "executable": False,
                        },
                        "delta": {
                            "rva_end": {"expected": expected_end, "candidate": candidate_end},
                            "size": {"expected": expected_end - expected_start, "candidate": candidate_end - candidate_start, "delta": candidate_end - expected_end},
                        },
                    },
                },
            }

        callsite_item = {
            "violated_contract_family": "abi_callsites",
            "original_function": "__acrt_iob_func",
            "original_block": "__acrt_iob_func-0000",
            "generated_source_location": {"file": "src/jq_stage_b_skeleton.c", "line_start": 20, "line_end": 30},
            "likely_repair_class": "call_target_mismatch",
            "next_action": "repair __acrt_iob_func call target mapping",
            "evidence": {
                "source": "stage-a-contract-candidate-validation",
                "coverage_gap": {
                    "callsite_id": "callsite:__acrt_iob_func-0000:c363",
                    "name": "__acrt_iob_func",
                },
            },
        }
        introduced_item = {
            "violated_contract_family": "abi_callsites",
            "original_function": "__mingw_fprintf",
            "original_block": "__mingw_fprintf-0000",
            "generated_source_location": {"file": "src/jq_stage_b_skeleton.c", "line_start": 40, "line_end": 50},
            "likely_repair_class": "callsite_argument_inventory_mismatch",
            "next_action": "repair __mingw_fprintf call argument order/count/roles",
            "evidence": {
                "source": "stage-a-contract-candidate-validation",
                "coverage_gap": {
                    "callsite_id": "callsite:__mingw_fprintf-0000:beef",
                    "name": "__mingw_fprintf",
                },
            },
        }
        before = {
            "format": "stage-b-delta-explanation-v1",
            "status": "incomplete",
            "counts": {"repair_items": 2},
            "repair_items": [section_item(".rdata", 0xFF6C, 0xF8BC), callsite_item],
        }
        after = {
            "format": "stage-b-delta-explanation-v1",
            "status": "incomplete",
            "counts": {"repair_items": 2},
            "repair_items": [section_item(".rdata", 0xFF6C, 0xFF5C), introduced_item],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            before_path = root / "before.json"
            after_path = root / "after.json"
            before_path.write_text(json.dumps(before), encoding="utf-8")
            after_path.write_text(json.dumps(after), encoding="utf-8")

            result = stage_b_diff_delta(before=before_path, after=after_path, out=root / "diff")

            self.assertEqual(result["format"], "stage-b-delta-diff-v1")
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["counts"]["resolved"], 1)
            self.assertEqual(result["counts"]["introduced"], 1)
            self.assertEqual(result["counts"]["persisted"], 1)
            self.assertEqual(result["counts"]["changed"], 1)
            self.assertEqual(result["resolved"][0]["original_function"], "__acrt_iob_func")
            self.assertEqual(result["introduced"][0]["original_function"], "__mingw_fprintf")
            rdata = result["layout_synthesis"]["sections"][0]
            self.assertEqual(rdata["section"], ".rdata")
            self.assertEqual(rdata["delta_bytes"], -16)
            self.assertEqual(rdata["before_delta_bytes"], -1712)
            self.assertEqual(rdata["absolute_delta_improvement_bytes"], 1696)
            self.assertEqual(rdata["source"]["operation"], "add")
            self.assertEqual(rdata["source"]["bytes"], 16)
            self.assertIn(".rdata$stage_b_layout_pad", rdata["source"]["declaration"])
            self.assertIn("gc-sections", rdata["linker_gc"]["risk"])
            self.assertIn("alignment", rdata["alignment"]["note"])
            self.assertTrue((root / "diff" / "stage-b-delta-diff.json").exists())

    def test_explain_delta_imports_unit_contracts_and_candidate_probe_repairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "tiny")
            candidate_map = self._write_map(root / "candidate.map", "tiny")
            delta_candidate_map = root / "delta-candidate.map"
            delta_candidate_map.write_text("", encoding="utf-8")
            skeleton_dir = root / "skeleton"
            stage_b_generate_skeleton(
                original=original,
                linker_map=original_map,
                target_name="jq",
                out_dir=skeleton_dir,
            )
            block_map = root / "block-map.json"
            layout_contract = root / "layout-contract.json"
            stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=block_map,
                layout_contract_out=layout_contract,
            )
            units = root / "units"
            reference_contract = root / "reference-contract.json"
            write_relational_report(
                root / "stage-a", original=original, candidate=candidate
            )
            stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                mapping=block_map,
                validation_report=root / "stage-a",
                layout_contract=layout_contract,
                unit_contract_dir=units,
                out=reference_contract,
            )
            repair_units = json.loads((units / "repair-units.json").read_text(encoding="utf-8"))
            repair_units["work_items"] = [
                {
                    "id": "work:stdio-bridge",
                    "family": "abi_callsites",
                    "category": "abi_varargs_callsite",
                    "severity": "incomplete",
                    "original_function": "tiny",
                    "original_block": "tiny:0",
                    "repair_class": "varargs_or_stdio_bridge",
                    "next_action": "repair the generated stdio varargs bridge for tiny",
                }
            ]
            (units / "repair-units.json").write_text(json.dumps(repair_units, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            probe_report = root / "candidate-probe.json"
            probe_report.write_text(
                json.dumps(
                    {
                        "format": "stage-b-candidate-probe-report-v1",
                        "status": "incomplete",
                        "probes": [
                            {
                                "id": "probe:tiny:preserved-register",
                                "status": "fail",
                                "function": "tiny",
                                "family": "abi_callsites",
                                "category": "preserved_register_mismatch",
                                "next_action": "repair candidate register save/restore in tiny",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = stage_b_explain_delta(
                reference_contract=reference_contract,
                candidate=candidate,
                linker_map_candidate=delta_candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                unit_contract_dir=units,
                candidate_probe_report=probe_report,
                out=root / "delta",
            )

            repair_classes = {item["likely_repair_class"] for item in result["repair_items"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertIn("varargs_or_stdio_bridge", repair_classes)
            self.assertIn("preserved_register_mismatch", repair_classes)
            self.assertEqual(result["unit_contracts"]["counts"]["work_items"], 1)
            self.assertEqual(result["candidate_probe_report"]["counts"]["failing"], 1)

    def test_explain_delta_ranks_contract_candidate_validation_before_unit_backlog(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 1},
                        "candidate_counts": {"functions": 1, "callsites": 0},
                        "coverage_gaps": {
                            "incomplete_callsites": [
                                {
                                    "name": "__d2b_D2A",
                                    "match_key": "__d2b_D2A",
                                    "reference_callsites": 1,
                                    "candidate_callsites": 0,
                                    "missing_callsites": 1,
                                }
                            ],
                            "counts": {
                                "missing_functions": 0,
                                "incomplete_callsite_functions": 1,
                                "missing_callsites": 1,
                            },
                        },
                    },
                }
            ]
        }
        unit_contracts = {
            "repair_units": {
                "work_items": [
                    {
                        "id": "work:__Balloc_D2A:hidden-sret",
                        "family": "abi_callsites",
                        "original_function": "__Balloc_D2A",
                        "repair_class": "hidden_sret_or_out_param",
                        "next_action": "repair __Balloc_D2A hidden sret/out-param evidence",
                    }
                ]
            }
        }
        skeleton = {
            "source_map": {
                "functions": [
                    {
                        "function": "__d2b_D2A",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 1148,
                        "line_end": 1154,
                    },
                    {
                        "function": "__Balloc_D2A",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 1090,
                        "line_end": 1130,
                    },
                ]
            }
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton=skeleton,
            candidate_functions=[],
            crash=None,
            functional=None,
            unit_contracts=unit_contracts,
        )

        callsite_item = next(item for item in result if item["original_function"] == "__d2b_D2A")
        unit_item = next(item for item in result if item["original_function"] == "__Balloc_D2A")
        self.assertEqual(callsite_item["evidence"]["source"], "stage-a-contract-candidate-validation")
        self.assertEqual(unit_item["evidence"]["source"], "stage-a-unit-contract")
        self.assertLess(callsite_item["rank"], unit_item["rank"])
        self.assertEqual(result[0]["evidence"]["source"], "stage-a-contract-candidate-validation")
        self.assertEqual(
            _count_by_evidence_source(result),
            {"stage-a-contract-candidate-validation": 2, "stage-a-unit-contract": 1},
        )

    def test_explain_delta_suppresses_unit_backlog_for_satisfied_candidate_families(self):
        validation = {
            "families": [
                {"family": "function_ranges", "status": "satisfied"},
                {"family": "import_thunks", "status": "satisfied"},
                {"family": "abi_callsites", "status": "incomplete"},
            ]
        }
        unit_contracts = {
            "repair_units": {
                "work_items": [
                    {
                        "id": "work:function:runtime-entry",
                        "family": "function_ranges",
                        "original_function": "__dyn_tls_init@12",
                        "repair_class": "tls_callback_abi",
                    },
                    {
                        "id": "work:import-thunk:__iob_func",
                        "family": "import_thunks",
                        "original_function": "__iob_func",
                        "repair_class": "import_prototype_mismatch",
                    },
                    {
                        "id": "work:abi:__Balloc_D2A",
                        "family": "abi_callsites",
                        "original_function": "__Balloc_D2A",
                        "repair_class": "hidden_sret_or_out_param",
                    },
                ]
            }
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash=None,
            functional=None,
            unit_contracts=unit_contracts,
        )

        unit_items = [item for item in result if item["evidence"].get("source") == "stage-a-unit-contract"]
        self.assertEqual([item["original_function"] for item in unit_items], ["__Balloc_D2A"])
        self.assertEqual(unit_items[0]["violated_contract_family"], "abi_callsites")
        self.assertNotIn("function_ranges", {item["violated_contract_family"] for item in unit_items})
        self.assertNotIn("import_thunks", {item["violated_contract_family"] for item in unit_items})

    def test_explain_delta_suppresses_loop_unit_covered_by_checked_semantic_region_jump(self):
        validation = {"families": [{"family": "abi_callsites", "status": "incomplete"}]}
        unit_contracts = {
            "semantic_region_contracts": [
                {
                    "id": "semantic-region:jq-section-gap-0498-to-0202",
                    "status": "checked",
                    "block_id": "section-gap--text-0498",
                    "ir": {
                        "operations": [
                            {"op": "direct_call", "target_rva": 0x61A0},
                            {"op": "direct_jump", "target_rva": 0x72D0},
                        ]
                    },
                }
            ],
            "repair_units": {
                "work_items": [
                    {
                        "id": "work:cluster:loop:section-gap--text-0498:731c",
                        "family": "abi_callsites",
                        "original_function": "section-gap--text-0498",
                        "original_block": "section-gap--text-0498",
                        "repair_class": "loop_or_state_machine",
                        "source_cluster": {
                            "cluster_kind": "abi_loop_backedge_candidate",
                            "block_id": "section-gap--text-0498",
                            "evidence": {"loop_hint": {"target_rva": 0x72D0}},
                        },
                    },
                    {
                        "id": "work:cluster:hidden-sret:section-gap--text-0202",
                        "family": "abi_callsites",
                        "original_function": "section-gap--text-0202",
                        "original_block": "section-gap--text-0202",
                        "repair_class": "hidden_sret_or_out_param",
                    },
                ]
            },
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash=None,
            functional=None,
            unit_contracts=unit_contracts,
        )

        unit_items = [item for item in result if item["evidence"].get("source") == "stage-a-unit-contract"]
        self.assertEqual([item["original_function"] for item in unit_items], ["section-gap--text-0202"])

    def test_explain_delta_ranks_explicit_contract_gap_before_candidate_abi_sample(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 2, "callsites": 2},
                        "candidate_counts": {"functions": 2, "callsites": 1},
                        "coverage_gaps": {
                            "incomplete_callsites": [
                                {
                                    "name": "__d2b_D2A",
                                    "match_key": "__d2b_D2A",
                                    "reference_callsites": 1,
                                    "candidate_callsites": 0,
                                    "missing_callsites": 1,
                                }
                            ],
                            "counts": {
                                "missing_functions": 0,
                                "incomplete_callsite_functions": 1,
                                "missing_callsites": 1,
                            },
                        },
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "_FindPESectionByName",
                                        "callsites": [
                                            {
                                                "id": "callsite:_FindPESectionByName:22df",
                                                "block_id": "_FindPESectionByName",
                                                "hidden_sret_or_out_param_evidence": {
                                                    "status": "candidate",
                                                    "address_role": "stack_out_param_or_scratch_buffer",
                                                    "address_source": {
                                                        "kind": "address",
                                                        "address_class": "stack_address",
                                                    },
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
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "__d2b_D2A",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1148,
                            "line_end": 1154,
                        },
                        {
                            "function": "_FindPESectionByName",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 976,
                            "line_end": 978,
                            "source_kind": "omitted_runtime_entry",
                        },
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        gap_item = next(item for item in result if item["original_function"] == "__d2b_D2A")
        sample_item = next(item for item in result if item["original_function"] == "_FindPESectionByName")
        self.assertEqual(gap_item["evidence"]["source"], "stage-a-contract-candidate-validation")
        self.assertIn("coverage_gap", gap_item["evidence"])
        self.assertIn("callsite", sample_item["evidence"])
        self.assertLess(gap_item["rank"], sample_item["rank"])
        self.assertEqual(result[0]["original_function"], "__d2b_D2A")

    def test_abi_coverage_gap_items_surface_callsite_and_function_mismatch_repairs(self):
        evidence = {
            "coverage_gaps": {
                "callsite_mismatches": [
                    {
                        "name": "___mingw_fprintf",
                        "block_id": "fprintf:0",
                        "repair_class": "varargs_or_stdio_bridge",
                        "next_action": "repair ___mingw_fprintf varargs/stdio bridge",
                        "issues": [{"category": "varargs_format_inventory_mismatch"}],
                    }
                ],
                "function_mismatches": [
                    {
                        "name": "jq_init",
                        "repair_class": "hidden_sret_or_out_param",
                        "next_action": "repair jq_init hidden sret/out-param representation",
                        "issues": [{"category": "register_carried_out_param_missing"}],
                    }
                ],
                "counts": {"callsite_mismatches": 1, "function_mismatches": 1},
            }
        }
        source_map = {
            "___mingw_fprintf": {"file": "src/jq_stage_b_skeleton.c", "line_start": 40, "line_end": 45},
            "jq_init": {"file": "src/jq_stage_b_skeleton.c", "line_start": 80, "line_end": 95},
        }

        items = _stage_b_abi_coverage_gap_items(evidence, source_map)

        by_function = {item["original_function"]: item for item in items}
        self.assertEqual(by_function["___mingw_fprintf"]["likely_repair_class"], "varargs_or_stdio_bridge")
        self.assertEqual(by_function["jq_init"]["likely_repair_class"], "hidden_sret_or_out_param")
        self.assertEqual(by_function["jq_init"]["generated_source_location"]["line_start"], 80)

    def test_semantic_contract_repair_items_surface_transfer_and_cluster_blockers(self):
        unit_contracts = {
            "semantic_transfer_contracts": [
                {
                    "id": "semantic-transfer:umain:42",
                    "status": "incomplete",
                    "function": "umain",
                    "block_id": "umain:42",
                    "blocker_category": "unsupported_semantics",
                    "blocker": "instruction setcc is not modeled",
                    "next_action": "add setcc transfer semantics",
                }
            ],
            "cluster_semantic_contracts": [
                {
                    "id": "semantic-cluster:switch",
                    "status": "incomplete",
                    "function": "dispatch",
                    "block_id": "dispatch:0",
                    "cluster_kind": "abi_switch_or_jump_table_candidate",
                    "repair_class": "switch_or_jump_table_dispatch",
                    "blocker": "switch table bounds are not fully recovered",
                    "next_action": "recover switch table bounds and default edge",
                }
            ],
        }
        source_map = {
            "umain": {"file": "src/jq_stage_b_skeleton.c", "line_start": 120, "line_end": 240},
            "dispatch": {"file": "src/jq_stage_b_skeleton.c", "line_start": 300, "line_end": 340},
        }

        items = _stage_b_semantic_contract_repair_items(unit_contracts, source_map)

        by_function = {item["original_function"]: item for item in items}
        self.assertEqual(by_function["umain"]["likely_repair_class"], "semantic_transfer_contract")
        self.assertEqual(by_function["umain"]["generated_source_location"]["line_start"], 120)
        self.assertEqual(by_function["dispatch"]["likely_repair_class"], "switch_or_jump_table_dispatch")

    def test_explain_delta_classifies_missing_function_range_by_source_kind(self):
        validation = {
            "families": [
                {
                    "family": "function_ranges",
                    "status": "incomplete",
                    "evidence": {"missing_functions": ["__iob_func", "regular_body"]},
                }
            ]
        }
        skeleton = {
            "source_map": {
                "functions": [
                    {
                        "function": "___iob_func",
                        "aliases": ["__iob_func"],
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 10,
                        "line_end": 12,
                        "source_kind": "omitted_import_thunk",
                    },
                    {
                        "function": "regular_body",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 20,
                        "line_end": 24,
                        "source_kind": "decompiled_function",
                    },
                ]
            }
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton=skeleton,
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        by_function = {item["original_function"]: item for item in result}
        self.assertEqual(by_function["__iob_func"]["likely_repair_class"], "import_thunk_linkage")
        self.assertIn("import thunk symbol", by_function["__iob_func"]["next_action"])
        self.assertEqual(by_function["regular_body"]["likely_repair_class"], "function_mapping")

    def test_explain_delta_prefers_stage_a_missing_function_details(self):
        validation = {
            "families": [
                {
                    "family": "function_ranges",
                    "status": "incomplete",
                    "evidence": {
                        "missing_functions": ["__iob_func", "wmain"],
                        "missing_function_details": [
                            {
                                "function": "__iob_func",
                                "category": "import_thunk_symbol_missing_with_matching_import",
                                "next_action": "preserve the original import thunk symbol for __iob_func",
                                "candidate_import_match": {"dll": "msvcrt.dll", "symbol": "__p__iob", "ordinal": None},
                            },
                            {
                                "function": "wmain",
                                "category": "runtime_entry_replaced_by_generated_bridge",
                                "next_action": "emit or retain the runtime/CRT entry/support function wmain",
                            },
                        ],
                    },
                }
            ]
        }
        skeleton = {
            "source_map": {
                "functions": [
                    {
                        "function": "___iob_func",
                        "aliases": ["__iob_func"],
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 2305,
                        "line_end": 2308,
                        "source_kind": "omitted_import_thunk",
                    },
                    {
                        "function": "_wmain",
                        "aliases": ["wmain"],
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 8477,
                        "line_end": 8480,
                        "source_kind": "omitted_runtime_entry",
                    },
                ]
            }
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton=skeleton,
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        by_function = {item["original_function"]: item for item in result}
        self.assertEqual(by_function["__iob_func"]["likely_repair_class"], "import_thunk_linkage")
        self.assertEqual(by_function["__iob_func"]["evidence"]["missing_function_detail"]["candidate_import_match"]["symbol"], "__p__iob")
        self.assertEqual(by_function["__iob_func"]["generated_source_location"]["line_start"], 2305)
        self.assertEqual(by_function["wmain"]["likely_repair_class"], "runtime_crt_function_coverage")
        self.assertEqual(by_function["wmain"]["generated_source_location"]["source_kind"], "omitted_runtime_entry")
        self.assertIn("runtime/CRT", by_function["wmain"]["next_action"])

    def test_explain_delta_splits_binary_faithfulness_layout_repairs(self):
        validation = {
            "families": [
                {
                    "family": "binary_faithfulness",
                    "status": "violated",
                    "blocker": "candidate PE layout/import/image-base target does not match the Stage A reference contract",
                    "next_action": "rebuild the candidate with matching PE target layout, imports, subsystem, and image base",
                    "evidence": {
                        "expected": {
                            "machine": "I386",
                            "bitness": 32,
                            "subsystem": "windows_cui",
                            "image_base": 0x400000,
                            "entrypoint_rva": 0x1420,
                            "sections": [
                                {
                                    "name": ".text",
                                    "rva_start": 0x1000,
                                    "rva_end": 0xC500,
                                    "executable": True,
                                    "readable": True,
                                    "writable": False,
                                },
                                {
                                    "name": ".idata",
                                    "rva_start": 0x12000,
                                    "rva_end": 0x12D00,
                                    "executable": False,
                                    "readable": True,
                                    "writable": True,
                                },
                                {
                                    "name": ".data",
                                    "rva_start": 0xD000,
                                    "rva_end": 0xD05C,
                                    "executable": False,
                                    "readable": True,
                                    "writable": True,
                                },
                            ],
                            "imports": [
                                {"dll": "msvcrt.dll", "symbol": "fprintf", "ordinal": None},
                                {"dll": "kernel32.dll", "symbol": "Sleep", "ordinal": None},
                            ],
                        },
                        "candidate": {
                            "machine": "I386",
                            "bitness": 32,
                            "subsystem": "windows_cui",
                            "image_base": 0x410000,
                            "entrypoint_rva": 0x8468,
                            "sections": [
                                {
                                    "name": ".text",
                                    "rva_start": 0x1000,
                                    "rva_end": 0xC1B4,
                                    "executable": True,
                                    "readable": True,
                                    "writable": False,
                                },
                                {
                                    "name": ".reloc",
                                    "rva_start": 0x14000,
                                    "rva_end": 0x14500,
                                    "executable": False,
                                    "readable": True,
                                    "writable": False,
                                },
                                {
                                    "name": ".data",
                                    "rva_start": 0xD000,
                                    "rva_end": 0xD0A8,
                                    "executable": False,
                                    "readable": True,
                                    "writable": True,
                                },
                            ],
                            "imports": [
                                {"dll": "msvcrt.dll", "symbol": "fprintf", "ordinal": None},
                                {"dll": "user32.dll", "symbol": "MessageBoxA", "ordinal": None},
                            ],
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "mainCRTStartup",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 4,
                            "line_end": 7,
                            "source_kind": "generated_runtime_bridge",
                            "rva_start": 0x1420,
                            "rva_end": 0x142F,
                        }
                    ]
                }
            },
            candidate_functions=[
                {
                    "name": "mainCRTStartup",
                    "rva_start": 0x8468,
                    "rva_end": 0x8500,
                }
            ],
            candidate_symbols=[
                {
                    "name": "_dtoa_CritSec",
                    "rva": 0xD060,
                    "rva_end": 0xD0A0,
                    "section": ".data",
                    "source": "section_fragment",
                    "size": 0x40,
                }
            ],
            crash=None,
            functional=None,
        )

        by_class = {item["likely_repair_class"]: item for item in result}
        self.assertEqual(by_class["pe_header_layout"]["original_function"], "pe-header")
        self.assertEqual(by_class["pe_header_layout"]["evidence"]["header_delta"]["image_base"]["expected"], 0x400000)
        entrypoint_item = by_class["runtime_crt_entrypoint_layout"]
        self.assertEqual(entrypoint_item["original_function"], "mainCRTStartup")
        self.assertEqual(entrypoint_item["generated_source_location"]["line_start"], 4)
        self.assertEqual(entrypoint_item["generated_source_location"]["source_kind"], "generated_runtime_bridge")
        self.assertEqual(entrypoint_item["evidence"]["entrypoint_delta"]["expected_function_name"], "mainCRTStartup")
        self.assertEqual(entrypoint_item["evidence"]["entrypoint_delta"]["expected_function"]["source_kind"], "generated_runtime_bridge")
        self.assertEqual(entrypoint_item["evidence"]["entrypoint_delta"]["candidate_function_name"], "mainCRTStartup")
        self.assertIn("0x1420", entrypoint_item["next_action"])
        self.assertIn("runtime/CRT entrypoint", entrypoint_item["next_action"])
        text_item = next(
            item
            for item in result
            if item["likely_repair_class"] == "pe_section_span_layout" and item["original_function"] == "section:.text"
        )
        self.assertEqual(text_item["evidence"]["section_delta"]["delta"]["size"]["delta"], -0x34C)
        self.assertIn("0x1000-0xc500", text_item["next_action"])
        data_item = next(
            item
            for item in result
            if item["likely_repair_class"] == "pe_section_span_layout" and item["original_function"] == "section:.data"
        )
        self.assertEqual(data_item["evidence"]["section_delta"]["candidate_overflow_symbols"][0]["name"], "_dtoa_CritSec")
        self.assertIn("_dtoa_CritSec at 0xd060", data_item["next_action"])
        section_table_items = [
            item for item in result if item["likely_repair_class"] == "pe_section_table_layout"
        ]
        self.assertEqual({item["original_function"] for item in section_table_items}, {"section:.idata", "section:.reloc"})
        self.assertEqual(by_class["pe_import_table_layout"]["evidence"]["import_delta"]["missing"][0]["symbol"], "Sleep")
        self.assertEqual(by_class["pe_import_table_layout"]["evidence"]["import_delta"]["extra"][0]["symbol"], "MessageBoxA")

    def test_explain_delta_splits_abi_callsites_into_actionable_repairs(self):
        skeleton = {
            "source_map": {
                "functions": [
                    {
                        "function": "foo",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 42,
                        "line_end": 53,
                    },
                    {
                        "function": "bar",
                        "file": "src/jq_stage_b_skeleton.c",
                        "line_start": 60,
                        "line_end": 70,
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
                        "coverage_gaps": {
                            "missing_functions": [
                                {
                                    "name": "bar",
                                    "match_key": "bar",
                                    "callsites": 2,
                                    "callsite_samples": [{"id": "callsite:bar:2000"}],
                                }
                            ],
                            "incomplete_callsites": [
                                {
                                    "name": "foo",
                                    "match_key": "foo",
                                    "reference_callsites": 3,
                                    "candidate_callsites": 1,
                                    "missing_callsites": 2,
                                    "reference_callsite_samples": [{"id": "callsite:foo:1000"}],
                                    "missing_callsite_signatures": [
                                        {
                                            "signature_id": "callsite-signature:0123456789abcdef",
                                            "missing": 1,
                                            "reference_count": 1,
                                            "candidate_count": 0,
                                            "signature": {
                                                "target": {
                                                    "kind": "import",
                                                    "dll": "msvcrt.dll",
                                                    "symbol": "malloc",
                                                    "ordinal": "",
                                                },
                                                "argument_inventory": {
                                                    "calling_convention": "cdecl_or_stdcall_stack",
                                                    "argument_count": 1,
                                                    "stack_roles": ["register"],
                                                    "stack_args": [
                                                        {
                                                            "index": 0,
                                                            "role": "immediate",
                                                            "source": {"kind": "immediate", "stack_offset": 0, "value": 2},
                                                        }
                                                    ],
                                                    "register_roles": [],
                                                },
                                            },
                                            "reference_examples": [
                                                {
                                                    "index": 2,
                                                    "callsite": {"id": "callsite:foo:1010", "block_id": "foo-0001"},
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                            "counts": {
                                "missing_functions": 1,
                                "incomplete_callsite_functions": 1,
                                "missing_callsites": 2,
                            },
                        },
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
        self.assertIn("abi_function_coverage", classes)
        self.assertIn("abi_callsite_function_coverage", classes)
        self.assertIn("abi_callsite_signature_coverage", classes)
        self.assertIn("hidden_sret_or_out_param", classes)
        function_item = next(item for item in result if item["likely_repair_class"] == "abi_function_coverage")
        self.assertEqual(function_item["original_function"], "bar")
        self.assertEqual(function_item["generated_source_location"]["line_start"], 60)
        signature_item = next(item for item in result if item["likely_repair_class"] == "abi_callsite_signature_coverage")
        self.assertEqual(signature_item["original_function"], "foo")
        self.assertEqual(signature_item["original_block"], "foo-0001")
        self.assertIn("recover 1 missing callsite signature for foo", signature_item["next_action"])
        self.assertIn("callsite-signature:0123456789abcdef", signature_item["next_action"])
        self.assertIn("target import msvcrt.dll!malloc", signature_item["next_action"])
        self.assertIn("example callsite:foo:1010", signature_item["next_action"])
        callsite_item = next(item for item in result if item["likely_repair_class"] == "abi_callsite_function_coverage")
        self.assertEqual(callsite_item["original_function"], "foo")
        self.assertEqual(callsite_item["generated_source_location"]["line_start"], 42)
        self.assertIn("callsite-signature:0123456789abcdef", callsite_item["next_action"])
        self.assertIn("target import msvcrt.dll!malloc", callsite_item["next_action"])
        self.assertIn("arg0=2", callsite_item["next_action"])
        self.assertIn("example callsite:foo:1010", callsite_item["next_action"])
        hidden_item = next(item for item in result if item["likely_repair_class"] == "hidden_sret_or_out_param")
        self.assertEqual(hidden_item["original_function"], "foo")
        self.assertEqual(hidden_item["generated_source_location"]["file"], "src/jq_stage_b_skeleton.c")
        self.assertEqual(hidden_item["generated_source_location"]["line_start"], 42)
        coverage_item = next(item for item in result if item["likely_repair_class"] == "abi_callsite_coverage")
        self.assertEqual(coverage_item["evidence"]["missing"], {"functions": 2, "callsites": 2})
        self.assertEqual(
            coverage_item["evidence"]["coverage_gap_counts"],
            {"missing_functions": 1, "incomplete_callsite_functions": 1, "missing_callsites": 2},
        )
        self.assertIn("1 named missing functions", coverage_item["next_action"])
        self.assertLess(function_item["rank"], coverage_item["rank"])

    def test_explain_delta_abi_coverage_guidance_prefers_callsites_when_functions_are_present(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "contract_status": "satisfied",
                    "evidence": {
                        "reference_counts": {"functions": 10, "callsites": 20},
                        "candidate_counts": {"functions": 10, "callsites": 12},
                        "coverage_gaps": {
                            "counts": {
                                "missing_functions": 0,
                                "incomplete_callsite_functions": 4,
                                "missing_callsites": 8,
                            }
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        coverage_item = next(item for item in result if item["likely_repair_class"] == "abi_callsite_coverage")
        self.assertIn("ABI callsite coverage gaps", coverage_item["next_action"])
        self.assertIn("0 functions, 8 callsites", coverage_item["next_action"])
        self.assertIn("missing callsites or mismatched call targets", coverage_item["next_action"])
        self.assertNotIn("missing linker-root/function coverage", coverage_item["next_action"])

    def test_explain_delta_classifies_missing_function_pointer_callsites(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 2},
                        "candidate_counts": {"functions": 1, "callsites": 1},
                        "coverage_gaps": {
                            "incomplete_callsites": [
                                {
                                    "name": "umain",
                                    "match_key": "umain",
                                    "reference_callsites": 2,
                                    "candidate_callsites": 1,
                                    "missing_callsites": 1,
                                    "missing_callsite_signatures": [
                                        {
                                            "signature_id": "callsite-signature:feedfacefeedface",
                                            "missing": 1,
                                            "signature": {
                                                "target": {
                                                    "kind": "function_pointer",
                                                    "operand": "dword ptr [esp + 0x64]",
                                                    "status": "unresolved",
                                                },
                                                "argument_inventory": {
                                                    "calling_convention": "cdecl_or_stdcall_stack",
                                                    "argument_count": 1,
                                                    "stack_roles": ["immediate"],
                                                    "stack_args": [
                                                        {
                                                            "index": 0,
                                                            "role": "immediate",
                                                            "source": {"kind": "immediate", "value": 2},
                                                        }
                                                    ],
                                                    "register_roles": [],
                                                },
                                            },
                                            "reference_examples": [
                                                {"index": 1, "callsite": {"id": "callsite:umain-0190:4479"}}
                                            ],
                                        }
                                    ],
                                }
                            ],
                            "counts": {"incomplete_callsite_functions": 1, "missing_callsites": 1},
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        item = next(item for item in result if item["original_function"] == "umain")
        self.assertEqual(item["likely_repair_class"], "function_pointer_callsite_coverage")
        self.assertIn("target function pointer dword ptr [esp + 0x64]", item["next_action"])
        self.assertIn("arg0=2", item["next_action"])
        self.assertIn("preserve indirect stack-slot call dword ptr [esp + 0x64]", item["next_action"])
        self.assertIn("prevent compiler folding to a direct call", item["next_action"])

    def test_explain_delta_reports_candidate_global_slot_owner(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 2},
                        "candidate_counts": {"functions": 1, "callsites": 1},
                        "coverage_gaps": {
                            "incomplete_callsites": [
                                {
                                    "name": "umain",
                                    "match_key": "umain",
                                    "reference_callsites": 2,
                                    "candidate_callsites": 1,
                                    "missing_callsites": 1,
                                    "missing_callsite_signatures": [
                                        {
                                            "signature_id": "callsite-signature:feedfacefeedface",
                                            "missing": 1,
                                            "signature": {
                                                "target": {
                                                    "kind": "function_pointer",
                                                    "operand": "esi",
                                                    "memory_role": "global_writable_pointer_slot",
                                                    "memory_rva": 0xD058,
                                                    "status": "unresolved",
                                                },
                                                "argument_inventory": {
                                                    "calling_convention": "cdecl_or_stdcall_stack",
                                                    "argument_count": 1,
                                                    "stack_roles": ["immediate"],
                                                    "stack_args": [
                                                        {
                                                            "index": 0,
                                                            "role": "immediate",
                                                            "source": {"kind": "immediate", "value": 1},
                                                        }
                                                    ],
                                                    "register_roles": [],
                                                },
                                            },
                                            "reference_examples": [
                                                {"index": 0, "callsite": {"id": "callsite:umain-0000:24b4"}}
                                            ],
                                        }
                                    ],
                                }
                            ],
                            "counts": {"incomplete_callsite_functions": 1, "missing_callsites": 1},
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            candidate_symbols=[
                {
                    "name": "_dtoa_CS_init",
                    "rva": 0xD058,
                    "rva_hex": "0xd058",
                    "section": ".data",
                    "source": "section_fragment",
                    "size": 4,
                    "rva_end": 0xD05C,
                }
            ],
            crash=None,
            functional=None,
        )

        item = next(item for item in result if item["original_function"] == "umain")
        self.assertEqual(item["likely_repair_class"], "function_pointer_callsite_coverage")
        self.assertIn("candidate RVA 0xd058", item["next_action"])
        self.assertIn("_dtoa_CS_init", item["next_action"])
        self.assertIn("preserve or relocate the reference global function-pointer slot", item["next_action"])
        context = item["evidence"]["candidate_memory_context"]
        self.assertEqual(context["symbols_at_rva"][0]["name"], "_dtoa_CS_init")
        self.assertEqual(context["symbols_at_rva"][0]["section"], ".data")

    def test_explain_delta_classifies_stack_out_param_as_scratch_buffer_verification(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 1},
                        "candidate_counts": {"functions": 1, "callsites": 1},
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "stack_bridge",
                                        "callsites": [
                                            {
                                                "id": "callsite:stack_bridge:1000",
                                                "block_id": "stack_bridge",
                                                "target": {"kind": "direct", "target_rva": 0x2000},
                                                "hidden_sret_or_out_param_evidence": {
                                                    "status": "candidate",
                                                    "address_role": "stack_out_param_or_scratch_buffer",
                                                    "address_source": {"kind": "address", "address_class": "stack_address"},
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
            skeleton={
                "source_map": {
                    "functions": [
                        {"function": "stack_bridge", "file": "src/out.c", "line_start": 30, "line_end": 40}
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        self.assertEqual(result[0]["likely_repair_class"], "stack_scratch_buffer_or_out_param")
        self.assertEqual(result[0]["original_function"], "stack_bridge")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 30)
        self.assertIn("local stack scratch/out-param", result[0]["next_action"])

    def test_explain_delta_classifies_runtime_crt_stack_bridge_separately(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 1},
                        "candidate_counts": {"functions": 1, "callsites": 1},
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "__wgetmainargs",
                                        "callsites": [
                                            {
                                                "id": "callsite:__wgetmainargs:11d3",
                                                "block_id": "__wgetmainargs",
                                                "hidden_sret_or_out_param_evidence": {
                                                    "status": "candidate",
                                                    "address_role": "stack_out_param_or_scratch_buffer",
                                                    "address_source": {
                                                        "kind": "address",
                                                        "address_class": "stack_address",
                                                    },
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
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "___wgetmainargs",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 8477,
                            "line_end": 8480,
                            "source_kind": "omitted_runtime_entry",
                        }
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        self.assertEqual(result[0]["likely_repair_class"], "runtime_crt_stack_bridge")
        self.assertEqual(result[0]["generated_source_location"]["source_kind"], "omitted_runtime_entry")
        self.assertIn("runtime/CRT support implementation", result[0]["next_action"])

    def test_explain_delta_classifies_runtime_crt_support_stack_helper_separately(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 1},
                        "candidate_counts": {"functions": 1, "callsites": 1},
                        "coverage_gaps": {
                            "missing_functions": [
                                {
                                    "name": "section-gap--text-0000",
                                    "match_key": "section-gap--text-0000",
                                    "blocks": [],
                                    "callsites": 0,
                                }
                            ],
                            "counts": {
                                "missing_functions": 1,
                                "incomplete_callsite_functions": 0,
                                "missing_callsites": 0,
                            },
                        },
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "_FindPESectionByName",
                                        "callsites": [
                                            {
                                                "id": "callsite:_FindPESectionByName:10d0",
                                                "block_id": "_FindPESectionByName",
                                                "hidden_sret_or_out_param_evidence": {
                                                    "status": "candidate",
                                                    "address_role": "stack_out_param_or_scratch_buffer",
                                                    "address_source": {
                                                        "kind": "address",
                                                        "address_class": "stack_address",
                                                    },
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
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "_FindPESectionByName",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 212,
                            "line_end": 215,
                            "source_kind": "omitted_runtime_entry",
                        }
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        by_function = {item["original_function"]: item for item in result}
        crt_item = by_function["_FindPESectionByName"]
        section_gap_item = by_function["section-gap--text-0000"]
        self.assertEqual(crt_item["likely_repair_class"], "runtime_crt_stack_bridge")
        self.assertEqual(crt_item["generated_source_location"]["source_kind"], "omitted_runtime_entry")
        self.assertIn("runtime/CRT support implementation", crt_item["next_action"])
        self.assertLess(section_gap_item["rank"], crt_item["rank"])

    def test_explain_delta_classifies_runtime_crt_function_coverage_gap(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 0},
                        "candidate_counts": {"functions": 0, "callsites": 0},
                        "coverage_gaps": {
                            "missing_functions": [
                                {
                                    "name": "_FindPESectionByName",
                                    "match_key": "FindPESectionByName",
                                    "blocks": [{"block_id": "_FindPESectionByName-0000"}],
                                    "callsites": 2,
                                }
                            ],
                            "counts": {"missing_functions": 1, "incomplete_callsite_functions": 0, "missing_callsites": 0},
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        self.assertEqual(result[0]["likely_repair_class"], "runtime_crt_function_coverage")
        self.assertEqual(result[0]["original_function"], "_FindPESectionByName")
        self.assertIn("runtime/CRT closure and linker roots", result[0]["next_action"])

    def test_explain_delta_uses_source_map_aliases_for_stdcall_sanitized_names(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 0},
                        "candidate_counts": {"functions": 0, "callsites": 0},
                        "coverage_gaps": {
                            "missing_functions": [
                                {
                                    "name": "__dyn_tls_dtor@12",
                                    "match_key": "dyn_tls_dtor",
                                    "blocks": [{"block_id": "__dyn_tls_dtor-12-0000"}],
                                    "callsites": 0,
                                }
                            ],
                            "counts": {"missing_functions": 1, "incomplete_callsite_functions": 0, "missing_callsites": 0},
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "___dyn_tls_dtor_12",
                            "aliases": ["__dyn_tls_dtor@12"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1362,
                            "line_end": 1379,
                            "source_kind": "decompiled_function",
                        }
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        self.assertEqual(result[0]["likely_repair_class"], "runtime_crt_function_coverage")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 1362)

    def test_explain_delta_classifies_specific_function_coverage_source_kinds(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 3, "callsites": 0},
                        "candidate_counts": {"functions": 0, "callsites": 0},
                        "coverage_gaps": {
                            "missing_functions": [
                                {"name": "__iob_func", "match_key": "iob_func", "blocks": [], "callsites": 0},
                                {"name": "_gnu_exception_handler@4", "match_key": "gnu_exception_handler", "blocks": [], "callsites": 0},
                                {"name": "section-gap--text-0000", "match_key": "section-gap--text-0000", "blocks": [], "callsites": 0},
                            ],
                            "counts": {"missing_functions": 3, "incomplete_callsite_functions": 0, "missing_callsites": 0},
                        },
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "___iob_func",
                            "aliases": ["__iob_func"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 2305,
                            "line_end": 2308,
                            "source_kind": "omitted_import_thunk",
                        },
                        {
                            "function": "_gnu_exception_handler@4",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 3661,
                            "line_end": 3670,
                            "source_kind": "generated_contract_placeholder",
                        },
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        by_function = {item["original_function"]: item for item in result}
        self.assertEqual(by_function["__iob_func"]["likely_repair_class"], "import_thunk_linkage")
        self.assertIn("import thunk linkage", by_function["__iob_func"]["next_action"])
        self.assertEqual(by_function["_gnu_exception_handler@4"]["likely_repair_class"], "missing_decompiler_body")
        self.assertIn("generated contract placeholder", by_function["_gnu_exception_handler@4"]["next_action"])
        self.assertEqual(by_function["section-gap--text-0000"]["likely_repair_class"], "section_gap_or_padding_coverage")
        self.assertIn("code, padding, or a section-gap artifact", by_function["section-gap--text-0000"]["next_action"])

    def test_explain_delta_classifies_indirect_call_source_roles(self):
        skeleton = {
            "source_map": {
                "functions": [
                    {"function": "global_slot", "file": "src/out.c", "line_start": 10, "line_end": 15},
                    {"function": "argument_table", "file": "src/out.c", "line_start": 20, "line_end": 25},
                ]
            }
        }
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "contract_status": "satisfied",
                    "evidence": {
                        "reference_counts": {"functions": 2, "callsites": 2},
                        "candidate_counts": {"functions": 2, "callsites": 2},
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "global_slot",
                                        "callsites": [
                                            {
                                                "id": "callsite:global_slot:1000",
                                                "block_id": "global_slot",
                                                "target": {
                                                    "kind": "function_pointer",
                                                    "operand": "eax",
                                                    "memory_role": "global_writable_pointer_slot",
                                                },
                                                "function_pointer_targets": [
                                                    {"status": "unresolved", "operand": "eax", "memory_role": "global_writable_pointer_slot"}
                                                ],
                                                "hidden_sret_or_out_param_evidence": {"status": "unknown"},
                                                "varargs_evidence": {"status": "not_observed"},
                                            }
                                        ],
                                    },
                                    {
                                        "name": "argument_table",
                                        "callsites": [
                                            {
                                                "id": "callsite:argument_table:1010",
                                                "block_id": "argument_table",
                                                "target": {
                                                    "kind": "function_pointer",
                                                    "operand": "eax",
                                                    "memory_role": "argument_pointer_deref",
                                                },
                                                "function_pointer_targets": [
                                                    {"status": "unresolved", "operand": "eax", "memory_role": "argument_pointer_deref"}
                                                ],
                                                "hidden_sret_or_out_param_evidence": {"status": "unknown"},
                                                "varargs_evidence": {"status": "not_observed"},
                                            }
                                        ],
                                    },
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

        by_function = {item["original_function"]: item for item in result}
        self.assertEqual(by_function["global_slot"]["likely_repair_class"], "global_callback_slot")
        self.assertIn("global callback", by_function["global_slot"]["next_action"])
        self.assertEqual(by_function["global_slot"]["generated_source_location"]["line_start"], 10)
        self.assertEqual(by_function["argument_table"]["likely_repair_class"], "argument_callback_table")
        self.assertIn("callback table/prototype", by_function["argument_table"]["next_action"])
        self.assertEqual(by_function["argument_table"]["generated_source_location"]["line_start"], 20)

    def test_explain_delta_classifies_ripgrep_harness_failures_from_candidate_stdout(self):
        functional = {
            "target_name": "ripgrep",
            "suite_id": "ripgrep-upstream-integration-tests",
            "coverage": {"suite_scope": "subset", "source_revision": "ripgrep-15.1.0", "case_count": 1},
            "cases": [
                {
                    "id": "ripgrep-upstream-integration-harness",
                    "status": "fail",
                    "args": ["--test-threads=1"],
                    "mismatch": {"fields": ["returncode"]},
                    "expected": {"returncode": 0},
                    "candidate": {
                        "returncode": 101,
                        "timed_out": False,
                        "stdout": {
                            "bytes": 512,
                            "preview": (
                                "\nrunning 4 tests\n"
                                "test binary::after_match1_explicit ... FAILED\n"
                                "test binary::mmap_binary_flag ... FAILED\n"
                                "test feature::f1078_max_columns_preview1 ... FAILED\n"
                                "test misc::context_stdin ... ok\n"
                                "test result: FAILED. 1 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out\n"
                            ),
                        },
                        "stderr": {"bytes": 0, "preview": ""},
                    },
                }
            ],
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "entrypoint",
                            "file": "src/ripgrep_stage_b_skeleton.rs",
                            "line_start": 20,
                            "line_end": 23,
                        }
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=functional,
        )

        by_class = {item["likely_repair_class"]: item for item in result}
        self.assertIn("ripgrep_binary_search_behavior", by_class)
        self.assertIn("ripgrep_feature_behavior", by_class)
        binary_item = by_class["ripgrep_binary_search_behavior"]
        self.assertEqual(binary_item["original_function"], "entrypoint")
        self.assertEqual(binary_item["generated_source_location"]["file"], "src/ripgrep_stage_b_skeleton.rs")
        self.assertEqual(binary_item["evidence"]["harness_test_prefix"]["prefix"], "binary")
        self.assertEqual(binary_item["evidence"]["harness_test_prefix"]["failed_tests"], 2)
        self.assertIn("binary::after_match1_explicit", binary_item["next_action"])

    def test_explain_delta_maps_generic_functional_failure_to_cli_entry_source(self):
        functional = {
            "target_name": "jq",
            "suite_id": "jq-upstream-integration-tests",
            "coverage": {"suite_scope": "full", "source_revision": "jq-1.8.1", "case_count": 1},
            "cases": [
                {
                    "id": "jq-cli-exit",
                    "status": "fail",
                    "args": ["--help"],
                    "mismatch": {"fields": ["returncode"]},
                    "expected": {"returncode": 0},
                    "candidate": {
                        "returncode": 2,
                        "timed_out": False,
                        "stdout": {"bytes": 0, "preview": ""},
                        "stderr": {"bytes": 12, "preview": "bad usage\n"},
                    },
                }
            ],
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {"function": "umain", "file": "src/jq_stage_b_skeleton.c", "line_start": 100, "line_end": 180}
                    ]
                }
            },
            candidate_functions=[],
            crash=None,
            functional=functional,
        )

        self.assertEqual(result[0]["likely_repair_class"], "cli_exit_status_behavior")
        self.assertEqual(result[0]["original_function"], "umain")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 100)
        self.assertEqual(result[0]["evidence"]["suite"]["source_revision"], "jq-1.8.1")

    def test_explain_delta_classifies_import_prototype_inventory_gap_as_import_work(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "next_action": "repair ABI evidence",
                    "evidence": {
                        "reference_counts": {"functions": 0, "callsites": 0, "import_prototypes": 12},
                        "candidate_counts": {"functions": 0, "callsites": 0, "import_prototypes": 9},
                        "candidate_abi": {"candidate": {"functions": []}},
                    },
                }
            ]
        }

        result = _stage_b_delta_repair_items(
            contract={},
            validation=validation,
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash=None,
            functional=None,
        )

        self.assertEqual(result[0]["likely_repair_class"], "import_prototype_mismatch")
        self.assertNotEqual(result[0]["likely_repair_class"], "varargs_or_stdio_bridge")

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

    def test_explain_delta_ignores_not_detected_candidate_crash_report(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "not_detected",
                "crash_kind": "",
                "stderr_preview": "",
                "repair_hints": ["no candidate crash signature detected"],
            },
            functional=None,
        )

        self.assertEqual(result, [])

    def test_extract_candidate_crash_reads_full_stderr_and_backtrace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "jq.exe"
            candidate.write_bytes(b"candidate")
            report_path = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                status="fail",
                candidate_binary=candidate,
            )
            stderr_path = root / "cases" / "identity" / "candidate.stderr"
            stderr_path.parent.mkdir(parents=True, exist_ok=True)
            stderr_text = (
                ("noise before crash\n" * 400)
                + "wine: Unhandled page fault on write access to 7BA5A716 at address 7BB482A3 (thread 0118), starting debugger...\n"
                + "Backtrace:\n"
                + "=>0 0x7BB482A3 NtRaiseException+0x43() in ntdll (0x0063f610)\n"
                + "  1 0x65741234 jq_testsuite+0x24() in libjq-1 (+0x1234) (0x0063f690)\n"
                + "Modules:\n"
                + "PE 65740000-65817000 Deferred        libjq-1\n"
            )
            stderr_path.write_text(stderr_text, encoding="utf-8")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["cases"][0]["candidate"]["returncode"] = 5
            report["cases"][0]["candidate"]["stderr"] = self._stream_artifact(stderr_path)
            report_path.write_text(json.dumps(report), encoding="utf-8")

            result = stage_b_extract_candidate_crash(
                functional_report=report_path,
                candidate=candidate,
                target_name="jq",
                out=root / "crash",
            )

            self.assertEqual(result["status"], "detected")
            self.assertEqual(result["crash_kind"], "wine_unhandled_page_fault")
            self.assertEqual(result["access"], "write")
            self.assertEqual(result["fault_address"], "0x7BA5A716")
            self.assertEqual(result["instruction_address"], "0x7BB482A3")
            self.assertEqual(result["thread"], "0118")
            self.assertEqual(result["case_id"], "identity")
            self.assertFalse(result["original_runtime_observations"])
            self.assertNotIn("Unhandled page fault", result["stderr_preview"])
            self.assertIn("Unhandled page fault", result["stderr_crash_excerpt"])
            self.assertEqual(result["backtrace"][1]["module"], "libjq-1")
            self.assertEqual(result["backtrace"][1]["rva"], "0x1234")
            self.assertEqual(result["loaded_modules"][0]["name"], "libjq-1")
            self.assertTrue((root / "crash" / "candidate-crash.json").exists())

    def test_extract_candidate_crash_reports_not_detected_for_functional_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                status="fail",
            )
            stderr_path = root / "candidate.stderr"
            stderr_path.write_text("usage mismatch only\n", encoding="utf-8")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["cases"][0]["candidate"]["stderr"] = self._stream_artifact(stderr_path)
            report_path.write_text(json.dumps(report), encoding="utf-8")

            result = stage_b_extract_candidate_crash(
                functional_report=report_path,
                out=root / "crash",
            )

            self.assertEqual(result["status"], "not_detected")
            self.assertEqual(result["crash_kind"], "")
            self.assertEqual(result["backtrace"], [])
            self.assertEqual(result["loaded_modules"], [])
            self.assertIn("no candidate crash signature", result["repair_hints"][0])

    def test_extract_candidate_crash_merges_candidate_only_seh_diagnostic_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidate = root / "jq.exe"
            candidate.write_bytes(b"candidate")
            report_path = self._write_functional_report(
                root / "functional-report.json",
                target_name="jq",
                status="fail",
                candidate_binary=candidate,
            )
            stderr_path = root / "candidate.stderr"
            stderr_path.write_text(
                "wine: Unhandled page fault on write access to 7BA5A716 at address 7BB482A3 (thread 0118), starting debugger...\n",
                encoding="utf-8",
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["cases"][0]["candidate"]["stderr"] = self._stream_artifact(stderr_path)
            report_path.write_text(json.dumps(report), encoding="utf-8")

            diagnostic_path = self._write_functional_report(
                root / "diagnostic-functional-report.json",
                target_name="jq",
                status="fail",
                candidate_binary=candidate,
            )
            noisy_diagnostic_stderr = root / "diagnostic-version.stderr"
            noisy_diagnostic_stderr.write_text(
                "002c:fixme:ntdll:init_logical_proc_info diagnostic noise before the real failing case\n",
                encoding="utf-8",
            )
            diagnostic_stderr = root / "diagnostic.stderr"
            diagnostic_stderr.write_text(
                "\n".join(
                    [
                        "0024:trace:seh:dispatch_exception code=c0000005 (EXCEPTION_ACCESS_VIOLATION) flags=0 addr=7A7382A3",
                        "0024:trace:seh:dispatch_exception  info[0]=00000001",
                        "0024:trace:seh:dispatch_exception  info[1]=7BB4A716",
                        "0024:trace:seh:dispatch_exception eip=7a7382a3 esp=0061f808 ebp=0061f818 eflags=00010202",
                        "0024:trace:seh:dispatch_exception eax=7bb4a716 ebx=004016f0 ecx=00000000 edx=c90cec82",
                        "0024:trace:seh:dispatch_exception esi=00000000 edi=00256878 cs=0023 ds=002b es=002b fs=0063 gs=006b ss=002b",
                        "wine: Unhandled page fault on write access to 7BB4A716 at address 7A7382A3 (thread 0024), starting debugger...",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))
            diagnostic_case = diagnostic["cases"][0]
            noisy_case = json.loads(json.dumps(diagnostic_case))
            noisy_case["id"] = "version"
            noisy_case["candidate"]["stderr"] = self._stream_artifact(noisy_diagnostic_stderr)
            diagnostic_case["candidate"]["stderr"] = self._stream_artifact(diagnostic_stderr)
            diagnostic["cases"] = [noisy_case, diagnostic_case]
            diagnostic_path.write_text(json.dumps(diagnostic), encoding="utf-8")

            result = stage_b_extract_candidate_crash(
                functional_report=report_path,
                diagnostic_functional_report=diagnostic_path,
                candidate=candidate,
                target_name="jq",
                out=root / "crash",
            )

            self.assertEqual(result["status"], "detected")
            self.assertEqual(result["instruction_address"], "0x7BB482A3")
            self.assertIsNotNone(result["diagnostic_functional_report"])
            self.assertIsNotNone(result["diagnostic_stderr_artifact"])
            self.assertEqual(result["diagnostic_stderr_artifact"]["path"], str(diagnostic_stderr))
            self.assertEqual(result["seh_exception"]["code"], "0xC0000005")
            self.assertEqual(result["seh_exception"]["access"], "write")
            self.assertEqual(result["seh_exception"]["fault_address"], "0x7BB4A716")
            self.assertEqual(result["seh_exception"]["registers"]["ebx"], "0x004016F0")

    def test_explain_delta_maps_candidate_crash_pc_inside_image_to_source(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {"function": "crashing_func", "file": "src/out.c", "line_start": 70, "line_end": 80}
                    ]
                }
            },
            candidate_functions=[
                {"name": "crashing_func", "rva_start": 0x1000, "rva_end": 0x1100},
            ],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "instruction_address": "0x401020",
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "stack_delta_mismatch")
        self.assertEqual(result[0]["original_function"], "crashing_func")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 70)
        self.assertEqual(result[0]["evidence"]["candidate_location"]["classification"], "inside_candidate_image")
        self.assertEqual(result[0]["evidence"]["candidate_location"]["rva"], 0x1020)

    def test_explain_delta_maps_candidate_crash_pc_inside_generated_module_to_source(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            candidate_modules=[
                {
                    "name": "libjq-1.dll",
                    "path": "build/libjq-1.dll",
                    "image": {"image_base": 0x65740000, "size_of_image": 0xC000, "image_end": 0x65800000},
                    "functions": [{"name": "jq_testsuite", "rva_start": 0x1200, "rva_end": 0x1300}],
                    "source_map": {
                        "jq_testsuite": {
                            "file": "src/jq-libjq-1_stage_b_skeleton.c",
                            "line_start": 410,
                            "line_end": 455,
                        }
                    },
                }
            ],
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "instruction_address": "0x65741234",
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "stack_delta_mismatch")
        self.assertEqual(result[0]["original_function"], "jq_testsuite")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 410)
        self.assertEqual(result[0]["evidence"]["candidate_location"]["classification"], "inside_candidate_module_image")
        self.assertEqual(result[0]["evidence"]["candidate_location"]["module"]["name"], "libjq-1.dll")
        self.assertEqual(result[0]["evidence"]["candidate_location"]["rva"], 0x1234)

    def test_explain_delta_maps_candidate_backtrace_frame_inside_generated_module(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            candidate_modules=[
                {
                    "name": "libjq-1.dll",
                    "image": {"image_base": 0x65740000, "size_of_image": 0xC000, "image_end": 0x65800000},
                    "functions": [{"name": "jv_string", "rva_start": 0x1210, "rva_end": 0x1260}],
                    "source_map": {
                        "jv_string": {
                            "file": "src/jq-libjq-1_stage_b_skeleton.c",
                            "line_start": 120,
                            "line_end": 140,
                        }
                    },
                }
            ],
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "instruction_address": "0x7BB482A3",
                "backtrace": [
                    {"index": 0, "module": "ntdll.dll", "address": "0x7BB482A3"},
                    {"index": 1, "module": "libjq-1.dll", "address": "65741234"},
                ],
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["original_function"], "jv_string")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 120)
        self.assertEqual(result[0]["evidence"]["candidate_location"]["classification"], "candidate_backtrace_frame")
        self.assertEqual(result[0]["evidence"]["candidate_location"]["frame_index"], 1)
        self.assertEqual(result[0]["evidence"]["candidate_location"]["module"]["name"], "libjq-1.dll")
        self.assertEqual(result[0]["evidence"]["candidate_location"]["rva"], 0x1234)

    def test_explain_delta_maps_candidate_seh_register_context_to_source(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "__dyn_tls_init@12",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1700,
                            "line_end": 1725,
                        }
                    ]
                }
            },
            candidate_functions=[
                {"name": "__dyn_tls_init@12", "rva_start": 0x16F0, "rva_end": 0x1780},
            ],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_page_fault",
                "instruction_address": "0x7BB482A3",
                "seh_exception": {
                    "code": "0xC0000005",
                    "registers": {
                        "eip": "0x7BB482A3",
                        "eax": "0x7BA5A716",
                        "ebx": "0x004016F0",
                    },
                },
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "candidate_crash_register_context")
        self.assertEqual(result[0]["original_function"], "__dyn_tls_init@12")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 1700)
        self.assertEqual(result[0]["evidence"]["candidate_location"]["classification"], "outside_candidate_image")
        register_context = result[0]["evidence"]["candidate_location"]["candidate_register_context"]
        self.assertEqual(register_context["classification"], "candidate_seh_register")
        self.assertEqual(register_context["register"], "ebx")
        self.assertEqual(register_context["rva"], 0x16F0)
        self.assertIn("SEH context", result[0]["next_action"])

    def test_explain_delta_classifies_seh_register_context_in_omitted_runtime_helper(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "__dyn_tls_init@12",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1344,
                            "line_end": 1347,
                            "source_kind": "omitted_runtime_helper",
                        }
                    ]
                }
            },
            candidate_functions=[
                {"name": "__dyn_tls_init@12", "rva_start": 0x16F0, "rva_end": 0x1780},
            ],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_page_fault",
                "instruction_address": "0x7BB482A3",
                "seh_exception": {
                    "code": "0xC0000005",
                    "registers": {
                        "eip": "0x7BB482A3",
                        "ebx": "0x004016F0",
                    },
                },
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "runtime_crt_tls_callback_context")
        self.assertEqual(result[0]["original_function"], "__dyn_tls_init@12")
        self.assertEqual(result[0]["generated_source_location"]["source_kind"], "omitted_runtime_helper")
        self.assertIn("TLS callback", result[0]["next_action"])

    def test_explain_delta_classifies_stack_probe_crash_separately(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "___chkstk_ms",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 2100,
                            "line_end": 2115,
                            "source_kind": "decompiled_function",
                        }
                    ]
                }
            },
            candidate_functions=[
                {"name": "___chkstk_ms", "rva_start": 0x2E50, "rva_end": 0x2E80},
            ],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_page_fault",
                "access": "write",
                "fault_address": "0x0040D0C0",
                "instruction_address": "0x00402E63",
                "stderr_preview": "wine: Unhandled page fault on write access to 0040D0C0 at address 00402E63\n",
                "repair_hints": ["inspect ABI, stack, hidden sret/out-param evidence"],
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "stack_probe_or_frame_layout")
        self.assertEqual(result[0]["original_function"], "___chkstk_ms")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 2100)
        self.assertIn("stack-probe", result[0]["next_action"])
        self.assertEqual(result[0]["evidence"]["candidate_location"]["rva"], 0x2E63)

    def test_explain_delta_classifies_stack_overflow_in_linked_stack_probe(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "___chkstk_ms",
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 1176,
                            "line_end": 1178,
                            "source_kind": "omitted_runtime_helper",
                        }
                    ]
                }
            },
            candidate_functions=[
                {"name": "__chkstk_ms", "rva_start": 0x2620, "rva_end": 0x264C},
            ],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_stack_overflow",
                "instruction_address": "0x00402633",
                "stderr_preview": "wine: Unhandled stack overflow at address 00402633\n",
                "repair_hints": ["candidate-only crash", "stack overflow during public jq upstream suite"],
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "stack_probe_or_frame_layout")
        self.assertEqual(result[0]["original_function"], "__chkstk_ms")
        self.assertEqual(result[0]["generated_source_location"]["source_kind"], "omitted_runtime_helper")
        self.assertEqual(result[0]["evidence"]["candidate_location"]["rva"], 0x2633)

    def test_explain_delta_classifies_wmain_stack_scratch_write_fault(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={
                "source_map": {
                    "functions": [
                        {
                            "function": "_wmain",
                            "aliases": ["wmain"],
                            "file": "src/jq_stage_b_skeleton.c",
                            "line_start": 6038,
                            "line_end": 6150,
                            "source_kind": "decompiled_function",
                        }
                    ]
                }
            },
            candidate_functions=[
                {"name": "_wmain", "rva_start": 0xD074, "rva_end": 0xD3E0},
            ],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_page_fault",
                "access": "write",
                "fault_address": "0xFDE90040",
                "instruction_address": "0x0040D22C",
                "stderr_preview": "wine: Unhandled page fault on write access to FDE90040 at address 0040D22C\n",
                "repair_hints": ["candidate-only crash", "inspect ABI and stack scratch recovery"],
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "stack_scratch_buffer_or_out_param")
        self.assertEqual(result[0]["original_function"], "_wmain")
        self.assertEqual(result[0]["generated_source_location"]["line_start"], 6038)
        self.assertIn("local stack scratch", result[0]["next_action"])
        self.assertEqual(result[0]["evidence"]["candidate_location"]["rva"], 0xD22C)

    def test_explain_delta_ranks_external_module_crash_behind_source_mapped_abi_repairs(self):
        validation = {
            "families": [
                {
                    "family": "abi_callsites",
                    "status": "incomplete",
                    "evidence": {
                        "reference_counts": {"functions": 1, "callsites": 1},
                        "candidate_counts": {"functions": 1, "callsites": 1},
                        "candidate_abi": {
                            "candidate": {
                                "functions": [
                                    {
                                        "name": "needs_abi_fix",
                                        "callsites": [
                                            {
                                                "id": "callsite:needs_abi_fix:1000",
                                                "block_id": "needs_abi_fix",
                                                "target": {"kind": "direct", "target_rva": 0x2000},
                                                "argument_sources": [],
                                                "hidden_sret_or_out_param_evidence": {
                                                    "status": "candidate",
                                                    "reason": "test",
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
            skeleton={
                "source_map": {
                    "functions": [
                        {"function": "needs_abi_fix", "file": "src/out.c", "line_start": 20, "line_end": 30}
                    ]
                }
            },
            candidate_functions=[],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "instruction_address": "0x7BB48767",
            },
            functional=None,
        )

        hidden_item = next(item for item in result if item["likely_repair_class"] == "hidden_sret_or_out_param")
        crash_item = next(item for item in result if item["likely_repair_class"] == "candidate_crash_external_module")
        self.assertLess(hidden_item["rank"], crash_item["rank"])
        self.assertIsNone(crash_item["original_function"])
        self.assertIn("outside the candidate image", crash_item["next_action"])
        self.assertEqual(crash_item["evidence"]["candidate_location"]["classification"], "outside_candidate_image")

    def test_explain_delta_ranks_external_pc_fault_into_candidate_image_as_pointer_context(self):
        result = _stage_b_delta_repair_items(
            contract={},
            validation={"families": []},
            skeleton={"source_map": {"functions": []}},
            candidate_functions=[],
            candidate_binary={"image_base": 0x400000, "size_of_image": 0x20000},
            crash={
                "format": "stage-b-candidate-crash-v1",
                "status": "detected",
                "crash_kind": "wine_unhandled_page_fault",
                "access": "write",
                "instruction_address": "0x7BB0165B",
                "fault_address": "0x0040E0F3",
                "seh_exception": {
                    "code": "0xC0000005",
                    "fault_address": "0x0040E0F3",
                    "info": {"0": "0x00000001", "1": "0x0040E0F3"},
                    "registers": {
                        "eip": "0x7BB0165B",
                        "eax": "0x0040E0F3",
                    },
                },
            },
            functional=None,
        )

        self.assertEqual(result[0]["violated_contract_family"], "candidate_crash")
        self.assertEqual(result[0]["likely_repair_class"], "candidate_crash_fault_address_context")
        self.assertIsNone(result[0]["original_function"])
        self.assertIn("fault address points into the candidate image", result[0]["next_action"])
        location = result[0]["evidence"]["candidate_location"]
        self.assertEqual(location["classification"], "outside_candidate_image")
        fault_context = location["candidate_fault_context"]
        self.assertEqual(fault_context["classification"], "candidate_fault_address")
        self.assertEqual(fault_context["rva"], 0xE0F3)

    def test_validate_candidate_reports_contract_only_failure_diagnostics(self):
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIsNone(result["stage_a"]["map_status"])
            self.assertNotEqual(result["stage_a"]["verdict"], "pass")
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            diagnostics = result["stage_a"]["diagnostics"]
            self.assertEqual(diagnostics["format"], "stage-b-stage-a-diagnostics-v1")
            self.assertEqual(diagnostics["status"], "incomplete")
            self.assertEqual(diagnostics["map"]["status"], "not_run")
            self.assertIsNone(diagnostics["artifacts"]["generated_block_map"])
            self.assertIsNone(diagnostics["artifacts"]["generated_layout_contract"])
            self.assertEqual(diagnostics["validation"]["status"], result["stage_a"]["verdict"])
            self.assertTrue((root / "report" / "stage-a" / "verdict.json").is_file())
            self.assertFalse((root / "report" / "generated" / "block-map.json").exists())

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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
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
                candidate=candidate,
                linker_map_candidate=candidate_map,
                skeleton_manifest=skeleton_dir / "manifest.json",
                candidate_provenance=provenance,
                functional_report=functional_report,
                reference_contract=self._write_static_reference_contract(root / "reference-contract.json", original),
                target_name="jq",
                out=root / "report",
            )

            categories = {issue["category"] for issue in result["issues"]}
            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(result["provenance_status"], "incomplete")
            self.assertIn("functional_binary_hash_mismatch", categories)
            self.assertTrue(result["stage_a"]["gate"]["ran"])
            self.assertIn("functional_binary_hash_mismatch", result["stage_a"]["gate"]["non_blocking_issue_categories"])
            self.assertTrue((root / "report" / "stage-a").exists())

    def _write_pe(self, path: Path, code: bytes) -> Path:
        path.write_bytes(_pe32_image(code))
        return path

    def _write_static_reference_contract(self, path: Path, original: Path) -> Path:
        stage_a_export_reference_contract(original=original, out=path)
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
