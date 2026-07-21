from __future__ import annotations

import json
import hashlib
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.analyses.segments import (
    _segment_refinement_candidates,
)
from spaghetti_extractor.relational.executor import _run_lean_relational
from spaghetti_extractor.relational.extraction import (
    _extract_relational_behaviors,
)
from spaghetti_extractor.relational.pipeline import stage_a_prepare_relational
from spaghetti_extractor.relational.schema import (
    RELATIONAL_ENVIRONMENT_ID,
    RELATIONAL_OBSERVATIONS,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


class StageAReverseSentinelScannerIntegrationTests(unittest.TestCase):
    _LAYOUT = {
        0: (0x100F, 7),
        1: (0x1016, 2),
        2: (0x1000, 9),
        3: (0x1009, 2),
        4: (0x1040, 4),
        5: (0x1044, 17),
        6: (0x1055, 2),
        7: (0x1057, 2),
        8: (0x100B, 4),
        9: (0x1018, 5),
        10: (0x1059, 1),
        11: (0x101D, 2),
    }

    @staticmethod
    def _relocation_block(page_rva: int, offsets: list[int]) -> bytes:
        entries = [0x3000 | offset for offset in offsets]
        if len(entries) % 2:
            entries.append(0)
        return (
            struct.pack("<II", page_rva, 8 + 2 * len(entries))
            + struct.pack("<" + "H" * len(entries), *entries)
        )

    @classmethod
    def _scanner_image(cls, data_rva: int, *, empty: bool = False) -> bytes:
        image_base = 0x400000
        table_base = image_base + data_rva
        text = bytearray(b"\x90" * 0x5A)

        # Header, scanner gate, bounded table call, and reverse-count loop.
        text[0x00:0x09] = (
            b"\xa1" + struct.pack("<I", table_base) + b"\x85\xc0\xeb\x00"
        )
        text[0x09:0x0B] = b"\x75\x35"
        text[0x0B:0x0F] = b"\x85\xc0\x74\x0e"
        text[0x0F:0x16] = b"\xff\x14\x85" + struct.pack("<I", table_base)
        text[0x16:0x18] = b"\xeb\xfe"
        text[0x18:0x1D] = b"\x83\xe8\x01\x75\xf2"
        text[0x1D:0x1F] = b"\xeb\xfe"

        # Split scanner body and test. The body writes ZF, then the test consumes it.
        text[0x40:0x44] = b"\x31\xc9\xeb\x00"
        text[0x44:0x55] = (
            b"\x89\xc8\x83\xc1\x01\x8b\x14\x8d"
            + struct.pack("<I", table_base)
            + b"\x83\xfa\x00\xeb\x00"
        )
        text[0x55:0x57] = b"\x75\xed"
        text[0x57:0x59] = b"\xeb\xb2"
        text[0x59] = 0xC3

        table = struct.pack(
            "<III", 0xFFFFFFFF, 0 if empty else image_base + 0x1059, 0
        )
        relocations = cls._relocation_block(0x1000, [0x01, 0x12, 0x4C])
        if not empty:
            relocations += cls._relocation_block(data_rva, [0x04])

        dos = bytearray(0x80)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x80)
        coff = struct.pack("<HHIIIHH", 0x014C, 3, 0, 0, 0, 224, 0x010F)
        optional = struct.pack(
            "<HBB" + "I" * 9 + "H" * 6 + "I" * 4 + "H" * 2 + "I" * 6,
            0x10B,
            0,
            0,
            0x200,
            0x200,
            0,
            0x1000,
            0x1000,
            data_rva,
            image_base,
            0x1000,
            0x200,
            4,
            0,
            0,
            0,
            4,
            0,
            0,
            0x6000,
            0x200,
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
        directories = bytearray(16 * 8)
        struct.pack_into("<II", directories, 5 * 8, 0x5000, len(relocations))
        sections = b"".join(
            (
                struct.pack(
                    "<8sIIIIIIHHI",
                    b".text\0\0\0",
                    len(text),
                    0x1000,
                    0x200,
                    0x200,
                    0,
                    0,
                    0,
                    0,
                    0x60000020,
                ),
                struct.pack(
                    "<8sIIIIIIHHI",
                    b".rdata\0\0",
                    len(table),
                    data_rva,
                    0x200,
                    0x400,
                    0,
                    0,
                    0,
                    0,
                    0x40000040,
                ),
                struct.pack(
                    "<8sIIIIIIHHI",
                    b".reloc\0\0",
                    len(relocations),
                    0x5000,
                    0x200,
                    0x600,
                    0,
                    0,
                    0,
                    0,
                    0x42000040,
                ),
            )
        )
        headers = (
            bytes(dos) + b"PE\0\0" + coff + optional + bytes(directories) + sections
        ).ljust(0x200, b"\0")
        return (
            headers
            + bytes(text).ljust(0x200, b"\0")
            + table.ljust(0x200, b"\0")
            + relocations.ljust(0x200, b"\0")
        )

    @classmethod
    def _relation_contract(cls) -> dict[str, object]:
        registers = [
            {"original": register, "candidate": register}
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        ]
        return {
            "format": "stage-a-relation-contract-v1",
            "environment": {"id": RELATIONAL_ENVIRONMENT_ID},
            "observations": RELATIONAL_OBSERVATIONS,
            "code_targets": [
                {"id": index, "original_rva": rva, "candidate_rva": rva}
                for index, (rva, _size) in cls._LAYOUT.items()
            ],
            "value_targets": [
                {
                    "id": 0,
                    "original_value": 0x402000,
                    "candidate_value": 0x403000,
                    "original_relocation_rva": 0x1001,
                    "candidate_relocation_rva": 0x1001,
                    "mapped_size": 12,
                }
            ],
            "regions": [
                {
                    "id": f"scanner-region-{index}",
                    "function_id": "reverse-sentinel-scanner",
                    "function_block_index": index,
                    "function_cut_index": 0,
                    "root": index in {2, 9},
                    "original": {
                        "rva": cls._LAYOUT[index][0],
                        "size": cls._LAYOUT[index][1],
                    },
                    "candidate": {
                        "rva": cls._LAYOUT[index][0],
                        "size": cls._LAYOUT[index][1],
                    },
                    "inputs": registers,
                    "outputs": registers,
                }
                for index in range(len(cls._LAYOUT))
            ],
            "padding": [
                {
                    "id": "scanner-gap",
                    "side": "both",
                    "rva": 0x101F,
                    "size": 0x21,
                }
            ],
            "memory_relation": {"mode": "identity"},
        }

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for scanner proofs")
    def test_generated_reverse_sentinel_scanner_certificates_kernel_compile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original_data = self._scanner_image(0x2000)
            candidate_data = self._scanner_image(0x3000)
            original.write_bytes(original_data)
            candidate.write_bytes(candidate_data)
            relation = root / "relation.json"
            relation.write_text(json.dumps(self._relation_contract()), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=relation,
                out=prepared,
            )
            self.assertEqual(result["status"], "prepared", result)

            generated_paths = sorted(
                path
                for path in prepared.rglob("*")
                if path.is_file() and path.suffix in {".json", ".lean"}
            )
            generated_hashes = {
                str(path.relative_to(prepared)): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in generated_paths
            }

            lean_dir = prepared / "lean"
            stage_a_dir = lean_dir / "StageA"
            contract = json.loads(
                (prepared / "relation-contract.json").read_text(encoding="utf-8")
            )
            memory_contracts = json.loads(
                (prepared / "relational-memory-contracts.json").read_text(
                    encoding="utf-8"
                )
            )
            register_relations = json.loads(
                (prepared / "relational-register-relations.json").read_text(
                    encoding="utf-8"
                )
            )
            bounded_report = json.loads(
                (prepared / "relational-bounded-table-call-inputs.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                bounded_report["status"], "candidate_requires_lean_replay"
            )
            self.assertEqual(len(bounded_report["candidates"]), 1)

            original_bin = _parse_stage_a_pe(original)
            candidate_bin = _parse_stage_a_pe(candidate)
            behaviors, extraction = _extract_relational_behaviors(
                lean_dir,
                original_bin,
                candidate_bin,
                original_data,
                candidate_data,
                contract,
                use_cache=True,
            )
            self.assertIsNotNone(behaviors, extraction)
            assert behaviors is not None
            self.assertIn("flags := some", behaviors[6]["original"])
            self.assertIn("flags := some", behaviors[6]["candidate"])

            for region_index in (5, 6, 7):
                for relation_key in ("input_relations", "output_relations"):
                    self.assertIn(
                        "edx",
                        {
                            relation["original"]
                            for relation in contract["regions"][region_index][
                                relation_key
                            ]
                        },
                    )
            self.assertIn(6, contract["regions"][6]["flag_inputs"])
            self.assertNotIn(
                "edx",
                {
                    claim["output"]["original"]
                    for claim in register_relations["regions"][5]["output_claims"]
                },
            )

            diagnostics: list[dict[str, object]] = []
            candidates = _segment_refinement_candidates(
                contract,
                behaviors,
                memory_contracts,
                register_relations,
                diagnostics=diagnostics,
                original_bin=original_bin,
                candidate_bin=candidate_bin,
                bounded_table_call_candidates=bounded_report["candidates"],
            )
            scanner_candidates = sorted(
                (
                    item
                    for item in candidates
                    if item.get("reverse_sentinel_scanner_claim") is not None
                ),
                key=lambda item: int(item["edge_index"]),
            )
            self.assertEqual(
                [item["certificate_profile"] for item in scanner_candidates],
                [
                    "composable_reverse_sentinel_scanner_v1",
                    "composable_reverse_sentinel_scanner_loop_v1",
                    "composable_reverse_sentinel_scanner_exit_v1",
                ],
                diagnostics,
            )
            self.assertEqual(
                [
                    item.get("guard_relation_claim", {}).get("profile")
                    for item in scanner_candidates[1:]
                ],
                [
                    "input_flags_guard_v1",
                    "input_flags_guard_v1",
                ],
            )
            self.assertEqual(
                scanner_candidates[0][
                    "reverse_sentinel_scanner_register_transfer_claim"
                ]["profile"],
                "reverse_sentinel_scanner_register_transfer_v1",
            )
            self.assertEqual(
                scanner_candidates[0][
                    "reverse_sentinel_scanner_register_transfer_claim"
                ]["output"],
                {
                    "original": "edx",
                    "candidate": "edx",
                    "relation": "related_word",
                },
            )
            self.assertEqual(
                scanner_candidates[0]["flag_transfer_claim"]["profile"],
                "reverse_sentinel_scanner_flags_v1",
            )
            bridge_diagnostic = next(
                item
                for item in diagnostics
                if item["source_region_index"] == 7
                and item["target_region_index"] == 8
            )
            self.assertTrue(bridge_diagnostic["eligible"], bridge_diagnostic)
            bridge_candidate = next(
                item
                for item in candidates
                if item["source_region_index"] == 7
                and item["target_region_index"] == 8
            )
            self.assertEqual(
                bridge_candidate["certificate_profile"],
                "composable_local_no_write_v1",
            )

            segment_modules = sorted(
                stage_a_dir.glob("RelationalSegmentRefinementChunk*.lean")
            )
            scanner_modules = sorted(
                {
                    module
                    for scanner_candidate in scanner_candidates
                    for module in segment_modules
                    if (
                        "segmentRefinementEdge"
                        f"{scanner_candidate['edge_index']}"
                        "ReverseSentinelScannerClaim"
                    )
                    in module.read_text(encoding="utf-8")
                }
            )
            self.assertEqual(len(scanner_modules), 2, scanner_modules)

            generated = "".join(
                module.read_text(encoding="utf-8") for module in scanner_modules
            )
            self.assertIn(".checked staticProofContext", generated)
            self.assertIn(".loopChecked", generated)
            self.assertIn(".exitChecked", generated)
            self.assertEqual(
                generated.count("inputFlagsGuard_eval_equal_of_checked"), 2
            )
            self.assertIn(
                "reverseSentinelScannerPostconditionClosed_of_checked", generated
            )
            self.assertIn(
                "reverseSentinelScannerLoadedOutputRelated_of_checked", generated
            )
            self.assertIn(
                "reverseSentinelScannerZeroFlagRelated_of_checked", generated
            )
            self.assertIn(
                "reverseSentinelScannerLoopBoundClosed_of_checked", generated
            )
            self.assertIn(
                "reverseSentinelScannerFinishedPostconditionClosed_of_checked",
                generated,
            )
            self.assertNotIn("OriginalScannerBehavior", generated)
            self.assertNotIn("CandidateScannerBehavior", generated)
            for module in scanner_modules:
                with self.subTest(module=module.stem):
                    checked = _run_lean_relational(lean_dir, bundle=module.stem)
                    self.assertEqual(checked["status"], "checked", checked)
                    self.assertNotIn("sorryAx", checked["stdout"])

            self.assertEqual(
                generated_hashes,
                {
                    str(path.relative_to(prepared)): hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                    for path in generated_paths
                },
                "kernel checking must not rewrite generated proof inputs",
            )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required for scanner proofs")
    def test_empty_table_call_is_closed_only_by_checked_guard_contradiction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(self._scanner_image(0x2000, empty=True))
            candidate.write_bytes(self._scanner_image(0x3000, empty=True))
            contract = self._relation_contract()
            for region in contract["regions"]:
                region["root"] = region["id"] == "scanner-region-2"
            relation = root / "relation.json"
            relation.write_text(json.dumps(contract), encoding="utf-8")
            prepared = root / "prepared"

            result = stage_a_prepare_relational(
                original=original,
                candidate=candidate,
                relation_contract=relation,
                out=prepared,
            )
            self.assertEqual(result["status"], "prepared", result)
            bounded = json.loads(
                (prepared / "relational-bounded-table-call-inputs.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(len(bounded["candidates"]), 1, bounded)
            table = bounded["candidates"][0]
            self.assertEqual(table["upper_exclusive"], 1)
            self.assertEqual(table["rows"], [])
            self.assertEqual(table["target_ids"], [])
            self.assertNotIn("bound", table)

            generated = sorted(
                (prepared / "lean" / "StageA").glob(
                    "RelationalSegmentRefinementEdge*.lean"
                )
            )
            contradiction_modules = [
                path
                for path in generated
                if "RegisterZeroGuardContradictionClaim"
                in path.read_text(encoding="utf-8")
            ]
            self.assertEqual(len(contradiction_modules), 1, contradiction_modules)
            source = contradiction_modules[0].read_text(encoding="utf-8")
            self.assertIn(
                "segmentTransitionClosed_of_register_zero_guard_contradiction",
                source,
            )
            self.assertIn("import StageA.RelationalStaticContextBase", source)
            self.assertNotIn("import StageA.RelationalStaticContext\n", source)
            self.assertNotIn("RelationalRegisterRelationsChunk", source)
            self.assertNotIn("axiom", source)
            checked = _run_lean_relational(
                prepared / "lean", bundle=contradiction_modules[0].stem
            )
            self.assertEqual(checked["status"], "checked", checked)
            self.assertNotIn("sorryAx", checked["stdout"])


if __name__ == "__main__":
    unittest.main()
