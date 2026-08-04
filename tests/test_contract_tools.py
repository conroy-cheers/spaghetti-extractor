from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.cli import _build_parser
from spaghetti_extractor.contract_tools import (
    BlockMapping,
    _semantic_fpu_state_from_observables,
    _semantic_transfer_contract,
    _semantic_transfer_contracts,
    _symbolic_execute,
    _unit_contract_ids_for_obligation,
    _unit_contract_obligation_lookup,
)
from spaghetti_extractor.relational.contract import stage_a_generate_relation_contract
from spaghetti_extractor.relational.mapping import stage_a_generate_map
from spaghetti_extractor.relational.reference_contract import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_export_reference_contract,
    stage_a_smoke_contract,
)
from spaghetti_extractor.stage_binary import BlockSide, StageAInputError, _parse_stage_a_pe
from spaghetti_extractor.util import sha256_file

from contract_fixtures import write_relational_report
from pe_fixtures import pe32_image, pe32_import_image
from stage_a_relational_support import _pe32_image_with_immutable_indirect_call


class ContractToolTests(unittest.TestCase):
    def test_exact_x87_replay_is_retained_without_legacy_state_changes(self):
        replay = {
            "architecture": "x86",
            "bitness": 32,
            "rva_start": 0x1000,
            "rva_end": 0x1001,
            "bytes": "9b",
        }

        result = _semantic_fpu_state_from_observables(
            {},
            native_exact_command_replay=replay,
        )

        self.assertEqual(
            result["model"],
            "native_exact_x87_command_replay_obligation_v1",
        )
        self.assertEqual(result["status"], "required")
        self.assertEqual(
            result["missing_or_invalid_fields"],
            [
                "stack",
                "tags",
                "control",
                "status",
                "pending_exception",
                "last_opcode",
                "instruction_pointer",
                "code_selector",
                "data_pointer",
                "data_selector",
            ],
        )
        self.assertEqual(result["replay"]["rva_start"], 0x1000)
        self.assertEqual(result["replay"]["bytes"], "9b")

    def test_relation_contract_isolates_x87_in_single_instruction_cutpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex("90d9e890ebfa")
            original = self._write_pe(root / "original.exe", code)
            candidate = self._write_pe(root / "candidate.exe", code)
            mapping = root / "mapping.json"
            mapping.write_text(
                json.dumps({
                    "blocks": [{
                        "id": "mixed-loop",
                        "kind": "code",
                        "original": {"rva": 0x1000, "size": len(code)},
                        "candidate": {"rva": 0x1000, "size": len(code)},
                    }]
                }),
                encoding="utf-8",
            )
            contract = root / "relation.json"

            result = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=contract,
            )

            self.assertEqual(result["status"], "generated", result)
            regions = json.loads(contract.read_text(encoding="utf-8"))["regions"]
            self.assertEqual(
                [
                    (row["original"]["rva_start"], row["original"]["size"])
                    for row in regions
                ],
                [(0x1000, 1), (0x1001, 2), (0x1003, 3)],
            )
            self.assertEqual(regions[1]["candidate"]["rva_start"], 0x1001)
            self.assertEqual(regions[1]["candidate"]["size"], 2)

    def test_obligation_lookup_indexes_relational_location_prefixes(self):
        lookup = _unit_contract_obligation_lookup(
            [{"id": "block:source", "block_id": "source"}],
            [{"id": "function:target", "function": "target"}],
            [{"id": "cluster:other", "cluster_kind": "other"}],
        )

        self.assertEqual(
            _unit_contract_ids_for_obligation(
                "segment:source:target:17", lookup,
            ),
            ["block:source", "function:target"],
        )
        self.assertEqual(
            _unit_contract_ids_for_obligation(
                "memory-transition:source", lookup,
            ),
            ["block:source"],
        )
        self.assertEqual(
            _unit_contract_ids_for_obligation("other", lookup),
            ["cluster:other"],
        )

    def test_cli_exposes_one_stage_a_authority_and_candidate_only_stage_b_tools(self):
        parser = _build_parser(prog=None)
        subcommands = parser._subparsers._group_actions[0].choices

        self.assertIn("stage-a-prove", subcommands)
        self.assertIn("stage-a-check-proof", subcommands)
        self.assertIn("stage-a-export-interfaces", subcommands)
        self.assertIn("stage-a-fuzz-generate", subcommands)
        self.assertIn("stage-a-fuzz-run", subcommands)
        self.assertIn("stage-b-check-contract", subcommands)
        self.assertIn("stage-b-audit-contract", subcommands)
        self.assertIn("stage-b-augment-rooted-views", subcommands)
        self.assertNotIn("stage-a-legacy-validate", subcommands)
        self.assertNotIn("stage-a-prove-relational", subcommands)
        self.assertNotIn("stage-a-validate-contract-candidate", subcommands)
        removed_internal_generators = {
            "stage-a-generate-interpreter-kernel",
            "stage-a-generate-interpreter-kernel-lookup",
            "stage-a-generate-interpreter-kernel-step",
            "stage-a-generate-interpreter-kernel-invoke",
            "stage-a-generate-interpreter-kernel-run",
            "stage-a-generate-interpreter-mixed-kernel-binding",
        }
        self.assertTrue(
            removed_internal_generators.isdisjoint(subcommands),
            removed_internal_generators.intersection(subcommands),
        )
        self.assertNotIn("workspace-prune", subcommands)
        self.assertNotIn(
            "--executor",
            subcommands["stage-a-build-relational"]._option_string_actions,
        )

    def test_generate_map_is_reproducible_for_identical_pe32_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            original_map = self._write_map(root / "original.map", "entry")
            candidate_map = self._write_map(root / "candidate.map", "entry")

            first = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "first.json",
            )
            second = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "second.json",
            )

            self.assertEqual(first, second)
            self.assertEqual(first["status"], "pass")
            self.assertGreater(first["counts"]["blocks"], 0)

    def test_generate_map_rejects_import_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_import_image(b"\xc3", symbol="WriteFile"))
            candidate.write_bytes(pe32_import_image(b"\xc3", symbol="ReadFile"))
            original_map = self._write_map(root / "original.map", "entry")
            candidate_map = self._write_map(root / "candidate.map", "entry")

            result = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=root / "map.json",
            )

            self.assertEqual(result["status"], "incomplete")
            self.assertIn("import", json.dumps(result["issues"]).lower())

    def test_import_thunk_map_projects_complete_function_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex("ff25402040009090")
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            original.write_bytes(pe32_import_image(code, symbol="WriteFile"))
            candidate.write_bytes(pe32_import_image(code, symbol="WriteFile"))
            original_map = self._write_map(root / "original.map", "write_file_thunk")
            candidate_map = self._write_map(root / "candidate.map", "write_file_thunk")
            mapping = root / "mapping.json"

            generated_map = stage_a_generate_map(
                original=original,
                candidate=candidate,
                linker_map_original=original_map,
                linker_map_candidate=candidate_map,
                out=mapping,
            )

            self.assertEqual(generated_map["status"], "pass", generated_map)
            block = json.loads(mapping.read_text(encoding="utf-8"))["blocks"][0]
            self.assertEqual(block["source"]["kind"], "import_thunk")
            self.assertEqual(block["source"]["function_block_index"], 0)

            relation = root / "relation.json"
            generated_relation = stage_a_generate_relation_contract(
                original=original,
                candidate=candidate,
                mapping=mapping,
                out=relation,
            )

            self.assertEqual(generated_relation["status"], "generated", generated_relation)
            region = json.loads(relation.read_text(encoding="utf-8"))["regions"][0]
            self.assertEqual(region["function_id"], "write_file_thunk")
            self.assertEqual(region["function_block_index"], 0)
            self.assertEqual(region["function_cut_index"], 0)
            self.assertTrue(region["function_entry"])

    def test_reference_contract_binds_relational_v3_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            report = write_relational_report(
                root / "report", original=original, candidate=candidate
            )

            contract = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                validation_report=report,
                out=root / "reference-contract.json",
            )

            binding = contract["constraints"]["validation_report_artifact_binding"]
            proof = contract["constraints"]["proof_obligation_inventory"]
            self.assertEqual(contract["model"], REFERENCE_CONTRACT_MODEL_ID)
            self.assertEqual(binding["status"], "satisfied")
            self.assertEqual(proof["status"], "satisfied")

    def test_reference_contract_rejects_tampered_proof_ir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            report = write_relational_report(
                root / "report", original=original, candidate=candidate
            )
            proof_ir = report / "relational-proof-ir.json"
            proof_ir.write_text(proof_ir.read_text(encoding="utf-8") + "\n", encoding="utf-8")

            contract = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                validation_report=report,
                out=root / "reference-contract.json",
            )

            binding = contract["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(binding["status"], "incomplete")
            self.assertFalse(binding["checks"]["proof_ir"])

    def test_reference_contract_binds_non_authoritative_prepared_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            report = write_relational_report(
                root / "report",
                original=original,
                candidate=candidate,
                status="incomplete",
            )
            (report / "verdict.json").unlink()
            proof_ir = report / "relational-proof-ir.json"
            (report / "prepared-proof.json").write_text(json.dumps({
                "format": "stage-a-prepared-relational-v1",
                "status": "prepared",
                "profile": "x86-pe32-lean-relational-v3",
                "model": REFERENCE_CONTRACT_MODEL_ID,
                "original_sha256": sha256_file(original),
                "candidate_sha256": sha256_file(candidate),
                "proof_ir_sha256": sha256_file(proof_ir),
            }), encoding="utf-8")
            (report / "verdict.json").write_text("{}", encoding="utf-8")

            contract = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                validation_report=report / "prepared-proof.json",
                out=root / "reference-contract.json",
            )

            binding = contract["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(binding["status"], "satisfied", binding)
            self.assertEqual(binding["report_kind"], "relational_v3_prepared")
            self.assertEqual(binding["verdict"], "incomplete")
            self.assertFalse(binding["acceptance_authority"])

    def test_reference_contract_binds_v2_prepared_proof_artifact_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            report = write_relational_report(
                root / "report",
                original=original,
                candidate=candidate,
                status="incomplete",
            )
            (report / "verdict.json").unlink()
            proof_ir = report / "relational-proof-ir.json"
            artifact_manifest = report / "artifact-manifest.json"
            artifact_manifest.write_text("{}\n", encoding="utf-8")
            prepared = report / "prepared-proof.json"
            prepared.write_text(json.dumps({
                "format": "stage-a-prepared-relational-v2",
                "status": "prepared",
                "profile": "x86-pe32-lean-relational-v3",
                "model": REFERENCE_CONTRACT_MODEL_ID,
                "original_sha256": sha256_file(original),
                "candidate_sha256": sha256_file(candidate),
                "proof_ir_sha256": sha256_file(proof_ir),
                "artifact_manifest_sha256": sha256_file(artifact_manifest),
            }), encoding="utf-8")

            contract = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                validation_report=prepared,
                out=root / "reference-contract.json",
            )

            binding = contract["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(binding["status"], "satisfied", binding)
            self.assertTrue(binding["checks"]["artifact_manifest"])

            artifact_manifest.write_text("{\"tampered\": true}\n", encoding="utf-8")
            contract = stage_a_export_reference_contract(
                original=original,
                candidate=candidate,
                validation_report=prepared,
                out=root / "tampered-reference-contract.json",
            )
            binding = contract["constraints"]["validation_report_artifact_binding"]
            self.assertEqual(binding["status"], "incomplete", binding)
            self.assertFalse(binding["checks"]["artifact_manifest"])

    def test_reference_contract_rejects_v2_without_artifact_manifest_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            candidate = self._write_pe(root / "candidate.exe", b"\xc3")
            report = write_relational_report(
                root / "report",
                original=original,
                candidate=candidate,
                status="incomplete",
            )
            (report / "verdict.json").unlink()
            proof_ir = report / "relational-proof-ir.json"
            prepared = report / "prepared-proof.json"
            prepared.write_text(json.dumps({
                "format": "stage-a-prepared-relational-v2",
                "status": "prepared",
                "profile": "x86-pe32-lean-relational-v3",
                "model": REFERENCE_CONTRACT_MODEL_ID,
                "original_sha256": sha256_file(original),
                "candidate_sha256": sha256_file(candidate),
                "proof_ir_sha256": sha256_file(proof_ir),
            }), encoding="utf-8")

            with self.assertRaisesRegex(StageAInputError, "relational v3"):
                stage_a_export_reference_contract(
                    original=original,
                    candidate=candidate,
                    validation_report=prepared,
                    out=root / "reference-contract.json",
                )

    def test_reference_contract_rejects_v2_report_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            report = root / "report"
            report.mkdir()
            (report / "verdict.json").write_text(
                json.dumps({"profile": "x86-pe32-env-v1"}), encoding="utf-8"
            )

            with self.assertRaisesRegex(StageAInputError, "relational v3"):
                stage_a_export_reference_contract(
                    original=original,
                    validation_report=report,
                    out=root / "reference-contract.json",
                )

    def test_smoke_contract_checks_emitted_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", b"\xc3")
            contract_path = root / "reference-contract.json"
            stage_a_export_reference_contract(original=original, out=contract_path)

            self.assertEqual(
                stage_a_smoke_contract(reference_contract=contract_path)["status"],
                "pass",
            )
            (root / "coverage_gaps.json").unlink()
            self.assertEqual(
                stage_a_smoke_contract(reference_contract=contract_path)["status"],
                "incomplete",
            )

    def test_reference_contract_tree_uses_ca_stable_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            export = root / "export"
            export.mkdir()
            original = self._write_pe(export / "original.exe", b"\xc3")
            mapping = export / "mapping.json"
            mapping.write_text("{}", encoding="utf-8")
            contract_path = export / "reference-contract.json"

            contract = stage_a_export_reference_contract(
                original=original,
                mapping=mapping,
                out=contract_path,
                sidecar_dir=export,
                unit_contract_dir=export,
            )

            self.assertEqual(contract["inputs"]["original"]["path"], "original.exe")
            self.assertEqual(contract["inputs"]["mapping"]["path"], "mapping.json")
            for path in export.iterdir():
                if path.suffix in {".json", ".jsonl"}:
                    self.assertNotIn(str(export), path.read_text(encoding="utf-8"))
            coverage = json.loads(
                (export / "coverage_gaps.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                coverage["reference_contract"]["path"],
                "reference-contract.json",
            )

    def test_semantic_transfer_models_register_bit_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", bytes.fromhex("0fa3c8"))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1003)
            mapping = BlockMapping(
                id="bt-register",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "bt_register"},
            )

            symbolic = _symbolic_execute(
                binary,
                side,
                binary.pe.get_data(side.rva_start, side.size),
                "original",
                mapping,
            )
            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "bt_register",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(symbolic["status"], "ok", symbolic)
            self.assertEqual(symbolic["observables"]["flag:cf"][0], "bool_eq")
            self.assertEqual(transfer["status"], "reimplementable", transfer)
            self.assertEqual(transfer["counts"]["faults"], 0)
            carry = next(item["value"] for item in transfer["flag_writes"] if item["flag"] == "cf")
            self.assertEqual(carry["op"], "eq_bool")
            self.assertIn("lshr32", json.dumps(carry))

    def test_symbolic_execution_models_32_bit_inc_dec_and_preserves_carry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = {
                "inc-register": bytes.fromhex("40"),
                "dec-register": bytes.fromhex("48"),
                "inc-memory": bytes.fromhex("ff00"),
                "dec-memory": bytes.fromhex("ff08"),
            }
            for name, encoded in cases.items():
                with self.subTest(name=name):
                    original = self._write_pe(root / f"{name}.exe", encoded)
                    binary = _parse_stage_a_pe(original)
                    side = BlockSide(0x1000, 0x1000 + len(encoded))
                    mapping = BlockMapping(
                        id=name,
                        original=side,
                        candidate=side,
                        kind="code",
                        reachable=True,
                        invariant_checked=True,
                        source={"function": name},
                    )

                    symbolic = _symbolic_execute(
                        binary,
                        side,
                        binary.pe.get_data(side.rva_start, side.size),
                        "original",
                        mapping,
                    )

                    self.assertEqual(symbolic["status"], "ok", symbolic)
                    observables = symbolic["observables"]
                    self.assertEqual(observables["flag:cf"], ("flag", "cf"))
                    for flag in ("zf", "sf", "of", "pf"):
                        self.assertNotEqual(
                            observables[f"flag:{flag}"],
                            ("flag", flag),
                        )
                    if name.endswith("register"):
                        operation = "add" if name.startswith("inc") else "sub"
                        self.assertEqual(observables["reg:eax"][0], operation)
                    else:
                        memory_events = observables["memory_events"]
                        self.assertEqual(
                            [event[0] for event in memory_events],
                            ["read", "write"],
                        )

    def test_symbolic_execution_rejects_unqualified_16_bit_inc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encoded = bytes.fromhex("6640")
            original = self._write_pe(root / "inc16.exe", encoded)
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="inc16",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "inc16"},
            )

            symbolic = _symbolic_execute(
                binary,
                side,
                binary.pe.get_data(side.rva_start, side.size),
                "original",
                mapping,
            )

            self.assertEqual(symbolic["status"], "incomplete")
            self.assertIn("only 32-bit inc/dec", symbolic["blocker"])

    def test_semantic_transfer_adds_fs_base_to_segmented_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encoded = bytes.fromhex("648b00")
            original = self._write_pe(root / "original.exe", encoded)
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="fs-load",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "fs_load"},
            )

            symbolic = _symbolic_execute(
                binary,
                side,
                binary.pe.get_data(side.rva_start, side.size),
                "original",
                mapping,
            )
            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "fs_load",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(symbolic["status"], "ok", symbolic)
            eax = next(
                write["value"]
                for write in transfer["register_writes"]
                if write["register"] == "eax"
            )
            self.assertEqual(eax["op"], "load")
            self.assertEqual(eax["address"]["op"], "add32")
            self.assertIn(
                {"op": "fs_base", "width": 32}, eax["address"]["args"]
            )

    def test_semantic_transfer_exports_large_rep_stosd_as_symbolic_fill(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encoded = bytes.fromhex("b9b9000000f3ab")
            original = self._write_pe(root / "original.exe", encoded)
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="rep-stosd",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "rep_stosd"},
            )

            symbolic = _symbolic_execute(
                binary,
                side,
                binary.pe.get_data(side.rva_start, side.size),
                "original",
                mapping,
            )
            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "rep_stosd",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(symbolic["status"], "ok", symbolic)
            event = transfer["external_events"][0]
            self.assertEqual(
                (event["kind"], event["index"], event["effect_model"]),
                ("rep_stosd", 0, "symbolic_string_fill_v1"),
            )
            self.assertEqual(event["destination"]["name"], "edi")
            self.assertEqual(event["value"]["name"], "eax")
            self.assertEqual(event["count"]["value"], 185)
            self.assertEqual(event["direction_flag"]["name"], "df")
            writes = {
                item["register"]: item["value"]
                for item in transfer["register_writes"]
            }
            self.assertEqual(writes["ecx"], {"op": "const", "width": 32, "value": 0})
            self.assertEqual(writes["edi"]["op"], "add32")
            self.assertIn('"value": 740', json.dumps(writes["edi"]))

    def test_semantic_transfer_canonicalizes_repeated_byte_adds_compactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            encoded = bytes.fromhex("0404" * 16)
            original = self._write_pe(root / "original.exe", encoded)
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="repeated-byte-adds",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "repeated_byte_adds"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "repeated_byte_adds",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            self.assertLess(len(json.dumps(transfer)), 200_000)

    def test_rep_stosd_supports_symbolic_count_and_retains_small_unroll(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            symbolic_path = self._write_pe(
                root / "symbolic.exe", bytes.fromhex("f3ab")
            )
            bounded_path = self._write_pe(
                root / "bounded.exe", bytes.fromhex("b902000000f3ab")
            )
            results = {}
            for name, path, size in (
                ("symbolic", symbolic_path, 2),
                ("bounded", bounded_path, 7),
            ):
                binary = _parse_stage_a_pe(path)
                side = BlockSide(0x1000, 0x1000 + size)
                mapping = BlockMapping(
                    id=f"rep-stosd-{name}",
                    original=side,
                    candidate=side,
                    kind="code",
                    reachable=True,
                    invariant_checked=True,
                    source={"function": f"rep_stosd_{name}"},
                )
                results[name] = _symbolic_execute(
                    binary,
                    side,
                    binary.pe.get_data(side.rva_start, side.size),
                    "original",
                    mapping,
                )

            self.assertEqual(results["symbolic"]["status"], "ok")
            symbolic_event = results["symbolic"]["observables"]["external_events"][0]
            self.assertEqual(symbolic_event[0], "rep_stosd")
            self.assertEqual(symbolic_event[4], ("reg", "ecx"))
            self.assertEqual(
                results["symbolic"]["observables"]["reg:ecx"], ("const", 0)
            )
            self.assertEqual(results["bounded"]["status"], "ok")
            self.assertEqual(
                results["bounded"]["observables"]["external_events"], ()
            )
            self.assertEqual(
                len(results["bounded"]["observables"]["memory_events"]), 2
            )

    def test_semantic_transfer_exports_complete_import_call_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            original.write_bytes(
                pe32_import_image(bytes.fromhex("ff1540204000"), symbol="WriteFile")
            )
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1006)
            mapping = BlockMapping(
                id="write-file-call",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "write_file_call"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "write_file_call",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            self.assertEqual(len(transfer["external_events"]), 1)
            event = transfer["external_events"][0]
            self.assertEqual(event["kind"], "external_call")
            self.assertEqual(event["dll"].lower(), "kernel32.dll")
            self.assertEqual(event["symbol"], "WriteFile")
            self.assertEqual(event["return_rva"], 0x1006)
            self.assertEqual(event["input_model"], "captured_machine_call_boundary_v1")
            self.assertEqual(
                set(event["register_inputs"]),
                {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"},
            )
            self.assertEqual(set(event["flag_inputs"]), {"cf", "zf", "sf", "of", "pf", "df"})
            self.assertEqual(
                transfer["ordered_events"][0],
                {"family": "external", "instruction_rva": 0x1000, **event},
            )

    def test_call_stack_inputs_sample_memory_after_register_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            encoded = bytes.fromhex(
                "8954240c"  # mov [esp+12], edx
                "8b54245c"  # mov edx, [esp+92]
                "89542410"  # mov [esp+16], edx
                "ff1540204000"  # call [WriteFile]
            )
            original.write_bytes(pe32_import_image(encoded, symbol="WriteFile"))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(encoded))
            mapping = BlockMapping(
                id="stack-input-register-reuse",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "stack_input_register_reuse"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "stack_input_register_reuse",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            event = transfer["external_events"][0]
            stack_inputs = {
                item["offset"]: item["value"] for item in event["stack_inputs"]
            }
            self.assertEqual(set(stack_inputs), {12, 16})
            for offset in (12, 16):
                self.assertEqual(stack_inputs[offset]["op"], "load")
                self.assertEqual(stack_inputs[offset]["width"], 4)
                self.assertEqual(stack_inputs[offset]["address"]["op"], "add32")
                self.assertIn(
                    {"op": "const", "width": 32, "value": offset},
                    stack_inputs[offset]["address"]["args"],
                )
            self.assertNotEqual(
                stack_inputs[12],
                {"op": "reg", "width": 32, "name": "edx"},
            )

    def test_semantic_transfer_keeps_writable_refptr_jump_indirect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            original.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030, writable=True, jump=True,
            ))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1006)
            mapping = BlockMapping(
                id="writable-refptr-jump",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "writable_refptr_jump"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "writable_refptr_jump",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            self.assertEqual(transfer["outcome"], {
                "kind": "indirect_jump",
                "target": {
                    "op": "load",
                    "width": 4,
                    "address": {
                        "op": "const",
                        "width": 32,
                        "value": binary.image_base + 0x2000,
                    },
                },
            })
            self.assertEqual(transfer["edge_conditions"], [])

    def test_semantic_transfer_may_normalize_immutable_refptr_jump(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original.exe"
            original.write_bytes(_pe32_image_with_immutable_indirect_call(
                0x2000, callee_rva=0x1030, writable=False, jump=True,
            ))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1006)
            mapping = BlockMapping(
                id="immutable-refptr-jump",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "immutable_refptr_jump"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "immutable_refptr_jump",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            self.assertEqual(
                transfer["outcome"],
                {"kind": "jump", "target_rva": 0x1030},
            )
            self.assertEqual(transfer["edge_conditions"], [{
                "target_rva": 0x1030,
                "condition": {"op": "true"},
            }])

    def test_semantic_transfer_models_signed_divide_and_fault_condition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", bytes.fromhex("f77c2440"))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1004)
            mapping = BlockMapping(
                id="idiv-memory",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "idiv_memory"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "idiv_memory",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            self.assertEqual(transfer["counts"]["faults"], 1)
            self.assertEqual(transfer["faults"][0]["kind"], "divide_error")
            self.assertEqual(transfer["faults"][0]["instruction_rva"], 0x1000)
            self.assertEqual(
                [(event["family"], event["instruction_rva"]) for event in transfer["ordered_events"]],
                [("memory", 0x1000), ("fault", 0x1000)],
            )
            self.assertIn("udiv_valid32", json.dumps(transfer["faults"][0]))
            register_writes = {item["register"]: item["value"] for item in transfer["register_writes"]}
            self.assertIn("udiv_quot32", json.dumps(register_writes["eax"]))
            self.assertIn("udiv_rem32", json.dumps(register_writes["edx"]))

    def test_semantic_transfers_split_at_divide_checked_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code = bytes.fromhex(
                "31d2"          # xor edx, edx
                "b808000000"    # mov eax, 8
                "b902000000"    # mov ecx, 2
                "f7f1"          # div ecx
                "890424"        # mov [esp], eax
                "c3"            # ret
            )
            original = self._write_pe(root / "original.exe", code)
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1000 + len(code))
            mapping = BlockMapping(
                id="divide-then-store",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "divide_then_store"},
            )

            transfers = _semantic_transfer_contracts(
                binary,
                [mapping],
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(len(transfers), 2, transfers)
            divide, returned = sorted(
                transfers,
                key=lambda transfer: transfer["original"]["rva_start"],
            )
            self.assertEqual(divide["original"], {
                "rva_start": 0x1000,
                "rva_end": 0x100E,
                "size": 0xE,
            })
            self.assertEqual(
                divide["outcome"],
                {"kind": "fallthrough", "target_rva": 0x100E},
            )
            self.assertEqual(divide["counts"]["faults"], 1)
            self.assertEqual(divide["faults"][0]["kind"], "divide_error")
            self.assertEqual(divide["faults"][0]["instruction_rva"], 0x100C)
            self.assertEqual(
                divide["semantic_cutpoint"],
                {
                    "index": 0,
                    "parent_block_id": "divide-then-store",
                    "policy": "formal_stopping_instruction_v1",
                },
            )
            self.assertEqual(returned["original"]["rva_start"], 0x100E)
            self.assertEqual(returned["outcome"]["kind"], "return")

    def test_unsigned_divide_fault_values_are_guarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", bytes.fromhex("f7f1"))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1002)
            mapping = BlockMapping(
                id="div-register",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "div_register"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "div_register",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["counts"]["faults"], 1)
            self.assertEqual(transfer["faults"][0]["kind"], "divide_error")
            register_writes = {
                item["register"]: item["value"]
                for item in transfer["register_writes"]
            }
            self.assertEqual(register_writes["eax"]["op"], "ite")
            self.assertEqual(register_writes["edx"]["op"], "ite")
            self.assertIn("udiv_valid32", json.dumps(register_writes["eax"]))

    def test_semantic_shift_preserves_flags_for_zero_count_and_updates_parity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = self._write_pe(root / "original.exe", bytes.fromhex("d3e0"))
            binary = _parse_stage_a_pe(original)
            side = BlockSide(0x1000, 0x1002)
            mapping = BlockMapping(
                id="shift-by-cl",
                original=side,
                candidate=side,
                kind="code",
                reachable=True,
                invariant_checked=True,
                source={"function": "shift_by_cl"},
            )

            transfer = _semantic_transfer_contract(
                binary,
                mapping,
                "shift_by_cl",
                {"model": REFERENCE_CONTRACT_MODEL_ID},
            )

            self.assertEqual(transfer["status"], "reimplementable", transfer)
            flags = {item["flag"]: item["value"] for item in transfer["flag_writes"]}
            self.assertEqual(set(flags), {"cf", "zf", "sf", "of", "pf"})
            for name in flags:
                self.assertEqual(flags[name]["op"], "ite")
                self.assertIn(f'"name": "{name}"', json.dumps(flags[name], sort_keys=True))
            self.assertIn("shift_cf", json.dumps(flags["cf"]))
            self.assertIn("shift_of", json.dumps(flags["of"]))
            self.assertIn("shift_overflow_undefined", json.dumps(flags["of"]))
            self.assertIn("parity", json.dumps(flags["pf"]))

    @staticmethod
    def _write_pe(path: Path, code: bytes) -> Path:
        path.write_bytes(pe32_image(code))
        return path

    @staticmethod
    def _write_map(path: Path, symbol: str) -> Path:
        path.write_text(
            f"                0x00401000                {symbol}\n",
            encoding="utf-8",
        )
        return path


if __name__ == "__main__":
    unittest.main()
