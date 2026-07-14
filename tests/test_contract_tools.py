from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.cli import _build_parser
from spaghetti_extractor.contract_tools import (
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
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file

from contract_fixtures import write_relational_report
from pe_fixtures import pe32_image, pe32_import_image


class ContractToolTests(unittest.TestCase):
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
        self.assertIn("stage-b-check-contract", subcommands)
        self.assertIn("stage-b-audit-contract", subcommands)
        self.assertNotIn("stage-a-legacy-validate", subcommands)
        self.assertNotIn("stage-a-prove-relational", subcommands)
        self.assertNotIn("stage-a-validate-contract-candidate", subcommands)

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
