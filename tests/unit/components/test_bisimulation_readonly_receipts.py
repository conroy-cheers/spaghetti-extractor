"""Both readers reject weakened local readable-contract proof claims."""
from __future__ import annotations

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_readonly_source_contracts
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from tests.unit.components.test_bisimulation_readonly_contracts import check_source
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json", "nix/jq/strong-contextual-proof.jq")}


class ReadonlyReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc", "jq")):
            raise unittest.SkipTest("proof reader tools are unavailable")
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.certificate = check_source(Path(directory.name))
        cls.program = (Path(__file__).resolve().parents[3] / "nix/jq/strong-contextual-proof.jq").read_text()

    def readers(self, value):
        value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})
        try:
            validate_readonly_source_contracts(value)
            python = True
        except ValueError:
            python = False
        jq = run_jq_reader([shutil.which("jq"), "-e", self.program + "\nspx_readonly_certificate"],
                            input=json.dumps(value), capture_output=True, text=True)
        return python, jq.returncode == 0

    def test_complete_solver_certificate_passes_both_readers(self):
        self.assertEqual(self.readers(copy.deepcopy(self.certificate)), (True, True))

    def test_full_exact_byte_reader_proof_binds_auxiliary_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                reference_authority=authority_payload(), read_buffer=True, source_contracts=True)
            self.assertEqual(result["status"], "satisfied", result["issues"])
            payload = json.loads((root / "contextual-refinement-result.json").read_text())
            for mutation in (None, "source", "profile", "interface", "failed_solver", "unknown_policy", "extra_field", "missing_certificate", "null_certificate"):
                value = copy.deepcopy(payload)
                proof = value["proof"]
                summary = proof["models"]["source_summary_contracts"]
                if mutation == "unknown_policy":
                    summary["certificate"]["policy"] = "unknown-contract"
                    summary["certificate"]["receipt_sha256"] = canonical_sha256_v3({
                        k: v for k, v in summary["certificate"].items() if k != "receipt_sha256"})
                elif mutation == "extra_field":
                    summary["unbound_assumption"] = True
                elif mutation == "missing_certificate":
                    del summary["certificate"]
                elif mutation == "null_certificate":
                    summary["certificate"] = None
                elif mutation == "failed_solver":
                    summary["certificate"]["checks"][-1]["status"] = "violated"
                    summary["certificate"]["receipt_sha256"] = canonical_sha256_v3({
                        k: v for k, v in summary["certificate"].items() if k != "receipt_sha256"})
                elif mutation is not None:
                    summary[{"source": "implementation_sha256", "profile": "source_profile_sha256",
                             "interface": "proof_interface_sha256"}[mutation]] = "a" * 64
                proof["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in proof.items() if k != "receipt_sha256"})
                with self.subTest(mutation=mutation):
                    if mutation is None:
                        validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
                    else:
                        with self.assertRaises(ValueError):
                            validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
                    jq = run_jq_reader([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
                                        input=json.dumps(value), capture_output=True, text=True)
                    self.assertEqual(jq.returncode == 0, mutation is None, jq.stderr)

    def test_missing_or_weakened_proofs_fail_both_readers(self):
        for mutation in ("options", "instrument", "result", "property", "model", "raw_model", "opacity",
                         "loops", "duplicate_command", "command_tool", "command_fields", "inventory_kind",
                         "include", "binding", "authority", "domain"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(self.certificate)
                if mutation == "options":
                    value["checker_options"].remove("--unwinding-assertions")
                elif mutation == "instrument":
                    next(row for row in value["commands"] if row["step"].endswith("-instrument"))["command"].remove("--enforce-contract")
                elif mutation == "result":
                    value["checks"][-1]["status"] = "violated"
                elif mutation == "property":
                    check = value["checks"][-1]
                    check["property_ids"] = [p for p in check["property_ids"] if not p.startswith("spx_readonly_input_dependence_compare.assertion")]
                    check["properties"] = len(check["property_ids"])
                elif mutation == "model":
                    value["models"].pop()
                elif mutation == "raw_model":
                    value["models"][-1]["raw_goto_sha256"] = "a" * 64
                elif mutation == "opacity":
                    value["checks"][0]["status"] = "violated"
                elif mutation == "loops":
                    value["inventories"] = [r for r in value["inventories"] if r["step"] != "authored-loops"]
                elif mutation == "duplicate_command":
                    value["commands"].append(value["commands"][0])
                elif mutation == "command_tool":
                    value["commands"][0]["command"][0] = None
                elif mutation == "command_fields":
                    value["commands"][0]["unbound_input"] = "unchecked.c"
                elif mutation == "inventory_kind":
                    value["inventories"][0]["kind"] = "unknown"
                elif mutation == "include":
                    value["source_dependencies"][0]["inputs"][0]["path"] = "../unbound.h"
                elif mutation == "binding":
                    value["source_profile"]["bindings"]["implementation_sha256"] = "a" * 64
                elif mutation == "authority":
                    value["authorizing"] = True
                else:
                    signature = next(row for row in value["interface_intent"]["schema"]["signatures"]
                                     if row["id"] == value["interface_intent"]["operations"][0]["signature_id"])
                    signature["parameters"][0]["extent"] = {"kind": "value", "bytes": None, "value_id": "count"}
                self.assertEqual(self.readers(value), (False, False))
