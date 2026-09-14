"""Supplier-bound mutable body omission and its required composition premises."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readable_composition import (
    image_readable_operations, mutable_summary_bounds, mutable_summary_unwind_arguments)
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from tests.unit.components.connected_reader_fixture import check_connected_reader
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class MutableCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(t) for t in ("cbmc", "goto-cc", "goto-instrument", "jq")):
            raise unittest.SkipTest("CBMC and receipt-reader tools are required")
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name); leaf = cls.root / "leaf"; leaf.mkdir()
        result = check_normal_exit(leaf, cbmc=Path(shutil.which("cbmc")), reference_view=True,
            read_buffer=True, write_buffer=True, source_contracts=True, return_to_caller=True,
            reference_authority=authority_payload())
        if result["status"] != "satisfied": raise AssertionError(result["issues"])
        cls.caller_root = cls.root / "caller"
        result = check_connected_reader(cls.caller_root, leaf=leaf, cbmc=Path(shutil.which("cbmc")), mutable=True)
        if result["status"] != "satisfied": raise AssertionError(result["issues"])
        cls.case = json.loads((cls.caller_root / "contextual-refinement-result.json").read_text())
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    @staticmethod
    def seal(value):
        value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})

    def readers(self, value):
        proof = value["proof"]
        for connected in proof["models"]["connected_components"]:
            entry = connected.get("entry_contract")
            if entry:
                child = entry["proof_system"]["proof"]
                self.seal(child); connected["proof_receipt_sha256"] = child["receipt_sha256"]
                self.seal(entry)
        self.seal(proof)
        try:
            validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        result = subprocess.run([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
            input=json.dumps(value), text=True, capture_output=True)
        return python, result.returncode == 0

    def test_actual_caller_omits_both_bodies_and_passes_both_readers(self):
        proof = self.case["proof"]
        self.assertEqual(proof["status"], "satisfied")
        self.assertEqual(self.readers(copy.deepcopy(self.case)), (True, True))
        self.assertEqual(proof["models"]["connected_components"][0]["summary_strategy"], "image-mutable-body-free-v1")
        model = proof["models"]["operation_models"][0]["obligation_models"][0]
        self.assertEqual(model["selected_unit_ids"], ["semantic-transfer:original-cutpoint-00002000-00002001",
                                                    "semantic-transfer:original-cutpoint-00002001-00002002"])
        inputs = json.loads((self.caller_root / "diagnostics/operation-0000-obligation-0000/compile-inputs.json").read_text())
        self.assertFalse(any("connected-0000/source-" in row["path"] for row in inputs["files"]))
        result = subprocess.run([shutil.which("goto-instrument"), "--show-goto-functions", "--json-ui",
            str(self.caller_root / "diagnostics/operation-0000-obligation-0000/model.goto")],
            capture_output=True, text=True, check=True)
        functions = next(row["functions"] for row in json.loads(result.stdout) if "functions" in row)
        self.assertFalse(any("spx_proof_connected_impl_" in f["name"] for f in functions))

    def test_loop_bounds_and_write_budget_come_from_the_writable_contract(self):
        components = self.case["proof"]["models"]["connected_components"]
        self.assertEqual(mutable_summary_bounds(components), ({"authored_run.0": 5}, 4))
        self.assertEqual(mutable_summary_unwind_arguments(components, ["--unwindset", "existing.0:7"]),
            ["--unwindset", "authored_run.0:5,existing.0:7"])
        model = self.case["proof"]["models"]["operation_models"][0]["obligation_models"][0]
        arguments = model["property_checker_command"]["assertion_arguments"]
        self.assertIn("authored_run.0:5", arguments[arguments.index("--unwindset") + 1].split(","))
        for query in model["nonvacuity_checker_command"]["queries"]:
            arguments = query["arguments"]
            self.assertIn("authored_run.0:5", arguments[arguments.index("--unwindset") + 1].split(","))

    def test_missing_supplier_machine_fact_cannot_keep_body_omission(self):
        for index in (0, 1):
            for field in ("exact_mutable_cut_machine_frame", "exact_mutable_exit_machine_frame"):
                with self.subTest(segment=index, field=field):
                    value = copy.deepcopy(self.case)
                    entry = value["proof"]["models"]["connected_components"][0]["entry_contract"]
                    del entry["proof_system"]["proof"]["shards"][index][field]
                    self.assertEqual(self.readers(value), (False, False))

    def test_actual_entry_post_memory_and_empty_world_guards_are_required(self):
        for prefix in ("spx-bisimulation-connected-mutable-entry:",
                       "spx-bisimulation-connected-summary-mutable-post-memory:",
                       "spx-bisimulation-connected-summary-mutable-empty-allocation-world"):
            with self.subTest(guard=prefix):
                value = copy.deepcopy(self.case)
                model = value["proof"]["models"]["operation_models"][0]["obligation_models"][0]
                model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"] if not d.startswith(prefix)]
                model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
                self.assertEqual(self.readers(value), (False, False))

    def test_parent_world_changes_prevent_image_mutable_admission(self):
        models = self.case["proof"]["models"]
        entry = models["connected_components"][0]["entry_contract"]
        self.assertIsNotNone(image_readable_operations(entry, models, mutable=True))
        for field in ("reference_allocation_requirements", "reference_runtime_inventory"):
            with self.subTest(field=field):
                changed = copy.deepcopy(models); changed[field] = {}
                self.assertIsNone(image_readable_operations(entry, changed, mutable=True))
        changed = copy.deepcopy(models); changed["reference_authority"]["rules"][0]["permissions"] = 1
        self.assertIsNone(image_readable_operations(entry, changed, mutable=True))
