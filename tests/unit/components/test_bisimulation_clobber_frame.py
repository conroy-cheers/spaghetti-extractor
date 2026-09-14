"""Declared clobbers need checked frames and original-side caller overapproximation."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_clobber_frame import (
    clobber_specs, clobber_guarantee, consumed_clobbers, validate_clobber_frame)
from spaghetti_extractor.components.bisimulation_mutable_machine_frame import checked_mutable_machine_frame_operations
from tests.unit.components import test_bisimulation_mutable_composition as composition_tests
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload
from tests.unit.components.connected_reader_fixture import check_connected_reader

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


def prepare_cases(root):
    cbmc = Path(shutil.which("cbmc"))
    for name, clobbers, at_cut in (("supplier", ("ecx",), False), ("wrong-frame", ("edx",), False),
                                  ("cut-supplier", ("ecx",), True), ("wrong-cut-frame", ("edx",), True)):
        path = root / name; path.mkdir()
        result = check_normal_exit(path, cbmc=cbmc, reference_view=True, read_buffer=True,
            write_buffer=True, source_contracts=True, return_to_caller=True,
            reference_authority=authority_payload(), readable_clobber_ecx=not at_cut,
            readable_clobber_before_cut=at_cut, machine_clobbers=clobbers)
        if result["status"] != "satisfied": raise AssertionError(result["issues"])
    for name, observes in (("caller", False), ("observed-caller", True)):
        result = check_connected_reader(root / name, leaf=root / "supplier", cbmc=cbmc,
                                        mutable=True, observe_callee_ecx=observes)
        if result["status"] != ("violated" if observes else "satisfied"):
            raise AssertionError(result["issues"])


class ClobberFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(t) for t in ("cbmc", "goto-cc", "goto-instrument", "jq")):
            raise unittest.SkipTest("CBMC and both receipt readers are required")
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        prepare_cases(cls.root)
        cls.load_cases()

    @classmethod
    def load_cases(cls):
        cls.cases = {name: json.loads((cls.root / name / "contextual-refinement-result.json").read_text())
                     for name in ("supplier", "wrong-frame", "cut-supplier", "wrong-cut-frame", "caller", "observed-caller")}
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    seal = staticmethod(composition_tests.MutableCompositionTests.seal)
    readers = composition_tests.MutableCompositionTests.readers

    def test_checked_frame_allows_declared_changes_and_rejects_undeclared_changes(self):
        for name, admitted in (("supplier", True), ("wrong-frame", False)):
            with self.subTest(case=name):
                case = self.cases[name]; proof = case["proof"]
                self.assertEqual(proof["status"], "satisfied")
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                operation = proof["models"]["operation_models"][0]
                self.assertEqual(clobber_guarantee(proof, operation), admitted)
                self.assertEqual(checked_mutable_machine_frame_operations(proof, artifacts=self.root / name / "diagnostics"),
                                 ("run",) if admitted else ())
                self.assertEqual(proof["shards"][-1]["exact_mutable_exit_machine_frame"]["result"]["status"], "violated")
                self.assertEqual(proof["shards"][-1]["exact_mutable_exit_clobber_frame"]["result"]["status"],
                                 "satisfied" if admitted else "violated")

    def test_body_free_caller_tolerates_dead_clobber_but_rejects_observed_clobber(self):
        for name, status in (("caller", "satisfied"), ("observed-caller", "violated")):
            with self.subTest(case=name):
                case = self.cases[name]; proof = case["proof"]
                self.assertEqual(proof["status"], status)
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                connected = proof["models"]["connected_components"][0]
                self.assertEqual(connected["summary_strategy"], "image-mutable-body-free-v1")
                self.assertEqual(consumed_clobbers(connected, "run"), ("ecx",))
                model = proof["models"]["operation_models"][0]["obligation_models"][0]
                self.assertIn("spx-bisimulation-connected-callee-clobber-state:counter:run", model["required_assertion_descriptions"])
        root = self.root / "caller/diagnostics/operation-0000-obligation-0000"
        harness = (root / "bisimulation.c").read_text()
        self.assertIn("call_state.ecx = spx_nondet_u32();", harness)
        self.assertNotIn("source_state.ecx = spx_nondet_u32();", harness)
        self.assertNotIn("call_state.eax = spx_nondet_u32();", harness)
        inventory = subprocess.check_output([shutil.which("goto-instrument"), "--json-ui", "--show-goto-functions", str(root / "model.goto")], text=True)
        self.assertNotIn("spx_proof_connected_impl_", inventory)

    def test_internal_cuts_check_clobber_containment_instead_of_assuming_identity(self):
        for name, admitted in (("cut-supplier", True), ("wrong-cut-frame", False)):
            with self.subTest(case=name):
                case = self.cases[name]; proof = case["proof"]
                self.assertEqual(proof["status"], "satisfied")
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                self.assertEqual(checked_mutable_machine_frame_operations(proof, artifacts=self.root / name / "diagnostics"),
                                 ("run",) if admitted else ())
                self.assertEqual(proof["shards"][0]["exact_mutable_cut_machine_frame"]["result"]["status"], "violated")
                self.assertEqual(proof["shards"][0]["exact_mutable_cut_clobber_frame"]["result"]["status"],
                                 "satisfied" if admitted else "violated")

    def test_missing_facts_do_not_turn_a_declaration_into_a_consumable_frame(self):
        for index in (0, 1):
            for field in ("exact_mutable_cut_clobber_frame", "exact_mutable_exit_clobber_frame"):
                with self.subTest(segment=index, fact=field):
                    case = copy.deepcopy(self.cases["caller"])
                    connected = case["proof"]["models"]["connected_components"][0]
                    del connected["entry_contract"]["proof_system"]["proof"]["shards"][index][field]
                    self.assertEqual(consumed_clobbers(connected, "run"), ())
                    self.assertEqual(self.readers(case), (False, False))

    def test_both_readers_reject_changed_clobber_sets_and_missing_call_guards(self):
        for mutation in ("clobbers", "result", "guard"):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.cases["caller"])
                connected = case["proof"]["models"]["connected_components"][0]
                if mutation == "guard":
                    for model in case["proof"]["models"]["operation_models"][0]["obligation_models"]:
                        model["required_assertion_descriptions"].remove("spx-bisimulation-connected-callee-clobber-state:counter:run")
                        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
                        model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
                else:
                    model = connected["entry_contract"]["proof_system"]["proof"]["models"]["operation_models"][0]
                    model["machine_clobbers" if mutation == "clobbers" else "machine_result_registers"] = ["edx"]
                self.assertEqual(self.readers(case), (False, False))

    def test_positive_frame_requires_its_exact_retained_model_and_solver_bytes(self):
        proof = self.cases["supplier"]["proof"]
        model = proof["models"]["operation_models"][0]["obligation_models"][0]
        shard = proof["shards"][0]
        for spec in clobber_specs(["ecx"], ["eax"]):
            with self.subTest(frame=spec.field), tempfile.TemporaryDirectory() as temporary:
                source = self.root / "supplier/diagnostics/operation-0000-obligation-0000"
                root = Path(temporary)
                for suffix in (".goto", ".stdout", ".stderr"):
                    shutil.copyfile(source / (spec.artifact_stem + suffix), root / (spec.artifact_stem + suffix))
                validate_clobber_frame(shard[spec.field], spec=spec, model=model, shard=shard, checker=proof["checker"], artifacts=root)
                (root / (spec.artifact_stem + ".stdout")).write_text("[]\n")
                with self.assertRaisesRegex(ValueError, "output differs"):
                    validate_clobber_frame(shard[spec.field], spec=spec, model=model, shard=shard, checker=proof["checker"], artifacts=root)

    def test_intent_clobbers_are_canonical_and_cannot_waive_stack_or_mapped_results(self):
        for fields in (["esp"], ["fs_base"], ["x87_stack"], ["ecx", "ecx"], ["edx", "ecx"], [True]):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                ComponentBisimulationIntentV1.create(component_id="counter", operations=[{
                    "operation_id": "run", "syncs": [], "machine_clobbers": fields}])
        with self.assertRaisesRegex(ValueError, "mapped result"):
            clobber_specs(["eax"], ["eax"])
