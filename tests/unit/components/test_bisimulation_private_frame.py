"""Residual original stack bytes require checked footprints and caller tolerance."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_private_frame import (
    checked_private_frame_operations, consumed_stack_writes, specs, validate_private_frame)
from tests.unit.components import test_bisimulation_mutable_composition as composition_tests
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload
from tests.unit.components.connected_reader_fixture import check_connected_reader

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


def prepare_cases(root):
    cbmc = Path(shutil.which("cbmc"))
    for name, offset in (("supplier", -8), ("wrong-frame", -4)):
        path = root / name; path.mkdir()
        result = check_normal_exit(path, cbmc=cbmc, reference_view=True, read_buffer=True,
            write_buffer=True, source_contracts=True, return_to_caller=True, private_write=True,
            reference_authority=authority_payload(), private_stack_writes=({"offset": offset, "bytes": 1},))
        if result["status"] != "satisfied": raise AssertionError(result["issues"])
    # These caller queries exceed 30s even in a serial Nix run. Keep the same
    # assertions and unwind bounds, with enough time to complete the proof.
    for name, observes in (("caller", False), ("observed-caller", True)):
        result = check_connected_reader(root / name, leaf=root / "supplier", cbmc=cbmc,
            mutable=True, private_write=True, observe_callee_private_byte=observes, timeout_seconds=120)
        if result["status"] != ("violated" if observes else "satisfied"):
            raise AssertionError(result["issues"])


class PrivateFrameTests(unittest.TestCase):
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
                     for name in ("supplier", "wrong-frame", "caller", "observed-caller")}
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    seal = staticmethod(composition_tests.MutableCompositionTests.seal)
    readers = composition_tests.MutableCompositionTests.readers

    def test_wrong_private_footprint_preserves_ordinary_proof_but_cannot_supply_summary(self):
        for name, admitted in (("supplier", True), ("wrong-frame", False)):
            with self.subTest(case=name):
                case = self.cases[name]; proof = case["proof"]
                self.assertEqual(proof["status"], "satisfied")
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                self.assertEqual(checked_private_frame_operations(proof, artifacts=self.root / name / "diagnostics"),
                                 ("run",) if admitted else ())
                final = proof["shards"][-1]
                self.assertEqual(final["exact_mutable_memory_frame"]["result"]["status"], "violated")
                self.assertEqual(final["exact_private_write_frame"]["result"]["status"],
                                 "satisfied" if admitted else "violated")
                self.assertEqual("mutable_entry_contract" in final, admitted)

    def test_body_free_caller_must_tolerate_residual_original_bytes(self):
        for name, status in (("caller", "satisfied"), ("observed-caller", "violated")):
            with self.subTest(case=name):
                case = self.cases[name]; proof = case["proof"]
                self.assertEqual(proof["status"], status)
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                connected = proof["models"]["connected_components"][0]
                self.assertEqual(connected["summary_strategy"], "image-mutable-body-free-v1")
                self.assertEqual(consumed_stack_writes(connected, "run"), ((-8, 1),))
                model = proof["models"]["operation_models"][0]["obligation_models"][0]
                self.assertIn("spx-bisimulation-connected-callee-private-poststate:counter:run",
                              model["required_assertion_descriptions"])
        root = self.root / "caller/diagnostics/operation-0000-obligation-0000"
        inventory = subprocess.check_output([shutil.which("goto-instrument"), "--json-ui", "--show-goto-functions",
                                            str(root / "model.goto")], text=True)
        self.assertNotIn("spx_proof_connected_impl_", inventory)
        inputs = json.loads((root / "compile-inputs.json").read_text())
        self.assertFalse(any("connected-0000/source-" in row["path"] for row in inputs["files"]))
        failed = self.cases["observed-caller"]["proof"]["shards"][0]
        self.assertEqual(failed["code"], "cbmc_counterexample")
        self.assertEqual(failed["detail"], "spx-bisimulation-exit-observable:run:result:value")
        self.assertEqual([q["kind"] for q in failed["partitioned_evidence"]["queries"]
                          if q["status"] != "satisfied"], ["authored_assertion"])

    def test_missing_frame_or_entry_fact_cannot_be_consumed(self):
        for index in (0, 1):
            for field in ("exact_private_write_frame", "exact_private_cut_frame", "mutable_entry_contract"):
                with self.subTest(segment=index, fact=field):
                    case = copy.deepcopy(self.cases["caller"])
                    connected = case["proof"]["models"]["connected_components"][0]
                    del connected["entry_contract"]["proof_system"]["proof"]["shards"][index][field]
                    self.assertEqual(consumed_stack_writes(connected, "run"), ())
                    self.assertEqual(self.readers(case), (False, False))

    def test_rehashed_domain_and_footprint_substitutions_are_rejected(self):
        for mutation in ("minimum_esp", "image_exclusion_below_esp", "footprint", "call_guard"):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.cases["caller"])
                connected = case["proof"]["models"]["connected_components"][0]
                supplier = connected["entry_contract"]["proof_system"]["proof"]
                if mutation in ("minimum_esp", "image_exclusion_below_esp"):
                    theorem = supplier["shards"][0]["mutable_entry_contract"]
                    theorem["domain"][mutation] = 4 if mutation == "minimum_esp" else 0
                    self.seal(theorem)
                elif mutation == "footprint":
                    supplier["models"]["operation_models"][0]["private_stack_writes"][0]["offset"] = -4
                else:
                    for model in case["proof"]["models"]["operation_models"][0]["obligation_models"]:
                        model["required_assertion_descriptions"].remove(
                            "spx-bisimulation-connected-callee-private-poststate:counter:run")
                        model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
                self.assertEqual(self.readers(case), (False, False))

    def test_positive_frames_bind_the_exact_retained_model_and_solver_output(self):
        proof = self.cases["supplier"]["proof"]
        for index, model in enumerate(proof["models"]["operation_models"][0]["obligation_models"]):
            shard = proof["shards"][index]
            for spec in specs(((-8, 1),)):
                for tamper in (".goto", ".stdout"):
                    with self.subTest(segment=index, frame=spec.field, tamper=tamper), tempfile.TemporaryDirectory() as temporary:
                        source = self.root / f"supplier/diagnostics/operation-0000-obligation-{index:04d}"
                        root = Path(temporary)
                        for suffix in (".goto", ".stdout", ".stderr"):
                            shutil.copyfile(source / (spec.artifact_stem + suffix), root / (spec.artifact_stem + suffix))
                        validate_private_frame(shard[spec.field], spec=spec, model=model, shard=shard,
                                               checker=proof["checker"], artifacts=root)
                        (root / (spec.artifact_stem + tamper)).write_text("[]\n")
                        with self.assertRaises(ValueError):
                            validate_private_frame(shard[spec.field], spec=spec, model=model, shard=shard,
                                                   checker=proof["checker"], artifacts=root)

    def test_intent_footprints_are_canonical_and_bounded(self):
        for ranges in ([{"offset": True, "bytes": 1}], [{"offset": -8, "bytes": 0}],
                       [{"offset": -1025, "bytes": 1}], [{"offset": 4095, "bytes": 2}],
                       [{"offset": -8, "bytes": 4}, {"offset": -6, "bytes": 1}],
                       [{"offset": 0, "bytes": 1}, {"offset": -8, "bytes": 1}]):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                ComponentBisimulationIntentV1.create(component_id="counter", operations=[{
                    "operation_id": "run", "syncs": [], "private_stack_writes": ranges}])
