"""A derived stack relation must constrain original checks before execution."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_private_frame import specs, validate_private_frame
from tests.unit.components import test_bisimulation_mutable_composition as composition_tests
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


def prepare_cases(root):
    for name, relation in (("valid", 28), ("wrong", 24), ("missing", None)):
        path = root / name
        path.mkdir()
        check_normal_exit(path, cbmc=Path(shutil.which("cbmc")), reference_view=True,
            read_buffer=True, write_buffer=True, return_to_caller=True, private_write=True,
            reference_authority=authority_payload(), machine_clobbers=("ebp",),
            private_stack_writes=({"offset": 20, "bytes": 1},), frame_base_offset=28,
            frame_relation_offset=relation)


class IncomingStackRelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(t) for t in ("cbmc", "goto-cc", "goto-instrument", "jq")):
            raise unittest.SkipTest("CBMC and both receipt readers are required")
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        prepare_cases(cls.root)
        cls.load_cases()

    @classmethod
    def load_cases(cls):
        cls.cases = {name: json.loads((cls.root / name / "contextual-refinement-result.json").read_text())
                     for name in ("valid", "wrong", "missing")}
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    seal = staticmethod(composition_tests.MutableCompositionTests.seal)
    readers = composition_tests.MutableCompositionTests.readers

    def test_established_relation_admits_resumed_private_frame(self):
        proof = self.cases["valid"]["proof"]
        self.assertEqual(proof["status"], "satisfied")
        self.assertEqual(self.readers(copy.deepcopy(self.cases["valid"])), (True, True))
        for shard in proof["shards"]:
            for spec in specs(((20, 1),)):
                self.assertEqual(shard[spec.field]["result"]["status"], "satisfied")
        # Writing private memory still does not supply a logical-writable-only
        # frame. Admission changes neither footprint nor that stronger claim.
        self.assertEqual(proof["shards"][1]["exact_mutable_memory_frame"]["result"]["status"], "violated")

    def test_false_relation_fails_its_actual_predecessor(self):
        case = self.cases["wrong"]
        self.assertEqual(case["proof"]["status"], "violated")
        self.assertEqual(case["proof"]["shards"][0]["detail"], "spx-bisimulation-derived:cut:frame-base")
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
        self.assertFalse(case["proof"]["activation_authorized"])

    def test_missing_relation_cannot_export_the_private_footprint(self):
        case = self.cases["missing"]
        proof = case["proof"]
        self.assertEqual(proof["status"], "violated")
        self.assertEqual(proof["shards"][1]["detail"],
                         "spx-bisimulation-exit-world-memory:run:spx_bisimulation_check_0001")
        self.assertNotIn("exact_private_write_frame", proof["shards"][1])
        self.assertFalse(proof["activation_authorized"])
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))

    def test_positive_frame_still_binds_retained_solver_and_model_bytes(self):
        proof = self.cases["valid"]["proof"]
        model = proof["models"]["operation_models"][0]["obligation_models"][1]
        shard = proof["shards"][1]
        spec = specs(((20, 1),))[0]
        source = self.root / "valid/diagnostics/operation-0000-obligation-0001"
        for tamper in (".goto", ".stdout"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for suffix in (".goto", ".stdout", ".stderr"):
                    shutil.copyfile(source / (spec.artifact_stem + suffix), root / (spec.artifact_stem + suffix))
                validate_private_frame(shard[spec.field], spec=spec, model=model, shard=shard,
                                       checker=proof["checker"], artifacts=root)
                (root / (spec.artifact_stem + tamper)).write_text("[]\n")
                with self.assertRaises(ValueError):
                    validate_private_frame(shard[spec.field], spec=spec, model=model, shard=shard,
                                           checker=proof["checker"], artifacts=root)
