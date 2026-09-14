"""Physical footprints must survive cuts that project pointers from current memory."""
import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_mutable_frame import (
    FRAME, CUT_FRAME, checked_fixed_writable_frame_operations, validate_mutable_cut_frame)
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class MutableCutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc", "jq")):
            raise unittest.SkipTest("CBMC and receipt-reader tools are unavailable")
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name)
        cls.cases = {}
        for name, offset, invariant in (("stable", 0, None), ("moved", 4, None), ("false-fact", 0, 4)):
            root = cls.root / name
            root.mkdir()
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                read_buffer=True, write_buffer=True, return_to_caller=True,
                reference_authority=authority_payload(), memory_cut_offset=offset, memory_cut_invariant_offset=invariant, timeout_seconds=30)
            if result["status"] != ("violated" if name == "false-fact" else "satisfied"):
                raise AssertionError(result["issues"])
            cls.cases[name] = json.loads((root / "contextual-refinement-result.json").read_text())
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    def readers(self, case):
        proof = case["proof"]
        for shard in proof["shards"]:
            value = shard.get(CUT_FRAME.field)
            if value is not None:
                value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})
        proof["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in proof.items() if k != "receipt_sha256"})
        try:
            validate_contextual_refinement_v2(proof, proof_plan=case["proof_plan"], exact_c_slice=case["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        jq = subprocess.run([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
                            input=json.dumps(case), capture_output=True, text=True)
        return python, jq.returncode == 0

    def test_current_memory_and_fixed_footprints_are_independent_of_register_equality(self):
        for name, case in self.cases.items():
            if name == "false-fact":
                continue
            with self.subTest(case=name):
                proof = case["proof"]
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                self.assertEqual([s[FRAME.field]["result"]["status"] for s in proof["shards"]], ["satisfied"] * 2)
                self.assertEqual([s[CUT_FRAME.field]["result"]["status"] for s in proof["shards"]],
                    ["satisfied" if name == "stable" else "violated", "satisfied"])
                facts = checked_fixed_writable_frame_operations(proof, artifacts=self.root / name / "diagnostics")
                self.assertEqual(facts, ("run",) if name == "stable" else ())
                native = json.loads((self.root / name / "native-fixture-inputs.json").read_text())
                self.assertEqual(native["units"][0]["semantics"]["register_writes"], [])
                if name == "moved":
                    self.assertIn(CUT_FRAME.description, str(proof["shards"][0][CUT_FRAME.field]["result"]))

    def test_false_pointer_fact_cannot_bypass_its_predecessor_obligation(self):
        case = self.cases["false-fact"]
        proof = case["proof"]
        self.assertEqual(proof["status"], "violated")
        # Both structural readers accept honest diagnostic failures. Activation
        # additionally requires the strong predicate and its satisfied proof.
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
        self.assertIs(proof["activation_authorized"], False)
        strong = subprocess.run([shutil.which("jq"), "-e", self.program + "\nspx_strong_contextual_proof"],
            input=json.dumps(case), capture_output=True, text=True)
        self.assertEqual(strong.returncode, 1)
        predecessor = proof["shards"][0]["partitioned_evidence"]
        properties = {row["property_id"] for row in predecessor["assertions"]
            if row["description"] == "spx-bisimulation-invariant:cut"}
        self.assertEqual(len(properties), 1)
        # Assertion batching preserves the selected property IDs in a list.
        failed = [row for row in predecessor["queries"]
            if properties & set(row.get("property_ids", [row.get("property_id")]))]
        self.assertEqual([row["status"] for row in failed], ["violated"])
        self.assertEqual(failed[0]["detail"], "spx-bisimulation-invariant:cut")
        self.assertEqual(checked_fixed_writable_frame_operations(proof,
            artifacts=self.root / "false-fact/diagnostics"), ())

    def test_missing_or_failed_segment_cannot_export_an_operation_frame(self):
        for index in (0, 1):
            for field in (FRAME.field, CUT_FRAME.field):
                proof = copy.deepcopy(self.cases["stable"]["proof"])
                del proof["shards"][index][field]
                self.assertEqual(checked_fixed_writable_frame_operations(proof,
                    artifacts=self.root / "stable/diagnostics"), ())
        proof = copy.deepcopy(self.cases["stable"]["proof"])
        proof["status"] = "incomplete"
        self.assertEqual(checked_fixed_writable_frame_operations(proof, artifacts=self.root / "stable/diagnostics"), ())

    def test_both_readers_reject_rehashed_cut_evidence_tampering(self):
        for change in ("policy", "authorizing", "command", "binding", "tools", "property", "count"):
            case = copy.deepcopy(self.cases["stable"])
            value = case["proof"]["shards"][0][CUT_FRAME.field]
            if change == "policy": value["policy"] = FRAME.policy
            elif change == "authorizing": value["authorizing"] = True
            elif change == "command": value["command"][-1] = FRAME.property_id
            elif change == "binding": value["bindings"]["goto_model_sha256"] = "0" * 64
            elif change == "tools": value["tools"]["cbmc_sha256"] = "0" * 64
            elif change == "property": value["result"]["property_ids"] = [FRAME.property_id]
            else: value["result"]["properties"] = True
            with self.subTest(change=change):
                self.assertEqual(self.readers(case), (False, False))

    def test_retained_cut_artifacts_are_required(self):
        proof = self.cases["stable"]["proof"]
        root = self.root / "stable/diagnostics/operation-0000-obligation-0000"
        options = dict(model=proof["models"]["operation_models"][0]["obligation_models"][0],
            shard=proof["shards"][0], checker=proof["checker"], artifacts=root)
        value = proof["shards"][0][CUT_FRAME.field]
        validate_mutable_cut_frame(value, **options)
        path = root / (CUT_FRAME.artifact_stem + ".goto")
        content = path.read_bytes()
        try:
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                validate_mutable_cut_frame(value, **options)
        finally:
            path.write_bytes(content)
