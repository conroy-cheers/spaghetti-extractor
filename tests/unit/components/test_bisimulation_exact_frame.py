"""Physical original writes are a separate fact from ordinary equivalence."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_exact_frame import checked_empty_frame_operations, PROPERTY
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class ExactFrameTests(unittest.TestCase):
    def test_conditional_shards_and_extracted_frames_cannot_enter_strong_readers(self):
        assurance = {"kind": "conditional-runtime-contracts", "contracts": [
            {"id": "runtime.frame", "revision": 1, "contract_sha256": "a" * 64},
        ]}
        for location in ("shard", "frame"):
            for selection in (assurance, None):
                with self.subTest(location=location, selection=selection):
                    value = copy.deepcopy(self.cases[0])
                    shard = value["proof"]["shards"][-1]
                    (shard if location == "shard" else shard["exact_memory_frame"])["assurance"] = selection
                    self.assertEqual(self.readers(value), (False, False))

    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc", "jq")):
            raise unittest.SkipTest("CBMC and receipt-reader tools are unavailable")
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name)
        cls.cases = []
        for private in (False, True):
            root = cls.root / str(private)
            root.mkdir()
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                read_buffer=True, return_to_caller=True, private_write=private,
                reference_authority=authority_payload(), source_contracts=True)
            if result["status"] != "satisfied":
                raise AssertionError(result["issues"])
            cls.cases.append(json.loads((root / "contextual-refinement-result.json").read_text()))
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    def readers(self, value):
        proof = value["proof"]
        for shard in proof["shards"]:
            frame = shard.get("exact_memory_frame")
            if frame is not None:
                frame["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in frame.items() if k != "receipt_sha256"})
        proof["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in proof.items() if k != "receipt_sha256"})
        try:
            validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        jq = subprocess.run([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
                            input=json.dumps(value), text=True, capture_output=True)
        return python, jq.returncode == 0

    def test_real_return_proves_frame_and_private_write_only_vetoes_the_stronger_fact(self):
        for private, case in zip((False, True), self.cases, strict=True):
            with self.subTest(private=private):
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                self.assertEqual(case["proof"]["status"], "satisfied")
                self.assertEqual([row["exact_memory_frame"]["result"]["status"] for row in case["proof"]["shards"]],
                                 ["satisfied", "violated" if private else "satisfied"])
                self.assertEqual(checked_empty_frame_operations(case["proof"], artifacts=self.root / str(private) / "diagnostics"),
                                 () if private else ("run",))

    def test_missing_segment_fact_keeps_ordinary_proof_but_cannot_supply_operation_frame(self):
        value = copy.deepcopy(self.cases[0])
        del value["proof"]["shards"][-1]["exact_memory_frame"]
        value["proof"]["shards"][-1].pop("readable_entry_contract", None)
        self.assertEqual(self.readers(value), (True, True))
        self.assertEqual(checked_empty_frame_operations(value["proof"], artifacts=self.root / "False" / "diagnostics"), ())

    def test_both_readers_reject_rehashed_stale_or_weakened_frame_claims(self):
        for mutation in ("policy", "authority", "entry", "model", "command", "tool", "property", "fields"):
            value = copy.deepcopy(self.cases[0])
            frame = value["proof"]["shards"][-1]["exact_memory_frame"]
            if mutation == "policy": frame["policy"] = "declared-frame"
            elif mutation == "authority": frame["authorizing"] = True
            elif mutation == "entry": frame["proof_function"] += "_relation"
            elif mutation == "model": frame["bindings"]["goto_model_sha256"] = "a" * 64
            elif mutation == "command": frame["command"].remove("--unwinding-assertions")
            elif mutation == "tool": frame["tools"]["cbmc_sha256"] = "a" * 64
            elif mutation == "property": frame["result"]["property_ids"] = []
            else: frame["unchecked_assumption"] = True
            with self.subTest(mutation=mutation):
                self.assertEqual(self.readers(value), (False, False))

    def test_supplier_consumption_rejects_fabricated_success_and_missing_retained_model(self):
        value = copy.deepcopy(self.cases[1])
        frame = value["proof"]["shards"][-1]["exact_memory_frame"]
        frame["result"] = {"status": "satisfied", "code": "cbmc_properties_satisfied", "properties": 1,
                           "property_ids": [PROPERTY], "output_sha256": frame["result"]["output_sha256"]}
        # Metadata readers cannot reconstruct solver truth from a digest. The
        # mandatory supplier check reads the actual bound negative transcript.
        self.assertEqual(self.readers(value), (True, True))
        with self.assertRaisesRegex(ValueError, "does not prove"):
            checked_empty_frame_operations(value["proof"], artifacts=self.root / "True" / "diagnostics")
        with self.assertRaisesRegex(ValueError, "missing"):
            checked_empty_frame_operations(self.cases[0]["proof"], artifacts=self.root / "absent")
