"""Mutable entry admission must survive failure of a stronger machine frame."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_mutable_machine_frame import (
    CUT, EXIT, SPECS, checked_mutable_machine_frame_operations, validate_mutable_machine_frame)
from spaghetti_extractor.components.bisimulation_readable_entry import checked_mutable_entry_operations
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload
from tests.unit.components.connected_reader_fixture import check_connected_reader
from tests.unit.components.readable_transfer_fixture import reader_transfers
from spaghetti_extractor.transfer.evaluator import EvaluatorStateV1, EvaluatorMemoryV1, _evaluate_transfer

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class MutableMachineFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc", "goto-instrument", "jq")):
            raise unittest.SkipTest("CBMC and receipt-reader tools are required")
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name); cls.cases = {}
        for name, flags in (("leaf", {}), ("exit-clobber", {"readable_clobber_ecx": True}),
                            ("cut-clobber", {"readable_clobber_before_cut": True}), ("domain-trap", {"entry_domain_trap": True})):
            root = cls.root / name; root.mkdir()
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                read_buffer=True, write_buffer=True, source_contracts=True, return_to_caller=True,
                reference_authority=authority_payload(), **flags)
            if result["status"] != "satisfied":
                raise AssertionError(result["issues"])
            cls.cases[name] = json.loads((root / "contextual-refinement-result.json").read_text())
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    @staticmethod
    def seal(value):
        value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})

    def readers(self, value):
        proof = value["proof"]
        for shard in proof["shards"]:
            for spec in SPECS:
                if spec.field in shard:
                    self.seal(shard[spec.field])
        self.seal(proof)
        try:
            validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        jq = subprocess.run([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
            input=json.dumps(value), text=True, capture_output=True)
        return python, jq.returncode == 0

    def test_full_machine_frame_requires_both_facts_for_every_segment(self):
        for name, case in self.cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
                root = self.root / name / "diagnostics"
                self.assertEqual(checked_mutable_machine_frame_operations(case["proof"], artifacts=root),
                    ("run",) if name == "leaf" else ())
                self.assertEqual(checked_mutable_entry_operations(case["proof"], artifacts=root),
                    () if name == "domain-trap" else ("run",))

    def test_cut_and_exit_clobbers_fail_their_actual_queries_without_losing_entry(self):
        for name, index, spec in (("exit-clobber", 1, EXIT), ("cut-clobber", 0, CUT)):
            with self.subTest(case=name):
                shards = self.cases[name]["proof"]["shards"]
                self.assertEqual([s["mutable_entry_contract"]["result"]["status"] for s in shards], ["satisfied", "satisfied"])
                self.assertEqual(shards[index][spec.field]["result"]["status"], "violated")
                self.assertEqual(shards[index][spec.field]["result"]["detail"], spec.description)
                self.assertEqual(shards[1-index][spec.field]["result"]["status"], "satisfied")
        shard = self.cases["domain-trap"]["proof"]["shards"][-1]
        self.assertEqual(shard["mutable_entry_contract"]["result"]["status"], "violated")
        self.assertTrue(all(spec.field not in shard for spec in SPECS))

    def test_missing_machine_fact_keeps_entry_but_exports_no_complete_machine_frame(self):
        for index in (0, 1):
            for spec in SPECS:
                with self.subTest(segment=index, fact=spec.field):
                    value = copy.deepcopy(self.cases["leaf"])
                    del value["proof"]["shards"][index][spec.field]
                    self.assertEqual(self.readers(value), (True, True))
                    self.assertEqual(checked_mutable_entry_operations(value["proof"], artifacts=self.root / "leaf/diagnostics"), ("run",))
                    self.assertEqual(checked_mutable_machine_frame_operations(value["proof"], artifacts=self.root / "leaf/diagnostics"), ())

    def test_both_readers_reject_rehashed_machine_claim_substitution(self):
        for spec in SPECS:
            for mutation in ("policy", "authority", "entry", "model", "tool", "command", "property", "count", "guard", "required", "domain"):
                with self.subTest(fact=spec.field, mutation=mutation):
                    value = copy.deepcopy(self.cases["leaf"])
                    proof = value["proof"]; shard = proof["shards"][-1]; fact = shard[spec.field]
                    if mutation == "policy": fact["policy"] = "declared-machine-compatible"
                    elif mutation == "authority": fact["authorizing"] = True
                    elif mutation == "entry": fact["proof_function"] = "other"
                    elif mutation == "model": fact["bindings"]["goto_model_sha256"] = "a" * 64
                    elif mutation == "tool": fact["tools"]["cbmc_sha256"] = "a" * 64
                    elif mutation == "command": fact["command"][-1] = "other.assertion.1"
                    elif mutation == "property": fact["result"]["property_ids"] = []
                    elif mutation == "count": fact["result"]["properties"] = True
                    elif mutation == "domain": del shard["mutable_entry_contract"]
                    elif mutation == "required":
                        model = proof["models"]["operation_models"][0]["obligation_models"][-1]
                        model["required_assertion_descriptions"].remove(spec.description)
                        model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
                    else:
                        next(row for row in shard["partitioned_evidence"]["assertions"]
                            if row["description"] == spec.description)["source_function"] = "other"
                    self.assertEqual(self.readers(value), (False, False))

    def test_retained_solver_bytes_are_mandatory(self):
        proof = self.cases["leaf"]["proof"]
        for spec in SPECS:
            with self.subTest(fact=spec.field):
                arguments = dict(spec=spec, model=proof["models"]["operation_models"][0]["obligation_models"][0],
                    shard=proof["shards"][0], checker=proof["checker"])
                root = self.root / "leaf/diagnostics/operation-0000-obligation-0000"
                value = proof["shards"][0][spec.field]
                validate_mutable_machine_frame(value, artifacts=root, **arguments)
                with tempfile.TemporaryDirectory() as temporary:
                    copy_root = Path(temporary)
                    for suffix in (".goto", ".stderr"):
                        shutil.copyfile(root / (spec.artifact_stem + suffix), copy_root / (spec.artifact_stem + suffix))
                    with self.assertRaisesRegex(ValueError, "missing"):
                        validate_mutable_machine_frame(value, artifacts=copy_root, **arguments)
                    (copy_root / (spec.artifact_stem + ".stdout")).write_bytes(b"[]\n")
                    with self.assertRaisesRegex(ValueError, "output differs"):
                        validate_mutable_machine_frame(value, artifacts=copy_root, **arguments)

    @classmethod
    def clobber_caller(cls):
        if not hasattr(cls, "_clobber_caller"):
            root = cls.root / "clobber-caller"
            check_connected_reader(root, leaf=cls.root / "exit-clobber", cbmc=Path(shutil.which("cbmc")),
                mutable=True, observe_callee_ecx=True)
            cls._clobber_caller = json.loads((root / "contextual-refinement-result.json").read_text())
        return cls._clobber_caller

    def test_replayed_calls_cannot_hide_a_register_clobber_observed_by_the_caller(self):
        # The original callee stores 77 in ECX. The original caller returns ECX,
        # while the candidate returns the byte saved before the call (17 here).
        state = EvaluatorStateV1.from_payload({"registers": {"esp": 0x410500, "ebx": 0x401004, "ecx": 17}})
        memory = EvaluatorMemoryV1({0x401004: 17, **{0x410500+i: 0 for i in range(4)}})
        memory.write(0x410500, 4, 0x402001)
        _evaluate_transfer(reader_transfers(write_buffer=True, clobber_ecx=True)[1], state, memory, {}, None)
        self.assertEqual((state.registers["eax"], state.registers["ecx"]), (17, 77))
        case = self.clobber_caller()
        self.assertEqual(case["proof"]["status"], "violated")
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
        self.assertTrue(any(query.get("status") == "violated" and query.get("detail") ==
            "spx-bisimulation-connected-callee-machine-state:counter:run"
            for shard in case["proof"]["shards"] for query in shard["partitioned_evidence"]["queries"]))

    def test_replay_receipts_cannot_omit_the_machine_state_guard(self):
        value = copy.deepcopy(self.clobber_caller())
        for model in value["proof"]["models"]["operation_models"][0]["obligation_models"]:
            model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"]
                if not d.startswith("spx-bisimulation-connected-callee-machine-state:")]
            model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
        self.assertEqual(self.readers(value), (False, False))

    def test_replay_cannot_omit_the_entire_entry_contract_and_its_guards(self):
        value = copy.deepcopy(self.clobber_caller())
        connected = value["proof"]["models"]["connected_components"][0]
        del connected["entry_contract"]
        del connected["mutable_transport_policy"]
        for model in value["proof"]["models"]["operation_models"][0]["obligation_models"]:
            model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"]
                if not d.startswith(("spx-bisimulation-connected-callee-", "spx-bisimulation-connected-summary-mutable-"))]
            model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
        self.assertEqual(self.readers(value), (False, False))

    def test_missing_source_contract_rejects_replay_before_proof_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("spaghetti_extractor.components.bisimulation_refinement._run_bisimulation_obligation",
                       side_effect=AssertionError("unqualified replay reached proof execution")) as execute:
                with self.assertRaisesRegex(BisimulationRefinementError,
                        "lacks checked callee entry and machine-state premises"):
                    check_connected_reader(Path(temporary), leaf=self.root / "exit-clobber",
                        cbmc=Path(shutil.which("cbmc")), mutable=True, observe_callee_ecx=True,
                        omit_summary_contracts=True)
                execute.assert_not_called()
