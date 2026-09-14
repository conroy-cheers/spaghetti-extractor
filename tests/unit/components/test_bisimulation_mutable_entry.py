"""Mutable suppliers must cover the actual CALL state before composition."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_call_entry import MUTABLE_POLICY
from spaghetti_extractor.components.bisimulation_readable_entry import MUTABLE, checked_mutable_entry_operations
from spaghetti_extractor.components.bisimulation_reference_transport import CONNECTED_MUTABLE_TRANSPORT_POLICY
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload
from tests.unit.components.connected_reader_fixture import check_connected_reader

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class MutableEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc", "goto-instrument", "jq")):
            raise unittest.SkipTest("CBMC and receipt-reader tools are unavailable")
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.cases = {}
        for suffix, trap in (("", False), ("-trap", True)):
            leaf = cls.root / ("leaf" + suffix)
            leaf.mkdir()
            result = check_normal_exit(leaf, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                read_buffer=True, write_buffer=True, source_contracts=True, return_to_caller=True,
                reference_authority=authority_payload(), entry_domain_trap=trap)
            if result["status"] != "satisfied":
                raise AssertionError(result["issues"])
            caller = cls.root / ("caller" + suffix)
            result = check_connected_reader(caller, leaf=leaf, cbmc=Path(shutil.which("cbmc")),
                mutable=True, domain_trap=trap)
            if result["status"] != ("violated" if trap else "satisfied"):
                raise AssertionError(result["issues"])
            for name in ("leaf" + suffix, "caller" + suffix):
                cls.cases[name] = json.loads((cls.root / name / "contextual-refinement-result.json").read_text())
        for name, flags in (("caller-forged", {"forged_reader": True}), ("caller-forged-write", {"forged_writer": True})):
            result = check_connected_reader(cls.root / name, leaf=cls.root / "leaf", cbmc=Path(shutil.which("cbmc")),
                mutable=True, **flags)
            if result["status"] != "violated":
                raise AssertionError(result["issues"])
            cls.cases[name] = json.loads((cls.root / name / "contextual-refinement-result.json").read_text())
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    @staticmethod
    def seal(value):
        value["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in value.items() if k != "receipt_sha256"})

    def readers(self, value):
        proof = value["proof"]
        for shard in proof["shards"]:
            if MUTABLE.field in shard:
                self.seal(shard[MUTABLE.field])
        for connected in proof["models"]["connected_components"]:
            if connected.get("entry_contract") is not None:
                self.seal(connected["entry_contract"])
        self.seal(proof)
        try:
            validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        jq = subprocess.run([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
            input=json.dumps(value), capture_output=True, text=True)
        return python, jq.returncode == 0

    def test_wider_mutable_domain_needs_new_paired_evidence_for_every_segment(self):
        for name, expected in (("leaf", ["satisfied", "satisfied"]), ("leaf-trap", ["satisfied", "violated"])):
            value = self.cases[name]
            with self.subTest(case=name):
                self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
                self.assertEqual([s[MUTABLE.field]["result"]["status"] for s in value["proof"]["shards"]], expected)
                self.assertEqual(checked_mutable_entry_operations(value["proof"], artifacts=self.root / name / "diagnostics"),
                    ("run",) if name == "leaf" else ())
        self.assertEqual(self.cases["leaf-trap"]["proof"]["shards"][1][MUTABLE.field]["result"]["detail"],
            "spx-bisimulation-exit-observable:run:result:value")

    def test_actual_call_selects_body_omission_only_with_the_checked_mutable_domain(self):
        for name, expected in (("caller", "mutable-wide"), ("caller-trap", "ordinary")):
            value = self.cases[name]
            with self.subTest(case=name):
                self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
                connected = value["proof"]["models"]["connected_components"][0]
                self.assertEqual(connected["entry_contract"]["policy"], MUTABLE_POLICY)
                self.assertEqual(connected["entry_contract"]["operations"][0]["domain"], expected)
                self.assertEqual(connected["summary_strategy"],
                    "image-mutable-body-free-v1" if name == "caller" else "connected-replay-v1")
                self.assertIsNone(connected["readable_transport_policy"])
                self.assertEqual(connected["mutable_transport_policy"], CONNECTED_MUTABLE_TRANSPORT_POLICY)
        failed = self.cases["caller-trap"]["proof"]["shards"][0]
        self.assertEqual(failed["status"], "violated")
        # Ordinary replay also requires the supplier's paired machine-state
        # guarantee. This fixture lacks that guarantee after wider admission fails.
        description = "spx-bisimulation-connected-callee-machine-state:counter:run"
        evidence = failed["partitioned_evidence"]
        properties = {row["property_id"] for row in evidence["assertions"] if row["description"] == description}
        self.assertEqual(len(properties), 1)
        self.assertTrue(any(q.get("status") == "violated" and q.get("detail") == description
            and properties & set(q.get("property_ids", [q.get("property_id")])) for q in evidence["queries"]))
        self.assertIs(self.cases["caller-trap"]["proof"]["activation_authorized"], False)

    def test_missing_wider_fact_preserves_ordinary_proof_but_exports_no_wider_domain(self):
        for index in (0, 1):
            value = copy.deepcopy(self.cases["leaf"])
            del value["proof"]["shards"][index][MUTABLE.field]
            self.assertEqual(self.readers(value), (False, False))
            for field in ("exact_mutable_cut_machine_frame", "exact_mutable_exit_machine_frame"):
                del value["proof"]["shards"][index][field]
            self.assertEqual(self.readers(value), (True, True))
            self.assertEqual(checked_mutable_entry_operations(value["proof"], artifacts=self.root / "leaf/diagnostics"), ())

    def test_actual_calls_cannot_substitute_the_world_reader_or_writer(self):
        for name in ("caller-forged", "caller-forged-write"):
            value = self.cases[name]
            with self.subTest(case=name):
                self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
                failed = value["proof"]["shards"][0]
                self.assertTrue(any(q.get("status") == "violated" and q.get("detail") ==
                    "spx-bisimulation-connected-summary-mutable-runtime" for q in failed["partitioned_evidence"]["queries"]))

    def test_both_readers_require_the_mutable_transport_policy_and_guards(self):
        for mutation in ("missing", "policy", "guard", "overlay"):
            value = copy.deepcopy(self.cases["caller"])
            connected = value["proof"]["models"]["connected_components"][0]
            model = value["proof"]["models"]["operation_models"][0]["obligation_models"][0]
            if mutation == "missing": del connected["mutable_transport_policy"]
            elif mutation == "policy": connected["mutable_transport_policy"] = "canonical-readable-callee-transport-v1"
            elif mutation == "overlay":
                model["proof_inputs"] = [row for row in model["proof_inputs"] if row["sha256"] != connected["proof_overlay_sha256"]]
            else:
                model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"]
                    if not d.startswith("spx-bisimulation-connected-summary-mutable-")]
                model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
            with self.subTest(mutation=mutation):
                self.assertEqual(self.readers(value), (False, False))

    def test_both_readers_reject_rehashed_wider_domain_and_model_tampering(self):
        for mutation in ("policy", "domain", "command", "model", "tools", "property", "frame", "count"):
            value = copy.deepcopy(self.cases["leaf"])
            shard = value["proof"]["shards"][0]
            entry = shard[MUTABLE.field]
            if mutation == "policy": entry["policy"] = "paired-readable-entry-empty-frame-v1"
            elif mutation == "domain": entry["domain"]["minimum_esp"] = 0
            elif mutation == "command": entry["command"].remove("--no-self-loops-to-assumptions")
            elif mutation == "model": entry["bindings"]["goto_model_sha256"] = "0" * 64
            elif mutation == "tools": entry["tools"]["cbmc_sha256"] = "0" * 64
            elif mutation == "property": entry["result"]["property_ids"].remove("__CPROVER_spx_exact_writable_cut_frame.assertion.1")
            elif mutation == "frame": del shard["exact_mutable_cut_frame"]
            else: entry["result"]["properties"] = True
            with self.subTest(mutation=mutation):
                self.assertEqual(self.readers(value), (False, False))

    def test_both_readers_reject_rehashed_caller_entry_substitution(self):
        for mutation in ("policy", "domain", "high", "supplier", "missing", "guard"):
            value = copy.deepcopy(self.cases["caller"])
            connected = value["proof"]["models"]["connected_components"][0]
            entry = connected["entry_contract"]
            if mutation == "policy": entry["policy"] = "checked-readable-callee-stack-entry-v1"
            elif mutation == "domain": entry["operations"][0]["domain"] = "readable-wide"
            elif mutation == "high": entry["operations"][0]["private_high_offset"] = 0
            elif mutation == "supplier": connected["proof_receipt_sha256"] = "0" * 64
            elif mutation == "missing": del connected["entry_contract"]
            else:
                model = value["proof"]["models"]["operation_models"][0]["obligation_models"][0]
                model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"]
                    if not d.startswith("spx-bisimulation-connected-callee-stack-entry:")]
                model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
            with self.subTest(mutation=mutation):
                self.assertEqual(self.readers(value), (False, False))

    def test_wider_solver_bytes_are_required_even_when_frame_bytes_are_present(self):
        path = self.root / "leaf/diagnostics/operation-0000-obligation-0000/mutable-entry.stdout"
        content = path.read_bytes()
        try:
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing"):
                checked_mutable_entry_operations(self.cases["leaf"]["proof"], artifacts=self.root / "leaf/diagnostics")
        finally:
            path.write_bytes(content)
