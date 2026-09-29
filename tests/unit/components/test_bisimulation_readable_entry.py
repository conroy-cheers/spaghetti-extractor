"""Expanded callee domains require a new paired theorem, not an assumption."""

import copy
import hashlib
import json
from .jq_reader import run as run_jq_reader
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_exact_frame import ACTIVE, frame_private_low
from spaghetti_extractor.components.bisimulation_readable_entry import checked_memory_summary_facts
from spaghetti_extractor.components.bisimulation_readable_composition import image_readable_operations
from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
from spaghetti_extractor.components.bisimulation_view_extent import stack_admission_expression
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload
from tests.unit.components.readable_transfer_fixture import reader_transfers, DOMAIN_TRAP_ESP
from tests.unit.components.connected_reader_fixture import check_connected_reader
from spaghetti_extractor.transfer.evaluator import EvaluatorStateV1, EvaluatorMemoryV1, _evaluate_transfer

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}


class ReadableEntryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc", "goto-instrument", "jq")):
            raise unittest.SkipTest("CBMC and both receipt-reader tools are required")
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.root = Path(directory.name)
        cls.cases = []
        for trap in (False, True):
            root = cls.root / str(trap)
            root.mkdir()
            result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
                read_buffer=True, return_to_caller=True, source_contracts=True,
                reference_authority=authority_payload(), entry_domain_trap=trap)
            if result["status"] != "satisfied":
                raise AssertionError(result.get("issues"))
            cls.cases.append(json.loads((root / "contextual-refinement-result.json").read_text()))
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()

    def readers(self, value):
        proof = value["proof"]
        for shard in proof["shards"]:
            if "readable_entry_contract" in shard:
                entry = shard["readable_entry_contract"]
                entry["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in entry.items() if k != "receipt_sha256"})
        for connected in proof["models"]["connected_components"]:
            contract = connected.get("entry_contract")
            if contract is not None:
                contract["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in contract.items() if k != "receipt_sha256"})
        proof["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in proof.items() if k != "receipt_sha256"})
        try:
            validate_contextual_refinement_v2(proof, proof_plan=value["proof_plan"], exact_c_slice=value["exact_c_slice"])
            python = True
        except ValueError:
            python = False
        jq = run_jq_reader([shutil.which("jq"), "-e", self.program + "\nspx_contextual_proof_system"],
                            input=json.dumps(value), text=True, capture_output=True)
        return python, jq.returncode == 0

    def test_a_wider_domain_requires_new_equivalence_even_when_old_proof_and_frame_pass(self):
        for trap, value in zip((False, True), self.cases, strict=True):
            with self.subTest(trap=trap):
                self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
                facts = checked_memory_summary_facts(value["proof"], artifacts=self.root / str(trap) / "diagnostics")
                self.assertEqual(facts["empty_exact_frame_operations"], ("run",))
                self.assertEqual(facts["readable_entry_operations"], () if trap else ("run",))
                self.assertEqual(facts["readable_machine_state_operations"], () if trap else ("run",))
                self.assertEqual([s["readable_entry_contract"]["result"]["status"] for s in value["proof"]["shards"]],
                                 ["satisfied", "violated" if trap else "satisfied"])
        self.assertEqual(self.cases[1]["proof"]["shards"][-1]["readable_entry_contract"]["result"]["detail"],
                         "spx-bisimulation-exit-observable:run:result:value")

    def test_missing_segment_keeps_ordinary_qualification_without_the_stronger_fact(self):
        value = copy.deepcopy(self.cases[0])
        del value["proof"]["shards"][-1]["readable_entry_contract"]
        self.assertEqual(self.readers(value), (True, True))
        facts = checked_memory_summary_facts(value["proof"], artifacts=self.root / "False" / "diagnostics")
        self.assertEqual(facts["readable_entry_operations"], ())

    @classmethod
    def caller_cases(cls):
        if not hasattr(cls, "_callers"):
            cls._callers = []
            for trap in (False, True):
                root = cls.root / ("caller-" + str(trap))
                result = check_connected_reader(root, leaf=cls.root / str(trap),
                    cbmc=Path(shutil.which("cbmc")), domain_trap=trap,
                    proof_workspace=cls.root / ("caller-work-" + str(trap)))
                cls._callers.append((result, json.loads((root / "contextual-refinement-result.json").read_text())))
        return cls._callers

    def test_actual_call_establishes_supplier_domain_and_rejects_the_previously_accepted_trap(self):
        for trap, (result, value) in zip((False, True), self.caller_cases(), strict=True):
            with self.subTest(trap=trap):
                self.assertEqual(result["status"], "violated" if trap else "satisfied", result.get("issues"))
                connected = result["bindings"]["connected_components"][0]
                self.assertEqual(connected["summary_strategy"],
                                 "connected-replay-v1" if trap else "image-readable-body-free-v1")
                self.assertEqual(connected["readable_transport_policy"], "canonical-readable-callee-transport-v1")
                self.assertEqual(connected["entry_contract"]["operations"][0]["domain"],
                                 "ordinary" if trap else "readable-wide")
                # Both readers validate honest negative receipts; satisfaction is a separate gate.
                self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
        rejected, packet = self.caller_cases()[1]
        guards = {f"spx-bisimulation-connected-callee-{kind}:counter:run"
                  for kind in ("stack-entry", "machine-state")}
        # The trap lacks both domain guarantees. A batched SAT query may find
        # either counterexample first; both guards must remain proof obligations.
        self.assertIn(rejected["issues"][0]["detail"], guards)
        required = {description for operation in packet["proof"]["models"]["operation_models"]
                    for model in operation["obligation_models"]
                    for description in model["required_assertion_descriptions"]}
        self.assertTrue(guards <= required)

    def test_caller_readers_reject_rehashed_entry_claims_and_missing_guards(self):
        for mutation in ("domain", "high", "image", "supplier", "binding", "missing", "guard", "transitive", "transport-policy", "transport-guard", "transport-entire", "transport-overlay", "readable-entry-guard", "empty-world-guard", "parent-authority"):
            value = copy.deepcopy(self.caller_cases()[0][1])
            connected = value["proof"]["models"]["connected_components"][0]
            entry = connected["entry_contract"]
            if mutation == "domain": entry["operations"][0]["domain"] = "ordinary"
            elif mutation == "high": entry["operations"][0]["private_high_offset"] = 0
            elif mutation == "image": entry["operations"][0]["machine_image"]["image_size"] = 1
            elif mutation == "supplier": connected["proof_receipt_sha256"] = "f" * 64
            elif mutation == "binding": entry["binding_intent"]["intent_sha256"] = "f" * 64
            elif mutation == "missing": del connected["entry_contract"]
            elif mutation == "transitive": entry["proof_system"]["proof"]["models"]["connected_components"] = [{}]
            elif mutation == "transport-policy": del connected["readable_transport_policy"]
            elif mutation == "parent-authority": value["proof"]["models"]["reference_authority"] = None
            elif mutation in {"readable-entry-guard", "empty-world-guard"}:
                prefix = ("spx-bisimulation-connected-readable-entry:" if mutation == "readable-entry-guard"
                          else "spx-bisimulation-connected-summary-readable-empty-allocation-world")
                for model in value["proof"]["models"]["operation_models"][0]["obligation_models"]:
                    model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"] if not d.startswith(prefix)]
                    model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
            elif mutation == "transport-overlay":
                for model in value["proof"]["models"]["operation_models"][0]["obligation_models"]:
                    model["proof_inputs"] = [row for row in model["proof_inputs"]
                        if row["sha256"] != connected["proof_overlay_sha256"]]
            elif mutation in {"transport-guard", "transport-entire"}:
                if mutation == "transport-entire": del connected["readable_transport_policy"]
                for model in value["proof"]["models"]["operation_models"][0]["obligation_models"]:
                    model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"]
                        if not d.startswith("spx-bisimulation-connected-summary-readable-")]
                    model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
            else:
                for model in value["proof"]["models"]["operation_models"][0]["obligation_models"]:
                    model["required_assertion_descriptions"] = [d for d in model["required_assertion_descriptions"]
                        if not d.startswith("spx-bisimulation-connected-callee-stack-entry:")]
                    model["required_assertion_descriptions_sha256"] = canonical_sha256_v3(model["required_assertion_descriptions"])
            with self.subTest(mutation=mutation):
                self.assertEqual(self.readers(value), (False, False))

    def test_actual_caller_cannot_replace_the_checked_world_reader(self):
        root = self.root / "forged-reader"
        result = check_connected_reader(root, leaf=self.root / "False",
            cbmc=Path(shutil.which("cbmc")), forged_reader=True)
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["issues"][0]["detail"], "spx-bisimulation-connected-summary-readable-runtime")
        self.assertEqual(self.readers(json.loads((root / "contextual-refinement-result.json").read_text())), (True, True))

    def test_actual_body_free_call_requires_a_valid_native_view_and_equal_readable_contents(self):
        for name, flags, description in (
            ("invalid-view", {"invalid_callee_view": True}, "spx-bisimulation-connected-readable-entry:counter:run"),
            ("changed-byte", {"changed_byte": True}, "spx-bisimulation-exit-world-memory:run:spx_bisimulation_check_0000"),
        ):
            with self.subTest(case=name):
                root = self.root / name
                result = check_connected_reader(root, leaf=self.root / "False",
                    cbmc=Path(shutil.which("cbmc")), **flags)
                self.assertEqual(result["status"], "violated", result.get("issues"))
                self.assertEqual(result["issues"][0]["detail"], description)
                self.assertEqual(self.readers(json.loads((root / "contextual-refinement-result.json").read_text())), (True, True))

    def test_unimplemented_world_or_frame_premises_keep_replay(self):
        parent = self.caller_cases()[0][1]["proof"]["models"]
        original = parent["connected_components"][0]["entry_contract"]
        self.assertIsNotNone(image_readable_operations(original, parent))
        for mutation in ("finite-control", "allocation", "image", "guard-function", "missing-wide", "missing-frame-description"):
            entry, world = copy.deepcopy(original), copy.deepcopy(parent)
            child = entry["proof_system"]["proof"]
            operation = child["models"]["operation_models"][0]
            if mutation == "finite-control": operation["obligation_models"][0]["finite_control_route_inventory_sha256"] = "a" * 64
            elif mutation == "allocation": world["reference_allocation_requirements"] = []
            elif mutation == "image": world["operation_models"][0]["machine_image"]["image_size"] += 1
            elif mutation == "missing-wide": del child["shards"][0]["readable_entry_contract"]
            elif mutation == "missing-frame-description": operation["obligation_models"][0]["required_assertion_descriptions"].remove("spx-bisimulation-readable-cut-machine-state")
            else:
                row = next(r for r in child["shards"][0]["partitioned_evidence"]["assertions"]
                           if r["property_id"] == "__CPROVER_spx_readable_cut_machine_state.assertion.1")
                row["source_function"] = "unrelated_function"
            with self.subTest(mutation=mutation):
                self.assertIsNone(image_readable_operations(entry, world))

    def test_query_reuse_requires_the_previous_proof_to_validate(self):
        root = self.root / "previous-proof-validation"
        root.mkdir()
        value = copy.deepcopy(self.cases[0])
        path = root / "contextual-refinement-result.json"
        path.write_text(json.dumps(value))
        self.assertEqual(len(previous_proof_queries(root)), 2)
        value["proof"]["receipt_sha256"] = "f" * 64
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "previous query proof"):
            previous_proof_queries(root)

    @staticmethod
    def goto_bodies(model):
        value = json.loads(subprocess.check_output([shutil.which("goto-instrument"), "--json-ui", "--show-goto-functions", str(model)], text=True))
        functions = next(row["functions"] for row in value if "functions" in row)
        return {row["name"]: len(row["instructions"]) for row in functions if row["isBodyAvailable"]}

    def test_z_callee_growth_reuses_the_checked_parent_queries(self):
        # Reuse the conditional theorem while binding the exact new supplier.
        # Native provider/activation evidence remains a separate obligation.
        before = copy.deepcopy(self.caller_cases()[0][1]["proof"])
        root = self.root / "caller-False"
        diagnostics = root / "diagnostics"
        model_path = Path("operation-0000-obligation-0000/model.goto")
        bodies = self.goto_bodies(diagnostics / model_path)
        before_model = before["models"]["operation_models"][0]["obligation_models"][0]
        self.assertEqual(hashlib.sha256((diagnostics / model_path).read_bytes()).hexdigest(), before_model["goto_model_sha256"])
        self.assertNotIn("spx_sub_00001000", bodies)
        self.assertFalse(any(name.startswith("spx_proof_connected_impl_") for name in bodies))
        self.assertIn("authored_run", bodies)  # The summary wrapper retains this ABI symbol.
        previous = self.root / "caller-before-edit"
        shutil.copytree(root, previous)
        shutil.move(diagnostics, self.root / "caller-before-edit-diagnostics")
        leaf = self.root / "grown-leaf"
        leaf.mkdir()
        result = check_normal_exit(leaf, cbmc=Path(shutil.which("cbmc")), reference_view=True,
            read_buffer=True, return_to_caller=True, source_contracts=True,
            reference_authority=authority_payload(), readable_body_growth=32)
        self.assertEqual(result["status"], "satisfied", result.get("issues"))
        child_model = Path("diagnostics/operation-0000-obligation-0001/exact-frame.goto")
        self.assertGreater(self.goto_bodies(leaf / child_model)["authored_run"],
                           self.goto_bodies(self.root / "False" / child_model)["authored_run"])
        execute = subprocess.run
        def no_new_solver(command, *args, **kwargs):
            if Path(command[0]).name == "cbmc" and "--version" not in command:
                raise AssertionError("unchanged parent attempted a new CBMC query")
            return execute(command, *args, **kwargs)
        with patch("spaghetti_extractor.components.cbmc_backend.subprocess.run", side_effect=no_new_solver):
            result = check_connected_reader(root, leaf=leaf, cbmc=Path(shutil.which("cbmc")),
                proof_workspace=self.root / "caller-work-False", previous_query_evidence=previous)
        self.assertEqual(result["status"], "satisfied", result.get("issues"))
        reuse = json.loads((diagnostics / "operation-0000-obligation-0000/query-evidence/reuse.json").read_text())
        self.assertEqual(reuse["executed_queries"], 0)
        self.assertGreater(reuse["reused_queries"], 0)
        after = json.loads((root / "contextual-refinement-result.json").read_text())
        self.assertEqual(self.readers(copy.deepcopy(after)), (True, True))
        after_model = after["proof"]["models"]["operation_models"][0]["obligation_models"][0]
        self.assertEqual(self.goto_bodies(diagnostics / model_path), bodies)
        self.assertEqual(before_model["proof_inputs"], after_model["proof_inputs"])
        self.assertEqual(before_model["proof_model_sha256"], after_model["proof_model_sha256"])
        self.assertEqual(before_model["goto_model_sha256"], after_model["goto_model_sha256"])
        self.assertNotEqual(before["models"]["connected_components"][0]["proof_receipt_sha256"],
                            after["proof"]["models"]["connected_components"][0]["proof_receipt_sha256"])
        self.assertEqual(hashlib.sha256((diagnostics / model_path).read_bytes()).hexdigest(), after_model["goto_model_sha256"])

    def test_transport_assembly_preserves_raw_overlay_bytes_and_compiles_only_its_wrapper(self):
        self.caller_cases()
        root = self.root / "caller-False" / "diagnostics"
        original = root / "connected-0000/machine-overlay.c"
        self.assertEqual(original.read_bytes(), (self.root / "False/diagnostics/overlay-0000.c").read_bytes())
        wrapper = root / "connected-0000/machine-overlay-transport.c"
        self.assertTrue(wrapper.read_text().startswith('#include "machine-overlay.c"\n'))
        model = self.caller_cases()[0][1]["proof"]["models"]
        expected = model["connected_components"][0]["proof_overlay_sha256"]
        for obligation in model["operation_models"][0]["obligation_models"]:
            self.assertEqual(sum(row["role"] == "connected_provider_c" and row["sha256"] == expected
                                 for row in obligation["proof_inputs"]), 1)
        command = json.loads((root / "operation-0000-obligation-0000/compile-inputs.json").read_text())["command"]
        self.assertEqual(sum(arg.endswith("/machine-overlay-transport.c") for arg in command), 1)
        self.assertFalse(any(arg.endswith("/connected-0000/machine-overlay.c") for arg in command))

    def test_readable_summary_needs_the_original_machine_exit_frame(self):
        root = self.root / "register-frame"
        root.mkdir()
        result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
            read_buffer=True, return_to_caller=True, source_contracts=True,
            reference_authority=authority_payload(), readable_clobber_ecx=True)
        self.assertEqual(result["status"], "satisfied", result.get("issues"))
        value = json.loads((root / "contextual-refinement-result.json").read_text())
        self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
        facts = checked_memory_summary_facts(value["proof"], artifacts=root / "diagnostics")
        self.assertEqual(facts["empty_exact_frame_operations"], ("run",))
        self.assertEqual(facts["readable_machine_state_operations"], ())
        self.assertEqual(value["proof"]["shards"][-1]["readable_entry_contract"]["result"]["detail"],
            "spx-bisimulation-readable-machine-state")

    def test_exit_frame_cannot_hide_a_machine_state_change_before_a_cut(self):
        root = self.root / "cut-register-frame"
        root.mkdir()
        result = check_normal_exit(root, cbmc=Path(shutil.which("cbmc")), reference_view=True,
            read_buffer=True, return_to_caller=True, source_contracts=True,
            reference_authority=authority_payload(), readable_clobber_before_cut=True)
        self.assertEqual(result["status"], "satisfied", result.get("issues"))
        value = json.loads((root / "contextual-refinement-result.json").read_text())
        self.assertEqual(self.readers(copy.deepcopy(value)), (True, True))
        facts = checked_memory_summary_facts(value["proof"], artifacts=root / "diagnostics")
        self.assertEqual(facts["empty_exact_frame_operations"], ("run",))
        self.assertEqual(facts["readable_machine_state_operations"], ())
        self.assertEqual(value["proof"]["shards"][0]["readable_entry_contract"]["result"]["detail"],
                         "spx-bisimulation-readable-cut-machine-state")
        self.assertEqual(value["proof"]["shards"][-1]["readable_entry_contract"]["result"]["status"], "satisfied")

    def test_readers_reject_weakened_rehashed_domain_or_model_claims(self):
        for mutation in ("domain", "policy", "command", "model", "property", "fields", "frame"):
            value = copy.deepcopy(self.cases[0])
            shard = value["proof"]["shards"][-1]
            entry = shard["readable_entry_contract"]
            if mutation == "domain": entry["domain"]["minimum_esp"] = 0
            elif mutation == "policy": entry["policy"] = "declared-entry-compatible"
            elif mutation == "command": entry["command"].remove("--no-self-loops-to-assumptions")
            elif mutation == "model": entry["bindings"]["goto_model_sha256"] = "f" * 64
            elif mutation == "property": entry["result"]["property_ids"] = []
            elif mutation == "fields": entry["assuming_caller"] = True
            else: del shard["exact_memory_frame"]
            with self.subTest(mutation=mutation):
                self.assertEqual(self.readers(value), (False, False))

    def test_supplier_reads_actual_transcripts_and_rejects_a_fabricated_stronger_success(self):
        value = copy.deepcopy(self.cases[1])
        entry = value["proof"]["shards"][-1]["readable_entry_contract"]
        digest = entry["result"]["output_sha256"]
        entry["result"] = copy.deepcopy(self.cases[0]["proof"]["shards"][-1]["readable_entry_contract"]["result"])
        entry["result"]["output_sha256"] = digest
        self.assertEqual(self.readers(value), (True, True))
        with self.assertRaisesRegex(ValueError, "does not prove"):
            checked_memory_summary_facts(value["proof"], artifacts=self.root / "True" / "diagnostics")
        with self.assertRaisesRegex(ValueError, "missing"):
            checked_memory_summary_facts(self.cases[0]["proof"], artifacts=self.root / "absent")


class ReadableEntryDomainTests(unittest.TestCase):
    def test_original_transfer_exposes_the_behavior_outside_the_old_callee_domain(self):
        # Veto-only concrete evidence: an actual CALL from the admitted caller
        # ESP reaches this child input. This is not a native activation test.
        outputs = []
        for trap in (False, True):
            state = EvaluatorStateV1.from_payload({"registers": {"esp": DOMAIN_TRAP_ESP, "ebx": 0x401004}})
            memory = EvaluatorMemoryV1({0x401004: 17, **{DOMAIN_TRAP_ESP + i: 0 for i in range(4)}})
            memory.write(DOMAIN_TRAP_ESP, 4, 0x402001)
            result = _evaluate_transfer(reader_transfers(domain_trap=trap)[1], state, memory, {}, None)
            self.assertEqual(result, {"kind": "return", "target_rva": 0, "value": 0x402001})
            outputs.append(state.registers["eax"])
        self.assertEqual(outputs, [17, 18])

    def test_ordinary_domain_inclusion_and_reached_call_domain_are_checked(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        def predicate(esp, relaxed=False):
            return stack_admission_expression(stack_pointer=esp, high_offset="high",
                image_base=0x400000, image_size=0x10000, readable_entry=relaxed)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "domain.c"
            source.write_text(f'''#include <stdint.h>
static uint32_t {ACTIVE};
void check(void) {{
  uint32_t esp, high;
  __CPROVER_assume(high >= 1024U && high <= 4096U);
  uint32_t ordinary = {predicate('esp')};
  {ACTIVE} = 0U;
  __CPROVER_assert(ordinary == {predicate('esp', True)}, "ordinary domain unchanged");
  {ACTIVE} = 2U;
  __CPROVER_assert(!ordinary || {predicate('esp', True)}, "ordinary witness remains admitted");
  __CPROVER_assert(!ordinary || {predicate('esp - 4U', True)}, "actual callee stack domain admitted");
  uint32_t entry_esp = esp;
  __CPROVER_assert(!ordinary || ({frame_private_low(True)}) == ({frame_private_low(False)}),
                   "ordinary witness retains private memory partition");
}}
''')
            result = run_cbmc_properties(command=[cbmc, str(source), "--function", "check", "--json-ui",
                "--trace", "--unwind", "2", "--unwinding-assertions"], timeout_seconds=10)
            self.assertEqual(result["status"], "satisfied", result)
