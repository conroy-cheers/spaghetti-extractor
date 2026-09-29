"""Completion facts require checked prefix implications, including fault paths."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components import bisimulation_completion as completion
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_diagnostics import ProofQueryTimings
from spaghetti_extractor.components.bisimulation_execution import (
    _run_partitioned_properties, property_checker_command,
)
from spaghetti_extractor.components.bisimulation_property_evidence import _validate_partitioned_property_evidence
from spaghetti_extractor.components.cbmc_backend import bind_smt_solver
from .jq_reader import run as run_jq_reader
from .test_bisimulation_cutpoints import _cut_intent

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq", "z3"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}

LEMMA = {"id": "converted", "start_sync": "cut", "target_sync": "done",
         "component_id": "supplier", "operation_id": "convert", "completed_calls": 2}
SUPPLIER = {"component_id": "supplier", "summary_strategy": "scalar-body-free-v1",
            "entry_contract": None, "summary_ids": {"convert": 0}, "summary_capacity": 2,
            "source_summary_certificate": {"operation_symbols": {"convert": "convert"}}}


def intent():
    payload = _cut_intent().to_payload()
    operation = payload["operations"][0]
    operation["syncs"].append({**operation["syncs"][0], "id": "done",
        "exact_unit_id": "semantic-transfer:original-cutpoint-00001020-00001030"})
    operation["call_completion_lemmas"] = [LEMMA]
    return ComponentBisimulationIntentV1.create(component_id="counter", operations=[operation])


class CompletionLemmaTests(unittest.TestCase):
    def reader(self, packet, predicate="spx_call_completion_lemmas"):
        source = (Path(__file__).parents[3] / TESTKIT["resources"][0]).read_text()
        result = run_jq_reader([shutil.which("jq"), "-e", source + "\n" + predicate],
            input=json.dumps(packet), text=True, capture_output=True, timeout=10)
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_intent_and_binding_reject_unestablished_contracts(self):
        authored = intent().operations[0]
        bound = completion.bind(authored, "cut", [SUPPLIER], {"done"}, {})
        self.assertEqual(bound, [{**LEMMA, "summary_id": 0, "target_rva": 0x1020}])
        self.assertEqual(completion.bind(authored, "done", [SUPPLIER], set(), {}), [])
        self.assertEqual(completion.declarations([]), [])
        for field, value in (("start_sync", "missing"), ("target_sync", "missing"),
                             ("completed_calls", 0), ("completed_calls", True),
                             ("completed_calls", 2**32), ("id", "not-c-safe")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                completion.parse_lemmas([{**LEMMA, field: value}], {"cut", "done"})
        for suppliers, targets in (([], {"done"}), ([SUPPLIER, SUPPLIER], {"done"}),
                ([{**SUPPLIER, "summary_capacity": 1}], {"done"}),
                ([{**SUPPLIER, "summary_ids": {}}], {"done"}),
                ([{**SUPPLIER, "summary_strategy": "connected-replay-v1"}], {"done"}),
                ([{**SUPPLIER, "entry_contract": {}}], {"done"}),
                ([{**SUPPLIER, "assurance": {}}], {"done"}), ([SUPPLIER], set())):
            with self.subTest(suppliers=suppliers, targets=targets), self.assertRaises(ValueError):
                completion.bind(authored, "cut", suppliers, targets, {})

    def check_model(self, root, case, *, smt=True):
        bound = completion.bind(intent().operations[0], "cut", [SUPPLIER], {"done"}, {})
        source = root / "prefix.c"
        # Symbolic completion and outcome inputs cover incomplete calls as well
        # as success. The production helper is the only added control premise.
        statements = {
            "correct": "if (count >= 2U && finished) { kind = 1U; target = 0x1020U; }",
            "wrong_target": "count = 2U; finished = 1U; kind = 1U; target = 0x1021U;",
            "fault": "count = 2U; finished = 1U; kind = 4U; target = 0x1020U;",
            "unfinished": "count = 2U; finished = 0U; kind = 4U; target = 0x1021U;",
            "too_few": "count = 1U; finished = 1U; kind = 4U; target = 0x1021U;",
        }
        consumer_guard = "  __CPROVER_assume(count >= 2U && finished);\n" if case == "correct" else ""
        source.write_text('''
typedef unsigned int uint32_t;
#define UINT32_C(n) n##U
#define SPX_BRANCH 1U
unsigned nondet(void) { unsigned value; __CPROVER_havoc_object(&value); return value; }
static unsigned spx_proof_connected_0000_exact_count;
static unsigned spx_proof_connected_0000_finished[2];
static struct {unsigned kind, target_rva;} spx_proof_exact_result;
''' + "\n".join(completion.declarations(bound)) + '''
void proof(void) {
  unsigned count = nondet(), finished = nondet(), kind = nondet(), target = nondet();
  __CPROVER_assume(count <= 2U && finished <= 1U);
''' + statements[case] + '''
  unsigned index = nondet();
  __CPROVER_assume(index < 2U);
  spx_proof_connected_0000_finished[index] = 0U;
  spx_proof_connected_0000_exact_count = count;
  spx_proof_connected_0000_finished[1] = finished;
  spx_proof_exact_result.kind = kind;
  spx_proof_exact_result.target_rva = target;
  spx_proof_call_completion_converted();
''' + consumer_guard + '''
  __CPROVER_assert(kind <= 1U && target == 0x1020U, "consumer-successor");
}
''')
        model_path = root / "prefix.goto"
        subprocess.run([shutil.which("goto-cc"), "--i386-win32", str(source), "-o", str(model_path)],
                       check=True, capture_output=True, text=True)
        command = property_checker_command([], completion_lemmas=True,
            smt_solver=bind_smt_solver(Path(shutil.which("z3"))) if smt else None)
        required = sorted([completion.description(LEMMA), "consumer-successor"])
        result = _run_partitioned_properties(cbmc=Path(shutil.which("cbmc")), goto_model=model_path,
            command=command, proof_function="proof", required_assertion_descriptions=required,
            timeout_seconds=30, timings=ProofQueryTimings(model_path, {}))
        queries = [json.loads(line) for line in (root / "query-timings.jsonl").read_text().splitlines()]
        for query in queries:
            args = query["command"]
            if "--property" not in args:
                continue
            is_lemma = "spx_proof_call_completion_converted.assertion.1" in args
            self.assertEqual("--external-smt2-solver" in args, smt and not is_lemma)
            self.assertEqual("--sat-solver" in args, not smt or is_lemma)
        return result, {"proof_function": "proof", "property_checker_command": command,
                        "required_assertion_descriptions": required,
                        "required_assertion_descriptions_sha256": canonical_sha256_v3(required)}

    def test_checked_prefix_cannot_hide_fault_or_wrong_successor(self):
        for case, smt in (("correct", True), ("correct", False), ("wrong_target", True),
                          ("fault", True), ("unfinished", True), ("too_few", True)):
            with self.subTest(case=case, smt=smt), tempfile.TemporaryDirectory() as directory:
                result, model = self.check_model(Path(directory), case, smt=smt)
                self.assertEqual(result["status"], "satisfied" if case == "correct" else "violated", result)
                _validate_partitioned_property_evidence(shard=result, model=model)
                authored = [q for q in result["partitioned_evidence"]["queries"] if q["kind"] == "authored_assertion"]
                self.assertEqual(authored[0].get("property_ids", [authored[0].get("property_id")]), ["spx_proof_call_completion_converted.assertion.1"])
                self.assertEqual(authored[0]["status"], "violated" if case in {"wrong_target", "fault"} else "satisfied")
                if case == "correct":
                    self.check_reader_mutations(result, model)

    def check_reader_mutations(self, result, model):
        operation = intent().to_payload()["operations"][0]
        policy = completion.metadata(intent().operations[0])
        model.update(policy, obligation_id="sync:cut")
        planned = {"operation_id": "run", "source": operation}
        packet = {"proof_plan": {"operations": [planned]}, "proof": {"models": {
            "connected_components": [SUPPLIER], "operation_models": [
                {**policy, "operation_id": "run", "obligation_models": [model]}]}, "shards": [result]}}
        completion.validate_model(planned, model, [SUPPLIER])
        self.assertTrue(self.reader(packet))
        for change in ("missing-label", "stale-policy", "conditional-supplier", "missing-query", "wrong-site", "weakened-unwind"):
            forged = copy.deepcopy(packet)
            proof = forged["proof"]
            changed = proof["models"]["operation_models"][0]["obligation_models"][0]
            shard = proof["shards"][0]
            evidence = shard["partitioned_evidence"]
            if change == "missing-label":
                changed["required_assertion_descriptions"].remove(completion.description(LEMMA))
            elif change == "stale-policy":
                changed[completion.FIELD] = "unchecked"
            elif change == "conditional-supplier":
                proof["models"]["connected_components"][0]["entry_contract"] = {}
            elif change == "missing-query":
                # Even incomplete packets must not skip the checked premise and
                # retain only later queries that consumed its assumption.
                shard["status"] = "incomplete"
                evidence["queries"] = [q for q in evidence["queries"] if q["kind"] != "authored_assertion" or
                    "spx_proof_call_completion_converted.assertion.1" not in q.get("property_ids", [q.get("property_id")])]
            elif change == "wrong-site":
                next(a for a in evidence["assertions"] if a["description"].startswith(completion.PREFIX))["source_function"] = "unrelated"
            else:
                changed["property_checker_command"]["completion_assertion_arguments"].remove("--unwinding-assertions")
            shard["output_sha256"] = canonical_sha256_v3(evidence)
            with self.subTest(mutation=change):
                if change in {"missing-query", "wrong-site"}:
                    with self.assertRaises(ValueError):
                        _validate_partitioned_property_evidence(shard=shard, model=changed)
                elif change != "weakened-unwind":
                    with self.assertRaises(ValueError):
                        completion.validate_model(planned, changed, proof["models"]["connected_components"])
                if change != "missing-query":
                    self.assertFalse(self.reader(forged))
                else:
                    self.assertFalse(self.reader(evidence, "spx_selected_authored_queries"))
