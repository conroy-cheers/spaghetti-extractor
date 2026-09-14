"""An outgoing source cut cannot silently match an exact return or fault."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_cutpoints import _cut_intent

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


def check_cut(kind, *, target=0x1010, inactive=False, resume=False, tail=False, start_only=False, revisit=False):
    authored = _cut_intent().operations[0]
    header = _render_proof_header(authored=authored, image_base=0,
        active_start_sync_id="cut" if resume else None,
        active_target_sync_ids=set() if inactive or start_only else {"cut"})
    source = header + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) { return 1U; }
uint32_t spx_proof_world_atomics_equal(void) { return 1U; }
uint32_t spx_proof_world_public_memory_equal(void) { return 1U; }
uint32_t spx_proof_world_allocation_cut_admitted(void) { return 1U; }
uint32_t spx_proof_world_connected_calls_equal(void) { return 1U; }
void spx_bisimulation_relation_witness(void) {}
void spx_proof_unexpected_sync_cut(uint32_t aligned) {
  __CPROVER_assert(aligned, "spx-bisimulation-unexpected-sync:cut");
}
uint32_t candidate(void) {
  uint32_t n=42U;
  SPX_PROOF_BEGIN(run);
''' + ('  for (;;) {\n' if revisit else '') + '''  SPX_PROOF_SYNC(cut,1,n);
''' + ('  }\n' if revisit else '') + ('  __CPROVER_assert(0,"source tail reached");\n' if tail else '') + '''
  return spx_proof_exact_result.kind;
}
int main(void) {
  spx_proof_exact_input.edx=spx_proof_exact_output.edx=42U;
''' + f'''
  spx_proof_start={int(resume)}U;
  spx_proof_exact_result=(spx_step_result){{{kind},{target}U,0U}};
  uint32_t result=candidate();
  __CPROVER_assert(result==spx_proof_exact_result.kind,"terminal outcomes agree");
}}
'''
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        _write_cbmc_stdint(root / "stdint.h")
        (root / "state-machine-runtime.h").write_text(exact_runtime_header())
        path = root / "cuts.c"
        path.write_text(source)
        return run_cbmc_properties(command=[shutil.which("cbmc"), str(path),
            "--json-ui", "--trace", "--stop-on-fail", "--unwind", "3",
            "--unwinding-assertions", "--sat-solver", "cadical"], timeout_seconds=20)


class TerminalCutTests(unittest.TestCase):
    def test_independent_reader_rejects_omitted_alignment_and_unexpected_cut_checks(self):
        authored = _cut_intent().operations[0]
        sync = authored.syncs[0].to_payload()
        program = (Path(__file__).parents[3] / TESTKIT["resources"][0]).read_text()
        for outgoing in (False, True):
            required = _required_assertion_descriptions(authored=authored, proof_function="check",
                active_start_sync_id=None, next_sync_ids={"cut"} if outgoing else set(),
                logical_projection={"results": [], "state": []}, continuous_acyclic=False,
                typed_call_positions=())
            guard = "spx-bisimulation-" + ("sync-alignment" if outgoing else "unexpected-sync") + ":cut"
            self.assertIn(guard, required)
            planned = {"operation_id": "run", "source": {"syncs": [sync]}, "exact": {
                "control_edges": [{"source_unit_id": "entry", "target_unit_id": sync["exact_unit_id"]}]
                if outgoing else []}}
            model = {"obligation_id": "entry", "selected_unit_ids": ["entry"],
                     "required_assertion_descriptions": required}
            document = {"proof_plan": {"operations": [planned]}, "proof": {"models": {
                "operation_models": [{"operation_id": "run", "obligation_models": [model]}]}}}
            for omit in (False, True):
                value = copy.deepcopy(document)
                if omit:
                    value["proof"]["models"]["operation_models"][0]["obligation_models"][0][
                        "required_assertion_descriptions"].remove(guard)
                result = subprocess.run([shutil.which("jq"), "-e", program + "\nspx_cut_capture_codecs"],
                    input=json.dumps(value), text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, int(omit), (outgoing, omit, result.stderr))

    def test_start_only_cut_rejects_a_revisit_even_when_the_exact_target_matches(self):
        result = check_cut("SPX_BRANCH", resume=True, start_only=True, revisit=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-sync-alignment:cut")

    def test_outgoing_cut_rejects_terminal_and_other_control_outcomes(self):
        for kind, target in (("SPX_MEMORY_FAULT", 0), ("SPX_EXTERNAL_FAULT", 0),
                             ("SPX_RETURN", 0), ("SPX_BRANCH", 0x1020)):
            with self.subTest(kind=kind):
                result = check_cut(kind, target=target)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], "spx-bisimulation-sync-alignment:cut")

    def test_matched_cut_stops_before_source_tail(self):
        result = check_cut("SPX_BRANCH", tail=True)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_unexpected_cut_rejects_even_when_exact_side_faulted(self):
        result = check_cut("SPX_MEMORY_FAULT", inactive=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-unexpected-sync:cut")

    def test_incoming_cut_can_resume_toward_a_terminal_outcome(self):
        result = check_cut("SPX_MEMORY_FAULT", resume=True)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
