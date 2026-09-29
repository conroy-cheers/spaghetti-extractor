"""One operation's proof barriers must not instrument a neighboring body."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationError
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.contextual_bisimulation import (
    operation_proof_source, operation_source_text,
)
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_cutpoints import _cut_intent


TESTKIT = {"fixtures": ("cbmc", "compiler")}
SYMBOLS = {"run": "lifted", "neighbor": "neighbor"}
SOURCE = '''
/* neighbor(void) { SPX_PROOF_BEGIN(neighbor); } */
uint32_t neighbor(uint32_t n);
uint32_t neighbor(uint32_t n) {
  SPX_PROOF_BEGIN(neighbor);
  uint32_t other = n;
  /* Different arity, same operation-local cut name. */
  SPX_PROOF_SYNC(cut, 1, n, other);
  return other + DELTA;
}
void lifted(uint32_t n) {
  SPX_PROOF_BEGIN(run);
  n = neighbor(n);
  SPX_PROOF_SYNC(cut, 1, n);
}
'''


class OperationMarkerTests(unittest.TestCase):
    def test_definitions_ignore_comments_literals_and_prototypes(self):
        source = '/* lifted(void) { } */\nvoid lifted(void);\n' + '''
void lifted(void) {
  const char *text = "} lifted(void) { SPX_PROOF_BEGIN(run);";
  /* } */ SPX_PROOF_BEGIN(run);
}
'''
        body = operation_source_text(source, "lifted")
        self.assertTrue(body.startswith("lifted(void) {"))
        self.assertIn("/* } */ SPX_PROOF_BEGIN(run);", body)
        with self.assertRaisesRegex(ComponentBisimulationError, "2 source definitions"):
            operation_source_text(source + "void lifted(void) {}", "lifted")

    def test_only_neighbor_annotations_change_and_line_positions_survive(self):
        source = SOURCE.replace("SPX_PROOF_SYNC(cut, 1, n, other)",
            "SPX_PROOF_SYNC(cut,\n    1, n, other)")
        scoped = operation_proof_source(source, active_operation="run", symbols=SYMBOLS)
        self.assertEqual(operation_source_text(source, "lifted"),
                         operation_source_text(scoped, "lifted"))
        self.assertEqual(len(source), len(scoped))
        self.assertEqual([i for i, c in enumerate(source) if c == "\n"],
                         [i for i, c in enumerate(scoped) if c == "\n"])
        self.assertIn("return other + DELTA;", scoped)
        self.assertTrue(scoped.startswith("\n/* neighbor(void) { SPX_PROOF_BEGIN(neighbor); } */"))
        self.assertNotIn("SPX_PROOF_", operation_source_text(scoped, "neighbor"))
        self.assertEqual(operation_proof_source(source, active_operation="run",
                                               symbols={"run": "lifted"}), source)

    def test_unknown_operation_and_duplicate_neighbor_definitions_reject(self):
        with self.assertRaisesRegex(ComponentBisimulationError, "unknown operation"):
            operation_proof_source(SOURCE, active_operation="absent", symbols=SYMBOLS)
        with self.assertRaisesRegex(ComponentBisimulationError, "multiple source definitions"):
            operation_proof_source(SOURCE + "uint32_t neighbor(uint32_t n) { return n; }",
                                   active_operation="run", symbols=SYMBOLS)

    def check_calls(self, delta):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "proof.h").write_text(_render_proof_header(
                authored=_cut_intent().operations[0], image_base=0x400000,
                active_target_sync_ids={"cut"}))
            world = _world_source(max_writes=1, max_private_writes=1, max_calls=1,
                max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
                service_bindings=(), private_ranges=())
            source = root / "proof.c"
            source.write_text('#include "proof.h"\n' + world + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) { return 1U; }
uint32_t spx_proof_world_atomics_equal(void) { return 1U; }
uint32_t spx_proof_world_connected_calls_equal(void) { return 1U; }
void spx_bisimulation_relation_witness(void) { __CPROVER_cover(1); }
''' + operation_proof_source(SOURCE.replace("DELTA", f"{delta}U"),
                            active_operation="run", symbols=SYMBOLS) + '''
void main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  spx_proof_exact_output.edx = 5U;
  spx_proof_exact_result = (spx_step_result){SPX_BRANCH, 0x1010U, 0U};
  lifted(4U);
}
''')
            return run_cbmc_properties(command=[cbmc, str(source), "--json-ui", "--trace",
                "--unwind", "4", "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--sat-solver", "cadical"], timeout_seconds=30)

    def test_shared_cut_name_different_capture_arity_compiles_and_checks(self):
        result = self.check_calls(1)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_neighbor_body_still_executes_and_active_cut_detects_wrong_result(self):
        result = self.check_calls(2)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-capture:cut:n")
