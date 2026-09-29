from __future__ import annotations

import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


def _cut_intent(*, flag=False) -> ComponentBisimulationIntentV1:
    return ComponentBisimulationIntentV1.create(
        component_id="counter",
        operations=[{
            "operation_id": "run",
            "syncs": [{
                "id": "cut",
                "exact_unit_id": "semantic-transfer:original-cutpoint-00001010-00001020",
                "invariant": {"op": "true"},
                "captures": [{
                    "kind": "source_state", "id": "n", "mode": "machine_codec",
                    "projection": {"kind": "register", "register": "edx", "width": 32, "at": "entry"},
                    "encoding": {"op": "state_input", "name": "n"},
                    "decoding": {"op": "projected_value"},
                }],
                "derived": ([{'id': 'carry', 'projection': {'kind': 'flag', 'flag': 'cf', 'at': 'entry'},
                    'expression': {'op': 'ite', 'args': [
                        {'op': 'eq', 'args': [{'op': 'state_input', 'name': 'n'},
                                             {'op': 'const', 'width': 32, 'value': 42}]},
                        {'op': 'const', 'width': 32, 'value': 1},
                        {'op': 'const', 'width': 32, 'value': 0}]}}] if flag else []),
            }],
        }],
    )


class CutpointMemoryTests(unittest.TestCase):
    def _check(self, writes: str, *, connected_match: bool = True,
               erase_allocation_guard: bool = False, flag=False) -> dict[str, object]:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            header = _render_proof_header(
                authored=_cut_intent(flag=flag).operations[0], image_base=0x400000,
                active_target_sync_ids={"cut"},
            )
            if erase_allocation_guard:
                header = header.replace("__CPROVER_assert(spx_proof_world_allocation_cut_admitted(),",
                                        "__CPROVER_assert(1U,")
            (root / "cut.h").write_text(header)
            world = _world_source(
                max_writes=3, max_private_writes=2, max_calls=1, max_atomics=1,
                max_shadow_bytes=2, max_nul_views=1, service_bindings=(), private_ranges=(),
            )
            source = root / "cut.c"
            source.write_text('#include "cut.h"\n'
                             + f'#define SPX_CONNECTED_MATCH {int(connected_match)}U\n'
                             + world + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) {
  return spx_exact_world.call_count == spx_source_world.call_count;
}
uint32_t spx_proof_world_atomics_equal(void) {
  return spx_exact_world.atomic_count == spx_source_world.atomic_count;
}
uint32_t spx_proof_world_connected_calls_equal(void) { return SPX_CONNECTED_MATCH; }
void spx_bisimulation_relation_witness(void) { __CPROVER_cover(1); }
void main(void) {
  uint32_t fault = 0U, n = 42U;
  spx_proof_reset_worlds(8388608U, 256U);
  spx_proof_exact_output.edx = n;
  spx_proof_exact_result = (spx_step_result){SPX_BRANCH, 0x1010U, 0U};
  SPX_PROOF_BEGIN(run);
''' + writes + '''
  SPX_PROOF_SYNC(cut, 1, n);
}
''')
            return run_cbmc_properties(
                command=[cbmc, str(source), "--json-ui", "--trace", "--unwind", "4",
                         "--unwinding-assertions", "--bounds-check", "--pointer-check",
                         "--sat-solver", "cadical"],
                timeout_seconds=30,
            )

    def test_equal_captures_do_not_hide_different_public_memory_at_cut(self) -> None:
        result = self._check('''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 23U, &fault);
''')
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-world-memory:cut")

    def test_equal_effective_memory_allows_different_write_histories(self) -> None:
        result = self._check('''
  spx_proof_write_world(&spx_exact_world, 4096U, 2U, 0x1711U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 0xffU, &fault);
  spx_proof_write_world(&spx_source_world, 4097U, 1U, 0x17U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 0x11U, &fault);
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_cut_cannot_terminate_before_connected_pairing_check(self) -> None:
        result = self._check("", connected_match=False)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-world-connected-calls:cut")

    def test_boundary_checks_are_independently_required(self) -> None:
        descriptions = _required_assertion_descriptions(
            authored=_cut_intent().operations[0], proof_function="check_entry",
            active_start_sync_id=None, next_sync_ids={"cut"},
            logical_projection={"results": [], "state": []}, continuous_acyclic=False,
            typed_call_positions=(),
        )
        self.assertIn("spx-bisimulation-world-memory:cut", descriptions)
        self.assertIn("spx-bisimulation-world-connected-calls:cut", descriptions)
        self.assertIn("spx-bisimulation-allocation-cut-admission:cut", descriptions)

    def test_condition_flag_transport_is_checked_without_masking_bad_bits(self):
        for value, expected in ((1, 'satisfied'), (0, 'violated'), (3, 'violated')):
            with self.subTest(value=value):
                result = self._check(f'spx_proof_exact_output.cf = {value}U;', flag=True)
                self.assertEqual(result['status'], expected, result)
                if expected == 'violated':
                    self.assertEqual(result['detail'], 'spx-bisimulation-derived:cut:carry')
        descriptions = _required_assertion_descriptions(
            authored=_cut_intent(flag=True).operations[0], proof_function='check_entry',
            active_start_sync_id=None, next_sync_ids={'cut'},
            logical_projection={'results': [], 'state': []}, continuous_acyclic=False,
            typed_call_positions=())
        self.assertIn('spx-bisimulation-derived:cut:carry', descriptions)

    def test_flag_projection_rejects_unknown_flags_widths_and_phases(self):
        from spaghetti_extractor.components.machine_binding import MachineProjectionV1
        for change in ({'flag': 'af'}, {'flag': 'eax'}, {'width': 1}, {'at': 'before'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                MachineProjectionV1.parse({'kind': 'flag', 'flag': 'cf', 'at': 'entry', **change})

    def test_equal_live_or_retired_histories_cannot_be_erased_by_a_cut(self) -> None:
        for released in (False, True):
            body = ""
            for side in ("exact", "source"):
                world = f"&spx_{side}_world"
                body += f'''
  __CPROVER_assert(spx_proof_allocate({world}, 4096U, 4U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "allocate scratch");
  spx_proof_write_world({world}, 4096U, 1U, 17U, &fault);
'''
                if released:
                    body += f'''
  __CPROVER_assert(spx_proof_release_allocation({world}, 4096U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "release scratch");
'''
            with self.subTest(released=released):
                result = self._check(body)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], "spx-bisimulation-allocation-cut-admission:cut")
                old = self._check(body, erase_allocation_guard=True)
                self.assertEqual(old["status"], "satisfied", old.get("detail"))

    def test_null_allocation_has_no_history_to_transport(self) -> None:
        result = self._check('''
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 0U, 4U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "exact null allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 0U, 4U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "source null allocation");
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_nix_reader_requires_allocation_admission_even_without_view_captures(self) -> None:
        jq = shutil.which("jq")
        self.assertIsNotNone(jq)
        sync = _cut_intent().to_payload()["operations"][0]["syncs"][0]
        model = {"selected_unit_ids": ["predecessor"], "required_assertion_descriptions": [
            "spx-bisimulation-sync-alignment:cut",
            "spx-bisimulation-allocation-cut-admission:cut",
            "spx-bisimulation-capture-roundtrip:cut:n"]}
        payload = {"proof_plan": {"operations": [{"operation_id": "run",
            "source": {"syncs": [sync]}, "exact": {"control_edges": [{
                "source_unit_id": "predecessor", "target_unit_id": sync["exact_unit_id"]}]}}]},
            "proof": {"models": {"operation_models": [{"operation_id": "run",
                "obligation_models": [model]}]}}}
        program = (Path(__file__).parents[3] / TESTKIT["resources"][0]).read_text()
        for present in (True, False):
            if not present:
                model["required_assertion_descriptions"].remove("spx-bisimulation-allocation-cut-admission:cut")
            result = run_jq_reader([jq, "-e", program + "\nspx_cut_capture_codecs"],
                input=json.dumps(payload), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0 if present else 1, result.stderr)
