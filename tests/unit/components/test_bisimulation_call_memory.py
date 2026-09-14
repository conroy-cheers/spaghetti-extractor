"""Call-time observations must survive subsequent changes to paired memory."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class CallMemoryExecutionTests(unittest.TestCase):
    def _check(self, *, replay: str, different: bool = False,
               typed_exact: bool = False, address: int = 36864,
               erase_check: bool = False, second_call: bool = False,
               expose: bool = False, guard_private_observation: bool = False,
               eager_private_observation: bool = False) -> dict:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        binding = {"service_id": "read_buffer", "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
                   "abi_template": "pe32-cdecl-v1", "argument_offsets": [0],
                   "events": [{"instruction_rva": 100, "event_index": 0,
                               "return_rva": 105}]}
        spec = _proof_call_specs([binding])[0]["spec_id"]
        world = _world_source(max_writes=8, max_private_writes=4, max_calls=2,
            max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
            service_bindings=[binding], private_ranges=(),
            typed_exact_recording=typed_exact, max_exposed_stack_views=int(expose))
        if erase_check:
            world = world.replace(
                "return call->memory_byte == spx_proof_source_byte(address);",
                "return UINT32_C(1);")
        if eager_private_observation:
            world = world.replace(
                "call->memory_private ? UINT8_C(0) : spx_proof_exact_byte(address)",
                "spx_proof_exact_byte(address)")
        if guard_private_observation:
            world = world.replace(
                "static uint8_t spx_proof_exact_byte(uint32_t address) {",
                '''static uint32_t observing_call_public_memory;
static uint8_t spx_proof_exact_byte(uint32_t address) {
  __CPROVER_assert(!observing_call_public_memory ||
      !spx_proof_is_private(&spx_exact_world, address),
      "call observer evaluated an inactive private byte");''')
            world = world.replace(
                "static void spx_proof_record_call_memory(spx_proof_call *call) {",
                "static void spx_proof_record_call_memory(spx_proof_call *call) {\n"
                "  observing_call_public_memory = 1U;")
            end = world.index("\n}", world.index(
                "static void spx_proof_record_call_memory(spx_proof_call *call) {"))
            world = world[:end] + "\n  observing_call_public_memory = 0U;" + world[end:]
        exact_call = (f"spx_proof_typed_service_begin(&spx_exact_world, {spec}U);\n"
                      "spx_proof_typed_service_argument(0U, 36864U);\n"
                      "spx_proof_typed_service_finish();" if typed_exact else
                      "spx_proof_exact_external_call(0, &event, &input, &output);")
        source_call = (f"spx_proof_typed_service_begin(&spx_source_world, {spec}U);\n"
                       "spx_proof_typed_service_argument(0U, 36864U);\n"
                       "spx_proof_typed_service_finish();" if replay == "typed" else
                       "spx_proof_source_external_call(0, &event, &input, &output);")
        # Exact finishes first. Replaying must compare its earlier observation,
        # not the final 99 byte. A second call must obtain a fresh witness.
        body = f"""
int main(void) {{
  uint32_t fault = 0U;
  spx_machine_state input = {{0}}, output = {{0}};
  spx_call_event event = {{.kind = SPX_CALL_EXTERNAL_IMPORT,
      .instruction_rva = 100U, .call_index = 0U, .return_rva = 105U}};
  input.esp = 8192U;
  spx_proof_reset_worlds(8192U, 4U);
  {f'spx_proof_expose_stack_view({address}U, 1U);' if expose else ''}
  spx_proof_exact_write(0, 8192U, 4U, 36864U, &fault);
  spx_proof_source_write(0, 8192U, 4U, 36864U, &fault);
  spx_proof_exact_write(0, {address}U, 1U, 7U, &fault);
  {exact_call}
  spx_proof_exact_write(0, {address}U, 1U, 99U, &fault);
  {exact_call if second_call else ''}
  spx_proof_source_write(0, {address}U, 1U, {8 if different and not second_call else 7}U, &fault);
  {source_call}
  spx_proof_source_write(0, {address}U, 1U, {8 if different and second_call else 99}U, &fault);
  {source_call if second_call else ''}
  spx_proof_source_write(0, {address}U, 1U, 99U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "final-memory-equal");
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "call-memory.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + world + body)
            return run_cbmc_properties(command=[cbmc, str(source), "--json-ui",
                "--trace", "--unwind", "3", "--unwinding-assertions",
                "--bounds-check", "--pointer-check", "--signed-overflow-check",
                "--sat-solver", "cadical"], timeout_seconds=30)

    def test_replay_observes_the_call_snapshot_not_the_final_world(self) -> None:
        for replay, typed_exact in (("machine", False), ("typed", False), ("typed", True)):
            with self.subTest(replay=replay, typed_exact=typed_exact):
                result = self._check(replay=replay, typed_exact=typed_exact)
                self.assertEqual(result["status"], "satisfied", result)

    def test_later_repair_cannot_hide_different_memory_at_the_call(self) -> None:
        for replay, typed_exact in (("machine", False), ("typed", False), ("typed", True)):
            with self.subTest(replay=replay, typed_exact=typed_exact):
                result = self._check(replay=replay, different=True, typed_exact=typed_exact)
                self.assertEqual(result["status"], "violated", result)
                self.assertIn("call-public-memory", result["detail"])
        mutant = self._check(replay="machine", different=True, erase_check=True)
        self.assertEqual(mutant["status"], "satisfied", mutant)

    def test_each_call_has_an_independent_observation(self) -> None:
        for different in (False, True):
            result = self._check(replay="typed", second_call=True, different=different)
            self.assertEqual(result["status"], "violated" if different else "satisfied", result)
            if different:
                self.assertEqual(result["detail"], "spx-bisimulation-typed-call-public-memory:1")

    def test_private_frame_bytes_remain_separate_from_public_observations(self) -> None:
        result = self._check(replay="machine", different=True, address=8188)
        self.assertEqual(result["status"], "satisfied", result)
        exposed = self._check(replay="machine", different=True, address=8188, expose=True)
        self.assertEqual(exposed["status"], "violated", exposed)
        self.assertEqual(exposed["detail"], "spx-bisimulation-call-public-memory")

    def test_inactive_private_observation_is_not_evaluated(self) -> None:
        for replay, typed_exact in (("machine", False), ("typed", False), ("typed", True)):
            with self.subTest(replay=replay, typed_exact=typed_exact):
                result = self._check(replay=replay, typed_exact=typed_exact,
                    different=True, address=8188, guard_private_observation=True)
                self.assertEqual(result["status"], "satisfied", result)
        eager = self._check(replay="machine", address=8188,
            guard_private_observation=True, eager_private_observation=True)
        self.assertEqual(eager["status"], "violated", eager)
        self.assertEqual(eager["detail"], "call observer evaluated an inactive private byte")
        exposed = self._check(replay="machine", different=True, address=8188,
            expose=True, guard_private_observation=True)
        self.assertEqual(exposed["status"], "violated", exposed)
        self.assertEqual(exposed["detail"], "spx-bisimulation-call-public-memory")
