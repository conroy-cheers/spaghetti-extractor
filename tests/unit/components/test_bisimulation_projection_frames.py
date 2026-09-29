"""Parameter-slot frame facts preserve aliases, scope and mandatory evidence."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_projection_frames import (
    configuration, description, metadata, transports_anchor, validate_model,
)
from spaghetti_extractor.components.bisimulation_source_expressions import memory_projection_readers
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .jq_reader import run as run_jq_reader
from . import test_bisimulation_view_admission as cut_fixture

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",)}


def intent(*, successor_scope=None):
    payload = cut_fixture.CutViewAdmissionTests()._intent().to_payload()
    sync = payload["operations"][0]["syncs"][0]
    sync["captures"][0]["projection"]["base"] = {"kind": "stack", "at": "entry", "offset": 8, "width": 32}
    sync["private_stack_scope"] = {"register": "esp", "offset": 0}
    sync["preserved_parameter_slots"] = ["buffer"]
    if successor_scope is not None:
        successor = copy.deepcopy(sync)
        successor.update(id="finish", exact_unit_id="finish-cut", private_stack_scope=successor_scope)
        del successor["preserved_parameter_slots"]
        payload["operations"][0]["syncs"].append(successor)
    return ComponentBisimulationIntentV1.create(component_id="views", operations=payload["operations"])


def world_options():
    return dict(max_writes=2, max_private_writes=2, max_calls=1, max_atomics=1,
                max_shadow_bytes=1, max_nul_views=1, max_exposed_stack_views=1,
                service_bindings=(), private_ranges=())


class ProjectionFrameTests(unittest.TestCase):
    def test_authored_frames_are_canonical_and_reject_unsupported_coordinates(self):
        original = intent()
        self.assertEqual(ComponentBisimulationIntentV1.parse(original.to_payload()), original)
        for change in ("empty", "duplicate", "missing", "scope", "unaligned", "register"):
            payload = original.to_payload()
            sync = payload["operations"][0]["syncs"][0]
            if change == "empty": sync["preserved_parameter_slots"] = []
            elif change == "duplicate": sync["preserved_parameter_slots"] *= 2
            elif change == "missing": sync["preserved_parameter_slots"] = ["other"]
            elif change == "scope": sync["private_stack_scope"]["register"] = "ebp"
            elif change == "unaligned": sync["captures"][0]["projection"]["base"]["offset"] = 9
            else: sync["captures"][0]["projection"]["base"] = {"kind": "register", "register": "eax", "width": 32, "at": "entry"}
            with self.subTest(change=change), self.assertRaises(ValueError):
                ComponentBisimulationIntentV1.create(component_id="views", operations=payload["operations"])

    def test_both_readers_require_the_bound_frame_and_write_obligation(self):
        operation = intent().operations[0]
        planned = {"source": {"syncs": [operation.syncs[0].to_payload()]}}
        model = {**metadata(operation), "obligation_id": "sync:scan",
                 "required_assertion_descriptions": [description(configuration(operation.syncs[0]))]}
        reader = (Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]).read_text()
        for mutation in (None, "policy", "missing-policy", "guard", "capture"):
            changed, plan = copy.deepcopy(model), copy.deepcopy(planned)
            if mutation == "policy": changed["parameter_slot_frame_policy"] = "declared"
            elif mutation == "missing-policy": del changed["parameter_slot_frame_policy"]
            elif mutation == "guard": changed["required_assertion_descriptions"] = []
            elif mutation == "capture": plan["source"]["syncs"][0]["preserved_parameter_slots"] = ["other"]
            with self.subTest(mutation=mutation):
                if mutation is None:
                    validate_model(plan, changed)
                else:
                    with self.assertRaises(ValueError): validate_model(plan, changed)
                result = run_jq_reader([shutil.which("jq"), "-e", reader +
                    "\n.planned as $planned | .model | spx_parameter_slot_frame_model($planned)"],
                    input=json.dumps({"planned": plan, "model": changed}), capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mutation is None, result.stderr)

    def test_unimplemented_effect_paths_cannot_select_preserved_reads(self):
        frame = configuration(intent().operations[0].syncs[0])
        for key, value in (("maximum_input_allocations", 1), ("memory_fact_capacity", 1),
                           ("reference_allocation_requirements", []), ("summary_ranges", True),
                           ("service_bindings", ({"provider_kind": "external"},))):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "parameter slot frames"):
                _world_source(**{**world_options(), key: value}, projection_frame=frame)

    def check_frame(self, body, *, failure=None, successor=False, successor_offset=0):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        operation = intent(successor_scope={"register": "esp", "offset": successor_offset}
                           if successor else None).operations[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "proof.h").write_text(_render_proof_header(authored=operation, image_base=4194304,
                unit_rvas={"cut": 4096, "finish-cut": 4100}, active_start_sync_id="scan",
                active_target_sync_ids={"finish" if successor else "scan"}))
            source = root / "frame.c"
            source.write_text('#include "proof.h"\n#ifndef COVER\n#define __CPROVER_cover(x) ((void)0)\n#endif\n' +
                _world_source(**world_options(), projection_frame=configuration(operation.syncs[0])) + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
void spx_bisimulation_relation_witness(void) {}
uint32_t spx_proof_view_admitted(uint32_t a, uint32_t e, uint32_t s) {return a == 9216U && e == 4U;}
uint32_t spx_proof_world_calls_equal(void) {return 1;}
uint32_t spx_proof_world_atomics_equal(void) {return 1;}
uint32_t spx_proof_world_connected_calls_equal(void) {return 1;}
typedef struct view {
  struct { uint64_t object, domain, generation, offset, permissions, extent; } base;
  uint64_t extent; uint32_t element_width;
  void *context, *access_context;
  uint32_t (*read_u8)(void), (*write_u8)(void), (*read)(void), (*write)(void);
} spx_view_v1;
''' + "\n".join(memory_projection_readers()) + cut_fixture._FIXTURE_REFERENCE_SOURCE + '''
void run(spx_view_v1 *buffer) {
  uint32_t fault = 0U;
  SPX_PROOF_BEGIN(run);
  for (;;) {
    SPX_PROOF_SYNC(scan, 1, buffer);
    __CPROVER_cover(1);
''' + body + '''
  }
}
void check(void) {
  spx_proof_reset_worlds(5120U, 4096U);
  spx_proof_expose_stack_view(5128U, 4U);
  __CPROVER_assume(spx_proof_exact_input_read(5128U, 4U) == 9216U);
  __CPROVER_assume(spx_proof_exact_input_read(5124U, 4U) == 8192U);
  spx_proof_start = 1U;
  spx_proof_exact_input.esp = spx_proof_exact_output.esp = 5120U;
  spx_proof_exact_output.esp -= SUCCESSOR_OFFSET;
  spx_proof_exact_result = (spx_step_result){SPX_JUMP, TARGET_RVA, 0U};
  spx_machine_reference_v1 origin = {1U, 9216U, 1U, 0U, 4U, 3U};
  spx_runtime runtime = {.context=&origin, .realize_reference=fixture_reference};
  spx_component_view_context context = {&runtime, 9216U, 4U, 3U};
  spx_view_v1 view = {.base={9216U, 1U, 1U, 0U, 3U, 4U}, .extent=4U,
                     .element_width=1U, .context=&context, .access_context=&context};
  run(&view);
}
'''.replace("TARGET_RVA", "4100U" if successor else "4096U").replace(
                    "SUCCESSOR_OFFSET", f"{successor_offset}U"))
            command = [cbmc, str(source), "--function", "check", "--json-ui", "--unwind", "2"]
            result = run_cbmc_properties(command=[*command, "--unwinding-assertions", "--bounds-check",
                "--pointer-check", "--signed-overflow-check", "--stop-on-fail"], timeout_seconds=30)
            self.assertEqual(result["status"], "violated" if failure else "satisfied", result)
            if failure:
                self.assertEqual(result["detail"], failure, result)
            else:
                cover = run_cbmc_cover(command=[*command, "-DCOVER", "--cover", "cover"],
                    expected_functions=["run"], timeout_seconds=30)
                self.assertEqual(cover["status"], "satisfied", cover)

    def test_disjoint_writes_keep_the_original_argument_bits(self):
        self.check_frame("spx_proof_exact_write(0, 5120U, 4U, spx_nondet_u32(), &fault);")

    def test_frame_transports_to_a_distinct_successor_without_a_new_frame(self):
        operation = intent(successor_scope={"register": "esp", "offset": 0}).operations[0]
        header = _render_proof_header(authored=operation, image_base=4194304,
            unit_rvas={"cut": 4096, "finish-cut": 4100}, active_start_sync_id="scan",
            active_target_sync_ids={"finish"})
        self.assertIn("spx_proof_parameter_slot_output_read(",
                      header.split("#define SPX_PROOF_SYNC_finish(", 1)[1])
        self.check_frame("spx_proof_exact_write(0, 5120U, 4U, spx_nondet_u32(), &fault);\n"
                         "SPX_PROOF_SYNC(finish, 1, buffer);", successor=True)
        self.check_frame("spx_proof_exact_write(0, 5128U, 4U, 9216U, &fault);\n"
                         "SPX_PROOF_SYNC(finish, 1, buffer);", successor=True,
                         failure="spx-bisimulation-preserved-parameter-slot-writes:scan")

    def test_changed_successor_scope_keeps_ordinary_projections(self):
        for scope in ({"register": "esp", "offset": 4}, {"register": "ebp", "offset": 0}):
            with self.subTest(scope=scope):
                operation = intent(successor_scope=scope).operations[0]
                start, target = operation.syncs
                self.assertFalse(transports_anchor(start, target))
                header = _render_proof_header(authored=operation, image_base=4194304,
                    unit_rvas={"cut": 4096, "finish-cut": 4100}, active_start_sync_id="scan",
                    active_target_sync_ids={"finish"})
                successor_code = header.split("#define SPX_PROOF_SYNC_finish(", 1)[1]
                self.assertNotIn("spx_proof_parameter_slot_output_read(", successor_code)
                self.assertIn("spx_proof_exact_output_read(", successor_code)
        # Scope still matches after ESP falls by four, but the target slot now
        # contains a different pointer. Reusing the old slot would hide this.
        self.check_frame("SPX_PROOF_SYNC(finish, 1, buffer);", successor=True, successor_offset=4,
                         failure="spx-bisimulation-resumed-view-admission:finish:buffer")

    def test_partial_aliases_and_even_same_value_stores_violate_the_frame(self):
        for address, width, value in ((5127, 2, 0), (5131, 2, 0), (5128, 4, 9216)):
            with self.subTest(address=address):
                self.check_frame(f"spx_proof_exact_write(0, {address}U, {width}U, {value}U, &fault);",
                    failure="spx-bisimulation-preserved-parameter-slot-writes:scan")

    def test_scope_transport_is_checked_before_reusing_input_words(self):
        self.check_frame("spx_proof_exact_output.esp += 4U;",
            failure="spx-bisimulation-private-stack-scope:scan")

    def test_source_alias_writes_remain_observable(self):
        self.check_frame("spx_proof_source_write(0, 5128U, 4U, 0U, &fault);",
            failure="spx-bisimulation-world-memory:scan")
