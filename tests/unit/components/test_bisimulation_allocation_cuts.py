"""Hand-defined allocation histories use matched outgoing and incoming domains."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import BisimulationSyncV1, BisimulationOperationV1, ComponentBisimulationError
from spaghetti_extractor.components.bisimulation_allocation_cuts import (
    AllocationHistoryV1, allocation_cut_sources, history_metadata, history_recipes, validate_history_model,
)
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_reference_authority import (
    checked_reference_authority, reference_authority_unwind_arguments,
)
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_allocation_calls import inputs
from tests.unit.components.test_bisimulation_cutpoints import _cut_intent

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",
                         "profiles/pe32-kernel32-runtime-v1.json",)}


def operation(maximum=2):
    authored = _cut_intent().operations[0]
    payload = authored.syncs[0].to_payload()
    payload["allocation_history"] = {"maximum_instances": maximum, "classes": ["text"]}
    from dataclasses import replace
    return replace(authored, syncs=(BisimulationSyncV1.parse(payload, "fixture cut"),))


def sources(maximum=2, *, consumer_allocates=True, memory_fact_capacity=0):
    authority, inventory, bindings = inputs()
    if not consumer_allocates:
        bindings = []
    authored = operation(maximum)
    specs = _proof_call_specs(bindings, allow_lifetime_effects=True)
    recipes = history_recipes(authored.syncs[0].allocation_history, specs=specs,
        authority=checked_reference_authority(authority), inventory=inventory)
    world = _world_source(max_writes=2, max_private_writes=1, max_calls=1,
        maximum_input_allocations=maximum, max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
        memory_fact_capacity=memory_fact_capacity,
        service_bindings=bindings, private_ranges=(), reference_authority=authority,
        reference_runtime_inventory=inventory, image_size=0x20000)
    cuts = allocation_cut_sources(authored, specs=specs,
        authority=checked_reference_authority(authority), inventory=inventory, requirements=None,
        image_base=4194304, image_size=0x20000)
    return authored, recipes[0], world + '\nconst uint32_t spx_proof_private_high_offset=256U;\n' + cuts


class AllocationCutTests(unittest.TestCase):
    def test_operation_entry_history_is_separate_from_cuts_and_capacity_is_joint(self):
        payload = operation(2).to_payload()
        payload["entry_allocation_history"] = {"maximum_instances": 3, "classes": ["text"]}
        authored = BisimulationOperationV1.parse(payload, "entry history")
        self.assertEqual(authored.to_payload(), payload)
        self.assertEqual(history_metadata(authored)["maximum_input_allocations"], 3)
        planned = {"source": {"syncs": payload["syncs"],
                              "entry_allocation_history": payload["entry_allocation_history"]}}
        validate_history_model(planned, history_metadata(authored))
        for bad in (None, {}, {"maximum_instances": False, "classes": ["text"]}):
            with self.subTest(bad=bad), self.assertRaises(ComponentBisimulationError):
                BisimulationOperationV1.parse({**payload, "entry_allocation_history": bad}, "entry history")

    def check(self, source, *, unwind=3, allocation_capacity=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            path = root / "cut.c"
            path.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + source)
            return run_cbmc_properties(command=[shutil.which("cbmc"), str(path), "--json-ui",
                "--trace", "--unwind", str(unwind), "--unwinding-assertions", "--bounds-check",
                "--pointer-check", "--signed-overflow-check", "--undefined-shift-check",
                "--sat-solver", "cadical",
                *(reference_authority_unwind_arguments(inputs()[0],
                    allocation_capacity=allocation_capacity) if allocation_capacity is not None else [])],
                timeout_seconds=40)

    def test_canonical_history_is_explicit_bounded_and_identity_bearing(self):
        sync = operation().syncs[0]
        self.assertEqual(BisimulationSyncV1.parse(sync.to_payload(), "cut"), sync)
        self.assertNotEqual(operation(1).to_payload(), operation(2).to_payload())
        for value in (None, {}, {"maximum_instances": True, "classes": ["text"]},
                      {"maximum_instances": 0, "classes": ["text"]},
                      {"maximum_instances": 1, "classes": []},
                      {"maximum_instances": 1, "classes": ["text", "text"]},
                      {"maximum_instances": 1, "classes": ["z", "a"]}):
            with self.subTest(value=value), self.assertRaises(ComponentBisimulationError):
                BisimulationSyncV1.parse({**sync.to_payload(), "allocation_history": value}, "cut")
        with self.assertRaisesRegex(ValueError, "checked allocating service"):
            history_recipes(AllocationHistoryV1(1, ("unknown",)), specs=[], authority=None)

    def test_fresh_history_constructor_implies_the_same_cut_domain(self):
        _, _, source = sources()
        result = self.check(source + '''
int main(void) {
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_initialize_allocation_history_cut();
  __CPROVER_assert(spx_proof_allocation_history_admitted_cut(8388608U),
      "constructed history meets the outgoing cut domain");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "arbitrary input history and current memory agree");
  __CPROVER_assert(spx_source_world.input_allocation_count==spx_source_world.allocation_count,
      "all incoming generations are retained");
}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_history_contract_does_not_depend_on_consumer_calls_or_service_names(self):
        authority, inventory, bindings = inputs()
        checked = checked_reference_authority(authority)
        history = operation().syncs[0].allocation_history
        expected = history_recipes(history, specs=[], authority=checked, inventory=inventory)
        original = _proof_call_specs(bindings, allow_lifetime_effects=True)
        renamed = copy.deepcopy(bindings)
        renamed[0]["service_id"] = "other_component_allocator_name"
        changed = _proof_call_specs(renamed, allow_lifetime_effects=True)
        self.assertNotEqual(original[0]["spec_id"], changed[0]["spec_id"])
        for specs in (original, changed):
            self.assertEqual(history_recipes(history, specs=specs, authority=checked,
                                             inventory=inventory), expected)
        self.assertEqual(sources(consumer_allocates=False)[1], expected[0])

    def test_nonallocating_consumer_imports_current_bytes_and_distinct_instances(self):
        _, _, source = sources(consumer_allocates=False)
        self.assertNotIn("spx_proof_apply_lifetime_call", source)
        source += '''
int main(void) {
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_initialize_allocation_history_cut();
  __CPROVER_assume(spx_exact_world.allocation_count==2U);
  __CPROVER_assume(spx_exact_world.allocations[0].live && spx_exact_world.allocations[1].live);
  __CPROVER_assume(spx_exact_world.allocations[0].size>1U && spx_exact_world.allocations[1].size>0U);
  uint32_t first=spx_exact_world.allocations[0].base, second=spx_exact_world.allocations[1].base;
  __CPROVER_assume(spx_exact_world.allocations[0].zero_initialized==1U);
  __CPROVER_assume(spx_proof_initial_byte(first)==71U);
  spx_runtime runtime=spx_proof_runtime(&spx_exact_world);
  runtime.image_base=4194304U;
  spx_machine_reference_v1 a={0},alias={0},b={0};
  __CPROVER_assert(runtime.resolve_reference(runtime.context,first,1U,3U,"text",0U,0U,&a)==SPX_BOUNDARY_OK &&
      runtime.resolve_reference(runtime.context,first+1U,1U,3U,"text",0U,0U,&alias)==SPX_BOUNDARY_OK &&
      runtime.resolve_reference(runtime.context,second,1U,3U,"text",0U,0U,&b)==SPX_BOUNDARY_OK,
      "incoming checked class needs no allocator body");
  __CPROVER_assert(a.generation==alias.generation && alias.offset==a.offset+1U &&
      a.generation!=b.generation,"aliases share an instance and separate allocations do not");
  uint32_t realized;
  __CPROVER_assert(runtime.realize_reference(runtime.context,&b,3U,0U,0U,&realized)==SPX_BOUNDARY_OK &&
      realized==second,"second instance realizes through the native range loop");
  __CPROVER_assert(spx_proof_exact_byte(first)==71U,"imported current bytes are not birth zeros");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"incoming current memory corresponds");
}
'''
        result = self.check(source, allocation_capacity=3)  # One call slot plus two imported instances.
        self.assertEqual(result["status"], "satisfied", (result.get("detail"), result.get("source")))
        stale = self.check(source, allocation_capacity=1)
        self.assertEqual(stale["status"], "violated", stale.get("detail"))
        self.assertIn("unwind", stale.get("detail", ""))

    def test_history_preserves_retirement_and_rejects_changed_frames_and_classes(self):
        _, recipe, source = sources()
        birth = recipe["birth_class_selector"]
        result = self.check(source + f'''
int main(void) {{
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_allocation old={{.base=4096U,.size=16U,.family={recipe['family']}U,
      .generation=2U,.live=0U,.native_rule_selector={recipe['native_rule_selector']}U,
      .native_generation=42U,.birth_class_selector={birth}U}};
  spx_proof_allocation current=old;
  current.generation=3U; current.native_generation=43U; current.live=1U;
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&old)==SPX_BOUNDARY_OK &&
      spx_proof_restore_allocation_input(&spx_source_world,&old)==SPX_BOUNDARY_OK,
      "retired prefix is reconstructible");
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&current)==SPX_BOUNDARY_OK &&
      spx_proof_restore_allocation_input(&spx_source_world,&current)==SPX_BOUNDARY_OK,
      "reused allocation is reconstructible");
  __CPROVER_assert(spx_proof_allocation_history_admitted_cut(8388608U), "complete history admitted");
  __CPROVER_assert(!spx_proof_allocation_history_admitted_cut(4096U),
      "successor private stack cannot engulf the allocation");
  spx_source_world.allocations[1].birth_class_selector ^= 1U;
  __CPROVER_assert(!spx_proof_allocation_history_admitted_cut(8388608U), "changed birth contract rejected");
  spx_source_world.allocations[1].birth_class_selector ^= 1U;
  spx_source_world.allocations[1].native_generation=42U;
  __CPROVER_assert(!spx_proof_allocation_history_admitted_cut(8388608U), "duplicate native generation rejected");
}}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_actual_proof_barrier_consumes_the_declared_history(self):
        authored, _, source = sources(1)
        header = _render_proof_header(authored=authored, image_base=0,
                                      unit_rvas={authored.syncs[0].exact_unit_id: 0x1010})
        result = self.check(source + '\n' + header + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) { return 1U; }
uint32_t spx_proof_world_atomics_equal(void) { return 1U; }
uint32_t spx_proof_world_connected_calls_equal(void) { return 1U; }
void spx_bisimulation_relation_witness(void) {}
void main(void) {
  uint32_t n=42U;
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_initialize_allocation_history_cut();
  spx_proof_exact_output.esp=8388608U;
  spx_proof_exact_output.edx=n;
  spx_proof_exact_result=(spx_step_result){SPX_BRANCH,0x1010U,0U};
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(cut,1,n);
}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_both_reader_rules_bind_history_policy_and_resumption_check(self):
        authored = operation()
        planned = {"source": {"syncs": [authored.syncs[0].to_payload()]},
                   "exact": {"control_edges": []}, "operation_id": "run"}
        metadata = history_metadata(authored)
        validate_history_model(planned, metadata)
        for mutation in ({}, {**metadata, "maximum_input_allocations": 1},
                         {**metadata, "allocation_history_policy": "unchecked"}):
            with self.assertRaises(ValueError):
                validate_history_model(planned, mutation)
        module = Path(__file__).resolve().parents[3] / "nix/jq/strong-contextual-proof.jq"
        model = {**metadata, "obligation_id": "sync:cut", "selected_unit_ids": [],
                 "required_assertion_descriptions": ["spx-bisimulation-allocation-history-input:cut"]}
        document = {"proof_plan": {"operations": [planned]}, "proof": {"models": {
            "operation_models": [{**metadata, "operation_id": "run", "obligation_models": [model]}]}}}
        for bad in (False, True):
            value = copy.deepcopy(document)
            if bad:
                value["proof"]["models"]["operation_models"][0]["obligation_models"][0]["required_assertion_descriptions"] = []
            result = subprocess.run([shutil.which("jq"), "-e", module.read_text()+"\nspx_cut_capture_codecs"],
                input=json.dumps(value), text=True, capture_output=True)
            self.assertEqual(result.returncode, 1 if bad else 0, result.stderr)
