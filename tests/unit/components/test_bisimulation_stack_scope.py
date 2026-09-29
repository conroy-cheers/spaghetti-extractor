"""A real frame shift must transport visibility without rebasing the stack cache."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.bisimulation import BisimulationSyncV1, ComponentBisimulationError
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_stack_scope import scope_metadata, validate_scope_model
from spaghetti_extractor.components.bisimulation_world import _world_source
from tests.unit.components import test_bisimulation_allocation_cuts as allocations

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"),
           "resources": ("nix/jq/strong-contextual-proof.jq",
                         "profiles/pe32-kernel32-runtime-v1.json",)}


def scoped_operation(offset=4):
    authored = allocations.operation(1)
    sync = BisimulationSyncV1.parse({**authored.syncs[0].to_payload(),
        "private_stack_scope": {"register": "ebp", "offset": offset}}, "scope cut")
    return replace(authored, syncs=(sync,))


class StackScopeTests(unittest.TestCase):
    def test_region_cache_preserves_reads_and_partial_aliases_under_shifted_scope(self):
        source = _world_source(max_writes=2, max_private_writes=2, max_calls=1,
            max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
            service_bindings=[], private_ranges=(), exact_stack_accesses=((-4, 4),))
        result = allocations.AllocationCutTests().check(source + '''
int main(void) {
  uint32_t fault=0U, value=spx_nondet_u32();
  spx_proof_reset_worlds_in_scope(8388580U,8388608U,256U);
  __CPROVER_assert(spx_proof_exact_read(&spx_exact_world,8388576U,4U,&fault)==
      spx_proof_source_read(&spx_source_world,8388576U,4U,&fault), "cached input bytes agree");
  spx_proof_exact_write(&spx_exact_world,8388576U,4U,value,&fault);
  spx_proof_source_write(&spx_source_world,8388576U,4U,value,&fault);
  __CPROVER_assert(spx_proof_exact_stack_word_0000==value && spx_proof_exact_stack_valid_0000,
      "full store updates the region-relative cache");
  spx_proof_exact_write(&spx_exact_world,8388577U,1U,17U,&fault);
  spx_proof_source_write(&spx_source_world,8388577U,1U,17U,&fault);
  __CPROVER_assert(!spx_proof_exact_stack_valid_0000, "partial alias invalidates the cached word");
  __CPROVER_assert(spx_proof_exact_read(&spx_exact_world,8388576U,4U,&fault)==
      spx_proof_source_read(&spx_source_world,8388576U,4U,&fault), "byte-log fallback preserves memory");
  __CPROVER_assert(!fault, "all stack accesses remain defined");
}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_scope_is_canonical_and_identity_bearing(self):
        sync = scoped_operation().syncs[0]
        self.assertEqual(BisimulationSyncV1.parse(sync.to_payload(), "cut"), sync)
        self.assertNotEqual(scoped_operation().to_payload(), scoped_operation(5).to_payload())
        for value in (None, {}, {"register": "eflags", "offset": 4},
                      {"register": "ebp", "offset": True},
                      {"register": "ebp", "offset": 1 << 31},
                      {"register": "ebp", "offset": 4, "assume": True}):
            with self.subTest(value=value), self.assertRaises(ComponentBisimulationError):
                BisimulationSyncV1.parse({**sync.to_payload(), "private_stack_scope": value}, "cut")

    def test_shifted_constructor_retains_scope_and_rejects_wrapping(self):
        _, _, source = allocations.sources(1)
        result = allocations.AllocationCutTests().check(source + '''
int main(void) {
  spx_proof_reset_worlds_in_scope(8388580U,8388608U,256U);
  spx_proof_initialize_allocation_history_cut();
  __CPROVER_assert(spx_proof_allocation_history_admitted_cut(8388608U),
      "every resumed history fits the transported scope");
  __CPROVER_assert(spx_proof_private_scope_matches(8388608), "invocation scope preserved");
  __CPROVER_assert(!spx_proof_private_scope_matches(8388580), "ESP cannot redefine visibility");
  __CPROVER_assert(!spx_proof_private_scope_matches(INT64_C(4294967296)+8388608),
      "wrapped affine projection is rejected");
  __CPROVER_assert(!spx_proof_private_scope_matches(-1), "negative projection is rejected");
  __CPROVER_assert(spx_exact_world.private_anchor==8388580U &&
      spx_source_world.private_anchor==8388580U, "cache and footprint anchors remain region relative");
  __CPROVER_assert(spx_exact_world.private_low==8387584U &&
      spx_exact_world.private_high==8388864U, "visibility remains invocation relative");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "resumed current memory is paired");
}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def barrier(self, offset, *, erase_guard=False):
        authored = scoped_operation(offset)
        _, recipe, source = allocations.sources(1)
        header = _render_proof_header(authored=authored, image_base=0,
                                      unit_rvas={authored.syncs[0].exact_unit_id: 0x1010})
        if erase_guard:
            header = header.replace("spx_proof_private_scope_matches(((int64_t)spx_proof_exact_output.ebp + INT64_C(5)))", "1U")
        return allocations.AllocationCutTests().check(source + '\n' + header + f'''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_world_calls_equal(void) {{ return 1U; }}
uint32_t spx_proof_world_atomics_equal(void) {{ return 1U; }}
uint32_t spx_proof_world_connected_calls_equal(void) {{ return 1U; }}
void spx_bisimulation_relation_witness(void) {{}}
void main(void) {{
  uint32_t n=42U;
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_allocation live={{.base=8387474U,.size=110U,.family={recipe['family']}U,
      .generation=2U,.live=1U,.native_rule_selector={recipe['native_rule_selector']}U,
      .native_generation=42U,.birth_class_selector={recipe['birth_class_selector']}U}};
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&live)==SPX_BOUNDARY_OK &&
      spx_proof_restore_allocation_input(&spx_source_world,&live)==SPX_BOUNDARY_OK,
      "the real counterexample allocation is admitted");
  spx_proof_exact_output.esp=8388580U;
  spx_proof_exact_output.ebp=8388604U;
  spx_proof_exact_output.edx=n;
  spx_proof_exact_result=(spx_step_result){{SPX_BRANCH,0x1010U,0U}};
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(cut,1,n);
}}
''')

    def test_actual_barrier_accepts_real_edge_allocation_and_rejects_scope_change(self):
        good = self.barrier(4)
        self.assertEqual(good["status"], "satisfied", good.get("detail"))
        bad = self.barrier(5)
        self.assertEqual(bad["status"], "violated", bad.get("detail"))
        self.assertEqual(bad["detail"], "spx-bisimulation-private-stack-scope:cut")
        erased = self.barrier(5, erase_guard=True)
        self.assertEqual(erased["status"], "satisfied", erased.get("detail"))

    def test_independent_readers_bind_scope_policy_and_transport_assertion(self):
        authored = scoped_operation()
        metadata = {**allocations.history_metadata(authored), **scope_metadata(authored)}
        planned = {"source": {"syncs": [authored.syncs[0].to_payload()]},
            "operation_id": "run", "exact": {"control_edges": [{
                "source_unit_id": "predecessor", "target_unit_id": authored.syncs[0].exact_unit_id}]}}
        validate_scope_model(planned, metadata)
        for bad in ({}, {**metadata, "private_stack_scope_policy": "unchecked"}):
            with self.assertRaises(ValueError):
                validate_scope_model(planned, bad)
        checks = ["spx-bisimulation-sync-alignment:cut",
                  "spx-bisimulation-allocation-cut-admission:cut",
                  "spx-bisimulation-capture-roundtrip:cut:n",
                  "spx-bisimulation-private-stack-scope:cut"]
        model = {**metadata, "obligation_id": "entry", "selected_unit_ids": ["predecessor"],
                 "required_assertion_descriptions": checks}
        document = {"proof_plan": {"operations": [planned]}, "proof": {"models": {
            "operation_models": [{**metadata, "operation_id": "run", "obligation_models": [model]}]}}}
        program = (Path(__file__).parents[3] / TESTKIT["resources"][0]).read_text()
        for mutation in ("none", "missing-check", "missing-policy", "bad-offset", "missing-input-check"):
            value = copy.deepcopy(document)
            operation = value["proof"]["models"]["operation_models"][0]
            segment = operation["obligation_models"][0]
            if mutation == "missing-check":
                segment["required_assertion_descriptions"].remove(checks[-1])
            elif mutation == "missing-policy":
                del segment["private_stack_scope_policy"]
            elif mutation == "bad-offset":
                value["proof_plan"]["operations"][0]["source"]["syncs"][0]["private_stack_scope"]["offset"] = True
            elif mutation == "missing-input-check":
                segment["obligation_id"] = "sync:cut"
                segment["required_assertion_descriptions"].append("spx-bisimulation-allocation-history-input:cut")
            result = run_jq_reader([shutil.which("jq"), "-e", program + "\nspx_cut_capture_codecs"],
                input=json.dumps(value), text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0 if mutation == "none" else 1, (mutation, result.stderr))
