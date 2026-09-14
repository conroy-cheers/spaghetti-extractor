"""Incoming allocation state retains current bytes instead of replaying birth.

These constructor checks do not establish a predecessor relation or admit cuts.
The real cleanup consumes this primitive in the retained boundary experiment.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_allocation_lifetime import allocation_world

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class AllocationInputTests(unittest.TestCase):
    def check(self, body, *, replay_initialization=False):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        source = allocation_world(body)
        if replay_initialization:
            line = "if (index < world->input_allocation_count) return spx_proof_initial_byte(address);"
            self.assertIn(line, source)
            source = source.replace(line, "/* Incorrectly replay allocation initialization. */")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            path = root / "input.c"
            path.write_text(source)
            return run_cbmc_properties(command=[cbmc, str(path), "--json-ui", "--trace",
                "--unwind", "2", "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--signed-overflow-check", "--undefined-shift-check", "--sat-solver", "cadical"],
                timeout_seconds=30)

    def test_current_input_bytes_aliases_and_fresh_reuse_have_distinct_semantics(self):
        body = '''
int main(void) {
  start(); uint32_t fault=0U, address=0U, offset=spx_nondet_u32();
  __CPROVER_assume(offset < 16U);
  spx_proof_allocation incoming = {.base=4096U,.size=16U,.family=1U,.owner=77U,
      .generation=2U,.live=1U,.zero_initialized=1U,.write_floor=99U,.shadow_floor=99U,
      .native_rule_selector=1U,.native_generation=42U,.birth_class_selector=71U};
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&incoming)
      == SPX_BOUNDARY_OK, "exact current allocation input");
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&incoming)
      == SPX_BOUNDARY_OK, "source current allocation input");
  __CPROVER_assert(spx_proof_allocation_instance_equal(&incoming,&spx_source_world.allocations[0]),
      "input preserves complete semantic allocation metadata");
  __CPROVER_assert(spx_proof_source_read(0,4096U+offset,1U,&fault)
      == spx_proof_initial_byte(4096U+offset) && fault==0U,
      "input contains current bytes rather than birth zeros");
  spx_machine_reference_v1 whole=borrow(&spx_source_world,4096U,16U);
  spx_machine_reference_v1 alias=borrow(&spx_source_world,4096U+offset,1U);
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world,&alias,3U,0U,0U,&address)
      == SPX_BOUNDARY_OK && address==4096U+offset, "current input alias");
  spx_proof_source_write(0,address,1U,23U,&fault);
  spx_proof_exact_write(0,address,1U,23U,&fault);
  __CPROVER_assert(spx_proof_source_read(0,4096U+offset,1U,&fault)==23U && fault==0U,
      "new alias write overrides arbitrary input memory");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "paired current memory");
  __CPROVER_assert(!spx_proof_world_allocation_cut_admitted(),
      "constructor alone does not admit another cut");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world,4096U,1U,77U,1U)
      == SPX_BOUNDARY_OK, "release imported allocation");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world,&whole,1U,0U,0U,&address)
      == SPX_BOUNDARY_EXPIRED, "imported reference expires");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world,4096U,16U,1U,77U,1U)
      == SPX_BOUNDARY_OK, "fresh reuse after input");
  __CPROVER_assert(spx_proof_source_read(0,4096U+offset,1U,&fault)==0U && fault==0U,
      "fresh birth uses initialization and erases earlier input writes");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world,&alias,1U,0U,0U,&address)
      == SPX_BOUNDARY_EXPIRED, "reuse cannot revive input alias");
}
'''
        result = self.check(body)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
        mutant = self.check(body, replay_initialization=True)
        self.assertEqual(mutant["status"], "violated", mutant.get("detail"))
        self.assertEqual(mutant["detail"], "input contains current bytes rather than birth zeros")

    def test_retired_input_and_reused_address_keep_separate_generations(self):
        result = self.check('''
int main(void) {
  start(); uint32_t fault=0U;
  spx_proof_allocation old={.base=4096U,.size=16U,.family=1U,.generation=2U,
      .native_rule_selector=1U,.native_generation=42U,.birth_class_selector=71U};
  spx_proof_allocation current=old;
  current.size=8U; current.generation=3U; current.native_generation=43U; current.live=1U;
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&old)
      == SPX_BOUNDARY_OK, "restore retired generation");
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&current)
      == SPX_BOUNDARY_OK, "restore current reused address");
  __CPROVER_assert(!spx_proof_allocation_reference_live(&spx_source_world,4096U,8U,2U,0U),
      "retired input cannot become the current generation");
  __CPROVER_assert(spx_proof_allocation_reference_live(&spx_source_world,4096U,8U,3U,0U),
      "current input stays live");
  (void)spx_proof_source_read(0,4104U,1U,&fault);
  __CPROVER_assert(fault!=0U, "retired tail remains inaccessible");
  current.generation=4U; current.base=8192U;
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&current)
      == SPX_BOUNDARY_TYPE_MISMATCH && spx_source_world.allocation_count==2U,
      "duplicate native generation cannot be imported");
}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_malformed_or_late_inputs_cannot_partially_replace_state(self):
        template = '''
int main(void) {
  start(); uint32_t fault=0U;
  spx_proof_allocation input={.base=4096U,.size=16U,.family=1U,.generation=2U,.live=1U};
  MUTATION
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&input)
      != SPX_BOUNDARY_OK, "invalid input rejected");
  __CPROVER_assert(spx_source_world.allocation_count==COUNT &&
      spx_source_world.input_allocation_count==0U, "rejection preserves history");
}
'''
        cases = ["input.base=0U;", "input.live=2U;", "input.zero_initialized=2U;",
            "input.generation=1U;", "input.native_rule_selector=1U;",
            "input.native_generation=42U;", "input.base=UINT32_MAX;",
            "input.base=12288U;", "input.base=8388608U;",
            "spx_proof_source_write(0,8192U,1U,1U,&fault);",
            "spx_proof_initialize_source_byte(8192U,1U);",
            "spx_source_world.call_count=1U;", "spx_source_world.atomic_count=1U;"]
        for mutation in cases:
            with self.subTest(mutation=mutation):
                result = self.check(template.replace("MUTATION",mutation).replace("COUNT","0U"))
                self.assertEqual(result["status"], "satisfied", result.get("detail"))
        result = self.check(template.replace("MUTATION", '''
  (void)spx_proof_allocate(&spx_source_world,8192U,4U,1U,0U,0U);
  input.generation=3U;''').replace("COUNT","1U"))
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_native_input_retains_the_allocator_one_past_requirement(self):
        result = self.check('''
int main(void) {
  start();
  spx_proof_allocation input={.base=UINT32_MAX,.size=1U,.family=1U,.generation=2U,.live=1U,
      .native_rule_selector=1U,.native_generation=42U};
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&input)
      == SPX_BOUNDARY_MEMORY_FAULT && spx_source_world.allocation_count==0U,
      "native input cannot lose its representable one-past premise");
  input.native_rule_selector=0U; input.native_generation=0U;
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_source_world,&input)
      == SPX_BOUNDARY_OK, "flat input retains its wider byte-span domain");
}
''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
