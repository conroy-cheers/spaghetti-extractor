"""The incremental byte observer preserves the complete sparse-memory fold."""
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


class MutableObservationTests(unittest.TestCase):
    def test_empty_memory_and_arbitrary_append_preserve_the_observer_invariant(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            model = '#include "stdint.h"\n'+'\n'.join(sparse_mutable_memory_runtime(4, observed_byte=True))
            model += '''
static void valid(const struct spx_mutable_event *e){
 __CPROVER_assume(e->service<=1U && (uint64_t)e->address+e->extent<=UINT64_C(4294967296));
 __CPROVER_assume(e->service || (e->extent>=1U && e->extent<=4U));
}
static uint8_t initialized(const struct spx_mutable_world *world,uint32_t address){
 uint8_t result=0U;
 for(uint32_t i=0U;i<world->count;i++){
  const struct spx_mutable_event *e=&world->events[i];
  if(!e->service && address>=e->address && (uint64_t)address<(uint64_t)e->address+e->extent)result=1U;
 }
 return result;
}
void check(void){
 uint32_t probe;
 struct spx_mutable_world empty={.observed_address=probe,
   .observed_byte=__CPROVER_uninterpreted_readonly_byte(probe)};
 __CPROVER_assert(empty.observed_byte==spx_mutable_byte(&empty,probe),"observer-base");
 __CPROVER_assert(empty.observed_initialized==initialized(&empty,probe),"initialization-base");
 struct spx_mutable_world world;struct spx_mutable_event next;
 __CPROVER_assume(world.count<4U);world.observed_address=probe;
 for(uint32_t i=0U;i<world.count;i++)valid(&world.events[i]);
 valid(&next);
 __CPROVER_assume(world.observed_byte==spx_mutable_byte(&world,probe));
 __CPROVER_assume(world.observed_initialized==initialized(&world,probe));
 spx_mutable_event(&world,next.address,next.extent,next.value,next.service,next.position);
 __CPROVER_assert(world.observed_byte==spx_mutable_byte(&world,probe),"observer-append");
 __CPROVER_assert(world.observed_initialized==initialized(&world,probe),"initialization-append");
 __CPROVER_assert(world.observed_address==probe,"observer-address-frame");
}
'''
            (root/'model.c').write_text(model)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.c', '--i386-win32', '-I', '.',
                '--function', 'check', *mutable_checker_options(8)], cwd=root, timeout_seconds=60)
            self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_observation_requires_an_explicit_boolean(self):
        with self.assertRaisesRegex(ValueError, 'observation mode'):
            sparse_mutable_memory_runtime(8, observed_byte=1)
