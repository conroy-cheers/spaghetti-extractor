"""Snapshot byte effects preserve arbitrary spans without enumerating their size."""
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


class MutableBulkTests(unittest.TestCase):
    def check_model(self, body, *, capacity=4, preserved_spans=(), failure=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            model = '#include "stdint.h"\n'+'\n'.join(sparse_mutable_memory_runtime(
                capacity, bulk_operations=True, preserved_spans=preserved_spans))+'\n'+body
            (root/'model.c').write_text(model)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.c', '--i386-win32', '-I', '.',
                '--function', 'check', *mutable_checker_options(20)], cwd=root, timeout_seconds=60)
        self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
        if failure:
            self.assertEqual(result['source']['comment'], failure)

    def test_arbitrary_length_snapshot_overlap_and_write_frame(self):
        self.check_model('''
void check(void){
 uint32_t source,destination,probe,store,value,fill;uint64_t extent;
 __CPROVER_assume(extent<=UINT64_C(4294967296)-source && extent<=UINT64_C(4294967296)-destination);
 __CPROVER_assume(store<=4294967292U);
 struct spx_mutable_world world={0};
 spx_mutable_event(&world,store,4U,value,0U,0U);
 uint8_t prior=spx_mutable_byte(&world,probe),copied=prior;
 uint32_t inside=probe>=destination && (uint64_t)probe-destination<extent;
 if(inside)copied=spx_mutable_byte(&world,source+(probe-destination));
 spx_mutable_copy(&world,destination,source,extent);
 __CPROVER_assert(spx_mutable_byte(&world,probe)==copied,"snapshot-copy-and-frame");
 spx_mutable_fill(&world,source,extent,fill);
 if(probe>=source && (uint64_t)probe-source<extent)copied=(uint8_t)fill;
 __CPROVER_assert(spx_mutable_byte(&world,probe)==copied,"subsequent-fill-and-frame");
}
''')

    def test_nested_history_matches_independent_array_snapshots(self):
        self.check_model('''
void check(void){
 struct spx_mutable_world world={0};uint8_t bytes[8],snapshot[8],probe;
 __CPROVER_assume(probe<8U);
 for(uint32_t i=0U;i<8U;i++)bytes[i]=__CPROVER_uninterpreted_readonly_byte(100U+i);
 for(uint32_t step=0U;step<4U;step++){
  uint32_t kind,value;uint8_t source,destination,length;
  __CPROVER_assume(kind<=3U && source<=8U && destination<=8U);
  __CPROVER_assume(length<=8U-source && length<=8U-destination);
  __CPROVER_assume(kind!=0U || (length>=1U && length<=4U));
  for(uint32_t i=0U;i<8U;i++)snapshot[i]=bytes[i];
  spx_mutable_event(&world,100U+destination,length,kind==3U?100U+source:value,kind,step);
  for(uint32_t i=0U;i<length;i++){
   if(kind==0U)bytes[destination+i]=(uint8_t)(value>>(8U*i));
   else if(kind==1U)bytes[destination+i]=__CPROVER_uninterpreted_service_byte(step,100U+destination+i);
   else if(kind==2U)bytes[destination+i]=(uint8_t)value;
   else bytes[destination+i]=snapshot[source+i];
  }
 }
 __CPROVER_assert(spx_mutable_byte(&world,100U+probe)==bytes[probe],"independent-array-snapshot");
}
''')

    def test_zero_length_and_last_address_are_defined(self):
        self.check_model('''
void check(void){
 struct spx_mutable_world world={0};uint32_t probe;
 spx_mutable_copy(&world,4294967295U,0U,0U);
 spx_mutable_fill(&world,4294967295U,0U,0U);
 __CPROVER_assert(spx_mutable_byte(&world,probe)==__CPROVER_uninterpreted_readonly_byte(probe),"zero-extent-frame");
 spx_mutable_fill(&world,4294967295U,1U,0x1234U);
 __CPROVER_assert(spx_mutable_byte(&world,4294967295U)==0x34U,"last-byte-fill");
 spx_mutable_copy(&world,0U,4294967295U,1U);
 __CPROVER_assert(spx_mutable_byte(&world,0U)==0x34U,"last-byte-copy");
}
''')

    def test_invalid_ranges_capacity_and_preserved_bytes_reject(self):
        cases = [
            ('spx_mutable_fill(&world,1U,UINT64_C(18446744073709551615),0U);', {},
             'spx-shared-memory-destination-range'),
            ('spx_mutable_copy(&world,0U,4294967295U,2U);', {}, 'spx-shared-memory-source-range'),
            ('spx_mutable_copy(&world,15U,100U,2U);', {'preserved_spans':[(16,4)]}, 'spx-shared-preserved-span-0'),
            ('spx_mutable_fill(&world,19U,2U,0U);', {'preserved_spans':[(16,4)]}, 'spx-shared-preserved-span-0'),
            ('spx_mutable_fill(&world,0U,0U,0U);spx_mutable_copy(&world,0U,0U,0U);', {'capacity':1},
             'spx-shared-memory-event-capacity'),
        ]
        for body,options,failure in cases:
            with self.subTest(failure=failure,body=body):
                self.check_model('void check(void){struct spx_mutable_world world={0};'+body+'}',failure=failure,**options)

    def test_unchecked_initialization_observer_combination_rejects(self):
        with self.assertRaisesRegex(ValueError, 'snapshot.*transport'):
            sparse_mutable_memory_runtime(4,bulk_operations=True,observed_byte=True)
        with self.assertRaisesRegex(ValueError, 'bulk mode'):
            sparse_mutable_memory_runtime(4,bulk_operations=1)
