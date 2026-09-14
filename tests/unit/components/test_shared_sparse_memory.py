"""Sparse source/service writes agree with an independent small byte array."""
import shutil
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {'fixtures': ('cbmc','compiler')}


class SharedSparseMemoryTests(unittest.TestCase):
    def check_events(self, *, stale=False, preserved=(), admit_preserved=False, omit_checks=False, origin=0):
        if not all(shutil.which(tool) for tool in ('goto-cc','cbmc')):
            self.skipTest('CBMC tools unavailable')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            _write_cbmc_stdint(root/'stdint.h')
            runtime='\n'.join(sparse_mutable_memory_runtime(3, preserved_spans=preserved))
            if stale:
                runtime=runtime.replace('if (j < world->count)', 'if (0 && j < world->count)')
            if omit_checks:
                runtime=re.sub(r'^.*__CPROVER_assert.*"spx-shared-preserved-span-.*\n', '', runtime, flags=re.M)
            frame='\n'.join(f'    __CPROVER_assume((uint64_t)ORIGIN+address+extent<=UINT64_C({base}) || '
                            f'(uint64_t)ORIGIN+address>=UINT64_C({base+size}));'
                            for base,size in preserved) if not admit_preserved else ''
            (root/'model.c').write_text('#include "stdint.h"\n'+f'#define ORIGIN {origin}U\n'+runtime+'''
void exercise(void) {
  struct spx_mutable_world world = {.count=0};
  struct spx_mutable_domain domain = {&world,ORIGIN,8U,3U};
  uint8_t bytes[8];
  for (uint32_t i=0;i<8;++i) bytes[i]=__CPROVER_uninterpreted_readonly_byte(ORIGIN+i);
  for (uint32_t step=0;step<3;++step) {
    uint32_t address,extent,value,service,fault=0;
    __CPROVER_assume(address<8 && extent>0 && extent<=8-address && service<=1);
    __CPROVER_assume(service || extent<=4);
@FRAME@
    if (service) spx_mutable_event(&world,ORIGIN+address,extent,0U,1U,step);
    else spx_mutable_write(&domain,ORIGIN+address,extent,value,&fault);
    for (uint32_t i=0;i<8;++i) {
      if (i>=address && i-address<extent)
        bytes[i]=service ? __CPROVER_uninterpreted_service_byte(step,ORIGIN+i) : (uint8_t)(value >> (8U*(i-address)));
    }
    uint32_t probe;
    __CPROVER_assert(spx_mutable_byte(&world,probe) ==
      (probe>=ORIGIN && (uint64_t)probe<(uint64_t)ORIGIN+8U ? bytes[probe-ORIGIN] : __CPROVER_uninterpreted_readonly_byte(probe)), "sparse events equal reference bytes");
  }
}
'''.replace('@FRAME@',frame))
            compiler=shutil.which('goto-cc')
            result=subprocess.run([compiler,'--i386-win32','-I',str(root),str(root/'model.c'),
                '--function','exercise','-o',str(root/'model.goto')],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result=run_cbmc_properties(command=[shutil.which('cbmc'),str(root/'model.goto'),'--function','exercise',
                '--json-ui','--trace','--bounds-check','--pointer-check','--undefined-shift-check',
                '--unwind','10','--unwinding-assertions','--sat-solver','cadical'],timeout_seconds=30,output_prefix=root/'query')
            result['failure_descriptions']=[r['description'] for row in json.loads((root/'query.stdout').read_text())
                                            for r in row.get('result',[]) if r['status']=='FAILURE']
            return result

    def test_arbitrary_overlapping_events_agree_with_bytes_and_stale_reads_reject(self):
        for stale in (False,True):
            with self.subTest(stale=stale):
                result=self.check_events(stale=stale)
                self.assertEqual(result['status'],'violated' if stale else 'satisfied',result)

    def test_preserved_storage_shortcut_agrees_with_independent_bytes(self):
        result=self.check_events(preserved=[(2,2),(6,1)])
        self.assertEqual(result['status'],'satisfied',result)

    def test_preserved_storage_at_the_pe32_address_limit(self):
        result=self.check_events(origin=2**32-8,preserved=[(2**32-6,2),(2**32-1,1)])
        self.assertEqual(result['status'],'satisfied',result)

    def test_write_through_an_alias_must_discharge_the_preserved_frame(self):
        result=self.check_events(preserved=[(2,2)],admit_preserved=True)
        self.assertEqual(result['status'],'violated',result)
        self.assertIn('spx-shared-preserved-span-0',result['failure_descriptions'])

    def test_omitting_the_frame_check_makes_the_read_shortcut_unsound(self):
        result=self.check_events(preserved=[(2,2)],admit_preserved=True,omit_checks=True)
        self.assertEqual(result['status'],'violated',result)
        self.assertIn('sparse events equal reference bytes',result['detail'])

    def test_preserved_span_shapes_and_physical_limits_are_checked(self):
        for spans in [[(0,0)],[(0,True)],[(True,1)],[(2**32,1)],[(2**32-1,2)],[(2,2),(3,1)]]:
            with self.subTest(spans=spans),self.assertRaisesRegex(ValueError,'preserved physical span'):
                sparse_mutable_memory_runtime(3,preserved_spans=spans)
        sparse_mutable_memory_runtime(3,preserved_spans=[(2**32-1,1)])
