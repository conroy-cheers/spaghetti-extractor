"""Actual native-access semantics for editable boundary definitions."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_caller_memory import (
    access, checked_native_memory, constant, entry_offset, native_memory_initialization, native_memory_runtime, private_bytes,
)
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint


TESTKIT = {'fixtures': ('compiler','cbmc')}


class CallerMemoryTests(unittest.TestCase):
    def check_c(self, rows, body, *, failures=(), private_frame=(0,2**32), private_byte_capacity=0, unwind=5):
        rows=checked_native_memory(rows)
        source='\n'.join(['#include "stdint.h"',*sparse_mutable_memory_runtime(3),
                         *native_memory_runtime(len(rows),private_byte_capacity=private_byte_capacity)])
        source+='''
void check(void){
 struct { uint32_t eax,ebx,ecx,edx,esi,edi,esp,ebp,fs_base; } initial;
 struct spx_mutable_world world={0};struct spx_caller_memory memory={0};
 uint32_t fault=0U,value,probe;
 __CPROVER_assume(initial.esp>=16U && initial.esp<=1000U);
'''+native_memory_initialization(rows,instance='memory',world='&world',
        private_low=f'UINT64_C({private_frame[0]})',private_high=f'UINT64_C({private_frame[1]})')+body+'\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);_write_cbmc_stdint(root/'stdint.h');(root/'pair.c').write_text(source)
            compiler,checker=shutil.which('goto-cc'),shutil.which('cbmc')
            self.assertIsNotNone(compiler);self.assertIsNotNone(checker)
            compiled=subprocess.run([compiler,'--i386-win32','-nostdinc','-I','.',
                'pair.c','--function','check','-o','model.goto'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            result=subprocess.run([checker,'model.goto','--function','check','--json-ui','--unwind',str(unwind),
                '--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check',
                '--undefined-shift-check'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,10 if failures else 0,result.stdout[-3000:]+result.stderr)
            properties=[r for b in json.loads(result.stdout) for r in b.get('result',[])]
            self.assertTrue(properties)
            self.assertEqual({r['description'] for r in properties if r['status']=='FAILURE'},set(failures))
            self.assertTrue(all(r['status'] in {'SUCCESS','FAILURE'} for r in properties))

    def test_public_aliases_see_current_bytes_and_service_post_memory(self):
        rows=[access('write-word',constant(100),write=True),access('read-byte',constant(101),read=True,width=1)]
        self.check_c(rows,'''
 spx_caller_write(&memory,100U,4U,value,&fault);
 __CPROVER_assert(!fault && spx_caller_read(&memory,101U,1U,&fault)==((value>>8U)&255U),"overlapping-public-alias");
 spx_mutable_event(&world,0U,UINT64_C(4294967296),0U,1U,0U);
 __CPROVER_assert(spx_caller_read(&memory,101U,1U,&fault)==__CPROVER_uninterpreted_service_byte(0U,101U),"read-current-post-memory");
''')

    def test_private_words_transport_values_without_public_effects(self):
        rows=[access('private',entry_offset('esp',-4),read=True,write=True,storage='private')]
        self.check_c(rows,'''
 spx_caller_public_span(&memory,initial.esp,4U);
 uint8_t before=spx_mutable_byte(&world,probe);
 spx_caller_write(&memory,initial.esp-4U,4U,value,&fault);
 __CPROVER_assert(!fault && memory.private_writes==1U && world.count==0U,"private-effect-accounting");
 __CPROVER_assert(spx_caller_private_value(&memory,initial.esp-4U,4U)==value,"private-continuation-value");
 __CPROVER_assert(spx_caller_read(&memory,initial.esp-4U,4U,&fault)==value,"private-current-read");
 __CPROVER_assert(before==spx_mutable_byte(&world,probe),"private-does-not-write-public-memory");
''')
        self.check_c(rows,'spx_caller_private_value(&memory,initial.esp-4U,4U);',
                     failures=('spx-caller-private-transport-initialized',))
        self.check_c(rows,'spx_caller_read(&memory,initial.esp-4U,4U,&fault);',
                     failures=('spx-caller-private-read-initialized',))

    def test_missing_access_wrong_width_and_wrong_permission_reject(self):
        rows=[access('input',constant(100),read=True)]
        for body,diagnostic in [
            ('spx_caller_read(&memory,104U,4U,&fault);','spx-caller-readable-frame'),
            ('spx_caller_read(&memory,100U,2U,&fault);','spx-caller-readable-frame'),
            ('spx_caller_write(&memory,100U,4U,value,&fault);','spx-caller-writable-frame'),
            ('spx_caller_private_value(&memory,100U,4U);','spx-caller-private-transport-present')]:
            with self.subTest(body=body):self.check_c(rows,body,failures=(diagnostic,))

    def test_private_alias_and_public_view_separation_are_assertions(self):
        private=access('private',constant(100),write=True,storage='private')
        self.check_c([private,access('public',constant(102),read=True)],'',
                     failures=('spx-caller-private-slot-separation',))
        self.check_c([private],'spx_caller_public_span(&memory,103U,2U);',
                     failures=('spx-caller-private-view-separation',))
        self.check_c([private],'spx_caller_public_span(&memory,104U,4U);spx_caller_public_span(&memory,96U,4U);')
        self.check_c([private],'',private_frame=(100,103),failures=('spx-caller-private-slot-in-frame',))
        self.check_c([private],'',private_frame=(101,104),failures=('spx-caller-private-slot-in-frame',))
        self.check_c([private],'',private_frame=(100,104))

    def test_top_address_and_private_narrow_writes(self):
        for width in (1,2,4):
            with self.subTest(width=width):
                address=2**32-width
                row=access('top',constant(address),write=True,storage='private',width=width)
                self.check_c([row],f'''
 spx_caller_write(&memory,{address}U,{width}U,value,&fault);
 __CPROVER_assert(spx_caller_private_value(&memory,{address}U,{width}U)==(value & {2**(8*width)-1}U),"narrow-private-value");
''')
        self.check_c([access('wrap',constant(2**32-1),read=True)],'',failures=('spx-caller-nonwrapping-slot',))

    def test_definitions_are_typed_canonical_and_phase_bound(self):
        rows=[access('b',entry_offset('esp',-4),write=True),access('a',constant(100),read=True)]
        self.assertEqual(checked_native_memory(rows),checked_native_memory(list(reversed(rows))))
        bad=[]
        row=deepcopy(rows[0]);row['address']['args'][0]['attributes']['place']['phase']='caller_after';bad.append([row])
        row=deepcopy(rows[0]);row['address']['args'][0]['attributes']['place']['selector']={'register':'esp; abort()'};bad.append([row])
        row=deepcopy(rows[0]);row['address']='initial.esp-4U';bad.append([row])
        row=deepcopy(rows[0]);row['width']=True;bad.append([row])
        row=deepcopy(rows[0]);row['assume_live']=True;bad.append([row])
        bad.extend([[],[rows[0],rows[0]],rows*17])
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):checked_native_memory(value)

    def test_private_byte_spans_share_storage_across_widths_and_aliases(self):
        rows=[private_bytes('whole',constant(100),8),private_bytes('tail',constant(104),4,write=False)]
        self.check_c(rows,'''
 spx_caller_write(&memory,100U,4U,0x11223344U,&fault);
 spx_caller_write(&memory,104U,4U,0x55667788U,&fault);
 uint8_t *whole=spx_caller_private_bytes(&memory,100U,8U,3U);
 uint8_t *tail=spx_caller_private_bytes(&memory,104U,4U,1U);
 __CPROVER_assert(tail==whole+4U,"private-byte-view-alias");
 spx_caller_write(&memory,103U,2U,0xabcdU,&fault);
 __CPROVER_assert(spx_caller_read(&memory,102U,4U,&fault)==0x77abcd22U,"private-mixed-width-read");
 __CPROVER_assert(spx_caller_private_value(&memory,104U,1U)==0xabU,"private-byte-argument-transport");
 whole[7]=0x42U;
 __CPROVER_assert(spx_caller_read(&memory,107U,1U,&fault)==0x42U,"private-byte-callee-mutation");
 __CPROVER_assert(world.count==0U && memory.private_writes==3U,"private-byte-effect-frame");
''',private_frame=(100,108),private_byte_capacity=8,unwind=10)

    def test_private_byte_reads_need_actual_initialization(self):
        rows=[private_bytes('buffer',constant(100),8)]
        for body in ['spx_caller_read(&memory,100U,4U,&fault);',
                     'spx_caller_write(&memory,100U,4U,value,&fault);spx_caller_private_bytes(&memory,100U,8U,1U);']:
            with self.subTest(body=body):
                self.check_c(rows,body,private_frame=(100,108),private_byte_capacity=8,unwind=10,
                             failures=('spx-caller-private-byte-initialized',))

    def test_private_byte_capacity_permissions_and_abi_separation_are_checked(self):
        span=private_bytes('buffer',constant(100),8)
        self.check_c([span],'',private_frame=(100,108),private_byte_capacity=4,
                     failures=('spx-caller-private-byte-capacity',))
        for row in [access('abi',constant(104),read=True,storage='private'),access('public',constant(104),read=True)]:
            self.check_c([span,row],'',private_frame=(100,108),private_byte_capacity=8,
                         failures=('spx-caller-private-slot-separation',))
        self.check_c([{**span,'write':False}],'spx_caller_write(&memory,100U,4U,value,&fault);',
                     private_frame=(100,108),private_byte_capacity=8,failures=('spx-caller-writable-frame',))
        self.check_c([span],'spx_caller_public_span(&memory,107U,1U);',private_frame=(100,108),private_byte_capacity=8,
                     failures=('spx-caller-private-view-separation',))
        self.check_c([span],'spx_caller_private_bytes(&memory,107U,2U,2U);',private_frame=(100,108),private_byte_capacity=8,
                     failures=('spx-caller-private-byte-view',))

    def test_private_byte_spans_keep_address_space_endpoint_and_typed_bounds(self):
        span=private_bytes('last',constant(2**32-4),4)
        self.check_c([span],'''
 spx_caller_write(&memory,UINT32_MAX-3U,4U,value,&fault);
 __CPROVER_assert(spx_caller_read(&memory,UINT32_MAX,1U,&fault)==(value>>24U),"last-private-byte");
''',private_frame=(2**32-4,2**32),private_byte_capacity=4)
        for extent in (0,257,True,'4U'):
            with self.subTest(extent=extent),self.assertRaises(ValueError):
                checked_native_memory([{**span,'extent':extent}])
        with self.assertRaisesRegex(ValueError,'fields differ'):
            checked_native_memory([{**span,'width':4}])

    def test_byte_capacity_covers_declared_storage_without_copying_the_whole_frame(self):
        self.check_c([private_bytes('small',constant(100),4)],'''
 spx_caller_write(&memory,100U,4U,value,&fault);
 __CPROVER_assert(memory.local.low==100U && memory.local.high==104U,"local-storage-span");
 __CPROVER_assert(spx_caller_read(&memory,100U,4U,&fault)==value,"small-storage-wide-frame");
''',private_byte_capacity=4)
