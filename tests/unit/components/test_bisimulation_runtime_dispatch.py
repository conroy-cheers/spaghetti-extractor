"""Conditional dispatch preserves the actual native accessor and checks its domain."""

import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_assurance import (
    checked_implemented_runtime_assurance, runtime_assurance_defines,
)
from spaghetti_extractor.components.bisimulation_runtime_dispatch import (
    ASSERTION, runtime_dispatch_assurance, runtime_dispatch_source,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_lifetime_admission import interface_fixture
from tests.unit.components.test_conditional_contextual_refinement import fixture

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq")}


COMMON = '''
typedef struct { uint32_t calls, address, width, value, fault, resolve_status, resolved, selected; } record;
static void spx_proof_source_write(void *opaque, uint32_t address,
    uint32_t width, uint32_t value, uint32_t *fault) {
  record *r=opaque; r->calls++; r->address=address; r->width=width;
  r->value=value; r->selected=1U; *fault=r->fault;
}
static void spx_proof_exact_write(void *opaque, uint32_t address,
    uint32_t width, uint32_t value, uint32_t *fault) {
  record *r=opaque; r->calls++; r->address=address; r->width=width;
  r->value=value; r->selected=2U; *fault=r->fault;
}
static void wrong_write(void *opaque, uint32_t address,
    uint32_t width, uint32_t value, uint32_t *fault) { *fault=0U; }
static spx_boundary_status resolve(void *opaque, const spx_machine_reference_v1 *ref,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  record *r=opaque; *address=r->resolved; return (spx_boundary_status)r->resolve_status;
}
'''


def comparison_source():
    helpers = '\n'.join(result_view_runtime_helpers())
    digest = runtime_dispatch_assurance()['contracts'][0]['contract_sha256']
    macro = 'SPX_CONDITIONAL_RUNTIME_CONTRACT_' + digest
    native = helpers.replace('spx_component_result_view_', 'native_view_')
    return (COMMON + native + '\n#define ' + macro + '\n'
            + runtime_dispatch_source(runtime_dispatch_assurance()) + helpers + '''
static uint32_t compare(uint32_t choose, uint32_t address, uint32_t width,
    uint64_t offset, uint64_t extent, uint64_t base_offset, uint64_t value,
    uint32_t fault, uint32_t expired) {
  record a={0},b={0}; a.fault=b.fault=fault; a.resolved=b.resolved=address;
  a.resolve_status=b.resolve_status=expired;
  spx_runtime left={0},right={0}; left.context=&a; right.context=&b;
  left.realize_reference=right.realize_reference=resolve;
  left.write=right.write=choose ? spx_proof_source_write : spx_proof_exact_write;
  spx_ref_v5 ref={.domain=1,.object=2,.generation=3,.offset=base_offset,.extent=extent,.permissions=3};
  uint32_t x=native_view_write(&left,ref,offset,width,value);
  uint32_t y=spx_component_result_view_write(&right,ref,offset,width,value);
  return x==y && a.calls==b.calls && a.address==b.address && a.width==b.width &&
      a.value==b.value && a.selected==b.selected && a.fault==b.fault;
}
''')


class RuntimeDispatchTests(unittest.TestCase):
    def material(self, root, source):
        (root/'state-machine-runtime.h').write_text(exact_runtime_header())
        for name, value in render_component_c_headers_v5(
                interface_fixture(buffer_view=True), {'run': 'authored_run'}).items():
            (root/name).write_text(value)
        path=root/'dispatch.c'
        path.write_text('#include "state-machine-runtime.h"\n#include "portable-component.h"\n'+source)
        return path

    def cbmc(self, root, source):
        _write_cbmc_stdint(root/'stdint.h')
        (root/'stddef.h').write_text('#ifndef SPX_TEST_STDDEF\n#define SPX_TEST_STDDEF\n'
            'typedef unsigned int size_t; typedef signed int ptrdiff_t;\n#define NULL ((void *)0)\n#endif\n')
        path=self.material(root, source)
        return run_cbmc_properties(command=[shutil.which('cbmc'),str(path),'-I',str(root),'--i386-win32',
            '--json-ui','--trace','--unwind','3','--unwinding-assertions','--bounds-check',
            '--pointer-check','--signed-overflow-check','--undefined-shift-check'], timeout_seconds=60)

    def test_native_accessor_forwarding_for_symbolic_arguments_and_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            result=self.cbmc(Path(temporary),comparison_source()+'''
int main(void) {
  uint32_t choose,address,width,fault,expired;
  uint64_t offset,extent,base_offset,value;
  __CPROVER_assert(compare(choose,address,width,offset,extent,base_offset,value,fault,expired),
      "native accessor preserves dispatch, all arguments, failure and write effects");
}
''')
            self.assertEqual(result['status'],'satisfied',result.get('detail'))

    def test_real_native_compilation_matches_conditional_accessor(self):
        source='''#include <assert.h>
#define __CPROVER_assert(c,m) assert(c)
#define __CPROVER_assume(c) assert(c)
'''+comparison_source()+'''
int main(void) {
  const uint32_t addresses[]={0U,16U,0xfffffffcU,0xffffffffU};
  const uint32_t widths[]={0U,1U,2U,3U,4U,8U};
  for (uint32_t choose=0;choose<2;choose++)
    for (uint32_t a=0;a<4;a++) for (uint32_t w=0;w<6;w++)
      for (uint32_t fault=0;fault<2;fault++) for (uint32_t expired=0;expired<2;expired++)
        assert(compare(choose,addresses[a],widths[w],0U,16U,0U,0x123456789abcdef0ULL,fault,expired));
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=self.material(root,source)
            build=subprocess.run([shutil.which('cc'),str(path),'-o',str(root/'native')],capture_output=True,text=True)
            self.assertEqual(build.returncode,0,build.stderr)
            run=subprocess.run([str(root/'native')],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)

    def test_wrong_callback_and_changed_forwarded_value_are_detected(self):
        cases=[(comparison_source()+'''
int main(void) {
  record r={0}; spx_runtime rt={0}; rt.context=&r; rt.write=wrong_write;
  uint32_t fault=0; __CPROVER_spx_checked_runtime_write(&rt,16,1,7,&fault);
}
''',ASSERTION),
            (comparison_source().replace(
                'spx_proof_source_write(runtime->context, address, width, value, fault);',
                'spx_proof_source_write(runtime->context, address, width, value ^ 1U, fault);')+'''
int main(void) { __CPROVER_assert(compare(1U,16U,1U,0U,16U,0U,7U,0U,0U),"forwarded value mutation"); }
''','forwarded value mutation')]
        for source, expected in cases:
            with self.subTest(expected=expected),tempfile.TemporaryDirectory() as temporary:
                result=self.cbmc(Path(temporary),source)
                self.assertEqual(result['status'],'violated',result.get('detail'))
                self.assertEqual(result['source']['comment'],expected)

    def test_selection_requires_the_exact_contract_and_define(self):
        assurance=runtime_dispatch_assurance()
        self.assertEqual(checked_implemented_runtime_assurance(assurance),assurance)
        changed=copy.deepcopy(assurance);changed['contracts'][0]['revision']+=1
        with self.assertRaisesRegex(ValueError,'exact implemented'):
            checked_implemented_runtime_assurance(changed)
        self.assertEqual(runtime_dispatch_source(None),'')
        self.assertEqual(len(runtime_assurance_defines(assurance)),1)

    def test_engine_binds_mandatory_dispatch_check_and_conditional_policy(self):
        from spaghetti_extractor.components.contextual_bisimulation import (
            build_conditional_contextual_refinement_v1, validate_contextual_refinement_v2,
        )
        with tempfile.TemporaryDirectory() as temporary:
            system,inputs,assurance=fixture(Path(temporary),assurance=runtime_dispatch_assurance())
            result=system['proof']
            model=result['models']['operation_models'][0]['obligation_models'][0]
            self.assertIn(ASSERTION,model['required_assertion_descriptions'])
            self.assertFalse(result['authorizing'])
            self.assertEqual(result['status'],'satisfied',result)
            self.assertFalse(result['policy']['production_machine_overlay_executed'])
            self.assertEqual(result['policy']['conditional_runtime_write_dispatch'],'checked-target-forwarding-v1')
            with self.assertRaisesRegex(ValueError,'conditional runtime-contract'):
                validate_contextual_refinement_v2(result,proof_plan=system['proof_plan'],exact_c_slice=system['exact_c_slice'])
            changed=copy.deepcopy(inputs)
            model=changed['models']['operation_models'][0]['obligation_models'][0]
            model['required_assertion_descriptions'].remove(ASSERTION)
            model['required_assertion_descriptions_sha256']=canonical_sha256_v3(model['required_assertion_descriptions'])
            with self.assertRaisesRegex(ValueError,'dispatch applicability'):
                build_conditional_contextual_refinement_v1(**changed,runtime_assurance=assurance)
