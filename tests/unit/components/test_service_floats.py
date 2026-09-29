"""Binary floating C signatures, native adapters and value-class edge cases."""
import copy
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import compile_component_interface_v5
from spaghetti_extractor.components.service_authoring import ServiceDefinition,component_interface
from spaghetti_extractor.components.service_c import render_service_bridges,render_operation_bridge

TESTKIT={'fixtures':('compiler',),'resources':('tests/fixtures/jq-path-network/numeric-index.h',)}
TYPES=[dict(id='unit',kind='void'),dict(id='f32',kind='float',format='binary32',value_bits=32),
       dict(id='f64',kind='float',format='binary64',value_bits=64),
       dict(id='pair',kind='record',nominal_id='fixture.pair',fields=[
           dict(id='small',type_id='f32',bit_width=None),dict(id='large',type_id='f64',bit_width=None)])]


def definition(name,type_id):
    return ServiceDefinition.create(identity='fixture.'+name,types=TYPES,parameters=[('value',type_id)],result=type_id,
        resources=[],effects=['fixture.scalar-return'],outcomes=['return'],unobserved=['floating environment and native semantics'])


class FloatingServiceTests(unittest.TestCase):
    def build(self,*,wrong_adapter=False,wrong_operation=False,wrong_normalization=False,flags=(),compiler=None):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)
        services={'small':definition('small','f32'),'large':definition('large','f64')}
        interface=component_interface(component_id='floating',types=TYPES,
            parameters=[('small','f32'),('large','f64')],result='pair',services=services)
        for name,text in render_component_c_headers_v5(compile_component_interface_v5(interface),{'run':'lifted'}).items():
            (root/name).write_text(text)
        wrappers,_=render_service_bridges(services=services,adapters={n:dict(symbol='native_'+n,kind='native',outcomes={'return':None}) for n in services},transports={})
        entry=render_operation_bridge(interface=interface,operation_symbol='lifted',native_symbol='entry',services=services,transports={})
        numeric=(Path(__file__).parents[2]/'fixtures/jq-path-network/numeric-index.h').read_text()
        if wrong_normalization:
            numeric=numeric.replace('number = INT32_MAX;', 'number = INT32_MAX - 1;')
        (root/'numeric-index.h').write_text(numeric)
        source='''#include <string.h>
#include "portable-component-implementation.h"
typedef struct { int32_t index; uint32_t is_nan; } spx_numeric_index_v2;
#include "numeric-index.h"
static FLOAT_RETURN native_small(float value) { return value; }
static double native_large(double value) { return value; }
'''.replace('FLOAT_RETURN','double' if wrong_adapter else 'float')+wrappers+'''
spx_pair_v2 lifted(spx_floating_context_v5 *context, FIRST_TYPE small, double large) {
  spx_pair_v2 result = {context->services->small(context->services->context,small),
                       context->services->large(context->services->context,large)};
  return result;
}
'''.replace('FIRST_TYPE','double' if wrong_operation else 'float')+entry+'''
int main(void) {
  const uint32_t small_bits[] = {0, 0x80000000U, 1, 0x80000001U, 0x7f7fffffU,
                                0x7f800000U, 0xff800000U, 0x7fc12345U, 0x3fe00000U};
  const uint64_t large_bits[] = {0, UINT64_C(0x8000000000000000), 1, UINT64_C(0x8000000000000001),
      UINT64_C(0x7fefffffffffffff), UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000),
      UINT64_C(0x7ff8123456789abc), UINT64_C(0x3ffc000000000000)};
  for (unsigned i=0;i<sizeof small_bits/sizeof small_bits[0];i++) {
    float a; double b; uint32_t actual_a; uint64_t actual_b;
    memcpy(&a,&small_bits[i],sizeof a); memcpy(&b,&large_bits[i],sizeof b);
    spx_pair_v2 result=entry(a,b);
    memcpy(&actual_a,&result.small,sizeof actual_a); memcpy(&actual_b,&result.large,sizeof actual_b);
    if(actual_a!=small_bits[i] || actual_b!=large_bits[i]) return 10+(int)i;
  }
  spx_pair_v2 result=entry((float)1.75, (double)(float)1.75);
  if(result.small!=1.75f || result.large!=1.75) return 30;
  for (unsigned i=0;i<sizeof large_bits/sizeof large_bits[0];i++) {
    double value; memcpy(&value,&large_bits[i],sizeof value);
    spx_numeric_index_v2 index=path_numeric_index(value);
    const int32_t expected[]={0,0,0,0,INT32_MAX,INT32_MAX,INT32_MIN,0,1};
    if(index.index!=expected[i] || index.is_nan!=(i==7)) return 40+(int)i;
  }
  const double values[]={2147483647.0,2147483648.0,-2147483648.0,-2147483649.0,1.9,-1.9};
  const int32_t expected[]={INT32_MAX,INT32_MAX,INT32_MIN,INT32_MIN,1,-1};
  for (unsigned i=0;i<sizeof values/sizeof values[0];i++) {
    spx_numeric_index_v2 index=path_numeric_index(values[i]);
    if(index.index!=expected[i] || index.is_nan) return 60+(int)i;
  }
  return 0;
}
'''
        (root/'main.c').write_text(source)
        built=subprocess.run([compiler or shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',*flags,
            str(root/'main.c'),str(root/'component-conformance.c'),'-o',str(root/'run')],capture_output=True,text=True)
        return root,built

    def test_native_callbacks_and_record_results_preserve_edge_value_bits(self):
        root,built=self.build();self.assertEqual(built.returncode,0,built.stderr)
        result=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stderr.count('SPX_SERVICE_SCOPE '),20)

    def test_changed_saturation_is_detected(self):
        root,built=self.build(wrong_normalization=True)
        self.assertEqual(built.returncode,0,built.stderr)
        result=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,44)

    def test_wrong_native_floating_abi_and_implementation_signature_reject(self):
        _,built=self.build(wrong_adapter=True)
        self.assertNotEqual(built.returncode,0);self.assertIn('floating service adapter signature differs',built.stderr)
        _,built=self.build(wrong_operation=True)
        self.assertNotEqual(built.returncode,0);self.assertIn('conflicting types',built.stderr)

    def test_fast_math_and_unsupported_float_shapes_reject_early(self):
        for flag in ['-ffast-math','-ffinite-math-only']:
            _,built=self.build(flags=[flag])
            self.assertNotEqual(built.returncode,0);self.assertIn('ordinary C floating semantics',built.stderr)
        for format,width in [('binary16',16),('x87-extended80',80),('binary32',64)]:
            types=copy.deepcopy(TYPES);types[1].update(format=format,value_bits=width)
            interface=component_interface(component_id='floating',types=types,parameters=[('value','f32')],result='f32',services={})
            with self.assertRaisesRegex(ValueError,'binary32'):
                render_component_c_headers_v5(compile_component_interface_v5(interface),{'run':'lifted'})
