"""Real shared-buffer source reaches callers through the generated logical ABI."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_reference_transport import shared_state_overlay_transport_source
from spaghetti_extractor.components.machine_overlay_v5 import _logical_operation_thunk
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from .test_shared_state_views import write_native_fixture, projections
from .test_hand_defined_boundaries import shared_buffer_bundle

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text",)}


def write_logical_fixture(root):
    source = write_native_fixture(root)
    content = source.read_text()
    start = content.index('static spx_step_result invoke(')
    end = content.index('static void exercise(', start)
    bundle = shared_buffer_bundle()
    state, result = projections()
    thunk = _logical_operation_thunk(bundle=bundle, component='resource_text', operation=bundle.interface.operations[0],
        source_symbol='mutating_resource_text', logical_symbol='logical_get',
        service_bindings=[{'service_id':'load_string', 'symbol':'logical_interaction'}],
        state_projections=state, result_projections={'result':result}, authority_selectors={'module':'module','buffer':'buffer'})
    replacement = '''
typedef struct {
  spx_runtime *runtime; spx_machine_state *state; uint32_t *memory_fault, *service_fault;
  struct {uint32_t physical_word, target_rva;} callback_result;
} spx_component_service_context_v1;
static uint32_t mutation_at_call;
static uint32_t logical_interaction(void *opaque,uint32_t module,uint32_t id,const spx_view_v5 *buffer,uint32_t maximum) {
  spx_component_service_context_v1 *caller=opaque;
  return interaction(caller->runtime->context,module,id,buffer,maximum);
}
static spx_view_v5 mutating_resource_text(spx_resource_text_context_v5 *context,uint32_t id) {
  spx_view_v5 result=resource_text(context,id);
  spx_component_service_context_v1 *caller=context->services->context;
  mutate(context,&result,caller->runtime->context,mutation_at_call);
  return result;
}
''' + '\n'.join(thunk) + shared_state_overlay_transport_source('__CPROVER_spx_mutable_overlay_shared') + '''
static spx_step_result invoke(spx_runtime *rt,const spx_resource_text_services_v5 *services,
    uint32_t id,uint32_t mutation,spx_view_v5 *saved) {
  (void)services;
  uint32_t memory_fault=0U,service_fault=0U;
  spx_machine_state state={0};
  spx_component_service_context_v1 caller={rt,&state,&memory_fault,&service_fault,{0,0}};
  mutation_at_call=mutation;
  *saved=logical_get(&caller,id);
  if(memory_fault || service_fault)return (spx_step_result){SPX_MEMORY_FAULT,0,0};
  assert(__CPROVER_spx_mutable_overlay_shared(saved,rt,0x413d20U,3U));
  spx_runtime changed=*rt;changed.realize_reference=0;
  spx_view_v5 forged=*saved;forged.access_context=&changed;
  assert(!__CPROVER_spx_mutable_overlay_shared(&forged,rt,0x413d20U,3U));
  forged=*saved;forged.read=0;
  assert(!__CPROVER_spx_mutable_overlay_shared(&forged,rt,0x413d20U,3U));
  return (spx_step_result){SPX_RETURN,0,(uint32_t)(saved->base.object+saved->base.offset)};
}
'''
    source.write_text(content[:start]+replacement+content[end:])
    return source


class SharedLogicalTransportTests(unittest.TestCase):
    def test_generated_logical_call_compiles_and_runs_real_helper_with_current_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=write_logical_fixture(root)
            for compiler in (shutil.which('cc'),shutil.which('i686-w64-mingw32-gcc')):
                self.assertIsNotNone(compiler)
                result=subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(root/'test.o')],capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stderr)
            subprocess.run([shutil.which('cc'),str(source),'-o',str(root/'test')],capture_output=True,text=True,check=True,timeout=30)
            subprocess.run([str(root/'test')],capture_output=True,text=True,check=True,timeout=10)

    def test_logical_call_preserves_state_and_return_guards_for_each_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            source=write_logical_fixture(Path(directory))
            for mutation in range(12):
                with self.subTest(mutation=mutation):
                    result=run_cbmc_properties(command=[shutil.which('cbmc'),str(source),f'-DSPX_TEST_MUTATION={mutation}',
                        '--json-ui','--unwind','8','--unwinding-assertions','--pointer-check','--bounds-check',
                        '--signed-overflow-check','--undefined-shift-check','--div-by-zero-check','--sat-solver','cadical'],timeout_seconds=30)
                    self.assertEqual(result['status'],'satisfied',result.get('detail'))
