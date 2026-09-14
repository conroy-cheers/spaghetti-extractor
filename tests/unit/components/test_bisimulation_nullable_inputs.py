"""Nullable input initialization checks independently resolved worlds."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.components.bisimulation_harness import memory_projection_readers
from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
from spaghetti_extractor.components.bisimulation_native_admission import native_admission_assurance
from spaghetti_extractor.components.bisimulation_native_views import native_view_specs
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_view_extent import shared_view_initialization, shared_view_admission_source, view_parameter_ids
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties, run_cbmc_cover
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_allocation_calls import inputs
from tests.unit.components.test_bisimulation_allocation_cuts import sources
from tests.unit.components.test_bisimulation_lifetime_admission import interface_fixture
from tests.unit.components.test_nullable_input_views import input_overlay, projection

TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def input_model(*, aliases=False):
    # This deliberately constructs the private lowering candidate directly.
    # Public lowering separately requires the bound production projection.
    types = {'buffer': SimpleNamespace(kind='view', nullable=True, extent_kind='origin_remainder',
        access='read_write', element_type_id='u8', nul_terminated=False),
        'u8': SimpleNamespace(kind='scalar', c_type='uint8_t')}
    names = ['scratch', 'alias'] if aliases else ['scratch']
    interface = SimpleNamespace(type_index=lambda: types, operation_index=lambda: {'run': SimpleNamespace(
        parameters=[SimpleNamespace(identity=name, type_id='buffer') for name in names])})
    rows = []
    for i, name in enumerate(names):
        raw = projection();raw['base']['offset'] = 12 + i * 4
        rows.append({'id': name, 'projection': raw})
    machine = {'parameters': rows}
    authority, _, _ = inputs()
    specs = native_view_specs(interface, 'run', {'object_authority_selectors': {'scratch': 'text'}}, authority, machine)
    return interface, machine, specs


def fixture(before, after, *, aliases=False, live=True, drop_memory_check=False, after_exposure='', assurance=None):
    interface, machine, specs = input_model(aliases=aliases)
    initialization = shared_view_initialization(interface=interface, operation_id='run',
        operation_projection=machine, sync=None, proof_function='candidate', native_specs=specs)
    lines = '\n'.join([*initialization[:-1], after_exposure, initialization[-1]])
    if drop_memory_check:
        old = 'spx_proof_world_memory_range_equal(__CPROVER_spx_nullable_input_0_base, __CPROVER_spx_nullable_input_0_exact_reference.extent)'
        assert lines.count(old) == 1
        lines = lines.replace(old, '1')
    authority, inventory, _ = inputs()
    _, recipe, _ = sources(1)
    world = _world_source(max_writes=2, max_private_writes=2, max_calls=1, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, max_exposed_stack_views=2,
        maximum_input_allocations=1, service_bindings=[], private_ranges=(),
        reference_authority=authority, reference_runtime_inventory=inventory, image_size=0x20000,
        runtime_assurance=assurance)
    helpers = '\nconst uint32_t spx_proof_private_high_offset=256U;\n'
    helpers += shared_view_admission_source(private_ranges=(), image_base=0x400000, image_size=0x20000)
    helpers += '\n'.join(memory_projection_readers())
    helpers += '\n'.join(result_view_runtime_helpers(input_view_decoder=True,
        proof_codec_symbol='__CPROVER_spx_candidate_local_view_codec'))
    helpers += spx_portable_reference_runtime_v5_source()
    allocate = f'''
  spx_proof_allocation row={{.base=4096U,.size=size,.family={recipe['family']}U,
      .generation=2U,.live=1U,.native_rule_selector={recipe['native_rule_selector']}U,
      .native_generation=42U,.birth_class_selector={recipe['birth_class_selector']}U}};
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&row)==SPX_BOUNDARY_OK &&
      spx_proof_restore_allocation_input(&spx_source_world,&row)==SPX_BOUNDARY_OK,"paired input allocation");
''' if live else ''
    return '#include "state-machine-runtime.h"\n#include "portable-component.h"\n#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + world + helpers + '''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(value) ((void)0)
#endif
int main(void) {
  spx_proof_reset_worlds(8388608U,256U);
  uint32_t size=spx_nondet_u32(),interior=spx_nondet_u32(),fault=0U;
  __CPROVER_assume(size>=16U && size<=1024U && interior<size);
''' + allocate + '''
  spx_machine_state initial_state={0};initial_state.esp=8388608U;
  spx_runtime source_runtime=spx_proof_runtime(&spx_source_world);
''' + before + '\n' + lines + '\n' + after + '\n__CPROVER_cover(1);\n}\n'


class NullableInputAdmissionTests(unittest.TestCase):
    def check(self, before, after='', *, aliases=False, live=True, failure=None, drop_memory_check=False,
              after_exposure='', assurance=None):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_write_cbmc_stdint(root/'stdint.h')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            for name,text in render_component_c_headers_v5(interface_fixture(buffer_view=True), {'run':'authored_run'}).items():
                (root/name).write_text(text)
            (root/'input.c').write_text(fixture(before, after, aliases=aliases, live=live,
                drop_memory_check=drop_memory_check, after_exposure=after_exposure, assurance=assurance))
            command=[shutil.which('cbmc'),str(root/'input.c'),'--json-ui','--unwind','4','--sat-solver','cadical',
                *reference_authority_unwind_arguments(inputs()[0],allocation_capacity=2),
                *runtime_assurance_defines(assurance)]
            result=run_cbmc_properties(command=[*command,'--trace','--unwinding-assertions','--bounds-check',
                '--pointer-check','--signed-overflow-check','--undefined-shift-check'],timeout_seconds=120 if aliases else 40)
            self.assertEqual(result['status'],'violated' if failure else 'satisfied',result.get('detail'))
            if failure:self.assertIn(failure,result['detail'])
            else:
                result=run_cbmc_cover(command=[*command,'-DSPX_TEST_COVER','--cover','cover'],
                    expected_functions=['main'],timeout_seconds=40)
                self.assertEqual(result['status'],'satisfied',result)

    def test_null_failed_allocation_exposes_no_memory_and_matches_native_codec(self):
        self.check('''
  __CPROVER_assume(spx_proof_exact_input_read(initial_state.esp+12U,4U)==0U);
''','''
  __CPROVER_assert(spx_proof_exposed_count==0U,"null input exposes no invented byte span");
  spx_view_v5 view={0};
  __CPROVER_assert(!spx_component_input_view_decode(&source_runtime,0U,1U,3U,"text",&view),"native null decode");
  __CPROVER_assert(__CPROVER_spx_candidate_local_view_codec(&source_runtime,&view,0U,1U,UINT64_MAX,3U,"text",1U,0U),
      "null input agrees with existing cut codec");
''',live=False)

    def test_variable_allocation_and_interior_input_preserve_whole_origin(self):
        self.check('''
  __CPROVER_assume(spx_proof_exact_input_read(initial_state.esp+12U,4U)==4096U+interior);
''','''
  __CPROVER_assert(spx_proof_exposed_count==1U && spx_proof_exposed[0].base==4096U &&
      spx_proof_exposed[0].end==4096U+size,"complete runtime origin is exposed");
  spx_view_v5 view={0};
  __CPROVER_assert(!spx_component_input_view_decode(&source_runtime,4096U+interior,1U,3U,"text",&view),"native live decode");
  __CPROVER_assert(view.extent==size-interior && view.base.extent==size && view.base.offset==interior,
      "native input preserves runtime extent and offset");
  __CPROVER_assert(__CPROVER_spx_candidate_local_view_codec(&source_runtime,&view,4096U+interior,1U,UINT64_MAX,3U,"text",1U,0U),
      "live input agrees with existing cut codec");
  uint8_t byte=0U;
  __CPROVER_assert(spx_view_read_u8(&view,0U,&byte)==SPX_REF_OK &&
      byte==spx_proof_exact_input_read(4096U+interior,1U),"input bytes remain current");
''')

    def test_two_inputs_may_alias_and_copied_alias_observes_writes_and_expiry(self):
        self.check('''
  __CPROVER_assume(spx_proof_exact_input_read(initial_state.esp+12U,4U)==4096U+interior);
  __CPROVER_assume(spx_proof_exact_input_read(initial_state.esp+16U,4U)==4096U+interior);
''','''
  __CPROVER_assert(spx_proof_exposed_count==2U,"alias inputs retain both declared exposures");
  spx_view_v5 view={0};uint8_t byte=0U;
  __CPROVER_assert(!spx_component_input_view_decode(&source_runtime,4096U+interior,1U,3U,"text",&view),"decode aliased input");
  spx_view_v5 alias=view;
  __CPROVER_assert(spx_view_write_u8(&view,0U,91U)==SPX_REF_OK,"write via first alias");
  spx_proof_exact_write(0,4096U+interior,1U,91U,&fault);
  __CPROVER_assert(!fault && spx_view_read_u8(&alias,0U,&byte)==SPX_REF_OK && byte==91U,
      "copied alias observes same current storage");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"paired write preserves contents");
  spx_source_world.allocations[0].live=0U;
  __CPROVER_assert(spx_view_read_u8(&alias,0U,&byte)!=SPX_REF_OK,"alias cannot outlive allocation");
''',aliases=True)

    def test_current_memory_mismatch_is_detected_even_with_equal_reference_metadata(self):
        before='''
  __CPROVER_assume(spx_proof_exact_input_read(initial_state.esp+12U,4U)==4096U);
  __CPROVER_assume(spx_proof_exact_input_read(4096U,1U)==7U);
'''
        mutation='spx_proof_source_write(0,4096U,1U,8U,&fault);'
        self.check(before,after_exposure=mutation,failure='shared-view-inputs')
        self.check(before,after_exposure=mutation,drop_memory_check=True)

    def test_source_pointer_lifetime_and_generation_are_checked_not_assumed(self):
        before='__CPROVER_assume(spx_proof_exact_input_read(initial_state.esp+12U,4U)==4096U);'
        for mutation,diagnostic in (
                ('spx_source_world.allocations[0].live=0U;','shared-view-inputs'),
                ('spx_source_world.allocations[0].native_generation=43U;','shared-view-inputs'),
                ('spx_proof_source_write(0,initial_state.esp+12U,4U,0U,&fault);','exposed-stack-before-effects')):
            with self.subTest(mutation=mutation):self.check(before+mutation,failure=diagnostic)

    def test_failed_pointer_read_cannot_be_admitted_as_an_empty_view(self):
        self.check('''
  __CPROVER_assume(__CPROVER_uninterpreted_spx_native_residual_access(initial_state.esp+12U,4U,0U)==0U);
''',live=False,assurance=native_admission_assurance(),failure='exact-output-read')

    def test_public_lowering_and_unbound_admission_remain_closed(self):
        bundle,_=input_overlay()
        with self.assertRaisesRegex(ValueError,'nullable logical view contract'):_logical_projection(bundle)
        interface,machine,specs=input_model()
        with self.assertRaisesRegex(BisimulationRefinementError,'canonical non-null'):
            view_parameter_ids(interface,'run',machine)
        self.assertEqual(view_parameter_ids(interface,'run',machine,native_specs=specs),['scratch'])
        for key,value in [('extent',{'kind':'constant','value':1,'width':32}),('at','exit')]:
            changed=copy.deepcopy(machine);changed['parameters'][0]['projection'][key]=value
            with self.assertRaises(ValueError):
                native_view_specs(interface,'run',{'object_authority_selectors':{'scratch':'text'}},inputs()[0],changed)


if __name__=='__main__':unittest.main()
