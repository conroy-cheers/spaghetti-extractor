"""Conditional shared-summary consumers with canonical views and service calls."""

import json
import shutil
from pathlib import Path

from spaghetti_extractor.components.bisimulation_connected import render_connected_summary_wrapper, _connected_replay_source
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.components.bisimulation_shared_summary import SHARED_STRATEGY, current_memory_operations
from spaghetti_extractor.components.bisimulation_call_ranges import call_range_write_capacity
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs, build_typed_proof_service_thunk_renderer
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_reference_transport import (
    mutable_overlay_transport_source, mutable_connected_transport_source, connected_reference_transport_source,
)
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_shared_source_contracts import small_bundle
from .test_shared_service_premises import binding as selected_binding
from .test_bisimulation_call_ranges import buffer_binding
from .test_hand_defined_boundaries import FIXTURE


def summary_inputs(extent=8):
    bundle = small_bundle(extent)
    binding = {**buffer_binding(), **selected_binding(), 'symbol': 'load_string'}
    contract = {'relation_intent': json.loads((FIXTURE/'relation.json').read_text()),
        'maximum_calls': 1, 'maximum_memory_events': 1,
        'service_contracts': normalize_shared_service_bindings(bundle, [binding])}
    return bundle, binding, contract


def write_shared_pair(root, *, extent=8, mutation='', overlap=False, bundle=None, binding=None, contract=None, authority=None,
                      image_size=0x20000, framed_allocations=False, after_calls=''):
    root.mkdir(parents=True, exist_ok=True)
    if bundle is None:
        bundle, binding, contract = summary_inputs(extent)
    symbols = {'get': 'resource_text'}
    _write_cbmc_stdint(root/'stdint.h')
    (root/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
    (root/'state-machine-runtime.h').write_text(exact_runtime_header())
    (root/'connected-proof-summary.h').write_text('#define SPX_PROOF_CONNECTED_CAPACITY 2\n')
    for name, content in render_component_c_headers_v5(bundle, symbols).items():
        (root/name).write_text(content)
    wrapper = render_connected_summary_wrapper(bundle=bundle, operation_symbols=symbols,
        summary_ids={'get': 0}, checked_mutable_transport=True, shared_contract=contract)
    (root/'wrapper.c').write_text(wrapper)
    if authority is None:
        authority = MachineObjectAuthorityV2(machine_backend='x86-pe32', bindings={'original_pe_sha256':'a'*64}, rules=[{
            'id':'image', 'kind':'image', 'domain':1, 'object':2, 'generation':1, 'extent':0x5000,
            'permissions':3, 'lifetime':'image', 'locator':{'kind':'image_rva','image_id':'test','rva':0x10000},
            'interior_pointers':True, 'evidence_sha256':'a'*64}]).to_payload()
    current_zero = bool(current_memory_operations(contract))
    max_writes = 6 + 2 * int(current_zero)
    world = _world_source(max_writes=max_writes, max_private_writes=2, max_calls=2, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, service_bindings=[binding], private_ranges=(),
        reference_authority=authority, image_size=image_size, typed_exact_recording=True, summary_ranges=True,
        framed_shared_summaries=framed_allocations, summary_current_zero=current_zero)
    strategy = 'image-shared-framed-body-free-v1' if framed_allocations else SHARED_STRATEGY
    replay = '\n'.join(_connected_replay_source([{'summary_id':0, 'summary_capacity':2, 'summary_strategy':strategy,
        'mutable_transport_policy':'canonical-mutable-callee-transport-v1'}], max_writes=max_writes, max_calls=2, max_atomics=1,
        call_range_writes_per_call=call_range_write_capacity(_proof_call_specs([binding]))))
    renderer = build_typed_proof_service_thunk_renderer(interface=ProofKernelComponentInterface.parse(_logical_projection(bundle)),
        service_bindings=[binding], relation_evidence=[])
    source = '#include "state-machine-runtime.h"\n#include "portable-component-implementation.h"\n#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n'
    source += world + replay + connected_reference_transport_source() + '''
typedef struct { spx_runtime *runtime; spx_machine_state *state; uint32_t *memory_fault, *service_fault; } spx_component_service_context_v1;
uint32_t spx_component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  return rt->read(rt->context, address, width, fault);
}
'''
    source += '\n'.join(renderer(bundle, binding, {}))
    source += '\n'.join(_view_runtime_helpers(need_read=True, need_write=True))
    inspector = '__CPROVER_spx_mutable_overlay_fixture'
    source += mutable_overlay_transport_source(inspector)
    source += mutable_connected_transport_source([inspector], symbol='__CPROVER_spx_connected_mutable_transport_resource_text',
                                                framed=framed_allocations)
    source += wrapper + '''
static void fixture_view(spx_view_v5 *view, spx_component_view_context *transport, spx_runtime *runtime,
    uint32_t address, uint32_t extent, uint32_t permissions) {
  spx_machine_reference_v1 reference;
  __CPROVER_assert(runtime->resolve_reference(runtime->context,address,extent,permissions,0,0U,0U,&reference)==SPX_BOUNDARY_OK,
      "summary fixture origin");
  *transport=(spx_component_view_context){runtime,address,extent,permissions};
  *view=(spx_view_v5){.base={reference.domain,reference.object,reference.generation,reference.offset,reference.extent,reference.permissions},
    .extent=extent,.element_width=1U,.context=transport,.access_context=transport,
    .read_u8=spx_component_view_read,.read=spx_component_view_read_span,
    .write_u8=permissions==3U?spx_component_view_write:0,.write=permissions==3U?spx_component_view_write_span:0};
}
int main(void) {
  spx_proof_reset_worlds(0x800000U,256U); spx_proof_reset_connected_summaries();
  spx_runtime exact_runtime=spx_proof_runtime(&spx_exact_world), source_runtime=spx_proof_runtime(&spx_source_world);
  uint32_t fault=0U, service_fault=0U, id1=spx_nondet_u32(), id2=spx_nondet_u32(), updated=spx_nondet_u32();
  spx_machine_state exact_state={0},source_state={0};
  spx_component_service_context_v1 exact_service={&exact_runtime,&exact_state,&fault,&service_fault};
  spx_component_service_context_v1 source_service={&source_runtime,&source_state,&fault,&service_fault};
  spx_resource_text_services_v5 left_services={.context=&exact_service,.load_string=SERVICE};
  spx_resource_text_services_v5 right_services={.context=&source_service,.load_string=SERVICE};
  spx_resource_text_context_v5 left={.services=&left_services},right={.services=&right_services};
  spx_component_view_context left_module,left_buffer,right_module,right_buffer;
  fixture_view(&left.state.module,&left_module,&exact_runtime,MODULE,4U,1U);
  fixture_view(&right.state.module,&right_module,&source_runtime,MODULE,4U,1U);
  fixture_view(&left.state.buffer,&left_buffer,&exact_runtime,0x413d20U,EXTENT,3U);
  fixture_view(&right.state.buffer,&right_buffer,&source_runtime,0x413d20U,EXTENT,3U);
  MUTATION
  spx_view_v5 original1=resource_text(&left,id1);
  spx_proof_exact_write(0,MODULE,4U,updated,&fault);
  spx_view_v5 original2=resource_text(&left,id2);
  spx_view_v5 portable1=resource_text(&right,id1);
  spx_proof_source_write(0,MODULE,4U,updated,&fault);
  spx_view_v5 portable2=resource_text(&right,id2);
  AFTER_CALLS
  __CPROVER_assert(fault==0U && service_fault==0U,"summary boundary faults absent");
  __CPROVER_assert(spx_proof_connected_summaries_equal(),"summary paired invocations");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"summary related post-memory");
  __CPROVER_assert(portable1.access_context==&right_buffer && portable2.access_context==&right_buffer &&
      original1.access_context==&left_buffer && original2.access_context==&left_buffer,"summary keeps each caller transport");
  uint32_t offset=spx_nondet_u32(); __CPROVER_assume(offset<EXTENT);
  uint64_t observed=0U;
  __CPROVER_assert(portable1.read(portable1.access_context,portable1.base,offset,1U,&observed)==SPX_BOUNDARY_OK,
      "old summary alias remains readable");
  __CPROVER_assert(observed==spx_proof_source_byte(0x413d20U+offset),"old summary alias observes current bytes");
}
'''.replace('SERVICE',binding['symbol']).replace('MODULE','0x413d21U' if overlap else '0x410150U').replace('EXTENT',str(extent)+'U').replace('MUTATION',mutation).replace('  AFTER_CALLS\n', after_calls)
    (root/'pair.c').write_text(source)
    command=[shutil.which('cbmc'),str(root/'pair.c'),'--json-ui','--trace','--unwind','8',
        '--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check','--undefined-shift-check',
        '--object-bits','12','--sat-solver','cadical','--reachability-slice-fb','--slice-formula',
        *reference_authority_unwind_arguments(authority)]
    return command


def check_shared_pair(root, **kwargs):
    # The complete two-invocation service/store model measured 105 seconds with
    # all properties enabled. This is a query budget, not a weakened domain.
    return run_cbmc_properties(command=write_shared_pair(root, **kwargs), timeout_seconds=180)
