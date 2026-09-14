"""Actual image origins and the existing ordinary-C resource supplier for the network."""
import hashlib
from pathlib import Path

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.machine_overlay_v5 import _logical_operation_thunk
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from tests.unit.candidate.test_runtime_allocation_lifetime import _function
from tests.unit.components.native_image_shared_fixture import image_namespace
from tests.unit.components.test_hand_defined_boundaries import shared_buffer_bundle
from tests.unit.components.test_shared_state_views import projections

FIXTURES = Path(__file__).parents[2]/'fixtures'


def prepare_resource(root, source):
    # Keep the actual dynamic-origin context and bodies; replace only the static
    # locator stub and append the original image rules from the existing fixture.
    namespace = image_namespace()
    rows = namespace.split('spx_native_object_authority_rules[] = {', 1)[1].split('};', 1)[0]
    marker = 'static const spx_native_object_authority_rule spx_native_object_authority_rules[] = {'
    assert source.count(marker) == 1
    source = source.replace(marker, marker+rows)
    source = source.replace('spx_native_object_authority_rule_count = 1U;',
                            'spx_native_object_authority_rule_count = 5U;')
    helpers = namespace[namespace.index('static const uint32_t spx_native_tls_total_bytes'):]
    helpers = helpers[:helpers.index('static uint32_t spx_native_range_end')]
    source = source.replace(_function(source, 'spx_native_object_rule_base'),
                            helpers+_function(namespace, 'spx_native_object_rule_base'))
    # The stack rule remains explicit fixture admission. Image resolve/realize
    # now reach the same production functions as the dynamic origins.
    start = source.index('static const struct image_rule')
    end = source.index('static spx_boundary_status resolve_view', start)
    source = source[:start]+source[end:]
    start = source.index(' for(unsigned i=0;i<2;i++){')
    end = source.index(' spx_boundary_status status=', start)
    source = source[:start]+source[end:]
    start = source.index(' if(ref->domain==1U){')
    end = source.index(' return spx_native_realize_reference', start)
    source = source[:start]+source[end:]
    start = source.index('spx_view_v5 spx_component_logical_resource_text_get(void *opaque')
    source = source[:start]  # This is the final old notice-suppressed stub.
    source = source.replace('static unsigned char image_memory[0x37000];', 'static HMODULE metapad_image;')
    start = source.index('static void *physical(')
    end = source.index('\n', start)
    source = source[:start]+"""static void *physical(uint32_t address){
 return address>=0x400000U && address<0x437000U ? (char *)metapad_image+(address-0x400000U):(void *)(uintptr_t)address;
}"""+source[end:]
    source = source.replace('spx_native_resolve_reference(opaque,address,width,permissions,selector,nullable,one_past,ref)',
        'spx_native_resolve_reference(opaque,(uint32_t)(uintptr_t)physical(address),width,permissions,selector,nullable,one_past,ref)')
    source = source.replace(' return spx_native_realize_reference(opaque,ref,permissions,nullable,one_past,address);', """
 spx_boundary_status status=spx_native_realize_reference(opaque,ref,permissions,nullable,one_past,address);
 if(status==SPX_BOUNDARY_OK && ref->domain==1U){
  require(contains((uint32_t)(uintptr_t)metapad_image,0x37000U,*address,1U),"realized image address belongs to actual mapping");
  *address=0x400000U+(*address-(uint32_t)(uintptr_t)metapad_image);
 }
 return status;""")

    pe = (FIXTURES/'metapad-consumer-runtime/metapad.exe').read_bytes()
    assert hashlib.sha256(pe).hexdigest() == '685989bad8d8119eddbb49e36006d8ac9155c45d69dee060807368241c8e58ce'
    (root/'metapad.exe').write_bytes(pe)
    directory = root/'resource'; directory.mkdir()
    bundle = shared_buffer_bundle()
    for name, text in render_component_c_headers_v5(bundle, {'get':'resource_text'}).items():
        (directory/name).write_text(text)
    resource = (FIXTURES/'metapad-consumer-runtime/resource-text.c').read_bytes()
    assert hashlib.sha256(resource).hexdigest() == '6ff797884212a58148b4442effa4c1923ac3d13a3864f134d66b81b002fce54f'
    (directory/'resource-text.c').write_bytes(resource)
    state, result = projections()
    thunk = _logical_operation_thunk(bundle=bundle, component='resource_text', operation=bundle.interface.operations[0],
        source_symbol='resource_text', logical_symbol='spx_component_logical_resource_text_get',
        service_bindings=[{'service_id':'load_string', 'symbol':'network_load_string'}],
        state_projections=state, result_projections={'result':result},
        authority_selectors={'module':'image:metapad:section:2','buffer':'image:metapad:section:2'})
    overlay = (root/'overlay.c').read_text()
    context = overlay[overlay.index('typedef struct spx_component_service_context_v1 {'):overlay.index('} spx_component_service_context_v1;')+len('} spx_component_service_context_v1;')]
    (directory/'bridge.c').write_text('#include "portable-component-implementation.h"\n'
        '#include "../network.h"\n#include <string.h>\n'+context+'\n'
        +'\n'.join(result_view_runtime_helpers())+'\n'
        +'extern uint32_t network_load_string(void *,uint32_t,uint32_t,const spx_view_v5 *,uint32_t);\n'
        +'\n'.join(thunk)+'\n')
    return source
