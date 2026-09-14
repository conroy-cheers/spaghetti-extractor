"""Reuse the production cleanup adapter through both real consumer interfaces."""
import json
from pathlib import Path

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from tests.integration.native.cleanup_runtime_adapter import prepare as prepare_cleanup
from tests.integration.native.consumer_resource_adapter import prepare_resource

FIXTURES = Path(__file__).parents[2]/'fixtures'
FIXTURE = FIXTURES/'metapad-consumer-runtime'


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('retained cleanup runtime integration hook changed')
    return source.replace(before, after)


def prepare(root):
    inputs = prepare_cleanup(root)
    (root/'network.h').write_bytes((FIXTURE/'network.h').read_bytes())
    (root/'consumer-view-helpers.h').write_text('\n'.join(_view_runtime_helpers(need_read=True, need_write=True)))
    template = (FIXTURE/'consumer-bridge.c.in').read_text()
    for role, source, symbol in [('save','prepare-save.c','prepare_save'), ('replace','replace-selection.c','replace_selection')]:
        fixture = FIXTURES/('metapad-cleanup-'+role); directory = root/role; directory.mkdir()
        intent = ComponentInterfaceIntentV1.parse(json.loads((fixture/'component-interface-intent-v1.json').read_text()))
        bundle = compile_component_interface_v5(intent)
        operation = 'prepare' if role == 'save' else 'replace'
        for name, text in render_component_c_headers_v5(bundle, {operation:symbol}).items():
            (directory/name).write_text(text)
        (directory/source).write_bytes((fixture/source).read_bytes())
        if role == 'save':
            address = 'network_word(rt,state->ebp-20U)'
            call = '''(void)mode;
 spx_view_v5 length=view(rt,&contexts[5],state->ebp-12U,4U,3U,"network.stack");
 spx_cleanup_save_services_v5 services={.context=service,.cleanup=network_cleanup};
 spx_cleanup_save_context_v5 context={.services=&services};
 uint32_t result=prepare_save(&context,&text,&notice,&window,&edit,&caption,&length);
 return (network_result){result==UINT32_MAX,result};'''
        else:
            address = 'state->edi'
            call = '''spx_cleanup_replace_services_v5 services={.context=service,.cleanup=network_cleanup,.send_message=network_send_message};
 spx_cleanup_replace_context_v5 context={.services=&services};
 spx_outcome_v5 result=replace_selection(&context,&text,&notice,&window,&edit,&caption,mode);
 return (network_result){result.fault,result.value};'''
        (directory/'bridge.c').write_text(template.replace('@ROLE@',role).replace('@TEXT_ADDRESS@',address).replace('@CALL@',call))
        original = root/('original-'+role); original.mkdir()
        entry = '00005c2a' if role == 'save' else '0000b18e'
        for name in ['behavioral-fn-'+entry+'.c','behavioral-c.h','state-machine-runtime.h']:
            (original/name).write_bytes((fixture/'exact'/name).read_bytes())
        assert (original/'state-machine-runtime.h').read_bytes() == (root/'state-machine-runtime.h').read_bytes()
    support = [((FIXTURES/('metapad-cleanup-'+role))/'exact/behavioral-support.c').read_bytes() for role in ['save','replace']]
    assert support[0] == support[1]
    (root/'original-replace/behavioral-support.c').write_bytes(support[0])
    original = (root/'runtime-test.c').read_text()
    prefix = original[:original.index('static void run(')]
    prefix = replace_once(prefix, '#include "overlay.c"', '#include "overlay.c"\n#include "network.h"\nstatic HWND edits[2];\nstatic uint32_t swap_on_focus,message_value,callback_count;\nstatic char delivered[512];\nstatic WNDPROC edit_proc;\nstatic uint32_t deliver_message(uint32_t,uint32_t,uint32_t,uint32_t);')
    prefix = replace_once(prefix, 'require(a==0U,"scoped null focus target");output->eax=(uint32_t)(uintptr_t)SetFocus(NULL);',
        'require(a==(uint32_t)(uintptr_t)edits[0],"actual edit focus target");output->eax=(uint32_t)(uintptr_t)SetFocus((HWND)(uintptr_t)a);')
    # Fixture-owned stack/image admission remains explicit; dynamic text and
    # scratch origins continue to use the production native issuer.
    prefix = replace_once(prefix, ' for(unsigned i=0;i<2;i++){\n  const struct image_rule *r=&image_rules[i];',
        ''' if(selector && strcmp(selector,"network.stack")==0){
  if(!contains((uint32_t)(uintptr_t)stack_words,sizeof stack_words,address,width))return SPX_BOUNDARY_UNSUPPORTED;
  *ref=(spx_machine_reference_v1){2,1,1,address-(uint32_t)(uintptr_t)stack_words,sizeof stack_words,3};return SPX_BOUNDARY_OK;
 }
 for(unsigned i=0;i<2;i++){
  const struct image_rule *r=&image_rules[i];''')
    prefix = replace_once(prefix, ' if(ref->domain==1U){', ''' if(ref->domain==2U){
  if(ref->object!=1U || ref->generation!=1U || ref->extent!=sizeof stack_words || ref->permissions!=3U ||
      (permissions&3U)!=permissions || ref->offset>=ref->extent)return SPX_BOUNDARY_UNSUPPORTED;
  *address=(uint32_t)(uintptr_t)stack_words+(uint32_t)ref->offset;return SPX_BOUNDARY_OK;
 }
 if(ref->domain==1U){''')
    marker=' if(event->kind==SPX_CALL_INDIRECT){'
    prefix = replace_once(prefix, marker, (FIXTURE/'invoke-prefix.c.in').read_text()+marker)
    prefix = prepare_resource(root, prefix)
    prefix = prefix.replace('#include <windows.h>', '#include <windows.h>\n#include <assert.h>')
    prefix = replace_once(prefix, 'static uint32_t deliver_message(uint32_t,uint32_t,uint32_t,uint32_t);',
        'static uint32_t deliver_message(uint32_t,uint32_t,uint32_t,uint32_t);\n'
        'static uint32_t deliver_notice(uint32_t,uint32_t,uint32_t,uint32_t);')
    prefix = replace_once(prefix, ' if(event->kind==SPX_CALL_INDIRECT){', ''' if(event->symbol && strcmp(event->symbol,"MessageBoxA")==0){
  require(event->instruction_rva==0x565cU,"actual notice call edge");
  output->eax=deliver_notice(a,b,word(input->esp+8U),word(input->esp+12U));output->esp+=16U;return SPX_CALL_OK;
 }
 if(event->kind==SPX_CALL_INDIRECT){''')
    (root/'runtime-test.c').write_text(prefix+(FIXTURE/'runtime-resource.c.in').read_text()
                                     +(FIXTURE/'runtime-network.c.in').read_text())
    return inputs
