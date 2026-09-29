"""Typed caller facts from an evidence-validated paired-operation summary.

These are closed compatibility readers for the existing cleanup and borrowed-image producers,
not an authoring format or a proof checker. The operator must first replay the
supplier's evidence reader. Legacy semantic markers select implemented rules;
neither those markers nor a matching digest establish a theorem on their own.
Runtime premises remain explicit, exact, unverified inputs.
"""
from copy import deepcopy
import re

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_cleanup_entry_relations import normalized_cleanup_entry_relations
from .bisimulation_native_calls import SCALAR_FIELDS, ARRAY_FIELDS, summary_return
from .bisimulation_caller_memory import ENTRY_REGISTERS
from .interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5

RULE = 'checked-paired-supplier-facts-v1'
BORROWED_RULE = 'checked-borrowed-supplier-facts-v1'


def require(value, message):
    if not value:
        raise ValueError('supplier facts: '+message)


def fields(value, names, label):
    require(isinstance(value, dict) and set(value)==set(names.split()), label+' fields differ')


def marker(value, expected, label):
    require(value==expected, label+' needs a reviewed composition rule')


def checked_borrowed_supplier_facts(transition, *, original, required_frame):
    """Normalize a validated borrowed-image transition, never a declaration.

    The caller must first run checked_shared_original_transition against the
    complete original/source evidence. The original manifest is its validated
    input, retained here to bind the consumer's exact dependency body and plan.
    """
    from .bisimulation_call_domain import checked_borrowed_domain
    from .bisimulation_clobber_frame import frame_equalities
    from .bisimulation_harness import _architectural_state_equalities
    from .bisimulation_native_calls import checked_return
    transition=deepcopy(transition)
    shared=checked_borrowed_domain(transition)
    domain=transition['domain'];bundle=shared['bundle'];operation=shared['operation']
    require(original['slice_sha256']==domain['exact_c_slice_sha256'], 'borrowed original identity differs')
    surface=bundle.intent.to_payload()
    logical,=[op for op in bundle.interface.operations if op.identity==transition['operation_id']]
    signature=bundle.intent.schema.signature_index[logical.signature_id].to_payload()
    result,=signature['results']
    require(result['interpretation']=='view' and result['extent']['kind']=='fixed'
            and result['extent']['bytes']==shared['extent'], 'borrowed result extent differs')
    available=sorted(v.replace(' ','') for v in frame_equalities(
        _architectural_state_equalities('state','initial'),[*shared['clobbers'],'eax','esp']))
    require(isinstance(required_frame,list) and all(isinstance(v,str) and v in SCALAR_FIELDS|set(ARRAY_FIELDS) for v in required_frame)
            and required_frame==sorted(set(required_frame)), 'invalid requested borrowed frame')
    required=['state.'+v+'==initial.'+v for v in required_frame]
    missing=sorted(set(required)-set(available))
    preserved=[v for v in required_frame if 'state.'+v+'==initial.'+v in available]
    accesses=shared['accesses'];private={'low':min(o for o,n in accesses),
        'high':max(o+n for o,n in accesses),'writes':[list(r) for r in shared['writes']]}
    image=domain['machine_domain']
    views={name:{'address':address,'extent':extent,'permissions':permissions}
        for name,(extent,permissions,address) in shared['views'].items()}
    entry,=operation.semantics.entry_rvas
    facts={'rule':BORROWED_RULE,'component_id':bundle.interface.identity,'operation_id':logical.identity,
        'interface_intent':surface,'signature':signature,'original_entry_rva':entry,
        'original_transfer_plan_sha256':original['bindings']['executable_transfer_plan_sha256'],
        'original_files':{r['path']:r['sha256'] for r in original['files'] if r['path'] in
            {f'behavioral-fn-{entry:08x}.c','behavioral-support.c','state-machine-runtime.h'}},
        'native_projection':{'image_views':views,'call_entry_stack_delta':-4},
        'result_view':{'state_id':shared['alias'],'address':shared['address'],'extent':shared['extent']},
        'normal_return':checked_return({'result_field':'eax','stack_delta':0,'preserved_fields':preserved}),
        'entry_relations':[],'normal_excludes':[],'private_frame':private,
        'image':{'base':image['image_base'],'size':image['image_size']},
        'runtime_assumptions':{'status':'unverified','requirements':domain['runtime_contract'],
            'service_bindings':domain['service_bindings']},
        'assurance':{'authorizing':False,'activation_authorized':False,'whole_component_complete':False}}
    require(len(facts['original_files'])==3, 'borrowed original body/runtime binding is absent')
    return facts,{'rule':BORROWED_RULE,'status':'requires-recheck' if missing else 'compatible',
        'required_normal_frame':required,'available_normal_frame':available,'missing_guarantees':missing,
        'provided_contract_sha256':transition['domain_sha256'],'consumed_contract_sha256':canonical_sha256_v3(facts)}


def _surface(c):
    intent=ComponentInterfaceIntentV1.parse(c['interface_intent'])
    bundle=compile_component_interface_v5(intent)
    require(intent.component_id==c['component_id'], 'supplier component identity differs')
    interface=bundle.interface
    require(not interface.state and not interface.effects and len(interface.protocol_states)==1
            and len(interface.operations)==1, 'supplier state/effects require a composition rule')
    operation,=interface.operations
    require(operation.identity==c['operation_id'], 'supplier operation identity differs')
    raw=intent.to_payload()['operations'][0]
    require(not raw['effect_ids'] and not raw['lifecycle_bindings'] and not raw['checked_interaction_contract_ids']
            and raw['lifecycle_additional_roots']=={'state':[]}, 'supplier lifecycle requires a composition rule')
    signature=intent.schema.signature_index[operation.signature_id].to_payload()
    expected=[{'source_id':v['id'],'target':{'root':root,'value_id':v['id'],'fields':[]}}
              for root,key in [('parameter','parameters'),('result','results')] for v in signature[key]]
    require(raw['projection_entries']==expected and raw['source_values']==signature['parameters']+signature['results'],
            'supplier parameter/result transport requires a composition rule')
    return intent.to_payload(), signature


def checked_supplier_facts(summary, required_frame):
    """Select guarantees only after full supplier evidence validation upstream.

Unselected normal frame facts are removed; all other normalized semantics and
runtime premises remain bound. No general implication or runtime compatibility
claim is made. Unsupported semantic forms fail before generating a caller model.
"""
    require(isinstance(summary,dict) and summary.get('status')=='satisfied'
            and summary.get('authorizing') is False and summary.get('activation_authorized') is False
            and summary.get('runtime_compatibility')=='unverified', 'expected conditional checked summary')
    c=deepcopy(summary['contract'])
    require(summary['contract_sha256']==canonical_sha256_v3(c), 'dependency contract binding differs')
    fields(c,'profile component_id operation_id interface_intent original_entry_rva original_transfer_plan_sha256 '
           'native_projection input_relation runtime_requirements normal_return memory_fault all_outcomes private_frame termination use excluded','contract')
    marker(c['profile'],'conditional-cleanup-paired-operation-v1','summary profile')
    require(type(c['original_entry_rva']) is int and 0<=c['original_entry_rva']<2**32
            and isinstance(c['original_transfer_plan_sha256'],str)
            and re.fullmatch('[0-9a-f]{64}',c['original_transfer_plan_sha256']), 'original binding is malformed')
    surface,signature=_surface(c)
    p=c['native_projection'];fields(p,'text image_views call_entry_stack_delta normal_call_stack_delta return_word_offset','native projection')
    fields(p['text'],'register extent permissions','text projection')
    require(p['text']['register'] in ENTRY_REGISTERS and p['text']['extent']=='text_extent'
            and type(p['text']['permissions']) is int and p['text']['permissions']==3, 'unsupported text projection')
    # These offsets describe the implemented x86 CALL transport, not a target hash.
    require(type(p['call_entry_stack_delta']) is int and p['call_entry_stack_delta']==-4
            and type(p['return_word_offset']) is int and p['return_word_offset']==-4, 'unsupported CALL return-word transport')
    fields(p['image_views'],'suppress_notice main_window edit_window caption','image views')
    for name,view in p['image_views'].items():
        fields(view,'address extent','image view '+name)
        require(all(type(view[k]) is int for k in ('address','extent'))
                and 0<view['address']<2**32 and 0<view['extent']<=2**32-view['address'], 'invalid image view '+name)
    incoming=c['input_relation'];fields(incoming,'native_flag_bounds public_memory views caller_requirements entry_admission','input relation')
    marker(incoming['native_flag_bounds'],{'df':[0,1]},'native flag domain')
    marker(incoming['public_memory'],'The same current byte function at every admitted physical address; aliases share that function.','incoming public memory')
    marker(incoming['views'],'The complete checked parameter reference/view relation, including current contents, permissions and live context storage.','incoming view correspondence')
    normal=c['normal_return'];fields(normal,'result stack_delta return_target preserved_equalities frame_quantifiers','normal return')
    fields(normal['result'],'kind native_field excluded_values','normal result')
    marker(normal['return_target'],'The incoming return word.','normal return target')
    returned=summary_return(c)
    exclusions=normal['result']['excluded_values']
    require(isinstance(exclusions,list) and all(type(v) is int and 0<=v<2**32 for v in exclusions)
            and exclusions==sorted(set(exclusions)) and 2**32-1 in exclusions, 'normal result must exclude the fault sentinel')
    marker(c['memory_fault'],{'native_outcome':'SPX_MEMORY_FAULT','source_result':2**32-1,
        'native_register_relation':'Not exported; consumers must not assume a normal return frame on this exit.'},'memory fault')
    outcomes=c['all_outcomes'];fields(outcomes,'public_memory service_observations maximum_service_calls','all outcomes')
    marker(outcomes['public_memory'],{'kind':'pointwise-byte-equality','address_width':32,
        'scope':'The admitted public world, separate from the disjoint callee-private frame; not the full physical process heap.'},'public post-memory')
    marker(outcomes['service_observations'],'Ordered stage/kind, arguments, normalized results and public byte at each call; pointer results additionally use the checked view/reference relation.','ordered observations')
    require(type(outcomes['maximum_service_calls']) is int and 0<=outcomes['maximum_service_calls']<2**32, 'unsupported service bound')
    private=c['private_frame'];fields(private,'low high scope','private frame')
    require(type(private['low']) is int and -256<=private['low']<0 and type(private['high']) is int
            and private['high']==4, 'unsupported private frame transport')
    marker(private['scope'],'Checked private byte transport under the caller/allocator separation and physical-access premises.','private frame scope')
    marker(c['termination'],'Finite under the regional/runtime premises when dependency invocations return; the checked rank handles repeated loop cuts.','conditional progress')
    marker(c['use'],'Paired caller equivalence only. Assert corresponding inputs before coupling the abstract results and post-memory.','summary use')
    marker(c['excluded'],['Concrete caller/adapter/service qualification.','Service invocation failures and nonreturning services.',
        'Observable native fault-register context.','Native activation and strong contextual-bisimulation authority.'],'assurance exclusions')
    runtime=c['runtime_requirements']
    fields(runtime,'regional allocator_requirements named accessors observations service_model_contracts','runtime premises')
    require(isinstance(runtime['named'],dict) and runtime['named']
            and all(isinstance(k,str) and k and isinstance(v,str) and v for k,v in runtime['named'].items()), 'named runtime premises are malformed')
    require(isinstance(required_frame,list) and all(isinstance(v,str) and v in SCALAR_FIELDS|set(ARRAY_FIELDS)
            for v in required_frame) and required_frame==sorted(set(required_frame)), 'requested frame is not canonical')
    available=normal['preserved_equalities'];required=['state.'+v+'==initial.'+v for v in required_frame]
    missing=sorted(set(required)-set(available))
    returned['preserved_fields']=sorted(set(required_frame)&set(returned['preserved_fields']))
    facts={'rule':RULE,'component_id':c['component_id'],'operation_id':c['operation_id'],
        'original_entry_rva':c['original_entry_rva'],'original_transfer_plan_sha256':c['original_transfer_plan_sha256'],
        'interface_intent':surface,'signature':signature,'native_projection':p,
        'entry_relations':normalized_cleanup_entry_relations(c),'normal_return':returned,'normal_excludes':exclusions,
        'memory_fault':{'kind':'memory-fault','source_result':2**32-1,'preserved_fields':[]},
        'private_frame':{'low':private['low'],'high':private['high']},
        'correspondence':{'input_memory':'current-physical-bytes-with-aliases','views':'complete-live-reference-view-context',
            'post_memory':'current-public-bytes-outside-private-frame','observations':'ordered-paired-calls-and-current-bytes',
            'return_target':'incoming-return-word','progress':'finite-conditional-on-returning-services'},
        'runtime_assumptions':{'status':'unverified','requirements':runtime},
        'assurance':{'authorizing':False,'activation_authorized':False,'whole_component_complete':False}}
    digest=canonical_sha256_v3(facts)
    return facts, {'rule':RULE,'status':'requires-recheck' if missing else 'compatible',
        'required_normal_frame':required,'available_normal_frame':available,'missing_guarantees':missing,
        'provided_contract_sha256':summary['contract_sha256'],'consumed_contract_sha256':digest}


def check_supplier_service(facts, caller_intent, service_id):
    """Check the entire consumed value surface, including types and view extents.

This supplements the caller's supported context rule; signature compatibility
alone never qualifies operation effects, lifecycle, runtime or native activation.
"""
    supplier=ComponentInterfaceIntentV1.parse(facts['interface_intent'])
    service,=[v for v in caller_intent.to_payload()['services'] if v['id']==service_id]
    actual=caller_intent.schema.signature_index[service['signature_id']].to_payload()
    expected=facts['signature']
    require(not service['effect_ids'] and actual==expected, 'consumer service value contract differs from supplier')
    function=expected['function_type_id']
    require(caller_intent.schema.type_index[function].to_payload()==supplier.schema.type_index[function].to_payload(),
            'consumer service function type differs from supplier')
    for value in expected['parameters']+expected['results']:
        identity=value['type_id']
        require(caller_intent.schema.type_index[identity].to_payload()==supplier.schema.type_index[identity].to_payload(),
                'consumer service type differs from supplier')
    # The supported surface is byte views and an unsigned scalar. Checking only
    # pointer type IDs would miss a changed pointee or width.
    for identity,body in [('bytes',{'id':'bytes','kind':'pointer','pointee_type_id':'u8','qualifiers':[]}),
                          ('u8',{'id':'u8','kind':'integer','signed':False,'width_bits':8}),
                          ('u32',{'id':'u32','kind':'integer','signed':False,'width_bits':32})]:
        require(caller_intent.schema.type_index[identity].to_payload()==body
                and supplier.schema.type_index[identity].to_payload()==body, 'unsupported supplier scalar/view type')
    for parameter in expected['parameters']:
        if parameter['id'] in facts['native_projection']['image_views'] and parameter['extent']['kind']=='fixed':
            require(parameter['extent']['bytes']==facts['native_projection']['image_views'][parameter['id']]['extent'],
                    'native view extent differs from the portable contract')
