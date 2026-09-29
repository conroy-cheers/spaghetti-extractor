"""Shared service authoring binds contracts and checks real generated C traces."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5,render_component_c_skeleton_v5
from spaghetti_extractor.components.interface_package_v5 import compile_component_interface_v5
from spaghetti_extractor.components.service_authoring import OperationDefinition,ServiceDefinition,component_interface,service_catalog,service_types,checked_service_catalog,services_from_interface,service_resource_roles,value
from spaghetti_extractor.components.service_c import CTransport,render_service_bridges,render_operation_bridge
from spaghetti_extractor.components.comparison_services import service_observations

TESTKIT={'fixtures':('compiler',)}
TYPES=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',width_bits=32,signed=False)]


def definition(**changes):
    fields=dict(identity='fixture.increment',types=TYPES,parameters=[('input','u32')],result='u32',resources=[],
        effects=['fixture.scalar-result'],outcomes=['zero','nonzero'],unobserved=['arbitrary native semantics'])
    fields.update(changes)
    return ServiceDefinition.create(**fields)


class ServiceAuthoringTests(unittest.TestCase):
    def test_untraced_service_keeps_outcome_partition_diagnostics(self):
        from spaghetti_extractor.components.service_c import materialize_service_bridge
        service=definition()
        services={'increment':service}
        interface=component_interface(component_id='consumer',types=TYPES,
            parameters=[('input','u32')],result='u32',services=services)
        plan=dict(operation_symbols={'run':'lifted'},service_catalog=service_catalog(services).to_payload(),
            service_bridge=dict(native_symbol='entry',transports={},adapters={
                'increment':dict(symbol='native_increment',kind='portable',outcomes={'zero':'is_zero','nonzero':'is_nonzero'})}))
        bridge,coverage=materialize_service_bridge(plan,interface,trace_services=False)
        self.assertIn('outcome-partition',coverage['increment']['generated'])
        self.assertIn('service-call-return-protocol',coverage['increment']['unobserved'])
        with self.assertRaisesRegex(ValueError,'boolean'):
            materialize_service_bridge(plan,interface,trace_services='false')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,text in render_component_c_headers_v5(compile_component_interface_v5(interface),{'run':'lifted'}).items():
                (root/name).write_text(text)
            (root/'main.c').write_text('#include "portable-component-implementation.h"\n'
                'uint32_t native_increment(uint32_t value) { return value+1; }\n'
                'int is_zero(uint32_t value) { (void)value; return 1; }\n'
                'int is_nonzero(uint32_t value) { (void)value; return 1; }\n'+bridge+
                'uint32_t lifted(spx_consumer_context_v5 *c,uint32_t input) { return c->services->increment(NULL,input); }\n'
                'int main(void) { return (int)entry(0); }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',str(root/'main.c'),
                '-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([str(root/'run')],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,78)
            self.assertEqual(run.stderr,'service outcome predicates are not exclusive and total\n')

    def test_named_operations_share_state_with_explicit_service_selections(self):
        from spaghetti_extractor.components.service_c import materialize_service_bridge
        services={'increment':definition(outcomes=['return'])}
        operations={
            'add':OperationDefinition([('input','u32')],'u32',allowed_services=['increment']),
            'read':OperationDefinition([],'u32'),
            'reset':OperationDefinition([],'unit'),
        }
        arguments=dict(component_id='counter',types=[TYPES[0]],services=services,
            operations=operations,state=[dict(value=value('total','u32'),initial=None)])
        interface=component_interface(**arguments)
        self.assertEqual(interface.to_payload(),component_interface(**{**arguments,'types':TYPES}).to_payload())
        self.assertEqual({row['id']:row['allowed_service_ids'] for row in interface.operations},
                         {'add':['increment'],'read':[],'reset':[]})
        checked_service_catalog(service_catalog(services).to_payload(),interface)
        with self.assertRaisesRegex(ValueError,'unique available services'):
            component_interface(**{**arguments,'operations':{'bad':OperationDefinition([],'unit',['absent'])}})
        with self.assertRaisesRegex(ValueError,'single run signature'):
            component_interface(**arguments,parameters=[],result='unit')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            symbols={name:'counter_'+name for name in operations}
            for name,contents in render_component_c_headers_v5(compile_component_interface_v5(interface),symbols).items():
                (root/name).write_text(contents)
            catalog=service_catalog(services).to_payload()
            bindings,coverage=materialize_service_bridge(dict(operation_symbols=symbols,service_catalog=catalog,
                service_bridge=dict(native_symbol=None,transports={},adapters={
                    'increment':dict(symbol='increment',kind='portable',context=True,outcomes={'return':None})})),interface)
            self.assertIn('context-state-and-lifetime',coverage['increment']['adapter_owned'])
            with self.assertRaisesRegex(ValueError,'native_symbol=None'):
                materialize_service_bridge(dict(operation_symbols=symbols,service_catalog=catalog,
                    service_bridge=dict(native_symbol='entry',transports={},adapters={
                        'increment':dict(symbol='increment',kind='portable',context=True,outcomes={'return':None})})),interface)
            (root/'main.c').write_text('#include "portable-component-implementation.h"\n'
                'static uint32_t increment(void *context,uint32_t input) { return input+*(uint32_t *)context; }\n'+bindings+
                'uint32_t counter_add(spx_counter_context_v5 *c,uint32_t input) { '
                'c->state.total+=c->services->increment(c->services->context,input); return c->state.total; }\n'
                'uint32_t counter_read(spx_counter_context_v5 *c) { return c->state.total; }\n'
                'void counter_reset(spx_counter_context_v5 *c) { c->state.total=0; }\n'
                'int main(void) { uint32_t amount=1; spx_counter_services_v5 services=spx_counter_bind_services(&amount); '
                'spx_counter_context_v5 first={.services=&services},second={.services=&services}; '
                'spx_counter_services_begin(); '
                'if(counter_add(&first,4)!=5 || counter_add(&first,1)!=7 || counter_read(&second)!=0) return 1; '
                'counter_reset(&first); spx_counter_services_end(); return counter_read(&first)!=0; }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',str(root/'main.c'),
                '-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([str(root/'run')],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            trace=root/'trace';trace.write_text(run.stderr)
            observations=service_observations(dict(component_id='counter',service_catalog=catalog),{'source':trace})
            self.assertEqual(observations['status'],'satisfied',observations)
            self.assertEqual(observations['coverage']['fixture.increment']['calls'],2)
            from spaghetti_extractor.operator.comparison_participation import comparison_participation
            result=dict(component_id='counter',target_id='fixture',status='match',receipt_sha256='0'*64,case_selection=None,
                cases=[dict(id='sequence',arguments=[],status='match',resources=dict(status='satisfied',services=observations))])
            plan=dict(component_id='counter',service_catalog=catalog)
            view=comparison_participation(result,plan,component='counter',output=root)
            # One adapter scope encloses several operations; do not report it
            # as a count of component invocations or covered branches.
            self.assertEqual(view['cases'][0]['service_scope'],dict(status='observed',starts=1))
            plan['dependencies']=[dict(id='neighbor',service_catalog=catalog)]
            view=comparison_participation(result,plan,component='counter',output=root)
            self.assertEqual(view['catalog_shared_with'],['neighbor'])
            self.assertEqual(view['cases'][0]['service_scope']['status'],'shared')
            trace.write_text(''.join(run.stderr.splitlines(keepends=True)[:-1]))
            result['cases'][0]['resources']['services']=service_observations(plan,{'source':trace})
            view=comparison_participation(result,plan,component='counter',output=root)
            self.assertEqual(view['cases'][0]['service_scope'],dict(status='incomplete',starts=None))

    def test_reuse_from_saved_interface_preserves_full_contract_and_selects_local_names(self):
        types=[*TYPES,dict(id='block',kind='opaque',nominal_id='fixture.block')]
        options=dict(identity='fixture.replace',types=types,parameters=[('old','block')],result='block',
            nullable_result=True,outcomes=['return'],nonlocal_outcomes=['nomem'],
            resources=[dict(root=root,value=value,fields=[],transition=transition,kind='block',domain='fixture')
                for root,value,transition in [('parameter','old','consume'),('result','result','produce')]])
        replace=definition(**options)
        services={'replace':replace,'increment':definition()}
        previous=component_interface(component_id='previous',types=types,parameters=[],result='unit',services=services)
        catalog=service_catalog(services).to_payload()
        selected=services_from_interface(previous,catalog,names=['replace'])
        self.assertEqual(list(selected),['replace'])
        self.assertEqual(selected['replace'],replace)
        new=component_interface(component_id='new',parameters=[('old','block')],result='block',
            services=selected,nullable_result=True)
        checked_service_catalog(service_catalog(selected).to_payload(),new)
        self.assertEqual(new.services[0]['interaction_contract_id'],replace.binding_id)
        self.assertEqual({t.identity for t in new.schema.types if t.kind!='function'},{'block'})
        changed=definition(**options,effects=['fixture.changed'])
        aliases={'replace':replace,'replace_again':replace}
        self.assertEqual(service_catalog(aliases).to_payload(),service_catalog({'replace':replace}).to_payload())
        aliased_interface=component_interface(component_id='aliased',parameters=[],result='unit',
            types=[dict(id='unit',kind='void')],services=aliases)
        checked_service_catalog(service_catalog(aliases).to_payload(),aliased_interface)
        with self.assertRaisesRegex(ValueError,'service contract differs.*replace.*replace_again'):
            service_catalog({'replace':replace,'replace_again':changed})
        with self.assertRaisesRegex(ValueError,'bind exactly'):
            services_from_interface(previous,service_catalog({**services,'replace':changed}),names=['replace'])
        with self.assertRaisesRegex(ValueError,'unknown interface services: absent'):
            services_from_interface(previous,catalog,names=['absent'])

    def test_void_service_compiles_and_checks_nonlocal_delivery_without_dummy_values(self):
        from spaghetti_extractor.components.comparison_service_runtime import runtime_header,runtime_source
        d=definition(parameters=[],result='unit',outcomes=['return'],nonlocal_outcomes=['nomem'])
        self.assertEqual(d.contract.type_parameters,())
        self.assertEqual(d.contract.ports,())
        services={'stop':d}
        interface=component_interface(component_id='consumer',types=TYPES,parameters=[],result='unit',services=services)
        catalog=service_catalog(services).to_payload()
        checked_service_catalog(catalog,interface)
        wrappers,_=render_service_bridges(services=services,
            adapters={'stop':dict(symbol='native_stop',kind='native',outcomes={'return':None})},transports={})
        bridge=render_operation_bridge(interface=interface,operation_symbol='lifted',native_symbol='entry',
            services=services,transports={})
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,contents in render_component_c_headers_v5(compile_component_interface_v5(interface),{'run':'lifted'}).items():
                (root/name).write_text(contents)
            (root/'comparison-services.h').write_text(runtime_header(True))
            (root/'runtime.c').write_text(runtime_source(['nomem']))
            (root/'main.c').write_text('#include "portable-component-implementation.h"\n'
                '#include "comparison-services.h"\n#include <setjmp.h>\n'
                'static jmp_buf escape;\nstatic void native_stop(void) { longjmp(escape,1); }\n'+wrappers+
                'void lifted(spx_consumer_context_v5 *c) { c->services->stop(c->services->context); }\n'+bridge+
                'int main(void) { uint32_t h=spx_service_handler_begin(); '
                'if(!setjmp(escape)) { entry(); return 2; } '
                'spx_service_handler_catch(h,"nomem"); spx_service_handler_end(h); return 0; }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',
                str(root/'main.c'),str(root/'runtime.c'),'-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            stream=root/'trace';stream.write_text(run.stderr)
            report=service_observations(dict(component_id='consumer',service_catalog=catalog),{'source':stream})
            self.assertEqual(report['status'],'satisfied',report)
            self.assertEqual(report['coverage']['fixture.increment']['calls'],1)
            self.assertEqual([e['outcome'] for e in report['events'] if e['event']=='catch'],['nomem'])
            stream.write_text(run.stderr.replace('"outcome":"nomem"','"outcome":"undeclared"'))
            self.assertEqual(service_observations(dict(component_id='consumer',service_catalog=catalog),
                {'source':stream})['status'],'incomplete')

    def test_empty_value_boundary_still_binds_contract_and_rejects_missing_ports(self):
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
        from spaghetti_extractor.components.interaction_contract import InteractionContractV1
        d=definition(parameters=[],result='unit',outcomes=['return'])
        changed=definition(parameters=[],result='unit',outcomes=['return'],effects=['fixture.changed'])
        self.assertEqual(d.schema.to_payload(),changed.schema.to_payload())
        self.assertNotEqual(d.binding_id,changed.binding_id)
        interface=component_interface(component_id='consumer',types=TYPES,parameters=[],result='unit',services={'stop':d})
        with self.assertRaisesRegex(ValueError,'bind exactly'):
            checked_service_catalog(service_catalog({'stop':changed}).to_payload(),interface)
        payload=d.contract.to_payload()
        for mutation,diagnostic in [(dict(ports=[dict(id='missing',direction='input',type_parameter='u32')]),'unknown type parameter'),
                (dict(requires=[dict(op='port',direction='input',id='missing')]),'unknown port')]:
            edited={**payload,**mutation}
            edited['contract_sha256']=canonical_sha256_v3({k:v for k,v in edited.items() if k!='contract_sha256'})
            with self.assertRaisesRegex(ValueError,diagnostic):InteractionContractV1.parse(edited)

    def test_nullable_objects_are_bound_and_preserved_through_authoring(self):
        types=[dict(id='block',kind='opaque',nominal_id='fixture.block'),*TYPES]
        options=dict(types=types,parameters=[('old','block')],result='block')
        required=definition(**options)
        optional=definition(**options,nullable_parameters=['old'],nullable_result=True)
        self.assertNotEqual(required.binding_id,optional.binding_id)
        services={'resize':optional}
        interface=component_interface(component_id='grow',services=services,
            nullable_parameters=['old'],nullable_result=True,**options)
        checked_service_catalog(service_catalog(services).to_payload(),interface)
        for sig in interface.schema.signatures:
            self.assertTrue(sig.parameters[0].nullable)
            self.assertTrue(sig.results[0].nullable)
        for overrides in (dict(nullable_parameters=['missing']),dict(nullable_parameters=['old','old']),
                          dict(nullable_result='yes')):
            with self.assertRaisesRegex(ValueError,'nullable'):
                definition(**options,**overrides)
        with self.assertRaisesRegex(ValueError,'opaque'):
            definition(nullable_parameters=['input'])

    def test_unreached_supplier_requires_completed_boundary_and_reports_zero_coverage(self):
        catalog=service_catalog({'increment':definition()}).to_payload()
        plan=dict(component_id='consumer',dependencies=[dict(id='supplier',service_catalog=catalog)])
        begin='SPX_SERVICE_HANDLER {"handler":1,"event":"begin","outcome":""}\n'
        end='SPX_SERVICE_HANDLER {"handler":1,"event":"end","outcome":""}\n'
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'trace'
            for trace in ('',begin,end,begin+end+end):
                path.write_text(trace)
                self.assertEqual(service_observations(plan,{'source':path})['status'],'incomplete')
            path.write_text(begin+end)
            report=service_observations(plan,{'source':path})
            self.assertEqual(report['status'],'satisfied')
            self.assertEqual(report['coverage']['fixture.increment']['calls'],0)
            self.assertTrue(any('No selected service was exercised' in gap for gap in report['unobserved']))
            # A root with a catalog cannot substitute handlers alone for all
            # of its generated instrumentation.
            self.assertEqual(service_observations({**plan,'service_catalog':catalog},
                {'source':path})['status'],'incomplete')
            digest=catalog['catalog_sha256']
            path.write_text('SPX_SERVICE_SCOPE '+json.dumps(dict(catalog_sha256=digest,event='begin'))+'\n')
            self.assertEqual(service_observations(plan,{'source':path})['status'],'incomplete')

    def test_same_signature_changed_effect_or_outcome_changes_contract_binding(self):
        original=definition()
        for edited in [definition(effects=['fixture.write-global']),definition(outcomes=['return'])]:
            self.assertEqual(original.schema.to_payload(),edited.schema.to_payload())
            self.assertNotEqual(original.binding_id,edited.binding_id)
        interface=component_interface(component_id='consumer',types=TYPES,parameters=[('input','u32')],result='u32',services={'increment':original})
        checked_service_catalog(service_catalog({'increment':original}).to_payload(),interface)
        with self.assertRaisesRegex(ValueError,'bind exactly'):
            checked_service_catalog(service_catalog({'increment':definition(effects=['fixture.write-global'])}).to_payload(),interface)

    def test_unrelated_type_definition_is_not_a_service_dependency(self):
        unrelated=dict(id='unused',kind='integer',width_bits=16,signed=True)
        self.assertEqual(definition().binding_id,definition(types=TYPES+[unrelated]).binding_id)

    def test_shared_nested_types_compose_once_and_name_conflicting_services(self):
        types=[TYPES[1],
            dict(id='inner',kind='record',nominal_id='fixture.inner',fields=[
                dict(id='count',type_id='u32',bit_width=None)]),
            dict(id='outer',kind='record',nominal_id='fixture.outer',fields=[
                dict(id='details',type_id='inner',bit_width=None)])]
        first=definition(identity='fixture.first',types=types,parameters=[('input','outer')])
        second=definition(identity='fixture.second',types=types,parameters=[('input','outer')])
        services={'first':first,'second':second}
        inputs=dict(component_id='nested',parameters=[('input','outer')],result='u32',services=services)
        inherited=component_interface(**inputs)
        self.assertEqual(inherited.to_payload(),component_interface(**inputs,types=types).to_payload())
        self.assertEqual({row['id'] for row in service_types(services)},{'inner','outer','u32'})
        checked_service_catalog(service_catalog(services).to_payload(),inherited)
        changed=copy.deepcopy(types);changed[1]['nominal_id']='fixture.different-inner'
        incompatible=definition(identity='fixture.second',types=changed,parameters=[('input','outer')])
        with self.assertRaisesRegex(ValueError,r'type inner between service first.*service second'):
            component_interface(**{**inputs,'services':{'first':first,'second':incompatible}})
        with self.assertRaisesRegex(ValueError,'duplicate identities'):
            component_interface(**inputs,types=[types[0],types[0]])

    def test_type_layout_and_unsupported_protocol_fail_before_adapter_generation(self):
        with self.assertRaisesRegex(ValueError,'synchronous-return'):
            definition(protocol='async-completion')
        wrong=copy.deepcopy(TYPES);wrong[1]['signed']=True
        with self.assertRaisesRegex(ValueError,'schema differs'):
            component_interface(component_id='consumer',types=wrong,parameters=[('input','u32')],result='u32',services={'increment':definition()})
        with self.assertRaisesRegex(ValueError,'outcomes'):
            definition(outcomes=[])

    def test_native_resource_transport_requires_explicit_supported_roles(self):
        d=definition();transport={'u32':CTransport('uint32_t','take','borrow','pack')}
        with self.assertRaisesRegex(ValueError,'explicit consume'):
            render_service_bridges(services={'increment':d},adapters={'increment':dict(symbol='native',kind='native',outcomes={'zero':'is_zero','nonzero':'is_nonzero'})},transports=transport)
        role=dict(root='parameter',value='input',fields=[],transition='consume',kind='token',domain='fixture')
        produced=dict(root='result',value='result',fields=[],transition='produce',kind='token',domain='fixture')
        d=definition(resources=[role,produced])
        rendered,coverage=render_service_bridges(services={'increment':d},adapters={'increment':dict(symbol='native',kind='native',outcomes={'zero':'is_zero','nonzero':'is_nonzero'})},transports=transport)
        self.assertIn('pack(native(take(input)))',rendered)
        self.assertIn('whole-value-transport',coverage['increment']['generated'])
        with self.assertRaisesRegex(ValueError,'repeated'):
            definition(resources=[role,role])

    def test_resource_shorthand_preserves_mixed_roles_and_contract_identity(self):
        types=[*TYPES,dict(id='token',kind='integer',width_bits=32,signed=False)]
        parameters=[('key','token'),('owner','token'),('index','u32')]
        explicit=[dict(root=root,value=name,fields=[],transition=transition,kind='token',domain='fixture')
            for root,name,transition in [('parameter','key','borrow_shared'),('parameter','owner','consume'),
                                         ('result','result','produce')]]
        short=service_resource_roles(parameters,consumes=['owner'],borrows=['key'],produces=True,
            resource_kind='token',provider_domain='fixture')
        before=definition(types=types,parameters=parameters,result='token',resources=explicit)
        after=definition(types=types,parameters=parameters,result='token',resources=short)
        self.assertEqual(after,before)
        self.assertEqual(after.binding_id,before.binding_id)
        adapters={'increment':dict(symbol='native',kind='native',outcomes={'zero':'is_zero','nonzero':'is_nonzero'})}
        transports={'token':CTransport('uint32_t','take','borrow','pack')}
        # The unclassified scalar remains direct C, not an inferred resource.
        rendered,_=render_service_bridges(services={'increment':after},adapters=adapters,transports=transports)
        self.assertIn('pack(native(borrow(key), take(owner), index))',rendered)
        self.assertEqual(render_service_bridges(services={'increment':after},adapters=adapters,transports=transports),
                         render_service_bridges(services={'increment':before},adapters=adapters,transports=transports))
        with self.assertRaisesRegex(ValueError,'repeated: key'):
            service_resource_roles(parameters,consumes=['key'],borrows=['key'],resource_kind='token',provider_domain='fixture')
        with self.assertRaisesRegex(ValueError,'absent: missing'):
            service_resource_roles(parameters,consumes=['missing'],resource_kind='token',provider_domain='fixture')

    def test_adapter_can_receive_the_service_context(self):
        wrappers,_=render_service_bridges(services={'increment':definition()},
            adapters={'increment':dict(symbol='native',kind='native',context=True,outcomes={'zero':'is_zero','nonzero':'is_nonzero'})},transports={})
        self.assertIn('native(e, input)',wrappers)

    def test_generated_locals_do_not_shadow_callback_inputs(self):
        types=[*TYPES,dict(id='callback',kind='opaque',nominal_id='fixture.callback')]
        services={'invoke':definition(identity='fixture.invoke',types=types,
            parameters=[('e','callback'),('spx_result','u32'),('outcome_0','u32')])}
        interface=component_interface(component_id='notify',types=types,
            parameters=[('context','callback'),('context_2','u32'),('s','u32')],result='u32',services=services)
        bundle=compile_component_interface_v5(interface)
        wrappers,_=render_service_bridges(services=services,adapters={'invoke':dict(
            symbol='invoke_callback',kind='portable',context=True,outcomes={'zero':'is_zero','nonzero':'is_nonzero'})},transports={})
        entry=render_operation_bridge(interface=interface,operation_symbol='lifted',native_symbol='notify',
            services=services,transports={})
        skeleton=render_component_c_skeleton_v5(bundle,{'run':'lifted'})
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,contents in render_component_c_headers_v5(bundle,{'run':'lifted'}).items():
                (root/name).write_text(contents)
            # Author directly in the generated skeleton; its input names stay
            # intact while the implicit component context chooses a free name.
            implementation=skeleton.replace('    #error "Implement operation run using the declared boundary"',
                '    return context_3->services->invoke(context_3->services->context, context, context_2, s);')
            (root/'lifted.c').write_text(implementation)
            (root/'main.c').write_text('''#include "portable-component-implementation.h"
struct spx_opaque_callback_v5 {
  uint32_t value, calls;
  uint32_t (*invoke)(struct spx_opaque_callback_v5 *, uint32_t);
};
static uint32_t invoke_callback(void *metadata, struct spx_opaque_callback_v5 *e, uint32_t x, uint32_t y) {
  if (metadata != 0) return 0;
  return e->invoke(e, x+y);
}
static int is_zero(uint32_t value) { return value==0; }
static int is_nonzero(uint32_t value) { return value!=0; }
'''+wrappers+entry+'''
static uint32_t update(struct spx_opaque_callback_v5 *context, uint32_t amount) {
  ++context->calls; context->value+=amount; return context->value;
}
int main(void) {
  struct spx_opaque_callback_v5 first={3,0,update}, second={10,0,update};
  struct spx_opaque_callback_v5 *alias=&first;
  if (notify(&first,2,4)!=9 || alias->value!=9 || first.calls!=1) return 1;
  if (notify(&second,1,5)!=16 || second.value!=16 || second.calls!=1) return 2;
  if (notify(alias,1,2)!=12 || first.calls!=2) return 3;
  return 0;
}
''')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',
                str(root/'main.c'),str(root/'lifted.c'),str(root/'component-conformance.c'),
                '-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)
            (root/'trace').write_text(run.stderr)
            report=service_observations(dict(component_id='notify',service_catalog=service_catalog(services).to_payload()),
                {'source':root/'trace'})
            self.assertEqual(report['status'],'satisfied',report)
            self.assertEqual(report['coverage']['fixture.invoke']['calls'],3)

    def test_declared_adapter_links_a_separate_body_and_forwards_context(self):
        services={'increment':definition(outcomes=['return'])}
        adapters={'increment':dict(symbol='external_increment',kind='portable',context=True,
            declare=True,outcomes={'return':None})}
        wrappers,_=render_service_bridges(services=services,adapters=adapters,transports={})
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'main.c').write_text('#include <stdint.h>\n'+wrappers+
                'int main(void) { uint32_t amount=9; return service_increment(&amount,3)!=12; }\n')
            (root/'adapter.c').write_text('#include <stdint.h>\n'
                'uint32_t external_increment(void *context,uint32_t value) { return value+*(uint32_t *)context; }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',
                str(root/'main.c'),str(root/'adapter.c'),'-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
            self.assertEqual(run.returncode,0,run.stderr)

    def test_service_free_operation_bridge_needs_no_fictitious_catalog(self):
        from spaghetti_extractor.components.service_c import materialize_service_bridge
        types=[dict(id='u32',kind='integer',width_bits=32,signed=False)]
        intent=component_interface(component_id='leaf',types=types,
            parameters=[('input','u32')],result='u32',services={})
        rendered,_=materialize_service_bridge(dict(service_bridge=dict(adapters={},transports={},native_symbol='entry'),
            operation_symbols={'run':'lifted'}),intent)
        self.assertNotIn('SPX_SERVICE_SCOPE',rendered)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,contents in render_component_c_headers_v5(compile_component_interface_v5(intent),{'run':'lifted'}).items():
                (root/name).write_text(contents)
            (root/'main.c').write_text('#include "portable-component-implementation.h"\n'
                'uint32_t lifted(spx_leaf_context_v5 *c,uint32_t input) { (void)c; return input+1; }\n'
                +rendered+'\nint main(void) { return entry(6)==7 ? 0 : 1; }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',str(root/'main.c'),'-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            result=subprocess.run([str(root/'run')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stderr,'')

    def test_opaque_c_adapter_preserves_mutable_aliases_without_claiming_a_heap_rule(self):
        types = [dict(id='cell',kind='opaque',nominal_id='fixture.cell'),
                 dict(id='unit',kind='void')]
        d = ServiceDefinition.create(identity='fixture.cell-update',types=types,
            parameters=[('left','cell'),('right','cell')],result='unit',resources=[],
            effects=['fixture.cell-write'],outcomes=['return'],
            unobserved=['pointee applicability and lifetime are adapter premises'])
        services={'update':d}
        intent=component_interface(component_id='cell-user',
            parameters=[('left','cell'),('right','cell')],result='unit',services=services)
        checked_service_catalog(service_catalog(services).to_payload(),intent)
        wrappers,coverage=render_service_bridges(services=services,
            adapters={'update':dict(symbol='mutate',kind='portable',outcomes={'return':None})},transports={})
        self.assertIn('opaque-object-contents-aliases-and-lifetime',coverage['update']['adapter_owned'])
        self.assertEqual(d.contract.type_parameters[0].kind,'reference')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,contents in render_component_c_headers_v5(compile_component_interface_v5(intent),{'run':'lifted'}).items():
                (root/name).write_text(contents)
            (root/'main.c').write_text('#include "portable-component-implementation.h"\n'
                'struct spx_opaque_cell_v5 { unsigned value; };\n'
                'static void mutate(struct spx_opaque_cell_v5 *left,struct spx_opaque_cell_v5 *right) '
                '{ left->value += 2; right->value *= 3; }\n'+wrappers+
                'int main(void) { struct spx_opaque_cell_v5 cell={5}, other={7}; '
                'service_update(0,&cell,&cell); if(cell.value!=21) return 1; '
                'service_update(0,&cell,&other); return cell.value==23 && other.value==21 ? 0 : 2; }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',str(root/'main.c'),'-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            result=subprocess.run([str(root/'run')],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def execute(self,body,*,wrapper_change=None):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);d=definition();services={'increment':d}
            i=component_interface(component_id='consumer',types=TYPES,parameters=[('input','u32')],result='u32',services=services)
            for name,contents in render_component_c_headers_v5(compile_component_interface_v5(i),{'run':'lifted'}).items():
                (root/name).write_text(contents)
            wrappers,_=render_service_bridges(services=services,adapters={'increment':dict(symbol='native',kind='native',outcomes={'zero':'is_zero','nonzero':'is_nonzero'})},transports={})
            bridge=render_operation_bridge(interface=i,operation_symbol='lifted',native_symbol='entry',services=services,
                transports={})
            if wrapper_change:wrappers=wrapper_change(wrappers)
            (root/'main.c').write_text('#include "portable-component-implementation.h"\n'
                +body+'\n'+wrappers+
                'uint32_t lifted(spx_consumer_context_v5 *c,uint32_t input) { return c->services->increment(c->services->context,input); }\n'+bridge+
                'int main(void) { return entry(0)==1 ? 0 : 2; }\n')
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',str(root/'main.c'),'-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
            stream=root/'stderr';stream.write_text(run.stderr)
            report=service_observations(dict(component_id='consumer',service_catalog=service_catalog(services).to_payload()),{'source':stream})
            return run,report

    def test_generated_c_checks_partition_and_reports_bound_call_and_return(self):
        run,report=self.execute('static uint32_t native(uint32_t x) { return x+1; }\n'
            'static int is_zero(uint32_t x) { return x==0; }\nstatic int is_nonzero(uint32_t x) { return x!=0; }')
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'satisfied')
        self.assertEqual([e['event'] for e in report['events']],['begin','call','return','end'])
        self.assertEqual(report['events'][2]['outcome'],'nonzero')
        self.assertEqual(report['coverage']['fixture.increment']['calls'],1)

    def test_overlapping_outcomes_fail_and_cannot_satisfy_trace(self):
        run,report=self.execute('static uint32_t native(uint32_t x) { return x+1; }\n'
            'static int is_zero(uint32_t x) { (void)x; return 1; }\nstatic int is_nonzero(uint32_t x) { (void)x; return 1; }')
        self.assertEqual(run.returncode,78)
        self.assertIn('not exclusive and total',run.stderr)
        self.assertEqual(report['status'],'incomplete')

    def test_composed_consumer_may_call_only_a_selected_supplier(self):
        caller=definition();supplier=definition(identity='fixture.other')
        a=service_catalog({'increment':caller}).to_payload();b=service_catalog({'other':supplier}).to_payload()
        plan=dict(component_id='consumer',service_catalog=a,dependencies=[dict(id='other',service_catalog=b)])
        with tempfile.TemporaryDirectory() as temporary:
            stream=Path(temporary)/'stderr'
            stream.write_text(''.join('SPX_SERVICE_SCOPE '+json.dumps(dict(catalog_sha256=b['catalog_sha256'],event=event))+'\n' for event in ['begin','end']))
            report=service_observations(plan,{'source':stream})
            self.assertEqual(report['status'],'satisfied')
            self.assertEqual(report['coverage']['fixture.increment']['calls'],0)

    def test_unknown_outcome_missing_and_duplicate_event_fields_fail_closed(self):
        d=definition();catalog=service_catalog({'increment':d}).to_payload()
        with tempfile.TemporaryDirectory() as temporary:
            stream=Path(temporary)/'stderr';plan=dict(component_id='consumer',service_catalog=catalog)
            scope='SPX_SERVICE_SCOPE '+json.dumps(dict(catalog_sha256=catalog['catalog_sha256'],event='begin'))+'\n'
            call='SPX_SERVICE '+json.dumps(dict(contract_sha256=d.contract.contract_sha256,event='call',outcome=''))+'\n'
            for text,needle in [('', 'absent'),(scope+call,'incomplete'),
                (scope+call+'SPX_SERVICE '+json.dumps(dict(contract_sha256=d.contract.contract_sha256,event='return',outcome='invented')),'undeclared'),
                (scope+'SPX_SERVICE {"event":"call","event":"return"}','duplicate')]:
                stream.write_text(text);report=service_observations(plan,{'source':stream})
                self.assertEqual(report['status'],'incomplete')
                self.assertIn(needle,report['diagnostics'][0]['detail'])

    def test_catalog_reuse_is_content_bound_and_never_caches_observation_verdicts(self):
        from spaghetti_extractor.components.comparison_services import _catalog_index,InteractionContractCatalogV1
        _catalog_index.cache_clear()
        catalog=service_catalog({'increment':definition()}).to_payload()
        with tempfile.TemporaryDirectory() as temporary:
            stream=Path(temporary)/'stderr';plan=dict(component_id='consumer',service_catalog=catalog)
            stream.write_text(''.join('SPX_SERVICE_SCOPE '+json.dumps(dict(catalog_sha256=catalog['catalog_sha256'],event=e))+'\n' for e in ['begin','end']))
            with patch.object(InteractionContractCatalogV1,'parse',wraps=InteractionContractCatalogV1.parse) as parse:
                first=service_observations(plan,{'source':stream})
                self.assertEqual(first['status'],'satisfied')
                first['coverage'].clear()  # Returned mutable reports never poison cached facts.
                self.assertTrue(service_observations(plan,{'source':stream})['coverage'])
                self.assertEqual(parse.call_count,1)
                stream.write_text('')
                self.assertEqual(service_observations(plan,{'source':stream})['status'],'incomplete')
                self.assertEqual(parse.call_count,1)
                # Same outer claimed digest, changed contents: parse and reject.
                catalog['contracts'][0]['contract_sha256']='0'*64
                with self.assertRaises(ValueError):service_observations(plan,{'source':stream})
                self.assertEqual(parse.call_count,2)
