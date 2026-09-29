"""Executable resource observations preserve behavior and enforce selected premises."""
import json
import os
import subprocess
from unittest.mock import patch
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary import BoundaryLifecycleV1
from spaghetti_extractor.components.comparison_package import load_comparison_package
from spaghetti_extractor.components.comparison_resources import resource_applicability
from spaghetti_extractor.components.comparison_resources import checked_resource_checks
from spaghetti_extractor.components.resource_authoring import component_resource_checks,rebind_resource_checks
from spaghetti_extractor.components.comparison_run import load_comparison_result,comparison_result_identity
from spaghetti_extractor.util import sha256_file
from tests.unit.components import test_comparison as base
from tests.unit.candidate import test_experimental as experimental

TESTKIT = {'fixtures':('compiler',),'commands':('component check',),
           'resources':('tests/fixtures/jq-array-concat',)}


class ResourceContractShapeTests(unittest.TestCase):
    def authored(self, interface, **changes):
        options=dict(consumes=['owner'],produces=['result'],resource_kind='reference',
            provider_domain='fixture',service_id='transfer',interaction_contract_id='slice.resources',
            capacity=32,frame_capacity=16,instrumented_sides=['source'],unobserved=[])
        options.update(changes)
        return component_resource_checks(interface,**options)

    def test_authoring_retains_existing_lifecycle_identity(self):
        interface,checks=self.make(omitted=('start','scale'))
        bindings=checks['contracts'][0]['lifecycle']['bindings']
        for binding in bindings:binding['id']='saved.'+binding['path']['value_id']
        checks['contracts'][0]['lifecycle']=BoundaryLifecycleV1.create(schema=interface.schema,
            signature_id='operation.run',bindings=bindings).to_payload()
        authored=self.authored(interface,binding_ids={'parameter.owner':'saved.owner','result.result':'saved.result'})
        self.assertEqual(authored,checks)
        self.assertEqual(canonical_sha256_v3(authored),canonical_sha256_v3(checks))

    def test_authoring_rejects_missing_owned_values_before_preparation(self):
        interface,_=self.make(omitted=('start','scale'))
        for changes in (dict(consumes=[]),dict(produces=[])):
            with self.subTest(changes=changes),self.assertRaisesRegex(ValueError,'consume parameters and produce results'):
                self.authored(interface,**changes)
        with self.assertRaisesRegex(ValueError,'bounded unsigned count'):
            self.authored(interface,nonlocal_allowances={'nomem':dict(max_untransferred=33,max_retained=0)})

    def test_rebind_keeps_resource_roles_and_limits_across_service_schema_changes(self):
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,component_interface
        previous,checks=self.make(omitted=('start','scale'))
        limits={'nomem':dict(max_untransferred=2,max_retained=1)}
        checks['contracts'][0]['nonlocal_allowances']=limits
        before=json.dumps(checks,sort_keys=True)
        types=[t.to_payload() for t in previous.schema.types if t.kind!='function']
        service=ServiceDefinition.create(identity='fixture.inspect',types=types,
            parameters=[('value','i32')],result='i32',resources=[],effects=['fixture.inspect'],
            outcomes=['return'],unobserved=['Executable adapter remains explicit.'])
        current=component_interface(component_id='slice',types=types,
            parameters=[('owner','object'),('start','i32'),('scale','f64')],result='object',services={'inspect':service})
        revised=rebind_resource_checks(checks,previous=previous,interface=current)
        self.assertEqual(revised,self.authored(current,nonlocal_allowances=limits))
        self.assertEqual(json.dumps(checks,sort_keys=True),before)
        self.assertNotEqual(revised['contracts'][0]['lifecycle']['lifecycle_sha256'],
            checks['contracts'][0]['lifecycle']['lifecycle_sha256'])
        with self.assertRaisesRegex(ValueError,'another schema'):
            checked_resource_checks(checks,current)

    def test_rebind_requires_review_of_changed_values_and_nested_representation(self):
        from spaghetti_extractor.components.service_authoring import component_interface
        def boundary(*, width=32, name='owner'):
            return component_interface(component_id='slice',parameters=[(name,'payload')],result='payload',services={},
                types=[dict(id='word',kind='integer',width_bits=width,signed=False),
                    dict(id='payload',kind='record',nominal_id='fixture.payload',
                        fields=[dict(id='count',type_id='word',bit_width=None)])])
        previous=boundary();checks=self.authored(previous)
        for current,diagnostic in [(boundary(width=64),'type word changed'),
                                   (boundary(name='other'),'input/result declarations changed')]:
            with self.subTest(diagnostic=diagnostic),self.assertRaisesRegex(ValueError,diagnostic):
                rebind_resource_checks(checks,previous=previous,interface=current)

    def make(self, *, omitted=(), borrowed=()):
        from spaghetti_extractor.components.service_authoring import component_interface
        types=[dict(id='object',kind='opaque',nominal_id='fixture.live-object'),
               dict(id='i32',kind='integer',width_bits=32,signed=True),
               dict(id='f64',kind='float',format='binary64',value_bits=64)]
        interface=component_interface(component_id='slice',types=types,
            parameters=[('owner','object'),('start','i32'),('scale','f64')],result='object',services={})
        bindings=[]
        for root,name,transition in [('parameter','owner','consume'),('parameter','start','consume'),
                                     ('parameter','scale','consume'),('result','result','produce')]:
            if name in omitted:continue
            bindings.append(dict(id=root+'.'+name,path=dict(root=root,value_id=name,fields=[]),
                transition='borrow_shared' if name in borrowed else transition,resource_kind='reference',
                provider_domain='fixture',service_id='transfer',interaction_contract_id='slice.resources',condition=None))
        lifecycle=BoundaryLifecycleV1.create(schema=interface.schema,signature_id='operation.run',bindings=bindings)
        checks=dict(capacity=32,frame_capacity=16,instrumented_sides=['source'],unobserved=[],contracts=[
            dict(operation_id='run',lifecycle=lifecycle.to_payload(),max_untransferred=0,max_retained=0)])
        return interface,checks

    def test_numeric_values_need_no_ownership_role(self):
        interface,checks=self.make(omitted=('start','scale'))
        self.assertEqual(checked_resource_checks(checks,interface),checks)
        # Previously explicit scalar tokens remain supported as declarations.
        interface,checks=self.make()
        self.assertEqual(checked_resource_checks(checks,interface),checks)

    def test_resource_inputs_and_results_cannot_be_omitted(self):
        for name in ('owner','result'):
            with self.subTest(name=name):
                interface,checks=self.make(omitted=('start','scale',name))
                with self.assertRaisesRegex(ValueError,'consume parameters and produce results'):
                    checked_resource_checks(checks,interface)

    def test_optional_numeric_binding_still_needs_a_supported_transition(self):
        interface,checks=self.make(borrowed=('start',))
        with self.assertRaisesRegex(ValueError,'consume parameters and produce results'):
            checked_resource_checks(checks,interface)

    def test_numeric_resource_handle_cannot_be_omitted(self):
        from types import SimpleNamespace
        from spaghetti_extractor.boundary import BoundarySchemaV1
        interface,checks=self.make(omitted=('start','scale'))
        signatures=[signature.to_payload() for signature in interface.schema.signatures]
        index=next(value for value in signatures[0]['parameters'] if value['id']=='start')
        index.update(interpretation='resource',resource_kind='handle',provider_domain='fixture')
        schema=BoundarySchemaV1.create(schema_id='scalar-handle',
            types=[t.to_payload() for t in interface.schema.types],signatures=signatures)
        rule=checks['contracts'][0]
        rule['lifecycle']=BoundaryLifecycleV1.create(schema=schema,signature_id='operation.run',
            bindings=rule['lifecycle']['bindings']).to_payload()
        with self.assertRaisesRegex(ValueError,'consume parameters and produce results'):
            checked_resource_checks(checks,SimpleNamespace(schema=schema,operations=interface.operations))


def resource_checks(interface, *, untransferred=0, retained=0, sides=None, capacity=32):
    operation=interface.operations[0]
    signature=interface.schema.signature_index[operation['signature_id']]
    bindings=[]
    for root,values,transition in [('parameter',signature.parameters,'consume'),('result',signature.results,'produce')]:
        for value in values:
            bindings.append({'id':root+'.'+value.identity,'path':{'root':root,'value_id':value.identity,'fields':[]},
                'transition':transition,'resource_kind':'reference','provider_domain':'fixture',
                'service_id':'fixture-transfer','interaction_contract_id':interface.component_id+'.resources','condition':None})
    lifecycle=BoundaryLifecycleV1.create(schema=interface.schema,signature_id=signature.identity,bindings=bindings)
    return {'capacity':capacity,'frame_capacity':16,'instrumented_sides':sides or ['source'],
        'unobserved':['native allocation internals'],
        'contracts':[{'operation_id':operation['id'],'lifecycle':lifecycle.to_payload(),
                      'max_untransferred':untransferred,'max_retained':retained}]}


class ResourceComparisonTests(unittest.TestCase):
    setUp=base.ComponentComparisonTests.setUp
    command=base.ComponentComparisonTests.command
    check=base.ComponentComparisonTests.check
    candidate=experimental.ExperimentalCandidateTests.candidate
    prepare=experimental.ExperimentalCandidateTests.prepare
    def policy(self):
        path=experimental.ExperimentalCandidateTests.policy(self)
        plan,_=load_comparison_package(self.package)
        policy=json.loads(path.read_text())
        policy['accepted_resource_checks']={plan['component_id']:canonical_sha256_v3(plan['resource_checks'])}
        path.write_text(json.dumps(policy))
        return path

    def install(self, body, **options):
        plan,interface=load_comparison_package(self.package)
        checks=resource_checks(interface,**options)
        digest=canonical_sha256_v3(checks['contracts'][0])
        driver=self.package/'adapters/driver.c'
        sides=checks['instrumented_sides']
        driver.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include "comparison-resources.h"\n'
            'int main(int argc, char **argv) { if (argc!=3) return 2; (void)argv;\n'
            + ('if (!strcmp(argv[1],"source")) {\n' if sides==['source'] else '{\n')
            + f'const char *contract="{digest}"; uint32_t frame=spx_resource_frame_enter(contract);\n'
            +body+'\nspx_resource_frame_leave(frame); }\nputs("{\\\"value\\\":7}"); return 0; }\n')
        plan['original']['files']['adapters/driver.c']=sha256_file(driver)
        plan['resource_checks']=checks
        (self.package/'comparison-plan.json').write_text(json.dumps(plan))

    def test_interface_revision_keeps_existing_resource_declarations(self):
        from spaghetti_extractor.boundary import BoundarySchemaV1
        from spaghetti_extractor.components.comparison_package import revise_comparison_package
        from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
        self.install('spx_resource_consume(spx_resource_acquire(42));')
        before,interface=load_comparison_package(self.package)
        schema=BoundarySchemaV1.create(schema_id=interface.schema.schema_id,
            types=[*[t.to_payload() for t in interface.schema.types],
                dict(id='unrelated',kind='integer',width_bits=32,signed=False)],
            signatures=[s.to_payload() for s in interface.schema.signatures])
        proposed=ComponentInterfaceIntentV1.create(component_id=interface.component_id,schema=schema,
            state=interface.state,operations=interface.operations,effects=interface.effects,services=interface.services,
            protocol_states=interface.protocol_states,initial_protocol_state=interface.initial_protocol_state)
        output=self.root/'revised'
        with patch('subprocess.run',side_effect=AssertionError('boundary revision must not run tools')):
            revise_comparison_package(package=self.package,output=output,interface=proposed)
        after,current=load_comparison_package(output)
        old=before['resource_checks'];new=after['resource_checks']
        self.assertEqual(new['contracts'][0]['lifecycle']['bindings'],old['contracts'][0]['lifecycle']['bindings'])
        self.assertEqual(new['contracts'][0]['lifecycle']['schema_sha256'],current.schema.schema_sha256)
        self.assertNotEqual(new['contracts'][0]['lifecycle']['lifecycle_sha256'],old['contracts'][0]['lifecycle']['lifecycle_sha256'])
        self.assertEqual(new['unobserved'],old['unobserved'])
        self.assertEqual(load_comparison_package(self.package)[0],before)
        self.assertFalse((output/'comparison-result.json').exists())

    def test_introduced_leak_is_a_failed_premise_with_matching_outputs(self):
        self.install('spx_resource_token a=spx_resource_acquire(42); (void)a;')
        code,text,out=self.check(self.package,'leak')
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'match')
        self.assertEqual(resource_applicability(result),'violated')
        self.assertIn('untransferred-allowance-exceeded',text)
        self.assertIn('native allocation internals',text)

    def test_known_original_leak_remains_matching_and_visible(self):
        self.install('(void)spx_resource_acquire(42);',untransferred=1,sides=['original','source'])
        code,text,out=self.check(self.package,'preserved')
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(resource_applicability(result),'satisfied')
        findings=result['cases'][0]['resources']['diagnostics']
        self.assertEqual({f['side'] for f in findings},{'original','source'})
        self.assertTrue(all(f['classification']=='resource-diagnostic' for f in findings))
        self.assertIn('untransferred',text)
        # Removing a real observation cannot be repaired merely by rehashing JSON.
        receipt=out/'comparison-result.json'
        result['cases'][0]['resources']['diagnostics']=[]
        result['receipt_sha256']=comparison_result_identity({k:v for k,v in result.items() if k!='receipt_sha256'})
        receipt.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError,'resource findings differ'):
            load_comparison_result(out)

    def test_nested_aliases_retention_and_error_cleanup(self):
        self.install('''spx_resource_token outer=spx_resource_acquire(42);
uint32_t child=spx_resource_frame_enter(contract);
spx_resource_token alias=spx_resource_acquire(42);
(void)spx_resource_borrow(outer);
spx_resource_token error=spx_resource_acquire(99);
spx_resource_consume(error); spx_resource_retain(alias);
spx_resource_frame_leave(child);
/* A retained inner reference remains usable after return. */
spx_resource_consume(alias); spx_resource_consume(outer);''',retained=1)
        code,text,out=self.check(self.package,'nested')
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        events=result['cases'][0]['resources']['events']['source']
        self.assertEqual(sum(e['event']=='begin' for e in events),2)
        self.assertEqual([e['object'] for e in events if e['event']=='retained'],[42])
        aliases=[e for e in events if e['event']=='acquire' and e['object']==42]
        self.assertEqual(len(aliases),2)
        self.assertNotEqual(aliases[0]['token'],aliases[1]['token'])
        self.assertEqual([e['object'] for e in events if e['event']=='borrow'],[42])

    def test_generation_reuse_and_double_consume_are_rejected(self):
        self.install('''spx_resource_token stale=spx_resource_acquire(42);
spx_resource_consume(stale);
spx_resource_token fresh=spx_resource_acquire(42);
if (fresh.slot!=stale.slot || fresh.generation==stale.generation) return 9;
spx_resource_consume(stale);''')
        code,text,out=self.check(self.package,'stale')
        self.assertEqual(code,2,text)
        self.assertEqual(resource_applicability(load_comparison_result(out)),'violated')
        self.assertIn('expired',text)

    def test_capacity_failure_is_incomplete_instrumentation_not_a_new_bug(self):
        self.install('(void)spx_resource_acquire(42); (void)spx_resource_acquire(43);',capacity=1)
        code,text,out=self.check(self.package,'capacity')
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(resource_applicability(result),'incomplete')
        self.assertIn('instrumentation-limit',text)

    def test_missing_instrumentation_cannot_satisfy_a_contract(self):
        self.install('spx_resource_token v=spx_resource_acquire(1); spx_resource_consume(v);')
        driver=self.package/'adapters/driver.c'
        driver.write_text('#include <stdio.h>\nint main(void) { puts("{\\\"value\\\":7}"); return 0; }\n')
        plan=json.loads((self.package/'comparison-plan.json').read_text())
        plan['original']['files']['adapters/driver.c']=sha256_file(driver)
        (self.package/'comparison-plan.json').write_text(json.dumps(plan))
        code,text,out=self.check(self.package,'missing')
        self.assertEqual(code,2,text)
        self.assertEqual(resource_applicability(load_comparison_result(out)),'incomplete')

    def test_failed_premises_block_admission_and_are_rechecked_at_execution(self):
        self.install('spx_resource_token a=spx_resource_acquire(42); '
                     'if (!getenv("SPX_TEST_RESOURCE_LEAK")) spx_resource_consume(a);')
        package=self.prepare()
        with patch.dict(os.environ,{'SPX_TEST_RESOURCE_LEAK':'1'}):
            code,text,out=self.check(self.package,'failed-premise')
            self.assertEqual(code,2,text)
            self.assertEqual(load_comparison_result(out)['status'],'match')
            code,text=self.candidate('build','fixture','--experimental-comparison',str(out),
                '--experimental-policy',str(self.policy()),'--output',str(self.root/'rejected'))
            self.assertEqual(code,2,text)
            self.assertIn('resource contract premises',text)
            code,text=self.candidate('test','fixture','--experimental-package',str(package),
                '--output',str(self.root/'runtime-failure'))
            self.assertEqual(code,2,text)
        result=json.loads((self.root/'runtime-failure/experimental-run.json').read_text())
        self.assertEqual(result['behavioral_status'],'pass')
        self.assertEqual(result['status'],'fail')
        self.assertEqual(result['resources']['three']['status'],'violated')
        self.assertEqual(len(result['resource_report_sha256s']),1)

    def test_retention_requires_explicit_allowance(self):
        self.install('spx_resource_retain(spx_resource_acquire(42));')
        code,text,out=self.check(self.package,'retention-not-allowed')
        self.assertEqual(code,2,text)
        self.assertEqual(load_comparison_result(out)['status'],'match')
        self.assertIn('retained-allowance-exceeded',text)

    def test_resource_policy_acceptance_is_not_implied_by_a_stable_signature(self):
        self.install('spx_resource_token a=spx_resource_acquire(42); spx_resource_consume(a);')
        code,text,out=self.check(self.package,'matching')
        self.assertEqual(code,0,text)
        policy=experimental.ExperimentalCandidateTests.policy(self)
        code,text=self.candidate('build','fixture','--experimental-comparison',str(out),
            '--experimental-policy',str(policy),'--output',str(self.root/'unaccepted-resources'))
        self.assertEqual(code,2,text)
        self.assertIn('resource checks have not been accepted',text)

    def test_generation_exhaustion_is_reported_before_wrapping(self):
        from spaghetti_extractor.components.comparison_resource_runtime import runtime_header,runtime_source
        from spaghetti_extractor.components.comparison_resources import resource_contracts,resource_observations
        self.install('spx_resource_token a=spx_resource_acquire(42); spx_resource_consume(a);')
        plan,_=load_comparison_package(self.package)
        contracts=resource_contracts(plan);digest=next(iter(contracts))
        (self.root/'comparison-resources.h').write_text(runtime_header(32,16))
        model=self.root/'near-wrap.c'
        # Seed a reachable near-wrap observer state, avoiding billions of calls.
        model.write_text(runtime_source(contracts)+'\nint main(void) { spx_resource_frame_enter("'+digest+'"); '
            'tokens[0].generation=UINT32_MAX; (void)spx_resource_acquire(42); return 0; }\n')
        binary=self.root/'near-wrap'
        subprocess.run([plan['tools']['compiler']['path'],'-std=c11','-Wall','-Wextra','-Werror',str(model),'-o',str(binary)],check=True,timeout=30,capture_output=True)
        result=subprocess.run([str(binary)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,78)
        log=self.root/'near-wrap.stderr';log.write_bytes(result.stderr)
        observations=resource_observations(plan,{'source':log})
        self.assertEqual(observations['status'],'incomplete')
        self.assertEqual(observations['diagnostics'][0]['event'],'generation')

    def test_duplicate_or_unbound_resource_events_fail_closed(self):
        from spaghetti_extractor.components.comparison_resources import resource_observations
        self.install('spx_resource_token a=spx_resource_acquire(42); spx_resource_consume(a);')
        plan,_=load_comparison_package(self.package)
        log=self.root/'malformed.stderr'
        log.write_text('SPX_RESOURCE {"event":"begin","event":"end"}\n')
        observations=resource_observations(plan,{'source':log})
        self.assertEqual(observations['status'],'incomplete')
        self.assertIn('duplicate resource event field',observations['diagnostics'][0]['detail'])
