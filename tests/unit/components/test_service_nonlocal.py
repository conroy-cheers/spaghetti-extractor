"""Actual C callbacks/jumps and checked interruption of composed service scopes."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import compile_component_interface_v5
from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog, checked_service_catalog
from spaghetti_extractor.components.service_c import render_service_bridges, render_operation_bridge
from spaghetti_extractor.components.comparison_service_runtime import runtime_header, runtime_source
from spaghetti_extractor.components.comparison_resource_runtime import runtime_header as resource_header, runtime_source as resource_source
from spaghetti_extractor.components.comparison_resources import checked_resource_checks, resource_observations, resource_contracts
from spaghetti_extractor.components.comparison_services import service_observations
from .test_comparison_resources import resource_checks

TESTKIT = {'fixtures': ('compiler',)}
TYPES = [dict(id='unit', kind='void'), dict(id='u32', kind='integer', width_bits=32, signed=False)]


def definition(identity, escapes):
    return ServiceDefinition.create(identity=identity, types=TYPES, parameters=[('input', 'u32')],
        result='u32', resources=[], effects=['fixture.callback'], outcomes=['return'],
        nonlocal_outcomes=escapes, unobserved=['adapter callback semantics beyond the executed cases'])


class NonlocalServiceTests(unittest.TestCase):
    def execute(self, *, parent_escapes=True, catch_inside=False, leak=False, nonlocal_allowance=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalogs = {}
            checks = {}
            sources = []
            for name, service, target, escapes in [
                    ('outer', 'dispatch', 'inner_entry', ['nomem'] if parent_escapes else []),
                    ('inner', 'allocate', 'native_allocate', ['nomem'])]:
                services = {service: definition('fixture.'+service, escapes)}
                interface = component_interface(component_id=name, types=TYPES,
                    parameters=[('input','u32')], result='u32', services=services)
                catalogs[name] = service_catalog(services).to_payload()
                checked_service_catalog(catalogs[name], interface)
                checks[name] = resource_checks(interface)
                if name=='inner' and nonlocal_allowance is not None:
                    checks[name]['contracts'][0]['nonlocal_allowances']={'nomem':
                        dict(max_untransferred=nonlocal_allowance,max_retained=0)}
                checked_resource_checks(checks[name],interface)
                directory = root/name
                directory.mkdir()
                for filename, contents in render_component_c_headers_v5(
                        compile_component_interface_v5(interface), {'run':'lifted_'+name}).items():
                    (directory/filename).write_text(contents)
                declarations = 'uint32_t '+target+'(uint32_t input);\n'
                if name=='outer' and catch_inside:
                    target='catching_dispatch'
                    declarations+='''#include <setjmp.h>
extern jmp_buf *active_landing;
static uint32_t catching_dispatch(uint32_t input) {
  jmp_buf local;
  jmp_buf *previous=active_landing;
  uint32_t handler=spx_service_handler_begin();
  active_landing=&local;
  if (!setjmp(local)) return inner_entry(input);
  spx_service_handler_catch(handler,"nomem");
  spx_service_handler_end(handler);active_landing=previous;
  return input+1;
}
'''
                wrappers, _ = render_service_bridges(services=services,
                    adapters={service:dict(symbol=target,kind='native',outcomes={'return':None})},transports={})
                bridge=render_operation_bridge(interface=interface, operation_symbol='lifted_'+name,
                    native_symbol=name+'_entry', services=services, transports={}, resource_rule=checks[name]['contracts'][0])
                source=directory/'unit.c'
                source.write_text('#include "portable-component-implementation.h"\n#include "comparison-services.h"\n#include "comparison-resources.h"\n'+
                    declarations+wrappers+'uint32_t lifted_'+name+'(spx_'+name+'_context_v5 *c,uint32_t input) {\n'+
                    'return c->services->'+service+'(c->services->context,input); }\n'+bridge)
                sources.append(source)
            plan=dict(component_id='outer',service_catalog=catalogs['outer'],resource_checks=checks['outer'],
                dependencies=[dict(id='inner',service_catalog=catalogs['inner'],resource_checks=checks['inner'])])
            (root/'comparison-services.h').write_text(runtime_header(True))
            (root/'services.c').write_text(runtime_source(['nomem'],True))
            (root/'comparison-resources.h').write_text(resource_header(32,16))
            (root/'resources.c').write_text(resource_source(resource_contracts(plan)))
            digest=canonical_sha256_v3(checks['outer']['contracts'][0])
            main='''#include <setjmp.h>
#include <stdint.h>
#include <stdlib.h>
#include "comparison-services.h"
#include "comparison-resources.h"
jmp_buf *active_landing;
static uint32_t memory, callbacks;
uint32_t outer_entry(uint32_t input);
static void callback(void *context) {
  if (context!=&memory || memory!=17) exit(86);
  ++callbacks;longjmp(*active_landing,1);
}
uint32_t native_allocate(uint32_t input) {
  spx_resource_token token=spx_resource_acquire(77);
  TOKEN_ACTION
  memory=input;callback(&memory);return 99;
}
int main(void) {
  uint32_t frame=spx_resource_frame_enter("DIGEST");
  spx_resource_token outer=spx_resource_acquire(99);
  jmp_buf landing;active_landing=&landing;
  uint32_t handler=spx_service_handler_begin();
  if (!setjmp(landing)) {
    uint32_t result=outer_entry(17);
    NORMAL_CHECK
  } else {
    spx_service_handler_catch(handler,"nomem");
  }
  spx_service_handler_end(handler);
  if (callbacks!=1 || memory!=17) return 87;
  spx_resource_borrow(outer);spx_resource_consume(outer);spx_resource_frame_leave(frame);
  return 0;
}
'''.replace('DIGEST',digest).replace('TOKEN_ACTION','(void)token;' if leak else 'spx_resource_consume(token);').replace(
                'NORMAL_CHECK','if (result!=18) return 88;' if catch_inside else '(void)result;return 89;')
            (root/'main.c').write_text(main)
            built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror','-I',str(root),
                *map(str,sources),str(root/'main.c'),str(root/'services.c'),str(root/'resources.c'),'-o',str(root/'run')],capture_output=True,text=True)
            self.assertEqual(built.returncode,0,built.stderr)
            run=subprocess.run([root/'run'],capture_output=True,text=True,timeout=10)
            stream=root/'stderr';stream.write_text(run.stderr)
            return run,resource_observations(plan,{'source':stream}),plan,run.stderr

    def test_actual_callback_unwinds_two_components_and_preserves_outer_resources(self):
        run,report,_,_=self.execute()
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'satisfied',report['diagnostics'])
        self.assertEqual(sum(e['event']=='unwind' for e in report['events']['source']),2)
        self.assertEqual(sum(e['event']=='catch' for e in report['services']['events']),1)

    def test_every_interrupted_caller_must_permit_the_outcome(self):
        run,report,_,_=self.execute(parent_escapes=False)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'incomplete')
        self.assertIn('did not declare',report['services']['diagnostics'][0]['detail'])

    def test_inner_handler_preserves_pending_parent_call_and_its_resource_frame(self):
        run,report,_,_=self.execute(parent_escapes=False,catch_inside=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'satisfied',report['diagnostics'])
        self.assertEqual(sum(e['event']=='unwind' for e in report['events']['source']),1)
        self.assertEqual(sum(e['event']=='return' for e in report['services']['events']),1)

    def test_unwind_reports_lost_references_without_relaxing_allowances(self):
        run,report,_,_=self.execute(leak=True)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'violated')
        self.assertTrue(any(e.get('event')=='untransferred-allowance-exceeded' for e in report['diagnostics']))

    def test_named_nonlocal_allowance_preserves_lost_reference_diagnostics(self):
        run,report,plan,text=self.execute(leak=True,nonlocal_allowance=1)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'satisfied',report['diagnostics'])
        self.assertEqual(sum(e.get('event')=='untransferred' for e in report['diagnostics']),1)
        # A normal end cannot use the allowance reserved for an actual catch.
        with tempfile.TemporaryDirectory() as temporary:
            stream=Path(temporary)/'stderr';stream.write_text(text.replace('"event":"unwind"','"event":"end"'))
            rejected=resource_observations(plan,{'source':stream})
            self.assertEqual(rejected['status'],'violated')
        # Missing delivery cannot leave deferred resource accounting satisfied.
        with tempfile.TemporaryDirectory() as temporary:
            stream=Path(temporary)/'stderr'
            stream.write_text('\n'.join(line for line in text.splitlines() if not
                (line.startswith('SPX_SERVICE_HANDLER ') and '"catch"' in line)))
            self.assertEqual(resource_observations(plan,{'source':stream})['status'],'incomplete')

    def test_inner_nonlocal_allowance_does_not_waive_enclosing_frame(self):
        run,report,_,_=self.execute(leak=True,nonlocal_allowance=1,catch_inside=True,parent_escapes=False)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(report['status'],'satisfied',report['diagnostics'])
        self.assertEqual(sum(e['event']=='unwind' for e in report['events']['source']),1)
        _,report,_,_=self.execute(leak=True,nonlocal_allowance=0)
        self.assertEqual(report['status'],'violated')
        self.assertTrue(any(e.get('outcome')=='nomem' and e.get('allowed')==0 for e in report['diagnostics']))

    def test_nonlocal_allowances_are_exact_bounded_contract_inputs(self):
        interface=component_interface(component_id='fixture',types=TYPES,parameters=[('input','u32')],result='u32',services={})
        checks=resource_checks(interface);rule=checks['contracts'][0]
        before=canonical_sha256_v3(rule)
        rule['nonlocal_allowances']={'nomem':dict(max_untransferred=1,max_retained=0)}
        checked_resource_checks(checks,interface)
        self.assertNotEqual(before,canonical_sha256_v3(rule))
        for invalid in [{},{'return':dict(max_untransferred=1,max_retained=0)},
                {'nomem':dict(max_untransferred=-1,max_retained=0)},
                {'nomem':dict(max_untransferred=33,max_retained=0)},
                {'nomem':dict(max_untransferred=True,max_retained=0)},
                {'nomem':dict(max_untransferred=1)}]:
            rule['nonlocal_allowances']=invalid
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):checked_resource_checks(checks,interface)

    def test_missing_wrong_and_stale_handler_events_fail_closed(self):
        _,_,plan,text=self.execute()
        lines=text.splitlines()
        caught=next(s for s in lines if s.startswith('SPX_SERVICE_HANDLER ') and '"catch"' in s)
        for mutated in [text.replace(caught,''),text.replace(caught,caught.replace('"nomem"','"other"')),
                text.replace(caught,caught.replace('"handler":1','"handler":99')),
                text.replace(caught,caught+'\n'+caught)]:
            with self.subTest(mutated=mutated),tempfile.TemporaryDirectory() as temporary:
                stream=Path(temporary)/'stderr';stream.write_text(mutated)
                self.assertEqual(service_observations(plan,{'source':stream})['status'],'incomplete')

    def test_nonlocal_permissions_change_contract_even_with_same_signature(self):
        normal=definition('fixture.test',[]);nonlocal_=definition('fixture.test',['nomem'])
        self.assertEqual(normal.schema.to_payload(),nonlocal_.schema.to_payload())
        self.assertNotEqual(normal.binding_id,nonlocal_.binding_id)
        self.assertNotIn('nonlocal_outcomes',normal.contract.subject)
        for changes in [dict(nonlocal_outcomes=['return']),dict(protocol='synchronous-return',nonlocal_outcomes=['nomem']),
                dict(nonlocal_outcomes=['nomem','nomem'])]:
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                ServiceDefinition.create(identity='fixture.bad',types=TYPES,parameters=[],result='unit',
                    resources=[],effects=[],outcomes=['return'],unobserved=[],**changes)

    def test_matching_stack_depth_cannot_replace_the_saved_caller_invocation(self):
        _,_,plan,text=self.execute(parent_escapes=False,catch_inside=True)
        lines=text.splitlines()
        marker=next(s for s in lines if s.startswith('SPX_SERVICE_HANDLER ') and '"handler":2' in s and '"begin"' in s)
        scope=next(s for s in lines if s.startswith('SPX_SERVICE_SCOPE '))
        call=next(s for s in lines if s.startswith('SPX_SERVICE '))
        return_event=json.loads(call[len('SPX_SERVICE '):]);return_event.update(event='return',outcome='return')
        end_event=json.loads(scope[len('SPX_SERVICE_SCOPE '):]);end_event['event']='end'
        replacement='\n'.join(['SPX_SERVICE '+json.dumps(return_event),'SPX_SERVICE_SCOPE '+json.dumps(end_event),scope,call])
        with tempfile.TemporaryDirectory() as temporary:
            stream=Path(temporary)/'stderr';stream.write_text(text.replace(marker,marker+'\n'+replacement))
            report=service_observations(plan,{'source':stream})
            self.assertEqual(report['status'],'incomplete')
            self.assertIn('enclosing scope',report['diagnostics'][0]['detail'])
