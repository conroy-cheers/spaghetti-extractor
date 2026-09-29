"""Transitive selection, exact contract requirements and explicit recursion."""
import json
from pathlib import Path
import runpy
import shutil
from unittest.mock import patch

from spaghetti_extractor.components.comparison_package import (
    prepare_comparison_package,load_comparison_package,revise_comparison_package,start_comparison_package,
)
from spaghetti_extractor.components.comparison_composition import bind_dependencies,requirement,composition_graph,selection_impact
from spaghetti_extractor.components.comparison_run import run_comparison,load_comparison_result
from spaghetti_extractor.components.service_authoring import component_interface

TESTKIT={'fixtures':('compiler',)}


from .comparison_composition_fixture import CompositionFixture, TYPES

class CompositionTests(CompositionFixture):


    def test_reuse_named_services_and_explicit_shared_inputs_from_network(self):
        from spaghetti_extractor.components.comparison_environment import retained_service_inputs
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,service_catalog
        service=ServiceDefinition.create(identity='fixture.increment',types=TYPES,
            parameters=[('x','u32')],result='u32',resources=[],effects=['fixture.increment'],
            outcomes=['return'],unobserved=['finite scalar fixture'])
        interface=component_interface(component_id='leaf',types=TYPES,
            parameters=[('x','u32')],result='u32',services={'increment':service})
        leaf=self.make('leaf')
        support=self.root/'support.c';support.write_text('unsigned increment(unsigned x) { return x+1U; }\n')
        header=self.root/'support.h';header.write_text('unsigned increment(unsigned);\n')
        supplier=self.root/'supplier'
        revise_comparison_package(package=leaf,output=supplier,interface=interface,
            adapter_files={'driver.c':leaf/'adapters/driver.c','bridge.c':leaf/'adapters/bridge.c','support.c':support},
            include_files={'support.h':header},export_adapters=['adapters/bridge.c','adapters/support.c'],
            service_catalog=service_catalog({'increment':service}).to_payload(),
            service_bridge=dict(native_symbol=None,transports={},
                adapters={'increment':dict(symbol='increment',kind='native',outcomes={'return':None})}))
        network=self.make('network','exported_leaf(x)',oracle='x+1',selections=[dict(id='leaf',package=supplier)])
        args=dict(names=['increment'],native_symbol=None,
            adapters={'increment.c':'dependencies/leaf/bridges/support.c','driver.c':'adapters/driver.c'},
            headers={'api.h':'dependencies/leaf/headers/support.h'})
        services,inputs=retained_service_inputs(network,component_id='leaf',**args)
        self.assertEqual(services['increment'].binding_id,service.binding_id)
        self.assertEqual(inputs['adapter_files']['increment.c'].read_bytes(),support.read_bytes())
        self.assertEqual(inputs['adapter_files']['driver.c'],network/'adapters/driver.c')
        self.assertEqual(inputs['include_files']['api.h'].read_bytes(),header.read_bytes())
        self.assertEqual(inputs['service_bridge']['adapters']['increment']['symbol'],'increment')
        legacy,legacy_inputs=retained_service_inputs(supplier,names=['increment'],native_symbol=None,
            adapters=['support.c'],headers=['support.h'])
        self.assertEqual(legacy['increment'].binding_id,service.binding_id)
        self.assertEqual(legacy_inputs['adapter_files']['support.c'].read_bytes(),support.read_bytes())
        with self.assertRaisesRegex(ValueError,'component is absent'):
            retained_service_inputs(network,component_id='missing',**args)
        with self.assertRaisesRegex(ValueError,'adapter is not selected'):
            retained_service_inputs(network,component_id='leaf',**{**args,'adapters':{'body.c':'dependencies/leaf/source/body.c'}})
        with self.assertRaisesRegex(ValueError,'relative file name'):
            retained_service_inputs(network,component_id='leaf',**{**args,'headers':{'../escape.h':'dependencies/leaf/headers/support.h'}})

    def test_reuse_services_from_several_components_with_local_aliases_and_shared_state(self):
        from spaghetti_extractor.components.comparison_environment import retained_service_inputs
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,service_catalog
        types=[*TYPES,dict(id='cell',kind='opaque',nominal_id='fixture.cell'),
            dict(id='unused',kind='opaque',nominal_id='fixture.unused')]
        transport=dict(native_type='cell_pointer',take='cell_take',borrow='cell_borrow',pack='cell_pack')
        header=self.root/'cell.h';header.write_text('#include <stdint.h>\nstruct spx_opaque_cell_v5 { uint32_t value; };\n'
            'typedef struct spx_opaque_cell_v5 *cell_pointer;\n'
            'void cell_write(struct spx_opaque_cell_v5 *, uint32_t);\nuint32_t cell_read(struct spx_opaque_cell_v5 *);\n')
        suppliers={};definitions={}
        for name,parameters,result,body in [
                ('writer',[('cell','cell'),('value','u32')],'unit',
                    'void cell_write(struct spx_opaque_cell_v5 *cell,uint32_t value) { cell->value=value; }\n'),
                ('reader',[('cell','cell')],'u32',
                    'uint32_t cell_read(struct spx_opaque_cell_v5 *cell) { return cell->value; }\n')]:
            service=ServiceDefinition.create(identity='fixture.'+name,types=types,parameters=parameters,result=result,
                resources=[],effects=['fixture.'+name],outcomes=['return'],unobserved=['Live shared cell supplied by the caller.'])
            definitions[name]=service;previous=self.make(name)
            support=self.root/(name+'.c');support.write_text('#include "cell.h"\n'+body)
            interface=component_interface(component_id=name,types=types,parameters=[('x','u32')],result='u32',services={'action':service})
            destination=self.root/(name+'-services')
            revise_comparison_package(package=previous,output=destination,interface=interface,
                adapter_files={**{n:previous/'adapters'/n for n in ('driver.c','bridge.c')},'support.c':support},
                include_files={'cell.h':header},export_adapters=['adapters/bridge.c','adapters/support.c'],
                service_catalog=service_catalog({'action':service}).to_payload(),
                service_bridge=dict(native_symbol=None,transports={'cell':transport,
                    'unused':{**transport,'borrow':name+'_unused'}},
                    adapters={'action':dict(symbol='cell_write' if name=='writer' else 'cell_read',
                        kind='portable',outcomes={'return':None},declare=True)}))
            suppliers[name]=destination
        network=self.make('network',selections=[dict(id=name,package=path) for name,path in suppliers.items()])
        choices={'set':'writer/action','peek':'reader/action','again':'reader/action'}
        shared=dict(names=choices,native_symbol='entry_local',
            adapters={name+'.c':'dependencies/'+name+'/bridges/support.c' for name in suppliers},
            headers={'cell.h':'dependencies/writer/headers/cell.h'})
        services,inputs=retained_service_inputs(network,**shared)
        self.assertEqual(services['set'],definitions['writer'])
        self.assertEqual(services['peek'],definitions['reader'])
        self.assertEqual(services['again'],definitions['reader'])
        self.assertEqual(len(inputs['service_catalog']['contracts']),2)
        self.assertEqual(inputs['service_bridge']['transports'],{'cell':transport})
        self.assertEqual(inputs['service_bridge']['adapters']['peek']['symbol'],'cell_read')
        source=self.root/'local.c';source.write_text('''#include "portable-component-implementation.h"
#include "cell.h"
uint32_t lifted_local(spx_local_context_v5 *c,uint32_t x) {
  struct spx_opaque_cell_v5 cell={x};
  c->services->set(c->services->context,&cell,x+2U);
  return c->services->peek(c->services->context,&cell)+c->services->again(c->services->context,&cell);
}
''')
        driver=self.root/'local-driver.c';driver.write_text('''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "portable-component-implementation.h"
#include "cell.h"
#include "comparison-service-bridge.h"
int main(int argc,char **argv) {
  if(argc!=3)return 2;
  uint32_t x=(uint32_t)strtoul(argv[2],0,10);
  uint32_t result=!strcmp(argv[1],"original") ? 2U*(x+2U) : entry_local(x);
  printf("{\\"value\\":%u}\\n",result);return 0;
}
''')
        inputs['adapter_files']['driver.c']=driver
        local=self.root/'local'
        prepare_comparison_package(interface_package=component_interface(component_id='local',
            parameters=[('x','u32')],result='u32',services=services),target_id='fixture',component_id='local',
            source_files={'body.c':source},operation_symbols={'run':'lifted_local'},
            original_files=['adapters/driver.c'],oracle_kind='fixture',cases=[dict(id='five',arguments=['5'])],
            observation_fields=['value'],assumptions=['Live shared mutable cell.'],scope='service selection fixture',
            output=local,**inputs)
        result=run_comparison(package=local,output=self.root/'local-result',target_id='fixture',component_id='local')
        self.assertEqual(result['status'],'match','\n'.join(p.read_text() for p in
            (self.root/'local-result/build').glob('*.stderr'))+str(result['cases']))
        coverage=result['cases'][0]['resources']['services']['coverage']
        self.assertEqual(coverage['fixture.writer']['calls'],1)
        self.assertEqual(coverage['fixture.reader']['calls'],2)
        # Same C types with a different transport are not an implicit common ABI.
        plan,_=load_comparison_package(network)
        reader=next(row for row in plan['dependencies'] if row['id']=='reader')
        changed={**reader['service_bridge'],'transports':{'cell':{**transport,'borrow':'different_borrow'}}}
        conflicting=self.root/'conflicting'
        revise_comparison_package(package=network,component_id='reader',output=conflicting,service_bridge=changed)
        with self.assertRaisesRegex(ValueError,'transport differs for type cell between writer/action and reader/action'):
            retained_service_inputs(conflicting,**shared)

    def test_service_inventory_keeps_different_contracts_and_local_c_bindings_visible(self):
        import contextlib
        import io
        from spaghetti_extractor.cli import main
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,service_catalog

        def add_service(package,name,*,changed=False):
            service=ServiceDefinition.create(identity='fixture.increment',types=TYPES,
                parameters=[('x','u32')],result='u32',resources=[],effects=['fixture.changed' if changed else 'fixture.increment'],
                outcomes=['return'],unobserved=['finite scalar fixture'])
            interface=component_interface(component_id=name,types=TYPES,
                parameters=[('x','u32')],result='u32',services={'increment':service})
            support=self.root/(name+'-support.c');support.write_text('unsigned increment(unsigned x) { return x+1U; }\n')
            revised=self.root/(name+'-services')
            revise_comparison_package(package=package,output=revised,interface=interface,
                adapter_files={'driver.c':package/'adapters/driver.c','bridge.c':package/'adapters/bridge.c','support.c':support},
                export_adapters=['adapters/bridge.c','adapters/support.c'],
                service_catalog=service_catalog({'increment':service}).to_payload(),
                service_bridge=dict(native_symbol=None,transports={},
                    adapters={'increment':dict(symbol='increment',kind='native',outcomes={'return':None})}))
            return revised

        left=add_service(self.make('left'),'left')
        right=add_service(self.make('right'),'right')
        network=add_service(self.make('network','exported_left(x)+exported_right(x)',oracle='2*x+2',
            selections=[dict(id='left',package=left),dict(id='right',package=right)]),'network',changed=True)
        def command(*options):
            out=io.StringIO()
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):
                status=main(['component','list','fixture',*options])
            return status,out.getvalue()

        with (patch('subprocess.Popen',side_effect=AssertionError('inventory must not execute tools')),
              patch('spaghetti_extractor.commands.workflows._operator_index',side_effect=AssertionError('inventory must stay local'))):
            code,text=command('--comparison-package',str(network),'--service','increment','--json')
            self.assertEqual(code,0,text);view=json.loads(text)
            self.assertEqual(view['assurance'],'not-evaluated')
            self.assertEqual(len(view['groups']),2)  # Same signature, different declared effects.
            self.assertEqual(sorted(len(g['declarations']) for g in view['groups']),[1,2])
            declarations=[row for group in view['groups'] for row in group['declarations']]
            row=next(row for row in declarations if row['component_id']=='left')
            paths=[definition['path'] for definition in row['source_navigation']['definitions']]
            self.assertIn('dependencies/left/bridges/support.c',paths)
            self.assertIn('dependencies/left/bridges/support.c',view['knowledge_inputs_sha256'])
            self.assertEqual(row['adapter']['symbol'],'increment')
            self.assertIn('assumptions',view['components']['left'])
            code,text=command('--comparison-package',str(network),'--service','right')
            self.assertEqual(code,0,text)
            self.assertIn('right/increment',text);self.assertNotIn('left/increment',text)
            self.assertIn('C definition candidate:',text)
            self.assertIn('not a compiler-resolved dependency closure',text)
            code,text=command('--comparison-package',str(network),'--service','absent')
            self.assertEqual(code,0,text);self.assertIn('No service declarations match',text)
            code,text=command('--services')
            self.assertNotEqual(code,0);self.assertIn('requires --comparison-package',text)

    def test_prepare_local_from_selected_component_retains_boundary_and_requires_explicit_fixture(self):
        from spaghetti_extractor.components.comparison_environment import retained_component_inputs
        from spaghetti_extractor.components.comparison_composition import contract_identity
        from spaghetti_extractor.components.comparison_package import retained_comparison_environment
        leaf=self.make('leaf')
        mid=self.make('mid','exported_leaf(x)+1',oracle='x+2',selections=[dict(id='leaf',package=leaf)])
        helper=self.root/'helper.h';helper.write_text('#define INCREMENT 1\n')
        layout=self.root/'layout.h';layout.write_text('/* reviewed shared layout */\n')
        revised=self.root/'revised-mid'
        revise_comparison_package(package=mid,output=revised,
            source_files={'body.c':mid/'source/body.c','helper.h':helper},
            include_files={'layout.h':layout},private_headers=['source/helper.h'])
        body=revised/'source/body.c'
        body.write_text('#include "helper.h"\n'+body.read_text().replace('exported_leaf(x)+1','exported_leaf(x)+INCREMENT'))
        (revised/'source/shared.h').write_text('/* retained non-authored input */\n')
        root=self.make('root','exported_mid(x)',oracle='x+2',selections=[dict(id='mid',package=revised)])
        network,_=load_comparison_package(root)
        selected=next(row for row in network['dependencies'] if row['id']=='mid')
        local=self.root/'local-mid'
        with retained_component_inputs(root,component_id='mid') as inputs:
            self.assertEqual(inputs['private_headers'],['source/helper.h'])
            self.assertNotIn('adapter_files',inputs)
            self.assertNotIn('cases',inputs)
            self.assertEqual(inputs['requirements'],selected['requirements'])
            setup=dict(adapter_files={'driver.c':mid/'adapters/driver.c','bridge.c':mid/'adapters/bridge.c'},
                original_files=['adapters/driver.c'],oracle_kind='fixture',
                cases=[dict(id='three',arguments=['3'])],observation_fields=['value'],
                scope='operator-defined local fixture',export_adapters=['adapters/bridge.c'],
                **retained_comparison_environment(root))
            with self.assertRaisesRegex(ValueError,'missing supplier'):
                prepare_comparison_package(**inputs,**setup,output=local)
            self.assertFalse(local.exists())
        from spaghetti_extractor.cli import main
        work=self.root/'local-authoring'
        self.assertEqual(main(['component','start','fixture','mid','--comparison-package',str(root),
            '--output',str(work)]),0)
        recipe=work/'dependencies/mid/prepare-local.py'
        prepared=runpy.run_path(str(recipe))['prepare']
        # Fill only the local driver/oracle/cases. Boundary, source, shared
        # headers, execution setup and transitive suppliers come from the draft.
        environment=retained_comparison_environment(root)
        fixture={k:v for k,v in setup.items() if k not in environment}
        with patch.dict(prepared.__globals__,local_fixture=lambda:dict(fixture)):
            prepared(local)
        edited=recipe.read_bytes()+b'\n# Operator notes for this local fixture.\n'
        recipe.write_bytes(edited)
        reopened=self.root/'local-authoring-reopened'
        self.assertEqual(main(['component','start','fixture','mid','--comparison-package',str(work),
            '--output',str(reopened)]),0)
        self.assertEqual((reopened/'dependencies/mid/prepare-local.py').read_bytes(),edited)
        current,_=load_comparison_package(local)
        self.assertEqual(contract_identity(local,current),contract_identity(root,selected))
        self.assertEqual((local/'source/body.c').read_bytes(),body.read_bytes())
        self.assertEqual((local/'headers/layout.h').read_bytes(),layout.read_bytes())
        self.assertTrue((local/'source/shared.h').is_file())
        self.assertNotIn('source/shared.h',current['sources'])
        self.assertEqual([row['id'] for row in current['dependencies']],['leaf'])
        result=run_comparison(package=local,output=self.root/'local-result',target_id='fixture',component_id='mid')
        self.assertEqual(result['status'],'match')

    def test_local_network_selection_keeps_recursive_requirements_without_replacing_entry(self):
        from spaghetti_extractor.components.comparison_environment import retained_component_inputs
        from spaghetti_extractor.components.comparison_package import retained_comparison_environment
        left=self.make('left','x ? exported_right(x-1)+1 : 0',oracle='x')
        right=self.make('right','x ? exported_left(x-1)+1 : 0',oracle='x')
        network=self.make('network','exported_left(x)',oracle='x',selections=[
            dict(id='left',package=left),dict(id='right',package=right)])
        plan,_=load_comparison_package(network)
        units={u['id']:u for u in plan['dependencies']}
        for name,other in [('left','right'),('right','left')]:
            units[name]['requirements']=[requirement(identity='other',supplier=other,root=network,unit=units[other])]
        plan['recursion_groups']=[dict(id='pair',members=['left','right'],mode='synchronous-comparison',progress='unproved')]
        plan['composition']=composition_graph(network,plan)
        (network/'comparison-plan.json').write_text(json.dumps(plan))
        setup=dict(adapter_files={'driver.c':left/'adapters/driver.c','bridge.c':left/'adapters/bridge.c'},
            original_files=['adapters/driver.c'],oracle_kind='fixture',cases=[dict(id='three',arguments=['3'])],
            observation_fields=['value'],scope='reviewed recursive local fixture',export_adapters=['adapters/bridge.c'],
            **retained_comparison_environment(network))
        local=self.root/'local-left'
        with retained_component_inputs(network,component_id='left',retain_dependencies=True) as inputs:
            self.assertEqual(inputs.get('recursion_groups'),units['left'].get('recursion_groups'))
            prepare_comparison_package(**inputs,**setup,output=local)
            with self.assertRaisesRegex(ValueError,'different entry contract'):
                prepare_comparison_package(**{**inputs,'assumptions':['a changed entry premise']},**setup,output=self.root/'incompatible')
        current,_=load_comparison_package(local)
        self.assertEqual([u['id'] for u in current['dependencies']],['right'])
        self.assertEqual(current['composition']['recursion_groups'],plan['recursion_groups'])
        self.assertEqual(run_comparison(package=local,output=self.root/'local-result',target_id='fixture',component_id='left')['status'],'match')
        # The new local check must not invent a boundary change when its C goes
        # back to the enclosing network, including globally declared cycles.
        from spaghetti_extractor.components.comparison_source_draft import SourceDraft
        start_comparison_package(package=network,output=self.root/'returned',target_id='fixture',component_id='network',
            dependency_packages={'left':SourceDraft(local)})

    def test_reviewed_bindings_share_one_supplier_and_keep_contract_frozen(self):
        leaf=self.make('leaf')
        network=self.make('network','exported_leaf(x)',oracle='x+1',selections=[dict(id='leaf',package=leaf)])
        selected=dict(id='leaf',package=network)
        bound=bind_dependencies(consumers={'first-use':selected,'second-use':selected})
        self.assertEqual(len(bound['dependencies']),1)
        self.assertEqual(bound['requirements'],bind_dependencies(consumers={'first-use':leaf,'second-use':leaf})['requirements'])
        root=self.make('root','exported_leaf(x)+exported_leaf(x)',oracle='2*x+2',
            selections=bound['dependencies'],requirements=bound['requirements'])
        self.assertEqual([u['id'] for u in load_comparison_package(root)[0]['dependencies']],['leaf'])
        initial=run_comparison(package=root,output=self.root/'before',target_id='fixture',component_id='root')
        self.assertEqual(initial['status'],'match')
        source=leaf/'source/body.c';source.write_text(source.read_text().replace('x+1','x+1U'))
        edited=run_comparison(package=root,output=self.root/'body-edit',target_id='fixture',component_id='root',
            dependency_packages={'leaf':leaf},reuse_previous=self.root/'before')
        self.assertEqual(edited['status'],'match')
        self.assertEqual(edited['work_counts']['compiler'],1)
        plan=leaf/'comparison-plan.json';value=json.loads(plan.read_text())
        value['assumptions'].append('new caller restriction');plan.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'dependency contract changed for leaf'):
            run_comparison(package=root,output=self.root/'contract-edit',target_id='fixture',component_id='root',
                dependency_packages={'leaf':leaf},reuse_previous=self.root/'body-edit')
        self.assertFalse(list((self.root/'contract-edit').rglob('*.o')))

    def test_reviewed_bindings_reject_ambiguous_selections_and_duplicate_names(self):
        leaf=self.make('leaf');alternate=self.root/'alternate';shutil.copytree(leaf,alternate)
        source=alternate/'source/body.c';source.write_text(source.read_text().replace('x+1','x+2'))
        with self.assertRaisesRegex(ValueError,'ambiguous package selection for leaf'):
            bind_dependencies(services={'first':leaf,'second':alternate})
        with self.assertRaisesRegex(ValueError,'requirement name is repeated'):
            bind_dependencies(services={'same':leaf},consumers={'same':leaf})
        with self.assertRaisesRegex(ValueError,'absent selected component'):
            bind_dependencies(consumers={'unknown':dict(id='missing',package=leaf)})
        with self.assertRaisesRegex(ValueError,'ambiguous package selection for leaf'):
            bind_dependencies(consumers={'first':leaf,'second':dict(id='leaf',package=leaf,
                adapters={'bridge.c':alternate/'adapters/bridge.c'})})
        (leaf/'adapters/driver.c').write_text('changed original oracle')
        with self.assertRaisesRegex(ValueError,'original comparison input is stale'):
            bind_dependencies(consumers={'original':leaf})

    def test_add_supplier_retains_caller_edits_existing_selection_and_frozen_requirements(self):
        leaf=self.make('leaf')
        bound=bind_dependencies(consumers={'first':leaf})
        root=self.make('root','exported_leaf(x)+1',oracle='x+2',
            selections=bound['dependencies'],requirements=bound['requirements'])
        before,_=load_comparison_package(root)
        baseline=run_comparison(package=root,output=self.root/'before',target_id='fixture',component_id='root')
        self.assertEqual(baseline['status'],'match')
        extra=self.make('extra')
        addition=bind_dependencies(consumers={'second':extra})
        source=root/'source/body.c'
        source.write_text(source.read_text().replace('extern uint32_t exported_leaf',
            'extern uint32_t exported_extra(uint32_t);\nextern uint32_t exported_leaf')
            .replace('exported_leaf(x)+1','exported_extra(exported_leaf(x))'))
        (root/'operator-notes.txt').write_text('keep the caller analysis')
        revised=self.root/'revised'
        with patch('subprocess.Popen',side_effect=AssertionError('selection must not execute')):
            revise_comparison_package(package=root,output=revised,
                dependencies=addition['dependencies'],requirements=before['requirements']+addition['requirements'])
        after,_=load_comparison_package(revised)
        self.assertEqual([row['id'] for row in after['dependencies']],['extra','leaf'])
        self.assertEqual(next(row for row in after['dependencies'] if row['id']=='leaf'),before['dependencies'][0])
        self.assertEqual(after['requirements'][0],before['requirements'][0])
        self.assertEqual(after['original'],before['original'])
        self.assertEqual(after['cases'],before['cases'])
        self.assertEqual((revised/'source/body.c').read_bytes(),source.read_bytes())
        self.assertEqual((revised/'operator-notes.txt').read_text(),'keep the caller analysis')
        result=run_comparison(package=revised,output=self.root/'after',target_id='fixture',component_id='root',
            reuse_previous=self.root/'before')
        self.assertEqual(result['status'],'match')
        compilation=json.loads((self.root/'after/build/compilation.json').read_text())
        self.assertTrue(all(row['reused'] for row in compilation['units'] if row['source'].startswith('dependencies/leaf/')))
        (leaf/'source/body.c').write_text((leaf/'source/body.c').read_text().replace('x+1','x+2'))
        with self.assertRaisesRegex(ValueError,'conflicting selections for leaf'):
            revise_comparison_package(package=revised,output=self.root/'conflict',
                **bind_dependencies(consumers={'first':leaf}))
        self.assertFalse((self.root/'conflict').exists())
        self.assertEqual(load_comparison_package(root)[0],before)

    def test_reviewed_regrouping_retires_suppliers_without_leaving_dangling_consumers(self):
        root,mid,leaf=self.chain()
        before,_=load_comparison_package(root)
        (root/'operator-notes.txt').write_text('preserve caller analysis')
        revised=self.root/'regrouped'
        with self.assertRaisesRegex(ValueError,'missing supplier leaf'):
            revise_comparison_package(package=root,output=revised,remove_dependencies=['leaf'])
        self.assertFalse(revised.exists())
        fused=self.make('fused','2*x+3')
        selection=bind_dependencies(consumers={'combined':fused})
        source=self.root/'regrouped.c'
        source.write_text((root/'source/body.c').read_text().replace(
            'uint32_t lifted_root(', 'extern uint32_t exported_fused(uint32_t);\nuint32_t lifted_root(')
            .replace('exported_mid(x)+exported_leaf(x)','exported_fused(x)'))
        revise_comparison_package(package=root,output=revised,remove_dependencies=['mid','leaf'],
            source_files={'body.c':source},**selection)
        after,_=load_comparison_package(revised)
        self.assertEqual([row['id'] for row in after['dependencies']],['fused'])
        self.assertEqual(after['original'],before['original'])
        self.assertEqual(after['cases'],before['cases'])
        self.assertEqual((revised/'operator-notes.txt').read_text(),'preserve caller analysis')
        self.assertFalse((revised/'dependencies/leaf').exists())
        self.assertTrue((root/'dependencies/leaf').is_dir())
        result=run_comparison(package=revised,output=self.root/'regrouped-check',target_id='fixture',component_id='root')
        self.assertEqual(result['status'],'match')

    def test_boundary_revision_preserves_c_and_rebuilds_graph_without_refining_callers(self):
        leaf=self.make('leaf',requirements=[])
        bound=bind_dependencies(consumers={'call':leaf})
        root=self.make('root','exported_leaf(x)',oracle='x+1',
            selections=bound['dependencies'],requirements=bound['requirements'])
        source=leaf/'source/body.c';source.write_text(source.read_text()+'\n/* operator edit */\n')
        before,old_interface=load_comparison_package(leaf)
        revised=self.root/'revised'
        interface=component_interface(component_id='leaf',types=TYPES,
            parameters=[('value','u32')],result='u32',services={})
        with patch('subprocess.run',side_effect=AssertionError('revision must not execute tools')):
            revise_comparison_package(package=leaf,output=revised,interface=interface,
                assumptions=[*before['assumptions'],'A reviewed boundary clarification'])
            after,new_interface=load_comparison_package(revised)
            self.assertNotEqual(after['composition'],before['composition'])
            self.assertNotEqual(new_interface.intent_sha256,old_interface.intent_sha256)
            self.assertEqual(after['requirements'],before['requirements'])
            self.assertEqual((revised/'source/body.c').read_bytes(),source.read_bytes())
            self.assertEqual(after['original'],before['original'])
            self.assertEqual(load_comparison_package(leaf)[0],before)
            with self.assertRaisesRegex(ValueError,'dependency contract changed for leaf'):
                start_comparison_package(package=root,output=self.root/'rejected',target_id='fixture',component_id='root',
                    dependency_packages={'leaf':revised})
            self.assertFalse((self.root/'rejected').exists())
        result=run_comparison(package=revised,output=self.root/'revised-check',target_id='fixture',component_id='leaf')
        self.assertEqual(result['status'],'match')

    def test_named_refinement_keeps_shared_consumers_explicit_and_reuses_compilation(self):
        import contextlib
        import io
        from spaghetti_extractor.cli import main

        def start(package,output,*reviews,expected=0):
            capture=io.StringIO()
            with contextlib.redirect_stdout(capture),contextlib.redirect_stderr(capture):
                result=main(['component','start','fixture',load_comparison_package(package)[0]['component_id'],
                    '--comparison-package',str(package),'--output',str(output),
                    *[part for name,path in reviews for part in ('--refine-requirement',name+'='+str(path))]])
            self.assertEqual(result,expected,capture.getvalue())
            return capture.getvalue()

        root,mid,leaf=self.chain()
        source=root/'source/body.c';source.write_text(source.read_text()+'\n/* local caller edit */\n')
        (root/'operator-notes.txt').write_text('keep the caller analysis')
        baseline=run_comparison(package=root,output=self.root/'before',target_id='fixture',component_id='root')
        self.assertEqual(baseline['status'],'match')
        before,_=load_comparison_package(root)
        leaf_plan,_=load_comparison_package(leaf)
        revised_leaf=self.root/'reviewed-leaf';revised_mid=self.root/'reviewed-mid';revised_root=self.root/'reviewed-root'
        with patch('subprocess.Popen',side_effect=AssertionError('refinement must not execute tools')):
            revise_comparison_package(package=leaf,output=revised_leaf,
                assumptions=[*leaf_plan['assumptions'],'Reviewed caller premise'])
            from spaghetti_extractor.components.comparison_contract_diagnostics import dependency_contract_preview,describe_contract_changes
            preview=dependency_contract_preview(root,before,{'leaf':revised_leaf})
            self.assertIn('+ "Reviewed caller premise"',describe_contract_changes(preview[0]['changes']))
            text=start(root,self.root/'missing-review',('leaf',revised_leaf),expected=2)
            self.assertIn('supplier contract changed for mid/leaf',text)
            self.assertFalse((self.root/'missing-review').exists())
            text=start(mid,revised_mid,('leaf',revised_leaf))
            self.assertIn('reviewed caller requirements: leaf',text)
            staged_root=self.root/'staged-root'
            start(root,staged_root,('mid',revised_mid),('leaf',revised_leaf))
            start(root,revised_root,('root/leaf',revised_leaf),('mid/leaf',revised_leaf))
            self.assertEqual(load_comparison_package(revised_root)[0],load_comparison_package(staged_root)[0])
            text=start(root,self.root/'duplicate-review',('leaf',revised_leaf),('root/leaf',revised_leaf),expected=2)
            self.assertIn('reviewed twice: root/leaf',text)
            self.assertFalse((self.root/'duplicate-review').exists())
        after,_=load_comparison_package(revised_root)
        self.assertEqual([r['id'] for r in after['dependencies']],['leaf','mid'])
        self.assertEqual((revised_root/'source/body.c').read_bytes(),source.read_bytes())
        self.assertEqual((revised_root/'operator-notes.txt').read_text(),'keep the caller analysis')
        self.assertTrue((revised_root/'compile_commands.json').is_file())
        self.assertIn('Reviewed caller premise',(revised_root/'dependencies/leaf/generated/workspace.md').read_text())
        self.assertEqual(load_comparison_package(root)[0],before)
        self.assertEqual(after['original'],before['original'])
        result=run_comparison(package=revised_root,output=self.root/'after',target_id='fixture',component_id='root',
            reuse_previous=self.root/'before')
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],0)
        self.assertEqual(result['work_counts']['execution'],2)

    def test_refinement_preserves_independently_edited_compatible_bundled_suppliers(self):
        root,mid,_=self.chain()
        neighbor=root/'dependencies/leaf/source/body.c'
        neighbor.write_text(neighbor.read_text().replace('x+1','1U+x'))
        before=neighbor.read_bytes()
        baseline=self.root/'baseline'
        self.assertEqual(run_comparison(package=root,output=baseline,target_id='fixture',component_id='root')['status'],'match')
        assumptions=load_comparison_package(mid)[0]['assumptions']
        proposed=self.root/'proposed'
        revise_comparison_package(package=mid,output=proposed,assumptions=[*assumptions,'Reviewed input convention'])
        revised=self.root/'revised'
        start_comparison_package(package=root,output=revised,target_id='fixture',component_id='root',
            refine_requirements={'root/mid':proposed})
        self.assertEqual((revised/'dependencies/leaf/source/body.c').read_bytes(),before)
        result=run_comparison(package=revised,output=self.root/'after',target_id='fixture',component_id='root',reuse_previous=baseline)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],0)

    def test_revise_selected_supplier_without_local_setup_retains_consumers_and_requires_reviews(self):
        root,mid,leaf=self.chain()
        before,_=load_comparison_package(root)
        selected=next(unit for unit in before['dependencies'] if unit['id']=='leaf')
        baseline=self.root/'before'
        self.assertEqual(run_comparison(package=root,output=baseline,target_id='fixture',component_id='root')['status'],'match')
        shutil.rmtree(mid);shutil.rmtree(leaf)
        source=self.root/'renamed.c';source.write_text((root/selected['sources'][0]).read_text().replace('x+1','x+1U'))
        header=self.root/'adapter-note.h';header.write_text('/* Reviewed scalar transport. */\n')
        bridge=self.root/'entry.c';bridge.write_text('#include "adapter-note.h"\n'+(root/selected['adapters'][0]).read_text())
        revised=self.root/'revised'
        from spaghetti_extractor.operator.local_comparison_recipe import write_boundary_revision_recipe
        recipe=root/write_boundary_revision_recipe(root,target='fixture',component='leaf',plan=before)
        with self.assertRaisesRegex(ValueError,'fill boundary_changes'):
            runpy.run_path(str(recipe))['revise'](revised)
        self.assertFalse(revised.exists())
        recipe.write_text(recipe.read_text().replace('    return {}\n',
            '    return dict(assumptions=[*unit["assumptions"], "Caller inputs were reviewed for the selected scalar domain."],\n'
            f'        source_files={{"renamed.c": Path({str(source)!r})}},\n'
            f'        adapter_files={{"entry.c": Path({str(bridge)!r})}},\n'
            f'        include_files={{"adapter-note.h": Path({str(header)!r})}})\n'))
        authored_recipe=recipe.read_bytes()
        write_boundary_revision_recipe(root,target='fixture',component='leaf',plan=before)
        self.assertEqual(recipe.read_bytes(),authored_recipe)
        revise=runpy.run_path(str(recipe))['revise']
        with patch('subprocess.Popen',side_effect=AssertionError('boundary revision must not launch tools')):
            with self.assertRaisesRegex(ValueError,'needs reviewed requirements: mid/leaf, root/leaf'):
                revise(revised)
            self.assertFalse(revised.exists())
            revise(revised,reviewed_requirements=['root/leaf','mid/leaf'])
        after,_=load_comparison_package(revised)
        for field in ('component_id','original','cases','observation_fields','tools','adapters','sources'):
            self.assertEqual(after[field],before[field])
        revised_leaf=next(unit for unit in after['dependencies'] if unit['id']=='leaf')
        self.assertEqual(revised_leaf['sources'],['dependencies/leaf/source/renamed.c'])
        self.assertEqual(revised_leaf['adapters'],['dependencies/leaf/bridges/entry.c'])
        for unit in [before,*before['dependencies']]:
            if unit is selected:continue
            for name in unit['sources']+unit['adapters']:
                self.assertEqual((revised/name).read_bytes(),(root/name).read_bytes())
        self.assertEqual(load_comparison_package(root)[0],before)
        result=run_comparison(package=revised,output=self.root/'after',target_id='fixture',component_id='root',reuse_previous=baseline)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],2)
        self.assertEqual(result['work_counts']['execution'],2)
        # A reviewed boundary does not hide a wrong implementation from either caller.
        body=revised/'dependencies/leaf/source/renamed.c'
        body.write_text(body.read_text().replace('x+1U','x+2U'))
        wrong=run_comparison(package=revised,output=self.root/'wrong',target_id='fixture',component_id='root',reuse_previous=self.root/'after')
        self.assertEqual(wrong['status'],'mismatch')
        self.assertEqual(wrong['work_counts']['compiler'],1)
        with self.assertRaisesRegex(ValueError,'retains the enclosing execution and selection'):
            revise_comparison_package(package=root,output=self.root/'wrong-scope',component_id='leaf',cases=[dict(id='new',arguments=['7'])])

    def test_selected_caller_adds_supplier_without_rebuilding_its_local_fixture(self):
        root,_,_=self.chain()
        neighbor=root/'dependencies/leaf/source/body.c'
        neighbor.write_text(neighbor.read_text().replace('x+1','1U+x'))
        before,_=load_comparison_package(root)
        selected=next(unit for unit in before['dependencies'] if unit['id']=='mid')
        baseline=self.root/'baseline'
        self.assertEqual(run_comparison(package=root,output=baseline,target_id='fixture',component_id='root')['status'],'match')
        extra=self.make('extra','x')
        addition=bind_dependencies(consumers={'extra':extra})
        revised=self.root/'revised'
        with self.assertRaisesRegex(ValueError,'no requirement path'):
            revise_comparison_package(package=root,output=revised,component_id='mid',dependencies=addition['dependencies'])
        self.assertFalse(revised.exists())
        source=self.root/'mid.c'
        source.write_text((root/selected['sources'][0]).read_text().replace(
            'extern uint32_t exported_leaf','extern uint32_t exported_extra(uint32_t);\nextern uint32_t exported_leaf'
        ).replace('exported_leaf(x)+1','exported_extra(exported_leaf(x))+1'))
        with patch('subprocess.Popen',side_effect=AssertionError('selection preparation must not launch tools')):
            revise_comparison_package(package=root,output=revised,component_id='mid',
                source_files={'body.c':source},dependencies=addition['dependencies'],
                requirements=[*selected['requirements'],*addition['requirements']])
        after,_=load_comparison_package(revised)
        for field in ('component_id','original','cases','observation_fields','tools','sources','adapters','requirements'):
            self.assertEqual(after[field],before[field])
        for unit in [before,*before['dependencies']]:
            if unit is selected:continue
            for name in unit['sources']+unit['adapters']:
                self.assertEqual((revised/name).read_bytes(),(root/name).read_bytes())
        self.assertEqual(after['composition']['nodes']['extra']['required_by'],
            [dict(component='mid',requirement='extra',kind='consumer')])
        result=run_comparison(package=revised,output=self.root/'after',target_id='fixture',component_id='root',reuse_previous=baseline)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],3)
        self.assertEqual(load_comparison_package(root)[0],before)

    def test_reviewed_caller_refinement_imports_new_transitive_supplier(self):
        root,mid,_=self.chain()
        neighbor=root/'dependencies/leaf/source/body.c'
        neighbor.write_text(neighbor.read_text().replace('x+1','1U+x'))
        retained=neighbor.read_bytes()
        extra=self.make('extra','x')
        binding=bind_dependencies(consumers={'extra':extra})
        before,_=load_comparison_package(mid)
        source=self.root/'new-mid.c'
        source.write_text((mid/'source/body.c').read_text().replace(
            'extern uint32_t exported_leaf','extern uint32_t exported_extra(uint32_t);\nextern uint32_t exported_leaf'
        ).replace('exported_leaf(x)+1','exported_extra(exported_leaf(x))+1'))
        proposed=self.root/'proposed'
        revise_comparison_package(package=mid,output=proposed,source_files={'body.c':source},
            dependencies=binding['dependencies'],requirements=[*before['requirements'],*binding['requirements']])
        from spaghetti_extractor.components.comparison_contract_diagnostics import dependency_contract_preview
        from spaghetti_extractor.operator.comparison_guidance import render_workspace_summary,workspace_view
        with patch('subprocess.Popen',side_effect=AssertionError('proposal inspection must not execute tools')):
            view=workspace_view(root,'fixture','root')
            view['dependency_proposals']=dependency_contract_preview(root,load_comparison_package(root)[0],{'mid':proposed})
            added=next(row for row in view['dependency_proposals'] if row['component_id']=='extra')
            self.assertEqual(added['status'],'added')
            self.assertIsNone(added['previous_contract_sha256'])
            self.assertEqual(added['consumers'],[dict(component='mid',requirement='extra')])
            self.assertEqual(added['current_consumers'],[])
            self.assertEqual(added['transitive_consumers'],['mid','root'])
            self.assertEqual(neighbor.read_bytes(),retained)
            text=render_workspace_summary(view,package=root)
            self.assertIn('contract added',text)
            self.assertIn('component status fixture extra',text)
        with self.assertRaisesRegex(ValueError,'adds unselected supplier'):
            start_comparison_package(package=root,output=self.root/'unreviewed',target_id='fixture',component_id='root',
                dependency_packages={'mid':proposed})
        self.assertFalse((self.root/'unreviewed').exists())
        revised=self.root/'reviewed'
        start_comparison_package(package=root,output=revised,target_id='fixture',component_id='root',
            refine_requirements={'mid':proposed})
        plan,_=load_comparison_package(revised)
        self.assertEqual([u['id'] for u in plan['dependencies']],['extra','leaf','mid'])
        self.assertEqual((revised/'dependencies/leaf/source/body.c').read_bytes(),retained)
        self.assertEqual(plan['composition']['nodes']['extra']['required_by'],
            [dict(component='mid',requirement='extra',kind='consumer')])
        self.assertEqual(run_comparison(package=revised,output=self.root/'checked',target_id='fixture',component_id='root')['status'],'match')

    def test_driver_revision_keeps_selected_c_and_requires_reviewed_original_inputs(self):
        root,_,_=self.chain()
        before,_=load_comparison_package(root)
        baseline=run_comparison(package=root,output=self.root/'before',target_id='fixture',component_id='root')
        self.assertEqual(baseline['status'],'match')
        driver=self.root/'new-driver.c'
        driver.write_text((root/'adapters/driver.c').read_text()+'\n/* reviewed execution adapter */\n')
        context=self.root/'context.txt';context.write_text('reviewed runtime input\n')
        adapters={'bridge.c':root/'adapters/bridge.c','driver.c':driver}
        revised=self.root/'revised'
        with patch('subprocess.Popen',side_effect=AssertionError('revision must not compile or execute')):
            with self.assertRaisesRegex(ValueError,'requires reviewed original_files'):
                revise_comparison_package(package=root,output=revised,adapter_files=adapters)
            self.assertFalse(revised.exists())
            revise_comparison_package(package=root,output=revised,adapter_files=adapters,
                include_files={},runtime_files={'context.txt':context},link_files={},
                compiler=Path(before['tools']['compiler']['path']),runner=None,server=None,
                original_files=['adapters/driver.c','runtime/context.txt'],oracle_kind='fixture')
        after,_=load_comparison_package(revised)
        self.assertEqual(after['composition'],before['composition'])
        self.assertEqual(after['dependencies'],before['dependencies'])
        self.assertEqual(after['tools'],before['tools'])
        self.assertNotEqual(after['original'],before['original'])
        for unit in [before,*before['dependencies']]:
            for name in unit['sources']:
                self.assertEqual((root/name).read_bytes(),(revised/name).read_bytes())
        self.assertEqual(load_comparison_package(root)[0],before)
        result=run_comparison(package=revised,output=self.root/'after',target_id='fixture',component_id='root',
            reuse_previous=self.root/'before')
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts'],dict(compiler=1,link=1,execution=2,model=0,solver=0))

    def test_shared_input_change_names_the_file_and_consumer_before_replacing(self):
        from spaghetti_extractor.components.comparison_contract_diagnostics import dependency_contract_preview
        leaf=self.make('leaf')
        header=leaf/'source/layout.h';header.write_text('/* reviewed shared layout */\n')
        path=leaf/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['representation']=dict(group=dict(id='leaf-layout',label='Leaf layout',members=['leaf']),
            revision='v1',inputs={'layout':'source/layout.h'})
        path.write_text(json.dumps(plan))
        bound=bind_dependencies(consumers={'call':leaf})
        root=self.make('root','exported_leaf(x)',oracle='x+1',
            selections=bound['dependencies'],requirements=bound['requirements'])
        original=(root/'dependencies/leaf/source/layout.h').read_bytes()
        header.write_text('/* clarified shared layout */\n')
        plan,_=load_comparison_package(root)
        preview=dependency_contract_preview(root,plan,{'leaf':leaf})[0]
        self.assertEqual(preview['changes'][0]['field'],'representation.inputs.layout')
        self.assertEqual(preview['consumers'],[dict(component='root',requirement='call')])
        self.assertEqual(preview['transitive_consumers'],['root'])
        with self.assertRaisesRegex(ValueError,'consumers requiring refinement: root/call') as raised:
            run_comparison(package=root,output=self.root/'changed-layout',target_id='fixture',component_id='root',
                dependency_packages={'leaf':leaf})
        self.assertIn('representation.inputs.layout',str(raised.exception))
        self.assertIn(str(header),str(raised.exception))
        self.assertEqual((self.root/'changed-layout/inputs/dependencies/leaf/source/layout.h').read_bytes(),original)
        self.assertFalse(list((self.root/'changed-layout').rglob('*.o')))

    def test_transitive_diamond_compiles_once_and_records_both_reasons(self):
        root,_,_=self.chain();plan,_=load_comparison_package(root)
        self.assertEqual([r['id'] for r in plan['dependencies']],['leaf','mid'])
        self.assertEqual([r['component'] for r in plan['composition']['nodes']['leaf']['required_by']],['mid','root'])
        out=self.root/'check';run_comparison(package=root,output=out,target_id='fixture',component_id='root')
        result=load_comparison_result(out);self.assertEqual(result['status'],'match')
        self.assertEqual(set(result['source_profiles']),{'root','mid','leaf'})
        self.assertNotIn('dependencies/mid/dependencies',str(result['input_sha256s']))
        self.assertFalse((out/'inputs/dependencies/leaf/adapters/driver.c').exists())

    def test_intermediate_package_can_be_edited_without_flattening_its_children(self):
        root,mid,_=self.chain()
        run_comparison(package=root,output=self.root/'before',target_id='fixture',component_id='root')
        source=mid/'source/body.c';source.write_text(source.read_text().replace('exported_leaf(x)+1','exported_leaf(x)+1U'))
        result=run_comparison(package=root,output=self.root/'edited-mid',target_id='fixture',component_id='root',
            dependency_packages={'mid':mid},reuse_previous=self.root/'before')
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['selection_impact']['affected_integrations'],['mid','root'])
        self.assertEqual(result['selection_impact']['unchanged_unit_inputs'],['leaf','root'])

    def test_explicit_parent_and_leaf_edits_compose_in_either_argument_order(self):
        root,mid,leaf=self.chain()
        source=mid/'source/body.c';source.write_text(source.read_text().replace('exported_leaf(x)+1','exported_leaf(x)+3'))
        source=leaf/'source/body.c';source.write_text(source.read_text().replace('x+1','x+2'))
        for n,replacements in enumerate([{'mid':mid,'leaf':leaf},{'leaf':leaf,'mid':mid}]):
            out=self.root/('both-edited-'+str(n))
            run_comparison(package=root,output=out,target_id='fixture',component_id='root',dependency_packages=replacements)
            result=load_comparison_result(out)
            self.assertEqual(result['status'],'mismatch')
            self.assertEqual(result['cases'][0]['observations']['source'],{'value':13})
            self.assertEqual((out/'inputs/dependencies/leaf/source/body.c').read_bytes(),source.read_bytes())
            self.assertEqual(result['composition'],load_comparison_package(root)[0]['composition'])


    def test_explicit_body_override_does_not_accept_changed_contract(self):
        root,mid,leaf=self.chain()
        path=leaf/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['assumptions'].append('new caller restriction');path.write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError,'dependency contract changed for leaf'):
            run_comparison(package=root,output=self.root/'changed-contract',target_id='fixture',component_id='root',
                dependency_packages={'mid':mid,'leaf':leaf})
        self.assertFalse(list((self.root/'changed-contract').rglob('*.o')))

    def test_conflicting_bundled_replacements_still_need_an_explicit_choice(self):
        _,mid,leaf=self.chain()
        right=self.make('right','exported_leaf(x)',oracle='x+1',selections=[dict(id='leaf',package=leaf)])
        top=self.make('top','exported_mid(x)+exported_right(x)',oracle='2*x+3',
            selections=[dict(id='mid',package=mid),dict(id='right',package=right)])
        path=mid/'dependencies/leaf/source/body.c';path.write_text(path.read_text().replace('x+1','x+9'))
        with self.assertRaisesRegex(ValueError,'conflicting replacement selections for leaf'):
            run_comparison(package=top,output=self.root/'ambiguous',target_id='fixture',component_id='top',
                dependency_packages={'mid':mid,'right':right})
        self.assertFalse(list((self.root/'ambiguous').rglob('*.o')))

    def test_missing_supplier_and_same_signature_changed_contract_reject(self):
        leaf=self.make('leaf');req=self.req('needed',leaf)
        with self.assertRaisesRegex(ValueError,'missing supplier leaf required by root/needed'):
            self.make('root',requirements=[req])
        changed=self.root/'changed';shutil.copytree(leaf,changed)
        p=changed/'comparison-plan.json';v=json.loads(p.read_text());v['assumptions'].append('new premise');p.write_text(json.dumps(v))
        with self.assertRaisesRegex(ValueError,'supplier contract changed'):
            self.make('other',selections=[dict(id='leaf',package=changed)],requirements=[req])

    def test_conflicting_transitive_implementations_are_not_silently_overridden(self):
        leaf=self.make('leaf');mid=self.make('mid','exported_leaf(x)',oracle='x+1',selections=[dict(id='leaf',package=leaf)])
        changed=self.root/'changed';shutil.copytree(leaf,changed)
        p=changed/'source/body.c';p.write_text(p.read_text().replace('x+1','x+2'))
        with self.assertRaisesRegex(ValueError,'conflicting selections for leaf'):
            self.make('root',selections=[dict(id='mid',package=mid),dict(id='leaf',package=changed)])

    def test_stale_graph_and_unreachable_selection_reject(self):
        root,_,_=self.chain();p=root/'comparison-plan.json';plan=json.loads(p.read_text())
        plan['composition']['nodes']['leaf']['required_by']=[];p.write_text(json.dumps(plan))
        with self.assertRaisesRegex(ValueError,'graph is stale'):load_comparison_package(root)
        leaf=self.make('unused')
        with self.assertRaisesRegex(ValueError,'no requirement path'):
            self.make('other',selections=[dict(id='unused',package=leaf)],requirements=[])

    def test_program_entries_keep_independent_boundaries_without_invented_calls(self):
        root,_,_=self.chain();plan,_=load_comparison_package(root)
        # The program invokes root and mid independently; mid still requires leaf.
        plan['requirements']=[]
        with self.assertRaisesRegex(ValueError,'no requirement path'):composition_graph(root,plan)
        plan['program_driver']={'entries':['mid','root']}
        graph=composition_graph(root,plan)
        self.assertEqual(graph['program_entries'],['mid','root'])
        self.assertEqual(graph['nodes']['mid']['required_by'],[])
        self.assertEqual([row['consumer'] for row in graph['edges']],['mid'])
        plan['composition']=graph
        impact=selection_impact(plan,['dependencies/mid/source/body.c'])
        self.assertEqual(impact['affected_integrations'],['mid'])
        self.assertTrue(impact['program_integration_affected'])
        self.assertFalse(selection_impact(plan,[])['program_integration_affected'])
        for entries in (None,[],['mid'],['root','mid'],['mid','root','unknown']):
            plan['program_driver']['entries']=entries
            with self.assertRaisesRegex(ValueError,'program entries'):composition_graph(root,plan)

    def test_program_entry_revision_retains_selection_and_rejects_conflicting_shared_body(self):
        root,_,leaf=self.chain()
        other=self.make('other','exported_leaf(x)+3',oracle='x+4',selections=[dict(id='leaf',package=leaf)])
        source=root/'source/body.c';source.write_text(source.read_text()+'\n/* operator draft */\n')
        before,_=load_comparison_package(root)
        image=self.root/'program.exe';image.write_bytes(b'preparation-only program image')
        arguments=dict(package=root,program_entry_packages={'other':other},
            runtime_files={'program.exe':image},original_files=['adapters/driver.c','runtime/program.exe'],
            runner=Path(shutil.which('cc')),program_driver=dict(kind='pe32-import',image='runtime/program.exe',
                library='components.dll',symbol='fixture_anchor'))
        revised=self.root/'program'
        with patch('subprocess.Popen',side_effect=AssertionError('entry preparation must not execute tools')):
            revise_comparison_package(output=revised,**arguments)
            after,_=load_comparison_package(revised)
            self.assertEqual(after['program_driver']['entries'],['other','root'])
            self.assertEqual(after['requirements'],before['requirements'])
            self.assertEqual(after['composition']['nodes']['other']['required_by'],[])
            self.assertEqual([r['component'] for r in after['composition']['nodes']['leaf']['required_by']],
                ['mid','other','root'])
            self.assertEqual(len(after['dependencies']),3)
            self.assertEqual((revised/'source/body.c').read_bytes(),source.read_bytes())
            for unit in before['dependencies']:
                self.assertEqual(next(row for row in after['dependencies'] if row['id']==unit['id']),unit)
                for name in unit['sources']+unit['adapters']:
                    self.assertEqual((revised/name).read_bytes(),(root/name).read_bytes())
            shared=other/'dependencies/leaf/source/body.c';original=shared.read_text()
            shared.write_text(original+'\n/* conflicting selected body */\n')
            with self.assertRaisesRegex(ValueError,'conflicting selections for leaf'):
                revise_comparison_package(output=self.root/'conflict',**arguments)
            self.assertFalse((self.root/'conflict').exists())
            shared.write_text(original)
            revise_comparison_package(output=self.root/'conflict',**arguments)
        self.assertEqual(load_comparison_package(root)[0],before)

    def test_shared_input_revision_requires_named_reviews_and_preserves_selected_c(self):
        from spaghetti_extractor.components.comparison_representation import validate_representation_selection
        header=self.root/'layout.h';header.write_text('struct shared { unsigned count; unsigned flag; };\n')
        representation=dict(group=dict(id='shared-layout',label='Shared layout',members=['leaf','mid']),
            revision='count-first',inputs={'layout':'headers/layout.h'})

        def grouped(package, *, consumers=None):
            plan,_=load_comparison_package(package)
            source=self.root/(plan['component_id']+'-body.c')
            source.write_text('#include "layout.h"\n'+(package/'source/body.c').read_text())
            out=self.root/(plan['component_id']+'-grouped')
            revise_comparison_package(package=package,output=out,source_files={'body.c':source},
                include_files={'layout.h':header},representation=representation,
                **bind_dependencies(consumers=consumers))
            return out

        leaf=grouped(self.make('leaf'))
        mid=grouped(self.make('mid','exported_leaf(x)+1',oracle='x+2'),consumers={'leaf':leaf})
        root=self.make('root','exported_mid(x)+exported_leaf(x)',oracle='2*x+3',
            selections=[dict(id='mid',package=mid),dict(id='leaf',package=leaf)])
        note=root/'operator-notes.txt';note.write_text('Retain the caller analysis.\n')
        before,_=load_comparison_package(root)
        baseline=self.root/'before'
        self.assertEqual(run_comparison(package=root,output=baseline,target_id='fixture',component_id='root')['status'],'match')
        header.write_text('struct shared { unsigned flag; unsigned count; };\n')
        update=dict(revision='flag-first',inputs={'layout':header},reviewed_requirements=['root/leaf'])
        revised=self.root/'revised'
        with patch('subprocess.Popen',side_effect=AssertionError('shared boundary preparation must not execute tools')):
            with self.assertRaisesRegex(ValueError,'needs reviewed requirements: mid/leaf, root/mid'):
                revise_comparison_package(package=root,output=revised,representation_updates={'shared-layout':update})
            self.assertFalse(revised.exists())
            update['reviewed_requirements']=['mid/leaf','root/leaf','root/mid']
            revise_comparison_package(package=root,output=revised,representation_updates={'shared-layout':update})
            after,_=load_comparison_package(revised)
            self.assertEqual(after['original'],before['original'])
            self.assertEqual((revised/'operator-notes.txt').read_bytes(),note.read_bytes())
            for unit in [before,*before['dependencies']]:
                for name in unit['sources']+unit['adapters']+[unit['interface']]:
                    self.assertEqual((revised/name).read_bytes(),(root/name).read_bytes())
            group=validate_representation_selection(revised,after,complete=True)['shared-layout']
            self.assertEqual(group['binding']['revision'],'flag-first')
            self.assertEqual(after['composition']['nodes']['leaf']['required_by'],before['composition']['nodes']['leaf']['required_by'])
            self.assertNotEqual(after['requirements'],before['requirements'])
            # An isolated unit stays an incomplete group after local preparation.
            local=self.root/'local-revised'
            revise_comparison_package(package=leaf,output=local,representation_updates={
                'shared-layout':{**update,'reviewed_requirements':[]}})
            local_plan,_=load_comparison_package(local)
            self.assertEqual(validate_representation_selection(local,local_plan)['shared-layout']['missing_members'],['mid'])
            # Shared authoring input changes cannot silently rebind the oracle.
            pinned=self.root/'pinned'
            revise_comparison_package(package=root,output=pinned,
                original_files=[*before['original']['files'],'dependencies/leaf/headers/layout.h'])
            with self.assertRaisesRegex(ValueError,'cannot rewrite an original oracle input'):
                revise_comparison_package(package=pinned,output=self.root/'bad-oracle',representation_updates={'shared-layout':update})
            self.assertFalse((self.root/'bad-oracle').exists())
        result=run_comparison(package=revised,output=self.root/'after',target_id='fixture',component_id='root',reuse_previous=baseline)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],2)
        self.assertEqual(load_comparison_package(root)[0],before)

    def test_resolver_rejects_mixed_shared_representations_before_compilation(self):
        leaf=self.make('leaf');sibling=self.make('sibling')
        for package,revision in [(leaf,'raw'),(sibling,'handles')]:
            p=package/'comparison-plan.json';plan=json.loads(p.read_text())
            (package/'source/layout.h').write_text('/* '+revision+' */\n')
            plan['representation']=dict(group=dict(id='values',label='Shared values',members=['leaf','sibling']),
                revision=revision,inputs={'layout':'source/layout.h'})
            p.write_text(json.dumps(plan))
        # Both packages are legitimate partial local groups. Resolving them
        # together must reject the inconsistent private representation.
        load_comparison_package(leaf);load_comparison_package(sibling)
        with self.assertRaisesRegex(ValueError,'incompatible representation selection'):
            self.make('root',selections=[dict(id='leaf',package=leaf),dict(id='sibling',package=sibling)])
        self.assertFalse(list((self.root/'root').rglob('*.o')))

    def test_explicit_internal_recursion_is_non_authorizing_and_unsupported_modes_reject(self):
        root=self.make('root','x==0 ? 0 : lifted_root(ctx,x-1)+1',oracle='x')
        p=root/'comparison-plan.json';plan,_=load_comparison_package(root)
        plan['requirements']=[self.req('recursive-call',root,kind='internal')]
        with self.assertRaisesRegex(ValueError,'explicit synchronous-comparison group'):
            composition_graph(root,plan)
        plan['recursion_groups']=[dict(id='root-recursion',members=['root'],mode='synchronous-comparison',progress='unproved')]
        plan['composition']=composition_graph(root,plan);p.write_text(json.dumps(plan))
        result=run_comparison(package=root,output=self.root/'recursive',target_id='fixture',component_id='root')
        self.assertEqual(result['status'],'match');self.assertFalse(result['authorizing'])
        plan['recursion_groups'][0]['mode']='async-callback'
        with self.assertRaisesRegex(ValueError,'unsupported recursive selection'):composition_graph(root,plan)

    def test_consistent_global_body_replacement_keeps_contract_graph(self):
        root,_,leaf=self.chain()
        old=run_comparison(package=root,output=self.root/'before',target_id='fixture',component_id='root')
        p=leaf/'source/body.c';p.write_text(p.read_text().replace('x+1','x+2'))
        changed=run_comparison(package=root,output=self.root/'after',target_id='fixture',component_id='root',
            dependency_packages={'leaf':leaf},reuse_previous=self.root/'before')
        self.assertEqual(old['status'],'match');self.assertEqual(changed['status'],'mismatch')
        plan,_=load_comparison_package(self.root/'after/inputs')
        self.assertEqual(plan['composition'],load_comparison_package(root)[0]['composition'])
        self.assertIn('dependencies/leaf/source/body.c',changed['reuse']['changed_inputs'])
        self.assertEqual(changed['selection_impact']['affected_integrations'],['leaf','mid','root'])
        self.assertEqual(changed['selection_impact']['unchanged_unit_inputs'],['mid','root'])
        self.assertEqual(load_comparison_result(self.root/'after')['selection_impact'],changed['selection_impact'])
