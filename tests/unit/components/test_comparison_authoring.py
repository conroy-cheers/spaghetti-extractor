from __future__ import annotations
import json
from pathlib import Path
import runpy
import shlex
import shutil
import subprocess
from unittest.mock import patch
from spaghetti_extractor.components.comparison_package import prepare_comparison_package,load_comparison_package,retained_comparison_environment
from spaghetti_extractor.components.comparison_run import load_comparison_result
TESTKIT = {'fixtures':('compiler',),'commands':('component start','component check','component status'),
           'resources':('tests/fixtures/jq-array-concat',)}


from .comparison_fixture import ComparisonFixture

class ComponentAuthoringTests(ComparisonFixture):
    def test_interface_revision_carries_current_c_and_helpers_before_comparison(self):
        from spaghetti_extractor.components.service_authoring import component_interface

        types=[dict(id='u32',kind='integer',signed=False,width_bits=32)]
        declaration=self.root/'revision-interface.json'
        def boundary(parameters):
            intent=component_interface(component_id='increment',types=types,
                parameters=parameters,result='u32',services={})
            declaration.write_text(json.dumps(intent.to_payload()))
        boundary([('value','u32')])
        entry=self.root/'entry.c'
        entry.write_text('#include "portable-component-implementation.h"\n#include "math/add.h"\n'
            'uint32_t increment(spx_increment_context_v5 *context, uint32_t value) {\n'
            '(void)context; return add_one(value); }\n')
        helper=self.root/'add.c';helper.write_text('#include "add.h"\nuint32_t add_one(uint32_t value) { return value+1U; }\n')
        header=self.root/'add.h';header.write_text('#include <stdint.h>\nuint32_t add_one(uint32_t value);\n')
        compiler=self.root/'authoring-cc'
        compiler.write_text('#!/bin/sh\nexec '+shlex.quote(shutil.which('cc'))+' "$@"\n');compiler.chmod(0o755)
        original=self.root/'authoring-before'
        common=['start','fixture','increment','--interface-intent',str(declaration)]
        code,text=self.command(*common,'--operation-symbol','run=increment','--compiler',str(compiler),
            '--private-header','source/math/add.h','--source-file','source/component.c='+str(entry),
            '--source-file','source/math/add.c='+str(helper),'--source-file','source/math/add.h='+str(header),
            '--output',str(original))
        self.assertEqual(code,0,text)
        # Preserve edits made after the initial workspace was generated.
        (original/'source/math/add.h').write_text(header.read_text()+'/* reviewed helper */\n')
        before={str(p.relative_to(original)):p.read_bytes() for p in original.rglob('*') if p.is_file()}
        boundary([('value','u32'),('bias','u32')])
        revised=self.root/'authoring-after'
        with patch('subprocess.Popen',side_effect=AssertionError('revision must not build or execute')):
            code,text=self.command(*common,'--reuse-source',str(original),'--output',str(revised))
        self.assertEqual(code,0,text);self.assertIn('carried 3 authored',text)
        self.assertFalse((revised/'comparison-plan.json').exists())
        for name in ('source/component.c','source/math/add.c','source/math/add.h'):
            self.assertEqual((revised/name).read_bytes(),before[name])
        self.assertNotEqual((revised/'generated/portable-component-implementation.h').read_bytes(),
                            before['generated/portable-component-implementation.h'])
        self.assertIn('uint32_t bias',(revised/'generated/component-skeleton.c').read_text())
        editor=json.loads((revised/'compile_commands.json').read_text())
        self.assertEqual({row['arguments'][0] for row in editor},{str(compiler)})
        self.assertEqual((original/'authoring.json').read_bytes(),(revised/'authoring.json').read_bytes())
        self.assertEqual({row['file'] for row in editor},
            {str(revised/'source/component.c'),str(revised/'source/math/add.c')})
        entry_command=next(row for row in editor if row['file'].endswith('/component.c'))
        mismatch=subprocess.run(entry_command['arguments'],capture_output=True,text=True)
        self.assertNotEqual(mismatch.returncode,0)
        self.assertIn('conflicting types',mismatch.stderr)
        source=revised/'source/component.c'
        source.write_text(source.read_text().replace('uint32_t value)', 'uint32_t value, uint32_t bias)')
                          .replace('return add_one(value);','return add_one(value)+bias;'))
        inputs=runpy.run_path(str(revised/'prepare.py'))['source_inputs']()
        self.assertEqual(set(inputs['source_files']),{'component.c','math/add.c','math/add.h'})
        self.assertEqual(inputs['private_headers'],['source/math/add.h'])
        driver=self.root/'revision-driver.c'
        driver.write_text('#include <stdio.h>\n#include <string.h>\n#include "portable-component-implementation.h"\n'
            'int main(int argc,char **argv) { (void)argc;\n'
            'uint32_t result=!strcmp(argv[1],"original") ? 10U : increment(0,2U,7U);\n'
            'printf("{\\"value\\":%u}\\n",result); return 0; }\n')
        package=self.root/'revised-comparison'
        prepare_comparison_package(**inputs,adapter_files={'driver.c':driver},include_files={},
            original_files=['adapters/driver.c'],oracle_kind='fixture',cases=[dict(id='bias',arguments=[])],
            observation_fields=['value'],assumptions=['synthetic boundary revision'],scope='revised interface handoff',
            output=package,**retained_comparison_environment(self.package))
        code,text=self.command('check','fixture','increment','--comparison-package',str(package),
            '--output',str(self.root/'revised-check'))
        self.assertEqual(code,0,text)
        self.assertEqual({str(p.relative_to(original)):p.read_bytes() for p in original.rglob('*') if p.is_file()},before)
        rejected=self.root/'rejected-authoring'
        code,text=self.command(*common,'--reuse-source',str(original),'--source-file','../escape.c='+str(entry),
            '--output',str(rejected))
        self.assertEqual(code,2,text);self.assertFalse(rejected.exists())

    def test_interface_revision_retains_group_choices_without_executing_recipe(self):
        from spaghetti_extractor.components.service_authoring import OperationDefinition,component_interface

        declaration=self.root/'group.json'
        types=[dict(id='u32',kind='integer',signed=False,width_bits=32)]
        def boundary(names):
            intent=component_interface(component_id='group',types=types,services={},
                operations={name:OperationDefinition([('value','u32')],'u32') for name in names})
            declaration.write_text(json.dumps(intent.to_payload()))
        boundary(['read','write'])
        original=self.root/'group-before'
        common=['start','fixture','group','--interface-intent',str(declaration)]
        code,text=self.command(*common,'--operation-symbol','read=read_item','--operation-symbol','write=write_item',
            '--output',str(original))
        self.assertEqual(code,0,text)
        (original/'prepare.py').write_text('raise AssertionError("must not execute previous recipe")\n')
        boundary(['read','clear'])
        revised=self.root/'group-after'
        with patch('subprocess.Popen',side_effect=AssertionError('reopening must not execute tools')):
            code,text=self.command(*common,'--reuse-source',str(original),'--output',str(revised))
        self.assertEqual(code,0,text)
        inputs=runpy.run_path(str(revised/'prepare.py'))['source_inputs']()
        self.assertEqual(inputs['operation_symbols'],dict(read='read_item',clear='lifted_group_clear'))
        header=(revised/'generated/portable-component-implementation.h').read_text()
        self.assertIn('read_item(',header);self.assertNotIn('write_item(',header)
        self.assertIn('lifted_group_clear(',header)
        # Losing an explicit tool must not silently switch the adapter ABI.
        choices=json.loads((revised/'authoring.json').read_text())
        choices['compiler']=str(self.root/'missing-compiler')
        (revised/'authoring.json').write_text(json.dumps(choices))
        rejected=self.root/'group-rejected'
        code,text=self.command(*common,'--reuse-source',str(revised),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('--compiler FILE',text);self.assertFalse(rejected.exists())
        overridden=self.root/'group-overridden'
        code,text=self.command(*common,'--reuse-source',str(revised),'--compiler',shutil.which('cc'),
            '--operation-symbol','read=reviewed_read','--output',str(overridden))
        self.assertEqual(code,0,text)
        inputs=runpy.run_path(str(overridden/'prepare.py'))['source_inputs']()
        self.assertEqual(inputs['operation_symbols'],dict(read='reviewed_read',clear='lifted_group_clear'))

    def test_interface_authoring_prepares_adapters_before_a_comparison(self):
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,component_interface,service_catalog
        from spaghetti_extractor.components.resource_authoring import component_resource_checks

        types=[dict(id='u32',kind='integer',signed=False,width_bits=32)]
        services={'step':ServiceDefinition.create(identity='fixture.step',types=types,
            parameters=[('value','u32')],result='u32',resources=[],effects=['fixture.increment'],
            outcomes=['return'],nonlocal_outcomes=['fail'],unobserved=['Synthetic scalar backend only.'])}
        interface=component_interface(component_id='adder',parameters=[('value','u32')],result='u32',services=services)
        resources=component_resource_checks(interface,consumes=[],produces=[],resource_kind='fixture-token',
            provider_domain='fixture',service_id='step',interaction_contract_id='fixture.entry',
            instrumented_sides=['source'],unobserved=['Numeric-only operation; no heap coverage.'],capacity=8,frame_capacity=4)
        resource_file=self.root/'resources.json';resource_file.write_text(json.dumps(resources))
        declaration=self.root/'adder.json';declaration.write_text(json.dumps(interface.to_payload()))
        catalog=self.root/'catalog.json';catalog.write_text(json.dumps(service_catalog(services).to_payload()))
        bridge=dict(native_symbol='fixture_adder',transports={},adapters={
            'step':dict(symbol='lower_step',kind='portable',outcomes={'return':None})})
        binding=self.root/'bridge.json';binding.write_text(json.dumps(bridge))
        source=self.root/'adder.c';source.write_text('#include "portable-component-implementation.h"\n'
            'uint32_t lifted_adder_run(spx_adder_context_v5 *ctx, uint32_t value) {\n'
            'return ctx->services->step(ctx->services->context,value); }\n')
        header=self.root/'backend.h';header.write_text('#include <stdint.h>\n'
            'uint32_t lower_step(uint32_t);\nuint32_t fixture_adder(uint32_t);\n')
        adapter=self.root/'backend.c';adapter.write_text('#include "portable-component-implementation.h"\n'
            '#include "backend.h"\nuint32_t lower_step(uint32_t value) { return value+1U; }\n'
            '#include "comparison-service-bridge.h"\n')
        driver=self.root/'adapter-driver.c';driver.write_text('#include <stdio.h>\n#include <string.h>\n'
            '#include "backend.h"\nint main(int argc, char **argv) { (void)argc;\n'
            'uint32_t value=!strcmp(argv[1],"original") ? 10U : fixture_adder(9U);\n'
            'printf("{\\"value\\":%u}\\n",value); return 0; }\n')
        authored=self.root/'adapter-authoring'
        with patch('subprocess.Popen',side_effect=AssertionError('adapter preparation must not execute tools')):
            code,text=self.command('start','fixture','adder','--interface-intent',str(declaration),
                '--service-catalog',str(catalog),'--service-bridge',str(binding),'--resource-checks',str(resource_file),
                '--source-file','source/component.c='+str(source),'--adapter-file','backend.c='+str(adapter),
                '--adapter-file','driver.c='+str(driver),'--include-file','backend.h='+str(header),
                '--output',str(authored))
        self.assertEqual(code,0,text)
        self.assertFalse((authored/'comparison-plan.json').exists())
        self.assertIn('lower_step',(authored/'BOUNDARY.md').read_text())
        self.assertIn('adapters/backend.c',(authored/'BOUNDARY.md').read_text())
        self.assertIn('`BOUNDARY.md`',(authored/'AUTHORING.md').read_text())
        self.assertTrue((authored/'generated/service-coverage.json').is_file())
        editor=json.loads((authored/'compile_commands.json').read_text())
        self.assertEqual(len(editor),5)
        self.assertEqual({Path(row['file']).name for row in editor if '/generated/' in row['file']},
                         {'comparison-resources.c','comparison-services.c'})
        for row in editor:
            compiled=subprocess.run(row['arguments'],capture_output=True,text=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
        def prepare(work,name):
            recipe=work/'prepare.py'
            recipe.write_text(recipe.read_text().replace('environment = None','environment = host_environment()'))
            functions=runpy.run_path(str(recipe))
            inputs={**functions['source_inputs'](),**functions['comparison_inputs']()}
            self.assertEqual(inputs['service_bridge'],bridge)
            self.assertEqual(inputs['resource_checks'],resources)
            self.assertEqual(set(inputs['adapter_files']),{'backend.c','driver.c'})
            self.assertEqual(set(inputs['include_files']),{'backend.h'})
            output=self.root/name
            prepare_comparison_package(**{**inputs,'original_files':['adapters/driver.c'],'oracle_kind':'fixture',
                'cases':[dict(id='nine',arguments=[])],'observation_fields':['value'],
                'assumptions':['synthetic backend handoff'],'scope':'interface-first adapters','output':output})
            return output
        package=prepare(authored,'adapters-ready')
        code,text=self.command('check','fixture','adder','--comparison-package',str(package),
            '--output',str(self.root/'adapters-checked'))
        self.assertEqual(code,0,text)
        (authored/'adapters/backend.c').write_text(adapter.read_text().replace('value+1U','value+2U'))
        revised=self.root/'adapters-revised'
        code,text=self.command('start','fixture','adder','--interface-intent',str(declaration),
            '--reuse-source',str(authored),'--output',str(revised))
        self.assertEqual(code,0,text)
        self.assertEqual((revised/'adapters/backend.c').read_bytes(),(authored/'adapters/backend.c').read_bytes())
        self.assertEqual((revised/'headers/backend.h').read_bytes(),header.read_bytes())
        self.assertEqual((revised/'service-bridge.json').read_bytes(),binding.read_bytes())
        self.assertEqual(json.loads((revised/'resource-checks.json').read_text()),resources)
        wrong=prepare(revised,'adapter-defect')
        code,text=self.command('check','fixture','adder','--comparison-package',str(wrong),
            '--output',str(self.root/'adapter-defect-check'))
        self.assertEqual(code,2,text);self.assertIn('comparison=mismatch',text)
        binding.write_text(json.dumps({**bridge,'adapters':{}}))
        rejected=self.root/'adapters-rejected'
        code,text=self.command('start','fixture','adder','--interface-intent',str(declaration),
            '--reuse-source',str(authored),'--service-bridge',str(binding),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('cover exactly',text);self.assertFalse(rejected.exists())

    def test_interface_authoring_rebinds_resource_settings_during_revision(self):
        from spaghetti_extractor.components.service_authoring import component_interface
        from spaghetti_extractor.components.resource_authoring import component_resource_checks
        from spaghetti_extractor.components.comparison_resources import checked_resource_checks

        types=[dict(id='u32',kind='integer',signed=False,width_bits=32)]
        interface=component_interface(component_id='numeric',types=types,parameters=[('value','u32')],result='u32',services={})
        resources=component_resource_checks(interface,consumes=[],produces=[],resource_kind='fixture-token',
            provider_domain='fixture',service_id='fixture',interaction_contract_id='fixture.entry',
            instrumented_sides=['source'],unobserved=['No heap observations.'],capacity=8,frame_capacity=4)
        declaration=self.root/'numeric.json';declaration.write_text(json.dumps(interface.to_payload()))
        settings=self.root/'numeric-resources.json';settings.write_text(json.dumps(resources))
        original=self.root/'numeric-before'
        code,text=self.command('start','fixture','numeric','--interface-intent',str(declaration),
            '--resource-checks',str(settings),'--output',str(original))
        self.assertEqual(code,0,text)
        types.append(dict(id='other',kind='integer',signed=False,width_bits=16))
        revised=component_interface(component_id='numeric',types=types,parameters=[('value','u32')],result='u32',services={})
        declaration.write_text(json.dumps(revised.to_payload()))
        output=self.root/'numeric-after'
        code,text=self.command('start','fixture','numeric','--interface-intent',str(declaration),
            '--reuse-source',str(original),'--output',str(output))
        self.assertEqual(code,0,text)
        carried=json.loads((output/'resource-checks.json').read_text())
        checked_resource_checks(carried,revised)
        self.assertNotEqual(carried,resources)
        self.assertEqual({k:v for k,v in carried.items() if k!='contracts'},
                         {k:v for k,v in resources.items() if k!='contracts'})
        self.assertEqual(carried['contracts'][0]['max_untransferred'],0)
        changed=component_interface(component_id='numeric',types=types,parameters=[('renamed','u32')],result='u32',services={})
        declaration.write_text(json.dumps(changed.to_payload()))
        rejected=self.root/'numeric-rejected'
        code,text=self.command('start','fixture','numeric','--interface-intent',str(declaration),
            '--reuse-source',str(output),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('input/result declarations changed',text)
        self.assertFalse(rejected.exists())

    def test_interface_authoring_keeps_service_knowledge_and_assumptions(self):
        from spaghetti_extractor.components.service_authoring import ServiceDefinition,component_interface,service_catalog

        types=[dict(id='u32',kind='integer',signed=False,width_bits=32),
               dict(id='object',kind='opaque',nominal_id='fixture.object')]
        services={'peek':ServiceDefinition.create(identity='fixture.peek',types=types,
            parameters=[('object','object')],result='u32',
            resources=[dict(root='parameter',value='object',fields=[],transition='borrow_shared',
                            kind='shared-object',domain='fixture')],
            effects=['fixture.object.read'],outcomes=['return'],unobserved=['Concurrent mutation is outside scope.'])}
        intent=component_interface(component_id='reader',parameters=[('input','object')],result='u32',services=services)
        declaration=self.root/'reader.json';declaration.write_text(json.dumps(intent.to_payload()))
        catalog=self.root/'services.json';catalog.write_text(json.dumps(service_catalog(services).to_payload()))
        assumption=self.root/'premise.md';assumption.write_text('The argument names one live shared object.\n')
        original=self.root/'reader-authoring'
        with patch('subprocess.Popen',side_effect=AssertionError('knowledge handoff must not execute tools')):
            code,text=self.command('start','fixture','reader','--interface-intent',str(declaration),
                '--service-catalog',str(catalog),'--assumption-file',str(assumption),'--output',str(original))
        self.assertEqual(code,0,text)
        guide=(original/'BOUNDARY.md').read_text()
        for knowledge in ('borrow_shared','shared-object','fixture.object.read','Concurrent mutation',
                          'one live shared object','source/component.c'):
            self.assertIn(knowledge,guide)
        self.assertFalse((original/'comparison-plan.json').exists())
        revised=self.root/'reader-revised'
        # A revised operation retains the unchanged service declaration and
        # premises; they need not be recovered from the supplier's old recipe.
        changed=component_interface(component_id='reader',parameters=[('other','object')],result='u32',services=services)
        declaration.write_text(json.dumps(changed.to_payload()))
        code,text=self.command('start','fixture','reader','--interface-intent',str(declaration),
            '--reuse-source',str(original),'--output',str(revised))
        self.assertEqual(code,0,text)
        for name in ('service-catalog.json','assumptions.json','source/component.c'):
            self.assertEqual((original/name).read_bytes(),(revised/name).read_bytes())
        self.assertIn('`other: object`',(revised/'BOUNDARY.md').read_text())
        recipe=revised/'prepare.py'
        recipe.write_text(recipe.read_text().replace('environment = None','environment = host_environment()'))
        inputs=runpy.run_path(str(recipe))
        self.assertEqual(inputs['source_inputs']()['service_catalog'],service_catalog(services).to_payload())
        self.assertEqual(inputs['comparison_inputs']()['assumptions'],[assumption.read_text()])
        # Changed service definitions require their new exact catalog. A bare
        # contract ID must not silently discard the retained contract meaning.
        services={'peek':ServiceDefinition.create(identity='fixture.peek',types=types,
            parameters=[('object','object')],result='u32',resources=[],
            effects=['fixture.serialized-read'],outcomes=['return'],unobserved=['Native locking is assumed.'])}
        declaration.write_text(json.dumps(component_interface(component_id='reader',types=types,
            parameters=[('other','object')],result='u32',services=services).to_payload()))
        rejected=self.root/'reader-rejected'
        code,text=self.command('start','fixture','reader','--interface-intent',str(declaration),
            '--reuse-source',str(original),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('bind exactly',text);self.assertFalse(rejected.exists())
        catalog.write_text(json.dumps(service_catalog(services).to_payload()))
        assumption.write_text('Reads are serialized by the lower service.\n')
        code,text=self.command('start','fixture','reader','--interface-intent',str(declaration),
            '--reuse-source',str(original),'--service-catalog',str(catalog),'--assumption-file',str(assumption),
            '--output',str(rejected))
        self.assertEqual(code,0,text)
        self.assertEqual(json.loads((rejected/'assumptions.json').read_text()),[assumption.read_text()])

    def test_first_time_boundary_and_c_files_use_the_public_editing_workflow(self):
        from spaghetti_extractor.components.service_authoring import component_interface

        intent=component_interface(component_id='increment',
            types=[dict(id='unit',kind='void'),dict(id='u32',kind='integer',signed=False,width_bits=32)],
            parameters=[('value','u32')],result='u32',services={})
        declaration=self.root/'increment-interface.json'
        declaration.write_text(json.dumps(intent.to_payload()))
        assumption=self.root/'arithmetic-assumption.md'
        assumption.write_text('defined unsigned arithmetic; synthetic oracle')
        authoring=self.root/'first-authoring'
        start=['start','fixture','increment','--interface-intent',str(declaration),
            '--assumption-file',str(assumption),
            '--operation-symbol','run=increment','--output',str(authoring)]
        with patch('subprocess.Popen',side_effect=AssertionError('first authoring must not build or execute')):
            code,text=self.command(*start)
        self.assertEqual(code,0,text)
        self.assertFalse((authoring/'comparison-plan.json').exists())
        recipe=authoring/'prepare.py'
        recipe_inputs=runpy.run_path(str(recipe))
        with self.assertRaisesRegex(ValueError,'choose host_environment'):
            recipe_inputs['comparison_inputs']()
        source=authoring/'source/component.c'
        body=source.read_text().replace('#error "Implement operation run using the declared boundary"',
            '(void)context; return/**/add_one(value);')
        source.write_text(body.replace('#include "portable-component-implementation.h"',
            '#include "portable-component-implementation.h"\n#include "arithmetic.h"'))
        header=authoring/'source/arithmetic.h'
        header.write_text('static uint32_t add_one(uint32_t value) { return value + 1U; }\n')
        recipe.write_text(recipe.read_text().replace(
            'source_files={"component.c": WORKSPACE / "source/component.c"}',
            'source_files={"increment.c": WORKSPACE / "source/component.c", "arithmetic.h": WORKSPACE / "source/arithmetic.h"}'))
        source_inputs=runpy.run_path(str(recipe))['source_inputs']()
        self.assertEqual(source_inputs['operation_symbols'],{'run':'increment'})
        editor=json.loads((authoring/'compile_commands.json').read_text())[0]
        self.assertEqual(editor['directory'],str(authoring))
        syntax=subprocess.run(editor['arguments'],cwd=editor['directory'],capture_output=True,text=True)
        self.assertEqual(syntax.returncode,0,syntax.stderr)
        edited=source.read_bytes()
        self.assertEqual(self.command(*start)[0],2)
        self.assertEqual(source.read_bytes(),edited)
        driver=self.root/'increment-driver.c'
        driver.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
            '#include "portable-component-implementation.h"\n'
            'int main(int argc,char **argv) { if(argc!=3) return 2;\n'
            'uint32_t value=(uint32_t)strtoul(argv[2],0,10);\n'
            'uint32_t result=!strcmp(argv[1],"original") ? value+1U : increment(0,value);\n'
            'printf("{\\\"value\\\":%u}\\n",result); return 0; }\n')
        package=self.root/'first-package'
        arguments=dict(**source_inputs,adapter_files={'driver.c':driver},include_files={},
            original_files=['adapters/driver.c'],oracle_kind='fixture',
            cases=[dict(id='zero',arguments=['0']),dict(id='wrap',arguments=['4294967295'])],
            observation_fields=['value'],assumptions=['defined unsigned arithmetic; synthetic oracle'],
            scope='first-time interface authoring',output=package,**retained_comparison_environment(self.package))
        # A first boundary often needs corrections. Neither an input mistake
        # nor a rejected declaration should leave debris blocking the retry.
        with self.assertRaisesRegex(ValueError,'original files must name materialized inputs'):
            prepare_comparison_package(**{**arguments,'original_files':['adapters/misspelled.c']})
        self.assertFalse(package.exists())
        package.mkdir()
        with self.assertRaisesRegex(ValueError,'comparison has no cases'):
            prepare_comparison_package(**{**arguments,'cases':[]})
        self.assertEqual(list(package.iterdir()),[])
        prepare_comparison_package(**arguments)
        draft=self.root/'first-draft'
        self.assertEqual(self.command('start','fixture','increment','--comparison-package',str(package),
            '--output',str(draft))[0],0)
        editor_commands=json.loads((draft/'compile_commands.json').read_text())
        adapter_command=next(c for c in editor_commands if c['file']==str(draft/'adapters/driver.c'))
        syntax=subprocess.run(adapter_command['arguments'],cwd=adapter_command['directory'],capture_output=True,text=True)
        self.assertEqual(syntax.returncode,0,syntax.stderr)
        guide=(draft/'generated/workspace.md').read_text()
        self.assertIn('`increment`',guide)
        self.assertIn('defined unsigned arithmetic; synthetic oracle',guide)
        self.assertIn('`wrap`: arguments `4294967295`',guide)
        self.assertIn('../source/arithmetic.h',guide)
        with (patch('spaghetti_extractor.commands.workflows._operator_index',side_effect=AssertionError('workspace inspection must stay local')),
              patch('subprocess.run',side_effect=AssertionError('workspace navigation must not compile or execute'))):
            code,text=self.command('status','fixture','increment','--comparison-package',str(draft),'--json')
        self.assertEqual(code,0,text)
        view=json.loads(text)
        self.assertEqual(view['authority'],'authoring-guidance')
        self.assertEqual(view['assurance'],'not-evaluated')
        self.assertEqual(view['units'][0]['operation_symbols'],{'run':'increment'})
        definition=view['units'][0]['source_navigation']['operations']['run']['definitions'][0]
        self.assertEqual(definition['path'],'source/increment.c')
        self.assertEqual(definition['calls'][0]['expression'],'add_one')
        self.assertEqual(definition['calls'][0]['definitions'][0]['path'],'source/arithmetic.h')
        self.assertIn('source/arithmetic.h',view['knowledge_inputs_sha256'])
        self.assertIn('../source/arithmetic.h#L1',guide)
        result=self.root/'first-result'
        code,text=self.command('check','fixture','increment','--comparison-package',str(draft),'--output',str(result))
        self.assertEqual(code,0,text)
        receipt=load_comparison_result(result)
        self.assertEqual([row['observations']['source']['value'] for row in receipt['cases']],[1,0])
        self.assertFalse(receipt['authorizing'])
        self.assertIn('source/arithmetic.h',receipt['input_sha256s'])
        (authoring/'assumptions.json').write_text(json.dumps(['only zero is admitted']))
        rejected=self.root/'premise-mismatch'
        code,text=self.command('start','fixture','increment','--comparison-package',str(package),
            '--reuse-source',str(authoring),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('authoring assumptions differs',text)
        self.assertFalse(rejected.exists())
        (authoring/'assumptions.json').write_text(json.dumps([assumption.read_text()]))
        # Attach the still-editable interface-first workspace to this explicit
        # execution setup; preparation must neither run its recipe nor check C.
        recipe.write_text('raise RuntimeError("do not execute an authoring recipe during C import")\n')
        source.write_text(source.read_text().replace('return/**/add_one(value)', 'return 1U+add_one(value)'))
        attached=self.root/'attached-authoring'
        with patch('subprocess.Popen',side_effect=AssertionError('C import must not execute tools')):
            code,text=self.command('start','fixture','increment','--comparison-package',str(package),
                '--reuse-source',str(authoring),'--output',str(attached))
        self.assertEqual(code,0,text)
        attached_plan,_=load_comparison_package(attached)
        original_plan,_=load_comparison_package(package)
        for field in ('assumptions','original','adapters','cases','operation_symbols'):
            self.assertEqual(attached_plan[field],original_plan[field])
        self.assertEqual((attached/'source/component.c').read_bytes(),source.read_bytes())
        self.assertFalse((attached/'source/increment.c').exists())
        code,text=self.command('check','fixture','increment','--comparison-package',str(attached),
            '--output',str(self.root/'attached-check'))
        self.assertEqual(code,2,text)
        self.assertIn('comparison=mismatch',text)
        # Interface and shared headers remain explicit rather than inferred
        # compatible from function names or silently taken from the new tree.
        saved=(authoring/'interface.json').read_bytes()
        changed=component_interface(component_id='increment',types=[t.to_payload() for t in intent.schema.types if t.kind!='function'],
            parameters=[('other','u32')],result='u32',services={})
        (authoring/'interface.json').write_text(json.dumps(changed.to_payload()))
        rejected=self.root/'rejected-authoring'
        code,text=self.command('start','fixture','increment','--comparison-package',str(package),
            '--reuse-source',str(authoring),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('interface authoring declaration differs',text)
        self.assertFalse(rejected.exists())
        (authoring/'interface.json').write_bytes(saved)
        header.write_text(header.read_text()+'/* changed shared header */\n')
        code,text=self.command('start','fixture','increment','--comparison-package',str(package),
            '--reuse-source',str(authoring),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('authored header changed',text)
        self.assertFalse(rejected.exists())
        # Compiled header storage is checked even when introduced outside the TU.
        header=draft/'source/arithmetic.h'
        header.write_text(header.read_text()+'\nvolatile uint32_t shared;\n')
        invalid=self.root/'first-invalid'
        self.assertEqual(self.command('check','fixture','increment','--comparison-package',str(draft),
            '--output',str(invalid))[0],2)
        self.assertEqual(load_comparison_result(invalid)['status'],'source-profile-failed')

    def test_workspace_status_refreshes_declarations_and_rejects_wrong_identity(self):
        code,text=self.command('status','fixture','array-concat','--comparison-package',str(self.package),'--json')
        self.assertEqual(code,0,text)
        before=json.loads(text)
        path=self.package/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['assumptions']=['Changed initialization premise; this is not previously tested.']
        path.write_text(json.dumps(plan))
        code,text=self.command('status','fixture','array-concat','--comparison-package',str(self.package),'--json')
        self.assertEqual(code,0,text)
        after=json.loads(text)
        self.assertNotEqual(before['knowledge_inputs_sha256'],after['knowledge_inputs_sha256'])
        self.assertEqual(after['units'][0]['assumptions'],plan['assumptions'])
        self.assertEqual(after['assurance'],'not-evaluated')
        code,text=self.command('status','fixture','other','--comparison-package',str(self.package))
        self.assertNotEqual(code,0)
        self.assertIn('another target/component identity',text)
        code,text=self.command('status','fixture','array-concat','--comparison-package',str(self.package),'--development')
        self.assertNotEqual(code,0)
        self.assertIn('not provider-status filters',text)

    def test_restart_with_revised_boundary_preserves_authored_files_and_rechecks(self):
        from spaghetti_extractor.util import sha256_file

        plan_path=self.package/'comparison-plan.json'
        plan=json.loads(plan_path.read_text());plan['sources'].append('source/notes.h')
        plan_path.write_text(json.dumps(plan))
        (self.package/'source/notes.h').write_text('/* original authored header */\n')
        draft=self.root/'draft'
        self.assertEqual(self.command('start','fixture','array-concat',
            '--comparison-package',str(self.package),'--output',str(draft))[0],0)
        source=draft/'source/component.c'
        source.write_text(source.read_text().replace('a.metadata += b.metadata','a.metadata = b.metadata + a.metadata'))
        (draft/'source/notes.h').write_text('/* retained local header work */\n')
        (draft/'operator-notes.txt').write_text('keep this work')
        code,text,baseline=self.check(draft,'baseline')
        self.assertEqual(code,0,text)
        authored={name:(draft/name).read_bytes() for name in plan['sources']}
        # The revised setup adds a caller case and changes its declared scope.
        plan['cases'].append(dict(id='nine',arguments=['9']))
        plan['assumptions']=['reviewed unsigned addition for these two caller inputs']
        driver=self.package/'adapters/driver.c'
        driver.write_text(driver.read_text()+'\n/* revised observation adapter */\n')
        plan['original']['files']['adapters/driver.c']=sha256_file(driver)
        plan_path.write_text(json.dumps(plan))
        revised=self.root/'revised'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--reuse-source',str(draft),'--output',str(revised))
        self.assertEqual(code,0,text)
        self.assertEqual({n:(revised/n).read_bytes() for n in authored},authored)
        self.assertEqual(json.loads((revised/'comparison-plan.json').read_text()),plan)
        self.assertEqual((revised/'adapters/driver.c').read_bytes(),driver.read_bytes())
        self.assertEqual({n:(draft/n).read_bytes() for n in authored},authored)
        self.assertEqual((draft/'operator-notes.txt').read_text(),'keep this work')
        code,text,out=self.check(revised,'rechecked','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(result['reuse']['status'],'invalidated')
        self.assertEqual(result['work_counts']['execution'],4)
        self.assertEqual([r['observations']['source']['value'] for r in result['cases']],[5,11])
        # An added authored path cannot take over an unowned local input.
        plan['sources'].remove('source/notes.h');plan_path.write_text(json.dumps(plan))
        rejected=self.root/'rejected'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--reuse-source',str(draft),'--output',str(rejected))
        self.assertEqual(code,2,text)
        self.assertIn('would replace an unowned file',text)
        self.assertFalse(rejected.exists())
