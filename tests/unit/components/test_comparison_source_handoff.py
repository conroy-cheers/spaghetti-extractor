import json
from unittest.mock import patch
from spaghetti_extractor.components.comparison_package import (
    load_comparison_package,revise_comparison_package,start_comparison_package,
)
from spaghetti_extractor.components.comparison_run import run_comparison,load_comparison_result
TESTKIT={'fixtures':('compiler',)}


from .comparison_composition_fixture import CompositionFixture

class SourceHandoffCompositionTests(CompositionFixture):
    def test_interface_authoring_supplier_checks_under_existing_consumer(self):
        import contextlib
        import io
        from spaghetti_extractor.cli import main

        leaf=self.make('leaf')
        network=self.make('network','exported_leaf(x)',oracle='x+1',selections=[dict(id='leaf',package=leaf)])
        plan,_=load_comparison_package(leaf)
        def command(*args):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
                status=main(['component',*map(str,args)])
            return status,stream.getvalue()
        authoring=self.root/'leaf-authoring'
        code,text=command('start','fixture','leaf','--interface-intent',leaf/'interface.json',
            '--operation-symbol','run=lifted_leaf','--source-file','source/component.c='+str(leaf/plan['sources'][0]),
            '--output',authoring)
        self.assertEqual(code,0,text)
        source=authoring/'source/component.c';source.write_text(source.read_text().replace('x+1','x+2'))
        selection=['--dependency-source','leaf='+str(authoring)]
        with patch('subprocess.Popen',side_effect=AssertionError('draft preview must not execute')):
            code,text=command('status','fixture','network','--comparison-package',network,*selection,'--json')
        self.assertEqual(code,0,text)
        preview=json.loads(text)['dependency_proposals'][0]
        self.assertEqual(preview['status'],'unchanged')
        self.assertEqual(preview['source_kind'],'interface-c-draft')
        self.assertIn('dependencies/leaf/source/component.c',preview['changed_sources'])
        checked=self.root/'consumer-check'
        code,text=command('check','fixture','network','--comparison-package',network,*selection,'--output',checked)
        self.assertEqual(code,2,text);self.assertIn('comparison=mismatch',text)
        result=load_comparison_result(checked)
        self.assertEqual(result['cases'][0]['observations']['source']['value'],
                         result['cases'][0]['observations']['original']['value']+1)
        retained,_=load_comparison_package(network)
        for unit in [retained,*retained['dependencies']]:
            for name in [*unit['adapters'],*unit['sources']]:
                if not name.startswith('dependencies/leaf/source/'):
                    self.assertEqual((checked/'inputs'/name).read_bytes(),(network/name).read_bytes())

    def test_named_c_draft_keeps_selected_neighbors_and_checks_its_own_boundary(self):
        import contextlib
        import io
        from spaghetti_extractor.cli import main

        def cli(action, *options, expected=0):
            text=io.StringIO()
            with contextlib.redirect_stdout(text),contextlib.redirect_stderr(text):
                code=main(['component',action,'fixture','root','--comparison-package',str(root),
                    '--dependency-source','mid='+str(mid),*map(str,options)])
            self.assertEqual(code,expected,text.getvalue())
            return text.getvalue()

        root,mid,_=self.chain()
        neighbor=root/'dependencies/leaf/source/body.c'
        neighbor.write_text(neighbor.read_text().replace('x+1','x+1U'))
        source=mid/'source/body.c'
        source.write_text(source.read_text().replace('exported_leaf(x)+1','exported_leaf(x)+1U'))
        baseline=self.root/'before'
        self.assertEqual(run_comparison(package=root,output=baseline,target_id='fixture',component_id='root')['status'],'match')
        before,_=load_comparison_package(root)
        neighbors={p:(root/p).read_bytes() for unit in before['dependencies'] if unit['id']!='mid'
            for p in unit['sources']+unit['adapters']}
        bridge=root/'dependencies/mid/bridges/bridge.c'
        bridge_bytes=bridge.read_bytes()
        with patch('subprocess.Popen',side_effect=AssertionError('draft preparation must not execute tools')):
            preview=json.loads(cli('status','--json'))['dependency_proposals']
            self.assertEqual([(p['component_id'],p['source_kind']) for p in preview],[('mid','comparison-c-draft')])
            self.assertEqual(preview[0]['changed_sources'],['dependencies/mid/source/body.c'])
            out=self.root/'draft'
            self.assertIn('neighboring selections retained',cli('start','--output',out))
            self.assertEqual((out/'dependencies/mid/source/body.c').read_bytes(),source.read_bytes())
            self.assertEqual((out/bridge.relative_to(root)).read_bytes(),bridge_bytes)
            self.assertEqual({p:(out/p).read_bytes() for p in neighbors},neighbors)
        checked=self.root/'checked'
        cli('check','--reuse-comparison',baseline,'--output',checked)
        result=load_comparison_result(checked)
        self.assertEqual(result['work_counts'],dict(compiler=1,link=1,execution=2,model=0,solver=0))
        self.assertEqual(result['selection_impact']['unchanged_unit_inputs'],['leaf','root'])
        source.write_text(source.read_text().replace('exported_leaf(x)+1U','exported_leaf(x)+3U'))
        wrong=self.root/'wrong'
        cli('check','--reuse-comparison',checked,'--output',wrong,expected=2)
        self.assertEqual(load_comparison_result(wrong)['status'],'mismatch')
        from spaghetti_extractor.components.comparison_source_draft import SourceDraft
        # A named draft can also be read from an existing network workspace.
        selected=self.root/'selected-from-network'
        start_comparison_package(package=root,output=selected,target_id='fixture',component_id='root',
            dependency_packages={'mid':SourceDraft(out)})
        self.assertEqual((selected/'dependencies/mid/source/body.c').read_bytes(),
            (out/'dependencies/mid/source/body.c').read_bytes())
        plan,_=load_comparison_package(mid)
        revised=self.root/'reviewed-mid'
        revise_comparison_package(package=mid,output=revised,
            assumptions=[*plan['assumptions'],'New caller premise'])
        mid=revised
        with patch('subprocess.Popen',side_effect=AssertionError('changed boundary must reject before execution')):
            self.assertIn('source draft boundary differs for mid',
                cli('start','--output',self.root/'incompatible',expected=2))
        self.assertFalse((self.root/'incompatible').exists())
        self.assertEqual(load_comparison_package(root)[0],before)
        self.assertEqual({p:(root/p).read_bytes() for p in neighbors},neighbors)

    def test_named_c_draft_refactors_files_without_replacing_neighbors_or_adapters(self):
        import contextlib
        import io
        from spaghetti_extractor.cli import main
        from spaghetti_extractor.candidate.source_export import export_comparison_sources
        from spaghetti_extractor.components.comparison_contract_diagnostics import dependency_contract_preview
        from spaghetti_extractor.components.comparison_source_draft import SourceDraft

        root,mid,_=self.chain()
        neighbor=root/'dependencies/leaf/source/body.c'
        neighbor.write_text(neighbor.read_text().replace('x+1','x+1U'))
        before,_=load_comparison_package(root)
        baseline=self.root/'before'
        self.assertEqual(run_comparison(package=root,output=baseline,target_id='fixture',component_id='root')['status'],'match')
        entry=self.root/'entry.c';entry.write_text('#include "portable-component-implementation.h"\n'
            '#include "helpers/value.h"\n'
            'uint32_t lifted_mid(spx_mid_context_v5 *ctx,uint32_t x) { (void)ctx;return mid_value(x); }\n')
        header=self.root/'value.h';header.write_text('#include <stdint.h>\nuint32_t mid_value(uint32_t x);\n')
        helper=self.root/'value.c';helper.write_text('#include "value.h"\n'
            'extern uint32_t exported_leaf(uint32_t x);\n'
            'uint32_t mid_value(uint32_t x) { return exported_leaf(x)+1U; }\n')
        refactored=self.root/'refactored'
        revise_comparison_package(package=mid,output=refactored,source_files={
            'entry.c':entry,'helpers/value.c':helper,'helpers/value.h':header},
            private_headers=['source/helpers/value.h'])
        # Reopen the root component too, retaining its own fixture and suppliers.
        local=self.root/'local-refactor'
        start_comparison_package(package=mid,output=local,target_id='fixture',component_id='mid',reuse_source=refactored)
        local_plan,_=load_comparison_package(local)
        self.assertEqual(local_plan['sources'],['source/entry.c','source/helpers/value.c','source/helpers/value.h'])
        self.assertEqual(local_plan['private_headers'],['source/helpers/value.h'])
        self.assertFalse((local/'source/body.c').exists())
        self.assertEqual((local/'adapters/driver.c').read_bytes(),(mid/'adapters/driver.c').read_bytes())
        selection={'mid':SourceDraft(refactored)};prepared=self.root/'prepared'
        old='dependencies/mid/source/body.c'
        added=['dependencies/mid/source/'+name for name in ('entry.c','helpers/value.c','helpers/value.h')]
        def open_files(destination,header_input):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
                code=main(['component','start','fixture','mid','--comparison-package',str(root),
                    '--source-file','source/entry.c='+str(entry),
                    '--source-file','source/helpers/value.c='+str(helper),
                    '--source-file','source/helpers/value.h='+str(header_input),
                    '--remove-source','source/body.c','--private-header','source/helpers/value.h',
                    '--output',str(destination)])
            self.assertEqual(code,0,stream.getvalue())
        with patch('subprocess.Popen',side_effect=AssertionError('file-refactor preparation must not execute tools')):
            preview=dependency_contract_preview(root,before,selection)[0]
            self.assertEqual(preview['status'],'unchanged')
            self.assertEqual(preview['added_sources'],added)
            self.assertEqual(preview['removed_sources'],[old])
            open_files(prepared,header)
            after,_=load_comparison_package(prepared)
            self.assertEqual(after['composition'],before['composition'])
            self.assertFalse((prepared/old).exists())
            self.assertEqual(next(u for u in after['dependencies'] if u['id']=='mid')['sources'],added)
            for unit in [before,*before['dependencies']]:
                names=unit['adapters']+([] if unit.get('id')=='mid' else unit['sources'])
                for name in names:self.assertEqual((prepared/name).read_bytes(),(root/name).read_bytes())
            # A newly declared helper cannot overwrite an unowned local input.
            collision=root/added[-1];collision.parent.mkdir();collision.write_bytes(header.read_bytes())
            with self.assertRaisesRegex(ValueError,'would replace an unowned file'):
                start_comparison_package(package=root,output=self.root/'collision',target_id='fixture',component_id='root',
                    dependency_packages=selection)
            self.assertFalse((self.root/'collision').exists())
            self.assertEqual(collision.read_bytes(),header.read_bytes())
            # Naming that exact new local file explicitly can adopt its bytes;
            # the original package and its still-owned old body remain intact.
            adopted=self.root/'adopted-files'
            open_files(adopted,collision)
            self.assertEqual((adopted/added[-1]).read_bytes(),collision.read_bytes())
            self.assertTrue((root/old).is_file())
            collision.unlink()
        checked=self.root/'checked'
        result=run_comparison(package=prepared,output=checked,target_id='fixture',component_id='root',reuse_previous=baseline)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],2)
        self.assertEqual(result['selection_impact']['unchanged_unit_inputs'],['leaf','root'])
        exported=self.root/'source-project'
        export_comparison_sources(comparisons=[checked],target_id='fixture',output=exported)
        roundtrip=self.root/'roundtrip'
        start_comparison_package(package=root,output=roundtrip,target_id='fixture',component_id='root',
            dependency_packages={'mid':SourceDraft(exported)})
        self.assertEqual(load_comparison_package(roundtrip)[0],after)
        self.assertEqual({name:(roundtrip/name).read_bytes() for name in added},
            {name:(prepared/name).read_bytes() for name in added})
        # A later helper rename changes its private prototype without changing
        # the component boundary or importing another supplier implementation.
        for name in added:
            path=exported/'components/mid/sources'/name.removeprefix('dependencies/mid/')
            path.write_text(path.read_text().replace('mid_value','renamed_value'))
        from spaghetti_extractor.candidate.source_export_bindings import source_export_workspace
        _,edits=source_export_workspace(exported)
        self.assertIn('components/mid/sources/source/helpers/value.h',edits)
        reopened=self.root/'reopened-local'
        start_comparison_package(package=mid,output=reopened,target_id='fixture',component_id='mid',reuse_source=exported)
        self.assertEqual(load_comparison_package(reopened)[0],local_plan)
        self.assertIn('renamed_value',(reopened/'source/helpers/value.h').read_text())
        self.assertFalse((reopened/'source/body.c').exists())
        self.assertEqual((reopened/'dependencies/leaf/source/body.c').read_bytes(),(mid/'dependencies/leaf/source/body.c').read_bytes())
        self.assertEqual(run_comparison(package=reopened,output=self.root/'reopened-check',
            target_id='fixture',component_id='mid')['status'],'match')
        renamed=self.root/'renamed'
        result=run_comparison(package=prepared,output=renamed,target_id='fixture',component_id='root',
            dependency_packages={'mid':SourceDraft(exported)},reuse_previous=checked)
        self.assertEqual(result['status'],'match')
        self.assertEqual(result['work_counts']['compiler'],2)
        self.assertEqual(result['selection_impact']['unchanged_unit_inputs'],['leaf','root'])
        # Changing an existing header's role needs explicit refinement.
        unclassified=self.root/'unclassified'
        revise_comparison_package(package=refactored,output=unclassified,private_headers=None)
        with self.assertRaisesRegex(ValueError,'header roles changed'):
            start_comparison_package(package=prepared,output=self.root/'role-change',target_id='fixture',component_id='root',
                dependency_packages={'mid':SourceDraft(unclassified)})
        self.assertFalse((self.root/'role-change').exists())
        with self.assertRaisesRegex(ValueError,'header roles changed'):
            start_comparison_package(package=unclassified,output=self.root/'reused-role-change',
                target_id='fixture',component_id='mid',reuse_source=unclassified,
                private_headers=['source/helpers/value.h'])
        self.assertFalse((self.root/'reused-role-change').exists())
        with self.assertRaisesRegex(ValueError,'shared or original inputs cannot be private'):
            revise_comparison_package(package=refactored,output=self.root/'private-shared-header',representation=dict(
                group=dict(id='shared-mid',label='Shared mid layout',members=['mid']),revision='v1',
                inputs={'layout':'source/helpers/value.h'}))
