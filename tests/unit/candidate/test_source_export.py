"""A source handoff builds after removing the original comparison workspace."""
import contextlib
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import unittest
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.candidate.source_export import export_comparison_sources
from spaghetti_extractor.candidate.source_export_bindings import load_source_export, render_source_service_bridges, source_export_workspace, services_from_source_export
from spaghetti_extractor.components.source import load_component_source_package
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.util import sha256_file
from tests.unit.components import test_comparison as base
from tests.unit.components import test_comparison_dependencies as dependencies

TESTKIT = {'fixtures': ('compiler',), 'commands': ('candidate export', 'component start', 'component check', 'component list'),
           'resources': ('tests/fixtures/jq-array-concat', 'tests/fixtures/jq-array-append')}


class SourceExportTests(unittest.TestCase):
    setUp = base.ComponentComparisonTests.setUp
    command = base.ComponentComparisonTests.command
    check = base.ComponentComparisonTests.check
    supplier = dependencies.ComparisonDependencyTests.supplier
    select = dependencies.ComparisonDependencyTests.select

    def baseline(self, name='baseline'):
        code, text, comparison = self.check(self.package, name)
        self.assertEqual(code, 0, text)
        return comparison

    def service_comparison(self):
        from spaghetti_extractor.components.comparison_package import prepare_comparison_package, retained_comparison_environment
        from spaghetti_extractor.components.service_authoring import ServiceDefinition, component_interface, service_catalog

        types=[dict(id='u32',kind='integer',width_bits=32,signed=False)]
        service=ServiceDefinition.create(identity='fixture.increment',types=types,
            parameters=[('value','u32')],result='u32',resources=[],effects=['fixture.scalar-result'],
            outcomes=['return'],unobserved=['arbitrary backend semantics'])
        interface=component_interface(component_id='consumer',types=types,
            parameters=[('value','u32')],result='u32',services={'increment':service})
        source=self.root/'service.c';source.write_text('#include "portable-component-implementation.h"\n'
            'uint32_t lifted(spx_consumer_context_v5 *ctx,uint32_t value) { return ctx->services->increment(ctx->services->context,value); }\n')
        driver=self.root/'service-driver.c';driver.write_text('#include <stdio.h>\n#include <string.h>\n'
            '#include "portable-component-implementation.h"\n'
            'uint32_t native_increment(uint32_t value) { return value+1U; }\n'
            'uint32_t native_alias(uint32_t value) { return value+1U; }\n'
            '#include "comparison-service-bridge.h"\n'
            'int main(int argc,char **argv) { if(argc!=2) return 2; '
            'printf("{\\\"value\\\":%u}\\n",!strcmp(argv[1],"original")?4U:entry(3U));return 0; }\n')
        spec=dict(native_symbol='entry',transports={},adapters={
            'increment':dict(symbol='native_increment',kind='native',outcomes={'return':None})})
        package=self.root/'consumer-package'
        prepare_comparison_package(interface_package=interface,source_files={'service.c':source},
            operation_symbols={'run':'lifted'},target_id='fixture',component_id='consumer',
            adapter_files={'driver.c':driver},include_files={},original_files=['adapters/driver.c'],
            oracle_kind='fixture',cases=[dict(id='three',arguments=[])],observation_fields=['value'],
            assumptions=['synthetic scalar service'],scope='standalone source binding handoff',
            service_catalog=service_catalog({'increment':service}).to_payload(),service_bridge=spec,
            output=package,**retained_comparison_environment(self.package))
        comparison=self.root/'consumer-check'
        code,text=self.command('check','fixture','consumer','--comparison-package',str(package),'--output',str(comparison))
        self.assertEqual(code,0,text)
        return package,comparison,spec

    def test_service_binding_handoff_runs_after_comparison_removal_and_keeps_distinct_references(self):
        package,comparison,spec=self.service_comparison()
        plan_path=package/'comparison-plan.json';plan=json.loads(plan_path.read_text())
        plan['service_bridge']['adapters']['increment']['symbol']='native_alias'
        plan_path.write_text(json.dumps(plan));other=self.root/'other-service-check'
        code,text=self.command('check','fixture','consumer','--comparison-package',str(package),'--output',str(other))
        self.assertEqual(code,0,text)
        output=self.root/'service-export'
        export_comparison_sources(comparisons=[comparison,other],target_id='fixture',output=output)
        for path in (package,comparison,other):shutil.rmtree(path)
        report=load_source_export(output)
        # Browse and reuse the same declarations after their native comparison
        # folders have gone. Recorded C adapters must stay examples, not choices.
        from spaghetti_extractor.components.service_authoring import component_interface,service_catalog
        with (patch('subprocess.Popen',side_effect=AssertionError('declaration reuse must not execute tools')),
              patch('spaghetti_extractor.commands.workflows._operator_index',side_effect=AssertionError('stay in the source project'))):
            code,text=self.command('list','fixture','--source-project',str(output),'--service','native_alias','--json')
            self.assertEqual(code,0,text)
            view=json.loads(text)
            self.assertEqual(view['origin'],'source-project')
            self.assertEqual(view['assurance'],'not-evaluated')
            declaration=view['groups'][0]['declarations'][0]
            self.assertIsNone(declaration['adapter'])
            self.assertEqual({row['adapter']['symbol'] for row in declaration['binding_examples']},{'native_increment','native_alias'})
            selected=services_from_source_export(output,names={'increment':'consumer/increment','again':'consumer/increment'})
            self.assertEqual(selected['increment'],selected['again'])
            interface=component_interface(component_id='new-consumer',parameters=[('value','u32')],result='u32',services=selected)
            self.assertEqual(len(service_catalog(selected).contracts),1)
            intent=self.root/'new-interface.json';intent.write_text(json.dumps(interface.to_payload()))
            code,text=self.command('start','fixture','new-consumer','--interface-intent',str(intent),
                '--output',str(self.root/'new-authoring'))
            self.assertEqual(code,0,text)
            self.assertIn('(*again)',(self.root/'new-authoring/generated/portable-component.h').read_text())
            code,text=self.command('list','fixture','--source-project',str(output),'--service','increment')
            self.assertEqual(code,0,text)
            self.assertIn('Recorded comparison adapter: native_alias',text)
            self.assertIn('backend binding not selected here',text)
            self.assertIn('services_from_source_export',text)
            code,text=self.command('list','fixture','--source-project',str(output))
            self.assertEqual(code,0,text)
            self.assertIn('consumer: operations run',text)
            self.assertIn('boundary guide:',text)
            with self.assertRaisesRegex(ValueError,'unknown interface services'):
                services_from_source_export(output,names={'bad':'consumer/missing'})
        references=report['components']['consumer']['comparison_binding_references']
        self.assertEqual({r['service_bridge']['adapters']['increment']['symbol'] for r in references},
            {'native_increment','native_alias'})
        self.assertTrue(all(r['original']['kind']=='fixture' for r in report['comparisons']))
        guide=(output/'components/consumer/README.md').read_text()
        for expected in ('fixture.scalar-result', 'arbitrary backend semantics', 'synthetic scalar service',
                         'native_increment', 'native_alias', 'Case names: three', 'Observations: value',
                         'Comparison binding example (not a selected portable backend)'):
            self.assertIn(expected,guide)
        self.assertNotIn(str(self.root),guide)
        with self.assertRaisesRegex(ValueError,'explicit reviewed'):
            render_source_service_bridges(output,bindings={'consumer':None})
        spec['native_symbol']='portable_entry';spec['adapters']['increment']['symbol']='portable_increment'
        generated=render_source_service_bridges(output,bindings={'consumer':spec})
        bridge,coverage=generated['consumer']
        self.assertIn('arbitrary backend semantics',coverage['increment']['unobserved'])
        self.assertNotIn('comparison-resources.h',bridge)
        built=subprocess.run(['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')],cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        # A portable backend needs its own execution check: source provenance
        # and the original fixture comparison cannot validate a changed service.
        for traced in (True,False):
            program_bridge,program_coverage=render_source_service_bridges(output,
                bindings={'consumer':spec},trace_services=traced)['consumer']
            self.assertEqual('call-return-trace' in program_coverage['increment']['generated'],traced)
            if traced:self.assertEqual(program_bridge,bridge)
            for delta,want in [(1,0),(2,1)]:
                (output/'main.c').write_text('#include "portable-component-implementation.h"\n'
                    'static unsigned calls;\n'
                    f'uint32_t portable_increment(uint32_t value) {{ ++calls; return value+{delta}U; }}\n'+program_bridge+
                    'int main(void) { unsigned result=portable_entry(3U); fputs("application diagnostic\\n",stderr); '
                    'return result!=4U || calls!=1; }\n')
                built=subprocess.run([shutil.which('cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-Icomponents/consumer/sources/generated','main.c','liblifted.a','-o','program'],
                    cwd=output,capture_output=True,text=True,timeout=60)
                self.assertEqual(built.returncode,0,built.stderr)
                run=subprocess.run([output/'program'],capture_output=True,timeout=10)
                self.assertEqual(run.returncode,want,run.stderr)
                self.assertIn(b'application diagnostic\n',run.stderr)
                from spaghetti_extractor.components.comparison_services import service_observations
                stream=output/'observed.stderr';stream.write_bytes(run.stderr)
                observation=service_observations(dict(component_id='consumer',
                    service_catalog=report['components']['consumer']['contract']['service_catalog']),{'source':stream})
                self.assertEqual(observation['status'],'satisfied' if traced else 'incomplete')
                if not traced:self.assertEqual(run.stderr,b'application diagnostic\n')

    def test_source_handoff_reader_rejects_stale_inputs_and_changed_service_contracts(self):
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
        package,comparison,spec=self.service_comparison()
        output=self.root/'service-export';report=export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        source=output/'components/consumer/sources/source/service.c';original=source.read_bytes()
        source.write_bytes(original+b'\n/* unrecorded edit */\n')
        with self.assertRaisesRegex(ValueError,'stale or invalid'):load_source_export(output)
        declarations=services_from_source_export(output,names={'increment':'consumer/increment'})
        self.assertEqual(declarations['increment'].identity,'fixture.increment')
        code,text=self.command('list','fixture','--source-project',str(output),'--service','increment','--json')
        self.assertEqual(code,0,text);view=json.loads(text)
        self.assertTrue(view['components']['consumer']['unchecked_c_draft'])
        self.assertEqual(view['knowledge_inputs_sha256'][str(source.relative_to(output))],sha256_file(source))
        code,text=self.command('list','different','--source-project',str(output),'--services')
        self.assertNotEqual(code,0)
        self.assertIn('another target identity',text)
        source.write_bytes(original)
        # Older handoffs still load; generating a binding always requires an
        # explicit selection, even when provenance lacks example bindings.
        manifest=output/'source-export.json';retained=manifest.read_text()
        legacy=json.loads(retained);legacy['components']['consumer'].pop('comparison_binding_references')
        for row in legacy['comparisons']:row.pop('original')
        manifest.write_text(json.dumps(legacy))
        self.assertEqual(set(load_source_export(output)['components']),{'consumer'})
        for broken in [dict(qualification=True),dict(comparisons=[]),dict(components={'consumer':{}})]:
            manifest.write_text(json.dumps({**json.loads(retained),**broken}))
            with self.assertRaises(ValueError):load_source_export(output)
        manifest.write_text(retained)
        unit=report['components']['consumer'];unit['contract']['service_catalog']=None
        unit['contract_sha256']=canonical_sha256_v3(unit['contract'])
        (output/'source-export.json').write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError,'exact service contracts'):
            render_source_service_bridges(output,bindings={'consumer':spec})
        with self.assertRaisesRegex(ValueError,'exact service contracts'):
            services_from_source_export(output,names={'increment':'consumer/increment'})

    def test_public_export_builds_and_runs_without_comparison_or_toolkit(self):
        self.select(self.supplier())
        # A header that was not consumed must not become a build dependency.
        (self.package/'source/not-used.h').write_text('#error fixture only\n')
        (self.package/'source/LICENSE.fixture').write_text('Fixture license retained verbatim.\n')
        comparison = self.baseline()
        output = self.root/'export'
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            result = main(['candidate', 'export', 'fixture', '--comparison', str(comparison), '--output', str(output)])
        self.assertEqual(result, 0, stream.getvalue())
        report = json.loads((output/'source-export.json').read_text())
        self.assertEqual(set(report['components']), {'array-concat', 'array-append'})
        self.assertFalse(report['whole_program_portable'])
        self.assertFalse(report['qualification'])
        for name, digest in report['files'].items(): self.assertEqual(sha256_file(output/name), digest)
        for row in report['components'].values(): load_component_source_package(output/row['source_package'])
        self.assertFalse(list(output.rglob('not-used.h')))
        self.assertEqual(len(list(output.rglob('LICENSE.fixture'))), 1)
        self.assertFalse(list(output.rglob('driver.c')))
        self.assertFalse(list(output.rglob('*.o')))
        self.assertFalse(list(output.rglob('*.exe')))
        self.assertNotIn(str(self.root), (output/'Makefile').read_text())
        self.assertIn('platform/service bindings remain required', stream.getvalue())
        # Follow the supplier's generated commands. Its actual comparison entry
        # is the caller, so checking the supplier as an independent entry fails.
        guide=(output/'components/array-append/README.md').read_text()
        commands=[shlex.split(line) for line in guide.splitlines() if line.startswith('spaghetti')]
        paths={'LOCAL_CHECK':str(comparison),'EXPORTED_LIBRARY':str(output),
            'DRAFT':str(self.root/'guide-draft'),'CHECKS':str(self.root/'guide-checks')}
        for arguments in commands[:2]:
            if arguments[0]=='spaghetti-headless-wayland':arguments=arguments[1:]
            arguments=[paths.get(value,value) for value in arguments[1:]]
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
                result=main(arguments)
            self.assertEqual(result,0,stream.getvalue())
        self.assertTrue((self.root/'guide-checks/latest/comparison-result.json').is_file())
        # Relocate the complete project, then remove all other temporary inputs.
        moved = self.root/'relocated'; output.rename(moved)
        for path in self.root.iterdir():
            if path == moved: continue
            if path.is_dir(): shutil.rmtree(path)
            else: path.unlink()
        index=(moved/'README.md').read_text()
        for identity in report['components']:
            self.assertIn('(components/'+identity+'/README.md)',index)
            guide=(moved/'components'/identity/'README.md').read_text()
            self.assertIn('## Operations and state',guide)
            self.assertIn('(interface.json)',guide)
            self.assertIn('(../../source-export.json)',guide)
            self.assertNotIn(str(self.root),guide)
        # The compiler fixture also supplies a PE32 cross toolchain. Choose the
        # same host compiler for the library and its portable consumer.
        built = subprocess.run(['make', '-j2', 'CC='+shutil.which('cc'), 'AR='+shutil.which('ar')],
            cwd=moved, capture_output=True, text=True, timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)
        # Explicit portable integration supplies the omitted fixture bridge.
        (moved/'main.c').write_text('#include "portable-component-implementation.h"\n'
            'int main(void) { spx_jv_value_v2 a={0},b={0}; a.metadata=3;b.metadata=2;'
            'return lifted_array_concat(0,a,b).metadata!=5; }\n')
        (moved/'binding.c').write_text('#include "portable-component-implementation.h"\n'
            'uint32_t fixture_supplier(uint32_t v) { spx_jv_value_v2 a={0},b={0};b.metadata=v;'
            'return lifted_array_append(0,a,b).metadata; }\n')
        for name, unit in [('main','array-concat'), ('binding','array-append')]:
            result = subprocess.run([shutil.which('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-Icomponents/'+unit+'/sources/generated', '-c', name+'.c', '-o', name+'.o'],
                cwd=moved, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([shutil.which('cc'),'main.o','binding.o','liblifted.a','-o','program'],
            cwd=moved, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([str(moved/'program')], cwd=moved, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_wrong_target_mismatch_stale_evidence_and_nonempty_output(self):
        comparison = self.baseline()
        with self.assertRaisesRegex(ValueError, 'matching comparison'):
            export_comparison_sources(comparisons=[comparison], target_id='wrong', output=self.root/'wrong')
        self.assertFalse((self.root/'wrong').exists())
        output = self.root/'occupied'; output.mkdir(); (output/'keep').write_text('unchanged')
        with self.assertRaisesRegex(ValueError, 'new or empty'):
            export_comparison_sources(comparisons=[comparison], target_id='fixture', output=output)
        self.assertEqual((output/'keep').read_text(), 'unchanged')
        source = self.package/'source/component.c'
        source.write_text(source.read_text().replace('+= b.metadata', '+= b.metadata+1'))
        code, _, wrong = self.check(self.package, 'mismatch'); self.assertEqual(code, 2)
        with self.assertRaisesRegex(ValueError, 'matching comparison'):
            export_comparison_sources(comparisons=[wrong], target_id='fixture', output=self.root/'mismatch-export')
        (comparison/'inputs/source/component.c').write_text('changed\n')
        with self.assertRaises(ValueError):
            export_comparison_sources(comparisons=[comparison], target_id='fixture', output=self.root/'stale-export')
        self.assertFalse((self.root/'stale-export').exists())

    def test_deduplicates_exact_selection_and_rejects_conflicting_bodies(self):
        comparison = self.baseline()
        report = export_comparison_sources(comparisons=[comparison, comparison],
            target_id='fixture', output=self.root/'deduplicated')
        self.assertEqual(len(report['components']), 1)
        source = self.package/'source/component.c'
        source.write_text(source.read_text().replace('a.metadata += b.metadata', 'a.metadata = b.metadata + a.metadata'))
        other = self.baseline('alternative')
        with self.assertRaisesRegex(ValueError, 'conflicting source or boundary'):
            export_comparison_sources(comparisons=[comparison, other], target_id='fixture', output=self.root/'conflict')
        self.assertFalse((self.root/'conflict').exists())

    def test_input_change_during_copy_cannot_publish_an_export(self):
        comparison = self.baseline()

        def changed(**arguments):
            source = next(iter(arguments['files'].values()))
            source.write_text(source.read_text()+'\n/* concurrent source edit */\n')
            return build_component_source_package(**arguments)

        with patch('spaghetti_extractor.candidate.source_export.build_component_source_package', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed while copying'):
                export_comparison_sources(comparisons=[comparison], target_id='fixture', output=self.root/'raced')
        self.assertFalse((self.root/'raced').exists())

    def test_same_body_and_signature_do_not_hide_a_changed_contract(self):
        comparison = self.baseline()
        path = self.package/'comparison-plan.json'
        plan = json.loads(path.read_text()); plan['assumptions'].append('additional caller restriction')
        path.write_text(json.dumps(plan))
        changed = self.baseline('restricted')
        with self.assertRaisesRegex(ValueError, 'conflicting source or boundary'):
            export_comparison_sources(comparisons=[comparison, changed], target_id='fixture', output=self.root/'contract-conflict')
        self.assertFalse((self.root/'contract-conflict').exists())

    def test_public_update_preserves_operator_work_and_retains_previous_tree(self):
        comparison = self.baseline()
        output = self.root/'export'
        export_comparison_sources(comparisons=[comparison], target_id='fixture', output=output)
        (output/'notes.txt').write_text('operator work')
        (output/'build').mkdir(); (output/'build/operator.txt').write_text('operator build note')
        (output/'build/array-concat-0.o').write_text('old object')
        (output/'liblifted.a').write_text('old archive')
        old_manifest = sha256_file(output/'source-export.json')
        source = self.package/'source/component.c'
        source.write_text(source.read_text().replace('a.metadata += b.metadata', 'a.metadata = b.metadata + a.metadata'))
        changed = self.baseline('edited')
        # An exported C edit already present in the incoming checked source is
        # safe to retain, even though the previous package hash no longer matches.
        (output/'components/array-concat/sources/source/component.c').write_text(source.read_text())
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            status = main(['candidate','export','fixture','--comparison',str(changed),'--output',str(output),'--update'])
        self.assertEqual(status, 0, stream.getvalue())
        report = json.loads((output/'source-export.json').read_text())
        backup = Path(report['update']['backup'])
        self.assertEqual(sha256_file(backup/'source-export.json'), old_manifest)
        self.assertEqual((backup/'build/array-concat-0.o').read_text(), 'old object')
        self.assertEqual((output/'notes.txt').read_text(), 'operator work')
        self.assertEqual((output/'build/operator.txt').read_text(), 'operator build note')
        self.assertFalse((output/'build/array-concat-0.o').exists())
        self.assertFalse((output/'liblifted.a').exists())
        self.assertTrue(report['update']['program_validation_required'])
        self.assertFalse(report['qualification'])
        for name, digest in report['files'].items(): self.assertEqual(sha256_file(output/name), digest)
        load_component_source_package(output/'components/array-concat')
        self.assertIn('previous library retained', stream.getvalue())
        built = subprocess.run(['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')],cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)

    def test_update_rejects_local_edits_boundaries_and_shared_header_changes(self):
        header = self.package/'source/local.h'
        header.write_text('struct source_extra { uint32_t value; };\n')
        body = self.package/'source/component.c'
        body.write_text(body.read_text().replace('#include "portable-component-implementation.h"',
            '#include "portable-component-implementation.h"\n#include "local.h"'))
        plan_path = self.package/'comparison-plan.json'; plan = json.loads(plan_path.read_text())
        plan['sources'].append('source/local.h');plan_path.write_text(json.dumps(plan))
        comparison = self.baseline(); output = self.root/'export'
        report = export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        manifest = (output/'source-export.json').read_bytes()
        source = output/'components/array-concat/sources/source/component.c'
        correct = source.read_bytes(); source.write_text('uncompared operator edit\n')
        with self.assertRaisesRegex(ValueError, 'local edit'):
            export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output,update=True)
        self.assertEqual(source.read_text(), 'uncompared operator edit\n')
        self.assertEqual((output/'source-export.json').read_bytes(), manifest)
        source.write_bytes(correct)
        plan_path = self.package/'comparison-plan.json'; plan = json.loads(plan_path.read_text())
        original = plan_path.read_bytes(); plan['assumptions'].append('new caller restriction')
        plan_path.write_text(json.dumps(plan)); changed = self.baseline('restricted-update')
        with self.assertRaisesRegex(ValueError, 'changes the boundary'):
            export_comparison_sources(comparisons=[changed],target_id='fixture',output=output,update=True)
        plan_path.write_bytes(original)
        # A same-signature header change still needs explicit integration review.
        header.write_text('struct source_extra { uint32_t value; uint32_t extra; };\n')
        changed = self.baseline('header-update')
        with self.assertRaisesRegex(ValueError, 'shared/header'):
            export_comparison_sources(comparisons=[changed],target_id='fixture',output=output,update=True)
        self.assertEqual((output/'source-export.json').read_bytes(), manifest)
        for name, digest in report['files'].items(): self.assertEqual(sha256_file(output/name), digest)

    def test_update_rebuilds_edited_unit_and_preserves_neighbor_make_outputs(self):
        self.select(self.supplier())
        comparison = self.baseline()
        output = self.root/'export'
        export_comparison_sources(comparisons=[comparison], target_id='fixture', output=output)
        command = ['make', '-j2', 'CC='+shutil.which('cc'), 'AR='+shutil.which('ar')]
        built = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)
        neighbor = output/'build/array-append-0.o'
        neighbor_before = (sha256_file(neighbor), neighbor.stat().st_mtime_ns)
        dependency = output/'build/array-append-0.d'
        dependency_before = (dependency.read_bytes(), dependency.stat().st_mtime_ns)
        source = self.package/'source/component.c'
        self.assertIn('a.metadata += fixture_supplier(b.metadata)', source.read_text())
        source.write_text(source.read_text().replace('a.metadata += fixture_supplier(b.metadata)',
            'a.metadata = fixture_supplier(b.metadata) + a.metadata'))
        changed = self.baseline('edited')
        report = export_comparison_sources(comparisons=[changed], target_id='fixture', output=output, update=True)
        self.assertFalse((output/'build/array-concat-0.o').exists())

        self.assertFalse((output/'liblifted.a').exists())
        self.assertEqual((sha256_file(neighbor), neighbor.stat().st_mtime_ns), neighbor_before)
        self.assertEqual((dependency.read_bytes(), dependency.stat().st_mtime_ns), dependency_before)
        self.assertIn('build/array-append-0.o', report['update']['retained_build_outputs'])
        self.assertTrue(report['update']['program_validation_required'])
        built = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.assertIn('-c components/array-concat/', built.stdout)
        self.assertNotIn('-c components/array-append/', built.stdout)
        self.assertEqual((sha256_file(neighbor), neighbor.stat().st_mtime_ns), neighbor_before)
        archive = (sha256_file(output/'liblifted.a'), (output/'liblifted.a').stat().st_mtime_ns)
        unchanged = export_comparison_sources(comparisons=[changed], target_id='fixture', output=output, update=True)
        self.assertEqual(unchanged['update']['invalidated_build_outputs'], [])
        built = subprocess.run(command, cwd=output, capture_output=True, text=True, timeout=60)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.assertNotIn(' -c ', built.stdout)
        self.assertEqual((sha256_file(output/'liblifted.a'), (output/'liblifted.a').stat().st_mtime_ns), archive)
        # A changed generated recipe can alter every compiled object, even when
        # all component bodies and public contracts are identical.
        original = export_comparison_sources
        def incoming(**arguments):
            report = original(**arguments)
            makefile = arguments['output']/'Makefile'
            makefile.write_text(makefile.read_text().replace('-O2', '-O0'))
            report['files']['Makefile'] = sha256_file(makefile)
            return report
        with patch('spaghetti_extractor.candidate.source_export_update.export_comparison_sources', side_effect=incoming):
            updated = original(comparisons=[changed], target_id='fixture', output=output, update=True)
        self.assertEqual(updated['update']['unchanged_components'], ['array-append','array-concat'])
        self.assertEqual(updated['update']['retained_build_outputs'], [])
        self.assertFalse(neighbor.exists())
        self.assertFalse((output/'build/array-concat-0.o').exists())

    def test_partial_update_needs_only_changed_comparison_and_retains_neighbor_build(self):
        comparison=self.baseline();package,service,_=self.service_comparison()
        output=self.root/'export'
        report=export_comparison_sources(comparisons=[comparison,service],target_id='fixture',output=output)
        command=['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')]
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        neighbor=output/'build/array-concat-0.o'
        before=(sha256_file(neighbor),neighbor.stat().st_mtime_ns)
        (output/'application.c').write_text('/* Operator-owned integration. */\n')
        # Existing handoffs predate explicit build metadata. Their generated
        # recipe must migrate without reopening any old comparison workspace.
        for unit in report['components'].values():unit.pop('build')
        # The retained neighbor also predates component guides.
        guide='components/array-concat/README.md'
        (output/guide).unlink();report['files'].pop(guide)
        (output/'source-export.json').write_text(json.dumps(report))
        shutil.rmtree(comparison);shutil.rmtree(service)
        source=package/'source/service.c'
        source.write_text(source.read_text().replace('uint32_t lifted(',
            '#include "helper.h"\nuint32_t lifted(').replace(
                'ctx->services->context,value','ctx->services->context,pass_value(value)'))
        (package/'source/helper.h').write_text('#include <stdint.h>\nuint32_t pass_value(uint32_t value);\n')
        (package/'source/helper.c').write_text('#include "helper.h"\nuint32_t pass_value(uint32_t value) { return value; }\n')
        path=package/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['sources'].extend(['source/helper.c','source/helper.h'])
        plan['private_headers']=['source/helper.h'];path.write_text(json.dumps(plan))
        changed=self.root/'service-edit'
        code,text=self.command('check','fixture','consumer','--comparison-package',str(package),'--output',str(changed))
        self.assertEqual(code,0,text)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
            code=main(['candidate','export','fixture','--comparison',str(changed),'--output',str(output),'--update-components'])
        self.assertEqual(code,0,stream.getvalue())
        self.assertIn('components retained from existing export: array-concat',stream.getvalue())
        updated=load_source_export(output)
        self.assertEqual(updated['update']['updated_components'],['consumer'])
        self.assertEqual(updated['update']['accepted_boundary_changes'],{})
        self.assertEqual(updated['components']['consumer']['private_headers'],['source/helper.h'])
        self.assertEqual(updated['update']['retained_components'],['array-concat'])
        self.assertEqual(updated['components']['array-concat']['comparison_binding_references'],
            report['components']['array-concat']['comparison_binding_references'])
        self.assertIn('## Operations and state',(output/guide).read_text())
        self.assertIn('source/helper.c',(output/'components/consumer/README.md').read_text())
        index=(output/'README.md').read_text()
        self.assertEqual(index.count('## Component boundaries'),1)
        for identity in updated['components']:
            self.assertIn('(components/'+identity+'/README.md)',index)
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)
        self.assertEqual((output/'application.c').read_text(),'/* Operator-owned integration. */\n')
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        self.assertEqual(built.stdout.count(' -c '),2,built.stdout)
        self.assertNotIn('-c components/array-concat/',built.stdout)
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)
        # Keep neighboring C drafts without assigning matching provenance to
        # their new bytes or retaining old compiled objects for those drafts.
        retained=output/'components/array-concat/sources/source/component.c'
        retained.write_text(retained.read_text()+'\n/* unreviewed local edit */\n')
        draft_before=(retained.read_bytes(),retained.stat().st_mtime_ns)
        published=export_comparison_sources(comparisons=[changed],target_id='fixture',output=output,update_components=True)
        self.assertEqual((retained.read_bytes(),retained.stat().st_mtime_ns),draft_before)
        self.assertEqual(published['components']['array-concat'],updated['components']['array-concat'])
        path=retained.relative_to(output).as_posix()
        self.assertEqual(published['files'][path],updated['files'][path])
        self.assertEqual(published['update']['preserved_source_drafts'],{path:sha256_file(retained)})
        self.assertFalse(neighbor.exists())
        with self.assertRaisesRegex(ValueError,'source export input is stale'):
            load_source_export(output)
        # Shared headers still require the boundary refinement workflow.
        old_manifest=(output/'source-export.json').read_bytes()
        header=output/'components/array-concat/sources/generated/portable-component-implementation.h'
        header.write_text(header.read_text()+'\n/* changed shared input */\n')
        with self.assertRaisesRegex(ValueError,'component source size is stale'):
            export_comparison_sources(comparisons=[changed],target_id='fixture',output=output,update_components=True)
        self.assertEqual((output/'source-export.json').read_bytes(),old_manifest)

    def test_reviewed_component_addition_preserves_existing_sources_and_builds(self):
        comparison=self.baseline();_,service,_=self.service_comparison()
        output=self.root/'export'
        previous=export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        command=['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')]
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        neighbor=output/'build/array-concat-0.o'
        before=(sha256_file(neighbor),neighbor.stat().st_mtime_ns)
        (output/'application.c').write_text('/* Reviewed application integration. */\n')
        manifest=(output/'source-export.json').read_bytes()
        shutil.rmtree(comparison)
        with self.assertRaisesRegex(ValueError,'adds components: consumer'):
            export_comparison_sources(comparisons=[service],target_id='fixture',output=output,update_components=True)
        self.assertEqual((output/'source-export.json').read_bytes(),manifest)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
            code=main(['candidate','export','fixture','--comparison',str(service),'--output',str(output),
                '--update-components','--accept-boundary-change','consumer'])
        self.assertEqual(code,0,stream.getvalue())
        after=load_source_export(output)
        self.assertEqual(after['update']['added_components'],['consumer'])
        self.assertIn('new component',after['update']['accepted_boundary_changes']['consumer'])
        self.assertEqual(after['components']['array-concat'],previous['components']['array-concat'])
        self.assertEqual((output/'application.c').read_text(),'/* Reviewed application integration. */\n')
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        self.assertEqual(built.stdout.count(' -c '),1,built.stdout)
        self.assertIn('-c components/consumer/',built.stdout)
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)

    def test_reviewed_removal_preserves_neighbors_and_rebuilds_archive_without_retired_members(self):
        from tests.unit.components.comparison_composition_fixture import CompositionFixture as CompositionTests
        from spaghetti_extractor.components.comparison_run import run_comparison
        leaf=CompositionTests.make(self,'leaf')
        root=CompositionTests.make(self,'root','exported_leaf(x)+1',oracle='x+2',
            selections=[dict(id='leaf',package=leaf)])
        connected=self.root/'connected'
        self.assertEqual(run_comparison(package=root,output=connected,target_id='fixture',component_id='root')['status'],'match')
        comparison=self.baseline();output=self.root/'export'
        previous=export_comparison_sources(comparisons=[comparison,connected],target_id='fixture',output=output)
        command=['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')]
        self.assertEqual(subprocess.run(command,cwd=output,capture_output=True,timeout=60).returncode,0)
        neighbor=output/'build/array-concat-0.o';before=(sha256_file(neighbor),neighbor.stat().st_mtime_ns)
        note=output/'components/leaf/operator-notes.txt';note.write_text('retain the retired boundary analysis')
        manifest=(output/'source-export.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'must refine root/leaf'):
            export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output,
                update_components=True,remove_component_ids=['leaf'])
        self.assertEqual((output/'source-export.json').read_bytes(),manifest)
        old_source=output/'components/leaf/sources/source/body.c';original=old_source.read_bytes()
        old_source.write_bytes(original+b'\n/* unfinished operator edit */\n')
        with self.assertRaisesRegex(ValueError,'local edit'):
            export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output,
                update_components=True,remove_component_ids=['root','leaf'])
        self.assertEqual((output/'source-export.json').read_bytes(),manifest)
        old_source.write_bytes(original)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
            code=main(['candidate','export','fixture','--comparison',str(comparison),'--output',str(output),
                '--update-components','--remove-component','root','--remove-component','leaf'])
        self.assertEqual(code,0,stream.getvalue())
        after=load_source_export(output)
        self.assertEqual(set(after['components']),{'array-concat'})
        self.assertEqual(after['update']['removed_components'],['leaf','root'])
        self.assertIn('components removed after review: leaf, root',stream.getvalue())
        self.assertEqual(after['components']['array-concat'],previous['components']['array-concat'])
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)
        self.assertEqual(note.read_text(),'retain the retired boundary analysis')
        self.assertFalse(old_source.exists());self.assertFalse((output/'liblifted.a').exists())
        self.assertFalse((output/'build/leaf-0.o').exists())
        self.assertTrue((Path(after['update']['backup'])/'build/leaf-0.o').is_file())
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr);self.assertNotIn(' -c ',built.stdout)
        members=subprocess.run([shutil.which('ar'),'t','liblifted.a'],cwd=output,capture_output=True,text=True,check=True).stdout
        self.assertEqual(members.splitlines(),['array-concat-0.o'])

    def test_exported_c_edits_return_to_local_comparison_without_neighbor_reads(self):
        code,text,comparison=self.check(self.package,'baseline','--case','three')
        self.assertEqual(code,0,text)
        _,service,_=self.service_comparison()
        output=self.root/'export'
        export_comparison_sources(comparisons=[comparison,service],target_id='fixture',output=output)
        source=output/'components/array-concat/sources/source/component.c'
        source.write_text(source.read_text().replace('a.metadata += b.metadata','a.metadata = b.metadata + a.metadata'))
        neighbor=output/'components/consumer/sources/source/service.c'
        neighbor.write_text(neighbor.read_text()+'\n/* Another component is under edit. */\n')
        manifest=(output/'source-export.json').read_bytes()
        draft=self.root/'imported'
        with patch('subprocess.Popen',side_effect=AssertionError('source import must not execute tools')):
            code,text=self.command('start','fixture','array-concat','--comparison-result',str(comparison),
                '--reuse-source',str(output),'--output',str(draft))
        self.assertEqual(code,0,text)
        self.assertIn('--history-baseline '+str(comparison.resolve()),text)
        self.assertIn('--case three',text)
        self.assertEqual((draft/'source/component.c').read_bytes(),source.read_bytes())
        self.assertEqual((draft/'adapters/driver.c').read_bytes(),(self.package/'adapters/driver.c').read_bytes())
        code,text,checked=self.check(draft,'imported-check','--reuse-comparison',str(comparison));self.assertEqual(code,0,text)
        self.assertEqual(json.loads((checked/'comparison-result.json').read_text())['work_counts']['compiler'],1)
        self.assertEqual((output/'source-export.json').read_bytes(),manifest)
        with self.assertRaisesRegex(ValueError,'source export input is stale'):
            load_source_export(output)
        # Importing an exported draft grants no assurance: this defect is copied
        # into the chosen local boundary, where ordinary comparison catches it.
        source.write_text(source.read_text().replace('b.metadata + a.metadata','b.metadata + a.metadata + 1U'))
        bad=self.root/'bad-draft'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--reuse-source',str(output),'--output',str(bad))
        self.assertEqual(code,0,text)
        code,text,_=self.check(bad,'bad-check');self.assertEqual(code,2,text)
        header=output/'components/array-concat/sources/generated/portable-component-implementation.h'
        original=header.read_bytes();header.write_bytes(original+b'\n/* Unreviewed header change. */\n')
        rejected=self.root/'changed-header'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--reuse-source',str(output),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('review it in the comparison workspace',text)
        self.assertFalse(rejected.exists());header.write_bytes(original)
        plan_path=self.package/'comparison-plan.json';plan=json.loads(plan_path.read_text())
        plan['assumptions'].append('A different local boundary');plan_path.write_text(json.dumps(plan))
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(self.package),
            '--reuse-source',str(output),'--output',str(self.root/'changed-boundary'))
        self.assertEqual(code,2,text);self.assertIn('boundary differs',text)

    def test_exported_file_refactor_returns_through_local_and_consumer_workflows(self):
        supplier=self.supplier();self.select(supplier)
        comparison=self.baseline();output=self.root/'refactor-export'
        previous=export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        make=['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')]
        built=subprocess.run(make,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        neighbor=output/'build/array-concat-0.o';before=(sha256_file(neighbor),neighbor.stat().st_mtime_ns)
        directory=output/'components/array-append/sources/source'
        entry=directory/'entry.c';(directory/'append.c').rename(entry)
        entry.write_text(entry.read_text().replace('return b;', 'return keep_value(b);').replace(
            '#include "portable-component-implementation.h"','#include "portable-component-implementation.h"\n#include "helpers/value.h"'))
        helpers=directory/'helpers';helpers.mkdir()
        (helpers/'value.h').write_text('#include "portable-component.h"\nspx_jv_value_v2 keep_value(spx_jv_value_v2 value);\n')
        helper=helpers/'value.c'
        good='#include "value.h"\nspx_jv_value_v2 keep_value(spx_jv_value_v2 value) { return value; }\n'
        helper.write_text(good)
        edits=[arg for name in ('entry.c','helpers/value.c','helpers/value.h')
            for arg in ('--source-file','source/'+name+'='+str(directory/name))]
        edits+=['--remove-source','source/append.c','--private-header','source/helpers/value.h']
        common=['start','fixture','array-append','--reuse-source',str(output),*edits]
        extra=directory/'unfinished.c';extra.write_text('Unselected work.\n')
        rejected=self.root/'undeclared'
        code,text=self.command(*common,'--comparison-package',str(supplier),'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('undeclared file changes',text)
        self.assertFalse(rejected.exists());extra.unlink()
        # Both a standalone boundary and a supplier focus apply file selection
        # before importing C; neither has to edit hashes or run preparation tools.
        for name,package,prefix in [('local',supplier,''),('consumer',comparison/'inputs','dependencies/array-append/')]:
            draft=self.root/(name+'-refactor')
            with patch('subprocess.Popen',side_effect=AssertionError('source selection must not execute tools')):
                code,text=self.command(*common,'--comparison-package',str(package),'--output',str(draft))
            self.assertEqual(code,0,text)
            plan=json.loads((draft/'comparison-plan.json').read_text())
            unit=plan if not prefix else plan['dependencies'][0]
            self.assertEqual(unit['private_headers'],[prefix+'source/helpers/value.h'])
            self.assertFalse((draft/(prefix+'source/append.c')).exists())
            self.assertEqual((draft/(prefix+'source/entry.c')).read_bytes(),entry.read_bytes())
        checked_package=self.root/'consumer-refactor'
        code,text,checked=self.check(checked_package,'refactor-check','--reuse-comparison',str(comparison))
        self.assertEqual(code,0,text)
        self.assertEqual(json.loads((checked/'comparison-result.json').read_text())['work_counts']['compiler'],2)
        # The newly selected helper executes in the real consumer fixture.
        edited=checked_package/'dependencies/array-append/source/helpers/value.c'
        edited.write_text(good.replace('return value;', 'value.metadata += 1U; return value;'))
        code,text,_=self.check(checked_package,'refactor-defect','--reuse-comparison',str(checked))
        self.assertEqual(code,2,text);self.assertIn('comparison=mismatch',text)
        edited.write_text(good)
        stream=io.StringIO()
        with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
            code=main(['candidate','export','fixture','--comparison',str(checked),'--output',str(output),
                '--update-components','--component','array-append'])
        self.assertEqual(code,0,stream.getvalue())
        published=load_source_export(output)
        self.assertEqual(published['update']['accepted_boundary_changes'],{})
        self.assertEqual(published['components']['array-concat'],previous['components']['array-concat'])
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)
        self.assertFalse((directory/'append.c').exists())
        built=subprocess.run(make,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        self.assertEqual(built.stdout.count(' -c '),2,built.stdout)
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),before)
        # Explicit file selection cannot make a recorded boundary header private.
        header=output/'components/array-append/sources/generated/portable-component.h'
        code,text=self.command('start','fixture','array-append','--comparison-package',str(supplier),
            '--reuse-source',str(output),'--source-file','generated/portable-component.h='+str(header),
            '--private-header','generated/portable-component.h','--output',str(self.root/'shared-edit'))
        self.assertEqual(code,2,text);self.assertIn('shared inputs cannot become authored',text)

    def test_exported_supplier_draft_checks_in_existing_consumer_without_local_fixture(self):
        self.select(self.supplier())
        comparison=self.baseline();package=comparison/'inputs';output=self.root/'export'
        export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        source=output/'components/array-append/sources/source/append.c'
        source.write_text(source.read_text().replace('return b;', 'b.metadata += 1U; return b;'))
        # Another component may be under edit in the same source project. Only
        # the named supplier is selected; its original local fixture is unused.
        caller=output/'components/array-concat/sources/source/component.c'
        caller.write_text('An unrelated unfinished edit.\n')
        shutil.rmtree(self.root/'supplier')
        selection=['--dependency-package','array-append='+str(output)]
        code,text=self.command('status','fixture','array-concat','--comparison-package',str(package),
            *selection,'--json')
        self.assertEqual(code,0,text)
        proposal=json.loads(text)['dependency_proposals'][0]
        self.assertEqual(proposal['status'],'unchanged')
        self.assertEqual(proposal['source_kind'],'exported-c-draft')
        self.assertEqual(proposal['changed_sources'],['dependencies/array-append/source/append.c'])
        draft=self.root/'supplier-draft'
        with patch('subprocess.Popen',side_effect=AssertionError('source import must not execute tools')):
            code,text=self.command('start','fixture','array-concat','--comparison-package',str(package),
                *selection,'--output',str(draft))
        self.assertEqual(code,0,text)
        self.assertEqual((draft/'dependencies/array-append/source/append.c').read_bytes(),source.read_bytes())
        for name in ('source/component.c','dependencies/array-append/bridges/bridge.c','adapters/driver.c'):
            self.assertEqual((draft/name).read_bytes(),(package/name).read_bytes())
        code,text,checked=self.check(draft,'supplier-draft-check')
        self.assertEqual(code,2,text)
        self.assertIn('comparison=mismatch',text)
        # Direct checking has a fresh input snapshot: generated headers must be
        # materialized before validating the draft's existing boundary.
        code,text,direct=self.check(package,'direct-draft',*selection)
        self.assertEqual(code,2,text)
        left=json.loads((checked/'comparison-result.json').read_text())
        right=json.loads((direct/'comparison-result.json').read_text())
        self.assertEqual(left['cases'][0]['observations'],right['cases'][0]['observations'])
        self.assertEqual(left['cases'][0]['observations'],{'original':{'value':5},'source':{'value':6}})
        # Publish a repaired supplier using its consumer result, without
        # publishing or overwriting the unfinished caller beside it.
        source.write_text(source.read_text().replace('b.metadata += 1U; return b;', '/* compatible edit */ return b;'))
        code,text,repaired=self.check(package,'repaired-draft',*selection)
        self.assertEqual(code,0,text)
        previous=json.loads((output/'source-export.json').read_text())
        caller_before=(caller.read_bytes(),caller.stat().st_mtime_ns)
        for identity,expected in [('absent',2),('array-append',0)]:
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
                code=main(['candidate','export','fixture','--comparison',str(repaired),'--output',str(output),
                    '--update-components','--component',identity])
            self.assertEqual(code,expected,stream.getvalue())
        self.assertIn('unchecked C drafts preserved',stream.getvalue())
        published,drafts=source_export_workspace(output)
        self.assertEqual(published['update']['updated_components'],['array-append'])
        self.assertEqual(published['components']['array-concat'],previous['components']['array-concat'])
        self.assertEqual((caller.read_bytes(),caller.stat().st_mtime_ns),caller_before)
        self.assertEqual(drafts,{caller.relative_to(output).as_posix():sha256_file(caller)})
        self.assertIn('Unchecked C draft preserved',(output/'components/array-concat/README.md').read_text())
        load_component_source_package(output/'components/array-append')
        with self.assertRaisesRegex(ValueError,'source export input is stale'):
            load_source_export(output)
        # Finishing the neighbor restores a wholly checked source inventory.
        caller.write_bytes((package/'source/component.c').read_bytes())
        export_comparison_sources(comparisons=[repaired],target_id='fixture',output=output,
            update_components=True,component_ids=['array-concat'])
        self.assertEqual(load_source_export(output)['update']['preserved_source_drafts'],{})
        header=output/'components/array-append/sources/generated/portable-component-implementation.h'
        header.write_text(header.read_text()+'\n/* changed boundary */\n')
        rejected=self.root/'changed-supplier-header'
        code,text=self.command('start','fixture','array-concat','--comparison-package',str(package),
            *selection,'--output',str(rejected))
        self.assertEqual(code,2,text);self.assertIn('review it in the comparison workspace',text)
        self.assertFalse(rejected.exists())

    def test_public_reviewed_update_preserves_application_and_rebuilds_changed_headers(self):
        self.select(self.supplier())
        header=self.package/'source/local.h';header.write_text('struct local_view { uint32_t value; };\n')
        source=self.package/'source/component.c'
        source.write_text(source.read_text().replace('#include "portable-component-implementation.h"',
            '#include "portable-component-implementation.h"\n#include "local.h"'))
        path=self.package/'comparison-plan.json';plan=json.loads(path.read_text())
        plan['sources'].append('source/local.h');path.write_text(json.dumps(plan))
        comparison=self.baseline();output=self.root/'export'
        export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        command=['make','CC='+shutil.which('cc'),'AR='+shutil.which('ar')]
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        (output/'application.c').write_text('/* Operator-owned program integration. */\n')
        neighbor=output/'build/array-append-0.o'
        neighbor_before=(sha256_file(neighbor),neighbor.stat().st_mtime_ns)
        previous=sha256_file(output/'source-export.json')
        header.write_text('struct local_view { uint32_t value; uint32_t extra; };\n')
        plan['assumptions'].append('Reviewed application premise')
        path.write_text(json.dumps(plan));changed=self.baseline('reviewed')
        for accepted,expected in [('array-append',2),('array-concat',0)]:
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
                code=main(['candidate','export','fixture','--comparison',str(changed),'--output',str(output),
                    '--update','--accept-boundary-change',accepted])
            self.assertEqual(code,expected,stream.getvalue())
            if expected:
                self.assertIn('array-concat',stream.getvalue())
                self.assertEqual(sha256_file(output/'source-export.json'),previous)
        report=load_source_export(output)
        changes=report['update']['accepted_boundary_changes']
        self.assertEqual(set(changes),{'array-concat'})
        self.assertIn('assumptions',changes['array-concat'])
        self.assertTrue(any('shared/header input' in field for field in changes['array-concat']))
        self.assertEqual((output/'application.c').read_text(),'/* Operator-owned program integration. */\n')
        self.assertEqual(sha256_file(Path(report['update']['backup'])/'source-export.json'),previous)
        self.assertEqual((sha256_file(neighbor),neighbor.stat().st_mtime_ns),neighbor_before)
        self.assertFalse((output/'build/array-concat-0.o').exists())
        self.assertTrue(report['update']['program_validation_required'])
        built=subprocess.run(command,cwd=output,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        self.assertIn('-c components/array-concat/',built.stdout)
        self.assertNotIn('-c components/array-append/',built.stdout)

    def test_update_rejects_symlink_build_and_new_source_parent(self):
        comparison = self.baseline(); output = self.root/'export'
        export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        outside = self.root/'external'; outside.mkdir(); (outside/'array-concat-0.o').write_text('keep')
        (output/'build').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'real build directory'):
            export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output,update=True)
        self.assertEqual((outside/'array-concat-0.o').read_text(), 'keep')
        (output/'build').unlink()
        # A new generated source path must not follow an operator directory link.
        original = export_comparison_sources
        def incoming(**arguments):
            report = original(**arguments)
            fresh = arguments['output']; path = fresh/'operator-link/generated.txt'
            path.parent.mkdir(); path.write_text('new')
            report['files']['operator-link/generated.txt'] = sha256_file(path)
            return report
        (output/'operator-link').symlink_to(outside, target_is_directory=True)
        with patch('spaghetti_extractor.candidate.source_export_update.export_comparison_sources',side_effect=incoming):
            with self.assertRaisesRegex(ValueError, 'operator path'):
                original(comparisons=[comparison],target_id='fixture',output=output,update=True)
        self.assertFalse((outside/'generated.txt').exists())

    def test_update_rolls_back_failed_publication_and_detects_concurrent_edit(self):
        comparison = self.baseline(); output = self.root/'export'
        export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output)
        (output/'notes.txt').write_text('keep')
        manifest = (output/'source-export.json').read_bytes()
        rename = Path.rename
        def fail_publish(path, target):
            if path.name == 'merged': raise OSError('injected publication failure')
            return rename(path,target)
        with patch.object(Path,'rename',fail_publish):
            with self.assertRaisesRegex(OSError, 'injected publication failure'):
                export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output,update=True)
        self.assertEqual((output/'source-export.json').read_bytes(), manifest)
        self.assertEqual((output/'notes.txt').read_text(), 'keep')
        copytree = shutil.copytree
        def edit_during_copy(source, destination, *arguments, **keywords):
            result = copytree(source,destination,*arguments,**keywords)
            if Path(source) == output: (output/'notes.txt').write_text('concurrent edit')
            return result
        with patch('spaghetti_extractor.candidate.source_export_update.shutil.copytree',side_effect=edit_during_copy):
            with self.assertRaisesRegex(ValueError, 'changed while preparing'):
                export_comparison_sources(comparisons=[comparison],target_id='fixture',output=output,update=True)
        self.assertEqual((output/'source-export.json').read_bytes(), manifest)
        self.assertEqual((output/'notes.txt').read_text(), 'concurrent edit')


if __name__ == '__main__': unittest.main()
