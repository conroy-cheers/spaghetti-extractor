"""Actual compiler reuse, independent observation admission and include probes."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.comparison_run import load_comparison_result
from spaghetti_extractor.components.comparison_reuse import comparison_execution_context
from tests.unit.components import test_comparison as base

TESTKIT={'fixtures':('compiler',),'commands':('component check',),
         'resources':('tests/fixtures/jq-array-concat',)}


class CompilationCacheTests(unittest.TestCase):
    command=base.ComponentComparisonTests.command
    check=base.ComponentComparisonTests.check

    def setUp(self):
        base.ComponentComparisonTests.setUp(self)
        (self.package/'headers').mkdir()
        p=self.package/'comparison-plan.json';plan=json.loads(p.read_text())
        plan['include_directories'].append('headers');p.write_text(json.dumps(plan))
    def compilation(self,output):
        return json.loads((output/'build/compilation.json').read_text())

    def baseline(self):
        code,text,out=self.check(self.package,'baseline')
        self.assertEqual(code,0,text)
        return out

    def replace_body(self,prefix,expression):
        p=self.package/'source/component.c'
        p.write_text(prefix+'\n'+p.read_text().replace('(void)ctx;','(void)ctx; (void)b;').replace('a.metadata += b.metadata;',f'a.metadata += {expression};'))

    def test_body_edit_recompiles_only_that_translation_unit(self):
        baseline=self.baseline()
        p=self.package/'source/component.c';p.write_text(p.read_text().replace('+= b.metadata','+= b.metadata + 0U'))
        code,text,out=self.check(self.package,'edited','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        r=load_comparison_result(out)
        self.assertEqual(r['work_counts'],dict(compiler=1,link=1,execution=2,model=0,solver=0))
        self.assertEqual({u['source']:u['reused'] for u in self.compilation(out)['units']},
                         {'source/component.c':False,'adapters/driver.c':True})

    def test_compile_error_retains_successful_work_and_later_cached_neighbors(self):
        from spaghetti_extractor.components.comparison_package import revise_comparison_package

        helper=self.root/'helper.c'
        helper.write_text('unsigned helper(void) { return 0U; }\n')
        revised=self.root/'with-helper'
        revise_comparison_package(package=self.package,output=revised,source_files={
            'component.c':self.package/'source/component.c','helper.c':helper})
        self.package=revised
        baseline=self.baseline()
        source=self.package/'source/component.c'
        body=source.read_text().replace('+= b.metadata','+= b.metadata + 0U')
        source.write_text(body)
        helper=self.package/'source/helper.c'
        helper.write_text('unsigned helper(void) { return misspelled; }\n')
        code,text,failed=self.check(self.package,'typo','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        failure=load_comparison_result(failed)
        self.assertEqual(failure['status'],'compile-failed')
        self.assertEqual(failure['work_counts'],dict(compiler=2,link=0,execution=0,model=0,solver=0))
        self.assertEqual({u['source']:u['reused'] for u in self.compilation(failed)['units']},
                         {'source/component.c':False,'adapters/driver.c':True})
        self.assertIn('1 successfully compiled, 1 reused',text)
        helper.write_text('unsigned helper(void) { return 0U; }\n')
        code,text,repaired=self.check(self.package,'repaired','--reuse-comparison',str(failed))
        self.assertEqual(code,0,text)
        result=load_comparison_result(repaired)
        self.assertIn('previous comparison did not match',result['reuse']['reasons'])
        self.assertEqual(result['work_counts'],dict(compiler=1,link=1,execution=2,model=0,solver=0))
        self.assertEqual({u['source']:u['reused'] for u in self.compilation(repaired)['units']},
                         {'source/component.c':True,'source/helper.c':False,'adapters/driver.c':True})
        # Even an error in the first file keeps the unchanged objects after it.
        source.write_text(body.replace('+= b.metadata','+= misspelled'))
        code,text,first_failed=self.check(self.package,'first-typo','--reuse-comparison',str(repaired))
        self.assertEqual(code,2,text)
        self.assertEqual({u['source']:u['reused'] for u in self.compilation(first_failed)['units']},
                         {'source/helper.c':True,'adapters/driver.c':True})
        source.write_text(body)
        code,text,final=self.check(self.package,'first-repaired','--reuse-comparison',str(first_failed))
        self.assertEqual(code,0,text)
        self.assertEqual(load_comparison_result(final)['work_counts'],dict(compiler=1,link=1,execution=2,model=0,solver=0))

    def test_unread_header_addition_edit_and_removal_reuse_observations(self):
        baseline=self.baseline();p=self.package/'source/unused.h'
        for name,contents in [('added','/* unused */'),('edited','#define UNREAD 2'),('removed',None)]:
            if contents is None:p.unlink()
            else:p.write_text(contents)
            code,text,out=self.check(self.package,name,'--reuse-comparison',str(baseline))
            self.assertEqual(code,0,text)
            r=load_comparison_result(out)
            self.assertEqual(r['reuse']['status'],'reused')
            self.assertEqual(r['reuse']['ignored_unread_headers'],['source/unused.h'])
            self.assertFalse(any(r['work_counts'].values()))
            self.assertEqual(load_comparison_result(Path(os.path.relpath(out)))['receipt_sha256'],r['receipt_sha256'])
            baseline=out

    def test_new_header_shadowing_a_read_header_invalidates_only_its_consumer(self):
        (self.package/'headers/choice.h').write_text('#define AMOUNT 2U\n')
        self.replace_body('#include <choice.h>','AMOUNT')
        baseline=self.baseline()
        # source precedes headers in the actual compiler search list.
        (self.package/'source/choice.h').write_text('#define AMOUNT 3U\n')
        code,text,out=self.check(self.package,'shadow','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        r=load_comparison_result(out)
        self.assertEqual(r['status'],'mismatch')
        self.assertEqual(r['work_counts']['compiler'],1)
        self.assertEqual(r['reuse']['ignored_unread_headers'],[])

    def test_previously_absent_optional_include_is_a_dependency(self):
        (self.package/'headers/probe.h').write_text('#if __has_include("optional.h")\n#include "optional.h"\n#else\n#define AMOUNT 2U\n#endif')
        self.replace_body('#include "probe.h"','AMOUNT')
        baseline=self.baseline()
        (self.package/'source/optional.h').write_text('#define AMOUNT 7U\n')
        code,text,out=self.check(self.package,'optional','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        self.assertEqual(load_comparison_result(out)['status'],'mismatch')
        self.assertEqual(load_comparison_result(out)['work_counts']['compiler'],1)

    def test_computed_include_falls_back_to_compilation_with_visible_reason(self):
        (self.package/'headers/choice.h').write_text('#define AMOUNT 2U\n')
        (self.package/'headers/probe.h').write_text('#define HEADER "choice.h"\n#include HEADER\n')
        self.replace_body('#include "probe.h"','AMOUNT')
        baseline=self.baseline()
        code,text,out=self.check(self.package,'computed','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        r=load_comparison_result(out)
        self.assertEqual(r['work_counts']['compiler'],1)
        self.assertTrue(any('computed' in reason for unit in self.compilation(out)['units'] for reason in unit['unsupported']))

    def test_checker_change_reuses_objects_but_executes_new_observations(self):
        baseline=self.baseline();context=comparison_execution_context()
        context['engine_sha256s']['fixture-checker.py']='0'*64
        with patch('spaghetti_extractor.components.comparison_reuse.comparison_execution_context',return_value=context):
            code,text,out=self.check(self.package,'new-checker','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        r=load_comparison_result(out)
        self.assertEqual(r['reuse']['status'],'invalidated')
        self.assertEqual(r['work_counts'],dict(compiler=0,link=1,execution=2,model=0,solver=0))

    def test_shell_and_desktop_change_reuses_objects_but_runs_new_observations(self):
        from spaghetti_extractor.components.comparison_build import observed_command
        from spaghetti_extractor.components.comparison_compile_cache import (
            DESKTOP_VARIABLES, SHELL_TEMP_VARIABLES, SHELL_SESSION_VARIABLES, compiler_environment,
        )

        def observe(command,**arguments):
            self.assertFalse((DESKTOP_VARIABLES | SHELL_TEMP_VARIABLES | SHELL_SESSION_VARIABLES) & arguments['env'].keys())
            return observed_command(command,**arguments)
        with patch.dict(os.environ,{'NIX_ENFORCE_PURITY':'0','SHLVL':'1'}):
            with patch('spaghetti_extractor.components.comparison_build.observed_command',side_effect=observe):
                baseline=self.baseline()
                shell={key:'/another-session' for key in SHELL_TEMP_VARIABLES}
                desktop={key:'/another-desktop' for key in DESKTOP_VARIABLES}
                with patch.dict(os.environ,{**shell,**desktop,'SHLVL':'7'}):
                    code,text,out=self.check(self.package,'another-desktop','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertIn('execution_context',result['reuse']['reasons'])
        self.assertEqual(result['work_counts'],dict(compiler=0,link=1,execution=2,model=0,solver=0))
        self.assertNotEqual(result['execution_context']['environment_sha256'],
            load_comparison_result(baseline)['execution_context']['environment_sha256'])
        with patch.dict(os.environ,{**shell,'NIX_ENFORCE_PURITY':'1'}):
            self.assertTrue(shell.items() <= compiler_environment().items())

    def test_compiler_environment_flags_still_invalidate_objects(self):
        self.replace_body('','SPX_TEST_ADDEND')
        flags=os.environ.get('NIX_CFLAGS_COMPILE','')
        with patch.dict(os.environ,{'NIX_CFLAGS_COMPILE':flags+' -DSPX_TEST_ADDEND=2U'}):
            baseline=self.baseline()
        with patch.dict(os.environ,{'NIX_CFLAGS_COMPILE':flags+' -DSPX_TEST_ADDEND=3U'}):
            code,text,out=self.check(self.package,'compiler-flags','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        result=load_comparison_result(out)
        self.assertEqual(result['status'],'mismatch')
        self.assertEqual(result['work_counts']['compiler'],2)
        self.assertEqual(result['cases'][0]['observations'],{'original':{'value':5},'source':{'value':6}})

    def test_python_launcher_changes_reuse_objects_but_reach_runtime(self):
        from spaghetti_extractor.components.comparison_build import observed_command
        from spaghetti_extractor.components.comparison_compile_cache import PYTHON_VARIABLES
        from spaghetti_extractor.components.comparison_package import revise_comparison_package

        driver=self.root/'environment-driver.c'
        text=(self.package/'adapters/driver.c').read_text()
        self.assertIn('printf(',text)
        # Observe the execution environment without making it a C build input.
        text=text.replace('printf(', 'if (!getenv("PYTHONPATH")) return 9;\n'
            ' result += (uint32_t)strlen(getenv("PYTHONPATH"));\n printf(',1)
        driver.write_text(text)
        revised=self.root/'environment-package'
        revise_comparison_package(package=self.package,output=revised,
            adapter_files={'driver.c':driver},original_files=['adapters/driver.c'])
        self.package=revised
        def observe(command,**arguments):
            self.assertFalse(PYTHON_VARIABLES & arguments['env'].keys())
            return observed_command(command,**arguments)
        with patch.dict(os.environ,{'PYTHONPATH':'operator-one'}),\
                patch('spaghetti_extractor.components.comparison_build.observed_command',side_effect=observe):
            code,text,baseline=self.check(self.package,'python-one')
        self.assertEqual(code,0,text)
        with patch.dict(os.environ,{'PYTHONPATH':'operator-two-moved','PYTHONHASHSEED':'1'}),\
                patch('spaghetti_extractor.components.comparison_build.observed_command',side_effect=observe):
            code,text,out=self.check(self.package,'python-two','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertEqual(result['work_counts'],dict(compiler=0,link=1,execution=2,model=0,solver=0))
        self.assertIn('execution_context',result['reuse']['reasons'])
        for output,launcher in [(baseline,'operator-one'),(out,'operator-two-moved')]:
            self.assertEqual(load_comparison_result(output)['cases'][0]['observations'],
                {'original':{'value':5+len(launcher)},'source':{'value':5+len(launcher)}})

    def test_requested_rerun_executes_matching_case_with_cached_objects(self):
        baseline=self.baseline()
        code,text,out=self.check(self.package,'rerun','--reuse-comparison',str(baseline),'--rerun')
        self.assertEqual(code,0,text)
        result=load_comparison_result(out)
        self.assertIn('fresh execution requested',result['reuse']['reasons'])
        self.assertEqual(result['work_counts'],dict(compiler=0,link=1,execution=2,model=0,solver=0))

    def test_inactive_header_contents_are_not_effective_compiler_inputs(self):
        (self.package/'headers/probe.h').write_text('#if 0\n#include "inactive.h"\n#endif\n#define AMOUNT 2U\n')
        inactive=self.package/'headers/inactive.h';inactive.write_text('/* never read */\n')
        self.replace_body('#include "probe.h"','AMOUNT')
        baseline=self.baseline();inactive.write_text('/* changed but never read */\n')
        code,text,out=self.check(self.package,'inactive-edit','--reuse-comparison',str(baseline))
        self.assertEqual(code,0,text)
        self.assertFalse(any(load_comparison_result(out)['work_counts'].values()))

    def test_read_header_edit_recompiles_its_consumer_and_retains_difference(self):
        header=self.package/'headers/choice.h';header.write_text('#define AMOUNT 2U\n')
        self.replace_body('#include "choice.h"','AMOUNT')
        baseline=self.baseline();header.write_text('#define AMOUNT 4U\n')
        code,text,out=self.check(self.package,'header-edit','--reuse-comparison',str(baseline))
        self.assertEqual(code,2,text)
        r=load_comparison_result(out)
        self.assertEqual(r['status'],'mismatch');self.assertEqual(r['work_counts']['compiler'],1)
