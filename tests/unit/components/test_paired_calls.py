"""Solver checks for ordered body-free call composition and current memory."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_paired_calls import paired_call_runtime
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint


TESTKIT = {'fixtures': ('compiler', 'cbmc')}


class PairedCallTests(unittest.TestCase):
    def check_c(self, body, *, failures=(), capacity=2, arguments=2, object_capacity=0,
                object_observation_sites=False, terminal_outcomes=False, code_targets=False):
        source = '\n'.join(['#include "stdint.h"', *sparse_mutable_memory_runtime(4),
                           *paired_call_runtime(capacity, argument_capacity=arguments, object_capacity=object_capacity,
                                                object_observation_sites=object_observation_sites,
                                                terminal_outcomes=terminal_outcomes, code_targets=code_targets)])
        source += '''
void check(void) {
 struct spx_mutable_world left={0},right={0};
 struct spx_paired_trace trace={0};
 uint32_t p,v,f;trace.probe=p;__CPROVER_assume(f<=1U);
 uint32_t args[2]={11U,22U};
 struct spx_paired_outcome candidate={v,f},a,b;
''' + body + '\n}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'pair.c').write_text(source)
            compiler, checker = shutil.which('goto-cc'), shutil.which('cbmc')
            self.assertIsNotNone(compiler)
            self.assertIsNotNone(checker)
            compiled = subprocess.run([compiler, '--i386-win32', '-nostdinc', '-I', '.',
                'pair.c', '--function', 'check', '-o', 'model.goto'], cwd=root,
                capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([checker, 'model.goto', '--function', 'check', '--json-ui',
                '--unwind', '5', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check'], cwd=root,
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 10 if failures else 0, result.stdout[-3000:]+result.stderr)
            rows = [r for b in json.loads(result.stdout) for r in b.get('result', [])]
            self.assertTrue(rows)
            failed = {r['description'] for r in rows if r['status']=='FAILURE'}
            self.assertEqual(failed, set(failures))
            self.assertTrue(all(r['status'] in {'SUCCESS','FAILURE'} for r in rows))

    def test_terminal_calls_pair_the_prefix_and_stop_further_calls(self):
        paired = '''
 candidate.fault=0U;candidate.terminal=2U;
 a=spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 spx_paired_begin_source(&trace);
 b=spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);
 spx_paired_finish(&trace);
 __CPROVER_assert(a.terminal==2U && b.terminal==2U,"terminal-identity");
 __CPROVER_assert(spx_mutable_byte(&left,p)==spx_mutable_byte(&right,p),"terminal-current-memory");
'''
        self.check_c(paired, terminal_outcomes=True)
        self.check_c(paired.replace('spx_paired_begin_source(&trace);',
            'spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);\n'
            'spx_paired_begin_source(&trace);').replace('spx_paired_finish(&trace);', ''),
            terminal_outcomes=True, failures=('spx-paired-call-after-termination', 'terminal-current-memory'))
        self.check_c(paired.replace('spx_paired_finish(&trace);',
            'trace.terminated[1]=0U;spx_paired_finish(&trace);'),
            terminal_outcomes=True, failures=('spx-paired-final-termination',))
        self.check_c(paired.replace('candidate.fault=0U;', 'candidate.fault=1U;'),
            terminal_outcomes=True, failures=('spx-paired-disjoint-outcomes',))
        self.check_c(paired.replace('a=spx_paired_invoke',
            'spx_mutable_event(&left,p,1U,7U,0U,0U);\n a=spx_paired_invoke'),
            terminal_outcomes=True, failures=('spx-paired-current-input-memory',))

    def test_indirect_targets_are_checked_at_each_actual_call_position(self):
        body = '''
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,0U,11U,candidate);
 spx_paired_invoke(&trace,&left,0U,7U,args,0U,22U,candidate);
 spx_paired_begin_source(&trace);
 spx_paired_invoke(&trace,&right,1U,7U,args,0U,11U,candidate);
 spx_paired_invoke(&trace,&right,1U,7U,args,0U,22U,candidate);
 spx_paired_finish(&trace);
'''
        self.check_c(body, code_targets=True)
        self.check_c(body.replace('&right,1U,7U,args,0U,22U', '&right,1U,7U,args,0U,11U'),
                     code_targets=True, failures=('spx-paired-code-target',))

    def test_local_objects_cross_private_frame_and_keep_current_mutations(self):
        body = '''
 uint8_t original[4]={3U,5U,7U,9U},source[4]={3U,5U,7U,9U};
 struct spx_paired_object l[2]={{100U,3U,1U,4U,original},{101U,1U,1U,2U,original+1}};
 struct spx_paired_object r[2]={{100U,3U,1U,4U,source},{101U,1U,1U,2U,source+1}};
 trace.private_low=0U;trace.private_high=UINT64_C(4294967296);candidate.fault=0U;
 a=spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,l,2U);
 original[2]^=1U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,l,2U);
 spx_paired_begin_source(&trace);
 b=spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate,r,2U);
 source[2]^=1U;
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate,r,2U);
 spx_paired_finish(&trace);
 __CPROVER_assert(a.value==b.value,"local-result");
 for(uint32_t i=0;i<4U;i++)__CPROVER_assert(original[i]==source[i],"local-post-memory");
 __CPROVER_assert(left.count==0U && right.count==0U,"unrelated-shared-frame");
'''
        self.check_c(body, object_capacity=2)
        self.check_c(body.replace('101U,1U,1U', '101U,3U,1U'), object_capacity=2)
        self.check_c(body, object_capacity=2, object_observation_sites=True)
        self.check_c(body.replace('source[2]^=1U;', ''), object_capacity=2,
                     failures=('spx-paired-object-current-memory',))
        self.check_c(body.replace('source[2]^=1U;', ''), object_capacity=2, object_observation_sites=True,
                     failures=('spx-paired-object-current-memory:1:0', 'spx-paired-object-current-memory:1:1'))

    def test_local_objects_preserve_readonly_storage_and_unborrowed_bytes(self):
        self.check_c('''
 uint8_t original[4]={3U,5U,7U,9U},source[4]={3U,5U,7U,9U};
 struct spx_paired_object l[2]={{100U,3U,1U,2U,original+1},{200U,1U,0U,4U,0}};
 struct spx_paired_object r[2]={{100U,3U,1U,2U,source+1},{200U,1U,0U,4U,0}};
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,l,2U);
 spx_paired_begin_source(&trace);
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate,r,2U);
 spx_paired_finish(&trace);
 __CPROVER_assert(original[0]==3U && original[3]==9U && source[0]==3U && source[3]==9U,"outside-local-frame");
 __CPROVER_assert(left.count==0U && right.count==0U,"readonly-shared-frame");
''', object_capacity=2)

    def test_local_post_bytes_and_successive_invocations_remain_arbitrary(self):
        self.check_c('''
 uint8_t bytes[2]={0};
 struct spx_paired_object object={100U,3U,1U,2U,bytes};
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,&object,1U);
 uint8_t first=bytes[0];
 __CPROVER_assert(bytes[0]==bytes[1],"independent-local-post-bytes");
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,&object,1U);
 __CPROVER_assert(first==bytes[0],"fresh-local-invocation");
''', object_capacity=1, failures=('independent-local-post-bytes', 'fresh-local-invocation'))
        self.check_c('''
 uint8_t bytes[65]={0};
 struct spx_paired_object object={100U,3U,1U,65U,bytes};
 spx_paired_objects_check(&object,1U);
''', object_capacity=1, failures=('spx-paired-local-object-size',))

    def test_local_object_aliases_require_the_same_live_storage(self):
        self.check_c('''
 uint8_t first[4]={0},unrelated[4]={0};
 struct spx_paired_object objects[2]={{100U,3U,1U,4U,first},{101U,1U,1U,2U,unrelated}};
 spx_paired_objects_check(objects,2U);
''', object_capacity=2, failures=('spx-paired-local-object-alias',))
        self.check_c('''
 uint8_t first[4]={0};
 struct spx_paired_object objects[2]={{100U,3U,1U,4U,first},{101U,1U,0U,2U,0}};
 spx_paired_objects_check(objects,2U);
''', object_capacity=2, failures=('spx-paired-object-storage-alias',))

    def test_local_and_sparse_backings_need_a_separate_representation_rule(self):
        self.check_c('''
 uint8_t bytes[2]={0};
 struct spx_paired_object original={100U,2U,1U,2U,bytes},source={100U,2U,0U,2U,0};
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,&original,1U);
 spx_paired_begin_source(&trace);
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate,&source,1U);
''', object_capacity=1, failures=('spx-paired-object-correspondence',))

    def test_relative_observation_covers_the_last_physical_byte(self):
        self.check_c('''
 struct spx_paired_object object={UINT32_MAX-1U,1U,0U,2U,0};
 candidate.fault=0U;
 spx_mutable_event(&left,UINT32_MAX,1U,7U,0U,0U);
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate,&object,1U);
 spx_paired_begin_source(&trace);
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate,&object,1U);
''', object_capacity=1, failures=('spx-paired-object-current-memory',))

    def test_expired_or_short_local_storage_does_not_establish_a_live_view(self):
        for pointer in ('expired', 'short_object'):
            self.check_c('''
 uint8_t *expired;
 {uint8_t storage[4]={0};expired=storage;}
 uint8_t short_object[2]={0};
 struct spx_paired_object object={100U,1U,1U,4U,'''+pointer+'''};
 spx_paired_objects_check(&object,1U);
''', object_capacity=1, failures=('spx-paired-local-object-live', *(
                    ('dead object in R_OK(a->bytes, (unsigned int)a->extent)',) if pointer == 'expired' else ())))

    def test_normal_uint32_and_fault_outcomes_keep_distinct_tags(self):
        body = '''
 a=spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 spx_paired_begin_source(&trace);
 b=spx_paired_invoke(&trace,&right,1U,7U,args,2U,(struct spx_paired_outcome){0U,0U});
 spx_paired_finish(&trace);
 __CPROVER_assert(a.value==b.value && b.value==v && a.fault==b.fault && b.fault==f,"outcome-corresponds");
 __CPROVER_assert(spx_mutable_byte(&left,p)==spx_mutable_byte(&right,p),"partial-effects-correspond");
'''
        self.check_c(body)
        # Reachable counterexamples ensure neither normal UINT32_MAX nor the
        # fault branch was silently excluded by the adapter's assumptions.
        self.check_c(body + '__CPROVER_assert(f || v!=UINT32_MAX,"normal-max-admitted");'
                     '__CPROVER_assert(!f,"fault-admitted");',
                     failures=('normal-max-admitted','fault-admitted'))

    def test_repeated_service_has_fresh_post_memory_at_each_position(self):
        body = '''
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 uint8_t first=spx_mutable_byte(&left,p);
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 uint8_t second=spx_mutable_byte(&left,p);
 spx_paired_begin_source(&trace);
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);
 __CPROVER_assert(spx_mutable_byte(&right,p)==first,"first-current-memory");
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);
 __CPROVER_assert(spx_mutable_byte(&right,p)==second,"second-current-memory");
 spx_paired_finish(&trace);
'''
        self.check_c(body)
        self.check_c(body+'__CPROVER_assert(first==second,"distinct-invocation-memory");',
                     failures=('distinct-invocation-memory',))

    def test_optional_invocation_and_fault_prefix_are_chosen_by_bodies(self):
        body = '''
 uint32_t mode;
 if(mode!=2U && mode!=3U)spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 if(!trace.faulted[0])spx_paired_invoke(&trace,&left,0U,8U,args,2U,(struct spx_paired_outcome){v,0U});
 spx_paired_begin_source(&trace);
 if(mode!=2U && mode!=3U)spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);
 if(!trace.faulted[1])spx_paired_invoke(&trace,&right,1U,8U,args,2U,(struct spx_paired_outcome){v,0U});
 spx_paired_finish(&trace);
'''
        self.check_c(body)
        self.check_c('''
 candidate.fault=1U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 spx_paired_invoke(&trace,&left,0U,8U,args,2U,candidate);
''', failures=('spx-paired-call-after-fault',))

    def test_wrong_service_arguments_and_missing_invocation_reject(self):
        prefix = '''
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 spx_paired_begin_source(&trace);
'''
        self.check_c(prefix + 'spx_paired_finish(&trace);', failures=('spx-paired-complete-call-trace',))
        self.check_c(prefix + 'spx_paired_invoke(&trace,&right,1U,8U,args,2U,candidate);',
                     failures=('spx-paired-service-order',))
        self.check_c(prefix + 'args[0]++;spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);',
                     failures=('spx-paired-call-arguments',))
        self.check_c(prefix + 'spx_paired_invoke(&trace,&right,1U,7U,args,1U,candidate);',
                     failures=('spx-paired-argument-count',))

    def test_current_contents_and_half_open_private_frame(self):
        suffix = '''
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 spx_paired_begin_source(&trace);
 spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);
 spx_paired_finish(&trace);
'''
        write = 'spx_mutable_event(&left,UINT32_MAX,1U,42U,0U,0U);\n'
        self.check_c(write+suffix, failures=('spx-paired-current-input-memory',))
        self.check_c(write+'spx_mutable_event(&right,UINT32_MAX,1U,42U,0U,0U);'+suffix)
        self.check_c('trace.private_low=UINT32_MAX;trace.private_high=UINT64_C(4294967296);'+write+suffix)
        self.check_c('trace.private_low=0U;trace.private_high=UINT32_MAX;'+write+suffix,
                     failures=('spx-paired-current-input-memory',))

    def test_bounds_and_execution_phase_are_asserted(self):
        self.check_c('''
 candidate.fault=0U;
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
 spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);
''', capacity=1, failures=('spx-paired-call-capacity',))
        self.check_c('spx_paired_invoke(&trace,&left,0U,7U,args,2U,candidate);',
                     arguments=1, failures=('spx-paired-argument-capacity',))
        self.check_c('spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);',
                     failures=('spx-paired-call-phase',))
        self.check_c('spx_paired_begin_source(&trace);'
                     'spx_paired_invoke(&trace,&right,1U,7U,args,2U,candidate);',
                     failures=('spx-paired-original-call-present',))

    def test_renderer_limits_fail_closed(self):
        for capacity, arguments in [(0,1),(65,1),(True,1),(1,0),(1,33),(1,True)]:
            with self.subTest(capacity=capacity, arguments=arguments):
                with self.assertRaises(ValueError):
                    paired_call_runtime(capacity, argument_capacity=arguments)
