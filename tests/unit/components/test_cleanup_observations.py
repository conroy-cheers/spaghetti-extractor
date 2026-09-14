"""Checked service rules compose prefixes without importing application bodies."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_cleanup_composition import cleanup_control_domain
from spaghetti_extractor.components.bisimulation_cleanup_observations import cleanup_observation_domain, TEMPLATE
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-composition/inputs.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-composition',)}


class CleanupObservationsTests(unittest.TestCase):
    def setUp(self):
        x = json.loads(FIXTURE.read_text())
        self.models = {n: x['service_models'][n]+x['postambles'][n].replace(
                'void check_iteration(void){', 'void check_iteration(void){'+x['observation_setups'].get(n, ''), 1) for n in x['postambles']}
        self.control = cleanup_control_domain(x['postambles'], x['contracts'], x['graph'], x['private_transport'])

    def domain(self):
        return cleanup_observation_domain(self.models, self.control)

    def query(self, source=TEMPLATE):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'admission.c').write_text(source)
            process = subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', 'admission.c',
                '--function', 'check_admission', '-o', 'model.goto'], cwd=root, capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function',
                'check_admission', *checker_options(20, None)], cwd=root, timeout_seconds=60, output_prefix=root/'query')
            raw = json.loads((root/'query.stdout').read_text())
            failed = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
            return result, failed

    def test_real_service_rules_establish_conditional_complete_prefix(self):
        domain = self.domain()
        self.assertEqual(domain['entry_calls'], ['length', 'allocate', 'length'])
        self.assertEqual(domain['loop_calls'], [])
        self.assertEqual(domain['complete_call_limit'], 8)
        self.assertIn('modeled-memory-fault', domain['outcomes'])
        result, failures = self.query()
        self.assertEqual(result['status'], 'satisfied', failures)
        for body in ['authored.c', 'spx_sub_', 'spx_mutable_world']:
            self.assertNotIn(body, TEMPLATE)

    def test_final_memory_and_event_counts_must_cover_fault_exits(self):
        original = deepcopy(self.control)
        for role, name in [('entry', 'entry-three-service-invocations'),
                           ('tail', 'tail-complete-service-trace'),
                           *[(n, n+'-whole-post-memory') for n in self.models]]:
            with self.subTest(role=role, name=name):
                self.control = deepcopy(original)
                self.control['regional_postconditions'][role][name]['guards'] = ['result!=UINT32_MAX']
                with self.assertRaisesRegex(ValueError, 'every outcome|some outcome'):
                    self.domain()

    def test_hidden_effect_conditional_recorder_and_changed_reader_reject(self):
        original = dict(self.models)
        for role, old, new in [
            ('entry', 'entry_before_service(e);', 'if(e->phase)entry_before_service(e);'),
            ('entry', 'entry_before_service(e);', 'e->world->count=0U;entry_before_service(e);'),
            ('entry', 'uint8_t result = fresh_zero_byte(address);', 'uint8_t result = 0U;'),
            ('tail', 'return calls[e->count++].result;', 'return calls[e->count].result;'),
            ('tail', 'transition(e,1U,', 'e->released=1U;transition(e,1U,')]:
            with self.subTest(role=role, change=new):
                self.models = dict(original)
                self.assertIn(old, self.models[role])
                self.models[role] = self.models[role].replace(old, new, 1)
                with self.assertRaisesRegex(ValueError, 'observation rule|helper contract'):
                    self.domain()

    def test_distinct_incoming_world_or_missing_loop_rule_reject(self):
        original = dict(self.models)
        self.models['entry'] = self.models['entry'].replace('.world=&right,', '.world=&left,')
        with self.assertRaisesRegex(ValueError, 'setup contract'):
            self.domain()
        self.models = original
        self.models['loop'] = self.models['loop'].replace('__CPROVER_assert(0,"loop-no-service-call");', '')
        with self.assertRaisesRegex(ValueError, 'observation rule'):
            self.domain()

    def test_source_side_reset_or_changed_probe_cannot_bypass_recording(self):
        original = dict(self.models)
        for old, new in [('.side=1U,', '.side=0U,'),
                         ('probe=arbitrary_probe;', 'probe=0U;'),
                         ('uint32_t result=', 'b.count=0U;uint32_t result=')]:
            with self.subTest(change=new):
                self.models = dict(original)
                self.assertIn(old, self.models['tail'])
                head, tail = self.models['tail'].rsplit(old, 1)
                self.models['tail'] = head+new+tail
                with self.assertRaisesRegex(ValueError, 'setup contract'):
                    self.domain()

    def test_dropped_fault_prefix_reordered_calls_and_wrong_call_byte_fail(self):
        for old, new, expected in [
            ('left_count=3U+left_tail_count', 'left_count=(fault?0U:3U)+left_tail_count',
             'cleanup-fault-retains-entry-prefix'),
            ('entry_right[ordinal]', 'entry_right[2U-ordinal]', 'cleanup-composed-ordered-event-observation'),
            ('__CPROVER_assert(left_stage==right_stage', 'right.byte^=1U;__CPROVER_assert(left_stage==right_stage',
             'cleanup-composed-ordered-event-observation')]:
            with self.subTest(change=new):
                self.assertIn(old, TEMPLATE)
                result, failures = self.query(TEMPLATE.replace(old, new))
                self.assertEqual(result['status'], 'violated', result)
                self.assertIn(expected, failures)
