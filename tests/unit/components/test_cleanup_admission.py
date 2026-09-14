"""Actual spatial admission excerpts expose gaps without executing application bodies."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cleanup_admission import cleanup_admission_domain, render_cleanup_admission
from spaghetti_extractor.components.bisimulation_private_transport import cleanup_private_transport_domain
from spaghetti_extractor.components.bisimulation_public_transport import cleanup_public_transport_domain
from spaghetti_extractor.components.bisimulation_descriptor_transport import (
    cleanup_descriptor_transport_domain, checked_cleanup_grant_protocol,
)
from spaghetti_extractor.components.bisimulation_cleanup_source_use import checked_cleanup_source_use
from spaghetti_extractor.components.bisimulation_runtime_view_transport import runtime_view_recipe
from spaghetti_extractor.components.bisimulation_cleanup_composition import cleanup_control_domain
from spaghetti_extractor.components.bisimulation_cleanup_observations import cleanup_observation_domain
from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.operator.source_composition_check import _key, _queries, _validate_queries

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-entry/admission-excerpts.json'
TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('tests/fixtures/metapad-cleanup-entry',
                                                       'tests/fixtures/metapad-cleanup-descriptor',
                                                       'tests/fixtures/metapad-cleanup-composition')}


class CleanupAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.fixture = json.loads(FIXTURE.read_text())
        cls.domain = cleanup_admission_domain(cls.fixture['contracts'], cls.fixture['model_excerpts'])
        cls.domain['private_transport'] = cleanup_private_transport_domain(cls.fixture['model_excerpts'])
        cls.domain['public_transport'] = cleanup_public_transport_domain(json.loads(
            (FIXTURE.parent/'public-memory-excerpts.json').read_text())['model_excerpts'])
        descriptor = json.loads((FIXTURE.parent.parent/'metapad-cleanup-descriptor/inputs.json').read_text())
        cls.domain['descriptor_transport'] = cleanup_descriptor_transport_domain(descriptor['model_excerpts'], descriptor['headers'])
        cls.domain['descriptor_transport']['grant_protocol'] = checked_cleanup_grant_protocol(
            descriptor['source_body'], context_parameter='cleanup::context')
        cls.domain['source_representation_use'] = checked_cleanup_source_use(descriptor['source_body'], parameters={
            role: 'cleanup::'+role for role in ['context', 'text', 'suppress_notice', 'main_window', 'edit_window', 'caption']})
        cls.domain['runtime_view_transport'] = runtime_view_recipe()
        control = json.loads((FIXTURE.parent.parent/'metapad-cleanup-composition/inputs.json').read_text())
        cls.domain['control_transport'] = cleanup_control_domain(control['postambles'], control['contracts'],
            control['graph'], cls.domain['private_transport'])
        cls.domain['observations'] = cleanup_observation_domain(
            {n: control['service_models'][n]+control['postambles'][n].replace(
                'void check_iteration(void){', 'void check_iteration(void){'+control['observation_setups'].get(n, ''), 1) for n in control['postambles']},
            cls.domain['control_transport'])
        cls.key = _key(cls.domain, Path(shutil.which('goto-cc')), Path(shutil.which('cbmc')))
        cls.timings = []
        cls.queries = _queries(cls.root, cls.key, 60, cls.timings)

    def test_existing_gap_proposed_implication_and_nonempty_domain(self):
        self.assertEqual({n: v['query']['status'] for n, v in self.queries.items()},
                         {'existing': 'violated', 'proposed': 'satisfied', 'nonempty': 'violated',
                          'private_transport': 'satisfied', 'public_transport': 'satisfied', 'descriptor_transport': 'satisfied',
                          'runtime_view_transport': 'satisfied', 'control_transport': 'satisfied', 'observations': 'satisfied'})
        raw = json.loads(next((self.root/'existing/query-evidence').glob('*/stdout')).read_text())
        failed = {r['description'] for event in raw for r in event.get('result', []) if r['status'] == 'FAILURE'}
        self.assertEqual(failed, {f'tail-spatial-admission-{i}' for i in range(6)})
        for name in self.queries:
            source = (self.root/name/'admission.c').read_text()
            self.assertNotIn('authored.c', source)
            self.assertNotIn('spx_sub_', source)
            self.assertNotIn('spx_mutable_world', source)
        with patch('subprocess.run', side_effect=AssertionError('evidence import must not run tools')), patch(
                'spaghetti_extractor.operator.source_composition_check.render_cleanup_admission',
                side_effect=AssertionError('evidence import must not regenerate models')), patch(
                'spaghetti_extractor.operator.source_composition_check.private_transport_header',
                side_effect=AssertionError('evidence import must not regenerate private model data')), patch(
                'spaghetti_extractor.operator.source_composition_check.render_public_transport',
                side_effect=AssertionError('evidence import must not regenerate public memory models')), patch(
                'spaghetti_extractor.operator.source_composition_check.descriptor_files',
                side_effect=AssertionError('evidence import must not regenerate descriptor headers')), patch(
                'spaghetti_extractor.operator.source_composition_check.runtime_view_files',
                side_effect=AssertionError('evidence import must not regenerate runtime headers')):
            _validate_queries({'proof_key': self.key, 'queries': self.queries}, self.root)

    def test_each_additional_requirement_has_a_counterexample_when_omitted(self):
        for omitted in self.domain['additional_requirements']:
            with self.subTest(omitted=omitted):
                root = self.root/omitted; root.mkdir()
                source = render_cleanup_admission(self.domain, additional_requirements=[
                    n for n in self.domain['additional_requirements'] if n != omitted])
                (root/'model.c').write_text(source)
                subprocess.run([shutil.which('goto-cc'), '--i386-win32', '-nostdinc', 'model.c',
                    '--function', 'check_admission', '-o', 'model.goto'], cwd=root, capture_output=True, check=True)
                result = run_cbmc_properties(command=[shutil.which('cbmc'), 'model.goto', '--function',
                    'check_admission', *checker_options(2, None)], cwd=root, timeout_seconds=60)
                self.assertEqual(result['status'], 'violated', omitted)

    def test_independent_stack_initialization_order_preserves_the_contract(self):
        models = deepcopy(self.fixture['model_excerpts'])
        original = cleanup_admission_domain(self.fixture['contracts'], models)
        for role in ['loop', 'tail']:
            models[role] = models[role].replace('initial.esp=stack-16U;initial.ebp=stack+8U;',
                                               'initial.ebp=stack+8U;initial.esp=stack-16U;')
            self.assertEqual(cleanup_admission_domain(self.fixture['contracts'], models), original)
        models['loop'] = models['loop'].replace('initial.ebp=stack+8U;', 'initial.ebp=stack+8U;stack+=4U;')
        with self.assertRaisesRegex(ValueError, 'consumer stack initialization'):
            cleanup_admission_domain(self.fixture['contracts'], models)

    def test_changed_stack_convention_or_omitted_admission_rejects(self):
        contracts = deepcopy(self.fixture['contracts']); contracts['loop']['stack_offsets']['esp'] = -12
        with self.assertRaisesRegex(ValueError, 'private state convention'):
            cleanup_admission_domain(contracts, self.fixture['model_excerpts'])
        models = deepcopy(self.fixture['model_excerpts'])
        models['entry'] = models['entry'].replace('state.esp==stack-28U', 'state.esp==stack-24U')
        with self.assertRaisesRegex(ValueError, 'register transport'):
            cleanup_admission_domain(self.fixture['contracts'], models)
        models = deepcopy(self.fixture['model_excerpts'])
        models['tail'] = models['tail'].replace('__CPROVER_assume(', 'unbound_assumption(', 1)
        with self.assertRaisesRegex(ValueError, 'inventory changed'):
            cleanup_admission_domain(self.fixture['contracts'], models)

    def test_changed_complete_admission_changes_key_and_query_tampering_rejects(self):
        domain = deepcopy(self.domain)
        domain['regional_assumptions']['entry'][0] = 'length_target>1U'
        changed = _key(domain, self.key['tools']['compiler']['path'], self.key['tools']['checker']['path'])
        self.assertNotEqual(canonical_sha256_v3(changed), canonical_sha256_v3(self.key))
        queries = deepcopy(self.queries); queries['proposed']['query']['property_ids'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete admission query'):
            _validate_queries({'proof_key': self.key, 'queries': queries}, self.root)


if __name__ == '__main__':
    unittest.main()
