"""Complete operation coverage and contract/evidence separation for real cleanup."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components import bisimulation_cleanup_summary as summary
from spaghetti_extractor.util import sha256_file

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-cleanup-summary/inputs.json'
TESTKIT = {'resources': ('tests/fixtures/metapad-cleanup-summary',)}


def rebind(value):
    value['slice_sha256'] = canonical_sha256_v3({k: v for k, v in value.items() if k != 'slice_sha256'})


class CleanupSummaryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())

    def operation(self):
        x = self.fixture
        with patch.object(summary, '_manifest', side_effect=lambda root, component: x['manifests'][str(root)]):
            return summary.cleanup_operation_domain(x['domain'], x['models'], x['results'], 'root', 'text-cleanup')

    def result(self, operation):
        statuses = {'existing': 'violated', 'nonempty': 'violated', **{n: 'satisfied' for n in [
            'proposed', 'private_transport', 'public_transport', 'descriptor_transport',
            'runtime_view_transport', 'control_transport', 'observations']}}
        return {'proof_key': {'domain': {'operation': operation}}, 'proof_key_sha256': '1'*64,
                'queries': {n: {'query': {'status': s}} for n, s in statuses.items()},
                'dependencies': {n: {'receipt_sha256': '2'*64} for n in ['entry', 'loop', 'tail']}}

    def test_real_operation_exports_all_outcomes_and_complete_normal_frame(self):
        operation = self.operation(); value = summary.conditional_cleanup_summary(self.result(operation))
        self.assertEqual(len(operation['original_cover']['root_unit_ids']), 35)
        self.assertEqual(len(operation['original_cover']['shared_proof_units']), 2)
        self.assertEqual(value['status'], 'satisfied')
        self.assertFalse(value['activation_authorized'])
        contract = value['contract']; normal = contract['normal_return']
        self.assertEqual(contract['input_relation']['native_flag_bounds'], {'df': [0, 1]})
        self.assertEqual(normal['stack_delta'], 4)
        self.assertEqual(normal['result']['excluded_values'], [4294967295])
        self.assertEqual(contract['memory_fault']['source_result'], 4294967295)
        for field in ['esi', 'ebx', 'ebp', 'edi', 'fs_base']:
            self.assertIn('state.'+field+'==initial.'+field, normal['preserved_equalities'])
        self.assertNotIn('state.df==initial.df', normal['preserved_equalities'])
        self.assertEqual(contract['native_projection']['image_views']['main_window']['address'], 4260180)
        for forbidden in ['authored.c', 'source_cover', 'observer_body_sha256', 'regional_receipts']:
            self.assertNotIn(forbidden, json.dumps(contract))

    def test_implementation_rebinding_does_not_change_the_consumed_contract(self):
        first = self.operation(); a = self.result(first)
        self.fixture['results']['entry']['source_transport']['actual_marked_function_sha256'] = 'f'*64
        self.fixture['results']['loop']['proof_key']['bindings']['implementation_sha256'] = 'e'*64
        second = self.operation(); b = self.result(second)
        b['proof_key_sha256'] = '3'*64; b['dependencies']['loop']['receipt_sha256'] = '4'*64
        left, right = map(summary.conditional_cleanup_summary, [a, b])
        self.assertEqual(left['contract_sha256'], right['contract_sha256'])
        self.assertNotEqual(left['evidence'], right['evidence'])

    def test_normal_frame_export_is_checked_conjunction_elimination(self):
        result = self.result(self.operation())
        baseline = summary.conditional_cleanup_summary(result)
        frame = baseline['contract']['normal_return']['preserved_equalities']
        result['summary_export'] = {'rule':'normal-frame-subset-v1',
            'preserved_equalities':[v for v in frame if v != 'state.edi==initial.edi']}
        with patch('subprocess.run', side_effect=AssertionError('weakening cannot execute proofs')):
            exported = summary.conditional_cleanup_summary(result)
        self.assertNotEqual(exported['contract_sha256'], baseline['contract_sha256'])
        self.assertEqual(exported['evidence']['contract_projection']['source_contract_sha256'], baseline['contract_sha256'])
        self.assertEqual(exported['evidence']['composition_proof_key_sha256'], baseline['evidence']['composition_proof_key_sha256'])
        restored = deepcopy(exported['contract']); restored['normal_return']['preserved_equalities'] = frame
        self.assertEqual(restored, baseline['contract'])
        for bad in [frame + ['state.df==initial.df'], frame + frame[:1], list(reversed(frame)), 'edi']:
            with self.subTest(export=bad):
                result['summary_export']['preserved_equalities'] = bad
                with self.assertRaisesRegex(ValueError, 'withdraw checked'):
                    summary.conditional_cleanup_summary(result)
        result['summary_export'] = {'rule':'normal-frame-subset-v1', 'preserved_equalities':frame, 'stack_delta':8}
        with self.assertRaisesRegex(ValueError, 'unsupported cleanup contract export'):
            summary.conditional_cleanup_summary(result)

    def test_semantic_refinement_changes_contract_while_validation_status_does_not(self):
        first = self.operation()['contract_sha256']
        named = self.fixture['domain']['descriptor_transport']['runtime_requirements']
        next(iter(named.values()))['status'] = 'verified'
        self.assertEqual(self.operation()['contract_sha256'], first)
        self.fixture['domain']['additional_requirements']['caller-private-span'] = 'stack>=80U'
        self.assertNotEqual(self.operation()['contract_sha256'], first)

    def test_missing_original_units_wrong_identity_or_dependency_edge_reject(self):
        original = deepcopy(self.fixture)
        for change in ['hole', 'plan', 'identity', 'edge', 'extra-entry']:
            with self.subTest(change=change):
                self.fixture = deepcopy(original); m = self.fixture['manifests']; root = m['root']
                if change == 'hole':
                    root['root_unit_ids'].pop(); root['root_context_unit_ids'] = list(root['root_unit_ids'])
                elif change == 'plan':
                    m['loop']['bindings']['executable_transfer_plan_sha256'] = '0'*64
                elif change == 'identity':
                    m['entry']['source_map'][0]['rva'] += 1
                elif change == 'edge':
                    root['internal_direct_call_closure']['call_edges'][0]['target_rva'] += 1
                else:
                    root['root_entry_rvas'].append(0x55fa)
                for value in m.values(): rebind(value)
                with self.assertRaisesRegex(ValueError, 'cleanup original'):
                    self.operation()

    def test_weakened_or_unbound_scalar_cut_observer_rejects(self):
        original = deepcopy(self.fixture)
        for role, change in [('entry', 'predicate'), ('loop', 'invocation')]:
            with self.subTest(role=role):
                self.fixture = deepcopy(original)
                if change == 'predicate':
                    text = self.fixture['models'][role]
                    self.fixture['models'][role] = text.replace('input==observed.esi', 'input<=observed.esi')
                    self.assertNotEqual(text, self.fixture['models'][role])
                else:
                    self.fixture['results'][role]['source_transport']['local_cut_observer_arguments_checked'] = False
                with self.assertRaisesRegex(ValueError, 'scalar observer'):
                    self.operation()

    def test_missing_failed_or_incomplete_composition_cannot_export_a_summary(self):
        original = self.result(self.operation())
        for name in original['queries']:
            with self.subTest(query=name):
                value = deepcopy(original); value['queries'][name]['query']['status'] = 'incomplete'
                with self.assertRaisesRegex(ValueError, 'every composition obligation'):
                    summary.conditional_cleanup_summary(value)
        self.assertEqual(summary.conditional_cleanup_summary({'proof_key': {'domain': {}}})['status'], 'incomplete')

    def test_exact_file_binding_and_path_containment_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); file = root/'unit.c'; file.write_text('retained original fixture bytes\n')
            value = deepcopy(self.fixture['manifests']['root'])
            value['files'] = [{'path': 'unit.c', 'sha256': sha256_file(file)}]; rebind(value)
            manifest = root/'component-exact-c-slice-v1.json'; manifest.write_text(json.dumps(value))
            self.assertEqual(summary._manifest(root, 'text-cleanup'), value)
            file.write_text('changed')
            with self.assertRaisesRegex(ValueError, 'source binding'):
                summary._manifest(root, 'text-cleanup')
            value['files'] = [{'path': '../unit.c', 'sha256': '0'*64}]; rebind(value)
            manifest.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'source binding'):
                summary._manifest(root, 'text-cleanup')
