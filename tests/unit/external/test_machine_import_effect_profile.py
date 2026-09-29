import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external.environment_boundaries import lower_machine_import_boundary_v1
from spaghetti_extractor.external.machine_import_effect_profile import compose_native_callthrough_profile
from spaghetti_extractor.external.machine_import_profiles import (
    MachineImportProfileError, load_machine_import_profile_set,
)
from spaghetti_extractor.util import sha256_file


class MachineImportEffectProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.abi_path, self.effect_path = self.root/'abi.json', self.root/'effects.json'
        self.out = self.root/'composed.json'
        row = {'id': 'abi:invoke', 'import': {'dll': 'fixture.dll', 'symbol': 'invoke'},
               'abi_template': 'pe32-cdecl-v1', 'arity': {'kind': 'fixed', 'words': 1},
               'disposition': 'returns', 'result_register_relations': [{'register': 'eax', 'relation': 'exact'}]}
        self.abi = {'format': 'spaghetti-extractor-static-machine-import-profile-v2',
                    'id': 'fixture-abi', 'machine_import_signatures': [row]}
        self.write(self.abi_path, self.abi)
        contract = load_machine_import_profile_set([self.abi_path]).contracts[0]
        boundary = lower_machine_import_boundary_v1(contract, abi_dialect='pe32-i386-gnu-v1')
        row['canonical_boundary'] = {'boundary_schema': boundary['schema'],
                                     'target_data_layout': boundary['target_data_layout'],
                                     'signature_id': boundary['schema']['signatures'][0]['id']}
        effect = {k: v for k, v in row.items() if k != 'canonical_boundary'}
        effect.update({'id': 'reviewed:invoke', 'memory_effect': 'nativeCallthrough',
                       'world_effect': 'nativeCallthrough', 'memory_footprints': [],
                       'effect_model': {'kind': 'exact_native_dll_callthrough_v1', 'prerequisites': {
                           'same_pinned_dll_implementation': True, 'exact_machine_arguments': True,
                           'candidate_address_space_used_directly': True}}})
        self.effects = {'format': self.abi['format'], 'id': 'fixture-effects', 'machine_import_signatures': [effect]}
        self.write(self.abi_path, self.abi)
        self.write(self.effect_path, self.effects)

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value))

    def compose(self):
        return compose_native_callthrough_profile(abi_profile=self.abi_path,
                                                 effect_profile=self.effect_path, out=self.out)

    def test_composes_explicit_effects_and_preserves_physical_boundary(self):
        before = sha256_file(self.abi_path)
        result = self.compose()
        selected = load_machine_import_profile_set([self.out]).contracts[0]
        boundary = lower_machine_import_boundary_v1(selected, abi_dialect='pe32-i386-gnu-v1')
        self.assertEqual(boundary['schema'], self.abi['machine_import_signatures'][0]['canonical_boundary']['boundary_schema'])
        self.assertEqual(selected.contract['memory_effect'], 'nativeCallthrough')
        self.assertEqual(result['provenance']['abi_profiles'][0]['sha256'], before)
        self.assertEqual(sha256_file(self.abi_path), before)
        self.assertNotIn('memory_effect', load_machine_import_profile_set([self.abi_path]).contracts[0].contract)

    def test_rejects_changed_abi_or_missing_import(self):
        for field, value in [('arity', {'kind': 'fixed', 'words': 2}),
                             ('abi_template', 'pe32-stdcall-v1'),
                             ('result_register_relations', []),
                             ('import', {'dll': 'fixture.dll', 'symbol': 'missing'})]:
            with self.subTest(field=field):
                edited = copy.deepcopy(self.effects)
                edited['machine_import_signatures'][0][field] = value
                self.write(self.effect_path, edited)
                with self.assertRaises(MachineImportProfileError):
                    self.compose()

    def test_effect_change_under_same_abi_changes_binding(self):
        baseline = self.compose()
        edited = copy.deepcopy(self.effects)
        edited['machine_import_signatures'][0]['caller_memory_frame'] = {
            'status': 'complete', 'model': 'pe32-declared-pointer-arguments-v1',
            'arguments': [{'argument_index': 0, 'role': 'caller_memory', 'access': 'read',
                           'extent': 'fixed_word', 'retention': 'during_call'}],
            'assumptions': ['caller memory is accessed only through declared pointer arguments',
                            'non-callback pointer arguments are retained only during the call',
                            'opaque interface resources are disjoint from caller image and stack memory'],
        }
        self.write(self.effect_path, edited)
        refined = self.compose()
        self.assertNotEqual(baseline['provenance']['effect_profiles'], refined['provenance']['effect_profiles'])
        self.assertEqual(baseline['machine_import_signatures'][0]['canonical_boundary'],
                         refined['machine_import_signatures'][0]['canonical_boundary'])

    def test_rejects_absent_prerequisite_and_replaced_abi(self):
        for change in ['prerequisite', 'canonical_boundary', 'empty']:
            with self.subTest(change=change):
                edited = copy.deepcopy(self.effects)
                row = edited['machine_import_signatures'][0]
                if change == 'prerequisite':
                    row['effect_model']['prerequisites']['same_pinned_dll_implementation'] = False
                elif change == 'empty':
                    edited['machine_import_signatures'] = []
                else:
                    row['canonical_boundary'] = self.abi['machine_import_signatures'][0]['canonical_boundary']
                self.write(self.effect_path, edited)
                with self.assertRaises(MachineImportProfileError):
                    self.compose()

    def test_unselected_imports_remain_abi_only(self):
        second = copy.deepcopy(self.abi['machine_import_signatures'][0])
        second['id'], second['import']['symbol'] = 'abi:other', 'other'
        self.abi['machine_import_signatures'].append(second)
        self.write(self.abi_path, self.abi)
        result = self.compose()
        other = next(row for row in result['machine_import_signatures'] if row['import']['symbol'] == 'other')
        self.assertNotIn('memory_effect', other)
