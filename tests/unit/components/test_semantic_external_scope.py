"""A component may use selected imports while unrelated contracts remain open."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from . import test_semantic_external_services as fixture


class SemanticExternalScopeTests(unittest.TestCase):
    def contract(self, mutate):
        original = fixture._resolved_environment
        observed = []

        def environment(*args, **kwargs):
            value = original(*args, **kwargs)
            mutate(value)
            value['resolved_environment_sha256'] = canonical_sha256_v3({
                k: v for k, v in value.items() if k != 'resolved_environment_sha256'})
            observed.append(copy.deepcopy(value))
            return value

        with tempfile.TemporaryDirectory() as directory, patch.object(
                fixture, '_resolved_environment', side_effect=environment):
            inputs = fixture.SemanticExternalServiceTests()._factory_refinement_fixture(Path(directory))
            return json.loads(inputs['contract'].read_text()), observed[0]

    @staticmethod
    def unresolved(value):
        value['status'] = 'incomplete'
        value['authority'] = 'none'
        value['blockers'] = [{'category': 'reachable_import_contract_unresolved'}]
        value['machine_import_contracts'].append({
            'identity': {'dll': 'other.dll', 'symbol': 'Unresolved', 'ordinal': None},
            'contract': None, 'boundary': None})

    def test_unrelated_hole_preserves_selected_service_and_environment_binding(self):
        result, environment = self.contract(self.unresolved)
        self.assertEqual(result['status'], 'satisfied', result['issues'])
        self.assertEqual(result['bindings']['resolved_external_environment_sha256'],
                         environment['resolved_environment_sha256'])
        self.assertEqual(environment['status'], 'incomplete')
        self.assertTrue(environment['blockers'])
        self.assertEqual(result['services'][0]['provider']['kind'], 'checked_external_call_events')

    def test_selected_unresolved_service_remains_incomplete(self):
        def missing(value):
            self.unresolved(value)
            value['machine_import_contracts'][0].update(contract=None, boundary=None)
        result, _ = self.contract(missing)
        self.assertEqual(result['status'], 'incomplete', result['issues'])
        self.assertIn('bound_external_call_contract_missing', [r['code'] for r in result['issues']])

    def test_duplicate_or_partially_resolved_rows_remain_invalid(self):
        for variant in ('duplicate_unresolved', 'duplicate_selected', 'partial', 'omitted'):
            def invalid(value):
                self.unresolved(value)
                rows = value['machine_import_contracts']
                if variant.startswith('duplicate'):
                    rows.append(copy.deepcopy(rows[-1 if variant.endswith('unresolved') else 0]))
                elif variant == 'partial':
                    rows[-1]['boundary'] = {}
                else:
                    del rows[-1]['contract']
            with self.subTest(variant=variant):
                result, _ = self.contract(invalid)
                self.assertEqual(result['status'], 'violated', result['issues'])
                self.assertIn('resolved_external_environment_invalid', [r['code'] for r in result['issues']])


if __name__ == '__main__':
    unittest.main()
