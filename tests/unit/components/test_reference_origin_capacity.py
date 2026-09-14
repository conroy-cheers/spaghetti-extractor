"""Local proof storage bounds retain overflow obligations and exact binding."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_reference_origins import capacity_description, checked_capacity
from .borrowed_state_fixture import check_borrowed_state
from . import test_bisimulation_mutable_composition as composition_tests

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'nix/jq/strong-contextual-proof.jq')}


class ReferenceOriginCapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name); cls.cases = {}
        for capacity in (1, 2):
            root = cls.root / str(capacity); root.mkdir()
            cls.cases[capacity] = check_borrowed_state(root, cbmc=Path(shutil.which('cbmc')), origin_capacity=capacity)
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT['resources'][1]).read_text()

    seal = staticmethod(composition_tests.MutableCompositionTests.seal)
    readers = composition_tests.MutableCompositionTests.readers

    def test_sufficient_capacity_is_checked_and_bound(self):
        result, case = self.cases[2]
        self.assertEqual(result['status'], 'satisfied', result.get('issues'))
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
        operation = case['proof']['models']['operation_models'][0]
        self.assertEqual(operation['reference_origin_capacity'], 2)
        self.assertIn(capacity_description(2), operation['obligation_models'][0]['required_assertion_descriptions'])
        source = (self.root / '2/diagnostics/operation-0000-obligation-0000/bisimulation.c').read_text()
        self.assertIn('spx_proof_origin entries[2]', source)
        self.assertIn('__CPROVER_assert(origins->count < UINT32_C(2)', source)

    def test_insufficient_capacity_does_not_hide_the_extra_origin(self):
        result, case = self.cases[1]
        self.assertEqual(result['status'], 'violated', result.get('issues'))
        self.assertNotEqual(case['proof']['status'], 'satisfied')

    def test_modified_capacity_or_missing_guard_rejects_old_evidence(self):
        for mutation in ('operation', 'segment', 'plan', 'all', 'guard', 'null', 'boolean', 'erased'):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.cases[2][1]); operation = case['proof']['models']['operation_models'][0]
                segment = operation['obligation_models'][0]; planned = case['proof_plan']['operations'][0]
                rows = {'operation': operation, 'segment': segment, 'plan': planned}
                if mutation in rows: rows[mutation]['reference_origin_capacity'] = 1
                elif mutation == 'all':
                    for row in rows.values(): row['reference_origin_capacity'] = 1
                elif mutation == 'guard': segment['required_assertion_descriptions'].remove(capacity_description(2))
                elif mutation == 'null': segment['reference_origin_capacity'] = None
                elif mutation == 'boolean': segment['reference_origin_capacity'] = True
                else: operation.pop('reference_origin_capacity')
                self.assertEqual(self.readers(case), (False, False))

    def test_resource_request_validation_and_default(self):
        self.assertEqual(checked_capacity(None, 16), 16)
        self.assertEqual(checked_capacity(3, 16), 3)
        with self.assertRaises(ValueError): checked_capacity(17, 16)
        for value in (None, True, 0, -1, 1.5, 4294967296):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ComponentBisimulationIntentV1.create(component_id='sample', operations=[{
                    'operation_id': 'run', 'syncs': [], 'reference_origin_capacity': value}])
