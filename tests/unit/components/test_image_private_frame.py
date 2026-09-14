"""Locality is checked separately from ordinary empty-world equivalence."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_image_frame import FRAME, checked_operations
from .borrowed_state_fixture import check_borrowed_state
from . import test_bisimulation_mutable_composition as composition_tests

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'nix/jq/strong-contextual-proof.jq')}


class ImagePrivateFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.cases = {}
        for name, foreign in (('local', False), ('foreign', True)):
            root = cls.root / name; root.mkdir()
            result, case = check_borrowed_state(root, cbmc=Path(shutil.which('cbmc')), foreign_read=foreign)
            if result['status'] != 'satisfied':
                raise AssertionError(result['issues'])
            cls.cases[name] = case
        cls.program = (Path(__file__).resolve().parents[3] / TESTKIT['resources'][1]).read_text()

    seal = staticmethod(composition_tests.MutableCompositionTests.seal)
    readers = composition_tests.MutableCompositionTests.readers

    def test_checked_locality_binds_the_wide_entry_and_retained_model(self):
        case = self.cases['local']
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))
        self.assertEqual(checked_operations(case['proof'], artifacts=self.root/'local/diagnostics'), ('get',))

    def test_unused_foreign_read_preserves_equivalence_but_has_no_frame_guarantee(self):
        case = self.cases['foreign']
        self.assertEqual(case['proof']['status'], 'satisfied')
        self.assertEqual(case['proof']['shards'][0][FRAME.field]['result']['status'], 'violated')
        self.assertEqual(checked_operations(case['proof'], artifacts=self.root/'foreign/diagnostics'), ())
        self.assertEqual(self.readers(copy.deepcopy(case)), (True, True))

    def test_weakened_or_unbound_auxiliary_evidence_rejects_both_readers(self):
        for mutation in ('command', 'entry', 'model', 'inventory'):
            with self.subTest(mutation=mutation):
                case = copy.deepcopy(self.cases['local']); proof = case['proof']; shard = proof['shards'][0]
                frame = shard[FRAME.field]
                if mutation == 'command': frame['command'] = frame['command'][:2]
                elif mutation == 'entry': del shard['mutable_entry_contract']
                elif mutation == 'model': frame['bindings']['goto_model_sha256'] = '0' * 64
                else:
                    model = proof['models']['operation_models'][0]['obligation_models'][0]
                    model['required_assertion_descriptions'].remove(FRAME.description)
                self.seal(frame)
                self.assertEqual(self.readers(case), (False, False))

    def test_retained_bytes_are_required_for_consumption(self):
        path = self.root/'local/diagnostics/operation-0000-obligation-0000'/f'{FRAME.artifact_stem}.stdout'
        previous = path.read_bytes()
        try:
            path.write_bytes(previous + b'\nchanged\n')
            with self.assertRaisesRegex(ValueError, 'retained solver output differs'):
                checked_operations(self.cases['local']['proof'], artifacts=self.root/'local/diagnostics')
        finally:
            path.write_bytes(previous)
