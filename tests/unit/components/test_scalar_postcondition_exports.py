"""Authored scalar exports require their exact source and enclosing local proof."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.components.relation_v5 import ComponentRelationIntentV1
from spaghetti_extractor.semantic_providers.portable_c_postconditions import (
    checked_provider_postconditions, validate_provider_postconditions,
    validate_provider_postcondition_request,
)
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.jq_reader import run as run_jq

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': ('nix/jq/strong-contextual-proof.jq',)}


def request(op='true'):
    return ComponentRelationIntentV1.create(component_id='counter', blockers=[], operations=[{
        'operation_id': 'run', 'requirements': [{'id': 'normal-return',
            'relation': 'normal_exit_postcondition', 'expression': {
                'op': op, 'sort': {'kind': 'bool'}, 'args': [], 'attributes': {}}}]}])


class ScalarPostconditionExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cbmc = shutil.which('cbmc')
        if not cbmc:
            raise unittest.SkipTest('CBMC required')
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.inputs = {}
        result = check_normal_exit(Path(temporary.name), cbmc=Path(cbmc),
            scalar_postcondition_intent=request(), retained_inputs=cls.inputs)
        if result['status'] != 'satisfied':
            raise AssertionError(result)

    def test_export_requires_complete_bound_theorems_and_passes_both_readers(self):
        value = checked_provider_postconditions(intent=request(), **self.inputs)
        validate_provider_postconditions(value, **self.inputs)
        validate_provider_postcondition_request(value, requested_sha256=request().intent_sha256)
        self.assertFalse(value['authorizing'])
        self.assertEqual(value['facts'][0]['derivation'], 'checked-scalar-source-postcondition-v1')
        self.assertEqual(value['facts'][0]['proof_receipt_sha256'], self.inputs['proof_system']['proof']['receipt_sha256'])
        jq = shutil.which('jq')
        if not jq:
            self.skipTest('JQ required')
        reader = Path('nix/jq/strong-contextual-proof.jq').read_text() + '\nspx_strong_contextual_proof\n'
        checked = run_jq([jq, '-e', reader], input=json.dumps(self.inputs['proof_system']), text=True, capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_declared_false_guarantee_cannot_reuse_valid_true_export(self):
        with self.assertRaisesRegex(ValueError, 'requested checked guarantees'):
            checked_provider_postconditions(intent=request('false'), **self.inputs)

    def test_exports_cannot_be_attached_to_different_proof_or_source(self):
        for mutation in ('proof', 'source', 'signature', 'omitted-fact', 'activation'):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                inputs = copy.deepcopy(self.inputs)
                value = checked_provider_postconditions(intent=request(), **inputs)
                if mutation == 'proof':
                    inputs['proof_system']['proof']['receipt_sha256'] = 'f' * 64
                elif mutation == 'source':
                    inputs['proof_system']['proof']['models']['source_summary_contracts']['implementation_sha256'] = 'f' * 64
                elif mutation == 'signature':
                    inputs['operation_symbols']['run'] = 'another_function'
                elif mutation == 'omitted-fact':
                    value['facts'] = []
                else:
                    value['authorizing'] = True
                validate_provider_postconditions(value, **inputs)
