"""Ordinary source consumes a selected output fact, with exact local evidence."""
import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_shared_source_contracts
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from .test_shared_service_premises import binding
from .test_shared_source_contracts import small_bundle, check_shared
from .test_hand_defined_boundaries import FIXTURE

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'profiles/pe32-user32-resource-text-runtime-v1.json',
    'nix/jq/strong-contextual-proof.jq')}


def selected_output():
    row = binding()
    row['external_effect_contract']['result_register_relations'] = [{
        'register': 'eax', 'relation': 'written_terminated_byte_count',
        'base_argument': 2, 'capacity_argument': 3}]
    return row


def consumer():
    original = (FIXTURE/'resource-text.c').read_text().replace('500U', '8U')
    call = '''context->services->load_string(context->services->context,
      (uint32_t)module, id, &context->state.buffer, 8U);'''
    assert call in original
    return original.replace(call, 'uint32_t count = ' + call + '''
  uint64_t byte;
  if (count >= 8U) return context->state.module;
  if (context->state.buffer.read(context->state.buffer.access_context,
        context->state.buffer.base, count, 1U, &byte) || byte != 0U)
    return context->state.module;''')


class SharedOutputTerminationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(all(shutil.which(t) for t in ('cbmc', 'goto-cc', 'goto-instrument')))

    def test_ordinary_c_consumes_output_count_and_current_zero(self):
        contracts = normalize_shared_service_bindings(small_bundle(), [selected_output()])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = check_shared(root, consumer(), service_contracts=contracts, maximum_memory_events=2)
            self.assertEqual(result['status'], 'satisfied', result.get('checks'))
            validate_shared_source_contracts(result, artifacts=root/'proof')
            for capacity, valid in ((3, True), (2, False), (True, False), (4, False)):
                changed = copy.deepcopy(result)
                changed['shared_contract']['service_contracts'][0]['external_effect_contract']['result_register_relations'][0]['capacity_argument'] = capacity
                checked = run_jq_reader([shutil.which('jq'), '-L', 'nix/jq',
                    'include "strong-contextual-proof"; spx_shared_certificate'], input=json.dumps(changed),
                    capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(json.loads(checked.stdout), valid)
            altered = copy.deepcopy(result)
            altered['shared_contract']['service_contracts'][0]['external_effect_contract']['result_register_relations'] = [
                {'register': 'eax', 'relation': 'exact'}]
            altered['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in altered.items() if k != 'receipt_sha256'})
            with self.assertRaises(ValueError):
                validate_shared_source_contracts(altered, artifacts=root/'proof')

    def test_signature_alone_and_later_alias_overwrite_do_not_prove_output(self):
        mutated = consumer().replace('  uint64_t byte;', '''
  if (count >= 8U) return context->state.module;
  context->state.buffer.write(context->state.buffer.access_context,
      context->state.buffer.base, count, 1U, 93U);
  uint64_t byte;''')
        for row, source in ((binding(), consumer()), (selected_output(), mutated)):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                result = check_shared(Path(directory), source,
                    service_contracts=normalize_shared_service_bindings(small_bundle(), [row]),
                    maximum_memory_events=3)
                self.assertEqual(result['status'], 'incomplete')
                failures = [r for r in result['checks'] if r.get('kind') in {'frame', 'input_dependence'}
                            and r['status'] == 'violated']
                self.assertTrue(failures, result.get('checks'))
                self.assertTrue(any('result-alias' in str(r.get('detail')) for r in failures), failures)

    def test_zero_capacity_is_rejected_before_vacuous_output_constraint(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check_shared(Path(directory), consumer().replace('&context->state.buffer, 8U)', '&context->state.buffer, 0U)'),
                service_contracts=normalize_shared_service_bindings(small_bundle(), [selected_output()]),
                maximum_memory_events=2)
            self.assertEqual(result['status'], 'incomplete')
            self.assertTrue(any(r.get('kind') in {'frame', 'input_dependence'} and r['status'] == 'violated'
                                for r in result['checks']), result.get('checks'))
