"""A checked local current-memory fact cannot be supplied by alias evidence."""
import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_shared_source_contracts
from spaghetti_extractor.components.bisimulation_shared_model import render_shared_source_model
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.components.bisimulation_shared_summary import shared_summary_operation
from spaghetti_extractor.components.normal_exit_postconditions import shared_result_postcondition
from spaghetti_extractor.components.relation_ir import RelationExpressionV1
from spaghetti_extractor.components.relation_v5 import ComponentRelationIntentV1
from spaghetti_extractor.semantic_providers.portable_c_postconditions import normal_exit_intent
from .test_shared_output_termination import selected_output
from .test_shared_service_premises import binding
from .test_shared_source_contracts import small_bundle, check_shared
from .test_hand_defined_boundaries import FIXTURE

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'profiles/pe32-user32-resource-text-runtime-v1.json',
    'nix/jq/strong-contextual-proof.jq')}


def current_memory_intent():
    intent = json.loads((FIXTURE/'relation.json').read_text())
    row = intent['operations'][0]['requirements'][0]
    equality = row['expression']
    result = next(term for term in equality['args'] if term['attributes']['path']['root'] == 'result')
    row['expression'] = {'op': 'and', 'sort': {'kind': 'bool'}, 'attributes': {}, 'args': [
        equality, {'op': 'view_has_zero', 'sort': {'kind': 'bool'}, 'attributes': {}, 'args': [result]}]}
    return ComponentRelationIntentV1.create(component_id=intent['component_id'],
        operations=intent['operations'], blockers=[]).to_payload()


class SharedCurrentMemoryPostconditionTests(unittest.TestCase):
    def test_current_output_is_proved_and_exact_readers_require_the_new_assertions(self):
        contracts = normalize_shared_service_bindings(small_bundle(), [selected_output()])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = check_shared(root, service_contracts=contracts, maximum_memory_events=2,
                                  relation_intent=current_memory_intent())
            self.assertEqual(result['status'], 'satisfied', result.get('checks'))
            validate_shared_source_contracts(result, artifacts=root/'proof')
            def jq(value):
                p = subprocess.run([shutil.which('jq'), '-L', 'nix/jq',
                    'include "strong-contextual-proof"; spx_shared_certificate'], input=json.dumps(value),
                    capture_output=True, text=True, check=True, timeout=10)
                return json.loads(p.stdout)
            self.assertTrue(jq(result))
            for kind, indexes in (('frame', (3,)), ('input_dependence', (5, 6))):
                for index in indexes:
                    with self.subTest(kind=kind, index=index):
                        changed = copy.deepcopy(result)
                        check = next(r for r in changed['checks'] if r.get('kind') == kind)
                        check['property_ids'].remove(f'spx_shared_{kind}_get.assertion.{index}')
                        check['properties'] -= 1
                        changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
                        with self.assertRaisesRegex(ValueError, 'current-zero assertion'):
                            validate_shared_source_contracts(changed)
                        self.assertFalse(jq(changed))
            changed = copy.deepcopy(result)
            expression = changed['shared_contract']['relation_intent']['operations'][0]['requirements'][0]['expression']
            expression['args'][1]['args'][0] = next(term for term in expression['args'][0]['args']
                                                   if term['attributes']['path']['root'] == 'state')
            self.assertFalse(jq(changed))

    def test_alias_only_service_and_alias_overwrite_do_not_establish_current_zero(self):
        original = (FIXTURE/'resource-text.c').read_text().replace('500U', '8U')
        overwritten = original.replace('context->services->load_string(', 'uint32_t count = context->services->load_string(')
        overwritten = overwritten.replace('return context->state.buffer;', '''
  context->state.buffer.write(context->state.buffer.access_context,
      context->state.buffer.base, count, 1U, 93U);
  return context->state.buffer;''')
        for row, source in ((binding(), original), (selected_output(), overwritten)):
            with self.subTest(row=row), tempfile.TemporaryDirectory() as directory:
                result = check_shared(Path(directory), source, maximum_memory_events=3,
                    service_contracts=normalize_shared_service_bindings(small_bundle(), [row]),
                    relation_intent=current_memory_intent())
                self.assertEqual(result['status'], 'incomplete')
                failures = [r for r in result['checks'] if r.get('kind') in {'frame', 'input_dependence'}
                            and r['status'] == 'violated']
                self.assertTrue(failures, result.get('checks'))
                self.assertTrue(any('current-zero' in str(r.get('detail')) for r in failures), failures)

    def test_ordinary_store_proves_zero_without_an_output_service_promise(self):
        original = (FIXTURE/'resource-text.c').read_text().replace('500U', '8U')
        source = original.replace('return context->state.buffer;', '''
  context->state.buffer.write(context->state.buffer.access_context,
      context->state.buffer.base, 7U, 1U, 0U);
  return context->state.buffer;''')
        with tempfile.TemporaryDirectory() as directory:
            result = check_shared(Path(directory), source, maximum_memory_events=2,
                service_contracts=normalize_shared_service_bindings(small_bundle(), [binding()]),
                relation_intent=current_memory_intent())
            self.assertEqual(result['status'], 'satisfied', result.get('checks'))

    def test_memory_request_is_explicit_and_independent_of_buffer_length(self):
        intent = current_memory_intent()
        self.assertEqual(normal_exit_intent(intent, bundle=small_bundle()).to_payload(), intent)
        contract = {'relation_intent': intent, 'maximum_calls': 1, 'maximum_memory_events': 2,
                    'service_contracts': normalize_shared_service_bindings(small_bundle(), [selected_output()])}
        self.assertEqual(shared_summary_operation(small_bundle(), 'get', contract)[0], 'buffer')
        models = [render_shared_source_model(bundle=small_bundle(extent), operation_id='get',
                  symbol='resource_text', kind='frame', shared_contract=contract)[0]
                  for extent in (500, 1000000)]
        self.assertEqual(models[0].count('\n'), models[1].count('\n'))
        self.assertLess(abs(len(models[1])-len(models[0])), 160)
        expression = intent['operations'][0]['requirements'][0]['expression']
        for mutation in ('result_sort', 'operand_sort', 'extra_attribute', 'wrong_view'):
            bad = copy.deepcopy(expression)
            predicate = bad['args'][1]
            if mutation == 'result_sort':
                predicate['sort'] = {'kind': 'bitvector', 'width': 32}
            elif mutation == 'operand_sort':
                predicate['args'][0]['sort'] = {'kind': 'bitvector', 'width': 32}
            elif mutation == 'extra_attribute':
                predicate['attributes']['historical'] = True
            else:
                predicate['args'][0]['attributes']['path']['id'] = 'module'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                RelationExpressionV1.parse(bad)
                shared_result_postcondition(bad, bundle=small_bundle(), operation_id='get')
