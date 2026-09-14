"""Shared service consumers retain memory dependencies as checked contracts.

The real resource-text candidate is used at its full extent. These are auxiliary
frame/dependence tests, not a proof of its original binary or native activation.
"""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_readonly_source_contracts, check_shared_source_contracts
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_shared_source_contracts, validate_readonly_source_contracts
from spaghetti_extractor.components.bisimulation_readonly_evidence import checked_connected_source_contract
from spaghetti_extractor.components.bisimulation_shared_model import SHARED_DEPENDENCY_POLICY
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.machine_overlay_services_v5 import _c_identifier
from .test_bisimulation_readonly_model import fixed_readonly_bundle
from .test_hand_defined_boundaries import FIXTURE
from .test_shared_source_contracts import small_bundle

TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text',
    'targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json')}

WORD = '''uint64_t word;
  if (left->read(left->access_context, left->base, 0U, 4U, &word)) return 0U;
  return (uint32_t)word;'''
WORD_LOOP = '''uint32_t word = 0U;
  for (uint32_t i = 0; i < 4U; ++i) {
    uint8_t byte;
    if (spx_view_read_u8(left, i, &byte)) return 0U;
    word |= (uint32_t)byte << (8U * i);
  }
  return word;'''


def word_bundle(extent=4):
    intent = fixed_readonly_bundle((extent, extent)).intent
    signature = intent.schema.signature_index['operation.compare'].to_payload()
    signature['parameters'] = signature['parameters'][:1]
    signature['results'][0]['type_id'] = 'u32'
    types = intent.schema.to_payload()['types']
    function = next(row for row in types if row['id'] == signature['function_type_id'])
    function.update(parameter_type_ids=['byte_span'], result_type_id='u32')
    operation = copy.deepcopy(intent.to_payload()['operations'][0])
    operation['source_values'] = signature['parameters'] + signature['results']
    operation['projection_entries'] = [row for row in operation['projection_entries'] if row['source_id'] in {'left', 'result'}]
    operation['lifecycle_bindings'] = operation['lifecycle_bindings'][:1]
    schema = BoundarySchemaV1.create(schema_id='component.module-word', types=types, signatures=[signature])
    return compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id='module-word', schema=schema, state=(), operations=[operation], effects=(), services=(),
        protocol_states=intent.protocol_states, initial_protocol_state=intent.initial_protocol_state))


def check_word(root, body=WORD, *, extent=4):
    root.mkdir()
    source = root/'word.c'
    source.write_text('#include "portable-component-implementation.h"\n'
        'uint32_t module_word(spx_module_word_context_v5 *context, const spx_view_v5 *left) {\n  (void)context;\n' + body + '\n}\n')
    build_component_source_package(lift_unit_id='module-word', files={'word.c': source}, shared_inputs={},
        operation_symbols={'compare': 'module_word'}, out_dir=root/'source')
    return check_readonly_source_contracts(bundle=word_bundle(extent), package=root/'source', output=root/'proof',
        **checker_tools())


def checker_tools():
    return dict(goto_cc=Path(shutil.which('goto-cc')), goto_instrument=Path(shutil.which('goto-instrument')),
                cbmc=Path(shutil.which('cbmc')), unwind=16, timeout_seconds=60)


def check_consumer(root, dependency, *, source=None, previous=None, maximum_calls=1, extent=500, maximum_memory_events=None):
    root.mkdir()
    original = (FIXTURE/'resource-text.c').read_text()
    start = original.index('  uint64_t module;')
    end = original.index('  context->services->load_string', start)
    if source is None:
        source = original[:start] + ('  uint32_t module = spx_component_logical_module_word_compare(\n'
            '      context->services->context, &context->state.module);\n') + original[end:]
    author = root/'resource-text.c'
    author.write_text(source)
    build_component_source_package(lift_unit_id='resource-text', files={'resource-text.c': author}, shared_inputs={},
        operation_symbols={'get': 'resource_text'}, out_dir=root/'source')
    timings = []
    dependency_id = _c_identifier(dependency[0]['interface_intent']['id'])
    result = check_shared_source_contracts(bundle=small_bundle(extent), package=root/'source', output=root/'proof',
        summary_dependencies=[{'symbol': f'spx_component_logical_{dependency_id}_compare', 'operation_id': 'compare',
            'certificate': dependency[0], 'artifacts': dependency[1]}], previous_contract=previous,
        shared_contract={'relation_intent': json.loads((FIXTURE/'relation.json').read_text()),
            'maximum_calls': maximum_calls, 'maximum_memory_events': maximum_calls if maximum_memory_events is None else maximum_memory_events},
        timings=timings, **checker_tools())
    return result, timings


class SharedMemoryDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ('goto-cc', 'goto-instrument', 'cbmc')):
            raise unittest.SkipTest('CBMC tools unavailable')
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.word = check_word(cls.root/'word')
        assert cls.word['status'] == 'satisfied', cls.word['checks']
        cls.before, cls.timings = check_consumer(cls.root/'before', (cls.word, cls.root/'word/proof'))

    def test_real_shared_candidate_checks_without_word_reader_body(self):
        self.assertEqual(self.before['status'], 'satisfied', self.before['checks'])
        self.assertEqual(self.before['policy'], SHARED_DEPENDENCY_POLICY)
        validate_shared_source_contracts(self.before, artifacts=self.root/'before/proof')
        with self.assertRaises(ValueError):
            validate_readonly_source_contracts(self.before)
        with self.assertRaisesRegex(ValueError, 'requires transitive machine qualification'):
            checked_connected_source_contract(bound={'certificate': self.before}, bundle=small_bundle(500),
                source=self.before['source_package'], source_profile_sha256=self.before['source_profile']['receipt_sha256'],
                operation_symbols=self.before['operation_symbols'], headers={}, readonly_artifacts=self.root/'before/proof')
        for model in self.before['models']:
            text = (self.root/'before/proof'/f"{model['operation_id']}-{model['kind']}.c").read_text()
            self.assertIn('__CPROVER_uninterpreted_spx_component_logical_module_word_compare_result', text)
            self.assertIn('500U', text)
        authored = next(row for row in self.before['inventories'] if row['step'] == 'authored-functions')
        self.assertNotIn('module_word', {row['name'] for row in authored['rows'] if row.get('isBodyAvailable')})

    def test_supplier_loop_edit_reuses_shared_consumer_without_tools(self):
        changed = check_word(self.root/'changed', WORD_LOOP)
        self.assertEqual(changed['status'], 'satisfied', changed['checks'])
        self.assertNotEqual(changed['authored_goto_sha256'], self.word['authored_goto_sha256'])
        with patch('subprocess.run', side_effect=AssertionError('consumer ran a compiler or solver')):
            reused, timings = check_consumer(self.root/'reused', (changed, self.root/'changed/proof'),
                previous=self.root/'before/proof')
        self.assertEqual(reused['models'], self.before['models'])
        self.assertEqual(reused['checks'], self.before['checks'])
        self.assertNotEqual(reused['receipt_sha256'], self.before['receipt_sha256'])
        self.assertEqual([row['phase'] for row in timings], ['preparation', 'evidence-reuse'])
        self.assertEqual(timings[-1]['executed_queries'], 0)

    def test_changed_memory_extent_and_bad_alias_are_rejected(self):
        larger = check_word(self.root/'larger', extent=5)
        self.assertEqual(larger['status'], 'satisfied', larger['checks'])
        bad, timings = check_consumer(self.root/'incompatible', (larger, self.root/'larger/proof'),
            previous=self.root/'before/proof')
        self.assertEqual(bad['status'], 'incomplete')
        self.assertNotIn('evidence-reuse', [row['phase'] for row in timings])
        original = (self.root/'before/resource-text.c').read_text()
        bad, _ = check_consumer(self.root/'wrong-alias', (self.word, self.root/'word/proof'),
            source=original.replace('return context->state.buffer;', 'return context->state.module;'))
        self.assertEqual(bad['status'], 'incomplete')

    def test_readonly_store_artifacts_can_be_rebound_without_changing_inputs(self):
        cache = self.root/'readonly-cache'
        shutil.copytree(self.root/'before/proof', cache)
        paths = [cache, *cache.rglob('*')]
        before = {path.relative_to(cache): path.read_bytes() for path in paths if path.is_file()}
        try:
            for path in paths:
                path.chmod(0o555 if path.is_dir() else 0o444)
            with patch('subprocess.run', side_effect=AssertionError('consumer ran a tool')):
                result, _ = check_consumer(self.root/'readonly-rebound', (self.word, self.root/'word/proof'), previous=cache)
            self.assertEqual(result['status'], 'satisfied')
            for relative, contents in before.items():
                self.assertEqual((cache/relative).read_bytes(), contents)
                self.assertEqual((cache/relative).stat().st_mode & 0o222, 0)
        finally:
            for path in paths:
                path.chmod(0o755 if path.is_dir() else 0o644)

    def test_changed_own_service_contract_requires_rechecking(self):
        result, timings = check_consumer(self.root/'refined', (self.word, self.root/'word/proof'),
            previous=self.root/'before/proof', maximum_calls=2)
        self.assertEqual(result['status'], 'satisfied', result['checks'])
        self.assertNotIn('evidence-reuse', [row['phase'] for row in timings])
        self.assertNotEqual(result['models'], self.before['models'])

    def test_mutable_dependency_writes_flow_into_service_and_current_memory(self):
        from .test_bisimulation_source_dependencies import make_source
        from .test_bisimulation_mutable_model import COPY
        leaf, _ = make_source(self.root/'copy', 'copy', COPY, extents=(1, 4), unwind=16)
        self.assertEqual(leaf['status'], 'satisfied', [(row.get('kind'), row['status'], row.get('detail')) for row in leaf['checks']])
        source = (FIXTURE/'resource-text.c').read_text().replace('500U', '1U').replace(
            '  uint64_t module;', '  (void)spx_component_logical_copy_compare(context->services->context,\n'
            '      &context->state.buffer, &context->state.module, 1U);\n  uint64_t module;')
        result, _ = check_consumer(self.root/'copy-consumer', (leaf, self.root/'copy/proof'),
            source=source, extent=1, maximum_memory_events=2)
        self.assertEqual(result['status'], 'satisfied', [(row.get('kind'), row['status'], row.get('detail')) for row in result['checks']])
        bad, _ = check_consumer(self.root/'copy-capacity', (leaf, self.root/'copy/proof'),
            source=source, extent=1, maximum_memory_events=1)
        self.assertEqual(bad['status'], 'incomplete')

    def test_dependency_cannot_borrow_another_private_context(self):
        source = (self.root/'before/resource-text.c').read_text().replace(
            'context->services->context, &context->state.module', '(void *)0, &context->state.module')
        result, _ = check_consumer(self.root/'bad-context', (self.word, self.root/'word/proof'), source=source)
        self.assertEqual(result['status'], 'incomplete')
        opacity = next(row for row in result['checks'] if row.get('kind') == 'source_opacity')
        self.assertNotEqual(opacity['status'], 'satisfied')
