"""Local shared-memory/service theorems use authored boundaries and exact evidence."""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_shared_source_contracts
from spaghetti_extractor.components.bisimulation_readonly_evidence import (
    validate_shared_source_contracts, validate_mutable_source_contracts, checked_connected_source_contract,
)
from spaghetti_extractor.components.interface_package_v5 import compile_component_interface_v5
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.bisimulation_shared_model import render_shared_source_model
from spaghetti_extractor.commands.component_review import _interface
from .test_hand_defined_boundaries import FIXTURE

TESTKIT = {'fixtures': ('cbmc','compiler'), 'resources': ('tests/fixtures/hand-defined-boundaries/resource-text',)}


def small_bundle(extent=8):
    payload = json.loads((FIXTURE/'interface.json').read_text().replace('500',str(extent)))
    return compile_component_interface_v5(_interface(payload))


def check_shared(root, source=None, *, maximum_calls=1, service_contracts=None, maximum_memory_events=None, relation_intent=None):
    root.mkdir(parents=True,exist_ok=True)
    file=root/'author.c'
    file.write_text((FIXTURE/'resource-text.c').read_text().replace('500U','8U') if source is None else source)
    build_component_source_package(lift_unit_id='resource-text',files={'author.c':file}, shared_inputs={},
        operation_symbols={'get':'resource_text'},out_dir=root/'source')
    return check_shared_source_contracts(bundle=small_bundle(),package=root/'source',output=root/'proof',
        goto_cc=Path(shutil.which('goto-cc')),goto_instrument=Path(shutil.which('goto-instrument')),
        cbmc=Path(shutil.which('cbmc')),timeout_seconds=60,unwind=16,
        shared_contract={'relation_intent':json.loads((FIXTURE/'relation.json').read_text()) if relation_intent is None else relation_intent,'maximum_calls':maximum_calls,'maximum_memory_events':maximum_calls if maximum_memory_events is None else maximum_memory_events,
                         **({'service_contracts':service_contracts} if service_contracts is not None else {})})


class SharedSourceContractTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(tool) for tool in ('goto-cc','goto-instrument','cbmc')):
            self.skipTest('CBMC tools unavailable')

    def test_source_model_size_tracks_events_instead_of_buffer_extent(self):
        contract={'relation_intent':json.loads((FIXTURE/'relation.json').read_text()),
                  'maximum_calls':1,'maximum_memory_events':1}
        models=[render_shared_source_model(bundle=small_bundle(extent),operation_id='get',symbol='resource_text',
            kind='input_dependence',shared_contract=contract)[0] for extent in (8,1000000)]
        self.assertEqual(models[0].count('\n'),models[1].count('\n'))
        self.assertLess(abs(len(models[1])-len(models[0])),128)
        self.assertIn('uint32_t arbitrary_probe',models[0])

    def test_shared_frame_trace_and_authored_alias_bind_retained_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            result=check_shared(root)
            self.assertEqual(result['status'],'satisfied',[(r.get('kind'),r.get('step'),r.get('detail'),r.get('issues')) for r in result['checks']])
            validate_shared_source_contracts(result)
            validate_shared_source_contracts(result,artifacts=root/'proof')
            with self.assertRaises(ValueError):
                validate_mutable_source_contracts(result)
            with self.assertRaisesRegex(ValueError,'require checked supplier models and retained source evidence'):
                checked_connected_source_contract(bound={'certificate':result},bundle=small_bundle(),
                    source=result['source_package'],source_profile_sha256=result['source_profile']['receipt_sha256'],
                    operation_symbols=result['operation_symbols'],headers={},readonly_artifacts=root/'proof')
            altered=copy.deepcopy(result)
            altered['shared_contract']['maximum_calls']=2
            altered['receipt_sha256']=canonical_sha256_v3({k:v for k,v in altered.items() if k!='receipt_sha256'})
            with self.assertRaises(ValueError):
                validate_shared_source_contracts(altered)
            altered=copy.deepcopy(result)
            check=next(row for row in altered['checks'] if row.get('kind')=='input_dependence')
            check['property_ids'].remove('spx_shared_input_dependence_get.assertion.3')
            check['properties']-=1
            altered['receipt_sha256']=canonical_sha256_v3({k:v for k,v in altered.items() if k!='receipt_sha256'})
            with self.assertRaisesRegex(ValueError,'result-alias assertion'):
                validate_shared_source_contracts(altered)
            (root/'proof/get-input_dependence.c').write_text('void stale(void) {}\n')
            with self.assertRaisesRegex(ValueError,'model meaning'):
                validate_shared_source_contracts(result,artifacts=root/'proof')

    def test_wrong_result_alias_and_descriptor_mutation_fail_the_local_theorem(self):
        original=(FIXTURE/'resource-text.c').read_text().replace('500U','8U')
        for source in (
            original.replace('return context->state.buffer;', 'return context->state.module;'),
            original.replace('uint64_t module;', 'uint64_t module; context->state.buffer.extent -= 1;'),
        ):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                result=check_shared(Path(directory),source)
                self.assertEqual(result['status'],'incomplete')
                self.assertTrue(any(row.get('kind') in {'frame','input_dependence'} and row['status']!='satisfied'
                                    for row in result['checks']))

    def test_repeated_service_calls_preserve_current_memory_and_check_capacity(self):
        original=(FIXTURE/'resource-text.c').read_text().replace('500U','8U')
        call='''context->services->load_string(context->services->context,
      (uint32_t)module, id, &context->state.buffer, 8U);'''
        self.assertIn(call,original)
        repeated=original.replace(call,call+'\n'+call)
        for maximum_calls,expected in ((1,'incomplete'),(2,'satisfied')):
            with self.subTest(maximum_calls=maximum_calls), tempfile.TemporaryDirectory() as directory:
                result=check_shared(Path(directory),repeated,maximum_calls=maximum_calls)
                self.assertEqual(result['status'],expected,
                    [(row.get('kind'),row.get('detail')) for row in result['checks']])
