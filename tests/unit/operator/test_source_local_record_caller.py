"""Local C records retain byte contents, exact aliases, liveness and writeback."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from tests.unit.components.local_record_caller_fixture import HEADER, SOURCE, prepare

TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'commands': ('component check',),
           'resources': ('tests/fixtures/hello-quoting-state/slots',)}


class SourceLocalRecordCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.contract = cls.prepare('source')
        status, cls.baseline = cls.invoke('baseline')
        if status['status'] != 'complete':
            raise AssertionError(cls.baseline['checks'])

    @classmethod
    def prepare(cls, name, **kwargs):
        root = cls.root / name; contract = prepare(root, **kwargs)
        status = write_component_source_check(target_id='fixture', component_id=contract['component_id'],
            interface_package=root/'interface', source_package=root/'source', out=root/'preparation',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
        if status['status'] != 'complete':
            raise AssertionError(status)
        return contract

    @classmethod
    def invoke(cls, name, *, source='source', contract=None, previous=None):
        root = cls.root/source; out = cls.root/name; contract = contract or cls.contract
        status = write_component_source_call_check(target_id='fixture', component_id=contract['component_id'],
            preparation=root/'preparation', exact=root/'exact', supplier={}, contract=contract,
            source_package=root/'source', interface_package=root/'interface', out=out/'feedback', workspace=out/'work',
            goto_cc=Path(shutil.which('goto-cc')), cbmc=Path(shutil.which('cbmc')), smt_solver=None,
            unwind=16, timeout_seconds=60, previous=previous)
        return status, json.loads((out/'feedback/caller-comparison/result.json').read_text())

    def test_real_local_contents_and_aliases_have_zero_work_unchanged_reuse(self):
        with patch('subprocess.run', side_effect=AssertionError('reuse invoked tools')), patch.object(
                checker, 'render_caller_boundary', side_effect=AssertionError('reuse rendered model')):
            status, result = self.invoke('unchanged', previous=self.root/'baseline/feedback')
            self.assertEqual(status['status'], 'complete', result['checks'])
            checker.validate_operation_call_result(result, self.root/'unchanged/feedback/caller-comparison')
        self.assertEqual(result['proof_files'], self.baseline['proof_files'])
        self.assertEqual(result['reuse'], {'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertEqual(result['proof_key']['bindings']['runtime_contract']['local_record_lifetime']['status'], 'unverified')

    def test_wrong_initialization_stale_writeback_and_copied_alias_reject(self):
        cases = {
            'initialization': SOURCE.replace('.value=input', '.value=input^1U'),
            'stale': SOURCE.replace(' context->services->mutate', ' uint32_t old=count.value;\n context->services->mutate')
                           .replace('return count.value;', 'return old;'),
            'alias': SOURCE.replace(' context->services->mutate',
                                   ' struct spx_opaque_quote_word_v5 copy=count;\n context->services->mutate')
                           .replace('&count,&count', '&count,&copy'),
        }
        for name, source in cases.items():
            with self.subTest(name=name):
                contract = self.prepare(name+'-source', source=source)
                status, result = self.invoke(name, source=name+'-source', contract=contract)
                self.assertEqual(status['status'], 'violated', result['checks'])

    def test_host_field_offset_can_change_without_changing_native_offset(self):
        header = HEADER.read_text().replace('uint32_t value;', 'uint32_t prefix, value;')
        self.assertNotEqual(header, HEADER.read_text())
        contract = self.prepare('layout-source', header=header)
        status, result = self.invoke('layout', source='layout-source', contract=contract,
                                     previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'complete', result['checks'])
        self.assertEqual(result['reuse']['status'], 'requires-recheck')

    def test_wrong_native_local_binding_and_incomplete_byte_relation_reject(self):
        contract = deepcopy(self.contract)
        contract['boundary']['local_records'][1]['address']['args'][1]['attributes']['value'] = 7
        status, result = self.invoke('native-alias', contract=contract)
        self.assertEqual(status['status'], 'violated', result['checks'])
        contract = deepcopy(self.contract)
        contract['boundary']['records']['types'][0]['extent'] = 8
        status, result = self.invoke('padding', contract=contract)
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('native padding needs an explicit contents relation', json.dumps(result['checks']))

    def test_local_records_cannot_export_unchecked_lifetimes(self):
        with self.assertRaisesRegex(ValueError, 'checked callable lifetime and enclosing memory transport'):
            checker.checked_caller_supplier(self.root/'baseline/feedback', [])
