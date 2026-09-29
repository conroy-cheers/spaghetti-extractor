"""Public caller checks retain captured targets and explicit runtime premises."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator import source_operation_call_check as checker
from tests.unit.components.object_initializer_caller_fixture import prepare_caller
from tests.unit.operator.test_source_object_initialization import prepare

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


class SourceIndirectCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        supplier = cls.root/'supplier'
        binding, domain = prepare(supplier)
        status = write_component_source_check(target_id='fixture', component_id='initializer',
            interface_package=supplier/'interface', source_package=supplier/'source', out=supplier/'feedback',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')),
            cbmc=Path(shutil.which('cbmc')), contract_workspace=supplier/'contracts', contract_timeout_seconds=60,
            original_comparison={'exact_c_slice': supplier/'exact', 'binding_intent': binding.to_payload(),
                                 'machine_domain': domain})
        if status['status'] != 'complete': raise AssertionError(status)
        cls.contracts = {}
        for kind in ('register', 'static_slot'):
            caller = cls.root/kind
            cls.contracts[kind] = prepare_caller(caller, indirect=kind)
            status = write_component_source_check(target_id='fixture', component_id='initialization-consumer',
                interface_package=caller/'interface', source_package=caller/'source', out=caller/'preparation',
                host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
            if status['status'] != 'complete': raise AssertionError(status)
            status, result = cls.invoke(kind, 'baseline')
            if status['status'] != 'complete':
                raise AssertionError([(r['code'], r.get('detail')) for r in result['checks']])

    @classmethod
    def invoke(cls, kind, name, *, contract=None, previous=None):
        caller = cls.root/kind; output = caller/name
        status = write_component_source_call_check(target_id='fixture', component_id='initialization-consumer',
            preparation=caller/'preparation', exact=caller/'exact', supplier={'initialize': cls.root/'supplier/feedback'},
            contract=cls.contracts[kind] if contract is None else contract,
            source_package=caller/'source', interface_package=caller/'interface', out=output/'feedback',
            workspace=output/'work', goto_cc=Path(shutil.which('goto-cc')), cbmc=Path(shutil.which('cbmc')),
            smt_solver=None, unwind=16, timeout_seconds=60, previous=previous)
        return status, json.loads((output/'feedback/caller-comparison/result.json').read_text())

    def test_captured_target_is_bound_with_both_bodies_absent_and_no_activation(self):
        for kind in self.contracts:
            directory = self.root/kind/'baseline/feedback/caller-comparison'
            result = json.loads((directory/'result.json').read_text())
            with patch('subprocess.run', side_effect=AssertionError('reader ran proof tools')):
                checker.validate_operation_call_result(result, directory)
            bindings = result['proof_key']['bindings']
            self.assertFalse({'behavioral-fn-00001000.c', 'behavioral-fn-00001100.c'} & set(bindings['original_files']))
            premise = bindings['runtime_contract']['services']['reinitialize']
            self.assertEqual(premise['status'], 'unverified')
            self.assertEqual(premise['captured_target_projection']['kind'], kind)
            self.assertFalse(result['activation_authorized'])
            self.assertFalse(result['whole_component_complete'])

    def test_current_receipts_reuse_without_model_or_process_work(self):
        for kind in self.contracts:
            with (patch('subprocess.run', side_effect=AssertionError('reuse ran proof tools')),
                  patch.object(checker, 'render_caller_boundary', side_effect=AssertionError('reuse rendered caller'))):
                status, result = self.invoke(kind, 'reuse', previous=self.root/kind/'baseline/feedback')
            self.assertEqual(status['status'], 'complete')
            self.assertEqual(result['reuse'], {'status': 'reused', 'model_generation': 0, 'compiler_runs': 0, 'solver_runs': 0})

    def test_missing_or_unchecked_projection_is_refused_before_proof(self):
        for case in ('missing', 'phase', 'forged', 'boundary'):
            contract = deepcopy(self.contracts['register'])
            premise = contract['runtime_contracts']['reinitialize']
            if case == 'missing': premise.pop('captured_target_projection')
            elif case == 'phase': premise['captured_target_projection']['at'] = 'exit'
            elif case == 'forged': contract['native_calls'][1]['captured_target_projection'] = premise['captured_target_projection']
            else: contract['boundary']['services'][1]['captured_target_projection'] = premise['captured_target_projection']
            with patch('subprocess.run', side_effect=AssertionError('invalid target ran tools')):
                status, result = self.invoke('register', case, contract=contract)
            self.assertEqual(status['status'], 'incomplete')
            self.assertEqual(result['reuse']['solver_runs'], 0)

    def test_changed_capture_or_missing_slot_read_permission_is_disproved(self):
        for kind in self.contracts:
            contract = deepcopy(self.contracts[kind])
            if kind == 'register':
                contract['runtime_contracts']['reinitialize']['captured_target_projection']['register'] = 'esi'
                diagnostics = {'spx-native-captured-target', 'spx-paired-code-target', 'spx-source-captured-target-nonnull'}
            else:
                contract['native_memory'] = [r for r in contract['native_memory'] if r['id'] != 'import-slot']
                diagnostics = {'spx-caller-readable-frame', 'spx-native-target-slot-readable'}
            status, result = self.invoke(kind, 'bad-capture', contract=contract,
                previous=self.root/kind/'baseline/feedback')
            self.assertEqual(status['status'], 'violated')
            self.assertEqual(result['reuse']['status'], 'requires-recheck')
            self.assertEqual(result['query']['code'], 'cbmc_counterexample')
            self.assertIn(result['query']['detail'], diagnostics)
