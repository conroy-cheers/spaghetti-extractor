"""Several independent checked suppliers through the existing public caller path."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.components.source import build_component_source_package
from tests.unit.operator.test_source_object_initialization import prepare
from tests.unit.components.object_initializer_caller_fixture import prepare_caller

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


class SourceObjectNetworkTests(unittest.TestCase):
    repeated = False

    @classmethod
    def supplier(cls, name, *, component, entry, edited=False, weaker=False):
        root = cls.root/name
        binding, domain = prepare(root, component=component, entry=entry, edited=edited)
        if weaker: domain['initializes'][0]['extent'] = 4
        status = write_component_source_check(target_id='fixture', component_id=component,
            interface_package=root/'interface', source_package=root/'source', out=root/'feedback',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')),
            cbmc=Path(shutil.which('cbmc')), contract_workspace=root/'contracts', contract_timeout_seconds=60,
            original_comparison={'exact_c_slice': root/'exact', 'binding_intent': binding.to_payload(),
                                 'machine_domain': domain})
        if status['status'] != 'complete': raise AssertionError(status)
        return root/'feedback'

    @classmethod
    def invoke(cls, name, *, suppliers=None, contract=None, previous=None, caller='caller'):
        caller, output = cls.root/caller, cls.root/name
        status = write_component_source_call_check(target_id='fixture', component_id='initialization-consumer',
            preparation=caller/'preparation', exact=caller/'exact', supplier=cls.suppliers if suppliers is None else suppliers,
            contract=cls.contract if contract is None else contract,
            source_package=caller/'source', interface_package=caller/'interface', out=output/'feedback',
            workspace=output/'work', goto_cc=Path(shutil.which('goto-cc')), cbmc=Path(shutil.which('cbmc')),
            smt_solver=None, unwind=16, timeout_seconds=60, previous=previous)
        return status, json.loads((output/'feedback/caller-comparison/result.json').read_text())

    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(temp.cleanup); cls.root = Path(temp.name)
        cls.suppliers = {'initialize': cls.supplier('first', component='initializer', entry=4096)}
        if not cls.repeated:
            cls.suppliers['reinitialize'] = cls.supplier('second', component='reinitializer', entry=4352)
        caller = cls.root/'caller'
        cls.contract = prepare_caller(caller, network=True, repeated=cls.repeated)
        status = write_component_source_check(target_id='fixture', component_id='initialization-consumer',
            interface_package=caller/'interface', source_package=caller/'source', out=caller/'preparation',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
        if status['status'] != 'complete': raise AssertionError(status)
        cls.status, cls.result = cls.invoke('baseline')
        if cls.status['status'] != 'complete': raise AssertionError(cls.result.get('checks'))

    def test_suppliers_are_checked_absent_and_visible_to_the_consumer(self):
        with patch('subprocess.run', side_effect=AssertionError('reader executed tools')):
            checker.validate_operation_call_result(self.result, self.root/'baseline/feedback/caller-comparison')
        bindings = self.result['proof_key']['bindings']
        self.assertEqual(set(bindings['runtime_contract']['suppliers']), set(self.suppliers))
        self.assertEqual(bindings['runtime_contract']['services'], {})
        self.assertEqual(set(self.result['dependency_contract']['suppliers']), set(self.suppliers))
        self.assertFalse({'behavioral-fn-00001000.c', 'behavioral-fn-00001100.c'} & set(bindings['original_files']))
        self.assertEqual(len(self.contract['native_calls']), 2)
        self.assertEqual(len(self.contract['source_services']), 1 if self.repeated else 2)

    def test_second_supplier_edit_reuses_the_complete_caller_without_proof_work(self):
        identity, component, entry = ('initialize', 'initializer', 4096) if self.repeated else ('reinitialize', 'reinitializer', 4352)
        edited = self.supplier('edited', component=component, entry=entry, edited=True)
        with (patch.object(checker, 'render_caller_boundary', side_effect=AssertionError('rendered caller')),
              patch('subprocess.run', side_effect=AssertionError('executed tools'))):
            status, result = self.invoke('reused', suppliers={**self.suppliers, identity: edited},
                previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'complete', result.get('checks'))
        self.assertEqual(result['reuse'], {'status': 'reused', 'model_generation': 0, 'compiler_runs': 0, 'solver_runs': 0})
        self.assertEqual(result['proof_key'], self.result['proof_key'])
        self.assertNotEqual(result['supplier_transition'], self.result['supplier_transition'])

    def test_a_weaker_first_contract_invalidates_the_read_before_the_second_call(self):
        weaker = self.supplier('weaker', component='initializer', entry=4096, weaker=True)
        status, result = self.invoke('weaker-check', suppliers={**self.suppliers, 'initialize': weaker},
            previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'violated', result.get('checks'))
        self.assertEqual(result['reuse']['status'], 'requires-recheck')
        self.assertIn('spx-caller-private-byte-initialized', json.dumps(result['checks']))

    def test_missing_swapped_and_contradictory_authority_rejects(self):
        cases = [('missing', {}, self.contract)]
        if not self.repeated:
            cases.append(('swapped', {k: self.suppliers['reinitialize' if k=='initialize' else 'initialize'] for k in self.suppliers}, self.contract))
        contract = copy.deepcopy(self.contract); contract['runtime_contracts']['initialize'] = {'status': 'unverified'}
        cases.append(('duplicate-authority', self.suppliers, contract))
        with patch('subprocess.run', side_effect=AssertionError('bad dependencies executed tools')):
            for name, suppliers, contract in cases:
                status, result = self.invoke(name, suppliers=suppliers, contract=contract)
                self.assertEqual(status['status'], 'incomplete', result)
                self.assertEqual(result['reuse']['solver_runs'], 0)


class RepeatedObjectServiceTests(SourceObjectNetworkTests):
    """Two distinct native sites share one C service and checked dependency."""
    repeated = True

    def test_each_site_requires_its_exact_target_arity_stack_and_coverage(self):
        for case in ('duplicate', 'missing', 'target', 'arity', 'stack'):
            contract = copy.deepcopy(self.contract)
            second = contract['native_calls'][1]
            if case == 'duplicate': contract['native_calls'].append(copy.deepcopy(second))
            elif case == 'missing': contract['native_calls'].pop()
            elif case == 'target': second['event']['target_rva'] += 4
            elif case == 'arity': second['arguments'].pop()
            else: second['entry_stack_delta'] -= 4
            if case == 'stack':
                status, result = self.invoke('site-'+case, contract=contract)
                self.assertEqual(status['status'], 'violated', result.get('checks'))
                self.assertIn('spx-native-call-entry-stack', json.dumps(result['checks']))
            else:
                with patch('subprocess.run', side_effect=AssertionError('bad site executed tools')):
                    status, result = self.invoke('site-'+case, contract=contract)
                self.assertEqual(status['status'], 'incomplete', result)
                self.assertEqual(result['reuse']['solver_runs'], 0)

    def test_second_call_checks_arguments_read_from_current_mutable_storage(self):
        caller = self.root/'changed-current-bytes'
        prepare_caller(caller, repeated=True)
        source = caller/'caller.c'
        source.write_text(source.read_text().replace(' uint32_t result=0U;',
            ' bytes[4] ^= 1U;\n uint32_t result=0U;'))
        shutil.rmtree(caller/'source')
        build_component_source_package(lift_unit_id='initialization-consumer', files={'caller.c': source},
            shared_inputs={}, operation_symbols={'run': 'authored_consumer'}, out_dir=caller/'source')
        status = write_component_source_check(target_id='fixture', component_id='initialization-consumer',
            interface_package=caller/'interface', source_package=caller/'source', out=caller/'preparation',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
        self.assertEqual(status['status'], 'complete', status)
        status, result = self.invoke('wrong-current-bytes', caller=caller.name)
        self.assertEqual(status['status'], 'violated', result.get('checks'))
        self.assertIn('spx-paired-call-arguments', json.dumps(result['checks']))
