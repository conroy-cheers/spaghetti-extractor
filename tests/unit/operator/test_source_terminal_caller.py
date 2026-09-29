"""Normal initialization and checked termination through a body-free caller."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator import source_operation_call_check as checker
from tests.unit.operator.test_source_object_initialization import prepare
from tests.unit.operator.test_source_object_terminal import check
from tests.unit.components.object_initializer_caller_fixture import prepare_caller

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


class SourceTerminalCallerTests(unittest.TestCase):
    @classmethod
    def prepare_source(cls, caller):
        result = write_component_source_check(target_id='fixture', component_id='initialization-consumer',
            interface_package=caller/'interface', source_package=caller/'source', out=caller/'preparation',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
        if result['status'] != 'complete': raise AssertionError(result)

    @classmethod
    def invoke(cls, name, *, first=None, caller=None, previous=None):
        caller = cls.root/'caller' if caller is None else caller
        output = cls.root/name
        status = write_component_source_call_check(target_id='fixture', component_id='initialization-consumer',
            preparation=caller/'preparation', exact=caller/'exact',
            supplier={'initialize': first or cls.first, 'reinitialize': cls.second}, contract=cls.contract,
            source_package=caller/'source', interface_package=caller/'interface', out=output/'feedback',
            workspace=output/'work', goto_cc=Path(shutil.which('goto-cc')), cbmc=Path(shutil.which('cbmc')),
            smt_solver=None, unwind=16, timeout_seconds=60, previous=previous)
        return status, json.loads((output/'feedback/caller-comparison/result.json').read_text())

    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory(); cls.addClassCleanup(temp.cleanup); cls.root = Path(temp.name)
        first = cls.root/'terminal-supplier'
        status = check(first)
        if status['status'] != 'complete': raise AssertionError(status)
        cls.first = first/'feedback'
        second = cls.root/'normal-supplier'
        binding, domain = prepare(second, component='reinitializer', entry=4352)
        status = write_component_source_check(target_id='fixture', component_id='reinitializer',
            interface_package=second/'interface', source_package=second/'source', out=second/'feedback',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')),
            cbmc=Path(shutil.which('cbmc')), contract_workspace=second/'contracts', contract_timeout_seconds=60,
            original_comparison={'exact_c_slice': second/'exact', 'binding_intent': binding.to_payload(),
                                 'machine_domain': domain})
        if status['status'] != 'complete': raise AssertionError(status)
        cls.second = second/'feedback'
        caller = cls.root/'caller'; cls.contract = prepare_caller(caller, network=True)
        cls.prepare_source(caller)
        cls.status, cls.result = cls.invoke('baseline')
        if cls.status['status'] != 'complete': raise AssertionError(cls.result.get('checks'))

    def test_both_outcomes_compose_without_bodies_or_hidden_premises(self):
        with patch('subprocess.run', side_effect=AssertionError('reader executed tools')):
            checker.validate_operation_call_result(self.result, self.root/'baseline/feedback/caller-comparison')
        bindings = self.result['proof_key']['bindings']
        self.assertFalse({'behavioral-fn-00001000.c', 'behavioral-fn-00001100.c'} & set(bindings['original_files']))
        supplied = bindings['runtime_contract']['suppliers']['initialize']
        self.assertEqual(supplied['terminal_services'][0]['disposition'], 'terminates')
        self.assertEqual(supplied['terminal_services'][0]['status'], 'unverified')
        self.assertEqual(supplied['initializes'][0]['extent'], 8)
        self.assertFalse(self.result['activation_authorized'])

    def test_a_compatible_terminal_supplier_edit_reuses_the_caller_without_tools(self):
        root = self.root/'edited-supplier'
        self.assertEqual(check(root, edited=True)['status'], 'complete')
        with (patch.object(checker, 'render_caller_boundary', side_effect=AssertionError('rendered caller')),
              patch('subprocess.run', side_effect=AssertionError('executed tools'))):
            status, result = self.invoke('edited-reuse', first=root/'feedback', previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'complete', result.get('checks'))
        self.assertEqual(result['reuse'], {'status': 'reused', 'model_generation': 0, 'compiler_runs': 0, 'solver_runs': 0})
        self.assertEqual(result['proof_key'], self.result['proof_key'])
        self.assertNotEqual(result['supplier_transition'], self.result['supplier_transition'])

    def test_termination_cannot_hide_a_temporarily_corrupted_caller_context(self):
        caller = self.root/'corrupt-context'; prepare_caller(caller, network=True)
        path = caller/'caller.c'; source = path.read_text()
        source = source.replace(' context->services->initialize(',
            ' context->protocol_state=99;\n context->services->initialize(')
        source = source.replace(' uint32_t result=0U;',
            ' context->protocol_state=SPX_INITIALIZATION_CONSUMER_PROTOCOL_READY;\n uint32_t result=0U;')
        path.write_text(source)
        build_component_source_package(lift_unit_id='initialization-consumer', files={'caller.c': path},
            shared_inputs={}, operation_symbols={'run': 'authored_consumer'}, out_dir=caller/'source')
        self.prepare_source(caller)
        status, result = self.invoke('bad-frame', caller=caller)
        self.assertEqual(status['status'], 'violated', result.get('checks'))
        self.assertIn('source-context', json.dumps(result['checks']))

    def test_normal_initialization_is_still_required_before_a_following_call(self):
        root = self.root/'weaker-supplier'
        self.assertEqual(check(root, initialized_extent=4)['status'], 'complete')
        status, result = self.invoke('weaker-check', first=root/'feedback', previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'violated', result.get('checks'))
        self.assertEqual(result['reuse']['status'], 'requires-recheck')
        self.assertIn('spx-caller-private-byte-initialized', json.dumps(result['checks']))
