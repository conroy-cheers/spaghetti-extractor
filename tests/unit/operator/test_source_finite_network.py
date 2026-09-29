"""Complete caller proofs compose repeatedly without importing supplier bodies."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_call_relations import constant
from spaghetti_extractor.components.bisimulation_caller_boundary import eq, named, negate, value
from spaghetti_extractor.components.bisimulation_caller_summary import CALLER_CALL_RULE
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator import source_operation_call_check as checker
from tests.unit.components.finite_caller_fixture import leaf, parent

TESTKIT = {'fixtures': ('compiler', 'cbmc')}


class FiniteCallerNetworkTests(unittest.TestCase):
    @classmethod
    def prepare(cls, name, contract, *, source='source'):
        root = cls.root/name
        status = write_component_source_check(target_id='fixture', component_id=contract['component_id'],
            interface_package=root/'interface', source_package=root/source, out=root/'preparation',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
        if status['status'] != 'complete': raise AssertionError(status)
        cls.components[name] = (contract, source)

    @classmethod
    def invoke(cls, name, output='baseline', *, suppliers=None, contract=None, previous=None):
        root = cls.root/name
        original, source = cls.components[name]
        status = write_component_source_call_check(target_id='fixture', component_id=original['component_id'],
            preparation=root/'preparation', exact=root/'exact', supplier=suppliers or {},
            contract=contract or original, source_package=root/source, interface_package=root/'interface',
            out=root/output/'feedback', workspace=root/output/'work',
            goto_cc=Path(shutil.which('goto-cc')), cbmc=Path(shutil.which('cbmc')), smt_solver=None,
            unwind=16, timeout_seconds=90, previous=previous)
        return status, json.loads((root/output/'feedback/caller-comparison/result.json').read_text())

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.components = {}
        cls.leaf_transfers = []
        cls.prepare('leaf', leaf(cls.root/'leaf', transfers_out=cls.leaf_transfers))
        status, cls.leaf_result = cls.invoke('leaf')
        if status['status'] != 'complete': raise AssertionError(cls.leaf_result['checks'])
        cls.leaf_feedback = cls.root/'leaf/baseline/feedback'
        parent_transfers = []
        cls.prepare('parent', parent(cls.root/'parent', supplier_transfers=cls.leaf_transfers, transfers_out=parent_transfers,
            supplier_interface=cls.root/'leaf/interface/component-interface-intent-v1.json'))
        status, cls.parent_result = cls.invoke('parent', suppliers={'child': cls.leaf_feedback})
        if status['status'] != 'complete': raise AssertionError(cls.parent_result['checks'])
        cls.parent_feedback = cls.root/'parent/baseline/feedback'
        cls.prepare('outer', parent(cls.root/'outer',
            supplier_interface=cls.root/'parent/interface/component-interface-intent-v1.json',
            supplier_transfers=parent_transfers, entry=0x4000, callee=0x3000, depth=3))
        status, cls.outer_result = cls.invoke('outer', suppliers={'child': cls.parent_feedback})
        if status['status'] != 'complete': raise AssertionError(cls.outer_result['checks'])

    def test_three_levels_have_absent_bodies_and_transitive_runtime_premises(self):
        for name, result, callee in [('parent', self.parent_result, 0x2000), ('outer', self.outer_result, 0x3000)]:
            with patch('subprocess.run', side_effect=AssertionError('reader ran tools')):
                checker.validate_operation_call_result(result, self.root/name/'baseline/feedback/caller-comparison')
            bindings = result['proof_key']['bindings']
            self.assertNotIn(f'behavioral-fn-{callee:08x}.c', bindings['original_files'])
            supplier = bindings['runtime_contract']['suppliers']['child']
            self.assertEqual(supplier['rule'], CALLER_CALL_RULE)
            self.assertFalse(result['activation_authorized'])
            self.assertEqual(result['runtime_compatibility'], 'unverified')
        nested = self.outer_result['proof_key']['bindings']['runtime_contract']['suppliers']['child']['runtime_assumptions']
        leaf_facts = nested['suppliers']['child']
        self.assertEqual(leaf_facts['runtime_assumptions']['services']['cell']['status'], 'unverified')

    def test_growing_leaf_implementation_reuses_both_callers_without_proof_work(self):
        self.prepare('edited', leaf(self.root/'edited', edited=True), source='source-edited')
        status, edited = self.invoke('edited')
        self.assertEqual(status['status'], 'complete', edited['checks'])
        self.assertNotEqual(edited['proof_key'], self.leaf_result['proof_key'])
        with (patch('subprocess.run', side_effect=AssertionError('neighbor reuse ran tools')),
              patch.object(checker, 'render_caller_boundary', side_effect=AssertionError('neighbor model rebuilt'))):
            status, middle = self.invoke('parent', 'reused', suppliers={'child': self.root/'edited/baseline/feedback'},
                previous=self.parent_feedback)
            self.assertEqual(status['status'], 'complete', middle['checks'])
            status, outer = self.invoke('outer', 'reused', suppliers={'child': self.root/'parent/reused/feedback'},
                previous=self.root/'outer/baseline/feedback')
        self.assertEqual(status['status'], 'complete', outer['checks'])
        for result, baseline in [(middle, self.parent_result), (outer, self.outer_result)]:
            self.assertEqual(result['reuse'], {'status': 'reused', 'model_generation': 0, 'compiler_runs': 0, 'solver_runs': 0})
            self.assertEqual(result['proof_key'], baseline['proof_key'])
            self.assertEqual(result['proof_files'], baseline['proof_files'])

    def test_entry_precondition_is_checked_at_each_call_and_invalidates(self):
        contract = deepcopy(self.components['leaf'][0])
        contract['boundary']['admission'].append(named('nonzero-input', negate(eq(value('input'), constant(0)))))
        status, restricted = self.invoke('leaf', 'restricted', contract=contract)
        self.assertEqual(status['status'], 'complete', restricted['checks'])
        status, parent_result = self.invoke('parent', 'restricted',
            suppliers={'child': self.root/'leaf/restricted/feedback'}, previous=self.parent_feedback)
        self.assertEqual(status['status'], 'violated', parent_result['checks'])
        self.assertEqual(parent_result['reuse']['status'], 'requires-recheck')
        self.assertIn('finite-supplier-entry-nonzero-input', json.dumps(parent_result['checks']))

    def test_wrong_call_arguments_and_wrong_leaf_are_disproved(self):
        self.prepare('wrong', parent(self.root/'wrong',
            supplier_interface=self.root/'leaf/interface/component-interface-intent-v1.json',
            supplier_transfers=self.leaf_transfers, wrong=True))
        status, result = self.invoke('wrong', suppliers={'child': self.leaf_feedback})
        self.assertEqual(status['status'], 'violated', result['checks'])
        self.assertIn('spx-paired-call-arguments', json.dumps(result['checks']))
        self.prepare('wrong-leaf', leaf(self.root/'wrong-leaf', wrong=True))
        status, result = self.invoke('wrong-leaf')
        self.assertEqual(status['status'], 'violated', result['checks'])
        with patch('subprocess.run', side_effect=AssertionError('bad supplier ran tools')):
            status, result = self.invoke('parent', 'wrong-leaf', suppliers={'child': self.root/'wrong-leaf/baseline/feedback'})
        self.assertEqual(status['status'], 'incomplete')
        self.assertEqual(result['reuse']['solver_runs'], 0)

    def test_missing_wrong_sort_and_side_specific_contract_bindings_reject(self):
        from spaghetti_extractor.components.bisimulation_caller_boundary import wide, word
        for name, binding in [('missing', None), ('sort', constant(0).to_payload()),
                              ('heap', wide(word('original_memory', constant(100))).to_payload())]:
            contract = deepcopy(self.components['parent'][0])
            if binding is None: del contract['suppliers']['child']['bindings']['protected_low']
            else: contract['suppliers']['child']['bindings']['protected_low'] = binding
            with patch('subprocess.run', side_effect=AssertionError('bad binding ran tools')):
                status, result = self.invoke('parent', 'bad-'+name, suppliers={'child': self.leaf_feedback}, contract=contract)
            self.assertEqual(status['status'], 'incomplete', result['checks'])
            self.assertEqual(result['reuse']['solver_runs'], 0)

    def test_dynamic_footprint_uses_each_actual_call_argument(self):
        from spaghetti_extractor.components.bisimulation_call_relations import expression, parameter
        from spaghetti_extractor.components.bisimulation_caller_boundary import U32, U64, le, wide
        from spaghetti_extractor.components.bisimulation_caller_memory import entry_register
        contract = deepcopy(self.components['parent'][0])
        contract['suppliers']['child']['bindings']['protected_low'] = wide(expression('bit_and', U32,
            parameter('argument_0', U32), constant(255))).to_payload()
        contract['boundary']['admission'].extend([
            named('room-below-stack', le(constant(1024), entry_register('esp'))),
            named('room-above-protected', le(value('protected_high', U64), constant(2**32-4, 64)))])
        status, result = self.invoke('parent', 'dynamic', suppliers={'child': self.leaf_feedback}, contract=contract)
        self.assertEqual(status['status'], 'complete', result['checks'])
        facts = result['proof_key']['bindings']['boundary']['services'][0]['objects']
        self.assertTrue(all(row['at'] == 'call' for row in facts))
        self.assertIn('argument_0', json.dumps(facts))
        # Exporting that operation itself requires an envelope over both actual
        # arguments; treating argument_0 as its original entry would be unsound.
        with patch('subprocess.run', side_effect=AssertionError('reader ran tools')):
            with self.assertRaisesRegex(ValueError, 'checked enclosing-operation envelope'):
                checker.checked_caller_supplier(self.root/'parent/dynamic/feedback', ['ebx'])

    def test_missing_register_guarantee_rejects_before_proof(self):
        contract = deepcopy(self.components['parent'][0])
        contract['suppliers']['child']['required_frame'] = ['ecx']
        with patch('subprocess.run', side_effect=AssertionError('missing guarantee ran tools')):
            status, result = self.invoke('parent', 'missing-frame', suppliers={'child': self.leaf_feedback}, contract=contract)
        self.assertEqual(status['status'], 'incomplete', result['checks'])
        self.assertIn('ecx', json.dumps(result['checks']))
        self.assertEqual(result['reuse']['solver_runs'], 0)

    def test_implicit_entry_definedness_survives_summary_export(self):
        from spaghetti_extractor.components.bisimulation_caller_boundary import U32, word
        contract = deepcopy(self.components['leaf'][0])
        contract['boundary']['values'].append({'id': 'unused_read', 'sort': U32.to_payload(),
            'expression': word('entry_memory', value('input')).to_payload()})
        status, leaf_result = self.invoke('leaf', 'partial-value', contract=contract)
        self.assertEqual(status['status'], 'complete', leaf_result['checks'])
        status, result = self.invoke('parent', 'partial-value',
            suppliers={'child': self.root/'leaf/partial-value/feedback'}, previous=self.parent_feedback)
        self.assertEqual(status['status'], 'violated', result['checks'])
        self.assertIn('finite-supplier-entry-value-defined-unused_read', json.dumps(result['checks']))

    def test_callee_stack_writes_cannot_silently_preserve_live_caller_storage(self):
        self.prepare('live-slot', parent(self.root/'live-slot',
            supplier_interface=self.root/'leaf/interface/component-interface-intent-v1.json',
            supplier_transfers=self.leaf_transfers, live_slot=True))
        status, result = self.invoke('live-slot', suppliers={'child': self.leaf_feedback})
        self.assertEqual(status['status'], 'violated', result['checks'])
        self.assertIn('finite-supplier-live-storage-live-0', json.dumps(result['checks']))
