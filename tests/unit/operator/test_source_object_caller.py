"""Public complete real caller, on an explicitly fixed-stack test domain.

Supplier facts are test premises. The separate retained experiment consumes
current real supplier evidence and admits the full symbolic stack domain.
"""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_caller_boundary import eq, named, constant
from spaghetti_extractor.components.bisimulation_caller_memory import entry_register
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check, validate_component_source_call_feedback
from spaghetti_extractor.operator.source_check import write_component_source_check

FIXTURE=Path(__file__).parents[2]/'fixtures/hello-quoting-state/caller'
TESTKIT={'fixtures':('compiler','cbmc'),'resources':('tests/fixtures/hello-quoting-state',)}


class SourceObjectCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name)
        cls.contract=json.loads((FIXTURE/'caller-contract.json').read_text())
        cls.contract['boundary']['admission'].append(named('test-only-fixed-stack',eq(entry_register('esp'),constant(0x100000))))
        cls.facts=json.loads((FIXTURE/'supplier-facts.json').read_text())
        required=['state.'+v+'==initial.'+v for v in cls.contract['required_frame']]
        cls.summary={'contract_sha256':'1'*64,'consumer_requirements':{'rule':cls.facts['rule'],'status':'compatible',
            'required_normal_frame':required,'available_normal_frame':required,'missing_guarantees':[],
            'provided_contract_sha256':'1'*64,'consumed_contract_sha256':canonical_sha256_v3(cls.facts)},
            'evidence':{'supplier_receipt_sha256':'2'*64,'source_certificate_sha256':'3'*64}}
        cls.prepare('baseline',(FIXTURE/'caller.c').read_text())
        result=cls.invoke('baseline')
        if result['status']!='complete':raise AssertionError(cls.result('baseline').get('checks'))

    @classmethod
    def prepare(cls,name,text):
        r=cls.root/name;r.mkdir();(r/'caller.c').write_text(text)
        build_component_source_package(lift_unit_id='quote-character',files={'caller.c':r/'caller.c'},shared_inputs={},
            operation_symbols={'run':'authored_quote_character'},out_dir=r/'source')
        status=write_component_source_check(target_id='gnu-hello',component_id='quote-character',interface_package=FIXTURE,
            source_package=r/'source',out=r/'preparation',host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete':raise AssertionError(status)

    @classmethod
    def invoke(cls,name,source='baseline',summary=None,previous=None,contract=None):
        r=cls.root/name
        with patch.object(checker,'checked_caller_supplier',return_value=(cls.facts,summary or cls.summary)):
            return write_component_source_call_check(target_id='gnu-hello',component_id='quote-character',
                preparation=cls.root/source/'preparation',exact=FIXTURE/'exact',supplier=cls.root/'supplier',
                contract=contract or cls.contract,source_package=cls.root/source/'source',interface_package=FIXTURE,
                out=r/'feedback',workspace=r/'work',goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),
                smt_solver=None,unwind=50,timeout_seconds=60,previous=previous)

    @classmethod
    def result(cls,name):
        return json.loads((cls.root/name/'feedback/caller-comparison/result.json').read_text())

    def test_public_result_replays_all_partitions_and_retains_assumptions(self):
        r=self.root/'baseline/feedback';result=self.result('baseline')
        self.assertFalse(result['activation_authorized'])
        self.assertEqual(result['runtime_compatibility'],'unverified')
        self.assertIn('partitioned_evidence',result['query'])
        with patch.object(checker,'checked_caller_supplier',return_value=(self.facts,self.summary)),\
                patch('subprocess.run',side_effect=AssertionError('validation must not run tools')):
            checker.validate_operation_call_result(result,r/'caller-comparison')
            feedback=json.loads((r/'compiler-checks.json').read_text())
            status=json.loads((r/'source-check.json').read_text())
            validate_component_source_call_feedback(r,feedback['local_contract'],status['status'])

    def test_current_memory_corruption_is_rejected(self):
        source=(FIXTURE/'caller.c').read_text().replace('  uint32_t result=', '  options[0]^=1U;\n  uint32_t result=')
        self.prepare('wrong',source)
        self.assertEqual(self.invoke('wrong',source='wrong')['status'],'violated',self.result('wrong')['checks'])

    def test_compatible_supplier_evidence_reuses_without_model_compiler_or_solver(self):
        summary=deepcopy(self.summary);summary['evidence']['supplier_receipt_sha256']='4'*64
        with patch.object(checker,'render_caller_boundary',side_effect=AssertionError('reuse regenerated a model')),\
                patch('subprocess.run',side_effect=AssertionError('reuse ran a tool')):
            self.assertEqual(self.invoke('reuse',summary=summary,previous=self.root/'baseline/feedback')['status'],'complete')
        self.assertEqual(self.result('reuse')['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})

    def test_public_word_cannot_be_silently_preserved_across_a_callee_private_write(self):
        contract=deepcopy(self.contract)
        from spaghetti_extractor.components.bisimulation_caller_memory import access, entry_offset
        contract['native_memory'].append(access('public-observable',entry_offset('esp',-84),read=True))
        self.assertEqual(self.invoke('bad-frame',contract=contract)['status'],'violated',self.result('bad-frame')['checks'])
