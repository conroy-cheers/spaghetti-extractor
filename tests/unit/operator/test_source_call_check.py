"""Public caller proofs consume real source preparation and functional suppliers."""

import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.components import bisimulation_call_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from tests.unit.operator.test_source_call_regions import check as prepare, FIXTURE as SOURCE
from tests.unit.operator.test_source_original_comparison import check as supplier_check, ORIGINAL

FIXTURE = Path(__file__).parents[2]/'fixtures/metapad-call-comparison'
TESTKIT = {'fixtures':('compiler','cbmc','z3'), 'commands':('component check',), 'resources':(
    'tests/fixtures/metapad-call-comparison','tests/fixtures/metapad-authored-call',
    'tests/fixtures/hand-defined-boundaries/resource-text','profiles/pe32-user32-resource-text-runtime-v1.json')}


class SourceCallCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.root=Path(cls.temporary.name)
        cls.contract=json.loads((FIXTURE/'contract.json').read_text())
        source=(ORIGINAL/'resource-text.c').read_text()
        start,end=source.index('  uint64_t module;'),source.index('  spx_view_v5 buffer =')
        loop=source[:start]+'''  uint32_t module=0U;
  for(uint32_t i=0; i<4U; ++i) {
    uint64_t byte;
    const spx_view_v5 *view=&context->state.module;
    if(view->read(view->access_context,view->base,i,1U,&byte)) return (spx_view_v5){0};
    module|=(uint32_t)byte << (8U*i);
  }
'''+source[end:]
        for name,body in [('supplier',source),('edited-supplier',loop)]:
            status,_,_=supplier_check(cls.root/name,body)
            if status['status']!='complete':raise AssertionError(status)
        for name,value in [('source',31),('wrong-source',30)]:
            root=cls.root/name;root.mkdir()
            text=(SOURCE/'cleanup.c').read_text().replace('context, 31U);',f'context, {value}U);')
            boundary=json.loads((SOURCE/'boundary.json').read_text())
            for anchor in [boundary['entry'],*boundary['exits'].values()]:anchor['text']=anchor['text'].replace('31U',f'{value}U')
            status,_,_=prepare(root,text,boundary=boundary)
            if status['status']!='complete':raise AssertionError(status)
        cls.baseline_status=cls.invoke('baseline')
        if cls.baseline_status['status']!='complete':raise AssertionError((cls.root/'baseline/work/result.json').read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def invoke(cls,name,*,source='source',supplier='supplier',previous=None,contract=None):
        root=cls.root/name;root.mkdir()
        return write_component_source_call_check(target_id='metapad',component_id='text-cleanup',
            preparation=cls.root/source/'feedback',exact=FIXTURE/'exact',supplier=cls.root/supplier/'feedback',
            contract=cls.contract if contract is None else contract,out=root/'feedback',workspace=root/'work',
            goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),smt_solver=Path(shutil.which('z3')),
            previous=previous,timeout_seconds=30)

    def result(self,name):
        return json.loads((self.root/name/'feedback/caller-comparison/result.json').read_text())

    def test_public_actual_edit_failure_and_repair_preserve_region_scope(self):
        broken=self.invoke('broken',source='wrong-source',previous=self.root/'baseline/feedback')
        self.assertEqual(broken['status'],'violated')
        self.assertIn('caller-dependency-arguments',self.result('broken')['checks'][0]['detail'])
        with patch.object(bisimulation_call_check,'render_call_model',side_effect=AssertionError('consumer generation forbidden')),patch(
                'subprocess.run',side_effect=AssertionError('consumer compiler/solver forbidden')):
            repaired=self.invoke('repair',previous=self.root/'baseline/feedback')
        self.assertEqual(repaired['status'],'complete')
        self.assertEqual(self.result('repair')['reuse']['status'],'reused')
        output=io.StringIO()
        with patch('spaghetti_extractor.commands.workflows._operator_index',return_value={
                'components':{'units':{'text-cleanup':{'products':['sourceContractCheck']}}}}),patch(
                'spaghetti_extractor.commands.workflows._realize_artifact',return_value=(self.root/'broken/feedback/source-check.json',broken)),contextlib.redirect_stdout(output):
            code=main(['component','check','metapad','text-cleanup','--source','--local-contracts','--json'])
        self.assertEqual(code,2)
        caller=json.loads(output.getvalue())['local_contract']['caller_comparison']
        self.assertFalse(caller['whole_component_complete'])
        self.assertFalse(caller['activation_authorized'])

    def test_changed_supplier_reuses_actual_caller_with_no_processes_or_generation(self):
        with patch.object(bisimulation_call_check,'render_call_model',side_effect=AssertionError('consumer generation forbidden')),patch(
                'subprocess.run',side_effect=AssertionError('consumer compiler/solver forbidden')):
            status=self.invoke('neighbor-edit',supplier='edited-supplier',previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'complete')
        old,new=self.result('baseline'),self.result('neighbor-edit')
        self.assertNotEqual(old['supplier_transition']['supplier_receipt_sha256'],new['supplier_transition']['supplier_receipt_sha256'])
        self.assertEqual(old['proof_key'],new['proof_key'])
        self.assertEqual(old['proof_files'],new['proof_files'])
        self.assertEqual({k:new['reuse'][k] for k in ('model_generation','compiler_runs','solver_runs')},
                         {'model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertNotIn('behavioral-fn-00001284.c',new['proof_files'])
        self.assertNotIn('authored.goto',new['proof_files'])

    def test_contract_changes_and_damaged_evidence_cannot_borrow_the_baseline(self):
        contract=copy.deepcopy(self.contract);contract['private_stack']['low']=-40
        with patch('subprocess.run',side_effect=AssertionError('invalid caller entry must not reach compiler')):
            status=self.invoke('bad-frame',contract=contract,previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('does not admit supplier private frame',self.result('bad-frame')['checks'][0]['detail'])
        previous=self.root/'damaged';shutil.copytree(self.root/'baseline/feedback',previous)
        file=previous/'caller-comparison/proof/pair.c';file.write_text(file.read_text()+'\n/* changed */\n')
        with patch('subprocess.run',side_effect=AssertionError('stale caller must not reach compiler')):
            status=self.invoke('stale-evidence',previous=previous)
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('caller proof file changed',self.result('stale-evidence')['checks'][0]['detail'])
