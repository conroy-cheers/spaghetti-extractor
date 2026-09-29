"""Returned identities preserve null/aliases without granting storage or lifetime."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator.source_check import write_component_source_check
from tests.unit.components.identity_result_fixture import prepare

TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',)}


class SourceIdentityResultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)
        cls.leaf,cls.transfers=cls.make('leaf')
        status,result=cls.invoke('leaf',cls.leaf)
        if status['status']!='complete':raise AssertionError(result['checks'])
        cls.contract,_=cls.make('parent',parent=True,supplier_transfers=cls.transfers)
        status,cls.baseline=cls.invoke('parent',cls.contract)
        if status['status']!='complete':raise AssertionError(cls.baseline['checks'])

    @classmethod
    def make(cls,name,**kwargs):
        root=cls.root/name;contract,transfers=prepare(root,**kwargs)
        status=write_component_source_check(target_id='fixture',component_id=contract['component_id'],
            interface_package=root/'interface',source_package=root/'source',out=root/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete':raise AssertionError(status)
        return contract,transfers

    @classmethod
    def invoke(cls,name,contract,*,output='baseline',previous=None,supplier=None):
        root=cls.root/name;out=root/output
        status=write_component_source_call_check(target_id='fixture',component_id=contract['component_id'],
            preparation=root/'preparation',exact=root/'exact',supplier=(supplier or {'allocate':cls.root/'leaf/baseline/feedback'})
                if contract['suppliers'] else {},contract=contract,source_package=root/'source',interface_package=root/'interface',
            out=out/'feedback',workspace=out/'work',goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),
            smt_solver=None,unwind=16,timeout_seconds=60,previous=previous)
        return status,json.loads((out/'feedback/caller-comparison/result.json').read_text())

    def test_arbitrary_returns_aliases_null_publication_and_absent_body(self):
        self.assertFalse(self.baseline['activation_authorized'])
        self.assertFalse((self.root/'parent/baseline/feedback/caller-comparison/proof/behavioral-fn-00002000.c').exists())
        self.assertEqual(self.baseline['proof_key']['bindings']['runtime_contract']['result_transport'],
                         {'allocate':{'relation':'record-address'}})

    def test_compatible_supplier_edit_reuses_parent_without_tools(self):
        contract,_=self.make('edited',edited=True)
        status,result=self.invoke('edited',contract)
        self.assertEqual(status['status'],'complete',result['checks'])
        with patch('subprocess.run',side_effect=AssertionError('reuse invoked tools')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('reuse generated caller')):
            status,result=self.invoke('parent',self.contract,output='reuse',previous=self.root/'parent/baseline/feedback',
                supplier={'allocate':self.root/'edited/baseline/feedback'})
        self.assertEqual(status['status'],'complete',result['checks'])
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertEqual(result['proof_key'],self.baseline['proof_key'])
        self.assertEqual(result['proof_files'],self.baseline['proof_files'])

    def test_wrong_publication_and_identity_read_fail(self):
        for name,options in [('wrong',{'wrong':True}),('read',{'dereference':True})]:
            with self.subTest(name=name):
                contract,_=self.make(name,parent=True,supplier_transfers=self.transfers,**options)
                status,result=self.invoke(name,contract)
                self.assertEqual(status['status'],'violated',result['checks'])
                if name=='read':self.assertIn(result['query']['source']['propertyClass'],
                    {'array bounds','pointer','pointer arithmetic','pointer dereference'})

    def test_missing_or_forged_result_transport_rejects_without_tools(self):
        for name,edit in [('missing',lambda c:c['suppliers']['allocate'].pop('result_transport')),
            ('relation',lambda c:c['suppliers']['allocate'].update(result_transport={'relation':'allocated-pointer'})),
            ('storage',lambda c:c['boundary']['records']['types'][0].update(extent=1))]:
            contract=deepcopy(self.contract);edit(contract)
            with self.subTest(name=name),patch('subprocess.run',side_effect=AssertionError('invalid input invoked tools')):
                status,result=self.invoke('parent',contract,output=name)
            self.assertEqual(status['status'],'incomplete',result['checks'])
            self.assertEqual(result['reuse']['compiler_runs'],0)
