"""Public conditional checking of actual C records and shared byte aliases."""
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
from tests.unit.components.record_caller_fixture import HEADER, SOURCE, prepare

TESTKIT = {'fixtures': ('compiler','cbmc'), 'commands': ('component check',),
           'resources': ('tests/fixtures/hello-quoting-state/slots',)}


class SourceRecordCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)
        cls.contract=cls.prepare('source')
        status,cls.baseline=cls.invoke('baseline')
        if status['status']!='complete':raise AssertionError(cls.baseline['checks'])

    @classmethod
    def prepare(cls,name,**kwargs):
        root=cls.root/name
        contract=prepare(root,**kwargs)
        status=write_component_source_check(target_id='fixture',component_id='record-consumer',
            interface_package=root/'interface',source_package=root/'source',out=root/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete':raise AssertionError(status)
        return contract

    @classmethod
    def invoke(cls,name,*,source='source',contract=None,previous=None):
        root=cls.root/source;out=cls.root/name
        status=write_component_source_call_check(target_id='fixture',component_id='record-consumer',
            preparation=root/'preparation',exact=root/'exact',supplier={},contract=contract or cls.contract,
            source_package=root/'source',interface_package=root/'interface',out=out/'feedback',workspace=out/'work',
            goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),smt_solver=None,
            unwind=16,timeout_seconds=60,previous=previous)
        return status,json.loads((out/'feedback/caller-comparison/result.json').read_text())

    def test_contents_aliases_services_and_header_are_checked_and_replayed(self):
        self.assertFalse(self.baseline['activation_authorized'])
        self.assertEqual(self.baseline['runtime_compatibility'],'unverified')
        proof=self.root/'baseline/feedback/caller-comparison/proof'
        self.assertEqual((proof/'quote-objects.h').read_text(),HEADER.read_text())
        self.assertIn('record-types.goto',self.baseline['proof_files'])
        self.assertIn('--i386-win32',json.loads((proof/'compiler-command.json').read_text())['command'])
        with patch('subprocess.run',side_effect=AssertionError('reuse invoked tools')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('reuse generated a model')):
            status,result=self.invoke('reused',previous=self.root/'baseline/feedback')
            self.assertEqual(status['status'],'complete',result['checks'])
            checker.validate_operation_call_result(result,self.root/'reused/feedback/caller-comparison')
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})

    def test_stale_reads_delayed_stores_and_changed_identity_reject(self):
        cases={
            'stale':SOURCE.replace('  uint32_t size=table->size;\n','').replace(
                '  context->services->mutate','  uint32_t size=table->size;\n  context->services->mutate'),
            'delayed':SOURCE.replace('  table->size+=input;\n','').replace(
                '  uint32_t size=table->size;','  table->size+=input;\n  uint32_t size=table->size;'),
            'identity':SOURCE.replace('  return table->buffer;','  context->state.slots=0;\n  return table->buffer;')}
        for name,source in cases.items():
            with self.subTest(name=name):
                contract=self.prepare(name+'-source',source=source)
                status,result=self.invoke(name,source=name+'-source',contract=contract)
                self.assertEqual(status['status'],'violated',result['checks'])

    def test_reordered_host_fields_keep_native_offsets_and_require_a_fresh_proof(self):
        header=HEADER.read_text().replace('    uint32_t size;\n    struct spx_opaque_quote_bytes_v5 *buffer;',
                                         '    struct spx_opaque_quote_bytes_v5 *buffer;\n    uint32_t size;')
        self.assertNotEqual(header,HEADER.read_text())
        contract=self.prepare('reordered-source',header=header)
        status,result=self.invoke('reordered',source='reordered-source',contract=contract,previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'complete',result['checks'])
        self.assertEqual(result['reuse']['status'],'requires-recheck')
        self.assertEqual(result['reuse']['model_generation'],1)
        self.assertNotEqual(result['proof_key'],self.baseline['proof_key'])

    def test_wrong_c_field_type_and_unproved_alias_relation_reject(self):
        header=HEADER.read_text().replace('    uint32_t size;','    int32_t size;')
        contract=self.prepare('signed-source',header=header)
        status,result=self.invoke('signed',source='signed-source',contract=contract)
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('record field type',json.dumps(result['checks']))
        contract=deepcopy(self.contract)
        contract['boundary']['records']['objects'][2]['address']=contract['boundary']['records']['objects'][1]['address']
        status,result=self.invoke('alias',contract=contract)
        self.assertEqual(status['status'],'violated',result['checks'])

    def test_authored_paths_cannot_replace_proof_or_standard_headers(self):
        for name in ('pair.c','record-types.c','stdint.h','include/portable-component.h','behavioral-c.h','../elsewhere.h','-include.c'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                checker._authored_files({'shared_inputs':{},'files':[{'path':'unit.c','sha256':'0'*64},{'path':name,'sha256':'1'*64}]})

    def test_header_cannot_change_checker_constants_or_observe_relocated_paths(self):
        for name,declaration,diagnostic in [
                ('shadow','#define SPX_RETURN 0','reserved checker/compiler'),
                ('location','static inline unsigned line(void){return __LINE__;}','location macro')]:
            with self.subTest(name=name):
                header=HEADER.read_text().replace('#endif',declaration+'\n#endif')
                contract=self.prepare(name+'-source',header=header)
                status,result=self.invoke(name,source=name+'-source',contract=contract)
                self.assertEqual(status['status'],'incomplete')
                self.assertIn(diagnostic,json.dumps(result['checks']))
                self.assertEqual(result['reuse']['compiler_runs'],0)

    def test_header_tampering_invalidates_the_saved_evidence(self):
        copied=self.root/'tampered';shutil.copytree(self.root/'baseline/feedback/caller-comparison',copied)
        header=copied/'proof/quote-objects.h';header.write_text(header.read_text()+'\n/* changed */\n')
        with self.assertRaisesRegex(ValueError,'caller proof bytes changed'):
            checker.validate_evidence(self.baseline,copied)

    def test_local_record_proof_does_not_export_an_unchecked_lifetime_summary(self):
        with self.assertRaisesRegex(ValueError,'checked callable lifetime and enclosing memory transport'):
            checker.checked_caller_supplier(self.root/'baseline/feedback',[])

    def test_reference_target_requires_a_checked_layout_before_compilation(self):
        contract=deepcopy(self.contract)
        contract['boundary']['records']['types']=[row for row in contract['boundary']['records']['types']
                                                  if row['id']!='quote_bytes']
        with patch('subprocess.run',side_effect=AssertionError('invalid reference invoked tools')):
            status,result=self.invoke('missing-reference-layout',contract=contract)
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('invalid record reference type',json.dumps(result['checks']))
        self.assertEqual(result['reuse']['compiler_runs'],0)
