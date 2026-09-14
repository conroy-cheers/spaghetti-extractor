"""Acyclic machine/source composition with current supplier and frame evidence."""
import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_readonly_contracts import check_mutable_source_contracts
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_mutable_source_contracts
from spaghetti_extractor.components.bisimulation_mutable_machine_frame import checked_mutable_machine_frame_operations
from spaghetti_extractor.components.bisimulation_source_dependencies import validate_current_qualified_closure, validate_qualified_dependency_tree
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.source import build_component_source_package
from tests.unit.components.connected_reader_fixture import check_connected_reader
from tests.unit.components import test_bisimulation_mutable_composition as mutable_readers
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": ("nix/jq/strong-contextual-proof.jq",)}
CLOBBERS = ('cf','df','of','pf','sf','zf')


def prepare_cases(root):
    cbmc=Path(shutil.which('cbmc'))
    leaf=root/'leaf'; leaf.mkdir()
    result=check_normal_exit(leaf,cbmc=cbmc,reference_view=True,read_buffer=True,write_buffer=True,
        source_contracts=True,return_to_caller=True,reference_authority=authority_payload())
    if result['status']!='satisfied': raise AssertionError(result['issues'])
    middle={}
    result=check_connected_reader(root/'middle',leaf=leaf,cbmc=cbmc,mutable=True,source_contracts=True,
        caller_private_stack_writes=({'offset':-8,'bytes':8},),caller_machine_clobbers=CLOBBERS,
        capture_inputs=middle,timeout_seconds=120)
    if result['status']!='satisfied': raise AssertionError(result['issues'])
    result=check_connected_reader(root/'outer',leaf=root/'middle',cbmc=cbmc,mutable=True,
        caller_id='outer',caller_rva=12288,child_spec=middle,extra_connected=[middle['connected']],
        caller_private_stack_writes=({'offset':-16,'bytes':16},),caller_machine_clobbers=CLOBBERS,timeout_seconds=120)
    if result['status']!='satisfied': raise AssertionError(result['issues'])


class TransitiveMemoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(t) for t in ('cbmc','goto-cc','goto-instrument','jq')):
            raise unittest.SkipTest('CBMC and both readers are required')
        temporary=tempfile.TemporaryDirectory(); cls.addClassCleanup(temporary.cleanup)
        cls.root=Path(temporary.name)
        prepare_cases(cls.root)
        cls.load_cases()

    @classmethod
    def load_cases(cls):
        cls.cases={name:json.loads((cls.root/name/'contextual-refinement-result.json').read_text())
                   for name in ('leaf','middle','outer')}
        cls.program=(Path(__file__).resolve().parents[3]/TESTKIT['resources'][0]).read_text()

    seal=staticmethod(mutable_readers.MutableCompositionTests.seal)
    readers=mutable_readers.MutableCompositionTests.readers

    def test_three_machine_levels_pass_without_consumed_implementation_bodies(self):
        for name in ('middle','outer'):
            case=self.cases[name]
            self.assertEqual(case['proof']['status'],'satisfied')
            self.assertEqual(self.readers(copy.deepcopy(case)),(True,True))
            self.assertTrue(all(row['summary_strategy']=='image-mutable-body-free-v1'
                                for row in case['proof']['models']['connected_components']))
            root=self.root/name/'diagnostics/operation-0000-obligation-0000'
            inputs=json.loads((root/'compile-inputs.json').read_text())
            self.assertFalse(any('/source-' in row['path'] and 'connected-' in row['path'] for row in inputs['files']))
            inventory=subprocess.check_output([shutil.which('goto-instrument'),'--json-ui','--show-goto-functions',str(root/'model.goto')],text=True)
            self.assertNotIn('spx_proof_connected_impl_',inventory)

    def test_source_and_machine_dependencies_bind_the_same_supplier(self):
        proof=self.cases['middle']['proof']
        certificate=proof['models']['source_summary_contracts']['certificate']
        validate_mutable_source_contracts(certificate,artifacts=self.root/'middle/local-contract')
        self.assertEqual(certificate['summary_dependencies'][0]['certificate'],
                         self.cases['leaf']['proof']['models']['source_summary_contracts']['certificate'])
        self.assertEqual(checked_mutable_machine_frame_operations(proof,artifacts=self.root/'middle/diagnostics'),('run',))

    def test_missing_transitive_entry_or_machine_frame_rejects_both_readers(self):
        for field in ('mutable_entry_contract','exact_private_write_frame','exact_mutable_exit_clobber_frame'):
            with self.subTest(field=field):
                case=copy.deepcopy(self.cases['outer'])
                middle=next(row for row in case['proof']['models']['connected_components'] if row['component_id']=='caller')
                del middle['entry_contract']['proof_system']['proof']['shards'][0][field]
                self.assertEqual(self.readers(case),(False,False))

    def test_current_retained_closure_cannot_omit_or_replace_grandchild(self):
        rows=[{**row,'proof_system':row['entry_contract']['proof_system']}
              for row in self.cases['outer']['proof']['models']['connected_components']]
        validate_current_qualified_closure(rows)
        with self.assertRaisesRegex(ValueError,'current retained input'):
            validate_current_qualified_closure([row for row in rows if row['component_id']=='caller'])
        changed=copy.deepcopy(rows)
        next(row for row in changed if row['component_id']=='counter')['qualification_sha256']='f'*64
        with self.assertRaisesRegex(ValueError,'current retained input'):
            validate_current_qualified_closure(changed)

    def test_dependency_cycle_is_rejected_before_recursive_proof_validation(self):
        node={'component_id':'caller','receipt_sha256':'a'*64,'models':{'connected_components':[]}}
        node['models']['source_summary_contracts']={'certificate':{
            'policy':'fixed-mutable-source-contract-dependencies-v2','summary_dependencies':[]}}
        node['models']['connected_components']=[{'component_id':'caller','summary_strategy':'image-mutable-body-free-v1',
            'entry_contract':{'proof_system':{'proof':node}}}]
        with self.assertRaisesRegex(ValueError,'cyclic|cycle'):
            validate_qualified_dependency_tree(node)

    def test_valid_local_proof_for_another_supplier_does_not_rebind_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            leaf=self.cases['leaf']['proof']['models']['source_summary_contracts']['certificate']
            source=root/'leaf.c'
            source.write_bytes((self.root/'leaf/source/sources'/leaf['source_package']['files'][0]['path']).read_bytes()+b'\n')
            build_component_source_package(lift_unit_id='counter',files={'leaf.c':source},shared_inputs={},
                operation_symbols=leaf['operation_symbols'],out_dir=root/'leaf-source')
            tools={name:Path(shutil.which(name.replace('_','-'))) for name in ('goto_cc','goto_instrument','cbmc')}
            replacement=check_mutable_source_contracts(bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(leaf['interface_intent'])),
                package=root/'leaf-source',output=root/'leaf-proof',unwind=10,timeout_seconds=30,**tools)
            self.assertEqual(replacement['status'],'satisfied',replacement['checks'])
            case=copy.deepcopy(self.cases['middle'])
            bound=case['proof']['models']['source_summary_contracts']
            certificate=check_mutable_source_contracts(bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(bound['certificate']['interface_intent'])),
                package=self.root/'middle/source',output=root/'middle-proof',unwind=10,timeout_seconds=30,**tools,
                summary_dependencies=[{'symbol':'spx_component_logical_counter_run','operation_id':'run',
                    'certificate':replacement,'artifacts':root/'leaf-proof'}])
            self.assertEqual(certificate['status'],'satisfied',certificate['checks'])
            validate_mutable_source_contracts(certificate,artifacts=root/'middle-proof')
            bound['certificate']=certificate
            self.assertEqual(self.readers(case),(False,False))
