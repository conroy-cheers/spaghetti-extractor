"""Source-summary composition without dependency bodies or private transport."""
import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_mutable_source_contracts, check_readonly_source_contracts
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_mutable_source_contracts, checked_connected_source_contract
from spaghetti_extractor.components.bisimulation_source_dependencies import validate_dependencies
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.source import build_component_source_package
from tests.unit.components.test_bisimulation_mutable_model import COPY, mutable_bundle
from tests.unit.components.test_bisimulation_readonly_model import COMPARISON, fixed_readonly_bundle
from spaghetti_extractor.components.bisimulation_readonly_evidence import validate_readonly_source_contracts

TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


def make_source(root, name, body, dependency=None, *, mutable=True, extents=(1, 1), previous=None, unwind=6):
    intent = (mutable_bundle if mutable else fixed_readonly_bundle)(extents=extents).intent
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=name, schema=intent.schema, state=intent.state, operations=intent.operations,
        effects=intent.effects, services=intent.services, protocol_states=intent.protocol_states,
        initial_protocol_state=intent.initial_protocol_state))
    root.mkdir()
    source = root/'implementation.c'
    source.write_text('#include "portable-component-implementation.h"\n'
        f'uint8_t {name}_run(spx_{name}_context_v5 *context, const spx_view_v5 *left, '
        f'const spx_view_v5 *right, uint32_t count) {{\n{body}\n}}\n')
    build_component_source_package(lift_unit_id=name, files={'implementation.c':source}, shared_inputs={},
                                   operation_symbols={'compare':name+'_run'}, out_dir=root/'source')
    rows = [] if dependency is None else [{'symbol':f"spx_component_logical_{dependency[0]}_compare",
        'operation_id':'compare','certificate':dependency[1],'artifacts':dependency[2]}]
    timings = []
    checker = check_mutable_source_contracts if mutable else check_readonly_source_contracts
    result = checker(bundle=bundle, package=root/'source', output=root/'proof',
        goto_cc=Path(shutil.which('goto-cc')), goto_instrument=Path(shutil.which('goto-instrument')),
        cbmc=Path(shutil.which('cbmc')), unwind=unwind, timeout_seconds=30, timings=timings, summary_dependencies=rows,
        previous_contract=previous)
    return result, timings


class SourceDependencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ('goto-cc','goto-instrument','cbmc')):
            raise unittest.SkipTest('CBMC tools are unavailable')
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.leaf, _ = make_source(cls.root/'leaf','leaf',COPY)
        dependency = ('leaf',cls.leaf,cls.root/'leaf/proof')
        cls.call = 'return spx_component_logical_leaf_compare(context->services->context,left,right,count);'
        cls.middle, _ = make_source(cls.root/'middle','middle',cls.call,dependency)
        cls.outer, _ = make_source(cls.root/'outer','outer',
            'return spx_component_logical_middle_compare(context->services->context,left,right,count);',
            ('middle',cls.middle,cls.root/'middle/proof'))

    def test_three_source_levels_check_without_dependency_bodies(self):
        for name, result in (('leaf',self.leaf),('middle',self.middle),('outer',self.outer)):
            with self.subTest(name=name):
                self.assertEqual(result['status'],'satisfied',result['checks'])
                self.assertIs(result['authorizing'],False)
                validate_mutable_source_contracts(result)
                validate_mutable_source_contracts(result,artifacts=self.root/name/'proof')
                if name != 'leaf':
                    for inventory in result['inventories']:
                        if inventory['kind']=='functions':
                            bodies={row['name'] for row in inventory['rows'] if row.get('isBodyAvailable')}
                            self.assertNotIn('leaf_run',bodies)
                            if name=='outer':self.assertNotIn('middle_run',bodies)

    def test_leaf_edit_leaves_middle_model_bytes_unchanged(self):
        slot=self.root/'edit_slot'
        before,_=make_source(slot,'middle',self.call,('leaf',self.leaf,self.root/'leaf/proof'))
        outer_slot=self.root/'outer_edit_slot'
        outer_call='return spx_component_logical_middle_compare(context->services->context,left,right,count);'
        outer_before,_=make_source(outer_slot,'outer',outer_call,('middle',before,slot/'proof'))
        slot.rename(self.root/'before_edit')
        outer_slot.rename(self.root/'before_outer_edit')
        changed,_=make_source(self.root/'changed','leaf',COPY.replace(
            'if (spx_view_read_u8(right,i,&byte) || spx_view_write_u8(left,i,byte)) return 0;',
            'if (spx_view_read_u8(right,i,&byte)) return 0;\n'
            '    if (spx_view_write_u8(left,i,byte)) return 0;'))
        self.assertNotEqual(changed['authored_goto_sha256'],self.leaf['authored_goto_sha256'])
        # Relocate the consumer. Retain its original compiled bytes and outputs;
        # do not compile a model with a new working directory or rewrite hashes.
        slot=self.root/'new_middle_workspace'
        outer_slot=self.root/'new_outer_workspace'
        with patch('subprocess.run',side_effect=AssertionError('consumer rebuild or solver execution')):
            result,timings=make_source(slot,'middle',self.call,('leaf',changed,self.root/'changed/proof'),
                                      previous=self.root/'before_edit/proof')
        self.assertEqual(result['status'],'satisfied',result['checks'])
        self.assertNotEqual(result['summary_dependencies'],before['summary_dependencies'])
        self.assertNotEqual(result['receipt_sha256'],before['receipt_sha256'])
        for model in ('authored.goto','compare-frame.goto','compare-input_dependence.goto'):
            self.assertEqual((self.root/'before_edit/proof'/model).read_bytes(),
                             (slot/'proof'/model).read_bytes(),model)
        with patch('subprocess.run',side_effect=AssertionError('consumer rebuild or solver execution')):
            outer_result,outer_timings=make_source(outer_slot,'outer',outer_call,('middle',result,slot/'proof'),
                                                   previous=self.root/'before_outer_edit/proof')
        self.assertEqual(outer_result['status'],'satisfied',outer_result['checks'])
        self.assertNotEqual(outer_result['receipt_sha256'],outer_before['receipt_sha256'])
        validate_mutable_source_contracts(outer_result,artifacts=outer_slot/'proof')
        for phases in (timings,outer_timings):
            reuse=[row for row in phases if row['phase']=='evidence-reuse']
            self.assertEqual(sum(row['reused_queries'] for row in reuse),2)
            self.assertEqual(sum(row['executed_queries'] for row in reuse),0)
            self.assertFalse(any(row['phase'] in {'compiler','solver'} for row in phases))

    def test_changed_consumed_extent_rebuilds_queries_and_rejects_bad_call(self):
        slot=self.root/'refine_slot'
        make_source(slot,'middle',self.call,('leaf',self.leaf,self.root/'leaf/proof'))
        slot.rename(self.root/'before_refine')
        changed,_=make_source(self.root/'refined_leaf','leaf',COPY,extents=(2,1))
        result,timings=make_source(slot,'middle',self.call,('leaf',changed,self.root/'refined_leaf/proof'),
                                  previous=self.root/'before_refine/proof')
        self.assertEqual(result['status'],'incomplete')
        solver=[row for row in timings if row['phase']=='solver']
        self.assertEqual(sum(row['reused_queries'] for row in solver),0)
        self.assertEqual(sum(row['executed_queries'] for row in solver),2)

    def test_forged_context_is_rejected_before_solver(self):
        result,timings=make_source(self.root/'forged','forged',
            self.call.replace('context->services->context','0'),('leaf',self.leaf,self.root/'leaf/proof'))
        self.assertEqual(result['status'],'incomplete')
        self.assertFalse(any(row['phase']=='solver' for row in timings))
        self.assertIn('service context',result['checks'][0]['issues'][0]['detail'])

    def test_dependency_entry_extent_is_checked(self):
        body='spx_view_v5 short_view=*left; short_view.extent=0;\n'+self.call.replace(',left,',',&short_view,')
        result,_=make_source(self.root/'short','short_view',body,('leaf',self.leaf,self.root/'leaf/proof'))
        self.assertEqual(result['status'],'incomplete')
        self.assertTrue(any(row.get('status')=='violated' and 'spx-summary-dependency-view' in row.get('detail','')
                            for row in result['checks']),result['checks'])

    def test_descriptor_resize_does_not_resize_opaque_backing_view(self):
        body='spx_view_v5 resized=*left; resized.extent=1;\n'+self.call.replace(',left,',',&resized,')
        result,_=make_source(self.root/'resized','resized',body,
            ('leaf',self.leaf,self.root/'leaf/proof'),extents=(2,1))
        self.assertEqual(result['status'],'incomplete')
        self.assertTrue(any(row.get('status')=='violated' and 'dependency-backing-view' in row.get('detail','')
                            for row in result['checks']),result['checks'])

    def test_readonly_dependency_checks_bodies_and_current_artifacts(self):
        leaf,_=make_source(self.root/'read_leaf','read_leaf',COMPARISON,mutable=False)
        result,_=make_source(self.root/'read_parent','read_parent',
            'return spx_component_logical_read_leaf_compare(context->services->context,left,right,count);',
            ('read_leaf',leaf,self.root/'read_leaf/proof'),mutable=False)
        self.assertEqual(result['status'],'satisfied',result['checks'])
        validate_readonly_source_contracts(result,artifacts=self.root/'read_parent/proof')
        for inventory in result['inventories']:
            if inventory['kind']=='functions':
                bodies={row['name'] for row in inventory['rows'] if row.get('isBodyAvailable')}
                self.assertNotIn('read_leaf_run',bodies)

    def test_missing_or_changed_dependency_bytes_reject_consumption(self):
        destination=self.root/'tampered'
        shutil.copytree(self.root/'middle/proof',destination)
        (destination/'dependency-0000/compare-input_dependence.goto').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'stale|binding'):
            validate_mutable_source_contracts(self.middle,artifacts=destination)
        changed=copy.deepcopy(self.middle)
        changed['summary_dependencies']=[]
        changed['receipt_sha256']=canonical_sha256_v3({k:v for k,v in changed.items() if k!='receipt_sha256'})
        with self.assertRaisesRegex(ValueError,'dependencies'):
            validate_mutable_source_contracts(changed)

    def test_current_input_bytes_participate_in_the_dependency_result(self):
        proof=self.root/'middle/proof'
        source=(proof/'compare-input_dependence.c').read_text()
        lines=source.splitlines()
        changed=0
        for index,line in enumerate(lines):
            if 'spx_world_right->values[' in line and '= __CPROVER_uninterpreted_readonly_byte(' in line:
                lines[index]=line.replace('= __CPROVER_', '= 1U ^ __CPROVER_')
                changed+=1
        self.assertEqual(changed,2)
        (proof/'unrelated-input.c').write_text('\n'.join(lines)+'\n')
        compile_command=next(row['command'] for row in self.middle['commands'] if row['step']=='compare-input_dependence-compile')
        compile_command=[{'compare-input_dependence.c':'unrelated-input.c',
                          'compare-input_dependence.goto':'unrelated-input.goto'}.get(arg,arg) for arg in compile_command]
        compiled=subprocess.run(compile_command,cwd=proof,capture_output=True,text=True)
        self.assertEqual(compiled.returncode,0,compiled.stderr)
        result=run_cbmc_properties(command=[shutil.which('cbmc'),'unrelated-input.goto','--function',
            'spx_mutable_input_dependence_compare',*self.middle['checker_options']],cwd=proof,timeout_seconds=30)
        self.assertEqual(result['status'],'violated',result)
        self.assertEqual(result['detail'],'spx-mutable-input_dependence:compare')

    def test_readonly_argument_cannot_supply_writable_dependency(self):
        result,_=make_source(self.root/'wrong_permissions','wrong_permissions',
            self.call.replace(',left,right,',',right,left,'),('leaf',self.leaf,self.root/'leaf/proof'))
        self.assertEqual(result['status'],'incomplete')
        self.assertTrue(any(row.get('status')=='violated' and 'dependency-backing-view' in row.get('detail','')
                            for row in result['checks']),result['checks'])

    def test_transitive_source_dependency_cycle_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'cyclic'):
            validate_dependencies([{'symbol':'spx_component_logical_middle_compare',
                'operation_id':'compare','certificate':self.middle}],component_id='leaf')

    def test_local_composition_does_not_enable_connected_activation(self):
        with self.assertRaises(ValueError):
            checked_connected_source_contract(bound={'certificate':self.middle},bundle=None,source={},
                source_profile_sha256='',operation_symbols={},headers={},readonly_artifacts=self.root/'middle/proof')
