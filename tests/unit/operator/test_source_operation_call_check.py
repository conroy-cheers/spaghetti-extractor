"""Real save consumer edits and reuse under an explicit conditional summary."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, write_component_interface_package_v5
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.bisimulation_cleanup_summary import project_cleanup_summary
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check, validate_component_source_call_feedback
from spaghetti_extractor.operator.source_check import write_component_source_check

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save'
TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',),
         'resources':('tests/fixtures/metapad-cleanup-save',)}


def stateful_save_definition(output):
    """Move actual persistent views into context without changing machine scope."""
    intent=ComponentInterfaceIntentV1.parse(json.loads((FIXTURE/'component-interface-intent-v1.json').read_text()))
    schema=intent.schema.to_payload()
    operation=copy.deepcopy(intent.operations[0])
    signature=next(row for row in schema['signatures'] if row['id']==operation['signature_id'])
    names={'suppress_notice','main_window','edit_window','length'}
    states=[v for v in signature['parameters'] if v['id'] in names]
    signature['parameters']=[v for v in signature['parameters'] if v['id'] not in names]
    function=next(t for t in schema['types'] if t['id']==signature['function_type_id'])
    function['parameter_type_ids']=[v['type_id'] for v in signature['parameters']]
    operation['source_values']=signature['parameters']+signature['results']
    operation['projection_entries']=[row for row in operation['projection_entries'] if row['source_id'] not in names]
    operation['lifecycle_additional_roots']={'state':states}
    changed=ComponentInterfaceIntentV1.create(component_id=intent.component_id,
        schema=BoundarySchemaV1.create(schema_id=schema['schema_id'],types=schema['types'],signatures=schema['signatures']),
        state=[{'value':v,'initial':None} for v in states],operations=[operation],
        effects=list(intent.effects),services=list(intent.services),protocol_states=['ready'],initial_protocol_state='ready')
    write_component_interface_package_v5(output,changed)
    contract=json.loads((FIXTURE/'caller-contract.json').read_text())
    for view in contract['boundary']['views']:
        if view['id'] in names:view['id']='state.'+view['id']
    for service in contract['source_services']:
        service['views']={k:'state.'+v if v in names else v for k,v in service['views'].items()}
    source=(FIXTURE/'prepare-save.c').read_text()
    start=source.index('    const spx_view_v5 *text,')
    end=source.index('  uint32_t removed =')
    source=source[:start]+'''    const spx_view_v5 *text, const spx_view_v5 *caption) {
'''+''.join(f'  const spx_view_v5 *{v["id"]}=&context->state.{v["id"]};\n' for v in states)+source[end:]
    return contract,source


class SourceOperationCallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.summary=json.loads((FIXTURE/'summary-input.json').read_text())
        cls.prepare('source',(FIXTURE/'prepare-save.c').read_text())
        status=cls.invoke('baseline')
        if status['status']!='complete':raise AssertionError(cls.result('baseline'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def prepare(cls,name,text,interface=FIXTURE,relative='prepare-save.c'):
        d=cls.root/name;d.mkdir();(d/'prepare-save.c').write_text(text)
        build_component_source_package(lift_unit_id='cleanup-save',files={relative:d/'prepare-save.c'},
            shared_inputs={},operation_symbols={'prepare':'prepare_save'},out_dir=d/'source')
        status=write_component_source_check(target_id='metapad',component_id='cleanup-save',
            interface_package=interface,source_package=d/'source',out=d/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete':raise AssertionError(status)

    @classmethod
    def invoke(cls,name,source='source',summary=None,previous=None,native_memory=None,contract=None,interface=FIXTURE):
        d=cls.root/name;d.mkdir()
        contract=copy.deepcopy(contract if contract is not None else json.loads((FIXTURE/'caller-contract.json').read_text()))
        if native_memory is not None:contract['native_memory']=native_memory
        with patch.object(checker,'checked_component_operation_summary',return_value=cls.summary if summary is None else summary):
            return write_component_source_call_check(target_id='metapad',component_id='cleanup-save',
                preparation=cls.root/source/'preparation',exact=FIXTURE/'exact',supplier=cls.root/'supplier',
                contract=contract,
                source_package=cls.root/source/'source',interface_package=interface,out=d/'feedback',workspace=d/'work',
                goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),smt_solver=None,
                previous=previous,timeout_seconds=60)

    @classmethod
    def result(cls,name):
        return json.loads((cls.root/name/'feedback/caller-comparison/result.json').read_text())

    def test_canonical_nested_source_path_is_compiled_bound_and_reused(self):
        relative='components/cleanup-save.c'
        self.prepare('nested-source',(FIXTURE/'prepare-save.c').read_text(),relative=relative)
        self.assertEqual(self.invoke('nested-check',source='nested-source')['status'],'complete')
        result=self.result('nested-check')
        self.assertIn(relative,result['proof_files'])
        self.assertEqual(self.invoke('nested-reuse',source='nested-source',previous=self.root/'nested-check/feedback')['status'],'complete')
        self.assertEqual(self.result('nested-reuse')['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})

    def test_shared_context_views_use_current_bytes_and_reuse_the_public_caller_proof(self):
        interface=self.root/'state-interface'
        contract,source=stateful_save_definition(interface)
        self.prepare('state-source',source,interface=interface)
        self.assertEqual(self.invoke('state-check',source='state-source',contract=contract,interface=interface)['status'],
                         'complete',self.result('state-check'))
        baseline=self.result('state-check')
        self.assertFalse(baseline['activation_authorized'])
        self.assertNotIn('behavioral-fn-000055b7.c',baseline['proof_files'])
        model=(self.root/'state-check/feedback/caller-comparison/proof/pair.c').read_text()
        self.assertIn('context.state.length',model)
        self.assertIn('spx-source-state-view-frame',model)
        changed=copy.deepcopy(self.summary);changed['evidence']['regional_receipts']['tail']='2'*64
        with patch('subprocess.run',side_effect=AssertionError('state reuse ran a process')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('state reuse generated a model')):
            self.assertEqual(self.invoke('state-reuse',source='state-source',contract=contract,interface=interface,
                summary=changed,previous=self.root/'state-check/feedback')['status'],'complete')
        self.assertEqual(self.result('state-reuse')['reuse'],
                         {'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        start=source.index('  uint64_t previous;');end=source.index('  if (length->write(')
        stale=(source[:start]+source[end:]).replace('  uint32_t removed =',source[start:end]+'  uint32_t removed =',1)
        cases=[('state-stale',stale,'save-adjusted-length'),
               ('state-metadata',source.replace('  return removed;',
                    '  context->state.length.base.generation++;\n  return removed;'),'spx-source-state-view-frame')]
        for name,text,diagnostic in cases:
            with self.subTest(name=name):
                self.prepare(name+'-source',text,interface=interface)
                self.assertEqual(self.invoke(name,source=name+'-source',contract=contract,interface=interface)['status'],
                                 'violated',self.result(name))
                raw=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
                self.assertIn(diagnostic,{r.get('description') for b in raw for r in b.get('result',[]) if r['status']=='FAILURE'})

    def test_real_operation_proof_and_neighbor_rebinding_have_no_callee_body(self):
        r=self.result('baseline');self.assertEqual(r['query']['status'],'satisfied')
        self.assertGreater(r['query']['properties'],1000)
        proof=self.root/'baseline/feedback/caller-comparison/proof'
        names={p.name for p in proof.iterdir() if p.suffix in {'.c','.h'}}
        self.assertNotIn('behavioral-fn-000055b7.c',names);self.assertNotIn('cleanup.c',names)
        changed=copy.deepcopy(self.summary);changed['evidence']['regional_receipts']['tail']='1'*64
        with patch('subprocess.run',side_effect=AssertionError('no compiler or solver on reuse')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('no model regeneration')),patch.object(
                checker,'render_component_c_headers_v5',side_effect=AssertionError('no header regeneration')):
            status=self.invoke('neighbor',summary=changed,previous=self.root/'baseline/feedback')
            self.assertEqual(status['status'],'complete',self.result('neighbor'))
            with patch.object(checker,'checked_component_operation_summary',return_value=changed):
                feedback=json.loads((self.root/'neighbor/feedback/compiler-checks.json').read_text())
                validate_component_source_call_feedback(self.root/'neighbor/feedback',feedback['local_contract'],'complete')
        n=self.result('neighbor')
        self.assertEqual(n['proof_key'],r['proof_key']);self.assertEqual(n['proof_files'],r['proof_files'])
        self.assertNotEqual(n['supplier_transition'],r['supplier_transition'])
        self.assertEqual(n['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertFalse(n['whole_component_complete']);self.assertFalse(n['activation_authorized'])

    def test_actual_wrong_arithmetic_fault_handling_and_view_arguments_reject(self):
        original=(FIXTURE/'prepare-save.c').read_text()
        cases=[('arithmetic','(uint32_t)previous - removed','(uint32_t)previous + removed','save-adjusted-length'),
            ('fault','  if (removed == UINT32_MAX) return UINT32_MAX;\n','','save-no-post-fault-writes'),
            ('view','text, suppress_notice, main_window, edit_window, caption);',
             'text, main_window, suppress_notice, edit_window, caption);','save-cleanup-complete-view-arguments')]
        cases.append(('temporary-write','  uint32_t removed =', '  uint64_t saved;\n  if (length->read(length->access_context,length->base,0,4,&saved)) return UINT32_MAX;\n  length->write(length->access_context,length->base,0,4,0U);\n  length->write(length->access_context,length->base,0,4,saved);\n  uint32_t removed =', 'save-no-public-writes-before-cleanup'))
        cases.append(('context','  return removed;',
            '  context->protocol_state=(spx_cleanup_save_protocol_state_v5)1;\n  return removed;',
            'save-source-context-frame'))
        cases.extend([
            ('view-generation','  return removed;',
             '  ((spx_view_v5 *)length)->base.generation++;\n  return removed;', 'spx-source-view-frame'),
            ('view-hook','  return removed;',
             '  ((spx_view_v5 *)length)->read=0;\n  return removed;', 'spx-source-view-frame'),
            ('view-backing','  uint32_t removed =',
             '  ((uint8_t *)suppress_notice->access_context)[4] ^= 1U;\n  uint32_t removed =', 'spx-source-view-storage'),
        ])
        for name,before,after,diagnostic in cases:
            with self.subTest(name=name):
                self.assertIn(before,original);self.prepare('source-'+name,original.replace(before,after))
                status=self.invoke(name,source='source-'+name,previous=self.root/'baseline/feedback')
                self.assertEqual(status['status'],'violated',self.result(name))
                query=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
                failures={row.get('description') for block in query for row in block.get('result',[])
                          if row.get('status')=='FAILURE'}
                self.assertIn(diagnostic,failures)
                self.assertIn('source',self.result(name)['reuse']['changed_bindings'])
        with patch('subprocess.run',side_effect=AssertionError('repair must reuse')):
            self.assertEqual(self.invoke('repair',previous=self.root/'baseline/feedback')['status'],'complete')

    def test_reading_length_before_mutating_dependency_rejects(self):
        original=(FIXTURE/'prepare-save.c').read_text()
        start=original.index('  uint64_t previous;')
        end=original.index('  if (length->write(')
        read=original[start:end]
        changed=original[:start]+original[end:]
        changed=changed.replace('  uint32_t removed =',read+'  uint32_t removed =',1)
        self.prepare('source-stale-length',changed)
        self.assertEqual(self.invoke('stale-length',source='source-stale-length')['status'],
                         'violated',self.result('stale-length'))
        raw=json.loads((self.root/'stale-length/feedback/caller-comparison/proof/query.stdout').read_text())
        failures={r.get('description') for b in raw for r in b.get('result',[]) if r.get('status')=='FAILURE'}
        self.assertIn('save-adjusted-length',failures)

    def test_incompatible_full_contract_stops_before_model_or_solver(self):
        changed=copy.deepcopy(self.summary);changed['contract']['normal_return']['stack_delta']=8
        changed['contract_sha256']=canonical_sha256_v3(changed['contract'])
        with patch('subprocess.run',side_effect=AssertionError('incompatible contract must fail before processes')):
            status=self.invoke('incompatible',summary=changed,previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'],'incomplete')
        self.assertIn('supplier stack transport differs',self.result('incompatible')['checks'][0]['detail'])

    def test_unused_edi_guarantee_withdrawal_reuses_the_real_save_proof(self):
        frame=self.summary['contract']['normal_return']['preserved_equalities']
        changed=project_cleanup_summary(self.summary, {'rule':'normal-frame-subset-v1',
            'preserved_equalities':[v for v in frame if v!='state.edi==initial.edi']})
        with patch('subprocess.run',side_effect=AssertionError('compatible contract view cannot execute processes')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('no model rendering')),patch.object(
                checker,'render_component_c_headers_v5',side_effect=AssertionError('no headers')):
            self.assertEqual(self.invoke('withdraw-edi',summary=changed,previous=self.root/'baseline/feedback')['status'],'complete')
        baseline=self.result('baseline');result=self.result('withdraw-edi')
        self.assertEqual(result['proof_key'],baseline['proof_key']);self.assertEqual(result['proof_files'],baseline['proof_files'])
        self.assertNotEqual(result['supplier_transition']['domain_sha256'],baseline['supplier_transition']['domain_sha256'])
        self.assertEqual(result['dependency_contract']['missing_guarantees'],[])
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        model=(self.root/'baseline/feedback/caller-comparison/proof/pair.c').read_text()
        self.assertNotIn('output->edi=input->edi',model)

    def test_tampered_compiler_input_cannot_be_imported(self):
        root=self.root/'tampered';shutil.copytree(self.root/'baseline/feedback/caller-comparison',root)
        r=json.loads((root/'result.json').read_text())
        with (root/'proof/prepare-save.c').open('a') as f:f.write('\n/* changed */\n')
        with self.assertRaisesRegex(ValueError,'proof bytes changed'):
            checker.validate_evidence(r,root)

    def test_edit_native_boundary_rejects_missing_access_and_hidden_public_write(self):
        baseline=self.result('baseline');memory=baseline['proof_key']['bindings']['native_memory']
        cases=[]
        cases.append(('missing-push',[row for row in memory if row['id']!='outgoing-1'],'spx-caller-writable-frame'))
        changed=copy.deepcopy(memory);next(row for row in changed if row['id']=='length')['read']=False
        cases.append(('missing-read',changed,'spx-caller-readable-frame'))
        changed=copy.deepcopy(memory);next(row for row in changed if row['id']=='length')['storage']='private'
        cases.append(('hidden-length-write',changed,'spx-caller-private-view-separation'))
        for name,definition,diagnostic in cases:
            with self.subTest(name=name):
                self.assertEqual(self.invoke(name,native_memory=definition)['status'],'violated',self.result(name))
                raw=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
                failures={r.get('description') for b in raw for r in b.get('result',[]) if r.get('status')=='FAILURE'}
                self.assertIn(diagnostic,failures)
        # An explicit repaired declaration with reordered rows has the same typed
        # meaning as the compatibility default and must reuse the baseline proof.
        with patch('subprocess.run',side_effect=AssertionError('equivalent boundary cannot execute processes')):
            self.assertEqual(self.invoke('boundary-repair',native_memory=list(reversed(memory)),
                previous=self.root/'baseline/feedback')['status'],'complete')
        repaired=self.result('boundary-repair')
        self.assertEqual(repaired['proof_key'],baseline['proof_key'])
        self.assertEqual(repaired['proof_files'],baseline['proof_files'])

    def test_displayed_native_boundary_is_bound_to_checked_inputs(self):
        root=self.root/'baseline/feedback'
        for field,diagnostic in [('native_memory','native access'),('native_calls','native call'),('source_services','source service')]:
            local=json.loads((root/'compiler-checks.json').read_text())['local_contract']
            expected=self.result('baseline')['proof_key']['bindings'][field]
            self.assertEqual(local['caller_comparison'][field],expected)
            local['caller_comparison'][field].pop()
            with self.assertRaisesRegex(ValueError,'displayed '+diagnostic+' definitions differ'):
                validate_component_source_call_feedback(root,local,'complete')
        for field,diagnostic in [('boundary','displayed caller boundary definition differs'),('admission','displayed caller entry admission differs')]:
            local=json.loads((root/'compiler-checks.json').read_text())['local_contract']
            local['caller_comparison'][field]={}
            with self.assertRaisesRegex(ValueError,diagnostic):validate_component_source_call_feedback(root,local,'complete')

    def test_empty_admission_and_missing_outcome_coverage_reject(self):
        from spaghetti_extractor.components.bisimulation_call_relations import expression
        from spaghetti_extractor.components.relation_ir import BOOL_SORT
        for case in ('empty-admission','missing-outcome'):
            contract=json.loads((FIXTURE/'caller-contract.json').read_text())
            false=expression('false',BOOL_SORT).to_payload()
            if case=='empty-admission':contract['boundary']['admission'].append({'id':'contradiction','expression':false})
            else:contract['boundary']['outcomes'][1]['guard']=false
            status=self.invoke(case,contract=contract)
            result=self.result(case)
            if case=='empty-admission':
                self.assertEqual(status['status'],'incomplete')
                self.assertEqual(result['reuse']['solver_runs'],1)
                self.assertIn('entry admission is empty',result['checks'][0]['detail'])
            else:
                self.assertEqual(status['status'],'violated')
                raw=json.loads((self.root/case/'feedback/caller-comparison/proof/query.stdout').read_text())
                failures={r.get('description') for b in raw for r in b.get('result',[]) if r.get('status')=='FAILURE'}
                self.assertIn('spx-boundary-outcome-partition',failures)

    def test_public_definition_cannot_omit_supplier_admission_or_hide_public_inputs(self):
        from spaghetti_extractor.components.bisimulation_call_relations import constant
        for case,diagnostic in [('missing-supplier-admission','supplier-call-entry-admission-2'),
                                ('hidden-call-inputs','supplier-call-input-private-scope'),
                                ('wrong-fixed-extent','spx-source-fixed-view-extent')]:
            contract=json.loads((FIXTURE/'caller-contract.json').read_text())
            if case=='missing-supplier-admission':
                contract['boundary']['admission']=[row for row in self.result('baseline')['proof_key']['bindings']['boundary']['admission'] if row['id']!='entry-admission-2']
                contract['boundary'].pop('supplier_admission')
            elif case=='wrong-fixed-extent':
                next(row for row in contract['boundary']['views'] if row['id']=='length')['extent']=constant(8).to_payload()
            else:
                contract['boundary']['call_private_low']=constant(0,64).to_payload()
                contract['boundary']['call_private_high']=constant(2**32,64).to_payload()
            with self.subTest(case=case):
                self.assertEqual(self.invoke(case,contract=contract)['status'],'violated',self.result(case))
                raw=json.loads((self.root/case/'feedback/caller-comparison/proof/query.stdout').read_text())
                self.assertTrue(any(row.get('status')=='FAILURE' and row.get('description')==diagnostic
                                    for block in raw for row in block.get('result',[])))

    def test_equivalent_stateless_interface_change_needs_no_profile_registration(self):
        from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
        intent=ComponentInterfaceIntentV1.parse(json.loads((FIXTURE/'component-interface-intent-v1.json').read_text()))
        operations=copy.deepcopy(list(intent.operations));operations[0]['pre_states']=operations[0]['post_states']=['idle']
        changed=ComponentInterfaceIntentV1.create(component_id=intent.component_id,schema=intent.schema,state=[],
            operations=operations,effects=[],services=list(intent.services),protocol_states=['idle'],initial_protocol_state='idle')
        interface=self.root/'changed-interface';interface.mkdir()
        (interface/'component-interface-intent-v1.json').write_text(json.dumps(changed.to_payload()))
        self.prepare('source-interface',(FIXTURE/'prepare-save.c').read_text(),interface=interface)
        self.assertEqual(self.invoke('interface-change',source='source-interface',interface=interface,
            previous=self.root/'baseline/feedback')['status'],'complete',self.result('interface-change'))
        self.assertIn('interface_intent',self.result('interface-change')['reuse']['changed_bindings'])
