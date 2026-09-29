"""The public conditional check reports actual engine results without qualification."""
import contextlib
import copy
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.cli import main
from spaghetti_extractor.components.formats import CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.bisimulation_entry_queries import entry_query_summary
from spaghetti_extractor.components.bisimulation_world_memory import allocation_byte_projection_assurance
from spaghetti_extractor.operator.conditional_check import write_component_conditional_feedback, render_component_conditional_check
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit

TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'commands': ('component check',)}


class ConditionalCheckTests(unittest.TestCase):
    def fixture(self, root, *, source_value=7, previous=None, assurance=None, capture_inputs=None, reuse_inputs=None,
                requirements=(), selected=None, fixture_options=None, entry_timeout=None):
        cbmc = shutil.which('cbmc')
        if cbmc is None or shutil.which('goto-cc') is None:
            self.skipTest('CBMC tools required')
        assurance = assurance or allocation_byte_projection_assurance()
        class Checked(Exception):
            pass
        def run(**kwargs):
            if capture_inputs is not None:
                capture_inputs.update(kwargs)
            kwargs['diagnostic_root'] = root / 'proof-diagnostics'
            kwargs['source_entry_timeout_seconds'] = entry_timeout
            result = check_bisimulation_refinement(**kwargs, runtime_assurance=assurance,
                                                   previous_query_evidence=previous, selected_obligations=selected)
            inputs = {'component_id': 'counter', 'runtime_assurance': assurance,
                      'implementation_sha256': result['bindings']['implementation_sha256']}
            if selected is not None:
                inputs['selected_obligations'] = result['selected_obligations']
            if requirements:
                inputs['boundary_requirements'] = list(requirements)
                result['boundary_requirements'] = list(requirements)
                result['receipt_sha256'] = canonical_sha256_v3({k:v for k,v in result.items() if k != 'receipt_sha256'})
            from spaghetti_extractor.components.conditional_check_result import conditional_packet_status
            (root/'conditional-engine-result.json').write_text(json.dumps({'format': CONDITIONAL_CONTEXTUAL_CHECK_V1_FORMAT,
                'status': conditional_packet_status(result), 'inputs': inputs,
                'inputs_sha256': canonical_sha256_v3(inputs), 'result': result, 'authorizing': False}))
            raise Checked()
        with patch('tests.unit.components.test_bisimulation_normal_exits.check_bisimulation_refinement', side_effect=run):
            with self.assertRaises(Checked):
                if reuse_inputs is None:
                    check_normal_exit(root, cbmc=Path(cbmc), source_value=source_value, **(fixture_options or {}))
                else:
                    run(**reuse_inputs)
        return write_component_conditional_feedback(target_id='fixture', component_id='counter',
                                                    packet_path=root/'conditional-engine-result.json')

    def test_conditional_engine_reuses_repairs_and_reparses_counterexamples(self):
        from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
        from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, changed, repaired, repeated, selection = (root/name for name in ('first', 'changed', 'repaired', 'repeated', 'selection'))
            for path in (first, changed, repaired, repeated, selection):
                path.mkdir()
            first_inputs, changed_inputs = {}, {}
            self.assertEqual(self.fixture(first, capture_inputs=first_inputs)['status'], 'complete')
            self.assertTrue(previous_proof_queries(first, runtime_assurance=allocation_byte_projection_assurance()))
            with self.assertRaisesRegex(ValueError, 'requires explicit runtime contracts'):
                previous_proof_queries(first)
            # Even identical signatures and inputs cannot import another trust selection.
            self.assertEqual(previous_proof_queries(first, runtime_assurance=world_reference_assurance()), {})
            self.assertEqual(self.fixture(changed, source_value=8, previous=first, capture_inputs=changed_inputs)['status'], 'violated')
            with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process',
                       side_effect=AssertionError('identical queries must use retained process output')):
                self.assertEqual(self.fixture(repaired, previous=first, reuse_inputs=first_inputs)['status'], 'complete')
                self.assertEqual(self.fixture(repeated, previous=changed, reuse_inputs=changed_inputs)['status'], 'violated')
            self.assertEqual(self.fixture(selection, previous=first, assurance=world_reference_assurance(), reuse_inputs=first_inputs)['status'], 'complete')
            for path in (repaired, repeated):
                reuse = json.loads(next((path/'proof-diagnostics').glob('*/query-evidence/reuse.json')).read_text())
                self.assertEqual(reuse['executed_queries'], 0)
                self.assertGreater(reuse['reused_queries'], 0)
            reuse = json.loads(next((selection/'proof-diagnostics').glob('*/query-evidence/reuse.json')).read_text())
            self.assertEqual(reuse['reused_queries'], 0)
            self.assertGreater(reuse['executed_queries'], 0)

    def test_conditional_query_import_rejects_unbound_models_and_corrupt_outputs(self):
        from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); first = root/'first'; first.mkdir()
            inputs = {}
            self.fixture(first, capture_inputs=inputs)
            packet_path = first/'conditional-engine-result.json'
            original = json.loads(packet_path.read_text())
            packet = copy.deepcopy(original)
            packet['result']['checks'][0]['goto_model_sha256'] = 'a'*64
            packet['result']['receipt_sha256'] = canonical_sha256_v3({k:v for k,v in packet['result'].items() if k != 'receipt_sha256'})
            packet_path.write_text(json.dumps(packet))
            with self.assertRaisesRegex(ValueError, 'model binding differs'):
                previous_proof_queries(first, runtime_assurance=allocation_byte_projection_assurance())
            packet_path.write_text(json.dumps(original))
            output = next((first/'proof-diagnostics').glob('*/query-evidence/*/stdout'))
            output.write_text('corrupt retained output')
            replay = root/'replay'; replay.mkdir()
            with self.assertRaisesRegex(ValueError, 'retained bytes differ'):
                self.fixture(replay, previous=first, reuse_inputs=inputs)

    def test_coverage_timeout_preserves_property_reuse_and_legacy_files_stay_unpublished(self):
        from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries, run_cbmc_process
        from spaghetti_extractor.components.conditional_check_result import checked_conditional_packet
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, repeated, legacy, legacy_repeat = (root/name for name in ('first', 'repeated', 'legacy', 'legacy-repeat'))
            first.mkdir(); repeated.mkdir(); legacy_repeat.mkdir(); inputs = {}
            def timeout_cover(command, **options):
                if '--cover' in command:
                    raise subprocess.TimeoutExpired(command, options['timeout'])
                return run_cbmc_process(command, **options)
            with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process', side_effect=timeout_cover):
                self.assertEqual(self.fixture(first, capture_inputs=inputs)['status'], 'incomplete')
            packet = json.loads((first/'conditional-engine-result.json').read_text())
            result, _ = checked_conditional_packet(packet, 'counter')
            self.assertTrue(all(row['property_result']['status'] == 'satisfied' for row in result['checks']))
            def cover_only(command, **options):
                self.assertIn('--cover', command, 'completed properties must reuse their bound outputs')
                return run_cbmc_process(command, **options)
            with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process', side_effect=cover_only):
                self.assertEqual(self.fixture(repeated, previous=first, reuse_inputs=inputs)['status'], 'complete')
            shutil.copytree(first, legacy)
            for row in packet['result']['checks']:
                del row['property_result']
            packet['result']['receipt_sha256'] = canonical_sha256_v3(
                {key:value for key,value in packet['result'].items() if key != 'receipt_sha256'})
            (legacy/'conditional-engine-result.json').write_text(json.dumps(packet))
            admitted = previous_proof_queries(legacy, runtime_assurance=allocation_byte_projection_assurance())
            self.assertTrue(all(row['coverage_only'] for row in admitted.values()))
            with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process', wraps=run_cbmc_process) as fresh:
                self.assertEqual(self.fixture(legacy_repeat, previous=legacy, reuse_inputs=inputs)['status'], 'complete')
                self.assertTrue(any('--show-properties' in call.args[0] for call in fresh.call_args_list))

    def test_public_command_reports_satisfied_and_real_counterexample_without_authority(self):
        for value, state, code in ((7, 'complete', 0), (8, 'violated', 2)):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                payload = self.fixture(root, source_value=value)
                self.assertEqual(payload['status'], state)
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout), patch('spaghetti_extractor.commands.workflows._operator_index',
                        return_value={'components': {'units': {'counter': {'products': ['conditionalCheck']}}}}), patch(
                        'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(root/'conditional-check.json', payload)) as realize:
                    status = main(['component', 'check', 'fixture', 'counter', '--conditional', '--json'])
                self.assertEqual(status, code)
                self.assertEqual(realize.call_args.args[1], 'components.units."counter".conditionalCheck')
                result = json.loads(stdout.getvalue())
                self.assertFalse(result['activation_authorized'])
                self.assertEqual(result['assurance'], allocation_byte_projection_assurance())
                self.assertTrue(result['details']['obligations'])
                self.assertEqual(result['details']['total'], 0 if state == 'complete' else 1)
                self.assertEqual(result['details']['returned'], result['details']['total'])
                if state == 'violated':
                    self.assertEqual(result['details']['blockers'][0]['status'], 'violated')
                for filename in ('semantic-provider-qualification.json', 'implementation-choices.json', 'definition-choices.json'):
                    self.assertFalse((root/filename).exists())

    def test_stale_result_source_assurance_status_and_authority_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory);payload = self.fixture(root)
            original = json.loads((root/'conditional-engine-result.json').read_text())
            for kind in ('source', 'assurance', 'activation', 'digest', 'status', 'result_shape', 'bindings_shape'):
                packet = copy.deepcopy(original)
                if kind == 'source':
                    packet['inputs']['implementation_sha256'] = 'a'*64
                    packet['inputs_sha256'] = canonical_sha256_v3(packet['inputs'])
                elif kind == 'assurance': packet['result']['assurance'] = None
                elif kind == 'activation': packet['result']['activation_authorized'] = True
                elif kind == 'digest': packet['result']['receipt_sha256'] = 'b'*64
                elif kind == 'result_shape': packet['result'] = None
                elif kind == 'bindings_shape': packet['result']['bindings'] = []
                else: packet['result']['status'] = 'violated'
                if kind not in ('digest', 'result_shape'):
                    packet['result']['receipt_sha256'] = canonical_sha256_v3({k:v for k,v in packet['result'].items() if k != 'receipt_sha256'})
                (root/'conditional-engine-result.json').write_text(json.dumps(packet))
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    write_component_conditional_feedback(target_id='fixture', component_id='counter',
                                                         packet_path=root/'conditional-engine-result.json')
            (root/'conditional-engine-result.json').write_text(json.dumps(original))
            detail_path = root/'conditional-check-details.json'
            detail_bytes = detail_path.read_bytes()
            details = json.loads(detail_bytes)
            details['composition_facts'] = [{'fact': 'invented', 'status': 'satisfied'}]
            detail_path.write_text(json.dumps(details))
            with self.assertRaisesRegex(ValueError, 'composition facts disagree'):
                render_component_conditional_check(path=root/'conditional-check.json', payload=payload,
                    target_id='fixture', component_id='counter', as_json=True)
            detail_path.write_bytes(detail_bytes)
            (root/'conditional-engine-result.json').write_text(json.dumps(original)+' ')
            with self.assertRaisesRegex(ValueError, 'evidence is stale'):
                render_component_conditional_check(path=root/'conditional-check.json', payload=payload,
                    target_id='fixture', component_id='counter', as_json=True)

    def test_conditional_work_package_refuses_existing_activation_artifacts(self):
        import inspect
        from spaghetti_extractor.semantic_providers.portable_c_work_package import write_portable_c_work_package_provider_v2
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            existing = root/'semantic-provider-qualification.json'
            existing.write_text('existing evidence')
            options = {name: root for name, parameter in inspect.signature(write_portable_c_work_package_provider_v2).parameters.items()
                       if parameter.default is inspect.Parameter.empty}
            options.update(out=root, provider_id='fixture', proof_classification='machine_overlay',
                           runtime_assurance=allocation_byte_projection_assurance())
            with self.assertRaisesRegex(ValueError, 'conditional check output contains activation artifacts'):
                write_portable_c_work_package_provider_v2(**options)
            self.assertEqual(existing.read_text(), 'existing evidence')

    def test_conditional_and_source_checks_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(main(['component', 'check', 'fixture', 'counter', '--conditional', '--source']), 0)

    def test_pending_boundary_keeps_passing_local_queries_incomplete_and_reusable(self):
        from spaghetti_extractor.components.conditional_check_result import checked_conditional_packet
        from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            requirements = [{'code': 'incoming_text_lifetime_unqualified', 'operation_id': 'run'}]
            payload = self.fixture(root, requirements=requirements)
            self.assertEqual(payload['status'], 'incomplete')
            self.assertTrue(previous_proof_queries(root, runtime_assurance=allocation_byte_projection_assurance()))
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(render_component_conditional_check(path=root/'conditional-check.json', payload=payload,
                    target_id='fixture', component_id='counter', as_json=True), 2)
            details = json.loads(stdout.getvalue())['details']
            self.assertEqual(details['local_obligation_status'], 'satisfied')
            self.assertTrue(details['supplier_export_blocked_by_boundary'])
            self.assertEqual(details['boundary_requirements'], requirements)
            packet = json.loads((root/'conditional-engine-result.json').read_text())
            for mutation in ('outer-status', 'input-requirements', 'result-requirements'):
                changed = copy.deepcopy(packet)
                if mutation == 'outer-status':
                    changed['status'] = 'satisfied'
                elif mutation == 'input-requirements':
                    del changed['inputs']['boundary_requirements']
                    changed['inputs_sha256'] = canonical_sha256_v3(changed['inputs'])
                else:
                    del changed['result']['boundary_requirements']
                    changed['result']['receipt_sha256'] = canonical_sha256_v3(
                        {k:v for k,v in changed['result'].items() if k != 'receipt_sha256'})
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    checked_conditional_packet(changed, 'counter')

    def test_local_readiness_never_ignores_normalizer_errors(self):
        from types import SimpleNamespace as Record
        from spaghetti_extractor.semantic_providers.portable_c_inputs import pending_local_check_requirements
        authored = {'code': 'incoming_text_lifetime_unqualified'}
        bundle = Record(interface=Record(operations=['run']))
        contract = Record(status='checked', issues=[])
        binding = Record(status='incomplete', operations=['run'], blockers=[authored])
        options = dict(bundle=bundle, contract=contract, binding=binding,
                       binding_model=Record(blockers=[authored]), runtime_assurance=allocation_byte_projection_assurance())
        self.assertEqual(pending_local_check_requirements(**options), [authored])
        with self.assertRaisesRegex(ValueError, 'not statically complete'):
            pending_local_check_requirements(**{**options, 'runtime_assurance': None})
        for mutation in ('authority-missing', 'operation-missing', 'contract-error'):
            changed = copy.deepcopy(options)
            if mutation == 'authority-missing':
                changed['binding'].blockers.append({'code': 'component_binding_services_disagree'})
            elif mutation == 'operation-missing':
                changed['binding'].operations = []
            else:
                changed['contract'].status = 'incomplete'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'not statically complete'):
                pending_local_check_requirements(**changed)

    def test_focus_preserves_models_defers_coverage_and_reuses_only_executed_regions(self):
        from spaghetti_extractor.components.conditional_check_result import checked_conditional_packet
        from spaghetti_extractor.components.bisimulation_query_evidence import previous_proof_queries
        from tests.unit.components.test_bisimulation_reference_authority import authority_payload
        selected = [{'operation_id': 'run', 'obligation_id': 'sync:cut'}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            whole, focused = root/'whole', root/'focused'
            whole.mkdir(); focused.mkdir(); inputs = {}
            self.assertEqual(self.fixture(whole, capture_inputs=inputs, fixture_options={
                'reference_view': True, 'reference_authority': authority_payload()})['status'], 'complete')
            from spaghetti_extractor.components.bisimulation_entry_queries import run_entry_queries
            with patch('spaghetti_extractor.components.bisimulation_entry_queries.run_entry_queries',
                       wraps=run_entry_queries) as entry_queries:
                self.assertEqual(self.fixture(focused, previous=whole, reuse_inputs=inputs,
                    selected=selected, entry_timeout=47)['status'], 'incomplete')
                self.assertEqual(entry_queries.call_args.kwargs['timeout_seconds'], 47)
            packet = json.loads((focused/'conditional-engine-result.json').read_text())
            result, _ = checked_conditional_packet(packet, 'counter')
            full = json.loads((whole/'conditional-engine-result.json').read_text())['result']
            self.assertEqual(len(result['checks']), 2)
            self.assertEqual(result['checks'][0]['code'], 'conditional_region_deferred')
            self.assertIsNone(result['checks'][0]['goto_model_sha256'])
            self.assertFalse((focused/'proof-diagnostics/operation-0000-obligation-0000/query-timings.jsonl').exists())
            self.assertEqual(result['checks'][1]['status'], 'satisfied')
            entry = result['checks'][1]['source_entry_model']
            self.assertEqual(entry['status'], 'compiled', entry.get('detail'))
            self.assertTrue(entry['compiled_types_checked'])
            self.assertTrue(entry['source_conformance_checked'])
            self.assertTrue(entry['entry_obligations_checked'])
            self.assertFalse(entry['authorizing'])
            self.assertEqual(entry['entry_check']['status'], 'satisfied')
            self.assertEqual(entry['entry_check']['executed_queries'], 0)
            self.assertGreater(entry['entry_check']['reused_queries'], 0)
            prefix = entry['prefix_correspondence']
            self.assertEqual(prefix['status'], 'matched', prefix.get('detail'))
            self.assertEqual(prefix['original_goto_model_sha256'], result['checks'][1]['goto_model_sha256'])
            self.assertEqual(prefix['entry_goto_model_sha256'], entry['goto_model_sha256'])
            self.assertEqual(entry['goto_model_sha256'], full['checks'][1]['source_entry_model']['goto_model_sha256'])
            self.assertTrue((focused/'proof-diagnostics/operation-0000-obligation-0001/source-entry/model.goto').exists())
            self.assertEqual(result['checks'][1]['goto_model_sha256'], full['checks'][1]['goto_model_sha256'])
            reuse = json.loads((focused/'proof-diagnostics/operation-0000-obligation-0001/query-evidence/reuse.json').read_text())
            self.assertEqual(reuse['executed_queries'], 0)
            self.assertGreater(reuse['reused_queries'], 0)
            self.assertEqual(set(previous_proof_queries(focused, runtime_assurance=allocation_byte_projection_assurance())), {('run','sync:cut')})
            details = json.loads((focused/'conditional-check-details.json').read_text())
            visible_entry = {**entry, 'entry_check': entry_query_summary(entry['entry_check'])}
            self.assertEqual(details['entry_models'], [{'operation_id': 'run', 'obligation_id': 'sync:cut', **visible_entry}])
            self.assertEqual(details['selected_obligation_status'], 'satisfied')
            self.assertTrue(details['supplier_export_blocked_by_focus'])
            for mutation in ('selection', 'deferred-success', 'deferred-evidence', 'missing-coverage',
                             'entry-conformance', 'entry-theorem', 'entry-binding', 'entry-deferred',
                             'prefix-model', 'prefix-root', 'prefix-authority', 'prefix-inventory',
                             'entry-query-model', 'entry-query-safety', 'entry-query-assertion', 'entry-query-cover',
                             'entry-query-site'):
                changed = copy.deepcopy(packet)
                if mutation == 'selection':
                    del changed['inputs']['selected_obligations']
                    changed['inputs_sha256'] = canonical_sha256_v3(changed['inputs'])
                elif mutation == 'deferred-success':
                    changed['result']['checks'][0]['status'] = 'satisfied'
                elif mutation == 'deferred-evidence':
                    changed['result']['checks'][0]['goto_model_sha256'] = 'a'*64
                elif mutation == 'missing-coverage':
                    changed['result']['checks'].pop(0)
                elif mutation == 'entry-conformance':
                    changed['result']['checks'][1]['source_entry_model']['source_conformance_checked'] = False
                elif mutation == 'entry-theorem':
                    changed['result']['checks'][1]['source_entry_model']['status'] = 'satisfied'
                elif mutation == 'entry-binding':
                    changed['result']['checks'][1]['source_entry_model']['preparation']['binding_sha256'] = 'f'*64
                elif mutation == 'entry-deferred':
                    changed['result']['checks'][0]['source_entry_model'] = copy.deepcopy(entry)
                elif mutation.startswith('prefix-'):
                    altered = changed['result']['checks'][1]['source_entry_model']['prefix_correspondence']
                    if mutation == 'prefix-model':
                        altered['original_goto_model_sha256'] = 'a'*64
                    elif mutation == 'prefix-root':
                        altered['entry_function'] = 'another_root'
                    elif mutation == 'prefix-authority':
                        altered['authorizing'] = True
                    else:
                        del altered['inventory_sha256']['original_symbols']
                elif mutation.startswith('entry-query-'):
                    altered = changed['result']['checks'][1]['source_entry_model']['entry_check']
                    properties = altered['property_result']
                    if mutation == 'entry-query-model':
                        altered['goto_model_sha256'] = 'a'*64
                    elif mutation == 'entry-query-site':
                        evidence = properties['partitioned_evidence']
                        evidence['assertions'].pop()
                        properties['output_sha256'] = canonical_sha256_v3(evidence)
                    elif mutation in ('entry-query-safety', 'entry-query-assertion'):
                        evidence = properties['partitioned_evidence']
                        kind = 'language_safety' if mutation == 'entry-query-safety' else 'authored_assertion'
                        victim = next(row for row in evidence['queries'] if row['kind'] == kind)
                        evidence['queries'].remove(victim)
                        properties['output_sha256'] = canonical_sha256_v3(evidence)
                    else:
                        altered['nonvacuity']['witnessed_functions'] = []
                    altered['receipt_sha256'] = canonical_sha256_v3(
                        {k:v for k,v in altered.items() if k != 'receipt_sha256'})
                changed['result']['receipt_sha256'] = canonical_sha256_v3(
                    {k:v for k,v in changed['result'].items() if k != 'receipt_sha256'})
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    checked_conditional_packet(changed, 'counter')
            with patch('spaghetti_extractor.components.bisimulation_refinement._run_bisimulation_obligation') as run:
                for assurance in (None, allocation_byte_projection_assurance()):
                    selection = [{'operation_id':'run','obligation_id':'sync:missing'}]
                    with self.assertRaisesRegex(ValueError, 'unknown obligations'):
                        check_bisimulation_refinement(**{**inputs, 'diagnostic_root': root/'invalid'},
                            runtime_assurance=assurance, selected_obligations=selection)
                for budget, assurance in ((0, allocation_byte_projection_assurance()),
                        (-1, allocation_byte_projection_assurance()), (True, allocation_byte_projection_assurance()),
                        ('180', allocation_byte_projection_assurance()), (180, None)):
                    with self.subTest(budget=budget, assurance=assurance), self.assertRaisesRegex(ValueError, 'entry query timeout'):
                        check_bisimulation_refinement(**{**inputs, 'diagnostic_root': root/'invalid',
                            'source_entry_timeout_seconds': budget}, runtime_assurance=assurance)
                run.assert_not_called()

    def test_public_region_request_and_invalid_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            payload=self.fixture(root, selected=[{'operation_id':'run',
                'obligation_id':'entry:semantic-transfer:original-cutpoint-00001000-00001001'}])
            self.assertEqual(payload['status'], 'incomplete')
            with contextlib.redirect_stdout(io.StringIO()), patch('spaghetti_extractor.commands.workflows._operator_index',
                    return_value={'components': {'units': {'counter': {'products': ['conditionalCheck','conditionalCheckFor']}}}}), patch(
                    'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(root/'conditional-check.json',payload)) as realize:
                self.assertEqual(main(['component','check','fixture','counter','--conditional','--region',
                    'run/entry:semantic-transfer:original-cutpoint-00001000-00001001','--query-timeout','60',
                    '--entry-query-timeout','180','--json']),2)
                self.assertEqual(realize.call_args.args[1], 'components.units."counter".conditionalCheckFor')
                self.assertEqual(realize.call_args.kwargs['apply_arguments']['queryTimeoutSeconds'],60)
                self.assertEqual(realize.call_args.kwargs['apply_arguments']['entryQueryTimeoutSeconds'],180)
            with contextlib.redirect_stderr(io.StringIO()):
                for options in (['--source','--region','run/sync:cut'],['--conditional','--region','missing-slash'],
                                ['--query-timeout','60'], ['--entry-query-timeout','180']):
                    self.assertNotEqual(main(['component','check','fixture','counter',*options]),0)
                with self.assertRaises(SystemExit) as rejected:
                    main(['component','check','fixture','counter','--conditional','--entry-query-timeout','0'])
                self.assertEqual(rejected.exception.code, 2)
