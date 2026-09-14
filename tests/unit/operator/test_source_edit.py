"""Public source edits retain exact inputs and never import a baseline theorem."""

import contextlib
from copy import deepcopy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.cli import main
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_edit import write_component_source_edit
from tests.unit.cli.test_component_review import review_fixture


TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'commands': ('component check',)}
SOURCE = '''#include "portable-component-implementation.h"
void authored_run(spx_leaf_context_v5 *context) {
  uint8_t a = context != 0;
  SPX_PROOF_SYNC(entry, 1);
  BODY
  SPX_PROOF_SYNC(next, 1);
  return;
tail:
  SPX_PROOF_SYNC(tail, 1);
}
'''
ORIGINAL = 'if (!a) goto tail;'
EDIT = 'int has_byte = a != 0U; if (!has_byte) goto tail;'
BOUNDARY = {'operation_id': 'run', 'source': 'authored.c',
    'entry': {'position': 'after', 'text': '  SPX_PROOF_SYNC(entry, 1);\n'},
    'exits': {name: {'position': 'before', 'text': '  SPX_PROOF_SYNC(' + name + ', 1);\n'} for name in ['next', 'tail']}}


class SourceEditTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(v) for v in ['cc', 'goto-cc', 'goto-instrument', 'cbmc', 'bwrap']):
            self.skipTest('source-edit compiler tools unavailable')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        review_fixture(self.root)
        self.interface = self.root / 'interface'
        self.interface.mkdir()
        shutil.copyfile(self.root / 'interface.json', self.interface / 'component-interface-intent-v1.json')
        self.source('baseline', ORIGINAL)
        self.source('edited', EDIT)

    def source(self, name, body):
        file = self.root / (name + '.c')
        file.write_text(SOURCE.replace('BODY', body))
        build_component_source_package(lift_unit_id='leaf', files={'authored.c': file}, shared_inputs={},
            operation_symbols={'run': 'authored_run'}, out_dir=self.root / name)

    def check(self, *, name='check', source='edited', previous=None, boundary=None, baseline_interface=None, packet=None,
              baseline_evidence=None, baseline_obligation=None):
        timings = []
        status = write_component_source_edit(target_id='fixture', component_id='leaf',
            interface_package=self.interface, baseline_interface_package=baseline_interface or self.interface,
            source_package=self.root / source, baseline_source_package=self.root / 'baseline',
            boundary=BOUNDARY if boundary is None else boundary, workspace=self.root / (name + '-work'),
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')),
            cbmc=Path(shutil.which('cbmc')), out=self.root / name, previous=previous,
            baseline_conditional_packet=packet, timings=timings,
            baseline_conditional_evidence=baseline_evidence, baseline_obligation=baseline_obligation)
        return status, json.loads((self.root / name / 'source-edit-evidence.json').read_text()), timings

    def public(self, name='check', extra=('--json',)):
        path = self.root / name / 'source-edit-check.json'
        status = json.loads(path.read_text())
        output = io.StringIO()
        with patch('spaghetti_extractor.commands.workflows._operator_index', return_value={
                'components': {'units': {'leaf': {'products': ['sourceEditCheck']}}}}), patch(
                'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(path, status)) as realize, contextlib.redirect_stdout(output):
            code = main(['component', 'check', 'fixture', 'leaf', '--source', '--compare-baseline', *extra])
        return code, output.getvalue(), realize

    def test_public_edit_runs_real_proof_and_retains_ordinary_portability_checks(self):
        status, result, timings = self.check()
        self.assertEqual(status['status'], 'complete', result['checks'])
        self.assertEqual(result['status'], 'satisfied')
        self.assertEqual(result['query_reuse'], {'executed_queries': 1, 'reused_queries': 0})
        code, output, realize = self.public()
        self.assertEqual(code, 0, output)
        parsed = json.loads(output)
        self.assertFalse(parsed['source_edit']['baseline_proof_imported'])
        self.assertEqual(parsed['details']['baseline']['status'], 'unavailable')
        self.assertFalse(parsed['activation_authorized'])
        self.assertTrue(any(v['step'] == 'host-and-pe32-source-check' for v in timings))
        self.assertEqual(realize.call_args.args[1], 'components.units."leaf".sourceEditCheck')

    def test_violation_and_exact_repair_use_current_models(self):
        self.assertEqual(self.check(name='first')[0]['status'], 'complete')
        self.source('wrong', EDIT.replace('!has_byte', 'has_byte'))
        status, result, _ = self.check(name='wrong-check', source='wrong', previous=self.root / 'first')
        self.assertEqual(status['status'], 'violated', result['checks'])
        self.assertEqual(result['query_reuse']['executed_queries'], 1)
        self.assertEqual(self.public('wrong-check')[0], 2)
        with patch('spaghetti_extractor.components.bisimulation_query_evidence.run_cbmc_process', side_effect=AssertionError('fresh repair solver forbidden')):
            status, result, _ = self.check(name='repair', previous=self.root / 'first')
        self.assertEqual(status['status'], 'complete', result['checks'])
        self.assertEqual(result['query_reuse'], {'executed_queries': 0, 'reused_queries': 1})

    def test_existing_state_edit_is_unsupported_without_a_state_relation(self):
        self.source('edited', 'a = 0; ' + EDIT)
        status, result, _ = self.check()
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('preexisting storage', result['checks'][0]['detail'])
        self.assertEqual(self.public()[0], 2)

    def test_ambiguous_manual_anchor_is_not_guessed(self):
        boundary = deepcopy(BOUNDARY)
        boundary['entry']['text'] = '  SPX_PROOF_SYNC(missing, 1);\n'
        status, result, _ = self.check(boundary=boundary)
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('exactly once', result['checks'][0]['detail'])

    def test_contract_change_cannot_reuse_a_stable_function_signature(self):
        from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
        old = self.root / 'old-interface'
        old.mkdir()
        intent = ComponentInterfaceIntentV1.parse(json.loads((self.interface / 'component-interface-intent-v1.json').read_text()))
        other = ComponentInterfaceIntentV1.create(component_id=intent.component_id, schema=intent.schema,
            state=intent.state, services=intent.services, effects=intent.effects, operations=intent.operations,
            protocol_states=['ready', 'reserved'], initial_protocol_state='ready')
        (old / 'component-interface-intent-v1.json').write_text(json.dumps(other.to_payload()))
        status, result, _ = self.check(baseline_interface=old)
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('compatibility proof', result['checks'][0]['detail'])
        self.assertEqual(result['models'], {})

    def test_changed_context_invalidates_the_comparison(self):
        self.source('edited', EDIT)
        file = self.root / 'edited.c'
        file.write_text(file.read_text().replace('uint8_t a = context != 0;', 'uint8_t a = context == 0;'))
        build_component_source_package(lift_unit_id='leaf', files={'authored.c': file}, shared_inputs={},
            operation_symbols={'run': 'authored_run'}, out_dir=self.root / 'edited')
        status, result, _ = self.check()
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('context outside region differs', result['checks'][0]['detail'])

    def test_observable_compilation_location_is_not_changed_by_staging(self):
        self.source('edited', 'int location = __LINE__; (void)location; ' + EDIT)
        status, result, _ = self.check()
        self.assertEqual(status['status'], 'incomplete')
        self.assertIn('source-path correspondence', result['checks'][0]['detail'])

    def test_missing_conditional_baseline_authority_is_visible(self):
        packet = self.root / 'unsupported.json'
        packet.write_text(json.dumps({'authorizing': False, 'claimed_status': 'satisfied'}))
        self.check(packet=packet)
        code, output, _ = self.public()
        self.assertEqual(code, 0, output)
        self.assertEqual(json.loads(output)['details']['baseline']['status'], 'unsupported')
        self.assertFalse(json.loads(output)['details']['application_proofs_reused'])

    def test_requested_baseline_context_cannot_be_replaced_by_local_success(self):
        evidence = self.root / 'retained-baseline'
        evidence.mkdir()
        (evidence / 'conditional-engine-result.json').write_text('{}')
        status, result, _ = self.check(baseline_evidence=evidence, baseline_obligation='sync:entry')
        self.assertEqual(result['query']['status'], 'satisfied')
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual(status['status'], 'incomplete')
        self.assertNotIn('baseline_context', result)
        self.assertEqual(self.public()[0], 2)

    def test_baseline_context_cannot_claim_query_import_or_omit_models(self):
        from spaghetti_extractor.components.bisimulation_source_edit_context import POLICY, validate_baseline_edit_context
        context = {'policy': POLICY, 'status': 'matched', 'authorizing': False,
                   'baseline_queries_imported': True, 'activation_authorized': False}
        with self.assertRaisesRegex(ValueError, 'authority differs'):
            validate_baseline_edit_context(context, packet={}, packet_sha256='0' * 64, local={})
        context['baseline_queries_imported'] = False
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            validate_baseline_edit_context(context, packet={}, packet_sha256='0' * 64, local={})

    def test_rebound_baseline_feedback_is_rejected(self):
        self.check()
        path = self.root / 'check/source-edit-details.json'
        details = json.loads(path.read_text())
        details['baseline']['proof_imported'] = True
        path.write_text(json.dumps(details))
        code, output, _ = self.public()
        self.assertEqual(code, 2, output)

    def test_baseline_bridge_requires_the_full_interface_contract(self):
        # Isolate the binding bridge; the real public pilot also exercises the
        # packet validator on retained engine evidence without mocking it.
        from spaghetti_extractor.operator.source_edit import _baseline
        from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
        from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
        from spaghetti_extractor.components.refinement_v5 import _logical_projection
        packet = self.root / 'packet.json'
        intent = json.loads((self.interface / 'component-interface-intent-v1.json').read_text())
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(intent))
        interface_sha256 = bundle.interface.interface_sha256
        logical_sha256 = ProofKernelComponentInterface.parse(_logical_projection(bundle)).sha256
        source = json.loads((self.root / 'baseline/source-package.json').read_text())
        evidence = {'inputs': {'source_packages': {'original': source}, 'interface_intents': {'original': intent}}}
        baseline = {'bindings': {'implementation_sha256': source['implementation_sha256'], 'interface_sha256': logical_sha256},
                    'status': 'incomplete', 'checks': [{'operation_id': 'run', 'obligation_id': 'entry',
                        'status': 'incomplete', 'code': 'cbmc_timeout'}]}
        packet.write_text(json.dumps({'inputs': {'interface_sha256': interface_sha256}, 'status': 'incomplete'}))
        with patch('spaghetti_extractor.operator.source_edit.checked_conditional_packet', return_value=(baseline, {})):
            accepted = _baseline(packet, 'leaf', evidence)
            self.assertEqual(accepted['status'], 'available-unimported')
            self.assertEqual(accepted['baseline_packet_status'], 'incomplete')
            self.assertEqual(accepted['obligations'][0]['code'], 'cbmc_timeout')
            self.assertFalse(accepted['proof_imported'])
            # A same-source packet with changed or missing interface metadata
            # cannot become eligible because its implementation hash matches.
            for digest in [None, '0' * 64]:
                packet.write_text(json.dumps({'inputs': {'interface_sha256': digest}, 'status': 'incomplete'}))
                self.assertEqual(_baseline(packet, 'leaf', evidence)['status'], 'unsupported')
            packet.write_text(json.dumps({'inputs': {'interface_sha256': interface_sha256}, 'status': 'incomplete'}))
            baseline['bindings']['interface_sha256'] = '0' * 64
            self.assertEqual(_baseline(packet, 'leaf', evidence)['status'], 'unsupported')

    def test_modified_compiled_evidence_is_rejected(self):
        self.check()
        (self.root / 'check/source-edit-models/comparison/model.goto').write_bytes(b'corrupt')
        self.assertEqual(self.public()[0], 2)

    def test_compare_flag_cannot_be_mistaken_for_qualification(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = main(['component', 'check', 'fixture', 'leaf', '--compare-baseline'])
        self.assertEqual(result, 2)
        self.assertIn('requires --source', output.getvalue())
