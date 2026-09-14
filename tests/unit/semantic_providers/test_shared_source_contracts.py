"""A provider retains only exact, selected shared-source premises."""
import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.relation_v5 import ComponentRelationIntentV1
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.components.bisimulation_readonly_evidence import checked_connected_source_contract, validate_shared_source_contracts
from spaghetti_extractor.components.bisimulation_call_entry import checked_call_entry_contract
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.semantic_providers.portable_c_shared_contracts import prepare_provider_shared_contract
from ..components import test_shared_source_contracts as source_fixture
from ..components.test_shared_service_premises import binding

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'nix/jq/strong-contextual-proof.jq',
    'tests/fixtures/hand-defined-boundaries/resource-text',
    'profiles/pe32-user32-resource-text-runtime-v1.json')}


class SharedProviderSourceContractsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(tool) for tool in ('goto-cc', 'goto-instrument', 'cbmc', 'jq')):
            raise unittest.SkipTest('CBMC tools unavailable')
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.bundle = source_fixture.small_bundle()
        cls.service = binding()
        cls.certificate = source_fixture.check_shared(cls.root,
            service_contracts=normalize_shared_service_bindings(cls.bundle, [cls.service]))
        if cls.certificate['status'] != 'satisfied':
            raise AssertionError(cls.certificate['checks'])
        cls.intent = ComponentRelationIntentV1.parse(cls.certificate['shared_contract']['relation_intent'])
        cls.jq = (Path(__file__).resolve().parents[3]/'nix/jq/strong-contextual-proof.jq').read_text()

    def certificate_readers(self, certificate):
        # Reseal adversarial copies so rejection tests the claims, not just a
        # stale outer digest. This never changes retained qualification evidence.
        certificate['receipt_sha256'] = canonical_sha256_v3({
            key: value for key, value in certificate.items() if key != 'receipt_sha256'})
        try:
            validate_shared_source_contracts(certificate)
            python = True
        except ValueError:
            python = False
        result = subprocess.run([shutil.which('jq'), '-e', self.jq+'\nspx_shared_certificate'],
            input=json.dumps(certificate), text=True, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 3, result.stderr)
        return python, result.returncode == 0

    def test_both_readers_accept_the_checked_shared_source_certificate(self):
        self.assertEqual(self.certificate_readers(copy.deepcopy(self.certificate)), (True, True))
        result = subprocess.run([shutil.which('jq'), '-e', self.jq+'\nspx_mutable_certificate'],
            input=json.dumps(self.certificate), text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_both_readers_reject_missing_alias_memory_progress_and_service_premises(self):
        for mutation in ('frame-alias', 'input-memory', 'left-alias', 'right-alias',
                         'initializer', 'foreign-alias', 'opacity', 'unwind', 'calls',
                         'callback', 'lifetime', 'service-footprint', 'service-domain'):
            certificate = copy.deepcopy(self.certificate)
            shared = certificate['shared_contract']
            if mutation in ('frame-alias', 'input-memory', 'left-alias', 'right-alias'):
                kind, index = {'frame-alias': ('frame', 2), 'input-memory': ('input_dependence', 2),
                    'left-alias': ('input_dependence', 3), 'right-alias': ('input_dependence', 4)}[mutation]
                check = next(row for row in certificate['checks'] if row.get('kind') == kind)
                check['property_ids'].remove(f'spx_shared_{kind}_get.assertion.{index}')
                check['properties'] -= 1
            elif mutation == 'initializer': certificate['interface_intent']['state'][0]['initial'] = 0
            elif mutation == 'foreign-alias':
                shared['relation_intent']['operations'][0]['requirements'][0]['expression']['args'][1]['attributes']['path']['id'] = 'foreign'
            elif mutation == 'opacity': certificate['checks'][0]['service_arities']['load_string'] = 1
            elif mutation == 'unwind': certificate['checker_options'].remove('--unwinding-assertions')
            elif mutation == 'calls': shared['maximum_calls'] = 0
            else:
                effect = shared['service_contracts'][0]['external_effect_contract']
                if mutation == 'callback': effect['callback_effect'] = 'arbitrary'
                elif mutation == 'lifetime': effect['world_effect'] = 'dynamicRanges'
                elif mutation == 'service-footprint': effect['memory_footprints'][0]['base_argument'] = 0
                else: effect['argument_domain'][0]['argument_index'] = 2
            with self.subTest(mutation=mutation):
                self.assertEqual(self.certificate_readers(certificate), (False, False))

    def inputs(self):
        return dict(artifacts=self.root/'proof', bundle=self.bundle,
            source=self.certificate['source_package'], source_profile_sha256=self.certificate['source_profile']['receipt_sha256'],
            symbols={'get': 'resource_text'}, intent=self.intent,
            service_bindings=[self.service], connected_components=[])

    def test_retained_evidence_is_bound_and_copied_without_source_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'source-contract'
            result = prepare_provider_shared_contract(**self.inputs(), output=output)
            self.assertEqual(result, self.certificate)
            inputs = self.inputs(); inputs['artifacts'] = output
            self.assertEqual(prepare_provider_shared_contract(**inputs), result)
            self.assertTrue((output/'authored.goto').is_file())
            with self.assertRaisesRegex(ValueError, 'require checked supplier models and retained source evidence'):
                checked_connected_source_contract(bound={'certificate': result}, bundle=self.bundle,
                    source=result['source_package'], source_profile_sha256=result['source_profile']['receipt_sha256'],
                    operation_symbols={'get':'resource_text'}, headers={}, readonly_artifacts=output)

    def test_foreign_source_request_service_or_dependency_is_rejected(self):
        for mutation in ('source', 'request', 'service', 'dependency', 'missing-request', 'file-binding'):
            inputs = self.inputs()
            if mutation == 'source':
                inputs['source'] = {**inputs['source'], 'implementation_sha256': 'f'*64}
            elif mutation == 'request':
                operations = copy.deepcopy(list(self.intent.operations))
                operations[0]['requirements'][0]['expression']['args'][1]['attributes']['path']['id'] = 'module'
                inputs['intent'] = ComponentRelationIntentV1.create(component_id='resource-text', operations=operations, blockers=[])
            elif mutation == 'service':
                inputs['service_bindings'] = [{**self.service, 'external_contract_identity_sha256':'f'*64}]
            elif mutation == 'dependency': inputs['connected_components'] = [{'component_id':'other'}]
            elif mutation == 'missing-request': inputs['intent'] = None
            else: inputs['expected_file_sha256'] = 'f'*64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                prepare_provider_shared_contract(**inputs)

    def test_a_valid_certificate_does_not_replace_retained_model_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)/'proof'
            shutil.copytree(self.root/'proof', artifacts)
            (artifacts/'get-frame.c').write_text('void changed(void) {}\n')
            inputs = self.inputs(); inputs['artifacts'] = artifacts
            with self.assertRaises(ValueError):
                prepare_provider_shared_contract(**inputs)

    def test_source_admission_cannot_replace_the_paired_supplier_or_call_entry(self):
        bound = {'certificate': self.certificate,
            'implementation_sha256': self.certificate['source_package']['implementation_sha256'],
            'source_profile_sha256': self.certificate['source_profile']['receipt_sha256'],
            'proof_interface_sha256': self.bundle.interface.interface_sha256}
        arguments = dict(bound=bound, bundle=self.bundle, source=self.certificate['source_package'],
            source_profile_sha256=bound['source_profile_sha256'], operation_symbols={'get': 'resource_text'},
            headers=render_component_c_headers_v5(self.bundle, {'get': 'resource_text'}),
            readonly_artifacts=self.root/'proof', qualified_models={'source_summary_contracts': bound})
        # Auxiliary source admission selects no strategy and cannot manufacture
        # a paired proof, machine frame or actual-call entry contract.
        self.assertIsNone(checked_connected_source_contract(**arguments))
        with self.assertRaisesRegex(ValueError, 'supplier proof system is incomplete'):
            checked_call_entry_contract({'source_summary_contracts': bound}, connected={})
        arguments['qualified_models'] = {'source_summary_contracts': {**bound, 'certificate': {}}}
        with self.assertRaisesRegex(ValueError, 'differs from its paired supplier'):
            checked_connected_source_contract(**arguments)
