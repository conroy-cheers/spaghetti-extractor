"""Selected runtime packages discharge only the allocation classes actually used."""

import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.build_model import CandidateNativeBuildError
from spaghetti_extractor.candidate.formats import SHARED_MODULE_RUNTIME_PACKAGE_FORMAT
from spaghetti_extractor.components.bisimulation_allocation_dependencies import allocation_dependencies
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.native_realization.allocation_link import check_allocation_manifest_binding, check_portable_allocation_contexts
from spaghetti_extractor.util import sha256_file, write_json
from tests.unit.components.test_bisimulation_allocation_calls import inputs as call_inputs
from tests.unit.components.test_bisimulation_allocation_namespace import inputs as class_inputs
from tests.unit.components.test_allocation_class_requirements import shifted_inventory

TESTKIT = {'fixtures': (), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def local_inputs():
    authority, requirements = class_inputs()
    _, inventory, bindings = call_inputs()
    models = {'reference_authority': authority.to_payload(), 'reference_allocation_requirements': requirements}
    overlay = {'operation_id': 'buffer', 'object_authority_selectors': {}, 'service_bindings': bindings}
    context = allocation_dependencies(models, overlay)
    return models, overlay, inventory, context


def runtime_fixture(root, *, shifted=False, native_mutation=None):
    models, overlay, inventory, context = local_inputs()
    if shifted:
        inventory = shifted_inventory(inventory)
    if native_mutation == 'effect':
        next(row for row in inventory['external_range_rules'] if row['action'] == 'add_result_range')['minimum_size'] = 1
    authority = root / 'authority.json'
    native_authority = copy.deepcopy(models['reference_authority'])
    if native_mutation == 'authority':
        native_authority['rules'][0]['extent'] = 2
        native_authority['authority_sha256'] = canonical_sha256_v3({k: v for k, v in native_authority.items() if k != 'authority_sha256'})
        inventory['object_rules'][0]['extent'] = 2
    write_json(authority, native_authority)
    write_json(root / 'native-ingress-plan.json', {'fixture': 'ingress'})
    runtime = {'format': SHARED_MODULE_RUNTIME_PACKAGE_FORMAT, 'status': 'ready', 'blockers': [], 'inputs': {
        'canonical_inputs': {'machine_object_authority': {'path': authority.name, 'sha256': sha256_file(authority),
            'authority_sha256': native_authority['authority_sha256'], 'rules': inventory['object_rules']}},
        'external_range_contracts': {'rules': inventory['external_range_rules']},
        'external_dispatch': {'authorized_instruction_rvas': sorted({row['instruction_rva'] for row in context['call_specs']})},
    }}
    if native_mutation == 'unauthorized-site':
        runtime['inputs']['external_dispatch']['authorized_instruction_rvas'] = []
    runtime_path = root / 'shared-module-runtime-package.json'
    write_json(runtime_path, runtime)
    native_object = root / 'runtime.o'
    native_object.write_bytes(b'compiled runtime fixture')
    objects = [sha256_file(native_object)]
    core = {'source_runtime_package_sha256': sha256_file(runtime_path),
            'objects': [{'object_sha256': objects[0], 'path': native_object.name}]}
    manifest = {**core, 'receipt_sha256': canonical_sha256_v3(core)}
    manifest_path = root / 'native-realization-object-manifest.json'
    write_json(manifest_path, manifest)
    artifact = canonical_sha256_v3({'runtime_package_sha256': sha256_file(runtime_path),
        'ingress_plan_sha256': sha256_file(root / 'native-ingress-plan.json'),
        'object_manifest_receipt_sha256': manifest['receipt_sha256'], 'object_sha256s': objects})
    # The enclosing build parses V2 qualifications and stages exact objects.
    # This fixture isolates the additional package/facet/selection checks.
    qualification = SimpleNamespace(provider_kind='qualified_runtime', provider_id='runtime', identity='a' * 64,
        payload={'status': 'complete', 'provider_artifact_sha256': artifact, 'facets': [
            {'name': 'runtime_qualification', 'status': 'checked', 'receipt_sha256': sha256_file(runtime_path)}]})
    selection = SimpleNamespace(payload={'status': 'complete', 'definition_selections': [
        {'provider_id': 'portable', 'qualification_sha256': 'b' * 64}],
        'obligation_selections': [{'provider_id': 'runtime', 'qualification_sha256': 'a' * 64}]})
    portable = {'provider_id': 'portable', 'qualification_sha256': 'b' * 64, 'contextual_proof_sha256': 'c' * 64,
                'overlay': overlay, 'allocation_context': context}
    return {'portable_inputs': [portable], 'object_manifest_path': manifest_path,
            'selection': selection, 'qualifications': [qualification]}, runtime, manifest


class AllocationLinkTests(unittest.TestCase):
    def test_unused_class_needs_no_runtime_inventory_but_named_decoder_does(self):
        models, overlay, _, _ = local_inputs()
        overlay['service_bindings'] = []
        self.assertIsNone(allocation_dependencies(models, overlay))
        self.assertIsNone(check_portable_allocation_contexts(portable_inputs=[], object_manifest_path=Path('/unused'),
            selection=None, qualifications=[]))
        overlay['object_authority_selectors'] = {'buffer': 'text'}
        self.assertEqual(len(allocation_dependencies(models, overlay)['requirements']), 1)
        models['reference_allocation_requirements'] = []
        with self.assertRaisesRegex(BisimulationRefinementError, 'decoder lacks'):
            allocation_dependencies(models, overlay)

    def test_missing_call_class_or_selected_site_is_not_an_unused_declaration(self):
        models, overlay, _, _ = local_inputs()
        for mutation in ('classes', 'site'):
            altered_models, altered_overlay = copy.deepcopy(models), copy.deepcopy(overlay)
            if mutation == 'classes': altered_models['reference_allocation_requirements'] = []
            else: del altered_overlay['service_bindings'][0]['events'][0]['checked_external_contract']
            with self.subTest(mutation=mutation), self.assertRaises(BisimulationRefinementError):
                allocation_dependencies(altered_models, altered_overlay)

    def test_stateful_connected_dependencies_cannot_disappear_from_local_projection(self):
        models, overlay, _, _ = local_inputs()
        overlay['service_bindings'] = []
        models['connected_components'] = [{'summary_strategy': 'paired-execution-v1'}]
        with self.assertRaisesRegex(BisimulationRefinementError, 'transitive proof premises'):
            allocation_dependencies(models, overlay)
        # The strong proof reader separately checks the scalar empty-frame
        # certificate; its strategy has no memory or lifetime effects to inherit.
        models['connected_components'][0]['summary_strategy'] = 'scalar-body-free-v1'
        self.assertIsNone(allocation_dependencies(models, overlay))

    def test_framed_strategy_without_supplier_evidence_cannot_hide_lifetime_dependencies(self):
        models, overlay, _, _ = local_inputs()
        for entry in (None, {}, {'proof_system': {'proof': {'models': {}}}}):
            models['connected_components'] = [{
                'summary_strategy': 'image-shared-framed-body-free-v1', 'entry_contract': entry}]
            with self.subTest(entry=entry), self.assertRaisesRegex(
                    BisimulationRefinementError, 'transitive proof premises'):
                allocation_dependencies(models, overlay)

    def test_exact_selected_runtime_matches_classes_after_native_selector_changes(self):
        selectors = []
        for shifted in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                arguments, _, _ = runtime_fixture(Path(temporary), shifted=shifted)
                report = check_portable_allocation_contexts(**arguments)
                self.assertIs(report['authority'], False)
                self.assertEqual(report['runtime_qualification_sha256'], 'a' * 64)
                row = report['entries'][0]['correspondence'][0]
                self.assertEqual(row['class_requirement'], arguments['portable_inputs'][0]['allocation_context']['requirements'][0])
                selectors.append((row['native_object_selector'], row['native_producer_selector'], row['native_family_selector']))
        self.assertTrue(all(left != right for left, right in zip(*selectors)))

    def test_changed_packages_objects_selection_and_facets_fail_closed(self):
        for mutation in ('package', 'manifest', 'ingress', 'runtime-facet', 'runtime-artifact', 'unselected-runtime',
                         'unselected-component', 'incomplete-selection'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                arguments, runtime, manifest = runtime_fixture(root)
                if mutation == 'package':
                    runtime['inputs']['external_range_contracts']['rules'][0]['minimum_size'] = 7
                    write_json(root / 'shared-module-runtime-package.json', runtime)
                if mutation == 'manifest':
                    manifest['objects'][0]['object_sha256'] = 'e' * 64
                    manifest['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in manifest.items() if k != 'receipt_sha256'})
                    write_json(arguments['object_manifest_path'], manifest)
                if mutation == 'ingress': write_json(root / 'native-ingress-plan.json', {'fixture': 'changed'})
                if mutation == 'runtime-facet': arguments['qualifications'][0].payload['facets'][0]['receipt_sha256'] = 'e' * 64
                if mutation == 'runtime-artifact': arguments['qualifications'][0].payload['provider_artifact_sha256'] = 'e' * 64
                if mutation == 'unselected-runtime': arguments['selection'].payload['obligation_selections'] = []
                if mutation == 'unselected-component': arguments['selection'].payload['definition_selections'] = []
                if mutation == 'incomplete-selection': arguments['selection'].payload['status'] = 'incomplete'
                with self.assertRaises(CandidateNativeBuildError):
                    check_portable_allocation_contexts(**arguments)

    def test_changed_proof_class_site_or_module_cannot_match_selected_runtime(self):
        for mutation in ('class', 'site', 'module', 'decoder'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                arguments, _, _ = runtime_fixture(Path(temporary))
                context = arguments['portable_inputs'][0]['allocation_context']
                if mutation == 'class':
                    row = context['requirements'][0]
                    row['effect']['nullable'] = False
                    row['class_sha256'] = canonical_sha256_v3({k: v for k, v in row.items() if k != 'class_sha256'})
                if mutation == 'site': context['call_specs'][0]['instruction_rva'] += 1
                if mutation == 'module':
                    authority = context['reference_authority']
                    authority['bindings']['original_pe_sha256'] = 'e' * 64
                    authority['authority_sha256'] = canonical_sha256_v3({k: v for k, v in authority.items() if k != 'authority_sha256'})
                if mutation == 'decoder': context['requirements'][0]['authority']['permissions'] = 1
                with self.assertRaises(CandidateNativeBuildError):
                    check_portable_allocation_contexts(**arguments)

    def test_newly_bound_runtime_with_different_semantics_still_fails_the_proof_premise(self):
        for mutation, diagnostic in (('effect', 'local requirement'), ('authority', 'local requirement'),
                                      ('unauthorized-site', 'not authorized')):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                arguments, _, _ = runtime_fixture(Path(temporary), native_mutation=mutation)
                with self.assertRaisesRegex(CandidateNativeBuildError, diagnostic):
                    check_portable_allocation_contexts(**arguments)

    def test_manifest_metadata_cannot_change_behind_unchanged_qualification(self):
        manifest = {'qualification_input_sha256': 'a' * 64, 'implementation_sha256': 'b' * 64,
                    'proof_classification': {'fixture': 'checked'}}
        binding = {'qualification_input': 'a' * 64, 'source_package': 'b' * 64, 'object_manifest': 'c' * 64,
                   'proof_classification': manifest['proof_classification'], 'provenance_artifact_sha256s': {'fixture:input': 'd' * 64},
                   'facet': 'object_binding', 'status': 'checked'}
        qualification = SimpleNamespace(payload={'dependencies': ['provider-provenance:fixture:input:' + 'd' * 64],
            'facets': [{'name': 'object_binding', 'status': 'checked', 'receipt_sha256': canonical_sha256_v3(binding)}]})
        check_allocation_manifest_binding(qualification=qualification, manifest=manifest, manifest_sha256='c' * 64)
        with self.assertRaisesRegex(CandidateNativeBuildError, 'manifest is not bound'):
            check_allocation_manifest_binding(qualification=qualification, manifest=manifest, manifest_sha256='e' * 64)
        del manifest['qualification_input_sha256']
        with self.assertRaisesRegex(CandidateNativeBuildError, 'omits its qualification binding'):
            check_allocation_manifest_binding(qualification=qualification, manifest=manifest, manifest_sha256='c' * 64)
