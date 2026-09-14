"""Conditional receipts retain component obligations without native authority."""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_refinement import check_bisimulation_refinement
from spaghetti_extractor.components.bisimulation_world_memory import allocation_byte_projection_assurance
from spaghetti_extractor.components.contextual_bisimulation import (
    build_conditional_contextual_refinement_v1, validate_conditional_contextual_refinement_v1,
    build_contextual_refinement_v2, validate_contextual_refinement_v2,
)
from spaghetti_extractor.components.formats import CONTEXTUAL_REFINEMENT_V2_FORMAT
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def reseal(value):
    value['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in value.items() if k != 'receipt_sha256'})


def fixture(root, *, capture_binding=None, assurance=None, **options):
    assurance = assurance or allocation_byte_projection_assurance()
    inputs = {}
    def build(**kwargs):
        inputs.update(kwargs)
        return build_conditional_contextual_refinement_v1(**kwargs, runtime_assurance=assurance)
    from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
    original_create = ComponentMachineBindingIntentV1.create
    def create(*args, **kwargs):
        result = original_create(*args, **kwargs)
        if capture_binding is not None:
            capture_binding.update(result.to_payload())
        return result
    module = 'tests.unit.components.test_bisimulation_normal_exits.'
    with patch.object(ComponentMachineBindingIntentV1, 'create', side_effect=create), patch(module+'check_bisimulation_refinement', side_effect=lambda **kw: check_bisimulation_refinement(
            **kw, runtime_assurance=assurance)), patch(module+'build_contextual_refinement_v2', side_effect=build), patch(
            module+'validate_contextual_refinement_v2', side_effect=lambda *a, **kw:
                validate_conditional_contextual_refinement_v1(*a, **kw, runtime_assurance=assurance)):
        check_normal_exit(root, cbmc=Path(shutil.which('cbmc')), **options)
    path = root/'contextual-refinement-result.json'
    result = json.loads(path.read_text())
    path.rename(root/'conditional-refinement-result.json')
    return result, inputs, assurance


class ConditionalContextualRefinementTests(unittest.TestCase):
    def setUp(self):
        if shutil.which('cbmc') is None or shutil.which('goto-cc') is None:
            self.skipTest('CBMC tools required')

    def test_real_component_proof_and_counterexample_keep_authority_separate(self):
        for source_value, expected in ((7, 'satisfied'), (8, 'violated')):
            with self.subTest(source_value=source_value), tempfile.TemporaryDirectory() as directory:
                system, inputs, assurance = fixture(Path(directory), source_value=source_value)
                proof = system['proof']
                self.assertEqual(proof['status'], expected)
                self.assertFalse(proof['activation_authorized'])
                self.assertFalse(proof['authorizing'])
                with self.assertRaisesRegex(ValueError, 'conditional runtime-contract'):
                    build_contextual_refinement_v2(**inputs)
                with self.assertRaisesRegex(ValueError, 'conditional runtime-contract'):
                    validate_contextual_refinement_v2(system['proof'], proof_plan=system['proof_plan'], exact_c_slice=system['exact_c_slice'])
                with self.assertRaisesRegex(ValueError, 'explicit runtime contracts'):
                    validate_conditional_contextual_refinement_v1(system['proof'], proof_plan=system['proof_plan'], exact_c_slice=system['exact_c_slice'], runtime_assurance=None)
                with self.assertRaisesRegex(ValueError, 'binding differs'):
                    changed = copy.deepcopy(assurance)
                    changed['contracts'] = []
                    forged = copy.deepcopy(system)
                    forged['proof']['assurance'] = changed
                    reseal(forged['proof'])
                    validate_conditional_contextual_refinement_v1(forged['proof'], proof_plan=forged['proof_plan'], exact_c_slice=forged['exact_c_slice'], runtime_assurance=assurance)

    def test_resealed_missing_obligations_and_mixed_assumptions_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            original, _, assurance = fixture(Path(directory))
            mutations = ('operation_assurance', 'model_assurance', 'shard_assurance', 'model_authority',
                         'runtime_input', 'authored_assertions', 'language_safety', 'nonvacuity',
                         'execution_binding', 'activation', 'native_policy', 'shard_inventory')
            for mutation in mutations:
                system = copy.deepcopy(original)
                proof = system['proof']
                operation = proof['models']['operation_models'][0]
                model = operation['obligation_models'][0]
                shard = proof['shards'][0]
                if mutation == 'operation_assurance': operation.pop('assurance')
                elif mutation == 'model_assurance': model.pop('assurance')
                elif mutation == 'shard_assurance': shard.pop('assurance')
                elif mutation == 'model_authority': model['authorizing'] = True
                elif mutation == 'runtime_input':
                    next(row for row in model['proof_inputs'] if row['role'] == 'runtime_assurance')['sha256'] = 'a'*64
                    model['proof_model_sha256'] = canonical_sha256_v3(model['proof_inputs'])
                elif mutation == 'authored_assertions': shard['partitioned_evidence']['assertions'].pop()
                elif mutation == 'language_safety': shard['partitioned_evidence']['language_safety'] = {}
                elif mutation == 'nonvacuity': shard['nonvacuity']['status'] = 'incomplete'
                elif mutation == 'execution_binding': shard['execution_binding_sha256'] = 'a'*64
                elif mutation == 'activation': proof['activation_authorized'] = True
                elif mutation == 'native_policy': proof['policy']['proof_form'] = 'strong_cutpoint_bisimulation'
                else: proof['shards'].pop()
                reseal(proof)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    validate_conditional_contextual_refinement_v1(system['proof'], proof_plan=system['proof_plan'], exact_c_slice=system['exact_c_slice'], runtime_assurance=assurance)
            # Removing the outer label and resealing cannot erase model assumptions.
            forged = copy.deepcopy(original)
            proof = forged['proof']
            proof.pop('assurance'); proof.pop('authorizing')
            proof['format'] = CONTEXTUAL_REFINEMENT_V2_FORMAT
            proof['policy'].pop('assumed_runtime_contracts')
            proof['policy']['proof_form'] = 'strong_cutpoint_bisimulation'
            reseal(proof)
            with self.assertRaises(ValueError):
                validate_contextual_refinement_v2(forged['proof'], proof_plan=forged['proof_plan'], exact_c_slice=forged['exact_c_slice'])

    def test_auxiliary_frames_bind_assumptions_and_retained_output(self):
        from spaghetti_extractor.components.bisimulation_exact_frame import validate_exact_frame
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            system, _, assurance = fixture(root, reference_view=True, read_buffer=True, return_to_caller=True,
                                           reference_authority=authority_payload())
            proof = system['proof']
            self.assertEqual(proof['status'], 'satisfied')
            shard = proof['shards'][0]
            model = proof['models']['operation_models'][0]['obligation_models'][0]
            frame = shard['exact_memory_frame']
            self.assertEqual(frame['result']['status'], 'satisfied')
            kwargs = dict(model=model, shard=shard, checker=proof['checker'])
            artifacts = root/'diagnostics/operation-0000-obligation-0000'
            validate_exact_frame(frame, **kwargs, runtime_assurance=assurance, artifacts=artifacts)
            with self.assertRaisesRegex(ValueError, 'conditional runtime-contract'):
                validate_exact_frame(frame, **kwargs)
            missing = copy.deepcopy(system)
            missing['proof']['shards'][0]['exact_memory_frame'].pop('assurance')
            reseal(missing['proof']['shards'][0]['exact_memory_frame']); reseal(missing['proof'])
            with self.assertRaisesRegex(ValueError, 'binding differs'):
                validate_conditional_contextual_refinement_v1(missing['proof'], proof_plan=missing['proof_plan'], exact_c_slice=missing['exact_c_slice'], runtime_assurance=assurance)
            (artifacts/'exact-frame.stdout').write_text('corrupt retained solver output')
            with self.assertRaisesRegex(ValueError, 'retained solver output differs'):
                validate_exact_frame(frame, **kwargs, runtime_assurance=assurance, artifacts=artifacts)

    def test_conditional_supplier_cannot_export_a_regional_continuation(self):
        from spaghetti_extractor.components.contextual_bisimulation import validate_complete_local_refinement
        with tempfile.TemporaryDirectory() as directory:
            system, _, assurance = fixture(Path(directory), common_context=True)
            self.assertEqual(system['proof']['status'], 'satisfied')
            self.assertTrue(system['proof_plan']['operations'][0]['continuation'])
            with self.assertRaisesRegex(ValueError, 'continuation or allocation-history premises'):
                validate_complete_local_refinement(system, runtime_assurance=assurance)

    def test_checked_callee_entry_requires_the_callers_exact_assumptions(self):
        from spaghetti_extractor.components.bisimulation_assurance import admitted_supplier_assurance
        from spaghetti_extractor.components.bisimulation_call_entry import checked_call_entry_contract, validate_call_entry_contract
        from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance
        from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binding = {}
            system, _, assurance = fixture(root, reference_view=True, read_buffer=True, return_to_caller=True,
                source_contracts=True, reference_authority=authority_payload(), capture_binding=binding)
            proof = system['proof']
            raw = {'proof_system': system, 'binding_intent': binding, 'proof_artifacts': root/'diagnostics',
                   'source_summary_contracts': proof['models']['source_summary_contracts']}
            connected = {'component_id': proof['component_id'], 'proof_receipt_sha256': proof['receipt_sha256'],
                         'binding_intent_sha256': ComponentMachineBindingIntentV1.parse(binding).intent_sha256,
                         **{k: proof['models'][k] for k in ('implementation_sha256', 'source_profile_sha256',
                                                           'machine_overlay_sha256', 'proof_overlay_sha256')}}
            entry = checked_call_entry_contract(raw, connected=connected, runtime_assurance=assurance)
            self.assertEqual(entry['operations'][0]['domain'], 'readable-wide')
            self.assertEqual(entry['assurance'], assurance)
            with self.assertRaises(ValueError):
                checked_call_entry_contract(raw, connected=connected)
            with self.assertRaises(ValueError):
                validate_call_entry_contract(entry, connected=connected)
            for parent in (None, world_reference_assurance()):
                with self.subTest(parent=parent), self.assertRaisesRegex(ValueError, 'not selected by the caller'):
                    admitted_supplier_assurance(proof, parent)
            superset = copy.deepcopy(assurance)
            superset['contracts'].extend(world_reference_assurance()['contracts'])
            self.assertEqual(admitted_supplier_assurance(proof, superset), assurance)
            changed = copy.deepcopy(entry); changed.pop('assurance'); reseal(changed)
            with self.assertRaisesRegex(ValueError, 'binding differs'):
                validate_call_entry_contract(changed, connected=connected, runtime_assurance=assurance)

    def test_actual_caller_proof_composes_conditional_leaf_and_detects_bad_view(self):
        from tests.unit.components.connected_reader_fixture import check_connected_reader
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); leaf = root/'leaf'; leaf.mkdir()
            _, _, assurance = fixture(leaf, reference_view=True, read_buffer=True, return_to_caller=True,
                source_contracts=True, reference_authority=authority_payload())
            for bad in (False, True):
                caller = root/('bad' if bad else 'caller')
                result = check_connected_reader(caller, leaf=leaf, cbmc=Path(shutil.which('cbmc')),
                    runtime_assurance=assurance, invalid_callee_view=bad, timeout_seconds=60)
                self.assertEqual(result['status'], 'violated' if bad else 'satisfied', result['issues'])
                proof = json.loads((caller/'conditional-refinement-result.json').read_text())['proof']
                supplier = proof['models']['connected_components'][0]
                self.assertIsNone(supplier['qualification_sha256'])
                self.assertEqual(supplier['assurance'], assurance)
                self.assertEqual(supplier['summary_strategy'], 'image-readable-body-free-v1')
                self.assertFalse(proof['activation_authorized'])
                if not bad:
                    mutated = copy.deepcopy(proof)
                    mutated['models']['connected_components'][0].pop('assurance'); reseal(mutated)
                    system = json.loads((caller/'conditional-refinement-result.json').read_text())
                    with self.assertRaisesRegex(ValueError, 'binding differs'):
                        validate_conditional_contextual_refinement_v1(mutated, proof_plan=system['proof_plan'],
                            exact_c_slice=system['exact_c_slice'], runtime_assurance=assurance)
