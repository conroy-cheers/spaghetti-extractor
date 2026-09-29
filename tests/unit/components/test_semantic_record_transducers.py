import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.refinement_harness import _render_expression, _UnsupportedRefinement
from spaghetti_extractor.components.machine_overlay_services_v5 import _normalize_aggregate_result_binding
from spaghetti_extractor.components.semantic_external_transducers import ComponentSemanticContractError, checked_external_argument_transducers
from spaghetti_extractor.components.semantic_record_transducers import normalize_external_aggregate_binding, checked_record_result_projection

ROOT = Path(__file__).parents[3]
TESTKIT = {
    "resources": (
        "targets/jq/intent/interfaces-v5/output-value-pipeline.json",
        "targets/jq/intent/bindings-v5/output-value-pipeline.json",
    ),
}


class SemanticRecordTransducerTests(unittest.TestCase):
    def setUp(self):
        intent = ComponentInterfaceIntentV1.parse(json.loads((ROOT/'targets/jq/intent/interfaces-v5/output-value-pipeline.json').read_text()))
        self.bundle = compile_component_interface_v5(intent)
        self.interface = ProofKernelComponentInterface.parse(_logical_projection(self.bundle))
        self.types = self.interface.type_index()
        self.logical = next(row for row in self.interface.services if row.identity == 'copy_value')
        binding = json.loads((ROOT/'targets/jq/intent/bindings-v5/output-value-pipeline.json').read_text())
        self.provider = binding['operations'][0]['machine_projection']['service_bindings'][0]['provider']
        # Minimal checked transport geometry, also exercised against the retained
        # real Clang ABI in the jq provider preparation regression.
        self.contract = {'profile_sha256': 'a'*64, 'payload': {'arity': {'kind': 'fixed', 'words': 5}}}
        self.row = {'contract': self.contract, 'boundary': {'physical_call_frame_v3': {'transport': {
            'arguments': [{'id': 'sret', 'role': 'hidden_sret', 'storage_bits': 32,
                           'fragments': [{'location': {'kind': 'stack', 'stack_offset_bytes': 4, 'width_bits': 32}}]}],
            'results': [{'pass_mode': 'indirect', 'storage_bits': 128,
                         'fragments': [{'location': {'kind': 'memory', 'memory_slot': 'sret', 'width_bits': 128}}]}],
        }}}}
        self.arguments = [{'op': 'const', 'width': 32, 'value': value} for value in [4096, 11, 22, 33, 44]]

    def normalize(self):
        return normalize_external_aggregate_binding(provider=self.provider, logical=self.logical,
            logical_types=self.types, contract_row=self.row, payload=self.contract['payload'])

    def decode(self, provider, payload):
        return checked_external_argument_transducers(provider['argument_transducers'],
            logical=self.logical, logical_types=self.types, contract=self.contract,
            contract_payload=payload, contract_arguments=self.arguments)

    def test_semantic_and_overlay_normalization_are_identical(self):
        provider, payload = self.normalize()
        service = next(row for row in self.bundle.interface.services if row.identity == 'copy_value')
        transducers, cells, memory, result = _normalize_aggregate_result_binding(
            signature=self.bundle.intent.schema.signature_index[service.signature_id],
            types=self.bundle.intent.schema.type_index, provider=self.provider,
            payload=self.contract['payload'], contract_row=self.row, argument_words=5, context='fixture')
        self.assertEqual((provider['argument_transducers'], payload['local_cells'], payload['caller_memory_frame'], provider['result_projection']),
                         (transducers, cells, memory, result))
        logical, physical, guards, writebacks = self.decode(provider, payload)
        self.assertEqual(dict(zip(logical[0]['field_ids'], [row['value'] for row in logical[0]['args']])),
                         {'metadata': 11, 'size': 22, 'payload_low': 33, 'payload_high': 44})
        self.assertEqual(len(physical), 5)
        self.assertEqual((guards, writebacks), ([], []))
        with self.assertRaisesRegex(_UnsupportedRefinement, "record.*unsupported"):
            _render_expression(logical[0])
        result, rule = checked_record_result_projection(provider['result_projection'],
            logical_type=self.types[self.logical.result_type_id], logical_types=self.types,
            transducers=provider['argument_transducers'], contract_payload=payload, argument_words=5)
        self.assertIsNone(rule)
        self.assertEqual(result['kind'], 'record_view')
        self.assertEqual([row['id'] for row in result['fields']], ['metadata', 'payload_high', 'payload_low', 'size'])

    def test_rejects_missing_duplicate_unknown_and_mixed_argument_fields(self):
        for change in ['missing', 'duplicate', 'unknown', 'whole']:
            with self.subTest(change=change):
                provider, payload = self.normalize()
                provider = copy.deepcopy(provider)
                row = provider['argument_transducers'][-1]
                if change == 'missing':
                    provider['argument_transducers'][-1] = {'kind': 'constant', 'value': 44}
                elif change == 'duplicate':
                    row['field_id'] = 'metadata'
                elif change == 'unknown':
                    row['field_id'] = 'absent'
                else:
                    provider['argument_transducers'][-1] = {'kind': 'logical_argument', 'parameter_index': 0}
                with self.assertRaises(ComponentSemanticContractError):
                    self.decode(provider, payload)

    def test_rejects_missing_or_uninitialized_result_word(self):
        for change in ['missing', 'duplicate', 'outside']:
            with self.subTest(change=change):
                provider, payload = self.normalize()
                value = copy.deepcopy(provider['result_projection'])
                if change == 'missing':
                    value['fields'].pop()
                elif change == 'duplicate':
                    value['fields'][-1]['id'] = value['fields'][0]['id']
                else:
                    value['fields'][-1]['word_index'] = 4
                with self.assertRaises(ComponentSemanticContractError):
                    checked_record_result_projection(value,
                        logical_type=self.types[self.logical.result_type_id], logical_types=self.types,
                        transducers=provider['argument_transducers'], contract_payload=payload, argument_words=5)

    def test_rejects_single_word_in_place_of_whole_record(self):
        provider, payload = self.normalize()
        provider['argument_transducers'][1:] = [
            {'kind': 'logical_argument', 'parameter_index': 0},
            *[{'kind': 'constant', 'value': value} for value in [22, 33, 44]],
        ]
        with self.assertRaisesRegex(ComponentSemanticContractError, 'complete checked field inventory'):
            self.decode(provider, payload)

    def test_rejects_stale_hidden_return_geometry(self):
        for field, value in [('storage_bits', 64), ('pass_mode', 'direct')]:
            with self.subTest(field=field):
                row = copy.deepcopy(self.row)
                row['boundary']['physical_call_frame_v3']['transport']['results'][0][field] = value
                with self.assertRaises(ComponentSemanticContractError):
                    normalize_external_aggregate_binding(provider=self.provider, logical=self.logical,
                        logical_types=self.types, contract_row=row, payload=self.contract['payload'])

    def test_rejects_nonword_record_field(self):
        field = self.types[self.logical.result_type_id].fields[0]
        self.types[field.type_id] = replace(self.types[field.type_id], c_type='uint64_t')
        with self.assertRaisesRegex(ComponentSemanticContractError, 'one checked word'):
            self.normalize()
