"""Canonical semantic contracts preserve checked allocation result wrappers."""

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.machine_binding import create_proof_kernel_machine_binding
from spaghetti_extractor.components.semantic_contract import (
    CanonicalTransferRefinementUniverseV2, build_proof_kernel_semantic_contract,
)
from .test_inductive_relation import _unit
from .test_semantic_external_services import _resolved_environment
from .test_bisimulation_allocation_calls import selected_row

TESTKIT = {'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def compile_allocation(*, kind='reference', mutate=None, register='eax', projection=True):
    row = copy.deepcopy(selected_row('GlobalAlloc'))
    payload = row['contract']['payload']
    if mutate:
        mutate(payload)
    logical = {'id': 'allocated', 'kind': kind}
    if kind in {'reference', 'view'}:
        logical.update(access='read_write', nullable=True, element_type_id='byte')
    if kind == 'reference':
        logical.update(allow_one_past=False, lifetime='origin')
    if kind == 'view':
        logical.update(ownership='borrowed', extent={'kind': 'fixed', 'elements': 16})
    if kind == 'scalar':
        logical.update(c_type='uint32_t')
    if kind == 'resource':
        logical.update(resource_kind='handle', ownership='borrowed')
    interface = {'id': 'allocation_result', 'types': [
        {'id': 'word', 'kind': 'scalar', 'c_type': 'uint32_t'},
        {'id': 'byte', 'kind': 'scalar', 'c_type': 'uint8_t'}, logical],
        'state': [], 'operations': [{'id': 'run', 'kind': 'operation', 'parameters': [],
            'results': [], 'effect_ids': [], 'allowed_service_ids': ['allocate'],
            'pre_states': ['ready'], 'post_states': ['ready']}],
        'effects': [], 'services': [{'id': 'allocate', 'parameter_type_ids': ['word', 'word'],
            'result_type_id': 'allocated', 'effect_ids': []}],
        'protocol': {'states': ['ready'], 'initial_state': 'ready'}}
    unit = _unit('unit:allocate', 4096, [], [])
    unit['status'] = 'qualified'
    event = {'kind': 'external_call', 'dll': 'kernel32.dll', 'symbol': 'GlobalAlloc',
        'ordinal': None, 'instruction_rva': 4100, 'return_rva': 4105, 'target_rva': 0,
        'register_inputs': {name: {'op': 'reg', 'name': name, 'width': 32}
            for name in ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')},
        'stack_inputs': [{'offset': i * 4, 'width': 4,
            'value': {'op': 'const', 'value': value, 'width': 32}}
            for i, value in enumerate((64, 16))]}
    unit['semantics']['external_events'] = [event]
    provider = {'kind': 'external_call', 'identity': row['identity'],
        'events': [{'unit_id': unit['id'], 'event_index': 0}]}
    if projection:
        provider['result_projection'] = {
            'kind': 'view' if kind == 'view' else 'reference', 'at': 'call',
            'base' if kind == 'view' else 'source':
                {'kind': 'register', 'register': register, 'width': 32, 'at': 'call'},
            'requested_extent': {'kind': 'constant', 'value': 1, 'width': 32},
            'authority': {'id': 'allocated', 'kind': 'external', 'lifetime': 'allocation'}}
        if kind == 'view':
            provider['result_projection']['extent'] = {'kind': 'origin_remainder'}
    binding = create_proof_kernel_machine_binding(id='allocation_result',
        binary={'pe_sha256': 'a' * 64, 'machine_ir_sha256': 'b' * 64},
        interface={'id': interface['id'], 'sha256': canonical_sha256_v3(interface)},
        unit_ids=[unit['id']], operations=[{'operation_id': 'run',
            'entry_unit_ids': [unit['id']], 'exit_unit_ids': [unit['id']],
            'parameters': [], 'results': [], 'state': [], 'effects': [],
            'preserved_state_ids': [], 'callback_operation_ids': [], 'continuation_unit_ids': []}],
        services=[{'service_id': 'allocate', 'mediation': 'direct', 'provider': provider}])
    universe = CanonicalTransferRefinementUniverseV2({}, {unit['id']: unit}, 'b' * 64, 'a' * 64)
    return build_proof_kernel_semantic_contract(interface=interface, binding=binding,
        machine_ir=universe, resolved_external_environment=_resolved_environment(row))


class SemanticAllocationResultTests(unittest.TestCase):
    def test_checked_owned_allocation_retains_reference_and_view(self):
        for kind in ('reference', 'view'):
            with self.subTest(kind=kind):
                result = compile_allocation(kind=kind)
                self.assertEqual(result['status'], 'satisfied', result['issues'])
                event = result['services'][0]['provider']['events'][0]
                self.assertEqual(event['result']['kind'], kind)
                self.assertEqual(event['result']['authority']['lifetime'], 'allocation')

    def test_allocation_does_not_establish_scalar_or_handle_equality(self):
        for kind in ('scalar', 'resource'):
            with self.subTest(kind=kind):
                result = compile_allocation(kind=kind, projection=False)
                self.assertNotEqual(result['status'], 'satisfied')
                self.assertIn('external_call_service_result_unresolved',
                              [row['code'] for row in result['issues']])

    def test_allocation_requires_supported_owned_transition(self):
        mutations = {
            'ownership': lambda p: p['result_register_relations'][0].pop('ownership'),
            'initialization': lambda p: p['result_register_relations'][0].pop('allocation'),
            'additional_write': lambda p: p.update(memory_effect='argumentRanges'),
            'wrong_world': lambda p: p.update(world_effect='opaqueResources'),
            'size_frame': lambda p: p['result_register_relations'][0].update(size={'kind': 'argument', 'argument': 2}),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                result = compile_allocation(mutate=mutation)
                self.assertNotEqual(result['status'], 'satisfied')

    def test_result_wrapper_still_requires_the_authorized_register(self):
        for options in ({'register': 'ebx'}, {'projection': False}):
            with self.subTest(options=options):
                result = compile_allocation(**options)
                self.assertNotEqual(result['status'], 'satisfied')
                self.assertTrue(any('result_projection' in row['code'] for row in result['issues']))
