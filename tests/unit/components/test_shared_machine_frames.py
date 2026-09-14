"""Fixed shared grants constrain exact writes without granting body substitution."""
import copy
from dataclasses import replace
import unittest
import shutil
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import CanonicalValueV3
from spaghetti_extractor.components.interface_ir import (
    ProofKernelComponentInterface, ProofKernelLogicalType, ProofKernelLogicalValue,
    ProofKernelStateField, ProofKernelOperation, ProofKernelEffect)
from spaghetti_extractor.components.bisimulation_mutable_frame import (
    mutable_frame_views, mutable_frame_initialization, mutable_cut_frame_checks, ACTIVE, BASES)
from spaghetti_extractor.components.bisimulation_clobber_frame import result_registers, clobber_specs
from .test_shared_state_views import projections
from .test_bisimulation_call_ranges import check_buffer_program

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text",)}


def interface():
    return ProofKernelComponentInterface('private-proof-kernel', 'helper', (
        ProofKernelLogicalType('buffer', 'view', access='read_write', nullable=False,
                               extent_kind='fixed', fixed_extent=500),
        ProofKernelLogicalType('module', 'view', access='read', nullable=False,
                               extent_kind='fixed', fixed_extent=4)), (
        ProofKernelStateField('buffer', 'buffer', CanonicalValueV3.of(None)),
        ProofKernelStateField('module', 'module', CanonicalValueV3.of(None))), (
        ProofKernelOperation('get', 'operation', (), (), ('written',), ('load_string',), ('ready',), ('ready',)),),
        (ProofKernelEffect('written', 'memory', 'buffer', 'get'),), (), ('ready',), 'ready')


class SharedMachineFrameTests(unittest.TestCase):
    def test_borrowed_shared_grant_transports_across_cut_without_parameter_capture(self):
        model = interface()
        views = mutable_frame_views(model, 'get', ())
        self.assertEqual(views, (('state:buffer', 500),))
        state, _ = projections()
        operation = {'parameters': [], 'state': list(state.values())}
        sync = SimpleNamespace(captures=())
        self.assertEqual(mutable_frame_initialization(views, operation, None),
                         mutable_frame_initialization(views, operation, sync))
        self.assertEqual(len(mutable_cut_frame_checks(views, sync, operation)), 1)
        # A parameter and a shared object may have the same logical name.
        parameter = ProofKernelLogicalValue('buffer', 'buffer')
        model = replace(model, operations=(replace(model.operations[0], parameters=(parameter,)),))
        self.assertEqual(mutable_frame_views(model, 'get', ()), (('buffer', 500), ('state:buffer', 500)))

    def test_moved_dynamic_initialized_or_unchecked_boundaries_supply_no_frame(self):
        model = interface()
        views = mutable_frame_views(model, 'get', ())
        state, _ = projections()
        original = {'parameters': [], 'state': list(state.values())}
        for mutation in ('moved', 'register', 'extent', 'lifetime', 'absent'):
            with self.subTest(mutation=mutation):
                operation = copy.deepcopy(original)
                row = operation['state'][0]
                if mutation == 'moved':
                    row['exit'] = copy.deepcopy(row['exit'])
                    row['exit']['base']['value'] += 1
                elif mutation == 'register': row['entry']['base'] = {'kind': 'register', 'width': 32, 'register': 'eax', 'at': 'entry'}
                elif mutation == 'extent': row['entry']['extent']['value'] -= 1
                elif mutation == 'lifetime': row['entry']['authority']['lifetime'] = 'operation'
                else: operation['state'] = []
                with self.assertRaisesRegex(ValueError, 'unchanged fixed image'):
                    mutable_cut_frame_checks(views, SimpleNamespace(captures=()), operation)
        self.assertEqual(mutable_frame_views(replace(model, state=(replace(model.state[0], initial_value=CanonicalValueV3.of(0)),)), 'get', ()), ())
        self.assertEqual(mutable_frame_views(model, 'get', ({'summary_strategy': 'replay'},)), ())
        self.assertEqual(mutable_frame_views(replace(model, effects=(replace(model.effects[0], kind='resource'),)), 'get', ()), ())

    def test_service_range_must_fit_shared_grant_even_inside_larger_image_origin(self):
        if not shutil.which('cbmc'):
            self.skipTest('CBMC is unavailable')
        for size, status in ((500, 'satisfied'), (499, 'violated')):
            with self.subTest(frame_bytes=size):
                body = f"""
  spx_proof_reset_worlds(0x800000U, 4096U);
  {ACTIVE} = 1U;
  {BASES}[0] = 0x413d20U;
  original(0x413d20U, 500U);
"""
                result = check_buffer_program(body, world_options={
                    'mutable_frame_views': (('state:buffer', size),)})
                self.assertEqual(result['status'], status, result.get('detail'))

    def test_returned_view_base_remains_observable_in_clobber_frames(self):
        _, result = projections()
        operation = {'results': [{'projection': result}]}
        self.assertEqual(result_registers(operation), ('eax',))
        with self.assertRaisesRegex(ValueError, 'preserve separately mapped'):
            clobber_specs(('eax',), result_registers(operation))
        for bad in ({'kind': 'constant', 'width': 32, 'value': 0},
                    {'kind': 'register', 'width': 16, 'register': 'eax', 'at': 'exit'},
                    {'kind': 'register', 'width': 32, 'register': 'eax', 'at': 'entry'}):
            with self.assertRaisesRegex(ValueError, 'full-width register'):
                result_registers({'results': [{'projection': {**result, 'base': bad}}]})
