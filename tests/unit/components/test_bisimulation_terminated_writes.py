"""Constructible output termination, current-memory consumers and strict readers."""

import copy
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.external.terminated_reads import checked_terminated_write
from .test_bisimulation_call_ranges import buffer_binding, check_buffer_program
from .test_bisimulation_heap_call_ranges import program
from . import test_bisimulation_allocation_calls as calls

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler', 'jq'),
           'resources': ('profiles/pe32-kernel32-runtime-v1.json', 'nix/jq/strong-contextual-proof.jq')}


def binding():
    selected = buffer_binding()
    selected['external_effect_contract'].update(disposition='returns', result_register_relations=[{
        'register': 'eax', 'relation': 'written_terminated_byte_count',
        'base_argument': 2, 'capacity_argument': 3}])
    return selected


class TerminatedWriteTests(unittest.TestCase):
    def check(self, body, *, status='satisfied', detail=None):
        result = check_buffer_program(body, binding=binding())
        self.assertEqual(result['status'], status, result)
        if detail:
            self.assertIn(detail, result['detail'])

    def test_real_resource_buffer_shape_replays_bytes_and_supplies_current_nul_view(self):
        self.check('''
  original(0x413d20U, 500U);
  uint32_t n = spx_exact_world.calls[0].response_eax;
  __CPROVER_assert(n < 500U, "output count fits real resource buffer");
  __CPROVER_assert(spx_proof_exact_byte(0x413d20U + n) == 0U, "returned count byte is zero");
  __CPROVER_assert(spx_proof_borrowed_nul_extent(&spx_exact_world, 0x413d20U, 500U) == n + 1U,
      "message view has a current bounded terminator");
  portable(0x413d20U, 500U);
  __CPROVER_assert(spx_proof_borrowed_nul_extent(&spx_source_world, 0x413d20U, 500U) == n + 1U,
      "portable message view sees the replayed terminator");
  if (address >= 0x413d20U && address < 0x413d20U + 500U && address != 0x413d20U + n)
    __CPROVER_assert(spx_proof_source_byte(address) == __CPROVER_uninterpreted_spx_call_byte(0U, address),
      "unconstrained output bytes are not invented string contents");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "paired output memory and frame");
''')

    def test_every_admitted_count_including_zero_has_an_output_witness(self):
        for count in (0, 1, 499):
            with self.subTest(count=count):
                self.check(f'''
  original(0x413d20U, 500U);
  __CPROVER_assume(spx_exact_world.calls[0].response_eax == {count}U);
  __CPROVER_assert(0U, "output count remains reachable");
''', status='violated', detail='output count remains reachable')

    def test_history_does_not_preserve_terminator_after_alias_write(self):
        self.check('''
  original(0x413d20U, 500U);
  uint32_t n = spx_exact_world.calls[0].response_eax;
  __CPROVER_assume(n < 499U);
  spx_proof_exact_write(0, 0x413d20U + n, 1U, 93U, &fault);
  __CPROVER_assert(spx_proof_borrowed_nul_extent(&spx_exact_world, 0x413d20U, 500U) == 500U,
      "overwritten witness falls back to checked adapter final byte");
  __CPROVER_assert(spx_proof_exact_byte(0x413d20U + n) == 93U, "alias mutation wins");
''')

    def test_invalid_capacity_authority_and_changed_input_reject(self):
        for body, detail in (
            ('original(0x413d20U, 0U);', 'written-termination-capacity'),
            ('original(0x413d20U, 501U);', 'call-buffer-authority'),
            ('original(0U, 500U);', 'call-buffer-authority'),
            ('''original(0x413d20U, 500U);
                spx_proof_source_write(0, 0x413d20U, 1U, 93U, &fault);
                portable(0x413d20U, 500U);''', 'buffer-typed-arguments')):
            with self.subTest(body=body):
                self.check(body, status='violated', detail=detail)

    def test_heap_output_requires_current_origin_and_retirement_removes_read_authority(self):
        body = program('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  BUFFER(&spx_exact_world, 4096U, 16U);
  BUFFER(&spx_source_world, 4096U, 16U);
  uint32_t n = spx_exact_world.calls[1].response_eax;
  __CPROVER_assert(spx_proof_terminated_read_span(&spx_exact_world, 4096U) == n + 1U,
      "current heap origin supplies readable output");
  __CPROVER_assert(spx_proof_terminated_read_span(&spx_source_world, 4096U) == n + 1U,
      "replayed heap origin supplies readable output");
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) == 0U, "paired release");
  __CPROVER_assert(spx_proof_terminated_read_span(&spx_source_world, 4096U) == 0U,
      "historical output cannot revive a retired buffer");
''', binding())
        calls.AllocationCallTests.check(self, body, unwind=7, typed_source=True, typed_exact=True,
                                       max_calls=3, extra_bindings=(binding(),))

    def test_python_and_independent_reader_reject_weakened_output_contract(self):
        program_text = Path('nix/jq/strong-contextual-proof.jq').read_text()
        good = binding()['external_effect_contract']
        mutations = [None]
        for key, value in (('base_argument', True), ('capacity_argument', 2), ('capacity_argument', 4),
                           ('register', 'edx'), ('first_zero', True)):
            p = copy.deepcopy(good); p['result_register_relations'][0][key] = value; mutations.append(p)
        for key, value in (('disposition', 'noreturn'), ('world_effect', 'dynamicRanges'),
                           ('memory_footprints', []), ('out_pointer_relations', None), ('effect_model', {})):
            p = copy.deepcopy(good); p[key] = value; mutations.append(p)
        for key, value in (('offset', False), ('nullable', 0), ('access', 'read_write')):
            p = copy.deepcopy(good); p['memory_footprints'][0][key] = value; mutations.append(p)
        p = copy.deepcopy(good); p['memory_footprints'][0]['size']['scale'] = True; mutations.append(p)
        for mutation in mutations:
            payload = good if mutation is None else mutation
            with self.subTest(payload=payload):
                if mutation is None:
                    self.assertIsNotNone(checked_terminated_write(payload, argument_words=4))
                    _proof_call_specs([binding()])
                else:
                    with self.assertRaises(ValueError):
                        checked_terminated_write(payload, argument_words=4)
                    with self.assertRaises(ValueError):
                        _proof_call_specs([{**binding(), 'external_effect_contract': payload}])
                result = subprocess.run([shutil.which('jq'), program_text + '\nspx_terminated_write_effect(4)'],
                    input=json.dumps(payload), text=True, capture_output=True, check=True, timeout=10)
                self.assertEqual(json.loads(result.stdout), mutation is None)
