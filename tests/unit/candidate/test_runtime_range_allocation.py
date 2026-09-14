"""Real fixed-GlobalAlloc contracts retain flags through native admission."""

import copy
import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.candidate.runtime_canonical_errors import CanonicalRuntimeError
from spaghetti_extractor.candidate.runtime_external_range_validation import _external_range_rules
from spaghetti_extractor.candidate.runtime_range_allocation import allocation_tables
from spaghetti_extractor.candidate.runtime_model import CandidateRuntimeError
from spaghetti_extractor.components.bisimulation_service_effects import checked_proof_external_effect_contract
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.external.contracts import parse_checked_external_site_contract, CheckedExternalSiteContractError
from spaghetti_extractor.external.range_allocation import RangeAllocationError, parse_range_allocation
from spaghetti_extractor.external.machine_import_profiles import load_machine_import_profile_set, MachineImportProfileError
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_runtime_allocation_sites import native_inventory, checked_site
from .test_runtime_range_ownership import ownership_fixture, rules as heap_rules

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "profiles/pe32-kernel32-runtime-v1.json", "profiles/pe32-native-callthrough-runtime-v1.json",
)}
ROOT = Path(__file__).resolve().parents[3]


def selected_profile(symbol):
    path = ROOT / 'profiles/pe32-kernel32-runtime-v1.json'
    profiles = load_machine_import_profile_set([path])
    return next(row for identity, row in profiles.by_identity().items() if identity.value == symbol)


def profile(symbol):
    return copy.deepcopy(selected_profile(symbol).contract)


def checked(payload, *, rva=0x55d1):
    identity = {**payload['import'], 'ordinal': None}
    selected = selected_profile(payload['import']['symbol'])
    return _checked_contract(row={'identity': identity, 'boundary': {}, 'contract': {
        'payload': payload, 'profile_id': selected.profile_id,
        'profile_sha256': selected.profile_sha256,
        'entry_key': selected.entry_key, 'entry_index': selected.entry_index}},
        call=SimpleNamespace(argument_nodes=(), instruction_rva=rva), escape_index={})


def global_rules():
    sites = []
    for index, symbol in enumerate(('GlobalAlloc', 'GlobalFree')):
        template = checked_site(index)
        contract = checked(profile(symbol), rva=template.instruction_rva)
        sites.append(replace(template, dll='kernel32.dll', symbol=symbol,
            checked_external_contract=contract,
            abi_metadata_sha256=canonical_sha256_v3(contract.profile_effect_payload()),
            target_resolution_evidence={**template.target_resolution_evidence,
                'identity': ['kernel32.dll', 'symbol', symbol]}))
    rules, _, blocked = _external_range_rules(native_inventory(sites), None,
        resolved_environment_sha256='d' * 64)
    assert not blocked, blocked
    return tuple(rule for rule in rules if rule.action in {'add_result_range', 'release_argument_range'})


class AllocationContractTests(unittest.TestCase):
    def test_initialization_codec_preserves_explicit_modes_and_rejects_extra_fields(self):
        for kind in ('zero', 'uninitialized'):
            payload = {'argument_masks': [], 'initialization': {'kind': kind}}
            parsed = parse_range_allocation(payload, argument_words=2, context='test')
            self.assertEqual(parsed.payload(), payload)
            payload['initialization']['ignored'] = True
            with self.assertRaises(RangeAllocationError):
                parse_range_allocation(payload, argument_words=2, context='test')

    def test_real_profile_codec_inventory_and_native_tables_preserve_contract(self):
        profiles = load_machine_import_profile_set([ROOT / 'profiles/pe32-kernel32-runtime-v1.json',
            ROOT / 'profiles/pe32-native-callthrough-runtime-v1.json'])
        self.assertEqual(sum(key.value == 'GlobalAlloc' for key in profiles.by_identity()), 1)
        payload = profile('GlobalAlloc')
        parsed = parse_checked_external_site_contract(checked(payload).payload())
        self.assertEqual(parsed.profile_effect_payload()['result_register_relations'],
                         payload['result_register_relations'])
        allocate, release = global_rules()
        self.assertEqual(allocate.argument_count, 2)
        self.assertEqual(allocate.size_argument, 1)
        self.assertEqual(allocate.allocation.argument_masks, ((0, 64),))
        self.assertEqual(allocate.allocation.zero_argument, 0)
        self.assertEqual(allocate.allocation.zero_mask, 64)
        self.assertEqual(allocate.allocation.initialization, 'argument_flag')
        self.assertEqual(allocate.ownership, release.ownership)
        self.assertEqual(release.release.success, 'eax_zero')
        self.assertEqual(release.argument, 0)
        self.assertEqual(release.argument_count, 1)
        self.assertIn('{ 0U, 64U }', allocation_tables((allocate, release)))
        with self.assertRaises(CandidateRuntimeError):
            allocation_tables((replace(allocate, ownership=None),))
        # Native admission is not sufficient to remove the portable proof blocker.
        for symbol in ('GlobalAlloc', 'GlobalFree'):
            with self.assertRaisesRegex(BisimulationRefinementError, 'proof_service_lifetime_effect_unsupported'):
                checked_proof_external_effect_contract({'provider_kind': 'external_call',
                    'service_id': symbol, 'external_effect_contract': profile(symbol)})

    def test_malformed_allocation_metadata_fails_at_both_authority_readers(self):
        payload = profile('GlobalAlloc')
        receipt = checked(payload).payload()
        bads = (None, {}, {'argument_masks': [], 'initialization': {'kind': 'host_magic'}},
            {'argument_masks': [{'argument_index': True, 'allowed_mask': 64}],
             'initialization': {'kind': 'zero'}},
            {'argument_masks': [{'argument_index': 2, 'allowed_mask': 64}],
             'initialization': {'kind': 'zero'}},
            {'argument_masks': [{'argument_index': 0, 'allowed_mask': 64}],
             'initialization': {'kind': 'argument_flag', 'argument_index': 0, 'mask': 2}},
            {'argument_masks': [{'argument_index': 0, 'allowed_mask': 64}] * 2,
             'initialization': {'kind': 'zero'}})
        for bad in bads:
            with self.subTest(bad=bad):
                changed = copy.deepcopy(payload)
                changed['result_register_relations'][0]['allocation'] = bad
                with self.assertRaises(CanonicalRuntimeError): checked(changed)
                changed_receipt = copy.deepcopy(receipt)
                changed_receipt['result_register_relations'][0]['allocation'] = bad
                with self.assertRaises(CheckedExternalSiteContractError):
                    parse_checked_external_site_contract(changed_receipt)
        for field, value in (('world_effect', 'none'), ('ownership', None), ('relation', 'related_word')):
            changed = copy.deepcopy(payload)
            destination = changed if field == 'world_effect' else changed['result_register_relations'][0]
            destination[field] = value
            with self.assertRaises(CanonicalRuntimeError): checked(changed)

    def test_profile_loader_rejects_unchecked_flag_contract(self):
        source = json.loads((ROOT / 'profiles/pe32-kernel32-runtime-v1.json').read_text())
        row = next(row for row in source['machine_import_signatures'] if row['import']['symbol'] == 'GlobalAlloc')
        row['result_register_relations'][0]['allocation']['argument_masks'][0]['allowed_mask'] = -1
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'profile.json'
            path.write_text(json.dumps(source))
            with self.assertRaises(MachineImportProfileError): load_machine_import_profile_set([path])


class AllocationAdmissionTests(unittest.TestCase):
    def check(self, body, *, mutant=None):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        allocate, release = global_rules()
        native_rules = (replace(allocate, target_iat_rva=None, target_catalog_index=None),
                        replace(release, target_iat_rva=None, target_catalog_index=None), heap_rules()[2])
        setup = '''
static spx_call_status global_alloc(uint32_t flags, uint32_t size, uint32_t pointer) {
  select_site(0U, flags, 0U); snapshot.arguments[1] = size;
  spx_call_status status = spx_native_validate_release_calls(&event, &snapshot);
  if (status != SPX_CALL_OK) return status;
  ++host_calls; output.eax = pointer;
  return spx_native_record_range_allocation(&spx_native_external_range_rules[0], &event, &snapshot, &output);
}
static spx_call_status global_free(uint32_t pointer, uint32_t result) {
  return release(1U, 0U, pointer, result);
}
'''
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'allocation.c'
            path.write_text(ownership_fixture(setup + body, mutant=mutant, native_rules=native_rules))
            return run_cbmc_properties(command=[cbmc, str(path), '--json-ui', '--trace',
                '--unwind', '16', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check', '--sat-solver', 'cadical'], timeout_seconds=30)

    def test_symbolic_flags_are_checked_before_host_call(self):
        body = '''
uint32_t nondet_flags(void);
int main(void) {
  uint32_t flags = nondet_flags();
  spx_call_status status = global_alloc(flags, 16U, 4096U);
  if ((flags & ~64U) != 0U) {
    __CPROVER_assert(status == SPX_CALL_UNIMPLEMENTED && host_calls == 0U,
        "unsupported allocation flags cannot reach host");
    __CPROVER_assert(spx_native_diagnostic_reason == 0x2221U, "flag diagnostic");
  } else {
    __CPROVER_assert(status == SPX_CALL_OK && host_calls == 1U, "fixed allocation admitted");
  }
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check(body, mutant='allocation_mask')
        self.assertEqual(result['status'], 'violated', result.get('detail'))

    def test_null_zero_size_and_release_failure_preserve_correct_lifetimes(self):
        result = self.check('''
int main(void) {
  __CPROVER_assert(global_alloc(64U, 16U, 0U) == SPX_CALL_OK, "null allocation result");
  __CPROVER_assert(spx_native_context_value.external_range_count == 0U, "null registers nothing");
  __CPROVER_assert(global_alloc(64U, 0U, 4096U) == SPX_CALL_OK, "zero-size fixed instance");
  __CPROVER_assert(spx_native_context_value.external_range_count == 1U, "instance registered");
  __CPROVER_assert(global_free(4096U, 4096U) == SPX_CALL_OK, "failed release preserves instance");
  __CPROVER_assert(spx_native_context_value.external_range_count == 1U, "failure keeps lifetime");
  __CPROVER_assert(global_free(4096U, 0U) == SPX_CALL_OK, "successful release");
  __CPROVER_assert(spx_native_context_value.external_range_count == 0U, "success retires instance");
  __CPROVER_assert(global_alloc(0U, 16U, 4096U) == SPX_CALL_OK, "fixed address reuse");
  uint32_t calls = host_calls;
  __CPROVER_assert(release(2U, 0U, 4096U, 0U) == SPX_CALL_UNIMPLEMENTED,
      "CRT cannot release global allocation");
  __CPROVER_assert(host_calls == calls, "family mismatch rejected before host");
}
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
