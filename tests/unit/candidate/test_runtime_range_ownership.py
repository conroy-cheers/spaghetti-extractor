"""Checked allocator families and heap owners protect native allocation lifetimes."""

import json
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.candidate.runtime_model import CandidateRuntimeError
from spaghetti_extractor.candidate.runtime_allocation_bindings import allocation_object_selectors
from spaghetti_extractor.candidate.runtime_range_ownership import ownership_fields
from spaghetti_extractor.candidate.runtime_range_release import release_tables, range_release_source
from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.candidate.runtime_external_range_validation import _external_range_rules
from spaghetti_extractor.candidate.runtime_canonical_errors import CanonicalRuntimeError
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.external.contracts import parse_checked_external_site_contract, CheckedExternalSiteContractError
from spaghetti_extractor.external.range_ownership import RangeOwnership, RangeOwnershipError, parse_range_ownership
from spaghetti_extractor.external.range_release import RangeRelease
from spaghetti_extractor.external.machine_import_profiles import load_machine_import_profile_set, MachineImportProfileError
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_runtime_allocation_lifetime import allocation_fixture_source, _function
from .test_runtime_allocation_sites import native_inventory, checked_site, authority as native_authority
from .test_runtime_canonical import _external_range_rule
from .test_runtime_range_release import checked, release_profile

TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": (
        "profiles/pe32-kernel32-lockstep-v1.json",
        "profiles/pe32-msvcrt-lockstep-v1.json",
    ),
}
ROOT = Path(__file__).resolve().parents[3]
HEAP = RangeOwnership("kernel32.heap", 0)
CRT = RangeOwnership("msvcrt.heap", None)


def rules():
    allocation = replace(_external_range_rule("fixture:allocator", 100),
        target_iat_rva=None, argument_count=3, ownership=HEAP, minimum_size=0,
        size_kind="argument", size_value=1, size_argument=2, nullable=True)
    release = replace(allocation, instruction_rva=200, action="release_argument_range",
        contract_id="fixture:release", argument=2, release=RangeRelease("eax_nonzero", (), HEAP))
    crt = replace(release, instruction_rva=300, argument_count=1, argument=0,
        contract_id="fixture:crt-free", ownership=CRT, release=RangeRelease("always", (), CRT))
    return allocation, release, crt


def ownership_fixture(body, *, mutant=None, native_rules=None, native_authorities=None):
    native_rules = rules() if native_rules is None else native_rules
    fields, families = ownership_fields(native_rules)
    release_fields, table = release_tables(native_rules)
    selectors, groups = ({}, {}) if native_authorities is None else allocation_object_selectors(
        native_authorities, native_rules)
    rows = []
    for index, rule in enumerate(native_rules):
        family, owner = fields[index]
        success, start, count = release_fields[index]
        rows.append(f'''{{ .instruction_rva={rule.instruction_rva}U,
            .argument_count={rule.argument_count}U, .argument={rule.argument or 0}U,
            .action={1 if rule.action == "add_result_range" else 2}U, .ownership_family={family}U,
            .ownership_owner_argument={owner}U, .release_success={success}U,
            .release_guard_start={start}U, .release_guard_count={count}U,
            .object_rule_selector={1 if native_authorities is None else selectors.get(index + 1, 0)}U,
            .allocation_group_selector={1 if native_authorities is None else groups.get(index + 1, index + 1)}U,
            .size_kind=2U, .size_value=1U, .size_argument={rule.size_argument or 0}U,
            .nullable=1U }}''')
    prelude = '''
typedef struct {
  uint32_t instruction_rva, target_iat_rva, target_catalog_index;
  uint32_t argument_base_offset, argument_count, argument, action;
  uint32_t release_success, release_guard_start, release_guard_count;
  uint32_t ownership_family, ownership_owner_argument;
  uint32_t object_rule_selector, allocation_group_selector;
  uint32_t register_index, nullable, size_kind, size_value, size_argument;
  uint32_t size_right_argument, minimum_size;
  uint32_t termination_unit_bytes, termination_zero_units, termination_max_units;
} spx_native_external_range_rule;
static spx_native_external_range_rule spx_native_external_range_rules[] = {
''' + ',\n'.join(rows) + f'''\n}};
static const uint32_t spx_native_external_range_rule_count = {len(native_rules)}U;
static const uint32_t spx_native_ownership_family_count = {families}U;
''' + '''
static uint32_t spx_native_external_range_rule_matches(
    const spx_native_external_range_rule *rule, const spx_call_event *event) {
  __CPROVER_assert(event->kind != SPX_CALL_INDIRECT, "fixture uses direct sites");
  return rule->instruction_rva == event->instruction_rva;
}
static uint32_t spx_native_zero_run_extent(uint32_t pointer, uint32_t unit,
    uint32_t zeros, uint32_t maximum, uint32_t *size) {
  __CPROVER_assert(0, "heap allocation has argument extent, never a terminator scan");
  return 0U;
}
'''
    core = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=()))
    source = range_release_source()
    for condition, name in (("range->ownership_owner != owner", "owner"),
                            ("range->ownership_family != rule->ownership_family", "family"),
                            ("(observed & ~guard->allowed_mask) != 0U", "allocation_mask")):
        if mutant == name:
            assert condition in source
            source = source.replace(condition, "0")
    names = ("spx_native_external_argument", "spx_native_state_register",
             "spx_native_range_size", "spx_native_add_external_range_for_rule",
             "spx_native_record_range_allocation")
    setup = '''
static spx_call_event event;
static spx_external_call_snapshot snapshot;
static spx_machine_state output;
static uint32_t host_calls;
static void select_site(uint32_t index, uint32_t owner, uint32_t value) {
  event.instruction_rva = spx_native_external_range_rules[index].instruction_rva;
  snapshot.instruction_rva = event.instruction_rva;
  snapshot.argument_count = spx_native_external_range_rules[index].argument_count;
  snapshot.arguments[0] = owner; snapshot.arguments[1] = 0U;
  snapshot.arguments[2] = value;
}
static spx_call_status add(uint32_t owner, uint32_t pointer, uint32_t size) {
  select_site(0U, owner, size); output.eax = pointer;
  return spx_native_record_range_allocation(&spx_native_external_range_rules[0],
      &event, &snapshot, &output);
}
static spx_call_status release(uint32_t index, uint32_t owner, uint32_t pointer, uint32_t result) {
  select_site(index, owner, pointer);
  if (spx_native_external_range_rules[index].argument == 0U) snapshot.arguments[0] = pointer;
  spx_call_status status = spx_native_validate_release_calls(&event, &snapshot);
  if (status != SPX_CALL_OK) return status;
  ++host_calls; output.eax = result;
  return spx_native_apply_range_release(&spx_native_external_range_rules[index],
      &event, &snapshot, &output);
}
'''
    fixture = allocation_fixture_source(prelude + table + source +
        ''.join(_function(core, name) for name in names) + setup + body)
    if native_authorities is not None:
        start = fixture.index('static const spx_native_object_authority_rule spx_native_object_authority_rules[] = {')
        end = fixture.index('static spx_native_context spx_native_context_value;', start)
        table = ',\n'.join('  {' + ', '.join((json.dumps(rule.identity),
            f'{rule.domain}ULL', f'{rule.object_id}ULL', f'{rule.generation}ULL',
            f'{rule.extent}U', f'{rule.permissions}U', f'{rule.locator_code}U',
            f'{rule.locator_offset}U', f'{rule.locator_subject_rva}U',
            f'{int(rule.interior_pointers)}U', f'{rule.extent_mode_code}U')) + '}'
            for rule in native_authorities)
        fixture = fixture[:start] + ('static const spx_native_object_authority_rule '
            'spx_native_object_authority_rules[] = {\n' + table + '\n};\n'
            f'static const uint32_t spx_native_object_authority_rule_count = {len(native_authorities)}U;\n') + fixture[end:]
        return fixture
    return fixture.replace('16U, 3U, 5U, 0U, 7U, 1U, 0U}', '16U, 3U, 5U, 0U, 1U, 1U, 0U}')


class RangeOwnershipContractTests(unittest.TestCase):
    def test_release_ownership_survives_active_codec_and_cannot_be_dropped(self):
        profile = release_profile()
        profile['world_effect_release']['ownership'] = HEAP.payload()
        contract = checked(profile)
        parsed = parse_checked_external_site_contract(contract.payload())
        self.assertEqual(parsed.world_effect_release.ownership, HEAP)
        self.assertEqual(parsed.profile_effect_payload()['world_effect_release'], profile['world_effect_release'])
        allocation, release, _ = rules()
        for bad in (replace(release, ownership=None), replace(release, ownership=CRT)):
            with self.assertRaisesRegex(CandidateRuntimeError, 'disagree'):
                ownership_fields((allocation, bad))
        self.assertEqual(ownership_fields(rules()), ([(1, 1), (1, 1), (2, 0)], 2))

    def test_owned_allocation_survives_checked_inventory_and_runtime_lowering(self):
        site = checked_site(0)
        payload = site.checked_external_contract.payload()
        payload['result_register_relations'][0]['ownership'] = HEAP.payload()
        contract = parse_checked_external_site_contract(payload)
        site = replace(site, checked_external_contract=contract)
        result, _, blockers = _external_range_rules(native_inventory([site]), None,
            resolved_environment_sha256='d' * 64)
        self.assertEqual(blockers, ())
        allocation = next(r for r in result if r.action == 'add_result_range')
        self.assertEqual(allocation.ownership, HEAP)
        self.assertEqual(allocation.payload()['ownership'], HEAP.payload())

    def test_malformed_ownership_rejected_by_checked_consumers(self):
        for bad in ({}, {'family': 'heap'}, {'family': '', 'owner_argument': None},
                    {'family': 'Heap', 'owner_argument': None},
                    {'family': 'heap', 'owner_argument': True},
                    {'family': 'heap', 'owner_argument': 3},
                    {'family': 'heap', 'owner_argument': -1}):
            with self.subTest(bad=bad):
                with self.assertRaises(RangeOwnershipError):
                    parse_range_ownership(bad, argument_words=3, context='test')
                profile = release_profile()
                profile['world_effect_release']['ownership'] = bad
                with self.assertRaises(CanonicalRuntimeError): checked(profile)
                payload = checked(release_profile()).payload()
                payload['world_effect_release']['ownership'] = bad
                with self.assertRaises(CheckedExternalSiteContractError):
                    parse_checked_external_site_contract(payload)

    def test_real_profiles_keep_heap_and_crt_families_distinct(self):
        seen = {}
        for name in ('pe32-kernel32-lockstep-v1.json', 'pe32-msvcrt-lockstep-v1.json'):
            profiles = load_machine_import_profile_set([ROOT / 'profiles' / name])
            seen.update({identity.value: row.contract for identity, row in profiles.by_identity().items()})
        for name, owner in (('HeapAlloc', HEAP), ('malloc', CRT), ('calloc', CRT)):
            relation = next(r for r in seen[name]['result_register_relations'] if r['relation'] == 'dynamic_range_base')
            self.assertEqual(relation['ownership'], owner.payload())
            self.assertEqual(relation['minimum_size'], 0)
        for name, owner in (('HeapFree', HEAP), ('free', CRT)):
            self.assertEqual(seen[name]['world_effect_release']['ownership'], owner.payload())
        source = json.loads((ROOT / 'profiles/pe32-kernel32-lockstep-v1.json').read_text())
        row = next(r for r in source['machine_import_call_contracts'] if r['import']['symbol'] == 'HeapAlloc')
        row['result_register_relations'][0]['ownership']['owner_argument'] = 3
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'bad.json'
            path.write_text(json.dumps(source))
            with self.assertRaises(MachineImportProfileError): load_machine_import_profile_set([path])


class RangeOwnershipExecutionTests(unittest.TestCase):
    def check(self, body, *, mutant=None, native_authorities=None):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'ownership.c'
            path.write_text(ownership_fixture(body, mutant=mutant, native_authorities=native_authorities))
            return run_cbmc_properties(command=[cbmc, str(path), '--json-ui', '--trace',
                '--unwind', '6', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--sat-solver', 'cadical'], timeout_seconds=30)

    def test_empty_dynamic_instance_retains_identity_but_no_native_byte_access(self):
        rule = replace(native_authority(), extent=0, extent_mode='instance_remainder', locator_subject_rva=1)
        body = '''
int main(void) {
  __CPROVER_assert(add(77U, 4096U, 0U) == SPX_CALL_OK, "native empty allocation");
  spx_machine_reference_v1 reference;
  uint32_t address = 0U;
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value,4096U,0U,3U,
      0,0U,1U,&reference) == SPX_BOUNDARY_OK && reference.object != 0U && reference.extent == 0U,
      "native empty instance identity");
  __CPROVER_assert(spx_native_realize_reference(&spx_native_context_value,&reference,3U,0U,1U,&address)
      == SPX_BOUNDARY_OK && address == 4096U, "native empty identity round trip");
  spx_machine_reference_v1 rejected;
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value,4096U,1U,1U,
      0,0U,1U,&rejected) != SPX_BOUNDARY_OK, "empty instance grants no byte authority");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value,4096U,0U,1U,
      0,0U,0U,&rejected) != SPX_BOUNDARY_OK, "empty instance requires end permission");
  __CPROVER_assert(release(1U,77U,4096U,1U) == SPX_CALL_OK, "release native empty instance");
  __CPROVER_assert(spx_native_realize_reference(&spx_native_context_value,&reference,3U,0U,1U,&address)
      != SPX_BOUNDARY_OK, "released empty native identity expires");
  __CPROVER_assert(add(77U,4096U,8U) == SPX_CALL_OK, "reuse empty native address");
  __CPROVER_assert(spx_native_realize_reference(&spx_native_context_value,&reference,3U,0U,1U,&address)
      != SPX_BOUNDARY_OK, "address reuse does not revive empty native identity");
}
'''
        result = self.check(body, native_authorities=[rule])
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_wrong_owner_and_family_rejected_before_host_call(self):
        body = '''
int main(void) {
  uint32_t address;
  __CPROVER_assert(add(77U, 4096U, 16U) == SPX_CALL_OK, "heap allocation");
  spx_machine_reference_v1 old = borrow(4100U);
  __CPROVER_assert(release(1U, 88U, 4096U, 1U) == SPX_CALL_UNIMPLEMENTED, "wrong heap rejected");
  __CPROVER_assert(spx_native_diagnostic_reason == 0x2212U, "wrong heap diagnostic");
  __CPROVER_assert(release(2U, 0U, 4096U, 1U) == SPX_CALL_UNIMPLEMENTED, "CRT cannot free heap allocation");
  __CPROVER_assert(spx_native_diagnostic_reason == 0x2211U, "wrong family diagnostic");
  __CPROVER_assert(release(1U, 77U, 4100U, 1U) == SPX_CALL_UNIMPLEMENTED, "interior free rejected");
  __CPROVER_assert(release(1U, 77U, 8192U, 1U) == SPX_CALL_UNIMPLEMENTED, "untracked free rejected");
  spx_native_external_range_rules[2].ownership_family = 0U;
  __CPROVER_assert(release(2U, 0U, 4096U, 1U) == SPX_CALL_UNIMPLEMENTED, "unowned contract cannot free owned range");
  __CPROVER_assert(host_calls == 0U, "all rejected before host invocation");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_OK, "rejections preserve origin");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result)
        for mutant in ('owner', 'family'):
            with self.subTest(mutant=mutant):
                self.assertEqual(self.check(body, mutant=mutant)['status'], 'violated')

    def test_release_failure_and_reuse_preserve_correct_lifetimes(self):
        body = '''
int main(void) {
  uint32_t address;
  __CPROVER_assert(add(77U, 4096U, 16U) == SPX_CALL_OK, "first allocation");
  spx_machine_reference_v1 old = borrow(4100U);
  __CPROVER_assert(add(77U, 8192U, 16U) == SPX_CALL_OK, "unrelated allocation");
  spx_machine_reference_v1 other = borrow(8196U);
  __CPROVER_assert(release(1U, 77U, 4096U, 0U) == SPX_CALL_OK, "failed host release recorded");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_OK, "failure keeps origin live");
  __CPROVER_assert(release(1U, 77U, 4096U, 1U) == SPX_CALL_OK, "successful release");
  __CPROVER_assert(add(88U, 4096U, 16U) == SPX_CALL_OK, "new heap reuses address");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "old origin stays expired");
  __CPROVER_assert(realize(other, &address) == SPX_BOUNDARY_OK, "unrelated origin stays live");
  __CPROVER_assert(release(1U, 77U, 4096U, 1U) == SPX_CALL_UNIMPLEMENTED, "previous heap cannot release new allocation");
  __CPROVER_assert(release(1U, 88U, 4096U, 1U) == SPX_CALL_OK, "new heap can release");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result)

    def test_null_zero_size_overlap_and_owner_snapshot(self):
        body = '''
int main(void) {
  spx_machine_reference_v1 ref;
  __CPROVER_assert(add(77U, 0U, 0xffffffffU) == SPX_CALL_OK, "null allocation grants nothing");
  __CPROVER_assert(spx_native_context_value.external_range_count == 0U, "no null range");
  __CPROVER_assert(add(77U, 4096U, 0U) == SPX_CALL_OK, "track non-null zero-size allocation");
  __CPROVER_assert(spx_native_context_value.external_range_count == 1U, "zero-size lifetime exists");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4096U, 1U, 1U,
      0, 0U, 0U, &ref) != SPX_BOUNDARY_OK, "zero-size allocation grants no byte access");
  __CPROVER_assert(release(1U, 88U, 4096U, 1U) == SPX_CALL_UNIMPLEMENTED, "zero-size allocation has owner");
  __CPROVER_assert(release(1U, 77U, 4096U, 1U) == SPX_CALL_OK, "zero-size allocation can be released");
  __CPROVER_assert(add(77U, 4096U, 16U) == SPX_CALL_OK, "live range");
  __CPROVER_assert(add(88U, 4100U, 16U) == SPX_CALL_UNIMPLEMENTED, "overlapping owned range rejected");
  __CPROVER_assert(spx_native_add_external_range(4096U, 16U, 0U, 1U, 0U, 0U)
      == SPX_CALL_UNIMPLEMENTED, "unowned registration cannot erase ownership");
  select_site(0U, 77U, 16U); snapshot.argument_count = 2U;
  __CPROVER_assert(spx_native_validate_release_calls(&event, &snapshot) == SPX_CALL_UNIMPLEMENTED,
      "allocation owner frame checked before call");
  __CPROVER_assert(release(1U, 77U, 0U, 1U) == SPX_CALL_OK, "null release needs no allocation");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result)
