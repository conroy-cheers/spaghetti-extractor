"""Repeated checked allocator sites share authority without merging lifetimes."""

import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.module_runtime_plan import NativeExternalSite, normalized_external_site_inventory_v2
from spaghetti_extractor.candidate.runtime_allocation_bindings import (
    _bind_dynamic_external_object_rules, allocation_object_selectors,
)
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.candidate.runtime_external_range_validation import _external_range_rules
from spaghetti_extractor.candidate.runtime_model import CandidateRuntimeError, NativeObjectAuthorityRule
from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_runtime_allocation_lifetime import allocation_fixture_source, _function
from .test_runtime_canonical import _external_range_rule

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def authority():
    return NativeObjectAuthorityRule(identity="allocation", domain=3, object_id=55,
        generation=1, extent=16, permissions=3, lifetime="allocation",
        locator_kind="external_allocation", locator_identity="fixture:allocator",
        locator_offset=0, locator_subject_rva=0, interior_pointers=True)


def producer_sites():
    return tuple(replace(_external_range_rule("fixture:allocator", rva),
                         target_iat_rva=None, contract_identity_sha256="a" * 64)
                 for rva in (0x55D1, 0x5838))


def native_inventory(sites):
    catalog, domains, callbacks, rows, _ = normalized_external_site_inventory_v2(tuple(sites))
    return {"external_target_contracts": catalog, "external_contract_domains": domains,
            "callback_target_domains": callbacks, "external_sites": rows,
            "import_bindings": [], "implementation_dispatch_receipt": {"reachability": {"status": "complete"}}}


def checked_site(index, profile_sha="a" * 64):
    rva = (0x55D1, 0x5838)[index]
    profile = {"id": "fixture:allocator", "abi_template": "pe32-stdcall-v1",
               "arity": {"kind": "fixed", "words": 2}, "memory_effect": "none",
               "world_effect": "dynamicRanges", "result_register_relations": [{
                   "register": "eax", "relation": "dynamic_range_base",
                   "size": {"kind": "argument", "argument": 1, "scale": 1},
                   "minimum_size": 1, "nullable": True,
               }]}
    checked = _checked_contract(row={
        "identity": {"dll": "fixture.dll", "symbol": "allocate", "ordinal": None},
        "boundary": {}, "contract": {"payload": profile, "profile_id": "fixture",
            "profile_sha256": profile_sha, "entry_key": "contracts", "entry_index": 0},
    }, call=SimpleNamespace(argument_nodes=(index * 2, index * 2 + 1), instruction_rva=rva),
       escape_index={})
    return NativeExternalSite(id=index, transfer_id=f"semantic-transfer:fixture-{index}",
        event_index=0, instruction_rva=rva, return_rva=rva+6,
        source_instruction_sha256="b" * 64, site_kind="direct_import",
        dll="fixture.dll", symbol="allocate", ordinal=None, disposition="returns_here",
        iat_rva=0x3000, transfer_sha256="c" * 64,
        abi_metadata_sha256=canonical_sha256_v3(checked.profile_effect_payload()),
        checked_external_contract=checked, target_resolution_evidence={
            "kind": "resolved-external-environment-v1", "sha256": "d" * 64,
            "identity": ["fixture.dll", "symbol", "allocate"],
        })


def allocation_sites_fixture(body, *, mutant=False):
    rules = producer_sites()
    blockers = []
    bound = _bind_dynamic_external_object_rules([authority()], rules, blockers)
    assert not blockers, blockers
    selectors, groups = allocation_object_selectors(bound, rules)
    rows = "\n".join(f"  {{ {rule.instruction_rva}U, 1U, {selectors[index]}U, {groups[index]}U }},"
                     for index, rule in enumerate(rules, 1))
    prelude = '''
typedef struct {
  uint32_t instruction_rva, action, object_rule_selector, allocation_group_selector;
} spx_native_external_range_rule;
static spx_native_external_range_rule spx_native_external_range_rules[] = {
''' + rows + '''
};
static const uint32_t spx_native_external_range_rule_count = 2U;
'''
    core = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=()))
    function = _function(core, "spx_native_add_external_range_for_rule")
    if mutant:
        function = function.replace('object_rule->locator_subject_rva != rule->allocation_group_selector',
                                    'object_rule->locator_subject_rva != external_range_rule_selector')
    fixture = allocation_fixture_source(prelude + function + body)
    # This fixture's authority is bound to the first member of the two-site group.
    return fixture.replace('16U, 3U, 5U, 0U, 7U, 1U, 0U}', '16U, 3U, 5U, 0U, 1U, 1U, 0U}')


class AllocationSiteBindingTests(unittest.TestCase):
    def test_real_checked_inventory_groups_repeated_sites_and_preserves_site_frames(self):
        sites = [checked_site(0), checked_site(1)]
        self.assertNotEqual(sites[0].checked_external_contract.arguments,
                            sites[1].checked_external_contract.arguments)
        rules, _, blocked = _external_range_rules(native_inventory(sites), None,
                                                  resolved_environment_sha256="d" * 64)
        self.assertEqual(blocked, ())
        producers = [r for r in rules if r.action == "add_result_range"]
        self.assertEqual(len(producers), 2)
        self.assertEqual(producers[0].contract_identity_sha256, producers[1].contract_identity_sha256)
        self.assertEqual(len(producers[0].contract_identity_sha256), 64)
        blockers = []
        bound = _bind_dynamic_external_object_rules([authority()], rules, blockers)
        self.assertEqual(blockers, [])
        selectors, groups = allocation_object_selectors(bound, rules)
        indexes = [i for i,r in enumerate(rules, 1) if r.action == "add_result_range"]
        self.assertEqual(selectors, dict.fromkeys(indexes, 1))
        self.assertEqual(groups, dict.fromkeys(indexes, indexes[0]))
        self.assertEqual([r.instruction_rva for r in producers], [0x55D1, 0x5838])
        # A different physical call frame does not change the allocation contract.
        framed = (producer_sites()[0], replace(producer_sites()[1], argument_base_offset=4))
        blockers = []
        _bind_dynamic_external_object_rules([authority()], framed, blockers)
        self.assertEqual(blockers, [])
        self.assertEqual(framed[1].argument_base_offset, 4)

    def test_equal_display_ids_do_not_merge_distinct_checked_profile_bindings(self):
        rules, _, _ = _external_range_rules(native_inventory([checked_site(0), checked_site(1, "b" * 64)]),
                                            None, resolved_environment_sha256="d" * 64)
        blockers = []
        bound = _bind_dynamic_external_object_rules([authority()], rules, blockers)
        self.assertEqual(bound[0].locator_subject_rva, 0)
        self.assertIn("exact checked contract identity", blockers[0]["detail"])

    def test_missing_identity_conflicting_outputs_and_duplicate_sites_are_rejected(self):
        first, second = producer_sites()
        for altered in (replace(second, contract_identity_sha256=None),
                        replace(second, contract_identity_sha256=""),
                        replace(second, size_value=64),
                        replace(second, argument_count=2),
                        replace(second, action="add_result_pointee_ranges"),
                        replace(second, instruction_rva=first.instruction_rva, argument_base_offset=4)):
            with self.subTest(altered=altered):
                blockers = []
                bound = _bind_dynamic_external_object_rules([authority()], (first, altered), blockers)
                self.assertEqual(bound[0].locator_subject_rva, 0)
                self.assertEqual(blockers[0]["matching_range_rules"], 2)

    def test_ambiguous_authorities_and_stale_renderer_bindings_are_rejected(self):
        rules = producer_sites()
        blockers = []
        other = replace(authority(), identity="other", object_id=77)
        bound = _bind_dynamic_external_object_rules([authority(), other], rules, blockers)
        self.assertEqual([r.locator_subject_rva for r in bound], [0, 0])
        self.assertEqual(len(blockers), 2)
        stale = replace(authority(), locator_subject_rva=2)
        with self.assertRaisesRegex(CandidateRuntimeError, "stale"):
            allocation_object_selectors([stale], rules)
        with self.assertRaisesRegex(CandidateRuntimeError, "ambiguous"):
            allocation_object_selectors([replace(r, locator_subject_rva=1) for r in (authority(), other)], rules)


class AllocationSiteExecutionTests(unittest.TestCase):
    def check(self, body, *, mutant=False):
        cbmc = shutil.which("cbmc")
        if cbmc is None: self.skipTest("CBMC unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "allocation-sites.c"
            source.write_text(allocation_sites_fixture(body, mutant=mutant))
            return run_cbmc_properties(command=[cbmc, str(source), "--json-ui", "--trace",
                "--unwind", "6", "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=30)

    def test_two_sites_share_authority_but_keep_distinct_live_and_expired_instances(self):
        body = '''
int main(void) {
  uint32_t address;
  __CPROVER_assert(spx_native_add_external_range_for_rule(&spx_native_external_range_rules[0],
      4096U, 16U) == SPX_CALL_OK, "first site allocation");
  spx_machine_reference_v1 first = borrow(4100U);
  __CPROVER_assert(spx_native_add_external_range_for_rule(&spx_native_external_range_rules[1],
      8192U, 16U) == SPX_CALL_OK, "second site allocation");
  spx_machine_reference_v1 second = borrow(8196U);
  __CPROVER_assert(first.generation != second.generation, "distinct simultaneous allocation epochs");
  __CPROVER_assert(realize(first, &address) == SPX_BOUNDARY_OK, "first site remains live");
  __CPROVER_assert(spx_native_context_value.external_ranges[1].producer_rva == 22584U,
      "second site's physical provenance retained");
  __CPROVER_assert(spx_native_release_external_range(4096U, 123U) == SPX_CALL_OK, "release first site allocation");
  __CPROVER_assert(spx_native_add_external_range_for_rule(&spx_native_external_range_rules[1],
      4096U, 16U) == SPX_CALL_OK, "different site reuses address");
  __CPROVER_assert(realize(first, &address) == SPX_BOUNDARY_EXPIRED, "reuse cannot revive stale origin");
  __CPROVER_assert(realize(second, &address) == SPX_BOUNDARY_OK && address == 8196U,
      "unrelated second-site allocation remains live");
  spx_machine_reference_v1 fresh = borrow(4100U);
  __CPROVER_assert(realize(fresh, &address) == SPX_BOUNDARY_OK, "fresh cross-site origin resolves");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result)
        result = self.check(body, mutant=True)
        self.assertEqual(result['status'], 'violated', result)

    def test_corrupt_group_selector_does_not_register_an_allocation(self):
        body = '''
int main(void) {
  spx_native_external_range_rules[1].allocation_group_selector = 2U;
  __CPROVER_assert(spx_native_add_external_range_for_rule(&spx_native_external_range_rules[1],
      4096U, 16U) == SPX_CALL_UNIMPLEMENTED, "wrong group cannot issue authority");
  __CPROVER_assert(spx_native_context_value.external_range_count == 0U, "no range published");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result)
