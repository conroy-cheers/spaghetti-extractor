"""Owned call transitions use prepared classes without a final native inventory."""

import copy
import unittest
from dataclasses import fields, replace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_call_allocation import allocation_call_fragments
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.external.contracts import CheckedExternalContractBehavior, parse_checked_external_site_contract
from spaghetti_extractor.external.import_sites import bind_import_site
from spaghetti_extractor.external.resolved_contract import resolved_import_contract_behavior
from . import test_bisimulation_allocation_calls as allocation_calls
from .test_bisimulation_allocation_namespace import inputs
from . import test_machine_overlay_v5 as overlay_fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',
    'targets/gnu-hello/intent/interfaces-v5', 'targets/gnu-hello/intent/bindings-v5')}


def fragments(bindings, requirements):
    authority, _ = inputs()
    return allocation_call_fragments(specs=_proof_call_specs(bindings, allow_lifetime_effects=True),
        authority=authority, inventory=None, capacity=3, requirements=requirements)


class LocalAllocationCallTests(unittest.TestCase):
    def check(self, body, **options):
        _, requirements = inputs()
        return allocation_calls.AllocationCallTests.check(self, body, local_requirements=requirements, **options)

    def test_local_allocate_write_release_and_reuse(self):
        body = '''
  uint32_t pointer = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(pointer == 4096U);
  spx_proof_exact_write(0, pointer + 3U, 1U, 7U, &fault);
  __CPROVER_assert(!fault, "exact buffer write");
  __CPROVER_assume(invoke(1U, 0U, pointer, 0U) == 0U);
  __CPROVER_assume(invoke(1U, 1U, 64U, 8U) == pointer);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == pointer, "paired allocation");
  spx_proof_source_write(0, pointer + 3U, 1U, 7U, &fault);
  __CPROVER_assert(!fault, "source buffer write");
  __CPROVER_assert(invoke(0U, 0U, pointer, 0U) == 0U, "paired release");
  __CPROVER_assert(invoke(0U, 1U, 64U, 8U) == pointer, "paired reuse");
  __CPROVER_assert(spx_source_world.allocations[0].native_generation != spx_source_world.allocations[1].native_generation,
      "reuse keeps a fresh generation");
  __CPROVER_assert(spx_proof_source_read(0, pointer + 3U, 1U, &fault) == 0U && !fault,
      "new zeroed lifetime does not inherit retired writes");
'''
        self.check(body, typed_source=True)
        self.check(body, typed_source=True, typed_exact=True)
        self.check(body.replace('spx_proof_source_write(0, pointer + 3U, 1U, 7U,',
                               'spx_proof_source_write(0, pointer + 3U, 1U, 8U,'),
                   typed_source=True, failure='lifetime-typed-arguments')

    def test_local_null_allocation_and_failed_release(self):
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 0U);
  uint32_t pointer = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(pointer != 0U);
  __CPROVER_assume(invoke(1U, 0U, pointer, 0U) != 0U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 0U, "paired null");
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == pointer, "paired nonnull");
  __CPROVER_assert(invoke(0U, 0U, pointer, 0U) != 0U, "paired failed release");
  __CPROVER_assert(spx_source_world.allocation_count == 1U && spx_source_world.allocations[0].live,
      "null creates no instance and failure preserves live allocation");
''', typed_source=True, typed_exact=True)

    def test_missing_or_changed_site_class_and_effect_are_rejected(self):
        _, requirements = inputs()
        _, _, original = allocation_calls.inputs()
        for kind in ('missing-site', 'foreign-profile', 'effect', 'class-effect', 'empty-classes', 'frame', 'cleanup'):
            bindings, classes = copy.deepcopy(original), copy.deepcopy(requirements)
            site = bindings[0]['events'][0]['checked_external_contract']
            if kind == 'missing-site': del bindings[0]['events'][0]['checked_external_contract']
            if kind == 'foreign-profile': site['profile_binding']['profile_sha256'] = 'e' * 64
            if kind == 'effect': bindings[0]['external_effect_contract']['result_register_relations'][0]['nullable'] = False
            if kind == 'class-effect':
                classes[0]['effect']['nullable'] = False
                classes[0]['class_sha256'] = canonical_sha256_v3({k: v for k, v in classes[0].items() if k != 'class_sha256'})
            if kind == 'empty-classes': classes = []
            if kind == 'frame': bindings[0]['argument_offsets'] = [0]
            if kind == 'cleanup': bindings[0]['abi_template'] = 'pe32-cdecl-v1'
            with self.subTest(kind=kind), self.assertRaises(BisimulationRefinementError):
                fragments(bindings, classes)

    def test_valid_but_unmodeled_site_outcomes_do_not_become_ordinary_calls(self):
        _, requirements = inputs()
        _, _, original = allocation_calls.inputs()
        for kind in ('tail', 'terminates', 'nonlocal', 'protocol'):
            bindings = copy.deepcopy(original)
            site = parse_checked_external_site_contract(bindings[0]['events'][0]['checked_external_contract'])
            behavior = CheckedExternalContractBehavior(**{field.name: getattr(site, field.name)
                                                          for field in fields(CheckedExternalContractBehavior)})
            if kind == 'tail':
                site = bind_import_site(behavior, argument_nodes=(), tail_jump=True)
            if kind == 'terminates': site = replace(site, profile_disposition=kind)
            if kind in {'nonlocal', 'protocol'}:
                symbol = 'RtlUnwind' if kind == 'nonlocal' else 'UnhandledExceptionFilter'
                protocol = resolved_import_contract_behavior(allocation_calls.selected_row(symbol)).external_service_protocol
                behavior = replace(behavior, external_service_protocol=protocol,
                    argument_words=4 if kind == 'nonlocal' else 2,
                    profile_disposition='nonlocal' if kind == 'nonlocal' else 'returns')
                site = bind_import_site(behavior, argument_nodes=())
                bindings[0]['argument_offsets'] = list(range(0, 4 * site.argument_words, 4))
            self.assertEqual(parse_checked_external_site_contract(site.payload()).payload(), site.payload())
            bindings[0]['events'][0]['checked_external_contract'] = site.payload()
            bindings[0]['external_contract_identity_sha256'] = site.identity_sha256()
            with self.subTest(kind=kind), self.assertRaisesRegex(BisimulationRefinementError, 'direct CALL frame|outcome or protocol'):
                fragments(bindings, requirements)

    def test_overlay_derives_lifetime_site_from_its_selected_profile_and_transfer(self):
        # Exercise canonical production lowering with an explicit synthetic
        # three-word lifetime profiles. This does not qualify the fixture's source.
        unit = 'semantic-transfer:original-cutpoint-00008d6f-00008d7f'
        call = overlay_fixture._Call('external_call', 0x8d76, 0, None, 0, 0x8d7b,
            'msvcrt.dll', 'memcmp', None, (), (), (), ((0, 4, 0), (4, 4, 0), (8, 4, 0)))
        selected = overlay_fixture._external_contract({'dll': 'msvcrt.dll', 'symbol': 'memcmp', 'ordinal': None},
            abi_template='pe32-cdecl-v1', argument_words=3)
        selected['contract']['payload'].update(memory_effect='none', world_effect='dynamicRangeRelease',
            world_effect_argument=0, world_effect_release={'success': 'eax_zero', 'argument_equals': [],
                'ownership': {'family': 'fixture.heap', 'owner_argument': None}})
        allocation = copy.deepcopy(selected)
        payload = allocation['contract']['payload']
        del payload['world_effect_argument'], payload['world_effect_release']
        payload.update(world_effect='dynamicRanges', result_register_relations=copy.deepcopy(
            allocation_calls.selected_row()['contract']['payload']['result_register_relations']))
        payload['result_register_relations'][0]['size'] = {'kind': 'fixed', 'bytes': 16}
        for profile in (selected, allocation):
            with self.subTest(effect=profile['contract']['payload']['world_effect']):
                rendered = overlay_fixture._component_overlay('memory-regions-equal', call_by_unit={unit: (call,)},
                    resolved_external_environment=overlay_fixture._resolved_environment(profile))
                binding = rendered.entries[0]['service_bindings'][0]
                expected = overlay_fixture._checked_contract(row=profile, call=call, escape_index={})
                self.assertEqual(binding['events'][0]['checked_external_contract'], expected.payload())
                spec = _proof_call_specs([binding], allow_lifetime_effects=True)[0]
                self.assertEqual(spec['checked_external_contract'], expected.payload())
                self.assertEqual(spec['external_effect_contract'], expected.profile_effect_payload())
                self.assertEqual(spec['external_contract_identity_sha256'], expected.identity_sha256())

    def test_site_locations_do_not_change_the_shared_transition_identity(self):
        _, requirements = inputs()
        _, _, bindings = allocation_calls.inputs()
        event = copy.deepcopy(bindings[0]['events'][0])
        event.update(instruction_rva=0x8000, return_rva=0x8006)
        bindings[0]['events'].append(event)
        specs = _proof_call_specs(bindings, allow_lifetime_effects=True)
        self.assertEqual(specs[0]['spec_id'], specs[1]['spec_id'])
        fragments(bindings, requirements)
        event['checked_external_contract']['profile_binding']['profile_sha256'] = 'e' * 64
        with self.assertRaisesRegex(BisimulationRefinementError, 'selected behavior identity'):
            fragments(bindings, requirements)
