"""Locally prepared allocation classes agree with independently lowered native sites."""

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_allocation_classes import require_allocation_class
from spaghetti_extractor.components.bisimulation_allocation_producers import allocation_producer_correspondence
from spaghetti_extractor.components.bisimulation_reference_authority import checked_reference_authority
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.semantic_providers.allocation_inputs import allocation_producer_inputs
from tests.unit.semantic_providers.test_allocation_inputs import inputs as preparation_inputs, rehash, transfer
from .test_bisimulation_allocation_calls import inputs as native_inputs

TESTKIT = {'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def shifted_inventory(original):
    inventory = copy.deepcopy(original)
    unrelated = copy.deepcopy(next(row for row in inventory['external_range_rules']
                                   if row['action'] == 'release_argument_range'))
    unrelated.update(contract_id='fixture:unrelated-release', contract_identity_sha256='a' * 64,
                     instruction_rva=0x8000)
    unrelated['ownership']['family'] = 'a.unrelated'
    unrelated['release']['ownership']['family'] = 'a.unrelated'
    inventory['external_range_rules'].insert(0, unrelated)
    for row in inventory['object_rules']:
        row['locator']['subject_rva'] += 1
    image = copy.deepcopy(inventory['object_rules'][0])
    image.update(id='image', domain=4, object=99, lifetime='image', extent_mode='fixed')
    image['locator'] = {'kind': 'image_rva', 'identity': 'image', 'offset': 0, 'subject_rva': 0}
    inventory['object_rules'].insert(0, image)
    repeated = copy.deepcopy(next(row for row in inventory['external_range_rules']
                                  if row['action'] == 'add_result_range'))
    repeated['instruction_rva'] = 0x9000
    inventory['external_range_rules'].append(repeated)
    return inventory


class AllocationClassRequirementTests(unittest.TestCase):
    def test_preparation_without_native_planning_binds_the_same_class_after_relocation(self):
        data = preparation_inputs()
        report = allocation_producer_inputs(**data)
        required = report['classes'][0]['class_requirement']
        self.assertEqual(required['class_sha256'], canonical_sha256_v3({
            key: value for key, value in required.items() if key != 'class_sha256'}))
        payload, original, _bindings = native_inputs()
        authority = checked_reference_authority(payload)
        native = allocation_producer_correspondence(authority, original)[0]
        relocated = allocation_producer_correspondence(authority, shifted_inventory(original))[0]
        require_allocation_class(required, native['class_requirement'])
        require_allocation_class(required, relocated['class_requirement'])
        self.assertNotEqual(native['native_object_selector'], relocated['native_object_selector'])
        self.assertNotEqual(native['native_family_selector'], relocated['native_family_selector'])
        self.assertNotEqual(native['native_producer_selector'], relocated['native_producer_selector'])
        self.assertEqual(len(relocated['native_site_selectors']), 2)
        self.assertEqual(native['class_requirement'], relocated['class_requirement'])
        self.assertFalse(report['authority'])
        self.assertFalse(report['producer_set_complete'])
        self.assertFalse(report['caller_ownership_proved'])

    def test_sites_and_unrelated_environment_changes_keep_class_identity_but_change_provenance(self):
        original = allocation_producer_inputs(**preparation_inputs())
        data = preparation_inputs(transfers=(transfer(), transfer(0x55d1), transfer(0x59aa, tail=True)))
        environment = data['resolved_environment']
        environment.update(status='incomplete', authority='none', blockers=[{'code': 'unrelated-import'}])
        data['resolved_environment'] = rehash(environment)
        changed = allocation_producer_inputs(**data)
        self.assertEqual(original['classes'][0]['class_requirement'], changed['classes'][0]['class_requirement'])
        self.assertNotEqual(original['producer_inputs_sha256'], changed['producer_inputs_sha256'])
        self.assertFalse(changed['native_runtime_inventory'])

    def test_rehashed_semantic_policy_mutations_cannot_match_native_class(self):
        required = allocation_producer_inputs(**preparation_inputs())['classes'][0]['class_requirement']
        payload, inventory, _bindings = native_inputs()
        actual = allocation_producer_correspondence(checked_reference_authority(payload), inventory)[0]['class_requirement']
        edits = (
            (('authority', 'domain'), 4), (('authority', 'object'), 56),
            (('authority', 'generation'), 2), (('authority', 'generation'), True),
            (('authority', 'extent'), 2), (('authority', 'permissions'), 1),
            (('authority', 'interior_pointers'), False), (('authority', 'extent_mode'), 'fixed'),
            (('authority', 'locator', 'offset'), 4), (('authority', 'locator', 'identity'), 'other'),
            (('contract_identity_sha256',), 'f' * 64), (('argument_words',), 3),
            (('effect', 'ownership', 'family'), 'other'), (('effect', 'ownership', 'owner_argument'), 0),
            (('effect', 'allocation', 'initialization'), {'kind': 'zero'}),
            (('effect', 'minimum_size'), 1), (('effect', 'size_value'), True),
            (('effect', 'nullable'), False),
        )
        for keys, value in edits:
            mutated = copy.deepcopy(required)
            target = mutated
            for key in keys[:-1]:
                target = target[key]
            self.assertTrue(type(target[keys[-1]]) is not type(value) or target[keys[-1]] != value, keys)
            target[keys[-1]] = value
            mutated['class_sha256'] = canonical_sha256_v3({k: v for k, v in mutated.items() if k != 'class_sha256'})
            with self.subTest(keys=keys), self.assertRaisesRegex(BisimulationRefinementError, 'local requirement'):
                require_allocation_class(mutated, actual)

    def test_native_effect_change_cannot_hide_behind_unchanged_contract_digest(self):
        required = allocation_producer_inputs(**preparation_inputs())['classes'][0]['class_requirement']
        payload, inventory, _bindings = native_inputs()
        producer = next(row for row in inventory['external_range_rules'] if row['action'] == 'add_result_range')
        producer['allocation']['initialization'] = {'kind': 'zero'}
        actual = allocation_producer_correspondence(checked_reference_authority(payload), inventory)[0]['class_requirement']
        with self.assertRaisesRegex(BisimulationRefinementError, 'local requirement'):
            require_allocation_class(required, actual)
