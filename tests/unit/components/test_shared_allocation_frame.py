"""Conditional framed consumers retain unrelated live and released objects."""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_image_frame import allocation_frame_source, authority_extension
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from .shared_summary_fixture import check_shared_pair
from .test_bisimulation_reference_authority import authority_payload
from .test_bisimulation_allocation_authority import allocation_authority

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'profiles/pe32-user32-resource-text-runtime-v1.json',
    'nix/jq/strong-contextual-proof.jq')}

SETUP = '''
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world,0x600000U,16U,1U,0U,0U)==SPX_BOUNDARY_OK,"exact live allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world,0x600000U,16U,1U,0U,0U)==SPX_BOUNDARY_OK,"source live allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world,0x700000U,8U,1U,0U,0U)==SPX_BOUNDARY_OK,"exact later allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world,0x700000U,8U,1U,0U,0U)==SPX_BOUNDARY_OK,"source later allocation");
  __CPROVER_assert(spx_proof_release_allocation(&spx_exact_world,0x700000U,1U,0U,1U)==SPX_BOUNDARY_OK,"exact release");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world,0x700000U,1U,0U,1U)==SPX_BOUNDARY_OK,"source release");
  uint32_t heap_offset=spx_nondet_u32(), heap_index=spx_nondet_u32();
  __CPROVER_assume(heap_offset<16U && heap_index<2U);
  spx_proof_allocation heap_before=spx_source_world.allocations[heap_index];
  uint8_t heap_byte=spx_proof_source_byte(0x600000U+heap_offset);
'''
ADMISSION = '''
  __CPROVER_assert(spx_proof_image_private_allocation_frame(&spx_exact_world,SPX_PROOF_IMAGE_BASE,0x20000U,
      spx_exact_world.private_low,spx_exact_world.private_high),"foreign allocation frame");
'''
PRESERVATION = '''
  __CPROVER_assert(spx_source_world.allocation_count==2U && spx_exact_world.allocation_count==2U,"allocation history retained");
  __CPROVER_assert(spx_proof_allocation_instance_equal(&heap_before,&spx_source_world.allocations[heap_index]),"foreign identity and lifetime unchanged");
  __CPROVER_assert(spx_proof_source_byte(0x600000U+heap_offset)==heap_byte,"foreign current contents unchanged");
  __CPROVER_assert(!spx_proof_allocation_reference_live(&spx_source_world,0x700000U,8U,3U,0U),"released reference remains expired");
'''


class SharedAllocationFrameTests(unittest.TestCase):
    def test_authority_extension_preserves_image_meaning_in_both_readers(self):
        child = authority_payload()
        parent = MachineObjectAuthorityV2(machine_backend=child['machine_backend'], bindings=child['bindings'],
            rules=[*child['rules'], *allocation_authority()['rules']]).to_payload()
        program = (Path(__file__).resolve().parents[3]/TESTKIT['resources'][2]).read_text()
        for mutation in ('none', 'image-permission', 'foreign-alias', 'binding', 'missing-image', 'static-extension'):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(parent)
                image = next(row for row in changed['rules'] if row['kind'] == 'image')
                allocation = next(row for row in changed['rules'] if row['kind'] == 'external')
                if mutation == 'image-permission': image['permissions'] ^= 2
                elif mutation == 'foreign-alias': allocation.update(domain=image['domain'], object=image['object'])
                elif mutation == 'binding': changed['bindings']['original_pe_sha256'] = 'f' * 64
                elif mutation == 'missing-image': changed['rules'].remove(image)
                elif mutation == 'static-extension': allocation.update(kind='image', lifetime='image')
                expected = mutation == 'none'
                self.assertEqual(authority_extension(child, changed), expected)
                query = subprocess.run([shutil.which('jq'), '-e', program + '\nspx_image_authority_extension(.child; .parent)'],
                    input=json.dumps({'child': child, 'parent': changed}), text=True, capture_output=True)
                self.assertEqual(query.returncode == 0, expected, query.stderr)

    def test_two_consumers_preserve_foreign_contents_identity_and_release_history(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check_shared_pair(Path(directory), framed_allocations=True,
                mutation=SETUP + ADMISSION, after_calls=PRESERVATION)
            self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_a_dead_overlapping_record_is_not_an_unrelated_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check_shared_pair(Path(directory), framed_allocations=True,
                mutation=SETUP + 'spx_exact_world.allocations[1].base=0x413d20U;\n' + ADMISSION)
            self.assertEqual(result['status'], 'violated', result.get('detail'))
            self.assertIn('foreign allocation frame', result.get('detail', ''))

    def test_lifetime_disagreement_cannot_hide_behind_matching_image_views(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check_shared_pair(Path(directory), framed_allocations=True,
                mutation=SETUP + ADMISSION + 'spx_source_world.allocations[1].generation+=1U;\n')
            self.assertEqual(result['status'], 'violated', result.get('detail'))

    def test_frame_check_does_not_copy_or_enumerate_the_allocation_table(self):
        small, large = allocation_frame_source(2), allocation_frame_source(1000)
        self.assertEqual(small.replace('UINT32_C(2)', 'UINT32_C(1000)'), large)
        self.assertNotIn('for (', large)
