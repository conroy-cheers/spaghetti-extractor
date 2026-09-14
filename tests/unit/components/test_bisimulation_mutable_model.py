"""Actual solver checks for mutable bytes, alias transport and write frames."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_readonly_model import (
    fixed_mutable_summary_operations, fixed_readonly_summary_operations, render_mutable_source_model,
)
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from tests.unit.components.test_bisimulation_readonly_model import check_model, fixed_readonly_bundle


TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}
COPY = '''
  (void)context;
  if (count > left->extent || count > right->extent) return 0;
  for (uint32_t i=0; i<count; ++i) {
    uint8_t byte;
    if (spx_view_read_u8(right,i,&byte) || spx_view_write_u8(left,i,byte)) return 0;
  }
  return 1;
'''


def mutable_bundle(*, accesses=("read_write", "read"), extents=(2, 2)):
    intent = fixed_readonly_bundle(extents).intent
    payload = intent.to_payload()
    # Use the existing schema and lifecycle validator, not a hand-built model.
    for signature in payload["schema"]["signatures"]:
        if signature["id"] == "operation.compare":
            for value, access in zip(signature["parameters"], accesses):
                value["access"] = access
    for value, access in zip(payload["operations"][0]["source_values"], accesses):
        value["access"] = access
    return compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=intent.component_id,
        schema=BoundarySchemaV1.create(schema_id=intent.schema.schema_id, types=intent.schema.types,
                                      signatures=payload["schema"]["signatures"]),
        state=(), operations=payload["operations"], effects=(), services=(),
        protocol_states=intent.protocol_states, initial_protocol_state=intent.initial_protocol_state,
    ))


class MutableModelTests(unittest.TestCase):
    def check(self, body, *, bundle=None, **kwargs):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc")):
            self.skipTest("CBMC tools are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            return check_model(Path(directory), body, bundle=mutable_bundle() if bundle is None else bundle,
                               renderer=render_mutable_source_model, **kwargs)

    def test_shape_remains_separate_from_readonly(self):
        self.assertEqual(fixed_mutable_summary_operations(mutable_bundle()), ("compare",))
        self.assertIsNone(fixed_readonly_summary_operations(mutable_bundle()))
        self.assertIsNone(fixed_mutable_summary_operations(fixed_readonly_bundle()))
        self.assertIsNone(fixed_mutable_summary_operations(mutable_bundle(extents=(0x40000000, 1))))

    def test_loop_copies_current_bytes_with_overlap(self):
        for frame in (False, True):
            with self.subTest(frame=frame):
                result = self.check(COPY, frame=frame)
                self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_post_memory_is_checked_even_when_results_are_equal(self):
        result = self.check('uint8_t arbitrary; spx_view_write_u8(left,0,arbitrary); return 0;')
        self.assertEqual(result["status"], "violated")
        self.assertIn("spx-mutable-post-memory", result["detail"])

    def test_missing_initial_byte_correspondence_rejects(self):
        def unrelated_right(model):
            return model.replace(
                'spx_world_right->values[2U+i] = __CPROVER_uninterpreted_readonly_byte(spx_parameter_1_address+i);',
                'spx_world_right->values[2U+i] = (uint8_t)(1U ^ __CPROVER_uninterpreted_readonly_byte(spx_parameter_1_address+i));')
        result = self.check(COPY, model_transform=unrelated_right)
        self.assertEqual(result["status"], "violated")
        self.assertIn("spx-mutable-post-memory", result["detail"])

    def test_readonly_overlap_observes_current_writes(self):
        body = '''
          uint8_t byte;
          spx_view_write_u8(left,0,90);
          spx_view_read_u8(right,0,&byte);
          __CPROVER_assert(byte==90, "overlap sees current contents");
          return 0;
        '''
        def overlap(model):
            return model.replace('  spx_mutable_frame = spx_world_left;',
                '  __CPROVER_assume(spx_parameter_0_address == spx_parameter_1_address);\n'
                '  spx_mutable_frame = spx_world_left;')
        result = self.check(body, model_transform=overlap)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
        # Mutating the model to update only the first duplicate byte is unsound
        # even though the paired executions would agree with each other.
        def stale_alias(model):
            return overlap(model).replace('if (domain->world->addresses[j] == address+i) {\n        domain->world->values',
                'if (!found && domain->world->addresses[j] == address+i) {\n        domain->world->values')
        result = self.check(body, model_transform=stale_alias)
        self.assertEqual(result["status"], "violated")
        self.assertIn("overlap sees current contents", result["detail"])

    def test_restored_descriptor_and_context_writes_violate_frame(self):
        for body in (
            'context->state.reserved ^= 1; context->state.reserved ^= 1; return 0;',
            'spx_view_v5 *v=(spx_view_v5 *)left; v->extent ^= 1; v->extent ^= 1; return 0;',
        ):
            with self.subTest(body=body):
                result = self.check(body, frame=True)
                self.assertEqual(result["status"], "violated")
                self.assertIn("assignable", result["detail"])

    def test_readonly_permission_and_extent_failures_are_normal_outcomes(self):
        result = self.check('''
          __CPROVER_assert(spx_view_write_u8(right,0,1) != 0, "read-only grant rejects write");
          __CPROVER_assert(spx_view_write_u8(left,left->extent,1) != 0, "extent rejects write");
          return 0;
        ''')
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_descriptor_alias_and_scalar_domain_are_not_restricted_by_unwinding(self):
        for assertion in ('left != right', 'count <= 2U'):
            with self.subTest(assertion=assertion):
                result = self.check(f'__CPROVER_assert({assertion}, "open input domain"); return 0;',
                                    bundle=mutable_bundle(accesses=("read_write", "read_write")))
                self.assertEqual(result["status"], "violated")

    def test_nonprogress_loop_rejects(self):
        self.assertEqual(self.check('while (1) {} return 0;')["status"], "violated")
