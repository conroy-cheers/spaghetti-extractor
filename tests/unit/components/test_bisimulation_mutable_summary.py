"""Conditional mutable post-memory composition in the existing sparse world."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_connected import render_connected_summary_wrapper
from spaghetti_extractor.components.bisimulation_evidence import _validate_model_and_shard_evidence
from tests.unit.components.test_bisimulation_mutable_model import mutable_bundle
from tests.unit.components.test_bisimulation_readonly_summary import check_memory_pair

TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


class MutableSummaryTests(unittest.TestCase):
    def check_pair(self, **kwargs):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc", "goto-instrument")):
            self.skipTest("CBMC contract tools are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            kwargs.setdefault("bundle", mutable_bundle(accesses=("read_write", "read_write")))
            return check_memory_pair(Path(directory), mutable=True, reference_permissions=3, **kwargs)

    def test_overlapping_read_alias_observes_paired_post_bytes_without_a_callee_body(self):
        result = self.check_pair(overlap=True, separate_overlay=True, bundle=mutable_bundle())
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
        self.assertFalse(result["callee_bodies_present"])

    def test_overlapping_writers_and_identical_descriptors_share_one_post_memory(self):
        for overlap in (False, True):
            with self.subTest(overlap=overlap):
                result = self.check_pair(overlap=overlap,
                    bundle=mutable_bundle(accesses=("read_write", "read_write")))
                self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_post_writes_cannot_hide_different_input_memory_or_descriptor_aliases(self):
        for options, detail in (({"mismatch_bytes": True}, "memory"), ({"mismatch_alias": True}, "input")):
            with self.subTest(options=options):
                result = self.check_pair(**options)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], f"spx-bisimulation-connected-summary-{detail}:0")

    def test_arbitrary_post_bytes_and_results_do_not_assume_unproved_facts(self):
        for options, detail in (({"unproved_post_byte": True}, "unproved mutable byte fact"),
                                ({"wrong_result": True}, "unproved result fact")):
            with self.subTest(options=options):
                result = self.check_pair(**options)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], detail)

    def test_body_omission_requires_fixed_views_and_checked_mutable_transport(self):
        with self.assertRaisesRegex(ValueError, "fixed views and checked transport"):
            render_connected_summary_wrapper(bundle=mutable_bundle(), operation_symbols={"compare": "compare"},
                summary_ids={"compare": 0}, body_free_mutable=True)

    def test_mutable_composition_checks_actual_write_transport(self):
        for fault, detail in (("runtime_writer", "runtime"),
                              ("writer_callback", "transport:memory-regions-equal:compare")):
            with self.subTest(fault=fault):
                result = self.check_pair(transport_fault=fault)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-mutable-" + detail)

    def test_extent_growth_does_not_expand_post_memory_into_python_generated_stores(self):
        small, large = (render_connected_summary_wrapper(bundle=mutable_bundle(extents=(extent, extent)),
            operation_symbols={"compare": "compare"}, summary_ids={"compare": 0},
            body_free_mutable=True, checked_mutable_transport=True) for extent in (2, 4096))
        self.assertEqual(small.count("post_runtime->write("), 1)
        self.assertEqual(large.count("post_runtime->write("), 1)
        self.assertLess(len(large) - len(small), 50)

    def test_conditional_rendering_cannot_select_a_provider_summary(self):
        fields = ("binding_intent_sha256", "implementation_sha256", "source_profile_sha256",
                  "qualification_sha256", "contextual_refinement_sha256", "proof_receipt_sha256",
                  "machine_overlay_sha256", "proof_overlay_sha256", "machine_overlay_entries_sha256")
        connected = {field: "a" * 64 for field in fields}
        connected.update(component_id="probe", trusted_adapter_lowering_receipt_sha256=None,
                         summary_strategy="mutable-body-free-experiment-v1", source_summary_certificate=None)
        with self.assertRaisesRegex(ValueError, "connected summary strategy is malformed"):
            _validate_model_and_shard_evidence(proof_plan={}, shard_results=[],
                models={"operation_models": [], "connected_components": [connected]})
