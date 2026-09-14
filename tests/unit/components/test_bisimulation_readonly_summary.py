"""Conditional read-only composition; these probes do not qualify providers."""
from __future__ import annotations

import json
import hashlib
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_connected import (
    _connected_replay_source, render_connected_summary_wrapper,
)
from spaghetti_extractor.components.bisimulation_reference_transport import (
    connected_reference_transport_source, readonly_connected_transport_source,
    readonly_overlay_transport_source,
    mutable_connected_transport_source, mutable_overlay_transport_source,
)
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.components.bisimulation_evidence import _validate_model_and_shard_evidence
from spaghetti_extractor.components.bisimulation_summary_contracts import readonly_summary_operations, scalar_summary_operations
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",),
}


def readonly_bundle():
    path = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
    intent = ComponentInterfaceIntentV1.parse(json.loads(path.read_text()))
    operations = [{**row, "allowed_service_ids": []} for row in intent.operations]
    return compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=intent.component_id, schema=intent.schema, state=(),
        operations=operations, effects=(), services=(),
        protocol_states=intent.protocol_states, initial_protocol_state=intent.initial_protocol_state,
    ))


def check_memory_pair(root: Path, *, mismatch_bytes=False, mismatch_alias=False,
                        null_view=False, overlap=False, wrong_result=False, bundle=None,
                        element_width=1, transport_fault=None, separate_overlay=False, reference_permissions=1,
                        mutable=False, unproved_post_byte=False):
    """Use the production memory observer and transport, with no callee body."""
    if bundle is None:
        if mutable:
            from tests.unit.components.test_bisimulation_mutable_model import mutable_bundle
            bundle = mutable_bundle()
        else:
            from tests.unit.components.test_bisimulation_readonly_model import fixed_readonly_bundle
            bundle = fixed_readonly_bundle((2, 2))
    symbols = {"compare": "regions_equal"}
    start = time.monotonic()
    root.mkdir(parents=True, exist_ok=True)
    _write_cbmc_stdint(root / "stdint.h")
    (root / "stddef.h").write_text("typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
    (root / "state-machine-runtime.h").write_text(exact_runtime_header())
    (root / "connected-proof-summary.h").write_text("#define SPX_PROOF_CONNECTED_CAPACITY 1\n")
    for name, content in render_component_c_headers_v5(bundle, symbols).items():
        (root / name).write_text(content)
    write_capacity = 1 + (sum(v.extent['bytes'] for v in bundle.intent.schema.signature_index['operation.compare'].parameters
                              if v.interpretation == 'view' and v.access == 'read_write') if mutable else 0)
    world = _world_source(max_writes=write_capacity, max_private_writes=2, max_calls=1, max_atomics=1,
                          max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
                          max_exposed_stack_views=1)
    replay = '\n'.join(_connected_replay_source([
        {"summary_id": 0, "summary_capacity": 1, "summary_strategy": "mutable-body-free-experiment-v1" if mutable else "readonly-body-free-experiment-v1",
         **({'mutable_transport_policy': 'canonical-mutable-callee-transport-v1'} if mutable else {})}
    ], max_writes=write_capacity, max_calls=1, max_atomics=1))
    wrapper = render_connected_summary_wrapper(bundle=bundle, operation_symbols=symbols,
                                               summary_ids={"compare": 0}, body_free_readonly=not mutable,
                                               body_free_mutable=mutable, checked_mutable_transport=mutable)
    readonly_alias = mutable and bundle.intent.schema.signature_index['operation.compare'].parameters[1].access == 'read'
    second = '&b' if overlap or readonly_alias else '&a'
    replay_second = '&b' if overlap or mismatch_alias or readonly_alias else '&a'
    outside_frame = ' && '.join(
        f'!((uint64_t)frame_address >= {4096 + int(index == 1 and overlap)}U && '
        f'(uint64_t)frame_address < {4096 + int(index == 1 and overlap) + value.extent["bytes"]}U)'
        for index, value in enumerate(bundle.intent.schema.signature_index['operation.compare'].parameters)
        if value.interpretation == 'view' and value.access == 'read_write') or '1U'
    source = '#include "state-machine-runtime.h"\n#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n'
    source += '#include "portable-component-implementation.h"\n'
    overlay = '\n'.join(_view_runtime_helpers(need_read=True, need_write=mutable))
    inspector = "__CPROVER_spx_mutable_overlay_fixture" if mutable else "__CPROVER_spx_readonly_overlay_fixture"
    overlay += (mutable_overlay_transport_source if mutable else readonly_overlay_transport_source)(inspector)
    overlay += """
void fixture_view(spx_view_v5 *view, void *context) {
  view->context = view->access_context = context;
  view->read_u8 = spx_component_view_read; view->read = spx_component_view_read_span;
""" + ("  view->write_u8 = spx_component_view_write; view->write = spx_component_view_write_span;\n" if mutable else '') + "}\n"
    compilation_files = []
    if separate_overlay:
        from spaghetti_extractor.components.machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION
        source += VIEW_CONTEXT_DECLARATION + "void fixture_view(spx_view_v5 *, void *);\n"
        (root / "overlay.c").write_text('#include "state-machine-runtime.h"\n#include "portable-component-implementation.h"\n' + overlay)
        compilation_files.append(str(root / "overlay.c"))
    else:
        source += overlay
    source += (mutable_connected_transport_source([inspector],
               symbol="__CPROVER_spx_connected_mutable_transport_memory_regions_equal") if mutable else
               readonly_connected_transport_source([inspector]))
    source += world + replay + connected_reference_transport_source() + wrapper + '''
static uint32_t bad_read(void *context, uint32_t offset, uint8_t *result) {
  __CPROVER_assert(0, "untrusted accessor must never be invoked"); return 0U;
}
static uint32_t bad_world_read(void *context, uint32_t address, uint32_t width, uint32_t *fault) {
  __CPROVER_assert(0, "untrusted world reader must never be invoked"); return 0U;
}
static spx_boundary_status fixture_reference(void *opaque, const spx_machine_reference_v1 *ref,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  (void)opaque; (void)nullable; (void)one_past;
  if (ref->domain != 1U || ref->object != 4096U || ref->generation != 1U ||
      ref->extent != 2U || ref->offset > 1U || ref->permissions != 1U || permissions != 1U)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = ref->object + ref->offset; return SPX_BOUNDARY_OK;
}
void main(void) {
  uint32_t fault = 0U;
  spx_proof_reset_worlds(4096U, 4U);
  spx_proof_reset_connected_summaries();
  spx_runtime exact_runtime = spx_proof_runtime(&spx_exact_world);
  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);
  spx_proof_expose_stack_view(4096U, 3U);
  spx_machine_reference_v1 reference;
  __CPROVER_assert(exact_runtime.resolve_reference(exact_runtime.context, 4096U, 3U, ''' + str(reference_permissions) + '''U,
      0, 0U, 0U, &reference) == SPX_BOUNDARY_OK, "exact issued origin");
  __CPROVER_assert(source_runtime.resolve_reference(source_runtime.context, 4096U, 3U, ''' + str(reference_permissions) + '''U,
      0, 0U, 0U, &reference) == SPX_BOUNDARY_OK, "source issued origin");
  spx_proof_connected_service_prefix exact_service = {&exact_runtime};
  spx_proof_connected_service_prefix source_service = {&source_runtime};
  spx_memory_regions_equal_services_v5 left_services = {&exact_service};
  spx_memory_regions_equal_services_v5 right_services = {&source_service};
  spx_memory_regions_equal_context_v5 left = {0}, right = {0};
  left.services = &left_services; right.services = &right_services;
  left.state.reserved = 11U; right.state.reserved = 29U;
  spx_view_v5 a = {0};
  a.base.domain = 1U; a.base.object = 4096U; a.base.generation = 1U;
  a.base.extent = 3U; a.base.permissions = ''' + str(reference_permissions) + '''U; a.extent = 2U; a.element_width = ''' + str(element_width) + '''U;
  spx_component_view_context a_context = {&exact_runtime, 4096U, 2U, ''' + ('3U' if mutable else '1U') + '''};
  spx_component_view_context b_context = {&exact_runtime, 4096U, 2U, ''' + ('3U' if mutable else '1U') + '''};
  fixture_view(&a, &a_context);
  spx_view_v5 b = a; b.context = b.access_context = &b_context;
''' + ('  b.write_u8 = 0; b.write = 0; b_context.permissions = 1U;\n' if readonly_alias else '') + (
        '  b.base.offset = 1U; b_context.address = 4097U;\n' if overlap else '') + '''
  spx_proof_exact_write(0, 4097U, 1U, 17U, &fault);
  spx_proof_source_write(0, 4097U, 1U, ''' + ('23U' if mismatch_bytes else '17U') + ''', &fault);
  uint32_t frame_address; __CPROVER_havoc_object(&frame_address);
  uint8_t outside_before = spx_proof_exact_byte(frame_address);
  uint8_t x = regions_equal(&left, &a, ''' + second + ''', 1U);
  a_context.runtime = &source_runtime; b_context.runtime = &source_runtime;
''' + ({
        "callback": "a.read_u8 = bad_read;",
        "null_callback": "a.read_u8 = 0;",
        "span_callback": "a.read = 0;",
        "access_context": "a.access_context = &b_context;",
        "address": "a_context.address = 4097U;",
        "extent": "a_context.extent = 1U;",
        "permissions": "a_context.permissions = 0U;",
        "runtime": "a_context.runtime = &exact_runtime;",
        "runtime_reader": "source_runtime.read = bad_world_read;",
        "runtime_writer": "source_runtime.write = 0;",
        "writer_callback": "a.write_u8 = 0;",
        "runtime_realizer": "source_runtime.realize_reference = fixture_reference;",
        "generation": "a.base.generation = 2U;",
        "null_runtime": "a_context.runtime = 0;",
    }[transport_fault] if transport_fault else '') + '''
  uint8_t y = regions_equal(&right, ''' + ('0' if null_view else '&a') + ', ' + replay_second + ''', 1U);
  __CPROVER_assert(x == y, "paired abstract result");
  __CPROVER_assert(left.state.reserved == 11U && right.state.reserved == 29U &&
      left.services == &left_services && right.services == &right_services,
      "read-only summary preserves distinct caller contexts");
''' + ('''
  uint32_t post_address; __CPROVER_havoc_object(&post_address);
  __CPROVER_assert(spx_proof_exact_byte(post_address) == spx_proof_source_byte(post_address),
      "paired mutable post-memory");
  __CPROVER_assert(!(''' + outside_frame + ''') ||
      (spx_proof_exact_byte(frame_address) == outside_before &&
       spx_proof_source_byte(frame_address) == outside_before), "mutable frame outside views");
''' if mutable else '''  __CPROVER_assert(spx_proof_source_read(0, 4097U, 1U, &fault) == ''' + ('23U' if mismatch_bytes else '17U') + ''',
      "read-only summary preserves shared input bytes");
''') + '''
  __CPROVER_assert(spx_proof_connected_summaries_equal(), "paired invocation count");
''' + ('  __CPROVER_assert(x == 0U, "unproved result fact");\n' if wrong_result else '') + (
        '  __CPROVER_assert(spx_proof_source_byte(4097U) == 17U, "unproved mutable byte fact");\n' if unproved_post_byte else '') + '}\n'
    (root / "pair.c").write_text(source)
    timings = {"model_generation_seconds": time.monotonic() - start}
    start = time.monotonic()
    command = [shutil.which("goto-cc"), "--i386-win32", "-I", str(root), str(root / "pair.c"), *compilation_files, "-o", str(root / "pair.goto")]
    subprocess.run(command, capture_output=True, text=True, check=True)
    timings["source_compilation_seconds"] = time.monotonic() - start
    inventory = subprocess.run([shutil.which("goto-instrument"), "--show-goto-functions", "--json-ui", str(root / "pair.goto")], capture_output=True, text=True, check=True)
    (root / "goto-inventory.json").write_text(inventory.stdout)
    functions = next(row["functions"] for row in json.loads(inventory.stdout) if "functions" in row)
    assert not any("spx_proof_connected_impl_" in row["name"] for row in functions)
    start = time.monotonic()
    query_command = [shutil.which("cbmc"), str(root / "pair.goto"), "--json-ui", "--trace",
        "--bounds-check", "--pointer-check", "--signed-overflow-check", "--undefined-shift-check", "--div-by-zero-check",
        "--unwind", "3", "--unwinding-assertions", "--sat-solver", "cadical"]
    result = run_cbmc_properties(command=query_command, timeout_seconds=30, output_prefix=root / "query")
    timings["solver_seconds"] = time.monotonic() - start
    (root / "probe-inputs.json").write_text(json.dumps({"authorizing": False,
        "compile_command": command, "query_command": query_command,
        "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()
                  if p.suffix in ('.c', '.h', '.goto', '.stdout', '.stderr') or p.name == 'goto-inventory.json'}}, indent=2) + '\n')
    return {**result, "authority": False, "timings": timings,
            "parent_goto_instructions": sum(len(row.get("instructions", [])) for row in functions),
            "write_event_capacity": write_capacity,
            "callee_bodies_present": False}


# Retain the existing fixture entrypoint for readable engine experiments.
check_readonly_pair = check_memory_pair


class ReadonlySummaryTests(unittest.TestCase):
    def test_conditional_composition_does_not_qualify_a_provider(self):
        fields = ("binding_intent_sha256", "implementation_sha256", "source_profile_sha256",
                  "qualification_sha256", "contextual_refinement_sha256", "proof_receipt_sha256",
                  "machine_overlay_sha256", "proof_overlay_sha256", "machine_overlay_entries_sha256")
        connected = {field: "a" * 64 for field in fields}
        connected.update(component_id="probe", trusted_adapter_lowering_receipt_sha256=None,
                         summary_strategy="readonly-body-free-experiment-v1", source_summary_certificate=None)
        with self.assertRaisesRegex(ValueError, "connected summary strategy is malformed"):
            _validate_model_and_shard_evidence(proof_plan={}, shard_results=[],
                models={"operation_models": [], "connected_components": [connected]})

    def test_service_calling_hello_is_not_a_readonly_summary(self):
        path = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(json.loads(path.read_text())))
        self.assertIsNone(readonly_summary_operations(bundle))
        self.assertIsNone(scalar_summary_operations(readonly_bundle()))
        self.assertEqual(readonly_summary_operations(readonly_bundle()), ("compare",))
        with self.assertRaisesRegex(ValueError, "unsupported interface"):
            render_connected_summary_wrapper(bundle=bundle, operation_symbols={"compare": "compare"},
                                             summary_ids={"compare": 0}, body_free_readonly=True)

    def check_pair(self, **kwargs):
        if not all(shutil.which(tool) for tool in ("cbmc", "goto-cc", "goto-instrument")):
            self.skipTest("CBMC contract tools are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            return check_readonly_pair(Path(directory), **kwargs)

    def test_overlapping_views_compose_without_a_callee_body(self):
        result = self.check_pair(overlap=True)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_trusted_accessor_identity_survives_separate_translation_units(self):
        result = self.check_pair(overlap=True, separate_overlay=True)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_read_borrow_accepts_rw_backing_and_rejects_missing_read_permission(self):
        result = self.check_pair(reference_permissions=3, separate_overlay=True)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))
        result = self.check_pair(reference_permissions=2, separate_overlay=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-readable-transport:0")

    def test_equal_metadata_cannot_hide_different_readable_private_bytes(self):
        result = self.check_pair(mismatch_bytes=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertIn("connected-summary", result["detail"])

    def test_descriptor_aliases_are_preserved_separately_from_memory_overlap(self):
        result = self.check_pair(mismatch_alias=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-input:0")

    def test_nonnullable_view_precondition_is_checked(self):
        result = self.check_pair(null_view=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-readable-view:0")

    def test_summary_checks_the_local_readable_domain(self):
        from tests.unit.components.test_bisimulation_readonly_model import fixed_readonly_bundle

        for options in ({"element_width": 2}, {"bundle": fixed_readonly_bundle()}):
            with self.subTest(options=tuple(options)):
                result = self.check_pair(**options)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-readable-domain:0")

    def test_actual_callback_context_and_live_span_are_checked(self):
        for fault in ("callback", "null_callback", "span_callback", "access_context",
                      "address", "extent", "permissions", "runtime", "generation", "null_runtime"):
            with self.subTest(fault=fault):
                result = self.check_pair(transport_fault=fault)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-readable-transport:0")

    def test_world_reader_identity_is_checked_without_invoking_a_substitute(self):
        for fault in ("runtime_reader", "runtime_realizer"):
            with self.subTest(fault=fault):
                result = self.check_pair(transport_fault=fault)
                self.assertEqual(result["status"], "violated", result.get("detail"))
                self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-readable-runtime")

    def test_unproved_result_fact_is_not_assumed(self):
        result = self.check_pair(wrong_result=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "unproved result fact")
