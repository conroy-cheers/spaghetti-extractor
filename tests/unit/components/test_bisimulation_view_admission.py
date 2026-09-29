"""Resumed view-domain assumptions require a checked outgoing cut predicate."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_harness import _VIEW_ADMISSION_SOURCE
from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_support import PROOF_PRIVATE_STACK_BELOW
from spaghetti_extractor.components.bisimulation_view_extent import shared_view_admission_source, stack_admission_expression
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}

# These isolated cut tests supply an explicit transport authority, including
# the private test cell whose bytes the cut must still compare. Native origin
# admission and expiry are exercised by test_bisimulation_reference_transport.
_FIXTURE_REFERENCE_SOURCE = '''
static spx_boundary_status fixture_reference(void *opaque, const spx_machine_reference_v1 *ref,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  const spx_machine_reference_v1 *origin = (const spx_machine_reference_v1 *)opaque;
  if (ref->domain != origin->domain || ref->object != origin->object ||
      ref->generation != origin->generation || ref->extent != origin->extent ||
      ref->permissions != origin->permissions || (ref->permissions & permissions) != permissions ||
      ref->offset >= ref->extent || ref->object > UINT32_MAX - ref->offset)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = (uint32_t)(ref->object + ref->offset); return SPX_BOUNDARY_OK;
}
'''


class CutViewAdmissionTests(unittest.TestCase):
    def test_entry_stack_domain_is_preserved_but_must_be_rechecked_after_call(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        predicate = stack_admission_expression(stack_pointer="esp", high_offset="high_offset",
                                              image_base=0x400000, image_size=0x10000)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "entry-domain.c"
            source.write_text('''#include <stdint.h>
uint32_t admitted(uint32_t esp, uint32_t high_offset) {
  return ''' + predicate + ''';
}
const uint32_t spx_proof_private_high_offset = 4096U;
''' + shared_view_admission_source(private_ranges=(), image_base=0x400000, image_size=0x10000) + '''
void equivalence(void) {
  uint32_t esp, high_offset;
  uint64_t low = (uint64_t)esp - ''' + str(PROOF_PRIVATE_STACK_BELOW) + '''U;
  uint64_t high = (uint64_t)esp + high_offset;
  uint32_t previous = esp >= ''' + str(PROOF_PRIVATE_STACK_BELOW) + '''U && high <= UINT32_MAX &&
      (high <= 0x400000U || low >= 0x410000U);
  __CPROVER_assert(admitted(esp, high_offset) == previous, "entry-domain unchanged");
  __CPROVER_assert(spx_proof_view_admitted(0x401004U, 4U, esp) == admitted(esp, 4096U),
                   "shared-view uses the same stack domain");
}
void unsafe_call(void) {
  uint32_t caller_esp = 0x410000U + ''' + str(PROOF_PRIVATE_STACK_BELOW) + '''U;
  __CPROVER_assert(admitted(caller_esp, 4096U), "caller entry is admitted");
  __CPROVER_assert(admitted(caller_esp - 4U, 4096U), "callee entry must be established");
}
void checked_call(void) {
  uint32_t esp;
  __CPROVER_assume(admitted(esp, 4096U));
  /* The caller must prove this condition; assuming it would restrict its domain. */
  if (!admitted(esp - 4U, 4096U)) return;
  __CPROVER_assert(spx_proof_view_admitted(0x401004U, 4U, esp - 4U),
                   "callee shared view domain established");
}
''')
            for entry, expected in (("equivalence", "satisfied"), ("unsafe_call", "violated"),
                                    ("checked_call", "satisfied")):
                with self.subTest(entry=entry):
                    result = run_cbmc_properties(command=[cbmc, str(source), "--function", entry,
                        "--json-ui", "--trace", "--unwind", "2", "--unwinding-assertions"], timeout_seconds=10)
                    self.assertEqual(result["status"], expected, result)
                    if entry == "unsafe_call":
                        self.assertEqual(result["detail"], "callee entry must be established")

    def _intent(self):
        return ComponentBisimulationIntentV1.create(component_id="views", operations=[{
            "operation_id": "run", "syncs": [{"id": "scan", "exact_unit_id": "cut", "captures": [{
                "kind": "parameter", "id": "buffer", "mode": "machine_codec",
                "projection": {"kind": "view", "at": "entry", "base": {
                    "kind": "register", "register": "ebx", "width": 32, "at": "entry"},
                    "extent": {"kind": "constant", "width": 32, "value": 4},
                    "requested_extent": {"kind": "constant", "width": 32, "value": 4},
                    "authority": {"kind": "external", "id": "buffer", "lifetime": "invocation"}},
                "encoding": {"op": "bytes_address", "name": "buffer"}, "decoding": None}],
                "derived": [], "invariant": {"op": "true"}}]}])

    def test_parsed_view_capture_requires_outgoing_assertion_in_inventory(self):
        authored = self._intent().operations[0]
        description = "spx-bisimulation-resumed-view-admission:scan:buffer"
        memory = "spx-bisimulation-capture-reference-memory:scan:buffer"
        methods = "spx-bisimulation-capture-methods:scan:buffer"
        metadata = "spx-bisimulation-capture-metadata:scan:buffer"
        context = "spx-bisimulation-capture-context:scan:buffer"
        extent = "spx-bisimulation-capture-extent:scan:buffer"
        header = _render_proof_header(authored=authored, image_base=0x400000,
                                      unit_rvas={"cut": 4096})
        self.assertIn(description, header)
        self.assertIn(memory, header)
        self.assertIn(methods, header)
        self.assertIn(metadata, header)
        self.assertIn(context, header)
        self.assertIn(extent, header)
        for next_sync_ids in ({"scan"}, set()):
            with self.subTest(next_sync_ids=next_sync_ids):
                descriptions = _required_assertion_descriptions(
                    authored=authored, proof_function="check", active_start_sync_id=None,
                    next_sync_ids=next_sync_ids, logical_projection={"results": [], "state": []},
                    continuous_acyclic=False, typed_call_positions=[])
                self.assertEqual(description in descriptions, "scan" in next_sync_ids)
                self.assertEqual(memory in descriptions, "scan" in next_sync_ids)
                self.assertEqual(methods in descriptions, "scan" in next_sync_ids)
                self.assertEqual(metadata in descriptions, "scan" in next_sync_ids)
                self.assertEqual(context in descriptions, "scan" in next_sync_ids)
                self.assertEqual(extent in descriptions, "scan" in next_sync_ids)

    def test_outgoing_cut_rejects_invalid_views_even_when_captures_agree(self):
        self._check_outgoing_cut((
            (9216, 5120, True), (0xfffffffc, 5120, True), (0, 5120, False),
            (0xfffffffd, 5120, False), (4096, 5120, False), (4094, 5120, False),
            (10000, 5120, True), (10000, 9000, False), (10000, 18000, True),
            (10000, 0, False), (10000, 0xfffff000, False),
        ))

    def test_context_assumption_consumes_one_evaluation_and_cannot_hide_failure(self):
        for reject_first in (False, True):
            with self.subTest(reject_first=reject_first):
                self._check_outgoing_cut(((9216, 5120, not reject_first),),
                    count_reference=True, reject_first=reject_first)

    def _check_outgoing_cut(self, cases, *, count_reference=False, reject_first=False):
        intent = self._intent()
        header = _render_proof_header(authored=intent.operations[0], image_base=0x400000,
                                      unit_rvas={"cut": 4096})
        reference_source = _FIXTURE_REFERENCE_SOURCE
        if count_reference:
            reference_source = 'uint32_t fixture_reference_calls;\n' + reference_source.replace(
                '  const spx_machine_reference_v1 *origin',
                '  ++fixture_reference_calls;\n'
                + ('  if (fixture_reference_calls == 1U) return SPX_BOUNDARY_MEMORY_FAULT;\n'
                   if reject_first else '')
                + '  const spx_machine_reference_v1 *origin')
            # Check the actual generated cut before the next independent
            # reference-memory observation. The old assert/re-evaluate/assume
            # sequence calls the stateful validator twice and fails this test.
            needle = '    __CPROVER_assert(spx_proof_world_memory_range_equal('
            self.assertIn(needle, header)
            header = 'extern unsigned int fixture_reference_calls;\n' + header.replace(
                needle, '    __CPROVER_assert(fixture_reference_calls == 1U, '
                '"context validated once"); ' + chr(92) + '\n' + needle)
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "proof.h").write_text(header)
            for address, stack_pointer, valid in cases:
                with self.subTest(address=address, stack_pointer=stack_pointer):
                    source = root / "test.c"
                    source.write_text('''
#include "proof.h"
const uint32_t spx_proof_private_high_offset = 4096;
''' + _VIEW_ADMISSION_SOURCE + reference_source + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
void spx_bisimulation_relation_witness(void) {}
uint32_t spx_proof_world_calls_equal(void) {return 1;}
uint32_t spx_proof_world_atomics_equal(void) {return 1;}
uint32_t spx_proof_world_public_memory_equal(void) {return 1;}
uint32_t spx_proof_world_allocation_cut_admitted(void) {return 1;}
uint32_t spx_proof_world_connected_calls_equal(void) {return 1;}
uint32_t spx_proof_world_memory_range_equal(uint32_t base, uint64_t extent) {return 1;}
typedef struct view {
  struct { uint64_t object, domain, generation, offset, permissions, extent; } base;
  uint64_t extent; uint32_t element_width;
  void *context, *access_context;
  uint32_t (*read_u8)(void), (*write_u8)(void), (*read)(void), (*write)(void);
} spx_view_v1;
void run(struct view *buffer) {
  SPX_PROOF_BEGIN(run);
  SPX_PROOF_SYNC(scan, 1, buffer);
  __CPROVER_assert(0, "cut must stop");
}
void check(void) {
  spx_proof_exact_result.kind = SPX_JUMP;
  spx_proof_exact_result.target_rva = 4096;
  spx_proof_exact_output.ebx = ''' + str(address) + '''U;
  spx_proof_exact_output.esp = ''' + str(stack_pointer) + '''U;
  spx_machine_reference_v1 origin = {1U, ''' + str(address) + '''ULL, 1U, 0U, 4U, 3U};
  spx_runtime runtime = {.context=&origin, .realize_reference=fixture_reference};
  spx_component_view_context view_context = {&runtime, ''' + str(address) + '''U, 4U, 3U};
  struct view buffer = {.base = {.object = ''' + str(address) + '''ULL, .domain=1U, .generation=1U,
                       .permissions=3U, .extent = 4U}, .extent = 4U,
                       .context = &view_context, .access_context = &view_context};
  run(&buffer);
}
''')
                    result = run_cbmc_properties(command=[cbmc, str(source), "--function", "check",
                        "--json-ui", "--unwind", "2", "--stop-on-fail"], timeout_seconds=10)
                    self.assertEqual(result["status"], "satisfied" if valid else "violated", result)
                    if not valid:
                        description = ("capture-context" if reject_first else "resumed-view-admission")
                        self.assertEqual(result["detail"], f"spx-bisimulation-{description}:scan:buffer")

    def test_byte_view_capture_also_requires_its_memory_assertion(self):
        payload = self._intent().to_payload()
        capture = payload["operations"][0]["syncs"][0]["captures"][0]
        capture["projection"] = {"kind": "bytes_view", "at": "entry", "extent_id": None,
                                 "base": capture["projection"]["base"]}
        authored = ComponentBisimulationIntentV1.create(
            component_id="views", operations=payload["operations"]).operations[0]
        header = _render_proof_header(authored=authored, image_base=0x400000, unit_rvas={"cut": 4096})
        descriptions = _required_assertion_descriptions(
            authored=authored, proof_function="check", active_start_sync_id=None,
            next_sync_ids={"scan"}, logical_projection={"results": [], "state": []},
            continuous_acyclic=False, typed_call_positions=[])
        self.assertIn("spx-bisimulation-capture-reference-memory:scan:buffer", header)
        self.assertIn("spx-bisimulation-capture-reference-memory:scan:buffer", descriptions)
        self.assertIn("spx-bisimulation-capture-methods:scan:buffer", descriptions)
        self.assertIn("spx-bisimulation-capture-metadata:scan:buffer", descriptions)
        self.assertIn("spx-bisimulation-capture-context:scan:buffer", descriptions)
        self.assertIn("spx-bisimulation-capture-extent:scan:buffer", descriptions)

    def test_outgoing_view_checks_bytes_omitted_by_public_frame_comparison(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "proof.h").write_text(_render_proof_header(
                authored=self._intent().operations[0], image_base=0x400000, unit_rvas={"cut": 4096}))
            cases = [(7, "", False), (8, "", False),
                     (7, "read_u8", False), (7, "read_u8", True), (7, "restored_permissions", False), (7, "context_permissions", False), (7, "context_permissions", True),
                     (7, "access_context", False), (7, "wide_address", False), (7, "visible_extent", False), (7, "reference_extent", False), (8, "reference_tail", False)]
            for field in ("base.domain", "base.generation", "base.offset", "base.permissions", "element_width"):
                cases.extend([(7, field, False), (7, field, True)])
            for source_value, mutate, renamed in cases:
                with self.subTest(source_value=source_value, mutate=mutate, renamed=renamed):
                    intent_payload = self._intent().to_payload()
                    reference_extent = 8 if mutate == "reference_tail" else 4
                    store_address = 16388 if mutate == "reference_tail" else 16384
                    if mutate == "reference_tail":
                        intent_payload["operations"][0]["syncs"][0]["captures"][0]["projection"]["requested_extent"]["value"] = 8
                    if renamed:
                        intent_payload["operations"][0]["syncs"][0]["source_bindings"] = {
                            "buffer": {"root": "renamed", "members": []}}
                    authored = ComponentBisimulationIntentV1.create(
                        component_id="views", operations=intent_payload["operations"]).operations[0]
                    (root / "proof.h").write_text(_render_proof_header(
                        authored=authored, image_base=0x400000, unit_rvas={"cut": 4096}))
                    source = root / "cut.c"
                    mutation = ""
                    if mutate == "read_u8":
                        mutation = "buffer->read_u8 = 0;"
                    elif mutate == "restored_permissions":
                        mutation = "buffer->base.permissions = 1U; buffer->base.permissions = 3U;"
                    elif mutate == "context_permissions":
                        mutation = "((spx_component_view_context *)buffer->context)->permissions = 1U;"
                    elif mutate == "reference_tail":
                        mutation = ""
                    elif mutate == "visible_extent":
                        mutation = "buffer->extent = 2U; ((spx_component_view_context *)buffer->context)->extent = 2U;"
                    elif mutate == "reference_extent":
                        mutation = "buffer->base.extent = 8U;"
                    elif mutate == "wide_address":
                        mutation = "buffer->base.object += 4294967296ULL;"
                    elif mutate == "access_context":
                        mutation = "buffer->access_context = 0;"
                    elif mutate:
                        mutation = f"buffer->{mutate} += 1U;"
                    source.write_text('#include "proof.h"\n#define SPX_PROOF_IMAGE_BASE 4194304U\n'
                        + _world_source(max_writes=1, max_private_writes=1, max_calls=1,
                            max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
                            service_bindings=(), private_ranges=((16384, 8),)) + '''
const uint32_t spx_proof_private_high_offset = 4096;
''' + _VIEW_ADMISSION_SOURCE + _FIXTURE_REFERENCE_SOURCE + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
void spx_bisimulation_relation_witness(void) {}
uint32_t spx_proof_world_calls_equal(void) {return 1;}
uint32_t spx_proof_world_atomics_equal(void) {return 1;}
uint32_t spx_proof_world_connected_calls_equal(void) {return 1;}
typedef struct view {
  struct { uint64_t object, domain, generation, offset, permissions, extent; } base;
  uint64_t extent; uint32_t element_width;
  void *context, *access_context;
  uint32_t (*read_u8)(void), (*write_u8)(void), (*read)(void), (*write)(void);
} spx_view_v1;
uint32_t read_byte(void) {return 7U;}
void run(struct view *buffer) {
  SPX_PROOF_BEGIN(run);
  ''' + mutation + '''
  SPX_PROOF_SYNC(scan, 1, buffer);
  __CPROVER_assert(0, "cut must stop");
}
void check(void) {
  uint32_t fault = 0U;
  spx_proof_reset_worlds(5120U, 4096U);
  spx_proof_write_world(&spx_exact_world, ''' + str(store_address) + '''U, 4U, 7U, &fault);
  spx_proof_write_world(&spx_source_world, ''' + str(store_address) + '''U, 4U, ''' + str(source_value) + '''U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "old public comparison omits these bytes");
  if (''' + str(int(mutate == 'reference_tail')) + ''')
    __CPROVER_assert(spx_proof_world_memory_range_equal(16384U, 4U), "visible prefix still matches");
  spx_proof_exact_result.kind = SPX_JUMP;
  spx_proof_exact_result.target_rva = 4096;
  spx_proof_exact_output.ebx = 16384U;
  spx_proof_exact_output.esp = 5120U;
  spx_machine_reference_v1 origin = {1U, 16384U, 1U, 0U, ''' + str(reference_extent) + '''U, 3U};
  spx_runtime runtime = {.context=&origin, .realize_reference=fixture_reference};
  spx_component_view_context view_context = {&runtime, 16384U, 4U, 3U};
  struct view buffer = {
    .base = {16384U, 1U, 1U, 0U, 3U, ''' + str(reference_extent) + '''U}, .extent = 4U, .element_width = 1U,
    .context = &view_context, .access_context = &view_context, .read_u8 = read_byte
  };
  run(&buffer);
}
''')
                    if renamed:
                        source.write_text(source.read_text().replace("buffer", "renamed"))
                    result = run_cbmc_properties(command=[cbmc, str(source), "--function", "check",
                        "--json-ui", "--unwind", "2", "--stop-on-fail"], timeout_seconds=10)
                    valid = source_value == 7 and mutate in {"", "restored_permissions"}
                    self.assertEqual(result["status"], "satisfied" if valid else "violated", result)
                    if not valid:
                        kind = ("methods" if mutate == "read_u8" else "metadata") if mutate else "reference-memory"
                        if mutate == "reference_tail":
                            kind = "reference-memory"
                        if mutate in {"visible_extent", "reference_extent"}:
                            kind = "extent"
                        if mutate in {"context_permissions", "access_context", "wide_address"}:
                            kind = "context"
                        self.assertEqual(result["detail"], f"spx-bisimulation-capture-{kind}:scan:buffer")


if __name__ == "__main__":
    unittest.main()
