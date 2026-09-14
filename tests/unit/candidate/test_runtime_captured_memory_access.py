"""Actual captured-stack admission can agree with a component's memory map."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.native_ingress_runtime_source import render_native_ingress_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from .test_runtime_canonical import _inputs
from .test_runtime_memory_access import access_fixture_source

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def captured_access_fixture(body, *, section_rows=None):
    # Render the real native ingress implementation. Only its surrounding TLS
    # context is bounded here; the access predicate itself is not reimplemented.
    with tempfile.TemporaryDirectory() as temporary:
        inputs = _inputs(Path(temporary))
        native = render_native_ingress_source(json.loads(inputs['native_ingress_plan'].read_text()))
    first = native.index('uint32_t spx_native_captured_stack_memory_access(')
    last = native.index('static uint32_t spx_native_lifecycle_borrow_value(', first)
    predicate = native[first:last]
    prelude = '''
#define SPX_NATIVE_THREAD_MAGIC 123U
static uint32_t captured_private_bytes;
#define SPX_PRIVATE_STACK_BYTES captured_private_bytes
typedef struct {uint32_t esp;} spx_machine_state;
typedef struct {uint32_t magic,depth;} spx_native_thread_header;
typedef struct {
 uint32_t bridge_index; spx_machine_state *input;
 uint32_t host_stack_base,host_stack_limit;
} spx_native_ingress_frame;
static spx_native_thread_header header={SPX_NATIVE_THREAD_MAGIC,0U};
static spx_machine_state captured_input;
static spx_native_ingress_frame frame;
static const uint32_t spx_native_ingress_descriptor_count=1U;
static uint8_t *spx_native_thread_base(void) {return (uint8_t *)&header;}
static spx_native_ingress_frame *spx_native_frame_at(uint8_t *base,uint32_t index) {
 __CPROVER_assert(base==(uint8_t *)&header && index==0U,"current checked ingress frame");
 return &frame;
}
'''
    source = access_fixture_source(body, section_rows=section_rows)
    old = '''static uint32_t spx_native_captured_stack_memory_access(
 uint32_t address,uint32_t width,uint32_t write_access) {
 (void)address; (void)width; (void)write_access; return access_overrides[1];
}'''
    if source.count(old) != 1:
        raise AssertionError('captured-stack fixture provider is ambiguous')
    return source.replace(old, prelude + predicate)


class CapturedMemoryAccessTests(unittest.TestCase):
    def check(self, body):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            path = root / 'captured.c'
            path.write_text(captured_access_fixture(body))
            return run_cbmc_properties(command=[shutil.which('cbmc'), str(path),
                '--json-ui', '--trace', '--unwind', '6', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check',
                '--undefined-shift-check', '--sat-solver', 'cadical'], timeout_seconds=40)

    def test_active_captured_frame_preserves_normal_map_for_all_accesses(self):
        result = self.check('''uint32_t nondet_u32(void);
int main(void) {
 start();
 uint32_t address=nondet_u32(),width=nondet_u32();
 uint32_t ordinary_read=spx_native_read_allowed(address,width);
 uint32_t ordinary_write=spx_native_write_allowed(address,width);
 captured_input.esp=nondet_u32();captured_private_bytes=nondet_u32();
 __CPROVER_assume(captured_input.esp>=spx_native_context_value.stack_low &&
  captured_input.esp<=spx_native_context_value.stack_high);
 frame=(spx_native_ingress_frame){0U,&captured_input,
  spx_native_context_value.stack_high,spx_native_context_value.stack_low};
 header.depth=1U;
 __CPROVER_assert(spx_native_read_allowed(address,width)==ordinary_read &&
  spx_native_write_allowed(address,width)==ordinary_write,
  "active captured-stack provider agrees with normal mapped admission");
 captured_input.esp=0x800000U;captured_private_bytes=4096U;
 __CPROVER_assert(spx_native_captured_stack_memory_access(0x7ffffcU,4U,1U)==1U,
  "agreement includes an actual active private-stack grant");
 __CPROVER_assert(spx_native_captured_stack_memory_access(0U,1U,1U)==0U &&
  !spx_native_write_allowed(0U,1U),"active normal frame preserves null denial");
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_dropping_frame_to_context_correspondence_changes_faults(self):
        result = self.check('''int main(void) {
 start();
 __CPROVER_assert(!spx_native_write_allowed(0U,1U),"ordinary context denies null");
 captured_input.esp=0x800000U;captured_private_bytes=UINT32_MAX;
 frame=(spx_native_ingress_frame){0U,&captured_input,0x801000U,0U};
 header.depth=1U;
 __CPROVER_assert(!spx_native_write_allowed(0U,1U),
  "missing frame correspondence cannot preserve fault behavior");
}''')
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'],
                         'missing frame correspondence cannot preserve fault behavior', result)
