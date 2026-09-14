"""Validate an experimental span contract using actual native admission and loader C."""
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from .test_runtime_captured_memory_access import captured_access_fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler')}
HEADER = Path(__file__).resolve().parents[2] / 'fixtures/native/context_span_contract.h'


def context_fixture(body):
    # Compile the emitted native loader predicate itself, with explicit bounded
    # metadata and a symbolic IAT word. No loader semantics are transcribed.
    native = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=[]))
    first = native.index('uint32_t spx_native_loader_code_target_matches(')
    last = native.index('uint32_t spx_native_external_code_target_matches(', first)
    loader = native[first:last]
    return ('#define spx_native_u32 context_metadata_read\n' + captured_access_fixture('') +
        '\n#undef spx_native_u32\n' + HEADER.read_text() + '''
static uint32_t iat_address=0x402010U,iat_word;
static uint32_t spx_native_u32(uint32_t address) {
  if(address==iat_address) return iat_word;
  __CPROVER_assert(0,"loader only reads the declared IAT slot");return 0U;
}
typedef struct {uint32_t iat_rva;} spx_native_loader_target;
static const uint32_t spx_native_loader_target_count=0U;
static spx_native_loader_target spx_native_loader_targets[1];
static uint32_t spx_native_loader_target_words[1];
''' + loader + body)


class NativeContextSpanTests(unittest.TestCase):
    def check(self, body):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            path = root / 'context.c'
            path.write_text(context_fixture(body))
            return run_cbmc_properties(command=[shutil.which('cbmc'), str(path),
                '--json-ui', '--trace', '--stop-on-fail', '--unwind', '6', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check',
                '--undefined-shift-check', '--sat-solver', 'cadical'], timeout_seconds=40)

    def test_backed_span_covers_arbitrary_future_accesses_with_active_capture(self):
        result = self.check('''uint32_t nondet_u32(void);
int main(void) {
 start();
 uint32_t low=nondet_u32(),high=nondet_u32();
 __CPROVER_assume(low>=spx_native_context_value.stack_low &&
   low<high && high<=spx_native_context_value.stack_high);
 captured_input.esp=high;captured_private_bytes=high-low;
 frame=(spx_native_ingress_frame){0U,&captured_input,
  spx_native_context_value.stack_high,spx_native_context_value.stack_low};
 header.depth=1U;
 uint32_t address=nondet_u32(),width=nondet_u32();
 if(spx_context_span_contains(low,high,address,width)) {
  __CPROVER_assert(spx_native_read_allowed(address,width) &&
   spx_native_write_allowed(address,width),"native backing grants every whole future frame access");
 }
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_geometric_private_span_does_not_establish_backing(self):
        result = self.check('''int main(void) {
 start();
 __CPROVER_assert(!spx_context_span_contains(0x2000U,0x2040U,0x2010U,4U) ||
  spx_native_write_allowed(0x2010U,4U),"missing native backing must be detected");
}''')
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'], 'missing native backing must be detected', result)

    def test_priority_override_is_not_hidden_by_a_backed_span(self):
        result = self.check('''int main(void) {
 start();access_overrides[0]=2U;
 __CPROVER_assert(!spx_context_span_contains(0x800000U,0x800040U,0x800010U,4U) ||
  spx_native_write_allowed(0x800010U,4U),"priority closure is required for frame access");
}''')
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'], 'priority closure is required for frame access', result)

    def test_old_frame_promise_cannot_outlive_its_backing(self):
        result = self.check('''int main(void) {
 start();
 __CPROVER_assert(spx_native_write_allowed(0x800010U,4U),"old frame is initially backed");
 spx_native_context_value.stack_high=0x800000U;
 __CPROVER_assert(!spx_context_span_contains(0x800000U,0x800040U,0x800010U,4U) ||
  spx_native_write_allowed(0x800010U,4U),"stale frame permission is rejected");
}''')
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'], 'stale frame permission is rejected', result)

    def test_span_bounds_retain_null_zero_and_exclusive_end_rules(self):
        result = self.check('''int main(void) {
 __CPROVER_assert(!spx_context_span_contains(0U,16U,0U,1U) &&
  !spx_context_span_contains(16U,32U,16U,0U) &&
  !spx_context_span_contains(32U,16U,32U,1U) &&
  !spx_context_span_contains(16U,32U,31U,2U) &&
  !spx_context_span_contains(16U,UINT32_MAX,UINT32_MAX,1U) &&
  spx_context_span_contains(16U,UINT32_MAX,UINT32_MAX-1U,1U),
  "whole-span arithmetic preserves native exclusive-end semantics");
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_readable_iat_and_actual_loader_matching_bind_a_nonzero_current_word(self):
        result = self.check('''uint32_t nondet_u32(void);
int main(void) {
 start();iat_word=nondet_u32();uint32_t target=nondet_u32();
 __CPROVER_assert(spx_native_read_allowed(iat_address,4U),"declared IAT storage is readable");
 uint32_t bound=spx_native_loader_code_target_matches(target,iat_address-0x400000U,0U);
 __CPROVER_assert(bound==(target!=0U && target==iat_word),
  "actual loader matcher requires the nonzero current IAT word");
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_loader_identity_alone_does_not_establish_iat_read_permission(self):
        result = self.check('''int main(void) {
 start();iat_address=0x401800U;iat_word=0x70000000U;
 __CPROVER_assert(spx_native_loader_code_target_matches(iat_word,0x1800U,0U),
  "bounded loader read can match its target word");
 __CPROVER_assert(spx_native_read_allowed(iat_address,4U),
  "loader target identity does not establish IAT read permission");
}''')
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'], 'loader target identity does not establish IAT read permission', result)
