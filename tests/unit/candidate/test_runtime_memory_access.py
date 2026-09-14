"""Exercise native admission predicates and the closure premises they require."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.runtime_memory_access import (
    access_predicates_source, range_predicates_source, thread_environment_predicate_source,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def access_fixture_source(body, *, section_rows=None):
    """Bound the native context; preserve production admission predicate bodies.

    Priority-handler answers are explicit inputs, not proofs that handlers are
    absent. Section reads are immutable rows, not guest heap reads. The real
    consumer must bind those rows and discharge both context closure premises.
    """
    rows = section_rows or ((0x1000, 0x100, 0x100, 0x20000000),
                            (0x2000, 0x100, 0x100, 0))
    section_values = ',\n'.join('{' + ','.join(f'{v}U' for v in row) + '}' for row in rows)
    providers = ('physical_frame', 'captured_stack', 'unwind_service', 'exception_service', 'exception')
    return '''#include <stdint.h>
#define SPX_NATIVE_IMAGE_SCN_MEM_EXECUTE 0x20000000U
#define SPX_NATIVE_THREAD_ENVIRONMENT_BYTES 0x1000U
typedef struct { uint32_t start, size; } spx_native_external_range;
typedef struct {
 uint32_t image_base, image_size, headers_size, section_table, section_count;
 uint32_t stack_low, stack_high, owner_fs_base, external_range_count;
 spx_native_external_range external_ranges[4];
} spx_native_context;
static spx_native_context spx_native_context_value;
static uint32_t access_overrides[5];
static const uint32_t sections[][4]={''' + section_values + '''};
static uint32_t spx_native_u32(uint32_t address) {
 uint32_t offset=address-spx_native_context_value.section_table;
 uint32_t index=offset/40U, field=offset%40U;
 __CPROVER_assert(index<sizeof(sections)/sizeof(sections[0]),"bound section-table access");
 if(field==8U) return sections[index][1];
 if(field==12U) return sections[index][0];
 if(field==16U) return sections[index][2];
 __CPROVER_assert(field==36U,"only admission metadata is read");
 return sections[index][3];
}
''' + '\n'.join(f'''static uint32_t spx_native_{name}_memory_access(
 uint32_t address,uint32_t width,uint32_t write_access) {{
 (void)address; (void)width; (void)write_access; return access_overrides[{i}];
}}''' for i, name in enumerate(providers)) + '\n' + range_predicates_source() + thread_environment_predicate_source() + access_predicates_source() + f'''
static void start(void) {{
 spx_native_context_value=(spx_native_context){{
  .image_base=0x400000U,.image_size=0x4000U,.headers_size=0x400U,
  .section_table=0x400178U,.section_count={len(rows)}U,
  .stack_low=0x7f0000U,.stack_high=0x801000U,.owner_fs_base=0x900000U
 }};
}}
''' + body


class NativeMemoryAccessTests(unittest.TestCase):
    def check(self, body, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            path = root / 'admission.c'
            path.write_text(access_fixture_source(body, **kwargs))
            return run_cbmc_properties(command=[shutil.which('cbmc'), str(path),
                '--json-ui', '--trace', '--unwind', '6', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check',
                '--undefined-shift-check', '--sat-solver', 'cadical'], timeout_seconds=40)

    def satisfied(self, body, **kwargs):
        result = self.check(body, **kwargs)
        self.assertEqual(result['status'], 'satisfied', result)

    def test_image_permissions_holes_and_whole_spans(self):
        self.satisfied('''int main(void) {
 start();
 __CPROVER_assert(spx_native_read_allowed(0x400000U,4U) &&
  !spx_native_write_allowed(0x400000U,4U),"headers are only readable");
 __CPROVER_assert(spx_native_read_allowed(0x401000U,4U) &&
  !spx_native_write_allowed(0x401000U,4U),"executable section cannot be written");
 __CPROVER_assert(spx_native_read_allowed(0x402000U,4U) &&
  spx_native_write_allowed(0x402000U,4U),"data section is admitted");
 __CPROVER_assert(!spx_native_read_allowed(0x401800U,4U) &&
  !spx_native_write_allowed(0x401800U,4U),"image envelope does not admit holes");
 __CPROVER_assert(!spx_native_read_allowed(0x4020ffU,2U),"complete span must fit");
}''')

    def test_closed_map_matches_all_address_and_width_inputs(self):
        self.satisfied('''uint32_t nondet_u32(void);
int main(void) {
 start();
 uint32_t address=nondet_u32(),width=nondet_u32();
 uint64_t end=(uint64_t)address+width;
 uint32_t valid=width!=0U && end<=UINT32_MAX;
 uint32_t headers=address>=0x400000U && end<=0x400400U;
 uint32_t code=address>=0x401000U && end<=0x401100U;
 uint32_t data=address>=0x402000U && end<=0x402100U;
 uint32_t stack=address>=0x7f0000U && end<=0x801000U;
 uint32_t teb=address>=0x900000U && end<=0x901000U;
 __CPROVER_assert(spx_native_read_allowed(address,width)==
  (valid && (headers || code || data || stack || teb)),"all read spans match closed map");
 __CPROVER_assert(spx_native_write_allowed(address,width)==
  (valid && (data || stack || teb)),"all write spans match closed map");
}''')

    def test_null_denial_requires_external_range_closure(self):
        result = self.check('''int main(void) {
 start();
 __CPROVER_assert(!spx_native_write_allowed(0U,1U),"closed context rejects null");
 spx_native_context_value.external_range_count=1U;
 spx_native_context_value.external_ranges[0]=(spx_native_external_range){0U,4U};
 __CPROVER_assert(!spx_native_write_allowed(0U,1U),"dropping range closure is invalid");
}''')
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'], 'dropping range closure is invalid', result)

    def test_native_edge_widths_and_adjacent_ranges(self):
        self.satisfied('''int main(void) {
 start();
 spx_native_context_value.external_range_count=2U;
 spx_native_context_value.external_ranges[0]=(spx_native_external_range){4096U,4U};
 spx_native_context_value.external_ranges[1]=(spx_native_external_range){4100U,4U};
 __CPROVER_assert(spx_native_write_allowed(4096U,4U) &&
  !spx_native_write_allowed(4098U,4U),"adjacent ranges do not make one object");
 __CPROVER_assert(!spx_native_read_allowed(4096U,0U) &&
  !spx_native_write_allowed(UINT32_MAX,1U),"native end must be representable");
}''')

    def test_live_range_removal_revokes_admission(self):
        self.satisfied('''int main(void) {
 start();
 spx_native_context_value.external_range_count=1U;
 spx_native_context_value.external_ranges[0]=(spx_native_external_range){4096U,16U};
 __CPROVER_assert(spx_native_read_allowed(4096U,4U) &&
  spx_native_write_allowed(4096U,4U),"live range grants access");
 spx_native_context_value.external_range_count=0U;
 __CPROVER_assert(!spx_native_read_allowed(4096U,4U) &&
  !spx_native_write_allowed(4096U,4U),"historical bytes do not grant access");
}''')

    def test_priority_handlers_can_revoke_or_grant_access(self):
        self.satisfied('''int main(void) {
 start();
 access_overrides[4]=1U;
 __CPROVER_assert(spx_native_read_allowed(0U,1U),"active exception grant precedes map");
 access_overrides[0]=2U;
 __CPROVER_assert(!spx_native_read_allowed(0U,1U) &&
  !spx_native_write_allowed(0x402000U,4U),"higher priority denial precedes grants");
 access_overrides[0]=1U;
 __CPROVER_assert(spx_native_write_allowed(0U,1U),"higher priority grant is decisive");
}''')

    def test_stack_and_thread_environment_do_not_grant_neighbors(self):
        self.satisfied('''int main(void) {
 start();
 __CPROVER_assert(spx_native_read_allowed(0x800ffcU,4U) &&
  spx_native_write_allowed(0x800ffcU,4U),"stack span admitted");
 __CPROVER_assert(!spx_native_read_allowed(0x800ffdU,4U),"stack crossing fails");
 __CPROVER_assert(spx_native_read_allowed(0x900fffU,1U) &&
  spx_native_write_allowed(0x900fffU,1U),"thread environment admitted");
 __CPROVER_assert(!spx_native_write_allowed(0x901000U,1U),"thread neighbor denied");
}''')

    def test_overlapping_executable_section_vetoes_write(self):
        self.satisfied('''int main(void) {
 start();
 __CPROVER_assert(spx_native_read_allowed(0x401000U,1U) &&
  !spx_native_write_allowed(0x401000U,1U),"executable overlap vetoes data grant");
}''', section_rows=((0x1000, 0x100, 0x100, 0), (0x1000, 0x100, 0x100, 0x20000000)))
