/* Explicit small machine-memory environment, not a native malloc/free test.
 * Host arrays remain alive. Logical deallocation preserves bytes; reuse changes
 * bytes and lifetime generation; unmapping faults. Reading an expired logical
 * allocation is observable and permitted by this fixture's selected scope.
 */
#include <stdio.h>
#include <string.h>
#include "portable-component-implementation.h"
typedef struct { uint8_t bytes[4]; uint32_t generation; int live,mapped; } arena;
static unsigned expired_reads, faults;
static int source_side;
static const int enforce_source_lifetime=0;
spx_ref_status spx_view_read_u8(const spx_view_v5 *view,uint64_t index,uint8_t *out) {
  arena *a=view->context;
  if (!a->mapped || index>=view->extent || view->base.offset>=sizeof(a->bytes) ||
      index>=sizeof(a->bytes)-view->base.offset) { ++faults; return SPX_REF_FAULT; }
  if (!a->live || view->base.generation!=a->generation) {
    ++expired_reads;
    if (enforce_source_lifetime && source_side) { ++faults; return SPX_REF_EXPIRED; }
  }
  *out=a->bytes[view->base.offset+index]; return SPX_REF_OK;
}
static uint8_t original_machine_compare(const spx_view_v5 *left,const spx_view_v5 *right) {
  for (uint64_t index=0; index<4; ++index) {
    uint8_t a,b;
    if (spx_view_read_u8(left,index,&a) || spx_view_read_u8(right,index,&b)) return 0;
    if (a!=b) return 0;
  }
  return 1;
}
int main(int argc,char **argv) {
  if (argc!=3) return 2;
  source_side=!strcmp(argv[1],"source");
  arena a={{3,4,5,6},1,1,1},b=a;
  spx_view_v5 left={0},right={0};
  left.context=&a;right.context=&b;left.extent=right.extent=4;
  left.base.generation=right.base.generation=1;
  if (!strcmp(argv[2],"freed")) a.live=0;
  else if (!strcmp(argv[2],"reused")) { a.generation=2; a.bytes[0]=9; }
  else if (!strcmp(argv[2],"unmapped")) { a.live=0; a.mapped=0; }
  else if (strcmp(argv[2],"live")) return 2;
  unsigned equal=source_side?regions_equal(0,&left,&right,4):original_machine_compare(&left,&right);
  printf("{\"equal\":%u,\"expired_reads\":%u,\"faults\":%u}\n",equal,expired_reads,faults);
  return 0;
}
