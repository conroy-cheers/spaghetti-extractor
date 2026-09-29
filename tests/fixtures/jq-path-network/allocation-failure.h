/* Test-only native nonlocal delivery. Values inspected after longjmp have
 * static storage. Only references retained by the caller are reclaimed. */
#include <setjmp.h>
#include <inttypes.h>
#include "comparison-services.h"
static jmp_buf path_failure_landing;
static jv path_failure_root, path_failure_key, path_failure_item, path_failure_kept[4];
static unsigned path_failure_callbacks, path_failure_marker=0x5a170123U;
static int path_failure_context_matches;
static void path_allocation_exhausted(void *context) {
  ++path_failure_callbacks;
  path_failure_context_matches=context==&path_failure_marker && path_failure_marker==0x5a170123U;
  longjmp(path_failure_landing,1);
}
static void failure_details(void) {
  printf(",\"allocation_failure\":{\"callbacks\":%u,\"context_preserved\":%s,"
    "\"failed_allocations\":%" PRIu64 ",\"requested_bytes\":%zu},\"references\":[",
    path_failure_callbacks,path_failure_context_matches?"true":"false",
    allocation_observer_failures(),allocation_observer_failed_size());
  for (unsigned i=0;i<4;++i) printf("%s%d",i?",":"",jv_get_refcnt(path_failure_kept[i]));
  printf("],\"alias_matrix\":[");
  for (unsigned i=0;i<4;++i) for (unsigned j=0;j<4;++j) {
    jv a=path_failure_kept[i],b=path_failure_kept[j];
    printf("%s%d",i||j?",":"",(a.kind_flags&128U) && (b.kind_flags&128U) && a.u.ptr==b.u.ptr);
  }
  printf("]");
}
static void warm_native_numbers(void) {
  jv number=input("0");(void)jv_number_value(number);jv_free(number);
}
static int path_allocation_failure(const char *root, const char *key, const char *item, int warm_numbers) {
  if (warm_numbers) warm_native_numbers();
  allocation_observer_begin();
  path_failure_root=input(root);path_failure_key=input(key);path_failure_item=input(item);
  path_failure_kept[0]=jv_copy(path_failure_root);path_failure_kept[1]=jv_copy(path_failure_key);
  path_failure_kept[2]=jv_copy(path_failure_item);path_failure_kept[3]=jv_number(12345);
  jv_nomem_handler(path_allocation_exhausted,&path_failure_marker);
#if SPX_COMPARISON_NONLOCAL
  uint32_t handler=path_use_selected?spx_service_handler_begin():0;
#endif
  if (!setjmp(path_failure_landing)) {
    allocation_observer_fail_next_malloc();
#if PATH_IS_SET
    path_failure_kept[3]=path_use_selected?PATH_ENTRY(path_failure_root,path_failure_key,path_failure_item):
      PATH_ORIGINAL(path_failure_root,path_failure_key,path_failure_item);
#else
    path_failure_kept[3]=path_use_selected?PATH_ENTRY(path_failure_root,path_failure_key):
      PATH_ORIGINAL(path_failure_root,path_failure_key);
#endif
    fputs("guarded allocation unexpectedly returned after injected failure\n",stderr);return 86;
  }
#if SPX_COMPARISON_NONLOCAL
  if (path_use_selected) {
    spx_service_handler_catch(handler,"nomem");spx_service_handler_end(handler);
  }
#endif
  allocation_observer_pause(1);
  printf("{\"outcome\":\"nonlocal-nomem\",");emit("result",jv_copy(path_failure_kept[3]));printf(",");
  emit("root_after",jv_copy(path_failure_kept[0]));printf(",");emit("key_after",jv_copy(path_failure_kept[1]));printf(",");
  emit("item_after",jv_copy(path_failure_kept[2]));printf(",\"readback\":null");failure_details();
  allocation_observer_pause(0);
  for (unsigned i=0;i<4;++i) release_observed(path_failure_kept[i]);
#if !PATH_IS_SET
  release_observed(path_failure_item);
#endif
  finish_observation();return 0;
}
