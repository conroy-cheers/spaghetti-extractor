/* Finite controlled get service for the real getpath consumer. All native get
 * bytes are replaced while callers run. The source get implementation is not
 * linked. Separate service mode checks the same transcript against native get.
 * This is executable local evidence, not a checked summary or activation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-api.h"
#include "controlled-mode.h"
#include "pe32-entry-hook.h"
#if CONTROLLED_ARRAY_STORAGE
#include "allocation-observer.h"
#endif

static jv steps, observations;
static int position;
int path_use_selected;
static void premise(const char *message) {
  fprintf(stderr, "controlled get premise failed: %s\n", message);
  exit(4);
}
static jv field(jv value, const char *name) {
  return jv_object_get(jv_copy(value), jv_string(name));
}
static jv outcome(jv value) {
  if (jv_is_valid(value)) return jv_object_set(jv_object(),jv_string("value"),value);
  return jv_object_set(jv_object(),jv_string("error"),jv_invalid_get_msg(value));
}
static void equal(jv actual, jv expected, const char *message) {
  if (!jv_equal(actual,expected)) premise(message);
}
static jv controlled_get(jv value, jv key) {
  if (position >= jv_array_length(jv_copy(steps))) premise("unexpected call");
  jv step=jv_array_get(jv_copy(steps),position++);
  equal(jv_copy(value),field(step,"root"),"root differs from current state");
  equal(jv_copy(key),field(step,"key"),"key differs from next path element");
  jv expected=field(step,"outcome");
  jv result;
  if (jv_object_has(jv_copy(expected),jv_string("value"))) result=field(expected,"value");
  else if (jv_object_has(jv_copy(expected),jv_string("error")))
    result=jv_invalid_with_msg(field(expected,"error"));
  else { premise("outcome must be explicit value or error"); result=jv_invalid(); }
  jv_free(value);jv_free(key);jv_free(expected);
  observations=jv_array_append(observations,step);
  return result;
}
jv path_dispatch_get(jv value,jv key) { return controlled_get(value,key); }
static void emit(const char *name,jv value) {
  jv text=jv_dump_string(value,JV_PRINT_SORTED);
  printf("\"%s\":%s",name,jv_string_value(text));jv_free(text);
}
int main(int argc,char **argv) {
  if (argc!=6 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
  path_use_selected=!strcmp(argv[1],"source");
#if CONTROLLED_ARRAY_STORAGE
  allocation_observer_begin();
#endif
  jv root=jv_parse(argv[2]),key=jv_parse(argv[3]);steps=jv_parse(argv[4]);
  if (!jv_is_valid(root)||!jv_is_valid(key)||jv_get_kind(steps)!=JV_KIND_ARRAY) return 2;
  observations=jv_array();
  jv kept_root=jv_copy(root),kept_key=jv_copy(key),result;
  int erased=0;

  if (!strcmp(argv[5],"service")) {
    /* Supplier conformance, in a separate run with no erased body. */
    result=path_use_selected?controlled_get(root,key):jv_get(root,key);
    if (!path_use_selected) {
      if(jv_array_length(jv_copy(steps))!=1) premise("service scenario needs one call");
      jv step=jv_array_get(jv_copy(steps),0);
      equal(jv_copy(kept_root),field(step,"root"),"service root");
      equal(jv_copy(kept_key),field(step,"key"),"service key");
      equal(outcome(jv_copy(result)),field(step,"outcome"),"native outcome outside scenario");
      observations=jv_array_append(observations,step);position=1;
    }
  }
#if !CONTROLLED_SERVICE_ONLY
  else if (!strcmp(argv[5],"caller")) {
    spx_fixture_entry_hook hook={0};
    const unsigned char prefix[5]={0x56,0x53,0x81,0xec,0xc4};
    /* Pinned DLL COFF symbols: jv_get .text+0x2e806, next jv_set +0x2f2b4.
     * All 2734 bytes are replaced, including internal branch destinations. */
    if(!spx_fixture_redirect_body(&hook,"libjq-1.dll","jv_get",prefix,2734,
                                  (void(*)(void))controlled_get)) premise("native body binding");
    for(size_t i=5;i<hook.length;++i) if(hook.entry[i]!=0xcc) premise("body remains executable");
    result=path_use_selected?fixture_path_get(root,key):jv_getpath(root,key);
    for(size_t i=5;i<hook.length;++i) if(hook.entry[i]!=0xcc) premise("body changed during call");
    if(!spx_fixture_restore_entry(&hook)) premise("body restore");
    erased=2734;
    fprintf(stderr,"controlled get: removed 2734 native bytes; calls=%d; side=%s\n",position,argv[1]);
  }
#endif
  else return 2;
  if(position!=jv_array_length(jv_copy(steps))) premise("missing required calls");
  int root_refs=jv_get_refcnt(kept_root),key_refs=jv_get_refcnt(kept_key);
#if CONTROLLED_ARRAY_STORAGE
  allocation_observer_pause(1);
#endif
  printf("{");emit("outcome",outcome(result));printf(",");emit("root_after",kept_root);
  printf(",");emit("key_after",kept_key);printf(",");emit("calls",observations);
  printf(",\"body_absence\":%d,\"references\":[%d,%d]",erased,root_refs,key_refs);
  jv_free(steps);
  printf(",\"allocation_lifetime\":");
#if CONTROLLED_ARRAY_STORAGE
  allocation_observer_finish(stdout);
#else
  printf("null");
#endif
  printf("}\n");return 0;
}
