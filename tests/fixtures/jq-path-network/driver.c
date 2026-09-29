/* Test-only ownership contexts. Each side runs in a fresh process. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "native-api.h"
#include "config.h"
#include "comparison-selection.h"
#ifdef SPX_SELECTED_STRING_SLICE
#include "string-native.h"
#endif
#if PATH_ALLOCATION_OBSERVER
#include "allocation-observer.h"
#include "array-native.h"
#endif

static void release_observed(jv value) {
#if PATH_ALLOCATION_OBSERVER
  jq_cell input=storage_pack(value);storage_selected=path_use_selected;
  storage_release(0,&input);
#else
  jv_free(value);
#endif
}
static void finish_observation(void) {
#ifdef SPX_SELECTED_STRING_SLICE
  if (path_use_selected) string_slice_report();
#endif
#if PATH_ALLOCATION_OBSERVER
  printf(",\"allocation_lifetime\":");allocation_observer_finish(stdout);
#endif
  printf("}\n");
}

static jv input(const char *text) {
  if (!strcmp(text, "@invalid")) return jv_invalid_with_msg(jv_string("injected invalid"));
  if (!strcmp(text, "@nan")) return jv_number(NAN);
  if (!strcmp(text, "@deep")) {
    jv path = jv_array();
    for (int i = 0; i < 10001; ++i) path = jv_array_append(path, jv_number(0));
    return path;
  }
  jv value = jv_parse(text);
  if (!jv_is_valid(value)) { fprintf(stderr, "invalid fixture JSON: %s\n", text); exit(6); }
  return value;
}
static void emit(const char *name, jv value) {
  if (!jv_is_valid(value))
    value = jv_object_set(jv_object(), jv_string("invalid"), jv_invalid_get_msg(value));
  jv text = jv_dump_string(value, JV_PRINT_SORTED);
  printf("\"%s\":%s", name, jv_string_value(text));
  jv_free(text);
}
#if PATH_ALLOCATION_OBSERVER
#include "allocation-failure.h"
#endif
#if PATH_NETWORK && PATH_IS_SET
#include "interpreter.h"
#endif
int main(int argc, char **argv) {
  if (argc != 6 || (strcmp(argv[1], "original") && strcmp(argv[1], "source"))) return 2;
  path_use_selected = !strcmp(argv[1], "source");
  const char *mode = argv[5];
#ifdef SPX_SELECTED_STRING_SLICE
  if (path_use_selected && strcmp(mode,"program-nomem-string")) string_slice_install();
#endif
#if PATH_ALLOCATION_OBSERVER
  if (!strcmp(mode,"nomem") || !strcmp(mode,"nomem-cold"))
    return path_allocation_failure(argv[2],argv[3],argv[4],!strcmp(mode,"nomem"));
#endif
#if PATH_NETWORK && PATH_IS_SET
  if (!strcmp(mode,"program")) return program_case(argv[2],argv[3]);
#if PATH_ALLOCATION_OBSERVER
  if (!strcmp(mode,"program-nomem")) return program_allocation_failure(argv[2],argv[3]);
#ifdef SPX_SELECTED_STRING_SLICE
  if (!strcmp(mode,"program-nomem-string")) return program_string_allocation_failure(argv[2],argv[3]);
#endif
#endif
#endif
  if (strcmp(mode,"retained") && strcmp(mode,"unique") && strcmp(mode,"alias-item") && strcmp(mode,"siblings")) return 2;
#if PATH_ALLOCATION_OBSERVER
  allocation_observer_begin();
#endif
  jv root=input(argv[2]), key=input(argv[3]), item=input(argv[4]);
  if (!strcmp(mode,"alias-item")) {
    jv_free(item); item=jv_copy(root);
    if (root.u.ptr != item.u.ptr) return 6;
  }
  if (!strcmp(mode,"siblings")) {
    jv shared=root;
    root=jv_object_set(jv_object(),jv_string("a"),jv_copy(shared));
    root=jv_object_set(root,jv_string("b"),shared);
    jv a=jv_object_get(jv_copy(root),jv_string("a")), b=jv_object_get(jv_copy(root),jv_string("b"));
    if (a.u.ptr != b.u.ptr) return 6;
    jv_free(a); jv_free(b);
  }
  int unique=!strcmp(mode,"unique");
  if (unique && (jv_get_kind(root)==JV_KIND_ARRAY || jv_get_kind(root)==JV_KIND_OBJECT) && jv_get_refcnt(root)!=1) return 6;
  jv kept_root=unique?jv_null():jv_copy(root), kept_key=jv_copy(key), kept_item=jv_copy(item);
  jv result;
#if PATH_IS_SET
  result = path_use_selected ? PATH_ENTRY(root,key,item) : PATH_ORIGINAL(root,key,item);
#else
  result = path_use_selected ? PATH_ENTRY(root,key) : PATH_ORIGINAL(root,key);
  jv_free(item);
#endif
  jv readback=jv_null();
#if PATH_NETWORK && PATH_IS_SET
  /* Consumer chain: setpath -> get/set, then getpath -> get. */
  if (jv_is_valid(result)) readback=path_dispatch_getpath(jv_copy(result),jv_copy(kept_key));
#endif
#if PATH_ALLOCATION_OBSERVER
  allocation_observer_pause(1);
#endif
  printf("{\"outcome\":\"%s\",",jv_is_valid(result)?"value":"invalid");
  emit("result",jv_copy(result)); printf(","); emit("root_after",jv_copy(kept_root)); printf(",");
  emit("key_after",jv_copy(kept_key)); printf(","); emit("item_after",jv_copy(kept_item)); printf(",");
  emit("readback",jv_copy(readback));
#if PATH_ALLOCATION_OBSERVER
  printf(",\"allocation_failure\":null,\"references\":null,\"alias_matrix\":null");
  allocation_observer_pause(0);
#endif
  release_observed(result);release_observed(kept_root);release_observed(kept_key);
  release_observed(kept_item);release_observed(readback);finish_observation();
  return 0;
}
