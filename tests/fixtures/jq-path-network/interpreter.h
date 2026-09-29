/* Fixture-only PE32 entry redirection into all four authored operations.
 * Only entry instructions are replaced. This does not establish body absence,
 * arbitrary native ingress safety, or permission to activate a provider. */
#include "pe32-entry-hook.h"
#include "jq.h"
static unsigned path_calls[4];
static jv counted_get(jv v,jv k) { ++path_calls[0]; return fixture_value_get(v,k); }
static jv counted_set(jv v,jv k,jv i) { ++path_calls[1]; return fixture_value_set(v,k,i); }
static jv counted_getpath(jv v,jv k) { ++path_calls[2]; return fixture_path_get(v,k); }
static jv counted_setpath(jv v,jv k,jv i) { ++path_calls[3]; return fixture_path_set(v,k,i); }
#if PATH_ALLOCATION_OBSERVER
#include "interpreter-failure.h"
#endif
static int program_case(const char *program, const char *json) {
  jq_state *jq=jq_init();
  if (!jq || !jq_compile(jq,program)) return 5;
  spx_fixture_entry_hook hooks[4]={{0}};
  const unsigned char prefixes[4][5]={{0x56,0x53,0x81,0xec,0xc4},
    {0x55,0x57,0x56,0x53,0x81},{0x56,0x53,0x81,0xec,0xc4},{0x56,0x53,0x81,0xec,0x64}};
  const char *symbols[4]={"jv_get","jv_set","jv_getpath","jv_setpath"};
  void (*replacements[4])(void)={(void(*)(void))counted_get,(void(*)(void))counted_set,
    (void(*)(void))counted_getpath,(void(*)(void))counted_setpath};
  for (unsigned i=0;i<4 && path_use_selected;++i)
    if (!spx_fixture_redirect_body(&hooks[i],"libjq-1.dll",symbols[i],prefixes[i],i==1?10:8,replacements[i])) {
      fprintf(stderr,"failed pinned entry binding: %s\n",symbols[i]); return 5;
    }
#if PATH_ALLOCATION_OBSERVER
  allocation_observer_begin();
#endif
  jq_start(jq,input(json),0);
  jv values=jv_array(), error=jv_null();
  for (;;) {
    jv value=jq_next(jq);
    if (!jv_is_valid(value)) {
      if (jv_invalid_has_msg(jv_copy(value))) error=jv_invalid_get_msg(value);
      else jv_free(value);
      break;
    }
    values=jv_array_append(values,value);
  }
  jq_teardown(&jq);
  for (unsigned i=0;i<4 && path_use_selected;++i)
    if (!spx_fixture_restore_entry(&hooks[i])) return 5;
  if (path_use_selected) {
    fprintf(stderr,"authored-entry-calls get=%u set=%u getpath=%u setpath=%u\n",
            path_calls[0],path_calls[1],path_calls[2],path_calls[3]);
    if (!(path_calls[0]+path_calls[1]+path_calls[2]+path_calls[3])) return 6;
  }
#if PATH_ALLOCATION_OBSERVER
  allocation_observer_pause(1);
#endif
  printf("{\"outcome\":\"program\",");emit("result",jv_copy(values));printf(",");emit("readback",jv_copy(error));
  printf(",\"root_after\":null,\"key_after\":null,\"item_after\":null");
#if PATH_ALLOCATION_OBSERVER
  printf(",\"allocation_failure\":null,\"references\":null,\"alias_matrix\":null");
  allocation_observer_pause(0);
#endif
  release_observed(values);release_observed(error);finish_observation();
  return 0;
}
