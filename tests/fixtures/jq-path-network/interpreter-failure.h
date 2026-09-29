/* A real interpreter reaches the selected setpath entry before failure is armed.
 * The observer retains caller aliases on both sides. Original execution restores
 * the pinned entry before calling it; no trampoline or substitute oracle is used. */
static jq_state *failure_jq;
static spx_fixture_entry_hook failure_hooks[5];
static int failure_hook_active[5];
static unsigned failure_string_calls;
#ifdef SPX_SELECTED_STRING_SLICE
static jv failure_string_entry(jv value,int start,int end) {
  if (++failure_string_calls!=1) exit(85);
  path_failure_kept[0]=jv_copy(value);path_failure_kept[1]=jv_number(start);
  path_failure_kept[2]=jv_number(end);path_failure_kept[3]=jv_number(12345);
  if (!path_use_selected) {
    if (!spx_fixture_restore_entry(&failure_hooks[4])) exit(85);
    failure_hook_active[4]=0;
  }
  allocation_observer_fail_next_malloc();
  return path_use_selected?fixture_string_slice(value,start,end):jv_string_slice(value,start,end);
}
#endif
static jv failure_setpath_entry(jv root,jv key,jv item) {
  if (++path_calls[3]!=1) exit(85);
  path_failure_kept[0]=jv_copy(root);path_failure_kept[1]=jv_copy(key);
  path_failure_kept[2]=jv_copy(item);path_failure_kept[3]=jv_number(12345);
  if (!path_use_selected) {
    if (!spx_fixture_restore_entry(&failure_hooks[3])) exit(85);
    failure_hook_active[3]=0;
  }
  allocation_observer_fail_next_malloc();
  return path_use_selected?fixture_path_set(root,key,item):jv_setpath(root,key,item);
}
static int program_allocation_failure_kind(const char *program,const char *json,int string_failure) {
  failure_jq=jq_init();
  if (!failure_jq || !jq_compile(failure_jq,program)) return 5;
  warm_native_numbers();
  const unsigned char prefixes[4][5]={{0x56,0x53,0x81,0xec,0xc4},
    {0x55,0x57,0x56,0x53,0x81},{0x56,0x53,0x81,0xec,0xc4},{0x56,0x53,0x81,0xec,0x64}};
  const char *symbols[4]={"jv_get","jv_set","jv_getpath","jv_setpath"};
  void (*replacements[4])(void)={(void(*)(void))counted_get,(void(*)(void))counted_set,
    (void(*)(void))counted_getpath,(void(*)(void))(string_failure?counted_setpath:failure_setpath_entry)};
  for (unsigned i=0;i<4;++i) if (path_use_selected || (!string_failure && i==3)) {
    if (!spx_fixture_redirect_body(&failure_hooks[i],"libjq-1.dll",symbols[i],prefixes[i],
        i==1?10:8,replacements[i])) return 5;
    failure_hook_active[i]=1;
  }
#ifdef SPX_SELECTED_STRING_SLICE
  if (string_failure) {
    const unsigned char prefix[5]={0x55,0x57,0x56,0x53,0x81};
    if (!spx_fixture_redirect_body(&failure_hooks[4],"libjq-1.dll","jv_string_slice",prefix,
        0x33b,(void(*)(void))failure_string_entry)) return 5;
    failure_hook_active[4]=1;
  }
#endif
  jq_set_nomem_handler(failure_jq,path_allocation_exhausted,&path_failure_marker);
  allocation_observer_begin();
#if SPX_COMPARISON_NONLOCAL
  uint32_t handler=path_use_selected?spx_service_handler_begin():0;
#endif
  if (!setjmp(path_failure_landing)) {
    jq_start(failure_jq,input(json),0);
    jv value=jq_next(failure_jq);jv_free(value);
    fputs("interpreter did not deliver the selected allocation failure\n",stderr);return 86;
  }
#if SPX_COMPARISON_NONLOCAL
  if (path_use_selected) {
    spx_service_handler_catch(handler,"nomem");spx_service_handler_end(handler);
  }
#endif
  for (unsigned i=0;i<5;++i) if (failure_hook_active[i]) {
    if (!spx_fixture_restore_entry(&failure_hooks[i])) return 5;
    failure_hook_active[i]=0;
  }
  if ((string_failure?failure_string_calls:path_calls[3])!=1) return 85;
  fprintf(stderr,"interpreter-failure-entry side=%s setpath=%u string-slice=%u\n",
    path_use_selected?"source":"original",path_calls[3],failure_string_calls);
  jq_teardown(&failure_jq);
  allocation_observer_pause(1);
  printf("{\"outcome\":\"program-nonlocal-nomem\",");emit("result",jv_copy(path_failure_kept[3]));printf(",");
  emit("root_after",jv_copy(path_failure_kept[0]));printf(",");emit("key_after",jv_copy(path_failure_kept[1]));printf(",");
  emit("item_after",jv_copy(path_failure_kept[2]));printf(",\"readback\":null");failure_details();
  allocation_observer_pause(0);
  for (unsigned i=0;i<4;++i) release_observed(path_failure_kept[i]);
  finish_observation();return 0;
}
static int program_allocation_failure(const char *program,const char *json) {
  return program_allocation_failure_kind(program,json,0);
}
#ifdef SPX_SELECTED_STRING_SLICE
static int program_string_allocation_failure(const char *program,const char *json) {
  return program_allocation_failure_kind(program,json,1);
}
#endif
