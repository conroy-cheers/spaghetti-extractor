/* Optional ordinary C DLL entry for the normal-process experiment. Both sides
 * run the same observer; only the source side installs component replacements.
 * Original PE entry/startup and original TLS callback bodies remain executable.
 * This is finite instrumentation, never qualified native admission. */
#if HELLO_NATIVE_PROGRAM
static PIMAGE_TLS_CALLBACK program_tls[2];
static uint32_t program_tls_calls[2][4];
static FILE *program_report;
static uint32_t program_handler;
static spx_fixture_import_hook program_exit_hook;
static uint32_t program_exit_code,program_exit_seen;
#if SPX_SELECTED_STRING_CONVERSION
void fixture_string_program_initialize(unsigned char *,int);
uint32_t fixture_string_program_implicit(void);
uint32_t fixture_string_calls(void);
#endif

static void program_exit(int status) {
  program_exit_seen=1;program_exit_code=(uint32_t)status;
  /* Hello's actual atexit callback closes stderr. Complete the enclosing
   * observation before forwarding exit; it does not replace CRT termination. */
  if(source_side){spx_service_handler_end(program_handler);program_handler=0;}
  void (*call)(int)=(void *)(uintptr_t)program_exit_hook.original;call(status);
  ExitProcess(125); /* The original exit import is nonreturning. */
}

static void NTAPI program_tls_first(void *module,DWORD reason,void *reserved) {
  if(reason<4)++program_tls_calls[0][reason];
  program_tls[0](module,reason,reserved);
}
static void NTAPI program_tls_second(void *module,DWORD reason,void *reserved) {
  if(reason<4)++program_tls_calls[1][reason];
  program_tls[1](module,reason,reserved);
}

static void program_observe_tls(void) {
  PIMAGE_TLS_CALLBACK *callbacks=(void *)(image+0x2810c);
  native_require(callbacks[0]==(PIMAGE_TLS_CALLBACK)(image+0xa2f0) &&
      callbacks[1]==(PIMAGE_TLS_CALLBACK)(image+0xa2a0) && !callbacks[2],"reviewed original TLS callbacks");
  program_tls[0]=callbacks[0];program_tls[1]=callbacks[1];
  DWORD old,ignored;
  native_require(VirtualProtect(callbacks,8,PAGE_READWRITE,&old),"TLS observation protection");
  callbacks[0]=program_tls_first;callbacks[1]=program_tls_second;
  native_require(VirtualProtect(callbacks,8,old,&ignored),"TLS observation publication");
}

static void program_write_report(void) {
  if(!program_report)return;
  uint32_t conversion[4];fixture_multibyte_counts(conversion);
#if HELLO_PUBLIC_COMPARISON
  /* These were checked by the former program runner. Keep them in the observer
   * when the generic engine compares the declared state and actual streams. */
  if(program_exit_seen!=1 || program_tls_calls[0][1]!=1 || program_tls_calls[1][1]!=1 ||
      (source_side && conversion[3]!=1)) {
    fputs("{\"error\":\"program exit, TLS or selected reset was not observed\"}\n",program_report);
    fclose(program_report);program_report=NULL;return;
  }
  fprintf(program_report,"{\"side\":\"%s\",\"exit_code\":%u,\"observations\":{\"tls_calls\":[",
      source_side?"source":"original",program_exit_code);
#else
  fprintf(program_report,"{\"source\":%s,\"exit_seen\":%u,\"exit_code\":%u,\"tls_calls\":[",
      source_side?"true":"false",program_exit_seen,program_exit_code);
#endif
  for(unsigned i=0;i<2;++i) {
    fprintf(program_report,"%s[",i?",":"");
    for(unsigned j=0;j<4;++j)fprintf(program_report,"%s%u",j?",":"",program_tls_calls[i][j]);
    fputc(']',program_report);
  }
  fprintf(program_report,"],\"allocation_events\":[");
  for(unsigned i=0;i<event_count;++i) {
    fprintf(program_report,"%s[",i?",":"");
    for(unsigned j=0;j<4;++j)fprintf(program_report,"%s%u",j?",":"",allocation_events[i][j]);
    fputc(']',program_report);
  }
  fprintf(program_report,"],\"remaining_allocations\":[");
  unsigned count=0;
  for(unsigned i=0;i<allocation_count;++i)if(allocations[i].alive)
    fprintf(program_report,"%s[%u,%u]",count++?",":"",i+1,allocations[i].bytes);
  fprintf(program_report,"],\"implicit_states\":[%u,%u]",word(0x30314),word(0x30318));
#if SPX_SELECTED_STRING_CONVERSION
  fprintf(program_report,",\"string_implicit\":%u",fixture_string_program_implicit());
#endif
#if HELLO_PUBLIC_COMPARISON
  fputs("},\"diagnostics\":{",program_report);
#else
  fputc(',',program_report);
#endif
  fprintf(program_report,"\"source_calls\":[");
  for(unsigned i=0;i<5;++i)fprintf(program_report,"%s%u",i?",":"",source_calls[i]);
  fprintf(program_report,"],\"checked_calls\":[");
  for(unsigned i=0;i<8;++i)fprintf(program_report,"%s%u",i?",":"",checked_calls[i]);
  fprintf(program_report,"],\"conversion_calls\":[");
  for(unsigned i=0;i<4;++i)fprintf(program_report,"%s%u",i?",":"",conversion[i]);
  fprintf(program_report,"],\"quote_engine_calls\":%u",quote_engine_calls);
#if SPX_SELECTED_STRING_CONVERSION
  fprintf(program_report,",\"string_calls\":%u",fixture_string_calls());
#endif
  fputc('}',program_report);
#if HELLO_PUBLIC_COMPARISON
  fputc('}',program_report);
#endif
  fputc('\n',program_report);
  int failed=ferror(program_report) || fflush(program_report);
  if(fclose(program_report))failed=1;
  program_report=NULL;
  if(failed)OutputDebugStringA("Hello program observation could not be written");
}

__declspec(dllexport) void spx_hello_program_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void *reserved) {
  (void)module;(void)reserved;
  if(reason==DLL_PROCESS_ATTACH) {
    char side[16],path[4096];
#if HELLO_PUBLIC_COMPARISON
    const char *side_variable="SPX_COMPARISON_SIDE",*report_variable="SPX_COMPARISON_REPORT";
#else
    const char *side_variable="SPX_HELLO_PROGRAM_SIDE",*report_variable="SPX_HELLO_PROGRAM_REPORT";
#endif
    DWORD size=GetEnvironmentVariableA(side_variable,side,sizeof(side));
    if(!size || size>=sizeof(side) || (strcmp(side,"original") && strcmp(side,"source")))return FALSE;
    size=GetEnvironmentVariableA(report_variable,path,sizeof(path));
    if(!size || size>=sizeof(path))return FALSE;
    program_report=fopen(path,"wb");if(!program_report)return FALSE;
    image=(void *)GetModuleHandleA(NULL);image_module=NULL;program_mode=1;
    IMAGE_DOS_HEADER *dos=(void *)image;IMAGE_NT_HEADERS32 *nt=(void *)(image+dos->e_lfanew);
    native_require(nt->OptionalHeader.AddressOfEntryPoint==HELLO_ORIGINAL_ENTRY &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress==HELLO_ORIGINAL_TLS,
        "original program entry and TLS directory");
    program_observe_tls();
    native_install(!strcmp(side,"source"));
#if SPX_SELECTED_STRING_CONVERSION
    fixture_string_program_initialize(image,source_side);
#endif
    native_require(spx_fixture_redirect_import(&program_exit_hook,NULL,"msvcrt.dll","exit",
        (void (*)(void))program_exit),"observe original process exit");
    if(source_side)program_handler=spx_service_handler_begin();
  } else if(reason==DLL_PROCESS_DETACH)program_write_report();
  return TRUE;
}
#endif
