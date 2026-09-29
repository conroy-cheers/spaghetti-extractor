/* Test-only observer of original application-boundary calls, not their bodies.
 * Entry bytes are restored around every actual original call. Synchronous use
 * only. A separate run without this observer is always an output/exit veto;
 * allocation-fault cases apply the same lower service fault to both runs. */
#include "pe32-entry-hook.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned char *image;
static FILE *report;
static spx_fixture_entry_hook allocation, release, reset, decode, convert, entry, fatal;
static uint32_t allocated_bytes, allocations, releases, resets, decodes, conversions;
static uint32_t converted, cursor_null, word_hash, target_errno;
static uint32_t fatal_entries, fatal_errno;
static unsigned char conversion_state[4];
static char arguments[8][16384];
static unsigned argument_count, word_count;
static uint16_t first_words[16];

static void require(int success) { if (!success) ExitProcess(125); }
static void install(spx_fixture_entry_hook *hook, void (*function)(void)) {
    require(spx_fixture_redirect_address_body(hook,hook->entry,hook->saved,5,function));
}
static void *observed_allocate(uint32_t bytes) {
    ++allocations; allocated_bytes=bytes;
    require(spx_fixture_restore_entry(&allocation));
    void *(*call)(uint32_t)=(void *)allocation.entry;
    void *result=call(bytes);
    install(&allocation,(void (*)(void))observed_allocate);
    return result;
}
static void observed_fatal(void) {
    int *(*get_errno)(void); memcpy(&get_errno,image+0x321e4,4);
    fatal_errno=(uint32_t)*get_errno(); ++fatal_entries;
    require(spx_fixture_restore_entry(&fatal));
    void (*call)(void)=(void *)fatal.entry; call();
    /* The actual body is noreturn. No simulated exit is supplied. */
    ExitProcess(125);
}
static void observed_release(void *block) {
    ++releases; require(spx_fixture_restore_entry(&release));
    void (*call)(void *)=(void *)release.entry; call(block);
    install(&release,(void (*)(void))observed_release);
}
static void observed_reset(void *state) {
    ++resets; require(spx_fixture_restore_entry(&reset));
    void (*call)(void *)=(void *)reset.entry; call(state);
    install(&reset,(void (*)(void))observed_reset);
}
static uint32_t observed_decode(uint16_t *out,const unsigned char *input,uint32_t size,void *state) {
    ++decodes; require(spx_fixture_restore_entry(&decode));
    uint32_t (*call)(uint16_t *,const unsigned char *,uint32_t,void *)=(void *)decode.entry;
    uint32_t result=call(out,input,size,state);
    install(&decode,(void (*)(void))observed_decode);
    return result;
}
static uint32_t observed_convert(uint16_t *out,const unsigned char **input,uint32_t limit,void *state) {
    ++conversions; require(spx_fixture_restore_entry(&convert));
    uint32_t (*call)(uint16_t *,const unsigned char **,uint32_t,void *)=(void *)convert.entry;
    uint32_t result=call(out,input,limit,state);
    install(&convert,(void (*)(void))observed_convert);
    converted=result; cursor_null=*input==NULL;
    memcpy(conversion_state,state,4);
    word_hash=2166136261U;
    if (result<limit) for (uint32_t i=0;i<=result;++i) word_hash=(word_hash ^ out[i])*16777619U;
    if (result<limit) {
        word_count=result+1<16 ? result+1 : 16;
        for (unsigned i=0;i<word_count;++i) first_words[i]=out[i];
    }
    int *(*get_errno)(void); memcpy(&get_errno,image+0x321e4,4); target_errno=(uint32_t)*get_errno();
    return result;
}
static int observed_main(int argc,char **argv) {
    require(argc>=0 && argc<=8); argument_count=(unsigned)argc;
    for (int i=0;i<argc;++i) {
        unsigned n=0;
        while (n<16383 && argv[i][n]) { arguments[i][n]=argv[i][n]; ++n; }
        require(!argv[i][n]); arguments[i][n]=0;
    }
    require(spx_fixture_restore_entry(&entry));
    int (*call)(int,char **)=(void *)entry.entry;
    return call(argc,argv);
}
static void attach(spx_fixture_entry_hook *hook,uint32_t rva,void (*function)(void)) {
    unsigned char expected[5]; memcpy(expected,image+rva,5);
    require(spx_fixture_redirect_address_body(hook,image+rva,expected,5,function));
}
__declspec(dllexport) void spx_hello_observe(void) {}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,void *reserved) {
    (void)module;(void)reserved;
    if (reason==DLL_PROCESS_ATTACH) {
        char path[32768]; DWORD n=GetEnvironmentVariableA("SPX_ORIGINAL_REPORT",path,sizeof(path));
        if (!n || n>=sizeof(path) || !(report=fopen(path,"wb"))) return FALSE;
        image=(void *)GetModuleHandleA(NULL);
        attach(&allocation,0x622d,(void (*)(void))observed_allocate);
        attach(&release,0x1b34,(void (*)(void))observed_release);
        attach(&reset,0x2b28,(void (*)(void))observed_reset);
        attach(&decode,0x7214,(void (*)(void))observed_decode);
        attach(&convert,0x29a4,(void (*)(void))observed_convert);
        attach(&entry,0x14548,(void (*)(void))observed_main);
        attach(&fatal,0x658c,(void (*)(void))observed_fatal);
    } else if (reason==DLL_PROCESS_DETACH && report) {
        fprintf(report,"{\"allocated_bytes\":%u,\"allocations\":%u,\"releases\":%u,"
            "\"resets\":%u,\"decodes\":%u,\"conversions\":%u,\"converted\":%u,"
            "\"cursor_null\":%u,\"word_hash\":%u,\"target_errno\":%u,"
            "\"fatal_entries\":%u,\"fatal_errno\":%u,"
            "\"conversion_state\":[%u,%u,%u,%u],\"first_words\":[",
            allocated_bytes,allocations,releases,resets,decodes,conversions,converted,cursor_null,word_hash,target_errno,
            fatal_entries,fatal_errno,
            conversion_state[0],conversion_state[1],conversion_state[2],conversion_state[3]);
        for (unsigned i=0;i<word_count;++i) fprintf(report,"%s%u",i ? "," : "",first_words[i]);
        fprintf(report,"],\"argv_hex\":[");
        for (unsigned i=0;i<argument_count;++i) {
            fprintf(report,"%s\"",i ? "," : "");
            for (const unsigned char *p=(const unsigned char *)arguments[i];*p;++p) fprintf(report,"%02x",*p);
            fputc('"',report);
        }
        fprintf(report,"]}\n");
        int failed=ferror(report); if (fclose(report)) failed=1;
        report=NULL; if (failed) ExitProcess(125);
    }
    return TRUE;
}
