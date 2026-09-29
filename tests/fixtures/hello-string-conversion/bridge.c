#include "portable-component-implementation.h"
#include "comparison-selection.h"
#include "string-objects.h"
#include "string-runtime.h"
#include "string-entry.h"
#include "pe32-entry-hook.h"
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct spx_opaque_mb_bytes_v5 Bytes;
typedef struct spx_opaque_mb_state_v5 State;
typedef struct spx_opaque_mb_word16_v5 Word16;
typedef struct spx_opaque_mb_cursor_v5 Cursor;
static unsigned char *image;
static spx_fixture_entry_hook decoder;
static unsigned mode, calls, event_count;
static int selected;
struct Event { uint32_t size, result, before, after, has_output, output; unsigned char input[5]; };
static struct Event events[4096];

static void require(int okay, const char *message) {
    if (!okay) { fprintf(stderr,"string adapter: %s\n",message); exit(2); }
}
static uint32_t load(const void *p) { uint32_t v; memcpy(&v,p,4); return v; }
static void set_errno(void *unused, uint32_t number) {
    (void)unused; int *(*get)(void)=(void *)(uintptr_t)load(image+0x321e4); *get()=(int)number;
}
static void invalid_state(void *unused) {
    (void)unused; void (*call)(void)=(void *)(uintptr_t)load(image+0x32204); call();
    require(0,"native abort returned");
}
static uint32_t traced_decode(uint16_t *output, const unsigned char *input, uint32_t size, void *state);
static void install_decoder(void) {
    require(spx_fixture_redirect_address_body(&decoder,image+0x7214,decoder.saved,5,
        (void (*)(void))traced_decode),"decoder observation entry");
}
static uint32_t traced_decode(uint16_t *output, const unsigned char *input, uint32_t size, void *state) {
    require(event_count<4096 && size>=1 && size<=5 && state,"bounded decoder interaction");
    struct Event *event=&events[event_count++];
    *event=(struct Event){.size=size,.before=load(state),.has_output=output!=NULL};
    memcpy(event->input,input,size);
    uint32_t result;
    if (mode==2) {
        /* Explicit controlled synchronous service, shared by both sides. */
        uint32_t next=load(state)+1; memcpy(state,&next,4);
        result=input[0]==0xfe ? UINT32_MAX-1U : input[0]==0xfd ? UINT32_MAX : input[0] ? 1 : 0;
        if (result<UINT32_MAX-1U && output) *output=input[0];
        if (result==UINT32_MAX) set_errno(NULL,7);
    } else {
        require(spx_fixture_restore_entry(&decoder),"restore actual decoder");
        uint32_t (*call)(uint16_t *,const unsigned char *,uint32_t,void *)=(void *)(image+0x7214);
        result=call(output,input,size,state);
        install_decoder();
    }
    event->result=result; event->after=load(state); event->output=output ? *output : 0;
    return result;
}
static uint32_t decode16(void *unused,Word16 *output,Bytes *input,uint32_t size,State *state) {
    (void)unused;
    uint32_t (*call)(uint16_t *,const unsigned char *,uint32_t,void *)=(void *)(image+0x7214);
    return call(output ? output->value : NULL,input->data,size,state->data);
}
static uint32_t replacement(uint16_t *output,const unsigned char **input,uint32_t limit,void *state) {
    ++calls;
    State explicit_state={state},implicit={image+0x30300};
    Word16 destination={output}; Cursor cursor={input};
    const spx_string_conversion_services_v5 services={.decode16=decode16,.set_errno=set_errno,
        .invalid_state=invalid_state};
    spx_string_conversion_context_v5 context={.services=&services,.state={.implicit=&implicit}};
    return string_convert(&context,output ? &destination : NULL,&cursor,limit,state ? &explicit_state : NULL);
}
static void install_body(void) {
    require(spx_install_string_entry_at(image,(void (*)(void))replacement),
        "replace reviewed string body and cold fragment");
}
void fixture_string_initialize(unsigned char *loaded,int source,unsigned context) {
    require(!image && loaded && context<3,"single image and declared context");
    image=loaded;mode=context;selected=source;
    require(setlocale(LC_ALL,mode==1 ? "Japanese_Japan.932" : "C")!=NULL,"locale available");
    unsigned char prefix[5]; memcpy(prefix,image+0x7214,5);
    require(spx_fixture_redirect_address_body(&decoder,image+0x7214,prefix,5,
        (void (*)(void))traced_decode),"observe original decoder");
    if (source) install_body();
}
uint32_t fixture_string_calls(void) { return calls; }
static void check_body_absence(void) {
    if (selected) require(spx_install_string_entry_intact(),"string body and cold fragment remain absent");
}
void fixture_string_observe(void) {
    check_body_absence();
    printf("[");
    for (unsigned i=0;i<event_count;++i) {
        const struct Event *e=&events[i];
        printf("%s[%u,%u,%u,%u,%u,%u,\"",i ? "," : "",e->size,e->result,e->before,e->after,e->has_output,e->output);
        for (unsigned j=0;j<e->size;++j) printf("%02x",e->input[j]);
        printf("\"]");
    }
    printf("]"); event_count=0;
}

/* Ordinary target adapter for experimental normal-entry assembly. The public
 * component comparison compiles this same file; its EXE does not call DllMain.
 * A DLL link uses it without the comparison driver. Existing conversion hooks
 * remain in place and are reached through decode16's live entry on every call. */
void fixture_string_program_initialize(unsigned char *loaded,int source) {
    require(!image && loaded,"single program image");
    image=loaded;selected=source;
    if (selected) install_body();
}
uint32_t fixture_string_program_implicit(void) {
    check_body_absence();return load(image+0x30300);
}
#ifndef SPX_COMPARISON_PROGRAM
static FILE *program_report;
__declspec(dllexport) void spx_hello_string_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved) {
    (void)module;(void)reserved;
    if (reason==DLL_PROCESS_ATTACH) {
        char side[32],path[32768];
        DWORD n=GetEnvironmentVariableA("SPX_HELLO_PROGRAM_SIDE",side,sizeof(side));
        if (!n || n>=sizeof(side)) return FALSE;
        n=GetEnvironmentVariableA("SPX_HELLO_PROGRAM_REPORT",path,sizeof(path)-8);
        if (!n || n>=sizeof(path)-8) return FALSE;
        memcpy(path+n,".string",8); program_report=fopen(path,"wb");
        if (!program_report) return FALSE;
        fixture_string_program_initialize((void *)GetModuleHandleA(NULL),!strcmp(side,"source"));
    } else if (reason==DLL_PROCESS_DETACH && program_report) {
        fprintf(program_report,"{\"source\":%d,\"calls\":%u,\"implicit\":%u}\n",selected,calls,load(image+0x30300));
        fclose(program_report);program_report=NULL;
    }
    return TRUE;
}
#endif
