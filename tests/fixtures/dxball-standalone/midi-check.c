/* The actual SDK adapter and exported stream C, driven by the existing shared
 * Wine environment. Including the adapter lets this boundary check identify its
 * callback and inspect SDK storage; the backend knows no application layout. */
#include <stdio.h>
#include <string.h>
#include "win32-midi.c"
#include "spx-wine-test.h"
#include "mds-loader-runtime.h"
#include "mds-parser-runtime.h"

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "MIDI assembly check line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static LONG completions;
static void observed(void *u, const spx_wine_event *event) {
    (void)u;
    if (event->api==SPX_MIDI_CALLBACK && event->arguments[0]==MOM_DONE) InterlockedIncrement(&completions);
}
int main(int argc, char **argv) {
    REQUIRE(argc==2);
    const char *mode=argv[1];
    int native=!strncmp(mode,"native",6), reset=!strcmp(mode,"native-reset"), looping=!strcmp(mode,"native-loop");
    spx_wine_env *env=spx_wine_create(native ? SPX_WINE_NATIVE : SPX_WINE_CONTROLLED);
    spx_wine_set_hooks(env,(spx_wine_hooks){.after=observed});
    void (CALLBACK *sdk_callback)(HMIDIOUT,UINT,DWORD_PTR,DWORD_PTR,DWORD_PTR)=completed;
    spx_wine_midi_callback callback;
    _Static_assert(sizeof(callback)==sizeof(sdk_callback), "PE32 callback identity transport");
    memcpy(&callback,&sdk_callback,sizeof(callback));
    spx_wine_bind_midi_callback(env,callback,0,1);
    REQUIRE(spx_wine_install_midi(env,NULL,SPX_WINE_MIDI_ALL));
    mds_info *info=loader_allocate(NULL,0x40,36); REQUIRE(info);
    info->signature=0x4953444d; info->division=96; info->capacity=12; info->count=2;
    mds_memory *allocation=parser_allocate(NULL,0x2002,2*(64+12)); REQUIRE(allocation);
    info->buffers=parser_lock(NULL,info,allocation); REQUIRE(info->buffers);
    for (unsigned i=0;i<2;++i) {
        mds_buffer *b=&info->buffers->headers[i];
        /* Explicit incoming allocation history; the original parser writes only
         * the first six header words. Remaining words belong to the provider. */
        memset(b->payload-64,0,64+12);
        uint32_t events[3]={reset ? 100000 : looping ? 1 : 0,0,0x02000000};
        memcpy(b->payload,events,sizeof(events));
        b->event=(mds_event_block){b->payload,12,12}; b->owner=info; b->flags=0; b->next=NULL;
    }
    spx_wine_bind_midi_user(env,(uintptr_t)info,1);
    int fail_open=!strcmp(mode,"fail-open");
    if (fail_open) spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_OPEN,.flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE,.result=2});
    uint32_t start=fixture_mds_start(info,!native || looping);
    if (fail_open) REQUIRE(start==5 && !info->stream && !info->pending);
    else {
        /* A missing native MIDI device is a capability result, never a pass. */
        REQUIRE(!start && info->stream);
        if (!strncmp(mode,"provider-",9)) {
            midi_header *h=header_for(info,&info->buffers->headers[0]);
            midi_header *other=header_for(info,&info->buffers->headers[1]);
            /* A provider update after import must survive an unchanged C view,
             * including an API failure that writes no output fields. */
            if (!strcmp(mode,"provider-link")) h->native.lpNext=&other->native;
            else { REQUIRE(!strcmp(mode,"provider-flags")); h->native.dwFlags|=0x40000000; }
            mds_header view={h->buffer};
            REQUIRE(stream_queue(NULL,info,&view,64)==65);
            if (!strcmp(mode,"provider-link")) REQUIRE(h->native.lpNext==&other->native);
            else REQUIRE(h->native.dwFlags&0x40000000);
        }
        if (native && !reset) {
            LONG wanted=looping ? 4 : 2;
            for (unsigned i=0;i<3000 && InterlockedCompareExchange(&completions,0,0)<wanted;++i) Sleep(1);
            REQUIRE(InterlockedCompareExchange(&completions,0,0)>=wanted);
            REQUIRE(info->pending==(looping ? 2U : 0U));
        } else if (!native) {
            midi_header *h=header_for(info,&info->buffers->headers[0]);
            spx_wine_midi_complete(env,info->stream,spx_wine_midi_header_identity(env,&h->native));
            REQUIRE(completions==1 && info->pending==2); /* loop requeues */
        }
        REQUIRE(!fixture_mds_pause(info));
        REQUIRE(!fixture_mds_stop(info) && !info->stream && !info->pending);
        REQUIRE(looping ? completions>=6 : completions==(native ? 2 : 3));
    }
    REQUIRE(!fixture_mds_release(info));
    spx_observer out=spx_observe_begin(stdout);
    spx_observe_u64(&out,"start",start); spx_observe_u64(&out,"completions",completions);
    spx_wine_observe(env,&out,"platform"); REQUIRE(spx_observe_finish(&out)); puts("");
    spx_wine_destroy(env);
    return 0;
}
