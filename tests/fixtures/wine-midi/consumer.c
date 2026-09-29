/* A small stream producer with two retained buffers and callback requeue. */
#include "spx-wine-test.h"
#include <stdio.h>
#include <string.h>
#include <stdatomic.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"MIDI consumer line %d\n",__LINE__);return 42; } } while(0)
static spx_wine_env *env;
static atomic_uint done,opened,closed;
static int requeue;
static int owner;
static uint32_t cleanup_results[2];
static uint32_t open_published;
#if defined(_WIN32) && !defined(USE_BINDING)
#define OPEN(out,device,callback,instance,flags) midiStreamOpen((LPHMIDISTRM)(out),(LPUINT)(device),1,(DWORD_PTR)(callback),instance,flags)
#define PROPERTY(s,p,f) midiStreamProperty((HMIDISTRM)(s),(LPBYTE)(p),f)
#define PREPARE(s,p) midiOutPrepareHeader((HMIDIOUT)(s),p,64)
#define QUEUE(s,p) midiStreamOut((HMIDISTRM)(s),p,64)
#define UNPREPARE(s,p) midiOutUnprepareHeader((HMIDIOUT)(s),p,64)
#define RESTART(s) midiStreamRestart((HMIDISTRM)(s))
#define PAUSE(s) midiStreamPause((HMIDISTRM)(s))
#define RESET(s) midiOutReset((HMIDIOUT)(s))
#define CLOSE(s) midiStreamClose((HMIDISTRM)(s))
#define ALLOC(n) ((uintptr_t)GlobalAlloc(0x42,n))
#define LOCK(h) GlobalLock((HGLOBAL)(h))
#define UNLOCK(h) GlobalUnlock((HGLOBAL)(h))
#define FREE(h) ((uintptr_t)GlobalFree((HGLOBAL)(h)))
#else
#define OPEN(out,device,callback,instance,flags) spx_wine_midi_open(env,out,device,1,callback,instance,flags)
#define PROPERTY(s,p,f) spx_wine_midi_property(env,s,p,f)
#define PREPARE(s,p) spx_wine_midi_header_call(env,SPX_MIDI_PREPARE,s,p,64)
#define QUEUE(s,p) spx_wine_midi_header_call(env,SPX_MIDI_OUT,s,p,64)
#define UNPREPARE(s,p) spx_wine_midi_header_call(env,SPX_MIDI_UNPREPARE,s,p,64)
#define RESTART(s) spx_wine_midi_stream_call(env,SPX_MIDI_RESTART,s)
#define PAUSE(s) spx_wine_midi_stream_call(env,SPX_MIDI_PAUSE,s)
#define RESET(s) spx_wine_midi_stream_call(env,SPX_MIDI_RESET,s)
#define CLOSE(s) spx_wine_midi_stream_call(env,SPX_MIDI_CLOSE,s)
#define ALLOC(n) spx_wine_global_alloc(env,0x42,n)
#define LOCK(h) spx_wine_global_lock(env,h)
#define UNLOCK(h) spx_wine_global_unlock(env,h)
#define FREE(h) spx_wine_global_free(env,h)
#endif
static void SPX_WINE_CALLBACK callback(uintptr_t stream,uint32_t message,uintptr_t instance,uintptr_t first,uintptr_t second) {
    if(instance!=(uintptr_t)&owner || second)spx_wine_unavailable("consumer callback arguments");
    if(message==0x3c7)atomic_fetch_add(&opened,1);
    if(message==0x3c8)atomic_fetch_add(&closed,1);
    if(message==0x3c9) {
        spx_wine_midi_header *h=(void *)first;
        if(h->dwUser!=(uintptr_t)&owner || !(h->dwFlags&1) || (h->dwFlags&4))spx_wine_unavailable("consumer completed header state");
        unsigned count=atomic_fetch_add(&done,1)+1;
        if(count==1 && requeue && QUEUE(stream,h))spx_wine_unavailable("consumer callback requeue failed");
    }
}
static int report(uint32_t open_result) {
    spx_observer out=spx_observe_begin(stdout);spx_observe_u64(&out,"open_result",open_result);
    spx_observe_u64(&out,"opened",atomic_load(&opened));spx_observe_u64(&out,"done",atomic_load(&done));spx_observe_u64(&out,"closed",atomic_load(&closed));
    spx_observe_u32s(&out,"cleanup_results",cleanup_results,2);
    spx_observe_u64(&out,"open_published",open_published);
    spx_wine_observe(env,&out,"platform");CHECK(spx_observe_finish(&out));puts("");spx_wine_destroy(env);return 0;
}
int main(int argc,char **argv) {
    const char *mode=argc>1 ? argv[1] : "controlled";int native=!strncmp(mode,"native",6),fail=!strcmp(mode,"failures");
    int deferred=!strcmp(mode,"deferred-reset") || !strcmp(mode,"native-reset");
    requeue=!native && !deferred && strcmp(mode,"defect");env=spx_wine_create(native ? SPX_WINE_NATIVE : SPX_WINE_CONTROLLED);
    int disposed=!strcmp(mode,"unsafe-free-record") || !strcmp(mode,"retired-callback") || !strcmp(mode,"retired-api");
    if(disposed)spx_wine_allow_retained_midi_disposal(env);
    spx_wine_bind_midi_callback(env,callback,(uintptr_t)&owner,1);spx_wine_bind_midi_user(env,(uintptr_t)&owner,1);
#ifdef _WIN32
    if(argc==99) {
        HMIDISTRM s=NULL;UINT dev=UINT_MAX;MIDIHDR h={0};MIDIPROPTIMEDIV p={8,96};
        midiStreamOpen(&s,&dev,1,0,0,0);midiStreamProperty(s,(LPBYTE)&p,0x80000001);
        midiOutPrepareHeader((HMIDIOUT)s,&h,64);midiStreamOut(s,&h,64);midiStreamRestart(s);midiStreamPause(s);
        midiOutReset((HMIDIOUT)s);midiOutUnprepareHeader((HMIDIOUT)s,&h,64);midiStreamClose(s);
        HGLOBAL a=GlobalAlloc(0x42,8);GlobalLock(a);GlobalUnlock(a);GlobalFree(a);
    }
#ifndef NO_INTERCEPTION
    CHECK(spx_wine_install_midi(env,NULL,SPX_WINE_MIDI_ALL));
    CHECK(spx_wine_install_memory(env,NULL,SPX_WINE_MEMORY_GLOBAL_ALLOC|SPX_WINE_MEMORY_GLOBAL_LOCK|SPX_WINE_MEMORY_GLOBAL_UNLOCK|SPX_WINE_MEMORY_GLOBAL_FREE));
#endif
    SetLastError(0);
#endif
    if(fail) {
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_OPEN,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE,.result=2});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_PROPERTY,.occurrence=2,.flags=SPX_RULE_RETURN|SPX_RULE_WORD,.result=1,.mask=255,.value=23});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_PREPARE,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_WORD,.result=7,.mask=0xf0,.value=0x80});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_OUT,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_NO_WRITE,.result=1});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_RESET,.occurrence=1,.flags=SPX_RULE_RETURN,.result=1});
    }
    if(deferred && !native) {
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_RESET,.flags=SPX_RULE_DEFER_COMPLETIONS});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_CLOSE,.flags=SPX_RULE_RETURN,.result=0});
    }
    int publication=!strcmp(mode,"failed-publication");
    if(publication)spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_MIDI_OPEN,.flags=SPX_RULE_RETURN|SPX_RULE_OBJECT,.result=2,.object=SPX_WINE_FAILED_PUBLICATION});
    uint32_t device=UINT32_MAX;uintptr_t stream=0x11223344;
    if(!strcmp(mode,"unsupported")) { OPEN(&stream,&device,callback,(uintptr_t)&owner,0x10000);return 43; }
    if(fail) { CHECK(OPEN(&stream,&device,callback,(uintptr_t)&owner,0x30000)==2);CHECK(stream==0x11223344); }
    uint32_t result=OPEN(&stream,&device,callback,(uintptr_t)&owner,0x30000);
    open_published=stream!=0x11223344 && stream!=0;
    if(publication) { CHECK(result==2 && open_published);return report(result); }
    if(native && result)return report(result);
    CHECK(!result && stream!=0x11223344);
    uint32_t property[2]={8,96};CHECK(!PROPERTY(stream,property,0x80000001));
    property[1]=0x11223344;result=PROPERTY(stream,property,0x40000001);
    CHECK(fail ? result==1 && property[1]==0x11223317 : !result && property[1]==96);
    uintptr_t allocation=ALLOC(24);CHECK(allocation);uint32_t *data=LOCK(allocation);CHECK(data);
    data[2]=data[5]=0x02000000; /* Two zero-delay MEVT_NOP events. */
    if(deferred)data[0]=data[3]=100000; /* Pending when reset is called. */
    spx_wine_midi_header a={0},b={0};a.lpData=(char *)data;b.lpData=(char *)(data+3);
    a.dwBufferLength=b.dwBufferLength=12;a.dwUser=b.dwUser=(uintptr_t)&owner;
    uintptr_t header_storage=0;uint32_t header_identity=0;
    if(!strncmp(mode,"header-storage",14)) {
        header_storage=ALLOC(128);CHECK(header_storage);void *bytes=LOCK(header_storage);CHECK(bytes);
        header_identity=spx_wine_memory_storage(env,bytes).identity;
        spx_wine_bind_midi_header_storage(env,&a,header_identity,!strcmp(mode,"header-storage-bounds") ? 65 : 0);
        spx_wine_bind_midi_header_storage(env,&b,header_identity,64);
        a.dwBufferLength=b.dwBufferLength=0;
    }
    if(fail) { CHECK(PREPARE(stream,&a)==7);CHECK(a.dwFlags==0x80); }
    CHECK(!PREPARE(stream,&a) && !PREPARE(stream,&b));
    if(fail) { uint32_t before=a.dwFlags;CHECK(QUEUE(stream,&a)==1 && a.dwFlags==before); }
    CHECK(!QUEUE(stream,&a) && !QUEUE(stream,&b));
    if(!strcmp(mode,"header-storage-move")) { spx_wine_bind_midi_header_storage(env,&a,header_identity,64);return 43; }
    if(!native && !deferred)CHECK(QUEUE(stream,&a)==65 && UNPREPARE(stream,&a)==65 && CLOSE(stream)==65);
    if(!strcmp(mode,"unsafe-free")) { FREE(allocation);return 43; }
    CHECK(!RESTART(stream));
    if(disposed) {
        CHECK(!UNLOCK(allocation) && !FREE(allocation));
        if(!strcmp(mode,"retired-callback"))spx_wine_midi_complete(env,stream,spx_wine_midi_header_identity(env,&a));
        if(!strcmp(mode,"retired-api"))UNPREPARE(stream,&a);
        return report(0);
    }
    if(!strcmp(mode,"bad-schedule")) { spx_wine_midi_complete(env,stream,spx_wine_midi_header_identity(env,&b));return 43; }
    if(deferred) {
        CHECK(!RESET(stream));cleanup_results[0]=UNPREPARE(stream,&a);cleanup_results[1]=UNPREPARE(stream,&b);
        if(!native)CHECK(cleanup_results[0]==65 && cleanup_results[1]==65 && !atomic_load(&done));
    } else if(!native) {
        spx_wine_midi_complete(env,stream,spx_wine_midi_header_identity(env,&a));
        if(!strcmp(mode,"payload-defect"))data[1]=1;
        CHECK(!PAUSE(stream));
        if(fail) { CHECK(RESET(stream)==1);CHECK(b.dwFlags&4); }
        CHECK(!RESET(stream));CHECK(atomic_load(&done)==(requeue ? 3U : 2U));
    } else {
#ifdef _WIN32
        for(unsigned i=0;i<2000 && atomic_load(&done)<2;++i)Sleep(1);
#endif
        CHECK(atomic_load(&done)==2);CHECK(!PAUSE(stream) && !RESET(stream));
    }
    if(!deferred)CHECK(!UNPREPARE(stream,&a) && !UNPREPARE(stream,&b));
    CHECK(!CLOSE(stream));
#ifdef _WIN32
    if(native)for(unsigned i=0;i<2000 && !atomic_load(&closed);++i)Sleep(1);
#endif
    CHECK(atomic_load(&closed)==1);if(deferred)CHECK(atomic_load(&done)==2);
    if(header_storage)CHECK(!UNLOCK(header_storage) && !FREE(header_storage));
    CHECK(!UNLOCK(allocation) && !FREE(allocation));return report(0);
}
