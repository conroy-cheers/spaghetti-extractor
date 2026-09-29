/* SDK-typed DirectSound binding shared by native callers and authored C. */
#include "spx-wine-test-internal.h"
#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
#define CINTERFACE 1
#define COBJMACROS 1
#include <windows.h>
#include <dsound.h>
#include "pe32-import-hook.h"

typedef HRESULT (WINAPI *sound_factory)(LPCGUID,LPDIRECTSOUND *,LPUNKNOWN);
typedef struct { spx_fixture_import_hook sound,message; } native_hooks;
static spx_wine_env *installed;
typedef struct { CRITICAL_SECTION lock;unsigned depth; } environment_guard;
static _Thread_local spx_wine_env *callback_environment;
void spx_wine_enter(spx_wine_env *e) {
    environment_guard *g=e->guard;EnterCriticalSection(&g->lock);++g->depth;
}
void spx_wine_leave(spx_wine_env *e) {
    environment_guard *g=e->guard;--g->depth;LeaveCriticalSection(&g->lock);
}
unsigned spx_wine_suspend(spx_wine_env *e) {
    environment_guard *g=e->guard;unsigned depth=g->depth;
    for(unsigned i=0;i<depth;++i)spx_wine_leave(e);
    return depth;
}
void spx_wine_resume(spx_wine_env *e,unsigned depth) { for(unsigned i=0;i<depth;++i)spx_wine_enter(e); }
void spx_wine_guard_destroy(spx_wine_env *e) { environment_guard *g=e->guard;DeleteCriticalSection(&g->lock);free(g); }
spx_wine_env *spx_wine_callback_enter(spx_wine_env *e) {
    spx_wine_env *previous=callback_environment;callback_environment=e;spx_wine_enter(e);return previous;
}
void spx_wine_callback_leave(spx_wine_env *e,spx_wine_env *previous) { spx_wine_leave(e);callback_environment=previous; }
void spx_wine_thread_check(spx_wine_env *e) {
    DWORD thread=GetCurrentThreadId();
    if(!e->guard) {
        environment_guard *g=calloc(1,sizeof(*g));if(!g)spx_wine_unavailable("environment synchronization allocation");
        InitializeCriticalSection(&g->lock);e->guard=g;e->thread=thread;
    }
    if(e->thread!=thread && callback_environment!=e)spx_wine_unavailable("unregistered concurrent platform calls require a scheduling backend");
}
static sound_factory factory(void) {
    static sound_factory result;
    if (!result) {
        HMODULE module=LoadLibraryA("dsound.dll");
        if (!module)spx_wine_unavailable("load Wine dsound.dll");
        result=(sound_factory)(uintptr_t)GetProcAddress(module,"DirectSoundCreate");
        if (!result)spx_wine_unavailable("resolve DirectSoundCreate");
    }
    return result;
}
static spx_wine_object *object(void *p) {
    if (!p)spx_wine_unavailable("null DirectSound receiver");
    return p;
}
static HRESULT WINAPI create(LPCGUID guid,LPDIRECTSOUND *out,LPUNKNOWN outer) {
    if (!installed)spx_wine_unavailable("DirectSound factory environment");
    spx_wine_call c={0};c.api=SPX_DS_CREATE;c.input=guid;c.output=out;
    if (outer)spx_wine_unavailable("DirectSound aggregation");
    return (HRESULT)spx_wine_invoke(installed,c);
}
static ULONG WINAPI release_device(LPDIRECTSOUND self) { spx_wine_object *o=object(self);return spx_wine_method(o->owner,SPX_COM_RELEASE,o,0); }
static ULONG WINAPI release_buffer(LPDIRECTSOUNDBUFFER self) { spx_wine_object *o=object(self);return spx_wine_method(o->owner,SPX_COM_RELEASE,o,0); }
static ULONG WINAPI addref_device(LPDIRECTSOUND self) { spx_wine_object *o=object(self);return spx_wine_method(o->owner,SPX_COM_ADDREF,o,0); }
static ULONG WINAPI addref_buffer(LPDIRECTSOUNDBUFFER self) { spx_wine_object *o=object(self);return spx_wine_method(o->owner,SPX_COM_ADDREF,o,0); }
static HRESULT query(spx_wine_object *o,REFIID iid,void **out) {
    spx_wine_call c={0};c.api=SPX_COM_QUERY;c.receiver=o;c.input=iid;c.output=out;memcpy(c.arguments,iid,16);c.argument_count=4;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI query_device(LPDIRECTSOUND self,REFIID iid,void **out) { return query(object(self),iid,out); }
static HRESULT WINAPI query_buffer(LPDIRECTSOUNDBUFFER self,REFIID iid,void **out) { return query(object(self),iid,out); }
static HRESULT WINAPI cooperative(LPDIRECTSOUND self,HWND window,DWORD level) {
    spx_wine_object *o=object(self);spx_wine_call c={0};c.api=SPX_DS_COOPERATIVE;c.receiver=o;c.window=(uintptr_t)window;
    c.arguments[0]=level;c.argument_count=1;return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI create_buffer(LPDIRECTSOUND self,LPCDSBUFFERDESC spec,LPDIRECTSOUNDBUFFER *out,LPUNKNOWN outer) {
    if (outer || !spec || spec->dwSize<20)spx_wine_unavailable("DirectSound buffer descriptor or aggregation");
    spx_wine_object *o=object(self);spx_wine_call c={0};c.api=SPX_DS_CREATE_BUFFER;c.receiver=o;c.output=out;
    /* The legacy 20-byte descriptor is intentional. Larger versions need
     * their additional fields admitted before they can be projected. */
    if (spec->dwSize!=20)spx_wine_unavailable("DirectSound descriptor revision beyond legacy 20 bytes");
    spx_wine_buffer_spec view={spec->dwSize,spec->dwFlags,spec->dwBufferBytes,spec->dwReserved,spec->lpwfxFormat};c.input=&view;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
#define SETTER(name,api,type) static HRESULT WINAPI name(LPDIRECTSOUNDBUFFER self,type value) { \
    spx_wine_object *o=object(self);return (HRESULT)spx_wine_method(o->owner,api,o,(uint32_t)value); }
SETTER(frequency,SPX_DS_FREQUENCY,DWORD) SETTER(pan,SPX_DS_PAN,LONG) SETTER(volume,SPX_DS_VOLUME,LONG) SETTER(position,SPX_DS_POSITION,DWORD)
#undef SETTER
#define GETTER(name,operation,type) static HRESULT WINAPI name(LPDIRECTSOUNDBUFFER self,type *out) { \
    spx_wine_object *o=object(self);spx_wine_call c={0};c.api=operation;c.receiver=o;c.output=out;return (HRESULT)spx_wine_invoke(o->owner,c); }
GETTER(status,SPX_DS_STATUS,DWORD) GETTER(get_frequency,SPX_DS_GET_FREQUENCY,DWORD) GETTER(get_pan,SPX_DS_GET_PAN,LONG) GETTER(get_volume,SPX_DS_GET_VOLUME,LONG)
#undef GETTER
static HRESULT WINAPI play(LPDIRECTSOUNDBUFFER self,DWORD reserved,DWORD priority,DWORD flags) {
    spx_wine_object *o=object(self);spx_wine_call c={0};c.api=SPX_DS_PLAY;c.receiver=o;
    c.arguments[0]=flags;c.arguments[1]=reserved;c.arguments[2]=priority;c.argument_count=3;return (HRESULT)spx_wine_invoke(o->owner,c);
}
static HRESULT WINAPI stop(LPDIRECTSOUNDBUFFER self) { spx_wine_object *o=object(self);return (HRESULT)spx_wine_method(o->owner,SPX_DS_STOP,o,0); }
static HRESULT WINAPI restore(LPDIRECTSOUNDBUFFER self) { spx_wine_object *o=object(self);return (HRESULT)spx_wine_method(o->owner,SPX_DS_RESTORE,o,0); }
static HRESULT WINAPI lock_buffer(LPDIRECTSOUNDBUFFER self,DWORD offset,DWORD bytes,void **first,DWORD *first_bytes,void **second,DWORD *second_bytes,DWORD flags) {
    spx_wine_object *o=object(self);spx_wine_call c={0};spx_wine_locked parts={0};
    if (first)memcpy(&parts.first,first,sizeof(parts.first));
    if (second)memcpy(&parts.second,second,sizeof(parts.second));
    if (first_bytes)memcpy(&parts.first_bytes,first_bytes,4);
    if (second_bytes)memcpy(&parts.second_bytes,second_bytes,4);
    c.api=SPX_DS_LOCK;c.receiver=o;c.arguments[0]=offset;c.arguments[1]=bytes;c.arguments[2]=flags;
    c.arguments[3]=(first ? 1 : 0)|(first_bytes ? 2 : 0)|(second ? 4 : 0)|(second_bytes ? 8 : 0);c.argument_count=4;c.output=&parts;
    uint32_t result=spx_wine_invoke(o->owner,c);
    if (first)memcpy(first,&parts.first,sizeof(parts.first));
    if (second)memcpy(second,&parts.second,sizeof(parts.second));
    if (first_bytes)memcpy(first_bytes,&parts.first_bytes,4);
    if (second_bytes)memcpy(second_bytes,&parts.second_bytes,4);
    return (HRESULT)result;
}
static HRESULT WINAPI unlock_buffer(LPDIRECTSOUNDBUFFER self,void *first,DWORD first_bytes,void *second,DWORD second_bytes) {
    spx_wine_object *o=object(self);spx_wine_call c={0};spx_wine_locked parts={first,second,first_bytes,second_bytes};
    c.api=SPX_DS_UNLOCK;c.receiver=o;c.input=&parts;c.arguments[0]=first_bytes;c.arguments[1]=second_bytes;c.argument_count=2;
    return (HRESULT)spx_wine_invoke(o->owner,c);
}
/* Unsupported methods terminate the comparison as incomplete. A fake HRESULT
 * would conceal an environment gap and could be mistaken for equivalence. */
static HRESULT WINAPI device_caps(LPDIRECTSOUND self,LPDSCAPS caps) { (void)self;(void)caps;spx_wine_unavailable("IDirectSound.GetCaps");return 0; }
static HRESULT WINAPI duplicate(LPDIRECTSOUND self,LPDIRECTSOUNDBUFFER src,LPDIRECTSOUNDBUFFER *out) { (void)self;(void)src;(void)out;spx_wine_unavailable("IDirectSound.DuplicateSoundBuffer");return 0; }
static HRESULT WINAPI compact(LPDIRECTSOUND self) { (void)self;spx_wine_unavailable("IDirectSound.Compact");return 0; }
static HRESULT WINAPI speaker_get(LPDIRECTSOUND self,LPDWORD out) { (void)self;(void)out;spx_wine_unavailable("IDirectSound.GetSpeakerConfig");return 0; }
static HRESULT WINAPI speaker_set(LPDIRECTSOUND self,DWORD value) { (void)self;(void)value;spx_wine_unavailable("IDirectSound.SetSpeakerConfig");return 0; }
static HRESULT WINAPI initialize_device(LPDIRECTSOUND self,LPCGUID guid) { (void)self;(void)guid;spx_wine_unavailable("IDirectSound.Initialize");return 0; }
static HRESULT WINAPI buffer_caps(LPDIRECTSOUNDBUFFER self,LPDSBCAPS caps) { (void)self;(void)caps;spx_wine_unavailable("IDirectSoundBuffer.GetCaps");return 0; }
static HRESULT WINAPI cursor(LPDIRECTSOUNDBUFFER self,LPDWORD play_out,LPDWORD write_out) { (void)self;(void)play_out;(void)write_out;spx_wine_unavailable("IDirectSoundBuffer.GetCurrentPosition");return 0; }
static HRESULT WINAPI format_get(LPDIRECTSOUNDBUFFER self,LPWAVEFORMATEX format,DWORD bytes,LPDWORD written) { (void)self;(void)format;(void)bytes;(void)written;spx_wine_unavailable("IDirectSoundBuffer.GetFormat");return 0; }
static HRESULT WINAPI initialize_buffer(LPDIRECTSOUNDBUFFER self,LPDIRECTSOUND device,LPCDSBUFFERDESC spec) { (void)self;(void)device;(void)spec;spx_wine_unavailable("IDirectSoundBuffer.Initialize");return 0; }
static HRESULT WINAPI format_set(LPDIRECTSOUNDBUFFER self,LPCWAVEFORMATEX format) { (void)self;(void)format;spx_wine_unavailable("IDirectSoundBuffer.SetFormat");return 0; }
static const IDirectSoundVtbl device_vtable={query_device,addref_device,release_device,create_buffer,device_caps,duplicate,cooperative,compact,speaker_get,speaker_set,initialize_device};
static const IDirectSoundBufferVtbl buffer_vtable={query_buffer,addref_buffer,release_buffer,buffer_caps,cursor,format_get,get_volume,get_pan,get_frequency,status,initialize_buffer,lock_buffer,play,position,format_set,volume,pan,frequency,stop,unlock_buffer,restore};
void spx_wine_native_object(spx_wine_object *o) {
    if(o->kind>=SPX_WINE_DD_DEVICE) { spx_wine_draw_object(o);return; }
    o->vtable=o->kind==SPX_WINE_DS_DEVICE ? (const void *)&device_vtable : (const void *)&buffer_vtable;
}
static int WINAPI message(HWND window,LPCSTR text,LPCSTR caption,UINT flags) {
    if (!installed)spx_wine_unavailable("MessageBox environment");
    spx_wine_call c={0};c.api=SPX_USER_MESSAGE_A;c.window=(uintptr_t)window;c.text=text;c.caption=caption;c.arguments[0]=flags;c.argument_count=1;
    return (int)spx_wine_invoke(installed,c);
}
int spx_wine_install(spx_wine_env *e,const char *module,int sound,int messages) {
    if (installed || e->native_hooks || (!sound&&!messages))return 0;
    native_hooks *h=calloc(1,sizeof(*h));if (!h)return 0;
    if (sound && !spx_fixture_redirect_import(&h->sound,module,"dsound.dll","DirectSoundCreate",(void (*)(void))create)) { free(h);return 0; }
    if (messages && !spx_fixture_redirect_import(&h->message,module,"user32.dll","MessageBoxA",(void (*)(void))message)) {
        if (h->sound.slot)(void)spx_fixture_restore_import(&h->sound);
        free(h);return 0;
    }
    e->native_hooks=h;installed=e;return 1;
}
int spx_wine_uninstall(spx_wine_env *e) {
    native_hooks *h=e->native_hooks;if (!h)return 1;
    if (installed!=e)return 0;
    if (h->sound.slot && !spx_fixture_restore_import(&h->sound))return 0;
    if (h->message.slot && !spx_fixture_restore_import(&h->message))return 0;
    free(h);e->native_hooks=NULL;installed=NULL;return 1;
}
static HRESULT call_lock(LPDIRECTSOUNDBUFFER buffer,spx_wine_call *c) {
    spx_wine_locked *p=c->output;
    DWORD first_bytes=p->first_bytes,second_bytes=p->second_bytes;
    unsigned mask=c->argument_count>=4 ? c->arguments[3] : 15;
    HRESULT result=IDirectSoundBuffer_Lock(buffer,c->arguments[0],c->arguments[1],
        mask&1 ? &p->first : NULL,mask&2 ? &first_bytes : NULL,
        mask&4 ? &p->second : NULL,mask&8 ? &second_bytes : NULL,c->arguments[2]);
    p->first_bytes=first_bytes;p->second_bytes=second_bytes;return result;
}
uint32_t spx_wine_candidate_call(spx_wine_env *e,spx_wine_call c) {
    if(c.api>=SPX_DD_CREATE)return spx_wine_draw_candidate_call(e,c);
    if(c.api>=SPX_MIDI_OPEN)return spx_wine_midi_candidate_call(e,c);
    if(c.api>=SPX_LOCAL_ALLOC)return spx_wine_memory_candidate_call(e,c);
    if(c.api>=SPX_FILE_OPEN_A)return spx_wine_file_candidate_call(e,c);
    LPDIRECTSOUND d=(void *)c.receiver;LPDIRECTSOUNDBUFFER b=(void *)c.receiver;
    if (c.receiver && c.receiver->owner!=e)spx_wine_unavailable("candidate receiver owner");
    switch (c.api) {
    case SPX_DS_CREATE:
        if (installed!=e)spx_wine_unavailable("candidate factory binding requires installed environment");
        return (uint32_t)create(c.input,c.output,NULL);
    case SPX_DS_CREATE_BUFFER: {
        const spx_wine_buffer_spec *s=c.input;DSBUFFERDESC spec={0};
        spec.dwSize=s->size;spec.dwFlags=s->flags;spec.dwBufferBytes=s->bytes;spec.dwReserved=s->reserved;spec.lpwfxFormat=(LPWAVEFORMATEX)s->format;
        return (uint32_t)IDirectSound_CreateSoundBuffer(d,&spec,c.output,NULL);
    }
    case SPX_DS_COOPERATIVE:return (uint32_t)IDirectSound_SetCooperativeLevel(d,(HWND)c.window,c.arguments[0]);
    case SPX_COM_RELEASE:return ((IUnknown *)c.receiver)->lpVtbl->Release((IUnknown *)c.receiver);
    case SPX_COM_ADDREF:return ((IUnknown *)c.receiver)->lpVtbl->AddRef((IUnknown *)c.receiver);
    case SPX_COM_QUERY:return (uint32_t)((IUnknown *)c.receiver)->lpVtbl->QueryInterface((IUnknown *)c.receiver,c.input,c.output);
    case SPX_DS_FREQUENCY:return (uint32_t)IDirectSoundBuffer_SetFrequency(b,c.arguments[0]);
    case SPX_DS_PAN:return (uint32_t)IDirectSoundBuffer_SetPan(b,(LONG)c.arguments[0]);
    case SPX_DS_VOLUME:return (uint32_t)IDirectSoundBuffer_SetVolume(b,(LONG)c.arguments[0]);
    case SPX_DS_POSITION:return (uint32_t)IDirectSoundBuffer_SetCurrentPosition(b,c.arguments[0]);
    case SPX_DS_PLAY:return (uint32_t)IDirectSoundBuffer_Play(b,c.arguments[1],c.arguments[2],c.arguments[0]);
    case SPX_DS_STATUS:return (uint32_t)IDirectSoundBuffer_GetStatus(b,c.output);
    case SPX_DS_RESTORE:return (uint32_t)IDirectSoundBuffer_Restore(b);
    case SPX_DS_STOP:return (uint32_t)IDirectSoundBuffer_Stop(b);
    case SPX_DS_GET_FREQUENCY:return (uint32_t)IDirectSoundBuffer_GetFrequency(b,c.output);
    case SPX_DS_GET_PAN:return (uint32_t)IDirectSoundBuffer_GetPan(b,c.output);
    case SPX_DS_GET_VOLUME:return (uint32_t)IDirectSoundBuffer_GetVolume(b,c.output);
    case SPX_DS_LOCK: {
        return (uint32_t)call_lock(b,&c);
    }
    case SPX_DS_UNLOCK: {
        const spx_wine_locked *p=c.input;return (uint32_t)IDirectSoundBuffer_Unlock(b,p->first,p->first_bytes,p->second,p->second_bytes);
    }
    case SPX_USER_MESSAGE_A:
        if (installed!=e)spx_wine_unavailable("candidate message binding requires installed environment");
        return (uint32_t)message((HWND)c.window,c.text,c.caption,c.arguments[0]);
    default:spx_wine_unavailable("candidate platform binding");return 0;
    }
}
/* Preserve caller output bytes on failure instead of manufacturing NULL. Never
 * dereference an unrecognized initial pointer while translating an out cell. */
void *spx_wine_initial_output(spx_wine_env *e,void *slot) {
    void *p;memcpy(&p,slot,sizeof(p));
    for (unsigned i=0;i<e->object_count;++i)if (p==&e->objects[i])return e->objects[i].native;
    return p;
}
void spx_wine_publish_output(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v,void *before,void *after,uint32_t result,enum spx_wine_kind kind) {
    if ((result&UINT32_C(0x80000000)) && before==after)return;
    spx_wine_object *p=NULL;
    if (after) {
        /* A live interface returned again is an alias. An address recycled
         * after final Release instead receives a fresh identity. */
        for(unsigned i=0;i<e->object_count;++i) {
            spx_wine_object *existing=&e->objects[i];
            if(existing->native==after && existing->kind==kind && existing->state.references) {
                p=existing;++p->state.references;break;
            }
        }
        if(!p)p=spx_wine_new_object(e,kind,after);
    }
    spx_wine_store_object(c->output,p);v->output_object=spx_wine_object_id(p);
    /* Values are observed; exact native write footprints are not inferred. */
}
uint32_t spx_wine_native_call(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v) {
    spx_wine_object *o=c->receiver;LPDIRECTSOUND device=o ? o->native : NULL;LPDIRECTSOUNDBUFFER buffer=o ? o->native : NULL;
    HRESULT result=0;
    switch (c->api) {
    case SPX_DS_CREATE: {
        void *before=spx_wine_initial_output(e,c->output);LPDIRECTSOUND made=before;result=factory()(c->input,&made,NULL);
        spx_wine_publish_output(e,c,v,before,made,result,SPX_WINE_DS_DEVICE);
        break;
    }
    case SPX_DS_CREATE_BUFFER: {
        const spx_wine_buffer_spec *s=c->input;DSBUFFERDESC spec={0};
        spec.dwSize=s->size;spec.dwFlags=s->flags;spec.dwBufferBytes=s->bytes;spec.dwReserved=s->reserved;spec.lpwfxFormat=(LPWAVEFORMATEX)s->format;
        void *before=spx_wine_initial_output(e,c->output);LPDIRECTSOUNDBUFFER made=before;result=IDirectSound_CreateSoundBuffer(device,&spec,&made,NULL);
        spx_wine_publish_output(e,c,v,before,made,result,SPX_WINE_DS_BUFFER);
        break;
    }
    case SPX_DS_COOPERATIVE:result=IDirectSound_SetCooperativeLevel(device,(HWND)c->window,c->arguments[0]);break;
    case SPX_COM_RELEASE:result=(HRESULT)((IUnknown *)o->native)->lpVtbl->Release((IUnknown *)o->native);o->state.references=(uint32_t)result;break;
    case SPX_COM_ADDREF:result=(HRESULT)((IUnknown *)o->native)->lpVtbl->AddRef((IUnknown *)o->native);o->state.references=(uint32_t)result;break;
    case SPX_COM_QUERY: {
        void *before=spx_wine_initial_output(e,c->output),*p=before;
        result=((IUnknown *)o->native)->lpVtbl->QueryInterface((IUnknown *)o->native,c->input,&p);
        if (FAILED(result) && p==before)break;
        if (p) {
            if (p!=o->native)spx_wine_unavailable("QueryInterface alias requires a supported interface projection");
            ++o->state.references;spx_wine_store_object(c->output,o);v->output_object=o->id;
        } else spx_wine_store_object(c->output,NULL);
        break;
    }
    case SPX_DS_FREQUENCY:result=IDirectSoundBuffer_SetFrequency(buffer,c->arguments[0]);break;
    case SPX_DS_PAN:result=IDirectSoundBuffer_SetPan(buffer,(LONG)c->arguments[0]);break;
    case SPX_DS_VOLUME:result=IDirectSoundBuffer_SetVolume(buffer,(LONG)c->arguments[0]);break;
    case SPX_DS_POSITION:result=IDirectSoundBuffer_SetCurrentPosition(buffer,c->arguments[0]);break;
    case SPX_DS_PLAY:result=IDirectSoundBuffer_Play(buffer,c->arguments[1],c->arguments[2],c->arguments[0]);break;
    case SPX_DS_STATUS:result=IDirectSoundBuffer_GetStatus(buffer,c->output);break;
    case SPX_DS_RESTORE:result=IDirectSoundBuffer_Restore(buffer);break;
    case SPX_DS_STOP:result=IDirectSoundBuffer_Stop(buffer);break;
    case SPX_DS_GET_FREQUENCY:result=IDirectSoundBuffer_GetFrequency(buffer,c->output);break;
    case SPX_DS_GET_PAN:result=IDirectSoundBuffer_GetPan(buffer,c->output);break;
    case SPX_DS_GET_VOLUME:result=IDirectSoundBuffer_GetVolume(buffer,c->output);break;
    case SPX_DS_LOCK: {
        result=call_lock(buffer,c);break;
    }
    case SPX_DS_UNLOCK: {
        const spx_wine_locked *p=c->input;result=IDirectSoundBuffer_Unlock(buffer,p->first,p->first_bytes,p->second,p->second_bytes);break;
    }
    case SPX_USER_MESSAGE_A: {
        /* The binding may be linked into the importing executable itself. */
        typedef int (WINAPI *message_proc)(HWND,LPCSTR,LPCSTR,UINT);
        message_proc actual=(message_proc)(uintptr_t)GetProcAddress(GetModuleHandleA("user32.dll"),"MessageBoxA");
        if(!actual)spx_wine_unavailable("resolve MessageBoxA");
        result=(HRESULT)actual((HWND)c->window,c->text,c->caption,c->arguments[0]);break;
    }
    default:spx_wine_unavailable("native API implementation");
    }
    if (c->api==SPX_DS_STATUS || (c->api>=SPX_DS_GET_FREQUENCY && c->api<=SPX_DS_GET_VOLUME)) {
        memcpy(&v->output_word,c->output,4);
    }
    return (uint32_t)result;
}
#else
void spx_wine_thread_check(spx_wine_env *e) { (void)e; }
void spx_wine_enter(spx_wine_env *e) { (void)e; }
void spx_wine_leave(spx_wine_env *e) { (void)e; }
unsigned spx_wine_suspend(spx_wine_env *e) { (void)e;return 0; }
void spx_wine_resume(spx_wine_env *e,unsigned depth) { (void)e;(void)depth; }
void spx_wine_guard_destroy(spx_wine_env *e) { (void)e; }
spx_wine_env *spx_wine_callback_enter(spx_wine_env *e) { (void)e;return NULL; }
void spx_wine_callback_leave(spx_wine_env *e,spx_wine_env *previous) { (void)e;(void)previous; }
void spx_wine_native_object(spx_wine_object *o) { (void)o; }
uint32_t spx_wine_candidate_call(spx_wine_env *e,spx_wine_call c) { return spx_wine_invoke(e,c); }
uint32_t spx_wine_native_call(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v) {
    (void)e;(void)c;(void)v;spx_wine_unavailable("native mode requires Wine/Win32");return 0;
}
int spx_wine_install(spx_wine_env *e,const char *module,int sound,int messages) { (void)e;(void)module;(void)sound;(void)messages;return 0; }
int spx_wine_uninstall(spx_wine_env *e) { (void)e;return 1; }
#endif
