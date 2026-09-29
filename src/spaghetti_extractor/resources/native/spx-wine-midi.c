/* Candidate-neutral WinMM stream service. Controlled completions are explicit
 * scenario steps; native callbacks retain their actual Wine thread and timing. */
#include "spx-wine-test-internal.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include "pe32-import-hook.h"
#endif
enum { MIDI_STREAMS=128,MIDI_HEADERS=512,MIDI_BINDINGS=256,
       MIDI_DONE=1,MIDI_PREPARED=2,MIDI_QUEUED=4,MIDI_STREAM_BUFFER=8,
       MOM_OPEN_VALUE=0x3c7,MOM_CLOSE_VALUE=0x3c8,MOM_DONE_VALUE=0x3c9,MOM_POSITION_VALUE=0x3ca };
typedef struct { spx_wine_midi_callback function;uintptr_t instance;uint32_t id; } callback_binding;
typedef struct {
    spx_wine_env *owner;
    uintptr_t native;
    callback_binding callback;
    uint32_t id,live,playing,tempo,division,closed_notification,opened;
} midi_stream;
typedef struct {
    spx_wine_midi_header *value;
    midi_stream *stream;
    uint32_t id,prepared,queued,generation,order,retired,return_pending,invalid_disposal;
    const void *storage;
    char *data;
    uint32_t size;
} midi_header;
typedef struct { spx_wine_midi_header *value;const void *storage;uint32_t allocation,offset; } header_binding;
typedef struct {
    midi_stream streams[MIDI_STREAMS];midi_header headers[MIDI_HEADERS];
    header_binding storage_bindings[MIDI_HEADERS];unsigned storage_binding_count,allow_retained_disposal;
    callback_binding callbacks[MIDI_BINDINGS];
    uintptr_t users[MIDI_BINDINGS];uint32_t user_ids[MIDI_BINDINGS],user_live[MIDI_BINDINGS],user_allocation[MIDI_BINDINGS];
    unsigned stream_count,header_count,callback_count,user_count,queue_order;
#ifdef _WIN32
    spx_fixture_import_hook imports[9];
#endif
} midi_environment;
static void require(int yes,const char *why) { if(!yes)spx_wine_unavailable(why); }
static midi_environment *midi(spx_wine_env *e) {
    if(!e->midi) { e->midi=calloc(1,sizeof(midi_environment));require(e->midi!=NULL,"MIDI environment allocation"); }
    return e->midi;
}
void spx_wine_bind_midi_callback(spx_wine_env *e,spx_wine_midi_callback fn,uintptr_t instance,uint32_t id) {
    require(fn && id,"MIDI callback correspondence");midi_environment *m=midi(e);
    for(unsigned i=0;i<m->callback_count;++i) {
        callback_binding *b=&m->callbacks[i];
        if((b->function==fn && b->instance==instance) || b->id==id) {
            require(b->function==fn && b->instance==instance && b->id==id,"conflicting MIDI callback correspondence");return;
        }
    }
    require(m->callback_count<MIDI_BINDINGS,"MIDI callback capacity");m->callbacks[m->callback_count++]=(callback_binding){fn,instance,id};
}
void spx_wine_bind_midi_user(spx_wine_env *e,uintptr_t value,uint32_t id) {
    require(value && id,"MIDI user correspondence");midi_environment *m=midi(e);
    for(unsigned i=0;i<m->user_count;++i)if((m->users[i]==value && m->user_live[i]) || m->user_ids[i]==id) {
        require(m->users[i]==value && m->user_ids[i]==id && m->user_live[i],"conflicting MIDI user correspondence");return;
    }
    require(m->user_count<MIDI_BINDINGS,"MIDI user capacity");m->users[m->user_count]=value;m->user_live[m->user_count]=1;m->user_ids[m->user_count++]=id;
}
void spx_wine_bind_midi_allocation_user(spx_wine_env *e,uint32_t id) {
    uintptr_t value=(uintptr_t)spx_wine_memory_address(e,id);spx_wine_bind_midi_user(e,value,id);midi_environment *m=midi(e);
    for(unsigned i=0;i<m->user_count;++i)if(m->user_ids[i]==id) { m->user_allocation[i]=1;return; }
}
static uint32_t user_identity(midi_environment *m,uintptr_t value) {
    if(!value)return 0;
    for(unsigned i=m->user_count;i;--i)if(m->users[i-1]==value && m->user_live[i-1])return m->user_ids[i-1];
    spx_wine_unavailable("MIDI header user value requires a boundary correspondence");return 0;
}
static callback_binding callback_at(midi_environment *m,const callback_binding *input) {
    if(!input->function) { require(!input->instance,"null MIDI callback instance");return *input; }
    for(unsigned i=0;i<m->callback_count;++i)if(m->callbacks[i].function==input->function && m->callbacks[i].instance==input->instance)return m->callbacks[i];
    spx_wine_unavailable("MIDI callback requires a boundary correspondence");return (callback_binding){0};
}
static midi_stream *stream_at(midi_environment *m,uintptr_t handle) {
    for(unsigned i=0;i<m->stream_count;++i)if((uintptr_t)&m->streams[i]==handle)return &m->streams[i];
    require(!handle,"unbound MIDI stream; observe midiStreamOpen");return NULL;
}
static midi_header *header_at(midi_environment *m,const spx_wine_midi_header *value) {
    for(unsigned i=m->header_count;i;--i)if(m->headers[i-1].value==value)return &m->headers[i-1];
    return NULL;
}
void spx_wine_allow_retained_midi_disposal(spx_wine_env *e) {
    require(e->mode==SPX_WINE_CONTROLLED && !e->event_count,"retained MIDI disposal experiment requires controlled mode before execution");
    midi(e)->allow_retained_disposal=1;
}
void spx_wine_bind_midi_header_storage(spx_wine_env *e,spx_wine_midi_header *value,uint32_t allocation,uint32_t offset) {
    require(value!=NULL,"MIDI header storage binding requires a header");
    const unsigned char *base=spx_wine_memory_address(e,allocation);
    spx_wine_storage storage=spx_wine_memory_storage(e,base);
    require(offset<=storage.extent && 64<=storage.extent-offset,"MIDI header storage binding exceeds allocation");
    midi_environment *m=midi(e);header_binding *b=NULL;
    for(unsigned i=0;i<m->storage_binding_count;++i)if(m->storage_bindings[i].value==value)b=&m->storage_bindings[i];
    if(b && b->allocation==allocation && b->offset==offset)return;
    midi_header *h=header_at(m,value);
    require(!h || h->retired || (!h->prepared && !h->queued),"cannot move retained MIDI header storage");
    if(!b) { require(m->storage_binding_count<MIDI_HEADERS,"MIDI header storage binding capacity");b=&m->storage_bindings[m->storage_binding_count++]; }
    *b=(header_binding){value,base+offset,allocation,offset};
    if(h && !h->retired)h->storage=b->storage;
}
static const void *bound_header_storage(midi_environment *m,const spx_wine_midi_header *value) {
    for(unsigned i=0;i<m->storage_binding_count;++i)if(m->storage_bindings[i].value==value)return m->storage_bindings[i].storage;
    return NULL;
}
uint32_t spx_wine_midi_header_identity(spx_wine_env *e,const spx_wine_midi_header *value) {
    midi_header *h=header_at(midi(e),value);require(h!=NULL,"unbound MIDI header");return h->id;
}
static spx_wine_event *event(spx_wine_env *e,enum spx_wine_api api,midi_stream *s) {
    require(e->event_count<SPX_WINE_EVENTS,"MIDI event capacity");
    spx_wine_event *v=&e->events[e->event_count++];v->api=api;v->sequence=e->event_count;v->occurrence=++e->calls[api];
    v->controlled=e->mode==SPX_WINE_CONTROLLED;v->receiver=s ? s->id : 0;v->handle_known=1;
    v->handle_live_before=s ? s->live : 0;v->preserved=v->output_preserved=1;return v;
}
static void snapshot(spx_wine_event *v,const void *bytes,uint32_t size) {
    require(size<65536 && (!size || bytes),"MIDI payload extent");
    if(!size)return;
    v->data=malloc(size);require(v->data!=NULL,"MIDI payload observation");memcpy(v->data,bytes,size);v->data_bytes=size;
}
static void notify(midi_stream *s,uint32_t message,midi_header *h,uintptr_t second) {
    spx_wine_env *e=s->owner;midi_environment *m=midi(e);
    require(message==MOM_OPEN_VALUE || message==MOM_CLOSE_VALUE || message==MOM_DONE_VALUE || message==MOM_POSITION_VALUE,"unsupported MIDI callback message");
    require(!second,"MIDI callback secondary parameter");
    require(!h || !h->retired,"MIDI callback header storage has been retired");
    if(message==MOM_CLOSE_VALUE)s->closed_notification=1;
    if(message==MOM_DONE_VALUE) {
        require(h && h->stream==s && h->queued,"MIDI completion requires a pending header");
        h->queued=0;h->return_pending=0;
        if(e->mode==SPX_WINE_CONTROLLED)h->value->dwFlags=(h->value->dwFlags&~MIDI_QUEUED)|MIDI_DONE;
    }
    if(!s->callback.function)return;
    spx_wine_event *v=event(e,SPX_MIDI_CALLBACK,s);v->callback=s->callback.id;
    v->arguments[0]=message;v->arguments[1]=h ? h->id : 0;v->argument_count=2;
    if(h) {
        v->arguments[2]=user_identity(m,h->value->dwUser);v->arguments[3]=h->value->dwOffset;v->argument_count=4;
        v->storage=h->id;v->generation=h->generation;v->output_word=h->value->dwFlags;v->written_mask=UINT32_MAX;
        snapshot(v,h->value->lpData,h->value->dwBufferLength);
    }
    v->handle_live_after=s->live;
    if(e->hooks.before)e->hooks.before(e->hooks.context,v);
    if(s->callback.function)s->callback.function((uintptr_t)s,message,s->callback.instance,h ? (uintptr_t)h->value : 0,second);
    if(e->hooks.after)e->hooks.after(e->hooks.context,v);
}
static void flush_pending(midi_stream *s,uint32_t limit) {
    midi_environment *m=midi(s->owner);
    for(;;) {
        midi_header *first=NULL;
        for(unsigned i=0;i<m->header_count;++i) {
            midi_header *h=&m->headers[i];
            if(h->stream==s && h->queued && h->order<=limit && (!first || h->order<first->order))first=h;
        }
        if(!first)break;
        notify(s,MOM_DONE_VALUE,first,0);
    }
}
void spx_wine_midi_complete(spx_wine_env *e,uintptr_t handle,uint32_t id) {
    spx_wine_enter(e);spx_wine_thread_check(e);require(e->mode==SPX_WINE_CONTROLLED,"native MIDI completions come from Wine");
    midi_environment *m=midi(e);midi_stream *s=stream_at(m,handle);require(s && s->live,"scheduled completion requires a live MIDI stream");
    midi_header *first=NULL;
    for(unsigned i=0;i<m->header_count;++i)if(m->headers[i].stream==s && m->headers[i].queued && (!first || m->headers[i].order<first->order))first=&m->headers[i];
    require(first && first->id==id,"scheduled MIDI completion does not name the next queued header");
    require(s->playing || first->return_pending,"scheduled completion requires playback or a pending reset return");
    notify(s,MOM_DONE_VALUE,first,0);spx_wine_leave(e);
}
void spx_wine_midi_validate_rule(const spx_wine_rule *r) {
    require(r->api>=SPX_MIDI_OPEN && r->api<=SPX_MIDI_CLOSE,"MIDI scenario API");
    require(!(r->flags&~(SPX_RULE_RETURN|SPX_RULE_OBJECT|SPX_RULE_WORD|SPX_RULE_NO_WRITE|SPX_RULE_CALLBACK|SPX_RULE_DEFER_COMPLETIONS)),"MIDI scenario flags");
    require(!(r->flags&SPX_RULE_DEFER_COMPLETIONS) || r->api==SPX_MIDI_RESET,"deferred completion rule requires MIDI reset");
    require(!(r->flags&SPX_RULE_OBJECT) || r->api==SPX_MIDI_OPEN,"MIDI object output requires stream open");
    require(!(r->flags&SPX_RULE_WORD) || r->api==SPX_MIDI_PROPERTY || r->api==SPX_MIDI_PREPARE || r->api==SPX_MIDI_OUT || r->api==SPX_MIDI_UNPREPARE,"MIDI word output API");
    require(!(r->flags&SPX_RULE_NO_WRITE) || r->api==SPX_MIDI_OPEN || r->api==SPX_MIDI_PROPERTY || r->api==SPX_MIDI_PREPARE || r->api==SPX_MIDI_OUT || r->api==SPX_MIDI_UNPREPARE,"MIDI no-write output API");
    require(!(r->flags&SPX_RULE_NO_WRITE) || !(r->flags&(SPX_RULE_WORD|SPX_RULE_OBJECT)),"conflicting MIDI output rules");
}
static void refresh_unnotified(spx_wine_env *e) {
    midi_environment *m=e->midi;if(!m || e->mode!=SPX_WINE_NATIVE)return;
    /* CALLBACK_NULL has no application callback to intercept. Observe completed
     * flags at API/observation boundaries without inventing a delivery event. */
    for(unsigned i=0;i<m->header_count;++i) {
        midi_header *h=&m->headers[i];
        if(h->queued && h->stream && !h->stream->callback.function &&
            (h->value->dwFlags&MIDI_DONE) && !(h->value->dwFlags&MIDI_QUEUED))h->queued=0;
    }
}
#ifdef _WIN32
static FARPROC procedure(const char *name) {
    HMODULE module=GetModuleHandleA("winmm.dll");if(!module)module=LoadLibraryA("winmm.dll");
    FARPROC p=module ? GetProcAddress(module,name) : NULL;require(p!=NULL,"resolve native MIDI API");return p;
}
static void CALLBACK native_callback(HMIDIOUT native_handle,UINT message,DWORD_PTR instance,DWORD_PTR first,DWORD_PTR second) {
    midi_stream *s=(void *)instance;spx_wine_env *e=s->owner;
    spx_wine_env *previous=spx_wine_callback_enter(e);
    if(!s->native)s->native=(uintptr_t)native_handle;
    require(s->native==(uintptr_t)native_handle,"native MIDI callback stream identity");
    midi_header *h=first ? header_at(midi(e),(const spx_wine_midi_header *)first) : NULL;
    require(!first || h,"unbound native MIDI callback header");notify(s,message,h,second);
    spx_wine_callback_leave(e,previous);
}
static uint32_t native(spx_wine_env *e,spx_wine_call c,midi_stream *s,spx_wine_event *v) {
    FARPROC p=procedure(spx_wine_api_name(c.api));uint32_t result;
    uintptr_t handle=s ? s->native : 0;
    /* A reset/close may wait for a callback thread. Never hold the observation
     * mutex across the native call. Its event was reserved before suspension. */
    uintptr_t previous=0,previous_native=0;
    if(c.api==SPX_MIDI_OPEN) {
        memcpy(&previous,c.output,sizeof(previous));previous_native=previous;
        midi_environment *m=midi(e);
        for(unsigned i=0;i<m->stream_count;++i)if(previous==(uintptr_t)&m->streams[i])previous_native=m->streams[i].native;
    }
    unsigned depth=spx_wine_suspend(e);
    if(c.api==SPX_MIDI_OPEN) {
        typedef MMRESULT (WINAPI *fn)(LPHMIDISTRM,LPUINT,DWORD,DWORD_PTR,DWORD_PTR,DWORD);
        HMIDISTRM opened=(HMIDISTRM)previous_native;
        result=((fn)(uintptr_t)p)(&opened,c.buffer,c.arguments[0],s->callback.function ? (DWORD_PTR)native_callback : 0,
            s->callback.function ? (DWORD_PTR)s : 0,c.arguments[1]);
        handle=(uintptr_t)opened;
    } else if(c.api==SPX_MIDI_PROPERTY) {
        typedef MMRESULT (WINAPI *fn)(HMIDISTRM,LPBYTE,DWORD);result=((fn)(uintptr_t)p)((HMIDISTRM)handle,c.buffer,c.arguments[0]);
    } else if(c.api==SPX_MIDI_PREPARE || c.api==SPX_MIDI_OUT || c.api==SPX_MIDI_UNPREPARE) {
        typedef MMRESULT (WINAPI *fn)(HMIDIOUT,LPMIDIHDR,UINT);result=((fn)(uintptr_t)p)((HMIDIOUT)handle,c.buffer,c.arguments[0]);
    } else {
        typedef MMRESULT (WINAPI *fn)(HMIDISTRM);result=((fn)(uintptr_t)p)((HMIDISTRM)handle);
    }
    spx_wine_resume(e,depth);
    if(c.api==SPX_MIDI_OPEN) {
        v->second_bytes=*(uint32_t *)c.buffer;
        if(!result)s->native=handle;
        else if(handle!=previous_native) {
            uintptr_t published=0;
            if(handle) {
                midi_environment *m=midi(e);midi_stream *alias=NULL;
                for(unsigned i=m->stream_count;i;--i)if(m->streams[i-1].native==handle) { alias=&m->streams[i-1];break; }
                if(!alias) { s->native=handle;alias=s; }
                published=(uintptr_t)alias;v->output_object=alias->id;
            }
            memcpy(c.output,&published,sizeof(published));v->written_mask=UINT32_MAX;
        }
    }
    return result;
}
#endif
uint32_t spx_wine_midi_invoke(spx_wine_env *e,spx_wine_call c) {
    require(c.api>=SPX_MIDI_OPEN && c.api<=SPX_MIDI_CLOSE,"MIDI API call");
    midi_environment *m=midi(e);refresh_unnotified(e);midi_stream *s=c.api==SPX_MIDI_OPEN ? NULL : stream_at(m,c.handle);
    spx_wine_event *v=event(e,c.api,s);spx_wine_rule r=spx_wine_select_rule(e,c.api,v->receiver,v->occurrence);spx_wine_midi_validate_rule(&r);
    midi_header *h=NULL;uint32_t before=0,mask=0,*word=NULL;
    int header_call=c.api==SPX_MIDI_PREPARE || c.api==SPX_MIDI_OUT || c.api==SPX_MIDI_UNPREPARE;
    uint32_t result=s && !s->live ? 5 : 0;
    if(c.api==SPX_MIDI_OPEN) {
        require(c.output && c.buffer && c.input && c.arguments[0]==1,"MIDI stream open requires one device and outputs");
        callback_binding b=callback_at(m,c.input);require(c.arguments[1]==(b.function ? 0x30000U : 0),"MIDI profile supports null or function callbacks");
        require(m->stream_count<MIDI_STREAMS,"MIDI stream capacity");s=&m->streams[m->stream_count++];
        s->id=m->stream_count;s->owner=e;s->callback=b;s->tempo=500000;s->division=480;
        v->arguments[0]=*(uint32_t *)c.buffer;v->arguments[1]=c.arguments[0];v->arguments[2]=c.arguments[1];v->arguments[3]=b.id;v->argument_count=4;
    } else if(header_call) {
        spx_wine_midi_header *value=c.buffer;require(value && c.arguments[0]==64,"MIDI profile uses complete PE32 headers (64-byte ABI size)");
        h=header_at(m,value);
        require(!h || !h->invalid_disposal,"MIDI API header storage was disposed while retained");
        if(h && h->retired) { require(c.api==SPX_MIDI_PREPARE,"MIDI header storage has been retired");h=NULL; }
        if(!h) {
            require(m->header_count<MIDI_HEADERS,"MIDI header capacity");h=&m->headers[m->header_count++];h->id=m->header_count;h->value=value;h->stream=s;h->storage=bound_header_storage(m,value);
        }
        if(h->prepared)require(h->stream==s && h->data==value->lpData && h->size==value->dwBufferLength,"prepared MIDI header storage changed before unprepare");
    else h->stream=s;
        word=(uint32_t *)&value->dwFlags;memcpy(&before,word,4);
        v->arguments[0]=h->id;v->arguments[1]=c.arguments[0];v->arguments[2]=value->dwBufferLength;v->arguments[3]=before;
        v->arguments[4]=user_identity(m,value->dwUser);v->argument_count=5;v->storage=h->id;v->storage_extent=value->dwBufferLength;
        snapshot(v,value->lpData,value->dwBufferLength);
        if(!s)result=5;
        else if((c.api==SPX_MIDI_OUT || c.api==SPX_MIDI_UNPREPARE) && h->queued)result=65;
        else if(c.api==SPX_MIDI_OUT && (!h->prepared || !(before&MIDI_PREPARED)))result=64;
    } else if(c.api==SPX_MIDI_PROPERTY) {
        uint32_t size;require(c.buffer!=NULL,"MIDI property storage");memcpy(&size,c.buffer,4);
        require(size==8 && (c.arguments[0]==0x80000001 || c.arguments[0]==0x80000002 || c.arguments[0]==0x40000001 || c.arguments[0]==0x40000002),"MIDI property profile supports tempo and time division");
        word=(uint32_t *)((unsigned char *)c.buffer+4);memcpy(&before,word,4);
        v->arguments[0]=c.arguments[0];v->arguments[1]=size;v->argument_count=2;
        if(c.arguments[0]&0x80000000U) { v->arguments[2]=before;v->argument_count=3; }
        require(!(c.arguments[0]&0x80000000U) || !(r.flags&(SPX_RULE_WORD|SPX_RULE_NO_WRITE)),"MIDI setter has no word output");
    } else if(c.api==SPX_MIDI_CLOSE && s) {
        for(unsigned i=0;i<m->header_count;++i)if(m->headers[i].stream==s && m->headers[i].queued)result=65;
    }
    if(c.api!=SPX_MIDI_OPEN && !s)result=5;
    if(r.flags&SPX_RULE_RETURN)result=r.result;
    if(e->hooks.before)e->hooks.before(e->hooks.context,v);
    uint32_t attempted_generation=0;
    if(c.api==SPX_MIDI_OUT && !result) {
        h->queued=1;attempted_generation=++h->generation;h->order=++m->queue_order;
    }
    if(e->mode==SPX_WINE_NATIVE) {
#ifdef _WIN32
        result=native(e,c,s,v);
#else
        spx_wine_unavailable("native MIDI requires Wine/Win32");
#endif
        if(word) {
            uint32_t after;memcpy(&after,word,4);
            mask=!result && (header_call || (c.arguments[0]&0x40000000)) ? UINT32_MAX : before^after;
        }
        if(c.api==SPX_MIDI_OUT && result && h->generation==attempted_generation)h->queued=0;
    } else if(word) {
        uint32_t value=before;
        if(!result && !(r.flags&SPX_RULE_NO_WRITE)) {
            if(c.api==SPX_MIDI_PREPARE)value|=MIDI_PREPARED;
            else if(c.api==SPX_MIDI_UNPREPARE)value&=~MIDI_PREPARED;
            else if(c.api==SPX_MIDI_OUT)value=(value&~MIDI_DONE)|MIDI_QUEUED|MIDI_STREAM_BUFFER;
            else if(c.api==SPX_MIDI_PROPERTY && (c.arguments[0]&0x40000000))value=(c.arguments[0]&1) ? s->division : s->tempo;
            mask=header_call || (c.arguments[0]&0x40000000) ? UINT32_MAX : 0;
        }
        if(r.flags&SPX_RULE_WORD) { mask=r.mask;value=r.value; }
        value=(before&~mask)|(value&mask);memcpy(word,&value,4);
    }
    if(c.api==SPX_MIDI_OPEN) {
        if(e->mode==SPX_WINE_CONTROLLED)v->second_bytes=*(uint32_t *)c.buffer;
        require(!(r.flags&(SPX_RULE_NO_WRITE|SPX_RULE_OBJECT)) || result,"MIDI open output injection requires failure");
        if(!result) { s->live=s->opened=1;uintptr_t handle=(uintptr_t)s;memcpy(c.output,&handle,sizeof(handle));v->output_object=s->id;v->written_mask=UINT32_MAX; }
        else if(r.flags&SPX_RULE_OBJECT) {
            midi_stream *published=NULL;
            if(r.object==SPX_WINE_FAILED_PUBLICATION)published=s;
            else if(r.object) { require(r.object<=m->stream_count,"MIDI output alias identity");published=&m->streams[r.object-1]; }
            uintptr_t value=(uintptr_t)published;memcpy(c.output,&value,sizeof(value));v->output_object=published ? published->id : 0;v->written_mask=UINT32_MAX;
        }
    } else if(!result) {
        if(c.api==SPX_MIDI_PREPARE) { h->prepared=1;h->data=h->value->lpData;h->size=h->value->dwBufferLength; }
        else if(c.api==SPX_MIDI_UNPREPARE)h->prepared=0;
        else if(c.api==SPX_MIDI_RESTART)s->playing=1;
        else if(c.api==SPX_MIDI_PAUSE || c.api==SPX_MIDI_RESET)s->playing=0;
        else if(c.api==SPX_MIDI_CLOSE) { s->live=0;s->playing=0; }
        else if(c.api==SPX_MIDI_PROPERTY && (c.arguments[0]&0x80000000U)) {
            if(c.arguments[0]&1)s->division=before;else s->tempo=before;
        }
    }
    v->result=result;v->handle_live_after=s ? s->live : 0;
    if(word) { uint32_t value;memcpy(&value,word,4);v->output_word=value&mask;v->written_mask=mask;v->output_preserved=((before^value)&~mask)==0; }
    if(h)v->generation=h->generation;
    if(e->mode==SPX_WINE_CONTROLLED && !result) {
        if(c.api==SPX_MIDI_OPEN && s->callback.function)notify(s,MOM_OPEN_VALUE,NULL,0);
        else if(c.api==SPX_MIDI_CLOSE) {
            /* An explicit successful-close outcome can return still-pending
             * buffers, as native stream providers do. Keep failed unprepares
             * visible rather than turning them into successful cleanup. */
            flush_pending(s,m->queue_order);
            if(s->callback.function)notify(s,MOM_CLOSE_VALUE,NULL,0);
        }
        else if(c.api==SPX_MIDI_RESET) {
            /* Flush precisely the pending generation at reset entry. Callback
             * requeue creates new work; it cannot turn this into an infinite loop. */
            if(r.flags&SPX_RULE_DEFER_COMPLETIONS) {
                for(unsigned i=0;i<m->header_count;++i)if(m->headers[i].stream==s && m->headers[i].queued)m->headers[i].return_pending=1;
            } else flush_pending(s,m->queue_order);
        }
    }
    if(r.flags&SPX_RULE_CALLBACK) { require(e->hooks.callback!=NULL,"MIDI scenario callback is unbound");v->callback=r.callback;e->hooks.callback(e->hooks.context,r.callback); }
    refresh_unnotified(e);
    if(e->hooks.after)e->hooks.after(e->hooks.context,v);
    return result;
}
void spx_wine_midi_retire_memory(spx_wine_env *e,const void *p,size_t size,int committed) {
    midi_environment *m=e->midi;if(!m || !p)return;
    uintptr_t base=(uintptr_t)p;
    if(committed)for(unsigned i=0;i<m->user_count;++i)if(m->user_allocation[i] && m->users[i]>=base && m->users[i]-base<size)m->user_live[i]=0;
    for(unsigned i=0;i<m->header_count;++i) {
        midi_header *h=&m->headers[i];if(h->retired)continue;
        uintptr_t header=(uintptr_t)(h->storage ? h->storage : h->value),data=(uintptr_t)h->data;
        size_t header_size=h->storage ? 64 : sizeof(*h->value);
        int header_overlap=header>=base ? header-base<size : base-header<header_size;
        int data_overlap=h->size && (data>=base ? data-base<size : base-data<h->size);
        if(header_overlap || data_overlap) {
            int invalid=h->queued || (h->prepared && (!h->stream || h->stream->live));
            require(!invalid || m->allow_retained_disposal,"freeing MIDI-retained header or payload requires an explicit invalid-lifetime experiment");
            if(committed) { h->retired=1;h->invalid_disposal=(uint32_t)invalid; }
        }
    }
}
void spx_wine_midi_observe(spx_wine_env *e,spx_observer *out) {
    midi_environment *m=e->midi;if(!m)return;
    refresh_unnotified(e);
    if(m->allow_retained_disposal)spx_observe_u64(out,"midi_invalid_disposal_experiment",1);
    spx_observe_array(out,"midi_streams");
    for(unsigned i=0;i<m->stream_count;++i) {
        midi_stream *s=&m->streams[i];spx_observe_object(out,NULL);spx_observe_u64(out,"id",s->id);spx_observe_u64(out,"live",s->live);
        spx_observe_u64(out,"playing",s->playing);spx_observe_u64(out,"tempo",s->tempo);spx_observe_u64(out,"division",s->division);spx_observe_end(out);
    }
    spx_observe_end(out);spx_observe_array(out,"midi_headers");
    for(unsigned i=0;i<m->header_count;++i) {
        midi_header *h=&m->headers[i];spx_observe_object(out,NULL);spx_observe_u64(out,"id",h->id);spx_observe_u64(out,"stream",h->stream ? h->stream->id : 0);
        spx_observe_u64(out,"prepared",h->prepared);spx_observe_u64(out,"queued",h->queued);spx_observe_u64(out,"generation",h->generation);
        spx_observe_u64(out,"storage_retired",h->retired);
        if(h->invalid_disposal)spx_observe_u64(out,"storage_invalid_disposal",1);
        spx_observe_end(out);
    }
    spx_observe_end(out);
}
void spx_wine_midi_destroy(spx_wine_env *e) {
    midi_environment *m=e->midi;if(!m)return;
    if(e->mode==SPX_WINE_NATIVE)for(unsigned i=0;i<m->stream_count;++i) {
        midi_stream *s=&m->streams[i];require(!s->live,"close native MIDI streams before disposing callback storage");
        require(!s->opened || !s->callback.function || s->closed_notification,"wait for the native MIDI close callback before disposing storage");
    }
    free(m);e->midi=NULL;
}
#ifdef _WIN32
static spx_wine_env *installed;
static MMRESULT WINAPI midi_open(LPHMIDISTRM out,LPUINT device,DWORD count,DWORD_PTR fn,DWORD_PTR instance,DWORD flags) {
    callback_binding binding={(spx_wine_midi_callback)fn,instance,0};spx_wine_call c={0};c.api=SPX_MIDI_OPEN;
    c.output=out;c.buffer=device;c.input=&binding;c.arguments[0]=count;c.arguments[1]=flags;return spx_wine_invoke(installed,c);
}
static MMRESULT WINAPI midi_property(HMIDISTRM stream,LPBYTE property,DWORD flags) {
    spx_wine_call c={0};c.api=SPX_MIDI_PROPERTY;c.handle=(uintptr_t)stream;c.buffer=property;c.arguments[0]=flags;return spx_wine_invoke(installed,c);
}
#define HEADER_WRAPPER(name,operation) static MMRESULT WINAPI name(HMIDIOUT stream,LPMIDIHDR header,UINT size) { \
    spx_wine_call c={0};c.api=operation;c.handle=(uintptr_t)stream;c.buffer=header;c.arguments[0]=size;return spx_wine_invoke(installed,c); }
HEADER_WRAPPER(midi_prepare,SPX_MIDI_PREPARE)
HEADER_WRAPPER(midi_out,SPX_MIDI_OUT)
HEADER_WRAPPER(midi_unprepare,SPX_MIDI_UNPREPARE)
#undef HEADER_WRAPPER
#define STREAM_WRAPPER(name,operation) static MMRESULT WINAPI name(HMIDISTRM stream) { \
    spx_wine_call c={0};c.api=operation;c.handle=(uintptr_t)stream;return spx_wine_invoke(installed,c); }
STREAM_WRAPPER(midi_restart,SPX_MIDI_RESTART)
STREAM_WRAPPER(midi_pause,SPX_MIDI_PAUSE)
STREAM_WRAPPER(midi_reset,SPX_MIDI_RESET)
STREAM_WRAPPER(midi_close,SPX_MIDI_CLOSE)
#undef STREAM_WRAPPER
int spx_wine_install_midi(spx_wine_env *e,const char *module,unsigned operations) {
    if(installed || !operations || (operations&~511U))return 0;
    midi_environment *m=midi(e);void (*functions[])(void)={(void (*)(void))midi_open,(void (*)(void))midi_property,
        (void (*)(void))midi_prepare,(void (*)(void))midi_out,(void (*)(void))midi_restart,(void (*)(void))midi_pause,
        (void (*)(void))midi_reset,(void (*)(void))midi_unprepare,(void (*)(void))midi_close};
    for(unsigned i=0;i<9;++i)if(operations&(1U<<i)) {
        if(!spx_fixture_redirect_import(&m->imports[i],module,"winmm.dll",spx_wine_api_name(SPX_MIDI_OPEN+i),functions[i])) {
            for(unsigned j=0;j<i;++j)if(m->imports[j].slot)require(spx_fixture_restore_import(&m->imports[j]),"rollback MIDI imports");
            return 0;
        }
    }
    installed=e;return 1;
}
int spx_wine_uninstall_midi(spx_wine_env *e) {
    if(installed!=e)return 1;
    midi_environment *m=midi(e);for(unsigned i=0;i<9;++i)if(m->imports[i].slot && !spx_fixture_restore_import(&m->imports[i]))return 0;
    installed=NULL;return 1;
}
uint32_t spx_wine_midi_candidate_call(spx_wine_env *e,spx_wine_call c) {
    require(installed==e,"candidate MIDI binding requires installed environment");return spx_wine_invoke(e,c);
}
#else
int spx_wine_install_midi(spx_wine_env *e,const char *module,unsigned operations) { (void)e;(void)module;(void)operations;return 0; }
int spx_wine_uninstall_midi(spx_wine_env *e) { (void)e;return 1; }
uint32_t spx_wine_midi_candidate_call(spx_wine_env *e,spx_wine_call c) { return spx_wine_invoke(e,c); }
#endif
uint32_t spx_wine_midi_open(spx_wine_env *e,void *out,uint32_t *device,uint32_t count,spx_wine_midi_callback fn,uintptr_t instance,uint32_t flags) {
    callback_binding binding={fn,instance,0};spx_wine_call c={0};c.api=SPX_MIDI_OPEN;c.output=out;c.buffer=device;c.input=&binding;c.arguments[0]=count;c.arguments[1]=flags;
    return spx_wine_candidate_call(e,c);
}
uint32_t spx_wine_midi_property(spx_wine_env *e,uintptr_t stream,void *property,uint32_t flags) {
    spx_wine_call c={0};c.api=SPX_MIDI_PROPERTY;c.handle=stream;c.buffer=property;c.arguments[0]=flags;return spx_wine_candidate_call(e,c);
}
uint32_t spx_wine_midi_header_call(spx_wine_env *e,enum spx_wine_api api,uintptr_t stream,spx_wine_midi_header *header,uint32_t abi_size) {
    require(api==SPX_MIDI_PREPARE || api==SPX_MIDI_OUT || api==SPX_MIDI_UNPREPARE,"MIDI header binding API");
    spx_wine_call c={0};c.api=api;c.handle=stream;c.buffer=header;c.arguments[0]=abi_size;return spx_wine_candidate_call(e,c);
}
uint32_t spx_wine_midi_stream_call(spx_wine_env *e,enum spx_wine_api api,uintptr_t stream) {
    require(api>=SPX_MIDI_RESTART && api<=SPX_MIDI_CLOSE && api!=SPX_MIDI_UNPREPARE,"MIDI stream binding API");
    spx_wine_call c={0};c.api=api;c.handle=stream;return spx_wine_candidate_call(e,c);
}
