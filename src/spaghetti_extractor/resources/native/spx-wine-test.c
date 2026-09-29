#include "spx-wine-test-internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void spx_wine_unavailable(const char *reason) {
    fprintf(stderr,"shared Wine environment: unsupported or invalid setup: %s\n",reason);fflush(NULL);exit(78);
}
static void require(int yes,const char *reason) { if (!yes) spx_wine_unavailable(reason); }
static int word_output(enum spx_wine_api);
const char *spx_wine_api_name(enum spx_wine_api api) {
    static const char *const names[]={"DirectSoundCreate","IDirectSound.SetCooperativeLevel","IDirectSound.CreateSoundBuffer",
        "IUnknown.Release","IUnknown.AddRef","IUnknown.QueryInterface","IDirectSoundBuffer.SetFrequency",
        "IDirectSoundBuffer.SetPan","IDirectSoundBuffer.SetVolume","IDirectSoundBuffer.SetCurrentPosition",
        "IDirectSoundBuffer.Play","IDirectSoundBuffer.GetStatus","IDirectSoundBuffer.Restore","IDirectSoundBuffer.Stop",
        "IDirectSoundBuffer.GetFrequency","IDirectSoundBuffer.GetPan","IDirectSoundBuffer.GetVolume",
        "IDirectSoundBuffer.Lock","IDirectSoundBuffer.Unlock","MessageBoxA",
        "CreateFileA","GetFileSize","ReadFile","CloseHandle",
        "CreateFileMappingA","MapViewOfFile","UnmapViewOfFile",
        "LocalAlloc","LocalFree","GlobalAlloc","GlobalLock","GlobalUnlock","GlobalFree","GlobalHandle",
        "midiStreamOpen","midiStreamProperty","midiOutPrepareHeader","midiStreamOut","midiStreamRestart",
        "midiStreamPause","midiOutReset","midiOutUnprepareHeader","midiStreamClose","MidiOutProc",
        "DirectDrawCreate","IDirectDraw.SetCooperativeLevel","IDirectDraw.CreateSurface",
        "IDirectDrawSurface.GetSurfaceDesc","IDirectDrawSurface.Lock","IDirectDrawSurface.Unlock","IDirectDrawSurface.Blt"};
    require((unsigned)api<SPX_WINE_API_COUNT,"unknown API");return names[api];
}
spx_wine_env *spx_wine_create(enum spx_wine_mode mode) {
    require(mode==SPX_WINE_CONTROLLED || mode==SPX_WINE_NATIVE,"unknown mode");
    spx_wine_env *e=calloc(1,sizeof(*e));require(e!=NULL,"environment allocation");e->mode=mode;spx_wine_thread_check(e);return e;
}
void spx_wine_destroy(spx_wine_env *e) {
    spx_wine_enter(e);
    require(spx_wine_uninstall_draw(e) && spx_wine_uninstall_midi(e) && spx_wine_uninstall_memory(e) && spx_wine_uninstall_files(e) && spx_wine_uninstall(e),"restore import hooks before disposal");
    spx_wine_draw_destroy(e);
    spx_wine_midi_destroy(e);
    spx_wine_memory_destroy(e);
    spx_wine_files_destroy(e);
    for (unsigned i=0;i<e->rule_count;++i)free((void *)e->rules[i].bytes);
    for (unsigned i=0;i<e->object_count;++i) free(e->objects[i].bytes);
    for (unsigned i=0;i<e->event_count;++i) { free(e->events[i].text);free(e->events[i].caption);free(e->events[i].data);free(e->events[i].byte_mask); }
    /* Do not release live application resources on its behalf. */
    spx_wine_leave(e);spx_wine_guard_destroy(e);free(e);
}
void spx_wine_set_hooks(spx_wine_env *e,spx_wine_hooks hooks) { e->hooks=hooks; }
void spx_wine_add_rule(spx_wine_env *e,spx_wine_rule r) {
    require((unsigned)r.api<SPX_WINE_API_COUNT,"invalid scenario API");
    if(r.api>=SPX_DD_CREATE)spx_wine_draw_validate_rule(&r);
    else if(r.api>=SPX_MIDI_OPEN)spx_wine_midi_validate_rule(&r);
    else if(r.api>=SPX_LOCAL_ALLOC)spx_wine_memory_validate_rule(&r);
    else if(r.api>=SPX_FILE_OPEN_A)spx_wine_file_validate_rule(&r);
    else {
        require(!(r.flags&~31U),"invalid scenario rule");
        require(!(r.flags&SPX_RULE_NO_WRITE) || !(r.flags&(SPX_RULE_OBJECT|SPX_RULE_WORD)),"conflicting output rules");
        int factory=r.api==SPX_DS_CREATE || r.api==SPX_DS_CREATE_BUFFER;
        require(!(r.flags&SPX_RULE_OBJECT) || factory,"object rule requires a factory");
        require(!(r.flags&SPX_RULE_WORD) || word_output(r.api),"word rule requires a word output");
        require(!(r.flags&SPX_RULE_NO_WRITE) || factory || word_output(r.api) || r.api==SPX_COM_QUERY,"no-write rule requires a supported output");
        require(!(r.flags&SPX_RULE_RETURN) || (r.api!=SPX_COM_RELEASE && r.api!=SPX_COM_ADDREF),"reference counts follow the controlled lifecycle");
    }
    require(e->rule_count<SPX_WINE_RULES,"scenario capacity");
    require(e->mode==SPX_WINE_CONTROLLED,"injection requires explicit controlled mode");
    if(r.flags&SPX_RULE_BYTES) {
        unsigned char *copy=r.byte_count ? malloc(r.byte_count) : NULL;
        require(!r.byte_count || copy,"scenario byte allocation");
        if(r.byte_count)memcpy(copy,r.bytes,r.byte_count);
        r.bytes=copy;
    } else r.bytes=NULL;
    e->rules[e->rule_count++]=r;
}
spx_wine_object *spx_wine_object_at(spx_wine_env *e,uint32_t id) {
    require(id && id<=e->object_count && e->objects[id-1].id==id,"unknown object identity");return &e->objects[id-1];
}
spx_wine_object *spx_wine_new_object(spx_wine_env *e,enum spx_wine_kind kind,void *native) {
    require(kind>=SPX_WINE_DS_DEVICE && kind<=SPX_WINE_DD_SURFACE,"unsupported interface kind");
    require(e->object_count<SPX_WINE_OBJECTS,"object capacity");
    spx_wine_object *o=&e->objects[e->object_count++];o->owner=e;o->id=e->object_count;o->kind=kind;o->native=native;
    o->state.references=1;o->state.generation=1;spx_wine_native_object(o);return o;
}
spx_wine_object *spx_wine_seed(spx_wine_env *e,uint32_t id,enum spx_wine_kind kind,spx_wine_object_state state) {
    require(e->mode==SPX_WINE_CONTROLLED && id==e->object_count+1,"seed order or execution mode");
    spx_wine_object *o=spx_wine_new_object(e,kind,NULL);o->state=state;if (!o->state.generation)o->state.generation=1;return o;
}
uint32_t spx_wine_object_id(const void *p) { const spx_wine_object *o=p;return o ? o->id : 0; }
enum spx_wine_kind spx_wine_object_kind(const void *p) { require(p!=NULL,"null interface");return ((const spx_wine_object *)p)->kind; }
spx_wine_object_state spx_wine_state(const void *p) { require(p!=NULL,"null interface");return ((const spx_wine_object *)p)->state; }
void spx_wine_controlled_state(spx_wine_object *o,spx_wine_object_state state) {
    require(o->owner->mode==SPX_WINE_CONTROLLED,"changing native resource state");o->state=state;
}
void spx_wine_store_object(void *slot,spx_wine_object *o) { require(slot!=NULL,"missing object output");memcpy(slot,&o,sizeof(o)); }
static char *copy_text(const char *s) {
    if (!s)return NULL;
    size_t n=strlen(s);require(n<=65536,"text observation capacity");char *p=malloc(n+1);require(p!=NULL,"text observation allocation");memcpy(p,s,n+1);return p;
}
static int word_output(enum spx_wine_api api) {
    return api==SPX_DS_STATUS || api==SPX_DS_GET_FREQUENCY || api==SPX_DS_GET_PAN || api==SPX_DS_GET_VOLUME;
}
static void capture(spx_wine_event *v,const void *first,size_t a,const void *second,size_t b) {
    require(a<=4194304 && b<=4194304 && (!a || first) && (!b || second),"byte observation extent");
    v->data_bytes=a+b;if (!v->data_bytes)return;
    v->data=malloc(a+b);require(v->data!=NULL,"byte observation allocation");
    if(a)memcpy(v->data,first,a);
    if(b)memcpy(v->data+a,second,b);
}
void spx_wine_bind_window(spx_wine_env *e,uintptr_t window,uint32_t identity) {
    require(window && identity,"external window binding");
    for (unsigned i=0;i<e->window_count;++i)if(e->windows[i]==window || e->window_ids[i]==identity) {
        require(e->windows[i]==window && e->window_ids[i]==identity,"conflicting external window binding");return;
    }
    require(e->window_count<128,"window identity capacity");
    unsigned i=e->window_count++;e->windows[i]=window;e->window_ids[i]=identity;
}
uint32_t spx_wine_window_identity(spx_wine_env *e,uintptr_t window) {
    if (!window)return 0;
    for (unsigned i=0;i<e->window_count;++i)if(e->windows[i]==window)return e->window_ids[i];
    spx_wine_unavailable("external window needs an input correspondence binding");return 0;
}
static int supported_iid(spx_wine_object *o,const void *iid) {
    static const unsigned char unknown[16]={0,0,0,0,0,0,0,0,0xc0,0,0,0,0,0,0,0x46};
    unsigned char sound[16]={0x83,0xfa,0x9a,0x27,0x81,0x49,0xce,0x11,0xa5,0x21,0,0x20,0xaf,0x0b,0xe5,0x60};
    if(o->kind==SPX_WINE_DS_BUFFER)sound[0]=0x85;
    if(o->kind==SPX_WINE_DD_DEVICE || o->kind==SPX_WINE_DD_SURFACE) {
        const unsigned char draw[16]={0x80,0xdb,0x14,0x6c,0x33,0xa7,0xce,0x11,0xa5,0x21,0,0x20,0xaf,0x0b,0xe5,0x60};
        memcpy(sound,draw,16);if(o->kind==SPX_WINE_DD_SURFACE)sound[0]=0x81;
    }
    return iid && (!memcmp(iid,unknown,16) || !memcmp(iid,sound,16));
}
static uint32_t controlled(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v,const spx_wine_rule *r) {
    spx_wine_object *o=c->receiver;
    uint32_t result=r->flags&SPX_RULE_RETURN ? r->result : 0;
    /* A controlled object's lifetime is explicit scenario state. An expired
     * receiver is an unsupported experiment, not an invented native fault. */
    if (o)require(o->state.references!=0,"controlled expired receiver needs an explicit memory/lifetime experiment");
    if (c->api==SPX_DS_CREATE || c->api==SPX_DS_CREATE_BUFFER) {
        if (c->api==SPX_DS_CREATE_BUFFER)require(o && o->kind==SPX_WINE_DS_DEVICE && c->input,"buffer creation arguments");
        if (!(r->flags&SPX_RULE_NO_WRITE) && (!result || (r->flags&SPX_RULE_OBJECT))) {
            enum spx_wine_kind kind=c->api==SPX_DS_CREATE ? SPX_WINE_DS_DEVICE : SPX_WINE_DS_BUFFER;
            spx_wine_object *made=r->flags&SPX_RULE_OBJECT ? (r->object ? spx_wine_object_at(e,r->object) : NULL) : spx_wine_new_object(e,kind,NULL);
            if (made) {
                require(made->kind==kind,"wrong output interface kind");
                if (r->references) { made->state.references=r->references;++made->state.generation; }
                if (kind==SPX_WINE_DS_BUFFER) {
                    const spx_wine_buffer_spec *spec=c->input;
                    free(made->bytes);made->size=spec->bytes;made->bytes=spec->bytes ? calloc(1,spec->bytes) : NULL;
                    require(!spec->bytes || made->bytes,"controlled buffer allocation");
                }
            }
            spx_wine_store_object(c->output,made);v->output_object=spx_wine_object_id(made);v->written_mask=UINT32_MAX;
        }
    } else if (c->api==SPX_USER_MESSAGE_A) {
        require(r->flags&SPX_RULE_RETURN,"controlled MessageBox requires an explicit return schedule");
    } else if (word_output(c->api)) {
        require(o && c->output,"query arguments");
        uint32_t value=c->api==SPX_DS_STATUS ? o->state.status : c->api==SPX_DS_GET_FREQUENCY ? o->state.frequency : c->api==SPX_DS_GET_PAN ? o->state.pan : o->state.volume;
        uint32_t mask=r->flags&SPX_RULE_NO_WRITE ? 0 : r->flags&SPX_RULE_WORD ? r->mask : (!result ? UINT32_MAX : 0);
        if (r->flags&SPX_RULE_WORD)value=r->value;
        memcpy(&v->output_word,c->output,4);v->output_word=(v->output_word&~mask)|(value&mask);memcpy(c->output,&v->output_word,4);v->written_mask=mask;
    } else if (c->api==SPX_COM_RELEASE) {
        require(o!=NULL,"release receiver");result=--o->state.references;
    } else if (c->api==SPX_COM_ADDREF || c->api==SPX_COM_QUERY) {
        require(o!=NULL,"reference receiver");
        if (c->api==SPX_COM_QUERY) {
            require(supported_iid(o,c->input),"controlled QueryInterface projection");
            if (result || (r->flags&SPX_RULE_NO_WRITE))return result;
        }
        ++o->state.references;
        if (c->api==SPX_COM_QUERY) { spx_wine_store_object(c->output,o);v->output_object=o->id;v->written_mask=UINT32_MAX; }
        else result=o->state.references;
    } else if (!result) {
        switch (c->api) {
        case SPX_DS_COOPERATIVE:break;
        case SPX_DS_FREQUENCY:o->state.frequency=c->arguments[0];break;
        case SPX_DS_PAN:o->state.pan=c->arguments[0];break;
        case SPX_DS_VOLUME:o->state.volume=c->arguments[0];break;
        case SPX_DS_POSITION:o->state.position=c->arguments[0];break;
        case SPX_DS_PLAY:o->state.status|=1;break;
        case SPX_DS_STOP:o->state.status&=~1U;break;
        case SPX_DS_RESTORE:o->state.status&=~2U;break;
        case SPX_DS_LOCK: {
            require(o && c->output && o->size,"lock arguments");uint32_t start=c->arguments[0],n=c->arguments[1];
            require(c->arguments[3]==15 && !c->arguments[2],"controlled lock flags or optional outputs");
            require(start<o->size && n<=o->size,"controlled lock range");spx_wine_locked *lock=c->output;
            lock->first=o->bytes+start;lock->first_bytes=n<o->size-start ? n : o->size-start;
            lock->second=n>lock->first_bytes ? o->bytes : NULL;lock->second_bytes=n-lock->first_bytes;break;
        }
        case SPX_DS_UNLOCK:break;
        default:spx_wine_unavailable("controlled API implementation");
        }
    }
    return result;
}
spx_wine_rule spx_wine_select_rule(spx_wine_env *e,enum spx_wine_api api,uint32_t receiver,uint32_t occurrence) {
    spx_wine_rule selected={0};selected.api=api;
    for (unsigned i=0;i<e->rule_count;++i) {
        const spx_wine_rule *r=&e->rules[i];
        if (r->api==api && (!r->receiver || r->receiver==receiver) && (!r->occurrence || r->occurrence==occurrence)) {
            /* Composition is explicit; overlapping flags are rejected so rule
             * order cannot silently change a result or output. */
            require(!(selected.flags&r->flags),"ambiguous scenario rules");
            if (r->flags&SPX_RULE_RETURN)selected.result=r->result;
            if (r->flags&SPX_RULE_OBJECT) { selected.object=r->object;selected.references=r->references; }
            if (r->flags&SPX_RULE_WORD) { selected.mask=r->mask;selected.value=r->value; }
            if (r->flags&SPX_RULE_CALLBACK)selected.callback=r->callback;
            if(r->flags&SPX_RULE_BYTES) { selected.bytes=r->bytes;selected.byte_count=r->byte_count; }
            if(r->flags&SPX_RULE_ERROR)selected.last_error=r->last_error;
            if(r->flags&SPX_RULE_LIMIT)selected.limit=r->limit;
            selected.flags|=r->flags;
        }
    }
    require(!(selected.flags&SPX_RULE_NO_WRITE) || !(selected.flags&(SPX_RULE_OBJECT|SPX_RULE_WORD|SPX_RULE_BYTES)),"conflicting composed output rules");
    return selected;
}
static uint32_t invoke(spx_wine_env *e,spx_wine_call c) {
    require(e && (unsigned)c.api<SPX_WINE_API_COUNT && c.argument_count<=8,"call shape");
    spx_wine_thread_check(e);
    if(c.api>=SPX_DD_CREATE)return spx_wine_draw_invoke(e,c);
    if(c.api>=SPX_MIDI_OPEN)return spx_wine_midi_invoke(e,c);
    if(c.api>=SPX_LOCAL_ALLOC)return spx_wine_memory_invoke(e,c);
    if(c.api>=SPX_FILE_OPEN_A)return spx_wine_file_invoke(e,c);
    require(!c.receiver || c.receiver->owner==e,"foreign environment receiver");
    require(!c.receiver || !c.receiver->input_identity,"borrowed interface reference operations require observed ownership");
    require(c.receiver || c.api==SPX_DS_CREATE || c.api==SPX_USER_MESSAGE_A,"missing API receiver");
    require(e->event_count<SPX_WINE_EVENTS,"event capacity");
    spx_wine_event *v=&e->events[e->event_count++];v->sequence=e->event_count;v->api=c.api;v->occurrence=++e->calls[c.api];
    v->controlled=e->mode==SPX_WINE_CONTROLLED;v->receiver=spx_wine_object_id(c.receiver);v->kind=c.receiver ? c.receiver->kind : 0;
    v->argument_count=c.argument_count;memcpy(v->arguments,c.arguments,sizeof(v->arguments));
    /* Canonical ABI shape is independent of a candidate's binding language. */
    if (c.api==SPX_COM_RELEASE || c.api==SPX_COM_ADDREF || c.api==SPX_DS_STOP || c.api==SPX_DS_RESTORE || word_output(c.api))v->argument_count=0;
    if (c.api==SPX_DS_PLAY)v->argument_count=3;
    if (c.api==SPX_DS_LOCK) { if(c.argument_count<4)c.arguments[3]=15;v->arguments[3]=c.arguments[3];v->argument_count=4; }
    if (c.api==SPX_COM_QUERY) { require(c.input!=NULL,"query IID");capture(v,c.input,16,NULL,0);v->argument_count=0; }
    if (c.api==SPX_DS_CREATE && c.input)capture(v,c.input,16,NULL,0);
    if (c.api==SPX_DS_CREATE_BUFFER) {
        require(c.input!=NULL,"missing buffer descriptor");const spx_wine_buffer_spec *s=c.input;
        uint32_t words[]={s->size,s->flags,s->bytes,s->reserved,s->format!=NULL};
        memcpy(v->arguments,words,sizeof(words));v->argument_count=5;
        if (s->format) {
            const unsigned char *p=s->format;
            size_t n=16;
            if (p[0]!=1 || p[1]!=0)n=18+(size_t)p[16]+((size_t)p[17]<<8);
            capture(v,p,n,NULL,0);
        }
    }
    if (c.api==SPX_DS_UNLOCK) {
        require(c.input!=NULL,"unlock input");const spx_wine_locked *p=c.input;
        v->first_bytes=p->first_bytes;v->second_bytes=p->second_bytes;
        v->arguments[0]=p->first_bytes;v->arguments[1]=p->second_bytes;v->argument_count=2;
        capture(v,p->first,p->first_bytes,p->second,p->second_bytes);
    }
    v->text=copy_text(c.text);v->caption=copy_text(c.caption);
    if (c.receiver) { v->references_before=c.receiver->state.references;v->generation=c.receiver->state.generation; }
    if (word_output(c.api)) { require(c.output!=NULL,"query output");memcpy(&v->output_before,c.output,4); }
    if (e->hooks.before)e->hooks.before(e->hooks.context,v);
    if (c.api==SPX_DS_COOPERATIVE || c.api==SPX_USER_MESSAGE_A)v->window=spx_wine_window_identity(e,c.window);
    spx_wine_rule selected=spx_wine_select_rule(e,c.api,v->receiver,v->occurrence);
    v->result=e->mode==SPX_WINE_NATIVE ? spx_wine_native_call(e,&c,v) : controlled(e,&c,v,&selected);
    if (c.api==SPX_DS_LOCK && !v->result) {
        const spx_wine_locked *p=c.output;v->first_bytes=p->first_bytes;v->second_bytes=p->second_bytes;
    }
    if (selected.flags&SPX_RULE_CALLBACK) {
        require(e->hooks.callback!=NULL,"scenario callback is unbound");v->callback=selected.callback;e->hooks.callback(e->hooks.context,selected.callback);
    }
    if (c.receiver)v->references_after=c.receiver->state.references;
    if (e->hooks.after)e->hooks.after(e->hooks.context,v);
    return v->result;
}
uint32_t spx_wine_invoke(spx_wine_env *e,spx_wine_call c) {
    require(e!=NULL,"missing environment");spx_wine_enter(e);
    uint32_t result=invoke(e,c);spx_wine_leave(e);return result;
}
static void observe_byte_mask(spx_observer *out,const unsigned char *mask,size_t size) {
    size_t runs=0;
    for(size_t i=0;i<size;++i)if(!i || mask[i]!=mask[i-1])++runs;
    /* Keep every mask bit. Long initialized/preserved spans need not repeat
     * millions of identical hex digits; irregular or small masks stay hex. */
    if(runs>size/16) { spx_observe_bytes(out,"byte_mask",mask,size);return; }
    spx_observe_array(out,"byte_mask_runs");
    for(size_t i=0;i<size;) {
        size_t end=i+1;while(end<size && mask[end]==mask[i])++end;
        uint32_t run[]={(uint32_t)(end-i),mask[i]};spx_observe_u32s(out,NULL,run,2);i=end;
    }
    spx_observe_end(out);
}
static void observe_payload(spx_wine_env *e,spx_observer *out,unsigned index) {
    const spx_wine_event *v=&e->events[index];
    /* An audio upload commonly copies a range of an already observed file read.
     * This is a byte-value reference, never an inferred storage alias. Search
     * retained bytes exactly; do not know file formats, offsets or target names. */
    if(v->api==SPX_DS_UNLOCK && v->data_bytes>=16)for(unsigned i=0;i<index;++i) {
        const spx_wine_event *p=&e->events[i];
        if(p->api!=SPX_FILE_READ || p->data_bytes<v->data_bytes)continue;
        size_t offset=0,last=p->data_bytes-v->data_bytes;
        while(offset<=last) {
            const unsigned char *found=memchr(p->data+offset,v->data[0],last-offset+1);
            if(!found)break;
            offset=(size_t)(found-p->data);
            if(!memcmp(found,v->data,v->data_bytes)) {
                uint32_t ref[]={i+1,(uint32_t)offset,(uint32_t)v->data_bytes};
                spx_observe_u32s(out,"data_slice_ref",ref,3);return;
            }
            ++offset;
        }
    }
    /* Surface locks often differ by a few raster writes. Keep the complete
     * snapshot in memory and emit a lossless patch against the preceding equal-
     * extent snapshot for this receiver. No hashes, samples or pixel omissions. */
    if(v->api==SPX_DD_UNLOCK)for(unsigned i=index;i;--i) {
        const spx_wine_event *previous=&e->events[i-1];
        if(previous->api!=v->api || previous->receiver!=v->receiver || previous->data_bytes!=v->data_bytes)continue;
        size_t changes=0,runs=0;
        for(size_t j=0;j<v->data_bytes;) {
            if(v->data[j]==previous->data[j]) { ++j;continue; }
            ++runs;
            do { ++changes;++j; } while(j<v->data_bytes && v->data[j]!=previous->data[j]);
        }
        if(!changes) { spx_observe_u64(out,"data_ref",i);return; }
        if(changes*2+runs*48+64<v->data_bytes*2) {
            spx_observe_u64(out,"data_delta_ref",i);spx_observe_array(out,"data_delta");
            for(size_t j=0;j<v->data_bytes;) {
                if(v->data[j]==previous->data[j]) { ++j;continue; }
                size_t start=j;
                do { ++j; } while(j<v->data_bytes && v->data[j]!=previous->data[j]);
                spx_observe_object(out,NULL);spx_observe_u64(out,"offset",start);
                spx_observe_bytes(out,"data",v->data+start,j-start);spx_observe_end(out);
            }
            spx_observe_end(out);return;
        }
        break;
    }
    /* MIDI headers retain the same bytes across prepare/queue/return/unprepare.
     * Retain every snapshot while storing identical contents once in the report.
     * References are one-based positions in calls, never hashes or samples. */
    if(v->api>=SPX_MIDI_OPEN && v->api<=SPX_MIDI_CALLBACK)for(unsigned i=0;i<index;++i) {
        const spx_wine_event *previous=&e->events[i];
        if(previous->api>=SPX_MIDI_OPEN && previous->api<=SPX_MIDI_CALLBACK && previous->data_bytes==v->data_bytes &&
            !memcmp(previous->data,v->data,v->data_bytes)) {
            spx_observe_u64(out,"data_ref",i+1);return;
        }
    }
    spx_observe_bytes(out,"data",v->data,v->data_bytes);
}
void spx_wine_observe(spx_wine_env *e,spx_observer *out,const char *name) {
    spx_wine_enter(e);
    spx_observe_object(out,name);spx_observe_u64(out,"controlled",e->mode==SPX_WINE_CONTROLLED);spx_observe_array(out,"calls");
    for (unsigned i=0;i<e->event_count;++i) {
        const spx_wine_event *v=&e->events[i];spx_observe_object(out,NULL);
        const char *api=spx_wine_api_name(v->api);spx_observe_bytes(out,"api",(const unsigned char *)api,strlen(api));
        spx_observe_u64(out,"receiver",v->receiver);spx_observe_u32s(out,"arguments",v->arguments,v->argument_count);
        if(v->input_identity)spx_observe_u64(out,"input_object",v->input_identity);
        spx_observe_u64(out,"result",v->result);spx_observe_u64(out,"output_object",v->output_object);
        spx_observe_u64(out,"output_word",v->output_word);spx_observe_u64(out,"written_mask",v->written_mask);
        spx_observe_u64(out,"callback",v->callback);spx_observe_u64(out,"references_before",v->references_before);
        spx_observe_u64(out,"references_after",v->references_after);spx_observe_u64(out,"generation",v->generation);
        spx_observe_u64(out,"window",v->window);spx_observe_u64(out,"first_bytes",v->first_bytes);spx_observe_u64(out,"second_bytes",v->second_bytes);
        if(v->api>=SPX_FILE_OPEN_A && v->api<=SPX_MIDI_CALLBACK) {
            spx_observe_u64(out,"last_error",v->last_error);spx_observe_u64(out,"handle_known",v->handle_known);
            spx_observe_u64(out,"live_before",v->handle_live_before);spx_observe_u64(out,"live_after",v->handle_live_after);
            spx_observe_u64(out,"position_before",v->file_position_before);spx_observe_u64(out,"position_after",v->file_position_after);
            spx_observe_u64(out,"positions_known",v->positions_known);
            spx_observe_u64(out,"buffer_extent",v->buffer_extent);spx_observe_u64(out,"transferred",v->transferred);
            spx_observe_u64(out,"footprint_known",v->footprint_known);spx_observe_u64(out,"preserved",v->preserved);
            spx_observe_u64(out,"output_preserved",v->output_preserved);
        }
        if(v->api>=SPX_FILE_MAPPING_A) {
            spx_observe_u64(out,"storage",v->storage);spx_observe_u64(out,"storage_offset",v->storage_offset);
            spx_observe_u64(out,"storage_extent",v->storage_extent);
            spx_observe_u64(out,"locks_before",v->locks_before);spx_observe_u64(out,"locks_after",v->locks_after);
        }
        if(v->byte_mask)observe_byte_mask(out,v->byte_mask,v->data_bytes);
        if(v->data_bytes)observe_payload(e,out,i);
        if (v->text)spx_observe_bytes(out,"text",(const unsigned char *)v->text,strlen(v->text));
        if (v->caption)spx_observe_bytes(out,"caption",(const unsigned char *)v->caption,strlen(v->caption));
        spx_observe_end(out);
    }
    spx_observe_end(out);spx_wine_files_observe(e,out);spx_wine_memory_observe(e,out);spx_wine_midi_observe(e,out);spx_wine_draw_observe(e,out);spx_observe_end(out);
    spx_wine_leave(e);
}
