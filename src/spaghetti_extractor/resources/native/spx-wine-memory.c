/* Win32 storage services. Resource identity is independent of handle value;
 * movable handles and their locked bytes are deliberately different objects. */
#include "spx-wine-test-internal.h"
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include "pe32-import-hook.h"
#endif

enum { MEMORY_BLOCKS=512, MEMORY_BYTES=4194304 };
typedef struct {
    uintptr_t handle;
    unsigned char *bytes;
    uint32_t id,local,flags,size,live,locks;
} memory_block;
typedef struct {
    memory_block blocks[MEMORY_BLOCKS];
    unsigned count,history_set;
    unsigned char history;
    uint32_t error;
#ifdef _WIN32
    spx_fixture_import_hook imports[7];
#endif
} memory_environment;
static void require(int yes,const char *why) { if(!yes)spx_wine_unavailable(why); }
static memory_environment *memory(spx_wine_env *e) {
    if(!e->memory) { e->memory=calloc(1,sizeof(memory_environment));require(e->memory!=NULL,"memory environment allocation"); }
    return e->memory;
}
void spx_wine_allocation_history(spx_wine_env *e,unsigned char value) {
    require(e->mode==SPX_WINE_CONTROLLED,"allocator history requires controlled mode");
    memory_environment *m=memory(e);m->history_set=1;m->history=value;
}
static memory_block *by_handle(memory_environment *m,uintptr_t h) {
    for(unsigned i=m->count;i;--i)if(m->blocks[i-1].handle==h)return &m->blocks[i-1];
    return NULL;
}
static memory_block *by_pointer(memory_environment *m,const void *p) {
    uintptr_t a=(uintptr_t)p;
    if(!p)return NULL;
    for(unsigned i=m->count;i;--i) {
        memory_block *b=&m->blocks[i-1];uintptr_t base=(uintptr_t)b->bytes;
        if(base && a>=base && a-base<(b->size ? b->size : 1))return b;
    }
    return NULL;
}
spx_wine_storage spx_wine_memory_storage(spx_wine_env *e,const void *p) {
    if(!p)return (spx_wine_storage){0};
    memory_block *b=by_pointer(memory(e),p);require(b!=NULL,"unbound allocation pointer");
    return (spx_wine_storage){b->id,(uint32_t)((uintptr_t)p-(uintptr_t)b->bytes),b->size,b->live,b->locks};
}
void *spx_wine_memory_address(spx_wine_env *e,uint32_t id) {
    memory_environment *m=memory(e);require(id && id<=m->count,"allocation identity");memory_block *b=&m->blocks[id-1];
    require(b->live && b->bytes && (!(b->flags&2) || b->locks),"allocation address requires live accessible storage");return b->bytes;
}
void spx_wine_memory_validate_rule(const spx_wine_rule *r) {
    int alloc=r->api==SPX_LOCAL_ALLOC || r->api==SPX_GLOBAL_ALLOC;
    require(!(r->flags&~(SPX_RULE_RETURN|SPX_RULE_ERROR|SPX_RULE_BYTES|SPX_RULE_CALLBACK)),"memory scenario flags");
    require(!(r->flags&SPX_RULE_BYTES) || (alloc && r->byte_count<=MEMORY_BYTES && (!r->byte_count || r->bytes)),"allocation history bytes");
    if(r->flags&SPX_RULE_RETURN) {
        int free_call=r->api==SPX_LOCAL_FREE || r->api==SPX_GLOBAL_FREE;
        require(free_call ? r->result==1 : r->result==0,"memory return injection accepts only API failure");
        require(r->api!=SPX_GLOBAL_UNLOCK || ((r->flags&SPX_RULE_ERROR) && r->last_error),"unlock failure requires a nonzero error");
    }
}
#ifdef _WIN32
static FARPROC procedure(const char *name) {
    FARPROC p=GetProcAddress(GetModuleHandleA("kernel32.dll"),name);require(p!=NULL,"resolve native storage API");return p;
}
static uintptr_t native(spx_wine_call c,uint32_t error,uint32_t *after) {
    FARPROC p=procedure(spx_wine_api_name(c.api));uintptr_t result;
    SetLastError(error);
    if(c.api==SPX_LOCAL_ALLOC || c.api==SPX_GLOBAL_ALLOC) {
        typedef HGLOBAL (WINAPI *fn)(UINT,SIZE_T);result=(uintptr_t)((fn)(uintptr_t)p)(c.arguments[0],c.arguments[1]);
    } else if(c.api==SPX_GLOBAL_UNLOCK) {
        typedef BOOL (WINAPI *fn)(HGLOBAL);result=(uint32_t)((fn)(uintptr_t)p)((HGLOBAL)c.handle);
    } else {
        typedef HGLOBAL (WINAPI *fn)(HGLOBAL);result=(uintptr_t)((fn)(uintptr_t)p)((HGLOBAL)c.handle);
    }
    *after=GetLastError();return result;
}
#endif
uint32_t spx_wine_memory_invoke(spx_wine_env *e,spx_wine_call c) {
    require(c.api>=SPX_LOCAL_ALLOC && c.api<=SPX_GLOBAL_HANDLE && c.output,"memory call shape");
    spx_wine_thread_check(e);memory_environment *m=memory(e);uint32_t error=spx_wine_file_last_error(e);
    int alloc=c.api==SPX_LOCAL_ALLOC || c.api==SPX_GLOBAL_ALLOC;
    int local=c.api==SPX_LOCAL_ALLOC || c.api==SPX_LOCAL_FREE;
    memory_block *b=NULL;
    if(alloc) {
        require(c.arguments[1]<=MEMORY_BYTES && !(c.arguments[0]&~(local ? 0x40U : 0x2042U)),"storage supports bounded fixed-local or fixed/movable-global allocation");
    } else if(c.handle) {
        b=c.api==SPX_GLOBAL_HANDLE ? by_pointer(m,(const void *)c.handle) : by_handle(m,c.handle);
        require(b!=NULL,"unbound memory handle; observe its allocation");
        require(b->local==(uint32_t)local,"mismatched local/global allocation family");
        if(c.api==SPX_GLOBAL_HANDLE)require(c.handle==(uintptr_t)b->bytes,"GlobalHandle requires the allocation base");
    }
    require(e->event_count<SPX_WINE_EVENTS,"memory event capacity");
    spx_wine_event *v=&e->events[e->event_count++];v->sequence=e->event_count;v->api=c.api;v->occurrence=++e->calls[c.api];
    v->controlled=e->mode==SPX_WINE_CONTROLLED;v->receiver=b ? b->id : 0;v->handle_known=1;
    v->last_error=error;v->argument_count=alloc ? 2 : 0;memcpy(v->arguments,c.arguments,sizeof(v->arguments));
    if(b) { v->handle_live_before=b->live;v->locks_before=b->locks; }
    spx_wine_rule r=spx_wine_select_rule(e,c.api,v->receiver,v->occurrence);spx_wine_memory_validate_rule(&r);
    if(e->hooks.before)e->hooks.before(e->hooks.context,v);
    uintptr_t result=0;int failed=(r.flags&SPX_RULE_RETURN)!=0;
    if(b && b->live && !failed && (c.api==SPX_LOCAL_FREE || c.api==SPX_GLOBAL_FREE))spx_wine_midi_retire_memory(e,b->bytes,b->size,0);
    if(e->mode==SPX_WINE_NATIVE) {
#ifdef _WIN32
        result=native(c,error,&v->last_error);
#else
        spx_wine_unavailable("native storage requires Wine/Win32");
#endif
    } else if(failed) {
        result=(c.api==SPX_LOCAL_FREE || c.api==SPX_GLOBAL_FREE) ? c.handle : 0;
        v->last_error=8;
    } else if(alloc) {
        require((c.arguments[0]&0x40) || m->history_set || (r.flags&SPX_RULE_BYTES),"nonzero-initialized allocation requires explicit history bytes");
        result=1;
    } else if(c.api==SPX_LOCAL_FREE || c.api==SPX_GLOBAL_FREE) {
        if(c.handle && (!b || !b->live)) { result=c.handle;v->last_error=6; }
    } else if(!b || !b->live) {
        v->last_error=6;
    } else if(c.api==SPX_GLOBAL_LOCK) {
        result=b->size ? (uintptr_t)b->bytes : 0;
        if(!result)v->last_error=157;
    } else if(c.api==SPX_GLOBAL_HANDLE)result=b->handle;
    else if(!(b->flags&2))result=1;
    else if(!b->locks)v->last_error=158;
    else { result=b->locks>1;v->last_error=0; }
    if(r.flags&SPX_RULE_ERROR)v->last_error=r.last_error;
    if(alloc && result) {
        require(m->count<MEMORY_BLOCKS,"memory allocation capacity");b=&m->blocks[m->count++];
        b->id=m->count;b->local=(uint32_t)local;b->flags=c.arguments[0];b->size=c.arguments[1];b->live=1;
        if(e->mode==SPX_WINE_CONTROLLED) {
            b->bytes=malloc(b->size ? b->size : 1);require(b->bytes!=NULL,"controlled allocation storage");
            memset(b->bytes,(b->flags&0x40) ? 0 : m->history,b->size);
            if(r.flags&SPX_RULE_BYTES) { require(r.byte_count==b->size && !(b->flags&0x40),"allocation history must cover noninitialized allocation exactly");if(b->size)memcpy(b->bytes,r.bytes,b->size); }
            result=(b->flags&2) ? (uintptr_t)b : (uintptr_t)b->bytes;
        } else if(!(b->flags&2))b->bytes=(void *)result;
        b->handle=result;
    } else if(b && b->live) {
        if((c.api==SPX_LOCAL_FREE || c.api==SPX_GLOBAL_FREE) && !result) { spx_wine_midi_retire_memory(e,b->bytes,b->size,1);b->live=0;b->locks=0; }
        else if(c.api==SPX_GLOBAL_LOCK && result) { b->bytes=(void *)result;if(b->flags&2)++b->locks; }
        else if(c.api==SPX_GLOBAL_UNLOCK && !failed && (b->flags&2) && b->locks && (result || !v->last_error))--b->locks;
    }
    if(b) { v->storage=b->id;v->storage_extent=b->size;v->handle_live_after=b->live;v->locks_after=b->locks; }
    v->result=c.api==SPX_GLOBAL_UNLOCK ? (uint32_t)result : result && b ? b->id : 0;
    v->output_object=c.api==SPX_GLOBAL_UNLOCK ? 0 : v->result;
    memcpy(c.output,&result,sizeof(result));spx_wine_set_last_error(e,v->last_error);
    if(r.flags&SPX_RULE_CALLBACK) { require(e->hooks.callback!=NULL,"memory callback is unbound");v->callback=r.callback;e->hooks.callback(e->hooks.context,r.callback); }
    if(e->hooks.after)e->hooks.after(e->hooks.context,v);
    spx_wine_set_last_error(e,v->last_error);return v->result;
}
void spx_wine_memory_observe(spx_wine_env *e,spx_observer *out) {
    /* Installing an import hook is instrumentation, not an allocation event. */
    memory_environment *m=e->memory;if(!m || !m->count)return;
    spx_observe_array(out,"allocations");
    for(unsigned i=0;i<m->count;++i) {
        memory_block *b=&m->blocks[i];spx_observe_object(out,NULL);
        spx_observe_u64(out,"id",b->id);spx_observe_u64(out,"local",b->local);spx_observe_u64(out,"flags",b->flags);
        spx_observe_u64(out,"size",b->size);spx_observe_u64(out,"live",b->live);spx_observe_u64(out,"locks",b->locks);spx_observe_end(out);
    }
    spx_observe_end(out);
}
void spx_wine_memory_destroy(spx_wine_env *e) {
    memory_environment *m=e->memory;if(!m)return;
    /* Retain controlled addresses until teardown so stale identities remain
     * observable. This does not authorize dereferencing a retired allocation. */
    if(e->mode==SPX_WINE_CONTROLLED)for(unsigned i=0;i<m->count;++i)free(m->blocks[i].bytes);
    free(m);e->memory=NULL;
}
#ifdef _WIN32
static spx_wine_env *installed;
static uintptr_t invoke(enum spx_wine_api api,uintptr_t h,uint32_t flags,size_t size) {
    require(installed && size<=MEMORY_BYTES,"installed bounded memory binding");
    spx_wine_call c={0};uintptr_t result=0;c.api=api;c.handle=h;c.arguments[0]=flags;c.arguments[1]=(uint32_t)size;c.output=&result;
    spx_wine_invoke(installed,c);return result;
}
static HLOCAL WINAPI local_alloc(UINT f,SIZE_T n) { return (HLOCAL)invoke(SPX_LOCAL_ALLOC,0,f,n); }
static HLOCAL WINAPI local_free(HLOCAL h) { return (HLOCAL)invoke(SPX_LOCAL_FREE,(uintptr_t)h,0,0); }
static HGLOBAL WINAPI global_alloc(UINT f,SIZE_T n) { return (HGLOBAL)invoke(SPX_GLOBAL_ALLOC,0,f,n); }
static LPVOID WINAPI global_lock(HGLOBAL h) { return (LPVOID)invoke(SPX_GLOBAL_LOCK,(uintptr_t)h,0,0); }
static BOOL WINAPI global_unlock(HGLOBAL h) { return (BOOL)invoke(SPX_GLOBAL_UNLOCK,(uintptr_t)h,0,0); }
static HGLOBAL WINAPI global_free(HGLOBAL h) { return (HGLOBAL)invoke(SPX_GLOBAL_FREE,(uintptr_t)h,0,0); }
static HGLOBAL WINAPI global_handle(LPCVOID p) { return (HGLOBAL)invoke(SPX_GLOBAL_HANDLE,(uintptr_t)p,0,0); }
int spx_wine_install_memory(spx_wine_env *e,const char *module,unsigned operations) {
    if(installed || !operations || (operations&~127U))return 0;
    void (*functions[])(void)={(void (*)(void))local_alloc,(void (*)(void))local_free,(void (*)(void))global_alloc,
        (void (*)(void))global_lock,(void (*)(void))global_unlock,(void (*)(void))global_free,(void (*)(void))global_handle};
    memory_environment *m=memory(e);
    for(unsigned i=0;i<7;++i)if(operations&(1U<<i)) {
        if(!spx_fixture_redirect_import(&m->imports[i],module,"kernel32.dll",spx_wine_api_name(SPX_LOCAL_ALLOC+i),functions[i])) {
            for(unsigned j=0;j<i;++j)if(m->imports[j].slot)require(spx_fixture_restore_import(&m->imports[j]),"rollback memory import interception");
            return 0;
        }
    }
    installed=e;return 1;
}
int spx_wine_uninstall_memory(spx_wine_env *e) {
    if(installed!=e)return 1;
    memory_environment *m=memory(e);
    for(unsigned i=0;i<7;++i)if(m->imports[i].slot && !spx_fixture_restore_import(&m->imports[i]))return 0;
    installed=NULL;return 1;
}
uint32_t spx_wine_memory_candidate_call(spx_wine_env *e,spx_wine_call c) {
    require(installed==e,"candidate memory binding requires installed environment");
    uintptr_t value=invoke(c.api,c.handle,c.arguments[0],c.arguments[1]);memcpy(c.output,&value,sizeof(value));
    return c.api==SPX_GLOBAL_UNLOCK ? (uint32_t)value : value!=0;
}
#else
int spx_wine_install_memory(spx_wine_env *e,const char *module,unsigned operations) { (void)e;(void)module;(void)operations;return 0; }
int spx_wine_uninstall_memory(spx_wine_env *e) { (void)e;return 1; }
uint32_t spx_wine_memory_candidate_call(spx_wine_env *e,spx_wine_call c) { return spx_wine_invoke(e,c); }
#endif
static uintptr_t candidate(spx_wine_env *e,enum spx_wine_api api,uintptr_t h,uint32_t flags,size_t size) {
    require(size<=MEMORY_BYTES,"allocation extent");spx_wine_call c={0};uintptr_t value=0;
    c.api=api;c.handle=h;c.arguments[0]=flags;c.arguments[1]=(uint32_t)size;c.output=&value;spx_wine_candidate_call(e,c);return value;
}
uintptr_t spx_wine_local_alloc(spx_wine_env *e,uint32_t f,size_t n) { return candidate(e,SPX_LOCAL_ALLOC,0,f,n); }
uintptr_t spx_wine_local_free(spx_wine_env *e,uintptr_t h) { return candidate(e,SPX_LOCAL_FREE,h,0,0); }
uintptr_t spx_wine_global_alloc(spx_wine_env *e,uint32_t f,size_t n) { return candidate(e,SPX_GLOBAL_ALLOC,0,f,n); }
void *spx_wine_global_lock(spx_wine_env *e,uintptr_t h) { return (void *)candidate(e,SPX_GLOBAL_LOCK,h,0,0); }
uint32_t spx_wine_global_unlock(spx_wine_env *e,uintptr_t h) { return (uint32_t)candidate(e,SPX_GLOBAL_UNLOCK,h,0,0); }
uintptr_t spx_wine_global_free(spx_wine_env *e,uintptr_t h) { return candidate(e,SPX_GLOBAL_FREE,h,0,0); }
uintptr_t spx_wine_global_handle(spx_wine_env *e,const void *p) { return candidate(e,SPX_GLOBAL_HANDLE,(uintptr_t)p,0,0); }
