/* Candidate-neutral synchronous Win32 file services. Controlled data is scenario
 * input; native calls use the DLL exports, even when linked into the importer. */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#include "spx-wine-test-internal.h"
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include "pe32-import-hook.h"
#elif defined(__unix__)
#include <sys/mman.h>
#endif

enum { FILE_ASSETS=128, FILE_HANDLES=512, FILE_BYTES=4194304 };
typedef struct { char *path;unsigned char *bytes;uint32_t size; } file_asset;
typedef struct {
    uintptr_t value;
    uint32_t id,live,share,position_known,mapping,backing,size;
    uint64_t position;
    file_asset *asset;
} file_handle;
typedef struct {
    void *address;
    uint32_t id,live,backing,mapping,offset,size;
} file_view;
typedef struct { uint32_t volume,high,low;file_asset *asset; } file_backing;
typedef struct {
    file_asset assets[FILE_ASSETS];file_handle handles[FILE_HANDLES];
    file_view views[FILE_HANDLES];
    file_backing backings[FILE_HANDLES];
    unsigned asset_count,handle_count,view_count,backing_count;
    uint32_t native_unbound_close;
#ifdef _WIN32
    spx_fixture_import_hook imports[7];
#endif
} file_environment;
static void require(int yes,const char *reason) { if(!yes)spx_wine_unavailable(reason); }
static file_environment *files(spx_wine_env *e) {
    if(!e->files) { e->files=calloc(1,sizeof(file_environment));require(e->files!=NULL,"file environment allocation"); }
    return e->files;
}
static char *text_copy(const char *s) {
    require(s!=NULL,"file path input");size_t n=strlen(s);require(n<=65536,"file path extent");
    char *p=malloc(n+1);require(p!=NULL,"file path allocation");memcpy(p,s,n+1);return p;
}
void spx_wine_seed_file(spx_wine_env *e,const char *path,const void *bytes,uint32_t size) {
    require(e->mode==SPX_WINE_CONTROLLED && path && size<=FILE_BYTES && (!size || bytes),"controlled file input");
    file_environment *f=files(e);require(f->asset_count<FILE_ASSETS,"file input capacity");
    for(unsigned i=0;i<f->asset_count;++i)require(strcmp(path,f->assets[i].path)!=0,"duplicate file input path");
    file_asset *a=&f->assets[f->asset_count++];a->path=text_copy(path);a->size=size;
    a->bytes=size ? malloc(size) : NULL;require(!size || a->bytes,"file input allocation");if(size)memcpy(a->bytes,bytes,size);
}
static file_handle *lookup(file_environment *f,uintptr_t value) {
    for(unsigned i=f->handle_count;i;--i)if(f->handles[i-1].value==value)return &f->handles[i-1];
    return NULL;
}
uint32_t spx_wine_file_identity(spx_wine_env *e,uintptr_t value) {
    if(!value)return 0;
    if(value==SPX_WINE_INVALID_HANDLE)return UINT32_MAX;
    file_handle *h=lookup(files(e),value);require(h!=NULL,"unbound file handle; enter through observed CreateFileA");return h->id;
}
static file_handle *opened(file_environment *f,uintptr_t value,file_asset *asset,uint32_t share) {
    require(f->handle_count<FILE_HANDLES,"file handle capacity");
    file_handle *h=&f->handles[f->handle_count++];h->id=f->handle_count;h->live=1;h->position_known=asset!=NULL;h->asset=asset;h->share=share;
    h->value=value ? value : (uintptr_t)h;return h;
}
void spx_wine_bind_handle(spx_wine_env *e,uintptr_t value,uint32_t identity,const char *path,uint64_t position) {
    require(value && value!=SPX_WINE_INVALID_HANDLE && identity,"incoming handle binding");
    file_environment *f=files(e);file_handle *existing=lookup(f,value);
    if(existing) { require(existing->id==identity && existing->live,"conflicting or retired incoming handle binding");return; }
    require(identity==f->handle_count+1,"incoming handle identity order");
    file_asset *a=NULL;
    if(e->mode==SPX_WINE_CONTROLLED && path) {
        for(unsigned i=0;i<f->asset_count;++i)if(!strcmp(path,f->assets[i].path))a=&f->assets[i];
        require(a!=NULL,"incoming file handle needs a seeded path");
    }
    file_handle *h=opened(f,value,a,7);h->position=position;
}
void spx_wine_file_validate_rule(const spx_wine_rule *r) {
    require(!(r->flags&~(SPX_RULE_RETURN|SPX_RULE_WORD|SPX_RULE_NO_WRITE|SPX_RULE_CALLBACK|SPX_RULE_BYTES|SPX_RULE_ERROR|SPX_RULE_LIMIT)),"file scenario flags");
    require(!(r->flags&SPX_RULE_WORD) || r->api==SPX_FILE_SIZE || r->api==SPX_FILE_READ,"file word rule API");
    require(!(r->flags&SPX_RULE_NO_WRITE) || r->api==SPX_FILE_SIZE || r->api==SPX_FILE_READ,"file no-write rule API");
    require(!(r->flags&SPX_RULE_NO_WRITE) || !(r->flags&(SPX_RULE_WORD|SPX_RULE_BYTES|SPX_RULE_LIMIT)),"conflicting file output rules");
    require(!(r->flags&(SPX_RULE_BYTES|SPX_RULE_LIMIT)) || r->api==SPX_FILE_READ,"file byte rule API");
    require(!(r->flags&SPX_RULE_BYTES) || (!(r->flags&SPX_RULE_LIMIT) && r->byte_count<=FILE_BYTES && (!r->byte_count || r->bytes)),"file byte scenario extent");
    require(r->api!=SPX_FILE_OPEN_A || !(r->flags&SPX_RULE_RETURN) || r->result==UINT32_MAX,"CreateFileA return injection accepts INVALID_HANDLE_VALUE");
    require(r->api<SPX_FILE_MAPPING_A || !(r->flags&SPX_RULE_RETURN) || !r->result,"mapping return injection accepts API failure");
}
static uint32_t word_write(void *p,uint32_t value,uint32_t mask) {
    uint32_t old=0;if(!p)return 0;memcpy(&old,p,4);uint32_t result=(old&~mask)|(value&mask);memcpy(p,&result,4);return result;
}
static uint32_t error_before(spx_wine_env *e) {
#ifdef _WIN32
    (void)e;return GetLastError();
#else
    return e->last_error;
#endif
}
void spx_wine_set_last_error(spx_wine_env *e,uint32_t error) {
    e->last_error=error;
#ifdef _WIN32
    SetLastError(error);
#endif
}
uint32_t spx_wine_file_last_error(spx_wine_env *e) { return error_before(e); }
#ifdef _WIN32
static FARPROC procedure(const char *name) {
    FARPROC p=GetProcAddress(GetModuleHandleA("kernel32.dll"),name);require(p!=NULL,"resolve native file API");return p;
}
static void native_position(file_handle *h) {
    if(!h || !h->live || h->mapping)return;
    typedef BOOL (WINAPI *proc)(HANDLE,LARGE_INTEGER,PLARGE_INTEGER,DWORD);
    proc call=(proc)(uintptr_t)procedure("SetFilePointerEx");LARGE_INTEGER zero={0},position={0};
    h->position_known=call((HANDLE)h->value,zero,&position,FILE_CURRENT)!=0;
    if(h->position_known)h->position=(uint64_t)position.QuadPart;
}
static uint32_t native(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v,file_handle **handle,uint32_t incoming_error) {
    file_environment *f=files(e);uint32_t result=0;
    if(c->api==SPX_FILE_OPEN_A) {
        typedef HANDLE (WINAPI *proc)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
        proc call=(proc)(uintptr_t)procedure("CreateFileA");
        const spx_wine_file_security *security=c->input;SECURITY_ATTRIBUTES attributes={0};
        if(security) { attributes.nLength=security->size;attributes.bInheritHandle=(BOOL)security->inherit; }
        SetLastError(incoming_error);
        uintptr_t value=(uintptr_t)call(c->text,c->arguments[0],c->arguments[1],security ? &attributes : NULL,c->arguments[2],c->arguments[3],NULL);
        v->last_error=GetLastError();
        if(value!=SPX_WINE_INVALID_HANDLE) { *handle=opened(f,value,NULL,c->arguments[1]);v->output_object=(*handle)->id; }
        memcpy(c->output,&value,sizeof(value));result=value==SPX_WINE_INVALID_HANDLE ? UINT32_MAX : v->output_object;
    } else if(c->api==SPX_FILE_SIZE) {
        typedef DWORD (WINAPI *proc)(HANDLE,LPDWORD);proc call=(proc)(uintptr_t)procedure("GetFileSize");SetLastError(incoming_error);
        result=call((HANDLE)c->handle,c->output);v->last_error=GetLastError();
        if(c->output && (result!=UINT32_MAX || !v->last_error))v->written_mask=UINT32_MAX;
    } else if(c->api==SPX_FILE_READ) {
        typedef BOOL (WINAPI *proc)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
        proc call=(proc)(uintptr_t)procedure("ReadFile");SetLastError(incoming_error);
        result=(uint32_t)call((HANDLE)c->handle,c->buffer,c->arguments[0],c->output,NULL);v->last_error=GetLastError();
        uint32_t count;memcpy(&count,c->output,4);v->written_mask=UINT32_MAX;
        require(count<=c->arguments[0],"native ReadFile count exceeds admitted output extent");v->transferred=count;
        /* Synchronous successful reads initialize this prefix. For failures,
         * record changed bytes without pretending to know an exact footprint. */
        if(result && count)memset(v->byte_mask,255,count);
        if(*handle && (*handle)->live)(*handle)->position+=count;
    } else {
        typedef BOOL (WINAPI *proc)(HANDLE);proc call=(proc)(uintptr_t)procedure("CloseHandle");SetLastError(incoming_error);
        result=(uint32_t)call((HANDLE)c->handle);v->last_error=GetLastError();if(result && *handle)(*handle)->live=0;
    }
    native_position(*handle);return result;
}
#else
static uint32_t native(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v,file_handle **h,uint32_t error) {
    (void)e;(void)c;(void)v;(void)h;(void)error;spx_wine_unavailable("native files require Wine/Win32");return 0;
}
#endif
static uint32_t controlled(spx_wine_env *e,spx_wine_call *c,spx_wine_event *v,file_handle **handle,const spx_wine_rule *r) {
    file_environment *f=files(e);file_handle *h=*handle;uint32_t result=0,value=0;
    v->footprint_known=1;
    if(c->api==SPX_FILE_OPEN_A) {
        file_asset *a=NULL;for(unsigned i=0;i<f->asset_count;++i)if(!strcmp(c->text,f->assets[i].path))a=&f->assets[i];
        uint32_t error=a ? 0 : 2;
        if(a)for(unsigned i=0;i<f->handle_count;++i)if(f->handles[i].live && !f->handles[i].mapping && f->handles[i].asset==a &&
            (!(f->handles[i].share&1) || !(c->arguments[1]&1)))error=32;
        if(r->flags&SPX_RULE_RETURN)error=error ? error : 5;
        uintptr_t value=SPX_WINE_INVALID_HANDLE;
        if(!error) { h=*handle=opened(f,0,a,c->arguments[1]);value=h->value;v->output_object=h->id; }
        else v->last_error=error;
        memcpy(c->output,&value,sizeof(value));result=error ? UINT32_MAX : h->id;
    } else {
        int valid=h && h->live;
        require(!valid || h->asset || c->api==SPX_HANDLE_CLOSE,"opaque incoming handle supports CloseHandle only");
        if(!valid)v->last_error=6;
        result=c->api==SPX_FILE_SIZE ? (valid ? h->asset->size : UINT32_MAX) : (uint32_t)valid;
        if(r->flags&SPX_RULE_RETURN)result=r->result;
        if(c->api==SPX_FILE_READ) {
            uint32_t n=valid && result ? (uint32_t)(h->position<h->asset->size ? h->asset->size-h->position : 0) : 0;
            if(n>c->arguments[0])n=c->arguments[0];
            if((r->flags&SPX_RULE_LIMIT) && n>r->limit)n=r->limit;
            if(r->flags&SPX_RULE_BYTES)n=r->byte_count;
            if(r->flags&SPX_RULE_NO_WRITE)n=0;
            require(n<=c->arguments[0],"scheduled ReadFile bytes exceed requested extent");
            if(n) { require(valid,"scheduled bytes require a live file");memcpy(c->buffer,r->flags&SPX_RULE_BYTES ? r->bytes : h->asset->bytes+h->position,n);memset(v->byte_mask,255,n);h->position+=n; }
            v->transferred=n;value=result ? n : 0;
            v->written_mask=r->flags&SPX_RULE_NO_WRITE ? 0 : UINT32_MAX;
            if(!result && valid)v->last_error=30;
        } else if(c->api==SPX_FILE_SIZE) {
            v->written_mask=c->output && result!=UINT32_MAX ? UINT32_MAX : 0;value=0;
            if(result==UINT32_MAX && valid)v->last_error=5;
        } else if(result && valid)h->live=0;
        if(r->flags&SPX_RULE_WORD) { value=r->value;v->written_mask=r->mask; }
        if(r->flags&SPX_RULE_NO_WRITE)v->written_mask=0;
        if(c->output)word_write(c->output,value,v->written_mask);
    }
    if(r->flags&SPX_RULE_ERROR)v->last_error=r->last_error;
    return result;
}
static uint32_t mapping_invoke(spx_wine_env *,spx_wine_call);
uint32_t spx_wine_file_invoke(spx_wine_env *e,spx_wine_call c) {
    if(c.api>=SPX_FILE_MAPPING_A)return mapping_invoke(e,c);
    uint32_t incoming_error=error_before(e);file_environment *f=files(e);
    require(e && c.api>=SPX_FILE_OPEN_A && c.api<=SPX_HANDLE_CLOSE && !c.receiver,"file call shape");
    spx_wine_thread_check(e);file_handle *h=NULL;
    if(c.api==SPX_FILE_OPEN_A) {
        require(c.text && c.output && !c.handle,"CreateFileA requires a path, output and null template");
        const spx_wine_file_security *security=c.input;
        require(!security || (security->size==12 && !security->descriptor),"CreateFileA security descriptor requires an admitted representation");
        require(c.arguments[0]==UINT32_C(0x80000000) && !(c.arguments[1]&~7U) && c.arguments[2]==3 &&
            !(c.arguments[3]&~UINT32_C(0x08000080)),"file profile supports synchronous read-only OPEN_EXISTING");
        c.argument_count=4;
        if(security) { c.arguments[4]=1;c.arguments[5]=security->size;c.arguments[6]=security->inherit;c.argument_count=7; }
    } else {
        if(c.handle && c.handle!=SPX_WINE_INVALID_HANDLE) {
            h=lookup(f,c.handle);
            if(!h && !(e->mode==SPX_WINE_NATIVE && c.api==SPX_HANDLE_CLOSE && f->native_unbound_close)) { char detail[192];snprintf(detail,sizeof(detail),"%s: unbound handle 0x%" PRIxPTR "; declare its incoming identity or observe its acquisition",spx_wine_api_name(c.api),c.handle);spx_wine_unavailable(detail); }
        }
        if(c.api==SPX_FILE_READ)require(!c.overlapped && c.output && c.arguments[0]<=FILE_BYTES && (!c.arguments[0] || c.buffer),"ReadFile requires synchronous bounded output and count storage");
        require(!h || !h->mapping || c.api==SPX_HANDLE_CLOSE,"file operations require a file handle");
        c.argument_count=c.api==SPX_FILE_READ ? 1 : 0;
    }
    require(e->event_count<SPX_WINE_EVENTS,"file event capacity");
    spx_wine_event *v=&e->events[e->event_count++];v->sequence=e->event_count;v->api=c.api;v->occurrence=++e->calls[c.api];
    v->controlled=e->mode==SPX_WINE_CONTROLLED;v->handle_known=c.api==SPX_FILE_OPEN_A || h || !c.handle || c.handle==SPX_WINE_INVALID_HANDLE;v->receiver=h ? h->id : c.handle==SPX_WINE_INVALID_HANDLE ? UINT32_MAX : 0;
    v->argument_count=c.argument_count;memcpy(v->arguments,c.arguments,sizeof(v->arguments));
    v->last_error=incoming_error;v->preserved=1;v->output_preserved=1;
    if(c.api==SPX_FILE_OPEN_A)v->text=text_copy(c.text);
    if(h) { v->handle_live_before=h->live;v->file_position_before=h->position; }
    if(c.api==SPX_FILE_SIZE) { v->arguments[0]=c.output!=NULL;v->argument_count=1; }
    if(c.api!=SPX_FILE_OPEN_A && c.output)memcpy(&v->output_before,c.output,4);
    unsigned char *before=NULL;
    if(c.api==SPX_FILE_READ) {
        v->buffer_extent=c.arguments[0];v->data_bytes=c.arguments[0];
        if(v->data_bytes) {
            before=malloc(v->data_bytes);v->data=malloc(v->data_bytes);v->byte_mask=calloc(1,v->data_bytes);
            require(before && v->data && v->byte_mask,"file observation allocation");memcpy(before,c.buffer,v->data_bytes);
        }
    }
#ifdef _WIN32
    if(e->mode==SPX_WINE_NATIVE)native_position(h);
#endif
    if(h) { v->file_position_before=h->position;v->positions_known=h->live && h->position_known ? 1 : 0; }
    if(e->hooks.before)e->hooks.before(e->hooks.context,v);
    spx_wine_rule r=spx_wine_select_rule(e,c.api,v->receiver,v->occurrence);spx_wine_file_validate_rule(&r);
    v->result=e->mode==SPX_WINE_NATIVE ? native(e,&c,v,&h,incoming_error) : controlled(e,&c,v,&h,&r);
    if(c.api!=SPX_FILE_OPEN_A && c.output) {
        uint32_t value;memcpy(&value,c.output,4);
        if(e->mode==SPX_WINE_NATIVE && !v->written_mask)v->written_mask=v->output_before^value;
        v->output_preserved=((v->output_before^value)&~v->written_mask)==0;
        v->output_word=value&v->written_mask;
    }
    if(c.api==SPX_FILE_READ)for(size_t i=0;i<v->data_bytes;++i) {
        unsigned char after=((unsigned char *)c.buffer)[i];
        if(e->mode==SPX_WINE_NATIVE)v->byte_mask[i]|=before[i]^after;
        if((before[i]^after)&~v->byte_mask[i])v->preserved=0;
        v->data[i]=after&v->byte_mask[i];
    }
    free(before);
    if(h) { v->handle_live_after=h->live;v->file_position_after=h->position;if(h->position_known)v->positions_known|=2; }
    /* Scenario outputs and the API error are published before callback reentry. */
    spx_wine_set_last_error(e,v->last_error);
    if(r.flags&SPX_RULE_CALLBACK) { require(e->hooks.callback!=NULL,"file callback is unbound");v->callback=r.callback;e->hooks.callback(e->hooks.context,r.callback); }
    if(e->hooks.after)e->hooks.after(e->hooks.context,v);
    spx_wine_set_last_error(e,v->last_error);return v->result;
}
static file_view *view_at(file_environment *f,const void *p) {
    uintptr_t a=(uintptr_t)p;if(!p)return NULL;
    for(unsigned i=f->view_count;i;--i) {
        file_view *w=&f->views[i-1];uintptr_t base=(uintptr_t)w->address;
        if(a>=base && a-base<w->size)return w;
    }
    return NULL;
}
static void *readonly_view(const void *bytes,size_t size) {
    void *p=NULL;
#ifdef _WIN32
    p=VirtualAlloc(NULL,size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);require(p!=NULL,"controlled mapping pages");
    memcpy(p,bytes,size);DWORD old;require(VirtualProtect(p,size,PAGE_READONLY,&old),"read-only mapping protection");
#elif defined(__unix__)
    p=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);require(p!=MAP_FAILED,"controlled mapping pages");
    memcpy(p,bytes,size);require(!mprotect(p,size,PROT_READ),"read-only mapping protection");
#else
    (void)bytes;(void)size;spx_wine_unavailable("controlled mappings require page protection support");
#endif
    return p;
}
static void retire_view(file_view *w,int dispose) {
#ifdef _WIN32
    if(dispose)require(VirtualFree(w->address,0,MEM_RELEASE),"release controlled mapping pages");
    else { DWORD old;require(VirtualProtect(w->address,w->size,PAGE_NOACCESS,&old),"retire controlled mapping pages"); }
#elif defined(__unix__)
    require(!(dispose ? munmap(w->address,w->size) : mprotect(w->address,w->size,PROT_NONE)),"retire controlled mapping pages");
#else
    (void)w;(void)dispose;
#endif
}
static uint32_t backing_identity(spx_wine_env *e,file_handle *h) {
    if(h->backing)return h->backing;
    file_environment *f=files(e);file_backing key={0};key.asset=h->asset;
#ifdef _WIN32
    if(e->mode==SPX_WINE_NATIVE) {
        typedef BOOL (WINAPI *fn)(HANDLE,LPBY_HANDLE_FILE_INFORMATION);
        fn call=(fn)(uintptr_t)procedure("GetFileInformationByHandle");BY_HANDLE_FILE_INFORMATION info={0};
        require(call((HANDLE)h->value,&info),"mapped file backing identity");
        key.volume=info.dwVolumeSerialNumber;key.high=info.nFileIndexHigh;key.low=info.nFileIndexLow;
    }
#endif
    unsigned i;
    for(i=0;i<f->backing_count;++i) {
        file_backing *k=&f->backings[i];
        if(k->asset==key.asset && k->volume==key.volume && k->high==key.high && k->low==key.low)break;
    }
    if(i==f->backing_count) { require(i<FILE_HANDLES,"mapped backing capacity");f->backings[f->backing_count++]=key; }
    h->backing=i+1;return h->backing;
}
spx_wine_storage spx_wine_mapped_storage(spx_wine_env *e,const void *p) {
    if(!p)return (spx_wine_storage){0};
    file_view *w=view_at(files(e),p);require(w!=NULL,"unbound mapped pointer");
    return (spx_wine_storage){w->backing,w->offset+(uint32_t)((uintptr_t)p-(uintptr_t)w->address),w->size,w->live,0};
}
static uint32_t mapping_invoke(spx_wine_env *e,spx_wine_call c) {
    require(c.api>=SPX_FILE_MAPPING_A && c.api<=SPX_FILE_UNMAP,"mapping API shape");spx_wine_thread_check(e);
    file_environment *f=files(e);uint32_t incoming_error=error_before(e),size=0;
    file_handle *h=NULL;file_view *w=NULL;
    if(c.api==SPX_FILE_UNMAP) {
        w=view_at(f,c.buffer);require(!c.buffer || (w && w->address==c.buffer),"UnmapViewOfFile requires an observed view base");
    } else {
        h=lookup(f,c.handle);require(h!=NULL,"mapping requires an observed file or mapping handle");
        require(c.output!=NULL,"mapping result storage");
        if(c.api==SPX_FILE_MAPPING_A) {
            require(!h->mapping && !c.input && !c.text && c.arguments[0]==2 && !c.arguments[1],"mapping profile requires an unnamed read-only file with default security");
            size=h->asset ? h->asset->size : 0;
#ifdef _WIN32
            if(e->mode==SPX_WINE_NATIVE && h->live) {
                typedef BOOL (WINAPI *fn)(HANDLE,PLARGE_INTEGER);LARGE_INTEGER n={0};
                fn call=(fn)(uintptr_t)procedure("GetFileSizeEx");
                require(call((HANDLE)h->value,&n) && n.QuadPart>=0 && n.QuadPart<=FILE_BYTES,"mapping file extent");size=(uint32_t)n.QuadPart;
            }
#endif
            require(c.arguments[2]<=size,"read-only mapping cannot extend its file");
            if(c.arguments[2])size=c.arguments[2];
        } else {
            require(h->mapping && c.arguments[0]==4 && !c.arguments[1],"mapping profile requires FILE_MAP_READ and a bounded file offset");
            size=c.arguments[3] ? c.arguments[3] : (c.arguments[2]<=h->size ? h->size-c.arguments[2] : 0);
            require(size<=FILE_BYTES,"mapped view extent");
        }
    }
    require(e->event_count<SPX_WINE_EVENTS,"mapping event capacity");
    spx_wine_event *v=&e->events[e->event_count++];v->sequence=e->event_count;v->api=c.api;v->occurrence=++e->calls[c.api];
    v->controlled=e->mode==SPX_WINE_CONTROLLED;v->handle_known=1;v->last_error=incoming_error;
    v->receiver=h ? h->id : w ? w->id : 0;v->handle_live_before=h ? h->live : w ? w->live : 0;
    v->argument_count=c.api==SPX_FILE_MAPPING_A ? 3 : c.api==SPX_FILE_MAP ? 4 : 0;memcpy(v->arguments,c.arguments,sizeof(v->arguments));
    spx_wine_rule r=spx_wine_select_rule(e,c.api,v->receiver,v->occurrence);spx_wine_file_validate_rule(&r);
    if(e->hooks.before)e->hooks.before(e->hooks.context,v);
    uintptr_t result=0;
    if(c.api==SPX_FILE_UNMAP && w && w->live && !(r.flags&SPX_RULE_RETURN))spx_wine_midi_retire_memory(e,w->address,w->size,0);
    if(e->mode==SPX_WINE_NATIVE) {
#ifdef _WIN32
        if(c.api==SPX_FILE_MAPPING_A) {
            typedef HANDLE (WINAPI *fn)(HANDLE,LPSECURITY_ATTRIBUTES,DWORD,DWORD,DWORD,LPCSTR);
            fn call=(fn)(uintptr_t)procedure("CreateFileMappingA");SetLastError(incoming_error);
            result=(uintptr_t)call((HANDLE)c.handle,NULL,2,0,c.arguments[2],NULL);
        } else if(c.api==SPX_FILE_MAP) {
            typedef LPVOID (WINAPI *fn)(HANDLE,DWORD,DWORD,DWORD,SIZE_T);
            fn call=(fn)(uintptr_t)procedure("MapViewOfFile");SetLastError(incoming_error);
            result=(uintptr_t)call((HANDLE)c.handle,4,0,c.arguments[2],c.arguments[3]);
        } else {
            typedef BOOL (WINAPI *fn)(LPCVOID);fn call=(fn)(uintptr_t)procedure("UnmapViewOfFile");SetLastError(incoming_error);
            result=(uint32_t)call(c.buffer);
        }
        v->last_error=GetLastError();
#else
        spx_wine_unavailable("native mapping requires Wine/Win32");
#endif
    } else if(r.flags&SPX_RULE_RETURN)v->last_error=8;
    else if(!v->handle_live_before)v->last_error=c.api==SPX_FILE_UNMAP ? 487 : 6;
    else if(c.api==SPX_FILE_MAP && (c.arguments[2]&65535U))v->last_error=1132;
    else if(c.api!=SPX_FILE_UNMAP && (!size || (c.api==SPX_FILE_MAP &&
        (c.arguments[2]>h->size || size>h->size-c.arguments[2]))))v->last_error=c.api==SPX_FILE_MAPPING_A ? 1006 : 87;
    else { result=1;if(c.api==SPX_FILE_MAPPING_A)v->last_error=0; }
    if(r.flags&SPX_RULE_ERROR)v->last_error=r.last_error;
    if(result && c.api==SPX_FILE_MAPPING_A) {
        file_handle *made=opened(f,e->mode==SPX_WINE_NATIVE ? result : 0,h->asset,0);
        made->mapping=1;made->backing=backing_identity(e,h);made->size=size;made->position_known=0;
        result=made->value;v->output_object=made->id;v->storage=made->backing;v->storage_extent=size;h=made;
    } else if(result && c.api==SPX_FILE_MAP) {
        require(f->view_count<FILE_HANDLES,"mapped view capacity");w=&f->views[f->view_count++];
        w->id=f->view_count;w->live=1;w->mapping=h->id;w->backing=h->backing;w->offset=c.arguments[2];w->size=size;
        if(e->mode==SPX_WINE_CONTROLLED) {
            w->address=readonly_view(h->asset->bytes+w->offset,size);
        } else w->address=(void *)result;
        result=(uintptr_t)w->address;v->output_object=w->id;
        v->data=malloc(size);require(v->data!=NULL,"mapped byte observation");memcpy(v->data,w->address,size);v->data_bytes=size;
    } else if(result && w) { spx_wine_midi_retire_memory(e,w->address,w->size,1);if(e->mode==SPX_WINE_CONTROLLED)retire_view(w,0);w->live=0; }
    if(w) { v->storage=w->backing;v->storage_offset=w->offset;v->storage_extent=w->size;v->handle_live_after=w->live; }
    else if(h)v->handle_live_after=h->live;
    v->result=c.api==SPX_FILE_UNMAP ? (uint32_t)result : v->output_object;
    if(c.output)memcpy(c.output,&result,sizeof(result));
    spx_wine_set_last_error(e,v->last_error);
    if(r.flags&SPX_RULE_CALLBACK) { require(e->hooks.callback!=NULL,"mapping callback is unbound");v->callback=r.callback;e->hooks.callback(e->hooks.context,r.callback); }
    if(e->hooks.after)e->hooks.after(e->hooks.context,v);
    spx_wine_set_last_error(e,v->last_error);return v->result;
}
void spx_wine_files_observe(spx_wine_env *e,spx_observer *out) {
    file_environment *f=e->files;if(!f)return;
    spx_observe_array(out,"file_handles");
    for(unsigned i=0;i<f->handle_count;++i) {
        file_handle *h=&f->handles[i];spx_observe_object(out,NULL);spx_observe_u64(out,"id",h->id);
        spx_observe_u64(out,"live",h->live);spx_observe_u64(out,"position",h->position);spx_observe_u64(out,"position_known",h->position_known);spx_observe_end(out);
    }
    spx_observe_end(out);
    if(f->view_count) {
        spx_observe_array(out,"mapped_views");
        for(unsigned i=0;i<f->view_count;++i) {
            file_view *w=&f->views[i];spx_observe_object(out,NULL);spx_observe_u64(out,"id",w->id);
            spx_observe_u64(out,"live",w->live);spx_observe_u64(out,"backing",w->backing);spx_observe_u64(out,"mapping",w->mapping);
            spx_observe_u64(out,"offset",w->offset);spx_observe_u64(out,"size",w->size);spx_observe_end(out);
        }
        spx_observe_end(out);
    }
}
void spx_wine_files_destroy(spx_wine_env *e) {
    file_environment *f=e->files;if(!f)return;
    for(unsigned i=0;i<f->asset_count;++i) { free(f->assets[i].path);free(f->assets[i].bytes); }
    if(e->mode==SPX_WINE_CONTROLLED)for(unsigned i=0;i<f->view_count;++i)retire_view(&f->views[i],1);
    /* Native handles stay owned by the candidate, including leaked handles. */
    free(f);e->files=NULL;
}
#ifdef _WIN32
static spx_wine_env *installed;
static HANDLE WINAPI file_open(LPCSTR path,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES security,DWORD disposition,DWORD attributes,HANDLE template_handle) {
    require(installed!=NULL,"file factory environment");spx_wine_call c={0};uintptr_t value=SPX_WINE_INVALID_HANDLE;
    c.api=SPX_FILE_OPEN_A;c.text=path;c.arguments[0]=access;c.arguments[1]=share;c.arguments[2]=disposition;c.arguments[3]=attributes;
    spx_wine_file_security view={0};
    if(security) { view.size=security->nLength;view.descriptor=security->lpSecurityDescriptor;view.inherit=(uint32_t)security->bInheritHandle; }
    c.input=security ? &view : NULL;c.handle=(uintptr_t)template_handle;c.output=&value;spx_wine_invoke(installed,c);return (HANDLE)value;
}
static DWORD WINAPI file_size(HANDLE h,LPDWORD high) {
    spx_wine_call c={0};c.api=SPX_FILE_SIZE;c.handle=(uintptr_t)h;c.output=high;return spx_wine_invoke(installed,c);
}
static BOOL WINAPI file_read(HANDLE h,LPVOID buffer,DWORD count,LPDWORD out,LPOVERLAPPED overlapped) {
    spx_wine_call c={0};c.api=SPX_FILE_READ;c.handle=(uintptr_t)h;c.buffer=buffer;c.arguments[0]=count;c.output=out;c.overlapped=overlapped;
    return (BOOL)spx_wine_invoke(installed,c);
}
static BOOL WINAPI file_close(HANDLE h) {
    spx_wine_call c={0};c.api=SPX_HANDLE_CLOSE;c.handle=(uintptr_t)h;return (BOOL)spx_wine_invoke(installed,c);
}
static HANDLE WINAPI file_mapping(HANDLE h,LPSECURITY_ATTRIBUTES security,DWORD protection,DWORD high,DWORD low,LPCSTR name) {
    spx_wine_call c={0};uintptr_t value=0;c.api=SPX_FILE_MAPPING_A;c.handle=(uintptr_t)h;c.input=security;
    c.arguments[0]=protection;c.arguments[1]=high;c.arguments[2]=low;c.text=name;c.output=&value;
    spx_wine_invoke(installed,c);return (HANDLE)value;
}
static LPVOID WINAPI file_map(HANDLE h,DWORD access,DWORD high,DWORD low,SIZE_T size) {
    require(size<=FILE_BYTES,"mapping size exceeds profile");spx_wine_call c={0};uintptr_t value=0;
    c.api=SPX_FILE_MAP;c.handle=(uintptr_t)h;c.arguments[0]=access;c.arguments[1]=high;c.arguments[2]=low;c.arguments[3]=(uint32_t)size;c.output=&value;
    spx_wine_invoke(installed,c);return (void *)value;
}
static BOOL WINAPI file_unmap(LPCVOID p) {
    spx_wine_call c={0};c.api=SPX_FILE_UNMAP;c.buffer=(void *)p;return (BOOL)spx_wine_invoke(installed,c);
}
int spx_wine_install_mappings(spx_wine_env *e,const char *module,unsigned operations) {
    if((installed && installed!=e) || !operations || (operations&~7U))return 0;
    file_environment *f=files(e);
    for(unsigned i=4;i<7;++i)if(f->imports[i].slot)return 0;
    void (*functions[])(void)={(void (*)(void))file_mapping,(void (*)(void))file_map,(void (*)(void))file_unmap};
    for(unsigned i=0;i<3;++i)if(operations&(1U<<i)) {
        if(!spx_fixture_redirect_import(&f->imports[i+4],module,"kernel32.dll",spx_wine_api_name(SPX_FILE_MAPPING_A+i),functions[i])) {
            for(unsigned j=0;j<i;++j)if(f->imports[j+4].slot)require(spx_fixture_restore_import(&f->imports[j+4]),"rollback mapping imports");
            return 0;
        }
    }
    installed=e;return 1;
}
int spx_wine_install_files(spx_wine_env *e,const char *module,unsigned operations) {
    if(installed || !(operations&15U) || (operations&~31U) || ((operations&SPX_WINE_FILES_NATIVE_UNBOUND_CLOSE) && e->mode!=SPX_WINE_NATIVE))return 0;
    const char *names[]={"CreateFileA","GetFileSize","ReadFile","CloseHandle"};
    void (*functions[])(void)={(void (*)(void))file_open,(void (*)(void))file_size,(void (*)(void))file_read,(void (*)(void))file_close};
    file_environment *f=files(e);
    for(unsigned i=0;i<4;++i)if(operations&(1U<<i)) {
        if(!spx_fixture_redirect_import(&f->imports[i],module,"kernel32.dll",names[i],functions[i])) {
            for(unsigned j=0;j<i;++j)if(f->imports[j].slot)require(spx_fixture_restore_import(&f->imports[j]),"rollback file import interception");
            return 0;
        }
    }
    f->native_unbound_close=(operations&SPX_WINE_FILES_NATIVE_UNBOUND_CLOSE)!=0;installed=e;return 1;
}
int spx_wine_uninstall_files(spx_wine_env *e) {
    file_environment *f=e->files;if(!f || installed!=e)return 1;
    for(unsigned i=0;i<7;++i)if(f->imports[i].slot && !spx_fixture_restore_import(&f->imports[i]))return 0;
    installed=NULL;return 1;
}
uint32_t spx_wine_file_candidate_call(spx_wine_env *e,spx_wine_call c) {
    require(installed==e,"candidate file bindings require installed environment");
    switch(c.api) {
    case SPX_FILE_OPEN_A: {
        const spx_wine_file_security *security=c.input;SECURITY_ATTRIBUTES attributes={0};
        if(security) { attributes.nLength=security->size;attributes.lpSecurityDescriptor=(void *)security->descriptor;attributes.bInheritHandle=(BOOL)security->inherit; }
        uintptr_t value=(uintptr_t)file_open(c.text,c.arguments[0],c.arguments[1],security ? &attributes : NULL,c.arguments[2],c.arguments[3],(HANDLE)c.handle);
        uint32_t error=GetLastError();memcpy(c.output,&value,sizeof(value));uint32_t id=spx_wine_file_identity(e,value);SetLastError(error);return id;
    }
    case SPX_FILE_SIZE:return file_size((HANDLE)c.handle,c.output);
    case SPX_FILE_READ:return (uint32_t)file_read((HANDLE)c.handle,c.buffer,c.arguments[0],c.output,c.overlapped);
    case SPX_HANDLE_CLOSE:return (uint32_t)file_close((HANDLE)c.handle);
    case SPX_FILE_MAPPING_A: {
        uintptr_t value=(uintptr_t)file_mapping((HANDLE)c.handle,(LPSECURITY_ATTRIBUTES)c.input,c.arguments[0],c.arguments[1],c.arguments[2],c.text);
        memcpy(c.output,&value,sizeof(value));return value!=0;
    }
    case SPX_FILE_MAP: {
        void *value=file_map((HANDLE)c.handle,c.arguments[0],c.arguments[1],c.arguments[2],c.arguments[3]);memcpy(c.output,&value,sizeof(value));return value!=NULL;
    }
    case SPX_FILE_UNMAP:return (uint32_t)file_unmap(c.buffer);
    default:spx_wine_unavailable("candidate file binding");return 0;
    }
}
#else
int spx_wine_install_files(spx_wine_env *e,const char *module,unsigned operations) { (void)e;(void)module;(void)operations;return 0; }
int spx_wine_install_mappings(spx_wine_env *e,const char *module,unsigned operations) { (void)e;(void)module;(void)operations;return 0; }
int spx_wine_uninstall_files(spx_wine_env *e) { (void)e;return 1; }
uint32_t spx_wine_file_candidate_call(spx_wine_env *e,spx_wine_call c) { return spx_wine_invoke(e,c); }
#endif
uintptr_t spx_wine_file_open(spx_wine_env *e,const char *path,uint32_t access,uint32_t share,const void *security,uint32_t disposition,uint32_t attributes,uintptr_t template_handle) {
    spx_wine_call c={0};uintptr_t value=SPX_WINE_INVALID_HANDLE;c.api=SPX_FILE_OPEN_A;c.text=path;
    c.arguments[0]=access;c.arguments[1]=share;c.arguments[2]=disposition;c.arguments[3]=attributes;c.input=security;c.handle=template_handle;c.output=&value;
    spx_wine_candidate_call(e,c);return value;
}
uint32_t spx_wine_file_size(spx_wine_env *e,uintptr_t handle,void *high) {
    spx_wine_call c={0};c.api=SPX_FILE_SIZE;c.handle=handle;c.output=high;return spx_wine_candidate_call(e,c);
}
uint32_t spx_wine_file_read(spx_wine_env *e,uintptr_t handle,void *buffer,uint32_t size,void *count,void *overlapped) {
    spx_wine_call c={0};c.api=SPX_FILE_READ;c.handle=handle;c.buffer=buffer;c.arguments[0]=size;c.output=count;c.overlapped=overlapped;
    return spx_wine_candidate_call(e,c);
}
uint32_t spx_wine_file_close(spx_wine_env *e,uintptr_t handle) {
    spx_wine_call c={0};c.api=SPX_HANDLE_CLOSE;c.handle=handle;return spx_wine_candidate_call(e,c);
}
uintptr_t spx_wine_file_mapping(spx_wine_env *e,uintptr_t h,const void *security,uint32_t protection,uint32_t high,uint32_t low,const char *name) {
    spx_wine_call c={0};uintptr_t value=0;c.api=SPX_FILE_MAPPING_A;c.handle=h;c.input=security;c.text=name;c.output=&value;
    c.arguments[0]=protection;c.arguments[1]=high;c.arguments[2]=low;spx_wine_candidate_call(e,c);return value;
}
void *spx_wine_file_map(spx_wine_env *e,uintptr_t h,uint32_t access,uint32_t high,uint32_t low,size_t size) {
    require(size<=FILE_BYTES,"mapping size exceeds profile");spx_wine_call c={0};void *value=NULL;
    c.api=SPX_FILE_MAP;c.handle=h;c.arguments[0]=access;c.arguments[1]=high;c.arguments[2]=low;c.arguments[3]=(uint32_t)size;c.output=&value;
    spx_wine_candidate_call(e,c);return value;
}
uint32_t spx_wine_file_unmap(spx_wine_env *e,const void *p) {
    spx_wine_call c={0};c.api=SPX_FILE_UNMAP;c.buffer=(void *)p;return spx_wine_candidate_call(e,c);
}
