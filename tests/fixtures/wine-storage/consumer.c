/* Independent mapped-input and movable-storage consumer. No target layouts. */
#include "spx-wine-test.h"
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"storage consumer line %d\n",__LINE__);return 42; } } while(0)
static spx_wine_env *env;
#if defined(_WIN32) && !defined(USE_BINDING)
#define OPEN(p) ((uintptr_t)CreateFileA(p,GENERIC_READ,1,NULL,3,0x80,NULL))
#define CLOSE(h) CloseHandle((HANDLE)(h))
#define MAPPING(h) ((uintptr_t)CreateFileMappingA((HANDLE)(h),NULL,PAGE_READONLY,0,0,NULL))
#define MAP(h,n) MapViewOfFile((HANDLE)(h),FILE_MAP_READ,0,0,n)
#define UNMAP(p) UnmapViewOfFile(p)
#define LALLOC(f,n) ((uintptr_t)LocalAlloc(f,n))
#define LFREE(h) ((uintptr_t)LocalFree((HLOCAL)(h)))
#define ALLOC(f,n) ((uintptr_t)GlobalAlloc(f,n))
#define LOCK(h) GlobalLock((HGLOBAL)(h))
#define UNLOCK(h) GlobalUnlock((HGLOBAL)(h))
#define FREE(h) ((uintptr_t)GlobalFree((HGLOBAL)(h)))
#define HANDLE(p) ((uintptr_t)GlobalHandle(p))
#else
#define OPEN(p) spx_wine_file_open(env,p,0x80000000,1,NULL,3,0x80,0)
#define CLOSE(h) spx_wine_file_close(env,h)
#define MAPPING(h) spx_wine_file_mapping(env,h,NULL,2,0,0,NULL)
#define MAP(h,n) spx_wine_file_map(env,h,4,0,0,n)
#define UNMAP(p) spx_wine_file_unmap(env,p)
#define LALLOC(f,n) spx_wine_local_alloc(env,f,n)
#define LFREE(h) spx_wine_local_free(env,h)
#define ALLOC(f,n) spx_wine_global_alloc(env,f,n)
#define LOCK(h) spx_wine_global_lock(env,h)
#define UNLOCK(h) spx_wine_global_unlock(env,h)
#define FREE(h) spx_wine_global_free(env,h)
#define HANDLE(p) spx_wine_global_handle(env,p)
#endif
int main(int argc,char **argv) {
    const char *mode=argc>1 ? argv[1] : "controlled";
    int native=!strcmp(mode,"native"),fail=!strcmp(mode,"failures");
    env=spx_wine_create(native ? SPX_WINE_NATIVE : SPX_WINE_CONTROLLED);
    const unsigned char content[]={3,1,4,1,5,9,2,6,5,3,5,8};
    if(!native) { spx_wine_seed_file(env,"file.bin",content,sizeof(content));spx_wine_allocation_history(env,0xa5); }
    if(fail) {
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_FILE_MAP,.occurrence=1,.flags=SPX_RULE_RETURN|SPX_RULE_ERROR,.last_error=8});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_GLOBAL_ALLOC,.occurrence=1,.flags=SPX_RULE_RETURN});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_GLOBAL_LOCK,.occurrence=1,.flags=SPX_RULE_RETURN});
        spx_wine_add_rule(env,(spx_wine_rule){.api=SPX_GLOBAL_FREE,.occurrence=1,.flags=SPX_RULE_RETURN,.result=1});
    }
#ifdef _WIN32
    /* Retain SDK imports even in the portable-binding candidate. */
    if(argc==99) {
        HANDLE f=CreateFileA("",GENERIC_READ,1,NULL,3,0x80,NULL),m=CreateFileMappingA(f,NULL,2,0,0,NULL);
        void *p=MapViewOfFile(m,4,0,0,0);UnmapViewOfFile(p);CloseHandle(m);CloseHandle(f);
        HLOCAL l=LocalAlloc(0x40,8);LocalFree(l);HGLOBAL h=GlobalAlloc(2,16);
        p=GlobalLock(h);GlobalHandle(p);GlobalUnlock(h);GlobalFree(h);
    }
    CHECK(spx_wine_install_files(env,NULL,SPX_WINE_FILES_OPEN|SPX_WINE_FILES_CLOSE));
    CHECK(spx_wine_install_mappings(env,NULL,SPX_WINE_MAPPINGS_ALL));
    CHECK(spx_wine_install_memory(env,NULL,SPX_WINE_MEMORY_ALL));SetLastError(0);
#endif
    uintptr_t f=OPEN("file.bin");CHECK(f!=SPX_WINE_INVALID_HANDLE);
    uintptr_t m=MAPPING(f);CHECK(m);
    if(fail)CHECK(!MAP(m,0) && spx_wine_file_last_error(env)==8);
    unsigned char *a=MAP(m,0),*b=MAP(m,8);CHECK(a && b && a!=b);
    CHECK(!memcmp(a,content,12) && !memcmp(b,content,8));
    spx_wine_storage av=spx_wine_mapped_storage(env,a+2),bv=spx_wine_mapped_storage(env,b+2);
    CHECK(av.identity==bv.identity && av.offset==bv.offset && av.live && bv.live);
    uintptr_t f2=OPEN("file.bin"),m2=MAPPING(f2);CHECK(m2);
    unsigned char *c=MAP(m2,8);CHECK(c && spx_wine_mapped_storage(env,c+2).identity==av.identity);
    CHECK(CLOSE(f2) && CLOSE(m2) && UNMAP(c));
    CHECK(CLOSE(f) && CLOSE(m));CHECK(!memcmp(a,content,12));
    CHECK(UNMAP(a));CHECK(!spx_wine_mapped_storage(env,a).live && b[7]==6);
    if(strcmp(mode,"leak"))CHECK(UNMAP(b));
    uintptr_t l=LALLOC(0x40,8);CHECK(l);unsigned char *lp=(void *)l;
    for(unsigned i=0;i<8;++i)CHECK(!lp[i]);
    lp[2]=77;CHECK(!LFREE(l));CHECK(!spx_wine_memory_storage(env,lp).live);
    if(fail)CHECK(!ALLOC(0x2042,16));
    uintptr_t h=ALLOC(0x2042,16);CHECK(h);
    if(fail)CHECK(!LOCK(h));
    unsigned char *p=LOCK(h);CHECK(p && h!=(uintptr_t)p && HANDLE(p)==h);
    for(unsigned i=0;i<16;++i)CHECK(!p[i]);
    memcpy(p,content,12);CHECK(LOCK(h)==p && spx_wine_memory_storage(env,p).locks==2);
    CHECK(UNLOCK(h));CHECK(!UNLOCK(h) && !spx_wine_file_last_error(env));
    CHECK(!UNLOCK(h) && spx_wine_file_last_error(env)==158);
    CHECK(LOCK(h)==p && !memcmp(p,content,12));
    if(fail) { CHECK(FREE(h)==h);CHECK(spx_wine_memory_storage(env,p).live); }
    /* Win32 permits freeing locked global memory. Do not impose Rust ownership. */
    CHECK(!FREE(h));CHECK(!spx_wine_memory_storage(env,p).live);
    if(!native) {
        h=ALLOC(0,4);CHECK(h);p=LOCK(h);CHECK(p==(void *)h && p[0]==0xa5);
        CHECK(UNLOCK(h));CHECK(!FREE(h));
    }
    spx_observer out=spx_observe_begin(stdout);spx_wine_observe(env,&out,"platform");CHECK(spx_observe_finish(&out));puts("");
    spx_wine_destroy(env);return 0;
}
