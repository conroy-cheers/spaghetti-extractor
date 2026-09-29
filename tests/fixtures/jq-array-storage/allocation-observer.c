/* Observe the pinned DLL's real CRT allocations. Metadata belongs to the host
 * fixture and uses its own imports; target memory is never cloned or emulated. */
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "allocation-observer.h"
#ifdef SPX_PORTABLE_ALLOCATION_OBSERVER
/* Static source backend: GNU link wrappers observe the same CRT boundary.
 * Metadata must use the real allocator to avoid observing itself recursively. */
extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t,size_t);
extern void *__real_realloc(void *,size_t);
extern void __real_free(void *);
extern char *__real_strdup(const char *);
#define metadata_malloc __real_malloc
#define metadata_free __real_free
#define original_malloc __real_malloc
#define original_calloc __real_calloc
#define original_realloc __real_realloc
#define original_free __real_free
#define original_strdup __real_strdup
#define observed_malloc __wrap_malloc
#define observed_calloc __wrap_calloc
#define observed_realloc __wrap_realloc
#define observed_free __wrap_free
#define observed_strdup __wrap_strdup
#define OBSERVER_LINKAGE
static int observer_active;
#else
#include "pe32-import-hook.h"
static spx_fixture_import_hook hooks[5];
#define metadata_malloc malloc
#define metadata_free free
#define original_malloc ((void *(*)(size_t))(uintptr_t)hooks[0].original)
#define original_calloc ((void *(*)(size_t,size_t))(uintptr_t)hooks[1].original)
#define original_realloc ((void *(*)(void *,size_t))(uintptr_t)hooks[2].original)
#define original_free ((void (*)(void *))(uintptr_t)hooks[3].original)
#define original_strdup ((char *(*)(const char *))(uintptr_t)hooks[4].original)
#define OBSERVER_LINKAGE static
#endif

typedef struct allocation_record {
    uintptr_t address;
    uint64_t generation;
    size_t size;
    int live, observed;
    struct allocation_record *next;
} allocation_record;
static allocation_record *records;
static uint64_t generation;
static int paused;
static uint64_t allocations, releases, invalid_releases, unknown_releases;
static int fail_next_malloc;
static uint64_t injected_failures;
static size_t failed_size;

static void fail(const char *reason) {
    fprintf(stderr,"allocation observer: %s\n",reason);
#ifdef SPX_PORTABLE_ALLOCATION_OBSERVER
    _Exit(83);
#else
    ExitProcess(83);
#endif
}
static allocation_record *find(uintptr_t address) {
    for (allocation_record *row=records;row;row=row->next)
        if (row->address==address) return row;
    return NULL;
}
static void acquired(void *address,size_t size) {
#ifdef SPX_PORTABLE_ALLOCATION_OBSERVER
    if (!observer_active) return;
#endif
    if (!address) return;
    allocation_record *row=find((uintptr_t)address);
    if (row && row->live) fail("allocator returned an already-live address");
    if (!row) {
        row=metadata_malloc(sizeof(*row)); if(!row) fail("fixture metadata allocation failed");
        row->address=(uintptr_t)address;row->next=records;records=row;
    }
    if (generation==UINT64_MAX) fail("allocation generation exhausted");
    row->generation=++generation;
    row->size=size;row->live=1;row->observed=!paused;
    if (row->observed) ++allocations;
}
static void released(uintptr_t address) {
#ifdef SPX_PORTABLE_ALLOCATION_OBSERVER
    if (!observer_active) return;
#endif
    if (!address) return;
    allocation_record *row=find(address);
    if (!row) { if(!paused) ++unknown_releases; return; }
    if (!row->live) { ++invalid_releases; fail("repeated release of recorded allocation"); }
    row->live=0;
    if(row->observed) ++releases;
}
OBSERVER_LINKAGE void *observed_malloc(size_t size) {
    if (fail_next_malloc && !paused) {
        fail_next_malloc=0;++injected_failures;failed_size=size;return NULL;
    }
    void *p=original_malloc(size);
    acquired(p,size);return p;
}
OBSERVER_LINKAGE void *observed_calloc(size_t count,size_t size) {
    void *p=original_calloc(count,size);
    if (p && count && size>SIZE_MAX/count) fail("successful overflowing calloc");
    acquired(p,count*size);return p;
}
OBSERVER_LINKAGE void *observed_realloc(void *old,size_t size) {
    uintptr_t previous=(uintptr_t)old;
    void *p=original_realloc(old,size);
    if (p || !size) released(previous);
    if (p) acquired(p,size);
    return p;
}
OBSERVER_LINKAGE void observed_free(void *p) {
    released((uintptr_t)p);
    original_free(p);
}
OBSERVER_LINKAGE char *observed_strdup(const char *text) {
    char *p=original_strdup(text);
    if(p) acquired(p,strlen(p)+1);
    return p;
}
void allocation_observer_begin(void) {
#ifdef SPX_PORTABLE_ALLOCATION_OBSERVER
    if (observer_active || records) fail("observer already started");
    observer_active=1;
#else
    const char *names[5]={"malloc","calloc","realloc","free","_strdup"};
    void (*functions[5])(void)={(void(*)(void))observed_malloc,(void(*)(void))observed_calloc,
        (void(*)(void))observed_realloc,(void(*)(void))observed_free,(void(*)(void))observed_strdup};
    for (unsigned i=0;i<5;++i)
        if (!spx_fixture_redirect_import(&hooks[i],"libjq-1.dll","msvcrt.dll",names[i],functions[i]))
            fail(names[i]);
#endif
}
void allocation_observer_pause(int value) { paused=value!=0; }
void allocation_observer_fail_next_malloc(void) {
    if (paused || fail_next_malloc) fail("invalid malloc failure injection scope");
    fail_next_malloc=1;
}
uint64_t allocation_observer_failures(void) { return injected_failures; }
size_t allocation_observer_failed_size(void) { return failed_size; }
uint64_t allocation_observer_generation(const void *address) {
    allocation_record *row=find((uintptr_t)address);
    return row && row->observed && row->live ? row->generation : 0;
}
int allocation_observer_live_allocation(const void *address,uint64_t captured,size_t *size) {
    allocation_record *row=find((uintptr_t)address);
    if (!captured || !row || !row->observed || !row->live || row->generation!=captured) return 0;
    *size=row->size;
    return 1;
}
void allocation_observer_live_sizes(FILE *output) {
    unsigned count=0;fputc('[',output);
    for (allocation_record *row=records;row;row=row->next)
        if (row->observed && row->live) fprintf(output,"%s%zu",count++?",":"",row->size);
    fputc(']',output);
}
allocation_observer_summary allocation_observer_snapshot(void) {
    allocation_observer_summary result={0,0,invalid_releases};
    for(allocation_record *row=records;row;row=row->next)
        if(row->observed && row->live) { ++result.live_blocks;result.live_bytes+=row->size; }
    return result;
}
static int compare_size(const void *left,const void *right) {
    size_t a=*(const size_t *)left,b=*(const size_t *)right;
    return (a>b)-(a<b);
}
void allocation_observer_remaining_sizes(FILE *output,const void *address,uint64_t captured) {
    allocation_record *excluded=NULL;
    if (address || captured) {
        size_t size;
        if (!allocation_observer_live_allocation(address,captured,&size))
            fail("represented object is not the captured live allocation");
        excluded=find((uintptr_t)address);
    }
    size_t count=0;
    for(allocation_record *row=records;row;row=row->next)
        if(row->observed && row->live && row!=excluded) ++count;
    if (count>SIZE_MAX/sizeof(size_t)) fail("allocation size inventory overflow");
    size_t *sizes=count?metadata_malloc(count*sizeof(*sizes)):NULL;
    if (count && !sizes) fail("fixture size inventory allocation failed");
    size_t index=0;
    for(allocation_record *row=records;row;row=row->next)
        if(row->observed && row->live && row!=excluded) sizes[index++]=row->size;
    if(count) qsort(sizes,count,sizeof(*sizes),compare_size);
    fputc('[',output);
    for(index=0;index<count;++index) fprintf(output,"%s%zu",index?",":"",sizes[index]);
    fputc(']',output);metadata_free(sizes);
}
void allocation_observer_end(void) {
    if (fail_next_malloc) fail("requested malloc failure was not exercised");
#ifdef SPX_PORTABLE_ALLOCATION_OBSERVER
    observer_active=0;
#else
    for(unsigned i=0;i<5;++i) if(!spx_fixture_restore_import(&hooks[i])) fail("restore import");
#endif
    fprintf(stderr,"allocation-activity allocations=%" PRIu64 " releases=%" PRIu64
        " unregistered_releases=%" PRIu64 "\n",allocations,releases,unknown_releases);
    while(records) { allocation_record *row=records;records=row->next;metadata_free(row); }
}
void allocation_observer_finish(FILE *output) {
    allocation_observer_summary result=allocation_observer_snapshot();
    allocation_observer_end();
    /* Allocation strategies may differ. Compare residual lifetime effects;
     * retain total activity as diagnostic data rather than equality policy. */
    fprintf(output,"{\"live_blocks\":%" PRIu64 ",\"live_bytes\":%" PRIu64
        ",\"invalid_releases\":%" PRIu64 "}",result.live_blocks,result.live_bytes,result.invalid_releases);
}
