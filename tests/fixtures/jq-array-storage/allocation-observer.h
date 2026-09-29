#ifndef SPX_JQ_ALLOCATION_OBSERVER_H
#define SPX_JQ_ALLOCATION_OBSERVER_H
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
/* Install before observed operations. Diagnostic serialization can be excluded
 * from counts without losing allocation generations or subsequent releases.
 * PE32 uses the pinned DLL's CRT imports. Static portable source uses
 * SPX_PORTABLE_ALLOCATION_OBSERVER and --wrap=malloc,calloc,realloc,free,strdup;
 * the actual target allocator still owns callback/failure delivery. */
void allocation_observer_begin(void);
void allocation_observer_pause(int paused);
void allocation_observer_finish(FILE *output);
/* Fail exactly the next observed malloc. The guarded native allocator still
 * decides how to deliver that failure; this does not invent a null-return API. */
void allocation_observer_fail_next_malloc(void);
uint64_t allocation_observer_failures(void);
size_t allocation_observer_failed_size(void);
/* Capture a particular observed allocation, then inspect that same lifetime.
 * Zero is not a recorded live allocation. Reuse of its address gets a new token.
 * These queries do not allocate, initialize target state or choose equality. */
uint64_t allocation_observer_generation(const void *address);
int allocation_observer_live_allocation(const void *address,uint64_t generation,size_t *size);
typedef struct {
    uint64_t live_blocks,live_bytes,invalid_releases;
} allocation_observer_summary;
allocation_observer_summary allocation_observer_snapshot(void);
/* Sorted sizes for the remaining observed heap after describing one particular
 * live object separately. NULL/zero describes the entire observed heap. */
void allocation_observer_remaining_sizes(FILE *output,const void *address,uint64_t generation);
/* End observation and retain activity diagnostics without choosing a JSON view.
 * finish() remains the convenience operation for exact physical totals. */
void allocation_observer_end(void);
/* Diagnostic physical allocation sizes, without addresses or equality policy. */
void allocation_observer_live_sizes(FILE *output);
#endif
