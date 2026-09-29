#ifndef SPX_JQ_CONTEXT_SERVICES_H
#define SPX_JQ_CONTEXT_SERVICES_H
#include <stddef.h>
#include <stdint.h>
/* Allocation belongs to the same heap as jv_mem_free. These calls may return
 * NULL, unlike guarded jv_mem_alloc. Entropy transfers bytes, not a host word. */
void *spx_context_malloc(size_t size);
/* Register in the selected runtime's callback registry, shared with neighbors. */
int spx_context_atexit(void (*cleanup)(void));
int spx_seed_open(const char *path, int flags);
int spx_seed_read(int descriptor, void *bytes, unsigned length);
int spx_seed_close(int descriptor);
uint32_t spx_seed_process_id(void);
uint32_t spx_seed_time32(void);
#endif
