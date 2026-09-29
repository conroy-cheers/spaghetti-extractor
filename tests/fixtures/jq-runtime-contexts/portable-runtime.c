#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "context-services.h"

void *spx_context_malloc(size_t size) { return malloc(size); }
int spx_context_atexit(void (*cleanup)(void)) { return atexit(cleanup); }
int spx_seed_open(const char *path, int flags) { return open(path,flags); }
int spx_seed_read(int descriptor, void *bytes, unsigned length) {
    return (int)read(descriptor,bytes,length);
}
int spx_seed_close(int descriptor) { return close(descriptor); }
uint32_t spx_seed_process_id(void) { return (uint32_t)getpid(); }
uint32_t spx_seed_time32(void) {
    time_t value=time(NULL);
    if (value<0 || (uint64_t)value>INT32_MAX) {
        errno=EOVERFLOW;
        return UINT32_MAX;
    }
    return (uint32_t)value;
}
