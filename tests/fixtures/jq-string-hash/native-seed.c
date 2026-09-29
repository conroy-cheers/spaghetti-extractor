#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Reviewed seed service in the pinned PE; no hash implementation is retained
 * behind this call. pthread_once and process entropy remain backend services. */
uint32_t spx_string_hash_seed(void) {
    unsigned char *base = (unsigned char *)GetModuleHandleA("libjq-1.dll");
    if (!base) abort();
    return ((uint32_t (*)(void))(base + 0x2627b))();
}
void fixture_hash_seed(uint32_t seed) {
    (void)spx_string_hash_seed(); /* Complete native once-initialization before controlling it. */
    unsigned char *base = (unsigned char *)GetModuleHandleA("libjq-1.dll");
    memcpy(base + 0x75014, &seed, sizeof(seed));
}
