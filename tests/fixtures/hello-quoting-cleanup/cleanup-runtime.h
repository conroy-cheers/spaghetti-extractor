#ifndef HELLO_CLEANUP_RUNTIME_H
#define HELLO_CLEANUP_RUNTIME_H
#include "quote-objects.h"
#define HELLO_CLEANUP_MAX_SLOTS 64U
struct cleanup_adapter {
    void *context;
    void (*release_buffer)(void *, struct spx_opaque_quote_bytes_v5 *);
    void (*release_table)(void *, struct spx_opaque_quote_table_v5 *);
};
uint32_t fixture_quote_cleanup(struct spx_opaque_quote_state_v5 *, const struct cleanup_adapter *);
#endif
