#ifndef SPX_JQ_HASH_NATIVE_H
#define SPX_JQ_HASH_NATIVE_H
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
#include "hash-view.h"

/* The existing jq string layout: refcount, hash, length/flag, capacity, bytes.
 * This borrows the real mutable cache, with no private-struct type punning. */
_Static_assert(CHAR_BIT == 8 && sizeof(int) == 4 && sizeof(jv) == 16, "jq string layout");
static inline void hash_view(jv value, struct spx_opaque_hash_view_v5 *view) {
    if (jv_get_kind(value) != JV_KIND_STRING) abort();
    view->cache = (unsigned char *)value.u.ptr + 4;
    view->data = (const unsigned char *)value.u.ptr + 16;
    memcpy(&view->length_hashed, view->cache + 4, sizeof(view->length_hashed));
    view->hash = 0;
    if (view->length_hashed & 1U)
        memcpy(&view->hash, view->cache, sizeof(view->hash));
}
uint32_t spx_string_hash_seed(void);
uint32_t fixture_string_hash(jv);
#endif
