#ifndef SPX_JQ_STRING_STORAGE_H
#define SPX_JQ_STRING_STORAGE_H
#include <limits.h>
#include <string.h>
#include "string-native.h"

/* Shared executable projection of the pinned jq string allocation. Four
 * 32-bit words precede the bytes: references, cached hash, length/hash flag,
 * capacity. The native DLL and the reviewed source backend use this layout.
 * A live, well-formed string owns this complete allocation; no heap is copied.
 * Read object bytes with memcpy, without aliasing a private jq struct type. */
_Static_assert(CHAR_BIT == 8 && sizeof(int) == 4, "jq string header requires 32-bit int");
static inline void spx_jq_string_contents(jv value, struct spx_opaque_string_bytes_v5 *bytes) {
    const unsigned char *storage=(const unsigned char *)value.u.ptr;
    uint32_t length_hashed;
    memcpy(&length_hashed,storage+8,sizeof(length_hashed));
    bytes->data=storage+16;
    bytes->length=length_hashed>>1;
}
#endif
