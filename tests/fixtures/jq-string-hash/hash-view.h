#ifndef SPX_JQ_HASH_VIEW_H
#define SPX_JQ_HASH_VIEW_H
#include <stdint.h>

/* A live borrowed allocation; cache points to the hash and length/flag words.
 * The owner keeps both ranges alive until the consuming entry releases it. */
struct spx_opaque_hash_view_v5 {
    const unsigned char *data;
    unsigned char *cache;
    uint32_t length_hashed, hash;
};
#endif
