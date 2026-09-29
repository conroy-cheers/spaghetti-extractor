#ifndef SPX_JQ_HASH_SEED_BACKEND_H
#define SPX_JQ_HASH_SEED_BACKEND_H
/* Included after the private seed definitions in the reviewed jq backend TU.
 * Reuse the same once-initialization and state as unlifted hash consumers. */
uint32_t spx_string_hash_seed(void) { return jvp_hash_seed(); }
#endif
