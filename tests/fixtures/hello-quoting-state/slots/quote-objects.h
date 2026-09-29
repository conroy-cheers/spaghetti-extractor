#ifndef HELLO_QUOTE_OBJECTS_H
#define HELLO_QUOTE_OBJECTS_H
#include <stdint.h>

/* These are the proposed logical objects, not claims about decoded ownership.
 * Buffer contents stay behind the actual quoting/allocation service boundary. */
struct spx_opaque_quote_bytes_v5;
struct spx_opaque_quote_word_v5 { uint32_t value; };
struct spx_opaque_quote_mask_v5 { uint32_t words[8]; };
struct spx_opaque_quote_options_v5 {
    uint32_t style, flags;
    struct spx_opaque_quote_mask_v5 mask;
    struct spx_opaque_quote_bytes_v5 *left_quote, *right_quote;
};
struct spx_opaque_quote_table_v5 {
    uint32_t size;
    struct spx_opaque_quote_bytes_v5 *buffer;
};
struct spx_opaque_quote_state_v5 {
    struct spx_opaque_quote_table_v5 *table;
    uint32_t count;
    struct spx_opaque_quote_table_v5 *initial_table;
    struct spx_opaque_quote_bytes_v5 *initial_buffer;
};
#endif
