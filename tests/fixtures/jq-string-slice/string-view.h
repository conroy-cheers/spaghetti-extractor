#ifndef SPX_JQ_STRING_VIEW_H
#define SPX_JQ_STRING_VIEW_H
#include <stdint.h>
/* Borrowed contents of an existing live string. No copy or pointer reconstruction.
 * The owner must remain live through every read and construction from this view.
 * Embedded NUL and malformed UTF-8 are contents, not terminators or invalid pointers. */
struct spx_opaque_string_bytes_v5 {
    const unsigned char *data;
    uint32_t length;
};
#endif
