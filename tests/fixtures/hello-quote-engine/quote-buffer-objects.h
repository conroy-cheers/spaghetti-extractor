#ifndef HELLO_QUOTE_BUFFER_OBJECTS_H
#define HELLO_QUOTE_BUFFER_OBJECTS_H
#include <stdint.h>
#include "quote-objects.h"
/* Call-scoped borrowed spans. The adapter preserves live aliases; it does not
 * snapshot bytes or retain these wrapper objects across calls. */
struct spx_opaque_quote_bytes_v5 { unsigned char *data; };
/* This is the conversion-service representation, not the host mbstate_t ABI.
 * The PE32 adapter relates state to the original four-byte conversion object. */
struct spx_opaque_quote_conversion_v5 { uint32_t state, character; };
#endif
