#ifndef HELLO_MULTIBYTE_OBJECTS_H
#define HELLO_MULTIBYTE_OBJECTS_H
#include <stdint.h>
/* Call-scoped live proxies; no input/state/output snapshot. The state bytes are
 * the reviewed conversion representation, not a claim about host mbstate_t. */
struct spx_opaque_mb_bytes_v5 { const unsigned char *data; };
struct spx_opaque_mb_state_v5 { unsigned char *data; };
struct spx_opaque_mb_word16_v5 { uint16_t *value; };
struct spx_opaque_mb_word32_v5 { uint32_t *value; };
#endif
