#ifndef HELLO_STRING_OBJECTS_H
#define HELLO_STRING_OBJECTS_H
#include "multibyte-objects.h"
/* A live caller-owned cursor, valid for the complete call. Its pointed-to bytes
 * and the reusable conversion objects obey the workspace's boundary contract. */
struct spx_opaque_mb_cursor_v5 { const unsigned char **value; };
#endif
