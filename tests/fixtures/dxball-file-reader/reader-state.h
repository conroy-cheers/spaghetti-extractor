#ifndef DXBALL_READER_STATE_H
#define DXBALL_READER_STATE_H
#include <stdint.h>
typedef struct spx_opaque_reader_name_v5 { const char *text; } reader_name;
typedef struct spx_opaque_reader_bytes_v5 { unsigned char *bytes; } reader_bytes;
typedef struct spx_opaque_reader_handle_v5 { uintptr_t value; } reader_handle;
#endif
