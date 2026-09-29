#ifndef SPX_JQ_STRING_NATIVE_H
#define SPX_JQ_STRING_NATIVE_H
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jv.h"
#pragma GCC diagnostic pop
#include "string-view.h"
void string_contents(jv, struct spx_opaque_string_bytes_v5 *);
jv string_create(jv, uint32_t, uint32_t);
jv string_empty(void);
jv string_invalid(void);
jv fixture_string_slice(jv, int32_t, int32_t);
void string_slice_install(void);
void string_slice_report(void);
extern unsigned string_slice_calls;
#endif
