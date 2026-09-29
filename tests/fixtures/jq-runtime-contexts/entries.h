#ifndef SPX_JQ_CONTEXT_ENTRIES_H
#define SPX_JQ_CONTEXT_ENTRIES_H
#include "context-inputs.h"
void spx_entry_jv_tsd_dec_ctx_init(void);
void jv_tsd_dec_ctx_init(void);
void spx_entry_jv_tsd_dec_ctx_fini(void);
void jv_tsd_dec_ctx_fini(void);
__attribute__((regparm(1))) decContext * spx_entry_tsd_dec_ctx_get(void *key);
decContext * spx_native_decimal_context(void);
void spx_entry_jv_tsd_dtoa_ctx_init(void);
void jv_tsd_dtoa_ctx_init(void);
void spx_entry_jv_tsd_dtoa_ctx_fini(void);
void jv_tsd_dtoa_ctx_fini(void);
struct dtoa_context * spx_entry_tsd_dtoa_context_get(void);
struct dtoa_context * tsd_dtoa_context_get(void);
uint32_t spx_entry_jvp_hash_seed(void);
uint32_t jvp_hash_seed(void);
#endif
