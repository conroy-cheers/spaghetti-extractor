#ifndef SPX_JQ_CONTEXT_INPUTS_H
#define SPX_JQ_CONTEXT_INPUTS_H
#include <stdint.h>
#include "jv_dtoa.h"
#define DECNUMDIGITS 1
#include "decNumber.h"
struct spx_opaque_context_result_v5 {
    decContext *decimal;
    struct dtoa_context *dtoa;
    uint32_t seed;
};
void portable_decimal_initialize(void);
void portable_decimal_finalize(void);
decContext *portable_decimal_context(void);
void portable_dtoa_initialize(void);
void portable_dtoa_finalize(void);
struct dtoa_context *portable_dtoa_context(void);
uint32_t portable_hash_seed(void);
#endif
