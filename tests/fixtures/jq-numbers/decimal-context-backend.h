#ifndef SPX_JQ_DECIMAL_CONTEXT_BACKEND_H
#define SPX_JQ_DECIMAL_CONTEXT_BACKEND_H
/* Included after the existing backend's private TLS declarations. */
decContext *spx_decimal_context(void) { return DEC_CONTEXT(); }
#endif
