#ifndef SPX_JQ_IMPORT_RUNTIME_H
#define SPX_JQ_IMPORT_RUNTIME_H
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "jq.h"
#pragma GCC diagnostic pop
/* The pinned PE32 CLI passes its import thunk, not the DLL function address. */
jv spx_imported_input_callback(jq_state *, void *);
_Noreturn void spx_input_callback_assertion(void);
#endif
