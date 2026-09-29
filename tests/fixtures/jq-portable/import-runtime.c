/* Observed pinned CLI import identity and redirected --binary CRT assertion.
 * This preserves the original defect instead of silently correcting it when
 * a static source link unifies the DLL and executable function addresses. */
#include <stdio.h>
#include <stdlib.h>
#include "import-runtime.h"
#include "observations.h"
#include "windows-output.h"
jv spx_imported_input_callback(jq_state *jq, void *data) {
    return jq_util_input_next_input_cb(jq,data);
}
_Noreturn void spx_input_callback_assertion(void) {
    const char *message=
        "Assertion failed: cb == jq_util_input_next_input_cb, file src/util.c, line 351\n\n";
    spx_output_wide_stderr_ascii(message);
    fflush(NULL);
    portable_component_report();
    _Exit(3);
}
