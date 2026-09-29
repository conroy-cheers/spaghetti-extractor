#include "portable-component-implementation.h"
#include "test-input.h"
int32_t lifted_test_runner_run(spx_test_runner_context_v5 *context, struct spx_opaque_test_input_v5 *input) {
    (void)context; (void)&jv_is_valid;
    return portable_jq_testsuite(input->libraries, input->verbose, input->argc, input->argv);
}
