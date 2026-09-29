#include "portable-component-implementation.h"
#include "test-input.h"
#include "observations.h"
int jq_testsuite(jv libraries, int verbose, int argc, char **argv) {
    static unsigned slot; portable_component_entry("test-runner", &slot);
    spx_test_runner_context_v5 context = {0};
    struct spx_opaque_test_input_v5 input = {libraries, verbose, argc, argv};
    (void)&jv_is_valid;
    return lifted_test_runner_run(&context, &input);
}
