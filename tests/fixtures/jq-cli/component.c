#include "portable-component-implementation.h"
#include "cli-input.h"
void lifted_cli_run(spx_cli_context_v5 *context, struct spx_opaque_arguments_v5 *input) {
    (void)context;
    portable_cli_main(input->argc, input->argv);
}
