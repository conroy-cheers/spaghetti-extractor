#include "portable-component-implementation.h"
#include "cli-input.h"
#include "observations.h"
int main(int argc, char **argv) {
    static unsigned slot;
    portable_component_entry("cli", &slot);
    spx_cli_context_v5 context = {0};
    struct spx_opaque_arguments_v5 input = {argc, argv};
    lifted_cli_run(&context, &input);
    return 125; /* The declared process entry must terminate through its runtime. */
}
