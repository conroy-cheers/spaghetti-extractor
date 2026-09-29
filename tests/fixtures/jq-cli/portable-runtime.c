#include <locale.h>
#include <stdlib.h>
#include <unistd.h>
#include "cli-runtime.h"
#include "windows-output.h"
#include "original-configuration.h"
int onig_set_parse_depth_limit(unsigned int);
void spx_stdin_set_binary(int);
jv spx_imported_input_callback(jq_state *, void *);

void spx_cli_initialize(void) {
    (void)&jv_is_valid;
    (void)setlocale(LC_ALL, "");
    onig_set_parse_depth_limit(1024);
    if (spx_output_initialize()) exit(2);
}
void spx_cli_binary(void) { spx_stdin_set_binary(1); spx_output_binary(); }
int spx_cli_isatty(int descriptor) { return isatty(descriptor); }
int spx_cli_terminal_flags(void) {
    return isatty(STDOUT_FILENO) ? JV_PRINT_ISATTY | JV_PRINT_COLOR : 0;
}
void spx_cli_write(const char *bytes, size_t length, FILE *output, int tty) {
    (void)tty;
    fwrite(bytes, 1, length, output);
}
jq_input_cb spx_cli_input_callback(void) { return spx_imported_input_callback; }
const char *spx_cli_configuration(void) { return SPX_ORIGINAL_CONFIGURATION; }
_Noreturn void spx_cli_exit(int status) { exit(status); }
