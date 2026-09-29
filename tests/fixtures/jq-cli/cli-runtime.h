#ifndef SPX_JQ_CLI_RUNTIME_H
#define SPX_JQ_CLI_RUNTIME_H
#include <stddef.h>
#include <stdio.h>
#include "jq.h"
void spx_cli_initialize(void);
void spx_cli_binary(void);
int spx_cli_isatty(int);
int spx_cli_terminal_flags(void);
void spx_cli_write(const char *, size_t, FILE *, int);
jq_input_cb spx_cli_input_callback(void);
const char *spx_cli_configuration(void);
_Noreturn void spx_cli_exit(int);
_Noreturn void portable_cli_main(int, char **);
#endif
