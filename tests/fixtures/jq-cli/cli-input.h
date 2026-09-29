#ifndef SPX_JQ_CLI_INPUT_H
#define SPX_JQ_CLI_INPUT_H
struct spx_opaque_arguments_v5 { int argc; char **argv; };
_Noreturn void portable_cli_main(int, char **);
#endif
