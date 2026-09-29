#include "services.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef SPX_UTF8_ARGUMENTS
#include "windows-argv.h"
static spx_windows_argv arguments;
static void release_arguments(void) { spx_windows1252_argv_dispose(&arguments); }
#endif

int main(int argc, char **argv) {
#ifdef SPX_UTF8_ARGUMENTS
    int result=spx_windows1252_argv_init(&arguments,argc,argv);
    if (result!=SPX_ARGV_OK) {
        fputs(result==SPX_ARGV_INVALID_UTF8 ? "hello: invalid UTF-8 argument\n" : "hello: memory exhausted\n",stderr);
        return 1;
    }
    /* Application atexit handlers run first, while their argv references live. */
    if (atexit(release_arguments)) { release_arguments(); return 125; }
    argv=arguments.values;
#endif
    return hello_application(argc,argv);
}
