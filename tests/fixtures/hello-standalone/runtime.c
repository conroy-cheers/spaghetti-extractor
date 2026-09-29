#include "services.h"
#include "windows-1252.h"
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

HelloRuntime hello_runtime;

static void report(void) {
    const char *path=getenv("SPX_PORTABLE_REPORT");
    if (!path) return;
    FILE *file=fopen(path,"wb");
    if (!file) _Exit(125);
    fprintf(file,"{\"allocated_bytes\":%u,\"allocations\":%u,\"releases\":%u,"
        "\"resets\":%u,\"decodes\":%u,\"conversions\":%u,\"converted\":%u,"
        "\"cursor_null\":%u,\"word_hash\":%u,\"target_errno\":%u,\"exit_code\":%d,"
        "\"fatal_entries\":%u,\"fatal_errno\":%u,"
        "\"conversion_state\":[%u,%u,%u,%u],\"first_words\":[",
        hello_runtime.allocated_bytes, hello_runtime.allocations, hello_runtime.releases,
        hello_runtime.resets, hello_runtime.decodes, hello_runtime.conversions, hello_runtime.converted,
        hello_runtime.cursor_null, hello_runtime.word_hash, hello_runtime.target_errno, hello_runtime.exit_code,
        hello_runtime.fatal_entries,hello_runtime.fatal_errno,
        hello_runtime.conversion_state[0],hello_runtime.conversion_state[1],
        hello_runtime.conversion_state[2],hello_runtime.conversion_state[3]);
    for (unsigned i=0;i<hello_runtime.word_count;++i) fprintf(file,"%s%u",i ? "," : "",hello_runtime.first_words[i]);
    fprintf(file,"],\"argv_hex\":[");
    for (int i=0;i<hello_runtime.argument_count;++i) {
        fprintf(file,"%s\"",i ? "," : "");
        for (const unsigned char *p=(const unsigned char *)hello_runtime.arguments[i];*p;++p) fprintf(file,"%02x",*p);
        fputc('"',file);
    }
    fprintf(file,"]}\n");
    free(hello_runtime.arguments);hello_runtime.arguments=NULL;
    int failed=ferror(file);
    if (fclose(file)) failed=1;
    if (failed) _Exit(125);
}

static void close_output(void) {
    int failed=spx_target_close(stdout);
    if (failed) {
        int error=errno;
        spx_target_fprintf(stderr,"%s: write error%s%s\n",spx_target_basename(hello_runtime.program_name),
            error ? ": " : "",error ? strerror(error) : "");
    }
    if (spx_target_close(stderr)) failed=1;
    if (failed) hello_runtime.exit_code=1;
    report();
    if (failed) _Exit(1);
}

void hello_start(int argc, char **argv) {
    hello_runtime.program_name=argv[0];
    if (getenv("SPX_PORTABLE_REPORT")) {
        hello_runtime.arguments=malloc((size_t)argc*sizeof(char *));
        if (!hello_runtime.arguments) _Exit(125);
        memcpy(hello_runtime.arguments,argv,(size_t)argc*sizeof(char *));
        hello_runtime.argument_count=argc;
    }
    setlocale(LC_ALL, "");
    spx_target_console_init();
    if (atexit(close_output)) _Exit(125);
}

_Noreturn void hello_allocation_failed(void) {
    ++hello_runtime.fatal_entries; hello_runtime.fatal_errno=(uint32_t)errno;
    spx_target_fprintf(stderr,"%s: memory exhausted\n",spx_target_basename(hello_runtime.program_name));
    hello_runtime.exit_code=1; exit(1);
}
_Noreturn void hello_invalid_state(void) { abort(); }
