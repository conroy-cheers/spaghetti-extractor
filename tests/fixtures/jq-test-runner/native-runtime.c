#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "test-input.h"
#include "windows-files.h"
#include "portable-component-implementation.h"
#include "pe32-import-hook.h"
#include "native-entry.h"

static spx_fixture_import_hook exit_hook, process_exit_hook, create_hook, join_hook;
static FILE *report;
static int source_side;
static unsigned source_calls, created, joined;

static void write_report(int status) {
    if (!report) return;
    if (source_side && (source_calls != 1 || !install_tests_intact())) ExitProcess(125);
    fprintf(report, "{\"side\":\"%s\",\"exit_code\":%d,"
        "\"observations\":{\"threads_created\":%u,\"threads_joined\":%u},"
        "\"diagnostics\":{\"source_calls\":%u,\"old_body_removed\":%s}}\n",
        source_side ? "source" : "original", status, created, joined,
        source_calls, source_side ? "true" : "false");
    if (ferror(report) || fclose(report)) ExitProcess(125);
    report = NULL;
}
static _Noreturn void WINAPI observe_process_exit(UINT status) {
    write_report((int)status);
    ((void (WINAPI *)(UINT))(uintptr_t)process_exit_hook.original)(status);
    ExitProcess(125);
}
static _Noreturn void observe_exit(int status) {
    write_report(status);
    ((void (*)(int))(uintptr_t)exit_hook.original)(status);
    ExitProcess(125);
}
_Noreturn void spx_test_exit(int status) { observe_exit(status); }

/* Native services share the same CRT FILE objects and input mode as jq. */
spx_input *spx_runtime_stdin(void) { return (spx_input *)stdin; }
spx_input *spx_input_open(const char *path, int text) {
    return (spx_input *)fopen(path, text ? "r" : "rb");
}
char *spx_input_gets(char *buffer, int capacity, spx_input *input) {
    return fgets(buffer, capacity, (FILE *)input);
}
int spx_test_thread_create(pthread_t *id, const pthread_attr_t *attributes,
        void *(*entry)(void *), void *data) {
    int status = ((int (*)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *))
        (uintptr_t)create_hook.original)(id, attributes, entry, data);
    if (!status) ++created;
    return status;
}
int spx_test_thread_join(pthread_t id, void **result) {
    int status = ((int (*)(pthread_t, void **))(uintptr_t)join_hook.original)(id, result);
    if (!status) ++joined;
    return status;
}
static __attribute__((no_caller_saved_registers, target("general-regs-only")))
int replacement_tests(jv libraries, int verbose, int argc, char **argv) {
    ++source_calls;
    spx_test_runner_context_v5 context = {0};
    struct spx_opaque_test_input_v5 input = {libraries, verbose, argc, argv};
    (void)&jv_is_valid;
    return lifted_test_runner_run(&context, &input);
}
__declspec(dllexport) void spx_jq_tests_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *reserved) {
    (void)module; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    char side[16], path[4096];
    DWORD length = GetEnvironmentVariableA("SPX_COMPARISON_SIDE", side, sizeof(side));
    if (!length || length >= sizeof(side) || (strcmp(side,"original") && strcmp(side,"source"))) return FALSE;
    source_side = !strcmp(side, "source");
    length = GetEnvironmentVariableA("SPX_COMPARISON_REPORT", path, sizeof(path));
    if (!length || length >= sizeof(path) || !(report = fopen(path, "wb"))) return FALSE;
    if (!spx_fixture_redirect_import(&exit_hook, NULL, "msvcrt.dll", "exit", (void (*)(void))observe_exit)) return FALSE;
    if (!spx_fixture_redirect_import(&process_exit_hook, "msvcrt.dll", "kernel32.dll", "ExitProcess",
        (void (*)(void))observe_process_exit)) return FALSE;
    if (!spx_fixture_redirect_import(&create_hook, "libjq-1.dll", "libwinpthread-1.dll", "pthread_create",
        (void (*)(void))spx_test_thread_create)) return FALSE;
    if (!spx_fixture_redirect_import(&join_hook, "libjq-1.dll", "libwinpthread-1.dll", "pthread_join",
        (void (*)(void))spx_test_thread_join)) return FALSE;
    if (source_side && !install_tests((void (*)(void))replacement_tests)) return FALSE;
    return TRUE;
}
