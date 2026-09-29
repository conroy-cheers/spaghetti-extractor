#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <io.h>
#include <windows.h>
#include "cli-runtime.h"
#include "cli-input.h"
#include "portable-component-implementation.h"
#include "windows-output.h"
#include "original-configuration.h"
#include "pe32-import-hook.h"
#include "native-entry.h"

static spx_fixture_import_hook exit_hook;
static spx_fixture_import_hook process_exit_hook;
static FILE *report;
static int source_side;
static unsigned source_calls;

static void write_report(int status) {
    if (!report) return;
    if (source_side && (source_calls != 1 || !install_cli_intact())) ExitProcess(125);
    fprintf(report, "{\"side\":\"%s\",\"exit_code\":%d,\"observations\":{},"
        "\"diagnostics\":{\"source_calls\":%u,\"old_cli_removed\":%s}}\n",
        source_side ? "source" : "original", status, source_calls, source_side ? "true" : "false");
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
_Noreturn void spx_cli_exit(int status) { observe_exit(status); }

void spx_cli_initialize(void) {
    (void)&jv_is_valid;
    setlocale(LC_ALL, "");
    HMODULE onig = GetModuleHandleA("libonig-5.dll");
    int (*limit)(unsigned int) = (void *)GetProcAddress(onig, "onig_set_parse_depth_limit");
    if (!limit) ExitProcess(125);
    limit(1024);
    /* Shared original dtoa initialization, called by the original CLI too. */
    void (*init)(void) = (void *)((unsigned char *)GetModuleHandleA(NULL) + 0x4a08);
    init();
    if (spx_output_initialize()) ExitProcess(125);
}
void spx_cli_binary(void) { spx_output_binary(); }
int spx_cli_isatty(int descriptor) { return _isatty(descriptor); }
int spx_cli_terminal_flags(void) {
    DWORD mode;
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!_isatty(1) || !GetConsoleMode(console, &mode)) return 0;
    return JV_PRINT_ISATTY | ((getenv("ANSICON") || SetConsoleMode(console, mode | 4)) ? JV_PRINT_COLOR : 0);
}
void spx_cli_write(const char *bytes, size_t length, FILE *output, int tty) {
    if (tty) WriteFile((HANDLE)_get_osfhandle(_fileno(output)), bytes, length, NULL, NULL);
    else fwrite(bytes, 1, length, output);
}
jq_input_cb spx_cli_input_callback(void) {
    return (jq_input_cb)((unsigned char *)GetModuleHandleA(NULL) + 0x4ac8);
}
const char *spx_cli_configuration(void) { return SPX_ORIGINAL_CONFIGURATION; }

static int replacement_main(int argc, char **argv) {
    ++source_calls;
    spx_cli_context_v5 context = {0};
    struct spx_opaque_arguments_v5 input = {argc, argv};
    lifted_cli_run(&context, &input);
    ExitProcess(125);
}
__declspec(dllexport) void spx_jq_cli_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *reserved) {
    (void)module; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    char side[16], path[4096];
    DWORD length = GetEnvironmentVariableA("SPX_COMPARISON_SIDE", side, sizeof(side));
    if (!length || length >= sizeof(side) || (strcmp(side, "original") && strcmp(side, "source"))) return FALSE;
    source_side = !strcmp(side, "source");
    length = GetEnvironmentVariableA("SPX_COMPARISON_REPORT", path, sizeof(path));
    if (!length || length >= sizeof(path) || !(report = fopen(path, "wb"))) return FALSE;
    if (!spx_fixture_redirect_import(&exit_hook, NULL, "msvcrt.dll", "exit", (void (*)(void))observe_exit)) return FALSE;
    /* The existing input-callback assertion reaches CRT _exit through abort.
     * Observe actual termination status instead of synthesizing that outcome. */
    if (!spx_fixture_redirect_import(&process_exit_hook, "msvcrt.dll", "kernel32.dll", "ExitProcess",
            (void (*)(void))observe_process_exit)) return FALSE;
    if (source_side && !install_cli((void (*)(void))replacement_main)) return FALSE;
    return TRUE;
}
