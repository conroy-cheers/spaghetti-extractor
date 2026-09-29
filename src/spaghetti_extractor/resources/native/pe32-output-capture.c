/* Keep Win32 standard handles separate from Wine's Unix diagnostic descriptors.
 * The existing process observer owns pipes, deadlines and descendant cleanup.
 * Run only inside the caller's managed headless Wayland/Wine session. */
#define SPX_PROCESS_OUTPUT_CAPACITY (8U * 1024U * 1024U)
#ifndef SPX_CAPTURE_TRACE_CAPACITY
#define SPX_CAPTURE_TRACE_CAPACITY (64U * 1024U * 1024U)
#endif
#define SPX_PROCESS_CONSUME_OUTPUT spx_capture_output
#include "pe32-process-observer.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

static spx_fixture_process_result observation;
static FILE *trace;
static DWORD trace_size, trace_status;
static unsigned char pending[32];
static unsigned pending_size, stderr_mode; /* prefix, application line, trace line */

static int append_output(int stream, const unsigned char *bytes, DWORD size,
    spx_fixture_process_result *result) {
    unsigned char *destination = stream ? result->err : result->out;
    DWORD *used = stream ? &result->err_size : &result->out_size;
    if (size > SPX_PROCESS_OUTPUT_CAPACITY - *used) { result->status = SPX_PROCESS_OVERFLOW; return 0; }
    memcpy(destination + *used, bytes, size); *used += size; return 1;
}

static int append_trace(const unsigned char *bytes, DWORD size, spx_fixture_process_result *result) {
    /* Matches the existing service/resource readers' bounded trace budget. */
    if (size > SPX_CAPTURE_TRACE_CAPACITY - trace_size) {
        result->status = SPX_PROCESS_OVERFLOW; trace_status = SPX_PROCESS_OVERFLOW; return 0;
    }
    size_t written = fwrite(bytes, 1, size, trace); trace_size += (DWORD)written;
    if (written != size) { result->status = SPX_PROCESS_IO; trace_status = SPX_PROCESS_IO; return 0; }
    return 1;
}

static int spx_capture_output(int stream, const unsigned char *bytes, DWORD size,
    spx_fixture_process_result *result) {
    static const char *const prefixes[] = {"SPX_SERVICE ", "SPX_SERVICE_SCOPE ",
        "SPX_SERVICE_HANDLER ", "SPX_RESOURCE "};
    if (!stream) return append_output(0, bytes, size, result);
    while (size) {
        if (stderr_mode) {
            const unsigned char *newline = memchr(bytes, '\n', size);
            DWORD count = newline ? (DWORD)(newline - bytes) + 1 : size;
            int ok = stderr_mode == 2 ? append_trace(bytes, count, result) : append_output(1, bytes, count, result);
            if (!ok) return 0;
            bytes += count; size -= count;
            if (newline) stderr_mode = 0;
        } else {
            pending[pending_size++] = *bytes++; --size;
            int possible = 0, matched = 0;
            for (unsigned i = 0; i < sizeof(prefixes)/sizeof(*prefixes); ++i) {
                size_t length = strlen(prefixes[i]);
                if (pending_size <= length && !memcmp(pending, prefixes[i], pending_size)) {
                    possible = 1; matched |= pending_size == length;
                }
            }
            if (matched) {
                if (!append_trace(pending, pending_size, result)) return 0;
                pending_size = 0; stderr_mode = 2;
            } else if (!possible) {
                if (!append_output(1, pending, pending_size, result)) return 0;
                stderr_mode = pending[pending_size-1] == '\n' ? 0 : 1; pending_size = 0;
            }
        }
    }
    return 1;
}

static int save(const char *name, const void *data, size_t size) {
    FILE *file = fopen(name, "wb");
    if (!file) return 0;
    int ok = fwrite(data, 1, size, file) == size;
    return fclose(file) == 0 && ok;
}

int wmain(int argc, wchar_t **argv) {
    const char *deadline = getenv("SPX_CAPTURE_TIMEOUT_MS");
    if (argc < 2 || !deadline) return 125;
    char *end;
    unsigned long milliseconds = strtoul(deadline, &end, 10);
    if (!milliseconds || *end || milliseconds == INFINITE) return 125;
    /* Wine has already quoted the argument vector. Remove only this launcher's
     * argv[0], retaining the target's command line, including empty arguments. */
    wchar_t *command = GetCommandLineW();
    if (*command == L'"') {
        command = wcschr(command + 1, L'"');
        if (!command) return 125;
        ++command;
    } else {
        while (*command && *command != L' ' && *command != L'\t') ++command;
    }
    while (*command == L' ' || *command == L'\t') ++command;
    trace = fopen("tmp/spaghetti-capture/trace", "wb");
    if (!trace) return 125;
    spx_fixture_observe_process(argv[1], command, milliseconds, &observation);
    /* An incomplete prefix is ordinary application data, including at EOF. */
    if (pending_size) (void)append_output(1, pending, pending_size, &observation);
    if (fclose(trace)) { trace_status = SPX_PROCESS_IO; observation.status = SPX_PROCESS_IO; }
    if (!save("tmp/spaghetti-capture/stdout", observation.out, observation.out_size) ||
        !save("tmp/spaghetti-capture/stderr", observation.err, observation.err_size)) return 125;
    char report[256];
    int length = snprintf(report, sizeof(report),
        "{\"status\":%u,\"error\":%lu,\"exit_code\":%lu,\"trace_status\":%lu,\"trace_bytes\":%lu}\n",
        (unsigned)observation.status, observation.error, observation.exit_code, trace_status, trace_size);
    if (length < 0 || (size_t)length >= sizeof(report) ||
        !save("tmp/spaghetti-capture/result.json", report, (size_t)length)) return 125;
    ExitProcess(observation.status == SPX_PROCESS_OK ? observation.exit_code : 125);
}
