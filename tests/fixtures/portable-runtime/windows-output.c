#define _GNU_SOURCE
#include "windows-output.h"
#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <wchar.h>

int spx_output_initialize(void) {
    fflush(stdout);
    fflush(stderr);
    /* Preserve the original jq CRT mode request, including its result policy. */
    _setmode(_fileno(stdout), _O_TEXT | _O_U8TEXT);
    _setmode(_fileno(stderr), _O_TEXT | _O_U8TEXT);
    return 0;
}
void spx_output_binary(void) {
    fflush(stdout);
    fflush(stderr);
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    _setmode(_fileno(stderr), _O_BINARY);
}
void spx_output_wide_stderr_ascii(const char *text) {
    for (; *text; ++text) fputwc((unsigned char)*text, stderr);
}
#else
#include <string.h>
#include <sys/types.h>

/* This backend uses the libc cookie-stream facility. The translation itself
 * depends only on ordinary byte I/O. Keep FILE transport in one provider so
 * serializers and diagnostics share the same policy without private wrappers. */
struct output_stream { FILE *underlying; };
static struct output_stream outputs[2];
/* Previous CLI backends use the explicit binary comparison profile. The
 * process entry changes to the Windows default text policy on initialization. */
static int binary_mode = 1;

static ssize_t output_write(void *opaque, const char *bytes, size_t length) {
    struct output_stream *stream = opaque;
    size_t consumed = 0;
    while (consumed < length) {
        const char *newline = binary_mode ? NULL : memchr(bytes + consumed, '\n', length - consumed);
        size_t count = newline ? (size_t)(newline - bytes) - consumed : length - consumed;
        if (count && fwrite(bytes + consumed, 1, count, stream->underlying) != count) return -1;
        consumed += count;
        if (newline) {
            if (fwrite("\r\n", 1, 2, stream->underlying) != 2) return -1;
            ++consumed;
        }
    }
    if (fflush(stream->underlying)) return -1;
    return (ssize_t)length;
}
static int output_close(void *opaque) {
    struct output_stream *stream = opaque;
    return fclose(stream->underlying);
}

int spx_output_initialize(void) {
    binary_mode = 0;
    cookie_io_functions_t methods = { .write = output_write, .close = output_close };
    outputs[0].underlying = stdout;
    outputs[1].underlying = stderr;
    FILE *out = fopencookie(&outputs[0], "w", methods);
    if (!out) return -1;
    FILE *err = fopencookie(&outputs[1], "w", methods);
    if (!err) {
        /* Initialization failure is fatal to this process-owned runtime. */
        fclose(out);
        return -1;
    }
    setvbuf(err, NULL, _IONBF, 0);
    stdout = out;
    stderr = err;
    return 0;
}
void spx_output_binary(void) {
    fflush(stdout);
    fflush(stderr);
    binary_mode = 1;
}
void spx_output_wide_stderr_ascii(const char *text) {
    if (!binary_mode) fputs(text, stderr);
    else for (; *text; ++text) { fputc((unsigned char)*text, stderr); fputc(0, stderr); }
}
#endif
