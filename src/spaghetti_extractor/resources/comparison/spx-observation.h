#ifndef SPX_OBSERVATION_H
#define SPX_OBSERVATION_H
/* Portable output support for comparison adapters, not application C.
 * Choose observations explicitly; this never follows pointers or infers object
 * identity, lifetime, valid memory, service effects or coverage. Byte spans must
 * be readable for their stated length. Capture state before emitting it when
 * stream operations could change that state (for example errno).
 *
 * begin() opens the root object. Object members require a name; array elements
 * use NULL. end() closes a nested array/object. finish() closes the root and
 * flushes the stream, returning 0 on malformed nesting or output failure.
 * Check that result. Duplicate object names remain errors in the JSON reader.
 * Bytes are lowercase hex, preserving NULs and non-text data without encoding
 * assumptions. Floating values and pointer relationships need explicit views.
 */
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum { SPX_OBSERVATION_DEPTH = 32 };
typedef struct {
    FILE *stream;
    unsigned depth;
    int failed;
    struct { unsigned char object, nonempty; } frames[SPX_OBSERVATION_DEPTH];
} spx_observer;

static inline spx_observer spx_observe_begin(FILE *stream) {
    spx_observer out = {0};
    out.stream = stream; out.depth = 1; out.frames[0].object = 1;
    if (!stream) out.failed = 1;
    else fputc('{', stream);
    return out;
}

static inline void spx_observe_key_(FILE *stream, const char *name) {
    fputc('"', stream);
    for (const unsigned char *p = (const unsigned char *)name; *p; ++p) {
        if (*p == '"' || *p == '\\') { fputc('\\', stream); fputc(*p, stream); }
        else if (*p < 0x20) fprintf(stream, "\\u%04x", (unsigned)*p);
        else fputc(*p, stream);
    }
    fputs("\":", stream);
}

static inline int spx_observe_item_(spx_observer *out, const char *name) {
    if (out->failed) return 0;
    if (!out->depth || (out->frames[out->depth-1].object != (name != NULL))) {
        out->failed = 1; return 0;
    }
    if (out->frames[out->depth-1].nonempty) fputc(',', out->stream);
    out->frames[out->depth-1].nonempty = 1;
    if (name) spx_observe_key_(out->stream, name);
    return 1;
}

static inline void spx_observe_container_(spx_observer *out, const char *name, unsigned char object) {
    if (out->depth >= SPX_OBSERVATION_DEPTH) { out->failed = 1; return; }
    if (!spx_observe_item_(out, name)) return;
    fputc(object ? '{' : '[', out->stream);
    out->frames[out->depth].object = object;
    out->frames[out->depth++].nonempty = 0;
}

static inline void spx_observe_array(spx_observer *out, const char *name) {
    spx_observe_container_(out, name, 0);
}
static inline void spx_observe_object(spx_observer *out, const char *name) {
    spx_observe_container_(out, name, 1);
}
static inline void spx_observe_end(spx_observer *out) {
    if (out->failed) return;
    if (out->depth <= 1) { out->failed = 1; return; }
    fputc(out->frames[--out->depth].object ? '}' : ']', out->stream);
}
static inline void spx_observe_u64(spx_observer *out, const char *name, uint64_t value) {
    if (spx_observe_item_(out, name)) fprintf(out->stream, "%" PRIu64, value);
}
static inline void spx_observe_i64(spx_observer *out, const char *name, int64_t value) {
    if (spx_observe_item_(out, name)) fprintf(out->stream, "%" PRId64, value);
}
static inline void spx_observe_bool(spx_observer *out, const char *name, int value) {
    if (spx_observe_item_(out, name)) fputs(value ? "true" : "false", out->stream);
}
static inline void spx_observe_null(spx_observer *out, const char *name) {
    if (spx_observe_item_(out, name)) fputs("null", out->stream);
}
static inline void spx_observe_bytes(spx_observer *out, const char *name, const void *data, size_t count) {
    const unsigned char *bytes = (const unsigned char *)data;
    if (count && !bytes) { out->failed = 1; return; }
    if (!spx_observe_item_(out, name)) return;
    fputc('"', out->stream);
    for (size_t i = 0; i < count; ++i) fprintf(out->stream, "%02x", (unsigned)bytes[i]);
    fputc('"', out->stream);
}
static inline void spx_observe_u32s(spx_observer *out, const char *name, const uint32_t *values, size_t count) {
    if (count && !values) { out->failed = 1; return; }
    spx_observe_array(out, name);
    for (size_t i = 0; !out->failed && i < count; ++i) spx_observe_u64(out, NULL, values[i]);
    spx_observe_end(out);
}
static inline int spx_observe_finish(spx_observer *out) {
    if (out->failed || out->depth != 1) { out->failed = 1; return 0; }
    out->depth = 0;
    fputs("}\n", out->stream);
    if (fflush(out->stream) || ferror(out->stream)) { out->failed = 1; return 0; }
    return 1;
}
#endif
