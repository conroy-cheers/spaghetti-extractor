#include "dr_api.h"
#include "drmgr.h"

#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define MAX_TEST_ID 256
#define SEEN_BUCKETS 65536
#define TRACE_RECORD_MAX 4096
#define PROC_MAPS_EAGER_SCANS 4096

typedef struct trace_module_t {
    app_pc start;
    app_pc end;
    app_pc entry;
    ptr_uint_t rva_base;
    char name[MAXIMUM_PATH];
    char path[MAXIMUM_PATH];
    char sha256[65];
    struct trace_module_t *next;
} trace_module_t;

typedef struct pe_candidate_t {
    char name[MAXIMUM_PATH];
    char path[MAXIMUM_PATH];
    char sha256[65];
    struct pe_candidate_t *next;
} pe_candidate_t;

typedef struct seen_entry_t {
    ptr_uint_t key[5];
    struct seen_entry_t *next;
} seen_entry_t;

typedef struct {
    app_pc start;
    app_pc end;
    app_pc entry;
    ptr_uint_t rva_base;
    char name[MAXIMUM_PATH];
    char path[MAXIMUM_PATH];
    char sha256[65];
} trace_module_snapshot_t;

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx_t;

static file_t trace_file = INVALID_FILE;
static void *trace_lock;
static char test_id[MAX_TEST_ID] = "unknown";
static char output_path[MAXIMUM_PATH] = "wincr-trace.jsonl";
static trace_module_t *trace_modules;
static pe_candidate_t *pe_candidates;
static seen_entry_t *seen_buckets[SEEN_BUCKETS];
static uint64_t proc_maps_scans;
static bool force_trace_all;
static bool semantic_values_enabled;
static uint64_t semantic_max_records = 128;
static uint64_t semantic_records_written;

static void event_exit(void);

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t
rotr(uint32_t value, uint32_t count)
{
    return (value >> count) | (value << (32 - count));
}

static void
register_client_exit_event(void)
{
#ifdef dr_register_exit_event
    drmgr_register_exit_event(event_exit);
#else
    dr_register_exit_event(event_exit);
#endif
}

static void
sha256_transform(sha256_ctx_t *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) |
            ((uint32_t)data[j + 2] << 8) | ((uint32_t)data[j + 3]);
    }
    for (; i < 64; ++i) {
        uint32_t s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t1 = h + s1 + ch + k[i] + m[i];
        t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void
sha256_init(sha256_ctx_t *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void
sha256_update(sha256_ctx_t *ctx, const uint8_t data[], size_t len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void
sha256_final(sha256_ctx_t *ctx, uint8_t hash[])
{
    uint32_t i = ctx->datalen;
    uint32_t j;

    ctx->data[i++] = 0x80;
    if (ctx->datalen < 56) {
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 8; ++j)
            hash[i + (j * 4)] = (uint8_t)((ctx->state[j] >> (24 - i * 8)) & 0xff);
    }
}

static bool
sha256_file(const char *path, char hex[65])
{
#ifdef _WIN32
    HANDLE file;
    sha256_ctx_t ctx;
    uint8_t buffer[4096];
    uint8_t digest[SHA256_DIGEST_SIZE];
    DWORD bytes_read = 0;
    BOOL ok = TRUE;
    int i;

    if (path == NULL || path[0] == '\0')
        return false;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    sha256_init(&ctx);
    while ((ok = ReadFile(file, buffer, sizeof(buffer), &bytes_read, NULL)) && bytes_read > 0)
        sha256_update(&ctx, buffer, (size_t)bytes_read);
    CloseHandle(file);
    if (!ok)
        return false;
    sha256_final(&ctx, digest);
    for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
        dr_snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[64] = '\0';
    return true;
#else
    file_t file = dr_open_file(path, DR_FILE_READ | DR_FILE_ALLOW_LARGE);
    sha256_ctx_t ctx;
    uint8_t buffer[4096];
    uint8_t digest[SHA256_DIGEST_SIZE];
    ssize_t read;
    int i;

    if (file == INVALID_FILE)
        return false;
    sha256_init(&ctx);
    while ((read = dr_read_file(file, buffer, sizeof(buffer))) > 0)
        sha256_update(&ctx, buffer, (size_t)read);
    dr_close_file(file);
    if (read < 0)
        return false;
    sha256_final(&ctx, digest);
    for (i = 0; i < SHA256_DIGEST_SIZE; ++i)
        dr_snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[64] = '\0';
    return true;
#endif
}

static void
append_char(char **cursor, char *end, char value)
{
    if (*cursor < end - 1) {
        **cursor = value;
        ++*cursor;
        **cursor = '\0';
    }
}

static void
append_raw(char **cursor, char *end, const char *value)
{
    const char *source = value == NULL ? "" : value;
    while (*source != '\0') {
        append_char(cursor, end, *source);
        ++source;
    }
}

static void
append_u64(char **cursor, char *end, unsigned long long value)
{
    char buffer[32];
    dr_snprintf(buffer, sizeof(buffer), "%llu", value);
    buffer[sizeof(buffer) - 1] = '\0';
    append_raw(cursor, end, buffer);
}

static void
append_int(char **cursor, char *end, int value)
{
    char buffer[32];
    dr_snprintf(buffer, sizeof(buffer), "%d", value);
    buffer[sizeof(buffer) - 1] = '\0';
    append_raw(cursor, end, buffer);
}

static void
append_json_string(char **cursor, char *end, const char *value)
{
    const unsigned char *source = (const unsigned char *)(value == NULL ? "" : value);
    append_char(cursor, end, '"');
    while (*source != '\0') {
        if (*source == '"' || *source == '\\') {
            append_char(cursor, end, '\\');
            append_char(cursor, end, (char)*source);
        } else if (*source == '\n') {
            append_raw(cursor, end, "\\n");
        } else if (*source == '\r') {
            append_raw(cursor, end, "\\r");
        } else if (*source == '\t') {
            append_raw(cursor, end, "\\t");
        } else if (*source < 0x20) {
            char escape[7];
            dr_snprintf(escape, sizeof(escape), "\\u%04x", *source);
            escape[sizeof(escape) - 1] = '\0';
            append_raw(cursor, end, escape);
        } else {
            append_char(cursor, end, (char)*source);
        }
        ++source;
    }
    append_char(cursor, end, '"');
}

static void
write_record(const char *record)
{
    size_t length = strlen(record);
    if (length > 0)
        dr_write_file(trace_file, record, length);
    dr_flush_file(trace_file);
}

static void
append_module_fields(char **cursor, char *end, const char *name, const char *sha)
{
    append_raw(cursor, end, ",\"pid\":");
    append_int(cursor, end, dr_get_process_id());
    append_raw(cursor, end, ",\"module_name\":");
    append_json_string(cursor, end, name == NULL ? "" : name);
    append_raw(cursor, end, ",\"module_sha256\":");
    append_json_string(cursor, end, sha == NULL ? "" : sha);
}

static void
begin_record(char **cursor, char *end, const char *kind)
{
    append_raw(cursor, end, "{\"kind\":");
    append_json_string(cursor, end, kind);
    append_raw(cursor, end, ",\"test_id\":");
    append_json_string(cursor, end, test_id);
}

static void
append_record_end(char **cursor, char *end)
{
    if (*cursor >= end - 2) {
        if (end - *cursor > 1)
            append_char(cursor, end, '\n');
        return;
    }
    append_raw(cursor, end, "}\n");
}

static void
append_module_record(char *record, size_t record_size, const char *name, const char *path,
                     const char *sha, app_pc start, app_pc end, app_pc entry, ptr_uint_t rva_base)
{
    char *cursor = record;
    char *limit = record + record_size;
    record[0] = '\0';
    begin_record(&cursor, limit, "module");
    append_raw(&cursor, limit, ",\"pid\":");
    append_int(&cursor, limit, dr_get_process_id());
    append_raw(&cursor, limit, ",\"module_name\":");
    append_json_string(&cursor, limit, name == NULL ? "" : name);
    append_raw(&cursor, limit, ",\"module_path\":");
    append_json_string(&cursor, limit, path == NULL ? "" : path);
    append_raw(&cursor, limit, ",\"module_sha256\":");
    append_json_string(&cursor, limit, sha == NULL ? "" : sha);
    append_raw(&cursor, limit, ",\"base\":");
    append_u64(&cursor, limit, (unsigned long long)(ptr_uint_t)start);
    append_raw(&cursor, limit, ",\"end\":");
    append_u64(&cursor, limit, (unsigned long long)(ptr_uint_t)end);
    append_raw(&cursor, limit, ",\"entry\":");
    append_u64(&cursor, limit, (unsigned long long)(ptr_uint_t)entry);
    append_raw(&cursor, limit, ",\"rva_base\":");
    append_u64(&cursor, limit, (unsigned long long)rva_base);
    append_record_end(&cursor, limit);
}

static void
append_block_record(char *record, size_t record_size, const trace_module_snapshot_t *module,
                    ptr_uint_t rva_start, uint size)
{
    char *cursor = record;
    char *limit = record + record_size;
    record[0] = '\0';
    begin_record(&cursor, limit, "block");
    append_module_fields(&cursor, limit, module->name, module->sha256);
    append_raw(&cursor, limit, ",\"rva_block\":");
    append_u64(&cursor, limit, (unsigned long long)rva_start);
    append_raw(&cursor, limit, ",\"size\":");
    append_u64(&cursor, limit, (unsigned long long)size);
    append_record_end(&cursor, limit);
}

static void
append_cfg_edge_record(char *record, size_t record_size, const trace_module_snapshot_t *module,
                       ptr_uint_t from_rva, ptr_uint_t to_rva, const char *observation)
{
    char *cursor = record;
    char *limit = record + record_size;
    record[0] = '\0';
    begin_record(&cursor, limit, "cfg_edge");
    append_module_fields(&cursor, limit, module->name, module->sha256);
    append_raw(&cursor, limit, ",\"edge_observation\":");
    append_json_string(&cursor, limit, observation);
    append_raw(&cursor, limit, ",\"rva_edge_from\":");
    append_u64(&cursor, limit, (unsigned long long)from_rva);
    append_raw(&cursor, limit, ",\"rva_edge_to\":");
    append_u64(&cursor, limit, (unsigned long long)to_rva);
    append_record_end(&cursor, limit);
}

static void
append_call_edge_record(char *record, size_t record_size, const trace_module_snapshot_t *caller_module,
                        ptr_uint_t caller_rva, const trace_module_snapshot_t *callee_module,
                        bool has_callee, ptr_uint_t callee_rva)
{
    char *cursor = record;
    char *limit = record + record_size;
    record[0] = '\0';
    begin_record(&cursor, limit, "call_edge");
    append_module_fields(&cursor, limit, caller_module->name, caller_module->sha256);
    append_raw(&cursor, limit, ",\"caller_rva\":");
    append_u64(&cursor, limit, (unsigned long long)caller_rva);
    append_raw(&cursor, limit, ",\"callee_module_sha256\":");
    append_json_string(&cursor, limit, has_callee ? callee_module->sha256 : "");
    append_raw(&cursor, limit, ",\"callee_rva\":");
    if (has_callee)
        append_u64(&cursor, limit, (unsigned long long)callee_rva);
    else
        append_raw(&cursor, limit, "null");
    append_record_end(&cursor, limit);
}

static void
append_register_value(char **cursor, char *limit, const char *name, reg_t value, bool *first)
{
    if (!*first)
        append_raw(cursor, limit, ",");
    append_json_string(cursor, limit, name);
    append_raw(cursor, limit, ":");
    append_u64(cursor, limit, (unsigned long long)value);
    *first = false;
}

static void
append_value_trace_record(char *record, size_t record_size, const trace_module_snapshot_t *module,
                          ptr_uint_t rva, app_pc pc, const dr_mcontext_t *mc)
{
    char *cursor = record;
    char *limit = record + record_size;
    bool first_register = true;
    record[0] = '\0';
    begin_record(&cursor, limit, "value_trace");
    append_module_fields(&cursor, limit, module->name, module->sha256);
    append_raw(&cursor, limit, ",\"rva\":");
    append_u64(&cursor, limit, (unsigned long long)rva);
    append_raw(&cursor, limit, ",\"profile\":");
    append_json_string(&cursor, limit, "bounded-block-entry-registers");
    append_raw(&cursor, limit, ",\"values\":{\"capture\":\"registers\",\"registers\":{");
    append_register_value(&cursor, limit, "xax", mc->xax, &first_register);
    append_register_value(&cursor, limit, "xbx", mc->xbx, &first_register);
    append_register_value(&cursor, limit, "xcx", mc->xcx, &first_register);
    append_register_value(&cursor, limit, "xdx", mc->xdx, &first_register);
    append_register_value(&cursor, limit, "xsi", mc->xsi, &first_register);
    append_register_value(&cursor, limit, "xdi", mc->xdi, &first_register);
    append_register_value(&cursor, limit, "xbp", mc->xbp, &first_register);
    append_register_value(&cursor, limit, "xsp", mc->xsp, &first_register);
    append_raw(&cursor, limit, "},\"pc\":");
    append_u64(&cursor, limit, (unsigned long long)(ptr_uint_t)pc);
    append_raw(&cursor, limit, "},\"semantic_profile\":{\"enabled\":true,\"bounded\":true,\"max_records\":");
    append_u64(&cursor, limit, (unsigned long long)semantic_max_records);
    append_raw(&cursor, limit, "}");
    append_record_end(&cursor, limit);
}
static void
copy_string(char *destination, size_t destination_size, const char *source)
{
    dr_snprintf(destination, destination_size, "%s", source == NULL ? "" : source);
    destination[destination_size - 1] = '\0';
}

static const char *
base_name(const char *path)
{
    const char *last = path;
    const char *cursor;
    if (path == NULL)
        return "";
    for (cursor = path; *cursor != '\0'; ++cursor) {
        if (*cursor == '/' || *cursor == '\\')
            last = cursor + 1;
    }
    return last;
}

static char
lower_ascii(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
        return (char)(ch - 'A' + 'a');
    return ch;
}

static bool
has_suffix_ci(const char *value, const char *suffix)
{
    size_t value_len;
    size_t suffix_len;
    size_t offset;
    size_t i;
    if (value == NULL || suffix == NULL)
        return false;
    value_len = strlen(value);
    suffix_len = strlen(suffix);
    if (value_len < suffix_len)
        return false;
    offset = value_len - suffix_len;
    for (i = 0; i < suffix_len; ++i) {
        if (lower_ascii(value[offset + i]) != lower_ascii(suffix[i]))
            return false;
    }
    return true;
}

static bool
is_pe_path(const char *path)
{
    return has_suffix_ci(path, ".exe") || has_suffix_ci(path, ".dll");
}

static bool
is_absolute_unix_path(const char *path)
{
    return path != NULL && path[0] == '/';
}

static bool
trace_filter_enabled(void)
{
    return !force_trace_all && pe_candidates != NULL;
}

static uint16_t
read_le16(const unsigned char *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t
read_le32(const unsigned char *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
        ((uint32_t)data[3] << 24);
}

static bool
pe_image_metadata_from_headers(const unsigned char *headers, size_t bytes_read, ptr_uint_t *size_out,
                               ptr_uint_t *entrypoint_rva_out)
{
    uint32_t pe_offset;
    uint16_t optional_header_size;
    const unsigned char *optional_header;
    uint16_t magic;
    uint32_t size_of_image;
    uint32_t entrypoint_rva;

    if (headers == NULL || bytes_read < 0x100 || size_out == NULL)
        return false;
    if (headers[0] != 'M' || headers[1] != 'Z')
        return false;
    pe_offset = read_le32(headers + 0x3c);
    if ((size_t)pe_offset + 24 + 64 > bytes_read)
        return false;
    if (headers[pe_offset] != 'P' || headers[pe_offset + 1] != 'E' || headers[pe_offset + 2] != 0 ||
        headers[pe_offset + 3] != 0) {
        return false;
    }
    optional_header_size = read_le16(headers + pe_offset + 20);
    if ((size_t)pe_offset + 24 + optional_header_size > bytes_read || optional_header_size < 64)
        return false;
    optional_header = headers + pe_offset + 24;
    magic = read_le16(optional_header);
    if (magic != 0x10b && magic != 0x20b)
        return false;
    size_of_image = read_le32(optional_header + 56);
    if (size_of_image < 0x1000 || size_of_image > 0x40000000)
        return false;
    entrypoint_rva = read_le32(optional_header + 16);
    if (entrypoint_rva >= size_of_image)
        entrypoint_rva = 0;
    *size_out = (ptr_uint_t)size_of_image;
    if (entrypoint_rva_out != NULL)
        *entrypoint_rva_out = (ptr_uint_t)entrypoint_rva;
    return true;
}

static void
remember_pe_candidate(const char *path)
{
    pe_candidate_t *existing;
    pe_candidate_t *node;
    char sha[65] = "";
    char resolved_path[MAXIMUM_PATH];
    char cwd[MAXIMUM_PATH];

    if (path == NULL || !is_pe_path(path))
        return;
    if (is_absolute_unix_path(path)) {
        copy_string(resolved_path, sizeof(resolved_path), path);
    } else if (dr_get_current_directory(cwd, sizeof(cwd)) && cwd[0] != '\0') {
        dr_snprintf(resolved_path, sizeof(resolved_path), "%s/%s", cwd, path);
        resolved_path[sizeof(resolved_path) - 1] = '\0';
    } else {
        copy_string(resolved_path, sizeof(resolved_path), path);
    }
    for (existing = pe_candidates; existing != NULL; existing = existing->next) {
        if (strcmp(existing->path, resolved_path) == 0)
            return;
    }
    if (!sha256_file(resolved_path, sha))
        return;

    node = dr_global_alloc(sizeof(*node));
    if (node == NULL)
        return;
    copy_string(node->name, sizeof(node->name), base_name(resolved_path));
    copy_string(node->path, sizeof(node->path), resolved_path);
    copy_string(node->sha256, sizeof(node->sha256), sha);
    node->next = pe_candidates;
    pe_candidates = node;
}

static pe_candidate_t *
first_pe_executable_candidate(void)
{
    pe_candidate_t *candidate;
    for (candidate = pe_candidates; candidate != NULL; candidate = candidate->next) {
        if (has_suffix_ci(candidate->name, ".exe"))
            return candidate;
    }
    return pe_candidates;
}

static pe_candidate_t *
candidate_for_pe_path(const char *path)
{
    pe_candidate_t *candidate;
    const char *name = base_name(path);
    if (path != NULL && *path != '\0') {
        for (candidate = pe_candidates; candidate != NULL; candidate = candidate->next) {
            if (strcmp(candidate->path, path) == 0 || strcmp(candidate->name, name) == 0)
                return candidate;
        }
    }
    return first_pe_executable_candidate();
}

static pe_candidate_t *
exact_candidate_for_pe_path(const char *path)
{
    pe_candidate_t *candidate;
    const char *name = base_name(path);
    if (path == NULL || *path == '\0')
        return NULL;
    for (candidate = pe_candidates; candidate != NULL; candidate = candidate->next) {
        if (strcmp(candidate->path, path) == 0 || strcmp(candidate->name, name) == 0)
            return candidate;
    }
    return NULL;
}

static bool
should_record_pe_path(const char *path)
{
    return !trace_filter_enabled() || exact_candidate_for_pe_path(path) != NULL;
}

static bool
memory_pe_size(app_pc start, ptr_uint_t *size_out)
{
    unsigned char headers[4096];
    size_t bytes_read = 0;

    if (start == NULL || size_out == NULL)
        return false;
    if (!dr_safe_read(start, sizeof(headers), headers, &bytes_read) || bytes_read < 0x100)
        return false;
    return pe_image_metadata_from_headers(headers, bytes_read, size_out, NULL);
}

static bool
file_pe_image_metadata(const char *path, ptr_uint_t *size_out, ptr_uint_t *entrypoint_rva_out)
{
    unsigned char headers[8192];
    file_t file;
    ssize_t read;

    if (path == NULL || size_out == NULL)
        return false;
    file = dr_open_file(path, DR_FILE_READ | DR_FILE_ALLOW_LARGE);
    if (file == INVALID_FILE)
        return false;
    read = dr_read_file(file, headers, sizeof(headers));
    dr_close_file(file);
    if (read <= 0)
        return false;
    return pe_image_metadata_from_headers(headers, (size_t)read, size_out, entrypoint_rva_out);
}

static ptr_uint_t
pe_rva_for_file_offset(const char *path, ptr_uint_t file_offset)
{
    unsigned char headers[8192];
    file_t file;
    ssize_t read;
    uint32_t pe_offset;
    uint16_t section_count;
    uint16_t optional_header_size;
    size_t section_table;
    uint16_t i;

    if (file_offset == 0)
        return 0;
    file = dr_open_file(path, DR_FILE_READ | DR_FILE_ALLOW_LARGE);
    if (file == INVALID_FILE)
        return file_offset;
    read = dr_read_file(file, headers, sizeof(headers));
    dr_close_file(file);
    if (read < 0x100 || headers[0] != 'M' || headers[1] != 'Z')
        return file_offset;
    pe_offset = read_le32(headers + 0x3c);
    if ((size_t)pe_offset + 24 > (size_t)read)
        return file_offset;
    if (headers[pe_offset] != 'P' || headers[pe_offset + 1] != 'E' || headers[pe_offset + 2] != 0 ||
        headers[pe_offset + 3] != 0) {
        return file_offset;
    }
    section_count = read_le16(headers + pe_offset + 6);
    optional_header_size = read_le16(headers + pe_offset + 20);
    section_table = (size_t)pe_offset + 24 + optional_header_size;
    for (i = 0; i < section_count; ++i) {
        size_t section = section_table + (size_t)i * 40;
        uint32_t virtual_size;
        uint32_t virtual_address;
        uint32_t raw_size;
        uint32_t raw_pointer;
        uint32_t raw_end;
        if (section + 40 > (size_t)read)
            break;
        virtual_size = read_le32(headers + section + 8);
        virtual_address = read_le32(headers + section + 12);
        raw_size = read_le32(headers + section + 16);
        raw_pointer = read_le32(headers + section + 20);
        raw_end = raw_pointer + raw_size;
        if (raw_size == 0)
            raw_end = raw_pointer + virtual_size;
        if (file_offset >= raw_pointer && file_offset < raw_end)
            return (ptr_uint_t)virtual_address + (file_offset - raw_pointer);
    }
    return file_offset;
}

static bool
pc_in_module_snapshot(app_pc pc, const trace_module_snapshot_t *module)
{
    return module != NULL && pc != NULL && pc >= module->start && pc < module->end;
}

static ptr_uint_t
rva_for_pc(app_pc pc, const trace_module_snapshot_t *module)
{
    if (!pc_in_module_snapshot(pc, module))
        return 0;
    return module->rva_base + (ptr_uint_t)(pc - module->start);
}

static bool
remember_module_range(app_pc start, app_pc end, app_pc entry, ptr_uint_t rva_base, const char *name,
                      const char *path, const char *sha)
{
    trace_module_t *existing;
    trace_module_t *node = dr_global_alloc(sizeof(*node));

    dr_mutex_lock(trace_lock);
    for (existing = trace_modules; existing != NULL; existing = existing->next) {
        if (existing->start == start && existing->end == end && strcmp(existing->path, path == NULL ? "" : path) == 0) {
            dr_mutex_unlock(trace_lock);
            if (node != NULL)
                dr_global_free(node, sizeof(*node));
            return false;
        }
    }
    if (node == NULL) {
        dr_mutex_unlock(trace_lock);
        return false;
    }
    node->start = start;
    node->end = end;
    node->entry = entry;
    node->rva_base = rva_base;
    copy_string(node->name, sizeof(node->name), name);
    copy_string(node->path, sizeof(node->path), path);
    copy_string(node->sha256, sizeof(node->sha256), sha);
    node->next = trace_modules;
    trace_modules = node;
    dr_mutex_unlock(trace_lock);
    return true;
}

static void
emit_module_record(const char *name, const char *path, const char *sha, app_pc start, app_pc end,
                   app_pc entry, ptr_uint_t rva_base)
{
    char record[TRACE_RECORD_MAX];
    append_module_record(record, sizeof(record), name, path, sha, start, end, entry, rva_base);
    dr_mutex_lock(trace_lock);
    write_record(record);
    dr_mutex_unlock(trace_lock);
}

#if defined(UNIX) || defined(__linux__)
static void
load_pe_candidates_from_cmdline(void)
{
    file_t file;
    char *buffer;
    ssize_t read;
    ssize_t index;
    ssize_t start = 0;

    file = dr_open_file("/proc/self/cmdline", DR_FILE_READ);
    if (file == INVALID_FILE)
        return;
    buffer = dr_global_alloc(64 * 1024 + 1);
    if (buffer == NULL) {
        dr_close_file(file);
        return;
    }
    read = dr_read_file(file, buffer, 64 * 1024);
    dr_close_file(file);
    if (read <= 0) {
        dr_global_free(buffer, 64 * 1024 + 1);
        return;
    }
    buffer[read] = '\0';
    for (index = 0; index <= read; ++index) {
        if (index == read || buffer[index] == '\0') {
            if (index > start)
                remember_pe_candidate(buffer + start);
            start = index + 1;
        }
    }
    dr_global_free(buffer, 64 * 1024 + 1);
}

static bool
parse_hex_value(const char **cursor, ptr_uint_t *out)
{
    ptr_uint_t value = 0;
    bool saw_digit = false;
    const char *p = *cursor;
    while (*p != '\0') {
        char ch = *p;
        uint digit;
        if (ch >= '0' && ch <= '9')
            digit = (uint)(ch - '0');
        else if (ch >= 'a' && ch <= 'f')
            digit = (uint)(ch - 'a' + 10);
        else if (ch >= 'A' && ch <= 'F')
            digit = (uint)(ch - 'A' + 10);
        else
            break;
        value = (value << 4) | digit;
        saw_digit = true;
        ++p;
    }
    if (!saw_digit)
        return false;
    *cursor = p;
    *out = value;
    return true;
}

static void
skip_spaces(const char **cursor)
{
    while (**cursor == ' ' || **cursor == '\t')
        ++*cursor;
}

static void
skip_token(const char **cursor)
{
    skip_spaces(cursor);
    while (**cursor != '\0' && **cursor != ' ' && **cursor != '\t')
        ++*cursor;
}

static void
trim_newline(char *value)
{
    size_t len = strlen(value);
    while (len > 0 && (value[len - 1] == '\n' || value[len - 1] == '\r')) {
        value[len - 1] = '\0';
        --len;
    }
}

static void
process_proc_maps_line(char *line)
{
    const char *cursor = line;
    ptr_uint_t start;
    ptr_uint_t end;
    ptr_uint_t file_offset;
    const char *path;
    char sha[65] = "";
    ptr_uint_t rva_base;
    ptr_uint_t image_size;
    pe_candidate_t *candidate;

    if (!parse_hex_value(&cursor, &start) || *cursor != '-')
        return;
    ++cursor;
    if (!parse_hex_value(&cursor, &end))
        return;
    skip_token(&cursor); /* permissions */
    skip_spaces(&cursor);
    if (!parse_hex_value(&cursor, &file_offset))
        return;
    skip_token(&cursor); /* dev */
    skip_token(&cursor); /* inode */
    skip_spaces(&cursor);
    path = cursor;
    trim_newline((char *)path);

    if (!is_pe_path(path)) {
        if (file_offset != 0 || !memory_pe_size((app_pc)start, &image_size))
            return;
        candidate = candidate_for_pe_path(path);
        if (candidate != NULL) {
            if (remember_module_range((app_pc)start, (app_pc)(start + image_size), (app_pc)start, 0,
                                      candidate->name, candidate->path, candidate->sha256)) {
                emit_module_record(candidate->name, candidate->path, candidate->sha256, (app_pc)start,
                                   (app_pc)(start + image_size), (app_pc)start, 0);
            }
        } else {
            if (remember_module_range((app_pc)start, (app_pc)(start + image_size), (app_pc)start, 0,
                                      "anonymous-pe", path, "")) {
                emit_module_record("anonymous-pe", path, "", (app_pc)start, (app_pc)(start + image_size),
                                   (app_pc)start, 0);
            }
        }
        return;
    }

    if (!should_record_pe_path(path))
        return;

    sha256_file(path, sha);
    if (file_offset == 0 && file_pe_image_metadata(path, &image_size, &rva_base)) {
        if (remember_module_range((app_pc)start, (app_pc)(start + image_size), (app_pc)(start + rva_base),
                                  0, base_name(path), path, sha)) {
            emit_module_record(base_name(path), path, sha, (app_pc)start, (app_pc)(start + image_size),
                               (app_pc)(start + rva_base), 0);
        }
        return;
    }
    rva_base = pe_rva_for_file_offset(path, file_offset);
    if (remember_module_range((app_pc)start, (app_pc)end, (app_pc)start, rva_base, base_name(path), path, sha)) {
        emit_module_record(base_name(path), path, sha, (app_pc)start, (app_pc)end, (app_pc)start, rva_base);
    }
}

static void
refresh_proc_maps(void)
{
    file_t file;
    char *buffer;
    ssize_t read;
    char *line;
    char *cursor;

    file = dr_open_file("/proc/self/maps", DR_FILE_READ);
    if (file == INVALID_FILE)
        return;
    buffer = dr_global_alloc(1024 * 1024 + 1);
    if (buffer == NULL) {
        dr_close_file(file);
        return;
    }
    read = dr_read_file(file, buffer, 1024 * 1024);
    dr_close_file(file);
    if (read <= 0) {
        dr_global_free(buffer, 1024 * 1024 + 1);
        return;
    }
    buffer[read] = '\0';
    line = buffer;
    for (cursor = buffer; *cursor != '\0'; ++cursor) {
        if (*cursor == '\n') {
            *cursor = '\0';
            process_proc_maps_line(line);
            line = cursor + 1;
        }
    }
    if (*line != '\0')
        process_proc_maps_line(line);
    dr_global_free(buffer, 1024 * 1024 + 1);
}
#else
static void
load_pe_candidates_from_cmdline(void)
{
}

static void
refresh_proc_maps(void)
{
}
#endif

static bool
lookup_module_cached(app_pc pc, trace_module_snapshot_t *out)
{
    trace_module_t *node;
    bool found = false;
    if (pc == NULL || out == NULL)
        return false;

    dr_mutex_lock(trace_lock);
    for (node = trace_modules; node != NULL; node = node->next) {
        if (pc >= node->start && pc < node->end) {
            out->start = node->start;
            out->end = node->end;
            out->entry = node->entry;
            out->rva_base = node->rva_base;
            copy_string(out->name, sizeof(out->name), node->name);
            copy_string(out->path, sizeof(out->path), node->path);
            copy_string(out->sha256, sizeof(out->sha256), node->sha256);
            found = true;
            break;
        }
    }
    dr_mutex_unlock(trace_lock);
    return found;
}

static bool
lookup_module(app_pc pc, trace_module_snapshot_t *out)
{
    if (lookup_module_cached(pc, out))
        return true;
    if (proc_maps_scans < PROC_MAPS_EAGER_SCANS || (proc_maps_scans & 0xff) == 0)
        refresh_proc_maps();
    ++proc_maps_scans;
    return lookup_module_cached(pc, out);
}

static void
free_module_cache(void)
{
    trace_module_t *node = trace_modules;
    while (node != NULL) {
        trace_module_t *next = node->next;
        dr_global_free(node, sizeof(*node));
        node = next;
    }
    trace_modules = NULL;
}

static void
free_pe_candidates(void)
{
    pe_candidate_t *node = pe_candidates;
    while (node != NULL) {
        pe_candidate_t *next = node->next;
        dr_global_free(node, sizeof(*node));
        node = next;
    }
    pe_candidates = NULL;
}

static uint32_t
hash_seen_key(ptr_uint_t key0, ptr_uint_t key1, ptr_uint_t key2, ptr_uint_t key3, ptr_uint_t key4)
{
    uint64_t value = (uint64_t)key0;
    value ^= (uint64_t)key1 + 0x9e3779b97f4a7c15ULL + (value << 6) + (value >> 2);
    value ^= (uint64_t)key2 + 0x9e3779b97f4a7c15ULL + (value << 6) + (value >> 2);
    value ^= (uint64_t)key3 + 0x9e3779b97f4a7c15ULL + (value << 6) + (value >> 2);
    value ^= (uint64_t)key4 + 0x9e3779b97f4a7c15ULL + (value << 6) + (value >> 2);
    return (uint32_t)(value & (SEEN_BUCKETS - 1));
}

static bool
mark_seen_locked(ptr_uint_t key0, ptr_uint_t key1, ptr_uint_t key2, ptr_uint_t key3, ptr_uint_t key4)
{
    uint32_t bucket = hash_seen_key(key0, key1, key2, key3, key4);
    seen_entry_t *entry;
    for (entry = seen_buckets[bucket]; entry != NULL; entry = entry->next) {
        if (entry->key[0] == key0 && entry->key[1] == key1 && entry->key[2] == key2 &&
            entry->key[3] == key3 && entry->key[4] == key4) {
            return false;
        }
    }
    entry = dr_global_alloc(sizeof(*entry));
    if (entry == NULL)
        return false;
    entry->key[0] = key0;
    entry->key[1] = key1;
    entry->key[2] = key2;
    entry->key[3] = key3;
    entry->key[4] = key4;
    entry->next = seen_buckets[bucket];
    seen_buckets[bucket] = entry;
    return true;
}

static void
free_seen_cache(void)
{
    uint32_t bucket;
    for (bucket = 0; bucket < SEEN_BUCKETS; ++bucket) {
        seen_entry_t *entry = seen_buckets[bucket];
        while (entry != NULL) {
            seen_entry_t *next = entry->next;
            dr_global_free(entry, sizeof(*entry));
            entry = next;
        }
        seen_buckets[bucket] = NULL;
    }
}

static void
emit_module(const module_data_t *mod)
{
    const char *name = dr_module_preferred_name(mod);
    char sha[65] = "";
    if (trace_filter_enabled())
        return;
    if (mod->full_path != NULL)
        sha256_file(mod->full_path, sha);
    if (remember_module_range(mod->start, mod->end, mod->entry_point, 0, name, mod->full_path, sha))
        emit_module_record(name, mod->full_path, sha, mod->start, mod->end, mod->entry_point, 0);
}

static bool
should_trace_basic_block(app_pc start)
{
    trace_module_snapshot_t module;

    if (!trace_filter_enabled())
        return true;
    if (lookup_module_cached(start, &module))
        return true;
    if (proc_maps_scans < PROC_MAPS_EAGER_SCANS || (proc_maps_scans & 0xff) == 0)
        refresh_proc_maps();
    ++proc_maps_scans;
    return lookup_module_cached(start, &module);
}

static void
emit_block(app_pc start, app_pc end)
{
    trace_module_snapshot_t module;
    ptr_uint_t rva_start;
    ptr_uint_t rva_end;
    char record[TRACE_RECORD_MAX];
    if (!lookup_module(start, &module))
        return;
    rva_start = rva_for_pc(start, &module);
    rva_end = rva_start + (ptr_uint_t)(end - start);

    dr_mutex_lock(trace_lock);
    if (!mark_seen_locked(1, (ptr_uint_t)module.start, rva_start, rva_end, 0)) {
        dr_mutex_unlock(trace_lock);
        return;
    }
    append_block_record(record, sizeof(record), &module, rva_start, (uint)(end - start));
    write_record(record);
    dr_mutex_unlock(trace_lock);
}

static void
emit_value_trace(app_pc pc)
{
    trace_module_snapshot_t module;
    ptr_uint_t rva;
    dr_mcontext_t mc;
    char record[TRACE_RECORD_MAX];
    void *drcontext;

    if (!semantic_values_enabled)
        return;
    if (!lookup_module(pc, &module))
        return;
    rva = rva_for_pc(pc, &module);

    dr_mutex_lock(trace_lock);
    if (semantic_records_written >= semantic_max_records ||
        !mark_seen_locked(4, (ptr_uint_t)module.start, rva, 0, 0)) {
        dr_mutex_unlock(trace_lock);
        return;
    }
    ++semantic_records_written;
    dr_mutex_unlock(trace_lock);

    drcontext = dr_get_current_drcontext();
    memset(&mc, 0, sizeof(mc));
    mc.size = sizeof(mc);
    mc.flags = DR_MC_INTEGER | DR_MC_CONTROL;
    if (!dr_get_mcontext(drcontext, &mc))
        return;

    dr_mutex_lock(trace_lock);
    append_value_trace_record(record, sizeof(record), &module, rva, pc, &mc);
    write_record(record);
    dr_mutex_unlock(trace_lock);
}

static void
emit_cfg_edge_observed(app_pc from, app_pc to, const char *observation)
{
    trace_module_snapshot_t module;
    ptr_uint_t from_rva;
    ptr_uint_t to_rva;
    char record[TRACE_RECORD_MAX];
    if (!lookup_module(from, &module))
        return;
    if (!pc_in_module_snapshot(to, &module))
        return;
    from_rva = rva_for_pc(from, &module);
    to_rva = rva_for_pc(to, &module);

    dr_mutex_lock(trace_lock);
    if (!mark_seen_locked(2, (ptr_uint_t)module.start, from_rva, to_rva, 0)) {
        dr_mutex_unlock(trace_lock);
        return;
    }
    append_cfg_edge_record(record, sizeof(record), &module, from_rva, to_rva, observation);
    write_record(record);
    dr_mutex_unlock(trace_lock);
}

static void
emit_direct_branch_edge(app_pc from, app_pc to)
{
    emit_cfg_edge_observed(from, to, "direct_taken");
}

static void
emit_indirect_branch_edge(app_pc from, app_pc to)
{
    emit_cfg_edge_observed(from, to, "indirect_taken");
}

static void
emit_conditional_branch_edge(app_pc from, app_pc target, app_pc fallthrough, bool taken, void *user_data)
{
    (void)user_data;
    emit_cfg_edge_observed(from, taken ? target : fallthrough, taken ? "conditional_taken" : "conditional_fallthrough");
}

static void
emit_call_edge(app_pc caller, app_pc callee)
{
    trace_module_snapshot_t caller_module;
    trace_module_snapshot_t callee_module;
    bool has_callee;
    ptr_uint_t caller_rva;
    ptr_uint_t callee_module_key;
    ptr_uint_t callee_rva;
    char record[TRACE_RECORD_MAX];

    if (!lookup_module(caller, &caller_module))
        return;
    has_callee = lookup_module(callee, &callee_module);
    caller_rva = rva_for_pc(caller, &caller_module);
    callee_module_key = has_callee ? (ptr_uint_t)callee_module.start : 0;
    callee_rva = has_callee ? rva_for_pc(callee, &callee_module) : 0;

    dr_mutex_lock(trace_lock);
    if (!mark_seen_locked(3, (ptr_uint_t)caller_module.start, caller_rva, callee_module_key, callee_rva)) {
        dr_mutex_unlock(trace_lock);
        return;
    }
    append_call_edge_record(record, sizeof(record), &caller_module, caller_rva, &callee_module,
                            has_callee, callee_rva);
    write_record(record);
    dr_mutex_unlock(trace_lock);
}

static void
emit_call_transfer(app_pc caller, app_pc callee)
{
    emit_cfg_edge_observed(caller, callee, "call_taken");
    emit_call_edge(caller, callee);
}

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    emit_module(mod);
}

static dr_emit_flags_t
event_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace,
         bool translating, void *user_data)
{
    instr_t *last;
    app_pc start;
    app_pc end;

    if (!drmgr_is_first_instr(drcontext, instr))
        return DR_EMIT_DEFAULT;

    start = instr_get_app_pc(instr);
    if (start == NULL || !should_trace_basic_block(start))
        return DR_EMIT_DEFAULT;

    drmgr_disable_auto_predication(drcontext, bb);
    last = instrlist_last_app(bb);
    if (start != NULL && last != NULL && instr_get_app_pc(last) != NULL) {
        end = instr_get_app_pc(last) + instr_length(drcontext, last);
        dr_insert_clean_call(drcontext, bb, instr, (void *)emit_block, false, 2,
                             OPND_CREATE_INTPTR(start), OPND_CREATE_INTPTR(end));
        if (semantic_values_enabled) {
            dr_insert_clean_call(drcontext, bb, instr, (void *)emit_value_trace, false, 1,
                                 OPND_CREATE_INTPTR(start));
        }
    }

    if (last != NULL && instr_is_cti(last) && instr_get_app_pc(last) != NULL) {
        if (instr_is_cbr(last)) {
            dr_insert_cbr_instrumentation_ex(drcontext, bb, last, (void *)emit_conditional_branch_edge,
                                             OPND_CREATE_INTPTR(0));
        } else if (instr_is_call_direct(last)) {
            dr_insert_call_instrumentation(drcontext, bb, last, (void *)emit_call_transfer);
        } else if (instr_is_call_indirect(last)) {
            dr_insert_mbr_instrumentation(drcontext, bb, last, (void *)emit_call_transfer, SPILL_SLOT_1);
        } else if (instr_is_ubr(last)) {
            dr_insert_ubr_instrumentation(drcontext, bb, last, (void *)emit_direct_branch_edge);
        } else if (instr_is_mbr(last) && !instr_is_return(last)) {
            dr_insert_mbr_instrumentation(drcontext, bb, last, (void *)emit_indirect_branch_edge, SPILL_SLOT_1);
        }
    }

    return DR_EMIT_DEFAULT;
}

static void
event_exit(void)
{
    drmgr_unregister_module_load_event(module_load_event);
    drmgr_unregister_bb_insertion_event(event_bb);
    if (trace_file != INVALID_FILE && trace_file != STDERR)
        dr_close_file(trace_file);
    free_module_cache();
    free_pe_candidates();
    free_seen_cache();
    dr_mutex_destroy(trace_lock);
    drmgr_exit();
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    int i;
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            dr_snprintf(output_path, sizeof(output_path), "%s", argv[++i]);
            output_path[sizeof(output_path) - 1] = '\0';
        } else if (strcmp(argv[i], "-test_id") == 0 && i + 1 < argc) {
            dr_snprintf(test_id, sizeof(test_id), "%s", argv[++i]);
            test_id[sizeof(test_id) - 1] = '\0';
        } else if (strcmp(argv[i], "-trace_all") == 0) {
            force_trace_all = true;
        } else if (strcmp(argv[i], "-semantic_values") == 0) {
            semantic_values_enabled = true;
        } else if (strcmp(argv[i], "-semantic_max_records") == 0 && i + 1 < argc) {
            uint64_t parsed = 0;
            if (dr_sscanf(argv[++i], "%llu", &parsed) == 1 && parsed > 0)
                semantic_max_records = parsed;
        }
    }

    dr_set_client_name("Windows clean-room trace client", "https://github.com/conroy-cheers");
    if (!drmgr_init())
        DR_ASSERT(false);
    trace_lock = dr_mutex_create();
    {
        char process_output_path[MAXIMUM_PATH];
        dr_snprintf(process_output_path, sizeof(process_output_path), "%s.%d", output_path, dr_get_process_id());
        process_output_path[sizeof(process_output_path) - 1] = '\0';
        trace_file = dr_open_file(process_output_path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
    }
    if (trace_file == INVALID_FILE)
        trace_file = STDERR;

    load_pe_candidates_from_cmdline();
    register_client_exit_event();
    drmgr_register_module_load_event(module_load_event);
    if (!drmgr_register_bb_instrumentation_event(NULL, event_bb, NULL))
        DR_ASSERT(false);
}
