#ifndef SPX_JQ_BINARY_DRIVER_H
#define SPX_JQ_BINARY_DRIVER_H
/* Operator-owned comparison support for two consumed jv inputs and an owned
 * result. Entry ranges, kinds, contracts and cases remain explicit inputs.
 * Both sides use the same parsing, observations and allocation observer. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "jq.h"
#include "allocation-observer.h"
#include "native-entry.h"

#define SPX_JQ_ANY_VALID (-1)
struct spx_jq_binary_driver {
    const char *name;
    jv (*original)(jv, jv);
    jv (*replacement)(jv, jv);
    int left_kind, right_kind;
    /* Optional admission and root observation fields, before entry installation
     * or allocation accounting. Emit complete JSON fields followed by commas. */
    int (*case_fields)(const char *left, const char *right, const char *mode);
};
static const struct spx_jq_binary_driver *spx_jq_binary_active;
static unsigned spx_jq_binary_calls;

static jv spx_jq_binary_counted(jv left, jv right) {
    ++spx_jq_binary_calls;
    return spx_jq_binary_active->replacement(left, right);
}
static void spx_jq_binary_emit(jv value) {
    jv text = jv_dump_string(value, JV_PRINT_SORTED);
    fputs(jv_string_value(text), stdout);
    jv_free(text);
}
static int spx_jq_binary_kind(jv value, int expected) {
    return expected == SPX_JQ_ANY_VALID ? jv_is_valid(value) : jv_get_kind(value) == (jv_kind)expected;
}
static int spx_jq_binary_heap(jv_kind kind) {
    return kind == JV_KIND_ARRAY || kind == JV_KIND_OBJECT || kind == JV_KIND_STRING;
}
static void spx_jq_binary_sample(jv left, jv right, unsigned index, int retained, int observe_address) {
    const struct spx_jq_binary_driver *driver = spx_jq_binary_active;
    if (!spx_jq_binary_kind(left, driver->left_kind) || !spx_jq_binary_kind(right, driver->right_kind)) exit(84);
    int left_references = jv_get_refcnt(left), right_references = jv_get_refcnt(right);
    jv_kind left_kind = jv_get_kind(left);
    /* Capture integer address bits while the value is live. Never inspect a
     * consumed input after the call; a matching address is not lifetime proof. */
    uintptr_t left_address = spx_jq_binary_heap(left_kind) ? (uintptr_t)left.u.ptr : 0;
    jv keep_left = retained ? jv_copy(left) : jv_null();
    jv keep_right = retained ? jv_copy(right) : jv_null();
    jv result = driver->original(left, right);
    allocation_observer_pause(1);
    if (index) fputc(',', stdout);
    fputs("{\"result\":", stdout); spx_jq_binary_emit(jv_copy(result));
    fputs(",\"left_after\":", stdout); spx_jq_binary_emit(jv_copy(keep_left));
    fputs(",\"right_after\":", stdout); spx_jq_binary_emit(jv_copy(keep_right));
    if (retained) printf(",\"references\":[%d,%d]}", jv_get_refcnt(keep_left), jv_get_refcnt(keep_right));
    else {
        printf(",\"references\":null,\"input_references\":[%d,%d]", left_references, right_references);
        if (observe_address) {
            fputs(",\"result_uses_left_address\":", stdout);
            if (spx_jq_binary_heap(left_kind) && jv_get_kind(result) == left_kind)
                fputs((uintptr_t)result.u.ptr == left_address ? "true" : "false", stdout);
            else fputs("null", stdout);
        }
        fputc('}', stdout);
    }
    allocation_observer_pause(0);
    jv_free(result); jv_free(keep_left); jv_free(keep_right);
}
static void spx_jq_binary_batch(const char *input) {
    jv rows = jv_parse(input);
    if (jv_get_kind(rows) != JV_KIND_ARRAY) exit(84);
    int count = jv_array_length(jv_copy(rows));
    if (count == 0) exit(84);
    for (int i = 0; i < count; ++i) {
        jv row = jv_array_get(jv_copy(rows), i);
        if (jv_get_kind(row) != JV_KIND_ARRAY) exit(84);
        int length = jv_array_length(jv_copy(row));
        if (length != 2 && length != 3) exit(84);
        int aliased = 0;
        if (length == 3) {
            jv flag = jv_array_get(jv_copy(row), 2);
            if (jv_get_kind(flag) != JV_KIND_TRUE && jv_get_kind(flag) != JV_KIND_FALSE) exit(84);
            aliased = jv_get_kind(flag) == JV_KIND_TRUE; jv_free(flag);
        }
        jv left = jv_array_get(jv_copy(row), 0);
        jv right = aliased ? jv_copy(left) : jv_array_get(jv_copy(row), 1);
        jv_free(row);
        spx_jq_binary_sample(left, right, (unsigned)i, 1, 0);
    }
    jv_free(rows);
}

/* Arguments after the checker-supplied side:
 * LEFT_JSON RIGHT_JSON retained|aliased|unique|unique-address
 * PAIRS_JSON null batch                 pairs: [left,right,optional-alias-bool]
 * FILTER INPUT_JSON program            one collected interpreter result
 * Raw malformed byte fixtures, nonlocal failure and other call shapes use an
 * operator-specific driver. JSON parsing is deliberately not a raw heap loader. */
static int spx_jq_binary_main(int argc, char **argv, const struct spx_jq_binary_driver *driver) {
    if (argc != 5 || (strcmp(argv[1], "original") && strcmp(argv[1], "source"))) return 2;
    const char *mode = argv[4];
    int unique = !strcmp(mode, "unique") || !strcmp(mode, "unique-address");
    if (strcmp(mode, "retained") && strcmp(mode, "aliased") && !unique && strcmp(mode, "batch") && strcmp(mode, "program")) return 2;
    fputc('{', stdout);
    if (driver->case_fields) {
        int status = driver->case_fields(argv[2], argv[3], mode);
        if (status) return status;
    }
    spx_jq_binary_active = driver;
    int selected = !strcmp(argv[1], "source");
    if (selected && !spx_install_component_entry((void(*)(void))spx_jq_binary_counted)) return 85;
    if (!strcmp(mode, "program")) {
        jq_state *jq = jq_init();
        if (!jq || !jq_compile(jq, argv[2])) return 84;
        allocation_observer_begin();
        jq_start(jq, jv_parse(argv[3]), 0);
        jv result = jq_next(jq), more = jq_next(jq);
        if (!jv_is_valid(result) || jv_is_valid(more)) return 84;
        jv_free(more); allocation_observer_pause(1);
        fputs("\"samples\":[{\"result\":", stdout); spx_jq_binary_emit(jv_copy(result));
        fputs(",\"left_after\":null,\"right_after\":null,\"references\":null}", stdout);
        allocation_observer_pause(0);
        jv_free(result); jq_teardown(&jq);
    } else {
        allocation_observer_begin(); fputs("\"samples\":[", stdout);
        if (!strcmp(mode, "batch")) spx_jq_binary_batch(argv[2]);
        else {
            jv left = jv_parse(argv[2]);
            jv right = !strcmp(mode, "aliased") ? jv_copy(left) : jv_parse(argv[3]);
            spx_jq_binary_sample(left, right, 0, !unique, !strcmp(mode, "unique-address"));
        }
    }
    fputs("],\"allocation_lifetime\":", stdout); allocation_observer_finish(stdout); fputs("}\n", stdout);
    fprintf(stderr, "authored-%s-calls=%u\n", driver->name, spx_jq_binary_calls);
    return selected && !spx_jq_binary_calls ? 85 : 0;
}
#endif
