#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jv.h"
#include "entries.h"
#include "allocation-observer.h"
#include "native-entry.h"

static unsigned calls;
void spx_observe_entry(void) { ++calls; }

static void emit(jv value) {
    allocation_observer_pause(1);
    printf("{\"kind\":%d,\"value\":", jv_get_kind(value));
    if (!jv_is_valid(value)) value = jv_invalid_get_msg(value);
    if (!jv_is_valid(value)) { jv_free(value); value = jv_null(); }
    jv text = jv_dump_string(value, JV_PRINT_SORTED);
    fputs(jv_string_value(text), stdout);
    jv_free(text); putchar('}');
    allocation_observer_pause(0);
}

static void inputs(const char *left, const char *right, jv *first, jv *second) {
    if (!strcmp(left, "@views")) {
        jv backing = jv_parse("[0,1,2,3,4]");
        *first = jv_array_slice(jv_copy(backing), 0, 2);
        *second = jv_array_slice(backing, 2, 4);
    } else if (!strcmp(left, "@alias")) {
        *first = jv_parse(right); *second = jv_copy(*first);
    } else if (!strcmp(left, "@zeros")) {
        *first = jv_number(0.0); *second = jv_number(-0.0);
    } else if (!strcmp(left, "@invalids")) {
        *first = jv_invalid_with_msg(jv_string("first"));
        *second = jv_invalid_with_msg(jv_string("second"));
    } else if (!strcmp(left, "@invalid-slot")) {
        *first = jv_object_set(jv_object(), jv_string("a"), jv_invalid());
        *second = !strcmp(right, "missing") ? jv_object() :
            jv_object_set(jv_object(), jv_string("a"), jv_invalid());
    } else {
        *first = jv_parse(left); *second = jv_parse(right);
        if (!jv_is_valid(*first) || !jv_is_valid(*second)) exit(82);
    }
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int source = !strcmp(argv[1], "source");
    if (source && !install_entries()) return 85;
    allocation_observer_begin();
    jv first, second, result;
    inputs(argv[3], argv[4], &first, &second);
    unsigned before = calls;
    if (!strcmp(argv[2], "equal")) result = jv_number(jv_equal(jv_copy(first), jv_copy(second)));
    else if (!strcmp(argv[2], "identical")) result = jv_number(jv_identical(jv_copy(first), jv_copy(second)));
    else if (!strcmp(argv[2], "contains")) result = jv_number(jv_contains(jv_copy(first), jv_copy(second)));
    else if (!strcmp(argv[2], "merge")) result = jv_object_merge(jv_copy(first), jv_copy(second));
    else if (!strcmp(argv[2], "merge_recursive")) result = jv_object_merge_recursive(jv_copy(first), jv_copy(second));
    else return 2;
    if (source && calls == before) return 85;
    fputs("{\"result\":", stdout); emit(result);
    printf(",\"shared_backing\":%d,\"reference_counts\":[%d,%d]",
        (first.kind_flags & second.kind_flags & 0x80) && first.u.ptr == second.u.ptr,
        jv_get_refcnt(first), jv_get_refcnt(second));
    /* Invalid object slots are legal low-level inputs but cannot be dumped. */
    if (!strcmp(argv[3], "@invalid-slot")) {
        fputs(",\"retained_first\":", stdout); emit(jv_number(jv_object_length(jv_copy(first))));
        fputs(",\"retained_second\":", stdout); emit(jv_number(jv_object_length(jv_copy(second))));
    } else {
        fputs(",\"retained_first\":", stdout); emit(jv_copy(first));
        fputs(",\"retained_second\":", stdout); emit(jv_copy(second));
    }
    jv_free(first); jv_free(second);
    fputs(",\"allocation_lifetime\":", stdout); allocation_observer_finish(stdout);
    puts("}");
    fprintf(stderr, "authored-value-relation-calls=%u\n", calls);
    return source && !entries_intact() ? 85 : 0;
}
