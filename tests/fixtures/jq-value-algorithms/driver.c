#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jv.h"
#include "entries.h"
#include "allocation-observer.h"
#include "native-entry.h"

static unsigned calls;
void spx_observe_entry(void) { ++calls; }

/* Diagnostic serialization is excluded from heap activity, but ownership of
 * the passed reference is still consumed normally. Retained aliases stay live. */
static void emit(jv value) {
    allocation_observer_pause(1);
    printf("{\"kind\":%d,\"value\":", jv_get_kind(value));
    if (!jv_is_valid(value)) value = jv_invalid_get_msg(value);
    if (!jv_is_valid(value)) { jv_free(value); value = jv_null(); }
    jv text = jv_dump_string(value, JV_PRINT_SORTED);
    fputs(jv_string_value(text), stdout);
    jv_free(text);
    putchar('}');
    allocation_observer_pause(0);
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int source = !strcmp(argv[1], "source");
    if (source && !install_entries()) return 85;
    allocation_observer_begin();
    jv first = jv_parse(argv[3]), second = jv_parse(argv[4]);
    if (!jv_is_valid(first) || !jv_is_valid(second)) return 82;
    jv result;
    if (!strcmp(argv[2], "compare"))
        result = jv_number(jv_cmp(jv_copy(first), jv_copy(second)));
    else if (!strcmp(argv[2], "keys")) result = jv_keys(jv_copy(first));
    else if (!strcmp(argv[2], "keys_unsorted")) result = jv_keys_unsorted(jv_copy(first));
    else if (!strcmp(argv[2], "has")) result = jv_has(jv_copy(first), jv_copy(second));
    else if (!strcmp(argv[2], "delete")) result = jv_delpaths(jv_copy(first), jv_copy(second));
    else if (!strcmp(argv[2], "sort")) result = jv_sort(jv_copy(first), jv_copy(second));
    else if (!strcmp(argv[2], "group")) result = jv_group(jv_copy(first), jv_copy(second));
    else if (!strcmp(argv[2], "unique")) result = jv_unique(jv_copy(first), jv_copy(second));
    else return 2;
    /* Check entry execution before diagnostic serialization can call keys. */
    if (source && !calls) return 85;
    fputs("{\"result\":", stdout); emit(result);
    fputs(",\"retained_first\":", stdout); emit(jv_copy(first));
    fputs(",\"retained_second\":", stdout); emit(jv_copy(second));
    jv_free(first); jv_free(second);
    fputs(",\"allocation_lifetime\":", stdout);
    allocation_observer_finish(stdout);
    puts("}");
    fprintf(stderr, "authored-value-algorithm-calls=%u\n", calls);
    return source && !entries_intact() ? 85 : 0;
}
