/* Diagnostic consumer of the existing jq API, separate from program entry.
 * Observe live contents, pointer aliases and references across representation
 * transport. Addresses themselves are not compared across processes. */
#include <stdio.h>
#include "jv.h"
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
static void print_value(jv value) {
    jv text=jv_dump_string(jv_copy(value),JV_PRINT_SORTED);
    if (!jv_is_valid(text)) { fputs("serialization failed\n",stderr); return; }
    fputs(jv_string_value(text),stdout);
    jv_free(text);
}
int main(void) {
#ifdef _WIN32
    _setmode(_fileno(stdout),_O_BINARY);
    _setmode(_fileno(stderr),_O_BINARY);
#endif
    for (int i=0;i<32;++i) {
        jv root=jv_parse("[{\"a\":[1,2]},[3,4],\"caf\u00e9\u4e2d\U0001f642\"]");
        jv retained=jv_copy(root);
        jv view=jv_array_slice(jv_copy(root),1,3);
        printf("{\"case\":%d,\"before_refs\":%d,\"shared_view\":%d,",i,
            jv_get_refcnt(retained),view.u.ptr==retained.u.ptr);
        jv changed=jv_setpath(root,jv_parse("[0,\"a\",1]"),jv_number(100+i));
        jv child=jv_getpath(jv_copy(changed),jv_parse("[0,\"a\"]"));
        printf("\"after_refs\":[%d,%d,%d],\"copy_on_write\":%d,\"child_refs\":%d,\"old\":",
            jv_get_refcnt(retained),jv_get_refcnt(view),jv_get_refcnt(changed),
            retained.u.ptr!=changed.u.ptr,jv_get_refcnt(child));
        print_value(retained);fputs(",\"changed\":",stdout);print_value(changed);
        fputs(",\"view\":",stdout);print_value(view);fputs(",\"child\":",stdout);print_value(child);
        jv_free(child);jv_free(view);
        printf(",\"retained_after_view_release\":%d",jv_get_refcnt(retained));
        jv text=jv_get(jv_copy(retained),jv_number(2));
        jv alias=jv_copy(text);
        jv sliced=jv_string_slice(text,i%6-2,i%8);
        printf(",\"string_refs\":%d,\"string_alias\":%d,\"string_original\":",
            jv_get_refcnt(alias),sliced.u.ptr==alias.u.ptr);
        print_value(alias);fputs(",\"string_slice\":",stdout);print_value(sliced);
        jv_free(sliced);jv_free(alias);jv_free(changed);
        printf(",\"before_final_release\":%d}\n",jv_get_refcnt(retained));
        jv_free(retained);
    }
    return 0;
}
