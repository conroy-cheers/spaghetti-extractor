/* Native ABI and observed callers belong to the fixture, not the portable C. */
#include <stdio.h>
#include <inttypes.h>
#include <setjmp.h>
#include <windows.h>
#include "object-storage-native.h"
#include "jq.h"
#include "allocation-observer.h"
#include "comparison-selection.h"
#include "comparison-services.h"
#include "create-entry.h"
#include "release-entry.h"
#include "unshare-entry.h"

static unsigned calls[3];
static int selected;
#ifdef SPX_SELECTED_OBJECT_CREATE
static jv *__attribute__((regparm(2))) replaced_create(jv *output, uint32_t capacity) {
    jq_object_cell result; ++calls[0]; fixture_object_create(capacity, &result);
    *output = object_unpack(result); return output;
}
#endif
#ifdef SPX_SELECTED_OBJECT_RELEASE
static void replaced_release(jv value) {
    jq_object_cell input = object_pack(value); ++calls[1]; fixture_object_release(&input);
}
#endif
#ifdef SPX_SELECTED_OBJECT_UNSHARE
static jv *__attribute__((regparm(1))) replaced_unshare(jv *output, jv value) {
    jq_object_cell input = object_pack(value); ++calls[2];
    /* Deliberately exercise an aliased input/output holder. */
    fixture_object_unshare(&input, &input); *output = object_unpack(input); return output;
}
#endif
static jv native_unshare(jv value) {
    typedef jv *(__attribute__((regparm(1))) *function)(jv *, jv);
    jv output; ((function)((unsigned char *)GetModuleHandleA("libjq-1.dll") + 0x2a7e3))(&output, value);
    return output;
}
static jv native_create(uint32_t capacity) {
    typedef jv *(__attribute__((regparm(2))) *function)(jv *, uint32_t);
    jv output; ((function)((unsigned char *)GetModuleHandleA("libjq-1.dll") + 0x25f23))(&output, capacity);
    return output;
}
static void emit(jv value) {
    jv text = jv_dump_string(value, JV_PRINT_SORTED);
    fputs(jv_string_value(text), stdout); jv_free(text);
}
static void sequence(int shared) {
    allocation_observer_begin();
    jv value = native_create(8);
    for (int i = 0; i < 8; ++i)
        value = jv_object_set(value, jv_string_fmt("key%d", i), jv_parse("{\"nested\":[1,2]}"));
    value = jv_object_delete(value, jv_string("key3"));
    jv alias = shared ? jv_copy(value) : jv_null();
    uintptr_t before = (uintptr_t)value.u.ptr;
    value = native_unshare(value);
    int same = before == (uintptr_t)value.u.ptr;
    /* Fill beyond next-free to exercise the existing rehash consumer of create. */
    value = jv_object_set(value, jv_string("added"), jv_parse("[7,{\"child\":9}]"));
    allocation_observer_pause(1);
    printf("\"sample\":{\"unshare_kept_allocation\":%s,\"result\":", same ? "true" : "false");
    emit(jv_copy(value)); fputs(",\"alias\":", stdout); emit(jv_copy(alias));
    printf(",\"references\":[%d,%d],\"capacity\":%d}", jv_get_refcnt(value), jv_get_refcnt(alias), value.size);
    allocation_observer_pause(0); jv_free(value); jv_free(alias);
}
static jmp_buf landing;
static jv failure_input, failure_alias;
static unsigned failure_callbacks;
static void exhausted(void *context) {
    if (context != &failure_callbacks) abort();
    ++failure_callbacks; longjmp(landing, 1);
}
static void allocation_failure(int create) {
    allocation_observer_begin(); failure_input = jv_parse("{\"keep\":{\"child\":[1,2]}}");
    failure_alias = jv_copy(failure_input); jv_nomem_handler(exhausted, &failure_callbacks);
#if SPX_COMPARISON_NONLOCAL
    uint32_t handler = selected ? spx_service_handler_begin() : 0;
#endif
    if (!setjmp(landing)) {
        allocation_observer_fail_next_malloc();
        if (create) failure_input = native_create(8);
        else failure_input = native_unshare(failure_input);
        abort();
    }
#if SPX_COMPARISON_NONLOCAL
    if (selected) { spx_service_handler_catch(handler, "nomem"); spx_service_handler_end(handler); }
#endif
    allocation_observer_pause(1);
    printf("\"sample\":{\"outcome\":\"nomem\",\"callbacks\":%u,\"failed_allocations\":%" PRIu64
           ",\"requested_bytes\":%zu,\"alias\":", failure_callbacks,
           allocation_observer_failures(), allocation_observer_failed_size());
    emit(jv_copy(failure_alias)); printf(",\"references\":%d}", jv_get_refcnt(failure_alias));
    allocation_observer_pause(0); jv_free(failure_input); jv_free(failure_alias);
}
static void program(void) {
    jq_state *state = jq_init();
    const char *filter = ". as $old | .key0.nested[0]=99 | del(.key3) | .added={x:[4,5]} | [.,$old]";
    if (!state || !jq_compile(state, filter)) abort();
    allocation_observer_begin();
    jq_start(state, jv_parse("{\"key0\":{\"nested\":[1,2]},\"key3\":{\"child\":3}}"), 0);
    jv value = jq_next(state), end = jq_next(state);
    if (!jv_is_valid(value) || jv_is_valid(end)) abort();
    jv_free(end); allocation_observer_pause(1);
    fputs("\"sample\":", stdout); emit(jv_copy(value));
    allocation_observer_pause(0); jv_free(value); jq_teardown(&state);
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "original") && strcmp(argv[1], "source"))) return 2;
    selected = !strcmp(argv[1], "source");
    if (selected) {
#ifdef SPX_SELECTED_OBJECT_CREATE
        if (!install_object_create((void (*)(void))replaced_create)) return 85;
#endif
#ifdef SPX_SELECTED_OBJECT_RELEASE
        if (!install_object_release((void (*)(void))replaced_release)) return 85;
#endif
#ifdef SPX_SELECTED_OBJECT_UNSHARE
        if (!install_object_unshare((void (*)(void))replaced_unshare)) return 85;
#endif
    }
    fputc('{', stdout);
    if (!strcmp(argv[2], "shared")) sequence(1);
    else if (!strcmp(argv[2], "unique")) sequence(0);
    else if (!strcmp(argv[2], "program")) program();
    else if (!strcmp(argv[2], "nomem-create")) allocation_failure(1);
    else if (!strcmp(argv[2], "nomem-unshare")) allocation_failure(0);
    else return 2;
    fputs(",\"allocation_lifetime\":", stdout); allocation_observer_finish(stdout); puts("}");
    fprintf(stderr, "authored-object-calls create=%u release=%u unshare=%u\n", calls[0], calls[1], calls[2]);
    return selected && !(calls[0] + calls[1] + calls[2]) ? 85 : 0;
}
