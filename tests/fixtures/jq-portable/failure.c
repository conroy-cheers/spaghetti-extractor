/* Diagnostic consumer: real allocation guard, registered callback and longjmp.
 * All values observed after a jump have static storage; no indeterminate locals. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <inttypes.h>
#include "jq.h"
#include "jv_dtoa.h"
#include "allocation-observer.h"
#ifdef SPX_COMPONENT_COMPARISON
#include "string-native.h"
#include "comparison-services.h"
static int component_selected;
#endif
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include "pe32-entry-hook.h"
static spx_fixture_entry_hook hook;
static spx_fixture_entry_hook dtoa_hook;
static void (*original_dtoa_init)(struct dtoa_context *);
static const unsigned char dtoa_prefix[5]={0x56,0x53,0x8b,0x4c,0x24};
#else
extern jv __real_jv_string_slice(jv,int,int);
extern void __real_jvp_dtoa_context_init(struct dtoa_context *);
#endif

static jmp_buf landing;
static jv input_value,kept,item,item_kept,output_value;
static jq_state *interpreter;
static unsigned marker=0x5a17U,callbacks,entries;
static int context_matches,program_mode,program_armed;
static int observe_dtoa;
static struct dtoa_context *observed_dtoa;
static uint64_t dtoa_generation;
static unsigned dtoa_creations;
static size_t dtoa_bytes;
#ifdef _WIN32
static void observed_dtoa_init(struct dtoa_context *context) {
    if (!spx_fixture_restore_entry(&dtoa_hook)) exit(85);
    original_dtoa_init(context);
#else
void __wrap_jvp_dtoa_context_init(struct dtoa_context *context) {
    __real_jvp_dtoa_context_init(context);
#endif
    uint64_t current=allocation_observer_generation(context);
    if (observe_dtoa && current) {
        observed_dtoa=context;
        dtoa_generation=current;
        ++dtoa_creations;
    }
#ifdef _WIN32
    /* The same initializer also handles parser-local stack objects. Continue
     * observing until the actual recorded heap context is initialized. */
    if (!dtoa_generation && !spx_fixture_redirect_address_body(&dtoa_hook,dtoa_hook.entry,
            dtoa_prefix,5,(void(*)(void))observed_dtoa_init)) exit(85);
#endif
}

static void print_dtoa_context(void) {
    size_t size=0;
    if (!observe_dtoa) return;
    if (dtoa_creations!=1 || !allocation_observer_live_allocation(observed_dtoa,dtoa_generation,&size)
            || size!=sizeof(*observed_dtoa)) {
        fprintf(stderr,"numeric context is not the captured live allocation: creations=%u generation=%" PRIu64
            " size=%zu expected=%zu\n",dtoa_creations,dtoa_generation,size,sizeof(*observed_dtoa));exit(85);
    }
    /* This reviewed relation covers the empty pointer slots. A populated cache
     * needs its contents and aliases described; it cannot pass on size alone. */
    for (unsigned i=0;i<sizeof(observed_dtoa->freelist)/sizeof(observed_dtoa->freelist[0]);++i)
        if (observed_dtoa->freelist[i]) { fputs("numeric context has a populated freelist\n",stderr);exit(85); }
    if (observed_dtoa->p5s) { fputs("numeric context has a populated powers cache\n",stderr);exit(85); }
    dtoa_bytes=size;
    printf(",\"dtoa_context\":{\"created\":%u,\"live\":true,\"null_pointer_slots\":9}",dtoa_creations);
}
static void exhausted(void *context) {
    ++callbacks;context_matches=context==&marker && marker==0x5a17U;
    longjmp(landing,1);
}
static void print_value(jv value) {
    if (jv_get_kind(value)==JV_KIND_STRING) {
        int n=jv_string_length_bytes(jv_copy(value));
        const unsigned char *bytes=(const unsigned char *)jv_string_value(value);
        putchar('"');for (int i=0;i<n;++i) printf("%02x",bytes[i]);putchar('"');
    } else {
        jv text=jv_dump_string(jv_copy(value),JV_PRINT_SORTED);
        if (!jv_is_valid(text)) exit(87);
        fputs(jv_string_value(text),stdout);jv_free(text);
    }
}
static jv reached_string(jv value,int start,int end) {
    if (++entries!=1) exit(85);
    program_armed=0;
    kept=jv_copy(value);
#ifdef _WIN32
    if (!spx_fixture_restore_entry(&hook)) exit(85);
#endif
#ifdef SPX_COMPONENT_COMPARISON
    if (component_selected) string_slice_install();
#endif
    allocation_observer_fail_next_malloc();
#ifdef _WIN32
    return jv_string_slice(value,start,end);
#else
    return __real_jv_string_slice(value,start,end);
#endif
}
#ifndef _WIN32
jv __wrap_jv_string_slice(jv value,int start,int end) {
    return program_armed ? reached_string(value,start,end) : __real_jv_string_slice(value,start,end);
}
#endif
int main(int argc,char **argv) {
#ifdef SPX_COMPONENT_COMPARISON
    if (argc!=3 || (strcmp(argv[1],"source") && strcmp(argv[1],"original"))) return 2;
    component_selected=!strcmp(argv[1],"source");
    --argc;++argv;
#endif
    if (argc!=2) return 2;
#ifdef _WIN32
    _setmode(_fileno(stdout),_O_BINARY);_setmode(_fileno(stderr),_O_BINARY);
#endif
    /* Handler registration may allocate ABI-sized TLS data. Establish it before
     * observing the component, on both sides; it is still the real jq handler. */
    jv_nomem_handler(exhausted,&marker);
    kept=item=item_kept=input_value=jv_null();output_value=jv_number(12345);
    program_mode=!strcmp(argv[1],"program-string") || !strcmp(argv[1],"program-string-cold");
    observe_dtoa=!strcmp(argv[1],"program-string-cold");
    if (program_mode) {
        /* Numeric conversion owns a per-thread context of nine host pointers.
         * Establish that dependency before measuring component residuals. The
         * explicit cold probe retains its 36/72-byte representation difference. */
        if (strcmp(argv[1],"program-string-cold")) {
            jv number=jv_parse("0");(void)jv_number_value(number);jv_free(number);
        }
        interpreter=jq_init();
        if (!interpreter || !jq_compile(interpreter,".text[1:3]")) return 5;
        jq_set_nomem_handler(interpreter,exhausted,&marker);
#ifdef _WIN32
        const unsigned char prefix[5]={0x55,0x57,0x56,0x53,0x81};
        if (!spx_fixture_redirect_body(&hook,"libjq-1.dll","jv_string_slice",prefix,
            0x33b,(void(*)(void))reached_string)) return 85;
        if (observe_dtoa) {
            /* Pinned libjq jvp_dtoa_context_init, RVA 0x36f83. This observer
             * restores the original entry and executes it before recording. */
            unsigned char *entry=(unsigned char *)GetModuleHandleA("libjq-1.dll")+0x36f83;
            original_dtoa_init=(void (*)(struct dtoa_context *))(void *)entry;
            if (!spx_fixture_redirect_address_body(&dtoa_hook,entry,dtoa_prefix,5,
                    (void(*)(void))observed_dtoa_init)) {
                fprintf(stderr,"numeric context entry hook rejected prefix %02x %02x %02x %02x %02x\n",
                    entry[0],entry[1],entry[2],entry[3],entry[4]);return 85;
            }
        }
#endif
    }
#ifdef SPX_COMPONENT_COMPARISON
    if (component_selected && !program_mode) string_slice_install();
#endif
    allocation_observer_begin();
    if (!program_mode && !strncmp(argv[1],"string-",7)) {
        input_value=jv_string_sized("\xc3\xa9",2);
        if (!strcmp(argv[1],"string-invalid")) memcpy((char *)jv_string_value(input_value),"\xffx",2);
        kept=jv_copy(input_value);
    } else if (!strcmp(argv[1],"array-set") || !strcmp(argv[1],"array-grow")) {
        input_value=jv_array_sized(3);
        input_value=jv_array_append(input_value,jv_string("kept"));
        input_value=jv_array_append(input_value,jv_number(1));
        input_value=jv_array_append(input_value,jv_number(2));
        kept=jv_copy(input_value);item=jv_string("new");item_kept=jv_copy(item);
    } else if (!program_mode && strcmp(argv[1],"array-create")) return 2;
#ifdef SPX_COMPONENT_COMPARISON
    uint32_t handler=component_selected?spx_service_handler_begin():0;
#endif
    if (!setjmp(landing)) {
        if (program_mode) {
            program_armed=1;
            jq_start(interpreter,jv_parse("{\"text\":\"a\\u20ac\\ud83d\\ude00z\"}"),0);
            output_value=jq_next(interpreter);
        } else {
            allocation_observer_fail_next_malloc();
            if (!strcmp(argv[1],"array-create")) output_value=jv_array_sized(3);
            else if (!strncmp(argv[1],"array-",6))
                output_value=jv_array_set(input_value,!strcmp(argv[1],"array-grow")?64:1,item);
            else {
                int empty=!strcmp(argv[1],"string-empty");
                output_value=jv_string_slice(input_value,empty?2:0,empty?2:1);
            }
        }
        fputs("selected allocation did not deliver the real nomem callback\n",stderr);return 86;
    }
#ifdef SPX_COMPONENT_COMPARISON
    if (component_selected) { spx_service_handler_catch(handler,"nomem");spx_service_handler_end(handler); }
#endif
    if (program_mode) jq_teardown(&interpreter);
    allocation_observer_pause(1);
    printf("{\"case\":\"%s\",\"callbacks\":%u,\"context_preserved\":%s,\"entries\":%u",
        argv[1],callbacks,context_matches?"true":"false",entries);
    print_dtoa_context();
    printf(",\"output\":");print_value(output_value);
    printf(",\"kept\":");print_value(kept);
    printf(",\"item_kept\":");print_value(item_kept);
    printf(",\"references\":[%d,%d],\"failed_size\":%zu,\"failures\":%" PRIu64
        ",\"lifetime\":",jv_get_refcnt(kept),jv_get_refcnt(item_kept),
        allocation_observer_failed_size(),allocation_observer_failures());
    allocation_observer_pause(0);
    jv_free(kept);jv_free(item_kept);jv_free(output_value);
    allocation_observer_summary physical=allocation_observer_snapshot();
    size_t current_size=0;
    if (observe_dtoa && (!allocation_observer_live_allocation(observed_dtoa,dtoa_generation,&current_size)
            || current_size!=dtoa_bytes || !physical.live_blocks || physical.live_bytes<dtoa_bytes)) return 85;
    printf("{\"live_blocks\":%" PRIu64 ",\"live_bytes\":%" PRIu64 ",\"invalid_releases\":%" PRIu64 "}",
        physical.live_blocks-(observe_dtoa?1:0),physical.live_bytes-dtoa_bytes,physical.invalid_releases);
    fputs(",\"unmapped_live_sizes\":",stdout);
    allocation_observer_remaining_sizes(stdout,observed_dtoa,dtoa_generation);
    fputs("}\n",stdout);
    fprintf(stderr,"physical-allocations={\"live_blocks\":%" PRIu64 ",\"live_bytes\":%" PRIu64
        ",\"invalid_releases\":%" PRIu64 ",\"dtoa_context_bytes\":%zu,\"live_sizes\":",
        physical.live_blocks,physical.live_bytes,physical.invalid_releases,dtoa_bytes);
    allocation_observer_live_sizes(stderr);fputs("}\n",stderr);
    allocation_observer_end();
#ifdef SPX_COMPONENT_COMPARISON
    if (component_selected && !string_slice_calls) return 85;
    string_slice_report();
#endif
    return callbacks!=1 || !context_matches || allocation_observer_failures()!=1 || (program_mode && entries!=1);
}
