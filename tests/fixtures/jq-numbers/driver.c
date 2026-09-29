#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jq.h"
#include "entries.h"
#include "native-entry.h"
#include "allocation-observer.h"

static unsigned calls;
void spx_observe_number_entry(const char *name) { (void)name; ++calls; }

static LONG WINAPI report_exception(EXCEPTION_POINTERS *error) {
    fprintf(stderr,"native-fault code=%08lx ip=%08lx image=%p\n",
        (unsigned long)error->ExceptionRecord->ExceptionCode,
        (unsigned long)error->ContextRecord->Eip, (void *)GetModuleHandleA("libjq-1.dll"));
    fflush(stderr); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}

/* Formatting allocations are outside observations; value reads and cache
 * creation in snapshot() remain observed. */
static void emit(jv value) {
    allocation_observer_pause(1);
    if (!jv_is_valid(value)) value=jv_invalid_get_msg(value);
    if (!jv_is_valid(value)) { jv_free(value); value=jv_null(); }
    jv text=jv_dump_string(value,JV_PRINT_SORTED);
    /* Decimal text can exceed the host JSON parser's finite double range.
     * Observe exact jq output bytes rather than round them through that parser. */
    putchar('"');
    const unsigned char *bytes=(const unsigned char *)jv_string_value(text);
    int length=jv_string_length_bytes(jv_copy(text));
    for(int i=0;i<length;++i)printf("%02x",bytes[i]);
    putchar('"');jv_free(text);
    allocation_observer_pause(0);
}
static void emit_text(const char *text) {
    allocation_observer_pause(1);
    jv value=text?jv_string(text):jv_null();
    emit(value);
}
static void snapshot(jv number) {
    printf("{\"kind\":%d,\"integer\":%d", jv_get_kind(number),jv_is_integer(number));
    if (jv_get_kind(number)==JV_KIND_NUMBER) {
        const char *text=jv_number_get_literal(number), *again=jv_number_get_literal(number);
        double value=jv_number_value(number); uint64_t bits; memcpy(&bits,&value,sizeof(bits));
        printf(",\"flags\":%u,\"literal\":",number.kind_flags);emit_text(text);
        printf(",\"stable_cache\":%s,\"has_literal\":%d,\"nan\":%d,\"bits\":\"%016" PRIx64 "\"",
            text==again?"true":"false",jv_number_has_literal(number),jvp_number_is_nan(number),bits);
        value=jv_number_value(number);memcpy(&bits,&value,sizeof(bits));
        printf(",\"repeat_bits\":\"%016" PRIx64 "\",\"references\":%d",bits,jv_get_refcnt(number));
    }
    putchar('}');
}
static void release(jv value) {
    if (jv_get_kind(value)==JV_KIND_NUMBER) jvp_number_free(value);
    else jv_free(value);
}
static void direct_case(const char *kind,const char *a,const char *b) {
    jv first;
    if (!strcmp(kind,"binary")) {
        uint64_t bits=strtoull(a,NULL,16);double value;memcpy(&value,&bits,sizeof(value));
        first=jv_number(value);
    } else first=jv_number_with_literal(a);
    jv second=jv_number_with_literal(b),alias=jv_copy(first);
    fputs("{\"before\":",stdout);snapshot(first);
    if (jv_get_kind(first)==JV_KIND_NUMBER) {
        jv absolute=jv_number_abs(first),negative=jv_number_negate(first);
        fputs(",\"absolute\":",stdout);snapshot(absolute);
        fputs(",\"negative\":",stdout);snapshot(negative);
        if(jv_get_kind(second)==JV_KIND_NUMBER)
            printf(",\"comparison\":%d",jvp_number_cmp(first,second));
        release(absolute);release(negative);
    }
    release(first);
    fputs(",\"retained_alias\":",stdout);snapshot(alias);
    release(alias);release(second);putchar('}');
}
static void consumer_case(const char *program,const char *text) {
    jq_state *states[2]={jq_init(),jq_init()};
    jv input=jv_parse(text);putchar('[');
    for (int i=0;i<2;++i) {
        if(!states[i])exit(84);
        int compiled=jq_compile(states[i],program);
        printf("%s{\"compiled\":%d,\"values\":[",i?",":"",compiled);
        if(compiled) {
            jq_start(states[i],jv_copy(input),0);
            unsigned count=0;
            for (;;) {
                jv value=jq_next(states[i]);
                if(!jv_is_valid(value)) { fputs("],\"error\":",stdout);emit(value);break; }
                if(count++)putchar(',');
                emit(value);
                if(count>100)exit(82);
            }
        } else fputs("],\"error\":null",stdout);
        fputs(",\"retained_input\":",stdout);emit(jv_copy(input));putchar('}');
    }
    jq_teardown(&states[1]);jq_teardown(&states[0]);jv_free(input);putchar(']');
}
int main(int argc,char **argv) {
    if(argc!=5)return 2;
    SetUnhandledExceptionFilter(report_exception);
    int source=!strcmp(argv[1],"source");
    if(source&&!install_entries())return 85;
    allocation_observer_begin();
    fputs("{\"result\":",stdout);
    if(!strcmp(argv[2],"consumer"))consumer_case(argv[3],argv[4]);
    else direct_case(argv[2],argv[3],argv[4]);
    fputs(",\"allocation_lifetime\":",stdout);allocation_observer_finish(stdout);puts("}");
    fprintf(stderr,"authored-number-values-calls=%u\n",calls);
    return source&&(!calls||!entries_intact())?85:0;
}
