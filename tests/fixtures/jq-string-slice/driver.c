/* Native storage, aliases and real guarded-allocation failure; no heap simulation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <inttypes.h>
#include <limits.h>
#include "string-native.h"
#include "allocation-observer.h"
#include "comparison-services.h"

static jmp_buf landing;
static jv input_value, kept, output_value;
static unsigned callbacks, marker=0x5a17U;
static int context_matches;
static void exhausted(void *context) {
    ++callbacks; context_matches=context==&marker && marker==0x5a17U; longjmp(landing,1);
}
static jv raw_string(const unsigned char *data, unsigned size) {
    char placeholder[512];
    if (size>sizeof(placeholder)) exit(84);
    memset(placeholder,'x',size);
    jv value=jv_string_sized(placeholder,(int)size);
    /* The buffer is freshly allocated and uniquely owned. Preserve its real
     * length/capacity while constructing malformed UTF-8 states as well. */
    memcpy((char *)jv_string_value(value),data,size);
    return value;
}
static void hex(jv value) {
    int size=jv_string_length_bytes(jv_copy(value));
    const unsigned char *data=(const unsigned char *)jv_string_value(value);
    putchar('"');for (int i=0;i<size;++i) printf("%02x",data[i]);putchar('"');
}
static void observe(int number, int start, int end) {
    allocation_observer_pause(1);
    printf("%s{\"start\":%d,\"end\":%d,\"kind\":%d,\"result\":",number?",":"",start,end,jv_get_kind(output_value));
    if (jv_get_kind(output_value)==JV_KIND_STRING) hex(output_value);
    else if (!jv_is_valid(output_value)) {
        jv message=jv_invalid_get_msg(jv_copy(output_value));hex(message);jv_free(message);
    } else printf("null");
    printf(",\"retained\":");
    if (jv_get_kind(kept)==JV_KIND_STRING) hex(kept);else printf("null");
    printf(",\"references\":%d,\"output_references\":%d,\"aliases_output\":%s}",
        jv_get_refcnt(kept),jv_get_refcnt(output_value),
        jv_get_kind(output_value)==JV_KIND_STRING && kept.u.ptr==output_value.u.ptr?"true":"false");
    allocation_observer_pause(0);
}
static uint32_t random_word(uint32_t *seed) {
    uint32_t value=*seed;value^=value<<13;value^=value>>17;value^=value<<5;*seed=value;return value;
}
static void sample(const unsigned char *bytes,unsigned length,int start,int end,int shared,int number) {
    input_value=raw_string(bytes,length);kept=shared?jv_copy(input_value):jv_null();
    output_value=jv_string_slice(input_value,start,end);
    observe(number,start,end);jv_free(kept);jv_free(output_value);
}
static void corpus(int shared) {
    static const unsigned char texts[][16]={
        {'a','b','c','d'}, {0xc3,0xa9}, {'a',0xe2,0x82,0xac,0xf0,0x9f,0x98,0x80,'z'},
        {'a',0,'b'}, {0x80,'x'}, {0xc0,0xaf}, {0xed,0xa0,0x80}, {0xf4,0x90,0x80,0x80},
        {0xe2,0x82}, {'a',0xff,'b'}, {0xf8,0x88,0x80,0x80,0x80}, {0xf0,0x90,0x80,0x80}, {0}};
    static const unsigned lengths[]={4,2,9,3,2,2,3,4,2,3,5,4,0};
    static const int indices[][2]={{0,0},{0,1},{0,INT_MAX},{1,2},{2,2},{2,4},{-2,-1},
        {INT_MIN,INT_MAX},{INT_MAX,INT_MIN},{1,-1},{-1,INT_MAX},{3,1}};
    int number=0;
    for (unsigned i=0;i<sizeof(lengths)/sizeof(*lengths);++i)
        for (unsigned j=0;j<sizeof(indices)/sizeof(*indices);++j)
            sample(texts[i],lengths[i],indices[j][0],indices[j][1],shared,number++);
}
static void generated(uint32_t seed) {
    static const unsigned char symbols[][4]={{'a'}, {0}, {0xc2,0xa2}, {0xe2,0x82,0xac},
        {0xf0,0x9f,0x98,0x80}, {0xff}, {0xed,0xa0,0x80}};
    static const unsigned sizes[]={1,1,2,3,4,1,3};
    for (int n=0;n<64;++n) {
        unsigned char bytes[128];unsigned length=0,count=random_word(&seed)%20U;
        for (unsigned i=0;i<count;++i) {
            unsigned kind=random_word(&seed)%7U;memcpy(bytes+length,symbols[kind],sizes[kind]);length+=sizes[kind];
        }
        int start=(int)(random_word(&seed)%80U)-40,end=(int)(random_word(&seed)%80U)-40;
        sample(bytes,length,start,end,n%2,n);
    }
}
int main(int argc,char **argv) {
    if (argc!=3 || (strcmp(argv[1],"source") && strcmp(argv[1],"original"))) return 2;
    int selected=!strcmp(argv[1],"source");
    if (selected) string_slice_install();
    allocation_observer_begin();
    printf("{\"sequences\":[");
    if (!strncmp(argv[2],"nomem-",6)) {
        int empty=!strcmp(argv[2],"nomem-empty"),invalid=!strcmp(argv[2],"nomem-invalid");
        static const unsigned char text[]={0xc3,0xa9},bad[]={0xff,'x'};
        input_value=raw_string(invalid?bad:text,2);kept=jv_copy(input_value);output_value=jv_number(12345);
        jv_nomem_handler(exhausted,&marker);
        uint32_t handler=selected?spx_service_handler_begin():0;
        if (!setjmp(landing)) {
            allocation_observer_fail_next_malloc();
            output_value=jv_string_slice(input_value,empty?2:0,empty?2:1);
            fputs("string boundary: expected native allocation failure\n",stderr);return 86;
        }
        if (selected) { spx_service_handler_catch(handler,"nomem");spx_service_handler_end(handler); }
        observe(0,empty?2:0,empty?2:1);jv_free(kept);jv_free(output_value);
    } else if (!strcmp(argv[2],"retained") || !strcmp(argv[2],"unique")) corpus(!strcmp(argv[2],"retained"));
    else if (!strncmp(argv[2],"generated:",10)) generated((uint32_t)strtoul(argv[2]+10,NULL,10));
    else return 2;
    printf("],\"allocation_failure\":{\"callbacks\":%u,\"context_preserved\":%s,\"failures\":%" PRIu64
        ",\"requested_bytes\":%zu},\"allocation_lifetime\":",callbacks,context_matches?"true":"false",
        allocation_observer_failures(),allocation_observer_failed_size());
    allocation_observer_finish(stdout);printf("}\n");
    if (selected && !string_slice_calls) return 85;
    string_slice_report();return 0;
}
