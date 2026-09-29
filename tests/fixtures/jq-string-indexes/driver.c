#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string-native.h"
#include "jq.h"
#include "allocation-observer.h"
#include "native-entry.h"

extern jv fixture_string_indexes(jv, jv);
static unsigned calls;
static jv counted_indexes(jv value, jv needle) {
    ++calls;
    return fixture_string_indexes(value, needle);
}
static void install(void) {
    if (!spx_install_component_entry((void(*)(void))counted_indexes)) exit(85);
}
static jv raw_string(const unsigned char *bytes, unsigned length) {
    char placeholder[64];
    if (length>sizeof(placeholder)) exit(84);
    memset(placeholder,'x',length);
    jv value=jv_string_sized(placeholder,(int)length);
    memcpy((char *)jv_string_value(value),bytes,length);
    return value;
}
static void hex_bytes(jv value) {
    struct spx_opaque_string_bytes_v5 bytes;
    string_contents(value,&bytes);
    for (unsigned i=0;i<bytes.length;++i) printf("%02x",bytes.data[i]);
}
static void sample(const unsigned char *bytes,unsigned length,
                   const unsigned char *pattern,unsigned size,int retained,int aliased,unsigned number) {
    jv value=raw_string(bytes,length);
    jv needle=aliased?jv_copy(value):raw_string(pattern,size);
    jv keep_value=retained?jv_copy(value):jv_null();
    jv keep_needle=retained?jv_copy(needle):jv_null();
    jv result=jv_string_indexes(value,needle);
    allocation_observer_pause(1);
    jv text=jv_dump_string(result,0);
    printf("%s{\"positions\":%s,\"value_references\":%d,\"needle_references\":%d,\"value_bytes\":\"",
        number?",":"",jv_string_value(text),jv_get_refcnt(keep_value),jv_get_refcnt(keep_needle));
    if(retained) hex_bytes(keep_value);
    fputs("\",\"needle_bytes\":\"",stdout);
    if(retained) hex_bytes(keep_needle);
    fputs("\"}",stdout);jv_free(text);
    allocation_observer_pause(0);
    jv_free(keep_value);jv_free(keep_needle);
}
int main(int argc,char **argv) {
    if(argc!=3 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
    int selected=!strcmp(argv[1],"source");
    if(selected) install();
    allocation_observer_begin();fputs("{\"searches\":[",stdout);
    if(!strcmp(argv[2],"program")) {
        jq_state *jq=jq_init();
        if(!jq || !jq_compile(jq,"map(.[0] as $s | .[1] as $n | $s | indices($n))")) return 84;
        jq_start(jq,jv_parse("[[\"aaaa\",\"aa\"],[\"a\\u20aca\\u20ac\",\"\\u20ac\"],[\"a\\u0000a\",\"\\u0000\"],[\"abc\",\"\"],[\"same\",\"same\"]]"),0);
        jv result=jq_next(jq);if(!jv_is_valid(result)) return 84;
        jv more=jq_next(jq);if(jv_is_valid(more)) return 84;jv_free(more);
        allocation_observer_pause(1);
        jv text=jv_dump_string(result,0);
        printf("],\"program\":%s,\"allocation_lifetime\":",jv_string_value(text));
        jv_free(text);allocation_observer_pause(0);jq_teardown(&jq);
    } else {
        static const unsigned char values[][16]={{'a','a','a','a'}, {'a',0,'a'},
            {'a',0xe2,0x82,0xac,'a',0xe2,0x82,0xac}, {0xe2,'x','x'}, {0x80,0x80,0xff}, {'a'}, {0}};
        static const unsigned lengths[]={4,3,8,3,3,1,0};
        static const unsigned char patterns[][4]={{'a','a'},{0},{0xe2,0x82,0xac},{'x'},{0x80},{'a','a'},{0}};
        static const unsigned sizes[]={2,1,3,1,1,2,0};
        int aliased=!strcmp(argv[2],"aliased"),retained=strcmp(argv[2],"unique")!=0;
        if(strcmp(argv[2],"unique") && strcmp(argv[2],"retained") && !aliased) return 2;
        for(unsigned i=0;i<sizeof(lengths)/sizeof(*lengths);++i)
            sample(values[i],lengths[i],patterns[i],sizes[i],retained,aliased,i);
        fputs("],\"program\":null,\"allocation_lifetime\":",stdout);
    }
    allocation_observer_finish(stdout);fputs("}\n",stdout);
    fprintf(stderr,"authored-string-indexes-calls=%u\n",calls);
    return selected && !calls ? 85 : 0;
}
