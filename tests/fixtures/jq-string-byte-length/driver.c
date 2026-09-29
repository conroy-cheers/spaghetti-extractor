#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "string-native.h"
#include "jq.h"
#include "allocation-observer.h"
#include "native-entry.h"

extern int32_t fixture_string_byte_length(jv);
static unsigned calls;
static int32_t counted_length(jv value) { ++calls;return fixture_string_byte_length(value); }
static void install(void) {
    if (!spx_install_component_entry((void(*)(void))counted_length)) exit(85);
}
static void sample(const unsigned char *bytes,unsigned length,int shared,int hashed,unsigned number) {
    char placeholder[32];memset(placeholder,'x',length);
    jv value=jv_string_sized(placeholder,(int)length);
    memcpy((char *)jv_string_value(value),bytes,length);
    if (hashed) (void)jv_string_hash(jv_copy(value));
    jv kept=shared?jv_copy(value):jv_null();
    int result=jv_string_length_bytes(value);
    printf("%s{\"count\":%d,\"shared\":%s,\"hashed\":%s,\"references\":%d,\"bytes\":\"",
        number?",":"",result,shared?"true":"false",hashed?"true":"false",jv_get_refcnt(kept));
    const unsigned char *after=shared?(const unsigned char *)jv_string_value(kept):bytes;
    for (unsigned i=0;i<length;++i) printf("%02x",after[i]);
    printf("\"}");jv_free(kept);
}
int main(int argc,char **argv) {
    if(argc!=3 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
    int selected=!strcmp(argv[1],"source");if(selected) install();
    allocation_observer_begin();fputs("{\"strings\":[",stdout);
    if (!strcmp(argv[2],"program")) {
        jq_state *jq=jq_init();
        if(!jq || !jq_compile(jq,"map([utf8bytelength,length,.[1:]])")) return 84;
        jq_start(jq,jv_parse("[\"a\\u20ac\\ud83d\\ude00z\",\"\\u0000x\",\"\",\"\\u00e9\",\"ascii\"]"),0);
        jv result=jq_next(jq);if(!jv_is_valid(result)) return 84;
        jv more=jq_next(jq);if(jv_is_valid(more)) return 84;jv_free(more);
        allocation_observer_pause(1);jv text=jv_dump_string(result,JV_PRINT_SORTED);
        printf("],\"program\":%s,\"allocation_lifetime\":",jv_string_value(text));
        jv_free(text);allocation_observer_pause(0);jq_teardown(&jq);
    } else {
        static const unsigned char values[][12]={{0},{'a',0,'b'},{0xc3,0xa9},
            {'a',0xe2,0x82,0xac,0xf0,0x9f,0x98,0x80,'z'},{0xe2,'x'},{0x80,0xff,0xc0,0xaf}};
        static const unsigned sizes[]={0,3,2,9,2,4};
        if(strcmp(argv[2],"unique") && strcmp(argv[2],"retained")) return 2;
        unsigned n=0;
        for (unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i)
            for (int hashed=0;hashed<2;++hashed) sample(values[i],sizes[i],!strcmp(argv[2],"retained"),hashed,n++);
        fputs("],\"program\":null,\"allocation_lifetime\":",stdout);
    }
    allocation_observer_finish(stdout);fputs("}\n",stdout);
    fprintf(stderr,"authored-string-byte-length-calls=%u\n",calls);
    return selected && !calls ? 85 : 0;
}
