/* Real live values and native callers; ordinary C adapters are reused unchanged. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "string-native.h"
#include "jq.h"
#include "allocation-observer.h"
#include "native-entry.h"
extern int32_t fixture_string_length(jv);
static unsigned calls;
static int32_t counted_length(jv value) { ++calls;return fixture_string_length(value); }

static void install(void) {
    if (!spx_install_component_entry((void(*)(void))counted_length)) exit(85);
}
static uint32_t random_word(uint32_t *seed) {
    uint32_t x=*seed;x^=x<<13;x^=x>>17;x^=x<<5;*seed=x;return x;
}
static void sample(const unsigned char *bytes,unsigned length,int shared,unsigned number) {
    char placeholder[128];if(length>sizeof(placeholder)) exit(84);
    memset(placeholder,'x',length);
    jv value=jv_string_sized(placeholder,(int)length);
    memcpy((char *)jv_string_value(value),bytes,length);
    jv kept=shared?jv_copy(value):jv_null();
    int result=jv_string_length_codepoints(value);
    printf("%s{\"count\":%d,\"shared\":%s,\"references\":%d,\"bytes\":\"",
        number?",":"",result,shared?"true":"false",jv_get_refcnt(kept));
    const unsigned char *after=shared?(const unsigned char *)jv_string_value(kept):bytes;
    for (unsigned i=0;i<length;++i) printf("%02x",after[i]);
    printf("\"}");jv_free(kept);
}
static void corpus(int shared) {
    static const unsigned char values[][12]={{0},{'a',0,'b'},{0xc3,0xa9},
        {'a',0xe2,0x82,0xac,0xf0,0x9f,0x98,0x80,'z'}, {0xe2,'x'}, {0xe2,'x','y'},
        {0x80,0x80}, {0xc0,0xaf}, {0xed,0xa0,0x80}, {0xf4,0x90,0x80,0x80},
        {0xf0,0x90,0x80}, {0xf8,0x88,0x80,0x80,0x80}};
    static const unsigned sizes[]={0,3,2,9,2,3,2,2,3,4,3,5};
    unsigned n=0;
    for (unsigned i=0;i<sizeof(sizes)/sizeof(*sizes);++i)
        for (unsigned len=0;len<=sizes[i];++len) sample(values[i],len,shared,n++);
    for (unsigned i=0;i<256;++i) { unsigned char byte=(unsigned char)i;sample(&byte,1,shared,n++); }
}
static void generated(uint32_t seed) {
    for (unsigned n=0;n<256;++n) {
        unsigned char bytes[128];unsigned length=random_word(&seed)%sizeof(bytes);
        for (unsigned i=0;i<length;++i) bytes[i]=(unsigned char)random_word(&seed);
        sample(bytes,length,(int)(n%2),n);
    }
}
int main(int argc,char **argv) {
    if(argc!=3 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
    int selected=!strcmp(argv[1],"source");
    if(selected) install();
    allocation_observer_begin();fputs("{\"sequences\":[",stdout);
    if (!strcmp(argv[2],"program")) {
        jq_state *jq=jq_init();
        if(!jq || !jq_compile(jq,"map([length,.[0:1],.[1:]])")) return 84;
        jq_start(jq,jv_parse("[\"a\\u20ac\\ud83d\\ude00z\",\"\\u0000x\",\"\",\"\\u00e9\",\"ascii\"]"),0);
        jv result=jq_next(jq);if(!jv_is_valid(result)) return 84;
        jv more=jq_next(jq);if(jv_is_valid(more)) return 84;jv_free(more);
        allocation_observer_pause(1);
        jv text=jv_dump_string(result,JV_PRINT_SORTED);
        printf("],\"program\":%s,\"allocation_lifetime\":",jv_string_value(text));
        jv_free(text);allocation_observer_pause(0);jq_teardown(&jq);
    } else {
        if(!strcmp(argv[2],"unique") || !strcmp(argv[2],"retained")) corpus(!strcmp(argv[2],"retained"));
        else if(!strncmp(argv[2],"generated:",10)) generated((uint32_t)strtoul(argv[2]+10,NULL,10));
        else return 2;
        fputs("],\"program\":null,\"allocation_lifetime\":",stdout);
    }
    allocation_observer_finish(stdout);fputs("}\n",stdout);
    fprintf(stderr,"authored-string-length-calls=%u\n",calls);
    return selected && !calls ? 85 : 0;
}
