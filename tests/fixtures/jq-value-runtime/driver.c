#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "jq.h"
#include "entries.h"
#include "native-entry.h"
#include "allocation-observer.h"

void spx_test_hash_seed(uint32_t);
static unsigned calls, release_calls;
void spx_observe_value_entry(const char *name) {
    ++calls;
    if (!strcmp(name,"jv_free")) ++release_calls;
}
static LONG WINAPI report_exception(EXCEPTION_POINTERS *error) {
    fprintf(stderr,"native-fault code=%08lx ip=%08lx image=%p\n",
        (unsigned long)error->ExceptionRecord->ExceptionCode,
        (unsigned long)error->ContextRecord->Eip,(void *)GetModuleHandleA("libjq-1.dll"));
    fflush(stderr);ExitProcess(86);return EXCEPTION_EXECUTE_HANDLER;
}
static void bytes(const char *text,int length) {
    putchar('"');
    for(int i=0;i<length;++i)printf("%02x",(unsigned char)text[i]);
    putchar('"');
}
static void emit(jv value) {
    allocation_observer_pause(1);
    printf("{\"kind\":%d,\"bytes\":",jv_get_kind(value));
    if(!jv_is_valid(value))value=jv_invalid_get_msg(value);
    if(!jv_is_valid(value)){jv_free(value);value=jv_null();}
    jv text=jv_dump_string(value,JV_PRINT_SORTED);
    bytes(jv_string_value(text),jv_string_length_bytes(jv_copy(text)));
    jv_free(text);putchar('}');allocation_observer_pause(0);
}
static char *decode(const char *hex,int *length) {
    if(!strncmp(hex,"repeat:",7)) {
        unsigned count,byte;
        if(sscanf(hex+7,"%u:%2x",&count,&byte)!=2||count>1048576)exit(2);
        char *out=malloc((size_t)count+1);if(!out)exit(2);
        memset(out,(int)byte,count);out[count]=0;*length=(int)count;return out;
    }
    size_t n=strlen(hex)/2;if(strlen(hex)%2)exit(2);
    char *out=malloc(n+1);if(!out)exit(2);
    for(size_t i=0;i<n;++i){unsigned byte;if(sscanf(hex+i*2,"%2x",&byte)!=1)exit(2);out[i]=(char)byte;}
    out[n]=0;*length=(int)n;return out;
}
static void primitive_case(void) {
    jv values[]={jv_null(),jv_false(),jv_true(),jv_bool(0),jv_bool(-3),jv_bool(17),jv_invalid()};
    fputs("{\"values\":[",stdout);
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i){if(i)putchar(',');emit(values[i]);}
    fputs("],\"names\":[",stdout);
    for(int i=0;i<8;++i){if(i)putchar(',');const char *text=jv_kind_name((jv_kind)i);bytes(text,(int)strlen(text));}
    jv message=jv_parse("{\"error\":[1,2]}"),invalid=jv_invalid_with_msg(jv_copy(message)),alias=jv_copy(invalid);
    printf("],\"has_message\":%d,\"references\":%d,\"message\":",jv_invalid_has_msg(jv_copy(invalid)),jv_get_refcnt(invalid));
    emit(jv_invalid_get_msg(invalid));
    fputs(",\"retained\":",stdout);emit(jv_invalid_get_msg(jv_copy(alias)));
    jvp_invalid_free(alias);jv_free(message);putchar('}');
}
static void string_case(const char *raw,const char *suffix,int repeat) {
    int n,m;char *text=decode(raw,&n),*extra=decode(suffix,&m);
    jv first=jv_string_sized(text,n),alias=jv_copy(first);
    unsigned long hash=jv_string_hash(jv_copy(first));
    printf("{\"hash\":%lu,\"repeat_hash\":%lu,\"references\":%d,\"original\":",hash,jv_string_hash(jv_copy(alias)),jv_get_refcnt(first));emit(jv_copy(first));
    jv changed=jv_string_append_buf(first,extra,m);
    printf(",\"same_after_shared_edit\":%d,\"changed_hash\":%lu,\"changed\":",changed.u.ptr==alias.u.ptr,jv_string_hash(jv_copy(changed)));emit(jv_copy(changed));
    fputs(",\"retained\":",stdout);emit(jv_copy(alias));
    fputs(",\"repeat\":",stdout);emit(jv_string_repeat(jv_copy(alias),repeat));
    fputs(",\"explode\":",stdout);emit(jv_string_explode(jv_copy(alias)));
    fputs(",\"roundtrip\":",stdout);emit(jv_string_implode(jv_string_explode(jv_copy(alias))));
    fputs(",\"nul_terminated\":",stdout);emit(jv_string(text));
    fputs(",\"append_str\":",stdout);emit(jv_string_append_str(jv_copy(alias),extra));
    fputs(",\"concat\":",stdout);emit(jv_string_concat(jv_copy(alias),jv_copy(alias)));
    fputs(",\"codepoint\":",stdout);emit(jv_string_append_codepoint(jv_copy(alias),0x1f642));
    fputs(",\"bad_codepoints\":",stdout);emit(jv_string_implode(jv_parse("[-1,55296,1114112,0,65]")));
    jv unique=jv_string_empty(64);void *before=unique.u.ptr;
    unique=jv_string_append_str(unique,"abc");
    (void)jv_string_hash(jv_copy(unique));
    unique=jv_string_append_buf(unique,jv_string_value(unique),3);
    printf(",\"in_place\":%d,\"self_append_hash\":%lu,\"self_append\":",before==unique.u.ptr,jv_string_hash(jv_copy(unique)));emit(unique);
    jvp_string_free(changed);jvp_string_free(alias);free(text);free(extra);putchar('}');
}
static void object_case(const char *text,int count) {
    jv original=jv_parse(text),work=jv_copy(original);
    for(int i=0;i<count;++i){jv key=jv_string_fmt("key-%03d",i);work=jv_object_set(work,key,jv_number(i));}
    work=jv_object_set(work,jv_string_sized("a\0b",3),jv_array_append(jv_array(),jv_true()));
    work=jv_object_set(work,jv_string("a"),jv_string("replaced"));
    for(int i=0;i<count;i+=3)work=jv_object_delete(work,jv_string_fmt("key-%03d",i));
    jv order=jv_array();
    for(int i=jv_object_iter(work);jv_object_iter_valid(work,i);i=jv_object_iter_next(work,i)){
        jv pair=jv_array_append(jv_array(),jv_object_iter_key(work,i));
        pair=jv_array_append(pair,jv_object_iter_value(work,i));order=jv_array_append(order,pair);
    }
    printf("{\"length\":%d,\"has_binary_key\":%d,\"has_missing\":%d,\"shared_after_write\":%d,\"order\":",jv_object_length(jv_copy(work)),jv_object_has(jv_copy(work),jv_string_sized("a\0b",3)),jv_object_has(jv_copy(work),jv_string("absent")),original.u.ptr==work.u.ptr);emit(order);
    fputs(",\"original\":",stdout);emit(jv_copy(original));fputs(",\"modified\":",stdout);emit(jv_copy(work));
    jv array=jv_array_append(jv_array(),jv_copy(original)),alias=jv_copy(array);
    array=jv_array_concat(array,jv_array_append(jv_array(),jv_copy(work)));
    fputs(",\"array\":",stdout);emit(array);fputs(",\"array_alias\":",stdout);emit(alias);
    printf(",\"references\":[%d,%d]",jv_get_refcnt(original),jv_get_refcnt(work));
    jv_free(original);jv_free(work);putchar('}');
}
static void invalid_slot_case(void) {
    jv object=jv_object_set(jv_object(),jv_string("x"),jv_invalid());
    jv value=jv_object_iter_value(object,jv_object_iter(object));
    printf("{\"has\":%d,\"kind\":%d,\"length\":%d}",jv_object_has(jv_copy(object),jv_string("x")),jv_get_kind(value),jv_object_length(jv_copy(object)));
    jv_free(value);jv_free(object);
}
static void release_case(void) {
    jv tree=jv_parse("{\"values\":[null,false,true,0,1.25,123456789012345678901234567890,\"text\",[],{},[{},[1]]]}"),alias=jv_copy(tree);
    jv error=jv_invalid_with_msg(jv_copy(tree)),retained_error=jv_copy(error);
    printf("{\"references_before\":%d",jv_get_refcnt(tree));
    jv_free(tree);jv_free(error);
    printf(",\"references_after\":%d,\"retained\":",jv_get_refcnt(alias));
    emit(jv_copy(alias));
    fputs(",\"message\":",stdout);emit(jv_invalid_get_msg(retained_error));
    jv_free(alias);jv_free(jv_invalid());putchar('}');
}
static void slice_case(const char *raw,const char *descriptor,int alias_outputs) {
    int n;char *text=decode(raw,&n),*spec=decode(descriptor,&n);
    jv value=jv_parse(text),slice=jv_parse(spec);
    jv retained_value=jv_copy(value),retained_slice=jv_copy(slice);
    int start=117,end=-119;
    jv status=parse_slice(value,slice,&start,alias_outputs?&start:&end);
    printf("{\"start\":%d,\"end\":%d,\"status\":",start,end);emit(status);
    fputs(",\"value\":",stdout);emit(retained_value);
    fputs(",\"slice\":",stdout);emit(retained_slice);
    putchar('}');free(text);free(spec);
}
static jv via_vfmt(const char *format,...) {
    va_list args;va_start(args,format);jv value=jv_string_vfmt(format,args);va_end(args);return value;
}
static void format_case(const char *hex,const char *number,int integer) {
    int length;char *text=decode(hex,&length);double value=strtod(number,NULL);
    const char *format="%s|%.*s|%+012d|%#x|%lld|%llu|%.17g|%.3f|%%";
    long long signed_value=-9223372036854775807LL;unsigned long long unsigned_value=18446744073709551615ULL;
    fputs("{\"variadic\":",stdout);emit(jv_string_fmt(format,text,length/2,text,integer,(unsigned)integer,signed_value,unsigned_value,value,value));
    fputs(",\"va_list\":",stdout);emit(via_vfmt(format,text,length/2,text,integer,(unsigned)integer,signed_value,unsigned_value,value,value));
    free(text);putchar('}');
}
static void consumer_case(const char *program,const char *text) {
    jq_state *states[2]={jq_init(),jq_init()};jv input=jv_parse(text);putchar('[');
    for(int i=0;i<2;++i){
        if(!states[i])exit(84);
        int compiled=jq_compile(states[i],program);
        printf("%s{\"compiled\":%d,\"values\":[",i?",":"",compiled);
        if(compiled){
            jq_start(states[i],jv_copy(input),0);unsigned count=0;
            for(;;){jv value=jq_next(states[i]);if(!jv_is_valid(value)){fputs("],\"error\":",stdout);emit(value);break;}
                if(count++)putchar(',');
                emit(value);
                if(count>100)exit(82);}
        }else fputs("],\"error\":null",stdout);
        fputs(",\"input\":",stdout);emit(jv_copy(input));putchar('}');
    }
    jq_teardown(&states[1]);jq_teardown(&states[0]);jv_free(input);putchar(']');
}
int main(int argc,char **argv) {
    if(argc!=6)return 2;
    SetUnhandledExceptionFilter(report_exception);
    int source=!strcmp(argv[1],"source");
    spx_test_hash_seed(0xdecaffe5);
    if(source&&!install_entries())return 85;
    allocation_observer_begin();fputs("{\"result\":",stdout);
    if(!strcmp(argv[2],"primitive"))primitive_case();
    else if(!strcmp(argv[2],"string"))string_case(argv[3],argv[4],atoi(argv[5]));
    else if(!strcmp(argv[2],"object"))object_case(argv[3],atoi(argv[5]));
    else if(!strcmp(argv[2],"invalid-slot"))invalid_slot_case();
    else if(!strcmp(argv[2],"release"))release_case();
    else if(!strcmp(argv[2],"slice"))slice_case(argv[3],argv[4],atoi(argv[5]));
    else if(!strcmp(argv[2],"format"))format_case(argv[3],argv[4],atoi(argv[5]));
    else if(!strcmp(argv[2],"consumer")) {
        int ignored;
        char *program=decode(argv[3],&ignored),*input=decode(argv[4],&ignored);
        consumer_case(program,input);free(program);free(input);
    }
    else return 2;
    fputs(",\"allocation_lifetime\":",stdout);allocation_observer_finish(stdout);puts("}");
    fprintf(stderr,"authored-value-runtime-calls=%u\n",calls);
    fprintf(stderr,"authored-release-calls=%u\n",release_calls);
    return source&&(!calls||!entries_intact())?85:0;
}
