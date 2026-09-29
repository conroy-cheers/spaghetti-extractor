#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include "support-inputs.h"
#include "entries.h"
#include "native-entry.h"
#include "allocation-observer.h"

static unsigned source_calls[23];
void spx_observe_support_entry(unsigned index) { if(index>=23)ExitProcess(85); ++source_calls[index]; }
void spx_probe_locate(struct locfile *, location);

static LONG WINAPI report_exception(EXCEPTION_POINTERS *error) {
    fprintf(stderr,"native-fault code=%08lx ip=%08lx image=%p\n",
        (unsigned long)error->ExceptionRecord->ExceptionCode,
        (unsigned long)error->ContextRecord->Eip,(void *)GetModuleHandleA("libjq-1.dll"));
    fflush(stderr); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
static unsigned digit(char c) {
    if(c>='0'&&c<='9')return c-'0';
    if(c>='a'&&c<='f')return c-'a'+10;
    exit(2);
}
static char *decode(const char *hex, size_t *length) {
    *length=strlen(hex)/2;
    if(strlen(hex)%2)exit(2);
    char *bytes=malloc(*length+1);if(!bytes)exit(2);
    for(size_t i=0;i<*length;i++)bytes[i]=(char)((digit(hex[2*i])<<4)|digit(hex[2*i+1]));
    bytes[*length]=0;return bytes;
}
static jv hex_value(const void *data, size_t length) {
    static const char digits[]="0123456789abcdef";
    const unsigned char *bytes=data;char *hex=malloc(2*length+1);if(!hex)exit(2);
    for(size_t i=0;i<length;i++){hex[2*i]=digits[bytes[i]>>4];hex[2*i+1]=digits[bytes[i]&15];}
    hex[2*length]=0;jv value=jv_string_sized(hex,(int)(2*length));free(hex);return value;
}
static jv put(jv object, const char *key, jv value) { return jv_object_set(object,jv_string(key),value); }
static jv observed_value(jv value) {
    jv result=put(jv_object(),"kind",jv_number(jv_get_kind(value)));
    if (!jv_is_valid(value)) value=jv_invalid_get_msg(value);
    if (!jv_is_valid(value)) { jv_free(value); value=jv_null(); }
    return put(result,"value",value);
}
static jv environment_case(const char *hex, int mode) {
    if (_putenv("HOME=") || _putenv("USERPROFILE=") ||
        _putenv("HOMEPATH=") || _putenv("HOMEDRIVE=")) exit(82);
    if (mode>=1 && mode<=3 && _putenv("HOMEPATH=/users/fallback")) exit(82);
    if (mode>=1 && mode<=2 && _putenv("USERPROFILE=/profile/second")) exit(82);
    if (mode==1 && _putenv("HOME=/home/first")) exit(82);
    if (mode==3 && _putenv("HOMEDRIVE=D:")) exit(82);
    if (mode==4 && _putenv("HOMEPATH=/path/only")) exit(82);
    size_t length;char *bytes=decode(hex,&length);
    jv path=jv_string_sized(bytes,(int)length),alias=jv_copy(path);
    jv home=get_home();jv expanded=expand_path(path);
    jv result=put(jv_object(),"home",observed_value(home));
    result=put(result,"alias_preserved",jv_bool(jv_get_kind(expanded)==JV_KIND_STRING && expanded.u.ptr==alias.u.ptr));
    result=put(result,"expanded",observed_value(expanded));
    result=put(result,"retained_path",alias);free(bytes);return result;
}
static jv path_case(const char *hex,int mode) {
    if (!SetCurrentDirectoryA(mode==1?"C:\\windows":"Z:\\")) exit(82);
    size_t length;char *bytes=decode(hex,&length);
    jv path=jv_string_sized(bytes,(int)length),alias=jv_copy(path);
    jv expanded=spx_probe_jq_realpath(path);
    jv result=put(jv_object(),"same_input",jv_bool(expanded.u.ptr==alias.u.ptr));
    result=put(result,"expanded",observed_value(expanded));
    result=put(result,"retained",alias);
    char *directory=malloc(length+1),*base=malloc(length+1);
    if (!directory || !base) exit(2);
    memcpy(directory,bytes,length+1);memcpy(base,bytes,length+1);
    /* CRT library scratch storage is separate from observed jv ownership. */
    allocation_observer_pause(1);
    char *dir=spx_probe_dirname(mode==2?NULL:directory);
    int same_dir=dir==directory;
    char *dir_text=strdup(dir);
    char *leaf=spx_probe_basename(mode==2?NULL:base);
    intptr_t base_offset=(uintptr_t)leaf>=(uintptr_t)base && (uintptr_t)leaf<=(uintptr_t)base+length ? leaf-base : -1;
    char *leaf_text=strdup(leaf);
    allocation_observer_pause(0);
    if (!dir_text || !leaf_text) exit(2);
    result=put(result,"directory",jv_string(dir_text));
    result=put(result,"directory_alias",jv_bool(same_dir));
    result=put(result,"basename",jv_string(leaf_text));
    result=put(result,"basename_offset",jv_number((double)base_offset));
    result=put(result,"directory_frame",hex_value(directory,length+1));
    result=put(result,"basename_frame",hex_value(base,length+1));
    free(bytes);free(directory);free(base);free(dir_text);free(leaf_text);return result;
}
static jv memory_case(const char *haystack_hex, const char *needle_hex) {
    size_t length,needle_length;
    char *haystack=decode(haystack_hex,&length),*needle=decode(needle_hex,&needle_length);
    const char *found=_jq_memmem(haystack,length,needle,needle_length);
    jv result=put(jv_object(),"offset",jv_number(found ? found-haystack : -1));
    result=put(result,"haystack",hex_value(haystack,length));
    result=put(result,"needle",hex_value(needle,needle_length));
    /* The needle may alias a suffix of the same live buffer. */
    size_t start=length/2;
    found=_jq_memmem(haystack,length,haystack+start,length-start);
    result=put(result,"aliased_offset",jv_number(found ? found-haystack : -1));
    free(haystack);free(needle);return result;
}
static jv unicode_case(const char *hex, int scalar) {
    size_t length;char *bytes=decode(hex,&length);
    jv result=jv_object(),next=jv_array(),back=jv_array(),decode_lengths=jv_array();
    for(const char *p=bytes;;) {
        int codepoint=777;const char *after=jvp_utf8_next(p,bytes+length,&codepoint);
        next=jv_array_append(next,JV_ARRAY(jv_number(p-bytes),jv_number(after?after-bytes:-1),jv_number(codepoint)));
        if(!after)break;
        p=after;
    }
    for(size_t i=0;i<length;i++) {
        int missing=777;const char *start=jvp_utf8_backtrack(bytes+i,bytes,&missing);
        back=jv_array_append(back,JV_ARRAY(jv_number(i),jv_number(start?start-bytes:-1),jv_number(missing)));
    }
    for(unsigned i=0;i<256;i++)decode_lengths=jv_array_append(decode_lengths,jv_number(jvp_utf8_decode_length((char)i)));
    result=put(result,"next",next);result=put(result,"backtrack",back);
    result=put(result,"valid",jv_number(jvp_utf8_is_valid(bytes,bytes+length)));
    result=put(result,"decode_lengths",decode_lengths);
    result=put(result,"encode_length",jv_number(jvp_utf8_encode_length(scalar)));
    result=put(result,"whitespace",jv_number(jvp_codepoint_is_whitespace(scalar)));
    char output[12];memset(output,0x5a,sizeof(output));
    int count=scalar>=0&&scalar<=0x10ffff?jvp_utf8_encode(scalar,output+3):-1;
    result=put(result,"encoded_count",jv_number(count));
    result=put(result,"output_with_frame",hex_value(output,sizeof(output)));
    result=put(result,"input_after",hex_value(bytes,length));free(bytes);return result;
}
static void message(void *data, jv value) { jv *events=data;*events=jv_array_append(*events,value); }
static jv location_case(const char *hex) {
    size_t length;char *bytes=decode(hex,&length);
    jq_state *jq=jq_init();if(!jq)exit(84);
    jv events=jv_array();jq_set_error_cb(jq,message,&events);
    struct locfile *file=locfile_init(jq,"sample.jq",bytes,(int)length);
    memset(bytes,'?',length); /* The source-location object owns its copy. */
    struct locfile *alias=locfile_retain(file);
    jv result=put(jv_object(),"alias",jv_bool(file==alias));
    result=put(result,"references",jv_number(file->refct));
    result=put(result,"copied_bytes",hex_value(file->data,(size_t)file->length));
    jv lines=jv_array(),map=jv_array();
    for(int i=0;i<file->length;i++)lines=jv_array_append(lines,jv_number(locfile_get_line(file,i)));
    for(int i=0;i<=file->nlines;i++)map=jv_array_append(map,jv_number(file->linemap[i]));
    result=put(result,"lines",lines);result=put(result,"map",map);
    spx_probe_locate(file,UNKNOWN_LOCATION);
    if(length) {
        spx_probe_locate(file,(location){0,(int)length});
        spx_probe_locate(file,(location){(int)length-1,(int)length});
    }
    locfile_free(file);
    result=put(result,"retained_references",jv_number(alias->refct));
    result=put(result,"retained_bytes",hex_value(alias->data,(size_t)alias->length));
    locfile_free(alias);jq_teardown(&jq);free(bytes);
    return put(result,"messages",events);
}
static jv opcode_case(void) {
    jv result=jv_array();
    for(int op=-2;op<NUM_OPCODES+3;op++) {
        const struct opcode_description *description=opcode_describe((opcode)op);
        uint16_t code[2]={(uint16_t)op,7};
        result=jv_array_append(result,JV_ARRAY(jv_number(op),jv_number(description->op),
            jv_string(description->name),jv_number(description->flags),jv_number(description->length),
            jv_number(description->stack_in),jv_number(description->stack_out),
            jv_bool(description==opcode_describe((opcode)op)),jv_number(bytecode_operation_length(code))));
    }
    bytecode_free(NULL);return result;
}

/* The same reviewed native jq_state prefix used by the compiler-IR fixture. */
static struct bytecode *compiled_code(jq_state *state) {
    struct { void (*handler)(void *); void *data; struct bytecode *code; } prefix;
    memcpy(&prefix,state,sizeof(prefix));return prefix.code;
}
static jv bytecode_snapshot(struct bytecode *code, struct bytecode *parent) {
    if(!code)return jv_null();
    jv words=jv_array(),children=jv_array();
    for(int i=0;i<code->codelen;i++)words=jv_array_append(words,jv_number(code->code[i]));
    for(int i=0;i<code->nsubfunctions;i++)children=jv_array_append(children,bytecode_snapshot(code->subfunctions[i],code));
    jv result=put(jv_object(),"code",words);
    result=put(result,"children",children);result=put(result,"debug",jv_copy(code->debuginfo));
    result=put(result,"parent_ok",jv_bool(code->parent==parent));
    result=put(result,"globals_ok",jv_bool(!parent||code->globals==parent->globals));
    return put(result,"constants",jv_copy(code->constants));
}
static jv disassembly(struct bytecode *code) {
    fflush(stdout);int saved=_dup(_fileno(stdout));FILE *capture=tmpfile();
    if(saved<0||!capture||_dup2(_fileno(capture),_fileno(stdout)))exit(82);
    _setmode(_fileno(stdout),_O_BINARY);
    dump_disassembly(2,code);
    /* The interpreter also enters the single-operation formatter directly. */
    dump_operation(code,code->code);putchar('\n');
    fflush(stdout);
    if(_dup2(saved,_fileno(stdout)))exit(82);
    _close(saved);
    if(fseek(capture,0,SEEK_END))exit(82);
    long count=ftell(capture);if(count<0||count>1048576||fseek(capture,0,SEEK_SET))exit(82);
    char *bytes=malloc((size_t)count+1);if(!bytes)exit(82);
    if(fread(bytes,1,(size_t)count,capture)!=(size_t)count||fclose(capture))exit(82);
    jv result=hex_value(bytes,(size_t)count);free(bytes);return result;
}
static jv compiler_case(const char *program_hex, const char *input_hex) {
    size_t length;char *program=decode(program_hex,&length),*input=decode(input_hex,&length);
    jv result=jv_array();jq_state *states[2]={jq_init(),jq_init()};
    for(int i=0;i<2;i++) {
        if(!states[i])exit(84);
        jv events=jv_array();jq_set_error_cb(states[i],message,&events);
        jq_set_debug_cb(states[i],message,&events);jq_set_stderr_cb(states[i],message,&events);
        int compiled=jq_compile(states[i],program);
        jv row=put(jv_object(),"compiled",jv_number(compiled));
        if(compiled) {
            row=put(row,"bytecode",bytecode_snapshot(compiled_code(states[i]),NULL));
            row=put(row,"disassembly_hex",disassembly(compiled_code(states[i])));
            jq_start(states[i],jv_parse(input),0);
            jv values=jv_array();
            for(int n=0;n<256;n++) {
                jv value=jq_next(states[i]);
                if(!jv_is_valid(value)) {
                    jv error=jv_invalid_get_msg(value);
                    if(!jv_is_valid(error)){jv_free(error);error=jv_null();}
                    row=put(row,"error",error);break;
                }
                values=jv_array_append(values,value);
                if(n==255)exit(82); /* An incomplete consumer run is not a pass. */
            }
            row=put(row,"values",values);
        }
        jq_teardown(&states[i]);
        result=jv_array_append(result,put(row,"messages",events));
    }
    free(program);free(input);return result;
}
int main(int argc, char **argv) {
    if(argc!=5)return 2;
    SetUnhandledExceptionFilter(report_exception);_setmode(_fileno(stdout),_O_BINARY);
    int source=!strcmp(argv[1],"source");
    if(source&&!install_entries())return 85;
    allocation_observer_begin();jv result;
    if(!strcmp(argv[2],"unicode"))result=unicode_case(argv[3],atoi(argv[4]));
    else if(!strcmp(argv[2],"locations"))result=location_case(argv[3]);
    else if(!strcmp(argv[2],"opcodes"))result=opcode_case();
    else if(!strcmp(argv[2],"compiler"))result=compiler_case(argv[3],argv[4]);
    else if(!strcmp(argv[2],"environment"))result=environment_case(argv[3],atoi(argv[4]));
    else if(!strcmp(argv[2],"paths"))result=path_case(argv[3],atoi(argv[4]));
    else if(!strcmp(argv[2],"memory"))result=memory_case(argv[3],argv[4]);
    else return 2;
    allocation_observer_pause(1);
    jv text=jv_dump_string(result,JV_PRINT_SORTED);
    fputs("{\"result\":",stdout);fputs(jv_string_value(text),stdout);jv_free(text);
    allocation_observer_pause(0);
    fputs(",\"allocation_lifetime\":",stdout);allocation_observer_finish(stdout);puts("}");
    unsigned total=0;
    for(unsigned i=0;i<23;i++){fprintf(stderr,"support-entry-%u=%u\n",i,source_calls[i]);total+=source_calls[i];}
    return source&&(!total||!entries_intact())?85:0;
}
