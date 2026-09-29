#include "portable-component-implementation.h"
#include "stream-view.h"
#include "pe32-entry-hook.h"
#include "pe32-import-hook.h"
#include <errno.h>
#include <io.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef FILE *NativeStream;
typedef struct spx_opaque_io_stream_v5 Stream;
_Static_assert(sizeof(void *)==4 && offsetof(FILE,_ptr)==0 && offsetof(FILE,_base)==8,
               "reviewed native FILE prefix differs");
static unsigned char *image;
static spx_fixture_entry_hook body, pending_hook;
static spx_fixture_import_hook error_hook, close_hook, errno_hook;
static NativeStream active;
static Stream view;
static unsigned alive, closes, identity, events, controlled;
static int prior_error, close_result, close_errno;
static int records[8][4];

static void require(int okay, const char *message) {
    if (!okay) { fprintf(stderr,"stream adapter: %s\n",message); exit(77); }
}
static int *error_address(void) {
    return ((int *(*)(void))(uintptr_t)errno_hook.original)();
}
static void record(int operation, int value) {
    require(events<8,"bounded interaction trace");
    records[events][0]=operation; records[events][1]=(int)identity;
    records[events][2]=value; records[events][3]=*error_address(); ++events;
}
static void live(NativeStream stream) { require(stream==active && alive,"live stream identity"); }
static NativeStream fixture_borrow(Stream *stream) {
    NativeStream value=spx_stream_borrow(stream);
    require(value!=NULL,"borrow after consumption");live(value);return value;
}
static NativeStream fixture_take(Stream *stream) {
    NativeStream value=spx_stream_take(stream);
    require(value!=NULL,"consume after consumption");live(value);return value;
}
static Stream *fixture_pack(NativeStream stream) {
    live(stream);require(view.handle==stream && view.live,"existing live proxy");return &view;
}
static uint32_t traced_pending(NativeStream stream);
static void hook_pending(void) {
    require(spx_fixture_redirect_address_body(&pending_hook,image+0x68f8,pending_hook.saved,5,
        (void (*)(void))traced_pending),"observe pending service");
}
static uint32_t traced_pending(NativeStream stream) {
    live(stream);
    require(spx_fixture_restore_entry(&pending_hook),"restore actual pending helper");
    uint32_t result=((uint32_t (*)(NativeStream))(void *)(image+0x68f8))(stream);
    hook_pending();record(1,(int)result);return result;
}
static int32_t traced_error(NativeStream stream) {
    live(stream);
    int result=controlled ? prior_error : ((int (*)(FILE *))(uintptr_t)error_hook.original)(stream);
    record(2,result);return result;
}
static int32_t traced_close(NativeStream stream) {
    live(stream);int result;
    if (controlled) {
        stream->_flag^=0x100;*error_address()=close_errno;result=close_result;
    } else result=((int (*)(FILE *))(uintptr_t)close_hook.original)(stream);
    ++closes;alive=0;record(3,result);return result;
}
static int *traced_errno_address(void) { record(4,*error_address());return error_address(); }
static uint32_t traced_bad_descriptor(void) { return *traced_errno_address()==9; }
static void traced_clear_errno(void) { *traced_errno_address()=0; }

#include "comparison-service-bridge.h"

static void reset(FILE *stream,unsigned context) {
    active=stream;identity=context;alive=1;closes=0;events=0;
    view=(Stream){stream,1};*error_address()=73;
}
static int call(void) {
    int result=((int (*)(FILE *))(void *)(image+0x6894))(active);
    require(!alive && closes==1,"stream consumed exactly once");return result;
}
static void observe(int result, int saved_errno) {
    printf("{\"result\":%d,\"errno\":%d,\"alive\":%u,\"closes\":%u,\"events\":[",
        result,saved_errno,alive,closes);
    for (unsigned i=0;i<events;++i) printf("%s[%d,%d,%d,%d]",i?",":"",records[i][0],records[i][1],records[i][2],records[i][3]);
    printf("]");
}
int main(int argc,char **argv) {
    if (argc!=4 || (strcmp(argv[1],"original") && strcmp(argv[1],"source"))) return 2;
    int source=!strcmp(argv[1],"source");
    image=(void *)LoadLibraryA("hello-routines.dll");require(image!=NULL,"load pinned routine image");
    require(spx_fixture_redirect_import(&error_hook,"hello-routines.dll","msvcrt.dll","ferror",(void (*)(void))traced_error),"ferror import");
    require(spx_fixture_redirect_import(&close_hook,"hello-routines.dll","msvcrt.dll","fclose",(void (*)(void))traced_close),"fclose import");
    require(spx_fixture_redirect_import(&errno_hook,"hello-routines.dll","msvcrt.dll","_errno",(void (*)(void))traced_errno_address),"errno import");
    const unsigned char pending_prefix[5]={0x8b,0x54,0x24,0x04,0x31};
    require(spx_fixture_redirect_address_body(&pending_hook,image+0x68f8,pending_prefix,5,(void (*)(void))traced_pending),"pending entry");
    if (source) {
        const unsigned char prefix[5]={0x57,0x56,0x53,0x83,0xec};
        require(spx_fixture_redirect_address_body(&body,image+0x6894,prefix,0x64,(void (*)(void))fixture_close),"complete close body");
    }
    controlled=!strcmp(argv[2],"controlled");printf("{\"sequences\":[");
    if (controlled) {
        unsigned context=(unsigned)strtoul(argv[3],NULL,10);require(context<2,"declared caller identity");
        const int errors[]={0,1,-3}, returns[]={0,-1,7}, numbers[]={0,9,22,28};
        const unsigned pending[]={0,1,7};unsigned sequence=0;
        for (unsigned p=0;p<3;++p) for (unsigned e=0;e<3;++e)
        for (unsigned c=0;c<3;++c) for (unsigned n=0;n<4;++n) {
            struct { unsigned before; FILE file; unsigned after; char data[16]; } storage;
            memset(&storage,0xa5,sizeof(storage));storage.file._base=storage.data;
            storage.file._ptr=storage.data+pending[p];storage.file._flag=0x1234;
            prior_error=errors[e];close_result=returns[c];close_errno=numbers[n];reset(&storage.file,context);
            int result=call(),saved_errno=*error_address();
            if (sequence++) putchar(',');
            observe(result,saved_errno);
            printf(",\"frame\":[%u,%u,%d,\"",storage.before,storage.after,storage.file._flag);
            for (unsigned i=0;i<sizeof(storage.data);++i) printf("%02x",(unsigned char)storage.data[i]);
            printf("\"]}");
            require(!source || (!view.live && !view.handle),"all aliases observe consumed view");
        }
    } else {
        require(!strcmp(argv[2],"real"),"selected native scenario");
        FILE *seed=fopen("contents","wb");require(seed!=NULL && fputs("abcdef",seed)>=0 && !fclose(seed),"seed real file");
        int reading=!strcmp(argv[3],"read") || !strcmp(argv[3],"prior-error");
        FILE *file=fopen("contents",reading ? "rb" : "wb");require(file!=NULL,"open real stream");
        if (!strcmp(argv[3],"read")) require(fgetc(file)=='a',"real read");
        else if (!strcmp(argv[3],"prior-error")) require(fputc('x',file)==EOF && ferror(file),"real prior write error");
        else if (!strcmp(argv[3],"write") || !strcmp(argv[3],"closed-pending")) require(fputs("hello",file)>=0,"pending real write");
        else require(!strcmp(argv[3],"closed-empty"),"declared native file case");
        if (!strncmp(argv[3],"closed-",7)) require(_close(_fileno(file))==0,"close descriptor while FILE remains owned");
        reset(file,2);int result=call(),saved_errno=*error_address();observe(result,saved_errno);
        printf(",\"contents\":[");FILE *input=fopen("contents","rb");require(input!=NULL,"observe file contents");
        int byte;unsigned index=0;while ((byte=fgetc(input))!=EOF) printf("%s%d",index++?",":"",byte);
        require(!ferror(input) && !fclose(input),"finish file observation");printf("]}");
    }
    printf("]}\n");
    if (source) for (unsigned i=5;i<0x64;++i) require(image[0x6894+i]==0xcc,"original body remains absent");
    require(FreeLibrary((HMODULE)image),"unload native image");return 0;
}
