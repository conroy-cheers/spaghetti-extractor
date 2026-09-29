/* Controlled file effects and observed byte backing around the actual PE entries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "board-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#endif
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr,"board adapter:%u: %s\n",__LINE__,#c); exit(3); } } while (0)
struct spx_opaque_board_file_v5 { uint32_t id,writing,open; };
static board_set boards;
static board_file files[3]={{1,0,0},{2,1,0},{3,0,0}};
static unsigned char disk[20000];
static uint32_t disk_size=20000,mode,entries[5],events[32][5],event_count;
static uint32_t guards[4]={0xabcdf001,0xabcdf002,0xabcdf003,0xabcdf004};
void board_enter(unsigned operation) { REQUIRE(operation<5); ++entries[operation]; }
static uint32_t file_id(board_file *file) {
    if (!file) return 0;
    for (unsigned i=0;i<3;++i) if (file==&files[i]) return file->id;
    REQUIRE(0); return 0;
}
static void record(uint32_t operation,uint32_t a,uint32_t b,uint32_t c) {
    REQUIRE(event_count<32); uint32_t values[]={operation,a,b,c,file_id(boards.file)};
    memcpy(events[event_count++],values,sizeof(values));
}
board_file *board_open(void *unused,board_set *state,board_name *name,uint32_t writing) {
    (void)unused; REQUIRE(state==&boards && !strcmp(name->text,"default.bds") && writing<2);
    board_file *file=(mode==3 && !writing) || (mode==4 && writing) ? NULL : &files[writing];
    record(0,writing,file_id(file),0);
    if (file) { REQUIRE(!file->open); file->open=1; if (writing) disk_size=0; }
    return file;
}
void board_read(void *unused,board_set *state,board_file *file,board_bytes *bytes) {
    (void)unused; REQUIRE(state==&boards && file && file->open && !file->writing);
    REQUIRE(bytes->data==(unsigned char *)state->saved && bytes->size==20000);
    uint32_t limit=mode==5 ? 0 : mode==6 ? 1 : mode==7 ? 399 : mode==8 ? 400 : mode==9 ? 19999 : 20000;
    uint32_t count=disk_size<limit ? disk_size : limit; record(1,file_id(file),bytes->size,count); memcpy(bytes->data,disk,count);
}
void board_write(void *unused,board_set *state,board_file *file,board_bytes *bytes) {
    (void)unused; REQUIRE(state==&boards && file && file->open && file->writing);
    REQUIRE(bytes->data==(unsigned char *)state->saved && bytes->size==20000);
    disk_size=mode==10 ? 417 : mode==11 ? 0 : 20000; record(2,file_id(file),bytes->size,disk_size); memcpy(disk,bytes->data,disk_size);
}
void board_close(void *unused,board_set *state,board_file *file) {
    (void)unused; REQUIRE(state==&boards && file && file->open); record(3,file_id(file),0,0); file->open=0;
}
#ifndef DX_STANDALONE
static const uint32_t guard_addresses[]={0x42ca5c,0x42cbf0,0x42cdf4,0x431c18};
static void to_native(void) {
    memcpy((void *)0x42ca60,&boards.current,400); memcpy((void *)0x42cdf8,boards.saved,20000);
    *(uint32_t *)0x434964=(uint32_t)(uintptr_t)boards.file;
    for (unsigned i=0;i<4;++i) *(uint32_t *)(uintptr_t)guard_addresses[i]=guards[i];
}
static void from_native(void) {
    memcpy(&boards.current,(void *)0x42ca60,400); memcpy(boards.saved,(void *)0x42cdf8,20000);
    boards.file=(board_file *)(uintptr_t)*(uint32_t *)0x434964;
    for (unsigned i=0;i<4;++i) guards[i]=*(uint32_t *)(uintptr_t)guard_addresses[i];
}
static uint32_t native_open(const char *name,const char *access) {
    REQUIRE(!strcmp(access,"rb") || !strcmp(access,"wb")); from_native(); board_name path={name};
    board_file *file=board_open(NULL,&boards,&path,!strcmp(access,"wb")); to_native(); return (uint32_t)(uintptr_t)file;
}
#define TRANSFER(name) \
static uint32_t native_##name(void *data,uint32_t size,uint32_t count,board_file *file) { \
    REQUIRE(data==(void *)0x42cdf8 && size==1 && count==20000); from_native(); \
    board_bytes bytes={(unsigned char *)boards.saved,20000}; board_##name(NULL,&boards,file,&bytes); to_native(); return 0; \
}
TRANSFER(read) TRANSFER(write)
static uint32_t native_close(board_file *file) { from_native(); board_close(NULL,&boards,file); to_native(); return UINT32_MAX; }
#define IO_ROOT(operation) static void native_board_##operation(const char *name) { \
    from_native(); board_name path={name}; fixture_board_##operation(&boards,&path); to_native(); }
IO_ROOT(load) IO_ROOT(save)
#define COPY_ROOT(operation) static void native_board_##operation(uint32_t index) { \
    from_native(); fixture_board_##operation(&boards,index); to_native(); }
COPY_ROOT(select) COPY_ROOT(store)
static uint32_t native_board_sprite(uint32_t kind) { return fixture_board_sprite(kind); }
static void install(int source) {
#define SERVICE(name) REQUIRE(install_board_service_##name((void (*)(void))native_##name));
    SERVICE(open) SERVICE(read) SERVICE(write) SERVICE(close)
    if (!source) return;
#define ROOT(name) REQUIRE(install_board_##name((void (*)(void))native_board_##name));
    ROOT(load) ROOT(save) ROOT(select) ROOT(store) ROOT(sprite)
}
#endif
static void snapshot(spx_observer *o) {
    spx_observe_object(o,NULL); spx_observe_bytes(o,"current",(const unsigned char *)&boards.current,400);
    spx_observe_bytes(o,"saved",(const unsigned char *)boards.saved,20000);
    uint32_t handles[]={file_id(boards.file),files[0].open,files[1].open,files[2].open};
    spx_observe_u32s(o,"handles",handles,4); spx_observe_u32s(o,"guards",guards,4); spx_observe_end(o);
}
int main(int argc,char **argv) {
    REQUIRE(argc==3); mode=(uint32_t)strtoul(argv[2],NULL,10); REQUIRE(mode<14);
    memset(&boards.current,0x97,400); memset(boards.saved,0xa5,20000); boards.file=&files[2];
    for (unsigned i=0;i<20000;++i) disk[i]=(unsigned char)(i*(mode==13 ? 31 : 7)+mode);
    if (mode==12) { FILE *input=fopen("default.bds","rb"); REQUIRE(input && fread(disk,1,20000,input)==20000); fclose(input); }
    uint32_t index=mode==0 ? 0 : mode==1 ? 49 : 17;
#ifndef DX_STANDALONE
    int source=!strcmp(argv[1],"source"); install(source); to_native();
#define IO_CALL(name,address) ((void (*)(const char *))(uintptr_t)address)("default.bds"); from_native(); snapshot(&o)
#define COPY_CALL(name,address,n) ((void (*)(uint32_t))(uintptr_t)address)(n); from_native(); snapshot(&o)
#define SPRITE(kind) ((uint32_t (*)(uint32_t))0x403dd0)(kind)
#define SYNC() to_native()
#else
    REQUIRE(!strcmp(argv[1],"source")); board_name path={"default.bds"};
#define IO_CALL(name,address) fixture_board_##name(&boards,&path); snapshot(&o)
#define COPY_CALL(name,address,n) fixture_board_##name(&boards,n); snapshot(&o)
#define SPRITE(kind) fixture_board_sprite(kind)
#define SYNC() ((void)0)
#endif
    fputs("{\"boards\":",stdout); spx_observer o=spx_observe_begin(stdout); spx_observe_array(&o,"states");
    IO_CALL(load,0x403d50); COPY_CALL(select,0x403ed0,index);
    for (unsigned y=0;y<20;++y) for (unsigned x=0;x<20;++x) boards.current.cells[y][x]=(unsigned char)(x+11*y+mode);
    SYNC(); COPY_CALL(store,0x403f00,index); COPY_CALL(select,0x403ed0,index ? index-1 : 49);
    IO_CALL(save,0x403d90); spx_observe_end(&o);
    uint32_t mapped[258]; for (uint32_t i=0;i<256;++i) mapped[i]=SPRITE(i);
    mapped[256]=SPRITE(0x80000000); mapped[257]=SPRITE(UINT32_MAX);
    spx_observe_u32s(&o,"sprites",mapped,258); spx_observe_u64(&o,"disk_size",disk_size);
    spx_observe_bytes(&o,"disk",disk,disk_size); spx_observe_array(&o,"calls");
    for (uint32_t i=0;i<event_count;++i) spx_observe_u32s(&o,NULL,events[i],5);
    spx_observe_end(&o); REQUIRE(spx_observe_finish(&o)); fputs("}\n",stdout);
#ifndef DX_STANDALONE
    if (source) {
        REQUIRE(install_board_load_intact() && install_board_save_intact() && install_board_select_intact()
            && install_board_store_intact() && install_board_sprite_intact());
        for (unsigned i=0;i<5;++i) REQUIRE(entries[i]);
    }
#endif
    return 0;
}
#ifndef DX_STANDALONE
static LONG WINAPI fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);
    fflush(NULL); ExitProcess(86); return EXCEPTION_EXECUTE_HANDLER;
}
struct native_startupinfo { int newmode; };
__declspec(dllimport) int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static void run_case(void) {
    SetUnhandledExceptionFilter(fault); int count; char **args,**environment; struct native_startupinfo startup={0};
    REQUIRE(__getmainargs(&count,&args,&environment,0,&startup)==0); int result=main(count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_boards_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance; (void)reserved;
    return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
