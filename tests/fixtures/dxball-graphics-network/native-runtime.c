/* Experimental original-x86 oracle for the existing four graphics boundaries.
 * Windows loads the fixed-base original as the main executable. An imported
 * observer redirects startup to the existing case driver. Game startup and
 * real DirectDraw remain outside this controlled component experiment.
 */
#include <windows.h>
#include "pe32-entry-hook.h"
#include "pe32-import-hook.h"
#include "native-image.h"
#define DX_NATIVE_ORACLE 1
#include "runtime.c"

static uint32_t tables[4][32], objects[4], sprites[3][16];
static const uint32_t handles[]={DRAW,PRIMARY,BACKBUFFER,CLIPPER};
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t encode(uint32_t value) {
  for (unsigned i=0;i<4;++i) if (value==handles[i]) return (uint32_t)(uintptr_t)&objects[i];
  return value; /* The reviewed state also contains deliberately invalid words. */
}
static uint32_t decode(uint32_t value) {
  for (unsigned i=0;i<4;++i) if (value==(uint32_t)(uintptr_t)&objects[i]) return handles[i];
  return value;
}
static int handle_slot(uint32_t address) {
  return address==0x4349a8 || address==0x4349ac || address==0x4349b4 ||
      address==0x4349bc || address==0x434960;
}
static void to_native(void) {
  fixture *f=&storage; store_state(f);
  for (unsigned i=0;i<sizeof(globals)/sizeof(*globals);++i) {
    uint32_t address=globals[i].address, value=get(f,address);
    *word(address)=handle_slot(address) ? encode(value) : value;
  }
  for (unsigned b=0;b<3;++b) {
    for (unsigned j=0;j<262;++j) {
      uint32_t address=BANKS+BANK_BYTES*b+4*j, value=get(f,address);
      if (j<255 && value) {
        struct dx_sprite *sprite=sprite_pointer(f,value);
        value=(uint32_t)(uintptr_t)sprites[sprite-f->sprites];
      }
      *word(address)=value;
    }
    sprites[b][0]=encode(f->sprites[b].surface);
    for (unsigned j=0;j<4;++j) sprites[b][5+j]=f->sprites[b].rectangle[j];
  }
  *word(0x4349b0)=get(f,0x4349b0); *word(0x4349b8)=get(f,0x4349b8);
}
static void from_native(void) {
  fixture *f=&storage;
  for (unsigned i=0;i<sizeof(globals)/sizeof(*globals);++i) {
    uint32_t address=globals[i].address, value=*word(address);
    put(f,address,handle_slot(address) ? decode(value) : value);
  }
  for (unsigned b=0;b<3;++b) {
    for (unsigned j=0;j<262;++j) {
      uint32_t address=BANKS+BANK_BYTES*b+4*j, value=*word(address);
      if (j<255 && value) {
        unsigned k=0;
        for (;k<3;++k) if (value==(uint32_t)(uintptr_t)sprites[k]) break;
        dx_require(k<3); value=SPRITE+64*k;
      }
      put(f,address,value);
    }
    /* These operations read sprites; unexplained pointee writes are a failure. */
    dx_require(decode(sprites[b][0])==f->sprites[b].surface);
    for (unsigned j=0;j<4;++j) dx_require(sprites[b][5+j]==f->sprites[b].rectangle[j]);
  }
  put(f,0x4349b0,*word(0x4349b0)); put(f,0x4349b8,*word(0x4349b8));
  load_state(f);
}

/* Each native service imports the current shared state before its observation
 * and exports callback mutations before returning to the original instruction.
 * No original component is replaced by a C algorithm on this side. */
static int32_t WINAPI native_draw(void *guid, uint32_t *output, void *outer) {
  dx_require(!guid && output==word(0x4349a8) && !outer); from_native();
  int32_t result=dx_create_draw(NULL,&storage.state); to_native(); return result;
}
static int32_t WINAPI native_cooperative(uint32_t draw, uint32_t window, uint32_t flags) {
  from_native(); int32_t result=dx_cooperative(NULL,&storage.state,decode(draw),window,flags);
  to_native(); return result;
}
static int32_t WINAPI native_caps(uint32_t draw, uint32_t *caps, void *other) {
  dx_require(caps && caps[0]==0x17c && !other); from_native();
  caps[1]=dx_caps(NULL,&storage.state,decode(draw)); to_native();
  return storage.caps_failure ? -1 : 0;
}
static int32_t WINAPI native_surface(uint32_t draw, const uint32_t *desc,
                                     uint32_t *output, void *outer) {
  unsigned kind=output==word(0x4349b4);
  dx_require(!outer && (kind || output==word(0x4349ac)) && desc && desc[0]==0x6c &&
      desc[1]==(kind ? 7U : 1U) && desc[26]==(kind ? 0x40U : 0x200U));
  if (kind) dx_require(desc[2]==480 && desc[3]==640);
  from_native(); int32_t result=dx_create_surface(NULL,&storage.state,decode(draw),kind);
  to_native(); return result;
}
static int32_t WINAPI native_clipper(uint32_t draw, uint32_t flags, uint32_t *output, void *outer) {
  dx_require(!flags && output==word(0x4349bc) && !outer); from_native();
  int32_t result=dx_create_clipper(NULL,&storage.state,decode(draw)); to_native(); return result;
}
static int32_t WINAPI native_window(uint32_t clipper, uint32_t flags, uint32_t window) {
  dx_require(!flags); from_native();
  int32_t result=dx_clipper_window(NULL,&storage.state,decode(clipper),window);
  to_native(); return result;
}
static int32_t WINAPI native_attach(uint32_t primary, uint32_t clipper) {
  from_native(); int32_t result=dx_attach(NULL,&storage.state,decode(primary),decode(clipper));
  to_native(); return result;
}
static int WINAPI __attribute__((used)) native_hide(uint32_t window, int show) {
  dx_require(!show); from_native(); dx_hide(NULL,&storage.state,window); to_native(); return 0;
}
static uint32_t WINAPI native_message(uint32_t window, const char *text, const char *caption, unsigned flags) {
  static const uint32_t messages[]={0x417aac,0x417bf0,0x417bc0,0x417b8c,0x417b5c,0x417b24,0x417ae8};
  unsigned kind=0;
  for (unsigned i=0;i<7;++i) if ((uintptr_t)text==messages[i]) kind=i+1;
  dx_require(kind && (uintptr_t)caption==0x41639c && !flags); from_native();
  uint32_t result=dx_message(NULL,&storage.state,window,kind); to_native(); return result;
}
static int WINAPI native_destroy(uint32_t window) {
  from_native(); dx_destroy(NULL,&storage.state,window); to_native(); return 1;
}
static uint32_t WINAPI native_blit(uint32_t destination, uint32_t x, uint32_t y,
                                   uint32_t source, const uint32_t *rect, uint32_t flags) {
  unsigned found=0;
  for (unsigned i=0;i<3;++i) found|=rect==&sprites[i][5];
  dx_require(found); from_native();
  uint32_t result=dx_blit_fast(NULL,&storage.state,decode(destination),x,y,decode(source),
      rect[0],rect[1],rect[2],rect[3],flags);
  to_native(); return result;
}

/* The reviewed cd5c cut is inside a function. Recreate its saved ESI/EBX and
 * 0x210-byte local frame, keeping the real C caller's saved registers/return.
 * The original tail removes that frame itself. This is adapter-only x86 code. */
static uint32_t __attribute__((naked)) enter_initialize(void) {
  __asm__ volatile(
      "subl $0x210, %esp\n\tpushl %ebx\n\tpushl %esi\n\t"
      "leal 8(%esp), %edx\n\tmovl $132, %ecx\n"
      "1: movl $0xcdcdcdcd, (%edx)\n\taddl $4, %edx\n\tloop 1b\n\t"
      "movl $_native_hide@8, %esi\n\tmovl $0x33333333, %ebx\n\tcld\n\t"
      "movl $0x40cd5c, %eax\n\tjmp *%eax\n\t");
}
void original_reset(dx_graphics *state) {
  (void)owner(state); to_native(); ((void (*)(void))(uintptr_t)0x40bc90)(); from_native();
}
void original_bind(dx_graphics *state, uint32_t surface) {
  (void)owner(state); to_native(); ((void (*)(uint32_t))(uintptr_t)0x40bd60)(encode(surface)); from_native();
}
uint32_t original_blit(dx_graphics *state, uint32_t index, uint32_t x, uint32_t y) {
  (void)owner(state); to_native();
  uint32_t result=((uint32_t (*)(uint32_t,uint32_t,uint32_t))(uintptr_t)0x40bd90)(index,x,y);
  from_native(); return result;
}
uint32_t original_initialize(dx_graphics *state) {
  (void)owner(state); to_native(); uint32_t result=enter_initialize(); from_native(); return result;
}

static void forbidden_body(void) {
  fputs("source execution entered an original component body\n",stderr); ExitProcess(4);
}
int main(int, char **);
/* MSVCRT's argument parser is needed because the original CRT entry is skipped. */
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *, char ***, char ***, int, struct native_startupinfo *);
static void run_case(void) {
  int count; char **args, **environment; struct native_startupinfo startup={0};
  dx_require(__getmainargs(&count,&args,&environment,0,&startup)==0);
  dx_require(count==8);
  if (!strcmp(args[1],"source")) {
    static spx_fixture_entry_hook hooks[4];
    for (unsigned i=0;i<4;++i)
      dx_require(spx_fixture_redirect_address_body(&hooks[i],(unsigned char *)(uintptr_t)native_ranges[i][0],
          native_prefixes[i],native_ranges[i][1],forbidden_body));
  }
  int result=main((int)count,args); fflush(NULL); ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_graphics_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved) {
  (void)instance; (void)reserved;
  if (reason!=DLL_PROCESS_ATTACH) return TRUE;
  if ((uintptr_t)GetModuleHandleA(NULL)!=0x400000) return FALSE;
  for (unsigned i=0;i<4;++i) objects[i]=(uint32_t)(uintptr_t)tables[i];
  tables[0][0x50/4]=(uint32_t)(uintptr_t)native_cooperative;
  tables[0][0x2c/4]=(uint32_t)(uintptr_t)native_caps;
  tables[0][0x18/4]=(uint32_t)(uintptr_t)native_surface;
  tables[0][0x10/4]=(uint32_t)(uintptr_t)native_clipper;
  tables[1][0x70/4]=(uint32_t)(uintptr_t)native_attach;
  tables[1][0x1c/4]=tables[2][0x1c/4]=(uint32_t)(uintptr_t)native_blit;
  tables[3][0x20/4]=(uint32_t)(uintptr_t)native_window;
  static spx_fixture_import_hook imports[3]; static spx_fixture_entry_hook entry;
  return spx_fixture_redirect_import(&imports[0],NULL,"DDRAW.dll","DirectDrawCreate",(void(*)(void))native_draw) &&
      spx_fixture_redirect_import(&imports[1],NULL,"USER32.dll","MessageBoxA",(void(*)(void))native_message) &&
      spx_fixture_redirect_import(&imports[2],NULL,"USER32.dll","DestroyWindow",(void(*)(void))native_destroy) &&
      spx_fixture_redirect_address_body(&entry,(unsigned char *)(uintptr_t)0x40eaa0,native_entry_prefix,5,run_case);
}
