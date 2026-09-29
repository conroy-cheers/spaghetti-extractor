/* Native platform backend for the portable display component. */
#define SHELL_NORMAL_LIBRARY_ONLY 1
#include "shell-normal-runtime.c"
#include "display-runtime.h"
struct spx_opaque_display_clipper_v5 { uint32_t address; };
struct spx_opaque_display_events_v5 { uint32_t address; };
static display_events display_events_target={0x40d130};
static display_state display={.application=&application,.damage=&damage,.events=&display_events_target};
static display_clipper clipper_pool[64];static uint32_t clipper_count;
static uint32_t display_entries[2],display_count,display_records[8][17];
uint32_t display_entry_history[2] __attribute__((used));
void display_enter(unsigned operation) { REQUIRE(operation<2);++display_entries[operation]; }
static uint32_t display_clipper_address(display_clipper *p) { return p ? p->address : 0; }
static display_clipper *display_clipper_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<clipper_count;++i) { if (clipper_pool[i].address==address) return &clipper_pool[i]; }
    REQUIRE(clipper_count<64);display_clipper *p=&clipper_pool[clipper_count++];p->address=address;return p;
}
static void display_parent_to_native(void) { shell_to_native();push(); }
static void display_parent_from_native(void) { shell_from_native();pull(); }
#include "display-native.h"
#define DISPLAY_BEGIN() (void)u;REQUIRE(s==&display);display_to_native()
#define DISPLAY_END() display_from_native()
shell_handle *display_load_icon(void *u,display_state *s,shell_handle *instance,uint32_t resource) {
    DISPLAY_BEGIN();HICON result=((HICON (WINAPI *)(HINSTANCE,LPCSTR))(uintptr_t)*word(0x41511c))((HINSTANCE)(uintptr_t)shell_handle_address(instance),(LPCSTR)(uintptr_t)resource);
    DISPLAY_END();return shell_handle_view((uint32_t)(uintptr_t)result);
}
shell_handle *display_load_cursor(void *u,display_state *s,shell_handle *instance,uint32_t resource) {
    DISPLAY_BEGIN();HCURSOR result=((HCURSOR (WINAPI *)(HINSTANCE,LPCSTR))(uintptr_t)*word(0x415150))((HINSTANCE)(uintptr_t)shell_handle_address(instance),(LPCSTR)(uintptr_t)resource);
    DISPLAY_END();return shell_handle_view((uint32_t)(uintptr_t)result);
}
shell_handle *display_stock_object(void *u,display_state *s,uint32_t object) {
    DISPLAY_BEGIN();HGDIOBJ result=((HGDIOBJ (WINAPI *)(int))(uintptr_t)*word(0x415010))((int)object);
    DISPLAY_END();return shell_handle_view((uint32_t)(uintptr_t)result);
}
void display_register_class(void *u,display_state *s,display_class *c) {
    DISPLAY_BEGIN();REQUIRE(c && c->events==&display_events_target);
    WNDCLASSA native={.style=c->style,.lpfnWndProc=(WNDPROC)(uintptr_t)c->events->address,
        .cbClsExtra=(int)c->class_extra,.cbWndExtra=(int)c->window_extra,.hInstance=(HINSTANCE)(uintptr_t)shell_handle_address(c->instance),
        .hIcon=(HICON)(uintptr_t)shell_handle_address(c->icon),.hCursor=(HCURSOR)(uintptr_t)shell_handle_address(c->cursor),
        .hbrBackground=(HBRUSH)(uintptr_t)shell_handle_address(c->brush),.lpszMenuName=c->menu->text,.lpszClassName=c->name->text};
    ((ATOM (WINAPI *)(const WNDCLASSA *))(uintptr_t)*word(0x415154))(&native);DISPLAY_END();
}
shell_handle *display_create_window(void *u,display_state *s,shell_handle *instance,asset_name *name,uint32_t style,uint32_t width,uint32_t height) {
    DISPLAY_BEGIN();HWND result=((HWND (WINAPI *)(DWORD,LPCSTR,LPCSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID))(uintptr_t)*word(0x41514c))
        (0,name->text,name->text,style,0,0,(int)width,(int)height,NULL,NULL,(HINSTANCE)(uintptr_t)shell_handle_address(instance),NULL);
    DISPLAY_END();return shell_handle_view((uint32_t)(uintptr_t)result);
}
void display_show_window(void *u,display_state *s,shell_handle *window,uint32_t command) {
    DISPLAY_BEGIN();((BOOL (WINAPI *)(HWND,int))(uintptr_t)*word(0x41515c))((HWND)(uintptr_t)shell_handle_address(window),(int)command);DISPLAY_END();
}
void display_update_window(void *u,display_state *s,shell_handle *window) {
    DISPLAY_BEGIN();((BOOL (WINAPI *)(HWND))(uintptr_t)*word(0x415160))((HWND)(uintptr_t)shell_handle_address(window));DISPLAY_END();
}
void display_focus_window(void *u,display_state *s,shell_handle *window) {
    DISPLAY_BEGIN();((HWND (WINAPI *)(HWND))(uintptr_t)*word(0x415158))((HWND)(uintptr_t)shell_handle_address(window));DISPLAY_END();
}
void display_initialize_sound(void *u,display_state *s,shell_handle *window) {
    DISPLAY_BEGIN();((void (*)(uint32_t))0x402c60)(shell_handle_address(window));DISPLAY_END();
}
uint32_t display_create_draw(void *u,display_state *s) {
    DISPLAY_BEGIN();uint32_t result=((uint32_t (WINAPI *)(void *,uint32_t *,void *))0x40dbe0)(NULL,word(0x4349a8),NULL);DISPLAY_END();return result;
}
uint32_t display_cooperative(void *u,display_state *s,shell_device *device,shell_handle *window,uint32_t flags) {
    DISPLAY_BEGIN();uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t))(uintptr_t)table[20])(address,shell_handle_address(window),flags);DISPLAY_END();return result;
}
uint32_t display_display_mode(void *u,display_state *s,shell_device *device,uint32_t width,uint32_t height,uint32_t depth) {
    DISPLAY_BEGIN();uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t))(uintptr_t)table[21])(address,width,height,depth);DISPLAY_END();return result;
}
void display_capabilities(void *u,display_state *s,shell_device *device,display_caps *caps) {
    DISPLAY_BEGIN();uint32_t native[95]={0};native[0]=caps->size;native[1]=caps->flags;native[16]=caps->video_memory;
    uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,void *,void *))(uintptr_t)table[11])(address,native,NULL);
    if (result) {
        fprintf(stderr,"display backend: failed GetCaps requires explicit original-caller history transport\n");fflush(NULL);ExitProcess(86);
    }
    caps->size=native[0];caps->flags=native[1];caps->video_memory=native[16];DISPLAY_END();
}
uint32_t display_create_surface(void *u,display_state *s,shell_device *device,display_surface *d,uint32_t slot) {
    DISPLAY_BEGIN();REQUIRE(slot<2);uint32_t native[27]={0};native[0]=d->size;native[1]=d->flags;native[26]=d->caps;
    if (d->flags&2) native[2]=d->height;
    if (d->flags&4) native[3]=d->width;
    if (d->flags&32) native[5]=d->backbuffers;
    uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,void *,uint32_t *,void *))(uintptr_t)table[6])(address,native,word(slot ? 0x4349b4 : 0x4349ac),NULL);
    d->size=native[0];d->flags=native[1];d->caps=native[26];
    if (d->flags&2) d->height=native[2];
    if (d->flags&4) d->width=native[3];
    if (d->flags&32) d->backbuffers=native[5];
    DISPLAY_END();return result;
}
uint32_t display_attached_surface(void *u,display_state *s,font_surface *surface,uint32_t caps) {
    DISPLAY_BEGIN();uint32_t address=surface_address(surface),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t *,uint32_t *))(uintptr_t)table[12])(address,&caps,word(0x4349b0));DISPLAY_END();return result;
}
uint32_t display_create_clipper(void *u,display_state *s,shell_device *device) {
    DISPLAY_BEGIN();uint32_t address=shell_device_address(device),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t *,void *))(uintptr_t)table[4])(address,0,word(0x4349bc),NULL);DISPLAY_END();return result;
}
uint32_t display_clipper_window(void *u,display_state *s,display_clipper *clipper,shell_handle *window,uint32_t flags) {
    DISPLAY_BEGIN();uint32_t address=display_clipper_address(clipper),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t))(uintptr_t)table[8])(address,flags,shell_handle_address(window));DISPLAY_END();return result;
}
uint32_t display_attach_clipper(void *u,display_state *s,font_surface *surface,display_clipper *clipper) {
    DISPLAY_BEGIN();uint32_t address=surface_address(surface),*table=word(*word(address));
    uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t))(uintptr_t)table[28])(address,display_clipper_address(clipper));DISPLAY_END();return result;
}
void display_message(void *u,display_state *s,shell_handle *window,asset_name *text,asset_name *caption,uint32_t flags) {
    DISPLAY_BEGIN();((int (WINAPI *)(HWND,LPCSTR,LPCSTR,UINT))(uintptr_t)*word(0x415118))((HWND)(uintptr_t)shell_handle_address(window),text->text,caption->text,flags);DISPLAY_END();
}
void display_destroy_window(void *u,display_state *s,shell_handle *window) {
    DISPLAY_BEGIN();((BOOL (WINAPI *)(HWND))(uintptr_t)*word(0x415128))((HWND)(uintptr_t)shell_handle_address(window));DISPLAY_END();
}
#undef DISPLAY_BEGIN
#undef DISPLAY_END
static void display_record(unsigned operation,uint32_t result) {
    REQUIRE(display_count<8);display_from_native();uint32_t slots=0;
    /* The successful component includes the old pure destination-binding
     * helper. Observe its actual resulting binding at this boundary instead
     * of requiring a call to an instruction that the C legitimately inlines.
     * No platform call follows that store before the initializer returns. */
    if (source_side && result) {
        ++graphics_depth;graphics_record(0,observed_surface(surface_address(font.destination)),0,0,0,0);
    }
    for (unsigned b=0;b<3;++b) for (unsigned i=0;i<255;++i) slots+=font.objects->banks[b].slots[i]!=NULL;
    uint32_t values[]={operation,result,damage.capability,damage.clipped,scene.presentation_mode,scene.no_hardware,scene.low_memory,title.fast,
        !!title.primary,!!title.back,!!scene.flip,title.primary==title.back,title.primary==scene.flip,title.back==scene.flip,
        font.destination==title.primary,slots,!!application.graphics};
    memcpy(display_records[display_count++],values,sizeof(values));
}
/* Preserve actual entry history on the instrumented original side. The source
 * normal backend instead requires complete GetCaps outputs; its private input
 * placeholders never reach a component decision and do not claim old history. */
#define ORIGINAL(name,address) static uint32_t __attribute__((naked)) original_##name(uint32_t instance __attribute__((unused)),uint32_t show __attribute__((unused))) { \
    __asm__ volatile("movl _display_entry_history, %eax\n\tmovl %eax, -0x178(%esp)\n\t" \
        "movl _display_entry_history+4, %eax\n\tmovl %eax, -0x13c(%esp)\n\t" \
        "movl $" #address ", %eax\n\tjmp *%eax\n\t"); }
ORIGINAL(display_windowed,0x40cc60) ORIGINAL(display_fullscreen,0x40c810)
#undef ORIGINAL
#define ENTRY(name,operation) \
static uint32_t live_display_##name(uint32_t,uint32_t); \
static uint32_t __attribute__((used,noinline)) display_##name##_body(uint32_t instance,uint32_t show) { \
    display_from_native();uint32_t result; \
    if (source_side) { display_history overwritten={0,0};result=fixture_display_##name(&display,shell_handle_view(instance),show,&overwritten);display_to_native(); } \
    else { REQUIRE(spx_fixture_restore_entry(&install_display_##name##_hook));result=original_display_##name(instance,show); \
        install_display_##name##_hook.entry=NULL;REQUIRE(install_display_##name((void (*)(void))live_display_##name)); } \
    display_record(operation,result);return result; } \
static uint32_t __attribute__((naked)) live_display_##name(uint32_t instance __attribute__((unused)),uint32_t show __attribute__((unused))) { \
    __asm__ volatile("movl -0x178(%esp), %eax\n\tmovl %eax, _display_entry_history\n\t" \
        "movl -0x13c(%esp), %eax\n\tmovl %eax, _display_entry_history+4\n\t" \
        "jmp _display_" #name "_body\n\t"); }
ENTRY(windowed,0) ENTRY(fullscreen,1)
#undef ENTRY
static void display_observe(spx_observer *o) {
    warning_observe(o);spx_observe_array(o,"display_setup");
    for (unsigned i=0;i<display_count;++i) spx_observe_u32s(o,NULL,display_records[i],17);
    spx_observe_end(o);
}
static void display_diagnose(spx_observer *o) { shell_diagnose(o);spx_observe_u32s(o,"selected_display_setup",display_entries,2); }
static void display_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if (!path) return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);display_observe(&o);REQUIRE(spx_observe_finish(&o));
    fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);display_diagnose(&o);REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL display_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!shell_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { display_report();return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_display_windowed((void (*)(void))live_display_windowed));REQUIRE(install_display_fullscreen((void (*)(void))live_display_fullscreen));return TRUE;
}
#ifndef DISPLAY_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return display_main(instance,reason,reserved); }
#endif
