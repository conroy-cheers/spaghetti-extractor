/* The shell is portable; this backend still supplies the native platform. */
#define WARNING_NORMAL_LIBRARY_ONLY 1
#include "warning-normal-runtime.c"
#include "shell-runtime.h"
struct spx_opaque_shell_handle_v5 { uint32_t address; };
struct spx_opaque_shell_device_v5 { uint32_t address; };
struct spx_opaque_shell_palette_v5 { uint32_t address; };
static shell_state application={.scene=&scene};
static uint32_t shell_entries[4];
void shell_enter(unsigned operation) { REQUIRE(operation<4);++shell_entries[operation]; }
#define SHELL_VIEW(name,type) \
static type name##_pool[256];static unsigned name##_count; \
static type *name##_view(uint32_t address) { \
    if (!address) { return NULL; } \
    for (unsigned i=0;i<name##_count;++i) { if (name##_pool[i].address==address) return &name##_pool[i]; } \
    REQUIRE(name##_count<256);type *p=&name##_pool[name##_count++];p->address=address;return p; } \
static uint32_t name##_address(const type *p) { return p ? p->address : 0; }
SHELL_VIEW(shell_handle,shell_handle) SHELL_VIEW(shell_device,shell_device) SHELL_VIEW(shell_palette,shell_palette)
#undef SHELL_VIEW
#include "shell-native.h"
#define SHELL_BEGIN() (void)u;REQUIRE(s==&application);shell_to_native()
#define SHELL_END() shell_from_native()
#define NATIVE0(name,address) void shell_##name(void *u,shell_state *s) { SHELL_BEGIN();((void (*)(void))address)();SHELL_END(); }
NATIVE0(initialize_clock,0x40dba0) NATIVE0(initialize_trig,0x40d6b0) NATIVE0(frame,0x40ab10)
NATIVE0(stop_sounds,0x403460) NATIVE0(stop_music,0x402200) NATIVE0(clear_sprites,0x40bcc0)
NATIVE0(resume_music,0x4021a0) NATIVE0(suspend_sounds,0x402f20) NATIVE0(pause_music,0x4021d0)
#undef NATIVE0
#define NATIVE1(name,address) void shell_##name(void *u,shell_state *s,uint32_t value) { SHELL_BEGIN();((void (*)(uint32_t))address)(value);SHELL_END(); }
NATIVE1(shutdown,0x40ae50) NATIVE1(leave_scene,0x40aca0) NATIVE1(key,0x40abf0) NATIVE1(terminate,0x40e3d0)
#undef NATIVE1
void shell_focus_sounds(void *u,shell_state *s,shell_handle *window) {
    SHELL_BEGIN();((void (*)(uint32_t))0x402c80)(shell_handle_address(window));SHELL_END();
}
#define GRAPHICS(name,address) uint32_t shell_##name(void *u,shell_state *s,shell_handle *instance,uint32_t show) { \
    SHELL_BEGIN();uint32_t result=((uint32_t (*)(uint32_t,uint32_t))address)(shell_handle_address(instance),show);SHELL_END();return result; }
GRAPHICS(windowed_graphics,0x40cc60) GRAPHICS(fullscreen_graphics,0x40c810)
#undef GRAPHICS
shell_handle *shell_open_semaphore(void *u,shell_state *s,uint32_t access,uint32_t inherit,asset_name *name) {
    SHELL_BEGIN();HANDLE result=((HANDLE (WINAPI *)(DWORD,BOOL,LPCSTR))(uintptr_t)*word(0x41506c))(access,(BOOL)inherit,name->text);
    SHELL_END();return shell_handle_view((uint32_t)(uintptr_t)result);
}
shell_handle *shell_create_semaphore(void *u,shell_state *s,uint32_t inherit,uint32_t initial,uint32_t maximum,asset_name *name) {
    SHELL_BEGIN();SECURITY_ATTRIBUTES attributes={sizeof(attributes),NULL,(BOOL)inherit};
    HANDLE result=((HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES,LONG,LONG,LPCSTR))(uintptr_t)*word(0x415068))(&attributes,(LONG)initial,(LONG)maximum,name->text);
    SHELL_END();return shell_handle_view((uint32_t)(uintptr_t)result);
}
void shell_close_handle(void *u,shell_state *s,shell_handle *handle) {
    SHELL_BEGIN();((BOOL (WINAPI *)(HANDLE))(uintptr_t)*word(0x415034))((HANDLE)(uintptr_t)shell_handle_address(handle));SHELL_END();
}
void shell_message_box(void *u,shell_state *s,shell_handle *window,asset_name *text,asset_name *caption,uint32_t flags) {
    SHELL_BEGIN();((int (WINAPI *)(HWND,LPCSTR,LPCSTR,UINT))(uintptr_t)*word(0x415118))((HWND)(uintptr_t)shell_handle_address(window),text->text,caption->text,flags);SHELL_END();
}
void shell_cursor_position(void *u,shell_state *s,shell_point *point) {
    SHELL_BEGIN();REQUIRE(point==&s->cursor);((BOOL (WINAPI *)(LPPOINT))(uintptr_t)*word(0x41513c))((LPPOINT)0x434980);SHELL_END();
}
static void shell_message_from_native(shell_message *view,const MSG *native) {
    *view=(shell_message){shell_handle_view((uint32_t)(uintptr_t)native->hwnd),native->message,native->wParam,(uint32_t)native->lParam,native->time,(uint32_t)native->pt.x,(uint32_t)native->pt.y};
}
static void shell_message_to_native(MSG *native,const shell_message *view) {
    *native=(MSG){.hwnd=(HWND)(uintptr_t)shell_handle_address(view->window),.message=view->kind,.wParam=view->wparam,.lParam=(LPARAM)view->lparam,
        .time=view->time,.pt={(LONG)view->x,(LONG)view->y}};
}
uint32_t shell_peek_message(void *u,shell_state *s,shell_message *message) {
    SHELL_BEGIN();MSG native;BOOL result=((BOOL (WINAPI *)(LPMSG,HWND,UINT,UINT,UINT))(uintptr_t)*word(0x415164))(&native,NULL,0,0,0);
    if (result) shell_message_from_native(message,&native);
    SHELL_END();return (uint32_t)result;
}
uint32_t shell_get_message(void *u,shell_state *s,shell_message *message) {
    SHELL_BEGIN();MSG native;shell_message_to_native(&native,message);
    BOOL result=((BOOL (WINAPI *)(LPMSG,HWND,UINT,UINT))(uintptr_t)*word(0x415134))(&native,NULL,0,0);
    shell_message_from_native(message,&native);SHELL_END();return (uint32_t)result;
}
void shell_translate_message(void *u,shell_state *s,shell_message *message) {
    SHELL_BEGIN();MSG native;shell_message_to_native(&native,message);
    ((BOOL (WINAPI *)(const MSG *))(uintptr_t)*word(0x415144))(&native);
    shell_message_from_native(message,&native);SHELL_END();
}
void shell_dispatch_message(void *u,shell_state *s,shell_message *message) {
    SHELL_BEGIN();MSG native;shell_message_to_native(&native,message);
    ((LRESULT (WINAPI *)(const MSG *))(uintptr_t)*word(0x415148))(&native);
    shell_message_from_native(message,&native);SHELL_END();
}
void shell_wait_message(void *u,shell_state *s) { SHELL_BEGIN();((BOOL (WINAPI *)(void))(uintptr_t)*word(0x415140))();SHELL_END(); }
void shell_post_quit(void *u,shell_state *s,uint32_t code) { SHELL_BEGIN();((void (WINAPI *)(int))(uintptr_t)*word(0x415124))((int)code);SHELL_END(); }
void shell_set_cursor(void *u,shell_state *s,shell_handle *cursor) { SHELL_BEGIN();((HCURSOR (WINAPI *)(HCURSOR))(uintptr_t)*word(0x415120))((HCURSOR)(uintptr_t)shell_handle_address(cursor));SHELL_END(); }
void shell_post_message(void *u,shell_state *s,shell_handle *window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    SHELL_BEGIN();((BOOL (WINAPI *)(HWND,UINT,WPARAM,LPARAM))(uintptr_t)*word(0x41512c))((HWND)(uintptr_t)shell_handle_address(window),message,wparam,(LPARAM)lparam);SHELL_END();
}
void shell_capture(void *u,shell_state *s,shell_handle *window) { SHELL_BEGIN();((HWND (WINAPI *)(HWND))(uintptr_t)*word(0x415130))((HWND)(uintptr_t)shell_handle_address(window));SHELL_END(); }
void shell_release_capture(void *u,shell_state *s) { SHELL_BEGIN();((BOOL (WINAPI *)(void))(uintptr_t)*word(0x415168))();SHELL_END(); }
uint32_t shell_default_event(void *u,shell_state *s,shell_handle *window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    SHELL_BEGIN();LRESULT result=((LRESULT (WINAPI *)(HWND,UINT,WPARAM,LPARAM))(uintptr_t)*word(0x415138))((HWND)(uintptr_t)shell_handle_address(window),message,wparam,(LPARAM)lparam);
    SHELL_END();return (uint32_t)result;
}
void shell_release_surface(void *u,shell_state *s,font_surface *surface) {
    SHELL_BEGIN();uint32_t address=surface_address(surface),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[2])(address);SHELL_END();
}
void shell_release_palette(void *u,shell_state *s,shell_palette *palette) {
    SHELL_BEGIN();uint32_t address=shell_palette_address(palette),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t))(uintptr_t)table[2])(address);SHELL_END();
}
void shell_palette_entries(void *u,shell_state *s,shell_palette *palette,pcx_state *colors) {
    SHELL_BEGIN();REQUIRE(colors==title.palettes);uint32_t address=shell_palette_address(palette),*table=word(*word(address));
    ((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t,void *))(uintptr_t)table[6])(address,0,0,256,(void *)0x42c148);SHELL_END();
}
#undef SHELL_BEGIN
#undef SHELL_END
static uint32_t WINAPI live_shell_run(uint32_t instance,uint32_t previous,const char *command,uint32_t show) {
    shell_from_native();uint32_t result;
    if (source_side) { result=fixture_shell_run(&application,shell_handle_view(instance),show);shell_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_shell_run_hook));result=((uint32_t (WINAPI *)(uint32_t,uint32_t,const char *,uint32_t))0x40d010)(instance,previous,command,show);
        install_shell_run_hook.entry=NULL;REQUIRE(install_shell_run((void (*)(void))live_shell_run)); }
    return result;
}
static uint32_t WINAPI live_shell_event(uint32_t window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    shell_from_native();uint32_t result;
    if (source_side) { result=fixture_shell_event(&application,shell_handle_view(window),message,wparam,lparam);shell_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_shell_event_hook));result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t))0x40d130)(window,message,wparam,lparam);
        install_shell_event_hook.entry=NULL;REQUIRE(install_shell_event((void (*)(void))live_shell_event)); }
    return result;
}
static uint32_t live_shell_acquire(void) {
    shell_from_native();uint32_t result;
    if (source_side) { result=shell_handle_address(fixture_shell_acquire(&application));shell_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_shell_acquire_hook));result=((uint32_t (*)(void))0x40d4b0)();
        install_shell_acquire_hook.entry=NULL;REQUIRE(install_shell_acquire((void (*)(void))live_shell_acquire)); }
    return result;
}
static void live_shell_release(void) {
    shell_from_native();
    if (source_side) { fixture_shell_release(&application);shell_to_native(); }
    else { REQUIRE(spx_fixture_restore_entry(&install_shell_release_hook));((void (*)(void))0x40d500)();
        install_shell_release_hook.entry=NULL;REQUIRE(install_shell_release(live_shell_release)); }
}
static void shell_diagnose(spx_observer *o) {
    warning_diagnose(o);spx_observe_u32s(o,"selected_application_shell",shell_entries,4);
}
static void shell_report(void) {
    const char *path=getenv("SPX_COMPARISON_REPORT");if (!path) return;FILE *out=fopen(path,"wb");REQUIRE(out);
    fprintf(out,"{\"side\":\"%s\",\"exit_code\":0,\"observations\":",source_side ? "source" : "original");
    spx_observer o=spx_observe_begin(out);warning_observe(&o);
    REQUIRE(spx_observe_finish(&o));fputs(",\"diagnostics\":",out);o=spx_observe_begin(out);shell_diagnose(&o);
    REQUIRE(spx_observe_finish(&o));fputs("}\n",out);fclose(out);
}
static BOOL shell_main(HINSTANCE instance,DWORD reason,void *reserved) {
    if (!warning_main(instance,reason,reserved)) return FALSE;
    if (reason==DLL_PROCESS_DETACH) { shell_report();return TRUE; }
    if (reason!=DLL_PROCESS_ATTACH) return TRUE;
    REQUIRE(install_shell_run((void (*)(void))live_shell_run));REQUIRE(install_shell_event((void (*)(void))live_shell_event));
    REQUIRE(install_shell_acquire((void (*)(void))live_shell_acquire));REQUIRE(install_shell_release(live_shell_release));return TRUE;
}
#ifndef SHELL_NORMAL_LIBRARY_ONLY
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) { return shell_main(instance,reason,reserved); }
#endif
