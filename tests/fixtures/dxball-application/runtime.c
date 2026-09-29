/* Native shell control flow with local objects and a deterministic message queue. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "shell-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#include "pe32-import-hook.h"
#include "comparison-services.h"
#endif
struct spx_opaque_shell_handle_v5 { uint32_t identity; };
struct spx_opaque_shell_device_v5 { uint32_t identity; };
struct spx_opaque_shell_palette_v5 { uint32_t identity; };
static shell_handle handles[5]={{1},{2},{3},{4},{5}};
static shell_device device={1};
static shell_palette palettes[2]={{1},{2}};
static font_surface surfaces[4]={{1},{2},{3},{4}};
static struct spx_opaque_cleanup_state_v5 objects;
static asset_state assets={.objects=&objects};
static font_state font={.objects=&objects};
static pcx_state colors;
static flow_state flow={.sprites=&assets};
static title_state title={.font=&font,.palettes=&colors,.flow=&flow};
static scene_state scene={.animation=&title};
static shell_state application={.scene=&scene};
static uint32_t scenario,entered[4],calls,stage,cursor_calls,terminated,exit_code;
static uint32_t handle_live[5],surface_live[4],palette_live[2];
static int source_side;
static jmp_buf exit_landing;
static spx_observer *observer;
static void require(int value,const char *expression,unsigned line) {
    if (!value) { fprintf(stderr,"shell-runtime.c:%u: adapter premise failed: %s\n",line,expression);exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
#define ID(name,type,array,count) static uint32_t name##_id(const type *p) { \
    if (!p) { return 0; } \
    for (unsigned i=0;i<count;++i) { if (p==&array[i]) return i+1; } \
    REQUIRE(0);return 0; }
ID(handle,shell_handle,handles,5) ID(surface,font_surface,surfaces,4) ID(palette,shell_palette,palettes,2)
#undef ID
void shell_enter(unsigned operation) { REQUIRE(operation<4);++entered[operation]; }
static uint32_t call_event(uint32_t message,uint32_t wparam,uint32_t lparam);
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={application.active,application.control,application.shift,application.suspended,
        application.cursor.x,application.cursor.y,scene.mouse_x,scene.mouse_y,scene.mouse_buttons,
        flow.windowed,flow.refresh_needed,flow.first_frame,flow.scene,flow.next_scene,flow.transition_pending};
    uint32_t roots[]={handle_id(application.instance_lock),application.graphics ? 1u : 0u,palette_id(application.palette),
        surface_id(title.primary),surface_id(title.back),surface_id(scene.flip)};
    spx_observe_u32s(observer,"fields",fields,15);spx_observe_u32s(observer,"roots",roots,6);
    spx_observe_u32s(observer,"handles_live",handle_live,5);spx_observe_u32s(observer,"surfaces_live",surface_live,4);
    spx_observe_u32s(observer,"palettes_live",palette_live,2);spx_observe_bytes(observer,"colors",(unsigned char *)colors.current,1024);
    spx_observe_end(observer);
}
static void begin(shell_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&application && calls++<1000);spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation);spx_observe_u32s(observer,"arguments",args,count);snapshot("before");
}
static uint32_t end(uint32_t result) {
    snapshot("after");spx_observe_u64(observer,"result",result);spx_observe_end(observer);return result;
}
static void message_observation(const char *name,const shell_message *m) {
    uint32_t fields[]={handle_id(m->window),m->kind,m->wparam,m->lparam,m->time,m->x,m->y};
    spx_observe_u32s(observer,name,fields,7);
}
#define BEGIN0(name) (void)u;begin(s,SHELL_SERVICE_##name,NULL,0)
#define BEGIN(name,...) (void)u;const uint32_t args[]={__VA_ARGS__};begin(s,SHELL_SERVICE_##name,args,sizeof(args)/sizeof(*args))
static void name_observation(const char *name,asset_name *text) {
    REQUIRE(text && text->text);spx_observe_bytes(observer,name,(const unsigned char *)text->text,strlen(text->text));
}
shell_handle *shell_open_semaphore(void *u,shell_state *s,uint32_t access,uint32_t inherit,asset_name *name) {
    BEGIN(OPEN_SEMAPHORE,access,inherit);name_observation("name",name);
    uint32_t exists=scenario==1 || scenario==22;
    if (exists) handle_live[2]=1;
    (void)end(exists ? 3 : 0);return exists ? &handles[2] : NULL;
}
shell_handle *shell_create_semaphore(void *u,shell_state *s,uint32_t inherit,uint32_t initial,uint32_t maximum,asset_name *name) {
    BEGIN(CREATE_SEMAPHORE,inherit,initial,maximum);name_observation("name",name);
    uint32_t success=scenario!=2;if (success) handle_live[1]=1;
    (void)end(success ? 2 : 0);return success ? &handles[1] : NULL;
}
void shell_close_handle(void *u,shell_state *s,shell_handle *handle) {
    uint32_t id=handle_id(handle);BEGIN(CLOSE_HANDLE,id);REQUIRE(id && handle_live[id-1]);handle_live[id-1]=0;
    if (scenario==3) { handle_live[3]=1;s->instance_lock=&handles[3]; }
    (void)end(0);
}
void shell_message_box(void *u,shell_state *s,shell_handle *window,asset_name *text,asset_name *caption,uint32_t flags) {
    BEGIN(MESSAGE_BOX,handle_id(window),flags);name_observation("text",text);name_observation("caption",caption);(void)end(0);
}
void shell_terminate(void *u,shell_state *s,uint32_t code) {
    BEGIN(TERMINATE,code);terminated=1;exit_code=code;(void)end(0);longjmp(exit_landing,1);
}
static uint32_t graphics(shell_state *s,unsigned operation,shell_handle *instance,uint32_t show) {
    uint32_t args[]={handle_id(instance),show};begin(s,operation,args,2);
    spx_observe_array(observer,"callbacks");
    if (scenario==24) (void)call_event(SHELL_ACTIVATE,1,0);
    spx_observe_end(observer);
    return end(scenario==21 ? 0 : scenario==20 ? UINT32_MAX : 1);
}
uint32_t shell_windowed_graphics(void *u,shell_state *s,shell_handle *instance,uint32_t show) {
    (void)u;return graphics(s,SHELL_SERVICE_WINDOWED_GRAPHICS,instance,show);
}
uint32_t shell_fullscreen_graphics(void *u,shell_state *s,shell_handle *instance,uint32_t show) {
    (void)u;return graphics(s,SHELL_SERVICE_FULLSCREEN_GRAPHICS,instance,show);
}
#define SIMPLE(name,operation) void shell_##name(void *u,shell_state *s) { BEGIN0(operation);(void)end(0); }
SIMPLE(initialize_clock,INITIALIZE_CLOCK) SIMPLE(initialize_trig,INITIALIZE_TRIG)
SIMPLE(stop_sounds,STOP_SOUNDS) SIMPLE(stop_music,STOP_MUSIC) SIMPLE(clear_sprites,CLEAR_SPRITES)
SIMPLE(resume_music,RESUME_MUSIC) SIMPLE(suspend_sounds,SUSPEND_SOUNDS) SIMPLE(pause_music,PAUSE_MUSIC)
SIMPLE(release_capture,RELEASE_CAPTURE)
#undef SIMPLE
void shell_frame(void *u,shell_state *s) { BEGIN0(FRAME);REQUIRE(stage==0);++stage;(void)end(0); }
void shell_wait_message(void *u,shell_state *s) { BEGIN0(WAIT_MESSAGE);REQUIRE(stage==0);++stage;s->active=1;(void)end(0); }
void shell_cursor_position(void *u,shell_state *s,shell_point *point) {
    BEGIN0(CURSOR_POSITION);REQUIRE(point==&s->cursor);
    if (scenario!=18) { point->x=100+cursor_calls;point->y=UINT32_C(0xfffffff0)-cursor_calls; }
    ++cursor_calls;
    if (scenario==10) { s->control=9;scene.mouse_buttons=7; }
    (void)end(0);
}
static void queued_message(shell_message *m) {
    *m=(shell_message){.window=&handles[0],.kind=stage==1 ? SHELL_KEY_DOWN : stage==2 ? SHELL_MOUSE_MOVE : stage==3 ? SHELL_DESTROY : 18,
        .wparam=stage==1 ? 17 : stage==4 ? (scenario==27 ? UINT32_C(0xf0000001) : 42) : 73,
        .lparam=0x81234567,.time=654,.x=0xfffffffb,.y=321};
}
uint32_t shell_peek_message(void *u,shell_state *s,shell_message *message) {
    BEGIN0(PEEK_MESSAGE);REQUIRE(stage<=4);
    if (stage) { queued_message(message);message_observation("message",message); }
    return end(stage ? 1 : 0);
}
uint32_t shell_get_message(void *u,shell_state *s,shell_message *message) {
    BEGIN0(GET_MESSAGE);REQUIRE(stage>0 && stage<=4);message_observation("before_message",message);
    uint32_t result=stage==4 ? 0 : scenario==26 && stage==2 ? UINT32_MAX : 1;
    if (result!=UINT32_MAX) queued_message(message);
    ++stage;message_observation("message",message);return end(result);
}
void shell_translate_message(void *u,shell_state *s,shell_message *message) {
    BEGIN0(TRANSLATE_MESSAGE);message_observation("before_message",message);
    if (scenario==25 && message->kind==SHELL_KEY_DOWN) message->wparam=16;
    message_observation("message",message);(void)end(0);
}
void shell_dispatch_message(void *u,shell_state *s,shell_message *message) {
    BEGIN0(DISPATCH_MESSAGE);message_observation("message",message);
    spx_observe_array(observer,"callbacks");
    (void)call_event(message->kind,message->wparam,message->lparam);
    spx_observe_end(observer);(void)end(0);
}
void shell_shutdown(void *u,shell_state *s,uint32_t reason) { BEGIN(SHUTDOWN,reason);(void)end(0); }
void shell_focus_sounds(void *u,shell_state *s,shell_handle *window) {
    BEGIN(FOCUS_SOUNDS,handle_id(window));if (scenario==11) s->suspended=2;(void)end(0);
}
void shell_leave_scene(void *u,shell_state *s,uint32_t reason) {
    BEGIN(LEAVE_SCENE,reason);flow.scene=3;(void)end(0);
}
void shell_key(void *u,shell_state *s,uint32_t key) {
    BEGIN(KEY,key);if (scenario==6) { s->control=9;s->shift=8; }(void)end(0);
}
void shell_post_quit(void *u,shell_state *s,uint32_t code) { BEGIN(POST_QUIT,code);(void)end(0); }
void shell_set_cursor(void *u,shell_state *s,shell_handle *cursor) { BEGIN(SET_CURSOR,handle_id(cursor));(void)end(0); }
void shell_post_message(void *u,shell_state *s,shell_handle *window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    BEGIN(POST_MESSAGE,handle_id(window),message,wparam,lparam);(void)end(0);
}
void shell_capture(void *u,shell_state *s,shell_handle *window) { BEGIN(CAPTURE,handle_id(window));scene.mouse_buttons=99;(void)end(0); }
uint32_t shell_default_event(void *u,shell_state *s,shell_handle *window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    BEGIN(DEFAULT_EVENT,handle_id(window),message,wparam,lparam);return end(message^wparam^lparam);
}
void shell_release_surface(void *u,shell_state *s,font_surface *surface) {
    uint32_t id=surface_id(surface);BEGIN(RELEASE_SURFACE,id);REQUIRE(id && surface_live[id-1]);surface_live[id-1]=0;
    if (scenario==17 && id==2) { title.primary=&surfaces[2];scene.flip=&surfaces[3];s->palette=&palettes[1]; }
    (void)end(0);
}
void shell_release_palette(void *u,shell_state *s,shell_palette *palette) {
    uint32_t id=palette_id(palette);BEGIN(RELEASE_PALETTE,id);REQUIRE(id && palette_live[id-1]);palette_live[id-1]=0;(void)end(0);
}
void shell_palette_entries(void *u,shell_state *s,shell_palette *palette,pcx_state *entries) {
    BEGIN(PALETTE_ENTRIES,palette_id(palette));REQUIRE(entries==&colors && palette && palette_live[palette_id(palette)-1]);
    entries->current[0][0]^=0x5a;(void)end(0);
}

#ifndef DX_STANDALONE
static uint32_t native_surfaces[4][1],native_palettes[2][1],surface_vtable[3],palette_vtable[7];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t shell_handle_address(shell_handle *handle) { uint32_t id=handle_id(handle);return id ? 0x30000000+id*16 : 0; }
static shell_handle *shell_handle_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<5;++i) { if (address==shell_handle_address(&handles[i])) return &handles[i]; }
    REQUIRE(0);return NULL;
}
static uint32_t shell_device_address(shell_device *value) { REQUIRE(!value || value==&device);return value ? 0x30001000 : 0; }
static shell_device *shell_device_view(uint32_t address) { REQUIRE(!address || address==0x30001000);return address ? &device : NULL; }
#define NATIVE_VIEW(name,type,array,count,id_function) \
static uint32_t name##_address(type *p) { uint32_t id=id_function(p);return id ? (uint32_t)(uintptr_t)&native_##array[id-1] : 0; } \
static type *name##_view(uint32_t address) { if (!address) return NULL; \
    for (unsigned i=0;i<count;++i) { if (address==(uint32_t)(uintptr_t)&native_##array[i]) return &array[i]; } \
    REQUIRE(0);return NULL; }
NATIVE_VIEW(surface,font_surface,surfaces,4,surface_id)
NATIVE_VIEW(shell_palette,shell_palette,palettes,2,palette_id)
#undef NATIVE_VIEW
#include "shell-native.h"
static void message_from_native(shell_message *view,const MSG *native) {
    *view=(shell_message){shell_handle_view((uint32_t)(uintptr_t)native->hwnd),native->message,native->wParam,(uint32_t)native->lParam,native->time,(uint32_t)native->pt.x,(uint32_t)native->pt.y};
}
static void message_to_native(MSG *native,const shell_message *view) {
    *native=(MSG){.hwnd=(HWND)(uintptr_t)shell_handle_address(view->window),.message=view->kind,.wParam=view->wparam,.lParam=(LPARAM)view->lparam,
        .time=view->time,.pt={(LONG)view->x,(LONG)view->y}};
}
#define SYNC() shell_to_native()
#define NATIVE_BEGIN() shell_from_native()
#define NATIVE_END() shell_to_native()
static HANDLE WINAPI native_open_semaphore(DWORD access,BOOL inherit,LPCSTR name) {
    NATIVE_BEGIN();asset_name text={name};shell_handle *result=shell_open_semaphore(NULL,&application,access,(uint32_t)inherit,&text);NATIVE_END();return (HANDLE)(uintptr_t)shell_handle_address(result);
}
static HANDLE WINAPI native_create_semaphore(LPSECURITY_ATTRIBUTES attributes,LONG initial,LONG maximum,LPCSTR name) {
    NATIVE_BEGIN();REQUIRE(attributes && attributes->nLength==12 && !attributes->lpSecurityDescriptor);asset_name text={name};
    shell_handle *result=shell_create_semaphore(NULL,&application,(uint32_t)attributes->bInheritHandle,(uint32_t)initial,(uint32_t)maximum,&text);
    NATIVE_END();return (HANDLE)(uintptr_t)shell_handle_address(result);
}
static BOOL WINAPI native_close_handle(HANDLE handle) { NATIVE_BEGIN();shell_close_handle(NULL,&application,shell_handle_view((uint32_t)(uintptr_t)handle));NATIVE_END();return FALSE; }
static int WINAPI native_message_box(HWND window,LPCSTR text,LPCSTR caption,UINT flags) {
    NATIVE_BEGIN();asset_name t={text},c={caption};shell_message_box(NULL,&application,shell_handle_view((uint32_t)(uintptr_t)window),&t,&c,flags);NATIVE_END();return 0;
}
static void native_terminate(uint32_t code) { NATIVE_BEGIN();shell_terminate(NULL,&application,code); }
#define NATIVE_GRAPHICS(name) static uint32_t native_##name(uint32_t instance,uint32_t show) { NATIVE_BEGIN(); \
    uint32_t result=shell_##name(NULL,&application,shell_handle_view(instance),show);NATIVE_END();return result; }
NATIVE_GRAPHICS(windowed_graphics) NATIVE_GRAPHICS(fullscreen_graphics)
#undef NATIVE_GRAPHICS
#define NATIVE0(name) static void native_##name(void) { NATIVE_BEGIN();shell_##name(NULL,&application);NATIVE_END(); }
NATIVE0(initialize_clock) NATIVE0(initialize_trig) NATIVE0(stop_sounds) NATIVE0(stop_music)
NATIVE0(clear_sprites) NATIVE0(resume_music) NATIVE0(suspend_sounds) NATIVE0(pause_music)
NATIVE0(frame)
#undef NATIVE0
#define NATIVE1(name) static void native_##name(uint32_t value) { NATIVE_BEGIN();shell_##name(NULL,&application,value);NATIVE_END(); }
NATIVE1(shutdown) NATIVE1(leave_scene) NATIVE1(key)
#undef NATIVE1
static void native_focus_sounds(uint32_t window) { NATIVE_BEGIN();shell_focus_sounds(NULL,&application,shell_handle_view(window));NATIVE_END(); }
static BOOL WINAPI native_cursor_position(LPPOINT point) {
    NATIVE_BEGIN();REQUIRE(point==(LPPOINT)(uintptr_t)0x434980);shell_cursor_position(NULL,&application,&application.cursor);NATIVE_END();return scenario!=18;
}
static BOOL WINAPI native_peek_message(LPMSG message,HWND window,UINT first,UINT last,UINT remove) {
    NATIVE_BEGIN();REQUIRE(!window && !first && !last && !remove);shell_message view;
    uint32_t result=shell_peek_message(NULL,&application,&view);if (result) message_to_native(message,&view);NATIVE_END();return (BOOL)result;
}
static BOOL WINAPI native_get_message(LPMSG message,HWND window,UINT first,UINT last) {
    NATIVE_BEGIN();REQUIRE(!window && !first && !last);shell_message view;message_from_native(&view,message);
    uint32_t result=shell_get_message(NULL,&application,&view);message_to_native(message,&view);NATIVE_END();return (BOOL)result;
}
static BOOL WINAPI native_translate_message(const MSG *message) {
    NATIVE_BEGIN();shell_message view;message_from_native(&view,message);shell_translate_message(NULL,&application,&view);
    message_to_native((MSG *)message,&view);NATIVE_END();return TRUE;
}
static LRESULT WINAPI native_dispatch_message(const MSG *message) {
    NATIVE_BEGIN();shell_message view;message_from_native(&view,message);shell_dispatch_message(NULL,&application,&view);NATIVE_END();return 0;
}
static BOOL WINAPI native_wait_message(void) { NATIVE_BEGIN();shell_wait_message(NULL,&application);NATIVE_END();return TRUE; }
static void WINAPI native_post_quit(int code) { NATIVE_BEGIN();shell_post_quit(NULL,&application,(uint32_t)code);NATIVE_END(); }
static HCURSOR WINAPI native_set_cursor(HCURSOR cursor) { NATIVE_BEGIN();shell_set_cursor(NULL,&application,shell_handle_view((uint32_t)(uintptr_t)cursor));NATIVE_END();return NULL; }
static BOOL WINAPI native_post_message(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
    NATIVE_BEGIN();shell_post_message(NULL,&application,shell_handle_view((uint32_t)(uintptr_t)window),message,wparam,(uint32_t)lparam);NATIVE_END();return FALSE;
}
static HWND WINAPI native_capture(HWND window) { NATIVE_BEGIN();shell_capture(NULL,&application,shell_handle_view((uint32_t)(uintptr_t)window));NATIVE_END();return NULL; }
static BOOL WINAPI native_release_capture(void) { NATIVE_BEGIN();shell_release_capture(NULL,&application);NATIVE_END();return FALSE; }
static LRESULT WINAPI native_default_event(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
    NATIVE_BEGIN();uint32_t result=shell_default_event(NULL,&application,shell_handle_view((uint32_t)(uintptr_t)window),message,wparam,(uint32_t)lparam);NATIVE_END();return (LRESULT)result;
}
static uint32_t WINAPI native_release_surface(uint32_t surface) { NATIVE_BEGIN();shell_release_surface(NULL,&application,surface_view(surface));NATIVE_END();return 0; }
static uint32_t WINAPI native_release_palette(uint32_t palette) { NATIVE_BEGIN();shell_release_palette(NULL,&application,shell_palette_view(palette));NATIVE_END();return 0; }
static uint32_t WINAPI native_palette_entries(uint32_t palette,uint32_t flags,uint32_t first,uint32_t count,void *entries) {
    NATIVE_BEGIN();REQUIRE(!flags && !first && count==256 && entries==(void *)0x42c148);
    shell_palette_entries(NULL,&application,shell_palette_view(palette),&colors);NATIVE_END();return 0;
}
static uint32_t WINAPI native_root_run(uint32_t instance,uint32_t previous,const char *command,uint32_t show) {
    (void)previous;(void)command;NATIVE_BEGIN();uint32_t result=fixture_shell_run(&application,shell_handle_view(instance),show);NATIVE_END();return result;
}
static uint32_t WINAPI native_root_event(uint32_t window,uint32_t message,uint32_t wparam,uint32_t lparam) {
    NATIVE_BEGIN();uint32_t result=fixture_shell_event(&application,shell_handle_view(window),message,wparam,lparam);NATIVE_END();return result;
}
static uint32_t native_root_acquire(void) { NATIVE_BEGIN();shell_handle *result=fixture_shell_acquire(&application);NATIVE_END();return shell_handle_address(result); }
static void native_root_release(void) { NATIVE_BEGIN();fixture_shell_release(&application);NATIVE_END(); }
static void install(void) {
    surface_vtable[2]=(uint32_t)(uintptr_t)native_release_surface;
    palette_vtable[2]=(uint32_t)(uintptr_t)native_release_palette;palette_vtable[6]=(uint32_t)(uintptr_t)native_palette_entries;
    for (unsigned i=0;i<4;++i) native_surfaces[i][0]=(uint32_t)(uintptr_t)surface_vtable;
    for (unsigned i=0;i<2;++i) native_palettes[i][0]=(uint32_t)(uintptr_t)palette_vtable;
#define HOOK(name,dll,symbol) { static spx_fixture_import_hook hook;REQUIRE(spx_fixture_redirect_import(&hook,NULL,dll,symbol,(void (*)(void))native_##name)); }
#include "shell-imports.h"
#undef HOOK
#define HOOK(name) REQUIRE(install_shell_service_##name((void (*)(void))native_##name));
    HOOK(windowed_graphics) HOOK(fullscreen_graphics) HOOK(initialize_clock) HOOK(initialize_trig) HOOK(frame)
    HOOK(shutdown) HOOK(stop_sounds) HOOK(stop_music) HOOK(clear_sprites) HOOK(focus_sounds) HOOK(resume_music)
    HOOK(suspend_sounds) HOOK(pause_music) HOOK(leave_scene) HOOK(key) HOOK(terminate)
#undef HOOK
    if (!source_side) return;
#define HOOK(name) REQUIRE(install_shell_##name((void (*)(void))native_root_##name));
    HOOK(run) HOOK(event) HOOK(acquire) HOOK(release)
#undef HOOK
}
#else
#define SYNC() ((void)0)
#endif

static uint32_t call_event(uint32_t message,uint32_t wparam,uint32_t lparam) {
    SYNC();uint32_t result;
#ifndef DX_STANDALONE
    result=((uint32_t (WINAPI *)(uint32_t,uint32_t,uint32_t,uint32_t))0x40d130)(shell_handle_address(&handles[0]),message,wparam,lparam);
    shell_from_native();
#else
    result=fixture_shell_event(&application,&handles[0],message,wparam,lparam);
#endif
    return result;
}
static void event_case(uint32_t message,uint32_t wparam) {
    uint32_t result=call_event(message,wparam,0x81234567);
    spx_observe_object(observer,NULL);spx_observe_u64(observer,"event_result",result);snapshot("state");spx_observe_end(observer);
}
static void setup(void) {
    application=(shell_state){.scene=&scene,.instance_lock=&handles[1],.graphics=&device,.palette=&palettes[0],
        .cursor={0x80000001,33},.active=scenario==23 ? 0 : 1,.control=3,.shift=4,.suspended=5};
    title.primary=&surfaces[0];title.back=&surfaces[1];scene.flip=&surfaces[3];
    scene.mouse_x=9;scene.mouse_y=10;scene.mouse_buttons=6;
    flow.windowed=scenario==20 ? 0 : 1;flow.scene=4;flow.next_scene=3;flow.first_frame=0;flow.refresh_needed=7;flow.transition_pending=0;
    for (unsigned i=0;i<5;++i) handle_live[i]=1;
    for (unsigned i=0;i<4;++i) surface_live[i]=1;
    palette_live[0]=palette_live[1]=1;
    for (unsigned i=0;i<1024;++i) ((unsigned char *)colors.current)[i]=(unsigned char)(i*31+7);
    if (scenario==4) application.instance_lock=NULL;
    if (scenario==7) flow.scene=0;
    if (scenario==16) application.graphics=NULL;
}
static uint32_t run(void) {
    if (scenario<=2) {
        SYNC();
#ifndef DX_STANDALONE
        uint32_t result=((uint32_t (*)(void))0x40d4b0)();shell_from_native();return handle_id(shell_handle_view(result));
#else
        return handle_id(fixture_shell_acquire(&application));
#endif
    }
    if (scenario<=4) {
        SYNC();
#ifndef DX_STANDALONE
        ((void (*)(void))0x40d500)();shell_from_native();
#else
        fixture_shell_release(&application);
#endif
        return 0;
    }
    if (scenario==5) { const uint32_t messages[]={1,20,0,15,515,UINT32_MAX};for (unsigned i=0;i<6;++i) event_case(messages[i],19); }
    else if (scenario==6) { event_case(SHELL_ACTIVATE,0x80000001);event_case(SHELL_KEY_DOWN,17);event_case(SHELL_KEY_DOWN,16);event_case(SHELL_KEY_UP,17);event_case(SHELL_KEY_UP,16); }
    else if (scenario==7 || scenario==8) event_case(SHELL_KEY_DOWN,27);
    else if (scenario==9) { const uint32_t messages[]={513,516,514,517,32};for (unsigned i=0;i<5;++i) event_case(messages[i],0); }
    else if (scenario==10 || scenario==18) event_case(SHELL_MOUSE_MOVE,33);
    else if (scenario==11) { event_case(SHELL_FOCUS_GAIN,0);event_case(SHELL_FOCUS_LOSS,0);application.suspended=0;event_case(SHELL_FOCUS_LOSS,0);application.graphics=NULL;event_case(SHELL_FOCUS_GAIN,0); }
    else if (scenario==12 || scenario==13) { for (unsigned i=0;i<9;++i) event_case(scenario==12 ? SHELL_POWER : SHELL_POWER_BROADCAST,i); }
    else if (scenario==14) {
        flow.first_frame=1;event_case(SHELL_QUERY_PALETTE,0);flow.first_frame=0;application.graphics=NULL;event_case(SHELL_QUERY_PALETTE,0);
        application.graphics=&device;title.primary=NULL;event_case(SHELL_QUERY_PALETTE,0);title.primary=&surfaces[0];event_case(SHELL_QUERY_PALETTE,0);
    } else if (scenario<=17) event_case(SHELL_DESTROY,73);
    else {
        SYNC();
#ifndef DX_STANDALONE
        uint32_t result=((uint32_t (WINAPI *)(uint32_t,uint32_t,const char *,uint32_t))0x40d010)(shell_handle_address(&handles[0]),0,"ignored command",7);shell_from_native();return result;
#else
        return fixture_shell_run(&application,&handles[0],7);
#endif
    }
    return 0;
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);scenario=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(scenario<28);
    source_side=!strcmp(argv[1],"source");REQUIRE(source_side || !strcmp(argv[1],"original"));setup();
#ifndef DX_STANDALONE
    install();
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"application");snapshot("initial");spx_observe_array(observer,"calls");
    uint32_t result=0;
#ifndef DX_STANDALONE
    uint32_t handler=source_side ? spx_service_handler_begin() : 0;
#endif
    if (!setjmp(exit_landing)) result=run();
    else {
        REQUIRE(scenario==22 && terminated);
#ifndef DX_STANDALONE
        if (source_side) spx_service_handler_catch(handler,"process-exit");
#endif
    }
#ifndef DX_STANDALONE
    if (source_side) spx_service_handler_end(handler);
#endif
    spx_observe_end(observer);snapshot("final");uint32_t outcome[]={result,terminated,exit_code};spx_observe_u32s(observer,"outcome",outcome,3);
    spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));fputc('\n',stdout);return 0;
}
#ifndef DX_STANDALONE
struct native_startupinfo { int newmode; };
int __cdecl __getmainargs(int *,char ***,char ***,int,struct native_startupinfo *);
static LONG WINAPI fault(EXCEPTION_POINTERS *p) {
    fprintf(stderr,"native fault %08lx at %08lx\n",p->ExceptionRecord->ExceptionCode,p->ContextRecord->Eip);fflush(NULL);ExitProcess(86);return EXCEPTION_EXECUTE_HANDLER;
}
static void run_case(void) {
    SetUnhandledExceptionFilter(fault);int argc;char **argv,**environment;struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_shell_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
