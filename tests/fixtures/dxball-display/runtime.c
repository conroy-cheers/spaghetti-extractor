/* Whole native initializer bodies with controlled platform boundaries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "display-runtime.h"
#include "spx-observation.h"
#ifndef DX_STANDALONE
#include <windows.h>
#include "native-image.h"
#include "pe32-import-hook.h"
#endif
struct spx_opaque_shell_handle_v5 { uint32_t identity; };
struct spx_opaque_shell_device_v5 { uint32_t identity; };
struct spx_opaque_shell_palette_v5 { uint32_t identity; };
struct spx_opaque_display_clipper_v5 { uint32_t identity; };
struct spx_opaque_display_events_v5 { uint32_t identity; };
static shell_handle handles[8]={{1},{2},{3},{4},{5},{6},{7},{8}};
static shell_device devices[2]={{1},{2}};
static shell_palette palette={1};
static display_clipper clippers[2]={{1},{2}};
static display_events events={1};
static font_surface surfaces[4]={{1},{2},{3},{4}};
static font_sprite sprites[3];
static struct spx_opaque_cleanup_state_v5 objects;
static asset_state assets={.objects=&objects};
static font_state font={.objects=&objects};
static pcx_state colors;
static flow_state flow={.sprites=&assets};
static title_state title={.font=&font,.palettes=&colors,.flow=&flow};
static scene_state scene={.animation=&title};
static shell_state application={.scene=&scene};
static damage_state damage={.scene=&scene};
static display_state display={.application=&application,.damage=&damage,.events=&events};
static display_history history;
uint32_t display_native_history[2] __attribute__((used));
static uint32_t mode,scenario,entered[2],calls,surface_calls,attach_calls;
static uint32_t window_live[8],device_live[2],surface_live[4],clipper_live[2];
static int source_side;
static spx_observer *observer;
static void require(int value,const char *expression,unsigned line) {
    if (!value) { fprintf(stderr,"display-runtime.c:%u: adapter premise failed: %s\n",line,expression);exit(3); }
}
#define REQUIRE(test) require(!!(test),#test,__LINE__)
#define ID(name,type,array,count) static uint32_t name##_id(const type *p) { \
    if (!p) { return 0; } \
    for (unsigned i=0;i<count;++i) { if (p==&array[i]) return i+1; } \
    REQUIRE(0);return 0; }
ID(handle,shell_handle,handles,8) ID(device,shell_device,devices,2) ID(surface,font_surface,surfaces,4)
ID(clipper,display_clipper,clippers,2) ID(sprite,font_sprite,sprites,3)
#undef ID
void display_enter(unsigned operation) { REQUIRE(operation<2);++entered[operation]; }
static void snapshot(const char *name) {
    spx_observe_object(observer,name);
    uint32_t fields[]={damage.capability,damage.clipped,scene.presentation_mode,scene.no_hardware,scene.low_memory,title.fast,
        application.active,application.control,application.shift,application.suspended,application.cursor.x,application.cursor.y,
        scene.mouse_x,scene.mouse_y,scene.mouse_buttons,flow.windowed,flow.first_frame,flow.refresh_needed,flow.scene,
        flow.next_scene,flow.transition_pending,font.bank,font.spacing,objects.current_bank};
    uint32_t roots[]={handle_id(display.window),device_id(application.graphics),clipper_id(display.clipper),
        surface_id(title.primary),surface_id(title.back),surface_id(scene.flip),surface_id(font.destination),
        handle_id(application.instance_lock),application.palette ? 1u : 0u};
    spx_observe_u32s(observer,"fields",fields,sizeof(fields)/4);spx_observe_u32s(observer,"roots",roots,sizeof(roots)/4);
    spx_observe_u32s(observer,"windows_live",window_live,8);spx_observe_u32s(observer,"devices_live",device_live,2);
    spx_observe_u32s(observer,"surfaces_live",surface_live,4);spx_observe_u32s(observer,"clippers_live",clipper_live,2);
    spx_observe_array(observer,"banks");
    for (unsigned b=0;b<3;++b) {
        spx_observe_object(observer,NULL);uint32_t slots[255];
        for (unsigned i=0;i<255;++i) slots[i]=sprite_id(objects.banks[b].slots[i]);
        spx_observe_u32s(observer,"slots",slots,255);spx_observe_u64(observer,"count",objects.banks[b].count);
        spx_observe_u32s(observer,"retained",objects.banks[b].retained,6);spx_observe_end(observer);
    }
    spx_observe_end(observer);spx_observe_array(observer,"sprites");
    for (unsigned i=0;i<3;++i) {
        spx_observe_object(observer,NULL);spx_observe_u64(observer,"surface",surface_id(sprites[i].surface));
        spx_observe_bytes(observer,"bytes",sprites[i].retained,41);spx_observe_end(observer);
    }
    spx_observe_end(observer);spx_observe_bytes(observer,"palette",(unsigned char *)colors.current,1024);spx_observe_end(observer);
}
static void begin(display_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&display && calls++<100);spx_observe_object(observer,NULL);
    spx_observe_u64(observer,"operation",operation);spx_observe_u32s(observer,"arguments",args,count);snapshot("before");
}
static uint32_t end(uint32_t result) { snapshot("after");spx_observe_u64(observer,"result",result);spx_observe_end(observer);return result; }
#define BEGIN0(name) (void)u;begin(s,DISPLAY_SERVICE_##name,NULL,0)
#define BEGIN(name,...) (void)u;const uint32_t args[]={__VA_ARGS__};begin(s,DISPLAY_SERVICE_##name,args,sizeof(args)/4)
static void name_observation(const char *field,asset_name *name) {
    REQUIRE(name && name->text);spx_observe_bytes(observer,field,(const unsigned char *)name->text,strlen(name->text));
}
static uint32_t negative(unsigned case_id) { return scenario==case_id ? UINT32_MAX : 0; }
shell_handle *display_load_icon(void *u,display_state *s,shell_handle *instance,uint32_t resource) {
    BEGIN(LOAD_ICON,handle_id(instance),resource);uint32_t result=scenario==26 ? 0 : 4;(void)end(result);return result ? &handles[3] : NULL;
}
shell_handle *display_load_cursor(void *u,display_state *s,shell_handle *instance,uint32_t resource) {
    BEGIN(LOAD_CURSOR,handle_id(instance),resource);uint32_t result=scenario==26 ? 0 : 5;(void)end(result);return result ? &handles[4] : NULL;
}
shell_handle *display_stock_object(void *u,display_state *s,uint32_t object) {
    BEGIN(STOCK_OBJECT,object);uint32_t result=scenario==26 ? 0 : 6;(void)end(result);return result ? &handles[5] : NULL;
}
void display_register_class(void *u,display_state *s,display_class *c) {
    REQUIRE(c && c->events==&events && c->menu==c->name);
    BEGIN(REGISTER_CLASS,c->style,c->class_extra,c->window_extra,1,handle_id(c->instance),handle_id(c->icon),handle_id(c->cursor),handle_id(c->brush));
    name_observation("name",c->name);name_observation("menu",c->menu);(void)end(0);
}
shell_handle *display_create_window(void *u,display_state *s,shell_handle *instance,asset_name *name,uint32_t style,uint32_t width,uint32_t height) {
    BEGIN(CREATE_WINDOW,handle_id(instance),style,width,height);name_observation("name",name);
    if (scenario==20) { application.active=2;application.control=0;s->window=&handles[6]; }
    uint32_t result=scenario==1 ? 0 : 3;
    if (result) window_live[result-1]=1;
    (void)end(result);return result ? &handles[result-1] : NULL;
}
void display_show_window(void *u,display_state *s,shell_handle *window,uint32_t command) {
    BEGIN(SHOW_WINDOW,handle_id(window),command);REQUIRE(window && window_live[handle_id(window)-1]);
    if ((scenario==20 || scenario==21) && !command) { s->window=&handles[6];application.shift=5; }
    (void)end(0);
}
void display_update_window(void *u,display_state *s,shell_handle *window) { BEGIN(UPDATE_WINDOW,handle_id(window));(void)end(0); }
void display_focus_window(void *u,display_state *s,shell_handle *window) { BEGIN(FOCUS_WINDOW,handle_id(window));(void)end(0); }
void display_initialize_sound(void *u,display_state *s,shell_handle *window) { BEGIN(INITIALIZE_SOUND,handle_id(window));(void)end(0); }
uint32_t display_create_draw(void *u,display_state *s) {
    BEGIN0(CREATE_DRAW);uint32_t result=scenario==2 || scenario==21 ? UINT32_MAX : scenario==3 ? 1 : 0;
    if (result!=UINT32_MAX) { application.graphics=&devices[0];device_live[0]=1; }
    return end(result);
}
uint32_t display_cooperative(void *u,display_state *s,shell_device *device,shell_handle *window,uint32_t flags) {
    BEGIN(COOPERATIVE,device_id(device),handle_id(window),flags);REQUIRE(device && device_live[device_id(device)-1]);return end(negative(4));
}
uint32_t display_display_mode(void *u,display_state *s,shell_device *device,uint32_t width,uint32_t height,uint32_t depth) {
    BEGIN(DISPLAY_MODE,device_id(device),width,height,depth);REQUIRE(device && device_live[device_id(device)-1]);return end(negative(5));
}
void display_capabilities(void *u,display_state *s,shell_device *device,display_caps *caps) {
    BEGIN(CAPABILITIES,device_id(device));REQUIRE(caps && caps->size==380);
    uint32_t before[]={caps->size,caps->flags,caps->video_memory};spx_observe_u32s(observer,"input",before,3);
    if (scenario!=18) {
        caps->flags=scenario==16 ? 0x02000000 : 0;
        if (scenario!=19) caps->video_memory=scenario==25 ? 0 : scenario==17 ? 309999 : 310000;
    }
    if (scenario==23) { damage.capability=2;damage.clipped=0; }
    uint32_t after[]={caps->size,caps->flags,caps->video_memory};spx_observe_u32s(observer,"output",after,3);(void)end(0);
}
static void descriptor_observation(const char *name,const display_surface *d) {
    uint32_t words[]={d->size,d->flags,d->caps,(d->flags&2) ? d->height : 0,(d->flags&4) ? d->width : 0,
        (d->flags&32) ? d->backbuffers : 0};spx_observe_u32s(observer,name,words,6);
}
uint32_t display_create_surface(void *u,display_state *s,shell_device *device,display_surface *descriptor,uint32_t slot) {
    BEGIN(CREATE_SURFACE,device_id(device),slot);REQUIRE(slot==surface_calls++ && slot<2);descriptor_observation("descriptor",descriptor);
    uint32_t result=slot ? negative(9) : scenario==6 ? UINT32_MAX : scenario==7 ? 1 : 0;
    if (result!=UINT32_MAX) {
        if (slot) title.back=&surfaces[1];else title.primary=&surfaces[0];
        surface_live[slot]=1;
    }
    if (scenario==22 && !slot) { damage.capability=0;title.primary=&surfaces[2]; }
    if (scenario==24 && !slot) descriptor->size=112;
    descriptor_observation("after_descriptor",descriptor);return end(result);
}
uint32_t display_attached_surface(void *u,display_state *s,font_surface *surface,uint32_t caps) {
    BEGIN(ATTACHED_SURFACE,surface_id(surface),caps);uint32_t result=negative(8);
    if (!result) { scene.flip=&surfaces[3];surface_live[3]=1; }
    return end(result);
}
uint32_t display_create_clipper(void *u,display_state *s,shell_device *device) {
    BEGIN(CREATE_CLIPPER,device_id(device));uint32_t result=negative(10);
    if (!result) { s->clipper=&clippers[0];clipper_live[0]=1; }
    return end(result);
}
uint32_t display_clipper_window(void *u,display_state *s,display_clipper *clipper,shell_handle *window,uint32_t flags) {
    BEGIN(CLIPPER_WINDOW,clipper_id(clipper),handle_id(window),flags);return end(negative(11));
}
uint32_t display_attach_clipper(void *u,display_state *s,font_surface *surface,display_clipper *clipper) {
    BEGIN(ATTACH_CLIPPER,surface_id(surface),clipper_id(clipper));return end(negative(attach_calls++ ? 13 : 12));
}
void display_message(void *u,display_state *s,shell_handle *window,asset_name *text,asset_name *caption,uint32_t flags) {
    BEGIN(MESSAGE,handle_id(window),flags);name_observation("text",text);name_observation("caption",caption);
    if (scenario==21) s->window=&handles[7];
    (void)end(0);
}
void display_destroy_window(void *u,display_state *s,shell_handle *window) {
    uint32_t id=handle_id(window);BEGIN(DESTROY_WINDOW,id);REQUIRE(id && window_live[id-1]);window_live[id-1]=0;
    if (scenario==21) application.active=0;
    (void)end(0);
}

#ifndef DX_STANDALONE
static uint32_t native_devices[2][1],native_surfaces[4][1],native_clippers[2][1],native_sprites[3][12];
static uint32_t draw_vtable[22],surface_vtable[29],clipper_vtable[9];
static uint32_t *word(uint32_t address) { return (uint32_t *)(uintptr_t)address; }
static uint32_t shell_handle_address(shell_handle *p) { uint32_t id=handle_id(p);return id ? 0x31000000+id*16 : 0; }
static shell_handle *shell_handle_view(uint32_t address) {
    if (!address) return NULL;
    for (unsigned i=0;i<8;++i) { if (address==shell_handle_address(&handles[i])) return &handles[i]; }
    REQUIRE(0);return NULL;
}
#define NATIVE_VIEW(name,type,array,count,id_function) \
static uint32_t name##_address(type *p) { uint32_t id=id_function(p);return id ? (uint32_t)(uintptr_t)&native_##array[id-1] : 0; } \
static type *name##_view(uint32_t address) { \
    if (!address) { return NULL; } \
    for (unsigned i=0;i<count;++i) { if (address==(uint32_t)(uintptr_t)&native_##array[i]) return &array[i]; } \
    REQUIRE(0);return NULL; }
NATIVE_VIEW(shell_device,shell_device,devices,2,device_id) NATIVE_VIEW(surface,font_surface,surfaces,4,surface_id)
NATIVE_VIEW(display_clipper,display_clipper,clippers,2,clipper_id) NATIVE_VIEW(sprite,font_sprite,sprites,3,sprite_id)
#undef NATIVE_VIEW
static uint32_t shell_palette_address(shell_palette *p) { REQUIRE(!p || p==&palette);return p ? 0x31010000 : 0; }
static shell_palette *shell_palette_view(uint32_t address) { REQUIRE(!address || address==0x31010000);return address ? &palette : NULL; }
#include "shell-native.h"
static void display_parent_to_native(void) {
    shell_to_native();*word(0x434960)=surface_address(font.destination);*word(0x43496c)=font.bank;
    *word(0x4179f8)=font.spacing;*word(0x434968)=objects.current_bank;
    for (unsigned b=0;b<3;++b) {
        uint32_t *row=word(0x433d18+0x418*b);
        for (unsigned i=0;i<255;++i) row[i]=sprite_address(objects.banks[b].slots[i]);
        row[255]=objects.banks[b].count;memcpy(row+256,objects.banks[b].retained,24);
        native_sprites[b][0]=surface_address(sprites[b].surface);memcpy((unsigned char *)native_sprites[b]+4,sprites[b].retained,41);
    }
}
static void display_parent_from_native(void) {
    shell_from_native();font.destination=surface_view(*word(0x434960));font.bank=*word(0x43496c);
    font.spacing=*word(0x4179f8);objects.current_bank=*word(0x434968);
    for (unsigned b=0;b<3;++b) {
        uint32_t *row=word(0x433d18+0x418*b);
        for (unsigned i=0;i<255;++i) objects.banks[b].slots[i]=sprite_view(row[i]);
        objects.banks[b].count=row[255];memcpy(objects.banks[b].retained,row+256,24);
        sprites[b].surface=surface_view(native_sprites[b][0]);memcpy(sprites[b].retained,(unsigned char *)native_sprites[b]+4,41);
    }
}
#include "display-native.h"
#define NATIVE_BEGIN() display_from_native()
#define NATIVE_END() display_to_native()
static HICON WINAPI native_load_icon(HINSTANCE instance,LPCSTR resource) {
    NATIVE_BEGIN();shell_handle *result=display_load_icon(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)instance),(uint32_t)(uintptr_t)resource);
    NATIVE_END();return (HICON)(uintptr_t)shell_handle_address(result);
}
static HCURSOR WINAPI native_load_cursor(HINSTANCE instance,LPCSTR resource) {
    NATIVE_BEGIN();shell_handle *result=display_load_cursor(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)instance),(uint32_t)(uintptr_t)resource);
    NATIVE_END();return (HCURSOR)(uintptr_t)shell_handle_address(result);
}
static HGDIOBJ WINAPI native_stock_object(int object) {
    NATIVE_BEGIN();shell_handle *result=display_stock_object(NULL,&display,(uint32_t)object);NATIVE_END();return (HGDIOBJ)(uintptr_t)shell_handle_address(result);
}
static ATOM WINAPI native_register_class(const WNDCLASSA *c) {
    NATIVE_BEGIN();REQUIRE(c && (uintptr_t)c->lpfnWndProc==0x40d130 && c->lpszMenuName==c->lpszClassName);
    asset_name name={c->lpszClassName};display_class view={c->style,(uint32_t)c->cbClsExtra,(uint32_t)c->cbWndExtra,&events,
        shell_handle_view((uint32_t)(uintptr_t)c->hInstance),shell_handle_view((uint32_t)(uintptr_t)c->hIcon),
        shell_handle_view((uint32_t)(uintptr_t)c->hCursor),shell_handle_view((uint32_t)(uintptr_t)c->hbrBackground),&name,&name};
    display_register_class(NULL,&display,&view);NATIVE_END();return scenario==26 ? 0 : 1;
}
static HWND WINAPI native_create_window(DWORD extended,LPCSTR class_name,LPCSTR title_name,DWORD style,int x,int y,int width,int height,HWND parent,HMENU menu,HINSTANCE instance,LPVOID parameter) {
    NATIVE_BEGIN();REQUIRE(!extended && class_name==title_name && !x && !y && !parent && !menu && !parameter);asset_name name={class_name};
    shell_handle *result=display_create_window(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)instance),&name,style,(uint32_t)width,(uint32_t)height);
    NATIVE_END();return (HWND)(uintptr_t)shell_handle_address(result);
}
static BOOL WINAPI native_show_window(HWND window,int command) { NATIVE_BEGIN();display_show_window(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)window),(uint32_t)command);NATIVE_END();return FALSE; }
static BOOL WINAPI native_update_window(HWND window) { NATIVE_BEGIN();display_update_window(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)window));NATIVE_END();return FALSE; }
static HWND WINAPI native_focus_window(HWND window) { NATIVE_BEGIN();display_focus_window(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)window));NATIVE_END();return NULL; }
static void native_sound(uint32_t window) { NATIVE_BEGIN();display_initialize_sound(NULL,&display,shell_handle_view(window));NATIVE_END(); }
static uint32_t WINAPI native_draw(void *guid,uint32_t *output,void *outer) {
    NATIVE_BEGIN();REQUIRE(!guid && output==word(0x4349a8) && !outer);uint32_t result=display_create_draw(NULL,&display);NATIVE_END();return result;
}
static uint32_t WINAPI native_cooperative(uint32_t device,uint32_t window,uint32_t flags) {
    NATIVE_BEGIN();uint32_t result=display_cooperative(NULL,&display,shell_device_view(device),shell_handle_view(window),flags);NATIVE_END();return result;
}
static uint32_t WINAPI native_display_mode(uint32_t device,uint32_t width,uint32_t height,uint32_t depth) {
    NATIVE_BEGIN();uint32_t result=display_display_mode(NULL,&display,shell_device_view(device),width,height,depth);NATIVE_END();return result;
}
static uint32_t WINAPI native_capabilities(uint32_t device,uint32_t *caps,void *other) {
    NATIVE_BEGIN();REQUIRE(caps && !other);display_caps view={caps[0],caps[1],caps[16]};
    display_capabilities(NULL,&display,shell_device_view(device),&view);caps[0]=view.size;caps[1]=view.flags;caps[16]=view.video_memory;
    NATIVE_END();return scenario==18 || scenario==19 || scenario==25 ? UINT32_MAX : 0;
}
static uint32_t WINAPI native_create_surface(uint32_t device,uint32_t *d,uint32_t *output,void *outer) {
    NATIVE_BEGIN();REQUIRE(d && !outer && (output==word(0x4349ac) || output==word(0x4349b4)));
    display_surface view={d[0],d[1],(d[1]&2) ? d[2] : 0,(d[1]&4) ? d[3] : 0,(d[1]&32) ? d[5] : 0,d[26]};
    uint32_t result=display_create_surface(NULL,&display,shell_device_view(device),&view,output==word(0x4349b4));
    d[0]=view.size;d[1]=view.flags;d[26]=view.caps;
    if (view.flags&2) d[2]=view.height;
    if (view.flags&4) d[3]=view.width;
    if (view.flags&32) d[5]=view.backbuffers;
    NATIVE_END();return result;
}
static uint32_t WINAPI native_attached_surface(uint32_t surface,uint32_t *caps,uint32_t *output) {
    NATIVE_BEGIN();REQUIRE(caps && output==word(0x4349b0));uint32_t result=display_attached_surface(NULL,&display,surface_view(surface),*caps);NATIVE_END();return result;
}
static uint32_t WINAPI native_create_clipper(uint32_t device,uint32_t flags,uint32_t *output,void *outer) {
    NATIVE_BEGIN();REQUIRE(!flags && !outer && output==word(0x4349bc));uint32_t result=display_create_clipper(NULL,&display,shell_device_view(device));NATIVE_END();return result;
}
static uint32_t WINAPI native_clipper_window(uint32_t clipper,uint32_t flags,uint32_t window) {
    NATIVE_BEGIN();uint32_t result=display_clipper_window(NULL,&display,display_clipper_view(clipper),shell_handle_view(window),flags);NATIVE_END();return result;
}
static uint32_t WINAPI native_attach_clipper(uint32_t surface,uint32_t clipper) {
    NATIVE_BEGIN();uint32_t result=display_attach_clipper(NULL,&display,surface_view(surface),display_clipper_view(clipper));NATIVE_END();return result;
}
static int WINAPI native_message(HWND window,LPCSTR text,LPCSTR caption,UINT flags) {
    NATIVE_BEGIN();asset_name t={text},c={caption};display_message(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)window),&t,&c,flags);NATIVE_END();return 0;
}
static BOOL WINAPI native_destroy_window(HWND window) { NATIVE_BEGIN();display_destroy_window(NULL,&display,shell_handle_view((uint32_t)(uintptr_t)window));NATIVE_END();return FALSE; }
#define ROOT(name) static uint32_t native_root_##name(uint32_t instance,uint32_t show) { NATIVE_BEGIN(); \
    uint32_t result=fixture_display_##name(&display,shell_handle_view(instance),show,&history);NATIVE_END();return result; }
ROOT(windowed) ROOT(fullscreen)
#undef ROOT
static void forbidden_helper(void) { REQUIRE(0); }
static void install(void) {
    draw_vtable[4]=(uint32_t)(uintptr_t)native_create_clipper;draw_vtable[6]=(uint32_t)(uintptr_t)native_create_surface;
    draw_vtable[11]=(uint32_t)(uintptr_t)native_capabilities;draw_vtable[20]=(uint32_t)(uintptr_t)native_cooperative;
    draw_vtable[21]=(uint32_t)(uintptr_t)native_display_mode;surface_vtable[12]=(uint32_t)(uintptr_t)native_attached_surface;
    surface_vtable[28]=(uint32_t)(uintptr_t)native_attach_clipper;clipper_vtable[8]=(uint32_t)(uintptr_t)native_clipper_window;
    for (unsigned i=0;i<2;++i) { native_devices[i][0]=(uint32_t)(uintptr_t)draw_vtable;native_clippers[i][0]=(uint32_t)(uintptr_t)clipper_vtable; }
    for (unsigned i=0;i<4;++i) native_surfaces[i][0]=(uint32_t)(uintptr_t)surface_vtable;
#define HOOK(name,dll,symbol) { static spx_fixture_import_hook hook;REQUIRE(spx_fixture_redirect_import(&hook,NULL,dll,symbol,(void (*)(void))native_##name)); }
#include "display-imports.h"
#undef HOOK
    REQUIRE(install_display_sound((void (*)(void))native_sound));REQUIRE(install_display_draw((void (*)(void))native_draw));
    if (!source_side) return;
    REQUIRE(install_display_windowed((void (*)(void))native_root_windowed));REQUIRE(install_display_fullscreen((void (*)(void))native_root_fullscreen));
    REQUIRE(install_display_reset(forbidden_helper));REQUIRE(install_display_bind(forbidden_helper));
}
/* Seed the two declared original-entry history words before the actual body
 * reserves its frame. Normal C never reads uninitialized stack storage. */
#define SEEDED(name,address) static uint32_t __attribute__((naked)) seeded_##name(uint32_t instance __attribute__((unused)),uint32_t show __attribute__((unused))) { \
    __asm__ volatile("movl _display_native_history, %eax\n\tmovl %eax, -0x178(%esp)\n\t" \
        "movl _display_native_history+4, %eax\n\tmovl %eax, -0x13c(%esp)\n\t" \
        "movl $" #address ", %eax\n\tjmp *%eax\n\t"); }
SEEDED(windowed,0x40cc60) SEEDED(fullscreen,0x40c810)
#undef SEEDED
#endif

static void setup(void) {
    application.graphics=&devices[1];application.palette=&palette;application.instance_lock=&handles[1];
    application.active=1;application.control=3;application.shift=4;application.suspended=7;application.cursor=(shell_point){21,22};
    scene.mouse_x=31;scene.mouse_y=32;scene.mouse_buttons=2;flow.windowed=!mode;flow.first_frame=9;flow.refresh_needed=8;
    flow.scene=3;flow.next_scene=2;flow.transition_pending=1;display.window=&handles[1];display.clipper=&clippers[1];
    title.primary=&surfaces[2];title.back=&surfaces[3];scene.flip=&surfaces[3];font.destination=&surfaces[3];
    scene.presentation_mode=6;scene.no_hardware=5;scene.low_memory=7;title.fast=8;
    damage.capability=1;damage.clipped=scenario==14 ? 0 : scenario==15 ? 2 : 1;
    history=(display_history){0x02000000,100000};display_native_history[0]=history.capability_flags;display_native_history[1]=history.video_memory;
    for (unsigned i=0;i<8;++i) window_live[i]=i!=2;
    device_live[0]=0;device_live[1]=1;clipper_live[0]=0;clipper_live[1]=1;
    for (unsigned i=0;i<4;++i) surface_live[i]=i>=2;
    font.bank=2;font.spacing=17;objects.current_bank=1;
    for (unsigned b=0;b<3;++b) {
        sprites[b].surface=&surfaces[2+(b%2)];
        for (unsigned i=0;i<41;++i) sprites[b].retained[i]=(unsigned char)(b*17+i*3);
        for (unsigned i=0;i<255;++i) objects.banks[b].slots[i]=i%7 ? NULL : &sprites[(i+b)%3];
        objects.banks[b].count=0xf0000010+b;
        for (unsigned i=0;i<6;++i) objects.banks[b].retained[i]=0xdead0000+b*16+i;
    }
    for (unsigned i=0;i<1024;++i) ((unsigned char *)colors.current)[i]=(unsigned char)(i*31+7);
}
int main(int argc,char **argv) {
    REQUIRE(argc==4);mode=(uint32_t)strtoul(argv[2],NULL,10);scenario=(uint32_t)strtoul(argv[3],NULL,10);REQUIRE(mode<2 && scenario<27);
    source_side=!strcmp(argv[1],"source");REQUIRE(source_side || !strcmp(argv[1],"original"));setup();
#ifndef DX_STANDALONE
    install();display_to_native();
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"display");snapshot("initial");
    uint32_t input[]={mode,7,history.capability_flags,history.video_memory};spx_observe_u32s(observer,"input",input,4);spx_observe_array(observer,"calls");
    uint32_t result;
#ifndef DX_STANDALONE
    result=mode ? seeded_fullscreen(shell_handle_address(&handles[0]),7) : seeded_windowed(shell_handle_address(&handles[0]),7);display_from_native();
#else
    result=mode ? fixture_display_fullscreen(&display,&handles[0],7,&history) : fixture_display_windowed(&display,&handles[0],7,&history);
#endif
    spx_observe_end(observer);snapshot("final");spx_observe_u64(observer,"result",result);spx_observe_end(observer);
    REQUIRE(spx_observe_finish(observer));fputc('\n',stdout);return 0;
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
__declspec(dllexport) void dx_display_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(run_case));
}
#endif
