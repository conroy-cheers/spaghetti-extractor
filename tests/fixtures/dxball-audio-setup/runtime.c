/* Reuse the independently executable bank over the same records and providers. */
#include <setjmp.h>
#define main bank_test_main
#define DllMain bank_test_DllMain
#include "bank-runtime.c"
#undef DllMain
#undef main
#include "setup-runtime.h"
#ifndef DX_STANDALONE
#include "comparison-services.h"
#endif
struct spx_opaque_shell_handle_v5 { uint32_t identity; };
struct spx_opaque_shell_device_v5 { uint32_t identity; };
static shell_handle setup_window={1};
static shell_device setup_graphics={1};
static shell_state setup_application;
static audio_setup_state configuration={.bank=&sound,.application=&setup_application};
static uint32_t setup_case,setup_entries[2],terminated,termination_code;
static jmp_buf setup_exit;
void setup_enter(unsigned operation) { REQUIRE(operation<2);++setup_entries[operation]; }
static void setup_begin(audio_setup_state *s,unsigned operation,const uint32_t *args,unsigned count) {
    REQUIRE(s==&configuration);begin(s->bank,100+operation,args,count);
    spx_observe_u64(observer,"graphics_before",s->application->graphics!=NULL);
}
static uint32_t setup_end(uint32_t result) {
    spx_observe_u64(observer,"graphics_after",setup_application.graphics!=NULL);return end(result);
}
#define SETUP_BEGIN0(name) (void)u;setup_begin(s,SETUP_SERVICE_##name,NULL,0)
#define SETUP_BEGIN(name,...) (void)u;const uint32_t args[]={__VA_ARGS__};setup_begin(s,SETUP_SERVICE_##name,args,sizeof(args)/sizeof(*args))
void setup_release_all(void *u,audio_setup_state *s) {
    (void)u;REQUIRE(s==&configuration);fixture_audio_release_all(s->bank,&history);
}
uint32_t setup_create_device(void *u,audio_setup_state *s) {
    (void)u;REQUIRE(s==&configuration);spx_wine_call call={0};call.api=SPX_DS_CREATE;
#ifndef DX_STANDALONE
    call.output=word(0x42ca10);
#else
    call.output=&s->bank->device;
#endif
    return platform_call(call);
}
uint32_t setup_cooperative(void *u,audio_setup_state *s,audio_device *device,shell_handle *window,uint32_t level) {
    (void)u;REQUIRE(s==&configuration);spx_wine_call call={0};call.api=SPX_DS_COOPERATIVE;call.receiver=(void *)device;
    call.window=window->identity;call.arguments[0]=level;call.argument_count=1;return platform_call(call);
}
uint32_t setup_create_primary(void *u,audio_setup_state *s,audio_device *device,audio_buffer_spec *spec) {
    (void)u;REQUIRE(s==&configuration);spx_wine_call call={0};call.api=SPX_DS_CREATE_BUFFER;call.receiver=(void *)device;
    spx_wine_buffer_spec view={spec->size,spec->flags,spec->bytes,spec->reserved,spec->format};call.input=&view;
#ifndef DX_STANDALONE
    call.output=word(0x42ca14);
#else
    call.output=&s->bank->primary;
#endif
    return platform_call(call);
}
uint32_t setup_play_primary(void *u,audio_setup_state *s,audio_buffer *buffer,uint32_t flags) {
    (void)u;REQUIRE(s==&configuration);return platform_method(SPX_DS_PLAY,buffer,flags,NULL);
}
void setup_release_buffer(void *u,audio_setup_state *s,audio_buffer *buffer) { (void)u;REQUIRE(s==&configuration);audio_release_buffer(NULL,s->bank,buffer); }
void setup_release_device(void *u,audio_setup_state *s,audio_device *device) { (void)u;REQUIRE(s==&configuration);audio_release_device(NULL,s->bank,device); }
uint32_t setup_message(void *u,audio_setup_state *s,shell_handle *window,audio_name *text,audio_name *caption,uint32_t flags) {
    (void)u;REQUIRE(s==&configuration);spx_wine_call call={0};call.api=SPX_USER_MESSAGE_A;
    call.window=window->identity;call.text=text->text;call.caption=caption->text;call.arguments[0]=flags;call.argument_count=1;
    return platform_call(call);
}
void setup_terminate(void *u,audio_setup_state *s,uint32_t code) {
    SETUP_BEGIN(TERMINATE,code);terminated=1;termination_code=code;(void)setup_end(0);longjmp(setup_exit,1);
}
void setup_load_sample(void *u,audio_setup_state *s,uint32_t slot,audio_name *name) {
    (void)u;REQUIRE(s==&configuration);audio_load_sample(NULL,s->bank,slot,name);
}
#undef SETUP_BEGIN0
#undef SETUP_BEGIN

#ifndef DX_STANDALONE
static void setup_to_native(void) {
    audio_to_native();*word(0x4349a8)=setup_application.graphics ? 0x4349a8 : 0;
}
static void setup_from_native(void) {
    audio_from_native();setup_application.graphics=*word(0x4349a8) ? &setup_graphics : NULL;
}
static void native_setup_terminate(uint32_t code) { setup_from_native();setup_terminate(NULL,&configuration,code); }
#define SETUP_ROOT(name) static void native_setup_##name(uint32_t window) { \
    REQUIRE(window==1);setup_from_native();fixture_setup_##name(&configuration,&setup_window);setup_to_native(); }
SETUP_ROOT(initialize) SETUP_ROOT(focus)
#undef SETUP_ROOT
static void setup_install(void) {
    install();sync_from=setup_from_native;sync_to=setup_to_native;
    REQUIRE(spx_wine_install(wine_environment,NULL,1,1));
    REQUIRE(install_setup_terminate((void (*)(void))native_setup_terminate));
    if (!source_side) return;
    REQUIRE(install_setup_initialize((void (*)(void))native_setup_initialize));REQUIRE(install_setup_focus((void (*)(void))native_setup_focus));
}
#endif
static void setup_callback(uint32_t action) {
    switch(action) {
    case 100:setup_application.graphics=&setup_graphics;break;
    case 101:setup_application.graphics=NULL;break;
    case 102:sound.device=devices[1];break;
    case 103:sound.primary=buffers[6];break;
    case 104:sound.slots[4]=&samples[1];sound.slots[17]=NULL;break;
    default:bank_callback(action);
    }
}
static void setup_schedule(void) {
    uint32_t create_error=0;
    if(setup_case==2 || setup_case==3 || setup_case==9 || setup_case==20 || setup_case==29)create_error=UINT32_C(0x80004005);
    if(setup_case==4 || setup_case==5)create_error=UINT32_C(0x88780078);
    if(setup_case==7 || setup_case==8)create_error=UINT32_C(0x8878000a);
    /* Finite occurrence schedules keep retry inputs explicit and replayable. */
    for(unsigned i=1;i<=4;++i) {
        uint32_t result=create_error;
        if((setup_case==6 && i==1) || (setup_case==30 && i<3))result=UINT32_C(0x8878000a);
        if(setup_case==33)result=1;
        uint32_t flags=SPX_RULE_RETURN|((!result || setup_case==33) ? SPX_RULE_OBJECT : SPX_RULE_NO_WRITE);
        spx_wine_add_rule(wine_environment,(spx_wine_rule){.api=SPX_DS_CREATE,.occurrence=i,.flags=flags,.result=result,.object=9,.references=2});
    }
    if(setup_case==10 || setup_case==11 || setup_case==12 || setup_case==21 || setup_case==24 || setup_case==31)
        rule(SPX_DS_COOPERATIVE,0,0,SPX_RULE_RETURN,setup_case==31 ? 1 : UINT32_C(0x80004005),0);
    uint32_t failed=(setup_case>=13 && setup_case<=16) || setup_case==22 || setup_case==23;
    spx_wine_add_rule(wine_environment,(spx_wine_rule){.api=SPX_DS_CREATE_BUFFER,
        .flags=SPX_RULE_RETURN|(setup_case==13 ? SPX_RULE_NO_WRITE : SPX_RULE_OBJECT),
        .result=failed ? (setup_case==14 ? 1 : UINT32_C(0x80004005)) : 0,.object=8,.references=4});
    if(setup_case==17 || setup_case==18 || setup_case==19 || setup_case==32)
        rule(SPX_DS_PLAY,8,0,SPX_RULE_RETURN,setup_case==32 ? 1 : UINT32_C(0x80004005),0);
    for(unsigned i=1;i<=4;++i) {
        uint32_t answer=setup_case==3 || setup_case==5 || setup_case==11 || setup_case==15 || setup_case==18 ? 7 :
            setup_case==8 ? 3 : setup_case==7 ? 5 : setup_case==6 ? 4 : setup_case==29 ? 0 : setup_case==30 ? (i>1 ? 4 : 0) : 6;
        rule(SPX_USER_MESSAGE_A,0,i,SPX_RULE_RETURN,answer,0);
    }
    if(setup_case==20)rule(SPX_DS_CREATE,0,0,SPX_RULE_CALLBACK,0,100);
    if(setup_case==21)rule(SPX_DS_COOPERATIVE,0,0,SPX_RULE_CALLBACK,0,101);
    if(setup_case==22)rule(SPX_DS_CREATE_BUFFER,0,0,SPX_RULE_CALLBACK,0,102);
    if(setup_case==23)rule(SPX_COM_RELEASE,8,0,SPX_RULE_CALLBACK,0,103);
    if(setup_case==24)rule(SPX_COM_RELEASE,9,0,SPX_RULE_CALLBACK,0,102);
    if(setup_case==25)rule(SPX_DS_PLAY,8,0,SPX_RULE_CALLBACK,0,104);
}
static void configure(void) {
    scenario=1000;setup();application_callback=setup_callback;setup_schedule();sound.device=setup_case==0 || setup_case==28 ? devices[0] : NULL;sound.primary=NULL;
    spx_wine_bind_window(wine_environment,setup_window.identity,1);
    setup_application.graphics=setup_case==9 || setup_case==12 || setup_case==16 || setup_case==19 || setup_case==21 ? &setup_graphics : NULL;
    if (setup_case==26) for (unsigned i=0;i<50;++i) sound.slots[i]=NULL;
}
static void setup_run(unsigned operation) {
#ifndef DX_STANDALONE
    setup_to_native();((void (*)(uint32_t))(uintptr_t)(operation ? 0x402c80 : 0x402c60))(1);setup_from_native();
#else
    if (operation) fixture_setup_focus(&configuration,&setup_window);
    else fixture_setup_initialize(&configuration,&setup_window);
#endif
}
int main(int argc,char **argv) {
    REQUIRE(argc==3);setup_case=(uint32_t)strtoul(argv[2],NULL,10);REQUIRE(setup_case<36);
    source_side=!strcmp(argv[1],"source");REQUIRE(source_side || !strcmp(argv[1],"original"));configure();
#ifndef DX_STANDALONE
    setup_install();setup_to_native();
#else
    REQUIRE(source_side);
#endif
    spx_observer out=spx_observe_begin(stdout);observer=&out;spx_observe_object(observer,"audio_setup");snapshot("initial");
    spx_observe_u64(observer,"graphics_initial",setup_application.graphics!=NULL);spx_observe_array(observer,"calls");
#ifndef DX_STANDALONE
    uint32_t handler=source_side ? spx_service_handler_begin() : 0;
#endif
    if (!setjmp(setup_exit)) {
        setup_run(setup_case==27 || setup_case==28 ? 0 : 1);
        if (setup_case==34 || setup_case==35) {
            if (setup_case==35) { run_operation(0,0,0,0,0);loaded=0;setup_run(1); }
            setup_run(0);
        }
    } else {
        REQUIRE(terminated);
#ifndef DX_STANDALONE
        if (source_side) spx_service_handler_catch(handler,"process-exit");
#endif
    }
#ifndef DX_STANDALONE
    if (source_side) spx_service_handler_end(handler);
#endif
    spx_observe_end(observer);snapshot("final");spx_observe_u64(observer,"graphics_final",setup_application.graphics!=NULL);
    uint32_t outcome[]={terminated,termination_code};spx_observe_u32s(observer,"outcome",outcome,2);spx_wine_observe(wine_environment,observer,"platform");
    spx_observe_end(observer);REQUIRE(spx_observe_finish(observer));fputc('\n',stdout);return 0;
}
#ifndef DX_STANDALONE
static void setup_run_case(void) {
    SetUnhandledExceptionFilter(fault);int argc;char **argv,**environment;struct native_startupinfo startup={0};
    REQUIRE(!__getmainargs(&argc,&argv,&environment,0,&startup));int result=main(argc,argv);fflush(NULL);ExitProcess((UINT)result);
}
__declspec(dllexport) void dx_audio_setup_anchor(void) {}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved) {
    (void)instance;(void)reserved;return reason!=DLL_PROCESS_ATTACH || ((uintptr_t)GetModuleHandleA(NULL)==0x400000 && install_startup(setup_run_case));
}
#endif
