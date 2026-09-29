/* The same explicit environment interactions drive both native sides. */
#include <windows.h>
#include <string.h>
#include "context-services.h"
#include "pe32-import-hook.h"

static spx_fixture_import_hook hooks[5];
static unsigned selected_mode;
void context_event(const char *);
static int observed_open(const char *path, int flags, ...) {
    if (strcmp(path,"/dev/urandom") || flags!=0) ExitProcess(84);
    context_event("{\"service\":\"open\",\"path\":\"/dev/urandom\",\"flags\":0}");
    return selected_mode==1 ? -1 : 731;
}
static int observed_read(int descriptor, void *bytes, unsigned length) {
    if (descriptor!=731 || length!=4) ExitProcess(84);
    context_event("{\"service\":\"read\",\"length\":4}");
    static const unsigned char entropy[4]={0x9a,0xbb,0xcd,0xfe};
    if (selected_mode==3) return -1;
    unsigned count=selected_mode==2 ? 3 : 4;
    memcpy(bytes,entropy,count);
    return (int)count;
}
static int observed_close(int descriptor) {
    if (descriptor!=731) ExitProcess(84);
    context_event("{\"service\":\"close\"}");
    return 0;
}
static int observed_process_id(void) {
    context_event("{\"service\":\"process_id\"}");
    return 0x1234;
}
static int32_t observed_time(int32_t *output) {
    context_event("{\"service\":\"time32\"}");
    if (output) *output=0x5678;
    return 0x5678;
}
void context_entropy_begin(unsigned mode) {
    if (mode>3) ExitProcess(84);
    selected_mode=mode;
    const char *names[]={"_open","_read","_close","_getpid","time"};
    void (*functions[])(void)={(void (*)(void))observed_open,(void (*)(void))observed_read,
        (void (*)(void))observed_close,(void (*)(void))observed_process_id,(void (*)(void))observed_time};
    for (unsigned i=0;i<5;i++)
        if (!spx_fixture_redirect_import(&hooks[i],"libjq-1.dll","msvcrt.dll",names[i],functions[i]))
            ExitProcess(84);
}
int spx_seed_open(const char *path, int flags) { return observed_open(path,flags); }
int spx_seed_read(int descriptor, void *bytes, unsigned length) { return observed_read(descriptor,bytes,length); }
int spx_seed_close(int descriptor) { return observed_close(descriptor); }
uint32_t spx_seed_process_id(void) { return (uint32_t)observed_process_id(); }
uint32_t spx_seed_time32(void) { return (uint32_t)observed_time(NULL); }
