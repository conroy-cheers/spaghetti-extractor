/* External input driver: observe readiness in the pinned image, never write it. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static DWORD target;
static HWND window;
static HANDLE process;
static BOOL CALLBACK find_window(HWND candidate, LPARAM unused) {
    (void)unused; DWORD pid; char name[64]; GetWindowThreadProcessId(candidate, &pid);
    GetClassNameA(candidate, name, sizeof(name));
    if (pid==target && IsWindowVisible(candidate) && !strcmp(name,"DX-Ball")) window=candidate;
    return TRUE;
}
static uint32_t read_word(uint32_t address) {
    uint32_t value; SIZE_T count;
    if (!ReadProcessMemory(process,(void *)(uintptr_t)address,&value,sizeof(value),&count) || count!=sizeof(value)) {
        fprintf(stderr,"cannot observe %08x\n",address); ExitProcess(81);
    }
    return value;
}
static int failed(unsigned code) {
    fprintf(stderr,"controller %u: phase=%u banks=%u,%u,%u pending=%u next=%u active=%u\n",code,read_word(0x431fd0),
            read_word(0x434114),read_word(0x43452c),read_word(0x434944),read_word(0x431fc8),read_word(0x431fc4),read_word(0x43498c));
    PostMessageA(window,WM_CLOSE,0,0); CloseHandle(process);return (int)code;
}
int main(void) {
    DWORD started=GetTickCount();
    while (!window && GetTickCount()-started<18000) {
        HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
        PROCESSENTRY32 entry={0};entry.dwSize=sizeof(entry);
        if (Process32First(snapshot,&entry)) do {
            if (!_stricmp(entry.szExeFile,"DXBall.exe")) {target=entry.th32ProcessID;break;}
        } while (Process32Next(snapshot,&entry));
        CloseHandle(snapshot); if (target) EnumWindows(find_window,0); if (!window) Sleep(100);
    }
    if (!window) return 82;
    process=OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,FALSE,target);if(!process)return 83;
    printf("window=%08x game_window=%08x\n",(unsigned)(uintptr_t)window,read_word(0x434974));fflush(stdout);
    DWORD last_key=0;
    while (GetTickCount()-started<30000) {
        /* Window creation precedes the splash state. Sending this sooner loses
         * the request in startup's message pumping. Its two banks identify ready. */
        if (GetTickCount()-last_key>=500 && read_word(0x431fd0)==4 && read_word(0x434114)==52 && read_word(0x43452c)==50) {
            DWORD_PTR result=0;
            if (!SendMessageTimeoutA(window,WM_KEYDOWN,VK_F2,0,SMTO_ABORTIFHUNG,1000,&result))
                fprintf(stderr,"key delivery failed: %lu\n",GetLastError());
            PostMessageA(window,WM_KEYUP,VK_F2,0);
            if (!last_key) { puts("splash ready; key posted");fflush(stdout); }
            last_key=GetTickCount();
        }
        if (read_word(0x434114)==7 && read_word(0x43452c)==48 && read_word(0x434944)==96) break;
        Sleep(50);
    }
    if (read_word(0x434114)!=7 || read_word(0x43452c)!=48 || read_word(0x434944)!=96) return failed(84);
    puts("menu assets ready");fflush(stdout);
    PostMessageA(window,WM_LBUTTONDOWN,MK_LBUTTON,MAKELPARAM(320,240));
    while (read_word(0x431fd0)!=1 && GetTickCount()-started<40000) Sleep(50);
    PostMessageA(window,WM_LBUTTONUP,0,MAKELPARAM(320,240));
    printf("phase=%u transition=%u\n",read_word(0x431fd0),read_word(0x431fc8));fflush(stdout);
    if (read_word(0x431fd0)!=1) return failed(85);
    /* Game initialization changes bank 2's count to 1 and captures its slot 1. */
    while (GetTickCount()-started<44000) {
        uint32_t sprite=read_word(0x43454c);
        if (read_word(0x434944)==1 && sprite && read_word(sprite+8)==159 && read_word(sprite+12)==479) break;
        Sleep(50);
    }
    uint32_t sprite=read_word(0x43454c);
    printf("capture bank count=%u sprite=%08x\n",read_word(0x434944),sprite);fflush(stdout);
    if (read_word(0x434944)!=1 || !sprite || read_word(sprite+8)!=159 || read_word(sprite+12)!=479) return failed(86);
    Sleep(500); PostMessageA(window,WM_CLOSE,0,0); CloseHandle(process);return 0;
}
