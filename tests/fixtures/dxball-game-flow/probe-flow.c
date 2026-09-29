/* External frame-counted input driver for the pinned DX-Ball image.
 * Uses a hardware execution breakpoint; never patches application code/data.
 * All three comparison sides run under the same debugger and Windows messages. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#ifndef SPX_GAMEPLAY_CLOSE_FRAMES
#define SPX_GAMEPLAY_CLOSE_FRAMES 6
#endif

static HANDLE game_process, game_thread;
static DWORD game_pid, game_tid, frames, game_frames;
static uint32_t frame_return;
static int key_sent, click_sent, close_sent;
static DWORD startup_breaks[16], startup_break_count;
static DWORD breakpoint_disposition(const DEBUG_EVENT *event) {
    const EXCEPTION_DEBUG_INFO *exception = &event->u.Exception;
    uintptr_t address = (uintptr_t)exception->ExceptionRecord.ExceptionAddress;
    /* Accept one loader breakpoint per process, never a selected-body trap in
     * the pinned image. Subsequent application breakpoints remain exceptions. */
    if (!exception->dwFirstChance || (address >= 0x400000 && address < 0x460000))
        return DBG_EXCEPTION_NOT_HANDLED;
    for (DWORD i = 0; i < startup_break_count; ++i)
        if (startup_breaks[i] == event->dwProcessId) return DBG_EXCEPTION_NOT_HANDLED;
    if (startup_break_count == 16) return DBG_EXCEPTION_NOT_HANDLED;
    startup_breaks[startup_break_count++] = event->dwProcessId; return DBG_CONTINUE;
}
static uint32_t read_word(uint32_t address) {
    uint32_t value; SIZE_T count;
    if (!ReadProcessMemory(game_process, (void *)(uintptr_t)address, &value, sizeof(value), &count) || count != sizeof(value)) {
        fprintf(stderr, "cannot read %08x: %lu\n", address, GetLastError()); ExitProcess(81);
    }
    return value;
}
static int breakpoint(int resume) {
    CONTEXT context = {0}; context.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
    if (!GetThreadContext(game_thread, &context)) return 0;
    /* Count the outer frame call, independent of the caller's implementation.
     * While it runs, wait at its return address so an observation wrapper's
     * nested original-body call cannot be counted a second time. */
    context.Dr0 = frame_return ? frame_return : 0x40ab10;
    context.Dr7 = 1; context.Dr6 = 0;
    if (resume) context.EFlags |= 0x10000; /* Resume once past this execution breakpoint. */
    return SetThreadContext(game_thread, &context);
}
static int frame_input(void) {
    CONTEXT context = {0}; context.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(game_thread, &context)) return 0;
    frame_return = read_word(context.Esp);
    if (!frame_return || frame_return == 0x40ab10) return 0;
    ++frames; uint32_t scene = read_word(0x431fd0);
    HWND window = (HWND)(uintptr_t)read_word(0x434974);
    if (frames <= 20) printf("frame=%lu scene=%u pending=%u\n", frames, scene, read_word(0x431fc8));
    if (!key_sent && frames >= 3 && scene == 4) {
        if (!PostMessageW(window, WM_KEYDOWN, VK_F2, 0) || !PostMessageW(window, WM_KEYUP, VK_F2, 0)) return 0;
        key_sent = 1; printf("key at frame %lu\n", frames);
    }
    if (key_sent && !click_sent && scene == 0) {
        if (!PostMessageW(window, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(320,240))) return 0;
        click_sent = 1; printf("click at frame %lu\n", frames);
    }
    if (click_sent && scene == 1) {
        if (!game_frames++ && !PostMessageW(window, WM_LBUTTONUP, 0, MAKELPARAM(320,240))) return 0;
#ifdef SPX_GAMEPLAY_LAUNCH
        if (game_frames==2 && !PostMessageW(window, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(320,240))) return 0;
        if (game_frames==3 && !PostMessageW(window, WM_LBUTTONUP, 0, MAKELPARAM(320,240))) return 0;
#endif
        if (game_frames == SPX_GAMEPLAY_CLOSE_FRAMES && !close_sent) {
            uint32_t sprite = read_word(0x43454c);
            if (read_word(0x434944) != 1 || !sprite || read_word(sprite+8) != 159 || read_word(sprite+12) != 479) return 0;
            if (!PostMessageW(window, WM_CLOSE, 0, 0)) return 0;
            close_sent = 1; printf("close at frame %lu after capture\n", frames);
        }
    }
    fflush(stdout); return breakpoint(1);
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 2) return 80;
    wchar_t *command = GetCommandLineW();
    if (*command == L'"') { command = wcschr(command+1, L'"'); if (!command) return 80; ++command; }
    else while (*command && *command != L' ' && *command != L'\t') ++command;
    while (*command == L' ' || *command == L'\t') ++command;
    STARTUPINFOW startup = {0}; PROCESS_INFORMATION launcher = {0}; startup.cb = sizeof(startup);
    if (!CreateProcessW(argv[1], command, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &startup, &launcher)) {
        fprintf(stderr, "debug spawn: %lu\n", GetLastError()); return 82;
    }
    DWORD begun = GetTickCount(), result = 83;
    for (;;) {
        DEBUG_EVENT event; DWORD continuation = DBG_CONTINUE;
        if (GetTickCount()-begun > 35000) { fprintf(stderr, "frame driver deadline; frames=%lu\n", frames); break; }
        if (!WaitForDebugEvent(&event, 100)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
            fprintf(stderr, "debug wait: %lu\n", GetLastError()); break;
        }
        int ok = 1, finished = 0;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            CREATE_PROCESS_DEBUG_INFO *created = &event.u.CreateProcessInfo;
            wchar_t name[1024]; DWORD length = created->hFile ? GetFinalPathNameByHandleW(created->hFile, name, 1024, 0) : 0;
            if (length && length < 1024 && wcsstr(name, L"DXBall.exe")) {
                game_pid = event.dwProcessId; game_tid = event.dwThreadId;
                game_process = created->hProcess; game_thread = created->hThread;
                ok = (uintptr_t)created->lpBaseOfImage == 0x400000 && breakpoint(0);
                printf("debugged pinned game image\n"); fflush(stdout);
            }
            if (created->hFile) CloseHandle(created->hFile);
        } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_DEBUG_INFO *exception = &event.u.Exception;
            if (event.dwProcessId == game_pid && event.dwThreadId == game_tid &&
                    exception->ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
                    (uintptr_t)exception->ExceptionRecord.ExceptionAddress == (frame_return ? frame_return : 0x40ab10)) {
                if (frame_return) { frame_return = 0; ok = breakpoint(1); }
                else ok = frame_input();
            }
            else if (exception->ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) continuation = breakpoint_disposition(&event);
            else continuation = DBG_EXCEPTION_NOT_HANDLED;
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && event.dwProcessId == launcher.dwProcessId) {
            result = event.u.ExitProcess.dwExitCode;
            if (!close_sent || game_frames < SPX_GAMEPLAY_CLOSE_FRAMES) result = 84;
            finished = 1;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) ok = 0;
        if (!ok) { fprintf(stderr, "frame driver failed: %lu\n", GetLastError()); break; }
        if (finished) {
            CloseHandle(launcher.hThread); CloseHandle(launcher.hProcess);
            printf("completed frames=%lu game=%lu exit=%lu\n", frames, game_frames, result); return (int)result;
        }
    }
    TerminateProcess(launcher.hProcess, 85); CloseHandle(launcher.hThread); CloseHandle(launcher.hProcess); return 85;
}
