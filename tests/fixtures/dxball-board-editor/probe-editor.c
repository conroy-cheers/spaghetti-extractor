/* Editor clear/save workload using the existing frame-counted debug protocol.
 * Derived from dxball-game-flow/probe-flow.c; ordinary keyboard/window messages.
 * Uses a hardware execution breakpoint; never patches application code/data.
 * All three comparison sides run under the same debugger and Windows messages. */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

static HANDLE game_process, game_thread;
static DWORD game_pid, game_tid, frames, game_frames;
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
    /* Break at the main loop's call site. An original-body observation wrapper
     * also calls the entry; counting entry hits would count that frame twice. */
    context.Dr0 = 0x40d110; context.Dr7 = 1; context.Dr6 = 0;
    if (resume) context.EFlags |= 0x10000; /* Resume once past this execution breakpoint. */
    return SetThreadContext(game_thread, &context);
}
static int send_key(HWND window, WPARAM key) {
    return PostMessageW(window, WM_KEYDOWN, key, 0) && PostMessageW(window, WM_KEYUP, key, 0);
}
static int frame_input(void) {
    ++frames; uint32_t scene = read_word(0x431fd0);
    HWND window = (HWND)(uintptr_t)read_word(0x434974);
    printf("frame=%lu scene=%u pending=%u\n", frames, scene, read_word(0x431fc8));
    if (!key_sent && frames >= 3 && scene == 4) {
        if (!send_key(window, VK_F2)) return 0;
        key_sent = 1;
    }
    if (key_sent && !click_sent && scene == 0) {
        if (!PostMessageW(window, WM_KEYDOWN, VK_CONTROL, 0) || !send_key(window, VK_F1)) return 0;
        click_sent = 1;
    }
    if (click_sent && scene == 2) {
        ++game_frames;
        if (game_frames == 1) {
            if (!PostMessageW(window, WM_KEYUP, VK_CONTROL, 0) || !send_key(window, VK_BACK)) return 0;
            printf("clear current board\n");
        }
        if (game_frames == 2) {
            for (uint32_t i=0;i<400;i+=4) if (read_word(0x42ca60+i)) return 0;
            if (!send_key(window, 'S')) return 0;
            printf("save changed collection\n");
        }
        if (game_frames == 4 && !close_sent) {
            for (uint32_t i=0;i<400;i+=4) if (read_word(0x42cdf8+i)) return 0;
            if (!PostMessageW(window, WM_CLOSE, 0, 0)) return 0;
            close_sent = 1; printf("close after native editor save\n");
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
                    (uintptr_t)exception->ExceptionRecord.ExceptionAddress == 0x40d110) ok = frame_input();
            else if (exception->ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) continuation = breakpoint_disposition(&event);
            else continuation = DBG_EXCEPTION_NOT_HANDLED;
        } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && event.dwProcessId == launcher.dwProcessId) {
            result = event.u.ExitProcess.dwExitCode;
            if (!close_sent || game_frames < 4) result = 84;
            finished = 1;
        }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation)) ok = 0;
        if (!ok) { fprintf(stderr, "frame driver failed: %lu\n", GetLastError()); break; }
        if (finished) {
            CloseHandle(launcher.hThread); CloseHandle(launcher.hProcess);
            printf("completed frames=%lu editor=%lu exit=%lu\n", frames, game_frames, result); return (int)result;
        }
    }
    TerminateProcess(launcher.hProcess, 85); CloseHandle(launcher.hThread); CloseHandle(launcher.hProcess); return 85;
}
