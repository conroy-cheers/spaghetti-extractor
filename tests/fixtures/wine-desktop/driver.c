/* Candidate-neutral desktop workload driver. No image addresses, application
 * names or original/replacement roles: act on the process that we launch. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DWORD target;
static HWND window;
static BOOL CALLBACK find_window(HWND candidate, LPARAM unused) {
    (void)unused; DWORD pid;
    GetWindowThreadProcessId(candidate, &pid);
    if (pid==target && IsWindowVisible(candidate) && !GetWindow(candidate, GW_OWNER)) {
        window=candidate; return FALSE;
    }
    return TRUE;
}
static int capture(const char *path) {
    RECT area;
    if (!GetClientRect(window, &area) || area.right<=0 || area.bottom<=0) return 0;
    HDC source=GetDC(window), copy=CreateCompatibleDC(source);
    BITMAPINFO info={0};
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth=area.right;
    info.bmiHeader.biHeight=area.bottom; info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32;
    void *pixels=NULL;
    HBITMAP bitmap=CreateDIBSection(source, &info, DIB_RGB_COLORS, &pixels, NULL, 0);
    int result=0;
    if (bitmap) {
        HGDIOBJ previous=SelectObject(copy, bitmap);
        if (BitBlt(copy, 0, 0, area.right, area.bottom, source, 0, 0, SRCCOPY)) {
            BITMAPFILEHEADER header={0}; header.bfType=0x4d42;
            header.bfOffBits=sizeof(header)+sizeof(info.bmiHeader);
            size_t bytes=(size_t)area.right*(size_t)area.bottom*4;
            header.bfSize=header.bfOffBits+(DWORD)bytes;
            FILE *out=fopen(path, "wb");
            if (out) {
                result=fwrite(&header, sizeof(header), 1, out)==1 &&
                    fwrite(&info.bmiHeader, sizeof(info.bmiHeader), 1, out)==1 && fwrite(pixels, 1, bytes, out)==bytes;
                if (fclose(out)) result=0;
            }
        }
        SelectObject(copy, previous); DeleteObject(bitmap);
    }
    DeleteDC(copy); ReleaseDC(window, source); return result;
}
static int snapshot(const char *name, unsigned sequence, HANDLE process) {
    RECT area; POINT origin={0};
    if (!GetClientRect(window, &area) || !ClientToScreen(window, &origin)) return 0;
    FILE *request=fopen("desktop-control/snapshot.tmp", "wb");
    if (!request) return 0;
    int written=fprintf(request, "%u %s %ld %ld %ld %ld\n", sequence, name,
        origin.x, origin.y, area.right, area.bottom)>0;
    if (fclose(request) || !written ||
        !MoveFileExA("desktop-control/snapshot.tmp", "desktop-control/snapshot.request", MOVEFILE_REPLACE_EXISTING)) return 0;
    DWORD started=GetTickCount();
    while (GetTickCount()-started<10000) {
        FILE *response=fopen("desktop-control/snapshot.done", "rb");
        if (response) {
            unsigned received, ok;
            int matched=fscanf(response, "%u %u", &received, &ok)==2 && received==sequence;
            fclose(response);
            if (matched) return ok==1;
        }
        if (WaitForSingleObject(process, 10)==WAIT_OBJECT_0) return 0;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc!=3) { fputs("usage: desktop-driver CANDIDATE.exe ACTIONS.txt\n", stderr); return 2; }
    FILE *actions=fopen(argv[2], "r");
    if (!actions) return 3;
    STARTUPINFOA startup={0}; startup.cb=sizeof(startup); startup.dwFlags=STARTF_USESTDHANDLES;
    startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE); startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process={0};
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, TRUE, 0, NULL, NULL, &startup, &process)) {
        fprintf(stderr, "candidate launch failed: %lu\n", GetLastError()); fclose(actions); return 4;
    }
    CloseHandle(process.hThread); target=process.dwProcessId;
    DWORD started=GetTickCount(), status=STILL_ACTIVE;
    while (!window && GetTickCount()-started<20000) {
        EnumWindows(find_window, 0);
        if (WaitForSingleObject(process.hProcess, 20)==WAIT_OBJECT_0) break;
    }
    if (window) {
        char class_name[256]={0}, title[256]={0}; RECT client={0};
        GetClassNameA(window, class_name, sizeof(class_name)); GetWindowTextA(window, title, sizeof(title));
        GetClientRect(window, &client);
        /* Do not interleave driver diagnostics with candidate trace writes. */
        FILE *log=fopen("desktop-driver.log", "wb");
        if (log) {
            fprintf(log, "desktop window: class=%s title=%s client=%ldx%ld\n", class_name, title, client.right, client.bottom);
            fclose(log);
        }
    }
    char action[32]; unsigned executed=0; int error=!window;
    while (!error && fscanf(actions, "%31s", action)==1) {
        if (!strcmp(action, "wait")) {
            unsigned delay; if (fscanf(actions, "%u", &delay)!=1 || delay>30000) { error=1; break; }
            if (WaitForSingleObject(process.hProcess, delay)==WAIT_OBJECT_0) { error=1; break; }
        } else if (!strcmp(action, "message")) {
            unsigned message, wparam, lparam;
            if (fscanf(actions, "%u %u %u", &message, &wparam, &lparam)!=3 ||
                !PostMessageA(window, message, wparam, (LPARAM)lparam)) { error=1; break; }
        } else if (!strcmp(action, "move")) {
            int x,y; if (fscanf(actions, "%d %d", &x, &y)!=2 || !SetCursorPos(x,y)) { error=1; break; }
        } else if (!strcmp(action, "capture")) {
            char path[260]; if (fscanf(actions, "%259s", path)!=1 || !capture(path)) { error=1; break; }
        } else if (!strcmp(action, "snapshot")) {
            char name[260];
            if (fscanf(actions, "%259s", name)!=1 || !snapshot(name, executed, process.hProcess)) { error=1; break; }
        } else { error=1; break; }
        ++executed;
    }
    fclose(actions);
    if (window) PostMessageA(window, WM_CLOSE, 0, 0);
    if (WaitForSingleObject(process.hProcess, 10000)!=WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 87); WaitForSingleObject(process.hProcess, 2000); error=1;
    }
    GetExitCodeProcess(process.hProcess, &status); CloseHandle(process.hProcess);
    FILE *report=fopen("desktop-driver.json", "wb");
    if (!report) return 86;
    fprintf(report, "{\"window_found\":%s,\"actions\":%u,\"driver_error\":%s,\"candidate_exit\":%lu}\n",
        window ? "true" : "false", executed, error ? "true" : "false", status);
    if (fclose(report)) return 86;
    return error ? 86 : (int)status;
}
