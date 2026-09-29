/* Read-only window/state inspection, then request close in a private Wine run. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static DWORD target;
static HWND window;
static int quiet;
static BOOL CALLBACK describe(HWND hwnd, LPARAM unused) {
    (void)unused; DWORD pid; GetWindowThreadProcessId(hwnd, &pid);
    if (pid != target) return TRUE;
    char text[512], name[128]; GetWindowTextA(hwnd, text, sizeof(text)); GetClassNameA(hwnd, name, sizeof(name));
    if (!quiet) printf("window visible=%d class=%s text=%s\n", IsWindowVisible(hwnd), name, text);
    if (!window && IsWindowVisible(hwnd)) window = hwnd;
    return TRUE;
}
int main(int argc, char **argv) {
    int drive = argc > 1 && !strcmp(argv[1], "--drive");
    if (!drive) Sleep(8000);
    DWORD started = GetTickCount(); quiet = 1;
    do {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 entry = {0}; entry.dwSize = sizeof(entry);
        if (Process32First(snapshot, &entry)) do {
            if (!_stricmp(entry.szExeFile, "DXBall.exe")) { target = entry.th32ProcessID; break; }
        } while (Process32Next(snapshot, &entry));
        CloseHandle(snapshot);
        if (target) EnumWindows(describe, 0);
        if (window || !drive) break;
        Sleep(100);
    } while (GetTickCount() - started < 18000);
    quiet = 0; printf("game_process=%lu\n", target);
    if (!target) return 2;
    EnumWindows(describe, 0);
    if (window) EnumChildWindows(window, describe, 0);
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, target);
    uint32_t counts[3] = {0}; SIZE_T read;
    for (unsigned i = 0; i < 3; ++i)
        ReadProcessMemory(process, (void *)(uintptr_t)(0x434114 + i * 0x418), &counts[i], 4, &read);
    printf("bank_counts=%u,%u,%u\n", counts[0], counts[1], counts[2]); CloseHandle(process);
    if (window && drive) {
        Sleep(1000);
        PostMessageA(window, WM_KEYDOWN, VK_F2, 0); Sleep(100); PostMessageA(window, WM_KEYUP, VK_F2, 0);
        PostMessageA(window, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(320, 240));
        Sleep(100); PostMessageA(window, WM_LBUTTONUP, 0, MAKELPARAM(320, 240));
        Sleep(2000); PostMessageA(window, WM_CLOSE, 0, 0); return 0;
    }
    if (window) {
        RECT area; GetClientRect(window, &area); int width = area.right, height = area.bottom;
        HDC source = GetDC(window), copy = CreateCompatibleDC(source);
        BITMAPINFO info = {0}; info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        info.bmiHeader.biWidth = width; info.bmiHeader.biHeight = height;
        info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32;
        void *pixels = NULL; HBITMAP bitmap = CreateDIBSection(source, &info, DIB_RGB_COLORS, &pixels, NULL, 0);
        if (bitmap) {
            HGDIOBJ previous = SelectObject(copy, bitmap); BitBlt(copy, 0, 0, width, height, source, 0, 0, SRCCOPY);
            BITMAPFILEHEADER header = {0}; header.bfType = 0x4d42; header.bfOffBits = sizeof(header) + sizeof(info.bmiHeader);
            header.bfSize = header.bfOffBits + (DWORD)(width * height * 4);
            FILE *out = fopen("window.bmp", "wb");
            if (out) { fwrite(&header, sizeof(header), 1, out); fwrite(&info.bmiHeader, sizeof(info.bmiHeader), 1, out);
                fwrite(pixels, (size_t)width * height * 4, 1, out); fclose(out); }
            SelectObject(copy, previous); DeleteObject(bitmap);
        }
        DeleteDC(copy); ReleaseDC(window, source); PostMessageA(window, WM_CLOSE, 0, 0);
    }
    return 0;
}
