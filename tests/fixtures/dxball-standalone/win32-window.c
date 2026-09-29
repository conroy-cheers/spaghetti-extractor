#include <stdlib.h>
#include "win32-platform.h"
#include "shell-runtime.h"
#include "display-runtime.h"
#include "runtime-support.h"
#include "paddle-runtime.h"

static LRESULT CALLBACK window_event(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    dxball_program *p = (void *)GetWindowLongPtrA(window, GWLP_USERDATA);
    if (message == WM_NCCREATE) {
        p = ((CREATESTRUCTA *)lparam)->lpCreateParams;
        SetWindowLongPtrA(window, GWLP_USERDATA, (LONG_PTR)p);
    }
    if (!p) return DefWindowProcA(window, message, wparam, lparam);
    return (LRESULT)dxball_program_event(p, (void *)window, message, (uint32_t)wparam, (uint32_t)lparam);
}
void dxball_win32_initialize(dxball_program *p, dxball_win32 *platform) {
    platform->events.procedure = window_event;
    dxball_program_initialize(p, platform);
    p->display.events = &platform->events;
    /* Reviewed WinMain -> flow -> gameplay preserved-register values. These
     * remain explicit compatibility inputs, not relocated application code. */
    HMODULE user = GetModuleHandleA("user32.dll");
    p->frame_history.incoming_ebp = (uint32_t)(uintptr_t)GetProcAddress(user, "DispatchMessageA");
    p->frame_history.incoming_esi = (uint32_t)(uintptr_t)GetProcAddress(user, "PeekMessageA");
}
shell_handle *display_load_icon(void *u, display_state *s, shell_handle *instance, uint32_t resource) {
    (void)u; (void)s; return (void *)LoadIconA((HINSTANCE)instance, MAKEINTRESOURCEA(resource));
}
shell_handle *display_load_cursor(void *u, display_state *s, shell_handle *instance, uint32_t resource) {
    (void)u; (void)s; return (void *)LoadCursorA((HINSTANCE)instance, MAKEINTRESOURCEA(resource));
}
shell_handle *display_stock_object(void *u, display_state *s, uint32_t object) {
    (void)u; (void)s; return (void *)GetStockObject((int)object);
}
void display_register_class(void *u, display_state *s, display_class *c) {
    (void)u; (void)s;
    WNDCLASSA native = {.style=c->style, .lpfnWndProc=c->events->procedure,
        .cbClsExtra=(int)c->class_extra, .cbWndExtra=(int)c->window_extra,
        .hInstance=(HINSTANCE)c->instance, .hIcon=(HICON)c->icon, .hCursor=(HCURSOR)c->cursor,
        .hbrBackground=(HBRUSH)c->brush, .lpszMenuName=c->menu->text, .lpszClassName=c->name->text};
    (void)RegisterClassA(&native);
}
shell_handle *display_create_window(void *u, display_state *s, shell_handle *instance, asset_name *name,
                                    uint32_t style, uint32_t width, uint32_t height) {
    (void)u;
    return (void *)CreateWindowExA(0, name->text, name->text, style, 0, 0, (int)width, (int)height,
        NULL, NULL, (HINSTANCE)instance, DXBALL_OWNER(s, display));
}
void display_show_window(void *u, display_state *s, shell_handle *window, uint32_t show) { (void)u; (void)s; ShowWindow((HWND)window, (int)show); }
void display_update_window(void *u, display_state *s, shell_handle *window) { (void)u; (void)s; UpdateWindow((HWND)window); }
void display_focus_window(void *u, display_state *s, shell_handle *window) { (void)u; (void)s; SetFocus((HWND)window); }
void display_destroy_window(void *u, display_state *s, shell_handle *window) { (void)u; (void)s; DestroyWindow((HWND)window); }
void display_message(void *u, display_state *s, shell_handle *window, asset_name *text, asset_name *caption, uint32_t flags) {
    (void)u; (void)s; MessageBoxA((HWND)window, text->text, caption->text, flags);
}
shell_handle *shell_open_semaphore(void *u, shell_state *s, uint32_t access, uint32_t inherit, asset_name *name) {
    (void)u; (void)s; return (void *)OpenSemaphoreA(access, (BOOL)inherit, name->text);
}
shell_handle *shell_create_semaphore(void *u, shell_state *s, uint32_t inherit, uint32_t initial, uint32_t maximum, asset_name *name) {
    (void)u; (void)s;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, (BOOL)inherit};
    return (void *)CreateSemaphoreA(&attributes, (LONG)initial, (LONG)maximum, name->text);
}
void shell_close_handle(void *u, shell_state *s, shell_handle *handle) { (void)u; (void)s; CloseHandle((HANDLE)handle); }
void shell_message_box(void *u, shell_state *s, shell_handle *window, asset_name *text, asset_name *caption, uint32_t flags) {
    (void)u; (void)s; MessageBoxA((HWND)window, text->text, caption->text, flags);
}
void shell_cursor_position(void *u, shell_state *s, shell_point *point) {
    (void)u; (void)s;
    POINT native = {(LONG)point->x, (LONG)point->y};
    GetCursorPos(&native); point->x = (uint32_t)native.x; point->y = (uint32_t)native.y;
}
void paddle_cursor(void *u, paddle_state *s, uint32_t x, uint32_t y) { (void)u; (void)s; SetCursorPos((int)x, (int)y); }
static void message_read(shell_message *view, const MSG *native) {
    *view = (shell_message){(void *)native->hwnd, native->message, (uint32_t)native->wParam,
        (uint32_t)native->lParam, native->time, (uint32_t)native->pt.x, (uint32_t)native->pt.y};
}
static MSG message_write(const shell_message *view) {
    return (MSG){.hwnd=(HWND)view->window, .message=view->kind, .wParam=view->wparam,
        .lParam=(LPARAM)view->lparam, .time=view->time, .pt={(LONG)view->x, (LONG)view->y}};
}
uint32_t shell_peek_message(void *u, shell_state *s, shell_message *message) {
    (void)u; (void)s;
    MSG native;
    BOOL result = PeekMessageA(&native, NULL, 0, 0, 0);
    if (result) message_read(message, &native);
    return (uint32_t)result;
}
uint32_t shell_get_message(void *u, shell_state *s, shell_message *message) {
    (void)u; (void)s;
    MSG native = message_write(message);
    BOOL result = GetMessageA(&native, NULL, 0, 0);
    message_read(message, &native);
    return (uint32_t)result;
}
void shell_translate_message(void *u, shell_state *s, shell_message *message) {
    (void)u; (void)s; MSG native = message_write(message); TranslateMessage(&native); message_read(message, &native);
}
void shell_dispatch_message(void *u, shell_state *s, shell_message *message) {
    (void)u; (void)s; MSG native = message_write(message); DispatchMessageA(&native); message_read(message, &native);
}
void shell_wait_message(void *u, shell_state *s) { (void)u; (void)s; WaitMessage(); }
void shell_post_quit(void *u, shell_state *s, uint32_t code) { (void)u; (void)s; PostQuitMessage((int)code); }
void shell_set_cursor(void *u, shell_state *s, shell_handle *cursor) { (void)u; (void)s; SetCursor((HCURSOR)cursor); }
void shell_post_message(void *u, shell_state *s, shell_handle *window, uint32_t message, uint32_t wparam, uint32_t lparam) {
    (void)u; (void)s; PostMessageA((HWND)window, message, wparam, (LPARAM)lparam);
}
void shell_capture(void *u, shell_state *s, shell_handle *window) { (void)u; (void)s; SetCapture((HWND)window); }
void shell_release_capture(void *u, shell_state *s) { (void)u; (void)s; ReleaseCapture(); }
uint32_t shell_default_event(void *u, shell_state *s, shell_handle *window, uint32_t message, uint32_t wparam, uint32_t lparam) {
    (void)u; (void)s; return (uint32_t)DefWindowProcA((HWND)window, message, wparam, (LPARAM)lparam);
}
void shell_terminate(void *u, shell_state *s, uint32_t status) { (void)u; (void)s; exit((int)status); }
void runtime_version(void *u, runtime_state *s, runtime_version_query *query) {
    (void)u; (void)s;
    OSVERSIONINFOA version = {.dwOSVersionInfoSize=query->size, .dwPlatformId=query->platform};
    GetVersionExA(&version); query->platform = version.dwPlatformId;
}
uint32_t runtime_frequency(void *u, runtime_state *s, runtime_sample *sample) {
    (void)u; (void)s;
    LARGE_INTEGER value; value.LowPart=sample->low; value.HighPart=(LONG)sample->high;
    BOOL result = QueryPerformanceFrequency(&value);
    sample->low=value.LowPart; sample->high=(uint32_t)value.HighPart;
    return (uint32_t)result;
}
void runtime_counter(void *u, runtime_state *s, runtime_sample *sample) {
    (void)u; (void)s;
    LARGE_INTEGER value; value.LowPart=sample->low; value.HighPart=(LONG)sample->high;
    QueryPerformanceCounter(&value); sample->low=value.LowPart; sample->high=(uint32_t)value.HighPart;
}
uint32_t runtime_ticks(void *u, runtime_state *s) { (void)u; (void)s; return timeGetTime(); }
void runtime_fault(void *u, runtime_state *s, uint32_t exception) {
    (void)u; (void)s; RaiseException(exception, EXCEPTION_NONCONTINUABLE, 0, NULL); abort();
}
