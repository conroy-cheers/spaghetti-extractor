#include "boundary.h"

ATOM dxball_register_window_class(WNDCLASSA_ptr window_class) {
  return RegisterClassA(window_class);
}

LONG SPX_STDCALL dxball_window_proc(
    HWND window, DWORD message, DWORD wparam, LONG lparam) {
  (void)window;
  (void)message;
  (void)wparam;
  (void)lparam;
  return 0;
}
