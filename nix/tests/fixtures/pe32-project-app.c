#include <stdint.h>
#include <windows.h>

__declspec(dllimport) int Ping(int value);
__declspec(dllimport) extern int SharedValue;

typedef int (*unary_fn)(int);

typedef struct worker_input {
  unary_fn ping;
  volatile LONG *shared_atomic;
} worker_input;

static DWORD WINAPI worker(void *opaque) {
  worker_input *input = (worker_input *)opaque;
  if (input->ping(41) != 42) return 1;
  InterlockedIncrement(input->shared_atomic);
  return 0;
}

int main(void) {
  HMODULE private_module = LoadLibraryA("private.dll");
  HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
  unary_fn ping, alias_ping, ordinal_only;
  int *shared, *shared_alias, *interior, *constant;
  volatile LONG *shared_atomic, *lifecycle_count;
  int *lifecycle_events;
  worker_input input;
  HANDLE threads[6];
  DWORD status;
  unsigned index;
  FARPROC forward_sleep;

  if (private_module == 0 || kernel32 == 0) return 1;
  ping = (unary_fn)(uintptr_t)GetProcAddress(private_module, "Ping");
  alias_ping = (unary_fn)(uintptr_t)GetProcAddress(private_module, "AliasPing");
  ordinal_only = (unary_fn)(uintptr_t)GetProcAddress(private_module, (LPCSTR)11);
  shared = (int *)(uintptr_t)GetProcAddress(private_module, "SharedValue");
  shared_alias = (int *)(uintptr_t)GetProcAddress(private_module, "SharedAlias");
  interior = (int *)(uintptr_t)GetProcAddress(private_module, "InteriorValue");
  constant = (int *)(uintptr_t)GetProcAddress(private_module, "ConstValue");
  shared_atomic = (volatile LONG *)(uintptr_t)GetProcAddress(
      private_module, "SharedAtomic");
  lifecycle_count = (volatile LONG *)(uintptr_t)GetProcAddress(
      private_module, "LifecycleCount");
  lifecycle_events = (int *)(uintptr_t)GetProcAddress(
      private_module, "LifecycleEvents");
  forward_sleep = GetProcAddress(private_module, "ForwardSleep");

  if (ping == 0 || ping != alias_ping || ping(7) != 8 || Ping(9) != 10)
    return 2;
  if (GetProcAddress(private_module, (LPCSTR)3) != (FARPROC)ping ||
      GetProcAddress(private_module, (LPCSTR)1) != 0 || ordinal_only == 0 ||
      ordinal_only(5) != 15) return 3;
  if (shared == 0 || shared != shared_alias || shared != &SharedValue ||
      *shared != 17) return 4;
  *shared = 23;
  if (SharedValue != 23) return 5;
  if (interior == 0 || *interior != 37 || constant == 0 || *constant != 29)
    return 6;
  if (forward_sleep == 0 ||
      forward_sleep != GetProcAddress(kernel32, "Sleep")) return 7;
  if (shared_atomic == 0 || lifecycle_count == 0 || lifecycle_events == 0)
    return 8;
  if (*lifecycle_count < 3 || lifecycle_events[0] != 101 ||
      lifecycle_events[1] != 102 || lifecycle_events[2] != 201) return 9;

  input.ping = ping;
  input.shared_atomic = shared_atomic;
  for (index = 0; index < 6; ++index) {
    threads[index] = CreateThread(0, 0, worker, &input, 0, 0);
    if (threads[index] == 0) return 10;
  }
  WaitForMultipleObjects(6, threads, TRUE, INFINITE);
  for (index = 0; index < 6; ++index) {
    if (!GetExitCodeThread(threads[index], &status) || status != 0) return 11;
    CloseHandle(threads[index]);
  }
  if (*shared_atomic != 6) return 12;
  if (*lifecycle_count < 21) return 13;
  return 0;
}
