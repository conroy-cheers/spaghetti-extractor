#include <windows.h>

int SharedValue = 17;
const int ConstValue = 29;
int SharedBlock[3] = { 31, 37, 41 };
volatile LONG SharedAtomic = 0;
volatile LONG LifecycleCount = 0;
int LifecycleEvents[32];
__thread int TargetTlsValue = 73;

__asm__(
    ".globl _InteriorValue\n"
    "_InteriorValue = _SharedBlock + 4\n");

static void record_event(int event) {
  LONG index = InterlockedIncrement(&LifecycleCount) - 1;
  if (index >= 0 && index < 32) LifecycleEvents[index] = event;
}

static void NTAPI tls_callback_one(
    void *module, DWORD reason, void *reserved) {
  (void)module;
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) record_event(101);
  if (reason == DLL_THREAD_ATTACH) record_event(111);
  if (reason == DLL_THREAD_DETACH) record_event(121);
  if (reason == DLL_PROCESS_DETACH) record_event(131);
}

static void NTAPI tls_callback_two(
    void *module, DWORD reason, void *reserved) {
  (void)module;
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) record_event(102);
  if (reason == DLL_THREAD_ATTACH) record_event(112);
  if (reason == DLL_THREAD_DETACH) record_event(122);
  if (reason == DLL_PROCESS_DETACH) record_event(132);
}

PIMAGE_TLS_CALLBACK callback_one
    __attribute__((section(".CRT$XLB"), used)) = tls_callback_one;
PIMAGE_TLS_CALLBACK callback_two
    __attribute__((section(".CRT$XLC"), used)) = tls_callback_two;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, void *reserved) {
  (void)module;
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) record_event(201);
  if (reason == DLL_THREAD_ATTACH) record_event(211);
  if (reason == DLL_THREAD_DETACH) record_event(221);
  if (reason == DLL_PROCESS_DETACH) record_event(231);
  return TRUE;
}

int Ping(int value) {
  return value + 1;
}

int OrdinalOnly(int value) {
  return value + 10;
}
