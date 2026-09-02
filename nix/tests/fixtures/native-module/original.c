#include <stdint.h>
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)instance;
  (void)reason;
  (void)reserved;
  return TRUE;
}

/* Keep one exact loader-owned slot available for process-termination support. */
void __stdcall fixture_process_termination_anchor(DWORD code)
    __attribute__((used, noinline));
void __stdcall fixture_process_termination_anchor(DWORD code) {
  ExitProcess(code);
}

uint32_t __stdcall fixture_export(void) {
  return 0xc0dec0deU;
}

uint32_t __stdcall fixture_atomic(void) {
  return 0U;
}

uint32_t __stdcall fixture_reentrant(void) {
  return 0U;
}

typedef struct fixture_interface FixtureInterface;
typedef struct fixture_record {
  uint32_t input;
  uint32_t output;
} fixture_record;
typedef uint32_t (__stdcall *fixture_enum_callback)(
    FixtureInterface *, uint32_t);
typedef struct fixture_interface_vtable {
  int32_t (__stdcall *clone)(FixtureInterface *, FixtureInterface **);
  int32_t (__stdcall *set_value)(FixtureInterface *, uint32_t);
  uint32_t (__stdcall *get_value)(FixtureInterface *);
  uint32_t (__stdcall *release)(FixtureInterface *);
  uint32_t (__stdcall *enumerate)(
      FixtureInterface *, fixture_enum_callback, uint32_t);
  int32_t (__stdcall *fill_record)(FixtureInterface *, fixture_record *);
} fixture_interface_vtable;

struct fixture_interface {
  const fixture_interface_vtable *vtable;
};

__declspec(dllimport) int32_t __stdcall FixtureCreate(
    FixtureInterface **result);

uint32_t __stdcall fixture_interface(void) {
  FixtureInterface *root = NULL;
  FixtureInterface *nested = NULL;
  uint32_t result;
  if (FixtureCreate(&root) < 0 || root == NULL) return 0U;
  if (root->vtable->clone(root, &nested) < 0 || nested == NULL) return 0U;
  if (nested->vtable->set_value(nested, 0xfaceb00cU) < 0) return 0U;
  result = nested->vtable->get_value(nested);
  nested->vtable->release(nested);
  root->vtable->release(root);
  return result;
}

uint32_t __stdcall fixture_interface_stale(void) {
  FixtureInterface *root = NULL;
  fixture_record record;
  uint32_t stale_result;
  if (FixtureCreate(&root) < 0 || root == NULL) return 0U;
  record.input = 8U;
  (void)root->vtable->fill_record(root, &record);
  root->vtable->release(root);
  stale_result = root->vtable->get_value(root);
  return record.output ^ stale_result;
}

uint32_t __stdcall fixture_interface_record(void) {
  FixtureInterface *root = NULL;
  fixture_record record;
  if (FixtureCreate(&root) < 0 || root == NULL) return 0U;
  record.input = 8U;
  (void)root->vtable->fill_record(root, &record);
  root->vtable->release(root);
  return record.output;
}

uint32_t __stdcall fixture_interface_callback(
    FixtureInterface *object, uint32_t cookie)
    __attribute__((used, noinline));
uint32_t __stdcall fixture_interface_callback(
    FixtureInterface *object, uint32_t cookie) {
  if (object == NULL) return 0U;
  return object->vtable->get_value(object) ^ cookie;
}

uint32_t __stdcall fixture_interface_callback_flow(void) {
  FixtureInterface *root = NULL;
  uint32_t result;
  if (FixtureCreate(&root) < 0 || root == NULL) return 0U;
  result = root->vtable->enumerate(
      root, fixture_interface_callback, 0x13572468U);
  root->vtable->release(root);
  return result;
}

uint32_t __cdecl fixture_nonlocal_callee(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_nonlocal_callee(void) {
  return 0U;
}

uint32_t __cdecl fixture_nonlocal_continuation(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_nonlocal_continuation(void) {
  return 0U;
}

uint32_t __stdcall fixture_nonlocal(void) {
  return fixture_nonlocal_callee() + fixture_nonlocal_continuation();
}

uint32_t __stdcall fixture_seh(void) {
  return 0U;
}

uint32_t __stdcall fixture_hardware_seh(void) {
  return 0U;
}

uint32_t __stdcall fixture_access_violation(void) {
  return 0U;
}

uint32_t __stdcall fixture_hardware_access_violation(void) {
  return 0U;
}

uint32_t __cdecl fixture_host_import_seh(
    uint32_t code, uint32_t flags, uint32_t count,
    const ULONG_PTR *arguments) {
  RaiseException(code, flags, count, arguments);
  return 0U;
}

uint32_t __cdecl fixture_guest_exception_handler(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_guest_exception_handler(void) {
  return 0U;
}

uint32_t __cdecl fixture_guest_exception_resumption(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_guest_exception_resumption(void) {
  return 0U;
}

uint32_t __cdecl fixture_guest_finally_inner(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_guest_finally_inner(void) {
  return 0U;
}

uint32_t __cdecl fixture_guest_finally_outer(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_guest_finally_outer(void) {
  return 0U;
}

LONG WINAPI fixture_callback_target(EXCEPTION_POINTERS *pointers)
    __attribute__((used, noinline));
LONG WINAPI fixture_callback_target(EXCEPTION_POINTERS *pointers) {
  (void)pointers;
  return EXCEPTION_EXECUTE_HANDLER;
}

uintptr_t __stdcall fixture_register_callback(void) {
  SetUnhandledExceptionFilter(fixture_callback_target);
  return (uintptr_t)&fixture_callback_target;
}

LONG __stdcall fixture_unhandled_filter(EXCEPTION_POINTERS *pointers) {
  return UnhandledExceptionFilter(pointers);
}

uint32_t __cdecl fixture_guest_unwind_handler(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_guest_unwind_handler(void) {
  return 0U;
}

uint32_t __cdecl fixture_unwind_continuation(void)
    __attribute__((used, noinline));
uint32_t __cdecl fixture_unwind_continuation(void) {
  return 0U;
}

uint32_t __stdcall fixture_unwind(void) {
  RtlUnwind(
      (PVOID)(uintptr_t)1U,
      (PVOID)(uintptr_t)&fixture_unwind_continuation,
      NULL,
      (PVOID)(uintptr_t)0x554e5744U);
  return 0U;
}

uint32_t fixture_data[2] = {0x11223344U, 0xa5a5a5a5U};

uint8_t fixture_tls_template[4]
    __attribute__((section(".tls$AAB"), used)) = {
        0x10U, 0x20U, 0x30U, 0x40U};

static void NTAPI fixture_tls_callback_one(
    PVOID module, DWORD reason, PVOID reserved) {
  (void)module;
  (void)reason;
  (void)reserved;
}

static void NTAPI fixture_tls_callback_two(
    PVOID module, DWORD reason, PVOID reserved) {
  (void)module;
  (void)reason;
  (void)reserved;
}

DWORD fixture_tls_index;

PIMAGE_TLS_CALLBACK fixture_tls_callbacks[]
    __attribute__((section(".rdata$T"), used)) = {
        fixture_tls_callback_one,
        fixture_tls_callback_two,
        NULL,
    };

IMAGE_TLS_DIRECTORY32 _tls_used
    __attribute__((section(".rdata$T"), used)) = {
        (DWORD)(uintptr_t)&fixture_tls_template[0],
        (DWORD)(uintptr_t)&fixture_tls_template[4],
        (DWORD)(uintptr_t)&fixture_tls_index,
        (DWORD)(uintptr_t)&fixture_tls_callbacks[0],
        0U,
        0U,
    };
