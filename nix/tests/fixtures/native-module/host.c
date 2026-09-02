#include <stdint.h>
#include <stdio.h>
#include <windows.h>

typedef uint32_t (__stdcall *fixture_export_fn)(void);
typedef uintptr_t (__stdcall *fixture_register_callback_fn)(void);
typedef LONG (__stdcall *fixture_unhandled_filter_fn)(EXCEPTION_POINTERS *);
typedef LONG (WINAPI *fixture_exception_filter_fn)(EXCEPTION_POINTERS *);
typedef uint32_t (__cdecl *fixture_host_import_seh_fn)(
    uint32_t, uint32_t, uint32_t, const ULONG_PTR *);
typedef uint32_t (__stdcall *fixture_provider_counter_fn)(void);

#define ATOMIC_THREADS 8U
#define ATOMIC_ITERATIONS 500U

static volatile LONG exception_seen;
static volatile LONG access_violation_seen;

static LONG WINAPI fixture_exception_handler(EXCEPTION_POINTERS *pointers) {
  EXCEPTION_RECORD *record = pointers->ExceptionRecord;
  if (record->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
    InterlockedIncrement(&exception_seen);
  } else if (
      record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
      record->NumberParameters == 2U &&
      record->ExceptionInformation[0] == 1U &&
      record->ExceptionInformation[1] == 0x1badb002U) {
    InterlockedIncrement(&access_violation_seen);
  } else {
    return EXCEPTION_CONTINUE_SEARCH;
  }
  pointers->ContextRecord->Edi = 0x13579bdfU;
  return EXCEPTION_CONTINUE_EXECUTION;
}

typedef struct atomic_worker_input {
  fixture_export_fn function;
} atomic_worker_input;

typedef struct callback_worker_input {
  fixture_exception_filter_fn function;
} callback_worker_input;

#ifndef EXPECTED_TLS_ORDER
#error EXPECTED_TLS_ORDER must be derived from the original TLS callback table
#endif

static DWORD WINAPI atomic_worker(void *argument) {
  atomic_worker_input *input = (atomic_worker_input *)argument;
  uint32_t iteration;
  for (iteration = 0U; iteration < ATOMIC_ITERATIONS; ++iteration)
    if (input->function() == 0U) return 20U;
  return 0U;
}

static DWORD WINAPI callback_worker(void *argument) {
  callback_worker_input *input = (callback_worker_input *)argument;
  EXCEPTION_RECORD record;
  CONTEXT context;
  EXCEPTION_POINTERS pointers;
  LONG observed;
  ZeroMemory(&record, sizeof(record));
  ZeroMemory(&context, sizeof(context));
  record.ExceptionCode = 0xe0424242U;
  record.NumberParameters = 2U;
  record.ExceptionInformation[0] = 0xfeed0001U;
  record.ExceptionInformation[1] = 0xfeed0002U;
  context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  pointers.ExceptionRecord = &record;
  pointers.ContextRecord = &context;
  observed = input->function(&pointers);
  if (observed != EXCEPTION_EXECUTE_HANDLER ||
      record.ExceptionFlags != 0x46584c54U ||
      context.Edi != 0x2468ace0U) {
    fprintf(
        stderr,
        "escaped filter observed result=%ld flags=0x%08lx edi=0x%08lx\n",
        (long)observed, (unsigned long)record.ExceptionFlags,
        (unsigned long)context.Edi);
    return 29U;
  }
  return 0U;
}

static LONG WINAPI fixture_fallback_filter(EXCEPTION_POINTERS *pointers) {
  pointers->ContextRecord->Ebx = 0xfabbacc0U;
  return EXCEPTION_EXECUTE_HANDLER;
}

int main(void) {
  HMODULE module = LoadLibraryA("fixture.dll");
  FARPROC named;
  FARPROC alias;
  FARPROC ordinal;
  FARPROC hole;
  uint32_t *data_named;
  uint32_t *data_ordinal;
  fixture_export_fn atomic_function;
  fixture_export_fn reentrant_function;
  fixture_export_fn nonlocal_function;
  fixture_export_fn unwind_function;
  fixture_export_fn seh_function;
  fixture_export_fn hardware_seh_function;
  fixture_export_fn access_violation_function;
  fixture_export_fn hardware_access_violation_function;
  fixture_export_fn interface_function;
  fixture_export_fn stale_interface_function;
  fixture_export_fn record_interface_function;
  fixture_export_fn interface_callback_function;
  fixture_provider_counter_fn invoke_stale_callback_function;
  fixture_provider_counter_fn stale_call_count_function;
  fixture_provider_counter_fn provider_trace_function;
  fixture_provider_counter_fn last_record_input_function;
  fixture_provider_counter_fn last_record_output_function;
  HMODULE interface_provider;
  fixture_host_import_seh_fn host_import_seh_function;
  fixture_unhandled_filter_fn unhandled_filter_function;
  PVOID exception_handler;
  fixture_register_callback_fn register_callback;
  fixture_exception_filter_fn escaped_callback;
  callback_worker_input callback_input;
  HANDLE callback_thread;
  atomic_worker_input atomic_input;
  HANDLE threads[ATOMIC_THREADS];
  DWORD thread_status;
  uint32_t thread_index;
  uint32_t result;
  EXCEPTION_RECORD filter_record;
  CONTEXT filter_context;
  EXCEPTION_POINTERS filter_pointers;
  LONG filter_result;

  if (module == NULL) return 10;
  printf("fixture module base=0x%08lx\n", (unsigned long)(uintptr_t)module);
  fflush(stdout);
  named = GetProcAddress(module, "fixture_export");
  alias = GetProcAddress(module, "fixture_alias");
  ordinal = GetProcAddress(module, (LPCSTR)(uintptr_t)2U);
  hole = GetProcAddress(module, (LPCSTR)(uintptr_t)3U);
  if (named == NULL || alias == NULL || ordinal == NULL || hole != NULL)
    return 11;
  if (named != alias || named != ordinal) return 12;
  result = ((fixture_export_fn)(uintptr_t)named)();
  if (result != 0xc0dec0deU) {
    fprintf(stderr, "fixture export observed 0x%08lx\n", (unsigned long)result);
    return 13;
  }
  data_named = (uint32_t *)(uintptr_t)GetProcAddress(module, "fixture_data");
  data_ordinal = (uint32_t *)(uintptr_t)GetProcAddress(
      module, (LPCSTR)(uintptr_t)5U);
  if (data_named == NULL || data_named != data_ordinal) return 14;
  if (data_named[0] != 0x11223344U || data_named[1] != EXPECTED_TLS_ORDER)
    return 15;
  data_named[0] = 0x55667788U;
  if (data_ordinal[0] != 0x55667788U) return 16;
  atomic_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_atomic");
  if (atomic_function == NULL) return 18;
  data_named[0] = 0U;
  atomic_input.function = atomic_function;
  for (thread_index = 0U; thread_index < ATOMIC_THREADS; ++thread_index) {
    threads[thread_index] = CreateThread(
        NULL, 0U, atomic_worker, &atomic_input, 0U, NULL);
    if (threads[thread_index] == NULL) return 19;
  }
  for (thread_index = 0U; thread_index < ATOMIC_THREADS; ++thread_index) {
    WaitForSingleObject(threads[thread_index], INFINITE);
    if (!GetExitCodeThread(threads[thread_index], &thread_status) ||
        thread_status != 0U)
      return 20;
    CloseHandle(threads[thread_index]);
  }
  if (data_named[0] != ATOMIC_THREADS * ATOMIC_ITERATIONS) return 21;
  interface_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_interface");
  stale_interface_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_interface_stale");
  record_interface_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_interface_record");
  interface_callback_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_interface_callback_flow");
  interface_provider = GetModuleHandleA("fixture-provider.dll");
  stale_call_count_function = interface_provider == NULL ? NULL :
      (fixture_provider_counter_fn)(uintptr_t)GetProcAddress(
          interface_provider, "FixtureProviderStaleCallCount");
  invoke_stale_callback_function = interface_provider == NULL ? NULL :
      (fixture_provider_counter_fn)(uintptr_t)GetProcAddress(
          interface_provider, "FixtureProviderInvokeStaleCallback");
  provider_trace_function = interface_provider == NULL ? NULL :
      (fixture_provider_counter_fn)(uintptr_t)GetProcAddress(
          interface_provider, "FixtureProviderTrace");
  last_record_input_function = interface_provider == NULL ? NULL :
      (fixture_provider_counter_fn)(uintptr_t)GetProcAddress(
          interface_provider, "FixtureProviderLastRecordInput");
  last_record_output_function = interface_provider == NULL ? NULL :
      (fixture_provider_counter_fn)(uintptr_t)GetProcAddress(
          interface_provider, "FixtureProviderLastRecordOutput");
  if (interface_function == NULL || stale_interface_function == NULL ||
      record_interface_function == NULL || interface_callback_function == NULL ||
      invoke_stale_callback_function == NULL ||
      stale_call_count_function == NULL || provider_trace_function == NULL ||
      last_record_input_function == NULL || last_record_output_function == NULL)
    return 42;
  result = interface_function();
  if (result != 0xfaceb00cU ||
      provider_trace_function() != 0x00021111U) {
    fprintf(
        stderr,
        "fixture interface observed result=0x%08lx trace=0x%08lx\n",
        (unsigned long)result, (unsigned long)provider_trace_function());
    return 43;
  }
  result = stale_interface_function();
  if (result != 1U || stale_call_count_function() != 0U ||
      provider_trace_function() != 0x01031112U) {
    fprintf(
        stderr,
        "fixture stale interface result=0x%08lx provider-calls=%lu "
        "trace=0x%08lx record=0x%08lx->0x%08lx\n",
        (unsigned long)result,
        (unsigned long)stale_call_count_function(),
        (unsigned long)provider_trace_function(),
        (unsigned long)last_record_input_function(),
        (unsigned long)last_record_output_function());
    return 44;
  }
  result = record_interface_function();
  if (result != 0xcafebab6U || stale_call_count_function() != 0U ||
      provider_trace_function() != 0x02041113U ||
      last_record_input_function() != 8U ||
      last_record_output_function() != 0xcafebab6U) {
    fprintf(
        stderr,
        "fixture record interface result=0x%08lx provider-calls=%lu "
        "trace=0x%08lx record=0x%08lx->0x%08lx\n",
        (unsigned long)result,
        (unsigned long)stale_call_count_function(),
        (unsigned long)provider_trace_function(),
        (unsigned long)last_record_input_function(),
        (unsigned long)last_record_output_function());
    return 47;
  }
  result = interface_callback_function();
  if (result != 0x18fae4b6U || stale_call_count_function() != 0U ||
      provider_trace_function() != 0x02152114U) {
    fprintf(
        stderr,
        "fixture interface callback result=0x%08lx provider-calls=%lu "
        "trace=0x%08lx\n",
        (unsigned long)result,
        (unsigned long)stale_call_count_function(),
        (unsigned long)provider_trace_function());
    return 45;
  }
  puts("fixture interface callback passed");
  fflush(stdout);
  result = invoke_stale_callback_function();
  if (result != 1U || stale_call_count_function() != 0U ||
      provider_trace_function() != 0x02152114U) {
    fprintf(
        stderr,
        "fixture stale callback result=0x%08lx provider-calls=%lu "
        "trace=0x%08lx\n",
        (unsigned long)result,
        (unsigned long)stale_call_count_function(),
        (unsigned long)provider_trace_function());
    return 46;
  }
  puts("fixture stale callback rejection passed");
  fflush(stdout);
  reentrant_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_reentrant");
  if (reentrant_function == NULL ||
      reentrant_function() != 0xc0dec0dfU)
    return 22;
  puts("fixture reentrant call passed");
  fflush(stdout);
  nonlocal_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_nonlocal");
  if (nonlocal_function == NULL) return 35;
  result = nonlocal_function();
  if (result != 0x4e4f4e4cU) {
    fprintf(
        stderr, "fixture nonlocal observed result=0x%08lx\n",
        (unsigned long)result);
    return 35;
  }
  unwind_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_unwind");
  data_named[0] = 0U;
  result = unwind_function == NULL ? 0U : unwind_function();
  if (unwind_function == NULL || result != 0x554e5744U ||
      data_named[0] != 1U) {
    fprintf(
        stderr, "fixture unwind observed result=0x%08lx notifications=%lu\n",
        (unsigned long)result, (unsigned long)data_named[0]);
    return 41;
  }
  puts("fixture unwind call passed");
  fflush(stdout);
  seh_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_seh");
  exception_handler = AddVectoredExceptionHandler(
      1U, fixture_exception_handler);
  if (seh_function == NULL || exception_handler == NULL) return 23;
  result = seh_function();
  RemoveVectoredExceptionHandler(exception_handler);
  if (result != 0x5e110001U || exception_seen != 1) {
    fprintf(
        stderr, "fixture SEH observed result=0x%08lx exceptions=%ld\n",
        (unsigned long)result, (long)exception_seen);
    return 24;
  }
  puts("fixture generated SEH escape passed");
  fflush(stdout);
  hardware_seh_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_hardware_seh");
  if (hardware_seh_function == NULL) {
    fprintf(stderr, "fixture handled SEH export is unavailable\n");
    return 25;
  }
  result = hardware_seh_function();
  if (result != 0xc0dec0dfU) {
    fprintf(
        stderr, "fixture handled SEH observed result=0x%08lx\n",
        (unsigned long)result);
    return 25;
  }
  puts("fixture hardware SEH handling passed");
  fflush(stdout);
  access_violation_function = (fixture_export_fn)(uintptr_t)GetProcAddress(
      module, "fixture_access_violation");
  exception_handler = AddVectoredExceptionHandler(
      1U, fixture_exception_handler);
  if (access_violation_function == NULL || exception_handler == NULL)
    return 31;
  result = access_violation_function();
  RemoveVectoredExceptionHandler(exception_handler);
  if (result != 0x5e110001U || access_violation_seen != 1) {
    fprintf(
        stderr, "fixture access violation result=0x%08lx exceptions=%ld\n",
        (unsigned long)result, (long)access_violation_seen);
    return 32;
  }
  puts("fixture generated access-violation escape passed");
  fflush(stdout);
  hardware_access_violation_function =
      (fixture_export_fn)(uintptr_t)GetProcAddress(
          module, "fixture_hardware_access_violation");
  if (hardware_access_violation_function == NULL ||
      hardware_access_violation_function() != 0xc0dec0dfU)
    return 33;
  puts("fixture hardware access-violation handling passed");
  fflush(stdout);
  puts("fixture entering host-import SEH call");
  fflush(stdout);
  host_import_seh_function =
      (fixture_host_import_seh_fn)(uintptr_t)GetProcAddress(
          module, "fixture_host_import_seh");
  if (host_import_seh_function == NULL ||
      host_import_seh_function(
          EXCEPTION_INT_DIVIDE_BY_ZERO, 0U, 0U, NULL) != 0xc0dec0dfU)
    return 34;
  puts("fixture host-import SEH call passed");
  fflush(stdout);
  unhandled_filter_function =
      (fixture_unhandled_filter_fn)(uintptr_t)GetProcAddress(
          module, "fixture_unhandled_filter");
  if (unhandled_filter_function == NULL) return 36;
  ZeroMemory(&filter_record, sizeof(filter_record));
  ZeroMemory(&filter_context, sizeof(filter_context));
  filter_record.ExceptionCode = 0xe0424242U;
  filter_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  filter_pointers.ExceptionRecord = &filter_record;
  filter_pointers.ContextRecord = &filter_context;
  SetUnhandledExceptionFilter(fixture_fallback_filter);
  filter_result = unhandled_filter_function(&filter_pointers);
  if (filter_result != EXCEPTION_EXECUTE_HANDLER ||
      filter_context.Ebx != 0xfabbacc0U) {
    fprintf(
        stderr, "loader fallback observed result=%ld ebx=0x%08lx\n",
        (long)filter_result, (unsigned long)filter_context.Ebx);
    return 37;
  }
  register_callback = (fixture_register_callback_fn)(uintptr_t)GetProcAddress(
      module, "fixture_register_callback");
  if (register_callback == NULL) return 26;
  escaped_callback = (fixture_exception_filter_fn)register_callback();
  if (escaped_callback == NULL) return 27;
  ZeroMemory(&filter_record, sizeof(filter_record));
  ZeroMemory(&filter_context, sizeof(filter_context));
  filter_record.ExceptionCode = 0xe0424242U;
  filter_record.NumberParameters = 1U;
  filter_record.ExceptionInformation[0] = 0xfeed0003U;
  filter_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  filter_pointers.ExceptionRecord = &filter_record;
  filter_pointers.ContextRecord = &filter_context;
  filter_result = escaped_callback(&filter_pointers);
  if (filter_result != EXCEPTION_EXECUTE_HANDLER ||
      filter_record.ExceptionFlags != 0x46584c54U ||
      filter_context.Edi != 0x2468ace0U) {
    fprintf(
        stderr,
        "direct checked filter result=%ld flags=0x%08lx edi=0x%08lx\n",
        (long)filter_result, (unsigned long)filter_record.ExceptionFlags,
        (unsigned long)filter_context.Edi);
    return 39;
  }
  ZeroMemory(&filter_record, sizeof(filter_record));
  ZeroMemory(&filter_context, sizeof(filter_context));
  filter_record.ExceptionCode = 0xe0424242U;
  filter_record.NumberParameters = 1U;
  filter_record.ExceptionInformation[0] = 0xfeed0003U;
  filter_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  filter_pointers.ExceptionRecord = &filter_record;
  filter_pointers.ContextRecord = &filter_context;
  filter_result = unhandled_filter_function(&filter_pointers);
  if (filter_result != EXCEPTION_EXECUTE_HANDLER ||
      filter_record.ExceptionFlags != 0x46584c54U ||
      filter_context.Edi != 0x2468ace0U) {
    fprintf(
        stderr,
        "checked filter service result=%ld flags=0x%08lx edi=0x%08lx\n",
        (long)filter_result, (unsigned long)filter_record.ExceptionFlags,
        (unsigned long)filter_context.Edi);
    return 38;
  }
  callback_input.function = escaped_callback;
  callback_thread = CreateThread(
      NULL, 0U, callback_worker, &callback_input, 0U, NULL);
  if (callback_thread == NULL) return 28;
  WaitForSingleObject(callback_thread, INFINITE);
  if (!GetExitCodeThread(callback_thread, &thread_status) ||
      thread_status != 0U) {
    printf(
        "escaped callback worker exit 0x%08lx\n",
        (unsigned long)thread_status);
    fflush(stdout);
    CloseHandle(callback_thread);
    return 40 + (int)(thread_status & 31U);
  }
  CloseHandle(callback_thread);
  ZeroMemory(&filter_record, sizeof(filter_record));
  ZeroMemory(&filter_context, sizeof(filter_context));
  filter_record.ExceptionCode = 0xe0424242U;
  filter_context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
  filter_pointers.ExceptionRecord = &filter_record;
  filter_pointers.ContextRecord = &filter_context;
  if (escaped_callback(&filter_pointers) != EXCEPTION_EXECUTE_HANDLER ||
      filter_record.ExceptionFlags != 0x46584c54U ||
      filter_context.Edi != 0x2468ace0U)
    return 30;
  SetUnhandledExceptionFilter(NULL);
  if (!FreeLibrary(module)) return 17;
  return 0;
}
