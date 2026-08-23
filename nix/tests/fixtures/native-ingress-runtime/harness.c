#include <stdint.h>
#include <stdio.h>
#include <windows.h>

#include "native-ingress-runtime.h"

#define THREADS 8U
#define ITERATIONS 200U
#define TLS_BYTES 0x180000U

extern uint32_t spx_ingress_0000(void);
extern uint32_t spx_ingress_0001(void);
extern uint32_t spx_ingress_0002(void);
extern uint32_t spx_ingress_0003(void);
extern uint32_t spx_ingress_0004(void);
extern uint32_t spx_ingress_0005(void);
extern uint32_t spx_ingress_0006(void);
extern uint32_t spx_ingress_0007(void);
extern uint32_t spx_ingress_0008(void);
extern uint32_t spx_ingress_0009(void);
extern void *spx_native_runtime_context_current(void);
extern uint32_t *spx_native_raise_exception_iat_pointer;

static DWORD tls_index;
static uint32_t raise_exception_cell;
static volatile LONG shared_calls;
static volatile LONG ready_threads;
static volatile LONG release_threads;
static volatile LONG stack_faults;
static volatile LONG veh_seen;
static volatile LONG resumed_register_seen;
static uint32_t escaped_original_edi;
static void *thread_contexts[THREADS];

static int install_thread_tls(void) {
  void **slots;
  void *storage = VirtualAlloc(
      0, TLS_BYTES, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (storage == 0 || TlsSetValue(tls_index, storage) == 0) return 0;
  /* The composed backend uses the loader's static-TLS vector at fs:0x2c.
   * TlsAlloc addresses the separate Win32 dynamic-TLS vector, so the fixture
   * realizes the selected static slot exactly as the PE loader would. */
  __asm__ volatile ("movl %%fs:0x2c,%0" : "=r" (slots));
  if (slots == 0) return 0;
  slots[tls_index] = storage;
  return 1;
}

static void remove_thread_tls(void) {
  void **slots;
  void *storage = TlsGetValue(tls_index);
  __asm__ volatile ("movl %%fs:0x2c,%0" : "=r" (slots));
  if (slots != 0) slots[tls_index] = 0;
  TlsSetValue(tls_index, 0);
  if (storage != 0) VirtualFree(storage, 0, MEM_RELEASE);
}

static LONG WINAPI exception_observer(EXCEPTION_POINTERS *pointers) {
  if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_INT_DIVIDE_BY_ZERO)
    return EXCEPTION_CONTINUE_SEARCH;
  InterlockedIncrement(&veh_seen);
  pointers->ContextRecord->Edi = 0x13579bdfU;
  return EXCEPTION_CONTINUE_EXECUTION;
}

spx_call_status spx_native_runtime_run_at_rva(
    uint32_t rva, const spx_machine_state *input, spx_machine_state *output) {
  volatile uint32_t *slot;
  uint32_t nested;
  *output = *input;
  switch (rva) {
    case 0x1010U:
      slot = spx_native_runtime_diagnostic_slot(0U);
      if (slot == 0) return SPX_CALL_UNIMPLEMENTED;
      output->eax = ++*slot;
      InterlockedIncrement(&shared_calls);
      break;
    case 0x1020U:
      slot = spx_native_runtime_diagnostic_slot(1U);
      if (slot == 0) return SPX_CALL_UNIMPLEMENTED;
      if (*slot == 0U) {
        *slot = 1U;
        nested = spx_ingress_0002();
        *slot = 0U;
        output->eax = nested + 1U;
      } else {
        output->eax = 40U;
      }
      break;
    case 0x1030U:
      slot = spx_native_runtime_diagnostic_slot(2U);
      if (slot == 0) return SPX_CALL_UNIMPLEMENTED;
      ++*slot;
      nested = spx_ingress_0003();
      --*slot;
      if (nested == SPX_CALL_UNIMPLEMENTED) {
        InterlockedIncrement(&stack_faults);
        output->eax = 0U;
      } else {
        output->eax = nested;
      }
      break;
    case 0x1040U:
      output->eax = 0x1040U;
      break;
    case 0x1050U:
      __asm__ volatile (
          "xorl %%edx, %%edx\n\t"
          "movl $1, %%eax\n\t"
          "xorl %%ecx, %%ecx\n\t"
          "divl %%ecx" ::: "eax", "ecx", "edx", "cc");
      return SPX_CALL_UNIMPLEMENTED;
    case 0x1060U:
      RaiseException(EXCEPTION_INT_DIVIDE_BY_ZERO, 0U, 0U, 0);
      return SPX_CALL_UNIMPLEMENTED;
    case 0x1070U:
      escaped_original_edi = input->edi;
      return SPX_CALL_DIVIDE_ERROR;
    case 0x10a0U:
      output->eax = 0x10a0U;
      break;
    case 0x10b0U:
      output->eax = 0x10b0U;
      break;
    case 0x10c0U:
      output->eax = 0x10c0U;
      break;
    case 0x2050U:
      output->eax = 50U;
      break;
    case 0x2060U:
      output->eax = 0x6050U;
      break;
    case 0x2070U:
      output->eax = 70U;
      break;
    case 0x2080U:
      output->eax = 0x8070U;
      break;
    case 0x2090U:
      if (output->edi == 0x13579bdfU)
        InterlockedIncrement(&resumed_register_seen);
      output->edi = escaped_original_edi;
      output->eax = 0x9070U;
      break;
    default:
      return SPX_CALL_UNIMPLEMENTED;
  }
  output->esp = input->esp + 4U;
  return SPX_CALL_OK;
}

static DWORD WINAPI concurrent_worker(void *argument) {
  uintptr_t index = (uintptr_t)argument;
  uint32_t iteration;
  void **slots;
  if (!install_thread_tls()) return 10U;
  thread_contexts[index] = spx_native_runtime_context_current();
  if (thread_contexts[index] == 0) {
    __asm__ volatile ("movl %%fs:0x2c,%0" : "=r" (slots));
    fprintf(
        stderr, "tls index %lu api %p slots %p direct %p\n",
        (unsigned long)tls_index, TlsGetValue(tls_index), (void *)slots,
        slots == 0 ? 0 : slots[tls_index]);
    return 11U;
  }
  InterlockedIncrement(&ready_threads);
  while (InterlockedCompareExchange(&release_threads, 0, 0) == 0) Sleep(0);
  for (iteration = 0; iteration < ITERATIONS; ++iteration) {
    uint32_t observed = spx_ingress_0000();
    if (observed != iteration + 1U) {
      fprintf(
          stderr, "thread %lu iteration %lu observed %08lx\n",
          (unsigned long)index, (unsigned long)iteration,
          (unsigned long)observed);
      return 12U;
    }
  }
  remove_thread_tls();
  return 0U;
}

static DWORD WINAPI escaped_worker(void *argument) {
  uint32_t result;
  (void)argument;
  if (!install_thread_tls()) return 20U;
  result = spx_ingress_0001();
  remove_thread_tls();
  return result == 0x1040U ? 0U : 21U;
}

static int join_ok(HANDLE thread) {
  DWORD result;
  WaitForSingleObject(thread, INFINITE);
  if (!GetExitCodeThread(thread, &result)) result = 0xffffffffU;
  CloseHandle(thread);
  if (result != 0U)
    fprintf(stderr, "worker exit %lu\n", (unsigned long)result);
  return result == 0U;
}

static void checkpoint(const char *name) {
  puts(name);
  fflush(stdout);
}

int main(void) {
  HANDLE threads[THREADS];
  HANDLE thread;
  PVOID observer;
  uint32_t generation;
  uint32_t index, other;

  tls_index = TlsAlloc();
  if (tls_index == TLS_OUT_OF_INDEXES || !install_thread_tls()) return 1;
  spx_native_tls_index_cell_pointer = (uint32_t *)(void *)&tls_index;
  raise_exception_cell = (uint32_t)(uintptr_t)RaiseException;
  spx_native_raise_exception_iat_pointer = &raise_exception_cell;
  checkpoint("phase: concurrent");

  for (index = 0; index < THREADS; ++index) {
    threads[index] = CreateThread(
        0, 0, concurrent_worker, (void *)(uintptr_t)index, 0, 0);
    if (threads[index] == 0) return 2;
  }
  while (InterlockedCompareExchange(&ready_threads, 0, 0) != (LONG)THREADS)
    Sleep(0);
  InterlockedExchange(&release_threads, 1);
  for (index = 0; index < THREADS; ++index)
    if (!join_ok(threads[index])) return 3;
  if (shared_calls != (LONG)(THREADS * ITERATIONS)) return 4;
  for (index = 0; index < THREADS; ++index)
    for (other = index + 1U; other < THREADS; ++other)
      if (thread_contexts[index] == thread_contexts[other]) return 5;

  checkpoint("phase: nested");
  if (spx_ingress_0002() != 41U) return 6;
  checkpoint("phase: stack exhaustion");
  if (spx_ingress_0003() != 0U || stack_faults != 1) return 7;

  checkpoint("phase: capabilities");
  if (spx_ingress_0001() != SPX_CALL_UNIMPLEMENTED) return 8;
  generation = spx_native_capability_activate(0U, 0U);
  if (generation == 0U || spx_ingress_0001() != 0x1040U) return 9;
  if (!spx_native_capability_revoke(0U, generation) ||
      spx_ingress_0001() != SPX_CALL_UNIMPLEMENTED) return 10;
  generation = spx_native_capability_activate(0U, 1U);
  thread = CreateThread(0, 0, escaped_worker, 0, 0, 0);
  if (thread == 0 || !join_ok(thread)) return 11;
  if (!spx_native_capability_revoke(0U, generation)) return 12;
  generation = spx_native_capability_activate(1U, 1U);
  if (generation == 0U || spx_ingress_0007() != 0x10a0U ||
      spx_ingress_0007() != SPX_CALL_UNIMPLEMENTED) return 18;
  generation = spx_native_capability_activate(2U, 1U);
  if (generation == 0U || spx_ingress_0009() != 0x10c0U) return 19;
  generation = spx_native_capability_replace(2U, 0U, 1U);
  if (generation == 0U ||
      spx_ingress_0009() != SPX_CALL_UNIMPLEMENTED ||
      spx_ingress_0001() != 0x1040U) return 20;
  generation = spx_native_capability_activate(3U, 1U);
  if (generation == 0U || spx_ingress_0008() != 0x10b0U ||
      spx_native_capability_expire_event("resource_closed") != 1U ||
      spx_ingress_0008() != SPX_CALL_UNIMPLEMENTED) return 21;

  checkpoint("phase: hardware seh");
  if (spx_ingress_0004() != 0x6050U) return 13;
  checkpoint("phase: host seh");
  if (spx_ingress_0005() != 0x8070U) return 14;
  checkpoint("phase: escaping seh");
  observer = AddVectoredExceptionHandler(1U, exception_observer);
  if (observer == 0) return 15;
  if (spx_ingress_0006() != 0x9070U) return 16;
  RemoveVectoredExceptionHandler(observer);
  if (veh_seen != 1 || resumed_register_seen != 1) return 17;

  checkpoint("phase: teardown");
  remove_thread_tls();
  TlsFree(tls_index);
  puts("native ingress runtime acceptance: pass");
  return 0;
}
