#include <stdint.h>
#include <stdio.h>
#include <string.h>
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
extern uint32_t spx_ingress_0010(void);
extern uint32_t spx_ingress_0011(void);
extern uint32_t spx_ingress_0012(void);
extern uint32_t spx_ingress_0013(void);
extern uint32_t spx_ingress_0014(void);
extern uint32_t spx_ingress_0015(void);
extern uint32_t spx_ingress_0016(void);
extern uint32_t spx_ingress_0017(void);
extern uint32_t spx_ingress_0018(void);
extern uint32_t spx_ingress_0019(void);
extern uint32_t spx_ingress_0020(void);
extern const uint8_t spx_exception_pinned_retry[];
extern void *spx_native_runtime_context_current(void);
extern uint32_t *spx_native_raise_exception_iat_pointer;

static DWORD tls_index;
static uint32_t raise_exception_cell;
typedef VOID (NTAPI *rtl_raise_exception_fn)(PEXCEPTION_RECORD);
static rtl_raise_exception_fn rtl_raise_exception;
static volatile LONG shared_calls;
static volatile LONG captured_stack_checks;
static volatile LONG ready_threads;
static volatile LONG release_threads;
static volatile LONG stack_faults;
static volatile LONG veh_seen;
static volatile LONG resumed_register_seen;
static volatile LONG execution_restores;
static volatile LONG recovery_mark_checks;
static volatile LONG scoped_ready_threads;
static volatile LONG release_scoped_threads;
static uint32_t escaped_original_edi;
static uint32_t transactional_generation;
static uint32_t nested_transactional_generation;
static volatile LONG nested_handler_checks;
static volatile LONG nested_unwind_order;
static volatile LONG pinned_retry_armed;
static void *thread_contexts[THREADS];

typedef struct fixture_runtime_service_state {
  uint32_t guest_seh_head;
  uint32_t unwind_bound;
  uint32_t record_base;
  uint32_t record_count;
  uint32_t context;
  uint32_t handler_frame;
} fixture_runtime_service_state;

static fixture_runtime_service_state *fixture_runtime_services(void) {
  uint8_t *storage = (uint8_t *)TlsGetValue(tls_index);
  if (storage == 0) return 0;
  return (fixture_runtime_service_state *)(void *)(
      storage + TLS_BYTES - sizeof(fixture_runtime_service_state));
}

volatile spx_native_terminal_kind spx_native_terminal_status =
    SPX_NATIVE_TERMINAL_UNIMPLEMENTED;
volatile spx_call_status spx_native_terminal_call_status =
    SPX_CALL_UNIMPLEMENTED;
spx_machine_state spx_native_terminal_state;

void spx_native_terminate(spx_native_terminal_kind status) {
  ExitProcess((UINT)status);
}

uint32_t spx_behavioral_function_owner(
    uint32_t source_rva, uint32_t *owner_rva) {
  if (owner_rva == 0 || source_rva < 0x2000U || source_rva > 0x21ffU)
    return 0U;
  *owner_rva = source_rva;
  return 1U;
}

void spx_native_runtime_reset_guest_seh_chain(void) {
  fixture_runtime_service_state *state = fixture_runtime_services();
  if (state != 0) state->guest_seh_head = 0xffffffffU;
}

uint32_t spx_native_runtime_guest_seh_chain_head(uint32_t *head) {
  fixture_runtime_service_state *state = fixture_runtime_services();
  if (state == 0 || head == 0) return 0U;
  *head = state->guest_seh_head;
  return 1U;
}

uint32_t spx_native_runtime_set_guest_seh_chain_head(uint32_t head) {
  fixture_runtime_service_state *state = fixture_runtime_services();
  if (state == 0) return 0U;
  state->guest_seh_head = head;
  return 1U;
}

spx_call_status spx_native_runtime_bind_unwind_handler_objects(
    uint32_t record_base, uint32_t record_count,
    uint32_t context, uint32_t handler_frame) {
  fixture_runtime_service_state *state = fixture_runtime_services();
  if (state == 0 || state->unwind_bound != 0U || record_base == 0U ||
      record_count == 0U || context == 0U || handler_frame == 0U)
    return SPX_CALL_UNIMPLEMENTED;
  state->unwind_bound = 1U;
  state->record_base = record_base;
  state->record_count = record_count;
  state->context = context;
  state->handler_frame = handler_frame;
  return SPX_CALL_OK;
}

spx_call_status spx_native_runtime_unbind_unwind_handler_objects(
    uint32_t record_base, uint32_t record_count,
    uint32_t context, uint32_t handler_frame) {
  fixture_runtime_service_state *state = fixture_runtime_services();
  if (state == 0 || state->unwind_bound == 0U ||
      state->record_base != record_base ||
      state->record_count != record_count || state->context != context ||
      state->handler_frame != handler_frame)
    return SPX_CALL_UNIMPLEMENTED;
  state->unwind_bound = 0U;
  return SPX_CALL_OK;
}

uint32_t spx_native_runtime_exception_filter_callback_expected(void) {
  return 0U;
}

spx_call_status spx_native_runtime_bind_exception_filter_callback(
    uint32_t exception_pointers) {
  (void)exception_pointers;
  return SPX_CALL_UNIMPLEMENTED;
}

spx_call_status spx_native_runtime_unbind_exception_filter_callback(
    uint32_t exception_pointers) {
  (void)exception_pointers;
  return SPX_CALL_UNIMPLEMENTED;
}

static uint32_t call_dll_entry(uint32_t reason) {
  uint32_t result;
  __asm__ volatile (
      "pushl $0\n\t"
      "pushl %1\n\t"
      "pushl $0\n\t"
      "call _spx_ingress_0010"
      : "=a" (result) : "r" (reason) : "ecx", "edx", "cc", "memory");
  return result;
}

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

void spx_native_runtime_execution_mark(
    uint32_t *initialized, uint32_t *nested_depth) {
  if (initialized != 0) *initialized = 1U;
  if (nested_depth != 0) *nested_depth = 0U;
}

uint32_t spx_native_runtime_restore_execution(
    uint32_t initialized, uint32_t nested_depth,
    void *outgoing_mark, void *x87_mark) {
  void **state = (void **)spx_module_runtime_thread_state_current();
  if (initialized > 1U || (initialized == 0U && nested_depth != 0U) ||
      state == 0)
    return 0U;
  state[0] = outgoing_mark;
  state[2] = x87_mark;
  InterlockedIncrement(&execution_restores);
  return 1U;
}

uint32_t spx_native_realize_registered_code_result(
    uint32_t source_rva, uint32_t logical_value, uint32_t *native_value) {
  (void)source_rva;
  (void)logical_value;
  if (native_value == 0) return 2U;
  /* This isolated ingress fixture has no module code-capability table. */
  *native_value = 0U;
  return 0U;
}

static int recovered_execution_frames_are_clean(void) {
  if (spx_native_outgoing_frame_current() != 0 ||
      spx_native_x87_frame_current() != 0) {
    fprintf(
        stderr, "recovery marks outgoing=%p x87=%p\n",
        spx_native_outgoing_frame_current(), spx_native_x87_frame_current());
    return 0;
  }
  InterlockedIncrement(&recovery_mark_checks);
  return 1;
}

spx_call_status spx_native_runtime_run_at_rva(
    uint32_t rva, const spx_machine_state *input, spx_machine_state *output) {
  volatile uint32_t *slot;
  uint32_t nested, selector, matched_selector, object_base;
  uint32_t object_generation, matches;
  *output = *input;
  switch (rva) {
    case 0x1010U:
      matches = 0U;
      matched_selector = 0U;
      for (selector = 1U; selector <= 64U; ++selector) {
        if (spx_native_captured_stack_rule_base(
                selector, 0U, 4U, &object_base, &object_generation) == 0U)
          continue;
        if (object_base != input->esp || object_generation == 0U)
          return SPX_CALL_UNIMPLEMENTED;
        matched_selector = selector;
        ++matches;
      }
      if (matches != 1U ||
          spx_native_captured_stack_rule_base(
              matched_selector, 0xffffffffU, 4U,
              &object_base, &object_generation) != 0U)
        return SPX_CALL_UNIMPLEMENTED;
      InterlockedIncrement(&captured_stack_checks);
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
      transactional_generation = spx_native_capability_activate(0U, 1U);
      if (transactional_generation == 0U) return SPX_CALL_UNIMPLEMENTED;
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
    case 0x10d0U:
      output->eax = 1U;
      output->esp = input->esp + 16U;
      return SPX_CALL_OK;
    case 0x10e0U:
      output->eax = 0x10e0U;
      break;
    case 0x10f0U:
      return SPX_CALL_DIVIDE_ERROR;
    case 0x1100U:
      transactional_generation = spx_native_capability_activate(0U, 1U);
      if (transactional_generation == 0U) return SPX_CALL_UNIMPLEMENTED;
      output->eax = transactional_generation;
      break;
    case 0x1110U:
      transactional_generation = spx_native_capability_activate(0U, 1U);
      if (transactional_generation == 0U ||
          spx_native_capability_commit(0U, transactional_generation) == 0U)
        return SPX_CALL_UNIMPLEMENTED;
      output->eax = transactional_generation;
      break;
    case 0x1120U: {
      static const uint8_t one[10] = {
          0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x80U, 0xffU, 0x3fU};
      static const uint8_t two[10] = {
          0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x80U, 0x00U, 0x40U};
      uint32_t byte_index;
      if (input->x87_stack[0].empty != 0U ||
          input->x87_stack[0].tag != 0U) {
        fprintf(stderr, "x87 ingress tag empty=%lu tag=%lu status=%04x\n",
            (unsigned long)input->x87_stack[0].empty,
            (unsigned long)input->x87_stack[0].tag,
            (unsigned int)input->x87_status);
        return SPX_CALL_UNIMPLEMENTED;
      }
      for (byte_index = 0U; byte_index < 10U; ++byte_index)
        if (input->x87_stack[0].value_bytes[byte_index] != one[byte_index]) {
          fprintf(stderr, "x87 ingress byte %lu observed=%02x expected=%02x\n",
              (unsigned long)byte_index,
              (unsigned int)input->x87_stack[0].value_bytes[byte_index],
              (unsigned int)one[byte_index]);
          return SPX_CALL_UNIMPLEMENTED;
        }
      for (byte_index = 0U; byte_index < 10U; ++byte_index)
        output->x87_stack[0].value_bytes[byte_index] = two[byte_index];
      output->eax = 0x1120U;
      break;
    }
    case 0x1130U:
      nested = spx_ingress_0017();
      output->eax = nested;
      break;
    case 0x1140U:
      nested_transactional_generation =
          spx_native_capability_activate(0U, 1U);
      if (nested_transactional_generation == 0U)
        return SPX_CALL_UNIMPLEMENTED;
      __asm__ volatile (
          "xorl %%edx, %%edx\n\t"
          "movl $1, %%eax\n\t"
          "xorl %%ecx, %%ecx\n\t"
          "divl %%ecx" ::: "eax", "ecx", "edx", "cc");
      return SPX_CALL_UNIMPLEMENTED;
    case 0x1150U:
      return SPX_CALL_DIVIDE_ERROR;
    case 0x1160U:
      if (InterlockedCompareExchange(&pinned_retry_armed, 0, 1) == 1) {
        output->eax = 0x1160U;
        break;
      }
      __asm__ volatile (
          "xorl %%edx, %%edx\n\t"
          "movl $1, %%eax\n\t"
          "xorl %%ecx, %%ecx\n\t"
          "divl %%ecx" ::: "eax", "ecx", "edx", "cc");
      return SPX_CALL_UNIMPLEMENTED;
    case 0x1170U: {
      EXCEPTION_RECORD primary;
      EXCEPTION_RECORD nested_record;
      if (rtl_raise_exception == 0) return SPX_CALL_UNIMPLEMENTED;
      ZeroMemory(&primary, sizeof(primary));
      ZeroMemory(&nested_record, sizeof(nested_record));
      nested_record.ExceptionCode = 0xe0424242U;
      primary.ExceptionCode = EXCEPTION_INT_DIVIDE_BY_ZERO;
      primary.ExceptionRecord = &nested_record;
      rtl_raise_exception(&primary);
      return SPX_CALL_UNIMPLEMENTED;
    }
    case 0x2050U:
      if (!recovered_execution_frames_are_clean())
        return SPX_CALL_UNIMPLEMENTED;
      {
        static const uint8_t one[10] = {
            0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x80U, 0xffU, 0x3fU};
        uint32_t *handler_frame = (uint32_t *)(uintptr_t)input->esp;
        uint32_t *record = (uint32_t *)(uintptr_t)handler_frame[1];
        uint32_t *context = (uint32_t *)(uintptr_t)handler_frame[3];
        if (record == 0 || context == 0 ||
            record[0] != EXCEPTION_INT_DIVIDE_BY_ZERO ||
            record[2] != 0U ||
            input->x87_stack[0].empty != 0U ||
            input->x87_stack[0].tag != 0U ||
            memcmp(input->x87_stack[0].value_bytes, one, sizeof(one)) != 0)
          return SPX_CALL_UNIMPLEMENTED;
        context[44] = 0x31415926U;
      }
      output->eax = 50U;
      return SPX_CALL_OK;
    case 0x2060U:
      if (input->eax != 0x31415926U) return SPX_CALL_UNIMPLEMENTED;
      output->eax = 0x6050U;
      break;
    case 0x2070U:
      if (!recovered_execution_frames_are_clean())
        return SPX_CALL_UNIMPLEMENTED;
      output->eax = 70U;
      return SPX_CALL_OK;
    case 0x2080U:
      output->eax = 0x8070U;
      break;
    case 0x2090U:
      if (output->edi == 0x13579bdfU)
        InterlockedIncrement(&resumed_register_seen);
      output->edi = escaped_original_edi;
      output->eax = 0x9070U;
      break;
    case 0x20a0U:
      output->eax = 0x20a0U;
      break;
    case 0x20b0U:
      output->eax = 0x20b0U;
      break;
    case 0x2150U:
      if (!recovered_execution_frames_are_clean() ||
          nested_unwind_order != 2 ||
          nested_transactional_generation == 0U ||
          spx_native_capability_revoke(
              0U, nested_transactional_generation) != 0U)
        return SPX_CALL_UNIMPLEMENTED;
      InterlockedIncrement(&nested_handler_checks);
      output->eax = 0x2150U;
      return SPX_CALL_OK;
    case 0x2160U:
      output->eax = 0x2160U;
      break;
    case 0x2170U:
      if (InterlockedCompareExchange(&nested_unwind_order, 1, 0) != 0)
        return SPX_CALL_UNIMPLEMENTED;
      return SPX_CALL_OK;
    case 0x2180U:
      if (InterlockedCompareExchange(&nested_unwind_order, 2, 1) != 1)
        return SPX_CALL_UNIMPLEMENTED;
      return SPX_CALL_OK;
    case 0x2190U: {
      uint32_t *handler_frame = (uint32_t *)(uintptr_t)input->esp;
      uint32_t *context = (uint32_t *)(uintptr_t)handler_frame[3];
      if (context == 0 ||
          InterlockedCompareExchange(&pinned_retry_armed, 1, 0) != 0)
        return SPX_CALL_UNIMPLEMENTED;
      context[46] = (uint32_t)(uintptr_t)spx_exception_pinned_retry;
      return SPX_CALL_OK;
    }
    case 0x21a0U:
      output->eax = 0x21a0U;
      break;
    case 0x21b0U: {
      uint32_t *handler_frame = (uint32_t *)(uintptr_t)input->esp;
      uint32_t *record = (uint32_t *)(uintptr_t)handler_frame[1];
      uint32_t *nested_record;
      if (record == 0 || record[0] != EXCEPTION_INT_DIVIDE_BY_ZERO)
        return SPX_CALL_UNIMPLEMENTED;
      nested_record = (uint32_t *)(uintptr_t)record[2];
      if (nested_record == 0 || nested_record[0] != 0xe0424242U ||
          nested_record[2] != 0U)
        return SPX_CALL_UNIMPLEMENTED;
      output->eax = 0x21b0U;
      return SPX_CALL_OK;
    }
    case 0x21c0U:
      output->eax = 0x21c0U;
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

static DWORD WINAPI blocked_foreign_worker(void *argument) {
  uint32_t result;
  (void)argument;
  if (!install_thread_tls()) return 22U;
  result = spx_ingress_0001();
  remove_thread_tls();
  return result == SPX_CALL_UNIMPLEMENTED ? 0U : 23U;
}

static DWORD WINAPI scoped_worker(void *argument) {
  uint32_t generation, result;
  (void)argument;
  if (!install_thread_tls()) return 24U;
  generation = spx_native_capability_activate(4U, 0U);
  if (generation == 0U) return 25U;
  InterlockedIncrement(&scoped_ready_threads);
  while (InterlockedCompareExchange(&release_scoped_threads, 0, 0) == 0)
    Sleep(0);
  result = spx_ingress_0001();
  if (!spx_native_capability_revoke(4U, generation)) return 26U;
  remove_thread_tls();
  return result == 0x1040U ? 0U : 27U;
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

int main(int argc, char **argv) {
  HANDLE threads[THREADS];
  HANDLE thread;
  PVOID observer;
  uint32_t generation, other_generation;
  uint32_t index, other;
  uint32_t hardware_result, blocked_result, revoked_result, nested_result;
  uint32_t nested_record_result;

  if (argc == 2 && strcmp(argv[1], "process-root-termination") == 0) {
    tls_index = TlsAlloc();
    if (tls_index == TLS_OUT_OF_INDEXES || !install_thread_tls()) return 40;
    spx_native_tls_index_cell_pointer = (uint32_t *)(void *)&tls_index;
    (void)spx_ingress_0018();
    return 41;
  }

  tls_index = TlsAlloc();
  if (tls_index == TLS_OUT_OF_INDEXES || !install_thread_tls()) return 1;
  spx_native_tls_index_cell_pointer = (uint32_t *)(void *)&tls_index;
  spx_native_module_base_pointer = (uint8_t *)(uintptr_t)(
      (uintptr_t)spx_exception_pinned_retry - 0x1160U);
  raise_exception_cell = (uint32_t)(uintptr_t)RaiseException;
  spx_native_raise_exception_iat_pointer = &raise_exception_cell;
  rtl_raise_exception = (rtl_raise_exception_fn)(uintptr_t)GetProcAddress(
      GetModuleHandleA("ntdll.dll"), "RtlRaiseException");
  if (rtl_raise_exception == 0) return 42;
  checkpoint("phase: concurrent");
  if (call_dll_entry(DLL_PROCESS_ATTACH) != 1U) return 28;

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
  if (captured_stack_checks != (LONG)(THREADS * ITERATIONS)) return 34;
  for (index = 1U; index <= 64U; ++index) {
    uint32_t base, observed_generation;
    if (spx_native_captured_stack_rule_base(
            index, 0U, 4U, &base, &observed_generation) != 0U)
      return 35;
  }
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
  generation = spx_native_capability_activate(4U, 0U);
  thread = CreateThread(0, 0, blocked_foreign_worker, 0, 0, 0);
  if (generation == 0U || thread == 0 || !join_ok(thread) ||
      !spx_native_capability_revoke(4U, generation)) return 22;
  for (index = 0; index < THREADS; ++index) {
    threads[index] = CreateThread(0, 0, scoped_worker, 0, 0, 0);
    if (threads[index] == 0) return 23;
  }
  while (InterlockedCompareExchange(&scoped_ready_threads, 0, 0) !=
         (LONG)THREADS)
    Sleep(0);
  InterlockedExchange(&release_scoped_threads, 1);
  for (index = 0; index < THREADS; ++index)
    if (!join_ok(threads[index])) return 24;
  generation = spx_native_capability_activate(1U, 1U);
  other_generation = spx_native_capability_activate(1U, 1U);
  if (generation == 0U || other_generation == 0U ||
      generation == other_generation ||
      spx_ingress_0007() != 0x10a0U ||
      spx_ingress_0007() != 0x10a0U ||
      spx_ingress_0007() != SPX_CALL_UNIMPLEMENTED) return 18;
  generation = spx_native_capability_activate(2U, 1U);
  if (generation == 0U || spx_ingress_0009() != 0x10c0U) return 19;
  generation = spx_native_capability_replace(2U, 0U, 1U);
  if (generation == 0U ||
      spx_ingress_0009() != SPX_CALL_UNIMPLEMENTED ||
      spx_ingress_0001() != 0x1040U ||
      spx_native_capability_revoke(0U, generation) == 0U) return 20;
  generation = spx_native_capability_activate(3U, 1U);
  if (generation == 0U || spx_ingress_0008() != 0x10b0U ||
      spx_native_capability_expire_event("resource_closed") != 1U ||
      spx_ingress_0008() != SPX_CALL_UNIMPLEMENTED) return 21;

  checkpoint("phase: hardware seh");
  __asm__ volatile ("fninit\n\tfld1" : : : "memory");
  hardware_result = spx_ingress_0004();
  __asm__ volatile ("fninit" : : : "memory");
  blocked_result = spx_ingress_0001();
  revoked_result = spx_native_capability_revoke(
      0U, transactional_generation);
  if (hardware_result != 0x6050U ||
      blocked_result != SPX_CALL_UNIMPLEMENTED || revoked_result != 0U) {
    fprintf(
        stderr,
        "hardware seh result=%08lx blocked=%08lx revoked=%lu "
        "restores=%ld checks=%ld\n",
        (unsigned long)hardware_result, (unsigned long)blocked_result,
        (unsigned long)revoked_result, execution_restores,
        recovery_mark_checks);
    return 13;
  }
  checkpoint("phase: host seh");
  if (spx_ingress_0005() != 0x8070U ||
      execution_restores < 2 || recovery_mark_checks != 2)
    return 14;
  checkpoint("phase: nested exception record");
  nested_record_result = spx_ingress_0020();
  if (nested_record_result != 0x21c0U) {
    fprintf(
        stderr, "nested record result=%08lx\n",
        (unsigned long)nested_record_result);
    return 43;
  }
  checkpoint("phase: pinned eip retry");
  if (spx_ingress_0019() != 0x1160U || pinned_retry_armed != 0)
    return 39;
  checkpoint("phase: nested seh search");
  nested_result = spx_ingress_0016();
  revoked_result = spx_native_capability_revoke(
      0U, nested_transactional_generation);
  if (nested_result != 0x2160U || nested_handler_checks != 1 ||
      nested_unwind_order != 2 ||
      revoked_result != 0U) {
    fprintf(
        stderr,
        "nested seh result=%08lx handlers=%ld unwind=%ld revoked=%lu generation=%08lx "
        "restores=%ld checks=%ld\n",
        (unsigned long)nested_result, nested_handler_checks,
        nested_unwind_order,
        (unsigned long)revoked_result,
        (unsigned long)nested_transactional_generation,
        execution_restores, recovery_mark_checks);
    return 36;
  }
  checkpoint("phase: escaping seh");
  observer = AddVectoredExceptionHandler(1U, exception_observer);
  if (observer == 0) return 15;
  if (spx_ingress_0006() != 0x9070U) return 16;
  RemoveVectoredExceptionHandler(observer);
  if (veh_seen != 1 || resumed_register_seen != 1) return 17;

  checkpoint("phase: process-root termination");
  {
    char executable[MAX_PATH];
    char command[MAX_PATH + 64];
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD exit_code = 0xffffffffU;
    startup.cb = sizeof(startup);
    if (GetModuleFileNameA(0, executable, MAX_PATH) == 0U ||
        snprintf(
            command, sizeof(command), "\"%s\" process-root-termination",
            executable) < 0 ||
        !CreateProcessA(
            0, command, 0, 0, FALSE, 0, 0, 0, &startup, &process))
      return 37;
    WaitForSingleObject(process.hProcess, INFINITE);
    if (!GetExitCodeProcess(process.hProcess, &exit_code)) exit_code = 0xffffffffU;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (exit_code != SPX_NATIVE_TERMINAL_DIVIDE_ERROR) {
      fprintf(
          stderr, "process-root termination exit=%08lx expected=%08lx\n",
          (unsigned long)exit_code,
          (unsigned long)SPX_NATIVE_TERMINAL_DIVIDE_ERROR);
      return 38;
    }
  }

  checkpoint("phase: outcome protocol");
  if (spx_ingress_0011() != SPX_CALL_UNIMPLEMENTED ||
      spx_ingress_0012() != SPX_CALL_DIVIDE_ERROR) return 31;

  checkpoint("phase: transactional capabilities");
  if (spx_ingress_0013() == SPX_CALL_UNIMPLEMENTED ||
      spx_ingress_0001() != SPX_CALL_UNIMPLEMENTED ||
      spx_native_capability_revoke(0U, transactional_generation) != 0U ||
      spx_ingress_0014() == SPX_CALL_UNIMPLEMENTED ||
      spx_ingress_0001() != 0x1040U ||
      spx_native_capability_revoke(0U, transactional_generation) == 0U)
    return 32;

  checkpoint("phase: complete x87 ingress state");
  {
    static const uint8_t two[10] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x80U, 0x00U, 0x40U};
    uint8_t observed[10];
    uint32_t byte_index;
    __asm__ volatile ("fninit\n\tfld1" : : : "memory");
    if (spx_ingress_0015() != 0x1120U) return 33;
    __asm__ volatile ("fstpt %0" : "=m" (observed) : : "memory");
    for (byte_index = 0U; byte_index < 10U; ++byte_index)
      if (observed[byte_index] != two[byte_index]) return 34;
  }

  checkpoint("phase: loader lifecycle");
  generation = spx_native_capability_activate(4U, 0U);
  if (generation == 0U || call_dll_entry(DLL_THREAD_DETACH) != 1U ||
      spx_ingress_0001() != SPX_CALL_UNIMPLEMENTED ||
      spx_native_capability_revoke(4U, generation) != 0U ||
      call_dll_entry(DLL_THREAD_ATTACH) != 1U) return 29;
  generation = spx_native_capability_activate(0U, 1U);
  if (generation == 0U || spx_ingress_0001() != 0x1040U ||
      call_dll_entry(DLL_PROCESS_DETACH) != 1U ||
      spx_ingress_0001() != SPX_CALL_UNIMPLEMENTED ||
      spx_native_capability_revoke(0U, generation) != 0U ||
      spx_native_capability_activate(0U, 1U) != 0U) return 30;

  checkpoint("phase: teardown");
  remove_thread_tls();
  TlsFree(tls_index);
  puts("native ingress runtime acceptance: pass");
  return 0;
}
