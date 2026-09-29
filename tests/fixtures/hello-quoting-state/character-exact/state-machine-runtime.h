#ifndef SPX_STATE_MACHINE_RUNTIME_H
#define SPX_STATE_MACHINE_RUNTIME_H

#define SPX_MACHINE_STATE_HAS_EFLAGS 1

#include <stdint.h>

typedef struct spx_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} spx_x87_value;

typedef struct spx_machine_state {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  spx_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t eflags;
  uint32_t fs_base;
  uint32_t original_rva;
} spx_machine_state;

_Static_assert(sizeof(((spx_x87_value *)0)->value_bytes) == 10U,
    "x87 payload must be exactly 80 bits");
_Static_assert(sizeof(((spx_x87_value *)0)->empty) == 4U,
    "x87 occupancy must match the runtime-state layout");
_Static_assert(sizeof(((spx_x87_value *)0)->tag) == 1U,
    "x87 tag must match the runtime-state layout");

typedef struct spx_stack_input {
  uint32_t offset;
  uint32_t width;
  uint32_t value;
} spx_stack_input;

typedef enum spx_call_event_kind {
  SPX_CALL_EXTERNAL_IMPORT = 0,
  SPX_CALL_INTERNAL_DIRECT = 1,
  SPX_CALL_INDIRECT = 2
} spx_call_event_kind;

typedef enum spx_code_site_kind {
  SPX_CODE_SITE_INDIRECT_CALL = 0,
  SPX_CODE_SITE_INDIRECT_JUMP = 1
} spx_code_site_kind;

typedef struct spx_call_event {
  spx_call_event_kind kind;
  uint32_t source_rva;
  uint32_t instruction_rva;
  uint32_t call_index;
  uint32_t target_rva;
  uint32_t return_rva;
  const char *dll;
  const char *symbol;
  uint32_t ordinal;
  uint32_t has_ordinal;
  const uint32_t *arguments;
  uint32_t argument_count;
  const spx_stack_input *stack_inputs;
  uint32_t stack_input_count;
} spx_call_event;

#define SPX_MAX_EXTERNAL_ARGUMENTS 256U
typedef struct spx_external_call_snapshot {
  uint32_t instruction_rva;
  uint32_t target_iat_rva;
  uint32_t target_catalog_index;
  uint32_t argument_base_offset;
  uint32_t argument_count;
  uint32_t arguments[SPX_MAX_EXTERNAL_ARGUMENTS];
} spx_external_call_snapshot;

#define SPX_MACHINE_STATE_HAS_X87 1

typedef struct spx_typed_x87_operation {
  uint32_t image_base, rva_start, rva_end, source_size;
  const char *operation_identity;
  const char *contract_sha256;
  const char *checked_decoder;
  const char *checked_executor;
  const char *mnemonic;
  uint32_t operand_kind, operand_width;
  uint32_t stack_register_count, stack_register_0, stack_register_1;
  uint32_t base_register, index_register, scale;
  int32_t displacement;
  uint32_t image_rva, has_image_rva;
} spx_typed_x87_operation;

typedef struct spx_runtime spx_runtime;

typedef enum spx_call_status {
  SPX_CALL_OK = 0,
  SPX_CALL_UNIMPLEMENTED = 1,
  SPX_CALL_DIVIDE_ERROR = 2,
  SPX_CALL_MEMORY_FAULT = 3,
  SPX_CALL_EXTERNAL_FAULT = 4,
  SPX_CALL_NONLOCAL = 5
} spx_call_status;

typedef spx_call_status (*spx_external_call_handler)(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

typedef void (*spx_atomic_compare_exchange_handler)(
    void *context,
    uint32_t address,
    uint32_t width,
    uint32_t expected,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *exchanged,
    uint32_t *fault);

typedef void (*spx_atomic_exchange_handler)(
    void *context,
    uint32_t address,
    uint32_t width,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *fault);

typedef enum spx_boundary_status {
  SPX_BOUNDARY_OK = 0,
  SPX_BOUNDARY_MEMORY_FAULT = 1,
  SPX_BOUNDARY_EXPIRED = 2,
  SPX_BOUNDARY_UNSUPPORTED = 3,
  SPX_BOUNDARY_TYPE_MISMATCH = 4
} spx_boundary_status;

typedef struct spx_machine_reference_v1 {
  uint64_t domain;
  uint64_t object;
  uint64_t generation;
  uint64_t offset;
  uint64_t extent;
  uint32_t permissions;
} spx_machine_reference_v1;

typedef struct spx_machine_resource_v1 {
  uint32_t type_tag;
  uint32_t generation;
  uint64_t identity;
} spx_machine_resource_v1;

typedef spx_boundary_status (*spx_boundary_resolve_reference_handler)(
    void *context, uint32_t address, uint32_t requested_extent,
    uint32_t permissions, const char *authority_selector,
    uint32_t nullable, uint32_t allow_one_past,
    spx_machine_reference_v1 *result);

typedef spx_boundary_status (*spx_boundary_realize_reference_handler)(
    void *context, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t allow_one_past,
    uint32_t *address);

typedef spx_boundary_status (*spx_boundary_resolve_interface_resource_handler)(
    void *context, const char *profile_sha256, const char *interface_id,
    uint32_t physical_word, uint32_t nullable,
    spx_machine_resource_v1 *result);

typedef spx_boundary_status (*spx_boundary_realize_interface_resource_handler)(
    void *context, const char *profile_sha256, const char *interface_id,
    const spx_machine_resource_v1 *resource, uint32_t nullable,
    uint32_t *physical_word);

typedef spx_call_status (*spx_typed_x87_handler)(
    spx_runtime *runtime,
    const spx_typed_x87_operation *program,
    const spx_machine_state *input,
    spx_machine_state *output);

typedef uint32_t (*spx_code_target_resolver)(
    spx_runtime *runtime,
    spx_code_site_kind site_kind,
    uint32_t source_rva,
    uint32_t instruction_rva,
    uint32_t event_index,
    uint32_t target_word,
    uint32_t *target_rva);

typedef spx_call_status (*spx_callable_external_jump_handler)(
    spx_runtime *runtime,
    uint32_t source_rva,
    uint32_t target_word,
    const spx_machine_state *input,
    spx_machine_state *output);

typedef uint32_t (*spx_access_violation_handler)(
    void *context, uint32_t operation, uint32_t address);

typedef uint32_t (*spx_nonlocal_route_handler)(
    spx_runtime *runtime,
    uint32_t observed_source_rva,
    uint32_t target_rva,
    uint32_t value,
    uint32_t current_function_entry_rva,
    spx_machine_state *state,
    uint32_t *resume_rva);

struct spx_runtime {
  void *context;
  uint32_t image_base;
  uint32_t (*read)(void *context, uint32_t address, uint32_t width, uint32_t *fault);
  void (*write)(void *context, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault);
  spx_atomic_compare_exchange_handler atomic_compare_exchange;
  spx_atomic_exchange_handler atomic_exchange;
  spx_boundary_resolve_reference_handler resolve_reference;
  spx_boundary_realize_reference_handler realize_reference;
  spx_boundary_resolve_interface_resource_handler resolve_interface_resource;
  spx_boundary_realize_interface_resource_handler realize_interface_resource;
  uint32_t (*undefined_value)(
      void *context, uint32_t slot, const spx_machine_state *input,
      uint32_t defined_value);
  spx_external_call_handler external_call_fallback;
  spx_code_target_resolver resolve_code_target;
  spx_typed_x87_handler execute_typed_x87_operation;
  spx_nonlocal_route_handler route_nonlocal;
  spx_callable_external_jump_handler invoke_callable_external_jump;
  spx_access_violation_handler record_access_violation;
};

void spx_runtime_atomic_compare_exchange(
    spx_runtime *runtime,
    uint32_t address,
    uint32_t width,
    uint32_t expected,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *exchanged,
    uint32_t *fault);

void spx_runtime_atomic_exchange(
    spx_runtime *runtime,
    uint32_t address,
    uint32_t width,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *fault);

spx_call_status spx_invoke_call(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

typedef enum spx_control_kind {
  SPX_FALLTHROUGH = 0,
  SPX_JUMP = 1,
  SPX_BRANCH = 2,
  SPX_RETURN = 3,
  SPX_INDIRECT_JUMP = 4,
  SPX_DIVIDE_ERROR = 5,
  SPX_MEMORY_FAULT = 6,
  SPX_UNIMPLEMENTED = 7,
  SPX_EXTERNAL_FAULT = 8,
  SPX_EXTERNAL_JUMP = 9,
  SPX_NONLOCAL = 10
} spx_control_kind;

typedef struct spx_step_result {
  spx_control_kind kind;
  uint32_t target_rva;
  uint32_t value;
} spx_step_result;

#endif
