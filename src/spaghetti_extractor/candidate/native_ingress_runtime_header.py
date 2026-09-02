# ruff: noqa: F401
"""Exact IA-32 PE-TLS ABI and table-driven native-ingress source emission."""

from __future__ import annotations

from typing import Any, Mapping

from ..transfer.exception_projection import MAX_EXCEPTION_RECORD_CHAIN_V1
from .native_ingress_runtime_abi import (
    EXCEPTION_CHAIN_SCRATCH_BYTES,
    MAX_INGRESS_DEPTH,
    PRIVATE_STACK_SLICE_BYTES,
    RUNTIME_CONTEXT_OFFSET,
    THREAD_ABI_VERSION,
    THREAD_MAGIC,
    exact_tls_regions,
)
from .native_ingress_runtime_model import NativeIngressSupportABI


def render_native_ingress_header(plan: Mapping[str, Any]) -> str:
    abi = NativeIngressSupportABI.parse(plan)
    return f'''#ifndef SPX_NATIVE_INGRESS_RUNTIME_H
#define SPX_NATIVE_INGRESS_RUNTIME_H

#include "shared-module-runtime.h"

#define SPX_NATIVE_THREAD_MAGIC 0x{THREAD_MAGIC:08x}U
#define SPX_NATIVE_THREAD_ABI_VERSION {THREAD_ABI_VERSION}U
#define SPX_NATIVE_TLS_RUNTIME_OFFSET {abi.runtime_offset}U
#define SPX_NATIVE_TLS_CONTROL_BYTES {abi.runtime_control_bytes}U
#define SPX_PRIVATE_STACK_OFFSET {abi.private_stack_offset}U
#define SPX_PRIVATE_STACK_BYTES {abi.private_stack_bytes}U
#define SPX_PRIVATE_STACK_SLICE_BYTES {PRIVATE_STACK_SLICE_BYTES}U
#define SPX_EXCEPTION_CHAIN_SCRATCH_BYTES {EXCEPTION_CHAIN_SCRATCH_BYTES}U
#define SPX_EXCEPTION_RECORD_CHAIN_CAPACITY {MAX_EXCEPTION_RECORD_CHAIN_V1}U
#define SPX_NATIVE_MAX_INGRESS_DEPTH {MAX_INGRESS_DEPTH}U
#define SPX_NATIVE_RUNTIME_CONTEXT_OFFSET {RUNTIME_CONTEXT_OFFSET}U
#define SPX_NATIVE_CHECKED_UNWIND_FRAME_LIMIT 64U

typedef struct spx_native_physical_capture {{
  uint32_t edi, esi, ebp, entry_esp, ebx, edx, ecx, eax, eflags;
}} spx_native_physical_capture;

typedef struct spx_native_checked_unwind_frame {{
  uint32_t establisher, handler_rva;
}} spx_native_checked_unwind_frame;

typedef struct spx_native_checked_unwind_snapshot {{
  uint32_t head, target_frame, frame_count;
  spx_native_checked_unwind_frame
      frames[SPX_NATIVE_CHECKED_UNWIND_FRAME_LIMIT];
}} spx_native_checked_unwind_snapshot;

extern uint32_t *spx_native_tls_index_cell_pointer;
extern uint8_t *spx_native_module_base_pointer;
void *spx_native_ingress_prepare(
    uint32_t bridge_index, spx_native_physical_capture *capture);
uint32_t spx_native_ingress_dispatch(uint32_t bridge_index);
void *spx_native_callback_prepare(
    uint32_t flat_target_index, spx_native_physical_capture *capture);
uint32_t spx_native_callback_dispatch(void);
spx_native_physical_capture *spx_native_ingress_finish(uint32_t status);
spx_native_physical_capture *spx_native_ingress_current_capture(void);
uint32_t spx_native_ingress_recover_exception(void);
uint32_t spx_native_exception_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access);
uint32_t spx_native_physical_frame_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access);
uint32_t spx_native_captured_stack_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access);
uint32_t spx_native_exception_stack_pointer_authorized(uint32_t address);
uint32_t spx_native_checked_unwind_inspect(
    uint32_t target_frame, spx_native_checked_unwind_snapshot *snapshot);
spx_call_status spx_native_checked_unwind_commit(
    const spx_native_checked_unwind_snapshot *snapshot,
    uint32_t exception_record_count,
    const uint32_t exception_record_words[][20],
    spx_runtime *runtime, spx_machine_state *state);
int32_t spx_native_seh_dispatch(
    const void *record, void *establisher, void *context, void *dispatcher);
uint32_t spx_native_capability_publish(
    uint32_t capability_index, uint32_t generation, uint32_t escaped);
uint32_t spx_native_capability_revoke(
    uint32_t capability_index, uint32_t generation);
uint32_t spx_native_capability_commit(
    uint32_t capability_index, uint32_t generation);
uint32_t spx_native_capability_activate(
    uint32_t capability_index, uint32_t escaped);
uint32_t spx_native_capability_is_active(uint32_t capability_index);
uint32_t spx_native_capability_replace(
    uint32_t old_capability_index, uint32_t new_capability_index,
    uint32_t escaped);
uint32_t spx_native_capability_expire_event(const char *event_id);
uint32_t spx_native_compact_callback_activate(
    uint32_t flat_target_index, uint32_t escaped);
uint32_t spx_native_compact_callback_commit(
    uint32_t flat_target_index, uint32_t generation);
uint32_t spx_native_compact_callback_revoke(
    uint32_t flat_target_index, uint32_t generation);
uint32_t spx_native_compact_callback_is_active(uint32_t flat_target_index);
uint32_t spx_native_captured_stack_rule_base(
    uint32_t physical_frame_selector, uint32_t offset, uint32_t extent,
    uint32_t *base, uint32_t *generation);
volatile uint32_t *spx_native_runtime_diagnostic_slot(uint32_t index);
void *spx_module_runtime_thread_state_current(void);
void *spx_native_module_tls_base_current(void);
void *spx_native_outgoing_frame_current(void);
void *spx_native_x87_frame_current(void);
uint32_t spx_native_outgoing_stack_enter_host(void);
uint32_t spx_native_outgoing_stack_leave_host(void);
uint32_t spx_native_host_stack_bounds_current(
    uint32_t *stack_base, uint32_t *stack_limit);
void spx_native_runtime_execution_mark(
    uint32_t *initialized, uint32_t *nested_depth);
uint32_t spx_native_runtime_restore_execution(
    uint32_t initialized, uint32_t nested_depth,
    void *outgoing_mark, void *x87_mark);
void spx_native_runtime_reset_guest_seh_chain(void);
uint32_t spx_native_runtime_guest_seh_chain_head(uint32_t *head);
uint32_t spx_native_runtime_set_guest_seh_chain_head(uint32_t head);
uint32_t spx_native_realize_registered_code_result(
    uint32_t source_rva, uint32_t logical_value, uint32_t *native_value);

#endif
'''
