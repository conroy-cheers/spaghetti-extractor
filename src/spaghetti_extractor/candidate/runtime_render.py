"""Native runtime header, tables, and front-half C rendering."""

from __future__ import annotations

import json

from ..artifacts.artifact_set import canonical_sha256_v3
from .runtime_model import (
    INTERFACE_METHOD_TARGET_TAG,
    SharedModuleRuntimePlan,
    interface_class_catalog,
    interface_method_target_catalog,
    loader_target_catalog,
)
from .runtime_render_core import _native_runtime_source_core
from .runtime_render_entry import _native_runtime_source_entry


def _native_runtime_header() -> str:
    return r'''#ifndef SPX_NATIVE_RUNTIME_H
#define SPX_NATIVE_RUNTIME_H

#include "behavioral-c.h"

typedef enum spx_native_terminal_kind {
  SPX_NATIVE_TERMINAL_RETURNED = 0,
  SPX_NATIVE_TERMINAL_UNIMPLEMENTED = 1,
  SPX_NATIVE_TERMINAL_DIVIDE_ERROR = 2,
  SPX_NATIVE_TERMINAL_MEMORY_FAULT = 3,
  SPX_NATIVE_TERMINAL_EXTERNAL_FAULT = 4,
  SPX_NATIVE_TERMINAL_UNDEFINED_VALUE = 5,
  SPX_NATIVE_TERMINAL_INVALID_IMAGE = 6
} spx_native_terminal_kind;

extern const char spx_native_behavioral_c_manifest_sha256[65];
extern const char spx_module_runtime_plan_sha256[65];
extern const char spx_native_state_machine_sha256[65];
extern volatile spx_native_terminal_kind spx_native_terminal_status;
extern volatile spx_call_status spx_native_terminal_call_status;
extern spx_machine_state spx_native_terminal_state;
extern spx_runtime spx_native_runtime_instance;
void spx_native_terminate(spx_native_terminal_kind status)
    __attribute__((noreturn));

spx_call_status spx_native_runtime_run_at_rva(
    uint32_t entry_rva, const spx_machine_state *input,
    spx_machine_state *output);

#define SPX_NATIVE_EXCEPTION_OBJECT_SNAPSHOT_BYTES 2112U
spx_call_status spx_native_runtime_begin_exception_object(
    uint32_t exception_pointers, void *snapshot, uint32_t capacity,
    uint32_t *snapshot_size);
spx_call_status spx_native_runtime_finish_exception_object(
    uint32_t exception_pointers, void *snapshot, uint32_t snapshot_size,
    uint32_t commit);
spx_call_status spx_native_runtime_bind_exception_filter_callback(
    uint32_t exception_pointers);
spx_call_status spx_native_runtime_unbind_exception_filter_callback(
    uint32_t exception_pointers);
uint32_t spx_native_runtime_exception_filter_callback_expected(void);
spx_call_status spx_native_runtime_begin_checked_unwind(
    uint32_t source_rva, uint32_t target_frame,
    uint32_t target_instruction, uint32_t exception_record,
    uint32_t return_value, const spx_machine_state *input,
    spx_machine_state *output);
spx_call_status spx_native_runtime_bind_unwind_handler_objects(
    uint32_t record_base, uint32_t record_count,
    uint32_t context, uint32_t handler_frame);
spx_call_status spx_native_runtime_unbind_unwind_handler_objects(
    uint32_t record_base, uint32_t record_count,
    uint32_t context, uint32_t handler_frame);
void spx_native_runtime_reset_guest_seh_chain(void);
uint32_t spx_native_runtime_guest_seh_chain_head(uint32_t *head);
uint32_t spx_native_runtime_set_guest_seh_chain_head(uint32_t head);

#endif
'''


def _portable_component_reference_runtime() -> str:
    """Reviewed shared implementation of the portable component reference ABI."""

    return r'''
typedef struct spx_ref_v5 {
  uint32_t domain;
  uint32_t object;
  uint32_t generation;
  uint64_t offset;
  uint64_t extent;
  uint32_t permissions;
} spx_ref_v5;

typedef struct spx_view_v5 {
  void *context;
  uint32_t (*read_u8)(void *, uint64_t, uint8_t *);
  uint32_t (*write_u8)(void *, uint64_t, uint8_t);
  spx_ref_v5 base;
  uint64_t extent;
} spx_view_v5;

static uint32_t spx_component_ref_is_null(spx_ref_v5 value) {
  return value.domain == 0U && value.object == 0U &&
      value.generation == 0U && value.offset == 0U &&
      value.extent == 0U && value.permissions == 0U;
}

uint32_t spx_ref_derive(
    spx_ref_v5 reference, uint64_t delta, uint32_t allow_one_past,
    spx_ref_v5 *result) {
  uint64_t offset;
  if (result == 0 || spx_component_ref_is_null(reference) ||
      UINT64_MAX - reference.offset < delta)
    return 1U;
  offset = reference.offset + delta;
  if (offset > reference.extent ||
      (offset == reference.extent && allow_one_past == 0U))
    return 1U;
  *result = reference;
  result->offset = offset;
  return 0U;
}

uint32_t spx_ref_difference(
    spx_ref_v5 left, spx_ref_v5 right, int64_t *result) {
  if (result == 0 || spx_component_ref_is_null(left) ||
      spx_component_ref_is_null(right) || left.domain != right.domain ||
      left.object != right.object || left.generation != right.generation ||
      left.extent != right.extent || left.offset > INT64_MAX ||
      right.offset > INT64_MAX)
    return 1U;
  *result = (int64_t)left.offset - (int64_t)right.offset;
  return 0U;
}

uint32_t spx_view_read_u8(
    const spx_view_v5 *view, uint64_t index, uint8_t *result) {
  if (view == 0 || result == 0 || view->read_u8 == 0 ||
      index >= view->extent)
    return 1U;
  return view->read_u8(view->context, index, result) == 0U ? 0U : 1U;
}
'''


def _native_runtime_source(plan: SharedModuleRuntimePlan) -> str:
    ingress_include = '#include "native-ingress-runtime.h"\n'
    transfer_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.transfer_rvas
    )
    guest_target_values: list[int] = []
    guest_domain_offsets: dict[str, tuple[int, int]] = {}
    guest_external_iat_values: list[int] = []
    guest_external_catalog_values: list[int] = []
    guest_external_domain_offsets: dict[str, tuple[int, int]] = {}
    loader_targets, loader_target_indexes = loader_target_catalog(
        plan.guest_dispatch_domains
    )
    interface_targets, interface_target_indexes = interface_method_target_catalog(
        plan.guest_dispatch_domains
    )
    interface_classes, interface_class_indexes = interface_class_catalog(
        plan.guest_dispatch_domains
    )
    for domain in plan.guest_dispatch_domains:
        offset = len(guest_target_values)
        guest_target_values.extend(domain.target_rvas)
        guest_domain_offsets[domain.domain_sha256] = (
            offset, len(domain.target_rvas)
        )
        external_offset = len(guest_external_iat_values)
        external_iats = tuple(
            int(target.get("iat_rva") or 0)
            for target in domain.external_loader_targets
        )
        guest_external_catalog_values.extend(
            loader_target_indexes[canonical_sha256_v3(target)]
            for target in domain.external_loader_targets
        )
        guest_external_iat_values.extend(external_iats)
        guest_external_catalog_values.extend(
            INTERFACE_METHOD_TARGET_TAG
            | interface_target_indexes[str(target["method_contract_sha256"])]
            for target in domain.external_interface_targets
        )
        guest_external_iat_values.extend(
            0 for _target in domain.external_interface_targets
        )
        guest_external_domain_offsets[domain.domain_sha256] = (
            external_offset,
            len(external_iats) + len(domain.external_interface_targets),
        )
    guest_site_rows: list[str] = []
    for site in plan.guest_dispatch_sites:
        offset, count = guest_domain_offsets[site.domain_sha256]
        external_offset, external_count = guest_external_domain_offsets[
            site.domain_sha256
        ]
        guest_site_rows.append(
            "  {{ {kind}U, 0x{source:08x}U, 0x{instruction:08x}U, "
            "{event}U, {offset}U, {count}U, "
            "{external_offset}U, {external_count}U }},".format(
                kind=site.kind_code,
                source=site.source_rva,
                instruction=site.instruction_rva or 0,
                event=site.event_index or 0,
                offset=offset,
                count=count,
                external_offset=external_offset,
                external_count=external_count,
            )
        )
    guest_target_rows = "\n".join(
        f"  0x{target:08x}U," for target in guest_target_values
    ) or "  0U,"
    guest_external_iat_rows = "\n".join(
        f"  0x{iat_rva:08x}U," for iat_rva in guest_external_iat_values
    ) or "  0U,"
    guest_external_catalog_rows = "\n".join(
        f"  {index}U," for index in guest_external_catalog_values
    ) or "  0U,"
    guest_site_table = "\n".join(guest_site_rows) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    )
    loader_modules = sorted({
        str(target["identity"]["dll"]).lower() for target in loader_targets
    })
    loader_module_index = {
        dll: index for index, dll in enumerate(loader_modules)
    }
    loader_module_rows = "\n".join(
        f"  {{ {json.dumps(dll, ensure_ascii=True)} }},"
        for dll in loader_modules
    ) or '  { "" },'
    loader_target_rows = "\n".join(
        "  {{ {module}U, 0x{iat:08x}U, {ordinal}U, {has_ordinal}U, {symbol} }},".format(
            module=loader_module_index[dll],
            iat=iat_rva,
            ordinal=ordinal or 0,
            has_ordinal=1 if ordinal is not None else 0,
            symbol=(
                json.dumps(symbol, ensure_ascii=True)
                if symbol is not None else "(const char *)0"
            ),
        )
        for target in loader_targets
        for identity in (target["identity"],)
        for dll, symbol, ordinal, iat_rva in ((
            str(identity["dll"]).lower(), identity.get("symbol"),
            identity.get("ordinal"), int(target.get("iat_rva") or 0),
        ),)
    ) or "  { 0U, 0U, 0U, 0U, (const char *)0 },"
    interface_class_rows = "\n".join(
        "  {{ {index}U, {vtable_bytes}U, {profile_id}, {profile_sha256}, {interface_id} }},".format(
            index=index,
            vtable_bytes=max(
                int(target["method"]["external_protocol"]["slot"]) + 1
                for target in interface_targets
                if str(target["profile_sha256"]) == profile_sha256
                and str(target["interface_id"]) == interface_id
            ) * 4,
            profile_id=json.dumps(profile_id, ensure_ascii=True),
            profile_sha256=json.dumps(profile_sha256, ensure_ascii=True),
            interface_id=json.dumps(interface_id, ensure_ascii=True),
        )
        for index, (profile_sha256, interface_id, profile_id) in enumerate(
            interface_classes, 1
        )
    ) or '  { 0U, 0U, "", "", "" },'
    lifecycle_codes = {"preserve": 0, "may_release": 1, "release": 2}
    interface_method_rows = "\n".join(
        "  {{ {class_index}U, {slot}U, {receiver}U, {lifecycle}U, "
        "{method_sha256} }},".format(
            class_index=interface_class_indexes[(
                str(target["profile_sha256"]), str(target["interface_id"])
            )],
            slot=int(target["method"]["external_protocol"]["slot"]),
            receiver=int(target["method"]["receiver_resource"]["argument_index"]),
            lifecycle=lifecycle_codes[
                str(target["method"]["receiver_resource"]["lifecycle_effect"])
            ],
            method_sha256=json.dumps(
                target["method_contract_sha256"], ensure_ascii=True
            ),
        )
        for target in interface_targets
    ) or '  { 0U, 0U, 0U, 0U, "" },'
    nonlocal_transition_rows = "\n".join(
        "  {{ 0x{source:08x}U, 0x{target:08x}U, 0x{entry:08x}U }},".format(
            source=transition.source_rva,
            target=transition.target_rva,
            entry=transition.target_function_entry_rva,
        )
        for transition in sorted(
            plan.nonlocal_transitions,
            key=lambda row: (
                row.source_rva,
                row.target_rva,
                row.target_function_entry_rva,
                row.identity,
            ),
        )
    ) or "  { 0U, 0U, 0U },"
    implementation_rows = "\n".join(
        "  {{ 0x{rva:08x}U, {class_code}U, {entry_rva}, {replacement}, {cluster} }},".format(
            rva=dispatch.rva,
            class_code=dispatch.class_code,
            entry_rva=(
                "0U"
                if dispatch.component_entry_rva is None
                else f"0x{dispatch.component_entry_rva:08x}U"
            ),
            replacement=(
                "0"
                if dispatch.replacement_id is None
                else json.dumps(dispatch.replacement_id, ensure_ascii=True)
            ),
            cluster=(
                "0"
                if dispatch.cluster_id is None
                else json.dumps(dispatch.cluster_id, ensure_ascii=True)
            ),
        )
        for dispatch in plan.implementation_dispatches
    )
    portable_dispatch_count = sum(
        dispatch.implementation_class == "selected_portable_component"
        for dispatch in plan.implementation_dispatches
    )
    recovered_data_rows = "\n".join(
        f"  {{ 0x{start:08x}U, 0x{end:08x}U }},"
        for start, end in plan.recovered_executable_data_ranges
    ) or "  { 0U, 0U },"
    undefined_rows = "\n".join(
        f"  {{ 0x{policy.slot:08x}U, {policy.policy_code}U, "
        f"{policy.input_location_code}U }},"
        for policy in plan.undefined_policies
    ) or "  { 0U, 2U, 0U },"
    object_authority_rows = "\n".join(
        "  {{ {identity}, UINT64_C({domain}), UINT64_C({object_id}), "
        "UINT64_C({generation}), {extent}U, {permissions}U, "
        "{locator}U, {offset}U, 0x{subject_rva:08x}U, {interior}U }},".format(
            identity=json.dumps(rule.identity, ensure_ascii=True),
            domain=rule.domain,
            object_id=rule.object_id,
            generation=rule.generation,
            extent=rule.extent,
            permissions=rule.permissions,
            locator=rule.locator_code,
            offset=rule.locator_offset,
            subject_rva=rule.locator_subject_rva,
            interior=1 if rule.interior_pointers else 0,
        )
        for rule in plan.object_authority_rules
    ) or "  { 0, UINT64_C(0), UINT64_C(0), UINT64_C(0), 0U, 0U, 0U, 0U, 0U, 0U },"
    register_codes = {
        name: index
        for index, name in enumerate(
            ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
    }
    callable_resolver_table = "  { 0U, 0U, 0U, 0U },"
    callable_route_table = "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    callable_argument_table = "  { 0U, 0U, 0U },"
    callable_footprint_table = "  { 0U, 0U, 0U, 0U, 0U },"
    callable_binding_rows = "  0U,"
    callable_binding_count = 0
    action_codes = {
        "validate_call": 0,
        "add_result_range": 1,
        "release_argument_range": 2,
        "add_result_pointee_ranges": 3,
        "add_argument_pointee_ranges": 4,
        "add_argument_interface_ranges": 5,
    }
    size_codes = {
        None: 0,
        "fixed": 1,
        "argument": 2,
        "product": 3,
        "bounded_zero_run": 4,
    }
    dynamic_object_selectors = {
        rule.locator_subject_rva: index + 1
        for index, rule in enumerate(plan.object_authority_rules)
        if (
            rule.locator_kind in {"external_allocation", "resource"}
            and rule.locator_subject_rva != 0
        )
    }
    authorized_external_site_rows = "\n".join(
        f"  0x{rva:08x}U," for rva in plan.authorized_external_site_rvas
    ) or "  0U,"
    external_range_rows = "\n".join(
        "  {{ 0x{rva:08x}U, 0x{target_iat_rva:08x}U, {target_catalog_index}U, "
        "{interface_class_index}U, {action}U, {argument_base_offset}U, "
        "{argument_count}U, {register}U, {argument}U, "
        "{size_kind}U, {size_value}U, {size_argument}U, "
        "{size_right_argument}U, {minimum_size}U, {nullable}U, "
        "{termination_unit_bytes}U, {termination_zero_units}U, "
        "{termination_max_units}U, "
        "{pointee_offset}U, {max_elements}U, {element_unit_bytes}U, "
        "{element_max_units}U, {object_rule_selector}U }},".format(
            rva=rule.instruction_rva,
            target_iat_rva=rule.target_iat_rva or 0,
            target_catalog_index=rule.target_catalog_index or 0,
            interface_class_index=rule.interface_class_index or 0,
            action=action_codes[rule.action],
            argument_base_offset=rule.argument_base_offset,
            argument_count=rule.argument_count,
            register=register_codes.get(rule.register or "", 0),
            argument=rule.argument or 0,
            size_kind=size_codes[rule.size_kind],
            size_value=rule.size_value,
            size_argument=rule.size_argument or 0,
            size_right_argument=rule.size_right_argument or 0,
            minimum_size=rule.minimum_size,
            nullable=1 if rule.nullable else 0,
            termination_unit_bytes=rule.termination_unit_bytes,
            termination_zero_units=rule.termination_zero_units,
            termination_max_units=rule.termination_max_units,
            pointee_offset=rule.pointee_offset,
            max_elements=rule.max_elements,
            element_unit_bytes=rule.element_unit_bytes,
            element_max_units=rule.element_max_units,
            object_rule_selector=dynamic_object_selectors.get(index + 1, 0),
        )
        for index, rule in enumerate(plan.external_range_rules)
    ) or (
        "  { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, "
        "0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U },"
    )
    x87_declaration = (
        r'''extern spx_call_status spx_native_execute_typed_x87_operation(
    spx_runtime *runtime, const spx_typed_x87_operation *program,
    const spx_machine_state *input, spx_machine_state *output);
'''
        if plan.has_typed_x87_handler
        else ""
    )
    control_bytes = int(plan.ingress_tls_layout["runtime_control_bytes"])
    runtime_offset = int(plan.ingress_tls_layout["runtime_offset"])
    tls_regions = plan.ingress_tls_layout["runtime_regions"]
    tls_total_bytes = runtime_offset + max(
        int(region["offset"]) + int(region["extent"])
        for region in tls_regions.values()
    )
    context_offset = int(
        plan.ingress_tls_layout["runtime_regions"]["runtime_context"]["offset"]
    )
    context_storage = f'''extern void *spx_native_runtime_context_current(void);
#define spx_native_context_value \
  (*(spx_native_context *)spx_native_runtime_context_current())
_Static_assert(sizeof(spx_native_context) <= {control_bytes - context_offset}U,
    "native runtime context exceeds its checked PE TLS region");'''
    diagnostic_storage = r'''#define spx_native_diagnostic_reason \
  (*spx_native_runtime_diagnostic_slot(0U))
#define spx_native_diagnostic_value \
  (*spx_native_runtime_diagnostic_slot(1U))
#define spx_native_diagnostic_aux \
  (*spx_native_runtime_diagnostic_slot(2U))
#define spx_native_diagnostic_detail \
  (*spx_native_runtime_diagnostic_slot(3U))'''
    diagnostic_declarations = ""
    return (f'''#include "shared-module-runtime.h"
{ingress_include}

#include <stdint.h>

#define SPX_NATIVE_IMAGE_SCN_MEM_EXECUTE 0x20000000U
#define SPX_NATIVE_MAX_PE_SECTIONS 96U
#define SPX_NATIVE_MAX_EXTERNAL_RANGES 8192U
#define SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS 64U
#define SPX_NATIVE_MAX_INTERFACE_INSTANCES 2048U

extern const unsigned char __ImageBase[];
{diagnostic_declarations}
{diagnostic_storage}
extern spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output);
extern const spx_region_override *spx_region_override_lookup(
    uint32_t entry_rva) __attribute__((weak));
extern const spx_region_override spx_region_overrides[]
    __attribute__((weak));
extern const uint32_t spx_region_override_count __attribute__((weak));
extern const uint32_t spx_behavioral_transfer_count __attribute__((weak));
{x87_declaration}

_Static_assert(sizeof(uintptr_t) == 4U, "native runtime requires i686 pointers");

volatile spx_native_terminal_kind spx_native_terminal_status =
    SPX_NATIVE_TERMINAL_UNIMPLEMENTED;
volatile spx_call_status spx_native_terminal_call_status =
    SPX_CALL_UNIMPLEMENTED;
spx_machine_state spx_native_terminal_state;

static const uint32_t spx_native_transfer_rvas[] = {{
{transfer_rows}
}};
static const uint32_t spx_native_transfer_count = {len(plan.transfer_rvas)}U;

typedef struct spx_native_guest_dispatch_site {{
  uint32_t kind, source_rva, instruction_rva, event_index;
  uint32_t target_offset, target_count;
  uint32_t external_target_offset, external_target_count;
}} spx_native_guest_dispatch_site;
static const uint32_t spx_native_guest_dispatch_targets[] = {{
{guest_target_rows}
}};
static const uint32_t spx_native_guest_dispatch_target_count = {len(guest_target_values)}U;
static const uint32_t spx_native_guest_dispatch_external_iats[] = {{
{guest_external_iat_rows}
}};
static const uint32_t spx_native_guest_dispatch_external_iat_count = {len(guest_external_iat_values)}U;
static const uint32_t spx_native_guest_dispatch_external_catalog_indexes[] = {{
{guest_external_catalog_rows}
}};
static const uint32_t spx_native_guest_dispatch_external_catalog_index_count = {len(guest_external_catalog_values)}U;
static const spx_native_guest_dispatch_site spx_native_guest_dispatch_sites[] = {{
{guest_site_table}
}};
static const uint32_t spx_native_guest_dispatch_site_count = {len(plan.guest_dispatch_sites)}U;

typedef struct spx_native_loader_module {{
  const char *dll;
}} spx_native_loader_module;
typedef struct spx_native_loader_target {{
  uint32_t module_index, iat_rva, ordinal, has_ordinal;
  const char *symbol;
}} spx_native_loader_target;
static const spx_native_loader_module spx_native_loader_modules[] = {{
{loader_module_rows}
}};
static const uint32_t spx_native_loader_module_count = {len(loader_modules)}U;
static const spx_native_loader_target spx_native_loader_targets[] = {{
{loader_target_rows}
}};
static const uint32_t spx_native_loader_target_count = {len(loader_targets)}U;
/* Slots are indexed by immutable catalog identity, so one atomic word publishes
 * each binding without a lock, allocation, paired-field race, or wait. */
static volatile uint32_t spx_native_loader_module_handles[{max(1, len(loader_modules))}] = {{0U}};
static volatile uint32_t spx_native_loader_target_words[{max(1, len(loader_targets))}] = {{0U}};

#define SPX_NATIVE_INTERFACE_TARGET_TAG 0x80000000U
typedef struct spx_native_interface_class {{
  uint32_t class_index, vtable_bytes;
  const char *profile_id, *profile_sha256, *interface_id;
}} spx_native_interface_class;
static const spx_native_interface_class spx_native_interface_classes[] = {{
{interface_class_rows}
}};
static const uint32_t spx_native_interface_class_count = {len(interface_classes)}U;
typedef struct spx_native_interface_method {{
  uint32_t class_index, slot, receiver_argument, lifecycle_effect;
  const char *method_sha256;
}} spx_native_interface_method;
static const spx_native_interface_method spx_native_interface_methods[] = {{
{interface_method_rows}
}};
static const uint32_t spx_native_interface_method_count = {len(interface_targets)}U;

typedef struct spx_native_implementation_dispatch {{
  uint32_t rva, implementation_class;
  uint32_t component_entry_rva;
  const char *replacement_id, *cluster_id;
}} spx_native_implementation_dispatch;
static const spx_native_implementation_dispatch
spx_native_implementation_dispatches[] = {{
{implementation_rows}
}};
static const uint32_t spx_native_implementation_dispatch_count =
    {len(plan.implementation_dispatches)}U;
static const uint32_t spx_native_portable_dispatch_count =
    {portable_dispatch_count}U;

typedef struct spx_native_noncode_range {{
  uint32_t rva_start, rva_end;
}} spx_native_noncode_range;
static const spx_native_noncode_range spx_native_noncode_ranges[] = {{
{recovered_data_rows}
}};
static const uint32_t spx_native_noncode_range_count = {len(plan.recovered_executable_data_ranges)}U;

typedef struct spx_native_undefined_policy {{
  uint32_t slot, policy, input_location;
}} spx_native_undefined_policy;
static const spx_native_undefined_policy spx_native_undefined_policies[] = {{
{undefined_rows}
}};
static const uint32_t spx_native_undefined_policy_count = {len(plan.undefined_policies)}U;

typedef struct spx_native_object_authority_rule {{
  const char *identity;
  uint64_t domain, object_id, generation;
  uint32_t extent, permissions, locator_kind, locator_offset;
  uint32_t locator_subject_rva, interior_pointers;
}} spx_native_object_authority_rule;
static const spx_native_object_authority_rule
spx_native_object_authority_rules[] = {{
{object_authority_rows}
}};
static const uint32_t spx_native_object_authority_rule_count =
    {len(plan.object_authority_rules)}U;
static const uint32_t spx_native_tls_total_bytes = {tls_total_bytes}U;

static const uint32_t spx_native_authorized_external_sites[] = {{
{authorized_external_site_rows}
}};
static const uint32_t spx_native_authorized_external_site_count = {len(plan.authorized_external_site_rvas)}U;

typedef struct spx_native_external_range_rule {{
  uint32_t instruction_rva, target_iat_rva, target_catalog_index;
  uint32_t interface_class_index, action;
  uint32_t argument_base_offset, argument_count;
  uint32_t register_index, argument;
  uint32_t size_kind, size_value, size_argument, size_right_argument;
  uint32_t minimum_size, nullable;
  uint32_t termination_unit_bytes, termination_zero_units, termination_max_units;
  uint32_t pointee_offset, max_elements, element_unit_bytes, element_max_units;
  uint32_t object_rule_selector;
}} spx_native_external_range_rule;
static const spx_native_external_range_rule spx_native_external_range_rules[] = {{
{external_range_rows}
}};
static const uint32_t spx_native_external_range_rule_count = {len(plan.external_range_rules)}U;

typedef struct spx_native_callable_resolver {{
  uint32_t instruction_rva, capability_id, result_register, nullable;
}} spx_native_callable_resolver;
static const spx_native_callable_resolver spx_native_callable_resolvers[] = {{
{callable_resolver_table}
}};
static const uint32_t spx_native_callable_resolver_count = 0U;
static const uint32_t spx_native_callable_binding_capabilities[] = {{
{callable_binding_rows}
}};
static const uint32_t spx_native_callable_binding_count = {callable_binding_count}U;

typedef struct spx_native_callable_argument {{
  uint32_t kind, register_index, value;
}} spx_native_callable_argument;
static const spx_native_callable_argument spx_native_callable_arguments[] = {{
{callable_argument_table}
}};
static const uint32_t spx_native_callable_argument_count = 0U;

typedef struct spx_native_callable_footprint {{
  uint32_t access, base_argument, offset, size, nullable;
}} spx_native_callable_footprint;
static const spx_native_callable_footprint spx_native_callable_footprints[] = {{
{callable_footprint_table}
}};
static const uint32_t spx_native_callable_footprint_count = 0U;

typedef struct spx_native_callable_route {{
  uint32_t source_rva, instruction_rva, capability_id, abi_contract_id;
  uint32_t stack_result_delta, preserved_register_mask;
  uint32_t argument_offset, argument_count;
  uint32_t footprint_offset, footprint_count;
}} spx_native_callable_route;
static const spx_native_callable_route spx_native_callable_routes[] = {{
{callable_route_table}
}};
static const uint32_t spx_native_callable_route_count = 0U;

typedef struct spx_native_nonlocal_transition {{
  uint32_t source_rva, target_rva, target_function_entry_rva;
}} spx_native_nonlocal_transition;
static const spx_native_nonlocal_transition spx_native_nonlocal_transitions[] = {{
{nonlocal_transition_rows}
}};
static const uint32_t spx_native_nonlocal_transition_count = {len(plan.nonlocal_transitions)}U;

typedef struct spx_native_callable_binding {{
  uint32_t capability_id, target_word, bound;
}} spx_native_callable_binding;

typedef struct spx_native_external_range {{
  uint32_t start, size, producer_rva, producer_action, generation;
  uint32_t external_range_rule_selector;
  uint64_t object_id;
}} spx_native_external_range;

typedef struct spx_native_interface_instance {{
  uint32_t class_index, object, vtable, generation;
}} spx_native_interface_instance;

typedef struct spx_native_external_lifecycle_event {{
  uint32_t sequence, operation, status, instruction_rva;
  uint32_t start, size, producer_rva, producer_action, generation;
}} spx_native_external_lifecycle_event;

#define SPX_NATIVE_EXCEPTION_RECORD_BYTES 80U
#define SPX_NATIVE_X86_CONTEXT_BYTES 716U
#define SPX_NATIVE_EXCEPTION_RECORD_LIMIT 16U

typedef struct spx_native_context {{
  uint32_t image_base;
  uint32_t image_size;
  uint32_t headers_size;
  uint32_t section_table;
  uint32_t section_count;
  uint32_t stack_low;
  uint32_t stack_high;
  uint32_t initialized;
  uint32_t process_world_initialized;
  uint32_t owner_fs_base;
  uint32_t guest_seh_head;
  uint32_t nested_depth;
  uint32_t undefined_fault;
  uint32_t undefined_fault_slot;
  uint32_t undefined_fault_rva;
  uint32_t last_undefined_fault;
  uint32_t nonlocal_active;
  uint32_t nonlocal_source_rva;
  uint32_t nonlocal_target_rva;
  uint32_t nonlocal_value;
  uint32_t nonlocal_target_function_entry_rva;
  uint32_t unwind_service_active;
  spx_native_checked_unwind_snapshot unwind_snapshot;
  uint32_t unwind_exception_record_count;
  uint32_t unwind_exception_records[
      SPX_NATIVE_EXCEPTION_RECORD_LIMIT][SPX_NATIVE_EXCEPTION_RECORD_BYTES / 4U];
  uint32_t unwind_handler_bound;
  uint32_t unwind_handler_record_base;
  uint32_t unwind_handler_record_count;
  uint32_t unwind_handler_context;
  uint32_t unwind_handler_frame;
  spx_native_external_range external_ranges[SPX_NATIVE_MAX_EXTERNAL_RANGES];
  uint32_t external_range_count;
  spx_native_interface_instance
      interface_instances[SPX_NATIVE_MAX_INTERFACE_INSTANCES];
  uint32_t interface_instance_count;
  spx_native_external_lifecycle_event external_lifecycle_events[
      SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS];
  uint32_t external_lifecycle_count;
  uint32_t external_lifecycle_next;
  uint32_t external_lifecycle_sequence;
  uint32_t external_object_sequence;
  uint32_t invocation_generation;
  uint32_t exception_service_active;
  uint32_t exception_service_root;
  uint32_t exception_service_record_count;
  uint32_t exception_service_records[SPX_NATIVE_EXCEPTION_RECORD_LIMIT];
  uint32_t exception_service_context;
  uint32_t exception_callback_bound;
  uint32_t exception_callback_root;
  spx_native_callable_binding callable_bindings[{max(1, callable_binding_count)}U];
}} spx_native_context;

#define SPX_NATIVE_THREAD_ENVIRONMENT_BYTES 0x1000U

{context_storage}

static uint16_t spx_native_u16(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}}

static uint32_t spx_native_u32(uint32_t address) {{
  const volatile uint8_t *p = (const volatile uint8_t *)(uintptr_t)address;
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}}

static uint32_t spx_native_range_end(
    uint32_t start, uint32_t width, uint32_t *end) {{
  if (width == 0U || start > 0xffffffffU - width) return 0U;
  *end = start + width;
  return 1U;
}}

static uint32_t spx_native_inside(
    uint32_t start, uint32_t end, uint32_t region_start, uint32_t region_size) {{
  uint32_t region_end;
  if (region_size == 0U ||
      !spx_native_range_end(region_start, region_size, &region_end))
    return 0U;
  return start >= region_start && end <= region_end;
}}

static uint32_t spx_native_inside_external_range(
    const spx_native_context *context, uint32_t start, uint32_t end) {{
  uint32_t i;
  for (i = 0U; i < context->external_range_count; ++i)
    if (spx_native_inside(
            start, end, context->external_ranges[i].start,
            context->external_ranges[i].size))
      return 1U;
  return 0U;
}}

static void spx_native_diagnose_external_range(
    const spx_native_context *context, uint32_t address) {{
  uint32_t i, nearest_start = 0U, nearest_end = 0U, has_preceding = 0U;
  if (context == 0) return;
  for (i = 0U; i < context->external_range_count; ++i) {{
    uint32_t start = context->external_ranges[i].start;
    uint32_t end;
    if (!spx_native_range_end(
            start, context->external_ranges[i].size, &end))
      continue;
    if ((start <= address &&
         (has_preceding == 0U || start > nearest_start)) ||
        (start > address && has_preceding == 0U &&
         (nearest_start == 0U || start < nearest_start))) {{
      nearest_start = start;
      nearest_end = end;
      has_preceding = start <= address;
    }}
  }}
  spx_native_diagnostic_aux = nearest_start;
  spx_native_diagnostic_detail = nearest_end;
}}


static uint32_t spx_native_inside_thread_environment(
    const spx_native_context *context, uint32_t start, uint32_t end) {{
  uint32_t teb_end;
  return context->owner_fs_base != 0U &&
      spx_native_range_end(
          context->owner_fs_base,
          SPX_NATIVE_THREAD_ENVIRONMENT_BYTES,
          &teb_end) &&
      start >= context->owner_fs_base && end <= teb_end;
}}

static uint32_t spx_native_ranges_overlap(
    uint32_t left_start, uint32_t left_end,
    uint32_t right_start, uint32_t right_size) {{
  uint32_t right_end;
  return spx_native_range_end(right_start, right_size, &right_end) &&
      left_start < right_end && right_start < left_end;
}}

/* Exact read-only objects materialized for one checked x86 unwind-handler
 * notification.  They are never a grant over the surrounding private stack. */
static uint32_t spx_native_unwind_service_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access) {{
  const spx_native_context *context = &spx_native_context_value;
  uint32_t end, record_bytes;
  if (context->unwind_handler_bound == 0U ||
      !spx_native_range_end(address, width, &end) ||
      context->unwind_handler_record_count == 0U ||
      context->unwind_handler_record_count >
          SPX_NATIVE_EXCEPTION_RECORD_LIMIT)
    return 0U;
  record_bytes = context->unwind_handler_record_count *
      SPX_NATIVE_EXCEPTION_RECORD_BYTES;
#define SPX_CHECK_UNWIND_OBJECT(base_value, size_value) \
  do {{ \
    if (spx_native_ranges_overlap( \
            address, end, (base_value), (size_value))) \
      return write_access == 0U && spx_native_inside( \
          address, end, (base_value), (size_value)) ? 1U : 2U; \
  }} while (0)
  SPX_CHECK_UNWIND_OBJECT(
      context->unwind_handler_record_base, record_bytes);
  SPX_CHECK_UNWIND_OBJECT(
      context->unwind_handler_context, SPX_NATIVE_X86_CONTEXT_BYTES);
  SPX_CHECK_UNWIND_OBJECT(context->unwind_handler_frame, 20U);
#undef SPX_CHECK_UNWIND_OBJECT
  return 0U;
}}

/* Return 0 when the active checked exception-service transaction has no
 * opinion, 1 when it grants the exact access, and 2 when an overlapping access
 * violates the typed view.  In particular, neither this helper nor its caller
 * grants general access to the reviewed private native stack. */
static uint32_t spx_native_exception_service_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access) {{
  const spx_native_context *context = &spx_native_context_value;
  uint32_t end, index;
  if (context->exception_service_active == 0U ||
      !spx_native_range_end(address, width, &end))
    return 0U;
#define SPX_CHECK_EXCEPTION_ROOT(root_value) \
  do {{ \
    if (spx_native_ranges_overlap(address, end, (root_value), 8U)) \
      return write_access == 0U && \
          spx_native_inside(address, end, (root_value), 8U) ? 1U : 2U; \
  }} while (0)
  SPX_CHECK_EXCEPTION_ROOT(context->exception_service_root);
  if (context->exception_callback_bound != 0U)
    SPX_CHECK_EXCEPTION_ROOT(context->exception_callback_root);
#undef SPX_CHECK_EXCEPTION_ROOT
  for (index = 0U; index < context->exception_service_record_count; ++index) {{
    const uint32_t record = context->exception_service_records[index];
    if (spx_native_ranges_overlap(
            address, end, record, SPX_NATIVE_EXCEPTION_RECORD_BYTES))
      return spx_native_inside(
          address, end, record, SPX_NATIVE_EXCEPTION_RECORD_BYTES) ? 1U : 2U;
  }}
  if (spx_native_ranges_overlap(
          address, end, context->exception_service_context,
          SPX_NATIVE_X86_CONTEXT_BYTES))
    return spx_native_inside(
        address, end, context->exception_service_context,
        SPX_NATIVE_X86_CONTEXT_BYTES) ? 1U : 2U;
  return 0U;
}}

static uint32_t spx_native_validate_image(spx_native_context *context) {{
  uint32_t base = (uint32_t)(uintptr_t)&__ImageBase;
  uint32_t pe_offset, pe, optional, section_table, section_bytes, section_end;
  uint32_t image_size, headers_size;
  uint16_t section_count, optional_size;
  if (base == 0U || base > 0xffffffffU - 0x40U ||
      spx_native_u16(base) != 0x5a4dU)
    return 0U;
  pe_offset = spx_native_u32(base + 0x3cU);
  if (pe_offset < 0x40U || pe_offset > 0x00100000U ||
      base > 0xffffffffU - pe_offset ||
      base + pe_offset > 0xffffffffU - 24U)
    return 0U;
  pe = base + pe_offset;
  if (spx_native_u32(pe) != 0x00004550U) return 0U;
  section_count = spx_native_u16(pe + 6U);
  optional_size = spx_native_u16(pe + 20U);
  if (section_count == 0U || section_count > SPX_NATIVE_MAX_PE_SECTIONS ||
      optional_size < 64U)
    return 0U;
  optional = pe + 24U;
  if (optional > 0xffffffffU - 64U) return 0U;
  if (spx_native_u16(optional) != 0x010bU) return 0U;
  image_size = spx_native_u32(optional + 56U);
  headers_size = spx_native_u32(optional + 60U);
  if (image_size == 0U || headers_size == 0U || headers_size > image_size ||
      base > 0xffffffffU - image_size)
    return 0U;
  if (optional > 0xffffffffU - optional_size) return 0U;
  section_table = optional + optional_size;
  section_bytes = (uint32_t)section_count * 40U;
  if (!spx_native_range_end(section_table, section_bytes, &section_end) ||
      section_end > base + headers_size)
    return 0U;
  context->image_base = base;
  context->image_size = image_size;
  context->headers_size = headers_size;
  context->section_table = section_table;
  context->section_count = section_count;
  return 1U;
}}

static uint32_t spx_native_validate_stack(
    spx_native_context *context, const spx_machine_state *captured) {{
  uint32_t stack_high, stack_low;
  if (captured->fs_base == 0U ||
      !spx_native_host_stack_bounds_current(&stack_high, &stack_low))
    return 0U;
  if (stack_low >= stack_high ||
      ((captured->esp < stack_low || captured->esp > stack_high) &&
       !spx_native_exception_stack_pointer_authorized(captured->esp)))
    return 0U;
  context->stack_low = stack_low;
  context->stack_high = stack_high;
  return 1U;
}}

static uint32_t spx_native_string_equal(
    const char *left, const char *right) {{
  if (left == 0 || right == 0) return left == right;
  while (*left != '\\0' && *left == *right) {{ ++left; ++right; }}
  return *left == *right;
}}

static uint32_t spx_native_override_table_valid(void) {{
  uint32_t i, matched = 0U;
  if ((uintptr_t)&spx_region_override_count == 0U ||
      (uintptr_t)spx_region_overrides == 0U)
    return spx_native_portable_dispatch_count == 0U;
  if (spx_region_override_count != spx_native_portable_dispatch_count)
    return 0U;
  for (i = 0U; i < spx_region_override_count; ++i) {{
    const spx_region_override *observed = &spx_region_overrides[i];
    uint32_t j, found = 0U;
    for (j = 0U; j < spx_native_implementation_dispatch_count; ++j) {{
      const spx_native_implementation_dispatch *expected =
          &spx_native_implementation_dispatches[j];
      if (expected->implementation_class != 1U || expected->rva != observed->entry_rva)
        continue;
      if (found != 0U || observed->function == 0 ||
          observed->fallback_on_unimplemented != 0U ||
          !spx_native_string_equal(
              observed->replacement_id, expected->replacement_id) ||
          !spx_native_string_equal(
              observed->cluster_id, expected->cluster_id))
        return 0U;
      found = 1U;
    }}
    if (found == 0U) return 0U;
    ++matched;
  }}
  return matched == spx_native_portable_dispatch_count;
}}

static uint32_t spx_native_transfer_table_valid(void) {{
  uint32_t i;
  if ((uintptr_t)&spx_behavioral_transfer_count == 0U ||
      spx_behavioral_transfer_count != spx_native_transfer_count ||
      spx_native_transfer_count == 0U ||
      spx_native_implementation_dispatch_count !=
          spx_native_transfer_count ||
      !spx_native_override_table_valid())
    return 0U;
  for (i = 0U; i < spx_native_transfer_count; ++i) {{
    uint32_t rva = spx_native_transfer_rvas[i];
    const spx_native_implementation_dispatch *expected =
        &spx_native_implementation_dispatches[i];
    const spx_region_override *override;
    if ((i != 0U && spx_native_transfer_rvas[i - 1U] >= rva) ||
        expected->rva != rva ||
        rva >= spx_native_context_value.image_size ||
        !spx_behavioral_has_unit(rva))
      return 0U;
    override = (
        spx_region_override_lookup == 0
        ? (const spx_region_override *)0
        : spx_region_override_lookup(rva));
    if (expected->implementation_class == 0U) {{
      if (override != 0 || expected->replacement_id != 0 ||
          expected->cluster_id != 0)
        return 0U;
    }} else if (expected->implementation_class == 1U) {{
      if (override == 0 || override->entry_rva != rva ||
          override->function == 0 || override->fallback_on_unimplemented != 0U ||
          !spx_native_string_equal(
              override->replacement_id, expected->replacement_id) ||
          !spx_native_string_equal(
              override->cluster_id, expected->cluster_id))
        return 0U;
    }} else if (expected->implementation_class == 2U) {{
      if (override != 0 || expected->replacement_id == 0 ||
          expected->cluster_id == 0 || expected->component_entry_rva == 0U ||
          expected->component_entry_rva == rva)
        return 0U;
    }} else {{
      return 0U;
    }}
  }}
'''
        + _native_runtime_source_core(plan)
        + _native_runtime_source_entry(plan)
        + _portable_component_reference_runtime()
    )


def _native_runtime_bindings_source(plan: SharedModuleRuntimePlan) -> str:
    return f'''#include "shared-module-runtime.h"

const char spx_native_behavioral_c_manifest_sha256[65] =
    "{plan.semantic_backend_manifest_sha256}";
const char spx_module_runtime_plan_sha256[65] =
    "{plan.module_runtime_plan_sha256}";
const char spx_native_state_machine_sha256[65] =
    "{plan.state_machine_sha256}";
'''
