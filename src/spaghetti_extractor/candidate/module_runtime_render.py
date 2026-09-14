"""Generated freestanding C and assembly for a checked module-runtime plan."""

from __future__ import annotations

from collections.abc import Mapping
import json

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from .runtime_argument_domains import argument_domain_source
from .module_runtime_plan import (
    ModuleRuntimePlan,
    _FNSAVE_IMAGE_SIZE,
    _FRAME_OFFSETS,
    _MACHINE_STATE_SIZE,
    _STATE_OFFSETS,
    _X87_CHECKED_DECODER,
    _X87_CHECKED_EXECUTOR,
    _X87_FRAME_OFFSETS,
    _X87_REPLAY_INLINE_BODY_SIZE,
    _X87_REPLAY_INLINE_CAPTURE_OFFSET,
    _X87_REPLAY_INLINE_INSTRUCTION_OFFSET,
    _X87_REPLAY_INLINE_RETURN_OFFSET,
    _X87_VALUE_EMPTY_OFFSET,
    _X87_VALUE_SIZE,
    _X87_VALUE_TAG_OFFSET,
)
from .runtime_x87_render import (
    _capture_pushad_registers,
    _capture_split_flags,
    _render_typed_x87_instruction,
    _restore_pushes,
)
from .native_ingress_runtime_model import compact_callback_runtime_v1
from .runtime_model import (
    INTERFACE_METHOD_TARGET_TAG,
    interface_method_target_catalog,
    loader_target_catalog,
)


def _native_callback_lifetime_kind(value: object) -> str:
    if isinstance(value, Mapping):
        raw_kind = value.get("kind")
    else:
        raw_kind = value
    if not isinstance(raw_kind, str) or not raw_kind:
        raise ToolkitInputError("native callback capability lifetime is missing")
    kind = raw_kind.split(":", 1)[0]
    aliases = {
        "during_native_call": "during_call",
        "until_class_unregistered_or_process_exit": (
            "until_resource_event_or_process_exit"
        ),
    }
    kind = aliases.get(kind, kind)
    if kind not in {
        "during_call",
        "one_shot_or_process_exit",
        "until_replaced_or_process_exit",
        "until_resource_event_or_process_exit",
    }:
        raise ToolkitInputError(
            f"native callback capability lifetime {raw_kind!r} is unsupported"
        )
    return kind


def _wrapper_header() -> str:
    return """#ifndef SPX_MODULE_RUNTIME_H
#define SPX_MODULE_RUNTIME_H

#include <stddef.h>
#include "state-machine-runtime.h"

/* Intel 32-bit protected-mode FNSAVE/FRSTOR image.  The register array is
 * physical R0..R7 and tag_word is the complete architectural tag word. */
typedef struct __attribute__((packed, aligned(4))) spx_x87_fnsave_image {
  uint16_t control_word, reserved_02;
  uint16_t status_word, reserved_06;
  uint16_t tag_word, reserved_0a;
  uint32_t instruction_pointer;
  uint16_t code_selector, last_opcode;
  uint32_t data_pointer;
  uint16_t data_selector, reserved_1a;
  uint8_t physical_registers[8][10];
} spx_x87_fnsave_image;

typedef struct spx_native_bridge_frame {
  struct spx_native_bridge_frame *parent;
  const spx_machine_state *input;
  spx_machine_state *output;
  uint32_t private_esp;
  uint32_t call_target;
  spx_call_status status;
  uint32_t saved_continuation;
  uint32_t tail_jump;
  uint32_t argument_source;
  uint32_t argument_words;
  uint32_t cleanup_bytes;
  uint32_t logical_result_esp;
  uint32_t expected_capture_esp;
  spx_x87_fnsave_image input_x87;
  spx_x87_fnsave_image output_x87;
} spx_native_bridge_frame;

typedef struct spx_native_x87_frame {
  struct spx_native_x87_frame *parent;
  const spx_machine_state *input;
  spx_machine_state *output;
  uint32_t private_esp;
  spx_call_status status;
  spx_x87_fnsave_image input_x87;
  spx_x87_fnsave_image output_x87;
} spx_native_x87_frame;

extern volatile uint32_t spx_native_diagnostic_reason;
extern volatile uint32_t spx_native_diagnostic_value;
extern volatile uint32_t spx_native_diagnostic_aux;
extern volatile uint32_t spx_native_diagnostic_detail;
extern spx_runtime spx_native_runtime_instance;

spx_call_status spx_native_runtime_run_at_rva(
    uint32_t entry_rva, const spx_machine_state *input,
    spx_machine_state *output);
spx_call_status spx_native_runtime_capture_external_call(
    const spx_call_event *event, const spx_machine_state *input,
    spx_external_call_snapshot *snapshot);
spx_call_status spx_native_runtime_record_external_result(
    const spx_call_event *event,
    const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output);
uint32_t spx_native_loader_code_target_matches(
    uint32_t target_word, uint32_t iat_rva,
    uint32_t loader_target_index);
uint32_t spx_native_external_code_target_matches(
    uint32_t target_word, uint32_t iat_rva,
    uint32_t target_catalog_index);
spx_call_status spx_native_runtime_record_loader_service(
    uint32_t kind, uint32_t argument_base_offset,
    uint32_t argument_0, uint32_t argument_1, uint32_t nullable,
    const spx_external_call_snapshot *snapshot,
    const spx_machine_state *output);
#define SPX_NATIVE_EXCEPTION_OBJECT_SNAPSHOT_BYTES 2112U
spx_call_status spx_native_runtime_begin_exception_object(
    uint32_t exception_pointers, void *snapshot, uint32_t capacity,
    uint32_t *snapshot_size);
spx_call_status spx_native_runtime_finish_exception_object(
    uint32_t exception_pointers, void *snapshot, uint32_t snapshot_size,
    uint32_t commit);
spx_call_status spx_native_runtime_begin_checked_unwind(
    uint32_t source_rva, uint32_t target_frame,
    uint32_t target_instruction, uint32_t exception_record,
    uint32_t return_value, const spx_machine_state *input,
    spx_machine_state *output);
spx_call_status spx_native_runtime_bind_exception_filter_callback(
    uint32_t exception_pointers);
spx_call_status spx_native_runtime_unbind_exception_filter_callback(
    uint32_t exception_pointers);
uint32_t spx_native_runtime_exception_filter_callback_expected(void);
uint32_t spx_native_code_bridge_address(uint32_t target_rva);
uint32_t spx_native_publish_registered_code_result(
    uint32_t source_rva, uint32_t logical_value);
#endif
"""


def _wrapper_source(
    plan: ModuleRuntimePlan,
    native_ingress_plan: dict,
) -> str:
    compact_runtime = compact_callback_runtime_v1(native_ingress_plan or {})
    declarations = ["extern void spx_native_bridge(void);"]
    ingress_symbols: dict[int, str] = {}
    for row in (native_ingress_plan or {}).get("bridges", []):
        if not isinstance(row, dict):
            continue
        target_rva = int(row["target_rva"])
        symbol = str(row["symbol"])
        prior = ingress_symbols.setdefault(target_rva, symbol)
        if prior != symbol:
            raise ToolkitInputError(
                "native ingress target has multiple unequal bridge addresses"
            )
    ingress_declarations = [
        f"extern void {symbol}(void);"
        for symbol in sorted(set(ingress_symbols.values()))
    ]
    ingress_callback_symbols = {
        int(row["target_rva"]): str(row["bridge_symbol"])
        for row in (native_ingress_plan or {}).get("ingresses", [])
        if isinstance(row, dict) and row.get("role") == "callback"
    }
    ingress_capability_ids = sorted({
        str(row["capability_id"])
        for row in (native_ingress_plan or {}).get("ingresses", [])
        if isinstance(row, dict) and row.get("capability_id") is not None
    })
    ingress_capability_index = {
        identity: index for index, identity in enumerate(ingress_capability_ids)
    }
    compact_domains_by_id = {
        domain.identity: domain for domain in compact_runtime.domains
    }
    expected_compact_domains = {
        domain.domain_id: domain for domain in plan.compact_code_capability_domains
    }
    if set(expected_compact_domains) != set(compact_domains_by_id):
        raise ToolkitInputError(
            "module runtime and native ingress compact callback domains differ"
        )
    for identity, planned in expected_compact_domains.items():
        native = compact_domains_by_id[identity]
        if (
            planned.protocol_id != native.protocol_id
            or planned.target_rvas != tuple(
                target.target_rva for target in native.targets
            )
            or planned.trampoline_table_symbol
            != native.trampoline_table_symbol
            or planned.trampoline_stride_bytes
            != native.trampoline_stride_bytes
            or planned.flat_first != native.flat_first
        ):
            raise ToolkitInputError(
                "module runtime compact callback domain is stale"
            )
    callback_lifetimes = {
        (registration.instruction_rva, registration.logical_target_rva): (
            _native_callback_lifetime_kind(registration.lifetime)
        )
        for registration in plan.code_capability_registrations
    }
    missing_callback_ingresses = sorted({
        binding.code_target_rva for binding in plan.code_capability_bindings
        if binding.code_target_rva not in ingress_callback_symbols
    })
    if missing_callback_ingresses:
        raise ToolkitInputError(
            "native ingress plan lacks callback capabilities for "
            + ", ".join(f"0x{rva:08x}" for rva in missing_callback_ingresses)
        )
    compact_declarations = [
        f"extern const uint8_t {domain.trampoline_table_symbol}[];"
        for domain in compact_runtime.domains
    ]
    x87_declarations = [
        f"extern void spx_native_x87_bridge_{operation.id:04d}(void);"
        for operation in plan.x87_operations
    ]
    compact_site_publication_routes: dict[tuple[int, str], int] = {}
    compact_interface_publication_routes: dict[str, int] = {}
    for index, publication in enumerate(
        plan.compact_code_capability_publications
    ):
        if publication.authority_kind == "checked_external_site_contract":
            key = (publication.instruction_rva, publication.authority_sha256)
            if key in compact_site_publication_routes:
                raise ToolkitInputError(
                    "module runtime callback publication route is ambiguous"
                )
            compact_site_publication_routes[key] = index + 1
        elif publication.authority_kind == "interface_method_contract":
            if publication.authority_sha256 in compact_interface_publication_routes:
                raise ToolkitInputError(
                    "module runtime interface callback publication is ambiguous"
                )
            compact_interface_publication_routes[
                publication.authority_sha256
            ] = index + 1
        else:
            raise ToolkitInputError(
                "module runtime callback publication authority is unsupported"
            )
    table = []
    service_kinds: dict[
        tuple[str, int, int], tuple[int, tuple[int, int, int, int]]
    ] = {}
    for route in plan.external_service_routes:
        if not route.realized:
            raise ToolkitInputError(
                "cannot render an unrealized external-service route"
            )
        protocol = route.admitted_domain["protocol"]
        protocol_id = protocol.get("id")
        service_kind = {
            "win32-unhandled-exception-filter-v1": 1,
            "win32-rtl-unwind-v1": 2,
        }.get(protocol_id)
        if service_kind is None:
            raise ToolkitInputError(
                "module runtime external-service implementation is unsupported"
            )
        for service_site in route.admitted_domain["sites"]:
            key = (
                str(service_site["transfer_id"]),
                int(service_site["instruction_rva"]),
                int(service_site["call_id"]),
            )
            if key in service_kinds:
                raise ToolkitInputError(
                    "module runtime external-service site is ambiguous"
                )
            arguments = protocol.get("arguments")
            if not isinstance(arguments, Mapping):
                raise ToolkitInputError(
                    "module runtime external-service arguments are malformed"
                )
            if service_kind == 1:
                selectors = (
                    int(arguments["exception_pointers"]), 0, 0, 0,
                )
            else:
                selectors = tuple(int(arguments[name]) for name in (
                    "target_frame", "target_instruction",
                    "exception_record", "return_value",
                ))
            service_kinds[key] = (service_kind, selectors)
    _loader_targets, loader_target_indexes = loader_target_catalog(
        plan.guest_dispatch_domains
    )
    _interface_targets, interface_target_indexes = (
        interface_method_target_catalog(plan.guest_dispatch_domains)
    )
    for site in plan.external_sites:
        external_service_kind, external_service_arguments = service_kinds.get(
            (site.transfer_id, site.instruction_rva, site.event_index),
            (0, (0, 0, 0, 0)),
        )
        service = site.loader_service or {}
        service_kind = service.get("kind")
        if service_kind == "module_handle":
            loader_kind = 2 if service.get("wide_name") else 1
            loader_argument_0 = int(service["module_name_argument"])
            loader_argument_1 = 0
            loader_nullable = 1 if service["nullable_module_name"] else 0
        elif service_kind == "dynamic_export_resolution":
            loader_kind = 3
            loader_argument_0 = int(service["module_handle_argument"])
            loader_argument_1 = int(service["export_name_argument"])
            loader_nullable = 0
        elif service:
            raise ToolkitInputError("module runtime loader service is unsupported")
        else:
            loader_kind = loader_argument_0 = loader_argument_1 = loader_nullable = 0
        argument_base_offset = (
            site.checked_external_contract.argument_base_offset
            if site.checked_external_contract is not None else 0
        )
        arity_variadic = (
            site.checked_external_contract is not None
            and site.checked_external_contract.arity_kind == "variadic"
        )
        argument_words = (
            site.checked_external_contract.argument_words
            if site.checked_external_contract is not None else 0
        )
        abi_template = (
            site.checked_external_contract.abi_template
            if site.checked_external_contract is not None else None
        )
        if arity_variadic and abi_template != "pe32-cdecl-v1":
            raise ToolkitInputError(
                "variadic native callthrough requires the checked PE32 cdecl ABI"
            )
        cleanup_bytes = (
            argument_words * 4 if abi_template == "pe32-stdcall-v1" else 0
        )
        admitted_member_sha256 = (
            site.target_resolution_evidence.get("admitted_member_sha256")
            if site.target_resolution_evidence is not None else None
        )
        loader_target_index = (
            loader_target_indexes.get(str(admitted_member_sha256), 0)
            if admitted_member_sha256 is not None else 0
        )
        interface_target_index = (
            interface_target_indexes.get(str(admitted_member_sha256), 0)
            if admitted_member_sha256 is not None else 0
        )
        if loader_target_index != 0 and interface_target_index != 0:
            raise ToolkitInputError(
                "module runtime external target catalog is ambiguous"
            )
        target_catalog_index = (
            INTERFACE_METHOD_TARGET_TAG | interface_target_index
            if interface_target_index != 0 else loader_target_index
        )
        checked_sha256 = (
            canonical_sha256_v3(site.checked_external_contract.payload())
            if site.checked_external_contract is not None else None
        )
        compact_publication_index = (
            compact_interface_publication_routes.get(
                str(admitted_member_sha256), 0
            )
            if interface_target_index != 0
            else compact_site_publication_routes.get(
                (site.instruction_rva, str(checked_sha256)), 0
            )
        )
        table.append(
            f"  {{ 0x{site.instruction_rva:08x}U, "
            f"0x{(site.iat_rva or 0):08x}U, "
            f"{1 if site.site_kind != 'direct_import' else 0}U, "
            f"{1 if site.disposition == 'tail_jump' else 0}U, "
            f"{2 if site.callback_source_kind == 'argument_pointee' else 1 if site.callback_argument_offset is not None else 0}U, "
            f"{site.callback_argument_index or 0}U, "
            f"{site.callback_argument_offset or 0}U, "
            f"{site.callback_pointee_offset}U, "
            f"{1 if site.callback_nullable else 0}U, "
            f"{compact_publication_index}U, "
            f"{1 if arity_variadic else 0}U, {argument_words}U, "
            f"{cleanup_bytes}U, {argument_base_offset}U, "
            f"{loader_kind}U, "
            f"{loader_argument_0}U, {loader_argument_1}U, "
            f"{loader_nullable}U, {target_catalog_index}U, "
            f"{external_service_kind}U, "
            + ", ".join(
                f"{selector}U" for selector in external_service_arguments
            )
            + " },"
        )
    if service_kinds and sum(
        1 for site in plan.external_sites
        if (site.transfer_id, site.instruction_rva, site.event_index)
        in service_kinds
    ) != len(service_kinds):
        raise ToolkitInputError(
            "module runtime external-service table is not total over its sites"
        )
    state_assertions = [
        f'_Static_assert(offsetof(spx_machine_state, {field}) == {offset}U, '
        f'"assembly offset for {field} is stale");'
        for field, offset in _STATE_OFFSETS.items()
        if field != "x87_stack"
    ]
    state_assertions.extend([
        f'_Static_assert(offsetof(spx_machine_state, x87_stack) == '
        f'{_STATE_OFFSETS["x87_stack"]}U, '
        '"assembly offset for x87_stack is stale");',
        f'_Static_assert(sizeof(spx_x87_value) == {_X87_VALUE_SIZE}U, '
        '"assembly x87-value stride is stale");',
        f'_Static_assert(offsetof(spx_x87_value, empty) == '
        f'{_X87_VALUE_EMPTY_OFFSET}U, '
        '"assembly x87 empty offset is stale");',
        f'_Static_assert(offsetof(spx_x87_value, tag) == '
        f'{_X87_VALUE_TAG_OFFSET}U, '
        '"assembly x87 tag offset is stale");',
    ])
    frame_assertions = [
        f'_Static_assert(offsetof(spx_native_bridge_frame, {field}) == {offset}U, '
        f'"assembly bridge-frame offset for {field} is stale");'
        for field, offset in _FRAME_OFFSETS.items()
    ]
    x87_frame_assertions = [
        f'_Static_assert(offsetof(spx_native_x87_frame, {field}) == {offset}U, '
        f'"assembly x87-frame offset for {field} is stale");'
        for field, offset in _X87_FRAME_OFFSETS.items()
    ]
    code_capability_table = [
        (
            f"  {{ 0x{binding.instruction_rva:08x}U, "
            f"{binding.argument_index}U, 0x{binding.original_rva:08x}U, "
            f"{ingress_callback_symbols[binding.code_target_rva]}, "
            f"{ingress_capability_index[binding.capability_id]}U, "
            f"{0 if callback_lifetimes.get((binding.instruction_rva, binding.original_rva)) == 'during_call' else 1}U }},"
        )
        for binding in plan.code_capability_bindings
    ]
    compact_target_table = [
        (
            f"  {{ 0x{target.target_rva:08x}U, {target.flat_index}U, "
            f"(spx_native_assembly_fn)({domain.trampoline_table_symbol} + "
            f"{target.target_index * domain.trampoline_stride_bytes}U) }},"
        )
        for domain in compact_runtime.domains
        for target in domain.targets
    ]
    compact_publication_by_id = {
        str(row["id"]): row for row in compact_runtime.publications
    }
    compact_publication_table = []
    for publication in plan.compact_code_capability_publications:
        native = compact_publication_by_id.get(publication.publication_id)
        domain = compact_domains_by_id.get(publication.domain_id)
        if (
            domain is None
            or (
                native is not None
                and (
                    native.get("domain_id") != publication.domain_id
                    or native.get("instruction_rva")
                    != publication.instruction_rva
                )
            )
            or (
                native is None
                and not publication.publication_id.startswith(
                    "compact-callback-publication-v2:"
                )
            )
        ):
            raise ToolkitInputError(
                "module runtime compact callback publication is stale"
            )
        compact_publication_table.append(
            f"  {{ 0x{publication.instruction_rva:08x}U, "
            f"{publication.argument_index}U, {domain.flat_first}U, "
            f"{len(domain.targets)}U, "
            f"{0 if _native_callback_lifetime_kind(publication.lifetime) == 'during_call' else 1}U, "
            f"{1 if publication.authority_kind == 'interface_method_contract' else 0}U }},"
        )
    ingress_code_table = [
        (
            f"  {{ 0x{target_rva:08x}U, {symbol} }},"
        )
        for target_rva, symbol in sorted(ingress_symbols.items())
    ]
    x87_table = [
        (
            f"  {{ 0x{operation.image_base:08x}U, 0x{operation.rva_start:08x}U, "
            f"0x{operation.rva_end:08x}U, {operation.operation.source_size}U, "
            f"{json.dumps(operation.operation.identity)}, "
            f"{json.dumps(operation.contract_sha256)}, "
            f"spx_native_x87_bridge_{operation.id:04d} }},"
        )
        for operation in plan.x87_operations
    ]
    bridge_dispatch = [
        "static void spx_native_dispatch_bridge(void) {",
        "  spx_native_bridge();",
        "}",
    ]
    thread_state = [
        '#include "native-ingress-runtime.h"',
        "typedef struct spx_module_runtime_thread_state {",
        "  spx_native_bridge_frame *current_outgoing;",
        "  void *reserved;",
        "  spx_native_x87_frame *current_x87;",
        "} spx_module_runtime_thread_state;",
        "static spx_module_runtime_thread_state *spx_module_runtime_thread_state_get(void) {",
        "  return (spx_module_runtime_thread_state *)spx_module_runtime_thread_state_current();",
        "}",
        "#define spx_native_current_outgoing (spx_module_runtime_thread_state_get()->current_outgoing)",
        "#define spx_native_current_x87 (spx_module_runtime_thread_state_get()->current_x87)",
        "#define spx_native_diagnostic_reason (*spx_native_runtime_diagnostic_slot(0U))",
        "#define spx_native_diagnostic_value (*spx_native_runtime_diagnostic_slot(1U))",
        "#define spx_native_diagnostic_aux (*spx_native_runtime_diagnostic_slot(2U))",
        "#define spx_native_diagnostic_detail (*spx_native_runtime_diagnostic_slot(3U))",
        '_Static_assert(sizeof(spx_module_runtime_thread_state) == 12U, "PE TLS runtime state ABI changed");',
    ]
    return "\n".join([
        '#include "module-runtime.h"',
        "",
        *declarations,
        *ingress_declarations,
        *compact_declarations,
        *x87_declarations,
        "extern const unsigned char __ImageBase[];",
        "",
        *thread_state,
        "",
        *state_assertions,
        *frame_assertions,
        *x87_frame_assertions,
        f'_Static_assert(sizeof(spx_machine_state) == {_MACHINE_STATE_SIZE}U, '
        '"assembly machine-state size is stale");',
        f'_Static_assert(sizeof(spx_x87_fnsave_image) == {_FNSAVE_IMAGE_SIZE}U, '
        '"FNSAVE image must be 108 bytes in i686 mode");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, control_word) == 0U, '
        '"FNSAVE control offset changed");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, status_word) == 4U, '
        '"FNSAVE status offset changed");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, tag_word) == 8U, '
        '"FNSAVE tag offset changed");',
        '_Static_assert(offsetof(spx_x87_fnsave_image, physical_registers) == 28U, '
        '"FNSAVE physical-register offset changed");',
        '_Static_assert(SPX_CALL_OK == 0, "assembly status encoding is stale");',
        "",
        "typedef void (*spx_native_assembly_fn)(void);",
        "typedef struct spx_native_bridge_entry {",
        "  uint32_t instruction_rva;",
        "  uint32_t iat_rva;",
        "  uint32_t dynamic_target, tail_jump;",
        "  uint32_t callback_registration, callback_argument_index;",
        "  uint32_t callback_argument_offset, callback_pointee_offset;",
        "  uint32_t callback_nullable, compact_publication_index;",
        "  uint32_t arity_variadic, argument_words, cleanup_bytes;",
        "  uint32_t argument_base_offset, loader_service_kind;",
        "  uint32_t loader_argument_0, loader_argument_1, loader_nullable;",
        "  uint32_t target_catalog_index, external_service_kind;",
        "  uint32_t external_service_argument_0;",
        "  uint32_t external_service_argument_1;",
        "  uint32_t external_service_argument_2;",
        "  uint32_t external_service_argument_3;",
        "} spx_native_bridge_entry;",
        "typedef struct spx_native_code_capability {",
        "  uint32_t instruction_rva, argument_index, original_rva;",
        "  spx_native_assembly_fn bridge;",
        "  uint32_t capability_index, escaped;",
        "} spx_native_code_capability;",
        "typedef struct spx_native_compact_code_target {",
        "  uint32_t original_rva, flat_target_index;",
        "  spx_native_assembly_fn bridge;",
        "} spx_native_compact_code_target;",
        "typedef struct spx_native_compact_code_publication {",
        "  uint32_t instruction_rva, argument_index;",
        "  uint32_t target_first, target_count, escaped, method_scoped;",
        "} spx_native_compact_code_publication;",
        "typedef void (*spx_native_ingress_fn)(void);",
        "typedef struct spx_native_ingress_code_entry {",
        "  uint32_t target_rva;",
        "  spx_native_ingress_fn bridge;",
        "} spx_native_ingress_code_entry;",
        "typedef struct spx_native_x87_entry {",
        "  uint32_t image_base, rva_start, rva_end, source_size;",
        "  const char *operation_identity, *contract_sha256;",
        "  spx_native_assembly_fn bridge;",
        "} spx_native_x87_entry;",
        "",
        "static const spx_native_bridge_entry spx_native_bridges[] = {",
        *table,
        "};",
        f"static const uint32_t spx_native_bridge_count = {len(table)}U;",
        "",
        "static const spx_native_code_capability spx_native_code_capabilities[] = {",
        *code_capability_table,
        "};",
        f"static const uint32_t spx_native_code_capability_count = {len(code_capability_table)}U;",
        "",
        "static const spx_native_compact_code_target spx_native_compact_code_targets[] = {",
        *compact_target_table,
        "};",
        f"static const uint32_t spx_native_compact_code_target_count = {len(compact_target_table)}U;",
        "static const spx_native_compact_code_publication spx_native_compact_code_publications[] = {",
        *compact_publication_table,
        "};",
        f"static const uint32_t spx_native_compact_code_publication_count = {len(compact_publication_table)}U;",
        "",
        "static const spx_native_ingress_code_entry spx_native_ingress_code[] = {",
        *ingress_code_table,
        "};",
        f"static const uint32_t spx_native_ingress_code_count = {len(ingress_code_table)}U;",
        "",
        "static const spx_native_x87_entry spx_native_x87_entries[] = {",
        *x87_table,
        "};",
        f"static const uint32_t spx_native_x87_count = {len(x87_table)}U;",
        "",
        "static uint32_t spx_native_original_iat_target(uint32_t iat_rva);",
        "",
        "static const spx_native_bridge_entry *spx_native_bridge_entry_for(",
        "    const spx_call_event *event) {",
        "  const spx_native_bridge_entry *result = 0;",
        "  uint32_t i;",
        "  if (event == 0) return (const spx_native_bridge_entry *)0;",
        "  for (i = 0; i < spx_native_bridge_count; ++i) {",
        "    const spx_native_bridge_entry *entry = &spx_native_bridges[i];",
        "    if (entry->instruction_rva != event->instruction_rva) continue;",
        "    if (entry->dynamic_target != 0U) {",
        "      if (event->kind != SPX_CALL_INDIRECT ||",
        "          (entry->iat_rva == 0U && entry->target_catalog_index == 0U) ||",
        "          !spx_native_external_code_target_matches(",
        "              event->target_rva, entry->iat_rva,",
        "              entry->target_catalog_index))",
        "        continue;",
        "    } else if (event->kind != SPX_CALL_EXTERNAL_IMPORT) {",
        "      continue;",
        "    }",
        "    if (result != 0) return (const spx_native_bridge_entry *)0;",
        "    result = entry;",
        "  }",
        "  return result;",
        "}",
        "",
        "static const spx_native_code_capability *",
        "spx_native_code_capability_for(",
        "    uint32_t instruction_rva, uint32_t argument_index,",
        "    uint32_t observed_target) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  uint32_t i;",
        "  for (i = 0; i < spx_native_code_capability_count; ++i) {",
        "    const spx_native_code_capability *capability =",
        "        &spx_native_code_capabilities[i];",
        "    if (capability->instruction_rva == instruction_rva &&",
        "        capability->argument_index == argument_index &&",
        "        image_base + capability->original_rva == observed_target)",
        "      return capability;",
        "  }",
        "  return (const spx_native_code_capability *)0;",
        "}",
        "",
        "static const spx_native_compact_code_target *",
        "spx_native_compact_code_target_for(",
        "    const spx_native_compact_code_publication *publication,",
        "    uint32_t original_rva) {",
        "  uint32_t low, high;",
        "  if (publication == 0 || publication->target_first >",
        "      spx_native_compact_code_target_count || publication->target_count >",
        "      spx_native_compact_code_target_count - publication->target_first)",
        "    return (const spx_native_compact_code_target *)0;",
        "  low = publication->target_first;",
        "  high = low + publication->target_count;",
        "  while (low < high) {",
        "    const uint32_t middle = low + (high - low) / 2U;",
        "    const spx_native_compact_code_target *target =",
        "        &spx_native_compact_code_targets[middle];",
        "    if (target->original_rva < original_rva) low = middle + 1U;",
        "    else if (target->original_rva > original_rva) high = middle;",
        "    else return target;",
        "  }",
        "  return (const spx_native_compact_code_target *)0;",
        "}",
        "",
        "static const spx_native_compact_code_target *",
        "spx_native_compact_code_capability_for(",
        "    uint32_t publication_index, uint32_t instruction_rva,",
        "    uint32_t argument_index,",
        "    uint32_t observed_target,",
        "    const spx_native_compact_code_publication **publication_out) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  if (publication_out == 0 || observed_target < image_base)",
        "    return (const spx_native_compact_code_target *)0;",
        "  *publication_out = 0;",
        "  if (publication_index != 0U) {",
        "    const spx_native_compact_code_publication *publication;",
        "    const spx_native_compact_code_target *target;",
        "    if (publication_index > spx_native_compact_code_publication_count)",
        "      return (const spx_native_compact_code_target *)0;",
        "    publication = &spx_native_compact_code_publications[publication_index - 1U];",
        "    if ((publication->method_scoped == 0U &&",
        "         publication->instruction_rva != instruction_rva) ||",
        "        publication->argument_index != argument_index)",
        "      return (const spx_native_compact_code_target *)0;",
        "    target = spx_native_compact_code_target_for(",
        "        publication, observed_target - image_base);",
        "    if (target == 0) return (const spx_native_compact_code_target *)0;",
        "    *publication_out = publication;",
        "    return target;",
        "  }",
        "  {",
        "    uint32_t i;",
        "    for (i = 0U; i < spx_native_compact_code_publication_count; ++i) {",
        "      const spx_native_compact_code_publication *publication =",
        "          &spx_native_compact_code_publications[i];",
      "      const spx_native_compact_code_target *target;",
        "      if (publication->method_scoped != 0U) continue;",
        "      if (publication->instruction_rva != instruction_rva ||",
        "          publication->argument_index != argument_index) continue;",
        "      target = spx_native_compact_code_target_for(",
        "          publication, observed_target - image_base);",
        "      if (target == 0) continue;",
        "      if (*publication_out != 0)",
        "        return (const spx_native_compact_code_target *)0;",
        "      *publication_out = publication;",
        "    }",
        "    if (*publication_out != 0)",
        "      return spx_native_compact_code_target_for(",
        "          *publication_out, observed_target - image_base);",
        "  }",
        "  return (const spx_native_compact_code_target *)0;",
        "}",
        "",
        "uint32_t spx_native_code_bridge_address(uint32_t target_rva) {",
        "  uint32_t i, result = 0U;",
        "  for (i = 0U; i < spx_native_ingress_code_count; ++i)",
        "    if (spx_native_ingress_code[i].target_rva == target_rva)",
        "      return (uint32_t)(uintptr_t)spx_native_ingress_code[i].bridge;",
        "  for (i = 0U; i < spx_native_compact_code_target_count; ++i)",
        "    if (spx_native_compact_code_targets[i].original_rva == target_rva) {",
        "      const uint32_t observed = (uint32_t)(uintptr_t)",
        "          spx_native_compact_code_targets[i].bridge;",
        "      if (result != 0U && result != observed) return 0U;",
        "      result = observed;",
        "    }",
        "  return result;",
        "}",
        "",
        "uint32_t spx_native_publish_registered_code_result(",
        "    uint32_t source_rva, uint32_t logical_value) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  uint32_t i;",
        "  for (i = 0U; i < spx_native_code_capability_count; ++i) {",
        "    const spx_native_code_capability *capability =",
        "        &spx_native_code_capabilities[i];",
        "    uint32_t generation;",
        "    if (capability->instruction_rva != source_rva ||",
        "        image_base + capability->original_rva != logical_value)",
        "      continue;",
        "    if (capability->capability_index == 0xffffffffU) return 1U;",
        "    generation = spx_native_capability_activate(",
        "        capability->capability_index, capability->escaped);",
        "    if (generation == 0U) return 0U;",
        "    if (capability->escaped != 0U &&",
        "        spx_native_capability_commit(",
        "            capability->capability_index, generation) == 0U) {",
        "      (void)spx_native_capability_revoke(",
        "          capability->capability_index, generation);",
        "      return 0U;",
        "    }",
        "    return 1U;",
        "  }",
        "  for (i = 0U; i < spx_native_compact_code_publication_count; ++i) {",
        "    const spx_native_compact_code_publication *publication =",
        "        &spx_native_compact_code_publications[i];",
        "    const spx_native_compact_code_target *target;",
        "    uint32_t generation;",
        "    if (publication->instruction_rva != source_rva ||",
        "        logical_value < image_base) continue;",
        "    target = spx_native_compact_code_target_for(",
        "        publication, logical_value - image_base);",
        "    if (target == 0) continue;",
        "    generation = spx_native_compact_callback_activate(",
        "        target->flat_target_index, publication->escaped);",
        "    if (generation == 0U) return 0U;",
        "    if (publication->escaped != 0U &&",
        "        spx_native_compact_callback_commit(",
        "            target->flat_target_index, generation) == 0U) {",
        "      (void)spx_native_compact_callback_revoke(",
        "          target->flat_target_index, generation);",
        "      return 0U;",
        "    }",
        "    return 1U;",
        "  }",
        "  return 0U;",
        "}",
        "",
        "uint32_t spx_native_realize_registered_code_result(",
        "    uint32_t source_rva, uint32_t logical_value,",
        "    uint32_t *native_value) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  uint32_t i;",
        "  if (native_value == 0) return 2U;",
        "  for (i = 0; i < spx_native_code_capability_count; ++i) {",
        "    const spx_native_code_capability *capability =",
        "        &spx_native_code_capabilities[i];",
        "    if (capability->instruction_rva != source_rva ||",
        "        image_base + capability->original_rva != logical_value)",
        "      continue;",
        "    if (capability->capability_index != 0xffffffffU &&",
        "        spx_native_capability_is_active(",
        "            capability->capability_index) == 0U)",
        "      return 2U;",
        "    *native_value = (uint32_t)(uintptr_t)capability->bridge;",
        "    return *native_value != 0U ? 1U : 2U;",
        "  }",
        "  for (i = 0U; i < spx_native_compact_code_publication_count; ++i) {",
        "    const spx_native_compact_code_publication *publication =",
        "        &spx_native_compact_code_publications[i];",
        "    const spx_native_compact_code_target *target;",
        "    if (publication->instruction_rva != source_rva ||",
        "        logical_value < image_base) continue;",
        "    target = spx_native_compact_code_target_for(",
        "        publication, logical_value - image_base);",
        "    if (target == 0) continue;",
        "    if (spx_native_compact_callback_is_active(",
        "            target->flat_target_index) == 0U) return 2U;",
        "    *native_value = (uint32_t)(uintptr_t)target->bridge;",
        "    return *native_value != 0U ? 1U : 2U;",
        "  }",
        "  return 0U;",
        "}",
        "",
        "static __attribute__((unused)) const spx_native_x87_entry *",
        "spx_native_x87_entry_for(",
        "    uint32_t rva) {",
        "  uint32_t i;",
        "  for (i = 0; i < spx_native_x87_count; ++i)",
        "    if (spx_native_x87_entries[i].rva_start == rva)",
        "      return &spx_native_x87_entries[i];",
        "  return (const spx_native_x87_entry *)0;",
        "}",
        "",
        *bridge_dispatch,
        "",
        "static __attribute__((unused)) uint32_t spx_native_bytes_equal(",
        "    const uint8_t *left, const uint8_t *right, uint32_t count) {",
        "  uint32_t i;",
        "  if (left == 0 || right == 0) return 0U;",
        "  for (i = 0; i < count; ++i) if (left[i] != right[i]) return 0U;",
        "  return 1U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t spx_native_string_equal(",
        "    const char *left, const char *right) {",
        "  if (left == 0 || right == 0) return 0U;",
        "  while (*left != '\\0' && *right != '\\0')",
        "    if (*left++ != *right++) return 0U;",
        "  return *left == *right;",
        "}",
        "",
        "static uint32_t spx_native_fixed_flat_read_u32(",
        "    uint32_t address, uint32_t *value) {",
        "  const volatile uint8_t *bytes;",
        "  if (value == 0 || address > 0xffffffffU - 3U) return 0U;",
        "  bytes = (const volatile uint8_t *)(uintptr_t)address;",
        "  *value = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |",
        "      ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);",
        "  return 1U;",
        "}",
        "",
        "static uint32_t spx_native_fixed_flat_write_u32(",
        "    uint32_t address, uint32_t value) {",
        "  volatile uint8_t *bytes;",
        "  if (address > 0xffffffffU - 3U) return 0U;",
        "  bytes = (volatile uint8_t *)(uintptr_t)address;",
        "  bytes[0] = (uint8_t)value;",
        "  bytes[1] = (uint8_t)(value >> 8U);",
        "  bytes[2] = (uint8_t)(value >> 16U);",
        "  bytes[3] = (uint8_t)(value >> 24U);",
        "  return 1U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t spx_native_state_to_fnsave(",
        "    const spx_machine_state *state, spx_x87_fnsave_image *image) {",
        "  uint32_t i, j, top; uint16_t tags = 0U;",
        "  if (state == 0 || image == 0 || state->x87_last_opcode > 0x7ffU)",
        "    return 1U;",
        "  top = (state->x87_status >> 11U) & 7U;",
        "  if (((state->x87_status >> 7) & 1U) !=",
        "      (uint32_t)(state->x87_pending_exception & 1U)) return 1U;",
        "  for (i = 0; i < 8U; ++i) {",
        "    const uint32_t physical = (top + i) & 7U;",
        "    const uint32_t tag = state->x87_stack[i].tag;",
        "    const uint32_t empty = state->x87_stack[i].empty;",
        "    if (tag > 3U || empty > 1U || ((tag == 3U) != (empty != 0U)))",
        "      return 1U;",
        "    tags = (uint16_t)(tags | (uint16_t)(tag << (2U * physical)));",
        "  }",
        "  for (i = 0; i < sizeof(*image); ++i) ((uint8_t *)image)[i] = 0U;",
        "  image->control_word = state->x87_control;",
        "  image->status_word = state->x87_status;",
        "  image->tag_word = tags;",
        "  image->instruction_pointer = state->x87_instruction_pointer;",
        "  image->code_selector = state->x87_code_selector;",
        "  image->last_opcode = state->x87_last_opcode;",
        "  image->data_pointer = state->x87_data_pointer;",
        "  image->data_selector = state->x87_data_selector;",
        "  /* FNSAVE's tag word uses physical register numbers, but its 80-byte",
        "   * register area is serialized in logical ST(0)..ST(7) order. */",
        "  for (i = 0; i < 8U; ++i) for (j = 0; j < 10U; ++j)",
        "    image->physical_registers[i][j] =",
        "      state->x87_stack[i].value_bytes[j];",
        "  return 0U;",
        "}",
        "",
        "static __attribute__((unused)) uint32_t spx_native_fnsave_to_state(",
        "    const spx_x87_fnsave_image *image, spx_machine_state *state) {",
        "  uint32_t i, j, top;",
        "  if (image == 0 || state == 0 || image->last_opcode > 0x7ffU) return 1U;",
        "  top = (image->status_word >> 11U) & 7U;",
        "  state->x87_control = image->control_word;",
        "  state->x87_status = image->status_word;",
        "  state->x87_pending_exception = (uint8_t)((image->status_word >> 7) & 1U);",
        "  state->x87_last_opcode = image->last_opcode;",
        "  state->x87_instruction_pointer = image->instruction_pointer;",
        "  state->x87_code_selector = image->code_selector;",
        "  state->x87_data_pointer = image->data_pointer;",
        "  state->x87_data_selector = image->data_selector;",
        "  for (i = 0; i < 8U; ++i) {",
        "    const uint32_t physical = (top + i) & 7U;",
        "    const uint8_t tag =",
        "      (uint8_t)((image->tag_word >> (2U * physical)) & 3U);",
        "    state->x87_stack[i].tag = tag;",
        "    state->x87_stack[i].empty = tag == 3U ? 1U : 0U;",
        "    for (j = 0; j < 10U; ++j)",
        "      state->x87_stack[i].value_bytes[j] =",
        "        image->physical_registers[i][j];",
        "  }",
        "  return 0U;",
        "}",
        "",
        "static void spx_native_pack_flags(spx_machine_state *state) {",
        "  /* The supported machine model carries exactly these six flags.",
        "   * Do not replay unmodeled control bits such as TF, NT, RF, or VM. */",
        "  state->eflags = 2U |",
        "      ((state->cf & 1U) << 0) | ((state->pf & 1U) << 2) |",
        "      ((state->zf & 1U) << 6) | ((state->sf & 1U) << 7) |",
        "      ((state->df & 1U) << 10) | ((state->of & 1U) << 11);",
        "}",
        "",
        "static uint32_t spx_native_original_iat_target(uint32_t iat_rva) {",
        "  const uint32_t image_base = (uint32_t)(uintptr_t)&__ImageBase;",
        "  if (image_base == 0U || iat_rva == 0U ||",
        "      image_base > 0xffffffffU - iat_rva)",
        "    return 0U;",
        "  return *(volatile const uint32_t *)(uintptr_t)(image_base + iat_rva);",
        "}",
        "",
        *(
            _x87_handler_source_lines()
            if plan.x87_operations
            else []
        ),
        argument_domain_source(plan.external_sites),
        "spx_call_status spx_dispatch_external_call(",
        "    spx_runtime *runtime,",
        "    const spx_call_event *event,",
        "    const spx_machine_state *input,",
        "    spx_machine_state *output) {",
        "  spx_native_bridge_frame frame;",
        "  spx_external_call_snapshot external_snapshot;",
        "  const spx_native_bridge_entry *entry;",
        "  const spx_native_code_capability *code_capability = 0;",
        "  const spx_native_compact_code_publication *compact_publication = 0;",
        "  const spx_native_compact_code_target *compact_target = 0;",
        "  spx_native_assembly_fn callback_bridge = 0;",
        "  uint32_t callback_argument_address = 0U;",
        "  uint32_t callback_container_address = 0U;",
        "  uint32_t callback_argument_original = 0U;",
        "  uint32_t callback_argument_patched = 0U;",
        "  uint32_t callback_capability_generation = 0U;",
        "  uint32_t exception_snapshot[",
        "      SPX_NATIVE_EXCEPTION_OBJECT_SNAPSHOT_BYTES / 4U];",
        "  uint32_t exception_snapshot_size = 0U;",
        "  uint32_t exception_object_active = 0U;",
        "  uint32_t preserved_ebx, preserved_esi, preserved_edi, preserved_ebp;",
        "  if (runtime == 0 || runtime->context == 0 ||",
        "      event == 0 || input == 0 || output == 0)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_diagnostic_reason = 0U;",
        "  spx_native_diagnostic_value = 0U;",
        "  spx_native_diagnostic_aux = 0U;",
        "  spx_native_diagnostic_detail = 0U;",
        "  entry = spx_native_bridge_entry_for(event);",
        "  if (entry == 0) {",
        "    spx_native_diagnostic_reason = 0x1002U;",
        "    spx_native_diagnostic_value = event->instruction_rva;",
        "    spx_native_diagnostic_aux = event->target_rva;",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  if ((entry->dynamic_target && event->kind != SPX_CALL_INDIRECT) ||",
        "      (!entry->dynamic_target && event->kind != SPX_CALL_EXTERNAL_IMPORT))",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  if (entry->dynamic_target != 0U &&",
        "      !spx_native_external_code_target_matches(",
        "          event->target_rva, entry->iat_rva,",
        "          entry->target_catalog_index)) {",
        "    spx_native_diagnostic_reason = 0x1003U;",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  preserved_ebx = input->ebx;",
        "  if (!spx_native_arguments_admitted(runtime, entry, input)) {",
        "    spx_native_diagnostic_reason = 0x1019U;",
        "    spx_native_diagnostic_value = event->instruction_rva;",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  preserved_esi = input->esi;",
        "  preserved_edi = input->edi;",
        "  preserved_ebp = input->ebp;",
        "  if (spx_native_runtime_capture_external_call(",
        "          event, input, &external_snapshot) != SPX_CALL_OK)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  if (input->df != 0U) {",
        "    spx_native_diagnostic_reason = 0x1006U;",
        "    spx_native_diagnostic_value = input->df;",
        "    spx_native_diagnostic_aux = event->instruction_rva;",
        "    spx_native_diagnostic_detail = event->target_rva;",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  frame.parent = spx_native_current_outgoing;",
        "  frame.output = output;",
        "  frame.private_esp = 0U;",
        "  frame.call_target = entry->dynamic_target",
        "      ? event->target_rva : spx_native_original_iat_target(entry->iat_rva);",
        "  frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  frame.saved_continuation = 0U;",
        "  frame.tail_jump = entry->tail_jump != 0U;",
        "  frame.argument_source = 0U;",
        "  frame.argument_words = entry->argument_words;",
        "  frame.cleanup_bytes = entry->cleanup_bytes;",
        "  frame.logical_result_esp = 0U;",
        "  frame.expected_capture_esp = 0U;",
        "  if (frame.call_target == 0U) return SPX_CALL_UNIMPLEMENTED;",
        "  if (entry->tail_jump != 0U) {",
        "    if (runtime->context == 0)",
        "      return SPX_CALL_UNIMPLEMENTED;",
        "    if (spx_native_fixed_flat_read_u32(",
        "            input->esp, &frame.saved_continuation) == 0U ||",
        "        frame.saved_continuation == 0U)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "  }",
        "  if (input->esp > 0xffffffffU - entry->argument_base_offset)",
        "    return SPX_CALL_MEMORY_FAULT;",
        "  frame.argument_source = input->esp + entry->argument_base_offset;",
        "  if (entry->arity_variadic != 0U) {",
        "    uint32_t host_stack_base, host_stack_limit, suffix_bytes;",
        "    if (spx_native_host_stack_bounds_current(",
        "            &host_stack_base, &host_stack_limit) == 0U ||",
        "        frame.argument_source < host_stack_limit ||",
        "        frame.argument_source > host_stack_base)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "    suffix_bytes = host_stack_base - frame.argument_source;",
        "    if ((suffix_bytes & 3U) != 0U ||",
        "        suffix_bytes / 4U < entry->argument_words)",
        "      return SPX_CALL_UNIMPLEMENTED;",
        "    frame.argument_words = suffix_bytes / 4U;",
        "  }",
        "  if (input->esp > 0xffffffffU - entry->cleanup_bytes -",
        "          (entry->tail_jump != 0U ? 4U : 0U))",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  frame.logical_result_esp = input->esp + entry->cleanup_bytes +",
        "      (entry->tail_jump != 0U ? 4U : 0U);",
        "  if (entry->callback_registration != 0U) {",
        "    if (input->esp > 0xffffffffU - entry->callback_argument_offset)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "    callback_argument_address =",
        "        input->esp + entry->callback_argument_offset;",
        "    if (entry->callback_registration == 2U) {",
        "      if (spx_native_fixed_flat_read_u32(",
        "              callback_argument_address,",
        "              &callback_container_address) == 0U ||",
        "          callback_container_address == 0U ||",
        "          callback_container_address >",
        "              0xffffffffU - entry->callback_pointee_offset)",
        "        return SPX_CALL_MEMORY_FAULT;",
        "      callback_argument_address =",
        "          callback_container_address + entry->callback_pointee_offset;",
        "    } else if (entry->callback_registration != 1U) {",
        "      return SPX_CALL_UNIMPLEMENTED;",
        "    }",
        "    if (spx_native_fixed_flat_read_u32(",
        "            callback_argument_address, &callback_argument_original) == 0U)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "    if (callback_argument_original == 0U) {",
        "      if (entry->callback_nullable == 0U)",
        "        return SPX_CALL_UNIMPLEMENTED;",
        "    } else {",
        "      code_capability = spx_native_code_capability_for(",
        "          entry->instruction_rva, entry->callback_argument_index,",
        "          callback_argument_original);",
        "      if (code_capability != 0) {",
        "        callback_bridge = code_capability->bridge;",
        "      } else {",
        "        compact_target = spx_native_compact_code_capability_for(",
        "            entry->compact_publication_index, entry->instruction_rva,",
        "            entry->callback_argument_index,",
        "            callback_argument_original, &compact_publication);",
        "        if (compact_target == 0 || compact_publication == 0)",
        "          return SPX_CALL_UNIMPLEMENTED;",
        "        callback_bridge = compact_target->bridge;",
        "      }",
        "      if (code_capability != 0 &&",
        "          code_capability->capability_index != 0xffffffffU) {",
        "        callback_capability_generation = spx_native_capability_activate(",
        "            code_capability->capability_index, code_capability->escaped);",
        "        if (callback_capability_generation == 0U)",
        "          return SPX_CALL_UNIMPLEMENTED;",
        "      } else if (compact_target != 0) {",
        "        callback_capability_generation =",
        "            spx_native_compact_callback_activate(",
        "                compact_target->flat_target_index,",
        "                compact_publication->escaped);",
        "        if (callback_capability_generation == 0U)",
        "          return SPX_CALL_UNIMPLEMENTED;",
        "      }",
        "      if (spx_native_fixed_flat_write_u32(",
        "              callback_argument_address,",
        "              (uint32_t)(uintptr_t)callback_bridge) == 0U)",
        "        return SPX_CALL_MEMORY_FAULT;",
        "      callback_argument_patched = 1U;",
        "    }",
        "  }",
        "  *output = *input;",
        "  spx_native_pack_flags(output);",
        "  if (entry->external_service_kind == 2U) {",
        "    if (external_snapshot.argument_count != 4U)",
        "      return SPX_CALL_UNIMPLEMENTED;",
        "    return spx_native_runtime_begin_checked_unwind(",
        "        event->source_rva,",
        "        external_snapshot.arguments[",
        "            entry->external_service_argument_0],",
        "        external_snapshot.arguments[",
        "            entry->external_service_argument_1],",
        "        external_snapshot.arguments[",
        "            entry->external_service_argument_2],",
        "        external_snapshot.arguments[",
        "            entry->external_service_argument_3],",
        "        input, output);",
        "  }",
        *(
            [
                "  if (spx_native_state_to_fnsave(input, &frame.input_x87) != 0U)",
                "    return SPX_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_operations
            else []
        ),
        "  if (entry->external_service_kind == 1U) {",
        "    if (external_snapshot.argument_count != 1U ||",
        "        spx_native_runtime_begin_exception_object(",
        "            external_snapshot.arguments[",
        "                entry->external_service_argument_0],",
        "            exception_snapshot,",
        "            sizeof(exception_snapshot),",
        "            &exception_snapshot_size) != SPX_CALL_OK)",
        "      return SPX_CALL_MEMORY_FAULT;",
        "    exception_object_active = 1U;",
        "  } else if (entry->external_service_kind != 0U) {",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  frame.input = output;",
        "  spx_native_current_outgoing = &frame;",
        "  spx_native_dispatch_bridge();",
        "  if (callback_argument_patched != 0U &&",
        "      spx_native_fixed_flat_write_u32(",
        "          callback_argument_address, callback_argument_original) == 0U)",
        "    frame.status = SPX_CALL_MEMORY_FAULT;",
        "  if (spx_native_current_outgoing != &frame)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_current_outgoing = frame.parent;",
        "  if (frame.status != SPX_CALL_OK &&",
        "      spx_native_diagnostic_reason == 0U) {",
        "    spx_native_diagnostic_reason = 0x1010U;",
        "    spx_native_diagnostic_value = (uint32_t)frame.status;",
        "    spx_native_diagnostic_aux = frame.expected_capture_esp;",
        "    spx_native_diagnostic_detail = output->esp;",
        "  }",
        "  if (exception_object_active != 0U) {",
        "    const spx_call_status object_status =",
        "        spx_native_runtime_finish_exception_object(",
        "            external_snapshot.arguments[",
        "                entry->external_service_argument_0],",
        "            exception_snapshot,",
        "            exception_snapshot_size,",
        "            frame.status == SPX_CALL_OK ? 1U : 0U);",
        "    if (object_status != SPX_CALL_OK)",
        "      frame.status = object_status;",
        "  }",
        "  if (callback_capability_generation != 0U && compact_target != 0) {",
        "    if (frame.status == SPX_CALL_OK && compact_publication->escaped != 0U) {",
        "      if (spx_native_compact_callback_commit(",
        "              compact_target->flat_target_index,",
        "              callback_capability_generation) == 0U)",
        "        frame.status = SPX_CALL_UNIMPLEMENTED;",
        "    } else if (spx_native_compact_callback_revoke(",
        "                   compact_target->flat_target_index,",
        "                   callback_capability_generation) == 0U &&",
        "               frame.status == SPX_CALL_OK) {",
        "      frame.status = SPX_CALL_UNIMPLEMENTED;",
        "    }",
        "  } else if (callback_capability_generation != 0U &&",
        "             code_capability != 0) {",
        "    if (frame.status == SPX_CALL_OK && code_capability->escaped != 0U) {",
        "      if (spx_native_capability_commit(code_capability->capability_index,",
        "              callback_capability_generation) == 0U)",
        "        frame.status = SPX_CALL_UNIMPLEMENTED;",
        "    } else if (spx_native_capability_revoke(",
        "                   code_capability->capability_index,",
        "                   callback_capability_generation) == 0U &&",
        "               frame.status == SPX_CALL_OK) {",
        "      frame.status = SPX_CALL_UNIMPLEMENTED;",
        "    }",
        "  }",
        "  if (frame.status == SPX_CALL_OK &&",
        "      (output->ebx != preserved_ebx || output->esi != preserved_esi ||",
        "       output->edi != preserved_edi || output->ebp != preserved_ebp)) {",
        "    spx_native_diagnostic_reason = 0x1005U;",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  }",
        "  if (frame.status == SPX_CALL_OK) {",
        "    output->df = 0U;",
        "    output->eflags &= ~(1U << 10);",
        "  }",
        *(
            [
                "  if (frame.status == SPX_CALL_OK &&",
                "      spx_native_fnsave_to_state(&frame.output_x87, output) != 0U)",
                "    frame.status = SPX_CALL_UNIMPLEMENTED;",
            ]
            if plan.x87_operations
            else []
        ),
        "  if (frame.status == SPX_CALL_OK)",
        "    frame.status = spx_native_runtime_record_external_result(",
        "        event, &external_snapshot, output);",
        "  if (frame.status == SPX_CALL_OK && entry->loader_service_kind != 0U)",
        "    frame.status = spx_native_runtime_record_loader_service(",
        "        entry->loader_service_kind, entry->argument_base_offset,",
        "        entry->loader_argument_0, entry->loader_argument_1,",
        "        entry->loader_nullable, &external_snapshot, output);",
        "  return frame.status;",
        "}",
        "",
    ])


def _x87_handler_source_lines() -> list[str]:
    return [
        "spx_call_status spx_native_execute_typed_x87_operation(",
        "    spx_runtime *runtime, const spx_typed_x87_operation *program,",
        "    const spx_machine_state *input, spx_machine_state *output) {",
        "  const spx_native_x87_entry *entry;",
        "  spx_native_x87_frame frame;",
        "  if (runtime == 0 || runtime->context == 0 || program == 0 ||",
        "      input == 0 || output == 0)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  entry = spx_native_x87_entry_for(program->rva_start);",
        "  if (entry == 0 || entry->image_base != program->image_base ||",
        "      entry->rva_end != program->rva_end ||",
        "      entry->source_size != program->source_size ||",
        "      !spx_native_string_equal(entry->operation_identity,",
        "          program->operation_identity) ||",
        "      !spx_native_string_equal(entry->contract_sha256,",
        "          program->contract_sha256) ||",
        f"      !spx_native_string_equal(program->checked_decoder, {json.dumps(_X87_CHECKED_DECODER)}) ||",
        f"      !spx_native_string_equal(program->checked_executor, {json.dumps(_X87_CHECKED_EXECUTOR)}))",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  frame.parent = spx_native_current_x87;",
        "  frame.input = output;",
        "  frame.output = output;",
        "  frame.private_esp = 0U;",
        "  frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  *output = *input;",
        "  spx_native_pack_flags(output);",
        "  if (spx_native_state_to_fnsave(input, &frame.input_x87) != 0U)",
        "    return SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_current_x87 = &frame;",
        "  entry->bridge();",
        "  if (spx_native_current_x87 != &frame)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  spx_native_current_x87 = frame.parent;",
        "  if (frame.status == SPX_CALL_OK &&",
        "      spx_native_fnsave_to_state(&frame.output_x87, output) != 0U)",
        "    frame.status = SPX_CALL_UNIMPLEMENTED;",
        "  return frame.status;",
        "}",
        "",
    ]


def _bridge_assembly(plan: ModuleRuntimePlan) -> str:
    termination_iat = (
        f"0x{plan.termination_import.iat_va:08x}"
        if plan.termination_import is not None
        else None
    )
    lines = [
        "    .intel_syntax noprefix",
        "    .text",
        "",
        "    .extern _spx_native_outgoing_frame_current",
        "    .extern _spx_native_x87_frame_current",
        "_spx_native_halt:",
        "    .globl _spx_native_termination",
        "_spx_native_termination:",
        *(
            [
                "    push eax",
                "    push 0",
                f"    jmp DWORD PTR ds:{termination_iat}",
            ]
            if termination_iat is not None
            else [
                "    int 0x29",
                "    jmp _spx_native_halt",
            ]
        ),
        "",
        "    .globl _spx_native_terminate",
        "_spx_native_terminate:",
        *(
            [f"    jmp DWORD PTR ds:{termination_iat}"]
            if termination_iat is not None
            else [
                "    int 0x29",
                "    jmp _spx_native_terminate",
            ]
        ),
        "",
        "/* The boundary transducer keeps the Windows TEB, SEH chain, and native",
        " * target on the checked private stack.  It copies either the exact fixed",
        " * frame or the authorized complete variadic suffix from the captured",
        " * caller stack, preserves target-entry alignment, captures the result,",
        " * and translates physical stack cleanup back to logical guest ESP. */",
        "    .globl _spx_native_bridge",
        "_spx_native_bridge:",
        "    push ebp",
        "    push ebx",
        "    push esi",
        "    push edi",
        "    call _spx_native_outgoing_frame_current",
        "    test eax, eax",
        "    je _spx_native_bridge_unavailable",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}], esp",
        f"    mov ecx, DWORD PTR [eax + {_FRAME_OFFSETS['input']}]",
        *(
            [f"    frstor [eax + {_FRAME_OFFSETS['input_x87']}]" ]
            if plan.x87_operations
            else []
        ),
        f"    mov ebx, DWORD PTR [eax + {_FRAME_OFFSETS['argument_words']}]",
        "    cmp ebx, 0x3fffffff",
        "    ja _spx_native_bridge_unavailable",
        "    shl ebx, 2",
        f"    mov edi, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
        "    sub edi, ebx",
        "    jc _spx_native_bridge_unavailable",
        "    sub edi, 4",
        "    jc _spx_native_bridge_unavailable",
        "    mov esi, edi",
        f"    mov edx, DWORD PTR [ecx + {_STATE_OFFSETS['esp']}]",
        f"    cmp DWORD PTR [eax + {_FRAME_OFFSETS['tail_jump']}], 0",
        "    jne _spx_native_bridge_alignment_ready",
        "    sub edx, 4",
        "_spx_native_bridge_alignment_ready:",
        "    sub esi, edx",
        "    and esi, 15",
        "    sub edi, esi",
        "    jc _spx_native_bridge_unavailable",
        "    mov esi, DWORD PTR fs:8",
        "    add esi, 40",
        "    jc _spx_native_bridge_unavailable",
        "    cmp edi, esi",
        "    jb _spx_native_bridge_unavailable",
        "    mov DWORD PTR [edi], OFFSET FLAT:_spx_native_capture",
        "    lea edx, [edi + 4]",
        f"    add edx, DWORD PTR [eax + {_FRAME_OFFSETS['cleanup_bytes']}]",
        "    jc _spx_native_bridge_unavailable",
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['expected_capture_esp']}], edx",
        "    mov edx, edi",
        "    lea edi, [edi + 4]",
        f"    mov esi, DWORD PTR [eax + {_FRAME_OFFSETS['argument_source']}]",
        f"    mov ecx, DWORD PTR [eax + {_FRAME_OFFSETS['argument_words']}]",
        "    cld",
        "    rep movsd",
        f"    mov ecx, DWORD PTR [eax + {_FRAME_OFFSETS['input']}]",
        "    lea esp, [edx - 4]",
        f"    mov edx, DWORD PTR [eax + {_FRAME_OFFSETS['call_target']}]",
        "    mov DWORD PTR [esp], edx",
        "_spx_native_bridge_restore:",
        *_restore_pushes("ecx"),
        "    popad",
        "    popfd",
        "    ret",
        "_spx_native_bridge_unavailable:",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
        "",
        "    .globl _spx_native_capture",
        "_spx_native_capture:",
        "    pushfd",
        "    pushad",
        "    call _spx_native_outgoing_frame_current",
        "    test eax, eax",
        "    je _spx_native_halt",
        *(
            [f"    fnsave [eax + {_FRAME_OFFSETS['output_x87']}]" ]
            if plan.x87_operations
            else []
        ),
        f"    mov edx, DWORD PTR [eax + {_FRAME_OFFSETS['output']}]",
        *_capture_pushad_registers("edx"),
        f"    cmp ecx, DWORD PTR [eax + {_FRAME_OFFSETS['expected_capture_esp']}]",
        "    jne _spx_native_capture_preserve_status",
        f"    mov ebx, DWORD PTR [eax + {_FRAME_OFFSETS['logical_result_esp']}]",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['esp']}], ebx",
        "    mov ecx, DWORD PTR [esp + 32]",
        f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], ecx",
        *_capture_split_flags("edx"),
        f"    mov DWORD PTR [eax + {_FRAME_OFFSETS['status']}], 0",
        "_spx_native_capture_preserve_status:",
        f"    mov esp, DWORD PTR [eax + {_FRAME_OFFSETS['private_esp']}]",
        "    cld",
        "    pop edi",
        "    pop esi",
        "    pop ebx",
        "    pop ebp",
        "    ret",
    ]
    if plan.x87_operations:
        lines.extend([
            "",
            "/* Typed x87 operations use reviewed mnemonic and operand rendering. */",
        ])
    for replay in plan.x87_operations:
        lines.extend([
            "",
            f"    .globl _spx_native_x87_bridge_{replay.id:04d}",
            f"_spx_native_x87_bridge_{replay.id:04d}:",
            "    push ebp",
            "    push ebx",
            "    push esi",
            "    push edi",
            "    call _spx_native_x87_frame_current",
            f"    mov DWORD PTR [eax + {_X87_FRAME_OFFSETS['private_esp']}], esp",
            f"    frstor [eax + {_X87_FRAME_OFFSETS['input_x87']}]",
            f"    mov eax, DWORD PTR [eax + {_X87_FRAME_OFFSETS['input']}]",
            f"    mov ebx, DWORD PTR [eax + {_STATE_OFFSETS['ebx']}]",
            f"    mov ecx, DWORD PTR [eax + {_STATE_OFFSETS['ecx']}]",
            f"    mov esi, DWORD PTR [eax + {_STATE_OFFSETS['esi']}]",
            f"    mov edi, DWORD PTR [eax + {_STATE_OFFSETS['edi']}]",
            f"    mov ebp, DWORD PTR [eax + {_STATE_OFFSETS['ebp']}]",
            f"    mov esp, DWORD PTR [eax + {_STATE_OFFSETS['esp']}]",
            f"    push DWORD PTR [eax + {_STATE_OFFSETS['eflags']}]",
            f"    push DWORD PTR [eax + {_STATE_OFFSETS['eax']}]",
            f"    mov edx, DWORD PTR [eax + {_STATE_OFFSETS['edx']}]",
            "    pop eax",
            "    popfd",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"> {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET}",
            '    .error "x87 replay prologue exceeds its fixed bridge slot"',
            "    .endif",
            f"    .fill {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_INSTRUCTION_OFFSET}",
            '    .error "x87 replay instruction offset changed"',
            "    .endif",
            f"    .globl _spx_native_x87_instruction_{replay.id:04d}",
            f"_spx_native_x87_instruction_{replay.id:04d}:",
            f"    {_render_typed_x87_instruction(replay)}",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"> {_X87_REPLAY_INLINE_CAPTURE_OFFSET}",
            '    .error "x87 replay instruction exceeds its fixed bridge slot"',
            "    .endif",
            f"    .fill {_X87_REPLAY_INLINE_CAPTURE_OFFSET} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_CAPTURE_OFFSET}",
            '    .error "x87 replay capture offset changed"',
            "    .endif",
            f"_spx_native_x87_capture_{replay.id:04d}:",
            "    pushfd",
            "    push eax",
            "    call _spx_native_x87_frame_current",
            f"    fnsave [eax + {_X87_FRAME_OFFSETS['output_x87']}]",
            f"    mov edx, DWORD PTR [eax + {_X87_FRAME_OFFSETS['output']}]",
            "    mov ecx, DWORD PTR [esp]",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eax']}], ecx",
            f"    setc BYTE PTR [edx + {_STATE_OFFSETS['cf']}]",
            f"    setp BYTE PTR [edx + {_STATE_OFFSETS['pf']}]",
            f"    setz BYTE PTR [edx + {_STATE_OFFSETS['zf']}]",
            f"    sets BYTE PTR [edx + {_STATE_OFFSETS['sf']}]",
            f"    seto BYTE PTR [edx + {_STATE_OFFSETS['of']}]",
            "    mov ebx, DWORD PTR [esp + 4]",
            f"    mov ecx, DWORD PTR [eax + {_X87_FRAME_OFFSETS['input']}]",
            f"    mov ecx, DWORD PTR [ecx + {_STATE_OFFSETS['eflags']}]",
            "    and ecx, 0xfffff32a",
            "    and ebx, 0x00000cd5",
            "    or ecx, ebx",
            f"    mov DWORD PTR [edx + {_STATE_OFFSETS['eflags']}], ecx",
            f"    mov DWORD PTR [eax + {_X87_FRAME_OFFSETS['status']}], 0",
            f"    mov esp, DWORD PTR [eax + {_X87_FRAME_OFFSETS['private_esp']}]",
            "    cld",
            "    pop edi",
            "    pop esi",
            "    pop ebx",
            "    pop ebp",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"> {_X87_REPLAY_INLINE_RETURN_OFFSET}",
            '    .error "x87 replay capture exceeds its fixed bridge slot"',
            "    .endif",
            f"    .fill {_X87_REPLAY_INLINE_RETURN_OFFSET} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_RETURN_OFFSET}",
            '    .error "x87 replay return offset changed"',
            "    .endif",
            f"_spx_native_x87_return_{replay.id:04d}:",
            "    ret",
            f"    .fill {_X87_REPLAY_INLINE_BODY_SIZE} - "
            f"(. - _spx_native_x87_bridge_{replay.id:04d}), 1, 0x90",
            f"    .if (. - _spx_native_x87_bridge_{replay.id:04d}) "
            f"!= {_X87_REPLAY_INLINE_BODY_SIZE}",
            '    .error "x87 replay bridge size changed"',
            "    .endif",
        ])
    return "\n".join(lines).rstrip() + "\n"
