"""Lift a checked Windows path-component scanner into portable C."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from spaghetti_extractor.component_profile import (
    ComponentProfileContext,
    PreparedComponentProfile,
    array_value,
    machine_eflags_sync_lines,
    object_value,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import write_json


_FORMAT = "stage-b-windows-path-info-scan-contract-v1"
_MAX_PATH_BYTES = 16
_EXPECTED_LOWERING_SHA256 = "b9a4909e29d0c7f5acae754fe5861b47c1810e41a3401c099b57583409c5f76a"


def _canonical_sha256(value: Any) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _rva(unit: Mapping[str, Any]) -> int:
    return int(object_value(unit.get("source"), "path-scan source")["original"]["rva_start"])


def _normalized_operand(
    operand: Mapping[str, Any],
    *,
    mnemonic: str,
    image_base: int,
    unit_index_by_rva: Mapping[int, int],
    service: tuple[str, str] | None,
) -> list[Any]:
    kind = operand.get("kind")
    width = int(operand.get("width_bits", 0))
    if kind == "register":
        return ["register", str(operand.get("name")), width]
    if kind == "immediate":
        value = int(operand.get("value", 0))
        target_rva = value - image_base
        if mnemonic.startswith("j") and target_rva in unit_index_by_rva:
            return ["target", unit_index_by_rva[target_rva]]
        return ["immediate", value, width]
    if kind != "memory":
        raise StageAInputError(f"unsupported path-scan operand kind: {kind!r}")
    base = operand.get("base")
    displacement: Any = int(operand.get("displacement", 0))
    if mnemonic == "call" and base is None and service is not None:
        displacement = ["service", *service]
    elif base is None and displacement >= image_base:
        displacement = ["image_relative", displacement - image_base]
    return [
        "memory",
        base,
        operand.get("index"),
        int(operand.get("scale", 1)),
        displacement,
        width,
    ]


def _lowering_signature(
    units: Sequence[Mapping[str, Any]], *, image_base: int
) -> tuple[dict[str, Any], str]:
    ordered = sorted(units, key=_rva)
    index_by_rva = {_rva(unit): index for index, unit in enumerate(ordered)}
    entry_rva = _rva(ordered[0])
    rows: list[dict[str, Any]] = []
    for index, unit in enumerate(ordered):
        semantics = object_value(unit.get("semantics"), "path-scan semantics")
        events = array_value(semantics.get("external_events"), "path-scan events")
        service = None
        if len(events) == 1:
            event = object_value(events[0], "path-scan event")
            service = (str(event.get("dll")), str(event.get("symbol")))
        elif len(events) > 1:
            raise StageAInputError("path-scan unit contains multiple service calls")
        instructions = []
        for instruction_value in array_value(
            unit.get("instructions"), "path-scan instructions"
        ):
            instruction = object_value(instruction_value, "path-scan instruction")
            mnemonic = str(instruction.get("mnemonic"))
            instructions.append(
                [
                    mnemonic,
                    [
                        _normalized_operand(
                            object_value(value, "path-scan operand"),
                            mnemonic=mnemonic,
                            image_base=image_base,
                            unit_index_by_rva=index_by_rva,
                            service=service,
                        )
                        for value in array_value(
                            instruction.get("operands"), "path-scan operands"
                        )
                    ],
                ]
            )
        control = object_value(unit.get("control"), "path-scan control")
        direct_targets = []
        for target in control.get("direct_targets", []):
            target_value = int(target)
            direct_targets.append(
                ["unit", index_by_rva[target_value]]
                if target_value in index_by_rva
                else ["relative", target_value - entry_rva]
            )
        normalized_events = []
        for event_value in events:
            event = object_value(event_value, "path-scan event")
            return_rva = int(event.get("return_rva", -1))
            normalized_events.append(
                {
                    "kind": event.get("kind"),
                    "dll": event.get("dll"),
                    "symbol": event.get("symbol"),
                    "argument_count": len(event.get("arguments", [])),
                    "return": (
                        ["unit", index_by_rva[return_rva]]
                        if return_rva in index_by_rva
                        else ["relative", return_rva - entry_rva]
                    ),
                }
            )
        source = object_value(unit.get("source"), "path-scan source")
        original = object_value(source.get("original"), "path-scan original span")
        rows.append(
            {
                "index": index,
                "offset": _rva(unit) - entry_rva,
                "size": int(original["size"]),
                "instructions": instructions,
                "control": {
                    "kind": control.get("kind"),
                    "indirect": control.get("has_indirect_target"),
                    "targets": direct_targets,
                },
                "events": normalized_events,
            }
        )
    signature = {"format": "windows-path-info-lowering-signature-v1", "units": rows}
    return signature, _canonical_sha256(signature)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("Windows path scanner has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("Windows path scanner units do not match exact membership")
    if len(context.units) != 59:
        raise StageAInputError("Windows path scanner requires 59 machine units")

    binary = object_value(context.machine_ir_manifest.get("binary"), "machine IR binary")
    image_base = binary.get("image_base")
    if not isinstance(image_base, int):
        raise StageAInputError("Windows path scanner has no image base")
    signature, lowering_sha256 = _lowering_signature(
        context.units, image_base=image_base
    )
    if lowering_sha256 != _EXPECTED_LOWERING_SHA256:
        raise StageAInputError(
            "unsupported Windows path-scanner lowering: " + lowering_sha256
        )

    ordered = sorted(context.units, key=_rva)
    service_sites: dict[str, list[tuple[int, int]]] = {}
    for unit in ordered:
        semantics = object_value(unit.get("semantics"), "path-scan semantics")
        events = array_value(
            semantics.get("external_events"),
            "path-scan events",
        )
        ordered_events = [
            object_value(value, "path-scan ordered event")
            for value in array_value(
                semantics.get("ordered_events"), "path-scan ordered events"
            )
            if isinstance(value, Mapping) and value.get("family") == "external"
        ]
        if len(events) != len(ordered_events):
            raise StageAInputError("Windows path scanner event order is incomplete")
        for event_value, ordered_event in zip(events, ordered_events, strict=True):
            event = object_value(event_value, "path-scan event")
            if event.get("kind") != "external_call" or event.get("dll") != "kernel32.dll":
                raise StageAInputError("Windows path scanner has an unexpected service")
            symbol = str(event.get("symbol"))
            service_sites.setdefault(symbol, []).append(
                (
                    int(ordered_event["instruction_rva"]),
                    int(event.get("return_rva", -1)),
                )
            )
    if set(service_sites) != {"AreFileApisANSI", "IsDBCSLeadByteEx"}:
        raise StageAInputError("Windows path scanner service inventory is incomplete")
    if len(service_sites["AreFileApisANSI"]) != 1 or len(
        service_sites["IsDBCSLeadByteEx"]
    ) != 2:
        raise StageAInputError("Windows path scanner service sites are malformed")

    boundary = object_value(context.component.get("machine_boundary"), "component boundary")
    counts = object_value(boundary.get("counts"), "component boundary counts")
    exits = array_value(boundary.get("exits"), "component exits")
    if (
        boundary.get("call_closure", {}).get("status") != "complete"
        or counts.get("entries") != 1
        or counts.get("exits") != 1
        or counts.get("external_events") != 3
        or counts.get("faults") != 0
        or len(exits) != 1
        or exits[0].get("kind") != "return"
    ):
        raise StageAInputError("Windows path scanner boundary is not exact")

    bindings = []
    for unit in ordered:
        source = object_value(unit.get("source"), "path-scan source")
        semantic_export = source.get("semantic_export")
        bindings.append(
            {
                "unit_id": str(unit["id"]),
                "rva_start": _rva(unit),
                "rva_end": int(source["original"]["rva_end"]),
                "instruction_bytes_sha256": str(source["instruction_bytes_sha256"]),
                "semantic_transfer_sha256": (
                    None
                    if semantic_export is None
                    else str(semantic_export["semantic_transfer_sha256"])
                ),
            }
        )
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "windows_path_info_scan_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
        },
        "lowering": {
            "format": signature["format"],
            "sha256": lowering_sha256,
            "unit_count": len(ordered),
        },
        "domain": {
            "kind": "guarded_partial",
            "max_path_bytes": _MAX_PATH_BYTES,
            "requires_nul_terminator": True,
            "requires_readable_path": True,
            "requires_writable_info_record": True,
            "requires_writable_stack_frame": True,
            "requires_disjoint_path_info_stack": True,
            "requires_nonwrapping_ranges": True,
            "fallback": "canonical_machine_ir",
            "decline_before_guest_writes": True,
            "decline_before_observable_effects": True,
            "declines_before_guest_writes_or_external_events": True,
        },
        "abi": {
            "info_register": "eax",
            "path_register": "edx",
            "result_register": "eax",
            "zeroed_registers": ["eax", "ecx", "edx"],
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            "stack_frame_bytes": 60,
            "return_bytes": 4,
        },
        "path_info": {
            "size": 20,
            "fields": {
                "prefix_end": 0,
                "base_sep_begin": 4,
                "base_sep_end": 8,
                "term_sep_begin": 12,
                "path_end": 16,
            },
            "separators": [47, 92],
            "drive_letters_ascii_only": True,
            "unc_components": 2,
        },
        "services": {
            "are_file_apis_ansi": {
                "dll": "kernel32.dll",
                "symbol": "AreFileApisANSI",
                "argument_count": 0,
                "code_page_if_true": 0,
                "code_page_if_false": 1,
                "instruction_rva": service_sites["AreFileApisANSI"][0][0],
                "return_rva": service_sites["AreFileApisANSI"][0][1],
            },
            "is_dbcs_lead_byte": {
                "dll": "kernel32.dll",
                "symbol": "IsDBCSLeadByteEx",
                "argument_count": 2,
                "instruction_rvas": [value[0] for value in service_sites["IsDBCSLeadByteEx"]],
                "return_rvas": [value[1] for value in service_sites["IsDBCSLeadByteEx"]],
                "stdcall_cleanup_bytes": 8,
            },
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("windows_path_info_scan_contract"),
        "Windows path-info scan contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("Windows path-info scan contract is stale")
    return contract


def _adapter_parts(
    *, root: Path, backend_workspace: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter = root / str(files["machine_adapter_source"])
    symbols = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter.read_text(encoding="ascii"),
    )
    if len(symbols) != 1:
        raise StageAInputError("Windows path scanner adapter does not have one entry")
    return files, adapter, symbols[0]


_HEADER = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

#define WINDOWS_PATH_INFO_MAX_BYTES UINT32_C(16)

typedef struct windows_path_info_services {
  void *context;
  uint8_t (*read_byte)(void *context, uint32_t address, uint32_t *ok);
  void (*write_pointer)(void *context, uint32_t address, uint32_t value,
                        uint32_t *ok);
  uint32_t (*are_file_apis_ansi)(void *context);
  uint32_t (*is_dbcs_lead_byte)(void *context, uint32_t code_page,
                                uint8_t value, uint32_t address,
                                uint32_t unc_scan);
  void (*begin_unc_scan)(void *context, uint32_t *ok);
} windows_path_info_services;

uint32_t scan_windows_path_info(windows_path_info_services *services,
                                uint32_t info, uint32_t path,
                                uint32_t max_path_bytes);

#endif
"""


_PORTABLE = """#include "implementation.h"

static uint32_t is_dir_sep(uint8_t value) {
  return value == UINT8_C(0x2f) || value == UINT8_C(0x5c);
}

static uint32_t is_drive_letter(uint8_t value) {
  uint8_t folded = (uint8_t)(value & UINT8_C(0xdf));
  return folded >= UINT8_C('A') && folded <= UINT8_C('Z');
}

static uint8_t read_path(windows_path_info_services *services,
                         uint32_t address, uint32_t *ok) {
  if (*ok == 0U) return 0U;
  return services->read_byte(services->context, address, ok);
}

static void store_path_info(windows_path_info_services *services,
                            uint32_t info, uint32_t offset, uint32_t value,
                            uint32_t *ok) {
  if (*ok != 0U)
    services->write_pointer(services->context, info + offset, value, ok);
}

uint32_t scan_windows_path_info(windows_path_info_services *services,
                                uint32_t info, uint32_t path,
                                uint32_t max_path_bytes) {
  uint32_t ok = 1U, pos = path, unc_components = 0U;
  uint32_t dbcs_trail = 0U, previous_separator = 0U, separator;
  uint32_t code_page, terminal_separator = 0U;
  uint8_t value, next;

  if (services == 0 || services->read_byte == 0 ||
      services->write_pointer == 0 || services->are_file_apis_ansi == 0 ||
      services->is_dbcs_lead_byte == 0 || services->begin_unc_scan == 0)
    return 1U;

  code_page = services->are_file_apis_ansi(services->context) ? 0U : 1U;
  store_path_info(services, info, 0U, 0U, &ok);
  store_path_info(services, info, 4U, 0U, &ok);
  store_path_info(services, info, 8U, 0U, &ok);
  store_path_info(services, info, 12U, 0U, &ok);
  if (ok == 0U) return 1U;

  value = read_path(services, pos, &ok);
  if (ok == 0U) return 1U;
  if (is_dir_sep(value)) {
    next = read_path(services, pos + 1U, &ok);
    if (ok == 0U) return 1U;
    if (is_dir_sep(next)) {
      pos += 2U;
      value = read_path(services, pos, &ok);
      if (ok == 0U) return 1U;
      if (value != 0U) {
        services->begin_unc_scan(services->context, &ok);
        if (ok == 0U) return 1U;
        while (value != 0U) {
          separator = 0U;
          if (dbcs_trail != 0U) {
            dbcs_trail = 0U;
          } else if (services->is_dbcs_lead_byte(
                         services->context, code_page, value, pos, 1U)) {
            dbcs_trail = 1U;
          } else {
            separator = is_dir_sep(value);
          }
          if (separator != 0U && previous_separator == 0U) {
            ++unc_components;
            if (unc_components == 2U) break;
          }
          previous_separator = separator;
          ++pos;
          if (pos - path > max_path_bytes) return 1U;
          value = read_path(services, pos, &ok);
          if (ok == 0U) return 1U;
        }
      }
      store_path_info(services, info, 0U, pos, &ok);
    }
  } else if (is_drive_letter(value)) {
    next = read_path(services, pos + 1U, &ok);
    if (ok == 0U) return 1U;
    if (next == UINT8_C(':')) {
      pos += 2U;
      store_path_info(services, info, 0U, pos, &ok);
    }
  }
  if (ok == 0U) return 1U;

  dbcs_trail = 0U;
  previous_separator = 0U;
  value = read_path(services, pos, &ok);
  if (ok == 0U) return 1U;
  while (value != 0U) {
    separator = 0U;
    if (dbcs_trail != 0U) {
      dbcs_trail = 0U;
    } else if (services->is_dbcs_lead_byte(
                   services->context, code_page, value, pos, 0U)) {
      dbcs_trail = 1U;
    } else {
      separator = is_dir_sep(value);
    }
    if (separator != 0U && previous_separator == 0U) {
      terminal_separator = pos;
      store_path_info(services, info, 12U, pos, &ok);
    }
    if (separator == 0U && previous_separator != 0U) {
      store_path_info(services, info, 4U, terminal_separator, &ok);
      store_path_info(services, info, 8U, pos, &ok);
      store_path_info(services, info, 12U, 0U, &ok);
    }
    if (ok == 0U) return 1U;
    previous_separator = separator;
    ++pos;
    if (pos - path > max_path_bytes) return 1U;
    value = read_path(services, pos, &ok);
    if (ok == 0U) return 1U;
  }
  store_path_info(services, info, 16U, pos, &ok);
  return ok == 0U;
}
"""


def _install_sources(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    entry_rva: int,
    contract: Mapping[str, Any],
) -> None:
    files, adapter_path, adapter_symbol = _adapter_parts(
        root=root, backend_workspace=backend_workspace
    )
    abi = object_value(contract["abi"], "path-scan ABI")
    services_contract = object_value(contract["services"], "path-scan services")
    ansi = object_value(services_contract["are_file_apis_ansi"], "ANSI service")
    dbcs = object_value(services_contract["is_dbcs_lead_byte"], "DBCS service")
    domain = object_value(contract["domain"], "path-scan domain")
    sync = machine_eflags_sync_lines("  ")
    context_sync = [line.replace("state->", "context->state->") for line in sync]
    dbcs_instruction_rvas = [int(value) for value in dbcs["instruction_rvas"]]
    dbcs_return_rvas = [int(value) for value in dbcs["return_rvas"]]
    adapter_lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        "typedef struct path_scan_context {",
        "  stage_b_runtime *runtime; stage_b_machine_state *state;",
        "  stage_b_call_status status; uint32_t entry_esp, call_esp, info;",
        "} path_scan_context;",
        "",
        "static uint32_t byte_parity(uint32_t value) {",
        "  value ^= value >> 4; value &= UINT32_C(0x0f);",
        "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
        "}",
        "",
        "static void subtraction_flags(stage_b_machine_state *state, uint32_t left, uint32_t right, uint32_t result) {",
        "  state->cf = left < right;",
        "  state->of = (((left ^ right) & (left ^ result)) >> 31) & UINT32_C(1);",
        "  state->pf = byte_parity(result); state->sf = result >> 31; state->zf = result == 0U;",
        "}",
        "",
        "static uint32_t ranges_overlap(uint32_t first, uint32_t first_size, uint32_t second, uint32_t second_size) {",
        "  return first < second + second_size && second < first + first_size;",
        "}",
        "",
        "static uint8_t read_path_byte(void *opaque, uint32_t address, uint32_t *ok) {",
        "  path_scan_context *context = (path_scan_context *)opaque; uint32_t fault = 0U;",
        "  uint32_t value = context->runtime->read(context->runtime->context, address, 1U, &fault);",
        "  *ok = fault == 0U; return (uint8_t)value;",
        "}",
        "",
        "static void write_path_pointer(void *opaque, uint32_t address, uint32_t value, uint32_t *ok) {",
        "  path_scan_context *context = (path_scan_context *)opaque; uint32_t fault = 0U;",
        "  context->runtime->write(context->runtime->context, address, 4U, value, &fault);",
        "  *ok = fault == 0U;",
        "}",
        "",
        "static uint32_t invoke_ansi(void *opaque) {",
        "  path_scan_context *context = (path_scan_context *)opaque;",
        "  stage_b_machine_state output; stage_b_call_event event = {0};",
        "  if (context->status != STAGE_B_CALL_OK) return 0U;",
        "  event.kind = STAGE_B_CALL_EXTERNAL_IMPORT;",
        f"  event.instruction_rva = UINT32_C(0x{int(ansi['instruction_rva']):08x});",
        f"  event.return_rva = UINT32_C(0x{int(ansi['return_rva']):08x});",
        f'  event.dll = "{ansi["dll"]}"; event.symbol = "{ansi["symbol"]}";',
        *context_sync,
        "  output = *context->state;",
        "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
        "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
        "  return output.eax;",
        "}",
        "",
        "static uint32_t invoke_dbcs(void *opaque, uint32_t code_page, uint8_t value, uint32_t address, uint32_t unc_scan) {",
        "  path_scan_context *context = (path_scan_context *)opaque;",
        "  stage_b_machine_state output; stage_b_call_event event = {0};",
        "  stage_b_stack_input stack_inputs[2]; uint32_t arguments[2], fault = 0U;",
        "  uint32_t site = unc_scan != 0U ? 1U : 0U;",
        "  if (context->status != STAGE_B_CALL_OK) return 0U;",
        "  context->state->eax = value; context->state->edi = code_page;",
        "  context->state->ebx = address; context->state->esp = context->call_esp;",
        "  context->runtime->write(context->runtime->context, context->call_esp + 4U, 4U, value, &fault);",
        "  context->runtime->write(context->runtime->context, context->call_esp, 4U, code_page, &fault);",
        "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return 0U; }",
        "  arguments[0] = code_page; arguments[1] = value;",
        "  stack_inputs[0] = (stage_b_stack_input){ 0U, 4U, code_page };",
        "  stack_inputs[1] = (stage_b_stack_input){ 4U, 4U, value };",
        "  event.kind = STAGE_B_CALL_EXTERNAL_IMPORT;",
        f"  event.instruction_rva = site ? UINT32_C(0x{dbcs_instruction_rvas[1]:08x}) : UINT32_C(0x{dbcs_instruction_rvas[0]:08x});",
        f"  event.return_rva = site ? UINT32_C(0x{dbcs_return_rvas[1]:08x}) : UINT32_C(0x{dbcs_return_rvas[0]:08x});",
        f'  event.dll = "{dbcs["dll"]}"; event.symbol = "{dbcs["symbol"]}";',
        "  event.arguments = arguments; event.argument_count = 2U;",
        "  event.stack_inputs = stack_inputs; event.stack_input_count = 2U;",
        *context_sync,
        "  output = *context->state;",
        "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
        "  if (context->status == STAGE_B_CALL_OK) {",
        "    *context->state = output; context->state->esp -= UINT32_C(8);",
        "  }",
        "  return output.eax;",
        "}",
        "",
        "static void begin_unc_scan(void *opaque, uint32_t *ok) {",
        "  path_scan_context *context = (path_scan_context *)opaque; uint32_t fault = 0U;",
        "  context->runtime->write(context->runtime->context, context->entry_esp - UINT32_C(32), 4U, context->info, &fault);",
        "  *ok = fault == 0U;",
        "}",
        "",
        f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  stage_b_machine_state entry; path_scan_context context; windows_path_info_services services;",
        "  uint32_t info, path, path_bytes = 0U, fault = 0U, return_target, status;",
        "  uint32_t entry_df; uint8_t byte;",
        "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  entry = *state; info = state->eax; path = state->edx; entry_df = state->df;",
        f"  while (path_bytes <= UINT32_C({int(domain['max_path_bytes'])})) {{",
        "    byte = (uint8_t)rt->read(rt->context, path + path_bytes, 1U, &fault);",
        "    if (fault) return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, state->original_rva, 0U };",
        "    if (byte == 0U) break;",
        "    ++path_bytes;",
        "  }",
        f"  if (path_bytes > UINT32_C({int(domain['max_path_bytes'])}) || info > UINT32_MAX - UINT32_C(20) ||",
        "      path > UINT32_MAX - path_bytes - UINT32_C(1) || state->esp < UINT32_C(60) ||",
        "      state->esp > UINT32_MAX - UINT32_C(4) ||",
        "      ranges_overlap(info, UINT32_C(20), path, path_bytes + UINT32_C(1)) ||",
        "      ranges_overlap(info, UINT32_C(20), state->esp - UINT32_C(60), UINT32_C(64)) ||",
        "      ranges_overlap(path, path_bytes + UINT32_C(1), state->esp - UINT32_C(60), UINT32_C(64)))",
        f"    return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "  rt->write(rt->context, entry.esp - UINT32_C(4), 4U, entry.ebp, &fault);",
        "  rt->write(rt->context, entry.esp - UINT32_C(8), 4U, entry.edi, &fault);",
        "  rt->write(rt->context, entry.esp - UINT32_C(12), 4U, entry.esi, &fault);",
        "  rt->write(rt->context, entry.esp - UINT32_C(16), 4U, entry.ebx, &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  state->esi = info; state->ebx = path; state->esp = entry.esp - UINT32_C(60);",
        "  subtraction_flags(state, entry.esp - UINT32_C(16), UINT32_C(44), state->esp);",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  context = (path_scan_context){ rt, state, STAGE_B_CALL_OK, entry.esp, state->esp, info };",
        "  services = (windows_path_info_services){ &context, read_path_byte, write_path_pointer, invoke_ansi, invoke_dbcs, begin_unc_scan };",
        f"  status = scan_windows_path_info(&services, info, path, UINT32_C({int(domain['max_path_bytes'])}));",
        "  if (context.status != STAGE_B_CALL_OK)",
        "    return (stage_b_step_result){ context.status == STAGE_B_CALL_MEMORY_FAULT ? STAGE_B_MEMORY_FAULT : STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
        "  if (status != 0U)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
        "  return_target = rt->read(rt->context, entry.esp, 4U, &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  state->eax = 0U; state->ecx = 0U; state->edx = 0U;",
        "  state->ebx = entry.ebx; state->esi = entry.esi; state->edi = entry.edi; state->ebp = entry.ebp;",
        "  state->esp = entry.esp + UINT32_C(4); state->df = entry_df;",
        "  state->cf = 0U; state->of = 0U; state->pf = 1U; state->sf = 0U; state->zf = 1U;",
        *sync,
        "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
        "}",
        "",
    ]
    (root / str(files["portable_header"])).write_text(_HEADER, encoding="ascii")
    (root / str(files["portable_source"])).write_text(_PORTABLE, encoding="ascii")
    adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")


def _is_sep(value: int) -> bool:
    return value in {0x2F, 0x5C}


def _dbcs_calls(path: bytes, lead_offsets: set[int]) -> list[int]:
    calls: list[int] = []
    pos = 0
    if _is_sep(path[0]) and _is_sep(path[1]):
        pos = 2
        trail = False
        previous_sep = False
        components = 0
        while path[pos] != 0:
            sep = False
            if trail:
                trail = False
            else:
                calls.append(pos)
                if pos in lead_offsets:
                    trail = True
                else:
                    sep = _is_sep(path[pos])
            if sep and not previous_sep:
                components += 1
                if components == 2:
                    break
            previous_sep = sep
            pos += 1
    elif (
        (ord("A") <= (path[0] & 0xDF) <= ord("Z"))
        and path[1] == ord(":")
    ):
        pos = 2
    trail = False
    while path[pos] != 0:
        if trail:
            trail = False
        else:
            calls.append(pos)
            trail = pos in lead_offsets
        pos += 1
    return calls


def _install_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    cluster: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    abi = object_value(contract["abi"], "path-scan ABI")
    files = object_value(backend_workspace.get("files"), "backend files")
    probes = (
        ("empty", b"\0", set()),
        ("relative", b"usr\0", set()),
        ("root", b"/\0", set()),
        ("drive", b"C:\0", set()),
        ("drive-tree", b"C:\\usr\\lib\0", set()),
        ("unc", b"\\\\host\\share\\lib\0", set()),
        ("repeat", b"\\home\\\\dwc\\\\test\0", set()),
        ("lower-drive", b"z:src/file\0", set()),
        ("dbcs-slash-trail", bytes((0x81, 0x5C, ord("x"), 0)), {0}),
        ("unc-dbcs", bytes((0x5C, 0x5C, 0x81, 0x5C, 0x5C, ord("s"), 0)), {2}),
    )
    rows = []
    for index, (label, path_bytes, lead_offsets) in enumerate(probes):
        esp = 0x70004000 + index * 0x200
        info = 0x71000000 + index * 0x100
        path = 0x72000000 + index * 0x100
        are_ansi = index & 1
        call_esp = esp - int(abi["stack_frame_bytes"])
        calls = _dbcs_calls(path_bytes, lead_offsets)
        responses = [
            {"eax": are_ansi, "registers": {"esp": call_esp}},
            *[
                {
                    "eax": int(offset in lead_offsets),
                    "registers": {"esp": call_esp + 8},
                }
                for offset in calls
            ],
        ]
        rows.append(
            {
                "id": f"case:windows-path-info-{label}",
                "registers": {
                    "eax": info,
                    "ebx": 0x22220000 + index,
                    "ecx": 0x33330000 + index,
                    "edx": path,
                    "esi": 0x55550000 + index,
                    "edi": 0x66660000 + index,
                    "ebp": 0x77770000 + index,
                    "esp": esp,
                },
                "flags": {
                    "cf": index & 1,
                    "zf": (index >> 1) & 1,
                    "sf": (index >> 2) & 1,
                    "of": (index >> 3) & 1,
                    "pf": (index + 1) & 1,
                    "df": index & 1,
                },
                "memory": [
                    {
                        "address": esp,
                        "bytes": (0x12347000 + index).to_bytes(4, "little").hex(),
                    },
                    {"address": info, "bytes": (bytes([0xA5]) * 20).hex()},
                    {"address": path, "bytes": path_bytes.hex()},
                ],
                "external_responses": responses,
                "external_response_seed": f"windows-path-info-{label}",
            }
        )
    payload = {
        "format": "stage-b-reconstruction-cases-v1",
        "cluster_id": cluster["id"],
        "entry_unit_id": cluster["entry_unit_id"],
        "entry_rva": cluster["entry_rva"],
        "cases": rows,
    }
    payload["cases_sha256"] = _canonical_sha256(payload)
    write_json(root / str(files["cases"]), payload)


class WindowsPathInfoScanProfile:
    name = "windows_path_info_scan_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        _contract(interface_refinement)
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="scan_windows_path_info",
            contract_field="windows_path_info_scan_contract",
            contract_filename="windows-path-info-scan-contract.json",
            contract_hash_binding="windows_path_info_scan_contract_sha256",
            contract=contract,
            activation_domain=dict(object_value(contract["domain"], "path-scan domain")),
        )

    def install_sources(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        entry_rva: int,
        prepared: PreparedComponentProfile,
    ) -> None:
        _install_sources(
            root=root,
            backend_workspace=backend_workspace,
            entry_rva=entry_rva,
            contract=_contract(
                {"windows_path_info_scan_contract": prepared.contract}
            ),
        )

    def install_cases(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        cluster: Mapping[str, Any],
        prepared: PreparedComponentProfile,
    ) -> None:
        _install_cases(
            root=root,
            backend_workspace=backend_workspace,
            cluster=cluster,
            contract=_contract(
                {"windows_path_info_scan_contract": prepared.contract}
            ),
        )

    def render_cbmc_harness(self, refinement: Mapping[str, Any]) -> str:
        symbol = str(refinement.get("portable_symbol") or "")
        _contract(refinement)
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint8_t nondet_u8(void);
extern uint32_t nondet_u32(void);

typedef struct model {{
  uint8_t bytes[WINDOWS_PATH_INFO_MAX_BYTES + 1U];
  uint8_t leads[WINDOWS_PATH_INFO_MAX_BYTES + 1U];
  uint32_t words[5], calls, call_addresses[40], call_values[40];
  uint32_t ansi, unc_scans;
}} model;

static uint8_t read_byte(void *opaque, uint32_t address, uint32_t *ok) {{
  model *m = (model *)opaque; uint32_t offset = address - UINT32_C(0x1000);
  *ok = offset <= WINDOWS_PATH_INFO_MAX_BYTES;
  return *ok ? m->bytes[offset] : 0U;
}}
static void write_pointer(void *opaque, uint32_t address, uint32_t value,
                          uint32_t *ok) {{
  model *m = (model *)opaque; uint32_t offset = address - UINT32_C(0x2000);
  *ok = offset <= UINT32_C(16) && (offset & UINT32_C(3)) == 0U;
  if (*ok) m->words[offset / 4U] = value;
}}
static uint32_t ansi(void *opaque) {{ return ((model *)opaque)->ansi; }}
static uint32_t dbcs(void *opaque, uint32_t code_page, uint8_t value,
                     uint32_t address, uint32_t unc_scan) {{
  model *m = (model *)opaque; uint32_t offset = address - UINT32_C(0x1000);
  (void)unc_scan;
  __CPROVER_assert(code_page == (m->ansi ? 0U : 1U), "code page follows ANSI mode");
  __CPROVER_assert(m->calls < UINT32_C(40), "bounded DBCS trace");
  m->call_addresses[m->calls] = address; m->call_values[m->calls] = value;
  ++m->calls; return m->leads[offset] != 0U;
}}
static void begin_unc(void *opaque, uint32_t *ok) {{
  model *m = (model *)opaque; ++m->unc_scans; *ok = 1U;
}}

int main(void) {{
  model m = {{0}}; windows_path_info_services services; uint32_t length, i;
  length = nondet_u32(); __CPROVER_assume(length <= WINDOWS_PATH_INFO_MAX_BYTES);
  for (i = 0U; i <= WINDOWS_PATH_INFO_MAX_BYTES; ++i) {{
    m.bytes[i] = nondet_u8(); m.leads[i] = nondet_u8() & UINT8_C(1);
    if (i < length) __CPROVER_assume(m.bytes[i] != 0U);
  }}
  m.bytes[length] = 0U; m.ansi = nondet_u32() & UINT32_C(1);
  services = (windows_path_info_services){{
      &m, read_byte, write_pointer, ansi, dbcs, begin_unc}};
  __CPROVER_assert({symbol}(&services, UINT32_C(0x2000), UINT32_C(0x1000),
                            WINDOWS_PATH_INFO_MAX_BYTES) == 0U,
                   "bounded path scan completes");
  __CPROVER_assert(m.words[4] >= UINT32_C(0x1000) &&
                   m.words[4] <= UINT32_C(0x1000) + length,
                   "path end remains within the input");
  __CPROVER_assert(m.words[0] == 0U ||
                   (m.words[0] >= UINT32_C(0x1000) &&
                    m.words[0] <= UINT32_C(0x1000) + length),
                   "prefix end is null or within the input");
  __CPROVER_assert(m.words[1] == 0U || m.words[1] < m.words[4],
                   "base separator precedes the path end");
  __CPROVER_assert(m.words[2] == 0U || m.words[2] <= m.words[4],
                   "base begins no later than the path end");
  __CPROVER_assert(m.words[3] == 0U || m.words[3] < m.words[4],
                   "terminal separator precedes the path end");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 40

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_paths_up_to_bytes": _MAX_PATH_BYTES,
            "complete_for_all_ansi_and_dbcs_results": True,
            "requires_disjoint_nonwrapping_ranges": True,
            "outside_domain": "decline_to_canonical_machine_ir",
        }

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        return (
            activation_domain.get("kind") == "guarded_partial"
            and activation_domain.get("max_path_bytes")
            == evidence_scope.get("complete_for_all_paths_up_to_bytes")
            and activation_domain.get("requires_nul_terminator") is True
            and activation_domain.get("requires_readable_path") is True
            and activation_domain.get("requires_writable_info_record") is True
            and activation_domain.get("requires_writable_stack_frame") is True
            and activation_domain.get("requires_disjoint_path_info_stack") is True
            and activation_domain.get("requires_nonwrapping_ranges") is True
            and activation_domain.get("fallback") == "canonical_machine_ir"
            and activation_domain.get("decline_before_guest_writes") is True
            and activation_domain.get("decline_before_observable_effects") is True
            and activation_domain.get("declines_before_guest_writes_or_external_events")
            is True
            and evidence_scope.get("complete_for_all_ansi_and_dbcs_results") is True
            and evidence_scope.get("requires_disjoint_nonwrapping_ranges") is True
        )


PROFILE = WindowsPathInfoScanProfile()
