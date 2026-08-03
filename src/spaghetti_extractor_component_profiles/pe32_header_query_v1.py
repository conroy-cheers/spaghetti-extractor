"""Lift exact PE32 header queries into portable scalar C functions."""

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


_FORMAT = "stage-b-pe32-header-query-contract-v1"
_DOS_MAGIC = 0x5A4D
_PE_SIGNATURE = 0x00004550
_PE32_MAGIC = 0x010B
_MAX_SECTIONS = 16


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return sha256(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _rva(unit: Mapping[str, Any]) -> int:
    return int(object_value(unit.get("source"), "unit source")["original"]["rva_start"])


def _operand(value: Any) -> tuple[Any, ...]:
    operand = object_value(value, "instruction operand")
    kind = operand.get("kind")
    if kind == "register":
        return ("r", str(operand.get("name")), int(operand.get("width_bits", 0)))
    if kind == "immediate":
        return ("i", int(operand.get("value", 0)), int(operand.get("width_bits", 0)))
    if kind == "memory":
        return (
            "m",
            operand.get("base"),
            operand.get("index"),
            int(operand.get("scale", 1)),
            int(operand.get("displacement", 0)),
            int(operand.get("width_bits", 0)),
        )
    raise StageAInputError(f"unsupported PE32 query operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        (
            str(instruction.get("mnemonic")),
            tuple(
                _operand(value)
                for value in array_value(
                    instruction.get("operands"), "instruction operands"
                )
            ),
        )
        for instruction in array_value(unit.get("instructions"), "unit instructions")
    )


def _r(name: str) -> tuple[Any, ...]:
    return ("r", name, 32)


def _i(value: int, width: int = 32) -> tuple[Any, ...]:
    return ("i", value, width)


def _m(base: str | None, displacement: int, width: int) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _derive_scalar_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("PE32 header query has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("PE32 header query units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 5:
        raise StageAInputError("PE32 header query requires five machine units")

    binary = object_value(context.machine_ir_manifest.get("binary"), "machine IR binary")
    image_base = binary.get("image_base")
    if not isinstance(image_base, int):
        raise StageAInputError("PE32 header query has no image base")
    failure_rva = _rva(ordered[2])
    validation_rva = _rva(ordered[3])
    common = (
        (
            ("xor", (_r("eax"), _r("eax"))),
            ("cmp", (_m(None, image_base, 16), _i(_DOS_MAGIC, 16))),
            ("jne", (_i(image_base + failure_rva),)),
        ),
        (
            ("mov", (_r("edx"), _m(None, image_base + 0x3C, 32))),
            ("cmp", (_m("edx", image_base, 32), _i(_PE_SIGNATURE))),
            ("je", (_i(image_base + validation_rva),)),
        ),
        (
            ("xor", (_r("edx"), _r("edx"))),
            ("ret", ()),
        ),
    )
    if tuple(_shape(unit) for unit in ordered[:3]) != common:
        raise StageAInputError("PE32 header validation prefix is malformed")

    count_success = (
        ("movzx", (_r("eax"), _m("edx", image_base + 6, 16))),
        ("xor", (_r("edx"), _r("edx"))),
        ("ret", ()),
    )
    base_validation = (
        ("cmp", (_m("edx", image_base + 24, 16), _i(_PE32_MAGIC, 16))),
        ("mov", (_r("edx"), _i(image_base))),
        ("cmove", (_r("eax"), _r("edx"))),
        ("xor", (_r("edx"), _r("edx"))),
    )
    if _shape(ordered[3]) == (
        ("cmp", (_m("edx", image_base + 24, 16), _i(_PE32_MAGIC, 16))),
        ("jne", (_i(image_base + failure_rva),)),
    ) and _shape(ordered[4]) == count_success:
        query = "section_count"
        portable_symbol = "validated_pe32_section_count"
    elif _shape(ordered[3]) == base_validation and _shape(ordered[4]) == (("ret", ()),):
        query = "image_base"
        portable_symbol = "validated_pe32_image_base"
    else:
        raise StageAInputError("PE32 header query result projection is unsupported")

    controls = [object_value(unit.get("control"), "PE32 query control") for unit in ordered]
    expected_targets = (
        {failure_rva, _rva(ordered[1])},
        {failure_rva, validation_rva},
        set(),
        ({failure_rva, _rva(ordered[4])} if query == "section_count" else {_rva(ordered[4])}),
        set(),
    )
    expected_kinds = (
        "branch",
        "branch",
        "return",
        "branch" if query == "section_count" else "fallthrough",
        "return",
    )
    if any(
        control.get("kind") != kind
        or set(control.get("direct_targets", [])) != targets
        or control.get("has_indirect_target") is not False
        for control, kind, targets in zip(
            controls, expected_kinds, expected_targets, strict=True
        )
    ):
        raise StageAInputError("PE32 header query CFG is malformed")
    if any(
        array_value(
            object_value(unit.get("semantics"), "PE32 query semantics").get(
                "external_events"
            ),
            "PE32 query events",
        )
        for unit in ordered
    ):
        raise StageAInputError("PE32 header query unexpectedly crosses a service boundary")

    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(unit["source"]["instruction_bytes_sha256"]),
            "semantic_transfer_sha256": (
                None
                if unit["source"].get("semantic_export") is None
                else str(
                    unit["source"]["semantic_export"]["semantic_transfer_sha256"]
                )
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "pe32_header_query_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
        },
        "domain": {"kind": "total"},
        "query": query,
        "portable_symbol": portable_symbol,
        "pe32": {
            "image_base": image_base,
            "dos_magic": _DOS_MAGIC,
            "pe_signature": _PE_SIGNATURE,
            "optional_header_magic": _PE32_MAGIC,
            "pe_offset_field": 0x3C,
            "section_count_offset": 6,
            "optional_header_offset": 24,
        },
        "abi": {
            "arguments": [],
            "result_register": "eax",
            "zeroed_register": "edx",
            "preserved_registers": ["ebx", "ecx", "esi", "edi", "ebp"],
            "stack_return_bytes": 4,
        },
        "behavior": {
            "invalid_header_result": 0,
            "short_circuit_reads": True,
            "final_logical_flags": {"cf": 0, "of": 0, "pf": 1, "sf": 0, "zf": 1},
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _derive_section_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("PE32 section query has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("PE32 section query units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 15:
        raise StageAInputError("PE32 section query requires fifteen machine units")
    binary = object_value(context.machine_ir_manifest.get("binary"), "machine IR binary")
    image_base = binary.get("image_base")
    if not isinstance(image_base, int):
        raise StageAInputError("PE32 section query has no image base")

    failure_rva = _rva(ordered[2])
    validation_rva = _rva(ordered[3])
    epilogue_rva = _rva(ordered[13])
    loop_rva = _rva(ordered[9])
    expected_shapes = (
        (
            ("xor", (_r("eax"), _r("eax"))),
            ("cmp", (_m(None, image_base, 16), _i(_DOS_MAGIC, 16))),
            ("jne", (_i(image_base + failure_rva),)),
        ),
        (
            ("mov", (_r("edx"), _m(None, image_base + 0x3C, 32))),
            ("cmp", (_m("edx", image_base, 32), _i(_PE_SIGNATURE))),
            ("je", (_i(image_base + validation_rva),)),
        ),
        (
            ("xor", (_r("edx"), _r("edx"))),
            ("xor", (_r("ecx"), _r("ecx"))),
            ("ret", ()),
        ),
        (
            ("cmp", (_m("edx", image_base + 24, 16), _i(_PE32_MAGIC, 16))),
            ("jne", (_i(image_base + failure_rva),)),
        ),
        (
            ("push", (_r("esi"),)),
            ("push", (_r("ebx"),)),
            ("movzx", (_r("esi"), _m("edx", image_base + 6, 16))),
            ("test", (("r", "si", 16), ("r", "si", 16))),
        ),
        (("je", (_i(image_base + epilogue_rva),)),),
        (
            ("mov", (_r("ebx"), _m("esp", 12, 32))),
            ("movzx", (_r("eax"), _m("edx", image_base + 20, 16))),
            ("xor", (_r("ecx"), _r("ecx"))),
            ("sub", (_r("ebx"), _i(image_base))),
        ),
        (
            (
                "lea",
                (
                    _r("eax"),
                    ("m", "edx", "eax", 1, image_base + 24, 32),
                ),
            ),
        ),
        (
            (
                "lea",
                (
                    _r("esi"),
                    ("m", "esi", None, 1, 0, 32),
                ),
            ),
        ),
        (
            ("mov", (_r("edx"), _m("eax", 12, 32))),
            ("cmp", (_r("ebx"), _r("edx"))),
            ("jb", (_i(image_base + _rva(ordered[11])),)),
        ),
        (
            ("add", (_r("edx"), _m("eax", 8, 32))),
            ("cmp", (_r("ebx"), _r("edx"))),
            ("jb", (_i(image_base + epilogue_rva),)),
        ),
        (
            ("add", (_r("ecx"), _i(1))),
            ("add", (_r("eax"), _i(40))),
            ("cmp", (_r("esi"), _r("ecx"))),
            ("jne", (_i(image_base + loop_rva),)),
        ),
        (("xor", (_r("eax"), _r("eax"))),),
        (
            ("pop", (_r("ebx"),)),
            ("pop", (_r("esi"),)),
            ("xor", (_r("edx"), _r("edx"))),
            ("xor", (_r("ecx"), _r("ecx"))),
        ),
        (("ret", ()),),
    )
    observed_shapes = tuple(_shape(unit) for unit in ordered)
    if observed_shapes != expected_shapes:
        raise StageAInputError("PE32 section query instruction shape is malformed")

    expected_targets = (
        {failure_rva, _rva(ordered[1])},
        {failure_rva, validation_rva},
        set(),
        {failure_rva, _rva(ordered[4])},
        {_rva(ordered[5])},
        {epilogue_rva, _rva(ordered[6])},
        {_rva(ordered[7])},
        {_rva(ordered[8])},
        {_rva(ordered[9])},
        {_rva(ordered[10]), _rva(ordered[11])},
        {epilogue_rva, _rva(ordered[11])},
        {loop_rva, _rva(ordered[12])},
        {epilogue_rva},
        {_rva(ordered[14])},
        set(),
    )
    expected_kinds = (
        "branch",
        "branch",
        "return",
        "branch",
        "fallthrough",
        "branch",
        "fallthrough",
        "fallthrough",
        "fallthrough",
        "branch",
        "branch",
        "branch",
        "fallthrough",
        "fallthrough",
        "return",
    )
    controls = [object_value(unit.get("control"), "PE32 section control") for unit in ordered]
    if any(
        control.get("kind") != kind
        or set(control.get("direct_targets", [])) != targets
        or control.get("has_indirect_target") is not False
        for control, kind, targets in zip(
            controls, expected_kinds, expected_targets, strict=True
        )
    ):
        raise StageAInputError("PE32 section query CFG is malformed")
    if any(
        array_value(
            object_value(unit.get("semantics"), "PE32 section semantics").get(
                "external_events"
            ),
            "PE32 section events",
        )
        for unit in ordered
    ):
        raise StageAInputError("PE32 section query crosses a service boundary")

    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(unit["source"]["instruction_bytes_sha256"]),
            "semantic_transfer_sha256": (
                None
                if unit["source"].get("semantic_export") is None
                else str(
                    unit["source"]["semantic_export"]["semantic_transfer_sha256"]
                )
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "pe32_header_query_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "units": bindings,
        },
        "domain": {
            "kind": "guarded_partial",
            "max_sections": _MAX_SECTIONS,
            "requires_readable_pe32_header": True,
            "requires_writable_stack_spill": True,
            "fallback": "canonical_machine_ir",
            "decline_before_guest_writes": True,
            "decline_before_observable_effects": True,
        },
        "query": "section_for_address",
        "portable_symbol": "validated_pe32_section_for_address",
        "pe32": {
            "image_base": image_base,
            "dos_magic": _DOS_MAGIC,
            "pe_signature": _PE_SIGNATURE,
            "optional_header_magic": _PE32_MAGIC,
            "pe_offset_field": 0x3C,
            "section_count_offset": 6,
            "optional_header_size_offset": 20,
            "optional_header_offset": 24,
            "section_header_size": 40,
            "section_virtual_size_offset": 8,
            "section_virtual_address_offset": 12,
        },
        "abi": {
            "arguments": [{"kind": "stack_word", "offset": 4, "name": "address"}],
            "result_register": "eax",
            "zeroed_registers": ["ecx", "edx"],
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            "stack_return_bytes": 4,
        },
        "behavior": {
            "invalid_header_result": 0,
            "first_containing_section": True,
            "unsigned_half_open_ranges": True,
            "short_circuit_reads": True,
            "final_logical_flags": {"cf": 0, "of": 0, "pf": 1, "sf": 0, "zf": 1},
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if len(context.units) == 5:
        return _derive_scalar_contract(context)
    if len(context.units) == 15:
        return _derive_section_contract(context)
    raise StageAInputError("PE32 header query has an unsupported unit count")


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("pe32_header_query_contract"), "PE32 header query contract"
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or contract.get("query")
        not in {"section_count", "image_base", "section_for_address"}
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("PE32 header query contract is stale")
    return contract


def _adapter_parts(
    *, root: Path, backend_workspace: Mapping[str, Any]
) -> tuple[Mapping[str, Any], Path, str]:
    files = object_value(backend_workspace.get("files"), "backend workspace files")
    adapter = root / str(files["machine_adapter_source"])
    matches = re.findall(
        r"stage_b_step_result\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
        adapter.read_text(encoding="ascii"),
    )
    if len(matches) != 1:
        raise StageAInputError("PE32 header query adapter does not have one entry")
    return files, adapter, matches[0]


def _portable_parts(query: str) -> tuple[str, str, str]:
    if query == "section_for_address":
        declaration = """typedef struct pe32_section_reader {
  void *context;
  uint32_t (*read_u32)(void *context, uint32_t address, uint32_t *ok);
} pe32_section_reader;
"""
        symbol = "validated_pe32_section_for_address"
        definition = """uint32_t validated_pe32_section_for_address(
    pe32_section_reader *reader, uint32_t section_table,
    uint16_t section_count, uint32_t image_base, uint32_t address,
    uint32_t *read_ok) {
  uint32_t index;
  uint32_t target_rva = address - image_base;
  *read_ok = 1U;
  for (index = 0U; index < section_count; ++index) {
    uint32_t header = section_table + index * UINT32_C(40);
    uint32_t virtual_address =
        reader->read_u32(reader->context, header + UINT32_C(12), read_ok);
    uint32_t virtual_size;
    if (*read_ok == 0U)
      return 0U;
    if (target_rva < virtual_address)
      continue;
    virtual_size =
        reader->read_u32(reader->context, header + UINT32_C(8), read_ok);
    if (*read_ok == 0U)
      return 0U;
    if (target_rva < virtual_address + virtual_size)
      return header;
  }
  return 0U;
}
"""
        return declaration, symbol, definition
    declaration = """typedef struct pe32_header_summary {
  uint16_t dos_magic;
  uint32_t pe_signature;
  uint16_t optional_header_magic;
  uint16_t section_count;
} pe32_header_summary;
"""
    if query == "section_count":
        symbol = "validated_pe32_section_count"
        definition = """uint32_t validated_pe32_section_count(pe32_header_summary header) {
  if (header.dos_magic != UINT16_C(0x5a4d) ||
      header.pe_signature != UINT32_C(0x00004550) ||
      header.optional_header_magic != UINT16_C(0x010b))
    return 0U;
  return header.section_count;
}
"""
    elif query == "image_base":
        symbol = "validated_pe32_image_base"
        definition = """uint32_t validated_pe32_image_base(pe32_header_summary header,
                                      uint32_t image_base) {
  if (header.dos_magic != UINT16_C(0x5a4d) ||
      header.pe_signature != UINT32_C(0x00004550) ||
      header.optional_header_magic != UINT16_C(0x010b))
    return 0U;
  return image_base;
}
"""
    else:
        raise StageAInputError(f"unsupported PE32 portable query: {query}")
    return declaration, symbol, definition


def _install_section_sources(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    entry_rva: int,
    contract: Mapping[str, Any],
) -> None:
    pe32 = object_value(contract["pe32"], "PE32 section constants")
    domain = object_value(contract["domain"], "PE32 section domain")
    files, adapter_path, adapter_symbol = _adapter_parts(
        root=root, backend_workspace=backend_workspace
    )
    declaration, symbol, definition = _portable_parts("section_for_address")
    prototype = f"""uint32_t {symbol}(
    pe32_section_reader *reader, uint32_t section_table,
    uint16_t section_count, uint32_t image_base, uint32_t address,
    uint32_t *read_ok);"""
    header = f"""#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

{declaration}
{prototype}

#endif
"""
    portable = f"""#include "implementation.h"

{definition}"""
    image_base = int(pe32["image_base"])
    max_sections = int(domain["max_sections"])
    adapter_lines = [
        '#include "state-machine-runtime.h"',
        '#include "implementation.h"',
        "",
        "typedef struct runtime_section_reader {",
        "  stage_b_runtime *runtime;",
        "  uint32_t fault;",
        "} runtime_section_reader;",
        "",
        "static uint32_t read_section_u32(void *opaque, uint32_t address, uint32_t *ok) {",
        "  runtime_section_reader *reader = (runtime_section_reader *)opaque;",
        "  uint32_t value = reader->runtime->read(",
        "      reader->runtime->context, address, UINT32_C(4), &reader->fault);",
        "  *ok = reader->fault == 0U;",
        "  return value;",
        "}",
        "",
        f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  runtime_section_reader runtime_reader; pe32_section_reader reader;",
        "  uint32_t fault = 0U, pe_offset, signature, optional_magic;",
        "  uint32_t section_table, address, result = 0U, read_ok = 1U, return_target;",
        "  uint32_t optional_size = 0U, section_count = 0U;",
        "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"  if ((uint16_t)rt->read(rt->context, UINT32_C(0x{image_base:08x}), 2U, &fault) == UINT16_C(0x{int(pe32['dos_magic']):04x})) {{",
        "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"    pe_offset = rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['pe_offset_field']):08x}), 4U, &fault);",
        "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"    signature = rt->read(rt->context, UINT32_C(0x{image_base:08x}) + pe_offset, 4U, &fault);",
        "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"    if (signature == UINT32_C(0x{int(pe32['pe_signature']):08x})) {{",
        f"      optional_magic = rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['optional_header_offset']):08x}) + pe_offset, 2U, &fault);",
        "      if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"      if ((uint16_t)optional_magic == UINT16_C(0x{int(pe32['optional_header_magic']):04x})) {{",
        f"        section_count = rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['section_count_offset']):08x}) + pe_offset, 2U, &fault);",
        "        if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"        if (section_count > UINT32_C({max_sections}))",
        f"          return (stage_b_step_result){{ STAGE_B_UNIMPLEMENTED, UINT32_C(0x{entry_rva:08x}), 0U }};",
        "        rt->write(rt->context, state->esp - UINT32_C(4), 4U, state->esi, &fault);",
        "        if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "        rt->write(rt->context, state->esp - UINT32_C(8), 4U, state->ebx, &fault);",
        "        if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "        if (section_count != 0U) {",
        "          address = rt->read(rt->context, state->esp + UINT32_C(4), 4U, &fault);",
        "          if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"          optional_size = rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['optional_header_size_offset']):08x}) + pe_offset, 2U, &fault);",
        "          if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"          section_table = UINT32_C(0x{image_base + int(pe32['optional_header_offset']):08x}) + pe_offset + optional_size;",
        "          runtime_reader = (runtime_section_reader){ rt, 0U };",
        "          reader = (pe32_section_reader){ &runtime_reader, read_section_u32 };",
        f"          result = {symbol}(&reader, section_table, (uint16_t)section_count,",
        f"              UINT32_C(0x{image_base:08x}), address, &read_ok);",
        "          if (read_ok == 0U || runtime_reader.fault != 0U)",
        "            return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "        }",
        "      }",
        "    }",
        "  } else if (fault) {",
        "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        "  }",
        "  return_target = rt->read(rt->context, state->esp, 4U, &fault);",
        "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
        "  state->eax = result; state->ecx = 0U; state->edx = 0U;",
        "  state->esp += UINT32_C(4);",
        "  state->cf = 0U; state->of = 0U; state->pf = 1U;",
        "  state->sf = 0U; state->zf = 1U;",
        *machine_eflags_sync_lines("  "),
        "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
        "}",
        "",
    ]
    (root / str(files["portable_header"])).write_text(header, encoding="ascii")
    (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
    adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")


def _install_section_cases(
    *,
    root: Path,
    backend_workspace: Mapping[str, Any],
    cluster: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    pe32 = object_value(contract["pe32"], "PE32 section constants")
    image_base = int(pe32["image_base"])
    pe_offset = 0x80
    optional_size = 224
    section_table = image_base + pe_offset + 24 + optional_size
    files = object_value(backend_workspace.get("files"), "backend files")
    probes = (
        ("first-start", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x200), (0x2000, 0x300)), image_base + 0x1000),
        ("first-interior", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x200), (0x2000, 0x300)), image_base + 0x11FF),
        ("second", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x200), (0x2000, 0x300)), image_base + 0x2100),
        ("half-open-end", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x200),), image_base + 0x1200),
        ("below", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x200),), image_base + 0x0FFF),
        ("zero-sections", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, (), image_base + 0x1000),
        ("bad-dos", 0, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x200),), image_base + 0x1000),
        ("bad-signature", _DOS_MAGIC, 0, _PE32_MAGIC, ((0x1000, 0x200),), image_base + 0x1000),
        ("bad-optional", _DOS_MAGIC, _PE_SIGNATURE, 0x020B, ((0x1000, 0x200),), image_base + 0x1000),
        ("overlap-first", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, ((0x1000, 0x400), (0x1100, 0x400)), image_base + 0x1180),
    )
    rows = []
    for index, (label, dos, signature, optional, sections, address) in enumerate(probes):
        esp = 0x70002000 + index * 0x100
        memory = [
            {"address": esp, "bytes": (0x12346000 + index).to_bytes(4, "little").hex()},
            {"address": esp + 4, "bytes": int(address).to_bytes(4, "little").hex()},
            {"address": image_base, "bytes": int(dos).to_bytes(2, "little").hex()},
            {"address": image_base + 0x3C, "bytes": pe_offset.to_bytes(4, "little").hex()},
            {"address": image_base + pe_offset, "bytes": int(signature).to_bytes(4, "little").hex()},
            {"address": image_base + pe_offset + 6, "bytes": len(sections).to_bytes(2, "little").hex()},
            {"address": image_base + pe_offset + 20, "bytes": optional_size.to_bytes(2, "little").hex()},
            {"address": image_base + pe_offset + 24, "bytes": int(optional).to_bytes(2, "little").hex()},
        ]
        for section_index, (virtual_address, virtual_size) in enumerate(sections):
            header = section_table + section_index * 40
            memory.extend(
                [
                    {"address": header + 8, "bytes": int(virtual_size).to_bytes(4, "little").hex()},
                    {"address": header + 12, "bytes": int(virtual_address).to_bytes(4, "little").hex()},
                ]
            )
        rows.append(
            {
                "id": f"case:pe32-section-query-{label}",
                "registers": {
                    "eax": 0x11110000 + index,
                    "ebx": 0x22220000 + index,
                    "ecx": 0x33330000 + index,
                    "edx": 0x44440000 + index,
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
                "memory": memory,
                "external_response_seed": f"pe32-section-query-{label}",
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


class Pe32HeaderQueryProfile:
    name = "pe32_header_query_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return ()

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol=str(contract["portable_symbol"]),
            contract_field="pe32_header_query_contract",
            contract_filename="pe32-header-query-contract.json",
            contract_hash_binding="pe32_header_query_contract_sha256",
            contract=contract,
            activation_domain=dict(object_value(contract["domain"], "PE32 query domain")),
        )

    def install_sources(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        entry_rva: int,
        prepared: PreparedComponentProfile,
    ) -> None:
        contract = _contract({"pe32_header_query_contract": prepared.contract})
        pe32 = object_value(contract["pe32"], "PE32 constants")
        query = str(contract["query"])
        if query == "section_for_address":
            _install_section_sources(
                root=root,
                backend_workspace=backend_workspace,
                entry_rva=entry_rva,
                contract=contract,
            )
            return
        declaration, symbol, definition = _portable_parts(query)
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        image_base = int(pe32["image_base"])
        arguments = (
            "summary"
            if query == "section_count"
            else f"summary, UINT32_C(0x{image_base:08x})"
        )
        prototype = (
            f"uint32_t {symbol}(pe32_header_summary header);"
            if query == "section_count"
            else f"uint32_t {symbol}(pe32_header_summary header, uint32_t image_base);"
        )
        header = f"""#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

{declaration}
{prototype}

#endif
"""
        portable = f"""#include "implementation.h"

{definition}"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  pe32_header_summary summary = {0};",
            "  uint32_t fault = 0U, pe_offset = 0U, result = 0U, return_target;",
            "  if (rt == 0 || rt->read == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"  summary.dos_magic = (uint16_t)rt->read(rt->context, UINT32_C(0x{image_base:08x}), 2U, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"  if (summary.dos_magic == UINT16_C(0x{int(pe32['dos_magic']):04x})) {{",
            f"    pe_offset = rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['pe_offset_field']):08x}), 4U, &fault);",
            "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"    summary.pe_signature = rt->read(rt->context, UINT32_C(0x{image_base:08x}) + pe_offset, 4U, &fault);",
            "    if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"    if (summary.pe_signature == UINT32_C(0x{int(pe32['pe_signature']):08x})) {{",
            f"      summary.optional_header_magic = (uint16_t)rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['optional_header_offset']):08x}) + pe_offset, 2U, &fault);",
            "      if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
        ]
        if query == "section_count":
            adapter_lines.extend(
                [
                    f"      if (summary.optional_header_magic == UINT16_C(0x{int(pe32['optional_header_magic']):04x})) {{",
                    f"        summary.section_count = (uint16_t)rt->read(rt->context, UINT32_C(0x{image_base + int(pe32['section_count_offset']):08x}) + pe_offset, 2U, &fault);",
                    "        if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
                    "      }",
                ]
            )
        adapter_lines.extend(
            [
                "    }",
                "  }",
                f"  result = {symbol}({arguments});",
                "  return_target = rt->read(rt->context, state->esp, 4U, &fault);",
                "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
                f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
                "  state->eax = result; state->edx = 0U; state->esp += UINT32_C(4);",
                "  state->cf = 0U; state->of = 0U; state->pf = 1U;",
                "  state->sf = 0U; state->zf = 1U;",
                *machine_eflags_sync_lines("  "),
                "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
                "}",
                "",
            ]
        )
        (root / str(files["portable_header"])).write_text(header, encoding="ascii")
        (root / str(files["portable_source"])).write_text(portable, encoding="ascii")
        adapter_path.write_text("\n".join(adapter_lines), encoding="ascii")

    def install_cases(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        cluster: Mapping[str, Any],
        prepared: PreparedComponentProfile,
    ) -> None:
        contract = _contract({"pe32_header_query_contract": prepared.contract})
        if contract["query"] == "section_for_address":
            _install_section_cases(
                root=root,
                backend_workspace=backend_workspace,
                cluster=cluster,
                contract=contract,
            )
            return
        pe32 = object_value(contract["pe32"], "PE32 constants")
        image_base = int(pe32["image_base"])
        files = object_value(backend_workspace.get("files"), "backend files")
        probes = (
            ("valid-one", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, 1, 0x80),
            ("valid-zero", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, 0, 0x100),
            ("valid-max", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, 0xFFFF, 0x200),
            ("bad-dos-zero", 0, _PE_SIGNATURE, _PE32_MAGIC, 3, 0x80),
            ("bad-dos-near", _DOS_MAGIC ^ 1, _PE_SIGNATURE, _PE32_MAGIC, 4, 0x90),
            ("bad-signature-zero", _DOS_MAGIC, 0, _PE32_MAGIC, 5, 0xA0),
            ("bad-signature-near", _DOS_MAGIC, _PE_SIGNATURE ^ 1, _PE32_MAGIC, 6, 0xB0),
            ("pe32-plus", _DOS_MAGIC, _PE_SIGNATURE, 0x020B, 7, 0xC0),
            ("bad-optional-zero", _DOS_MAGIC, _PE_SIGNATURE, 0, 8, 0xD0),
            ("wrapped-offset", _DOS_MAGIC, _PE_SIGNATURE, _PE32_MAGIC, 9, 0x1000),
        )
        rows = []
        for index, (label, dos, signature, optional, count, pe_offset) in enumerate(probes):
            esp = 0x70001000 + index * 0x100
            rows.append(
                {
                    "id": f"case:pe32-header-query-{label}",
                    "registers": {
                        "eax": 0x11110000 + index,
                        "ebx": 0x22220000 + index,
                        "ecx": 0x33330000 + index,
                        "edx": 0x44440000 + index,
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
                        {"address": esp, "bytes": (0x12345000 + index).to_bytes(4, "little").hex()},
                        {"address": image_base, "bytes": int(dos).to_bytes(2, "little").hex()},
                        {"address": image_base + 0x3C, "bytes": int(pe_offset).to_bytes(4, "little").hex()},
                        {"address": image_base + pe_offset, "bytes": int(signature).to_bytes(4, "little").hex()},
                        {"address": image_base + pe_offset + 6, "bytes": int(count).to_bytes(2, "little").hex()},
                        {"address": image_base + pe_offset + 24, "bytes": int(optional).to_bytes(2, "little").hex()},
                    ],
                    "external_response_seed": f"pe32-header-query-{label}",
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

    def render_cbmc_harness(self, refinement: Mapping[str, Any]) -> str:
        contract = _contract(refinement)
        query = str(contract["query"])
        symbol = str(refinement.get("portable_symbol") or "")
        if query == "section_for_address":
            return f'''#include "implementation.h"
#include <stdint.h>

extern uint16_t nondet_u16(void);
extern uint32_t nondet_u32(void);
typedef struct model {{
  uint32_t table;
  uint32_t virtual_address[{_MAX_SECTIONS}];
  uint32_t virtual_size[{_MAX_SECTIONS}];
}} model;
static uint32_t read_u32(void *opaque, uint32_t address, uint32_t *ok) {{
  model *memory = (model *)opaque;
  uint32_t offset = address - memory->table;
  uint32_t index = offset / UINT32_C(40);
  uint32_t field = offset % UINT32_C(40);
  if (index >= UINT32_C({_MAX_SECTIONS}) ||
      (field != UINT32_C(8) && field != UINT32_C(12))) {{
    *ok = 0U;
    return 0U;
  }}
  *ok = 1U;
  return field == UINT32_C(8) ? memory->virtual_size[index]
                              : memory->virtual_address[index];
}}
int main(void) {{
  model memory;
  pe32_section_reader reader = {{ &memory, read_u32 }};
  uint32_t image_base = nondet_u32(), address = nondet_u32();
  uint16_t count = nondet_u16();
  uint32_t index, expected = 0U, result, read_ok = 0U;
  memory.table = nondet_u32();
  __CPROVER_assume(count <= UINT16_C({_MAX_SECTIONS}));
  for (index = 0U; index < UINT32_C({_MAX_SECTIONS}); ++index) {{
    memory.virtual_address[index] = nondet_u32();
    memory.virtual_size[index] = nondet_u32();
  }}
  for (index = 0U; index < count; ++index) {{
    uint32_t target = address - image_base;
    uint32_t start = memory.virtual_address[index];
    if (target >= start && target < start + memory.virtual_size[index]) {{
      expected = memory.table + index * UINT32_C(40);
      break;
    }}
  }}
  result = {symbol}(&reader, memory.table, count, image_base, address, &read_ok);
  __CPROVER_assert(read_ok == 1U, "bounded section table is readable");
  __CPROVER_assert(result == expected, "first containing PE32 section");
  return 0;
}}
'''
        call = f"{symbol}(header)" if query == "section_count" else f"{symbol}(header, image_base)"
        expected = "header.section_count" if query == "section_count" else "image_base"
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint16_t nondet_u16(void);
extern uint32_t nondet_u32(void);
int main(void) {{
  pe32_header_summary header;
  uint32_t image_base = nondet_u32(), result, expected;
  header.dos_magic = nondet_u16();
  header.pe_signature = nondet_u32();
  header.optional_header_magic = nondet_u16();
  header.section_count = nondet_u16();
  expected = header.dos_magic == UINT16_C(0x5a4d) &&
             header.pe_signature == UINT32_C(0x00004550) &&
             header.optional_header_magic == UINT16_C(0x010b)
      ? {expected} : 0U;
  result = {call};
  __CPROVER_assert(result == expected, "validated PE32 header query");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        contract = _contract(refinement)
        return _MAX_SECTIONS + 1 if contract["query"] == "section_for_address" else 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        contract = _contract(refinement)
        if contract["query"] == "section_for_address":
            return {
                "complete_for_all_bounded_pe32_section_tables": True,
                "query": contract["query"],
                "max_sections": _MAX_SECTIONS,
                "loops": 1,
                "outside_domain": "decline_to_canonical_machine_ir",
                "requires_readable_pe32_header": True,
                "requires_writable_stack_spill": True,
            }
        return {
            "complete_for_all_pe32_header_scalar_values": True,
            "query": contract["query"],
            "loops": 0,
        }

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        if evidence_scope.get("query") == "section_for_address":
            return (
                activation_domain.get("kind") == "guarded_partial"
                and activation_domain.get("max_sections") == _MAX_SECTIONS
                and activation_domain.get("requires_readable_pe32_header") is True
                and activation_domain.get("requires_writable_stack_spill") is True
                and activation_domain.get("fallback") == "canonical_machine_ir"
                and activation_domain.get("decline_before_guest_writes") is True
                and activation_domain.get("decline_before_observable_effects") is True
                and evidence_scope.get(
                    "complete_for_all_bounded_pe32_section_tables"
                )
                is True
                and evidence_scope.get("max_sections") == _MAX_SECTIONS
                and evidence_scope.get("requires_readable_pe32_header") is True
                and evidence_scope.get("requires_writable_stack_spill") is True
            )
        return (
            activation_domain.get("kind") == "total"
            and evidence_scope.get("complete_for_all_pe32_header_scalar_values") is True
            and evidence_scope.get("query") in {"section_count", "image_base"}
        )


PROFILE = Pe32HeaderQueryProfile()
