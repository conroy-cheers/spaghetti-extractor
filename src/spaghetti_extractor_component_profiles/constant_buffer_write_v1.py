"""Forward one exact immutable PE buffer to a machine output service."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

import pefile

from spaghetti_extractor.component_profile import (
    ComponentProfileContext,
    PreparedComponentProfile,
    array_value,
    object_value,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


_FORMAT = "stage-b-constant-buffer-write-contract-v1"


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
    raise StageAInputError(f"unsupported constant-buffer operand kind: {kind!r}")


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


def _read_exact_virtual_bytes(
    image: Path, *, address: int, size: int
) -> tuple[int, bytes]:
    try:
        data = image.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
    except (OSError, pefile.PEFormatError) as error:
        raise StageAInputError(f"cannot inspect constant-buffer PE image: {error}") from error
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    if address < image_base or size <= 0:
        raise StageAInputError("constant buffer has an invalid virtual span")
    rva = address - image_base
    matches = []
    for section in pe.sections:
        start = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        if start <= rva and rva + size <= start + raw_size:
            matches.append(int(section.PointerToRawData) + rva - start)
    if len(matches) != 1 or matches[0] + size > len(data):
        raise StageAInputError("constant buffer is not backed by one exact PE section")
    return image_base, data[matches[0] : matches[0] + size]


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("constant-buffer write has no component dependencies")
    if context.static_image is None:
        raise StageAInputError("constant-buffer write requires the exact static PE image")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("constant-buffer units do not match membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 2:
        raise StageAInputError("constant-buffer write requires two units")
    call_shape = _shape(ordered[0])
    if (
        len(call_shape) != 4
        or any(item[0] != "mov" for item in call_shape[:3])
        or call_shape[0][1][0] != ("m", "esp", None, 1, 8, 32)
        or call_shape[1][1][0] != ("m", "esp", None, 1, 4, 32)
        or call_shape[2][1][0] != ("m", "esp", None, 1, 0, 32)
        or any(item[1][1][0] != "i" for item in call_shape[:3])
        or call_shape[3][0] != "call"
    ):
        raise StageAInputError("constant-buffer call frame is malformed")
    count = int(call_shape[0][1][1][1])
    element_size = int(call_shape[1][1][1][1])
    address = int(call_shape[2][1][1][1])
    if count <= 0 or element_size <= 0 or count > 0xFFFFFFFF // element_size:
        raise StageAInputError("constant-buffer size is invalid")
    byte_size = count * element_size
    jump_shape = _shape(ordered[1])
    if len(jump_shape) != 1 or jump_shape[0][0] != "jmp":
        raise StageAInputError("constant-buffer continuation is not a direct jump")

    first_control = object_value(ordered[0].get("control"), "write control")
    second_control = object_value(ordered[1].get("control"), "jump control")
    if (
        first_control.get("kind") != "fallthrough"
        or first_control.get("direct_targets") != [_rva(ordered[1])]
        or second_control.get("kind") != "jump"
        or len(second_control.get("direct_targets", [])) != 1
    ):
        raise StageAInputError("constant-buffer CFG is malformed")
    continuation_rva = int(second_control["direct_targets"][0])
    events = array_value(
        object_value(ordered[0].get("semantics"), "write semantics").get(
            "external_events"
        ),
        "constant-buffer service events",
    )
    if len(events) != 1:
        raise StageAInputError("constant-buffer write requires one service")
    event = object_value(events[0], "constant-buffer service event")
    arguments = array_value(event.get("arguments"), "write arguments")
    stack_inputs = array_value(event.get("stack_inputs"), "write stack inputs")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not isinstance(event.get("symbol"), str)
        or event.get("ordinal") is not None
        or event.get("return_rva") != _rva(ordered[1])
        or len(arguments) != 4
        or [item.get("offset") for item in stack_inputs] != [0, 4, 8]
        or any(item.get("width") != 4 for item in stack_inputs)
    ):
        raise StageAInputError("constant-buffer service ABI is outside the profile")
    image_base, payload = _read_exact_virtual_bytes(
        context.static_image, address=address, size=byte_size
    )
    manifest_binary = object_value(
        context.machine_ir_manifest.get("binary"), "machine IR binary"
    )
    if manifest_binary.get("image_base") != image_base:
        raise StageAInputError("constant-buffer PE image base is stale")

    bindings = [
        {
            "unit_id": str(unit["id"]),
            "rva_start": _rva(unit),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "instruction_bytes_sha256": str(
                unit["source"]["instruction_bytes_sha256"]
            ),
            "semantic_transfer_sha256": str(
                unit["source"]["semantic_export"]["semantic_transfer_sha256"]
            ),
        }
        for unit in ordered
    ]
    core = {
        "format": _FORMAT,
        "status": "checked",
        "executes_original_binary": False,
        "profile": "constant_buffer_write_v1",
        "component": {
            "id": str(context.component["id"]),
            "sha256": str(context.component["component_sha256"]),
            "unit_ids": member_ids,
        },
        "bindings": {
            "machine_ir_sha256": context.machine_ir_sha256,
            "static_image_sha256": sha256_file(context.static_image),
            "units": bindings,
        },
        "domain": {"kind": "total"},
        "buffer": {
            "virtual_address": address,
            "rva": address - image_base,
            "element_size": element_size,
            "element_count": count,
            "byte_size": byte_size,
            "bytes_sha256": sha256(payload).hexdigest(),
        },
        "stream": {"entry_stack_offset": 12},
        "external_event": {
            "dll": str(event["dll"]),
            "symbol": str(event["symbol"]),
            "call_rva": int(ordered[0]["instructions"][-1]["rva_start"]),
            "call_unit_rva": _rva(ordered[0]),
            "return_rva": int(event["return_rva"]),
        },
        "control": {
            "jump_unit_rva": _rva(ordered[1]),
            "continuation_rva": continuation_rva,
        },
        "behavior": {
            "service_calls": 1,
            "arguments": "exact buffer, element size/count, and incoming stream",
            "control": "jump to the declared continuation",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("constant_buffer_write_contract"),
        "constant-buffer write contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("constant-buffer write contract is stale")
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
        raise StageAInputError("constant-buffer adapter does not have one entry")
    return files, adapter, matches[0]


class ConstantBufferWriteProfile:
    name = "constant_buffer_write_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return (
            {
                "semantic_expression": {"op": "reg", "name": "esp", "width": 32},
                "width": 16,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="write_constant_buffer",
            contract_field="constant_buffer_write_contract",
            contract_filename="constant-buffer-write-contract.json",
            contract_hash_binding="constant_buffer_write_contract_sha256",
            contract=contract,
            activation_domain={"kind": "total"},
        )

    def install_sources(
        self,
        *,
        root: Path,
        backend_workspace: Mapping[str, Any],
        entry_rva: int,
        prepared: PreparedComponentProfile,
    ) -> None:
        del entry_rva
        contract = prepared.contract
        buffer = object_value(contract["buffer"], "constant buffer")
        event = object_value(contract["external_event"], "write event")
        control = object_value(contract["control"], "write control")
        stream = object_value(contract["stream"], "write stream")
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct byte_output_service {
  void *context;
  uint32_t (*write)(void *context, const uint8_t *buffer,
                    uint32_t element_size, uint32_t element_count,
                    uintptr_t stream);
} byte_output_service;

uint32_t write_constant_buffer(byte_output_service *service,
                               const uint8_t *buffer,
                               uint32_t element_size,
                               uint32_t element_count,
                               uintptr_t stream);

#endif
"""
        portable = """#include "implementation.h"

uint32_t write_constant_buffer(byte_output_service *service,
                               const uint8_t *buffer,
                               uint32_t element_size,
                               uint32_t element_count,
                               uintptr_t stream) {
  return service->write(service->context, buffer, element_size,
                        element_count, stream);
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct output_context {",
            "  stage_b_runtime *runtime; stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "} output_context;",
            "",
            "static uint32_t invoke_write(void *opaque, const uint8_t *buffer,",
            "    uint32_t element_size, uint32_t element_count, uintptr_t stream) {",
            "  output_context *context = (output_context *)opaque;",
            "  stage_b_machine_state output = *context->state;",
            "  const uint32_t arguments[] = {",
            "    (uint32_t)(uintptr_t)buffer, element_size, element_count, (uint32_t)stream",
            "  };",
            "  const stage_b_stack_input stack_inputs[] = {",
            "    { 0U, 4U, (uint32_t)(uintptr_t)buffer },",
            "    { 4U, 4U, element_size }, { 8U, 4U, element_count },",
            "    { 12U, 4U, (uint32_t)stream }",
            "  };",
            "  const stage_b_call_event call = {",
            f"    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
            f'    "{event["dll"]}", "{event["symbol"]}", 0U, 0U, arguments, 4U, stack_inputs, 4U',
            "  };",
            "  uint32_t fault = 0U;",
            "  context->runtime->write(context->runtime->context, context->state->esp, 4U, arguments[0], &fault);",
            "  context->runtime->write(context->runtime->context, context->state->esp + 4U, 4U, element_size, &fault);",
            "  context->runtime->write(context->runtime->context, context->state->esp + 8U, 4U, element_count, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return 0U; }",
            f"  context->state->original_rva = UINT32_C(0x{int(event['call_unit_rva']):08x});",
            "  context->status = stage_b_invoke_call(context->runtime, &call, context->state, &output);",
            "  *context->state = output; return output.eax;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  output_context context; byte_output_service service; uint32_t fault = 0U, stream_word;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"  stream_word = rt->read(rt->context, state->esp + UINT32_C({int(stream['entry_stack_offset'])}), 4U, &fault);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  context = (output_context){ rt, state, STAGE_B_CALL_UNIMPLEMENTED };",
            "  service = (byte_output_service){ &context, invoke_write };",
            "  (void)write_constant_buffer(&service,",
            f"      (const uint8_t *)(uintptr_t)UINT32_C(0x{int(buffer['virtual_address']):08x}),",
            f"      UINT32_C({int(buffer['element_size'])}), UINT32_C({int(buffer['element_count'])}),",
            "      (uintptr_t)stream_word);",
            "  if (context.status != STAGE_B_CALL_OK) {",
            "    stage_b_control_kind kind = context.status == STAGE_B_CALL_MEMORY_FAULT",
            "        ? STAGE_B_MEMORY_FAULT : context.status == STAGE_B_CALL_DIVIDE_ERROR",
            "        ? STAGE_B_DIVIDE_ERROR : STAGE_B_EXTERNAL_FAULT;",
            "    return (stage_b_step_result){ kind, state->original_rva, 0U };",
            "  }",
            f"  state->original_rva = UINT32_C(0x{int(control['jump_unit_rva']):08x});",
            f"  return (stage_b_step_result){{ STAGE_B_JUMP, UINT32_C(0x{int(control['continuation_rva']):08x}), 0U }};",
            "}",
            "",
        ]
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
        _contract({"constant_buffer_write_contract": prepared.contract})
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        probes = (
            ("null-stream", 0, 0),
            ("stdout", 1, 1),
            ("stderr", 2, 2),
            ("small", 3, 0xFFFFFFFF),
            ("pointer-a", 0x1000, 3),
            ("pointer-b", 0x70002000, 4),
            ("high", 0xFFFFFFFF, 5),
            ("pattern-a", 0xA5A5A5A5, 0x80000000),
            ("pattern-b", 0x5A5A5A5A, 0x12345678),
            ("aligned", 0x71000000, 0x87654321),
        )
        rows = []
        esp = 0x70001000
        for index, (label, stream_word, response) in enumerate(probes):
            rows.append(
                {
                    "id": f"case:constant-buffer-write-{label}",
                    "registers": {
                        "eax": 0x01020304 + index,
                        "ebx": 0x11121314 + index,
                        "ecx": 0x21222324 + index,
                        "edx": 0x31323334 + index,
                        "esi": 0x41424344 + index,
                        "edi": 0x51525354 + index,
                        "ebp": 0x61626364 + index,
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
                        {"address": esp + 12, "bytes": int(stream_word).to_bytes(4, "little").hex()}
                    ],
                    "external_responses": [{"eax": response}],
                    "external_response_seed": f"constant-buffer-write-{label}",
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
        symbol = str(refinement.get("portable_symbol") or "")
        _contract(refinement)
        return f'''#include "implementation.h"
#include <stdint.h>

extern uint32_t nondet_u32(void);
typedef struct model {{
  uint32_t calls, size, count, response; uintptr_t buffer, stream;
}} model;
static uint32_t write_bytes(void *opaque, const uint8_t *buffer,
    uint32_t size, uint32_t count, uintptr_t stream) {{
  model *m = (model *)opaque; m->calls++; m->buffer = (uintptr_t)buffer;
  m->size = size; m->count = count; m->stream = stream; return m->response;
}}
int main(void) {{
  uintptr_t buffer = (uintptr_t)nondet_u32(), stream = (uintptr_t)nondet_u32();
  uint32_t size = nondet_u32(), count = nondet_u32();
  model m = {{ 0U, 0U, 0U, nondet_u32(), 0U, 0U }};
  byte_output_service service = {{ &m, write_bytes }};
  uint32_t actual = {symbol}(&service, (const uint8_t *)buffer, size, count, stream);
  __CPROVER_assert(m.calls == 1U, "one write call");
  __CPROVER_assert(m.buffer == buffer, "buffer forwarded");
  __CPROVER_assert(m.size == size, "element size forwarded");
  __CPROVER_assert(m.count == count, "element count forwarded");
  __CPROVER_assert(m.stream == stream, "stream forwarded");
  __CPROVER_assert(actual == m.response, "service result forwarded");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        contract = _contract(refinement)
        return {
            "complete_for_all_forwarded_values": True,
            "static_buffer_bytes_sha256": contract["buffer"]["bytes_sha256"],
            "service_calls": 1,
            "loops": 0,
        }

    def activation_scope_matches(
        self,
        *,
        activation_domain: Mapping[str, Any],
        evidence_scope: Mapping[str, Any],
    ) -> bool:
        return (
            activation_domain.get("kind") == "total"
            and evidence_scope.get("complete_for_all_forwarded_values") is True
            and isinstance(evidence_scope.get("static_buffer_bytes_sha256"), str)
            and len(str(evidence_scope["static_buffer_bytes_sha256"])) == 64
            and evidence_scope.get("service_calls") == 1
        )


PROFILE = ConstantBufferWriteProfile()
