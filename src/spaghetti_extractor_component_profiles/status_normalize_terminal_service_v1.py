"""Normalize a status word and forward it to one terminal machine service."""

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


_FORMAT = "stage-b-status-normalize-terminal-service-contract-v1"


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
    raise StageAInputError(f"unsupported status-route operand kind: {kind!r}")


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


def _i(value: int) -> tuple[Any, ...]:
    return ("i", value, 32)


def _m(base: str, displacement: int) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, 32)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("status-normalization route has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("status-normalization units do not match membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 3:
        raise StageAInputError("status-normalization route requires three units")
    binary = object_value(
        context.machine_ir_manifest.get("binary"), "machine IR binary"
    )
    image_base = binary.get("image_base")
    if not isinstance(image_base, int):
        raise StageAInputError("status-normalization route has no PE image base")
    if _shape(ordered[0]) != (
        ("test", (_r("ebp"), _r("ebp"))),
        ("jns", (_i(_rva(ordered[2]) + image_base),)),
    ):
        raise StageAInputError("status-normalization sign branch is malformed")
    if _shape(ordered[1]) != (
        ("test", (_r("ebx"), _r("ebx"))),
        ("mov", (_r("eax"), _i(2))),
        ("cmove", (_r("ebx"), _r("eax"))),
    ):
        raise StageAInputError("status-normalization zero route is malformed")
    call_shape = _shape(ordered[2])
    if (
        len(call_shape) != 2
        or call_shape[0] != ("mov", (_m("esp", 0), _r("ebx")))
        or call_shape[1][0] != "call"
    ):
        raise StageAInputError("status-normalization terminal call is malformed")

    entry_rvas = [_rva(unit) for unit in ordered]
    first = object_value(ordered[0].get("control"), "sign control")
    second = object_value(ordered[1].get("control"), "zero control")
    third = object_value(ordered[2].get("control"), "call control")
    if (
        first.get("kind") != "branch"
        or set(first.get("direct_targets", [])) != {entry_rvas[1], entry_rvas[2]}
        or second.get("kind") != "fallthrough"
        or second.get("direct_targets") != [entry_rvas[2]]
        or third.get("kind") != "fallthrough"
        or len(third.get("direct_targets", [])) != 1
    ):
        raise StageAInputError("status-normalization CFG is malformed")
    continuation_rva = int(third["direct_targets"][0])

    events = array_value(
        object_value(ordered[2].get("semantics"), "call semantics").get(
            "external_events"
        ),
        "terminal service events",
    )
    if len(events) != 1:
        raise StageAInputError("status-normalization route requires one service")
    event = object_value(events[0], "terminal service event")
    arguments = array_value(event.get("arguments"), "terminal service arguments")
    stack_inputs = array_value(event.get("stack_inputs"), "terminal stack inputs")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not isinstance(event.get("symbol"), str)
        or event.get("ordinal") is not None
        or event.get("return_rva") != continuation_rva
        or len(arguments) != 1
        or len(stack_inputs) != 1
        or stack_inputs[0].get("offset") != 0
        or stack_inputs[0].get("width") != 4
    ):
        raise StageAInputError("terminal service ABI is outside the status profile")

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
        "profile": "status_normalize_terminal_service_v1",
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
        "abi": {
            "sign_register": "ebp",
            "status_register": "ebx",
            "temporary_register": "eax",
            "default_status": 2,
            "argument_stack_offset": 0,
        },
        "external_event": {
            "dll": str(event["dll"]),
            "symbol": str(event["symbol"]),
            "call_rva": int(ordered[2]["instructions"][-1]["rva_start"]),
            "call_unit_rva": _rva(ordered[2]),
            "return_rva": continuation_rva,
        },
        "behavior": {
            "normalization": "status becomes 2 iff sign input is negative and status is zero",
            "service_calls": 1,
            "control": "fallthrough to the declared continuation if the terminal service returns",
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("status_normalize_terminal_service_contract"),
        "status-normalization contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("status-normalization contract is stale")
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
        raise StageAInputError("status-normalization adapter does not have one entry")
    return files, adapter, matches[0]


class StatusNormalizeTerminalServiceProfile:
    name = "status_normalize_terminal_service_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return (
            {
                "semantic_expression": {"op": "reg", "name": "esp", "width": 32},
                "width": 4,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="normalize_usage_status",
            contract_field="status_normalize_terminal_service_contract",
            contract_filename="status-normalize-terminal-service-contract.json",
            contract_hash_binding="status_normalize_terminal_service_contract_sha256",
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
        contract = prepared.contract
        event = object_value(contract["external_event"], "terminal service event")
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = """#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

typedef struct status_service {
  void *context;
  void (*terminate)(void *context, uint32_t status);
} status_service;

void normalize_usage_status(status_service *service,
                            int32_t sign_source,
                            uint32_t status);

#endif
"""
        portable = """#include "implementation.h"

void normalize_usage_status(status_service *service,
                            int32_t sign_source,
                            uint32_t status) {
  if (sign_source < 0 && status == 0U)
    status = 2U;
  service->terminate(service->context, status);
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct terminal_context {",
            "  stage_b_runtime *runtime;",
            "  stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "} terminal_context;",
            "",
            "static uint32_t byte_parity(uint32_t value) {",
            "  value ^= value >> 4; value &= UINT32_C(0x0f);",
            "  return (UINT32_C(0x9669) >> value) & UINT32_C(1);",
            "}",
            "",
            "static void test_flags(stage_b_machine_state *state, uint32_t value) {",
            "  state->cf = 0U; state->of = 0U; state->pf = byte_parity(value);",
            "  state->sf = value >> 31; state->zf = value == 0U;",
            "}",
            "",
            "static void invoke_terminal(void *opaque, uint32_t status) {",
            "  terminal_context *context = (terminal_context *)opaque;",
            "  stage_b_machine_state output = *context->state;",
            "  const uint32_t arguments[] = { status };",
            "  const stage_b_stack_input stack_inputs[] = { { 0U, 4U, status } };",
            "  const stage_b_call_event call = {",
            f"    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
            f'    "{event["dll"]}", "{event["symbol"]}", 0U, 0U, arguments, 1U, stack_inputs, 1U',
            "  };",
            "  uint32_t fault = 0U;",
            "  context->runtime->write(context->runtime->context, context->state->esp, 4U, status, &fault);",
            "  if (fault) { context->status = STAGE_B_CALL_MEMORY_FAULT; return; }",
            f"  context->state->original_rva = UINT32_C(0x{int(event['call_unit_rva']):08x});",
            "  context->status = stage_b_invoke_call(context->runtime, &call, context->state, &output);",
            "  *context->state = output;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  terminal_context context; status_service service;",
            "  uint32_t sign_source, initial_status;",
            "  if (rt == 0 || rt->write == 0)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  sign_source = state->ebp; initial_status = state->ebx;",
            "  test_flags(state, sign_source);",
            "  if ((sign_source >> 31) != 0U) {",
            "    test_flags(state, initial_status);",
            "    state->eax = UINT32_C(2);",
            "    if (initial_status == 0U) state->ebx = UINT32_C(2);",
            "  }",
            *machine_eflags_sync_lines("  "),
            "  context = (terminal_context){ rt, state, STAGE_B_CALL_UNIMPLEMENTED };",
            "  service = (status_service){ &context, invoke_terminal };",
            "  normalize_usage_status(&service, (int32_t)sign_source, initial_status);",
            "  if (context.status != STAGE_B_CALL_OK) {",
            "    stage_b_control_kind kind = context.status == STAGE_B_CALL_MEMORY_FAULT",
            "        ? STAGE_B_MEMORY_FAULT : context.status == STAGE_B_CALL_DIVIDE_ERROR",
            "        ? STAGE_B_DIVIDE_ERROR : STAGE_B_EXTERNAL_FAULT;",
            "    return (stage_b_step_result){ kind, state->original_rva, 0U };",
            "  }",
            f"  return (stage_b_step_result){{ STAGE_B_FALLTHROUGH, UINT32_C(0x{int(event['return_rva']):08x}), 0U }};",
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
        _contract({"status_normalize_terminal_service_contract": prepared.contract})
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        probes = (
            ("zero-positive", 0, 0, 0),
            ("one-positive", 1, 1, 1),
            ("max-positive", 0x7FFFFFFF, 0, 0xFFFFFFFF),
            ("minus-one-zero", 0xFFFFFFFF, 0, 2),
            ("minus-one-existing", 0xFFFFFFFF, 7, 3),
            ("minimum-zero", 0x80000000, 0, 4),
            ("minimum-existing", 0x80000000, 0xFFFFFFFF, 5),
            ("negative-pattern", 0xA5A5A5A5, 0, 0x80000000),
            ("positive-pattern", 0x5A5A5A5A, 0, 0x12345678),
            ("high-status", 0xFFFFFFFE, 0x80000000, 0x87654321),
        )
        rows = []
        for index, (label, sign_source, status, response) in enumerate(probes):
            rows.append(
                {
                    "id": f"case:status-normalization-{label}",
                    "registers": {
                        "eax": 0x01020304 + index,
                        "ebx": status,
                        "ecx": 0x21222324 + index,
                        "edx": 0x31323334 + index,
                        "esi": 0x41424344 + index,
                        "edi": 0x51525354 + index,
                        "ebp": sign_source,
                        "esp": 0x70001000,
                    },
                    "flags": {
                        "cf": index & 1,
                        "zf": (index >> 1) & 1,
                        "sf": (index >> 2) & 1,
                        "of": (index >> 3) & 1,
                        "pf": (index + 1) & 1,
                        "df": index & 1,
                    },
                    "memory": [],
                    "external_responses": [{"eax": response}],
                    "external_response_seed": f"status-normalization-{label}",
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
typedef struct model {{ uint32_t calls, observed; }} model;
static void terminate(void *opaque, uint32_t status) {{
  model *m = (model *)opaque; m->calls++; m->observed = status;
}}
int main(void) {{
  uint32_t sign_source = nondet_u32(), status = nondet_u32();
  uint32_t expected = ((sign_source >> 31) != 0U && status == 0U) ? 2U : status;
  model m = {{ 0U, 0U }};
  status_service service = {{ &m, terminate }};
  {symbol}(&service, (int32_t)sign_source, status);
  __CPROVER_assert(m.calls == 1U, "one terminal service call");
  __CPROVER_assert(m.observed == expected, "normalized status");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_sign_and_status_words": True,
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
            and evidence_scope.get("complete_for_all_sign_and_status_words") is True
            and evidence_scope.get("service_calls") == 1
        )


PROFILE = StatusNormalizeTerminalServiceProfile()
