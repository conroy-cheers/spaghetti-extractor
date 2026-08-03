"""Portable classification of a byte-prefixed token with one unary service."""

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


_FORMAT = "stage-b-prefixed-unary-byte-predicate-contract-v1"


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
    raise StageAInputError(f"unsupported prefixed-predicate operand kind: {kind!r}")


def _shape(unit: Mapping[str, Any]) -> tuple[Any, ...]:
    result = []
    for instruction in array_value(unit.get("instructions"), "unit instructions"):
        mnemonic = str(instruction.get("mnemonic"))
        operands = tuple(
            _operand(value)
            for value in array_value(
                instruction.get("operands"), "instruction operands"
            )
        )
        if mnemonic in {"je", "jne"} and len(operands) == 1:
            operands = (("i", 0, 0),)
        result.append((mnemonic, operands))
    return tuple(result)


def _r(name: str, width: int = 32) -> tuple[Any, ...]:
    return ("r", name, width)


def _i(value: int, width: int = 32) -> tuple[Any, ...]:
    return ("i", value, width)


def _m(base: str | None, displacement: int, width: int) -> tuple[Any, ...]:
    return ("m", base, None, 1, displacement, width)


def _derive_contract(context: ComponentProfileContext) -> dict[str, Any]:
    if context.component_dependencies:
        raise StageAInputError("prefixed unary predicate has no component dependencies")
    member_ids = [
        str(value) for value in context.component["membership"]["resolved_unit_ids"]
    ]
    by_id = {str(unit.get("id")): unit for unit in context.units}
    if len(by_id) != len(context.units) or set(by_id) != set(member_ids):
        raise StageAInputError("prefixed-predicate units do not match exact membership")
    ordered = sorted(context.units, key=_rva)
    if len(ordered) != 7:
        raise StageAInputError("prefixed unary predicate requires seven machine units")

    first_shape = _shape(ordered[0])
    branch_shape = _shape(ordered[2])
    if (
        len(first_shape) != 2
        or first_shape[0][0] != "cmp"
        or first_shape[0][1][0] != _m("eax", 0, 8)
        or first_shape[0][1][1][0] != "i"
        or first_shape[1] != ("je", (_i(0, 0),))
    ):
        raise StageAInputError("prefixed-predicate entry is not a byte-prefix branch")
    prefix_byte = int(first_shape[0][1][1][1]) & 0xFF
    if (
        len(branch_shape) != 4
        or branch_shape[0] != ("movzx", (_r("edx"), _m("eax", 1, 8)))
        or branch_shape[1] != ("mov", (_r("eax"), _i(1)))
        or branch_shape[2][0] != "cmp"
        or branch_shape[2][1][0] != _r("dl", 8)
        or branch_shape[2][1][1][0] != "i"
        or branch_shape[3] != ("je", (_i(0, 0),))
    ):
        raise StageAInputError("prefixed-predicate second-byte branch is malformed")
    accepted_byte = int(branch_shape[2][1][1][1]) & 0xFF

    frame_shape = _shape(ordered[3])
    if (
        len(frame_shape) != 3
        or frame_shape[0][0] != "sub"
        or frame_shape[0][1][0] != _r("esp")
        or frame_shape[0][1][1][0] != "i"
        or frame_shape[1] != ("mov", (_m("esp", 0, 32), _r("edx")))
        or frame_shape[2][0] != "call"
    ):
        raise StageAInputError("prefixed-predicate external-call frame is malformed")
    frame_bytes = int(frame_shape[0][1][1][1])
    if frame_bytes < 4 or frame_bytes % 4 != 0:
        raise StageAInputError("prefixed-predicate frame is not word aligned")

    expected = (
        None,
        (
            ("xor", (_r("eax"), _r("eax"))),
            ("xor", (_r("edx"), _r("edx"))),
            ("ret", ()),
        ),
        None,
        None,
        (
            ("test", (_r("eax"), _r("eax"))),
            ("setne", (_r("al", 8),)),
            ("add", (_r("esp"), _i(frame_bytes))),
            ("movzx", (_r("eax"), _r("al", 8))),
        ),
        (("xor", (_r("edx"), _r("edx"))), ("ret", ())),
        (("xor", (_r("edx"), _r("edx"))), ("ret", ())),
    )
    for index, shape in enumerate(expected):
        if shape is not None and _shape(ordered[index]) != shape:
            raise StageAInputError(
                f"prefixed-predicate unit {index} has an unexpected instruction shape"
            )

    starts = [_rva(unit) for unit in ordered]
    controls = (
        ("branch", [starts[1], starts[2]]),
        ("return", []),
        ("branch", [starts[3], starts[6]]),
        ("fallthrough", [starts[4]]),
        ("fallthrough", [starts[5]]),
        ("return", []),
        ("return", []),
    )
    for unit, (kind, targets) in zip(ordered, controls, strict=True):
        control = object_value(unit.get("control"), "prefixed-predicate control")
        if control.get("kind") != kind or set(control.get("direct_targets", [])) != set(
            targets
        ):
            raise StageAInputError(
                f"prefixed-predicate CFG mismatch at RVA 0x{_rva(unit):x}"
            )

    events = array_value(
        object_value(ordered[3].get("semantics"), "call semantics").get(
            "external_events"
        ),
        "prefixed-predicate events",
    )
    if len(events) != 1:
        raise StageAInputError("prefixed-predicate call must emit one external event")
    event = object_value(events[0], "prefixed-predicate event")
    stack_inputs = array_value(event.get("stack_inputs"), "predicate stack inputs")
    if (
        event.get("kind") != "external_call"
        or not isinstance(event.get("dll"), str)
        or not event.get("dll")
        or not isinstance(event.get("symbol"), str)
        or not event.get("symbol")
        or event.get("ordinal") is not None
        or event.get("return_rva") != starts[4]
        or event.get("arguments") != []
        or len(stack_inputs) != 1
        or stack_inputs[0].get("offset") != 0
        or stack_inputs[0].get("width") != 4
    ):
        raise StageAInputError("prefixed-predicate event is outside the unary profile")

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
        "profile": "prefixed_unary_byte_predicate_v1",
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
            "kind": "total",
            "requires": "two readable bytes and the declared unary service",
        },
        "bytes": {"required_prefix": prefix_byte, "accepted_second": accepted_byte},
        "external_event": {
            "dll": str(event["dll"]),
            "symbol": str(event["symbol"]),
            "call_rva": int(ordered[3]["instructions"][-1]["rva_start"]),
            "return_rva": starts[4],
        },
        "abi": {"token_register": "eax", "frame_bytes": frame_bytes},
        "behavior": {
            "not_prefixed": 0,
            "accepted_second_byte": 1,
            "otherwise": "one exactly when the unary service result is nonzero",
        },
        "machine_projection": {
            "eax": "classification result",
            "edx": 0,
            "esp_delta": 4,
            "other_registers": "preserved on short paths; external response on service path",
            "flags": {"cf": 0, "of": 0, "pf": 1, "sf": 0, "zf": 1},
        },
    }
    return {**core, "contract_sha256": _canonical_sha256(core)}


def _contract(refinement: Mapping[str, Any]) -> Mapping[str, Any]:
    contract = object_value(
        refinement.get("prefixed_unary_byte_predicate_contract"),
        "prefixed unary byte-predicate contract",
    )
    core = dict(contract)
    expected = core.pop("contract_sha256", None)
    if (
        contract.get("format") != _FORMAT
        or contract.get("status") != "checked"
        or contract.get("executes_original_binary") is not False
        or expected != _canonical_sha256(core)
    ):
        raise StageAInputError("prefixed unary byte-predicate contract is stale")
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
        raise StageAInputError("prefixed-predicate adapter does not have one entry")
    return files, adapter, matches[0]


class PrefixedUnaryBytePredicateProfile:
    name = "prefixed_unary_byte_predicate_v1"

    def observable_memory(
        self, interface_refinement: Mapping[str, Any]
    ) -> Sequence[Mapping[str, Any]]:
        del interface_refinement
        return (
            {
                "semantic_expression": {"op": "reg", "name": "eax", "width": 32},
                "width": 2,
                "access": "read",
            },
            {
                "semantic_expression": {
                    "op": "sub32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 28, "width": 32},
                    ],
                },
                "width": 4,
                "access": "read_write",
            },
        )

    def prepare(self, context: ComponentProfileContext) -> PreparedComponentProfile:
        contract = _derive_contract(context)
        return PreparedComponentProfile(
            portable_symbol="classify_prefixed_token",
            contract_field="prefixed_unary_byte_predicate_contract",
            contract_filename="prefixed-unary-byte-predicate-contract.json",
            contract_hash_binding="prefixed_unary_byte_predicate_contract_sha256",
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
        prefix = int(contract["bytes"]["required_prefix"])
        accepted = int(contract["bytes"]["accepted_second"])
        frame_bytes = int(contract["abi"]["frame_bytes"])
        event = object_value(contract["external_event"], "predicate event")
        files, adapter_path, adapter_symbol = _adapter_parts(
            root=root, backend_workspace=backend_workspace
        )
        header = f"""#ifndef SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H
#define SPAGHETTI_RECONSTRUCTED_IMPLEMENTATION_H

#include <stdint.h>

#define PREFIXED_TOKEN_REQUIRED_BYTE UINT8_C(0x{prefix:02x})
#define PREFIXED_TOKEN_ACCEPTED_BYTE UINT8_C(0x{accepted:02x})

typedef struct prefixed_token_services {{
  void *context;
  uint8_t (*load_byte)(void *context, uint32_t address);
  int32_t (*test_byte)(void *context, uint32_t value);
}} prefixed_token_services;

int classify_prefixed_token(prefixed_token_services *services, uint32_t token);

#endif
"""
        portable = """#include "implementation.h"

int classify_prefixed_token(prefixed_token_services *services, uint32_t token) {
  uint8_t second;
  if (services->load_byte(services->context, token) !=
      PREFIXED_TOKEN_REQUIRED_BYTE)
    return 0;
  second = services->load_byte(services->context, token + UINT32_C(1));
  if (second == PREFIXED_TOKEN_ACCEPTED_BYTE)
    return 1;
  return services->test_byte(services->context, second) != 0;
}
"""
        adapter_lines = [
            '#include "state-machine-runtime.h"',
            '#include "implementation.h"',
            "",
            "typedef struct prefixed_token_context {",
            "  stage_b_runtime *runtime;",
            "  stage_b_machine_state *state;",
            "  stage_b_call_status status;",
            "  uint32_t memory_fault;",
            "  uint32_t service_called;",
            "} prefixed_token_context;",
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
            "static uint8_t load_byte(void *opaque, uint32_t address) {",
            "  prefixed_token_context *context = (prefixed_token_context *)opaque;",
            "  uint32_t fault = 0U;",
            "  uint32_t value = context->runtime->read(context->runtime->context, address, 1U, &fault);",
            "  if (fault) context->memory_fault = 1U;",
            "  return (uint8_t)value;",
            "}",
            "",
            "static int32_t test_byte(void *opaque, uint32_t value) {",
            "  prefixed_token_context *context = (prefixed_token_context *)opaque;",
            "  stage_b_machine_state output; uint32_t fault = 0U;",
            f"  uint32_t frame_esp = context->state->esp - UINT32_C({frame_bytes});",
            "  const stage_b_stack_input stack_inputs[] = { { 0U, 4U, value } };",
            "  const stage_b_call_event event = {",
            f"    STAGE_B_CALL_EXTERNAL_IMPORT, UINT32_C(0x{int(event['call_rva']):08x}), 0U, 0U, UINT32_C(0x{int(event['return_rva']):08x}),",
            f'    "{event["dll"]}", "{event["symbol"]}", 0U, 0U, 0, 0U, stack_inputs, 1U',
            "  };",
            "  context->service_called = 1U; context->state->eax = 1U; context->state->edx = value;",
            f"  subtraction_flags(context->state, context->state->esp, UINT32_C({frame_bytes}), frame_esp);",
            "  context->state->esp = frame_esp;",
            "  context->runtime->write(context->runtime->context, frame_esp, 4U, value, &fault);",
            "  if (fault) { context->memory_fault = 1U; return 0; }",
            "  output = *context->state;",
            "  context->status = stage_b_invoke_call(context->runtime, &event, context->state, &output);",
            "  if (context->status == STAGE_B_CALL_OK) *context->state = output;",
            "  return (int32_t)output.eax;",
            "}",
            "",
            f"stage_b_step_result {adapter_symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
            "  uint32_t fault = 0U, token, result, return_target;",
            "  prefixed_token_context context; prefixed_token_services services;",
            "  if (rt == 0 || rt->read == 0 || rt->write == 0) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            "  token = state->eax;",
            f"  state->original_rva = UINT32_C(0x{entry_rva:08x});",
            "  context = (prefixed_token_context){ rt, state, STAGE_B_CALL_OK, 0U, 0U };",
            "  services = (prefixed_token_services){ &context, load_byte, test_byte };",
            "  result = (uint32_t)classify_prefixed_token(&services, token);",
            "  if (context.memory_fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  if (context.status != STAGE_B_CALL_OK) return (stage_b_step_result){ STAGE_B_EXTERNAL_FAULT, state->original_rva, 0U };",
            f"  if (context.service_called) state->esp += UINT32_C({frame_bytes});",
            "  return_target = rt->read(rt->context, state->esp, 4U, &fault); state->esp += UINT32_C(4);",
            "  if (fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, state->original_rva, 0U };",
            "  state->eax = result; state->edx = 0U;",
            "  state->cf = 0U; state->of = 0U; state->pf = 1U; state->sf = 0U; state->zf = 1U;",
            *machine_eflags_sync_lines("  "),
            "  return (stage_b_step_result){ STAGE_B_RETURN, 0U, return_target };",
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
        contract = prepared.contract
        files = object_value(backend_workspace.get("files"), "backend workspace files")
        prefix = int(contract["bytes"]["required_prefix"])
        accepted = int(contract["bytes"]["accepted_second"])
        esp = 0x70001000
        token = 0x70002000
        probes = (
            ("not-prefixed-zero", 0, accepted, None),
            ("not-prefixed-letter", ord("x"), ord("a"), None),
            ("accepted-second", prefix, accepted, None),
            ("predicate-zero", prefix, ord("0"), 0),
            ("predicate-one", prefix, ord("a"), 1),
            ("predicate-positive", prefix, ord("Z"), 42),
            ("predicate-negative", prefix, 0x80, 0xFFFFFFFF),
            ("predicate-high-bit", prefix, 0xFF, 0x80000000),
            ("predicate-nul", prefix, 0, 0),
            ("accepted-with-df", prefix, accepted, None),
        )
        rows = []
        for index, (label, first, second, response) in enumerate(probes):
            rows.append(
                {
                    "id": f"case:prefixed-unary-byte-predicate-{label}",
                    "registers": {
                        "eax": token,
                        "ebx": 0x11223344 + index,
                        "ecx": 0x55667788 + index,
                        "edx": 0x89ABCDEF + index,
                        "esi": 0x12345678,
                        "edi": 0x87654321,
                        "ebp": 0x70004000,
                        "esp": esp,
                    },
                    "flags": {
                        "cf": index & 1,
                        "zf": (index >> 1) & 1,
                        "sf": (index >> 2) & 1,
                        "of": (index >> 3) & 1,
                        "pf": (index + 1) & 1,
                        "df": 1 if label == "accepted-with-df" else index & 1,
                    },
                    "memory": [
                        {"address": esp, "bytes": "78563412"},
                        {"address": token, "bytes": bytes((first, second)).hex()},
                    ],
                    "external_responses": (
                        [] if response is None else [{"eax": response}]
                    ),
                    "external_response_seed": f"prefixed-unary-{label}",
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
  uint32_t token, loads, calls, argument;
  uint8_t first, second;
  int32_t response;
}} model;
static uint8_t load_byte(void *opaque, uint32_t address) {{
  model *m = (model *)opaque; uint32_t call = m->loads++;
  if (call == 0U) {{ __CPROVER_assert(address == m->token, "prefix address"); return m->first; }}
  __CPROVER_assert(call == 1U, "at most two byte reads");
  __CPROVER_assert(address == m->token + UINT32_C(1), "second-byte address");
  return m->second;
}}
static int32_t test_byte(void *opaque, uint32_t value) {{
  model *m = (model *)opaque; m->calls++; m->argument = value; return m->response;
}}
int main(void) {{
  model m = {{ nondet_u32(), 0U, 0U, 0U, (uint8_t)nondet_u32(),
               (uint8_t)nondet_u32(), (int32_t)nondet_u32() }};
  prefixed_token_services services = {{ &m, load_byte, test_byte }};
  int actual = {symbol}(&services, m.token);
  uint32_t expected_loads = 1U, expected_calls = 0U;
  int expected = 0;
  if (m.first == PREFIXED_TOKEN_REQUIRED_BYTE) {{
    expected_loads = 2U;
    if (m.second == PREFIXED_TOKEN_ACCEPTED_BYTE) expected = 1;
    else {{ expected_calls = 1U; expected = m.response != 0; }}
  }}
  __CPROVER_assert(actual == expected, "classification result");
  __CPROVER_assert(m.loads == expected_loads, "byte-read count");
  __CPROVER_assert(m.calls == expected_calls, "predicate-call count");
  if (expected_calls != 0U) __CPROVER_assert(m.argument == m.second, "predicate argument");
  return 0;
}}
'''

    def cbmc_unwind(self, refinement: Mapping[str, Any]) -> int:
        _contract(refinement)
        return 1

    def evidence_scope(self, refinement: Mapping[str, Any]) -> Mapping[str, Any]:
        _contract(refinement)
        return {
            "complete_for_all_32_bit_inputs_and_service_results": True,
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
            and evidence_scope.get(
                "complete_for_all_32_bit_inputs_and_service_results"
            )
            is True
        )


PROFILE = PrefixedUnaryBytePredicateProfile()
