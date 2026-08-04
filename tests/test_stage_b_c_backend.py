from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_c_backend import (
    stage_b_generate_semantic_c_from_state_machine,
    write_stage_b_semantic_c_backend,
)
from spaghetti_extractor.stage_b_api_catalog import load_machine_call_catalog
from spaghetti_extractor.stage_b_state_machine import normalize_stage_a_semantic_transfer


def _transfer(**updates):
    row = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": "semantic-transfer:integer-branch",
        "function": "integer_branch",
        "block_id": "integer-branch",
        "status": "reimplementable",
        "expression_model": "stage-a-semantic-ir-v1",
        "original": {"rva_start": 0x1000, "rva_end": 0x1004},
        "instructions": [{"rva": 0x1000, "bytes": "deadbeef"}],
        "register_writes": [
            {
                "register": "eax",
                "value": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "ebx", "width": 32},
                        {"op": "const", "value": 7, "width": 32},
                    ],
                },
            }
        ],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "fpu_state": None,
        "outcome": {
            "kind": "branch",
            "condition": {
                "op": "eq",
                "args": [
                    {"op": "reg", "name": "ecx", "width": 32},
                    {"op": "const", "value": 0, "width": 32},
                ],
            },
            "true_target_rva": 0x1010,
            "false_target_rva": 0x1020,
        },
    }
    row.update(updates)
    return row


def _rep_scas_event():
    return {
        "kind": "rep_scas",
        "index": 0,
        "element_width": 1,
        "address_size": 32,
        "destination": {"op": "reg", "name": "edi", "width": 32},
        "accumulator": {"op": "reg", "name": "eax", "width": 32},
        "count": {"op": "reg", "name": "ecx", "width": 32},
        "direction_flag": {"op": "flag", "name": "df"},
        "repeat_condition": "while_not_equal_v1",
        "comparison_model": "subtraction_flags_v1",
        "segment_model": "flat_es_zero_v1",
        "effect_model": "symbolic_string_scan_v1",
        "restart_semantics": "element_committed_v1",
        "fault_model": "read_before_commit_v1",
        "owned_register_outputs": ["edi", "ecx"],
        "owned_flag_outputs": ["cf", "pf", "af", "zf", "sf", "of"],
    }


class StageBSemanticCBackendTests(unittest.TestCase):
    def test_emits_compiler_consumable_c_from_semantic_ir_without_original_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            report = write_stage_b_semantic_c_backend(root, [_transfer()])

            self.assertEqual(report["status"], "complete", report)
            self.assertEqual(report["counts"], {"transfers": 1, "generated": 1, "unsupported": 0})
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            self.assertIn("input.ebx", source)
            self.assertIn("STAGE_B_BRANCH", source)
            self.assertNotIn("deadbeef", source)
            self.assertFalse(report["constraints"]["original_instruction_bytes_embedded"])
            source_map = json.loads((root / "state-machine-source-map.json").read_text(encoding="utf-8"))
            self.assertEqual(source_map["authority"], "stage-a-semantic-transfer-contracts")
            self.assertEqual(source_map["transfers"][0]["id"], "semantic-transfer:integer-branch")
            self.assertEqual(source_map["transfers"][0]["implementation"], "generated_semantic_c")
            self.assertRegex(source_map["transfers"][0]["contract_sha256"], r"^[0-9a-f]{64}$")
            implementation = json.loads((root / "state-machine-implementation.json").read_text(encoding="utf-8"))
            self.assertEqual(implementation["authority"], "stage-a-semantic-transfer-contracts")
            self.assertEqual(implementation["strict_candidate"]["status"], "ready")
            self.assertEqual(implementation["transfer_inventory"][0]["id"], "semantic-transfer:integer-branch")
            self.assertEqual(
                implementation["transfer_inventory"][0]["contract_sha256"],
                source_map["transfers"][0]["contract_sha256"],
            )
            dispatch = (root / "state-machine-dispatch.c").read_text(encoding="utf-8")
            self.assertIn("stage_b_step_by_rva", dispatch)
            self.assertIn("semantic-transfer:integer-branch", dispatch)

            compiler = shutil.which("cc")
            if compiler is not None:
                for name in ("state-machine-transfers", "state-machine-repairs", "state-machine-dispatch", "state-machine-engine", "state-machine-api-adapters"):
                    subprocess.run(
                        [compiler, "-std=c11", "-Werror", "-c", str(root / f"{name}.c"), "-o", str(root / f"{name}.o")],
                        check=True,
                        cwd=root,
                        capture_output=True,
                        text=True,
                    )

    def test_fails_closed_on_external_x87_and_ambiguous_memory_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            register_inputs = {
                name: {"op": "reg", "name": name, "width": 32}
                for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            }
            flag_inputs = {
                name: {"op": "flag", "name": name}
                for name in ("cf", "zf", "sf", "of", "pf", "df")
            }
            call_event = {
                "kind": "external_call",
                "dll": "kernel32.dll",
                "symbol": "WriteFile",
                "ordinal": None,
                "return_rva": 0x1004,
                "arguments": [],
                "register_inputs": register_inputs,
                "stack_inputs": [],
                "flag_inputs": flag_inputs,
            }
            external = _transfer(
                id="semantic-transfer:external",
                external_events=[call_event],
                ordered_events=[{"family": "external", "instruction_rva": 0x1000, **call_event}],
                register_writes=[
                    {
                        "register": name,
                        "value": {"op": "call_response", "call_index": 0, "register": name, "width": 32},
                    }
                    for name in register_inputs
                ],
                flag_writes=[
                    {
                        "flag": name,
                        "value": {"op": "call_flag", "call_index": 0, "flag": name},
                    }
                    for name in flag_inputs
                ],
            )
            mixed = _transfer(
                id="semantic-transfer:mixed-memory",
                original={"rva_start": 0x1100, "rva_end": 0x1104},
                memory_events=[
                    {"kind": "read", "width": 4, "address": {"op": "reg", "name": "eax", "width": 32}},
                    {
                        "kind": "write",
                        "width": 4,
                        "address": {"op": "reg", "name": "ebx", "width": 32},
                        "value": {"op": "const", "value": 1, "width": 32},
                    },
                ],
            )
            x87 = _transfer(
                id="semantic-transfer:x87",
                original={"rva_start": 0x1200, "rva_end": 0x1204},
                fpu_state={"model": "symbolic_x87_stack_v1"},
            )

            report = write_stage_b_semantic_c_backend(root, [external, mixed, x87])

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["source_generation_status"], "incomplete")
            self.assertEqual(report["counts"], {"transfers": 3, "generated": 1, "unsupported": 2})
            self.assertEqual(report["runtime_obligation_count"], 1)
            self.assertEqual(report["reason_counts"]["mixed_memory_event_order"], 1)
            self.assertEqual(report["reason_counts"]["x87_state"], 1)
            self.assertEqual(
                report["strict_candidate"]["blockers"],
                ["repair_stubs_remaining", "runtime_call_adapters_unbound"],
            )
            persisted = json.loads((root / "state-machine-c-report.json").read_text(encoding="utf-8"))
            self.assertFalse(persisted["constraints"]["original_instruction_bytes_embedded"])
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            self.assertIn("STAGE_B_CALL_EXTERNAL_IMPORT", source)
            self.assertIn('"WriteFile"', source)
            self.assertIn("stage_b_invoke_call", source)
            self.assertIn("call_output_0.eax", source)
            repairs = (root / "state-machine-repairs.c").read_text(encoding="utf-8")
            self.assertIn("STAGE_B_UNIMPLEMENTED", repairs)
            self.assertNotIn("semantic-transfer:external", repairs)
            self.assertNotIn("deadbeef", repairs)
            source_map = json.loads((root / "state-machine-source-map.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {item["implementation"] for item in source_map["transfers"]},
                {"generated_semantic_c_runtime_contract", "repair_stub"},
            )
            implementation = json.loads((root / "state-machine-implementation.json").read_text(encoding="utf-8"))
            self.assertEqual(implementation["status"], "incomplete")
            self.assertEqual(implementation["strict_candidate"]["status"], "incomplete")
            runtime_obligations = json.loads(
                (root / "state-machine-runtime-obligations.json").read_text(encoding="utf-8")
            )
            self.assertEqual(runtime_obligations["counts"]["unbound_obligations"], 1)
            self.assertEqual(runtime_obligations["call_boundaries"][0]["identity"]["symbol"], "WriteFile")

            compiler = shutil.which("cc")
            if compiler is not None:
                for name in ("state-machine-transfers", "state-machine-repairs", "state-machine-dispatch", "state-machine-engine", "state-machine-api-adapters"):
                    subprocess.run(
                        [compiler, "-std=c11", "-Werror", "-c", str(root / f"{name}.c"), "-o", str(root / f"{name}.o")],
                        check=True,
                        cwd=root,
                        capture_output=True,
                        text=True,
                    )

    def test_emits_rep_movsd_memory_protocol_without_runtime_call_adapter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = {
                "kind": "rep_movsd",
                "index": 0,
                "destination": {"op": "reg", "name": "edi", "width": 32},
                "source": {"op": "reg", "name": "esi", "width": 32},
                "count": {"op": "reg", "name": "ecx", "width": 32},
                "direction_flag": {"op": "flag", "name": "df"},
                "effect_model": "symbolic_string_copy_v1",
            }
            row = _transfer(
                id="semantic-transfer:rep-movsd",
                external_events=[event],
                ordered_events=[{"family": "external", "instruction_rva": 0x1000, **event}],
            )

            report = write_stage_b_semantic_c_backend(root, [row])

            self.assertEqual(report["status"], "complete", report)
            self.assertEqual(report["runtime_obligation_count"], 0)
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            self.assertIn("copy_count_0", source)
            self.assertIn("stage_b_read(rt, copy_source_0", source)
            self.assertIn("stage_b_write(rt, copy_destination_0", source)

    def test_emits_width_generic_string_copy_and_fill_protocols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            register = lambda name: {"op": "reg", "name": name, "width": 32}
            flag = {"op": "flag", "name": "df"}
            copy = {
                "kind": "rep_movs",
                "index": 0,
                "element_width": 1,
                "address_size": 32,
                "destination": register("edi"),
                "source": register("esi"),
                "count": register("ecx"),
                "direction_flag": flag,
                "effect_model": "symbolic_string_copy_v2",
                "restart_semantics": "element_committed_v1",
            }
            fill = {
                "kind": "rep_stos",
                "index": 1,
                "element_width": 2,
                "address_size": 32,
                "destination": register("edi"),
                "value": register("eax"),
                "count": register("ecx"),
                "direction_flag": flag,
                "effect_model": "symbolic_string_fill_v2",
                "restart_semantics": "element_committed_v1",
            }
            row = _transfer(
                id="semantic-transfer:width-generic-strings",
                external_events=[copy, fill],
                ordered_events=[
                    {"family": "external", "instruction_rva": 0x1000, **copy},
                    {"family": "external", "instruction_rva": 0x1002, **fill},
                ],
            )

            report = write_stage_b_semantic_c_backend(root, [row])

            self.assertEqual(report["status"], "complete", report)
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            self.assertIn(
                "stage_b_read(rt, copy_source_0, 1U, &memory_fault)", source
            )
            self.assertIn(
                "stage_b_write(rt, copy_destination_0, 1U", source
            )
            self.assertIn(
                "stage_b_write(rt, fill_destination_1, 2U", source
            )
            self.assertIn("0xfffffffeU : 2U", source)

    def test_rep_scas_runtime_covers_repeat_flags_restart_and_owned_outputs(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = _rep_scas_event()
            row = _transfer(
                id="semantic-transfer:rep-scas",
                external_events=[event],
                ordered_events=[{
                    "family": "external",
                    "instruction_rva": 0x1000,
                    **event,
                }],
                register_writes=[
                    {"register": "edi", "value": {"op": "const", "value": 0xBAD0, "width": 32}},
                    {"register": "ecx", "value": {"op": "const", "value": 0xBAD1, "width": 32}},
                    {"register": "eax", "value": {"op": "const", "value": 0xDEADBEEF, "width": 32}},
                ],
                flag_writes=[
                    {"flag": name, "value": {"op": "false"}}
                    for name in ("cf", "pf", "af", "zf", "sf", "of")
                ] + [{"flag": "df", "value": {"op": "false"}}],
                outcome={"kind": "fallthrough", "target_rva": 0x1002},
            )

            report = write_stage_b_semantic_c_backend(root, [row])

            self.assertEqual(report["status"], "complete", report)
            source = (root / "state-machine-transfers.c").read_text(encoding="ascii")
            self.assertIn("scan_accumulator_0", source)
            self.assertIn("stage_b_read(rt, scan_destination_0, 1U", source)
            self.assertNotIn("state->edi = 47824U", source)
            self.assertNotIn("state->ecx = 47825U", source)
            self.assertIn("state->eax = 3735928559U", source)

            harness = root / "harness.c"
            harness.write_text(
                r'''
#include "state-machine-transfers.h"

typedef struct scan_context {
  uint32_t base, fault_address, reads;
  uint8_t bytes[4];
} scan_context;

static uint32_t read_byte(
    void *raw, uint32_t address, uint32_t width, uint32_t *fault) {
  scan_context *context = (scan_context *)raw;
  ++context->reads;
  if (width != 1U || address == context->fault_address ||
      address < context->base || address >= context->base + 4U) {
    *fault = 1U;
    return 0U;
  }
  return context->bytes[address - context->base];
}

static void write_unused(
    void *raw, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {
  (void)raw; (void)address; (void)width; (void)value; *fault = 1U;
}

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  (void)runtime; (void)event; (void)input; (void)output;
  return STAGE_B_CALL_UNIMPLEMENTED;
}

static void initial_flags(stage_b_machine_state *state) {
  state->cf = 1U; state->zf = 0U; state->sf = 1U;
  state->of = 1U; state->pf = 0U; state->eflags = 1U << 4;
}

static int flags_are(
    const stage_b_machine_state *state, uint32_t cf, uint32_t zf,
    uint32_t sf, uint32_t of, uint32_t pf, uint32_t af) {
  return state->cf == cf && state->zf == zf && state->sf == sf &&
      state->of == of && state->pf == pf &&
      ((state->eflags >> 4) & 1U) == af;
}

static stage_b_step_result run(
    scan_context *context, stage_b_machine_state *state) {
  stage_b_runtime runtime = {0};
  runtime.context = context; runtime.read = read_byte; runtime.write = write_unused;
  return stage_b_transfer_semantic_transfer_rep_scas(&runtime, state);
}

int main(void) {
  const uint32_t base = 0x2000U;
  scan_context context = {base, 0xffffffffU, 0U, {0U,0U,0U,0U}};
  stage_b_machine_state state = {0};
  stage_b_step_result result;

  state.eax = 0x41U; state.edi = base; state.ecx = 0U; initial_flags(&state);
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || context.reads != 0U) return 1;
  if (state.edi != base || state.ecx != 0U ||
      !flags_are(&state, 1U,0U,1U,1U,0U,1U)) return 2;
  if (state.eax != 0xdeadbeefU || state.df != 0U) return 3;

  context = (scan_context){base, 0xffffffffU, 0U, {0x20U,0x41U,0U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0x41U; state.edi = base; state.ecx = 3U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || context.reads != 2U) return 4;
  if (state.edi != base + 2U || state.ecx != 1U ||
      !flags_are(&state, 0U,1U,0U,0U,1U,0U)) return 5;

  context = (scan_context){base, 0xffffffffU, 0U, {1U,2U,0U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0U; state.edi = base; state.ecx = 2U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || state.edi != base + 2U ||
      state.ecx != 0U || !flags_are(&state, 1U,0U,1U,0U,0U,1U)) return 6;

  context = (scan_context){base, 0xffffffffU, 0U, {0U,0x41U,0x10U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0x41U; state.edi = base + 2U; state.ecx = 2U; state.df = 1U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_FALLTHROUGH || state.edi != base ||
      state.ecx != 0U || !flags_are(&state, 0U,1U,0U,0U,1U,0U)) return 7;
  if (state.df != 0U) return 8;

  context = (scan_context){base, base + 1U, 0U, {0x42U,0U,0U,0U}};
  state = (stage_b_machine_state){0};
  state.eax = 0x41U; state.edi = base; state.ecx = 3U;
  result = run(&context, &state);
  if (result.kind != STAGE_B_MEMORY_FAULT || result.target_rva != 0x1000U ||
      context.reads != 2U) return 9;
  if (state.edi != base + 1U || state.ecx != 2U ||
      !flags_are(&state, 1U,0U,1U,0U,1U,1U)) return 10;
  if (state.eax != 0x41U) return 11;
  return 0;
}
''',
                encoding="ascii",
            )
            executable = root / "rep-scas-c"
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Werror",
                    "-I",
                    str(root),
                    str(root / "state-machine-transfers.c"),
                    str(harness),
                    "-o",
                    str(executable),
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_rep_scas_contract_validation_fails_closed(self):
        cases = (
            {"element_width": 2},
            {"address_size": 16},
            {"repeat_condition": "unchecked"},
            {"comparison_model": "unchecked"},
            {"segment_model": "unchecked"},
            {"effect_model": "unchecked"},
            {"restart_semantics": "unchecked"},
            {"fault_model": "unchecked"},
            {"owned_flag_outputs": ["cf", "zf"]},
        )
        for mutation in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                event = {**_rep_scas_event(), **mutation}
                report = write_stage_b_semantic_c_backend(
                    root,
                    [_transfer(
                        external_events=[event],
                        ordered_events=[{
                            "family": "external",
                            "instruction_rva": 0x1000,
                            **event,
                        }],
                    )],
                )
                self.assertEqual(report["status"], "incomplete", report)
                self.assertEqual(
                    report["reason_counts"]["malformed_rep_scas_event"], 1
                )

    def test_generates_exact_import_adapter_from_machine_call_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            register_inputs = {
                name: {"op": "reg", "name": name, "width": 32}
                for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            }
            flag_inputs = {
                name: {"op": "flag", "name": name}
                for name in ("cf", "zf", "sf", "of", "pf", "df")
            }
            event = {
                "kind": "external_call",
                "dll": "kernel32.dll",
                "symbol": "WriteFile",
                "ordinal": None,
                "return_rva": 0x1004,
                "arguments": [],
                "register_inputs": register_inputs,
                "stack_inputs": [],
                "flag_inputs": flag_inputs,
            }
            row = _transfer(
                id="semantic-transfer:write-file",
                external_events=[event],
                ordered_events=[{"family": "external", "instruction_rva": 0x1000, **event}],
                register_writes=[
                    {
                        "register": name,
                        "value": {"op": "call_response", "call_index": 0, "register": name, "width": 32},
                    }
                    for name in register_inputs
                ],
                flag_writes=[
                    {"flag": name, "value": {"op": "call_flag", "call_index": 0, "flag": name}}
                    for name in flag_inputs
                ],
            )
            catalog_path = root / "machine-calls.json"
            catalog_path.write_text(
                json.dumps(
                    {
                        "format": "stage-b-machine-call-catalog-v1",
                        "entries": [
                            {
                                "id": "kernel32-write-file",
                                "import": {"dll": "kernel32.dll", "symbol": "WriteFile"},
                                "calling_convention": "stdcall",
                                "stack_argument_offsets": [0, 4, 8, 12, 16],
                                "stack_result_delta": 20,
                                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                                "clobbered_registers": ["eax", "ecx", "edx"],
                                "disposition": "returns",
                                "memory_effect": "argumentRanges",
                                "memory_footprints": [],
                                "world_effect": "none",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            report = write_stage_b_semantic_c_backend(
                root / "generated",
                [row],
                machine_call_catalog=load_machine_call_catalog(catalog_path),
            )

            self.assertEqual(report["status"], "complete", report)
            self.assertEqual(report["runtime_obligation_count"], 0)
            self.assertEqual(report["api_adapters"]["bound_calls"], 1)
            self.assertEqual(report["api_adapters"]["generated_import_adapters"], 1)
            self.assertEqual(report["strict_candidate"]["status"], "ready")
            adapter = (root / "generated" / "state-machine-api-adapters.c").read_text(encoding="utf-8")
            self.assertIn("__attribute__((stdcall, dllimport))", adapter)
            self.assertIn('__asm__("WriteFile")', adapter)
            self.assertIn("input->esp + 16U", adapter)
            self.assertIn("stage_b_import_0(argument_0, argument_1, argument_2, argument_3, argument_4)", adapter)
            boundaries = json.loads(
                (root / "generated" / "state-machine-runtime-obligations.json").read_text(encoding="utf-8")
            )["call_boundaries"]
            self.assertEqual(boundaries[0]["binding"], "generated_machine_call_adapter_v1")

            compiler = shutil.which("i686-w64-mingw32-gcc")
            if compiler is not None:
                subprocess.run(
                    [compiler, "-std=gnu17", "-O0", "-Werror", "-c", "state-machine-api-adapters.c", "-o", "state-machine-api-adapters.o"],
                    check=True,
                    cwd=root / "generated",
                    capture_output=True,
                    text=True,
                )

    def test_binds_direct_internal_calls_to_generated_nested_frame_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            register_inputs = {
                name: {"op": "reg", "name": name, "width": 32}
                for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
            }
            flag_inputs = {
                name: {"op": "flag", "name": name}
                for name in ("cf", "zf", "sf", "of", "pf", "df")
            }
            event = {
                "kind": "internal_call",
                "target_rva": 0x2000,
                "return_rva": 0x1004,
                "register_inputs": register_inputs,
                "stack_inputs": [],
                "flag_inputs": flag_inputs,
                "effect_model": "uninterpreted_internal_call_response_v1",
            }
            caller = _transfer(
                id="semantic-transfer:caller",
                external_events=[event],
                ordered_events=[{"family": "external", "instruction_rva": 0x1000, **event}],
                register_writes=[
                    {
                        "register": name,
                        "value": {"op": "call_response", "call_index": 0, "register": name, "width": 32},
                    }
                    for name in register_inputs
                ],
                flag_writes=[
                    {"flag": name, "value": {"op": "call_flag", "call_index": 0, "flag": name}}
                    for name in flag_inputs
                ],
            )
            callee = _transfer(
                id="semantic-transfer:callee",
                original={"rva_start": 0x2000, "rva_end": 0x2001},
                outcome={"kind": "return", "value": {"op": "reg", "name": "eax", "width": 32}},
            )

            report = write_stage_b_semantic_c_backend(root, [caller, callee])

            self.assertEqual(report["status"], "complete", report)
            self.assertEqual(report["runtime_obligation_count"], 0)
            self.assertEqual(report["generated_runtime_binding_count"], 1)
            self.assertEqual(report["strict_candidate"]["status"], "ready")
            boundaries = json.loads(
                (root / "state-machine-runtime-obligations.json").read_text(encoding="utf-8")
            )["call_boundaries"]
            self.assertEqual(boundaries[0]["status"], "bound")
            self.assertEqual(boundaries[0]["binding"], "generated_nested_frame_engine_v1")
            engine = (root / "state-machine-engine.c").read_text(encoding="utf-8")
            self.assertIn("stage_b_run_function", engine)
            self.assertIn("STAGE_B_CALL_INTERNAL_DIRECT", engine)

    def test_rejects_ordered_event_payload_that_does_not_match_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            summary = {"kind": "read", "width": 4, "address": {"op": "reg", "name": "eax", "width": 32}}
            ordered = {"family": "memory", "instruction_rva": 0x1000, "kind": "read", "width": 4, "address": {"op": "reg", "name": "ebx", "width": 32}}

            report = write_stage_b_semantic_c_backend(
                root,
                [_transfer(memory_events=[summary], ordered_events=[ordered])],
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["reason_counts"]["ordered_event_projection_mismatch"], 1)

    def test_lowers_shift_and_sbb_flag_expressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = {"op": "reg", "name": "eax", "width": 32}
            count = {"op": "reg", "name": "ecx", "width": 32}
            result = {"op": "shl32", "args": [left, count]}
            row = _transfer(
                flag_writes=[
                    {"flag": "cf", "value": {"op": "shift_cf", "args": ["shl", 32, left, count]}},
                    {"flag": "of", "value": {"op": "shift_of", "args": ["shl", 32, left, count, result]}},
                    {
                        "flag": "zf",
                        "value": {
                            "op": "sbb_borrow",
                            "args": [32, left, {"op": "reg", "name": "edx", "width": 32}, {"op": "const", "value": 1, "width": 32}, result],
                        },
                    },
                    {
                        "flag": "sf",
                        "value": {
                            "op": "sbb_overflow",
                            "args": [32, left, {"op": "reg", "name": "edx", "width": 32}, {"op": "const", "value": 1, "width": 32}, result],
                        },
                    },
                ]
            )

            report = write_stage_b_semantic_c_backend(root, [row])

            self.assertEqual(report["status"], "complete", report)
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            self.assertIn("stage_b_shift_cf", source)
            self.assertIn("stage_b_shift_of", source)
            self.assertIn("stage_b_sbb_borrow", source)
            self.assertIn("stage_b_sbb_overflow", source)

    def test_lowers_double_shift_flag_expressions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = {"op": "reg", "name": "eax", "width": 32}
            count = {"op": "reg", "name": "ecx", "width": 32}
            result = {"op": "lshr32", "args": [left, count]}
            row = _transfer(
                flag_writes=[
                    {"flag": "cf", "value": {"op": "shift_cf", "args": ["shrd", 32, left, count]}},
                    {"flag": "of", "value": {"op": "shift_of", "args": ["shrd", 32, left, count, result]}},
                ]
            )

            report = write_stage_b_semantic_c_backend(root, [row])

            self.assertEqual(report["status"], "complete", report)
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            self.assertIn("stage_b_shift_cf(1U", source)
            self.assertIn("stage_b_shift_of(1U", source)

    def test_ordered_events_check_divide_fault_before_later_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_address = {"op": "reg", "name": "eax", "width": 32}
            second_address = {"op": "reg", "name": "ebx", "width": 32}
            divide_fault = {
                "kind": "divide_error",
                "condition": {"op": "eq", "args": [{"op": "reg", "name": "ecx", "width": 32}, {"op": "const", "value": 0, "width": 32}]},
                "instruction_rva": 0x1000,
            }
            row = _transfer(
                memory_events=[
                    {"kind": "read", "width": 4, "address": first_address},
                    {"kind": "read", "width": 4, "address": second_address},
                ],
                faults=[divide_fault],
                ordered_events=[
                    {"family": "memory", "kind": "read", "width": 4, "address": first_address, "instruction_rva": 0x1000},
                    {"family": "fault", **divide_fault},
                    {"family": "memory", "kind": "read", "width": 4, "address": second_address, "instruction_rva": 0x1004},
                ],
            )

            report = write_stage_b_semantic_c_backend(root, [row])

            self.assertEqual(report["status"], "complete", report)
            source = (root / "state-machine-transfers.c").read_text(encoding="utf-8")
            first_read = source.index("stage_b_read(rt, input.eax")
            divide_check = source.index("STAGE_B_DIVIDE_ERROR")
            second_read = source.index("stage_b_read(rt, input.ebx")
            self.assertLess(first_read, divide_check)
            self.assertLess(divide_check, second_read)

    def test_dispatch_fails_closed_on_ambiguous_source_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [
                _transfer(id="semantic-transfer:first"),
                _transfer(id="semantic-transfer:overlapping-view"),
            ]

            report = write_stage_b_semantic_c_backend(root, rows)

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["dispatch"]["status"], "incomplete")
            self.assertEqual(report["dispatch"]["duplicate_rvas"][0]["rva_start"], 0x1000)
            dispatch = (root / "state-machine-dispatch.c").read_text(encoding="utf-8")
            self.assertIn("if (match != 0) return 0;", dispatch)

    def test_regenerates_from_hash_checked_canonical_state_machine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_machine = root / "state-machine.jsonl"
            row = normalize_stage_a_semantic_transfer(_transfer())
            state_machine.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

            report = stage_b_generate_semantic_c_from_state_machine(
                state_machine=state_machine,
                out_dir=root / "semantic-c",
            )

            self.assertEqual(report["status"], "complete", report)
            self.assertEqual(report["state_machine"]["path"], "state-machine.jsonl")
            implementation = json.loads(
                (root / "semantic-c" / "state-machine-implementation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(implementation["state_machine"], report["state_machine"])

            row["register_writes"][0]["register"] = "edx"
            state_machine.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "contract_sha256"):
                stage_b_generate_semantic_c_from_state_machine(
                    state_machine=state_machine,
                    out_dir=root / "tampered",
                )


if __name__ == "__main__":
    unittest.main()
