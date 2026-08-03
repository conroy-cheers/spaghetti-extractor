from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.reconstruction_ir import (
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
)
from spaghetti_extractor.reconstruction_workspace import (
    RECONSTRUCTION_PLAN_FORMAT,
    RECONSTRUCTION_REGISTRY_FORMAT,
    RECONSTRUCTION_STATUS_FORMAT,
    RECONSTRUCTION_WORKSPACE_FORMAT,
    _affine_register_address,
    _checked_machine_abi_comparison,
    _executable_alias_cases,
    _generate_cases,
    _manual_memory_fields,
    _regional_call_stack_observations,
    _render_manual_contract,
    _render_regional_harness,
    _synthesize_cluster_validation,
    check_reconstruction_workspace,
    create_reconstruction_workspace,
    promote_reconstruction_workspaces,
    rebind_reconstruction_workspace,
    write_reconstruction_plan,
    write_reconstruction_status,
)
from spaghetti_extractor.region_replacement import (
    REGION_OBSERVATIONS_FORMAT,
    load_region_replacement_manifest,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file, write_json


SHA = "a" * 64
REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
FLAGS = ("cf", "zf", "sf", "of", "pf", "df")


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _flag(name: str) -> dict:
    return {"op": "flag", "name": name}


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


def _pre_state() -> dict:
    return {
        "registers": {name: _reg(name) for name in REGISTERS},
        "flags": {name: _flag(name) for name in FLAGS},
        "memory": {"op": "memory", "name": "mem0", "address_width": 32, "value_width": 8},
    }


def _unit(rva: int, end: int, *, instructions: list, control: dict, semantics: dict) -> dict:
    semantics = {
        "pre_state": _pre_state(),
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "stack_delta": {"status": "derived", "net_bytes": 0, "expression": _reg("esp")},
        **semantics,
    }
    return {
        "record_kind": "unit",
        "id": f"unit:{rva:08x}",
        "status": "qualified",
        "reachable": True,
        "source": {
            "contract_sha256": f"{rva:064x}"[-64:],
            "instruction_bytes_sha256": SHA,
            "original": {"rva_start": rva, "rva_end": end, "size": end - rva},
        },
        "instructions": instructions,
        "control": control,
        "semantics": semantics,
    }


def _fixtures() -> list[dict]:
    sub = {"op": "sub32", "args": [_reg("ebx"), _reg("eax")]}
    equal = {"op": "eq", "args": [sub, _const(0)]}
    branch = _unit(
        0x1000,
        0x1008,
        instructions=[
            {
                "mnemonic": "cmp",
                "operands": [
                    {"kind": "register", "name": "ebx"},
                    {"kind": "register", "name": "eax"},
                ],
            },
            {"mnemonic": "je", "operands": [{"kind": "immediate", "value": 0x1020}]},
        ],
        control={"kind": "branch", "direct_targets": [0x1020, 0x1008], "has_indirect_target": False},
        semantics={
            "flag_writes": [
                {"flag": "cf", "value": {"op": "ult32", "args": [_reg("ebx"), _reg("eax")]}},
                {"flag": "of", "value": {"op": "sub_overflow", "args": [32, _reg("ebx"), _reg("eax"), sub]}},
                {"flag": "pf", "value": {"op": "parity", "args": [32, sub]}},
                {"flag": "sf", "value": {"op": "msb", "args": [32, sub]}},
                {"flag": "zf", "value": equal},
            ],
            "outcome": {"kind": "branch", "condition": equal, "true_target_rva": 0x1020, "false_target_rva": 0x1008},
        },
    )
    fallthrough = _unit(
        0x1008, 0x1010,
        instructions=[{"mnemonic": "jmp", "operands": []}],
        control={"kind": "jump", "direct_targets": [0x1020], "has_indirect_target": False},
        semantics={"outcome": {"kind": "jump", "target_rva": 0x1020}},
    )
    target = _unit(
        0x1020, 0x1021,
        instructions=[{"mnemonic": "ret", "operands": []}],
        control={"kind": "return", "direct_targets": [], "has_indirect_target": False},
        semantics={"outcome": {"kind": "return", "value": {"op": "load", "address": _reg("esp"), "width": 4}}},
    )
    external_event = {
        "kind": "external_call", "dll": "kernel32.dll", "symbol": "Sleep", "ordinal": None,
        "return_rva": 0x2010,
        "stack_inputs": [{"offset": 0, "width": 4, "value": _const(1000)}],
        "arguments": [{"op": "load", "address": _reg("esp"), "width": 4}],
        "register_inputs": {name: _reg(name) for name in REGISTERS},
        "flag_inputs": {name: _flag(name) for name in FLAGS},
    }
    ordered_external_event = {
        **external_event,
        "family": "external",
        "instruction_rva": 0x200A,
    }
    response_registers = [
        {"register": name, "value": {"op": "call_response", "call_index": 0, "register": name, "width": 32}}
        for name in REGISTERS
    ]
    response_flags = [
        {"flag": name, "value": {"op": "call_flag", "call_index": 0, "flag": name}}
        for name in FLAGS
    ]
    external = _unit(
        0x2000, 0x2010,
        instructions=[
            {"mnemonic": "mov", "operands": [], "rva_start": 0x2000, "rva_end": 0x200A},
            {"mnemonic": "call", "operands": [], "rva_start": 0x200A, "rva_end": 0x2010},
        ],
        control={"kind": "fallthrough", "direct_targets": [0x2010], "has_indirect_target": False},
        semantics={
            "register_writes": response_registers,
            "flag_writes": response_flags,
            "memory_events": [{"kind": "write", "address": _reg("esp"), "width": 4, "value": _const(1000)}],
            "external_events": [external_event],
            "ordered_events": [
                {
                    "family": "memory", "instruction_rva": 0x2000,
                    "kind": "write", "address": _reg("esp"), "width": 4,
                    "value": _const(1000),
                },
                ordered_external_event,
            ],
            "outcome": {"kind": "fallthrough", "target_rva": 0x2010},
            "stack_delta": {"status": "unknown", "expression": response_registers[-1]["value"]},
        },
    )
    external_target = _unit(
        0x2010, 0x2011,
        instructions=[{"mnemonic": "ret", "operands": []}],
        control={"kind": "return", "direct_targets": [], "has_indirect_target": False},
        semantics={"outcome": {"kind": "return", "value": {"op": "load", "address": _reg("esp"), "width": 4}}},
    )
    internal_event = {
        "kind": "internal_call", "target_rva": 0x3100, "return_rva": 0x3010,
        "register_inputs": {name: _reg(name) for name in REGISTERS},
        "flag_inputs": {name: _flag(name) for name in FLAGS}, "stack_inputs": [],
    }
    internal_event["register_inputs"]["edx"] = {
        "op": "load", "address": _const(0x430344), "width": 4
    }
    internal = _unit(
        0x3000, 0x3010,
        instructions=[{"mnemonic": "mov", "operands": []}, {"mnemonic": "call", "operands": []}],
        control={"kind": "fallthrough", "direct_targets": [0x3010], "has_indirect_target": False},
        semantics={
            "register_writes": response_registers,
            "flag_writes": response_flags,
            "memory_events": [
                {"kind": "read", "address": _const(0x430344), "width": 4},
                {"kind": "write", "address": _reg("eax"), "width": 4, "value": {"op": "load", "address": _const(0x430344), "width": 4}},
            ],
            "external_events": [internal_event],
            "outcome": {"kind": "fallthrough", "target_rva": 0x3010},
            "stack_delta": {"status": "unknown", "expression": response_registers[-1]["value"]},
        },
    )
    internal_target = _unit(
        0x3010, 0x3011,
        instructions=[{"mnemonic": "ret", "operands": []}],
        control={"kind": "return", "direct_targets": [], "has_indirect_target": False},
        semantics={"outcome": {"kind": "return", "value": {"op": "load", "address": _reg("esp"), "width": 4}}},
    )
    callee = _unit(
        0x3100, 0x3103,
        instructions=[{"mnemonic": "xor", "operands": []}, {"mnemonic": "ret", "operands": []}],
        control={"kind": "return", "direct_targets": [], "has_indirect_target": False},
        semantics={
            "register_writes": [{"register": "eax", "value": _const(0)}, {"register": "esp", "value": {"op": "add32", "args": [_const(4), _reg("esp")]}}],
            "flag_writes": [
                {"flag": "cf", "value": {"op": "false"}}, {"flag": "of", "value": {"op": "false"}},
                {"flag": "pf", "value": {"op": "parity", "args": [32, _const(0)]}},
                {"flag": "sf", "value": {"op": "msb", "args": [32, _const(0)]}},
                {"flag": "zf", "value": {"op": "eq", "args": [_const(0), _const(0)]}},
            ],
            "memory_events": [{"kind": "read", "address": _reg("esp"), "width": 4}],
            "outcome": {"kind": "return", "value": {"op": "load", "address": _reg("esp"), "width": 4}},
            "stack_delta": {"status": "derived", "net_bytes": 4, "expression": {"op": "add32", "args": [_const(4), _reg("esp")]}},
        },
    )
    return [branch, fallthrough, target, external, external_target, internal, internal_target, callee]


def _write_machine_ir(root: Path) -> Path:
    package = root / "machine-ir"
    package.mkdir()
    rows = _fixtures()
    (package / MACHINE_IR_FILENAME).write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    write_json(
        package / MACHINE_IR_MANIFEST_FILENAME,
        {"format": MACHINE_IR_FORMAT, "status": "qualified", "counts": {"units": len(rows)}},
    )
    return package


def _write_interpreter(root: Path) -> Path:
    package = root / "interpreter"
    package.mkdir()
    (package / "state-machine-program.c").write_text("int program_data;\n", encoding="ascii")
    (package / "state-machine-runtime.h").write_text(
        """#include <stdint.h>
typedef struct stage_b_machine_state { uint32_t eax,ebx,ecx,edx,esi,edi,ebp,esp,cf,zf,sf,of,pf,df,original_rva; } stage_b_machine_state;
typedef struct stage_b_runtime stage_b_runtime;
typedef enum stage_b_call_status { STAGE_B_CALL_OK, STAGE_B_CALL_UNIMPLEMENTED, STAGE_B_CALL_DIVIDE_ERROR, STAGE_B_CALL_MEMORY_FAULT, STAGE_B_CALL_EXTERNAL_FAULT } stage_b_call_status;
typedef enum stage_b_call_event_kind { STAGE_B_CALL_EXTERNAL_IMPORT, STAGE_B_CALL_INTERNAL_DIRECT, STAGE_B_CALL_INDIRECT } stage_b_call_event_kind;
typedef struct stage_b_stack_input { uint32_t offset,width,value; } stage_b_stack_input;
typedef struct stage_b_call_event { stage_b_call_event_kind kind; uint32_t instruction_rva,call_index,target_rva,return_rva; const char *dll,*symbol; uint32_t ordinal,has_ordinal; const uint32_t *arguments; uint32_t argument_count; const stage_b_stack_input *stack_inputs; uint32_t stack_input_count; } stage_b_call_event;
typedef stage_b_call_status (*stage_b_external_call_handler)(stage_b_runtime *,const stage_b_call_event *,const stage_b_machine_state *,stage_b_machine_state *);
struct stage_b_runtime { void *context; uint32_t (*read)(void *,uint32_t,uint32_t,uint32_t *); void (*write)(void *,uint32_t,uint32_t,uint32_t,uint32_t *); void (*atomic_compare_exchange)(void *,uint32_t,uint32_t,uint32_t,uint32_t,uint32_t *,uint32_t *,uint32_t *); void (*atomic_exchange)(void *,uint32_t,uint32_t,uint32_t,uint32_t *,uint32_t *); stage_b_external_call_handler external_call_fallback; };
stage_b_call_status stage_b_invoke_call(stage_b_runtime *,const stage_b_call_event *,const stage_b_machine_state *,stage_b_machine_state *);
typedef enum stage_b_control_kind { STAGE_B_FALLTHROUGH,STAGE_B_JUMP,STAGE_B_BRANCH,STAGE_B_RETURN,STAGE_B_INDIRECT_JUMP,STAGE_B_DIVIDE_ERROR,STAGE_B_MEMORY_FAULT,STAGE_B_UNIMPLEMENTED,STAGE_B_EXTERNAL_FAULT,STAGE_B_EXTERNAL_JUMP } stage_b_control_kind;
typedef struct stage_b_step_result { stage_b_control_kind kind; uint32_t target_rva,value; } stage_b_step_result;
""",
        encoding="ascii",
    )
    (package / "state-machine-interpreter.h").write_text(
        '#include "state-machine-runtime.h"\n'
        "stage_b_step_result stage_b_interpreter_step(stage_b_runtime *,stage_b_machine_state *,uint32_t);\n",
        encoding="ascii",
    )
    (package / "state-machine-interpreter.c").write_text(
        """#include "state-machine-interpreter.h"
stage_b_call_status stage_b_dispatch_external_call(stage_b_runtime *,const stage_b_call_event *,const stage_b_machine_state *,stage_b_machine_state *);
static uint32_t parity(uint32_t value) { value ^= value >> 4; value &= 15U; return (0x9669U >> value) & 1U; }
stage_b_step_result stage_b_interpreter_step(stage_b_runtime *rt,stage_b_machine_state *s,uint32_t rva) {
  uint32_t d;
  (void)rt;
  s->original_rva = rva;
  if (rva != 0x1000U) return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED,rva,0U };
  d = s->ebx - s->eax;
  s->cf = s->ebx < s->eax;
  s->of = ((s->ebx ^ s->eax) & (s->ebx ^ d) & 0x80000000U) != 0U;
  s->pf = parity(d); s->sf = d >> 31; s->zf = d == 0U;
  return (stage_b_step_result){ STAGE_B_BRANCH,s->zf ? 0x1020U : 0x1008U,0U };
}
stage_b_call_status stage_b_invoke_call(stage_b_runtime *rt,const stage_b_call_event *event,const stage_b_machine_state *input,stage_b_machine_state *output) {
  return stage_b_dispatch_external_call(rt,event,input,output);
}
""",
        encoding="ascii",
    )
    program_sha = sha256_file(package / "state-machine-program.c")
    write_json(
        package / "state-machine-interpreter-package.json",
        {
            "format": "stage-b-semantic-interpreter-package-v1",
            "program": {"path": "state-machine-program.c", "sha256": program_sha},
        },
    )
    return package


def _observations(manifest: dict) -> dict:
    outputs = [
        {"id": item["id"], "value": 0}
        for item in manifest["live_state"]["outputs"]
    ]
    inputs = [
        {"id": item["id"], "value": 0}
        for item in manifest["live_state"]["inputs"]
    ]
    memory = [
        {"id": item["id"], "base": 0x70000000 + index * 16, "before": "00" * item["byte_length"], "after": "00" * item["byte_length"]}
        for index, item in enumerate(manifest["memory_views"])
    ]
    controls = manifest["expectations"]["control"]
    control = controls[0]
    events = [
        {
            "id": item["id"], "kind": item["kind"], "identity": item["identity"],
            "arguments": [], "memory_reads": [], "result": {}, "memory_writes": [],
            "callbacks": [],
        }
        for item in manifest["expectations"]["external_events"]
    ]
    return {
        "format": REGION_OBSERVATIONS_FORMAT,
        "manifest_sha256": manifest["manifest_sha256"],
        "cases": [{
            "id": "case:synthetic", "entry_unit_id": manifest["cluster"]["entry_unit_id"],
            "live_inputs": inputs, "live_outputs": outputs, "memory_views": memory,
            "control": {
                "id": control["id"], "kind": control["kind"],
                "target_unit_id": control["target_unit_ids"][0] if control["target_unit_ids"] else None,
                "target_rva": control["target_rvas"][0] if control["target_rvas"] else None,
                "value": 0,
            },
            "fault": None, "external_events": events,
        }],
    }


class ReconstructionWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.machine_ir = _write_machine_ir(self.root)
        self.interpreter = _write_interpreter(self.root)
        self.plan = self.root / "plan.json"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_plan_is_deterministic_and_classifies_representative_clusters(self) -> None:
        first = write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        second_path = self.root / "plan-second.json"
        second = write_reconstruction_plan(machine_ir=self.machine_ir, out=second_path)
        self.assertEqual(first, second)
        self.assertEqual(first["format"], RECONSTRUCTION_PLAN_FORMAT)
        selected = {item["entry_rva"]: item for item in first["clusters"]}
        self.assertEqual(selected[0x1000]["template"], "compare_branch")
        self.assertEqual(selected[0x2000]["template"], "constant_external_call")
        self.assertEqual(selected[0x3000]["template"], "store_then_zero_call")
        self.assertEqual(len(selected[0x3000]["unit_ids"]), 1)
        self.assertEqual(
            selected[0x3000]["template_dependency_unit_ids"], ["unit:00003100"]
        )
        claimed_units = [
            unit_id for cluster in first["clusters"] for unit_id in cluster["unit_ids"]
        ]
        self.assertEqual(len(claimed_units), len(set(claimed_units)))
        self.assertFalse(first["executes_original_binary"])

    def test_regional_call_stack_observations_are_canonical_and_fail_closed(self) -> None:
        payload = {
            "call_stack_observations": [
                {
                    "event_index": 2,
                    "slots": [
                        {"offset": 8, "width": 4},
                        {"offset": 0, "width": 1},
                    ],
                },
                {
                    "event_index": 0,
                    "slots": [{"offset": 4, "width": 2}],
                },
            ]
        }

        self.assertEqual(
            _regional_call_stack_observations(payload),
            (
                (0, ((4, 2),)),
                (2, ((8, 4), (0, 1))),
            ),
        )
        payload["call_stack_observations"][0]["slots"].append(
            {"offset": 8, "width": 4}
        )
        with self.assertRaisesRegex(StageAInputError, "invalid or duplicate"):
            _regional_call_stack_observations(payload)

    def test_checked_machine_abi_comparison_is_bound_and_fail_closed(self) -> None:
        contract = {
            "contract_id": 11,
            "template": "pe32-stdcall-v1",
            "argument_words": 2,
            "profile_binding": {
                "profile_id": "pe32-kernel32-lockstep-v1",
                "profile_sha256": "9" * 64,
            },
        }

        first = _checked_machine_abi_comparison({"abi_contract": contract})
        second = _checked_machine_abi_comparison({"abi_contract": contract})

        self.assertEqual(first, second)
        self.assertEqual(first["mode"], "checked_machine_abi_v1")
        self.assertRegex(first["abi_contract_sha256"], r"^[0-9a-f]{64}$")
        self.assertIsNone(_checked_machine_abi_comparison({}))

        malformed = copy.deepcopy(contract)
        malformed["profile_binding"]["profile_sha256"] = "not-a-hash"
        self.assertIsNone(
            _checked_machine_abi_comparison({"abi_contract": malformed})
        )

    def test_finite_dispatch_cases_bind_selector_register_exhaustively(self) -> None:
        unit = _unit(
            0x4000,
            0x4004,
            instructions=[{"mnemonic": "jmp", "operands": []}],
            control={
                "kind": "indirect_jump",
                "direct_targets": [],
                "has_indirect_target": True,
            },
            semantics={
                "outcome": {
                    "kind": "indirect_jump",
                    "target": {"name": "eax", "op": "reg", "width": 32},
                }
            },
        )
        entries = [
            {
                "index": index,
                "entry_rva": 0x8000 + index * 4,
                "target_rva": 0x5000 + index * 0x10,
                "target_address": 0x405000 + index * 0x10,
            }
            for index in range(3)
        ]
        cluster = {
            "id": "cluster:dispatch",
            "entry_unit_id": unit["id"],
            "entry_rva": 0x4000,
            "template": None,
            "typed_contract": {"memory_views": []},
            "control": [
                {
                    "kind": "indirect_jump",
                    "target_rvas": [0x5000, 0x5010, 0x5020],
                    "target_unit_ids": ["target:0", "target:1", "target:2"],
                    "finite_target_inventory": True,
                    "dispatch_entries": entries,
                    "selector": {
                        "expression": {"name": "eax", "op": "reg", "width": 32},
                        "lower_inclusive": 0,
                        "upper_exclusive": 3,
                    },
                    "table": {"address": 0x408000, "entry_width": 4},
                }
            ],
        }

        generated = _synthesize_cluster_validation(cluster, [unit])
        self.assertEqual(generated["counts"]["indirect_dispatch"], 3)
        self.assertTrue(
            all(
                case["dispatch_binding"]["executable"]
                for case in generated["indirect_dispatch_cases"]
            )
        )
        cases = _generate_cases(cluster=cluster, entry=unit, units=[unit])
        self.assertEqual(len(cases["cases"]), 3)
        self.assertEqual(
            [case["registers"]["eax"] for case in cases["cases"]], [0, 1, 2]
        )
        self.assertEqual(
            [
                next(
                    item["bytes"]
                    for item in case["memory"]
                    if item["address"] == 0x408000 + index * 4
                )
                for index, case in enumerate(cases["cases"])
            ],
            ["00504000", "10504000", "20504000"],
        )

    def test_manual_contract_exposes_typed_memory_through_runtime_adapter(self) -> None:
        address = {"op": "add32", "args": [_reg("eax"), _const(4)]}
        cluster = {
            "entry_rva": 0x4100,
            "inputs": [{"kind": "register", "name": "eax"}],
            "outputs": [{"kind": "register", "name": "ebx"}],
            "typed_contract": {
                "memory_views": [
                    {
                        "base": _reg("eax"),
                        "fields": [
                            {
                                "offset": 4,
                                "width_bytes": 4,
                                "accesses": ["read", "write"],
                                "observations": [{"address": address}],
                            }
                        ],
                    }
                ],
                "atomic_effects": [],
            },
        }

        header, _portable, adapter = _render_manual_contract(cluster, "replace_4100")

        self.assertIn("RECONSTRUCTED_INDIRECT_JUMP = 4", header)
        self.assertIn("uint32_t memory_view_00_p4;", header)
        self.assertIn("bool write_memory_view_00_p4;", header)
        self.assertIn(
            "inputs.memory_view_00_p4 = rt->read(rt->context, "
            "(state->eax + UINT32_C(0x00000004)), 4U, &memory_fault);",
            adapter,
        )
        self.assertIn("if (outputs.write_memory_view_00_p4)", adapter)
        self.assertIn("rt->write(rt->context", adapter)

    def test_manual_contract_does_not_lower_atomic_target_to_plain_memory(self) -> None:
        address = {"op": "add32", "args": [_reg("eax"), _const(4)]}
        cluster = {
            "typed_contract": {
                "memory_views": [
                    {
                        "base": _reg("eax"),
                        "fields": [
                            {
                                "offset": 4,
                                "width_bytes": 4,
                                "accesses": ["read", "write"],
                                "observations": [{"address": address}],
                            }
                        ],
                    }
                ],
                "atomic_effects": [{"target": {"address": address}}],
            }
        }

        self.assertEqual(_manual_memory_fields(cluster), [])

    def test_manual_contract_lowers_compare_exchange_through_atomic_runtime(self) -> None:
        address = _const(0x430324)
        load = {"op": "load", "address": address, "width": 4}
        cluster = {
            "entry_rva": 0x1050,
            "inputs": [{"kind": "register", "name": "ebx"}],
            "outputs": [{"kind": "register", "name": "eax"}],
            "typed_contract": {
                "memory_views": [],
                "atomic_effects": [
                    {
                        "operation": "compare_exchange",
                        "target": {"address": address, "width_bytes": 4},
                    }
                ],
            },
            "composition": {
                "summary_unit": {
                    "semantics": {
                        "memory_events": [
                            {
                                "kind": "write",
                                "address": address,
                                "width": 4,
                                "value": {
                                    "op": "ite",
                                    "args": [
                                        {"op": "eq", "args": [_const(0), load]},
                                        _reg("ebx"),
                                        load,
                                    ],
                                },
                            }
                        ]
                    }
                }
            },
        }

        header, _portable, adapter = _render_manual_contract(cluster, "replace_1050")

        self.assertIn("uint32_t atomic_00_observed;", header)
        self.assertIn("uint32_t atomic_00_exchanged;", header)
        self.assertIn("stage_b_runtime_atomic_compare_exchange(", adapter)
        self.assertNotIn("rt->atomic_compare_exchange(", adapter)
        self.assertIn("UINT32_C(0x00000000), state->ebx", adapter)

    def test_alias_descriptors_become_executable_register_placements(self) -> None:
        left = {"op": "add32", "args": [_reg("esp"), _const(80)]}
        right = {"op": "add32", "args": [_reg("ebx"), _const(8)]}
        contract = {
            "memory_views": [
                {
                    "id": "stack",
                    "base": _reg("esp"),
                    "fields": [
                        {"id": "stack-80", "offset": 80, "width_bytes": 4, "accesses": ["read"]}
                    ],
                },
                {
                    "id": "object",
                    "base": _reg("ebx"),
                    "fields": [
                        {"id": "object-8", "offset": 8, "width_bytes": 4, "accesses": ["read", "write"]}
                    ],
                },
            ]
        }
        generated = {
            "memory_cases": [
                {
                    "id": "alias",
                    "scenario": "alias_partial",
                    "placements": [
                        {
                            "relation": "right_base_equals_left_base_plus",
                            "byte_offset": 1,
                            "left_view_id": "stack-80",
                            "right_view_id": "object-8",
                        }
                    ],
                }
            ]
        }
        registers = {name: 0x70000000 for name in REGISTERS}
        flags = {name: 0 for name in FLAGS}

        cases = _executable_alias_cases(
            generated=generated, contract=contract, registers=registers, flags=flags
        )

        self.assertEqual(_affine_register_address(left), ("esp", 80))
        self.assertEqual(_affine_register_address(right), ("ebx", 8))
        self.assertEqual(len(cases), 1)
        values = cases[0]["registers"]
        self.assertEqual(
            (values["ebx"] + 8) & 0xFFFFFFFF,
            (values["esp"] + 81) & 0xFFFFFFFF,
        )

    def test_workspaces_compile_and_keep_portable_logic_out_of_machine_state(self) -> None:
        write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        compiler = shutil.which("cc")
        external_adapter_path = None
        for rva in (0x1000, 0x2000, 0x3000):
            workspace = create_reconstruction_workspace(
                plan=self.plan, machine_ir=self.machine_ir,
                interpreter_package=self.interpreter,
                entry_rva=rva, out_dir=self.root / f"workspace-{rva:x}",
            )
            if rva == 0x2000:
                external_adapter_path = workspace.source
            metadata = json.loads(workspace.workspace.read_text(encoding="utf-8"))
            self.assertEqual(metadata["format"], RECONSTRUCTION_WORKSPACE_FORMAT)
            portable = metadata["source_boundaries"]["portable_logic"]
            lines = workspace.portable_source.read_text(encoding="ascii").splitlines()
            portable_text = "\n".join(lines[portable["line_start"] - 1:portable["line_end"]])
            self.assertNotIn("stage_b_machine_state", portable_text)
            self.assertNotIn("state->", portable_text)
            if compiler:
                for label, source in (
                    ("adapter", workspace.source),
                    ("portable", workspace.portable_source),
                ):
                    subprocess.run(
                        [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(self.interpreter), "-I", str(workspace.source.parent), "-c", str(source), "-o", str(self.root / f"{rva:x}-{label}.o")],
                        check=True, capture_output=True, text=True,
                    )

        self.assertIsNotNone(external_adapter_path)
        external_adapter = external_adapter_path.read_text(encoding="ascii")
        self.assertIn("UINT32_C(0x0000200a), 0U, 0U", external_adapter)
        self.assertNotIn("UINT32_C(0x00002000), 0U, 0U", external_adapter)

    def test_external_template_rejects_missing_instruction_event_binding(self) -> None:
        rows = _fixtures()
        external = next(row for row in rows if row["source"]["original"]["rva_start"] == 0x2000)
        external["semantics"]["ordered_events"] = []
        package = self.root / "unbound-machine-ir"
        package.mkdir()
        (package / MACHINE_IR_FILENAME).write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        write_json(
            package / MACHINE_IR_MANIFEST_FILENAME,
            {"format": MACHINE_IR_FORMAT, "status": "qualified", "counts": {"units": len(rows)}},
        )
        plan = self.root / "unbound-plan.json"

        result = write_reconstruction_plan(machine_ir=package, out=plan)

        selected = {item["entry_rva"]: item for item in result["clusters"]}
        self.assertIsNone(selected[0x2000]["template"])

    def test_stale_plan_and_source_binding_fail_closed(self) -> None:
        write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        workspace = create_reconstruction_workspace(
            plan=self.plan, machine_ir=self.machine_ir, interpreter_package=self.interpreter,
            entry_rva=0x1000, out_dir=self.root / "workspace",
        )
        workspace.portable_source.write_text(
            workspace.portable_source.read_text(encoding="ascii") + "\n",
            encoding="ascii",
        )
        with self.assertRaises(StageAInputError):
            check_reconstruction_workspace(
                workspace=workspace.root,
                baseline_observations=self.root / "missing-a.json",
                replacement_observations=self.root / "missing-b.json",
            )
        rebound = rebind_reconstruction_workspace(workspace=workspace.root)
        support = {item["path"]: item for item in rebound.support_sources}
        self.assertEqual(
            support["src/implementation.c"]["sha256"],
            sha256_file(workspace.portable_source),
        )
        metadata = json.loads(workspace.workspace.read_text(encoding="utf-8"))
        self.assertEqual(
            metadata["bindings"]["replacement_manifest_sha256"],
            rebound.manifest_sha256,
        )
        self.assertEqual(
            metadata["source_boundaries"]["portable_logic"]["line_end"],
            len(workspace.portable_source.read_text(encoding="ascii").splitlines()),
        )

        machine_path = self.machine_ir / MACHINE_IR_FILENAME
        machine_path.write_text(machine_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        with self.assertRaises(StageAInputError):
            create_reconstruction_workspace(
                plan=self.plan, machine_ir=self.machine_ir, interpreter_package=self.interpreter,
                entry_rva=0x2000, out_dir=self.root / "stale",
            )

    def test_runner_detects_and_source_maps_a_portable_logic_mutation(self) -> None:
        from spaghetti_extractor.reconstruction_workspace import (
            build_reconstruction_regional_kernel,
            run_reconstruction_workspace_check,
        )

        if shutil.which("cc") is None:
            self.skipTest("cc is unavailable")
        write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        workspace = create_reconstruction_workspace(
            plan=self.plan, machine_ir=self.machine_ir,
            interpreter_package=self.interpreter, entry_rva=0x1000,
            out_dir=self.root / "workspace-runner",
        )
        kernel = self.root / "regional-kernel"
        build_reconstruction_regional_kernel(
            interpreter_package=self.interpreter, out_dir=kernel
        )
        report = run_reconstruction_workspace_check(
            workspace=workspace.root, interpreter_package=self.interpreter,
            out_dir=workspace.root / "check", regional_kernel=kernel,
        )
        self.assertEqual(report["status"], "qualified")
        source = workspace.portable_source
        text = source.read_text(encoding="ascii")
        self.assertEqual(text.count("left == right"), 1)
        source.write_text(text.replace("left == right", "left != right"), encoding="ascii")
        rebind_reconstruction_workspace(workspace=workspace.root)
        mutated = run_reconstruction_workspace_check(
            workspace=workspace.root, interpreter_package=self.interpreter,
            out_dir=workspace.root / "mutation-check", regional_kernel=kernel,
        )
        self.assertEqual(mutated["status"], "violated")
        locations = [item for delta in mutated["deltas"] for item in delta["repair_locations"]]
        self.assertTrue(locations)
        self.assertEqual(locations[0]["path"], "src/implementation.c")
        self.assertTrue(
            any("left != right" in line for line in locations[0]["edited"])
        )

    def test_regional_harness_follows_only_in_component_indirect_jumps(self) -> None:
        write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        workspace = create_reconstruction_workspace(
            plan=self.plan,
            machine_ir=self.machine_ir,
            interpreter_package=self.interpreter,
            entry_rva=0x1000,
            out_dir=self.root / "workspace-indirect-routing",
        )
        manifest = load_region_replacement_manifest(
            workspace.manifest, source_root=workspace.root
        )
        cases = json.loads(
            (workspace.root / "tests" / "cases.json").read_text(encoding="utf-8")
        )
        cases["address_space"] = {
            "kind": "pe32_image_rva_v1",
            "image_base": 0x400000,
            "size_of_image": 0x30000,
        }

        harness = _render_regional_harness(manifest, cases)

        self.assertIn("result.kind == STAGE_B_INDIRECT_JUMP", harness)
        self.assertIn(
            "const uint32_t image_base = UINT32_C(0x00400000);", harness
        )
        self.assertIn("image_address_to_rva(result.value, &indirect_rva)", harness)
        self.assertIn(
            "current = cluster_contains_rva(result.value) ? result.value : indirect_rva;",
            harness,
        )
        self.assertRegex(
            harness,
            r"if \(result\.kind == STAGE_B_INDIRECT_JUMP[\s\S]*?continue;[\s\S]*?return result;",
        )

        x87_harness = _render_regional_harness(
            manifest, cases, typed_x87_runtime=True
        )
        self.assertIn("harness_execute_typed_x87_operation", x87_harness)
        self.assertIn(
            "opaque, address, width, *exchanged ? desired : current, fault",
            harness,
        )
        self.assertIn(
            ".x87_stack = {"
            "{ .empty = 1U, .tag = 3U }",
            x87_harness,
        )
        self.assertIn(
            "baseline_runtime.execute_typed_x87_operation = "
            "harness_execute_typed_x87_operation;",
            x87_harness,
        )

        cases["address_space"]["size_of_image"] = 0
        with self.assertRaisesRegex(StageAInputError, "address space is invalid"):
            _render_regional_harness(manifest, cases)

    def test_regional_harness_scripts_external_responses_by_event_index(self) -> None:
        write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        workspace = create_reconstruction_workspace(
            plan=self.plan,
            machine_ir=self.machine_ir,
            interpreter_package=self.interpreter,
            entry_rva=0x2000,
            out_dir=self.root / "workspace-response-script",
        )
        manifest = load_region_replacement_manifest(
            workspace.manifest, source_root=workspace.root
        )
        cases = json.loads(
            (workspace.root / "tests" / "cases.json").read_text(encoding="utf-8")
        )
        cases["cases"][0]["external_responses"] = [
            {
                "eax": 0x11223344,
                "registers": {"esp": 0x70000020, "ecx": 0xAABBCCDD},
                "flags": {"cf": 1, "zf": 0},
                "memory_writes": [
                    {"argument_index": 0, "offset": 4, "bytes": "00112233"}
                ],
            },
            {
                "eax": 0x55667788,
                "memory_writes": [
                    {"stack_pointer_offset": 8, "offset": 0, "bytes": "aabb"}
                ],
            },
        ]

        harness = _render_regional_harness(manifest, cases)

        self.assertIn(
            "static const uint8_t response_0_0_write_0_bytes[] = { "
            "UINT8_C(0x00), UINT8_C(0x11), UINT8_C(0x22), UINT8_C(0x33) };",
            harness,
        )
        self.assertIn(
            "static const harness_response_write response_0_0_writes[] = { "
            "{ 0U, UINT32_C(0x00000000), UINT32_C(0x00000004), "
            "response_0_0_write_0_bytes, 4U } };",
            harness,
        )
        self.assertIn(
            "{ 1U, UINT32_C(0x00000008), UINT32_C(0x00000000), "
            "response_0_1_write_0_bytes, 2U }",
            harness,
        )
        self.assertIn("static const harness_response responses_0[]", harness)
        self.assertIn("if (event_index < context->response_count)", harness)
        self.assertIn(
            "if (response->register_mask & UINT32_C(0x80)) output->esp = response->registers[7];",
            harness,
        )
        self.assertIn(
            "if (response->flag_mask & UINT32_C(0x01)) output->cf = response->flags[0];",
            harness,
        )
        self.assertIn("UINT32_C(0x70000020)", harness)
        self.assertIn("UINT32_C(0xaabbccdd)", harness)
        self.assertIn("base = event->arguments[write->location_value];", harness)
        self.assertIn(
            "base = harness_read(context, input->esp + write->location_value, "
            "4U, &fault);",
            harness,
        )
        self.assertIn(
            "harness_write(context, address + byte_index, 1U, "
            "write->bytes[byte_index], &fault);",
            harness,
        )
        self.assertIn("context->write_overflow", harness)
        self.assertIn('printf("W %c %u %u %u\\n"', harness)
        self.assertIn('printf("B %c %u %u %u\\n"', harness)

        cases["cases"][0]["external_responses"][0]["memory_writes"][0][
            "argument_index"
        ] = 16
        with self.assertRaisesRegex(StageAInputError, "location is invalid"):
            _render_regional_harness(manifest, cases)

        cases["cases"][0]["external_responses"] = [
            {"eax": index} for index in range(20)
        ]
        expanded = _render_regional_harness(manifest, cases)
        self.assertIn("harness_event events[20];", expanded)
        self.assertIn("context->event_count >= 20U", expanded)
        self.assertIn("index < 20U", expanded)

        cases["cases"][0]["external_responses"] = [
            {"eax": index} for index in range(257)
        ]
        with self.assertRaisesRegex(StageAInputError, "more than 256"):
            _render_regional_harness(manifest, cases)

    def test_candidate_only_check_promotion_and_status(self) -> None:
        write_reconstruction_plan(machine_ir=self.machine_ir, out=self.plan)
        workspaces = []
        for rva in (0x1000, 0x2000, 0x3000):
            workspace = create_reconstruction_workspace(
                plan=self.plan, machine_ir=self.machine_ir, interpreter_package=self.interpreter,
                entry_rva=rva, out_dir=self.root / f"workspace-{rva:x}",
            )
            manifest = json.loads(workspace.manifest.read_text(encoding="utf-8"))
            observations = _observations(manifest)
            baseline = workspace.root / "baseline-observations.json"
            replacement = workspace.root / "replacement-observations.json"
            write_json(baseline, observations)
            write_json(replacement, observations)
            report = check_reconstruction_workspace(
                workspace=workspace.root,
                baseline_observations=baseline,
                replacement_observations=replacement,
            )
            self.assertEqual(report["status"], "qualified")
            self.assertFalse(report["executes_original_binary"])
            workspaces.append(workspace.root)

        parent_root = workspaces[0]
        child_root = workspaces[1]
        child_manifest = load_region_replacement_manifest(
            child_root / "region-replacement.json", source_root=child_root
        )
        child_support = {
            str(item["role"]): item for item in child_manifest.support_sources
        }
        dependency_root = (
            parent_root / "src" / "component-dependencies" / "child-component"
        )
        dependency_root.mkdir(parents=True)
        dependency_source = dependency_root / "implementation.c"
        dependency_header = dependency_root / "implementation.h"
        shutil.copyfile(
            child_root / str(child_support["portable_source"]["path"]),
            dependency_source,
        )
        shutil.copyfile(
            child_root / str(child_support["portable_header"]["path"]),
            dependency_header,
        )
        parent_manifest_path = parent_root / "region-replacement.json"
        parent_manifest = json.loads(parent_manifest_path.read_text(encoding="utf-8"))
        parent_manifest["support_sources"].extend(
            [
                {
                    "path": dependency_source.relative_to(parent_root).as_posix(),
                    "role": "adapter_support",
                    "sha256": sha256_file(dependency_source),
                },
                {
                    "path": dependency_header.relative_to(parent_root).as_posix(),
                    "role": "portable_header",
                    "sha256": sha256_file(dependency_header),
                },
            ]
        )
        write_json(parent_manifest_path, parent_manifest)
        rebound = rebind_reconstruction_workspace(workspace=parent_root)
        observations = _observations(rebound.to_payload())
        baseline = parent_root / "baseline-observations.json"
        replacement = parent_root / "replacement-observations.json"
        write_json(baseline, observations)
        write_json(replacement, observations)
        report = check_reconstruction_workspace(
            workspace=parent_root,
            baseline_observations=baseline,
            replacement_observations=replacement,
        )
        self.assertEqual(report["status"], "qualified")

        parent_only = self.root / "promoted-parent-only"
        parent_registry = promote_reconstruction_workspaces(
            workspaces=[parent_root], out_dir=parent_only
        )
        parent_promoted_manifest = load_region_replacement_manifest(
            parent_only / parent_registry["entries"][0]["manifest"],
            source_root=parent_only,
        )
        parent_support_paths = {
            str(item["path"]) for item in parent_promoted_manifest.support_sources
        }
        self.assertTrue(
            any(
                "component-dependencies/child-component/implementation.c" in path
                for path in parent_support_paths
            )
        )

        promoted = self.root / "promoted"
        registry = promote_reconstruction_workspaces(workspaces=workspaces, out_dir=promoted)
        self.assertEqual(registry["format"], RECONSTRUCTION_REGISTRY_FORMAT)
        self.assertEqual(registry["counts"]["replacements"], 3)
        aggregate_parent = next(
            item
            for item in registry["entries"]
            if item["id"] == parent_promoted_manifest.id
        )
        aggregate_parent_manifest = load_region_replacement_manifest(
            promoted / aggregate_parent["manifest"], source_root=promoted
        )
        self.assertFalse(
            any(
                "component-dependencies/child-component" in str(item["path"])
                for item in aggregate_parent_manifest.support_sources
            )
        )
        status_path = self.root / "status.json"
        status = write_reconstruction_status(
            plan=self.plan, registry=promoted / "reconstruction-registry.json", out=status_path
        )
        self.assertEqual(status["format"], RECONSTRUCTION_STATUS_FORMAT)
        self.assertEqual(status["counts"]["promoted_clusters"], 3)
        self.assertGreater(status["counts"]["remaining_clusters"], 0)
        self.assertEqual(status["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
