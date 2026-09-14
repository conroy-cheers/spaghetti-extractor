from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.formats import (
    BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
    BEHAVIORAL_C_PACKAGE_FORMAT,
)
from spaghetti_extractor.candidate.behavioral_c import (
    BehavioralCLayoutIntent,
    build_behavioral_c_plan,
    write_spx_behavioral_c_package,
)
from spaghetti_extractor.candidate.behavioral_c_render import (
    behavioral_c_header,
    behavioral_c_source,
    behavioral_c_translation_units,
)
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from spaghetti_extractor.transfer.model import (
    TransferPlanError,
    _Action,
    _Call,
    _Node,
    _Transfer,
)
from spaghetti_extractor.transfer.plan import write_executable_transfer_plan
from spaghetti_extractor.util import sha256_file
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit as _test_machine_ir_unit,
    transfer_row as _row,
)


def _transfer(rva: int, *, nodes=(), actions=(), calls=()) -> _Transfer:
    return _Transfer(
        identity=f"semantic-transfer:{rva:x}",
        contract_sha256="a" * 64,
        instruction_bytes_sha256="b" * 64,
        rva_start=rva,
        nodes=tuple(nodes),
        x87_nodes=(),
        actions=tuple(actions),
        calls=tuple(calls),
        x87_operations=(),
    )


class BehavioralCBackendTests(unittest.TestCase):
    def test_checked_nonlocal_propagates_to_exact_ancestor_in_compiled_c(
        self,
    ) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        register_and_flag_nodes = tuple(
            _Node("reg", aux=index) for index in range(8)
        ) + tuple(_Node("flag", aux=index) for index in range(6))
        call = _Call(
            kind="internal_call",
            instruction_rva=0x1000,
            call_index=0,
            target_node=None,
            target_rva=0x2000,
            return_rva=0x3000,
            dll=None,
            symbol=None,
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(),
            stack_inputs=(),
        )
        caller = _transfer(
            0x1000,
            nodes=register_and_flag_nodes,
            actions=(
                _Action("call", (0,)),
                _Action("outcome_fallthrough", (0x3000,)),
            ),
            calls=(call,),
        )
        callee = _transfer(
            0x2000,
            nodes=(
                _Node("const", immediate=0x3000),
                _Node("const", immediate=9),
            ),
            actions=(_Action("outcome_nonlocal", (0, 1)),),
        )
        continuation = _transfer(
            0x3000,
            nodes=(_Node("const", immediate=77),),
            actions=(
                _Action("set_reg", (0,), aux=0),
                _Action("outcome_return", (0,)),
            ),
        )
        transfers = (caller, callee, continuation)
        plan = build_behavioral_c_plan(
            transfers, entry_rvas=(0x1000, 0x2000)
        )
        translation_units, _source_map = behavioral_c_translation_units(
            transfers, plan
        )
        harness = r'''
#include "behavioral-c.h"

typedef struct fixture_context {
  uint32_t active;
  uint32_t first_route_seen;
  uint32_t ancestor_route_seen;
  uint32_t return_address;
} fixture_context;

static uint32_t fixture_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)opaque; (void)address; (void)width;
  *fault = 1U;
  return 0U;
}

static void fixture_write(
    void *opaque, uint32_t address, uint32_t width, uint32_t value,
    uint32_t *fault) {
  fixture_context *context = (fixture_context *)opaque;
  if (address != 0x00001000U || width != 4U) {
    *fault = 1U;
    return;
  }
  context->return_address = value;
  *fault = 0U;
}

static uint32_t fixture_route_nonlocal(
    spx_runtime *runtime, uint32_t source_rva, uint32_t target_rva,
    uint32_t value, uint32_t function_entry_rva,
    spx_machine_state *state, uint32_t *resume_rva) {
  fixture_context *context = (fixture_context *)runtime->context;
  (void)state;
  if (context->active == 0U) {
    if (source_rva != 0x00002000U || target_rva != 0x00003000U ||
        value != 9U || function_entry_rva != 0x00002000U)
      return 2U;
    context->active = 1U;
    context->first_route_seen = 1U;
    return 1U;
  }
  if (source_rva != 0x00001000U || target_rva != 0U || value != 0U ||
      function_entry_rva != 0x00001000U)
    return 2U;
  context->active = 0U;
  context->ancestor_route_seen = 1U;
  *resume_rva = 0x00003000U;
  return 0U;
}

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {
  (void)runtime; (void)event;
  if (input != 0 && output != 0) *output = *input;
  return SPX_CALL_UNIMPLEMENTED;
}

void spx_runtime_atomic_compare_exchange(
    spx_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t expected, uint32_t desired, uint32_t *observed,
    uint32_t *exchanged, uint32_t *fault) {
  (void)runtime; (void)address; (void)width; (void)expected; (void)desired;
  *observed = 0U; *exchanged = 0U; *fault = 1U;
}

void spx_runtime_atomic_exchange(
    spx_runtime *runtime, uint32_t address, uint32_t width,
    uint32_t desired, uint32_t *observed, uint32_t *fault) {
  (void)runtime; (void)address; (void)width; (void)desired;
  *observed = 0U; *fault = 1U;
}

int main(void) {
  fixture_context context = {0};
  spx_runtime runtime = {0};
  spx_machine_state input = {0}, output = {0};
  spx_call_status status;
  runtime.context = &context;
  runtime.image_base = 0x00400000U;
  runtime.read = fixture_read;
  runtime.write = fixture_write;
  runtime.route_nonlocal = fixture_route_nonlocal;
  input.esp = 0x00001004U;
  status = spx_behavioral_run(&runtime, 0x00001000U, &input, &output);
  return !(
      status == SPX_CALL_OK && output.eax == 77U &&
      output.esp == input.esp &&
      context.active == 0U && context.first_route_seen == 1U &&
      context.ancestor_route_seen == 1U &&
      context.return_address == 0x00403000U);
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "state-machine-runtime.h").write_text(
                exact_runtime_header(), encoding="ascii"
            )
            (root / "behavioral-c.h").write_text(
                behavioral_c_header(plan), encoding="ascii"
            )
            for filename, source in translation_units.items():
                (root / filename).write_text(source, encoding="ascii")
            (root / "harness.c").write_text(harness, encoding="ascii")
            executable = root / "checked-nonlocal"
            compile_result = subprocess.run(
                [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root),
                    *(str(root / filename) for filename in translation_units),
                    str(root / "harness.c"), "-o", str(executable),
                ],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(
                compile_result.returncode, 0, compile_result.stderr
            )
            subprocess.run(
                [str(executable)], check=True, capture_output=True, text=True
            )

    def test_renders_direct_control_without_semantic_program_tables(self) -> None:
        rows = (
            _transfer(
                0x1000,
                nodes=(_Node("reg", aux=0), _Node("const", immediate=0), _Node("eq", (0, 1))),
                actions=(
                    _Action("eval_word", (2,)),
                    _Action("outcome_branch", (2, 0x1010, 0x1020)),
                ),
            ),
            _transfer(
                0x1010,
                nodes=(_Node("const", immediate=7),),
                actions=(
                    _Action("eval_word", (0,)),
                    _Action("outcome_return", (0,)),
                ),
            ),
            _transfer(
                0x1020,
                nodes=(_Node("const", immediate=9),),
                actions=(
                    _Action("eval_word", (0,)),
                    _Action("outcome_return", (0,)),
                ),
            ),
        )
        plan = build_behavioral_c_plan(rows, entry_rvas=(0x1000,))

        source, spans = behavioral_c_source(rows, plan)

        self.assertEqual(len(plan.functions), 1)
        self.assertEqual(set(spans), {0x1000, 0x1010, 0x1020})
        self.assertIn("if (w_00001000_2) goto spx_unit_00001010", source)
        self.assertEqual(source.count("input = *state;"), 3)
        self.assertNotIn("spx_word_node", source)
        self.assertNotIn("spx_program_transfer", source)
        self.assertNotIn("word_valid", source)

    def test_atomic_observation_is_materialized_only_by_one_rmw(self) -> None:
        row = _transfer(
            0x2000,
            nodes=(
                _Node("const", immediate=0x430320),
                _Node("reg", aux=3),
                _Node("load", (0,), aux=4),
            ),
            actions=(
                _Action("eval_word", (0,)),
                _Action("eval_word", (1,)),
                _Action("atomic_exchange", (0, 1, 2), aux=4),
                _Action("set_reg", (2,), aux=3),
                _Action("sync_eflags"),
                _Action("outcome_return", (2,)),
            ),
        )
        plan = build_behavioral_c_plan((row,), entry_rvas=(0x2000,))

        source, _spans = behavioral_c_source((row,), plan)

        self.assertEqual(source.count("spx_runtime_atomic_exchange("), 1)
        self.assertNotIn("spx_read(rt", source)
        self.assertIn("state->edx = w_00002000_2;", source)

    def test_auxiliary_carry_is_rendered_in_the_physical_eflags_word(self) -> None:
        row = _transfer(
            0x2050,
            nodes=(_Node("true"), _Node("const", immediate=0)),
            actions=(
                _Action("set_flag", (0,), aux=6),
                _Action("sync_eflags"),
                _Action("outcome_return", (1,)),
            ),
        )
        plan = build_behavioral_c_plan((row,), entry_rvas=(0x2050,))

        source, _spans = behavioral_c_source((row,), plan)

        self.assertIn(
            "state->eflags = (state->eflags & ~(1U << 4U)) |",
            source,
        )
        self.assertIn("((w_00002050_0) & 1U) << 4U", source)

    def test_access_violation_uses_the_canonical_runtime_projection(self) -> None:
        row = _transfer(
            0x2100,
            nodes=(
                _Node("true"),
                _Node("const", immediate=1),
                _Node("const", immediate=0x1BADB002),
                _Node("const", immediate=0),
            ),
            actions=(
                _Action("access_violation_if", (0, 1, 2), aux=0),
                _Action("outcome_return", (3,)),
            ),
        )
        plan = build_behavioral_c_plan((row,), entry_rvas=(0x2100,))

        source, _spans = behavioral_c_source((row,), plan)

        self.assertIn("rt->record_access_violation == 0", source)
        self.assertIn(
            "rt->record_access_violation(rt->context, "
            "w_00002100_1, w_00002100_2)",
            source,
        )
        self.assertIn("SPX_MEMORY_FAULT", source)

    def test_nested_call_fault_preserves_exact_original_rva(self) -> None:
        nodes = tuple(
            _Node("reg", aux=index) for index in range(8)
        ) + tuple(_Node("flag", aux=index) for index in range(6))
        call = _Call(
            kind="internal_call",
            instruction_rva=0x1000,
            call_index=0,
            target_node=None,
            target_rva=0x2000,
            return_rva=0x1001,
            dll=None,
            symbol=None,
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(),
            stack_inputs=(),
        )
        caller = _transfer(
            0x1000,
            nodes=nodes,
            actions=(
                _Action("call", (0,)),
                _Action("outcome_return", (0,)),
            ),
            calls=(call,),
        )
        callee = _transfer(
            0x2000,
            nodes=(_Node("true"), _Node("const", immediate=0)),
            actions=(
                _Action("divide_if", (0,), aux=0),
                _Action("outcome_return", (1,)),
            ),
        )
        plan = build_behavioral_c_plan(
            (caller, callee), entry_rvas=(0x1000,)
        )

        source, _spans = behavioral_c_source((caller, callee), plan)

        self.assertIn(
            "return spx_call_status_result(status, state->original_rva);",
            source,
        )

    def test_indirect_outcome_uses_exact_last_transfer_site(self) -> None:
        row = _transfer(
            0x1000,
            nodes=(_Node("reg", aux=0),),
            actions=(_Action("outcome_indirect", (0,)),),
        )
        plan = build_behavioral_c_plan((row,), entry_rvas=(0x1000,))

        source, _spans = behavioral_c_source((row,), plan)

        self.assertIn("state.original_rva = rva;", source)
        self.assertIn(
            "result.kind == SPX_NONLOCAL && result.target_rva == 0U",
            source,
        )
        self.assertIn(
            "SPX_CODE_SITE_INDIRECT_JUMP, source_rva, source_rva, 0U,",
            source,
        )
        self.assertIn(
            "rt, source_rva, result.value, &state, &external_output",
            source,
        )

    def test_exception_capable_call_selects_exact_instruction_portal(self) -> None:
        nodes = tuple(
            _Node("reg", aux=index) for index in range(8)
        ) + tuple(_Node("flag", aux=index) for index in range(6))
        call = _Call(
            kind="external_call",
            instruction_rva=0x1004,
            call_index=0,
            target_node=None,
            target_rva=0,
            return_rva=0x1009,
            dll="kernel32.dll",
            symbol="RaiseException",
            ordinal=None,
            register_nodes=tuple(range(8)),
            flag_nodes=tuple(range(8, 14)),
            argument_nodes=(),
            stack_inputs=(),
            native_exception_operations=("divide_if",),
        )
        transfer = _transfer(
            0x1000,
            nodes=nodes,
            actions=(
                _Action("call", (0,)),
                _Action("outcome_return", (0,)),
            ),
            calls=(call,),
        )
        plan = build_behavioral_c_plan((transfer,), entry_rvas=(0x1000,))

        source, _spans = behavioral_c_source((transfer,), plan)

        self.assertIn("call_input.original_rva = 0x00001004U;", source)
        self.assertIn(
            "if (status != SPX_CALL_OK) {\n"
            "      *state = call_output;\n"
            "      return spx_call_status_result(status, state->original_rva);",
            source,
        )
        self.assertIn(
            "*state = call_output;\n"
            "    state->original_rva = 0x00001000U;",
            source,
        )

    def test_package_emits_exact_coverage_and_compiler_consumable_c(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(_test_machine_ir_unit(_row()), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            unit = _test_machine_ir_unit(_row())
            source = unit["source"]
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps({
                "format": unit["format"],
                "record_kind": "manifest",
                "binary": {"sha256": "f" * 64},
                "artifacts": {
                    "machine_ir": {"sha256": sha256_file(machine_ir)},
                },
                "counts": {"units": 1},
                "source_map": [{
                    "unit_id": unit["id"],
                    "rva_start": source["original"]["rva_start"],
                    "contract_sha256": source["contract_sha256"],
                }],
            }, sort_keys=True), encoding="utf-8")
            write_executable_transfer_plan(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                out=root / "transfer",
            )

            package = write_spx_behavioral_c_package(
                transfer_plan=root / "transfer/executable-transfer-plan.json",
                out=root / "out",
                entry_rvas=(0x1000,),
            )

            self.assertEqual(package["format"], BEHAVIORAL_C_PACKAGE_FORMAT)
            self.assertEqual(package["status"], "ready")
            self.assertNotIn("completion_status", package)
            self.assertEqual(package["counts"]["required_units"], 1)
            self.assertFalse(package["constraints"]["runtime_instruction_decoder"])
            self.assertNotIn("runtime_qualification", package["artifacts"])
            self.assertNotIn("completion", package["artifacts"])
            self.assertFalse(
                (root / "out" / "behavioral-c-completion.json").exists()
            )
            self.assertFalse(
                (root / "out" / "behavioral-c-runtime-qualification.json").exists()
            )
            function_sources = sorted(
                (root / "out").glob("behavioral-fn-*.c")
            )
            self.assertEqual(len(function_sources), 1)
            self.assertTrue((root / "out" / "behavioral-dispatch.c").is_file())
            support_source = root / "out" / "behavioral-support.c"
            self.assertTrue(support_source.is_file())
            self.assertNotIn(
                "uint32_t spx_mask(",
                function_sources[0].read_text(encoding="ascii"),
            )
            self.assertEqual(
                support_source.read_text(encoding="ascii").count(
                    "uint32_t spx_mask("
                ),
                1,
            )
            dispatch_source = (
                root / "out" / "behavioral-dispatch.c"
            ).read_text(encoding="ascii")
            self.assertIn("spx_call_status spx_invoke_call(", dispatch_source)
            self.assertIn("status = spx_behavioral_run(", dispatch_source)
            self.assertIn(
                "if (status == SPX_CALL_NONLOCAL)\n"
                "      output->esp = input->esp;",
                dispatch_source,
            )
            self.assertIn("call_input.esp -= 4U;", dispatch_source)
            self.assertIn(
                "return_address = rt->image_base + event->return_rva;",
                dispatch_source,
            )
            self.assertIn(
                "rt->write(rt->context, call_input.esp, 4U, return_address, &fault);",
                dispatch_source,
            )
            source_map = json.loads(
                (root / "out" / "behavioral-c-source-map.json").read_text()
            )
            self.assertEqual(source_map["units"][0]["file"], function_sources[0].name)
            build_manifest = json.loads(
                (root / "out" / "behavioral-c-build-manifest.json").read_text()
            )
            self.assertEqual(build_manifest["function_translation_unit_count"], 1)
            self.assertEqual(
                build_manifest["shared_support_translation_unit_count"], 1
            )
            coverage = json.loads(
                (root / "out" / "behavioral-c-coverage.json").read_text()
            )
            self.assertEqual(
                coverage["operation_coverage"]["status"], "complete"
            )
            compiler = shutil.which("cc")
            if compiler is not None:
                for index, source_file in enumerate(
                    [
                        *function_sources,
                        root / "out" / "behavioral-dispatch.c",
                        support_source,
                    ]
                ):
                    subprocess.run([
                        compiler,
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        str(root / "out"),
                        "-c",
                        str(source_file),
                        "-o",
                        str(root / f"behavioral-c-{index}.o"),
                    ], check=True, capture_output=True, text=True)

    def test_layout_intent_cannot_invent_machine_units(self) -> None:
        row = _transfer(
            0x1000,
            nodes=(_Node("const", immediate=0),),
            actions=(_Action("outcome_return", (0,)),),
        )
        intent = BehavioralCLayoutIntent.from_payload(
            {
                "format": BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
                "roots": [0xDEAD],
                "names": {},
                "forced_labels": [],
            }
        )

        with self.assertRaises(TransferPlanError) as caught:
            build_behavioral_c_plan((row,), intent=intent)

        self.assertEqual(caught.exception.code, "behavioral_c_layout_unknown_rva")

    def test_forced_label_is_a_step_barrier_without_changing_run_semantics(self) -> None:
        first = _transfer(
            0x1000,
            actions=(_Action("outcome_fallthrough", (0x1010,)),),
        )
        second = _transfer(
            0x1010,
            nodes=(_Node("const", immediate=7),),
            actions=(
                _Action("set_reg", (0,), aux=0),
                _Action("outcome_return", (0,)),
            ),
        )
        intent = BehavioralCLayoutIntent.from_payload(
            {
                "format": BEHAVIORAL_C_LAYOUT_INTENT_FORMAT,
                "roots": [0x1000],
                "names": {},
                "forced_labels": [0x1010],
            }
        )
        plan = build_behavioral_c_plan((first, second), intent=intent)

        source, _spans = behavioral_c_source((first, second), plan)

        self.assertIn(
            "return (spx_step_result){ SPX_FALLTHROUGH, 0x00001010U, 0U };",
            source,
        )
        self.assertIn(
            "if (result.kind <= SPX_BRANCH) { rva = result.target_rva; continue; }",
            source,
        )


if __name__ == "__main__":
    unittest.main()
