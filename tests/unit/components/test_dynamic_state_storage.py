"""Frame-relative state uses the same addresses in production and proof."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation_harness import _exit_comparisons, _projection_expression, _source_storage_initialization
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.machine_overlay_v5 import _projection_read, render_component_machine_overlay_v5
from spaghetti_extractor.components.machine_storage import scalar_storage_address
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract
from spaghetti_extractor.transfer.model import _Action, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def memory_projection(phase: str = "entry", register: str = "ebp", offset: int = -4) -> dict:
    return {"kind": "memory", "width": 32, "access": "read_write", "at": phase,
            "address": {"kind": "offset", "offset_bytes": offset, "at": phase,
                        "base": {"kind": "register", "register": register, "width": 32, "at": phase}}}


def state_fixture(unit_id: str = "unit"):
    schema = BoundarySchemaV1.create(schema_id="counter", types=[
        {"id": "unit", "kind": "void"},
        {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
        {"id": "run.fn", "kind": "function", "calling_convention": "cdecl",
         "parameter_type_ids": [], "result_type_id": "unit", "variadic": False}],
        signatures=[{"id": "run", "function_type_id": "run.fn", "parameters": [], "results": []}])
    value = {"id": "count", "type_id": "u32", "interpretation": "value", "access": "none",
             "nullable": False, "provider_domain": None, "resource_kind": None,
             "extent": {"kind": "none", "bytes": None, "value_id": None}}
    interface = ComponentInterfaceIntentV1.create(component_id="counter", schema=schema,
        state=[{"value": value, "initial": 0}], effects=[], services=[],
        protocol_states=["ready"], initial_protocol_state="ready", operations=[{
            "id": "run", "signature_id": "run", "source_values": [], "projection_entries": [],
            "lifecycle_bindings": [], "lifecycle_additional_roots": {"state": []},
            "checked_interaction_contract_ids": [], "effect_ids": [], "allowed_service_ids": [],
            "pre_states": ["ready"], "post_states": ["ready"]}])
    projection = {"operation_id": "run", "entry_unit_ids": [unit_id], "exit_unit_ids": [unit_id],
                  "parameters": [], "results": [], "state": [{"id": "count",
                    "entry": memory_projection(), "exit": memory_projection("exit")}],
                  "preserved_state_ids": [], "effects": [], "callback_operation_ids": [],
                  "continuation_unit_ids": []}
    binding = ComponentMachineBindingIntentV1.create(component_id="counter", blockers=[], operations=[{
        "id": "run", "kind": "operation", "unit_ids": [unit_id], "entry_rvas": [4096],
        "transfer_ids": [unit_id], "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": projection, "service_bindings": []},
        "object_authority_selectors": [], "pointer_views": [], "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None}])
    bundle = compile_component_interface_v5(interface)
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    transfer = _Transfer(unit_id, "a" * 64, "b" * 64, 4096, (), (),
                         (_Action("outcome_fallthrough", (4097,)),), (), ())
    overlay = render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        operation_symbols={"run": "authored_run"}, transfers=[transfer])
    return bundle, overlay


class DynamicStateStorageTests(unittest.TestCase):
    def test_register_relative_view_uses_an_address_not_a_memory_read(self) -> None:
        for displacement in (-4, 0, (1 << 31) - 1, -(1 << 31)):
            projection = memory_projection(offset=displacement)["address"]
            address = _projection_read(projection)
            proof = _projection_expression(projection, state="(*state)", read="unexpected_read")
            self.assertEqual(address, proof)
            with self.subTest(displacement=displacement), tempfile.TemporaryDirectory() as temporary:
                source = "#include <stdint.h>\n" + exact_runtime_header() + '''
int main(void) {
  spx_machine_state storage;
  spx_machine_state *state = &storage;
  uint64_t wide = (uint64_t)state->ebp + UINT64_C(4294967296);
''' + f"  wide = wide {'+' if displacement >= 0 else '-'} UINT64_C({abs(displacement)});\n" + '''
  __CPROVER_assert(ADDRESS == (uint32_t)(wide % UINT64_C(4294967296)), "modular-view-address");
}
'''.replace("ADDRESS", address)
                self._cbmc(Path(temporary), source)
        for mutation in ("phase", "narrow", "nested", "large"):
            projection = memory_projection()["address"]
            if mutation == "phase": projection["base"]["at"] = "exit"
            if mutation == "narrow": projection["base"]["width"] = 16
            if mutation == "nested": projection["base"] = copy.deepcopy(projection)
            if mutation == "large": projection["offset_bytes"] = 1 << 32
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                _projection_read(projection)
            with self.subTest(proof=mutation), self.assertRaises(ValueError):
                _projection_expression(projection, state="state", read="read")
        with self.assertRaises(ValueError):
            _projection_read(memory_projection("exit")["address"])

    def test_generated_adapter_compiles_with_host_and_pe32_compilers(self) -> None:
        bundle, overlay = state_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in render_component_c_headers_v5(bundle, {"run": "authored_run"}).items():
                (root / name).write_text(content)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            path = root / "overlay.c"
            path.write_text(overlay.source)
            for name in ("cc", "i686-w64-mingw32-cc"):
                compiler = shutil.which(name)
                if compiler is None:
                    self.skipTest(f"compiler unavailable: {name}")
                result = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(root), "-c", str(path), "-o", str(root / (name + ".o"))],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_adapter_and_proof_reject_bad_phase_width_and_storage_shape(self) -> None:
        for mutation in ("phase", "width", "access", "register_width", "offset", "nested"):
            value = memory_projection()
            if mutation == "phase": value["address"]["base"]["at"] = "exit"
            if mutation == "width": value["width"] = 64
            if mutation == "access": value["access"] = "read"
            if mutation == "register_width": value["address"]["base"]["width"] = 16
            if mutation == "offset": value["address"]["offset_bytes"] = 1 << 40
            if mutation == "nested": value["address"]["base"] = copy.deepcopy(value["address"])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                scalar_storage_address(value, state="state", image_base="base", phase="entry")
            with self.subTest(proof=mutation), self.assertRaises(ValueError):
                _projection_expression(value, state="state", read="read_word")

    def _cbmc(self, root: Path, source: str, *, expect_pass: bool = True) -> dict:
        compiler = shutil.which("cbmc")
        if compiler is None:
            self.skipTest("CBMC unavailable")
        path = root / "check.c"
        path.write_text(source)
        completed = subprocess.run([compiler, str(path), "-I", str(root), "--function", "main",
            "--bounds-check", "--pointer-check", "--signed-overflow-check", "--unwind", "4",
            "--unwinding-assertions", "--json-ui"], capture_output=True, text=True, timeout=60)
        report = json.loads(completed.stdout)
        failures = [row for message in report for row in message.get("result", []) if row["status"] == "FAILURE"]
        self.assertEqual(completed.returncode, 0 if expect_pass else 10, completed.stderr + str(failures))
        return {"failures": failures}

    def test_generated_adapter_arbitrary_frame_import_export_faults_and_alias(self) -> None:
        bundle, overlay = state_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in render_component_c_headers_v5(bundle, {"run": "authored_run"}).items():
                (root / name).write_text(content)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "overlay.c").write_text(overlay.source)
            source = r'''
#include "state-machine-runtime.h"
#include "portable-component-implementation.h"
typedef struct { uint32_t address, word, other, calls, writes, read_fault, write_fault; spx_machine_state *state; } model;
static model data;
static uint32_t read_word(void *unused, uint32_t address, uint32_t width, uint32_t *fault) {
  (void)unused; __CPROVER_assert(width == 4U, "word-width");
  if (data.read_fault) { *fault = 1U; return 0U; }
  return address == data.address ? data.word : data.other;
}
static void write_word(void *unused, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  (void)unused; __CPROVER_assert(width == 4U, "word-width"); ++data.writes;
  if (data.write_fault) { *fault = 1U; return; }
  if (address == data.address) data.word = value; else data.other = value;
}
void authored_run(spx_counter_context_v5 *context) {
  ++data.calls;
  /* MUTATION */
  context->state.count += 1U;
}
#include "overlay.c"
int main(void) {
  spx_machine_state state;
  uint32_t before, untouched;
  data.address = state.ebp - 4U; data.word = before; data.other = untouched;
  data.state = &state;
  spx_runtime rt = {0}; rt.read = read_word; rt.write = write_word;
  /* FAULT */
  spx_step_result result = spx_component_counter_00001000(&rt, &state);
  /* ASSERTIONS */
  return 0;
}
'''
            for mode in ("normal", "read_fault", "write_fault", "moved_frame", "alias"):
                with self.subTest(mode=mode):
                    mutation = "data.state->ebp += 4U;" if mode == "moved_frame" else "data.word += 5U;" if mode == "alias" else ""
                    fault = f"data.{mode} = 1U;" if mode in {"read_fault", "write_fault"} else ""
                    if mode in {"normal", "alias"}:
                        assertion = ('__CPROVER_assert(result.kind == SPX_FALLTHROUGH, "completed");'
                                     f'__CPROVER_assert(data.word == before + {6 if mode == "alias" else 1}U, "state-result");'
                                     '__CPROVER_assert(data.other == untouched, "frame-outside-word");')
                    else:
                        kind = "SPX_UNIMPLEMENTED" if mode == "moved_frame" else "SPX_MEMORY_FAULT"
                        assertion = f'__CPROVER_assert(result.kind == {kind}, "failure-propagates");'
                        assertion += '__CPROVER_assert(data.word == before && data.other == untouched, "failed-word-unchanged");'
                        if mode != "write_fault": assertion += '__CPROVER_assert(data.writes == 0U, "no-write-before-admission");'
                        if mode == "read_fault": assertion += '__CPROVER_assert(data.calls == 0U, "no-source-before-read");'
                    report = self._cbmc(root, source.replace("/* MUTATION */", mutation).replace(
                        "/* FAULT */", fault).replace("/* ASSERTIONS */", assertion), expect_pass=mode != "alias")
                    if mode == "alias":
                        self.assertTrue(any(row["description"] == "state-result" for row in report["failures"]))

    def test_cut_reconstruction_checks_address_and_shared_memory(self) -> None:
        projection = memory_projection()
        lines = "\n".join(_source_storage_initialization(projection, "expected"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = '''#include <stdint.h>
typedef struct { uint32_t ebp; } frame;
static uint32_t observed;
static uint32_t spx_proof_source_output_read(uint32_t address, uint32_t width) { (void)address; (void)width; return observed; }
int main(void) {
 frame initial_state; frame source_state = initial_state;
 uint32_t expected; observed = expected;
 /* MUTATION */
''' + lines + "\nreturn 0; }\n"
            self._cbmc(root, source)
            for mutation, failure in (("source_state.ebp += 4U;", "address"), ("observed ^= 1U;", "memory")):
                result = self._cbmc(root, source.replace("/* MUTATION */", mutation), expect_pass=False)
                self.assertTrue(any(row["description"] == f"spx-bisimulation-source-state-{failure}-preserved"
                                    for row in result["failures"]))

    def test_cut_reconstructs_register_relative_view_base_modulo_32_bits(self) -> None:
        for offset in (-2147483648, -4, 0, 2147483647):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as temporary:
                projection = memory_projection(offset=offset)["address"]
                lines = "\n".join(_source_storage_initialization(projection, "logical_address"))
                source = '''#include <stdint.h>
typedef struct { uint32_t ebp, esi; } frame;
int main(void) {
  frame source_state;
  uint32_t original_base, other_register = source_state.esi;
''' + f"  uint32_t logical_address = (uint32_t)((uint64_t)original_base + UINT64_C({offset & 0xffffffff}));\n" + lines + '''
  __CPROVER_assert(source_state.ebp == original_base, "reconstructed-base");
  __CPROVER_assert(source_state.esi == other_register, "other-register-preserved");
  return 0;
}
'''
                self._cbmc(Path(temporary), source)
        projection = memory_projection()["address"]
        invalid = [
            {**projection, "at": "exit"},
            {**projection, "offset_bytes": 2147483648},
            {**projection, "base": {**projection["base"], "width": 16}},
            {**projection, "base": {**projection["base"], "at": "exit"}},
            {**projection, "base": projection},
        ]
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(ValueError):
                _source_storage_initialization(row, "logical_address")

    def test_equal_exit_words_at_different_frame_addresses_do_not_match(self) -> None:
        comparisons = _exit_comparisons({"results": [], "state": [{
            "id": "count", "entry": memory_projection(), "exit": memory_projection("exit")}]})
        checks = "\n".join(f'__CPROVER_assert(({row["left"]}) == ({row["right"]}), "{row["id"]}");'
                           for row in comparisons)
        source = '''#include <stdint.h>
typedef struct { uint32_t ebp; } frame;
static uint8_t spx_proof_exact_byte(uint32_t address) { (void)address; return 7U; }
static uint8_t spx_proof_source_byte(uint32_t address) { (void)address; return 7U; }
int main(void) {
 frame source_state; frame spx_proof_exact_output = source_state;
 spx_proof_exact_output.ebp += 4U;
''' + checks + "\nreturn 0; }\n"
        with tempfile.TemporaryDirectory() as temporary:
            result = self._cbmc(Path(temporary), source, expect_pass=False)
            self.assertEqual([row["description"] for row in result["failures"]], ["state-address:count"])
            wrapped = source.replace("spx_proof_exact_output.ebp += 4U;",
                                     "source_state.ebp = 2U; spx_proof_exact_output = source_state;")
            self._cbmc(Path(temporary), wrapped)
            mismatched = wrapped.replace(
                "spx_proof_source_byte(uint32_t address) { (void)address; return 7U; }",
                "spx_proof_source_byte(uint32_t address) { return address == 0U ? 8U : 7U; }")
            result = self._cbmc(Path(temporary), mismatched, expect_pass=False)
            self.assertEqual([row["description"] for row in result["failures"]], ["state:count"])
