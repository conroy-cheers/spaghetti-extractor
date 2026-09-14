"""Execute generated service thunks against the actual proof reference world."""
from __future__ import annotations

from dataclasses import replace
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_typed_services import build_typed_proof_service_thunk_renderer
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json",)}


class ServicePreconditionTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[3]
        self.bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
            json.loads((root / TESTKIT["resources"][0]).read_text())))
        self.interface = ProofKernelComponentInterface.parse(_logical_projection(self.bundle))
        self.binding = {
            "service_id": "find_last_character", "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "symbol": "find_character", "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0, 4],
            "argument_transducers": [{"kind": "logical_argument", "parameter_index": i}
                                     for i in range(2)],
            "result_projection": {"kind": "reference",
                "authority": {"id": "argv_string", "kind": "process", "lifetime": "process"},
                "requested_extent": {"kind": "constant", "value": 1, "width": 32},
                "source": {"kind": "register", "register": "eax", "width": 32, "at": "call"},
                "at": "call"},
            "events": [{"instruction_rva": 100, "event_index": 0, "return_rva": 105}],
        }

    def _thunk(self, relation_evidence=()):
        renderer = build_typed_proof_service_thunk_renderer(
            interface=self.interface, service_bindings=[self.binding], relation_evidence=relation_evidence)
        return "\n".join(renderer(self.bundle, self.binding, {"argv_string": "argv-rule"}))

    def _check(self, mutation="", *, after="", erase=False):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        if erase:
            with patch("spaghetti_extractor.components.bisimulation_typed_services.borrowed_input_checks",
                       side_effect=lambda **kw: [
                           f"  uint32_t spx_typed_input_{kw['parameter_index']}_address = "
                           f"(uint32_t)({kw['logical']}->base.object + {kw['logical']}->base.offset);"]):
                thunk = self._thunk()
        else:
            thunk = self._thunk()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for name, content in render_component_c_headers_v5(self.bundle, {"select": "select"}).items():
                (root / name).write_text(content)
            source = root / "service.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                '#include "portable-component-implementation.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + _world_source(
                    max_writes=4, max_private_writes=1, max_calls=1, max_atomics=1,
                    max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
                ) + '''
typedef struct {
  spx_runtime *runtime;
  spx_machine_state *state;
  uint32_t *memory_fault, *service_fault;
} spx_component_service_context_v1;
uint32_t spx_component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  if (rt->read == 0) { *fault = 1U; return 0U; }
  return rt->read(rt->context, address, width, fault);
}
/* Observe admission at the real generated thunk boundary. The callee result is
   canonical null so these tests need no unrelated strrchr result semantics. */
#define spx_proof_typed_service_begin test_begin
#define spx_proof_typed_service_argument test_argument
#define spx_proof_typed_service_result test_result
#define spx_proof_typed_service_finish test_finish
uint32_t admitted;
void test_begin(void *context, uint32_t spec) { ++admitted; }
void test_argument(uint32_t index, uint32_t value) {
  if (index == 0U) __CPROVER_assert(value == 4100U, "interior address reaches service");
}
uint32_t test_result(void) { return 0U; }
void test_finish(void) {}
''' + thunk + '''
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_state state = {0};
  uint32_t memory_fault = 0, service_fault = 0;
  spx_component_service_context_v1 service = {&runtime, &state, &memory_fault, &service_fault};
  spx_machine_reference_v1 issued;
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4096U, 16U,
      1U, 0, 0U, 0U, &issued) == SPX_BOUNDARY_OK, "issue original view");
  spx_view_v5 view = {0};
  view.base = (spx_ref_v1){1, 4096, 1, 4, 16, 1};
  view.extent = 12; view.element_width = 1;
  spx_proof_source_write(0, 4111U, 1U, 0U, &memory_fault);
''' + mutation + '''
  find_character(&service, &view, 47U);
''' + after + '''
  __CPROVER_assert(admitted == 1U && service_fault == 0U && memory_fault == 0U,
      "borrowed service admitted");
}
''')
            return run_cbmc_properties(command=[cbmc, str(source), "--json-ui", "--trace",
                "--unwind", "3", "--unwinding-assertions", "--bounds-check",
                "--pointer-check", "--signed-overflow-check", "--sat-solver", "cadical"],
                timeout_seconds=30)

    def test_current_terminator_and_interior_origin_are_admitted(self):
        for mutation in ("", "spx_proof_source_write(0, 4100U, 1U, 0U, &memory_fault);",
                         "spx_proof_source_write(0, 4111U, 1U, 7U, &memory_fault);\n"
                         "spx_proof_source_write(0, 4111U, 1U, 0U, &memory_fault);"):
            with self.subTest(mutation=mutation):
                result = self._check(mutation)
                self.assertEqual(result["status"], "satisfied", result)

    def test_invalid_origins_never_reach_the_service(self):
        for mutation in ("view.base.generation = 2;", "view.base.domain = 2;",
                         "view.base.permissions = 0;", "view.base.permissions = 3;",
                         "view.base.extent = 32;", "view.base.offset = 16; view.extent = 0;",
                         "view.extent = 13;", "runtime.realize_reference = 0;"):
            with self.subTest(mutation=mutation):
                result = self._check(mutation)
                self.assertEqual(result["status"], "violated", result)
                self.assertIn("typed-service-reference:find_character:0", result["detail"])
        mutant = self._check("view.base.generation = 2;", erase=True)
        self.assertEqual(mutant["status"], "satisfied", mutant)

    def test_termination_is_checked_in_current_memory_and_visible_extent(self):
        repair = "spx_proof_source_write(0, 4111U, 1U, 0U, &memory_fault);"
        overwrite = "spx_proof_source_write(0, 4111U, 1U, 7U, &memory_fault);"
        for mutation in (overwrite, "view.extent = 0;", "view.element_width = 2;",
                         "view.extent = 11; spx_proof_source_write(0, 4110U, 1U, 1U, &memory_fault);",
                         "runtime.read = 0;"):
            with self.subTest(mutation=mutation):
                result = self._check(mutation, after=repair)
                self.assertEqual(result["status"], "violated", result)
                self.assertIn("typed-service-termination:find_character:0", result["detail"])
        mutant = self._check(overwrite, after=repair, erase=True)
        self.assertEqual(mutant["status"], "satisfied", mutant)

    def test_wide_strings_cannot_use_a_byte_termination_contract(self):
        self.interface = replace(self.interface, types=tuple(
            replace(row, c_type="uint16_t") if row.identity == "u8" else row
            for row in self.interface.types))
        with self.assertRaisesRegex(BisimulationRefinementError, "byte elements"):
            self._thunk()

    def test_registered_prefix_is_distinct_from_storage_capacity(self):
        prefix = """
  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent(4096U) == 8U);
  spx_proof_register_nul_view(4096U, 8U);
  spx_proof_source_write(0, 4103U, 1U, 0U, &memory_fault);
  spx_proof_source_write(0, 4111U, 1U, 7U, &memory_fault);
"""
        for mutation, status in (("", "satisfied"),
                ("spx_source_world.nul_view_count = 0U;", "violated"),
                ("view.extent = 3; spx_proof_source_write(0, 4102U, 1U, 7U, &memory_fault);", "violated"),
                ("spx_proof_source_write(0, 4103U, 1U, 7U, &memory_fault);", "violated"),
                ("runtime.read = 0;", "violated")):
            with self.subTest(mutation=mutation):
                result = self._check(prefix + mutation)
                self.assertEqual(result["status"], status, result)
                if status == "violated":
                    self.assertIn("typed-service-termination:find_character:0", result["detail"])
