"""Service adapters consume actual native IDs, offsets and lifetime checks."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.machine_overlay_external_v5 import _external_reference_result_lines
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source
from tests.unit.components import test_bisimulation_service_preconditions as fixture_module

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json",)}


def borrowed_relation():
    core = {"format": "spaghetti-extractor-interaction-contract-receipt-v1",
            "contract_id": "c-runtime.strrchr.borrowed-interior-v1",
            "contract_sha256": "b" * 64, "status": "checked",
            "code": "reviewed_reusable_contract"}
    receipt = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    return {"operation_id": "select", "requirement_id": "find-last-character-borrowed-interior",
            "service_id": "find_last_character", "input_argument_index": 0,
            "relation": "borrowed_interior_or_null",
            "origin_type": {"kind": "view", "nul_terminated": True},
            "result_policy": {"nullable": True, "allow_one_past": False, "permissions": 1},
            "nonnull_min_remaining": {"nonzero_argument_index": 1, "minimum": 2},
            "contract_id": core["contract_id"], "contract_sha256": core["contract_sha256"],
            "contract_catalog_sha256": "d" * 64, "contract_receipt": receipt,
            "contract_receipt_sha256": receipt["receipt_sha256"]}


class TypedServiceNativeReferenceTests(unittest.TestCase):
    def check(self, *, mutation="", related=False, native_result=False, null=False,
              mutant=None, expected_failure=None):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        fixture = fixture_module.ServicePreconditionTests()
        fixture.setUp()
        thunk = fixture._thunk((borrowed_relation(),) if related else ()).replace('"argv-rule"', '"allocation"')
        original_thunk = thunk
        if mutant == "argument":
            thunk = thunk.replace(
                "spx_proof_typed_service_argument(UINT32_C(0), spx_typed_input_0_address)",
                "spx_proof_typed_service_argument(UINT32_C(0), "
                "(uint32_t)(logical_argument_0000->base.object + logical_argument_0000->base.offset))")
        if mutant == "result":
            thunk = thunk.replace("      spx_typed_input_0_address;",
                "      (uint32_t)(logical_argument_0000->base.object + logical_argument_0000->base.offset);")
        if mutant == "width":
            thunk = thunk.replace("    service_result_reference.object,",
                                  "    (uint32_t)service_result_reference.object,")
        if mutant == "permissions":
            thunk = thunk.replace("service_result_origin.extent, service_result_origin.permissions",
                                  "service_result_origin.extent, UINT32_C(1)")
        if mutant:
            self.assertNotEqual(thunk, original_thunk, "mutation must change the generated adapter")
        signature = fixture.bundle.intent.schema.signature_index["service.find_last_character"]
        native_lines = _external_reference_result_lines(result=signature.results[0],
            result_type="spx_ref_v1", projection=fixture.binding["result_projection"],
            authority_selectors={"argv_string": "allocation"})
        native_thunk = "\n".join(native_lines)
        result_word = 0 if null else 4101
        body = '''
#include "portable-component-implementation.h"
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
typedef struct {
  spx_runtime *runtime;
  spx_machine_state *state;
  uint32_t *memory_fault, *service_fault;
} spx_component_service_context_v1;
static uint32_t admitted, finished;
/* The fixture's twelve-byte string starts at the realized interior address.
 * Supply its existing extent provider explicitly; an undefined extern gives
 * CBMC an arbitrary extent and cannot justify the fixed terminator address. */
uint64_t spx_proof_borrowed_nul_extent(void *context, uint32_t address, uint64_t capacity) {
  __CPROVER_assert(address == 4100U && capacity == 12U,
      "native string extent uses realized input and visible capacity");
  return 12U;
}
uint32_t spx_component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  __CPROVER_assert(address == 4111U && width == 1U, "termination uses realized address");
  *fault = 0U; return 0U;
}
void spx_proof_typed_service_begin(void *context, uint32_t spec) { ++admitted; }
void spx_proof_typed_service_argument(uint32_t index, uint32_t value) {
  if (index == 0U) __CPROVER_assert(value == 4100U, "native address reaches service");
}
void spx_proof_typed_service_finish(void) { ++finished; }
''' + f'uint32_t spx_proof_typed_service_result(void) {{ return {result_word}U; }}\n' + thunk + '''
static spx_ref_v1 native_return(spx_component_service_context_v1 *service, uint32_t address) {
  spx_machine_state call_output = {.eax = address};
''' + native_thunk + '''
spx_service_fail:
  __CPROVER_assert(0, "native result resolution failed");
  return (spx_ref_v1){0};
}
int main(void) {
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "native allocation");
  spx_machine_reference_v1 issued = borrow(4100U);
  spx_runtime runtime = {.context=&spx_native_context_value,
      .realize_reference=spx_native_realize_reference, .resolve_reference=spx_native_resolve_reference};
  spx_machine_state state = {0};
  uint32_t memory_fault = 0U, service_fault = 0U;
  spx_component_service_context_v1 service = {&runtime, &state, &memory_fault, &service_fault};
  spx_view_v5 view = {.base={issued.domain, issued.object, issued.generation,
      issued.offset, issued.extent, issued.permissions}, .extent=12U, .element_width=1U};
''' + mutation + (f'\n  spx_ref_v1 result = native_return(&service, {result_word}U);\n' if native_result else
                 '\n  spx_ref_v1 result = find_character(&service, &view, 47U);\n') + '''
  spx_machine_reference_v1 returned = {result.domain, result.object, result.generation,
      result.offset, result.extent, result.permissions};
  uint32_t address;
''' + ('''
  __CPROVER_assert(result.domain == 0U && result.object == 0U && result.generation == 0U &&
      result.offset == 0U && result.extent == 0U && result.permissions == 0U, "canonical null result");
''' if null else '''
  __CPROVER_assert(result.domain == issued.domain && result.object == issued.object &&
      result.generation == issued.generation && result.extent == issued.extent &&
      result.offset == 5U && result.permissions == issued.permissions, "full native result identity preserved");
  __CPROVER_assert(realize(returned, &address) == SPX_BOUNDARY_OK && address == 4101U,
      "returned native reference realizes at service result");
''') + ('' if native_result else '''
  __CPROVER_assert(admitted == 1U && finished == 1U && service_fault == 0U,
      "live native service completed");
''') + '\n  __CPROVER_cover(1);\n}\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for name, content in render_component_c_headers_v5(fixture.bundle, {"select": "select"}).items():
                (root / name).write_text(content)
            source = root / "service.c"
            source.write_text(allocation_fixture_source(body, domain=0x100000003, object_id=0x200000037))
            # Includes the native selector's bounded string comparison.
            command = [cbmc, str(source), "--json-ui", "--unwind", "16", "--sat-solver", "cadical"]
            result = run_cbmc_properties(command=[*command, "--trace", "--unwinding-assertions",
                "--bounds-check", "--pointer-check", "--signed-overflow-check"], timeout_seconds=30)
            self.assertEqual(result["status"], "violated" if expected_failure else "satisfied", result.get("detail"))
            if expected_failure:
                self.assertIn(expected_failure, result["detail"])
                return
            cover = run_cbmc_cover(command=[*command, "-DSPX_TEST_COVER", "--cover", "cover"],
                                   expected_functions=["main"], timeout_seconds=30)
            self.assertEqual(cover["status"], "incomplete" if mutant == "result" else "satisfied", cover)
            if mutant == "result":
                # A timeout or tool error is not evidence that the constraint
                # excluded the successful return path.
                self.assertEqual(cover["code"], "cbmc_nonvacuity_unwitnessed", cover)
                self.assertIn(":FAILED:main", cover["detail"])

    def test_service_admits_native_ids_and_preserves_resolved_result(self):
        self.check()

    def test_borrowed_result_uses_realized_origin_for_its_interior_delta(self):
        self.check(related=True)

    def test_native_service_result_preserves_full_width_reference_fields(self):
        self.check(native_result=True)

    def test_null_results_remain_canonical(self):
        for related, native in ((False, False), (True, False), (False, True)):
            with self.subTest(related=related, native=native):
                self.check(related=related, native_result=native, null=True)

    def test_invalid_and_expired_native_inputs_are_rejected(self):
        for mutation in ("view.base.object++;", "view.base.domain++;", "view.base.generation++;",
                         "view.base.extent++;", "view.base.permissions = 0U;",
                         "view.base.offset = 16U; view.extent = 0U;", "view.extent = 13U;",
                         "runtime.realize_reference = 0;",
                         "spx_native_release_external_range(4096U, 101U);"):
            with self.subTest(mutation=mutation):
                self.check(mutation=mutation, expected_failure="typed-service-reference:find_character:0")

    def test_object_arithmetic_mutant_corrupts_service_argument(self):
        self.check(mutant="argument", expected_failure="native address reaches service")

    def test_object_arithmetic_mutant_cannot_hide_result_behind_false_assumption(self):
        self.check(related=True, mutant="result")

    def test_truncated_identity_mutant_corrupts_result(self):
        self.check(mutant="width", expected_failure="full native result identity preserved")

    def test_narrowed_authority_metadata_mutant_cannot_return_an_invalid_reference(self):
        self.check(related=True, mutant="permissions", expected_failure="typed-service-reference-result:find_character")
