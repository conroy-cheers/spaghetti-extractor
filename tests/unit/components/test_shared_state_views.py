"""The actual helper's shared views cross live state and result adapters."""

import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.machine_overlay_boundaries_v5 import state_import_lines, state_export_lines
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from spaghetti_extractor.components.machine_overlay_state_views import state_view_result_lines
from spaghetti_extractor.components.machine_overlay_v5 import render_component_machine_overlay_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract
from spaghetti_extractor.transfer.model import _Transfer, _Action
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_hand_defined_boundaries import FIXTURE, shared_buffer_bundle

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text",
)}


def constant(value):
    return {"kind": "constant", "width": 32, "value": value}


def projections():
    rows = {}
    for name, address, extent in (("buffer", 0x413d20, 500), ("module", 0x410150, 4)):
        entry = {"kind": "view", "at": "entry", "base": constant(address),
                 "extent": constant(extent), "requested_extent": constant(extent),
                 "authority": {"kind": "image", "id": name, "lifetime": "image"}}
        rows[name] = {"id": name, "entry": entry, "exit": {**entry, "at": "exit"}}
    result = {**rows["buffer"]["exit"],
              "base": {"kind": "register", "register": "eax", "width": 32, "at": "exit"}}
    return rows, result


def generated_boundary():
    bundle = shared_buffer_bundle()
    rows, result = projections()
    imports = state_import_lines(bundle=bundle, state_projections=rows,
        authority_selectors={"buffer": "buffer", "module": "module"},
        context_expression="context", runtime_expression="rt")
    exports = state_export_lines(bundle=bundle, state_projections=rows,
        context_expression="context", runtime_expression="rt")
    returned = state_view_result_lines(bundle=bundle,
        value=bundle.intent.schema.signature_index["get"].results[0],
        projection=result, state_projections=rows, runtime="rt")
    return '''
static spx_step_result invoke(spx_runtime *rt, const spx_resource_text_services_v5 *services,
    uint32_t id, uint32_t mutation, spx_view_v5 *saved) {
  spx_resource_text_context_v5 context = {.services = services};
''' + '\n'.join(imports) + '''
  spx_view_v5 logical_result = resource_text(&context, id);
  mutate(&context, &logical_result, rt->context, mutation);
''' + '\n'.join(exports + returned) + '''
  *saved = logical_result;
  return (spx_step_result){SPX_RETURN, 0U, logical_result_word};
}
'''


def write_native_fixture(root):
    for name, content in render_component_c_headers_v5(shared_buffer_bundle(), {"get": "resource_text"}).items():
        (root / name).write_text(content)
    (root / "state-machine-runtime.h").write_text(exact_runtime_header())
    source = root / "native.c"
    source.write_text('#include "portable-component-implementation.h"\n'
        '#include "state-machine-runtime.h"\n#include <assert.h>\n#include <string.h>\n'
        + '\n'.join(result_view_runtime_helpers()) + '\n'
        + spx_portable_reference_runtime_v5_source() + '\n'
        + (FIXTURE / "resource-text.c").read_text() + '\n'
        + (FIXTURE / "exercise-native.c").read_text().replace("GENERATED_BOUNDARY", generated_boundary()))
    return source


def transport_only_overlay(*, proof_classification="machine_overlay"):
    # Isolate the native operation wrapper without supplying an invented
    # LoadStringA contract. The real service is exercised separately above.
    original = shared_buffer_bundle().intent
    operations = copy.deepcopy(original.to_payload()["operations"])
    operations[0].update(effect_ids=[], allowed_service_ids=[])
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=original.component_id, schema=original.schema, state=original.state,
        operations=operations, effects=[], services=[], protocol_states=["ready"],
        initial_protocol_state="ready"))
    rows, result = projections()
    unit = "semantic-transfer:original-cutpoint-00001284-000012a7"
    operation = {"operation_id": "get", "entry_unit_ids": [unit], "exit_unit_ids": [unit],
        "parameters": [{"id": "id", "projection": {"kind": "stack", "width": 32, "offset": 4, "at": "entry"}}],
        "results": [{"id": "result", "projection": result}], "state": list(rows.values()),
        "effects": [], "preserved_state_ids": [], "callback_operation_ids": [], "continuation_unit_ids": []}
    binding = ComponentMachineBindingIntentV1.create(component_id="resource-text", blockers=[], operations=[{
        "id": "get", "kind": "operation", "unit_ids": [unit], "entry_rvas": [0x1284],
        "transfer_ids": [unit], "effect_ids": [], "service_ids": [], "callback_ids": [],
        "outcome_protocol_ids": [], "machine_projection": {"operation": operation, "service_bindings": []},
        "object_authority_selectors": [], "pointer_views": [], "relation_receipt_sha256s": [],
        "induction_evidence_sha256": None}])
    contract = NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    transfer = _Transfer(unit, "a" * 64, "b" * 64, 0x1284, (), (), (_Action("outcome_return", (0,)),), (), ())
    return bundle, render_component_machine_overlay_v5(bundle=bundle, contract=contract,
        operation_symbols={"get": "resource_text"}, transfers=[transfer], proof_classification=proof_classification)


class SharedStateViewTests(unittest.TestCase):
    def test_full_operation_overlay_compiles_for_host_and_pe32(self):
        bundle, overlay = transport_only_overlay()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in render_component_c_headers_v5(bundle, {"get": "resource_text"}).items():
                (root / name).write_text(content)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "overlay.c").write_text(overlay.source)
            for compiler in (shutil.which("cc"), shutil.which("i686-w64-mingw32-gcc")):
                self.assertIsNotNone(compiler)
                built = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-c", str(root / "overlay.c"), "-o", str(root / "overlay.o")],
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(built.returncode, 0, built.stderr)

    def test_borrowed_runtime_cannot_be_persisted_in_owned_state(self):
        with self.assertRaisesRegex(ValueError, "borrowed operation runtime"):
            transport_only_overlay(proof_classification="encapsulated_owned")

    def test_real_helper_transports_shared_bytes_aliases_and_rejects_stale_or_changed_views(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_native_fixture(root)
            built = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                str(source), "-o", str(root / "exercise")], capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(root / "exercise")], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)

    def test_native_transport_safety_and_all_mutations_with_cbmc(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as directory:
            source = write_native_fixture(Path(directory))
            for mutation in range(12):
                with self.subTest(mutation=mutation):
                    result = run_cbmc_properties(command=[cbmc, str(source), f"-DSPX_TEST_MUTATION={mutation}",
                        "--json-ui", "--trace", "--unwind", "8", "--unwinding-assertions",
                        "--pointer-check", "--bounds-check", "--signed-overflow-check",
                        "--undefined-shift-check", "--div-by-zero-check", "--sat-solver", "cadical"],
                        timeout_seconds=30)
                    self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_bindings_reject_changed_ranges_and_missing_returned_alias(self):
        bundle = shared_buffer_bundle()
        for change in ("address", "extent", "lifetime"):
            rows, _ = projections()
            if change == "address": rows["buffer"]["exit"]["base"] = constant(0x413d21)
            elif change == "extent": rows["buffer"]["exit"]["extent"] = constant(499)
            else: rows["buffer"]["exit"]["authority"] = {"kind": "image", "id": "buffer", "lifetime": "call"}
            with self.subTest(change=change), self.assertRaises(ValueError):
                state_import_lines(bundle=bundle, state_projections=rows, authority_selectors={},
                    context_expression="context", runtime_expression="rt")
        rows, result = projections()
        result = copy.deepcopy(result)
        result["authority"]["id"] = "unrelated"
        with self.assertRaisesRegex(ValueError, "exact matching state binding"):
            state_view_result_lines(bundle=bundle,
                value=bundle.intent.schema.signature_index["get"].results[0],
                projection=result, state_projections=rows, runtime="rt")


if __name__ == "__main__":
    unittest.main()
