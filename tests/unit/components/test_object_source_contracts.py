"""Real nullable/shared operations and the limits of their local source theorem."""

import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_object_model import (
    OBJECT_CONTRACT_POLICY, object_source_shape, render_object_source_model,
)
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_object_source_contracts
from spaghetti_extractor.components.bisimulation_readonly_evidence import (
    validate_object_source_contracts, validate_mutable_source_contracts, validate_shared_source_contracts,
)
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.practical_contracts import _rule
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_object_model import _runtime
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


FIXTURE = Path(__file__).resolve().parents[2] / "fixtures/hello-quoting-state"
TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": ("tests/fixtures/hello-quoting-state",)}
SYMBOLS = {"get": "gnu_hello_get_quoting_style", "set": "gnu_hello_set_quoting_style",
           "set_character": "gnu_hello_set_char_quoting"}


def bundle():
    return compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
        json.loads((FIXTURE / "component-interface-intent-v1.json").read_text())))


def check(root, *, source=None, output="proof", previous=None, timings=None):
    root.mkdir(parents=True, exist_ok=True)
    package = root / "source"
    if not package.exists():
        author = root / "quoting.c"
        author.write_text((FIXTURE / "quoting-style.c").read_text() if source is None else source)
        build_component_source_package(lift_unit_id="quoting-style", files={"quoting.c": author},
            shared_inputs={}, operation_symbols=SYMBOLS, out_dir=package)
    return check_object_source_contracts(bundle=bundle(), package=package, output=root / output,
        goto_cc=Path(shutil.which("goto-cc")), goto_instrument=Path(shutil.which("goto-instrument")),
        cbmc=Path(shutil.which("cbmc")), timeout_seconds=60, unwind=16,
        previous_contract=previous, timings=timings)


class ObjectSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(t) for t in ("cbmc", "goto-cc", "goto-instrument")):
            raise unittest.SkipTest("CBMC tools unavailable")
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.good = check(cls.root / "baseline")
        if cls.good["status"] != "satisfied":
            raise AssertionError([(r.get("kind"), r.get("detail")) for r in cls.good["checks"]])

    def test_real_operations_have_bound_frames_and_dependence_without_activation(self):
        self.assertEqual(object_source_shape(bundle()), ("get", "set", "set_character"))
        self.assertEqual(_rule({}, bundle())[0], "object-memory-contracts")
        self.assertEqual(self.good["policy"], OBJECT_CONTRACT_POLICY)
        self.assertFalse(self.good["authorizing"])
        validate_object_source_contracts(self.good, artifacts=self.root / "baseline/proof")
        for validator in (validate_mutable_source_contracts, validate_shared_source_contracts):
            with self.assertRaises(ValueError):
                validator(self.good)

    def test_unchanged_inputs_reuse_without_compiler_model_or_solver_work(self):
        timings = []
        reused = check(self.root / "baseline", output="reused", previous=self.root / "baseline/proof", timings=timings)
        self.assertEqual(reused, self.good)
        self.assertFalse(any(row["phase"] in {"compiler", "model", "solver"} for row in timings))
        self.assertEqual(sum(row.get("reused_queries", 0) for row in timings), 6)

    def test_null_descriptor_and_metadata_mutation_fail(self):
        original = (FIXTURE / "quoting-style.c").read_text()
        edits = {
            "null": original.replace("options->base.object != 0U", "options != 0"),
            "metadata": original.replace("SPX_PROOF_BEGIN(set);", "SPX_PROOF_BEGIN(set); context->state.defaults.extent = 1U;"),
        }
        for name, source in edits.items():
            with self.subTest(case=name):
                result = check(self.root / name, source=source)
                self.assertEqual(result["status"], "incomplete")
                self.assertTrue(any(row.get("code") == "cbmc_counterexample" for row in result["checks"]))

    def test_full_origin_does_not_grant_writes_beyond_the_shared_frame(self):
        original = (FIXTURE / "quoting-style.c").read_text()
        changed = original.replace("selected->base, 0, 4, style", "selected->base, 40, 4, style")
        self.assertNotEqual(original, changed)
        result = check(self.root / "frame-escape", source=changed)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("code") == "cbmc_counterexample" and
                            "spx-object-writable-frame" in row.get("detail", "") for row in result["checks"]))

    def test_model_or_property_tampering_does_not_retain_a_certificate(self):
        changed = copy.deepcopy(self.good)
        row = next(row for row in changed["checks"] if row.get("kind") == "input_dependence")
        row["property_ids"].remove("spx_object_input_dependence_get.assertion.2")
        row["properties"] -= 1
        changed["receipt_sha256"] = canonical_sha256_v3({k: v for k, v in changed.items() if k != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "post-memory assertion"):
            validate_object_source_contracts(changed)
        path = self.root / "baseline/proof/get-input_dependence.c"
        before = path.read_bytes()
        try:
            path.write_text("void stale(void) {}\n")
            with self.assertRaisesRegex(ValueError, "model meaning"):
                validate_object_source_contracts(self.good, artifacts=self.root / "baseline/proof")
        finally:
            path.write_bytes(before)

    def test_large_origins_do_not_expand_the_source_model(self):
        intent = bundle().intent.to_payload()
        before, _ = render_object_source_model(bundle=bundle(), operation_id="set_character",
            symbol=SYMBOLS["set_character"], kind="input_dependence")
        intent["state"][0]["value"]["extent"]["bytes"] = 1000000
        # The state schema is repeated in each lifecycle relation input.
        for operation in intent["operations"]:
            operation["lifecycle_additional_roots"]["state"][0]["extent"]["bytes"] = 1000000
        changed = ComponentInterfaceIntentV1.create(component_id=intent["id"], schema=bundle().intent.schema,
            state=intent["state"], operations=intent["operations"], services=[], effects=[],
            protocol_states=["ready"], initial_protocol_state="ready")
        after, _ = render_object_source_model(bundle=compile_component_interface_v5(changed),
            operation_id="set_character", symbol=SYMBOLS["set_character"], kind="input_dependence")
        self.assertEqual(before.count("\n"), after.count("\n"))
        self.assertLess(abs(len(before) - len(after)), 30)

    def test_aliases_current_bytes_generations_and_capacity_are_checked(self):
        root = self.root / "runtime"
        root.mkdir()
        _write_cbmc_stdint(root / "stdint.h")
        (root / "state-machine-runtime.h").write_text(exact_runtime_header())
        for name, source in render_component_c_headers_v5(bundle(), SYMBOLS).items():
            (root / name).write_text(source)
        prefix = '#include "state-machine-runtime.h"\n#include "portable-component.h"\n'
        prefix += "\n".join([*sparse_mutable_memory_runtime(2), *_runtime(2), *result_view_runtime_helpers()])
        body = '''
int main(void) {
  struct spx_mutable_world world={0};
  struct spx_object_environment env={.world=&world,.inputs={
    {{1U,1U,3U,4U,8U,3U},4100U,3U,4U},
    {{1U,2U,5U,0U,2U,1U},4102U,1U,2U}}};
  spx_runtime runtime={.context=&env,.read=spx_object_read,.write=spx_object_write,
                       .realize_reference=spx_object_realize};
  uint32_t value; uint64_t observed=0U;
  __CPROVER_assert(spx_component_result_view_write(&runtime,env.inputs[0].reference,1U,2U,value)==0U,
      "write through interior reference");
  __CPROVER_assert(spx_component_result_view_read(&runtime,env.inputs[1].reference,0U,1U,&observed)==0U &&
      observed==((value>>8U)&255U),"overlapping readonly alias sees current byte");
  __CPROVER_assert(spx_mutable_byte(&world,4103U)==__CPROVER_uninterpreted_readonly_byte(4103U),
      "untouched suffix retains its actual input byte");
  __CPROVER_assert(spx_component_result_view_write(&runtime,env.inputs[1].reference,0U,1U,0U)!=0U,
      "readonly alias gains no write permission");
  spx_ref_v5 stale=env.inputs[0].reference; stale.generation++;
  __CPROVER_assert(spx_component_result_view_read(&runtime,stale,0U,1U,&observed)!=0U,
      "unrepresented generation cannot access memory");
  EXTRA
}
'''
        for overflow in (False, True):
            path = root / ("capacity.c" if overflow else "alias.c")
            extra = "" if not overflow else '''
  (void)spx_component_result_view_write(&runtime,env.inputs[0].reference,0U,1U,0U);
  (void)spx_component_result_view_write(&runtime,env.inputs[0].reference,0U,1U,0U);
'''
            path.write_text(prefix + body.replace("EXTRA", extra))
            result = run_cbmc_properties(command=[shutil.which("cbmc"), str(path), "--json-ui",
                "--unwind", "4", "--unwinding-assertions", "--pointer-check", "--bounds-check",
                "--signed-overflow-check", "--undefined-shift-check", "--sat-solver", "cadical", "--trace"],
                timeout_seconds=30)
            self.assertEqual(result["status"], "violated" if overflow else "satisfied", result.get("detail"))
            if overflow:
                self.assertIn("spx-shared-memory-event-capacity", result["detail"])


if __name__ == "__main__":
    unittest.main()
