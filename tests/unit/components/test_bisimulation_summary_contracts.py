from __future__ import annotations

import json
import hashlib
import copy
import shutil
import tempfile
import subprocess
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_summary_contracts import (
    check_scalar_summary_contracts, checked_scalar_summary_certificate,
    validate_scalar_summary_contracts,
)
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.bisimulation_connected import _connected_replay_source, render_connected_summary_wrapper
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": ("targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json",),
}


class ScalarSummaryContractTests(unittest.TestCase):
    def _pair(self, second_value: int, *, first_value: int = 65, facts=(), expect_zero=False,
              preserve_context=False) -> dict[str, object]:
        cbmc, compiler, instrument = (shutil.which(name) for name in ("cbmc", "goto-cc", "goto-instrument"))
        if not all((cbmc, compiler, instrument)):
            self.skipTest("CBMC contract tools are unavailable")
        interface = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(json.loads(interface.read_text())))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "stddef.h").write_text("typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "connected-proof-summary.h").write_text("#define SPX_PROOF_CONNECTED_CAPACITY 1\n")
            for name, content in render_component_c_headers_v5(bundle, {"convert": "test_convert"}).items():
                (root / name).write_text(content)
            world = _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                                  max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=())
            replay = '\n'.join(_connected_replay_source([{"summary_id": 0, "summary_capacity": 1,
                "summary_strategy": "scalar-body-free-v1"}],
                max_writes=1, max_calls=1, max_atomics=1))
            for effect in ("write", "call", "atomic"):
                self.assertNotIn(f"spx-bisimulation-connected-summary-{effect}-capacity:", replay)
            self.assertIn("spx-bisimulation-connected-summary-memory:", replay)
            self.assertIn("spx-bisimulation-connected-summary-prefix:", replay)
            wrapper = render_connected_summary_wrapper(bundle=bundle, operation_symbols={"convert": "test_convert"},
                                                       summary_ids={"convert": 0}, body_free_scalar=True,
                                                       scalar_postconditions=facts)
            source = root / "pair.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                              '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + world + replay + wrapper + '''
void main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  spx_proof_reset_connected_summaries();
  spx_runtime exact_runtime = spx_proof_runtime(&spx_exact_world);
  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);
  spx_proof_connected_service_prefix exact_service = {&exact_runtime};
  spx_proof_connected_service_prefix source_service = {&source_runtime};
  spx_ascii_to_lower_services_v5 left_services = {&exact_service};
  spx_ascii_to_lower_services_v5 right_services = {&source_service};
  spx_ascii_to_lower_context_v5 left = {0}, right = {0};
  left.services = &left_services; right.services = &right_services;
  left.state.reserved = 11U; right.state.reserved = 29U;
  uint32_t a = test_convert(&left, ''' + str(first_value) + '''U);
  uint32_t b = test_convert(&right, ''' + str(second_value) + '''U);
  __CPROVER_assert(a == b, "paired abstract result");
''' + ('''  __CPROVER_assert(left.state.reserved == 11U && right.state.reserved == 29U &&
      left.services == &left_services && right.services == &right_services,
      "scalar summary preserves each caller context");
''' if preserve_context else '') + ('  __CPROVER_assert(a == 0U, "proved scalar postcondition");\n' if expect_zero else '') + '''
  __CPROVER_assert(spx_proof_connected_summaries_equal(), "paired invocation count");
}
''')
            model = root / "pair.goto"
            compiled = subprocess.run([compiler, "--i386-win32", "-I", str(root), str(source), "-o", str(model)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            inventory = subprocess.run([instrument, "--show-goto-functions", "--json-ui", str(model)], capture_output=True, text=True)
            self.assertEqual(inventory.returncode, 0, inventory.stderr)
            self.assertIn("test_convert", inventory.stdout)
            self.assertNotIn("spx_proof_connected_impl_", inventory.stdout)
            result = run_cbmc_properties(command=[cbmc, str(model), "--json-ui", "--trace",
                "--bounds-check", "--pointer-check", "--unwind", "2", "--unwinding-assertions",
                "--sat-solver", "cadical"], timeout_seconds=30)
            functions = next(row["functions"] for row in json.loads(inventory.stdout) if "functions" in row)
            return {**result, "parent_goto_instructions": sum(len(row.get("instructions", [])) for row in functions)}

    def test_body_free_scalar_calls_pair_without_a_callee_implementation(self) -> None:
        result = self._pair(65)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_empty_frame_preserves_the_two_distinct_caller_contexts(self) -> None:
        result = self._pair(65, preserve_context=True)
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_body_free_scalar_call_requires_matching_inputs(self) -> None:
        result = self._pair(66)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-input:0")

    def test_only_a_checked_postcondition_constrains_the_abstract_result(self) -> None:
        certificate = self._check('(void)context; return value;')
        self.assertEqual(len(certificate["postconditions"]), 1)
        unconstrained = self._pair(0, first_value=0, expect_zero=True)
        self.assertEqual(unconstrained["status"], "violated")
        constrained = self._pair(0, first_value=0, facts=certificate["postconditions"], expect_zero=True)
        self.assertEqual(constrained["status"], "satisfied", constrained.get("detail"))

    def test_false_postcondition_does_not_constrain_a_valid_scalar_summary(self) -> None:
        result = self._check('(void)context; return value + 1U;')
        self.assertEqual(result["status"], "satisfied", result.get("checks"))
        self.assertEqual(result["postconditions"], [])
        validate_scalar_summary_contracts(result)

    def test_callee_body_growth_does_not_grow_the_paired_parent_model(self) -> None:
        measurements = []
        for size in (0, 256):
            child = {}
            certificate = self._check('(void)context;\n' + 'value += 0U;\n' * size + 'return value;', measurements=child)
            self.assertEqual(certificate["status"], "satisfied")
            parent = self._pair(0, first_value=0, facts=certificate["postconditions"], expect_zero=True)
            self.assertEqual(parent["status"], "satisfied")
            measurements.append((child["callee_goto_instructions"], parent["parent_goto_instructions"]))
        self.assertGreater(measurements[1][0], measurements[0][0])
        self.assertEqual(measurements[0][1], measurements[1][1])

    def _check(self, body: str, declarations: str = "", *, measurements=None, staged=False) -> dict[str, object]:
        commands = {name: shutil.which(name) for name in ("cbmc", "goto-cc", "goto-instrument")}
        if not all(commands.values()):
            self.skipTest("CBMC contract tools are unavailable")
        interface = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(json.loads(interface.read_text())))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "proof"
            if not staged:
                output.mkdir()
                _write_cbmc_stdint(output / "stdint.h")
            source = root / "convert.c"
            source.write_text('#include "portable-component-implementation.h"\n' + declarations + '''
uint32_t test_convert(spx_ascii_to_lower_context_v5 *context, uint32_t value) {
''' + body + '\n}\n')
            result = check_scalar_summary_contracts(
                bundle=bundle, operation_symbols={"convert": "test_convert"},
                source_files=[source], headers=render_component_c_headers_v5(bundle, {"convert": "test_convert"}),
                output=output, goto_cc=Path(commands["goto-cc"]),
                goto_instrument=Path(commands["goto-instrument"]), cbmc=Path(commands["cbmc"]),
                timeout_seconds=30,
                workspace=root / "workspace" if staged else None,
            )
            if staged:
                for model in result["models"]:
                    name = model["operation_id"] + "-" + model["kind"]
                    suffix = "-checked.goto" if model["kind"] == "frame" else "-reachable.goto"
                    content = (output / (name + suffix)).read_bytes()
                    self.assertEqual(hashlib.sha256(content).hexdigest(), model["goto_sha256"])
                    self.assertNotIn(str(output).encode(), content)
                for fact in result["postconditions"]:
                    content = (output / Path(fact["checker_command"][1]).name).read_bytes()
                    self.assertEqual(hashlib.sha256(content).hexdigest(), fact["goto_sha256"])
                    self.assertNotIn(str(output).encode(), content)
            if measurements is not None:
                inventory = subprocess.run([commands["goto-instrument"], "--show-goto-functions", "--json-ui",
                    str(output / "convert-context_independence-reachable.goto")], capture_output=True, text=True, check=True)
                functions = next(row["functions"] for row in json.loads(inventory.stdout) if "functions" in row)
                measurements["callee_goto_instructions"] = len(next(row["instructions"] for row in functions if row["name"] == "test_convert"))
            return result

    def test_scalar_function_has_checked_frame_and_context_independence(self) -> None:
        result = self._check('(void)context; return value >= 65U && value <= 90U ? value + 32U : value;')
        self.assertEqual(result["status"], "satisfied", result.get("checks"))
        self.assertFalse(result["authorizing"])
        self.assertEqual({row["kind"] for row in result["checks"]}, {"frame", "context_independence"})
        validate_scalar_summary_contracts(result)
        interface = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(json.loads(interface.read_text())))
        source = {"implementation_sha256": "1" * 64,
                  "files": [{"path": "convert.c", "sha256": result["inputs"][0]["sha256"]}]}
        arguments = dict(bound={"certificate": result, "implementation_sha256": "1" * 64,
                                "source_profile_sha256": "2" * 64}, bundle=bundle,
                         source=source, source_profile_sha256="2" * 64,
                         operation_symbols={"convert": "test_convert"},
                         headers=render_component_c_headers_v5(bundle, {"convert": "test_convert"}))
        self.assertIs(checked_scalar_summary_certificate(**arguments), result)
        stale_fact = copy.deepcopy(result)
        stale_fact["postconditions"][0]["expression"] = {
            "op": "false", "sort": {"kind": "bool"}, "args": [], "attributes": {}}
        stale_fact["receipt_sha256"] = canonical_sha256_v3({
            key: item for key, item in stale_fact.items() if key != "receipt_sha256"})
        with self.assertRaisesRegex(ValueError, "postcondition source binding is stale"):
            checked_scalar_summary_certificate(**{**arguments, "bound": {**arguments["bound"], "certificate": stale_fact}})
        source["files"][0]["sha256"] = "3" * 64
        with self.assertRaisesRegex(ValueError, "source bytes are stale"):
            checked_scalar_summary_certificate(**arguments)

    def test_staged_scalar_models_keep_their_bound_bytes_without_output_self_references(self):
        result = self._check('(void)context; return value;', staged=True)
        self.assertEqual(result["status"], "satisfied")
        validate_scalar_summary_contracts(result)

    def test_rehashed_certificate_cannot_omit_required_checks(self) -> None:
        original = self._check('(void)context; return value;')
        self.assertEqual(original["status"], "satisfied", original.get("checks"))
        for mutation in ("frame", "instrumentation", "pointer_check", "authority", "postcondition_check",
                         "postcondition_expression", "postcondition_source", "postcondition_options"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                if mutation == "frame":
                    value["checks"] = [row for row in value["checks"] if row["kind"] != "frame"]
                elif mutation == "instrumentation":
                    value["commands"] = [row for row in value["commands"] if not row["step"].endswith("-instrument")]
                elif mutation == "pointer_check":
                    next(row for row in value["commands"] if row["step"].endswith("-check"))["command"].remove("--pointer-check")
                elif mutation == "authority":
                    value["authorizing"] = True
                elif mutation == "postcondition_check":
                    value["postconditions"][0]["check"]["property_ids"] = []
                elif mutation == "postcondition_expression":
                    value["postconditions"][0]["expression"] = {
                        "op": "false", "sort": {"kind": "bool"}, "args": [], "attributes": {}}
                elif mutation == "postcondition_source":
                    value["postconditions"][0]["compile_command"].remove("$MODEL_ROOT/source-0000.c")
                else:
                    value["postconditions"][0]["checker_command"].remove("--pointer-check")
                value["receipt_sha256"] = canonical_sha256_v3({
                    key: item for key, item in value.items() if key != "receipt_sha256"
                })
                with self.assertRaises(ValueError):
                    validate_scalar_summary_contracts(value)

    def test_empty_interface_does_not_prove_a_frame(self) -> None:
        result = self._check('context->protocol_state = 7U; return value;')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("kind") == "frame" and row["status"] == "violated"
                            for row in result["checks"]), result["checks"])

    def test_equal_explicit_arguments_do_not_hide_context_dependence(self) -> None:
        result = self._check('return value + context->protocol_state;')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("kind") == "context_independence" and row["status"] == "violated"
                            for row in result["checks"]), result["checks"])

    def test_missing_function_body_cannot_be_assumed_effect_free(self) -> None:
        result = self._check('(void)context; hidden(); return value;', 'void hidden(void);\n')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("code") == "summary_contract_undefined_function"
                            and "hidden" in row["functions"] for row in result["checks"]), result["checks"])

    def test_divergence_is_not_a_successful_empty_frame(self) -> None:
        result = self._check('(void)context; while (value == 0U) {} return value;')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("code") == "summary_contract_requires_acyclic_control"
                            for row in result["checks"]), result["checks"])

    def test_recursive_summary_needs_an_inductive_rule(self) -> None:
        result = self._check('return test_convert(context, value);')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("code") == "summary_contract_requires_acyclic_control"
                            for row in result["checks"]), result["checks"])
