from __future__ import annotations

import json
import copy
import hashlib
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.bisimulation import (
    ComponentBisimulationError,
    ComponentBisimulationIntentV1,
    build_component_proof_plan_v1,
)
from spaghetti_extractor.components.bisimulation_refinement import (
    BisimulationRefinementError,
    check_bisimulation_refinement,
)
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer
from spaghetti_extractor.components.capabilities import spx_reference_runtime_header
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import (
    check_component_source_profile,
)
from tests.unit.components.test_bisimulation_refinement import ROOT, _intent
from tests.unit.components.test_inductive_relation import _interface, _operation


TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": (
        "targets/dxball/intent/bindings-v5/directdraw-init.json",
    ),
}


class BisimulationRefinementIntegrationTests(unittest.TestCase):
    def test_dxball_backbuffer_descriptor_matches_the_exact_0x40_capability(self) -> None:
        binding = ComponentMachineBindingIntentV1.parse(
            json.loads(
                (
                    ROOT
                    / "targets/dxball/intent/bindings-v5/directdraw-init.json"
                ).read_text(encoding="utf-8")
            )
        )
        services = binding.operations[0].semantics.machine_projection[
            "service_bindings"
        ]
        backbuffer = next(
            item for item in services if item["service_id"] == "create_backbuffer"
        )
        descriptor = backbuffer["provider"]["argument_transducers"][1]
        self.assertEqual(len(descriptor["initial_words"]), 27)
        self.assertEqual(descriptor["initial_words"][26], 0x40)

    def _check_acyclic_operation(
        self, *, cut: bool = False, mutation: str = "", source_layout: str = "scalar",
        final_cut: bool = False, source_unwind_limit: int | None = None,
        private_scope: bool = False, stack_fact: bool = False,
    ) -> dict[str, object]:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        interface = _interface()
        symbols = {"run": "countdown_run"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authored = root / "countdown.c"
            source_text = '''#include "portable-component-implementation.h"
uint32_t countdown_run(spx_countdown_context_v2 *context, uint32_t count) {
  uint32_t n = count;
  (void)context;
  SPX_PROOF_BEGIN(run);
  if (n != 0U) {
    if (n != 0U)
      n -= 1U;
  }
  return n;
}
'''
            if cut:
                marker = "SPX_PROOF_SYNC(loop, 1, count, n);"
                if mutation == "capture":
                    marker = "n += 1U; " + marker
                if mutation == "missing_branch":
                    marker = "if (n != 1U) { " + marker + " }"
                source_text = source_text.replace("    if (n != 0U)", "    " + marker + "\n    if (n != 0U)")
            if mutation == "finite_loop":
                source_text = source_text.replace("n -= 1U;", "for (uint32_t k = 0; k < 2U; ++k) { if (k == 1U) n -= 1U; }")
            if mutation == "suffix":
                source_text = source_text.replace("n -= 1U", "n -= 2U")
            if mutation == "diverge":
                source_text = source_text.replace("  if (n != 0U) {", "  while (n == 0U) {}\n  if (n != 0U) {")
            if mutation == "uncaptured_parameter":
                source_text = source_text.replace(
                    "SPX_PROOF_SYNC(loop, 1, count, n);",
                    "count += 1U; SPX_PROOF_SYNC(loop, n != 0U, n);",
                ).replace("      n -= 1U;", "      n -= 1U;\n    return n + (count != n + 1U);")
            if mutation in {"dead_parameter", "omitted_live_parameter", "omitted_aliased_parameter"}:
                source_text = source_text.replace("SPX_PROOF_SYNC(loop, 1, count, n);", "SPX_PROOF_SYNC(loop, 1, n);")
                if mutation != "dead_parameter":
                    observed = "count"
                    if mutation == "omitted_aliased_parameter":
                        source_text = source_text.replace("uint32_t n = count;", "uint32_t n = count; uint32_t *alias = &count;")
                        observed = "*alias"
                    source_text = source_text.replace("      n -= 1U;", f"      n -= 1U;\n    return n + ({observed} == 0U);")
            if mutation == "uncaptured_context":
                source_text = source_text.replace("uint32_t n = count;",
                    "uint32_t n = count; spx_countdown_context_v2 alternate = *context;")
                source_text = source_text.replace("SPX_PROOF_SYNC(loop, 1, count, n);",
                    "alternate.state.reserved = 1; context = &alternate; SPX_PROOF_SYNC(loop, 1, count, n);")
                source_text = source_text.replace("return n;", "return n + context->state.reserved;")
            if mutation == "renamed_parameter":
                source_text = re.sub(r"\bcount\b", "incoming", source_text)
            if mutation == "shadowed_parameter":
                source_text = source_text.replace("  if (n != 0U) {", "  if (n != 0U) {\n    uint32_t count = 0;")
            if mutation == "parameter_local_alias":
                source_text = source_text.replace("uint32_t n = count;", "uint32_t n = count; uint32_t shadow = 0;")
                source_text = source_text.replace("loop, 1, count, n", "loop, 1, shadow, n").replace("return n;", "return n + count;")
            if mutation == "parameter_codec":
                source_text = source_text.replace("return n;", "return n + count;")
            if mutation == "state_codec":
                source_text = source_text.replace("return n;", "return n + n;")
            if mutation in {"uncaptured_local", "uncaptured_array", "dead_local"}:
                declaration = "uint32_t forgotten = 0;"
                value = "forgotten"
                if mutation == "uncaptured_array":
                    declaration = "uint32_t forgotten[2] = {0, 0};"
                    value = "forgotten[1]"
                source_text = source_text.replace("uint32_t n = count;", "uint32_t n = count; " + declaration)
                source_text = source_text.replace("SPX_PROOF_SYNC(loop, 1, count, n);",
                    value + " = 1U; SPX_PROOF_SYNC(loop, 1, count, n);"
                    + (value + " = 0U;" if mutation == "dead_local" else ""))
                source_text = source_text.replace("return n;", "return n + " + value + ";")
            if final_cut:
                self.assertTrue(cut)
                self.assertEqual(source_layout, "scalar")
                source_text = source_text.replace(
                    "  return n;",
                    "  uint32_t final = n;\n"
                    "  SPX_PROOF_SYNC(done, 1, count, final);\n"
                    + ("  return n;" if mutation == "uncaptured_at_final" else "  return final;"),
                )
                if mutation == "final_capture":
                    source_text = source_text.replace("uint32_t final = n;", "uint32_t final = n + 1U;")
            if source_layout != "scalar":
                access = "." if source_layout == "member" else "->"
                declaration = (
                    "struct counter_state { uint32_t remaining; };\n"
                    "  struct counter_state values = {count};\n"
                    + ("  struct counter_state state = values;" if access == "."
                       else "  struct counter_state *state = &values;")
                )
                if mutation == "null_base":
                    declaration = declaration.replace("*state = &values", "*state = 0")
                source_text = source_text.replace("uint32_t n = count;", declaration)
                source_text = re.sub(r"\bn\b", "state" + access + "remaining", source_text)
            authored.write_text(source_text, encoding="ascii")
            package = root / "package"
            source = build_component_source_package(
                lift_unit_id="countdown",
                files={"countdown.c": authored},
                shared_inputs={},
                operation_symbols=symbols,
                out_dir=package,
            )
            profile = check_component_source_profile(package=package)
            operation_base = _operation()
            if mutation in {"parameter_local_alias", "parameter_codec", "state_codec"}:
                operation_base["units"][0]["semantics"]["register_writes"].append({
                    "register": "ecx", "value": {"op": "const", "value": 0, "width": 32},
                })
            operation_base["units"] = [
                (
                    unit
                    if unit["id"] != "body"
                    else {
                        **unit,
                        "semantics": {
                            **unit["semantics"],
                            "edge_conditions": [
                                {
                                    "target_rva": 0x1030,
                                    "condition": {"op": "true"},
                                }
                            ],
                            "outcome": {"kind": "jump", "target_rva": 0x1030},
                        },
                    }
                )
                for unit in operation_base["units"]
            ]
            unit_ids = {
                "entry": "semantic-transfer:original-cutpoint-00001000-00001010",
                "head": "semantic-transfer:original-cutpoint-00001010-00001020",
                "body": "semantic-transfer:original-cutpoint-00001020-00001030",
                "exit": "semantic-transfer:original-cutpoint-00001030-00001034",
            }
            operation = {
                **operation_base,
                "machine_image": {
                    "preferred_base": 0x400000,
                    "image_size": 0x10000,
                },
                "entry_unit_ids": [
                    "semantic-transfer:original-cutpoint-00001000-00001010"
                ],
                "exit_unit_ids": [
                    "semantic-transfer:original-cutpoint-00001030-00001034"
                ],
                "units": [
                    {**unit, "id": unit_ids[str(unit["id"])]}
                    for unit in operation_base["units"]
                ],
            }
            semantic = {
                "component_id": "countdown",
                "contract_sha256": "a" * 64,
                "operations": [operation],
            }
            proof_intent = _intent() if cut else ComponentBisimulationIntentV1.create(
                component_id="countdown",
                operations=[{"operation_id": "run", "syncs": []}],
            )
            if private_scope:
                operations = proof_intent.to_payload()["operations"]
                operations[0]["syncs"][0]["private_stack_scope"] = {
                    "register": "esp", "offset": 0,
                }
                proof_intent = ComponentBisimulationIntentV1.create(
                    component_id="countdown", operations=operations,
                )
            if stack_fact:
                self.assertTrue(cut)
                operations = proof_intent.to_payload()['operations']
                operations[0]['syncs'][0]['derived'].append({
                    'id': 'stack_count',
                    'projection': {'kind': 'stack', 'offset': 12 if mutation == 'stack_fact' else 8,
                                   'width': 32, 'at': 'entry'},
                    'expression': {'op': 'exact_projection', 'projection': {
                        'kind': 'register', 'register': 'ecx', 'width': 32, 'at': 'entry'}}})
                proof_intent = ComponentBisimulationIntentV1.create(component_id='countdown', operations=operations)
            if source_unwind_limit is not None:
                operations = proof_intent.to_payload()["operations"]
                operations[0]["source_unwind_limit"] = source_unwind_limit
                proof_intent = ComponentBisimulationIntentV1.create(component_id="countdown", operations=operations)
            if final_cut:
                operations = proof_intent.to_payload()["operations"]
                done = json.loads(json.dumps(operations[0]["syncs"][0]))
                done["id"] = "done"
                done["exact_unit_id"] = unit_ids["exit"]
                done["captures"][1]["id"] = "final"
                done["captures"][1]["encoding"]["name"] = "final"
                done["derived"][0]["expression"]["name"] = "final"
                operations[0]["syncs"].append(done)
                proof_intent = ComponentBisimulationIntentV1.create(
                    component_id="countdown", operations=operations,
                )
            if mutation in {"uncaptured_parameter", "dead_parameter", "omitted_live_parameter", "omitted_aliased_parameter"}:
                operations = proof_intent.to_payload()["operations"]
                sync = operations[0]["syncs"][0]
                sync["captures"] = [sync["captures"][1]]
                sync["invariant"] = {"op": "not", "args": [{"op": "eq", "args": [
                    {"op": "state_input", "name": "n"}, {"op": "const", "value": 0, "width": 32},
                ]}]}
                sync["derived"].append({"id": "original_count", "projection": {
                    "kind": "register", "register": "ecx", "width": 32, "at": "entry",
                }, "expression": {"op": "state_input", "name": "n"}})
                proof_intent = ComponentBisimulationIntentV1.create(
                    component_id="countdown", operations=operations,
                )
            if source_layout != "scalar":
                operations = proof_intent.to_payload()["operations"]
                operations[0]["syncs"][0]["source_bindings"] = {
                    "n": {"root": "state", "members": [{
                        "access": "direct" if source_layout == "member" else "pointer",
                        "name": "remaining",
                    }]},
                }
                proof_intent = ComponentBisimulationIntentV1.create(
                    component_id="countdown", operations=operations,
                )
            if mutation in {"renamed_parameter", "parameter_local_alias"}:
                operations = proof_intent.to_payload()["operations"]
                operations[0]["syncs"][0]["source_bindings"] = {"count": {
                    "root": "incoming" if mutation == "renamed_parameter" else "shadow", "members": [],
                }}
                proof_intent = ComponentBisimulationIntentV1.create(component_id="countdown", operations=operations)
            if mutation == "parameter_codec":
                operations = proof_intent.to_payload()["operations"]
                operations[0]["syncs"][0]["captures"][0]["encoding"] = {"op": "const", "value": 0, "width": 32}
                proof_intent = ComponentBisimulationIntentV1.create(component_id="countdown", operations=operations)
            if mutation == "state_codec":
                operations = proof_intent.to_payload()["operations"]
                captures = operations[0]["syncs"][0]["captures"]
                captures[0]["projection"]["register"] = "edx"
                captures[1]["projection"]["register"] = "ecx"
                captures[1]["encoding"] = {"op": "const", "value": 0, "width": 32}
                proof_intent = ComponentBisimulationIntentV1.create(component_id="countdown", operations=operations)
            plan = build_component_proof_plan_v1(
                component_id="countdown", semantic_contract_sha256="a" * 64,
                interface=interface, operations=[operation],
                operation_sources={"run": source_text},
                source_package_sha256=source["implementation_sha256"], intent=proof_intent,
            )
            self.assertEqual(plan["operations"][0]["exact"]["cyclic_sccs"], [])
            expected_shards = 1 + int(cut) + int(final_cut)
            self.assertEqual(plan["cost"]["shards"], expected_shards)
            self.assertEqual(plan["cost"]["materialized_paths"], 0)
            nodes_actions = {
                "entry": (
                    (_Node("reg", aux=2), _Node("const"), _Node("eq", (0, 1))),
                    (_Action("set_reg", (0,), aux=0), _Action("set_reg", (0,), aux=3),
                     _Action("outcome_branch", (2, 0x1030, 0x1010))),
                ),
                "head": (
                    (_Node("reg", aux=0), _Node("const"), _Node("eq", (0, 1))),
                    (_Action("outcome_branch", (2, 0x1030, 0x1020)),),
                ),
                "body": (
                    (_Node("reg", aux=3), _Node("const", immediate=1), _Node("sub32", (0, 1))),
                    (_Action("set_reg", (2,), aux=0), _Action("set_reg", (2,), aux=3),
                     _Action("outcome_jump", (0x1030,))),
                ),
                "exit": ((_Node("const"),), (_Action("outcome_return", (0,)),)),
            }
            if mutation == "undeclared_public_write":
                nodes_actions["exit"] = (
                    (_Node("const"), _Node("const", immediate=0x500000),
                     _Node("const", immediate=23)),
                    (_Action("memory_write", (1, 2), aux=1), _Action("outcome_return", (0,))),
                )
            if stack_fact:
                nodes, actions = nodes_actions['entry']
                nodes_actions['entry'] = ((*nodes, _Node('reg', aux=7), _Node('const', immediate=8),
                    _Node('add32', (3, 4))),
                    (_Action('memory_write', (5, 0), aux=4), *actions))
            if mutation in {"parameter_local_alias", "parameter_codec", "state_codec"}:
                nodes, actions = nodes_actions["entry"]
                nodes_actions["entry"] = (nodes, (*actions[:-1], _Action("set_reg", (1,), aux=2), actions[-1]))
            transfers = tuple(
                _Transfer(unit_ids[name], "a" * 64, "b" * 64, 0x1000 + index * 16,
                          nodes, (), actions, (), ())
                for index, (name, (nodes, actions)) in enumerate(nodes_actions.items())
            )
            exact_root = root / "exact"
            exact_slice = write_component_exact_c_slice_v1(
                component_id="countdown", transfers=transfers,
                operations=[{"operation_id": "run", "unit_ids": list(unit_ids.values()),
                             "entry_rvas": [0x1000]}],
                intent=proof_intent, executable_transfer_plan_sha256="c" * 64,
                out=exact_root,
            )
            overlay = '''#include "state-machine-runtime.h"
#include "portable-component-implementation.h"
spx_step_result spx_component_countdown_00001000(
    spx_runtime *rt, spx_machine_state *state) {
  spx_countdown_context_v2 context = {0};
  uint32_t result;
  (void)rt;
  result = countdown_run(&context, state->ecx);
  state->eax = result;
  return (spx_step_result){SPX_RETURN, 0U, 0U};
}
'''
            result = check_bisimulation_refinement(
                semantic_contract=semantic,
                interface=interface,
                source_package=package,
                source_profile=profile,
                intent=proof_intent,
                exact_c_root=exact_root,
                exact_c_slice=exact_slice,
                machine_overlay_source=overlay,
                machine_overlay_entries=[
                    {
                        "operation_id": "run",
                        "entry_rva": 0x1000,
                        "symbol": "spx_component_countdown_00001000",
                    }
                ],
                machine_projections={
                    "run": {"operation": operation, "service_bindings": []}
                },
                cbmc=Path(cbmc),
                c_headers={
                    "portable-component.h": interface.render_public_header(),
                    "portable-component-implementation.h": (
                        interface.render_implementation_header(symbols)
                    ),
                    "spx-reference-runtime.h": spx_reference_runtime_header(),
                },
                timeout_seconds=60,
                diagnostic_root=root / "diagnostics",
            )
            retained = root / "diagnostics"
            if (source_unwind_limit is not None or stack_fact) and result["status"] == "satisfied":
                from spaghetti_extractor.components.bisimulation_evidence import _validate_model_and_shard_evidence
                from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
                _validate_model_and_shard_evidence(proof_plan=plan, models=result["bindings"],
                    shard_results=result["checks"], checker=result["checker"])
                if source_unwind_limit is not None:
                    altered = copy.deepcopy(result["bindings"])
                    model = altered["operation_models"][0]["obligation_models"][0]
                    model["property_checker_command"]["assertion_arguments"].remove("--no-self-loops-to-assumptions")
                    model["property_checker_command_sha256"] = canonical_sha256_v3(model["property_checker_command"])
                    with self.assertRaisesRegex(ComponentBisimulationError, "checker command"):
                        _validate_model_and_shard_evidence(proof_plan=plan, models=altered,
                            shard_results=result["checks"], checker=result["checker"])
            hashes = {hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in retained.rglob("*") if path.is_file()}
            self.assertFalse(list(retained.rglob("*.goto")))
            for model in result["bindings"]["operation_models"][0]["obligation_models"]:
                self.assertTrue({row["sha256"] for row in model["proof_inputs"]} <= hashes)
            timing_files = list(retained.rglob("query-timings.jsonl"))
            self.assertEqual(len(timing_files), expected_shards)
            for path in timing_files:
                compilation = json.loads((path.parent / "compile-inputs.json").read_text())
                self.assertFalse(compilation["authorizing"])
                for row in compilation["files"]:
                    recorded = retained / row["path"].removeprefix("$PROOF_ROOT/")
                    self.assertEqual(hashlib.sha256(recorded.read_bytes()).hexdigest(), row["sha256"])
                self.assertIn(
                    "$PROOF_ROOT/" + (path.parent / "source-0000.c").relative_to(retained).as_posix(),
                    compilation["command"],
                )
                timings = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertTrue(all(row["authorizing"] is False for row in timings))
                self.assertIn("compile", {row["kind"] for row in timings})
                self.assertIn("assertion_inventory", {row["kind"] for row in timings})
                if result["status"] == "satisfied":
                    self.assertTrue(any(row["kind"].startswith("assertion:") for row in timings))

        if mutation:
            return result
        self.assertEqual(source["lift_unit_id"], "countdown")
        self.assertEqual(result["status"], "satisfied", result["issues"])
        self.assertEqual(len(result["checks"]), expected_shards)
        self.assertEqual(result["checker"]["maximum_parallel_shards"], 1)
        self.assertEqual(
            result["checker"]["maximum_parallel_solver_processes"], 4
        )
        self.assertFalse(result["checker"]["nested_solver_parallelism"])
        self.assertEqual(
            result["checker"]["model_bounds"][
                "maximum_atomics_per_obligation"
            ],
            1,
        )
        entry_model = result["bindings"]["operation_models"][0][
            "obligation_models"
        ][0]
        self.assertEqual(
            entry_model["proof_model_sha256"],
            entry_model["nonvacuity_proof_model_sha256"],
        )
        self.assertEqual(
            entry_model["nonvacuity_proof_inputs"],
            entry_model["proof_inputs"],
        )
        self.assertNotIn("inductive_cutpoint_live_in_relation", entry_model)
        self.assertTrue(
            result["checker"]["model_bounds"][
                "private_stack_disjoint_checked_image"
            ]
        )
        for check in result["checks"]:
            self.assertEqual(len(check["goto_model_sha256"]), 64)
            self.assertEqual(len(check["nonvacuity_goto_model_sha256"]), 64)
            self.assertEqual(
                len(check["property_checker_command_sha256"]), 64
            )
            self.assertEqual(
                len(check["nonvacuity_checker_command_sha256"]), 64
            )
            self.assertEqual(len(check["execution_binding_sha256"]), 64)
            self.assertEqual(
                check["goto_model_sha256"],
                check["nonvacuity_goto_model_sha256"],
            )
            model = next(
                row
                for row in result["bindings"]["operation_models"][0][
                    "obligation_models"
                ]
                if row["obligation_id"] == check["obligation_id"]
            )
            self.assertEqual(
                model["execution_binding_sha256"],
                check["execution_binding_sha256"],
            )

        return result

    def test_matching_acyclic_operation_uses_one_continuous_entry_proof(self) -> None:
        self._check_acyclic_operation()

    def test_current_stack_fact_composes_through_the_complete_regional_engine(self) -> None:
        result = self._check_acyclic_operation(cut=True, stack_fact=True)
        self.assertEqual(result['status'], 'satisfied')
        self.assertEqual(len(result['checks']), 2)
        rejected = self._check_acyclic_operation(cut=True, stack_fact=True, mutation='stack_fact')
        self.assertEqual(rejected['status'], 'violated', rejected['issues'])
        self.assertIn('spx-bisimulation-derived:loop:stack_count', str(rejected))

    def test_distinct_capture_vectors_compose_across_three_regions(self) -> None:
        self._check_acyclic_operation(cut=True, final_cut=True)

    def test_final_region_cannot_use_a_local_captured_only_at_an_earlier_cut(self) -> None:
        result = self._check_acyclic_operation(cut=True, final_cut=True, mutation="uncaptured_at_final")
        self.assertEqual(result["status"], "violated", result.get("issues"))
        self.assertTrue(any(row["status"] == "violated" and row["obligation_id"] == "sync:done"
                            for row in result["checks"]), result["checks"])

    def test_distinct_final_capture_is_checked_on_incoming_transitions(self) -> None:
        result = self._check_acyclic_operation(cut=True, final_cut=True, mutation="final_capture")
        self.assertEqual(result["status"], "violated", result.get("issues"))

    def test_omitted_mutated_parameter_cannot_revert_to_its_entry_value(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="uncaptured_parameter")
        self.assertEqual(result["status"], "violated", result.get("issues"))

    def test_setup_only_scalar_parameter_need_not_survive_a_cut(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="dead_parameter")
        self.assertEqual(result["status"], "satisfied", result.get("issues"))

    def test_omitted_live_scalar_is_arbitrary_in_the_resumed_proof(self) -> None:
        for mutation in ("omitted_live_parameter", "omitted_aliased_parameter"):
            with self.subTest(mutation=mutation):
                result = self._check_acyclic_operation(cut=True, mutation=mutation)
                self.assertEqual(result["status"], "violated", result.get("issues"))
                self.assertTrue(any(row["status"] == "violated" and row["obligation_id"] == "sync:loop"
                                    for row in result["checks"]), result["checks"])

    def test_reassigned_context_pointer_cannot_revert_to_its_entry_value(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="uncaptured_context")
        self.assertEqual(result["status"], "violated", result.get("issues"))

    def test_parameter_capture_cannot_substitute_a_different_local_object(self) -> None:
        with self.assertRaisesRegex(BisimulationRefinementError, "must bind its actual C argument"):
            self._check_acyclic_operation(cut=True, mutation="parameter_local_alias")

    def test_actual_parameter_may_be_renamed_in_source(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="renamed_parameter")
        self.assertEqual(result["status"], "satisfied", result.get("issues"))

    def test_parameter_capture_name_cannot_resolve_to_a_shadowing_local(self) -> None:
        with self.assertRaisesRegex(BisimulationRefinementError, "without shadowing"):
            self._check_acyclic_operation(cut=True, mutation="shadowed_parameter")

    def test_parameter_encoding_cannot_discard_the_argument_value(self) -> None:
        with self.assertRaisesRegex(ComponentBisimulationError, "canonical argument encoding"):
            self._check_acyclic_operation(cut=True, mutation="parameter_codec")

    def test_source_state_decoder_must_reproduce_the_captured_value(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="state_codec")
        self.assertEqual(result["status"], "violated", result.get("issues"))
        self.assertTrue(any("capture-roundtrip:loop:n" in row.get("detail", "")
                            for row in result["issues"]), result["issues"])

    def test_equal_results_do_not_hide_undeclared_public_memory_changes(self) -> None:
        result = self._check_acyclic_operation(mutation="undeclared_public_write")
        self.assertEqual(result["status"], "violated", result.get("issues"))

    def test_empty_infinite_loop_cannot_disappear_from_a_region_proof(self) -> None:
        with self.assertRaisesRegex(ComponentBisimulationError, "unannotated source cycle"):
            self._check_acyclic_operation(mutation="diverge")

    def test_scoped_cut_proves_complete_inventory_and_reachability(self) -> None:
        result = self._check_acyclic_operation(cut=True, private_scope=True)
        resumed = result["checks"][1]
        self.assertEqual(resumed["status"], "satisfied")
        self.assertEqual(resumed["nonvacuity"]["status"], "satisfied")

    def test_matching_acyclic_cut_proves_two_generated_regions(self) -> None:
        result = self._check_acyclic_operation(cut=True)
        models = result["bindings"]["operation_models"][0]["obligation_models"]
        self.assertEqual([m["scope"] for m in models], ["cutpoint_segment"] * 2)
        self.assertEqual([m["selected_unit_count"] for m in models], [2, 3])

    def test_acyclic_cut_rejects_wrong_live_value(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="capture")
        self.assertEqual(result["status"], "violated", result["issues"])
        self.assertTrue(any("capture:loop:n" in str(i) for i in result["issues"]), result["issues"])

    def test_acyclic_cut_rejects_wrong_suffix(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="suffix")
        self.assertEqual(result["status"], "violated", result["issues"])
        self.assertTrue(any("exit-observable" in str(i) for i in result["issues"]), result["issues"])

    def test_acyclic_cut_cannot_omit_a_branch_from_composition(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="missing_branch")
        self.assertEqual(result["status"], "violated", result["issues"])
        self.assertTrue(any("exit-control" in str(i) for i in result["issues"]), result["issues"])

    def test_acyclic_cut_resumes_struct_member_state(self) -> None:
        self._check_acyclic_operation(cut=True, source_layout="member")

    def test_acyclic_cut_resumes_pointer_member_state(self) -> None:
        self._check_acyclic_operation(cut=True, source_layout="pointer")

    def test_member_capture_does_not_assume_pointer_validity(self) -> None:
        result = self._check_acyclic_operation(cut=True, source_layout="pointer", mutation="null_base")
        self.assertEqual(result["status"], "violated", result["issues"])
        self.assertTrue(any("pointer" in str(i) for i in result["issues"]), result["issues"])

    def test_record_parameters_fit_inside_reserved_activation_window(self) -> None:
        from spaghetti_extractor.components.bisimulation_refinement import (
            PROOF_PRIVATE_STACK_ABOVE,
            _private_stack_high_offset,
        )

        self.assertEqual(
            _private_stack_high_offset(
                operation_projection={
                    "parameters": [
                        {
                            "id": "value",
                            "projection": {
                                "kind": "record_view",
                                "fields": [
                                    {
                                        "id": "low",
                                        "projection": {
                                            "kind": "stack",
                                            "offset": 80,
                                            "width": 32,
                                        },
                                    },
                                    {
                                        "id": "high",
                                        "projection": {
                                            "kind": "stack",
                                            "offset": 84,
                                            "width": 32,
                                        },
                                    },
                                ],
                            },
                        }
                    ],
                    "state": [],
                },
            ),
            PROOF_PRIVATE_STACK_ABOVE,
        )

    def test_every_obligation_reserves_the_complete_activation_frame(self) -> None:
        from spaghetti_extractor.components.bisimulation_refinement import (
            PROOF_PRIVATE_STACK_ABOVE,
            _private_stack_high_offset,
        )

        self.assertEqual(
            _private_stack_high_offset(
                operation_projection={"parameters": [], "state": []},
            ),
            PROOF_PRIVATE_STACK_ABOVE,
        )

    def test_entry_frame_uses_the_reserved_activation_window(self) -> None:
        from spaghetti_extractor.components.bisimulation_refinement import (
            PROOF_PRIVATE_STACK_ABOVE,
            _private_stack_high_offset,
        )

        self.assertEqual(
            _private_stack_high_offset(
                operation_projection={"parameters": [], "state": []},
            ),
            PROOF_PRIVATE_STACK_ABOVE,
        )

    def test_uncaptured_live_local_cannot_revert_to_its_initializer(self) -> None:
        for mutation in ("uncaptured_local", "uncaptured_array"):
            with self.subTest(mutation=mutation):
                result = self._check_acyclic_operation(cut=True, mutation=mutation)
                self.assertEqual(result["status"], "violated")

    def test_uncaptured_local_overwritten_after_the_cut_does_not_need_a_capture(self) -> None:
        result = self._check_acyclic_operation(cut=True, mutation="dead_local")
        self.assertEqual(result["status"], "satisfied")


if __name__ == "__main__":
    unittest.main()
