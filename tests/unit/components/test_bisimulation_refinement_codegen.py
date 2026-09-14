from __future__ import annotations

import tempfile
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation import (
    BisimulationOperationV1,
    ComponentBisimulationError,
    ComponentBisimulationIntentV1,
)
from spaghetti_extractor.components.bisimulation_exact import (
    _exact_stack_accesses,
    _connected_service_unit_costs,
    _validate_exact_slice,
    _expand_exact_direct_call_closure,
    _maximum_acyclic_path_cost,
    _obligation_exact_compilation_files,
)
from spaghetti_extractor.components.bisimulation_refinement import (
    _compact_exact_temporaries,
    _next_barrier_sync_ids,
    _render_proof_header,
    _segment_exact_unit_ids,
    _specialize_exact_function_source,
)
from spaghetti_extractor.components.bisimulation_support import (
    BisimulationRefinementError,
)
from spaghetti_extractor.components.bisimulation_harness import (
    _entry_preconditions,
    _nul_view_registrations,
    _projection_expression,
    _render_harness,
    _incoming_scalar_invariant,
    _validate_static_slot_rvas,
)
from spaghetti_extractor.components.interface_ir import (
    ProofKernelComponentInterface,
)
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.component_exact_c_slice import (
    _internal_direct_call_closure,
)
from spaghetti_extractor.transfer.model import _Action, _Call, _Transfer
from tests.unit.components.test_bisimulation_refinement import _intent
from tests.unit.components.test_inductive_relation import _interface, _operation


def _cover_functions(source: str) -> set[str]:
    current = ""
    result: set[str] = set()
    for line in source.splitlines():
        if line.startswith("void ") and "(" in line:
            current = line.removeprefix("void ").split("(", 1)[0]
        if line.lstrip().startswith("__CPROVER_cover("):
            result.add(current)
    return result




def _exact_transfer(
    unit_id: str,
    rva: int,
    *,
    outcome: _Action,
    calls: tuple[_Call, ...] = (),
) -> _Transfer:
    return _Transfer(
        identity=unit_id,
        contract_sha256="a" * 64,
        instruction_bytes_sha256="b" * 64,
        rva_start=rva,
        nodes=(),
        x87_nodes=(),
        actions=(*(_Action("call", (index,)) for index in range(len(calls))), outcome),
        calls=calls,
        x87_operations=(),
    )


def _direct_call(source_rva: int, target_rva: int, return_rva: int) -> _Call:
    return _Call(
        kind="internal_call",
        instruction_rva=source_rva,
        call_index=0,
        target_node=None,
        target_rva=target_rva,
        return_rva=return_rva,
        dll=None,
        symbol=None,
        ordinal=None,
        register_nodes=(),
        flag_nodes=(),
        argument_nodes=(),
        stack_inputs=(),
    )


class BisimulationRefinementCodegenTests(unittest.TestCase):
    def test_early_scalar_invariant_requires_complete_identity_word_transport(self):
        from dataclasses import replace
        sync = _intent().operations[0].syncs[0]
        invariant = {'op': 'ult32', 'args': [
            {'op': 'state_input', 'name': 'n'}, {'op': 'parameter', 'name': 'count'}]}
        sync = replace(sync, invariant=invariant)
        admitted = _incoming_scalar_invariant(sync, unsigned_words=['n', 'count'])
        self.assertIn('spx_proof_exact_input.edx', admitted[-1])
        self.assertIn('spx_proof_exact_input.ecx', admitted[-1])
        for words in ([], ['n'], ['count']):
            self.assertEqual(_incoming_scalar_invariant(sync, unsigned_words=words), [])
        for changed in (
            replace(sync, source_bindings={'n': {'kind': 'symbol', 'name': 'other'}}),
            replace(sync, invariant={'op': 'or', 'args': [invariant,
                {'op': 'eq', 'args': [{'op': 'byte_extent', 'name': 'count'},
                                     {'op': 'const', 'value': 0, 'width': 32}]}]}),
            replace(sync, invariant={'op': 'eq', 'args': [invariant['args'][0],
                {'op': 'const', 'value': 1 << 40, 'width': 64}]}),
            replace(sync, captures=tuple(replace(c, decoding=None) if c.identity == 'n' else c
                                         for c in sync.captures)),
        ):
            self.assertEqual(_incoming_scalar_invariant(changed, unsigned_words=['n', 'count']), [])

    def test_connected_summary_costs_end_at_the_next_cut(self):
        entry = {"service_bindings": [
            {"provider_kind": "external_call", "events": [{"unit_id": "entry"}]},
            {"provider_kind": "component_operation", "events": [
                {"unit_id": "left"}, {"unit_id": "right"}, {"unit_id": "right"},
                {"unit_id": "cut"}, {"unit_id": "later"}]},
        ]}
        edges = [{"source_unit_id": source, "target_unit_id": target} for source, target in
                 [("entry", "left"), ("entry", "right"), ("left", "cut"),
                  ("right", "cut"), ("cut", "later"), ("later", "cut")]]
        costs = _connected_service_unit_costs(entry)
        options = dict(selected_unit_ids={"entry", "left", "right", "cut", "later"},
                       control_edges=edges, barrier_unit_ids=frozenset({"cut"}), costs=costs)
        self.assertEqual(_maximum_acyclic_path_cost(start_unit_id="entry", **options), 2)
        untyped = _connected_service_unit_costs({"service_bindings": []},
            exact_internal_calls={"entry": 1, "later": 100})
        self.assertEqual(_maximum_acyclic_path_cost(start_unit_id="entry",
            **{**options, "costs": untyped}), 1)
        combined = _connected_service_unit_costs(entry, exact_internal_calls={"right": 2, "later": 100})
        self.assertEqual(combined["right"], 2)
        self.assertEqual(_maximum_acyclic_path_cost(start_unit_id="cut", **options), 2)
        self.assertEqual(_maximum_acyclic_path_cost(start_unit_id="entry",
            selected_unit_ids={"entry"}, control_edges=edges, costs=costs), 0)
        # Growing a different region cannot enlarge this region's summary cost.
        entry["service_bindings"][1]["events"] += [{"unit_id": "later"}] * 100
        options["costs"] = _connected_service_unit_costs(entry)
        self.assertEqual(_maximum_acyclic_path_cost(start_unit_id="entry", **options), 2)
        with self.assertRaisesRegex(BisimulationRefinementError, "exact unit"):
            _connected_service_unit_costs({"service_bindings": [
                {"provider_kind": "component_operation", "events": [{}]}]})

    def test_exact_slice_rejects_changed_proof_intent_before_model_generation(self):
        core = {'component_id': 'counter', 'bindings': {'bisimulation_intent_sha256': 'a' * 64}, 'files': []}
        value = {**core, 'slice_sha256': canonical_sha256_v3(core)}
        with tempfile.TemporaryDirectory() as temporary:
            _validate_exact_slice(value, Path(temporary), 'counter', intent_sha256='a' * 64)
            with self.assertRaisesRegex(ValueError, 'different bisimulation intent; regenerate'):
                _validate_exact_slice(value, Path(temporary), 'counter', intent_sha256='b' * 64)

    def test_exact_stack_accesses_are_derived_from_affine_generated_ssa(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "behavioral.c"
            source.write_text(
                "  spx_proof_words[0] = state->esp;\n"
                "  spx_proof_words[1] = 4U;\n"
                "  spx_proof_words[2] = ((spx_proof_words[0]) + "
                "(spx_proof_words[1]));\n"
                "  spx_proof_words[3] = 7U;\n"
                "  spx_write(rt, spx_proof_words[2], 4U, "
                "spx_proof_words[3], &fault);\n"
                "  spx_proof_words[4] = 8U;\n"
                "  spx_proof_words[5] = (spx_proof_words[0]) + "
                "(spx_proof_words[4]);\n"
                "  spx_proof_words[6] = spx_read(rt, spx_proof_words[5], 4U, "
                "&fault);\n",
                encoding="ascii",
            )

            accesses = _exact_stack_accesses(
                exact_files=(source,), service_bindings=()
            )

        self.assertEqual(accesses, [(4, 4), (8, 4)])

    def test_exact_stack_accesses_ignore_calls_beyond_the_selected_barrier(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "behavioral.c"
            source.write_text(
                "spx_unit_00001000:\n"
                "  spx_proof_words[0] = state->esp;\n"
                "  spx_proof_words[1] = 4U;\n"
                "  spx_proof_words[2] = (spx_proof_words[0]) + "
                "(spx_proof_words[1]);\n"
                "  spx_proof_words[3] = spx_read(rt, spx_proof_words[2], 4U, "
                "&fault);\n"
                "spx_unit_00002000:\n"
                "  const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00002000U, 0x00002000U, 0U, 0x00003000U, "
                "0x00002005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n",
                encoding="ascii",
            )

            accesses = _exact_stack_accesses(
                exact_files=(source,),
                service_bindings=(),
                selected_unit_rvas={0x1000},
            )

        self.assertEqual(accesses, [(4, 4)])

    def test_exact_stack_accesses_keep_pre_call_facts_and_transport_admitted_cleanup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            affine = Path(temporary) / "affine.c"
            affine.write_text(
                "  spx_proof_words[0] = state->esp;\n"
                "  spx_proof_words[1] = 7U;\n"
                "  spx_write(rt, spx_proof_words[0], 4U, "
                "spx_proof_words[1], &fault);\n",
                encoding="ascii",
            )
            direct = Path(temporary) / "direct.c"
            direct.write_text(
                "const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00001000U, 0x00001000U, 0U, 0x00002000U, "
                "0x00001005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n",
                encoding="ascii",
            )
            self.assertEqual(
                _exact_stack_accesses(
                    exact_files=(affine, direct), service_bindings=()
                ),
                [(0, 4)],
            )
            post_call = Path(temporary) / "post-call.c"
            post_call.write_text(
                "  spx_proof_words[0] = state->esp;\n"
                "    call_input.esp = spx_proof_words[0];\n"
                "  const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00001000U, 0x00001000U, 0U, 0x00002000U, "
                "0x00001005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n"
                "  spx_proof_words[1] = call_output.esp;\n"
                "  spx_proof_words[2] = 4U;\n"
                "  spx_proof_words[3] = ((spx_proof_words[1]) + "
                "(spx_proof_words[2]));\n"
                "  spx_proof_words[4] = spx_read(rt, spx_proof_words[3], "
                "4U, &fault);\n",
                encoding="ascii",
            )
            self.assertEqual(
                _exact_stack_accesses(
                    exact_files=(affine, post_call), service_bindings=()
                ),
                [(0, 4)],
            )
            cleanup_binding = {
                "provider_kind": "external_call",
                "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
                "external_contract_identity_sha256": "b" * 64,
                "service_id": "service",
                "argument_offsets": [0],
                "abi_template": "x86-stdcall",
                "events": [{
                    "instruction_rva": 0x1000,
                    "event_index": 0,
                    "return_rva": 0x1005,
                }],
            }
            self.assertEqual(
                _exact_stack_accesses(
                    exact_files=(affine,),
                    service_bindings=(cleanup_binding,),
                ),
                [(0, 4)],
            )
            external = post_call.read_text().replace("SPX_CALL_INTERNAL_DIRECT", "SPX_CALL_EXTERNAL_IMPORT")
            post_call.write_text(external)
            self.assertEqual(_exact_stack_accesses(exact_files=(affine, post_call),
                service_bindings=(cleanup_binding,)), [(0, 4), (8, 4)])
            # An unbound site must not inherit a different site's cleanup.
            post_call.write_text(external.replace("0x00001000U", "0x00003000U"))
            self.assertEqual(_exact_stack_accesses(exact_files=(affine, post_call),
                service_bindings=(cleanup_binding,)), [(0, 4)])

    def test_exact_slice_closes_recursive_internal_direct_calls_as_context(
        self,
    ) -> None:
        root = _exact_transfer(
            "root",
            0x1000,
            outcome=_Action("outcome_return", (0,)),
            calls=(_direct_call(0x1000, 0x2000, 0x1005),),
        )
        callee_entry = _exact_transfer(
            "callee-entry",
            0x2000,
            outcome=_Action("outcome_fallthrough", (0x2010,)),
        )
        callee_tail = _exact_transfer(
            "callee-tail",
            0x2010,
            outcome=_Action("outcome_return", (0,)),
            calls=(_direct_call(0x2010, 0x3000, 0x2015),),
        )
        nested = _exact_transfer(
            "nested",
            0x3000,
            outcome=_Action("outcome_return", (0,)),
        )

        closure = _internal_direct_call_closure(
            transfers=(root, callee_entry, callee_tail, nested),
            seed_unit_ids=("root",),
        )

        self.assertEqual(
            closure["unit_ids"],
            ["callee-entry", "callee-tail", "nested"],
        )
        self.assertEqual(closure["entry_rvas"], [0x2000, 0x3000])
        self.assertEqual(len(closure["call_edges"]), 2)
        self.assertNotIn("root", closure["unit_ids"])

    def test_exact_slice_rejects_unresolved_internal_direct_call(self) -> None:
        root = _exact_transfer(
            "root",
            0x1000,
            outcome=_Action("outcome_return", (0,)),
            calls=(_direct_call(0x1000, 0x2000, 0x1005),),
        )

        with self.assertRaisesRegex(
            ComponentBisimulationError,
            "internal direct-call target 0x00002000 is absent",
        ):
            _internal_direct_call_closure(
                transfers=(root,),
                seed_unit_ids=("root",),
            )

    def test_obligation_slice_adds_the_called_exact_function(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            exact_root = Path(temporary)
            (exact_root / "behavioral.c").write_text(
                "const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00001000U, 0x00001000U, 0U, 0x00002000U, "
                "0x00001005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n"
                "(void)0;\n"
                "(void)0;\n",
                encoding="ascii",
            )
            source_by_unit = {
                "root": {
                    "unit_id": "root",
                    "file": "behavioral.c",
                    "line_start": 1,
                    "line_end": 1,
                    "rva": 0x1000,
                },
                "callee-entry": {
                    "unit_id": "callee-entry",
                    "file": "behavioral.c",
                    "line_start": 2,
                    "line_end": 2,
                    "rva": 0x2000,
                },
                "callee-tail": {
                    "unit_id": "callee-tail",
                    "file": "behavioral.c",
                    "line_start": 3,
                    "line_end": 3,
                    "rva": 0x2010,
                },
            }
            exact_slice = {
                "unit_ids": ["root"],
                "internal_direct_call_closure": {
                    "unit_ids": ["callee-entry", "callee-tail"],
                    "entry_rvas": [0x2000],
                    "call_edges": [
                        {
                            "source_unit_id": "root",
                            "source_rva": 0x1000,
                            "instruction_rva": 0x1000,
                            "call_index": 0,
                            "target_unit_id": "callee-entry",
                            "target_rva": 0x2000,
                            "return_rva": 0x1005,
                        }
                    ],
                },
                "functions": [
                    {"unit_rvas": [0x1000]},
                    {"unit_rvas": [0x2000, 0x2010]},
                ],
            }

            selected = _expand_exact_direct_call_closure(
                selected_unit_ids={"root"},
                exact_c_slice=exact_slice,
                exact_root=exact_root,
                source_by_unit=source_by_unit,
            )
            summarized = _expand_exact_direct_call_closure(
                selected_unit_ids={"root"}, exact_c_slice=exact_slice,
                exact_root=exact_root, source_by_unit=source_by_unit,
                summarized_entry_rvas=frozenset({0x2000}),
            )

        self.assertEqual(selected, {"root", "callee-entry", "callee-tail"})
        self.assertEqual(summarized, {"root"})

    def test_obligation_materializes_multi_function_call_closure(self) -> None:
        operation = _operation()
        unit_ids = {
            "entry": "semantic-transfer:original-cutpoint-00001000-00001010",
            "head": "semantic-transfer:original-cutpoint-00001010-00001020",
            "body": "semantic-transfer:original-cutpoint-00001020-00001030",
            "exit": "semantic-transfer:original-cutpoint-00001030-00001034",
        }
        operation = {
            **operation,
            "entry_unit_ids": [unit_ids["entry"]],
            "exit_unit_ids": [unit_ids["exit"]],
            "units": [
                {**unit, "id": unit_ids[str(unit["id"])]}
                for unit in operation["units"]
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            exact_root = Path(temporary) / "exact"
            out_dir = Path(temporary) / "out"
            exact_root.mkdir()
            out_dir.mkdir()
            root_source = exact_root / "behavioral-root.c"
            root_source.write_text(
                "#include \"behavioral-c.h\"\n"
                "spx_step_result spx_root(spx_runtime *rt, "
                "spx_machine_state *state, uint32_t source_rva) {\n"
                "  switch (source_rva) {\n"
                "    case 0x00001000U: goto spx_unit_00001000;\n"
                "    case 0x00001030U: goto spx_unit_00001030;\n"
                "  }\n"
                "spx_unit_00001000:\n"
                "  const spx_call_event event = { SPX_CALL_INTERNAL_DIRECT, "
                "0x00001000U, 0x00001000U, 0U, 0x00002000U, "
                "0x00001005U, 0, 0, 0U, 0U, 0, 0U, 0, 0U };\n"
                "  (void)rt; (void)state; (void)event;\n"
                "  return (spx_step_result){SPX_FALLTHROUGH, 0x00001030U, 0U};\n"
                "spx_unit_00001030:\n"
                "  return (spx_step_result){SPX_RETURN, 0U, 0U};\n"
                "}\n",
                encoding="ascii",
            )
            helper_source = exact_root / "behavioral-helper.c"
            helper_source.write_text(
                "#include \"behavioral-c.h\"\n"
                "spx_step_result spx_helper(spx_runtime *rt, "
                "spx_machine_state *state, uint32_t source_rva) {\n"
                "  switch (source_rva) {\n"
                "    case 0x00002000U: goto spx_unit_00002000;\n"
                "  }\n"
                "spx_unit_00002000:\n"
                "  (void)rt; (void)state;\n"
                "  return (spx_step_result){SPX_RETURN, 0U, 0U};\n"
                "}\n",
                encoding="ascii",
            )
            dispatch_source = exact_root / "behavioral-dispatch.c"
            dispatch_source.write_text(
                "#include \"behavioral-c.h\"\n"
                "const uint32_t spx_behavioral_transfer_count = 3U;\n"
                "spx_step_result spx_behavioral_step(spx_runtime *rt, "
                "spx_machine_state *state, uint32_t source_rva) {\n"
                "  switch (source_rva) {\n"
                "    case 0x00001000U: return spx_root(rt, state, source_rva);\n"
                "    case 0x00001030U: return spx_root(rt, state, source_rva);\n"
                "    case 0x00002000U: return spx_helper(rt, state, source_rva);\n"
                "  }\n"
                "}\n",
                encoding="ascii",
            )
            exact_slice = {
                "unit_ids": [unit_ids["entry"], unit_ids["exit"]],
                "internal_direct_call_closure": {
                    "unit_ids": ["helper"],
                    "entry_rvas": [0x2000],
                    "call_edges": [
                        {
                            "source_unit_id": unit_ids["entry"],
                            "source_rva": 0x1000,
                            "instruction_rva": 0x1000,
                            "call_index": 0,
                            "target_unit_id": "helper",
                            "target_rva": 0x2000,
                            "return_rva": 0x1005,
                        }
                    ],
                },
                "functions": [
                    {"unit_rvas": [0x1000, 0x1030]},
                    {"unit_rvas": [0x2000]},
                ],
                "source_map": [
                    {
                        "unit_id": unit_ids["entry"],
                        "file": root_source.name,
                        "symbol": "spx_root",
                        "line_start": 7,
                        "line_end": 10,
                        "rva": 0x1000,
                    },
                    {
                        "unit_id": unit_ids["exit"],
                        "file": root_source.name,
                        "symbol": "spx_root",
                        "line_start": 11,
                        "line_end": 12,
                        "rva": 0x1030,
                    },
                    {
                        "unit_id": "helper",
                        "file": helper_source.name,
                        "symbol": "spx_helper",
                        "line_start": 6,
                        "line_end": 8,
                        "rva": 0x2000,
                    },
                ],
                "policy": {"forced_labels_are_step_barriers": True},
            }

            copied, model = _obligation_exact_compilation_files(
                out_dir=out_dir,
                exact_files=(root_source, helper_source, dispatch_source),
                exact_root=exact_root,
                exact_c_slice=exact_slice,
                operation=operation,
                authored=_intent().operations[0],
                start_unit_id=unit_ids["entry"],
                connected=False,
            )

        self.assertEqual(len(copied), 3)
        self.assertEqual(model["internal_direct_call_unit_ids"], ["helper"])
        self.assertEqual(model["internal_direct_call_unit_count"], 1)

    def test_resumed_harness_uses_the_universal_authored_relation(self) -> None:
        arguments = {
            "interface": _interface(),
            "authored": _intent().operations[0],
            "machine_image": {
                "preferred_base": 0x400000,
                "image_size": 0x10000,
            },
            "operation_projection": {"operation": _operation()},
            "overlay_entry": {
                "symbol": "spx_component_countdown_00001000",
                "service_bindings": [],
            },
            "functions": [{
                "symbol": "spx_check_loop",
                "sync_id": "loop",
                "start_code": 1,
                "start_rva": 0x1010,
            }],
            "max_writes": 1,
            "max_private_writes": 1,
            "max_calls": 1,
            "max_atomics": 1,
            "max_shadow_bytes": 8,
            "max_nul_views": 1,
            "service_bindings": [],
            "connected_summaries": [],
            "include_finite_control": False,
        }
        rendered = _render_harness(**arguments)

        # Both the executable region and relation witness must construct the
        # transported domain. Changing only the outgoing barrier is incomplete.
        from dataclasses import replace
        scalar = replace(arguments['authored'], syncs=tuple(replace(sync,
            invariant={'op': 'ult32', 'args': [{'op': 'state_input', 'name': 'n'},
                                             {'op': 'parameter', 'name': 'count'}]})
            for sync in arguments['authored'].syncs))
        early = _render_harness(**{**arguments, 'authored': scalar,
                                    'cut_unsigned_words': {'loop': ['n', 'count']}})
        for function in ('spx_check_loop', 'spx_check_loop_relation'):
            body = early.split(f'void {function}(void) {{', 1)[1].split('\n}', 1)[0]
            marker = '/* Existing unsigned scalar cut invariant: loop. */'
            self.assertLess(body.index('spx_proof_exact_input = initial_state;'), body.index(marker))
            self.assertLess(body.index(marker), body.index('source_result = spx_component_'))
            if function == 'spx_check_loop':
                self.assertLess(body.index(marker), body.index('spx_behavioral_step('))
        from spaghetti_extractor.components.bisimulation_stack_scope import PrivateStackScopeV1
        from spaghetti_extractor.components.inductive_relation import CutpointDerivedRelationV1
        authored = arguments["authored"]
        target_fact = CutpointDerivedRelationV1.parse({"id": "target",
            "projection": {"kind": "register", "register": "ebx", "width": 32, "at": "entry"},
            "expression": {"op": "exact_projection", "projection": {
                "kind": "static_slot", "rva": 128, "width": 32, "at": "entry"}}}, "target fact")
        scoped = replace(authored, syncs=tuple(replace(sync,
            private_stack_scope=PrivateStackScopeV1("ebp", 4), derived=(target_fact,)) for sync in authored.syncs))
        transported = _render_harness(**{**arguments, "authored": scoped})
        for function in ("spx_check_loop", "spx_check_loop_relation"):
            body = transported.split(f"void {function}(void) {{", 1)[1].split("\n}", 1)[0]
            self.assertIn("spx_proof_reset_worlds_in_scope(initial_state.esp,", body)
            self.assertIn("spx_proof_private_scope_input_loop(", body)
            self.assertNotIn("__CPROVER_assume(initial_state.esp >=", body)
            self.assertIn("(uint64_t)(((int64_t)initial_state.ebp + INT64_C(4)))", body)
            fact = "__CPROVER_assume((((initial_state.ebx))) == (spx_proof_exact_input_read("
            self.assertIn(fact, body)
            self.assertLess(body.index(fact), body.index("spx_proof_exact_input = initial_state;"))

        self.assertEqual(transported.count('"spx-bisimulation-private-stack-scope-input:loop"'), 1)

        for kind in ("shared-view-inputs", "source-frame-preservation"):
            for function in ("spx_check_loop", "spx_check_loop_relation"):
                description = f'"spx-bisimulation-{kind}:run:{function}"'
                self.assertEqual(rendered.count(description), 1, description)

        self.assertNotIn("spx_proof_reach_cutpoint", rendered)
        self.assertNotIn("spx_proof_exact_prefix", rendered)
        self.assertNotIn("exact_prefix_state", rendered)
        self.assertNotIn("lean_witness", rendered)
        self.assertNotIn("spx_lean_", rendered)

        source_byte = rendered[
            rendered.index("static uint8_t spx_proof_source_byte(") :
            rendered.index("static uint32_t spx_proof_exact_read(")
        ]
        self.assertIn("spx_source_world.shadow[0]", source_byte)
        self.assertNotIn("spx_exact_world.writes", source_byte)
        self.assertIn("uint32_t exact_position = position;", rendered)
        self.assertNotIn("spx_proof_world_writes_equal", rendered)
        self.assertNotIn("spx-bisimulation-write-address", rendered)
        self.assertIn('"spx-bisimulation-exact-input-read"', rendered)
        self.assertIn(
            "__CPROVER_assume(fault == UINT32_C(0));", rendered
        )
        self.assertNotIn("spx_proof_world_capacity_ok", rendered)
        self.assertNotIn("world-capacity", rendered)
        self.assertEqual(
            _cover_functions(rendered),
            {"spx_bisimulation_relation_witness"},
        )

        relation = rendered[rendered.index("void spx_check_loop_relation(void) {") :]
        self.assertIn("spx_proof_relation_probe = UINT32_C(1);", relation)
        self.assertIn(
            "source_result = spx_component_countdown_00001000(", relation
        )
        self.assertNotIn("spx_behavioral_step(", relation)
        self.assertNotIn("spx-bisimulation-exit-control", relation)
        self.assertNotIn("spx-bisimulation-exit-world", relation)
        self.assertIn("__CPROVER_assume(0);", relation)

        with patch(
            "spaghetti_extractor.components.bisimulation_harness._finite_control_proof_model",
            return_value={
                "immutable_bytes": [],
                "selector_expression": "initial_state.eax",
                "preconditions": [],
                "witness_definitions": [
                    "void spx_finite_control_route_0000(uint32_t selector) {",
                    "  (void)selector;",
                    "  __CPROVER_cover(1);",
                    "}",
                ],
                "witness_functions": ["spx_finite_control_route_0000"],
            },
        ):
            finite = _render_harness(
                **{**arguments, "include_finite_control": True}
            )
        dispatcher = (
            "spx_finite_control_route_0000(spx_proof_relation_selector);"
        )
        relation = finite[finite.index("void spx_check_loop_relation(void) {") :]
        self.assertIn(dispatcher, finite)
        self.assertIn(
            "spx_proof_relation_selector =\n      initial_state.eax;",
            relation,
        )
        self.assertLess(
            relation.index("spx_proof_relation_selector ="),
            relation.index(
                "source_result = spx_component_countdown_00001000("
            ),
        )
        self.assertEqual(
            _cover_functions(finite),
            {"spx_finite_control_route_0000"},
        )

    def test_harness_emits_typed_barrier_prefix_entries(self) -> None:
        binding = {
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "service_id": "service",
            "argument_offsets": [0, 4],
            "events": [{
                "instruction_rva": 0x1000,
                "event_index": 0,
                "return_rva": 0x1005,
            }],
        }
        rendered = _render_harness(
            interface=_interface(),
            authored=_intent().operations[0],
            machine_image={"preferred_base": 0x400000, "image_size": 0x10000},
            operation_projection={"operation": _operation()},
            overlay_entry={
                "symbol": "spx_component_countdown_00001000",
                "service_bindings": [binding],
            },
            functions=[{
                "symbol": "spx_check_entry",
                "sync_id": None,
                "start_code": 0,
                "start_rva": 0x1000,
            }],
            max_writes=1,
            max_private_writes=1,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=8,
            max_nul_views=1,
            service_bindings=[binding],
            connected_summaries=[],
            include_finite_control=False,
        )

        wrapper = "void spx_check_entry_focus_typed_call_0(void) {"
        self.assertIn(wrapper, rendered)
        body = rendered[rendered.index(wrapper) :]
        self.assertLess(
            body.index("spx_proof_property_focus_kind = UINT32_C(1);"),
            body.index("spx_check_entry();"),
        )
        self.assertIn(
            "spx_proof_property_focus_position = UINT32_C(0);", body
        )
        self.assertNotIn("spx_proof_property_focus_index", body)

    def test_continuous_acyclic_harness_requires_one_terminal_exact_step(self) -> None:
        rendered = _render_harness(
            interface=_interface(),
            authored=BisimulationOperationV1("run", ()),
            machine_image={"preferred_base": 0x400000, "image_size": 0x10000},
            operation_projection={"operation": _operation()},
            overlay_entry={
                "symbol": "spx_component_countdown_00001000",
                "service_bindings": [],
            },
            functions=[{
                "symbol": "spx_check_entry",
                "sync_id": None,
                "start_code": 0,
                "start_rva": 0x1000,
            }],
            max_writes=1,
            max_private_writes=1,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=8,
            max_nul_views=1,
            service_bindings=[],
            connected_summaries=[],
            include_finite_control=False,
            continuous_acyclic=True,
            continuous_exact_unit_rvas=[0x1000, 0x1010],
        )

        property_body = rendered[
            rendered.index("void spx_check_entry(void) {") :
            rendered.index("void spx_check_entry_relation(void) {")
        ]
        self.assertEqual(
            property_body.count("spx_proof_exact_result = spx_behavioral_step("),
            1,
        )
        self.assertIn(
            "spx-bisimulation-continuous-exact-internal-transfer:run:spx_check_entry",
            property_body,
        )
        self.assertIn(
            "spx_proof_exact_result.target_rva == UINT32_C(4096)",
            property_body,
        )
        self.assertIn(
            "source_result = spx_component_countdown_00001000(",
            property_body,
        )
        self.assertLess(
            property_body.index("spx_proof_exact_result = spx_behavioral_step("),
            property_body.index(
                "source_result = spx_component_countdown_00001000("
            ),
        )
        self.assertNotIn("spx_check_entry_source_safety", rendered)
        relation_body = rendered[
            rendered.index("void spx_check_entry_relation(void) {") :
        ]
        self.assertNotIn("spx_behavioral_step(", relation_body)

    def test_exact_ssa_temporaries_share_one_bounded_proof_object(self) -> None:
        rendered = _compact_exact_temporaries(
            """spx_step_result f(void) {
  uint32_t w_00001000_0 = 0U;
  uint32_t w_00001000_1 = 0U;
  w_00001000_0 = 3U;
  w_00001000_1 = w_00001000_0 + 1U;
}
"""
        )
        self.assertIn("uint32_t spx_proof_words[2] = {0U};", rendered)
        self.assertIn("spx_proof_words[1] = spx_proof_words[0] + 1U;", rendered)
        self.assertNotIn("w_00001000_", rendered)

    def test_exact_source_specialization_retains_the_function_epilogue(self) -> None:
        source = """#include \"behavioral-c.h\"
spx_step_result spx_behavioral_fn(spx_runtime *rt) {
  uint32_t w_00001000_0 = 0U;
  switch (0U) {
    case 0x00001000U: goto spx_unit_00001000;
  }
spx_unit_00001000:
  (void)rt;
  return (spx_step_result){SPX_FALLTHROUGH, 0U, 0U};
}
"""
        rows = [
            {
                "symbol": "spx_behavioral_fn",
                "line_start": 7,
                "line_end": 9,
                "rva": 0x1000,
            }
        ]
        rendered = _specialize_exact_function_source(
            source=source,
            rows=rows,
            all_rows=rows,
            selected_rvas={0x1000},
        )
        self.assertTrue(rendered.rstrip().endswith("}"))
        self.assertEqual(rendered.count("spx_unit_00001000:"), 1)

    def test_exact_segment_closure_stops_at_authored_barrier(self) -> None:
        operation = _operation()
        unit_ids = {
            "entry": "semantic-transfer:original-cutpoint-00001000-00001010",
            "head": "semantic-transfer:original-cutpoint-00001010-00001020",
            "body": "semantic-transfer:original-cutpoint-00001020-00001030",
            "exit": "semantic-transfer:original-cutpoint-00001030-00001034",
        }
        operation = {
            **operation,
            "entry_unit_ids": [unit_ids["entry"]],
            "exit_unit_ids": [unit_ids["exit"]],
            "units": [
                {**unit, "id": unit_ids[str(unit["id"])]}
                for unit in operation["units"]
            ],
        }
        self.assertEqual(
            _segment_exact_unit_ids(
                operation=operation,
                authored=_intent().operations[0],
                start_unit_id=unit_ids["entry"],
            ),
            {unit_ids["entry"], unit_ids["exit"]},
        )
        self.assertEqual(
            _segment_exact_unit_ids(
                operation=operation,
                authored=_intent().operations[0],
                start_unit_id=unit_ids["head"],
            ),
            {unit_ids["head"], unit_ids["body"], unit_ids["exit"]},
        )
        self.assertEqual(
            _next_barrier_sync_ids(
                operation=operation,
                authored=_intent().operations[0],
                selected_unit_ids={unit_ids["entry"], unit_ids["exit"]},
            ),
            {"loop"},
        )

    def test_proof_header_specializes_source_barriers_to_one_shard(self) -> None:
        authored = _intent().operations[0]
        entry = _render_proof_header(
            authored=authored,
            image_base=0x400000,
            active_target_sync_ids={"loop"},
        )
        resumed = _render_proof_header(
            authored=authored,
            image_base=0x400000,
            active_start_sync_id="loop",
            active_target_sync_ids=set(),
        )
        inactive = _render_proof_header(
            authored=authored,
            image_base=0x400000,
            active_target_sync_ids=set(),
        )
        self.assertNotIn("if (spx_proof_start == UINT32_C(1)) goto", entry)
        self.assertIn("spx-bisimulation-invariant:loop", entry)
        self.assertNotIn("spx_proof_source_safety", entry)
        self.assertNotIn("spx_proof_source_safety", resumed)
        self.assertNotIn("spx_proof_exact_input.ecx", entry)
        self.assertNotIn("spx_proof_resumed = UINT32_C(1)", entry)
        self.assertNotIn("spx-bisimulation-invariant:loop", resumed)
        self.assertNotIn("spx-bisimulation-capture:loop:count", resumed)
        self.assertIn("spx-bisimulation-sync-alignment:loop", resumed)
        self.assertIn(
            'spx_proof_exact_output.ecx))) == (count), '
            '"spx-bisimulation-capture:loop:count"',
            entry,
        )
        self.assertIn("spx_proof_exact_output.edx", entry)
        self.assertIn("goto spx_proof_sync_loop", resumed)
        self.assertIn(
            "spx_proof_unexpected_sync_loop(UINT32_C(0))",
            inactive,
        )
        witness = "spx_bisimulation_relation_witness"
        self.assertEqual(entry.count(witness), 1)
        self.assertEqual(resumed.count(witness), 2)
        self.assertEqual(inactive.count(witness), 1)

    def test_logical_cutpoint_definitions_follow_machine_decoding(self) -> None:
        intent = ComponentBisimulationIntentV1.create(
            component_id="dependent-cutpoint",
            operations=[{
                "operation_id": "run",
                "syncs": [{
                    "id": "resume",
                    "exact_unit_id": (
                        "semantic-transfer:original-cutpoint-00001010-00001020"
                    ),
                    "invariant": {"op": "true"},
                    "captures": [
                        {
                            "kind": "source_state",
                            "id": "a_derived",
                            "mode": "logical_definition",
                            "projection": None,
                            "encoding": {
                                "op": "state_input",
                                "name": "z_machine",
                            },
                            "decoding": None,
                        },
                        {
                            "kind": "source_state",
                            "id": "z_machine",
                            "mode": "machine_codec",
                            "projection": {
                                "kind": "register",
                                "register": "edx",
                                "width": 32,
                                "at": "entry",
                            },
                            "encoding": {
                                "op": "state_input",
                                "name": "z_machine",
                            },
                            "decoding": {"op": "projected_value"},
                        },
                    ],
                    "derived": [],
                }],
            }],
        )

        rendered = _render_proof_header(
            authored=intent.operations[0], image_base=0x400000
        )

        self.assertLess(
            rendered.index("z_machine ="),
            rendered.index("a_derived = (z_machine)"),
        )


if __name__ == "__main__":
    unittest.main()
