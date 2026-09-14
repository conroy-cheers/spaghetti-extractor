from __future__ import annotations

from dataclasses import replace

import hashlib

import json

import shutil

import subprocess

import unittest

from pathlib import Path

from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError

from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1

from spaghetti_extractor.components.bisimulation_connected import (
    connected_source_prefix,
    render_connected_summary_wrapper,
)

from spaghetti_extractor.components.bisimulation_connected import (
    _connected_replay_source,
)

from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)

from spaghetti_extractor.components.bisimulation_refinement import (
    _compact_exact_temporaries,
    _exit_comparisons,
    _finite_control_proof_model,
    _next_barrier_sync_ids,
    _obligation_functions,
    _render_proof_header,
    _required_assertion_descriptions,
    _segment_exact_unit_ids,
    _render_source_expression,
    _source_service_unit_costs,
    _specialize_exact_function_source,
    _specialize_machine_overlay_for_proof,
    _world_source,
    build_typed_proof_service_thunk_renderer,
    check_bisimulation_refinement,
)

from spaghetti_extractor.components.capabilities import spx_reference_runtime_header

from spaghetti_extractor.components.cbmc_backend import (
    discover_cbmc_assertions,
    discover_cbmc_loops,
    discover_cbmc_safety_properties,
    run_cbmc_cover,
    run_cbmc_properties,
)

from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface

from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)

from spaghetti_extractor.components.bisimulation_typed_services import (
    _canonical_proof_service_bindings,
    _proof_call_specs,
)

from spaghetti_extractor.components.machine_binding import MachineProjectionV1

from spaghetti_extractor.components.refinement_v5 import (
    _logical_projection,
    _materialize_kernel_finite_control_targets,
)

from spaghetti_extractor.components.source import build_component_source_package

from spaghetti_extractor.components.source_profile import (
    _block_scope_static_storage,
    _nonconstant_macro_definitions,
    _top_level_object_declarations,
    check_component_source_profile,
)

from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

from spaghetti_extractor.util import sha256_file

from tests.unit.components.test_inductive_relation import _interface, _operation

ROOT = Path(__file__).parents[3]

TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": (
        "targets/dxball/intent/interfaces-v5/directdraw-init.json",
        "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",
        "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json",
        "targets/gnu-hello/intent/interfaces-v5/startup-callback-registration.json",
        "targets/jq/intent/interfaces-v5/output-value-pipeline.json",
    ),
}



class BisimulationServiceTests(unittest.TestCase):
    def test_connected_service_cost_uses_unique_overlay_owner(self) -> None:
        writes, calls = _source_service_unit_costs(
            overlay_sources=[
                "spx_step_result root(void) {\n  return (spx_step_result){0};\n}\n",
                "void connected_service(void) {\n  spx_component_write();\n}\n",
            ],
            overlay_entry={
                "service_bindings": [
                    {
                        "symbol": "connected_service",
                        "events": [{"unit_id": "unit:service"}],
                    }
                ]
            },
        )
        self.assertEqual(writes, {"unit:service": 4})
        self.assertEqual(calls, {"unit:service": 1})


    def test_service_cost_rejects_ambiguous_overlay_owner(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "exactly one definition in the proof overlay closure"
        ):
            _source_service_unit_costs(
                overlay_sources=[
                    "void connected_service(void) {}",
                    "void connected_service(void) {}",
                ],
                overlay_entry={
                    "service_bindings": [
                        {
                            "symbol": "connected_service",
                            "events": [{"unit_id": "unit:service"}],
                        }
                    ]
                },
            )


    def test_restricted_source_profile_distinguishes_helpers_from_hidden_state(
        self,
    ) -> None:
        self.assertEqual(
            _top_level_object_declarations(
                "static uint32_t helper(uint32_t value) { return value; }\n"
                "uint32_t operation(uint32_t value) { uint32_t local = value; return local; }\n"
            ),
            [],
        )
        self.assertEqual(
            len(
                _top_level_object_declarations(
                    "static uint32_t hidden = 0U;\n"
                    "uint32_t operation(void) { return hidden++; }\n"
                )
            ),
            1,
        )
        self.assertEqual(
            len(
                _block_scope_static_storage(
                    "uint32_t operation(void) { static uint32_t calls; return calls++; }"
                )
            ),
            1,
        )
        self.assertEqual(
            _nonconstant_macro_definitions(
                "#define SAFE UINT32_C(7)\n#define HIDDEN static uint32_t state;\n"
            ),
            [25],
        )


    def test_exact_stack_address_is_rendered_from_the_selected_machine_side(
        self,
    ) -> None:
        expression = {"op": "exact_stack_address", "offset": 112}
        self.assertEqual(
            _render_source_expression(expression, memory="input"),
            "((spx_proof_exact_input.esp) + UINT32_C(112))",
        )
        self.assertEqual(
            _render_source_expression(expression, memory="output"),
            "((spx_proof_exact_output.esp) + UINT32_C(112))",
        )


    def test_private_memory_is_sparse_and_width_aware(self) -> None:
        rendered = _world_source(
            max_writes=1,
            max_private_writes=2,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(),
            private_ranges=(),
        )
        self.assertIn("private_writes[1].width", rendered)
        self.assertIn("spx_proof_write_event private_writes[2]", rendered)
        self.assertIn("spx_proof_append_private_write", rendered)
        self.assertIn("world->writes[0].width = width", rendered)
        self.assertIn("spx_proof_append_write(world, address, width, value);", rendered)
        self.assertNotIn("spx_proof_append_byte", rendered)
        self.assertIn("spx_proof_exact_private_read", rendered)
        self.assertIn("spx_proof_source_private_read", rendered)
        self.assertIn("(uint64_t)address + (uint64_t)width", rendered)
        self.assertIn("private_bytes != width", rendered)
        self.assertIn("uint8_t value;", rendered)
        self.assertIn("static uint32_t spx_proof_word_suffix(", rendered)
        self.assertNotIn("spx_proof_private_words[", rendered)


    def test_atomic_transcript_has_an_independent_capacity(self) -> None:
        rendered = _world_source(
            max_writes=1,
            max_private_writes=1,
            max_calls=2,
            max_atomics=3,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(),
            private_ranges=(),
        )

        self.assertIn("#define SPX_PROOF_MAX_CALLS UINT32_C(2)", rendered)
        self.assertIn("#define SPX_PROOF_MAX_ATOMICS UINT32_C(3)", rendered)
        self.assertIn("spx_proof_atomic atomics[3];", rendered)
        atomic_common = rendered[
            rendered.index("static void spx_proof_atomic_common(") : rendered.index(
                "static void spx_proof_compare_exchange("
            )
        ]
        self.assertIn('"spx-bisimulation-atomic-capacity"', atomic_common)
        self.assertIn(
            "__CPROVER_assume(position < SPX_PROOF_MAX_ATOMICS);",
            atomic_common,
        )
        self.assertNotIn("SPX_PROOF_MAX_CALLS", atomic_common)


    def test_call_transcript_stores_only_the_shared_abi_response(self) -> None:
        binding = {
            "service_id": "service",
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0, 4],
            "argument_transducers": [
                {"kind": "logical_argument", "parameter_index": 0},
                {"kind": "logical_argument", "parameter_index": 1},
            ],
            "out_interfaces": [
                {"physical_index": 1, "parameter_index": 1, "nullable": False}
            ],
            "local_cells": [],
            "events": [
                {"instruction_rva": 0x1010, "event_index": 0, "return_rva": 0x1015}
            ],
        }
        rendered = _world_source(
            max_writes=1,
            max_private_writes=1,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(binding,),
            private_ranges=(),
            reference_result_relations={
                "service": {
                    "input_argument_index": 0,
                    "origin_type": {"kind": "view", "nul_terminated": True},
                    "nonnull_min_remaining": None,
                }
            },
        )
        self.assertIn("uint32_t response_eax, response_ecx, response_edx;", rendered)
        self.assertIn("].arguments[0] == value", rendered)
        self.assertNotIn("].arguments[index] == value", rendered)
        self.assertIn(
            "call->arguments[0] = spx_proof_call_argument(world, event, input, "
            "UINT32_C(0), &fault);",
            rendered,
        )
        self.assertIn("event->stack_inputs[0].offset == offset", rendered)
        self.assertIn("event->stack_inputs[0].width != UINT32_C(4)", rendered)
        self.assertIn(
            "return spx_proof_call_word(world, input, offset, fault);", rendered
        )
        self.assertIn("*output = *input;", rendered)
        self.assertIn("output->eax = call->response_eax;", rendered)
        self.assertIn("__CPROVER_assume(call->response_eax >=", rendered)
        self.assertIn("call->arguments[0]);", rendered)
        self.assertIn("spx_response_origin_extent", rendered)
        self.assertNotIn("spx_machine_state output;", rendered)
        self.assertNotIn("*output = call->output;", rendered)


    def test_connected_service_specs_have_stable_semantic_identities(self) -> None:
        def binding(service_id: str, instruction_rva: int) -> dict[str, object]:
            return {
                "service_id": service_id,
                "provider_kind": "external_call",
                "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
                "external_contract_identity_sha256": "b" * 64,
                "abi_sha256": "a" * 64,
                "abi_template": "pe32-cdecl-v1",
                "argument_offsets": [0],
                "argument_transducers": [
                    {"kind": "logical_argument", "parameter_index": 0}
                ],
                "out_interfaces": [],
                "local_cells": [],
                "events": [
                    {
                        "instruction_rva": instruction_rva,
                        "event_index": 0,
                        "return_rva": instruction_rva + 5,
                    }
                ],
            }

        first = binding("root_service", 0x1010)
        connected = binding("connected_service", 0x2020)
        isolated_id = _proof_call_specs((connected,))[0]["spec_id"]
        closure = _canonical_proof_service_bindings((first,), (connected,))
        combined = _proof_call_specs(closure)

        self.assertEqual(
            next(
                row["spec_id"]
                for row in combined
                if row["service_id"] == "connected_service"
            ),
            isolated_id,
        )
        self.assertEqual(len({row["spec_id"] for row in combined}), 2)
        self.assertTrue(all(row["spec_id"] != 0 for row in combined))


    def test_typed_services_record_exact_and_replay_source_by_runtime_context(
        self,
    ) -> None:
        binding = {
            "service_id": "service",
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "abi_sha256": "a" * 64,
            "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0],
            "argument_transducers": [
                {"kind": "logical_argument", "parameter_index": 0}
            ],
            "out_interfaces": [],
            "local_cells": [],
            "events": [
                {
                    "instruction_rva": 0x1010,
                    "event_index": 0,
                    "return_rva": 0x1015,
                }
            ],
        }
        rendered = _world_source(
            max_writes=1,
            max_private_writes=1,
            max_calls=2,
            max_atomics=1,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(binding,),
            private_ranges=(),
            typed_exact_recording=True,
        )

        self.assertIn(
            "void spx_proof_typed_service_begin(void *context, uint32_t spec)",
            rendered,
        )
        self.assertIn("if (context == &spx_exact_world)", rendered)
        self.assertIn("position = spx_exact_world.call_count++", rendered)
        self.assertIn("call->arguments[index] = value", rendered)
        self.assertIn("__CPROVER_assert(context == &spx_source_world", rendered)
        self.assertIn("__CPROVER_assume(context == &spx_source_world);", rendered)
        self.assertIn("position = spx_source_world.call_count++", rendered)
        self.assertIn("spx-bisimulation-typed-call-fields:0", rendered)
        self.assertIn("spx_proof_typed_call_matches =", rendered)
        self.assertIn("spx_exact_world.calls[0].arguments[0] == value", rendered)
        self.assertNotIn("overflow", rendered)


    def test_exact_input_reads_do_not_allocate_a_mutable_world(self) -> None:
        rendered = _world_source(
            max_writes=1,
            max_private_writes=1,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(),
            private_ranges=(),
        )
        self.assertIn("static uint32_t spx_proof_initial_read(", rendered)
        self.assertIn("return spx_proof_initial_byte(address);", rendered)
        self.assertNotIn("spx_exact_input_world", rendered)


    def test_mutable_memory_reads_are_specialized_by_machine_side(self) -> None:
        rendered = _world_source(
            max_writes=2,
            max_private_writes=2,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(),
            private_ranges=(),
        )
        self.assertIn("static uint8_t spx_proof_exact_byte(", rendered)
        self.assertIn("address >= spx_exact_world.writes[1].address", rendered)
        self.assertIn("address - spx_exact_world.writes[1].address <", rendered)
        self.assertIn("static uint8_t spx_proof_source_byte(", rendered)
        self.assertIn("address >= spx_source_world.writes[1].address", rendered)
        self.assertIn("? spx_proof_source_read : spx_proof_exact_read", rendered)
        self.assertNotIn("spx_proof_byte(spx_proof_world *", rendered)


    def test_proof_overlay_is_the_exact_production_source(self) -> None:
        source = """static void thunk(void) {
  uint32_t saved_frame_word_0 = spx_component_read(rt, esp, UINT32_C(4), &memory_fault);
  spx_component_write(rt, esp, UINT32_C(4), argument, &memory_fault);
  spx_component_write(rt, esp, UINT32_C(4), saved_frame_word_0, &restore_fault);
}
"""
        rendered = _specialize_machine_overlay_for_proof(source)
        self.assertEqual(rendered, source)


    def test_typed_service_thunk_is_rendered_structurally_and_deterministically(
        self,
    ) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/jq/intent/interfaces-v5/output-value-pipeline.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        binding = {
            "service_id": "dump_value",
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "symbol": "spx_component_external_output_value_pipeline_dump_value",
            "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0, 4, 8, 12, 16, 20],
            "argument_transducers": [
                {
                    "kind": "record_field",
                    "parameter_index": 0,
                    "field_id": field,
                }
                for field in ("metadata", "size", "payload_low", "payload_high")
            ]
            + [
                {"kind": "logical_argument", "parameter_index": 1},
                {"kind": "constant", "value": 2},
            ],
            "out_interfaces": [],
            "local_cells": [],
            "result_projection": None,
            "events": [
                {
                    "instruction_rva": 0x1F6B,
                    "event_index": 0,
                    "return_rva": 0x1F70,
                }
            ],
        }
        renderer = build_typed_proof_service_thunk_renderer(
            interface=interface,
            service_bindings=(
                binding,
                {
                    "service_id": "dump_value",
                    "provider_kind": "component_operation",
                    "symbol": "spx_component_logical_connected_dump_value",
                },
            ),
        )

        first = tuple(renderer(bundle, binding, {}))
        second = tuple(renderer(bundle, binding, {}))

        self.assertEqual(first, second)
        source = "\n".join(first)
        self.assertIn(
            "static void spx_component_external_output_value_pipeline_dump_value(",
            source,
        )
        self.assertIn(
            "spx_proof_typed_service_begin(spx_typed_service->runtime->context, "
            "UINT32_C(",
            source,
        )
        self.assertIn("(uint32_t)logical_value.metadata", source)
        self.assertIn("(uint32_t)logical_stream.identity", source)
        self.assertNotIn("spx_invoke_call", source)


    def test_typed_interface_thunk_checks_receiver_target_before_call_record(
        self,
    ) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/dxball/intent/interfaces-v5/directdraw-init.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        binding = {
            "service_id": "set_cooperative_level",
            "provider_kind": "interface_method",
            "symbol": "spx_interface_method_directdraw_init_set_cooperative_level",
            "abi_sha256": "a" * 64,
            "argument_offsets": [0, 4, 8],
            "argument_transducers": [
                {"kind": "logical_argument", "parameter_index": index}
                for index in range(3)
            ],
            "receiver_argument": 0,
            "slot": 5,
            "out_interfaces": [],
            "local_cells": [],
            "result_projection": None,
            "events": [
                {
                    "instruction_rva": 0xCDBA,
                    "event_index": 0,
                    "return_rva": 0xCDBD,
                }
            ],
        }
        renderer = build_typed_proof_service_thunk_renderer(
            interface=interface,
            service_bindings=(binding,),
        )

        source = "\n".join(renderer(bundle, binding, {}))

        first_read = source.index("uint32_t spx_typed_vtable = spx_component_read")
        second_read = source.index("uint32_t spx_typed_target = spx_component_read")
        receiver_separation = source.index(
            "spx_proof_typed_service_public_range(\n"
            "      spx_typed_receiver, UINT32_C(4))"
        )
        target_separation = source.index(
            "spx_proof_typed_service_public_range(\n"
            "      spx_typed_vtable + UINT32_C(20)"
        )
        begin = source.index(
            "  spx_proof_typed_service_begin(spx_typed_service->runtime->context,"
        )
        self.assertLess(receiver_separation, first_read)
        self.assertLess(first_read, second_read)
        self.assertLess(target_separation, second_read)
        self.assertLess(second_read, begin)
        self.assertIn("spx_typed_vtable + UINT32_C(20)", source)
        self.assertNotIn("UINT32_MAX - UINT32_C(20)", source)
        self.assertNotIn(
            "__CPROVER_assume(spx_proof_typed_service_public_range", source
        )
        self.assertIn("spx_typed_receiver, UINT32_C(4)) == UINT32_C(0)) {", source)
        self.assertIn(
            "spx_typed_vtable + UINT32_C(20),\n      UINT32_C(4)) == UINT32_C(0)) {",
            source,
        )
        self.assertGreaterEqual(
            source.count("*spx_typed_service->memory_fault = UINT32_C(1)"),
            4,
        )
        self.assertIn("*spx_typed_service->memory_fault = UINT32_C(1)", source)
        self.assertIn("*spx_typed_service->service_fault = UINT32_C(1)", source)
        self.assertIn("spx_proof_typed_service_target(spx_typed_target)", source)


    def test_typed_view_service_uses_checked_physical_base_before_call_record(
        self,
    ) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT
                    / "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        binding = {
            "service_id": "compare_memory",
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "symbol": "spx_external_memory_regions_equal_compare_memory",
            "abi_sha256": "a" * 64,
            "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0, 4, 8],
            "argument_transducers": [
                {"kind": "logical_argument", "parameter_index": index}
                for index in range(3)
            ],
            "input_interfaces": [],
            "out_interfaces": [],
            "local_cells": [],
            "result_projection": None,
            "events": [
                {
                    "instruction_rva": 0x8D72,
                    "event_index": 0,
                    "return_rva": 0x8D7F,
                }
            ],
        }
        renderer = build_typed_proof_service_thunk_renderer(
            interface=interface,
            service_bindings=(binding,),
        )

        source = "\n".join(renderer(bundle, binding, {}))

        begin = source.index(
            "  spx_proof_typed_service_begin(spx_typed_service->runtime->context,"
        )
        validation = source.index("spx_typed_service->runtime->realize_reference(")
        argument = source.index(
            "spx_proof_typed_service_argument(UINT32_C(0), spx_typed_input_0_address)"
        )
        self.assertLess(validation, begin)
        self.assertGreater(argument, begin)
        self.assertIn("*spx_typed_service->service_fault = UINT32_C(1)", source)


    def test_typed_callback_service_round_trips_the_physical_word(self) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT
                    / "targets/gnu-hello/intent/interfaces-v5/startup-callback-registration.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        binding = {
            "service_id": "set_unhandled_exception_filter",
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "symbol": (
                "spx_component_external_startup_callback_registration_"
                "set_unhandled_exception_filter"
            ),
            "abi_sha256": "a" * 64,
            "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0],
            "argument_transducers": [
                {"kind": "logical_argument", "parameter_index": 0}
            ],
            "input_interfaces": [],
            "out_interfaces": [],
            "local_cells": [],
            "result_projection": {
                "kind": "callback_handle",
                "source": {
                    "kind": "register",
                    "register": "eax",
                    "width": 32,
                    "at": "call",
                },
            },
            "events": [
                {
                    "instruction_rva": 0x113E,
                    "event_index": 0,
                    "return_rva": 0x1144,
                }
            ],
        }
        renderer = build_typed_proof_service_thunk_renderer(
            interface=interface,
            service_bindings=(binding,),
        )

        source = "\n".join(renderer(bundle, binding, {}))

        validation = source.index("logical_argument_0000->physical_word == UINT32_C(0)")
        begin = source.index(
            "  spx_proof_typed_service_begin(spx_typed_service->runtime->context,"
        )
        argument = source.index("(uint32_t)logical_argument_0000->physical_word")
        self.assertLess(validation, begin)
        self.assertGreater(argument, begin)
        self.assertIn(
            "spx_typed_service->callback_result.physical_word = result;", source
        )
        self.assertIn(
            "return (spx_callback_previous_exception_filter_v5 *)"
            "&spx_typed_service->callback_result;",
            source,
        )
        service = next(row for row in interface.services if row.identity == binding["service_id"])
        self.assertNotEqual(service.result_type_id, service.parameter_type_ids[0])
        stale_interface = replace(interface, services=tuple(
            replace(row, result_type_id=service.parameter_type_ids[0]) if row.identity == service.identity else row
            for row in interface.services))
        stale_renderer = build_typed_proof_service_thunk_renderer(
            interface=stale_interface, service_bindings=(binding,))
        with self.assertRaisesRegex(BisimulationRefinementError, "signature is stale"):
            stale_renderer(bundle, binding, {})


    def test_typed_reference_service_resolves_the_physical_result(self) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT
                    / "targets/gnu-hello/intent/interfaces-v5/program-name-selection.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        binding = {
            "service_id": "find_last_character",
            "provider_kind": "external_call",
            "external_effect_contract": {"memory_effect": "none", "world_effect": "none"},
            "external_contract_identity_sha256": "b" * 64,
            "symbol": "spx_component_external_program_name_selection_find_last_character",
            "abi_sha256": "a" * 64,
            "abi_template": "pe32-cdecl-v1",
            "argument_offsets": [0, 4],
            "argument_transducers": [
                {"kind": "logical_argument", "parameter_index": 0},
                {"kind": "logical_argument", "parameter_index": 1},
            ],
            "input_interfaces": [],
            "out_interfaces": [],
            "local_cells": [],
            "result_projection": {
                "kind": "reference",
                "authority": {
                    "id": "argv_string",
                    "kind": "process",
                    "lifetime": "process",
                },
                "requested_extent": {
                    "kind": "constant",
                    "value": 1,
                    "width": 32,
                },
                "source": {
                    "kind": "register",
                    "register": "eax",
                    "width": 32,
                    "at": "call",
                },
                "at": "call",
            },
            "events": [
                {
                    "instruction_rva": 0x2B67,
                    "event_index": 0,
                    "return_rva": 0x2B6C,
                }
            ],
        }
        renderer = build_typed_proof_service_thunk_renderer(
            interface=interface,
            service_bindings=(binding,),
        )

        source = "\n".join(renderer(bundle, binding, {"argv_string": "argv-rule"}))

        self.assertIn("spx_machine_reference_v1 service_result_reference", source)
        self.assertIn("runtime->resolve_reference(", source)
        self.assertIn('"argv-rule", UINT32_C(1), UINT32_C(0)', source)
        self.assertIn("return (spx_ref_v5){", source)
        self.assertNotIn("return (spx_ref_v5)result;", source)

        receipt_core = {
            "format": "spaghetti-extractor-interaction-contract-receipt-v1",
            "contract_id": "c-runtime.strrchr.borrowed-interior-v1",
            "contract_sha256": "b" * 64,
            "status": "checked",
            "code": "reviewed_reusable_contract",
        }
        receipt = {
            **receipt_core,
            "receipt_sha256": canonical_sha256_v3(receipt_core),
        }
        constrained_renderer = build_typed_proof_service_thunk_renderer(
            interface=interface,
            service_bindings=(binding,),
            relation_evidence=(
                {
                    "operation_id": "select",
                    "requirement_id": "find-last-character-borrowed-interior",
                    "service_id": "find_last_character",
                    "input_argument_index": 0,
                    "relation": "borrowed_interior_or_null",
                    "origin_type": {"kind": "view", "nul_terminated": True},
                    "result_policy": {
                        "nullable": True,
                        "allow_one_past": False,
                        "permissions": 1,
                    },
                    "nonnull_min_remaining": {
                        "nonzero_argument_index": 1,
                        "minimum": 2,
                    },
                    "contract_id": "c-runtime.strrchr.borrowed-interior-v1",
                    "contract_sha256": "b" * 64,
                    "contract_catalog_sha256": "d" * 64,
                    "contract_receipt": receipt,
                    "contract_receipt_sha256": receipt["receipt_sha256"],
                },
            ),
        )
        constrained = "\n".join(
            constrained_renderer(bundle, binding, {"argv_string": "argv-rule"})
        )

        self.assertIn(
            "spx_ref_v1 service_result_origin = logical_argument_0000->base;",
            constrained,
        )
        self.assertIn(
            "service_result_origin_word =\n      spx_typed_input_0_address;",
            constrained,
        )
        self.assertIn("spx_machine_reference_v1 service_result_origin_machine", constrained)
        self.assertIn(
            "__CPROVER_assume(result >= service_result_origin_word);",
            constrained,
        )
        self.assertIn(
            "service_result_minimum_remaining = UINT64_C(2);",
            constrained,
        )
        self.assertIn(
            "service_result_delta <=",
            constrained,
        )
        self.assertIn("service_result_origin.extent, service_result_origin.permissions", constrained)
        self.assertNotIn(
            "spx_machine_reference_v1 service_result_reference", constrained
        )



if __name__ == "__main__":
    unittest.main()
