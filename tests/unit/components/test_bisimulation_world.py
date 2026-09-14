from __future__ import annotations

import tempfile

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



class BisimulationWorldCodegenTests(unittest.TestCase):
    def test_capacity_uses_maximum_reachable_path_not_mutually_exclusive_sum(
        self,
    ) -> None:
        edges = [
            {"source_unit_id": "entry", "target_unit_id": "left"},
            {"source_unit_id": "entry", "target_unit_id": "right"},
            {"source_unit_id": "left", "target_unit_id": "exit"},
            {"source_unit_id": "right", "target_unit_id": "exit"},
            {"source_unit_id": "exit", "target_unit_id": "barrier"},
        ]
        self.assertEqual(
            _maximum_acyclic_path_cost(
                start_unit_id="entry",
                selected_unit_ids={"entry", "left", "right", "exit"},
                control_edges=edges,
                costs={"entry": 1, "left": 10, "right": 3, "exit": 2},
            ),
            13,
        )

    def test_capacity_rejects_a_cycle_left_inside_a_proof_segment(self) -> None:
        with self.assertRaisesRegex(
            BisimulationRefinementError, "cyclic cost segment"
        ):
            _maximum_acyclic_path_cost(
                start_unit_id="entry",
                selected_unit_ids={"entry", "body"},
                control_edges=[
                    {"source_unit_id": "entry", "target_unit_id": "body"},
                    {"source_unit_id": "body", "target_unit_id": "entry"},
                ],
                costs={"entry": 1, "body": 1},
            )

    def test_capacity_stops_on_return_to_starting_barrier(self) -> None:
        self.assertEqual(_maximum_acyclic_path_cost(
            start_unit_id="cut", selected_unit_ids={"cut", "body"},
            control_edges=[
                {"source_unit_id": "cut", "target_unit_id": "body"},
                {"source_unit_id": "body", "target_unit_id": "cut"},
            ],
            barrier_unit_ids=frozenset({"cut"}),
            costs={"cut": 3, "body": 7},
        ), 10)

    def test_private_write_reads_use_total_constant_shift_extractor(self) -> None:
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

        self.assertIn("static uint32_t spx_proof_word_suffix(", rendered)
        self.assertIn("if (byte_offset == UINT32_C(3)) return value >> 24U;", rendered)
        self.assertNotIn("private_writes[0].value >>", rendered)
        self.assertNotIn("private_writes[1].value >>", rendered)
        self.assertIn("uint32_t address, uint32_t minimum_extent", rendered)
        self.assertIn("__CPROVER_assume(extent >= minimum_extent);", rendered)

    def test_reference_resolution_totalizes_private_range_rejection(self) -> None:
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
        resolver = rendered[
            rendered.index("static spx_boundary_status spx_proof_record_reference_origin(") :
            rendered.index("static spx_boundary_status spx_proof_realize_reference(")
        ]

        self.assertIn("return spx_proof_record_reference_origin(world, address, result, one_past);", resolver)
        self.assertNotIn("__CPROVER_assume", resolver)
        self.assertIn("world != 0 && extent != UINT64_C(0)", resolver)
        self.assertIn(
            "!((uint64_t)address + extent <= (uint64_t)world->private_low ||",
            resolver,
        )
        self.assertIn("return SPX_BOUNDARY_MEMORY_FAULT;", resolver)
        self.assertIn("*result = (spx_machine_reference_v1){", resolver)
        self.assertIn("return SPX_BOUNDARY_OK;", resolver)

    def test_entry_view_domain_excludes_both_private_stacks(self) -> None:
        interface = ProofKernelComponentInterface.parse(
            {
                "id": "view_component",
                "types": [
                    {"id": "u8", "kind": "scalar", "c_type": "uint8_t"},
                    {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
                    {
                        "id": "span",
                        "kind": "view",
                        "element_type_id": "u8",
                        "access": "read",
                        "extent": {"kind": "parameter", "parameter_id": "count"},
                        "ownership": "borrowed",
                    },
                ],
                "state": [],
                "operations": [
                    {
                        "id": "compare",
                        "kind": "operation",
                        "parameters": [
                            {"id": "data", "type_id": "span"},
                            {"id": "count", "type_id": "u32"},
                        ],
                        "results": [],
                        "effect_ids": [],
                        "allowed_service_ids": [],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
        )
        def stack(offset: int) -> dict[str, object]:
            return {
                "kind": "stack",
                "offset": offset,
                "width": 32,
                "at": "entry",
            }
        rendered = "\n".join(
            _entry_preconditions(
                interface,
                "compare",
                {
                    "parameters": [
                        {
                            "id": "data",
                            "projection": {
                                "kind": "view",
                                "base": stack(4),
                                "extent": stack(8),
                                "requested_extent": stack(8),
                            },
                        },
                        {"id": "count", "projection": stack(8)},
                    ]
                },
            )
        )

        self.assertIn("spx_source_world.private_low", rendered)
        self.assertIn("spx_source_world.private_high", rendered)
        self.assertIn("spx_exact_world.private_low", rendered)
        self.assertIn("spx_exact_world.private_high", rendered)
        self.assertIn("UINT64_C(4294967296)", rendered)

    def test_nullable_reference_state_is_related_at_entry(self) -> None:
        interface = ProofKernelComponentInterface.parse(
            {
                "id": "reference_state_component",
                "types": [
                    {"id": "u8", "kind": "scalar", "c_type": "uint8_t"},
                    {
                        "id": "char_ref",
                        "kind": "reference",
                        "element_type_id": "u8",
                        "access": "read",
                        "nullable": True,
                        "allow_one_past": False,
                        "lifetime": "origin",
                    },
                ],
                "state": [
                    {
                        "id": "program_name",
                        "type_id": "char_ref",
                        "initial": {
                            "domain": 0,
                            "object": 0,
                            "generation": 0,
                            "offset": 0,
                            "extent": 0,
                            "permissions": 0,
                        },
                    }
                ],
                "operations": [
                    {
                        "id": "select",
                        "kind": "operation",
                        "parameters": [],
                        "results": [],
                        "effect_ids": [],
                        "allowed_service_ids": [],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
        )
        rendered = "\n".join(
            _entry_preconditions(
                interface,
                "select",
                {
                    "parameters": [],
                    "state": [
                        {
                            "id": "program_name",
                            "entry": {
                                "kind": "reference",
                                "source": {
                                    "kind": "static_slot",
                                    "rva": 196768,
                                    "width": 32,
                                    "at": "entry",
                                },
                                "requested_extent": {
                                    "kind": "constant",
                                    "value": 1,
                                    "width": 32,
                                },
                                "at": "entry",
                            },
                        }
                    ],
                },
            )
        )

        self.assertIn("SPX_PROOF_IMAGE_BASE + UINT32_C(196768)", rendered)
        self.assertIn(") == UINT32_C(0) ||", rendered)
        self.assertIn("spx_source_world.private_low", rendered)
        self.assertIn("spx_exact_world.private_low", rendered)

    def test_static_slot_must_be_image_relative(self) -> None:
        _validate_static_slot_rvas(
            {"kind": "static_slot", "rva": 12, "width": 32},
            image_size=16,
        )
        with self.assertRaisesRegex(
            BisimulationRefinementError,
            "static-slot RVA is outside the proof image",
        ):
            _validate_static_slot_rvas(
                {"kind": "static_slot", "rva": 0x4300A0, "width": 32},
                image_size=0x40000,
            )

    def test_nul_view_registration_preserves_requested_extent(self) -> None:
        interface = ProofKernelComponentInterface.parse(
            {
                "id": "cstring_component",
                "types": [
                    {"id": "u8", "kind": "scalar", "c_type": "uint8_t"},
                    {
                        "id": "cstring",
                        "kind": "view",
                        "element_type_id": "u8",
                        "access": "read",
                        "extent": {"kind": "nul_terminated"},
                        "ownership": "borrowed",
                    },
                ],
                "state": [],
                "operations": [
                    {
                        "id": "inspect",
                        "kind": "operation",
                        "parameters": [{"id": "value", "type_id": "cstring"}],
                        "results": [],
                        "effect_ids": [],
                        "allowed_service_ids": [],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
        )
        self.assertEqual(
            _nul_view_registrations(
                interface=interface,
                operation_id="inspect",
                operation_projection={
                    "parameters": [
                        {
                            "id": "value",
                            "projection": {
                                "kind": "view",
                                "base": {
                                    "kind": "constant",
                                    "value": 0x421440,
                                    "width": 32,
                                },
                                "extent": {"kind": "origin_remainder"},
                                "requested_extent": {
                                    "kind": "constant",
                                    "value": 8,
                                    "width": 32,
                                },
                            },
                        }
                    ]
                },
                sync=None,
            ),
            [
                "  spx_proof_register_nul_view("
                "UINT32_C(4330560), UINT32_C(8));"
            ],
        )

    def test_callback_handle_projection_uses_its_physical_word(self) -> None:
        self.assertEqual(
            _projection_expression(
                {
                    "kind": "callback_handle",
                    "authority_id": "callback-authority",
                    "protocol_id": "callback-protocol",
                    "source": {
                        "kind": "register",
                        "register": "eax",
                        "width": 32,
                        "at": "exit",
                    },
                    "at": "exit",
                },
                state="output",
                read="read_output",
            ),
            "((output.eax))",
        )

    def test_reference_projection_uses_its_physical_address(self) -> None:
        self.assertEqual(
            _projection_expression(
                {
                    "kind": "reference",
                    "authority": {
                        "id": "process-string",
                        "kind": "process",
                        "lifetime": "process",
                    },
                    "requested_extent": {
                        "kind": "constant",
                        "value": 1,
                        "width": 32,
                    },
                    "source": {
                        "kind": "static_slot",
                        "rva": 0x3000,
                        "width": 32,
                        "at": "exit",
                    },
                    "at": "exit",
                },
                state="output",
                read="read_output",
            ),
            "read_output(SPX_PROOF_IMAGE_BASE + UINT32_C(12288), UINT32_C(4))",
        )

    def test_exact_stack_cache_invalidates_partial_word_replacement(self) -> None:
        rendered = _world_source(
            max_writes=1,
            max_private_writes=1,
            max_calls=1,
            max_atomics=1,
            max_shadow_bytes=1,
            max_nul_views=1,
            service_bindings=(),
            private_ranges=(),
            exact_stack_accesses=((4, 4),),
        )

        self.assertIn("spx_proof_exact_stack_valid_0000 = UINT32_C(0);", rendered)
        self.assertIn("spx_proof_exact_stack_valid_0000 != UINT32_C(0)", rendered)
        self.assertNotIn("exact-stack-cache-write-compatible", rendered)
        self.assertIn(
            "width == UINT32_C(4) && address == "
            "spx_exact_world.private_anchor + UINT32_C(4)",
            rendered,
        )
        self.assertIn(
            "return spx_proof_exact_stack_word_0000;",
            rendered,
        )



if __name__ == "__main__":
    unittest.main()
