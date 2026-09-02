from __future__ import annotations

import json
import shutil
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary._canonical import BoundaryModelError
from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.machine_binding import ServiceMachineBindingV1
from spaghetti_extractor.components.machine_binding_schema import (
    ComponentMachineBindingError,
)
from spaghetti_extractor.components.machine_overlay_external_v5 import (
    _external_logical_word_lines,
    _external_service_runtime_helpers,
    _external_service_thunk,
)
from spaghetti_extractor.components.machine_overlay_boundaries_v5 import (
    checked_opaque_resource_projection,
)
from spaghetti_extractor.components.machine_overlay_v5 import (
    _resource_parameter_lines,
)
from spaghetti_extractor.components.semantic_contract import (
    _checked_interface_method_service_v1,
)
from spaghetti_extractor.components.semantic_external_transducers import (
    ComponentSemanticContractError,
    checked_captured_external_target_guard,
)
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


SHA = "7" * 64


def _stack_word(index: int) -> dict[str, object]:
    address: dict[str, object] = {"op": "reg", "name": "esp", "width": 32}
    if index:
        address = {
            "op": "add32",
            "args": [
                address,
                {"op": "const", "value": index * 4, "width": 32},
            ],
        }
    return {"op": "load", "address": address, "width": 4}


class InterfaceMethodTransducerTests(unittest.TestCase):
    def test_opaque_resource_projection_round_trips_one_checked_word(self) -> None:
        value = SimpleNamespace(
            interpretation="resource",
            access="none",
            resource_kind="window_handle",
            provider_domain="component-environment.directdraw-init",
            nullable=False,
        )
        projection = {
            "kind": "resource",
            "resource_kind": "window_handle",
            "source": {
                "kind": "static_slot",
                "rva": 0x34974,
                "width": 32,
                "at": "entry",
            },
        }
        source, type_tag = checked_opaque_resource_projection(
            value=value,
            projection=projection,
            context="fixture window",
        )
        self.assertEqual(source, projection["source"])
        self.assertGreaterEqual(type_tag, 0x80000000)
        parameter_lines, parameter_name = _resource_parameter_lines(
            value=SimpleNamespace(**vars(value), identity="window"),
            projection=projection,
            name="argument_window",
        )
        parameter_source = "\n".join(parameter_lines)
        self.assertEqual(parameter_name, "argument_window")
        self.assertIn(
            "spx_component_read(rt, UINT32_C(215412), UINT32_C(4), &memory_fault)",
            parameter_source,
        )
        self.assertIn(f"UINT32_C({type_tag}), UINT32_C(1)", parameter_source)
        lines = _external_logical_word_lines(
            value=value,
            logical="logical_window",
            physical="physical_window",
            binding={"provider_kind": "external_call"},
            parameter_index=0,
        )
        rendered = "\n".join(lines)
        self.assertIn(f"logical_window.type_tag != UINT32_C({type_tag})", rendered)
        self.assertIn("logical_window.generation != UINT32_C(1)", rendered)
        self.assertIn("physical_window = (uint32_t)logical_window.identity", rendered)

        method_lines = _external_logical_word_lines(
            value=value,
            logical="logical_window",
            physical="physical_window",
            binding={"provider_kind": "interface_method"},
            parameter_index=1,
        )
        self.assertIn(
            f"logical_window.type_tag != UINT32_C({type_tag})",
            "\n".join(method_lines),
        )

        interface_lines = _external_logical_word_lines(
            value=SimpleNamespace(**{**vars(value), "resource_kind": "clipper"}),
            logical="logical_clipper",
            physical="physical_clipper",
            binding={"provider_kind": "interface_method"},
            parameter_index=1,
            input_interfaces=(
                {
                    "physical_index": 1,
                    "parameter_index": 1,
                    "profile_sha256": SHA,
                    "interface_id": "IDirectDrawClipper",
                },
            ),
        )
        interface_source = "\n".join(interface_lines)
        self.assertIn("realize_interface_resource", interface_source)
        self.assertIn('"IDirectDrawClipper"', interface_source)

        with self.assertRaises(BoundaryModelError):
            checked_opaque_resource_projection(
                value=value,
                projection={**projection, "resource_kind": "another_handle"},
                context="fixture mismatched window",
            )

    def test_service_event_inventory_is_nonempty_unique_and_canonical(self) -> None:
        def binding(events: list[dict[str, object]]) -> dict[str, object]:
            return {
                "service_id": "destroy_window",
                "mediation": "direct",
                "provider": {
                    "kind": "external_call",
                    "events": events,
                    "identity": {
                        "dll": "user32.dll",
                        "symbol": "DestroyWindow",
                        "ordinal": None,
                    },
                },
            }

        canonical = [
            {"unit_id": "unit:a", "event_index": 0},
            {"unit_id": "unit:b", "event_index": 1},
        ]
        parsed = ServiceMachineBindingV1.parse(
            binding(canonical), "fixture multi-event service"
        )
        self.assertEqual(parsed.provider["events"], canonical)

        for events in ([], [canonical[0], canonical[0]], list(reversed(canonical))):
            with (
                self.subTest(events=events),
                self.assertRaises(ComponentMachineBindingError),
            ):
                ServiceMachineBindingV1.parse(
                    binding(events), "fixture malformed multi-event service"
                )

    def test_service_event_inventory_rejects_legacy_singleton_fields(self) -> None:
        with self.assertRaises(ComponentMachineBindingError):
            ServiceMachineBindingV1.parse(
                {
                    "service_id": "destroy_window",
                    "mediation": "direct",
                    "provider": {
                        "kind": "external_call",
                        "unit_id": "unit:a",
                        "event_index": 0,
                        "identity": {
                            "dll": "user32.dll",
                            "symbol": "DestroyWindow",
                            "ordinal": None,
                        },
                    },
                },
                "fixture legacy singleton service",
            )

    def test_external_service_accepts_only_a_checked_entry_target_projection(
        self,
    ) -> None:
        provider = {
            "kind": "external_call",
            "events": [{"unit_id": "unit:show", "event_index": 0}],
            "identity": {
                "dll": "user32.dll",
                "symbol": "ShowWindow",
                "ordinal": None,
            },
            "target_projection": {
                "kind": "register",
                "register": "esi",
                "width": 32,
                "at": "entry",
            },
        }
        parsed = ServiceMachineBindingV1.parse(
            {
                "service_id": "hide_window",
                "mediation": "direct",
                "provider": provider,
            },
            "fixture captured external service",
        )
        self.assertEqual(
            parsed.provider["target_projection"], provider["target_projection"]
        )

        for projection in (
            {**provider["target_projection"], "at": "call"},
            {**provider["target_projection"], "width": 16},
            {
                "kind": "constant",
                "value": 0x401000,
                "width": 32,
                "at": "entry",
            },
        ):
            malformed = json.loads(json.dumps(provider))
            malformed["target_projection"] = projection
            with (
                self.subTest(projection=projection),
                self.assertRaises(ComponentMachineBindingError),
            ):
                ServiceMachineBindingV1.parse(
                    {
                        "service_id": "hide_window",
                        "mediation": "direct",
                        "provider": malformed,
                    },
                    "fixture malformed captured external service",
                )

    def test_captured_external_target_is_an_exact_entry_guard(self) -> None:
        projection = {
            "kind": "register",
            "register": "esi",
            "width": 32,
            "at": "entry",
        }
        target = {"op": "reg", "name": "esi", "width": 32}
        guard = checked_captured_external_target_guard(
            projection,
            machine_event={"kind": "indirect_call", "target": target},
        )
        self.assertEqual(
            guard,
            {
                "op": "eq",
                "args": [
                    target,
                    {"op": "entry_projection", "projection": projection},
                ],
            },
        )
        with self.assertRaises(ComponentSemanticContractError):
            checked_captured_external_target_guard(
                projection,
                machine_event={"kind": "external_call", "target": target},
            )

    def test_captured_external_renderer_preserves_target_and_identity(self) -> None:
        schema = BoundarySchemaV1.create(
            schema_id="component.captured-external",
            types=[
                {
                    "id": "word",
                    "kind": "integer",
                    "signed": False,
                    "width_bits": 32,
                },
                {
                    "id": "unit",
                    "kind": "void",
                },
                {
                    "id": "service.hide.function",
                    "kind": "function",
                    "result_type_id": "unit",
                    "parameter_type_ids": ["word"],
                    "variadic": False,
                    "calling_convention": "cdecl",
                },
            ],
            signatures=[
                {
                    "id": "service.hide",
                    "function_type_id": "service.hide.function",
                    "parameters": [
                        {
                            "id": "window",
                            "type_id": "word",
                            "interpretation": "value",
                            "nullable": False,
                            "access": "none",
                            "extent": {
                                "kind": "none",
                                "bytes": None,
                                "value_id": None,
                            },
                            "resource_kind": None,
                            "provider_domain": None,
                        }
                    ],
                    "results": [],
                }
            ],
        )
        bundle = SimpleNamespace(
            interface=SimpleNamespace(
                services=(
                    SimpleNamespace(identity="hide", signature_id="service.hide"),
                )
            ),
            intent=SimpleNamespace(schema=schema),
        )
        source = "\n".join(
            _external_service_thunk(
                bundle,
                {
                    "service_id": "hide",
                    "provider_kind": "external_call",
                    "symbol": "fixture_hide",
                    "argument_offsets": [0, 4],
                    "events": [
                        {
                            "unit_id": "unit:hide",
                            "source_rva": 0x2000,
                            "instruction_rva": 0x2004,
                            "event_index": 0,
                            "return_rva": 0x2006,
                            "event_stack_offsets": [0],
                        }
                    ],
                    "argument_transducers": [
                        {"kind": "logical_argument", "parameter_index": 0},
                        {"kind": "constant", "value": 0},
                    ],
                    "out_interfaces": [],
                    "local_cells": [],
                    "result_projection": None,
                    "dll": "user32.dll",
                    "import_symbol": "ShowWindow",
                    "ordinal": None,
                    "captured_target_projection": {
                        "kind": "register",
                        "register": "esi",
                        "width": 32,
                        "at": "entry",
                    },
                },
                {},
            )
        )
        self.assertIn("captured_external_target = service->state->esi", source)
        self.assertIn("SPX_CALL_INDIRECT, UINT32_C(8192)", source)
        self.assertIn('"user32.dll", "ShowWindow"', source)
        self.assertNotIn("SPX_CALL_EXTERNAL_IMPORT", source)

    def test_finite_word_map_is_a_canonical_bijection(self) -> None:
        def binding(cases: list[dict[str, int]]) -> dict[str, object]:
            return {
                "service_id": "show_error",
                "mediation": "direct",
                "provider": {
                    "kind": "external_call",
                    "events": [{"unit_id": "unit:show", "event_index": 0}],
                    "identity": {
                        "dll": "user32.dll",
                        "symbol": "MessageBoxA",
                        "ordinal": None,
                    },
                    "argument_transducers": [
                        {
                            "kind": "finite_word_map",
                            "parameter_index": 0,
                            "cases": cases,
                        }
                    ],
                },
            }

        cases = [
            {"logical_value": 1, "physical_value": 0x401000},
            {"logical_value": 2, "physical_value": 0x402000},
        ]
        parsed = ServiceMachineBindingV1.parse(
            binding(cases), "fixture finite-word service"
        )
        self.assertEqual(parsed.provider["argument_transducers"][0]["cases"], cases)
        malformed = (
            list(reversed(cases)),
            [cases[0], cases[0]],
            [cases[0], {"logical_value": 2, "physical_value": 0x401000}],
        )
        for rows in malformed:
            with (
                self.subTest(cases=rows),
                self.assertRaises(ComponentMachineBindingError),
            ):
                ServiceMachineBindingV1.parse(
                    binding(rows), "fixture malformed finite-word service"
                )

    def test_local_cell_renderer_restores_private_storage_and_returns_word(
        self,
    ) -> None:
        schema = BoundarySchemaV1.create(
            schema_id="component.local-cell-renderer",
            types=[
                {"id": "receiver", "kind": "opaque", "nominal_id": "fixture.receiver"},
                {"id": "word", "kind": "integer", "signed": False, "width_bits": 32},
                {
                    "id": "service.get.function",
                    "kind": "function",
                    "result_type_id": "word",
                    "parameter_type_ids": ["receiver", "word"],
                    "variadic": False,
                    "calling_convention": "cdecl",
                },
            ],
            signatures=[
                {
                    "id": "service.get",
                    "function_type_id": "service.get.function",
                    "parameters": [
                        {
                            "id": "receiver",
                            "type_id": "receiver",
                            "interpretation": "resource",
                            "nullable": False,
                            "access": "none",
                            "extent": {"kind": "none", "bytes": None, "value_id": None},
                            "resource_kind": "fixture_receiver",
                            "provider_domain": "fixture",
                        },
                        {
                            "id": "selector",
                            "type_id": "word",
                            "interpretation": "value",
                            "nullable": False,
                            "access": "none",
                            "extent": {"kind": "none", "bytes": None, "value_id": None},
                            "resource_kind": None,
                            "provider_domain": None,
                        },
                    ],
                    "results": [
                        {
                            "id": "word",
                            "type_id": "word",
                            "interpretation": "value",
                            "nullable": False,
                            "access": "none",
                            "extent": {"kind": "none", "bytes": None, "value_id": None},
                            "resource_kind": None,
                            "provider_domain": None,
                        }
                    ],
                }
            ],
        )
        bundle = SimpleNamespace(
            interface=SimpleNamespace(
                services=(SimpleNamespace(identity="get", signature_id="service.get"),)
            ),
            intent=SimpleNamespace(schema=schema),
        )
        relation = {
            "argument_index": 1,
            "extent_words": 2,
            "variants": [
                {
                    "id": "eight",
                    "discriminants": [
                        {
                            "word_index": 0,
                            "mask": 0xFFFFFFFF,
                            "value": 8,
                        }
                    ],
                    "input_word_indices": [0, 1],
                    "output_word_indices": [1],
                    "output_condition": "hresult_succeeded_eax",
                    "failure_preserved_word_indices": [1],
                    "failure_observed_word_indices": [],
                },
                {
                    "id": "nine",
                    "discriminants": [
                        {
                            "word_index": 0,
                            "mask": 0xFFFFFFFF,
                            "value": 9,
                        }
                    ],
                    "input_word_indices": [0],
                    "output_word_indices": [1],
                    "output_condition": "always",
                    "failure_preserved_word_indices": [],
                    "failure_observed_word_indices": [],
                },
            ],
        }
        transducers = [
            {"kind": "logical_argument", "parameter_index": 0},
            {
                "kind": "local_cell",
                "cell_id": "record",
                "initial_words": [
                    8,
                    {
                        "kind": "entry_projection",
                        "projection": {
                            "kind": "stack",
                            "offset": 64,
                            "width": 32,
                            "at": "entry",
                        },
                    },
                ],
                "local_cell_relation_sha256": canonical_sha256_v3(relation),
            },
            {
                "kind": "finite_word_map",
                "parameter_index": 1,
                "cases": [
                    {"logical_value": 1, "physical_value": 0x401000},
                    {"logical_value": 2, "physical_value": 0x402000},
                ],
            },
            {"kind": "constant", "value": 0},
        ]
        source = "\n".join(
            _external_service_thunk(
                bundle,
                {
                    "service_id": "get",
                    "provider_kind": "interface_method",
                    "symbol": "fixture_get",
                    "argument_offsets": [0, 4, 8, 12],
                    "events": [
                        {
                            "unit_id": "unit:get",
                            "source_rva": 0x1000,
                            "instruction_rva": 0x1004,
                            "event_index": 0,
                            "return_rva": 0x1008,
                            "event_stack_offsets": [0],
                        }
                    ],
                    "argument_transducers": transducers,
                    "out_interfaces": [],
                    "argument_interfaces": [
                        {
                            "physical_index": 0,
                            "parameter_index": 0,
                            "profile_sha256": SHA,
                            "interface_id": "IFixture",
                        }
                    ],
                    "local_cells": [relation],
                    "result_projection": {
                        "kind": "local_cell_word",
                        "cell_id": "record",
                        "word_index": 1,
                    },
                    "receiver_argument": 0,
                    "slot": 11,
                    "profile_sha256": SHA,
                    "interface_id": "IFixture",
                },
                {},
            )
        )
        self.assertIn("service->state->esp < UINT32_C(24)", source)
        self.assertIn("physical_argument_1 = call_input.esp + UINT32_C(16)", source)
        self.assertIn(
            "UINT32_C(20), UINT32_C(4), initial_local_cell_record_1",
            source,
        )
        self.assertIn("switch (logical_argument_word_1)", source)
        self.assertIn("physical_argument_2 = UINT32_C(4202496)", source)
        self.assertIn("physical_local_cell_result", source)
        self.assertIn("service->state->esp + UINT32_C(64)", source)
        self.assertIn("checked_local_cell_result", source)
        self.assertIn("call_output.eax & UINT32_C(0x80000000)", source)
        self.assertIn("call_input.esp + UINT32_C(20)", source)
        self.assertIn("return (uint32_t)checked_local_cell_result", source)
        self.assertIn("saved_frame_word_5", source)

        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        harness = f"""{exact_runtime_header()}
typedef struct spx_resource_v5 {{
  uint32_t type_tag;
  uint32_t generation;
  uint64_t identity;
}} spx_resource_v5;
typedef struct spx_component_service_context_v1 {{
  spx_runtime *runtime;
  spx_machine_state *state;
  uint32_t *fault;
  struct {{ uint32_t physical_word; uint32_t target_rva; }} callback_result;
}} spx_component_service_context_v1;
static uint32_t spx_component_read(
    spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {{
  if (rt == 0 || rt->read == 0) {{ *fault = 1U; return 0U; }}
  return rt->read(rt->context, address, width, fault);
}}
{"\n".join(_external_service_runtime_helpers())}
{source}
static uint32_t memory_words[1024];
static uint32_t fixture_read(
    void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {{
  (void)opaque;
  if (width != 4U || (address & 3U) != 0U || address / 4U >= 1024U) {{
    *fault = 1U;
    return 0U;
  }}
  return memory_words[address / 4U];
}}
static void fixture_write(
    void *opaque, uint32_t address, uint32_t width,
    uint32_t value, uint32_t *fault) {{
  (void)opaque;
  if (width != 4U || (address & 3U) != 0U || address / 4U >= 1024U) {{
    *fault = 1U;
    return;
  }}
  memory_words[address / 4U] = value;
}}
static spx_boundary_status fixture_realize(
    void *opaque, const char *profile, const char *interface_id,
    const spx_machine_resource_v1 *resource, uint32_t nullable,
    uint32_t *physical_word) {{
  (void)opaque; (void)profile; (void)interface_id; (void)nullable;
  if (resource->type_tag != 1U || resource->generation != 2U ||
      resource->identity != UINT64_C(3)) return SPX_BOUNDARY_TYPE_MISMATCH;
  *physical_word = UINT32_C(256);
  return SPX_BOUNDARY_OK;
}}
spx_call_status spx_invoke_call(
    spx_runtime *runtime, const spx_call_event *event,
    const spx_machine_state *input, spx_machine_state *output) {{
  uint32_t fault = 0U;
  uint32_t cell = runtime->read(runtime->context, input->esp + 4U, 4U, &fault);
  if (fault != 0U || event->kind != SPX_CALL_INDIRECT ||
      event->target_rva != UINT32_C(768) ||
      runtime->read(runtime->context, input->esp + 8U, 4U, &fault) !=
          UINT32_C(0x402000) ||
      runtime->read(runtime->context, input->esp + 12U, 4U, &fault) != 0U ||
      runtime->read(runtime->context, cell, 4U, &fault) != 8U ||
      runtime->read(runtime->context, cell + 4U, 4U, &fault) !=
          UINT32_C(0x12345678))
    return SPX_CALL_EXTERNAL_FAULT;
  runtime->write(runtime->context, cell + 4U, 4U, UINT32_C(0xdecafbad), &fault);
  *output = *input;
  output->eax = UINT32_C(0x80004005);
  return fault == 0U ? SPX_CALL_OK : SPX_CALL_MEMORY_FAULT;
}}
int main(void) {{
  spx_runtime runtime = {{0}};
  spx_machine_state state = {{0}};
  uint32_t fault = 0U;
  uint32_t sentinels[6] = {{11U, 12U, 13U, 14U, 15U, 16U}};
  runtime.read = fixture_read;
  runtime.write = fixture_write;
  runtime.realize_interface_resource = fixture_realize;
  state.esp = UINT32_C(2048);
  memory_words[UINT32_C(256) / 4U] = UINT32_C(512);
  memory_words[(UINT32_C(512) + UINT32_C(44)) / 4U] = UINT32_C(768);
  memory_words[(UINT32_C(2048) + UINT32_C(64)) / 4U] =
      UINT32_C(0x12345678);
  for (uint32_t index = 0U; index < 6U; ++index)
    memory_words[(UINT32_C(2024) / 4U) + index] = sentinels[index];
  spx_component_service_context_v1 context = {{
    &runtime, &state, &fault, {{0U, 0U}}
  }};
  spx_resource_v5 receiver = {{1U, 2U, UINT64_C(3)}};
  if (fixture_get(&context, receiver, UINT32_C(2)) !=
          UINT32_C(0x12345678) || fault != 0U)
    return 1;
  for (uint32_t index = 0U; index < 6U; ++index)
    if (memory_words[(UINT32_C(2024) / 4U) + index] != sentinels[index])
      return 2;
  return 0;
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_path = root / "local-cell.c"
            executable = root / "local-cell"
            source_path.write_text(harness, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source_path),
                    "-o",
                    str(executable),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_hresult_out_interface_uses_the_shared_checked_transducer(self) -> None:
        relation = {
            "argument_index": 2,
            "interface_id": "IFixtureChild",
            "nullable": False,
            "object_size": 4,
            "success_condition": "hresult_succeeded_eax",
            "vtable_size": 12,
            "write_width": 4,
        }
        relation_sha256 = canonical_sha256_v3(relation)
        receiver = {
            "argument_index": 0,
            "dispatch_slot": 4,
            "lifecycle_effect": "preserve",
            "required_state": "live",
            "view_id": "IFixture",
        }
        method = {
            "abi": {
                "callee_cleanup": True,
                "clobbered_registers": ["eax", "ecx", "edx"],
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "template": "pe32-stdcall-v1",
            },
            "argument_words": 4,
            "callback_effect": "none",
            "external_protocol": {
                "kind": "pe32-interface-method",
                "profile_id": "fixture-profile",
                "profile_sha256": SHA,
                "interface_id": "IFixture",
                "method": "CreateChild",
                "slot": 4,
                "offset": 16,
            },
            "out_interfaces": [relation],
            "receiver_resource": receiver,
        }
        target = {
            "profile_id": "fixture-profile",
            "profile_sha256": SHA,
            "interface_id": "IFixture",
            "method": method,
        }
        method_sha256 = canonical_sha256_v3(target)
        transducers = [
            {"kind": "logical_argument", "parameter_index": 0},
            {"kind": "constant", "value": 0},
            {
                "kind": "out_interface",
                "parameter_index": 1,
                "out_interface_relation_sha256": relation_sha256,
            },
            {"kind": "constant", "value": 0},
        ]
        parsed = ServiceMachineBindingV1.parse(
            {
                "service_id": "create_child",
                "mediation": "direct",
                "provider": {
                    "kind": "interface_method",
                    "events": [
                        {
                            "unit_id": "unit:create-child",
                            "event_index": 0,
                        }
                    ],
                    "method_contract_sha256": method_sha256,
                    "argument_transducers": transducers,
                },
            },
            "fixture interface-method service",
        )
        self.assertEqual(parsed.provider["argument_transducers"], transducers)

        arguments = [_stack_word(index) for index in range(4)]
        machine_event = {
            "kind": "indirect_call",
            "arguments": arguments,
            "stack_inputs": [
                {"offset": 0, "width": 4, "value": arguments[0]},
            ],
            "target": {
                "op": "load",
                "address": {
                    "op": "add32",
                    "args": [
                        {
                            "op": "load",
                            "address": json.loads(json.dumps(arguments[0])),
                            "width": 4,
                        },
                        {"op": "const", "value": 16, "width": 32},
                    ],
                },
                "width": 4,
            },
        }
        provider = _checked_interface_method_service_v1(
            service_id="create_child",
            logical=SimpleNamespace(
                parameter_type_ids=("receiver", "child_cell"),
                result_type_id="hresult",
            ),
            logical_types={
                "receiver": SimpleNamespace(kind="resource"),
                "child_cell": SimpleNamespace(
                    kind="resource_cell", resource_kind="fixture_child"
                ),
                "hresult": SimpleNamespace(kind="scalar"),
            },
            target=target,
            method_contract_sha256=method_sha256,
            unit_id="unit:create-child",
            event_index=0,
            machine_event=machine_event,
            argument_transducers=transducers,
        )

        event = provider["events"][0]
        self.assertEqual(provider["call_boundary"]["stack_pointer_adjustment"], 16)
        self.assertEqual(
            event["arguments"],
            [
                arguments[0],
                {
                    "op": "const",
                    "value": 0,
                    "width": 64,
                },
            ],
        )
        self.assertEqual(event["physical_arguments"][2]["transducer"], transducers[2])
        self.assertEqual(len(event["argument_guards"]), 8)
        self.assertEqual(event["writebacks"][0]["interface_id"], "IFixtureChild")
        self.assertEqual(event["writebacks"][0]["parameter_index"], 1)
        self.assertEqual(event["result"]["register"], "eax")

        stale = json.loads(json.dumps(transducers))
        stale[2]["out_interface_relation_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            ValueError, "does not bind the checked relation position"
        ):
            _checked_interface_method_service_v1(
                service_id="create_child",
                logical=SimpleNamespace(
                    parameter_type_ids=("receiver", "child_cell"),
                    result_type_id="hresult",
                ),
                logical_types={
                    "receiver": SimpleNamespace(kind="resource"),
                    "child_cell": SimpleNamespace(
                        kind="resource_cell", resource_kind="fixture_child"
                    ),
                    "hresult": SimpleNamespace(kind="scalar"),
                },
                target=target,
                method_contract_sha256=method_sha256,
                unit_id="unit:create-child",
                event_index=0,
                machine_event=machine_event,
                argument_transducers=stale,
            )



if __name__ == "__main__":
    unittest.main()
