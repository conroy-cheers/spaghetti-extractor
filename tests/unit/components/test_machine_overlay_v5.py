from __future__ import annotations

import json
import copy
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary._canonical import BoundaryModelError
from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import (
    ComponentMachineBindingIntentV1,
)
from spaghetti_extractor.components.component_c_v5 import (
    render_component_c_headers_v5,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.machine_binding import ServiceMachineBindingV1
from spaghetti_extractor.components.machine_overlay_external_v5 import (
    _external_service_thunk,
)
from spaghetti_extractor.components.machine_overlay_v5 import (
    _common_owned_boundary_exit,
    _logical_operation_thunk,
    render_component_dispatch_registry_v1,
    render_component_machine_overlay_v5,
)
from spaghetti_extractor.components.normalized_component import (
    NormalizedComponentContract,
)
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


ROOT = Path(__file__).parents[3]
TESTKIT = {
    "fixtures": ("compiler",),
    "resources": (
        "targets/gnu-hello/intent/interfaces-v5",
        "targets/gnu-hello/intent/bindings-v5",
        "targets/dxball/intent/interfaces-v5",
        "targets/jq/intent/interfaces-v5",
    ),
}


from .machine_overlay_fixture import _transfer as _transfer, _component_overlay as _component_overlay, _external_contract as _external_contract, _resolved_environment as _resolved_environment

class ComponentMachineOverlayV5Tests(unittest.TestCase):
    def test_complete_replacement_links_without_body_and_rejects_interior(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is unavailable")
        entry = {
            "component_id": "whole", "operation_id": "run",
            "entry_unit_id": "entry", "entry_rva": 4096,
            "owned_unit_ids": ["entry", "return"],
            "symbol": "portable_entry", "logical_symbol": "portable_run",
            "logical_abi_sha256": "a" * 64,
        }
        source = render_component_dispatch_registry_v1(
            entries=[entry], portable_unit_rvas={"entry": 4096, "return": 4100},
            retired_function_symbols=["original_routine"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "registry.c").write_text(source + r'''
spx_step_result portable_entry(spx_runtime *rt, spx_machine_state *state) {
  (void)rt;
  state->eax = 42U;
  return (spx_step_result){ SPX_RETURN, 0U, 123U };
}
int main(void) {
  spx_machine_state state = {0};
  const spx_region_override *entry = spx_region_override_lookup(4096U);
  const spx_region_override *interior = spx_region_override_lookup(4100U);
  if (!entry || !interior || entry->fallback_on_unimplemented ||
      interior->fallback_on_unimplemented || spx_region_override_lookup(4104U)) return 1;
  if (entry->function(0, &state).kind != SPX_RETURN || state.eax != 42U) return 2;
  if (interior->function(0, &state).kind != SPX_UNIMPLEMENTED || state.eax != 42U) return 3;
  if (original_routine(0, &state, 4096U).kind != SPX_UNIMPLEMENTED || state.eax != 42U) return 4;
  if (original_routine(0, &state, 4100U).kind != SPX_UNIMPLEMENTED || state.eax != 42U) return 5;
  return 0;
}
''')
            subprocess.run([compiler, "-std=c11", str(root / "registry.c"),
                            "-o", str(root / "check")], check=True, capture_output=True)
            subprocess.run([str(root / "check")], check=True, capture_output=True)
        with self.assertRaisesRegex(BoundaryModelError, "RVAs overlap"):
            render_component_dispatch_registry_v1(
                entries=[entry], portable_unit_rvas={"entry": 4096, "return": 4096})
        with self.assertRaisesRegex(BoundaryModelError, "symbol is invalid"):
            render_component_dispatch_registry_v1(
                entries=[entry], portable_unit_rvas={"entry": 4096, "return": 4100},
                retired_function_symbols=["portable_entry"])

    def test_common_exit_uses_only_outgoing_edges_and_preserves_kind(self):
        def transfer(identity, rva, action):
            return _Transfer(identity, 'a' * 64, 'b' * 64, rva, (), (), (action,), (), ())
        head = transfer('head', 0x1000, _Action('outcome_branch', (0, 0x2000, 0x1010)))
        step = transfer('step', 0x1010, _Action('outcome_branch', (0, 0x1010, 0x2000)))
        checked = lambda candidate: _common_owned_boundary_exit((head, candidate),
            owned_units=('head', 'step'), transfer_index={'head': head, 'step': candidate})
        self.assertEqual(checked(step), ('SPX_BRANCH', 0x2000))
        for action in (_Action('outcome_branch', (0, 0x1010, 0x3000)),
                       _Action('outcome_branch', (0, 0x2000, 0x3000)),
                       _Action('outcome_branch', (0, 0x1000, 0x1010)),
                       _Action('outcome_jump', (0x2000,)),
                       _Action('outcome_return', (0,)),
                       _Action('outcome_branch', (0, True, 0x2000))):
            with self.subTest(action=action):
                self.assertIsNone(checked(transfer('step', 0x1010, action)))

    def test_multiple_branch_exits_render_one_checked_boundary_outcome(self):
        interface = ComponentInterfaceIntentV1.parse(json.loads(
            (ROOT/'targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json').read_text()))
        raw = json.loads((ROOT/'targets/gnu-hello/intent/bindings-v5/ascii-to-lower.json').read_text())['operations'][0]
        head, step = raw['transfer_ids']
        raw['unit_ids'] = [head, step]
        raw['machine_projection']['operation']['exit_unit_ids'] = [head, step]
        def render(other_target):
            binding = ComponentMachineBindingIntentV1.create(component_id=interface.component_id,
                operations=[copy.deepcopy(raw)])
            bundle = compile_component_interface_v5(interface)
            contract = NormalizedComponentContract.create(interface=bundle.interface,
                machine_semantics=[op.semantics for op in binding.operations])
            transfers = [_Transfer(head, 'a'*64, 'b'*64, 0x933d, (), (),
                (_Action('outcome_branch', (0, 0x9400, 0x934a)),), (), ()),
                _Transfer(step, 'a'*64, 'b'*64, 0x934a, (), (),
                (_Action('outcome_branch', (0, 0x934a, other_target)),), (), ())]
            return render_component_machine_overlay_v5(bundle=bundle, contract=contract,
                operation_symbols={'convert': 'convert'}, transfers=transfers)
        rendered = render(0x9400)
        self.assertIn('return (spx_step_result){ SPX_BRANCH, UINT32_C(37888), 0U };', rendered.source)
        self.assertEqual(rendered.entries[0]['owned_unit_ids'], [head, step])
        with self.assertRaisesRegex(BoundaryModelError, 'common-boundary equivalence'):
            render(0x9500)

    def test_logical_record_has_one_named_portable_c_value_type(self) -> None:
        interface = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/jq/intent/interfaces-v5/output-value-pipeline.json"
                ).read_text(encoding="utf-8")
            )
        )
        headers = render_component_c_headers_v5(
            compile_component_interface_v5(interface),
            {"run": "jq_output_value_pipeline_run"},
        )
        public = headers["portable-component.h"]
        self.assertEqual(public.count("typedef struct spx_jv_value_v2"), 1)
        self.assertIn("uint32_t metadata;", public)
        self.assertIn("uint32_t payload_high;", public)
        self.assertIn("typedef spx_jv_value_v2 spx_jv_value_v5;", public)

    def test_scalar_stack_parameter_and_register_result_use_faithful_exit(self) -> None:
        interface = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json"
                ).read_text(encoding="utf-8")
            )
        )
        binding = ComponentMachineBindingIntentV1.parse(
            json.loads(
                (
                    ROOT / "targets/gnu-hello/intent/bindings-v5/ascii-to-lower.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(interface)
        contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[item.semantics for item in binding.operations],
        )
        rendered = render_component_machine_overlay_v5(
            bundle=bundle,
            contract=contract,
            operation_symbols={"convert": "gnu_hello_ascii_to_lower"},
            transfers=(
                _transfer(
                    "semantic-transfer:original-cutpoint-0000933d-0000934a",
                    0x933D,
                ),
                _Transfer(
                    "semantic-transfer:original-cutpoint-0000934a-00009352",
                    "a" * 64,
                    "b" * 64,
                    0x934A,
                    (),
                    (),
                    (_Action("outcome_return", (0,)),),
                    (),
                    (),
                ),
            ),
        )
        self.assertEqual(len(rendered.entries), 1)
        self.assertEqual(
            rendered.entries[0]["owned_unit_ids"],
            ["semantic-transfer:original-cutpoint-0000933d-0000934a",
             "semantic-transfer:original-cutpoint-0000934a-00009352"],
        )
        self.assertIn("state->esp + UINT32_C(4)", rendered.source)
        self.assertIn("state->eax = ((uint32_t)(logical_result_word))", rendered.source)
        self.assertIn("state->esp += UINT32_C(4)", rendered.source)
        self.assertIn("SPX_RETURN, 0U, return_address", rendered.source)

        registry = render_component_dispatch_registry_v1(
            entries=rendered.entries,
            portable_unit_rvas={
                "semantic-transfer:original-cutpoint-0000933d-0000934a": 0x933D,
                "semantic-transfer:original-cutpoint-0000934a-00009352": 0x934A,
            },
        )
        self.assertIn("spx_region_override_lookup", registry)
        self.assertIn("const spx_region_override spx_region_overrides[]", registry)
        self.assertIn("const uint32_t spx_region_override_count", registry)
        self.assertIn('#include "state-machine-runtime.h"', registry)
        self.assertNotIn('#include "behavioral-c.h"', registry)
        self.assertNotIn("spx_portable_overrides", registry)
        self.assertNotIn("spx_native_machine_fallback_allowed", registry)
        self.assertIn("uint32_t fallback_on_unimplemented;", registry)
        self.assertIn(", UINT32_C(0),", registry)

    def test_control_result_uses_exact_machine_branch_targets(self) -> None:
        unit_id = "semantic-transfer:original-cutpoint-000011ac-000011b3"
        rendered = _component_overlay(
            "short-option-classifier",
            action_by_unit={unit_id: (_Action("outcome_branch", (0, 0x1200, 0x1300)),)},
        )
        self.assertIn(
            "logical_result != 0U ? UINT32_C(4608) : UINT32_C(4864)",
            rendered.source,
        )
        self.assertIn("(void)rt;", rendered.source)
        # Suppress the unused-helper warning without adding a runtime function
        # pointer target to the generated proof model.
        self.assertIn("(void)sizeof(&spx_component_read);", rendered.source)
        self.assertIn("SPX_BRANCH", rendered.source)

    def test_finite_control_target_is_total_and_fails_closed(self) -> None:
        rendered = _component_overlay("finite-selector-dispatch")
        self.assertIn("switch ((uint32_t)logical_result)", rendered.source)
        self.assertIn("case UINT32_C(11)", rendered.source)
        self.assertIn(
            "SPX_INDIRECT_JUMP, 0U, rt->image_base + UINT32_C(15128)",
            rendered.source,
        )
        self.assertIn(
            "default: return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            rendered.source,
        )

    def test_operation_inlines_unconditional_exit_control(self) -> None:
        exit_unit = "semantic-transfer:original-cutpoint-00013d07-00013d08"
        rendered = _component_overlay(
            "bounded-string-length",
            action_by_unit={exit_unit: (_Action("outcome_jump", (0x1CDB,)),)},
        )
        self.assertIn(
            "return (spx_step_result){ SPX_JUMP, UINT32_C(7387), 0U };",
            rendered.source,
        )

    def test_view_is_resolved_with_checked_extent_and_no_static_context(self) -> None:
        rendered = _component_overlay("bounded-string-length")
        self.assertIn("rt->resolve_reference", rendered.source)
        self.assertIn("argument_maximum", rendered.source)
        self.assertIn("argument_buffer_machine.extent", rendered.source)
        self.assertIn("offset >= view->extent", rendered.source)
        self.assertNotIn("static spx_bounded_string_length_context_v5", rendered.source)

    def test_result_codec_encodes_logical_offset_back_to_machine_pointer(self) -> None:
        rendered = _component_overlay("last-path-component")
        self.assertIn("argument_value_view.base.object", rendered.source)
        self.assertIn("+ (logical_result_word)", rendered.source)
        self.assertIn("state->eax = ((uint32_t)", rendered.source)

    def test_atomic_object_calls_shared_runtime_directly(self) -> None:
        exit_unit = "semantic-transfer:original-cutpoint-0000105a-0000105c"
        rendered = _component_overlay(
            "startup-atomic-compare-exchange",
            action_by_unit={
                exit_unit: (_Action("outcome_branch", (0, 0x1050, 0x105C)),)
            },
        )
        self.assertIn("spx_runtime_atomic_compare_exchange", rendered.source)
        self.assertIn("spx_runtime_atomic_exchange", rendered.source)
        self.assertIn("UINT32_C(4391716)", rendered.source)
        self.assertIn(
            "logical_result != 0U ? UINT32_C(4176) : UINT32_C(4188)", rendered.source
        )

    def test_component_operation_service_uses_typed_provider_thunk(self) -> None:
        call_units = {
            "semantic-transfer:original-cutpoint-000067dc-000067e7": (
                _Call(
                    "internal_call",
                    0x67E2,
                    0,
                    None,
                    0x933D,
                    0x67E7,
                    None,
                    None,
                    None,
                    (),
                    (),
                    (),
                    ((0, 4, 0),),
                ),
            ),
            "semantic-transfer:original-cutpoint-000067e7-000067f4": (
                _Call(
                    "internal_call",
                    0x67EF,
                    0,
                    None,
                    0x933D,
                    0x67F4,
                    None,
                    None,
                    None,
                    (),
                    (),
                    (),
                    ((0, 4, 0),),
                ),
            ),
        }
        rendered = _component_overlay("ascii-string-compare", call_by_unit=call_units)
        provider_overlay = _component_overlay("ascii-to-lower")
        self.assertEqual(provider_overlay.source.count(
            "spx_ascii_to_lower_services_v5 logical_services = {"), 2)
        self.assertEqual(provider_overlay.source.count(
            "(&logical_context)->services = &logical_services;"), 2)
        provider = "spx_component_logical_ascii_to_lower_convert"
        self.assertIn(f"extern uint32_t {provider}(void *, uint32_t);", rendered.source)
        self.assertIn(
            "spx_ascii_string_compare_services_v5 logical_services",
            rendered.source,
        )
        self.assertIn(f"&service_context, {provider}", rendered.source)
        self.assertEqual(
            rendered.entries[0]["service_bindings"][0]["provider_component_id"],
            "ascii-to-lower",
        )
        self.assertEqual(
            rendered.entries[0]["service_bindings"][0]["abi_sha256"],
            provider_overlay.entries[0]["logical_abi_sha256"],
        )
        self.assertEqual(
            [
                event["unit_id"]
                for event in rendered.entries[0]["service_bindings"][0]["events"]
            ],
            [
                "semantic-transfer:original-cutpoint-000067dc-000067e7",
                "semantic-transfer:original-cutpoint-000067e7-000067f4",
            ],
        )
        unit_rvas = {}
        for entry in (*rendered.entries, *provider_overlay.entries):
            for unit_id in entry["owned_unit_ids"]:
                match = re.search(r"original-cutpoint-([0-9a-f]{8})", unit_id)
                assert match is not None
                unit_rvas[unit_id] = int(match.group(1), 16)
        registry = render_component_dispatch_registry_v1(
            entries=(*rendered.entries, *provider_overlay.entries),
            portable_unit_rvas=unit_rvas,
        )
        self.assertIn("spx_region_override_lookup", registry)

        incompatible = [dict(entry) for entry in rendered.entries]
        incompatible[0]["service_bindings"] = [
            {
                **incompatible[0]["service_bindings"][0],
                "abi_sha256": "0" * 64,
            }
        ]
        with self.assertRaisesRegex(BoundaryModelError, "ABI-incompatible"):
            render_component_dispatch_registry_v1(
                entries=(*incompatible, *provider_overlay.entries),
                portable_unit_rvas=unit_rvas,
            )

    def test_logical_provider_thunk_normalizes_value_bounded_views(self) -> None:
        intent = ComponentInterfaceIntentV1.parse(
            json.loads(
                (
                    ROOT
                    / "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json"
                ).read_text(encoding="utf-8")
            )
        )
        bundle = compile_component_interface_v5(intent)
        source = "\n".join(
            _logical_operation_thunk(
                bundle=bundle,
                component="memory_regions_equal",
                operation=bundle.interface.operations[0],
                source_symbol="test_memory_regions_equal",
                logical_symbol="test_logical_memory_regions_equal",
                service_bindings=[
                    {
                        "service_id": "compare_memory",
                        "symbol": "test_compare_memory",
                    }
                ],
            )
        )

        self.assertIn("spx_view_v5 logical_left_bounded;", source)
        self.assertIn("logical_left_requested = (uint64_t)logical_count;", source)
        self.assertIn("logical_right_requested = (uint64_t)logical_count;", source)
        self.assertIn(
            "logical_left_argument, logical_right_argument, logical_count)",
            source,
        )

    def test_external_service_uses_authorized_call_frame_and_reference_realization(
        self,
    ) -> None:
        unit_id = "semantic-transfer:original-cutpoint-00008d6f-00008d7f"
        site_id = (
            "external-site-v3:"
            "113b3481e724d854f3ba27d44c90758a943de5b69ade25293e7db67512986955"
        )
        call = _Call(
            "external_call",
            0x8D76,
            0,
            None,
            0,
            0x8D7B,
            "msvcrt.dll",
            "memcmp",
            None,
            (),
            (),
            (),
            ((0, 4, 0), (4, 4, 0), (8, 4, 0)),
        )

        def stack_word(offset: int) -> dict[str, object]:
            return {
                "op": "load",
                "width": 4,
                "address": (
                    {"op": "reg", "name": "esp", "width": 32}
                    if offset == 0
                    else {
                        "op": "add32",
                        "args": [
                            {"op": "reg", "name": "esp", "width": 32},
                            {"op": "const", "value": offset, "width": 32},
                        ],
                        "width": 32,
                    }
                ),
            }

        site = {
            "id": site_id,
            "status": "complete",
            "authorizing": True,
            "primary_blocker": None,
            "unit_id": unit_id,
            "event_index": 0,
            "identity": {"dll": "msvcrt.dll", "symbol": "memcmp", "ordinal": None},
            "contract": {
                "arguments": [stack_word(0), stack_word(4), stack_word(8)],
                "machine_contract": {"abi_template": "pe32-cdecl-v1"},
            },
        }
        rendered = _component_overlay(
            "memory-regions-equal",
            call_by_unit={unit_id: (call,)},
            resolved_external_environment=_resolved_environment(
                _external_contract(
                    dict(site["identity"]),
                    abi_template="pe32-cdecl-v1",
                    argument_words=3,
                )
            ),
        )
        explicit_production_renderer = _component_overlay(
            "memory-regions-equal",
            call_by_unit={unit_id: (call,)},
            resolved_external_environment=_resolved_environment(
                _external_contract(
                    dict(site["identity"]),
                    abi_template="pe32-cdecl-v1",
                    argument_words=3,
                )
            ),
            external_service_thunk_renderer=_external_service_thunk,
        )
        self.assertEqual(rendered, explicit_production_renderer)
        source = rendered.source
        self.assertIn(
            "spx_component_external_memory_regions_equal_compare_memory", source
        )
        self.assertIn("spx_machine_reference_v1 physical_argument_0_reference", source)
        self.assertIn("service->runtime->realize_reference", source)
        self.assertIn("call_input.esp -= UINT32_C(12)", source)
        self.assertIn('"msvcrt.dll", "memcmp"', source)
        self.assertIn("spx_invoke_call", source)
        self.assertIn("saved_frame_word_2", source)
        self.assertIn("SPX_EXTERNAL_FAULT", source)

        selected_payload = _external_contract(dict(site["identity"]),
            abi_template="pe32-cdecl-v1", argument_words=3)["contract"]["payload"]
        self.assertEqual(rendered.entries[0]["service_bindings"][0]["external_effect_contract"],
                         selected_payload)

        selected_row = _external_contract(dict(site["identity"]),
            abi_template="pe32-cdecl-v1", argument_words=3)
        native_contract = _checked_contract(row=selected_row, call=call, escape_index={})
        proof_binding = rendered.entries[0]["service_bindings"][0]
        self.assertEqual(proof_binding["external_contract_identity_sha256"],
                         native_contract.identity_sha256())
        original_spec = _proof_call_specs([proof_binding])[0]
        # A profile-only change must reach the proof transcript even though
        # import address, logical service and effect payload all stay the same.
        selected_row["contract"]["profile_sha256"] = "6" * 64
        altered_overlay = _component_overlay("memory-regions-equal",
            call_by_unit={unit_id: (call,)},
            resolved_external_environment=_resolved_environment(selected_row))
        altered_binding = altered_overlay.entries[0]["service_bindings"][0]
        self.assertEqual(proof_binding["external_effect_contract"], altered_binding["external_effect_contract"])
        self.assertNotEqual(original_spec["spec_id"], _proof_call_specs([altered_binding])[0]["spec_id"])

        for field in ("memory_effect", "world_effect"):
            incomplete = _external_contract(dict(site["identity"]),
                abi_template="pe32-cdecl-v1", argument_words=3)
            del incomplete["contract"]["payload"][field]
            with self.subTest(field=field), self.assertRaisesRegex(BoundaryModelError, field):
                _component_overlay("memory-regions-equal", call_by_unit={unit_id: (call,)},
                    resolved_external_environment=_resolved_environment(incomplete))

        stale_site = dict(site)
        stale_site["identity"] = {
            "dll": "msvcrt.dll",
            "symbol": "strcmp",
            "ordinal": None,
        }
        with self.assertRaisesRegex(BoundaryModelError, "contract is absent"):
            _component_overlay(
                "memory-regions-equal",
                call_by_unit={unit_id: (call,)},
                resolved_external_environment=_resolved_environment(
                    _external_contract(
                        dict(stale_site["identity"]),
                        abi_template="pe32-cdecl-v1",
                        argument_words=3,
                    )
                ),
            )

    def test_interface_method_service_checks_receiver_and_out_interface(self) -> None:
        raw = json.loads(
            (
                ROOT / "targets/dxball/intent/interfaces-v5/directdraw-init.json"
            ).read_text(encoding="utf-8")
        )
        types = {row["id"]: dict(row) for row in raw["schema"]["types"]}
        types["operation.initialize.function"] = {
            **types["operation.initialize.function"],
            "parameter_type_ids": [],
            "result_type_id": "unit",
        }
        types["service.set_cooperative_level.function"] = {
            **types["service.set_cooperative_level.function"],
            "parameter_type_ids": ["directdraw", "surface"],
        }
        signatures = {row["id"]: dict(row) for row in raw["schema"]["signatures"]}
        signatures["operation.initialize"] = {
            **signatures["operation.initialize"],
            "parameters": [],
            "results": [],
        }
        method_signature = json.loads(
            json.dumps(signatures["service.set_cooperative_level"])
        )
        method_signature["parameters"] = [
            method_signature["parameters"][0],
            {
                "access": "write",
                "extent": {"bytes": None, "kind": "none", "value_id": None},
                "id": "created",
                "interpretation": "resource",
                "nullable": False,
                "provider_domain": "component-environment.directdraw-init",
                "resource_kind": "directdraw_surface",
                "type_id": "surface",
            },
        ]
        signatures["service.set_cooperative_level"] = method_signature
        schema = BoundarySchemaV1.create(
            schema_id="component.interface-method-fixture",
            types=[
                types[name]
                for name in (
                    "directdraw",
                    "operation.initialize.function",
                    "service.set_cooperative_level.function",
                    "status",
                    "surface",
                    "status-underlying",
                    "unit",
                )
            ],
            signatures=[
                signatures["operation.initialize"],
                signatures["service.set_cooperative_level"],
            ],
        )
        operation = json.loads(json.dumps(raw["operations"][0]))
        operation.update(
            {
                "allowed_service_ids": ["set_cooperative_level"],
                "effect_ids": [],
                "lifecycle_bindings": [],
                "projection_entries": [],
                "source_values": [],
            }
        )
        intent = ComponentInterfaceIntentV1.create(
            component_id="interface-method-fixture",
            schema=schema,
            state=[],
            operations=[operation],
            effects=[],
            services=[
                next(
                    row
                    for row in raw["services"]
                    if row["id"] == "set_cooperative_level"
                ),
                {
                    "id": "unused",
                    "signature_id": "service.set_cooperative_level",
                    "effect_ids": [],
                    "interaction_contract_id": "component-service.fixture.unused",
                },
            ],
            protocol_states=["ready"],
            initial_protocol_state="ready",
        )
        bundle = compile_component_interface_v5(intent)
        unit_id = "semantic-transfer:original-cutpoint-0000cdb7-0000cdbd"
        profile_sha256 = "7" * 64
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
        method = {
            "argument_words": 4,
            "callback_effect": "none",
            "external_protocol": {
                "kind": "pe32-interface-method",
                "profile_id": "fixture-profile",
                "profile_sha256": profile_sha256,
                "interface_id": "IFixture",
                "method": "CreateChild",
                "slot": 4,
                "offset": 16,
            },
            "receiver_resource": {
                "argument_index": 0,
                "dispatch_slot": 4,
                "lifecycle_effect": "preserve",
                "required_state": "live",
                "view_id": "IFixture",
            },
            "argument_interfaces": [{"argument_index": 0, "interface_id": "IFixture"}],
            "out_interfaces": [relation],
        }
        method_core = {
            "profile_id": "fixture-profile",
            "profile_sha256": profile_sha256,
            "interface_id": "IFixture",
            "method": method,
        }
        method_sha256 = canonical_sha256_v3(method_core)
        parsed_service = ServiceMachineBindingV1.parse(
            {
                "service_id": "set_cooperative_level",
                "mediation": "direct",
                "provider": {
                    "kind": "interface_method",
                    "events": [{"unit_id": unit_id, "event_index": 0}],
                    "method_contract_sha256": method_sha256,
                    "argument_transducers": transducers,
                },
            },
            "fixture interface method",
        )
        self.assertEqual(parsed_service.provider["kind"], "interface_method")
        operation_binding = {
            "id": "initialize",
            "kind": "operation",
            "unit_ids": [unit_id],
            "entry_rvas": [0xCDB7],
            "transfer_ids": [unit_id],
            "effect_ids": [],
            "service_ids": ["set_cooperative_level"],
            "callback_ids": [],
            "outcome_protocol_ids": [],
            "machine_projection": {
                "operation": {
                    "operation_id": "initialize",
                    "entry_unit_ids": [unit_id],
                    "exit_unit_ids": [unit_id],
                    "parameters": [],
                    "results": [],
                    "state": [],
                    "preserved_state_ids": [],
                    "effects": [],
                    "callback_operation_ids": [],
                    "continuation_unit_ids": [],
                },
                "service_bindings": [
                    {
                        "service_id": "set_cooperative_level",
                        "mediation": "direct",
                        "provider": {
                            "kind": "interface_method",
                            "events": [{"unit_id": unit_id, "event_index": 0}],
                            "method_contract_sha256": method_sha256,
                            "argument_transducers": transducers,
                        },
                    }
                ],
            },
            "object_authority_selectors": [],
            "pointer_views": [],
            "relation_receipt_sha256s": [],
            "induction_evidence_sha256": None,
        }
        binding = ComponentMachineBindingIntentV1.create(
            component_id="interface-method-fixture",
            operations=[operation_binding],
        )
        contract = NormalizedComponentContract.create(
            interface=bundle.interface,
            machine_semantics=[binding.operations[0].semantics],
        )
        transfer = _Transfer(
            unit_id,
            "a" * 64,
            "b" * 64,
            0xCDB7,
            (
                _Node("const", immediate=16),
                _Node("reg", aux=2),
                _Node("load", (1,), aux=4),
                _Node("add32", (0, 2)),
                _Node("load", (3,), aux=4),
                _Node("const", immediate=1),
                _Node("const", immediate=2),
                _Node("const", immediate=0),
            ),
            (),
            (),
            (
                _Call(
                    "indirect_call",
                    0xCDBA,
                    0,
                    4,
                    0,
                    0xCDBD,
                    None,
                    None,
                    None,
                    (),
                    (),
                    (1, 5, 6, 7),
                    ((0, 4, 1),),
                ),
            ),
            (),
        )
        rendered = render_component_machine_overlay_v5(
            bundle=bundle,
            contract=contract,
            operation_symbols={"initialize": "fixture_initialize"},
            transfers=(transfer,),
            resolved_external_environment=_resolved_environment(
                interface_catalogs=(
                    {
                        "profile_id": "fixture-profile",
                        "profile_sha256": profile_sha256,
                        "interface_id": "IFixture",
                        "methods": [method],
                    },
                ),
            ),
        )
        self.assertIn("realize_interface_resource", rendered.source)
        self.assertIn("physical_out_interface_1", rendered.source)
        self.assertIn("resolved_out_interface_1", rendered.source)
        self.assertIn("interface_vtable + UINT32_C(16)", rendered.source)
        self.assertNotIn(
            "interface_vtable > UINT32_MAX - UINT32_C(16)", rendered.source
        )
        self.assertIn("*service->memory_fault = UINT32_C(1)", rendered.source)
        self.assertIn("*service->service_fault = UINT32_C(1)", rendered.source)
        self.assertIn("SPX_CALL_INDIRECT", rendered.source)
        self.assertRegex(
            rendered.source,
            r"spx_interface_method_fixture_services_v5 logical_services = \{\s*"
            r"&service_context, [^,]+, 0\s*\};",
        )
        self.assertIn(method_sha256, json.dumps(rendered.entries))


if __name__ == "__main__":
    unittest.main()
