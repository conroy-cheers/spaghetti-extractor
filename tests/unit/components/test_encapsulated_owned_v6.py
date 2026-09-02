from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.component_c_v5 import (
    render_component_c_headers_v5,
)
from spaghetti_extractor.components.binding_intent import (
    MachineOperationSemanticsV1,
)
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.components.machine_overlay_v5 import (
    render_component_machine_overlay_v5,
)
from spaghetti_extractor.components.normalized_component import (
    NormalizedComponentContract,
)
from spaghetti_extractor.components.refinement import check_component_refinement
from spaghetti_extractor.components.work_package_v6 import ComponentWorkPackageV6
from spaghetti_extractor.semantic_objects.object_authority import (
    LoaderRealizedLocatorV2,
    MachineObjectAuthorityV2,
    MachineObjectRuleV2,
)
from spaghetti_extractor.semantic_providers.encapsulated_owned import (
    EncapsulatedOwnedAdmissionError,
    check_encapsulated_owned_admission,
)
from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components import test_semantic_refinement as refinement_support


TESTKIT = {"fixtures": ("cbmc", "compiler")}

UNIT = "semantic-transfer:original-cutpoint-00001000-00001010"
DEFINITION = "semantic-definition-v2:" + "1" * 64


def _value(identity: str, type_id: str) -> dict[str, object]:
    return {
        "id": identity,
        "type_id": type_id,
        "interpretation": "value",
        "nullable": False,
        "access": "none",
        "extent": {"kind": "none", "bytes": None, "value_id": None},
        "resource_kind": None,
        "provider_domain": None,
    }


def _bundle():
    schema = BoundarySchemaV1.create(
        schema_id="owned-counter-schema",
        types=[
            {"id": "unit", "kind": "void"},
            {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
            {
                "id": "add-function",
                "kind": "function",
                "result_type_id": "u32",
                "parameter_type_ids": ["u32"],
                "variadic": False,
                "calling_convention": "cdecl",
            },
        ],
        signatures=[{
            "id": "add-signature",
            "function_type_id": "add-function",
            "parameters": [_value("amount", "u32")],
            "results": [_value("result", "u32")],
        }],
    )
    intent = ComponentInterfaceIntentV1.create(
        component_id="owned-counter",
        schema=schema,
        state=[{"value": _value("value", "u32"), "initial": 0}],
        operations=[{
            "id": "add",
            "signature_id": "add-signature",
            "source_values": [_value("amount", "u32"), _value("result", "u32")],
            "projection_entries": [
                {
                    "source_id": "amount",
                    "target": {"root": "parameter", "value_id": "amount", "fields": []},
                },
                {
                    "source_id": "result",
                    "target": {"root": "result", "value_id": "result", "fields": []},
                },
            ],
            "lifecycle_bindings": [],
            "lifecycle_additional_roots": {"state": []},
            "checked_interaction_contract_ids": [],
            "effect_ids": [],
            "allowed_service_ids": [],
            "pre_states": ["ready"],
            "post_states": ["ready"],
        }],
        effects=[],
        services=[],
        protocol_states=["ready"],
        initial_protocol_state="ready",
    )
    return compile_component_interface_v5(intent)


def _machine_projection() -> dict[str, object]:
    return {
        "operation": {
            "operation_id": "add",
            "entry_unit_ids": [UNIT],
            "exit_unit_ids": [UNIT],
            "parameters": [{
                "id": "amount",
                "projection": {
                    "kind": "register", "register": "ecx",
                    "width": 32, "at": "entry",
                },
            }],
            "results": [{
                "id": "result",
                "projection": {
                    "kind": "register", "register": "eax",
                    "width": 32, "at": "exit",
                },
            }],
            "state": [{
                "id": "value",
                "entry": {
                    "kind": "static_slot", "rva": 0x3000,
                    "width": 32, "at": "entry",
                },
                "exit": {
                    "kind": "static_slot", "rva": 0x3000,
                    "width": 32, "at": "exit",
                },
            }],
            "preserved_state_ids": [],
            "effects": [],
            "callback_operation_ids": [],
            "continuation_unit_ids": [],
        },
        "service_bindings": [],
        "preserved_unit_inventory": [UNIT],
    }


def _transfer() -> _Transfer:
    return _Transfer(
        UNIT,
        "2" * 64,
        "3" * 64,
        0x1000,
        (
            _Node("const", immediate=0x3000),
            _Node("load", (0,), aux=4),
            _Node("reg", aux=2),
            _Node("add32", (1, 2)),
        ),
        (),
        (
            _Action("memory_write", (0, 3), aux=4),
            _Action("outcome_return", (3,)),
        ),
        (),
        (),
    )


def _contract(bundle):
    semantics = MachineOperationSemanticsV1.create(
        operation_id="add",
        kind="operation",
        unit_ids=[UNIT],
        entry_rvas=[0x1000],
        transfer_ids=[UNIT],
        effect_ids=[],
        service_ids=[],
        callback_ids=[],
        outcome_protocol_ids=["normal"],
        machine_projection=_machine_projection(),
    )
    return NormalizedComponentContract.create(
        interface=bundle.interface, machine_semantics=[semantics]
    )


def _package() -> ComponentWorkPackageV6:
    operation = {
        "operation_id": "add",
        "definition_ids": [DEFINITION],
        "unit_ids": [UNIT],
        "effect_ids": [],
        "service_ids": [],
        "callback_ids": [],
        "outcome_protocol_ids": ["normal"],
        "object_authority_selectors": [],
        "pointer_views": [],
        "machine_projection": _machine_projection(),
    }
    return ComponentWorkPackageV6({
        "component_id": "owned-counter",
        "proof_classification": "encapsulated_owned",
        "work_package_sha256": "4" * 64,
        "bindings": {"executable_transfer_plan_sha256": "5" * 64},
        "operations": [operation],
        "semantic_slice": {
            "definitions": [{"definition_id": DEFINITION}],
        },
    })


def _linked():
    return SimpleNamespace(
        identity="6" * 64,
        payload={
            "bindings": {"executable_transfer_plan_sha256": "5" * 64},
            "definitions": [{
                "definition_id": DEFINITION,
                "definition_kind": "transfer_v2",
                "symbol_id": f"original:function:{UNIT}",
            }],
            "roots": [{
                "kind": "process_entry",
                "target_symbol": f"original:function:{UNIT}",
            }],
            "effects": {
                "callbacks": [], "code_capabilities": [], "exceptions": [],
                "export_capabilities": [], "external_contracts": [],
                "import_uses": [], "indirect_targets": [],
                "nonlocal_transitions": [],
            },
        },
    )


def _authority(*, anchor: bool = False) -> MachineObjectAuthorityV2:
    rule = MachineObjectRuleV2(
        identity="owned-counter-state",
        kind="image",
        domain=1,
        object_id=1,
        generation=1,
        extent=4,
        permissions=3,
        lifetime="image",
        locator=LoaderRealizedLocatorV2("image_rva", "fixture.exe", 0x3000),
        interior_pointers=False,
        evidence_sha256="7" * 64,
    )
    anchors = [] if not anchor else [{
        "id": "counter-export",
        "rule_id": rule.identity,
        "byte_offset": 0,
        "access": "read_write",
        "aliases": [{"ordinal": 1, "name": "counter"}],
        "typed_view": None,
    }]
    return MachineObjectAuthorityV2(
        machine_backend="pe32-i686",
        bindings={"original_pe_sha256": "8" * 64},
        rules=[rule],
        data_export_anchors=anchors,
    )


class EncapsulatedOwnedV6Tests(unittest.TestCase):
    def test_admission_binds_total_transfer_and_exact_private_partition(self) -> None:
        package = _package()
        receipt = check_encapsulated_owned_admission(
            component_id="owned-counter",
            proof_classification="encapsulated_owned",
            operations=package.payload["operations"],
            semantic_slice=SimpleNamespace(
                identity="9" * 64,
                payload=package.payload["semantic_slice"],
            ),
            qualification_input_sha256="a" * 64,
            bundle=_bundle(), linked=_linked(),
            transfers=[_transfer()], authority=_authority(),
        )
        self.assertEqual(receipt["status"], "checked")
        self.assertTrue(receipt["state_relation"]["total"])
        self.assertTrue(receipt["threading"]["thread_confined"])
        self.assertEqual(receipt["ownership"]["outside_aliases"], 0)

    def test_loader_visible_data_anchor_rejects_representation_change(self) -> None:
        with self.assertRaisesRegex(
            EncapsulatedOwnedAdmissionError, "data anchor"
        ):
            package = _package()
            check_encapsulated_owned_admission(
                component_id="owned-counter",
                proof_classification="encapsulated_owned",
                operations=package.payload["operations"],
                semantic_slice=SimpleNamespace(
                    identity="9" * 64,
                    payload=package.payload["semantic_slice"],
                ),
                qualification_input_sha256="a" * 64,
                bundle=_bundle(), linked=_linked(),
                transfers=[_transfer()], authority=_authority(anchor=True),
            )

    def test_existing_cbmc_kernel_proves_the_persistent_state_step(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is required for the encapsulated-owned vertical")
        fixture_owner = refinement_support.SemanticRefinementTests(
            methodName="test_state_path_tracks_exact_machine_update"
        )
        with tempfile.TemporaryDirectory() as temporary:
            paths = fixture_owner._state_fixture(Path(temporary))
            result = check_component_refinement(
                semantic_contract=paths["contract"],
                interface=paths["interface"],
                source_package=paths["source"],
                source_profile=paths["profile"],
                cbmc=cbmc,
                timeout_seconds=60,
            )
        self.assertEqual(result["status"], "satisfied", result["issues"])
        self.assertTrue(result["activation_authorized"])
        self.assertEqual(result["checks"][0]["operation_id"], "add")

    def test_adapter_uses_distinct_persistent_storage_and_builds_for_pe32(self) -> None:
        bundle = _bundle()
        rendered = render_component_machine_overlay_v5(
            bundle=bundle,
            contract=_contract(bundle),
            operation_symbols={"add": "owned_counter_add"},
            transfers=[_transfer()],
            proof_classification="encapsulated_owned",
        )
        source = rendered.source
        self.assertIn("static spx_owned_counter_context_v5", source)
        self.assertIn("spx_owned_counter_owned_initialized", source)
        self.assertEqual(source.count("UINT32_C(12288)"), 1)
        self.assertNotIn("component_state_value_old_word", source)
        self.assertEqual(
            rendered.entries[0]["proof_classification"], "encapsulated_owned"
        )

        compilers = [
            shutil.which("cc"), shutil.which("i686-w64-mingw32-gcc")
        ]
        if any(item is None for item in compilers):
            self.skipTest("host and PE32 compilers are required")
        headers = render_component_c_headers_v5(
            bundle, {"add": "owned_counter_add"}
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, body in headers.items():
                (root / name).write_text(body, encoding="ascii")
            (root / "state-machine-runtime.h").write_text(
                exact_runtime_header(), encoding="ascii"
            )
            (root / "adapter.c").write_text(source, encoding="ascii")
            (root / "component.c").write_text(
                '#include "portable-component-implementation.h"\n'
                "uint32_t owned_counter_add(spx_owned_counter_context_v5 *context, "
                "uint32_t amount) {\n"
                "  context->state.value += amount;\n"
                "  return context->state.value;\n"
                "}\n",
                encoding="ascii",
            )
            (root / "harness.c").write_text(
                '#include "state-machine-runtime.h"\n'
                "typedef struct fixture_memory { uint32_t word; uint32_t writes; } "
                "fixture_memory;\n"
                "static uint32_t fixture_read(void *opaque, uint32_t address, "
                "uint32_t width, uint32_t *fault) {\n"
                "  fixture_memory *memory = (fixture_memory *)opaque;\n"
                "  if (address != UINT32_C(12288) || width != UINT32_C(4)) { "
                "*fault = 1U; return 0U; }\n"
                "  return memory->word;\n"
                "}\n"
                "static void fixture_write(void *opaque, uint32_t address, "
                "uint32_t width, uint32_t value, uint32_t *fault) {\n"
                "  fixture_memory *memory = (fixture_memory *)opaque;\n"
                "  if (address != UINT32_C(12288) || width != UINT32_C(4)) { "
                "*fault = 1U; return; }\n"
                "  memory->word = value; memory->writes += 1U;\n"
                "}\n"
                "spx_step_result spx_component_owned_counter_00001000("
                "spx_runtime *, spx_machine_state *);\n"
                "int main(void) {\n"
                "  fixture_memory memory = { UINT32_C(5), 0U };\n"
                "  spx_runtime runtime = {0}; spx_machine_state state = {0};\n"
                "  runtime.context = &memory; runtime.read = fixture_read; "
                "runtime.write = fixture_write;\n"
                "  state.ecx = UINT32_C(3);\n"
                "  spx_step_result first = "
                "spx_component_owned_counter_00001000(&runtime, &state);\n"
                "  if (first.kind != SPX_FALLTHROUGH || state.eax != UINT32_C(8)) "
                "return 1;\n"
                "  state.ecx = UINT32_C(2);\n"
                "  spx_step_result second = "
                "spx_component_owned_counter_00001000(&runtime, &state);\n"
                "  if (second.kind != SPX_FALLTHROUGH || state.eax != UINT32_C(10)) "
                "return 2;\n"
                "  if (memory.word != UINT32_C(5) || memory.writes != 0U) return 3;\n"
                "  return 0;\n"
                "}\n",
                encoding="ascii",
            )
            for index, compiler in enumerate(compilers):
                assert compiler is not None
                for source_name in ("adapter.c", "component.c"):
                    subprocess.run(
                        [compiler, "-std=c11", "-I", str(root), "-c",
                         str(root / source_name), "-o",
                         str(root / f"{index}-{source_name}.o")],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
            host = compilers[0]
            assert host is not None
            executable = root / "encapsulated-owned-runtime"
            subprocess.run(
                [host, "-std=c11", "-I", str(root), str(root / "adapter.c"),
                 str(root / "component.c"), str(root / "harness.c"),
                 "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
