from __future__ import annotations

import unittest

from spaghetti_extractor.components.interface_ir import (
    ComponentInterfaceIRError,
    ComponentInterfaceIRV1,
    PortableComponentInterfaceV2,
    parse_component_interface,
)


def _interface() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v1",
        "id": "video_init",
        "types": [
            {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
            {
                "id": "mode",
                "kind": "record",
                "access": "read",
                "fields": [
                    {"id": "width", "type_id": "u32"},
                    {"id": "height", "type_id": "u32"},
                ],
            },
            {
                "id": "window",
                "kind": "resource",
                "resource_kind": "window_handle",
                "ownership": "borrowed",
            },
            {
                "id": "surface",
                "kind": "resource",
                "resource_kind": "directdraw_surface",
                "ownership": "created",
            },
            {
                "id": "error_callback",
                "kind": "callback",
                "abi": "logical_c",
                "parameter_type_ids": ["u32"],
                "result_type_id": None,
            },
        ],
        "parameters": [
            {"id": "window", "type_id": "window", "machine_projection": {"kind": "resource"}},
            {"id": "mode", "type_id": "mode", "machine_projection": {"kind": "record"}},
        ],
        "results": [
            {"id": "surface", "type_id": "surface", "machine_projection": {"kind": "resource"}}
        ],
        "effects": [
            {
                "id": "surface_created",
                "kind": "resource",
                "target_id": "surface",
                "operation": "create",
                "machine_refs": [{"unit_id": "unit-1", "event_index": 0}],
            }
        ],
        "services": [
            {
                "id": "directdraw_create",
                "operation_identity": {"kind": "import", "dll": "ddraw.dll", "symbol": "DirectDrawCreate"},
                "parameter_type_ids": ["window"],
                "result_type_id": "surface",
                "effect_ids": ["surface_created"],
            }
        ],
    }


def _interface_v2() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": "counter",
        "types": [
            {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
        ],
        "state": [
            {"id": "value", "type_id": "u32", "initial": 0},
        ],
        "operations": [
            {
                "id": "add",
                "kind": "operation",
                "parameters": [{"id": "amount", "type_id": "u32"}],
                "results": [{"id": "value", "type_id": "u32"}],
                "effect_ids": [],
                "allowed_service_ids": ["observe"],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            },
            {
                "id": "reset",
                "kind": "callback",
                "parameters": [],
                "results": [],
                "effect_ids": [],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            },
        ],
        "effects": [],
        "services": [
            {
                "id": "observe",
                "parameter_type_ids": ["u32"],
                "result_type_id": None,
                "effect_ids": [],
            }
        ],
        "protocol": {
            "states": ["ready"],
            "initial_state": "ready",
        },
    }


class ComponentInterfaceIRTests(unittest.TestCase):
    def test_parses_stateful_interface_and_renders_portable_c(self) -> None:
        interface = ComponentInterfaceIRV1.parse(_interface())
        rendered = interface.render_c_header()

        self.assertIn("spx_resource_v1 window", rendered)
        self.assertIn("const spx_mode_v1 * mode", rendered)
        self.assertIn("(*directdraw_create)(void *context", rendered)
        self.assertIn("const spx_video_init_services_v1 *services", rendered)
        self.assertIn("spx_resource_v1 spx_component_video_init", rendered)
        self.assertNotIn("eax", rendered)
        self.assertNotIn("uintptr_t", rendered)
        self.assertEqual(ComponentInterfaceIRV1.parse(interface.to_payload()), interface)
        self.assertEqual(len(interface.sha256), 64)

    def test_rejects_unknown_type_reference(self) -> None:
        payload = _interface()
        payload["results"][0]["type_id"] = "machine_pointer"  # type: ignore[index]
        with self.assertRaisesRegex(ComponentInterfaceIRError, "unknown type"):
            ComponentInterfaceIRV1.parse(payload)

    def test_rejects_duplicate_logical_values(self) -> None:
        payload = _interface()
        payload["results"][0]["id"] = "window"  # type: ignore[index]
        with self.assertRaisesRegex(ComponentInterfaceIRError, "logical value ids"):
            ComponentInterfaceIRV1.parse(payload)

    def test_rejects_unbounded_bytes(self) -> None:
        payload = _interface()
        payload["types"].append(  # type: ignore[union-attr]
            {
                "id": "bytes",
                "kind": "bytes",
                "access": "read_write",
                "extent_parameter_id": None,
                "nul_terminated": False,
            }
        )
        with self.assertRaisesRegex(ComponentInterfaceIRError, "exactly one"):
            ComponentInterfaceIRV1.parse(payload)

    def test_v2_is_machine_free_and_declares_exact_source_symbols(self) -> None:
        interface = PortableComponentInterfaceV2.parse(_interface_v2())
        public = interface.render_public_header()
        implementation = interface.render_implementation_header(
            {"add": "counter_add_exact", "reset": "counter_reset_exact"}
        )

        self.assertIn("typedef struct spx_counter_context_v2", public)
        self.assertNotIn("struct spx_counter_context_v2 {", public)
        self.assertIn("uint32_t value;", implementation)
        self.assertIn("uint32_t counter_add_exact(", implementation)
        self.assertIn("void counter_reset_exact(", implementation)
        self.assertNotIn("machine", str(interface.to_payload()))
        self.assertEqual(parse_component_interface(interface.to_payload()), interface)

    def test_v2_rejects_machine_unit_and_external_fields(self) -> None:
        for field in ("machine_projection", "unit_id", "external_id"):
            payload = _interface_v2()
            payload["operations"][0]["parameters"][0][field] = "forbidden"  # type: ignore[index]
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ComponentInterfaceIRError, "cannot contain machine, unit, or external"
                ):
                    PortableComponentInterfaceV2.parse(payload)

    def test_v2_operation_fields_are_exact(self) -> None:
        payload = _interface_v2()
        del payload["operations"][0]["allowed_service_ids"]  # type: ignore[index]
        with self.assertRaisesRegex(ComponentInterfaceIRError, "fields differ"):
            PortableComponentInterfaceV2.parse(payload)

    def test_v2_byte_extent_is_operation_local(self) -> None:
        payload = _interface_v2()
        payload["types"].append(  # type: ignore[union-attr]
            {
                "id": "input_bytes",
                "kind": "bytes",
                "access": "read",
                "extent_parameter_id": "extent",
                "nul_terminated": False,
            }
        )
        payload["operations"][0]["parameters"].append(  # type: ignore[index]
            {"id": "input", "type_id": "input_bytes"}
        )
        # A same-named parameter on another operation must not satisfy the
        # extent relation for this operation.
        payload["operations"][1]["parameters"].append(  # type: ignore[index]
            {"id": "extent", "type_id": "u32"}
        )
        with self.assertRaisesRegex(
            ComponentInterfaceIRError, "operation-local extent parameter"
        ):
            PortableComponentInterfaceV2.parse(payload)

        payload["operations"][0]["parameters"].append(  # type: ignore[index]
            {"id": "extent", "type_id": "u32"}
        )
        PortableComponentInterfaceV2.parse(payload)

    def test_v2_rejects_recursive_by_value_records(self) -> None:
        payload = _interface_v2()
        payload["types"].extend(  # type: ignore[union-attr]
            [
                {
                    "id": "left_record",
                    "kind": "record",
                    "access": "read",
                    "fields": [{"id": "right", "type_id": "right_record"}],
                },
                {
                    "id": "right_record",
                    "kind": "record",
                    "access": "read",
                    "fields": [{"id": "left", "type_id": "left_record"}],
                },
            ]
        )
        with self.assertRaisesRegex(ComponentInterfaceIRError, "by-value cycle"):
            PortableComponentInterfaceV2.parse(payload)


if __name__ == "__main__":
    unittest.main()
