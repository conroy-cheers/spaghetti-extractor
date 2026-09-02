from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary import BoundaryModelError
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
    write_component_interface_package_v5,
)
from spaghetti_extractor.components.component_c_v5 import (
    render_component_c_headers_v5,
)
from tests.unit.boundary._support import schema, value

TESTKIT = {
    "resources": (
        "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json",
    )
}


def _intent() -> ComponentInterfaceIntentV1:
    return ComponentInterfaceIntentV1.create(
        component_id="fixture-component",
        schema=schema(),
        state=[],
        operations=[
            {
                "id": "run",
                "signature_id": "operation",
                "source_values": [value("argument", "pair"), value("result", "pair")],
                "projection_entries": [
                    {
                        "source_id": "argument",
                        "target": {
                            "root": "parameter",
                            "value_id": "argument",
                            "fields": [],
                        },
                    },
                    {
                        "source_id": "result",
                        "target": {
                            "root": "result",
                            "value_id": "result",
                            "fields": [],
                        },
                    },
                ],
                "lifecycle_bindings": [],
                "lifecycle_additional_roots": {},
                "checked_interaction_contract_ids": [],
                "effect_ids": ["observe"],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        effects=[
            {
                "id": "observe",
                "kind": "observable",
                "operation": "run",
                "target": {
                    "root": "parameter",
                    "value_id": "argument",
                    "fields": [],
                },
            }
        ],
        services=[],
        protocol_states=["ready"],
        initial_protocol_state="ready",
    )


class ComponentInterfacePackageV5Tests(unittest.TestCase):
    def test_intent_round_trips_and_compiles_checked_interface(self) -> None:
        intent = _intent()
        parsed = ComponentInterfaceIntentV1.parse(intent.to_payload())
        bundle = compile_component_interface_v5(parsed)
        self.assertEqual(bundle.interface.identity, "fixture-component")
        self.assertEqual(bundle.projection_receipts["run"].status, "complete")
        self.assertEqual(bundle.lifecycle_receipts["run"].status, "complete")

    def test_stale_intent_digest_fails_closed(self) -> None:
        payload = _intent().to_payload()
        payload["id"] = "another-component"
        with self.assertRaisesRegex(BoundaryModelError, "digest is stale"):
            ComponentInterfaceIntentV1.parse(payload)

    def test_incomplete_projection_cannot_form_an_intent(self) -> None:
        operation = dict(_intent().operations[0])
        operation["projection_entries"] = list(operation["projection_entries"][:-1])
        operation["source_values"] = list(operation["source_values"][:-1])
        with self.assertRaisesRegex(BoundaryModelError, "unchecked or inconsistent"):
            ComponentInterfaceIntentV1.create(
                component_id="fixture-component",
                schema=schema(),
                state=[],
                operations=[operation],
                effects=[],
                services=[],
                protocol_states=["ready"],
                initial_protocol_state="ready",
            )

    def test_writer_emits_deterministic_boundary_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = write_component_interface_package_v5(root, _intent())
            payload = json.loads(
                (root / "portable-component-interface-v5.json").read_text()
            )
            self.assertEqual(payload, bundle.interface.to_payload())
            self.assertTrue(
                (root / "operations/0000/boundary-lifecycle-receipt-v1.json").is_file()
            )

    def test_induction_plan_emits_the_deployable_operation_wrapper(self) -> None:
        intent_path = (
            Path(__file__).parents[3]
            / "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json"
        )
        bundle = compile_component_interface_v5(
            ComponentInterfaceIntentV1.parse(
                json.loads(intent_path.read_text(encoding="utf-8"))
            )
        )
        rendered = render_component_c_headers_v5(
            bundle,
            {"convert": "gnu_hello_ascii_to_lower"},
            {
                "interface_id": "ascii-to-lower",
                "operation_id": "convert",
                "state": [],
                "phase_ids": ["scan"],
                "completion_ids": ["return"],
                "symbols": {
                    "wrapper": "gnu_hello_ascii_to_lower",
                    "initialize": "fixture_component_initialize",
                    "step": "fixture_component_step",
                    "finish": "fixture_component_finish",
                },
            },
        )
        wrapper = rendered["component-induction-wrapper.c"]
        self.assertIn("gnu_hello_ascii_to_lower(", wrapper)
        self.assertIn("fixture_component_initialize(&state", wrapper)
        self.assertIn("while (control.kind ==", wrapper)
        self.assertIn("fixture_component_finish(&state", wrapper)


if __name__ == "__main__":
    unittest.main()
