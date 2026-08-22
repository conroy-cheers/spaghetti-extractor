from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.atomics import (
    spx_atomics_header,
    spx_atomics_validation_source,
)
from spaghetti_extractor.components.compiler import compile_component
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2


def _interface() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": "atomic_update",
        "types": [
            {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
            {
                "id": "atomic_u32",
                "kind": "resource",
                "resource_kind": "atomic_object",
                "ownership": "borrowed",
            },
        ],
        "state": [],
        "operations": [
            {
                "id": "compare_exchange",
                "kind": "operation",
                "parameters": [
                    {"id": "object", "type_id": "atomic_u32"},
                    {"id": "desired", "type_id": "u32"},
                ],
                "results": [{"id": "retry", "type_id": "u32"}],
                "effect_ids": ["update"],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        "effects": [
            {
                "id": "update",
                "kind": "memory",
                "target_id": "object",
                "operation": "compare_exchange",
            }
        ],
        "services": [],
        "protocol": {"states": ["ready"], "initial_state": "ready"},
    }


_SOURCE = """
#include "portable-component-implementation.h"
#include "spx-atomics.h"

uint32_t atomic_update_compare_exchange(
    spx_atomic_update_context_v2 *context,
    spx_atomic_object *object,
    uint32_t desired) {
  spx_atomic_observation observation = {0};
  (void)context;
  (void)spx_atomic_compare_exchange(object, 0U, desired, &observation);
  return !observation.exchanged;
}
"""


class AtomicPortableComponentTests(unittest.TestCase):
    def test_public_api_exposes_unconditional_exchange(self) -> None:
        self.assertIn("spx_atomic_exchange(", spx_atomics_header())
        self.assertIn(
            "spx_atomic_exchange_callback", spx_atomics_validation_source()
        )

    def test_atomic_resource_renders_as_an_opaque_capability(self) -> None:
        header = PortableComponentInterfaceV2.parse(_interface()).render_public_header()

        self.assertIn('#include "spx-atomics.h"', header)
        self.assertIn("spx_atomic_object * object", header)
        self.assertNotIn("_Atomic", header)

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_atomic_component_compiles_without_raw_atomic_storage(self) -> None:
        interface = PortableComponentInterfaceV2.parse(_interface())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sources").mkdir()
            (root / "sources" / "atomic.c").write_text(_SOURCE, encoding="ascii")
            compile_component(
                package=root,
                source={"files": [{"path": "atomic.c"}]},
                compiler=Path(shutil.which("cc") or "cc"),
                output=root / "atomic.so",
                interface=interface,
                operation_symbols={
                    "compare_exchange": "atomic_update_compare_exchange"
                },
            )
            self.assertTrue((root / "atomic.so").is_file())


if __name__ == "__main__":
    unittest.main()
