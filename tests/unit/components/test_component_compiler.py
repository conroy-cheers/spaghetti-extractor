from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.compiler import (
    ComponentCompileError,
    compile_component,
)
from spaghetti_extractor.components.formats import (
    COMPONENT_SOURCE_PACKAGE_V2_FORMAT,
    COMPONENT_SOURCE_PACKAGE_V3_FORMAT,
)
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.source import (
    build_component_source_package,
    component_operation_symbols,
    load_component_source_package,
)

from .test_interface_ir import _interface_v2


_GOOD_SOURCE = """
uint32_t counter_add_exact(spx_counter_context_v2 *context, uint32_t amount) {
  context->state.value += amount;
  return context->state.value;
}

void counter_reset_exact(spx_counter_context_v2 *context) {
  context->state.value = 0;
}
"""


class PortableComponentCompilerTests(unittest.TestCase):
    def test_source_v3_bindings_and_v2_reader_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_file = root / "counter.c"
            source_file.write_text(_GOOD_SOURCE, encoding="ascii")
            v3 = build_component_source_package(
                lift_unit_id="counter",
                files={"counter.c": source_file},
                shared_inputs={},
                operation_symbols={
                    "add": "counter_add_exact",
                    "reset": "counter_reset_exact",
                },
                out_dir=root / "v3",
            )
            v2 = build_component_source_package(
                lift_unit_id="counter",
                files={"counter.c": source_file},
                shared_inputs={},
                entry={"abi": "portable-interface-v1", "symbol": "counter_add_exact"},
                out_dir=root / "v2",
            )

            self.assertEqual(v3["format"], COMPONENT_SOURCE_PACKAGE_V3_FORMAT)
            self.assertEqual(v2["format"], COMPONENT_SOURCE_PACKAGE_V2_FORMAT)
            self.assertEqual(
                component_operation_symbols(load_component_source_package(root / "v3")),
                {"add": "counter_add_exact", "reset": "counter_reset_exact"},
            )
            self.assertEqual(
                load_component_source_package(root / "v2")["format"],
                COMPONENT_SOURCE_PACKAGE_V2_FORMAT,
            )

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_compiles_conformance_tu_in_host_and_object_modes_and_runs_audit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, source = self._package(root, _GOOD_SOURCE)
            interface = PortableComponentInterfaceV2.parse(_interface_v2())
            audited: list[Path] = []

            compile_component(
                package=package,
                source=source,
                compiler=Path(shutil.which("cc") or "cc"),
                output=root / "component.so",
                interface=interface,
                operation_symbols=component_operation_symbols(source),
                mutable_global_audit=audited.append,
            )
            compile_component(
                package=package,
                source=source,
                compiler=Path(shutil.which("cc") or "cc"),
                output=root / "component.o",
                interface=interface,
                operation_symbols=component_operation_symbols(source),
                mode="pe32-object",
            )

            self.assertEqual(audited, [root / "component.so"])
            self.assertTrue((root / "component.so").is_file())
            self.assertTrue((root / "component.o").is_file())
            self.assertIn(
                "counter_add_exact",
                (root / "portable-component-implementation.h").read_text(
                    encoding="ascii"
                ),
            )

    @unittest.skipUnless(shutil.which("cc"), "C compiler unavailable")
    def test_conformance_rejects_missing_and_wrong_symbols(self) -> None:
        interface = PortableComponentInterfaceV2.parse(_interface_v2())
        cases = (
            (
                _GOOD_SOURCE.replace("counter_reset_exact", "counter_reset_actual"),
                "missing configured symbols|undefined reference",
            ),
            (
                _GOOD_SOURCE.replace(
                    "uint32_t counter_add_exact", "uint64_t counter_add_exact"
                ),
                "conflicting types",
            ),
        )
        for index, (source_text, message) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                package, source = self._package(root, source_text)
                with self.assertRaisesRegex(ComponentCompileError, message):
                    compile_component(
                        package=package,
                        source=source,
                        compiler=Path(shutil.which("cc") or "cc"),
                        output=root / "component.so",
                        interface=interface,
                        operation_symbols=component_operation_symbols(source),
                    )

    def _package(
        self, root: Path, source_text: str
    ) -> tuple[Path, dict[str, object]]:
        source_file = root / "counter.c"
        source_file.write_text(source_text, encoding="ascii")
        package = root / "source"
        source = build_component_source_package(
            lift_unit_id="counter",
            files={"counter.c": source_file},
            shared_inputs={},
            operation_symbols={
                "add": "counter_add_exact",
                "reset": "counter_reset_exact",
            },
            out_dir=package,
        )
        return package, source


if __name__ == "__main__":
    unittest.main()
