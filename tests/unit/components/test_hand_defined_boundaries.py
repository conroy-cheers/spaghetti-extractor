"""Hand-authored shared-state boundary acceptance, separate from qualification."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_summary_contracts import (
    memory_summary_operations,
    scalar_summary_operations,
)
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)

TESTKIT = {
    "fixtures": ("compiler",),
    "resources": ("tests/fixtures/hand-defined-boundaries/resource-text",),
}
FIXTURE = Path(__file__).parents[2] / "fixtures/hand-defined-boundaries/resource-text"


def shared_buffer_bundle():
    return compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
        json.loads((FIXTURE / "interface.json").read_text())
    ))


class HandDefinedBoundaryTests(unittest.TestCase):
    def test_two_contexts_and_old_returned_view_observe_current_shared_storage(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        bundle = shared_buffer_bundle()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, content in render_component_c_headers_v5(
                bundle, {"get": "resource_text"}
            ).items():
                (root / name).write_text(content)
            executable = root / "exercise"
            (root / "reference-runtime.c").write_text(
                '#include "portable-component.h"\n'
                + spx_portable_reference_runtime_v5_source()
            )
            compiled = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(root), str(FIXTURE / "resource-text.c"),
                 str(FIXTURE / "exercise.c"), str(root / "component-conformance.c"),
                 str(root / "reference-runtime.c"),
                 "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)

    def test_declared_shared_state_and_effects_do_not_grant_existing_summary_rules(self):
        # Remove this scope guard only when checked state/service composition
        # lands with its own positive and adversarial evidence tests.
        bundle = shared_buffer_bundle()
        self.assertIsNone(scalar_summary_operations(bundle))
        self.assertIsNone(memory_summary_operations(bundle))
        self.assertIsNone(memory_summary_operations(bundle, mutable=True))


if __name__ == "__main__":
    unittest.main()
