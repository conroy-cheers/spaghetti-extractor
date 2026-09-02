from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.candidate.formats import (
    NATIVE_INGRESS_PLAN_FORMAT,
    SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
)
from spaghetti_extractor.native_realization.materialize import (
    NativeMaterializationError,
)
from spaghetti_extractor.native_realization.runtime_provider_v2 import (
    write_qualified_runtime_provider_v2,
)
from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.semantic_objects.semantic_object import SemanticObjectV1
from spaghetti_extractor.util import write_json
from tests.unit.semantic_link.test_module_v2 import (
    LinkedSemanticModuleV2Tests,
)


class QualifiedRuntimeProviderV2Tests(unittest.TestCase):
    def _complete_module(
        self, root: Path,
    ) -> tuple[Path, LinkedSemanticModuleV2]:
        payload = LinkedSemanticModuleV2Tests()._module(root)
        linked_path = root / "linked-semantic-module-v2.json"
        write_json(linked_path, payload)
        # The writer branch under test begins only after a complete module has
        # passed its own codec.  Reuse this compact module's real definitions
        # and package here while mocking that prior boundary; target/Nix tests
        # exercise the path with a genuinely complete linked module.
        linked = LinkedSemanticModuleV2(
            payload={**payload, "status": "complete"},
            package_root=root,
            semantic_object=SemanticObjectV1.load(root / "semantic-object.json"),
        )
        return linked_path, linked

    def test_incomplete_module_emits_nonmaterialized_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = LinkedSemanticModuleV2Tests()._module(root)
            self.assertEqual(payload["status"], "incomplete")
            linked_path = root / "linked-semantic-module-v2.json"
            write_json(linked_path, payload)
            compiler = root / "fixture-compiler"
            compiler.write_bytes(b"pinned compiler fixture\n")
            output = root / "provider"

            qualification = write_qualified_runtime_provider_v2(
                linked_semantic_module=linked_path,
                behavioral_c_package=root / "unused-behavioral-c",
                compiler=compiler,
                nm=root / "unused-nm",
                provider_id="fixture.runtime",
                out=output,
            )

            self.assertEqual(qualification["status"], "incomplete")
            self.assertEqual(qualification["definition_materializations"], [])
            self.assertEqual(qualification["obligation_implementations"], [])
            self.assertIn(
                "linked_semantic_module_incomplete",
                {row["code"] for row in qualification["blockers"]},
            )
            self.assertEqual(json.loads(
                (output / "implementation-choices.json").read_text(
                    encoding="utf-8"
                )
            ), {"definitions": {}, "obligations": {}})
            self.assertFalse(
                (output / "native-realization-object-manifest.json").exists()
            )
            self.assertFalse((output / "native-ingress-plan.json").exists())

    def test_runtime_planning_blockers_emit_diagnostic_qualification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked_path, linked = self._complete_module(root)
            compiler = root / "fixture-compiler"
            compiler.write_bytes(b"pinned compiler fixture\n")
            output = root / "provider"
            planning_blockers = [{
                "category": "incompatible_ingress_physical_abi",
                "target_rva": 0x1000,
                "bridge_equivalence_classes": ["frame:a", "frame:b"],
            }]

            def blocked_runtime(**arguments: object) -> dict[str, object]:
                out = Path(arguments["out"])
                write_json(out / "native-ingress-plan.json", {
                    "format": NATIVE_INGRESS_PLAN_FORMAT,
                    "status": "incomplete",
                    "blockers": planning_blockers,
                })
                runtime = {
                    "format": SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
                    "status": "incomplete",
                    "blockers": planning_blockers,
                }
                write_json(out / "shared-module-runtime-package.json", runtime)
                return runtime

            with patch(
                "spaghetti_extractor.native_realization.runtime_provider_v2."
                "LinkedSemanticModuleV2.load",
                return_value=linked,
            ), patch(
                "spaghetti_extractor.native_realization.materialize."
                "write_shared_module_runtime_package_from_linked_module",
                side_effect=blocked_runtime,
            ):
                qualification = write_qualified_runtime_provider_v2(
                    linked_semantic_module=linked_path,
                    behavioral_c_package=root / "unused-behavioral-c",
                    compiler=compiler,
                    nm=root / "unused-nm",
                    provider_id="fixture.runtime",
                    out=output,
                )

            self.assertEqual(qualification["status"], "incomplete")
            self.assertEqual(qualification["definition_materializations"], [])
            self.assertEqual(qualification["obligation_implementations"], [])
            blocker = next(
                row for row in qualification["blockers"]
                if row["code"] == "runtime_materialization_incomplete"
            )
            self.assertEqual(blocker["runtime_blockers"], planning_blockers)
            self.assertEqual(
                set(blocker["diagnostic_artifact_sha256s"]),
                {"native_ingress_plan", "shared_module_runtime_package"},
            )
            self.assertTrue((output / "native-ingress-plan.json").is_file())
            self.assertTrue(
                (output / "shared-module-runtime-package.json").is_file()
            )
            self.assertFalse(
                (output / "native-realization-object-manifest.json").exists()
            )

    def test_unstructured_materialization_failure_is_not_hidden(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked_path, linked = self._complete_module(root)
            compiler = root / "fixture-compiler"
            compiler.write_bytes(b"pinned compiler fixture\n")

            with patch(
                "spaghetti_extractor.native_realization.runtime_provider_v2."
                "LinkedSemanticModuleV2.load",
                return_value=linked,
            ), patch(
                "spaghetti_extractor.native_realization.runtime_provider_v2."
                "materialize_native_realization_support_v1",
                side_effect=NativeMaterializationError("compiler failed"),
            ), self.assertRaisesRegex(
                NativeMaterializationError, "compiler failed"
            ):
                write_qualified_runtime_provider_v2(
                    linked_semantic_module=linked_path,
                    behavioral_c_package=root / "unused-behavioral-c",
                    compiler=compiler,
                    nm=root / "unused-nm",
                    provider_id="fixture.runtime",
                    out=root / "provider",
                )


if __name__ == "__main__":
    unittest.main()
