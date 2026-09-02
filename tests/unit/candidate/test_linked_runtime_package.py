from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.candidate.runtime import (
    write_shared_module_runtime_package_from_linked_module,
)


class LinkedRuntimePackageTests(unittest.TestCase):
    def test_v2_runtime_uses_packaged_semantic_members_and_direct_payload(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "linked-semantic-module.json").write_text(
                json.dumps({
                    "format": (
                        "spaghetti-extractor-linked-semantic-module-v2"
                    ),
                }),
                encoding="utf-8",
            )
            semantic = SimpleNamespace(
                transfer_plan_path=root / "transfer.json",
                resolved_external_environment_path=root / "environment.json",
                machine_object_authority_path=root / "objects.json",
            )
            linked = SimpleNamespace(
                identity="c" * 64,
                package_root=root,
                semantic_object=semantic,
                payload={
                    "format": (
                        "spaghetti-extractor-linked-semantic-module-v2"
                    ),
                },
            )
            execution_semantics = {
                "linked_semantic_module_sha256": "c" * 64,
                "_linked_semantic_module_v2": {"validated": True},
            }
            expected = {"status": "ready"}
            with (
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "LinkedSemanticModuleV2.load",
                    return_value=linked,
                ),
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "linked_execution_view_v2",
                    return_value=execution_semantics,
                ),
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "write_shared_module_runtime_package",
                    return_value=expected,
                ) as writer,
                patch(
                    "spaghetti_extractor.candidate.native_ingress_plan."
                    "_write_native_ingress_plan_from_loaded_module",
                    return_value={"status": "complete"},
                ),
            ):
                observed = (
                    write_shared_module_runtime_package_from_linked_module(
                        linked_semantic_module=root,
                        behavioral_c_package=root / "behavioral",
                        out=root / "out",
                    )
                )

        self.assertIs(observed, expected)
        self.assertEqual(
            writer.call_args.kwargs["transfer_plan"],
            semantic.transfer_plan_path,
        )
        self.assertEqual(
            writer.call_args.kwargs["execution_closure"],
            execution_semantics,
        )
        self.assertEqual(
            writer.call_args.kwargs["resolved_external_environment"],
            semantic.resolved_external_environment_path,
        )
        self.assertEqual(
            writer.call_args.kwargs["object_authority"],
            semantic.machine_object_authority_path,
        )

    def test_linked_runtime_opens_semantics_only_from_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "linked-semantic-module.json").write_text(
                json.dumps({
                    "format": (
                        "spaghetti-extractor-linked-semantic-module-v2"
                    ),
                }),
                encoding="utf-8",
            )
            semantic = SimpleNamespace(
                transfer_plan_path=root / "transfer.json",
                resolved_external_environment_path=root / "environment.json",
                machine_object_authority_path=root / "objects.json",
            )
            linked = SimpleNamespace(
                identity="b" * 64,
                package_root=root,
                semantic_object=semantic,
                payload={"format": "spaghetti-extractor-linked-semantic-module-v2"},
            )
            execution_semantics = {
                "linked_semantic_module_sha256": "b" * 64,
                "source_execution_closure_sha256": "a" * 64,
            }
            expected = {"status": "ready"}
            with (
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "LinkedSemanticModuleV2.load",
                    return_value=linked,
                ),
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "linked_execution_view_v2",
                    return_value=execution_semantics,
                ),
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "write_shared_module_runtime_package",
                    return_value=expected,
                ) as writer,
                patch(
                    "spaghetti_extractor.candidate.native_ingress_plan."
                    "_write_native_ingress_plan_from_loaded_module",
                    return_value={"status": "complete"},
                ) as ingress_writer,
            ):
                observed = (
                    write_shared_module_runtime_package_from_linked_module(
                        linked_semantic_module=root,
                        behavioral_c_package=root / "behavioral",
                        out=root / "out",
                    )
                )
            self.assertIs(observed, expected)
            self.assertEqual(
                writer.call_args.kwargs["transfer_plan"],
                semantic.transfer_plan_path,
            )
            self.assertEqual(
                writer.call_args.kwargs["execution_closure"],
                execution_semantics,
            )
            self.assertEqual(
                writer.call_args.kwargs["resolved_external_environment"],
                semantic.resolved_external_environment_path,
            )
            self.assertEqual(
                writer.call_args.kwargs["object_authority"],
                semantic.machine_object_authority_path,
            )
            self.assertEqual(
                writer.call_args.kwargs["native_ingress_plan"],
                root / "out" / "native-ingress-plan.json",
            )
            ingress_writer.assert_called_once_with(
                linked=linked,
                pinned_layout_authorities=(),
                out=root / "out",
            )

    def test_incomplete_ingress_is_packaged_without_runtime_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "linked-semantic-module.json").write_text(
                json.dumps({
                    "format": (
                        "spaghetti-extractor-linked-semantic-module-v2"
                    ),
                }),
                encoding="utf-8",
            )
            semantic = SimpleNamespace(
                transfer_plan_path=root / "transfer.json",
                resolved_external_environment_path=root / "environment.json",
                machine_object_authority_path=root / "objects.json",
            )
            linked = SimpleNamespace(
                identity="b" * 64,
                package_root=root,
                semantic_object=semantic,
                payload={"format": "spaghetti-extractor-linked-semantic-module-v2"},
            )
            ingress = {
                "format": "spaghetti-extractor-native-ingress-plan-v2",
                "status": "incomplete",
                "blockers": [{"category": "execution_closure_blocker"}],
                "plan_sha256": "c" * 64,
            }
            execution_semantics = {
                "linked_semantic_module_sha256": "b" * 64,
                "source_execution_closure_sha256": "a" * 64,
            }

            def write_ingress(*, out: Path, **_kwargs: object) -> dict:
                out.mkdir()
                (out / "native-ingress-plan.json").write_text(
                    json.dumps(ingress, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return ingress

            with (
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "LinkedSemanticModuleV2.load",
                    return_value=linked,
                ),
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "linked_execution_view_v2",
                    return_value=execution_semantics,
                ),
                patch(
                    "spaghetti_extractor.candidate.runtime."
                    "write_shared_module_runtime_package"
                ) as writer,
                patch(
                    "spaghetti_extractor.candidate.native_ingress_plan."
                    "_write_native_ingress_plan_from_loaded_module",
                    side_effect=write_ingress,
                ),
            ):
                observed = write_shared_module_runtime_package_from_linked_module(
                    linked_semantic_module=root,
                    behavioral_c_package=root / "behavioral",
                    out=root / "out",
                )

            self.assertEqual(observed["status"], "incomplete")
            self.assertEqual(observed["counts"], {"blockers": 1})
            self.assertEqual(
                observed["sources"],
                [{
                    "role": "native_ingress_plan",
                    "path": "native-ingress-plan.json",
                    "sha256": observed["inputs"]["native_ingress_plan"][
                        "sha256"
                    ],
                }],
            )
            self.assertEqual(
                observed["inputs"]["linked_semantic_module"],
                {"semantic_module_sha256": "b" * 64},
            )
            writer.assert_not_called()


if __name__ == "__main__":
    unittest.main()
