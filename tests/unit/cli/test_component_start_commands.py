from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.cli import main


TESTKIT = {"commands": ("component start",)}


class ComponentStartCommandTests(unittest.TestCase):
    def test_materializes_a_writable_checked_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package_root = root / "checked-package"
            (package_root / "src").mkdir(parents=True)
            (package_root / "include").mkdir()
            (package_root / "src/component.c").write_text(
                '#include "component.h"\n\n#error "implement me"\n',
                encoding="utf-8",
            )
            (package_root / "include/component.h").write_text(
                "void fixture_run(void);\n", encoding="utf-8"
            )
            package = {
                "component_id": "leaf",
                "work_package_sha256": "a" * 64,
                "operations": [{"operation_id": "run", "symbol": "fixture_run"}],
            }
            output = root / "worktree"
            index = {
                "components": {
                    "units": {"leaf": {"products": ["workPackage"]}},
                },
            }
            with patch(
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value=index,
            ), patch(
                "spaghetti_extractor.commands.workflows._component_start_work_package",
                return_value=(package_root, package),
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main([
                        "component",
                        "start",
                        "fixture",
                        "leaf",
                        "--output",
                        str(output),
                    ]),
                    0,
                )
            plan = json.loads(
                (output / "component-start-plan.json").read_text(encoding="utf-8")
            )
            self.assertFalse(plan["authority"])
            self.assertEqual(plan["work_package_sha256"], "a" * 64)
            self.assertEqual(
                plan["source_transition"]["target_path"], "components/leaf.c"
            )
            self.assertTrue((output / "src/component.c").stat().st_mode & 0o200)

    def test_apply_rolls_back_then_adds_source_and_rehashes_intent(self) -> None:
        from spaghetti_extractor.components.lifting_intent import (
            ComponentLiftingIntentV1,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = root / "targets"
            bundle = corpus / "fixture"
            intent_path = bundle / "intent/components.json"
            source_root = bundle / "source"
            package_root = root / "checked-package"
            intent_path.parent.mkdir(parents=True)
            source_root.mkdir()
            (package_root / "src").mkdir(parents=True)
            (package_root / "src/component.c").write_text(
                '#include "component.h"\n\n#error "implement me"\n',
                encoding="utf-8",
            )
            (bundle / "target.json").write_text(
                json.dumps(
                    {
                        "format": "spaghetti-extractor-target-bundle-v3",
                        "id": "fixture",
                        "display_name": "Fixture",
                        "input": {"kind": "pe32", "expected_sha256": "b" * 64},
                        "paths": {
                            "nix": "default.nix",
                            "components": "intent/components.json",
                            "component_sources": "source",
                        },
                        "workflow": {"default_configuration": "default"},
                    }
                ),
                encoding="utf-8",
            )
            intent = ComponentLiftingIntentV1.create(
                program_id="fixture-program",
                components=[{"id": "leaf", "label": "Leaf"}],
                groups=[],
                configurations=[
                    {
                        "id": "default",
                        "label": "Default",
                        "selections": [
                            {
                                "kind": "component",
                                "id": "leaf",
                                "activation": "draft",
                            }
                        ],
                    }
                ],
            )
            intent_path.write_text(json.dumps(intent.to_payload()), encoding="utf-8")
            package = {
                "component_id": "leaf",
                "work_package_sha256": "c" * 64,
                "operations": [{"operation_id": "run", "symbol": "fixture_run"}],
            }
            index = {
                "components": {
                    "units": {"leaf": {"products": ["workPackage"]}},
                },
            }
            arguments = [
                "component",
                "start",
                "fixture",
                "leaf",
                "--target-flake",
                str(corpus),
                "--apply",
            ]
            original_intent = intent_path.read_bytes()
            real_replace = __import__("os").replace

            def fail_intent_replace(source: object, destination: object) -> None:
                if Path(destination) == intent_path:
                    raise OSError("injected intent replacement failure")
                real_replace(source, destination)

            common_patches = (
                patch(
                    "spaghetti_extractor.commands.workflows._operator_index",
                    return_value=index,
                ),
                patch(
                    "spaghetti_extractor.commands.workflows."
                    "_component_start_work_package",
                    return_value=(package_root, package),
                ),
            )
            with common_patches[0], common_patches[1], patch(
                "spaghetti_extractor.commands.component_start.os.replace",
                side_effect=fail_intent_replace,
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(arguments), 2)
            self.assertEqual(intent_path.read_bytes(), original_intent)
            self.assertFalse((source_root / "components/leaf.c").exists())

            with patch(
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value=index,
            ), patch(
                "spaghetti_extractor.commands.workflows._component_start_work_package",
                return_value=(package_root, package),
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(arguments), 0)
            updated = ComponentLiftingIntentV1.parse(
                json.loads(intent_path.read_text(encoding="utf-8"))
            )
            self.assertEqual(
                updated.components[0]["source"],
                {
                    "files": ["components/leaf.c"],
                    "shared_inputs": [],
                    "operation_symbols": {"run": "fixture_run"},
                },
            )
            source = source_root / "components/leaf.c"
            self.assertIn(
                '#include "portable-component-implementation.h"',
                source.read_text(encoding="utf-8"),
            )
            self.assertNotIn('#include "component.h"', source.read_text())
            with patch(
                "spaghetti_extractor.commands.workflows._operator_index",
                return_value=index,
            ), patch(
                "spaghetti_extractor.commands.workflows._component_start_work_package",
                return_value=(package_root, package),
            ), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(arguments), 2)


if __name__ == "__main__":
    unittest.main()
