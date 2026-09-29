from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.cli import main


TESTKIT = {"commands": ("component start", "boundary inspect", "boundary propose", "boundary adopt"),
           "fixtures": ("compiler",)}


class ComponentStartCommandTests(unittest.TestCase):
    def test_caller_definition_is_inspected_copied_and_checked_for_staleness(self):
        from tests.unit.components.test_work_package_v6 import _caller_payload
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
        from spaghetti_extractor.components.work_package_v6 import caller_definition_text
        from spaghetti_extractor.util import sha256_text

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); package = _caller_payload()
            files = {'include/component.h': 'void fixture_run(void);\n',
                     'src/component.c': '#include "component.h"\n#error "implement me"\n',
                     'caller-contract.json': caller_definition_text(package),
                     'baseline/behavioral-fn-00401000.c': '/* original slice */\n'}
            for name, text in files.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text)
            for row in package['generated_files']:
                row['sha256'] = sha256_text(files[row['path']])
            package['faithful_c_slices'][0]['source_sha256'] = sha256_text(files['baseline/behavioral-fn-00401000.c'])
            package['work_package_sha256'] = canonical_sha256_v3({k:v for k,v in package.items() if k != 'work_package_sha256'})
            (root/'semantic-slice-v2.json').write_text(json.dumps(package['semantic_slice']))
            artifact = root/'component-work-package-v6.json'; artifact.write_text(json.dumps(package))
            index = {'components': {'units': {'fixture-component': {'products': ['workPackage']}}},
                     'boundaries': {'subjects': {'component:fixture-component': {'kind': 'component', 'products': ['source']}}}}
            with patch('spaghetti_extractor.commands.workflows._operator_index', return_value=index), patch(
                'spaghetti_extractor.commands.workflows._realize_artifact', return_value=(artifact,package)):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(main(['boundary','inspect','fixture','component:fixture-component']),0)
                self.assertIn('declared; local proof required',stdout.getvalue())
                self.assertIn('requested frame facts:',stdout.getvalue())
                output = root.parent/(root.name+'-writable')
                proposed = root.parent/(root.name+'-boundary')
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(main(['component','start','fixture','fixture-component','--output',str(output)]),0)
                    self.assertEqual((output/'caller-contract.json').read_text(),files['caller-contract.json'])
                    self.assertTrue((output/'caller-contract.json').stat().st_mode & 0o200)
                    plan = json.loads((output/'component-start-plan.json').read_text())
                    self.assertEqual(plan['caller_definition']['requested_frame_facts'],['edi'])
                    self.assertFalse(plan['caller_definition']['authorizes_activation'])
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(main(['boundary','propose','fixture','component:fixture-component',
                                               '--output',str(proposed)]),0)
                    definition = json.loads((proposed/'caller-contract.json').read_text())
                    definition['required_frame'] = []
                    (proposed/'caller-contract.json').write_text(json.dumps(definition))
                    adopted = root/'adopted.json'
                    arguments = ['boundary','adopt','fixture','component:fixture-component',
                                 '--input',str(proposed),'--output',str(adopted)]
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        self.assertEqual(main(arguments),0)
                    self.assertIn('authority=no',stdout.getvalue())
                    self.assertEqual(json.loads(adopted.read_text()),definition)
                    preserved = adopted.read_bytes()
                    definition['unit_rvas'].append(0x401010)
                    (proposed/'caller-contract.json').write_text(json.dumps(definition))
                    with contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(main(arguments),2)
                    self.assertEqual(adopted.read_bytes(),preserved)
                    stale = json.loads((proposed/'component-work-package-v6.json').read_text())
                    stale['blockers'].append({'code':'another-reviewed-package'})
                    stale['work_package_sha256'] = canonical_sha256_v3({k:v for k,v in stale.items() if k != 'work_package_sha256'})
                    (proposed/'component-work-package-v6.json').write_text(json.dumps(stale))
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        self.assertEqual(main(arguments),2)
                    self.assertIn('editing baseline is stale',stderr.getvalue())
                    self.assertEqual(adopted.read_bytes(),preserved)
                    (root/'caller-contract.json').write_text('{}\n')
                    stderr=io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        self.assertEqual(main(['component','start','fixture','fixture-component','--output',str(root/'unused')]),2)
                    self.assertIn('stale',stderr.getvalue())
                finally:
                    __import__('shutil').rmtree(output,ignore_errors=True)
                    __import__('shutil').rmtree(proposed,ignore_errors=True)

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
            guidance = (output / "AUTHORING.md").read_text()
            self.assertIn("portable-component-c11-cbmc-v1", guidance)
            self.assertIn("no qualification or execution authority", guidance)
            command = json.loads((output / "compile_commands.json").read_text())[0]
            (output / "src/component.c").write_text(
                '#include "component.h"\nvoid fixture_run(void) {}\n')
            import subprocess
            compiled = subprocess.run(command["arguments"], cwd=command["directory"],
                                      capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)

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
