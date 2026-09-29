from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from spaghetti_extractor.build_support.python_module_index import declared_public_command_roots
from spaghetti_extractor.testkit import TestkitError
from spaghetti_extractor.testkit.discovery import build_impact_index


def _repository(root: Path) -> Path:
    (root / "src" / "spaghetti_extractor").mkdir(parents=True)
    (root / "src" / "spaghetti_extractor" / "__init__.py").write_text("", encoding="ascii")
    (root / "tests").mkdir()
    return root


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="ascii")


class TestDiscoveryTests(unittest.TestCase):
    def test_fixture_import_does_not_inherit_developer_tool_invalidation(self) -> None:
        initializer = (Path(__file__).resolve().parents[3] /
                       "src/spaghetti_extractor/testkit/__init__.py").read_text()
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            package = "src/spaghetti_extractor/testkit/"
            _write(root, package + "__init__.py", initializer)
            for module in ("diagnostics", "fixtures", "model", "discovery", "doctor",
                           "planning", "rebuild", "scaffold", "static_manifest", "transfer_fixture"):
                _write(root, package + module + ".py", "VALUE = 1\n")
            _write(root, "tests/unit/value/test_value.py",
                   "from spaghetti_extractor.testkit.transfer_fixture import VALUE\n")
            before = build_impact_index(root).tests[0]
            _write(root, package + "scaffold.py", "VALUE = 2\n")
            after_tool_edit = build_impact_index(root).tests[0]
            self.assertEqual(before.input_sha256, after_tool_edit.input_sha256)
            self.assertNotIn(package + "scaffold.py", after_tool_edit.dependency_paths)
            _write(root, package + "transfer_fixture.py", "VALUE = 2\n")
            after_fixture_edit = build_impact_index(root).tests[0]
            self.assertNotEqual(before.input_sha256, after_fixture_edit.input_sha256)

    def test_command_backends_are_role_roots_not_cli_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "src/spaghetti_extractor/commands/__init__.py", "")
            _write(
                root,
                "src/spaghetti_extractor/commands/manifest.py",
                """
SUPPORTED_COMMAND_MANIFEST = (
    {
        "name": "example",
        "group": "spaghetti_extractor.commands.example",
        "help": "exercise dynamic command closure",
    },
)
SUPPORTED_COMMAND_ROLES = {"example": "expert"}
""".lstrip(),
            )
            _write(
                root,
                "src/spaghetti_extractor/commands/example.py",
                "from spaghetti_extractor.support import VALUE\n",
            )
            _write(root, "src/spaghetti_extractor/support.py", "VALUE = 1\n")
            _write(
                root,
                "src/spaghetti_extractor/cli.py",
                "import importlib\n"
                "from .commands.manifest import SUPPORTED_COMMAND_MANIFEST\n"
                "def load(group): return importlib.import_module(group)\n",
            )
            _write(
                root,
                "tests/unit/cli/test_cli.py",
                "from spaghetti_extractor.cli import load\n",
            )

            row = build_impact_index(root).tests[0]
            roots = declared_public_command_roots(root)

            self.assertNotIn(
                "src/spaghetti_extractor/commands/example.py",
                row.dependency_paths,
            )
            self.assertNotIn(
                "src/spaghetti_extractor/support.py",
                row.dependency_paths,
            )
            self.assertEqual(
                {(item.module, item.role, item.owner) for item in roots},
                {
                    (
                        "spaghetti_extractor.commands.example",
                        "expert",
                        "command:example",
                    )
                },
            )

    def test_declared_test_commands_add_only_the_selected_backend_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "src/spaghetti_extractor/commands/__init__.py", "")
            _write(
                root,
                "src/spaghetti_extractor/commands/manifest.py",
                "SUPPORTED_COMMAND_MANIFEST = ("
                "{'name': 'example', 'group': 'spaghetti_extractor.commands.example', "
                "'help': 'fixture'},)\n"
                "SUPPORTED_COMMAND_ROLES = {'example': 'expert'}\n",
            )
            _write(
                root,
                "src/spaghetti_extractor/commands/example.py",
                "from spaghetti_extractor.support import VALUE\n",
            )
            _write(root, "src/spaghetti_extractor/support.py", "VALUE = 1\n")
            _write(
                root,
                "tests/unit/cli/test_cli.py",
                "TESTKIT = {'commands': ('example',)}\n",
            )

            row = build_impact_index(root).tests[0]

            self.assertIn(
                "src/spaghetti_extractor/commands/example.py",
                row.dependency_paths,
            )
            self.assertIn(
                "src/spaghetti_extractor/support.py",
                row.dependency_paths,
            )

    def test_conventions_supply_classification_and_import_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "src/spaghetti_extractor/base.py", "VALUE = 1\n")
            _write(root, "src/spaghetti_extractor/feature.py", "from .base import VALUE\n")
            _write(
                root,
                "tests/unit/control/test_feature.py",
                "from spaghetti_extractor.feature import VALUE\n",
            )
            _write(root, "tests/integration/lean/test_semantics.py", "from spaghetti_extractor.feature import VALUE\n")

            index = build_impact_index(root, shard_count=8)

            tests = {row.path: row for row in index.tests}
            unit = tests["tests/unit/control/test_feature.py"]
            self.assertEqual((unit.tier, unit.subsystem), ("unit", "control"))
            self.assertIn("src/spaghetti_extractor/base.py", unit.dependency_paths)
            lean = tests["tests/integration/lean/test_semantics.py"]
            self.assertEqual(lean.fixtures, ("lean-isa-runner",))
            self.assertEqual(lean.tier, "integration")

    def test_sharding_does_not_move_existing_tests_when_an_unrelated_test_is_added(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "tests/unit/core/test_first.py", "VALUE = 1\n")
            before = build_impact_index(root, shard_count=16)
            _write(root, "tests/unit/other/test_second.py", "VALUE = 2\n")
            after = build_impact_index(root, shard_count=16)

            self.assertEqual(before.tests[0].shard, {row.id: row.shard for row in after.tests}[before.tests[0].id])

    def test_canonical_test_direct_tool_bypass_has_actionable_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(
                root,
                "tests/integration/lean/test_bad.py",
                "import subprocess\nsubprocess.run(['lean', 'Bad.lean'])\n",
            )

            with self.assertRaises(TestkitError) as raised:
                build_impact_index(root)

            message = str(raised.exception)
            self.assertIn("direct_heavy_tool_invocation", message)
            self.assertIn('fixture("lean-isa-runner")', message)

    def test_nix_in_flat_filename_does_not_realize_nix_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "tests/test_module_nix.py", "VALUE = 1\n")

            row = build_impact_index(root).tests[0]

            self.assertNotIn("nix", row.capabilities)
            self.assertNotIn("nix", row.fixtures)

    def test_compiler_lookup_selects_shared_compiler_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(
                root,
                "tests/test_compile.py",
                'import shutil\nHOST = shutil.which("cc")\nCROSS = shutil.which("i686-w64-mingw32-gcc")\n',
            )

            row = build_impact_index(root).tests[0]

            self.assertIn("compiler", row.capabilities)
            self.assertIn("compiler", row.fixtures)

    def test_cbmc_lookup_selects_shared_checker_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(
                root,
                "tests/test_refinement.py",
                'import shutil\nCHECKER = shutil.which("cbmc")\n',
            )

            row = build_impact_index(root).tests[0]

            self.assertIn("cbmc", row.capabilities)
            self.assertIn("cbmc", row.fixtures)

    def test_unusual_resource_is_declared_once_in_testkit_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "profiles/example.json", "{}\n")
            _write(
                root,
                "tests/unit/profile/test_profile.py",
                'TESTKIT = {"resources": ["profiles/example.json"]}\n',
            )

            row = build_impact_index(root).tests[0]

            self.assertEqual(row.resources, ("profiles/example.json",))

    def test_root_relative_path_reads_are_automatically_hashed_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "nix/example.nix", "{}\n")
            _write(root, "profiles/one.json", "{}\n")
            _write(
                root,
                "tests/unit/config/test_inputs.py",
                """from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
NIX = ROOT / \"nix\" / \"example.nix\"
PROFILES = ROOT / \"profiles\"
NIX.read_text()
list(PROFILES.glob(\"*.json\"))
""",
            )

            row = build_impact_index(root).tests[0]

            self.assertEqual(row.resources, ("nix/example.nix", "profiles"))

    def test_cwd_relative_path_constructor_is_a_hashed_resource(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "profiles/runtime.json", "{}\n")
            _write(
                root,
                "tests/unit/config/test_profile.py",
                'from pathlib import Path\nPath("profiles/runtime.json").resolve().read_text()\n',
            )

            row = build_impact_index(root).tests[0]

            self.assertEqual(row.resources, ("profiles/runtime.json",))

    def test_transitive_source_resource_and_json_include_are_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "profiles/base.json", "{}\n")
            _write(
                root,
                "profiles/selected.json",
                json.dumps({"includes": ["base.json"]}),
            )
            _write(
                root,
                "src/spaghetti_extractor/profile.py",
                'from pathlib import Path\nPROFILE = Path(__file__).parents[2] / "profiles" / "selected.json"\ndef load(): return PROFILE.read_text()\n',
            )
            _write(
                root,
                "tests/unit/config/test_profile.py",
                "from spaghetti_extractor.profile import load\n",
            )

            row = build_impact_index(root).tests[0]

            self.assertEqual(
                row.resources,
                ("profiles/base.json", "profiles/selected.json"),
            )

    def test_fixture_catalog_names_do_not_become_directory_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            catalog = {"format": "spaghetti-extractor-test-fixture-catalog-v1", "fixtures": [
                {"id": "nix", "description": "Nix fixture", "capabilities": ["nix"],
                 "nix_attribute": "test-fixture-nix"}]}
            _write(root, "fixtures.json", json.dumps(catalog))
            _write(root, "nix/unrelated.nix", "{}\n")
            _write(root, "tests/unit/config/test_fixture.py", 'TESTKIT = {"resources": ["fixtures.json"]}\n')
            before = build_impact_index(root).tests[0]
            self.assertEqual(before.resources, ("fixtures.json",))
            _write(root, "nix/unrelated.nix", "{ changed = true; }\n")
            self.assertEqual(before.input_sha256, build_impact_index(root).tests[0].input_sha256)
            catalog["fixtures"][0]["description"] = "Updated fixture"
            _write(root, "fixtures.json", json.dumps(catalog))
            self.assertNotEqual(before.input_sha256, build_impact_index(root).tests[0].input_sha256)
            catalog["includes"] = ["nix/unrelated.nix"]
            _write(root, "fixtures.json", json.dumps(catalog))
            with self.assertRaises(TestkitError):
                build_impact_index(root)

    def test_caller_definition_labels_are_not_filesystem_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            document = {"profile": "finite-paired-caller-v1", "component_id": "example", "operation_id": "run",
                        "entry_rva": 16, "unit_rvas": [16], "service_id": "dependency", "required_frame": [],
                        "boundary": {}, "native_calls": [], "source_services": [], "witnesses": {},
                        "runtime_contracts": {}, "native_memory": [{"storage": "private"}]}
            _write(root, "caller.json", json.dumps(document))
            _write(root, "private/unrelated.bin", "before")
            _write(root, "tests/unit/config/test_caller.py", 'TESTKIT = {"resources": ["caller.json"]}\n')
            before = build_impact_index(root).tests[0]
            self.assertEqual(before.resources, ("caller.json",))
            _write(root, "private/unrelated.bin", "after")
            self.assertEqual(before.input_sha256, build_impact_index(root).tests[0].input_sha256)
            document["input_path"] = "private/unrelated.bin"
            _write(root, "caller.json", json.dumps(document))
            with self.assertRaises(TestkitError) as failure:
                build_impact_index(root)
            self.assertEqual(failure.exception.diagnostics[0].code, "invalid_caller_definition")

    def test_transitive_module_owned_resources_are_discovered_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            _write(root, "src/spaghetti_extractor/data/model.txt", "model\n")
            _write(
                root,
                "src/spaghetti_extractor/model.py",
                'PYTHON_RESOURCES = ("src/spaghetti_extractor/data/model.txt",)\n',
            )
            _write(
                root,
                "tests/unit/model/test_model.py",
                "import spaghetti_extractor.model\n",
            )

            index = build_impact_index(root)

            self.assertEqual(
                index.tests[0].resources,
                ("src/spaghetti_extractor/data/model.txt",),
            )
            modules = {row.name: row for row in index.modules}
            self.assertEqual(
                modules["spaghetti_extractor.model"].resources,
                ("src/spaghetti_extractor/data/model.txt",),
            )

    def test_json_semantic_strings_are_not_treated_as_oversized_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = _repository(Path(temporary))
            resource = "src/spaghetti_extractor/data/forms.json"
            _write(
                root,
                resource,
                json.dumps({"semantic_form": "semantic\n" + "x" * 512}),
            )
            _write(
                root,
                "src/spaghetti_extractor/model.py",
                f'PYTHON_RESOURCES = ("{resource}",)\n',
            )
            _write(
                root,
                "tests/unit/model/test_model.py",
                "import spaghetti_extractor.model\n",
            )

            row = build_impact_index(root).tests[0]

            self.assertEqual(row.resources, (resource,))


if __name__ == "__main__":
    unittest.main()
