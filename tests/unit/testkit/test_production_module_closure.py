from __future__ import annotations

import tempfile
import unittest
import hashlib
from pathlib import Path

from spaghetti_extractor.build_support.python_module_index import (
    build_python_module_index,
    declared_public_command_modules,
    nix_phase_module_roots,
    production_module_closure,
    production_roots_by_role,
    production_unreachable_modules,
)


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class ProductionModuleClosureTests(unittest.TestCase):
    def test_entrypoint_and_nix_roots_close_transitive_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(
                root,
                "pyproject.toml",
                """
[project]
name = "fixture"
version = "0"
[project.scripts]
fixture = "spaghetti_extractor.cli:main"
""".lstrip(),
            )
            _write(
                root,
                "flake.nix",
                "# spaghetti-extractor-python-role: authority\n"
                '"spaghetti_extractor.phase"\n',
            )
            _write(
                root,
                "nix/phases/worker.nix",
                "# spaghetti-extractor-python-role: developer\n"
                "python -m \\\n"
                "    spaghetti_extractor.worker\n",
            )
            _write(root, "src/spaghetti_extractor/__init__.py", "")
            _write(root, "src/spaghetti_extractor/commands/__init__.py", "")
            _write(
                root,
                "src/spaghetti_extractor/commands/manifest.py",
                """
SUPPORTED_COMMAND_MANIFEST = (
    {
        "name": "fixture-command",
        "group": "spaghetti_extractor.commands.fixture",
        "help": "exercise the fixture command",
    },
)
SUPPORTED_COMMAND_ROLES = {"fixture-command": "proposal"}
""".lstrip(),
            )
            _write(
                root,
                "src/spaghetti_extractor/commands/fixture.py",
                "from ..shared import VALUE\n",
            )
            _write(
                root,
                "src/spaghetti_extractor/cli.py",
                "from .commands.manifest import SUPPORTED_COMMAND_MANIFEST\n"
                "from .shared import VALUE\ndef main(): return VALUE\n",
            )
            _write(root, "src/spaghetti_extractor/shared.py", "VALUE = 1\n")
            _write(root, "src/spaghetti_extractor/phase.py", "from .shared import VALUE\n")
            _write(root, "src/spaghetti_extractor/worker.py", "from .shared import VALUE\n")
            _write(root, "src/spaghetti_extractor/orphan.py", "VALUE = 2\n")

            index = build_python_module_index(root)

            self.assertEqual(
                index["modules"]["spaghetti_extractor.shared"]["source_sha256"],
                hashlib.sha256(b"VALUE = 1\n").hexdigest(),
            )

            self.assertEqual(
                declared_public_command_modules(root),
                ("spaghetti_extractor.commands.fixture",),
            )
            self.assertIn(
                "spaghetti_extractor.worker",
                nix_phase_module_roots(root),
            )
            self.assertNotIn(
                "spaghetti_extractor.commands.fixture",
                index["modules"]["spaghetti_extractor.cli"]["dependencies"],
            )
            self.assertIn(
                ("spaghetti_extractor.commands.fixture", "proposal"),
                {
                    (root.module, root.role)
                    for root in production_roots_by_role(root, index)
                },
            )

            self.assertEqual(
                set(production_module_closure(root, index)),
                {
                    "spaghetti_extractor",
                    "spaghetti_extractor.cli",
                    "spaghetti_extractor.commands",
                    "spaghetti_extractor.commands.fixture",
                    "spaghetti_extractor.commands.manifest",
                    "spaghetti_extractor.phase",
                    "spaghetti_extractor.shared",
                    "spaghetti_extractor.worker",
                },
            )
            self.assertEqual(
                production_unreachable_modules(root, index),
                ("spaghetti_extractor.orphan",),
            )

    def test_missing_production_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(
                root,
                "pyproject.toml",
                """
[project]
name = "fixture"
version = "0"
[project.scripts]
fixture = "spaghetti_extractor.missing:main"
""".lstrip(),
            )
            _write(root, "flake.nix", "{}\n")
            _write(root, "src/spaghetti_extractor/__init__.py", "")
            _write(
                root,
                "src/spaghetti_extractor/commands/manifest.py",
                "SUPPORTED_COMMAND_MANIFEST = ()\nSUPPORTED_COMMAND_ROLES = {}\n",
            )

            with self.assertRaisesRegex(ValueError, "missing modules"):
                production_unreachable_modules(root)

    def test_python_bearing_nix_file_requires_explicit_role(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(root, "flake.nix", '"spaghetti_extractor.phase"\n')
            _write(root, "src/spaghetti_extractor/__init__.py", "")
            _write(root, "src/spaghetti_extractor/phase.py", "")

            with self.assertRaisesRegex(ValueError, "must declare exactly one"):
                nix_phase_module_roots(root)

    def test_only_declared_module_entrypoints_become_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(
                root,
                "pyproject.toml",
                """
[project]
name = "fixture"
version = "0"
[tool.spaghetti-extractor.module-entrypoints]
"spaghetti_extractor.__main__" = "operator"
""".lstrip(),
            )
            _write(root, "flake.nix", "{}\n")
            _write(root, "src/spaghetti_extractor/__init__.py", "")
            _write(root, "src/spaghetti_extractor/__main__.py", "")
            _write(root, "src/spaghetti_extractor/internal/__init__.py", "")
            _write(root, "src/spaghetti_extractor/internal/__main__.py", "")
            _write(root, "src/spaghetti_extractor/commands/__init__.py", "")
            _write(
                root,
                "src/spaghetti_extractor/commands/manifest.py",
                "SUPPORTED_COMMAND_MANIFEST = ()\nSUPPORTED_COMMAND_ROLES = {}\n",
            )

            roots = production_roots_by_role(root)
            self.assertIn(
                ("spaghetti_extractor.__main__", "operator"),
                {(item.module, item.role) for item in roots},
            )
            self.assertNotIn(
                "spaghetti_extractor.internal.__main__",
                {item.module for item in roots},
            )

    def test_command_implementation_modules_must_be_role_pure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(root, "pyproject.toml", "[project]\nname='fixture'\nversion='0'\n")
            _write(root, "flake.nix", "{}\n")
            _write(root, "src/spaghetti_extractor/__init__.py", "")
            _write(root, "src/spaghetti_extractor/commands/__init__.py", "")
            _write(root, "src/spaghetti_extractor/commands/mixed.py", "")
            _write(
                root,
                "src/spaghetti_extractor/commands/manifest.py",
                """
SUPPORTED_COMMAND_MANIFEST = (
    {"name": "expert one", "group": "spaghetti_extractor.commands.mixed", "help": "one"},
    {"name": "expert two", "group": "spaghetti_extractor.commands.mixed", "help": "two"},
)
SUPPORTED_COMMAND_ROLES = {"expert one": "proposal", "expert two": "diagnostic"}
""".lstrip(),
            )

            with self.assertRaisesRegex(ValueError, "role-pure"):
                production_roots_by_role(root)


if __name__ == "__main__":
    unittest.main()
