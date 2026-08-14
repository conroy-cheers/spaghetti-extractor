from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.python_module_index import (
    build_python_module_index,
    declared_public_command_modules,
    nix_phase_module_roots,
    production_module_closure,
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
            _write(root, "flake.nix", '"spaghetti_extractor.phase"\n')
            _write(
                root,
                "nix/phases/worker.nix",
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
                declared_public_command_modules(root),
                ("spaghetti_extractor.commands.fixture",),
            )
            self.assertIn(
                "spaghetti_extractor.worker",
                nix_phase_module_roots(root),
            )
            self.assertIn(
                "spaghetti_extractor.commands.fixture",
                index["modules"]["spaghetti_extractor.cli"]["dependencies"],
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
                "SUPPORTED_COMMAND_MANIFEST = ()\n",
            )

            with self.assertRaisesRegex(ValueError, "missing modules"):
                production_unreachable_modules(root)


if __name__ == "__main__":
    unittest.main()
